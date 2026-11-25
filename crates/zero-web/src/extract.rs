//! Map and extract (WEB-07, WEB-13, WEB-14).
//!
//! Two independent pieces live here:
//!
//! - [`map_urls`] discovers page URLs from sitemap bodies and already-fetched
//!   link lists without fetching anything. It resolves relative links against
//!   the seed, keeps only the seed's host, deduplicates with
//!   [`canonical_url_key`], applies URL and per-page limits, and returns a
//!   deterministically sorted [`UrlMap`] with per-source counts (WEB-13).
//! - [`Schema`], [`validate`], [`extract`], [`extract_html`], and
//!   [`extract_from_content_type`] turn a JSON or HTML document into structured
//!   JSON that is checked against a caller schema (WEB-14). A schema is a small,
//!   dependency-free subset of JSON Schema; unknown keywords are ignored, while
//!   malformed structural keywords are refused before extraction.
//!
//! Extraction is all-or-nothing: the mapped value is validated after mapping,
//! and an invalid value is returned as a typed `zero.fnd.invalid_input` error
//! with a JSON path instead of a partially valid object. Required source
//! properties are errors; optional absent properties are reported in
//! [`Extraction::missing`] and omitted from the value.
//!
//! The HTML reader is a bounded tokenizer, not a DOM: it recognizes `title`,
//! `meta name`/`meta property`, `h1`, `a href`, and elements carrying
//! `data-zero-field="name"`. Script and style bodies, comments, declarations,
//! and processing instructions are skipped. There is no CSS selector engine,
//! no `<base>` handling, no charset decoding (the caller passes text), and no
//! tree repair; see `docs/web.md` for the full mapping table and limits.
//!
//! No network access happens in this module.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::{Map, Number, Value};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::crawl::{decode_entities, resolve_link, sitemap_locs};
use crate::search::canonical_url_key;

/// Maximum nesting depth of a schema, counting the root as depth 0.
pub const MAX_SCHEMA_DEPTH: usize = 32;
/// Maximum number of schema nodes (root, every property, every `items`).
pub const MAX_SCHEMA_NODES: usize = 4_096;
/// Maximum number of values in one `enum`.
pub const MAX_ENUM_VALUES: usize = 256;
/// Maximum value nesting accepted by [`validate`] and [`extract`].
pub const MAX_VALUE_DEPTH: usize = 64;
/// Maximum HTML or text source size in bytes (4 MiB).
pub const MAX_SOURCE_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of parsed tags in one HTML document.
pub const MAX_HTML_TAGS: usize = 100_000;
/// Maximum number of attributes read from one tag.
pub const MAX_ATTRIBUTES_PER_TAG: usize = 128;
/// Maximum length of one attribute value in bytes.
pub const MAX_ATTRIBUTE_CHARS: usize = 8 * 1024;
/// Maximum length of one extracted HTML field in characters.
pub const MAX_FIELD_CHARS: usize = 64 * 1024;
/// Default ceiling on URLs returned by [`map_urls`].
pub const DEFAULT_MAX_URLS: usize = 1_000;
/// Default ceiling on URLs taken from one page's link list.
pub const DEFAULT_MAX_PER_PAGE: usize = 200;

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn schema_error(path: &str, message: impl std::fmt::Display) -> ZeroError {
    invalid(format!("invalid schema at `{path}`: {message}"))
}

fn value_error(path: &str, message: impl std::fmt::Display) -> ZeroError {
    invalid(format!("invalid value at `{path}`: {message}"))
}

/// Append a child key to a JSON path, using dot notation for plain keys and
/// bracket-quoted notation otherwise.
fn child_path(parent: &str, key: &str) -> String {
    let plain = !key.is_empty()
        && key.chars().all(|character| {
            character.is_ascii_alphanumeric() || character == '_' || character == '-'
        });
    if plain {
        format!("{parent}.{key}")
    } else {
        let escaped = key.replace('\\', "\\\\").replace('"', "\\\"");
        format!("{parent}[\"{escaped}\"]")
    }
}

// ---------------------------------------------------------------------------
// Schema subset
// ---------------------------------------------------------------------------

/// The JSON types this subset understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SchemaType {
    String,
    Number,
    Integer,
    Boolean,
    Array,
    Object,
    Null,
}

impl SchemaType {
    /// Stable lower-case name used in messages and type errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            SchemaType::String => "string",
            SchemaType::Number => "number",
            SchemaType::Integer => "integer",
            SchemaType::Boolean => "boolean",
            SchemaType::Array => "array",
            SchemaType::Object => "object",
            SchemaType::Null => "null",
        }
    }

    fn parse(name: &str) -> Option<Self> {
        Some(match name {
            "string" => SchemaType::String,
            "number" => SchemaType::Number,
            "integer" => SchemaType::Integer,
            "boolean" => SchemaType::Boolean,
            "array" => SchemaType::Array,
            "object" => SchemaType::Object,
            "null" => SchemaType::Null,
            _ => return None,
        })
    }
}

/// A parsed JSON-Schema subset.
///
/// Supported keywords: `type` (one string, not an array of types),
/// `properties`, `required`, `items`, `enum`, `minLength`, `maxLength`,
/// `minimum`, `maximum`, `maxItems`, and `additionalProperties` (boolean,
/// default `true`). Every other keyword is ignored. See `docs/web.md` for the
/// exact semantics and the refusal rules.
#[derive(Debug, Clone, PartialEq)]
pub struct Schema {
    kind: Option<SchemaType>,
    properties: BTreeMap<String, Schema>,
    required: BTreeSet<String>,
    items: Option<Box<Schema>>,
    enum_values: Vec<Value>,
    min_length: Option<usize>,
    max_length: Option<usize>,
    minimum: Option<f64>,
    maximum: Option<f64>,
    max_items: Option<usize>,
    additional_properties: bool,
}

impl Schema {
    /// Parse and validate a schema from JSON.
    ///
    /// Structural mistakes (an unknown `type`, a negative limit, a non-object
    /// root, a schema deeper than [`MAX_SCHEMA_DEPTH`] or larger than
    /// [`MAX_SCHEMA_NODES`], `required` naming a property that is not declared,
    /// `minimum > maximum`, an empty or duplicated `enum`, ...) are refused
    /// with `zero.fnd.invalid_input` and a schema path.
    pub fn parse(value: &Value) -> Result<Self> {
        let mut nodes = 0;
        let schema = parse_schema(value, 0, &mut nodes, "$")?;
        validate_schema(&schema)?;
        Ok(schema)
    }

    /// The declared type, if the schema constrains one.
    pub fn kind(&self) -> Option<SchemaType> {
        self.kind
    }

    /// Declared properties, in deterministic name order.
    pub fn properties(&self) -> &BTreeMap<String, Schema> {
        &self.properties
    }

    /// Property names that must be present.
    pub fn required(&self) -> &BTreeSet<String> {
        &self.required
    }

    /// The schema for array elements, if declared.
    pub fn items(&self) -> Option<&Schema> {
        self.items.as_deref()
    }

    /// The allowed values; empty means `enum` was not declared.
    pub fn enum_values(&self) -> &[Value] {
        &self.enum_values
    }

    /// Whether undeclared object properties are allowed (the default).
    pub fn additional_properties(&self) -> bool {
        self.additional_properties
    }
}

fn parse_schema(value: &Value, depth: usize, nodes: &mut usize, path: &str) -> Result<Schema> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(schema_error(
            path,
            format!("nesting exceeds the depth limit of {MAX_SCHEMA_DEPTH}"),
        ));
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Err(schema_error(
            path,
            format!("schema exceeds the node limit of {MAX_SCHEMA_NODES}"),
        ));
    }
    let Some(object) = value.as_object() else {
        return Err(schema_error(path, "a schema must be a JSON object"));
    };

    let mut schema = Schema {
        kind: None,
        properties: BTreeMap::new(),
        required: BTreeSet::new(),
        items: None,
        enum_values: Vec::new(),
        min_length: None,
        max_length: None,
        minimum: None,
        maximum: None,
        max_items: None,
        additional_properties: true,
    };

    for (key, keyword) in object {
        match key.as_str() {
            "type" => {
                let name = keyword
                    .as_str()
                    .ok_or_else(|| schema_error(path, "`type` must be a single string"))?;
                schema.kind = Some(SchemaType::parse(name).ok_or_else(|| {
                    schema_error(
                        path,
                        format!(
                            "unknown type `{name}`; expected one of string, number, integer, \
                             boolean, array, object, null"
                        ),
                    )
                })?);
            }
            "properties" => {
                let properties = keyword
                    .as_object()
                    .ok_or_else(|| schema_error(path, "`properties` must be an object"))?;
                for (name, child) in properties {
                    let child_path = child_path(path, name);
                    schema.properties.insert(
                        name.clone(),
                        parse_schema(child, depth + 1, nodes, &child_path)?,
                    );
                }
            }
            "required" => {
                let names = keyword
                    .as_array()
                    .ok_or_else(|| schema_error(path, "`required` must be an array of strings"))?;
                for name in names {
                    let name = name.as_str().ok_or_else(|| {
                        schema_error(path, "`required` must contain only strings")
                    })?;
                    if !schema.required.insert(name.to_string()) {
                        return Err(schema_error(
                            path,
                            format!("`required` lists `{name}` more than once"),
                        ));
                    }
                }
            }
            "items" => {
                schema.items = Some(Box::new(parse_schema(
                    keyword,
                    depth + 1,
                    nodes,
                    &format!("{path}.items"),
                )?));
            }
            "enum" => {
                let values = keyword
                    .as_array()
                    .ok_or_else(|| schema_error(path, "`enum` must be an array"))?;
                if values.is_empty() {
                    return Err(schema_error(path, "`enum` must not be empty"));
                }
                if values.len() > MAX_ENUM_VALUES {
                    return Err(schema_error(
                        path,
                        format!("`enum` has more than {MAX_ENUM_VALUES} values"),
                    ));
                }
                for (index, candidate) in values.iter().enumerate() {
                    if values[..index]
                        .iter()
                        .any(|previous| json_equal(previous, candidate))
                    {
                        return Err(schema_error(
                            path,
                            format!("`enum` repeats the value at index {index}"),
                        ));
                    }
                }
                schema.enum_values = values.clone();
            }
            "minLength" => schema.min_length = Some(parse_limit(path, "minLength", keyword)?),
            "maxLength" => schema.max_length = Some(parse_limit(path, "maxLength", keyword)?),
            "maxItems" => schema.max_items = Some(parse_limit(path, "maxItems", keyword)?),
            "minimum" => schema.minimum = Some(parse_bound(path, "minimum", keyword)?),
            "maximum" => schema.maximum = Some(parse_bound(path, "maximum", keyword)?),
            "additionalProperties" => {
                schema.additional_properties = keyword.as_bool().ok_or_else(|| {
                    schema_error(path, "`additionalProperties` must be a boolean")
                })?;
            }
            // Unknown keywords are ignored on purpose: schemas written for a
            // full JSON-Schema library stay usable with this subset.
            _ => {}
        }
    }

    if let (Some(minimum), Some(maximum)) = (schema.min_length, schema.max_length) {
        if minimum > maximum {
            return Err(schema_error(
                path,
                "`minLength` is greater than `maxLength`",
            ));
        }
    }
    if let (Some(minimum), Some(maximum)) = (schema.minimum, schema.maximum) {
        if minimum > maximum {
            return Err(schema_error(path, "`minimum` is greater than `maximum`"));
        }
    }
    Ok(schema)
}

fn parse_limit(path: &str, key: &str, value: &Value) -> Result<usize> {
    value
        .as_u64()
        .and_then(|number| usize::try_from(number).ok())
        .ok_or_else(|| schema_error(path, format!("`{key}` must be a non-negative integer")))
}

fn parse_bound(path: &str, key: &str, value: &Value) -> Result<f64> {
    let number = value
        .as_f64()
        .ok_or_else(|| schema_error(path, format!("`{key}` must be a number")))?;
    if !number.is_finite() {
        return Err(schema_error(
            path,
            format!("`{key}` must be a finite number"),
        ));
    }
    Ok(number)
}

/// Re-check the invariants of a parsed or hand-built schema.
///
/// [`Schema::parse`] already runs this, so the only reason to call it again is
/// to validate a schema assembled by crate-internal code. It never panics and
/// refuses the same malformed shapes that parsing refuses.
pub fn validate_schema(schema: &Schema) -> Result<()> {
    let mut nodes = 0;
    check_schema(schema, 0, &mut nodes, "$")
}

fn check_schema(schema: &Schema, depth: usize, nodes: &mut usize, path: &str) -> Result<()> {
    if depth > MAX_SCHEMA_DEPTH {
        return Err(schema_error(
            path,
            format!("nesting exceeds the depth limit of {MAX_SCHEMA_DEPTH}"),
        ));
    }
    *nodes += 1;
    if *nodes > MAX_SCHEMA_NODES {
        return Err(schema_error(
            path,
            format!("schema exceeds the node limit of {MAX_SCHEMA_NODES}"),
        ));
    }
    if let (Some(minimum), Some(maximum)) = (schema.min_length, schema.max_length) {
        if minimum > maximum {
            return Err(schema_error(
                path,
                "`minLength` is greater than `maxLength`",
            ));
        }
    }
    if let (Some(minimum), Some(maximum)) = (schema.minimum, schema.maximum) {
        if minimum > maximum {
            return Err(schema_error(path, "`minimum` is greater than `maximum`"));
        }
        if !minimum.is_finite() || !maximum.is_finite() {
            return Err(schema_error(path, "numeric bounds must be finite"));
        }
    }
    for name in &schema.required {
        if !schema.properties.contains_key(name) {
            return Err(schema_error(
                path,
                format!("`required` names `{name}`, which is not a declared property"),
            ));
        }
    }
    for (name, child) in &schema.properties {
        check_schema(child, depth + 1, nodes, &child_path(path, name))?;
    }
    if let Some(items) = &schema.items {
        check_schema(items, depth + 1, nodes, &format!("{path}.items"))?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Value validation
// ---------------------------------------------------------------------------

/// Validate one JSON value against a schema.
///
/// The error code is `zero.fnd.invalid_input` and the message starts with a
/// JSON path such as `$.items[1].name`. Schemas that fail
/// [`validate_schema`] are refused before the value is inspected.
pub fn validate(schema: &Schema, value: &Value) -> Result<()> {
    validate_schema(schema)?;
    validate_at(schema, value, "$", 0)
}

fn validate_at(schema: &Schema, value: &Value, path: &str, depth: usize) -> Result<()> {
    if depth > MAX_VALUE_DEPTH {
        return Err(value_error(
            path,
            format!("nesting exceeds the depth limit of {MAX_VALUE_DEPTH}"),
        ));
    }

    if !schema.enum_values.is_empty()
        && !schema
            .enum_values
            .iter()
            .any(|candidate| json_equal(candidate, value))
    {
        return Err(value_error(path, "is not one of the allowed enum values"));
    }

    if let Some(kind) = schema.kind {
        if !matches_kind(kind, value) {
            return Err(value_error(
                path,
                format!("expected {}, found {}", kind.as_str(), value_kind(value)),
            ));
        }
    }

    match value {
        Value::String(text) => {
            let length = text.chars().count();
            if let Some(minimum) = schema.min_length {
                if length < minimum {
                    return Err(value_error(
                        path,
                        format!("string has {length} characters, minimum is {minimum}"),
                    ));
                }
            }
            if let Some(maximum) = schema.max_length {
                if length > maximum {
                    return Err(value_error(
                        path,
                        format!("string has {length} characters, maximum is {maximum}"),
                    ));
                }
            }
        }
        Value::Number(number) => {
            let value = number
                .as_f64()
                .ok_or_else(|| value_error(path, "number is out of the supported range"))?;
            check_number_bounds(path, value, schema.minimum, schema.maximum)?;
        }
        Value::Array(items) => {
            if let Some(maximum) = schema.max_items {
                if items.len() > maximum {
                    return Err(value_error(
                        path,
                        format!("array has {} items, maximum is {maximum}", items.len()),
                    ));
                }
            }
            if let Some(item_schema) = &schema.items {
                for (index, item) in items.iter().enumerate() {
                    validate_at(item_schema, item, &format!("{path}[{index}]"), depth + 1)?;
                }
            }
        }
        Value::Object(object) => {
            for name in &schema.required {
                if !object.contains_key(name) {
                    return Err(value_error(
                        &child_path(path, name),
                        "required property is missing",
                    ));
                }
            }
            for (name, child) in object {
                if let Some(child_schema) = schema.properties.get(name) {
                    validate_at(child_schema, child, &child_path(path, name), depth + 1)?;
                } else if !schema.additional_properties {
                    return Err(value_error(
                        &child_path(path, name),
                        "additional properties are not allowed",
                    ));
                }
            }
        }
        Value::Bool(_) | Value::Null => {}
    }
    Ok(())
}

fn check_number_bounds(
    path: &str,
    value: f64,
    minimum: Option<f64>,
    maximum: Option<f64>,
) -> Result<()> {
    if !value.is_finite() {
        return Err(value_error(path, "non-finite numbers are not allowed"));
    }
    if let Some(minimum) = minimum {
        if value < minimum {
            return Err(value_error(
                path,
                format!("{value} is less than the minimum {minimum}"),
            ));
        }
    }
    if let Some(maximum) = maximum {
        if value > maximum {
            return Err(value_error(
                path,
                format!("{value} is greater than the maximum {maximum}"),
            ));
        }
    }
    Ok(())
}

fn matches_kind(kind: SchemaType, value: &Value) -> bool {
    match kind {
        SchemaType::String => value.is_string(),
        SchemaType::Number => value.is_number(),
        SchemaType::Integer => match value {
            Value::Number(number) => {
                number.as_i64().is_some()
                    || number.as_u64().is_some()
                    || number
                        .as_f64()
                        .is_some_and(|number| number.is_finite() && number.fract() == 0.0)
            }
            _ => false,
        },
        SchemaType::Boolean => value.is_boolean(),
        SchemaType::Array => value.is_array(),
        SchemaType::Object => value.is_object(),
        SchemaType::Null => value.is_null(),
    }
}

fn value_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

/// Numeric-aware JSON equality: `1` and `1.0` are the same value, as JSON
/// Schema requires for `enum` and `const`-style comparisons.
fn json_equal(left: &Value, right: &Value) -> bool {
    match (left, right) {
        (Value::Number(left), Value::Number(right)) => numbers_equal(left, right),
        _ => left == right,
    }
}

fn numbers_equal(left: &Number, right: &Number) -> bool {
    if let (Some(left), Some(right)) = (left.as_i64(), right.as_i64()) {
        return left == right;
    }
    if let (Some(left), Some(right)) = (left.as_u64(), right.as_u64()) {
        return left == right;
    }
    match (left.as_f64(), right.as_f64()) {
        (Some(left), Some(right)) => left == right,
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// JSON extraction
// ---------------------------------------------------------------------------

/// A mapped value plus the optional properties that were absent.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Extraction {
    /// The extracted JSON value, already validated against the schema.
    pub value: Value,
    /// JSON paths of optional schema properties that the source did not
    /// contain, sorted deterministically.
    pub missing: Vec<String>,
}

/// Map a JSON object onto a schema and validate the result.
///
/// Only schema-declared properties are copied, in schema order; source keys
/// outside the schema are ignored. Nested objects recurse through
/// `properties`, and arrays recurse through `items`. A missing required
/// property is an error; a missing optional property is listed in
/// [`Extraction::missing`] and omitted. An object schema with no declared
/// properties (and `additionalProperties` allowed) copies the source object
/// unchanged.
pub fn extract(document: &Value, schema: &Schema) -> Result<Extraction> {
    validate_schema(schema)?;
    if !document.is_object() {
        return Err(value_error(
            "$",
            format!(
                "extraction source must be a JSON object, found {}",
                value_kind(document)
            ),
        ));
    }
    let mut missing = BTreeSet::new();
    let value = map_value(document, schema, "$", 0, &mut missing)?;
    validate(schema, &value)?;
    Ok(Extraction {
        value,
        missing: missing.into_iter().collect(),
    })
}

fn map_value(
    value: &Value,
    schema: &Schema,
    path: &str,
    depth: usize,
    missing: &mut BTreeSet<String>,
) -> Result<Value> {
    if depth > MAX_VALUE_DEPTH {
        return Err(value_error(
            path,
            format!("nesting exceeds the depth limit of {MAX_VALUE_DEPTH}"),
        ));
    }
    match schema.kind {
        Some(SchemaType::Object) => {
            if !value.is_object() {
                return Err(value_error(
                    path,
                    format!(
                        "expected object for extraction, found {}",
                        value_kind(value)
                    ),
                ));
            }
            map_object(value, schema, path, depth, missing)
        }
        Some(SchemaType::Array) => {
            if !value.is_array() {
                return Err(value_error(
                    path,
                    format!("expected array for extraction, found {}", value_kind(value)),
                ));
            }
            map_array(value, schema, path, depth, missing)
        }
        Some(_) => Ok(value.clone()),
        None if !schema.properties.is_empty() => {
            if !value.is_object() {
                return Err(value_error(
                    path,
                    format!(
                        "expected object for extraction, found {}",
                        value_kind(value)
                    ),
                ));
            }
            map_object(value, schema, path, depth, missing)
        }
        None => {
            if let (Some(item_schema), Value::Array(items)) = (&schema.items, value) {
                return map_array_items(items, item_schema, path, depth, missing);
            }
            Ok(value.clone())
        }
    }
}

fn map_object(
    value: &Value,
    schema: &Schema,
    path: &str,
    depth: usize,
    missing: &mut BTreeSet<String>,
) -> Result<Value> {
    let Some(object) = value.as_object() else {
        return Err(value_error(path, "expected an object"));
    };
    if schema.properties.is_empty() && schema.additional_properties {
        return Ok(value.clone());
    }
    let mut mapped = Map::new();
    for (name, child_schema) in &schema.properties {
        let child = child_path(path, name);
        match object.get(name) {
            Some(value) => {
                mapped.insert(
                    name.clone(),
                    map_value(value, child_schema, &child, depth + 1, missing)?,
                );
            }
            None if schema.required.contains(name) => {
                return Err(value_error(&child, "required property is missing"));
            }
            None => {
                missing.insert(child);
            }
        }
    }
    Ok(Value::Object(mapped))
}

fn map_array(
    value: &Value,
    schema: &Schema,
    path: &str,
    depth: usize,
    missing: &mut BTreeSet<String>,
) -> Result<Value> {
    let Some(items) = value.as_array() else {
        return Err(value_error(path, "expected an array"));
    };
    match &schema.items {
        Some(item_schema) => map_array_items(items, item_schema, path, depth, missing),
        None => Ok(value.clone()),
    }
}

fn map_array_items(
    items: &[Value],
    item_schema: &Schema,
    path: &str,
    depth: usize,
    missing: &mut BTreeSet<String>,
) -> Result<Value> {
    let mut mapped = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        mapped.push(map_value(
            item,
            item_schema,
            &format!("{path}[{index}]"),
            depth + 1,
            missing,
        )?);
    }
    Ok(Value::Array(mapped))
}

// ---------------------------------------------------------------------------
// HTML extraction
// ---------------------------------------------------------------------------

/// Extract structured fields from an HTML document and validate them.
///
/// Mapping: `title`, `meta` (`name=` or `property=` selects a property and
/// `content=` is its value), `h1` to `heading`, `a href` to `url` and `link`,
/// and any element with `data-zero-field="name"` to that property. The first
/// occurrence of a field wins. See the module docs and `docs/web.md` for the
/// tokenizer subset and limits.
pub fn extract_html(html: &str, schema: &Schema) -> Result<Extraction> {
    validate_schema(schema)?;
    if html.len() > MAX_SOURCE_BYTES {
        return Err(invalid(format!(
            "HTML source has {} bytes, limit is {MAX_SOURCE_BYTES}",
            html.len()
        )));
    }
    let fields = html_fields(html, schema)?;
    let document = Value::Object(fields.into_iter().collect());
    extract(&document, schema)
}

struct Capture {
    field: String,
    depth: usize,
    text: String,
    chars: usize,
}

fn html_fields(html: &str, schema: &Schema) -> Result<BTreeMap<String, Value>> {
    let bytes = html.as_bytes();
    let mut fields: BTreeMap<String, Value> = BTreeMap::new();
    let mut stack: Vec<String> = Vec::new();
    let mut captures: Vec<Capture> = Vec::new();
    let mut index = 0usize;
    let mut tags = 0usize;

    while index < bytes.len() {
        if bytes[index] != b'<' {
            let end = find_byte(bytes, index, b'<').unwrap_or(bytes.len());
            append_text(&html[index..end], &mut captures)?;
            index = end;
            continue;
        }
        let rest = &html[index..];
        if rest.starts_with("<!--") {
            index = rest
                .find("-->")
                .map(|offset| index + offset + "-->".len())
                .unwrap_or(bytes.len());
            continue;
        }
        if rest.starts_with("<!") {
            index = find_byte(bytes, index, b'>')
                .map(|position| position + 1)
                .unwrap_or(bytes.len());
            continue;
        }
        if rest.starts_with("<?") {
            index = rest
                .find("?>")
                .map(|offset| index + offset + "?>".len())
                .unwrap_or(bytes.len());
            continue;
        }

        let is_end = bytes.get(index + 1) == Some(&b'/');
        let name_start = index + if is_end { 2 } else { 1 };
        if !bytes.get(name_start).is_some_and(u8::is_ascii_alphabetic) {
            append_text("<", &mut captures)?;
            index += 1;
            continue;
        }

        tags += 1;
        if tags > MAX_HTML_TAGS {
            return Err(invalid(format!("HTML has more than {MAX_HTML_TAGS} tags")));
        }

        if is_end {
            let (name, next) = parse_end_tag(html, index);
            index = next;
            if let Some(position) = stack.iter().rposition(|open| *open == name) {
                stack.truncate(position);
            }
            while captures
                .last()
                .is_some_and(|capture| capture.depth > stack.len())
            {
                if let Some(capture) = captures.pop() {
                    finish_capture(capture, &mut fields, schema);
                }
            }
            continue;
        }

        let tag = parse_start_tag(html, index)?;
        index = tag.next;

        if matches!(tag.name.as_str(), "script" | "style") && !tag.self_closing {
            index = skip_raw_text(html, index, &tag.name);
            continue;
        }

        if tag.name == "meta" {
            if let Some(content) = tag.attrs.get("content") {
                for key in ["name", "property"] {
                    if let Some(field) = tag.attrs.get(key) {
                        if !fields.contains_key(field) {
                            set_field(&mut fields, schema, field, content.clone());
                        }
                    }
                }
            }
        }
        if tag.name == "a" {
            if let Some(href) = tag.attrs.get("href") {
                set_field(&mut fields, schema, "url", href.clone());
                set_field(&mut fields, schema, "link", href.clone());
            }
        }

        let void = is_void(&tag.name);
        if !tag.self_closing && tag.name == "title" {
            begin_capture(&mut captures, &fields, schema, "title", stack.len() + 1);
        }
        if !tag.self_closing && tag.name == "h1" {
            begin_capture(&mut captures, &fields, schema, "heading", stack.len() + 1);
        }
        if let Some(field) = tag.attrs.get("data-zero-field") {
            if void || tag.self_closing {
                let value = tag
                    .attrs
                    .get("content")
                    .or_else(|| tag.attrs.get("value"))
                    .cloned()
                    .unwrap_or_default();
                set_field(&mut fields, schema, field, value);
            } else {
                begin_capture(&mut captures, &fields, schema, field, stack.len() + 1);
            }
        }

        if !void && !tag.self_closing {
            stack.push(tag.name);
        }
    }

    while let Some(capture) = captures.pop() {
        finish_capture(capture, &mut fields, schema);
    }
    Ok(fields)
}

pub(crate) struct StartTag {
    pub(crate) name: String,
    pub(crate) attrs: BTreeMap<String, String>,
    pub(crate) self_closing: bool,
    pub(crate) next: usize,
}

pub(crate) fn parse_start_tag(html: &str, start: usize) -> Result<StartTag> {
    let bytes = html.as_bytes();
    let mut index = start + 1;
    let name_start = index;
    while index < bytes.len() && is_name_byte(bytes[index]) {
        index += 1;
    }
    let name = html[name_start..index].to_ascii_lowercase();
    let mut attrs: BTreeMap<String, String> = BTreeMap::new();
    let mut self_closing = false;

    loop {
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let Some(&byte) = bytes.get(index) else {
            break;
        };
        if byte == b'>' {
            index += 1;
            break;
        }
        if byte == b'/' {
            self_closing = bytes.get(index + 1) == Some(&b'>');
            index += if self_closing { 2 } else { 1 };
            if self_closing {
                break;
            }
            continue;
        }

        let attr_start = index;
        while index < bytes.len()
            && !bytes[index].is_ascii_whitespace()
            && !matches!(bytes[index], b'=' | b'/' | b'>')
        {
            index += 1;
        }
        if index == attr_start {
            index += 1;
            continue;
        }
        let attr_name = html[attr_start..index].to_ascii_lowercase();
        while index < bytes.len() && bytes[index].is_ascii_whitespace() {
            index += 1;
        }
        let mut attr_value = String::new();
        if bytes.get(index) == Some(&b'=') {
            index += 1;
            while index < bytes.len() && bytes[index].is_ascii_whitespace() {
                index += 1;
            }
            match bytes.get(index) {
                Some(&quote @ (b'"' | b'\'')) => {
                    index += 1;
                    let value_start = index;
                    while index < bytes.len() && bytes[index] != quote {
                        index += 1;
                    }
                    attr_value = html[value_start..index].to_string();
                    if index < bytes.len() {
                        index += 1;
                    }
                }
                _ => {
                    let value_start = index;
                    while index < bytes.len()
                        && !bytes[index].is_ascii_whitespace()
                        && bytes[index] != b'>'
                    {
                        index += 1;
                    }
                    attr_value = html[value_start..index].to_string();
                }
            }
        }
        if attr_value.len() > MAX_ATTRIBUTE_CHARS {
            return Err(invalid(format!(
                "attribute `{attr_name}` exceeds {MAX_ATTRIBUTE_CHARS} bytes"
            )));
        }
        if !attrs.contains_key(&attr_name) {
            if attrs.len() >= MAX_ATTRIBUTES_PER_TAG {
                return Err(invalid(format!(
                    "tag `<{name}>` has more than {MAX_ATTRIBUTES_PER_TAG} attributes"
                )));
            }
            attrs.insert(attr_name, decode_entities(&attr_value).trim().to_string());
        }
    }

    Ok(StartTag {
        name,
        attrs,
        self_closing,
        next: index,
    })
}

pub(crate) fn parse_end_tag(html: &str, start: usize) -> (String, usize) {
    let bytes = html.as_bytes();
    let mut index = start + 2;
    while index < bytes.len() && bytes[index].is_ascii_whitespace() {
        index += 1;
    }
    let name_start = index;
    while index < bytes.len() && is_name_byte(bytes[index]) {
        index += 1;
    }
    let name = html[name_start..index].to_ascii_lowercase();
    let next = find_byte(bytes, index, b'>')
        .map(|position| position + 1)
        .unwrap_or(bytes.len());
    (name, next)
}

pub(crate) fn skip_raw_text(html: &str, from: usize, tag: &str) -> usize {
    let needle = format!("</{tag}");
    match find_ignore_ascii_case(html, from, &needle) {
        Some(position) => find_byte(html.as_bytes(), position, b'>')
            .map(|position| position + 1)
            .unwrap_or(html.len()),
        None => html.len(),
    }
}

fn begin_capture(
    captures: &mut Vec<Capture>,
    fields: &BTreeMap<String, Value>,
    schema: &Schema,
    field: &str,
    depth: usize,
) {
    if schema.properties.contains_key(field) && !fields.contains_key(field) {
        captures.push(Capture {
            field: field.to_string(),
            depth,
            text: String::new(),
            chars: 0,
        });
    }
}

fn finish_capture(capture: Capture, fields: &mut BTreeMap<String, Value>, schema: &Schema) {
    if schema.properties.contains_key(&capture.field) {
        fields
            .entry(capture.field)
            .or_insert_with(|| Value::String(normalize_text(&capture.text)));
    }
}

fn append_text(text: &str, captures: &mut [Capture]) -> Result<()> {
    if captures.is_empty() {
        return Ok(());
    }
    let decoded = decode_entities(text);
    let chars = decoded.chars().count();
    for capture in captures.iter_mut() {
        if capture.chars + chars > MAX_FIELD_CHARS {
            return Err(invalid(format!(
                "HTML field `{}` exceeds {MAX_FIELD_CHARS} characters",
                capture.field
            )));
        }
        capture.chars += chars;
        capture.text.push_str(&decoded);
    }
    Ok(())
}

/// Trim the ends and collapse every whitespace run to one space. HTML fields
/// such as a title split across lines become a single readable line.
pub(crate) fn normalize_text(text: &str) -> String {
    let mut normalized = String::with_capacity(text.len());
    let mut pending_space = false;
    for character in text.chars() {
        if character.is_whitespace() {
            pending_space = !normalized.is_empty();
        } else {
            if pending_space {
                normalized.push(' ');
                pending_space = false;
            }
            normalized.push(character);
        }
    }
    normalized
}

fn set_field(fields: &mut BTreeMap<String, Value>, schema: &Schema, name: &str, value: String) {
    if schema.properties.contains_key(name) {
        fields
            .entry(name.to_string())
            .or_insert_with(|| Value::String(value));
    }
}

pub(crate) fn is_void(name: &str) -> bool {
    matches!(
        name,
        "area"
            | "base"
            | "br"
            | "col"
            | "embed"
            | "hr"
            | "img"
            | "input"
            | "link"
            | "meta"
            | "param"
            | "source"
            | "track"
            | "wbr"
    )
}

fn is_name_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b':')
}

pub(crate) fn find_byte(haystack: &[u8], from: usize, needle: u8) -> Option<usize> {
    if from >= haystack.len() {
        return None;
    }
    haystack[from..]
        .iter()
        .position(|byte| *byte == needle)
        .map(|offset| from + offset)
}

pub(crate) fn find_ignore_ascii_case(haystack: &str, from: usize, needle: &str) -> Option<usize> {
    let bytes = haystack.as_bytes();
    let needle = needle.as_bytes();
    if needle.is_empty() || from >= bytes.len() || bytes.len() - from < needle.len() {
        return None;
    }
    (from..=bytes.len() - needle.len()).find(|&start| {
        bytes[start..start + needle.len()]
            .iter()
            .zip(needle)
            .all(|(left, right)| left.eq_ignore_ascii_case(right))
    })
}

// ---------------------------------------------------------------------------
// Content-type dispatch
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContentKind {
    Json,
    Html,
    Text,
}

/// Extract from a body using a content type or file extension.
///
/// Accepted values (case-insensitive, parameters after `;` ignored):
///
/// - JSON: `application/json`, `text/json`, any `*+json`, `json`, `.json`.
/// - HTML: `text/html`, `application/xhtml+xml`, `html`, `htm`, `xhtml`.
/// - Text: `text/plain`, any other `text/*`, `text`, `txt`.
///
/// Text maps the whole body to a schema property named `text` when the schema
/// declares one; otherwise the body contributes nothing and the usual
/// required/optional rules apply.
pub fn extract_from_content_type(
    content_type_or_extension: &str,
    body: &str,
    schema: &Schema,
) -> Result<Extraction> {
    validate_schema(schema)?;
    let kind = content_kind(content_type_or_extension).ok_or_else(|| {
        invalid(format!(
            "unsupported content type or extension `{}`; expected JSON, HTML, or text",
            content_type_or_extension.trim()
        ))
    })?;
    match kind {
        ContentKind::Json => {
            let document: Value = serde_json::from_str(body)
                .map_err(|error| invalid(format!("body is not valid JSON: {error}")))?;
            extract(&document, schema)
        }
        ContentKind::Html => extract_html(body, schema),
        ContentKind::Text => extract_text(body, schema),
    }
}

fn content_kind(value: &str) -> Option<ContentKind> {
    let essence = value
        .trim()
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .trim_start_matches('.')
        .to_ascii_lowercase();
    match essence.as_str() {
        "application/json" | "text/json" | "json" => Some(ContentKind::Json),
        "text/html" | "application/xhtml+xml" | "html" | "htm" | "xhtml" => Some(ContentKind::Html),
        "text/plain" | "text" | "txt" => Some(ContentKind::Text),
        _ if essence.ends_with("+json") => Some(ContentKind::Json),
        _ if essence.starts_with("text/") => Some(ContentKind::Text),
        _ => None,
    }
}

fn extract_text(body: &str, schema: &Schema) -> Result<Extraction> {
    if body.len() > MAX_SOURCE_BYTES {
        return Err(invalid(format!(
            "text source has {} bytes, limit is {MAX_SOURCE_BYTES}",
            body.len()
        )));
    }
    let mut document = Map::new();
    if schema.properties.contains_key("text") {
        document.insert("text".to_string(), Value::String(body.to_string()));
    }
    extract(&Value::Object(document), schema)
}

// ---------------------------------------------------------------------------
// URL map
// ---------------------------------------------------------------------------

/// Limits for [`map_urls`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MapLimits {
    /// Maximum number of URLs in the result. `0` yields an empty map.
    pub max_urls: usize,
    /// Maximum accepted URLs taken from one page's link list. Sitemap bodies
    /// are bounded by `max_urls` instead.
    pub max_per_page: usize,
    /// Whether links on subdomains of the seed host are kept.
    pub allow_subdomains: bool,
}

impl Default for MapLimits {
    fn default() -> Self {
        Self {
            max_urls: DEFAULT_MAX_URLS,
            max_per_page: DEFAULT_MAX_PER_PAGE,
            allow_subdomains: false,
        }
    }
}

/// Discovered URLs plus per-source counters.
///
/// `urls` is sorted lexicographically. The seed itself is not included; it is
/// only the base for relative links and the host filter. Counts describe
/// candidates, so `sitemap_urls + link_urls + duplicates + offsite + invalid +
/// over_limit == candidates` after a successful seed parse.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UrlMap {
    /// The seed as supplied (trimmed), or the supplied text when invalid.
    pub seed: String,
    /// Whether the seed was an absolute http(s) URL with a host.
    pub seed_valid: bool,
    /// Accepted URLs, sorted lexicographically.
    pub urls: Vec<String>,
    /// Unique URLs contributed by sitemap bodies.
    pub sitemap_urls: usize,
    /// Unique URLs contributed by page link lists.
    pub link_urls: usize,
    /// Candidates already seen (within or across sources).
    pub duplicates: usize,
    /// Candidates on another host.
    pub offsite: usize,
    /// Candidates that were not valid absolute http(s) URLs.
    pub invalid: usize,
    /// Unique valid candidates dropped by `max_urls` or `max_per_page`.
    pub over_limit: usize,
    /// Total candidates examined (or expected, when the seed is invalid).
    pub candidates: usize,
}

/// Discover URLs from sitemap bodies and fetched page-link lists.
///
/// Sitemap `<loc>` values are read with the crawl module's public scanner; a
/// relative location resolves against the seed. Every link is resolved against
/// the seed, filtered to the seed's exact host (or its subdomains with
/// [`MapLimits::allow_subdomains`]), and deduplicated by
/// [`canonical_url_key`], so query strings and trailing slashes collapse. No
/// network access happens: sitemap bodies and link lists are supplied by the
/// caller.
///
/// An invalid seed yields `seed_valid == false`, no URLs, and every candidate
/// counted as invalid. A sitemap body larger than [`MAX_SOURCE_BYTES`] is
/// counted as one invalid candidate without being scanned.
pub fn map_urls(
    seed: &str,
    sitemap_bodies: &[String],
    page_links: &[Vec<String>],
    limits: &MapLimits,
) -> UrlMap {
    let mut map = UrlMap {
        seed: seed.trim().to_string(),
        seed_valid: false,
        urls: Vec::new(),
        sitemap_urls: 0,
        link_urls: 0,
        duplicates: 0,
        offsite: 0,
        invalid: 0,
        over_limit: 0,
        candidates: 0,
    };

    let Some(seed_host) = url_host(seed) else {
        map.candidates = sitemap_bodies
            .iter()
            .map(|body| sitemap_locs(body).len())
            .sum::<usize>()
            + page_links.iter().map(Vec::len).sum::<usize>();
        map.invalid = map.candidates;
        return map;
    };
    map.seed_valid = true;
    let base = seed.trim();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();

    for body in sitemap_bodies {
        if body.len() > MAX_SOURCE_BYTES {
            map.candidates += 1;
            map.invalid += 1;
            continue;
        }
        let locations = sitemap_locs(body);
        map.candidates += locations.len();
        for location in locations {
            match add_candidate(&location, base, &seed_host, limits, &mut seen) {
                Candidate::Added => map.sitemap_urls += 1,
                Candidate::Duplicate => map.duplicates += 1,
                Candidate::Offsite => map.offsite += 1,
                Candidate::Invalid => map.invalid += 1,
                Candidate::OverLimit => map.over_limit += 1,
            }
        }
    }

    for links in page_links {
        let mut accepted = 0usize;
        map.candidates += links.len();
        for link in links {
            if accepted >= limits.max_per_page {
                map.over_limit += 1;
                continue;
            }
            match add_candidate(link, base, &seed_host, limits, &mut seen) {
                Candidate::Added => {
                    accepted += 1;
                    map.link_urls += 1;
                }
                Candidate::Duplicate => map.duplicates += 1,
                Candidate::Offsite => map.offsite += 1,
                Candidate::Invalid => map.invalid += 1,
                Candidate::OverLimit => map.over_limit += 1,
            }
        }
    }

    let mut urls: Vec<String> = seen.into_values().collect();
    urls.sort();
    map.urls = urls;
    map
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Candidate {
    Added,
    Duplicate,
    Offsite,
    Invalid,
    OverLimit,
}

fn add_candidate(
    raw: &str,
    base: &str,
    seed_host: &str,
    limits: &MapLimits,
    seen: &mut BTreeMap<String, String>,
) -> Candidate {
    let Some(resolved) = resolve_link(base, raw) else {
        return Candidate::Invalid;
    };
    let Some(host) = url_host(&resolved) else {
        return Candidate::Invalid;
    };
    if !host_matches(seed_host, &host, limits.allow_subdomains) {
        return Candidate::Offsite;
    }
    let key = canonical_url_key(&resolved);
    if key.is_empty() {
        return Candidate::Invalid;
    }
    if seen.contains_key(&key) {
        return Candidate::Duplicate;
    }
    if seen.len() >= limits.max_urls {
        return Candidate::OverLimit;
    }
    seen.insert(key, resolved);
    Candidate::Added
}

fn host_matches(seed_host: &str, host: &str, allow_subdomains: bool) -> bool {
    if host == seed_host {
        return true;
    }
    allow_subdomains
        && host
            .strip_suffix(seed_host)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

/// Lowercased host of an absolute http(s) URL, with any port removed.
///
/// IPv6 literals keep their brackets. A URL with userinfo, another scheme, or
/// no host yields `None`.
fn url_host(url: &str) -> Option<String> {
    let url = url.trim();
    let (scheme, rest) = url.split_once("://")?;
    if !scheme.eq_ignore_ascii_case("http") && !scheme.eq_ignore_ascii_case("https") {
        return None;
    }
    let rest = rest.split('#').next().unwrap_or("");
    let cut = rest.find(['/', '?']).unwrap_or(rest.len());
    let authority = &rest[..cut];
    if authority.is_empty() || authority.contains('@') {
        return None;
    }
    let host = if let Some(end) = authority.strip_prefix('[').and_then(|rest| rest.find(']')) {
        &authority[..=end + 1]
    } else {
        authority
            .rsplit_once(':')
            .filter(|(_, port)| {
                !port.is_empty() && port.chars().all(|character| character.is_ascii_digit())
            })
            .map(|(host, _)| host)
            .unwrap_or(authority)
    };
    if host.is_empty() {
        return None;
    }
    Some(host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn schema(value: Value) -> Schema {
        Schema::parse(&value).expect("schema should parse")
    }

    fn error(schema: &Schema, value: &Value) -> ZeroError {
        validate(schema, value).expect_err("value should be invalid")
    }

    fn string_schema() -> Schema {
        schema(json!({"type": "object", "properties": {"name": {"type": "string"}}}))
    }

    fn sample_schema() -> Schema {
        schema(json!({
            "type": "object",
            "required": ["name", "items"],
            "properties": {
                "name": {"type": "string", "minLength": 1, "maxLength": 20},
                "age": {"type": "integer", "minimum": 0, "maximum": 130},
                "items": {
                    "type": "array",
                    "maxItems": 3,
                    "items": {
                        "type": "object",
                        "required": ["id"],
                        "properties": {
                            "id": {"type": "integer"},
                            "label": {"type": "string"}
                        }
                    }
                }
            }
        }))
    }

    // -- schema validation -------------------------------------------------

    #[test]
    fn every_supported_type_accepts_its_value_and_rejects_another() {
        let cases = [
            (json!({"type": "string"}), json!("x"), json!(1)),
            (json!({"type": "number"}), json!(1.5), json!("1.5")),
            (json!({"type": "integer"}), json!(2), json!(2.5)),
            (json!({"type": "boolean"}), json!(true), json!(0)),
            (json!({"type": "array"}), json!([1]), json!({})),
            (json!({"type": "object"}), json!({}), json!([])),
            (json!({"type": "null"}), Value::Null, json!("null")),
        ];
        for (schema_value, valid, invalid) in cases {
            let schema = schema(schema_value);
            validate(&schema, &valid).expect("valid value");
            let error = error(&schema, &invalid);
            assert_eq!(error.code(), ErrorCode::InvalidInput);
        }
    }

    #[test]
    fn integer_accepts_integral_floats() {
        let schema = schema(json!({"type": "integer"}));
        validate(&schema, &json!(2)).unwrap();
        validate(&schema, &json!(2.0)).unwrap();
        validate(&schema, &json!(-2.0)).unwrap();
        assert!(validate(&schema, &json!(2.5)).is_err());
    }

    #[test]
    fn required_and_additional_properties_are_enforced() {
        let closed = schema(json!({
            "type": "object",
            "required": ["a"],
            "additionalProperties": false,
            "properties": {"a": {"type": "string"}, "b": {"type": "number"}}
        }));
        validate(&closed, &json!({"a": "x", "b": 1})).unwrap();
        assert!(validate(&closed, &json!({"b": 1})).is_err());
        let extra = error(&closed, &json!({"a": "x", "z": true}));
        assert!(extra.message().contains("$.z"));
        assert!(extra.message().contains("additional properties"));

        let open = schema(json!({
            "type": "object",
            "properties": {"a": {"type": "string"}}
        }));
        validate(&open, &json!({"a": "x", "anything": {"deep": 1}})).unwrap();
    }

    #[test]
    fn enum_rejects_values_outside_the_set() {
        let schema = schema(json!({"enum": ["red", "green", 3]}));
        validate(&schema, &json!("red")).unwrap();
        validate(&schema, &json!(3)).unwrap();
        let error = error(&schema, &json!("blue"));
        assert!(error.message().contains("enum"));
    }

    #[test]
    fn enum_compares_numbers_by_value() {
        let schema = schema(json!({"enum": [1, 2.5]}));
        validate(&schema, &json!(1.0)).unwrap();
        validate(&schema, &json!(2.5)).unwrap();
        assert!(validate(&schema, &json!(2)).is_err());
    }

    #[test]
    fn string_length_limits_count_characters() {
        let schema = schema(json!({
            "type": "string",
            "minLength": 2,
            "maxLength": 4
        }));
        validate(&schema, &json!("ab")).unwrap();
        validate(&schema, &json!("abcd")).unwrap();
        validate(&schema, &json!("éééé")).unwrap();
        assert!(validate(&schema, &json!("a")).is_err());
        assert!(validate(&schema, &json!("abcde")).is_err());
    }

    #[test]
    fn number_bounds_are_inclusive() {
        let schema = schema(json!({"type": "number", "minimum": 1.5, "maximum": 2.5}));
        validate(&schema, &json!(1.5)).unwrap();
        validate(&schema, &json!(2.5)).unwrap();
        assert!(validate(&schema, &json!(1.49)).is_err());
        assert!(validate(&schema, &json!(2.51)).is_err());
    }

    #[test]
    fn arrays_check_max_items_and_each_item() {
        let schema = schema(json!({
            "type": "array",
            "maxItems": 2,
            "items": {"type": "integer"}
        }));
        validate(&schema, &json!([1, 2])).unwrap();
        assert!(validate(&schema, &json!([1, 2, 3])).is_err());
        let error = error(&schema, &json!([1, "two"]));
        assert!(error.message().contains("$[1]"));
    }

    #[test]
    fn json_path_appears_in_nested_errors() {
        let error = error(
            &sample_schema(),
            &json!({
                "name": "ok",
                "items": [{"id": 1}, {"id": 2, "label": 7}]
            }),
        );
        assert!(
            error.message().contains("$.items[1].label"),
            "message was {}",
            error.message()
        );
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn malformed_schemas_are_refused() {
        let cases = [
            json!([]),
            json!({"type": "text"}),
            json!({"type": ["string", "null"]}),
            json!({"minLength": -1}),
            json!({"maxItems": 1.5}),
            json!({"minLength": 5, "maxLength": 2}),
            json!({"minimum": 5, "maximum": 2}),
            json!({"required": ["missing"], "properties": {"present": {}}}),
            json!({"required": "name"}),
            json!({"items": "string"}),
            json!({"properties": []}),
            json!({"enum": []}),
            json!({"enum": ["a", "a"]}),
            json!({"enum": "a"}),
            json!({"additionalProperties": "yes"}),
        ];
        for value in cases {
            let error = Schema::parse(&value).expect_err("schema should be refused");
            assert_eq!(error.code(), ErrorCode::InvalidInput, "schema {value}");
            assert!(error.message().contains("invalid schema"));
        }
    }

    #[test]
    fn unknown_schema_keywords_are_ignored() {
        let schema = schema(json!({
            "type": "object",
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "title": "A person",
            "properties": {"email": {"type": "string", "format": "email"}}
        }));
        validate(&schema, &json!({"email": "not-really-an-email"})).unwrap();
    }

    #[test]
    fn schema_depth_and_size_are_bounded() {
        let mut deep = json!({"type": "string"});
        for _ in 0..=MAX_SCHEMA_DEPTH {
            deep = json!({"type": "object", "properties": {"next": deep}});
        }
        let error = Schema::parse(&deep).expect_err("depth must be bounded");
        assert!(error.message().contains("depth limit"));

        let mut properties = Map::new();
        for index in 0..MAX_SCHEMA_NODES {
            properties.insert(format!("p{index}"), json!({"type": "string"}));
        }
        let wide = json!({"type": "object", "properties": properties});
        let error = Schema::parse(&wide).expect_err("size must be bounded");
        assert!(error.message().contains("node limit"));
    }

    #[test]
    fn validate_schema_rechecks_hand_built_schemas() {
        let broken = Schema {
            kind: Some(SchemaType::Object),
            properties: BTreeMap::new(),
            required: BTreeSet::from(["missing".to_string()]),
            items: None,
            enum_values: Vec::new(),
            min_length: None,
            max_length: None,
            minimum: None,
            maximum: None,
            max_items: None,
            additional_properties: true,
        };
        let error = validate_schema(&broken).expect_err("missing property");
        assert!(error.message().contains("missing"));

        let negative_span = Schema {
            min_length: Some(4),
            max_length: Some(2),
            ..broken
        };
        assert!(validate_schema(&negative_span).is_err());
    }

    #[test]
    fn non_finite_numbers_are_refused_by_the_bound_check() {
        let error = check_number_bounds("$", f64::NAN, None, None).expect_err("NaN");
        assert!(error.message().contains("non-finite"));
        assert!(check_number_bounds("$", f64::INFINITY, None, None).is_err());
        check_number_bounds("$", 1.0, Some(0.0), Some(2.0)).unwrap();
    }

    // -- JSON extraction ---------------------------------------------------

    #[test]
    fn json_extraction_maps_nested_objects_and_arrays() {
        let extraction = extract(
            &json!({
                "name": "Ada",
                "age": 36,
                "items": [{"id": 1, "label": "one", "extra": true}, {"id": 2}],
                "noise": "ignored"
            }),
            &sample_schema(),
        )
        .expect("extraction");

        assert_eq!(
            extraction.value,
            json!({
                "name": "Ada",
                "age": 36,
                "items": [{"id": 1, "label": "one"}, {"id": 2}]
            })
        );
        assert_eq!(extraction.missing, ["$.items[1].label"]);
    }

    #[test]
    fn json_extraction_lists_optional_missing_fields() {
        let extraction =
            extract(&json!({"name": "Ada", "items": []}), &sample_schema()).expect("extraction");
        assert_eq!(extraction.value, json!({"name": "Ada", "items": []}));
        assert_eq!(extraction.missing, ["$.age"]);
    }

    #[test]
    fn json_extraction_missing_required_is_an_error() {
        let error =
            extract(&json!({"name": "Ada"}), &sample_schema()).expect_err("required field missing");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("$.items"));
        assert!(error.message().contains("required"));
    }

    #[test]
    fn json_extraction_requires_an_object_source() {
        let error = extract(&json!([1, 2]), &sample_schema()).expect_err("array source");
        assert!(error.message().contains("must be a JSON object"));
    }

    #[test]
    fn invalid_extraction_returns_the_typed_error_and_valid_one_revalidates() {
        let error = extract(
            &json!({"name": "Ada", "items": [{"id": "one"}]}),
            &sample_schema(),
        )
        .expect_err("id is a string");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("$.items[0].id"));

        let extraction = extract(
            &json!({"name": "Ada", "items": [{"id": 1}]}),
            &sample_schema(),
        )
        .expect("valid extraction");
        validate(&sample_schema(), &extraction.value).expect("extraction re-validates");
    }

    #[test]
    fn object_schema_without_properties_copies_the_source() {
        let schema = schema(json!({"type": "object"}));
        let extraction = extract(&json!({"anything": [1, 2]}), &schema).unwrap();
        assert_eq!(extraction.value, json!({"anything": [1, 2]}));
    }

    // -- HTML extraction ---------------------------------------------------

    fn page_schema() -> Schema {
        schema(json!({
            "type": "object",
            "required": ["title", "description"],
            "properties": {
                "title": {"type": "string"},
                "description": {"type": "string"},
                "heading": {"type": "string"},
                "author": {"type": "string"},
                "price": {"type": "string"},
                "url": {"type": "string"},
                "link": {"type": "string"}
            }
        }))
    }

    #[test]
    fn html_extracts_title_meta_heading_and_data_fields() {
        let html = r#"
            <html><head>
              <title>  Example &amp; Co
                Docs </title>
              <meta name="description" content="A &quot;small&quot; site">
              <meta property="author" content="Ada">
            </head><body>
              <h1>Welcome</h1>
              <span data-zero-field="price">  &euro; 5 </span>
            </body></html>
        "#;
        let extraction = extract_html(html, &page_schema()).expect("html extraction");
        assert_eq!(extraction.value["title"], "Example & Co Docs");
        assert_eq!(extraction.value["description"], "A \"small\" site");
        assert_eq!(extraction.value["heading"], "Welcome");
        assert_eq!(extraction.value["author"], "Ada");
        assert_eq!(extraction.value["price"], "&euro; 5");
        assert!(extraction.missing.contains(&"$.url".to_string()));
    }

    #[test]
    fn html_ignores_scripts_styles_and_comments() {
        let html = r#"
            <title>Real</title>
            <!-- <title>Comment</title> -->
            <script>document.write('<title>Script</title>');
              <meta name="description" content="fake"> </script>
            <style>body { content: '<h1>Style</h1>'; }</style>
            <meta name="description" content="Real description">
        "#;
        let extraction = extract_html(html, &page_schema()).expect("html extraction");
        assert_eq!(extraction.value["title"], "Real");
        assert_eq!(extraction.value["description"], "Real description");
        assert!(extraction.value.get("heading").is_none());
    }

    #[test]
    fn html_handles_void_and_self_closing_tags() {
        let schema = schema(json!({
            "type": "object",
            "properties": {
                "description": {"type": "string"},
                "sku": {"type": "string"},
                "heading": {"type": "string"}
            }
        }));
        let html = r#"
            <meta name="description" content="Void meta">
            <br><img src="x.png" alt="x" />
            <input data-zero-field="sku" value="ABC-1" />
            <div data-zero-field="heading"/>Not text</div>
        "#;
        let extraction = extract_html(html, &schema).expect("html extraction");
        assert_eq!(extraction.value["description"], "Void meta");
        assert_eq!(extraction.value["sku"], "ABC-1");
        assert_eq!(extraction.value["heading"], "");
    }

    #[test]
    fn html_duplicate_fields_keep_the_first() {
        let html = r#"
            <title>First</title><title>Second</title>
            <meta name="description" content="Only">
            <h1>One</h1><h1>Two</h1>
            <a href="/first">one</a><a href="/second">two</a>
        "#;
        let extraction = extract_html(html, &page_schema()).expect("html extraction");
        assert_eq!(extraction.value["title"], "First");
        assert_eq!(extraction.value["heading"], "One");
        assert_eq!(extraction.value["url"], "/first");
        assert_eq!(extraction.value["link"], "/first");
    }

    #[test]
    fn html_decodes_entities_in_text_and_href() {
        let schema = schema(json!({
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "url": {"type": "string"}
            }
        }));
        let html = "<title>1 &lt; 2 &amp;&amp; &#51; &gt; 2</title>\
                    <a href=\"/search?a=1&amp;b=2\">go</a>";
        let extraction = extract_html(html, &schema).expect("html extraction");
        assert_eq!(extraction.value["title"], "1 < 2 && 3 > 2");
        assert_eq!(extraction.value["url"], "/search?a=1&b=2");
    }

    #[test]
    fn html_missing_required_field_is_an_error() {
        let error = extract_html("<title>Only</title>", &page_schema())
            .expect_err("description is required");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("$.description"));
    }

    #[test]
    fn html_attribute_values_may_contain_angle_brackets() {
        let schema = schema(json!({
            "type": "object",
            "properties": {"description": {"type": "string"}}
        }));
        let html = r#"<meta name="description" content="a > b and <c>"></meta>"#;
        let extraction = extract_html(html, &schema).expect("html extraction");
        assert_eq!(extraction.value["description"], "a > b and <c>");
    }

    #[test]
    fn html_input_size_is_bounded() {
        let huge = "a".repeat(MAX_SOURCE_BYTES + 1);
        let error = extract_html(&huge, &string_schema()).expect_err("too large");
        assert!(error.message().contains("limit is"));
    }

    #[test]
    fn html_tag_count_is_bounded() {
        let html = "<b>x</b>".repeat(MAX_HTML_TAGS);
        let error = extract_html(&html, &string_schema()).expect_err("too many tags");
        assert!(error.message().contains("more than"));
    }

    #[test]
    fn html_field_length_is_bounded() {
        let html = format!("<title>{}</title>", "a".repeat(MAX_FIELD_CHARS + 1));
        let schema = schema(json!({
            "type": "object",
            "properties": {"title": {"type": "string"}}
        }));
        let error = extract_html(&html, &schema).expect_err("field too long");
        assert!(error.message().contains("exceeds"));
    }

    #[test]
    fn html_tolerates_unterminated_markup() {
        let schema = schema(json!({
            "type": "object",
            "properties": {"title": {"type": "string"}}
        }));
        let extraction = extract_html("<!-- open <title>Text", &schema).expect("tolerant");
        assert!(extraction.value.get("title").is_none());

        let extraction = extract_html("<title>Unclosed", &schema).expect("tolerant");
        assert_eq!(extraction.value["title"], "Unclosed");
    }

    // -- dispatch ----------------------------------------------------------

    #[test]
    fn content_dispatch_selects_json_html_and_text() {
        let schema = schema(json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"},
                "title": {"type": "string"},
                "text": {"type": "string", "minLength": 1}
            }
        }));
        let json_body = r#"{"name": "Ada", "extra": 1}"#;
        for content_type in ["application/json", "application/ld+json", "JSON", ".json"] {
            let extraction =
                extract_from_content_type(content_type, json_body, &schema).expect(content_type);
            assert_eq!(extraction.value["name"], "Ada");
        }

        let extraction =
            extract_from_content_type("text/html; charset=utf-8", "<title>Page</title>", &schema)
                .expect("html");
        assert_eq!(extraction.value["title"], "Page");

        let extraction = extract_from_content_type("text/plain", "hello", &schema).expect("text");
        assert_eq!(extraction.value["text"], "hello");
    }

    #[test]
    fn text_without_a_text_property_contributes_nothing() {
        let extraction =
            extract_from_content_type("txt", "ignored", &string_schema()).expect("text");
        assert_eq!(extraction.value, json!({}));
        assert_eq!(extraction.missing, ["$.name"]);
    }

    #[test]
    fn invalid_json_body_and_unknown_content_type_are_typed_errors() {
        let error = extract_from_content_type("application/json", "{oops", &string_schema())
            .expect_err("bad json");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("valid JSON"));

        let error = extract_from_content_type("application/pdf", "x", &string_schema())
            .expect_err("unsupported");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("unsupported"));
    }

    // -- URL map -----------------------------------------------------------

    fn sitemap(paths: &[&str]) -> String {
        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <urlset xmlns=\"http://www.sitemaps.org/schemas/sitemap/0.9\">",
        );
        for path in paths {
            body.push_str("<url><loc>");
            body.push_str(path);
            body.push_str("</loc></url>");
        }
        body.push_str("</urlset>");
        body
    }

    fn links(paths: &[&str]) -> Vec<String> {
        paths.iter().map(|path| (*path).to_string()).collect()
    }

    #[test]
    fn map_discovers_sitemaps_and_links_and_sorts() {
        let bodies = [sitemap(&[
            "/b",
            "https://example.com/a?x=1",
            "https://other.example/nope",
        ])];
        let pages = [links(&["/c", "mailto:x@example.com", "/d"])];
        let map = map_urls(
            "https://example.com/",
            &bodies,
            &pages,
            &MapLimits::default(),
        );

        assert!(map.seed_valid);
        assert_eq!(
            map.urls,
            [
                "https://example.com/a?x=1",
                "https://example.com/b",
                "https://example.com/c",
                "https://example.com/d"
            ]
        );
        assert_eq!(map.sitemap_urls, 2);
        assert_eq!(map.link_urls, 2);
        assert_eq!(map.offsite, 1);
        assert_eq!(map.invalid, 1);
        assert_eq!(map.candidates, 6);
    }

    #[test]
    fn map_resolves_relative_links_against_the_seed() {
        let bodies = [sitemap(&["relative", "../up", "?q=1"])];
        let pages = [links(&["docs/a", "./b", "//example.com/proto"])];
        let map = map_urls(
            "https://example.com/root/",
            &bodies,
            &pages,
            &MapLimits::default(),
        );
        assert_eq!(
            map.urls,
            [
                "https://example.com/proto",
                "https://example.com/root/?q=1",
                "https://example.com/root/b",
                "https://example.com/root/docs/a",
                "https://example.com/root/relative",
                "https://example.com/up"
            ]
        );
    }

    #[test]
    fn map_dedupes_queries_trailing_slashes_and_sources() {
        let bodies = [sitemap(&["/a?x=1", "/a?y=2", "/b/"])];
        let pages = [links(&["/a", "/b", "/c#frag"])];
        let map = map_urls(
            "https://example.com/",
            &bodies,
            &pages,
            &MapLimits::default(),
        );
        assert_eq!(
            map.urls,
            [
                "https://example.com/a?x=1",
                "https://example.com/b/",
                "https://example.com/c"
            ]
        );
        assert_eq!(map.sitemap_urls, 2);
        assert_eq!(map.link_urls, 1);
        assert_eq!(map.duplicates, 3);
    }

    #[test]
    fn map_keeps_only_the_exact_seed_host() {
        let bodies = [sitemap(&[
            "https://example.com/ok",
            "https://sub.example.com/no",
            "https://example.com.evil.test/no",
            "https://other.test/no",
        ])];
        let map = map_urls("https://example.com/", &bodies, &[], &MapLimits::default());
        assert_eq!(map.urls, ["https://example.com/ok"]);
        assert_eq!(map.offsite, 3);

        let map = map_urls(
            "https://example.com/",
            &bodies,
            &[],
            &MapLimits {
                allow_subdomains: true,
                ..MapLimits::default()
            },
        );
        assert_eq!(
            map.urls,
            ["https://example.com/ok", "https://sub.example.com/no"]
        );
        assert_eq!(map.offsite, 2);
    }

    #[test]
    fn map_applies_url_and_per_page_limits() {
        let bodies = [sitemap(&["/a", "/b", "/c"])];
        let pages = [links(&["/d", "/e", "/f"]), links(&["/g"])];
        let map = map_urls(
            "https://example.com/",
            &bodies,
            &pages,
            &MapLimits {
                max_urls: 6,
                max_per_page: 2,
                allow_subdomains: false,
            },
        );
        assert_eq!(
            map.urls,
            [
                "https://example.com/a",
                "https://example.com/b",
                "https://example.com/c",
                "https://example.com/d",
                "https://example.com/e",
                "https://example.com/g"
            ]
        );
        assert_eq!(map.over_limit, 1);
        assert_eq!(map.sitemap_urls, 3);
        assert_eq!(map.link_urls, 3);
    }

    #[test]
    fn map_zero_limits_produce_an_empty_map() {
        let map = map_urls(
            "https://example.com/",
            &[sitemap(&["/a"])],
            &[links(&["/b"])],
            &MapLimits {
                max_urls: 0,
                max_per_page: 0,
                allow_subdomains: false,
            },
        );
        assert!(map.urls.is_empty());
        assert_eq!(map.sitemap_urls, 0);
        assert_eq!(map.link_urls, 0);
        assert_eq!(map.over_limit, 2);
    }

    #[test]
    fn map_invalid_seed_reports_every_candidate_as_invalid() {
        let map = map_urls(
            "ftp://example.com/",
            &[sitemap(&["/a", "/b"])],
            &[links(&["/c"])],
            &MapLimits::default(),
        );
        assert!(!map.seed_valid);
        assert!(map.urls.is_empty());
        assert_eq!(map.candidates, 3);
        assert_eq!(map.invalid, 3);
    }

    #[test]
    fn map_accepts_empty_inputs_and_oversized_sitemaps() {
        let map = map_urls("https://example.com/", &[], &[], &MapLimits::default());
        assert!(map.seed_valid);
        assert!(map.urls.is_empty());
        assert_eq!(map.candidates, 0);

        let oversized = "a".repeat(MAX_SOURCE_BYTES + 1);
        let map = map_urls(
            "https://example.com/",
            &[oversized],
            &[],
            &MapLimits::default(),
        );
        assert_eq!(map.candidates, 1);
        assert_eq!(map.invalid, 1);
    }

    #[test]
    fn host_extraction_is_case_insensitive_and_drops_ports() {
        assert_eq!(
            url_host("HTTPS://Example.COM:8443/path"),
            Some("example.com".to_string())
        );
        assert_eq!(url_host("http://[::1]:8080/"), Some("[::1]".to_string()));
        assert_eq!(url_host("mailto:a@b.test"), None);
        assert_eq!(url_host("https://user:pw@example.com/"), None);
    }
}
