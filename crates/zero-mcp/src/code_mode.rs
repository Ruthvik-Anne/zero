//! MCP code mode (T-MCP-12, MCP-20).
//!
//! Code mode presents the tools in a [`crate::client::ToolCatalog`] as a typed
//! code API. A model writes a program against generated TypeScript or Python
//! stubs; the program runs in an injected [`CodeExecutor`]; every tool call goes
//! through [`CodeModeBridge`] so the host can apply policy, approval, replay and
//! size checks per call. Only the executor's final value is returned.
//!
//! Two server shapes are supported:
//!
//! - [`CodeModePattern::SingleTool`]: one `code` tool whose description embeds
//!   the generated API.
//! - [`CodeModePattern::SearchExecute`]: a read-only `search` tool that finds a
//!   tool by name/description plus an `execute` tool, for catalogues too large
//!   to embed.
//!
//! Nothing here launches a sandbox, a process, or a network connection. The
//! executor is the seam; the shipped implementation in tests is scripted.
//! Tool descriptions, generated stubs, search hits, arguments, and results are
//! untrusted data. Errors name tools, dimensions, and caps, never argument or
//! result payloads.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use serde_json::{json, Map, Value};
use zero_types::clock::{Clock, SystemClock};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::client::{Tool, ToolAnnotations, ToolCatalog};
use crate::security::{
    classify, decide, PolicyMode, ReplayGuard, ReplayOutcome, ResponseLimits, ToolDecision,
    ToolRisk,
};
use crate::server::ToolHost;

/// Default cap on generated declarations (64 KiB).
pub const DEFAULT_MAX_API_BYTES: usize = 64 * 1024;
/// Default cap on one tool description rendered into a declaration (bytes).
pub const DEFAULT_MAX_DESCRIPTION_BYTES: usize = 160;
/// Smallest declaration budget accepted. The fixed header must fit.
pub const MIN_MAX_API_BYTES: usize = 128;
/// Catalogue size at which the search/execute shape is chosen by default.
pub const DEFAULT_SEARCH_EXECUTE_THRESHOLD: usize = 20;

/// Default code source cap (256 KiB).
pub const DEFAULT_MAX_SOURCE_BYTES: usize = 256 * 1024;
/// Default final result cap (1 MiB).
pub const DEFAULT_MAX_RESULT_BYTES: usize = 1024 * 1024;
/// Default bound on bridge calls in one program.
pub const DEFAULT_MAX_CALLS: usize = 64;
/// Default bound on one call's arguments (64 KiB).
pub const DEFAULT_MAX_ARGUMENT_BYTES: usize = 64 * 1024;
/// Default argument nesting depth; the root is depth 0.
pub const DEFAULT_MAX_ARGUMENT_DEPTH: usize = 32;
/// Default number of search hits returned.
pub const DEFAULT_MAX_SEARCH_HITS: usize = 16;

/// Deepest schema nesting rendered as a concrete type. Deeper schemas fall
/// back to `unknown` / `Any`.
pub const MAX_TYPE_DEPTH: usize = 6;
/// Search description cap (bytes).
pub const MAX_SEARCH_DESCRIPTION_BYTES: usize = 16 * 1024;
/// Example cap (bytes).
pub const MAX_EXAMPLE_BYTES: usize = 2048;

/// Names of the generated server tools.
pub const CODE_TOOL_NAME: &str = "code";
/// Search tool name in the search/execute shape.
pub const SEARCH_TOOL_NAME: &str = "search";
/// Execute tool name in the search/execute shape.
pub const EXECUTE_TOOL_NAME: &str = "execute";

// ---------------------------------------------------------------------------
// Configuration
// ---------------------------------------------------------------------------

/// Stub language.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeLanguage {
    /// TypeScript declarations.
    TypeScript,
    /// Python `TypedDict` stubs.
    Python,
}

impl CodeLanguage {
    /// Fence info string used in the code tool description.
    pub fn fence_language(self) -> &'static str {
        match self {
            CodeLanguage::TypeScript => "ts",
            CodeLanguage::Python => "python",
        }
    }

    /// Human-readable name.
    pub fn as_str(self) -> &'static str {
        match self {
            CodeLanguage::TypeScript => "TypeScript",
            CodeLanguage::Python => "Python",
        }
    }
}

/// Server shape for code mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CodeModePattern {
    /// One `code` tool embedding the whole generated API.
    SingleTool,
    /// A `search` tool plus an `execute` tool.
    SearchExecute,
}

impl CodeModePattern {
    /// Pick a shape from a catalogue size.
    ///
    /// A catalogue at or above [`DEFAULT_SEARCH_EXECUTE_THRESHOLD`] uses
    /// search/execute; a smaller one uses the single `code` tool.
    pub fn for_tool_count(count: usize) -> Self {
        if count >= DEFAULT_SEARCH_EXECUTE_THRESHOLD {
            CodeModePattern::SearchExecute
        } else {
            CodeModePattern::SingleTool
        }
    }
}

/// Generation configuration.
///
/// `template`, when set, may contain `{{types}}` and `{{example}}`. It is
/// trusted host configuration; tool data substituted into it is still cleaned
/// and bounded before substitution.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeModeConfig {
    /// Stub language.
    pub language: CodeLanguage,
    /// Server shape. This affects [`code_tool`] / [`search_execute_tools`], not
    /// the generated declarations themselves.
    pub pattern: CodeModePattern,
    /// Cap on the generated declaration block.
    pub max_api_bytes: usize,
    /// Cap on one tool description inside a declaration.
    pub max_description_bytes: usize,
    /// Optional description template.
    pub template: Option<String>,
}

impl Default for CodeModeConfig {
    fn default() -> Self {
        Self {
            language: CodeLanguage::TypeScript,
            pattern: CodeModePattern::SingleTool,
            max_api_bytes: DEFAULT_MAX_API_BYTES,
            max_description_bytes: DEFAULT_MAX_DESCRIPTION_BYTES,
            template: None,
        }
    }
}

impl CodeModeConfig {
    /// Default configuration for one language.
    pub fn new(language: CodeLanguage) -> Self {
        Self {
            language,
            ..Self::default()
        }
    }

    /// Default configuration for a catalogue, choosing the shape by size.
    pub fn for_catalog(language: CodeLanguage, catalog: &ToolCatalog) -> Self {
        Self {
            pattern: CodeModePattern::for_tool_count(catalog.tools.len()),
            ..Self::new(language)
        }
    }

    /// Replace the server shape.
    pub fn with_pattern(mut self, pattern: CodeModePattern) -> Self {
        self.pattern = pattern;
        self
    }

    /// Replace the declaration budget.
    pub fn with_max_api_bytes(mut self, max_api_bytes: usize) -> Self {
        self.max_api_bytes = max_api_bytes;
        self
    }

    /// Replace the per-tool description budget.
    pub fn with_max_description_bytes(mut self, max_description_bytes: usize) -> Self {
        self.max_description_bytes = max_description_bytes;
        self
    }

    /// Use a description template with `{{types}}` and `{{example}}`.
    pub fn with_template(mut self, template: impl Into<String>) -> Self {
        self.template = Some(template.into());
        self
    }

    /// Validate the budgets.
    pub fn validate(&self) -> Result<()> {
        if self.max_api_bytes < MIN_MAX_API_BYTES {
            return Err(invalid(format!(
                "MCP code mode declaration budget {} bytes is below the minimum {MIN_MAX_API_BYTES}",
                self.max_api_bytes
            )));
        }
        if self.max_description_bytes == 0 {
            return Err(invalid(
                "MCP code mode tool description budget must be non-zero",
            ));
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Generated API
// ---------------------------------------------------------------------------

/// One generated tool stub.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedTool {
    /// Tool name on the wire.
    pub original_name: String,
    /// TypeScript access expression, for example `codemode.list_pull_requests`
    /// or `codemode["3d-render"]`.
    pub ts_accessor: String,
    /// Python function/accessor name.
    pub python_name: String,
    /// Input type name (`...Input`).
    pub input_type: String,
    /// Output type name (`...Output`).
    pub output_type: String,
    /// Required input property names in schema order.
    pub required: Vec<String>,
    /// Cleaned, capped description.
    pub description: String,
}

/// A generated typed API.
///
/// `entries` covers every tool in the catalogue, including tools whose
/// declarations were omitted by the byte budget. `declarations` is the bounded
/// block; `truncated` reports that some entries were omitted. Search uses
/// `entries`, so an omitted tool can still be found and called.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodeApi {
    /// Language of this API.
    pub language: CodeLanguage,
    /// Every tool stub, in catalogue order.
    pub entries: Vec<GeneratedTool>,
    /// Bounded declaration block.
    pub declarations: String,
    /// One example program.
    pub example: String,
    /// Whether `declarations` omits entries.
    pub truncated: bool,
    /// Number of tools in the catalogue.
    pub tool_count: usize,
}

impl CodeApi {
    /// Entries whose declarations are present.
    pub fn is_truncated(&self) -> bool {
        self.truncated
    }
}

// ---------------------------------------------------------------------------
// Public generation entry point
// ---------------------------------------------------------------------------

/// Generate TypeScript or Python stubs for `catalog`.
///
/// The declaration block is a deterministic prefix of whole tool entries,
/// bounded by [`CodeModeConfig::max_api_bytes`]. A Python sanitized-name
/// collision is [`ErrorCode::InvalidInput`] and names both tools.
pub fn generate_api(catalog: &ToolCatalog, config: &CodeModeConfig) -> Result<CodeApi> {
    config.validate()?;
    check_unique_tool_names(catalog)?;
    for tool in &catalog.tools {
        tool.validate(crate::schema::SchemaLimits::default())?;
    }

    match config.language {
        CodeLanguage::TypeScript => generate_typescript(catalog, config),
        CodeLanguage::Python => generate_python(catalog, config),
    }
}

fn check_unique_tool_names(catalog: &ToolCatalog) -> Result<()> {
    let mut seen: HashSet<&str> = HashSet::new();
    for tool in &catalog.tools {
        if !seen.insert(tool.name.as_str()) {
            return Err(invalid(format!(
                "MCP catalogue repeats tool `{}`",
                safe_name(&tool.name)
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TypeScript generation
// ---------------------------------------------------------------------------

fn generate_typescript(catalog: &ToolCatalog, config: &CodeModeConfig) -> Result<CodeApi> {
    let mut type_names = NameAllocator::default();
    let mut entries = Vec::with_capacity(catalog.tools.len());
    for tool in &catalog.tools {
        let base = pascal_name(&tool.name);
        let input_type = type_names.allocate(&format!("{base}Input"));
        let output_type = type_names.allocate(&format!("{base}Output"));
        entries.push(GeneratedTool {
            original_name: tool.name.clone(),
            ts_accessor: ts_accessor(&tool.name),
            python_name: python_name(&tool.name),
            input_type,
            output_type,
            required: required_names(&tool.input_schema),
            description: clean_description(
                tool.description.as_deref().unwrap_or(""),
                config.max_description_bytes,
            ),
        });
    }

    let mut blocks = Vec::with_capacity(entries.len());
    let mut accessors = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let tool = &catalog.tools[index];
        blocks.push(ts_entry(tool, entry, config));
        accessors.push(ts_accessor_line(entry));
    }

    let mut selected = Vec::new();
    for index in 0..entries.len() {
        selected.push(index);
        if assemble_typescript(&blocks, &accessors, &selected).len() > config.max_api_bytes {
            selected.pop();
            break;
        }
    }
    let truncated = selected.len() < entries.len();
    let declarations = assemble_typescript(&blocks, &accessors, &selected);
    debug_assert!(
        declarations.len() <= config.max_api_bytes,
        "TypeScript declarations exceeded the configured budget"
    );
    let example = typescript_example(&catalog.tools, &entries, &selected);

    Ok(CodeApi {
        language: CodeLanguage::TypeScript,
        entries,
        declarations,
        example,
        truncated,
        tool_count: catalog.tools.len(),
    })
}

fn assemble_typescript(blocks: &[String], accessors: &[String], selected: &[usize]) -> String {
    let mut out = String::new();
    for index in selected {
        out.push_str(&blocks[*index]);
    }
    out.push_str("\nexport interface CodeModeApi {\n");
    for index in selected {
        out.push_str(&accessors[*index]);
    }
    out.push_str("}\n\nexport declare const codemode: CodeModeApi;\n");
    out
}

fn ts_entry(tool: &Tool, entry: &GeneratedTool, config: &CodeModeConfig) -> String {
    let mut out = String::new();
    out.push_str(&ts_root_declaration(
        &tool.input_schema,
        &entry.input_type,
        tool.description.as_deref(),
        config,
    ));
    out.push('\n');
    match &tool.output_schema {
        Some(schema) => {
            out.push_str(&ts_root_declaration(
                schema,
                &entry.output_type,
                None,
                config,
            ));
        }
        None => {
            out.push_str(&format!(
                "/** No output schema was advertised; typed as `unknown`. */\nexport type {} = unknown;\n",
                entry.output_type
            ));
        }
    }
    out
}

fn ts_root_declaration(
    schema: &Value,
    name: &str,
    description: Option<&str>,
    config: &CodeModeConfig,
) -> String {
    let mut out = String::new();
    let schema_description = description
        .map(|text| clean_description(text, config.max_description_bytes))
        .filter(|text| !text.is_empty());
    let type_description = schema
        .get("description")
        .and_then(Value::as_str)
        .map(|text| clean_description(text, config.max_description_bytes))
        .filter(|text| !text.is_empty());

    let mut doc = schema_description.unwrap_or_default();
    if let Some(extra) = type_description {
        if !doc.is_empty() {
            doc.push(' ');
        }
        doc.push_str(&extra);
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        if !properties.is_empty() {
            if !doc.is_empty() {
                out.push_str(&jsdoc(&doc));
            }
            out.push_str(&format!("export interface {name} {{\n"));
            out.push_str(&ts_properties(schema, properties, 0, config));
            out.push_str("}\n");
            return out;
        }
    }

    let rendered = ts_type(schema, 0, config);
    let mut note = rendered.note.unwrap_or_default();
    if !note.is_empty() && !doc.is_empty() {
        note = format!("{doc} {note}");
    } else if note.is_empty() {
        note = doc;
    }
    if !note.is_empty() {
        out.push_str(&jsdoc(&note));
    }
    out.push_str(&format!("export type {name} = {};\n", rendered.text));
    out
}

fn ts_properties(
    schema: &Value,
    properties: &Map<String, Value>,
    depth: usize,
    config: &CodeModeConfig,
) -> String {
    let required: HashSet<String> = required_names(schema).into_iter().collect();
    let mut out = String::new();
    for (name, property) in properties {
        let rendered = ts_type(property, depth + 1, config);
        let mut doc = property
            .get("description")
            .and_then(Value::as_str)
            .map(|text| clean_description(text, config.max_description_bytes))
            .unwrap_or_default();
        if rendered.note.is_some() {
            let note = rendered.note.unwrap_or_default();
            if !doc.is_empty() {
                doc.push(' ');
            }
            doc.push_str(&note);
        }
        if !doc.is_empty() {
            out.push_str(&jsdoc_indented(&doc, "  "));
        }
        let key = ts_property_key(name);
        let optional = if required.contains(name.as_str()) {
            ""
        } else {
            "?"
        };
        out.push_str(&format!("  {key}{optional}: {};\n", rendered.text));
    }
    out
}

#[derive(Debug)]
struct TypeExpr {
    text: String,
    note: Option<String>,
}

impl TypeExpr {
    fn plain(text: impl Into<String>) -> Self {
        Self {
            text: text.into(),
            note: None,
        }
    }

    fn unknown(note: impl Into<String>) -> Self {
        Self {
            text: "unknown".to_string(),
            note: Some(note.into()),
        }
    }

    fn with_text(mut self, text: impl Into<String>) -> Self {
        self.text = text.into();
        self
    }
}

fn ts_type(schema: &Value, depth: usize, config: &CodeModeConfig) -> TypeExpr {
    if depth > MAX_TYPE_DEPTH {
        return TypeExpr::unknown("Schema nests too deeply; typed as `unknown`.");
    }
    if !schema.is_object() {
        return TypeExpr::unknown("Schema is not an object; typed as `unknown`.");
    }
    if schema.get("$ref").is_some() {
        return TypeExpr::unknown(
            "Schema uses `$ref`, which is not resolved here; typed as `unknown`.",
        );
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.is_empty() {
            if let Some(text) = ts_union_values(values) {
                return TypeExpr::plain(text);
            }
            return TypeExpr::unknown(
                "Enum contains a value that cannot be a literal; typed as `unknown`.",
            );
        }
    }
    if let Some(value) = schema.get("const") {
        if let Some(text) = ts_literal(value) {
            return TypeExpr::plain(text);
        }
        return TypeExpr::unknown("Const value cannot be a literal; typed as `unknown`.");
    }

    match schema.get("type") {
        Some(Value::String(kind)) => ts_kind(schema, kind, depth, config),
        Some(Value::Array(kinds)) => {
            let mut parts = Vec::new();
            for kind in kinds {
                let Some(kind) = kind.as_str() else {
                    return TypeExpr::unknown(
                        "Schema `type` array is malformed; typed as `unknown`.",
                    );
                };
                let rendered = ts_kind(schema, kind, depth, config);
                if rendered.note.is_some() {
                    return TypeExpr::unknown(
                        "Schema uses an unsupported type union; typed as `unknown`.",
                    );
                }
                parts.push(rendered.text);
            }
            if parts.is_empty() {
                return TypeExpr::unknown("Schema has an empty `type` array; typed as `unknown`.");
            }
            dedup_preserving_order(&mut parts);
            TypeExpr::plain(parts.join(" | "))
        }
        None => TypeExpr::unknown("Schema has no `type`; typed as `unknown`."),
        Some(_) => TypeExpr::unknown("Schema `type` is malformed; typed as `unknown`."),
    }
}

fn ts_kind(schema: &Value, kind: &str, depth: usize, config: &CodeModeConfig) -> TypeExpr {
    match kind {
        "object" => {
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                if !properties.is_empty() {
                    return ts_inline_object(schema, properties, depth, config);
                }
            }
            match schema.get("additionalProperties") {
                Some(Value::Bool(false)) => TypeExpr::plain("{}"),
                Some(Value::Object(_)) => {
                    let value = ts_type(
                        schema.get("additionalProperties").expect("checked above"),
                        depth + 1,
                        config,
                    );
                    TypeExpr::plain(format!("Record<string, {}>", value.text))
                }
                _ => TypeExpr::unknown(
                    "Object schema has no `properties`; typed as `Record<string, unknown>`.",
                )
                .with_text("Record<string, unknown>"),
            }
        }
        "array" => match schema.get("items") {
            Some(items) if items.is_object() || items.is_array() => {
                if items.is_array() {
                    return TypeExpr::unknown(
                        "Tuple schemas are not supported; typed as `Array<unknown>`.",
                    )
                    .with_text("Array<unknown>");
                }
                let item = ts_type(items, depth + 1, config);
                TypeExpr {
                    text: format!("Array<{}>", item.text),
                    note: item.note,
                }
            }
            _ => TypeExpr::unknown("Array schema has no `items`; typed as `Array<unknown>`.")
                .with_text("Array<unknown>"),
        },
        "string" => TypeExpr::plain("string"),
        "number" => TypeExpr::plain("number"),
        "integer" => TypeExpr::plain("number"),
        "boolean" => TypeExpr::plain("boolean"),
        "null" => TypeExpr::plain("null"),
        other => TypeExpr::unknown(format!(
            "Unsupported schema type `{}`; typed as `unknown`.",
            safe_name(other)
        )),
    }
}

fn ts_inline_object(
    schema: &Value,
    properties: &Map<String, Value>,
    depth: usize,
    config: &CodeModeConfig,
) -> TypeExpr {
    let required: HashSet<String> = required_names(schema).into_iter().collect();
    let mut fields = Vec::new();
    let mut note = None;
    for (name, property) in properties {
        let rendered = ts_type(property, depth + 1, config);
        if note.is_none() {
            note = rendered.note;
        }
        let key = ts_property_key(name);
        let optional = if required.contains(name.as_str()) {
            ""
        } else {
            "?"
        };
        fields.push(format!("{key}{optional}: {}", rendered.text));
    }
    TypeExpr {
        text: format!("{{ {} }}", fields.join("; ")),
        note,
    }
}

fn ts_union_values(values: &[Value]) -> Option<String> {
    let mut parts = Vec::new();
    for value in values {
        parts.push(ts_literal(value)?);
    }
    dedup_preserving_order(&mut parts);
    Some(parts.join(" | "))
}

fn ts_literal(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(serde_json::to_string(text).ok()?),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => Some(boolean.to_string()),
        Value::Null => Some("null".to_string()),
        _ => None,
    }
}

fn ts_property_key(name: &str) -> String {
    if is_typescript_identifier(name) {
        name.to_string()
    } else {
        serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_string())
    }
}

fn ts_accessor(name: &str) -> String {
    if is_typescript_identifier(name) {
        format!("codemode.{name}")
    } else {
        let key = serde_json::to_string(name).unwrap_or_else(|_| "\"\"".to_string());
        format!("codemode[{key}]")
    }
}

fn ts_accessor_line(entry: &GeneratedTool) -> String {
    let key = ts_property_key(&entry.original_name);
    let mut out = String::new();
    if !entry.description.is_empty() {
        out.push_str(&jsdoc_indented(&entry.description, "  "));
    }
    out.push_str(&format!(
        "  {key}: (input: {}) => Promise<{}>;\n",
        entry.input_type, entry.output_type
    ));
    out
}

// ---------------------------------------------------------------------------
// Python generation
// ---------------------------------------------------------------------------

fn generate_python(catalog: &ToolCatalog, config: &CodeModeConfig) -> Result<CodeApi> {
    let mut names: HashMap<String, usize> = HashMap::new();
    for (index, tool) in catalog.tools.iter().enumerate() {
        let sanitized = python_name(&tool.name);
        if let Some(previous) = names.insert(sanitized.clone(), index) {
            return Err(invalid(format!(
                "MCP code mode name collision: tools `{}` and `{}` both map to Python name `{sanitized}`",
                safe_name(&catalog.tools[previous].name),
                safe_name(&tool.name)
            )));
        }
    }

    let mut type_names = NameAllocator::default();
    let mut entries = Vec::with_capacity(catalog.tools.len());
    for tool in &catalog.tools {
        let base = pascal_name(&tool.name);
        let input_type = type_names.allocate(&format!("{base}Input"));
        let output_type = type_names.allocate(&format!("{base}Output"));
        entries.push(GeneratedTool {
            original_name: tool.name.clone(),
            ts_accessor: ts_accessor(&tool.name),
            python_name: python_name(&tool.name),
            input_type,
            output_type,
            required: required_names(&tool.input_schema),
            description: clean_description(
                tool.description.as_deref().unwrap_or(""),
                config.max_description_bytes,
            ),
        });
    }

    let mut blocks = Vec::with_capacity(entries.len());
    let mut methods = Vec::with_capacity(entries.len());
    for (index, entry) in entries.iter().enumerate() {
        let tool = &catalog.tools[index];
        blocks.push(py_entry(tool, entry, config));
        methods.push(py_method(entry));
    }

    let mut selected = Vec::new();
    for index in 0..entries.len() {
        selected.push(index);
        if assemble_python(&blocks, &methods, &selected).len() > config.max_api_bytes {
            selected.pop();
            break;
        }
    }
    let truncated = selected.len() < entries.len();
    let declarations = assemble_python(&blocks, &methods, &selected);
    debug_assert!(
        declarations.len() <= config.max_api_bytes,
        "Python declarations exceeded the configured budget"
    );
    let example = python_example(&catalog.tools, &entries, &selected);

    Ok(CodeApi {
        language: CodeLanguage::Python,
        entries,
        declarations,
        example,
        truncated,
        tool_count: catalog.tools.len(),
    })
}

fn assemble_python(blocks: &[String], methods: &[String], selected: &[usize]) -> String {
    let mut out = String::from(
        "from typing import Any, Dict, List, Literal, NotRequired, Optional, TypedDict\n\n",
    );
    for index in selected {
        out.push_str(&blocks[*index]);
    }
    out.push_str("class codemode:\n");
    if selected.is_empty() {
        out.push_str("    pass\n");
    } else {
        for index in selected {
            out.push_str(&methods[*index]);
        }
    }
    out
}

fn py_entry(tool: &Tool, entry: &GeneratedTool, config: &CodeModeConfig) -> String {
    let mut out = String::new();
    out.push_str(&python_type_definition(
        &tool.input_schema,
        &entry.input_type,
        tool.description.as_deref(),
        config,
    ));
    out.push('\n');
    match &tool.output_schema {
        Some(schema) => out.push_str(&python_type_definition(
            schema,
            &entry.output_type,
            None,
            config,
        )),
        None => {
            out.push_str(&format!(
                "# No output schema was advertised; typed as Any.\n{} = Any\n",
                entry.output_type
            ));
        }
    }
    out
}

fn python_type_definition(
    schema: &Value,
    name: &str,
    description: Option<&str>,
    config: &CodeModeConfig,
) -> String {
    let mut out = String::new();
    let mut doc = description
        .map(|text| clean_description(text, config.max_description_bytes))
        .unwrap_or_default();
    if let Some(extra) = schema
        .get("description")
        .and_then(Value::as_str)
        .map(|text| clean_description(text, config.max_description_bytes))
    {
        if !doc.is_empty() {
            doc.push(' ');
        }
        doc.push_str(&extra);
    }
    if !doc.is_empty() {
        out.push_str(&py_comment(&doc, ""));
    }

    if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
        if !properties.is_empty() {
            out.push_str(&python_typed_dict(schema, properties, name, config));
            return out;
        }
    }

    let rendered = py_type(schema, 0, config);
    if let Some(note) = &rendered.note {
        out.push_str(&py_comment(note, ""));
    }
    out.push_str(&format!("{name} = {}\n", rendered.text));
    out
}

fn python_typed_dict(
    schema: &Value,
    properties: &Map<String, Value>,
    name: &str,
    config: &CodeModeConfig,
) -> String {
    let required: HashSet<String> = required_names(schema).into_iter().collect();
    let mut class_safe = true;
    for key in properties.keys() {
        // A dunder-style name would be mangled inside a class body, so use the
        // functional form for it as well.
        let mangled = key.starts_with("__") && !key.ends_with("__");
        if !is_python_identifier(key) || is_python_reserved(key) || mangled {
            class_safe = false;
            break;
        }
    }

    if class_safe {
        let mut out = format!("class {name}(TypedDict):\n");
        if properties.is_empty() {
            out.push_str("    pass\n");
            return out;
        }
        for (key, property) in properties {
            let rendered = py_type(property, 1, config);
            if let Some(note) = &rendered.note {
                out.push_str(&py_comment(note, "    "));
            }
            let ty = if required.contains(key.as_str()) {
                rendered.text
            } else {
                format!("NotRequired[{}]", rendered.text)
            };
            if let Some(description) = property
                .get("description")
                .and_then(Value::as_str)
                .map(|text| clean_description(text, config.max_description_bytes))
                .filter(|text| !text.is_empty())
            {
                out.push_str(&py_comment(&description, "    "));
            }
            out.push_str(&format!("    {key}: {ty}\n"));
        }
        return out;
    }

    // Functional syntax keeps property names that are not Python identifiers.
    let mut out = format!("{name} = TypedDict(\n    \"{name}\",\n    {{\n");
    for (key, property) in properties {
        let rendered = py_type(property, 1, config);
        if let Some(note) = &rendered.note {
            out.push_str(&py_comment(note, "        "));
        }
        let ty = if required.contains(key.as_str()) {
            rendered.text
        } else {
            format!("NotRequired[{}]", rendered.text)
        };
        let key = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
        out.push_str(&format!("        {key}: {ty},\n"));
    }
    out.push_str("    },\n)\n");
    out
}

fn py_method(entry: &GeneratedTool) -> String {
    let mut out = String::new();
    if !entry.description.is_empty() {
        out.push_str(&py_comment(&entry.description, "    "));
    }
    out.push_str(&format!(
        "    @staticmethod\n    def {}(input: {}) -> {}: ...\n",
        entry.python_name, entry.input_type, entry.output_type
    ));
    out
}

fn py_type(schema: &Value, depth: usize, config: &CodeModeConfig) -> TypeExpr {
    if depth > MAX_TYPE_DEPTH {
        return TypeExpr::unknown("Schema nests too deeply; typed as Any.");
    }
    if !schema.is_object() {
        return TypeExpr::unknown("Schema is not an object; typed as Any.");
    }
    if schema.get("$ref").is_some() {
        return TypeExpr::unknown("Schema uses `$ref`, which is not resolved here; typed as Any.");
    }

    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if !values.is_empty() {
            if let Some(text) = py_literal_union(values) {
                return TypeExpr::plain(text);
            }
            return TypeExpr::unknown(
                "Enum contains a value that cannot be a literal; typed as Any.",
            );
        }
    }
    if let Some(value) = schema.get("const") {
        if let Some(text) = py_literal(value) {
            return TypeExpr::plain(format!("Literal[{text}]"));
        }
        return TypeExpr::unknown("Const value cannot be a literal; typed as Any.");
    }

    match schema.get("type") {
        Some(Value::String(kind)) => py_kind(schema, kind, depth, config),
        Some(Value::Array(kinds)) => {
            let mut parts = Vec::new();
            let mut has_null = false;
            for kind in kinds {
                let Some(kind) = kind.as_str() else {
                    return TypeExpr::unknown("Schema `type` array is malformed; typed as Any.");
                };
                if kind == "null" {
                    has_null = true;
                    continue;
                }
                let rendered = py_kind(schema, kind, depth, config);
                if rendered.note.is_some() {
                    return TypeExpr::unknown(
                        "Schema uses an unsupported type union; typed as Any.",
                    );
                }
                parts.push(rendered.text);
            }
            dedup_preserving_order(&mut parts);
            if parts.is_empty() {
                if has_null {
                    return TypeExpr::plain("None");
                }
                return TypeExpr::unknown("Schema has an empty `type` array; typed as Any.");
            }
            if parts.len() == 1 {
                let text = parts.remove(0);
                if has_null {
                    return TypeExpr::plain(format!("Optional[{text}]"));
                }
                return TypeExpr::plain(text);
            }
            TypeExpr::unknown("Schema has several non-null types; typed as Any.")
        }
        None => TypeExpr::unknown("Schema has no `type`; typed as Any."),
        Some(_) => TypeExpr::unknown("Schema `type` is malformed; typed as Any."),
    }
}

fn py_kind(schema: &Value, kind: &str, depth: usize, config: &CodeModeConfig) -> TypeExpr {
    match kind {
        "object" => {
            if let Some(properties) = schema.get("properties").and_then(Value::as_object) {
                if !properties.is_empty() {
                    return TypeExpr::plain("Dict[str, Any]");
                }
            }
            TypeExpr::plain("Dict[str, Any]")
        }
        "array" => match schema.get("items") {
            Some(items) if items.is_object() => {
                let item = py_type(items, depth + 1, config);
                TypeExpr::plain(format!("List[{}]", item.text))
            }
            _ => TypeExpr::unknown("Array schema has no `items`; typed as List[Any].")
                .with_text("List[Any]"),
        },
        "string" => TypeExpr::plain("str"),
        "number" => TypeExpr::plain("float"),
        "integer" => TypeExpr::plain("int"),
        "boolean" => TypeExpr::plain("bool"),
        "null" => TypeExpr::plain("None"),
        other => TypeExpr::unknown(format!(
            "Unsupported schema type `{}`; typed as Any.",
            safe_name(other)
        )),
    }
}

fn py_literal_union(values: &[Value]) -> Option<String> {
    let mut parts = Vec::new();
    for value in values {
        parts.push(py_literal(value)?);
    }
    dedup_preserving_order(&mut parts);
    Some(format!("Literal[{}]", parts.join(", ")))
}

fn py_literal(value: &Value) -> Option<String> {
    match value {
        Value::String(text) => Some(serde_json::to_string(text).ok()?),
        Value::Number(number) => Some(number.to_string()),
        Value::Bool(boolean) => {
            if *boolean {
                Some("True".to_string())
            } else {
                Some("False".to_string())
            }
        }
        Value::Null => Some("None".to_string()),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Examples
// ---------------------------------------------------------------------------

fn typescript_example(tools: &[Tool], entries: &[GeneratedTool], selected: &[usize]) -> String {
    let Some(index) = selected.first().copied() else {
        return "const result = null;".to_string();
    };
    let entry = &entries[index];
    let sample = tools
        .get(index)
        .map(|tool| sample_ts(&tool.input_schema, 0))
        .unwrap_or_else(|| "{}".to_string());
    truncate_utf8(
        &format!("const result = await {}({});", entry.ts_accessor, sample),
        MAX_EXAMPLE_BYTES,
    )
}

fn python_example(tools: &[Tool], entries: &[GeneratedTool], selected: &[usize]) -> String {
    let Some(index) = selected.first().copied() else {
        return "result = None".to_string();
    };
    let entry = &entries[index];
    let sample = tools
        .get(index)
        .map(|tool| sample_py(&tool.input_schema, 0))
        .unwrap_or_else(|| "{}".to_string());
    truncate_utf8(
        &format!("result = codemode.{}({})", entry.python_name, sample),
        MAX_EXAMPLE_BYTES,
    )
}

fn sample_ts(schema: &Value, depth: usize) -> String {
    if depth > 2 {
        return "{}".to_string();
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if let Some(first) = values.first().and_then(ts_literal) {
            return first;
        }
    }
    match schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("object")
    {
        "object" => {
            let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
                return "{}".to_string();
            };
            let required = required_names(schema);
            let mut keys: Vec<&String> = properties
                .keys()
                .filter(|key| required.iter().any(|name| name == *key))
                .collect();
            if keys.is_empty() {
                keys = properties.keys().take(3).collect();
            }
            let fields: Vec<String> = keys
                .into_iter()
                .take(4)
                .map(|key| {
                    let value = properties
                        .get(key)
                        .map(|property| sample_ts(property, depth + 1))
                        .unwrap_or_else(|| "{}".to_string());
                    format!("{}: {value}", ts_property_key(key))
                })
                .collect();
            if fields.is_empty() {
                "{}".to_string()
            } else {
                format!("{{ {} }}", fields.join(", "))
            }
        }
        "array" => "[]".to_string(),
        "string" => "\"value\"".to_string(),
        "integer" | "number" => "0".to_string(),
        "boolean" => "true".to_string(),
        "null" => "null".to_string(),
        _ => "{}".to_string(),
    }
}

fn sample_py(schema: &Value, depth: usize) -> String {
    if depth > 2 {
        return "{}".to_string();
    }
    if let Some(values) = schema.get("enum").and_then(Value::as_array) {
        if let Some(first) = values.first().and_then(py_literal) {
            return first;
        }
    }
    match schema
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or("object")
    {
        "object" => {
            let Some(properties) = schema.get("properties").and_then(Value::as_object) else {
                return "{}".to_string();
            };
            let required = required_names(schema);
            let mut keys: Vec<&String> = properties
                .keys()
                .filter(|key| required.iter().any(|name| name == *key))
                .collect();
            if keys.is_empty() {
                keys = properties.keys().take(3).collect();
            }
            let fields: Vec<String> = keys
                .into_iter()
                .take(4)
                .map(|key| {
                    let value = properties
                        .get(key)
                        .map(|property| sample_py(property, depth + 1))
                        .unwrap_or_else(|| "{}".to_string());
                    let key = serde_json::to_string(key).unwrap_or_else(|_| "\"\"".to_string());
                    format!("{key}: {value}")
                })
                .collect();
            if fields.is_empty() {
                "{}".to_string()
            } else {
                format!("{{{}}}", fields.join(", "))
            }
        }
        "array" => "[]".to_string(),
        "string" => "\"value\"".to_string(),
        "integer" | "number" => "0".to_string(),
        "boolean" => "True".to_string(),
        "null" => "None".to_string(),
        _ => "{}".to_string(),
    }
}

// ---------------------------------------------------------------------------
// Server shapes
// ---------------------------------------------------------------------------

/// The single-tool shape: one `code` tool.
///
/// The description is a fixed preamble, the bounded generated declarations, and
/// one example (or the configured `{{types}}`/`{{example}}` template). The tool
/// is not read-only and not idempotent: the executed program may call any tool
/// and every call is checked individually.
pub fn code_tool(api: &CodeApi, config: &CodeModeConfig) -> Tool {
    code_like_tool(CODE_TOOL_NAME, api, config, "Run an MCP code-mode program")
}

/// The search/execute shape: a read-only `search` tool and an `execute` tool.
///
/// `search` indexes tool names and descriptions without embedding the full API;
/// `execute` carries the same bounded declarations as [`code_tool`].
pub fn search_execute_tools(api: &CodeApi, config: &CodeModeConfig) -> Vec<Tool> {
    vec![
        search_tool(api, config),
        code_like_tool(
            EXECUTE_TOOL_NAME,
            api,
            config,
            "Execute an MCP code-mode program",
        ),
    ]
}

fn code_like_tool(name: &str, api: &CodeApi, config: &CodeModeConfig, title: &str) -> Tool {
    let description = code_description(api, config);
    Tool {
        name: name.to_string(),
        title: Some(title.to_string()),
        description: Some(description),
        input_schema: json!({
            "type": "object",
            "properties": {
                "code": {"type": "string"}
            },
            "required": ["code"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "result": {}
            }
        })),
        annotations: Some(ToolAnnotations {
            read_only_hint: Some(false),
            destructive_hint: None,
            idempotent_hint: Some(false),
            open_world_hint: None,
        }),
    }
}

fn search_tool(api: &CodeApi, config: &CodeModeConfig) -> Tool {
    Tool {
        name: SEARCH_TOOL_NAME.to_string(),
        title: Some("Search MCP tools".to_string()),
        description: Some(search_description(api, config)),
        input_schema: json!({
            "type": "object",
            "properties": {
                "query": {"type": "string"}
            },
            "required": ["query"]
        }),
        output_schema: Some(json!({
            "type": "object",
            "properties": {
                "matches": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "name": {"type": "string"},
                            "description": {"type": "string"},
                            "accessor": {"type": "string"}
                        },
                        "required": ["name", "accessor"]
                    }
                }
            }
        })),
        annotations: Some(ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: None,
        }),
    }
}

fn code_description(api: &CodeApi, config: &CodeModeConfig) -> String {
    let body = default_code_description(api);
    match &config.template {
        Some(template) if template.contains("{{types}}") || template.contains("{{example}}") => {
            render_template(template, &api.declarations, &api.example)
        }
        Some(template) => format!("{template}\n\n{body}"),
        None => body,
    }
}

fn render_template(template: &str, declarations: &str, example: &str) -> String {
    let mut out = String::with_capacity(template.len() + declarations.len() + example.len());
    let mut remaining = template;
    loop {
        let next_types = remaining.find("{{types}}");
        let next_example = remaining.find("{{example}}");
        let next = match (next_types, next_example) {
            (None, None) => {
                out.push_str(remaining);
                break;
            }
            (Some(position), None) => (position, "{{types}}", declarations),
            (None, Some(position)) => (position, "{{example}}", example),
            (Some(types), Some(example_pos)) if types <= example_pos => {
                (types, "{{types}}", declarations)
            }
            (Some(_), Some(example_pos)) => (example_pos, "{{example}}", example),
        };
        out.push_str(&remaining[..next.0]);
        out.push_str(next.2);
        remaining = &remaining[next.0 + next.1.len()..];
    }
    out
}

fn default_code_description(api: &CodeApi) -> String {
    let language = api.language;
    let mut out = format!(
        "Run one {} program against the MCP tools.\n\
         Write code that calls the typed `codemode` API and return only the final result.\n\
         Every tool call is checked against host policy before it runs.\n",
        language.as_str()
    );
    if api.truncated {
        out.push_str(
            "The declaration block is truncated to the size budget; tools beyond it are still callable by name.\n",
        );
    }
    let fence = fence_for(&format!("{}\n{}", api.declarations, api.example));
    out.push_str(&format!(
        "\n{fence}{}\n{}\n{fence}\n",
        language.fence_language(),
        api.declarations
    ));
    out.push_str(&format!(
        "\nExample:\n\n{fence}{}\n{}\n{fence}\n",
        language.fence_language(),
        api.example
    ));
    out
}

fn search_description(api: &CodeApi, _config: &CodeModeConfig) -> String {
    let mut out = String::from(
        "Search the MCP tool catalogue by name or description. Returns matching tools with the accessor to call in `execute`. This list is an index only; the full typed API is not embedded.\n",
    );
    let marker = "\n- More tools are available; refine the query.\n";
    let mut included = 0usize;
    for entry in &api.entries {
        let description = if entry.description.is_empty() {
            "(no description)"
        } else {
            entry.description.as_str()
        };
        let line = format!("- {}: {}\n", safe_name(&entry.original_name), description);
        if out.len() + line.len() + marker.len() > MAX_SEARCH_DESCRIPTION_BYTES {
            break;
        }
        out.push_str(&line);
        included += 1;
    }
    if included < api.entries.len() {
        out.push_str(marker);
    }
    out
}

fn fence_for(code: &str) -> String {
    let mut longest = 0usize;
    let mut run = 0usize;
    for character in code.chars() {
        if character == '`' {
            run += 1;
            longest = longest.max(run);
        } else {
            run = 0;
        }
    }
    "`".repeat((longest + 1).max(3))
}

// ---------------------------------------------------------------------------
// Execution bridge
// ---------------------------------------------------------------------------

/// An executor turns a program into a final value.
///
/// The executor receives the bridge and calls tools through it. It owns any
/// intermediate state; only the returned value leaves [`execute`]. Production
/// sandboxing (zero-kernel/IPython or an OS sandbox) is a follow-up; tests use
/// scripted executors.
pub trait CodeExecutor {
    /// Run `program`, using `bridge` for every tool call, and return the final
    /// value.
    fn run(&self, program: &str, bridge: &mut dyn CodeModeBridge) -> Result<Value>;
}

/// One search result returned to a program.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SearchHit {
    /// Original tool name.
    pub name: String,
    /// Cleaned, capped description.
    pub description: String,
    /// Language-specific accessor, for example `codemode.list_pull_requests`.
    pub accessor: String,
}

/// The bridge a program uses to reach tools.
pub trait CodeModeBridge {
    /// Call one tool with JSON arguments.
    fn call(&mut self, tool: &str, arguments: Value) -> Result<Value>;
    /// Search tool names and descriptions.
    fn search(&self, query: &str) -> Vec<SearchHit>;
}

/// Approval seam for `Ask` decisions.
///
/// The default is [`DenyAllApproval`]. A host UI records consent here. The
/// oracle sees the tool name and risk class, never the arguments.
pub trait ApprovalOracle {
    /// Return whether the call is approved.
    fn approve(&mut self, tool: &str, risk: ToolRisk) -> bool;
}

/// Default approval policy: every `Ask` is refused.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct DenyAllApproval;

impl ApprovalOracle for DenyAllApproval {
    fn approve(&mut self, _tool: &str, _risk: ToolRisk) -> bool {
        false
    }
}

/// One recorded call. It carries the tool name, risk, decision, and whether the
/// call ran; it never carries arguments or results.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallRecord {
    /// Original tool name.
    pub tool: String,
    /// Classified risk.
    pub risk: ToolRisk,
    /// Policy decision before approval.
    pub decision: ToolDecision,
    /// Whether the call ran (an allowed call or an approved `Ask`).
    pub approved: bool,
}

/// Bounds for one code-mode execution and for host call checks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CodeModeLimits {
    /// Cap on the program source (bytes).
    pub max_source_bytes: usize,
    /// Cap on the final result (compact JSON bytes).
    pub max_result_bytes: usize,
    /// Cap on bridge calls in one program.
    pub max_calls: usize,
    /// Cap on one call's arguments (compact JSON bytes).
    pub max_argument_bytes: usize,
    /// Cap on one call's argument nesting depth; the root is depth 0.
    pub max_argument_depth: usize,
}

impl Default for CodeModeLimits {
    fn default() -> Self {
        Self {
            max_source_bytes: DEFAULT_MAX_SOURCE_BYTES,
            max_result_bytes: DEFAULT_MAX_RESULT_BYTES,
            max_calls: DEFAULT_MAX_CALLS,
            max_argument_bytes: DEFAULT_MAX_ARGUMENT_BYTES,
            max_argument_depth: DEFAULT_MAX_ARGUMENT_DEPTH,
        }
    }
}

impl CodeModeLimits {
    /// Validate that every bound is non-zero.
    pub fn validate(&self) -> Result<()> {
        if self.max_source_bytes == 0 {
            return Err(invalid("MCP code mode source cap must be non-zero"));
        }
        if self.max_result_bytes == 0 {
            return Err(invalid("MCP code mode result cap must be non-zero"));
        }
        if self.max_calls == 0 {
            return Err(invalid("MCP code mode call cap must be non-zero"));
        }
        if self.max_argument_bytes == 0 {
            return Err(invalid("MCP code mode argument byte cap must be non-zero"));
        }
        if self.max_argument_depth == 0 {
            return Err(invalid("MCP code mode argument depth cap must be non-zero"));
        }
        Ok(())
    }
}

/// Run one program and return only its final value.
///
/// The source is bounded before the executor is called, bridge calls are
/// counted, and the returned value is bounded after the executor finishes.
/// Intermediate bridge results stay inside the executor.
pub fn execute<B>(
    program: &str,
    executor: &dyn CodeExecutor,
    host: &mut B,
    limits: &CodeModeLimits,
) -> Result<Value>
where
    B: CodeModeBridge,
{
    limits.validate()?;
    if program.len() > limits.max_source_bytes {
        return Err(limit(
            "source bytes",
            program.len(),
            limits.max_source_bytes,
        ));
    }

    let (result, aborted) = {
        let mut bridge = GuardedBridge {
            inner: &mut *host,
            calls: 0,
            max_calls: limits.max_calls,
            aborted: None,
        };
        let result = executor.run(program, &mut bridge);
        (result, bridge.aborted)
    };
    // A policy refusal aborts the program even if the executor swallowed it.
    if let Some(error) = aborted {
        return Err(error);
    }
    let result = result?;

    let bytes = serde_json::to_vec(&result)?.len();
    if bytes > limits.max_result_bytes {
        return Err(limit("result bytes", bytes, limits.max_result_bytes));
    }
    Ok(result)
}

struct GuardedBridge<'a> {
    inner: &'a mut dyn CodeModeBridge,
    calls: usize,
    max_calls: usize,
    aborted: Option<ZeroError>,
}

impl CodeModeBridge for GuardedBridge<'_> {
    fn call(&mut self, tool: &str, arguments: Value) -> Result<Value> {
        if let Some(error) = &self.aborted {
            return Err(error.clone());
        }
        if self.calls >= self.max_calls {
            return Err(limit("bridge calls", self.calls + 1, self.max_calls));
        }
        self.calls += 1;
        let result = self.inner.call(tool, arguments);
        if let Err(error) = &result {
            if matches!(
                error.code(),
                ErrorCode::PolicyAskRequired | ErrorCode::PolicyDenied
            ) {
                self.aborted = Some(error.clone());
            }
        }
        result
    }

    fn search(&self, query: &str) -> Vec<SearchHit> {
        self.inner.search(query)
    }
}

// ---------------------------------------------------------------------------
// Host implementation
// ---------------------------------------------------------------------------

/// The code-mode bridge over a [`ToolCatalog`] and a [`ToolHost`].
///
/// Each call resolves the generated accessor to the original tool, checks the
/// argument bounds, applies the [`PolicyMode`] matrix, consults the
/// [`ApprovalOracle`] for `Ask`, records the call, and enforces
/// [`ResponseLimits`] on the result. The replay guard is keyed by
/// `(program, call index)`.
pub struct CodeModeHost<H> {
    catalog: ToolCatalog,
    host: H,
    entries: Vec<GeneratedTool>,
    keys: HashMap<String, Option<usize>>,
    language: CodeLanguage,
    policy_mode: PolicyMode,
    approval: Box<dyn ApprovalOracle>,
    replay: ReplayGuard,
    clock: Arc<dyn Clock>,
    program_id: String,
    next_call_index: u64,
    calls: Vec<CallRecord>,
    limits: CodeModeLimits,
    response_limits: ResponseLimits,
    max_search_hits: usize,
}

impl<H: ToolHost> CodeModeHost<H> {
    /// Build a host for `catalog` and `host`.
    ///
    /// Generation failure (for example a Python sanitized-name collision) is
    /// returned here; the host is otherwise ready with the default policy,
    /// [`DenyAllApproval`], and default limits.
    pub fn new(catalog: ToolCatalog, host: H, config: &CodeModeConfig) -> Result<Self> {
        let api = generate_api(&catalog, config)?;
        let mut keys: HashMap<String, Option<usize>> = HashMap::new();
        for (index, entry) in api.entries.iter().enumerate() {
            insert_key(&mut keys, entry.original_name.clone(), index);
            insert_key(&mut keys, entry.python_name.clone(), index);
            insert_key(&mut keys, entry.ts_accessor.clone(), index);
        }
        Ok(Self {
            catalog,
            host,
            entries: api.entries,
            keys,
            language: config.language,
            policy_mode: PolicyMode::Manual,
            approval: Box::new(DenyAllApproval),
            replay: ReplayGuard::with_defaults(),
            clock: Arc::new(SystemClock),
            program_id: "code-mode".to_string(),
            next_call_index: 0,
            calls: Vec::new(),
            limits: CodeModeLimits::default(),
            response_limits: ResponseLimits::default(),
            max_search_hits: DEFAULT_MAX_SEARCH_HITS,
        })
    }

    /// Replace the policy mode.
    pub fn with_policy_mode(mut self, policy_mode: PolicyMode) -> Self {
        self.policy_mode = policy_mode;
        self
    }

    /// Replace the approval oracle.
    pub fn with_approval(mut self, approval: Box<dyn ApprovalOracle>) -> Self {
        self.approval = approval;
        self
    }

    /// Replace the injected clock.
    pub fn with_clock(mut self, clock: Arc<dyn Clock>) -> Self {
        self.clock = clock;
        self
    }

    /// Set the replay and call-log program id.
    pub fn with_program_id(mut self, program_id: impl Into<String>) -> Self {
        self.program_id = program_id.into();
        self
    }

    /// Replace the call/argument bounds.
    pub fn with_limits(mut self, limits: CodeModeLimits) -> Self {
        self.limits = limits;
        self
    }

    /// Replace the per-call result bounds.
    pub fn with_response_limits(mut self, response_limits: ResponseLimits) -> Self {
        self.response_limits = response_limits;
        self
    }

    /// Replace the search-hit bound.
    pub fn with_max_search_hits(mut self, max_search_hits: usize) -> Self {
        self.max_search_hits = max_search_hits.max(1);
        self
    }

    /// Start a new program: reset the automatic call index for `program_id`.
    ///
    /// The replay guard is deliberately not cleared, so reusing a program id
    /// still rejects calls whose `(program, index)` was already executed.
    pub fn begin_program(&mut self, program_id: impl Into<String>) {
        self.program_id = program_id.into();
        self.next_call_index = 0;
    }

    /// The recorded calls, in order. Only names, risks, and decisions are kept.
    pub fn calls(&self) -> &[CallRecord] {
        &self.calls
    }

    /// The next automatic call index.
    pub fn next_call_index(&self) -> u64 {
        self.next_call_index
    }

    /// Resolve a key to its tool and call it at an explicit index.
    ///
    /// This is the replay-guard seam. The automatic [`CodeModeBridge::call`]
    /// path supplies the next index and the configured program id. Arguments
    /// are never echoed in an error.
    pub fn call_at(
        &mut self,
        program_id: &str,
        call_index: u64,
        tool: &str,
        arguments: Value,
    ) -> Result<Value> {
        self.limits.validate()?;
        self.response_limits.validate()?;

        let now_ms = self.clock.now().0;
        if self
            .replay
            .check_and_record_pair(&call_index.to_string(), program_id, now_ms)
            == ReplayOutcome::Replay
        {
            return Err(denied(format!(
                "MCP code mode call {call_index} was already executed for this program"
            )));
        }

        let tool_def = self.resolve(tool)?.clone();
        self.check_arguments(&arguments)?;

        let risk = classify(&tool_def);
        let decision = decide(&tool_def, self.policy_mode);
        match decision {
            ToolDecision::Allow => {
                self.record(&tool_def.name, risk, decision, true);
            }
            ToolDecision::Ask => {
                let approved = self.approval.approve(&tool_def.name, risk);
                self.record(&tool_def.name, risk, decision, approved);
                if !approved {
                    return Err(ask(format!(
                        "MCP code mode requires approval for tool `{}` ({risk:?})",
                        safe_name(&tool_def.name)
                    )));
                }
            }
            ToolDecision::Deny => {
                self.record(&tool_def.name, risk, decision, false);
                return Err(denied(format!(
                    "MCP code mode denied tool `{}` ({risk:?})",
                    safe_name(&tool_def.name)
                )));
            }
        }

        let value = self
            .host
            .call_tool(&tool_def.name, arguments)
            .map_err(|error| {
                // Keep the stable code but replace a host message that may
                // contain arguments or a result payload.
                ZeroError::new(
                    error.code(),
                    format!("MCP code mode tool `{}` failed", safe_name(&tool_def.name)),
                )
            })?;
        self.response_limits.check_tool_result(&[], Some(&value))?;
        Ok(value)
    }

    /// Search tool names and descriptions.
    pub fn search_hits(&self, query: &str) -> Vec<SearchHit> {
        let needle = query.trim().to_ascii_lowercase();
        let mut hits = Vec::new();
        for entry in &self.entries {
            let matches = needle.is_empty()
                || entry.original_name.to_ascii_lowercase().contains(&needle)
                || entry.python_name.to_ascii_lowercase().contains(&needle)
                || entry.description.to_ascii_lowercase().contains(&needle);
            if !matches {
                continue;
            }
            let accessor = match self.language {
                CodeLanguage::TypeScript => entry.ts_accessor.clone(),
                CodeLanguage::Python => format!("codemode.{}", entry.python_name),
            };
            hits.push(SearchHit {
                name: entry.original_name.clone(),
                description: entry.description.clone(),
                accessor,
            });
            if hits.len() >= self.max_search_hits {
                break;
            }
        }
        hits
    }

    fn resolve(&self, key: &str) -> Result<&Tool> {
        match self.keys.get(key) {
            Some(Some(index)) => self.catalog.tools.get(*index).ok_or_else(|| not_found(key)),
            Some(None) => Err(invalid(format!(
                "MCP code mode tool key `{}` is ambiguous",
                safe_name(key)
            ))),
            None => Err(not_found(key)),
        }
    }

    fn check_arguments(&self, arguments: &Value) -> Result<()> {
        let bytes = serde_json::to_vec(arguments)?.len();
        if bytes > self.limits.max_argument_bytes {
            return Err(limit(
                "argument bytes",
                bytes,
                self.limits.max_argument_bytes,
            ));
        }
        let depth = value_depth(arguments);
        if depth > self.limits.max_argument_depth {
            return Err(limit(
                "argument depth",
                depth,
                self.limits.max_argument_depth,
            ));
        }
        Ok(())
    }

    fn record(&mut self, tool: &str, risk: ToolRisk, decision: ToolDecision, approved: bool) {
        self.calls.push(CallRecord {
            tool: tool.to_string(),
            risk,
            decision,
            approved,
        });
    }
}

impl<H: ToolHost> CodeModeBridge for CodeModeHost<H> {
    fn call(&mut self, tool: &str, arguments: Value) -> Result<Value> {
        let call_index = self.next_call_index;
        self.next_call_index = self.next_call_index.saturating_add(1);
        let program_id = self.program_id.clone();
        self.call_at(&program_id, call_index, tool, arguments)
    }

    fn search(&self, query: &str) -> Vec<SearchHit> {
        self.search_hits(query)
    }
}

fn insert_key(keys: &mut HashMap<String, Option<usize>>, key: String, index: usize) {
    match keys.get(&key) {
        None => {
            keys.insert(key, Some(index));
        }
        Some(Some(existing)) if *existing == index => {}
        Some(_) => {
            keys.insert(key, None);
        }
    }
}

// ---------------------------------------------------------------------------
// Sanitization and helpers
// ---------------------------------------------------------------------------

fn required_names(schema: &Value) -> Vec<String> {
    schema
        .get("required")
        .and_then(Value::as_array)
        .map(|values| {
            values
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn snake_words(name: &str) -> Vec<String> {
    let characters: Vec<char> = name.chars().collect();
    let mut words = Vec::new();
    let mut current = String::new();
    for (index, character) in characters.iter().copied().enumerate() {
        if !character.is_ascii_alphanumeric() {
            flush_word(&mut words, &mut current);
            continue;
        }
        if character.is_ascii_uppercase() {
            let previous = index
                .checked_sub(1)
                .and_then(|position| characters.get(position))
                .copied();
            let next = characters.get(index + 1).copied();
            let boundary = previous
                .is_some_and(|value| value.is_ascii_lowercase() || value.is_ascii_digit())
                || (previous.is_some_and(|value| value.is_ascii_uppercase())
                    && next.is_some_and(|value| value.is_ascii_lowercase()));
            if boundary {
                flush_word(&mut words, &mut current);
            }
            current.push(character.to_ascii_lowercase());
        } else {
            current.push(character.to_ascii_lowercase());
        }
    }
    flush_word(&mut words, &mut current);
    words
}

fn flush_word(words: &mut Vec<String>, current: &mut String) {
    if !current.is_empty() {
        words.push(std::mem::take(current));
    }
}

/// Sanitize a tool name to a Python function name.
///
/// Non-ASCII and punctuation split words; camelCase is split; the result is
/// snake_case, prefixed with `_` when it starts with a digit, and suffixed with
/// `_` when it is a Python or JavaScript reserved word.
pub fn python_name(name: &str) -> String {
    let mut result = snake_words(name).join("_");
    if result.is_empty() {
        result = "tool".to_string();
    }
    if result
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
    {
        result.insert(0, '_');
    }
    if is_python_reserved(&result) {
        result.push('_');
    }
    result
}

fn pascal_name(name: &str) -> String {
    let mut out = String::new();
    for word in snake_words(name) {
        let mut characters = word.chars();
        if let Some(first) = characters.next() {
            out.push(first.to_ascii_uppercase());
            out.extend(characters);
        }
    }
    if out.is_empty() {
        return "Tool".to_string();
    }
    if out
        .chars()
        .next()
        .is_some_and(|character| character.is_ascii_digit())
    {
        out.insert(0, '_');
    }
    out
}

fn is_python_reserved(name: &str) -> bool {
    const RESERVED: &[&str] = &[
        // Python keywords.
        "False",
        "None",
        "True",
        "and",
        "as",
        "assert",
        "async",
        "await",
        "break",
        "class",
        "continue",
        "def",
        "del",
        "elif",
        "else",
        "except",
        "finally",
        "for",
        "from",
        "global",
        "if",
        "import",
        "in",
        "is",
        "lambda",
        "nonlocal",
        "not",
        "or",
        "pass",
        "raise",
        "return",
        "try",
        "while",
        "with",
        "yield",
        "match",
        "case",
        "_",
        // JavaScript reserved words, kept out of generated names so a name never
        // needs quoting or a surprising rewrite.
        "delete",
        "function",
        "var",
        "let",
        "const",
        "new",
        "this",
        "typeof",
        "instanceof",
        "void",
        "enum",
        "implements",
        "interface",
        "package",
        "private",
        "protected",
        "public",
        "static",
        "super",
        "export",
        "extends",
        "do",
        "switch",
        "throw",
        "catch",
        "debugger",
        "default",
        "of",
        "undefined",
    ];
    RESERVED.contains(&name)
}

fn is_typescript_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    match characters.next() {
        Some(character)
            if character.is_ascii_alphabetic() || character == '_' || character == '$' => {}
        _ => return false,
    }
    characters
        .all(|character| character.is_ascii_alphanumeric() || character == '_' || character == '$')
}

fn is_python_identifier(name: &str) -> bool {
    let mut characters = name.chars();
    match characters.next() {
        Some(character) if character == '_' || character.is_ascii_alphabetic() => {}
        _ => return false,
    }
    characters.all(|character| character == '_' || character.is_ascii_alphanumeric())
}

fn clean_description(text: &str, max_bytes: usize) -> String {
    let mut result = String::new();
    let mut last_space = false;
    for character in text.chars() {
        if character.is_control() || character.is_whitespace() {
            if !result.is_empty() && !last_space {
                result.push(' ');
                last_space = true;
            }
            continue;
        }
        result.push(character);
        last_space = false;
    }
    truncate_utf8(result.trim(), max_bytes)
}

fn truncate_utf8(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    let mut out = text[..end].trim_end().to_string();
    if out.len() + '…'.len_utf8() <= max_bytes {
        out.push('…');
    }
    out
}

fn jsdoc(description: &str) -> String {
    jsdoc_indented(description, "")
}

fn jsdoc_indented(description: &str, indent: &str) -> String {
    if description.is_empty() {
        return String::new();
    }
    let escaped = description.replace("*/", "*\\/");
    format!("{indent}/** {escaped} */\n")
}

fn py_comment(description: &str, indent: &str) -> String {
    if description.is_empty() {
        return String::new();
    }
    format!("{indent}# {description}\n")
}

fn safe_name(name: &str) -> String {
    let cleaned = clean_description(name, 128);
    if cleaned.is_empty() {
        "<unnamed>".to_string()
    } else {
        cleaned
    }
}

fn dedup_preserving_order(values: &mut Vec<String>) {
    let mut seen = HashSet::new();
    values.retain(|value| seen.insert(value.clone()));
}

fn value_depth(value: &Value) -> usize {
    fn walk(value: &Value, depth: usize) -> usize {
        match value {
            Value::Array(items) => items
                .iter()
                .map(|item| walk(item, depth + 1))
                .max()
                .unwrap_or(depth),
            Value::Object(map) => map
                .values()
                .map(|item| walk(item, depth + 1))
                .max()
                .unwrap_or(depth),
            _ => depth,
        }
    }
    walk(value, 0)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn ask(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyAskRequired, message)
}

fn not_found(name: &str) -> ZeroError {
    ZeroError::new(
        ErrorCode::NotFound,
        format!("MCP code mode tool `{}` was not found", safe_name(name)),
    )
}

fn limit(what: &str, value: usize, cap: usize) -> ZeroError {
    ZeroError::new(
        ErrorCode::LimitExceeded,
        format!("MCP code mode {what} {value} exceeds limit {cap}"),
    )
}

#[derive(Default)]
struct NameAllocator {
    used: HashSet<String>,
}

impl NameAllocator {
    fn allocate(&mut self, base: &str) -> String {
        if self.used.insert(base.to_string()) {
            return base.to_string();
        }
        let mut suffix = 2usize;
        loop {
            let candidate = format!("{base}_{suffix}");
            if self.used.insert(candidate.clone()) {
                return candidate;
            }
            suffix += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::rc::Rc;

    use super::*;
    use crate::client::ResultType;

    // -- fixtures -----------------------------------------------------------

    fn catalog(tools: Vec<Tool>) -> ToolCatalog {
        ToolCatalog {
            tools,
            next_cursor: None,
            ttl_ms: None,
            cache_scope: None,
            result_type: ResultType::Complete,
        }
    }

    fn tool(name: &str, input_schema: Value, output_schema: Option<Value>) -> Tool {
        Tool {
            name: name.to_string(),
            title: None,
            description: None,
            input_schema,
            output_schema,
            annotations: None,
        }
    }

    fn annotated(name: &str, read_only: Option<bool>, destructive: Option<bool>) -> Tool {
        let mut tool = tool(name, json!({"type": "object", "properties": {}}), None);
        tool.annotations = Some(ToolAnnotations {
            read_only_hint: read_only,
            destructive_hint: destructive,
            ..ToolAnnotations::default()
        });
        tool
    }

    fn read_tool(name: &str) -> Tool {
        annotated(name, Some(true), Some(false))
    }

    fn write_tool(name: &str) -> Tool {
        annotated(name, Some(false), None)
    }

    fn sample_catalog() -> ToolCatalog {
        let input = json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string", "description": "Repository owner"},
                "state": {"enum": ["open", "closed"], "description": "Filter by state"},
                "labels": {"type": "array", "items": {"type": "string"}},
                "page": {"type": "integer"},
                "note": {"type": ["string", "null"]},
                "filter": {
                    "type": "object",
                    "properties": {
                        "draft": {"type": "boolean"},
                        "ids": {"type": "array", "items": {"type": "number"}}
                    }
                },
                "weird key": {"type": "null"}
            },
            "required": ["owner", "labels"]
        });
        let output = json!({
            "type": "object",
            "properties": {
                "items": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {"id": {"type": "string"}}
                    }
                },
                "total": {"type": "integer"}
            },
            "required": ["items", "total"]
        });
        let mut list = tool("list-pull.requests", input, Some(output));
        list.description = Some(format!(
            "List pull requests\nwith control\u{7} characters and {}",
            "very long text ".repeat(20)
        ));
        list.annotations = Some(ToolAnnotations {
            read_only_hint: Some(true),
            destructive_hint: Some(false),
            idempotent_hint: Some(true),
            open_world_hint: None,
        });
        catalog(vec![list])
    }

    fn python_catalog() -> ToolCatalog {
        let input = json!({
            "type": "object",
            "properties": {
                "owner": {"type": "string", "description": "Repository owner"},
                "state": {"enum": ["open", "closed"]},
                "labels": {"type": "array", "items": {"type": "string"}},
                "page": {"type": "integer"},
                "note": {"type": ["string", "null"]},
                "filter": {
                    "type": "object",
                    "properties": {"draft": {"type": "boolean"}}
                }
            },
            "required": ["owner", "labels"]
        });
        let output = json!({
            "type": "object",
            "properties": {
                "items": {"type": "array", "items": {"type": "string"}},
                "total": {"type": "integer"}
            },
            "required": ["items", "total"]
        });
        catalog(vec![tool("list-pull.requests", input, Some(output))])
    }

    // -- TypeScript generation ---------------------------------------------

    #[test]
    fn typescript_generation_covers_required_optional_enum_array_nested_and_invalid_names() {
        let api = generate_api(
            &sample_catalog(),
            &CodeModeConfig::new(CodeLanguage::TypeScript),
        )
        .unwrap();

        assert_eq!(api.tool_count, 1);
        assert_eq!(api.entries.len(), 1);
        assert_eq!(api.entries[0].original_name, "list-pull.requests");
        assert_eq!(
            api.entries[0].ts_accessor,
            "codemode[\"list-pull.requests\"]"
        );
        assert_eq!(api.entries[0].python_name, "list_pull_requests");
        assert_eq!(api.entries[0].input_type, "ListPullRequestsInput");
        assert_eq!(api.entries[0].output_type, "ListPullRequestsOutput");
        assert_eq!(
            api.entries[0].required,
            vec!["owner".to_string(), "labels".to_string()]
        );
        assert!(!api.truncated);

        let declarations = &api.declarations;
        assert!(declarations.contains("export interface ListPullRequestsInput {"));
        assert!(declarations.contains("owner: string;"));
        assert!(declarations.contains("labels: Array<string>;"));
        assert!(declarations.contains("state?: \"open\" | \"closed\";"));
        assert!(declarations.contains("page?: number;"));
        assert!(declarations.contains("note?: string | null;"));
        assert!(declarations.contains("filter?: { draft?: boolean; ids?: Array<number> }"));
        assert!(declarations.contains("\"weird key\"?: null;"));
        assert!(declarations.contains("export interface ListPullRequestsOutput {"));
        assert!(declarations.contains("items: Array<{ id?: string }>;"));
        assert!(declarations.contains("total: number;"));
        assert!(declarations.contains("export interface CodeModeApi {"));
        assert!(declarations.contains(
            "\"list-pull.requests\": (input: ListPullRequestsInput) => Promise<ListPullRequestsOutput>;"
        ));
        assert!(declarations.contains("export declare const codemode: CodeModeApi;"));

        assert!(api
            .example
            .contains("await codemode[\"list-pull.requests\"]("));
        assert!(api.example.contains("owner: \"value\""));
        assert!(api.example.contains("labels: []"));

        let description = &api.entries[0].description;
        assert!(!description.chars().any(char::is_control));
        assert!(description.len() <= DEFAULT_MAX_DESCRIPTION_BYTES);
    }

    #[test]
    fn typescript_escapes_comment_terminators_and_uses_a_long_enough_fence() {
        let mut catalog = sample_catalog();
        catalog.tools[0].description =
            Some("hostile */ comment ```fence``` with \u{0} a control".to_string());
        let config = CodeModeConfig::new(CodeLanguage::TypeScript);
        let api = generate_api(&catalog, &config).unwrap();
        let tool = code_tool(&api, &config);
        let description = tool.description.as_deref().unwrap();

        assert!(description.contains("*\\/"));
        assert!(!description.contains("*/ comment"));
        assert!(description.contains("````ts"));
    }

    #[test]
    fn unknown_and_deep_schemas_fall_back_with_a_comment() {
        let mut deep = json!({"type": "string"});
        for _ in 0..10 {
            deep = json!({"type": "object", "properties": {"next": deep}});
        }
        let catalog = catalog(vec![
            tool(
                "weird",
                json!({"anyOf": [{"type": "string"}, {"type": "number"}]}),
                None,
            ),
            tool("deep", deep, None),
        ]);
        let api = generate_api(&catalog, &CodeModeConfig::new(CodeLanguage::TypeScript)).unwrap();

        assert!(api.declarations.contains("typed as `unknown`"));
        assert!(api.declarations.contains("nests too deeply"));
        assert!(api
            .declarations
            .contains("export type WeirdInput = unknown;"));
    }

    #[test]
    fn python_generation_uses_typeddict_literal_list_and_snake_case() {
        let api = generate_api(
            &python_catalog(),
            &CodeModeConfig::new(CodeLanguage::Python),
        )
        .unwrap();
        let declarations = &api.declarations;

        assert!(declarations.starts_with("from typing import "));
        assert!(declarations.contains("class ListPullRequestsInput(TypedDict):"));
        assert!(declarations.contains("owner: str"));
        assert!(declarations.contains("state: NotRequired[Literal[\"open\", \"closed\"]]"));
        assert!(declarations.contains("labels: List[str]"));
        assert!(declarations.contains("page: NotRequired[int]"));
        assert!(declarations.contains("note: NotRequired[Optional[str]]"));
        assert!(declarations.contains("filter: NotRequired[Dict[str, Any]]"));
        assert!(declarations.contains("class ListPullRequestsOutput(TypedDict):"));
        assert!(declarations.contains("class codemode:"));
        assert!(declarations.contains(
            "def list_pull_requests(input: ListPullRequestsInput) -> ListPullRequestsOutput: ..."
        ));
        assert!(api
            .example
            .contains("result = codemode.list_pull_requests("));
    }

    #[test]
    fn python_functional_syntax_handles_property_names_that_are_not_identifiers() {
        let input = json!({
            "type": "object",
            "properties": {
                "x-y": {"type": "string"},
                "__private": {"type": "string"},
                "owner": {"type": "string"}
            },
            "required": ["owner"]
        });
        let api = generate_api(
            &catalog(vec![tool("odd", input, None)]),
            &CodeModeConfig::new(CodeLanguage::Python),
        )
        .unwrap();

        assert!(api.declarations.contains("OddInput = TypedDict("));
        assert!(api.declarations.contains("\"x-y\": NotRequired[str]"));
        assert!(api.declarations.contains("\"__private\": NotRequired[str]"));
        assert!(api.declarations.contains("\"owner\": str"));
    }

    #[test]
    fn sanitization_handles_leading_digits_keywords_and_collisions() {
        let names = ["3d-render", "delete", "list-pull.requests"];
        let api_catalog = catalog(
            names
                .iter()
                .map(|name| tool(name, json!({"type": "object", "properties": {}}), None))
                .collect(),
        );
        let ts =
            generate_api(&api_catalog, &CodeModeConfig::new(CodeLanguage::TypeScript)).unwrap();
        assert_eq!(ts.entries[0].ts_accessor, "codemode[\"3d-render\"]");
        assert_eq!(ts.entries[1].ts_accessor, "codemode.delete");
        assert_eq!(
            ts.entries[2].ts_accessor,
            "codemode[\"list-pull.requests\"]"
        );

        let python =
            generate_api(&api_catalog, &CodeModeConfig::new(CodeLanguage::Python)).unwrap();
        assert_eq!(python.entries[0].python_name, "_3d_render");
        assert_eq!(python.entries[0].input_type, "_3dRenderInput");
        assert_eq!(python.entries[1].python_name, "delete_");
        assert_eq!(python.entries[1].input_type, "DeleteInput");
        assert_eq!(python.entries[2].python_name, "list_pull_requests");

        let collision = catalog(vec![
            tool("foo-bar", json!({"type": "object", "properties": {}}), None),
            tool("foo.bar", json!({"type": "object", "properties": {}}), None),
        ]);
        let error =
            generate_api(&collision, &CodeModeConfig::new(CodeLanguage::Python)).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("foo-bar"));
        assert!(error.message().contains("foo.bar"));
        assert!(error.message().contains("foo_bar"));
    }

    // -- Budgets and server shapes -----------------------------------------

    #[test]
    fn declarations_truncate_whole_entries_and_report_truncated() {
        let long = "x".repeat(400);
        let tools = ["alpha", "beta", "gamma"]
            .iter()
            .map(|name| {
                let mut tool = tool(
                    name,
                    json!({
                        "type": "object",
                        "properties": {"query": {"type": "string"}}
                    }),
                    None,
                );
                tool.description = Some(long.clone());
                tool
            })
            .collect::<Vec<_>>();
        let catalog = catalog(tools);

        let full = generate_api(
            &catalog,
            &CodeModeConfig::new(CodeLanguage::TypeScript).with_max_api_bytes(100_000),
        )
        .unwrap();
        assert!(full.declarations.contains("export interface BetaInput"));

        let mut cut = None;
        for cap in MIN_MAX_API_BYTES..=full.declarations.len() {
            let candidate = generate_api(
                &catalog,
                &CodeModeConfig::new(CodeLanguage::TypeScript).with_max_api_bytes(cap),
            )
            .unwrap();
            if candidate
                .declarations
                .contains("export interface AlphaInput")
            {
                cut = Some(cap);
                break;
            }
        }
        let cut = cut.expect("some budget fits the first tool");

        let api = generate_api(
            &catalog,
            &CodeModeConfig::new(CodeLanguage::TypeScript).with_max_api_bytes(cut),
        )
        .unwrap();
        assert!(api.truncated);
        assert_eq!(api.entries.len(), 3);
        assert!(api.declarations.len() <= cut);
        assert!(api.declarations.contains("export interface AlphaInput"));
        assert!(!api.declarations.contains("export interface BetaInput"));
        assert!(!api.declarations.contains("export interface GammaInput"));
        assert!(api.example.contains("codemode.alpha"));
    }

    #[test]
    fn code_tool_description_contains_types_example_and_the_expected_schema() {
        let config = CodeModeConfig::new(CodeLanguage::TypeScript);
        let api = generate_api(&sample_catalog(), &config).unwrap();
        let tool = code_tool(&api, &config);

        assert_eq!(tool.name, CODE_TOOL_NAME);
        let description = tool.description.as_deref().unwrap();
        assert!(description.contains("ListPullRequestsInput"));
        assert!(description.contains("ListPullRequestsOutput"));
        assert!(description.contains(&api.example));
        assert!(description.contains("codemode"));

        assert_eq!(tool.input_schema["required"], json!(["code"]));
        assert_eq!(
            tool.input_schema["properties"]["code"]["type"],
            json!("string")
        );
        assert!(tool.output_schema.as_ref().unwrap()["properties"]["result"].is_object());
        let annotations = tool.annotations.as_ref().unwrap();
        assert_eq!(annotations.read_only_hint, Some(false));
        assert_eq!(annotations.idempotent_hint, Some(false));
        assert_eq!(decide(&tool, PolicyMode::Manual), ToolDecision::Ask);
    }

    #[test]
    fn code_tool_honours_template_placeholders() {
        let config = CodeModeConfig::new(CodeLanguage::TypeScript)
            .with_template("HEAD\n{{types}}\nSEP\n{{example}}\nTAIL");
        let api = generate_api(&sample_catalog(), &config).unwrap();
        let tool = code_tool(&api, &config);
        let description = tool.description.as_deref().unwrap();

        assert!(description.starts_with("HEAD\n"));
        assert!(description.contains("SEP\n"));
        assert!(description.ends_with("TAIL"));
        assert!(description.contains(&api.declarations));
        assert!(description.contains(&api.example));

        // Placeholders inside tool data are not rescanned or substituted.
        let mut catalog = sample_catalog();
        catalog.tools[0].description = Some("literal {{example}} text".to_string());
        let config = CodeModeConfig::new(CodeLanguage::TypeScript).with_template("{{types}}");
        let api = generate_api(&catalog, &config).unwrap();
        let tool = code_tool(&api, &config);
        assert!(tool
            .description
            .as_deref()
            .unwrap()
            .contains("literal {{example}} text"));
    }

    #[test]
    fn search_execute_shape_indexes_names_without_embedding_the_api() {
        let tools = (0..25)
            .map(|index| {
                let mut tool = tool(
                    &format!("tool-{index:02}"),
                    json!({"type": "object", "properties": {}}),
                    None,
                );
                tool.description = Some(format!("Description for tool {index}"));
                tool
            })
            .collect::<Vec<_>>();
        let catalog = catalog(tools);
        let config = CodeModeConfig::for_catalog(CodeLanguage::TypeScript, &catalog);
        assert_eq!(config.pattern, CodeModePattern::SearchExecute);

        let api = generate_api(&catalog, &config).unwrap();
        let tools = search_execute_tools(&api, &config);
        assert_eq!(tools.len(), 2);
        assert_eq!(tools[0].name, SEARCH_TOOL_NAME);
        assert_eq!(tools[1].name, EXECUTE_TOOL_NAME);

        let search_description = tools[0].description.as_deref().unwrap();
        assert!(search_description.contains("tool-00"));
        assert!(search_description.contains("tool-24"));
        assert!(!search_description.contains("export interface"));
        assert_eq!(tools[0].input_schema["required"], json!(["query"]));
        assert_eq!(tools[1].input_schema["required"], json!(["code"]));
        assert_eq!(
            tools[0].annotations.as_ref().unwrap().read_only_hint,
            Some(true)
        );
        assert_eq!(
            tools[1].annotations.as_ref().unwrap().read_only_hint,
            Some(false)
        );
    }

    #[test]
    fn pattern_threshold_switches_to_search_execute() {
        assert_eq!(
            CodeModePattern::for_tool_count(DEFAULT_SEARCH_EXECUTE_THRESHOLD - 1),
            CodeModePattern::SingleTool
        );
        assert_eq!(
            CodeModePattern::for_tool_count(DEFAULT_SEARCH_EXECUTE_THRESHOLD),
            CodeModePattern::SearchExecute
        );
    }

    #[test]
    fn generation_is_deterministic_and_rejects_invalid_budgets() {
        let config = CodeModeConfig::new(CodeLanguage::TypeScript);
        let catalog = sample_catalog();
        assert_eq!(
            generate_api(&catalog, &config).unwrap(),
            generate_api(&catalog, &config).unwrap()
        );

        for bad in [
            CodeModeConfig::new(CodeLanguage::TypeScript).with_max_api_bytes(0),
            CodeModeConfig::new(CodeLanguage::TypeScript).with_max_api_bytes(MIN_MAX_API_BYTES - 1),
            CodeModeConfig::new(CodeLanguage::TypeScript).with_max_description_bytes(0),
        ] {
            assert_eq!(
                generate_api(&catalog, &bad).unwrap_err().code(),
                ErrorCode::InvalidInput
            );
        }
    }

    // -- Execution bridge and the Done criterion ---------------------------

    struct MapHost;

    impl ToolHost for MapHost {
        fn list_tools(&self) -> Result<Vec<Tool>> {
            Ok(Vec::new())
        }

        fn call_tool(&self, name: &str, arguments: Value) -> Result<Value> {
            match name {
                "read_alpha" => Ok(json!({"count": 2, "raw": "INTERMEDIATE_ALPHA"})),
                "read_beta" => Ok(json!({"count": 3, "raw": "INTERMEDIATE_BETA"})),
                "write_result" => Ok(json!({
                    "total": arguments["total"],
                    "ok": true,
                    "writeRaw": "INTERMEDIATE_WRITE"
                })),
                _ => Ok(json!({"ok": true})),
            }
        }
    }

    struct DoneExecutor;

    impl CodeExecutor for DoneExecutor {
        fn run(&self, program: &str, bridge: &mut dyn CodeModeBridge) -> Result<Value> {
            assert_eq!(program, "done");
            let alpha = bridge.call("read_alpha", json!({"secret": "ALPHA"}))?;
            let beta = bridge.call("read_beta", json!({"secret": "BETA"}))?;
            let total = alpha["count"].as_i64().unwrap() + beta["count"].as_i64().unwrap();
            let written = bridge.call("write_result", json!({"total": total}))?;
            Ok(json!({"total": written["total"], "ok": written["ok"]}))
        }
    }

    struct CountingApproval {
        allow: bool,
        calls: Rc<Cell<usize>>,
    }

    impl ApprovalOracle for CountingApproval {
        fn approve(&mut self, _tool: &str, _risk: ToolRisk) -> bool {
            self.calls.set(self.calls.get() + 1);
            self.allow
        }
    }

    fn done_host() -> CodeModeHost<MapHost> {
        let catalog = catalog(vec![
            read_tool("read_alpha"),
            read_tool("read_beta"),
            write_tool("write_result"),
        ]);
        let approvals = Rc::new(Cell::new(0));
        let host = CodeModeHost::new(
            catalog,
            MapHost,
            &CodeModeConfig::new(CodeLanguage::TypeScript),
        )
        .unwrap()
        .with_approval(Box::new(CountingApproval {
            allow: true,
            calls: Rc::clone(&approvals),
        }))
        .with_program_id("done-program");
        // Keep the counter alive for the assertion below.
        assert_eq!(approvals.get(), 0);
        host
    }

    #[test]
    fn done_criterion_two_reads_and_an_approved_write_return_only_the_final_value() {
        let mut host = done_host();
        let final_value =
            execute("done", &DoneExecutor, &mut host, &CodeModeLimits::default()).unwrap();

        assert_eq!(final_value, json!({"total": 5, "ok": true}));
        let text = final_value.to_string();
        assert!(!text.contains("INTERMEDIATE"));
        assert!(!text.contains("raw"));

        let calls = host.calls();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls
                .iter()
                .map(|call| call.tool.as_str())
                .collect::<Vec<_>>(),
            vec!["read_alpha", "read_beta", "write_result"]
        );
        assert_eq!(
            calls.iter().map(|call| call.decision).collect::<Vec<_>>(),
            vec![ToolDecision::Allow, ToolDecision::Allow, ToolDecision::Ask]
        );
        assert_eq!(
            calls.iter().map(|call| call.risk).collect::<Vec<_>>(),
            vec![ToolRisk::ReadOnly, ToolRisk::ReadOnly, ToolRisk::Write]
        );
        assert!(calls.iter().all(|call| call.approved));
        assert!(!format!("{calls:?}").contains("ALPHA"));
        assert!(!format!("{calls:?}").contains("total"));
    }

    #[test]
    fn policy_allows_reads_asks_writes_and_denies_destructive_tools_in_restricted() {
        let catalog = catalog(vec![
            read_tool("read_doc"),
            write_tool("write_doc"),
            annotated("drop_all", Some(false), Some(true)),
            tool("mystery", json!({"type": "object", "properties": {}}), None),
        ]);
        let config = CodeModeConfig::new(CodeLanguage::TypeScript);
        let mut host = CodeModeHost::new(catalog.clone(), MapHost, &config).unwrap();

        host.call_at("p", 0, "read_doc", json!({})).unwrap();
        assert_eq!(
            host.call_at("p", 1, "write_doc", json!({}))
                .unwrap_err()
                .code(),
            ErrorCode::PolicyAskRequired
        );
        assert_eq!(
            host.call_at("p", 2, "mystery", json!({}))
                .unwrap_err()
                .code(),
            ErrorCode::PolicyAskRequired
        );

        let mut restricted = CodeModeHost::new(catalog.clone(), MapHost, &config)
            .unwrap()
            .with_policy_mode(PolicyMode::Restricted);
        assert_eq!(
            restricted
                .call_at("r", 0, "drop_all", json!({}))
                .unwrap_err()
                .code(),
            ErrorCode::PolicyDenied
        );

        let mut approved = CodeModeHost::new(catalog, MapHost, &config)
            .unwrap()
            .with_approval(Box::new(CountingApproval {
                allow: true,
                calls: Rc::new(Cell::new(0)),
            }));
        approved.call_at("a", 0, "write_doc", json!({})).unwrap();
        assert_eq!(approved.calls().len(), 1);
        assert!(approved.calls()[0].approved);
    }

    struct EchoExecutor;

    impl CodeExecutor for EchoExecutor {
        fn run(&self, _program: &str, _bridge: &mut dyn CodeModeBridge) -> Result<Value> {
            Ok(json!("ran"))
        }
    }

    struct HugeExecutor;

    impl CodeExecutor for HugeExecutor {
        fn run(&self, _program: &str, _bridge: &mut dyn CodeModeBridge) -> Result<Value> {
            Ok(json!({"blob": "x".repeat(200)}))
        }
    }

    struct ThreeCallsExecutor;

    impl CodeExecutor for ThreeCallsExecutor {
        fn run(&self, _program: &str, bridge: &mut dyn CodeModeBridge) -> Result<Value> {
            for _ in 0..3 {
                bridge.call("read_doc", json!({}))?;
            }
            Ok(Value::Null)
        }
    }

    struct SwallowAskExecutor;

    impl CodeExecutor for SwallowAskExecutor {
        fn run(&self, _program: &str, bridge: &mut dyn CodeModeBridge) -> Result<Value> {
            let _ = bridge.call("write_doc", json!({}));
            let _ = bridge.call("read_doc", json!({}));
            Ok(json!({"swallowed": true}))
        }
    }

    fn simple_host() -> CodeModeHost<MapHost> {
        CodeModeHost::new(
            catalog(vec![read_tool("read_doc")]),
            MapHost,
            &CodeModeConfig::new(CodeLanguage::TypeScript),
        )
        .unwrap()
    }

    #[test]
    fn caps_source_result_call_count_and_argument_depth() {
        let limits = CodeModeLimits {
            max_source_bytes: 4,
            ..CodeModeLimits::default()
        };
        let mut host = simple_host();
        let error = execute("12345", &EchoExecutor, &mut host, &limits).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("source bytes"));
        assert!(host.calls().is_empty());

        let limits = CodeModeLimits {
            max_result_bytes: 16,
            ..CodeModeLimits::default()
        };
        let error = execute("ok", &HugeExecutor, &mut host, &limits).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("result bytes"));
        assert!(!error.message().contains("blob"));

        let limits = CodeModeLimits {
            max_calls: 2,
            ..CodeModeLimits::default()
        };
        let error = execute("ok", &ThreeCallsExecutor, &mut host, &limits).unwrap_err();
        assert_eq!(error.code(), ErrorCode::LimitExceeded);
        assert!(error.message().contains("bridge calls"));

        let mut depth_host = simple_host().with_limits(CodeModeLimits {
            max_argument_bytes: 1024,
            max_argument_depth: 2,
            ..CodeModeLimits::default()
        });
        let depth = depth_host
            .call_at("p", 0, "read_doc", json!({"a": {"b": {"c": 1}}}))
            .unwrap_err();
        assert_eq!(depth.code(), ErrorCode::LimitExceeded);
        assert!(depth.message().contains("argument depth"));

        let mut byte_host = simple_host().with_limits(CodeModeLimits {
            max_argument_bytes: 16,
            ..CodeModeLimits::default()
        });
        let bytes = byte_host
            .call_at(
                "p",
                1,
                "read_doc",
                json!({"x": "012345678901234567890123456789"}),
            )
            .unwrap_err();
        assert_eq!(bytes.code(), ErrorCode::LimitExceeded);
        assert!(bytes.message().contains("argument bytes"));
    }

    #[test]
    fn a_swallowed_policy_refusal_still_aborts_the_program() {
        let mut host = CodeModeHost::new(
            catalog(vec![read_tool("read_doc"), write_tool("write_doc")]),
            MapHost,
            &CodeModeConfig::new(CodeLanguage::TypeScript),
        )
        .unwrap();

        let error = execute(
            "ok",
            &SwallowAskExecutor,
            &mut host,
            &CodeModeLimits::default(),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyAskRequired);
        assert_eq!(host.calls().len(), 1);
        assert_eq!(host.calls()[0].tool, "write_doc");
    }

    #[test]
    fn replay_guard_rejects_a_repeated_program_and_index() {
        let mut host = simple_host();
        const SECRET: &str = "SECRET_ARGUMENT_0123456789";
        host.call_at("p", 3, "read_doc", json!({"secret": SECRET}))
            .unwrap();
        let error = host
            .call_at("p", 3, "read_doc", json!({"secret": SECRET}))
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains('3'));
        assert!(!error.message().contains(SECRET));

        // A different program may use the same index.
        host.call_at("q", 3, "read_doc", json!({})).unwrap();
    }

    #[test]
    fn errors_and_call_records_never_contain_arguments_or_results() {
        const SECRET: &str = "SECRET_PAYLOAD_0123456789";
        let catalog = catalog(vec![
            write_tool("write_doc"),
            annotated("drop_all", Some(false), Some(true)),
        ]);
        let config = CodeModeConfig::new(CodeLanguage::TypeScript);
        let mut host = CodeModeHost::new(catalog.clone(), MapHost, &config).unwrap();

        let ask_error = host
            .call_at("p", 0, "write_doc", json!({"secret": SECRET}))
            .unwrap_err();
        assert_eq!(ask_error.code(), ErrorCode::PolicyAskRequired);
        assert!(!ask_error.message().contains(SECRET));

        let mut restricted = CodeModeHost::new(catalog, MapHost, &config)
            .unwrap()
            .with_policy_mode(PolicyMode::Restricted);
        let deny_error = restricted
            .call_at("r", 0, "drop_all", json!({"secret": SECRET}))
            .unwrap_err();
        assert_eq!(deny_error.code(), ErrorCode::PolicyDenied);
        assert!(!deny_error.message().contains(SECRET));

        let mut small = simple_host().with_limits(CodeModeLimits {
            max_argument_bytes: 8,
            ..CodeModeLimits::default()
        });
        let limit_error = small
            .call_at("s", 0, "read_doc", json!({"secret": SECRET}))
            .unwrap_err();
        assert_eq!(limit_error.code(), ErrorCode::LimitExceeded);
        assert!(!limit_error.message().contains(SECRET));

        let records = format!("{:?}", host.calls());
        assert!(!records.contains(SECRET));
        assert!(!format!("{:?}", small.calls()).contains(SECRET));
    }

    #[test]
    fn search_hits_return_name_description_and_accessor_without_arguments() {
        let mut catalog = sample_catalog();
        catalog.tools.push(tool(
            "other",
            json!({"type": "object", "properties": {}}),
            None,
        ));
        let host = CodeModeHost::new(
            catalog.clone(),
            MapHost,
            &CodeModeConfig::new(CodeLanguage::TypeScript),
        )
        .unwrap();

        let hits = host.search_hits("pull");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].name, "list-pull.requests");
        assert_eq!(hits[0].accessor, "codemode[\"list-pull.requests\"]");
        assert!(!hits[0].description.is_empty());
        assert!(!format!("{hits:?}").contains("owner"));

        let python_host =
            CodeModeHost::new(catalog, MapHost, &CodeModeConfig::new(CodeLanguage::Python))
                .unwrap();
        assert_eq!(
            python_host.search_hits("pull")[0].accessor,
            "codemode.list_pull_requests"
        );
    }

    #[test]
    fn generated_api_does_not_embed_call_arguments_or_results() {
        const SECRET: &str = "SECRET_CALL_DATA_0123456789";
        let catalog = catalog(vec![read_tool("read_doc")]);
        let config = CodeModeConfig::new(CodeLanguage::TypeScript);
        let api = generate_api(&catalog, &config).unwrap();
        let mut host = CodeModeHost::new(catalog, MapHost, &config).unwrap();
        host.call_at("p", 0, "read_doc", json!({"secret": SECRET}))
            .unwrap();

        assert!(!api.declarations.contains(SECRET));
        assert!(!api.example.contains(SECRET));
        assert!(!search_description(&api, &config).contains(SECRET));
    }
}
