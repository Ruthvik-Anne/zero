//! MCP resources, prompts, `@` references, slash commands, and completions
//! (T-MCP-09, MCP-09 and MCP-16).
//!
//! The module is deliberately transport-free. It parses the `resources/list`,
//! `resources/templates/list`, and `prompts/list` result shapes into validated
//! catalogues, resolves `@` references, parses slash commands, and produces
//! bounded local completions. Nothing here contacts a server or a child
//! process.
//!
//! The one persistence seam is [`ResourceStore`]: a JSON file holding one
//! [`ResourceCatalog`] per server. After a reload, [`ResourceStore::resolve`]
//! still returns the same resource even when the server is offline, which is
//! this task's Done criterion. A missing file opens an empty store; a corrupt
//! file or an unsupported schema is a typed error.
//!
//! Only simple level-1 RFC 6570 `{var}` expressions are understood for
//! template matching. Operator expressions (`{+path}`, `{/path}`, ...) are
//! retained in the catalogue but never match, and percent-decoding is not
//! applied. Slash commands use plain whitespace tokenisation plus `key=value`;
//! there is no quoting or escaping. [`CompletionRequest`] and
//! [`CompletionTransport`] model the optional server-side
//! `completion/complete` call, but it is not wired into `Client` yet. See
//! `docs/mcp.md` for the full grammar, resolution order, and deferred items.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::jsonrpc::{expect_result, protocol_error, Request, RequestId};

/// JSON schema version written by [`ResourceStore::save`].
pub const RESOURCE_STORE_SCHEMA_VERSION: u32 = 1;

/// Largest number of completions returned for one prefix.
pub const MAX_COMPLETIONS: usize = 100;

/// `resources/list` method name.
pub const METHOD_RESOURCES_LIST: &str = "resources/list";
/// `resources/templates/list` method name.
pub const METHOD_RESOURCES_TEMPLATES_LIST: &str = "resources/templates/list";
/// `resources/read` method name (the call itself is deferred).
pub const METHOD_RESOURCES_READ: &str = "resources/read";
/// `prompts/list` method name.
pub const METHOD_PROMPTS_LIST: &str = "prompts/list";
/// `prompts/get` method name (the call itself is deferred).
pub const METHOD_PROMPTS_GET: &str = "prompts/get";
/// `completion/complete` method name.
pub const METHOD_COMPLETION_COMPLETE: &str = "completion/complete";

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn not_found(reference: &ResourceRef) -> ZeroError {
    ZeroError::new(
        ErrorCode::NotFound,
        format!("no MCP resource matches `{reference}`"),
    )
}

fn ambiguous(reference: &ResourceRef, candidates: &BTreeSet<String>) -> ZeroError {
    let list = candidates.iter().cloned().collect::<Vec<_>>().join(", ");
    ZeroError::new(
        ErrorCode::InvalidInput,
        format!("MCP resource reference `{reference}` is ambiguous; candidates: {list}"),
    )
}

/// Why a reference did not resolve to exactly one target.
///
/// This is the typed projection of [`ResourceStore::resolve`] failures:
/// [`ErrorCode::NotFound`] is always [`LookupFailure::NotFound`], and an
/// ambiguous reference is [`ErrorCode::InvalidInput`] with a message that
/// lists the candidates. A malformed reference is also
/// [`ErrorCode::InvalidInput`], but comes from [`ResourceRef::parse`] before
/// any lookup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LookupFailure {
    /// Nothing in the store matched.
    NotFound,
    /// More than one target matched at the strongest resolution stage.
    Ambiguous,
}

impl LookupFailure {
    /// Classify a lookup error; `None` means the error is not a lookup
    /// failure.
    pub fn from_error(error: &ZeroError) -> Option<Self> {
        match error.code() {
            ErrorCode::NotFound => Some(Self::NotFound),
            ErrorCode::InvalidInput if error.message().contains("is ambiguous") => {
                Some(Self::Ambiguous)
            }
            _ => None,
        }
    }
}

/// Returns a human-readable problem when `value` is not a usable token.
fn token_problem(value: &str, what: &str) -> Option<String> {
    if value.trim().is_empty() {
        Some(format!("{what} must not be empty"))
    } else if value
        .chars()
        .any(|character| character.is_whitespace() || character.is_control())
    {
        Some(format!(
            "{what} must not contain whitespace or control characters"
        ))
    } else {
        None
    }
}

fn string_field(object: &Map<String, Value>, field: &str, context: &str) -> Result<String> {
    match object.get(field) {
        Some(Value::String(value)) => Ok(value.clone()),
        Some(other) => Err(protocol_error(format!(
            "{context} `{field}` must be a string, got {other}"
        ))),
        None => Err(protocol_error(format!("{context} is missing `{field}`"))),
    }
}

fn optional_string(
    object: &Map<String, Value>,
    field: &str,
    context: &str,
) -> Result<Option<String>> {
    match object.get(field) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => Ok(Some(value.clone())),
        Some(other) => Err(protocol_error(format!(
            "{context} `{field}` must be a string, got {other}"
        ))),
    }
}

fn as_object<'a>(value: &'a Value, context: &str) -> Result<&'a Map<String, Value>> {
    match value {
        Value::Object(object) => Ok(object),
        _ => Err(protocol_error(format!("{context} must be an object"))),
    }
}

// ---------------------------------------------------------------------------
// Resources
// ---------------------------------------------------------------------------

/// One resource advertised by `resources/list`.
///
/// Titles and descriptions are untrusted server data: they are payload here,
/// never instructions.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Resource {
    /// Resource URI used by `resources/read`.
    pub uri: String,
    /// Stable name used by `@` references.
    pub name: String,
    /// Optional display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Optional MIME type.
    #[serde(default, rename = "mimeType", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

impl Resource {
    /// Parse one entry of a `resources/list` result.
    pub fn from_value(value: &Value, context: &str) -> Result<Self> {
        let object = as_object(value, context)?;
        let uri = string_field(object, "uri", context)?;
        if let Some(problem) = token_problem(&uri, &format!("{context} `uri`")) {
            return Err(protocol_error(problem));
        }
        let name = string_field(object, "name", context)?;
        if let Some(problem) = token_problem(&name, &format!("{context} `name`")) {
            return Err(protocol_error(problem));
        }
        Ok(Self {
            uri,
            name,
            title: optional_string(object, "title", context)?,
            description: optional_string(object, "description", context)?,
            mime_type: optional_string(object, "mimeType", context)?,
        })
    }
}

/// One resource template advertised by `resources/templates/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceTemplate {
    /// RFC 6570-style URI template (`file:///{path}`).
    #[serde(rename = "uriTemplate")]
    pub uri_template: String,
    /// Stable template name.
    pub name: String,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

impl ResourceTemplate {
    /// Parse one entry of a `resources/templates/list` result.
    pub fn from_value(value: &Value, context: &str) -> Result<Self> {
        let object = as_object(value, context)?;
        let uri_template = string_field(object, "uriTemplate", context)?;
        if let Some(problem) = token_problem(&uri_template, &format!("{context} `uriTemplate`")) {
            return Err(protocol_error(problem));
        }
        let name = string_field(object, "name", context)?;
        if let Some(problem) = token_problem(&name, &format!("{context} `name`")) {
            return Err(protocol_error(problem));
        }
        Ok(Self {
            uri_template,
            name,
            description: optional_string(object, "description", context)?,
        })
    }
}

/// A resolved `@` target: a concrete resource or a matching template.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Resolved<'a> {
    /// A resource advertised by `resources/list`.
    Resource(&'a Resource),
    /// A template whose pattern matched the target URI.
    Template(&'a ResourceTemplate),
}

impl Resolved<'_> {
    /// The resource or template name.
    pub fn name(&self) -> &str {
        match self {
            Resolved::Resource(resource) => &resource.name,
            Resolved::Template(template) => &template.name,
        }
    }

    /// The resource URI or template pattern.
    pub fn uri(&self) -> &str {
        match self {
            Resolved::Resource(resource) => &resource.uri,
            Resolved::Template(template) => &template.uri_template,
        }
    }
}

/// How strongly a target matched, in resolution order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum MatchStrength {
    Uri,
    Name,
    CaseInsensitiveName,
    Template,
}

struct Candidate<'a> {
    strength: MatchStrength,
    resolved: Resolved<'a>,
}

/// A validated `resources/list` plus `resources/templates/list` catalogue for
/// one server.
///
/// Duplicate resource names, resource URIs, template names, and template
/// patterns are protocol errors: the whole catalogue is rejected rather than
/// silently picking one entry.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceCatalog {
    /// Configured server name.
    pub server: String,
    /// Resources in server order.
    #[serde(default)]
    pub resources: Vec<Resource>,
    /// Templates in server order.
    #[serde(default)]
    pub templates: Vec<ResourceTemplate>,
}

impl ResourceCatalog {
    /// An empty catalogue for `server`.
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            resources: Vec::new(),
            templates: Vec::new(),
        }
    }

    /// Parse a `resources/list` result; templates stay empty.
    pub fn from_resources_list(server: impl Into<String>, value: &Value) -> Result<Self> {
        let mut catalog = Self::new(server);
        catalog.set_resources(value)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Parse a `resources/templates/list` result; resources stay empty.
    pub fn from_templates_list(server: impl Into<String>, value: &Value) -> Result<Self> {
        let mut catalog = Self::new(server);
        catalog.set_templates(value)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Parse both list results into one catalogue.
    pub fn from_lists(
        server: impl Into<String>,
        resources: &Value,
        templates: &Value,
    ) -> Result<Self> {
        let mut catalog = Self::new(server);
        catalog.set_resources(resources)?;
        catalog.set_templates(templates)?;
        catalog.validate()?;
        Ok(catalog)
    }

    /// Replace the resources from a `resources/list` result.
    ///
    /// The pagination `nextCursor` is ignored; the caller pages if it wants
    /// more. Unknown fields are ignored.
    pub fn set_resources(&mut self, value: &Value) -> Result<()> {
        let object = as_object(value, "`resources/list` result")?;
        let items = match object.get("resources") {
            Some(Value::Array(items)) => items,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`resources/list` result `resources` must be an array, got {other}"
                )))
            }
            None => {
                return Err(protocol_error(
                    "`resources/list` result is missing `resources`",
                ))
            }
        };
        let mut resources = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            resources.push(Resource::from_value(
                item,
                &format!("`resources/list` resource[{index}]"),
            )?);
        }
        self.resources = resources;
        Ok(())
    }

    /// Replace the templates from a `resources/templates/list` result.
    pub fn set_templates(&mut self, value: &Value) -> Result<()> {
        let object = as_object(value, "`resources/templates/list` result")?;
        let items = match object.get("templates") {
            Some(Value::Array(items)) => items,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`resources/templates/list` result `templates` must be an array, got {other}"
                )))
            }
            None => {
                return Err(protocol_error(
                    "`resources/templates/list` result is missing `templates`",
                ))
            }
        };
        let mut templates = Vec::with_capacity(items.len());
        for (index, item) in items.iter().enumerate() {
            templates.push(ResourceTemplate::from_value(
                item,
                &format!("`resources/templates/list` template[{index}]"),
            )?);
        }
        self.templates = templates;
        Ok(())
    }

    /// Validate names, URIs, and uniqueness.
    ///
    /// This is also run after loading [`ResourceStore`], because a stored file
    /// is data, not a witness that the catalogue was valid when saved.
    pub fn validate(&self) -> Result<()> {
        if let Some(problem) = token_problem(&self.server, "resource catalog server name") {
            return Err(protocol_error(problem));
        }

        let mut names: BTreeMap<&str, &str> = BTreeMap::new();
        let mut uris: BTreeSet<&str> = BTreeSet::new();
        for (index, resource) in self.resources.iter().enumerate() {
            if let Some(problem) = token_problem(
                &resource.uri,
                &format!("`resources/list` resource[{index}] `uri`"),
            ) {
                return Err(protocol_error(problem));
            }
            if let Some(problem) = token_problem(
                &resource.name,
                &format!("`resources/list` resource[{index}] `name`"),
            ) {
                return Err(protocol_error(problem));
            }
            if !uris.insert(resource.uri.as_str()) {
                return Err(protocol_error(format!(
                    "`resources/list` for server `{}` advertises duplicate resource URI `{}`",
                    self.server, resource.uri
                )));
            }
            if let Some(previous) = names.insert(resource.name.as_str(), resource.uri.as_str()) {
                return Err(protocol_error(format!(
                    "`resources/list` for server `{}` advertises duplicate resource name `{}` (`{previous}` and `{}`)",
                    self.server, resource.name, resource.uri
                )));
            }
        }

        let mut template_names: BTreeSet<&str> = BTreeSet::new();
        let mut template_uris: BTreeSet<&str> = BTreeSet::new();
        for (index, template) in self.templates.iter().enumerate() {
            if let Some(problem) = token_problem(
                &template.uri_template,
                &format!("`resources/templates/list` template[{index}] `uriTemplate`"),
            ) {
                return Err(protocol_error(problem));
            }
            if let Some(problem) = token_problem(
                &template.name,
                &format!("`resources/templates/list` template[{index}] `name`"),
            ) {
                return Err(protocol_error(problem));
            }
            if !template_uris.insert(template.uri_template.as_str()) {
                return Err(protocol_error(format!(
                    "`resources/templates/list` for server `{}` advertises duplicate template `{}`",
                    self.server, template.uri_template
                )));
            }
            if !template_names.insert(template.name.as_str()) {
                return Err(protocol_error(format!(
                    "`resources/templates/list` for server `{}` advertises duplicate template name `{}`",
                    self.server, template.name
                )));
            }
        }
        Ok(())
    }

    /// Every resource with an exact name.
    pub fn resource(&self, name: &str) -> Option<&Resource> {
        self.resources.iter().find(|resource| resource.name == name)
    }

    /// Every template with an exact name.
    pub fn template(&self, name: &str) -> Option<&ResourceTemplate> {
        self.templates.iter().find(|template| template.name == name)
    }

    /// Resolve a reference against this one catalogue.
    ///
    /// Resolution order is exact URI, exact name, unique case-insensitive
    /// name, then a URI template match (only for targets containing `://`).
    /// A server-qualified reference for another server is not found.
    pub fn resolve(&self, reference: &ResourceRef) -> Result<Resolved<'_>> {
        if let Some(server) = &reference.server {
            if server != &self.server {
                return Err(not_found(reference));
            }
        }
        let found = self
            .candidates(&reference.target)
            .into_iter()
            .map(|candidate| {
                (
                    Some(self.server.as_str()),
                    candidate.strength,
                    candidate.resolved,
                )
            })
            .collect();
        pick(reference, found, false)
    }

    fn candidates(&self, target: &str) -> Vec<Candidate<'_>> {
        let target_lower = target.to_lowercase();
        let mut candidates = Vec::new();
        for resource in &self.resources {
            let resolved = Resolved::Resource(resource);
            if resource.uri == target {
                candidates.push(Candidate {
                    strength: MatchStrength::Uri,
                    resolved,
                });
            }
            if resource.name == target {
                candidates.push(Candidate {
                    strength: MatchStrength::Name,
                    resolved,
                });
            } else if resource.name.to_lowercase() == target_lower {
                candidates.push(Candidate {
                    strength: MatchStrength::CaseInsensitiveName,
                    resolved,
                });
            }
        }
        if target.contains("://") {
            for template in &self.templates {
                if template_matches(&template.uri_template, target) {
                    candidates.push(Candidate {
                        strength: MatchStrength::Template,
                        resolved: Resolved::Template(template),
                    });
                }
            }
        }
        candidates
    }
}

/// Pick the strongest unique candidate, or report not-found/ambiguity.
fn pick<'a>(
    reference: &ResourceRef,
    found: Vec<(Option<&'a str>, MatchStrength, Resolved<'a>)>,
    qualify_server: bool,
) -> Result<Resolved<'a>> {
    if found.is_empty() {
        return Err(not_found(reference));
    }
    let best = found
        .iter()
        .map(|(_, strength, _)| *strength)
        .min()
        .expect("the candidate list is not empty");
    let winners: Vec<(Option<&'a str>, Resolved<'a>)> = found
        .into_iter()
        .filter(|(_, strength, _)| *strength == best)
        .map(|(server, _, resolved)| (server, resolved))
        .collect();
    if winners.len() > 1 {
        let mut candidates = BTreeSet::new();
        for (server, resolved) in &winners {
            let label = match (qualify_server, server) {
                (true, Some(server)) => {
                    format!("{server}:{} ({})", resolved.name(), resolved.uri())
                }
                _ => format!("{} ({})", resolved.name(), resolved.uri()),
            };
            candidates.insert(label);
        }
        return Err(ambiguous(reference, &candidates));
    }
    Ok(winners[0].1)
}

/// The strongly typed form of an `@` reference.
///
/// | Input | `server` | `target` |
/// |---|---|---|
/// | `@name` | `None` | `name` |
/// | `@server:name` | `some(server)` | `name` |
/// | `@ui://app/view` | `None` | `ui://app/view` |
///
/// The URI form is recognised first: when the text after `@` contains `://`,
/// the whole remainder is the target and no server is parsed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceRef {
    /// Optional configured server name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server: Option<String>,
    /// Resource name or URI.
    pub target: String,
}

impl ResourceRef {
    /// Parse an `@` reference.
    pub fn parse(input: &str) -> Result<Self> {
        let remainder = input
            .strip_prefix('@')
            .ok_or_else(|| invalid(format!("resource reference `{input}` must start with `@`")))?;
        if let Some(problem) = token_problem(remainder, "resource reference") {
            return Err(invalid(problem));
        }
        if remainder.starts_with('/') {
            return Err(invalid(
                "resource reference must name a resource after `@`, as in `@notes`",
            ));
        }
        if remainder.contains("://") {
            return Ok(Self {
                server: None,
                target: remainder.to_string(),
            });
        }
        match remainder.split_once(':') {
            Some((server, target)) => {
                if server.is_empty() {
                    return Err(invalid(
                        "server-qualified reference must name a server before `:`",
                    ));
                }
                if target.is_empty() {
                    return Err(invalid(
                        "server-qualified reference must name a target after `:`",
                    ));
                }
                Ok(Self {
                    server: Some(server.to_string()),
                    target: target.to_string(),
                })
            }
            None => Ok(Self {
                server: None,
                target: remainder.to_string(),
            }),
        }
    }

    /// Render the canonical `@` form.
    pub fn as_reference(&self) -> String {
        match &self.server {
            Some(server) => format!("@{server}:{}", self.target),
            None => format!("@{}", self.target),
        }
    }
}

impl fmt::Display for ResourceRef {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_reference())
    }
}

/// Parse an `@` reference; free-function form of [`ResourceRef::parse`].
pub fn parse_reference(input: &str) -> Result<ResourceRef> {
    ResourceRef::parse(input)
}

/// Simple level-1 template matching: every `{var}` matches any run of
/// characters, including an empty one. Operator expressions, prefixes, and
/// percent-decoding are not implemented.
fn template_matches(template: &str, uri: &str) -> bool {
    let Some(tokens) = template_tokens(template) else {
        return false;
    };
    let uri: Vec<char> = uri.chars().collect();
    let mut pattern_index = 0;
    let mut uri_index = 0;
    let mut wildcard: Option<(usize, usize)> = None;

    loop {
        if pattern_index < tokens.len() {
            match &tokens[pattern_index] {
                TemplateToken::Var => {
                    wildcard = Some((pattern_index + 1, uri_index));
                    pattern_index += 1;
                    continue;
                }
                TemplateToken::Literal(literal) => {
                    if literal.is_empty() {
                        pattern_index += 1;
                        continue;
                    }
                    if uri[uri_index..].starts_with(literal) {
                        uri_index += literal.len();
                        pattern_index += 1;
                        continue;
                    }
                }
            }
        } else if uri_index == uri.len() {
            return true;
        }

        match wildcard {
            Some((next_pattern, start)) if start < uri.len() => {
                let next = start + 1;
                wildcard = Some((next_pattern, next));
                uri_index = next;
                pattern_index = next_pattern;
            }
            _ => return false,
        }
    }
}

enum TemplateToken {
    Literal(Vec<char>),
    Var,
}

fn template_tokens(template: &str) -> Option<Vec<TemplateToken>> {
    let mut tokens = Vec::new();
    let mut rest = template;
    while let Some(open) = rest.find('{') {
        if open > 0 {
            tokens.push(TemplateToken::Literal(rest[..open].chars().collect()));
        }
        let close = rest[open..].find('}')? + open;
        let expression = &rest[open + 1..close];
        if !valid_template_variable(expression) {
            return None;
        }
        tokens.push(TemplateToken::Var);
        rest = &rest[close + 1..];
    }
    if !rest.is_empty() {
        tokens.push(TemplateToken::Literal(rest.chars().collect()));
    }
    Some(tokens)
}

fn valid_template_variable(expression: &str) -> bool {
    !expression.is_empty()
        && !expression.starts_with(['+', '#', '.', '/', ';', '?', '&'])
        && expression
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || character == '_')
}

/// A JSON-file store of resource catalogues keyed by server.
///
/// The wire shape is:
///
/// ```json
/// {
///   "schema": 1,
///   "servers": {
///     "files": {"server": "files", "resources": [], "templates": []}
///   }
/// }
/// ```
///
/// [`Self::open`] treats a missing file as an empty store. [`Self::save`]
/// writes a temporary file and renames it over the destination, so a crash
/// leaves either the old file or the new one. Lookups never need the server:
/// this is what makes a reference resolve after a restart while the server is
/// offline.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceStore {
    schema: u32,
    #[serde(default)]
    servers: BTreeMap<String, ResourceCatalog>,
    #[serde(skip)]
    path: Option<PathBuf>,
}

impl Default for ResourceStore {
    fn default() -> Self {
        Self {
            schema: RESOURCE_STORE_SCHEMA_VERSION,
            servers: BTreeMap::new(),
            path: None,
        }
    }
}

impl ResourceStore {
    /// An in-memory store with no backing file.
    pub fn new() -> Self {
        Self::default()
    }

    /// Open (or create) a store backed by `path`.
    ///
    /// A missing file is an empty store. A malformed document is
    /// [`ErrorCode::Corrupt`]; a different schema is
    /// [`ErrorCode::SchemaVersion`]. Stored catalogues are revalidated, and a
    /// duplicate or mismatched catalogue is [`ErrorCode::Corrupt`] because the
    /// problem is in the file, not in a live server's result.
    pub fn open(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        match std::fs::read(&path) {
            Ok(bytes) => {
                let mut store: Self = serde_json::from_slice(&bytes).map_err(|error| {
                    ZeroError::new(
                        ErrorCode::Corrupt,
                        format!(
                            "MCP resource store `{}` is corrupt: {error}",
                            path.display()
                        ),
                    )
                })?;
                if store.schema != RESOURCE_STORE_SCHEMA_VERSION {
                    return Err(ZeroError::new(
                        ErrorCode::SchemaVersion,
                        format!(
                            "MCP resource store `{}` has schema {}; this build reads schema {}",
                            path.display(),
                            store.schema,
                            RESOURCE_STORE_SCHEMA_VERSION
                        ),
                    ));
                }
                store.validate_stored(&path)?;
                store.path = Some(path);
                Ok(store)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(Self {
                path: Some(path),
                ..Self::default()
            }),
            Err(error) => Err(error.into()),
        }
    }

    /// The backing file path, when one is set.
    pub fn path(&self) -> Option<&Path> {
        self.path.as_deref()
    }

    fn validate_stored(&self, path: &Path) -> Result<()> {
        for (key, catalog) in &self.servers {
            if key != &catalog.server {
                return Err(ZeroError::new(
                    ErrorCode::Corrupt,
                    format!(
                        "MCP resource store `{}` maps server `{key}` to catalog `{}`",
                        path.display(),
                        catalog.server
                    ),
                ));
            }
            catalog.validate().map_err(|error| {
                ZeroError::new(
                    ErrorCode::Corrupt,
                    format!(
                        "MCP resource store `{}` server `{key}`: {}",
                        path.display(),
                        error.message()
                    ),
                )
            })?;
        }
        Ok(())
    }

    /// Atomically write the store to its backing path.
    pub fn save(&self) -> Result<()> {
        let path = self
            .path
            .as_deref()
            .ok_or_else(|| invalid("MCP resource store has no file path"))?;
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent)?;
        }
        let bytes = serde_json::to_vec_pretty(self)?;
        let temporary = path.with_extension("tmp");
        std::fs::write(&temporary, bytes)?;
        std::fs::rename(&temporary, path)?;
        Ok(())
    }

    /// Insert or replace one server's catalogue.
    pub fn insert(&mut self, catalog: ResourceCatalog) -> Result<Option<ResourceCatalog>> {
        catalog.validate()?;
        Ok(self.servers.insert(catalog.server.clone(), catalog))
    }

    /// Remove one server's catalogue.
    pub fn remove(&mut self, server: &str) -> Option<ResourceCatalog> {
        self.servers.remove(server)
    }

    /// One server's catalogue.
    pub fn catalog(&self, server: &str) -> Option<&ResourceCatalog> {
        self.servers.get(server)
    }

    /// Every catalogue, ordered by server name.
    pub fn catalogs(&self) -> &BTreeMap<String, ResourceCatalog> {
        &self.servers
    }

    /// Number of stored server catalogues.
    pub fn len(&self) -> usize {
        self.servers.len()
    }

    /// Whether the store holds no catalogues.
    pub fn is_empty(&self) -> bool {
        self.servers.is_empty()
    }

    /// Resolve an `@` reference against every stored catalogue.
    ///
    /// With no server qualifier, a stronger match on another server still
    /// wins (exact URI before name, and so on). Two equally strong matches are
    /// an error that lists the qualified candidates; nothing is picked
    /// silently.
    pub fn resolve(&self, reference: &str) -> Result<Resolved<'_>> {
        let reference = ResourceRef::parse(reference)?;
        self.resolve_ref(&reference)
    }

    /// Resolve an already parsed reference.
    pub fn resolve_ref(&self, reference: &ResourceRef) -> Result<Resolved<'_>> {
        let mut found = Vec::new();
        if let Some(server) = &reference.server {
            let catalog = self
                .servers
                .get(server)
                .ok_or_else(|| not_found(reference))?;
            for candidate in catalog.candidates(&reference.target) {
                found.push((
                    Some(catalog.server.as_str()),
                    candidate.strength,
                    candidate.resolved,
                ));
            }
        } else {
            for catalog in self.servers.values() {
                for candidate in catalog.candidates(&reference.target) {
                    found.push((
                        Some(catalog.server.as_str()),
                        candidate.strength,
                        candidate.resolved,
                    ));
                }
            }
        }
        pick(reference, found, true)
    }
}

impl CompletionSource for ResourceStore {
    fn completion_names(&self, kind: CompletionKind) -> Vec<String> {
        match kind {
            CompletionKind::Resource => self
                .servers
                .values()
                .flat_map(|catalog| {
                    catalog
                        .resources
                        .iter()
                        .map(|resource| resource.name.clone())
                })
                .collect(),
            CompletionKind::Prompt => Vec::new(),
        }
    }
}

// ---------------------------------------------------------------------------
// Prompts and slash commands
// ---------------------------------------------------------------------------

/// One declared prompt argument.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptArgument {
    /// Argument name.
    pub name: String,
    /// Whether the caller must provide it.
    #[serde(default)]
    pub required: bool,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
}

/// One prompt advertised by `prompts/list`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Prompt {
    /// Prompt name used by `/name` and `prompts/get`.
    pub name: String,
    /// Optional display title.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    /// Optional description.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Declared arguments in server order.
    #[serde(default)]
    pub arguments: Vec<PromptArgument>,
}

impl Prompt {
    /// Parse one entry of a `prompts/list` result.
    pub fn from_value(value: &Value, context: &str) -> Result<Self> {
        let object = as_object(value, context)?;
        let name = string_field(object, "name", context)?;
        if let Some(problem) = token_problem(&name, &format!("{context} `name`")) {
            return Err(protocol_error(problem));
        }
        let mut arguments = Vec::new();
        let mut seen = BTreeSet::new();
        match object.get("arguments") {
            None | Some(Value::Null) => {}
            Some(Value::Array(items)) => {
                for (index, item) in items.iter().enumerate() {
                    let argument_context = format!("{context} argument[{index}]");
                    let argument_object = as_object(item, &argument_context)?;
                    let argument_name = string_field(argument_object, "name", &argument_context)?;
                    if let Some(problem) =
                        token_problem(&argument_name, &format!("{argument_context} `name`"))
                    {
                        return Err(protocol_error(problem));
                    }
                    if !seen.insert(argument_name.clone()) {
                        return Err(protocol_error(format!(
                            "{context} declares duplicate argument `{argument_name}`"
                        )));
                    }
                    let required = match argument_object.get("required") {
                        None | Some(Value::Null) => false,
                        Some(Value::Bool(required)) => *required,
                        Some(other) => {
                            return Err(protocol_error(format!(
                                "{argument_context} `required` must be a boolean, got {other}"
                            )))
                        }
                    };
                    arguments.push(PromptArgument {
                        name: argument_name,
                        required,
                        description: optional_string(
                            argument_object,
                            "description",
                            &argument_context,
                        )?,
                    });
                }
            }
            Some(other) => {
                return Err(protocol_error(format!(
                    "{context} `arguments` must be an array, got {other}"
                )))
            }
        }
        Ok(Self {
            name,
            title: optional_string(object, "title", context)?,
            description: optional_string(object, "description", context)?,
            arguments,
        })
    }

    /// Names of the arguments this prompt requires.
    pub fn required_arguments(&self) -> Vec<&str> {
        self.arguments
            .iter()
            .filter(|argument| argument.required)
            .map(|argument| argument.name.as_str())
            .collect()
    }

    /// Required arguments missing from `command`, in declaration order.
    ///
    /// Positional tokens fill declared arguments in order; named tokens fill
    /// by name. Extra positional tokens are ignored here because
    /// [`Self::bind`] reports them as an error.
    pub fn missing_required(&self, command: &SlashCommand) -> Vec<String> {
        let mut supplied: BTreeSet<&str> = command.named.keys().map(String::as_str).collect();
        for argument in self
            .arguments
            .iter()
            .take(command.positional.len().min(self.arguments.len()))
        {
            supplied.insert(argument.name.as_str());
        }
        self.arguments
            .iter()
            .filter(|argument| argument.required && !supplied.contains(argument.name.as_str()))
            .map(|argument| argument.name.clone())
            .collect()
    }

    /// Bind a slash command to this prompt's declared arguments.
    ///
    /// Positional tokens fill arguments in declaration order. Named tokens
    /// must name a declared argument and must not duplicate a positional one.
    /// Too many positional tokens, an unknown name, a duplicate, or a missing
    /// required argument is [`ErrorCode::InvalidInput`].
    pub fn bind(&self, command: &SlashCommand) -> Result<BTreeMap<String, String>> {
        if command.name != self.name {
            return Err(invalid(format!(
                "prompt `{}` cannot bind command `/{}`",
                self.name, command.name
            )));
        }
        if command.positional.len() > self.arguments.len() {
            return Err(invalid(format!(
                "prompt `{}` accepts {} argument(s), got {} positional",
                self.name,
                self.arguments.len(),
                command.positional.len()
            )));
        }
        let mut bound = BTreeMap::new();
        for (index, value) in command.positional.iter().enumerate() {
            let argument = &self.arguments[index];
            bound.insert(argument.name.clone(), value.clone());
        }
        for (key, value) in &command.named {
            if !self.arguments.iter().any(|argument| &argument.name == key) {
                return Err(invalid(format!(
                    "prompt `{}` has no argument `{key}`",
                    self.name
                )));
            }
            if bound.insert(key.clone(), value.clone()).is_some() {
                return Err(invalid(format!(
                    "prompt `{}` argument `{key}` is given twice",
                    self.name
                )));
            }
        }
        let missing: Vec<&str> = self
            .arguments
            .iter()
            .filter(|argument| argument.required && !bound.contains_key(&argument.name))
            .map(|argument| argument.name.as_str())
            .collect();
        if !missing.is_empty() {
            return Err(invalid(format!(
                "prompt `{}` is missing required argument(s): {}",
                self.name,
                missing.join(", ")
            )));
        }
        Ok(bound)
    }
}

/// A validated `prompts/list` catalogue for one server.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptCatalog {
    /// Configured server name.
    pub server: String,
    /// Prompts in server order.
    #[serde(default)]
    pub prompts: Vec<Prompt>,
}

impl PromptCatalog {
    /// An empty catalogue for `server`.
    pub fn new(server: impl Into<String>) -> Self {
        Self {
            server: server.into(),
            prompts: Vec::new(),
        }
    }

    /// Parse a `prompts/list` result. Duplicate prompt names are rejected.
    pub fn parse(server: impl Into<String>, value: &Value) -> Result<Self> {
        let object = as_object(value, "`prompts/list` result")?;
        let items = match object.get("prompts") {
            Some(Value::Array(items)) => items,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`prompts/list` result `prompts` must be an array, got {other}"
                )))
            }
            None => return Err(protocol_error("`prompts/list` result is missing `prompts`")),
        };
        let mut catalog = Self::new(server);
        let mut seen = BTreeSet::new();
        for (index, item) in items.iter().enumerate() {
            let prompt = Prompt::from_value(item, &format!("`prompts/list` prompt[{index}]"))?;
            if !seen.insert(prompt.name.clone()) {
                return Err(protocol_error(format!(
                    "`prompts/list` for server `{}` advertises duplicate prompt name `{}`",
                    catalog.server, prompt.name
                )));
            }
            catalog.prompts.push(prompt);
        }
        Ok(catalog)
    }

    /// The prompt with an exact name.
    pub fn prompt(&self, name: &str) -> Option<&Prompt> {
        self.prompts.iter().find(|prompt| prompt.name == name)
    }

    /// Require a prompt, returning [`ErrorCode::NotFound`] for an unknown
    /// slash command.
    pub fn require(&self, name: &str) -> Result<&Prompt> {
        self.prompt(name).ok_or_else(|| {
            ZeroError::new(
                ErrorCode::NotFound,
                format!("no MCP prompt named `{name}` on server `{}`", self.server),
            )
        })
    }

    /// Validate a slash command against the catalogue.
    ///
    /// An unknown command is [`ErrorCode::NotFound`]. A bad argument binding,
    /// including missing required arguments, is [`ErrorCode::InvalidInput`].
    pub fn validate_command(&self, command: &SlashCommand) -> Result<&Prompt> {
        let prompt = self.require(&command.name)?;
        prompt.bind(command)?;
        Ok(prompt)
    }
}

impl CompletionSource for PromptCatalog {
    fn completion_names(&self, kind: CompletionKind) -> Vec<String> {
        match kind {
            CompletionKind::Prompt => self
                .prompts
                .iter()
                .map(|prompt| prompt.name.clone())
                .collect(),
            CompletionKind::Resource => Vec::new(),
        }
    }
}

impl CompletionSource for ResourceCatalog {
    fn completion_names(&self, kind: CompletionKind) -> Vec<String> {
        match kind {
            CompletionKind::Resource => self
                .resources
                .iter()
                .map(|resource| resource.name.clone())
                .collect(),
            CompletionKind::Prompt => Vec::new(),
        }
    }
}

/// A parsed slash command.
///
/// Grammar: `/name` followed by whitespace-separated tokens. A token with `=`
/// becomes a named argument (`key=value`, split at the first `=`); every other
/// token is positional. There is no quoting or escaping, so an argument value
/// cannot contain whitespace.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlashCommand {
    /// Prompt name after `/`.
    pub name: String,
    /// Positional tokens in order.
    pub positional: Vec<String>,
    /// Named tokens, sorted by key.
    pub named: BTreeMap<String, String>,
}

impl SlashCommand {
    /// Parse `/name arg1 arg2 key=value`.
    pub fn parse(input: &str) -> Result<Self> {
        let trimmed = input.trim();
        let remainder = trimmed
            .strip_prefix('/')
            .ok_or_else(|| invalid("slash command must start with `/`"))?;
        let mut tokens = remainder.split_whitespace();
        let name = tokens
            .next()
            .ok_or_else(|| invalid("slash command must name a prompt, as in `/review`"))?;
        if name.contains('=') {
            return Err(invalid("slash command name must not contain `=`"));
        }
        let mut positional = Vec::new();
        let mut named = BTreeMap::new();
        for token in tokens {
            match token.split_once('=') {
                Some((key, value)) => {
                    if key.is_empty() {
                        return Err(invalid(
                            "slash command named argument must have a non-empty key",
                        ));
                    }
                    if named.insert(key.to_string(), value.to_string()).is_some() {
                        return Err(invalid(format!(
                            "slash command repeats named argument `{key}`"
                        )));
                    }
                }
                None => positional.push(token.to_string()),
            }
        }
        Ok(Self {
            name: name.to_string(),
            positional,
            named,
        })
    }
}

/// Parse a slash command; free-function form of [`SlashCommand::parse`].
pub fn parse_slash(input: &str) -> Result<SlashCommand> {
    SlashCommand::parse(input)
}

// ---------------------------------------------------------------------------
// Completions
// ---------------------------------------------------------------------------

/// Which namespace a completion belongs to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CompletionKind {
    /// Resource names, used after `@`.
    Resource,
    /// Prompt names, used after `/`.
    Prompt,
}

/// A source of completion names.
///
/// Implemented for [`ResourceCatalog`], [`PromptCatalog`], and
/// [`ResourceStore`]. [`complete`] handles filtering, ordering, deduplication,
/// and the bound.
pub trait CompletionSource {
    /// Every candidate name in `kind`; order is irrelevant because
    /// [`complete`] sorts.
    fn completion_names(&self, kind: CompletionKind) -> Vec<String>;
}

impl<T: CompletionSource + ?Sized> CompletionSource for &T {
    fn completion_names(&self, kind: CompletionKind) -> Vec<String> {
        (**self).completion_names(kind)
    }
}

/// Bounded local completions for a prefix.
///
/// Matching is case-insensitive on the prefix; the original spelling is
/// returned. Results are sorted, deduplicated, and truncated to
/// [`MAX_COMPLETIONS`]. An empty prefix returns the first sorted names.
pub fn complete<S: CompletionSource + ?Sized>(
    prefix: &str,
    catalog: &S,
    kind: CompletionKind,
) -> Vec<String> {
    let folded = prefix.to_lowercase();
    let mut names: Vec<String> = catalog
        .completion_names(kind)
        .into_iter()
        .filter(|name| name.to_lowercase().starts_with(&folded))
        .collect();
    names.sort();
    names.dedup();
    names.truncate(MAX_COMPLETIONS);
    names
}

/// The `ref` of a `completion/complete` request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompletionTarget {
    /// Complete an argument of a prompt.
    Prompt {
        /// Prompt name.
        name: String,
    },
    /// Complete an argument of a resource template.
    Resource {
        /// Resource URI or template.
        uri: String,
    },
}

impl CompletionTarget {
    fn to_value(&self) -> Value {
        match self {
            CompletionTarget::Prompt { name } => {
                json!({"type": "ref/prompt", "name": name})
            }
            CompletionTarget::Resource { uri } => {
                json!({"type": "ref/resource", "uri": uri})
            }
        }
    }

    fn from_value(value: &Value) -> Result<Self> {
        let object = as_object(value, "`completion/complete` ref")?;
        let kind = string_field(object, "type", "`completion/complete` ref")?;
        match kind.as_str() {
            "ref/prompt" => {
                let name = string_field(object, "name", "`completion/complete` ref")?;
                if let Some(problem) = token_problem(&name, "`completion/complete` ref `name`") {
                    return Err(protocol_error(problem));
                }
                Ok(CompletionTarget::Prompt { name })
            }
            "ref/resource" => {
                let uri = string_field(object, "uri", "`completion/complete` ref")?;
                if let Some(problem) = token_problem(&uri, "`completion/complete` ref `uri`") {
                    return Err(protocol_error(problem));
                }
                Ok(CompletionTarget::Resource { uri })
            }
            other => Err(protocol_error(format!(
                "unsupported `completion/complete` ref type `{other}`"
            ))),
        }
    }
}

/// The argument being completed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionArgument {
    /// Argument name.
    pub name: String,
    /// Text already typed.
    pub value: String,
}

/// An optional server-side `completion/complete` request (MCP-16).
///
/// The local [`complete`] helper does not use this model. It is provided so a
/// caller with an injected transport can ask a server for completions without
/// waiting for the `Client` wiring, which is deferred.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionRequest {
    /// Prompt or resource being completed.
    pub target: CompletionTarget,
    /// Argument name and current text.
    pub argument: CompletionArgument,
    /// Additional argument values keyed by name; empty is omitted on the wire.
    pub context: Option<BTreeMap<String, String>>,
}

impl CompletionRequest {
    /// A request with no extra context.
    pub fn new(target: CompletionTarget, argument: CompletionArgument) -> Self {
        Self {
            target,
            argument,
            context: None,
        }
    }

    /// Add one context argument.
    pub fn with_context_argument(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Self {
        self.context
            .get_or_insert_with(BTreeMap::new)
            .insert(name.into(), value.into());
        self
    }

    /// Build the `completion/complete` params object.
    pub fn to_params(&self) -> Value {
        let mut params = Map::new();
        params.insert("ref".to_string(), self.target.to_value());
        params.insert(
            "argument".to_string(),
            json!({"name": self.argument.name, "value": self.argument.value}),
        );
        if let Some(context) = self.context.as_ref().filter(|context| !context.is_empty()) {
            params.insert("context".to_string(), json!({"arguments": context}));
        }
        Value::Object(params)
    }

    /// Parse a `completion/complete` params object.
    pub fn from_params(value: &Value) -> Result<Self> {
        let object = as_object(value, "`completion/complete` params")?;
        let target =
            CompletionTarget::from_value(object.get("ref").ok_or_else(|| {
                protocol_error("`completion/complete` params are missing `ref`")
            })?)?;
        let argument_object = object
            .get("argument")
            .ok_or_else(|| protocol_error("`completion/complete` params are missing `argument`"))
            .and_then(|value| as_object(value, "`completion/complete` argument"))?;
        let name = string_field(argument_object, "name", "`completion/complete` argument")?;
        if let Some(problem) = token_problem(&name, "`completion/complete` argument `name`") {
            return Err(protocol_error(problem));
        }
        let value = string_field(argument_object, "value", "`completion/complete` argument")?;
        let context = match object.get("context") {
            None | Some(Value::Null) => None,
            Some(Value::Object(context)) => match context.get("arguments") {
                None | Some(Value::Null) => None,
                Some(Value::Object(arguments)) => {
                    let mut map = BTreeMap::new();
                    for (key, value) in arguments {
                        let Value::String(value) = value else {
                            return Err(protocol_error(format!(
                                "`completion/complete` context argument `{key}` must be a string"
                            )));
                        };
                        map.insert(key.clone(), value.clone());
                    }
                    if map.is_empty() {
                        None
                    } else {
                        Some(map)
                    }
                }
                Some(other) => {
                    return Err(protocol_error(format!(
                        "`completion/complete` context `arguments` must be an object, got {other}"
                    )))
                }
            },
            Some(other) => {
                return Err(protocol_error(format!(
                    "`completion/complete` `context` must be an object, got {other}"
                )))
            }
        };
        Ok(Self {
            target,
            argument: CompletionArgument { name, value },
            context,
        })
    }
}

/// A bounded `completion/complete` response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompletionResponse {
    /// Completion values, truncated to [`MAX_COMPLETIONS`].
    pub values: Vec<String>,
    /// Server-reported total, when present.
    pub total: Option<u64>,
    /// Whether the server reported more values than it returned.
    pub has_more: bool,
}

impl CompletionResponse {
    /// Parse a `completion/complete` result.
    pub fn from_value(value: &Value) -> Result<Self> {
        let object = as_object(value, "`completion/complete` result")?;
        let completion = match object.get("completion") {
            Some(Value::Object(completion)) => completion,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`completion/complete` result `completion` must be an object, got {other}"
                )))
            }
            None => {
                return Err(protocol_error(
                    "`completion/complete` result is missing `completion`",
                ))
            }
        };
        let mut values = match completion.get("values") {
            Some(Value::Array(items)) => {
                let mut values = Vec::with_capacity(items.len());
                for item in items {
                    let Value::String(item) = item else {
                        return Err(protocol_error(
                            "`completion/complete` completion values must be strings",
                        ));
                    };
                    values.push(item.clone());
                }
                values
            }
            Some(other) => {
                return Err(protocol_error(format!(
                    "`completion/complete` completion `values` must be an array, got {other}"
                )))
            }
            None => {
                return Err(protocol_error(
                    "`completion/complete` completion is missing `values`",
                ))
            }
        };
        let total =
            match completion.get("total") {
                None | Some(Value::Null) => None,
                Some(Value::Number(number)) => match number.as_u64() {
                    Some(total) => Some(total),
                    None => return Err(protocol_error(
                        "`completion/complete` completion `total` must be a non-negative integer",
                    )),
                },
                Some(other) => {
                    return Err(protocol_error(format!(
                        "`completion/complete` completion `total` must be a number, got {other}"
                    )))
                }
            };
        let has_more = match completion.get("hasMore") {
            None | Some(Value::Null) => false,
            Some(Value::Bool(has_more)) => *has_more,
            Some(other) => {
                return Err(protocol_error(format!(
                    "`completion/complete` completion `hasMore` must be a boolean, got {other}"
                )))
            }
        };
        values.truncate(MAX_COMPLETIONS);
        Ok(Self {
            values,
            total,
            has_more,
        })
    }
}

/// Transport seam for the optional server-side `completion/complete` call.
///
/// Implementations take a complete JSON-RPC request value and return a
/// complete response value, exactly like [`crate::client::Transport`]. One
/// request is sent per call; there is no session or retry.
pub trait CompletionTransport {
    /// Exchange one JSON-RPC request for its response.
    fn exchange(&self, request: &Value) -> Result<Value>;
}

impl<T: CompletionTransport + ?Sized> CompletionTransport for &T {
    fn exchange(&self, request: &Value) -> Result<Value> {
        (**self).exchange(request)
    }
}

impl<T: CompletionTransport + ?Sized> CompletionTransport for Box<T> {
    fn exchange(&self, request: &Value) -> Result<Value> {
        (**self).exchange(request)
    }
}

/// Send one server-side `completion/complete` request through `transport`.
///
/// The request id is always `1` because this is a single stateless exchange.
/// A JSON-RPC error is mapped by [`expect_result`]; a malformed result is
/// [`ErrorCode::ProviderProtocol`]. Neither the values nor the arguments are
/// included in error messages.
pub fn request_completion<T: CompletionTransport>(
    transport: &T,
    request: &CompletionRequest,
) -> Result<CompletionResponse> {
    let id = RequestId::Number(1);
    let envelope = Request::new(
        id.clone(),
        METHOD_COMPLETION_COMPLETE,
        Some(request.to_params()),
    );
    let wire = serde_json::to_value(envelope)?;
    let response = transport.exchange(&wire)?;
    let result = expect_result(response, &id)?;
    CompletionResponse::from_value(&result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zero_types::error::ErrorCode;

    fn resource_catalog() -> ResourceCatalog {
        ResourceCatalog::from_lists(
            "files",
            &json!({
                "resources": [
                    {
                        "uri": "file:///notes.md",
                        "name": "notes",
                        "title": "Notes",
                        "description": "The project notes",
                        "mimeType": "text/markdown"
                    },
                    {"uri": "file:///readme.md", "name": "readme"}
                ],
                "nextCursor": "ignored"
            }),
            &json!({
                "templates": [
                    {
                        "uriTemplate": "file:///{path}",
                        "name": "any-file",
                        "description": "Any file"
                    }
                ]
            }),
        )
        .expect("the sample catalogue is valid")
    }

    fn prompt_catalog() -> PromptCatalog {
        PromptCatalog::parse(
            "prompts",
            &json!({
                "prompts": [
                    {
                        "name": "review",
                        "title": "Review",
                        "description": "Review a path",
                        "arguments": [
                            {"name": "path", "required": true, "description": "File to review"},
                            {"name": "depth", "required": false}
                        ]
                    },
                    {"name": "summarize"}
                ]
            }),
        )
        .expect("the sample prompt catalogue is valid")
    }

    #[test]
    fn reference_forms_parse() {
        let plain = parse_reference("@notes").unwrap();
        assert_eq!(plain.server, None);
        assert_eq!(plain.target, "notes");

        let qualified = parse_reference("@files:notes").unwrap();
        assert_eq!(qualified.server.as_deref(), Some("files"));
        assert_eq!(qualified.target, "notes");

        let uri = parse_reference("@ui://app/view").unwrap();
        assert_eq!(uri.server, None);
        assert_eq!(uri.target, "ui://app/view");
        assert_eq!(uri.as_reference(), "@ui://app/view");

        for bad in [
            "",
            "notes",
            "@",
            "@/notes",
            "@files:",
            "@files:two words",
            "@notes\n",
        ] {
            assert!(
                parse_reference(bad).is_err(),
                "`{bad}` must not parse as a reference"
            );
        }
    }

    #[test]
    fn reference_display_round_trips() {
        for input in ["@notes", "@files:notes", "@file:///notes.md"] {
            let reference = parse_reference(input).unwrap();
            assert_eq!(reference.to_string(), input);
            assert_eq!(parse_reference(&reference.to_string()).unwrap(), reference);
        }
    }

    #[test]
    fn catalog_parses_resources_and_templates() {
        let catalog = resource_catalog();
        assert_eq!(catalog.server, "files");
        assert_eq!(catalog.resources.len(), 2);
        assert_eq!(
            catalog.resources[0].mime_type.as_deref(),
            Some("text/markdown")
        );
        assert_eq!(catalog.resources[0].title.as_deref(), Some("Notes"));
        assert_eq!(catalog.templates.len(), 1);
        assert_eq!(catalog.templates[0].uri_template, "file:///{path}");
        assert_eq!(catalog.resource("notes").unwrap().uri, "file:///notes.md");
        assert!(catalog.resource("missing").is_none());
        assert!(catalog.template("any-file").is_some());
    }

    #[test]
    fn catalog_rejects_duplicate_names() {
        let error = ResourceCatalog::from_resources_list(
            "files",
            &json!({"resources": [
                {"uri": "mem://a", "name": "same"},
                {"uri": "mem://b", "name": "same"}
            ]}),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains("duplicate resource name"));
    }

    #[test]
    fn catalog_rejects_duplicate_uris() {
        let error = ResourceCatalog::from_resources_list(
            "files",
            &json!({"resources": [
                {"uri": "mem://same", "name": "a"},
                {"uri": "mem://same", "name": "b"}
            ]}),
        )
        .unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains("duplicate resource URI"));
    }

    #[test]
    fn catalog_rejects_duplicate_templates() {
        let duplicate_uri = ResourceCatalog::from_templates_list(
            "files",
            &json!({"templates": [
                {"uriTemplate": "file:///{path}", "name": "a"},
                {"uriTemplate": "file:///{path}", "name": "b"}
            ]}),
        )
        .unwrap_err();
        assert_eq!(duplicate_uri.code(), ErrorCode::ProviderProtocol);

        let duplicate_name = ResourceCatalog::from_templates_list(
            "files",
            &json!({"templates": [
                {"uriTemplate": "file:///{path}", "name": "same"},
                {"uriTemplate": "mem:///{path}", "name": "same"}
            ]}),
        )
        .unwrap_err();
        assert_eq!(duplicate_name.code(), ErrorCode::ProviderProtocol);
    }

    #[test]
    fn catalog_rejects_malformed_shapes() {
        let cases = [
            json!({}),
            json!({"resources": "nope"}),
            json!({"resources": [{"name": "no-uri"}]}),
            json!({"resources": [{"uri": "mem://a", "name": ""}]}),
            json!({"resources": [{"uri": "mem://a", "name": "a", "title": 7}]}),
            json!({"resources": [7]}),
        ];
        for value in cases {
            assert!(
                ResourceCatalog::from_resources_list("files", &value).is_err(),
                "`{value}` must be rejected"
            );
        }

        assert!(ResourceCatalog::from_templates_list("files", &json!({})).is_err());
        assert!(ResourceCatalog::from_templates_list(
            "files",
            &json!({"templates": [{"name": "no-template"}]})
        )
        .is_err());
    }

    #[test]
    fn resolve_prefers_exact_uri_then_exact_name() {
        let catalog = ResourceCatalog::from_resources_list(
            "files",
            &json!({"resources": [
                {"uri": "untitled", "name": "other"},
                {"uri": "mem://a", "name": "untitled"}
            ]}),
        )
        .unwrap();

        let by_uri = catalog
            .resolve(&parse_reference("@untitled").unwrap())
            .unwrap();
        assert_eq!(by_uri.uri(), "untitled");
        assert_eq!(
            by_uri,
            Resolved::Resource(catalog.resource("other").unwrap())
        );
    }

    #[test]
    fn resolve_case_insensitive_without_silent_pick() {
        let catalog = ResourceCatalog::from_resources_list(
            "files",
            &json!({"resources": [
                {"uri": "mem://a", "name": "Notes"},
                {"uri": "mem://b", "name": "notes"}
            ]}),
        )
        .unwrap();

        let error = catalog
            .resolve(&parse_reference("@NOTES").unwrap())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("ambiguous"));
        assert!(error.message().contains("mem://a"));
        assert!(error.message().contains("mem://b"));

        let unique = ResourceCatalog::from_resources_list(
            "files",
            &json!({"resources": [{"uri": "mem://a", "name": "Notes"}]}),
        )
        .unwrap();
        let resolved = unique.resolve(&parse_reference("@NOTES").unwrap()).unwrap();
        assert_eq!(resolved.name(), "Notes");
    }

    #[test]
    fn resolve_template_and_template_ambiguity() {
        let catalog = ResourceCatalog::from_lists(
            "files",
            &json!({"resources": []}),
            &json!({"templates": [
                {"uriTemplate": "file:///{path}", "name": "file"},
                {"uriTemplate": "file:///{dir}/{file}", "name": "nested"}
            ]}),
        )
        .unwrap();

        let error = catalog
            .resolve(&parse_reference("@file:///dir/notes.md").unwrap())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("ambiguous"));

        let single = ResourceCatalog::from_lists(
            "files",
            &json!({"resources": []}),
            &json!({"templates": [{"uriTemplate": "mem://notes/{id}", "name": "note"}]}),
        )
        .unwrap();
        let resolved = single
            .resolve(&parse_reference("@mem://notes/42").unwrap())
            .unwrap();
        assert_eq!(resolved.name(), "note");
        assert_eq!(resolved.uri(), "mem://notes/{id}");

        // Operator expressions are retained but never match.
        let unsupported = ResourceCatalog::from_lists(
            "files",
            &json!({"resources": []}),
            &json!({"templates": [{"uriTemplate": "mem://{+path}", "name": "raw"}]}),
        )
        .unwrap();
        assert_eq!(
            unsupported
                .resolve(&parse_reference("@mem://notes/42").unwrap())
                .unwrap_err()
                .code(),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn resolve_unknown_is_not_found() {
        let catalog = resource_catalog();
        let error = catalog
            .resolve(&parse_reference("@missing").unwrap())
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert_eq!(
            LookupFailure::from_error(&error),
            Some(LookupFailure::NotFound)
        );

        let other_server = catalog
            .resolve(&parse_reference("@other:notes").unwrap())
            .unwrap_err();
        assert_eq!(other_server.code(), ErrorCode::NotFound);
    }

    #[test]
    fn store_resolves_across_servers_and_reports_ambiguity() {
        let mut store = ResourceStore::new();
        store.insert(resource_catalog()).unwrap();
        store
            .insert(
                ResourceCatalog::from_resources_list(
                    "remote",
                    &json!({"resources": [{"uri": "mem://notes", "name": "notes"}]}),
                )
                .unwrap(),
            )
            .unwrap();

        let error = store.resolve("@notes").unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert_eq!(
            LookupFailure::from_error(&error),
            Some(LookupFailure::Ambiguous)
        );
        assert!(error.message().contains("files:notes"));
        assert!(error.message().contains("remote:notes"));

        assert_eq!(store.resolve("@files:notes").unwrap().name(), "notes");
        assert_eq!(store.resolve("@remote:notes").unwrap().name(), "notes");
        assert_eq!(
            store.resolve("@missing:notes").unwrap_err().code(),
            ErrorCode::NotFound
        );
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
        assert!(store.catalog("files").is_some());
        assert!(store.remove("remote").is_some());
        assert_eq!(store.len(), 1);
    }

    #[test]
    fn store_persists_and_resolves_after_restart() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("mcp-resources.json");
        {
            let mut store = ResourceStore::open(&path).unwrap();
            assert!(store.is_empty());
            store.insert(resource_catalog()).unwrap();
            store
                .insert(
                    ResourceCatalog::from_resources_list(
                        "remote",
                        &json!({"resources": [{"uri": "mem://Notes", "name": "Notes"}]}),
                    )
                    .unwrap(),
                )
                .unwrap();
            store.save().unwrap();
        }
        // The store is dropped; nothing keeps a server connection alive.
        let reopened = ResourceStore::open(&path).unwrap();
        let resolved = reopened.resolve("@notes").unwrap();
        assert_eq!(resolved.name(), "notes");
        assert_eq!(resolved.uri(), "file:///notes.md");
        assert_eq!(
            reopened.resolve("@file:///notes.md").unwrap().name(),
            "notes"
        );
        assert_eq!(
            reopened.resolve("@missing").unwrap_err().code(),
            ErrorCode::NotFound
        );
        let ambiguous = reopened.resolve("@NOTES").unwrap_err();
        assert_eq!(ambiguous.code(), ErrorCode::InvalidInput);
        assert_eq!(
            LookupFailure::from_error(&ambiguous),
            Some(LookupFailure::Ambiguous)
        );
        assert!(ambiguous.message().contains("files:notes"));
        assert!(ambiguous.message().contains("remote:Notes"));
        assert!(path.exists());
    }

    #[test]
    fn store_rejects_corrupt_and_unsupported_documents() {
        let directory = tempfile::tempdir().unwrap();

        let corrupt = directory.path().join("corrupt.json");
        std::fs::write(&corrupt, "{not json").unwrap();
        assert_eq!(
            ResourceStore::open(&corrupt).unwrap_err().code(),
            ErrorCode::Corrupt
        );

        let unsupported = directory.path().join("unsupported.json");
        std::fs::write(&unsupported, r#"{"schema": 99, "servers": {}}"#).unwrap();
        assert_eq!(
            ResourceStore::open(&unsupported).unwrap_err().code(),
            ErrorCode::SchemaVersion
        );

        let missing_schema = directory.path().join("missing-schema.json");
        std::fs::write(&missing_schema, r#"{"servers": {}}"#).unwrap();
        assert_eq!(
            ResourceStore::open(&missing_schema).unwrap_err().code(),
            ErrorCode::Corrupt
        );
    }

    #[test]
    fn store_rejects_duplicate_and_mismatched_catalogues_on_load() {
        let directory = tempfile::tempdir().unwrap();

        let duplicates = directory.path().join("duplicates.json");
        std::fs::write(
            &duplicates,
            r#"{
                "schema": 1,
                "servers": {
                    "files": {
                        "server": "files",
                        "resources": [
                            {"uri": "mem://a", "name": "same"},
                            {"uri": "mem://b", "name": "same"}
                        ],
                        "templates": []
                    }
                }
            }"#,
        )
        .unwrap();
        assert_eq!(
            ResourceStore::open(&duplicates).unwrap_err().code(),
            ErrorCode::Corrupt
        );

        let mismatched = directory.path().join("mismatched.json");
        std::fs::write(
            &mismatched,
            r#"{"schema": 1, "servers": {"a": {"server": "b", "resources": [], "templates": []}}}"#,
        )
        .unwrap();
        assert_eq!(
            ResourceStore::open(&mismatched).unwrap_err().code(),
            ErrorCode::Corrupt
        );
    }

    #[test]
    fn store_save_requires_a_path() {
        let store = ResourceStore::new();
        assert_eq!(store.save().unwrap_err().code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn prompt_catalog_parses_and_rejects_duplicates() {
        let catalog = prompt_catalog();
        assert_eq!(catalog.prompts.len(), 2);
        let review = catalog.prompt("review").unwrap();
        assert_eq!(review.required_arguments(), vec!["path"]);
        assert_eq!(review.arguments[1].name, "depth");

        let duplicate_prompt = PromptCatalog::parse(
            "prompts",
            &json!({"prompts": [{"name": "a"}, {"name": "a"}]}),
        )
        .unwrap_err();
        assert_eq!(duplicate_prompt.code(), ErrorCode::ProviderProtocol);

        let duplicate_argument = PromptCatalog::parse(
            "prompts",
            &json!({"prompts": [{"name": "a", "arguments": [
                {"name": "x"}, {"name": "x"}
            ]}]}),
        )
        .unwrap_err();
        assert_eq!(duplicate_argument.code(), ErrorCode::ProviderProtocol);

        for bad in [
            json!({}),
            json!({"prompts": "nope"}),
            json!({"prompts": [{"name": "a", "arguments": [{"required": true}]}]}),
            json!({"prompts": [{"name": "a", "arguments": [{"name": "x", "required": 1}]}]}),
        ] {
            assert!(PromptCatalog::parse("prompts", &bad).is_err());
        }
    }

    #[test]
    fn slash_parses_positional_and_named() {
        let command = parse_slash("/review src/main.rs 2 key=value").unwrap();
        assert_eq!(command.name, "review");
        assert_eq!(command.positional, vec!["src/main.rs", "2"]);
        assert_eq!(command.named.get("key").map(String::as_str), Some("value"));

        let empty_value = parse_slash("/review path=").unwrap();
        assert_eq!(empty_value.named.get("path").map(String::as_str), Some(""));

        let trimmed = parse_slash("  /review  a  ").unwrap();
        assert_eq!(trimmed.positional, vec!["a"]);
    }

    #[test]
    fn slash_rejects_bad_forms() {
        for bad in [
            "",
            "/",
            "review",
            "/review a=1 a=2",
            "/review =value",
            "/review=oops",
        ] {
            assert!(parse_slash(bad).is_err(), "`{bad}` must not parse");
        }
    }

    #[test]
    fn slash_quotes_are_not_special() {
        // Documented limitation: there is no quoting or escaping.
        let command = parse_slash("/review \"two words\"").unwrap();
        assert_eq!(command.positional, vec!["\"two", "words\""]);
    }

    #[test]
    fn slash_unknown_command_is_not_found() {
        let catalog = prompt_catalog();
        let command = parse_slash("/missing").unwrap();
        let error = catalog.validate_command(&command).unwrap_err();
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert!(error.message().contains("missing"));
    }

    #[test]
    fn slash_missing_required_arguments_are_reported() {
        let catalog = prompt_catalog();
        let command = parse_slash("/review").unwrap();
        let prompt = catalog.prompt("review").unwrap();
        assert_eq!(prompt.missing_required(&command), vec!["path"]);

        let error = catalog.validate_command(&command).unwrap_err();
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("path"));
    }

    #[test]
    fn slash_binds_arguments_and_rejects_bad_bindings() {
        let catalog = prompt_catalog();
        let command = parse_slash("/review src/main.rs depth=2").unwrap();
        let prompt = catalog.validate_command(&command).unwrap();
        let bound = prompt.bind(&command).unwrap();
        assert_eq!(bound.get("path").map(String::as_str), Some("src/main.rs"));
        assert_eq!(bound.get("depth").map(String::as_str), Some("2"));

        let duplicate = parse_slash("/review src/main.rs path=other").unwrap();
        assert_eq!(
            catalog.validate_command(&duplicate).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let unknown = parse_slash("/review src/main.rs nope=1").unwrap();
        assert_eq!(
            catalog.validate_command(&unknown).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let overflow = parse_slash("/review a b c").unwrap();
        assert_eq!(
            catalog.validate_command(&overflow).unwrap_err().code(),
            ErrorCode::InvalidInput
        );

        let empty = catalog.prompt("summarize").unwrap();
        assert!(empty
            .bind(&parse_slash("/summarize").unwrap())
            .unwrap()
            .is_empty());
    }

    #[test]
    fn completions_filter_sort_dedupe_and_bound() {
        let catalog = prompt_catalog();
        assert_eq!(
            complete("RE", &catalog, CompletionKind::Prompt),
            vec!["review"]
        );
        assert!(complete("zzz", &catalog, CompletionKind::Prompt).is_empty());
        assert_eq!(
            complete("", &catalog, CompletionKind::Prompt),
            vec!["review", "summarize"]
        );

        let mut store = ResourceStore::new();
        store
            .insert(
                ResourceCatalog::from_resources_list(
                    "a",
                    &json!({"resources": [{"uri": "mem://a", "name": "notes"}]}),
                )
                .unwrap(),
            )
            .unwrap();
        store
            .insert(
                ResourceCatalog::from_resources_list(
                    "b",
                    &json!({"resources": [{"uri": "mem://b", "name": "notes"}]}),
                )
                .unwrap(),
            )
            .unwrap();
        assert_eq!(
            complete("no", &store, CompletionKind::Resource),
            vec!["notes"]
        );

        let mut many = PromptCatalog::new("many");
        for index in 0..MAX_COMPLETIONS + 5 {
            many.prompts.push(Prompt {
                name: format!("prompt-{index:03}"),
                title: None,
                description: None,
                arguments: Vec::new(),
            });
        }
        let bounded = complete("prompt-", &many, CompletionKind::Prompt);
        assert_eq!(bounded.len(), MAX_COMPLETIONS);
        assert_eq!(bounded.first().map(String::as_str), Some("prompt-000"));
    }

    #[test]
    fn completion_kinds_do_not_leak() {
        assert!(complete("", &resource_catalog(), CompletionKind::Prompt).is_empty());
        assert!(complete("", &prompt_catalog(), CompletionKind::Resource).is_empty());
        assert_eq!(
            complete("n", &resource_catalog(), CompletionKind::Resource),
            vec!["notes"]
        );
    }

    #[test]
    fn completion_request_params_round_trip() {
        let request = CompletionRequest::new(
            CompletionTarget::Prompt {
                name: "review".to_string(),
            },
            CompletionArgument {
                name: "language".to_string(),
                value: "py".to_string(),
            },
        )
        .with_context_argument("path", "src/main.rs");

        assert_eq!(
            request.to_params(),
            json!({
                "ref": {"type": "ref/prompt", "name": "review"},
                "argument": {"name": "language", "value": "py"},
                "context": {"arguments": {"path": "src/main.rs"}}
            })
        );
        assert_eq!(
            CompletionRequest::from_params(&request.to_params()).unwrap(),
            request
        );

        let empty_context = CompletionRequest::new(
            CompletionTarget::Resource {
                uri: "file:///{path}".to_string(),
            },
            CompletionArgument {
                name: "path".to_string(),
                value: "n".to_string(),
            },
        );
        assert_eq!(
            empty_context.to_params(),
            json!({
                "ref": {"type": "ref/resource", "uri": "file:///{path}"},
                "argument": {"name": "path", "value": "n"}
            })
        );

        assert!(CompletionRequest::from_params(&json!({"argument": {}})).is_err());
        assert!(CompletionRequest::from_params(&json!({
            "ref": {"type": "ref/other"},
            "argument": {"name": "a", "value": "b"}
        }))
        .is_err());
    }

    #[test]
    fn completion_response_is_bounded_and_validated() {
        let response = CompletionResponse::from_value(&json!({
            "completion": {"values": ["python", "pytest"], "total": 2, "hasMore": false}
        }))
        .unwrap();
        assert_eq!(response.values, vec!["python", "pytest"]);
        assert_eq!(response.total, Some(2));
        assert!(!response.has_more);

        let values: Vec<String> = (0..MAX_COMPLETIONS + 10)
            .map(|index| format!("value-{index}"))
            .collect();
        let bounded = CompletionResponse::from_value(&json!({
            "completion": {"values": values}
        }))
        .unwrap();
        assert_eq!(bounded.values.len(), MAX_COMPLETIONS);

        for bad in [
            json!({}),
            json!({"completion": {"values": "nope"}}),
            json!({"completion": {"values": [1]}}),
            json!({"completion": {"values": [], "total": -1}}),
            json!({"completion": {"values": [], "hasMore": "yes"}}),
        ] {
            assert!(
                CompletionResponse::from_value(&bad).is_err(),
                "`{bad}` must be rejected"
            );
        }
    }

    struct ScriptedCompletion {
        response: Value,
    }

    impl CompletionTransport for ScriptedCompletion {
        fn exchange(&self, request: &Value) -> Result<Value> {
            assert_eq!(request["method"], METHOD_COMPLETION_COMPLETE);
            assert_eq!(request["params"]["argument"]["value"], "py");
            Ok(self.response.clone())
        }
    }

    #[test]
    fn completion_transport_is_injectable() {
        let transport = ScriptedCompletion {
            response: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "result": {"completion": {"values": ["python"], "total": 1}}
            }),
        };
        let request = CompletionRequest::new(
            CompletionTarget::Prompt {
                name: "review".to_string(),
            },
            CompletionArgument {
                name: "language".to_string(),
                value: "py".to_string(),
            },
        );
        let response = request_completion(&transport, &request).unwrap();
        assert_eq!(response.values, vec!["python"]);

        let failing = ScriptedCompletion {
            response: json!({
                "jsonrpc": "2.0",
                "id": 1,
                "error": {"code": -32601, "message": "no completion"}
            }),
        };
        assert_eq!(
            request_completion(&failing, &request).unwrap_err().code(),
            ErrorCode::Unsupported
        );
    }
}
