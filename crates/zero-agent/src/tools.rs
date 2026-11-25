//! Tool catalogue: metadata, deferral, BM25 search, context activation,
//! cache-safe injection, policy filtering, hygiene, and telemetry
//! (TOOL-01..TOOL-06, TOOL-10, TOOL-12).
//!
//! The registry is the single source of tool schemas. Search and activation are
//! advisory: they rank and suggest, but never remove a tool from the catalogue.

use crate::r#loop::{Tool, ToolRegistry};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use zero_model::ToolSchema;
use zero_policy::action::Actor;
use zero_policy::eval::Policy;
use zero_policy::mode::{default_verdict, Verdict};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ToolSource {
    Native,
    Kernel,
    Mcp,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ToolMeta {
    pub name: String,
    pub description: String,
    pub schema: serde_json::Value,
    pub tags: Vec<String>,
    pub examples: Vec<String>,
    pub action_class: zero_policy::ActionClass,
    pub read_only: bool,
    pub deferrable: bool,
    pub namespace: Option<String>,
    pub source: ToolSource,
    pub version: String,
}

impl ToolMeta {
    pub fn from_tool(tool: &dyn Tool, source: ToolSource) -> Self {
        Self {
            name: tool.name().to_string(),
            description: tool.description().to_string(),
            schema: tool.parameters(),
            tags: tool.tags(),
            examples: tool.examples(),
            action_class: tool.action_class(),
            read_only: tool.read_only(),
            deferrable: tool.deferrable(),
            namespace: tool.namespace().map(str::to_string),
            source,
            version: tool.version().to_string(),
        }
    }

    pub fn to_schema(&self) -> ToolSchema {
        ToolSchema {
            name: self.name.clone(),
            description: self.description.clone(),
            parameters: self.schema.clone(),
        }
    }
}

/// Schemas for the wire: non-deferred tools always, deferred tools only when
/// activated by search or context.
pub fn wire_schemas(registry: &ToolRegistry, active: &BTreeSet<String>) -> Vec<ToolSchema> {
    registry
        .entries()
        .filter(|entry| !entry.meta.deferrable || active.contains(&entry.meta.name))
        .map(|entry| entry.meta.to_schema())
        .collect()
}

fn tokenize(text: &str) -> Vec<String> {
    text.to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .filter(|t| t.len() > 1)
        .map(str::to_string)
        .collect()
}

fn document(meta: &ToolMeta) -> String {
    format!(
        "{} {} {} {} {} {}",
        meta.name,
        meta.name,
        meta.description,
        meta.tags.join(" "),
        meta.examples.join(" "),
        meta.schema
    )
}

#[derive(Debug, Clone, PartialEq)]
pub struct SearchHit {
    pub name: String,
    pub score: f64,
    pub source: ToolSource,
}

/// BM25 over names (weighted), tags, descriptions, examples, and arguments.
pub fn search(registry: &ToolRegistry, query: &str, limit: usize) -> Vec<SearchHit> {
    let terms = tokenize(query);
    if terms.is_empty() {
        return Vec::new();
    }
    let entries: Vec<&crate::r#loop::ToolEntry> = registry.entries().collect();
    let docs: Vec<Vec<String>> = entries.iter().map(|e| tokenize(&document(&e.meta))).collect();
    let avg_len = docs.iter().map(|d| d.len() as f64).sum::<f64>() / docs.len().max(1) as f64;
    let n = docs.len() as f64;
    let k1 = 1.2;
    let b = 0.75;
    let mut hits = Vec::new();
    for (entry, doc) in entries.iter().zip(&docs) {
        let mut score = 0.0;
        for term in &terms {
            let df = docs.iter().filter(|d| d.contains(term)).count() as f64;
            if df == 0.0 {
                continue;
            }
            let idf = ((n - df + 0.5) / (df + 0.5) + 1.0).ln();
            let tf = doc.iter().filter(|t| *t == term).count() as f64;
            let denom = tf + k1 * (1.0 - b + b * doc.len() as f64 / avg_len.max(1.0));
            score += idf * (tf * (k1 + 1.0)) / denom.max(0.0001);
            if entry.meta.name.to_ascii_lowercase().contains(term) {
                score += 2.0;
            }
        }
        if score > 0.0 {
            hits.push(SearchHit { name: entry.meta.name.clone(), score, source: entry.meta.source });
        }
    }
    // Native tools win ties; higher score first.
    hits.sort_by(|a, b| {
        b.score
            .partial_cmp(&a.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| source_rank(a.source).cmp(&source_rank(b.source)))
            .then(a.name.cmp(&b.name))
    });
    hits.truncate(limit);
    hits
}

fn source_rank(source: ToolSource) -> u8 {
    match source {
        ToolSource::Native => 0,
        ToolSource::Kernel => 1,
        ToolSource::Mcp => 2,
    }
}

#[derive(Debug, Clone, Default)]
pub struct ActivationContext {
    pub files: Vec<std::path::PathBuf>,
    pub directories: Vec<std::path::PathBuf>,
    pub git: bool,
    pub language: Option<String>,
    pub keywords: Vec<String>,
    pub recent: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Activation {
    pub suggested: Vec<String>,
    pub reasons: BTreeMap<String, Vec<String>>,
    /// Activation only advises; the full catalogue remains available.
    pub advisory_only: bool,
}

impl Activation {
    fn add(&mut self, name: &str, reason: String) {
        if !self.suggested.iter().any(|n| n == name) {
            self.suggested.push(name.to_string());
        }
        self.reasons.entry(name.to_string()).or_default().push(reason);
    }
}

/// Context rules: file extension, directory hint, git, language, keywords, and
/// recent use. Results are advisory.
pub fn activate(registry: &ToolRegistry, context: &ActivationContext) -> Activation {
    let mut activation = Activation { advisory_only: true, ..Activation::default() };
    let language = context
        .language
        .clone()
        .or_else(|| context.files.iter().find_map(|f| f.extension().and_then(|e| e.to_str()).map(|ext| extension_language(ext).to_string())))
        .unwrap_or_default()
        .to_ascii_lowercase();
    for entry in registry.entries() {
        let meta = &entry.meta;
        let mut haystack = format!("{} {}", meta.name, meta.tags.join(" ")).to_ascii_lowercase();
        haystack.push_str(&format!(" {}", meta.description.to_ascii_lowercase()));
        if !language.is_empty() && haystack.contains(&language) {
            activation.add(&meta.name, format!("language:{language}"));
        }
        if context.git && haystack.contains("git") {
            activation.add(&meta.name, "git repository".into());
        }
        for keyword in &context.keywords {
            if haystack.contains(&keyword.to_ascii_lowercase()) {
                activation.add(&meta.name, format!("keyword:{keyword}"));
            }
        }
        for dir in &context.directories {
            if let Some(name) = dir.file_name().and_then(|n| n.to_str()) {
                if haystack.contains(&name.to_ascii_lowercase()) {
                    activation.add(&meta.name, format!("directory:{name}"));
                }
            }
        }
        if context.recent.iter().any(|r| r == &meta.name) {
            activation.add(&meta.name, "recent use".into());
        }
    }
    activation
}

fn extension_language(extension: &str) -> &'static str {
    match extension {
        "rs" => "rust",
        "py" => "python",
        "ts" | "tsx" | "js" | "jsx" => "javascript",
        "go" => "go",
        _ => "",
    }
}

/// Cache-safe injection: the stable prefix is never rewritten; tool schemas are
/// appended to a tail whose hash can change without invalidating the prefix.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PromptInjection {
    pub stable_prefix: String,
    pub tail: String,
}

pub fn stable_prefix_hash(prefix: &str) -> String {
    blake3::hash(prefix.as_bytes()).to_hex().to_string()
}

pub fn inject_tools(prefix: &str, schemas: &[ToolSchema]) -> PromptInjection {
    let mut tail = String::from("\nTOOLS:\n");
    for schema in schemas {
        tail.push_str(&format!("- {}: {}\n", schema.name, schema.description));
        tail.push_str(&format!("  {}\n", schema.parameters));
    }
    PromptInjection { stable_prefix: prefix.to_string(), tail }
}

/// Hide tools the policy denies; asks remain visible. Returns visible names in
/// registry order.
pub fn filter_denied(registry: &ToolRegistry, policy: &Policy, actor: Actor) -> Vec<String> {
    registry
        .entries()
        .filter(|entry| {
            let action = zero_policy::Action::new(entry.meta.action_class, entry.meta.name.clone(), actor);
            default_verdict(policy.mode, entry.meta.action_class) != Verdict::Deny || policy.evaluate(&action).verdict != Verdict::Deny
        })
        .map(|entry| entry.meta.name.clone())
        .collect()
}

/// Hygiene: duplicate ids are impossible in the map, so this flags tools that
/// duplicate another tool's schema and description, or an extension without a
/// namespace.
pub fn hygiene(registry: &ToolRegistry) -> Vec<String> {
    let mut problems = Vec::new();
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for entry in registry.entries() {
        let signature = format!("{}|{}", entry.meta.description, entry.meta.schema);
        let digest = blake3::hash(signature.as_bytes()).to_hex().to_string();
        if let Some(existing) = seen.get(&digest) {
            problems.push(format!("tool `{}` duplicates `{existing}`", entry.meta.name));
        } else {
            seen.insert(digest, entry.meta.name.clone());
        }
        if entry.meta.source == ToolSource::Mcp && entry.meta.namespace.is_none() {
            problems.push(format!("tool `{}` has no namespace", entry.meta.name));
        }
    }
    problems
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Route {
    Native,
    Kernel,
    Protocol,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Use {
    Surfaced,
    Chosen,
    Rejected,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TelemetryEvent {
    pub route: Route,
    pub tool: String,
    pub used: Use,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolTelemetry {
    pub events: Vec<TelemetryEvent>,
    pub counts: BTreeMap<String, u64>,
}

impl ToolTelemetry {
    pub fn new() -> Self {
        Self::default()
    }

    fn key(route: Route, tool: &str, used: Use) -> String {
        format!("{:?}:{tool}:{used:?}", route)
    }

    pub fn record(&mut self, route: Route, tool: &str, used: Use) {
        *self.counts.entry(Self::key(route, tool, used)).or_insert(0) += 1;
        self.events.push(TelemetryEvent { route, tool: tool.into(), used });
    }

    pub fn surfaced(&mut self, route: Route, tools: &[String]) {
        for tool in tools {
            self.record(route, tool, Use::Surfaced);
        }
    }

    /// Rotation report: per tool, how often it was surfaced, chosen, rejected,
    /// and failed on each route.
    pub fn rotation_report(&self) -> BTreeMap<String, BTreeMap<String, u64>> {
        let mut report: BTreeMap<String, BTreeMap<String, u64>> = BTreeMap::new();
        for event in &self.events {
            *report
                .entry(event.tool.clone())
                .or_default()
                .entry(format!("{:?}:{:?}", event.route, event.used))
                .or_insert(0) += 1;
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::r#loop::{EchoTool, ReadFileTool, Tool};

    struct FakeTool {
        name: &'static str,
        description: &'static str,
        tags: Vec<String>,
        class: zero_policy::ActionClass,
        deferrable: bool,
    }

    impl Tool for FakeTool {
        fn name(&self) -> &str {
            self.name
        }
        fn description(&self) -> &str {
            self.description
        }
        fn parameters(&self) -> serde_json::Value {
            serde_json::json!({"type":"object","properties":{"q":{"type":"string"}}})
        }
        fn call(&mut self, _args: &serde_json::Value) -> zero_types::error::Result<String> {
            Ok("ok".into())
        }
        fn action_class(&self) -> zero_policy::ActionClass {
            self.class
        }
        fn tags(&self) -> Vec<String> {
            self.tags.clone()
        }
        fn examples(&self) -> Vec<String> {
            vec![format!("Use {} when needed", self.name)]
        }
        fn deferrable(&self) -> bool {
            self.deferrable
        }
    }

    fn corpus() -> ToolRegistry {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(ReadFileTool::default()));
        registry.register(Box::new(EchoTool));
        registry.register(Box::new(FakeTool {
            name: "edit_file",
            description: "edit or patch a source file",
            tags: vec!["file".into(), "write".into(), "rust".into()],
            class: zero_policy::ActionClass::Write,
            deferrable: false,
        }));
        registry.register(Box::new(FakeTool {
            name: "run_bash",
            description: "run a shell command",
            tags: vec!["shell".into(), "terminal".into()],
            class: zero_policy::ActionClass::ShellMutating,
            deferrable: false,
        }));
        registry.register(Box::new(FakeTool {
            name: "web_search",
            description: "search the web for pages and answers",
            tags: vec!["web".into(), "search".into(), "network".into()],
            class: zero_policy::ActionClass::NetworkRead,
            deferrable: false,
        }));
        registry.register(Box::new(FakeTool {
            name: "git_status",
            description: "read git status and branches",
            tags: vec!["git".into(), "repository".into()],
            class: zero_policy::ActionClass::Read,
            deferrable: false,
        }));
        registry
    }

    #[test]
    fn the_registry_has_metadata_schemas_and_passes_lint() {
        let registry = corpus();
        assert!(registry.lint().is_empty(), "{:?}", registry.lint());
        for entry in registry.entries() {
            assert!(!entry.meta.name.is_empty());
            assert!(!entry.meta.description.is_empty());
            assert!(entry.meta.schema.is_object());
            assert_eq!(entry.meta.to_schema().name, entry.meta.name);
        }
        // Non-deferred core tools are on the wire; a deferred one is not until
        // activated.
        let all: BTreeSet<String> = registry.entries().map(|e| e.meta.name.clone()).collect();
        let wire = wire_schemas(&registry, &BTreeSet::new());
        assert!(wire.iter().any(|s| s.name == "read_file"));
        assert_eq!(wire.len(), all.len(), "none of the core tools is deferred");
    }

    #[test]
    fn deferred_tools_stay_off_the_wire_until_activated() {
        let mut registry = ToolRegistry::new();
        registry.register(Box::new(FakeTool {
            name: "deferred_tool",
            description: "a deferred tool",
            tags: vec!["deferred".into()],
            class: zero_policy::ActionClass::Read,
            deferrable: true,
        }));
        assert!(wire_schemas(&registry, &BTreeSet::new()).is_empty());
        let active: BTreeSet<String> = ["deferred_tool".to_string()].into_iter().collect();
        let wire = wire_schemas(&registry, &active);
        assert_eq!(wire.len(), 1);
        assert_eq!(wire[0].name, "deferred_tool");
    }

    #[test]
    fn bm25_ranks_the_relevant_tool_first() {
        let registry = corpus();
        assert_eq!(search(&registry, "search the web", 3)[0].name, "web_search");
        assert_eq!(search(&registry, "edit file", 3)[0].name, "edit_file");
        assert_eq!(search(&registry, "git branch", 3)[0].name, "git_status");
        assert!(search(&registry, "", 3).is_empty());
        assert!(search(&registry, "zzz", 3).is_empty());
    }

    #[test]
    fn activation_is_advisory_and_explains_itself() {
        let registry = corpus();
        let activation = activate(
            &registry,
            &ActivationContext {
                files: vec!["src/lib.rs".into()],
                git: true,
                keywords: vec!["web".into()],
                recent: vec!["echo".into()],
                ..ActivationContext::default()
            },
        );
        assert!(activation.advisory_only);
        assert!(activation.suggested.iter().any(|n| n == "edit_file"), "rust language");
        assert!(activation.suggested.iter().any(|n| n == "git_status"), "git");
        assert!(activation.suggested.iter().any(|n| n == "web_search"), "keyword");
        assert!(activation.suggested.iter().any(|n| n == "echo"), "recent");
        assert!(activation.reasons["edit_file"].iter().any(|r| r.contains("language:rust")));
        // Everything is still present in the catalogue.
        assert_eq!(registry.entries().count(), 6);
    }

    #[test]
    fn tool_injection_leaves_the_stable_prefix_hash_unchanged() {
        let registry = corpus();
        let prefix = "SYSTEM PROMPT: you are Zero.";
        let before = stable_prefix_hash(prefix);
        let injection = inject_tools(prefix, &wire_schemas(&registry, &BTreeSet::new()));
        assert_eq!(stable_prefix_hash(&injection.stable_prefix), before);
        assert!(injection.tail.contains("read_file"));
        assert!(!injection.stable_prefix.contains("read_file"));
        // Loading more tools changes only the tail.
        let injection2 = inject_tools(prefix, &wire_schemas(&registry, &BTreeSet::new()));
        assert_eq!(stable_prefix_hash(&injection2.stable_prefix), before);
    }

    #[test]
    fn denied_tools_are_hidden_and_duplicates_are_flagged() {
        let registry = corpus();
        let policy = Policy::new(zero_policy::Mode::Plan, zero_types::protected::ProtectedPaths::for_current());
        let visible = filter_denied(&registry, &policy, Actor::Agent);
        assert!(visible.contains(&"read_file".to_string()));
        assert!(!visible.contains(&"edit_file".to_string()), "plan denies writes");
        assert!(!visible.contains(&"run_bash".to_string()), "plan denies mutating shell");
        assert!(visible.contains(&"web_search".to_string()), "network read is allowed (verified in plan)");

        let mut duplicates = ToolRegistry::new();
        duplicates.register(Box::new(FakeTool {
            name: "one",
            description: "same",
            tags: vec![],
            class: zero_policy::ActionClass::Read,
            deferrable: false,
        }));
        duplicates.register(Box::new(FakeTool {
            name: "two",
            description: "same",
            tags: vec![],
            class: zero_policy::ActionClass::Read,
            deferrable: false,
        }));
        assert!(hygiene(&duplicates).iter().any(|p| p.contains("duplicates")));
    }

    #[test]
    fn telemetry_records_all_four_outcomes_on_every_route() {
        let mut telemetry = ToolTelemetry::new();
        for route in [Route::Native, Route::Kernel, Route::Protocol] {
            telemetry.surfaced(route, &["read_file".into(), "web_search".into()]);
            telemetry.record(route, "read_file", Use::Chosen);
            telemetry.record(route, "web_search", Use::Rejected);
            telemetry.record(route, "read_file", Use::Failed);
        }
        let report = telemetry.rotation_report();
        assert_eq!(report["read_file"]["Kernel:Surfaced"], 1);
        assert_eq!(report["read_file"]["Kernel:Chosen"], 1);
        assert_eq!(report["read_file"]["Protocol:Failed"], 1);
        assert_eq!(report["web_search"]["Native:Rejected"], 1);
        // Kernel and protocol routes have the same shape and counts.
        let kernel: Vec<(&String, &u64)> = report["read_file"].iter().filter(|(k, _)| k.starts_with("Kernel")).collect();
        let protocol: Vec<(&String, &u64)> = report["read_file"].iter().filter(|(k, _)| k.starts_with("Protocol")).collect();
        assert_eq!(kernel.len(), protocol.len());
        assert!(kernel.iter().all(|(_, v)| **v == 1));
        assert!(protocol.iter().all(|(_, v)| **v == 1));
    }
}
