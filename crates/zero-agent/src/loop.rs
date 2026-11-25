//! Agent loop (SES-11, AR-01): tool dispatch, turn accounting, cancellation, and
//! journaled side effects.
//!
//! Every tool call is journaled before dispatch. A call that began but never
//! recorded a result is reported as uncertain on the next run and is never
//! executed twice.

use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use zero_model::{
    Capabilities, CompletionRequest, Control, EventSink, Message, Provider, ProviderEvent,
    RetryPolicy, Role as ModelRole, StopReason, ToolCall, ToolSchema, Usage,
};
use zero_store::journal::{ApplyOutcome, CommandJournal};
use zero_store::session::{Entry, Role, SessionLog, ToolCall as SessionToolCall};
use zero_policy::{Action, ActionClass, Actor, Permit, PolicyEngine};
use zero_types::error::{ErrorCode, Result, ZeroError};
use zero_types::id::Clock;

use crate::queue::MessageQueue;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ToolResult {
    pub call_id: String,
    pub name: String,
    pub ok: bool,
    pub output: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnRecord {
    pub turn: u32,
    pub model: String,
    pub usage: Usage,
    pub latency_ms: u64,
    pub stop: String,
    pub tool_calls: usize,
    pub retries: u32,
    #[serde(default)]
    pub policy_version: u64,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct RunOutcome {
    pub turns: Vec<TurnRecord>,
    pub tool_results: Vec<ToolResult>,
    pub final_text: String,
    pub uncertain: Vec<String>,
    pub cancelled: bool,
    pub usage: Usage,
}

pub trait Tool {
    fn name(&self) -> &str;
    fn description(&self) -> &str;
    fn parameters(&self) -> serde_json::Value;
    fn call(&mut self, args: &serde_json::Value) -> Result<String>;
    /// The policy class this tool dispatches as. Defaults to a read.
    fn action_class(&self) -> ActionClass {
        ActionClass::Read
    }
}

#[derive(Default)]
pub struct ToolRegistry {
    tools: std::collections::BTreeMap<String, Box<dyn Tool>>,
}

impl ToolRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register(&mut self, tool: Box<dyn Tool>) {
        self.tools.insert(tool.name().to_string(), tool);
    }

    pub fn names(&self) -> Vec<&str> {
        self.tools.keys().map(|s| s.as_str()).collect()
    }

    pub fn schemas(&self) -> Vec<ToolSchema> {
        self.tools
            .values()
            .map(|t| ToolSchema {
                name: t.name().to_string(),
                description: t.description().to_string(),
                parameters: t.parameters(),
            })
            .collect()
    }

    fn call_internal(&mut self, name: &str, args: &serde_json::Value) -> Result<String> {
        let tool = self.tools.get_mut(name).ok_or_else(|| {
            ZeroError::new(ErrorCode::NotFound, format!("unknown tool `{name}`"))
        })?;
        tool.call(args)
    }

    pub fn class_of(&self, name: &str) -> ActionClass {
        self.tools.get(name).map(|t| t.action_class()).unwrap_or(ActionClass::Read)
    }

    /// The only public dispatch used by the agent loop. The permit must have been
    /// minted for exactly this action.
    pub fn call_with_permit(
        &mut self,
        permit: &Permit,
        action: &Action,
        name: &str,
        args: &serde_json::Value,
    ) -> Result<String> {
        if permit.hash() != action.hash() || permit.class() != action.class {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                "the permit does not match this action; dispatch refused",
            ));
        }
        self.call_internal(name, args)
    }
}

/// Echo tool: returns the `text` argument.
pub struct EchoTool;

impl Tool for EchoTool {
    fn name(&self) -> &str {
        "echo"
    }
    fn description(&self) -> &str {
        "Echo the text argument back."
    }
    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({"type":"object","properties":{"text":{"type":"string"}},"required":["text"]})
    }
    fn call(&mut self, args: &serde_json::Value) -> Result<String> {
        args.get("text")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "echo requires a string `text`"))
    }
}

/// Read-only file tool with a size cap. Policy gating arrives in M2.
pub struct ReadFileTool {
    pub max_bytes: usize,
}

impl Default for ReadFileTool {
    fn default() -> Self {
        Self { max_bytes: 64 * 1024 }
    }
}

impl Tool for ReadFileTool {
    fn name(&self) -> &str {
        "read_file"
    }
    fn description(&self) -> &str {
        "Read a UTF-8 text file, capped at 64 KiB."
    }
    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({"type":"object","properties":{"path":{"type":"string"}},"required":["path"]})
    }
    fn call(&mut self, args: &serde_json::Value) -> Result<String> {
        let path = args
            .get("path")
            .and_then(|v| v.as_str())
            .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "read_file requires `path`"))?;
        let bytes = std::fs::read(path)?;
        if bytes.len() > self.max_bytes {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!("file is {} bytes, limit is {}", bytes.len(), self.max_bytes),
            ));
        }
        Ok(String::from_utf8_lossy(&bytes).to_string())
    }
}

#[derive(Debug, Clone, Default)]
pub struct CancelToken(Arc<AtomicBool>);

impl CancelToken {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn cancel(&self) {
        self.0.store(true, Ordering::SeqCst);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::SeqCst)
    }
    pub fn reset(&self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

struct LoopSink {
    cancel: CancelToken,
    text: String,
    cancelled: bool,
}

impl EventSink for LoopSink {
    fn event(&mut self, event: ProviderEvent) -> Control {
        if self.cancel.is_cancelled() {
            self.cancelled = true;
            return Control::Cancel;
        }
        if let ProviderEvent::TextDelta { text } = event {
            self.text.push_str(&text);
        }
        Control::Continue
    }
}

#[derive(Debug, Clone)]
pub struct LoopConfig {
    pub model: String,
    pub max_turns: u32,
    pub system: Option<String>,
    pub retry: RetryPolicy,
    /// Sleep between retries. Tests disable it; production leaves it on.
    pub retry_sleep: bool,
}

impl Default for LoopConfig {
    fn default() -> Self {
        Self {
            model: String::new(),
            max_turns: 16,
            system: None,
            retry: RetryPolicy::default(),
            retry_sleep: false,
        }
    }
}

pub struct AgentLoop {
    pub provider: Box<dyn Provider>,
    pub tools: ToolRegistry,
    pub journal: CommandJournal,
    pub log: SessionLog,
    pub queue: Option<MessageQueue>,
    pub cancel: CancelToken,
    pub config: LoopConfig,
    pub engine: PolicyEngine,
    clock: Arc<dyn Clock>,
}

impl AgentLoop {
    // The collaborators are explicit by design; there is no ambient runtime.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        provider: Box<dyn Provider>,
        tools: ToolRegistry,
        journal: CommandJournal,
        log: SessionLog,
        queue: Option<MessageQueue>,
        config: LoopConfig,
        engine: PolicyEngine,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self { provider, tools, journal, log, queue, cancel: CancelToken::new(), config, engine, clock }
    }

    /// Change mode, persist it, and return the new policy version.
    pub fn set_mode(&mut self, mode: zero_policy::Mode) -> Result<u64> {
        let version = self.engine.policy.set_mode(mode);
        let state = zero_policy::ModeState {
            mode,
            headless_ended: false,
            version,
            running_calls: 0,
        };
        let now = self.now();
        zero_policy::persist_mode(&state, &mut self.log, now)?;
        Ok(version)
    }

    fn capabilities(&self) -> Capabilities {
        self.provider.capabilities()
    }

    fn now(&self) -> i64 {
        self.clock.now().millis()
    }

    fn transcript(&self, extra_system: &mut Vec<Message>) -> Result<Vec<Message>> {
        let mut messages = Vec::new();
        if let Some(system) = &self.config.system {
            messages.push(Message::system(system.clone()));
        }
        for record in self.log.visible_records()? {
            match record.entry {
                Entry::Message { role, text, tool_calls, tool_call_id } => {
                    let role = match role {
                        Role::System => ModelRole::System,
                        Role::User => ModelRole::User,
                        Role::Assistant => ModelRole::Assistant,
                        Role::Tool => ModelRole::Tool,
                    };
                    messages.push(Message {
                        role,
                        content: text,
                        tool_calls: tool_calls
                            .into_iter()
                            .map(|c| ToolCall { id: c.id, name: c.name, arguments: c.arguments })
                            .collect(),
                        tool_call_id,
                    });
                }
                Entry::Compaction { summary, .. } => {
                    messages.push(Message::system(format!("Session compacted. Summary:\n{summary}")));
                }
                Entry::BranchSummary { summary } => {
                    messages.push(Message::system(format!("Resumed branch summary:\n{}", summary.render())));
                }
                _ => {}
            }
        }
        messages.append(extra_system);
        Ok(messages)
    }

    fn deliver_boundary(&mut self) -> Result<bool> {
        let Some(queue) = self.queue.as_mut() else {
            return Ok(false);
        };
        let outcome = queue.apply_at_boundary(false)?;
        for item in &outcome.delivered {
            self.log.append(self.now(), Entry::Message {
                role: Role::User,
                text: item.text.clone(),
                tool_calls: vec![],
                tool_call_id: None,
            })?;
        }
        Ok(outcome.interrupt)
    }

    /// Run one user prompt to completion (or cancellation / max turns).
    pub fn run(&mut self, prompt: &str) -> Result<RunOutcome> {
        let mut outcome = RunOutcome::default();
        if !prompt.is_empty() {
            self.log.append(self.now(), Entry::Message {
                role: Role::User,
                text: prompt.to_string(),
                tool_calls: vec![],
                tool_call_id: None,
            })?;
        }
        if !self.log.records()?.iter().any(|r| matches!(r.entry, Entry::ModelChange { .. })) {
            let model = if self.config.model.is_empty() {
                "unknown".to_string()
            } else {
                self.config.model.clone()
            };
            self.log.append(self.now(), Entry::ModelChange {
                provider: self.provider.id().to_string(),
                model,
            })?;
        }

        let mut final_text = String::new();
        for turn in 0..self.config.max_turns {
            if self.cancel.is_cancelled() {
                outcome.cancelled = true;
                break;
            }
            if self.deliver_boundary()? {
                self.cancel.cancel();
                self.log.append(self.now(), Entry::Status { state: "interrupted".into() })?;
                outcome.cancelled = true;
                break;
            }

            let mut extra = Vec::new();
            let messages = self.transcript(&mut extra)?;
            let tools = if self.capabilities().tool_calls { self.tools.schemas() } else { Vec::new() };
            let mut request = CompletionRequest::new(
                if self.config.model.is_empty() { "auto" } else { &self.config.model },
                messages,
            );
            request.tools = tools;

            let mut sink = LoopSink { cancel: self.cancel.clone(), text: String::new(), cancelled: false };
            let mut retries = 0u32;
            let mut failures = Vec::new();
            let response = loop {
                match self.provider.complete(&request, &mut sink) {
                    Ok(response) => break response,
                    Err(e) => {
                        let class = self.provider.classify(&e);
                        failures.push(format!("{}: {}", e.code().as_str(), e.message()));
                        if class == zero_model::RetryClass::Safe && retries + 1 < self.config.retry.max_attempts {
                            let delay = self.config.retry.delay_ms(retries);
                            retries += 1;
                            if self.config.retry_sleep {
                                std::thread::sleep(std::time::Duration::from_millis(delay));
                            }
                            continue;
                        }
                        self.log.append(self.now(), Entry::Info {
                            text: format!("provider failed after {} attempt(s): {}", retries + 1, failures.join("; ")),
                        })?;
                        return Err(e);
                    }
                }
            };

            outcome.usage.input_tokens += response.usage.input_tokens;
            outcome.usage.output_tokens += response.usage.output_tokens;
            outcome.usage.cache_read_tokens += response.usage.cache_read_tokens;
            outcome.usage.cache_write_tokens += response.usage.cache_write_tokens;
            outcome.usage.cost_micros += response.usage.cost_micros;
            if !response.text.is_empty() {
                final_text.push_str(&response.text);
            }

            let session_calls: Vec<SessionToolCall> = response
                .tool_calls
                .iter()
                .map(|c| SessionToolCall {
                    id: c.id.clone(),
                    name: c.name.clone(),
                    arguments: c.arguments.clone(),
                })
                .collect();
            self.log.append(self.now(), Entry::Message {
                role: Role::Assistant,
                text: response.text.clone(),
                tool_calls: session_calls,
                tool_call_id: None,
            })?;

            let record = TurnRecord {
                turn,
                model: response.model.clone(),
                usage: response.usage,
                latency_ms: response.latency_ms,
                stop: format!("{:?}", response.stop),
                tool_calls: response.tool_calls.len(),
                retries,
                policy_version: self.engine.policy.version,
            };
            self.log.append(self.now(), Entry::Custom {
                name: "turn".into(),
                data: serde_json::to_value(&record)?,
            })?;
            outcome.turns.push(record);

            if sink.cancelled || response.stop == StopReason::Cancelled {
                outcome.cancelled = true;
                break;
            }
            if response.tool_calls.is_empty() {
                break;
            }

            for call in &response.tool_calls {
                if self.cancel.is_cancelled() {
                    outcome.cancelled = true;
                    break;
                }
                let digest = blake3::hash(call.arguments.to_string().as_bytes()).to_hex().to_string();
                let now = self.now();
                let class = self.tools.class_of(&call.name);
                let mut action = Action::new(class, call.name.clone(), Actor::Agent)
                    .with_arguments(call.arguments.clone());
                if let Some(path) = call.arguments.get("path").and_then(|v| v.as_str()) {
                    action = action.with_target(path);
                }
                // The evaluator is the only way to obtain a permit. A denial or an
                // ask is reported to the model and never dispatched.
                let permit = match self.engine.authorize(&action, now) {
                    Ok(permit) => permit,
                    Err(e) => {
                        let output = format!("blocked: {} ({})", e.message(), e.code().as_str());
                        self.log.append(now, Entry::Info {
                            text: format!("tool call `{}` ({}) was not dispatched: {}", call.id, call.name, e.message()),
                        })?;
                        outcome.tool_results.push(ToolResult {
                            call_id: call.id.clone(),
                            name: call.name.clone(),
                            ok: false,
                            output: output.clone(),
                        });
                        self.log.append(now, Entry::Message {
                            role: Role::Tool,
                            text: output,
                            tool_calls: vec![],
                            tool_call_id: Some(call.id.clone()),
                        })?;
                        continue;
                    }
                };
                // Journal is a field; tools is a different field, so the two
                // mutable borrows are disjoint.
                let journal = &mut self.journal;
                let tools = &mut self.tools;
                let result = journal.apply_once(&call.id, &call.name, &digest, now, || {
                    tools
                        .call_with_permit(&permit, &action, &call.name, &call.arguments)
                        .map(serde_json::Value::String)
                });
                let (ok, output, uncertain) = match result {
                    Ok(ApplyOutcome::Applied(v)) | Ok(ApplyOutcome::Replayed(v)) => {
                        (true, value_to_string(v), false)
                    }
                    Err(e) if e.code() == ErrorCode::CommandUncertain => {
                        (false, format!("uncertain: {} (not replayed)", e.message()), true)
                    }
                    Err(e) => (false, e.to_string(), false),
                };
                if uncertain {
                    outcome.uncertain.push(call.id.clone());
                    self.log.append(now, Entry::Info {
                        text: format!("tool call `{}` ({}) has an uncertain outcome; not replayed", call.id, call.name),
                    })?;
                }
                outcome.tool_results.push(ToolResult {
                    call_id: call.id.clone(),
                    name: call.name.clone(),
                    ok,
                    output: output.clone(),
                });
                self.log.append(now, Entry::Message {
                    role: Role::Tool,
                    text: output,
                    tool_calls: vec![],
                    tool_call_id: Some(call.id.clone()),
                })?;
            }
        }

        if outcome.turns.len() >= self.config.max_turns as usize {
            self.log.append(self.now(), Entry::Status { state: "max_turns".into() })?;
        }
        outcome.final_text = final_text;
        Ok(outcome)
    }

    /// The exact message list the next turn would send. Used by resume tests to
    /// prove a branch summary and compaction summary are present.
    pub fn preview_messages(&self) -> Result<Vec<Message>> {
        let mut extra = Vec::new();
        self.transcript(&mut extra)
    }

    /// Cancel from another thread or a UI action.
    pub fn cancel_token(&self) -> CancelToken {
        self.cancel.clone()
    }
}

fn value_to_string(value: serde_json::Value) -> String {
    match value {
        serde_json::Value::String(s) => s,
        other => other.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::rc::Rc;
    use zero_model::{ScriptTurn, ScriptedProvider};
    use zero_store::session::{SessionMeta, ENTRY_SCHEMA_VERSION};
    use zero_types::id::FakeClock;

    fn setup(dir: &std::path::Path, turns: Vec<ScriptTurn>) -> AgentLoop {
        let log = SessionLog::create(
            dir.join("s.jsonl"),
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: 0,
                name: "loop".into(),
                project: None,
                parent: None,
            },
        )
        .unwrap();
        let journal = CommandJournal::open(dir.join("journal.jsonl")).unwrap();
        let mut tools = ToolRegistry::new();
        tools.register(Box::new(EchoTool));
        AgentLoop::new(
            Box::new(ScriptedProvider::new(turns)),
            tools,
            journal,
            log,
            None,
            LoopConfig { model: "scripted-1".into(), retry_sleep: false, ..LoopConfig::default() },
            zero_policy::PolicyEngine::new(zero_policy::Policy::new(
                zero_policy::Mode::Auto,
                zero_types::protected::ProtectedPaths::for_current(),
            )),
            Arc::new(FakeClock::at(1_700_000_000_000)),
        )
    }

    fn call(id: &str, text: &str) -> ToolCall {
        ToolCall { id: id.into(), name: "echo".into(), arguments: serde_json::json!({"text": text}) }
    }

    #[test]
    fn scripted_three_turn_fixture_runs_end_to_end() {
        let dir = tempfile::tempdir().unwrap();
        let turns = vec![
            ScriptTurn::tool_call(call("c1", "first")).with_usage(Usage { input_tokens: 10, output_tokens: 2, ..Usage::default() }),
            ScriptTurn::tool_call(call("c2", "second")).with_usage(Usage { input_tokens: 20, output_tokens: 3, ..Usage::default() }),
            ScriptTurn::text("all done").with_usage(Usage { input_tokens: 30, output_tokens: 4, ..Usage::default() }),
        ];
        let mut agent = setup(dir.path(), turns);
        let outcome = agent.run("please work").unwrap();

        assert_eq!(outcome.turns.len(), 3, "one provider turn per script turn");
        assert_eq!(outcome.tool_results.len(), 2);
        assert_eq!(outcome.tool_results[0].output, "first");
        assert_eq!(outcome.tool_results[1].output, "second");
        assert_eq!(outcome.final_text, "all done");
        assert_eq!(outcome.usage.input_tokens, 60);
        assert_eq!(outcome.usage.output_tokens, 9);
        assert!(!outcome.cancelled);
        assert!(outcome.uncertain.is_empty());

        // Turn accounting is in the log, and tool results are transcript entries.
        let records = agent.log.records().unwrap();
        let turn_entries = records
            .iter()
            .filter(|r| matches!(&r.entry, Entry::Custom { name, .. } if name == "turn"))
            .count();
        assert_eq!(turn_entries, 3);
        let tool_entries = records
            .iter()
            .filter(|r| matches!(&r.entry, Entry::Message { role: Role::Tool, .. }))
            .count();
        assert_eq!(tool_entries, 2);
    }

    #[test]
    fn cancellation_stops_before_the_next_tool() {
        let dir = tempfile::tempdir().unwrap();
        let turns = vec![
            ScriptTurn::tool_call(call("c1", "first")),
            ScriptTurn::text("should not run"),
        ];
        let mut agent = setup(dir.path(), turns);
        agent.cancel.cancel();
        let outcome = agent.run("go").unwrap();
        assert!(outcome.cancelled);
        assert!(outcome.tool_results.is_empty());
        assert_eq!(outcome.turns.len(), 0);
    }

    /// A tool that counts calls, to prove an uncertain call is not re-executed.
    struct CountingTool(Rc<Cell<u32>>);
    impl Tool for CountingTool {
        fn name(&self) -> &str {
            "echo"
        }
        fn description(&self) -> &str {
            "counting echo"
        }
        fn parameters(&self) -> serde_json::Value {
            serde_json::json!({"type":"object"})
        }
        fn call(&mut self, _args: &serde_json::Value) -> Result<String> {
            self.0.set(self.0.get() + 1);
            Ok("ran".into())
        }
    }

    #[test]
    fn crash_mid_turn_resumes_without_duplicating_the_side_effect() {
        let dir = tempfile::tempdir().unwrap();
        let log = SessionLog::create(
            dir.path().join("s.jsonl"),
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: 0,
                name: "crash".into(),
                project: None,
                parent: None,
            },
        )
        .unwrap();
        let journal_path = dir.path().join("journal.jsonl");
        // Simulate the previous process: side effect happened, journal Begin is
        // durable, and the result was never recorded.
        std::fs::write(dir.path().join("effect.txt"), b"once\n").unwrap();
        {
            let mut writer = zero_store::jsonl::JsonlWriter::open(&journal_path).unwrap();
            writer
                .append(&zero_store::journal::JournalEntry::Begin {
                    key: "c1".into(),
                    action: "echo".into(),
                    args_digest: "d".into(),
                    ts: 0,
                })
                .unwrap();
        }
        let journal = CommandJournal::open(&journal_path).unwrap();
        let effects = Rc::new(Cell::new(0));
        let mut tools = ToolRegistry::new();
        tools.register(Box::new(CountingTool(effects.clone())));
        let mut agent = AgentLoop::new(
            Box::new(ScriptedProvider::new(vec![
                ScriptTurn::tool_call(call("c1", "again")),
                ScriptTurn::text("done"),
            ])),
            tools,
            journal,
            log,
            None,
            LoopConfig { model: "m".into(), ..LoopConfig::default() },
            zero_policy::PolicyEngine::new(zero_policy::Policy::new(
                zero_policy::Mode::Auto,
                zero_types::protected::ProtectedPaths::for_current(),
            )),
            Arc::new(FakeClock::at(0)),
        );
        let outcome = agent.run("resume").unwrap();
        assert_eq!(outcome.uncertain, vec!["c1"]);
        assert_eq!(effects.get(), 0, "the uncertain side effect is not re-executed");
        assert_eq!(std::fs::read_to_string(dir.path().join("effect.txt")).unwrap().lines().count(), 1);
        assert!(outcome.tool_results[0].output.contains("uncertain"));
        assert_eq!(outcome.turns.len(), 2, "the loop continues after reporting uncertainty");
    }
}
