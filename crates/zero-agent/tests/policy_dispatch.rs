//! POL-03, POL-05, POL-11, TRU-04 evidence: the evaluator is the only path to a
//! tool effect, mode changes re-evaluate, and denials are audited and persisted.

use std::cell::Cell;
use std::rc::Rc;
use std::sync::Arc;
use zero_agent::{AgentLoop, LoopConfig, Tool, ToolRegistry};
use zero_model::{ScriptTurn, ScriptedProvider, ToolCall};
use zero_policy::{Action, ActionClass, Actor, Mode, Policy, PolicyEngine};
use zero_store::audit::{verify, AuditEvent};
use zero_store::journal::CommandJournal;
use zero_store::session::{SessionLog, SessionMeta, ENTRY_SCHEMA_VERSION};
use zero_types::id::FakeClock;
use zero_types::protected::ProtectedPaths;

struct WriteTool {
    calls: Rc<Cell<u32>>,
}

impl Tool for WriteTool {
    fn name(&self) -> &str {
        "write_file"
    }
    fn description(&self) -> &str {
        "write a file"
    }
    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({"type":"object","properties":{"path":{"type":"string"}}})
    }
    fn action_class(&self) -> ActionClass {
        ActionClass::Write
    }
    fn call(&mut self, _args: &serde_json::Value) -> zero_types::error::Result<String> {
        self.calls.set(self.calls.get() + 1);
        Ok("wrote".into())
    }
}

fn call(id: &str) -> ToolCall {
    ToolCall { id: id.into(), name: "write_file".into(), arguments: serde_json::json!({"path":"a.txt"}) }
}

#[test]
fn plan_mode_blocks_a_write_tool_without_dispatching_it_and_audits_the_denial() {
    let dir = tempfile::tempdir().unwrap();
    let audit_path = dir.path().join("audit").join("audit.jsonl");
    std::fs::create_dir_all(audit_path.parent().unwrap()).unwrap();
    let audit = zero_store::audit::AuditLog::open(&audit_path).unwrap();
    let engine = PolicyEngine::new(Policy::new(Mode::Plan, ProtectedPaths::for_current())).with_audit(audit);
    let log = SessionLog::create(
        dir.path().join("s.jsonl"),
        SessionMeta {
            schema: ENTRY_SCHEMA_VERSION,
            generation: 1,
            created_ts: 0,
            name: "policy".into(),
            project: None,
            parent: None,
        },
    )
    .unwrap();
    let journal = CommandJournal::open(dir.path().join("journal.jsonl")).unwrap();
    let calls = Rc::new(Cell::new(0));
    let mut tools = ToolRegistry::new();
    tools.register(Box::new(WriteTool { calls: calls.clone() }));

    let turns = vec![
        ScriptTurn::tool_call(call("w1")),
        ScriptTurn::text("the write was blocked"),
        ScriptTurn::tool_call(call("w2")),
        ScriptTurn::text("now it ran"),
    ];
    let mut agent = AgentLoop::new(
        Box::new(ScriptedProvider::new(turns)),
        tools,
        journal,
        log,
        None,
        LoopConfig { model: "scripted".into(), ..LoopConfig::default() },
        engine,
        Arc::new(FakeClock::at(0)),
    );

    let blocked = agent.run("write a.txt").unwrap();
    assert_eq!(calls.get(), 0, "a plan-mode write must not reach the tool");
    assert_eq!(blocked.tool_results.len(), 1);
    assert!(!blocked.tool_results[0].ok);
    assert!(blocked.tool_results[0].output.contains("blocked"));
    assert!(agent.journal.state("w1").is_none(), "a denied call is not journaled as dispatched");

    // The user switches to auto; the next dispatch is allowed and runs once.
    agent.set_mode(Mode::Auto).unwrap();
    let allowed = agent.run("now write it").unwrap();
    assert_eq!(calls.get(), 1);
    assert!(allowed.tool_results[0].ok);
    assert_eq!(allowed.tool_results[0].output, "wrote");

    // The audit chain records both verdicts and verifies.
    let report = verify(&audit_path).unwrap();
    assert!(report.valid, "{report:?}");
    let (events, _) = zero_store::jsonl::scan_raw::<AuditEvent>(&audit_path).unwrap();
    let kinds: Vec<&str> = events.iter().map(|e| e.kind.as_str()).collect();
    assert!(kinds.contains(&"policy.deny"), "{kinds:?}");
    assert!(kinds.contains(&"policy.allow"), "{kinds:?}");
    assert!(events.iter().any(|e| e.payload.get("rule").and_then(|r| r.as_str()) == Some("hard_deny.protected_path")
        || e.payload.get("rule").and_then(|r| r.as_str()) == Some("matrix")));

    // Mode persistence survives a reopen.
    let records = agent.log.records().unwrap();
    let loaded = zero_policy::load_mode(&records).expect("mode persisted");
    assert_eq!(loaded.mode, Mode::Auto);
    assert_eq!(loaded.version, agent.engine.policy.version);
}

#[test]
fn a_permit_is_bound_to_exactly_one_action() {
    let dir = tempfile::tempdir().unwrap();
    let mut engine = PolicyEngine::new(Policy::new(Mode::Auto, ProtectedPaths::for_current()));
    let read = Action::new(ActionClass::Read, "read_file", Actor::Agent)
        .with_arguments(serde_json::json!({"path":"a.txt"}));
    let permit = engine.authorize(&read, 0).unwrap();

    let mut tools = ToolRegistry::new();
    tools.register(Box::new(zero_agent::EchoTool));
    // Same tool, different arguments: the permit does not cover it.
    let other = Action::new(ActionClass::Read, "echo", Actor::Agent)
        .with_arguments(serde_json::json!({"text":"different"}));
    let err = tools
        .call_with_permit(&permit, &other, "echo", &serde_json::json!({"text":"different"}))
        .unwrap_err();
    assert_eq!(err.code(), zero_types::ErrorCode::PolicyDenied);

    // A permit for the matching action is accepted.
    let echo = Action::new(ActionClass::Read, "echo", Actor::Agent)
        .with_arguments(serde_json::json!({"text":"hi"}));
    let echo_permit = engine.authorize(&echo, 1).unwrap();
    let out = tools
        .call_with_permit(&echo_permit, &echo, "echo", &serde_json::json!({"text":"hi"}))
        .unwrap();
    assert_eq!(out, "hi");
    let _ = dir;
}

#[test]
fn self_escalation_is_denied_with_an_audit_record() {
    let dir = tempfile::tempdir().unwrap();
    let audit = zero_store::audit::AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
    let mut engine = PolicyEngine::new(Policy::new(Mode::Auto, ProtectedPaths::for_current())).with_audit(audit);
    let escalate = Action::new(ActionClass::ModeChange, "mode.set", Actor::Agent)
        .with_arguments(serde_json::json!({"mode":"auto"}));
    let err = engine.authorize(&escalate, 0).unwrap_err();
    assert_eq!(err.code(), zero_types::ErrorCode::PolicyDenied);
    assert!(err.message().contains("self_escalation"), "{}", err.message());

    let report = verify(dir.path().join("audit.jsonl")).unwrap();
    assert!(report.valid);
    let (events, _) = zero_store::jsonl::scan_raw::<AuditEvent>(&dir.path().join("audit.jsonl")).unwrap();
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].payload["rule"], "hard_deny.self_escalation");
}
