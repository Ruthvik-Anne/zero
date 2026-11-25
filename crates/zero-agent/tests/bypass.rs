//! TRU-04 evidence: a red-team suite of attempted bypasses. Every route either
//! needs a permit minted by the evaluator or fails closed.

use std::sync::Arc;
use zero_agent::{AgentLoop, LoopConfig, Tool, ToolRegistry};
use zero_model::{ScriptTurn, ScriptedProvider, ToolCall};
use zero_policy::{
    Action, ActionClass, Actor, FileOp, HostRequest, Mode, Policy, PolicyEngine, Verdict,
};
use zero_store::journal::CommandJournal;
use zero_store::session::{SessionLog, SessionMeta, ENTRY_SCHEMA_VERSION};
use zero_types::id::FakeClock;
use zero_types::protected::ProtectedPaths;

fn engine(mode: Mode) -> PolicyEngine {
    PolicyEngine::new(Policy::new(mode, ProtectedPaths::for_current()))
}

fn attempt_action(engine: &mut PolicyEngine, class: ActionClass, tool: &str, target: Option<&str>) -> Result<(), zero_types::ErrorCode> {
    let mut action = Action::new(class, tool, Actor::Agent).with_arguments(serde_json::json!({"x": 1}));
    if let Some(target) = target {
        action = action.with_target(target);
    }
    engine.authorize(&action, 0).map(|_| ()).map_err(|e| e.code())
}

#[test]
fn bypass_suite_fails_closed() {
    // 1. Direct tool dispatch without a permit is not exposed; a permit for a
    //    different action is rejected.
    let mut e = engine(Mode::Auto);
    let mut tools = ToolRegistry::new();
    tools.register(Box::new(zero_agent::EchoTool));
    let allowed = Action::new(ActionClass::Read, "echo", Actor::Agent)
        .with_arguments(serde_json::json!({"text":"ok"}));
    let permit = e.authorize(&allowed, 0).unwrap();
    let other = Action::new(ActionClass::Read, "echo", Actor::Agent)
        .with_arguments(serde_json::json!({"text":"other"}));
    assert_eq!(
        tools.call_with_permit(&permit, &other, "echo", &serde_json::json!({"text":"other"})).unwrap_err().code(),
        zero_types::ErrorCode::PolicyDenied
    );

    // 2. Kernel file writes bypassing the edit tool.
    let mut e = engine(Mode::Plan);
    let mut ran = false;
    let write = HostRequest::File { op: FileOp::Write, path: "generated.py".into() };
    assert_eq!(
        zero_policy::execute_host_request(&mut e, &write, 0, || {
            ran = true;
            Ok(())
        })
        .unwrap_err()
        .code(),
        zero_types::ErrorCode::PolicyDenied
    );
    assert!(!ran);

    // 3. The agent changing its own mode.
    assert_eq!(
        attempt_action(&mut e, ActionClass::ModeChange, "mode.set", None),
        Err(zero_types::ErrorCode::PolicyDenied)
    );

    // 4. A write to a protected policy file.
    assert_eq!(
        attempt_action(&mut engine(Mode::Auto), ActionClass::Write, "edit", Some(".zero/policy.toml")),
        Err(zero_types::ErrorCode::PolicyDenied)
    );

    // 5. A subagent escalating beyond its parent.
    let parent = Action::new(ActionClass::Write, "edit", Actor::Subagent)
        .with_target("src/a.rs")
        .with_parent_mode(Mode::Plan);
    assert_eq!(engine(Mode::Auto).authorize(&parent, 0).unwrap_err().code(), zero_types::ErrorCode::PolicyDenied);

    // 6. An untrusted project asking for auto-mode writes.
    let untrusted = Policy::untrusted(Mode::Auto, ProtectedPaths::for_current());
    let write = Action::new(ActionClass::Write, "edit", Actor::Agent).with_target("src/a.rs");
    assert_eq!(untrusted.evaluate(&write).verdict, Verdict::Deny);

    // 7. Headless irreversible work is queued, never silently allowed.
    let headless = Policy::new(Mode::Headless, ProtectedPaths::for_current());
    let purge = Action::new(ActionClass::Delete, "purge", Actor::Agent)
        .with_target("src")
        .irreversible(true);
    let decision = headless.evaluate(&purge);
    assert_eq!(decision.verdict, Verdict::Ask);
    assert!(decision.queue);
}

struct WriteTool;
impl Tool for WriteTool {
    fn name(&self) -> &str {
        "write_file"
    }
    fn description(&self) -> &str {
        "write"
    }
    fn parameters(&self) -> serde_json::Value {
        serde_json::json!({"type":"object"})
    }
    fn action_class(&self) -> ActionClass {
        ActionClass::Write
    }
    fn call(&mut self, _args: &serde_json::Value) -> zero_types::error::Result<String> {
        panic!("a denied write reached the tool")
    }
}

#[test]
fn a_denied_tool_never_executes_through_the_loop() {
    let dir = tempfile::tempdir().unwrap();
    let log = SessionLog::create(
        dir.path().join("s.jsonl"),
        SessionMeta {
            schema: ENTRY_SCHEMA_VERSION,
            generation: 1,
            created_ts: 0,
            name: "bypass".into(),
            project: None,
            parent: None,
        },
    )
    .unwrap();
    let mut tools = ToolRegistry::new();
    tools.register(Box::new(WriteTool));
    let mut agent = AgentLoop::new(
        Box::new(ScriptedProvider::new(vec![
            ScriptTurn::tool_call(ToolCall {
                id: "b1".into(),
                name: "write_file".into(),
                arguments: serde_json::json!({"path":"a.txt"}),
            }),
            ScriptTurn::text("blocked"),
        ])),
        tools,
        CommandJournal::open(dir.path().join("journal.jsonl")).unwrap(),
        log,
        None,
        LoopConfig { model: "m".into(), ..LoopConfig::default() },
        engine(Mode::Plan),
        Arc::new(FakeClock::at(0)),
    );
    let outcome = agent.run("try to write").unwrap();
    assert!(!outcome.tool_results[0].ok);
    assert!(outcome.tool_results[0].output.contains("blocked"));
}
