//! SES-04 evidence: a fixture branch summary passes the shape test and is used
//! on resume (the resumed prompt contains its sections).

use std::sync::Arc;
use zero_agent::queue::MessageQueue;
use zero_agent::{tool_registry_with_core, AgentLoop, LoopConfig, SessionTree};
use zero_model::{ScriptTurn, ScriptedProvider};
use zero_store::journal::CommandJournal;
use zero_store::session::{BranchSummary, Entry, Role};
use zero_types::id::FakeClock;

const FIXTURE: &str = include_str!("fixtures/branch_summary.json");

#[test]
fn fixture_summary_passes_shape_and_is_used_on_resume() {
    // Shape: all six sections plus files.
    let summary = BranchSummary::parse_strict(FIXTURE).unwrap();
    assert_eq!(summary.goal, "ship the release with a verified session log");
    assert_eq!(summary.constraints.len(), 2);
    assert_eq!(summary.files.len(), 1);
    assert!(summary.render().contains("GOAL: ship the release"));

    let dir = tempfile::tempdir().unwrap();
    let mut tree = SessionTree::open(dir.path()).unwrap();
    let node = tree.create("resume-me", Some("proj".into()), 0).unwrap();
    tree.append(&node.id, 1, Entry::Message {
        role: Role::User,
        text: "older work".into(),
        tool_calls: vec![],
        tool_call_id: None,
    })
    .unwrap();
    tree.append(&node.id, 2, Entry::BranchSummary { summary: summary.clone() }).unwrap();
    tree.append(&node.id, 3, Entry::Message {
        role: Role::Assistant,
        text: "continuing".into(),
        tool_calls: vec![],
        tool_call_id: None,
    })
    .unwrap();

    let resumed = tree.resume(&node.id).unwrap();
    assert_eq!(resumed.summary.as_ref(), Some(&summary));

    // The loop's next request includes the summary as a system message.
    let log = tree.log(&node.id).unwrap();
    let agent = AgentLoop::new(
        Box::new(ScriptedProvider::new(vec![ScriptTurn::text("ok")])),
        tool_registry_with_core(),
        CommandJournal::open(dir.path().join("journal.jsonl")).unwrap(),
        log,
        None::<MessageQueue>,
        LoopConfig { model: "m".into(), ..LoopConfig::default() },
        zero_policy::PolicyEngine::new(zero_policy::Policy::new(
            zero_policy::Mode::Auto,
            zero_types::protected::ProtectedPaths::for_current(),
        )),
        Arc::new(FakeClock::at(0)),
    );
    let messages = agent.preview_messages().unwrap();
    let system_text: String = messages
        .iter()
        .filter(|m| m.role == zero_model::Role::System)
        .map(|m| m.content.clone())
        .collect::<Vec<_>>()
        .join("\n");
    assert!(system_text.contains("GOAL: ship the release"), "{system_text}");
    assert!(system_text.contains("NEXT STEPS"), "{system_text}");
    assert!(messages.iter().any(|m| m.content == "continuing"));
}
