//! The evaluator (POL-03, POL-04, POL-06, POL-07, POL-08, POL-12, POL-16).
//!
//! Order: hard deny, then approved actions, then ask rules, then the matrix.
//! The first terminal match wins; a hard deny is never overridable.

use crate::action::Action;
use crate::mode::{default_verdict, ActionClass, Mode, Verdict};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::protected::ProtectedPaths;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub verdict: Verdict,
    pub rule: String,
    pub reason: String,
    pub policy_version: u64,
    pub action_hash: String,
    /// In headless mode an `Ask` is placed on the durable user queue.
    pub queue: bool,
    /// The mode actually used (plan-equivalent for untrusted projects).
    pub effective_mode: Mode,
}

impl Decision {
    pub fn allowed(&self) -> bool {
        self.verdict == Verdict::Allow
    }
}

#[derive(Debug, Clone)]
pub struct Policy {
    pub mode: Mode,
    pub version: u64,
    pub overrides: BTreeMap<(Mode, ActionClass), Verdict>,
    pub protected: ProtectedPaths,
    pub trusted: bool,
}

impl Policy {
    pub fn new(mode: Mode, protected: ProtectedPaths) -> Self {
        Self { mode, version: 1, overrides: BTreeMap::new(), protected, trusted: true }
    }

    pub fn untrusted(mode: Mode, protected: ProtectedPaths) -> Self {
        let mut policy = Self::new(mode, protected);
        policy.trusted = false;
        policy
    }

    pub fn set_mode(&mut self, mode: Mode) -> u64 {
        if self.mode != mode {
            self.mode = mode;
            self.version += 1;
        }
        self.version
    }

    pub fn set_override(&mut self, mode: Mode, class: ActionClass, verdict: Verdict) -> u64 {
        self.overrides.insert((mode, class), verdict);
        self.version += 1;
        self.version
    }

    pub fn untrust(&mut self) {
        self.trusted = false;
        self.version += 1;
    }

    fn effective_mode(&self, action: &Action) -> (Mode, Option<String>) {
        // An untrusted project is limited to plan-equivalent behaviour (TRU-02).
        if !self.trusted {
            return (Mode::Plan, Some("untrusted project: plan-equivalent behaviour".into()));
        }
        let mut mode = self.mode;
        if action.actor == crate::action::Actor::Subagent {
            if let Some(parent) = action.parent_mode {
                if parent.authority() < mode.authority() {
                    mode = parent;
                }
            }
        }
        if action.actor.is_unattended() && mode.authority() > Mode::Headless.authority() {
            mode = Mode::Headless;
        }
        (mode, None)
    }

    /// Evaluate an action. `approval_hash` is the hash a user approved, if any.
    pub fn evaluate(&self, action: &Action) -> Decision {
        self.evaluate_approved(action, None)
    }

    pub fn evaluate_approved(&self, action: &Action, approval_hash: Option<&str>) -> Decision {
        let (mode, untrusted_reason) = self.effective_mode(action);
        let hash = action.hash();
        let make = |verdict: Verdict, rule: &str, reason: String, queue: bool| Decision {
            verdict,
            rule: rule.to_string(),
            reason,
            policy_version: self.version,
            action_hash: hash.clone(),
            queue,
            effective_mode: mode,
        };

        // 1. Hard denies, first terminal match.
        if action.actor.is_agent() && action.class == ActionClass::ModeChange {
            return make(
                Verdict::Deny,
                "hard_deny.self_escalation",
                "the agent cannot change its own mode".into(),
                false,
            );
        }
        if action.actor == crate::action::Actor::Subagent {
            if let (Some(requested), Some(parent)) = (action.requested_mode, action.parent_mode) {
                if requested.authority() > parent.authority() {
                    return make(
                        Verdict::Deny,
                        "hard_deny.subagent_escalation",
                        format!("a subagent in {} cannot request {}", parent.as_str(), requested.as_str()),
                        false,
                    );
                }
            }
        }
        if action.actor.is_agent() {
            if let Some(target) = &action.target {
                if let Some(refusal) = self.protected.classify(target) {
                    let writes = matches!(
                        action.class,
                        ActionClass::Write
                            | ActionClass::Delete
                            | ActionClass::ShellMutating
                            | ActionClass::Install
                            | ActionClass::ModeChange
                    );
                    if writes {
                        return make(
                            Verdict::Deny,
                            "hard_deny.protected_path",
                            format!("{} is protected: {}", target.display(), refusal.reason),
                            false,
                        );
                    }
                }
            }
        }

        // User authority is outside the agent matrix: the user may change mode.
        if action.actor == crate::action::Actor::User && action.class == ActionClass::ModeChange {
            return make(Verdict::Allow, "user_authority", "the user changes modes directly".into(), false);
        }

        // 2. Exact approval can lift an Ask, never a Deny.
        let base = self.overrides.get(&(mode, action.class)).copied().unwrap_or_else(|| default_verdict(mode, action.class));
        if base == Verdict::Ask {
            if let Some(approved) = approval_hash {
                if approved == hash {
                    return make(Verdict::Allow, "approval", "the exact action was approved by the user".into(), false);
                }
            }
        }

        // 3. Ask rules.
        if matches!(mode, Mode::Plan)
            && matches!(
                action.class,
                ActionClass::McpRead | ActionClass::McpWrite | ActionClass::NetworkRead | ActionClass::NetworkWrite
            )
            && !action.verified_read_only
        {
            return make(
                Verdict::Ask,
                "ask.unverified_tool",
                "plan mode allows this tool only when it is verified read-only".into(),
                false,
            );
        }
        if action.actor.is_agent() && action.irreversible && matches!(mode, Mode::Plan | Mode::Manual | Mode::SemiAuto | Mode::Headless) {
            return make(
                Verdict::Ask,
                "ask.irreversible",
                "irreversible actions need an explicit approval in this mode".into(),
                mode == Mode::Headless,
            );
        }

        // 4. Matrix / override.
        let queue = mode == Mode::Headless && base == Verdict::Ask;
        let reason = untrusted_reason.unwrap_or_else(|| {
            if base == Verdict::Allow {
                format!("{} allows {} by default", mode.as_str(), action.class.as_str())
            } else if base == Verdict::Ask {
                format!("{} asks before {}", mode.as_str(), action.class.as_str())
            } else {
                format!("{} denies {} by default", mode.as_str(), action.class.as_str())
            }
        });
        make(base, "matrix", reason, queue)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::Actor;
    use zero_types::paths::Platform;

    fn protected() -> ProtectedPaths {
        ProtectedPaths::new(
            r"C:\Users\example",
            r"C:\Users\example\AppData\Local\Zero",
            r"C:\Users\example\AppData\Roaming\Zero",
            Platform::Windows,
        )
    }

    fn policy(mode: Mode) -> Policy {
        Policy::new(mode, protected())
    }

    #[test]
    fn conflicting_rules_resolve_to_deny() {
        let mut p = policy(Mode::Plan);
        // An override tries to allow writes in plan mode...
        p.set_override(Mode::Plan, ActionClass::Write, Verdict::Allow);
        // ...but a write to a protected path is a hard deny.
        let action = Action::new(ActionClass::Write, "edit", Actor::Agent)
            .with_target(r"C:\work\proj\.git\config")
            .with_arguments(serde_json::json!({"text":"x"}));
        let decision = p.evaluate(&action);
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.rule, "hard_deny.protected_path");

        // An ordinary write now wins the override.
        let ordinary = Action::new(ActionClass::Write, "edit", Actor::Agent)
            .with_target(r"C:\work\proj\src\main.rs");
        assert_eq!(p.evaluate(&ordinary).verdict, Verdict::Allow);
    }

    #[test]
    fn self_escalation_is_a_typed_hard_deny() {
        let p = policy(Mode::Auto);
        let action = Action::new(ActionClass::ModeChange, "mode.set", Actor::Agent)
            .with_arguments(serde_json::json!({"mode":"auto"}));
        let decision = p.evaluate(&action);
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.rule, "hard_deny.self_escalation");

        // The user may change mode through the same action class.
        let user = Action::new(ActionClass::ModeChange, "mode.set", Actor::User);
        assert_eq!(p.evaluate(&user).verdict, Verdict::Allow);
    }

    #[test]
    fn a_subagent_in_plan_mode_cannot_write() {
        let p = policy(Mode::Auto);
        let action = Action::new(ActionClass::Write, "edit", Actor::Subagent)
            .with_target(r"C:\work\proj\src\lib.rs")
            .with_parent_mode(Mode::Plan);
        let decision = p.evaluate(&action);
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.effective_mode, Mode::Plan);
    }

    #[test]
    fn plan_mode_requires_verified_read_only_tools() {
        let p = policy(Mode::Plan);
        let unverified = Action::new(ActionClass::McpRead, "mcp.search", Actor::Agent);
        assert_eq!(p.evaluate(&unverified).verdict, Verdict::Ask);
        assert_eq!(p.evaluate(&unverified).rule, "ask.unverified_tool");
        let verified = Action::new(ActionClass::McpRead, "mcp.search", Actor::Agent).verified_read_only(true);
        assert_eq!(p.evaluate(&verified).verdict, Verdict::Allow);
        // A write tool asks in plan mode even when marked read-only.
        let write = Action::new(ActionClass::McpWrite, "mcp.write", Actor::Agent).verified_read_only(true);
        assert_eq!(p.evaluate(&write).verdict, Verdict::Ask);
    }

    #[test]
    fn an_untrusted_project_is_plan_equivalent() {
        let p = Policy::untrusted(Mode::Auto, protected());
        let action = Action::new(ActionClass::Write, "edit", Actor::Agent)
            .with_target(r"C:\work\proj\src\lib.rs");
        let decision = p.evaluate(&action);
        assert_eq!(decision.verdict, Verdict::Deny);
        assert_eq!(decision.effective_mode, Mode::Plan);
        assert!(decision.reason.contains("untrusted"));
    }

    #[test]
    fn headless_asks_are_queued_not_stalled() {
        let p = policy(Mode::Headless);
        let action = Action::new(ActionClass::ShellMutating, "bash", Actor::Agent)
            .with_arguments(serde_json::json!({"command":"make"}));
        let decision = p.evaluate(&action);
        assert_eq!(decision.verdict, Verdict::Ask);
        assert!(decision.queue);

        // Independent work (a read) still runs.
        let read = Action::new(ActionClass::Read, "read_file", Actor::Agent);
        assert_eq!(p.evaluate(&read).verdict, Verdict::Allow);
    }

    #[test]
    fn approval_lifts_an_ask_but_never_a_deny() {
        let mut p = policy(Mode::Manual);
        let action = Action::new(ActionClass::Write, "edit", Actor::Agent)
            .with_target(r"C:\work\proj\a.rs");
        let hash = action.hash();
        assert_eq!(p.evaluate(&action).verdict, Verdict::Ask);
        assert_eq!(p.evaluate_approved(&action, Some(&hash)).verdict, Verdict::Allow);

        p.set_mode(Mode::Plan);
        let write = Action::new(ActionClass::Write, "edit", Actor::Agent)
            .with_target(r"C:\work\proj\a.rs");
        let write_hash = write.hash();
        assert_eq!(p.evaluate_approved(&write, Some(&write_hash)).verdict, Verdict::Deny);
    }

    #[test]
    fn version_changes_with_mode_and_override() {
        let mut p = policy(Mode::Manual);
        assert_eq!(p.version, 1);
        p.set_mode(Mode::Auto);
        assert_eq!(p.version, 2);
        p.set_override(Mode::Auto, ActionClass::Delete, Verdict::Ask);
        assert_eq!(p.version, 3);
        let action = Action::new(ActionClass::Delete, "trash", Actor::Agent)
            .with_target(r"C:\work\proj\old.txt");
        assert_eq!(p.evaluate(&action).verdict, Verdict::Ask);
        assert_eq!(p.evaluate(&action).policy_version, 3);
    }

    #[test]
    fn unattended_triggers_are_never_more_permissive_than_the_session() {
        let p = policy(Mode::Plan);
        let schedule = Action::new(ActionClass::Write, "edit", Actor::Schedule)
            .with_target(r"C:\work\proj\a.rs");
        assert_eq!(p.evaluate(&schedule).effective_mode, Mode::Plan);
        assert_eq!(p.evaluate(&schedule).verdict, Verdict::Deny);

        let p = policy(Mode::Auto);
        let schedule = Action::new(ActionClass::ShellMutating, "bash", Actor::Schedule)
            .with_arguments(serde_json::json!({"command":"make"}));
        assert_eq!(p.evaluate(&schedule).effective_mode, Mode::Headless);
        assert_eq!(p.evaluate(&schedule).verdict, Verdict::Ask);
    }
}
