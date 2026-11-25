//! Dispatch: permits, the policy engine, host-request gating, and batches
//! (POL-03, POL-05, POL-11).
//!
//! A [`Permit`] can only be minted by [`PolicyEngine::authorize`]. The agent's
//! tool registry accepts nothing else, so the evaluator is the only path to an
//! effect.

use crate::action::{Action, Actor};
use crate::approval::ApprovalStore;
use crate::eval::{Decision, Policy};
use crate::mode::ActionClass;
use crate::mode::Verdict;
use serde::{Deserialize, Serialize};
use std::time::Instant;
use zero_store::audit::AuditLog;
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone)]
pub struct Permit {
    hash: String,
    class: ActionClass,
    version: u64,
    minted_at: Instant,
}

impl Permit {
    pub fn hash(&self) -> &str {
        &self.hash
    }

    pub fn class(&self) -> ActionClass {
        self.class
    }

    pub fn policy_version(&self) -> u64 {
        self.version
    }

    pub fn age_ms(&self) -> u128 {
        self.minted_at.elapsed().as_millis()
    }
}

pub struct PolicyEngine {
    pub policy: Policy,
    pub audit: Option<AuditLog>,
    pub approvals: Option<ApprovalStore>,
}

impl PolicyEngine {
    pub fn new(policy: Policy) -> Self {
        Self { policy, audit: None, approvals: None }
    }

    pub fn with_audit(mut self, log: AuditLog) -> Self {
        self.audit = Some(log);
        self
    }

    pub fn with_approvals(mut self, store: ApprovalStore) -> Self {
        self.approvals = Some(store);
        self
    }

    fn record(&mut self, ts: i64, kind: &str, decision: &Decision) -> Result<()> {
        if let Some(audit) = self.audit.as_mut() {
            audit.append(
                ts,
                "policy",
                kind,
                serde_json::json!({
                    "rule": decision.rule,
                    "reason": decision.reason,
                    "class": decision.effective_mode.as_str(),
                    "action_hash": decision.action_hash,
                    "policy_version": decision.policy_version,
                }),
            )?;
        }
        Ok(())
    }

    /// Evaluate and, on allow, mint a permit. Denials and asks are audited.
    pub fn authorize(&mut self, action: &Action, now_ms: i64) -> Result<Permit> {
        let approval = self
            .approvals
            .as_ref()
            .map(|store| store.is_valid(&action.hash(), now_ms))
            .unwrap_or(false);
        self.authorize_inner(action, approval.then(|| action.hash()), now_ms)
    }

    /// Like [`authorize`], with an explicit approval hash supplied by the UI.
    pub fn authorize_with_approval(&mut self, action: &Action, approval_hash: Option<&str>, now_ms: i64) -> Result<Permit> {
        self.authorize_inner(action, approval_hash.map(str::to_string), now_ms)
    }

    fn authorize_inner(&mut self, action: &Action, approval_hash: Option<String>, now_ms: i64) -> Result<Permit> {
        let decision = self.policy.evaluate_approved(action, approval_hash.as_deref());
        match decision.verdict {
            Verdict::Allow => {
                self.record(now_ms, "policy.allow", &decision)?;
                Ok(Permit {
                    hash: decision.action_hash.clone(),
                    class: action.class,
                    version: decision.policy_version,
                    minted_at: Instant::now(),
                })
            }
            Verdict::Ask => {
                self.record(now_ms, "policy.ask", &decision)?;
                Err(ZeroError::new(
                    ErrorCode::PolicyAskRequired,
                    format!("approval required for {}: {}", action.class.as_str(), decision.reason),
                ))
            }
            Verdict::Deny => {
                self.record(now_ms, "policy.deny", &decision)?;
                Err(ZeroError::new(
                    ErrorCode::PolicyDenied,
                    format!("denied {}: {} ({})", action.class.as_str(), decision.reason, decision.rule),
                ))
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileOp {
    Read,
    Write,
    Delete,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostRequest {
    File { op: FileOp, path: std::path::PathBuf },
    Shell { command: String },
    Network { method: String, url: String },
    Credential { tag: String },
    Secret { tag: String },
    Mesh { peer: String },
}

impl HostRequest {
    pub fn to_action(&self, actor: Actor) -> Action {
        match self {
            HostRequest::File { op, path } => {
                let class = match op {
                    FileOp::Read => ActionClass::Read,
                    FileOp::Write => ActionClass::Write,
                    FileOp::Delete => ActionClass::Delete,
                };
                Action::new(class, "kernel.file", actor).with_target(path.clone())
            }
            HostRequest::Shell { command } => {
                Action::new(ActionClass::ShellMutating, "kernel.shell", actor).with_arguments(serde_json::json!({"command": command}))
            }
            HostRequest::Network { method, url } => {
                let class = if method.eq_ignore_ascii_case("GET") || method.eq_ignore_ascii_case("HEAD") {
                    ActionClass::NetworkRead
                } else {
                    ActionClass::NetworkWrite
                };
                Action::new(class, "kernel.network", actor).with_arguments(serde_json::json!({"url": url, "method": method}))
            }
            HostRequest::Credential { tag } => {
                Action::new(ActionClass::Credential, "kernel.credential", actor).with_arguments(serde_json::json!({"tag": tag}))
            }
            HostRequest::Secret { tag } => {
                Action::new(ActionClass::Credential, "kernel.secret", actor).with_arguments(serde_json::json!({"tag": tag}))
            }
            HostRequest::Mesh { peer } => {
                Action::new(ActionClass::Mesh, "kernel.mesh", actor).with_arguments(serde_json::json!({"peer": peer}))
            }
        }
    }
}

/// Gate a kernel effect. The closure runs only after an allow verdict; there is
/// no ambient authority inside the kernel (POL-05).
pub fn execute_host_request<T, F>(engine: &mut PolicyEngine, request: &HostRequest, now_ms: i64, effect: F) -> Result<T>
where
    F: FnOnce() -> Result<T>,
{
    let action = request.to_action(Actor::Agent);
    let _permit = engine.authorize(&action, now_ms)?;
    effect()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CallPhase {
    Pending,
    Running,
    Finished { result: String },
    Blocked { reason: String },
}

#[derive(Debug, Clone, PartialEq)]
pub struct BatchCall {
    pub id: String,
    pub action: Action,
    pub decision: Option<Decision>,
    pub phase: CallPhase,
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct DispatchBatch {
    pub calls: Vec<BatchCall>,
}

impl DispatchBatch {
    pub fn new(calls: impl IntoIterator<Item = (String, Action)>) -> Self {
        Self {
            calls: calls
                .into_iter()
                .map(|(id, action)| BatchCall { id, action, decision: None, phase: CallPhase::Pending })
                .collect(),
        }
    }

    pub fn get(&self, id: &str) -> Option<&BatchCall> {
        self.calls.iter().find(|c| c.id == id)
    }

    pub fn start(&mut self, id: &str) -> bool {
        if let Some(call) = self.calls.iter_mut().find(|c| c.id == id) {
            if call.phase == CallPhase::Pending {
                call.phase = CallPhase::Running;
                return true;
            }
        }
        false
    }

    /// Re-evaluate every pending call against the current policy. Running calls
    /// are left alone; their result is reported when they finish.
    pub fn reevaluate_pending(&mut self, engine: &mut PolicyEngine, now_ms: i64) -> Vec<(String, Verdict)> {
        let mut changes = Vec::new();
        for call in self.calls.iter_mut() {
            if call.phase != CallPhase::Pending {
                continue;
            }
            let decision = engine.policy.evaluate(&call.action);
            changes.push((call.id.clone(), decision.verdict));
            match decision.verdict {
                Verdict::Allow => {
                    call.decision = Some(decision);
                }
                Verdict::Ask => {
                    call.phase = CallPhase::Blocked { reason: "approval required".into() };
                    call.decision = Some(decision);
                }
                Verdict::Deny => {
                    call.phase = CallPhase::Blocked { reason: decision.reason.clone() };
                    call.decision = Some(decision);
                }
            }
        }
        let _ = now_ms;
        changes
    }

    pub fn finish(&mut self, id: &str, result: impl Into<String>) -> bool {
        if let Some(call) = self.calls.iter_mut().find(|c| c.id == id) {
            if call.phase == CallPhase::Running {
                call.phase = CallPhase::Finished { result: result.into() };
                return true;
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mode::Mode;
    use zero_types::paths::Platform;
    use zero_types::protected::ProtectedPaths;

    fn protected() -> ProtectedPaths {
        ProtectedPaths::new(
            r"C:\Users\example",
            r"C:\Users\example\AppData\Local\Zero",
            r"C:\Users\example\AppData\Roaming\Zero",
            Platform::Windows,
        )
    }

    #[test]
    fn a_mode_change_re_evaluates_pending_calls_and_not_the_running_one() {
        let mut engine = PolicyEngine::new(Policy::new(Mode::Manual, protected()));
        let mut batch = DispatchBatch::new(vec![
            ("c1".into(), Action::new(ActionClass::Read, "read_file", Actor::Agent)),
            (
                "c2".into(),
                Action::new(ActionClass::Write, "edit", Actor::Agent).with_target(r"C:\work\proj\a.rs"),
            ),
            (
                "c3".into(),
                Action::new(ActionClass::ShellMutating, "bash", Actor::Agent)
                    .with_arguments(serde_json::json!({"command":"cargo test"})),
            ),
        ]);
        // The write starts running, then the user switches to plan.
        assert!(batch.start("c2"));
        engine.policy.set_mode(Mode::Plan);
        let changes = batch.reevaluate_pending(&mut engine, 100);
        assert_eq!(changes.len(), 2);
        assert_eq!(batch.get("c1").unwrap().decision.as_ref().unwrap().verdict, Verdict::Allow);
        assert_eq!(batch.get("c3").unwrap().decision.as_ref().unwrap().verdict, Verdict::Deny);
        // The running write keeps running and reports its result.
        assert_eq!(batch.get("c2").unwrap().phase, CallPhase::Running);
        assert!(batch.finish("c2", "wrote a.rs"));
        match &batch.get("c2").unwrap().phase {
            CallPhase::Finished { result } => assert_eq!(result, "wrote a.rs"),
            other => panic!("{other:?}"),
        }
        // Pending calls carry the new policy version.
        assert_eq!(
            batch.get("c1").unwrap().decision.as_ref().unwrap().policy_version,
            engine.policy.version
        );
    }

    #[test]
    fn a_permit_is_required_and_denials_are_audited() {
        let dir = tempfile::tempdir().unwrap();
        let audit = AuditLog::open(dir.path().join("audit.jsonl")).unwrap();
        let mut engine = PolicyEngine::new(Policy::new(Mode::Plan, protected())).with_audit(audit);
        let write = Action::new(ActionClass::Write, "edit", Actor::Agent).with_target(r"C:\work\proj\a.rs");
        let err = engine.authorize(&write, 100).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);

        let read = Action::new(ActionClass::Read, "read_file", Actor::Agent);
        let permit = engine.authorize(&read, 101).unwrap();
        assert_eq!(permit.hash(), read.hash());
        assert_eq!(permit.class(), ActionClass::Read);

        let report = zero_store::audit::verify(engine.audit.as_ref().unwrap().path()).unwrap();
        assert!(report.valid);
        assert_eq!(report.events, 2);
    }

    #[test]
    fn kernel_writes_are_denied_in_plan_mode_without_running_the_effect() {
        let mut engine = PolicyEngine::new(Policy::new(Mode::Plan, protected()));
        let mut ran = false;
        let request = HostRequest::File {
            op: FileOp::Write,
            path: r"C:\work\proj\generated.py".into(),
        };
        let err = execute_host_request(&mut engine, &request, 0, || {
            ran = true;
            Ok(())
        })
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(!ran, "the kernel effect must not run without a permit");

        let read = HostRequest::File { op: FileOp::Read, path: r"C:\work\proj\a.py".into() };
        let value = execute_host_request(&mut engine, &read, 1, || Ok(42)).unwrap();
        assert_eq!(value, 42);
    }

    #[test]
    fn a_subagent_inherits_plan_even_when_the_session_is_auto() {
        let mut engine = PolicyEngine::new(Policy::new(Mode::Auto, protected()));
        let action = Action::new(ActionClass::Write, "edit", Actor::Subagent)
            .with_target(r"C:\work\proj\a.rs")
            .with_parent_mode(Mode::Plan);
        assert_eq!(engine.authorize(&action, 0).unwrap_err().code(), ErrorCode::PolicyDenied);
    }
}
