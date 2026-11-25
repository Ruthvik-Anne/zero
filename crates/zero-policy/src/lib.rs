//! `zero-policy` — action classes, modes, the matrix, the evaluator, approvals,
//! deletion guards, trust, and the regulators.
//!
//! Contract (`architecture.md` §5): must not perform IO on behalf of a tool.

pub mod action;
pub mod approval;
pub mod delete;
pub mod dispatch;
pub mod eval;
pub mod headless;
pub mod mode;
pub mod regulator;
pub mod sandbox;
pub mod shims;
pub mod transitions;
pub mod trust;

pub use action::{Action, Actor};
pub use approval::{Approval, ApprovalDecision, ApprovalStore};
pub use eval::{Decision, Policy};
pub use mode::{default_verdict, ActionClass, Mode, Verdict, MATRIX};
pub use transitions::{end_headless, load as load_mode, persist as persist_mode, transition, ModeState, TransitionContext};
pub use dispatch::{execute_host_request, CallPhase, DispatchBatch, FileOp, HostRequest, Permit, PolicyEngine};
pub use headless::{run_headless, HeadlessReport, ItemState, QueueKind, QueuedItem, UserQueue, Work};
pub use regulator::{auto_review, AiDecision, AiRegulator, AiVerdict, AutoOutcome, CodeRegulator, RegulatorContext, RegulatorInput};
pub use trust::{load_project_features, ProjectFeatures, TrustEntry, TrustStore};
