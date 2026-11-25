//! Auto-resume policy (AR-02, AR-04, AR-05; T-AR-02).
//!
//! [`decide`] turns a [`ResumeCause`], a [`ResumePolicy`], and the observed
//! [`ResumeContext`] into a [`ResumePlan`]. It is pure: the caller supplies
//! `now_ms`, so a decision is reproducible and tests need no sleeps. The plan
//! carries an optional [`ResumeAttempt`] with the next time, never a live timer.
//!
//! # Rules
//!
//! | Cause | Automatic | Prompt | Refuse | Wait |
//! |---|---|---|---|---|
//! | `DaemonRestart`, `Crash`, `Reboot`, `Disconnect` | yes, within attempts/budget | device changed, or uncertain effects | attempts exhausted, no budget, auto disabled | no budget but a reset is known |
//! | `DeviceChanged` | never | `device_prompt` | device prompts disabled, or a hard bound | no budget but a reset is known |
//! | `Teleport` | never | always | a hard bound | no budget but a reset is known |
//! | `UsageWindow` | only after the reset | device changed, or uncertain effects after the reset | no known reset, no budget after the reset, auto disabled | reset still in the future |
//!
//! Hard bounds are checked first, in this order: the attempt bound, the policy
//! budget veto, then the usage-window wait. After those, a cause that can resume
//! automatically is gated by the remaining budget, a device mismatch, uncertain
//! effects (AR-04), and the `auto` switch, in that order.
//!
//! # Prompts are not approval
//!
//! A [`ResumeDecision::Prompt`] plan does not resume anything. After the user
//! approves, the caller re-evaluates with the approved context (for a device
//! prompt that means the device now matches and the root cause is restored) and
//! the resulting [`ResumeDecision::Auto`] plan resumes the children through
//! [`children_plan`] (AR-05).
//!
//! # Uncertain effects (AR-04)
//!
//! `uncertain_effects` comes from the loop journal: a `begin` without an
//! `applied` result. Such a run is never resumed automatically, and the reason
//! says the effects are not replayed. The prompt is the surfacing mechanism; the
//! loop itself refuses to replay the command (`zero.ses.command_uncertain`).

use serde::{Deserialize, Serialize};

/// Why a run is being considered for a resume.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeCause {
    /// The daemon restarted while the run was live.
    DaemonRestart,
    /// The process crashed.
    Crash,
    /// The machine rebooted.
    Reboot,
    /// The connection to the daemon or provider was lost.
    Disconnect,
    /// The session moved to another device or daemon.
    Teleport,
    /// The same session is now observed on a different device.
    DeviceChanged,
    /// A subscription usage or rate-limit window closed.
    UsageWindow,
}

impl ResumeCause {
    /// Stable snake-case name for logs and UI.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::DaemonRestart => "daemon_restart",
            Self::Crash => "crash",
            Self::Reboot => "reboot",
            Self::Disconnect => "disconnect",
            Self::Teleport => "teleport",
            Self::DeviceChanged => "device_changed",
            Self::UsageWindow => "usage_window",
        }
    }

    /// True when this cause may ever resume without a prompt.
    ///
    /// `DeviceChanged` and `Teleport` are always prompted (or refused); the
    /// other causes can be automatic once their bounds pass.
    pub fn may_auto_resume(self) -> bool {
        !matches!(self, Self::DeviceChanged | Self::Teleport)
    }
}

/// The policy fields that govern every resume decision.
///
/// The defaults are safe: automatic resume is on (AR-02), a device change always
/// prompts, attempts are bounded, and a zero budget still refuses. No field
/// bypasses the attempt bound, the ledger budget, or uncertain effects.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ResumePolicy {
    /// Allow automatic resume for causes that need no prompt (AR-02).
    pub auto: bool,
    /// Prompt when the device changed instead of resuming across devices.
    ///
    /// A teleport always prompts, even when this is false, because it is a
    /// device/daemon move by definition.
    pub device_prompt: bool,
    /// Total attempts allowed, including the first one.
    pub max_attempts: u32,
    /// Backoff before the first retry (attempt 2). The first attempt is now.
    pub initial_backoff_ms: i64,
    /// Ceiling for the exponential retry backoff.
    pub max_backoff_ms: i64,
    /// Operator veto: when false, every resume is refused regardless of the
    /// remaining budget. `budget_remaining_micros == 0` is a separate, always-on
    /// ledger check.
    pub budget_allowed: bool,
}

impl Default for ResumePolicy {
    fn default() -> Self {
        Self {
            auto: true,
            device_prompt: true,
            max_attempts: 3,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 60_000,
            budget_allowed: true,
        }
    }
}

/// The observed state a decision is made from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ResumeContext {
    /// Attempts already consumed for this run.
    pub attempts_used: u32,
    /// Budget left for the run, in micros. Zero is over budget.
    pub budget_remaining_micros: u64,
    /// Whether the current device is the device that owns the session.
    pub device_matches: bool,
    /// When a closed usage/rate-limit window resets, when known.
    pub usage_reset_ms: Option<i64>,
    /// A journaled command began but never recorded a result (AR-04).
    pub uncertain_effects: bool,
}

/// What a plan says to do now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResumeDecision {
    /// Resume now (subject to the attempt in the plan).
    Auto,
    /// Ask the user before resuming.
    Prompt { reason: String },
    /// Do not resume; the reason is stable enough to show (AR-07).
    Refuse { reason: String },
    /// Resume no earlier than `until_ms`; the reason names the window.
    Wait { until_ms: i64, reason: String },
}

impl ResumeDecision {
    /// True for [`ResumeDecision::Auto`].
    pub fn is_auto(&self) -> bool {
        matches!(self, Self::Auto)
    }

    /// True for [`ResumeDecision::Prompt`].
    pub fn is_prompt(&self) -> bool {
        matches!(self, Self::Prompt { .. })
    }

    /// True for [`ResumeDecision::Refuse`].
    pub fn is_refused(&self) -> bool {
        matches!(self, Self::Refuse { .. })
    }

    /// True for [`ResumeDecision::Wait`].
    pub fn is_wait(&self) -> bool {
        matches!(self, Self::Wait { .. })
    }

    /// The prompt/refuse/wait reason, if this decision has one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Auto => None,
            Self::Prompt { reason } | Self::Refuse { reason } | Self::Wait { reason, .. } => {
                Some(reason)
            }
        }
    }

    /// The time to resume at, for a wait.
    pub fn until_ms(&self) -> Option<i64> {
        match self {
            Self::Wait { until_ms, .. } => Some(*until_ms),
            _ => None,
        }
    }
}

/// One planned attempt. `next_at_ms` is `now_ms + delay`; the caller waits, it
/// does not sleep inside this module.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeAttempt {
    /// 1-based attempt number.
    pub attempt: u32,
    /// Earliest time the caller may run this attempt.
    pub next_at_ms: i64,
}

/// One decision plus the attempt it would consume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumePlan {
    pub decision: ResumeDecision,
    /// Present only for [`ResumeDecision::Auto`]. A prompt, refusal, or wait
    /// schedules nothing.
    pub attempt: Option<ResumeAttempt>,
}

impl ResumePlan {
    /// True when the plan resumes now.
    pub fn is_auto(&self) -> bool {
        self.decision.is_auto()
    }

    /// True when the plan asks the user first.
    pub fn is_prompt(&self) -> bool {
        self.decision.is_prompt()
    }

    /// True when the plan refuses to resume.
    pub fn is_refused(&self) -> bool {
        self.decision.is_refused()
    }

    /// True when the plan waits for a window.
    pub fn is_wait(&self) -> bool {
        self.decision.is_wait()
    }
}

/// Decide what to do with one resume event.
///
/// Precedence, highest first:
///
/// 1. `attempts_used >= max_attempts` refuses.
/// 2. `budget_allowed == false` refuses (operator veto).
/// 3. `UsageWindow` with a future reset waits; with no reset it refuses.
/// 4. `budget_remaining_micros == 0` refuses, unless a future reset is known
///    (then it waits).
/// 5. `Teleport` prompts.
/// 6. A device mismatch, or `DeviceChanged`, prompts when `device_prompt` is
///    set and refuses otherwise.
/// 7. Uncertain effects prompt (AR-04).
/// 8. `auto == false` refuses.
/// 9. Otherwise the cause resumes automatically with the next bounded attempt.
///
/// The first attempt is immediate. Retry `n` (attempt `n + 1`) waits
/// `initial_backoff_ms * 2^(n - 1)`, capped at `max_backoff_ms`. Negative and
/// zero backoff values are clamped to zero, and the time addition saturates.
pub fn decide(
    cause: ResumeCause,
    policy: ResumePolicy,
    context: ResumeContext,
    now_ms: i64,
) -> ResumePlan {
    if context.attempts_used >= policy.max_attempts {
        return refused(format!(
            "attempt limit reached: {} of {} used",
            context.attempts_used, policy.max_attempts
        ));
    }

    if !policy.budget_allowed {
        return refused("resume refused: the budget policy disallows automatic resume");
    }

    if cause == ResumeCause::UsageWindow {
        if !policy.auto {
            return refused("automatic resume is disabled; resume manually after the window");
        }
        match context.usage_reset_ms {
            Some(reset) if now_ms < reset => {
                return wait(reset, "usage window is open; waiting for the reset");
            }
            Some(_) => {}
            None => {
                if context.budget_remaining_micros == 0 {
                    return refused("over budget: no budget remains for a resume");
                }
                return refused("usage window without a known reset time");
            }
        }
    }

    if context.budget_remaining_micros == 0 {
        if let Some(reset) = context.usage_reset_ms {
            if now_ms < reset {
                return wait(reset, "budget exhausted; waiting for the usage window to reset");
            }
        }
        return refused("over budget: no budget remains for a resume");
    }

    if cause == ResumeCause::Teleport {
        return prompted(prompt_reason(
            "the session was teleported; confirm the resume",
            context,
        ));
    }

    let device_moved = !context.device_matches || cause == ResumeCause::DeviceChanged;
    if device_moved {
        if policy.device_prompt {
            return prompted(prompt_reason("the device changed; confirm the resume", context));
        }
        return refused("the device changed; automatic resume across devices is disabled");
    }

    if context.uncertain_effects {
        return prompted(
            "the previous run left uncertain effects; confirm the resume instead of replaying them",
        );
    }

    if !policy.auto {
        return refused("automatic resume is disabled; resume manually");
    }

    let attempt = context.attempts_used + 1;
    let delay = retry_delay_ms(policy, context.attempts_used);
    ResumePlan {
        decision: ResumeDecision::Auto,
        attempt: Some(ResumeAttempt {
            attempt,
            next_at_ms: now_ms.saturating_add(delay),
        }),
    }
}

/// A child that should resume with its root, keeping its own next time.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildTask {
    /// Goal, heartbeat, schedule, or subagent identifier.
    pub id: String,
    /// The child's preserved next time, when it has one. `None` for a goal or a
    /// subagent that has no timer.
    pub next_at_ms: Option<i64>,
}

impl ChildTask {
    /// A child without a timer (a goal or a subagent).
    pub fn new(id: impl Into<String>) -> Self {
        Self { id: id.into(), next_at_ms: None }
    }

    /// A timed child (a heartbeat or a schedule).
    pub fn scheduled(id: impl Into<String>, next_at_ms: i64) -> Self {
        Self { id: id.into(), next_at_ms: Some(next_at_ms) }
    }
}

/// The children a root session owns (AR-05).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumeChildren {
    pub goals: Vec<ChildTask>,
    pub heartbeats: Vec<ChildTask>,
    pub schedules: Vec<ChildTask>,
    pub subagents: Vec<ChildTask>,
}

impl ResumeChildren {
    /// Total number of children across all four kinds.
    pub fn len(&self) -> usize {
        self.goals.len() + self.heartbeats.len() + self.schedules.len() + self.subagents.len()
    }

    /// True when there is nothing to resume.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// What [`children_plan`] decided for the root's children.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChildrenResume {
    /// True only when the root plan is [`ResumeDecision::Auto`]. A prompt has
    /// not been approved yet, so children are not resumed.
    pub resumed: bool,
    /// Empty when resumed; otherwise why the children stay put.
    pub reason: String,
    /// Children to resume, each with its preserved next time. Empty unless
    /// `resumed`.
    pub goals: Vec<ChildTask>,
    pub heartbeats: Vec<ChildTask>,
    pub schedules: Vec<ChildTask>,
    pub subagents: Vec<ChildTask>,
}

impl ChildrenResume {
    /// Total number of children that will resume on this plan.
    pub fn len(&self) -> usize {
        self.goals.len() + self.heartbeats.len() + self.schedules.len() + self.subagents.len()
    }

    /// True when no child will resume.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Resume children only when the root itself resumes now (AR-05).
///
/// A refused, waiting, or merely prompted root resumes no child: a prompt is not
/// approval. Children keep their `next_at_ms`; a heartbeat or schedule is not
/// brought forward and a goal or subagent keeps its state.
pub fn children_plan(parent: &ResumePlan, children: ResumeChildren) -> ChildrenResume {
    match &parent.decision {
        ResumeDecision::Auto => ChildrenResume {
            resumed: true,
            reason: String::new(),
            goals: children.goals,
            heartbeats: children.heartbeats,
            schedules: children.schedules,
            subagents: children.subagents,
        },
        ResumeDecision::Prompt { .. } => ChildrenResume {
            resumed: false,
            reason: "the root resume is awaiting approval; children resume with it only after approval"
                .to_string(),
            ..ChildrenResume::default()
        },
        ResumeDecision::Refuse { reason } => ChildrenResume {
            resumed: false,
            reason: format!("the root resume was refused ({reason}); children do not resume"),
            ..ChildrenResume::default()
        },
        ResumeDecision::Wait { until_ms, .. } => ChildrenResume {
            resumed: false,
            reason: format!("the root resume waits until {until_ms}; children do not resume yet"),
            ..ChildrenResume::default()
        },
    }
}

fn retry_delay_ms(policy: ResumePolicy, retries_done: u32) -> i64 {
    if retries_done == 0 {
        return 0;
    }
    let cap = policy.max_backoff_ms.max(0);
    if cap == 0 {
        return 0;
    }
    let mut delay = policy.initial_backoff_ms.max(0).min(cap);
    let mut doublings = retries_done.saturating_sub(1);
    while doublings > 0 && delay > 0 && delay < cap {
        delay = delay.saturating_mul(2).min(cap);
        doublings -= 1;
    }
    delay
}

fn prompt_reason(base: &str, context: ResumeContext) -> String {
    if context.uncertain_effects {
        format!("{base}; the previous run left uncertain effects, which will not be replayed")
    } else {
        base.to_string()
    }
}

fn refused(reason: impl Into<String>) -> ResumePlan {
    ResumePlan { decision: ResumeDecision::Refuse { reason: reason.into() }, attempt: None }
}

fn prompted(reason: impl Into<String>) -> ResumePlan {
    ResumePlan { decision: ResumeDecision::Prompt { reason: reason.into() }, attempt: None }
}

fn wait(until_ms: i64, reason: impl Into<String>) -> ResumePlan {
    ResumePlan {
        decision: ResumeDecision::Wait { until_ms, reason: reason.into() },
        attempt: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_000_000;
    const BUDGET: u64 = 5_000_000;
    const RESET: i64 = NOW + 60_000;
    const MAX: u32 = 3;

    fn ctx(attempts_used: u32, budget_remaining_micros: u64) -> ResumeContext {
        ResumeContext {
            attempts_used,
            budget_remaining_micros,
            device_matches: true,
            usage_reset_ms: None,
            uncertain_effects: false,
        }
    }

    fn moved(mut context: ResumeContext) -> ResumeContext {
        context.device_matches = false;
        context
    }

    fn uncertain(mut context: ResumeContext) -> ResumeContext {
        context.uncertain_effects = true;
        context
    }

    fn reset_at(mut context: ResumeContext, reset_ms: i64) -> ResumeContext {
        context.usage_reset_ms = Some(reset_ms);
        context
    }

    fn no_auto() -> ResumePolicy {
        ResumePolicy { auto: false, ..ResumePolicy::default() }
    }

    fn no_device_prompt() -> ResumePolicy {
        ResumePolicy { device_prompt: false, ..ResumePolicy::default() }
    }

    fn no_budget_policy() -> ResumePolicy {
        ResumePolicy { budget_allowed: false, ..ResumePolicy::default() }
    }

    fn wide_attempts() -> ResumePolicy {
        ResumePolicy { max_attempts: 10, ..ResumePolicy::default() }
    }

    #[derive(Debug, Clone, Copy)]
    enum Expect {
        Auto,
        Prompt(&'static str),
        Refuse(&'static str),
        Wait { until_ms: i64, contains: &'static str },
    }

    #[derive(Debug, Clone)]
    struct Case {
        label: String,
        cause: ResumeCause,
        policy: ResumePolicy,
        context: ResumeContext,
        now_ms: i64,
        expect: Expect,
    }

    fn case(
        label: impl Into<String>,
        cause: ResumeCause,
        policy: ResumePolicy,
        context: ResumeContext,
        expect: Expect,
    ) -> Case {
        Case { label: label.into(), cause, policy, context, now_ms: NOW, expect }
    }

    fn check(case: &Case) {
        let plan = decide(case.cause, case.policy, case.context, case.now_ms);
        match (case.expect, &plan.decision) {
            (Expect::Auto, ResumeDecision::Auto) => {
                let attempt = plan
                    .attempt
                    .unwrap_or_else(|| panic!("{}: an Auto plan carries an attempt", case.label));
                assert_eq!(
                    attempt.attempt,
                    case.context.attempts_used + 1,
                    "{}: the attempt number counts from one",
                    case.label
                );
            }
            (Expect::Prompt(contains), ResumeDecision::Prompt { reason }) => {
                assert!(
                    reason.contains(contains),
                    "{}: expected prompt containing `{contains}`, got `{reason}`",
                    case.label
                );
            }
            (Expect::Refuse(contains), ResumeDecision::Refuse { reason }) => {
                assert!(
                    reason.contains(contains),
                    "{}: expected refusal containing `{contains}`, got `{reason}`",
                    case.label
                );
            }
            (Expect::Wait { until_ms, contains }, ResumeDecision::Wait { until_ms: actual, reason }) => {
                assert_eq!(actual, &until_ms, "{}: wait target", case.label);
                assert!(
                    reason.contains(contains),
                    "{}: expected wait containing `{contains}`, got `{reason}`",
                    case.label
                );
            }
            (expected, actual) => {
                panic!("{}: expected {expected:?}, got {actual:?}", case.label);
            }
        }
        if !plan.is_auto() {
            assert!(plan.attempt.is_none(), "{}: only Auto schedules an attempt", case.label);
        }
    }

    /// The Done criterion for T-AR-02: every cause against the policy states.
    #[test]
    fn resume_matrix_decisions() {
        let mut cases = Vec::new();

        // Every cause that can resume automatically shares this block.
        for cause in [
            ResumeCause::DaemonRestart,
            ResumeCause::Crash,
            ResumeCause::Reboot,
            ResumeCause::Disconnect,
        ] {
            let name = cause.as_str();
            cases.push(case(
                format!("{name}: first attempt on the same device"),
                cause,
                ResumePolicy::default(),
                ctx(0, BUDGET),
                Expect::Auto,
            ));
            cases.push(case(
                format!("{name}: attempt limit"),
                cause,
                ResumePolicy::default(),
                ctx(MAX, BUDGET),
                Expect::Refuse("attempt limit"),
            ));
            cases.push(case(
                format!("{name}: zero budget"),
                cause,
                ResumePolicy::default(),
                ctx(0, 0),
                Expect::Refuse("over budget"),
            ));
            cases.push(case(
                format!("{name}: zero budget with a known reset"),
                cause,
                ResumePolicy::default(),
                reset_at(ctx(0, 0), RESET),
                Expect::Wait { until_ms: RESET, contains: "waiting for the usage window" },
            ));
            cases.push(case(
                format!("{name}: device changed"),
                cause,
                ResumePolicy::default(),
                moved(ctx(0, BUDGET)),
                Expect::Prompt("device changed"),
            ));
            cases.push(case(
                format!("{name}: device changed without device prompts"),
                cause,
                no_device_prompt(),
                moved(ctx(0, BUDGET)),
                Expect::Refuse("device changed"),
            ));
            cases.push(case(
                format!("{name}: uncertain effects"),
                cause,
                ResumePolicy::default(),
                uncertain(ctx(0, BUDGET)),
                Expect::Prompt("uncertain effects"),
            ));
            cases.push(case(
                format!("{name}: automatic resume disabled"),
                cause,
                no_auto(),
                ctx(0, BUDGET),
                Expect::Refuse("automatic resume is disabled"),
            ));
        }

        // DeviceChanged never resumes silently.
        cases.push(case(
            "device_changed: same device flag still prompts",
            ResumeCause::DeviceChanged,
            ResumePolicy::default(),
            ctx(0, BUDGET),
            Expect::Prompt("device changed"),
        ));
        cases.push(case(
            "device_changed: device prompts disabled",
            ResumeCause::DeviceChanged,
            no_device_prompt(),
            ctx(0, BUDGET),
            Expect::Refuse("device changed"),
        ));
        cases.push(case(
            "device_changed: over budget",
            ResumeCause::DeviceChanged,
            ResumePolicy::default(),
            ctx(0, 0),
            Expect::Refuse("over budget"),
        ));
        cases.push(case(
            "device_changed: exhausted attempts outrank the prompt",
            ResumeCause::DeviceChanged,
            ResumePolicy::default(),
            moved(ctx(MAX, BUDGET)),
            Expect::Refuse("attempt limit"),
        ));
        cases.push(case(
            "device_changed: uncertain effects stay in the prompt",
            ResumeCause::DeviceChanged,
            ResumePolicy::default(),
            uncertain(ctx(0, BUDGET)),
            Expect::Prompt("uncertain effects"),
        ));
        cases.push(case(
            "device_changed: auto disabled does not silence the prompt",
            ResumeCause::DeviceChanged,
            no_auto(),
            ctx(0, BUDGET),
            Expect::Prompt("device changed"),
        ));

        // Teleport always prompts; device_prompt cannot silence it.
        cases.push(case(
            "teleport: always prompts",
            ResumeCause::Teleport,
            ResumePolicy::default(),
            ctx(0, BUDGET),
            Expect::Prompt("teleported"),
        ));
        cases.push(case(
            "teleport: prompts even without device prompts",
            ResumeCause::Teleport,
            no_device_prompt(),
            ctx(0, BUDGET),
            Expect::Prompt("teleported"),
        ));
        cases.push(case(
            "teleport: prompts even with auto disabled",
            ResumeCause::Teleport,
            no_auto(),
            ctx(0, BUDGET),
            Expect::Prompt("teleported"),
        ));
        cases.push(case(
            "teleport: over budget",
            ResumeCause::Teleport,
            ResumePolicy::default(),
            ctx(0, 0),
            Expect::Refuse("over budget"),
        ));
        cases.push(case(
            "teleport: exhausted attempts",
            ResumeCause::Teleport,
            ResumePolicy::default(),
            ctx(MAX, BUDGET),
            Expect::Refuse("attempt limit"),
        ));
        cases.push(case(
            "teleport: uncertain effects stay in the prompt",
            ResumeCause::Teleport,
            ResumePolicy::default(),
            uncertain(ctx(0, BUDGET)),
            Expect::Prompt("uncertain effects"),
        ));

        // UsageWindow waits for the reset instead of resuming.
        cases.push(case(
            "usage_window: waits for the reset",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(0, BUDGET), RESET),
            Expect::Wait { until_ms: RESET, contains: "usage window is open" },
        ));
        cases.push(case(
            "usage_window: waits even with zero budget",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(0, 0), RESET),
            Expect::Wait { until_ms: RESET, contains: "usage window is open" },
        ));
        cases.push(case(
            "usage_window: no known reset",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            ctx(0, BUDGET),
            Expect::Refuse("without a known reset"),
        ));
        cases.push(case(
            "usage_window: no reset and no budget",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            ctx(0, 0),
            Expect::Refuse("over budget"),
        ));
        cases.push(case(
            "usage_window: reset reached resumes",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(0, BUDGET), NOW),
            Expect::Auto,
        ));
        cases.push(case(
            "usage_window: reset reached over budget",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(0, 0), NOW),
            Expect::Refuse("over budget"),
        ));
        cases.push(case(
            "usage_window: automatic resume disabled",
            ResumeCause::UsageWindow,
            no_auto(),
            reset_at(ctx(0, BUDGET), RESET),
            Expect::Refuse("automatic resume is disabled"),
        ));
        cases.push(case(
            "usage_window: reset reached on another device",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(moved(ctx(0, BUDGET)), NOW),
            Expect::Prompt("device changed"),
        ));
        cases.push(case(
            "usage_window: reset reached with uncertain effects",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(uncertain(ctx(0, BUDGET)), NOW),
            Expect::Prompt("uncertain effects"),
        ));
        cases.push(case(
            "usage_window: exhausted attempts",
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(MAX, BUDGET), RESET),
            Expect::Refuse("attempt limit"),
        ));

        // Policy gates outrank every cause.
        cases.push(case(
            "budget policy veto",
            ResumeCause::DaemonRestart,
            no_budget_policy(),
            ctx(0, BUDGET),
            Expect::Refuse("budget policy"),
        ));
        cases.push(case(
            "budget policy veto outranks a usage wait",
            ResumeCause::UsageWindow,
            no_budget_policy(),
            reset_at(ctx(0, BUDGET), RESET),
            Expect::Refuse("budget policy"),
        ));

        for case in &cases {
            check(case);
        }
        assert_eq!(cases.len(), 56, "matrix covers every cause and policy state");
    }

    #[test]
    fn backoff_grows_exponentially_and_is_capped() {
        let policy = ResumePolicy {
            max_attempts: 10,
            initial_backoff_ms: 1_000,
            max_backoff_ms: 3_000,
            ..ResumePolicy::default()
        };
        let expected = [(0, 0), (1, 1_000), (2, 2_000), (3, 3_000), (4, 3_000), (9, 3_000)];
        for (used, delay) in expected {
            let plan = decide(ResumeCause::DaemonRestart, policy, ctx(used, BUDGET), NOW);
            let attempt = plan.attempt.expect("auto");
            assert_eq!(attempt.attempt, used + 1, "attempt {used} of the policy");
            assert_eq!(attempt.next_at_ms, NOW + delay, "backoff after {used} attempt(s)");
        }
    }

    #[test]
    fn zero_negative_and_saturating_backoff_is_safe() {
        let zero = ResumePolicy { initial_backoff_ms: 0, max_backoff_ms: 0, ..wide_attempts() };
        for used in 0..4 {
            let attempt = decide(ResumeCause::Crash, zero, ctx(used, BUDGET), NOW).attempt.expect("auto");
            assert_eq!(attempt.next_at_ms, NOW, "a zero backoff is immediate");
        }

        let negative =
            ResumePolicy { initial_backoff_ms: -5, max_backoff_ms: -1, ..wide_attempts() };
        let attempt =
            decide(ResumeCause::Crash, negative, ctx(1, BUDGET), NOW).attempt.expect("auto");
        assert_eq!(attempt.next_at_ms, NOW, "negative backoff is clamped to zero");

        let saturated = ResumePolicy {
            initial_backoff_ms: i64::MAX,
            max_backoff_ms: i64::MAX,
            ..wide_attempts()
        };
        let attempt =
            decide(ResumeCause::Crash, saturated, ctx(2, BUDGET), NOW).attempt.expect("auto");
        assert_eq!(attempt.next_at_ms, i64::MAX, "time addition saturates");
    }

    #[test]
    fn policy_defaults_are_safe() {
        let policy = ResumePolicy::default();
        assert!(policy.auto, "AR-02 resumes automatically by default");
        assert!(policy.device_prompt, "a device change prompts by default");
        assert_eq!(policy.max_attempts, 3);
        assert_eq!(policy.initial_backoff_ms, 1_000);
        assert_eq!(policy.max_backoff_ms, 60_000);
        assert!(policy.budget_allowed);
        assert!(ResumeCause::DaemonRestart.may_auto_resume());
        assert!(ResumeCause::UsageWindow.may_auto_resume());
        assert!(!ResumeCause::DeviceChanged.may_auto_resume());
        assert!(!ResumeCause::Teleport.may_auto_resume());
    }

    #[test]
    fn policy_and_plan_round_trip_through_json() {
        // A partial policy keeps every safe default.
        let policy: ResumePolicy = serde_json::from_str(r#"{"max_attempts":5}"#).unwrap();
        assert_eq!(policy.max_attempts, 5);
        assert!(policy.auto);
        assert!(policy.device_prompt);
        assert_eq!(policy.initial_backoff_ms, 1_000);
        assert_eq!(policy.max_backoff_ms, 60_000);
        assert!(policy.budget_allowed);

        let plan =
            decide(ResumeCause::DaemonRestart, ResumePolicy::default(), ctx(0, BUDGET), NOW);
        let text = serde_json::to_string(&plan).unwrap();
        let restored: ResumePlan = serde_json::from_str(&text).unwrap();
        assert_eq!(restored, plan, "a plan survives a journal round trip (AR-01)");

        let waiting = decide(
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(0, BUDGET), RESET),
            NOW,
        );
        assert_eq!(waiting.decision.until_ms(), Some(RESET));
        assert!(waiting.decision.reason().unwrap().contains("usage window"));
        let restored: ResumePlan =
            serde_json::from_str(&serde_json::to_string(&waiting).unwrap()).unwrap();
        assert_eq!(restored, waiting);
    }

    #[test]
    fn decisions_are_deterministic() {
        let policy = ResumePolicy::default();
        let context = ctx(1, BUDGET);
        let first = decide(ResumeCause::DaemonRestart, policy, context, NOW);
        let second = decide(ResumeCause::DaemonRestart, policy, context, NOW);
        assert_eq!(first, second);
    }

    fn children() -> ResumeChildren {
        ResumeChildren {
            goals: vec![ChildTask::new("goal-1")],
            heartbeats: vec![ChildTask::scheduled("hb-user", NOW + 5_000)],
            schedules: vec![ChildTask::scheduled("sch-1", NOW + 60_000)],
            subagents: vec![ChildTask::new("sub-1")],
        }
    }

    #[test]
    fn daemon_restart_resumes_children_with_their_times() {
        let parent = decide(ResumeCause::DaemonRestart, ResumePolicy::default(), ctx(0, BUDGET), NOW);
        assert!(parent.is_auto());
        let resumed = children_plan(&parent, children());
        assert!(resumed.resumed, "{resumed:?}");
        assert!(resumed.reason.is_empty());
        assert_eq!(resumed.len(), 4);
        assert_eq!(resumed.goals[0].next_at_ms, None);
        assert_eq!(resumed.heartbeats[0].id, "hb-user");
        assert_eq!(resumed.heartbeats[0].next_at_ms, Some(NOW + 5_000), "the next beat is preserved");
        assert_eq!(resumed.schedules[0].next_at_ms, Some(NOW + 60_000), "the next tick is preserved");
        assert_eq!(resumed.subagents[0].id, "sub-1");
    }

    #[test]
    fn device_change_prompts_and_does_not_resume_children_before_approval() {
        let parent = decide(ResumeCause::DeviceChanged, ResumePolicy::default(), ctx(0, BUDGET), NOW);
        assert!(parent.is_prompt(), "{parent:?}");
        let blocked = children_plan(&parent, children());
        assert!(!blocked.resumed, "a prompt is not approval");
        assert!(blocked.is_empty());
        assert!(blocked.reason.contains("approval"), "{}", blocked.reason);

        // Approval is a fresh decision with the device now matching; the root
        // resumes and the children follow with their original times.
        let approved =
            decide(ResumeCause::DaemonRestart, ResumePolicy::default(), ctx(0, BUDGET), NOW);
        let resumed = children_plan(&approved, children());
        assert!(resumed.resumed);
        assert_eq!(resumed.heartbeats[0].next_at_ms, Some(NOW + 5_000));
        assert_eq!(resumed.schedules[0].next_at_ms, Some(NOW + 60_000));
    }

    #[test]
    fn refused_and_waiting_parents_resume_no_children() {
        let refused = decide(ResumeCause::DaemonRestart, ResumePolicy::default(), ctx(MAX, BUDGET), NOW);
        assert!(refused.is_refused());
        let blocked = children_plan(&refused, children());
        assert!(!blocked.resumed);
        assert!(blocked.is_empty(), "a refused root never resumes a child");
        assert!(blocked.reason.contains("refused"), "{}", blocked.reason);

        let waiting = decide(
            ResumeCause::UsageWindow,
            ResumePolicy::default(),
            reset_at(ctx(0, BUDGET), RESET),
            NOW,
        );
        assert!(waiting.is_wait());
        let blocked = children_plan(&waiting, children());
        assert!(!blocked.resumed);
        assert!(blocked.is_empty());
        assert!(blocked.reason.contains("waits until"), "{}", blocked.reason);
    }

    #[test]
    fn an_auto_parent_with_no_children_is_still_auto() {
        let parent = decide(ResumeCause::Crash, ResumePolicy::default(), ctx(0, BUDGET), NOW);
        let resumed = children_plan(&parent, ResumeChildren::default());
        assert!(resumed.resumed);
        assert!(resumed.is_empty());
    }
}
