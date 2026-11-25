//! T-MM-04 live host computer use policy.
//!
//! Computer use has two targets: a [`Target::Sandbox`] (VM, container, or
//! virtual display) and the [`Target::LiveHost`] desktop. The live host is the
//! higher-risk class: every action is described by a [`ComputerAction`], the
//! policy matrix in [`authorize`] decides allow, ask, or deny, and
//! [`ask_prompt`] renders a deterministic approval prompt. The manual-mode
//! contract is explicit: on the live host, manual mode asks for every action,
//! including screenshots.
//!
//! This module is data and policy only. It never captures a screen, moves a
//! pointer, types, reads or writes a clipboard, launches or closes an
//! application, or talks to an operating-system input API. A caller executes an
//! action only after [`Decision::Allow`], or after a person answers an
//! [`AskView`]. Typed text is represented by its length ([`ComputerAction::text_len`]),
//! never by its content, so an approval prompt cannot leak a password or a
//! message body (MM-05, MM-07, MM-11).
//!
//! Allowlist entries are exact strings in one of two forms:
//!
//! - `<kind>` matches an action that has no `app` (the whole desktop);
//! - `<kind>:<app>` matches the same kind with exactly that `app`.
//!
//! `<kind>` is [`ActionKind::as_str`], for example `click`, `type`, or
//! `clipboard-write`. Matching is case-sensitive. A destructive action is never
//! silently allowed, even when it is listed.

use std::fmt;

use serde::{Deserialize, Serialize};

/// Where a computer action runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Target {
    /// A VM, container, or virtual display. This is the lower-risk class.
    Sandbox,
    /// The person's real desktop. This is the higher-risk class.
    LiveHost,
}

impl Target {
    /// Every target in deterministic order.
    pub const ALL: [Target; 2] = [Target::Sandbox, Target::LiveHost];

    /// Stable lowercase name used in prompts, JSON, and error messages.
    pub const fn as_str(self) -> &'static str {
        match self {
            Target::Sandbox => "sandbox",
            Target::LiveHost => "live-host",
        }
    }

    /// Whether this target is the live host desktop.
    pub const fn is_live_host(self) -> bool {
        matches!(self, Target::LiveHost)
    }
}

impl fmt::Display for Target {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One kind of computer action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionKind {
    Move,
    Click,
    DoubleClick,
    RightClick,
    Type,
    Key,
    Scroll,
    Drag,
    Screenshot,
    ClipboardRead,
    ClipboardWrite,
    LaunchApp,
    CloseWindow,
}

impl ActionKind {
    /// Every action kind in deterministic order.
    pub const ALL: [ActionKind; 13] = [
        ActionKind::Move,
        ActionKind::Click,
        ActionKind::DoubleClick,
        ActionKind::RightClick,
        ActionKind::Type,
        ActionKind::Key,
        ActionKind::Scroll,
        ActionKind::Drag,
        ActionKind::Screenshot,
        ActionKind::ClipboardRead,
        ActionKind::ClipboardWrite,
        ActionKind::LaunchApp,
        ActionKind::CloseWindow,
    ];

    /// Stable lowercase name used in prompts, JSON, and allowlist entries.
    pub const fn as_str(self) -> &'static str {
        match self {
            ActionKind::Move => "move",
            ActionKind::Click => "click",
            ActionKind::DoubleClick => "double-click",
            ActionKind::RightClick => "right-click",
            ActionKind::Type => "type",
            ActionKind::Key => "key",
            ActionKind::Scroll => "scroll",
            ActionKind::Drag => "drag",
            ActionKind::Screenshot => "screenshot",
            ActionKind::ClipboardRead => "clipboard-read",
            ActionKind::ClipboardWrite => "clipboard-write",
            ActionKind::LaunchApp => "launch-app",
            ActionKind::CloseWindow => "close-window",
        }
    }

    /// Whether the action only observes state and cannot change it.
    ///
    /// A screenshot reads pixels and a clipboard read reads text. Every other
    /// kind moves, types, launches, closes, or writes, so it is a side effect.
    pub const fn is_read_only(self) -> bool {
        matches!(self, ActionKind::Screenshot | ActionKind::ClipboardRead)
    }
}

impl fmt::Display for ActionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The risk of one action, before a mode is applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Risk {
    Low,
    Medium,
    High,
}

impl Risk {
    /// Stable lowercase name used in prompts, JSON, and documentation.
    pub const fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
        }
    }
}

impl fmt::Display for Risk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One computer action request.
///
/// `app` is the application the action targets, or `None` for the whole
/// desktop. `text_len` is the number of characters a [`ActionKind::Type`] action
/// would type; the text itself is never part of this value. `destructive` is the
/// caller's declaration that the action can delete, overwrite, close unsaved
/// work, or otherwise lose state.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComputerAction {
    pub kind: ActionKind,
    pub target: Target,
    pub app: Option<String>,
    pub text_len: Option<usize>,
    pub destructive: bool,
}

impl ComputerAction {
    /// Classify the action.
    ///
    /// A destructive declaration always raises the risk to [`Risk::High`]. On
    /// the live host every input, clipboard, launch, and close action is High;
    /// a screenshot is Medium because it exposes the screen without changing it.
    /// Sandbox actions are lower: pointer, key, scroll, drag, screenshot, and
    /// clipboard-read actions are Low; typing, clipboard writes, launches, and
    /// closes are Medium.
    pub fn risk(&self) -> Risk {
        if self.destructive {
            return Risk::High;
        }
        match self.target {
            Target::LiveHost => match self.kind {
                ActionKind::Screenshot => Risk::Medium,
                ActionKind::Move
                | ActionKind::Click
                | ActionKind::DoubleClick
                | ActionKind::RightClick
                | ActionKind::Type
                | ActionKind::Key
                | ActionKind::Scroll
                | ActionKind::Drag
                | ActionKind::ClipboardRead
                | ActionKind::ClipboardWrite
                | ActionKind::LaunchApp
                | ActionKind::CloseWindow => Risk::High,
            },
            Target::Sandbox => match self.kind {
                ActionKind::Move
                | ActionKind::Click
                | ActionKind::DoubleClick
                | ActionKind::RightClick
                | ActionKind::Key
                | ActionKind::Scroll
                | ActionKind::Drag
                | ActionKind::Screenshot
                | ActionKind::ClipboardRead => Risk::Low,
                ActionKind::Type
                | ActionKind::ClipboardWrite
                | ActionKind::LaunchApp
                | ActionKind::CloseWindow => Risk::Medium,
            },
        }
    }

    /// Whether the action only observes state.
    pub fn is_read_only(&self) -> bool {
        !self.destructive && self.kind.is_read_only()
    }

    /// The canonical allowlist entry for this action, when it has a usable app
    /// id. An empty or control-character app id cannot be allowlisted.
    pub fn allowlist_entry(&self) -> Option<String> {
        match self.app.as_deref() {
            None => Some(self.kind.as_str().to_string()),
            Some(app) => safe_app(app).map(|app| format!("{}:{app}", self.kind.as_str())),
        }
    }
}

/// The mode that supplies the policy matrix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PolicyMode {
    Plan,
    Manual,
    SemiAuto,
    Auto,
}

impl PolicyMode {
    /// Every policy mode in deterministic order.
    pub const ALL: [PolicyMode; 4] = [
        PolicyMode::Plan,
        PolicyMode::Manual,
        PolicyMode::SemiAuto,
        PolicyMode::Auto,
    ];

    /// Stable lowercase name used in prompts and JSON.
    pub const fn as_str(self) -> &'static str {
        match self {
            PolicyMode::Plan => "plan",
            PolicyMode::Manual => "manual",
            PolicyMode::SemiAuto => "semi-auto",
            PolicyMode::Auto => "auto",
        }
    }
}

impl fmt::Display for PolicyMode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The policy verdict for one action.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum Decision {
    /// The action may run.
    Allow,
    /// A person must answer yes or no before the action runs.
    Ask { reason: String },
    /// The action must not run.
    Deny { reason: String },
}

impl Decision {
    /// Whether the action may run without a person answering.
    pub fn is_allow(&self) -> bool {
        matches!(self, Decision::Allow)
    }

    /// Whether a person must answer.
    pub fn is_ask(&self) -> bool {
        matches!(self, Decision::Ask { .. })
    }

    /// Whether the action must not run.
    pub fn is_deny(&self) -> bool {
        matches!(self, Decision::Deny { .. })
    }

    /// The ask or deny reason, when there is one.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Decision::Allow => None,
            Decision::Ask { reason } | Decision::Deny { reason } => Some(reason.as_str()),
        }
    }
}

/// The deterministic approval prompt for one action.
///
/// It names the action, target, and app, and carries a reason. It has no field
/// for typed or clipboard text, so a caller cannot accidentally render a
/// secret. For a typing action the reason reports the character count only.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AskView {
    pub action: ActionKind,
    pub target: Target,
    pub app: Option<String>,
    pub reason: String,
}

impl AskView {
    /// Render the prompt as fixed lines. The same view always renders the same
    /// bytes, and no typed or clipboard content can appear.
    pub fn render(&self) -> String {
        let app = match self.app.as_deref() {
            Some(app) if safe_app(app).is_some() => app,
            Some(_) => "(invalid app id)",
            None => "(whole desktop)",
        };
        format!(
            "Computer use approval\n\
             action: {}\n\
             target: {}\n\
             app: {app}\n\
             reason: {}\n\
             answer: yes or no. Typed text and clipboard contents are never shown.",
            self.action.as_str(),
            self.target.as_str(),
            self.reason
        )
    }
}

impl fmt::Display for AskView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.render())
    }
}

/// Apply the policy matrix to one action.
///
/// | Target | Plan | Manual | Semi-auto / Auto |
/// |---|---|---|---|
/// | live host | deny | ask every action, including screenshots | ask unless the exact kind and app are allowlisted |
/// | sandbox | allow screenshots and clipboard reads; deny side effects | allow low and medium; ask destructive | allow low and medium; ask destructive |
///
/// On the live host a destructive action always asks, and a clipboard read
/// always asks, even when the allowlist names it. There is no agent path that
/// bypasses either check: they run before the allowlist comparison.
pub fn authorize(action: &ComputerAction, mode: PolicyMode, allowlist: &[String]) -> Decision {
    match action.target {
        Target::LiveHost => authorize_live_host(action, mode, allowlist),
        Target::Sandbox => authorize_sandbox(action, mode),
    }
}

/// Build the deterministic approval prompt for one action.
///
/// The returned [`AskView`] describes the action without its typed or clipboard
/// content. It does not depend on a mode, an allowlist, or a clock, so the same
/// action always produces the same view and the same rendered text.
pub fn ask_prompt(action: &ComputerAction) -> AskView {
    AskView {
        action: action.kind,
        target: action.target,
        app: action.app.clone(),
        reason: prompt_reason(action),
    }
}

fn authorize_live_host(
    action: &ComputerAction,
    mode: PolicyMode,
    allowlist: &[String],
) -> Decision {
    match mode {
        PolicyMode::Plan => Decision::Deny {
            reason: action_reason(action, "plan mode denies every live host action"),
        },
        PolicyMode::Manual => Decision::Ask {
            reason: action_reason(
                action,
                "manual mode asks for every live host action, including screenshots",
            ),
        },
        PolicyMode::SemiAuto | PolicyMode::Auto => {
            if action.destructive {
                return Decision::Ask {
                    reason: action_reason(
                        action,
                        "a destructive live host action always asks and is never silently allowed",
                    ),
                };
            }
            if action.kind == ActionKind::ClipboardRead {
                return Decision::Ask {
                    reason: action_reason(action, "a clipboard read on the live host always asks"),
                };
            }
            if is_allowlisted(action, allowlist) {
                return Decision::Allow;
            }
            Decision::Ask {
                reason: action_reason(
                    action,
                    "the action is not on the live host allowlist at this exact kind and app",
                ),
            }
        }
    }
}

fn authorize_sandbox(action: &ComputerAction, mode: PolicyMode) -> Decision {
    if mode == PolicyMode::Plan {
        if action.is_read_only() {
            Decision::Allow
        } else {
            Decision::Deny {
                reason: action_reason(action, "plan mode denies sandbox side effects"),
            }
        }
    } else if action.destructive {
        Decision::Ask {
            reason: action_reason(
                action,
                "a destructive sandbox action asks instead of being silently allowed",
            ),
        }
    } else {
        Decision::Allow
    }
}

fn is_allowlisted(action: &ComputerAction, allowlist: &[String]) -> bool {
    let Some(entry) = action.allowlist_entry() else {
        return false;
    };
    allowlist.iter().any(|allowed| allowed == &entry)
}

fn prompt_reason(action: &ComputerAction) -> String {
    let mut reason = format!(
        "a {} action on the {} has {} risk and requires explicit approval",
        action.kind.as_str(),
        action.target.as_str(),
        action.risk().as_str()
    );
    if action.destructive {
        reason.push_str("; it is declared destructive");
    }
    if action.kind == ActionKind::Type {
        if let Some(len) = action.text_len {
            reason.push_str(&format!(
                "; {len} characters would be typed and their content is withheld"
            ));
        }
    }
    if action.kind == ActionKind::ClipboardRead {
        reason.push_str("; clipboard contents are not included in this prompt");
    }
    reason
}

fn action_reason(action: &ComputerAction, detail: &str) -> String {
    let mut reason = format!(
        "{detail}: `{}` on the {}",
        action.kind.as_str(),
        action.target.as_str()
    );
    if let Some(app) = action.app.as_deref() {
        if let Some(app) = safe_app(app) {
            reason.push_str(&format!(" in `{app}`"));
        } else if !app.trim().is_empty() {
            reason.push_str(" in an invalid app id");
        }
    }
    if action.kind == ActionKind::Type {
        if let Some(len) = action.text_len {
            reason.push_str(&format!(" ({len} characters; content withheld)"));
        }
    }
    reason
}

/// An app id that is safe to print: non-empty and free of control characters.
fn safe_app(app: &str) -> Option<&str> {
    if app.trim().is_empty() || app.chars().any(char::is_control) {
        None
    } else {
        Some(app)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn action(kind: ActionKind, target: Target, app: Option<&str>) -> ComputerAction {
        ComputerAction {
            kind,
            target,
            app: app.map(str::to_string),
            text_len: None,
            destructive: false,
        }
    }

    fn live(kind: ActionKind) -> ComputerAction {
        action(kind, Target::LiveHost, Some("com.example.app"))
    }

    fn sandbox(kind: ActionKind) -> ComputerAction {
        action(kind, Target::Sandbox, Some("com.example.app"))
    }

    fn allowlist(entries: &[&str]) -> Vec<String> {
        entries.iter().map(|entry| (*entry).to_string()).collect()
    }

    #[test]
    fn manual_mode_asks_for_every_live_host_action() {
        // T-MM-04 Done: manual mode asks for every live host action, and a
        // screenshot is included because it is still live host privacy.
        for kind in ActionKind::ALL {
            let mut action = live(kind);
            if kind == ActionKind::Type {
                action.text_len = Some(12);
            }
            let decision = authorize(&action, PolicyMode::Manual, &[]);
            assert!(
                decision.is_ask(),
                "manual mode must ask for live host `{}`: {decision:?}",
                kind.as_str()
            );
        }

        let screenshot = live(ActionKind::Screenshot);
        let decision = authorize(&screenshot, PolicyMode::Manual, &allowlist(&["screenshot"]));
        assert!(
            decision.is_ask(),
            "manual mode asks for a live host screenshot even when it is allowlisted"
        );
        assert!(decision
            .reason()
            .expect("an ask carries a reason")
            .contains("including screenshots"));
    }

    #[test]
    fn live_host_plan_denies_every_action_and_ignores_the_allowlist() {
        for kind in ActionKind::ALL {
            let decision = authorize(
                &live(kind),
                PolicyMode::Plan,
                &allowlist(&[kind.as_str(), &format!("{}:com.example.app", kind.as_str())]),
            );
            assert!(
                decision.is_deny(),
                "plan mode must deny live host `{}`: {decision:?}",
                kind.as_str()
            );
        }
    }

    #[test]
    fn allowlisted_non_destructive_action_is_allowed_in_auto_and_semi_auto() {
        let click = live(ActionKind::Click);
        let entries = allowlist(&["click:com.example.app"]);
        for mode in [PolicyMode::SemiAuto, PolicyMode::Auto] {
            let decision = authorize(&click, mode, &entries);
            assert!(
                decision.is_allow(),
                "{mode} must allow an exact allowlisted non-destructive action: {decision:?}"
            );
        }

        // The exact entry is case-sensitive and app-specific.
        assert!(authorize(&click, PolicyMode::Auto, &allowlist(&["click"])).is_ask());
        assert!(authorize(
            &click,
            PolicyMode::Auto,
            &allowlist(&["Click:com.example.app"])
        )
        .is_ask());
        assert!(authorize(
            &click,
            PolicyMode::Auto,
            &allowlist(&["click:com.example.other"])
        )
        .is_ask());

        // A whole-desktop action needs the kind-only entry.
        let desktop = action(ActionKind::Click, Target::LiveHost, None);
        assert!(authorize(&desktop, PolicyMode::Auto, &allowlist(&["click"])).is_allow());
        assert!(authorize(
            &desktop,
            PolicyMode::Auto,
            &allowlist(&["click:com.example.app"])
        )
        .is_ask());
    }

    #[test]
    fn destructive_action_still_asks_in_auto_even_when_allowlisted() {
        let mut click = live(ActionKind::Click);
        click.destructive = true;
        let entries = allowlist(&["click:com.example.app"]);
        for mode in [PolicyMode::Manual, PolicyMode::SemiAuto, PolicyMode::Auto] {
            let decision = authorize(&click, mode, &entries);
            assert!(
                decision.is_ask(),
                "{mode} must ask for a destructive action even when allowlisted: {decision:?}"
            );
        }

        let mut delete_window = live(ActionKind::CloseWindow);
        delete_window.destructive = true;
        assert!(authorize(&delete_window, PolicyMode::Auto, &entries).is_ask());
    }

    #[test]
    fn sandbox_allows_low_and_medium_actions_and_asks_destructive_ones() {
        for kind in ActionKind::ALL {
            let action = sandbox(kind);
            for mode in [PolicyMode::Manual, PolicyMode::SemiAuto, PolicyMode::Auto] {
                let decision = authorize(&action, mode, &[]);
                assert!(
                    decision.is_allow(),
                    "{mode} must allow a non-destructive sandbox `{}`: {decision:?}",
                    kind.as_str()
                );
            }

            let mut destructive = action;
            destructive.destructive = true;
            for mode in [PolicyMode::Manual, PolicyMode::SemiAuto, PolicyMode::Auto] {
                let decision = authorize(&destructive, mode, &[]);
                assert!(
                    decision.is_ask(),
                    "{mode} must ask for a destructive sandbox `{}`: {decision:?}",
                    kind.as_str()
                );
            }
        }
    }

    #[test]
    fn sandbox_plan_allows_reads_and_denies_side_effects() {
        for kind in ActionKind::ALL {
            let action = sandbox(kind);
            let decision = authorize(&action, PolicyMode::Plan, &[]);
            if kind.is_read_only() {
                assert!(
                    decision.is_allow(),
                    "plan mode must allow the sandbox read `{}`: {decision:?}",
                    kind.as_str()
                );
            } else {
                assert!(
                    decision.is_deny(),
                    "plan mode must deny the sandbox side effect `{}`: {decision:?}",
                    kind.as_str()
                );
            }
        }

        let mut destructive_read = sandbox(ActionKind::Screenshot);
        destructive_read.destructive = true;
        assert!(
            authorize(&destructive_read, PolicyMode::Plan, &[]).is_deny(),
            "a destructive screenshot is a side effect in plan mode"
        );
    }

    #[test]
    fn clipboard_read_on_the_live_host_always_asks() {
        let read = live(ActionKind::ClipboardRead);
        let entries = allowlist(&["clipboard-read:com.example.app"]);
        for mode in [PolicyMode::Manual, PolicyMode::SemiAuto, PolicyMode::Auto] {
            let decision = authorize(&read, mode, &entries);
            assert!(
                decision.is_ask(),
                "{mode} must ask for a live host clipboard read even when allowlisted: {decision:?}"
            );
        }
        assert!(authorize(&read, PolicyMode::Plan, &entries).is_deny());
    }

    #[test]
    fn risk_classification_matches_the_target() {
        for kind in ActionKind::ALL {
            let live_risk = live(kind).risk();
            if kind == ActionKind::Screenshot {
                assert_eq!(live_risk, Risk::Medium);
            } else {
                assert_eq!(
                    live_risk,
                    Risk::High,
                    "live host `{}` must be high risk",
                    kind.as_str()
                );
            }

            let sandbox_risk = sandbox(kind).risk();
            let expected = match kind {
                ActionKind::Move
                | ActionKind::Click
                | ActionKind::DoubleClick
                | ActionKind::RightClick
                | ActionKind::Key
                | ActionKind::Scroll
                | ActionKind::Drag
                | ActionKind::Screenshot
                | ActionKind::ClipboardRead => Risk::Low,
                ActionKind::Type
                | ActionKind::ClipboardWrite
                | ActionKind::LaunchApp
                | ActionKind::CloseWindow => Risk::Medium,
            };
            assert_eq!(sandbox_risk, expected, "sandbox `{}` risk", kind.as_str());

            let mut destructive = live(kind);
            destructive.destructive = true;
            assert_eq!(
                destructive.risk(),
                Risk::High,
                "destructive `{}` is always high risk",
                kind.as_str()
            );
        }
    }

    #[test]
    fn an_unknown_app_is_not_allowlisted() {
        let click = action(ActionKind::Click, Target::LiveHost, Some("org.unknown.app"));
        let entries = allowlist(&["click:com.example.app", "click"]);
        let decision = authorize(&click, PolicyMode::Auto, &entries);
        assert!(
            decision.is_ask(),
            "an unknown app must not borrow another app's entry: {decision:?}"
        );

        let empty_app = action(ActionKind::Click, Target::LiveHost, Some("  "));
        assert_eq!(
            empty_app.allowlist_entry(),
            None,
            "an empty app id cannot be allowlisted"
        );
        assert!(authorize(&empty_app, PolicyMode::Auto, &allowlist(&["click"])).is_ask());

        let control_app = action(ActionKind::Click, Target::LiveHost, Some("bad\u{7}app"));
        assert_eq!(control_app.allowlist_entry(), None);
        let view = ask_prompt(&control_app);
        assert!(
            view.render().contains("app: (invalid app id)"),
            "an app id with a control character must not be rendered verbatim"
        );
        assert!(
            !view.render().contains('\u{7}'),
            "the rendered prompt must not contain the control character"
        );
    }

    #[test]
    fn ask_prompt_reports_lengths_and_never_typed_text() {
        let mut typing = live(ActionKind::Type);
        typing.text_len = Some(42);
        let view = ask_prompt(&typing);
        assert_eq!(view.action, ActionKind::Type);
        assert_eq!(view.target, Target::LiveHost);
        assert_eq!(view.app.as_deref(), Some("com.example.app"));
        assert!(view.reason.contains("42 characters"));
        assert!(view.reason.contains("content is withheld"));

        let rendered = view.render();
        assert!(rendered.contains("action: type"));
        assert!(rendered.contains("target: live-host"));
        assert!(rendered.contains("app: com.example.app"));
        assert!(rendered.contains("Typed text and clipboard contents are never shown."));

        // The view and the action have no field that can carry the text.
        let view_json = serde_json::to_value(&view).expect("serialize ask view");
        let view_object = view_json.as_object().expect("ask view is an object");
        assert!(!view_object.contains_key("text"));
        let action_json = serde_json::to_value(&typing).expect("serialize action");
        let action_object = action_json.as_object().expect("action is an object");
        assert!(!action_object.contains_key("text"));
        assert_eq!(action_object["text_len"], serde_json::json!(42));

        let clipboard = live(ActionKind::ClipboardRead);
        let view = ask_prompt(&clipboard);
        assert!(view.reason.contains("clipboard contents are not included"));
    }

    #[test]
    fn policy_and_prompts_are_deterministic_and_serializable() {
        let mut typing = live(ActionKind::Type);
        typing.text_len = Some(7);
        let entries = allowlist(&["type:com.example.app"]);

        for mode in PolicyMode::ALL {
            let first = authorize(&typing, mode, &entries);
            let second = authorize(&typing, mode, &entries);
            assert_eq!(first, second, "authorize must be deterministic in {mode}");
            let json = serde_json::to_string(&first).expect("serialize decision");
            let restored: Decision = serde_json::from_str(&json).expect("deserialize decision");
            assert_eq!(restored, first);
        }

        let first = ask_prompt(&typing);
        let second = ask_prompt(&typing);
        assert_eq!(first, second, "ask_prompt must be deterministic");
        assert_eq!(first.render(), second.render());
        assert_eq!(
            serde_json::to_string(&first).expect("serialize ask view"),
            serde_json::to_string(&second).expect("serialize ask view")
        );

        let allowed = authorize(&sandbox(ActionKind::Click), PolicyMode::Auto, &[]);
        assert!(allowed.is_allow());
        let json = serde_json::to_string(&allowed).expect("serialize allow");
        let restored: Decision = serde_json::from_str(&json).expect("deserialize allow");
        assert_eq!(restored, allowed, "the allow verdict round-trips");
    }

    #[test]
    fn allowlist_entry_uses_the_canonical_kind_and_exact_app() {
        assert_eq!(
            live(ActionKind::DoubleClick).allowlist_entry().as_deref(),
            Some("double-click:com.example.app")
        );
        assert_eq!(
            action(ActionKind::ClipboardWrite, Target::LiveHost, None)
                .allowlist_entry()
                .as_deref(),
            Some("clipboard-write")
        );
        assert_eq!(
            sandbox(ActionKind::CloseWindow)
                .allowlist_entry()
                .as_deref(),
            Some("close-window:com.example.app")
        );
    }

    #[test]
    fn no_action_executes() {
        // The production half is policy data only. It must not reach an
        // operating-system input, clipboard, process, or network API.
        let source = include_str!("computer_use.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("computer_use.rs has a production half");
        for needle in [
            "std::process",
            "std::net",
            "std::fs",
            "Command::new",
            "TcpStream",
            "UdpSocket",
            "reqwest",
            "hyper",
            "ureq",
            "SendInput",
            "CGEvent",
            "CGDisplay",
            "xdotool",
            "enigo",
            "OpenProcess",
            "CreateProcess",
            "ShellExecute",
            "NtUserSendInput",
            "fn execute",
            "fn capture",
            "fn click",
            "fn type_text",
            "fn read_clipboard",
            "fn write_clipboard",
        ] {
            assert!(
                !production.contains(needle),
                "`{needle}` must not appear in the computer use module; it is policy data only"
            );
        }
    }
}
