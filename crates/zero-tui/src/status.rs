//! Status bar (TUI-15): mode, model, budget, queue, and pending approvals, with
//! no overstatement of completion.

use crate::theme::{Theme, Token};
use crate::unicode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StatusModel {
    pub mode: String,
    pub model: String,
    pub budget: Option<(u64, u64)>,
    pub queue_depth: usize,
    pub pending_approvals: usize,
    pub busy: bool,
}

impl Default for StatusModel {
    fn default() -> Self {
        Self {
            mode: "plan".into(),
            model: "auto".into(),
            budget: None,
            queue_depth: 0,
            pending_approvals: 0,
            busy: false,
        }
    }
}

impl StatusModel {
    pub fn budget_label(&self) -> String {
        match self.budget {
            None => "budget: none".into(),
            Some((spent, limit)) if spent >= limit => format!("budget: STOPPED {spent}/{limit}"),
            Some((spent, limit)) if spent * 10 >= limit * 8 => format!("budget: WARN {spent}/{limit}"),
            Some((spent, limit)) => format!("budget: {spent}/{limit}"),
        }
    }

    /// Plain text segments; colour is additive, never the only signal.
    pub fn segments(&self) -> Vec<String> {
        vec![
            format!("mode: {}", self.mode),
            format!("model: {}", self.model),
            self.budget_label(),
            format!("queue: {}", self.queue_depth),
            format!("approvals: {}", self.pending_approvals),
            if self.busy { "state: working".into() } else { "state: idle".into() },
        ]
    }

    pub fn render(&self, width: usize) -> String {
        let mut line = self.segments().join("  │  ");
        let w = unicode::width(&line);
        if w < width {
            line.push_str(&" ".repeat(width - w));
        } else if w > width {
            let mut out = String::new();
            let mut used = 0;
            for g in unicode::graphemes(&line) {
                let gw = unicode::grapheme_width(&g);
                if used + gw > width {
                    break;
                }
                used += gw;
                out.push_str(&g);
            }
            line = out;
        }
        line
    }

    pub fn token(&self) -> Token {
        match self.mode.as_str() {
            "plan" => Token::ModePlan,
            "manual" => Token::ModeManual,
            "semi-auto" => Token::ModeSemi,
            "auto" => Token::ModeAuto,
            "headless" => Token::ModeHeadless,
            _ => Token::StatusBarText,
        }
    }

    pub fn styled(&self, width: usize, theme: &Theme) -> String {
        format!("{}{}\u{1b}[0m", crate::style::Style::fg(theme.color(self.token())).sgr(), self.render(width))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_state_renders_its_facts_and_never_overstates() {
        let base = StatusModel::default();
        assert!(base.render(160).contains("mode: plan"));
        assert!(base.render(160).contains("budget: none"));
        assert!(base.render(160).contains("state: idle"));

        let busy = StatusModel { busy: true, queue_depth: 2, pending_approvals: 1, ..StatusModel::default() };
        let line = busy.render(120);
        assert!(line.contains("state: working"));
        assert!(line.contains("queue: 2"));
        assert!(line.contains("approvals: 1"), "pending approvals are visible");

        let warn = StatusModel { budget: Some((900, 1000)), ..StatusModel::default() };
        assert!(warn.render(80).contains("budget: WARN"));
        let stopped = StatusModel { budget: Some((1000, 1000)), ..StatusModel::default() };
        assert!(stopped.render(80).contains("budget: STOPPED"));
    }

    #[test]
    fn a_mode_change_is_visible_in_the_next_frame() {
        let mut status = StatusModel::default();
        let before = status.render(80);
        status.mode = "auto".into();
        let after = status.render(80);
        assert_ne!(before, after);
        assert!(after.contains("mode: auto"));
        assert_eq!(status.token(), Token::ModeAuto);
    }

    #[test]
    fn narrow_width_clips_on_a_grapheme_boundary() {
        let status = StatusModel::default();
        let line = status.render(12);
        assert!(unicode::width(&line) <= 12);
        assert!(!line.contains('\n'));
    }
}
