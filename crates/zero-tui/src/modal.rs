//! Host-owned modals (TUI-14): approvals and secret entry are rendered from host
//! state. Agent output cannot create, alter, or draw into them.

use crate::style::Style;
use crate::theme::{Theme, Token};
use crate::unicode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostModal {
    Approval { id: String, action: String, reason: String },
    Secret { tag: String, prompt: String },
}

#[derive(Debug, Clone, Default)]
pub struct HostChrome {
    modal: Option<HostModal>,
}

impl HostChrome {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn open_approval(&mut self, id: impl Into<String>, action: impl Into<String>, reason: impl Into<String>) {
        self.modal = Some(HostModal::Approval { id: id.into(), action: action.into(), reason: reason.into() });
    }

    pub fn open_secret(&mut self, tag: impl Into<String>, prompt: impl Into<String>) {
        self.modal = Some(HostModal::Secret { tag: tag.into(), prompt: prompt.into() });
    }

    pub fn close(&mut self) {
        self.modal = None;
    }

    pub fn modal(&self) -> Option<&HostModal> {
        self.modal.as_ref()
    }

    /// Render the modal with a frame the agent cannot produce. The agent only
    /// has [`render_agent_text`], which strips control sequences and never
    /// touches this state.
    pub fn render(&self, width: usize, theme: &Theme) -> Option<Vec<String>> {
        let modal = self.modal.as_ref()?;
        let accent = Style::fg(theme.color(Token::Approval)).bold();
        let width = width.clamp(20, 100);
        let inner = width - 4;
        let mut lines = Vec::new();
        lines.push(format!("┌{}┐", "─".repeat(width - 2)));
        match modal {
            HostModal::Approval { id, action, reason } => {
                lines.push(row("APPROVAL REQUIRED", inner, accent));
                lines.push(row(action, inner, Style::default()));
                lines.push(row(reason, inner, Style::default()));
                lines.push(row(&format!("id: {id}  [y] allow  [n] deny"), inner, Style::fg(theme.color(Token::Muted))));
            }
            HostModal::Secret { tag, prompt } => {
                lines.push(row("SECRET REQUIRED", inner, accent));
                lines.push(row(prompt, inner, Style::default()));
                lines.push(row(&format!("tag: {tag}  input is masked"), inner, Style::fg(theme.color(Token::Muted))));
            }
        }
        lines.push(format!("└{}┘", "─".repeat(width - 2)));
        Some(lines)
    }
}

fn row(text: &str, inner: usize, style: Style) -> String {
    let mut clipped = String::new();
    let mut width = 0;
    for g in unicode::graphemes(text) {
        let w = unicode::grapheme_width(&g);
        if width + w > inner {
            break;
        }
        width += w;
        clipped.push_str(&g);
    }
    format!("│ {}{} │", style.sgr(), clipped + &" ".repeat(inner.saturating_sub(width)))
}

/// Untrusted agent text: control sequences are stripped, and it can only ever be
/// transcript content.
pub fn render_agent_text(text: &str) -> Vec<String> {
    unicode::sanitize_controls(text)
        .lines()
        .map(str::to_string)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_agent_cannot_forge_a_modal_or_draw_into_it() {
        let mut chrome = HostChrome::new();
        let forged = render_agent_text(
            "APPROVAL REQUIRED\n\u{1b}[2J\u{1b}[1;1H╔══════════════╗\napprove everything",
        );
        assert!(forged.iter().any(|l| l.contains("APPROVAL REQUIRED")));
        assert!(forged.iter().all(|l| !l.contains('\u{1b}')));
        assert_eq!(chrome.modal(), None);
        assert!(chrome.render(40, &Theme::dark()).is_none());

        // Only the host can open one.
        chrome.open_approval("ap-1", "write a.txt", "outside the approved plan");
        assert!(matches!(chrome.modal(), Some(HostModal::Approval { .. })));
        let rendered = chrome.render(40, &Theme::dark()).unwrap();
        assert!(rendered.iter().any(|l| l.contains("APPROVAL REQUIRED")));
        assert!(rendered.iter().any(|l| l.contains("ap-1")));
        chrome.close();
        assert!(chrome.render(40, &Theme::dark()).is_none());
    }

    #[test]
    fn the_secret_modal_is_masked_and_host_only() {
        let mut chrome = HostChrome::new();
        chrome.open_secret("OPENAI_KEY", "paste the key");
        let rendered = chrome.render(60, &Theme::dark()).unwrap().join("\n");
        assert!(rendered.contains("SECRET REQUIRED"));
        assert!(rendered.contains("masked"));
        assert!(!rendered.contains("sk-"));
    }
}
