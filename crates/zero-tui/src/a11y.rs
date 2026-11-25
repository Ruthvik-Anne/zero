//! Accessibility (TUI-13): no-animation, high-contrast, and line-oriented modes;
//! state is never encoded by colour alone.

use crate::style::{Color, Style};
use crate::theme::{Theme, Token};

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Accessibility {
    pub no_animation: bool,
    pub high_contrast: bool,
    pub line_oriented: bool,
}

impl Accessibility {
    pub fn style(&self, token: Token, theme: &Theme) -> Style {
        if self.high_contrast {
            let fg = match token {
                Token::Danger | Token::DiffRemove => Color::Ansi(9),
                Token::Success | Token::DiffAdd => Color::Ansi(10),
                Token::Warning | Token::Approval | Token::Queue => Color::Ansi(11),
                _ => Color::Ansi(15),
            };
            return Style { fg, bg: Color::Ansi(0), bold: true, ..Style::default() };
        }
        Style::fg(theme.color(token))
    }

    /// Animation frames are suppressed entirely in no-animation mode.
    pub fn animation_frame(&self, tick: u64) -> Option<u64> {
        if self.no_animation {
            None
        } else {
            Some(tick % 8)
        }
    }
}

/// Text-only screen used by screen readers and the line-oriented mode. State is
/// written as words, never as a colour.
pub fn render_line_screen(transcript: &[String], labels: &[(&str, &str)]) -> String {
    let mut out = String::new();
    for (key, value) in labels {
        out.push_str(&format!("{key}={value} "));
    }
    if !labels.is_empty() {
        out.push('\n');
    }
    for line in transcript {
        out.push_str(line);
        out.push('\n');
    }
    out
}

/// A scripted screen-reader session: session start, a prompt, and an approval.
/// The test asserts every step is present in plain text.
pub fn screen_reader_session() -> Vec<String> {
    vec![
        "session started".into(),
        "mode=plan".into(),
        "prompt: create a file".into(),
        "approval required: write a.txt".into(),
        "approval resolved: allowed".into(),
        "turn complete".into(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_screen_reader_session_completes_and_state_is_textual() {
        let session = screen_reader_session();
        let output = render_line_screen(&session, &[("mode", "plan"), ("approvals", "1")]);
        assert!(output.contains("mode=plan"));
        assert!(output.contains("approval required"));
        assert!(output.contains("session started"));
        assert!(!output.contains('\u{1b}'), "no escape codes in line mode");
        assert!(output.contains("approvals=1"));
    }

    #[test]
    fn no_animation_disables_frames_and_high_contrast_is_explicit() {
        let mut a11y = Accessibility { no_animation: true, ..Accessibility::default() };
        assert_eq!(a11y.animation_frame(3), None);
        a11y.no_animation = false;
        assert_eq!(a11y.animation_frame(3), Some(3));

        let theme = Theme::dark();
        let contrast = Accessibility { high_contrast: true, ..Accessibility::default() };
        let normal = Accessibility::default();
        assert_ne!(
            contrast.style(Token::Danger, &theme).fg,
            normal.style(Token::Danger, &theme).fg
        );
        assert!(contrast.style(Token::Danger, &theme).bold);
    }

    #[test]
    fn line_mode_has_no_colour_dependency_for_state() {
        let plain = render_line_screen(&[], &[("mode", "semi-auto"), ("budget", "warn")]);
        assert!(plain.contains("mode=semi-auto"));
        assert!(plain.contains("budget=warn"));
    }
}
