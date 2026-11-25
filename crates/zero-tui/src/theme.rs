//! Theme token model (TUI-12): every visual role is a named, overridable token
//! with a 256-colour default.

use crate::style::Color;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Token {
    Background,
    Foreground,
    Muted,
    Border,
    Accent,
    Success,
    Warning,
    Danger,
    Info,
    ModePlan,
    ModeManual,
    ModeSemi,
    ModeAuto,
    ModeHeadless,
    UserMessage,
    AssistantMessage,
    ToolMessage,
    Thinking,
    Code,
    CodeBackground,
    Selection,
    StatusBar,
    StatusBarText,
    Queue,
    Approval,
    Secret,
    DiffAdd,
    DiffRemove,
    DiffContext,
}

impl Token {
    pub const ALL: [Token; 29] = [
        Token::Background,
        Token::Foreground,
        Token::Muted,
        Token::Border,
        Token::Accent,
        Token::Success,
        Token::Warning,
        Token::Danger,
        Token::Info,
        Token::ModePlan,
        Token::ModeManual,
        Token::ModeSemi,
        Token::ModeAuto,
        Token::ModeHeadless,
        Token::UserMessage,
        Token::AssistantMessage,
        Token::ToolMessage,
        Token::Thinking,
        Token::Code,
        Token::CodeBackground,
        Token::Selection,
        Token::StatusBar,
        Token::StatusBarText,
        Token::Queue,
        Token::Approval,
        Token::Secret,
        Token::DiffAdd,
        Token::DiffRemove,
        Token::DiffContext,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            Token::Background => "background",
            Token::Foreground => "foreground",
            Token::Muted => "muted",
            Token::Border => "border",
            Token::Accent => "accent",
            Token::Success => "success",
            Token::Warning => "warning",
            Token::Danger => "danger",
            Token::Info => "info",
            Token::ModePlan => "mode_plan",
            Token::ModeManual => "mode_manual",
            Token::ModeSemi => "mode_semi",
            Token::ModeAuto => "mode_auto",
            Token::ModeHeadless => "mode_headless",
            Token::UserMessage => "user_message",
            Token::AssistantMessage => "assistant_message",
            Token::ToolMessage => "tool_message",
            Token::Thinking => "thinking",
            Token::Code => "code",
            Token::CodeBackground => "code_background",
            Token::Selection => "selection",
            Token::StatusBar => "status_bar",
            Token::StatusBarText => "status_bar_text",
            Token::Queue => "queue",
            Token::Approval => "approval",
            Token::Secret => "secret",
            Token::DiffAdd => "diff_add",
            Token::DiffRemove => "diff_remove",
            Token::DiffContext => "diff_context",
        }
    }

    pub fn parse(name: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|t| t.as_str() == name)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Theme {
    pub name: String,
    colors: BTreeMap<Token, Color>,
}

impl Default for Theme {
    fn default() -> Self {
        Self::dark()
    }
}

impl Theme {
    pub fn dark() -> Self {
        use Token::*;
        let entries = [
            (Background, 234),
            (Foreground, 252),
            (Muted, 244),
            (Border, 240),
            (Accent, 75),
            (Success, 78),
            (Warning, 214),
            (Danger, 203),
            (Info, 81),
            (ModePlan, 111),
            (ModeManual, 180),
            (ModeSemi, 114),
            (ModeAuto, 78),
            (ModeHeadless, 141),
            (UserMessage, 117),
            (AssistantMessage, 252),
            (ToolMessage, 246),
            (Thinking, 240),
            (Code, 223),
            (CodeBackground, 236),
            (Selection, 60),
            (StatusBar, 236),
            (StatusBarText, 250),
            (Queue, 215),
            (Approval, 222),
            (Secret, 210),
            (DiffAdd, 78),
            (DiffRemove, 203),
            (DiffContext, 244),
        ];
        let colors = entries.into_iter().map(|(t, c)| (t, Color::Ansi(c))).collect();
        Self { name: "zero-dark".into(), colors }
    }

    pub fn color(&self, token: Token) -> Color {
        self.colors.get(&token).copied().unwrap_or(Color::Default)
    }

    pub fn set(&mut self, token: Token, color: Color) {
        self.colors.insert(token, color);
    }

    pub fn tokens(&self) -> impl Iterator<Item = (&Token, &Color)> {
        self.colors.iter()
    }

    /// Every token is present; a missing token would fall back silently.
    pub fn complete(&self) -> bool {
        Token::ALL.iter().all(|t| self.colors.contains_key(t))
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string_pretty(self).unwrap_or_default()
    }

    pub fn from_json(text: &str) -> Option<Self> {
        serde_json::from_str(text).ok().filter(|t: &Theme| t.complete())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_token_is_present_and_overridable() {
        let mut theme = Theme::dark();
        assert!(theme.complete());
        for token in Token::ALL {
            assert_eq!(theme.color(token), Color::Ansi(match token {
                Token::Background => 234,
                _ => match theme.color(token) {
                    Color::Ansi(n) => n,
                    other => panic!("{token:?} is not a 256-colour default: {other:?}"),
                },
            }));
            theme.set(token, Color::Ansi(123));
            assert_eq!(theme.color(token), Color::Ansi(123), "{token:?}");
        }
        assert!(theme.complete());
    }

    #[test]
    fn themes_round_trip_and_reject_incomplete_json() {
        let mut theme = Theme::dark();
        theme.set(Token::Accent, Color::Rgb(1, 2, 3));
        let json = theme.to_json();
        let back = Theme::from_json(&json).unwrap();
        assert_eq!(back.color(Token::Accent), Color::Rgb(1, 2, 3));
        assert!(Theme::from_json(r#"{"name":"x","colors":{}}"#).is_none());
    }

    #[test]
    fn token_names_are_unique_and_parseable() {
        let mut seen = std::collections::BTreeSet::new();
        for token in Token::ALL {
            assert!(seen.insert(token.as_str()), "duplicate token {}", token.as_str());
            assert_eq!(Token::parse(token.as_str()), Some(token));
        }
    }

    #[test]
    fn every_token_is_documented() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/themes.md"),
        )
        .expect("docs/themes.md");
        for token in Token::ALL {
            assert!(
                doc.contains(&format!("`{}`", token.as_str())),
                "docs/themes.md is missing `{}`",
                token.as_str()
            );
        }
    }
}
