//! Cell styles and SGR encoding.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Color {
    Default,
    /// 256-colour palette index (0–255).
    Ansi(u8),
    Rgb(u8, u8, u8),
}

impl Color {
    fn fg_sgr(self) -> String {
        match self {
            Color::Default => "39".into(),
            Color::Ansi(0..=7) => format!("{}", 30 + self.index()),
            Color::Ansi(8..=15) => format!("{}", 90 + self.index() - 8),
            Color::Ansi(n) => format!("38;5;{n}"),
            Color::Rgb(r, g, b) => format!("38;2;{r};{g};{b}"),
        }
    }

    fn bg_sgr(self) -> String {
        match self {
            Color::Default => "49".into(),
            Color::Ansi(0..=7) => format!("{}", 40 + self.index()),
            Color::Ansi(8..=15) => format!("{}", 100 + self.index() - 8),
            Color::Ansi(n) => format!("48;5;{n}"),
            Color::Rgb(r, g, b) => format!("48;2;{r};{g};{b}"),
        }
    }

    fn index(self) -> u8 {
        match self {
            Color::Ansi(n) => n,
            _ => 0,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct Style {
    pub fg: Color,
    pub bg: Color,
    pub bold: bool,
    pub dim: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self {
            fg: Color::Default,
            bg: Color::Default,
            bold: false,
            dim: false,
            italic: false,
            underline: false,
            inverse: false,
        }
    }
}

impl Style {
    pub fn fg(color: Color) -> Self {
        Self { fg: color, ..Self::default() }
    }

    pub fn bold(mut self) -> Self {
        self.bold = true;
        self
    }

    pub fn dim(mut self) -> Self {
        self.dim = true;
        self
    }

    pub fn italic(mut self) -> Self {
        self.italic = true;
        self
    }

    pub fn underline(mut self) -> Self {
        self.underline = true;
        self
    }

    pub fn inverse(mut self) -> Self {
        self.inverse = true;
        self
    }

    /// Full SGR sequence including a reset, so a run never inherits state.
    pub fn sgr(&self) -> String {
        let mut codes: Vec<String> = vec!["0".into(), self.fg.fg_sgr(), self.bg.bg_sgr()];
        if self.bold {
            codes.push("1".into());
        }
        if self.dim {
            codes.push("2".into());
        }
        if self.italic {
            codes.push("3".into());
        }
        if self.underline {
            codes.push("4".into());
        }
        if self.inverse {
            codes.push("7".into());
        }
        format!("\u{1b}[{}m", codes.join(";"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ansi_and_rgb_encoding() {
        assert_eq!(Color::Ansi(1).fg_sgr(), "31");
        assert_eq!(Color::Ansi(9).fg_sgr(), "91");
        assert_eq!(Color::Ansi(200).fg_sgr(), "38;5;200");
        assert_eq!(Color::Ansi(200).bg_sgr(), "48;5;200");
        assert_eq!(Color::Rgb(1, 2, 3).fg_sgr(), "38;2;1;2;3");
        assert_eq!(Color::Default.bg_sgr(), "49");
    }

    #[test]
    fn sgr_always_resets_first() {
        let style = Style::fg(Color::Ansi(4)).bold().underline();
        assert_eq!(style.sgr(), "\u{1b}[0;34;49;1;4m");
    }
}
