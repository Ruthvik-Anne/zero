//! Screen with front/back buffers and a changed-run diff emitter (TUI-02).

use crate::buffer::Buffer;
use crate::style::Style;

pub const SYNC_ON: &str = "\u{1b}[?2026h";
pub const SYNC_OFF: &str = "\u{1b}[?2026l";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Run {
    pub x: usize,
    pub y: usize,
    pub text: String,
    pub style: Style,
}

pub struct Screen {
    width: usize,
    height: usize,
    front: Buffer,
    back: Buffer,
    /// Emit synchronized-output markers when the terminal supports them.
    pub synchronized: bool,
}

impl Screen {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            front: Buffer::new(width, height),
            back: Buffer::new(width, height),
            synchronized: true,
        }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        self.width = width;
        self.height = height;
        self.front.resize(width, height);
        self.back.resize(width, height);
    }

    pub fn back_mut(&mut self) -> &mut Buffer {
        &mut self.back
    }

    pub fn back(&self) -> &Buffer {
        &self.back
    }

    pub fn front(&self) -> &Buffer {
        &self.front
    }

    pub fn clear_back(&mut self) {
        self.back.clear();
    }

    pub fn check_invariants(&self) -> Result<(), crate::buffer::InvariantError> {
        self.back.check_invariants()?;
        self.front.check_invariants()
    }

    /// Changed runs between front and back, left to right, top to bottom.
    pub fn diff_runs(&self) -> Vec<Run> {
        let mut runs = Vec::new();
        for y in 0..self.height {
            let mut x = 0;
            while x < self.width {
                let cell = self.back.cell(x, y);
                if cell.continuation {
                    x += 1;
                    continue;
                }
                let width = cell.width as usize;
                let front_main = self.front.cell(x, y);
                let mut changed = front_main != cell;
                if width == 2 && x + 1 < self.width {
                    changed |= self.front.cell(x + 1, y) != self.back.cell(x + 1, y);
                }
                if !changed {
                    x += width.max(1);
                    continue;
                }
                let mut run = Run { x, y, text: cell.symbol.clone(), style: cell.style };
                if run.text.is_empty() {
                    run.text = " ".into();
                }
                let mut next = x + width.max(1);
                // Extend while adjacent cells changed with the same style.
                while next < self.width {
                    let candidate = self.back.cell(next, y);
                    if candidate.continuation {
                        next += 1;
                        continue;
                    }
                    let candidate_width = candidate.width as usize;
                    let mut candidate_changed = self.front.cell(next, y) != candidate;
                    if candidate_width == 2 && next + 1 < self.width {
                        candidate_changed |= self.front.cell(next + 1, y) != self.back.cell(next + 1, y);
                    }
                    if !candidate_changed || candidate.style != run.style {
                        break;
                    }
                    run.text.push_str(if candidate.symbol.is_empty() { " " } else { &candidate.symbol });
                    next += candidate_width.max(1);
                }
                runs.push(run);
                x = next;
            }
        }
        runs
    }

    /// Emit only changed runs, wrapped in synchronized output when enabled.
    pub fn present(&mut self) -> String {
        let runs = self.diff_runs();
        if runs.is_empty() {
            self.front = self.back.clone();
            return String::new();
        }
        let out = self.emit(&runs);
        self.front = self.back.clone();
        out
    }

    /// Full repaint used as the declared fallback.
    pub fn redraw(&mut self) -> String {
        let mut runs = Vec::new();
        for y in 0..self.height {
            let mut x = 0;
            while x < self.width {
                let cell = self.back.cell(x, y);
                if cell.continuation {
                    x += 1;
                    continue;
                }
                let style = cell.style;
                let mut text = if cell.symbol.is_empty() { " ".to_string() } else { cell.symbol.clone() };
                let mut next = x + (cell.width as usize).max(1);
                while next < self.width {
                    let candidate = self.back.cell(next, y);
                    if candidate.continuation {
                        next += 1;
                        continue;
                    }
                    if candidate.style != style {
                        break;
                    }
                    text.push_str(&candidate.symbol);
                    next += (candidate.width as usize).max(1);
                }
                runs.push(Run { x, y, text, style });
                x = next;
            }
        }
        let mut out = String::from("\u{1b}[2J");
        out.push_str(&self.emit(&runs));
        self.front = self.back.clone();
        out
    }

    fn emit(&self, runs: &[Run]) -> String {
        let mut out = String::new();
        if self.synchronized {
            out.push_str(SYNC_ON);
        }
        for run in runs {
            out.push_str(&format!("\u{1b}[{};{}H", run.y + 1, run.x + 1));
            out.push_str(&run.style.sgr());
            out.push_str(&run.text);
        }
        out.push_str("\u{1b}[0m");
        if self.synchronized {
            out.push_str(SYNC_OFF);
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::{Color, Style};

    #[test]
    fn diff_emits_only_changed_runs_inside_synchronized_output() {
        let mut screen = Screen::new(10, 3);
        screen.back_mut().put_text(0, 0, "hello", Style::default());
        let first = screen.present();
        assert!(first.starts_with(SYNC_ON));
        assert!(first.ends_with(SYNC_OFF));
        assert!(first.contains("\u{1b}[1;1H"));
        assert!(first.contains("hello"));

        // Nothing changed: no bytes at all.
        assert_eq!(screen.present(), "");

        // Only the changed suffix is emitted.
        screen.back_mut().put_text(0, 0, "help!", Style::default());
        let second = screen.present();
        // "hello" -> "help!" changes from column 4 (1-based) onward.
        assert!(second.contains("\u{1b}[1;4H"));
        assert!(second.contains("p!"));
        assert!(!second.contains("hel"));
    }

    #[test]
    fn wide_glyphs_and_styles_have_byte_exact_golden_output() {
        let mut screen = Screen::new(12, 2);
        screen.back_mut().put_text(0, 0, "hi", Style::fg(Color::Ansi(2)).bold());
        screen.back_mut().put_text(0, 1, "日本", Style::fg(Color::Ansi(200)));
        let out = screen.present();
        let expected = concat!(
            "\u{1b}[?2026h",
            "\u{1b}[1;1H\u{1b}[0;32;49;1mhi",
            "\u{1b}[2;1H\u{1b}[0;38;5;200;49m日本",
            "\u{1b}[0m",
            "\u{1b}[?2026l"
        );
        assert_eq!(out, expected);
    }

    #[test]
    fn the_fallback_redraw_omits_synchronized_markers_and_clears() {
        let mut screen = Screen::new(6, 1);
        screen.synchronized = false;
        screen.back_mut().put_text(0, 0, "x", Style::default());
        let out = screen.redraw();
        assert!(out.starts_with("\u{1b}[2J"));
        assert!(!out.contains("2026"));
        assert!(out.contains("x"));
    }

    #[test]
    fn resize_and_diff_keep_buffer_invariants() {
        let mut screen = Screen::new(8, 2);
        screen.back_mut().put_text(0, 0, "日本語", Style::default());
        screen.present();
        screen.resize(4, 3);
        screen.check_invariants().unwrap();
        screen.back_mut().put_text(3, 0, "日", Style::default());
        screen.present();
        screen.check_invariants().unwrap();
    }
}
