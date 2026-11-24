//! Virtual terminal harness (TST-02, TST-09): records cells and escape
//! sequences so UI output can be asserted without a real terminal.
//!
//! Supported sequences: printable text (including CJK wide cells and combining
//! marks), CR, LF, BS, TAB, CSI cursor movement/positioning, CSI J/K erase, and
//! SGR attributes. Unknown sequences are recorded and ignored, never applied.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Style {
    pub fg: u8,
    pub bg: u8,
    pub bold: bool,
    pub italic: bool,
    pub underline: bool,
    pub inverse: bool,
}

impl Default for Style {
    fn default() -> Self {
        Self { fg: 7, bg: 0, bold: false, italic: false, underline: false, inverse: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cell {
    pub text: String,
    pub style: Style,
    /// True for the right half of a wide glyph.
    pub continuation: bool,
}

impl Default for Cell {
    fn default() -> Self {
        Self { text: " ".into(), style: Style::default(), continuation: false }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscapeRecord {
    pub sequence: String,
}

pub struct Terminal {
    width: usize,
    height: usize,
    cells: Vec<Cell>,
    cursor_x: usize,
    cursor_y: usize,
    saved: (usize, usize),
    style: Style,
    escapes: Vec<EscapeRecord>,
    /// Bytes fed, for throughput assertions.
    pub bytes_fed: usize,
}

fn char_width(c: char) -> usize {
    let cp = c as u32;
    match cp {
        0x1100..=0x115F
        | 0x2E80..=0x303E
        | 0x3041..=0x33FF
        | 0x3400..=0x4DBF
        | 0x4E00..=0x9FFF
        | 0xA000..=0xA4CF
        | 0xAC00..=0xD7A3
        | 0xF900..=0xFAFF
        | 0xFE30..=0xFE6F
        | 0xFF00..=0xFF60
        | 0xFFE0..=0xFFE6
        | 0x1F300..=0x1F64F
        | 0x1F900..=0x1F9FF
        | 0x20000..=0x3FFFD => 2,
        _ => 1,
    }
}

impl Terminal {
    pub fn new(width: usize, height: usize) -> Self {
        Self {
            width,
            height,
            cells: vec![Cell::default(); width * height],
            cursor_x: 0,
            cursor_y: 0,
            saved: (0, 0),
            style: Style::default(),
            escapes: Vec::new(),
            bytes_fed: 0,
        }
    }

    pub fn size(&self) -> (usize, usize) {
        (self.width, self.height)
    }

    pub fn cursor(&self) -> (usize, usize) {
        (self.cursor_x, self.cursor_y)
    }

    pub fn escapes(&self) -> &[EscapeRecord] {
        &self.escapes
    }

    pub fn cell(&self, x: usize, y: usize) -> &Cell {
        &self.cells[y * self.width + x]
    }

    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    fn idx(&self, x: usize, y: usize) -> usize {
        y * self.width + x
    }

    fn put(&mut self, ch: char) {
        if ch == '\r' {
            self.cursor_x = 0;
            return;
        }
        if ch == '\n' {
            self.cursor_y = (self.cursor_y + 1).min(self.height.saturating_sub(1));
            return;
        }
        if ch == '\u{8}' {
            self.cursor_x = self.cursor_x.saturating_sub(1);
            return;
        }
        if ch == '\t' {
            let next = ((self.cursor_x / 8) + 1) * 8;
            while self.cursor_x < next.min(self.width) {
                self.write_glyph(' ');
            }
            return;
        }
        if (ch as u32) < 0x20 {
            return;
        }
        self.write_glyph(ch);
    }

    fn write_glyph(&mut self, ch: char) {
        let w = char_width(ch).min(self.width.max(1));
        if self.cursor_x + w > self.width {
            self.cursor_x = 0;
            self.cursor_y = (self.cursor_y + 1).min(self.height.saturating_sub(1));
        }
        if self.cursor_y >= self.height {
            return;
        }
        let idx = self.idx(self.cursor_x, self.cursor_y);
        self.cells[idx] = Cell {
            text: ch.to_string(),
            style: self.style.clone(),
            continuation: false,
        };
        if w == 2 {
            if self.cursor_x + 1 < self.width {
                let idx2 = self.idx(self.cursor_x + 1, self.cursor_y);
                self.cells[idx2] = Cell { text: String::new(), style: self.style.clone(), continuation: true };
            } else {
                self.cells[idx].text = "?".into();
            }
        }
        self.cursor_x += w;
        if self.cursor_x >= self.width {
            self.cursor_x = self.width.saturating_sub(1);
        }
    }

    pub fn feed(&mut self, input: &str) {
        self.bytes_fed += input.len();
        let chars: Vec<char> = input.chars().collect();
        let mut i = 0;
        while i < chars.len() {
            let c = chars[i];
            if c == '\u{1b}' {
                let start = i;
                i += 1;
                if i < chars.len() && chars[i] == '[' {
                    i += 1;
                    let params_start = i;
                    while i < chars.len() && !(chars[i] as u32 >= 0x40 && chars[i] as u32 <= 0x7e) {
                        i += 1;
                    }
                    if i < chars.len() {
                        let seq: String = chars[start..=i].iter().collect();
                        self.escapes.push(EscapeRecord { sequence: seq.clone() });
                        let params: String = chars[params_start..i].iter().collect();
                        let fin = chars[i];
                        self.csi(&params, fin);
                        i += 1;
                    }
                } else if i < chars.len() && chars[i] == ']' {
                    // OSC: consume to BEL or ST.
                    while i < chars.len() && chars[i] != '\u{7}' {
                        i += 1;
                    }
                    i = (i + 1).min(chars.len());
                    let seq: String = chars[start..i].iter().collect();
                    self.escapes.push(EscapeRecord { sequence: seq });
                } else if i < chars.len() {
                    let seq: String = chars[start..=i].iter().collect();
                    self.escapes.push(EscapeRecord { sequence: seq });
                    if chars[i] == '7' {
                        self.saved = (self.cursor_x, self.cursor_y);
                    } else if chars[i] == '8' {
                        self.cursor_x = self.saved.0;
                        self.cursor_y = self.saved.1;
                    }
                    i += 1;
                }
                continue;
            }
            self.put(c);
            i += 1;
        }
    }

    fn csi(&mut self, params: &str, fin: char) {
        let nums: Vec<usize> = if params.is_empty() {
            Vec::new()
        } else {
            params
                .split(';')
                .map(|p| p.trim_start_matches('?').parse::<usize>().unwrap_or(0))
                .collect()
        };
        let n = |idx: usize, default: usize| { nums.get(idx).copied().filter(|v| *v > 0).unwrap_or(default) };
        match fin {
            'H' | 'f' => {
                self.cursor_y = (n(0, 1) - 1).min(self.height.saturating_sub(1));
                self.cursor_x = (n(1, 1) - 1).min(self.width.saturating_sub(1));
            }
            'A' => self.cursor_y = self.cursor_y.saturating_sub(n(0, 1)),
            'B' => self.cursor_y = (self.cursor_y + n(0, 1)).min(self.height.saturating_sub(1)),
            'C' => self.cursor_x = (self.cursor_x + n(0, 1)).min(self.width.saturating_sub(1)),
            'D' => self.cursor_x = self.cursor_x.saturating_sub(n(0, 1)),
            'G' => self.cursor_x = (n(0, 1) - 1).min(self.width.saturating_sub(1)),
            'd' => self.cursor_y = (n(0, 1) - 1).min(self.height.saturating_sub(1)),
            'J' => match nums.first().copied().unwrap_or(0) {
                2 | 3 => {
                    for c in &mut self.cells {
                        *c = Cell::default();
                    }
                }
                0 => {
                    let start = self.idx(self.cursor_x.min(self.width - 1), self.cursor_y);
                    for c in &mut self.cells[start..] {
                        *c = Cell::default();
                    }
                }
                _ => {}
            },
            'K' => {
                let start = self.idx(0, self.cursor_y);
                let end = self.idx(self.width - 1, self.cursor_y);
                match nums.first().copied().unwrap_or(0) {
                    0 => {
                        let start = self.idx(self.cursor_x.min(self.width - 1), self.cursor_y);
                        for c in &mut self.cells[start..=end] {
                            *c = Cell::default();
                        }
                    }
                    2 => {
                        for c in &mut self.cells[start..=end] {
                            *c = Cell::default();
                        }
                    }
                    _ => {}
                }
            }
            'm' => {
                if nums.is_empty() {
                    self.style = Style::default();
                    return;
                }
                let mut i = 0;
                while i < nums.len() {
                    match nums[i] {
                        0 => self.style = Style::default(),
                        1 => self.style.bold = true,
                        3 => self.style.italic = true,
                        4 => self.style.underline = true,
                        7 => self.style.inverse = true,
                        22 => self.style.bold = false,
                        23 => self.style.italic = false,
                        24 => self.style.underline = false,
                        27 => self.style.inverse = false,
                        30..=37 => self.style.fg = nums[i] as u8 - 30,
                        39 => self.style.fg = 7,
                        40..=47 => self.style.bg = nums[i] as u8 - 40,
                        49 => self.style.bg = 0,
                        90..=97 => self.style.fg = nums[i] as u8 - 90 + 8,
                        100..=107 => self.style.bg = nums[i] as u8 - 100 + 8,
                        38 | 48 => {
                            // 256-colour: 38;5;N
                            if let (Some(&5), Some(v)) = (nums.get(i + 1), nums.get(i + 2)) {
                                if nums[i] == 38 {
                                    self.style.fg = (*v).min(255) as u8;
                                } else {
                                    self.style.bg = (*v).min(255) as u8;
                                }
                                i += 2;
                            }
                        }
                        _ => {}
                    }
                    i += 1;
                }
            }
            's' => self.saved = (self.cursor_x, self.cursor_y),
            'u' => {
                self.cursor_x = self.saved.0;
                self.cursor_y = self.saved.1;
            }
            _ => {}
        }
    }

    /// Rows as strings with continuation cells collapsed.
    pub fn rows(&self) -> Vec<String> {
        (0..self.height)
            .map(|y| {
                let mut s = String::new();
                for x in 0..self.width {
                    let c = self.cell(x, y);
                    if !c.continuation {
                        s.push_str(&c.text);
                    }
                }
                s
            })
            .collect()
    }

    /// Trim trailing spaces so assertions read naturally.
    pub fn text(&self) -> String {
        self.rows()
            .iter()
            .map(|r| r.trim_end().to_string())
            .collect::<Vec<_>>()
            .join("\n")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn smoke_frame_renders_and_reads_back() {
        let mut t = Terminal::new(20, 4);
        t.feed("\u{1b}[2J\u{1b}[H");
        t.feed("\u{1b}[1;32mzero\u{1b}[0m ready\n");
        t.feed("\u{1b}[3;5Hstatus: ok");
        assert_eq!(t.rows()[0].trim_end(), "zero ready");
        assert_eq!(t.rows()[2].trim_end(), "status: ok".replace("status", "    status").as_str());
        assert_eq!(t.cell(0, 0).text, "z");
        assert_eq!(t.cell(0, 0).style.fg, 2);
        assert!(t.cell(0, 0).style.bold);

        // Escape sequences are recorded verbatim.
        let seqs: Vec<String> = t.escapes().iter().map(|e| e.sequence.clone()).collect();
        assert!(seqs.contains(&"\u{1b}[2J".to_string()));
        assert!(seqs.contains(&"\u{1b}[1;32m".to_string()));
        assert!(seqs.contains(&"\u{1b}[0m".to_string()));
    }

    #[test]
    fn wide_cells_are_two_wide_and_continuation_is_hidden() {
        let mut t = Terminal::new(10, 2);
        t.feed("日本");
        assert_eq!(t.cell(0, 0).text, "日");
        assert!(t.cell(1, 0).continuation);
        assert_eq!(t.cell(2, 0).text, "本");
        assert_eq!(t.rows()[0].trim_end(), "日本");
    }

    #[test]
    fn erase_and_cursor_motion_are_applied() {
        let mut t = Terminal::new(10, 3);
        t.feed("abcdef");
        t.feed("\u{1b}[3Gxx");
        assert_eq!(t.rows()[0].trim_end(), "abxxef");
        t.feed("\u{1b}[K");
        assert_eq!(t.rows()[0].trim_end(), "abxx");
        t.feed("\u{1b}[2J");
        assert_eq!(t.text().trim(), "");
    }

    #[test]
    fn unknown_sequences_are_logged_and_ignored() {
        let mut t = Terminal::new(5, 2);
        t.feed("\u{1b}[?25lhi");
        assert_eq!(t.rows()[0].trim_end(), "hi");
        assert!(t.escapes()[0].sequence.contains("?25l"));
    }
}
