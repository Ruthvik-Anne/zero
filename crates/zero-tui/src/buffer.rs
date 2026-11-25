//! Cell grid with front and back buffers (TUI-01, TUI-03).

use crate::style::Style;
use crate::unicode::{self, grapheme_width};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Cell {
    /// Empty for the right half of a wide glyph.
    pub symbol: String,
    pub style: Style,
    pub width: u8,
    pub continuation: bool,
}

impl Cell {
    pub fn blank(style: Style) -> Self {
        Self { symbol: " ".into(), style, width: 1, continuation: false }
    }
}

impl Default for Cell {
    fn default() -> Self {
        Self::blank(Style::default())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Buffer {
    width: usize,
    height: usize,
    cells: Vec<Cell>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvariantError(pub String);

impl std::fmt::Display for InvariantError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

impl Buffer {
    pub fn new(width: usize, height: usize) -> Self {
        Self { width, height, cells: vec![Cell::default(); width * height] }
    }

    pub fn width(&self) -> usize {
        self.width
    }

    pub fn height(&self) -> usize {
        self.height
    }

    pub fn cells(&self) -> &[Cell] {
        &self.cells
    }

    pub fn cell(&self, x: usize, y: usize) -> &Cell {
        &self.cells[y * self.width + x]
    }

    fn idx(&self, x: usize, y: usize) -> usize {
        y * self.width + x
    }

    pub fn resize(&mut self, width: usize, height: usize) {
        let mut next = Buffer::new(width, height);
        for y in 0..height.min(self.height) {
            for x in 0..width.min(self.width) {
                let dst = next.idx(x, y);
                let src = self.idx(x, y);
                next.cells[dst] = self.cells[src].clone();
            }
        }
        // A truncated wide glyph at the new edge becomes a space.
        for y in 0..height.min(next.height) {
            if width == 0 {
                break;
            }
            let last = next.idx(width - 1, y);
            if next.cells[last].width == 2 {
                next.cells[last] = Cell::default();
            } else if next.cells[last].continuation {
                next.cells[last] = Cell::default();
                if width >= 2 {
                    next.cells[last - 1] = Cell::default();
                }
            }
        }
        *self = next;
        self.normalise_edges();
    }

    fn normalise_edges(&mut self) {
        if self.width == 0 || self.height == 0 {
            return;
        }
        for y in 0..self.height {
            for x in 0..self.width {
                let idx = self.idx(x, y);
                if self.cells[idx].continuation && (x == 0 || self.cells[idx - 1].width != 2) {
                    self.cells[idx] = Cell::default();
                }
                // A wide glyph whose right half is missing is not renderable.
                if self.cells[idx].width == 2
                    && (x + 1 >= self.width || !self.cells[idx + 1].continuation)
                {
                    self.cells[idx] = Cell::default();
                }
            }
        }
    }

    /// Clear a cell and any wide glyph it belongs to, so a write never leaves a
    /// broken neighbour.
    fn clear_at(&mut self, x: usize, y: usize) {
        let idx = self.idx(x, y);
        if self.cells[idx].continuation && x > 0 {
            self.cells[idx - 1] = Cell::default();
        }
        if self.cells[idx].width == 2 && x + 1 < self.width {
            self.cells[idx + 1] = Cell::default();
        }
        self.cells[idx] = Cell::default();
    }

    /// Write one grapheme at (x, y), clearing wide neighbours first.
    pub fn put_grapheme(&mut self, x: usize, y: usize, grapheme: &str, style: Style) -> usize {
        if self.width == 0 || self.height == 0 || x >= self.width || y >= self.height {
            return x;
        }
        let width = grapheme_width(grapheme).min(2);
        if width == 0 {
            return x;
        }
        self.clear_at(x, y);
        if width == 2 {
            if x + 1 >= self.width {
                // No room for the second half: draw a single space instead.
                self.clear_at(x, y);
                return x + 1;
            }
            self.clear_at(x + 1, y);
        }
        let idx = self.idx(x, y);
        self.cells[idx] = Cell { symbol: grapheme.to_string(), style, width: width as u8, continuation: false };
        if width == 2 {
            let cont = self.idx(x + 1, y);
            self.cells[cont] = Cell { symbol: String::new(), style, width: 0, continuation: true };
        }
        x + width
    }

    /// Write text into one row, clipping at the buffer edge. Tabs expand.
    pub fn put_text(&mut self, x: usize, y: usize, text: &str, style: Style) {
        if y >= self.height {
            return;
        }
        let text = unicode::expand_tabs(text, 8);
        let mut cursor = x;
        for grapheme in unicode::graphemes(&text) {
            if cursor >= self.width {
                break;
            }
            if grapheme == "\n" {
                break;
            }
            cursor = self.put_grapheme(cursor, y, &grapheme, style);
        }
    }

    pub fn fill(&mut self, style: Style) {
        for cell in &mut self.cells {
            *cell = Cell::blank(style);
        }
    }

    pub fn clear_row(&mut self, y: usize, style: Style) {
        if y >= self.height {
            return;
        }
        for x in 0..self.width {
            let idx = self.idx(x, y);
            self.cells[idx] = Cell::blank(style);
        }
    }

    pub fn clear(&mut self) {
        self.fill(Style::default());
    }

    /// Row text with continuation cells collapsed.
    pub fn row_text(&self, y: usize) -> String {
        let mut out = String::new();
        for x in 0..self.width {
            let cell = self.cell(x, y);
            if !cell.continuation {
                out.push_str(&cell.symbol);
            }
        }
        out
    }

    pub fn text(&self) -> Vec<String> {
        (0..self.height).map(|y| self.row_text(y)).collect()
    }

    pub fn check_invariants(&self) -> Result<(), InvariantError> {
        if self.cells.len() != self.width * self.height {
            return Err(InvariantError(format!(
                "cell count {} != {}x{}",
                self.cells.len(),
                self.width,
                self.height
            )));
        }
        for y in 0..self.height {
            for x in 0..self.width {
                let idx = self.idx(x, y);
                let cell = &self.cells[idx];
                if cell.continuation {
                    if x == 0 {
                        return Err(InvariantError(format!("continuation at x=0,y={y}")));
                    }
                    if self.cells[idx - 1].width != 2 {
                        return Err(InvariantError(format!("orphan continuation at x={x},y={y}")));
                    }
                    if cell.width != 0 || !cell.symbol.is_empty() {
                        return Err(InvariantError(format!("bad continuation cell at x={x},y={y}")));
                    }
                } else {
                    let measured = grapheme_width(&cell.symbol);
                    if measured != cell.width as usize {
                        return Err(InvariantError(format!(
                            "width mismatch at x={x},y={y}: {:?} measured {measured}, stored {}",
                            cell.symbol, cell.width
                        )));
                    }
                    if cell.width == 2 && (x + 1 >= self.width || !self.cells[idx + 1].continuation) {
                        return Err(InvariantError(format!("wide glyph without continuation at x={x},y={y}")));
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::style::{Color, Style};
    use zero_types::id::DeterministicRng;

    #[test]
    fn wide_glyphs_write_a_continuation_and_can_be_overwritten() {
        let mut buffer = Buffer::new(10, 2);
        buffer.put_text(0, 0, "日本語", Style::default());
        assert_eq!(buffer.row_text(0).trim_end(), "日本語");
        assert!(buffer.cell(1, 0).continuation);
        assert_eq!(buffer.cell(0, 0).width, 2);
        buffer.check_invariants().unwrap();

        // Overwrite the right half of the first glyph; the whole glyph clears.
        buffer.put_text(1, 0, "X", Style::default());
        assert_eq!(buffer.cell(0, 0).symbol, " ");
        assert_eq!(buffer.cell(1, 0).symbol, "X");
        buffer.check_invariants().unwrap();
    }

    #[test]
    fn a_wide_glyph_at_the_last_column_degrades_to_a_space() {
        let mut buffer = Buffer::new(3, 1);
        buffer.put_text(2, 0, "日", Style::default());
        assert_eq!(buffer.cell(2, 0).symbol, " ");
        buffer.check_invariants().unwrap();
    }

    #[test]
    fn invariants_hold_under_random_mutations() {
        let mut rng = DeterministicRng::new(0xC0FFEE);
        let corpus = ["a", "Z", " ", "日", "本", "é", "e\u{301}", "👍", "👨‍👩‍👧‍👦", "🇺🇸", "x"];
        let styles = [
            Style::default(),
            Style::fg(Color::Ansi(2)).bold(),
            Style::fg(Color::Rgb(10, 20, 30)).inverse(),
        ];
        let mut buffer = Buffer::new(20, 8);
        for step in 0..2000 {
            let op: String;
            match rng.below(5) {
                0 => {
                    let x = rng.below(20) as usize;
                    let y = rng.below(8) as usize;
                    let text = corpus[rng.below(corpus.len() as u32) as usize];
                    let style = styles[rng.below(styles.len() as u32) as usize];
                    op = format!("put_grapheme({x},{y},{text:?})");
                    buffer.put_grapheme(x, y, text, style);
                }
                1 => {
                    let x = rng.below(18) as usize;
                    let y = rng.below(8) as usize;
                    let style = styles[rng.below(styles.len() as u32) as usize];
                    op = format!("put_text({x},{y})");
                    buffer.put_text(x, y, "日本語abc👍", style);
                }
                2 => { let r = rng.below(8) as usize; op = format!("clear_row({r})"); buffer.clear_row(r, styles[rng.below(styles.len() as u32) as usize]); }
                3 => {
                    let w = 1 + rng.below(24) as usize;
                    let h = 1 + rng.below(10) as usize;
                    op = format!("resize({w},{h}) from {}x{}", buffer.width(), buffer.height());
                    buffer.resize(w, h);
                }
                _ => { op = "fill".into(); buffer.fill(styles[rng.below(styles.len() as u32) as usize]); }
            }
            buffer
                .check_invariants()
                .unwrap_or_else(|e| panic!("step {step} after {op}: {e}"));
        }
    }
}
