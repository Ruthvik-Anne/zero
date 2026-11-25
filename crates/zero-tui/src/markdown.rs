//! Streaming Markdown (TUI-05): parse and lay out only the tail. Completed
//! blocks are stored; each push scans the appended bytes plus the unfinished
//! tail, never the whole history.

use crate::style::Style;
use crate::theme::Token;
use crate::unicode;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Block {
    Paragraph(String),
    Heading(u8, String),
    Code { lang: String, lines: Vec<String> },
    ListItem(String),
    Thinking(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MarkdownLine {
    pub text: String,
    pub token: Token,
    pub style: Style,
}

pub struct StreamingMarkdown {
    pending: String,
    blocks: Vec<Block>,
    pub folding: bool,
    /// Bytes examined by the last push (tail + delta).
    pub last_scan_bytes: usize,
    /// Blocks visited by the last layout call.
    pub last_layout_visits: usize,
}

impl Default for StreamingMarkdown {
    fn default() -> Self {
        Self::new()
    }
}

impl StreamingMarkdown {
    pub fn new() -> Self {
        Self { pending: String::new(), blocks: Vec::new(), folding: true, last_scan_bytes: 0, last_layout_visits: 0 }
    }

    pub fn blocks(&self) -> &[Block] {
        &self.blocks
    }

    pub fn pending(&self) -> &str {
        &self.pending
    }

    /// Feed a delta. Only the unfinished tail and the delta are scanned.
    pub fn push(&mut self, delta: &str) {
        self.last_scan_bytes = delta.len() + self.pending.len();
        self.pending.push_str(delta);
        self.extract_thinking();
        self.extract_complete_blocks();
    }

    fn extract_thinking(&mut self) {
        while let Some(open) = self.pending.find("<thinking>") {
            let Some(close_rel) = self.pending[open..].find("</thinking>") else {
                break;
            };
            let close = open + close_rel;
            let inner = self.pending[open + "<thinking>".len()..close].to_string();
            self.pending.replace_range(open..close + "</thinking>".len(), "");
            if !inner.trim().is_empty() {
                self.blocks.push(Block::Thinking(inner));
            }
        }
    }

    fn extract_complete_blocks(&mut self) {
        // A single complete fence with no trailing blank line still becomes a
        // block when it is closed.
        while let Some(split) = self.pending.find("\n\n") {
            let segment: String = self.pending.drain(..split + 2).collect();
            let segment = segment.trim_end_matches('\n');
            if !segment.trim().is_empty() {
                self.blocks.push(parse_block(segment));
            }
        }
        // A closed code fence at the end of the pending tail is complete.
        if self.pending.trim_start().starts_with("```") && self.pending.matches("```").count() >= 2 && self.pending.ends_with("```") {
            let block = parse_block(self.pending.trim_end());
            self.pending.clear();
            self.blocks.push(block);
        }
    }

    /// Lay out only the last `max_rows` rows; visits blocks from the end.
    pub fn layout(&mut self, width: usize, max_rows: usize) -> Vec<MarkdownLine> {
        let width = width.max(1);
        let mut rows: Vec<MarkdownLine> = Vec::new();
        let mut visits = 0;
        for block in self.blocks.iter().rev() {
            visits += 1;
            let mut block_rows = layout_block(block, width, self.folding);
            rows.append(&mut block_rows);
            if rows.len() >= max_rows {
                break;
            }
        }
        self.last_layout_visits = visits;
        rows.truncate(max_rows);
        rows.reverse();
        rows
    }

    /// Include the unfinished tail as a final paragraph (used for live output).
    pub fn layout_live(&mut self, width: usize, max_rows: usize) -> Vec<MarkdownLine> {
        let mut rows = self.layout(width, max_rows);
        if !self.pending.trim().is_empty() && rows.len() < max_rows {
            let mut tail = wrap(
                self.pending.trim_end(),
                width,
                Token::AssistantMessage,
            );
            let room = max_rows - rows.len();
            if tail.len() > room {
                tail = tail.split_off(tail.len() - room);
            }
            tail.append(&mut rows);
            rows = tail;
        }
        rows
    }
}

fn parse_block(segment: &str) -> Block {
    let trimmed = segment.trim();
    if let Some(rest) = trimmed.strip_prefix("```") {
        let mut lines = rest.split('\n');
        let lang = lines.next().unwrap_or("").trim().to_string();
        let body: Vec<String> = lines.map(str::to_string).collect();
        return Block::Code { lang, lines: body.into_iter().filter(|l| l != "```").collect() };
    }
    if let Some(rest) = trimmed.strip_prefix('#') {
        let level = trimmed.chars().take_while(|c| *c == '#').count().min(6) as u8;
        return Block::Heading(level, rest.trim_start_matches('#').trim().to_string());
    }
    if let Some(rest) = trimmed.strip_prefix("- ") {
        return Block::ListItem(rest.trim().to_string());
    }
    Block::Paragraph(trimmed.to_string())
}

fn layout_block(block: &Block, width: usize, folding: bool) -> Vec<MarkdownLine> {
    match block {
        Block::Paragraph(text) => wrap(text, width, Token::AssistantMessage),
        Block::Heading(level, text) => wrap(
            &format!("{} {}", "#".repeat(*level as usize), text),
            width,
            Token::Accent,
        )
        .into_iter()
        .map(|mut line| {
            line.style = line.style.bold();
            line
        })
        .collect(),
        Block::Code { lines, .. } => lines
            .iter()
            .map(|line| MarkdownLine {
                text: format!("  {line}"),
                token: Token::Code,
                style: Style::default(),
            })
            .collect(),
        Block::ListItem(text) => wrap(&format!("• {text}"), width, Token::Foreground),
        Block::Thinking(text) => {
            if folding {
                let n = text.lines().count().max(1);
                vec![MarkdownLine {
                    text: format!("▸ thinking ({n} lines)"),
                    token: Token::Thinking,
                    style: Style::default().dim(),
                }]
            } else {
                wrap(text, width, Token::Thinking)
            }
        }
    }
}

fn wrap(text: &str, width: usize, token: Token) -> Vec<MarkdownLine> {
    let mut rows = Vec::new();
    for source_line in text.split('\n') {
        let mut current = String::new();
        let mut current_width = 0usize;
        for word in source_line.split_whitespace() {
            let word_width = unicode::width(word);
            if current_width > 0 && current_width + 1 + word_width > width {
                rows.push(MarkdownLine { text: std::mem::take(&mut current), token, style: Style::default() });
                current_width = 0;
            }
            if current_width > 0 {
                current.push(' ');
                current_width += 1;
            }
            current.push_str(word);
            current_width += word_width;
        }
        rows.push(MarkdownLine { text: current, token, style: Style::default() });
    }
    rows
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_ten_thousand_message_stream_keeps_parse_and_layout_flat() {
        let mut markdown = StreamingMarkdown::new();
        for i in 0..10_000 {
            markdown.push(&format!("message {i} with a few words\n\n"));
            assert!(
                markdown.last_scan_bytes < 128,
                "push {i} scanned {} bytes",
                markdown.last_scan_bytes
            );
        }
        assert_eq!(markdown.blocks().len(), 10_000);
        let rows = markdown.layout(80, 40);
        assert_eq!(rows.len(), 40);
        assert!(markdown.last_layout_visits <= 41, "visited {} blocks", markdown.last_layout_visits);
        assert!(rows.last().unwrap().text.contains("message 9999"));
    }

    #[test]
    fn headings_lists_fences_and_thinking_are_structured() {
        let mut markdown = StreamingMarkdown::new();
        markdown.push("# Title\n\n- item one\n\n```rust\nlet x = 1;\n```\n\n");
        markdown.push("<thinking>hidden plan</thinking>\n\nbody text\n\n");
        assert!(markdown.blocks().iter().any(|b| matches!(b, Block::Heading(1, t) if t == "Title")));
        assert!(markdown.blocks().iter().any(|b| matches!(b, Block::ListItem(t) if t == "item one")));
        assert!(markdown.blocks().iter().any(|b| matches!(b, Block::Code { lang, .. } if lang == "rust")));
        assert!(markdown.blocks().iter().any(|b| matches!(b, Block::Thinking(t) if t.contains("hidden plan"))));
        let rows = markdown.layout(80, 40);
        assert!(rows.iter().any(|r| r.text.contains("thinking (1 lines)")));
        assert!(rows.iter().any(|r| r.text == "body text"));
    }

    #[test]
    fn an_unfinished_tail_is_not_lost_and_is_laid_out_live() {
        let mut markdown = StreamingMarkdown::new();
        markdown.push("partial sen");
        assert!(markdown.blocks().is_empty());
        let rows = markdown.layout_live(80, 5);
        assert_eq!(rows.last().unwrap().text, "partial sen");
        markdown.push("tence\n\n");
        assert_eq!(markdown.blocks().len(), 1);
        assert!(markdown.pending().is_empty());
    }

    #[test]
    fn wrapping_counts_display_columns_not_bytes() {
        let mut markdown = StreamingMarkdown::new();
        markdown.push("日本語 日本語 日本語\n\n");
        let rows = markdown.layout(10, 10);
        for row in &rows {
            assert!(unicode::width(&row.text) <= 10, "{:?}", row.text);
        }
    }
}
