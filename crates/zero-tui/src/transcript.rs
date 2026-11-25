//! Virtualised transcript (TUI-06): lay out only visible rows, with a fullscreen
//! mode. Layout cost is independent of history size.

use crate::style::Style;
use crate::theme::Token;
use crate::unicode;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    User,
    Assistant,
    Tool,
    System,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Message {
    pub id: String,
    pub role: Role,
    pub text: String,
    pub generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub message_id: String,
    pub text: String,
    pub token: Token,
    pub style: Style,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct LayoutStats {
    pub messages_visited: usize,
    pub rows_laid_out: usize,
}

pub struct VirtualTranscript {
    messages: Vec<Message>,
    /// Lines scrolled up from the bottom.
    pub offset: usize,
    pub fullscreen: bool,
}

impl Default for VirtualTranscript {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtualTranscript {
    pub fn new() -> Self {
        Self { messages: Vec::new(), offset: 0, fullscreen: false }
    }

    pub fn push(&mut self, message: Message) {
        self.messages.push(message);
    }

    pub fn messages(&self) -> &[Message] {
        &self.messages
    }

    pub fn len(&self) -> usize {
        self.messages.len()
    }

    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
    }

    pub fn scroll_up(&mut self, lines: usize) {
        self.offset = self.offset.saturating_add(lines);
    }

    pub fn scroll_down(&mut self, lines: usize) {
        self.offset = self.offset.saturating_sub(lines);
    }

    pub fn scroll_to_bottom(&mut self) {
        self.offset = 0;
    }

    /// Rows for the visible window. Walks backwards from the newest message and
    /// stops once `height` rows are filled.
    pub fn view(&self, width: usize, height: usize) -> (Vec<Row>, LayoutStats) {
        let mut rows: Vec<Row> = Vec::new();
        let mut stats = LayoutStats::default();
        let width = width.max(1);
        for message in self.messages.iter().rev() {
            stats.messages_visited += 1;
            let token = match message.role {
                Role::User => Token::UserMessage,
                Role::Assistant => Token::AssistantMessage,
                Role::Tool => Token::ToolMessage,
                Role::System => Token::Muted,
            };
            let mut message_rows = wrap(&message.text, width, token);
            for row in &mut message_rows {
                row.message_id = message.id.clone();
            }
            rows.extend(message_rows);
            // Collect a little extra so scrolling up has content, then trim.
            if rows.len() >= height + self.offset {
                break;
            }
        }
        rows.reverse();
        // Drop the newest `offset` rows (scrolled up), then take one screen.
        let end = rows.len().saturating_sub(self.offset);
        let start = end.saturating_sub(height);
        let visible: Vec<Row> = rows[start..end].to_vec();
        stats.rows_laid_out = visible.len();
        (visible, stats)
    }

    pub fn set_fullscreen(&mut self, fullscreen: bool) {
        self.fullscreen = fullscreen;
    }
}

fn wrap(text: &str, width: usize, token: Token) -> Vec<Row> {
    let mut out = Vec::new();
    for source in text.split('\n') {
        let mut current = String::new();
        let mut current_width = 0;
        for word in source.split_whitespace() {
            let w = unicode::width(word);
            if current_width > 0 && current_width + 1 + w > width {
                out.push(Row { message_id: String::new(), text: std::mem::take(&mut current), token, style: Style::default() });
                current_width = 0;
            }
            if current_width > 0 {
                current.push(' ');
                current_width += 1;
            }
            current.push_str(word);
            current_width += w;
        }
        out.push(Row { message_id: String::new(), text: current, token, style: Style::default() });
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(i: usize, words: usize) -> Message {
        Message {
            id: format!("m{i}"),
            role: if i.is_multiple_of(2) { Role::User } else { Role::Assistant },
            text: format!("message {i} {}", "word ".repeat(words)),
            generation: 1,
        }
    }

    #[test]
    fn layout_visits_only_visible_messages_and_scroll_cost_is_flat() {
        let mut transcript = VirtualTranscript::new();
        for i in 0..10_000 {
            transcript.push(message(i, 8));
        }
        let (rows, stats) = transcript.view(80, 40);
        assert_eq!(rows.len(), 40);
        assert!(stats.messages_visited <= 60, "visited {}", stats.messages_visited);
        assert!(rows.iter().all(|r| !r.message_id.is_empty()));

        transcript.scroll_up(80);
        let (_rows, stats) = transcript.view(80, 40);
        assert!(stats.messages_visited <= 160, "scroll visited {}", stats.messages_visited);
        transcript.scroll_to_bottom();
        let (bottom_rows, _) = transcript.view(80, 40);
        assert!(bottom_rows.last().unwrap().text.contains("message 9999"));
    }

    #[test]
    fn fullscreen_toggles_without_changing_content() {
        let mut transcript = VirtualTranscript::new();
        transcript.push(message(0, 2));
        let (normal, _) = transcript.view(40, 5);
        transcript.set_fullscreen(true);
        let (full, _) = transcript.view(40, 5);
        assert!(transcript.fullscreen);
        assert_eq!(normal.last().map(|r| &r.text), full.last().map(|r| &r.text));
    }

    #[test]
    fn an_empty_transcript_is_a_single_empty_screen() {
        let transcript = VirtualTranscript::new();
        let (rows, stats) = transcript.view(20, 10);
        assert!(rows.is_empty());
        assert_eq!(stats.messages_visited, 0);
    }
}
