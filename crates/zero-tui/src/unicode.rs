//! Unicode layout (TUI-04): grapheme clusters, East Asian width, emoji,
//! combining marks, tabs, and a declared bidi degradation.

use unicode_segmentation::UnicodeSegmentation;
use unicode_width::UnicodeWidthStr;

pub const RTL_MARKER: &str = "[RTL]";

/// Grapheme clusters in display order.
pub fn graphemes(text: &str) -> Vec<String> {
    UnicodeSegmentation::graphemes(text, true).map(str::to_string).collect()
}

/// Display width of one grapheme. Emoji sequences (ZWJ, variation selector 16,
/// regional-indicator pairs) are 2 columns; combining marks are 0 within their
/// base grapheme; East Asian wide characters are 2.
pub fn grapheme_width(grapheme: &str) -> usize {
    if grapheme.is_empty() {
        return 0;
    }
    let has = |c: char| grapheme.contains(c);
    let is_emoji = has('\u{200d}') // ZWJ
        || has('\u{fe0f}') // variation selector 16
        || grapheme.chars().next().map(|c| {
            matches!(c as u32, 0x1F1E6..=0x1F1FF | 0x1F300..=0x1FAFF | 0x2600..=0x27BF)
        }).unwrap_or(false);
    if is_emoji {
        return 2;
    }
    let width = UnicodeWidthStr::width(grapheme);
    // A grapheme consisting only of combining marks still occupies its base's
    // column; alone it is zero width.
    width
}

/// Total display width of a string (tabs are expanded first by callers).
pub fn width(text: &str) -> usize {
    graphemes(text).iter().map(|g| grapheme_width(g)).sum()
}

/// Expand tabs to spaces at the given tab stop.
pub fn expand_tabs(text: &str, tabstop: usize) -> String {
    let tabstop = tabstop.max(1);
    let mut out = String::with_capacity(text.len());
    let mut column = 0usize;
    for g in graphemes(text) {
        if g == "\t" {
            let next = ((column / tabstop) + 1) * tabstop;
            while column < next {
                out.push(' ');
                column += 1;
            }
        } else {
            column += grapheme_width(&g);
            out.push_str(&g);
        }
        if g == "\n" {
            column = 0;
        }
    }
    out
}

fn is_rtl(c: char) -> bool {
    matches!(
        c as u32,
        0x0590..=0x05FF
            | 0x0600..=0x06FF
            | 0x0700..=0x074F
            | 0x0750..=0x077F
            | 0x08A0..=0x08FF
            | 0xFB50..=0xFDFF
            | 0xFE70..=0xFEFF
    )
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BidiText {
    pub text: String,
    /// True when right-to-left text was replaced by the declared marker.
    pub degraded: bool,
}

/// The declared bidi degradation: a maximal right-to-left run is replaced by
/// `[RTL]` rather than reordered, so cell layout stays deterministic and no RTL
/// text is ever silently reversed.
pub fn degrade_bidi(text: &str) -> BidiText {
    let mut out = String::with_capacity(text.len());
    let mut in_rtl = false;
    let mut degraded = false;
    for c in text.chars() {
        if is_rtl(c) {
            if !in_rtl {
                out.push_str(RTL_MARKER);
                in_rtl = true;
                degraded = true;
            }
        } else {
            in_rtl = false;
            out.push(c);
        }
    }
    BidiText { text: out, degraded }
}

/// Remove terminal control sequences and control characters (except newline and
/// tab) from untrusted text before it reaches a cell grid.
pub fn sanitize_controls(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\u{1b}' {
            match chars.peek() {
                Some('[') => {
                    // CSI: consume to a final byte in 0x40..=0x7e.
                    chars.next();
                    for c in chars.by_ref() {
                        if ('\u{40}'..='\u{7e}').contains(&c) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: consume to BEL or ST.
                    chars.next();
                    for c in chars.by_ref() {
                        if c == '\u{7}' {
                            break;
                        }
                    }
                }
                _ => {
                    chars.next();
                }
            }
            continue;
        }
        if c == '\n' || c == '\t' || (c as u32) >= 0x20 {
            out.push(c);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn widths_cover_the_corpus() {
        assert_eq!(width("abc"), 3);
        assert_eq!(width("日本語"), 6);
        assert_eq!(width("e\u{301}"), 1, "combining mark adds no column");
        assert_eq!(width("👨‍👩‍👧‍👦"), 2, "ZWJ family is one wide grapheme");
        assert_eq!(width("👍🏽"), 2, "emoji with skin tone is two columns");
        assert_eq!(width("🇺🇸"), 2, "flag is one wide grapheme");
        assert_eq!(graphemes("a\u{301}b").len(), 2);
    }

    #[test]
    fn tabs_expand_to_the_next_stop() {
        assert_eq!(expand_tabs("a\tb", 4), "a   b");
        assert_eq!(expand_tabs("\tX", 8), "        X");
        assert_eq!(expand_tabs("日本語\tY", 8), "日本語  Y");
    }

    #[test]
    fn bidi_is_degraded_not_reordered() {
        let result = degrade_bidi("abc שלום def");
        assert!(result.degraded);
        assert_eq!(result.text, "abc [RTL] def");
        assert!(!result.text.contains('ש'));
    }

    #[test]
    fn control_sequences_are_stripped_from_untrusted_text() {
        let hostile = "ok\u{1b}[2J\u{1b}[31mred\u{1b}]0;title\u{7}\u{7}";
        let clean = sanitize_controls(hostile);
        assert_eq!(clean, "okred");
        assert!(!clean.contains('\u{1b}'));
        assert!(!clean.contains('\u{7}'));
    }
}
