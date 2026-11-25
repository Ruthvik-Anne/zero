//! Input protocols (TUI-07): a bounded Kitty probe with declared fallbacks, and
//! parsing for keys, paste, mouse, focus, and resize across terminal profiles.

use std::sync::Arc;
use zero_types::id::Clock;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Mods {
    pub shift: bool,
    pub ctrl: bool,
    pub alt: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    Char(char),
    Enter,
    Tab,
    BackTab,
    Esc,
    Up,
    Down,
    Left,
    Right,
    Home,
    End,
    PageUp,
    PageDown,
    Delete,
    Backspace,
    Insert,
    F(u8),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub code: KeyCode,
    pub mods: Mods,
}

impl Key {
    pub const fn plain(code: KeyCode) -> Self {
        Self { code, mods: Mods { shift: false, ctrl: false, alt: false } }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
    WheelUp,
    WheelDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MouseEvent {
    pub button: MouseButton,
    pub x: u16,
    pub y: u16,
    pub pressed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Key(Key),
    Paste(String),
    Mouse(MouseEvent),
    Focus(bool),
    Resize { width: u16, height: u16 },
}

/// Construct a resize event (delivered by the platform, not a byte sequence).
pub fn resize_event(width: u16, height: u16) -> Event {
    Event::Resize { width, height }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyboardProtocol {
    Kitty,
    Legacy,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalProfile {
    WindowsTerminal,
    ConPty,
    Tmux,
    Legacy,
}

impl TerminalProfile {
    /// Declared fallback chord for mode cycling when Kitty is unavailable.
    pub fn fallback_chords(self) -> Vec<(Key, &'static str)> {
        let shift_tab = Key { code: KeyCode::BackTab, mods: Mods { shift: true, ..Mods::default() } };
        match self {
            TerminalProfile::WindowsTerminal => vec![(shift_tab, "Shift+Tab (CSI Z)")],
            TerminalProfile::ConPty => vec![(shift_tab, "Shift+Tab (CSI Z via ConPTY)")],
            TerminalProfile::Tmux => vec![(shift_tab, "Shift+Tab (tmux sends CSI Z)")],
            TerminalProfile::Legacy => vec![(shift_tab, "Shift+Tab (CSI Z)")],
        }
    }

    /// The byte sequence this profile sends for Shift+Tab.
    pub fn shift_tab_sequence(self) -> &'static [u8] {
        match self {
            TerminalProfile::WindowsTerminal => b"\x1b[1;2Z",
            TerminalProfile::ConPty | TerminalProfile::Tmux | TerminalProfile::Legacy => b"\x1b[Z",
        }
    }
}

/// Probe the Kitty keyboard protocol with a bounded wait. `read` returns bytes if
/// available; a closure that never returns data ends in `Legacy` at the deadline.
pub fn probe_kitty(
    read: &mut dyn FnMut() -> Option<Vec<u8>>,
    deadline_ms: u64,
    clock: Arc<dyn Clock>,
) -> KeyboardProtocol {
    let start = clock.now().millis();
    loop {
        if let Some(bytes) = read() {
            if bytes.windows(2).any(|w| w == b"?1" || w == b"?u") {
                return KeyboardProtocol::Kitty;
            }
            return KeyboardProtocol::Legacy;
        }
        let elapsed = clock.now().millis() - start;
        if elapsed >= deadline_ms as i64 {
            return KeyboardProtocol::Legacy;
        }
    }
}

#[derive(Default)]
pub struct InputParser {
    pending: Vec<u8>,
    paste: Option<String>,
}

impl InputParser {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn parse(&mut self, bytes: &[u8]) -> Vec<Event> {
        self.pending.extend_from_slice(bytes);
        let mut events = Vec::new();
        loop {
            if let Some(paste) = &mut self.paste {
                if let Some(end) = find(&self.pending, b"\x1b[201~") {
                    let body = String::from_utf8_lossy(&self.pending[..end]).to_string();
                    paste.push_str(&body);
                    self.pending.drain(..end + 6);
                    events.push(Event::Paste(std::mem::take(paste)));
                    self.paste = None;
                    continue;
                }
                // Keep accumulating; take what is available.
                let body = String::from_utf8_lossy(&self.pending).to_string();
                paste.push_str(&body);
                self.pending.clear();
                break;
            }
            if self.pending.is_empty() {
                break;
            }
            match self.parse_one(&mut events) {
                true => continue,
                false => break,
            }
        }
        events
    }

    fn parse_one(&mut self, events: &mut Vec<Event>) -> bool {
        let Some(first) = self.pending.first().copied() else {
            return false;
        };
        match first {
            0x1b => self.parse_escape(events),
            b'\r' | b'\n' => {
                self.pending.remove(0);
                events.push(Event::Key(Key::plain(KeyCode::Enter)));
                true
            }
            b'\t' => {
                self.pending.remove(0);
                events.push(Event::Key(Key::plain(KeyCode::Tab)));
                true
            }
            0x7f => {
                self.pending.remove(0);
                events.push(Event::Key(Key::plain(KeyCode::Backspace)));
                true
            }
            1..=26 => {
                self.pending.remove(0);
                let letter = (b'a' + first - 1) as char;
                events.push(Event::Key(Key {
                    code: KeyCode::Char(letter),
                    mods: Mods { ctrl: true, ..Mods::default() },
                }));
                true
            }
            _ => {
                // Printable UTF-8.
                let available = String::from_utf8_lossy(&self.pending);
                let Some(ch) = available.chars().next() else {
                    return false;
                };
                let len = ch.len_utf8();
                if self.pending.len() < len {
                    return false;
                }
                self.pending.drain(..len);
                events.push(Event::Key(Key::plain(KeyCode::Char(ch))));
                true
            }
        }
    }

    fn parse_escape(&mut self, events: &mut Vec<Event>) -> bool {
        if self.pending.len() == 1 {
            self.pending.remove(0);
            events.push(Event::Key(Key::plain(KeyCode::Esc)));
            return true;
        }
        if self.pending[1] != b'[' {
            let ch = self.pending[1] as char;
            self.pending.drain(..2);
            events.push(Event::Key(Key { code: KeyCode::Char(ch), mods: Mods { alt: true, ..Mods::default() } }));
            return true;
        }
        // CSI: find a final byte in 0x40..=0x7e.
        let Some(end) = self.pending[2..]
            .iter()
            .position(|b| (0x40..=0x7e).contains(b))
            .map(|p| p + 2)
        else {
            return false;
        };
        let final_byte = self.pending[end];
        let params = String::from_utf8_lossy(&self.pending[2..end]).to_string();
        self.pending.drain(..end + 1);
        match final_byte {
            b'A' | b'B' | b'C' | b'D' | b'H' | b'F' | b'Z' => {
                let shift = params.ends_with(";2") || params.contains(";2");
                let code = match final_byte {
                    b'A' => KeyCode::Up,
                    b'B' => KeyCode::Down,
                    b'C' => KeyCode::Right,
                    b'D' => KeyCode::Left,
                    b'H' => KeyCode::Home,
                    b'F' => KeyCode::End,
                    b'Z' => KeyCode::BackTab,
                    _ if shift => KeyCode::BackTab,
                    _ => KeyCode::Tab,
                };
                events.push(Event::Key(Key { code, mods: Mods { shift, ..Mods::default() } }));
            }
            b'I' => events.push(Event::Focus(true)),
            b'O' => events.push(Event::Focus(false)),
            b'~' => self.tilde(&params, events),
            b'M' | b'm' => {
                // SGR mouse: <b;x;yM or m.
                if let Some(rest) = params.strip_prefix('<') {
                    let nums: Vec<i64> = rest.split(';').filter_map(|n| n.parse().ok()).collect();
                    if nums.len() == 3 {
                        let code = nums[0];
                        let button = match code & 0b1100_0011 {
                            0 => MouseButton::Left,
                            1 => MouseButton::Middle,
                            2 => MouseButton::Right,
                            64 => MouseButton::WheelUp,
                            65 => MouseButton::WheelDown,
                            _ => MouseButton::Left,
                        };
                        events.push(Event::Mouse(MouseEvent {
                            button,
                            x: nums[1].max(1) as u16,
                            y: nums[2].max(1) as u16,
                            pressed: final_byte == b'M',
                        }));
                    }
                }
            }
            b'u' => {
                // Kitty: CSI codepoint;mods u
                let mut parts = params.split(';');
                let code = parts.next().and_then(|n| n.parse::<u32>().ok()).unwrap_or(0);
                // Kitty encodes 1 + the modifier bitmask (shift=1, alt=2, ctrl=4).
                let mods_bits = parts.next().and_then(|n| n.parse::<u8>().ok()).unwrap_or(1);
                let flags = mods_bits.saturating_sub(1);
                let mods = Mods {
                    shift: flags & 1 != 0,
                    alt: flags & 2 != 0,
                    ctrl: flags & 4 != 0,
                };
                let key = match code {
                    9 => KeyCode::Tab,
                    13 => KeyCode::Enter,
                    27 => KeyCode::Esc,
                    127 => KeyCode::Backspace,
                    c if c >= 0x20 => KeyCode::Char(char::from_u32(c).unwrap_or('?')),
                    _ => KeyCode::Esc,
                };
                // Shift+Tab is reported as Tab with shift.
                let key = if key == KeyCode::Tab && mods.shift { KeyCode::BackTab } else { key };
                events.push(Event::Key(Key { code: key, mods }));
            }
            _ => {}
        }
        true
    }

    fn tilde(&mut self, params: &str, events: &mut Vec<Event>) {
        let code = params.split(';').next().and_then(|n| n.parse::<u8>().ok()).unwrap_or(0);
        match code {
            1 | 7 => events.push(Event::Key(Key::plain(KeyCode::Home))),
            2 => events.push(Event::Key(Key::plain(KeyCode::Insert))),
            3 => events.push(Event::Key(Key::plain(KeyCode::Delete))),
            4 | 8 => events.push(Event::Key(Key::plain(KeyCode::End))),
            5 => events.push(Event::Key(Key::plain(KeyCode::PageUp))),
            6 => events.push(Event::Key(Key::plain(KeyCode::PageDown))),
            200 => {
                self.paste = Some(String::new());
            }
            _ => {}
        }
    }
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_types::id::FakeClock;

    #[test]
    fn the_terminal_matrix_maps_shift_tab_and_common_events() {
        for profile in [
            TerminalProfile::WindowsTerminal,
            TerminalProfile::ConPty,
            TerminalProfile::Tmux,
            TerminalProfile::Legacy,
        ] {
            let mut parser = InputParser::new();
            let events = parser.parse(profile.shift_tab_sequence());
            assert!(
                events.iter().any(|e| matches!(e, Event::Key(Key { code: KeyCode::BackTab, .. }))),
                "{profile:?}"
            );
            assert!(!profile.fallback_chords().is_empty());
            assert!(profile.fallback_chords()[0].1.contains("Shift+Tab"));
        }

        // Kitty reporting of shift-tab.
        let mut parser = InputParser::new();
        let events = parser.parse(b"\x1b[9;2u");
        assert!(events.iter().any(|e| matches!(e, Event::Key(Key { code: KeyCode::BackTab, mods }) if mods.shift)));

        // Arrows, paste, mouse, focus, resize.
        let mut parser = InputParser::new();
        assert_eq!(parser.parse(b"\x1b[A"), vec![Event::Key(Key::plain(KeyCode::Up))]);
        assert_eq!(
            parser.parse(b"\x1b[200~hello\nworld\x1b[201~"),
            vec![Event::Paste("hello\nworld".into())]
        );
        let mouse = parser.parse(b"\x1b[<0;10;5M");
        assert!(matches!(
            mouse.as_slice(),
            [Event::Mouse(MouseEvent { button: MouseButton::Left, x: 10, y: 5, pressed: true })]
        ));
        assert_eq!(parser.parse(b"\x1b[I"), vec![Event::Focus(true)]);
        assert_eq!(parser.parse(b"\x1b[O"), vec![Event::Focus(false)]);
        assert_eq!(resize_event(120, 40), Event::Resize { width: 120, height: 40 });
    }

    #[test]
    fn the_kitty_probe_is_bounded_and_falls_back() {
        let clock = Arc::new(FakeClock::at(0));
        let mut tick = 0;
        let clock_ref = clock.clone();
        let mut reads = || {
            tick += 1;
            clock_ref.advance(10);
            let _ = tick;
            None
        };
        let protocol = probe_kitty(&mut reads, 50, clock.clone());
        assert_eq!(protocol, KeyboardProtocol::Legacy);

        let mut replies = vec![Some(b"\x1b[?1u".to_vec())];
        let mut read_reply = || replies.pop().flatten();
        assert_eq!(probe_kitty(&mut read_reply, 50, clock), KeyboardProtocol::Kitty);
    }

    #[test]
    fn partial_sequences_are_buffered_not_misparsed() {
        let mut parser = InputParser::new();
        assert!(parser.parse(b"\x1b[").is_empty());
        assert_eq!(parser.parse(b"A"), vec![Event::Key(Key::plain(KeyCode::Up))]);

        let mut parser = InputParser::new();
        assert!(parser.parse(b"\x1b[200~abc").iter().all(|e| !matches!(e, Event::Paste(_))));
        assert_eq!(parser.parse(b"def\x1b[201~"), vec![Event::Paste("abcdef".into())]);
    }
}
