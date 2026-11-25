//! TUI-10: golden frames across states and sizes. The fixture is the terminal's
//! read-back text plus the escape sequences it received, so both cell content and
//! styling are covered. Run with UPDATE_GOLDEN=1 to refresh deliberately.

use std::path::{Path, PathBuf};
use zero_tui::modal::HostChrome;
use zero_tui::screen::Screen;
use zero_tui::status::StatusModel;
use zero_tui::style::Style;
use zero_tui::theme::{Theme, Token};
use zero_tui::vterm::Terminal;

fn golden_path(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/golden").join(format!("{name}.txt"))
}

fn snapshot(name: &str, width: usize, height: usize, draw: impl FnOnce(&mut Screen, &Theme)) -> String {
    let theme = Theme::dark();
    let mut screen = Screen::new(width, height);
    draw(&mut screen, &theme);
    let bytes = screen.present();
    let mut terminal = Terminal::new(width, height);
    terminal.feed(&bytes);
    let mut out = String::new();
    out.push_str(&format!("# {name} {width}x{height}\nTEXT\n"));
    for row in terminal.rows() {
        out.push_str(row.trim_end());
        out.push('\n');
    }
    out.push_str("ESCAPES\n");
    for escape in terminal.escapes() {
        out.push_str(&escape.sequence.replace('\u{1b}', "\\x1b"));
        out.push('\n');
    }
    out
}

fn check(name: &str, actual: &str) {
    let path = golden_path(name);
    if std::env::var("UPDATE_GOLDEN").as_deref() == Ok("1") {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, actual).unwrap();
        return;
    }
    let expected = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| panic!("missing golden {}; run with UPDATE_GOLDEN=1", path.display()));
    // Checkouts may use CRLF; the frame content is line-ending agnostic.
    let normalise = |text: &str| text.replace("\r\n", "\n");
    assert_eq!(normalise(actual), normalise(&expected), "golden frame `{name}` changed");
}

fn write(screen: &mut Screen, x: usize, y: usize, text: &str, style: Style) {
    screen.back_mut().put_text(x, y, text, style);
}

fn welcome(screen: &mut Screen, theme: &Theme) {
    let accent = Style::fg(theme.color(Token::Accent)).bold();
    let muted = Style::fg(theme.color(Token::Muted));
    write(screen, 2, 1, "ZERO", accent);
    write(screen, 2, 3, "Press Enter to start, Shift+Tab to change mode", Style::default());
    write(screen, 2, 5, "tip: /help lists actions · ! runs a guarded shell command", muted);
    let status = StatusModel { mode: "semi-auto".into(), model: "scripted-1".into(), ..StatusModel::default() };
    write(screen, 0, screen.height() - 1, &status.render(screen.width()), Style::fg(theme.color(status.token())));
}

fn transcript(screen: &mut Screen, theme: &Theme) {
    let user = Style::fg(theme.color(Token::UserMessage)).bold();
    let assistant = Style::fg(theme.color(Token::AssistantMessage));
    let tool = Style::fg(theme.color(Token::ToolMessage)).dim();
    write(screen, 1, 0, "you", user);
    write(screen, 1, 1, "add a bounded retry to the provider call", Style::default());
    write(screen, 1, 3, "assistant", assistant);
    write(screen, 1, 4, "I will edit the retry policy, then run the tests.", Style::default());
    write(screen, 1, 6, "tool: edit  acked (2 files)", tool);
    write(screen, 1, 7, "tool: bash  ok (cargo test)", tool);
    let status = StatusModel {
        mode: "auto".into(),
        model: "scripted-1".into(),
        budget: Some((250, 1000)),
        queue_depth: 1,
        pending_approvals: 0,
        busy: true,
    };
    write(screen, 0, screen.height() - 1, &status.render(screen.width()), Style::fg(theme.color(status.token())));
}

fn palette(screen: &mut Screen, theme: &Theme) {
    let selected = Style::fg(theme.color(Token::Selection)).inverse();
    let rows = [
        "mode.set            switch mode",
        "session.rename      name this session",
        "session.export      write a bundle",
        "doctor.run          diagnose the install",
        "review.start        run the security checklist",
        "theme.select        pick a theme",
        "actions.list        show agent-invocable actions",
        "help                generated help",
    ];
    write(screen, 2, 0, "Actions  (type to filter)", Style::fg(theme.color(Token::Accent)).bold());
    for (i, row) in rows.iter().enumerate() {
        let style = if i == 2 { selected } else { Style::default() };
        write(screen, 1, 2 + i, &format!("{}{}", if i == 2 { "> " } else { "  " }, row), style);
    }
    write(screen, 2, screen.height() - 2, "8 actions · 2 denied in plan mode", Style::fg(theme.color(Token::Muted)));
}

fn approval(screen: &mut Screen, theme: &Theme) {
    let muted = Style::fg(theme.color(Token::Muted));
    write(screen, 1, 0, "assistant", Style::fg(theme.color(Token::AssistantMessage)).bold());
    write(screen, 1, 1, "The next step writes outside the plan; asking first.", Style::default());
    let mut chrome = HostChrome::new();
    chrome.open_approval("ap-7", "write src/generated.rs", "the file is outside the approved plan");
    if let Some(lines) = chrome.render(screen.width().saturating_sub(2), theme) {
        for (i, line) in lines.iter().enumerate() {
            write(screen, 1, 4 + i, line, Style::default());
        }
    }
    write(screen, 1, screen.height() - 2, "y allow · n deny · Esc cancel", muted);
}

#[test]
fn golden_welcome_80x24() {
    let actual = snapshot("welcome-80x24", 80, 24, welcome);
    check("welcome-80x24", &actual);
}

#[test]
fn golden_transcript_100x20() {
    let actual = snapshot("transcript-100x20", 100, 20, transcript);
    check("transcript-100x20", &actual);
}

#[test]
fn golden_transcript_60x12() {
    let actual = snapshot("transcript-60x12", 60, 12, transcript);
    check("transcript-60x12", &actual);
}

#[test]
fn golden_palette_80x20() {
    let actual = snapshot("palette-80x20", 80, 20, palette);
    check("palette-80x20", &actual);
}

#[test]
fn golden_approval_80x16() {
    let actual = snapshot("approval-80x16", 80, 16, approval);
    check("approval-80x16", &actual);
}
