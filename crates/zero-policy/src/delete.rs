//! Deletion guards for POSIX shells, PowerShell, and cmd (DEL-01, DEL-02, DEL-03).
//!
//! The guard parses each command segment and unwraps `sudo`, `env`, `sh -c`,
//! `cmd /c`, and PowerShell `-Command`, up to a bounded depth. It errs toward
//! blocking: a destructive command hidden behind a wrapper is still caught.
//! Exemptions (native extensions, `ctypes`, absolute-path binaries) are stated in
//! `docs/deletion-safety.md`; the trash and the overwrite journal are the
//! backstop.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Shell {
    Posix,
    PowerShell,
    Cmd,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Blocked {
    pub command: String,
    pub rule: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GuardReport {
    pub allowed: bool,
    pub findings: Vec<Blocked>,
    pub checked_segments: usize,
}

/// Check a command line for the given shell.
pub fn check(command: &str, shell: Shell) -> GuardReport {
    let mut report = GuardReport { allowed: true, findings: Vec::new(), checked_segments: 0 };
    check_recursive(command, shell, 0, &mut report);
    report
}

fn check_recursive(command: &str, shell: Shell, depth: usize, report: &mut GuardReport) {
    if depth > 4 {
        report.allowed = false;
        report.findings.push(Blocked {
            command: command.to_string(),
            rule: "wrapper_depth".into(),
            reason: "wrappers nest too deeply to verify; refusing".into(),
        });
        return;
    }
    for segment in split_segments(command) {
        report.checked_segments += 1;
        let tokens = tokenize(&segment);
        if tokens.is_empty() {
            continue;
        }
        if let Some((nested, nested_shell)) = unwrap(&tokens, shell, &segment) {
            check_recursive(&nested, nested_shell, depth + 1, report);
            continue;
        }
        if let Some((rule, reason)) = classify(&tokens, shell, &segment) {
            report.allowed = false;
            report.findings.push(Blocked { command: segment.clone(), rule: rule.into(), reason });
        }
        // Pipe targets: `... | xargs rm` or `... | Remove-Item`.
        for (i, token) in tokens.iter().enumerate() {
            if token == "xargs" {
                let rest = tokens[i + 1..].join(" ");
                if !rest.is_empty() {
                    check_recursive(&rest, shell, depth + 1, report);
                }
            }
        }
    }
}

/// Split on `;`, `&&`, `||`, and `|` outside quotes.
fn split_segments(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let chars: Vec<char> = input.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if let Some(q) = quote {
            current.push(c);
            if c == q || (q == '"' && c == '\\') {
                if c == '\\' && i + 1 < chars.len() {
                    current.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                quote = None;
            }
            i += 1;
            continue;
        }
        match c {
            '\'' | '"' => {
                quote = Some(c);
                current.push(c);
            }
            ';' | '\n' => {
                out.push(std::mem::take(&mut current));
            }
            '|' | '&' => {
                out.push(std::mem::take(&mut current));
                if i + 1 < chars.len() && (chars[i + 1] == '|' || chars[i + 1] == '&') {
                    i += 1;
                }
            }
            _ => current.push(c),
        }
        i += 1;
    }
    out.push(current);
    out.into_iter().map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect()
}

fn tokenize(segment: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut chars = segment.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == q {
                quote = None;
            } else if c == '\\' && q == '"' {
                if let Some(next) = chars.next() {
                    current.push(next);
                }
            } else {
                current.push(c);
            }
            continue;
        }
        match c {
            '\'' | '"' => quote = Some(c),
            c if c.is_whitespace() => {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
            }
            _ => current.push(c),
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

fn basename(token: &str) -> String {
    token
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(token)
        .trim_end_matches(".exe")
        .to_ascii_lowercase()
}

fn is_assignment(token: &str) -> bool {
    let Some((key, _)) = token.split_once('=') else {
        return false;
    };
    !key.is_empty() && key.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}

/// Unwrap a command that runs another command and return the inner text.
fn unwrap(tokens: &[String], shell: Shell, segment: &str) -> Option<(String, Shell)> {
    let mut i = 0;
    // Leading assignments and `env`.
    loop {
        let token = tokens.get(i)?;
        let base = basename(token);
        if is_assignment(token) {
            i += 1;
            continue;
        }
        match base.as_str() {
            "sudo" | "doas" => {
                i += 1;
                while i < tokens.len() && tokens[i].starts_with('-') {
                    i += 1;
                }
                continue;
            }
            "env" | "command" | "exec" | "nohup" | "time" => {
                i += 1;
                while i < tokens.len() && (tokens[i].starts_with('-') || is_assignment(&tokens[i])) {
                    i += 1;
                }
                continue;
            }
            "nice" => {
                i += 1;
                while i < tokens.len() && tokens[i].starts_with('-') {
                    i += 1;
                }
                if i < tokens.len() && tokens[i].parse::<i32>().is_ok() {
                    i += 1;
                }
                continue;
            }
            _ => break,
        }
    }
    let token = tokens.get(i)?;
    let base = basename(token);
    let rest = &tokens[i + 1..];
    match (shell, base.as_str()) {
        (Shell::Posix, "sh" | "bash" | "zsh" | "dash" | "ksh") => {
            // -c, or a combined short flag ending in c such as -lc.
            let c_index = rest.iter().position(|t| {
                t == "-c" || (t.starts_with('-') && !t.starts_with("--") && t.len() > 1 && t[1..].contains('c'))
            })?;
            rest.get(c_index + 1).cloned().map(|c| (c, Shell::Posix))
        }
        (Shell::Posix | Shell::Cmd, "cmd") => {
            let c_index = rest.iter().position(|t| t.eq_ignore_ascii_case("/c") || t.eq_ignore_ascii_case("/k"))?;
            Some((rest[c_index + 1..].join(" "), Shell::Cmd))
        }
        (_, "powershell" | "pwsh") => {
            let lower: Vec<String> = rest.iter().map(|t| t.to_ascii_lowercase()).collect();
            let c_index = lower.iter().position(|t| t == "-command" || t == "-c")?;
            Some((rest[c_index + 1..].join(" "), Shell::PowerShell))
        }
        (_, "python" | "python3" | "py") => {
            // A `-c` payload with a deletion call is caught by the classifier below.
            None
        }
        _ if i > 0 => {
            // A pure wrapper (sudo/env/nohup/...): classify the remainder.
            let _ = segment;
            Some((tokens[i..].join(" "), shell))
        }
        _ => {
            let _ = segment;
            None
        }
    }
}

fn classify(tokens: &[String], shell: Shell, segment: &str) -> Option<(&'static str, String)> {
    let first = basename(tokens.first()?);
    let lower: Vec<String> = tokens.iter().map(|t| t.to_ascii_lowercase()).collect();
    let args = &lower[1..];
    let has = |needle: &str| args.iter().any(|a| a == needle);

    match shell {
        Shell::Posix => match first.as_str() {
            "rm" | "unlink" | "srm" | "wipe" | "shred" => {
                Some(("delete_command", format!("`{first}` deletes files; use the `trash` tool")))
            }
            "rmdir" => Some(("delete_command", "`rmdir` deletes a directory; use `trash`".into())),
            "truncate" if has("-s") && (has("0") || args.iter().any(|a| a.starts_with("-s0"))) => {
                Some(("truncate_command", "`truncate -s 0` destroys file content".into()))
            }
            "find" if has("-delete") || (has("-exec") && args.iter().any(|a| a == "rm")) => {
                Some(("find_delete", "`find -delete` recursively deletes".into()))
            }
            "git" if args.first().map(String::as_str) == Some("clean") => {
                Some(("git_clean", "`git clean` deletes untracked files".into()))
            }
            "rsync" if has("--delete") || has("--delete-after") => {
                Some(("rsync_delete", "`rsync --delete` deletes at the destination".into()))
            }
            "dd" if args.iter().any(|a| a.starts_with("of=")) => {
                Some(("dd_overwrite", "`dd of=` overwrites a file outside the journal".into()))
            }
            _ => scan_inline_deletion(segment),
        },
        Shell::PowerShell => match first.as_str() {
            "remove-item" | "del" | "erase" | "rd" | "rmdir" | "ri" | "rm" => Some((
                "delete_command",
                format!("`{first}` deletes files; use the `trash` tool"),
            )),
            "clear-content" | "clc" => Some(("truncate_command", "`Clear-Content` destroys content".into())),
            "cmd" if args.iter().any(|a| a == "/c") => Some(("wrapper", "cmd /c inside PowerShell".into())),
            _ => {
                if segment.to_ascii_lowercase().contains("system.io.file]::delete")
                    || segment.to_ascii_lowercase().contains("system.io.directory]::delete")
                {
                    Some(("dotnet_delete", "the .NET delete API bypasses the guard".into()))
                } else {
                    scan_inline_deletion(segment)
                }
            }
        },
        Shell::Cmd => match first.as_str() {
            "del" | "erase" | "rd" | "rmdir" | "format" => {
                Some(("delete_command", format!("`{first}` deletes files or a volume")))
            }
            _ => scan_inline_deletion(segment),
        },
    }
}

fn scan_inline_deletion(segment: &str) -> Option<(&'static str, String)> {
    let lower = segment.to_ascii_lowercase();
    for needle in ["os.remove(", "os.unlink(", "os.rmdir(", "os.removedirs(", "shutil.rmtree(", ".unlink(", ".rmdir(", "os.truncate("] {
        if lower.contains(needle) {
            return Some(("inline_delete", format!("the inline code calls `{needle}`; use the `trash` tool")));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    const POSIX_DESTRUCTIVE: &[&str] = &[
        "rm old.txt",
        "rm -rf build",
        "sudo rm -rf /var/tmp/x",
        "env FOO=1 rm -f a",
        "sh -c 'rm -rf src'",
        "bash -lc \"rm -rf src\"",
        "/bin/rm -rf src",
        "unlink a.txt",
        "rmdir empty",
        "find . -name '*.tmp' -delete",
        "find . -exec rm {} ;",
        "git clean -fdx",
        "rsync -a --delete src/ dst/",
        "dd if=/dev/zero of=disk.img",
        "truncate -s 0 log.txt",
        "echo hi | xargs rm -f",
        "python -c 'import os; os.remove(\"a\")'",
    ];

    const POWERSHELL_DESTRUCTIVE: &[&str] = &[
        "Remove-Item -Recurse -Force build",
        "del old.txt",
        "erase old.txt",
        "rd /s /q build",
        "rmdir build",
        "Clear-Content log.txt",
        "Get-ChildItem *.tmp | Remove-Item",
        "[System.IO.File]::Delete('a.txt')",
        "powershell -Command \"Remove-Item -Recurse build\"",
        "cmd /c del old.txt",
    ];

    const CMD_DESTRUCTIVE: &[&str] = &[
        "del old.txt",
        "erase /f old.txt",
        "rd /s /q build",
        "rmdir build",
        "format D:",
        "cmd /c del /f old.txt",
    ];

    const SAFE: &[(&str, Shell)] = &[
        ("ls -la", Shell::Posix),
        ("grep -r rm src", Shell::Posix),
        ("echo 'rm -rf /'", Shell::Posix),
        ("cat notes.txt", Shell::Posix),
        ("git status", Shell::Posix),
        ("cargo test", Shell::Posix),
        ("Get-ChildItem", Shell::PowerShell),
        ("Write-Output 'Remove-Item'", Shell::PowerShell),
        ("dir", Shell::Cmd),
        ("echo del", Shell::Cmd),
    ];

    #[test]
    fn the_destructive_corpus_has_zero_false_allows() {
        for command in POSIX_DESTRUCTIVE {
            let report = check(command, Shell::Posix);
            assert!(!report.allowed, "POSIX false allow: {command}");
            assert!(!report.findings.is_empty());
        }
        for command in POWERSHELL_DESTRUCTIVE {
            let report = check(command, Shell::PowerShell);
            assert!(!report.allowed, "PowerShell false allow: {command}");
        }
        for command in CMD_DESTRUCTIVE {
            let report = check(command, Shell::Cmd);
            assert!(!report.allowed, "cmd false allow: {command}");
        }
    }

    #[test]
    fn safe_commands_are_not_blocked() {
        for (command, shell) in SAFE {
            let report = check(command, *shell);
            assert!(report.allowed, "false block: {command} -> {:?}", report.findings);
        }
    }

    #[test]
    fn wrappers_are_unwrapped_and_bounded() {
        let deep = "sudo env A=1 sh -c 'bash -c \"sh -c \\\"rm -rf x\\\"\"'";
        let report = check(deep, Shell::Posix);
        assert!(!report.allowed);
        assert!(report.findings.iter().any(|f| f.rule == "delete_command" || f.rule == "wrapper_depth"));
    }

    #[test]
    fn a_quoted_mention_is_not_a_command() {
        let report = check("echo \"please do not run rm -rf /\"", Shell::Posix);
        assert!(report.allowed);
    }
}
