//! `zero-guard` — the shim entry point. Exits 0 when the command is allowed and
//! 3 when the deletion guard blocks it. Invoked by PATH and PowerShell shims.

use std::process::ExitCode;
use zero_policy::delete::{check, Shell};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(shell_name) = args.first() else {
        eprintln!("usage: zero-guard <posix|powershell|cmd> <program> [args...]");
        return ExitCode::from(2);
    };
    let shell = match shell_name.as_str() {
        "posix" => Shell::Posix,
        "powershell" => Shell::PowerShell,
        "cmd" => Shell::Cmd,
        other => {
            eprintln!("zero-guard: unknown shell `{other}`");
            return ExitCode::from(2);
        }
    };
    let command = args[1..].join(" ");
    let report = check(&command, shell);
    if report.allowed {
        ExitCode::SUCCESS
    } else {
        for finding in &report.findings {
            eprintln!("zero-guard: blocked ({}): {} — {}", finding.rule, finding.command, finding.reason);
        }
        eprintln!("zero-guard: use the `trash` tool or the host UI to delete");
        ExitCode::from(3)
    }
}
