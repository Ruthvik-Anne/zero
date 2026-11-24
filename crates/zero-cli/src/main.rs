//! `zero` CLI shell (FND-11, ACT-10).
//!
//! The command line is limited to the product verbs: `resume`, `login`,
//! `logout`, `doctor`, plus `install`, `update`, `uninstall`, `service`, and
//! completion. Anything else prints the closest action name and exits non-zero.

mod line;

use std::path::PathBuf;
use std::process::ExitCode;
use zero_store::sqlite::SqliteStore;
use zero_types::ErrorCode;
use zero_types::paths::{self, PathKind};

const VERSION: &str = env!("CARGO_PKG_VERSION");
const PROTOCOL: u16 = zero_types::proto::PROTOCOL_VERSION;

const VERBS: &[&str] = &[
    "resume",
    "login",
    "logout",
    "doctor",
    "install",
    "update",
    "uninstall",
    "service",
    "completion",
];

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.iter().any(|a| a == "--version" || a == "-V") {
        println!("zero {VERSION} (protocol {PROTOCOL})");
        return ExitCode::SUCCESS;
    }
    if args.is_empty() || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
        print_help();
        return ExitCode::SUCCESS;
    }

    let verb = args[0].as_str();
    let rest = &args[1..];
    match verb {
        "resume" => resume(rest),
        "login" => login(rest),
        "logout" => logout(rest),
        "doctor" => doctor(rest),
        "install" => install(rest),
        "update" => update(rest),
        "uninstall" => uninstall(rest),
        "service" => service(rest),
        "completion" => completion(rest),
        other => {
            match closest(other) {
                Some(action) => {
                    eprintln!("unknown verb `{other}`; the matching action is `{action}`");
                }
                None => {
                    eprintln!("unknown verb `{other}`; no matching action");
                }
            }
            eprintln!("run `zero --help` for the permitted verbs");
            ExitCode::from(2)
        }
    }
}

fn print_help() {
    println!(
        "zero {VERSION} — the action registry owns every command.

usage: zero <verb> [options]

verbs:
  resume [--list] [--session ID]   resume or list sessions
  resume --line --script FILE      test-only line client (no terminal)
  login <provider>                 sign in to a provider
  logout <provider>                remove a provider's credentials
  doctor [--json]                  diagnose this installation
  install [--non-interactive]      install binaries and services
  update [--check]                 apply or check a signed update
  uninstall [--purge]              remove Zero; offer to trash its data
  service <status|start|stop>      manage the background service
  completion <shell>               print shell completion

global: --data-dir DIR, --version"
    );
}

fn take_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}

fn data_root(args: &[String]) -> PathBuf {
    match take_value(args, "--data-dir") {
        Some(d) => PathBuf::from(d),
        None => paths::current(PathKind::Data),
    }
}

fn resume(args: &[String]) -> ExitCode {
    let root = data_root(args);
    let sessions = root.join("sessions");
    let list = args.iter().any(|a| a == "--list") || args.is_empty();
    if list {
        let mut found = 0;
        if sessions.exists() {
            if let Ok(entries) = std::fs::read_dir(&sessions) {
                for entry in entries.flatten() {
                    if entry.path().extension().and_then(|e| e.to_str()) == Some("jsonl") {
                        println!("{}", entry.path().display());
                        found += 1;
                    }
                }
            }
        }
        if found == 0 {
            println!("no saved sessions in {}", sessions.display());
        }
        return ExitCode::SUCCESS;
    }
    let Some(id) = take_value(args, "--session") else {
        if args.iter().any(|a| a == "--line") {
            return line::line_mode(args);
        }
        eprintln!("resume: pass --session ID or --list");
        return ExitCode::from(2);
    };
    if args.iter().any(|a| a == "--line") {
        return line::line_mode(args);
    }
    let log = sessions.join(format!("{id}.jsonl"));
    if !log.exists() {
        report_error(ErrorCode::SessionNotFound, &format!("session `{id}` at {}", log.display()));
        return ExitCode::FAILURE;
    }
    println!("resuming {} (attach arrives with the worker supervisor)", log.display());
    ExitCode::SUCCESS
}

fn login(args: &[String]) -> ExitCode {
    let Some(provider) = args.first().filter(|a| !a.starts_with('-')) else {
        eprintln!("login: name a provider, for example `zero login openai`");
        return ExitCode::from(2);
    };
    // The credential store lands in M5. Until then, say so instead of pretending.
    report_error(
        ErrorCode::Unavailable,
        &format!("credential storage for `{provider}` is not built in this milestone"),
    );
    ExitCode::FAILURE
}

fn logout(args: &[String]) -> ExitCode {
    let Some(provider) = args.first().filter(|a| !a.starts_with('-')) else {
        eprintln!("logout: name a provider");
        return ExitCode::from(2);
    };
    println!("no stored credential for `{provider}` in this installation");
    ExitCode::SUCCESS
}

fn doctor(args: &[String]) -> ExitCode {
    let json = args.iter().any(|a| a == "--json");
    let data = data_root(args);
    let config = match take_value(args, "--data-dir") {
        Some(_) => data.join("config"),
        None => paths::current(PathKind::Config),
    };
    let state = match take_value(args, "--data-dir") {
        Some(_) => data.join("state"),
        None => paths::current(PathKind::State),
    };
    let cache = match take_value(args, "--data-dir") {
        Some(_) => data.join("cache"),
        None => paths::current(PathKind::Cache),
    };

    let mut checks: Vec<(String, Result<String, String>)> = Vec::new();
    for (name, dir) in [
        ("data_dir", &data),
        ("config_dir", &config),
        ("state_dir", &state),
        ("cache_dir", &cache),
    ] {
        checks.push((name.into(), probe_dir(dir)));
    }
    checks.push(("store".into(), probe_store(&data.join("store").join("zero.db"))));
    checks.push((
        "offline".into(),
        Ok("local operation does not require a network".into()),
    ));

    let failed = checks.iter().filter(|(_, r)| r.is_err()).count();
    if json {
        let rows: Vec<serde_json::Value> = checks
            .iter()
            .map(|(name, r)| {
                serde_json::json!({
                    "check": name,
                    "status": if r.is_ok() { "ok" } else { "fail" },
                    "detail": match r { Ok(d) => d.clone(), Err(e) => e.clone() },
                })
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&serde_json::json!({"checks": rows})).unwrap());
    } else {
        println!("doctor: {} checks, {} failed", checks.len(), failed);
        for (name, result) in &checks {
            match result {
                Ok(detail) => println!("  ok    {name}: {detail}"),
                Err(detail) => println!("  FAIL  {name}: {detail}"),
            }
        }
        println!("versions: zero {VERSION}, protocol {PROTOCOL}, os {}", std::env::consts::OS);
    }
    if failed == 0 {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    }
}

fn probe_dir(dir: &PathBuf) -> Result<String, String> {
    std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
    let probe = dir.join(".zero-write-probe");
    std::fs::write(&probe, b"ok").map_err(|e| format!("not writable: {e}"))?;
    let _ = std::fs::remove_file(&probe);
    Ok(dir.display().to_string())
}

fn probe_store(path: &PathBuf) -> Result<String, String> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    let store = SqliteStore::open(path).map_err(|e| e.to_string())?;
    let version = store.schema_version().map_err(|e| e.to_string())?;
    Ok(format!("schema {version}, journal {}, {}", store.journal_mode().unwrap_or_default(), path.display()))
}

fn install(args: &[String]) -> ExitCode {
    let non_interactive = args.iter().any(|a| a == "--non-interactive");
    println!("install: verified installer wiring lands with the release milestone");
    println!("  mode: {}", if non_interactive { "non-interactive" } else { "interactive" });
    ExitCode::SUCCESS
}

fn update(args: &[String]) -> ExitCode {
    if args.iter().any(|a| a == "--check") {
        println!("update: no signed release channel is configured in this build");
        return ExitCode::SUCCESS;
    }
    println!("update: nothing to apply (unsigned development build)");
    ExitCode::SUCCESS
}

fn uninstall(args: &[String]) -> ExitCode {
    let purge = args.iter().any(|a| a == "--purge");
    println!(
        "uninstall: remove services and PATH entries; user data {}",
        if purge { "will be offered for trash after confirmation" } else { "is kept" }
    );
    ExitCode::SUCCESS
}

fn service(args: &[String]) -> ExitCode {
    match args.first().map(String::as_str) {
        Some("status") => {
            println!("service: not installed");
            ExitCode::SUCCESS
        }
        Some("start") | Some("stop") => {
            report_error(ErrorCode::Unavailable, "no service unit is installed");
            ExitCode::FAILURE
        }
        _ => {
            eprintln!("service: expected status, start, or stop");
            ExitCode::from(2)
        }
    }
}

fn completion(args: &[String]) -> ExitCode {
    let shell = args.first().map(String::as_str).unwrap_or("");
    match shell {
        "bash" => println!(
            "complete -W \"{}\" zero",
            VERBS.join(" ")
        ),
        "zsh" => println!(
            "#compdef zero\n_arguments '1:verb:({})'",
            VERBS.join(" ")
        ),
        "fish" => {
            for v in VERBS {
                println!("complete -c zero -f -a {v}");
            }
        }
        "powershell" => {
            println!(
                "Register-ArgumentCompleter -Native -CommandName zero -ScriptBlock {{ param($wordToComplete) '{}' -split ' ' | Where-Object {{ $_ -like \"$wordToComplete*\" }} }}",
                VERBS.join(" ")
            );
        }
        _ => {
            eprintln!("completion: expected bash, zsh, fish, or powershell");
            return ExitCode::from(2);
        }
    }
    ExitCode::SUCCESS
}

fn report_error(code: ErrorCode, message: &str) {
    eprintln!("error {}: {message}", code.as_str());
    eprintln!("  {}", code.remediation());
}

/// Closest permitted verb, or None when nothing is close enough.
fn closest(input: &str) -> Option<&'static str> {
    let mut best: Option<(&'static str, usize)> = None;
    for verb in VERBS {
        let d = levenshtein(input, verb);
        if d <= 3 && best.map(|(_, bd)| d < bd).unwrap_or(true) {
            best = Some((verb, d));
        }
    }
    best.map(|(v, _)| v)
}

fn levenshtein(a: &str, b: &str) -> usize {
    let a: Vec<char> = a.chars().collect();
    let b: Vec<char> = b.chars().collect();
    let mut prev: Vec<usize> = (0..=b.len()).collect();
    let mut cur = vec![0usize; b.len() + 1];
    for i in 1..=a.len() {
        cur[0] = i;
        for j in 1..=b.len() {
            let cost = if a[i - 1] == b[j - 1] { 0 } else { 1 };
            cur[j] = (prev[j] + 1).min(cur[j - 1] + 1).min(prev[j - 1] + cost);
        }
        std::mem::swap(&mut prev, &mut cur);
    }
    prev[b.len()]
}
