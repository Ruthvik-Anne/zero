//! Line-mode test client (SES-12): drives the agent loop over stdin/stdout with
//! no terminal. Test-only; it is reached through the permitted `resume` verb.

use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::Arc;
use zero_agent::queue::MessageQueue;
use zero_agent::{tool_registry_with_core, AgentLoop, LoopConfig};
use zero_model::{ScriptTurn, ScriptedProvider, StopReason, ToolCall, Usage};
use zero_store::journal::CommandJournal;
use zero_store::session::{Entry, Role, SessionLog, SessionMeta, ENTRY_SCHEMA_VERSION};
use zero_types::id::{Clock, SystemClock};

#[derive(serde::Deserialize)]
struct Script {
    #[serde(default)]
    turns: Vec<TurnScript>,
}

#[derive(serde::Deserialize)]
struct TurnScript {
    #[serde(default)]
    text: String,
    #[serde(default)]
    thinking: String,
    #[serde(default)]
    tool_calls: Vec<CallScript>,
    #[serde(default)]
    usage: Usage,
    #[serde(default)]
    stop: Option<String>,
}

#[derive(serde::Deserialize)]
struct CallScript {
    #[serde(default)]
    id: String,
    name: String,
    #[serde(default)]
    arguments: serde_json::Value,
}

fn load_script(path: &Path) -> Result<Vec<ScriptTurn>, String> {
    let text = std::fs::read_to_string(path).map_err(|e| format!("{}: {e}", path.display()))?;
    let script: Script = serde_json::from_str(&text).map_err(|e| format!("script: {e}"))?;
    let mut turns = Vec::new();
    for (i, turn) in script.turns.into_iter().enumerate() {
        let tool_calls: Vec<ToolCall> = turn
            .tool_calls
            .into_iter()
            .map(|c| ToolCall {
                id: if c.id.is_empty() { format!("call-{i}") } else { c.id },
                name: c.name,
                arguments: c.arguments,
            })
            .collect();
        let stop = match turn.stop.as_deref() {
            Some("tool_calls") => StopReason::ToolCalls,
            Some("max_tokens") => StopReason::MaxTokens,
            Some("cancelled") => StopReason::Cancelled,
            Some("content_filter") => StopReason::ContentFilter,
            _ => {
                if tool_calls.is_empty() {
                    StopReason::EndTurn
                } else {
                    StopReason::ToolCalls
                }
            }
        };
        turns.push(ScriptTurn {
            text: turn.text,
            thinking: turn.thinking,
            tool_calls,
            usage: turn.usage,
            stop,
            fail: None,
        });
    }
    Ok(turns)
}

fn print_new_records(log: &SessionLog, from: usize) -> Result<(), String> {
    let records = log.records().map_err(|e| e.to_string())?;
    for record in records.iter().skip(from) {
        match &record.entry {
            Entry::Message { role: Role::Assistant, text, tool_calls, .. } => {
                if !text.is_empty() {
                    println!("assistant: {text}");
                }
                for call in tool_calls {
                    println!("call: {} {}", call.name, call.id);
                }
            }
            Entry::Message { role: Role::Tool, text, .. } => {
                println!("tool: {}", text.replace('\n', "\\n"));
            }
            Entry::Custom { name, data } if name == "turn" => {
                let turn = data.get("turn").and_then(|v| v.as_u64()).unwrap_or(0);
                let stop = data.get("stop").and_then(|v| v.as_str()).unwrap_or("?");
                println!("turn {turn}: stop={stop}");
            }
            Entry::Status { state } => println!("status: {state}"),
            _ => {}
        }
    }
    Ok(())
}

/// Run the interactive line client until EOF or `/quit`.
pub fn line_mode(args: &[String]) -> ExitCode {
    let data = match take_value(args, "--data-dir") {
        Some(d) => PathBuf::from(d),
        None => zero_types::paths::current(zero_types::paths::PathKind::Data),
    };
    let sessions = data.join("sessions");
    if let Err(e) = std::fs::create_dir_all(&sessions) {
        eprintln!("line: cannot create {}: {e}", sessions.display());
        return ExitCode::FAILURE;
    }
    let name = take_value(args, "--session").unwrap_or_else(|| "line".to_string());
    let script_path = match take_value(args, "--script") {
        Some(p) => PathBuf::from(p),
        None => {
            eprintln!("line: --script is required (this client is test-only)");
            return ExitCode::from(2);
        }
    };
    let turns = match load_script(&script_path) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("line: {e}");
            return ExitCode::FAILURE;
        }
    };

    let log_path = sessions.join(format!("{name}.jsonl"));
    let log = match SessionLog::open(&log_path) {
        Ok(log) => {
            println!("line: resumed {}", log_path.display());
            log
        }
        Err(_) => {
            let log = match SessionLog::create(
                &log_path,
                SessionMeta {
                    schema: ENTRY_SCHEMA_VERSION,
                    generation: 1,
                    created_ts: SystemClock.now().millis(),
                    name: name.clone(),
                    project: None,
                    parent: None,
                },
            ) {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("line: cannot create session: {e}");
                    return ExitCode::FAILURE;
                }
            };
            println!("line: created {}", log_path.display());
            log
        }
    };
    let journal = match CommandJournal::open(sessions.join(format!("{name}.journal.jsonl"))) {
        Ok(j) => j,
        Err(e) => {
            eprintln!("line: journal: {e}");
            return ExitCode::FAILURE;
        }
    };
    let queue = match MessageQueue::open(sessions.join(format!("{name}.queue.json")), 32) {
        Ok(q) => q,
        Err(e) => {
            eprintln!("line: queue: {e}");
            return ExitCode::FAILURE;
        }
    };
    let mut tools = tool_registry_with_core();
    let mut agent = AgentLoop::new(
        Box::new(ScriptedProvider::new(turns)),
        std::mem::take(&mut tools),
        journal,
        log,
        Some(queue),
        LoopConfig {
            model: "scripted-1".into(),
            system: Some("line-mode test client".into()),
            ..LoopConfig::default()
        },
        zero_policy::PolicyEngine::new(zero_policy::Policy::new(
            zero_policy::Mode::Auto,
            zero_types::protected::ProtectedPaths::for_current(),
        )),
        Arc::new(SystemClock),
    );

    let stdin = std::io::stdin();
    let mut input = stdin.lock();
    let mut line = String::new();
    loop {
        print!("> ");
        let _ = std::io::stdout().flush();
        line.clear();
        match input.read_line(&mut line) {
            Ok(0) | Err(_) => break,
            Ok(_) => {}
        }
        let text = line.trim();
        if text.is_empty() {
            continue;
        }
        if text == "/quit" {
            println!("bye");
            break;
        }
        if let Some(steer) = text.strip_prefix("/steer ") {
            match agent.queue.as_mut().map(|q| q.enqueue(steer.to_string(), zero_agent::queue::Delivery::Steer)) {
                Some(Ok(item)) => println!("queued: {}", item.id),
                Some(Err(e)) => println!("queue error: {}", e.message()),
                None => println!("queue unavailable"),
            }
            continue;
        }
        if text == "/cancel" {
            agent.cancel.cancel();
            println!("cancel requested");
            continue;
        }
        let before = agent.log.records().map(|r| r.len()).unwrap_or(0);
        match agent.run(text) {
            Ok(outcome) => {
                if let Err(e) = print_new_records(&agent.log, before) {
                    eprintln!("line: {e}");
                }
                println!(
                    "usage: in={} out={} uncertain={} cancelled={}",
                    outcome.usage.input_tokens,
                    outcome.usage.output_tokens,
                    outcome.uncertain.len(),
                    outcome.cancelled
                );
                if !outcome.final_text.is_empty() {
                    println!("final: {}", outcome.final_text.replace('\n', "\\n"));
                }
                agent.cancel.reset();
            }
            Err(e) => {
                println!("error: {} — {}", e.code().as_str(), e.message());
            }
        }
    }
    ExitCode::SUCCESS
}

fn take_value(args: &[String], flag: &str) -> Option<String> {
    args.iter().position(|a| a == flag).and_then(|i| args.get(i + 1)).cloned()
}
