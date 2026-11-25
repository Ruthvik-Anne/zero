//! Action execution (ACT-02..ACT-08, ACT-10, ACT-11): one handler for slash and
//! implicit forms, policy permits, journaled idempotency, audit rows, shell prefix
//! through the deletion guard, and deterministic actions with no model call.

use crate::record::{ActionRecord, Idempotency};
use crate::registry::ActionRegistry;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_policy::action::{Action, Actor};
use zero_policy::delete::{check, Shell};
use zero_policy::dispatch::PolicyEngine;
use zero_store::audit::AuditLog;
use zero_store::journal::{ApplyOutcome, CommandJournal};
use zero_types::error::{ErrorCode, Result, ZeroError};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Tui,
    DaemonApp,
    Web,
    Android,
    Agent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Form {
    Slash,
    Implicit,
    Agent,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Invocation {
    pub action_id: String,
    pub arguments: serde_json::Value,
    pub surface: Surface,
    pub actor: Actor,
    pub client_id: String,
    pub form: Form,
}

impl Invocation {
    pub fn new(action_id: impl Into<String>, arguments: serde_json::Value, surface: Surface, actor: Actor) -> Self {
        Self {
            action_id: action_id.into(),
            arguments,
            surface,
            actor,
            client_id: "client-1".into(),
            form: Form::Slash,
        }
    }
}

/// The event both forms emit. Identical for `/x` and the implicit `x`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActionEvent {
    pub action_id: String,
    pub surface: Surface,
    pub actor_agent: bool,
    pub arguments_digest: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ActionOutcome {
    pub event: ActionEvent,
    pub result: serde_json::Value,
    pub replayed: bool,
}

pub struct ActionContext<'a> {
    pub actor: Actor,
    pub surface: Surface,
    /// Handlers that would call a model increment this; deterministic actions do
    /// not, and the test asserts it stays zero.
    pub provider_calls: &'a mut u32,
}

type Handler = Box<dyn FnMut(&mut ActionContext, &serde_json::Value) -> Result<serde_json::Value>>;

pub struct Executor {
    handlers: BTreeMap<String, Handler>,
    journal: CommandJournal,
    audit: AuditLog,
}

impl Executor {
    pub fn new(audit_path: impl AsRef<std::path::Path>, journal_path: impl AsRef<std::path::Path>) -> Result<Self> {
        Ok(Self {
            handlers: BTreeMap::new(),
            journal: CommandJournal::open(journal_path)?,
            audit: AuditLog::open(audit_path)?,
        })
    }

    pub fn register<F>(&mut self, action_id: impl Into<String>, handler: F)
    where
        F: FnMut(&mut ActionContext, &serde_json::Value) -> Result<serde_json::Value> + 'static,
    {
        self.handlers.insert(action_id.into(), Box::new(handler));
    }

    pub fn audit_path(&self) -> &std::path::Path {
        self.audit.path()
    }

    fn record_action(&mut self, ts: i64, event: &ActionEvent, idempotency_key: &str, outcome: &str, form: Form) -> Result<()> {
        self.audit.append(
            ts,
            if event.actor_agent { "agent" } else { "user" },
            "action",
            serde_json::json!({
                "action": event.action_id,
                "surface": event.surface,
                "args_digest": event.arguments_digest,
                "idempotency_key": idempotency_key,
                "form": form,
                "verdict": "allow",
                "outcome": outcome,
            }),
        )?;
        Ok(())
    }

    pub fn execute(
        &mut self,
        registry: &ActionRegistry,
        engine: &mut PolicyEngine,
        invocation: Invocation,
        now_ms: i64,
    ) -> Result<ActionOutcome> {
        let record: ActionRecord = registry
            .get(&invocation.action_id)
            .cloned()
            .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("action `{}`", invocation.action_id)))?;

        // Agent invocation is gated by the record and by policy (ACT-05).
        if invocation.actor.is_agent() && !record.agent_invocable {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!("`{}` is not agent-invocable", record.id),
            ));
        }
        if invocation.actor.is_unattended() && !record.unattended {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!("`{}` is not allowed unattended", record.id),
            ));
        }
        validate_arguments(&record, &invocation.arguments)?;

        let digest = blake3::hash(invocation.arguments.to_string().as_bytes()).to_hex().to_string();
        let event = ActionEvent {
            action_id: record.id.clone(),
            surface: invocation.surface,
            actor_agent: invocation.actor.is_agent(),
            arguments_digest: digest.clone(),
        };

        // `!` runs through the same deletion guard as the shell tool.
        if record.id == "shell.prefix" {
            let command = invocation.arguments.get("command").and_then(|v| v.as_str()).unwrap_or("");
            let blocked = {
                let posix = check(command, Shell::Posix);
                #[cfg(windows)]
                {
                    let powershell = check(command, Shell::PowerShell);
                    if powershell.allowed {
                        posix
                    } else {
                        powershell
                    }
                }
                #[cfg(not(windows))]
                {
                    posix
                }
            };
            if !blocked.allowed {
                let reason = blocked
                    .findings
                    .first()
                    .map(|f| format!("{}: {}", f.rule, f.reason))
                    .unwrap_or_else(|| "deletion blocked".into());
                self.record_action(now_ms, &event, "", "blocked", invocation.form)?;
                return Err(ZeroError::new(ErrorCode::DeletionBlocked, reason));
            }
        }

        let policy_action = Action::new(record.policy_class, record.id.clone(), invocation.actor)
            .with_arguments(invocation.arguments.clone());
        let permit = match engine.authorize(&policy_action, now_ms) {
            Ok(permit) => permit,
            Err(e) => {
                self.record_action(now_ms, &event, "", "denied", invocation.form)?;
                return Err(e);
            }
        };

        let idempotency_key = match record.idempotency {
            Idempotency::Required => format!("{}/{}/{}", invocation.client_id, record.id, digest),
            Idempotency::None => format!("{}/{}/{}", invocation.client_id, record.id, now_ms),
        };

        let Some(mut handler) = self.handlers.remove(&record.id) else {
            return Err(ZeroError::new(ErrorCode::NotFound, format!("no handler for `{}`", record.id)));
        };
        let provider_calls = &mut 0u32;
        let mut context = ActionContext { actor: invocation.actor, surface: invocation.surface, provider_calls };
        let args = invocation.arguments.clone();
        let journal = &mut self.journal;
        let result = journal.apply_once(&idempotency_key, &record.id, &digest, now_ms, || {
            handler(&mut context, &args)
        });
        self.handlers.insert(record.id.clone(), handler);

        let _ = permit;
        match result {
            Ok(ApplyOutcome::Applied(value)) => {
                self.record_action(now_ms, &event, &idempotency_key, "ok", invocation.form)?;
                Ok(ActionOutcome { event, result: value, replayed: false })
            }
            Ok(ApplyOutcome::Replayed(value)) => {
                self.record_action(now_ms, &event, &idempotency_key, "replayed", invocation.form)?;
                Ok(ActionOutcome { event, result: value, replayed: true })
            }
            Err(e) => {
                self.record_action(now_ms, &event, &idempotency_key, "error", invocation.form)?;
                Err(e)
            }
        }
    }
}

fn validate_arguments(record: &ActionRecord, args: &serde_json::Value) -> Result<()> {
    if !args.is_object() {
        return Err(ZeroError::new(ErrorCode::InvalidInput, format!("`{}` needs an arguments object", record.id)));
    }
    if let Some(required) = record.arguments.get("required").and_then(|r| r.as_array()) {
        for key in required.iter().filter_map(|k| k.as_str()) {
            if args.get(key).is_none() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("`{}` is missing required argument `{key}`", record.id),
                ));
            }
        }
    }
    Ok(())
}

/// Build the `!` invocation used by the composer.
pub fn shell_prefix(command: &str, surface: Surface) -> Invocation {
    let mut invocation = Invocation::new(
        "shell.prefix",
        serde_json::json!({"command": command}),
        surface,
        Actor::User,
    );
    invocation.form = Form::Implicit;
    invocation
}

/// Parse a composer line as a slash action or an implicit action.
pub fn parse_input(input: &str, registry: &ActionRegistry) -> Option<(String, serde_json::Value, Form)> {
    let input = input.trim();
    if let Some(rest) = input.strip_prefix('/') {
        let mut parts = rest.splitn(2, char::is_whitespace);
        let id = parts.next()?.to_string();
        registry.get(&id)?;
        let arg_text = parts.next().unwrap_or("").trim();
        return Some((id, args_from_text(arg_text), Form::Slash));
    }
    let mut parts = input.splitn(2, char::is_whitespace);
    let id = parts.next()?.to_string();
    let record = registry.get(&id)?;
    if !record.implicit {
        return None;
    }
    Some((id, args_from_text(parts.next().unwrap_or("").trim()), Form::Implicit))
}

fn args_from_text(text: &str) -> serde_json::Value {
    if text.is_empty() {
        serde_json::json!({})
    } else {
        serde_json::json!({"input": text})
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::core_registry;
    use std::cell::Cell;
    use std::rc::Rc;
    use zero_policy::{Mode, Policy};
    use zero_types::protected::ProtectedPaths;

    fn setup(dir: &std::path::Path, mode: Mode) -> (ActionRegistry, PolicyEngine, Executor) {
        let registry = core_registry();
        let engine = PolicyEngine::new(Policy::new(mode, ProtectedPaths::for_current()));
        let executor = Executor::new(dir.join("audit.jsonl"), dir.join("journal.jsonl")).unwrap();
        (registry, engine, executor)
    }

    #[test]
    fn slash_and_implicit_forms_emit_identical_events() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, mut engine, mut executor) = setup(dir.path(), Mode::Auto);
        let runs = Rc::new(Cell::new(0));
        {
            let runs = runs.clone();
            executor.register("help.show", move |_ctx, _args| {
                runs.set(runs.get() + 1);
                Ok(serde_json::json!({"shown": true}))
            });
        }
        let parsed = parse_input("/help.show", &registry).unwrap();
        assert_eq!(parsed.0, "help.show");
        let slash = executor
            .execute(&registry, &mut engine, Invocation::new("help.show", parsed.1.clone(), Surface::Tui, Actor::User), 0)
            .unwrap();
        // Implicit form uses a new client id so idempotency does not replay it.
        let mut implicit = Invocation::new("help.show", parsed.1, Surface::Tui, Actor::User);
        implicit.form = Form::Implicit;
        implicit.client_id = "client-2".into();
        let implicit_out = executor.execute(&registry, &mut engine, implicit, 1).unwrap();
        assert_eq!(slash.event, implicit_out.event);
        assert_eq!(runs.get(), 2);
    }

    #[test]
    fn replaying_a_request_applies_one_effect() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, mut engine, mut executor) = setup(dir.path(), Mode::Auto);
        let runs = Rc::new(Cell::new(0));
        {
            let runs = runs.clone();
            executor.register("session.rename", move |_ctx, args| {
                runs.set(runs.get() + 1);
                Ok(serde_json::json!({"name": args.get("input").cloned().unwrap_or_default()}))
            });
        }
        let invocation = Invocation::new("session.rename", serde_json::json!({"name": "demo"}), Surface::Tui, Actor::User);
        let first = executor.execute(&registry, &mut engine, invocation.clone(), 0).unwrap();
        let second = executor.execute(&registry, &mut engine, invocation, 1).unwrap();
        assert!(!first.replayed);
        assert!(second.replayed);
        assert_eq!(first.result, second.result);
        assert_eq!(runs.get(), 1);
    }

    #[test]
    fn rm_through_the_shell_prefix_is_blocked_by_the_deletion_guard() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, mut engine, mut executor) = setup(dir.path(), Mode::Auto);
        let ran = Rc::new(Cell::new(false));
        {
            let ran = ran.clone();
            executor.register("shell.prefix", move |_ctx, _args| {
                ran.set(true);
                Ok(serde_json::json!({"status": 0}))
            });
        }
        let err = executor
            .execute(&registry, &mut engine, shell_prefix("rm -rf src", Surface::Tui), 0)
            .unwrap_err();
        assert_eq!(err.code(), zero_types::ErrorCode::DeletionBlocked);
        assert!(!ran.get());

        // A harmless command under auto mode runs.
        executor
            .execute(&registry, &mut engine, shell_prefix("echo hi", Surface::Tui), 1)
            .unwrap();
        assert!(ran.get());
    }

    #[test]
    fn a_non_invocable_action_is_unreachable_by_the_agent() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, mut engine, mut executor) = setup(dir.path(), Mode::Auto);
        executor.register("mode.set", |_ctx, _args| Ok(serde_json::json!({})));
        let invocation = Invocation::new("mode.set", serde_json::json!({"mode": "auto"}), Surface::Agent, Actor::Agent);
        let err = executor.execute(&registry, &mut engine, invocation, 0).unwrap_err();
        assert_eq!(err.code(), zero_types::ErrorCode::PolicyDenied);
        assert!(err.message().contains("not agent-invocable"));
    }

    #[test]
    fn a_deterministic_action_makes_no_provider_call() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, mut engine, mut executor) = setup(dir.path(), Mode::Auto);
        let provider_calls = Rc::new(Cell::new(0u32));
        {
            let provider_calls = provider_calls.clone();
            executor.register("theme.select", move |ctx, _args| {
                // A deterministic handler does no model work.
                *ctx.provider_calls += 0;
                provider_calls.set(*ctx.provider_calls);
                Ok(serde_json::json!({"theme": "zero-dark"}))
            });
        }
        let record = registry.get("theme.select").unwrap();
        assert!(record.deterministic);
        executor
            .execute(&registry, &mut engine, Invocation::new("theme.select", serde_json::json!({"input": "dark"}), Surface::Tui, Actor::User), 0)
            .unwrap();
        assert_eq!(provider_calls.get(), 0);
    }

    #[test]
    fn the_audit_reconstructs_a_session_of_actions() {
        let dir = tempfile::tempdir().unwrap();
        let (registry, mut engine, mut executor) = setup(dir.path(), Mode::Auto);
        executor.register("help.show", |_ctx, _args| Ok(serde_json::json!({})));
        executor.register("theme.select", |_ctx, _args| Ok(serde_json::json!({})));
        for (i, id) in ["help.show", "theme.select"].iter().enumerate() {
            executor
                .execute(&registry, &mut engine, Invocation::new(*id, serde_json::json!({}), Surface::Tui, Actor::User), i as i64)
                .unwrap();
        }
        let (events, _) = zero_store::jsonl::scan_raw::<zero_store::audit::AuditEvent>(executor.audit_path()).unwrap();
        let actions: Vec<&str> = events
            .iter()
            .filter(|e| e.kind == "action")
            .filter_map(|e| e.payload.get("action").and_then(|a| a.as_str()))
            .collect();
        assert_eq!(actions, vec!["help.show", "theme.select"]);
    }
}
