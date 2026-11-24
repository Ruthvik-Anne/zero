//! Compaction (SES-03): cut-point rules, hooks, and retained recent state.
//!
//! Cutting never orphans a tool result: if the cut would start at a `tool`
//! message, it moves back to the assistant message that made the call.

use zero_store::session::{Entry, Record, Role, SessionLog};
use zero_types::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CompactionConfig {
    /// Recent user/assistant messages to keep verbatim.
    pub keep_recent_messages: usize,
    /// Do not compact when fewer entries would be removed.
    pub min_removed: usize,
}

impl Default for CompactionConfig {
    fn default() -> Self {
        Self { keep_recent_messages: 8, min_removed: 2 }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompactionOutcome {
    pub compacted: bool,
    pub removed_entries: u64,
    pub kept_messages: usize,
    pub keep_from_seq: u64,
    pub generation: u64,
    pub reason: String,
}

/// Hooks run around the compaction marker. Each may append entries (for example
/// a custom "compaction.note") and returns whether it did.
pub trait CompactionHook {
    fn before(&mut self, _log: &mut SessionLog, _records: &[Record]) -> Result<()> {
        Ok(())
    }
    fn after(&mut self, _log: &mut SessionLog, _outcome: &CompactionOutcome) -> Result<()> {
        Ok(())
    }
}

fn is_message(entry: &Entry) -> bool {
    matches!(entry, Entry::Message { .. })
}

/// Compute the seq to keep from, or None when there is nothing to cut.
pub fn cut_point(records: &[Record], config: CompactionConfig) -> Option<usize> {
    let message_indices: Vec<usize> = records
        .iter()
        .enumerate()
        .filter(|(_, r)| is_message(&r.entry))
        .map(|(i, _)| i)
        .collect();
    if message_indices.len() <= config.keep_recent_messages {
        return None;
    }
    let mut cut = message_indices[message_indices.len() - config.keep_recent_messages];
    // Never start the retained tail with a tool result.
    loop {
        let starts_with_tool = matches!(
            &records.get(cut).map(|r| &r.entry),
            Some(Entry::Message { role: Role::Tool, .. })
        );
        if !starts_with_tool {
            break;
        }
        if cut == 0 {
            return None;
        }
        cut -= 1;
    }
    let removed = records[..cut].iter().filter(|r| is_message(&r.entry)).count();
    if removed < config.min_removed {
        return None;
    }
    Some(cut)
}

pub fn compact(
    log: &mut SessionLog,
    summary: &str,
    config: CompactionConfig,
    hooks: &mut [&mut dyn CompactionHook],
    now_ms: i64,
) -> Result<CompactionOutcome> {
    let records = log.records()?;
    let Some(cut) = cut_point(&records, config) else {
        return Ok(CompactionOutcome {
            compacted: false,
            removed_entries: 0,
            kept_messages: records.iter().filter(|r| is_message(&r.entry)).count(),
            keep_from_seq: 0,
            generation: log.meta().generation,
            reason: "not enough messages before the cut point".into(),
        });
    };
    let keep_from_seq = records[cut].seq;
    let removed_entries = records[..cut].iter().filter(|r| is_message(&r.entry)).count() as u64;
    let kept_messages = records[cut..].iter().filter(|r| is_message(&r.entry)).count();

    for hook in hooks.iter_mut() {
        hook.before(log, &records)?;
    }
    log.append(
        now_ms,
        Entry::Compaction {
            summary: summary.to_string(),
            keep_from_seq,
            removed_entries,
        },
    )?;
    let generation = log.bump_generation()?;
    let outcome = CompactionOutcome {
        compacted: true,
        removed_entries,
        kept_messages,
        keep_from_seq,
        generation,
        reason: format!("kept the last {kept_messages} messages"),
    };
    for hook in hooks.iter_mut() {
        hook.after(log, &outcome)?;
    }
    Ok(outcome)
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_store::session::{SessionMeta, ENTRY_SCHEMA_VERSION};

    fn new_log(dir: &std::path::Path) -> SessionLog {
        SessionLog::create(
            dir.join("s.jsonl"),
            SessionMeta {
                schema: ENTRY_SCHEMA_VERSION,
                generation: 1,
                created_ts: 0,
                name: "compact".into(),
                project: None,
                parent: None,
            },
        )
        .unwrap()
    }

    fn msg(role: Role, text: &str) -> Entry {
        Entry::Message { role, text: text.into(), tool_calls: vec![], tool_call_id: None }
    }

    struct CountingHook {
        before_calls: u32,
        after_calls: u32,
    }

    impl CompactionHook for CountingHook {
        fn before(&mut self, log: &mut SessionLog, _records: &[Record]) -> Result<()> {
            self.before_calls += 1;
            log.append(0, Entry::Custom { name: "hook.before".into(), data: serde_json::json!({}) })?;
            Ok(())
        }
        fn after(&mut self, log: &mut SessionLog, outcome: &CompactionOutcome) -> Result<()> {
            self.after_calls += 1;
            log.append(0, Entry::Custom { name: "hook.after".into(), data: serde_json::json!(outcome.generation) })?;
            Ok(())
        }
    }

    #[test]
    fn long_session_compacts_without_losing_the_visible_tail_or_kernel_state() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = new_log(dir.path());
        for i in 0..100 {
            let role = if i % 2 == 0 { Role::User } else { Role::Assistant };
            log.append(1000 + i, msg(role, &format!("m{i}"))).unwrap();
        }
        log.append(2000, Entry::State { key: "kernel.var.counter".into(), value: serde_json::json!(42) })
            .unwrap();

        let mut hook = CountingHook { before_calls: 0, after_calls: 0 };
        let outcome = compact(
            &mut log,
            "goal: keep going",
            CompactionConfig { keep_recent_messages: 8, min_removed: 2 },
            &mut [&mut hook],
            3000,
        )
        .unwrap();

        assert!(outcome.compacted);
        assert_eq!(outcome.removed_entries, 92);
        assert_eq!(outcome.kept_messages, 8);
        assert_eq!(outcome.generation, 2);
        assert_eq!(hook.before_calls, 1);
        assert_eq!(hook.after_calls, 1);

        let visible = log.visible_records().unwrap();
        let texts: Vec<&str> = visible.iter().filter_map(|r| r.entry.message_text()).collect();
        assert_eq!(texts, vec!["m92", "m93", "m94", "m95", "m96", "m97", "m98", "m99"]);
        assert!(visible.iter().any(|r| matches!(&r.entry, Entry::State { key, .. } if key == "kernel.var.counter")));
        assert!(visible.iter().any(|r| matches!(r.entry, Entry::Compaction { .. })));
        assert!(visible.iter().any(|r| matches!(&r.entry, Entry::Custom { name, .. } if name == "hook.before")));
        assert!(visible.iter().any(|r| matches!(&r.entry, Entry::Custom { name, .. } if name == "hook.after")));
    }

    #[test]
    fn cut_never_orphans_a_tool_result() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = new_log(dir.path());
        for i in 0..8 {
            log.append(i, msg(Role::User, &format!("u{i}"))).unwrap();
        }
        log.append(8, msg(Role::Assistant, "calling")).unwrap();
        log.append(9, msg(Role::Tool, "result")).unwrap();

        let records = log.records().unwrap();
        let cut = cut_point(&records, CompactionConfig { keep_recent_messages: 1, min_removed: 2 }).unwrap();
        let first_kept = &records[cut];
        assert!(
            !matches!(&first_kept.entry, Entry::Message { role: Role::Tool, .. }),
            "retained tail must not start with a tool result"
        );
        // It moved back to the assistant message that called the tool.
        assert_eq!(first_kept.entry.message_text(), Some("calling"));
    }

    #[test]
    fn short_sessions_do_not_compact() {
        let dir = tempfile::tempdir().unwrap();
        let mut log = new_log(dir.path());
        log.append(0, msg(Role::User, "one")).unwrap();
        log.append(1, msg(Role::Assistant, "two")).unwrap();
        let outcome = compact(
            &mut log,
            "s",
            CompactionConfig::default(),
            &mut [],
            2,
        )
        .unwrap();
        assert!(!outcome.compacted);
        assert_eq!(outcome.removed_entries, 0);
        assert_eq!(log.meta().generation, 1);
    }
}
