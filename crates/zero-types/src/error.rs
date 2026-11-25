//! Stable error taxonomy (FND-07).
//!
//! Every error carries a code from [`ErrorCode`], a stable string, and exactly
//! one remediation line. `docs/errors.md` is compared against [`ErrorCode::ALL`]
//! by a test, so an undocumented or duplicate code fails the build.

use std::fmt;

macro_rules! codes {
    ($( $variant:ident => $code:literal, $remediation:literal; )*) => {
        /// Stable, documented error code.
        #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
        pub enum ErrorCode {
            $( $variant, )*
        }

        impl ErrorCode {
            /// All codes in declaration order.
            pub const ALL: &'static [ErrorCode] = &[ $( ErrorCode::$variant, )* ];

            /// The wire code, e.g. `zero.ses.lease_held`.
            pub const fn as_str(self) -> &'static str {
                match self { $( ErrorCode::$variant => $code, )* }
            }

            /// The single remediation line shown to a user.
            pub const fn remediation(self) -> &'static str {
                match self { $( ErrorCode::$variant => $remediation, )* }
            }
        }
    };
}

codes! {
    // Foundations
    Internal => "zero.fnd.internal", "Report this with `zero doctor` output attached.";
    InvalidInput => "zero.fnd.invalid_input", "Check the value and retry with a valid one.";
    NotFound => "zero.fnd.not_found", "Check the path or identifier and retry.";
    AlreadyExists => "zero.fnd.already_exists", "Use the existing item or pick another name.";
    PermissionDenied => "zero.fnd.permission_denied", "Fix the file or directory permissions and retry.";
    Io => "zero.fnd.io", "Check the path, free space, and permissions, then retry.";
    Serialization => "zero.fnd.serialization", "The stored data is malformed; run `zero doctor` to inspect it.";
    SchemaVersion => "zero.fnd.schema_version", "Run the migration command; downgrades are refused.";
    MigrationFailed => "zero.fnd.migration_failed", "Restore the backup named in the message and retry.";
    ConfigInvalid => "zero.fnd.config_invalid", "Correct the reported config file and retry.";
    LimitExceeded => "zero.fnd.limit_exceeded", "Raise the limit in config or reduce the work.";
    ResourceExhausted => "zero.fnd.resource_exhausted", "Free the resource named in the message and retry.";
    Offline => "zero.fnd.offline", "Reconnect or configure a local model; the operation needs no network otherwise.";
    Unavailable => "zero.fnd.unavailable", "Enable the feature in config or install its prerequisite.";
    Cancelled => "zero.fnd.cancelled", "Retry when ready.";
    Timeout => "zero.fnd.timeout", "Retry, or raise the timeout in config.";
    Unsupported => "zero.fnd.unsupported", "Use a supported platform or option.";
    Corrupt => "zero.fnd.corrupt", "Restore from backup or run `zero doctor --repair`.";

    // Sessions
    SessionNotFound => "zero.ses.not_found", "List sessions with `zero resume` and pick an existing one.";
    SessionClosed => "zero.ses.closed", "Reopen the session or start a new one.";
    SessionLeaseHeld => "zero.ses.lease_held", "Attach to the running worker or stop it first.";
    SessionCorrupt => "zero.ses.corrupt", "Run `zero doctor`; the log has an unparseable record.";
    ForkFailed => "zero.ses.fork_failed", "Fork from an existing entry id.";
    CompactionFailed => "zero.ses.compaction_failed", "Keep more recent messages or raise the context budget.";
    SummaryInvalid => "zero.ses.summary_invalid", "Regenerate the branch summary; one of six sections is missing.";
    ContextTooLarge => "zero.ses.context_too_large", "Trim the context file or raise the size cap.";
    AttachCursorExpired => "zero.ses.cursor_expired", "Reconnect from a snapshot; the generation changed.";
    CommandUncertain => "zero.ses.command_uncertain", "Check the side effect manually; it will not be replayed.";
    ImportIncompatible => "zero.ses.import_incompatible", "Import a bundle from a supported format version.";

    // Providers
    ProviderUnavailable => "zero.prv.unavailable", "Check connectivity or configure another provider.";
    ProviderAuth => "zero.prv.auth", "Run `zero login` for this provider.";
    ProviderRateLimited => "zero.prv.rate_limited", "Wait for the retry window and try again.";
    ProviderOverloaded => "zero.prv.overloaded", "Retry later or use a fallback model.";
    ProviderBadRequest => "zero.prv.bad_request", "Correct the request parameters.";
    ProviderContextLength => "zero.prv.context_length", "Compact the session or choose a larger-context model.";
    ProviderContentFilter => "zero.prv.content_filter", "Adjust the prompt; the provider blocked it.";
    ProviderStreamBroken => "zero.prv.stream_broken", "Retry the turn; a partial response is not applied.";
    ProviderProtocol => "zero.prv.protocol", "Update Zero or the provider adapter; the response shape changed.";
    ProviderTimeout => "zero.prv.timeout", "Retry, or raise the provider timeout in config.";
    ProviderNoTools => "zero.prv.no_tools", "Pick a model with tool support or disable tools for this turn.";

    // Queue and steering
    QueueFull => "zero.mon.queue_full", "Wait for the turn to finish or send a shorter queue item.";
    QueueItemMissing => "zero.mon.item_missing", "Refresh the queue and retry.";
    SteerTooLate => "zero.mon.steer_too_late", "Send the message as a follow-up instead.";

    // Auto-resume
    ResumeRefused => "zero.ar.refused", "Resolve the reason in the message, then resume manually.";
    ResumeBudget => "zero.ar.budget", "Raise the budget or wait for the next window.";

    // Artifacts and export
    ArtifactMissing => "zero.ses.artifact_missing", "Recreate the artifact or clear the reference.";
    ExportFailed => "zero.ses.export_failed", "Check free space and retry the export.";

    // Policy (used by M2, defined now so codes never move)
    PolicyDenied => "zero.pol.denied", "Switch mode or get user approval.";
    PolicyAskRequired => "zero.pol.ask", "Approve the action in the host UI.";
    ApprovalExpired => "zero.pol.approval_expired", "Request a fresh approval.";
    ApprovalResolved => "zero.pol.approval_resolved", "Another client already decided this prompt.";
    SelfEscalation => "zero.pol.self_escalation", "Only the user can change mode, policy, or protected files.";
    RegulatorUnavailable => "zero.pol.regulator_unavailable", "The affected class degrades to manual; approve explicitly.";
    InvalidTransition => "zero.pol.transition_invalid", "End the headless run or choose an allowed transition.";
    RuleViolation => "zero.pol.rule_violation", "Adjust the action to satisfy the rule named in the message.";
    ProtectedPath => "zero.del.protected", "Choose a path outside the protected set.";

    // Deletion safety
    DeletionBlocked => "zero.del.blocked", "Use the `trash` tool instead; permanent deletion is human-only.";    TrashFailed => "zero.del.trash_failed", "Check the path and permissions; the original was left in place.";
    SnapshotMissing => "zero.del.snapshot_missing", "The overwrite journal has no snapshot to restore.";
    PurgeDenied => "zero.del.purge_denied", "Permanent purge requires a human confirmation token.";
    RetentionScope => "zero.del.retention_scope", "Garbage collection is limited to Zero's own data root.";

    // File manager and edit tool
    Stale => "zero.fs.stale", "Reopen the file; it changed outside this session and the write was refused.";
    Locked => "zero.fs.locked", "Wait for the lease holder or use another path.";
    BatchFailed => "zero.fs.batch_failed", "The batch rolled back; correct the failing operation and retry.";
    Conflict => "zero.fs.conflict", "Resolve the reported conflict; nothing was overwritten.";
    AnchorDrift => "zero.edt.anchor_drift", "Re-read the file and use a fresh anchor; the target text changed.";
    TooLarge => "zero.edt.too_large", "Edit a smaller range or raise the limit in config.";
    TodoConfirmation => "zero.todo.confirmation", "Ask the user to confirm completing or dropping a user-created todo.";

    // Locks and scheduling
    PoolMaxima => "zero.lck.maxima", "A worker exceeded its declared pool maximum; abort the request.";
    UnsafePreemption => "zero.lck.unsafe_preempt", "Preempt only at a safe boundary; retry when the call finishes.";
    NoQuorum => "zero.lck.no_quorum", "This node is in a minority partition; new leases are denied until quorum returns.";

    // Trust and audit
    TrustRequired => "zero.tru.trust_required", "Trust the project explicitly before its content is used.";
    Untrusted => "zero.tru.untrusted", "Trust the project explicitly before using its configuration.";
    AuditBroken => "zero.tru.audit_broken", "Run `zero doctor`; the audit chain failed verification.";
    TamperDetected => "zero.tru.tamper", "The audit chain does not match; treat the record as untrusted.";
}

impl fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl std::str::FromStr for ErrorCode {
    type Err = ZeroError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        ErrorCode::ALL
            .iter()
            .copied()
            .find(|c| c.as_str() == s)
            .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, format!("unknown error code `{s}`")))
    }
}

/// A typed error: stable code, message, and the code's single remediation line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ZeroError {
    code: ErrorCode,
    message: String,
}

impl ZeroError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn remediation(&self) -> &'static str {
        self.code.remediation()
    }

    /// Stable JSON projection used by the CLI and protocol.
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::json!({
            "code": self.code.as_str(),
            "message": self.message,
            "remediation": self.remediation(),
        })
    }
}

impl fmt::Display for ZeroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {} ({})", self.code, self.message, self.remediation())
    }
}

impl std::error::Error for ZeroError {}

impl From<std::io::Error> for ZeroError {
    fn from(e: std::io::Error) -> Self {
        let code = match e.kind() {
            std::io::ErrorKind::NotFound => ErrorCode::NotFound,
            std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            std::io::ErrorKind::AlreadyExists => ErrorCode::AlreadyExists,
            std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
            _ => ErrorCode::Io,
        };
        ZeroError::new(code, e.to_string())
    }
}

impl From<serde_json::Error> for ZeroError {
    fn from(e: serde_json::Error) -> Self {
        ZeroError::new(ErrorCode::Serialization, e.to_string())
    }
}

pub type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_has_a_stable_unique_name_and_remediation() {
        let mut seen = std::collections::BTreeSet::new();
        for code in ErrorCode::ALL {
            let name = code.as_str();
            assert!(name.starts_with("zero."), "{name} must be namespaced");
            assert!(seen.insert(name), "duplicate error code {name}");
            assert!(!code.remediation().trim().is_empty(), "{name} has no remediation");
        }
    }

    #[test]
    fn documented_codes_match_the_enum_exactly() {
        let doc = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/errors.md"),
        )
        .expect("docs/errors.md must exist");
        let mut documented = std::collections::BTreeSet::new();
        for line in doc.lines() {
            if let Some(rest) = line.strip_prefix("| `") {
                if let Some(end) = rest.find('`') {
                    documented.insert(rest[..end].to_string());
                }
            }
        }
        let actual: std::collections::BTreeSet<String> =
            ErrorCode::ALL.iter().map(|c| c.as_str().to_string()).collect();
        let undocumented: Vec<_> = actual.difference(&documented).cloned().collect();
        let stale: Vec<_> = documented.difference(&actual).cloned().collect();
        assert!(undocumented.is_empty(), "undocumented codes: {undocumented:?}");
        assert!(stale.is_empty(), "documented codes that do not exist: {stale:?}");
    }

    #[test]
    fn unknown_code_is_rejected_and_round_trips() {
        assert!("zero.nope".parse::<ErrorCode>().is_err());
        for code in ErrorCode::ALL {
            assert_eq!(code.as_str().parse::<ErrorCode>().unwrap(), *code);
        }
    }
}
