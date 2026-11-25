//! One diagnosis-and-repair playbook per stable error code (DOC-04).
//!
//! The playbook is data, not advice buried in a renderer: a user, the CLI, or an
//! agent's `diagnose` step can select it from an [`ErrorCode`] and print it as
//! is. Every code in [`ErrorCode::ALL`] has exactly one entry, and [`playbook`]
//! matches exhaustively, so adding a variant without a playbook fails to build.
//!
//! Playbooks never depend on the error message. [`triage`] reads only
//! `error.code()`, so a hostile or unusually shaped message cannot steer the
//! reader to different advice and cannot leak into playbook text.
//!
//! Steps are ordered safe actions. A test rejects blind destructive commands
//! (`rm -rf`, `del /f`, `format `, `drop database`) in any playbook text, no
//! step asks for a secret to be printed, and irreversible work is escalated to
//! the user or preceded by a backup.

use zero_types::{ErrorCode, ZeroError};

/// A diagnosis and repair script for one stable error code.
///
/// `remediation` mirrors [`ErrorCode::remediation`] verbatim so a renderer can
/// show it as the final line without contradicting the stable one-line fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Playbook {
    /// The stable code this playbook answers.
    pub code: ErrorCode,
    /// A distinct, human name for the failure.
    pub title: &'static str,
    /// One to three observations that point at this code.
    pub symptoms: &'static [&'static str],
    /// Two to five ordered diagnostic or repair steps.
    pub steps: &'static [&'static str],
    /// Where the user must take over, when the steps are not self-contained.
    pub escalation: Option<&'static str>,
    /// The stable remediation line from [`ErrorCode::remediation`].
    pub remediation: &'static str,
}

macro_rules! playbooks {
    ($(
        $variant:ident => $title:literal {
            symptoms: [$($symptom:literal),* $(,)?],
            steps: [$($step:literal),* $(,)?],
            escalation: $escalation:expr $(,)?
        } $(,)?
    )*) => {
        $(
            #[allow(non_upper_case_globals)]
            const $variant: Playbook = Playbook {
                code: ErrorCode::$variant,
                title: $title,
                symptoms: &[$($symptom),*],
                steps: &[$($step),*],
                escalation: $escalation,
                remediation: ErrorCode::$variant.remediation(),
            };
        )*

        /// The playbook for one stable code.
        ///
        /// Exhaustive and allocation-free: the code alone selects the entry.
        pub fn playbook(code: ErrorCode) -> &'static Playbook {
            match code {
                $( ErrorCode::$variant => &$variant, )*
            }
        }

        /// Every playbook, in [`ErrorCode::ALL`] order.
        pub fn all() -> &'static [Playbook] {
            &[$( $variant ),*]
        }
    };
}

playbooks! {
    // -----------------------------------------------------------------------
    // Foundations
    // -----------------------------------------------------------------------
    Internal => "Unexpected internal error" {
        symptoms: [
            "A command fails with zero.fnd.internal",
            "The message names no specific input or subsystem",
        ],
        steps: [
            "Rerun the same command once with verbose logging to see whether it repeats.",
            "Run zero doctor and keep the full output, including every check name and status.",
            "Note the exact time, the command, and the last successful action before the failure.",
            "Report the failure with the doctor output attached.",
        ],
        escalation: Some("A repeating internal error needs an upstream fix; an agent must not guess at repairs."),
    },
    InvalidInput => "Input rejected as invalid" {
        symptoms: [
            "The command returns zero.fnd.invalid_input",
            "The message names the offending field, flag, or value",
        ],
        steps: [
            "Read the field or flag named in the message.",
            "Compare it with the documented shape accepted by this build.",
            "Correct the value and rerun the command.",
            "If a config file supplies the value, fix the file and confirm with zero doctor.",
        ],
        escalation: None,
    },
    NotFound => "Path or identifier not found" {
        symptoms: [
            "The error names a path or id that does not exist",
            "A lookup or read fails before any work starts",
        ],
        steps: [
            "List the containing directory or collection to confirm the name and spelling.",
            "Check for a typo, a relative path resolved from another directory, or a file that moved.",
            "Rerun from the expected working directory with the corrected path or id.",
        ],
        escalation: None,
    },
    AlreadyExists => "Name is already taken" {
        symptoms: [
            "Creating a session, file, or workspace fails because the name exists",
        ],
        steps: [
            "List the existing items at that name to confirm what is there.",
            "Choose a different name, or reuse the existing item deliberately.",
            "Rerun the command with the chosen name.",
        ],
        escalation: None,
    },
    PermissionDenied => "Permission denied on a path" {
        symptoms: [
            "The operating system reports access denied",
            "The failing path appears in the message",
        ],
        steps: [
            "Confirm which user and group the Zero process runs as.",
            "Inspect the permissions on the named path and its parent directories, read-only.",
            "Grant the minimum permission needed to that user, or move Zero's data root under a path the user owns.",
            "Rerun the failed command.",
        ],
        escalation: Some("If the path is system-owned or policy-managed, the user or administrator must change ownership."),
    },
    Io => "Filesystem read or write failed" {
        symptoms: [
            "A read or write returns an operating system I/O error",
            "The same path fails repeatedly",
        ],
        steps: [
            "Check free space on the volume holding the path, and confirm the device is connected.",
            "Confirm the path exists and is not a directory where a file is expected.",
            "Check file and directory permissions for the Zero process.",
            "Retry; if the same path fails again, capture zero doctor disk and journals results.",
        ],
        escalation: Some("If the device reports hardware errors, the user must replace or repair the disk."),
    },
    Serialization => "Stored data is malformed" {
        symptoms: [
            "A JSON or JSONL file fails to parse",
            "zero doctor reports a malformed journal or registry",
        ],
        steps: [
            "Run zero doctor and note which check reports malformed data and at which line.",
            "Copy the affected file to a backup location before touching it.",
            "Inspect only the reported line for truncation or a partial write.",
            "Restore the last known-good copy from the backup location.",
        ],
        escalation: Some("If no good copy exists, the user must decide whether to accept the loss or recover from an external backup."),
    },
    SchemaVersion => "Stored schema does not match this build" {
        symptoms: [
            "Data was written by a different Zero build",
            "The error names a schema version",
        ],
        steps: [
            "Run zero --version and record the build.",
            "Run zero doctor and note the schema version in the config or journal detail.",
            "Run the documented migration command for this build.",
            "Do not downgrade the data; older builds refuse it by design.",
        ],
        escalation: Some("If the migration target is unclear, the user must confirm which build owns the data root before migrating."),
    },
    MigrationFailed => "Migration aborted part-way" {
        symptoms: [
            "A migration stops and names a backup path",
        ],
        steps: [
            "Stop other Zero processes that share the data root.",
            "Confirm the backup path named in the error exists and is readable.",
            "Copy that backup back over the data root, keeping the failed attempt aside.",
            "Rerun zero doctor to confirm the restored data parses.",
        ],
        escalation: Some("If the migration left partial writes, the user must approve the restore before it runs."),
    },
    ConfigInvalid => "Configuration file is invalid" {
        symptoms: [
            "zero doctor reports config malformed at a line",
        ],
        steps: [
            "Open the config file named in the error.",
            "Compare the reported key or section with the documented default config for this build.",
            "Fix only the reported key or section, keeping a copy of the original.",
            "Rerun zero doctor; its config check reports the failing line if the file is still invalid.",
        ],
        escalation: None,
    },
    LimitExceeded => "A configured limit was reached" {
        symptoms: [
            "The operation stops at a documented limit",
            "Counts in the message match a config value",
        ],
        steps: [
            "Read the limit named in the message and the current count.",
            "Decide whether to raise the limit or reduce the work.",
            "If raising, change only that setting and confirm with zero doctor.",
            "Retry the operation.",
        ],
        escalation: None,
    },
    ResourceExhausted => "A system resource is exhausted" {
        symptoms: [
            "The message names a resource such as memory, handles, or connections",
        ],
        steps: [
            "Identify the resource named in the message.",
            "Check disk free space and the running Zero workers.",
            "Stop idle sessions or workers that hold the resource through their own commands.",
            "Retry the operation.",
        ],
        escalation: Some("If the resource is system-wide, the user must free it; do not kill unrelated processes."),
    },
    Offline => "Network operation attempted while offline" {
        symptoms: [
            "A remote provider or fetch is required",
            "Offline mode is enabled or the network is down",
        ],
        steps: [
            "Check whether offline mode is enabled in config.",
            "Reconnect the network or disable offline mode when a remote provider is required.",
            "When no network is possible, configure a local model and retry.",
            "Run zero doctor to confirm the network check reflects the change.",
        ],
        escalation: None,
    },
    Unavailable => "Required feature or prerequisite is missing" {
        symptoms: [
            "The message names a feature or prerequisite",
            "The operation fails before any work starts, including kernel boot",
        ],
        steps: [
            "Read the feature or prerequisite named in the message.",
            "Check whether the kernel and daemon are running; zero doctor reports kernel state.",
            "Install the prerequisite or enable the feature in config.",
            "Restart the kernel or daemon only through its own command, then rerun zero doctor.",
        ],
        escalation: Some("If the kernel fails to boot repeatedly, the user must attach zero doctor output to a report."),
    },
    Cancelled => "Operation was cancelled" {
        symptoms: [
            "The operation stops on a user cancel or a shutdown",
        ],
        steps: [
            "Confirm whether the user, a timeout, or shutdown cancelled the work.",
            "Check whether any partial result was applied; the message says so when it matters.",
            "Retry when ready.",
        ],
        escalation: None,
    },
    Timeout => "Operation exceeded its deadline" {
        symptoms: [
            "The operation reports a timeout",
            "The same step takes longer than its configured limit",
        ],
        steps: [
            "Note the operation and how long it ran.",
            "Check whether the daemon or provider is overloaded with zero doctor workers and network.",
            "Raise the relevant timeout in config, or retry while the system is idle.",
            "Retry once; repeated timeouts at the same step need that step traced.",
        ],
        escalation: None,
    },
    Unsupported => "Unsupported platform or option" {
        symptoms: [
            "The message names a platform, revision, or option",
        ],
        steps: [
            "Read the platform, revision, or option named in the message.",
            "Check the documented support matrix for this build.",
            "Choose a supported platform, revision, or option.",
            "If it should be supported, report it with zero doctor output.",
        ],
        escalation: None,
    },
    Corrupt => "Stored state is corrupt" {
        symptoms: [
            "zero doctor reports corrupt state",
            "A file or database cannot be read back",
        ],
        steps: [
            "Run zero doctor and record every failing check.",
            "Copy the affected data root to a backup location before any repair.",
            "Restore the newest known-good backup of the corrupt component.",
            "Run zero doctor --repair only after the backup exists.",
        ],
        escalation: Some("If no backup exists, the user must choose between losing the corrupt component and manual recovery."),
    },

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------
    SessionNotFound => "Session does not exist" {
        symptoms: [
            "A resume or attach names an unknown session id",
        ],
        steps: [
            "List sessions with zero resume.",
            "Check the id for a typo, or for a session that was archived or moved.",
            "Pick an existing session or start a new one.",
        ],
        escalation: None,
    },
    SessionClosed => "Session is closed" {
        symptoms: [
            "Attaching to a session fails because it ended",
        ],
        steps: [
            "Check the session state with zero resume.",
            "Reopen the session, or start a new one when its transcript is complete.",
            "Reattach using the new id.",
        ],
        escalation: None,
    },
    SessionLeaseHeld => "Another worker holds the session lease" {
        symptoms: [
            "A second process tries to drive the same session",
            "The error names the lease holder or its generation",
        ],
        steps: [
            "Find the holder with zero doctor workers, or inspect the lease file under .zero/locks.",
            "Attach to the holder instead of starting a second worker.",
            "If the holder is gone, wait for the lease to expire before retrying.",
            "Confirm with zero doctor that no stale lock remains.",
        ],
        escalation: Some("If the holder is a worker the user did not start, the user must decide whether to stop it; never force-kill unrelated processes."),
    },
    SessionCorrupt => "Session log has an unparseable record" {
        symptoms: [
            "zero doctor journals reports an invalid JSONL line",
            "Resuming a session stops at one record",
        ],
        steps: [
            "Run zero doctor and note the session file and line.",
            "Copy the session file to a backup location.",
            "Inspect only the reported line for a partial write.",
            "Start a fresh session from the last good entry, or restore the backup copy.",
        ],
        escalation: Some("If the corrupt record is the only copy of work the user needs, the user must approve any edit to the journal."),
    },
    ForkFailed => "Fork from a session entry failed" {
        symptoms: [
            "A fork names an entry id that cannot be used",
        ],
        steps: [
            "List the session's entries and confirm the entry id exists.",
            "Fork again from a different, existing entry id.",
            "If every fork fails, run zero doctor on the session journal.",
        ],
        escalation: None,
    },
    CompactionFailed => "Context compaction failed" {
        symptoms: [
            "A compaction request stops on an oversized range",
        ],
        steps: [
            "Reduce the number of recent messages kept in context.",
            "Raise the context budget in config if the model supports it.",
            "Rerun compaction; the same range fails again for the same reason.",
        ],
        escalation: None,
    },
    SummaryInvalid => "Branch summary is missing a section" {
        symptoms: [
            "A branch summary is rejected",
            "The message names the missing section",
        ],
        steps: [
            "Regenerate the branch summary.",
            "If regeneration fails, compare the summary against the six required sections.",
            "Retry the branch operation that needed the summary.",
        ],
        escalation: None,
    },
    ContextTooLarge => "Context exceeds the size cap" {
        symptoms: [
            "Loading a context file stops at the size cap",
        ],
        steps: [
            "Identify the context file named in the message.",
            "Trim it to the documented cap, or raise the cap in config deliberately.",
            "Rerun the operation that loaded it.",
        ],
        escalation: None,
    },
    AttachCursorExpired => "Attach cursor belongs to an older generation" {
        symptoms: [
            "A reconnect presents a cursor from a previous generation",
        ],
        steps: [
            "Reconnect from the current snapshot instead of the saved cursor.",
            "Let the client request a fresh generation id.",
            "Do not replay the expired cursor; it will not be honoured.",
        ],
        escalation: None,
    },
    CommandUncertain => "Side effect outcome is unknown" {
        symptoms: [
            "A command was sent but its reply never arrived",
            "Replay is refused because the result is unknown",
        ],
        steps: [
            "Identify the command and its target from the message.",
            "Check the target's state directly before acting again.",
            "Do not resend; choose the next step from what you observed.",
        ],
        escalation: Some("When the side effect cannot be verified from the system, the user must confirm it."),
    },
    ImportIncompatible => "Imported bundle is not compatible with this build" {
        symptoms: [
            "An import names an older or newer bundle revision",
        ],
        steps: [
            "Read the bundle revision in the message.",
            "Compare it with the revisions this build accepts.",
            "Export again from a supported build, or upgrade the reader.",
            "Retry the import.",
        ],
        escalation: None,
    },

    // -----------------------------------------------------------------------
    // Providers
    // -----------------------------------------------------------------------
    ProviderUnavailable => "Provider endpoint is unreachable" {
        symptoms: [
            "Requests to the provider fail before a response",
        ],
        steps: [
            "Check connectivity and proxy settings with zero doctor network.",
            "Confirm the provider base URL is correct and reachable.",
            "Configure a fallback provider, or retry later.",
        ],
        escalation: None,
    },
    ProviderAuth => "Provider authentication failed or expired" {
        symptoms: [
            "The provider returns 401 or 403",
            "The credential was revoked, rotated, or expired",
        ],
        steps: [
            "Run zero login for the provider named in the message.",
            "Confirm the login succeeded without printing the token.",
            "Retry the request.",
        ],
        escalation: Some("If login still fails, the user must check the provider account and re-authorise."),
    },
    ProviderRateLimited => "Provider rate limit reached" {
        symptoms: [
            "The provider returns 429 or a retry window",
        ],
        steps: [
            "Wait for the retry window, honouring any retry-after value.",
            "Reduce request concurrency or switch to a fallback model.",
            "Retry the turn.",
        ],
        escalation: None,
    },
    ProviderOverloaded => "Provider is overloaded" {
        symptoms: [
            "The provider returns a temporary overload status",
        ],
        steps: [
            "Retry after a short delay.",
            "Use a fallback model if one is configured.",
            "Avoid retry storms; run one turn at a time.",
        ],
        escalation: None,
    },
    ProviderBadRequest => "Provider rejected the request parameters" {
        symptoms: [
            "The provider returns a parameter error",
        ],
        steps: [
            "Read the parameter named in the provider message.",
            "Correct the model name, tool schema, or sampling setting.",
            "Retry once with the corrected request.",
        ],
        escalation: None,
    },
    ProviderContextLength => "Prompt exceeds the model context window" {
        symptoms: [
            "The provider rejects the prompt as too long",
        ],
        steps: [
            "Compact the session or trim the attached files.",
            "Choose a model with a larger context window.",
            "Retry the turn.",
        ],
        escalation: None,
    },
    ProviderContentFilter => "Provider blocked the content" {
        symptoms: [
            "The provider reports a content policy block",
        ],
        steps: [
            "Read which part of the request was blocked.",
            "Rewrite the prompt without the blocked content.",
            "Retry; do not loop on the same wording.",
        ],
        escalation: None,
    },
    ProviderStreamBroken => "Provider stream ended mid-response" {
        symptoms: [
            "The stream stops without a finish reason",
            "No partial response was applied",
        ],
        steps: [
            "Retry the turn.",
            "If it repeats on the same model, switch to a fallback model.",
            "Check the provider status page before filing a report.",
        ],
        escalation: None,
    },
    ProviderProtocol => "Provider response shape changed" {
        symptoms: [
            "A response cannot be decoded by this adapter",
        ],
        steps: [
            "Record the provider, model, and adapter version.",
            "Update Zero or the provider adapter to a build that understands the new shape.",
            "Retry the turn.",
        ],
        escalation: Some("If the provider changed its API, the user must choose between pinning an older adapter and upgrading."),
    },
    ProviderTimeout => "Provider call exceeded the timeout" {
        symptoms: [
            "The provider request times out",
        ],
        steps: [
            "Check provider latency and the local network.",
            "Retry once.",
            "Raise the provider timeout in config when the model is known to be slow.",
        ],
        escalation: None,
    },
    ProviderNoTools => "Model does not support tool calls" {
        symptoms: [
            "A turn requests tools from a model without tool support",
        ],
        steps: [
            "Pick a model that supports tool calling.",
            "Or disable tools for this turn explicitly.",
            "Retry.",
        ],
        escalation: None,
    },

    // -----------------------------------------------------------------------
    // Queue and steering
    // -----------------------------------------------------------------------
    QueueFull => "Message queue is full" {
        symptoms: [
            "Sending a message is refused because the queue is at its limit",
        ],
        steps: [
            "Wait for the running turn to finish.",
            "Send a shorter queue item.",
            "Check zero doctor workers if the queue does not drain.",
        ],
        escalation: None,
    },
    QueueItemMissing => "Queued item no longer exists" {
        symptoms: [
            "Editing or cancelling a queue item fails on an unknown id",
        ],
        steps: [
            "Refresh the queue view.",
            "Re-send the message if it still matters.",
            "Do not retry the stale item id.",
        ],
        escalation: None,
    },
    SteerTooLate => "Steering arrived after the turn committed" {
        symptoms: [
            "A steer message is refused because the turn finished",
        ],
        steps: [
            "Check whether the turn already completed.",
            "Send the message as a follow-up turn instead.",
            "Do not resend the same steer id.",
        ],
        escalation: None,
    },

    // -----------------------------------------------------------------------
    // Auto-resume
    // -----------------------------------------------------------------------
    ResumeRefused => "Automatic resume refused" {
        symptoms: [
            "A resume is attempted after a crash",
            "The message states why it was refused",
        ],
        steps: [
            "Read the refusal reason in the message.",
            "Resolve that condition, such as auth, lease, config, or policy.",
            "Resume the session manually.",
            "Re-enable automatic resume only after the reason is gone.",
        ],
        escalation: Some("If the reason is policy or trust, only the user can clear it."),
    },
    ResumeBudget => "Auto-resume budget exhausted" {
        symptoms: [
            "Automatic resume stops after its configured attempts",
        ],
        steps: [
            "Note how many resume attempts were used and the current window.",
            "Raise the budget in config if the workload justifies it.",
            "Or wait for the next window and resume manually.",
        ],
        escalation: None,
    },

    // -----------------------------------------------------------------------
    // Artifacts and export
    // -----------------------------------------------------------------------
    ArtifactMissing => "Referenced artifact is missing" {
        symptoms: [
            "A tool or session refers to an artifact that is not there",
        ],
        steps: [
            "Check the path or id in the message.",
            "Recreate the artifact, or clear the reference that points at it.",
            "Rerun the operation that needed it.",
        ],
        escalation: None,
    },
    ExportFailed => "Export did not complete" {
        symptoms: [
            "An export stops before writing its output",
        ],
        steps: [
            "Check free space at the export destination with zero doctor disk.",
            "Confirm the destination directory is writable.",
            "Retry the export to a fresh path.",
            "If it fails again, keep the partial output aside and report the error.",
        ],
        escalation: Some("If the export holds the only copy of user data, the user must choose the destination."),
    },

    // -----------------------------------------------------------------------
    // Policy
    // -----------------------------------------------------------------------
    PolicyDenied => "Policy denied the action" {
        symptoms: [
            "A tool call is refused by the current mode or rule set",
        ],
        steps: [
            "Read which rule or mode denied the action.",
            "Choose a different tool or a narrower action that satisfies the rule.",
            "Or ask the user to approve the action in the host UI.",
            "Do not retry the identical action; it will be denied again.",
        ],
        escalation: None,
    },
    PolicyAskRequired => "Action needs explicit approval" {
        symptoms: [
            "The action is allowed only with user approval",
        ],
        steps: [
            "Present the exact action and its effects to the user.",
            "Wait for approval in the host UI.",
            "Proceed only after the approval is recorded.",
        ],
        escalation: None,
    },
    ApprovalExpired => "Approval prompt expired" {
        symptoms: [
            "A stored approval can no longer be used",
        ],
        steps: [
            "Check whether the requested action is still needed.",
            "Request a fresh approval.",
            "Do not reuse the expired approval id.",
        ],
        escalation: None,
    },
    ApprovalResolved => "Approval was decided elsewhere" {
        symptoms: [
            "Another client already answered the prompt",
        ],
        steps: [
            "Read the recorded decision, approved or denied.",
            "If approved, proceed once; if denied, stop and ask the user.",
            "Do not re-prompt for the same action.",
        ],
        escalation: None,
    },
    SelfEscalation => "Agent attempted to raise its own authority" {
        symptoms: [
            "A mode, policy, or protected-file change came from the agent",
            "The change was refused",
        ],
        steps: [
            "Stop the attempted change.",
            "Describe to the user what change is needed and why.",
            "Let the user make the change themselves.",
            "Record that the action remains blocked.",
        ],
        escalation: Some("Only the user can change mode, policy, or protected files."),
    },
    RegulatorUnavailable => "Policy regulator is unavailable" {
        symptoms: [
            "A policy class has no regulator to decide",
        ],
        steps: [
            "Note which action class lost its regulator.",
            "Treat that class as manual: ask the user for an explicit approval.",
            "Do not enable the class automatically.",
        ],
        escalation: Some("The user must approve each affected action until the regulator returns."),
    },
    InvalidTransition => "State transition is not allowed" {
        symptoms: [
            "A command asks for a transition the state machine forbids",
        ],
        steps: [
            "Read the current state and the requested transition.",
            "Check the documented allowed transitions for that state.",
            "Choose an allowed transition, or end the headless run.",
            "Retry.",
        ],
        escalation: None,
    },
    RuleViolation => "Action violates a declared rule" {
        symptoms: [
            "A rule name appears in the refusal",
        ],
        steps: [
            "Read the rule name in the message.",
            "Adjust the action so it satisfies the rule.",
            "Rerun; the same action will be refused again otherwise.",
        ],
        escalation: None,
    },
    ProtectedPath => "Path is protected from agent writes" {
        symptoms: [
            "A write is refused on a policy, config, journal, vault, audit, or credential path",
        ],
        steps: [
            "Identify the protected path and why it is protected.",
            "Choose a path outside the protected set, or stage the change somewhere writable.",
            "Ask the user to apply the change when a protected file itself must change.",
        ],
        escalation: Some("Only the user can edit protected files."),
    },

    // -----------------------------------------------------------------------
    // Deletion safety
    // -----------------------------------------------------------------------
    DeletionBlocked => "Permanent deletion is blocked" {
        symptoms: [
            "A tool requests a permanent delete",
        ],
        steps: [
            "Use the trash tool instead of a permanent delete.",
            "If the file must really be removed, ask the user for the confirmation token.",
            "Never bypass the guard by shelling out to a delete command.",
        ],
        escalation: None,
    },
    TrashFailed => "Moving to trash failed" {
        symptoms: [
            "A trash operation fails and the original stays in place",
        ],
        steps: [
            "Check that the path exists and is writable.",
            "Check free space on the trash volume.",
            "Retry the trash move; the original was left in place.",
            "If it still fails, leave the file alone and report the path to the user.",
        ],
        escalation: None,
    },
    SnapshotMissing => "No snapshot exists for the overwrite" {
        symptoms: [
            "An overwrite cannot be reversed",
        ],
        steps: [
            "Check the overwrite journal entry for that file.",
            "Look for a copy in the backup location named by the journal.",
            "If no snapshot exists, tell the user the original cannot be restored automatically.",
        ],
        escalation: Some("The user must decide how to recover the overwritten content."),
    },
    PurgeDenied => "Permanent purge needs human confirmation" {
        symptoms: [
            "A purge is refused without a confirmation token",
        ],
        steps: [
            "Explain exactly what would be purged and how much data it covers.",
            "Ask the user for the confirmation token.",
            "Run the purge only with that token, never with a substituted or guessed one.",
        ],
        escalation: None,
    },
    RetentionScope => "Garbage collection refused outside the data root" {
        symptoms: [
            "A retention job names a path outside Zero's own data root",
        ],
        steps: [
            "Check the path named in the message.",
            "Limit retention to Zero's own data root.",
            "If the path is user data, leave it alone and report it.",
        ],
        escalation: Some("Deleting outside the data root is a user decision."),
    },

    // -----------------------------------------------------------------------
    // File manager and edit tool
    // -----------------------------------------------------------------------
    Stale => "File changed outside the session" {
        symptoms: [
            "A write is refused because the file version moved",
        ],
        steps: [
            "Re-read the file to get its current content and version.",
            "Redo the edit against the new content.",
            "If the external change looks wrong, tell the user before overwriting.",
        ],
        escalation: None,
    },
    Locked => "File is locked by another holder" {
        symptoms: [
            "A write waits or fails on an active lease",
        ],
        steps: [
            "Find the lease holder with zero doctor locks.",
            "Wait for the holder to finish, or use a different path.",
            "Retry once the lock is released.",
        ],
        escalation: Some("If the holder is unknown, the user must decide whether the stale lock can be cleared."),
    },
    BatchFailed => "Batch operation rolled back" {
        symptoms: [
            "One operation in a batch failed",
            "No change from the batch was kept",
        ],
        steps: [
            "Read which operation in the batch failed.",
            "Fix that operation's cause.",
            "Rerun the batch; nothing from the failed batch was applied.",
        ],
        escalation: None,
    },
    Conflict => "Write conflict detected" {
        symptoms: [
            "A write is refused because the file changed concurrently",
        ],
        steps: [
            "Read which file or region conflicted.",
            "Compare the current content with the intended change.",
            "Resolve the conflict explicitly and reapply.",
            "The refused write overwrote nothing.",
        ],
        escalation: None,
    },
    AnchorDrift => "Edit anchor no longer matches" {
        symptoms: [
            "The target text moved since the anchor was captured",
        ],
        steps: [
            "Re-read the file and locate the target text again.",
            "Create a fresh anchor from the current content.",
            "Reapply the edit; do not reuse the stale anchor.",
        ],
        escalation: None,
    },
    TooLarge => "Edit range exceeds the size limit" {
        symptoms: [
            "An edit is refused for its size",
        ],
        steps: [
            "Split the edit into smaller ranges.",
            "Or raise the edit limit in config deliberately.",
            "Apply the first range and confirm it before the next.",
        ],
        escalation: None,
    },
    TodoConfirmation => "User-created todo needs confirmation" {
        symptoms: [
            "Completing or dropping a todo the user created",
        ],
        steps: [
            "Ask the user whether the todo is complete or should be dropped.",
            "Apply the answer.",
            "Do not complete or drop a user todo without that answer.",
        ],
        escalation: None,
    },

    // -----------------------------------------------------------------------
    // Locks and scheduling
    // -----------------------------------------------------------------------
    PoolMaxima => "Worker exceeded its pool maximum" {
        symptoms: [
            "A worker asks for more concurrency than its pool allows",
        ],
        steps: [
            "Identify the worker and the pool from the message.",
            "Abort the request that exceeded the maximum.",
            "Reduce concurrency or raise the pool maximum in config.",
            "Rerun the request.",
        ],
        escalation: None,
    },
    UnsafePreemption => "Preemption attempted at an unsafe point" {
        symptoms: [
            "A preempt request arrives while a call is in flight",
        ],
        steps: [
            "Wait for the running call to reach a safe boundary.",
            "Retry the preemption then.",
            "If the call never finishes, report it rather than forcing a kill.",
        ],
        escalation: Some("Forcing a kill is a user decision and must not target unrelated processes."),
    },
    NoQuorum => "Cluster partition has no quorum" {
        symptoms: [
            "This node is in a minority partition",
            "New leases are denied until quorum returns",
        ],
        steps: [
            "Check mesh reachability with zero doctor mesh and network.",
            "Restore connectivity to the majority partition.",
            "Wait for quorum before retrying lease acquisition.",
            "Do not force leases on a minority node.",
        ],
        escalation: Some("If the majority side is permanently gone, the user must decide how to recover the cluster."),
    },

    // -----------------------------------------------------------------------
    // Trust and audit
    // -----------------------------------------------------------------------
    TrustRequired => "Project must be trusted before use" {
        symptoms: [
            "Project content is used before trust is recorded",
        ],
        steps: [
            "Review what the project contains, such as config, hooks, and MCP servers.",
            "Ask the user to trust the project explicitly.",
            "Retry only after trust is recorded.",
        ],
        escalation: None,
    },
    Untrusted => "Project configuration is untrusted" {
        symptoms: [
            "An operation needs configuration from an untrusted project",
        ],
        steps: [
            "Identify which untrusted content the operation needed.",
            "Show the user the relevant file names, not their contents verbatim.",
            "Let the user decide whether to trust it.",
            "Do not load untrusted config to make progress.",
        ],
        escalation: Some("Trust is a user decision; an agent cannot grant it."),
    },
    AuditBroken => "Audit chain failed verification" {
        symptoms: [
            "Audit records do not hash-chain",
            "zero doctor reports an audit failure",
        ],
        steps: [
            "Stop writing to the audit log until the break is understood.",
            "Run zero doctor and record the first broken record.",
            "Preserve the current audit files in a backup location.",
            "Report to the user; do not edit or truncate the chain to silence the error.",
        ],
        escalation: Some("The chain is evidence; the user must decide on recovery."),
    },
    TamperDetected => "Audit chain does not match its record" {
        symptoms: [
            "Audit content no longer matches its recorded hash",
        ],
        steps: [
            "Treat the affected records as untrusted.",
            "Preserve copies of the audit files.",
            "Record the detection time and the affected range.",
            "Report to the user and the security owner.",
        ],
        escalation: Some("Only the user or security owner can decide remediation; never rewrite the chain."),
    },
}

/// The playbook for the code carried by an error.
///
/// Only `error.code()` is read. The message is never matched, echoed, or stored,
/// so a hostile message cannot change the advice and cannot leak into it.
pub fn triage(error: &ZeroError) -> &'static Playbook {
    playbook(error.code())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    /// Every human-readable string a playbook renders.
    fn text(playbook: &Playbook) -> impl Iterator<Item = &'static str> + '_ {
        std::iter::once(playbook.title)
            .chain(playbook.symptoms.iter().copied())
            .chain(playbook.steps.iter().copied())
            .chain(playbook.escalation)
            .chain(std::iter::once(playbook.remediation))
    }

    #[test]
    fn every_error_code_has_exactly_one_playbook() {
        assert_eq!(
            all().len(),
            ErrorCode::ALL.len(),
            "one playbook per stable code"
        );

        let mut seen = BTreeSet::new();
        for playbook in all() {
            assert!(
                seen.insert(playbook.code),
                "duplicate playbook for {}",
                playbook.code.as_str()
            );
            assert!(
                ErrorCode::ALL.contains(&playbook.code),
                "{} is not a stable code",
                playbook.code.as_str()
            );
        }
        assert_eq!(seen.len(), ErrorCode::ALL.len());

        let codes: Vec<ErrorCode> = all().iter().map(|playbook| playbook.code).collect();
        assert_eq!(
            codes,
            ErrorCode::ALL.to_vec(),
            "all() must follow ErrorCode::ALL order"
        );

        for code in ErrorCode::ALL {
            let found = playbook(*code);
            assert_eq!(found.code, *code, "lookup returned the wrong playbook");
            assert_eq!(found.remediation, code.remediation());
        }
    }

    #[test]
    fn every_playbook_is_usable() {
        let mut titles = BTreeSet::new();
        for playbook in all() {
            let code = playbook.code.as_str();
            assert!(!playbook.title.trim().is_empty(), "{code} has no title");
            assert!(
                titles.insert(playbook.title),
                "{code} reuses the title {:?}",
                playbook.title
            );
            assert!(
                (1..=3).contains(&playbook.symptoms.len()),
                "{code} must have one to three symptoms"
            );
            assert!(
                (2..=5).contains(&playbook.steps.len()),
                "{code} must have two to five steps"
            );
            assert!(!playbook.remediation.trim().is_empty(), "{code} has no remediation");

            for line in text(playbook) {
                assert!(!line.is_empty(), "{code} has an empty line");
                assert_eq!(line, line.trim(), "{code} has untrimmed text: {line:?}");
                assert!(
                    !line.contains("{}"),
                    "{code} leaks a raw placeholder: {line:?}"
                );
            }
        }
    }

    #[test]
    fn triage_uses_the_injected_error_code() {
        for code in ErrorCode::ALL {
            let error = ZeroError::new(*code, "injected fault");
            let found = triage(&error);
            assert_eq!(found.code, *code, "triage ignored the code");
            assert_eq!(found, playbook(*code));

            for line in text(found) {
                assert!(
                    !line.contains("injected fault"),
                    "{} echoed the error message",
                    code.as_str()
                );
            }
        }
    }

    #[test]
    fn remediation_matches_the_stable_code_line() {
        for code in ErrorCode::ALL {
            let found = playbook(*code);
            assert_eq!(found.remediation, code.remediation());

            let from_triage = triage(&ZeroError::new(*code, "injected fault"));
            assert_eq!(from_triage.remediation, code.remediation());
            assert!(
                text(found).any(|line| line.contains(code.remediation())),
                "{} does not render the stable remediation line",
                code.as_str()
            );
        }
    }

    #[test]
    fn no_playbook_recommends_blind_destruction() {
        const FORBIDDEN: [&str; 4] = ["rm -rf", "del /f", "format ", "drop database"];
        // `remediation` is owned by zero-types and is descriptive prose, not a
        // command (its import_incompatible line says "format version"), so only
        // text this crate authors is checked.
        for playbook in all() {
            let authored = std::iter::once(playbook.title)
                .chain(playbook.symptoms.iter().copied())
                .chain(playbook.steps.iter().copied())
                .chain(playbook.escalation);
            for line in authored {
                let lower = line.to_ascii_lowercase();
                for needle in FORBIDDEN {
                    assert!(
                        !lower.contains(needle),
                        "{} recommends {needle:?}: {line:?}",
                        playbook.code.as_str()
                    );
                }
            }
        }
    }
}
