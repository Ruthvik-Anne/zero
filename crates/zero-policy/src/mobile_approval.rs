//! Mobile approvals and secrets (AND-04, AND-08, POL-09, POL-15): an approval
//! is bound to the exact action digest, a nonce, and the approving device, and
//! may only be spent once.
//!
//! The Android app never sends raw action arguments back in an approval. It
//! returns the digest, the challenge identity, the nonce, and its device
//! binding; the host recomputes the digest from its own copy of the action, so
//! a changed argument can never ride an old approval. Spending is recorded in a
//! bounded in-memory set: a replay of the same approval, or of the same nonce
//! under another challenge, is refused.
//!
//! This module is pure: it holds no socket, no UI, and no secret value. The
//! Android host maps [`SecureDisplay`] to the window flag and draws
//! [`LockScreenView::render_locked`] while the device is locked.

use crate::action::canonical_json;
use crate::mode::ActionClass;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, VecDeque};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::OnceLock;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Maximum characters in an action id, session id, secret tag, or device id.
pub const MAX_ID_CHARS: usize = 128;
/// Characters of the digest shown on the lock screen and in errors.
pub const DIGEST_PREFIX_CHARS: usize = 12;
/// The consumed set keeps this many nonces unless a smaller bound is chosen.
pub const DEFAULT_CONSUMED_CAPACITY: usize = 4096;
/// The Android window flag the host must set when [`SecureDisplay::required`].
pub const FLAG_SECURE: &str = "FLAG_SECURE";

const MAX_TITLE_CHARS: usize = 64;
const MAX_LOCKED_CHARS: usize = 96;
const MAX_UNLOCKED_CHARS: usize = 160;
const MAX_SECRET_LINE_CHARS: usize = 96;

/// A blake3 digest over the canonical mobile action: action id, policy class,
/// session, and arguments. The action arguments themselves never appear in a
/// `Debug` output or an error; only the digest does.
#[derive(Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct ActionDigest(String);

impl ActionDigest {
    pub fn of(action: &MobileAction) -> Self {
        Self(blake3::hash(action.canonical().as_bytes()).to_hex().to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// The first `chars` characters, used for a lock-screen label or an error.
    pub fn prefix(&self, chars: usize) -> String {
        self.0.chars().take(chars).collect()
    }

    /// The bounded digest shown to a user.
    pub fn short(&self) -> String {
        self.prefix(DIGEST_PREFIX_CHARS)
    }
}

impl fmt::Display for ActionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for ActionDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "ActionDigest({})", self.short())
    }
}

/// The action a phone may approve. The digest covers exactly these four
/// fields, so a caller must put every security-relevant argument (including a
/// path or target) inside `arguments`.
#[derive(Clone, PartialEq)]
pub struct MobileAction {
    action_id: String,
    session: String,
    class: ActionClass,
    arguments: serde_json::Value,
}

impl MobileAction {
    pub fn new(
        action_id: impl Into<String>,
        class: ActionClass,
        session: impl Into<String>,
        arguments: serde_json::Value,
    ) -> Result<Self> {
        let action_id = action_id.into();
        let session = session.into();
        validate_identity("action id", &action_id)?;
        validate_identity("session id", &session)?;
        Ok(Self { action_id, session, class, arguments })
    }

    pub fn action_id(&self) -> &str {
        &self.action_id
    }

    pub fn session(&self) -> &str {
        &self.session
    }

    pub fn class(&self) -> ActionClass {
        self.class
    }

    pub fn digest(&self) -> ActionDigest {
        ActionDigest::of(self)
    }

    fn canonical(&self) -> String {
        // JSON-quote the identities so a separator or quote inside an id cannot
        // make two different actions share one canonical form.
        let id = serde_json::to_string(&self.action_id).unwrap_or_default();
        let session = serde_json::to_string(&self.session).unwrap_or_default();
        format!(
            "zero-mobile-action-v1|id={id}|class={}|session={session}|args={}",
            self.class.as_str(),
            canonical_json(&self.arguments)
        )
    }
}

impl fmt::Debug for MobileAction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("MobileAction")
            .field("action_id", &self.action_id)
            .field("class", &self.class)
            .field("session", &self.session)
            .field("digest", &self.digest())
            .finish_non_exhaustive()
    }
}

/// A prompt for one exact action. The nonce is fresh per challenge and is what
/// the consumed set records.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalChallenge {
    pub id: String,
    pub digest: ActionDigest,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub nonce: String,
}

/// Create a challenge for an exact action. `ttl_ms` is added to `now_ms`; a
/// zero or negative TTL produces an already-expired challenge, which cannot be
/// approved.
pub fn challenge(action: &MobileAction, ttl_ms: i64, now_ms: i64) -> ApprovalChallenge {
    let digest = ActionDigest::of(action);
    let expires_ms = now_ms.saturating_add(ttl_ms);
    let sequence = NEXT_CHALLENGE.fetch_add(1, Ordering::Relaxed);
    let nonce = derive_nonce(&digest, now_ms, expires_ms, sequence);
    let id = format!("ma-{}", nonce.chars().take(24).collect::<String>());
    ApprovalChallenge { id, digest, created_ms: now_ms, expires_ms, nonce }
}

static NEXT_CHALLENGE: AtomicU64 = AtomicU64::new(1);

fn derive_nonce(digest: &ActionDigest, created_ms: i64, expires_ms: i64, sequence: u64) -> String {
    blake3::hash(
        format!(
            "zero-mobile-approval-nonce-v1|{}|{}|{}|{}|{}",
            digest.as_str(),
            created_ms,
            expires_ms,
            sequence,
            process_salt()
        )
        .as_bytes(),
    )
    .to_hex()
    .to_string()
}

/// A per-process random salt, so two hosts that mint the same digest in the
/// same millisecond do not produce the same nonce. `RandomState` is std-only
/// and draws its keys from the OS.
fn process_salt() -> u64 {
    static SALT: OnceLock<u64> = OnceLock::new();
    *SALT.get_or_init(|| {
        use std::collections::hash_map::RandomState;
        use std::hash::{BuildHasher, Hasher};
        let mut hasher = RandomState::new().build_hasher();
        hasher.write_u32(std::process::id());
        hasher.finish()
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MobileDecision {
    Allow,
    Deny,
}

/// One decision for one challenge. The digest and nonce are copied from the
/// challenge, so the value the host verifies is bound to the action the user
/// actually saw.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MobileApproval {
    pub challenge_id: String,
    pub digest: ActionDigest,
    pub decision: MobileDecision,
    pub approved_by: String,
    pub approved_ms: i64,
    /// The challenge's expiry, carried with the approval so verification is
    /// self-contained.
    pub expires_ms: i64,
    pub nonce: String,
    pub device_binding: String,
}

impl MobileApproval {
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_ms
    }

    pub fn digest_prefix(&self) -> String {
        self.digest.short()
    }
}

/// Bind a decision to the exact digest, nonce, and device. The approving
/// identity defaults to the device id; use [`approve_by`] when the UI has a
/// separate human-readable actor.
pub fn approve(
    challenge: &ApprovalChallenge,
    decision: MobileDecision,
    device: &str,
    now_ms: i64,
) -> Result<MobileApproval> {
    approve_by(challenge, decision, device, device, now_ms)
}

/// Like [`approve`] with an explicit actor label for the audit record.
pub fn approve_by(
    challenge: &ApprovalChallenge,
    decision: MobileDecision,
    approved_by: &str,
    device: &str,
    now_ms: i64,
) -> Result<MobileApproval> {
    validate_identity("approver", approved_by)?;
    validate_identity("device binding", device)?;
    if challenge.id.trim().is_empty() || challenge.nonce.trim().is_empty() {
        return Err(ZeroError::new(ErrorCode::InvalidInput, "the approval challenge is malformed"));
    }
    if now_ms >= challenge.expires_ms {
        return Err(ZeroError::new(
            ErrorCode::ApprovalExpired,
            format!(
                "challenge {} for digest {} expired at {}",
                challenge.id,
                challenge.digest.short(),
                challenge.expires_ms
            ),
        ));
    }
    Ok(MobileApproval {
        challenge_id: challenge.id.clone(),
        digest: challenge.digest.clone(),
        decision,
        approved_by: approved_by.to_string(),
        approved_ms: now_ms,
        expires_ms: challenge.expires_ms,
        nonce: challenge.nonce.clone(),
        device_binding: device.to_string(),
    })
}

/// The bounded consumed-nonce set. `ApprovalStore` is module-local because
/// `crate::approval::ApprovalStore` is the durable prompt ledger; this type is
/// re-exported at the crate root as `MobileApprovalStore`.
#[derive(Debug)]
pub struct ApprovalStore {
    consumed: BTreeMap<String, String>,
    order: VecDeque<String>,
    capacity: usize,
}

impl ApprovalStore {
    /// A zero bound is refused: the set must be able to remember at least one
    /// approval.
    pub fn new(capacity: usize) -> Result<Self> {
        if capacity == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "the consumed-approval set needs a positive bound",
            ));
        }
        Ok(Self { consumed: BTreeMap::new(), order: VecDeque::new(), capacity })
    }

    pub fn capacity(&self) -> usize {
        self.capacity
    }

    pub fn consumed_len(&self) -> usize {
        self.consumed.len()
    }

    pub fn is_consumed(&self, nonce: &str) -> bool {
        self.consumed.contains_key(nonce)
    }

    /// Mark an approval used. Returns `false` when the nonce was already spent.
    /// FIFO eviction keeps the set bounded; the oldest nonce is forgotten
    /// first.
    pub fn consume(&mut self, approval: &MobileApproval) -> bool {
        if approval.nonce.trim().is_empty() || self.consumed.contains_key(&approval.nonce) {
            return false;
        }
        self.consumed.insert(approval.nonce.clone(), approval.challenge_id.clone());
        self.order.push_back(approval.nonce.clone());
        while self.order.len() > self.capacity {
            if let Some(oldest) = self.order.pop_front() {
                self.consumed.remove(&oldest);
            }
        }
        true
    }

    /// Verify a phone decision against the host's own action. Every failure
    /// names the digest only; raw arguments never enter an error.
    ///
    /// A successful verification consumes the nonce, so the caller must hold a
    /// fresh approval for every dispatch.
    pub fn verify(
        &mut self,
        approval: &MobileApproval,
        action: &MobileAction,
        device: &str,
        now_ms: i64,
    ) -> Result<()> {
        validate_identity("device binding", device)?;
        if approval.challenge_id.trim().is_empty() || approval.nonce.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::InvalidInput, "the approval is malformed"));
        }

        let expected = ActionDigest::of(action);
        if approval.digest != expected {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!(
                    "the approval is bound to digest {} but the action is now {}; request a fresh approval",
                    approval.digest.short(),
                    expected.short()
                ),
            ));
        }
        if approval.decision != MobileDecision::Allow {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!(
                    "approval for digest {} was denied by {}",
                    expected.short(),
                    approval.approved_by
                ),
            ));
        }
        if approval.device_binding != device {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!("approval for digest {} is bound to a different device", expected.short()),
            ));
        }
        if approval.is_expired(now_ms) {
            return Err(ZeroError::new(
                ErrorCode::ApprovalExpired,
                format!(
                    "approval for digest {} expired at {}",
                    expected.short(),
                    approval.expires_ms
                ),
            ));
        }
        if let Some(challenge_id) = self.consumed.get(&approval.nonce) {
            let message = if challenge_id == &approval.challenge_id {
                format!(
                    "approval {} for digest {} was already used; request a fresh approval",
                    approval.challenge_id,
                    expected.short()
                )
            } else {
                format!(
                    "the nonce for digest {} was already used by another challenge",
                    expected.short()
                )
            };
            return Err(ZeroError::new(ErrorCode::ApprovalResolved, message));
        }

        self.consume(approval);
        Ok(())
    }
}

impl Default for ApprovalStore {
    fn default() -> Self {
        Self {
            consumed: BTreeMap::new(),
            order: VecDeque::new(),
            capacity: DEFAULT_CONSUMED_CAPACITY,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Risk {
    Low,
    Medium,
    High,
    Critical,
}

impl Risk {
    pub fn as_str(self) -> &'static str {
        match self {
            Risk::Low => "low",
            Risk::Medium => "medium",
            Risk::High => "high",
            Risk::Critical => "critical",
        }
    }
}

/// The lock-screen projection of one approval. `render_locked` deliberately
/// omits the title, every argument, and every secret: only the risk and a short
/// digest are shown. `render_unlocked` may show the bounded title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LockScreenView {
    pub title: String,
    pub digest_prefix: String,
    pub risk: Risk,
}

impl LockScreenView {
    pub fn new(
        title: impl Into<String>,
        digest_prefix: impl Into<String>,
        risk: Risk,
    ) -> Result<Self> {
        let digest_prefix = digest_prefix.into();
        if digest_prefix.is_empty() || !digest_prefix.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "a lock-screen digest prefix must be hexadecimal",
            ));
        }
        let title = sanitize_line(&title.into(), MAX_TITLE_CHARS);
        let digest_prefix = bound_chars(&digest_prefix, DIGEST_PREFIX_CHARS);
        Ok(Self { title, digest_prefix, risk })
    }

    /// Build the view from an action. The title is the action id, never an
    /// argument, so a secret in the arguments cannot reach either renderer.
    pub fn from_action(action: &MobileAction, risk: Risk) -> Self {
        let digest = action.digest();
        Self {
            title: sanitize_line(action.action_id(), MAX_TITLE_CHARS),
            digest_prefix: digest.prefix(DIGEST_PREFIX_CHARS),
            risk,
        }
    }

    /// The locked rendering: no title, no action arguments, no secret text.
    pub fn render_locked(&self) -> String {
        bound_chars(
            &format!(
                "Approval request · risk {} · digest {}",
                self.risk.as_str(),
                self.digest_prefix
            ),
            MAX_LOCKED_CHARS,
        )
    }

    /// The unlocked rendering: a bounded one-line summary.
    pub fn render_unlocked(&self) -> String {
        bound_chars(
            &format!(
                "{} · risk {} · digest {}",
                self.title,
                self.risk.as_str(),
                self.digest_prefix
            ),
            MAX_UNLOCKED_CHARS,
        )
    }

    pub fn secure_display(&self) -> SecureDisplay {
        secure_display_for(PromptSurface::Approval)
    }
}

/// A secret prompt shows a tag and an opaque handle, never the value. There is
/// no value field and no constructor that accepts one; the host reads the value
/// in its own secure input and keeps it out of this payload.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SecretReveal {
    pub tag: String,
    pub handle: String,
}

impl SecretReveal {
    pub fn new(tag: impl Into<String>, handle: impl Into<String>) -> Result<Self> {
        let tag = tag.into();
        let handle = handle.into();
        validate_identity("secret tag", &tag)?;
        validate_identity("secret handle", &handle)?;
        Ok(Self { tag, handle })
    }

    pub fn render(&self) -> String {
        bound_chars(
            &format!("Secret {} · handle {}", self.tag, self.handle),
            MAX_SECRET_LINE_CHARS,
        )
    }
}

/// What kind of surface is about to be drawn. Approvals and secrets carry
/// action names or typed values while a secret prompt is open; notifications
/// and transcript previews carry a bounded, already-redacted line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PromptSurface {
    Approval,
    Secret,
    Notification,
    TranscriptPreview,
}

/// The host's window-flag decision. The model reports it; the Android host must
/// apply [`SecureDisplay::window_flag`] before the first frame.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecureDisplay {
    pub required: bool,
    pub reason: String,
}

impl SecureDisplay {
    pub fn window_flag(&self) -> Option<&'static str> {
        self.required.then_some(FLAG_SECURE)
    }
}

pub fn secure_display_for(surface: PromptSurface) -> SecureDisplay {
    match surface {
        PromptSurface::Approval => SecureDisplay {
            required: true,
            reason: "approvals name an action and its target; keep them out of screenshots and the recents thumbnail"
                .to_string(),
        },
        PromptSurface::Secret => SecureDisplay {
            required: true,
            reason: "secret entry must not appear in screenshots, recordings, or the recents thumbnail"
                .to_string(),
        },
        PromptSurface::Notification => SecureDisplay {
            required: false,
            reason: "a notification carries a bounded status line and no secret".to_string(),
        },
        PromptSurface::TranscriptPreview => SecureDisplay {
            required: false,
            reason: "a transcript preview is a bounded excerpt with secrets redacted".to_string(),
        },
    }
}

fn validate_identity(label: &str, value: &str) -> Result<()> {
    if value.trim().is_empty() {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!("{label} must not be blank"),
        ));
    }
    if value.chars().count() > MAX_ID_CHARS {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("{label} is longer than {MAX_ID_CHARS} characters"),
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!("{label} must not contain control characters"),
        ));
    }
    Ok(())
}

fn sanitize_line(text: &str, max: usize) -> String {
    let flat: String = text.chars().map(|c| if c.is_control() { ' ' } else { c }).collect();
    let collapsed = flat.split_whitespace().collect::<Vec<_>>().join(" ");
    bound_chars(collapsed.trim(), max)
}

fn bound_chars(text: &str, max: usize) -> String {
    if text.chars().count() <= max {
        return text.to_string();
    }
    let keep = max.saturating_sub(1);
    let mut out: String = text.chars().take(keep).collect();
    out.push('…');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use zero_types::error::ErrorCode;

    const SECRET: &str = "sk-live-TOPSECRET-do-not-print";
    const DEVICE: &str = "device-pixel-9";

    fn action() -> MobileAction {
        MobileAction::new(
            "act-1",
            ActionClass::ShellMutating,
            "sess-1",
            json!({"command": "deploy production", "token": SECRET}),
        )
        .unwrap()
    }

    #[test]
    fn mobile_approval_a_valid_approval_verifies_and_is_consumed() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        store.verify(&approval, &action, DEVICE, 1_200).unwrap();

        assert_eq!(approval.challenge_id, challenge.id);
        assert_eq!(approval.digest, ActionDigest::of(&action));
        assert_eq!(approval.approved_by, DEVICE);
        assert!(store.is_consumed(&approval.nonce));
        assert_eq!(store.consumed_len(), 1);
    }

    #[test]
    fn mobile_approval_a_changed_action_fails_the_digest_binding() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mutated = MobileAction::new(
            "act-1",
            ActionClass::ShellMutating,
            "sess-1",
            json!({"command": "deploy staging", "token": SECRET}),
        )
        .unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        let err = store.verify(&approval, &mutated, DEVICE, 1_200).unwrap_err();

        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(err.message().contains(&approval.digest.short()));
        assert!(!store.is_consumed(&approval.nonce), "a refused approval is not spent");
    }

    #[test]
    fn mobile_approval_a_replayed_nonce_is_refused() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(8).unwrap();
        store.verify(&approval, &action, DEVICE, 1_200).unwrap();

        let mut forged = approval.clone();
        forged.challenge_id = "ma-forged".to_string();
        let err = store.verify(&forged, &action, DEVICE, 1_300).unwrap_err();

        assert_eq!(err.code(), ErrorCode::ApprovalResolved);
        assert!(err.message().contains(&approval.digest.short()));
    }

    #[test]
    fn mobile_approval_replaying_an_old_approval_fails() {
        // The Done criterion: a byte-for-byte replay of an approval that was
        // already spent is refused.
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        store.verify(&approval, &action, DEVICE, 1_200).unwrap();
        let err = store.verify(&approval, &action, DEVICE, 1_300).unwrap_err();

        assert_eq!(err.code(), ErrorCode::ApprovalResolved);
        assert!(err.message().contains(&approval.digest.short()));
        assert_eq!(store.consumed_len(), 1, "a replay does not add a second entry");
    }

    #[test]
    fn mobile_approval_consume_marks_used_and_refuses_reuse() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(4).unwrap();

        assert!(store.consume(&approval));
        assert!(store.is_consumed(&approval.nonce));
        assert!(!store.consume(&approval));
        assert_eq!(store.consumed_len(), 1);

        let err = store.verify(&approval, &action, DEVICE, 1_200).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ApprovalResolved);
    }

    #[test]
    fn mobile_approval_an_expired_approval_is_refused() {
        let action = action();
        let challenge = challenge(&action, 500, 1_000);
        assert_eq!(challenge.expires_ms, 1_500);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        let err = store.verify(&approval, &action, DEVICE, 1_500).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ApprovalExpired);
        assert!(err.message().contains(&approval.digest.short()));

        let late = approve(&challenge, MobileDecision::Allow, DEVICE, 1_500).unwrap_err();
        assert_eq!(late.code(), ErrorCode::ApprovalExpired);
        assert!(!store.is_consumed(&approval.nonce));
    }

    #[test]
    fn mobile_approval_a_wrong_device_is_refused() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        let err = store.verify(&approval, &action, "device-pixel-8", 1_200).unwrap_err();

        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(err.message().contains("different device"));
        assert!(err.message().contains(&approval.digest.short()));
        assert!(!store.is_consumed(&approval.nonce));
    }

    #[test]
    fn mobile_approval_a_denied_approval_is_refused() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Deny, DEVICE, 1_100).unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        let err = store.verify(&approval, &action, DEVICE, 1_200).unwrap_err();

        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(err.message().contains("denied"));
        assert!(!store.is_consumed(&approval.nonce));
    }

    #[test]
    fn mobile_approval_the_locked_view_hides_args_and_secrets() {
        let action = action();
        let view = LockScreenView::from_action(&action, Risk::High);
        let locked = view.render_locked();

        assert!(!locked.contains(SECRET));
        assert!(!locked.contains("deploy production"));
        assert!(!locked.contains("token"));
        assert!(locked.contains("high"));
        assert!(locked.contains(&action.digest().prefix(8)));
        assert!(!format!("{action:?}").contains(SECRET), "Debug must not print arguments");

        // Even if a caller puts sensitive text in the title, the locked view
        // omits the title entirely.
        let tampered =
            LockScreenView::new(format!("run deploy {SECRET}"), "0123456789ab", Risk::High).unwrap();
        let locked = tampered.render_locked();
        assert!(!locked.contains(SECRET));
        assert!(!locked.contains("deploy"));

        // The unlocked summary still carries the action id, not the args.
        let unlocked = view.render_unlocked();
        assert!(unlocked.contains("act-1"));
        assert!(!unlocked.contains(SECRET));
        assert!(!unlocked.contains("deploy production"));
    }

    #[test]
    fn mobile_approval_flag_secure_is_required_for_approvals_and_secrets() {
        let approval = secure_display_for(PromptSurface::Approval);
        assert!(approval.required);
        assert_eq!(approval.window_flag(), Some(FLAG_SECURE));
        assert!(!approval.reason.is_empty());

        let secret = secure_display_for(PromptSurface::Secret);
        assert!(secret.required);
        assert_eq!(secret.window_flag(), Some(FLAG_SECURE));

        for surface in [PromptSurface::Notification, PromptSurface::TranscriptPreview] {
            let display = secure_display_for(surface);
            assert!(!display.required, "{surface:?} may show in the recents thumbnail");
            assert_eq!(display.window_flag(), None);
        }

        let view = LockScreenView::from_action(&action(), Risk::Medium);
        assert!(view.secure_display().required);
    }

    #[test]
    fn mobile_approval_the_consumed_set_is_bounded_and_evicts_fifo() {
        let action = action();
        let mut store = ApprovalStore::new(2).unwrap();
        let mut approvals = Vec::new();
        for i in 0..3 {
            let challenge = challenge(&action, 60_000, 1_000 + i);
            approvals.push(approve(&challenge, MobileDecision::Allow, DEVICE, 1_500 + i).unwrap());
        }

        for approval in &approvals {
            assert!(store.consume(approval));
        }
        assert_eq!(store.consumed_len(), 2);
        assert!(!store.is_consumed(&approvals[0].nonce), "the oldest nonce is evicted");
        assert!(store.is_consumed(&approvals[1].nonce));
        assert!(store.is_consumed(&approvals[2].nonce));

        // FIFO eviction means the forgotten approval can pass again until it
        // expires. That is the documented cost of a bounded in-memory set.
        store.verify(&approvals[0], &action, DEVICE, 2_000).unwrap();
        assert_eq!(store.consumed_len(), 2);
        assert!(!store.is_consumed(&approvals[1].nonce), "the next-oldest nonce is evicted");

        assert_eq!(ApprovalStore::new(0).unwrap_err().code(), ErrorCode::InvalidInput);
        assert_eq!(ApprovalStore::default().capacity(), DEFAULT_CONSUMED_CAPACITY);
    }

    #[test]
    fn mobile_approval_digests_are_deterministic_and_order_independent() {
        let base = MobileAction::new(
            "act-1",
            ActionClass::Write,
            "sess-1",
            json!({"path": "a.rs", "body": "x"}),
        )
        .unwrap();
        let reordered = MobileAction::new(
            "act-1",
            ActionClass::Write,
            "sess-1",
            json!({"body": "x", "path": "a.rs"}),
        )
        .unwrap();

        assert_eq!(ActionDigest::of(&base), ActionDigest::of(&reordered));
        assert_eq!(ActionDigest::of(&base), ActionDigest::of(&base));
        assert_eq!(ActionDigest::of(&base).as_str().len(), 64);
        assert_eq!(ActionDigest::of(&base).short().len(), DIGEST_PREFIX_CHARS);

        let changed = [
            MobileAction::new("act-2", ActionClass::Write, "sess-1", json!({"path": "a.rs", "body": "x"})).unwrap(),
            MobileAction::new("act-1", ActionClass::Read, "sess-1", json!({"path": "a.rs", "body": "x"})).unwrap(),
            MobileAction::new("act-1", ActionClass::Write, "sess-2", json!({"path": "a.rs", "body": "x"})).unwrap(),
            MobileAction::new("act-1", ActionClass::Write, "sess-1", json!({"path": "b.rs", "body": "x"})).unwrap(),
        ];
        for other in changed {
            assert_ne!(ActionDigest::of(&base), ActionDigest::of(&other));
        }
    }

    #[test]
    fn mobile_approval_errors_name_the_digest_and_never_the_args() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let mutated = MobileAction::new(
            "act-1",
            ActionClass::ShellMutating,
            "sess-1",
            json!({"command": "deploy staging", "token": "sk-live-OTHER"}),
        )
        .unwrap();
        let mut store = ApprovalStore::new(8).unwrap();

        let err = store.verify(&approval, &mutated, DEVICE, 1_200).unwrap_err();
        let rendered = format!("{err} | {}", err.message());
        assert!(!rendered.contains(SECRET));
        assert!(!rendered.contains("deploy production"));
        assert!(!rendered.contains("sk-live-OTHER"));
        assert!(err.message().contains(&approval.digest.short()));

        let wrong_device = store.verify(&approval, &action, "device-pixel-8", 1_200).unwrap_err();
        assert!(!format!("{wrong_device}").contains(SECRET));
        assert!(wrong_device.message().contains(&approval.digest.short()));

        let expired = store.verify(&approval, &action, DEVICE, 61_000).unwrap_err();
        assert_eq!(expired.code(), ErrorCode::ApprovalExpired);
        assert!(!format!("{expired}").contains(SECRET));
    }

    #[test]
    fn mobile_approval_a_secret_value_never_enters_the_payload() {
        let action = action();
        let challenge = challenge(&action, 60_000, 1_000);
        let approval = approve(&challenge, MobileDecision::Allow, DEVICE, 1_100).unwrap();
        let view = LockScreenView::from_action(&action, Risk::High);
        let reveal = SecretReveal::new("OPENAI_API_KEY", "sec-42").unwrap();

        let payload = format!(
            "{approval:?}\n{}\n{}\n{:?}",
            view.render_locked(),
            reveal.render(),
            challenge
        );
        assert!(!payload.contains(SECRET));
        assert!(!payload.contains("sk-"));
        assert!(reveal.render().contains("OPENAI_API_KEY"));
        assert!(reveal.render().contains("sec-42"));
    }

    #[test]
    fn mobile_approval_identities_and_ttl_are_validated() {
        assert_eq!(
            MobileAction::new("", ActionClass::Read, "sess", json!({})).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            MobileAction::new("act", ActionClass::Read, " ", json!({})).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            MobileAction::new("a\tb", ActionClass::Read, "sess", json!({})).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            MobileAction::new("a".repeat(MAX_ID_CHARS + 1), ActionClass::Read, "sess", json!({}))
                .unwrap_err()
                .code(),
            ErrorCode::LimitExceeded
        );

        let action = MobileAction::new("act-1", ActionClass::Read, "sess-1", json!({})).unwrap();
        let challenge = challenge(&action, 1_000, 5);
        assert_eq!(
            approve(&challenge, MobileDecision::Allow, "", 10).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            approve(&challenge, MobileDecision::Allow, DEVICE, 1_005).unwrap_err().code(),
            ErrorCode::ApprovalExpired
        );

        assert_eq!(SecretReveal::new("", "handle").unwrap_err().code(), ErrorCode::InvalidInput);
        assert_eq!(SecretReveal::new("tag", "").unwrap_err().code(), ErrorCode::InvalidInput);
        assert_eq!(
            LockScreenView::new("title", "not-hex", Risk::Low).unwrap_err().code(),
            ErrorCode::InvalidInput
        );
    }
}
