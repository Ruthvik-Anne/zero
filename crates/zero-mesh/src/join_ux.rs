//! Join UX: one action to offer, a QR or short code to join (T-MESH-06,
//! MESH-06, MESH-07).
//!
//! MESH-07 asks for one action on the host — create the identity if needed,
//! mint the invite, and show the QR — and a join on the guest by QR or by a
//! typed short code. This slice owns that glue. It mints exactly one
//! single-use [`JoinToken`] per offer, renders both encodings from the same
//! token, and records the guest's request as a [`PendingJoin`] until the owner
//! approves it. Approval is the existing
//! [`Membership::approve`](crate::identity::Membership::approve) flow: an
//! unapproved request is pending state, never a membership.
//!
//! There is no account, no service, and no network code here. The offer, the
//! QR payload, and the short code are plain values; the guest hands the
//! payload back to the host by whatever channel the two devices already have.
//! In the finished product that channel is the authenticated LAN/mDNS
//! transport (T-MESH-03/T-MESH-04); this module deliberately does not open a
//! socket, so the flow is testable offline and cannot leak an invite through a
//! background listener (MESH-06, MESH-12).
//!
//! Timing is modelled, not measured: [`JoinTimeline`] records the host's
//! one-action moment, the scan, the approval, and the joined moment, and
//! [`JoinTimeline::within_target`] checks MESH-07's "under a minute". The
//! values are supplied by the caller (the UI clock), so the test suite proves
//! the rule rather than the wall-clock speed of the host.

use std::fmt;

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::identity::{
    approve, device_id_for, issue_token, parse_join_payload, verify_token, DeviceRecord, JoinToken,
    KeyPair, Membership, PendingJoin, JOIN_PAYLOAD_PREFIX,
};

/// Default lifetime of a one-action join offer: five minutes. The token ceiling
/// is [`MAX_TOKEN_TTL_MS`](crate::identity::MAX_TOKEN_TTL_MS); an offer is meant
/// to be short-lived.
pub const DEFAULT_OFFER_TTL_MS: i64 = 5 * 60 * 1000;

/// MESH-07's completion target: the guest is a member within one minute of the
/// host's one action.
pub const JOIN_TARGET_MS: i64 = 60_000;

/// The result of the host's one action: a signed single-use token plus both
/// encodings a guest can use.
///
/// `qr_payload` and `short_code` are secrets. [`fmt::Debug`] prints the token
/// id and the window only; it never prints the payload, the code, or the token
/// secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinOffer {
    /// The signed, single-use token. It stays on the host; only its id and
    /// secret are shared through the encodings below.
    pub token: JoinToken,
    /// `zero-join:v1:<id>:<secret_b64>`, the string a QR image encodes.
    pub qr_payload: String,
    /// The human-typeable Crockford base32 code.
    pub short_code: String,
    /// When the host took the action, in milliseconds since the Unix epoch.
    pub created_ms: i64,
    /// When the offer (and its token) expires, in milliseconds since the Unix
    /// epoch.
    pub expires_ms: i64,
}

impl fmt::Debug for JoinOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinOffer")
            .field("token_id", &self.token.id)
            .field("created_ms", &self.created_ms)
            .field("expires_ms", &self.expires_ms)
            .finish_non_exhaustive()
    }
}

impl JoinOffer {
    /// The token id the offer shares.
    pub fn id(&self) -> &str {
        &self.token.id
    }

    /// True once the offer's token is past its expiry. Matches
    /// [`verify_token`](crate::identity::verify_token): the boundary itself is
    /// still valid.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms > self.expires_ms
    }

    /// Milliseconds until expiry, saturating at zero.
    pub fn remaining_ms(&self, now_ms: i64) -> i64 {
        self.expires_ms.saturating_sub(now_ms).max(0)
    }

    /// Check that the two encodings and the timestamps still describe the
    /// token, and that the offer has not expired.
    ///
    /// A serialised offer is not a signed value, so a caller that loaded one
    /// from disk or from another process calls this before trusting it. A
    /// mismatch means the offer was edited and is `zero.fnd.invalid_input`; an
    /// expired offer is `zero.pol.approval_expired`.
    pub fn validate(&self, now_ms: i64) -> Result<(), ZeroError> {
        if self.created_ms != self.token.issued_ms {
            return Err(invalid(
                "offer creation time does not match the token issue time; regenerate the offer",
            ));
        }
        if self.expires_ms != self.token.expires_ms {
            return Err(invalid(
                "offer expiry does not match the token expiry; regenerate the offer",
            ));
        }
        if self.qr_payload != self.token.payload()? {
            return Err(invalid(
                "offer QR payload does not match its token; regenerate the offer",
            ));
        }
        if self.short_code != self.token.short_code()? {
            return Err(invalid(
                "offer short code does not match its token; regenerate the offer",
            ));
        }
        if self.is_expired(now_ms) {
            return Err(expired(format!(
                "join offer `{}` expired at {} ms",
                self.token.id, self.expires_ms
            )));
        }
        Ok(())
    }
}

/// The host's one action: mint a token and render the QR payload and short code
/// from it.
///
/// `ttl_ms` is bounded by [`issue_token`](crate::identity::issue_token): it must
/// be positive and at most
/// [`MAX_TOKEN_TTL_MS`](crate::identity::MAX_TOKEN_TTL_MS). The default UI value
/// is [`DEFAULT_OFFER_TTL_MS`]. No account, service, or network call is made.
pub fn one_action_offer(
    owner_key: &KeyPair,
    ttl_ms: i64,
    now_ms: i64,
) -> Result<JoinOffer, ZeroError> {
    let token = issue_token(owner_key, ttl_ms, now_ms)?;
    Ok(JoinOffer {
        qr_payload: token.payload()?,
        short_code: token.short_code()?,
        created_ms: token.issued_ms,
        expires_ms: token.expires_ms,
        token,
    })
}

/// Record a guest's QR payload against the offer the host minted.
///
/// The host is the only party that holds the signed [`JoinOffer`], so it passes
/// the offer it created; the guest supplies the text it scanned and its own
/// public key. The checks run in this order:
///
/// 1. `owner_key` is the membership's owner root;
/// 2. the guest is not already a member (that is `zero.pol.denied`, not a
///    second pending request);
/// 3. an existing pending request is returned unchanged, so a retry after a
///    dropped reply is idempotent and consumes nothing;
/// 4. the offer is internally consistent and unexpired;
/// 5. the token verifies against this owner root and is unused;
/// 6. the payload parses and is the id and secret of this offer, not another;
/// 7. [`Membership::join`](crate::identity::Membership::join) consumes the token
///    and records the [`PendingJoin`].
///
/// Success still means **pending**: the returned request is not a membership.
/// Call [`approve_pending`] on the host to complete the join. A bad, expired,
/// used, or foreign code is a typed [`ZeroError`] whose message says what to do
/// next.
pub fn join_with_payload(
    owner_key: &KeyPair,
    membership: &mut Membership,
    offer: &JoinOffer,
    payload: &str,
    device_pubkey_b64: &str,
    now_ms: i64,
) -> Result<PendingJoin, ZeroError> {
    require_owner(owner_key, membership)?;
    let device_id = device_id_for(device_pubkey_b64)?;

    if membership.is_member(&device_id) {
        return Err(denied(format!(
            "device `{device_id}` is already a member; no join is needed"
        )));
    }
    if let Some(pending) = membership.pending.get(&device_id) {
        return Ok(pending.clone());
    }

    offer.validate(now_ms).map_err(join_guidance)?;
    verify_token(&offer.token, &owner_key.public_key_b64(), now_ms).map_err(join_guidance)?;

    let parsed = parse_join_payload(payload).map_err(|error| {
        guided(
            ErrorCode::InvalidInput,
            format!(
                "that is not a usable join code: {}; scan the QR again or retype the short code exactly as shown",
                error.message()
            ),
        )
    })?;
    if parsed.id != offer.token.id || parsed.secret_b64 != offer.token.secret_b64 {
        return Err(guided(
            ErrorCode::PolicyDenied,
            "that QR or short code belongs to a different invite",
        ));
    }

    let mut token = offer.token.clone();
    match membership.join(&mut token, device_pubkey_b64, now_ms) {
        Ok(record) => Err(denied(format!(
            "device `{}` is already a member; no join is needed",
            record.device_id
        ))),
        Err(error) => match membership.pending.get(&device_id) {
            Some(pending) => Ok(pending.clone()),
            None => Err(join_guidance(error)),
        },
    }
}

/// [`join_with_payload`] for a typed short code.
///
/// The same offer and checks apply. A QR payload pasted into the code field is
/// refused with guidance instead of being silently accepted, so the two entry
/// points stay distinguishable in the UI.
pub fn join_with_short_code(
    owner_key: &KeyPair,
    membership: &mut Membership,
    offer: &JoinOffer,
    short_code: &str,
    device_pubkey_b64: &str,
    now_ms: i64,
) -> Result<PendingJoin, ZeroError> {
    if short_code.trim().starts_with(JOIN_PAYLOAD_PREFIX) {
        return Err(guided(
            ErrorCode::InvalidInput,
            "that is a QR payload, not a short code; scan the QR or use join_with_payload",
        ));
    }
    join_with_payload(
        owner_key,
        membership,
        offer,
        short_code,
        device_pubkey_b64,
        now_ms,
    )
}

/// Approve a pending join, completing the membership.
///
/// This is the host-side step of MESH-08's explicit approval. It delegates to
/// [`Membership::approve`](crate::identity::Membership::approve), which requires
/// the owner root and also re-admits a revoked device. Approving a device that
/// is already a member is idempotent; an id with no pending request and no
/// record is `zero.fnd.not_found` with guidance to have the device join first.
pub fn approve_pending(
    owner_key: &KeyPair,
    membership: &mut Membership,
    pending_id: &str,
    now_ms: i64,
) -> Result<DeviceRecord, ZeroError> {
    if !membership.pending.contains_key(pending_id) {
        let live = membership
            .devices
            .get(pending_id)
            .filter(|record| !record.revoked);
        if let Some(record) = live {
            return Ok(record.clone());
        }
        return Err(not_found(format!(
            "no pending join for device `{pending_id}`; have the device join first, then approve it"
        )));
    }
    approve(membership, owner_key, pending_id, now_ms)
}

/// The four moments of one join, in milliseconds since the Unix epoch.
///
/// `offer_ms` is the host's one action; `scanned_ms` is when the guest read the
/// QR or finished typing the code; `approved_ms` is the owner's decision; and
/// `joined_ms` is when the guest could use the mesh. Later milestones are
/// optional so an in-flight join can be reported without inventing a finish
/// time.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinTimeline {
    /// When the host minted the offer.
    pub offer_ms: i64,
    /// When the guest scanned or entered the code.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub scanned_ms: Option<i64>,
    /// When the owner approved the pending join.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub approved_ms: Option<i64>,
    /// When the guest was a member and could use the mesh.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub joined_ms: Option<i64>,
}

impl JoinTimeline {
    /// Start a timeline at the host's one action.
    pub fn new(offer_ms: i64) -> Self {
        Self {
            offer_ms,
            scanned_ms: None,
            approved_ms: None,
            joined_ms: None,
        }
    }

    /// Record the scan. It may not precede the offer or the previous
    /// milestone.
    pub fn mark_scanned(mut self, now_ms: i64) -> Result<Self, ZeroError> {
        self.ensure_after(now_ms, "scan")?;
        self.scanned_ms = Some(now_ms);
        Ok(self)
    }

    /// Record the owner's approval. It may not precede the previous milestone.
    pub fn mark_approved(mut self, now_ms: i64) -> Result<Self, ZeroError> {
        self.ensure_after(now_ms, "approval")?;
        self.approved_ms = Some(now_ms);
        Ok(self)
    }

    /// Record the moment the guest could use the mesh. It may not precede the
    /// previous milestone.
    pub fn mark_joined(mut self, now_ms: i64) -> Result<Self, ZeroError> {
        self.ensure_after(now_ms, "join")?;
        self.joined_ms = Some(now_ms);
        Ok(self)
    }

    /// True once the joined moment is known.
    pub fn completed(&self) -> bool {
        self.joined_ms.is_some()
    }

    /// Offer-to-joined duration, when the join finished.
    pub fn join_duration_ms(&self) -> Option<i64> {
        self.joined_ms.map(|joined| joined - self.offer_ms)
    }

    /// True when the finished join took at most `target_ms`.
    ///
    /// An unfinished timeline is not "within target" — there is no result yet.
    /// A non-positive target is unsatisfiable.
    pub fn within_target(&self, target_ms: i64) -> bool {
        target_ms > 0 && self.join_duration_ms().is_some_and(|ms| ms <= target_ms)
    }

    fn last_ms(&self) -> i64 {
        self.joined_ms
            .or(self.approved_ms)
            .or(self.scanned_ms)
            .unwrap_or(self.offer_ms)
    }

    fn ensure_after(&self, now_ms: i64, label: &str) -> Result<(), ZeroError> {
        let anchor = self.last_ms();
        if now_ms < anchor {
            return Err(invalid(format!(
                "join {label} at {now_ms} ms precedes the previous milestone at {anchor} ms"
            )));
        }
        Ok(())
    }
}

fn require_owner(owner_key: &KeyPair, membership: &Membership) -> Result<(), ZeroError> {
    if owner_key.public_key_b64() != membership.owner_public_key_b64 {
        return Err(denied(
            "only the owner root of this membership can record a join",
        ));
    }
    Ok(())
}

/// Attach the next step to a join failure. The code is preserved, so callers
/// can still branch on `zero.pol.approval_expired` versus `zero.pol.denied`.
fn join_guidance(error: ZeroError) -> ZeroError {
    let hint = match error.code() {
        ErrorCode::ApprovalExpired => "the invite expired; create a fresh invite on the host",
        ErrorCode::PolicyDenied if error.message().contains("already been used") => {
            "that invite was already used; create a fresh invite on the host"
        }
        ErrorCode::PolicyDenied if error.message().contains("not signed by the owner root") => {
            "that invite was not signed by this mesh's owner root; scan a QR from the host"
        }
        ErrorCode::PolicyDenied => "ask the host to approve this device, or create a fresh invite",
        ErrorCode::InvalidInput => "scan the QR again or retype the short code exactly as shown",
        _ => "create a fresh invite on the host and try again",
    };
    ZeroError::new(error.code(), format!("{}; {hint}", error.message()))
}

fn guided(code: ErrorCode, message: impl Into<String>) -> ZeroError {
    ZeroError::new(code, message)
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn not_found(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::NotFound, message)
}

fn expired(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ApprovalExpired, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::{join, MAX_TOKEN_TTL_MS};

    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 2 * 60 * 1000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn host() -> (Membership, KeyPair) {
        let owner = key();
        let membership = Membership::new(owner.public_key_b64()).expect("membership");
        (membership, owner)
    }

    fn new_offer(owner: &KeyPair) -> JoinOffer {
        one_action_offer(owner, TTL, NOW).expect("offer")
    }

    fn error_code<T: std::fmt::Debug>(result: Result<T, ZeroError>) -> ErrorCode {
        result.expect_err("the operation should fail").code()
    }

    #[test]
    fn one_action_offer_carries_a_qr_code_and_expiry() {
        let five_minutes = 5 * 60 * 1000;
        assert_eq!(DEFAULT_OFFER_TTL_MS, five_minutes);
        const { assert!(DEFAULT_OFFER_TTL_MS <= MAX_TOKEN_TTL_MS) };

        let owner = key();
        let offer = one_action_offer(&owner, TTL, NOW).expect("offer");

        assert!(offer.qr_payload.starts_with(JOIN_PAYLOAD_PREFIX));
        assert!(offer.short_code.contains('-'));
        assert_eq!(offer.created_ms, NOW);
        assert_eq!(offer.expires_ms, NOW + TTL);
        assert_eq!(offer.token.issued_ms, offer.created_ms);
        assert_eq!(offer.token.expires_ms, offer.expires_ms);
        assert_eq!(offer.token.used, 0);
        assert_eq!(offer.token.max_uses, 1);
        assert!(!offer.token.signature_b64.is_empty());
        assert_eq!(offer.id(), offer.token.id);

        let parsed = parse_join_payload(&offer.qr_payload).expect("parse QR");
        assert_eq!(parsed.id, offer.token.id);
        assert_eq!(parsed.secret_b64, offer.token.secret_b64);
        let parsed = parse_join_payload(&offer.short_code).expect("parse short code");
        assert_eq!(parsed.id, offer.token.id);
        assert_eq!(parsed.secret_b64, offer.token.secret_b64);

        offer.validate(NOW).expect("fresh offer is consistent");
        assert!(!offer.is_expired(NOW));
        assert!(
            !offer.is_expired(NOW + TTL),
            "the expiry boundary is still valid"
        );
        assert!(offer.is_expired(NOW + TTL + 1));
        assert_eq!(offer.remaining_ms(NOW), TTL);
        assert_eq!(offer.remaining_ms(NOW + TTL + 5), 0);

        assert_eq!(
            one_action_offer(&owner, 0, NOW)
                .expect_err("zero ttl")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            one_action_offer(&owner, MAX_TOKEN_TTL_MS + 1, NOW)
                .expect_err("ttl above the ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn qr_and_short_code_are_secrets_in_debug_output() {
        let owner = key();
        let offer = new_offer(&owner);
        let debug = format!("{offer:?}");
        assert!(debug.contains(offer.id()), "{debug}");
        assert!(!debug.contains(&offer.qr_payload), "{debug}");
        assert!(!debug.contains(&offer.short_code), "{debug}");
        assert!(!debug.contains(&offer.token.secret_b64), "{debug}");
    }

    #[test]
    fn a_valid_qr_join_is_pending_until_approval() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = new_offer(&owner);

        let pending = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect("valid QR records a pending join");

        assert_eq!(pending.device_id, guest.device_id());
        assert_eq!(pending.public_key_b64, guest.public_key_b64());
        assert_eq!(pending.token_id, offer.token.id);
        assert_eq!(pending.requested_ms, NOW + 1_000);
        assert!(membership.pending.contains_key(guest.device_id()));
        assert!(!membership.is_member(guest.device_id()));
        assert!(membership.devices.is_empty());
        assert!(membership.consumed_tokens.contains_key(&offer.token.id));

        // A retry while pending is idempotent: no second request, no error.
        let again = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 2_000,
        )
        .expect("pending retry");
        assert_eq!(again, pending);
        assert_eq!(membership.pending.len(), 1);
    }

    #[test]
    fn a_valid_short_code_join_is_pending_until_approval() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = new_offer(&owner);

        let pending = join_with_short_code(
            &owner,
            &mut membership,
            &offer,
            &offer.short_code.to_lowercase(),
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect("a typed short code joins");

        assert_eq!(pending.device_id, guest.device_id());
        assert!(membership.pending.contains_key(guest.device_id()));
        assert!(!membership.is_member(guest.device_id()));

        // A QR payload in the code field is refused with guidance.
        let error = join_with_short_code(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_500,
        )
        .expect_err("a QR payload is not a short code");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("QR payload"), "{error}");
        assert!(error.message().contains("scan the QR"), "{error}");
    }

    #[test]
    fn an_expired_invite_is_refused_with_guidance() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = one_action_offer(&owner, 1_000, NOW).expect("short offer");

        let error = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_001,
        )
        .expect_err("expired invite");
        assert_eq!(error.code(), ErrorCode::ApprovalExpired);
        assert!(error.message().contains("expired"), "{error}");
        assert!(error.message().contains("fresh invite"), "{error}");
        assert!(error.remediation().contains("fresh approval"), "{error}");

        assert!(membership.pending.is_empty());
        assert!(!membership.is_member(guest.device_id()));
        assert!(membership.consumed_tokens.is_empty());
    }

    #[test]
    fn a_reused_invite_is_refused_and_the_second_device_stays_out() {
        let (mut membership, owner) = host();
        let first = key();
        let second = key();
        let offer = new_offer(&owner);

        join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &first.public_key_b64(),
            NOW + 1_000,
        )
        .expect("first guest joins as pending");

        let error = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &second.public_key_b64(),
            NOW + 2_000,
        )
        .expect_err("a single-use invite cannot admit a second device");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("already been used"), "{error}");
        assert!(error.message().contains("fresh invite"), "{error}");

        assert!(!membership.pending.contains_key(second.device_id()));
        assert!(!membership.is_member(second.device_id()));
        assert_eq!(membership.pending.len(), 1);
    }

    #[test]
    fn a_tampered_or_foreign_code_is_refused_with_guidance() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = new_offer(&owner);
        let other = new_offer(&owner);

        // Garbage text.
        let error = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            "lunch at noon",
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect_err("garbage");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(
            error.message().contains("not a usable join code"),
            "{error}"
        );
        assert!(error.message().contains("scan the QR"), "{error}");

        // A well-formed code from a different invite.
        let error = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &other.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect_err("another invite's code");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("different invite"), "{error}");

        // The host's own offer edited so the encoding no longer matches.
        let mut edited = offer.clone();
        edited.short_code = other.short_code.clone();
        let error = join_with_short_code(
            &owner,
            &mut membership,
            &edited,
            &edited.short_code,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect_err("edited offer");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(
            error.message().contains("does not match its token"),
            "{error}"
        );

        // A token secret swapped after minting: the signature no longer covers
        // the presented secret.
        let mut forged = offer.clone();
        forged.token.secret_b64 = other.token.secret_b64.clone();
        forged.qr_payload = forged
            .token
            .payload()
            .expect("payload for the forged token");
        forged.short_code = forged
            .token
            .short_code()
            .expect("code for the forged token");
        let error = join_with_payload(
            &owner,
            &mut membership,
            &forged,
            &forged.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect_err("tampered token");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("not signed by the owner root"),
            "{error}"
        );
        assert!(
            error.message().contains("scan a QR from the host"),
            "{error}"
        );

        assert!(membership.pending.is_empty());
        assert!(!membership.is_member(guest.device_id()));
    }

    #[test]
    fn approval_completes_membership_and_is_idempotent() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = new_offer(&owner);

        join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect("pending join");

        let record = approve_pending(&owner, &mut membership, guest.device_id(), NOW + 2_000)
            .expect("owner approves");
        assert_eq!(record.device_id, guest.device_id());
        assert_eq!(record.public_key_b64, guest.public_key_b64());
        assert_eq!(record.added_ms, NOW + 2_000);
        assert!(!record.revoked);
        assert!(membership.is_member(guest.device_id()));
        assert!(membership.pending.is_empty());

        let again = approve_pending(&owner, &mut membership, guest.device_id(), NOW + 3_000)
            .expect("approval is idempotent");
        assert_eq!(again, record);
        assert_eq!(membership.devices.len(), 1);

        // A member rescanning is told there is nothing to do.
        let error = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 4_000,
        )
        .expect_err("already a member");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("already a member"), "{error}");

        let absent = key();
        assert_eq!(
            error_code(approve_pending(
                &owner,
                &mut membership,
                absent.device_id(),
                NOW
            )),
            ErrorCode::NotFound
        );
    }

    #[test]
    fn a_two_device_join_completes_under_a_minute() {
        let (mut membership, host_key) = host();
        let guest_key = key();
        assert_ne!(host_key.device_id(), guest_key.device_id());

        let offer = one_action_offer(&host_key, DEFAULT_OFFER_TTL_MS, NOW).expect("one action");
        let pending = join_with_payload(
            &host_key,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest_key.public_key_b64(),
            NOW + 4_000,
        )
        .expect("guest scans the QR");
        assert_eq!(pending.device_id, guest_key.device_id());

        approve_pending(
            &host_key,
            &mut membership,
            guest_key.device_id(),
            NOW + 25_000,
        )
        .expect("host approves");

        let timeline = JoinTimeline::new(NOW)
            .mark_scanned(NOW + 4_000)
            .expect("scan")
            .mark_approved(NOW + 25_000)
            .expect("approval")
            .mark_joined(NOW + 25_500)
            .expect("joined");
        assert!(timeline.completed());
        assert_eq!(timeline.join_duration_ms(), Some(25_500));
        assert!(timeline.within_target(JOIN_TARGET_MS));
        assert!(timeline.join_duration_ms().unwrap() < JOIN_TARGET_MS);
        let one_minute = 60_000;
        assert_eq!(JOIN_TARGET_MS, one_minute);

        // The people-facing rule: two keys, one offer, one approval, member.
        assert!(membership.is_member(guest_key.device_id()));
        assert_ne!(membership.owner_public_key_b64, guest_key.public_key_b64());
    }

    #[test]
    fn an_over_target_join_is_reported_not_hidden() {
        let timeline = JoinTimeline::new(NOW)
            .mark_scanned(NOW + 5_000)
            .expect("scan")
            .mark_approved(NOW + 55_000)
            .expect("approval")
            .mark_joined(NOW + 61_000)
            .expect("joined");
        assert_eq!(timeline.join_duration_ms(), Some(61_000));
        assert!(!timeline.within_target(JOIN_TARGET_MS));
        assert!(!timeline.within_target(1));

        // An unfinished join has no duration and is not within any target.
        let unfinished = JoinTimeline::new(NOW)
            .mark_scanned(NOW + 1_000)
            .expect("scan");
        assert!(!unfinished.completed());
        assert_eq!(unfinished.join_duration_ms(), None);
        assert!(!unfinished.within_target(JOIN_TARGET_MS));

        // Milestones must move forward.
        assert_eq!(
            error_code(JoinTimeline::new(NOW).mark_scanned(NOW - 1)),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            error_code(
                JoinTimeline::new(NOW)
                    .mark_scanned(NOW + 10)
                    .expect("scan")
                    .mark_approved(NOW + 5)
            ),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn a_foreign_owner_or_unusable_offer_is_typed() {
        let (mut membership, owner) = host();
        let stranger = key();
        let guest = key();
        let offer = new_offer(&owner);

        // A key that is not this membership's root cannot record the join.
        let error = join_with_payload(
            &stranger,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect_err("foreign owner");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("owner root"), "{error}");

        // A malformed device key is invalid input, not a pending join.
        assert_eq!(
            error_code(join_with_payload(
                &owner,
                &mut membership,
                &offer,
                &offer.qr_payload,
                "not base64",
                NOW + 1_000,
            )),
            ErrorCode::InvalidInput
        );
        assert!(membership.pending.is_empty());
    }

    #[test]
    fn the_offer_and_timeline_have_no_account_or_service_fields() {
        let owner = key();
        let offer = new_offer(&owner);
        let timeline = JoinTimeline::new(NOW)
            .mark_scanned(NOW + 1_000)
            .expect("scan")
            .mark_joined(NOW + 2_000)
            .expect("joined");

        let mut keys = Vec::new();
        collect_keys(
            &serde_json::to_value(&offer).expect("offer json"),
            &mut keys,
        );
        collect_keys(
            &serde_json::to_value(timeline).expect("timeline json"),
            &mut keys,
        );

        let offer_json = serde_json::to_value(&offer).expect("offer json");
        let mut top: Vec<&str> = offer_json
            .as_object()
            .expect("offer object")
            .keys()
            .map(String::as_str)
            .collect();
        top.sort_unstable();
        assert_eq!(
            top,
            vec![
                "created_ms",
                "expires_ms",
                "qr_payload",
                "short_code",
                "token"
            ],
            "the offer field set is closed"
        );

        for forbidden in [
            "account", "service", "user", "email", "cloud", "relay", "url", "signup", "password",
        ] {
            assert!(
                !keys.iter().any(|key| key.contains(forbidden)),
                "serialised join UX carries `{forbidden}`: {keys:?}"
            );
        }

        // Structural check: this module opens no socket and names no transport.
        // The needles are split so the assertion itself is not a match.
        let source = include_str!("join_ux.rs");
        for needle in [
            concat!("std::", "net"),
            concat!("Tcp", "Stream"),
            concat!("Tcp", "Listener"),
            concat!("Udp", "Socket"),
            concat!("http", "://"),
            concat!("re", "qwest"),
        ] {
            assert!(
                !source.contains(needle),
                "join_ux must stay offline; found `{needle}`"
            );
        }
    }

    #[test]
    fn offers_pending_joins_and_timelines_survive_serde() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = new_offer(&owner);
        let pending = join_with_payload(
            &owner,
            &mut membership,
            &offer,
            &offer.qr_payload,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect("pending");

        let json = serde_json::to_string(&offer).expect("offer serialise");
        let restored_offer: JoinOffer = serde_json::from_str(&json).expect("offer parse");
        assert_eq!(restored_offer, offer);
        restored_offer
            .validate(NOW)
            .expect("restored offer is valid");

        let json = serde_json::to_string(&pending).expect("pending serialise");
        let restored_pending: PendingJoin = serde_json::from_str(&json).expect("pending parse");
        assert_eq!(restored_pending, pending);

        let timeline = JoinTimeline::new(NOW)
            .mark_scanned(NOW + 1_000)
            .expect("scan")
            .mark_approved(NOW + 2_000)
            .expect("approval")
            .mark_joined(NOW + 3_000)
            .expect("joined");
        let json = serde_json::to_string(&timeline).expect("timeline serialise");
        let restored: JoinTimeline = serde_json::from_str(&json).expect("timeline parse");
        assert_eq!(restored, timeline);
        assert_eq!(restored.join_duration_ms(), Some(3_000));

        // A partially recorded timeline keeps its missing milestones optional.
        let partial = JoinTimeline::new(NOW);
        let json = serde_json::to_string(&partial).expect("partial serialise");
        assert!(!json.contains("scanned_ms"), "{json}");
        let restored: JoinTimeline = serde_json::from_str(&json).expect("partial parse");
        assert_eq!(restored, partial);
    }

    #[test]
    fn the_join_path_reuses_the_identity_contract() {
        let (mut membership, owner) = host();
        let guest = key();
        let offer = new_offer(&owner);

        // The same token, presented directly, is single-use and waits for
        // approval; the UX layer does not invent a second membership path.
        let mut token = offer.token.clone();
        let error = join(
            &mut membership,
            &mut token,
            &guest.public_key_b64(),
            NOW + 1_000,
        )
        .expect_err("pending approval");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(token.used, 1);
        assert!(membership.pending.contains_key(guest.device_id()));
    }

    fn collect_keys(value: &serde_json::Value, out: &mut Vec<String>) {
        match value {
            serde_json::Value::Object(map) => {
                for (key, nested) in map {
                    out.push(key.clone());
                    collect_keys(nested, out);
                }
            }
            serde_json::Value::Array(items) => {
                for item in items {
                    collect_keys(item, out);
                }
            }
            _ => {}
        }
    }
}
