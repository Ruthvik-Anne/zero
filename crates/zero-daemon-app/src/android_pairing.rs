//! Android pairing (T-AND-01, AND-01, AND-02).
//!
//! The Android app is a remote control: it pairs with one host and then drives
//! that host's sessions. Pairing has three rules, and this module is the whole
//! of them:
//!
//! 1. **The host offers, the phone answers.** [`start_pairing`] mints one
//!    [`PairingOffer`] from OS entropy. The offer carries a QR payload and a
//!    short code, both derived deterministically from the offer secret, and a
//!    bounded lifetime ([`DEFAULT_PAIRING_TTL_MS`], at most
//!    [`MAX_PAIRING_TTL_MS`]). There is no account, no service, and no URL.
//! 2. **A stolen code cannot pair.** A [`PairingRequest`] must name this exact
//!    offer, carry the full secret (not only the printed short code), arrive
//!    before expiry, and be the first request for the offer. The first success
//!    consumes the offer and binds it to one device id, so a copied or replayed
//!    request is `zero.pol.denied`.
//! 3. **A human unlocks it.** [`pair`] requires a [`BiometricGate`]; a denied or
//!    failed unlock aborts the attempt without consuming the offer. The only way
//!    to skip the prompt is an explicit host-only setting
//!    ([`PairingConfig::allow_without_biometric`]), which is never read from the
//!    wire.
//!
//! The transport is deliberately absent. The offer and request are plain values
//! that travel over the authenticated mesh or loopback ([`PAIRING_TRANSPORT`]);
//! this module opens no socket and the host exposes no public listener. See
//! `docs/android.md`.
//!
//! Lock-screen safety is [`public_preview`]: it renders a request as a device
//! name and a status only, never the offer id, secret, short code, or token.

use std::fmt;

use serde::{Deserialize, Serialize};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Default lifetime of a pairing offer: five minutes.
pub const DEFAULT_PAIRING_TTL_MS: u64 = 5 * 60 * 1000;

/// Hard ceiling on a pairing offer's lifetime: ten minutes. Pairing is meant to
/// be immediate; a longer window is refused with `zero.fnd.limit_exceeded`.
pub const MAX_PAIRING_TTL_MS: u64 = 10 * 60 * 1000;

/// Prefix of the QR payload: `zero-android-pair:v1:<id>:<secret>`.
pub const QR_PAYLOAD_PREFIX: &str = "zero-android-pair:v1:";

/// The transport pairing uses. There is no public endpoint: the phone dials the
/// host over the authenticated mesh, or over loopback when both run on one
/// machine. The host never listens for an unauthenticated pairing request.
pub const PAIRING_TRANSPORT: &str =
    "mesh or loopback only; the host never opens a public pairing listener";

/// Reason shown by the platform biometric prompt.
pub const BIOMETRIC_PAIRING_REASON: &str = "Confirm pairing with this Android device";

/// Cap on a device name, in characters.
pub const MAX_DEVICE_NAME_CHARS: usize = 64;

/// Cap on a device id, in characters.
pub const MAX_DEVICE_ID_CHARS: usize = 128;

/// Cap on the offer id carried by a request, in characters.
pub const MAX_OFFER_ID_CHARS: usize = 64;

/// Cap on the secret field of a request, in characters. The typed form groups a
/// 64-character hex secret and may carry separators.
pub const MAX_SECRET_INPUT_CHARS: usize = 128;

/// Cap on the short code field of a request, in characters. It is larger than a
/// real code so a pasted QR payload reaches the comparison and is reported as a
/// mismatch, not as malformed input.
pub const MAX_CODE_INPUT_CHARS: usize = 160;

/// OS-entropy bytes behind one offer secret.
const SECRET_BYTES: usize = 32;

/// OS-entropy bytes behind one session token.
const TOKEN_BYTES: usize = 32;

/// Number of hex characters in a secret.
const SECRET_HEX_CHARS: usize = SECRET_BYTES * 2;

/// Short-code shape: four groups of four Crockford base32 characters.
const SHORT_CODE_GROUPS: usize = 4;
const SHORT_CODE_GROUP_LEN: usize = 4;

/// Crockford base32: no `I`, `L`, `O`, or `U`, so a code cannot be misread.
const CROCKFORD: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";

const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// Characters of the device name kept in a lock-screen preview.
const PREVIEW_NAME_CHARS: usize = 40;

/// The host's one action: a single-use pairing offer.
///
/// `secret`, `qr_payload`, and `short_code` are the offer's credentials.
/// [`fmt::Debug`] prints the id and the window only; it never prints the secret,
/// the QR payload, or the short code. The value is not serialisable as a whole:
/// [`PairingOffer::public_view`] is the safe, endpoint-free view to hand to a
/// renderer.
#[derive(Clone, PartialEq, Eq)]
pub struct PairingOffer {
    /// Offer id, derived from the secret.
    pub id: String,
    /// The full secret. It travels in the QR payload and nowhere else.
    pub secret: String,
    /// `zero-android-pair:v1:<id>:<secret>`, the string a QR image encodes.
    pub qr_payload: String,
    /// The human-readable commitment to the secret. It is **not** a credential
    /// on its own; pairing still requires the secret.
    pub short_code: String,
    /// When the offer was minted, in milliseconds since the Unix epoch.
    pub issued_ms: u64,
    /// When the offer expires, in milliseconds since the Unix epoch. The
    /// boundary itself is refused.
    pub expires_ms: u64,
    /// Single-use is the only supported shape.
    pub single_use: bool,
    /// Set by the first successful [`pair`]. Not serialised.
    consumed: bool,
    /// The device id the first successful [`pair`] bound. Not serialised.
    bound_device_id: Option<String>,
}

impl fmt::Debug for PairingOffer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingOffer")
            .field("id", &self.id)
            .field("secret", &"<redacted>")
            .field("qr_payload", &"<redacted>")
            .field("short_code", &"<redacted>")
            .field("issued_ms", &self.issued_ms)
            .field("expires_ms", &self.expires_ms)
            .field("single_use", &self.single_use)
            .field("consumed", &self.consumed)
            .field("bound_device_id", &self.bound_device_id)
            .finish()
    }
}

/// The endpoint-free view of an offer for a pairing screen.
///
/// It carries the id, short code, and window so the host can display and
/// re-display the offer, and nothing that names an account, a service, a URL, or
/// a listener. The secret and QR payload stay behind
/// [`PairingOffer`] because they are credentials.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingOfferView {
    pub id: String,
    pub short_code: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub single_use: bool,
}

impl PairingOffer {
    /// True once the offer is past its expiry. The boundary is refused, matching
    /// [`pair`].
    pub fn is_expired(&self, now_ms: u64) -> bool {
        now_ms >= self.expires_ms
    }

    /// Milliseconds until expiry, saturating at zero.
    pub fn remaining_ms(&self, now_ms: u64) -> u64 {
        self.expires_ms.saturating_sub(now_ms)
    }

    /// True after a successful [`pair`].
    pub fn is_consumed(&self) -> bool {
        self.consumed
    }

    /// The device id the offer is bound to, if it has been paired.
    pub fn bound_device_id(&self) -> Option<&str> {
        self.bound_device_id.as_deref()
    }

    /// The safe view for a pairing screen: no secret, no QR payload, no
    /// endpoint.
    pub fn public_view(&self) -> PairingOfferView {
        PairingOfferView {
            id: self.id.clone(),
            short_code: self.short_code.clone(),
            issued_ms: self.issued_ms,
            expires_ms: self.expires_ms,
            single_use: self.single_use,
        }
    }

    /// The secret grouped for manual entry, e.g. `a1b2c3d4-...`. The phone sends
    /// the hex digits back as [`PairingRequest::secret`]; the separators are
    /// ignored by [`pair`]. This is the "one-time code" form for a phone without
    /// a camera: it is long because it is the credential.
    pub fn typed_code(&self) -> String {
        let mut out = String::with_capacity(self.secret.len() + self.secret.len() / 8);
        for (index, ch) in self.secret.chars().enumerate() {
            if index > 0 && index % 8 == 0 {
                out.push('-');
            }
            out.push(ch);
        }
        out
    }

    /// Check that the offer is internally consistent: the id, QR payload, and
    /// short code all derive from the secret, and the window is bounded.
    ///
    /// A restored offer is a plain value, so the host calls this (or [`pair`],
    /// which calls it first) before trusting one. An edited offer is
    /// `zero.fnd.invalid_input` with guidance to mint a new one.
    pub fn validate(&self) -> Result<()> {
        if !is_lower_hex(&self.secret, SECRET_HEX_CHARS) {
            return Err(invalid(
                "pairing offer secret is not 64 lowercase hex characters; mint a new offer",
            ));
        }
        if self.id != derive_id(&self.secret) {
            return Err(invalid(
                "pairing offer id does not match its secret; mint a new offer",
            ));
        }
        if self.qr_payload != qr_payload_for(&self.id, &self.secret) {
            return Err(invalid(
                "pairing offer QR payload does not match its secret; mint a new offer",
            ));
        }
        if self.short_code != short_code_for(&self.secret) {
            return Err(invalid(
                "pairing offer short code does not match its secret; mint a new offer",
            ));
        }
        if self.expires_ms <= self.issued_ms {
            return Err(invalid(
                "pairing offer expiry does not follow its issue time; mint a new offer",
            ));
        }
        if self.expires_ms - self.issued_ms > MAX_PAIRING_TTL_MS {
            return Err(invalid(
                "pairing offer lifetime exceeds the ten-minute ceiling; mint a shorter offer",
            ));
        }
        Ok(())
    }
}

/// The host's one action. `ttl_ms` must be positive and at most
/// [`MAX_PAIRING_TTL_MS`]; the default UI value is
/// [`DEFAULT_PAIRING_TTL_MS`]. The secret is [`SECRET_BYTES`] OS-entropy bytes;
/// the id, QR payload, and short code are derived from it deterministically. No
/// account, service, or network call is made.
pub fn start_pairing(ttl_ms: u64, now_ms: u64) -> Result<PairingOffer> {
    if ttl_ms == 0 {
        return Err(invalid(
            "a pairing offer needs a positive lifetime; use five minutes",
        ));
    }
    if ttl_ms > MAX_PAIRING_TTL_MS {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!(
                "a pairing offer may live at most {MAX_PAIRING_TTL_MS} ms; {ttl_ms} ms was requested"
            ),
        ));
    }
    let secret = hex(&zero_secrets::signin::random_bytes(SECRET_BYTES));
    let id = derive_id(&secret);
    let expires_ms = now_ms.checked_add(ttl_ms).ok_or_else(|| {
        invalid("pairing offer expiry would overflow the millisecond clock; check the host clock")
    })?;
    Ok(PairingOffer {
        qr_payload: qr_payload_for(&id, &secret),
        short_code: short_code_for(&secret),
        id,
        secret,
        issued_ms: now_ms,
        expires_ms,
        single_use: true,
        consumed: false,
        bound_device_id: None,
    })
}

/// The phone's answer to one offer.
///
/// `device_name` is the only field a lock-screen preview may show. `secret` and
/// `code` are credentials for the offer and are redacted by [`fmt::Debug`].
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairingRequest {
    /// The offer this request is for.
    pub offer_id: String,
    /// The full secret from the QR payload or the grouped typed code.
    pub secret: String,
    /// The phone's stable device id.
    pub device_id: String,
    /// The name the user sees.
    pub device_name: String,
    /// The printed short code, for the host's display and a fast mismatch check.
    pub code: String,
    /// When the phone built the request, in milliseconds since the Unix epoch.
    pub now_ms: u64,
}

impl fmt::Debug for PairingRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairingRequest")
            .field("offer_id", &self.offer_id)
            .field("secret", &"<redacted>")
            .field("device_id", &self.device_id)
            .field("device_name", &self.device_name)
            .field("code", &"<redacted>")
            .field("now_ms", &self.now_ms)
            .finish()
    }
}

/// A paired phone. `token` is the session credential the phone keeps; it is
/// minted from OS entropy at pairing and is never printed by [`fmt::Debug`].
///
/// The pairing is single use. The session token is not: it authorises later
/// session traffic until the host revokes the device (T-AND-02/T-MESH).
#[derive(Clone, PartialEq, Eq)]
pub struct PairedDevice {
    pub device_id: String,
    pub name: String,
    pub paired_at: u64,
    /// Session token, 32 OS-entropy bytes as hex. Redacted in `Debug`.
    pub token: String,
}

impl fmt::Debug for PairedDevice {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PairedDevice")
            .field("device_id", &self.device_id)
            .field("name", &self.name)
            .field("paired_at", &self.paired_at)
            .field("token", &"<redacted>")
            .finish()
    }
}

/// The platform biometric prompt.
///
/// The Android host implements this over `BiometricPrompt`; tests implement it
/// directly. `unlock` returns `Ok(())` only after the user confirmed the prompt.
pub trait BiometricGate {
    fn unlock(&self, reason: &str) -> Result<()>;
}

/// Gate one host action behind biometric confirmation. Pairing calls this with
/// [`BIOMETRIC_PAIRING_REASON`]; a failed or denied unlock is returned
/// unchanged.
pub fn require_biometric(gate: &dyn BiometricGate, reason: &str) -> Result<()> {
    gate.unlock(reason)
}

/// Host-only pairing settings. This value is built by the host, never parsed
/// from an offer or a request.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PairingConfig {
    /// Skip the biometric prompt. It exists for hosts without a biometric sensor
    /// and is **refused for pairing** unless the host explicitly sets it; the
    /// default is `false`. It is not a wire field.
    pub allow_without_biometric: bool,
}

/// Pair one phone with one offer, requiring biometric confirmation.
///
/// Checks run in this order: the offer is internally consistent, the offer is
/// single-use and unused, the request is addressed to this offer and carries the
/// matching secret and short code, the offer has not expired, and the biometric
/// gate confirms. Every pairing failure is `zero.pol.denied`; only a malformed
/// offer or request is `zero.fnd.invalid_input`.
///
/// On success the offer is consumed and bound to `request.device_id`, so a
/// copied or replayed request fails. A denied biometric aborts the attempt
/// without consuming the offer, so the user can retry.
pub fn pair(
    offer: &mut PairingOffer,
    request: &PairingRequest,
    gate: &dyn BiometricGate,
    now_ms: u64,
) -> Result<PairedDevice> {
    pair_with_config(offer, request, Some(gate), &PairingConfig::default(), now_ms)
}

/// [`pair`] with an explicit host setting. `gate` is `None` only when the host
/// set [`PairingConfig::allow_without_biometric`]; any other `None` is refused.
///
/// The setting is host-only: neither [`PairingOffer`] nor [`PairingRequest`]
/// carries it, so a phone cannot ask to skip the prompt.
pub fn pair_with_config(
    offer: &mut PairingOffer,
    request: &PairingRequest,
    gate: Option<&dyn BiometricGate>,
    config: &PairingConfig,
    now_ms: u64,
) -> Result<PairedDevice> {
    offer.validate()?;
    validate_request(request)?;
    check_offer_usable(offer, request, now_ms)?;

    match gate {
        Some(gate) => require_biometric(gate, BIOMETRIC_PAIRING_REASON)?,
        None if config.allow_without_biometric => {}
        None => {
            return Err(denied(
                "pairing requires biometric confirmation; unlock the device to pair",
            ));
        }
    }

    let token = session_token();
    offer.consumed = true;
    offer.bound_device_id = Some(request.device_id.clone());
    Ok(PairedDevice {
        device_id: request.device_id.clone(),
        name: request.device_name.clone(),
        paired_at: now_ms,
        token,
    })
}

/// A lock-screen-safe line for a pending pairing request: the device name and a
/// status only.
///
/// The offer id, device id, secret, and short code are omitted. The name is
/// flattened to one line, occurrences of the secret or code are redacted, and
/// the result is bounded, so a request that names itself after its secret cannot
/// leak it onto the lock screen.
pub fn public_preview(request: &PairingRequest) -> String {
    let mut name = one_line(&request.device_name);
    let normalized_secret = normalize_secret(&request.secret);
    let normalized_code = normalize_short_code(&request.code);
    for needle in [
        request.secret.as_str(),
        normalized_secret.as_str(),
        request.code.as_str(),
        normalized_code.as_str(),
    ] {
        name = redact(&name, needle);
    }
    let name = bounded_name(&name);
    format!("pairing request · {name} · pending")
}

/// A lock-screen-safe line for a paired device: the device name and a status
/// only. The session token and device id are omitted.
pub fn paired_preview(device: &PairedDevice) -> String {
    let name = redact(&one_line(&device.name), &device.token);
    let name = bounded_name(&name);
    format!("paired device · {name} · paired")
}

fn check_offer_usable(
    offer: &PairingOffer,
    request: &PairingRequest,
    now_ms: u64,
) -> Result<()> {
    if !offer.single_use {
        return Err(denied(
            "this pairing offer is not single-use; mint a fresh offer",
        ));
    }
    if offer.consumed {
        return Err(denied(
            "this pairing offer was already used; mint a fresh offer",
        ));
    }
    if let Some(bound) = offer.bound_device_id() {
        if bound != request.device_id {
            return Err(denied(
                "this pairing offer is bound to another device; mint a fresh offer",
            ));
        }
    }
    if now_ms < offer.issued_ms {
        return Err(denied(
            "this pairing offer is not valid yet; check the host clock",
        ));
    }
    if offer.is_expired(now_ms) {
        return Err(denied(
            "this pairing offer expired; mint a fresh offer on the host",
        ));
    }
    // The request must also have been built while the offer was live. This is a
    // sanity check on the phone's clock, not the security boundary.
    if request.now_ms < offer.issued_ms || request.now_ms >= offer.expires_ms {
        return Err(denied(
            "this pairing request was built outside the offer's lifetime; mint a fresh offer",
        ));
    }
    if request.offer_id != offer.id {
        return Err(denied(
            "this pairing request names a different offer; scan the host's QR again",
        ));
    }
    if !constant_time_eq(&normalize_secret(&request.secret), &offer.secret) {
        return Err(denied(
            "the pairing secret does not match this offer; scan the QR again",
        ));
    }
    if !constant_time_eq(
        &normalize_short_code(&request.code),
        &normalize_short_code(&offer.short_code),
    ) {
        return Err(denied(
            "the pairing short code does not match this offer; retype it from the host screen",
        ));
    }
    Ok(())
}

fn validate_request(request: &PairingRequest) -> Result<()> {
    if request.offer_id.trim().is_empty()
        || request.offer_id.chars().count() > MAX_OFFER_ID_CHARS
    {
        return Err(invalid(
            "pairing request needs an offer id of at most 64 characters",
        ));
    }
    if request.device_id.trim().is_empty()
        || request.device_id.chars().count() > MAX_DEVICE_ID_CHARS
    {
        return Err(invalid(
            "pairing request needs a device id of at most 128 characters",
        ));
    }
    if request.device_name.trim().is_empty()
        || request.device_name.chars().count() > MAX_DEVICE_NAME_CHARS
    {
        return Err(invalid(
            "pairing request needs a device name of at most 64 characters",
        ));
    }
    if request.secret.trim().is_empty()
        || request.secret.chars().count() > MAX_SECRET_INPUT_CHARS
    {
        return Err(invalid(
            "pairing request needs the offer secret, not only the short code",
        ));
    }
    if request.code.trim().is_empty()
        || request.code.chars().count() > MAX_CODE_INPUT_CHARS
    {
        return Err(invalid(
            "pairing request needs the offer's short code",
        ));
    }
    Ok(())
}

/// `zero-android-pair:v1:<id>:<secret>`. Deterministic in the secret.
fn qr_payload_for(id: &str, secret: &str) -> String {
    format!("{QR_PAYLOAD_PREFIX}{id}:{secret}")
}

/// The offer id: the first 16 hex characters of an FNV-1a hash of the secret.
fn derive_id(secret: &str) -> String {
    format!("{:016x}", fnv1a(secret.as_bytes(), FNV_OFFSET))
}

/// Four groups of four Crockford base32 characters, derived from two FNV-1a
/// passes over the secret. Deterministic; not invertible to the secret.
fn short_code_for(secret: &str) -> String {
    let first = base32(fnv1a(secret.as_bytes(), FNV_OFFSET));
    let second = base32(fnv1a(secret.as_bytes(), FNV_OFFSET ^ 0x9e37_79b9_7f4a_7c15));
    let raw: String = first
        .chars()
        .chain(second.chars())
        .take(SHORT_CODE_GROUPS * SHORT_CODE_GROUP_LEN)
        .collect();
    group(&raw, SHORT_CODE_GROUP_LEN)
}

fn base32(mut value: u64) -> String {
    let mut out = String::with_capacity(13);
    for _ in 0..13 {
        out.push(CROCKFORD[(value & 0x1f) as usize] as char);
        value >>= 5;
    }
    out
}

fn group(raw: &str, size: usize) -> String {
    let mut out = String::with_capacity(raw.len() + raw.len() / size);
    for (index, ch) in raw.chars().enumerate() {
        if index > 0 && index % size == 0 {
            out.push('-');
        }
        out.push(ch);
    }
    out
}

/// Normalise a typed short code: uppercase, Crockford aliases (`I`/`L` to `1`,
/// `O` to `0`), separators dropped. Anything outside the alphabet is dropped, so
/// a pasted QR payload cannot normalise into a valid code.
fn normalize_short_code(code: &str) -> String {
    let mut out = String::with_capacity(code.len());
    for ch in code.trim().chars() {
        let upper = ch.to_ascii_uppercase();
        let mapped = match upper {
            'I' | 'L' => Some('1'),
            'O' => Some('0'),
            '-' | ' ' | '_' | '\t' => None,
            other if other.is_ascii() && CROCKFORD.contains(&(other as u8)) => Some(other),
            _ => None,
        };
        if let Some(ch) = mapped {
            out.push(ch);
        }
    }
    out
}

/// Normalise a typed secret: lowercase hex, separators dropped. A grouped
/// [`PairingOffer::typed_code`] and the raw QR secret normalise to the same
/// value.
fn normalize_secret(secret: &str) -> String {
    secret
        .chars()
        .filter(|ch| ch.is_ascii_hexdigit())
        .map(|ch| ch.to_ascii_lowercase())
        .collect()
}

fn is_lower_hex(text: &str, length: usize) -> bool {
    text.len() == length
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn constant_time_eq(left: &str, right: &str) -> bool {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut difference = left.len() ^ right.len();
    for (index, byte) in left.iter().enumerate() {
        difference |= usize::from(byte ^ right.get(index).copied().unwrap_or(0));
    }
    for byte in right.iter().skip(left.len()) {
        difference |= usize::from(*byte);
    }
    difference == 0
}

fn fnv1a(bytes: &[u8], seed: u64) -> u64 {
    let mut hash = seed;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(FNV_PRIME);
    }
    hash
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(DIGITS[usize::from(byte >> 4)] as char);
        out.push(DIGITS[usize::from(byte & 0x0f)] as char);
    }
    out
}

fn session_token() -> String {
    hex(&zero_secrets::signin::random_bytes(TOKEN_BYTES))
}

/// Flatten text to one line: control characters and whitespace runs become a
/// single space, and leading/trailing space is dropped.
fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_control() || ch.is_whitespace() {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(ch);
        }
    }
    out
}

fn redact(text: &str, needle: &str) -> String {
    if needle.is_empty() {
        return text.to_string();
    }
    text.replace(needle, "<redacted>")
}

fn bounded_name(name: &str) -> String {
    let trimmed = name.trim();
    if trimmed.is_empty() {
        return "unknown device".into();
    }
    trimmed.chars().take(PREVIEW_NAME_CHARS).collect()
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    const NOW: u64 = 1_700_000_000_000;
    const TTL: u64 = 2 * 60 * 1000;

    struct AcceptGate;

    impl BiometricGate for AcceptGate {
        fn unlock(&self, _reason: &str) -> Result<()> {
            Ok(())
        }
    }

    struct DenyGate;

    impl BiometricGate for DenyGate {
        fn unlock(&self, _reason: &str) -> Result<()> {
            Err(denied("biometric confirmation was denied"))
        }
    }

    struct RecordingGate {
        reasons: RefCell<Vec<String>>,
    }

    impl RecordingGate {
        fn new() -> Self {
            Self { reasons: RefCell::new(Vec::new()) }
        }

        fn seen(&self) -> Vec<String> {
            self.reasons.borrow().clone()
        }
    }

    impl BiometricGate for RecordingGate {
        fn unlock(&self, reason: &str) -> Result<()> {
            self.reasons.borrow_mut().push(reason.to_string());
            Ok(())
        }
    }

    fn offer() -> PairingOffer {
        start_pairing(TTL, NOW).expect("a bounded TTL mints an offer")
    }

    fn request(offer: &PairingOffer, device_id: &str, now_ms: u64) -> PairingRequest {
        PairingRequest {
            offer_id: offer.id.clone(),
            secret: offer.secret.clone(),
            device_id: device_id.into(),
            device_name: "Pixel 9".into(),
            code: offer.short_code.clone(),
            now_ms,
        }
    }

    fn error_code<T: fmt::Debug>(result: Result<T>) -> ErrorCode {
        result.expect_err("the operation should fail").code()
    }

    fn assert_denied<T: fmt::Debug>(result: Result<T>) {
        let error = result.expect_err("the operation should be denied");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert_eq!(error.code().as_str(), "zero.pol.denied");
    }

    #[test]
    fn android_pairing_a_valid_code_pairs_exactly_once() {
        let mut offer = offer();
        let request = request(&offer, "device-a", NOW + 1_000);
        let paired = pair(&mut offer, &request, &AcceptGate, NOW + 1_000).expect("valid pairing");

        assert_eq!(paired.device_id, "device-a");
        assert_eq!(paired.name, "Pixel 9");
        assert_eq!(paired.paired_at, NOW + 1_000);
        assert_eq!(paired.token.len(), TOKEN_BYTES * 2);
        assert!(paired.token.chars().all(|ch| ch.is_ascii_hexdigit()));
        assert!(offer.is_consumed());
        assert_eq!(offer.bound_device_id(), Some("device-a"));

        assert_denied(pair(&mut offer, &request, &AcceptGate, NOW + 2_000));
        assert_eq!(offer.bound_device_id(), Some("device-a"));
    }

    #[test]
    fn android_pairing_a_replayed_or_copied_request_cannot_pair() {
        let mut offer = offer();
        let original = request(&offer, "device-a", NOW + 1_000);
        pair(&mut offer, &original, &AcceptGate, NOW + 1_000).expect("first pairing");

        // The same phone replaying the same request.
        assert_denied(pair(&mut offer, &original, &AcceptGate, NOW + 1_500));

        // Another phone with a byte-for-byte copy of the request.
        let mut copied = original.clone();
        copied.device_id = "device-b".into();
        assert_denied(pair(&mut offer, &copied, &AcceptGate, NOW + 1_500));

        // A fresh request against the consumed offer is still refused.
        let fresh = request(&offer, "device-a", NOW + 1_500);
        assert_denied(pair(&mut offer, &fresh, &AcceptGate, NOW + 1_500));
        assert_eq!(offer.bound_device_id(), Some("device-a"));
    }

    #[test]
    fn android_pairing_an_expired_offer_is_refused() {
        let mut short = start_pairing(1_000, NOW).expect("one-second offer");
        assert!(!short.is_expired(NOW + 999));
        assert!(short.is_expired(NOW + 1_000), "the boundary is refused");
        assert_eq!(short.remaining_ms(NOW + 250), 750);
        assert_eq!(short.remaining_ms(NOW + 5_000), 0);

        let stale = request(&short, "device-a", NOW + 500);
        assert_denied(pair(&mut short, &stale, &AcceptGate, NOW + 1_000));
        assert!(!short.is_consumed());

        let mut fresh = start_pairing(1_000, NOW).expect("fresh offer");
        let live = request(&fresh, "device-a", NOW + 999);
        pair(&mut fresh, &live, &AcceptGate, NOW + 999).expect("inside the window");

        // A request built for a later window is refused now, and a request built
        // before the offer existed would be denied too.
        let mut later = start_pairing(1_000, NOW).expect("later offer");
        let after = request(&later, "device-b", NOW + 2_000);
        assert_denied(pair(&mut later, &after, &AcceptGate, NOW + 2_000));
    }

    #[test]
    fn android_pairing_a_wrong_code_secret_or_offer_is_refused() {
        let mut offer = offer();

        let mut wrong_code = request(&offer, "device-a", NOW + 1_000);
        wrong_code.code = "ZZZZ-ZZZZ-ZZZZ-ZZZZ".into();
        assert_denied(pair(&mut offer, &wrong_code, &AcceptGate, NOW + 1_000));
        assert!(!offer.is_consumed(), "a refused attempt consumes nothing");

        let mut wrong_secret = request(&offer, "device-a", NOW + 1_000);
        wrong_secret.secret = "0".repeat(SECRET_HEX_CHARS);
        assert_denied(pair(&mut offer, &wrong_secret, &AcceptGate, NOW + 1_000));

        let mut wrong_offer = request(&offer, "device-a", NOW + 1_000);
        wrong_offer.offer_id = "0000000000000000".into();
        assert_denied(pair(&mut offer, &wrong_offer, &AcceptGate, NOW + 1_000));

        // A missing secret is not the same as a wrong one: it is malformed
        // input, not a credential attempt.
        let mut secretless = request(&offer, "device-a", NOW + 1_000);
        secretless.secret.clear();
        assert_eq!(
            error_code(pair(&mut offer, &secretless, &AcceptGate, NOW + 1_000)),
            ErrorCode::InvalidInput
        );

        let good = request(&offer, "device-a", NOW + 1_000);
        pair(&mut offer, &good, &AcceptGate, NOW + 1_000).expect("the offer is still live");
    }

    #[test]
    fn android_pairing_a_stolen_code_cannot_pair_another_device() {
        let mut offer = offer();
        let stolen_code = offer.short_code.clone();
        let stolen_offer_id = offer.id.clone();

        // The attacker saw the printed short code but never the QR secret.
        let mut attacker = request(&offer, "attacker", NOW + 1_000);
        attacker.code = stolen_code.clone();
        attacker.secret = "0".repeat(SECRET_HEX_CHARS);
        attacker.device_name = "Attacker".into();
        assert_denied(pair(&mut offer, &attacker, &AcceptGate, NOW + 1_000));
        assert!(!offer.is_consumed());

        // A QR payload is a credential; knowledge of the code alone is not.
        let mut payload_typed_as_code = request(&offer, "attacker", NOW + 1_000);
        payload_typed_as_code.code = offer.qr_payload.clone();
        assert_denied(pair(
            &mut offer,
            &payload_typed_as_code,
            &AcceptGate,
            NOW + 1_000,
        ));

        // The owner pairs. After that, even the full copied request cannot admit
        // another device id.
        let owner = request(&offer, "owner-phone", NOW + 1_000);
        pair(&mut offer, &owner, &AcceptGate, NOW + 1_000).expect("owner pairs");

        let mut stolen_full = owner.clone();
        stolen_full.device_id = "attacker".into();
        stolen_full.device_name = "Attacker".into();
        stolen_full.offer_id = stolen_offer_id;
        assert_denied(pair(
            &mut offer,
            &stolen_full,
            &AcceptGate,
            NOW + 1_500,
        ));
        assert_eq!(offer.bound_device_id(), Some("owner-phone"));
    }

    #[test]
    fn android_pairing_requires_biometrics_and_denial_aborts() {
        let mut offer = offer();
        let request = request(&offer, "device-a", NOW + 1_000);

        let denial = pair(&mut offer, &request, &DenyGate, NOW + 1_000)
            .expect_err("a denied prompt aborts pairing");
        assert_eq!(denial.code(), ErrorCode::PolicyDenied);
        assert!(denial.message().contains("biometric"), "{denial}");
        assert!(!offer.is_consumed(), "denial must not burn the offer");

        // The user can retry and confirm.
        let gate = RecordingGate::new();
        pair(&mut offer, &request, &gate, NOW + 1_000).expect("second attempt confirms");
        assert_eq!(gate.seen(), vec![BIOMETRIC_PAIRING_REASON.to_string()]);
        assert!(gate.seen()[0].to_lowercase().contains("pairing"));
    }

    #[test]
    fn android_pairing_without_a_gate_needs_the_host_setting() {
        let mut offer = offer();
        let request = request(&offer, "device-a", NOW + 1_000);

        // No gate and the default config: refused, and the offer survives.
        assert_denied(pair_with_config(
            &mut offer,
            &request,
            None,
            &PairingConfig::default(),
            NOW + 1_000,
        ));
        assert!(!offer.is_consumed());

        // The explicit host setting is the only way to skip the prompt.
        let config = PairingConfig { allow_without_biometric: true };
        let paired = pair_with_config(&mut offer, &request, None, &config, NOW + 1_000)
            .expect("host explicitly opted out");
        assert_eq!(paired.device_id, "device-a");
        assert!(offer.is_consumed());
    }

    #[test]
    fn android_pairing_preview_hides_the_secret_code_and_token() {
        let offer = offer();
        let mut request = request(&offer, "device-a", NOW + 1_000);
        request.device_name = "Pixel\n9".into();

        let preview = public_preview(&request);
        assert!(preview.contains("Pixel 9"), "{preview}");
        assert!(preview.contains("pending"), "{preview}");
        assert!(!preview.contains('\n'), "{preview}");
        assert!(!preview.contains(&request.secret), "{preview}");
        assert!(!preview.contains(&request.code), "{preview}");
        assert!(!preview.contains(&request.offer_id), "{preview}");
        assert!(!preview.contains(&request.device_id), "{preview}");

        // A device that names itself after its secret cannot leak it.
        let mut self_named = request.clone();
        self_named.device_name = format!("Pixel {}", request.secret);
        let preview = public_preview(&self_named);
        assert!(!preview.contains(&request.secret), "{preview}");
        assert!(preview.contains("<redacted>"), "{preview}");

        let mut paired_offer = offer.clone();
        let paired = pair(&mut paired_offer, &request, &AcceptGate, NOW + 1_000)
            .expect("pair for preview");
        let paired_line = paired_preview(&paired);
        assert!(paired_line.contains("Pixel 9"), "{paired_line}");
        assert!(paired_line.contains("paired"), "{paired_line}");
        assert!(!paired_line.contains(&paired.token), "{paired_line}");
        assert!(!paired_line.contains(&paired.device_id), "{paired_line}");
        assert!(!paired_line.contains(&offer.short_code), "{paired_line}");
    }

    #[test]
    fn android_pairing_offer_has_no_endpoint_account_or_service_fields() {
        let offer = offer();
        let value = serde_json::to_value(offer.public_view()).expect("offer view json");
        let keys: std::collections::BTreeSet<&str> =
            value.as_object().expect("object").keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["expires_ms", "id", "issued_ms", "short_code", "single_use"]
                .into_iter()
                .collect(),
            "the public offer field set is closed"
        );

        let serialized = value.to_string().to_lowercase();
        for forbidden in [
            "account",
            "service",
            "url",
            "endpoint",
            "host",
            "port",
            "cloud",
            "signup",
            "password",
        ] {
            assert!(
                !serialized.contains(forbidden),
                "the offer view carries `{forbidden}`: {serialized}"
            );
        }

        assert!(PAIRING_TRANSPORT.contains("mesh"), "{PAIRING_TRANSPORT}");
        assert!(PAIRING_TRANSPORT.contains("loopback"));
        assert!(PAIRING_TRANSPORT.contains("never opens a public"));

        // Structural check: this module opens no socket and names no transport.
        // The needles are split so the assertion itself is not a match.
        let source = include_str!("android_pairing.rs");
        for needle in [
            concat!("std::", "net"),
            concat!("Tcp", "Listener"),
            concat!("Tcp", "Stream"),
            concat!("Udp", "Socket"),
            concat!("http", "://"),
            concat!("0.0.0.", "0"),
            concat!("re", "qwest"),
        ] {
            assert!(
                !source.contains(needle),
                "android_pairing must stay off the network; found `{needle}`"
            );
        }
    }

    #[test]
    fn android_pairing_secrets_and_tokens_are_redacted_in_debug() {
        let mut offer = offer();
        let request = request(&offer, "device-a", NOW + 1_000);
        let paired = pair(&mut offer, &request, &AcceptGate, NOW + 1_000).expect("pair");

        let debug = format!("{offer:?}");
        assert!(debug.contains(&offer.id), "{debug}");
        assert!(!debug.contains(&offer.secret), "{debug}");
        assert!(!debug.contains(&offer.qr_payload), "{debug}");
        assert!(!debug.contains(&offer.short_code), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");

        let debug = format!("{request:?}");
        assert!(debug.contains("Pixel 9"), "{debug}");
        assert!(!debug.contains(&request.secret), "{debug}");
        assert!(!debug.contains(&request.code), "{debug}");

        let debug = format!("{paired:?}");
        assert!(debug.contains("device-a"), "{debug}");
        assert!(!debug.contains(&paired.token), "{debug}");
        assert!(debug.contains("<redacted>"), "{debug}");

        // The session token is fresh for every pairing.
        let mut second_offer = self::offer();
        let second_request = self::request(&second_offer, "device-b", NOW + 1_000);
        let second = pair(&mut second_offer, &second_request, &AcceptGate, NOW + 1_000)
            .expect("second pair");
        assert_ne!(paired.token, second.token);
    }

    #[test]
    fn android_pairing_qr_and_short_code_are_deterministic() {
        let offer = offer();
        offer.validate().expect("a minted offer is consistent");
        assert_eq!(offer.qr_payload, qr_payload_for(&offer.id, &offer.secret));
        assert_eq!(offer.short_code, short_code_for(&offer.secret));
        assert_eq!(
            offer.qr_payload,
            format!("{QR_PAYLOAD_PREFIX}{}:{}", offer.id, offer.secret)
        );
        assert_eq!(offer.short_code.chars().filter(|c| *c != '-').count(), 16);
        assert!(offer.short_code.chars().all(|c| c == '-' || CROCKFORD.contains(&(c as u8))));
        assert_eq!(offer.typed_code().chars().filter(|c| *c == '-').count(), 7);
        assert_eq!(
            normalize_secret(&offer.typed_code()),
            offer.secret,
            "the grouped typed code is the same secret"
        );

        // A second offer shares no secret, id, or code with the first.
        let other = self::offer();
        assert_ne!(other.secret, offer.secret);
        assert_ne!(other.id, offer.id);
        assert_ne!(other.short_code, offer.short_code);

        // A restored offer with the same derived fields is accepted.
        let restored = PairingOffer {
            id: offer.id.clone(),
            secret: offer.secret.clone(),
            qr_payload: qr_payload_for(&offer.id, &offer.secret),
            short_code: short_code_for(&offer.secret),
            issued_ms: offer.issued_ms,
            expires_ms: offer.expires_ms,
            single_use: true,
            consumed: false,
            bound_device_id: None,
        };
        restored.validate().expect("derived fields validate");

        // Any edit to a credential or the window is refused.
        for tampered in [
            PairingOffer { id: "0000000000000000".into(), ..restored.clone() },
            PairingOffer { qr_payload: "zero-android-pair:v1:x:y".into(), ..restored.clone() },
            PairingOffer { short_code: "AAAA-AAAA-AAAA-AAAA".into(), ..restored.clone() },
            PairingOffer { expires_ms: restored.issued_ms, ..restored.clone() },
            PairingOffer {
                expires_ms: restored.issued_ms + MAX_PAIRING_TTL_MS + 1,
                ..restored.clone()
            },
        ] {
            let result = tampered.validate();
            assert_eq!(error_code(result), ErrorCode::InvalidInput);
        }

        // A non-single-use offer is structurally readable but refused for
        // pairing: the offer contract has exactly one shape.
        let mut reusable = restored.clone();
        reusable.single_use = false;
        let request = request(&reusable, "device-a", NOW + 1_000);
        assert_denied(pair(&mut reusable, &request, &AcceptGate, NOW + 1_000));
        assert!(!reusable.is_consumed());
    }

    #[test]
    fn android_pairing_ttl_is_bounded() {
        assert_eq!(
            error_code(start_pairing(0, NOW)),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            error_code(start_pairing(MAX_PAIRING_TTL_MS + 1, NOW)),
            ErrorCode::LimitExceeded
        );

        let shortest = start_pairing(1, NOW).expect("one millisecond is allowed");
        assert_eq!(shortest.expires_ms, NOW + 1);
        assert_eq!(shortest.remaining_ms(NOW), 1);

        let longest = start_pairing(MAX_PAIRING_TTL_MS, NOW).expect("the ceiling is allowed");
        assert_eq!(longest.expires_ms, NOW + MAX_PAIRING_TTL_MS);
        assert_eq!(longest.issued_ms, NOW);
        assert!(longest.single_use);

        let default = start_pairing(DEFAULT_PAIRING_TTL_MS, NOW).expect("the default");
        assert_eq!(default.expires_ms - default.issued_ms, DEFAULT_PAIRING_TTL_MS);
        const { assert!(DEFAULT_PAIRING_TTL_MS <= MAX_PAIRING_TTL_MS) };
    }

    #[test]
    fn android_pairing_request_identity_and_serde_are_bounded() {
        let offer = offer();
        let request = request(&offer, "device-a", NOW + 1_000);

        let json = serde_json::to_string(&request).expect("request serialise");
        let restored: PairingRequest = serde_json::from_str(&json).expect("request parse");
        assert_eq!(restored, request);
        assert!(public_preview(&restored).contains("Pixel 9"));

        let mut empty_id = request.clone();
        empty_id.device_id.clear();
        assert_eq!(
            error_code(pair(&mut offer.clone(), &empty_id, &AcceptGate, NOW + 1_000)),
            ErrorCode::InvalidInput
        );

        let mut long_name = request.clone();
        long_name.device_name = "x".repeat(MAX_DEVICE_NAME_CHARS + 1);
        assert_eq!(
            error_code(pair(&mut offer.clone(), &long_name, &AcceptGate, NOW + 1_000)),
            ErrorCode::InvalidInput
        );

        let mut empty_name = request.clone();
        empty_name.device_name = "   ".into();
        assert_eq!(
            error_code(pair(&mut offer.clone(), &empty_name, &AcceptGate, NOW + 1_000)),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn android_pairing_short_codes_are_typable_and_forgiving() {
        let offer = offer();
        assert_eq!(
            normalize_short_code(&offer.short_code.to_lowercase()),
            normalize_short_code(&offer.short_code)
        );
        assert_eq!(
            normalize_short_code(&offer.short_code.replace('-', " ")),
            normalize_short_code(&offer.short_code)
        );

        // Crockford aliases: I/L read as 1 and O as 0.
        assert_eq!(normalize_short_code("ILO"), "110");
        assert_eq!(normalize_short_code("abcd-2345"), "ABCD2345");

        // A typed code with extra separators still pairs.
        let mut typed_offer = self::offer();
        let mut typed = request(&typed_offer, "device-a", NOW + 1_000);
        typed.code = typed_offer.short_code.chars().collect::<Vec<_>>()
            .chunks(2)
            .map(|chunk| chunk.iter().collect::<String>())
            .collect::<Vec<_>>()
            .join(" - ");
        pair(&mut typed_offer, &typed, &AcceptGate, NOW + 1_000)
            .expect("spacing in a typed code does not matter");
    }
}
