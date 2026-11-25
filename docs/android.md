# Android pairing

`zero-daemon-app::android_pairing` is the host-side pairing policy for the
Android remote control (AND-01, AND-02, T-AND-01). The Android app is a remote
control only: it pairs with one host and then drives that host's sessions.

Files: `crates/zero-daemon-app/src/android_pairing.rs`, re-exported from
`crates/zero-daemon-app/src/lib.rs`.

## Model

```rust
pub struct PairingOffer {
    pub id: String,
    pub secret: String,          // redacted by Debug
    pub qr_payload: String,
    pub short_code: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
    pub single_use: bool,
    // consumed and bound_device_id are private pairing state
}

pub struct PairingRequest {
    pub offer_id: String,
    pub secret: String,          // redacted by Debug
    pub device_id: String,
    pub device_name: String,
    pub code: String,            // redacted by Debug
    pub now_ms: u64,
}

pub struct PairedDevice {
    pub device_id: String,
    pub name: String,
    pub paired_at: u64,
    pub token: String,           // session token, redacted by Debug
}
```

`start_pairing(ttl_ms, now_ms)` is the host's one action. It reads 32 bytes from
the OS entropy source through `zero_secrets::signin::random_bytes`, renders the
secret as 64 lowercase hex characters, and derives the id, QR payload, and short
code deterministically from it. There is no account, no service, no cloud id,
and no endpoint: `PairingOffer::public_view()` exposes only `id`, `short_code`,
`issued_ms`, `expires_ms`, and `single_use`.

The lifetime is bounded: the default is `DEFAULT_PAIRING_TTL_MS` (five minutes)
and the ceiling is `MAX_PAIRING_TTL_MS` (ten minutes). A zero TTL is
`zero.fnd.invalid_input`; a TTL above the ceiling is `zero.fnd.limit_exceeded`.
Expiry is inclusive at `expires_ms`.

## QR and the one-time code

- The QR payload is `zero-android-pair:v1:<id>:<secret>`. It is the credential.
- The printed short code is four groups of four Crockford base32 characters
  (`K7M2-9QX4-...`), derived from the secret. It is a human reference and a fast
  mismatch check, **not** a credential. `PairingOffer::typed_code()` renders the
  secret as eight groups of eight hex characters for a phone without a camera;
  that grouped value is the "one-time code" a user types into the secret field.
  Type separators and case do not matter (`normalize_secret`).
- `PairingOffer::validate()` recomputes the id, QR payload, and short code from
  the secret. A restored or edited offer that does not match is
  `zero.fnd.invalid_input` with guidance to mint a fresh offer.

## The stolen-code rule

`pair` / `pair_with_config` refuse a request unless all of these hold:

1. The offer is internally consistent (`validate`).
2. The offer is single-use and has not been consumed by an earlier pairing.
3. If the offer is bound to a device id, the request carries the same id.
4. The host clock is inside the offer window, and the request's `now_ms` was
   built inside it too.
5. `offer_id` names this offer.
6. The full secret matches (constant-time comparison; separators and case are
   normalised).
7. The short code matches (Crockford-normalised, constant-time comparison).

The first success consumes the offer and binds it to `request.device_id`, so a
replayed request, a byte-for-byte copied request from another device, and any
second request against the same offer are `zero.pol.denied`. A wrong short code,
a wrong secret, a foreign offer id, and an expired offer are the same code with
different guidance. A missing secret or an oversized device name is malformed
input (`zero.fnd.invalid_input`).

This is why a stolen short code cannot pair: the code alone is not enough; the
secret is also required, and once the legitimate phone pairs, the offer is dead
and bound to that phone.

Honest limitation: the full QR payload (or the full grouped one-time code) is a
bearer credential for its short window. An attacker who obtains the whole
payload **before** the legitimate phone pairs can consume the offer first; the
real phone's attempt then fails. Single use, the short TTL, the device binding,
and the biometric prompt bound the damage, but they cannot distinguish two
holders of the same full credential. The UI must treat the QR as a secret, keep
it off the lock screen, and mint a fresh offer after any suspected exposure.

## Biometric gate

```rust
pub trait BiometricGate {
    fn unlock(&self, reason: &str) -> Result<()>;
}

pub fn require_biometric(gate: &dyn BiometricGate, reason: &str) -> Result<()>;
```

Pairing requires a gate and calls it with `BIOMETRIC_PAIRING_REASON`. The Android
host implements the trait over `BiometricPrompt`; a failure or denial is returned
unchanged, so pairing aborts. A denied attempt does **not** consume the offer:
the user can retry and confirm.

`PairingConfig::allow_without_biometric` is the only way to skip the prompt. It
is a host-only value, default `false`, and it is not a field of the offer or the
request, so a phone cannot ask to skip biometrics. `pair` (the normal entry
point) always takes a gate; `pair_with_config(..., None, ...)` is refused unless
the host set the flag explicitly.

## No public endpoint

`PAIRING_TRANSPORT` is "mesh or loopback only; the host never opens a public
pairing listener". The module opens no socket, names no URL, and carries no
host/port field: the offer and request are plain values carried over the
authenticated mesh (or loopback when both processes are on one machine). A
source-scanning test fails the build if `std::net`, `TcpListener`, `TcpStream`,
`UdpSocket`, an `http://` literal, or `0.0.0.0` appears in the module.

The phone dials the host; the host does not accept an inbound pairing request
from the public internet.

## Lock screen

`public_preview(request)` returns one line with the device name and a status
only: `pairing request · Pixel 9 · pending`. It omits the offer id, device id,
secret, and short code; the name is flattened to one line, occurrences of the
secret and code are replaced with `<redacted>`, and the result is bounded to 40
characters. `paired_preview(device)` does the same for a paired device and never
prints the session token or device id.

## Session token

`PairedDevice::token` is 32 OS-entropy bytes as hex, minted once at pairing. It
is the phone's session credential for later traffic; the **pairing** is single
use, not the session. `Debug` prints `<redacted>` for the offer
secret/QR payload/short code and for the session token. `PairingOffer` and
`PairedDevice` are not serialisable, and `PairingOfferView` and the lock-screen
previews carry no secret, code, or token. `PairingRequest` is the wire credential
and does carry the secret and code; it must travel over the authenticated
transport and must not be logged.

## Session control

`zero-daemon-app::android_session` is the phone-side model of session control
(AND-02, AND-03, T-AND-02): list sessions, show a live transcript, send prompts,
steer, queue, cancel, and view diffs. Pairing gives the phone a session token; a
screen then drives one host through `AndroidSessionController<C>` and never
through the transport directly.

Files: `crates/zero-daemon-app/src/android_session.rs`, re-exported from
`crates/zero-daemon-app/src/lib.rs`.

### The seam

```rust
pub trait MeshSessionClient {
    fn list(&self) -> Result<Vec<SessionSummary>>;
    fn transcript(&self, id: &str, cursor: Option<&str>) -> Result<TranscriptPage>;
    fn prompt(&self, id: &str, text: &str) -> Result<PromptAck>;
    fn steer(&self, id: &str, text: &str) -> Result<SteerAck>;
    fn queue(&self, id: &str) -> Result<Vec<QueuedItemView>>;
    fn cancel(&self, id: &str) -> Result<()>;
    fn diff(&self, id: &str) -> Result<Vec<FileDiff>>;
}
```

`SESSION_TRANSPORT` is "mesh or loopback only; this module holds a transport
seam and opens no socket". Each method is one round trip: no retry loop, no
listener, and no credential field. The paired session token authorises the mesh
connection, not these values, so no view, `Debug` impl, or serialised model here
can print it. A source-scanning test fails the build if `std::net`, a TCP or UDP
type, an `http://` literal, or `0.0.0.0` appears in the module.

### Views and bounds

| Value | Fields | Bound |
|---|---|---|
| `SessionSummary` | `id`, `name`, `state`, `updated_ms`, `unread` | `MAX_SESSIONS` 200 rows |
| `TranscriptEntry` | `cursor`, `id`, `role`, `text`, `at_ms` | text `MAX_TRANSCRIPT_ENTRY_CHARS` 4000 |
| `TranscriptPage` | `entries`, `next_cursor` | `MAX_TRANSCRIPT_ENTRIES` 200 entries |
| `QueuedItemView` | `id`, `text`, `state` | `MAX_QUEUE_ITEMS` 100, text 2000 |
| `FileDiff` | `path`, `additions`, `deletions`, `patch` | `MAX_DIFF_FILES` 200, path 512, patch 16 KiB |

Ids and cursors are non-empty, at most `MAX_ID_CHARS` (128) characters, and free
of control characters. The rule applies in both directions: the phone's id is
validated before a request, and an id or cursor that arrives *from* the mesh is
validated before it is rendered or echoed into the next request
(`zero.fnd.invalid_input`). Prompt and steer text must not be blank and must not
carry control characters other than `\n` and `\t`.

A page larger than the caller's `limit` is trimmed, and the returned cursor is
the last kept entry's cursor, so the next call resumes at the first entry that
was not shown — trimming never loses entries. A patch that is cut ends with
`… [patch truncated]`; a cut path ends with `…` and is display-only.

### Controller actions

| Method | Mesh call | Notes |
|---|---|---|
| `list_sessions` | `list` | newest first, then id; ties never flip |
| `open(id)` | `list` | refuses an unknown id with `zero.ses.not_found` before any other call; resets the cursor to a snapshot |
| `transcript(limit)` | `transcript` | keeps the cursor across pages; `limit` is 1..=`MAX_TRANSCRIPT_ENTRIES` |
| `send_prompt(text)` | `prompt` | default `DeliveryMode::Queue` |
| `send_prompt_with(text, mode)` | `prompt` or `steer` | explicit delivery |
| `steer(text)` | `steer` | `DeliveryMode::Steer` |
| `queue()` | `queue` | the host's queue, in queue order |
| `diff()` | `diff` | ordered by path, bounded |
| `cancel()` | `cancel` | idempotent |

`open` performs one extra `list` so an unknown id fails before a transcript or
prompt request is sent. `cancel` is idempotent: a repeat cancel, or a cancel of a
session whose turn already ended (`zero.ses.closed`), is a success because "not
running" is the state the caller asked for. Any other cancel failure surfaces.

### Delivery modes

`DeliveryMode` is explicit, never inferred from the phone's clock:

- `Steer` — applied at the running turn's next safe boundary; a tool call
  already executing is never rewritten (MON-02, MON-03).
- `FollowUp` — the next user message once the turn ends.
- `Queue` — held in the durable queue until the user sends it (MON-01).

`send_prompt` defaults to `Queue` so a tap never interrupts a turn; `steer` and
`send_prompt_with` are the overrides. The returned `DeliveryAck` says which mode
was used and whether the host reported the text as queued.

### Paging and errors

The controller owns one cursor. `transcript` starts from a snapshot after `open`
(`cursor = None`), advances to `next_cursor` on each page, and stops at `None`.

| Condition | Code | Behaviour |
|---|---|---|
| Mesh unreachable | `zero.fnd.offline` | nothing was sent; reconnect and retry |
| Host session service off | `zero.fnd.unavailable` | retry when it is enabled |
| No answer in time | `zero.fnd.timeout` | retry the same request |
| Stale cursor | `zero.ses.cursor_expired` | cursor cleared; the next call refreshes from a snapshot |
| Unknown session | `zero.ses.not_found` | list sessions and open one that exists |
| Malformed peer value | `zero.fnd.invalid_input` | refuse the response and retry |

The transport codes keep their stable values and gain retry guidance in the
message. A failed action leaves the session open and the cursor intact (except
the stale-cursor case), so the phone can retry the same request.

### Test evidence

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-daemon-app android_session -j 1
```

Result: 12 passed, 0 failed (`android_session::tests::*`). The scripted client
records every call, so the tests assert the order as well as the outcome:

- `android_session_a_full_flow_drives_every_action_in_order` — the Done
  criterion: list → open → transcript → prompt → steer → queue → diff → cancel,
  with the exact call sequence (and cursor `None` on the first page) asserted.
- `android_session_pages_keep_the_cursor_and_refresh_after_it_expires` — pages
  advance the cursor, the end is `None`, a stale cursor is
  `zero.ses.cursor_expired`, clears itself, and the retry sends `None`.
- `android_session_trims_an_oversized_page_without_losing_entries` — a page over
  the limit is trimmed and the cursor points at the first dropped entry; a zero
  and an over-cap limit are refused.
- `android_session_queue_and_steer_take_different_roads` — queue and follow-up
  go through `prompt`, steer goes through `steer`, once each.
- `android_session_refuses_oversize_or_malformed_text_before_the_mesh` — over-cap
  prompt and steer are `zero.fnd.limit_exceeded`, blank or control-character text
  is `zero.fnd.invalid_input`, and nothing reaches the mesh; newlines and tabs
  are allowed.
- `android_session_an_unknown_session_is_not_found_before_any_action` — an
  unknown id is `zero.ses.not_found` at `open`; every action without an open
  session is refused locally; malformed ids are refused before the list call.
- `android_session_transport_failures_keep_the_code_and_add_retry_guidance` —
  offline, unavailable, and timeout keep their codes and say to retry; the
  session stays open.
- `android_session_cancel_is_idempotent_and_never_a_conflict` — a repeat cancel
  and a closed session both succeed; another failure still surfaces.
- `android_session_diffs_are_bounded_and_ordered_by_path` — the patch and path
  are cut with markers, the file count is capped, and a reversed input list
  still renders in path order.
- `android_session_lists_are_ordered_deterministically` — newest first then id,
  the same rows in any order produce the same list, and names/states are
  flattened.
- `android_session_views_and_debug_carry_no_secret` — the scripted client holds
  a bearer token; no view JSON, no `Debug` output, and no field set exposes it,
  and each view's key set is closed.
- `android_session_stays_off_the_network_and_names_its_transport` — the
  transport string and the source scan prove the seam holds no listener.

Clippy:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-daemon-app --all-targets -j 1 -- -D warnings
```

Result: clean.

### Honest limits of this slice

- `prompt` carries no delivery-mode field on the seam, so `FollowUp` and `Queue`
  both travel as a prompt and the host's durable queue decides when each is
  applied. The phone distinguishes them in `DeliveryAck` and in its own view;
  the mesh prompt frame needs a mode field before the host can tell them apart
  on the wire (MON-02, T-AND-04).
- The mesh implementation of `MeshSessionClient` is `zero-mesh` work
  (T-MESH/T-AND-04). This module is the contract and the controller; it is
  tested against a scripted client, not a live host.
- Approvals and the secrets prompt live in `zero-policy::mobile_approval`
  (T-AND-03); this module routes neither.
- Notifications and the offline queue (AND-05, AND-06) are T-AND-04. The
  controller maps an offline failure and leaves the request retryable; it does
  not persist unsent input itself.

## Approvals and secrets

`zero-policy::mobile_approval` is the host-side model for AND-04 (approvals)
and AND-08 (the secrets prompt), with the POL-09 exact-approval and POL-15
multi-client rules applied to a phone decision. Pairing proves which device is
talking (`android_pairing`); session control drives the turn
(`android_session`); this module decides whether one phone decision authorises
one exact action, and how much of that action may be visible on the lock
screen.

Files: `crates/zero-policy/src/mobile_approval.rs`, re-exported from
`crates/zero-policy/src/lib.rs`. The consumed set is re-exported as
`MobileApprovalStore` so it does not collide with the durable
`approval::ApprovalStore` prompt ledger.

### Digest binding

```rust
pub struct MobileAction { /* action id, class, session, arguments */ }
pub struct ActionDigest(String); // blake3, 64 lowercase hex

pub struct ApprovalChallenge {
    pub id: String,
    pub digest: ActionDigest,
    pub created_ms: i64,
    pub expires_ms: i64,
    pub nonce: String,
}

pub struct MobileApproval {
    pub challenge_id: String,
    pub digest: ActionDigest,
    pub decision: MobileDecision,   // Allow | Deny
    pub approved_by: String,
    pub approved_ms: i64,
    pub expires_ms: i64,
    pub nonce: String,
    pub device_binding: String,
}
```

`ActionDigest::of` hashes one canonical string:
`zero-mobile-action-v1|id=<json>|class=<class>|session=<json>|args=<canonical
json>`. Object keys are sorted, identities are JSON-quoted (a quote or
separator inside an id cannot create a second action with the same canonical
form), and the version tag is fixed. Changing any of the action id, policy
class, session, or arguments changes the digest; reordering object keys does
not.

`challenge(action, ttl_ms, now_ms)` mints a fresh nonce from the digest, the
created/expiry times, a process-local sequence counter, and a per-process
random salt. `approve(challenge, decision, device, now_ms)` copies the digest,
nonce, and expiry into the approval and binds the device (and, by default, the
approver label). `verify(approval, action, device, now_ms)` recomputes the
digest from the **host's** action, so a phone cannot widen or redirect the
action it saw. Expiry is inclusive at `expires_ms`; a zero or negative TTL
mints a challenge that is already expired and cannot be approved. The approval
carries `expires_ms` so verification needs no challenge lookup.

`MobileAction::new` refuses blank ids, control characters, and ids over
`MAX_ID_CHARS` (128). The digest covers only id, class, session, and arguments:
a caller must put every security-relevant target (a path, URL, recipient) into
`arguments`, because a separate field would not be bound.

### Replay and consumption

`ApprovalStore` is the in-memory consumed set. `verify` checks, in order: digest
match, an `Allow` decision, the device binding, expiry, and the consumed set. A
successful verification consumes the nonce atomically, so the approval is
spent. `consume` exposes the same step for a host that records a decision
itself.

A second `verify` of the same approval, or a second `consume`, is
`zero.pol.approval_resolved` ("was already used"). The same nonce under a
different challenge id is the same code with a nonce-collision message. A
failed verification consumes nothing.

The set is bounded (`DEFAULT_CONSUMED_CAPACITY`, 4096) and evicts FIFO: the
oldest nonce is forgotten first. A zero bound is `zero.fnd.invalid_input`. The
bound keeps memory flat under a long-lived phone connection; it also means a
sufficiently old approval that has fallen out of the set can be replayed until
it expires (see the honest limits).

Errors name the shortened digest only. Raw arguments, target values, and
secret values never enter an error message, and `Debug` for `MobileAction` and
`ApprovalChallenge` prints the digest rather than the arguments.

### Lock-screen hiding and secrets

```rust
pub struct LockScreenView {
    pub title: String,
    pub digest_prefix: String,
    pub risk: Risk, // low | medium | high | critical
}

pub struct SecretReveal {
    pub tag: String,    // e.g. OPENAI_API_KEY
    pub handle: String, // opaque reference, never the value
}
```

`LockScreenView::from_action` takes the title from the action id, never from an
argument. `render_locked()` prints only `Approval request · risk <risk> ·
digest <12 hex>`; it omits the title entirely, so even a caller that has put
sensitive text in the title cannot leak it while the device is locked.
`render_unlocked()` may print the bounded title, risk, and digest, flattened to
one line and capped at `MAX_UNLOCKED_CHARS`.

`SecretReveal` has no value field and no constructor that accepts one. A secret
prompt shows the tag and an opaque handle; the host reads the value in its own
secure input and keeps it out of the approval payload. `Debug` therefore cannot
print the value either, because the model never holds it.

### FLAG_SECURE

```rust
pub struct SecureDisplay {
    pub required: bool,
    pub reason: String,
}

pub fn secure_display_for(surface: PromptSurface) -> SecureDisplay;
```

`PromptSurface::Approval` and `PromptSurface::Secret` return `required = true`
with reason text, and `SecureDisplay::window_flag()` returns
`Some("FLAG_SECURE")`. Notifications and transcript previews return
`required = false`: their text is bounded and already redacted. The model only
reports the requirement; the Android host must set the window flag before the
first frame of an approval or secret prompt, and must not rely on the model to
apply it.

### Test evidence

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-policy mobile_approval -j 1
```

Result: 15 passed, 0 failed (`mobile_approval::tests::*`):

- `mobile_approval_a_valid_approval_verifies_and_is_consumed` — the happy path
  binds the digest, nonce, and device, and leaves the nonce spent.
- `mobile_approval_a_changed_action_fails_the_digest_binding` — changing an
  argument is `zero.pol.denied`, names the digest, and spends nothing.
- `mobile_approval_a_replayed_nonce_is_refused` — the same nonce under another
  challenge is `zero.pol.approval_resolved`.
- `mobile_approval_replaying_an_old_approval_fails` — the Done criterion: a
  byte-for-byte replay of a spent approval is refused.
- `mobile_approval_consume_marks_used_and_refuses_reuse` — explicit `consume`
  is idempotent-safe: the second call returns false and `verify` then refuses.
- `mobile_approval_an_expired_approval_is_refused` — verification and approval
  both fail at the inclusive expiry boundary.
- `mobile_approval_a_wrong_device_is_refused` — a valid approval on another
  device id is `zero.pol.denied`.
- `mobile_approval_a_denied_approval_is_refused` — a `Deny` decision never
  authorises.
- `mobile_approval_the_locked_view_hides_args_and_secrets` — the locked view
  omits the title and arguments, including a title deliberately carrying a
  secret; `Debug` carries no arguments.
- `mobile_approval_flag_secure_is_required_for_approvals_and_secrets` —
  approvals and secrets return `FLAG_SECURE`; notifications and transcript
  previews do not.
- `mobile_approval_the_consumed_set_is_bounded_and_evicts_fifo` — capacity 2
  evicts the oldest nonce, the next-oldest after one more spend, and a zero
  bound is refused.
- `mobile_approval_digests_are_deterministic_and_order_independent` — key order
  does not matter; id, class, session, and args each change the digest.
- `mobile_approval_errors_name_the_digest_and_never_the_args` — digest mismatch,
  wrong device, and expiry errors contain the digest and none of the arguments.
- `mobile_approval_a_secret_value_never_enters_the_payload` — the approval,
  challenge, locked view, and reveal contain the tag and handle only.
- `mobile_approval_identities_and_ttl_are_validated` — blank, control-character,
  and oversized ids, a blank device, an expired challenge, and a non-hex
  digest prefix are typed errors.

Clippy:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-policy --all-targets -j 1 -- -D warnings
```

Result: clean.

### Honest limits of this slice

- The consumed set is per-process and in memory, not durable. A host restart
  forgets which nonces were spent; expiry and the digest binding still hold, so
  the window in which an old approval can be replayed is bounded by its TTL.
  Making the set durable is follow-up work alongside the mesh transport.
- The set is bounded and evicts FIFO. Once an approval falls out, a replay can
  pass until its expiry. This trades a small, bounded replay window for flat
  memory; a host that needs a hard guarantee must persist spends or use a
  larger bound.
- The nonce is an anti-replay token, not a proof of who approved. The trust
  boundary is the paired, authenticated device from `android_pairing`; this
  module verifies what that device decided, not that a hostile app could not
  forge a decision.
- The digest covers action id, class, session, and arguments. There is no
  separate target field; callers must include a path or URL in `arguments` or
  it is not bound.
- This slice has no Kotlin UI. Mapping `SecureDisplay` to the Android window
  flag, drawing the locked view, and running `BiometricPrompt` before a
  decision are app work; the model reports the requirements.

## Tests

Command:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-daemon-app android_pairing -j 1
```

Result: 14 passed, 0 failed (`android_pairing::tests::*`). The test names state
the rule they prove:

- `android_pairing_a_valid_code_pairs_exactly_once` — a matching request pairs;
  the second attempt is `zero.pol.denied`; the offer is consumed and bound.
- `android_pairing_a_replayed_or_copied_request_cannot_pair` — replay, a copied
  request from another device id, and a fresh request against the used offer all
  fail.
- `android_pairing_an_expired_offer_is_refused` — the expiry boundary is refused
  and a request outside the window is refused.
- `android_pairing_a_wrong_code_secret_or_offer_is_refused` — wrong code/secret/
  offer id are denied; a missing secret is `zero.fnd.invalid_input`; failed
  attempts consume nothing.
- `android_pairing_a_stolen_code_cannot_pair_another_device` — the Done
  criterion: code-only theft is denied, a QR payload pasted into the code field
  is denied, and a copied full request from another device id is denied after
  the owner pairs.
- `android_pairing_requires_biometrics_and_denial_aborts` — denial aborts without
  consuming the offer; the retry reaches the gate with the pairing reason.
- `android_pairing_without_a_gate_needs_the_host_setting` — `None` with the
  default config is denied; the explicit host flag is the only skip.
- `android_pairing_preview_hides_the_secret_code_and_token` — the preview shows
  name/status only, flattens newlines, and redacts a name that contains the
  secret; the paired preview hides the token and device id.
- `android_pairing_offer_has_no_endpoint_account_or_service_fields` — the public
  field set is closed; the transport string and source scan prove no public
  endpoint.
- `android_pairing_secrets_and_tokens_are_redacted_in_debug` — offer, request,
  and paired-device `Debug` output hide the values; tokens differ per pairing.
- `android_pairing_qr_and_short_code_are_deterministic` — derived fields
  reproduce exactly; tampered id/QR/code/window are invalid; a non-single-use
  offer is refused for pairing.
- `android_pairing_ttl_is_bounded` — zero, one, default, ceiling, and above the
  ceiling.
- `android_pairing_request_identity_and_serde_are_bounded` — request survives
  serde, and empty/oversized identities are malformed input.
- `android_pairing_short_codes_are_typable_and_forgiving` — case, spacing, and
  Crockford aliases normalise; a spaced typed code pairs.

Clippy:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-daemon-app --all-targets -j 1 -- -D warnings
```

Result: clean.

## Offline input, reconnect, and notifications (T-AND-04)

`zero-agent::mobile_offline` is the client-side policy for AND-04, AND-05, and
AND-06. It is a plain library: no Kotlin, no daemon, and no transport. The
Android app owns the foreground service or UnifiedPush distributor, the
composer, and the screens; this module owns the rules those pieces must follow.

Files: `crates/zero-agent/src/mobile_offline.rs`, re-exported from
`crates/zero-agent/src/lib.rs`.

## Offline queue

```rust
pub enum InputKind { Prompt, Steer, Cancel }

pub struct OfflineInput {
    pub id: String,          // stable, also the dedupe key
    pub session: String,
    pub text: String,        // empty only for Cancel
    pub queued_ms: u64,
    pub kind: InputKind,
}

pub struct OfflineQueue { /* path, caps, pending, delivered ledger */ }
```

The queue is a versioned JSON file (`OFFLINE_QUEUE_SCHEMA_VERSION` is 1). Every
mutation writes a temporary file, syncs it, and renames it over the queue, so a
crash leaves the old or the new queue and never a torn one. The default caps are
`DEFAULT_OFFLINE_MAX_ENTRIES` (64) and `DEFAULT_OFFLINE_MAX_BYTES` (256 KiB of
serialized pending input); one input's text is capped at
`MAX_OFFLINE_INPUT_BYTES` (16 KiB). A full queue refuses the new item with
`zero.mon.queue_full` or `zero.fnd.limit_exceeded` and keeps every queued item
(MON-05). `Cancel` is the only kind allowed to carry empty text.

Rules:

- While the host is unreachable, the app calls `enqueue` and shows the returned
  id. Nothing is sent.
- On reconnect the app calls `flush(&mut client, now_ms)`. Items are sent in
  queue order. `client.deliver` returning `Ok` is the ack; only then is the item
  removed and its id recorded in the delivered ledger.
- A failed send is reported in `FlushReport::failed`, stays queued, and stops
  the flush so a later item cannot overtake it. The next flush retries it.
- The ledger is bounded (`MAX_DELIVERED_IDS`) and persisted, so reloading the
  app does not resend an acked id. `enqueue_existing` refuses an id that was
  already delivered or is already pending.

`FlushReport` carries the `delivered` and `duplicates_skipped` id lists, the
`failed` list of `FlushFailure`, and `at_ms`; `is_clean()` is the success check.

## Cursor reconnect

```rust
pub struct ResumeToken { pub session: String, pub generation: u64, pub sequence: u64 }

pub enum ReconnectOutcome {
    Resumed { from_sequence: u64 },
    SnapshotRequired,
    Offline,
}

pub fn reconnect(client: &mut dyn MobileClient, token: &ResumeToken) -> ReconnectOutcome;
```

`sequence` is the first entry the client has not seen, matching the store's
cursor convention (`zero_store::session::Cursor`). A matching generation resumes
from that sequence, so already-delivered entries are not replayed. A different
generation means the host rewrote the log (compaction, import, reset) and the
client attaches a fresh snapshot; `zero.ses.cursor_expired` from the host is
treated the same way. An unreachable host leaves the token untouched and returns
`Offline`.

The queue and the cursor are independent on purpose: `reconnect` never reads,
flushes, or clears the queue, so a snapshot cannot lose undelivered input, and
`flush` never advances the token, so delivering input cannot make the client
skip transcript entries.

## Notifications

```rust
pub enum NotificationKind { Completed, Failed, Approval }
pub enum NotificationAction { OpenSession, Approve, None }

pub struct Notification {
    pub id: String,
    pub title: String,
    pub body: String,
    pub at_ms: u64,
    pub action: NotificationAction,
}
```

`notify(kind, session, detail, at_ms)` produces a single-line, bounded title and
body. Both inputs pass through `redact_secrets`, which removes `Bearer <token>`,
`sk-`-style provider keys (including one embedded after a separator), `token=...`
and `secret: ...` assignments, and long runs of hex/base64-shaped characters
that contain letters and digits. The title is a fixed label per kind; the body
is capped at `MAX_NOTIFICATION_BODY_CHARS` (200). `Notification::lock_screen_line`
shows only the title and an `open`/`approve` hint, never the body, so a code or
prompt on the lock screen stays hidden.

`NotificationOutbox` is a bounded ring (`DEFAULT_NOTIFICATION_CAP` 16) that
evicts the oldest notice. `drain_into` sends through a `NotificationSink`; a
sink error stops the drain and leaves the failed notice queued. The
`NotificationTransport` enum names the two supported seams, `ForegroundService`
and `UnifiedPush`; both are implemented by the Android app, and this module
contains no network code and no Google dependency.

## Tests

Command:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-agent mobile_offline -j 1
```

Result: 18 passed, 0 failed (`mobile_offline::tests::*`). The test names state
the rule they prove:

- `mobile_offline_airplane_mode_then_reconnect_delivers_queued_input_once` —
  the Done criterion: three inputs queued offline, a failed flush keeps all
  three, reconnecting delivers them in order exactly once, and a retry sends
  nothing.
- `mobile_offline_duplicate_flush_after_ack_delivers_nothing` — a second flush
  and a restored acked item are not sent again; the ledger skips the duplicate.
- `mobile_offline_a_failed_send_stays_queued_and_blocks_later_items` — the
  failed item and its successors stay queued in order; the retry delivers both.
- `mobile_offline_cancel_kind_is_delivered_without_text` — a cancel needs no
  text; an empty prompt is invalid input.
- `mobile_offline_queue_is_persisted_with_a_schema_and_reloads` — the file
  carries schema 1, reloads the same ids, text, and order, and a foreign schema
  is `zero.fnd.schema_version`.
- `mobile_offline_delivered_ledger_survives_reload` — an ack recorded before a
  restart is never retried after it.
- `mobile_offline_queue_is_bounded_by_entries_and_bytes` — entry and byte caps
  reject new items without dropping old ones; zero caps and an oversized
  session are invalid, and oversized text is a limit error.
- `mobile_offline_pending_filters_by_session_in_order` — per-session views keep
  global queue order.
- `mobile_offline_clear_drops_pending_but_keeps_the_delivered_ledger` — clear
  empties the queue without forgetting acked ids.
- `mobile_offline_reconnect_resumes_after_a_valid_cursor` — a matching
  generation resumes after the token's sequence.
- `mobile_offline_reconnect_snapshots_on_a_stale_or_refused_cursor` — a newer
  generation and `zero.ses.cursor_expired` both require a snapshot.
- `mobile_offline_reconnect_reports_offline_and_keeps_the_token` — an
  unreachable host is `Offline` and nothing is rewritten.
- `mobile_offline_snapshot_does_not_lose_undelivered_inputs` — a snapshot leaves
  both queued inputs, which then flush; the post-snapshot cursor resumes.
- `mobile_offline_flush_does_not_move_the_transcript_cursor` — a flush leaves
  the generation and sequence unchanged.
- `mobile_offline_notifications_redact_secrets` — the session, a provider key,
  an assignment, a bearer token, and a 64-hex digest never appear in the
  notification; the lock-screen line hides the body and the approval action is
  `Approve`.
- `mobile_offline_notifications_are_bounded_and_evict_the_oldest` — the outbox
  evicts the oldest and long bodies are truncated.
- `mobile_offline_notification_sink_is_a_bounded_transport_seam` — a sink
  receives the notices in order, a failing sink leaves the notice queued, and
  the two transport variants are distinct.
- `mobile_offline_module_has_no_network_code` — a source scan rejects socket,
  HTTP, and client-library tokens in the module.

Clippy:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-agent --all-targets -j 1 -- -D warnings
```

Result: clean.

## Limits of this slice (offline and notifications)

- There is no Kotlin UI here. `MainActivity`, the foreground service, the
  UnifiedPush distributor, and the notification channel are the Android app's
  work; this module is the policy they call.
- Delivery is exactly once once the ack is durably recorded. A crash between
  the host's ack and the queue write can resend that item on the next start;
  the id is the dedupe key, so the host should refuse an id it has already
  applied. The window is one item wide and only on process death or a full
  disk.
- A reset is detected by a generation change (or the host's cursor-expired
  error). A host that rewinds its log without bumping the generation is not
  detected here; the store's `generation` is the contract.
- `redact_secrets` is a safety net for common credential shapes, not a proof.
  Notification text must still avoid secrets at the source, and the lock screen
  shows only the title by design.
- The foreground service and UnifiedPush paths are seams only: no wake-lock,
  battery, or distributor behaviour is exercised by this repository slice.

## Share and resources (T-AND-05)

`zero-daemon-app::share` is the phone-side model for a share that arrives from
the Android share sheet (AND-07, MM-12). It validates the payload, builds the
session sheet, delivers one bounded attachment through a sink seam, and reports
the path the mesh used — direct, or relayed via a named node (AND-10) — without
ever touching the system VPN (AND-09). A sleeping or offline host is reported by
the delivery failure, not disguised (AND-11).

Files: `crates/zero-daemon-app/src/share.rs`, re-exported from
`crates/zero-daemon-app/src/lib.rs`.

### Intake

```rust
pub enum ShareKind { Image, Text, File, Url }

pub struct SharePayload {
    pub kind: ShareKind,
    pub mime: String,
    pub name: Option<String>,
    pub bytes: Vec<u8>,      // bounded per kind
    pub url: Option<String>, // links only
}

pub struct ShareIntent {
    pub payload: SharePayload,
    pub source_app: String,
    pub created_ms: u64,
}
```

`SharePayload::image`, `text`, `file`, and `url` build and validate; a payload
decoded from an intent is validated again with `validate()` before delivery:

| Rule | Refusal |
|---|---|
| mime is `type/subtype`; image is `image/*`, text is `text/*` or JSON/XML/YAML, a file is any valid type, a link is `text/uri-list` or `text/plain` | `zero.fnd.invalid_input` |
| bytes are non-empty and capped: image `MAX_SHARE_IMAGE_BYTES` 20 MiB, text `MAX_SHARE_TEXT_BYTES` 64 KiB, file `MAX_SHARE_FILE_BYTES` 64 MiB; a link carries no bytes | `zero.fnd.invalid_input` / `zero.fnd.limit_exceeded` |
| a link is `http`/`https`, has a host, is at most `MAX_SHARE_URL_CHARS` 2048, and carries no `user:pass@` userinfo | `zero.fnd.invalid_input` (the message never echoes the URL) |
| a name is non-blank, has no control characters, and is at most `MAX_SHARE_NAME_CHARS` 128 | `zero.fnd.invalid_input` / `zero.fnd.limit_exceeded` |
| a non-link share carries no URL | `zero.fnd.invalid_input` |
| the source app is non-blank, single-line, and at most `MAX_SHARE_SOURCE_APP_CHARS` 128 | `zero.fnd.invalid_input` / `zero.fnd.limit_exceeded` |

`ShareAttachment::from_intent` is the delivery-ready form. Its id is FNV-1a over
the kind, mime, name, bytes, and URL (`att-<16 hex>`), so the same share always
has the same id and changing any part — including one byte — changes it.

### Share sheet

`share_sheet(sessions)` returns at most `MAX_SHEET_ENTRIES` (20) rows of
`ShareSheetEntry { id, label, target }`. Rows are ordered by newest activity then
id, a duplicated session id collapses to its newest copy, a malformed session id
is skipped rather than shown, labels are flattened to one line and bounded to
`MAX_SHEET_LABEL_CHARS` (80), and an empty name becomes `untitled session`. The
same sessions in any input order produce the same sheet. Each session row
targets `ShareTarget::Session(id)`; the mesh chooses the path. `ShareTarget`
also has `Direct` and `Relay { node }` for a caller that pins a path; those two
apply to the session bound with `ShareRouter::with_session`.

### Routing and reporting

```rust
pub trait ShareSink {
    fn deliver(&self, session: &str, attachment: &ShareAttachment)
        -> Result<DeliveryReceipt>;
    fn route_for(&self, session: &str) -> Route { Route::Direct }
}

pub struct DeliveryReceipt {
    pub session: String,
    pub attachment_id: String,
    pub route: Route,       // Direct | Relay { node }
    pub received_ms: u64,
    pub bytes: u64,
}

pub fn share(intent: &ShareIntent, target: &ShareTarget, router: &ShareRouter<'_>)
    -> ShareReport;
```

`share` always returns a `ShareReport`, never a lost share. It validates the
target, resolves the planned path, builds the attachment, delivers, and checks
the receipt (the same session, the same attachment id, a well-formed relay node).
The report is:

```json
{
  "target": {"session": "s1"},
  "attachment_id": "att-1f3c9a0d5b7e2468",
  "route": {"kind": "relay", "node": "node-b"},
  "delivered_ms": 1700000000000,
  "vpn_state": "untouched",
  "received": true,
  "bytes": 204800,
  "failure": null
}
```

- `route` is the path the receipt reports; `route_label()` renders `direct` or
  `relay via node-b`. A failed delivery still names the attempted path and puts
  the stable code and message in `failure` (`received` is false).
- `received` is true only when the session acknowledged exactly this attachment.
  A receipt for another session, another attachment, or with a malformed relay
  node is refused with `zero.fnd.invalid_input` and reported as not delivered.
- `bytes` is the data-use estimate (AND-10): what moved, or the attachment size
  when nothing did. A link moves no bytes.
- `summary()` is a one-line form for a log or a toast: target, path, bytes, VPN
  state, and outcome. It contains no attachment bytes and no URL.
- When a target is refused before a path exists, the report keeps the `direct`
  default and the `failure` explains why nothing moved. Nothing is sent.

### No VPN eviction

Zero never owns or changes the system VPN. A share rides the app-level userspace
mesh, or loopback when both processes are on one machine; `SHARE_TRANSPORT` is
"mesh or loopback only; a share rides the userspace mesh and this module opens no
socket".

The guarantee is structural, not a runtime check that a caller could forget:

- `ShareTarget` has no VPN variant, field, or constructor; `Direct` and `Relay`
  are mesh paths, not a tunnel. `ShareTarget::requires_vpn_change()` is false for
  every shape.
- `VpnState` has the single variant `Untouched`, and every `ShareReport` carries
  it.
- `refuse_vpn_change()` is the typed `zero.pol.denied` refusal kept for any
  future surface that tries to route a share through a VPN change; no current
  target reaches it.
- A source-scanning test rejects network types and the platform VPN service name
  in the module, so a listener or a tunnel cannot be added by accident.

This is AND-09 and MESH-01: no platform VPN service, no eviction of a running
VPN, and no route that depends on either.

### Test evidence

```powershell
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-daemon-app share -j 1
```

Result: 20 passed, 0 failed. Ten of them are `share::tests::*`; the other ten are
pre-existing tests whose names contain "share" (`shared_ui`, `desktop_shell`).
The share tests are:

- `share_an_image_reaches_the_scripted_session_sink` — the Done criterion: a
  shared PNG reaches the scripted session sink with its bytes, mime, and name;
  the receipt is reported with `received = true`, route `direct`, the exact
  attachment id, the delivered time, the byte count, and `vpn_state = untouched`.
- `share_relay_and_direct_report_the_right_route` — direct, relay, and
  mesh-chosen targets each report the path they used; a failed relay delivery
  still names the relay; a direct/relay target without a bound session is refused
  before delivery.
- `share_never_touches_the_vpn` — `VpnState` has one variant, every target is
  VPN-neutral, every report says `untouched`, and `refuse_vpn_change()` is a
  typed policy denial.
- `share_refuses_oversize_wrong_mime_and_bad_url_payloads` — per-kind size caps,
  mime/kind mismatches, empty content, `ftp://`, userinfo links (without echoing
  the credential), bytes on a link, bad names, and bad source apps are refused;
  a tampered intent never reaches the sink.
- `share_sheet_is_deterministic_and_bounded` — newest-first then id, any input
  order gives the same sheet, duplicates collapse, malformed ids are skipped,
  labels are flattened, empty names are labelled, and the list is capped.
- `share_a_failed_delivery_reports_the_reason_and_the_route` — an offline sink is
  reported with code, message, path, and the attachment size; a receipt for
  another session or attachment and a malformed relay node are refused.
- `share_attachment_ids_are_stable_and_content_bound` — the same share gives the
  same id; bytes, name, mime, and URL each change it; the clock and source app do
  not.
- `share_text_file_and_url_reach_the_session_too` — text, PDF, and link shares
  reach the sink with the right kind, mime, bytes, and URL; a link moves zero
  bytes.
- `share_reports_and_debug_hide_payloads_and_links` — a report's JSON, a
  report/intent/attachment `Debug`, and a sheet entry carry no URL token, no URL,
  and no key; the report's key set is closed.
- `share_module_stays_off_the_network_and_never_owns_a_vpn` — a source scan finds
  no socket type, HTTP literal, or platform VPN service token in the module.

Clippy:

```powershell
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-daemon-app --all-targets -j 1 -- -D warnings
```

Result: clean.

### Limits of this slice (share)

- This module is the contract and the policy, tested against a scripted sink.
  The mesh implementation of `ShareSink` (and the Android `Intent` decoding that
  feeds `ShareIntent`) is app and `zero-mesh` work; no live host is exercised.
- A `Direct` or `Relay` target states a preference, not a hard constraint: the
  receipt is authoritative, so if the mesh used another path the report names
  the path it actually used. Nothing claims a pinned path was honoured.
- Bytes are held in memory and bounded per kind (20 MiB image, 64 MiB file); a
  larger share is refused rather than streamed. Chunked delivery for large media
  is follow-up work alongside the mesh transport.
- Only http(s) links are accepted; `mailto:`, `content:`, and `file:` shares are
  refused, so the phone must resolve those before sharing.
- Downscaling, OCR, transcription, and original retention are the multimodal
  pipeline's work (T-MM-02); this module delivers the original bounded bytes.
- No Kotlin UI here: the share handler, the sheet rendering, and the receipt
  toast are app work.

## Limits of this slice

- This repository slice has no Kotlin UI. The module is the host-side policy the
  Android client must call; `BiometricPrompt`, Compose screens, and QR image
  rendering are the Android app's work (T-AND-02 onward).
- The mesh transport itself lives in `zero-mesh` and is intentionally not a
  dependency here, so pairing stays testable offline and cannot grow a listener
  by accident.
- Session control lives in `android_session` behind the `MeshSessionClient`
  seam; approvals/secrets are host-side policy in
  `zero-policy::mobile_approval`, and the live mesh implementation and
  notifications/offline queue (T-AND-04) are follow-up work.
- The short code is not a credential by design. A future host-mediated lookup
  for typed-only pairing would still need biometrics and the same single-use
  rule; it must not make the short code sufficient on its own.
