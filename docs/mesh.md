# Mesh identity, signed membership state, and LAN discovery

`zero-mesh` owns the mesh slices. This document covers T-MESH-01 (identity,
join tokens, approval, revocation, rotation), T-MESH-02 (signed, versioned
membership state), T-MESH-03 (authenticated LAN discovery), T-MESH-04
(traversal planning: NAT model, hole punch, TCP/443 fallback), T-MESH-05
(ciphertext-only relay), T-MESH-06 (one-action offer, QR and short-code join
UX), T-MESH-07 (reliable session stream over datagrams, prototype), T-MESH-08
(delegate quorum, revocation propagation, partition refusal), and T-MESH-09
(presence and cost). The real overlay carrier, the mDNS socket, and the UDP/TCP
traversal carriers remain later tasks.

| Slice | Module | State |
|---|---|---|
| T-MESH-01 identity, approval, join tokens, rotation | `src/identity.rs` | implemented |
| T-MESH-02 signed state | `src/state.rs` | implemented |
| T-MESH-03 LAN discovery | `src/discovery.rs` | implemented |
| T-MESH-04 traversal | `src/traversal.rs` | implemented |
| T-MESH-05 relay | `src/relay.rs` | implemented |
| T-MESH-06 join UX (QR and short code) | `src/join_ux.rs` | implemented |
| T-MESH-07 session stream over datagrams | `src/transport.rs` | prototype |
| T-MESH-08 quorum, revocation, partition | `src/partition.rs` | implemented |
| T-MESH-09 presence and cost | `src/presence.rs` | implemented |

`lib.rs` re-exports the identity surface: `KeyPair` (alias `DeviceKey`),
`DeviceRecord`, `JoinToken`, `JoinPayload`, `PendingJoin`, `Membership`,
`RotationRequest`, and the free functions `issue_token`, `verify_token`,
`consume`, `join`, `approve`, `revoke`, `rotate`, `apply_rotation`,
`sign_rotation`, `parse_join_payload`, `device_id_for`, `is_member`, `can_join`,
and `verify`. It also re-exports the signed-state surface: `MembershipState`,
`StateUpdate`, `ApplyOutcome`, `canonical_bytes`, `sign_state`, `sign_update`,
`verify_state`, `apply`, and the `MAX_*`/`*_DOMAIN` constants. The discovery
surface is `PeerAnnounce`, `PeerRecord`, `PeerPresence` (the discovery
`Presence` enum, aliased at the crate root so it does not collide with the
T-MESH-09 table record), `Discovery`,
`DiscoveryPolicy`, `AcceptOutcome`, `MdnsRecord`, `canonical_announce_bytes`,
`sign_announce`, `verify_announce`, `accept`, `sweep`, `remove`, `peers`,
`encode_announce`, `decode_announce`, `new_nonce`, and the discovery `MAX_*`
constants. The presence surface is `Presence`, `PresenceState`, `LinkKind`,
`PowerState`, `PublicPresence`, `PresenceTable`, `CostPolicy`, `Decision`,
`should_sync`, `should_relay`, and `relay_candidates`. The partition surface is
`DelegateSet`, `DelegateVote`, `QuorumDecision`, `check_quorum`, `sign_vote`,
`update_hash`, `RevocationSet`, `Revoked`, `sign_revocation_set`,
`verify_revocation_set`, `propagate`, `ensure_not_revoked`, `accept_update`,
`drop_revoked`, `PartitionView`, `can_write`, and the `VOTE_DOMAIN`/
`REVOCATION_SET_DOMAIN`/`MAX_*` constants. `partition::Decision` is re-exported
as `PartitionDecision`, because the presence `Decision` already owns that name.
The relay surface is `RelayEnvelope`, `RelayPolicy`, `RelayNode`, `RelayClock`,
`Forwarded`, `Endpoint`/`Sealed`, `seal`, `seal_with_aad`, `open`,
`relay_chain`, and the relay `MAX_*`/`DEFAULT_*` constants. The join UX surface
is `JoinOffer`, `JoinTimeline`, `one_action_offer`, `join_with_payload`,
`join_with_short_code`, `approve_pending`, and `DEFAULT_OFFER_TTL_MS`/
`JOIN_TARGET_MS`. The traversal surface is `NatKind`, `Endpoint` (aliased at the
crate root as `TraversalEndpoint`, because the relay test helper owns the
`Endpoint` name), `StunProbe`, `TraversalConfig`, `Path`, `Failure`,
`TraversalPlan`, `PunchAttempt`, `PunchOutcome`, `HolePuncher`, `Connected`,
`plan`, `attempt`, and the `MAX_*`/`TCP_FALLBACK_PORT`/`RENDEZVOUS_REQUIRED`
constants. The transport surface is `DatagramIo`, `PeerId`, `StreamConfig`,
`StreamError`, `TransferStats`, `SessionStream`, `Reassembler`, `SimulatedNet`,
`move_stream`, and the transport
`MAX_*`/`DEFAULT_*`/`PROTOCOL_VERSION`/`FRAME_MAGIC`/`HASH_BYTES` constants.
Transport is an in-process prototype: no socket is opened, and the real overlay
supplies `DatagramIo`.

## Device identity (MESH-08)

A device is an Ed25519 key pair generated with `KeyPair::generate()`, which
reads 32 seed bytes from the operating system through `getrandom`. The module
never mints a key from a timestamp, a counter, or a caller-supplied string.

| Value | Definition |
|---|---|
| private key | the Ed25519 signing key; held only inside `KeyPair` |
| `public_key_b64` | standard padded base64 of the 32-byte public key |
| `device_id` | 64 hex characters: the full blake3 hash of the 32 public-key bytes |
| signature | standard padded base64 of the 64-byte Ed25519 signature |

The id is derived from the key, so a caller cannot choose an id independently
of the key it holds. `device_id_for(public_key_b64)` recomputes it from a public
key and rejects malformed base64, a wrong length, and a byte string that is not
a valid Ed25519 point.

`KeyPair` has no `Display`, no serde implementation, and no accessor for the
private scalar. Its `Debug` prints only the derived device id and
`finish_non_exhaustive`, so a log line, an error string, or a panic cannot leak
the scalar. `sign(bytes)` returns the base64 signature; `verify(pubkey, bytes,
sig)` (also available as `KeyPair::verify`) uses `ed25519-dalek`'s strict
verification and returns `zero.pol.denied` on a mismatch. No signature or key
handling is hand-rolled.

A `DeviceRecord` is the approved-device entry:

```text
device_id      hex blake3 of the public key
public_key_b64 base64 Ed25519 public key
name           optional human label (preserved across rotation)
added_ms       owner approval time, milliseconds since the Unix epoch
revoked        true once the owner revoked the device
rotated_from   the replaced device id, when produced by a rotation
```

Device ids, records, tokens, and membership state are serde-serialisable. The
key pair itself is not.

## Join tokens

`JoinToken` is signed by the owner root:

```text
id            16 hex characters (8 random bytes)
secret_b64    standard padded base64 of 16 random bytes (128 bits)
issued_ms     issue time, milliseconds since the Unix epoch
expires_ms    issued_ms + ttl
max_uses      1
used          local use counter
signature_b64 owner-root signature
```

`issue_token(owner_key, ttl_ms, now_ms)` refuses a non-positive ttl, a ttl above
`MAX_TOKEN_TTL_MS` (24 hours, so an accidental "forever" invite is refused), and
a clock overflow; it draws the id and secret from the operating system, and
signs the length-prefixed encoding of `id`, `secret_b64`, `issued_ms`,
`expires_ms`, and `max_uses` under the `zero.mesh.join-token.v1` domain
separator. `used` is **outside** the signature on purpose: consumption is local
state; T-MESH-02's signed snapshot carries membership, not a token-consumption
ledger. Editing any covered field invalidates the signature.

`verify_token(token, owner_pubkey, now_ms)` checks, in order:

1. `max_uses` is at least one and the id/secret have the right shape;
2. the Ed25519 signature against the owner public key (`zero.pol.denied`);
3. expiry, `now_ms > expires_ms` (`zero.pol.approval_expired`);
4. remaining uses, `used >= max_uses` (`zero.pol.denied`).

`consume(token, now_ms)` repeats the expiry and use checks and increments
`used`. A single-use token therefore refuses its second use even when the
signature still verifies. `Membership` additionally records every consumed
token id in `consumed_tokens`, so copying a token and presenting it to the same
membership a second time is refused as well.

### Lifecycle

| Step | Call | Result |
|---|---|---|
| owner mints | `issue_token(&owner, ttl, now)` | signed token, `used = 0` |
| owner shares | `token.payload()` or `token.short_code()` | id + secret only, no signature |
| owner records the request | `join(&mut membership, &mut token, device_pubkey, now)` | pending request, `zero.pol.denied` |
| owner decides | `approve(&mut membership, &owner, device_id, now)` | `DeviceRecord`, member |
| token retires | `used == max_uses` and the id is in `consumed_tokens` | further use refused |
| token expires | `verify_token`/`consume` past `expires_ms` | `zero.pol.approval_expired` |

The signed token stays with the owner; the device only ever sees the id and
secret. That is why the QR and short code carry no signature. `join` is the
owner-side call that records the request, and the owner's clock is
`now_ms`.

## Short code and QR payload

Both strings are derived from the token id and secret and need no network.
`parse_join_payload(text)` accepts either form and returns `JoinPayload { id,
secret_b64 }`.

- **QR payload** — `zero-join:v1:<id>:<secret_b64>`. The base64 alphabet has no
  colon, so the split is unambiguous.
- **Short code** — Crockford base32 of the 8 id bytes followed by the 16 secret
  bytes, grouped in fours: for example `ABCD-EFGH-...`. The 24-byte payload is
  39 characters plus separators. Parsing ignores spaces and hyphens, accepts
  lower case, and folds the Crockford aliases `O` to `0` and `I`/`L` to `1`.
  Non-zero trailing padding bits are refused so one secret has one code.

Both forms are secrets: anyone holding either can present the token. Treat them
like a password, and prefer the QR because it is less likely to be mistyped or
shoulder-surfed. The code is self-contained, so a shorter human code needs a
lookup service that does not exist yet; T-MESH-06 uses this 39-character code
as-is (see [Join UX](#join-ux-t-mesh-06)).

## Join UX (T-MESH-06)

MESH-07 asks for one action on the host and a join by QR or short code on the
guest. `src/join_ux.rs` is that glue: it mints the invite, renders both
encodings, records the pending request, and models the MESH-07 timing target.
It adds no new authority: the token, consumption, approval, and membership
rules are T-MESH-01's, called unchanged.

### One action

`one_action_offer(owner_key, ttl_ms, now_ms)` is the host's single call. It
issues one signed, single-use `JoinToken` with `issue_token` and returns:

```text
JoinOffer {
    token         the signed token; stays on the host
    qr_payload    zero-join:v1:<id>:<secret_b64>
    short_code    the grouped Crockford base32 code
    created_ms    when the host acted
    expires_ms    the token expiry, created_ms + ttl_ms
}
```

`ttl_ms` follows the token rules: positive and at most `MAX_TOKEN_TTL_MS`
(24 hours); `DEFAULT_OFFER_TTL_MS` is five minutes. A non-positive ttl is
`zero.fnd.invalid_input` and a ttl above the ceiling is `zero.fnd.limit_exceeded`.
The call reads no clock, opens no socket, and calls no service: the caller
supplies `now_ms`. `JOIN_TARGET_MS` is `60_000`, MESH-07's "under a minute".

The guest never sees the signed token, only the id and secret through the two
encodings. `JoinOffer`'s `Debug` prints the token id and the window and
`finish_non_exhaustive`; it never prints the payload, the code, or
`token.secret_b64`. `JoinOffer::validate(now_ms)` re-derives both encodings
from the token, checks `created_ms`/`expires_ms` against it, and refuses an
expired offer, so a serialised offer that was edited after minting is refused
rather than trusted.

### Joining by QR or code

The host is the only party holding the signed offer, so it passes the offer it
minted; the guest contributes only the text it scanned or typed and its public
key.

```text
join_with_payload(owner_key, membership, offer, payload, device_pubkey, now_ms)
join_with_short_code(owner_key, membership, offer, code, device_pubkey, now_ms)
```

Both run the same checks, in this order:

1. `owner_key` is the membership's owner root (`zero.pol.denied` otherwise);
2. the guest key derives to a device id, and the device is not already a
   member (`zero.pol.denied` with "already a member");
3. an existing pending request for that device is returned unchanged, so a
   retry after a dropped reply is idempotent and consumes nothing;
4. `offer.validate(now_ms)` — the encodings and timestamps match the token and
   the offer has not expired;
5. `verify_token` — the owner-root signature, expiry, and remaining uses;
6. the payload parses and its id and secret are this offer's, not another
   invite's;
7. `Membership::join` consumes the token and records the `PendingJoin`.

`join_with_short_code` additionally refuses a QR payload pasted into the code
field, so the UI can keep the two entry points distinct.

Success returns the `PendingJoin`, and **the device is still not a member**:
`membership.devices` is untouched, `is_member` is false, and only
`membership.pending` and `membership.consumed_tokens` changed. That is
MESH-08's explicit approval rule reached through the UX layer.

Failures are typed `ZeroError`s whose message carries the next step:

| Situation | Code | Message guidance |
|---|---|---|
| text is not a join code | `zero.fnd.invalid_input` | scan the QR again or retype the code |
| code is from another invite | `zero.pol.denied` | the code belongs to a different invite |
| offer or token expired | `zero.pol.approval_expired` | create a fresh invite on the host |
| invite already used | `zero.pol.denied` | create a fresh invite on the host |
| offer edited after minting | `zero.fnd.invalid_input` | regenerate the offer |
| token secret or signature edited | `zero.pol.denied` | scan a QR from the host |
| caller is not the owner root | `zero.pol.denied` | only the owner root records the join |
| device already a member | `zero.pol.denied` | no join is needed |
| approval for an unknown id | `zero.fnd.not_found` | have the device join first |

`ZeroError::remediation()` adds the stable code-level line (for
`zero.pol.approval_expired`, "Request a fresh approval.") alongside the
message.

### Approval

`approve_pending(owner_key, membership, pending_id, now_ms)` is the host's
decision. It requires a pending request, then calls `Membership::approve`,
which checks the owner root, signs the approval, writes the `DeviceRecord`, and
removes the pending entry. Approving an already-approved member is idempotent.
A revoked device that joins again gets a fresh pending request and is re-admitted
by the same approval, matching T-MESH-01. An id with no pending request and no
live record is `zero.fnd.not_found` with guidance.

### Timing and the under-a-minute rule

`JoinTimeline { offer_ms, scanned_ms, approved_ms, joined_ms }` records the four
moments; the last three are `Option`s so an in-flight join can be reported
without inventing a finish time. `mark_scanned`, `mark_approved`, and
`mark_joined` are monotonic: a milestone before the offer or before the previous
milestone is `zero.fnd.invalid_input`, so a timeline cannot show a guest joining
before it approved.

`join_duration_ms()` is `joined_ms - offer_ms` when the join finished.
`within_target(target_ms)` is true only for a finished join whose duration is at
most the target; an unfinished timeline has no result and is not "within
target", and a non-positive target is unsatisfiable. `JOIN_TARGET_MS` (60
seconds) is the MESH-07 target; `an_over_target_join_is_reported_not_hidden`
shows a 61-second join failing the rule rather than being rounded down.

### Offline rule

Nothing in `src/join_ux.rs` talks to an account, a service, or a network: the
offer is a value, the QR payload and short code are strings, and the join is a
local state transition on the host's `Membership`. The test
`the_offer_and_timeline_have_no_account_or_service_fields` checks the closed
serde field sets and scans the module source for socket and HTTP names, so a
future edit that adds a transport to this file fails the suite. The caller,
not this module, moves the strings between devices; the authenticated LAN/mDNS
transport (T-MESH-03, with T-MESH-04 for traversal) is the intended carrier and
is a later wiring step. MESH-12's LAN-only path therefore needs no account.

### Tests

`join_ux::tests` has 14 tests, listed under [Test evidence](#test-evidence). The
core one is `a_two_device_join_completes_under_a_minute`: two independently
generated keys, one offer, a QR join, an owner approval, and a 25.5-second
timeline that passes `within_target(JOIN_TARGET_MS)`.

### Limitations

- **No QR image or camera.** The module produces and parses the payload string;
  rendering a QR bitmap and decoding a camera frame belong to the platform UI.
- **No transport carries the offer.** The host and guest exchange the payload by
  whatever channel they have. The mDNS transport that will carry it is
  T-MESH-03/T-MESH-04; until it is wired, the strings move by hand or by the
  caller's own channel.
- **Timing is modelled, not measured.** `JoinTimeline` stores caller-supplied
  clock values; the suite proves the under-a-minute rule, not the wall-clock
  latency of a real pair of devices.
- **The offer is host state.** If the host loses the `JoinOffer`, the guest's
  payload cannot be verified against the token; the correct recovery is a fresh
  one-action offer, not a re-issued code.
- **Consumption is local.** As in T-MESH-01, `consumed_tokens` lives in one
  `Membership`; a copied invite is single-use there but not across independent
  membership instances.
- **Strict clock.** Expiry is `now_ms > expires_ms` with no skew allowance; the
  caller supplies the clock.
- **The code is still long.** 39 base32 characters are typeable but not short;
  a genuinely short code needs a lookup or rendezvous service, which is
  deliberately absent (MESH-12).

## Approval and membership

`Membership` holds the owner root public key, approved devices (including
revoked records), pending joins, and consumed token ids. `Membership::new`
validates the owner key. The owner root is fixed at construction; there is no
API that changes it.

**An unapproved device cannot join.** `join` verifies and consumes a valid
token, records the request in `pending`, and still returns `zero.pol.denied`
with the device id. `is_member` stays false, and nothing is written to
`devices`. The request exists only so the owner has a device id and public key
to approve.

`approve` requires the owner root key:

1. the caller's public key must equal `owner_public_key_b64`, otherwise
   `zero.pol.denied` — a non-owner approval is refused;
2. an already approved, non-revoked device is returned idempotently;
3. otherwise the pending request supplies the public key (or, for a revoked
   record, the record's own key is re-used);
4. the device id must equal the blake3 hash of that public key;
5. the owner signs `device_id`, `public_key_b64`, and `approved_ms` under the
   `zero.mesh.approval.v1` domain, and the module verifies that signature
   against the membership's owner key;
6. the record is inserted with `revoked = false`, and the pending entry is
   removed.

`revoke` is owner-only in the same way. It keeps the record, sets `revoked =
true`, and signs `device_id` plus `revoked_ms` under
`zero.mesh.revocation.v1`. Keeping the record is what stops the same key from
silently re-entering: `join` refuses a revoked device with `zero.pol.denied`,
and `can_join` returns false. Revoking twice is idempotent.

A revoked device is not permanently bricked: a **fresh owner approval**
re-admits it, which matches MESH-08's "cannot rejoin without a fresh approval".
The new approval time replaces `added_ms`; the record keeps its `rotated_from`.

## Rotation

`rotate(&mut membership, old_key, new_key, now)` builds a `RotationRequest` with
`sign_rotation`, then applies it with `apply_rotation`:

```text
from_device_id     the old device id
new_public_key_b64 the replacement public key
new_device_id      blake3 of the replacement public key
rotated_ms         when the old key signed
signature_b64      the old device key's signature
```

`apply_rotation` checks that the old record exists, is not revoked, and is not
the same key; recomputes the new id from the new public key and refuses a
mismatch; refuses a new id that is already a member (or was revoked); then
verifies the old device key's signature over the length-prefixed
`zero.mesh.rotation.v1` payload. After that it marks the old record revoked,
keeps it, and inserts the replacement with `rotated_from =
Some(old_device_id)`, the old name, and `revoked = false`.

Rotation is bound to the old key, not to possession of the membership file:
editing a request after signing is `zero.pol.denied`, and an unrelated key
cannot stand in for the old device key (`zero.pol.denied`, or `not_found` when
its id was never a member). A revoked device cannot rotate, so a stolen device
cannot rotate back into the mesh.

## Signed membership state (T-MESH-02)

`MembershipState` is a complete snapshot of the mesh, not a log:

```text
version        monotonic snapshot version, 1 for the first signed state
epoch          owner-root epoch, signed but reserved (always 0 in this slice)
devices        BTreeMap<device id, DeviceRecord>
revoked        BTreeSet<device id>
names          BTreeMap<device id, name>  (in-mesh names, MESH-11)
updated_ms     owner signing time, milliseconds since the Unix epoch
signed_by      the owner root device id
signature_b64  owner-root Ed25519 signature over canonical_bytes(state)
```

`revoked` can contain an id whose device record was already evicted, so an
eviction need not keep the record to stay authoritative. `devices` and `names`
are `BTreeMap`s and `revoked` is a `BTreeSet`, so insertion order never affects
the encoding.

### Signing authority (MESH-02, MESH-09)

There is no privileged node and no per-device write authority. A snapshot is
accepted only when its signature verifies against the **owner root public key**,
and `signed_by` must equal the device id derived from that key. This is the
whole stolen-device guarantee: a stolen device can sign with its own key, and
`sign_state` will even produce a structurally valid snapshot, but no peer's
`verify_state` or `apply` accepts it because the key is not the owner root.
Consequently a device cannot add, revoke, evict, rename, or re-sign membership.

`verify_state(state, owner_pubkey)` checks, in order:

1. `signed_by` is the device id of `owner_pubkey` (`zero.pol.denied`);
2. the snapshot validates and canonicalises (see below);
3. `revoked` does not contain the owner's own id (`zero.pol.denied`);
4. the Ed25519 signature verifies against the owner public key
   (`zero.pol.denied`).

A tampered field, a wrong signature, a device-signed snapshot, and a snapshot
from another owner's mesh all fail. A snapshot that revokes the owner root
cannot be signed in the first place, because validation refuses it before
`sign_state` produces a signature.

Within `src/state.rs` there is exactly one root key. The delegate threshold
(an owner root key **or** a threshold of delegates) is T-MESH-08's
`src/partition.rs`; it reads the same canonical update and is documented
[below](#quorum-revocation-and-partitions-t-mesh-08).

### Canonical encoding

`canonical_bytes(state)` is deterministic and length-prefixed; all integers are
big-endian:

```text
"zero.mesh.membership.v1\0"         domain separator
version                            u64
epoch                              u64
device count                       u32
repeated devices, ascending id:
  device id                        u32 length + UTF-8 bytes
  public_key_b64                   u32 length + UTF-8 bytes
  name present                     u8 (0 or 1)
    name                           u32 length + UTF-8 bytes when present
  added_ms                         i64
  revoked                          u8 (0 or 1)
  rotated_from present             u8 (0 or 1)
    rotated_from                   u32 length + UTF-8 bytes when present
revoked count                      u32
repeated revoked ids, ascending:   u32 length + UTF-8 bytes
name count                         u32
repeated names, ascending id:
  device id                        u32 length + UTF-8 bytes
  name                             u32 length + UTF-8 bytes
updated_ms                         i64
signed_by                          u32 length + UTF-8 bytes
```

The signature is excluded because it is produced over these bytes; editing any
covered field invalidates it. The flags and length prefixes mean no two
different snapshots can share an encoding by shifting bytes across a field
boundary. `StateUpdate` frames `base_version` together with the canonical
snapshot under the `zero.mesh.state-update.v1` domain, and signs that envelope
separately, so an update cannot be replayed with a different base version.

Validation happens inside canonicalisation and refuses:

- a version of zero (only the unsigned genesis placeholder has version 0);
- a device id that is not 64 hex characters, a record whose `device_id` differs
  from its map key, or whose public key hashes to a different id;
- a revoked flag that disagrees with the `revoked` set;
- a name entry for an unknown or revoked device, an empty or whitespace-padded
  name, a control character, or two devices claiming the same name (compared
  case-insensitively);
- the owner id in `revoked`;
- more than `MAX_DEVICES` (4096) devices, `MAX_REVOKED` (8192) revoked ids, or
  `MAX_NAMES` (4096) names, a name longer than `MAX_NAME_BYTES` (64), or a
  canonical snapshot longer than `MAX_STATE_BYTES` (1 MiB).

Invalid shapes are `zero.fnd.invalid_input`; count and length overruns are
`zero.fnd.limit_exceeded`.

### Versioning and replication

`StateUpdate { base_version, state, signature }` carries one snapshot. The
signer sets `state.version = base_version + 1`, signs the snapshot, then signs
the envelope. `apply(current, update, owner_pubkey)` authenticates both
signatures and then applies these rules:

| Situation | Outcome |
|---|---|
| both signatures valid, version not yet handled | `Applied(state)` |
| local state is the unsigned version-0 placeholder, update is owner-signed version 1 for the same owner | `Applied(state)` |
| same version, identical canonical content | `AlreadyApplied` |
| same version, different canonical content | `Conflict { reason }` — never a silent pick |
| lower version, even when authentically owner-signed | `Rejected { reason }` (rollback) |
| higher version, valid owner signature | `Applied(state)` |
| successor evicts the owner root's own device record | `Rejected { reason }` |
| any signature, structure, or `base_version` failure | `Rejected { reason }` |

A node with no state starts from `MembershipState::empty(owner_pubkey)`, which
records the owner id but cannot be signed or canonicalised. The first replicated
snapshot must be version 1 for that same owner; a placeholder from a different
mesh is refused. `MembershipState::new(&owner, now)` builds that first signed
snapshot locally.

Snapshots are whole states, so a peer that missed intermediate versions can
still adopt a fresher owner-signed state: the version is the owner's total
order. This is why the table says "higher version wins" rather than requiring
every intermediate snapshot. Copies of a state are recognised by their
canonical bytes, which is what makes a re-delivered update `AlreadyApplied` and
a same-version disagreement a visible `Conflict`.

Revocation and eviction need no separate permission path: only the owner can
sign a snapshot at all, so a revoked or evicted device is always owner-signed
away. A stolen device cannot evict others, and the owner's own root authority
cannot be removed because `signed_by` is pinned to the verifying owner key, the
owner id cannot appear in `revoked`, and `apply` refuses a successor that
evicts the owner's own device record once the current snapshot carries it. Root
rotation is deferred, so that record is permanent in this slice.

Names (MESH-11) are part of the signed snapshot. They resolve only among mesh
members and are not DNS names; the snapshot rejects a name for an unknown or
revoked device and rejects two devices sharing a name.

### Replication limits

`apply` is a pure function. This slice has no wire protocol, no gossip, no retry
loop, and no socket; a caller moves `StateUpdate` values between peers itself.
Two peers that both mint different snapshots at the same version produce a
`Conflict`; resolving it requires the owner to sign a later version. There is
no automatic merge of two divergent contents, and no append-only audit chain
yet (MESH-15 is represented only by `version`, `updated_ms`, and `signed_by`).

## Quorum, revocation, and partitions (T-MESH-08)

`src/partition.rs` adds the replicated-write rules on top of the signed
snapshot. It is still a pure state machine: no socket, no gossip loop, no retry
timer (MESH-02, MESH-08, MESH-09, LCK-10).

### Delegate quorum

`DelegateSet` is the quorum configuration:

```text
threshold              votes required to accept one update, 1..=delegates.len()
delegates              BTreeMap<device id, base64 Ed25519 public key>
owner_public_key_b64   optional owner root key
```

Validation refuses an empty set, more than `MAX_DELEGATES` (128), a zero
threshold, a threshold above the delegate count, a malformed owner key, and a
delegate id that is not the blake3 hash of its recorded key. Because the id is
derived, ids and keys are unique together: a caller cannot name an id for a key
it does not hold.

`DelegateVote` carries `delegate_id`, `state_version`, `state_hash`, and
`signature_b64`. The signature covers the length-prefixed
`zero.mesh.delegate-vote.v1` payload of those first three fields. `state_hash`
is the hex blake3 of `StateUpdate::canonical_bytes`, so a vote binds the exact
devices, names, revoked ids, and `base_version`. Changing anything in the
update — or offering the same vote to a different update — breaks the binding.

`check_quorum(update, delegates, votes, now_ms)` returns
`QuorumDecision::Accepted` or `QuorumDecision::Refused { reason }`. A malformed
delegate set or a snapshot that cannot canonicalise is a typed `Err`; an
authentic-looking but unauthorised update is `Refused`, because that is a
decision rather than a parse failure. The checks run in this order:

| Check | Outcome |
|---|---|
| delegate set and snapshot structure | `Err` (`zero.fnd.invalid_input`) |
| `state.version == base_version + 1` | `Refused` on a gap |
| `state.updated_ms <= now_ms` | `Refused` when signed in the future |
| owner root signed the envelope **and** `signed_by` is the root id | `Accepted`, alone, whatever the threshold |
| `votes.len() >= threshold` | `Refused` as a minority partition |
| every voter is a known delegate | `Refused` for a non-delegate |
| no duplicate voter ids | `Refused` for a duplicate |
| every vote is for this state version | `Refused` for a version mismatch |
| every vote binds this exact update hash | `Refused` for a hash mismatch |
| every vote signature verifies under the delegate key | `Refused` otherwise |
| distinct, valid votes `>= threshold` | `Accepted` |

**Owner-root rule.** A valid owner-root signature on the update envelope
satisfies the quorum alone. The owner may also be listed in `delegates`; its
vote then counts as one delegate like any other. The envelope signature is never
double-counted as a vote: it is either full root authority or nothing. On the
delegate path the envelope signer need not be a delegate — the votes bind the
exact content, so the threshold itself is the authority.

### Revocation propagation

`RevocationSet` is the owner-signed revocation list:

```text
version        monotonic revocation version, 1 for the first signed set
revoked        BTreeSet<device id>
signature_b64  owner-root Ed25519 signature over canonical_bytes(set)
```

The canonical encoding is the domain `zero.mesh.revocation-set.v1`, the version,
the count, and the sorted ids, all length-prefixed with big-endian integers.
`sign_revocation_set` refuses version 0, malformed ids, and revoking the owner
root itself. `verify_revocation_set` checks the shape, refuses a set that
revokes the owner root, and verifies the owner root signature
(`zero.pol.denied` on a wrong key or a changed id). A stolen device therefore
cannot revoke another member.

`propagate(local, incoming, owner_pubkey)` verifies the signature first — an
unauthenticated set is an error even when it is old — and then applies the
monotonic rule:

| Situation | Result |
|---|---|
| `incoming.version < local.version` | the local table is returned unchanged (older is ignored) |
| `incoming.version >= local.version` | ids are unioned; the version becomes the higher of the two |

Ids are only ever added. A newer set cannot un-revoke an id by omitting it, so
revocation is permanent for the life of the mesh. The returned `Revoked`
exposes `is_revoked(device_id)`, which is the one check discovery, relay, and
state acceptance share.

### Partition behaviour

`PartitionView { reachable_delegates, has_owner }` describes what a node can
currently reach. `can_write(state, membership, partition)` returns
`partition::Decision::Write` or `Decision::Refuse { reason }`. `state` must
already have been checked with `verify_state` or `apply`; this function reads its
version and revoked set and does not re-verify the snapshot. The rules are:

- no signed membership state (version 0) — refuse; there is no authority and the
  function never falls back to a silent local write;
- an invalid delegate set — refuse;
- the owner root is reachable — write;
- otherwise count the reachable delegates named in the set and not revoked in
  the signed state; at or above `threshold` — write, below it — refuse as a
  minority.

Holding a delegate signing key is not enough. In a minority partition the node
has a key and no quorum, so the write is refused (LCK-10). Healing the
partition — the delegates become reachable again, the owner returns, or a newer
signed state arrives — restores writes without a local override.

### Revocation propagation across two nodes

The `revocation_propagates_between_two_nodes` test simulates the whole path:

1. node A signs `RevocationSet { version: 1, revoked: [victim] }` with the owner
   key and applies it to its `Revoked` table;
2. node B has not seen the revocation, so it still accepts the victim's signed
   announce and records the victim in discovery and presence;
3. node B receives the same signed set, `propagate` verifies it, and
   `drop_revoked` removes the victim from both tables;
4. `ensure_not_revoked` now returns `zero.pol.denied`, `accept_update` rejects an
   update whose sender is the victim, and a relay refuses an envelope whose
   source is the victim in the owner-signed state.

This is the T-MESH-08 done criterion: "revocation propagates". A stale node may
briefly accept a peer it has not yet learned is revoked; once it applies the
signed revocation, every local surface refuses that device.

### Tests

`partition::tests` has 16 tests, listed under [Test evidence](#test-evidence).

### Limitations

- **No transport or gossip.** `check_quorum`, `propagate`, and `drop_revoked`
  are pure functions. Nothing requests, retries, or anti-entropy-syncs a vote or
  a revocation set; a caller moves the signed values between peers.
- **Two revocation carriers.** `MembershipState.revoked` (inside the signed
  snapshot) and `RevocationSet` (the standalone list) both name revoked ids. The
  caller must keep them consistent; this slice does not cross-check one against
  the other.
- **Votes have no timestamp.** `now_ms` bounds the update's `updated_ms` only.
  There is no vote expiry, so a vote is valid until the update it binds stops
  being current.
- **The delegate set is not signed.** It is caller configuration. A peer that
  accepts a different delegate list accepts a different quorum.
- **The owner key is optional.** Without `owner_public_key_b64` only the
  delegate threshold authorises a write; no root path exists.
- **Relay has no peer table.** Relay carries no presence state to drop.
  `drop_revoked` clears discovery and presence, and relay is gated by
  `ensure_not_revoked` plus the signed state's own `revoked` set.
- **Strict clock.** An update dated after `now_ms` is refused with no skew
  allowance, matching the rest of the crate.

## LAN discovery (T-MESH-03)

LAN discovery forms a mesh locally with no account, no service, and no relay
(MESH-03, MESH-12). A peer announces its presence as a signed value; a listener
admits the announce only when the device is an approved, non-revoked member of
the owner-signed membership state and the signature verifies under that member's
public key. There is no account lookup and no server in the path.

### Announce and signature

`PeerAnnounce` is transport-independent:

```text
device_id      64 hex characters: blake3 of the announcing device's public key
name           optional display label; the authenticated identity is device_id
addrs          addresses the peer can be reached on, stored sorted and unique
port           UDP port
nonce          single-use ASCII alphanumeric value, 8..=64 bytes
issued_ms      issue time, milliseconds since the Unix epoch
expires_ms     expiry time, issued_ms < expires_ms, lifetime <= 5 minutes
signature_b64  Ed25519 signature by the device key, standard padded base64
```

`sign_announce(device_key, name, addrs, port, nonce, issued, expires)` derives
`device_id` from the key, normalizes the addresses, and signs
`canonical_announce_bytes`. `new_nonce()` draws 32 hex characters from the
operating system. `verify_announce(public_key_b64, announce)` re-derives the id,
checks `device_id` against it, and verifies the signature; a malformed announce
is `zero.fnd.invalid_input`, a wrong signature is `zero.pol.denied`.

`canonical_announce_bytes` is deterministic and length-prefixed, all integers
big-endian:

```text
"zero.mesh.discovery.announce.v1\0"  domain separator
device_id                            u32 length + UTF-8 bytes
name present                         u8 (0 or 1)
  name                               u32 length + UTF-8 bytes when present
address count                        u32
repeated addresses, sorted:
  encoded address                    u32 length + family byte + 4 or 16 octets
port                                 u16
nonce                                u32 length + UTF-8 bytes
issued_ms                            i64
expires_ms                           i64
```

The signature is excluded because it is produced over these bytes. Addresses
are sorted by family and octets and deduplicated, so a caller's order or
repetition cannot change the signed payload. Validation refuses an empty or
over-large address list, an unspecified or multicast address, a zero port, a
malformed nonce, a negative or non-increasing lifetime, a lifetime above
`MAX_ANNOUNCE_TTL_MS`, an over-long or control-character name, and an encoded
announce above `MAX_ANNOUNCE_BYTES` (4 KiB).

The announce carries nothing else: no account id, user, email, service URL,
token, relay, task, or command. The field set is closed at every layer, so
there is no fleet-orchestration channel (MESH-13: presence only).

### mDNS TXT framing

`MdnsRecord { service, txt, addrs, port }` is the mDNS shape, not a socket
message. `encode_announce` maps a signed announce to TXT fields and
`decode_announce` maps them back:

| TXT key | Value |
|---|---|
| `v` | announce format version, `"1"` |
| `id` | `device_id` |
| `name` | optional device name |
| `addr0`, `addr1`, ... | one address per field, in sorted order |
| `port` | decimal `u16` |
| `nonce` | the announce nonce |
| `issued` | decimal `issued_ms` |
| `expires` | decimal `expires_ms` |
| `sig` | base64 signature |

`service` is always `_zero._udp.local`. Addresses are split across `addrN`
fields so no single TXT value exceeds the 255-byte mDNS string limit. The TXT
fields are authoritative: `MdnsRecord::addrs` and `port` mirror them for the
transport, but `decode_announce` rebuilds the announce from TXT so the signature
covers exactly what was signed. The decoder is strict: a different service, an
unknown field (for example
`account`), a missing required field, a non-contiguous address index, a bad IP
or integer, more than 24 fields, a value over 255 bytes, or a record over 1300
bytes is refused. Decoding is **not** authentication; it only rebuilds the
announce. A decoded announce enters the table only through `accept`.

There is no multicast socket, no browse/respond loop, and no mDNS packet
encoder in this slice. The record type exists so the TXT mapping is exact and
tested; a later transport task owns joining the multicast group, sending
periodic announces, and feeding received records to `decode_announce` and
`accept`.

### Accept and ignore rules

`accept(&mut discovery, announce, &membership_state, now_ms)` returns
`AcceptOutcome::Accepted` or `AcceptOutcome::Ignored { reason }`. An ignored
announce is not an error: nothing is added or updated, and the refusal reason is
for logs and tests. The checks run in order:

| Check | Ignored when |
|---|---|
| membership version | `membership.version` is older than the last version recorded by `accept` (a removed device cannot be resurrected with an old snapshot) |
| structure | the announce fails any bound or address/nonce/lifetime rule |
| membership | `device_id` is absent from `membership.devices`, or has no approved record |
| revocation | the record is revoked or the id is in `membership.revoked` |
| key binding | the record's public key does not hash to `device_id` |
| signature | the signature does not verify under that member key |
| clock | `issued_ms > now_ms` (not yet valid) or `now_ms >= expires_ms` (expired) |
| replay | the nonce was already accepted from this device |
| capacity | the peer table is full (`max_peers`) |

The done criterion is the membership and signature rows: **an unauthenticated
peer is ignored**. An unknown device, a revoked member, and a tampered or
foreign-signed announce all leave `peers()` empty. On success the announce is
stored with sorted, deduplicated addresses, `last_seen_ms = now_ms`, and
`online = true`; the nonce is remembered until the announce expires. The
membership state must already have been authenticated with `verify_state` or
`apply`; `accept` re-checks the specific member's key and id but does not carry
an owner public key.

### Presence and the offline sweep

A `PeerRecord` exposes `announce`, `last_seen_ms`, `online`, and
`presence() -> PeerPresence::{Online, Offline}`. That is the whole peer surface:
there is no command, task, relay, or control channel.

`sweep(&mut discovery, now_ms, offline_after_ms)` marks every online peer whose
`now_ms - last_seen_ms >= offline_after_ms` as offline and returns how many
changed. `DiscoveryPolicy::offline_after_ms` defaults to 90 seconds — three
missed 30-second announces — so a sleeping or powered-off device reads as
offline rather than "unknown" (MESH-14). A fresh announce with a new nonce sets
it online again. `remove(device_id)` drops the peer and its replay ledger;
`peers()` returns the table.

Nonces are remembered per device only until their announce expiry, so the
replay ledger is bounded by the announce rate over one lifetime. When
`max_nonce_history` (64 by default) is reached the entry closest to expiry is
evicted first.

### Tests

`discovery::tests` has 17 tests, listed under [Test evidence](#test-evidence).

### Limitations

- **No socket transport.** Encoding/decoding and the accept rules are complete
  and tested, but nothing sends or receives multicast mDNS. Wiring a real
  responder is a later transport task.
- **Presence is one-way.** A peer is online when its announce was accepted and
  offline after a local sweep. There is no query, ping, or reachability probe
  (MESH-13 deliberately excludes orchestration).
- **Membership trusts the caller.** `accept` is given a `MembershipState`; it
  does not receive the owner public key, so the caller must have verified or
  applied the state first. `accept` does re-check the member record's key/id
  binding and the announce signature.
- **Nonces are per-process.** The replay ledger is local to one `Discovery`;
  a copied announce can be accepted once by a different process that has not
  seen it, within its short lifetime.
- **No announce relay.** A peer only learns of devices whose announce reached
  it. Bridging subnets, gossip, and mDNS reflection are later tasks.
- **Strict clock.** Expiry has no skew allowance; the caller supplies
  `now_ms` and clock quality is the host's responsibility.

## Presence and cost (T-MESH-09)

`src/presence.rs` turns accepted announces into a presence table and answers
two cost questions — may this device sync, and may it act as a relay — without
any fleet-wide view (MESH-13) and with battery and metered links respected
(MESH-14).

### Model

```text
LinkKind   Wifi | Ethernet | Cellular | Metered | Unknown
PowerState Plugged | Battery { percent: u8, charging: bool } | Unknown
Presence {
    device_id     64 hex characters, the same id discovery authenticates
    state         Online | Offline
    reachable     bool
    last_seen_ms  time of the last accepted announce
    link          LinkKind
    power         PowerState
}
```

`Cellular` and `Metered` are metered; `Wifi` and `Ethernet` are not, unless the
caller reports the link as `Metered`. `Unknown` exists because a reading may be
missing: there is no safe default for cost. `PowerState::Unknown` exists for
the same reason. A battery percentage above 100 is refused
(`zero.fnd.invalid_input`) by `PowerState::validate`, `Presence::validate`, and
`PresenceTable::update`; a refused record is not stored.

### Public view

Only `PublicPresence` leaves the module:

| Field | Meaning |
|---|---|
| `device_id` | the authenticated device id |
| `online` | `state == Online`, reduced to a boolean |
| `reachable` | directly reachable; always false while offline |
| `link` | the coarse `LinkKind` |

Power state, battery percentage, charging, `last_seen_ms`, device names,
addresses, and locations are **not** published. `public_view()` returns one
entry per device in ascending device-id order. It reports the stored state, so
sweep first if a sleeping host should already read as offline. It is a flat
list of per-device records, not an aggregate: there is no online count, fleet
total, or rollup, and one device going offline cannot change another device's
entry.

### Table and sleeping hosts

`PresenceTable::new(offline_after_ms)` (default 90 seconds, the discovery
window) holds the records. `update(presence, now_ms)` treats a record as an
announce: it validates the device id and battery, sets `state = Online` and
`last_seen_ms = now_ms`, and stores the reachability and cost fields.
`announce(device_id, link, power, now_ms)` is the shorthand for a fresh online
presence. `get(device_id)` returns the local record. `sweep(now_ms,
offline_after_ms)` marks every online device with
`now_ms - last_seen_ms >= offline_after_ms` as `Offline` and unreachable, and
returns how many changed; it is the discovery sweep rule applied to cost state.

**The done criterion is the sleeping-host rule.** A device that stops
announcing is offline, and offline devices are never relay targets.
`relay_candidates(table, policy, now_ms)` re-checks freshness against the
table's own window, so even a caller that has not swept yet cannot offer a
sleeping host as a relay. A new announce revives the same device.

### Cost policy and decisions

```text
metered_pause                   pause on a metered link            default true
low_battery_pause_percent       defer at or below this percent     default 20
require_charging_for_relay      relay targets must be charging     default true
```

`CostPolicy::validate` and `CostPolicy::new` refuse a low-battery threshold
above 100 (`zero.fnd.invalid_input`). `should_sync(presence, policy)` and
`should_relay(presence, policy)` return `Decision::Allow` or
`Decision::Defer { reason }`, checked in this order:

1. the policy is valid, and the presence is valid;
2. the device is online (a sleeping host defers);
3. the device is reachable;
4. the link is known — an unknown link defers even when `metered_pause` is
   off, because the metered status itself is unknown;
5. a metered link defers when `metered_pause` is set;
6. the power state is known — unknown power always defers;
7. a battery at or below `low_battery_pause_percent` defers unless charging;
8. for relay only, `require_charging_for_relay` refuses a battery device that
   is not charging even at a healthy percentage; a plugged device passes.

Deferring is local and advisory: the policy gates work this process starts. It
is not a remote permission and it does not stop a peer from attempting
anything. The reason strings are for logs and tests.

`relay_candidates(table, policy, now_ms)` returns online, fresh, reachable,
cost-allowed devices in ascending device-id order. It is deterministic and
never includes an offline or sleeping device.

### Tests

`presence::tests` has 12 tests, listed under [Test evidence](#test-evidence).

### Limitations

- **The table is fed by hand.** Nothing in this slice subscribes to discovery.
  A caller moves an accepted announce into `PresenceTable::update` or
  `announce`; wiring that bridge belongs with the mDNS transport.
- **Link and power are caller-reported.** A peer that lies about being plugged
  in is believed. The cost policy shapes our own work; it is not an audit of
  the peer.
- **Unknown is conservative.** An unknown link or power state always defers,
  so a device that never reports either is reachable but never a sync or relay
  partner.
- **Decisions are a snapshot.** `should_sync` and `should_relay` take a
  `Presence` value; a caller that holds the decision while the device sleeps is
  making a stale choice. Re-ask after a sweep.
- **Serde does not re-validate.** `Presence` and `PowerState` deserialise a
  battery percentage without checking it; call `validate` (or feed the record
  to `PresenceTable::update`, which validates) after reading untrusted JSON.
- **No scheduler here.** Deferring does not queue the work for later; retry,
  backoff, and wakeups belong to the caller.

## Relay (T-MESH-05)

A relay moves an opaque envelope between two approved members. It sees routing
metadata and ciphertext; it has no key and no code path that decrypts the
payload, so MESH-05's "a relay cannot read payloads" is a property of the type,
not a promise about behaviour. Inbound is default-deny (MESH-06): a node with
the default `RelayPolicy` approves no relays and forwards nothing.

### Envelope

`RelayEnvelope` has exactly these fields and **no plaintext or key field**:

| Field | Meaning | Validation |
|---|---|---|
| `id` | envelope id | 32 hex characters (16 bytes) |
| `src_device` | source device id | 64 hex characters, the blake3 hash of its key |
| `dst_device` | destination device id | 64 hex characters |
| `ciphertext_b64` | opaque ciphertext, standard padded base64 | non-empty, decoded length equals `bytes`, at most 256 KiB |
| `nonce_b64` | sender nonce, standard padded base64 | 8 to 32 decoded bytes |
| `aad` | public associated data bound by the sender | printable ASCII, at most 256 bytes |
| `created_ms` | sender clock, milliseconds since the epoch | checked against the relay's clock skew |
| `ttl_ms` | forwarding lifetime, milliseconds | positive, at most 10 minutes |
| `bytes` | ciphertext length in bytes | positive, at most 256 KiB |

`RelayEnvelope::validate()` checks those bounds and the base64 shape. It never
inspects the decoded ciphertext beyond its length. Its `Debug` output prints the
ids, `bytes`, `created_ms`, `ttl_ms`, and the lengths of the ciphertext, nonce,
and AAD, but not their contents.

### Approval rules

`RelayNode::forward(envelope, membership, now_ms)` runs the same checks for every
hop, in this order:

1. the policy and envelope pass structural validation;
2. the relay's own device id is listed in `policy.approved_relays`;
3. with `policy.require_member` (the default), the relay is an approved,
   non-revoked member of the owner-signed `MembershipState`;
4. the source and destination are approved, non-revoked members, and each
   record's public key hashes to its device id;
5. `bytes` is within `policy.max_bytes` and `ttl_ms` is within
   `policy.max_ttl_ms`;
6. `created_ms` is not in the future beyond `RelayClock::max_future_skew_ms`,
   and the envelope has not expired at `now_ms`.

A missing, unknown, or revoked source, destination, or relay is
`zero.pol.denied`. A size or TTL above a ceiling is `zero.fnd.limit_exceeded`.
A malformed envelope or policy is `zero.fnd.invalid_input`. There is no
"partially approved" state: the first failure returns an error.

### Ciphertext-only guarantee

`forward` clones the envelope into `Forwarded`; it does not rewrite `bytes`,
`ttl_ms`, or any payload field. `Forwarded` contains the envelope, the relay's
device id, and the relay's time — no plaintext, no key, and no decrypt helper.
The only decryption API is `Endpoint::open`, which requires a key the relay never
receives. Tests assert that the plaintext string and key bytes appear in neither
`Debug` nor serde output, and that a relay hop preserves the ciphertext exactly.

### Policy and bounds

`RelayPolicy` defaults are deliberately closed:

| Field | Default | Meaning |
|---|---|---|
| `max_bytes` | 64 KiB | largest ciphertext this relay forwards |
| `max_ttl_ms` | 5 minutes | longest lifetime this relay accepts |
| `approved_relays` | empty | default-deny: no relay may forward |
| `require_member` | `true` | the relay itself must be a signed-state member |

`RelayClock` defaults to strict (`0` future skew). An envelope is live while
`now_ms < created_ms + ttl_ms`; the boundary itself is expired. A relay does not
decrement the TTL or rewrite the envelope, so a chain is checked against the
same `now_ms`; advancing time between hops is the caller's choice and makes the
expiry check stricter, never looser.

### Endpoint sealing (test helper)

`Endpoint::seal(plaintext, key)` produces `Sealed` envelope parts with a random
16-byte nonce, and `Endpoint::open(envelope, key)` returns the plaintext.
`seal_with_aad` binds public associated data. `Sealed::envelope(...)` fills the
routing fields.

**This is not production cryptography.** The test cipher is a blake3-keyed XOR
keystream plus a 32-byte blake3-keyed MAC, with a constant-time tag comparison;
it exists to demonstrate the relay boundary and to fail on a tampered ciphertext,
changed AAD, or wrong key. Transport encryption, key agreement, and forward
secrecy are T-MESH-07 and are not implemented here.

### Chain

`relay_chain(envelope, relays, membership, now_ms)` calls `forward` for each
node and returns the `Forwarded` hops in order. An empty chain is refused
(`zero.pol.denied`, default-deny), a repeated relay id is refused as a loop, and
the first failure aborts the whole chain — no partial chain is returned. Each hop
re-checks approval and bounds and forwards the identical opaque bytes.

### Tests

`relay::tests` has 14 tests, listed under [Test evidence](#test-evidence).

### Limitations

- **Metadata is visible.** A relay sees the envelope id, the source and
  destination device ids, the AAD, sizes, and timing. The payload is opaque; the
  routing graph is not. Onion-style layers that hide the path are not built.
- **Transport crypto is deferred.** The endpoint cipher is a test double, not
  an AEAD for real traffic. Nothing here derives, rotates, or exchanges keys.
- **No transport or queue.** `forward` and `relay_chain` are pure functions.
  There is no socket, no store-and-forward buffer, no retry, and no
  backpressure.
- **Caller supplies verified state.** Relay checks membership in the
  `MembershipState` it is handed. The caller must obtain that snapshot through
  the owner-signed replication path (`verify_state`/`apply`) first.
- **Single snapshot, no replay ledger.** The relay does not remember envelope
  ids across calls, so a replay within the TTL is only stopped by the endpoints'
  own authentication and replay handling. A chain-local duplicate relay id is
  refused, but a loop spread across separate calls is not tracked.
- **TTL is not decremented.** Every hop judges the original `ttl_ms` against the
  caller's `now_ms`; there is no per-hop budget and no hop counter in the
  envelope.
- **Error codes are coarse.** Expired and not-yet-valid envelopes are
  `zero.pol.denied`, the same code as an unapproved member; the message carries
  the distinction for logs and tests.

## Traversal (T-MESH-04)

`src/traversal.rs` decides how two peers reach each other when a NAT sits in
front of one or both: a STUN probe reports the local mapping, a deterministic
table chooses a direct path, a simultaneous UDP punch, the TCP/443 fallback, or a
relay, and a bounded attempt runs the punch through an injectable seam. It opens
no socket and reads no clock (MESH-04), and any plan with no reachable node
carries the MESH-10 explanation.

### Model and configuration

```text
NatKind          Open | FullCone | Restricted | PortRestricted | Symmetric
Endpoint         { addr: SocketAddr }            JSON as "192.0.2.10:40000"
TraversalConfig {
    stun_servers         usize, 0..=8      default 2
    tcp_fallback         bool             default true
    hole_punch_attempts  u8,    1..=8      default 3
    timeout_ms           i64,   1..=30000  default 250
}
```

`NatKind` is caller-supplied: telling open, full-cone, restricted, and
port-restricted apart needs filter tests that a pair of STUN calls cannot
perform, so the module does not guess. All kinds except `Symmetric` reuse one
external mapping across destinations. `is_publicly_reachable()` is true for
`Open` and `FullCone`; `has_stable_mapping()` is true for everything but
`Symmetric`.

`StunProbe` is the only place a real probe enters:

```text
mapped_addr(local_port) -> Result<Endpoint>   the external address STUN reports
mapping_stable()        -> bool               one mapping for every destination
```

`mapping_stable() == false` means a symmetric NAT, whose reported endpoint is not
a punch target. The trait keeps traversal offline and testable; the STUN client
that answers it is later transport work.

`TraversalConfig::validate` refuses zero attempts, a zero or negative timeout,
more than eight attempts, more than eight STUN servers, and a timeout above
30 seconds (`zero.fnd.invalid_input` for a nonsensical value,
`zero.fnd.limit_exceeded` above a ceiling). `plan` validates before deciding, so
an invalid configuration is the only `Err` a plan can return; an unreachable pair
is an `Ok` plan with a `Failure`.

### Decision table

Rows are the source NAT, columns the destination NAT. Every cell is deterministic
and covered by the 5×5 test.

| source \ destination | Open | FullCone | Restricted | PortRestricted | Symmetric |
|---|---|---|---|---|---|
| Open | Direct | Direct | HolePunch | HolePunch | TCP/443 |
| FullCone | Direct | Direct | HolePunch | HolePunch | TCP/443 |
| Restricted | Direct | Direct | HolePunch | HolePunch | TCP/443 |
| PortRestricted | Direct | Direct | HolePunch | HolePunch | TCP/443 |
| Symmetric | Direct | Direct | TCP/443 | TCP/443 | TCP/443 |

- **Direct.** A destination behind `Open` or `FullCone` accepts an unsolicited
  packet, so `Path::Direct` needs neither a punch nor a local mapping.
- **HolePunch.** Once the destination is not publicly reachable, a punch needs a
  *predictable* mapping on both sides. `Restricted` and `PortRestricted` both
  work because each side's outbound packet opens its own filter for the other;
  `Path::HolePunch { local, remote }` carries both mapped addresses for the
  simultaneous send.
- **TCP/443.** A symmetric NAT allocates a fresh external port per destination,
  so the address it showed STUN is not where the peer's packets will come from;
  no punch target can be named. With `tcp_fallback` set the plan is
  `Path::TcpFallback { endpoint }`, the destination's published IP on port 443.
- **Relay.** With `tcp_fallback` off the same cell is `Path::RelayRequired` plus
  a `Failure` with `needs_rendezvous = true`: the only remaining route is an
  approved relay, and a relay is a reachable node.

The counts are fixed by the golden table: 10 direct cells, 8 punch cells, and 7
cells that fall back to TCP or require a relay.

### Rendezvous failure rule (MESH-10)

`Failure { reason, needs_rendezvous }` is the explanation. It is produced with
`needs_rendezvous = true` when:

- the destination published no mapped address (`path` is `None`);
- a punch is needed but the local mapping is unknown;
- the fallback is disabled behind a symmetric NAT (`Path::RelayRequired`).

The reason of every such failure contains the constant
`RENDEZVOUS_REQUIRED`: "cross-network connectivity needs at least one reachable
node". The caller surfaces that sentence instead of retrying a path that cannot
exist. When no STUN server is configured either, the reason names the missing
rendezvous rather than a probe count.

### Attempts

`attempt(plan, &mut dyn HolePuncher)` executes a plan against the punch seam:

- `Direct` and a selected `TcpFallback` connect with `attempts = 0`; the
  fallback is selected by the planner and dialled by the transport.
- A `HolePunch` is tried at most `hole_punch_attempts` times, each carrying
  `timeout_ms`. `PunchOutcome::Reached` stops with the punch's `attempt` number,
  `Missed` retries, and `TimedOut` stops the loop.
- When every attempt fails, `tcp_fallback` selects the fallback:
  `HolePuncher::tcp_fallback(endpoint)` reports whether it can carry the
  connection (the default says yes, because the carrier is later work). A success
  returns `Connected` with the failed punch in `fallback`; a failure is
  `zero.fnd.unavailable` and says the fallback was attempted and also failed.
- With `tcp_fallback` off the call is `zero.fnd.unavailable`, or
  `zero.fnd.timeout` when the punch timed out, and the message repeats
  `RENDEZVOUS_REQUIRED`.
- `RelayRequired` and a plan with no path return `zero.fnd.unavailable` carrying
  the plan's own explanation.

Nothing in this module waits, connects, or retries at a higher level: the bounds
are data and the seam owns the wait, so a caller can run the same plan under a
real carrier or a scripted fake.

### Tests

`traversal::tests` has 18 tests, listed under [Test evidence](#test-evidence).
The core one is `the_nat_matrix_is_deterministic_and_complete`: all 25 cells are
planned twice, compared, and matched against the golden table, with the 10/8/7
counts asserted so a changed cell cannot pass unnoticed.

### Limitations

- **No carrier.** The module plans and explains; it does not send a packet. The
  UDP punch and the TCP/443 dial are later transport work.
- **The fallback is selected, not dialled.** `Path::TcpFallback` means "dial this
  endpoint on 443". In a deployment that becomes a reachable rendezvous or relay,
  the planner's endpoint is the destination's published address because the
  configuration carries no rendezvous address.
- **Conservative symmetric rule.** A symmetric NAT can, in practice, reach a
  public peer that answers its first packet, and a punch can be initiated from
  the symmetric side. This planner treats *any* symmetric side (with a
  non-public destination) as un-punchable and uses TCP/443 or a relay instead;
  it will not claim a punch it cannot verify.
- **NAT kinds are caller-reported.** A peer that reports a friendlier NAT than it
  has is believed. The plan is our decision, not an audit of the peer.
- **Mappings are a snapshot.** A mapped address is what the last probe said. A
  NAT that rebinds its mapping invalidates the plan; the caller re-probes and
  re-plans.
- **A punch needs both mappings.** The plan refuses to punch without the local
  mapped address even when the NAT kind says one must exist.
- **No cross-plan retry.** One plan is one decision. Falling back from a failed
  punch to a fresh plan is the caller's loop; `attempt` only applies the
  configured TCP/443 fallback.
- **Timeout is a seam value.** `timeout_ms` is passed to the punch and enforced by
  it; the module has no timer and cannot measure a real wait.

## Transport (T-MESH-07)

T-MESH-07 records the transport decision and prototypes the layer above the
datagram carrier. The choice is **datagram streams with a small reliable
session-stream layer**, not a userspace TCP/IP stack. The full comparison,
consequences, and what would change the decision are in
[0002 — Datagram streams for the mesh overlay](decisions/0002-mesh-transport.md).
The deciding constraint is MESH-01: an app-level overlay with no TUN device, no
admin rights, and no `VpnService` has no packet interface to hand a TCP/IP stack,
while Zero's own traffic is session journal chunks and telemetry that need
reliable, ordered delivery rather than IP routing.

### Model

| Value | Meaning |
|---|---|
| `DatagramIo` | The only carrier seam: `send(peer, bytes)` and `recv() -> Option<(peer, bytes)>`. A WireGuard-style userspace overlay supplies it. |
| `PeerId` | An opaque peer label, not a socket address. |
| `StreamConfig` | Fragment size, send window, reassembly slots, stream/fragment ceilings, retransmission budget, round budget, and retransmit wait. |
| `SessionStream` | Sender: fragments the source, chooses in-flight frames, applies acks, and retransmits. |
| `Reassembler` | Receiver: validates frames, suppresses duplicates, buffers out-of-order fragments, returns acks, and yields the contiguous prefix. |
| `move_stream` | The prototype driver: source `Read` in, `DatagramIo` through, `Write` out, `TransferStats` back. |
| `SimulatedNet` | In-memory carrier with deterministic loss, reordering, and duplication. |
| `StreamError` | `Corrupt`, `Oversized`, `Timeout`, `Invalid`, or `Io`. |

`StreamConfig::default()` uses 512-byte fragments, a window of 8 unacknowledged
fragments, 32 reassembly slots, a 4 MiB stream ceiling, at most 16 384
fragments, 8 retransmissions per fragment, and a 10 000-round budget. Every
value is validated before a stream starts; a zero or nonsensical value is
`StreamError::Invalid` and a value above a ceiling is `StreamError::Oversized`.
`SessionStream` keeps at most a window of fragments in flight and a
retransmission never consumes another slot. `Reassembler` accepts at most
`max_buffered` out-of-order fragments and never lets the reassembled bytes
exceed `max_stream_bytes`.

### Wire format

Every datagram is a fixed header, the payload, and a truncated blake3 hash, all
integers big-endian:

```text
magic "ZMST" (4) | version (1) | kind (1) | stream id (8) |
fragment index (4) | total fragments (4) | payload length (2) |
payload | blake3 body hash (16)
```

Kind `0` is a data fragment and kind `1` is an acknowledgement (no payload).
The hash covers the header and payload, so a flipped byte is rejected before it
can enter the reassembly buffer. `PROTOCOL_VERSION` is 1; there is no version
negotiation yet.

### Reliability

- **Fragmentation and reassembly.** The source is split into
  `fragment_bytes` payloads and every data frame names its index and the total
  fragment count. The receiver writes only the contiguous prefix; an
  out-of-order fragment waits in the bounded buffer and is drained when the gap
  closes.
- **Acks and retransmission.** `Reassembler` acks every accepted fragment,
  including a duplicate, so a lost ack is repaired by the sender's retransmit.
  `SessionStream` resends an unacknowledged fragment after
  `retransmit_after_rounds`, up to `max_retransmits`, then reports
  `StreamError::Timeout` when no progress is possible. The whole stream also has
  `max_rounds`.
- **Duplicates and reordering.** A fragment below the expected index, or one
  already buffered, is acked again and not appended. A fragment above the
  expected index counts once as reordered and occupies a buffer slot.
- **Corruption and bounds.** A bad magic, version, kind, length, index, or hash
  is `StreamError::Corrupt`; an oversized fragment, buffer, stream, or
  configuration is `StreamError::Oversized`. `move_stream` compares the
  reassembled bytes with the source and writes nothing unless they are identical.

### Tests

`transport::tests` has 16 tests, listed under [Test evidence](#test-evidence).
The Done criterion is `a_session_jsonl_stream_moves_byte_identically`: 160
representative session events cross a carrier that drops every fifth datagram,
holds every fourth for two receive ticks, and duplicates every seventh, and the
receiver writes the exact source bytes, which still parse as 160 JSON lines.
The other tests cover loss and retransmission, reordering, duplicate
suppression, corruption, oversized streams and buffers, the send-window bound, a
stalled stream's timeout, an empty stream, frame round-trips, peer/config/stats
serde, and a source scan that proves the module names no socket and no clock.

### Limitations

- **No carrier.** `move_stream` runs both endpoints over one in-memory
  `DatagramIo`. The real WireGuard-style overlay that supplies the trait is
  later work; no socket is opened here.
- **No congestion control.** The window is fixed and the retransmit wait is a
  configured number of rounds, not an RTT estimate. Sustained loss backs off
  only by exhausting the retransmit budget. Production needs an in-flight byte
  cap, pacing, and backoff.
- **One stream per receiver.** There is no stream multiplexing, so a lost
  fragment blocks later bytes of that stream (head-of-line within the stream);
  independent streams are not yet separated.
- **Corruption fails the stream.** The prototype returns `StreamError::Corrupt`
  on the first bad datagram. A production receiver must drop the datagram,
  count it, and let retransmission repair it; a bad packet must not end a
  healthy stream.
- **No cryptography.** `DatagramIo` receives plaintext frames in the prototype.
  The userspace overlay must encrypt and authenticate them; a relay still
  forwards only ciphertext.
- **Configured fragment size, not path MTU.** 512 bytes is conservative. A
  larger value must fit the overlay and outer path, including WireGuard and relay
  encapsulation.
- **Modelled time.** The round budget and retransmit wait are loop iterations;
  nothing here waits, reads a clock, or wakes a radio. Real timers, battery, and
  metered-link behaviour belong to the carrier and the presence/cost policy.

## Trust-flow limitations

- **Snapshots have no transport.** `MembershipState` and `StateUpdate` are
  verified data structures. The quorum and revocation rules are T-MESH-08
  (`src/partition.rs`), but moving votes, snapshots, and revocation sets between
  peers — gossip, retry, anti-entropy — is still the caller's job; nothing here
  opens a socket.
- **The T-MESH-01 `Membership` is still trusted local state.** It is
  serialisable but not signed as a whole. Across a trust boundary, transfer a
  `MembershipState` and check it with `verify_state`; do not treat a transferred
  `Membership` as owner-authorised.
- **Threshold delegates are a separate configuration.** `MembershipState` is
  still signed by one owner root. The owner-or-threshold authority is the
  `DelegateSet` in `src/partition.rs`; the delegate list itself is not signed.
- **Rotation is device-signed, not owner-signed.** `rotate` accepts the old
  device key's signature over the new key. The owner must fold the result into
  a new signed snapshot for peers to accept it.
- **Epoch is reserved.** `MembershipState::epoch` is signed and replicated but
  has no rule yet; owner-root re-keying and its epoch transition are deferred.
- **Conflict resolution is manual.** Two same-version snapshots are a
  `Conflict`; the owner must sign a later version. There is no automatic merge
  and no fork log.
- **Consumption is local.** `used` is outside the token signature, and
  `consumed_tokens` lives in one `Membership`. A token copied to a different
  membership instance can be used once there; the signed snapshot does not yet
  carry a token-consumption ledger.
- **Strict clock.** Expiry is `now_ms > expires_ms` with no skew allowance. The
  caller supplies the clock; clock quality is the host's responsibility.
- **No detached approval transport.** `approve` takes the owner key pair
  directly. A signed approval envelope that can travel between hosts is still
  later work.
- **Short code length.** The code is self-contained at 39 base32 characters.
  T-MESH-06 uses it as-is; a genuinely short code needs a lookup service or a
  rendezvous channel, which the offline rule deliberately excludes.
- **The join offer has no transport.** T-MESH-06 renders the QR payload and
  short code and records the pending join, but the strings reach the guest by
  the caller's channel. The LAN/mDNS transport (T-MESH-03/T-MESH-04) will carry
  them later, and its absence is what keeps the flow offline and socket-free.
- **No labels API yet.** `DeviceRecord.name` serialises and survives rotation,
  and `MembershipState.names` is signed, but no public call sets either; a
  caller edits the snapshot and signs a new version.
- **Audit is deferred.** Every snapshot carries `version`, `updated_ms`, and
  `signed_by`, but there is no append-only audit chain for joins, approvals,
  rotations, revocations, and relays (MESH-15).
- **Scope.** There is no multicast socket, mDNS responder, STUN socket, punch
  carrier, TCP/443 dial, relay transport, or TUN device here. T-MESH-01,
  T-MESH-02, T-MESH-03, T-MESH-04, T-MESH-05, T-MESH-06, T-MESH-07, T-MESH-08,
  and T-MESH-09 are pure state machines (T-MESH-07 is the in-process transport
  prototype); the identity flow, the signed-snapshot flow, announce
  accept/ignore, the NAT decision table and punch state machine, the
  ciphertext-only relay checks, the one-action offer and QR/code join, the
  quorum/revocation rules, presence/cost decisions, and the lossy-datagram
  session stream are exercised without a network.

## Test evidence

Commands (run from the repository root):

```text
$env:CARGO_INCREMENTAL='0'; cargo test -p zero-mesh -j 1
$env:CARGO_INCREMENTAL='0'; cargo clippy -p zero-mesh --all-targets -j 1 -- -D warnings
```

`cargo test -p zero-mesh` runs 246 tests: 16 in `bundle::tests`, 17 in
`discovery::tests`, 12 in `fence::tests`, 13 in `identity::tests`, 14 in
`join_ux::tests`, 16 in `partition::tests`, 19 in `portability::tests`, 12 in
`presence::tests`, 14 in `relay::tests`, 12 in `restore::tests`, 17 in
`snapshot::tests`, 15 in `state::tests`, 17 in `transfer::tests`, 16 in
`transport::tests`, 18 in `traversal::tests`, 7 in `trip_matrix::tests`, and 11
in `vault_transfer::tests`. There are no integration tests, no network access,
no sockets, and no timers.

| Test | Proves |
|---|---|
| `an_unapproved_device_cannot_join` | **Done criterion:** a valid unapproved join returns `zero.pol.denied`, the device is not a member, the request is pending, and the token was consumed. |
| `a_valid_token_and_owner_approval_joins` | A valid token plus owner approval creates a member with the right key; a repeat join is idempotent and does not duplicate the device. |
| `an_expired_token_is_refused` | `join` and `consume` both refuse a token past `expires_ms` with `zero.pol.approval_expired`, and nothing becomes pending. |
| `a_reused_token_is_refused` | A token is single-use across devices and via `consume`; `used` stops at `max_uses`. |
| `a_tampered_token_is_refused` | A changed secret, expiry, or id, and a wrong owner key, all fail signature verification with `zero.pol.denied`. |
| `a_non_owner_cannot_approve_or_revoke` | A non-owner key cannot approve a pending device or revoke a member; the owner key still can. |
| `a_revoked_device_cannot_join_or_rotate_back` | Revocation blocks member status, join, and rotation; a fresh owner approval re-admits the device. |
| `rotation_requires_the_old_key_and_updates_the_id` | Rotation changes the device id, sets `rotated_from`, revokes the old record, refuses a tampered or unrelated-key request, and refuses a revoked old key. |
| `short_code_and_qr_payload_round_trip` | The QR payload and grouped base32 short code both parse back to the same id and secret; case, spaces, and hyphens are tolerated; garbage is `zero.fnd.invalid_input`. |
| `private_key_bytes_never_cross_debug` | Neither the hex nor the base64 private scalar appears in `KeyPair` or `DeviceRecord` `Debug` output; wrong-payload verification is `zero.pol.denied`. |
| `membership_survives_a_serde_round_trip` | Membership, pending joins, consumed tokens, and a token round-trip through JSON unchanged. |
| `a_duplicate_join_is_idempotent_and_a_pending_duplicate_is_refused` | A second pending request is refused without consuming a token; approval stays idempotent and leaves one device. |
| `malformed_ids_and_keys_are_typed` | Bad owner keys, bad token ids, a zero ttl (`zero.fnd.invalid_input`), and a ttl above the ceiling (`zero.fnd.limit_exceeded`) are refused. |

Join UX tests in `join_ux::tests`:

| Test | Proves |
|---|---|
| `one_action_offer_carries_a_qr_code_and_expiry` | **MESH-07:** one call yields a signed single-use token, the QR payload, and the short code; both encodings parse to the same id and secret; the window is `created_ms + ttl`; the expiry boundary is still valid; zero and over-ceiling ttls are typed. |
| `qr_and_short_code_are_secrets_in_debug_output` | `JoinOffer`'s `Debug` prints the token id and window but not the QR payload, the short code, or the token secret. |
| `a_valid_qr_join_is_pending_until_approval` | A scanned QR records a `PendingJoin`, consumes the token, and leaves `devices` empty; a retry while pending is idempotent. |
| `a_valid_short_code_join_is_pending_until_approval` | A typed (lower-case) short code joins as pending; a QR payload in the code field is refused with placement guidance. |
| `an_expired_invite_is_refused_with_guidance` | A past-expiry invite is `zero.pol.approval_expired`, nothing is pending or consumed, and the message says to create a fresh invite. |
| `a_reused_invite_is_refused_and_the_second_device_stays_out` | A single-use invite admits one device; a second device gets `zero.pol.denied` "already been used" with fresh-invite guidance and is not pending. |
| `a_tampered_or_foreign_code_is_refused_with_guidance` | Garbage, another invite's code, an offer whose encoding was edited, and a token whose secret was swapped all fail with typing and guidance. |
| `approval_completes_membership_and_is_idempotent` | `approve_pending` writes the member record, clears pending, is idempotent, refuses an already-member rescan, and is `not_found` for an unknown id. |
| `a_two_device_join_completes_under_a_minute` | **Done criterion:** two independently generated device keys, one offer, a QR join, an owner approval, and a 25.5-second `JoinTimeline` that passes `within_target(60_000)`. |
| `an_over_target_join_is_reported_not_hidden` | A 61-second join reports `join_duration_ms = 61_000` and fails the target; an unfinished join has no duration and is not within target; out-of-order milestones are invalid. |
| `a_foreign_owner_or_unusable_offer_is_typed` | A non-owner key cannot record a join and a malformed device key is `zero.fnd.invalid_input`, leaving nothing pending. |
| `the_offer_and_timeline_have_no_account_or_service_fields` | The serde field sets are closed with no account/service/user/email/relay/url key, and the module source names no socket or HTTP transport. |
| `offers_pending_joins_and_timelines_survive_serde` | An offer, a pending join, a finished timeline, and a partial timeline round-trip unchanged; the restored offer re-validates. |
| `the_join_path_reuses_the_identity_contract` | The same token presented through `identity::join` is single-use and pending, so the UX layer adds no second membership path. |

Signed-state tests in `state::tests`:

| Test | Proves |
|---|---|
| `owner_signed_add_and_revoke_apply` | Owner-signed version 2 adds two devices and version 3 revokes one; records, the revoked set, and names all move together. |
| `owner_signed_eviction_applies` | An owner-signed snapshot can remove a device record, drop its name, and keep its id in the revoked set; the eviction applies and the id stays revoked. |
| `the_owner_root_record_cannot_be_evicted` | Even an owner-signed successor that removes the owner root's own device record is `Rejected`; the root record is pinned while root rotation is deferred. |
| `a_device_signed_eviction_is_rejected` | **Done criterion:** a device-signed eviction verifies under the attacker's own key but not under the owner root; `apply` returns `Rejected` and the victim stays a member. |
| `tampered_state_and_signature_are_rejected` | An edited field, a replaced signature, and a device-signed snapshot all fail `verify_state` with `zero.pol.denied`; a tampered update envelope is rejected. |
| `version_rollback_is_rejected` | An authentically owner-signed version-2 update offered to a version-3 peer is `Rejected` as a rollback. |
| `a_duplicate_update_is_already_applied` | Re-delivering an applied update is `AlreadyApplied` by canonical content, not `Applied` and not `Conflict`. |
| `same_version_different_content_conflicts` | Two owner-signed version-2 snapshots with different content produce `Conflict`; neither is picked. |
| `a_higher_owner_signed_version_wins` | A peer at version 1 adopts owner-signed version 3, so missed intermediates do not wedge replication. |
| `name_changes_are_signed` | A signed rename applies; editing the name after signing is rejected and the old name remains. |
| `duplicate_device_ids_and_names_conflict` | Duplicate names (case-insensitive), a record id that disagrees with its map key, and a revoked flag that disagrees with the revoked set are `zero.fnd.invalid_input`. |
| `canonical_bytes_are_stable_and_exclude_the_signature` | Insertion order does not change the bytes, the domain prefix is present, the signature is excluded, and a name change does change the bytes. |
| `oversized_and_invalid_fields_are_typed` | Long/control names, too many devices, a bad revoked id, version 0, owner self-revocation, a malformed owner key, and a `sign_update` version gap are typed (`zero.fnd.invalid_input`, `zero.fnd.limit_exceeded`, `zero.pol.denied`). |
| `state_and_update_survive_serde` | A snapshot and an update round-trip through JSON unchanged, and the restored snapshot still verifies. |
| `an_unsigned_genesis_accepts_one_owner_signed_update` | A version-0 placeholder accepts exactly one owner-signed version-1 snapshot, then reports `AlreadyApplied`; another owner and a bad key are rejected. |

Discovery tests in `discovery::tests`:

| Test | Proves |
|---|---|
| `a_valid_member_announce_is_accepted` | A signed announce from an approved member is accepted, becomes online with `last_seen_ms = now`, carries its addresses, and records the membership version. |
| `an_unknown_device_is_ignored_without_adding_a_peer` | **Done criterion:** a well-formed announce from a device absent from the signed state is `Ignored` ("not an approved member") and the peer table stays empty. |
| `a_tampered_or_foreign_signature_is_ignored` | A signature from another key and an address changed after signing are both `Ignored`; neither adds a peer. |
| `a_revoked_member_is_ignored` | An announce from a device revoked in the signed state is `Ignored` and adds no peer. |
| `expired_and_not_yet_valid_announces_are_ignored` | An announce past `expires_ms` and one issued in the future are both `Ignored`, with distinct reasons. |
| `a_replayed_nonce_is_ignored` | Re-delivering an accepted announce is `Ignored` as "already seen", `last_seen_ms` does not move, and a fresh nonce refreshes the same peer. |
| `sweep_marks_a_sleeping_peer_offline_and_an_announce_revives_it` | **MESH-14:** a peer stays online one millisecond before the window, goes offline at the boundary, preserves its last-seen time, and returns online on a new announce. |
| `duplicate_addresses_are_deduplicated_and_sorted` | Repeated/reordered addresses verify against the canonical encoding, are stored once in sorted order, and the stored announce still verifies. |
| `canonical_bytes_ignore_signature_and_insertion_order` | Address order and the signature do not change the canonical bytes; a name change does; the domain prefix is present. |
| `mdns_txt_round_trips_and_has_no_account_fields` | Encode/decode is lossless, the TXT key set is exactly the closed announce set with no account/service/user/relay/cloud/token fields, and a decoded forged record is still ignored by `accept`. |
| `malformed_and_oversized_mdns_records_are_rejected` | Wrong service, missing `sig`, an unknown `account` field, a bad IP, a gapped address index, a zero port, a 256-byte value, too many fields, and too many addresses are typed `zero.fnd.invalid_input` or `zero.fnd.limit_exceeded`. |
| `an_older_membership_version_is_ignored` | After a version-2 state is applied, an announce offered with version 1 is `Ignored` as older than the last applied version and the peer count is unchanged. |
| `a_mismatched_membership_record_is_ignored` | A record whose public key does not hash to its device id is `Ignored` even though the caller supplied the state. |
| `announce_structure_is_bounded_and_typed` | Empty address list, zero port, short/non-alphanumeric nonce, non-positive lifetime, a lifetime above the ceiling, unspecified/multicast addresses, and long/control names are refused with the right code. |
| `presence_is_only_online_or_offline` | `Presence` serialises as `online`/`offline`, and a serialised announce contains no account, service, command, task, relay, or cloud field. |
| `remove_and_peers_expose_local_state` | `peers()` returns the accepted table, `remove()` returns and drops the peer plus its replay ledger, and removal allows a fresh local re-accept. |
| `announce_and_mdns_record_survive_serde` | An announce round-trips through JSON and still verifies; encode then decode returns the same value. |

Presence tests in `presence::tests`:

| Test | Proves |
|---|---|
| `a_fresh_announce_is_online_and_reachable` | A fresh announce stores an online, reachable record with `last_seen_ms = now` and the reported link and power. |
| `a_sleeping_host_is_offline_and_not_a_relay_candidate` | **Done criterion (MESH-14):** after the window the host is offline and unreachable, it is not a relay candidate, an unswept stale entry is also excluded, and a new announce revives it. |
| `sweep_boundary_matches_the_offline_window` | One millisecond before the window the device stays online, at the boundary it goes offline, and a second sweep is a no-op. |
| `an_unreachable_peer_is_not_a_relay_candidate` | An online but unreachable device is excluded from relay candidates and deferred with a reachability reason. |
| `a_metered_link_pauses_sync_and_relay_when_configured` | Cellular and metered links defer sync and relay under the default policy; Wi-Fi/Ethernet allow; disabling `metered_pause` allows them. |
| `low_battery_defers_unless_charging` | 10% and the exact threshold defer sync when not charging, above the threshold allows, charging allows, and plugged allows. |
| `relay_requires_charging_when_configured` | A healthy 90% battery device may sync but not relay; charging, plugged, and `require_charging_for_relay = false` change that as configured. |
| `unknown_power_and_link_are_conservatively_deferred` | Unknown power always defers; unknown link defers even with `metered_pause` off. |
| `public_view_exposes_only_the_allowed_fields` | The public view carries exactly `device_id`, `online`, `reachable`, and `link`; no power, battery, percentage, charging, last-seen, or location key. |
| `percent_validation_refuses_above_one_hundred` | 101% is `zero.fnd.invalid_input` at `PowerState`, `Presence`, and `update`, the record is not stored, and 100% is allowed. |
| `invalid_cost_policy_is_refused` | A threshold above 100 fails `validate`/`new`, cost decisions defer under it, and a valid policy allows. |
| `the_public_view_is_per_device_with_no_fleet_aggregation` | Two devices yield two independent entries in ascending id order, one offline does not change the other, and the serialised view is a flat per-device array with no totals. |

Relay tests in `relay::tests`:

| Test | Proves |
|---|---|
| `a_relay_forwards_opaque_bytes_and_the_endpoint_decrypts` | **Done criterion (MESH-05):** an approved relay forwards the exact ciphertext to the next hop, the endpoint decrypts with its key, and the relay's `Debug` view never contains the plaintext, ciphertext, or nonce. |
| `an_unapproved_relay_is_refused` | A member relay absent from `approved_relays` is `zero.pol.denied`; explicit approval without membership is also refused while `require_member` is set, and allowed when the owner relaxes it. |
| `default_deny_refuses_when_no_relay_is_approved` | **MESH-06:** the default policy approves no relays, refuses a hop, and refuses an empty chain. |
| `a_revoked_relay_source_or_destination_is_refused` | A relay, source, or destination revoked in the signed state is `zero.pol.denied` with a role-specific reason. |
| `unknown_members_are_refused` | An absent source or destination and a record whose public key does not hash to its id are refused. |
| `size_bounds_are_enforced` | A ciphertext above the policy ceiling or the global ceiling is `zero.fnd.limit_exceeded`; a `bytes` field that disagrees with the decoded length and a zero-byte policy are `zero.fnd.invalid_input`. |
| `ttl_bounds_are_enforced` | A zero TTL is invalid, a TTL above the policy or global ceiling is `zero.fnd.limit_exceeded`, and a TTL exactly at the ceiling is accepted and unchanged. |
| `expired_and_future_envelopes_are_refused` | The expiry boundary is refused, a future `created_ms` is refused under strict clock agreement, allowed within configured skew, and negative skew is invalid. |
| `a_multi_hop_chain_passes_the_same_opaque_bytes` | Three approved relays each accept the same envelope; every hop carries identical bytes, its own relay id and time, and the endpoint still decrypts. |
| `a_chain_refuses_a_bad_hop_or_a_loop` | A chain aborts with no partial result at an unapproved hop, and a repeated relay id is refused as a loop. |
| `a_tampered_ciphertext_or_wrong_key_fails_endpoint_decryption` | A flipped ciphertext character, changed associated data, a truncated tag, and the wrong key all fail authentication with `zero.pol.denied`. |
| `debug_and_serde_never_expose_plaintext_or_keys` | Envelope and hop `Debug`/JSON contain the plaintext marker and key neither in hex nor base64, and have no `plaintext` field. |
| `malformed_envelopes_and_policies_are_typed` | Bad ids, empty/non-base64 ciphertext, out-of-range nonces, binary or oversized AAD, zero TTL, and zero or malformed policy fields return `zero.fnd.invalid_input` or `zero.fnd.limit_exceeded`. |
| `envelopes_and_hops_survive_serde` | An envelope and a forwarded hop round-trip through JSON unchanged, and the restored envelope still opens with the endpoint key. |

Partition, quorum, and revocation tests in `partition::tests`:

| Test | Proves |
|---|---|
| `a_minority_below_threshold_cannot_write` | **Done criterion (LCK-10):** two votes against a threshold of three are `Refused` as a minority, and a node holding one delegate key still gets `Decision::Refuse` for a local write. |
| `threshold_delegates_accept_the_update` | Three distinct delegate votes at a threshold of three are `Accepted`. |
| `duplicate_voters_are_refused` | The same delegate voting twice is `Refused` as a duplicate even when `votes.len()` reaches the threshold. |
| `votes_must_bind_the_exact_update_version_and_hash` | A vote for another version, a forged hash, and a vote signed for a different update are all `Refused`. |
| `a_non_delegate_vote_is_refused` | A vote from a key outside the delegate set is `Refused` and names the outsider. |
| `a_tampered_vote_signature_is_refused` | A changed vote signature no longer verifies under the delegate key and is `Refused`. |
| `the_owner_root_signature_satisfies_quorum_alone` | **MESH-09:** an owner-signed envelope is `Accepted` with no votes; the owner listed as a delegate contributes exactly one vote toward a threshold of two. |
| `a_future_dated_update_is_refused` | An update whose `updated_ms` is after `now_ms` is `Refused`. |
| `a_malformed_delegate_set_is_typed` | Zero/oversized thresholds, an empty set, an id that does not match its key, a malformed key, and a malformed owner key are `zero.fnd.invalid_input`. |
| `a_revocation_signature_is_verified` | An owner-signed set verifies; changed ids, a foreign owner key, an owner self-revocation, and a self-revoked set are refused. |
| `an_older_revocation_is_ignored` | A version-1 set offered to a version-2 table returns the local table unchanged. |
| `a_newer_revocation_unions_the_ids` | Equal and newer versions union the ids, the version is monotonic, and an unauthenticated newer set is `zero.pol.denied`. |
| `revocation_propagates_between_two_nodes` | **Done criterion (MESH-08):** node A revokes, node B applies the signed set, drops the victim from discovery and presence, refuses it via `ensure_not_revoked` and `accept_update`, and a relay refuses it as a source. |
| `a_partition_heals_with_a_higher_version` | Minority refuses, healed reachability and an owner allow writes, a revoked delegate stops counting, and revocation continues from a higher version while an older one is ignored. |
| `no_write_happens_without_authority` | A version-0 state refuses with the "silent local write" reason, and a reachable non-delegate does not count toward the quorum. |
| `quorum_and_revocation_types_survive_serde` | `RevocationSet`, `Revoked`, and `DelegateSet` round-trip through JSON; the restored revocation still verifies and the restored set validates. |

Traversal tests in `traversal::tests`:

| Test | Proves |
|---|---|
| `the_nat_matrix_is_deterministic_and_complete` | **Done criterion:** all 25 NAT cells are planned twice with identical results and matched against the golden table; 10 direct, 8 punch, and 7 TCP/443 cells, and every usable plan carries no failure. |
| `disabling_the_fallback_makes_every_blocked_cell_require_a_relay` | With the fallback off, each of the seven blocked cells is `Path::RelayRequired` with `needs_rendezvous` and the MESH-10 sentence; direct and punch cells are unchanged and no plan is empty. |
| `symmetric_and_symmetric_falls_back_to_tcp_when_enabled` | Symmetric to symmetric cannot punch and selects `Path::TcpFallback` to the destination's IP on port 443, with no failure. |
| `symmetric_pairs_never_plan_a_punch` | No cell with a symmetric side and a non-public destination produces `Path::HolePunch`. |
| `a_missing_destination_mapping_needs_rendezvous` | **MESH-10:** a destination with no mapped address yields no path, `needs_rendezvous = true`, and a reason naming the probe count; with no STUN server the reason names the missing rendezvous; a public destination still needs an address. |
| `a_missing_local_mapping_falls_back_or_requires_a_relay` | An unknown local mapping selects TCP/443 when enabled, `RelayRequired` with the local-mapping reason when disabled, and does not block a public destination. |
| `config_validation_bounds_every_field` | The defaults are valid; zero attempts, zero/negative timeouts, and over-ceiling attempts, timeouts, and STUN servers return the right code; `plan` refuses an invalid configuration. |
| `a_direct_path_connects_without_punching` | A direct plan connects with zero attempts, zero punches, and no fallback. |
| `a_selected_tcp_fallback_connects_without_punching` | A plan that already selected TCP/443 connects with the fallback path and zero attempts. |
| `punch_attempts_are_bounded_by_the_configuration` | Three configured attempts mean exactly three punches; the fallback carries the connection and reports "missed after 3 of 3". |
| `a_reached_punch_stops_retrying` | A punch that lands on the second attempt stops the loop, reports `attempts = 2`, and the seam saw the attempt number, timeout, and both endpoints. |
| `a_punch_timeout_stops_the_retries_then_falls_back` | A timeout stops the retry loop after one attempt and the fallback reports it; with the fallback off the error is `zero.fnd.timeout` with the rendezvous sentence. |
| `a_failed_fallback_is_a_typed_error_with_the_explanation` | A punch failure plus a fallback that reports failure is `zero.fnd.unavailable`, says the fallback was attempted and also failed, and repeats MESH-10; the fallback was attempted once. |
| `a_relay_required_plan_repeats_the_rendezvous_explanation` | Attempting a `RelayRequired` plan returns `zero.fnd.unavailable` with the plan's rendezvous explanation and no punch. |
| `a_plan_without_a_path_returns_its_failure` | Attempting a plan with no path returns the plan's own failure, not a generic error. |
| `a_probe_mapping_and_stability_drive_the_plan` | A `StunProbe` mapping plus `mapping_stable()` decides punch versus TCP/443, and a probe error is surfaced unchanged. |
| `plans_paths_and_failures_survive_serde` | A plan, a path, and a failure round-trip through JSON; the path is tagged `hole-punch` and an endpoint is the `"ip:port"` string. |
| `the_module_opens_no_socket_and_starts_no_timer` | The module source names no UDP/TCP socket, no address resolution, and no clock or timer. |

Transport tests in `transport::tests`:

| Test | Proves |
|---|---|
| `a_session_jsonl_stream_moves_byte_identically` | **Done criterion (T-MESH-07):** 160 representative session events cross a carrier that drops, reorders, and duplicates datagrams and are written byte-identically; the result still parses as 160 JSON lines, fragments exceed 20, and retransmits and reordered fragments are both greater than zero. |
| `fragmentation_and_reassembly_are_exact_without_loss` | A 2048-byte source is split at the configured fragment size and reassembled exactly on a clean carrier with zero retransmissions and zero reordering. |
| `loss_is_repaired_by_retransmission` | Dropping every third datagram still moves the exact bytes, with retransmissions and drops both counted. |
| `reordered_fragments_are_buffered_and_ordered` | Delaying every second datagram makes later fragments arrive first; they are buffered, the transfer is exact, and reordering is counted. |
| `duplicate_fragments_are_suppressed` | A repeated fragment is acked again but not appended; the whole prototype also survives a carrier that duplicates datagrams. |
| `a_corrupt_datagram_fails_the_stream` | Flipping one payload byte is `StreamError::Corrupt` and nothing is written to the destination. |
| `corrupt_frames_are_rejected` | A bad hash, magic, kind, truncated frame, oversized payload, and out-of-range index are all rejected. |
| `oversized_streams_fragments_and_configs_are_rejected` | Zero and above-ceiling configuration fields are typed, and an oversized source, fragment count, or reassembler count is `StreamError::Oversized`. |
| `the_reassembly_buffer_is_bounded` | A second out-of-order fragment beyond `max_buffered` is `StreamError::Oversized` and the first stays buffered. |
| `a_stalled_stream_times_out` | A carrier that drops everything yields `StreamError::Timeout` after the retransmission budget is spent, and nothing is written. |
| `the_send_window_is_bounded` | Only `window` fragments are in flight, a duplicate ack changes nothing, and each ack frees exactly one slot for the next fragment. |
| `an_empty_stream_moves_nothing` | An empty source completes with zero bytes, fragments, retransmissions, and reordering, and writes nothing. |
| `data_and_ack_frames_round_trip` | A data frame and an ack frame encode and decode unchanged. |
| `peer_ids_configs_and_stats_survive_serde` | `PeerId`, `StreamConfig`, and `TransferStats` round-trip through JSON; a peer id is a bare string. |
| `peer_ids_are_bounded` | An empty peer id is invalid and an over-long one is oversized. |
| `the_module_opens_no_socket_and_reads_no_clock` | The module source names no UDP/TCP socket, no IP address API, no clock, and no address resolution. |
