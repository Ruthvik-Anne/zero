//! `zero-mesh` — see `architecture.md` section 5 for the module contract.
//!
//! [`identity`] is the T-MESH-01 slice: an Ed25519 device identity whose id is
//! the blake3 hash of its public key, short-lived single-use join tokens signed
//! by the owner root, explicit owner approval before a device becomes a member,
//! revocation, and device-key rotation (MESH-07, MESH-08, MESH-09).
//!
//! [`state`] is the T-MESH-02 slice: a complete membership snapshot — devices,
//! revoked ids, and in-mesh names — signed and versioned by the owner root and
//! replicated as whole snapshots (MESH-02, MESH-09, MESH-11, MESH-15). Only the
//! owner public key verifies, so a stolen device cannot evict, revoke, or
//! rename another member.
//!
//! [`discovery`] is the T-MESH-03 slice: signed LAN presence announcements that
//! are accepted only from approved, non-revoked members of the signed state
//! (MESH-03, MESH-12, MESH-14). An unauthenticated peer is ignored rather than
//! reported as an error, presence is online or offline only, and the mDNS TXT
//! framing is defined without opening a multicast socket.
//!
//! [`presence`] is the T-MESH-09 slice: the online/offline presence table, the
//! narrow per-device public view, and the battery/metered cost policy that
//! gates sync and relay (MESH-09, MESH-13, MESH-14). Power state stays local,
//! nothing is aggregated across the fleet, and a sleeping host is offline and
//! never a relay candidate.
//!
//! [`relay`] is the T-MESH-05 slice: an opaque ciphertext envelope forwarded
//! only by explicitly approved members of the signed state, with size and TTL
//! bounds, default-deny inbound, and no plaintext or key in the relay
//! (MESH-05, MESH-06). Transport encryption is T-MESH-07; the endpoint cipher
//! here exists only to prove the relay cannot read a payload.
//!
//! [`partition`] is the T-MESH-08 slice: a delegate threshold that accepts a
//! write only with enough distinct votes (or an owner-root signature), the
//! minority-partition refusal, and owner-signed revocation sets that propagate
//! monotonically and drop a revoked device from discovery, presence, and relay
//! (MESH-08, MESH-09, LCK-10). The `partition::Decision` type is re-exported as
//! `PartitionDecision` so it does not collide with the presence `Decision`.
//!
//! [`join_ux`] is the T-MESH-06 slice: the host's one action mints a signed
//! single-use invite and renders both the QR payload and the short code; the
//! guest joins by either, waits as a
//! [`PendingJoin`](crate::identity::PendingJoin) until the owner approves, and
//! the modelled [`join_ux::JoinTimeline`] checks MESH-07's
//! under-a-minute target (MESH-06, MESH-07). No account, service, or socket is
//! involved.
//!
//! [`traversal`] is the T-MESH-04 slice: the NAT model, the deterministic 5×5
//! path plan (direct, hole punch, TCP/443 fallback, relay required), and the
//! bounded punch attempt over an injectable seam (MESH-04, MESH-10). A pair with
//! no usable mapping fails with the rendezvous explanation, and the module
//! opens no socket.
//!
//! [`snapshot`] is the T-TEL-01 slice: the signed teleport snapshot (session,
//! kernel, artifacts, goals, schedules, ledger, and workspace manifest as
//! caller-supplied opaque bytes) and the same-device restore under
//! `.zero/teleport/snap-<id>/` (TEL-01, TEL-03, TODO-07). `verify` is
//! re-exported as `verify_snapshot` because the crate root already exports the
//! identity `verify`.
//!
//! [`bundle`] is the T-TEL-02 slice: content-addressed, deduplicated chunks for
//! the workspace files, a manifest that reports every exclusion, a resumable
//! writer with an atomic checkpoint (an interrupted bundle resumes), and a
//! reader that verifies every chunk before materializing files with modes and
//! recorded symlinks (TEL-02, TEL-04, TEL-05). `manifest_hash` is re-exported as
//! `bundle_manifest_hash` because `snapshot` already exports `manifest_hash`.
//! [`bundle::verify_bundle`] is the in-memory verification the transfer uses.
//!
//! [`transfer`] is the T-TEL-03 slice: X25519 key agreement, an HKDF-SHA256
//! per-bundle key, ChaCha20-Poly1305 over the manifest and every unique chunk
//! with nonce and AAD binding, verification before any materialization, and the
//! retain-until-verified policy (TEL-03, TEL-06, TEL-09). The sealed envelope
//! carries no key and no plaintext, so a relay only ever moves ciphertext.
//!
//! [`restore`](crate::restore) is the T-TEL-04 slice: a plan built from a
//! verified bundle plus components, a full preflight of every path, and a
//! conflict-safe apply that stages different content under
//! `.zero/restore-staging/<bundle_id>/` instead of overwriting it (TEL-04,
//! TEL-07, TEL-08). Identical paths are skipped, a type change is never
//! performed, recorded symlinks stay inside the root, and reviewed conflicts
//! are adopted one at a time. Components are written atomically under
//! `.zero/teleport/<bundle_id>/components/`. The module's `restore` function is
//! re-exported as `restore_bundle` because the crate root already exports the
//! snapshot `restore`.
//!
//! [`fence`] is the T-TEL-05 slice: a fenced write lease with one holder, a
//! monotonic generation, handoff through compare-and-set, renewal by the current
//! lease, holder-checked release, and a generation-aware resume cursor (TEL-10,
//! TEL-11, FS-10).
//! A stale holder's write is refused, an older cursor forces a snapshot instead
//! of replaying events across the fence, and a plan never starts at a sequence
//! the client already applied. `assert_can_write` is the gate for the restore
//! and transfer paths to call.
//!
//! [`portability`] is the T-TEL-06 slice: path remapping from a source root to a
//! target root (Windows drive/UNC to POSIX and back), text remapping that
//! touches only path-like tokens, snapshot remapping that re-signs the changed
//! components with the target device key, a target-appropriate kernel rebuild
//! plan, and a tool preflight with per-tool guidance (TEL-01, TEL-12, TEL-13,
//! TEL-14). A no-git directory never requires git.
//!
//! [`vault_transfer`] is the T-TEL-07 slice: opaque vault bytes sealed into a
//! passphrase-bound Argon2id + AES-256-GCM [`VaultEnvelope`](vault_transfer::VaultEnvelope),
//! one-unlock-per-transfer tracking, approval or passphrase unlock that fails
//! with a prompt when no valid secret is present, and transfer wrapping that
//! moves only the envelope ciphertext (TEL-07, SEC-11, TEL-05). The relay never
//! sees the vault plaintext or the passphrase.
//!
//! [`trip_matrix`] is the T-TEL-08 slice: the teleport failure matrix. Four
//! fixtures exercise the real modules — an interrupted bundle resumed from its
//! checkpoint and restored byte-identically, an unreachable source refused
//! through an injected availability seam while the local snapshot stays valid,
//! a forced lease takeover that fences the stale holder out of writes and
//! restores, and a return trip that remaps and re-signs A→B→A and refuses the
//! first leg's generation (TEL-08, TEL-10, TEL-13, TEL-14). No socket is
//! opened, and [`trip_matrix::assert_all_four`] is the typed four-fixture gate.
//!
//! [`transport`] is the T-MESH-07 slice: the datagram carrier seam, a
//! fragment/ack/reassembly layer for one session stream, and an in-memory
//! lossy/reordering harness (MESH-01, MESH-04, MESH-05). [`transport::move_stream`]
//! proves a representative session JSONL stream crosses a bad datagram path
//! byte-identically. No socket is opened; a WireGuard-style userspace overlay
//! supplies [`transport::DatagramIo`], and
//! `docs/decisions/0002-mesh-transport.md` records the decision.
//!
//! Membership state is local and serialisable. There is no socket transport
//! here; signed replication is a pure function over snapshots. The mDNS socket
//! transport, the UDP/TCP traversal carriers, and the real overlay carrier
//! remain later tasks; [`transport`] is the in-process prototype they will feed,
//! and portability supplies the target-side values they will carry.

pub mod bundle;
pub mod discovery;
pub mod fence;
pub mod identity;
pub mod join_ux;
pub mod partition;
pub mod portability;
pub mod presence;
pub mod relay;
pub mod restore;
pub mod snapshot;
pub mod state;
pub mod transfer;
pub mod transport;
pub mod traversal;
pub mod trip_matrix;
pub mod vault_transfer;

pub use bundle::{
    build, build_files, manifest_hash as bundle_manifest_hash, verify_bundle, Bundle,
    BundleCheckpoint, BundleFile, BundleManifest, BundleReader, BundleStats, BundleWriter,
    ChunkConfig, ChunkRef, Excluded, FileEntry, MaterializeOptions, Materialized, VerifyReport,
    WriteReport, BUNDLE_ID_DOMAIN, BUNDLE_ID_HEX, BUNDLE_MANIFEST_DOMAIN, BUNDLE_MANIFEST_FILE,
    BUNDLE_SCHEMA_VERSION, CHECKPOINT_FILE, CHUNK_PARTIAL_SUFFIX, DEFAULT_CHUNK_BYTES,
    DEFAULT_MAX_CHUNKS, MAX_BUNDLE_BYTES, MAX_BUNDLE_MANIFEST_BYTES, MAX_CHUNK_BYTES,
    MAX_EXCLUDED_REASON_BYTES, MAX_FILES, MAX_PATH_BYTES, MAX_TOTAL_CHUNKS,
};

pub use discovery::{
    accept, canonical_announce_bytes, decode_announce, encode_announce, new_nonce, peers, remove,
    sign_announce, sweep, verify_announce, AcceptOutcome, Discovery, DiscoveryPolicy, MdnsRecord,
    PeerAnnounce, PeerRecord, Presence as PeerPresence, ANNOUNCE_DOMAIN, DEFAULT_OFFLINE_AFTER_MS,
    MAX_ANNOUNCE_ADDRS, MAX_ANNOUNCE_BYTES, MAX_ANNOUNCE_TTL_MS, MAX_MDNS_BYTES, MAX_NONCE_BYTES,
    MAX_TXT_FIELDS, MAX_TXT_VALUE_BYTES, MIN_NONCE_BYTES, SERVICE,
};
pub use fence::{
    assert_can_write, fence, handoff, handoff_if, release, renew, resume, HolderId, Lease,
    LeaseGeneration, ResumeCursor, ResumePlan, DEFAULT_LEASE_TTL_MS, MAX_HOLDER_BYTES,
    MAX_LEASE_TTL_MS, MAX_RESOURCE_BYTES,
};
pub use identity::{
    apply_rotation, approve, can_join, consume, device_id_for, is_member, issue_token, join,
    parse_join_payload, revoke, rotate, sign_rotation, verify, verify_token, DeviceKey,
    DeviceRecord, JoinPayload, JoinToken, KeyPair, Membership, PendingJoin, RotationRequest,
    DEFAULT_TOKEN_TTL_MS, JOIN_PAYLOAD_PREFIX, MAX_TOKEN_TTL_MS, PUBLIC_KEY_BYTES, SIGNATURE_BYTES,
    TOKEN_ID_BYTES, TOKEN_SECRET_BYTES,
};
pub use join_ux::{
    approve_pending, join_with_payload, join_with_short_code, one_action_offer, JoinOffer,
    JoinTimeline, DEFAULT_OFFER_TTL_MS, JOIN_TARGET_MS,
};
pub use presence::{
    relay_candidates, should_relay, should_sync, CostPolicy, Decision, LinkKind, PowerState,
    Presence, PresenceState, PresenceTable, PublicPresence,
};
pub use partition::{
    accept_update, can_write, check_quorum, drop_revoked, ensure_not_revoked, propagate,
    sign_revocation_set, sign_vote, update_hash, verify_revocation_set, DelegateSet, DelegateVote,
    Decision as PartitionDecision, PartitionView, QuorumDecision, RevocationSet, Revoked,
    MAX_DELEGATES, MAX_REVOCATION_IDS, REVOCATION_SET_DOMAIN, VOTE_DOMAIN,
};
pub use portability::{
    can_run, install_guidance, plan_kernel_rebuild, preflight, remap_path, remap_snapshot,
    remap_snapshot_report, remap_text, working_directory_notice, KernelRebuildPlan, PathMap,
    PreflightReport, RemapReport, SnapshotRemap, TextRemap, ToolPreflight, ToolProbe, ToolSet,
    KERNEL_PACKAGES, MAX_KERNEL_PACKAGES, MAX_PACKAGE_NAME_BYTES, MAX_PATH_MAPS, MAX_PYTHON_BYTES,
    MAX_REMAP_OUTPUT_BYTES, MAX_REMAP_PATH_BYTES, MAX_REMAP_TEXT_BYTES, MAX_REMAP_TOKENS,
    REMAPPABLE_COMPONENTS,
};
pub use relay::{
    open, relay_chain, seal, seal_with_aad, Endpoint, Forwarded, RelayClock, RelayEnvelope,
    RelayNode, RelayPolicy, Sealed, DEFAULT_MAX_BYTES, DEFAULT_MAX_TTL_MS, ENVELOPE_ID_BYTES,
    KEY_BYTES, MAX_AAD_BYTES, MAX_CIPHERTEXT_BYTES, MAX_RELAY_NONCE_BYTES, MAX_TTL_MS,
    MIN_RELAY_NONCE_BYTES, NONCE_BYTES, TAG_BYTES,
};
pub use restore::{
    adopt, build_plan, restore as restore_bundle, RestoreEntry, RestoreKind, RestoreOptions,
    RestorePlan, RestoreReport, StagedConflict, CHILDREN_FILE, COMPONENTS_DIR, MAX_MODE_BITS,
    MAX_RESTORE_ENTRIES, RESTORE_STAGING_DIR,
};
pub use snapshot::{
    classify_component, create, create_excluding, inspect, is_secret_like, manifest_hash, restore,
    verify as verify_snapshot, Component, ComponentBlob, ComponentMeta, RestoredSnapshot, Snapshot,
    SnapshotManifest, SnapshotSummary, MANIFEST_DOMAIN, MANIFEST_FILE, MAX_COMPONENT_BYTES,
    MAX_EXCLUDED, MAX_EXCLUDED_BYTES, MAX_MANIFEST_BYTES, MAX_PROJECT_ID_BYTES, MAX_SNAPSHOT_BYTES,
    SCHEMA_VERSION, SNAPSHOT_ID_DOMAIN, SNAPSHOT_ID_HEX, TELEPORT_DIR,
};
pub use state::{
    apply, canonical_bytes, sign_state, sign_update, verify_state, ApplyOutcome, MembershipState,
    StateUpdate, MAX_DEVICES, MAX_NAMES, MAX_NAME_BYTES, MAX_REVOKED, MAX_STATE_BYTES,
    STATE_DOMAIN, UPDATE_DOMAIN,
};
pub use transfer::{
    open_bundle, open_bundle_verified, retain_until_verified, retain_until_verified_with,
    seal_bundle, seal_bundle_with_seed, transfer_report, RecipientKey, RecipientSecret,
    RetentionOptions, RetentionReport, SealedBundle, SealedChunk, SenderSecret, TransferReport,
    VerifiedTransfer, AEAD_KEY_BYTES, AEAD_NONCE_BYTES, AEAD_TAG_BYTES, CHUNK_AAD_DOMAIN,
    CHUNK_NONCE_DOMAIN, MANIFEST_AAD_DOMAIN, MANIFEST_NONCE_DOMAIN, MAX_SEALED_CHUNKS,
    MAX_SEALED_MANIFEST_PLAINTEXT_BYTES, RECIPIENT_ID_DOMAIN, RECIPIENT_ID_HEX,
    TRANSFER_KEY_DOMAIN, TRANSFER_SCHEMA_VERSION, X25519_KEY_BYTES,
};
pub use transport::{
    move_stream, DatagramIo, PeerId, Reassembler, SessionStream, SimulatedNet, StreamConfig,
    StreamError, TransferStats, DEFAULT_BUFFERED, DEFAULT_FRAGMENTS, DEFAULT_FRAGMENT_BYTES,
    DEFAULT_RETRANSMITS, DEFAULT_ROUNDS, DEFAULT_STREAM_BYTES, DEFAULT_WINDOW, FRAME_MAGIC,
    HASH_BYTES, MAX_BUFFERED, MAX_FRAGMENTS, MAX_FRAGMENT_BYTES, MAX_PEER_BYTES,
    MAX_RETRANSMITS, MAX_ROUNDS, MAX_STREAM_BYTES, MAX_WINDOW, PROTOCOL_VERSION,
};
pub use traversal::{
    attempt, plan, Connected, Endpoint as TraversalEndpoint, Failure, HolePuncher, NatKind, Path,
    PunchAttempt, PunchOutcome, StunProbe, TraversalConfig, TraversalPlan,
    MAX_HOLE_PUNCH_ATTEMPTS, MAX_STUN_SERVERS, MAX_TIMEOUT_MS, RENDEZVOUS_REQUIRED,
    TCP_FALLBACK_PORT,
};
pub use trip_matrix::{
    assert_all_four, run_matrix, run_trip, Direction, Fixture, FixtureRun, ScriptedSource,
    SourceAvailability, SourceProbe, Trip, TripMatrixError, TripMatrixReport, TripOutcome,
    TripRequest, TRIP_MATRIX_DIR,
};
pub use vault_transfer::{
    issue_approval, receive, seal_vault, seal_vault_with_kdf, unlock_vault, unwrap_envelope,
    vault_transfer_report, wrap_for_transfer, KdfOptions, KdfParams, SealedVault,
    TransferApproval, UnlockRequest, UnlockState, UnlockedVault, VaultEnvelope,
    VaultTransferReport, DEFAULT_M_COST, DEFAULT_P_COST, DEFAULT_T_COST, MAX_APPROVAL_ID_BYTES,
    MAX_APPROVAL_TTL_MS, MAX_VAULT_BYTES, VAULT_AAD_DOMAIN, VAULT_ENVELOPE_FILE,
    VAULT_ENVELOPE_ID_DOMAIN, VAULT_KEY_BYTES, VAULT_NONCE_BYTES, VAULT_SALT_BYTES,
    VAULT_SCHEMA_VERSION, VAULT_TAG_BYTES,
};
