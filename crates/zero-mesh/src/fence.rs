//! Fenced write leases and generation-aware resume (T-TEL-05, TEL-10, TEL-11,
//! FS-10).
//!
//! A [`Lease`] names one resource (for teleport, a session journal or workspace
//! path), exactly one holder, and a [`LeaseGeneration`]. The generation is the
//! fencing token: a write must present the generation of the **current** lease,
//! and [`fence`] / [`assert_can_write`] refuse a stale holder with
//! `zero.ses.lease_held`. The T-TEL-05 done criterion is
//! `a_stale_holder_cannot_write_after_handoff`: after the target takes the
//! lease, the source's generation no longer matches and its write is refused.
//!
//! [`handoff`] advances the generation exactly once and moves the holder. The
//! compare-and-set form, [`handoff_if`], takes the generation the caller
//! observed and returns [`ErrorCode::Conflict`] when the stored lease has moved
//! on, which is how two concurrent handoffs from one generation produce one
//! winner and one loser. An expired lease may still be handed off (expiry frees
//! the resource, and a forced takeover must be able to advance the generation),
//! but it cannot be renewed.
//!
//! [`ResumeCursor`] is the client's `{ generation, sequence }` position.
//! [`resume`] returns a [`ResumePlan`]: a cursor from the current generation
//! continues after its sequence, while a cursor from an older generation forces
//! a snapshot because events must never cross a fence. A plan never starts at or
//! before a sequence the client already applied, so a resumed turn does not
//! replay effects.
//!
//! This module is a value model, not a daemon. It holds no lock: the store that
//! owns the current lease must pass that value and commit the winner of a
//! handoff. Expiry takes a caller-supplied clock (`now_ms`), so cross-device
//! ordering is provided by the generation, never by comparing wall clocks. See
//! `docs/teleport.md` for the limitations.

use std::fmt;

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

/// Longest accepted holder id, in bytes.
pub const MAX_HOLDER_BYTES: usize = 128;

/// Longest accepted resource name, in bytes.
pub const MAX_RESOURCE_BYTES: usize = 512;

/// Longest accepted lease TTL: 24 hours.
pub const MAX_LEASE_TTL_MS: i64 = 24 * 60 * 60 * 1000;

/// Default lease TTL used by callers that have no explicit policy.
pub const DEFAULT_LEASE_TTL_MS: i64 = 30_000;

/// The identity of a lease holder.
///
/// A holder is an opaque, non-empty label (for teleport, a device id or the
/// endpoint's session id). It is a value, not a key: authority comes from
/// holding the current [`Lease`] and its generation, so a copied label cannot
/// write.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HolderId(String);

impl HolderId {
    /// Validate and construct a holder id.
    ///
    /// Non-empty, at most [`MAX_HOLDER_BYTES`], no surrounding whitespace, and
    /// no control characters.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        validate_holder(&value)?;
        Ok(Self(value))
    }

    /// The holder label.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for HolderId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// A fencing-token counter.
///
/// The first lease on a resource is generation 1, and every successful handoff
/// increments it by one. Generation zero is reserved for "no lease yet" and is
/// never a valid [`Lease`] generation; a [`ResumeCursor`] may carry zero to mean
/// "a client that has never attached" and is then treated as older than any
/// lease.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct LeaseGeneration(u64);

impl LeaseGeneration {
    /// The generation of the first lease on a resource.
    pub const FIRST: Self = Self(1);

    /// Wrap a raw counter. Callers should use [`Self::FIRST`] or a handoff.
    pub const fn new(value: u64) -> Self {
        Self(value)
    }

    /// The raw counter.
    pub const fn get(self) -> u64 {
        self.0
    }

    /// True for the reserved "no lease yet" value.
    pub const fn is_zero(self) -> bool {
        self.0 == 0
    }

    /// The next generation, refusing to wrap.
    pub fn next(self) -> Result<Self> {
        self.0
            .checked_add(1)
            .map(Self)
            .ok_or_else(|| limit("lease generation counter is exhausted"))
    }
}

impl fmt::Display for LeaseGeneration {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// A time-bounded, generation-fenced write lease on one resource.
///
/// `acquired_ms` and `expires_ms` are caller-clock milliseconds. Expiry is a
/// local convenience and a stale-holder gate; the generation, not the clock,
/// orders holders across devices. A lease is valid for `now_ms < expires_ms`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Lease {
    /// The leased resource (a session journal, workspace path, or opaque id).
    pub resource: String,
    /// The one holder allowed to write.
    pub holder: HolderId,
    /// The fencing token. A write must present this exact value.
    pub generation: LeaseGeneration,
    /// When the current holder acquired the lease.
    pub acquired_ms: i64,
    /// When the lease expires; `now_ms >= expires_ms` is expired.
    pub expires_ms: i64,
}

impl Lease {
    /// Create generation 1 on `resource` for `holder`.
    ///
    /// `ttl_ms` must be positive and at most [`MAX_LEASE_TTL_MS`], and
    /// `now_ms + ttl_ms` must not overflow.
    pub fn new(
        resource: impl Into<String>,
        holder: HolderId,
        now_ms: i64,
        ttl_ms: i64,
    ) -> Result<Self> {
        let resource = resource.into();
        validate_resource(&resource)?;
        let lease = Self {
            resource,
            holder,
            generation: LeaseGeneration::FIRST,
            acquired_ms: now_ms,
            expires_ms: expiry(now_ms, ttl_ms)?,
        };
        lease.validate()?;
        Ok(lease)
    }

    /// Validate every field, including a non-zero generation and a coherent
    /// acquisition/expiry pair.
    pub fn validate(&self) -> Result<()> {
        validate_resource(&self.resource)?;
        validate_holder(self.holder.as_str())?;
        if self.generation.is_zero() {
            return Err(invalid("a lease generation must be 1 or greater"));
        }
        if self.expires_ms <= self.acquired_ms {
            return Err(invalid(
                "a lease expiry must be later than its acquisition time",
            ));
        }
        Ok(())
    }

    /// Reject a lease that has expired at `now_ms`.
    ///
    /// Expiry is inclusive: `now_ms == expires_ms` is already expired. This
    /// checks the lease's shape as well, so a malformed deserialised lease is
    /// refused with `zero.fnd.invalid_input` rather than trusted.
    pub fn verify(&self, now_ms: i64) -> Result<()> {
        self.validate()?;
        if now_ms >= self.expires_ms {
            return Err(leased(format!(
                "lease on `{}` expired at {} ms (now {} ms)",
                self.resource, self.expires_ms, now_ms
            )));
        }
        Ok(())
    }

    /// True when the lease is expired at `now_ms` (without validating its
    /// shape; use [`Self::verify`] for a checked gate).
    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_ms
    }
}

/// Refuse a write that does not present the current generation.
///
/// `current` must be the authoritative lease from the store. A stale holder
/// (an older generation), a future generation, or generation zero is
/// `zero.ses.lease_held`. This function does not check expiry because it has no
/// clock; use [`assert_can_write`] for the complete gate.
pub fn fence(current: &Lease, observed_generation: LeaseGeneration) -> Result<()> {
    current.validate()?;
    if observed_generation != current.generation {
        return Err(leased(format!(
            "lease on `{}` is at generation {}; a write presenting generation {} is stale",
            current.resource, current.generation, observed_generation
        )));
    }
    Ok(())
}

/// Move the lease to `new_holder` and advance the generation by one.
///
/// The source's generation is stale afterwards, so any later write it presents
/// is refused by [`fence`] / [`assert_can_write`]. An expired current lease may
/// be handed off: expiry frees the resource and a forced takeover must still
/// advance the generation.
pub fn handoff(current: &Lease, new_holder: HolderId, now_ms: i64, ttl_ms: i64) -> Result<Lease> {
    handoff_if(current, current.generation, new_holder, now_ms, ttl_ms)
}

/// Compare-and-set handoff: succeed only if `current` is still at
/// `expected_generation`.
///
/// This is the concurrency model. Two contenders read the same lease and both
/// call `handoff_if` with that generation; the store commits the winner, and
/// the loser's call against the committed lease returns [`ErrorCode::Conflict`]
/// because the generation has moved. Only one generation bump survives.
pub fn handoff_if(
    current: &Lease,
    expected_generation: LeaseGeneration,
    new_holder: HolderId,
    now_ms: i64,
    ttl_ms: i64,
) -> Result<Lease> {
    current.validate()?;
    validate_holder(new_holder.as_str())?;
    if current.generation != expected_generation {
        return Err(conflict(format!(
            "handoff lost the compare-and-set on `{}`: expected generation {}, current generation {}",
            current.resource, expected_generation, current.generation
        )));
    }
    let generation = current.generation.next()?;
    let lease = Lease {
        resource: current.resource.clone(),
        holder: new_holder,
        generation,
        acquired_ms: now_ms,
        expires_ms: expiry(now_ms, ttl_ms)?,
    };
    lease.validate()?;
    Ok(lease)
}

/// Extend a live lease without changing its holder or generation.
///
/// A holder proves possession by presenting the current lease. An expired
/// lease, or one whose shape is invalid, cannot be renewed
/// (`zero.ses.lease_held` / `zero.fnd.invalid_input`). Renewing a superseded
/// copy extends only that stale value; writes are still refused against the
/// authoritative lease because the generation has moved.
pub fn renew(lease: &Lease, now_ms: i64, ttl_ms: i64) -> Result<Lease> {
    lease.verify(now_ms)?;
    let renewed = Lease {
        expires_ms: expiry(now_ms, ttl_ms)?,
        ..lease.clone()
    };
    renewed.validate()?;
    Ok(renewed)
}

/// Release the resource, retaining the generation for the handoff history.
///
/// Only the holder named by `lease` may release. The returned generation is the
/// generation that was released; a following acquisition starts at the next
/// generation via [`handoff`], never by reusing this one. `lease` must be the
/// store's current lease, so a superseded holder fails the holder check.
pub fn release(lease: &Lease, holder: &HolderId) -> Result<LeaseGeneration> {
    lease.validate()?;
    if lease.holder != *holder {
        return Err(denied(format!(
            "holder `{holder}` does not hold the lease on `{}` (held by `{}`)",
            lease.resource, lease.holder
        )));
    }
    Ok(lease.generation)
}

/// A client's replay position: the lease generation it last saw and the last
/// journal sequence it applied.
///
/// `sequence` is the last applied sequence (zero means "nothing applied").
/// `generation` zero means "never attached; take a snapshot".
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumeCursor {
    /// The generation the client last attached to.
    pub generation: LeaseGeneration,
    /// The last journal sequence the client applied.
    pub sequence: u64,
}

/// What a resume should do next.
///
/// `from_seq` is the first journal sequence to deliver (inclusive), so it is
/// always one past the point the client already applied. When `snapshot` is
/// true, no journal event is replayed: the client adopts a snapshot that
/// replaces its effect state, and `from_seq` starts after the journal head.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResumePlan {
    /// The current lease generation the client must adopt.
    pub generation: LeaseGeneration,
    /// First journal sequence to deliver, inclusive.
    pub from_seq: u64,
    /// True when the client must take a snapshot instead of replaying events.
    pub snapshot: bool,
}

impl ResumePlan {
    /// True when this plan requires a snapshot.
    pub const fn is_snapshot(&self) -> bool {
        self.snapshot
    }

    /// True when delivering `from_seq` as an event would replay an effect the
    /// client already applied. A snapshot replaces state, so it is never a
    /// replay.
    pub const fn replays_effect(&self, applied_sequence: u64) -> bool {
        !self.snapshot && self.from_seq <= applied_sequence
    }
}

/// Plan a resume from `cursor` against the journal head `journal_seq`.
///
/// - A cursor from the current generation continues at `sequence + 1`; a cursor
///   at the journal head yields `from_seq = journal_seq + 1` (no events yet).
/// - A cursor from an older generation (including generation zero) forces
///   `snapshot = true`: events from before the fence are never replayed.
/// - A cursor from a future generation is `zero.pol.denied`; a current-generation
///   cursor ahead of the journal is `zero.fnd.invalid_input` rather than being
///   clamped.
///
/// `lease` must be the current lease from the store. The plan never starts at or
/// before a sequence the cursor already applied, so a resumed turn does not
/// replay effects.
pub fn resume(lease: &Lease, cursor: &ResumeCursor, journal_seq: u64) -> Result<ResumePlan> {
    lease.validate()?;
    if cursor.generation > lease.generation {
        return Err(denied(format!(
            "resume cursor is from future generation {}; the current lease is generation {}",
            cursor.generation, lease.generation
        )));
    }

    let (snapshot, start) = if cursor.generation < lease.generation {
        (true, journal_seq)
    } else {
        if cursor.sequence > journal_seq {
            return Err(invalid(format!(
                "resume cursor is at sequence {} but the journal head is {journal_seq}",
                cursor.sequence
            )));
        }
        (false, cursor.sequence)
    };

    let from_seq = start
        .checked_add(1)
        .ok_or_else(|| limit("journal sequence counter is exhausted"))?;
    let plan = ResumePlan {
        generation: lease.generation,
        from_seq,
        snapshot,
    };
    if plan.replays_effect(cursor.sequence) {
        return Err(internal(
            "resume plan would replay an already applied effect",
        ));
    }
    Ok(plan)
}

/// The complete write gate used by restore and transfer paths.
///
/// Refuses an expired lease and a write that presents anything but the current
/// generation (`zero.ses.lease_held`). A caller that has been fenced off by a
/// handoff therefore cannot write through this path.
pub fn assert_can_write(lease: &Lease, generation: LeaseGeneration, now_ms: i64) -> Result<()> {
    lease.verify(now_ms)?;
    if generation != lease.generation {
        return Err(leased(format!(
            "write refused: lease on `{}` is at generation {}, not the presented generation {}",
            lease.resource, lease.generation, generation
        )));
    }
    Ok(())
}

fn validate_holder(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid("a lease holder must not be empty"));
    }
    if value.len() > MAX_HOLDER_BYTES {
        return Err(limit(format!(
            "lease holder is {} bytes; the limit is {MAX_HOLDER_BYTES}",
            value.len()
        )));
    }
    if value.trim() != value {
        return Err(invalid(
            "a lease holder must not start or end with whitespace",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(
            "a lease holder must not contain control characters",
        ));
    }
    Ok(())
}

fn validate_resource(value: &str) -> Result<()> {
    if value.is_empty() {
        return Err(invalid("a lease resource must not be empty"));
    }
    if value.len() > MAX_RESOURCE_BYTES {
        return Err(limit(format!(
            "lease resource is {} bytes; the limit is {MAX_RESOURCE_BYTES}",
            value.len()
        )));
    }
    if value.chars().any(char::is_control) {
        return Err(invalid(
            "a lease resource must not contain control characters",
        ));
    }
    Ok(())
}

fn expiry(now_ms: i64, ttl_ms: i64) -> Result<i64> {
    if ttl_ms <= 0 {
        return Err(invalid("a lease TTL must be positive"));
    }
    if ttl_ms > MAX_LEASE_TTL_MS {
        return Err(limit(format!(
            "lease TTL is {ttl_ms} ms; the limit is {MAX_LEASE_TTL_MS} ms"
        )));
    }
    now_ms
        .checked_add(ttl_ms)
        .ok_or_else(|| invalid("lease expiry overflows the clock"))
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn leased(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::SessionLeaseHeld, message)
}

fn conflict(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Conflict, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

type Result<T, E = ZeroError> = std::result::Result<T, E>;

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 60_000;

    fn holder(name: &str) -> HolderId {
        HolderId::new(name).expect("holder")
    }

    fn lease(owner: &str) -> Lease {
        Lease::new("/sessions/a.jsonl", holder(owner), NOW, TTL).expect("lease")
    }

    #[test]
    fn a_stale_holder_cannot_write_after_handoff() {
        let source = lease("laptop");
        assert_eq!(source.generation, LeaseGeneration::FIRST);
        assert_can_write(&source, source.generation, NOW).expect("the holder may write");

        let target = handoff(&source, holder("desktop"), NOW + 1, TTL).expect("handoff");
        assert_eq!(target.generation.get(), 2);
        assert_eq!(target.holder.as_str(), "desktop");
        assert_eq!(target.acquired_ms, NOW + 1);
        assert_eq!(target.expires_ms, NOW + 1 + TTL);

        let error = assert_can_write(&target, source.generation, NOW + 2)
            .expect_err("the source's generation is stale");
        assert_eq!(error.code(), ErrorCode::SessionLeaseHeld);
        let error = fence(&target, source.generation).expect_err("the stale fence is refused");
        assert_eq!(error.code(), ErrorCode::SessionLeaseHeld);

        assert_can_write(&target, target.generation, NOW + 2).expect("the target may write");
        fence(&target, target.generation).expect("the current generation is accepted");
    }

    #[test]
    fn a_future_cursor_and_a_future_generation_write_are_refused() {
        let current = lease("laptop");
        let future = LeaseGeneration::new(current.generation.get() + 1);

        let cursor = ResumeCursor {
            generation: future,
            sequence: 1,
        };
        assert_eq!(
            resume(&current, &cursor, 10)
                .expect_err("a future cursor is not trusted")
                .code(),
            ErrorCode::PolicyDenied
        );
        assert_eq!(
            fence(&current, future)
                .expect_err("a future generation cannot write")
                .code(),
            ErrorCode::SessionLeaseHeld
        );
    }

    #[test]
    fn an_expired_lease_is_refused() {
        let current = lease("laptop");
        let expiry = current.expires_ms;

        current.verify(expiry - 1).expect("one ms before expiry");
        assert_eq!(
            current
                .verify(expiry)
                .expect_err("expiry is inclusive")
                .code(),
            ErrorCode::SessionLeaseHeld
        );
        assert_eq!(
            assert_can_write(&current, current.generation, expiry)
                .expect_err("an expired lease cannot write")
                .code(),
            ErrorCode::SessionLeaseHeld
        );
        assert_eq!(
            renew(&current, expiry, TTL)
                .expect_err("an expired lease cannot renew")
                .code(),
            ErrorCode::SessionLeaseHeld
        );
    }

    #[test]
    fn renew_preserves_the_holder_and_generation() {
        let current = lease("laptop");
        let renewed = renew(&current, NOW + 1_000, TTL).expect("renew");

        assert_eq!(renewed.resource, current.resource);
        assert_eq!(renewed.holder, current.holder);
        assert_eq!(renewed.generation, current.generation);
        assert_eq!(renewed.acquired_ms, current.acquired_ms);
        assert_eq!(renewed.expires_ms, NOW + 1_000 + TTL);
        assert!(renewed.expires_ms > current.expires_ms);

        // A superseded copy can only extend itself; it is still stale against
        // the authoritative lease, so it cannot write.
        let target = handoff(&current, holder("desktop"), NOW + 2, TTL).expect("handoff");
        let stale = renew(&current, NOW + 3, TTL).expect("the old value renews itself");
        assert_eq!(stale.generation, current.generation);
        assert_eq!(
            assert_can_write(&target, stale.generation, NOW + 4)
                .expect_err("a renewed stale lease is still fenced off")
                .code(),
            ErrorCode::SessionLeaseHeld
        );

        let renewed_target = renew(&target, NOW + 4, TTL).expect("the target renews");
        assert_eq!(renewed_target.holder.as_str(), "desktop");
        assert_eq!(renewed_target.generation, target.generation);
    }

    #[test]
    fn a_stale_holder_cannot_release_the_current_lease() {
        let source = lease("laptop");
        let target = handoff(&source, holder("desktop"), NOW + 1, TTL).expect("handoff");

        let error =
            release(&target, &source.holder).expect_err("the source no longer holds the resource");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);

        let generation = release(&target, &target.holder).expect("the holder releases");
        assert_eq!(generation, target.generation);
        assert_eq!(generation.get(), 2);
    }

    #[test]
    fn concurrent_handoffs_from_one_generation_have_one_winner() {
        let stored = lease("laptop");
        let observed = stored.generation;

        let winner = handoff_if(&stored, observed, holder("desktop"), NOW + 1, TTL)
            .expect("the first compare-and-set wins");
        assert_eq!(winner.generation.get(), observed.get() + 1);

        // The loser read the same generation, but the store now holds the
        // winner; the compare-and-set no longer matches.
        let error = handoff_if(&winner, observed, holder("tablet"), NOW + 1, TTL)
            .expect_err("the second compare-and-set loses");
        assert_eq!(error.code(), ErrorCode::Conflict);

        // Only the winner's generation can drive the next handoff.
        let next = handoff_if(&winner, winner.generation, holder("tablet"), NOW + 2, TTL)
            .expect("the next generation hands off");
        assert_eq!(next.generation.get(), winner.generation.get() + 1);
        assert_eq!(next.holder.as_str(), "tablet");
    }

    #[test]
    fn an_older_cursor_forces_a_snapshot() {
        let source = lease("laptop");
        let target = handoff(&source, holder("desktop"), NOW + 1, TTL).expect("handoff");

        let cursor = ResumeCursor {
            generation: source.generation,
            sequence: 7,
        };
        let plan = resume(&target, &cursor, 10).expect("resume");
        assert!(plan.snapshot);
        assert!(plan.is_snapshot());
        assert_eq!(plan.generation, target.generation);
        assert_eq!(plan.from_seq, 11);
        assert!(!plan.replays_effect(cursor.sequence));

        // A client that never attached has generation zero and also snapshots.
        let fresh = ResumeCursor {
            generation: LeaseGeneration::new(0),
            sequence: 0,
        };
        let plan = resume(&target, &fresh, 3).expect("fresh resume");
        assert!(plan.snapshot);
        assert_eq!(plan.from_seq, 4);
    }

    #[test]
    fn a_current_generation_cursor_resumes_events_after_it() {
        let current = lease("laptop");
        let cursor = ResumeCursor {
            generation: current.generation,
            sequence: 7,
        };
        let plan = resume(&current, &cursor, 10).expect("resume");
        assert!(!plan.snapshot);
        assert_eq!(plan.generation, current.generation);
        assert_eq!(plan.from_seq, 8);
        assert!(!plan.replays_effect(cursor.sequence));

        let caught_up = ResumeCursor {
            generation: current.generation,
            sequence: 10,
        };
        let plan = resume(&current, &caught_up, 10).expect("caught up");
        assert!(!plan.snapshot);
        assert_eq!(plan.from_seq, 11);
        assert!(!plan.replays_effect(caught_up.sequence));
    }

    #[test]
    fn resume_never_moves_the_sequence_backwards() {
        let current = lease("laptop");
        let journal_seq = 25;
        for applied in 0..=journal_seq {
            let cursor = ResumeCursor {
                generation: current.generation,
                sequence: applied,
            };
            let plan = resume(&current, &cursor, journal_seq).expect("resume");
            assert!(!plan.replays_effect(applied), "{plan:?}");
            assert_eq!(plan.from_seq, applied + 1);
            assert!(plan.from_seq > applied);
        }

        // A cursor ahead of the journal is corrupt, not silently clamped.
        let ahead = ResumeCursor {
            generation: current.generation,
            sequence: journal_seq + 1,
        };
        assert_eq!(
            resume(&current, &ahead, journal_seq)
                .expect_err("a cursor ahead of the journal is refused")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn effects_are_not_replayed_across_a_fence() {
        let source = lease("laptop");
        let target = handoff(&source, holder("desktop"), NOW + 1, TTL).expect("handoff");
        let cursor = ResumeCursor {
            generation: source.generation,
            sequence: 9,
        };

        let plan = resume(&target, &cursor, 12).expect("resume");
        assert!(plan.snapshot);
        assert!(!plan.replays_effect(cursor.sequence));
        // A snapshot replaces state; the event cursor restarts after the head.
        assert_eq!(plan.from_seq, 13);

        let after = ResumeCursor {
            generation: target.generation,
            sequence: 12,
        };
        let next = resume(&target, &after, 14).expect("the next event");
        assert!(!next.snapshot);
        assert_eq!(next.from_seq, 13);
        assert!(!next.replays_effect(after.sequence));
    }

    #[test]
    fn leases_cursors_and_plans_survive_serde() {
        let current = lease("laptop");
        let json = serde_json::to_string(&current).expect("lease json");
        let restored: Lease = serde_json::from_str(&json).expect("lease parse");
        assert_eq!(restored, current);
        assert_can_write(&restored, current.generation, NOW).expect("the restored lease writes");

        let cursor = ResumeCursor {
            generation: current.generation,
            sequence: 3,
        };
        let cursor_json = serde_json::to_string(&cursor).expect("cursor json");
        let restored_cursor: ResumeCursor =
            serde_json::from_str(&cursor_json).expect("cursor parse");
        assert_eq!(restored_cursor, cursor);

        let plan = resume(&restored, &restored_cursor, 9).expect("resume");
        let plan_json = serde_json::to_string(&plan).expect("plan json");
        let restored_plan: ResumePlan = serde_json::from_str(&plan_json).expect("plan parse");
        assert_eq!(restored_plan, plan);
        assert_eq!(restored_plan.from_seq, 4);
        assert!(!restored_plan.snapshot);
    }

    #[test]
    fn invalid_leases_and_bounds_are_typed() {
        assert_eq!(
            HolderId::new("")
                .expect_err("an empty holder is invalid")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            HolderId::new("a".repeat(MAX_HOLDER_BYTES + 1))
                .expect_err("an oversized holder is refused")
                .code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            Lease::new("", holder("laptop"), NOW, TTL)
                .expect_err("an empty resource is invalid")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            Lease::new("r", holder("laptop"), NOW, 0)
                .expect_err("a zero TTL is invalid")
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            Lease::new("r", holder("laptop"), NOW, MAX_LEASE_TTL_MS + 1)
                .expect_err("an oversized TTL is refused")
                .code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            Lease::new("r", holder("laptop"), i64::MAX, TTL)
                .expect_err("an overflowing expiry is refused")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut zero_generation = lease("laptop");
        zero_generation.generation = LeaseGeneration::new(0);
        assert_eq!(
            zero_generation
                .validate()
                .expect_err("generation zero is not a lease")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut exhausted = lease("laptop");
        exhausted.generation = LeaseGeneration::new(u64::MAX);
        assert_eq!(
            handoff(&exhausted, holder("desktop"), NOW + 1, TTL)
                .expect_err("the generation cannot wrap")
                .code(),
            ErrorCode::LimitExceeded
        );
    }
}
