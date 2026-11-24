//! Opaque identifiers, monotonic sequences, injectable clocks, and deterministic
//! seeds (FND-08).
//!
//! Nothing in the core compares wall-clock values to order events. Ordering is
//! by [`Seq`], and every generator is injectable so schedules, locks, and leases
//! can be simulated.

use serde::{Deserialize, Serialize};
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// An opaque, stable 128-bit identifier rendered as 32 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct OpaqueId([u8; 16]);

impl OpaqueId {
    pub fn from_bytes(bytes: [u8; 16]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 16] {
        &self.0
    }

    pub fn to_hex(self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn parse(s: &str) -> Result<Self, crate::error::ZeroError> {
        if s.len() != 32 {
            return Err(crate::error::ZeroError::new(
                crate::error::ErrorCode::InvalidInput,
                format!("id `{s}` must be 32 hex characters"),
            ));
        }
        let mut out = [0u8; 16];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).map_err(|_| {
                crate::error::ZeroError::new(crate::error::ErrorCode::InvalidInput, "id is not ASCII")
            })?;
            out[i] = u8::from_str_radix(pair, 16).map_err(|_| {
                crate::error::ZeroError::new(
                    crate::error::ErrorCode::InvalidInput,
                    format!("id `{s}` is not hex"),
                )
            })?;
        }
        Ok(Self(out))
    }
}

impl fmt::Display for OpaqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.to_hex())
    }
}

impl fmt::Debug for OpaqueId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "id:{}", self.to_hex())
    }
}

/// Monotonic per-stream sequence number. Never derived from a clock.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Seq(u64);

impl Seq {
    pub const ZERO: Seq = Seq(0);

    pub fn new(v: u64) -> Self {
        Seq(v)
    }

    pub fn get(self) -> u64 {
        self.0
    }

    pub fn next(self) -> Self {
        Seq(self.0.saturating_add(1))
    }
}

impl fmt::Display for Seq {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Thread-safe monotonic sequence source.
#[derive(Debug, Default)]
pub struct SeqGen {
    next: Arc<AtomicU64>,
}

impl SeqGen {
    pub fn starting_at(v: u64) -> Self {
        Self { next: Arc::new(AtomicU64::new(v)) }
    }

    pub fn next(&self) -> Seq {
        Seq(self.next.fetch_add(1, Ordering::SeqCst))
    }

    pub fn peek(&self) -> Seq {
        Seq(self.next.load(Ordering::SeqCst))
    }
}

/// Milliseconds since the Unix epoch. Compared for display only; ordering uses
/// [`Seq`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Timestamp(pub i64);

impl Timestamp {
    pub fn from_millis(ms: i64) -> Self {
        Timestamp(ms)
    }

    pub fn millis(self) -> i64 {
        self.0
    }

    /// Compact UTC rendering without a calendar dependency.
    pub fn as_iso8601(self) -> String {
        let secs = self.0.div_euclid(1000);
        let ms = self.0.rem_euclid(1000);
        let days = secs.div_euclid(86_400);
        let rem = secs.rem_euclid(86_400);
        let (y, m, d) = civil_from_days(days);
        format!(
            "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}.{ms:03}Z",
            rem / 3600,
            (rem % 3600) / 60,
            rem % 60
        )
    }

    /// `YYYYMMDD-HHMMSS` for auto-naming.
    pub fn as_stamp(self) -> String {
        let iso = self.as_iso8601();
        let date = format!("{}{}{}", &iso[0..4], &iso[5..7], &iso[8..10]);
        format!("{}-{}{}{}", date, &iso[11..13], &iso[14..16], &iso[17..19])
    }
}

/// Howard Hinnant's civil-from-days algorithm.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

/// Injected clock.
pub trait Clock: Send + Sync {
    fn now(&self) -> Timestamp;
    /// Monotonic nanoseconds, for latency measurement only.
    fn monotonic_nanos(&self) -> u64;
}

#[derive(Debug, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now(&self) -> Timestamp {
        let ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_millis() as i64)
            .unwrap_or(0);
        Timestamp(ms)
    }

    fn monotonic_nanos(&self) -> u64 {
        // Wall-clock based is adequate for latency display; ordering never uses it.
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos() as u64)
            .unwrap_or(0)
    }
}

/// A clock the test or simulator controls. Advance is the only way time moves.
#[derive(Debug, Clone)]
pub struct FakeClock {
    millis: Arc<AtomicU64>,
}

impl FakeClock {
    pub fn at(millis: i64) -> Self {
        Self { millis: Arc::new(AtomicU64::new(millis.max(0) as u64)) }
    }

    pub fn advance(&self, millis: u64) {
        self.millis.fetch_add(millis, Ordering::SeqCst);
    }

    pub fn set(&self, millis: i64) {
        self.millis.store(millis.max(0) as u64, Ordering::SeqCst);
    }
}

impl Clock for FakeClock {
    fn now(&self) -> Timestamp {
        Timestamp(self.millis.load(Ordering::SeqCst) as i64)
    }

    fn monotonic_nanos(&self) -> u64 {
        self.millis.load(Ordering::SeqCst) * 1_000_000
    }
}

/// Deterministic, seedable random source (SplitMix64). No OS entropy.
#[derive(Debug, Clone)]
pub struct DeterministicRng {
    state: u64,
}

impl DeterministicRng {
    pub fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    pub fn below(&mut self, n: u32) -> u32 {
        if n == 0 {
            0
        } else {
            self.next_u32() % n
        }
    }

    pub fn next_id(&mut self) -> OpaqueId {
        let hi = self.next_u64();
        let lo = self.next_u64();
        let mut bytes = [0u8; 16];
        bytes[..8].copy_from_slice(&hi.to_be_bytes());
        bytes[8..].copy_from_slice(&lo.to_be_bytes());
        OpaqueId(bytes)
    }
}

/// Injected id generator. Seeded generators reproduce identical ids across runs.
#[derive(Debug, Clone)]
pub struct IdGen {
    rng: DeterministicRng,
}

impl Default for IdGen {
    fn default() -> Self {
        Self::new(0)
    }
}

impl IdGen {
    pub fn new(seed: u64) -> Self {
        Self { rng: DeterministicRng::new(seed) }
    }

    pub fn new_id(&mut self) -> OpaqueId {
        self.rng.next_id()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sim::Simulation;

    #[test]
    fn ids_round_trip_and_reject_bad_input() {
        let mut gen = IdGen::new(7);
        let id = gen.new_id();
        assert_eq!(id.to_hex().len(), 32);
        assert_eq!(OpaqueId::parse(&id.to_hex()).unwrap(), id);
        assert!(OpaqueId::parse("abc").is_err());
        assert!(OpaqueId::parse(&"z".repeat(32)).is_err());
    }

    #[test]
    fn same_seed_reproduces_identical_event_order() {
        let run = |seed: u64| {
            let clock = FakeClock::at(1_700_000_000_000);
            let mut sim = Simulation::new(seed, clock);
            let mut ids = IdGen::new(seed);
            for _ in 0..1000 {
                let id = ids.new_id();
                sim.schedule(id.to_hex(), |trace, tick| {
                    trace.push(format!("{tick}:set"));
                });
                sim.schedule(id.to_hex(), |trace, tick| {
                    trace.push(format!("{tick}:clear"));
                });
            }
            sim.run_all();
            sim.trace().join("\n")
        };
        assert_eq!(run(42), run(42));
        assert_ne!(run(42), run(43));
    }

    #[test]
    fn sequences_are_monotonic() {
        let seq = SeqGen::default();
        let a = seq.next();
        let b = seq.next();
        assert!(a < b);
        assert_eq!(Seq::ZERO.next(), Seq::new(1));
    }

    #[test]
    fn timestamps_render_without_a_calendar_dependency() {
        assert_eq!(Timestamp::from_millis(0).as_iso8601(), "1970-01-01T00:00:00.000Z");
        assert_eq!(Timestamp::from_millis(1_700_000_000_000).as_iso8601(), "2023-11-14T22:13:20.000Z");
        assert_eq!(Timestamp::from_millis(1_700_000_000_000).as_stamp(), "20231114-221320");
    }
}

