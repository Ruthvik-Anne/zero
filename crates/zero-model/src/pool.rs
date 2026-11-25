//! Model pool registry and checked-in seed data (T-MDL-01; MDL-01).
//!
//! This module is the data half of routing. [`crate::router`] decides which
//! model to call; this module records what the candidates *are*: provider,
//! family, version, context and output limits, list prices, rate limits,
//! availability, and capability grades.
//!
//! The seed is a versioned JSON document ([`PoolSeed`]) checked in at
//! `crates/zero-model/data/models.json`. Every entry names a source id from the
//! document's `sources` list, and every source records the URL and the date it
//! was checked. [`PoolSeed::validate`] refuses a seed with a dangling source
//! reference, a duplicate model id, a blank provider or family, a non-positive
//! limit, or a malformed `checked_on` date, so the router never sees a row whose
//! provenance is missing.
//!
//! [`PoolSeed::to_pool`] converts the registry into the router's [`Pool`]. The
//! escalation tier is derived from the combined list rate with
//! [`tier_for_combined_rate`], so tier and price cannot disagree by accident.
//!
//! Prices are **list prices at the recorded check date**, not a bill. They drift
//! (promotions end, cache tiers change), which is why the seed carries a date
//! and why [`crate::freshness`] gates a snapshot before routing on it.

use crate::classify::ModelGrades;
use crate::router::{self, Pool, PoolModel};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::path::Path;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Schema version of the seed document understood by this build.
pub const SEED_SCHEMA_VERSION: u32 = 1;

/// Maximum accepted seed size: 256 KiB.
///
/// The real seed is a few KiB. The bound keeps a malformed or hostile file from
/// being read into memory without limit.
pub const MAX_SEED_BYTES: u64 = 256 * 1024;

/// The checked-in default seed, embedded at compile time.
pub const DEFAULT_SEED_JSON: &str = include_str!("../data/models.json");

/// One model's list price in micros per million tokens.
///
/// Input and output are required. Cache fields are optional because a provider
/// may not offer a cache write, or may not publish the rate; `None` means
/// "unknown or not offered", never zero. A zero is a declared free rate (a local
/// model), which is different from an unpublished one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelCost {
    /// Input list price, micros per million tokens.
    pub input_micros_per_mtok: u64,
    /// Output list price, micros per million tokens.
    pub output_micros_per_mtok: u64,
    /// Cache read (hit) price, micros per million tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_read_micros_per_mtok: Option<u64>,
    /// Cache write price, micros per million tokens.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_write_micros_per_mtok: Option<u64>,
}

impl ModelCost {
    /// The combined input+output rate in micros per million tokens.
    ///
    /// This is the escalation-axis rate: it is what a round trip of one million
    /// input tokens plus one million output tokens would cost, and it saturates
    /// instead of overflowing.
    pub fn combined_micros_per_mtok(&self) -> u64 {
        self.input_micros_per_mtok.saturating_add(self.output_micros_per_mtok)
    }
}

/// Provider rate limits for one model, when the provider publishes them.
///
/// `None` means unknown or not published, not zero. A published zero is kept as
/// `Some(0)` so "no quota" is distinguishable from "not recorded".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RateLimits {
    /// Requests per minute.
    #[serde(default)]
    pub rpm: Option<u32>,
    /// Tokens per minute.
    #[serde(default)]
    pub tpm: Option<u64>,
}

/// Lifecycle and locality of a model.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Availability {
    /// Generally available.
    pub ga: bool,
    /// Preview access only.
    pub preview: bool,
    /// Withdrawn or scheduled for withdrawal. Never routed to.
    pub deprecated: bool,
    /// Served by a local runtime, so the data never leaves the machine.
    pub local_only: bool,
}

impl Availability {
    /// Whether the provider can serve the model now. Preview access counts;
    /// a model that is neither GA nor preview is not served.
    pub fn servable(&self) -> bool {
        self.ga || self.preview
    }
}

/// One model in the registry (MDL-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ModelEntry {
    /// Provider id, matched by [`router::is_local_provider`] for locality.
    pub provider: String,
    /// Model family, e.g. `gpt`, `claude`, `gemini`, `qwen`.
    pub family: String,
    /// Exact model id sent on the wire.
    pub model: String,
    /// Version or release label inside the family, e.g. `6.2`, `5.5`.
    pub version: String,
    /// Context window in tokens.
    pub context_tokens: u64,
    /// Maximum output tokens.
    pub output_tokens: u64,
    /// List price.
    pub cost: ModelCost,
    /// Provider rate limits.
    pub rate: RateLimits,
    /// Lifecycle and locality.
    pub availability: Availability,
    /// Capability grades. The embedded model id must equal `model`.
    pub grades: ModelGrades,
    /// Index into [`PoolSeed::sources`].
    pub source_ref: usize,
}

impl ModelEntry {
    /// The router's view of this entry.
    ///
    /// `available` is [`Availability::servable`], `deprecated` is the lifecycle
    /// flag, and `tier` follows [`tier_for_combined_rate`]. `local_only` is not
    /// copied: the router reads locality from the provider id
    /// ([`router::is_local_provider`]), which keeps one locality signal.
    pub fn to_pool_model(&self) -> PoolModel {
        PoolModel {
            model: self.model.clone(),
            provider: self.provider.clone(),
            grades: self.grades.clone(),
            input_cost_micros_per_mtok: self.cost.input_micros_per_mtok,
            output_cost_micros_per_mtok: self.cost.output_micros_per_mtok,
            available: self.availability.servable(),
            deprecated: self.availability.deprecated,
            tier: tier_for_combined_rate(self.cost.combined_micros_per_mtok()),
        }
    }
}

/// One provenance record: where a fact came from and when it was checked.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Source {
    /// Stable id referenced by [`ModelEntry::source_ref`] through its index.
    pub id: String,
    /// Exact URL, or a documented offline label such as `offline:seed`.
    pub url: String,
    /// Date the source was checked, `YYYY-MM-DD`.
    pub checked_on: String,
}

/// A versioned seed document.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PoolSeed {
    /// Seed schema version. Starts at 1.
    pub schema_version: u32,
    /// Data table version, bumped when the contents change.
    pub table_version: u64,
    /// Date the whole table was checked, `YYYY-MM-DD`.
    pub checked_on: String,
    /// Provenance records. Every model points at one by index.
    pub sources: Vec<Source>,
    /// The registered models.
    pub models: Vec<ModelEntry>,
}

/// `Seed` is the short name used in the task and in conversation.
pub type Seed = PoolSeed;

impl PoolSeed {
    /// Parse and validate a seed from JSON text, with a size bound.
    ///
    /// The bound is checked before parsing, so an oversized document is refused
    /// with `zero.fnd.limit_exceeded` rather than read.
    pub fn load_str(json: &str) -> Result<Self> {
        if json.len() as u64 > MAX_SEED_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "model seed is {} bytes; the bound is {MAX_SEED_BYTES} bytes",
                    json.len()
                ),
            ));
        }
        let seed: Self = serde_json::from_str(json).map_err(|error| {
            ZeroError::new(
                ErrorCode::Serialization,
                format!("model seed JSON is malformed: {error}"),
            )
        })?;
        seed.validate()?;
        Ok(seed)
    }

    /// Read, parse, and validate a seed file, with a size bound.
    ///
    /// The file size is checked before the read. A missing or unreadable file is
    /// `zero.fnd.io`; an oversized one is `zero.fnd.limit_exceeded`.
    pub fn load_path(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let metadata = std::fs::metadata(path).map_err(|error| {
            ZeroError::new(
                ErrorCode::Io,
                format!("cannot read model seed {}: {error}", path.display()),
            )
        })?;
        if metadata.len() > MAX_SEED_BYTES {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "model seed {} is {} bytes; the bound is {MAX_SEED_BYTES} bytes",
                    path.display(),
                    metadata.len()
                ),
            ));
        }
        let json = std::fs::read_to_string(path).map_err(|error| {
            ZeroError::new(
                ErrorCode::Io,
                format!("cannot read model seed {}: {error}", path.display()),
            )
        })?;
        Self::load_str(&json)
    }

    /// Re-check a seed, however it was built.
    ///
    /// A struct literal or a deserialized seed bypasses [`Self::load_str`], so
    /// every seed is validated before it is converted to a routing pool.
    ///
    /// Rejected, in this order: a schema version of 0, a table version of 0, a
    /// malformed `checked_on`, an empty source list, a source with a blank id or
    /// URL or a malformed date, a duplicate source id, a model with a blank
    /// model id, provider, family, or version, a zero context or output limit, a
    /// grade map that is empty or names a different model, an out-of-range
    /// `source_ref`, an unavailable local marker on a remote provider, and a
    /// duplicate model id.
    pub fn validate(&self) -> Result<()> {
        if self.schema_version == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "model seed has schema version 0; schema versions start at 1",
            ));
        }
        if self.table_version == 0 {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "model seed has table version 0; table versions start at 1",
            ));
        }
        if !valid_date(&self.checked_on) {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!(
                    "model seed checked_on {:?} is not a YYYY-MM-DD date",
                    self.checked_on
                ),
            ));
        }
        if self.sources.is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                "model seed has no sources; every model needs a recorded origin",
            ));
        }
        let mut source_ids = BTreeSet::new();
        for source in &self.sources {
            if source.id.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    "model seed source has an empty id",
                ));
            }
            if source.url.trim().is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("model seed source {:?} has an empty URL", source.id),
                ));
            }
            if !valid_date(&source.checked_on) {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed source {:?} has checked_on {:?}, which is not a YYYY-MM-DD date",
                        source.id, source.checked_on
                    ),
                ));
            }
            if !source_ids.insert(source.id.as_str()) {
                return Err(ZeroError::new(
                    ErrorCode::AlreadyExists,
                    format!("duplicate model seed source id {:?}", source.id),
                ));
            }
        }

        let mut seen = BTreeSet::new();
        for model in &self.models {
            for (field, value) in [
                ("model", &model.model),
                ("provider", &model.provider),
                ("family", &model.family),
                ("version", &model.version),
            ] {
                if value.trim().is_empty() {
                    return Err(ZeroError::new(
                        ErrorCode::InvalidInput,
                        format!("model seed entry has an empty {field} (model {:?})", model.model),
                    ));
                }
            }
            if model.context_tokens == 0 {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed entry {:?} has a zero context limit; limits must be positive",
                        model.model
                    ),
                ));
            }
            if model.output_tokens == 0 {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed entry {:?} has a zero output limit; limits must be positive",
                        model.model
                    ),
                ));
            }
            if model.grades.grades.is_empty() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!("model seed entry {:?} has no capability grades", model.model),
                ));
            }
            if model.grades.model != model.model {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed entry {:?} carries grades for {:?}; the ids must match",
                        model.model, model.grades.model
                    ),
                ));
            }
            if model.source_ref >= self.sources.len() {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed entry {:?} references source {} but only {} sources exist",
                        model.model,
                        model.source_ref,
                        self.sources.len()
                    ),
                ));
            }
            if model.availability.ga && model.availability.preview {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed entry {:?} is marked both ga and preview; pick one lifecycle",
                        model.model
                    ),
                ));
            }
            if model.availability.local_only && !router::is_local_provider(&model.provider) {
                return Err(ZeroError::new(
                    ErrorCode::InvalidInput,
                    format!(
                        "model seed entry {:?} is local_only but provider {:?} is not a local runtime",
                        model.model, model.provider
                    ),
                ));
            }
            if !seen.insert(model.model.as_str()) {
                return Err(ZeroError::new(
                    ErrorCode::AlreadyExists,
                    format!(
                        "duplicate model seed id {:?}; model ids must be unique",
                        model.model
                    ),
                ));
            }
        }
        Ok(())
    }

    /// Load a seed from a path or from JSON text.
    ///
    /// A string whose first non-whitespace byte is `{` is treated as a JSON
    /// document; anything else is treated as a filesystem path. Use
    /// [`Self::load_str`] or [`Self::load_path`] when the kind is already known.
    /// Both paths apply the same 256 KiB bound and validation.
    pub fn load(input: impl AsRef<Path>) -> Result<Self> {
        let path = input.as_ref();
        let text = path.to_string_lossy();
        if text.trim_start().starts_with('{') {
            Self::load_str(&text)
        } else {
            Self::load_path(path)
        }
    }

    /// Validate and convert to a routing pool.
    pub fn try_to_pool(&self) -> Result<Pool> {
        self.validate()?;
        let models: Vec<PoolModel> =
            self.models.iter().map(ModelEntry::to_pool_model).collect();
        Pool::new(models)
    }

    /// Convert to a routing pool.
    ///
    /// Panics only if the seed is invalid. The checked-in seed is validated by
    /// the test suite, and [`Self::try_to_pool`] is the non-panicking form for
    /// data loaded from storage.
    pub fn to_pool(&self) -> Pool {
        self.try_to_pool()
            .expect("a validated model seed converts to a routing pool")
    }
}

/// The documented tier rule: a cost band over the combined input+output rate.
///
/// | Combined rate (micros/Mtok) | Tier |
/// |---|---:|
/// | 0 (declared free route) | 0 |
/// | 1 ..= 5,000,000 ($5) | 1 |
/// | 5,000,001 ..= 15,000,000 ($15) | 2 |
/// | above 15,000,000 | 3 |
///
/// The band is based on list price, not benchmark quality, so two models in one
/// band are escalation peers. Escalation still moves only to a strictly higher
/// tier, which is why a stronger model in the same band is an alternative rather
/// than an escalation target.
pub fn tier_for_combined_rate(combined_micros_per_mtok: u64) -> u8 {
    match combined_micros_per_mtok {
        0 => 0,
        rate if rate <= 5_000_000 => 1,
        rate if rate <= 15_000_000 => 2,
        _ => 3,
    }
}

/// The checked-in seed, parsed and validated.
///
/// Panics only if the embedded file is invalid; the test suite parses and
/// validates it, so a broken seed fails the build rather than a runtime request.
pub fn seed_default() -> PoolSeed {
    PoolSeed::load_str(DEFAULT_SEED_JSON)
        .expect("the checked-in model seed at data/models.json is valid")
}

/// True when `value` is a real `YYYY-MM-DD` calendar date.
fn valid_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return false;
    }
    let number = |range: std::ops::Range<usize>| -> Option<u32> {
        let digits = std::str::from_utf8(&bytes[range]).ok()?;
        if !digits.bytes().all(|byte| byte.is_ascii_digit()) {
            return None;
        }
        digits.parse().ok()
    };
    let (Some(year), Some(month), Some(day)) = (number(0..4), number(5..7), number(8..10)) else {
        return false;
    };
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let days_in_month = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= days_in_month
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{self, Capability, Grade, TaskSignals, WorkClass};
    use crate::router::{self, Overrides};

    fn edit() -> classify::Classification {
        classify::classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() })
    }

    #[test]
    fn the_default_seed_loads_validates_and_is_the_size_the_task_asks_for() {
        let seed = seed_default();
        assert_eq!(seed.schema_version, SEED_SCHEMA_VERSION);
        assert!(seed.table_version >= 1);
        assert_eq!(seed.checked_on, "2026-11-25");
        assert!(
            (6..=10).contains(&seed.models.len()),
            "the seed has {} models; the task asks for 6-10 representative models",
            seed.models.len()
        );
        assert!(seed.sources.len() >= seed.models.len(), "each model needs provenance");
        assert!(seed.validate().is_ok());
    }

    #[test]
    fn every_model_has_a_source_with_a_url_and_check_date() {
        let seed = seed_default();
        let mut ids = BTreeSet::new();
        for model in &seed.models {
            let source = &seed.sources[model.source_ref];
            assert!(!source.id.trim().is_empty(), "{} has a blank source id", model.model);
            assert!(!source.url.trim().is_empty(), "{} has a blank source url", model.model);
            assert!(valid_date(&source.checked_on), "{} has a bad date", model.model);
            assert!(
                source.checked_on <= seed.checked_on,
                "{} cites a source checked after the table date",
                model.model
            );
            assert!(ids.insert(source.id.as_str()), "duplicate source id {}", source.id);
        }
        assert!(seed.sources.iter().any(|source| source.url.starts_with("https://")));
    }

    #[test]
    fn duplicate_model_ids_are_rejected() {
        let mut seed = seed_default();
        let duplicated = seed.models[0].clone();
        seed.models.push(duplicated);
        let error = seed.validate().expect_err("duplicate ids must be refused");
        assert_eq!(error.code(), ErrorCode::AlreadyExists);
        assert!(error.message().contains("duplicate"), "{}", error.message());
    }

    #[test]
    fn invalid_dates_zero_limits_and_negative_prices_are_rejected() {
        let mut bad_date = seed_default();
        bad_date.checked_on = "2026-13-01".to_owned();
        let error = bad_date.validate().expect_err("month 13 is not a date");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("YYYY-MM-DD"), "{}", error.message());

        let mut not_a_date = seed_default();
        not_a_date.checked_on = "25-11-2026".to_owned();
        assert!(not_a_date.validate().is_err());

        let mut zero_context = seed_default();
        zero_context.models[0].context_tokens = 0;
        let error = zero_context.validate().expect_err("a zero context is refused");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("context"), "{}", error.message());

        let mut zero_output = seed_default();
        zero_output.models[0].output_tokens = 0;
        assert!(zero_output.validate().is_err());

        // A negative price cannot exist in the type, so it must fail parsing.
        let negative = DEFAULT_SEED_JSON.replacen(
            "\"input_micros_per_mtok\": 2000000",
            "\"input_micros_per_mtok\": -1",
            1,
        );
        assert_ne!(negative, DEFAULT_SEED_JSON, "the fixture must contain the replaced price");
        let error = PoolSeed::load_str(&negative).expect_err("a negative price is not a price");
        assert_eq!(error.code(), ErrorCode::Serialization);
    }

    #[test]
    fn an_unknown_source_ref_is_rejected() {
        let mut seed = seed_default();
        seed.models[0].source_ref = seed.sources.len() + 10;
        let error = seed.validate().expect_err("dangling provenance must be refused");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("references source"), "{}", error.message());
    }

    #[test]
    fn blank_provider_family_and_mismatched_grades_are_rejected() {
        let mut blank_provider = seed_default();
        blank_provider.models[0].provider.clear();
        assert!(blank_provider.validate().is_err());

        let mut blank_family = seed_default();
        blank_family.models[0].family = "   ".to_owned();
        assert!(blank_family.validate().is_err());

        let mut mismatch = seed_default();
        mismatch.models[0].grades.model = "different-model".to_owned();
        let error = mismatch.validate().expect_err("grade ids must match the entry");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("must match"), "{}", error.message());
    }

    #[test]
    fn a_local_only_marker_requires_a_local_provider() {
        let mut remote = seed_default();
        remote.models[0].availability.local_only = true; // gpt-6.2-sol is openai
        let error = remote.validate().expect_err("a remote model cannot be local_only");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
        assert!(error.message().contains("local"), "{}", error.message());
    }

    #[test]
    fn to_pool_preserves_costs_grades_and_lifecycle() {
        let seed = seed_default();
        let pool = seed.to_pool();
        assert_eq!(pool.len(), seed.models.len());

        for entry in &seed.models {
            let model = pool.get(&entry.model).expect("every seed entry reaches the pool");
            assert_eq!(model.provider, entry.provider);
            assert_eq!(model.grades, entry.grades);
            assert_eq!(model.input_cost_micros_per_mtok, entry.cost.input_micros_per_mtok);
            assert_eq!(model.output_cost_micros_per_mtok, entry.cost.output_micros_per_mtok);
            assert_eq!(model.available, entry.availability.ga || entry.availability.preview);
            assert_eq!(model.deprecated, entry.availability.deprecated);
            assert_eq!(
                model.tier,
                tier_for_combined_rate(entry.cost.combined_micros_per_mtok())
            );
        }
    }

    #[test]
    fn tier_follows_the_documented_cost_bands() {
        assert_eq!(tier_for_combined_rate(0), 0);
        assert_eq!(tier_for_combined_rate(1), 1);
        assert_eq!(tier_for_combined_rate(5_000_000), 1);
        assert_eq!(tier_for_combined_rate(5_000_001), 2);
        assert_eq!(tier_for_combined_rate(15_000_000), 2);
        assert_eq!(tier_for_combined_rate(15_000_001), 3);

        let seed = seed_default();
        let local = seed.models.iter().find(|model| model.provider == "ollama").expect("a local model");
        assert_eq!(local.to_pool_model().tier, 0);
        let opus = seed
            .models
            .iter()
            .find(|model| model.model == "claude-opus-5-5")
            .expect("opus is seeded");
        assert_eq!(opus.to_pool_model().tier, 3);
    }

    #[test]
    fn the_seed_keeps_a_model_above_the_security_floor() {
        let pool = seed_default().to_pool();
        let security = classify::floor_for(WorkClass::Security);
        let capable: Vec<&str> = pool
            .models
            .iter()
            .filter(|model| classify::meets(&model.grades, &security).ok)
            .map(|model| model.model.as_str())
            .collect();
        assert!(
            !capable.is_empty(),
            "no seeded model clears the security floor; the capability floor is unsatisfiable"
        );
        assert!(
            capable.iter().any(|model| model.contains("claude-opus-5-5")),
            "the security floor should be demonstrably reachable: {capable:?}"
        );

        // The destructive floor is stricter (tool_use 5) and must also be reachable.
        let destructive = classify::floor_for(WorkClass::Destructive);
        assert!(
            pool.models
                .iter()
                .any(|model| classify::meets(&model.grades, &destructive).ok),
            "no seeded model clears the destructive floor"
        );
    }

    #[test]
    fn at_least_one_model_is_local_only_and_free() {
        let seed = seed_default();
        let local: Vec<&ModelEntry> = seed
            .models
            .iter()
            .filter(|model| model.availability.local_only)
            .collect();
        assert!(!local.is_empty(), "the seed must include a local-only option");
        for entry in local {
            assert!(router::is_local_provider(&entry.provider), "{}", entry.provider);
            assert_eq!(entry.cost.combined_micros_per_mtok(), 0, "{} is not free", entry.model);
            assert_eq!(entry.to_pool_model().tier, 0);
        }
    }

    #[test]
    fn a_deprecated_seed_model_is_excluded_by_the_router() {
        let mut seed = seed_default();
        let entry = seed
            .models
            .iter_mut()
            .find(|model| model.model == "gpt-oss:120b")
            .expect("the local model is seeded");
        entry.availability.deprecated = true;
        let pool = seed.to_pool();

        let decision = router::route(&pool, &edit(), &Overrides::default(), None, 1_000_000)
            .expect("another model clears the edit floor");
        assert_ne!(decision.chosen.model, "gpt-oss:120b");
        assert!(
            decision.warnings.iter().any(|warning| {
                warning.contains("gpt-oss:120b") && warning.contains("deprecated")
            }),
            "the reroute must be reported: {:?}",
            decision.warnings
        );
    }

    #[test]
    fn the_seed_json_is_parseable_from_the_checked_in_file() {
        let parsed: PoolSeed =
            serde_json::from_str(DEFAULT_SEED_JSON).expect("data/models.json is valid JSON");
        assert_eq!(parsed, seed_default());
        assert!(DEFAULT_SEED_JSON.len() as u64 <= MAX_SEED_BYTES);
    }

    #[test]
    fn load_path_reads_the_same_seed_and_enforces_the_size_bound() {
        let directory = tempfile::tempdir().expect("temp dir");
        let path = directory.path().join("models.json");
        std::fs::write(&path, DEFAULT_SEED_JSON).expect("write seed");
        assert_eq!(PoolSeed::load_path(&path).expect("load seed"), seed_default());
        assert_eq!(
            PoolSeed::load(path.to_str().expect("utf-8 path")).expect("load by path"),
            seed_default()
        );
        assert_eq!(PoolSeed::load(DEFAULT_SEED_JSON).expect("load json"), seed_default());

        let oversized = directory.path().join("oversized.json");
        std::fs::write(&oversized, "x".repeat(MAX_SEED_BYTES as usize + 1)).expect("write oversized");
        let error = PoolSeed::load_path(&oversized).expect_err("the size bound is enforced");
        assert_eq!(error.code(), ErrorCode::LimitExceeded);

        let missing = directory.path().join("missing.json");
        let error = PoolSeed::load_path(&missing).expect_err("a missing file is an io error");
        assert_eq!(error.code(), ErrorCode::Io);
    }

    #[test]
    fn grades_cover_every_capability_axis_and_stay_on_scale() {
        let seed = seed_default();
        for model in &seed.models {
            for capability in Capability::ALL {
                let grade = model.grades.grade(capability);
                assert!(grade <= Grade::MAX, "{} exceeds the scale", model.model);
            }
            // The task names these axes; a seed row declares each one.
            assert_eq!(
                model.grades.grades.len(),
                Capability::ALL.len(),
                "{} does not declare every capability axis",
                model.model
            );
        }
    }
}
