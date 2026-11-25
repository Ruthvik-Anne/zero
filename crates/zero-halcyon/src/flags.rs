//! The four Halcyon flags and their project-proof resolution (HAL-06, HAL-10).
//!
//! Exactly four keys gate Halcyon capabilities: [`MODE_KEY`], [`TODO_SYNC_KEY`],
//! [`JOKER_KEY`], and [`EPB_KEY`]. There is no fifth flag and no generic flag
//! namespace; a key outside the set is not recognised.
//!
//! Configuration is layered, but only the **global** (user-owned) layer can
//! enable a flag. A project file is untrusted, so [`resolve`] gives it one
//! direction only: it may turn a globally enabled flag off. A project `true`
//! where the global layer is `false` is ignored and recorded in
//! [`FlagResolution::rejected`]; it never enables anything. When the global
//! layer has no value, every flag is false regardless of the project layer.
//!
//! A flag only permits a capability. `halcyon.mode` being true does not start
//! the mode: [`crate::discovery`] must find a `.halcyon-mode` file and
//! [`crate::verify`] must accept its signature, binding, and time window. Flags
//! are consulted after those gates, never instead of them.
//!
//! Unknown keys in a configuration map are ignored for forward compatibility
//! and reported in [`FlagReport::ignored`]; a known key whose value is not a
//! boolean is `zero.fnd.config_invalid`.

use std::collections::BTreeMap;
use std::fmt;

use zero_types::{ErrorCode, ZeroError};

/// Documentation anchor referenced by the flags section.
pub const FLAGS_DOCS_ANCHOR: &str = "docs/halcyon.md#flags-t-hal-06";

/// The key that permits the Halcyon mode capability (HAL-10).
pub const MODE_KEY: &str = "halcyon.mode";

/// The key that permits two-way todo sync with `tkb` (HAL-10, HAL-11).
pub const TODO_SYNC_KEY: &str = "halcyon.todo_sync";

/// The key that permits gates through `joker` (HAL-10).
pub const JOKER_KEY: &str = "halcyon.joker";

/// The key that permits endpoints through `epb` (HAL-10).
pub const EPB_KEY: &str = "halcyon.epb";

/// The reason recorded when a project file tries to enable a flag.
pub const PROJECT_CANNOT_ENABLE_REASON: &str =
    "project config may only disable Halcyon flags; only user (global) config can enable them";

/// The reason reported for a flag a project file turned off.
pub const PROJECT_DISABLED_REASON: &str = "disabled by the project config";

/// One of the four flags HAL-10 allows.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Flag {
    /// `halcyon.mode`: the mode capability itself.
    Mode,
    /// `halcyon.todo_sync`: two-way todo sync with `tkb`.
    TodoSync,
    /// `halcyon.joker`: gates through `joker`.
    Joker,
    /// `halcyon.epb`: endpoints through `epb`.
    Epb,
}

impl Flag {
    /// Every flag, in diagnostic order.
    ///
    /// Exactly four entries. A fifth flag would change the HAL-10 surface, so
    /// the set is a constant and a test asserts its length.
    pub const ALL: [Flag; 4] = [Flag::Mode, Flag::TodoSync, Flag::Joker, Flag::Epb];

    /// The exact configuration key for this flag.
    pub const fn key(self) -> &'static str {
        match self {
            Flag::Mode => MODE_KEY,
            Flag::TodoSync => TODO_SYNC_KEY,
            Flag::Joker => JOKER_KEY,
            Flag::Epb => EPB_KEY,
        }
    }

    /// Parse a configuration key. Matching is exact and case-sensitive.
    ///
    /// `None` means "not one of the four flags", which callers treat as an
    /// unknown key rather than an error.
    pub fn parse_key(key: &str) -> Option<Flag> {
        Flag::ALL.into_iter().find(|flag| flag.key() == key)
    }

    /// Position in [`FlagValues`] storage.
    const fn index(self) -> usize {
        match self {
            Flag::Mode => 0,
            Flag::TodoSync => 1,
            Flag::Joker => 2,
            Flag::Epb => 3,
        }
    }
}

impl fmt::Display for Flag {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.key())
    }
}

/// Boolean values for exactly the four flags. Defaults to all false.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlagValues {
    values: [bool; 4],
}

impl FlagValues {
    /// All four flags off. This is also [`FlagValues::default`].
    pub const fn new() -> Self {
        Self { values: [false; 4] }
    }

    /// Whether `flag` is on.
    pub const fn enabled(self, flag: Flag) -> bool {
        self.values[flag.index()]
    }

    /// Set one flag.
    pub fn set(&mut self, flag: Flag, enabled: bool) {
        self.values[flag.index()] = enabled;
    }

    /// True when no flag is on.
    pub fn is_empty(&self) -> bool {
        self.values.iter().all(|enabled| !*enabled)
    }

    /// Every flag that is on, in [`Flag::ALL`] order.
    pub fn enabled_flags(&self) -> Vec<Flag> {
        Flag::ALL
            .into_iter()
            .filter(|flag| self.enabled(*flag))
            .collect()
    }
}

/// Result of parsing a raw flag map: recognised values plus ignored keys.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlagReport {
    /// Values of the four recognised keys. Missing keys are false.
    pub values: FlagValues,
    /// Keys that are not one of the four flags, sorted for determinism.
    pub ignored: Vec<String>,
}

/// Parse a configuration map into the four typed values.
///
/// Convenience wrapper around [`parse_report`] for callers that do not need the
/// ignored-key report. Wrong-typed known keys fail in both forms.
pub fn parse_values(map: &BTreeMap<String, serde_json::Value>) -> Result<FlagValues, ZeroError> {
    parse_report(map).map(|report| report.values)
}

/// Parse a configuration map, keeping the list of unknown keys.
///
/// Only the four HAL-10 keys are read. A known key must hold a JSON boolean;
/// anything else is `zero.fnd.config_invalid`. Unknown keys are ignored and
/// collected in [`FlagReport::ignored`], so a newer producer adding keys does
/// not break an older reader. A missing known key stays false.
pub fn parse_report(map: &BTreeMap<String, serde_json::Value>) -> Result<FlagReport, ZeroError> {
    let mut values = FlagValues::new();
    let mut ignored = Vec::new();
    for (key, value) in map {
        let Some(flag) = Flag::parse_key(key) else {
            ignored.push(key.clone());
            continue;
        };
        match value {
            serde_json::Value::Bool(enabled) => values.set(flag, *enabled),
            other => {
                return Err(ZeroError::new(
                    ErrorCode::ConfigInvalid,
                    format!(
                        "`{key}` must be a boolean, found {}; see {FLAGS_DOCS_ANCHOR}",
                        json_kind(other)
                    ),
                ))
            }
        }
    }
    Ok(FlagReport { values, ignored })
}

/// The two configuration layers a flag is read from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct FlagSources {
    /// The global (user-owned) layer. The only layer that may enable a flag.
    pub global: FlagValues,
    /// An untrusted project layer. It may only disable.
    pub project: Option<FlagValues>,
}

/// The effective flags plus every project override that was applied or refused.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct FlagResolution {
    /// The values a caller must consult. Never raised by the project layer.
    pub effective: FlagValues,
    /// Flags the project layer turned off, in [`Flag::ALL`] order.
    pub disabled_by_project: Vec<Flag>,
    /// Project attempts to enable a flag the global layer left off, with the
    /// reason. These never change [`FlagResolution::effective`].
    pub rejected: Vec<(Flag, String)>,
}

impl FlagResolution {
    /// Whether `flag` is effective.
    pub fn is_enabled(&self, flag: Flag) -> bool {
        self.effective.enabled(flag)
    }

    /// Every effective flag, in [`Flag::ALL`] order.
    pub fn enabled_flags(&self) -> Vec<Flag> {
        self.effective.enabled_flags()
    }

    /// A diagnostic reason for `flag`, if the project layer affected it.
    ///
    /// Returns the rejection reason for a project attempt to enable, or
    /// [`PROJECT_DISABLED_REASON`] for a project disable. `None` means the
    /// global layer decided the value.
    pub fn reason(&self, flag: Flag) -> Option<&str> {
        if let Some((_, reason)) = self.rejected.iter().find(|(rejected, _)| *rejected == flag) {
            return Some(reason);
        }
        if self.disabled_by_project.contains(&flag) {
            return Some(PROJECT_DISABLED_REASON);
        }
        None
    }
}

/// Resolve global and project flag layers.
///
/// The global layer is the only enabler. A project file can subtract from it:
///
/// | global | project | effective | record |
/// |---|---|---|---|
/// | false | absent/false | false | — |
/// | false | true | false | [`FlagResolution::rejected`] |
/// | true | absent | true | — |
/// | true | true | true | — |
/// | true | false | false | [`FlagResolution::disabled_by_project`] |
///
/// With no global layer every flag is false, even when the project layer says
/// true. This is the T-HAL-06 Done criterion: project config cannot enable a
/// flag.
///
/// A project layer is a complete snapshot, not a sparse overlay: because
/// [`FlagValues`] defaults every missing key to false, a key the project map
/// omits is a project `false` and disables that globally enabled flag. A
/// project that wants to keep other flags on states them `true`; if they are
/// globally off they are still rejected rather than enabled.
pub fn resolve(sources: FlagSources) -> FlagResolution {
    let mut effective = sources.global;
    let mut disabled_by_project = Vec::new();
    let mut rejected = Vec::new();

    if let Some(project) = sources.project {
        for flag in Flag::ALL {
            let wanted = project.enabled(flag);
            if wanted && !sources.global.enabled(flag) {
                rejected.push((flag, PROJECT_CANNOT_ENABLE_REASON.to_string()));
            } else if !wanted && sources.global.enabled(flag) {
                effective.set(flag, false);
                disabled_by_project.push(flag);
            }
        }
    }

    FlagResolution {
        effective,
        disabled_by_project,
        rejected,
    }
}

fn json_kind(value: &serde_json::Value) -> &'static str {
    match value {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "a boolean",
        serde_json::Value::Number(_) => "a number",
        serde_json::Value::String(_) => "a string",
        serde_json::Value::Array(_) => "an array",
        serde_json::Value::Object(_) => "an object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    fn global(on: &[Flag]) -> FlagValues {
        let mut values = FlagValues::new();
        for flag in on {
            values.set(*flag, true);
        }
        values
    }

    fn map(entries: &[(&str, serde_json::Value)]) -> BTreeMap<String, serde_json::Value> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), value.clone()))
            .collect()
    }

    fn bool_map(entries: &[(&str, bool)]) -> BTreeMap<String, serde_json::Value> {
        entries
            .iter()
            .map(|(key, value)| ((*key).to_string(), serde_json::Value::Bool(*value)))
            .collect()
    }

    #[test]
    fn flag_set_has_exactly_four_keys() {
        let expected = [
            "halcyon.mode",
            "halcyon.todo_sync",
            "halcyon.joker",
            "halcyon.epb",
        ];
        let actual: Vec<&str> = Flag::ALL.iter().map(|flag| flag.key()).collect();

        assert_eq!(actual, expected);
        assert_eq!(Flag::ALL.len(), 4);
        assert_eq!(
            actual.iter().collect::<BTreeSet<_>>().len(),
            actual.len(),
            "flag keys must be unique"
        );
    }

    #[test]
    fn there_is_no_fifth_flag() {
        // A key that looks plausible but is outside HAL-10 must not parse, and
        // the value storage is exactly four slots.
        for key in [
            "halcyon",
            "halcyon.other",
            "halcyon.todo",
            "halcyon.todo_sync.extra",
        ] {
            assert_eq!(Flag::parse_key(key), None, "unexpected flag key {key}");
        }
        assert_eq!(FlagValues::new().values.len(), 4);
    }

    #[test]
    fn flag_keys_are_case_sensitive() {
        assert_eq!(Flag::parse_key(MODE_KEY), Some(Flag::Mode));
        assert_eq!(Flag::parse_key(TODO_SYNC_KEY), Some(Flag::TodoSync));
        assert_eq!(Flag::parse_key(JOKER_KEY), Some(Flag::Joker));
        assert_eq!(Flag::parse_key(EPB_KEY), Some(Flag::Epb));

        for near_miss in [
            "Halcyon.Mode",
            "HALCYON.MODE",
            "halcyon.Mode",
            "halcyon.MODE",
            " halcyon.mode",
            "halcyon.mode ",
            "halcyon.mode\n",
        ] {
            assert_eq!(Flag::parse_key(near_miss), None, "{near_miss:?}");
        }
    }

    #[test]
    fn parse_reads_every_boolean_and_defaults_missing_to_false() {
        let parsed = parse_values(&bool_map(&[
            (MODE_KEY, true),
            (TODO_SYNC_KEY, false),
            (JOKER_KEY, true),
            (EPB_KEY, false),
        ]))
        .expect("parse");

        assert!(parsed.enabled(Flag::Mode));
        assert!(!parsed.enabled(Flag::TodoSync));
        assert!(parsed.enabled(Flag::Joker));
        assert!(!parsed.enabled(Flag::Epb));
        assert_eq!(parsed.enabled_flags(), vec![Flag::Mode, Flag::Joker]);
        assert!(parse_values(&BTreeMap::new())
            .expect("empty map")
            .is_empty());
    }

    #[test]
    fn unknown_keys_are_ignored_and_reported() {
        let report = parse_report(&bool_map(&[
            (MODE_KEY, true),
            ("halcyon.future_flag", true),
            ("unrelated", false),
        ]))
        .expect("unknown keys are forward compatible");

        assert!(report.values.enabled(Flag::Mode));
        assert_eq!(report.ignored, vec!["halcyon.future_flag", "unrelated"]);
        // The convenience form accepts the same map and drops the report.
        assert!(parse_values(&bool_map(&[
            (MODE_KEY, true),
            ("halcyon.future_flag", true),
        ]))
        .expect("parse")
        .enabled(Flag::Mode));
    }

    #[test]
    fn wrong_typed_known_flag_is_invalid() {
        for wrong in [
            serde_json::json!("true"),
            serde_json::json!(1),
            serde_json::json!(null),
            serde_json::json!([]),
            serde_json::json!({}),
        ] {
            let error =
                parse_values(&map(&[(JOKER_KEY, wrong)])).expect_err("typed value required");
            assert_eq!(error.code(), ErrorCode::ConfigInvalid);
            assert!(error.message().contains(JOKER_KEY), "{}", error.message());
            assert!(error.message().contains("boolean"), "{}", error.message());
            assert_eq!(error.code().as_str(), "zero.fnd.config_invalid");
        }
    }

    #[test]
    fn global_config_enables_a_flag() {
        let resolution = resolve(FlagSources {
            global: global(&[Flag::Mode, Flag::Epb]),
            project: None,
        });

        assert!(resolution.effective.enabled(Flag::Mode));
        assert!(!resolution.effective.enabled(Flag::TodoSync));
        assert!(!resolution.effective.enabled(Flag::Joker));
        assert!(resolution.effective.enabled(Flag::Epb));
        assert!(resolution.disabled_by_project.is_empty());
        assert!(resolution.rejected.is_empty());
        assert_eq!(resolution.reason(Flag::Mode), None);
    }

    #[test]
    fn absent_global_keeps_every_flag_false() {
        let resolution = resolve(FlagSources {
            global: FlagValues::new(),
            project: Some(global(&[
                Flag::Mode,
                Flag::TodoSync,
                Flag::Joker,
                Flag::Epb,
            ])),
        });

        assert!(resolution.effective.is_empty());
        assert!(resolution.enabled_flags().is_empty());
        assert!(resolution.disabled_by_project.is_empty());
        assert_eq!(resolution.rejected.len(), 4);
        assert_eq!(
            resolution.reason(Flag::Mode),
            Some(PROJECT_CANNOT_ENABLE_REASON)
        );
    }

    #[test]
    fn project_config_cannot_enable_a_flag() {
        // The T-HAL-06 Done criterion, one flag at a time.
        for flag in Flag::ALL {
            let resolution = resolve(FlagSources {
                global: FlagValues::new(),
                project: Some(global(&[flag])),
            });

            assert!(
                !resolution.effective.enabled(flag),
                "project config enabled {flag}"
            );
            assert_eq!(
                resolution.rejected,
                vec![(flag, PROJECT_CANNOT_ENABLE_REASON.to_string())]
            );
            assert_eq!(resolution.reason(flag), Some(PROJECT_CANNOT_ENABLE_REASON));
        }
    }

    #[test]
    fn project_true_with_global_false_is_rejected() {
        let resolution = resolve(FlagSources {
            global: global(&[Flag::Mode]),
            project: Some(global(&[Flag::Mode, Flag::TodoSync, Flag::Joker])),
        });

        // Global true plus project true stays true with no record.
        assert!(resolution.effective.enabled(Flag::Mode));
        assert_eq!(resolution.reason(Flag::Mode), None);
        // Global false plus project true stays false and is rejected.
        assert!(!resolution.effective.enabled(Flag::TodoSync));
        assert!(!resolution.effective.enabled(Flag::Joker));
        assert_eq!(resolution.rejected.len(), 2);
        assert_eq!(resolution.rejected[0].0, Flag::TodoSync);
        assert_eq!(resolution.rejected[1].0, Flag::Joker);
        assert!(resolution.disabled_by_project.is_empty());
    }

    #[test]
    fn project_can_disable_a_global_flag() {
        let resolution = resolve(FlagSources {
            global: global(&[Flag::Mode, Flag::TodoSync, Flag::Joker, Flag::Epb]),
            project: Some(global(&[Flag::Mode, Flag::Joker])),
        });

        assert!(resolution.effective.enabled(Flag::Mode));
        assert!(!resolution.effective.enabled(Flag::TodoSync));
        assert!(resolution.effective.enabled(Flag::Joker));
        assert!(!resolution.effective.enabled(Flag::Epb));
        assert_eq!(
            resolution.disabled_by_project,
            vec![Flag::TodoSync, Flag::Epb]
        );
        assert_eq!(
            resolution.reason(Flag::TodoSync),
            Some(PROJECT_DISABLED_REASON)
        );
        assert!(resolution.rejected.is_empty());
    }

    #[test]
    fn project_layer_is_a_complete_snapshot() {
        // A project map that mentions only one flag states false for the other
        // three, so those globally enabled flags are disabled.
        let resolution = resolve(FlagSources {
            global: global(&[Flag::Mode, Flag::TodoSync, Flag::Joker, Flag::Epb]),
            project: Some(global(&[Flag::Mode])),
        });

        assert!(resolution.effective.enabled(Flag::Mode));
        assert!(!resolution.effective.enabled(Flag::TodoSync));
        assert!(!resolution.effective.enabled(Flag::Joker));
        assert!(!resolution.effective.enabled(Flag::Epb));
        assert_eq!(
            resolution.disabled_by_project,
            vec![Flag::TodoSync, Flag::Joker, Flag::Epb]
        );
        assert!(resolution.rejected.is_empty());
    }

    #[test]
    fn project_true_with_global_true_stays_enabled() {
        let resolution = resolve(FlagSources {
            global: global(&[Flag::Mode, Flag::Joker]),
            project: Some(global(&[Flag::Mode, Flag::Joker])),
        });

        assert!(resolution.effective.enabled(Flag::Mode));
        assert!(resolution.effective.enabled(Flag::Joker));
        assert!(resolution.disabled_by_project.is_empty());
        assert!(resolution.rejected.is_empty());
        assert_eq!(resolution.reason(Flag::Mode), None);
    }

    #[test]
    fn project_false_with_global_false_is_inert() {
        let resolution = resolve(FlagSources {
            global: FlagValues::new(),
            project: Some(FlagValues::new()),
        });

        assert!(resolution.effective.is_empty());
        assert!(resolution.disabled_by_project.is_empty());
        assert!(resolution.rejected.is_empty());
        assert_eq!(resolution.reason(Flag::Mode), None);
    }

    #[test]
    fn flags_do_not_bypass_discovery_or_verification() {
        use crate::discovery::{activation, Discovery, TrustedRoots};
        use crate::verify::{verify, ModeDocument, PinSet};

        // An enabled mode flag still does not start the mode without a file.
        let flags = resolve(FlagSources {
            global: global(&[Flag::Mode]),
            project: None,
        });
        assert!(flags.effective.enabled(Flag::Mode));
        let activation = activation(Discovery::Absent, &TrustedRoots::default());
        assert!(activation.is_disabled());
        assert!(activation.mode_file().is_none());

        // Nor without a verifiable signature. An empty pin set denies even a
        // document that claims the mode flag.
        let mut document_flags = BTreeMap::new();
        document_flags.insert(MODE_KEY.to_string(), true);
        let document = ModeDocument {
            version: crate::verify::MODE_DOCUMENT_VERSION,
            project_id: "project-1".to_string(),
            issued_ms: 1_000,
            expires_ms: 2_000,
            flags: document_flags,
            nonce: "nonce-1".to_string(),
            key_id: "key-1".to_string(),
            signature: None,
        };
        let error = verify(&document, "", &PinSet::empty(), "project-1", 1_500)
            .expect_err("no pinned key may verify");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("no pinned key"),
            "{}",
            error.message()
        );
    }
}
