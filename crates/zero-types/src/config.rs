//! One config schema with layered precedence (FND-05).
//!
//! Resolution order, lowest to highest: defaults, user, trusted project,
//! environment, CLI, session. Project config is inert unless the project is
//! trusted; an untrusted project layer never wins, even over defaults.

use crate::error::{ErrorCode, Result, ZeroError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Layers in increasing precedence order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigLayer {
    Defaults,
    User,
    TrustedProject,
    Environment,
    Cli,
    Session,
}

impl ConfigLayer {
    pub const ORDERED: [ConfigLayer; 6] = [
        ConfigLayer::Defaults,
        ConfigLayer::User,
        ConfigLayer::TrustedProject,
        ConfigLayer::Environment,
        ConfigLayer::Cli,
        ConfigLayer::Session,
    ];

    pub fn precedence(self) -> u8 {
        match self {
            ConfigLayer::Defaults => 0,
            ConfigLayer::User => 1,
            ConfigLayer::TrustedProject => 2,
            ConfigLayer::Environment => 3,
            ConfigLayer::Cli => 4,
            ConfigLayer::Session => 5,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ConfigLayer::Defaults => "defaults",
            ConfigLayer::User => "user",
            ConfigLayer::TrustedProject => "trusted_project",
            ConfigLayer::Environment => "environment",
            ConfigLayer::Cli => "cli",
            ConfigLayer::Session => "session",
        }
    }
}

/// A value supplied by one layer for one key.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct LayeredValue {
    pub key: String,
    pub value: serde_json::Value,
    pub layer: ConfigLayer,
}

/// Resolved configuration with the winning layer per key, for display and audit.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResolvedConfig {
    values: BTreeMap<String, serde_json::Value>,
    sources: BTreeMap<String, ConfigLayer>,
}

impl ResolvedConfig {
    pub fn get(&self, key: &str) -> Option<&serde_json::Value> {
        self.values.get(key)
    }

    pub fn source(&self, key: &str) -> Option<ConfigLayer> {
        self.sources.get(key).copied()
    }

    pub fn as_map(&self) -> &BTreeMap<String, serde_json::Value> {
        &self.values
    }

    pub fn keys(&self) -> impl Iterator<Item = &String> {
        self.values.keys()
    }
}

/// The documented resolution order, used in docs and tests.
pub fn resolution_order() -> &'static [ConfigLayer] {
    &ConfigLayer::ORDERED
}

/// Resolve layered values. Untrusted project values are dropped before
/// resolution; the first terminal match is the highest-precedence layer.
pub fn resolve(
    values: impl IntoIterator<Item = LayeredValue>,
    project_trusted: bool,
) -> Result<ResolvedConfig> {
    let mut best: BTreeMap<String, (u8, serde_json::Value, ConfigLayer)> = BTreeMap::new();
    for v in values {
        // An untrusted project layer is inert: it cannot influence resolution.
        if v.layer == ConfigLayer::TrustedProject && !project_trusted {
            continue;
        }
        if v.key.trim().is_empty() {
            return Err(ZeroError::new(ErrorCode::ConfigInvalid, "empty config key"));
        }
        let prec = v.layer.precedence();
        match best.get(&v.key) {
            Some((current, _, _)) if *current > prec => {}
            _ => {
                best.insert(v.key, (prec, v.value, v.layer));
            }
        }
    }
    let mut out = ResolvedConfig::default();
    for (k, (_, v, layer)) in best {
        out.sources.insert(k.clone(), layer);
        out.values.insert(k, v);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn v(key: &str, layer: ConfigLayer) -> LayeredValue {
        LayeredValue { key: key.into(), value: json!(layer.as_str()), layer }
    }

    #[test]
    fn resolution_order_is_documented_lowest_to_highest() {
        let order = resolution_order();
        assert_eq!(order[0], ConfigLayer::Defaults);
        assert_eq!(order[order.len() - 1], ConfigLayer::Session);
        for pair in order.windows(2) {
            assert!(pair[0] < pair[1], "layers must be strictly ordered");
        }
    }

    #[test]
    fn matrix_covers_every_layer_pair() {
        let layers = ConfigLayer::ORDERED;
        for (i, low) in layers.iter().enumerate() {
            for high in &layers[i + 1..] {
                let cfg = resolve(vec![v("k", *low), v("k", *high)], true).unwrap();
                assert_eq!(cfg.source("k"), Some(*high), "{high:?} must beat {low:?}");
                assert_eq!(cfg.get("k"), Some(&json!(high.as_str())));
            }
        }
        // 6 layers -> 15 ordered pairs, each asserted above.
        assert_eq!(layers.len() * (layers.len() - 1) / 2, 15);
    }

    #[test]
    fn untrusted_project_config_is_inert() {
        for layer in ConfigLayer::ORDERED.iter().copied().filter(|l| *l != ConfigLayer::TrustedProject) {
            let cfg = resolve(
                vec![v("k", ConfigLayer::TrustedProject), v("k", layer)],
                false,
            )
            .unwrap();
            assert_eq!(cfg.source("k"), Some(layer), "untrusted project must lose to {layer:?}");
        }
        // Alone, untrusted project config produces nothing at all.
        let cfg = resolve(vec![v("k", ConfigLayer::TrustedProject)], false).unwrap();
        assert!(cfg.get("k").is_none());
        // Trusted, it participates normally.
        let cfg = resolve(vec![v("k", ConfigLayer::TrustedProject)], true).unwrap();
        assert_eq!(cfg.source("k"), Some(ConfigLayer::TrustedProject));
    }

    #[test]
    fn later_value_in_same_layer_is_last_write() {
        let mut a = v("k", ConfigLayer::User);
        a.value = json!(1);
        let mut b = v("k", ConfigLayer::User);
        b.value = json!(2);
        let cfg = resolve(vec![a, b], true).unwrap();
        assert_eq!(cfg.get("k"), Some(&json!(2)));
    }

    #[test]
    fn empty_key_is_rejected_with_a_typed_error() {
        let err = resolve(vec![LayeredValue { key: " ".into(), value: json!(1), layer: ConfigLayer::User }], true)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigInvalid);
    }
}
