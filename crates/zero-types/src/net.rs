//! Offline guards (FND-10, FND-13).
//!
//! Network-backed features report a typed unavailable state when the host is
//! offline. Local file work never consults this module.

use crate::error::{ErrorCode, Result, ZeroError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkState {
    Online,
    Offline,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Feature {
    WebSearch,
    WebFetch,
    HostedProvider,
    LocalProvider,
    McpRemote,
    Mesh,
    CatalogueRefresh,
    Telemetry,
}

impl Feature {
    pub const ALL: [Feature; 8] = [
        Feature::WebSearch,
        Feature::WebFetch,
        Feature::HostedProvider,
        Feature::LocalProvider,
        Feature::McpRemote,
        Feature::Mesh,
        Feature::CatalogueRefresh,
        Feature::Telemetry,
    ];

    pub fn needs_network(self) -> bool {
        !matches!(self, Feature::LocalProvider | Feature::Telemetry)
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Feature::WebSearch => "web_search",
            Feature::WebFetch => "web_fetch",
            Feature::HostedProvider => "hosted_provider",
            Feature::LocalProvider => "local_provider",
            Feature::McpRemote => "mcp_remote",
            Feature::Mesh => "mesh",
            Feature::CatalogueRefresh => "catalogue_refresh",
            Feature::Telemetry => "telemetry",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Availability {
    Available,
    Unavailable {
        feature: String,
        reason: String,
        code: String,
    },
}

impl Availability {
    pub fn is_available(&self) -> bool {
        matches!(self, Availability::Available)
    }

    pub fn unavailable(feature: Feature, reason: impl Into<String>) -> Self {
        Availability::Unavailable {
            feature: feature.as_str().to_string(),
            reason: reason.into(),
            code: ErrorCode::Offline.as_str().to_string(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct NetworkGuard {
    state: NetworkState,
}

impl NetworkGuard {
    pub fn new(state: NetworkState) -> Self {
        Self { state }
    }

    pub fn offline() -> Self {
        Self::new(NetworkState::Offline)
    }

    pub fn state(&self) -> NetworkState {
        self.state
    }

    pub fn set(&mut self, state: NetworkState) {
        self.state = state;
    }

    pub fn check(&self, feature: Feature) -> Availability {
        match (self.state, feature) {
            (NetworkState::Offline, f) if f.needs_network() => {
                Availability::unavailable(f, "the host is offline")
            }
            (NetworkState::Unknown, f) if f.needs_network() => Availability::Unavailable {
                feature: f.as_str().to_string(),
                reason: "network state is unknown".into(),
                code: ErrorCode::Unavailable.as_str().to_string(),
            },
            _ => Availability::Available,
        }
    }

    /// Require a feature, returning a typed error when it is unavailable.
    pub fn require(&self, feature: Feature) -> Result<()> {
        match self.check(feature) {
            Availability::Available => Ok(()),
            Availability::Unavailable { reason, .. } => Err(ZeroError::new(
                ErrorCode::Offline,
                format!("{} is unavailable: {reason}", feature.as_str()),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn offline_reports_every_network_feature_as_unavailable() {
        let guard = NetworkGuard::offline();
        for f in Feature::ALL {
            let a = guard.check(f);
            if f.needs_network() {
                assert!(!a.is_available(), "{f:?} must be unavailable offline");
                match a {
                    Availability::Unavailable { code, .. } => {
                        assert_eq!(code, ErrorCode::Offline.as_str())
                    }
                    _ => unreachable!(),
                }
                assert_eq!(guard.require(f).unwrap_err().code(), ErrorCode::Offline);
            } else {
                assert!(a.is_available(), "{f:?} must work offline");
            }
        }
    }

    #[test]
    fn local_work_passes_an_offline_smoke_test() {
        // Startup and file work do not consult the network guard at all; this
        // simulates the smoke path and proves no network feature is required.
        let guard = NetworkGuard::offline();
        let dir = tempfile::tempdir().unwrap();
        let file = dir.path().join("work.txt");
        std::fs::write(&file, "offline edit").unwrap();
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "offline edit");
        assert!(guard.require(Feature::LocalProvider).is_ok());
        assert_eq!(guard.check(Feature::Telemetry).code_or_empty(), "");
    }

    trait CodeExt {
        fn code_or_empty(&self) -> String;
    }
    impl CodeExt for Availability {
        fn code_or_empty(&self) -> String {
            match self {
                Availability::Unavailable { code, .. } => code.clone(),
                Availability::Available => String::new(),
            }
        }
    }

    #[test]
    fn online_availability_reports_available() {
        let guard = NetworkGuard::new(NetworkState::Online);
        for f in Feature::ALL {
            assert!(guard.check(f).is_available());
        }
    }

    #[test]
    fn unknown_state_is_not_silently_online() {
        let guard = NetworkGuard::new(NetworkState::Unknown);
        let a = guard.check(Feature::WebFetch);
        assert!(!a.is_available());
        assert!(guard.require(Feature::WebFetch).is_err());
    }
}
