//! MCP protocol revisions (MCP-01, MCP-19).
//!
//! Zero targets `2026-07-28` and negotiates `2025-11-25` for older servers.
//! Any other revision is rejected during `initialize`; new revisions are added
//! here deliberately, never guessed from an unknown string.

use std::fmt;
use std::str::FromStr;

use zero_types::error::{ErrorCode, Result, ZeroError};

/// The revision Zero requests when a caller does not pick one.
pub const DEFAULT_REVISION: McpRevision = McpRevision::V2026_07_28;

/// A supported MCP protocol revision.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum McpRevision {
    /// Older revision, kept for compatibility (MCP-19).
    V2025_11_25,
    /// Target revision: stateless core with `resultType` (MCP-01, MCP-03).
    V2026_07_28,
}

impl McpRevision {
    /// Every supported revision, oldest first.
    pub const ALL: &'static [McpRevision] = &[McpRevision::V2025_11_25, McpRevision::V2026_07_28];

    /// The newest supported revision.
    pub const LATEST: McpRevision = McpRevision::V2026_07_28;

    /// Wire spelling, exactly as it appears in `protocolVersion`.
    pub const fn as_str(self) -> &'static str {
        match self {
            McpRevision::V2025_11_25 => "2025-11-25",
            McpRevision::V2026_07_28 => "2026-07-28",
        }
    }

    /// Whether this revision defines `resultType` on every result (MCP-03).
    ///
    /// Older servers have no `resultType`; their results are treated as
    /// `complete`.
    pub const fn supports_result_type(self) -> bool {
        matches!(self, McpRevision::V2026_07_28)
    }

    /// Parse a revision from the wire. Unknown revisions are unsupported.
    pub fn parse(value: &str) -> Result<Self> {
        Self::ALL
            .iter()
            .copied()
            .find(|r| r.as_str() == value)
            .ok_or_else(|| {
                let supported = Self::ALL
                    .iter()
                    .map(|r| r.as_str())
                    .collect::<Vec<_>>()
                    .join(", ");
                ZeroError::new(
                    ErrorCode::Unsupported,
                    format!("unsupported MCP revision `{value}`; supported revisions: {supported}"),
                )
            })
    }
}

impl fmt::Display for McpRevision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

impl FromStr for McpRevision {
    type Err = ZeroError;

    fn from_str(s: &str) -> Result<Self> {
        Self::parse(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_revision_round_trips_and_only_the_newest_has_result_type() {
        for revision in McpRevision::ALL {
            assert_eq!(McpRevision::parse(revision.as_str()).unwrap(), *revision);
        }
        assert!(!McpRevision::V2025_11_25.supports_result_type());
        assert!(McpRevision::V2026_07_28.supports_result_type());
        assert_eq!(McpRevision::LATEST, DEFAULT_REVISION);
    }

    #[test]
    fn unknown_revision_is_unsupported() {
        let err = McpRevision::parse("2024-11-05").unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert!(err.message().contains("2024-11-05"));
    }
}
