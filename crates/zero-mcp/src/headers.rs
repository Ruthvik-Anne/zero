//! Routing headers stored by the client for a future transport (MCP-02).
//!
//! The stateless core routes requests with `MCP-Protocol-Version`,
//! `Mcp-Method`, and `Mcp-Name`. This crate stores those values so the Streamable
//! HTTP transport (T-MCP-02) can put them on the wire; the transport also stores
//! the server-assigned `Mcp-Session-Id`. No authorization scheme is implemented
//! here.

use std::collections::BTreeMap;

/// Protocol revision header, required on every request (MCP-02).
pub const HEADER_PROTOCOL_VERSION: &str = "MCP-Protocol-Version";
/// JSON-RPC method header used for routing and metering (MCP-02).
pub const HEADER_METHOD: &str = "Mcp-Method";
/// Tool name header used for routing and metering (MCP-02).
pub const HEADER_NAME: &str = "Mcp-Name";
/// Streamable HTTP session header (MCP-06). The server assigns it; the
/// transport echoes it on later requests.
pub const HEADER_SESSION_ID: &str = "Mcp-Session-Id";

/// A case-insensitive header map.
///
/// Names are stored lowercased, so `MCP-Protocol-Version`,
/// `mcp-protocol-version`, and `Mcp-Protocol-Version` address the same entry.
/// Iteration is ordered by lowercased name so output is deterministic.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Headers {
    entries: BTreeMap<String, String>,
}

impl Headers {
    /// An empty header set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Insert a header, replacing any entry whose name differs only in case.
    ///
    /// Returns the previous value, if any.
    pub fn insert(&mut self, name: &str, value: impl Into<String>) -> Option<String> {
        self.entries.insert(name.to_ascii_lowercase(), value.into())
    }

    /// Look a header up by name, ignoring case.
    pub fn get(&self, name: &str) -> Option<&str> {
        self.entries
            .get(&name.to_ascii_lowercase())
            .map(String::as_str)
    }

    /// Whether a header is present, ignoring case.
    pub fn contains_key(&self, name: &str) -> bool {
        self.entries.contains_key(&name.to_ascii_lowercase())
    }

    /// Remove a header, returning its value.
    pub fn remove(&mut self, name: &str) -> Option<String> {
        self.entries.remove(&name.to_ascii_lowercase())
    }

    /// Iterate over lowercased names and values in deterministic order.
    pub fn iter(&self) -> impl Iterator<Item = (&str, &str)> {
        self.entries
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
    }

    /// Number of stored headers.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no headers are stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lookup_and_replacement_ignore_case() {
        let mut headers = Headers::new();
        headers.insert(HEADER_PROTOCOL_VERSION, "2026-07-28");
        assert_eq!(headers.get("mcp-protocol-version"), Some("2026-07-28"));
        assert_eq!(headers.get("MCP-PROTOCOL-VERSION"), Some("2026-07-28"));

        headers.insert("mcp-protocol-version", "2025-11-25");
        assert_eq!(headers.len(), 1);
        assert_eq!(headers.get(HEADER_PROTOCOL_VERSION), Some("2025-11-25"));
    }

    #[test]
    fn iteration_is_deterministic() {
        let mut headers = Headers::new();
        headers.insert(HEADER_NAME, "echo");
        headers.insert(HEADER_METHOD, "tools/call");
        headers.insert(HEADER_PROTOCOL_VERSION, "2026-07-28");
        let pairs: Vec<_> = headers.iter().collect();
        assert_eq!(
            pairs,
            vec![
                ("mcp-method", "tools/call"),
                ("mcp-name", "echo"),
                ("mcp-protocol-version", "2026-07-28"),
            ]
        );
        assert_eq!(headers.remove(HEADER_NAME), Some("echo".to_string()));
        assert!(!headers.contains_key(HEADER_NAME));
    }
}
