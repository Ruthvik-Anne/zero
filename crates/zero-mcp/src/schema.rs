//! Bounded JSON Schema inspection and stable schema hashing (MCP-05, MCP-14).
//!
//! Server tool schemas are untrusted input. Before a catalogue is accepted, each
//! `inputSchema` (and `outputSchema`, when present) must be a JSON object within
//! the bounds below. Full JSON Schema 2020-12 validation with `$ref` resolution
//! and composition-keyword semantics belongs to a later task; this module only
//! enforces that the structure is bounded and hashable.
//!
//! The bounds are documented in `docs/mcp.md`. They are Zero's own limits, not
//! values from the MCP specification, and are deliberately conservative.

use serde_json::Value;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Maximum serialised size of one tool schema (64 KiB).
pub const MAX_SCHEMA_BYTES: usize = 64 * 1024;
/// Maximum container nesting depth of one tool schema.
pub const MAX_SCHEMA_DEPTH: usize = 32;
/// Maximum number of JSON values in one tool schema.
pub const MAX_SCHEMA_NODES: usize = 4096;

/// Bounds applied to a tool schema.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SchemaLimits {
    /// Maximum compact-JSON byte length.
    pub max_bytes: usize,
    /// Maximum container nesting depth. The root object has depth 1.
    pub max_depth: usize,
    /// Maximum number of JSON values, including scalars.
    pub max_nodes: usize,
}

impl Default for SchemaLimits {
    fn default() -> Self {
        Self {
            max_bytes: MAX_SCHEMA_BYTES,
            max_depth: MAX_SCHEMA_DEPTH,
            max_nodes: MAX_SCHEMA_NODES,
        }
    }
}

/// Validate a tool schema against [`SchemaLimits::default`].
pub fn validate_schema(schema: &Value) -> Result<()> {
    validate_schema_with(schema, SchemaLimits::default())
}

/// Validate a tool schema against explicit bounds.
///
/// The root must be an object because both `inputSchema` and `outputSchema` are
/// JSON Schema objects. Byte size is checked before the walk, so a hostile
/// schema cannot force more work than its serialised size allows.
pub fn validate_schema_with(schema: &Value, limits: SchemaLimits) -> Result<()> {
    if !schema.is_object() {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "MCP tool schema must be a JSON object",
        ));
    }

    let bytes = serde_json::to_vec(schema)?.len();
    if bytes > limits.max_bytes {
        return Err(limit_error("size", bytes, limits.max_bytes, "bytes"));
    }

    let mut nodes = 0usize;
    let mut depth = 0usize;
    measure(schema, 1, &mut nodes, &mut depth);

    if depth > limits.max_depth {
        return Err(limit_error("depth", depth, limits.max_depth, "levels"));
    }
    if nodes > limits.max_nodes {
        return Err(limit_error("node count", nodes, limits.max_nodes, "nodes"));
    }
    Ok(())
}

fn limit_error(what: &str, value: usize, limit: usize, unit: &str) -> ZeroError {
    ZeroError::new(
        ErrorCode::LimitExceeded,
        format!("MCP tool schema {what} {value} {unit} exceeds limit {limit}"),
    )
}

fn measure(value: &Value, depth: usize, nodes: &mut usize, max_depth: &mut usize) {
    *nodes += 1;
    *max_depth = (*max_depth).max(depth);
    match value {
        Value::Array(items) => {
            for item in items {
                measure(item, depth + 1, nodes, max_depth);
            }
        }
        Value::Object(map) => {
            for item in map.values() {
                measure(item, depth + 1, nodes, max_depth);
            }
        }
        _ => {}
    }
}

const FNV_OFFSET_BASIS: u64 = 0xcbf2_9ce4_8422_2325;
const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;

/// A deterministic 64-bit hash of a JSON value.
///
/// Object keys are sorted before hashing, so two schemas that differ only in
/// key order hash the same. The hash is used to notice a changed tool schema
/// between catalogue refreshes; it is not a signature and does not protect
/// against an adversary who can choose collisions.
pub fn schema_hash(value: &Value) -> u64 {
    let mut hash = FNV_OFFSET_BASIS;
    hash_value(value, &mut hash);
    hash
}

/// Feed bytes into an FNV-1a hash under construction.
pub(crate) fn hash_bytes(hash: &mut u64, bytes: &[u8]) {
    for byte in bytes {
        *hash ^= u64::from(*byte);
        *hash = hash.wrapping_mul(FNV_PRIME);
    }
}

/// Start an FNV-1a hash for combining several schema hashes.
pub(crate) fn hash_start() -> u64 {
    FNV_OFFSET_BASIS
}

fn hash_value(value: &Value, hash: &mut u64) {
    match value {
        Value::Null => hash_bytes(hash, b"null"),
        Value::Bool(true) => hash_bytes(hash, b"true"),
        Value::Bool(false) => hash_bytes(hash, b"false"),
        Value::Number(number) => {
            hash_bytes(hash, b"number:");
            hash_bytes(hash, number.to_string().as_bytes());
        }
        Value::String(string) => {
            hash_bytes(hash, b"string:");
            hash_bytes(hash, string.as_bytes());
        }
        Value::Array(items) => {
            hash_bytes(hash, b"array:");
            for item in items {
                hash_value(item, hash);
            }
            hash_bytes(hash, b"end-array");
        }
        Value::Object(map) => {
            hash_bytes(hash, b"object:");
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort_unstable();
            for key in keys {
                hash_bytes(hash, key.as_bytes());
                hash_bytes(hash, b"=");
                hash_value(&map[key], hash);
            }
            hash_bytes(hash, b"end-object");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn hashing_is_order_insensitive_and_change_sensitive() {
        let a = json!({"type": "object", "properties": {"b": {"type": "string"}, "a": {"type": "number"}}});
        let b = json!({"properties": {"a": {"type": "number"}, "b": {"type": "string"}}, "type": "object"});
        assert_eq!(schema_hash(&a), schema_hash(&b));

        let changed = json!({"type": "object", "properties": {"b": {"type": "integer"}, "a": {"type": "number"}}});
        assert_ne!(schema_hash(&a), schema_hash(&changed));
    }

    #[test]
    fn bounds_reject_deep_wide_and_large_schemas() {
        let mut deep = json!({"type": "object"});
        for _ in 0..(MAX_SCHEMA_DEPTH + 1) {
            deep = json!({"type": "object", "properties": {"n": deep}});
        }
        let err = validate_schema(&deep).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(err.message().contains("depth"));

        let wide = json!({"enum": vec![json!(1); MAX_SCHEMA_NODES + 1]});
        let err = validate_schema(&wide).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(err.message().contains("node count"));

        let large = json!({"description": "x".repeat(MAX_SCHEMA_BYTES + 1)});
        let err = validate_schema(&large).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(err.message().contains("size"));
    }

    #[test]
    fn a_non_object_schema_is_invalid_input() {
        let err = validate_schema(&json!("string")).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
    }
}
