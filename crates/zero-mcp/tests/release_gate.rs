//! Release conformance gate (T-TST-08, TST-10, MCP-19).
//!
//! The gate must pass on the checked-in MCP and protocol fixtures. Every
//! negative case points the gate at temporary fixture lists or directories, so
//! the checked-in fixtures are never modified.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::json;
use tempfile::TempDir;
use zero_mcp::conformance::ConformanceFixture;
use zero_mcp::conformance_gate::{
    self, GateError, GateFailure, GateInputs, ProtocolFixture, REQUIRED_PROTOCOL_CLASSES,
};
use zero_mcp::McpRevision;

fn manifest_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

fn mcp_fixture_dir() -> PathBuf {
    manifest_dir().join("tests/fixtures/conformance")
}

fn protocol_fixture_dir() -> PathBuf {
    manifest_dir().join("../../protocol/golden")
}

fn read_mcp_fixture(name: &str) -> String {
    let path = mcp_fixture_dir().join(name);
    std::fs::read_to_string(&path)
        .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
}

fn write_file(dir: &Path, name: &str, contents: &str) {
    std::fs::write(dir.join(name), contents)
        .unwrap_or_else(|error| panic!("write {}: {error}", dir.join(name).display()));
}

#[test]
fn the_release_gate_passes_on_the_checked_in_fixtures() {
    let report = conformance_gate::assert_gate().unwrap_or_else(|error| panic!("{error}"));

    assert!(report.ok, "{:?}", report.failures);
    assert!(report.failures.is_empty());
    assert!(
        report.mcp_fixtures >= McpRevision::ALL.len(),
        "expected one MCP fixture per revision, found {}",
        report.mcp_fixtures
    );
    assert_eq!(
        report.mcp_revisions,
        BTreeSet::from([McpRevision::V2025_11_25, McpRevision::V2026_07_28]),
        "the gate must cover both supported MCP revisions"
    );
    assert!(
        report.protocol_fixtures >= REQUIRED_PROTOCOL_CLASSES.len(),
        "expected a protocol fixture for every class, found {}",
        report.protocol_fixtures
    );
}

#[test]
fn empty_inputs_fail_and_the_error_lists_every_missing_class() {
    let inputs = GateInputs::default();
    let report = conformance_gate::evaluate(&inputs);

    assert!(!report.ok);
    assert_eq!(report.mcp_fixtures, 0);
    assert_eq!(report.protocol_fixtures, 0);
    assert!(report.failures.contains(&GateFailure::NoMcpFixtures));
    assert!(report.failures.contains(&GateFailure::NoProtocolFixtures));
    for revision in McpRevision::ALL {
        assert!(
            report.failures.iter().any(|failure| matches!(
                failure,
                GateFailure::MissingRevision { revision: missing } if missing == revision
            )),
            "revision {revision} must be listed as missing"
        );
    }
    for class in REQUIRED_PROTOCOL_CLASSES {
        assert!(
            report.failures.iter().any(
                |failure| matches!(failure, GateFailure::MissingProtocolClass { class: missing } if missing == class)
            ),
            "protocol class {class} must be listed as missing"
        );
    }

    let error: GateError =
        conformance_gate::assert_gate_with(&inputs).expect_err("empty inputs must fail the gate");
    let text = error.to_string();
    assert!(text.contains("missing MCP fixture class"));
    assert!(text.contains("2026-07-28"));
    assert!(text.contains("v1-frames"));
}

#[test]
fn a_single_revision_fixture_set_lists_the_missing_revision() {
    let dir = TempDir::new().expect("temp dir");
    write_file(
        dir.path(),
        "2025-11-25.json",
        &read_mcp_fixture("2025-11-25.json"),
    );

    let report =
        conformance_gate::evaluate(&GateInputs::from_dirs(dir.path(), protocol_fixture_dir()));

    assert!(!report.ok);
    assert_eq!(
        report.mcp_revisions,
        BTreeSet::from([McpRevision::V2025_11_25])
    );
    assert!(report.failures.iter().any(|failure| matches!(
        failure,
        GateFailure::MissingRevision { revision } if *revision == McpRevision::V2026_07_28
    )));
    assert!(
        report
            .failures
            .iter()
            .all(|failure| !matches!(failure, GateFailure::MissingProtocolClass { .. })),
        "the checked-in protocol goldens must still cover every class: {:?}",
        report.failures
    );
}

#[test]
fn an_unknown_revision_is_listed_and_covers_nothing() {
    let dir = TempDir::new().expect("temp dir");
    let unknown = read_mcp_fixture("2026-07-28.json").replace("2026-07-28", "2099-01-01");
    write_file(dir.path(), "2026-07-28.json", &unknown);

    let report =
        conformance_gate::evaluate(&GateInputs::from_dirs(dir.path(), protocol_fixture_dir()));

    assert!(!report.ok);
    assert!(report.mcp_revisions.is_empty());
    assert!(report.failures.iter().any(|failure| matches!(
        failure,
        GateFailure::UnknownRevision { revision, .. } if revision == "2099-01-01"
    )));
    assert!(report.failures.iter().any(|failure| matches!(
        failure,
        GateFailure::MissingRevision { revision } if *revision == McpRevision::V2026_07_28
    )));
}

#[test]
fn a_malformed_mcp_fixture_is_listed_with_its_path() {
    let dir = TempDir::new().expect("temp dir");
    write_file(dir.path(), "broken.json", "{ this is not a fixture");

    let report =
        conformance_gate::evaluate(&GateInputs::from_dirs(dir.path(), protocol_fixture_dir()));

    assert!(!report.ok);
    assert!(report.failures.iter().any(|failure| matches!(
        failure,
        GateFailure::MalformedFixture { path, .. } if path.ends_with("broken.json")
    )));
}

#[test]
fn a_failing_exchange_makes_the_gate_fail() {
    let mut fixture =
        ConformanceFixture::load(mcp_fixture_dir().join("2026-07-28.json")).expect("load fixture");
    let exchange = fixture
        .exchanges
        .iter_mut()
        .find(|exchange| exchange.expected.structured_content.is_some())
        .expect("the 2026 fixture has a structured-content call");
    exchange.expected.content = Some(vec![json!({"type": "text", "text": "wrong"})]);

    let dir = TempDir::new().expect("temp dir");
    write_file(
        dir.path(),
        "2026-07-28.json",
        &serde_json::to_string_pretty(&fixture).expect("serialize fixture"),
    );

    let report =
        conformance_gate::evaluate(&GateInputs::from_dirs(dir.path(), protocol_fixture_dir()));

    assert!(!report.ok);
    assert!(
        report.mcp_revisions.contains(&McpRevision::V2026_07_28),
        "a replayed fixture still covers its revision"
    );
    assert!(report.failures.iter().any(|failure| matches!(
        failure,
        GateFailure::ExchangeFailed { fixture, .. } if fixture == "conformance-2026-07-28"
    )));
}

#[test]
fn a_protocol_decode_failure_is_listed_with_its_fixture() {
    let dir = TempDir::new().expect("temp dir");
    for class in REQUIRED_PROTOCOL_CLASSES {
        let name = format!("{class}.json");
        std::fs::copy(protocol_fixture_dir().join(&name), dir.path().join(&name))
            .unwrap_or_else(|error| panic!("copy {name}: {error}"));
    }
    write_file(
        dir.path(),
        "v1-frames.json",
        r#"[{"v": 1, "kind": "not-a-frame", "correlation": "c", "payload": {}}]"#,
    );

    let report = conformance_gate::evaluate(&GateInputs::from_dirs(mcp_fixture_dir(), dir.path()));

    assert!(!report.ok);
    assert_eq!(report.failures.len(), 1, "{:?}", report.failures);
    assert!(matches!(
        &report.failures[0],
        GateFailure::ProtocolDecode { path, .. } if path.ends_with("v1-frames.json")
    ));
}

#[test]
fn a_missing_protocol_class_is_listed() {
    let dir = TempDir::new().expect("temp dir");
    std::fs::copy(
        protocol_fixture_dir().join("v1-frames.json"),
        dir.path().join("v1-frames.json"),
    )
    .expect("copy frames golden");

    let inputs = GateInputs {
        protocol_fixtures: vec![ProtocolFixture {
            class: "v1-frames".to_string(),
            json: dir.path().join("v1-frames.json"),
        }],
        ..GateInputs::from_dirs(mcp_fixture_dir(), protocol_fixture_dir())
    };
    let report = conformance_gate::evaluate(&inputs);

    assert!(!report.ok);
    assert!(report
        .failures
        .contains(&GateFailure::MissingProtocolClass {
            class: "v1-stream".to_string(),
        }));
}
