//! Conformance fixture replay for both supported revisions (T-MCP-11, MCP-19).
//!
//! Every fixture under `tests/fixtures/conformance/` is loaded, validated, and
//! replayed through the real client types. Mutated fixtures must produce typed
//! errors or typed report failures; none of these tests may panic through the
//! runner.

use std::collections::BTreeSet;
use std::path::PathBuf;

use serde_json::json;
use zero_mcp::conformance::{self, ConformanceError, ConformanceFailureKind, ConformanceFixture};
use zero_mcp::McpRevision;

fn fixture_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/conformance")
}

fn fixture_paths() -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = std::fs::read_dir(fixture_dir())
        .unwrap_or_else(|error| panic!("read {}: {error}", fixture_dir().display()))
        .map(|entry| entry.expect("directory entry").path())
        .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("json"))
        .collect();
    paths.sort();
    paths
}

fn fixture_2026() -> ConformanceFixture {
    ConformanceFixture::load(fixture_dir().join("2026-07-28.json"))
        .expect("the checked-in 2026 fixture must load")
}

#[test]
fn every_conformance_fixture_passes_and_both_revisions_are_covered() {
    let paths = fixture_paths();
    assert!(
        paths.len() >= 2,
        "expected a fixture for each revision, found {}",
        paths.len()
    );

    let mut revisions = BTreeSet::new();
    let mut exchanges = 0usize;
    for path in paths {
        let fixture = ConformanceFixture::load(&path)
            .unwrap_or_else(|error| panic!("load {}: {error}", path.display()));
        assert_eq!(fixture.schema_version, 1);
        let report = conformance::run(&fixture)
            .unwrap_or_else(|error| panic!("replay {}: {error}", path.display()));

        assert!(
            report.is_success(),
            "{} failed: {:?}",
            path.display(),
            report.failures()
        );
        assert_eq!(report.passed(), fixture.exchanges.len());
        assert_eq!(report.failed(), 0);
        assert!(report.failures().is_empty());
        revisions.insert(report.revision);
        exchanges += fixture.exchanges.len();
    }

    assert_eq!(
        revisions,
        BTreeSet::from([McpRevision::V2025_11_25, McpRevision::V2026_07_28]),
        "the suite must cover both supported revisions"
    );
    assert!(
        exchanges >= 10,
        "both fixtures should cover every revision-specific branch"
    );
}

#[test]
fn a_bad_expectation_is_a_typed_report_failure_not_a_panic() {
    let mut fixture = fixture_2026();
    let exchange = fixture
        .exchanges
        .iter_mut()
        .find(|exchange| exchange.expected.structured_content.is_some())
        .expect("the 2026 fixture has a structured-content call");
    exchange.expected.content = Some(vec![json!({"type": "text", "text": "wrong"})]);

    let report = conformance::run(&fixture).expect("a mismatch is a report failure, not an error");
    assert_eq!(report.failed(), 1);
    assert!(!report.is_success());
    let failures = report.failures();
    assert_eq!(failures.len(), 1);
    assert_eq!(
        failures[0].kind,
        ConformanceFailureKind::ExpectationMismatch
    );
    assert!(failures[0].detail.contains("content"));
}

#[test]
fn a_wrong_request_id_is_a_typed_fixture_error() {
    let mut fixture = fixture_2026();
    fixture.exchanges[0].request["id"] = json!(99);
    let error = conformance::run(&fixture).expect_err("a wrong request id must be rejected");
    assert!(
        matches!(error, ConformanceError::InvalidExchange { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn a_wrong_response_id_is_a_typed_fixture_error() {
    let mut fixture = fixture_2026();
    fixture.exchanges[1].response["id"] = json!(1);
    let error = conformance::run(&fixture).expect_err("a wrong response id must be rejected");
    assert!(
        matches!(error, ConformanceError::InvalidExchange { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn an_unknown_schema_version_is_a_typed_fixture_error() {
    let mut fixture = fixture_2026();
    fixture.schema_version = 99;
    let error = conformance::run(&fixture).expect_err("an unknown schema version must be rejected");
    assert!(
        matches!(
            error,
            ConformanceError::UnsupportedSchemaVersion { version: 99, .. }
        ),
        "unexpected error: {error}"
    );
}

#[test]
fn a_fixture_with_no_exchanges_is_rejected() {
    let mut fixture = fixture_2026();
    fixture.exchanges.clear();
    let error = conformance::run(&fixture).expect_err("an empty fixture must be rejected");
    assert!(
        matches!(error, ConformanceError::NoExchanges { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn a_response_with_the_wrong_revision_is_rejected() {
    let mut fixture = fixture_2026();
    fixture.exchanges[0].response["result"]["protocolVersion"] = json!("2025-11-25");
    let error = conformance::run(&fixture)
        .expect_err("a response revision different from the fixture must be rejected");
    assert!(
        matches!(error, ConformanceError::InvalidExchange { .. }),
        "unexpected error: {error}"
    );
}

#[test]
fn malformed_json_is_a_typed_parse_error() {
    let error = ConformanceFixture::from_json("{ not json").expect_err("malformed JSON must fail");
    assert!(
        matches!(error, ConformanceError::Parse { .. }),
        "unexpected error: {error}"
    );
}
