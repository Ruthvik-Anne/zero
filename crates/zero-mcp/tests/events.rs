//! MCP events fixtures (T-MCP-05, MCP-05, MCP-10).
//!
//! Every poll is scripted in memory and every webhook is verified locally; no
//! test opens a socket, parses a real clock, or depends on system time.

use std::cell::RefCell;
use std::collections::VecDeque;
use std::sync::Arc;

use serde_json::json;
use zero_mcp::Headers;
use zero_mcp::{
    resync_required, verify_webhook, Event, EventBatch, EventCursor, EventPollOutcome, EventPoller,
    EventSource, HmacSha256Verifier, WebhookOutcome, WebhookReceiver, HEADER_EVENT_KEY_ID,
    HEADER_EVENT_SIGNATURE, HEADER_EVENT_TIMESTAMP, MAX_SEEN_EVENT_IDS,
};
use zero_types::clock::FakeClock;
use zero_types::error::{ErrorCode, Result};

const KEY_ID: &str = "key-1";
const SECRET: &str = "webhook-secret";
const NOW_MS: i64 = 10_000;
const TOLERANCE_MS: u64 = 1_000;

fn event(id: &str) -> Event {
    Event::new(id, "resource_updated", json!({"id": id, "status": "ok"}), 0)
}

fn batch(ids: &[&str], cursor: &str, ttl_ms: Option<u64>) -> EventBatch {
    EventBatch::new(
        ids.iter().map(|id| event(id)).collect(),
        Some(EventCursor::new(cursor)),
        ttl_ms,
    )
}

fn ids(batch: &EventBatch) -> Vec<&str> {
    batch.events.iter().map(|event| event.id.as_str()).collect()
}

struct ScriptedSource {
    replies: RefCell<VecDeque<Result<EventBatch>>>,
    cursors: RefCell<Vec<Option<EventCursor>>>,
}

impl ScriptedSource {
    fn new(replies: Vec<Result<EventBatch>>) -> Self {
        Self {
            replies: RefCell::new(VecDeque::from(replies)),
            cursors: RefCell::new(Vec::new()),
        }
    }

    fn cursors(&self) -> Vec<Option<String>> {
        self.cursors
            .borrow()
            .iter()
            .map(|cursor| cursor.as_ref().map(|cursor| cursor.as_str().to_string()))
            .collect()
    }
}

impl EventSource for ScriptedSource {
    fn poll(&self, cursor: Option<&EventCursor>) -> Result<EventBatch> {
        self.cursors.borrow_mut().push(cursor.cloned());
        match self.replies.borrow_mut().pop_front() {
            Some(reply) => reply,
            None => Ok(EventBatch::new(Vec::new(), cursor.cloned(), None)),
        }
    }
}

#[test]
fn polling_follows_cursor_order_and_advances() {
    let source = ScriptedSource::new(vec![
        Ok(batch(&["e1"], "c1", Some(60_000))),
        Ok(EventBatch::new(
            vec![event("e2"), event("e3")],
            Some(EventCursor::new("c2")),
            None,
        )),
    ]);
    let mut poller = EventPoller::new(&source).with_clock(Arc::new(FakeClock::at(0)));

    match poller.poll_once().unwrap() {
        EventPollOutcome::Batch(batch) => {
            assert_eq!(ids(&batch), vec!["e1"]);
            assert_eq!(batch.next_cursor.as_ref().unwrap().as_str(), "c1");
            assert_eq!(batch.ttl_ms, Some(60_000));
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(poller.cursor().map(EventCursor::as_str), Some("c1"));

    match poller.poll_once().unwrap() {
        EventPollOutcome::Batch(batch) => {
            assert_eq!(ids(&batch), vec!["e2", "e3"]);
            assert_eq!(batch.next_cursor.as_ref().unwrap().as_str(), "c2");
        }
        other => panic!("unexpected outcome: {other:?}"),
    }
    assert_eq!(poller.cursor().map(EventCursor::as_str), Some("c2"));
    assert_eq!(
        source.cursors(),
        vec![None, Some("c1".to_string())],
        "the poller must send the cursor the previous batch returned"
    );
}

#[test]
fn expired_cursor_requires_resync_and_never_skips() {
    let source = ScriptedSource::new(vec![
        Ok(batch(&["e1"], "stale", None)),
        Err(resync_required("cursor expired at the source")),
        Ok(EventBatch::new(
            vec![event("e1"), event("e2")],
            Some(EventCursor::new("fresh")),
            None,
        )),
    ]);
    let mut poller = EventPoller::new(&source);

    assert!(matches!(
        poller.poll_once().unwrap(),
        EventPollOutcome::Batch(_)
    ));
    assert_eq!(poller.cursor().map(EventCursor::as_str), Some("stale"));

    match poller.poll_once().unwrap() {
        EventPollOutcome::ResyncRequired(resync) => {
            assert_eq!(resync.reason(), "cursor expired at the source");
        }
        other => panic!("expected resync, got {other:?}"),
    }
    assert!(
        poller.cursor().is_none(),
        "a rejected cursor must be discarded, not kept"
    );

    match poller.poll_once().unwrap() {
        EventPollOutcome::Batch(batch) => {
            assert_eq!(
                ids(&batch),
                vec!["e1", "e2"],
                "resync replays from the oldest retained event"
            );
        }
        other => panic!("expected a replay batch, got {other:?}"),
    }
    assert_eq!(
        source.cursors(),
        vec![None, Some("stale".to_string()), None],
        "resync must restart without a cursor"
    );
}

#[test]
fn ttl_renews_and_an_expired_subscription_requires_resubscribe() {
    let clock = Arc::new(FakeClock::at(1_000));
    let source = ScriptedSource::new(vec![
        Ok(batch(&["e1"], "c1", Some(1_000))),
        Ok(batch(&["e2"], "c2", None)),
    ]);
    let mut poller = EventPoller::new(&source).with_clock(clock.clone());

    assert!(matches!(
        poller.poll_once().unwrap(),
        EventPollOutcome::Batch(_)
    ));
    assert_eq!(poller.expires_at_ms(), Some(2_000));

    clock.advance(500);
    assert!(!poller.is_expired());
    assert_eq!(poller.renew(5_000).unwrap(), 6_500);
    assert_eq!(poller.expires_at_ms(), Some(6_500));

    clock.advance(4_999);
    assert!(!poller.is_expired());
    clock.advance(1);
    assert!(poller.is_expired());

    let error = poller.poll_once().unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderTimeout);
    assert!(error.message().contains("resubscribe"));
    assert_eq!(poller.cursor().map(EventCursor::as_str), Some("c1"));

    let error = poller.renew(1_000).unwrap_err();
    assert_eq!(
        error.code(),
        ErrorCode::ProviderTimeout,
        "renewal must not revive an expired subscription"
    );

    poller.resubscribe();
    assert!(!poller.is_expired());
    assert!(poller.cursor().is_none());
    assert!(poller.expires_at_ms().is_none());

    match poller.poll_once().unwrap() {
        EventPollOutcome::Batch(batch) => assert_eq!(ids(&batch), vec!["e2"]),
        other => panic!("expected a fresh batch, got {other:?}"),
    }
    assert_eq!(source.cursors().last().unwrap().as_ref(), None::<&String>);
}

#[test]
fn a_zero_ttl_expires_immediately_after_delivery() {
    let clock = Arc::new(FakeClock::at(0));
    let source = ScriptedSource::new(vec![Ok(batch(&["e1"], "c1", Some(0)))]);
    let mut poller = EventPoller::new(&source).with_clock(clock.clone());

    assert!(
        matches!(poller.poll_once().unwrap(), EventPollOutcome::Batch(_)),
        "the batch that carried the lease is still delivered"
    );
    assert_eq!(poller.expires_at_ms(), Some(0));
    assert!(poller.is_expired());
    assert_eq!(
        poller.poll_once().unwrap_err().code(),
        ErrorCode::ProviderTimeout
    );
}

#[test]
fn poll_until_idle_stops_at_the_attempt_bound() {
    let replies = (0..10)
        .map(|index| {
            Ok(EventBatch::new(
                vec![event(&format!("e{index}"))],
                Some(EventCursor::new(format!("c{index}"))),
                None,
            ))
        })
        .collect();
    let source = ScriptedSource::new(replies);
    let mut poller = EventPoller::new(&source);

    let summary = poller.poll_until_idle(3).unwrap();
    assert_eq!(summary.batches, 3);
    assert_eq!(summary.events.len(), 3);
    assert!(!summary.idle);
    assert!(summary.resync_required.is_none());
    assert_eq!(poller.cursor().map(EventCursor::as_str), Some("c2"));

    let summary = poller.poll_until_idle(1).unwrap();
    assert_eq!(summary.events.len(), 1);
    assert_eq!(summary.events[0].id, "e3");

    assert_eq!(
        poller.poll_until_idle(0).unwrap_err().code(),
        ErrorCode::InvalidInput
    );
}

#[test]
fn poll_until_idle_stops_on_an_empty_batch() {
    let source = ScriptedSource::new(vec![
        Ok(batch(&["e1"], "c1", None)),
        Ok(EventBatch::new(
            Vec::new(),
            Some(EventCursor::new("c1")),
            None,
        )),
    ]);
    let mut poller = EventPoller::new(&source);

    let summary = poller.poll_until_idle(5).unwrap();
    assert_eq!(summary.batches, 2);
    assert_eq!(summary.events.len(), 1);
    assert!(summary.idle);
    assert!(summary.resync_required.is_none());
}

#[test]
fn poll_until_idle_reports_resync_with_the_events_it_had() {
    let source = ScriptedSource::new(vec![
        Ok(batch(&["e1"], "c1", None)),
        Err(resync_required("retention window moved")),
    ]);
    let mut poller = EventPoller::new(&source);

    let summary = poller.poll_until_idle(5).unwrap();
    assert_eq!(summary.batches, 2);
    assert_eq!(summary.events.len(), 1);
    assert!(!summary.idle);
    assert_eq!(
        summary.resync_required.as_ref().unwrap().reason(),
        "retention window moved"
    );
}

#[test]
fn a_malformed_event_fails_the_batch_without_advancing_the_cursor() {
    let source = ScriptedSource::new(vec![Ok(EventBatch::new(
        vec![Event::new("", "resource_updated", json!({}), 0)],
        Some(EventCursor::new("c1")),
        None,
    ))]);
    let mut poller = EventPoller::new(&source);

    let error = poller.poll_once().unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(
        poller.cursor().is_none(),
        "a rejected batch must not consume the cursor"
    );
}

fn verifier() -> HmacSha256Verifier {
    HmacSha256Verifier::new().with_key(KEY_ID, SECRET)
}

fn headers(timestamp_ms: i64, signature: &str) -> Headers {
    let mut headers = Headers::new();
    headers.insert(HEADER_EVENT_KEY_ID, KEY_ID);
    headers.insert(HEADER_EVENT_SIGNATURE, signature);
    headers.insert(HEADER_EVENT_TIMESTAMP, timestamp_ms.to_string());
    headers
}

fn signed_headers(verifier: &HmacSha256Verifier, body: &[u8], timestamp_ms: i64) -> Headers {
    let signature = verifier.sign_hex(KEY_ID, body).expect("fixture key");
    headers(timestamp_ms, &signature)
}

const BODY: &[u8] = br#"{"id":"evt-1","kind":"resource_updated","payload":{"status":"ok"}}"#;

#[test]
fn a_valid_signature_is_accepted_in_lower_upper_and_prefixed_hex() {
    let verifier = verifier();
    let signature = verifier.sign_hex(KEY_ID, BODY).unwrap();

    let event = verify_webhook(
        &headers(NOW_MS, &signature),
        BODY,
        &verifier,
        NOW_MS,
        TOLERANCE_MS,
    )
    .unwrap();
    assert_eq!(event.id, "evt-1");
    assert_eq!(event.kind, "resource_updated");
    assert_eq!(event.payload["payload"]["status"], "ok");
    assert_eq!(event.delivered_at_ms, NOW_MS);

    let upper = headers(NOW_MS, &signature.to_ascii_uppercase());
    assert!(verify_webhook(&upper, BODY, &verifier, NOW_MS, TOLERANCE_MS).is_ok());

    let prefixed = headers(NOW_MS, &format!("sha256={signature}"));
    assert!(verify_webhook(&prefixed, BODY, &verifier, NOW_MS, TOLERANCE_MS).is_ok());
}

#[test]
fn invalid_signatures_and_tampered_bodies_are_rejected() {
    let verifier = verifier();
    let signature = verifier.sign_hex(KEY_ID, BODY).unwrap();

    let invalid = headers(NOW_MS, &"0".repeat(64));
    let error = verify_webhook(&invalid, BODY, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(error.message().contains("signature"));
    assert!(
        !error.message().contains(&"0".repeat(64)),
        "the signature must never be echoed"
    );

    let tampered = signed_headers(&verifier, BODY, NOW_MS);
    let error = verify_webhook(
        &tampered,
        b"{\"id\":\"evt-2\"}",
        &verifier,
        NOW_MS,
        TOLERANCE_MS,
    )
    .unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(error.message().contains("signature"));

    let mut unknown_key = headers(NOW_MS, &signature);
    unknown_key.insert(HEADER_EVENT_KEY_ID, "key-2");
    let error = verify_webhook(&unknown_key, BODY, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(!error.message().contains("key-2"));
}

#[test]
fn every_missing_or_empty_header_is_rejected() {
    let verifier = verifier();
    let signature = verifier.sign_hex(KEY_ID, BODY).unwrap();

    for name in [
        HEADER_EVENT_KEY_ID,
        HEADER_EVENT_SIGNATURE,
        HEADER_EVENT_TIMESTAMP,
    ] {
        let mut missing = headers(NOW_MS, &signature);
        missing.remove(name);
        let error = verify_webhook(&missing, BODY, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains(name));

        let mut empty = headers(NOW_MS, &signature);
        empty.insert(name, "");
        let error = verify_webhook(&empty, BODY, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains("must not be empty"));
    }
}

#[test]
fn timestamps_outside_the_replay_window_are_rejected() {
    let verifier = verifier();

    for timestamp in [NOW_MS - TOLERANCE_MS as i64, NOW_MS + TOLERANCE_MS as i64] {
        let headers = signed_headers(&verifier, BODY, timestamp);
        assert!(
            verify_webhook(&headers, BODY, &verifier, NOW_MS, TOLERANCE_MS).is_ok(),
            "the boundary is inside the window"
        );
    }

    for timestamp in [
        NOW_MS - TOLERANCE_MS as i64 - 1,
        NOW_MS + TOLERANCE_MS as i64 + 1,
    ] {
        let headers = signed_headers(&verifier, BODY, timestamp);
        let error = verify_webhook(&headers, BODY, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol);
        assert!(error.message().contains("replay window"));
    }

    let bad_timestamp = signed_headers(&verifier, BODY, NOW_MS);
    let mut malformed = bad_timestamp.clone();
    malformed.insert(HEADER_EVENT_TIMESTAMP, "not-a-number");
    let error = verify_webhook(&malformed, BODY, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(error.message().contains("Unix milliseconds"));
}

#[test]
fn signature_checks_run_before_json_parsing() {
    let verifier = verifier();
    let malformed_body = br#"{"id":"evt-1""#;

    let missing = Headers::new();
    let error =
        verify_webhook(&missing, malformed_body, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert!(error.message().contains("missing"));
    assert!(!error.message().contains("JSON"));

    let wrong_signature = headers(NOW_MS, &"0".repeat(64));
    let error = verify_webhook(
        &wrong_signature,
        malformed_body,
        &verifier,
        NOW_MS,
        TOLERANCE_MS,
    )
    .unwrap_err();
    assert!(error.message().contains("signature"));
    assert!(!error.message().contains("JSON"));

    let valid = signed_headers(&verifier, malformed_body, NOW_MS);
    let error =
        verify_webhook(&valid, malformed_body, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(error.message().contains("valid JSON"));
}

#[test]
fn a_duplicate_event_is_reported_without_redelivery() {
    let mut receiver = WebhookReceiver::new(verifier()).with_tolerance_ms(TOLERANCE_MS);
    let body = br#"{"id":"evt-1"}"#;
    let headers = signed_headers(&verifier(), body, NOW_MS);

    match receiver.receive(&headers, body, NOW_MS).unwrap() {
        WebhookOutcome::Deliver(event) => assert_eq!(event.id, "evt-1"),
        other => panic!("expected delivery, got {other:?}"),
    }
    match receiver.receive(&headers, body, NOW_MS).unwrap() {
        WebhookOutcome::Duplicate { event_id } => assert_eq!(event_id, "evt-1"),
        other => panic!("expected duplicate, got {other:?}"),
    }
    assert_eq!(receiver.seen_len(), 1);
}

#[test]
fn the_seen_set_evicts_the_oldest_id_at_its_bound() {
    assert_eq!(MAX_SEEN_EVENT_IDS, 1024);
    let mut receiver = WebhookReceiver::new(verifier())
        .with_tolerance_ms(TOLERANCE_MS)
        .with_seen_capacity(2);

    let deliver = |receiver: &mut WebhookReceiver<HmacSha256Verifier>, id: &str| {
        let body = format!(r#"{{"id":"{id}"}}"#).into_bytes();
        let headers = signed_headers(&verifier(), &body, NOW_MS);
        receiver.receive(&headers, &body, NOW_MS).unwrap()
    };

    for id in ["a", "b"] {
        assert!(matches!(
            deliver(&mut receiver, id),
            WebhookOutcome::Deliver(_)
        ));
    }
    assert!(matches!(
        deliver(&mut receiver, "a"),
        WebhookOutcome::Duplicate { .. }
    ));

    assert!(matches!(
        deliver(&mut receiver, "c"),
        WebhookOutcome::Deliver(_)
    ));
    assert_eq!(receiver.seen_len(), 2);
    assert!(
        matches!(deliver(&mut receiver, "a"), WebhookOutcome::Deliver(_)),
        "an evicted id may be delivered again"
    );
    assert_eq!(receiver.seen_len(), 2);
}

#[test]
fn malformed_event_payloads_are_protocol_errors() {
    let verifier = verifier();
    let cases: [(&[u8], &str); 6] = [
        (br#"{"kind":"resource_updated"}"#, "missing `id`"),
        (br#"{"id":123}"#, "`id` must be a string"),
        (br#"{"id":""}"#, "`id` must not be empty"),
        (br#"[1,2]"#, "JSON object"),
        (br#"null"#, "JSON object"),
        (br#"{"id":"evt-1","kind":7}"#, "`kind` must be a string"),
    ];

    for (body, expected) in cases {
        let headers = signed_headers(&verifier, body, NOW_MS);
        let error = verify_webhook(&headers, body, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
        assert_eq!(error.code(), ErrorCode::ProviderProtocol, "body {body:?}");
        assert!(
            error.message().contains(expected),
            "unexpected message for {body:?}: {}",
            error.message()
        );
    }
}

#[test]
fn raw_payloads_and_signatures_never_reach_an_error_message() {
    const MARKER: &str = "do-not-echo-this-payload";
    let verifier = verifier();

    let body = format!(r#"{{"id":123,"payload":"{MARKER}"}}"#).into_bytes();
    let headers = signed_headers(&verifier, &body, NOW_MS);
    let error = verify_webhook(&headers, &body, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert_eq!(error.code(), ErrorCode::ProviderProtocol);
    assert!(!error.message().contains(MARKER));
    assert!(!format!("{error}").contains(MARKER));

    let broken = format!(r#"{{"payload":"{MARKER}"#).into_bytes();
    let headers = signed_headers(&verifier, &broken, NOW_MS);
    let error = verify_webhook(&headers, &broken, &verifier, NOW_MS, TOLERANCE_MS).unwrap_err();
    assert!(!error.message().contains(MARKER));
    assert!(!format!("{error}").contains(MARKER));
}
