//! Provider error mapping (PRV-07): HTTP and transport failures become stable
//! codes with one remediation each. A fixture per code lives in the tests.

use zero_types::error::{ErrorCode, ZeroError};

/// Map an HTTP error response. `body` may include the provider's message.
pub fn map_status(status: u16, body: &str, retry_after_secs: Option<u64>) -> ZeroError {
    let lower = body.to_ascii_lowercase();
    let code = match status {
        400 | 404 | 422 => {
            if lower.contains("context_length") || lower.contains("maximum context") || lower.contains("too many tokens") {
                ErrorCode::ProviderContextLength
            } else if lower.contains("content_filter") || lower.contains("content policy") || lower.contains("safety") {
                ErrorCode::ProviderContentFilter
            } else if lower.contains("does not support tool") || lower.contains("tool use is not supported") {
                ErrorCode::ProviderNoTools
            } else {
                ErrorCode::ProviderBadRequest
            }
        }
        401 | 403 => ErrorCode::ProviderAuth,
        408 => ErrorCode::ProviderTimeout,
        413 => ErrorCode::ProviderContextLength,
        429 => ErrorCode::ProviderRateLimited,
        503 | 529 => ErrorCode::ProviderOverloaded,
        500 | 502 | 504 | 520..=599 => ErrorCode::ProviderUnavailable,
        _ => ErrorCode::ProviderProtocol,
    };
    let transient = matches!(
        code,
        ErrorCode::ProviderRateLimited | ErrorCode::ProviderOverloaded | ErrorCode::ProviderTimeout | ErrorCode::ProviderUnavailable
    );
    let retry = if transient {
        if let Some(secs) = retry_after_secs {
            format!(" (retry after {secs}s)")
        } else {
            String::new()
        }
    } else {
        String::new()
    };
    ZeroError::new(code, format!("provider returned HTTP {status}{retry}: {}", truncate(body)))
}

pub fn map_transport(kind: &str, detail: &str) -> ZeroError {
    let code = match kind {
        "timeout" => ErrorCode::ProviderTimeout,
        "connect" | "dns" | "offline" => ErrorCode::ProviderUnavailable,
        "body" | "stream" | "incomplete" => ErrorCode::ProviderStreamBroken,
        _ => ErrorCode::ProviderProtocol,
    };
    ZeroError::new(code, format!("provider transport {kind}: {}", truncate(detail)))
}

pub fn malformed_body(detail: &str) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, format!("provider response did not match the schema: {}", truncate(detail)))
}

pub fn map_reqwest(error: &reqwest::Error) -> ZeroError {
    let kind = if error.is_timeout() {
        "timeout"
    } else if error.is_connect() {
        "connect"
    } else if error.is_body() || error.is_decode() {
        "body"
    } else {
        "other"
    };
    map_transport(kind, &error.to_string())
}

pub fn retry_after(headers: &reqwest::header::HeaderMap) -> Option<u64> {
    headers
        .get(reqwest::header::RETRY_AFTER)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.trim().parse().ok())
}

fn truncate(body: &str) -> String {
    let body = body.trim();
    if body.len() <= 240 {
        body.to_string()
    } else {
        format!("{}…", &body[..240])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_fixture_for_every_error_code() {
        let cases: &[(u16, &str, Option<u64>, ErrorCode)] = &[
            (400, "invalid request", None, ErrorCode::ProviderBadRequest),
            (400, "maximum context length exceeded", None, ErrorCode::ProviderContextLength),
            (413, "", None, ErrorCode::ProviderContextLength),
            (400, "content_filter triggered", None, ErrorCode::ProviderContentFilter),
            (400, "this model does not support tools", None, ErrorCode::ProviderNoTools),
            (401, "bad key", None, ErrorCode::ProviderAuth),
            (403, "forbidden", None, ErrorCode::ProviderAuth),
            (408, "timeout", None, ErrorCode::ProviderTimeout),
            (429, "rate limited", Some(12), ErrorCode::ProviderRateLimited),
            (500, "boom", None, ErrorCode::ProviderUnavailable),
            (502, "bad gateway", None, ErrorCode::ProviderUnavailable),
            (503, "overloaded", None, ErrorCode::ProviderOverloaded),
            (529, "overloaded", None, ErrorCode::ProviderOverloaded),
            (418, "teapot", None, ErrorCode::ProviderProtocol),
        ];
        for (status, body, retry, expected) in cases {
            let err = map_status(*status, body, *retry);
            assert_eq!(err.code(), *expected, "{status} {body}");
            assert!(!err.remediation().is_empty());
        }
        let limited = map_status(429, "slow down", Some(30));
        assert!(limited.message().contains("retry after 30s"), "{}", limited.message());
    }

    #[test]
    fn transport_fixtures_map_to_codes() {
        let cases = [
            ("timeout", ErrorCode::ProviderTimeout),
            ("connect", ErrorCode::ProviderUnavailable),
            ("dns", ErrorCode::ProviderUnavailable),
            ("body", ErrorCode::ProviderStreamBroken),
            ("incomplete", ErrorCode::ProviderStreamBroken),
            ("other", ErrorCode::ProviderProtocol),
        ];
        for (kind, code) in cases {
            assert_eq!(map_transport(kind, "detail").code(), code, "{kind}");
        }
        assert_eq!(malformed_body("x").code(), ErrorCode::ProviderProtocol);
    }
}
