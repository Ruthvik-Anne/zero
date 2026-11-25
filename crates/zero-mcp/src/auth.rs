//! OAuth 2.1 authorization for remote MCP servers (T-MCP-07, MCP-07, MCP-13).
//!
//! MCP servers are OAuth 2.1 resource servers; this module is the client half:
//!
//! - Authorization Server Metadata discovery (RFC 8414 first, then OpenID
//!   Connect Discovery 1.0) with strict issuer validation.
//! - An authorization-code request with PKCE `S256`, `state`, and the RFC 8707
//!   `resource` parameter set to the canonical MCP server URL.
//! - Public-client code exchange and refresh (no client secret) on a scriptable
//!   [`TokenTransport`] seam.
//! - Access-token binding checks for issuer, resource, client id, audience, and
//!   expiry, so a token minted for one MCP server cannot be replayed to another.
//! - Client ID Metadata Document (CIMD) validation, the primary registration
//!   mechanism in the MCP authorization specification.
//!
//! Everything is offline by default in tests: [`MetadataFetcher`] and
//! [`TokenTransport`] are traits, and the shipped implementations use blocking
//! `reqwest`. No token, verifier, or metadata body is ever copied into a
//! `ZeroError`, and the token-bearing types have redacting `Debug` forms.
//!
//! Deliberately not implemented here: JWT/JWKS signature verification (the
//! token is treated as opaque), issuer metadata caching, DCR (only the
//! `registration_endpoint` is parsed), and enterprise managed authorization.
//! See `docs/mcp.md`.

use std::collections::BTreeMap;
use std::fmt;
use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use reqwest::Url;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Default timeout for one metadata or token HTTP request.
pub const DEFAULT_AUTH_TIMEOUT: Duration = Duration::from_secs(30);
/// Bound on one client metadata document read by this crate.
pub const MAX_CLIENT_METADATA_BYTES: usize = 64 * 1024;
/// Bound on one token endpoint response read by this crate.
pub const MAX_TOKEN_RESPONSE_BYTES: usize = 64 * 1024;
/// Bound on the redirect URI list in a client metadata document.
pub const MAX_REDIRECT_URIS: usize = 16;
/// Bound on a `state` value, in bytes.
pub const MAX_STATE_BYTES: usize = 512;
/// RFC 8414 well-known suffix.
pub const WELL_KNOWN_AUTHORIZATION_SERVER: &str = "/.well-known/oauth-authorization-server";
/// OpenID Connect Discovery 1.0 well-known suffix.
pub const WELL_KNOWN_OPENID_CONFIGURATION: &str = "/.well-known/openid-configuration";
/// The only PKCE challenge method this client uses.
pub const PKCE_METHOD_S256: &str = "S256";

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn protocol(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderProtocol, message)
}

fn auth_error(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::ProviderAuth, message)
}

fn unsupported(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unsupported, message)
}

/// Whether the URL host is a loopback address used by explicit test servers.
fn is_loopback_host(url: &Url) -> bool {
    matches!(
        url.host_str(),
        Some("127.0.0.1") | Some("::1") | Some("localhost")
    )
}

/// Whether the URL host is the IPv4 loopback literal, the only host allowed to
/// use plain `http` for an issuer or an authorization-server endpoint.
fn is_explicit_test_host(url: &Url) -> bool {
    url.host_str() == Some("127.0.0.1")
}

fn require_no_userinfo(url: &Url, label: &str) -> Result<()> {
    if !url.username().is_empty() || url.password().is_some() {
        return Err(invalid(format!("{label} must not contain userinfo")));
    }
    Ok(())
}

fn require_host(url: &Url, label: &str) -> Result<()> {
    match url.host_str() {
        Some(host) if !host.is_empty() => Ok(()),
        _ => Err(invalid(format!("{label} must have a host"))),
    }
}

fn require_transport_security(url: &Url, label: &str) -> Result<()> {
    match url.scheme() {
        "https" => Ok(()),
        "http" if is_explicit_test_host(url) => Ok(()),
        "http" => Err(invalid(format!(
            "{label} must use https; plain http is allowed only for 127.0.0.1 test servers"
        ))),
        other => Err(invalid(format!("{label} must use https, got `{other}`"))),
    }
}

/// Validate an issuer identifier.
///
/// The issuer is `https`, except for an explicit `127.0.0.1` test server where
/// plain `http` is allowed. It has a host, no userinfo, no query, and no
/// fragment, so two issuers can only compare equal when they identify the same
/// URL exactly. Comparison never uses a prefix or a normalised host suffix.
pub fn validate_issuer_url(issuer: &Url) -> Result<()> {
    require_host(issuer, "issuer")?;
    require_transport_security(issuer, "issuer")?;
    require_no_userinfo(issuer, "issuer")?;
    if issuer.query().is_some() {
        return Err(invalid("issuer must not contain a query"));
    }
    if issuer.fragment().is_some() {
        return Err(invalid("issuer must not contain a fragment"));
    }
    Ok(())
}

/// Validate an authorization-server endpoint URL.
fn validate_endpoint_url(url: &Url, label: &str) -> Result<()> {
    require_host(url, label)?;
    require_transport_security(url, label)?;
    require_no_userinfo(url, label)?;
    if url.fragment().is_some() {
        return Err(invalid(format!("{label} must not contain a fragment")));
    }
    Ok(())
}

/// Validate a redirect URI under OAuth 2.1: `https`, or plain `http` for a
/// loopback host (`127.0.0.1`, `::1`, or `localhost`). Fragments and userinfo
/// are refused because they are not part of an exact registered redirect.
pub fn validate_redirect_uri(value: &str) -> Result<Url> {
    let url = Url::parse(value).map_err(|_| invalid("redirect URI is not a valid absolute URL"))?;
    require_host(&url, "redirect URI")?;
    match url.scheme() {
        "https" => {}
        "http" if is_loopback_host(&url) => {}
        "http" => {
            return Err(invalid(
                "redirect URI must use https, or http on a loopback host",
            ))
        }
        other => {
            return Err(invalid(format!(
                "redirect URI must use https, got `{other}`"
            )))
        }
    }
    require_no_userinfo(&url, "redirect URI")?;
    if url.fragment().is_some() {
        return Err(invalid("redirect URI must not contain a fragment"));
    }
    Ok(url)
}

/// Validate an MCP server resource URL: `https` (or `http` on `127.0.0.1` for
/// tests), a host, no userinfo, and no fragment.
pub fn validate_mcp_server_url(url: &Url) -> Result<()> {
    require_host(url, "MCP server URL")?;
    require_transport_security(url, "MCP server URL")?;
    require_no_userinfo(url, "MCP server URL")?;
    if url.fragment().is_some() {
        return Err(invalid("MCP server URL must not contain a fragment"));
    }
    Ok(())
}

/// The canonical MCP server URL used as the RFC 8707 `resource` value.
///
/// The URL parser lowercases the scheme and host, drops a default port, and
/// percent-normalises the path, so two spellings of the same resource compare
/// equal. The fragment is removed because it is never part of a resource
/// identifier. A root URL retains the URL parser's `/` path, which is the same
/// resource as the bare origin.
pub fn canonical_resource(server_url: &Url) -> Result<Url> {
    validate_mcp_server_url(server_url)?;
    let mut canonical = server_url.clone();
    canonical.set_fragment(None);
    Ok(canonical)
}

// ---------------------------------------------------------------------------
// PKCE (RFC 7636), S256 only
// ---------------------------------------------------------------------------

const BASE64URL: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// Unpadded base64url, as required for a PKCE `code_challenge`.
fn base64url_nopad(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = u32::from(chunk[0]);
        let b1 = u32::from(chunk.get(1).copied().unwrap_or(0));
        let b2 = u32::from(chunk.get(2).copied().unwrap_or(0));
        let bits = (b0 << 16) | (b1 << 8) | b2;
        out.push(char::from(BASE64URL[((bits >> 18) & 63) as usize]));
        out.push(char::from(BASE64URL[((bits >> 12) & 63) as usize]));
        if chunk.len() > 1 {
            out.push(char::from(BASE64URL[((bits >> 6) & 63) as usize]));
        }
        if chunk.len() > 2 {
            out.push(char::from(BASE64URL[(bits & 63) as usize]));
        }
    }
    out
}

fn validate_verifier(verifier: &str) -> Result<()> {
    let len = verifier.len();
    if !(43..=128).contains(&len) {
        return Err(invalid("PKCE verifier must be 43 to 128 characters long"));
    }
    let valid = verifier
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~'));
    if !valid {
        return Err(invalid(
            "PKCE verifier may contain only letters, digits, `-`, `.`, `_`, and `~`",
        ));
    }
    Ok(())
}

fn s256_challenge(verifier: &str) -> String {
    base64url_nopad(&Sha256::digest(verifier.as_bytes()))
}

/// A PKCE verifier and its `S256` challenge.
///
/// The verifier is a secret for the duration of one authorization attempt. Its
/// `Debug` form is redacted; only [`Pkce::challenge`] is meant for the wire.
#[derive(Clone, PartialEq, Eq)]
pub struct Pkce {
    /// RFC 7636 verifier. It must come from a platform CSPRNG at the caller
    /// (`zero-mcp` sits below the crate that owns the OS entropy source).
    pub verifier: String,
    /// Base64url-encoded SHA-256 of the verifier, unpadded.
    pub challenge: String,
}

impl Pkce {
    /// Build a verifier/challenge pair from a caller-supplied CSPRNG verifier.
    pub fn from_verifier(verifier: impl Into<String>) -> Result<Self> {
        let verifier = verifier.into();
        validate_verifier(&verifier)?;
        let challenge = s256_challenge(&verifier);
        Ok(Self {
            verifier,
            challenge,
        })
    }

    /// Recompute the challenge and confirm this pair is internally consistent.
    ///
    /// This refuses a hand-built pair whose challenge does not match the
    /// verifier, so a caller cannot accidentally send `S256` with the wrong
    /// value.
    pub fn validate(&self) -> Result<()> {
        validate_verifier(&self.verifier)?;
        if self.challenge != s256_challenge(&self.verifier) {
            return Err(invalid(
                "PKCE challenge does not match the verifier for S256",
            ));
        }
        Ok(())
    }
}

impl fmt::Debug for Pkce {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Pkce")
            .field("verifier", &"[redacted]")
            .field("challenge", &self.challenge)
            .finish()
    }
}

// ---------------------------------------------------------------------------
// Authorization Server Metadata (RFC 8414, OIDC Discovery)
// ---------------------------------------------------------------------------

/// A discovered authorization server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizationServer {
    /// The issuer identifier, exactly as discovered and validated.
    pub issuer: Url,
    /// Authorization endpoint.
    pub authorization_endpoint: Url,
    /// Token endpoint.
    pub token_endpoint: Url,
    /// Dynamic Client Registration endpoint, when advertised. CIMD is the
    /// primary registration mechanism; this is parsed for the DCR fallback.
    pub registration_endpoint: Option<Url>,
    /// PKCE challenge methods the server advertises. [`PKCE_METHOD_S256`] must
    /// be present before an authorization attempt starts.
    pub code_challenge_methods_supported: Vec<String>,
    /// Whether the server advertises CIMD support via
    /// `client_id_metadata_document_supported`.
    pub client_id_metadata_document_supported: bool,
}

impl AuthorizationServer {
    /// Parse an RFC 8414 / OIDC metadata document and validate its identity.
    ///
    /// `expected_issuer` is the issuer the caller discovered out of band or
    /// from Protected Resource Metadata. The document's `issuer` must match it
    /// exactly (parsed-URL equality, never a prefix), and every endpoint must
    /// be `https` or a loopback test endpoint.
    pub fn from_metadata(expected_issuer: &Url, metadata: &Value) -> Result<Self> {
        validate_issuer_url(expected_issuer)?;
        let object = metadata
            .as_object()
            .ok_or_else(|| protocol("authorization server metadata must be a JSON object"))?;

        let issuer_raw = object
            .get("issuer")
            .and_then(Value::as_str)
            .ok_or_else(|| protocol("authorization server metadata is missing `issuer`"))?;
        let issuer = Url::parse(issuer_raw)
            .map_err(|_| protocol("authorization server metadata `issuer` is not a valid URL"))?;
        validate_issuer_url(&issuer)?;
        if &issuer != expected_issuer {
            return Err(auth_error(
                "authorization server metadata issuer does not match the expected issuer",
            ));
        }

        let authorization_endpoint = metadata_url(object, "authorization_endpoint")?;
        validate_endpoint_url(&authorization_endpoint, "authorization_endpoint")?;
        let token_endpoint = metadata_url(object, "token_endpoint")?;
        validate_endpoint_url(&token_endpoint, "token_endpoint")?;

        let registration_endpoint = match object.get("registration_endpoint") {
            None | Some(Value::Null) => None,
            Some(Value::String(raw)) => {
                let url = Url::parse(raw).map_err(|_| {
                    protocol(
                        "authorization server metadata `registration_endpoint` is not a valid URL",
                    )
                })?;
                validate_endpoint_url(&url, "registration_endpoint")?;
                Some(url)
            }
            Some(_) => {
                return Err(protocol(
                    "authorization server metadata `registration_endpoint` must be a string",
                ))
            }
        };

        let code_challenge_methods_supported = match object.get("code_challenge_methods_supported")
        {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => {
                let mut methods = Vec::with_capacity(items.len());
                for item in items {
                    let method = item.as_str().ok_or_else(|| {
                        protocol(
                            "authorization server metadata `code_challenge_methods_supported` \
                                 must be an array of strings",
                        )
                    })?;
                    methods.push(method.to_string());
                }
                methods
            }
            Some(_) => return Err(protocol(
                "authorization server metadata `code_challenge_methods_supported` must be an array",
            )),
        };

        let client_id_metadata_document_supported =
            match object.get("client_id_metadata_document_supported") {
                None | Some(Value::Null) => false,
                Some(Value::Bool(value)) => *value,
                Some(_) => {
                    return Err(protocol(
                        "authorization server metadata `client_id_metadata_document_supported` \
                         must be a boolean",
                    ))
                }
            };

        Ok(Self {
            issuer,
            authorization_endpoint,
            token_endpoint,
            registration_endpoint,
            code_challenge_methods_supported,
            client_id_metadata_document_supported,
        })
    }

    /// Refuse to proceed unless the server advertises PKCE `S256`.
    ///
    /// The MCP specification requires the client to verify PKCE support in
    /// authorization server metadata before starting the flow. A missing field
    /// is treated the same as a server that does not support PKCE.
    pub fn require_pkce_s256(&self) -> Result<()> {
        if self
            .code_challenge_methods_supported
            .iter()
            .any(|method| method == PKCE_METHOD_S256)
        {
            return Ok(());
        }
        Err(unsupported(
            "authorization server does not advertise PKCE S256; refusing to start authorization",
        ))
    }

    /// Discover authorization server metadata for `issuer`.
    ///
    /// Candidate URLs are tried in the order the MCP specification requires:
    /// RFC 8414 with path insertion, OIDC Discovery with path insertion, then
    /// OIDC Discovery with path appending when the issuer has a path. A fetched
    /// document whose `issuer` does not match `issuer` is a hard failure; the
    /// client does not fall through to the next candidate.
    pub fn discover(issuer: &Url, fetcher: &dyn MetadataFetcher) -> Result<Self> {
        validate_issuer_url(issuer)?;
        for url in discovery_urls(issuer)? {
            let Some(body) = fetcher.fetch(&url)? else {
                continue;
            };
            let metadata: Value = serde_json::from_str(&body).map_err(|_| {
                protocol("authorization server metadata response is not valid JSON")
            })?;
            let server = Self::from_metadata(issuer, &metadata)?;
            server.require_pkce_s256()?;
            return Ok(server);
        }
        Err(ZeroError::new(
            ErrorCode::NotFound,
            "no authorization server metadata document was found for the issuer",
        ))
    }

    /// Build the authorization URL for the code flow.
    ///
    /// `server_url` is the MCP server the token is for; `resource` is the same
    /// value the caller intends to send as the RFC 8707 parameter. Both are
    /// canonicalised and must identify the same resource, so the request can
    /// never ask for a token bound to a different server than the one being
    /// authorized. `client_id` is either a pre-registered identifier or an
    /// HTTPS CIMD URL.
    ///
    /// The URL always carries `response_type=code`,
    /// `code_challenge_method=S256`, a `state`, the exact `redirect_uri`, and
    /// the `resource` parameter. No scope is invented: the caller selects
    /// scopes from the protected resource metadata when that task lands.
    pub fn authorization_url(
        &self,
        server_url: &Url,
        redirect_uri: &str,
        state: &str,
        pkce: &Pkce,
        resource: &Url,
        client_id: &str,
    ) -> Result<Url> {
        let canonical_server = canonical_resource(server_url)?;
        let canonical_scope_resource = canonical_resource(resource)?;
        if canonical_server != canonical_scope_resource {
            return Err(invalid(
                "the RFC 8707 resource parameter must be the MCP server being authorized",
            ));
        }
        validate_redirect_uri(redirect_uri)?;
        if state.is_empty() {
            return Err(invalid("authorization state must not be empty"));
        }
        if state.len() > MAX_STATE_BYTES {
            return Err(invalid("authorization state is too long"));
        }
        if state.chars().any(char::is_control) {
            return Err(invalid(
                "authorization state must not contain control characters",
            ));
        }
        pkce.validate()?;
        validate_client_id(client_id)?;

        let mut url = self.authorization_endpoint.clone();
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("state", state)
                .append_pair("code_challenge", &pkce.challenge)
                .append_pair("code_challenge_method", PKCE_METHOD_S256)
                .append_pair("resource", canonical_scope_resource.as_str());
        }
        Ok(url)
    }

    /// Exchange an authorization code as a public client.
    ///
    /// The form contains `grant_type=authorization_code`, the code, the PKCE
    /// verifier, the exact redirect URI, `client_id`, and the RFC 8707
    /// `resource`. No client secret is ever sent. A response without an
    /// `access_token`, with a different `resource`, or with a non-`Bearer`
    /// `token_type` is refused.
    pub fn exchange_code(
        &self,
        transport: &dyn TokenTransport,
        code: &str,
        verifier: &str,
        redirect_uri: &str,
        client_id: &str,
        resource: &Url,
    ) -> Result<TokenGrant> {
        if code.trim().is_empty() {
            return Err(invalid("authorization code must not be empty"));
        }
        validate_verifier(verifier)?;
        validate_redirect_uri(redirect_uri)?;
        validate_client_id(client_id)?;
        let resource = canonical_resource(resource)?;

        let form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("code_verifier".to_string(), verifier.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("resource".to_string(), resource.as_str().to_string()),
        ];
        let response = transport.post_form(&self.token_endpoint, &form)?;
        parse_token_response(response, &self.issuer, &resource, client_id)
    }

    /// Refresh an access token as a public client.
    ///
    /// The form contains `grant_type=refresh_token`, the refresh token,
    /// `client_id`, and the RFC 8707 `resource`; no secret. The returned grant
    /// carries a rotated refresh token when the server returns one.
    pub fn refresh(
        &self,
        transport: &dyn TokenTransport,
        refresh_token: &str,
        client_id: &str,
        resource: &Url,
    ) -> Result<TokenGrant> {
        if refresh_token.trim().is_empty() {
            return Err(invalid("refresh token must not be empty"));
        }
        validate_client_id(client_id)?;
        let resource = canonical_resource(resource)?;

        let form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), client_id.to_string()),
            ("resource".to_string(), resource.as_str().to_string()),
        ];
        let response = transport.post_form(&self.token_endpoint, &form)?;
        parse_token_response(response, &self.issuer, &resource, client_id)
    }
}

fn metadata_url(object: &serde_json::Map<String, Value>, key: &str) -> Result<Url> {
    let raw = object
        .get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| protocol(format!("authorization server metadata is missing `{key}`")))?;
    Url::parse(raw).map_err(|_| {
        protocol(format!(
            "authorization server metadata `{key}` is not a valid URL"
        ))
    })
}

fn discovery_urls(issuer: &Url) -> Result<Vec<Url>> {
    let origin = issuer.origin().ascii_serialization();
    let path = issuer.path();
    let path = path.trim_end_matches('/');
    let mut candidates = Vec::with_capacity(3);
    if path.is_empty() {
        candidates.push(parse_discovery_url(&format!(
            "{origin}{WELL_KNOWN_AUTHORIZATION_SERVER}"
        ))?);
        candidates.push(parse_discovery_url(&format!(
            "{origin}{WELL_KNOWN_OPENID_CONFIGURATION}"
        ))?);
    } else {
        candidates.push(parse_discovery_url(&format!(
            "{origin}{WELL_KNOWN_AUTHORIZATION_SERVER}{path}"
        ))?);
        candidates.push(parse_discovery_url(&format!(
            "{origin}{WELL_KNOWN_OPENID_CONFIGURATION}{path}"
        ))?);
        candidates.push(parse_discovery_url(&format!(
            "{origin}{path}{WELL_KNOWN_OPENID_CONFIGURATION}"
        ))?);
    }
    Ok(candidates)
}

fn parse_discovery_url(value: &str) -> Result<Url> {
    Url::parse(value).map_err(|_| invalid("could not build an authorization server metadata URL"))
}

/// A scriptable HTTP GET seam for authorization server and CIMD documents.
///
/// `Ok(None)` means the document was not found (HTTP 404/410); discovery then
/// tries the next well-known candidate. Any other failure is returned as a
/// typed error. Production uses [`ReqwestMetadataFetcher`].
pub trait MetadataFetcher {
    /// Fetch `url` and return its body, or `None` when it does not exist.
    fn fetch(&self, url: &Url) -> Result<Option<String>>;
}

/// Blocking HTTPS metadata fetcher used outside tests.
///
/// Redirects are not followed: the document identity is the URL that was
/// requested, and silently following a redirect would let the issuer or the
/// CIMD host move without the caller noticing.
#[derive(Debug, Clone)]
pub struct ReqwestMetadataFetcher {
    timeout: Duration,
    max_body_bytes: usize,
}

impl Default for ReqwestMetadataFetcher {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_AUTH_TIMEOUT,
            max_body_bytes: MAX_CLIENT_METADATA_BYTES,
        }
    }
}

impl ReqwestMetadataFetcher {
    /// A fetcher with the default timeout and body bound.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replace the response-body bound.
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }
}

impl MetadataFetcher for ReqwestMetadataFetcher {
    fn fetch(&self, url: &Url) -> Result<Option<String>> {
        let client = auth_client(self.timeout)?;
        let response = client
            .get(url.clone())
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .map_err(map_reqwest)?;
        let status = response.status();
        if matches!(status.as_u16(), 404 | 410) {
            return Ok(None);
        }
        if !status.is_success() {
            // The body is not read: it is not a metadata document and can carry
            // attacker-controlled content.
            return Err(protocol(format!("metadata request returned HTTP {status}")));
        }
        Ok(Some(read_bounded_body(response, self.max_body_bytes)?))
    }
}

fn auth_client(timeout: Duration) -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|error| {
            ZeroError::new(
                ErrorCode::Internal,
                format!("failed to build the OAuth HTTP client: {error}"),
            )
        })
}

fn map_reqwest(error: reqwest::Error) -> ZeroError {
    if error.is_timeout() {
        ZeroError::new(
            ErrorCode::Timeout,
            format!("OAuth request timed out: {error}"),
        )
    } else if error.is_connect() {
        ZeroError::new(
            ErrorCode::Offline,
            format!("OAuth endpoint is unreachable: {error}"),
        )
    } else {
        ZeroError::new(
            ErrorCode::ProviderUnavailable,
            format!("OAuth request failed: {error}"),
        )
    }
}

fn read_bounded_body(response: reqwest::blocking::Response, max: usize) -> Result<String> {
    let limit = u64::try_from(max).unwrap_or(u64::MAX).saturating_add(1);
    let mut reader = response.take(limit);
    let mut bytes = Vec::new();
    reader.read_to_end(&mut bytes).map_err(|error| {
        if error.kind() == std::io::ErrorKind::TimedOut {
            ZeroError::new(
                ErrorCode::Timeout,
                format!("OAuth response body timed out: {error}"),
            )
        } else {
            ZeroError::new(
                ErrorCode::ProviderProtocol,
                format!("OAuth response body could not be read: {error}"),
            )
        }
    })?;
    if bytes.len() > max {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("OAuth response body is above the {max}-byte bound"),
        ));
    }
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

// ---------------------------------------------------------------------------
// Token endpoint seam and response parsing
// ---------------------------------------------------------------------------

/// One token endpoint response. `Debug` never prints the body, which may carry
/// an access or refresh token.
#[derive(Clone, PartialEq, Eq)]
pub struct AuthHttpResponse {
    /// HTTP status.
    pub status: u16,
    /// Response body.
    pub body: String,
}

impl fmt::Debug for AuthHttpResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AuthHttpResponse")
            .field("status", &self.status)
            .field("body_bytes", &self.body.len())
            .finish()
    }
}

/// A scriptable form POST seam for the token endpoint.
pub trait TokenTransport {
    /// POST an `application/x-www-form-urlencoded` body to `url`.
    fn post_form(&self, url: &Url, form: &[(String, String)]) -> Result<AuthHttpResponse>;
}

/// Blocking HTTPS token transport used outside tests.
#[derive(Debug, Clone)]
pub struct ReqwestTokenTransport {
    timeout: Duration,
    max_body_bytes: usize,
}

impl Default for ReqwestTokenTransport {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_AUTH_TIMEOUT,
            max_body_bytes: MAX_TOKEN_RESPONSE_BYTES,
        }
    }
}

impl ReqwestTokenTransport {
    /// A transport with the default timeout and body bound.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the per-request timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Replace the response-body bound.
    pub fn with_max_body_bytes(mut self, bytes: usize) -> Self {
        self.max_body_bytes = bytes;
        self
    }
}

impl TokenTransport for ReqwestTokenTransport {
    fn post_form(&self, url: &Url, form: &[(String, String)]) -> Result<AuthHttpResponse> {
        let client = auth_client(self.timeout)?;
        let encoded: BTreeMap<&str, &str> = form
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let response = client
            .post(url.clone())
            .form(&encoded)
            .send()
            .map_err(map_reqwest)?;
        let status = response.status().as_u16();
        let body = read_bounded_body(response, self.max_body_bytes)?;
        Ok(AuthHttpResponse { status, body })
    }
}

#[derive(Debug, Deserialize)]
struct TokenPayload {
    access_token: Option<String>,
    token_type: Option<String>,
    expires_in: Option<i64>,
    refresh_token: Option<String>,
    scope: Option<String>,
    resource: Option<String>,
    audience: Option<String>,
    error: Option<String>,
    #[serde(default, rename = "error_description")]
    _error_description: Option<String>,
}

/// An access token and the refresh token returned with it, when any.
///
/// Refresh tokens rotate for public clients, so the grant keeps the newest one
/// instead of silently dropping it. `Debug` redacts both token values.
#[derive(Clone, PartialEq, Eq)]
pub struct TokenGrant {
    /// The access token and its binding metadata.
    pub access: AccessToken,
    /// The rotated refresh token, when the server returned one.
    pub refresh_token: Option<String>,
}

impl fmt::Debug for TokenGrant {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TokenGrant")
            .field("access", &self.access)
            .field("has_refresh_token", &self.refresh_token.is_some())
            .finish()
    }
}

fn parse_token_response(
    response: AuthHttpResponse,
    issuer: &Url,
    resource: &Url,
    client_id: &str,
) -> Result<TokenGrant> {
    let payload: TokenPayload = match serde_json::from_str(&response.body) {
        Ok(payload) => payload,
        Err(_) if response.status >= 400 => {
            return Err(auth_error(format!(
                "token endpoint returned HTTP {}",
                response.status
            )))
        }
        Err(_) => return Err(protocol("token response is not valid JSON")),
    };

    if let Some(error) = payload.error.as_deref() {
        // Only the OAuth error code is surfaced. A description is untrusted
        // server text and could echo the code or verifier back at the caller.
        let error: String = error
            .chars()
            .take(64)
            .filter(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '_' | '.' | '-'))
            .collect();
        return Err(auth_error(format!("token endpoint refused with `{error}`")));
    }
    if response.status >= 400 {
        return Err(auth_error(format!(
            "token endpoint returned HTTP {}",
            response.status
        )));
    }

    let access_token = payload
        .access_token
        .filter(|token| !token.trim().is_empty())
        .ok_or_else(|| protocol("token response has no access_token"))?;

    if let Some(token_type) = payload.token_type.as_deref() {
        if !token_type.eq_ignore_ascii_case("bearer") {
            return Err(protocol(format!(
                "token response returned unsupported token_type `{token_type}`"
            )));
        }
    }

    if let Some(returned) = payload.resource.as_deref() {
        let returned = Url::parse(returned)
            .map_err(|_| protocol("token response `resource` is not a valid URL"))?;
        if &returned != resource {
            return Err(protocol(
                "token response `resource` does not match the requested MCP server",
            ));
        }
    }

    let scopes = payload
        .scope
        .as_deref()
        .map(|scope| {
            scope
                .split_whitespace()
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();

    let expires_at_ms = payload.expires_in.map(|seconds| {
        let seconds = seconds.max(0);
        now_ms().saturating_add(seconds.saturating_mul(1000))
    });

    Ok(TokenGrant {
        access: AccessToken {
            token: access_token,
            issuer: issuer.clone(),
            resource: resource.clone(),
            client_id: client_id.to_string(),
            scopes,
            audience: payload.audience,
            expires_at_ms,
        },
        refresh_token: payload.refresh_token,
    })
}

fn now_ms() -> i64 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => i64::try_from(duration.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

// ---------------------------------------------------------------------------
// Token binding
// ---------------------------------------------------------------------------

/// An access token and the identity it was minted under.
///
/// `Debug` and `Display` never print the token value. The fields are public so
/// a caller can persist the binding metadata, but the token itself should go to
/// the credential store, not to config or logs.
#[derive(Clone, PartialEq, Eq)]
pub struct AccessToken {
    /// The bearer token. Never printed by this crate.
    pub token: String,
    /// The authorization server that issued it.
    pub issuer: Url,
    /// The MCP server (RFC 8707 resource) it is bound to.
    pub resource: Url,
    /// The client id it was issued for.
    pub client_id: String,
    /// Granted scopes.
    pub scopes: Vec<String>,
    /// The token audience, when the issuer returns one.
    pub audience: Option<String>,
    /// Expiry as Unix milliseconds, when the issuer returns `expires_in`.
    pub expires_at_ms: Option<i64>,
}

impl AccessToken {
    /// Whether the token is expired at `now_ms`.
    ///
    /// A token without a known expiry is not treated as expired here; the
    /// resource server still enforces its own lifetime.
    pub fn is_expired(&self, now_ms: i64) -> bool {
        self.expires_at_ms.is_some_and(|expires| expires <= now_ms)
    }
}

impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AccessToken")
            .field("token", &"[redacted]")
            .field("issuer", &self.issuer)
            .field("resource", &self.resource)
            .field("client_id", &self.client_id)
            .field("scopes", &self.scopes)
            .field("audience", &self.audience)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish()
    }
}

impl fmt::Display for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "AccessToken([redacted] for {})", self.resource)
    }
}

/// What a token must be bound to before it is used for a given MCP server.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TokenBinding {
    /// Expected issuer.
    pub issuer: Url,
    /// Expected MCP server resource.
    pub resource: Url,
    /// Expected client id.
    pub client_id: String,
    /// Expected audience, when one is known. `None` accepts any audience,
    /// because many authorization servers do not return an audience field.
    pub audience: Option<String>,
}

impl TokenBinding {
    /// Build a binding for `resource` from `issuer` and `client_id`.
    ///
    /// The resource is canonicalised, so a caller cannot compare a raw spelling
    /// against the canonical value stored on the token.
    pub fn new(issuer: &Url, resource: &Url, client_id: impl Into<String>) -> Result<Self> {
        validate_issuer_url(issuer)?;
        Ok(Self {
            issuer: issuer.clone(),
            resource: canonical_resource(resource)?,
            client_id: client_id.into(),
            audience: None,
        })
    }

    /// Require an exact audience in addition to the other binding fields.
    pub fn with_audience(mut self, audience: impl Into<String>) -> Self {
        self.audience = Some(audience.into());
        self
    }
}

/// Verify that `token` may be presented to the server described by `expected`.
///
/// Checks, in order: non-empty token, exact issuer, exact resource, exact
/// client id, expected audience when one is set, and expiry. Every failure is
/// `zero.prv.auth` and none of the messages contains the token value.
pub fn validate_token(token: &AccessToken, expected: &TokenBinding, now_ms: i64) -> Result<()> {
    if token.token.trim().is_empty() {
        return Err(auth_error("access token is empty"));
    }
    if token.issuer != expected.issuer {
        return Err(auth_error(
            "access token was issued by a different authorization server",
        ));
    }
    if token.resource != expected.resource {
        return Err(auth_error(
            "access token is bound to a different MCP server",
        ));
    }
    if token.client_id != expected.client_id {
        return Err(auth_error("access token was issued for a different client"));
    }
    if let Some(audience) = expected.audience.as_deref() {
        if token.audience.as_deref() != Some(audience) {
            return Err(auth_error("access token audience does not match"));
        }
    }
    if token.is_expired(now_ms) {
        return Err(auth_error("access token has expired"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Client ID Metadata Documents (CIMD)
// ---------------------------------------------------------------------------

/// A Client ID Metadata Document.
///
/// The `client_id` is an HTTPS URL; the document is fetched from exactly that
/// URL and must repeat the same value. Unknown fields are ignored.
#[derive(Debug, Clone, Deserialize)]
pub struct ClientMetadata {
    /// HTTPS URL of this document, used as the OAuth client id.
    pub client_id: String,
    /// Human-readable client name shown on the consent screen.
    pub client_name: String,
    /// Exact redirect URIs. No wildcards and no prefix matching.
    #[serde(default)]
    pub redirect_uris: Vec<String>,
    /// Grant types the client uses.
    #[serde(default)]
    pub grant_types: Vec<String>,
    /// Response types the client uses.
    #[serde(default)]
    pub response_types: Vec<String>,
    /// Token endpoint authentication method.
    #[serde(default)]
    pub token_endpoint_auth_method: String,
    /// Requested scopes, when the client publishes them.
    #[serde(default)]
    pub scope: Option<String>,
}

/// Validate a CIMD `client_id` URL.
///
/// It is `https`, has a host, includes a path component, and carries no
/// userinfo or fragment. A plain `http` client id is refused even for loopback,
/// because the identifier is a public document URL rather than a callback.
pub fn validate_client_id_url(url: &Url) -> Result<()> {
    require_host(url, "client_id")?;
    if url.scheme() != "https" {
        return Err(invalid("CIMD client_id must use https"));
    }
    require_no_userinfo(url, "client_id")?;
    if url.fragment().is_some() {
        return Err(invalid("CIMD client_id must not contain a fragment"));
    }
    let path = url.path();
    if path.is_empty() || path == "/" {
        return Err(invalid("CIMD client_id must include a path component"));
    }
    Ok(())
}

/// Whether a client id is a URL-form (CIMD) identifier or an opaque
/// pre-registered identifier.
fn validate_client_id(client_id: &str) -> Result<()> {
    if client_id.trim().is_empty() {
        return Err(invalid("client id must not be empty"));
    }
    if client_id.chars().any(char::is_control) {
        return Err(invalid("client id must not contain control characters"));
    }
    let scheme = client_id
        .split_once("://")
        .map(|(scheme, _)| scheme.to_ascii_lowercase());
    if matches!(scheme.as_deref(), Some("https" | "http")) {
        let url = Url::parse(client_id)
            .map_err(|_| invalid("CIMD client_id is not a valid absolute URL"))?;
        validate_client_id_url(&url)?;
    }
    Ok(())
}

fn validate_client_metadata_document(metadata: &ClientMetadata) -> Result<()> {
    let client_id = Url::parse(&metadata.client_id)
        .map_err(|_| invalid("client metadata client_id is not a valid absolute URL"))?;
    validate_client_id_url(&client_id)?;

    if metadata.client_name.trim().is_empty() {
        return Err(invalid("client metadata client_name must not be empty"));
    }
    if metadata.client_name.chars().any(char::is_control) {
        return Err(invalid(
            "client metadata client_name must not contain control characters",
        ));
    }

    if metadata.redirect_uris.is_empty() {
        return Err(invalid(
            "client metadata redirect_uris must contain at least one entry",
        ));
    }
    if metadata.redirect_uris.len() > MAX_REDIRECT_URIS {
        return Err(invalid(format!(
            "client metadata redirect_uris is above the {MAX_REDIRECT_URIS}-entry bound"
        )));
    }
    for redirect in &metadata.redirect_uris {
        if redirect.contains('*') {
            return Err(invalid(
                "client metadata redirect_uris must not contain wildcards",
            ));
        }
        validate_redirect_uri(redirect)?;
    }

    if !metadata
        .response_types
        .iter()
        .any(|response_type| response_type == "code")
    {
        return Err(invalid(
            "client metadata response_types must include `code`",
        ));
    }
    if !metadata
        .grant_types
        .iter()
        .any(|grant_type| grant_type == "authorization_code")
    {
        return Err(invalid(
            "client metadata grant_types must include `authorization_code`",
        ));
    }
    if metadata.token_endpoint_auth_method != "none" {
        return Err(invalid(
            "client metadata token_endpoint_auth_method must be `none` for a public client",
        ));
    }
    if let Some(scope) = metadata.scope.as_deref() {
        if !scope.is_empty() && !scope.split_whitespace().all(valid_scope_token) {
            return Err(invalid("client metadata scope is not a valid scope string"));
        }
    }
    Ok(())
}

fn valid_scope_token(token: &str) -> bool {
    !token.is_empty()
        && token
            .bytes()
            .all(|byte| matches!(byte, 0x21 | 0x23..=0x5B | 0x5D..=0x7E))
}

/// Validate a client metadata document for one authorization request.
///
/// `redirect_uri` must be exactly one of the listed URIs (byte equality, no
/// wildcard or prefix matching), the response type must include `code`, the
/// grant types must allow `authorization_code`, and the token endpoint auth
/// method must be `none` because this is a public client.
pub fn validate_client_metadata(metadata: &ClientMetadata, redirect_uri: &str) -> Result<()> {
    validate_client_metadata_document(metadata)?;
    validate_redirect_uri(redirect_uri)?;
    if !metadata
        .redirect_uris
        .iter()
        .any(|registered| registered == redirect_uri)
    {
        return Err(invalid(
            "redirect URI does not exactly match a client metadata redirect_uris entry",
        ));
    }
    Ok(())
}

/// Fetch a CIMD document and confirm that it identifies itself by the same URL.
///
/// `client_id` must be a valid CIMD URL; the fetched document's `client_id`
/// field must equal `client_id`'s serialised form exactly. The network seam is
/// [`MetadataFetcher`], so tests script the document and no request leaves the
/// process.
pub fn fetch_client_metadata(
    fetcher: &dyn MetadataFetcher,
    client_id: &Url,
) -> Result<ClientMetadata> {
    validate_client_id_url(client_id)?;
    let body = fetcher.fetch(client_id)?.ok_or_else(|| {
        ZeroError::new(
            ErrorCode::NotFound,
            "client metadata document was not found",
        )
    })?;
    if body.len() > MAX_CLIENT_METADATA_BYTES {
        return Err(ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("client metadata document is above the {MAX_CLIENT_METADATA_BYTES}-byte bound"),
        ));
    }
    let metadata: ClientMetadata = serde_json::from_str(&body)
        .map_err(|_| protocol("client metadata document is not valid JSON"))?;
    if metadata.client_id != client_id.as_str() {
        return Err(auth_error(
            "client metadata client_id does not match the document URL",
        ));
    }
    validate_client_metadata_document(&metadata)?;
    Ok(metadata)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    const ISSUER: &str = "https://auth.example.com";
    const SERVER_A: &str = "https://server-a.example/mcp";
    const SERVER_B: &str = "https://server-b.example/mcp";
    const CLIENT_ID: &str = "https://client.example/oauth/client-metadata.json";

    #[derive(Default)]
    struct ScriptedFetcher {
        documents: BTreeMap<String, Option<String>>,
        requested: Mutex<Vec<String>>,
    }

    impl ScriptedFetcher {
        fn with(mut self, url: &str, body: Option<&str>) -> Self {
            self.documents
                .insert(url.to_string(), body.map(str::to_string));
            self
        }

        fn requested(&self) -> Vec<String> {
            self.requested.lock().unwrap().clone()
        }
    }

    impl MetadataFetcher for ScriptedFetcher {
        fn fetch(&self, url: &Url) -> Result<Option<String>> {
            self.requested.lock().unwrap().push(url.to_string());
            Ok(self.documents.get(url.as_str()).cloned().unwrap_or(None))
        }
    }

    #[derive(Default)]
    struct ScriptedTokenTransport {
        responses: Mutex<VecDeque<AuthHttpResponse>>,
        forms: Mutex<Vec<(String, RecordedForm)>>,
    }

    type RecordedForm = Vec<(String, String)>;

    impl ScriptedTokenTransport {
        fn with(responses: Vec<AuthHttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                forms: Mutex::new(Vec::new()),
            }
        }

        fn forms(&self) -> Vec<(String, RecordedForm)> {
            self.forms.lock().unwrap().clone()
        }

        fn next(&self) -> AuthHttpResponse {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(AuthHttpResponse {
                    status: 500,
                    body: "{}".to_string(),
                })
        }
    }

    impl TokenTransport for ScriptedTokenTransport {
        fn post_form(&self, url: &Url, form: &[(String, String)]) -> Result<AuthHttpResponse> {
            self.forms
                .lock()
                .unwrap()
                .push((url.to_string(), form.to_vec()));
            Ok(self.next())
        }
    }

    fn url(value: &str) -> Url {
        Url::parse(value).unwrap()
    }

    fn metadata(issuer: &str) -> Value {
        serde_json::json!({
            "issuer": issuer,
            "authorization_endpoint": "https://auth.example.com/authorize",
            "token_endpoint": "https://auth.example.com/token",
            "registration_endpoint": "https://auth.example.com/register",
            "code_challenge_methods_supported": ["S256"],
            "client_id_metadata_document_supported": true,
        })
    }

    fn server() -> AuthorizationServer {
        AuthorizationServer::from_metadata(&url(ISSUER), &metadata(ISSUER)).unwrap()
    }

    fn pkce() -> Pkce {
        // RFC 7636 Appendix B verifier.
        Pkce::from_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk").unwrap()
    }

    fn bearer_json(access: &str, resource: &str) -> AuthHttpResponse {
        AuthHttpResponse {
            status: 200,
            body: serde_json::json!({
                "access_token": access,
                "token_type": "Bearer",
                "expires_in": 3600,
                "refresh_token": "rotated-refresh",
                "scope": "files:read files:write",
                "resource": resource,
            })
            .to_string(),
        }
    }

    fn token_for(
        resource: &str,
        issuer: &str,
        client_id: &str,
        audience: Option<&str>,
        expires_at_ms: Option<i64>,
    ) -> AccessToken {
        AccessToken {
            token: "secret-access-token".to_string(),
            issuer: url(issuer),
            resource: url(resource),
            client_id: client_id.to_string(),
            scopes: vec!["files:read".to_string()],
            audience: audience.map(str::to_string),
            expires_at_ms,
        }
    }

    fn client_metadata() -> ClientMetadata {
        ClientMetadata {
            client_id: CLIENT_ID.to_string(),
            client_name: "Zero".to_string(),
            redirect_uris: vec!["http://127.0.0.1:33418/auth/callback".to_string()],
            grant_types: vec!["authorization_code".to_string()],
            response_types: vec!["code".to_string()],
            token_endpoint_auth_method: "none".to_string(),
            scope: Some("files:read".to_string()),
        }
    }

    #[test]
    fn pkce_matches_the_rfc7636_vector() {
        assert_eq!(
            pkce().challenge,
            "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
        );
        // The debug form must not print the verifier.
        let rendered = format!("{:?}", pkce());
        assert!(!rendered.contains(&pkce().verifier));
    }

    #[test]
    fn pkce_rejects_a_malformed_or_wrong_pair() {
        assert!(Pkce::from_verifier("too-short").is_err());
        assert!(Pkce::from_verifier("x".repeat(129)).is_err());
        assert!(Pkce::from_verifier("!".repeat(43)).is_err());
        assert!(Pkce::from_verifier("a".repeat(42)).is_err());

        let mut pair = pkce();
        pair.challenge = "not-the-right-challenge".to_string();
        assert!(pair.validate().is_err());
    }

    #[test]
    fn authorization_url_carries_pkce_state_and_resource() {
        let server = server();
        let server_url = url(SERVER_A);
        let redirect = "http://127.0.0.1:33418/auth/callback";
        let pair = pkce();
        let built = server
            .authorization_url(
                &server_url,
                redirect,
                "state-value",
                &pair,
                &server_url,
                CLIENT_ID,
            )
            .unwrap();
        assert_eq!(built.scheme(), "https");
        assert_eq!(built.host_str(), Some("auth.example.com"));
        assert_eq!(built.path(), "/authorize");
        let params: BTreeMap<String, String> = built
            .query_pairs()
            .map(|(key, value)| (key.into_owned(), value.into_owned()))
            .collect();
        assert_eq!(params["response_type"], "code");
        assert_eq!(params["client_id"], CLIENT_ID);
        assert_eq!(params["redirect_uri"], redirect);
        assert_eq!(params["state"], "state-value");
        assert_eq!(params["code_challenge"], pair.challenge);
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["resource"], SERVER_A);
        assert!(!params.contains_key("scope"));
    }

    #[test]
    fn authorization_url_rejects_a_resource_for_another_server() {
        let server = server();
        let err = server
            .authorization_url(
                &url(SERVER_A),
                "https://client.example/callback",
                "state",
                &pkce(),
                &url(SERVER_B),
                CLIENT_ID,
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidInput);
        assert!(err.message().contains("resource"));
    }

    #[test]
    fn authorization_url_rejects_bad_state_and_redirect() {
        let server = server();
        let server_url = url(SERVER_A);
        assert!(server
            .authorization_url(
                &server_url,
                "https://client.example/callback",
                "",
                &pkce(),
                &server_url,
                CLIENT_ID
            )
            .is_err());
        assert!(server
            .authorization_url(
                &server_url,
                "http://evil.example/callback",
                "state",
                &pkce(),
                &server_url,
                CLIENT_ID
            )
            .is_err());
        assert!(server
            .authorization_url(
                &server_url,
                "https://user:pass@client.example/callback",
                "state",
                &pkce(),
                &server_url,
                CLIENT_ID
            )
            .is_err());
        assert!(server
            .authorization_url(
                &server_url,
                "https://client.example/callback#fragment",
                "state",
                &pkce(),
                &server_url,
                CLIENT_ID
            )
            .is_err());
    }

    #[test]
    fn issuer_validation_is_strict() {
        assert!(validate_issuer_url(&url("https://auth.example.com")).is_ok());
        assert!(validate_issuer_url(&url("https://auth.example.com/tenant1")).is_ok());
        assert!(validate_issuer_url(&url("http://127.0.0.1:9000")).is_ok());
        assert!(validate_issuer_url(&url("http://localhost:9000")).is_err());
        assert!(validate_issuer_url(&url("http://auth.example.com")).is_err());
        assert!(validate_issuer_url(&url("https://user@auth.example.com")).is_err());
        assert!(validate_issuer_url(&url("https://auth.example.com#fragment")).is_err());
        assert!(validate_issuer_url(&url("https://auth.example.com?query=1")).is_err());

        let http_metadata = metadata("http://localhost:9000");
        assert!(
            AuthorizationServer::from_metadata(&url("http://localhost:9000"), &http_metadata)
                .is_err()
        );

        let test_server = AuthorizationServer::from_metadata(
            &url("http://127.0.0.1:9000"),
            &serde_json::json!({
                "issuer": "http://127.0.0.1:9000",
                "authorization_endpoint": "http://127.0.0.1:9000/authorize",
                "token_endpoint": "http://127.0.0.1:9000/token",
                "code_challenge_methods_supported": ["S256"],
            }),
        )
        .unwrap();
        assert_eq!(test_server.issuer, url("http://127.0.0.1:9000/"));
    }

    #[test]
    fn metadata_issuer_must_match_exactly() {
        let cases = [
            "https://auth.example.com.evil",
            "https://auth.example.com/tenant1",
            "https://auth.example.com:8443",
        ];
        for issuer in cases {
            let err =
                AuthorizationServer::from_metadata(&url(ISSUER), &metadata(issuer)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::ProviderAuth, "{issuer}");
        }
        // A malformed issuer is refused before comparison.
        for issuer in ["http://auth.example.com", "https://user@auth.example.com"] {
            let err =
                AuthorizationServer::from_metadata(&url(ISSUER), &metadata(issuer)).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{issuer}");
        }
        // The same issuer with a trailing slash is the same parsed URL.
        assert!(AuthorizationServer::from_metadata(
            &url(ISSUER),
            &metadata("https://auth.example.com/")
        )
        .is_ok());
    }

    #[test]
    fn authorization_server_endpoints_must_be_secure() {
        let mut document = metadata(ISSUER);
        document["authorization_endpoint"] =
            Value::String("http://auth.example.com/authorize".into());
        assert!(AuthorizationServer::from_metadata(&url(ISSUER), &document).is_err());

        let mut document = metadata(ISSUER);
        document["token_endpoint"] = Value::String("https://user@auth.example.com/token".into());
        assert!(AuthorizationServer::from_metadata(&url(ISSUER), &document).is_err());

        let mut document = metadata(ISSUER);
        document["token_endpoint"] = Value::String("https://auth.example.com/token#f".into());
        assert!(AuthorizationServer::from_metadata(&url(ISSUER), &document).is_err());

        let mut document = metadata(ISSUER);
        document["registration_endpoint"] = Value::Null;
        assert!(AuthorizationServer::from_metadata(&url(ISSUER), &document)
            .unwrap()
            .registration_endpoint
            .is_none());
    }

    #[test]
    fn discovery_tries_well_known_endpoints_in_order() {
        let fetcher = ScriptedFetcher::default().with(
            "https://auth.example.com/.well-known/openid-configuration",
            Some(&metadata(ISSUER).to_string()),
        );
        let discovered =
            AuthorizationServer::discover(&url("https://auth.example.com"), &fetcher).unwrap();
        assert_eq!(discovered.issuer, url(ISSUER));
        assert_eq!(
            fetcher.requested(),
            vec![
                "https://auth.example.com/.well-known/oauth-authorization-server".to_string(),
                "https://auth.example.com/.well-known/openid-configuration".to_string(),
            ]
        );
    }

    #[test]
    fn discovery_handles_an_issuer_with_a_path() {
        let tenant = "https://auth.example.com/tenant1";
        let fetched = "https://auth.example.com/tenant1/.well-known/openid-configuration";
        let fetcher = ScriptedFetcher::default().with(fetched, Some(&metadata(tenant).to_string()));
        let discovered = AuthorizationServer::discover(&url(tenant), &fetcher).unwrap();
        assert_eq!(discovered.issuer, url(tenant));
        assert_eq!(
            fetcher.requested(),
            vec![
                "https://auth.example.com/.well-known/oauth-authorization-server/tenant1"
                    .to_string(),
                "https://auth.example.com/.well-known/openid-configuration/tenant1".to_string(),
                fetched.to_string(),
            ]
        );
    }

    #[test]
    fn discovery_refuses_metadata_without_s256_or_for_another_issuer() {
        let mut without_pkce = metadata(ISSUER);
        without_pkce
            .as_object_mut()
            .unwrap()
            .remove("code_challenge_methods_supported");
        let fetcher = ScriptedFetcher::default().with(
            "https://auth.example.com/.well-known/oauth-authorization-server",
            Some(&without_pkce.to_string()),
        );
        assert!(AuthorizationServer::discover(&url(ISSUER), &fetcher).is_err());

        let mut plain_only = metadata(ISSUER);
        plain_only["code_challenge_methods_supported"] = serde_json::json!(["plain"]);
        let fetcher = ScriptedFetcher::default().with(
            "https://auth.example.com/.well-known/oauth-authorization-server",
            Some(&plain_only.to_string()),
        );
        assert!(AuthorizationServer::discover(&url(ISSUER), &fetcher).is_err());

        let fetcher = ScriptedFetcher::default().with(
            "https://auth.example.com/.well-known/oauth-authorization-server",
            Some(&metadata("https://attacker.example").to_string()),
        );
        let err = AuthorizationServer::discover(&url(ISSUER), &fetcher).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderAuth);
        // A mismatched document is fatal, not a reason to try the next URL.
        assert_eq!(fetcher.requested().len(), 1);
    }

    #[test]
    fn discovery_reports_missing_metadata_as_not_found() {
        let fetcher = ScriptedFetcher::default();
        let err = AuthorizationServer::discover(&url(ISSUER), &fetcher).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
        assert_eq!(fetcher.requested().len(), 2);
    }

    #[test]
    fn exchange_code_uses_a_public_client_form() {
        let transport = ScriptedTokenTransport::with(vec![bearer_json("access-1", SERVER_A)]);
        let grant = server()
            .exchange_code(
                &transport,
                "auth-code",
                &pkce().verifier,
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A),
            )
            .unwrap();
        assert_eq!(grant.access.token, "access-1");
        assert_eq!(grant.access.issuer, url(ISSUER));
        assert_eq!(grant.access.resource, url(SERVER_A));
        assert_eq!(grant.access.client_id, CLIENT_ID);
        assert_eq!(grant.access.scopes, vec!["files:read", "files:write"]);
        assert!(grant.access.expires_at_ms.is_some());
        assert_eq!(grant.refresh_token.as_deref(), Some("rotated-refresh"));

        let forms = transport.forms();
        assert_eq!(forms.len(), 1);
        assert_eq!(forms[0].0, "https://auth.example.com/token");
        let form: BTreeMap<String, String> = forms[0].1.iter().cloned().collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "auth-code");
        assert_eq!(form["code_verifier"], pkce().verifier);
        assert_eq!(form["redirect_uri"], "https://client.example/callback");
        assert_eq!(form["client_id"], CLIENT_ID);
        assert_eq!(form["resource"], SERVER_A);
        assert!(!form.contains_key("client_secret"));
    }

    #[test]
    fn token_response_shape_is_enforced() {
        let without_token = AuthHttpResponse {
            status: 200,
            body: serde_json::json!({"token_type": "Bearer"}).to_string(),
        };
        let err = server()
            .exchange_code(
                &ScriptedTokenTransport::with(vec![without_token]),
                "code",
                &pkce().verifier,
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A),
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderProtocol);

        let err = server()
            .exchange_code(
                &ScriptedTokenTransport::with(vec![bearer_json("access", SERVER_B)]),
                "code",
                &pkce().verifier,
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A),
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderProtocol);
        assert!(err.message().contains("resource"));

        let wrong_type = AuthHttpResponse {
            status: 200,
            body: serde_json::json!({"access_token": "a", "token_type": "N_A"}).to_string(),
        };
        let err = server()
            .exchange_code(
                &ScriptedTokenTransport::with(vec![wrong_type]),
                "code",
                &pkce().verifier,
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A),
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderProtocol);
        assert!(err.message().contains("token_type"));
    }

    #[test]
    fn oauth_errors_are_surfaced_without_server_text() {
        let response = AuthHttpResponse {
            status: 400,
            body: serde_json::json!({
                "error": "invalid_grant",
                "error_description": "the code was access-token-echo",
            })
            .to_string(),
        };
        let err = server()
            .exchange_code(
                &ScriptedTokenTransport::with(vec![response]),
                "code",
                &pkce().verifier,
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A),
            )
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderAuth);
        assert!(err.message().contains("invalid_grant"));
        assert!(!err.message().contains("access-token-echo"));
    }

    #[test]
    fn exchange_code_rejects_a_bad_verifier_or_code() {
        let transport = ScriptedTokenTransport::default();
        assert!(server()
            .exchange_code(
                &transport,
                "",
                &pkce().verifier,
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A)
            )
            .is_err());
        assert!(server()
            .exchange_code(
                &transport,
                "code",
                "short",
                "https://client.example/callback",
                CLIENT_ID,
                &url(SERVER_A)
            )
            .is_err());
        assert!(server()
            .exchange_code(
                &transport,
                "code",
                &pkce().verifier,
                "http://evil.example/callback",
                CLIENT_ID,
                &url(SERVER_A)
            )
            .is_err());
        assert!(transport.forms().is_empty());
    }

    #[test]
    fn refresh_is_a_public_client_request() {
        let transport = ScriptedTokenTransport::with(vec![bearer_json("access-2", SERVER_A)]);
        let grant = server()
            .refresh(&transport, "refresh-1", CLIENT_ID, &url(SERVER_A))
            .unwrap();
        assert_eq!(grant.access.token, "access-2");
        assert_eq!(grant.refresh_token.as_deref(), Some("rotated-refresh"));

        let forms = transport.forms();
        let form: BTreeMap<String, String> = forms[0].1.iter().cloned().collect();
        assert_eq!(form["grant_type"], "refresh_token");
        assert_eq!(form["refresh_token"], "refresh-1");
        assert_eq!(form["client_id"], CLIENT_ID);
        assert_eq!(form["resource"], SERVER_A);
        assert!(!form.contains_key("client_secret"));
    }

    #[test]
    fn a_minted_token_validates_for_its_own_server() {
        let now = 1_000_000;
        let token = token_for(
            SERVER_A,
            ISSUER,
            CLIENT_ID,
            Some(SERVER_A),
            Some(now + 60_000),
        );
        let binding = TokenBinding::new(&url(ISSUER), &url(SERVER_A), CLIENT_ID)
            .unwrap()
            .with_audience(SERVER_A);
        validate_token(&token, &binding, now).unwrap();
    }

    #[test]
    fn a_stolen_token_fails_on_another_server() {
        let now = 1_000_000;
        let stolen = token_for(
            SERVER_A,
            ISSUER,
            CLIENT_ID,
            Some(SERVER_A),
            Some(now + 60_000),
        );
        let expected = TokenBinding::new(&url(ISSUER), &url(SERVER_B), CLIENT_ID)
            .unwrap()
            .with_audience(SERVER_B);
        let err = validate_token(&stolen, &expected, now).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderAuth);
        assert!(err.message().contains("different MCP server"));
        assert!(!err.message().contains(&stolen.token));
    }

    #[test]
    fn token_issuer_client_and_audience_mismatches_fail() {
        let now = 1_000_000;
        let token = token_for(
            SERVER_A,
            ISSUER,
            CLIENT_ID,
            Some(SERVER_A),
            Some(now + 60_000),
        );

        let wrong_issuer = TokenBinding::new(
            &url("https://other-auth.example.com"),
            &url(SERVER_A),
            CLIENT_ID,
        )
        .unwrap();
        assert!(validate_token(&token, &wrong_issuer, now).is_err());

        let wrong_client =
            TokenBinding::new(&url(ISSUER), &url(SERVER_A), "another-client").unwrap();
        assert!(validate_token(&token, &wrong_client, now).is_err());

        let wrong_audience = TokenBinding::new(&url(ISSUER), &url(SERVER_A), CLIENT_ID)
            .unwrap()
            .with_audience("https://other-resource.example");
        let err = validate_token(&token, &wrong_audience, now).unwrap_err();
        assert!(err.message().contains("audience"));

        // No expected audience means the field is not checked.
        let no_audience = TokenBinding::new(&url(ISSUER), &url(SERVER_A), CLIENT_ID).unwrap();
        assert!(validate_token(&token, &no_audience, now).is_ok());
    }

    #[test]
    fn expired_and_empty_tokens_are_refused() {
        let now = 1_000_000;
        let binding = TokenBinding::new(&url(ISSUER), &url(SERVER_A), CLIENT_ID).unwrap();

        let expired = token_for(SERVER_A, ISSUER, CLIENT_ID, None, Some(now));
        let err = validate_token(&expired, &binding, now).unwrap_err();
        assert!(err.message().contains("expired"));

        let mut empty = token_for(SERVER_A, ISSUER, CLIENT_ID, None, Some(now + 60_000));
        empty.token = "   ".to_string();
        assert!(validate_token(&empty, &binding, now).is_err());
    }

    #[test]
    fn token_values_never_appear_in_errors_or_debug_output() {
        let secret = "very-secret-access-token";
        let refresh_secret = "very-secret-refresh-token";
        let mut token = token_for(SERVER_A, ISSUER, CLIENT_ID, None, Some(0));
        token.token = secret.to_string();
        let grant = TokenGrant {
            access: token.clone(),
            refresh_token: Some(refresh_secret.to_string()),
        };

        let rendered = format!(
            "{:?}\n{}\n{:?}\n{:?}",
            token,
            token,
            grant,
            AuthHttpResponse {
                status: 200,
                body: format!("{{\"access_token\":\"{secret}\"}}"),
            }
        );
        assert!(!rendered.contains(secret));
        assert!(!rendered.contains(refresh_secret));
        assert!(rendered.contains("[redacted]"));

        let binding = TokenBinding::new(&url(ISSUER), &url(SERVER_B), "other-client")
            .unwrap()
            .with_audience("other-audience");
        let err = validate_token(&token, &binding, 1).unwrap_err();
        assert!(!err.message().contains(secret));
        assert!(!err.to_string().contains(secret));
    }

    #[test]
    fn client_metadata_requires_a_secure_document_url() {
        assert!(validate_client_id_url(&url(CLIENT_ID)).is_ok());
        assert!(validate_client_id_url(&url("http://client.example/meta.json")).is_err());
        assert!(validate_client_id_url(&url("https://client.example")).is_err());
        assert!(validate_client_id_url(&url("https://user@client.example/meta.json")).is_err());
        assert!(validate_client_id_url(&url("https://client.example/meta.json#f")).is_err());
        assert!(validate_client_id_url(&url("https://client.example:8443/meta.json")).is_ok());
    }

    #[test]
    fn client_metadata_validation_enforces_public_client_rules() {
        let good = client_metadata();
        assert!(validate_client_metadata(&good, "http://127.0.0.1:33418/auth/callback").is_ok());

        let mut bad = client_metadata();
        bad.response_types = vec!["token".to_string()];
        assert!(validate_client_metadata(&bad, "http://127.0.0.1:33418/auth/callback").is_err());

        let mut bad = client_metadata();
        bad.grant_types = vec!["client_credentials".to_string()];
        assert!(validate_client_metadata(&bad, "http://127.0.0.1:33418/auth/callback").is_err());

        let mut bad = client_metadata();
        bad.token_endpoint_auth_method = "client_secret_basic".to_string();
        assert!(validate_client_metadata(&bad, "http://127.0.0.1:33418/auth/callback").is_err());

        let mut bad = client_metadata();
        bad.redirect_uris.clear();
        assert!(validate_client_metadata(&bad, "http://127.0.0.1:33418/auth/callback").is_err());

        let mut bad = client_metadata();
        bad.redirect_uris = (0..=MAX_REDIRECT_URIS)
            .map(|index| format!("https://client.example/callback/{index}"))
            .collect();
        assert!(validate_client_metadata(&bad, "https://client.example/callback/0").is_err());

        let mut bad = client_metadata();
        bad.client_name = String::new();
        assert!(validate_client_metadata(&bad, "http://127.0.0.1:33418/auth/callback").is_err());
    }

    #[test]
    fn redirect_uri_must_match_exactly() {
        let metadata = client_metadata();
        let cases = [
            "http://127.0.0.1:33419/auth/callback",
            "http://127.0.0.1:33418/auth/callback/extra",
            "https://client.example/auth/callback",
            "http://localhost:33418/auth/callback",
        ];
        for redirect in cases {
            let err = validate_client_metadata(&metadata, redirect).unwrap_err();
            assert_eq!(err.code(), ErrorCode::InvalidInput, "{redirect}");
        }

        let mut wildcard = client_metadata();
        wildcard.redirect_uris = vec!["https://client.example/*".to_string()];
        assert!(validate_client_metadata(&wildcard, "https://client.example/anything").is_err());
    }

    #[test]
    fn fetch_client_metadata_checks_document_identity() {
        let document = serde_json::json!({
            "client_id": CLIENT_ID,
            "client_name": "Zero",
            "redirect_uris": ["http://127.0.0.1:33418/auth/callback"],
            "grant_types": ["authorization_code"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
            "scope": "files:read",
        });
        let fetcher = ScriptedFetcher::default().with(CLIENT_ID, Some(&document.to_string()));
        let metadata = fetch_client_metadata(&fetcher, &url(CLIENT_ID)).unwrap();
        assert_eq!(metadata.client_id, CLIENT_ID);
        assert!(metadata.scope.is_some());

        let mut impostor = document.clone();
        impostor["client_id"] = Value::String("https://attacker.example/meta.json".into());
        let fetcher = ScriptedFetcher::default().with(CLIENT_ID, Some(&impostor.to_string()));
        let err = fetch_client_metadata(&fetcher, &url(CLIENT_ID)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderAuth);

        let fetcher = ScriptedFetcher::default().with(CLIENT_ID, Some("not json"));
        assert!(fetch_client_metadata(&fetcher, &url(CLIENT_ID)).is_err());

        let fetcher = ScriptedFetcher::default();
        let err = fetch_client_metadata(&fetcher, &url(CLIENT_ID)).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn canonical_resource_rejects_ambiguous_urls() {
        assert_eq!(
            canonical_resource(&url("HTTPS://Server-A.Example:443/mcp"))
                .unwrap()
                .as_str(),
            SERVER_A
        );
        assert!(canonical_resource(&url("http://server-a.example/mcp")).is_err());
        assert!(canonical_resource(&url("http://127.0.0.1:8080/mcp")).is_ok());
        assert!(canonical_resource(&url("https://server-a.example/mcp#fragment")).is_err());
        assert!(canonical_resource(&url("https://user@server-a.example/mcp")).is_err());
    }
}
