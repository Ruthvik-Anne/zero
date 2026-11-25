//! Sign-in flows (SEC-11, PRV-09, PRV-10).
//!
//! Two real flows:
//!
//! - **OpenCode Console** device authorization: `POST {server}/auth/device/code`,
//!   then poll `POST {server}/auth/device/token` with
//!   `grant_type=urn:ietf:params:oauth:grant-type:device_code`. The user opens the
//!   verification URL; `authorization_pending` and `slow_down` are handled.
//! - **ChatGPT "Sign in with ChatGPT"**: system-browser OAuth 2.0 code flow with
//!   PKCE S256 on a `127.0.0.1` loopback callback, the
//!   `chatgpt.tokens.use.direct` scope, the `https://api.openai.com/v1` resource,
//!   and `ext_agent_host_id`. The first sign-in presents the dynamic client and
//!   receives an issued client id on the callback.
//!
//! Tokens are written to the encrypted credential store, never to config. The
//! terms gate refuses any provider/method that is not documented for third-party
//! clients and records the date the documentation was checked.

use crate::credentials::Keychain;
use crate::flows::AuthMethod;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64URL;
use base64::Engine;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::{Duration, Instant};
use url::Url;
use zero_types::error::{ErrorCode, Result, ZeroError};

pub const OPENCODE_CONSOLE: &str = "https://opencode.ai/console";
pub const OPENCODE_CLIENT_ID: &str = "opencode-cli";
pub const CHATGPT_AUTHORIZE_URL: &str = "https://auth.openai.com/api/accounts/authorize";
pub const CHATGPT_TOKEN_URL: &str = "https://auth.openai.com/api/accounts/oauth/token";
pub const CHATGPT_DYNAMIC_CLIENT: &str = "dynamic_agent_client";
pub const CHATGPT_RESOURCE: &str = "https://api.openai.com/v1";
pub const CHATGPT_SCOPES: &str =
    "openid profile email offline_access resource.invoke chatgpt.tokens.use.direct";
pub const CHATGPT_CALLBACK_PATH: &str = "/auth/callback";
pub const TERMS_CHECKED_ON: &str = "2026-11-24";

/// OAuth tokens as returned by a provider.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TokenSet {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub id_token: Option<String>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub expires_in_s: Option<i64>,
    #[serde(default)]
    pub org_id: Option<String>,
    /// The client id issued by the provider during dynamic registration.
    #[serde(default)]
    pub issued_client_id: Option<String>,
    #[serde(default)]
    pub account: Option<String>,
}

impl TokenSet {
    pub fn grants(&self, scope: &str) -> bool {
        self.scopes.iter().any(|s| s == scope)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpResponse {
    pub status: u16,
    pub body: String,
}

/// The three request shapes the flows need. Tests substitute a scripted
/// implementation; production uses [`ReqwestTransport`].
pub trait Transport {
    fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<HttpResponse>;
    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse>;
    fn get_bearer(&self, url: &str, token: &str) -> Result<HttpResponse>;
}

/// Blocking HTTPS client used outside tests.
#[derive(Debug, Clone, Copy, Default)]
pub struct ReqwestTransport;

impl Transport for ReqwestTransport {
    fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<HttpResponse> {
        let client = blocking_client()?;
        let response = client.post(url).form(form).send().map_err(transport_error)?;
        finish(response)
    }

    fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse> {
        let client = blocking_client()?;
        let response = client.post(url).json(body).send().map_err(transport_error)?;
        finish(response)
    }

    fn get_bearer(&self, url: &str, token: &str) -> Result<HttpResponse> {
        let client = blocking_client()?;
        let response = client.get(url).bearer_auth(token).send().map_err(transport_error)?;
        finish(response)
    }
}

fn blocking_client() -> Result<reqwest::blocking::Client> {
    reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| ZeroError::new(ErrorCode::Internal, format!("http client: {e}")))
}

fn transport_error(error: reqwest::Error) -> ZeroError {
    if error.is_timeout() {
        ZeroError::new(ErrorCode::Timeout, format!("oauth request timed out: {error}"))
    } else if error.is_connect() {
        ZeroError::new(ErrorCode::Offline, format!("oauth endpoint unreachable: {error}"))
    } else {
        ZeroError::new(ErrorCode::ProviderUnavailable, format!("oauth request failed: {error}"))
    }
}

fn finish(response: reqwest::blocking::Response) -> Result<HttpResponse> {
    let status = response.status().as_u16();
    let body = response.text().map_err(transport_error)?;
    Ok(HttpResponse { status, body })
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Pkce {
    pub verifier: String,
    pub challenge: String,
}

/// RFC 7636 verifier and S256 challenge.
pub fn pkce() -> Pkce {
    let verifier = B64URL.encode(random_bytes(32));
    let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
    Pkce { verifier, challenge }
}

pub fn random_bytes(n: usize) -> Vec<u8> {
    let mut buf = vec![0u8; n];
    if getrandom::getrandom(&mut buf).is_err() {
        // A failure here must not silently produce a predictable verifier.
        panic!("the operating system random source failed");
    }
    buf
}

/// A new `urn:uuid:` host id for ChatGPT sign-in, bound to this host.
pub fn new_agent_host_id() -> String {
    let mut bytes = random_bytes(16);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "urn:uuid:{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13], bytes[14], bytes[15]
    )
}

/// One provider's OAuth configuration.
#[derive(Debug, Clone)]
pub struct OAuthClient {
    pub provider: String,
    pub client_id: String,
    pub scopes: String,
    pub authorize_url: String,
    pub token_url: String,
    pub device_code_url: Option<String>,
    pub userinfo_url: Option<String>,
    pub extra_authorize: BTreeMap<String, String>,
    pub extra_token: BTreeMap<String, String>,
}

impl OAuthClient {
    pub fn opencode_console(base: &str) -> Self {
        let base = base.trim_end_matches('/');
        Self {
            provider: "opencode".into(),
            client_id: OPENCODE_CLIENT_ID.into(),
            scopes: String::new(),
            authorize_url: String::new(),
            token_url: format!("{base}/auth/device/token"),
            device_code_url: Some(format!("{base}/auth/device/code")),
            userinfo_url: Some(format!("{base}/api/user")),
            extra_authorize: BTreeMap::new(),
            extra_token: BTreeMap::new(),
        }
    }

    /// ChatGPT sign-in. Pass the issued client id for a returning account; omit
    /// it to register a new one through `dynamic_agent_client`.
    pub fn chatgpt(host_id: &str, agent_name: &str, issued_client: Option<&str>) -> Self {
        let mut extra_authorize = BTreeMap::new();
        extra_authorize.insert("resource".into(), CHATGPT_RESOURCE.into());
        extra_authorize.insert("ext_agent_host_id".into(), host_id.into());
        if issued_client.is_none() {
            extra_authorize.insert("agent_name_hint".into(), agent_name.into());
        }
        let mut extra_token = BTreeMap::new();
        extra_token.insert("resource".into(), CHATGPT_RESOURCE.into());
        Self {
            provider: "chatgpt".into(),
            client_id: issued_client.unwrap_or(CHATGPT_DYNAMIC_CLIENT).into(),
            scopes: CHATGPT_SCOPES.into(),
            authorize_url: CHATGPT_AUTHORIZE_URL.into(),
            token_url: CHATGPT_TOKEN_URL.into(),
            device_code_url: None,
            userinfo_url: None,
            extra_authorize,
            extra_token,
        }
    }

    /// Authorization URL for the system browser.
    pub fn authorization_url(
        &self,
        redirect_uri: &str,
        pkce: &Pkce,
        state: &str,
        nonce: &str,
    ) -> Result<String> {
        let mut url = Url::parse(&self.authorize_url)
            .map_err(|e| ZeroError::new(ErrorCode::InvalidInput, format!("authorize URL: {e}")))?;
        {
            let mut query = url.query_pairs_mut();
            query
                .append_pair("response_type", "code")
                .append_pair("client_id", &self.client_id)
                .append_pair("redirect_uri", redirect_uri)
                .append_pair("scope", &self.scopes)
                .append_pair("state", state)
                .append_pair("nonce", nonce)
                .append_pair("code_challenge_method", "S256")
                .append_pair("code_challenge", &pkce.challenge);
            for (key, value) in &self.extra_authorize {
                query.append_pair(key, value);
            }
        }
        Ok(url.into())
    }

    /// Exchange an authorization code. `client_id` overrides the configured one
    /// for dynamic registration, where the callback carries the issued id.
    pub fn exchange_code(
        &self,
        transport: &dyn Transport,
        code: &str,
        redirect_uri: &str,
        verifier: &str,
        client_id: Option<&str>,
    ) -> Result<TokenSet> {
        let mut form = vec![
            ("grant_type".to_string(), "authorization_code".to_string()),
            ("code".to_string(), code.to_string()),
            ("code_verifier".to_string(), verifier.to_string()),
            ("redirect_uri".to_string(), redirect_uri.to_string()),
            ("client_id".to_string(), client_id.unwrap_or(&self.client_id).to_string()),
        ];
        for (key, value) in &self.extra_token {
            form.push((key.clone(), value.clone()));
        }
        let response = transport.post_form(&self.token_url, &form)?;
        parse_tokens(response, &self.scopes)
    }

    pub fn refresh(&self, transport: &dyn Transport, refresh_token: &str) -> Result<TokenSet> {
        let mut form = vec![
            ("grant_type".to_string(), "refresh_token".to_string()),
            ("refresh_token".to_string(), refresh_token.to_string()),
            ("client_id".to_string(), self.client_id.clone()),
        ];
        for (key, value) in &self.extra_token {
            form.push((key.clone(), value.clone()));
        }
        let response = transport.post_form(&self.token_url, &form)?;
        parse_tokens(response, &self.scopes)
    }
}

#[derive(Debug, Deserialize)]
struct TokenPayload {
    access_token: Option<String>,
    refresh_token: Option<String>,
    id_token: Option<String>,
    expires_in: Option<i64>,
    scope: Option<String>,
    org_id: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

fn parse_tokens(response: HttpResponse, requested_scopes: &str) -> Result<TokenSet> {
    let payload: TokenPayload = serde_json::from_str(&response.body).map_err(|e| {
        ZeroError::new(
            ErrorCode::ProviderProtocol,
            format!("token response is not JSON ({e})"),
        )
    })?;
    if let Some(error) = payload.error {
        return Err(oauth_error(&error, payload.error_description.as_deref()));
    }
    if response.status >= 400 {
        return Err(ZeroError::new(
            ErrorCode::ProviderAuth,
            format!("token endpoint returned {}", response.status),
        ));
    }
    let access_token = payload.access_token.ok_or_else(|| {
        ZeroError::new(ErrorCode::ProviderProtocol, "token response has no access_token")
    })?;
    let scopes = payload
        .scope
        .unwrap_or_else(|| requested_scopes.to_string())
        .split_whitespace()
        .map(str::to_string)
        .collect();
    Ok(TokenSet {
        access_token,
        refresh_token: payload.refresh_token,
        id_token: payload.id_token,
        scopes,
        expires_in_s: payload.expires_in,
        org_id: payload.org_id,
        issued_client_id: None,
        account: None,
    })
}

fn oauth_error(error: &str, description: Option<&str>) -> ZeroError {
    let detail = description.map(|d| format!(": {d}")).unwrap_or_default();
    let code = match error {
        "invalid_grant" | "expired_token" | "access_denied" | "slow_down"
        | "authorization_pending" | "invalid_client" | "unauthorized_client" => {
            ErrorCode::ProviderAuth
        }
        "temporarily_unavailable" => ErrorCode::ProviderUnavailable,
        _ => ErrorCode::ProviderProtocol,
    };
    ZeroError::new(code, format!("oauth error `{error}`{detail}"))
}

// ---------------------------------------------------------------------------
// Device authorization (OpenCode Console)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCode {
    pub device_code: String,
    pub user_code: String,
    pub verification_uri: String,
    pub expires_in_s: i64,
    pub interval_s: i64,
}

#[derive(Debug, Deserialize)]
struct DevicePayload {
    device_code: String,
    user_code: String,
    verification_uri_complete: Option<String>,
    verification_uri: Option<String>,
    expires_in: i64,
    #[serde(default)]
    interval: i64,
}

pub fn request_device_code(client: &OAuthClient, transport: &dyn Transport) -> Result<DeviceCode> {
    let url = client
        .device_code_url
        .as_deref()
        .ok_or_else(|| ZeroError::new(ErrorCode::Unsupported, "this provider has no device flow"))?;
    let body = serde_json::json!({
        "client_id": client.client_id.as_str(),
        "supports_org_scope": true,
    });
    let response = transport.post_json(url, &body)?;
    if response.status >= 400 {
        return Err(ZeroError::new(
            ErrorCode::ProviderAuth,
            format!("device authorization returned {}", response.status),
        ));
    }
    let payload: DevicePayload = serde_json::from_str(&response.body).map_err(|e| {
        ZeroError::new(
            ErrorCode::ProviderProtocol,
            format!("device authorization is not JSON ({e})"),
        )
    })?;
    let verification = payload
        .verification_uri_complete
        .or(payload.verification_uri)
        .ok_or_else(|| {
            ZeroError::new(ErrorCode::ProviderProtocol, "device authorization has no verification URL")
        })?;
    let verification_uri = resolve_verification_url(&client.token_url, &client.provider, &verification)?;
    Ok(DeviceCode {
        device_code: payload.device_code,
        user_code: payload.user_code,
        verification_uri,
        expires_in_s: payload.expires_in.max(1),
        interval_s: payload.interval.max(1),
    })
}

/// Device verification URLs may be origin-rooted (`/console/device?...`) or
/// relative. The server base is `https://opencode.ai/console`.
fn resolve_verification_url(token_url: &str, provider: &str, value: &str) -> Result<String> {
    let base = if provider == "opencode" {
        token_url
            .trim_end_matches("/auth/device/token")
            .trim_end_matches('/')
    } else {
        token_url.trim_end_matches('/')
    };
    let base = format!("{base}/");
    let joined = Url::parse(&base)
        .ok()
        .and_then(|b| b.join(value).ok())
        .ok_or_else(|| ZeroError::new(ErrorCode::ProviderProtocol, "invalid verification URL"))?;
    if !matches!(joined.scheme(), "http" | "https") {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "verification URL must be http or https",
        ));
    }
    Ok(joined.into())
}

/// Sleeps between device-token polls. Tests use a recorder so polling logic is
/// deterministic and fast.
pub trait Sleeper {
    fn sleep(&mut self, duration: Duration);
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ThreadSleeper;

impl Sleeper for ThreadSleeper {
    fn sleep(&mut self, duration: Duration) {
        std::thread::sleep(duration);
    }
}

/// Poll until the user approves, the code expires, or the provider refuses.
pub fn poll_device_token(
    client: &OAuthClient,
    transport: &dyn Transport,
    device: &DeviceCode,
    sleeper: &mut dyn Sleeper,
) -> Result<TokenSet> {
    let expires_ms = device.expires_in_s.saturating_mul(1000);
    let mut interval_ms = device.interval_s.saturating_mul(1000);
    let mut waited_ms = 0i64;
    loop {
        if waited_ms >= expires_ms {
            return Err(ZeroError::new(
                ErrorCode::ProviderAuth,
                "device code expired before approval; start the sign-in again",
            ));
        }
        sleeper.sleep(Duration::from_millis(interval_ms.max(1000) as u64));
        waited_ms += interval_ms.max(1000);
        let form = vec![
            (
                "grant_type".to_string(),
                "urn:ietf:params:oauth:grant-type:device_code".to_string(),
            ),
            ("device_code".to_string(), device.device_code.clone()),
            ("client_id".to_string(), client.client_id.clone()),
        ];
        let response = transport.post_form(&client.token_url, &form)?;
        let payload: TokenPayload = serde_json::from_str(&response.body).map_err(|e| {
            ZeroError::new(
                ErrorCode::ProviderProtocol,
                format!("device token response is not JSON ({e})"),
            )
        })?;
        if payload.access_token.is_some() {
            return parse_tokens(response, "");
        }
        match payload.error.as_deref() {
            Some("authorization_pending") => continue,
            Some("slow_down") => {
                interval_ms = interval_ms.saturating_add(5_000);
                continue;
            }
            Some(error) => {
                return Err(oauth_error(error, payload.error_description.as_deref()));
            }
            None => {
                return Err(ZeroError::new(
                    ErrorCode::ProviderProtocol,
                    "device token response has neither a token nor an error",
                ));
            }
        }
    }
}

/// The full OpenCode Console sign-in: obtain a code, show the URL, then poll.
pub struct DeviceSignIn {
    pub client: OAuthClient,
}

impl DeviceSignIn {
    pub fn opencode() -> Self {
        Self { client: OAuthClient::opencode_console(OPENCODE_CONSOLE) }
    }

    pub fn with_base(base: &str) -> Self {
        Self { client: OAuthClient::opencode_console(base) }
    }

    pub fn begin(&self, transport: &dyn Transport) -> Result<DeviceCode> {
        TermsRegistry::shipped().check(&self.client.provider, AuthMethod::DeviceCode)?;
        request_device_code(&self.client, transport)
    }

    pub fn complete(
        &self,
        transport: &dyn Transport,
        device: &DeviceCode,
        sleeper: &mut dyn Sleeper,
    ) -> Result<TokenSet> {
        poll_device_token(&self.client, transport, device, sleeper)
    }
}

// ---------------------------------------------------------------------------
// ChatGPT loopback PKCE
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct Authorization {
    pub url: String,
    pub pkce: Pkce,
    pub state: String,
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Callback {
    pub code: String,
    pub state: String,
    pub client_id: Option<String>,
    pub scope: Option<String>,
}

pub struct LoopbackListener {
    listener: TcpListener,
    path: String,
}

impl LoopbackListener {
    /// Bind `127.0.0.1` on an ephemeral port with the given callback path.
    pub fn bind(path: &str) -> Result<Self> {
        let listener = TcpListener::bind(("127.0.0.1", 0)).map_err(|e| {
            ZeroError::new(ErrorCode::Io, format!("loopback listener: {e}"))
        })?;
        listener.set_nonblocking(true)?;
        Ok(Self { listener, path: path.to_string() })
    }

    pub fn port(&self) -> u16 {
        self.listener.local_addr().map(|a| a.port()).unwrap_or(0)
    }

    pub fn redirect_uri(&self) -> String {
        format!("http://127.0.0.1:{}{}", self.port(), self.path)
    }

    /// Accept exactly one callback, validate `state`, and return the code.
    pub fn wait_for_callback(&self, expected_state: &str, timeout: Duration) -> Result<Callback> {
        let deadline = Instant::now() + timeout;
        let stream = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    if Instant::now() >= deadline {
                        return Err(ZeroError::new(
                            ErrorCode::Timeout,
                            "timed out waiting for the sign-in callback",
                        ));
                    }
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) => {
                    return Err(ZeroError::new(ErrorCode::Io, format!("callback listener: {e}")));
                }
            }
        };
        self.handle(stream, expected_state)
    }

    fn handle(&self, mut stream: TcpStream, expected_state: &str) -> Result<Callback> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut buf = Vec::new();
        let mut chunk = [0u8; 1024];
        while !buf.windows(4).any(|w| w == b"\r\n\r\n") && buf.len() < 16 * 1024 {
            let n = stream.read(&mut chunk)?;
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
        }
        let request = String::from_utf8_lossy(&buf);
        let target = request
            .lines()
            .next()
            .and_then(|line| line.split_whitespace().nth(1))
            .ok_or_else(|| ZeroError::new(ErrorCode::InvalidInput, "malformed callback request"))?;
        let url = Url::parse(&format!("http://127.0.0.1{target}"))
            .map_err(|_| ZeroError::new(ErrorCode::InvalidInput, "malformed callback URL"))?;
        if url.path() != self.path {
            respond(&mut stream, 404, "not found");
            return Err(ZeroError::new(ErrorCode::NotFound, "unexpected callback path"));
        }
        let mut code = None;
        let mut state = None;
        let mut client_id = None;
        let mut scope = None;
        let mut error = None;
        for (key, value) in url.query_pairs() {
            match key.as_ref() {
                "code" => code = Some(value.into_owned()),
                "state" => state = Some(value.into_owned()),
                "client_id" => client_id = Some(value.into_owned()),
                "scope" => scope = Some(value.into_owned()),
                "error" => error = Some(value.into_owned()),
                _ => {}
            }
        }
        if state.as_deref() != Some(expected_state) {
            respond(&mut stream, 400, "state mismatch");
            return Err(ZeroError::new(
                ErrorCode::ProviderAuth,
                "sign-in callback state does not match this attempt",
            ));
        }
        if let Some(error) = error {
            respond(&mut stream, 400, "sign-in refused");
            return Err(oauth_error(&error, None));
        }
        let code = code.ok_or_else(|| {
            respond(&mut stream, 400, "missing code");
            ZeroError::new(ErrorCode::ProviderAuth, "sign-in callback has no code")
        })?;
        respond(&mut stream, 200, "Zero sign-in complete. You can close this tab.");
        Ok(Callback { code, state: state.unwrap_or_default(), client_id, scope })
    }
}

fn respond(stream: &mut TcpStream, status: u16, message: &str) {
    let body = format!(
        "<!doctype html><html><body><p>{}</p></body></html>",
        html_escape(message)
    );
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        404 => "Not Found",
        _ => "Error",
    };
    let response = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(response.as_bytes());
    let _ = stream.flush();
}

fn html_escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

/// The ChatGPT sign-in driver.
pub struct ChatGptSignIn {
    pub client: OAuthClient,
    pub host_id: String,
    pub agent_name: String,
}

impl ChatGptSignIn {
    pub fn new(host_id: &str, agent_name: &str, issued_client: Option<&str>) -> Self {
        Self {
            client: OAuthClient::chatgpt(host_id, agent_name, issued_client),
            host_id: host_id.into(),
            agent_name: agent_name.into(),
        }
    }

    pub fn begin(&self, listener: &LoopbackListener) -> Result<Authorization> {
        TermsRegistry::shipped().check(&self.client.provider, AuthMethod::OAuth)?;
        let pkce = pkce();
        let state = B64URL.encode(random_bytes(32));
        let nonce = B64URL.encode(random_bytes(32));
        let url = self
            .client
            .authorization_url(&listener.redirect_uri(), &pkce, &state, &nonce)?;
        Ok(Authorization { url, pkce, state, nonce })
    }

    pub fn complete(
        &self,
        transport: &dyn Transport,
        listener: &LoopbackListener,
        authorization: &Authorization,
    ) -> Result<TokenSet> {
        let callback =
            listener.wait_for_callback(&authorization.state, Duration::from_secs(300))?;
        let dynamic = self.client.client_id == CHATGPT_DYNAMIC_CLIENT;
        let issued = callback.client_id.clone().or_else(|| {
            if dynamic {
                None
            } else {
                Some(self.client.client_id.clone())
            }
        });
        if dynamic && issued.is_none() {
            return Err(ZeroError::new(
                ErrorCode::ProviderAuth,
                "registration did not return an issued client id",
            ));
        }
        if let (Some(expected), Some(returned)) = (
            if dynamic { None } else { Some(&self.client.client_id) },
            callback.client_id.as_ref(),
        ) {
            if expected != returned {
                return Err(ZeroError::new(
                    ErrorCode::ProviderAuth,
                    "callback client id does not match this registration",
                ));
            }
        }
        let mut tokens = self.client.exchange_code(
            transport,
            &callback.code,
            &listener.redirect_uri(),
            &authorization.pkce.verifier,
            issued.as_deref(),
        )?;
        tokens.issued_client_id = issued;
        Ok(tokens)
    }
}

/// Open the system browser. User-initiated; never called by the agent.
pub fn open_system_browser(url: &str) -> Result<()> {
    #[cfg(windows)]
    let mut command = {
        let mut command = std::process::Command::new("cmd");
        command.args(["/C", "start", "", url]);
        command
    };
    #[cfg(target_os = "macos")]
    let mut command = {
        let mut command = std::process::Command::new("open");
        command.arg(url);
        command
    };
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut command = {
        let mut command = std::process::Command::new("xdg-open");
        command.arg(url);
        command
    };
    command
        .spawn()
        .map(|_| ())
        .map_err(|e| ZeroError::new(ErrorCode::Unavailable, format!("cannot open a browser: {e}")))
}

// ---------------------------------------------------------------------------
// Storage and terms gate
// ---------------------------------------------------------------------------

/// Tokens live in the encrypted credential store under `provider/account`.
pub fn store_tokens(
    keychain: &mut dyn Keychain,
    provider: &str,
    account: &str,
    tokens: &TokenSet,
) -> Result<()> {
    let encoded = serde_json::to_string(tokens)?;
    keychain.set(provider, account, &encoded)
}

pub fn load_tokens(
    keychain: &dyn Keychain,
    provider: &str,
    account: &str,
) -> Result<Option<TokenSet>> {
    match keychain.get(provider, account)? {
        Some(encoded) => Ok(Some(serde_json::from_str(&encoded)?)),
        None => Ok(None),
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TermsEntry {
    pub provider: String,
    pub methods: Vec<AuthMethod>,
    pub documented: bool,
    pub checked_on: String,
    pub note: String,
}

/// Shipped sign-in flows and their last verified terms status.
#[derive(Debug, Clone)]
pub struct TermsRegistry {
    entries: Vec<TermsEntry>,
}

impl TermsRegistry {
    pub fn shipped() -> Self {
        Self {
            entries: vec![
                TermsEntry {
                    provider: "opencode".into(),
                    methods: vec![AuthMethod::OAuth, AuthMethod::DeviceCode],
                    documented: true,
                    checked_on: TERMS_CHECKED_ON.into(),
                    note: "OpenCode Console device authorization for the `opencode-cli` client.".into(),
                },
                TermsEntry {
                    provider: "chatgpt".into(),
                    methods: vec![AuthMethod::OAuth],
                    documented: true,
                    checked_on: TERMS_CHECKED_ON.into(),
                    note: "Sign in with ChatGPT: dynamic client registration, loopback PKCE, \
                           chatgpt.tokens.use.direct."
                        .into(),
                },
                TermsEntry {
                    provider: "claude".into(),
                    methods: vec![AuthMethod::OAuth],
                    documented: false,
                    checked_on: TERMS_CHECKED_ON.into(),
                    note: "Anthropic consumer OAuth is for Anthropic's own apps; use an API key.".into(),
                },
                TermsEntry {
                    provider: "github-copilot".into(),
                    methods: vec![AuthMethod::OAuth],
                    documented: false,
                    checked_on: TERMS_CHECKED_ON.into(),
                    note: "The OpenCode partnership does not cover other agents.".into(),
                },
            ],
        }
    }

    pub fn entries(&self) -> &[TermsEntry] {
        &self.entries
    }

    pub fn check(&self, provider: &str, method: AuthMethod) -> Result<&TermsEntry> {
        let entry = self
            .entries
            .iter()
            .find(|entry| entry.provider.eq_ignore_ascii_case(provider))
            .ok_or_else(|| {
                ZeroError::new(
                    ErrorCode::Unavailable,
                    format!("no sign-in flow ships for `{provider}`"),
                )
            })?;
        if !entry.methods.contains(&method) {
            return Err(ZeroError::new(
                ErrorCode::Unavailable,
                format!(
                    "{provider} does not document {:?} for third-party clients (checked {})",
                    method, entry.checked_on
                ),
            ));
        }
        if !entry.documented {
            return Err(ZeroError::new(
                ErrorCode::Unavailable,
                format!(
                    "{provider} {:?} is not documented for third-party clients (checked {}): {}",
                    method, entry.checked_on, entry.note
                ),
            ));
        }
        Ok(entry)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keychain::EncryptedKeychain;
    use std::collections::VecDeque;
    use std::sync::Mutex;

    type Forms = Vec<(String, Vec<(String, String)>)>;
    type Jsons = Vec<(String, serde_json::Value)>;

    #[derive(Default)]
    struct FakeTransport {
        responses: Mutex<VecDeque<HttpResponse>>,
        forms: Mutex<Forms>,
        jsons: Mutex<Jsons>,
    }

    impl FakeTransport {
        fn with(responses: Vec<HttpResponse>) -> Self {
            Self {
                responses: Mutex::new(responses.into()),
                forms: Mutex::new(Vec::new()),
                jsons: Mutex::new(Vec::new()),
            }
        }

        fn forms(&self) -> Forms {
            self.forms.lock().unwrap().clone()
        }

        fn jsons(&self) -> Jsons {
            self.jsons.lock().unwrap().clone()
        }

        fn next(&self) -> HttpResponse {
            self.responses
                .lock()
                .unwrap()
                .pop_front()
                .unwrap_or(HttpResponse { status: 500, body: "{}".into() })
        }
    }

    impl Transport for FakeTransport {
        fn post_form(&self, url: &str, form: &[(String, String)]) -> Result<HttpResponse> {
            self.forms.lock().unwrap().push((url.into(), form.to_vec()));
            Ok(self.next())
        }

        fn post_json(&self, url: &str, body: &serde_json::Value) -> Result<HttpResponse> {
            self.jsons.lock().unwrap().push((url.into(), body.clone()));
            Ok(self.next())
        }

        fn get_bearer(&self, _url: &str, _token: &str) -> Result<HttpResponse> {
            Ok(self.next())
        }
    }

    #[derive(Default)]
    struct RecordingSleeper {
        slept: Vec<u64>,
    }

    impl Sleeper for RecordingSleeper {
        fn sleep(&mut self, duration: Duration) {
            self.slept.push(duration.as_millis() as u64);
        }
    }

    fn token_json(access: &str, refresh: &str) -> String {
        format!(
            r#"{{"access_token":"{access}","refresh_token":"{refresh}","id_token":"id-{access}","expires_in":3600,"scope":"openid profile email offline_access resource.invoke chatgpt.tokens.use.direct","org_id":"org-1"}}"#
        )
    }

    #[test]
    fn pkce_matches_the_rfc7636_vector() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let challenge = B64URL.encode(Sha256::digest(verifier.as_bytes()));
        assert_eq!(challenge, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        let pair = pkce();
        assert!(pair.verifier.len() >= 43);
        assert_ne!(pair.challenge, pair.verifier);
    }

    #[test]
    fn chatgpt_authorization_url_carries_the_documented_parameters() {
        let host = "urn:uuid:11111111-2222-4333-8444-555555555555";
        let sign_in = ChatGptSignIn::new(host, "Zero", None);
        let listener = LoopbackListener::bind(CHATGPT_CALLBACK_PATH).unwrap();
        let auth = sign_in.begin(&listener).unwrap();
        let url = Url::parse(&auth.url).unwrap();
        assert_eq!(url.scheme(), "https");
        assert_eq!(url.host_str(), Some("auth.openai.com"));
        assert_eq!(url.path(), "/api/accounts/authorize");
        let params: BTreeMap<String, String> = url
            .query_pairs()
            .map(|(k, v)| (k.into_owned(), v.into_owned()))
            .collect();
        assert_eq!(params["client_id"], CHATGPT_DYNAMIC_CLIENT);
        assert_eq!(params["redirect_uri"], listener.redirect_uri());
        assert_eq!(params["scope"], CHATGPT_SCOPES);
        assert_eq!(params["resource"], CHATGPT_RESOURCE);
        assert_eq!(params["ext_agent_host_id"], host);
        assert_eq!(params["agent_name_hint"], "Zero");
        assert_eq!(params["code_challenge_method"], "S256");
        assert_eq!(params["state"], auth.state);
        assert_eq!(params["nonce"], auth.nonce);
        assert!(listener.redirect_uri().starts_with("http://127.0.0.1:"));
        assert!(listener.redirect_uri().ends_with("/auth/callback"));
    }

    #[test]
    fn chatgpt_callback_is_validated_and_the_code_is_exchanged() {
        let listener = LoopbackListener::bind(CHATGPT_CALLBACK_PATH).unwrap();
        let sign_in = ChatGptSignIn::new(
            "urn:uuid:11111111-2222-4333-8444-555555555555",
            "Zero",
            None,
        );
        let auth = sign_in.begin(&listener).unwrap();
        let expected_state = auth.state.clone();
        let port = listener.port();
        let callback = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(
                stream,
                "GET /auth/callback?code=auth-code&state={expected_state}&client_id=oaiapp_123&scope=openid%20chatgpt.tokens.use.direct HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("200 OK"), "{response}");
        });
        let transport = FakeTransport::with(vec![HttpResponse {
            status: 200,
            body: token_json("access-1", "refresh-1"),
        }]);
        let tokens = sign_in.complete(&transport, &listener, &auth).unwrap();
        callback.join().unwrap();
        assert_eq!(tokens.access_token, "access-1");
        assert_eq!(tokens.issued_client_id.as_deref(), Some("oaiapp_123"));
        assert!(tokens.grants("chatgpt.tokens.use.direct"));
        let forms = transport.forms();
        assert_eq!(forms.len(), 1);
        let form: BTreeMap<String, String> = forms[0].1.iter().cloned().collect();
        assert_eq!(form["grant_type"], "authorization_code");
        assert_eq!(form["code"], "auth-code");
        assert_eq!(form["client_id"], "oaiapp_123");
        assert_eq!(form["redirect_uri"], listener.redirect_uri());
        assert_eq!(form["resource"], CHATGPT_RESOURCE);
        assert_eq!(form["code_verifier"], auth.pkce.verifier);
    }

    #[test]
    fn a_forged_callback_state_is_refused() {
        let listener = LoopbackListener::bind(CHATGPT_CALLBACK_PATH).unwrap();
        let port = listener.port();
        let callback = std::thread::spawn(move || {
            let mut stream = TcpStream::connect(("127.0.0.1", port)).unwrap();
            write!(
                stream,
                "GET /auth/callback?code=stolen&state=wrong HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            .unwrap();
            let mut response = String::new();
            stream.read_to_string(&mut response).unwrap();
            assert!(response.contains("400"), "{response}");
        });
        let err = listener
            .wait_for_callback("expected", Duration::from_secs(5))
            .unwrap_err();
        callback.join().unwrap();
        assert_eq!(err.code(), ErrorCode::ProviderAuth);
        assert!(err.message().contains("state"));
    }

    #[test]
    fn the_opencode_device_flow_resolves_the_url_and_polls() {
        let pending = HttpResponse {
            status: 200,
            body: r#"{"error":"authorization_pending"}"#.into(),
        };
        let slow = HttpResponse {
            status: 200,
            body: r#"{"error":"slow_down"}"#.into(),
        };
        let token = HttpResponse {
            status: 200,
            body: token_json("oc-access", "oc-refresh"),
        };
        let device_json = r#"{"device_code":"dev-1","user_code":"ABCD-EFGH","verification_uri_complete":"/console/device?user_code=ABCD-EFGH","expires_in":600,"interval":1}"#;
        let transport = FakeTransport::with(vec![
            HttpResponse { status: 200, body: device_json.into() },
            pending,
            slow,
            token,
        ]);
        let sign_in = DeviceSignIn::with_base("https://opencode.ai/console");
        let device = sign_in.begin(&transport).unwrap();
        assert_eq!(device.user_code, "ABCD-EFGH");
        assert_eq!(
            device.verification_uri,
            "https://opencode.ai/console/device?user_code=ABCD-EFGH"
        );
        let mut sleeper = RecordingSleeper::default();
        let tokens = sign_in.complete(&transport, &device, &mut sleeper).unwrap();
        assert_eq!(tokens.access_token, "oc-access");
        assert_eq!(tokens.refresh_token.as_deref(), Some("oc-refresh"));
        assert_eq!(sleeper.slept, vec![1000, 1000, 6000]);
        let calls = transport.forms();
        assert_eq!(calls.len(), 3);
        let form: BTreeMap<String, String> = calls[0].1.iter().cloned().collect();
        assert_eq!(
            form["grant_type"],
            "urn:ietf:params:oauth:grant-type:device_code"
        );
        assert_eq!(form["device_code"], "dev-1");
        assert_eq!(form["client_id"], OPENCODE_CLIENT_ID);
        let jsons = transport.jsons();
        let device_body = &jsons[0].1;
        assert_eq!(device_body["client_id"], OPENCODE_CLIENT_ID);
        assert_eq!(device_body["supports_org_scope"], true);
    }

    #[test]
    fn an_expired_device_code_stops_polling() {
        let pending = || HttpResponse {
            status: 200,
            body: r#"{"error":"authorization_pending"}"#.into(),
        };
        let device_json = r#"{"device_code":"dev-1","user_code":"AAAA","verification_uri":"https://opencode.ai/console/device","expires_in":2,"interval":1}"#;
        let transport = FakeTransport::with(vec![
            HttpResponse { status: 200, body: device_json.into() },
            pending(),
            pending(),
        ]);
        let sign_in = DeviceSignIn::with_base("https://opencode.ai/console");
        let device = sign_in.begin(&transport).unwrap();
        let mut sleeper = RecordingSleeper::default();
        let err = sign_in.complete(&transport, &device, &mut sleeper).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ProviderAuth);
        assert!(err.message().contains("expired"));
        assert_eq!(sleeper.slept.len(), 2);
    }

    #[test]
    fn refresh_rotates_the_tokens() {
        let transport = FakeTransport::with(vec![HttpResponse {
            status: 200,
            body: token_json("new-access", "new-refresh"),
        }]);
        let client = OAuthClient::chatgpt("urn:uuid:x", "Zero", Some("oaiapp_123"));
        let tokens = client.refresh(&transport, "old-refresh").unwrap();
        assert_eq!(tokens.access_token, "new-access");
        assert_eq!(tokens.refresh_token.as_deref(), Some("new-refresh"));
        let forms = transport.forms();
        let form: BTreeMap<String, String> = forms[0].1.iter().cloned().collect();
        assert_eq!(form["grant_type"], "refresh_token");
        assert_eq!(form["refresh_token"], "old-refresh");
        assert_eq!(form["client_id"], "oaiapp_123");
        assert_eq!(form["resource"], CHATGPT_RESOURCE);
    }

    #[test]
    fn tokens_are_stored_encrypted_and_reload() {
        let dir = tempfile::tempdir().unwrap();
        let mut keychain = EncryptedKeychain::open(dir.path().join("c.enc"), None).unwrap();
        let tokens = TokenSet {
            access_token: "secret-access-token".into(),
            refresh_token: Some("secret-refresh-token".into()),
            scopes: vec!["chatgpt.tokens.use.direct".into()],
            ..TokenSet::default()
        };
        store_tokens(&mut keychain, "chatgpt", "default", &tokens).unwrap();
        let raw = std::fs::read_to_string(dir.path().join("c.enc")).unwrap();
        assert!(!raw.contains("secret-access-token"));
        let loaded = load_tokens(&keychain, "chatgpt", "default").unwrap().unwrap();
        assert_eq!(loaded, tokens);
    }

    #[test]
    fn the_terms_registry_disables_undocumented_flows() {
        let registry = TermsRegistry::shipped();
        assert!(registry.check("opencode", AuthMethod::DeviceCode).is_ok());
        assert!(registry.check("chatgpt", AuthMethod::OAuth).is_ok());
        let claude = registry.check("claude", AuthMethod::OAuth).unwrap_err();
        assert_eq!(claude.code(), ErrorCode::Unavailable);
        assert!(claude.message().contains(TERMS_CHECKED_ON));
        let copilot = registry.check("github-copilot", AuthMethod::OAuth).unwrap_err();
        assert!(copilot.message().contains("not documented"));
        assert!(registry.check("unknown", AuthMethod::OAuth).is_err());
        assert_eq!(registry.entries().len(), 4);
    }

    #[test]
    fn a_flow_cannot_start_when_its_terms_do_not_allow_it() {
        let listener = LoopbackListener::bind(CHATGPT_CALLBACK_PATH).unwrap();
        let mut client = OAuthClient::chatgpt("urn:uuid:x", "Zero", None);
        client.provider = "claude".into();
        let sign_in = ChatGptSignIn {
            client,
            host_id: "urn:uuid:x".into(),
            agent_name: "Zero".into(),
        };
        let err = sign_in.begin(&listener).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(err.message().contains("not documented"));

        let mut device = DeviceSignIn::with_base("https://example.test");
        device.client.provider = "unknown".into();
        let transport = FakeTransport::with(Vec::new());
        let err = device.begin(&transport).unwrap_err();
        assert_eq!(err.code(), ErrorCode::Unavailable);
        assert!(transport.jsons().is_empty(), "no request leaves before the gate");
    }

    #[test]
    fn the_reqwest_transport_reaches_a_loopback_endpoint() {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let url = format!("http://127.0.0.1:{}/token", listener.local_addr().unwrap().port());
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 2048];
            let _ = stream.read(&mut buf).unwrap();
            let body = r#"{"access_token":"loopback"}"#;
            write!(
                stream,
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                body.len(),
                body
            )
            .unwrap();
        });
        let mut client = OAuthClient::chatgpt("urn:uuid:x", "Zero", Some("oaiapp_1"));
        client.token_url = url;
        let transport = ReqwestTransport;
        let tokens = client
            .exchange_code(&transport, "code", "http://127.0.0.1/cb", "verifier", None)
            .unwrap();
        server.join().unwrap();
        assert_eq!(tokens.access_token, "loopback");
    }
}
