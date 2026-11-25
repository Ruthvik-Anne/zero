//! SSRF and egress policy (WEB-16, WEB-17).
//!
//! [`EgressGuard`] is the gate every outbound web request passes through before
//! the fetch layer opens a socket:
//!
//! 1. The URL must use `http` or `https`, carry no userinfo, and name a host.
//! 2. Every address the host resolves to is classified. One forbidden answer
//!    rejects the request, so a DNS answer that mixes a public and a private
//!    address cannot win a race against the connect logic.
//! 3. The surviving addresses are returned in [`PinnedDestination`]. The fetch
//!    layer connects to those exact addresses and does not resolve again.
//! 4. Redirects repeat the whole check, including resolution, and may not
//!    downgrade HTTPS to HTTP or leave HTTP(S).
//! 5. Configured secrets are refused when they appear in the URL, a header
//!    value, or the body. Errors name the request part but never echo the
//!    secret.
//!
//! No fetch happens here: T-WEB-04 (fetch) calls [`EgressGuard::check_request`]
//! and then connects to [`PinnedDestination::addresses`].

use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};

use serde::{Deserialize, Serialize};
use url::{Host, Url};
use zero_types::error::{ErrorCode, Result, ZeroError};

/// Redirect budget for one navigation unless a caller sets another.
pub const DEFAULT_MAX_REDIRECTS: usize = 5;

/// Host names that front a cloud metadata service.
///
/// A hostname is refused before resolution, so a split-horizon DNS answer or a
/// name that changes later cannot expose the metadata endpoint.
const METADATA_HOSTS: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "metadata.azure.internal",
    "instance-data",
    "metadata",
];

/// How much outbound reach the caller allows.
///
/// The guard never infers a policy from an operating mode; the caller maps its
/// mode to one of these values and passes it in.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkPolicy {
    /// Deny every request. Local files, the search cache, and other work that
    /// does not open a socket keep working.
    Offline,
    /// Allow public HTTP(S) only. Loopback, private, shared, link-local,
    /// metadata, multicast, unspecified, broadcast, and reserved ranges are
    /// refused. This is the normal default for unattended web work.
    Restricted,
    /// Allow public and private destinations, including loopback, for a user
    /// who explicitly opted into local development targets. Link-local,
    /// metadata, multicast, unspecified, broadcast, and reserved ranges stay
    /// refused, as does every non-HTTP(S) scheme.
    Full,
}

impl NetworkPolicy {
    /// Stable lower-case name used in diagnostics and documentation.
    pub fn as_str(self) -> &'static str {
        match self {
            NetworkPolicy::Offline => "offline",
            NetworkPolicy::Restricted => "restricted",
            NetworkPolicy::Full => "full",
        }
    }

    /// Whether this policy allows one address class.
    pub fn allows(self, class: AddressClass) -> bool {
        match class {
            AddressClass::Public => !matches!(self, NetworkPolicy::Offline),
            AddressClass::Loopback | AddressClass::Private => {
                matches!(self, NetworkPolicy::Full)
            }
            AddressClass::LinkLocal
            | AddressClass::Multicast
            | AddressClass::Unspecified
            | AddressClass::Broadcast
            | AddressClass::Metadata
            | AddressClass::Reserved => false,
        }
    }
}

/// Coarse class of one resolved address.
///
/// The class is reported in refusals so a caller can tell loopback (local
/// development under [`NetworkPolicy::Full`]) from metadata (never allowed).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AddressClass {
    Public,
    Loopback,
    Private,
    LinkLocal,
    Multicast,
    Unspecified,
    Broadcast,
    Metadata,
    Reserved,
}

impl AddressClass {
    /// Stable lower-case name used in diagnostics and documentation.
    pub fn as_str(self) -> &'static str {
        match self {
            AddressClass::Public => "public",
            AddressClass::Loopback => "loopback",
            AddressClass::Private => "private",
            AddressClass::LinkLocal => "link-local",
            AddressClass::Multicast => "multicast",
            AddressClass::Unspecified => "unspecified",
            AddressClass::Broadcast => "broadcast",
            AddressClass::Metadata => "cloud metadata",
            AddressClass::Reserved => "reserved",
        }
    }
}

/// Scheme an egress request may use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EgressScheme {
    Http,
    Https,
}

impl EgressScheme {
    fn from_url(url: &Url) -> Option<Self> {
        match url.scheme() {
            "http" => Some(EgressScheme::Http),
            "https" => Some(EgressScheme::Https),
            _ => None,
        }
    }

    /// Stable lower-case name (`http` or `https`).
    pub fn as_str(self) -> &'static str {
        match self {
            EgressScheme::Http => "http",
            EgressScheme::Https => "https",
        }
    }

    /// Port used when the URL names none.
    pub fn default_port(self) -> u16 {
        match self {
            EgressScheme::Http => 80,
            EgressScheme::Https => 443,
        }
    }

    /// Whether this is the encrypted scheme.
    pub fn is_https(self) -> bool {
        matches!(self, EgressScheme::Https)
    }
}

/// Resolves a host to every address it currently answers with.
///
/// Tests supply a scripted resolver; production uses [`SystemResolver`]. The
/// trait takes `&self` so one guard can be shared across requests.
pub trait Resolver: Send + Sync {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>>;
}

/// Resolver backed by the operating system.
#[derive(Debug, Clone, Copy, Default)]
pub struct SystemResolver;

impl Resolver for SystemResolver {
    fn resolve(&self, host: &str, port: u16) -> io::Result<Vec<IpAddr>> {
        let mut addresses = Vec::new();
        for address in (host, port).to_socket_addrs()? {
            let ip = address.ip();
            if !addresses.contains(&ip) {
                addresses.push(ip);
            }
        }
        if addresses.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the host resolved to no addresses",
            ));
        }
        Ok(addresses)
    }
}

/// One validated destination with the addresses the fetch layer must use.
///
/// Fields are private so a caller cannot fabricate a destination that skipped
/// the address checks. Construct one with [`EgressGuard::check_url`] or
/// [`EgressGuard::check_redirect`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedDestination {
    url: String,
    scheme: EgressScheme,
    host: String,
    port: u16,
    addresses: Vec<IpAddr>,
    redirects: usize,
}

impl PinnedDestination {
    /// Canonical serialized URL (scheme and host lowercased, default port
    /// removed, path and query preserved).
    pub fn url(&self) -> &str {
        &self.url
    }

    /// HTTP or HTTPS.
    pub fn scheme(&self) -> EgressScheme {
        self.scheme
    }

    /// Host without brackets for IPv6 literals.
    pub fn host(&self) -> &str {
        &self.host
    }

    /// Effective port; the scheme default when the URL omitted it.
    pub fn port(&self) -> u16 {
        self.port
    }

    /// Every address returned by resolution, in resolver order, deduplicated.
    ///
    /// The fetch layer connects only to these addresses and must not resolve
    /// the host again.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }

    /// Hops followed from the original URL; zero for a direct request.
    pub fn redirects(&self) -> usize {
        self.redirects
    }

    /// Whether the destination uses TLS.
    pub fn is_https(&self) -> bool {
        self.scheme.is_https()
    }
}

/// A validated outbound request, ready for the fetch layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PinnedRequest<'a> {
    method: &'a str,
    destination: PinnedDestination,
    headers: &'a [(&'a str, &'a str)],
    body: &'a str,
}

impl<'a> PinnedRequest<'a> {
    /// HTTP method, validated as a token.
    pub fn method(&self) -> &'a str {
        self.method
    }

    /// Validated destination and pinned addresses.
    pub fn destination(&self) -> &PinnedDestination {
        &self.destination
    }

    /// Header name and value pairs as supplied by the caller.
    pub fn headers(&self) -> &'a [(&'a str, &'a str)] {
        self.headers
    }

    /// Request body as supplied by the caller.
    pub fn body(&self) -> &'a str {
        self.body
    }
}

/// The SSRF and egress gate.
///
/// `R` is the resolver; use [`EgressGuard::system`] for DNS or
/// [`EgressGuard::new`] with a scripted resolver in tests.
#[derive(Debug, Clone)]
pub struct EgressGuard<R = SystemResolver> {
    policy: NetworkPolicy,
    resolver: R,
    max_redirects: usize,
    secrets: Vec<String>,
}

impl EgressGuard<SystemResolver> {
    /// Build a guard that resolves through the operating system.
    pub fn system(policy: NetworkPolicy) -> Self {
        Self {
            policy,
            resolver: SystemResolver,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            secrets: Vec::new(),
        }
    }
}

impl<R: Resolver> EgressGuard<R> {
    /// Build a guard with an injectable resolver.
    pub fn new(policy: NetworkPolicy, resolver: R) -> Self {
        Self {
            policy,
            resolver,
            max_redirects: DEFAULT_MAX_REDIRECTS,
            secrets: Vec::new(),
        }
    }

    /// The policy this guard enforces.
    pub fn policy(&self) -> NetworkPolicy {
        self.policy
    }

    /// The redirect budget.
    pub fn max_redirects(&self) -> usize {
        self.max_redirects
    }

    /// Replace the redirect budget.
    pub fn with_max_redirects(mut self, max_redirects: usize) -> Self {
        self.max_redirects = max_redirects;
        self
    }

    /// Add secrets that must never leave the device.
    ///
    /// Empty strings are ignored. The set is enforced by [`Self::check_url`],
    /// [`Self::check_redirect`], and [`Self::check_request`] in addition to any
    /// per-request list.
    pub fn with_secrets<I, S>(mut self, secrets: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: Into<String>,
    {
        self.secrets = secrets
            .into_iter()
            .map(Into::into)
            .filter(|secret: &String| !secret.is_empty())
            .collect();
        self
    }

    /// Validate one absolute URL and pin its resolved addresses.
    ///
    /// Refuses the offline policy, non-HTTP(S) schemes, userinfo, an empty
    /// host, cloud metadata hostnames, and any address the policy forbids. All
    /// resolved addresses are checked before the destination is returned.
    pub fn check_url(&self, url: &str) -> Result<PinnedDestination> {
        self.check_url_with_secrets(url, &[])
    }

    /// [`Self::check_url`] plus a per-request secret list.
    pub fn check_url_with_secrets(
        &self,
        url: &str,
        secrets: &[String],
    ) -> Result<PinnedDestination> {
        self.ensure_online()?;
        self.assert_part_clean("URL", url, secrets)?;
        let parsed =
            Url::parse(url).map_err(|error| invalid(format!("the URL is invalid: {error}")))?;
        self.assert_part_clean("URL", parsed.as_str(), secrets)?;
        self.validate(parsed, 0)
    }

    /// Validate a redirect target from an already pinned destination.
    ///
    /// The target may be absolute or relative to `from`. The whole check runs
    /// again, including resolution, so a redirect cannot reach a private,
    /// loopback, or metadata address. An HTTPS-to-HTTP downgrade is refused;
    /// an HTTP-to-HTTPS upgrade is allowed. Non-HTTP(S) targets are refused by
    /// the same scheme check as a direct request.
    pub fn check_redirect(&self, from: &PinnedDestination, to: &str) -> Result<PinnedDestination> {
        self.check_redirect_with_secrets(from, to, &[])
    }

    /// [`Self::check_redirect`] plus a per-request secret list.
    pub fn check_redirect_with_secrets(
        &self,
        from: &PinnedDestination,
        to: &str,
        secrets: &[String],
    ) -> Result<PinnedDestination> {
        self.ensure_online()?;
        if from.redirects >= self.max_redirects {
            return Err(denied(format!(
                "redirect limit of {} exceeded",
                self.max_redirects
            )));
        }
        self.assert_part_clean("redirect target", to, secrets)?;
        let base =
            Url::parse(&from.url).map_err(|_| invalid("the pinned origin URL is malformed"))?;
        let parsed = base.join(to).map_err(|error| {
            invalid(format!("the redirect target could not be parsed: {error}"))
        })?;
        self.assert_part_clean("redirect target", parsed.as_str(), secrets)?;
        let next = self.validate(parsed, from.redirects + 1)?;
        if from.scheme.is_https() && !next.scheme.is_https() {
            return Err(denied("refusing an HTTPS-to-HTTP redirect downgrade"));
        }
        Ok(next)
    }

    /// Refuse `haystack` when it contains a configured or supplied secret.
    ///
    /// Both the guard's [`Self::with_secrets`] list and `secrets` are checked.
    /// Empty entries are ignored. This is a plain substring check over the
    /// exact text; it does not try to detect unregistered secrets. The error
    /// never contains the matched value.
    pub fn assert_no_secrets(&self, haystack: &str, secrets: &[String]) -> Result<()> {
        scan_secrets(haystack, &self.secrets)?;
        scan_secrets(haystack, secrets)
    }

    /// Validate a complete outbound request.
    ///
    /// Applies the network policy and the full URL check, then scans every
    /// header value and the body for configured or supplied secrets. Header
    /// names and the method must be HTTP tokens, and a header value may not
    /// contain a line break, so a caller cannot smuggle a second request.
    pub fn check_request<'a>(
        &self,
        method: &'a str,
        url: &'a str,
        headers: &'a [(&'a str, &'a str)],
        body: &'a str,
        secrets: &[String],
    ) -> Result<PinnedRequest<'a>> {
        self.ensure_online()?;
        if !is_http_token(method) {
            return Err(invalid("the request method is not a valid HTTP token"));
        }
        let destination = self.check_url_with_secrets(url, secrets)?;
        for (name, value) in headers {
            if !is_http_token(name) {
                return Err(invalid("a request header name is not a valid HTTP token"));
            }
            if value.contains('\r') || value.contains('\n') {
                return Err(invalid(format!("header `{name}` contains a line break")));
            }
            self.assert_part_clean("header value", value, secrets)?;
        }
        self.assert_part_clean("body", body, secrets)?;
        Ok(PinnedRequest {
            method,
            destination,
            headers,
            body,
        })
    }

    fn ensure_online(&self) -> Result<()> {
        if matches!(self.policy, NetworkPolicy::Offline) {
            return Err(denied(
                "the offline network policy denies every egress request",
            ));
        }
        Ok(())
    }

    fn assert_part_clean(&self, part: &str, haystack: &str, secrets: &[String]) -> Result<()> {
        self.assert_no_secrets(haystack, secrets).map_err(|_| {
            denied(format!(
                "refusing outbound request: a configured secret appears in the {part}"
            ))
        })
    }

    fn validate(&self, parsed: Url, redirects: usize) -> Result<PinnedDestination> {
        let scheme = EgressScheme::from_url(&parsed)
            .ok_or_else(|| denied(format!("refusing non-HTTP(S) scheme `{}`", parsed.scheme())))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(denied(
                "refusing a URL with embedded credentials (userinfo)",
            ));
        }
        let host = parsed
            .host()
            .ok_or_else(|| invalid("the URL has no host"))?;
        let port = parsed
            .port_or_known_default()
            .unwrap_or(scheme.default_port());

        let (host_text, addresses) = match host {
            Host::Domain(domain) => {
                if domain.is_empty() {
                    return Err(invalid("the URL has an empty host"));
                }
                if is_metadata_host(domain) {
                    return Err(denied(format!("refusing cloud metadata host `{domain}`")));
                }
                (domain.to_string(), self.resolve(domain, port)?)
            }
            Host::Ipv4(address) => (address.to_string(), vec![IpAddr::V4(address)]),
            Host::Ipv6(address) => (address.to_string(), vec![IpAddr::V6(address)]),
        };

        let mut pinned = Vec::with_capacity(addresses.len());
        for address in addresses {
            if !pinned.contains(&address) {
                pinned.push(address);
            }
        }
        if pinned.is_empty() {
            return Err(unavailable(format!(
                "host `{host_text}` resolved to no addresses"
            )));
        }
        for address in &pinned {
            let class = classify_address(*address);
            if !self.policy.allows(class) {
                return Err(denied(format!(
                    "refusing host `{host_text}`: {address} is {} and the {} network policy denies it",
                    class.as_str(),
                    self.policy.as_str()
                )));
            }
        }

        Ok(PinnedDestination {
            url: parsed.to_string(),
            scheme,
            host: host_text,
            port,
            addresses: pinned,
            redirects,
        })
    }

    fn resolve(&self, host: &str, port: u16) -> Result<Vec<IpAddr>> {
        self.resolver
            .resolve(host, port)
            .map_err(|error| unavailable(format!("could not resolve host `{host}`: {error}")))
    }
}

/// Classify one resolved address for the SSRF rules.
///
/// IPv4-mapped and IPv4-compatible IPv6 forms are unwrapped and classified as
/// their IPv4 address, so `::ffff:127.0.0.1` is loopback and
/// `::ffff:169.254.169.254` is metadata.
pub fn classify_address(address: IpAddr) -> AddressClass {
    match address {
        IpAddr::V4(address) => classify_v4(address),
        IpAddr::V6(address) => classify_v6(address),
    }
}

fn classify_v4(address: Ipv4Addr) -> AddressClass {
    if address.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if address.is_broadcast() {
        return AddressClass::Broadcast;
    }
    if is_metadata_v4(address) {
        return AddressClass::Metadata;
    }
    if address.is_loopback() {
        return AddressClass::Loopback;
    }
    if address.is_link_local() {
        return AddressClass::LinkLocal;
    }
    if address.is_private() {
        return AddressClass::Private;
    }
    if in_v4(address, [100, 64, 0, 0], 10) {
        // Carrier-grade NAT shares the "not publicly routable" property of
        // RFC 1918 space.
        return AddressClass::Private;
    }
    if address.is_multicast() {
        return AddressClass::Multicast;
    }
    let octets = address.octets();
    if octets[0] == 0
        || in_v4(address, [192, 0, 0, 0], 24)
        || in_v4(address, [192, 0, 2, 0], 24)
        || in_v4(address, [192, 88, 99, 0], 24)
        || in_v4(address, [198, 18, 0, 0], 15)
        || in_v4(address, [198, 51, 100, 0], 24)
        || in_v4(address, [203, 0, 113, 0], 24)
        || octets[0] >= 240
    {
        return AddressClass::Reserved;
    }
    AddressClass::Public
}

fn classify_v6(address: Ipv6Addr) -> AddressClass {
    if address.is_unspecified() {
        return AddressClass::Unspecified;
    }
    if address.is_loopback() {
        return AddressClass::Loopback;
    }
    if let Some(mapped) = embedded_ipv4(address) {
        return classify_v4(mapped);
    }
    if is_metadata_v6(address) {
        return AddressClass::Metadata;
    }
    let segments = address.segments();
    if (segments[0] & 0xfe00) == 0xfc00 {
        // fc00::/7, unique local addresses.
        return AddressClass::Private;
    }
    if (segments[0] & 0xffc0) == 0xfe80 {
        // fe80::/10, link-local unicast.
        return AddressClass::LinkLocal;
    }
    if address.is_multicast() {
        return AddressClass::Multicast;
    }
    if is_reserved_v6(segments) {
        return AddressClass::Reserved;
    }
    if (segments[0] & 0xe000) != 0x2000 {
        // Only 2000::/3 is global unicast; anything else left here is a
        // special-purpose block that is not a public destination.
        return AddressClass::Reserved;
    }
    AddressClass::Public
}

fn is_metadata_v4(address: Ipv4Addr) -> bool {
    matches!(
        address.octets(),
        [169, 254, 169, 254]
            | [169, 254, 170, 2]
            | [100, 100, 100, 200]
            | [168, 63, 129, 16]
            | [192, 0, 0, 192]
    )
}

fn is_metadata_v6(address: Ipv6Addr) -> bool {
    // fd00:ec2::254, the AWS EC2 IMDS address over IPv6.
    address.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
}

fn embedded_ipv4(address: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return Some(mapped);
    }
    let octets = address.octets();
    let last = u32::from_be_bytes([octets[12], octets[13], octets[14], octets[15]]);
    // IPv4-compatible ::a.b.c.d, excluding the unspecified and loopback
    // addresses that were handled before this point.
    if octets[..12].iter().all(|byte| *byte == 0) && last > 1 {
        Some(Ipv4Addr::new(
            octets[12], octets[13], octets[14], octets[15],
        ))
    } else {
        None
    }
}

fn is_reserved_v6(segments: [u16; 8]) -> bool {
    // Documentation 2001:db8::/32 and 3fff::/20.
    if segments[0] == 0x2001 && segments[1] == 0x0db8 {
        return true;
    }
    if segments[0] == 0x3fff && (segments[1] & 0xf000) == 0 {
        return true;
    }
    // Teredo 2001::/32.
    if segments[0] == 0x2001 && segments[1] == 0x0000 {
        return true;
    }
    // ORCHIDv1 2001:10::/28 and ORCHIDv2 2001:20::/28.
    if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0010 {
        return true;
    }
    if segments[0] == 0x2001 && (segments[1] & 0xfff0) == 0x0020 {
        return true;
    }
    // 6to4 2002::/16, which embeds an IPv4 address that would bypass the
    // direct IPv4 checks.
    if segments[0] == 0x2002 {
        return true;
    }
    // NAT64 64:ff9b::/96, for the same reason.
    if segments[0] == 0x0064
        && segments[1] == 0xff9b
        && segments[2..6].iter().all(|segment| *segment == 0)
    {
        return true;
    }
    // Discard-only 100::/64.
    if segments[0] == 0x0100 && segments[1..4].iter().all(|segment| *segment == 0) {
        return true;
    }
    false
}

fn in_v4(address: Ipv4Addr, base: [u8; 4], prefix: u32) -> bool {
    let shift = 32u32.saturating_sub(prefix);
    let mask = u32::MAX.checked_shl(shift).unwrap_or(0);
    (u32::from(address) & mask) == (u32::from(Ipv4Addr::from(base)) & mask)
}

fn is_metadata_host(host: &str) -> bool {
    let normalized = host.trim_end_matches('.').to_ascii_lowercase();
    METADATA_HOSTS.contains(&normalized.as_str())
}

fn is_http_token(value: &str) -> bool {
    if value.is_empty() {
        return false;
    }
    value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric()
            || matches!(
                byte,
                b'!' | b'#'
                    | b'$'
                    | b'%'
                    | b'&'
                    | b'\''
                    | b'*'
                    | b'+'
                    | b'-'
                    | b'.'
                    | b'^'
                    | b'_'
                    | b'`'
                    | b'|'
                    | b'~'
            )
    })
}

fn scan_secrets(haystack: &str, secrets: &[String]) -> Result<()> {
    if secrets
        .iter()
        .any(|secret| !secret.is_empty() && haystack.contains(secret.as_str()))
    {
        return Err(denied(
            "refusing outbound content: a configured secret appears in the request",
        ));
    }
    Ok(())
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn unavailable(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Unavailable, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    const PUBLIC_V4: Ipv4Addr = Ipv4Addr::new(93, 184, 216, 34);
    const PUBLIC_V6: &str = "2606:2800:220:1:248:1893:25c8:1946";

    struct ScriptedResolver {
        answers: HashMap<String, Vec<IpAddr>>,
        fallback: Option<Vec<IpAddr>>,
    }

    impl ScriptedResolver {
        fn new() -> Self {
            Self {
                answers: HashMap::new(),
                fallback: Some(vec![IpAddr::V4(PUBLIC_V4)]),
            }
        }

        fn with(mut self, host: &str, addresses: &[&str]) -> Self {
            self.answers.insert(
                host.to_string(),
                addresses
                    .iter()
                    .map(|address| address.parse().expect("fixture address"))
                    .collect(),
            );
            self
        }

        fn failing(mut self) -> Self {
            self.fallback = None;
            self
        }
    }

    impl Resolver for ScriptedResolver {
        fn resolve(&self, host: &str, _port: u16) -> io::Result<Vec<IpAddr>> {
            self.answers
                .get(host)
                .cloned()
                .or_else(|| self.fallback.clone())
                .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no fixture answer"))
        }
    }

    fn guard(policy: NetworkPolicy) -> EgressGuard<ScriptedResolver> {
        EgressGuard::new(policy, ScriptedResolver::new())
    }

    fn assert_blocked(guard: &EgressGuard<ScriptedResolver>, url: &str) {
        match guard.check_url(url) {
            Ok(destination) => panic!("{url} must be blocked, got {destination:?}"),
            Err(error) => assert_eq!(
                error.code(),
                ErrorCode::PolicyDenied,
                "{url}: {}",
                error.message()
            ),
        }
    }

    #[test]
    fn metadata_ips_and_hostnames_are_always_blocked() {
        let guard = guard(NetworkPolicy::Full);
        for url in [
            "http://169.254.169.254/latest/meta-data/",
            "http://[fd00:ec2::254]/",
            "http://[::ffff:169.254.169.254]/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://metadata.goog/",
            "http://metadata.azure.internal/",
            "http://instance-data/",
            "http://100.100.100.200/",
            "http://168.63.129.16/",
            "http://192.0.0.192/",
        ] {
            assert_blocked(&guard, url);
        }
    }

    #[test]
    fn loopback_is_blocked_outside_full_mode() {
        let guard = guard(NetworkPolicy::Restricted);
        for url in [
            "http://127.0.0.1/",
            "http://127.255.0.1:8080/",
            "http://127.1/",
            "http://[::1]/",
            "http://[::ffff:127.0.0.1]/",
        ] {
            assert_blocked(&guard, url);
        }
    }

    #[test]
    fn private_and_shared_ranges_are_blocked() {
        let guard = guard(NetworkPolicy::Restricted);
        for url in [
            "http://10.0.0.1/",
            "http://172.16.0.1/",
            "http://172.31.255.254/",
            "http://192.168.0.1/",
            "http://100.64.0.1/",
            "http://[fd12:3456:789a::1]/",
            "http://[fc00::1]/",
        ] {
            assert_blocked(&guard, url);
        }
    }

    #[test]
    fn link_local_multicast_unspecified_and_reserved_are_blocked() {
        let guard = guard(NetworkPolicy::Full);
        for url in [
            "http://169.254.1.1/",
            "http://[fe80::1]/",
            "http://224.0.0.1/",
            "http://239.255.255.250/",
            "http://0.0.0.0/",
            "http://255.255.255.255/",
            "http://[::]/",
            "http://[ff02::1]/",
            "http://192.0.2.1/",
            "http://[2001:db8::1]/",
        ] {
            assert_blocked(&guard, url);
        }
    }

    #[test]
    fn non_http_schemes_and_userinfo_are_refused() {
        let guard = guard(NetworkPolicy::Restricted);
        for url in [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "data:text/plain,secret",
            "ftp://example.com/file",
            "ws://example.com/socket",
            "http://user:pass@example.com/",
            "http://user@example.com/",
            "http://:pass@example.com/",
        ] {
            assert_blocked(&guard, url);
        }
    }

    #[test]
    fn offline_policy_denies_every_url_and_request() {
        let guard = guard(NetworkPolicy::Offline);
        for url in [
            "https://example.com/",
            "http://192.168.1.10/",
            "http://169.254.169.254/",
        ] {
            let error = guard.check_url(url).unwrap_err();
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(error.message().contains("offline"), "{}", error.message());
        }

        let error = guard
            .check_request("GET", "https://example.com/", &[], "", &[])
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
    }

    #[test]
    fn full_policy_allows_private_and_loopback_but_not_metadata() {
        let guard = guard(NetworkPolicy::Full);
        for url in [
            "http://10.1.2.3/",
            "http://192.168.1.20:8080/",
            "http://127.0.0.1/",
            "http://[fd12::1]/",
        ] {
            assert!(guard.check_url(url).is_ok(), "{url} must be allowed");
        }
        assert_blocked(&guard, "http://169.254.169.254/");
        assert_blocked(&guard, "http://[fd00:ec2::254]/");
        assert_blocked(&guard, "http://[fe80::1]/");
    }

    #[test]
    fn every_resolved_address_must_pass() {
        let resolver =
            ScriptedResolver::new().with("rebind.example", &["93.184.216.34", "127.0.0.1"]);
        let guard = EgressGuard::new(NetworkPolicy::Restricted, resolver);
        let error = guard.check_url("https://rebind.example/").unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("127.0.0.1"), "{}", error.message());

        let resolver =
            ScriptedResolver::new().with("rebind.example", &["10.0.0.5", "93.184.216.34"]);
        let guard = EgressGuard::new(NetworkPolicy::Restricted, resolver);
        assert!(guard.check_url("https://rebind.example/").is_err());
    }

    #[test]
    fn redirects_are_fully_rechecked() {
        let resolver = ScriptedResolver::new()
            .with("private.example", &["10.0.0.1"])
            .with("metadata.example", &["169.254.169.254"]);
        let guard = EgressGuard::new(NetworkPolicy::Restricted, resolver);
        let origin = guard.check_url("https://public.example/start").unwrap();

        for target in [
            "https://private.example/next",
            "https://metadata.example/next",
            "http://127.0.0.1/next",
            "file:///etc/passwd",
        ] {
            assert!(
                guard.check_redirect(&origin, target).is_err(),
                "{target} must be refused"
            );
        }

        let next = guard.check_redirect(&origin, "/next").unwrap();
        assert_eq!(next.url(), "https://public.example/next");
        assert_eq!(next.redirects(), 1);
    }

    #[test]
    fn https_downgrade_is_refused_but_upgrade_is_allowed() {
        let guard = guard(NetworkPolicy::Restricted);
        let secured = guard.check_url("https://example.com/").unwrap();
        let error = guard
            .check_redirect(&secured, "http://example.com/")
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("downgrade"), "{}", error.message());

        let plain = guard.check_url("http://example.com/").unwrap();
        let upgraded = guard
            .check_redirect(&plain, "https://example.com/")
            .unwrap();
        assert_eq!(upgraded.scheme(), EgressScheme::Https);
    }

    #[test]
    fn redirect_limit_is_enforced() {
        let guard = EgressGuard::new(NetworkPolicy::Restricted, ScriptedResolver::new())
            .with_max_redirects(2);
        let first = guard.check_url("https://example.com/0").unwrap();
        let second = guard
            .check_redirect(&first, "https://example.com/1")
            .unwrap();
        let third = guard
            .check_redirect(&second, "https://example.com/2")
            .unwrap();
        assert_eq!(third.redirects(), 2);

        let error = guard
            .check_redirect(&third, "https://example.com/3")
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("redirect limit"),
            "{}",
            error.message()
        );
    }

    #[test]
    fn secrets_are_refused_in_url_headers_and_body() {
        let secret = "sk-live-abcdef".to_string();
        let guard = EgressGuard::new(NetworkPolicy::Restricted, ScriptedResolver::new())
            .with_secrets([secret.clone()]);

        let error = guard
            .check_url("https://example.com/?token=sk-live-abcdef")
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("URL"), "{}", error.message());
        assert!(
            !error.message().contains(&secret),
            "the error must not echo the secret"
        );

        let headers = [("authorization", "Bearer sk-live-abcdef")];
        let error = guard
            .check_request("GET", "https://example.com/", &headers, "", &[])
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(
            error.message().contains("header value"),
            "{}",
            error.message()
        );
        assert!(!error.message().contains(&secret));

        let error = guard
            .check_request(
                "POST",
                "https://example.com/",
                &[],
                "body sk-live-abcdef",
                &[],
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("body"), "{}", error.message());
        assert!(!error.message().contains(&secret));

        let per_request = ["other-secret".to_string()];
        let error = guard
            .check_request(
                "GET",
                "https://example.com/other-secret",
                &[],
                "",
                &per_request,
            )
            .unwrap_err();
        assert_eq!(error.code(), ErrorCode::PolicyDenied);

        let empty = ["".to_string()];
        assert!(guard
            .check_request("GET", "https://example.com/", &[], "", &empty)
            .is_ok());
    }

    #[test]
    fn clean_public_url_is_pinned() {
        let resolver = ScriptedResolver::new().with("example.com", &["93.184.216.34", PUBLIC_V6]);
        let guard = EgressGuard::new(NetworkPolicy::Restricted, resolver);
        let destination = guard
            .check_url("HTTPS://EXAMPLE.COM:443/path?q=1#frag")
            .unwrap();

        assert_eq!(destination.scheme(), EgressScheme::Https);
        assert_eq!(destination.scheme().as_str(), "https");
        assert_eq!(destination.host(), "example.com");
        assert_eq!(destination.port(), 443);
        assert_eq!(destination.redirects(), 0);
        assert!(destination.is_https());
        assert_eq!(destination.url(), "https://example.com/path?q=1#frag");
        assert_eq!(destination.addresses().len(), 2);
        assert!(destination.addresses().contains(&IpAddr::V4(PUBLIC_V4)));
        assert!(destination
            .addresses()
            .contains(&PUBLIC_V6.parse::<IpAddr>().unwrap()));

        let plain = guard.check_url("http://example.com").unwrap();
        assert_eq!(plain.port(), 80);
        assert_eq!(plain.url(), "http://example.com/");
    }

    #[test]
    fn public_ipv6_and_ip_literals_need_no_resolution() {
        let guard = EgressGuard::new(NetworkPolicy::Restricted, ScriptedResolver::new().failing());
        let destination = guard
            .check_url("https://[2606:2800:220:1:248:1893:25c8:1946]/")
            .unwrap();
        assert!(matches!(destination.addresses()[0], IpAddr::V6(_)));

        let destination = guard.check_url("http://93.184.216.34/").unwrap();
        assert_eq!(destination.addresses(), &[IpAddr::V4(PUBLIC_V4)]);
    }

    #[test]
    fn resolution_failures_are_not_allowed() {
        let guard = EgressGuard::new(NetworkPolicy::Restricted, ScriptedResolver::new().failing());
        let error = guard.check_url("https://missing.example/").unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("missing.example"));

        let resolver = ScriptedResolver::new().with("empty.example", &[]);
        let guard = EgressGuard::new(NetworkPolicy::Restricted, resolver);
        let error = guard.check_url("https://empty.example/").unwrap_err();
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("no addresses"));
    }

    #[test]
    fn request_validation_rejects_bad_methods_and_header_injection() {
        let guard = guard(NetworkPolicy::Restricted);

        assert_eq!(
            guard
                .check_request("", "https://example.com/", &[], "", &[])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            guard
                .check_request("GE T", "https://example.com/", &[], "", &[])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );

        let bad_name = [("bad header", "x")];
        assert_eq!(
            guard
                .check_request("GET", "https://example.com/", &bad_name, "", &[])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );

        let injected = [("x-test", "a\r\nhost: evil")];
        assert_eq!(
            guard
                .check_request("GET", "https://example.com/", &injected, "", &[])
                .unwrap_err()
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn clean_request_returns_a_pinned_request() {
        let guard = guard(NetworkPolicy::Restricted);
        let headers = [("accept", "text/html")];
        let request = guard
            .check_request(
                "POST",
                "https://example.com/api",
                &headers,
                "{\"q\":1}",
                &[],
            )
            .unwrap();

        assert_eq!(request.method(), "POST");
        assert_eq!(request.destination().host(), "example.com");
        assert_eq!(request.headers().len(), 1);
        assert_eq!(request.headers()[0], ("accept", "text/html"));
        assert_eq!(request.body(), "{\"q\":1}");
    }

    #[test]
    fn address_classes_cover_the_documented_ranges() {
        let cases = [
            ("93.184.216.34", AddressClass::Public),
            ("127.0.0.1", AddressClass::Loopback),
            ("10.1.2.3", AddressClass::Private),
            ("100.64.0.1", AddressClass::Private),
            ("169.254.169.254", AddressClass::Metadata),
            ("169.254.1.1", AddressClass::LinkLocal),
            ("224.0.0.1", AddressClass::Multicast),
            ("0.0.0.0", AddressClass::Unspecified),
            ("255.255.255.255", AddressClass::Broadcast),
            ("192.0.2.1", AddressClass::Reserved),
            ("192.88.99.1", AddressClass::Reserved),
            ("::1", AddressClass::Loopback),
            ("fd00::1", AddressClass::Private),
            ("fe80::1", AddressClass::LinkLocal),
            ("ff02::1", AddressClass::Multicast),
            ("fd00:ec2::254", AddressClass::Metadata),
            ("::ffff:127.0.0.1", AddressClass::Loopback),
            ("::ffff:10.0.0.1", AddressClass::Private),
            ("2001:db8::1", AddressClass::Reserved),
            ("3fff::1", AddressClass::Reserved),
            ("4000::1", AddressClass::Reserved),
            (PUBLIC_V6, AddressClass::Public),
        ];
        for (address, expected) in cases {
            assert_eq!(
                classify_address(address.parse().unwrap()),
                expected,
                "{address}"
            );
        }
    }

    #[test]
    fn policy_matrix_matches_the_documented_table() {
        assert!(!NetworkPolicy::Offline.allows(AddressClass::Public));
        assert!(NetworkPolicy::Restricted.allows(AddressClass::Public));
        for class in [
            AddressClass::Loopback,
            AddressClass::Private,
            AddressClass::LinkLocal,
            AddressClass::Metadata,
            AddressClass::Multicast,
            AddressClass::Unspecified,
            AddressClass::Broadcast,
            AddressClass::Reserved,
        ] {
            assert!(!NetworkPolicy::Restricted.allows(class), "{class:?}");
        }
        for class in [
            AddressClass::Public,
            AddressClass::Loopback,
            AddressClass::Private,
        ] {
            assert!(NetworkPolicy::Full.allows(class), "{class:?}");
        }
        for class in [
            AddressClass::LinkLocal,
            AddressClass::Metadata,
            AddressClass::Multicast,
            AddressClass::Unspecified,
            AddressClass::Broadcast,
            AddressClass::Reserved,
        ] {
            assert!(!NetworkPolicy::Full.allows(class), "{class:?}");
        }
    }
}
