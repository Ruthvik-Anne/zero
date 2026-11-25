//! Authenticated LAN discovery with no account and no service (T-MESH-03,
//! MESH-03, MESH-12, MESH-14).
//!
//! A peer announces itself over the local network with a [`PeerAnnounce`]: its
//! device id, an optional name, the addresses and UDP port it can be reached
//! on, a single-use nonce, an issue/expiry window, and an Ed25519 signature by
//! the device key that owns the id. The announce is transport-independent; the
//! mDNS record shape is only a framing ([`MdnsRecord`]).
//!
//! [`accept`] is the authentication boundary. It ignores — silently, with a
//! reason and without adding a peer — every announce whose device id is not an
//! approved member in the owner-signed [`MembershipState`], whose record is
//! revoked, or whose signature does not verify under the member's public key.
//! That is the T-MESH-03 done criterion: an unauthenticated peer is ignored.
//!
//! What a caller learns from this module is presence: a peer is online or it is
//! offline. There are no tasks, commands, fleet controls, or orchestration
//! fields, and none can be smuggled in through the TXT framing: the field set
//! is closed.
//!
//! This slice deliberately opens no sockets. mDNS multicast send/receive is a
//! later transport task; here an announce is encoded into mDNS-style TXT fields,
//! decoded back, and fed to [`accept`] exactly as a listener would.
//!
//! Membership state arrives already authenticated: [`accept`] receives a
//! [`MembershipState`] that the caller has checked with
//! [`verify_state`](crate::state::verify_state) or [`apply`](crate::state::apply).
//! The module re-checks the announce against the member's key but cannot
//! re-derive the owner root from a state alone (no owner public key is passed),
//! so an unverified state is the caller's bug, not an accepted announce.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::identity::{device_id_for, verify, KeyPair};
use crate::state::{MembershipState, MAX_NAME_BYTES};

/// Domain separator for a signed announce.
pub const ANNOUNCE_DOMAIN: &[u8] = b"zero.mesh.discovery.announce.v1\0";

/// The DNS-SD service the record belongs to.
pub const SERVICE: &str = "_zero._udp.local";

/// Largest canonical announce this module will produce: 4 KiB.
pub const MAX_ANNOUNCE_BYTES: usize = 4096;

/// Most addresses one announce may carry.
pub const MAX_ANNOUNCE_ADDRS: usize = 16;

/// Longest announce lifetime: five minutes. An mDNS announce is refreshed, not
/// left to stand for an hour.
pub const MAX_ANNOUNCE_TTL_MS: i64 = 5 * 60 * 1000;

/// Longest accepted nonce, in bytes.
pub const MAX_NONCE_BYTES: usize = 64;

/// Shortest accepted nonce, in bytes.
pub const MIN_NONCE_BYTES: usize = 8;

/// mDNS TXT strings are length-prefixed by one byte, so a value is at most 255
/// bytes.
pub const MAX_TXT_VALUE_BYTES: usize = 255;

/// Most TXT fields one record may carry: version, id, name, sixteen addresses,
/// port, nonce, issue, expiry, and signature.
pub const MAX_TXT_FIELDS: usize = 24;

/// Practical upper bound for one encoded record, in bytes. A TXT record set
/// larger than this is not a healthy LAN announce.
pub const MAX_MDNS_BYTES: usize = 1300;

/// A peer is marked offline when it has not been heard from for this long.
/// Ninety seconds is three missed thirty-second announcements.
pub const DEFAULT_OFFLINE_AFTER_MS: i64 = 90_000;

/// A signed, transport-independent presence announcement.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerAnnounce {
    /// Hex blake3 of the announcing device's public key.
    pub device_id: String,
    /// Optional human label. Display only; the authenticated identity is
    /// `device_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    /// Addresses the peer can be reached on. Stored sorted and deduplicated.
    pub addrs: Vec<IpAddr>,
    /// UDP port the peer listens on.
    pub port: u16,
    /// Single-use nonce; a repeat from the same device is a replay.
    pub nonce: String,
    /// Issue time, in milliseconds since the Unix epoch.
    pub issued_ms: i64,
    /// Expiry time, in milliseconds since the Unix epoch.
    pub expires_ms: i64,
    /// Standard padded base64 Ed25519 signature by the device key. Excluded
    /// from [`canonical_announce_bytes`].
    pub signature_b64: String,
}

/// Presence is the only peer state this module exposes.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Presence {
    /// Heard from within the offline window.
    Online,
    /// Not heard from for at least the offline window (MESH-14).
    Offline,
}

/// A peer the discovery table knows about.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerRecord {
    /// The announce that was accepted. Its addresses are sorted and unique.
    pub announce: PeerAnnounce,
    /// When the announce was accepted, in milliseconds since the Unix epoch.
    pub last_seen_ms: i64,
    /// True until [`sweep`] marks a sleeping peer offline.
    pub online: bool,
}

impl PeerRecord {
    /// The only peer state exposed: online or offline.
    pub fn presence(&self) -> Presence {
        if self.online {
            Presence::Online
        } else {
            Presence::Offline
        }
    }

    /// The authenticated device id.
    pub fn device_id(&self) -> &str {
        &self.announce.device_id
    }

    /// The announced addresses, sorted and deduplicated.
    pub fn addrs(&self) -> &[IpAddr] {
        &self.announce.addrs
    }
}

/// Local discovery policy. It bounds memory, not authority.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryPolicy {
    /// Mark a peer offline after this many milliseconds without an announce.
    pub offline_after_ms: i64,
    /// Most peers the table will hold.
    pub max_peers: usize,
    /// Most nonces remembered per device to refuse replays.
    pub max_nonce_history: usize,
}

impl Default for DiscoveryPolicy {
    fn default() -> Self {
        Self {
            offline_after_ms: DEFAULT_OFFLINE_AFTER_MS,
            max_peers: 4096,
            max_nonce_history: 64,
        }
    }
}

/// The local discovery table.
///
/// It holds accepted peers, the policy, the highest membership version applied
/// so far, and a per-device nonce ledger. Nothing here talks to the network.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Discovery {
    /// Accepted peers, keyed by device id.
    pub peers: BTreeMap<String, PeerRecord>,
    /// Local bounds.
    pub policy: DiscoveryPolicy,
    /// Highest membership snapshot version seen by [`accept`].
    pub membership_version: u64,
    /// device id -> (nonce -> announce expiry). Pruned as announces expire.
    nonces: BTreeMap<String, BTreeMap<String, i64>>,
}

impl Discovery {
    /// An empty table with the given policy.
    pub fn new(policy: DiscoveryPolicy) -> Self {
        Self {
            peers: BTreeMap::new(),
            policy,
            membership_version: 0,
            nonces: BTreeMap::new(),
        }
    }

    fn prune_nonces(&mut self, now_ms: i64) {
        self.nonces.retain(|_, by_nonce| {
            by_nonce.retain(|_, expires_ms| *expires_ms > now_ms);
            !by_nonce.is_empty()
        });
    }
}

impl Default for Discovery {
    fn default() -> Self {
        Self::new(DiscoveryPolicy::default())
    }
}

/// Result of offering an announce to [`accept`].
///
/// An ignored announce is not an error: an unauthenticated peer is simply not
/// admitted, and no peer is added or updated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AcceptOutcome {
    /// The announce authenticated and the peer was added or refreshed.
    Accepted,
    /// The announce was refused. The reason is for logs and tests; nothing was
    /// added to the table.
    Ignored {
        /// Why the announce was ignored.
        reason: String,
    },
}

impl AcceptOutcome {
    /// True when the announce was accepted.
    pub fn is_accepted(&self) -> bool {
        matches!(self, Self::Accepted)
    }

    /// The refusal reason, when ignored.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Ignored { reason } => Some(reason),
            Self::Accepted => None,
        }
    }
}

/// The canonical, deterministic bytes a device signs for an announce.
///
/// Byte layout, all integers big-endian:
///
/// ```text
/// "zero.mesh.discovery.announce.v1\0"  domain separator
/// device_id                            u32 length + UTF-8 bytes
/// name present                         u8 (0 or 1)
///   name                               u32 length + UTF-8 bytes when present
/// address count                        u32
/// repeated addresses, sorted:
///   encoded address                    u32 length + (family byte + octets)
/// port                                 u16
/// nonce                                u32 length + UTF-8 bytes
/// issued_ms                            i64
/// expires_ms                           i64
/// ```
///
/// Addresses are sorted by family and octets and deduplicated, so the encoding
/// does not depend on how a caller ordered or repeated them. The signature is
/// excluded because it is produced over these bytes.
///
/// Validation is part of canonicalisation: malformed ids, an invalid or absent
/// name, zero, more than [`MAX_ANNOUNCE_ADDRS`], unspecified, or multicast
/// addresses, a zero port, a malformed or over-long nonce, a negative issue
/// time, a non-positive lifetime, a lifetime above [`MAX_ANNOUNCE_TTL_MS`], and
/// an encoded announce above [`MAX_ANNOUNCE_BYTES`] are refused.
pub fn canonical_announce_bytes(announce: &PeerAnnounce) -> Result<Vec<u8>, ZeroError> {
    validate_announce(announce)?;

    let mut out = Vec::with_capacity(256);
    out.extend_from_slice(ANNOUNCE_DOMAIN);
    put_str(&mut out, &announce.device_id)?;
    match &announce.name {
        Some(name) => {
            out.push(1);
            put_str(&mut out, name)?;
        }
        None => out.push(0),
    }

    let addrs = normalized_addr_bytes(&announce.addrs);
    put_count(&mut out, addrs.len(), MAX_ANNOUNCE_ADDRS, "addresses")?;
    for addr in &addrs {
        put_bytes(&mut out, addr)?;
    }

    out.extend_from_slice(&announce.port.to_be_bytes());
    put_str(&mut out, &announce.nonce)?;
    out.extend_from_slice(&announce.issued_ms.to_be_bytes());
    out.extend_from_slice(&announce.expires_ms.to_be_bytes());

    if out.len() > MAX_ANNOUNCE_BYTES {
        return Err(limit(format!(
            "announce is {} bytes; the limit is {MAX_ANNOUNCE_BYTES}",
            out.len()
        )));
    }
    Ok(out)
}

/// Sign an announce with the device key.
///
/// The returned announce carries the device's derived id, normalized addresses,
/// and the signature. `expires_ms` must be after `issued_ms` and within
/// [`MAX_ANNOUNCE_TTL_MS`].
pub fn sign_announce(
    device_key: &KeyPair,
    name: Option<&str>,
    addrs: &[IpAddr],
    port: u16,
    nonce: &str,
    issued_ms: i64,
    expires_ms: i64,
) -> Result<PeerAnnounce, ZeroError> {
    let mut announce = PeerAnnounce {
        device_id: device_key.device_id().to_string(),
        name: name.map(str::to_string),
        addrs: normalize_addrs(addrs),
        port,
        nonce: nonce.to_string(),
        issued_ms,
        expires_ms,
        signature_b64: String::new(),
    };
    let bytes = canonical_announce_bytes(&announce)?;
    announce.signature_b64 = device_key.sign(&bytes);
    Ok(announce)
}

/// Verify an announce's signature under the device's public key.
///
/// The announce must be well formed, `device_id` must be the id derived from
/// `public_key_b64`, and the signature must verify over
/// [`canonical_announce_bytes`]. A malformed announce or a wrong id is
/// `zero.fnd.invalid_input`; a bad signature is `zero.pol.denied`.
pub fn verify_announce(public_key_b64: &str, announce: &PeerAnnounce) -> Result<(), ZeroError> {
    let bytes = canonical_announce_bytes(announce)?;
    if device_id_for(public_key_b64)? != announce.device_id {
        return Err(invalid(
            "announce device id is not the id derived from the member public key",
        ));
    }
    verify(public_key_b64, &bytes, &announce.signature_b64)
        .map_err(|error| denied(format!("announce signature does not verify: {error}")))
}

/// Offer an announce to the discovery table.
///
/// The checks run in this order, and a failure at any point returns
/// [`AcceptOutcome::Ignored`] without touching the peer table:
///
/// 1. `membership.version` is at least the last version recorded here; an older
///    snapshot cannot be replayed to resurrect a removed device;
/// 2. the announce is structurally valid (bounds, addresses, nonce, lifetime);
/// 3. `device_id` names an approved, non-revoked member in the signed state;
/// 4. the member record's public key hashes to `device_id`;
/// 5. the announce signature verifies under that member key;
/// 6. the announce is not issued in the future and is not expired at `now_ms`;
/// 7. the nonce has not been seen from this device;
/// 8. the table has room for a new peer.
///
/// On success the announce is stored with sorted, deduplicated addresses,
/// `last_seen_ms` becomes `now_ms`, the peer is online, and the nonce is
/// remembered until the announce expires. Nothing else is exposed: presence is
/// online or offline only.
pub fn accept(
    discovery: &mut Discovery,
    announce: &PeerAnnounce,
    membership: &MembershipState,
    now_ms: i64,
) -> AcceptOutcome {
    if membership.version < discovery.membership_version {
        return ignored(format!(
            "membership state version {} is older than the last applied version {}",
            membership.version, discovery.membership_version
        ));
    }
    if membership.version > discovery.membership_version {
        discovery.membership_version = membership.version;
    }

    if let Err(error) = validate_announce(announce) {
        return ignored(format!("announce is malformed: {}", error.message()));
    }

    let record = match membership.devices.get(&announce.device_id) {
        Some(record) if !record.revoked => record,
        Some(_) => return ignored(format!("device `{}` is revoked", announce.device_id)),
        None => {
            return ignored(format!(
                "device `{}` is not an approved member",
                announce.device_id
            ))
        }
    };
    if membership.revoked.contains(&announce.device_id) {
        return ignored(format!("device `{}` is revoked", announce.device_id));
    }
    match device_id_for(&record.public_key_b64) {
        Ok(device_id) if device_id == announce.device_id => {}
        Ok(_) => {
            return ignored(format!(
                "membership record for `{}` does not match its public key",
                announce.device_id
            ))
        }
        Err(error) => {
            return ignored(format!(
                "membership record for `{}` has an unusable public key: {}",
                announce.device_id,
                error.message()
            ))
        }
    }
    if let Err(error) = verify_announce(&record.public_key_b64, announce) {
        return ignored(error.message());
    }

    if announce.issued_ms > now_ms {
        return ignored(format!(
            "announce from `{}` is not yet valid: issued at {} ms",
            announce.device_id, announce.issued_ms
        ));
    }
    if now_ms >= announce.expires_ms {
        return ignored(format!(
            "announce from `{}` expired at {} ms",
            announce.device_id, announce.expires_ms
        ));
    }

    let nonces = discovery
        .nonces
        .entry(announce.device_id.clone())
        .or_default();
    nonces.retain(|_, expires_ms| *expires_ms > now_ms);
    if nonces.contains_key(&announce.nonce) {
        return ignored(format!(
            "announce nonce `{}` was already seen from `{}`",
            announce.nonce, announce.device_id
        ));
    }

    if !discovery.peers.contains_key(&announce.device_id)
        && discovery.peers.len() >= discovery.policy.max_peers
    {
        return ignored("discovery peer table is full");
    }

    let max_nonce_history = discovery.policy.max_nonce_history;
    let nonces = discovery
        .nonces
        .entry(announce.device_id.clone())
        .or_default();
    if nonces.len() >= max_nonce_history.max(1) {
        if let Some(oldest) = nonces
            .iter()
            .min_by_key(|(_, expires_ms)| **expires_ms)
            .map(|(nonce, _)| nonce.clone())
        {
            nonces.remove(&oldest);
        }
    }
    nonces.insert(announce.nonce.clone(), announce.expires_ms);

    let mut accepted = announce.clone();
    accepted.addrs = normalize_addrs(&announce.addrs);
    discovery.peers.insert(
        announce.device_id.clone(),
        PeerRecord {
            announce: accepted,
            last_seen_ms: now_ms,
            online: true,
        },
    );
    AcceptOutcome::Accepted
}

/// Mark peers that have not been heard from within `offline_after_ms` offline
/// (MESH-14: a sleeping device is offline, not "unknown").
///
/// Returns how many peers changed from online to offline. A peer that
/// re-announces becomes online again through [`accept`].
pub fn sweep(discovery: &mut Discovery, now_ms: i64, offline_after_ms: i64) -> usize {
    let threshold = offline_after_ms.max(0);
    let mut marked = 0;
    for record in discovery.peers.values_mut() {
        if record.online && now_ms.saturating_sub(record.last_seen_ms) >= threshold {
            record.online = false;
            marked += 1;
        }
    }
    discovery.prune_nonces(now_ms);
    marked
}

/// Remove a peer and its replay ledger from the table.
pub fn remove(discovery: &mut Discovery, device_id: &str) -> Option<PeerRecord> {
    discovery.nonces.remove(device_id);
    discovery.peers.remove(device_id)
}

/// The accepted peers, keyed by device id.
pub fn peers(discovery: &Discovery) -> &BTreeMap<String, PeerRecord> {
    &discovery.peers
}

/// A fresh 32-hex-character nonce for an announce, drawn from the operating
/// system.
pub fn new_nonce() -> Result<String, ZeroError> {
    let mut bytes = [0u8; 16];
    getrandom::getrandom(&mut bytes)
        .map_err(|error| internal(format!("cannot read random bytes: {error}")))?;
    Ok(to_hex(&bytes))
}

/// The mDNS framing of an announce.
///
/// This is a plain record value, not a socket message: the encoder and decoder
/// exist so the TXT mapping can be tested and so a later mDNS transport can
/// carry it. The service is fixed at [`SERVICE`]; the address and port fields
/// duplicate the TTL-less A/AAAA and SRV parts a real responder would emit.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MdnsRecord {
    /// Always [`SERVICE`] for a record this module produces.
    pub service: String,
    /// Closed field set: `v`, `id`, optional `name`, `addr0`.., `port`,
    /// `nonce`, `issued`, `expires`, `sig`. Each value is at most
    /// [`MAX_TXT_VALUE_BYTES`] bytes.
    pub txt: BTreeMap<String, String>,
    /// The announced addresses, in the same order as the `addrN` fields.
    pub addrs: Vec<IpAddr>,
    /// The announced port.
    pub port: u16,
}

/// Encode a signed announce into its mDNS TXT fields.
///
/// Addresses are emitted as `addr0`, `addr1`, ... so no single TXT value can
/// exceed the 255-byte mDNS limit. The field set and total size are bounded;
/// an announce with too many addresses or a field over the limit is refused.
pub fn encode_announce(announce: &PeerAnnounce) -> Result<MdnsRecord, ZeroError> {
    validate_announce(announce)?;

    let addrs = normalize_addrs(&announce.addrs);
    let mut txt = BTreeMap::new();
    txt.insert("v".to_string(), "1".to_string());
    txt.insert("id".to_string(), announce.device_id.clone());
    if let Some(name) = &announce.name {
        txt.insert("name".to_string(), name.clone());
    }
    for (index, addr) in addrs.iter().enumerate() {
        txt.insert(format!("addr{index}"), addr.to_string());
    }
    txt.insert("port".to_string(), announce.port.to_string());
    txt.insert("nonce".to_string(), announce.nonce.clone());
    txt.insert("issued".to_string(), announce.issued_ms.to_string());
    txt.insert("expires".to_string(), announce.expires_ms.to_string());
    txt.insert("sig".to_string(), announce.signature_b64.clone());

    check_txt_bounds(&txt)?;
    Ok(MdnsRecord {
        service: SERVICE.to_string(),
        txt,
        addrs,
        port: announce.port,
    })
}

/// Decode an announce from mDNS TXT fields.
///
/// Decoding is **not** authentication: it only reconstructs the announce and
/// re-checks its structure. A decoded announce enters a [`Discovery`] only
/// through [`accept`], which verifies the member and the signature. Unknown TXT
/// fields, a wrong service, a missing required field, a non-contiguous address
/// index, an invalid address or integer, and any bound overrun are refused.
pub fn decode_announce(record: &MdnsRecord) -> Result<PeerAnnounce, ZeroError> {
    if record.service != SERVICE {
        return Err(invalid(format!(
            "record service must be `{SERVICE}`, not `{}`",
            record.service
        )));
    }
    check_txt_bounds(&record.txt)?;

    let version = required_txt(&record.txt, "v")?;
    if version != "1" {
        return Err(invalid(format!(
            "unsupported announce TXT version `{version}`"
        )));
    }

    let mut addrs: Vec<(usize, IpAddr)> = Vec::new();
    for (key, value) in &record.txt {
        let known = matches!(
            key.as_str(),
            "v" | "id" | "name" | "port" | "nonce" | "issued" | "expires" | "sig"
        );
        if known {
            continue;
        }
        let index = key
            .strip_prefix("addr")
            .filter(|rest| !rest.is_empty() && rest.bytes().all(|byte| byte.is_ascii_digit()))
            .ok_or_else(|| invalid(format!("unknown announce TXT field `{key}`")))?;
        let index: usize = index
            .parse()
            .map_err(|_| invalid(format!("announce address index `{key}` is not a number")))?;
        if index >= MAX_ANNOUNCE_ADDRS {
            return Err(limit(format!(
                "announce address index {index} exceeds the limit of {MAX_ANNOUNCE_ADDRS}"
            )));
        }
        let addr: IpAddr = value
            .parse()
            .map_err(|_| invalid(format!("announce address `{value}` is not an IP address")))?;
        addrs.push((index, addr));
    }
    addrs.sort_by_key(|(index, _)| *index);
    for (expected, (index, _)) in addrs.iter().enumerate() {
        if *index != expected {
            return Err(invalid(
                "announce address indices must be contiguous from zero",
            ));
        }
    }

    let announce = PeerAnnounce {
        device_id: required_txt(&record.txt, "id")?,
        name: record.txt.get("name").cloned(),
        addrs: addrs.into_iter().map(|(_, addr)| addr).collect(),
        port: parse_u16(&required_txt(&record.txt, "port")?, "port")?,
        nonce: required_txt(&record.txt, "nonce")?,
        issued_ms: parse_i64(&required_txt(&record.txt, "issued")?, "issued")?,
        expires_ms: parse_i64(&required_txt(&record.txt, "expires")?, "expires")?,
        signature_b64: required_txt(&record.txt, "sig")?,
    };
    canonical_announce_bytes(&announce)?;
    Ok(announce)
}

fn validate_announce(announce: &PeerAnnounce) -> Result<(), ZeroError> {
    validate_device_id(&announce.device_id)?;
    if let Some(name) = &announce.name {
        validate_name(name)?;
    }
    if announce.addrs.is_empty() {
        return Err(invalid("announce must carry at least one address"));
    }
    if announce.addrs.len() > MAX_ANNOUNCE_ADDRS {
        return Err(limit(format!(
            "announce carries {} addresses; the limit is {MAX_ANNOUNCE_ADDRS}",
            announce.addrs.len()
        )));
    }
    for addr in &announce.addrs {
        if addr.is_unspecified() {
            return Err(invalid("announce address must not be unspecified"));
        }
        if addr.is_multicast() {
            return Err(invalid("announce address must not be multicast"));
        }
    }
    if announce.port == 0 {
        return Err(invalid("announce port must not be zero"));
    }
    if announce.nonce.len() < MIN_NONCE_BYTES || announce.nonce.len() > MAX_NONCE_BYTES {
        return Err(invalid(format!(
            "announce nonce must be {MIN_NONCE_BYTES}..={MAX_NONCE_BYTES} bytes"
        )));
    }
    if !announce
        .nonce
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric())
    {
        return Err(invalid("announce nonce must be ASCII alphanumeric"));
    }
    if announce.issued_ms < 0 {
        return Err(invalid("announce issue time must not be negative"));
    }
    let ttl = announce
        .expires_ms
        .checked_sub(announce.issued_ms)
        .ok_or_else(|| invalid("announce expiry is before its issue time"))?;
    if ttl <= 0 {
        return Err(invalid("announce expiry must be after its issue time"));
    }
    if ttl > MAX_ANNOUNCE_TTL_MS {
        return Err(limit(format!(
            "announce lifetime {ttl} ms exceeds {MAX_ANNOUNCE_TTL_MS} ms"
        )));
    }
    Ok(())
}

fn validate_device_id(device_id: &str) -> Result<(), ZeroError> {
    if device_id.len() != 64 || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "device id must be 64 hex characters (the blake3 hash of the public key)",
        ));
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<(), ZeroError> {
    if name.is_empty() {
        return Err(invalid("device name must not be empty"));
    }
    if name.len() > MAX_NAME_BYTES {
        return Err(limit(format!(
            "device name is {} bytes; the limit is {MAX_NAME_BYTES}",
            name.len()
        )));
    }
    if name.trim() != name {
        return Err(invalid("device name must not start or end with whitespace"));
    }
    if name.chars().any(char::is_control) {
        return Err(invalid("device name must not contain control characters"));
    }
    Ok(())
}

fn encode_addr(addr: &IpAddr) -> Vec<u8> {
    match addr {
        IpAddr::V4(v4) => {
            let mut out = Vec::with_capacity(5);
            out.push(4);
            out.extend_from_slice(&v4.octets());
            out
        }
        IpAddr::V6(v6) => {
            let mut out = Vec::with_capacity(17);
            out.push(6);
            out.extend_from_slice(&v6.octets());
            out
        }
    }
}

fn decode_addr(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [4, a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        [6, rest @ ..] if rest.len() == 16 => {
            let mut octets = [0u8; 16];
            octets.copy_from_slice(rest);
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// Sort by family and octets and drop repeats, so an announce has one address
/// list regardless of how a peer or a caller ordered it.
fn normalized_addr_bytes(addrs: &[IpAddr]) -> Vec<Vec<u8>> {
    let mut encoded: Vec<Vec<u8>> = addrs.iter().map(encode_addr).collect();
    encoded.sort();
    encoded.dedup();
    encoded
}

fn normalize_addrs(addrs: &[IpAddr]) -> Vec<IpAddr> {
    normalized_addr_bytes(addrs)
        .iter()
        .filter_map(|bytes| decode_addr(bytes))
        .collect()
}

fn put_count(out: &mut Vec<u8>, count: usize, max: usize, field: &str) -> Result<(), ZeroError> {
    if count > max {
        return Err(limit(format!(
            "announce has {count} {field}; the limit is {max}"
        )));
    }
    let count =
        u32::try_from(count).map_err(|_| limit(format!("{field} count exceeds a u32 prefix")))?;
    out.extend_from_slice(&count.to_be_bytes());
    Ok(())
}

fn put_bytes(out: &mut Vec<u8>, bytes: &[u8]) -> Result<(), ZeroError> {
    let len = u32::try_from(bytes.len()).map_err(|_| limit("an announce field is too long"))?;
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(bytes);
    Ok(())
}

fn put_str(out: &mut Vec<u8>, value: &str) -> Result<(), ZeroError> {
    put_bytes(out, value.as_bytes())
}

fn check_txt_bounds(txt: &BTreeMap<String, String>) -> Result<(), ZeroError> {
    if txt.len() > MAX_TXT_FIELDS {
        return Err(limit(format!(
            "announce record has {} TXT fields; the limit is {MAX_TXT_FIELDS}",
            txt.len()
        )));
    }
    let mut total = SERVICE.len();
    for (key, value) in txt {
        if value.len() > MAX_TXT_VALUE_BYTES {
            return Err(limit(format!(
                "announce TXT field `{key}` is {} bytes; the mDNS limit is {MAX_TXT_VALUE_BYTES}",
                value.len()
            )));
        }
        total += key.len() + value.len() + 1;
    }
    if total > MAX_MDNS_BYTES {
        return Err(limit(format!(
            "announce record is {total} bytes; the limit is {MAX_MDNS_BYTES}"
        )));
    }
    Ok(())
}

fn required_txt(txt: &BTreeMap<String, String>, key: &str) -> Result<String, ZeroError> {
    txt.get(key)
        .cloned()
        .ok_or_else(|| invalid(format!("announce TXT is missing `{key}`")))
}

fn parse_u16(value: &str, field: &str) -> Result<u16, ZeroError> {
    value
        .parse()
        .map_err(|_| invalid(format!("announce {field} `{value}` is not a u16")))
}

fn parse_i64(value: &str, field: &str) -> Result<i64, ZeroError> {
    value
        .parse()
        .map_err(|_| invalid(format!("announce {field} `{value}` is not an i64")))
}

fn to_hex(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        let _ = write!(out, "{byte:02x}");
    }
    out
}

fn ignored(reason: impl Into<String>) -> AcceptOutcome {
    AcceptOutcome::Ignored {
        reason: reason.into(),
    }
}

fn denied(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::PolicyDenied, message)
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

fn limit(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::LimitExceeded, message)
}

fn internal(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::Internal, message)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::DeviceRecord;
    use crate::state::sign_update;

    const NOW: i64 = 1_700_000_000_000;
    const TTL: i64 = 60_000;
    const OFFLINE_AFTER: i64 = 30_000;

    fn key() -> KeyPair {
        KeyPair::generate().expect("device key")
    }

    fn addr(text: &str) -> IpAddr {
        text.parse().expect("ip address")
    }

    fn announce(device: &KeyPair, nonce: &str, issued_ms: i64) -> PeerAnnounce {
        sign_announce(
            device,
            Some("laptop"),
            &[addr("192.168.1.10"), addr("fd00::10")],
            5000,
            nonce,
            issued_ms,
            issued_ms + TTL,
        )
        .expect("signed announce")
    }

    fn add_device(state: &mut MembershipState, device: &KeyPair, name: &str) {
        state.devices.insert(
            device.device_id().to_string(),
            DeviceRecord {
                device_id: device.device_id().to_string(),
                public_key_b64: device.public_key_b64(),
                name: Some(name.to_string()),
                added_ms: NOW,
                revoked: false,
                rotated_from: None,
            },
        );
        state
            .names
            .insert(device.device_id().to_string(), name.to_string());
    }

    /// Version 2 when `members` is non-empty, otherwise the signed version 1
    /// genesis.
    fn state_with_members(owner: &KeyPair, members: &[&KeyPair]) -> MembershipState {
        let genesis = MembershipState::new(owner, NOW).expect("genesis state");
        if members.is_empty() {
            return genesis;
        }
        let mut next = genesis.clone();
        next.version = 2;
        for (index, device) in members.iter().enumerate() {
            add_device(&mut next, device, &format!("peer{index}"));
        }
        sign_update(owner, &mut next, 1, NOW + 1)
            .expect("signed membership")
            .state
    }

    fn state_with_revoked(
        owner: &KeyPair,
        member: &KeyPair,
        revoked: &KeyPair,
    ) -> MembershipState {
        let state = state_with_members(owner, &[member, revoked]);
        let mut next = state.clone();
        next.version = state.version + 1;
        next.devices
            .get_mut(revoked.device_id())
            .expect("revoked member")
            .revoked = true;
        next.revoked.insert(revoked.device_id().to_string());
        next.names.remove(revoked.device_id());
        sign_update(owner, &mut next, state.version, NOW + 2)
            .expect("revocation state")
            .state
    }

    fn ignored_reason(outcome: AcceptOutcome) -> String {
        match outcome {
            AcceptOutcome::Ignored { reason } => reason,
            AcceptOutcome::Accepted => panic!("expected Ignored, got Accepted"),
        }
    }

    fn test_discovery() -> Discovery {
        Discovery::new(DiscoveryPolicy {
            offline_after_ms: OFFLINE_AFTER,
            ..DiscoveryPolicy::default()
        })
    }

    #[test]
    fn a_valid_member_announce_is_accepted() {
        let owner = key();
        let device = key();
        let membership = state_with_members(&owner, &[&device]);
        let announce = announce(&device, "nonce00000001", NOW);
        verify_announce(&device.public_key_b64(), &announce).expect("signature verifies");

        let mut discovery = test_discovery();
        assert_eq!(
            accept(&mut discovery, &announce, &membership, NOW),
            AcceptOutcome::Accepted
        );

        let record = &peers(&discovery)[device.device_id()];
        assert_eq!(record.presence(), Presence::Online);
        assert_eq!(record.last_seen_ms, NOW);
        assert_eq!(record.device_id(), device.device_id());
        assert_eq!(record.addrs(), announce.addrs.as_slice());
        assert!(record.announce.signature_b64 == announce.signature_b64);
        assert_eq!(discovery.membership_version, membership.version);
    }

    #[test]
    fn an_unknown_device_is_ignored_without_adding_a_peer() {
        let owner = key();
        let member = key();
        let stranger = key();
        let membership = state_with_members(&owner, &[&member]);
        let announce = announce(&stranger, "nonce00000001", NOW);
        verify_announce(&stranger.public_key_b64(), &announce).expect("self-consistent announce");

        let mut discovery = test_discovery();
        let reason = ignored_reason(accept(&mut discovery, &announce, &membership, NOW));
        assert!(reason.contains("not an approved member"), "{reason}");
        assert!(peers(&discovery).is_empty());
    }

    #[test]
    fn a_tampered_or_foreign_signature_is_ignored() {
        let owner = key();
        let member = key();
        let other = key();
        let membership = state_with_members(&owner, &[&member]);
        let mut discovery = test_discovery();

        // Same member id, signed by somebody else: the signature does not
        // verify under the member key.
        let mut foreign = announce(&member, "nonce00000001", NOW);
        foreign.signature_b64 = other.sign(&canonical_announce_bytes(&foreign).expect("canonical"));
        let reason = ignored_reason(accept(&mut discovery, &foreign, &membership, NOW));
        assert!(reason.contains("signature"), "{reason}");
        assert!(peers(&discovery).is_empty());

        // A field changed after signing: the signature covers the address.
        let mut tampered = announce(&member, "nonce00000002", NOW);
        tampered.addrs = vec![addr("192.168.1.99")];
        let reason = ignored_reason(accept(&mut discovery, &tampered, &membership, NOW));
        assert!(reason.contains("signature"), "{reason}");
        assert!(peers(&discovery).is_empty());
    }

    #[test]
    fn a_revoked_member_is_ignored() {
        let owner = key();
        let member = key();
        let revoked = key();
        let membership = state_with_revoked(&owner, &member, &revoked);
        let announce = announce(&revoked, "nonce00000001", NOW);
        verify_announce(&revoked.public_key_b64(), &announce).expect("announce is well formed");

        let mut discovery = test_discovery();
        let reason = ignored_reason(accept(&mut discovery, &announce, &membership, NOW));
        assert!(reason.contains("revoked"), "{reason}");
        assert!(peers(&discovery).is_empty());
    }

    #[test]
    fn expired_and_not_yet_valid_announces_are_ignored() {
        let owner = key();
        let device = key();
        let membership = state_with_members(&owner, &[&device]);
        let mut discovery = test_discovery();

        let expired = announce(&device, "nonce00000001", NOW - 2 * TTL);
        let reason = ignored_reason(accept(&mut discovery, &expired, &membership, NOW));
        assert!(reason.contains("expired"), "{reason}");
        assert!(peers(&discovery).is_empty());

        let future = announce(&device, "nonce00000002", NOW + 1_000);
        let reason = ignored_reason(accept(&mut discovery, &future, &membership, NOW));
        assert!(reason.contains("not yet valid"), "{reason}");
        assert!(peers(&discovery).is_empty());
    }

    #[test]
    fn a_replayed_nonce_is_ignored() {
        let owner = key();
        let device = key();
        let membership = state_with_members(&owner, &[&device]);
        let first = announce(&device, "nonce00000001", NOW);
        let mut discovery = test_discovery();

        assert_eq!(
            accept(&mut discovery, &first, &membership, NOW),
            AcceptOutcome::Accepted
        );
        let reason = ignored_reason(accept(&mut discovery, &first, &membership, NOW + 1));
        assert!(reason.contains("already seen"), "{reason}");
        assert_eq!(peers(&discovery)[device.device_id()].last_seen_ms, NOW);

        // A fresh nonce refreshes the same peer.
        let fresh = announce(&device, "nonce00000002", NOW + 2);
        assert_eq!(
            accept(&mut discovery, &fresh, &membership, NOW + 2),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            peers(&discovery)[device.device_id()].last_seen_ms,
            NOW + 2
        );
        assert_eq!(peers(&discovery).len(), 1);
    }

    #[test]
    fn sweep_marks_a_sleeping_peer_offline_and_an_announce_revives_it() {
        let owner = key();
        let device = key();
        let membership = state_with_members(&owner, &[&device]);
        let mut discovery = test_discovery();
        assert_eq!(
            accept(
                &mut discovery,
                &announce(&device, "nonce00000001", NOW),
                &membership,
                NOW
            ),
            AcceptOutcome::Accepted
        );

        assert_eq!(sweep(&mut discovery, NOW + OFFLINE_AFTER - 1, OFFLINE_AFTER), 0);
        assert_eq!(
            peers(&discovery)[device.device_id()].presence(),
            Presence::Online
        );

        assert_eq!(sweep(&mut discovery, NOW + OFFLINE_AFTER, OFFLINE_AFTER), 1);
        let record = &peers(&discovery)[device.device_id()];
        assert_eq!(record.presence(), Presence::Offline);
        assert!(!record.online);
        assert_eq!(
            record.last_seen_ms, NOW,
            "the last successful announce is preserved"
        );

        // A newer announce makes it online again (MESH-14: presence only).
        assert_eq!(
            accept(
                &mut discovery,
                &announce(&device, "nonce00000002", NOW + OFFLINE_AFTER + 1),
                &membership,
                NOW + OFFLINE_AFTER + 1
            ),
            AcceptOutcome::Accepted
        );
        assert_eq!(
            peers(&discovery)[device.device_id()].presence(),
            Presence::Online
        );
    }

    #[test]
    fn duplicate_addresses_are_deduplicated_and_sorted() {
        let owner = key();
        let device = key();
        let membership = state_with_members(&owner, &[&device]);
        let mut announce = announce(&device, "nonce00000001", NOW);
        let first = announce.addrs.clone();
        announce.addrs = vec![
            first[1],
            first[0],
            first[1],
            first[0],
            addr("192.168.1.10"),
        ];
        verify_announce(&device.public_key_b64(), &announce)
            .expect("the canonical encoding deduplicates addresses");

        let mut discovery = test_discovery();
        assert_eq!(
            accept(&mut discovery, &announce, &membership, NOW),
            AcceptOutcome::Accepted
        );
        let stored = &peers(&discovery)[device.device_id()];
        assert_eq!(stored.addrs(), first.as_slice());
        verify_announce(&device.public_key_b64(), &stored.announce)
            .expect("stored announce still verifies after deduplication");
    }

    #[test]
    fn canonical_bytes_ignore_signature_and_insertion_order() {
        let device = key();
        let mut first = announce(&device, "nonce00000001", NOW);
        first.addrs = vec![addr("10.0.0.2"), addr("10.0.0.1")];
        let mut second = first.clone();
        second.addrs = vec![addr("10.0.0.1"), addr("10.0.0.2")];
        second.signature_b64 = "a different signature".to_string();

        let bytes = canonical_announce_bytes(&first).expect("canonical bytes");
        assert!(bytes.starts_with(ANNOUNCE_DOMAIN));
        assert_eq!(bytes, canonical_announce_bytes(&second).expect("same bytes"));

        let mut renamed = first.clone();
        renamed.name = Some("desktop".to_string());
        assert_ne!(
            bytes,
            canonical_announce_bytes(&renamed).expect("a name changes the bytes")
        );
    }

    #[test]
    fn mdns_txt_round_trips_and_has_no_account_fields() {
        let device = key();
        let announce = announce(&device, "nonce00000001", NOW);
        let record = encode_announce(&announce).expect("encode");
        assert_eq!(record.service, SERVICE);
        assert_eq!(record.addrs, announce.addrs);
        assert_eq!(record.port, announce.port);

        let expected = [
            "addr0", "addr1", "expires", "id", "issued", "name", "nonce", "port", "sig", "v",
        ];
        let keys: Vec<&str> = record.txt.keys().map(String::as_str).collect();
        assert_eq!(keys, expected);
        for forbidden in ["account", "service", "user", "email", "relay", "cloud", "token"] {
            assert!(
                !record.txt.keys().any(|key| key.contains(forbidden)),
                "TXT carries `{forbidden}`"
            );
            assert!(!record.txt.values().any(|value| value.contains(forbidden)));
        }
        assert_eq!(record.txt["v"], "1");
        assert_eq!(record.txt["sig"], announce.signature_b64);

        let decoded = decode_announce(&record).expect("decode");
        assert_eq!(decoded, announce);

        // Decoding is not authentication: a decoded forged record is still
        // ignored by accept.
        let foreign = key();
        let mut forged = decode_announce(&record).expect("decode");
        forged.signature_b64 = foreign.sign(&canonical_announce_bytes(&forged).expect("canonical"));
        let owner = key();
        let membership = state_with_members(&owner, &[&device]);
        let mut discovery = test_discovery();
        let reason = ignored_reason(accept(&mut discovery, &forged, &membership, NOW));
        assert!(reason.contains("signature"), "{reason}");
        assert!(peers(&discovery).is_empty());
    }

    #[test]
    fn malformed_and_oversized_mdns_records_are_rejected() {
        let device = key();
        let announce = announce(&device, "nonce00000001", NOW);
        let good = encode_announce(&announce).expect("encode");

        let mut wrong_service = good.clone();
        wrong_service.service = "_other._udp.local".to_string();
        assert_eq!(
            decode_announce(&wrong_service)
                .expect_err("wrong service")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut missing_signature = good.clone();
        missing_signature.txt.remove("sig");
        assert_eq!(
            decode_announce(&missing_signature)
                .expect_err("missing signature")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut unknown_field = good.clone();
        unknown_field
            .txt
            .insert("account".to_string(), "owner".to_string());
        assert_eq!(
            decode_announce(&unknown_field)
                .expect_err("unknown TXT field")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut bad_address = good.clone();
        bad_address
            .txt
            .insert("addr0".to_string(), "not-an-ip".to_string());
        assert_eq!(
            decode_announce(&bad_address)
                .expect_err("bad address")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut gapped = good.clone();
        gapped.txt.remove("addr0");
        assert_eq!(
            decode_announce(&gapped)
                .expect_err("address indices must start at zero")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut zero_port = good.clone();
        zero_port.txt.insert("port".to_string(), "0".to_string());
        assert_eq!(
            decode_announce(&zero_port)
                .expect_err("zero port")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut oversized_value = good.clone();
        oversized_value
            .txt
            .insert("name".to_string(), "n".repeat(MAX_TXT_VALUE_BYTES + 1));
        assert_eq!(
            decode_announce(&oversized_value)
                .expect_err("TXT value above 255 bytes")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut too_many_fields = good.clone();
        for index in 0..MAX_TXT_FIELDS {
            too_many_fields
                .txt
                .insert(format!("x{index}"), "v".to_string());
        }
        assert_eq!(
            decode_announce(&too_many_fields)
                .expect_err("too many TXT fields")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut too_many_addrs = announce.clone();
        too_many_addrs.addrs = (0..=MAX_ANNOUNCE_ADDRS)
            .map(|index| IpAddr::V4(Ipv4Addr::new(10, 0, 0, index as u8)))
            .collect();
        assert_eq!(
            encode_announce(&too_many_addrs)
                .expect_err("too many addresses")
                .code(),
            ErrorCode::LimitExceeded
        );
        assert_eq!(
            canonical_announce_bytes(&too_many_addrs)
                .expect_err("too many addresses")
                .code(),
            ErrorCode::LimitExceeded
        );
    }

    #[test]
    fn an_older_membership_version_is_ignored() {
        let owner = key();
        let device = key();
        let version_two = state_with_members(&owner, &[&device]);
        let version_one = MembershipState::new(&owner, NOW).expect("genesis state");
        assert_eq!(version_one.version, 1);
        assert_eq!(version_two.version, 2);

        let mut discovery = test_discovery();
        assert_eq!(
            accept(
                &mut discovery,
                &announce(&device, "nonce00000001", NOW),
                &version_two,
                NOW
            ),
            AcceptOutcome::Accepted
        );

        let reason = ignored_reason(accept(
            &mut discovery,
            &announce(&device, "nonce00000002", NOW),
            &version_one,
            NOW,
        ));
        assert!(
            reason.contains("older than the last applied version"),
            "{reason}"
        );
        assert_eq!(peers(&discovery).len(), 1);
    }

    #[test]
    fn a_mismatched_membership_record_is_ignored() {
        let device = key();
        let impostor = key();
        // A hand-built, unverified version-0 snapshot: accept must not trust a
        // record whose public key does not hash to its id.
        let mut membership = MembershipState::empty(impostor.public_key_b64()).expect("placeholder");
        membership.devices.insert(
            device.device_id().to_string(),
            DeviceRecord {
                device_id: device.device_id().to_string(),
                public_key_b64: impostor.public_key_b64(),
                name: None,
                added_ms: NOW,
                revoked: false,
                rotated_from: None,
            },
        );

        let announce = announce(&device, "nonce00000001", NOW);
        let mut discovery = test_discovery();
        let reason = ignored_reason(accept(&mut discovery, &announce, &membership, NOW));
        assert!(reason.contains("does not match its public key"), "{reason}");
        assert!(peers(&discovery).is_empty());
    }

    #[test]
    fn announce_structure_is_bounded_and_typed() {
        let device = key();
        let good = announce(&device, "nonce00000001", NOW);

        let mut empty_addrs = good.clone();
        empty_addrs.addrs.clear();
        assert_eq!(
            canonical_announce_bytes(&empty_addrs)
                .expect_err("no addresses")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut zero_port = good.clone();
        zero_port.port = 0;
        assert_eq!(
            canonical_announce_bytes(&zero_port)
                .expect_err("zero port")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut short_nonce = good.clone();
        short_nonce.nonce = "short".to_string();
        assert_eq!(
            canonical_announce_bytes(&short_nonce)
                .expect_err("short nonce")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut bad_nonce = good.clone();
        bad_nonce.nonce = "not a nonce!".to_string();
        assert_eq!(
            canonical_announce_bytes(&bad_nonce)
                .expect_err("non-alphanumeric nonce")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut backwards = good.clone();
        backwards.expires_ms = backwards.issued_ms;
        assert_eq!(
            canonical_announce_bytes(&backwards)
                .expect_err("non-positive lifetime")
                .code(),
            ErrorCode::InvalidInput
        );

        assert_eq!(
            sign_announce(
                &device,
                None,
                &[addr("192.168.1.10")],
                5000,
                "nonce00000001",
                NOW,
                NOW + MAX_ANNOUNCE_TTL_MS + 1,
            )
            .expect_err("lifetime above the ceiling")
            .code(),
            ErrorCode::LimitExceeded
        );

        let mut unspecified = good.clone();
        unspecified.addrs = vec![addr("0.0.0.0")];
        assert_eq!(
            canonical_announce_bytes(&unspecified)
                .expect_err("unspecified address")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut multicast = good.clone();
        multicast.addrs = vec![addr("224.0.0.251")];
        assert_eq!(
            canonical_announce_bytes(&multicast)
                .expect_err("multicast address")
                .code(),
            ErrorCode::InvalidInput
        );

        let mut long_name = good.clone();
        long_name.name = Some("n".repeat(MAX_NAME_BYTES + 1));
        assert_eq!(
            canonical_announce_bytes(&long_name)
                .expect_err("name above the limit")
                .code(),
            ErrorCode::LimitExceeded
        );

        let mut control_name = good.clone();
        control_name.name = Some("bad\u{7}name".to_string());
        assert_eq!(
            canonical_announce_bytes(&control_name)
                .expect_err("control character")
                .code(),
            ErrorCode::InvalidInput
        );
    }

    #[test]
    fn presence_is_only_online_or_offline() {
        assert_eq!(
            serde_json::to_string(&Presence::Online).expect("serialise"),
            "\"online\""
        );
        assert_eq!(
            serde_json::to_string(&Presence::Offline).expect("serialise"),
            "\"offline\""
        );

        let device = key();
        let announce = announce(&device, "nonce00000001", NOW);
        let json = serde_json::to_string(&announce).expect("serialise announce");
        for forbidden in ["account", "service", "command", "task", "relay", "cloud"] {
            assert!(
                !json.contains(forbidden),
                "announce carries `{forbidden}`: {json}"
            );
        }
    }

    #[test]
    fn remove_and_peers_expose_local_state() {
        let owner = key();
        let device = key();
        let membership = state_with_members(&owner, &[&device]);
        let mut discovery = test_discovery();
        assert_eq!(
            accept(
                &mut discovery,
                &announce(&device, "nonce00000001", NOW),
                &membership,
                NOW
            ),
            AcceptOutcome::Accepted
        );
        assert_eq!(peers(&discovery).len(), 1);

        let removed = remove(&mut discovery, device.device_id()).expect("peer removed");
        assert_eq!(removed.device_id(), device.device_id());
        assert!(peers(&discovery).is_empty());
        assert!(remove(&mut discovery, device.device_id()).is_none());

        // Removing the peer also clears its replay ledger, so the same announce
        // can be accepted again as a fresh local join.
        assert_eq!(
            accept(
                &mut discovery,
                &announce(&device, "nonce00000001", NOW),
                &membership,
                NOW
            ),
            AcceptOutcome::Accepted
        );
    }

    #[test]
    fn announce_and_mdns_record_survive_serde() {
        let device = key();
        let announce = announce(&device, "nonce00000001", NOW);
        let json = serde_json::to_string(&announce).expect("serialise");
        let restored: PeerAnnounce = serde_json::from_str(&json).expect("deserialise");
        assert_eq!(restored, announce);
        verify_announce(&device.public_key_b64(), &restored).expect("restored announce verifies");

        let record = encode_announce(&announce).expect("encode");
        let decoded = decode_announce(&record).expect("decode");
        assert_eq!(decoded, restored);
    }
}
