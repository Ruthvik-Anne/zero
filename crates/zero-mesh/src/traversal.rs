//! NAT traversal planning (T-MESH-04, MESH-04, MESH-10).
//!
//! This slice models the parts of traversal that can be decided without a
//! network: the NAT in front of each peer, the address a STUN probe reports,
//! which route a pair of peers can use, and what happens when a hole punch does
//! not land. It opens no socket, starts no timer, and reads no clock. The local
//! mapping comes from a [`StunProbe`]; the punch itself is the injectable
//! [`HolePuncher`] seam; every address is caller-supplied.
//!
//! [`plan`] is a pure decision table over the 5×5 NAT matrix:
//!
//! | source \ destination | Open | FullCone | Restricted | PortRestricted | Symmetric |
//! |---|---|---|---|---|---|
//! | Open | Direct | Direct | HolePunch | HolePunch | TCP/443 |
//! | FullCone | Direct | Direct | HolePunch | HolePunch | TCP/443 |
//! | Restricted | Direct | Direct | HolePunch | HolePunch | TCP/443 |
//! | PortRestricted | Direct | Direct | HolePunch | HolePunch | TCP/443 |
//! | Symmetric | Direct | Direct | TCP/443 | TCP/443 | TCP/443 |
//!
//! A destination behind `Open` or `FullCone` is reachable without a punch, so
//! the path is [`Path::Direct`]. Otherwise a punch needs a *predictable* mapping
//! on both sides: a `Restricted`/`PortRestricted` pair works because both peers
//! send at the same time. A `Symmetric` NAT allocates a fresh external port per
//! destination, so the address it showed STUN is not where the peer's traffic
//! will come from, and a punch target cannot be named. Those cells use the
//! TCP/443 fallback when [`TraversalConfig::tcp_fallback`] is on; otherwise the
//! plan is [`Path::RelayRequired`] and the [`Failure`] explains that
//! cross-network connectivity needs at least one reachable node (MESH-10).
//!
//! The same rule applies when the peer published no mapped address at all: no
//! direct path and no punch can be planned, the plan carries a [`Failure`] with
//! [`Failure::needs_rendezvous`] set, and the reason always contains
//! [`RENDEZVOUS_REQUIRED`].
//!
//! [`attempt`] executes a plan against the punch seam. It is bounded by
//! [`TraversalConfig::hole_punch_attempts`] and
//! [`TraversalConfig::timeout_ms`], retries a miss, stops on a timeout, and on
//! failure returns a typed error that names the TCP/443 fallback it tried and
//! repeats the MESH-10 explanation. The real UDP and TCP/443 carriers are later
//! transport work; this module only decides and explains.

use std::fmt;
use std::net::{SocketAddr, SocketAddrV4, SocketAddrV6};

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

/// The largest number of STUN servers a traversal configuration may name.
pub const MAX_STUN_SERVERS: usize = 8;

/// The largest number of simultaneous punch attempts per plan.
pub const MAX_HOLE_PUNCH_ATTEMPTS: u8 = 8;

/// The longest per-attempt wait a plan may carry, in milliseconds.
pub const MAX_TIMEOUT_MS: i64 = 30_000;

/// The well-known port of the TCP fallback (MESH-04).
pub const TCP_FALLBACK_PORT: u16 = 443;

/// The sentence every rendezvous failure carries (MESH-10).
pub const RENDEZVOUS_REQUIRED: &str =
    "cross-network connectivity needs at least one reachable node";

/// The NAT behaviour observed in front of a peer.
///
/// The kind is caller-supplied: distinguishing an open, full-cone, restricted,
/// and port-restricted NAT needs filter tests that a pair of STUN calls cannot
/// perform, and the mesh does not guess. All kinds except [`NatKind::Symmetric`]
/// reuse one external mapping across destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NatKind {
    /// No NAT: the local address is the public address.
    Open,
    /// One mapping for every destination, and any host may send to it.
    FullCone,
    /// One mapping, and only addresses the host has sent to may use it.
    Restricted,
    /// One mapping, and only address-and-port pairs the host has sent to may
    /// use it.
    PortRestricted,
    /// A fresh mapping per destination. The address reported by STUN is not
    /// the address the peer will see.
    Symmetric,
}

impl NatKind {
    /// True for [`NatKind::Open`] and [`NatKind::FullCone`]: a destination
    /// behind either can receive an unsolicited packet.
    pub fn is_publicly_reachable(self) -> bool {
        matches!(self, Self::Open | Self::FullCone)
    }

    /// True when the NAT allocates a mapping per destination.
    pub fn is_symmetric(self) -> bool {
        matches!(self, Self::Symmetric)
    }

    /// True when one external mapping is reused across destinations, so a
    /// STUN result is a usable punch target.
    pub fn has_stable_mapping(self) -> bool {
        !self.is_symmetric()
    }
}

impl fmt::Display for NatKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Open => "open",
            Self::FullCone => "full-cone",
            Self::Restricted => "restricted",
            Self::PortRestricted => "port-restricted",
            Self::Symmetric => "symmetric",
        })
    }
}

/// A reachable address, as STUN reported it or as a peer published it.
///
/// Serde treats it as the socket address itself, so JSON carries
/// `"192.0.2.10:40000"` and not a wrapper object.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Endpoint {
    /// The socket address.
    pub addr: SocketAddr,
}

impl fmt::Display for Endpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.addr.fmt(f)
    }
}

/// The local mapping seam (MESH-04).
///
/// A production implementation sends one STUN binding request and reports the
/// observed external address; this module only consumes the answer. The trait
/// is the only place a real probe would enter, which is what keeps traversal
/// free of sockets and testable offline.
pub trait StunProbe {
    /// The external address a STUN server reports for `local_port`.
    fn mapped_addr(&self, local_port: u16) -> Result<Endpoint, ZeroError>;

    /// Whether the external mapping is reused across destinations. `false`
    /// means the NAT is symmetric and its [`Endpoint`] is not a punch target.
    fn mapping_stable(&self) -> bool;
}

/// Traversal bounds, validated before a plan is built.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalConfig {
    /// Number of configured STUN servers. Zero is allowed: traversal is then
    /// offline and can plan only from caller-supplied mappings.
    pub stun_servers: usize,
    /// Whether a failed or impossible punch may use the TCP/443 fallback.
    pub tcp_fallback: bool,
    /// Simultaneous punch attempts per plan, at least one.
    pub hole_punch_attempts: u8,
    /// The bounded wait for one attempt, in milliseconds.
    pub timeout_ms: i64,
}

impl Default for TraversalConfig {
    fn default() -> Self {
        Self {
            stun_servers: 2,
            tcp_fallback: true,
            hole_punch_attempts: 3,
            timeout_ms: 250,
        }
    }
}

impl TraversalConfig {
    /// Refuse a configuration a plan cannot honour.
    ///
    /// Zero attempts, a zero or negative timeout, and a count above its ceiling
    /// are refused; an over-ceiling count or timeout is `zero.fnd.limit_exceeded`
    /// and a nonsensical value is `zero.fnd.invalid_input`.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.stun_servers > MAX_STUN_SERVERS {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "{} STUN servers are configured; at most {MAX_STUN_SERVERS} are allowed",
                    self.stun_servers
                ),
            ));
        }
        if self.hole_punch_attempts == 0 {
            return Err(invalid("hole punch attempts must be at least one"));
        }
        if self.hole_punch_attempts > MAX_HOLE_PUNCH_ATTEMPTS {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "{} hole punch attempts exceed the ceiling of {MAX_HOLE_PUNCH_ATTEMPTS}",
                    self.hole_punch_attempts
                ),
            ));
        }
        if self.timeout_ms <= 0 {
            return Err(invalid("hole punch timeout must be positive"));
        }
        if self.timeout_ms > MAX_TIMEOUT_MS {
            return Err(ZeroError::new(
                ErrorCode::LimitExceeded,
                format!(
                    "a {} ms hole punch timeout exceeds the ceiling of {MAX_TIMEOUT_MS} ms",
                    self.timeout_ms
                ),
            ));
        }
        Ok(())
    }
}

/// The route a pair of peers can use.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "kebab-case")]
pub enum Path {
    /// The destination is publicly reachable; send without a punch.
    Direct,
    /// Both sides send to the other's mapped address at the same time.
    HolePunch {
        /// The local mapped address.
        local: Endpoint,
        /// The destination's mapped address.
        remote: Endpoint,
    },
    /// Dial the destination's published address on TCP [`TCP_FALLBACK_PORT`].
    TcpFallback {
        /// The address to dial: the destination's IP on port 443.
        endpoint: Endpoint,
    },
    /// Only an approved relay node can carry the connection.
    RelayRequired,
}

/// Why no direct path exists.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    /// The human-readable reason. Every rendezvous failure contains
    /// [`RENDEZVOUS_REQUIRED`].
    pub reason: String,
    /// True when the reason is a missing reachable node (MESH-10), so the
    /// caller should surface the rendezvous explanation rather than retry.
    pub needs_rendezvous: bool,
}

/// The decision for one pair of peers.
///
/// A plan carries at most one of the three shapes:
///
/// - a usable path (`path` is `Some`, `failure` is `None`);
/// - a relay that is required but needs a reachable node
///   ([`Path::RelayRequired`] plus a [`Failure`] with `needs_rendezvous`);
/// - no path at all (`path` is `None`, `failure` is `Some`).
///
/// `RelayRequired` is the one case that carries both: the relay is the only
/// remaining route, and the failure says why the direct routes are gone.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TraversalPlan {
    /// The route to attempt, when one exists.
    pub path: Option<Path>,
    /// Why no direct path exists.
    pub failure: Option<Failure>,
    /// The bounds the plan was built under and that [`attempt`] enforces.
    pub config: TraversalConfig,
}

impl TraversalPlan {
    /// True when the plan has a route that needs no relay or rendezvous.
    pub fn is_usable(&self) -> bool {
        self.path.is_some() && self.failure.is_none()
    }
}

/// One simultaneous punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchAttempt {
    /// The one-based attempt number.
    pub number: u8,
    /// The local mapped address to send from.
    pub local: Endpoint,
    /// The destination's mapped address to send to.
    pub remote: Endpoint,
    /// The bounded wait for this attempt, in milliseconds.
    pub timeout_ms: i64,
}

/// What one punch produced.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PunchOutcome {
    /// A packet crossed; the punch succeeded.
    Reached,
    /// The attempt missed; another attempt may follow.
    Missed,
    /// The bounded wait expired; no further attempt is made.
    TimedOut,
}

/// The punch seam.
///
/// A production implementation sends from `local` toward `remote` on the
/// mapped addresses and waits `timeout_ms` for an inbound packet. Tests supply
/// a scripted fake, so the state machine is exercised without a socket.
pub trait HolePuncher {
    /// Run one simultaneous punch and report what happened.
    fn punch(&mut self, attempt: PunchAttempt) -> PunchOutcome;

    /// Whether the TCP/443 fallback to `endpoint` can carry the connection.
    ///
    /// The default reports success: the fallback is selected by the planner and
    /// dialled by the transport, which is later work. A caller with a real
    /// carrier overrides it.
    fn tcp_fallback(&mut self, _endpoint: Endpoint) -> bool {
        true
    }
}

/// A connection that [`attempt`] established or selected.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Connected {
    /// The route that carried the connection.
    pub path: Path,
    /// Punch attempts spent before it succeeded; zero for a direct path and for
    /// a fallback that needed no punch.
    pub attempts: u8,
    /// The punch that failed before the TCP/443 fallback carried the
    /// connection, when that happened.
    pub fallback: Option<Failure>,
}

/// Plan a route between two peers (MESH-04, MESH-10).
///
/// The arguments are the NAT kind in front of each peer, the mapped address each
/// peer published (if any), and the validated bounds. The result is a
/// deterministic decision: the same inputs always produce the same plan.
///
/// The `Result` is only for configuration errors; an unreachable pair is an
/// `Ok` plan whose [`Failure`] explains it. A destination with no mapped address
/// is such a failure, with `needs_rendezvous` set.
pub fn plan(
    source_nat: NatKind,
    dest_nat: NatKind,
    source_mapped: Option<Endpoint>,
    dest_mapped: Option<Endpoint>,
    config: &TraversalConfig,
) -> Result<TraversalPlan, ZeroError> {
    config.validate()?;

    let Some(remote) = dest_mapped else {
        let reason = if config.stun_servers == 0 {
            format!(
                "no STUN server is configured and the destination published no mapped address; \
                 {RENDEZVOUS_REQUIRED}"
            )
        } else {
            format!(
                "the destination published no mapped address after {} STUN probe(s); \
                 {RENDEZVOUS_REQUIRED}",
                config.stun_servers
            )
        };
        return Ok(without_path(reason, config));
    };

    if dest_nat.is_publicly_reachable() {
        return Ok(with_path(Path::Direct, config));
    }

    if source_nat.has_stable_mapping() && dest_nat.has_stable_mapping() {
        let Some(local) = source_mapped else {
            return Ok(blocked(
                format!(
                    "the local mapping is unknown, so no simultaneous-send target exists; \
                     {RENDEZVOUS_REQUIRED}"
                ),
                remote,
                config,
            ));
        };
        return Ok(with_path(Path::HolePunch { local, remote }, config));
    }

    Ok(blocked(
        format!(
            "a symmetric NAT (source {source_nat}, destination {dest_nat}) allocates a new \
             external port per destination, so the STUN mapping is not a usable punch target; \
             {RENDEZVOUS_REQUIRED}"
        ),
        remote,
        config,
    ))
}

/// Execute a plan through the punch seam.
///
/// A direct path and a selected TCP/443 fallback need no punch. A hole-punch
/// path is attempted at most [`TraversalConfig::hole_punch_attempts`] times with
/// a [`TraversalConfig::timeout_ms`] wait each: a miss retries, a timeout stops.
/// When the punch fails, the TCP/443 fallback is used if
/// [`TraversalConfig::tcp_fallback`] is on; otherwise the call returns a typed
/// error that names the fallback and repeats [`RENDEZVOUS_REQUIRED`].
pub fn attempt(plan: &TraversalPlan, punch: &mut dyn HolePuncher) -> Result<Connected, ZeroError> {
    let Some(path) = plan.path else {
        let reason = plan
            .failure
            .as_ref()
            .map(|failure| failure.reason.clone())
            .unwrap_or_else(|| RENDEZVOUS_REQUIRED.to_string());
        return Err(unavailable(reason));
    };

    match path {
        Path::Direct => Ok(Connected {
            path: Path::Direct,
            attempts: 0,
            fallback: None,
        }),
        Path::TcpFallback { endpoint } => Ok(Connected {
            path: Path::TcpFallback { endpoint },
            attempts: 0,
            fallback: None,
        }),
        Path::RelayRequired => Err(unavailable(
            plan.failure
                .as_ref()
                .map(|failure| failure.reason.clone())
                .unwrap_or_else(|| {
                    format!(
                        "only an approved relay can carry the connection; {RENDEZVOUS_REQUIRED}"
                    )
                }),
        )),
        Path::HolePunch { local, remote } => punch_until_reached(plan, punch, local, remote),
    }
}

fn punch_until_reached(
    plan: &TraversalPlan,
    punch: &mut dyn HolePuncher,
    local: Endpoint,
    remote: Endpoint,
) -> Result<Connected, ZeroError> {
    let max = plan.config.hole_punch_attempts;
    let mut spent = 0u8;
    let mut timed_out = false;

    for number in 1..=max {
        spent = number;
        let outcome = punch.punch(PunchAttempt {
            number,
            local,
            remote,
            timeout_ms: plan.config.timeout_ms,
        });
        match outcome {
            PunchOutcome::Reached => {
                return Ok(Connected {
                    path: Path::HolePunch { local, remote },
                    attempts: number,
                    fallback: None,
                });
            }
            PunchOutcome::Missed => {}
            PunchOutcome::TimedOut => {
                timed_out = true;
                break;
            }
        }
    }

    let failure = Failure {
        reason: format!(
            "hole punch from {local} to {remote} {} after {spent} of {max} attempt(s) with a \
             {} ms wait",
            if timed_out { "timed out" } else { "missed" },
            plan.config.timeout_ms
        ),
        needs_rendezvous: false,
    };

    if plan.config.tcp_fallback {
        let endpoint = tcp_endpoint(remote);
        if punch.tcp_fallback(endpoint) {
            return Ok(Connected {
                path: Path::TcpFallback { endpoint },
                attempts: spent,
                fallback: Some(failure),
            });
        }
        return Err(unavailable(format!(
            "{}; the TCP/443 fallback to {endpoint} was attempted and also failed; \
             {RENDEZVOUS_REQUIRED} and an approved relay node",
            failure.reason
        )));
    }

    let code = if timed_out {
        ErrorCode::Timeout
    } else {
        ErrorCode::Unavailable
    };
    Err(ZeroError::new(
        code,
        format!(
            "{}; the TCP/443 fallback is disabled; {RENDEZVOUS_REQUIRED}, so enable the fallback \
             or add a reachable relay node",
            failure.reason
        ),
    ))
}

/// The destination's published IP on the TCP fallback port.
fn tcp_endpoint(remote: Endpoint) -> Endpoint {
    let addr = match remote.addr {
        SocketAddr::V4(v4) => SocketAddr::V4(SocketAddrV4::new(*v4.ip(), TCP_FALLBACK_PORT)),
        SocketAddr::V6(v6) => SocketAddr::V6(SocketAddrV6::new(
            *v6.ip(),
            TCP_FALLBACK_PORT,
            v6.flowinfo(),
            v6.scope_id(),
        )),
    };
    Endpoint { addr }
}

fn with_path(path: Path, config: &TraversalConfig) -> TraversalPlan {
    TraversalPlan {
        path: Some(path),
        failure: None,
        config: *config,
    }
}

fn without_path(reason: String, config: &TraversalConfig) -> TraversalPlan {
    TraversalPlan {
        path: None,
        failure: Some(Failure {
            reason,
            needs_rendezvous: true,
        }),
        config: *config,
    }
}

fn blocked(reason: String, remote: Endpoint, config: &TraversalConfig) -> TraversalPlan {
    if config.tcp_fallback {
        return with_path(
            Path::TcpFallback {
                endpoint: tcp_endpoint(remote),
            },
            config,
        );
    }
    TraversalPlan {
        path: Some(Path::RelayRequired),
        failure: Some(Failure {
            reason: format!(
                "{reason}; the TCP/443 fallback is disabled, so only an approved relay node can \
                 carry the connection"
            ),
            needs_rendezvous: true,
        }),
        config: *config,
    }
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
    use std::collections::VecDeque;

    const KINDS: [NatKind; 5] = [
        NatKind::Open,
        NatKind::FullCone,
        NatKind::Restricted,
        NatKind::PortRestricted,
        NatKind::Symmetric,
    ];

    /// The golden matrix, indexed `[source][destination]` in [`KINDS`] order.
    /// `Fallback` is the TCP/443 cell, or `RelayRequired` when the fallback is
    /// disabled.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Route {
        Direct,
        Punch,
        Fallback,
    }

    const MATRIX: [[Route; 5]; 5] = [
        // destination: Open    FullCone Restricted PortRestricted Symmetric
        [
            Route::Direct,
            Route::Direct,
            Route::Punch,
            Route::Punch,
            Route::Fallback,
        ], // Open
        [
            Route::Direct,
            Route::Direct,
            Route::Punch,
            Route::Punch,
            Route::Fallback,
        ], // FullCone
        [
            Route::Direct,
            Route::Direct,
            Route::Punch,
            Route::Punch,
            Route::Fallback,
        ], // Restricted
        [
            Route::Direct,
            Route::Direct,
            Route::Punch,
            Route::Punch,
            Route::Fallback,
        ], // PortRestricted
        [
            Route::Direct,
            Route::Direct,
            Route::Fallback,
            Route::Fallback,
            Route::Fallback,
        ], // Symmetric
    ];

    fn ep(text: &str) -> Endpoint {
        Endpoint {
            addr: text.parse().expect("test socket address"),
        }
    }

    fn local() -> Endpoint {
        ep("192.0.2.10:40000")
    }

    fn remote() -> Endpoint {
        ep("198.51.100.20:50000")
    }

    fn config() -> TraversalConfig {
        TraversalConfig::default()
    }

    fn plan_pair(src: NatKind, dst: NatKind, config: &TraversalConfig) -> TraversalPlan {
        plan(src, dst, Some(local()), Some(remote()), config).expect("valid configuration")
    }

    #[test]
    fn the_nat_matrix_is_deterministic_and_complete() {
        let enabled = config();
        let mut counts = [0usize; 3];

        for (row, src) in KINDS.iter().enumerate() {
            for (column, dst) in KINDS.iter().enumerate() {
                let expected = MATRIX[row][column];
                counts[expected as usize] += 1;

                let first = plan_pair(*src, *dst, &enabled);
                let second = plan_pair(*src, *dst, &enabled);
                assert_eq!(
                    first, second,
                    "the plan for {src}/{dst} is not deterministic"
                );

                let path = first.path.expect("every matrix cell selects a path");
                match expected {
                    Route::Direct => {
                        assert_eq!(path, Path::Direct, "{src} -> {dst}");
                        assert!(first.failure.is_none(), "{src} -> {dst}");
                        assert!(first.is_usable());
                    }
                    Route::Punch => {
                        assert_eq!(
                            path,
                            Path::HolePunch {
                                local: local(),
                                remote: remote()
                            },
                            "{src} -> {dst}"
                        );
                        assert!(first.failure.is_none(), "{src} -> {dst}");
                        assert!(first.is_usable());
                    }
                    Route::Fallback => {
                        let expected_endpoint = ep("198.51.100.20:443");
                        assert_eq!(
                            path,
                            Path::TcpFallback {
                                endpoint: expected_endpoint
                            },
                            "{src} -> {dst}"
                        );
                        assert!(first.failure.is_none(), "{src} -> {dst}");
                        assert!(first.is_usable());
                    }
                }
            }
        }

        assert_eq!(
            counts,
            [10, 8, 7],
            "10 direct cells, 8 punch cells, 7 fallback cells"
        );
    }

    #[test]
    fn disabling_the_fallback_makes_every_blocked_cell_require_a_relay() {
        let strict = TraversalConfig {
            tcp_fallback: false,
            ..config()
        };

        for (row, src) in KINDS.iter().enumerate() {
            for (column, dst) in KINDS.iter().enumerate() {
                let plan = plan_pair(*src, *dst, &strict);
                match MATRIX[row][column] {
                    Route::Direct => {
                        assert_eq!(plan.path, Some(Path::Direct));
                        assert!(plan.failure.is_none());
                    }
                    Route::Punch => {
                        assert!(matches!(plan.path, Some(Path::HolePunch { .. })));
                        assert!(plan.failure.is_none());
                    }
                    Route::Fallback => {
                        assert_eq!(plan.path, Some(Path::RelayRequired), "{src} -> {dst}");
                        let failure = plan
                            .failure
                            .as_ref()
                            .expect("a relay-required plan explains why");
                        assert!(failure.needs_rendezvous, "{src} -> {dst}");
                        assert!(
                            failure.reason.contains(RENDEZVOUS_REQUIRED),
                            "{src} -> {dst}: {}",
                            failure.reason
                        );
                        assert!(!plan.is_usable(), "{src} -> {dst}");
                    }
                }
                assert!(
                    plan.path.is_some() || plan.failure.is_some(),
                    "a plan is never empty"
                );
            }
        }
    }

    #[test]
    fn symmetric_and_symmetric_falls_back_to_tcp_when_enabled() {
        let plan = plan_pair(NatKind::Symmetric, NatKind::Symmetric, &config());

        assert_eq!(
            plan.path,
            Some(Path::TcpFallback {
                endpoint: ep("198.51.100.20:443")
            })
        );
        assert!(plan.failure.is_none());
        assert!(plan.is_usable());
    }

    #[test]
    fn symmetric_pairs_never_plan_a_punch() {
        for src in KINDS {
            for dst in KINDS {
                if !src.is_symmetric() && !dst.is_symmetric() {
                    continue;
                }
                let plan = plan_pair(src, dst, &config());
                let path = plan.path.expect("a path is selected");
                assert!(
                    matches!(path, Path::Direct | Path::TcpFallback { .. }),
                    "{src} -> {dst} selected {path:?}"
                );
            }
        }
    }

    #[test]
    fn a_missing_destination_mapping_needs_rendezvous() {
        let built = plan(
            NatKind::Restricted,
            NatKind::Restricted,
            Some(local()),
            None,
            &config(),
        )
        .expect("valid configuration");

        assert_eq!(built.path, None);
        let failure = built
            .failure
            .as_ref()
            .expect("a missing mapping is a failure");
        assert!(failure.needs_rendezvous);
        assert!(
            failure.reason.contains(RENDEZVOUS_REQUIRED),
            "{}",
            failure.reason
        );
        assert!(
            failure.reason.contains("2 STUN probe(s)"),
            "{}",
            failure.reason
        );
        assert!(!built.is_usable());

        // With no STUN server configured the reason names the missing rendezvous
        // rather than a probe count.
        let offline = TraversalConfig {
            stun_servers: 0,
            ..config()
        };
        let built =
            plan(NatKind::Open, NatKind::Open, None, None, &offline).expect("valid configuration");
        let failure = built.failure.expect("no mapped address");
        assert!(failure.needs_rendezvous);
        assert!(
            failure.reason.contains("no STUN server"),
            "{}",
            failure.reason
        );
        assert!(failure.reason.contains(RENDEZVOUS_REQUIRED));

        // A publicly reachable destination still needs an address to dial.
        let built =
            plan(NatKind::Open, NatKind::Open, None, None, &config()).expect("valid configuration");
        assert_eq!(built.path, None);
        assert!(built.failure.expect("failure").needs_rendezvous);
    }

    #[test]
    fn a_missing_local_mapping_falls_back_or_requires_a_relay() {
        let built = plan(
            NatKind::PortRestricted,
            NatKind::Restricted,
            None,
            Some(remote()),
            &config(),
        )
        .expect("valid configuration");
        assert_eq!(
            built.path,
            Some(Path::TcpFallback {
                endpoint: ep("198.51.100.20:443")
            })
        );
        assert!(built.failure.is_none());

        let strict = TraversalConfig {
            tcp_fallback: false,
            ..config()
        };
        let built = plan(
            NatKind::PortRestricted,
            NatKind::Restricted,
            None,
            Some(remote()),
            &strict,
        )
        .expect("valid configuration");
        assert_eq!(built.path, Some(Path::RelayRequired));
        let failure = built.failure.expect("a relay-required plan explains why");
        assert!(failure.needs_rendezvous);
        assert!(failure.reason.contains("local mapping is unknown"));

        // A public destination needs no local mapping at all.
        let built = plan(
            NatKind::PortRestricted,
            NatKind::Open,
            None,
            Some(remote()),
            &config(),
        )
        .expect("valid configuration");
        assert_eq!(built.path, Some(Path::Direct));
        assert!(built.failure.is_none());
    }

    #[test]
    fn config_validation_bounds_every_field() {
        let valid = config();
        assert_eq!(valid, TraversalConfig::default());
        valid.validate().expect("the default is valid");

        let zero_attempts = TraversalConfig {
            hole_punch_attempts: 0,
            ..valid
        };
        assert_eq!(
            zero_attempts.validate().expect_err("zero attempts").code(),
            ErrorCode::InvalidInput
        );

        let too_many_attempts = TraversalConfig {
            hole_punch_attempts: MAX_HOLE_PUNCH_ATTEMPTS + 1,
            ..valid
        };
        assert_eq!(
            too_many_attempts
                .validate()
                .expect_err("over the attempts ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );

        let zero_timeout = TraversalConfig {
            timeout_ms: 0,
            ..valid
        };
        assert_eq!(
            zero_timeout.validate().expect_err("zero timeout").code(),
            ErrorCode::InvalidInput
        );

        let negative_timeout = TraversalConfig {
            timeout_ms: -1,
            ..valid
        };
        assert_eq!(
            negative_timeout
                .validate()
                .expect_err("negative timeout")
                .code(),
            ErrorCode::InvalidInput
        );

        let long_timeout = TraversalConfig {
            timeout_ms: MAX_TIMEOUT_MS + 1,
            ..valid
        };
        assert_eq!(
            long_timeout
                .validate()
                .expect_err("over the timeout ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );

        let too_many_servers = TraversalConfig {
            stun_servers: MAX_STUN_SERVERS + 1,
            ..valid
        };
        assert_eq!(
            too_many_servers
                .validate()
                .expect_err("over the STUN server ceiling")
                .code(),
            ErrorCode::LimitExceeded
        );

        let error = plan(
            NatKind::Open,
            NatKind::Open,
            Some(local()),
            Some(remote()),
            &zero_attempts,
        )
        .expect_err("plan validates the configuration");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    /// A punch seam driven by a script; the default fallback reports success.
    struct ScriptedPuncher {
        outcomes: VecDeque<PunchOutcome>,
        punches: u8,
        fallback_ok: bool,
        fallback_calls: u8,
        last_attempt: Option<PunchAttempt>,
    }

    impl ScriptedPuncher {
        fn new(outcomes: &[PunchOutcome]) -> Self {
            Self {
                outcomes: outcomes.iter().copied().collect(),
                punches: 0,
                fallback_ok: true,
                fallback_calls: 0,
                last_attempt: None,
            }
        }
    }

    impl HolePuncher for ScriptedPuncher {
        fn punch(&mut self, attempt: PunchAttempt) -> PunchOutcome {
            self.punches += 1;
            self.last_attempt = Some(attempt);
            self.outcomes.pop_front().unwrap_or(PunchOutcome::Missed)
        }

        fn tcp_fallback(&mut self, _endpoint: Endpoint) -> bool {
            self.fallback_calls += 1;
            self.fallback_ok
        }
    }

    #[test]
    fn a_direct_path_connects_without_punching() {
        let plan = plan_pair(NatKind::Symmetric, NatKind::Open, &config());
        assert_eq!(plan.path, Some(Path::Direct));

        let mut punch = ScriptedPuncher::new(&[]);
        let connected = attempt(&plan, &mut punch).expect("direct path");
        assert_eq!(connected.path, Path::Direct);
        assert_eq!(connected.attempts, 0);
        assert!(connected.fallback.is_none());
        assert_eq!(punch.punches, 0);
        assert_eq!(punch.fallback_calls, 0);
    }

    #[test]
    fn a_selected_tcp_fallback_connects_without_punching() {
        let plan = plan_pair(NatKind::Symmetric, NatKind::Symmetric, &config());
        let mut punch = ScriptedPuncher::new(&[]);

        let connected = attempt(&plan, &mut punch).expect("selected fallback");
        assert_eq!(
            connected.path,
            Path::TcpFallback {
                endpoint: ep("198.51.100.20:443")
            }
        );
        assert_eq!(connected.attempts, 0);
        assert!(connected.fallback.is_none());
        assert_eq!(punch.punches, 0);
    }

    #[test]
    fn punch_attempts_are_bounded_by_the_configuration() {
        let plan = plan_pair(NatKind::Restricted, NatKind::PortRestricted, &config());
        assert_eq!(plan.config.hole_punch_attempts, 3);

        let mut punch = ScriptedPuncher::new(&[
            PunchOutcome::Missed,
            PunchOutcome::Missed,
            PunchOutcome::Missed,
            PunchOutcome::Reached,
        ]);
        let connected = attempt(&plan, &mut punch).expect("the fallback carries it");

        assert_eq!(punch.punches, 3, "no attempt beyond the configured bound");
        assert_eq!(connected.attempts, 3);
        assert_eq!(
            connected.path,
            Path::TcpFallback {
                endpoint: ep("198.51.100.20:443")
            }
        );
        let fallback = connected.fallback.expect("the missed punch is reported");
        assert!(fallback.reason.contains("missed after 3 of 3 attempt(s)"));
        assert!(!fallback.needs_rendezvous);
    }

    #[test]
    fn a_reached_punch_stops_retrying() {
        let plan = plan_pair(NatKind::Restricted, NatKind::Restricted, &config());
        let mut punch = ScriptedPuncher::new(&[
            PunchOutcome::Missed,
            PunchOutcome::Reached,
            PunchOutcome::Reached,
        ]);

        let connected = attempt(&plan, &mut punch).expect("punch reached");
        assert_eq!(punch.punches, 2);
        assert_eq!(connected.attempts, 2);
        assert_eq!(
            connected.path,
            Path::HolePunch {
                local: local(),
                remote: remote()
            }
        );
        assert!(connected.fallback.is_none());
        assert_eq!(punch.fallback_calls, 0);

        let attempt = punch.last_attempt.expect("the seam saw an attempt");
        assert_eq!(attempt.number, 2);
        assert_eq!(attempt.timeout_ms, config().timeout_ms);
        assert_eq!(attempt.local, local());
        assert_eq!(attempt.remote, remote());
    }

    #[test]
    fn a_punch_timeout_stops_the_retries_then_falls_back() {
        let plan = plan_pair(NatKind::Restricted, NatKind::Restricted, &config());
        let mut punch = ScriptedPuncher::new(&[PunchOutcome::TimedOut, PunchOutcome::Reached]);

        let connected = attempt(&plan, &mut punch).expect("the fallback carries it");
        assert_eq!(punch.punches, 1, "a timeout stops the retry loop");
        assert_eq!(connected.attempts, 1);
        let fallback = connected.fallback.expect("the timeout is reported");
        assert!(fallback
            .reason
            .contains("timed out after 1 of 3 attempt(s)"));
        assert!(fallback.reason.contains("250 ms"));

        let strict = TraversalConfig {
            tcp_fallback: false,
            ..config()
        };
        let plan = plan_pair(NatKind::Restricted, NatKind::Restricted, &strict);
        let mut punch = ScriptedPuncher::new(&[PunchOutcome::TimedOut]);
        let error = attempt(&plan, &mut punch).expect_err("no fallback is configured");
        assert_eq!(error.code(), ErrorCode::Timeout);
        assert!(error.message().contains("timed out"));
        assert!(
            error.message().contains(RENDEZVOUS_REQUIRED),
            "{}",
            error.message()
        );
        assert_eq!(punch.punches, 1);
    }

    #[test]
    fn a_failed_fallback_is_a_typed_error_with_the_explanation() {
        let plan = plan_pair(NatKind::Restricted, NatKind::Restricted, &config());
        let mut punch = ScriptedPuncher::new(&[PunchOutcome::Missed]);
        punch.fallback_ok = false;

        let error = attempt(&plan, &mut punch).expect_err("both routes failed");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(
            error.message().contains("was attempted and also failed"),
            "{}",
            error.message()
        );
        assert!(
            error.message().contains(RENDEZVOUS_REQUIRED),
            "{}",
            error.message()
        );
        assert_eq!(punch.fallback_calls, 1);
    }

    #[test]
    fn a_relay_required_plan_repeats_the_rendezvous_explanation() {
        let strict = TraversalConfig {
            tcp_fallback: false,
            ..config()
        };
        let plan = plan_pair(NatKind::Symmetric, NatKind::Symmetric, &strict);
        assert_eq!(plan.path, Some(Path::RelayRequired));

        let mut punch = ScriptedPuncher::new(&[]);
        let error = attempt(&plan, &mut punch).expect_err("a relay is required");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(
            error.message().contains(RENDEZVOUS_REQUIRED),
            "{}",
            error.message()
        );
        assert!(error.message().contains("relay"));
        assert_eq!(punch.punches, 0);
    }

    #[test]
    fn a_plan_without_a_path_returns_its_failure() {
        let built =
            plan(NatKind::Open, NatKind::Open, None, None, &config()).expect("valid configuration");
        let mut punch = ScriptedPuncher::new(&[]);

        let error = attempt(&built, &mut punch).expect_err("no path");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(
            error.message().contains(RENDEZVOUS_REQUIRED),
            "{}",
            error.message()
        );
    }

    /// A local mapping seam; the production probe is transport work.
    struct FakeProbe {
        mapped: Result<Endpoint, ZeroError>,
        stable: bool,
    }

    impl StunProbe for FakeProbe {
        fn mapped_addr(&self, local_port: u16) -> Result<Endpoint, ZeroError> {
            assert!(local_port != 0, "the caller supplies the real port");
            self.mapped.clone()
        }

        fn mapping_stable(&self) -> bool {
            self.stable
        }
    }

    #[test]
    fn a_probe_mapping_and_stability_drive_the_plan() {
        let stable = FakeProbe {
            mapped: Ok(local()),
            stable: true,
        };
        let source_mapped = stable.mapped_addr(41_000).expect("the probe answered");
        assert_eq!(source_mapped, local());
        let source_nat = if stable.mapping_stable() {
            NatKind::Restricted
        } else {
            NatKind::Symmetric
        };
        assert_eq!(source_nat, NatKind::Restricted);
        let built = plan(
            source_nat,
            NatKind::PortRestricted,
            Some(source_mapped),
            Some(remote()),
            &config(),
        )
        .expect("valid configuration");
        assert!(matches!(built.path, Some(Path::HolePunch { .. })));

        // An unstable mapping means a symmetric NAT, which has no punch target.
        let unstable = FakeProbe {
            mapped: Ok(local()),
            stable: false,
        };
        let source_nat = if unstable.mapping_stable() {
            NatKind::Restricted
        } else {
            NatKind::Symmetric
        };
        let built = plan(
            source_nat,
            NatKind::PortRestricted,
            Some(unstable.mapped_addr(41_000).expect("answered")),
            Some(remote()),
            &config(),
        )
        .expect("valid configuration");
        assert!(matches!(built.path, Some(Path::TcpFallback { .. })));

        // A probe failure is surfaced unchanged rather than turned into a guess.
        let broken = FakeProbe {
            mapped: Err(invalid("no STUN server answered")),
            stable: true,
        };
        let error = broken.mapped_addr(41_000).expect_err("the probe failed");
        assert_eq!(error.code(), ErrorCode::InvalidInput);
    }

    #[test]
    fn plans_paths_and_failures_survive_serde() {
        let plan = plan_pair(NatKind::Restricted, NatKind::Restricted, &config());
        let json = serde_json::to_value(&plan).expect("plan serialises");
        let restored: TraversalPlan = serde_json::from_value(json).expect("plan deserialises");
        assert_eq!(restored, plan);

        let path = Path::HolePunch {
            local: local(),
            remote: remote(),
        };
        let json = serde_json::to_value(path).expect("path serialises");
        assert_eq!(json["kind"], "hole-punch");
        assert_eq!(json["remote"], "198.51.100.20:50000");
        let restored: Path = serde_json::from_value(json).expect("path deserialises");
        assert_eq!(restored, path);

        let failure = plan.failure.clone().unwrap_or(Failure {
            reason: RENDEZVOUS_REQUIRED.to_string(),
            needs_rendezvous: true,
        });
        let json = serde_json::to_value(&failure).expect("failure serialises");
        let restored: Failure = serde_json::from_value(json).expect("failure deserialises");
        assert_eq!(restored, failure);
    }

    #[test]
    fn the_module_opens_no_socket_and_starts_no_timer() {
        let source = include_str!("traversal.rs");
        // Assembled at compile time so this test's own literals are not what it
        // finds in the source.
        let forbidden = [
            concat!("Udp", "Socket"),
            concat!("Tcp", "Stream"),
            concat!("Tcp", "Listener"),
            concat!("std::", "time"),
            concat!("to_socket", "_addrs"),
        ];
        for needle in forbidden {
            assert!(
                !source.contains(needle),
                "traversal must stay transport-free but names `{needle}`"
            );
        }
    }
}
