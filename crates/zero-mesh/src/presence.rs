//! Presence and cost policy (T-MESH-09, MESH-13, MESH-14).
//!
//! This slice is the consumer of [`discovery`](crate::discovery): an accepted
//! announce becomes a [`Presence`] entry, and a device that stops announcing
//! becomes offline. Nothing here opens a socket; the table is a pure state
//! machine over times the caller supplies.
//!
//! What a caller may learn is deliberately small (MESH-13): only the device id,
//! whether it is online, whether it is directly reachable, and a coarse link
//! class leave the module through [`PublicPresence`]. Power state and battery
//! percentage stay local, there is no fleet-wide aggregate, no location, no
//! name, no command, and no orchestration surface.
//!
//! Cost decisions (MESH-14) are local policy, not remote authority:
//!
//! - a metered link is paused when [`CostPolicy::metered_pause`] is set;
//! - a battery at or below [`CostPolicy::low_battery_pause_percent`] defers
//!   work unless the device is charging;
//! - relaying requires a charging device when
//!   [`CostPolicy::require_charging_for_relay`] is set;
//! - an unknown link class or an unknown power state is **deferred**, never
//!   assumed cheap. Unknown link defers even when metered pausing is disabled,
//!   because the metered status itself is unknown.
//!
//! A sleeping host — one with no announce inside the offline window — is
//! [`PresenceState::Offline`] and is never offered as a relay candidate, both
//! after a [`PresenceTable::sweep`] and without one: [`relay_candidates`] also
//! checks freshness against the table's window, so a caller that forgets to
//! sweep still cannot route through a device that has gone quiet.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use zero_types::{ErrorCode, ZeroError};

use crate::discovery::DEFAULT_OFFLINE_AFTER_MS;

/// The transport class of a peer's current link.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinkKind {
    /// Wi-Fi. Treated as unmetered unless the caller reports [`Metered`].
    ///
    /// [`Metered`]: LinkKind::Metered
    Wifi,
    /// Wired Ethernet. Treated as unmetered.
    Ethernet,
    /// A cellular link. Always metered.
    Cellular,
    /// A link the caller knows to be metered, such as a tethered phone or a
    /// metered hotspot.
    Metered,
    /// The link class is not known. Cost decisions defer rather than guess.
    Unknown,
}

impl LinkKind {
    /// True when the link is billed by volume or time.
    pub fn is_metered(self) -> bool {
        matches!(self, Self::Cellular | Self::Metered)
    }

    /// True when the caller supplied a link class.
    pub fn is_known(self) -> bool {
        !matches!(self, Self::Unknown)
    }
}

/// A device's power source.
///
/// [`PowerState::Battery`] carries a percentage that must be at most 100;
/// [`validate`](PowerState::validate) and every table insert enforce that.
/// [`PowerState::Unknown`] exists so a caller that has no reading can say so:
/// cost decisions treat it conservatively (defer) instead of assuming mains
/// power.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PowerState {
    /// Mains or a charger with no battery constraint.
    Plugged,
    /// Running on a battery. `charging` is true when the device is plugged in
    /// and charging.
    Battery {
        /// Charge level, 0..=100.
        percent: u8,
        /// Whether the battery is charging right now.
        charging: bool,
    },
    /// No power reading is available. Always deferred by the cost policy.
    Unknown,
}

impl PowerState {
    /// Refuse a battery percentage above 100.
    pub fn validate(self) -> Result<(), ZeroError> {
        if let Self::Battery { percent, .. } = self {
            if percent > 100 {
                return Err(invalid(format!(
                    "battery percent {percent} is above 100"
                )));
            }
        }
        Ok(())
    }
}

/// A peer is online or offline. There is no "unknown" and no intermediate
/// state (MESH-13, MESH-14).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PresenceState {
    /// Heard from within the offline window.
    Online,
    /// Not heard from for at least the offline window; a sleeping host.
    Offline,
}

/// The local presence record for one device.
///
/// The fields are local state. Only [`PublicPresence`] leaves the module, and
/// it carries a strict subset.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Presence {
    /// The authenticated device id: 64 hex characters, the blake3 hash of the
    /// device public key, exactly as [`discovery`](crate::discovery) derives it.
    pub device_id: String,
    /// Online while the device is announcing inside the window.
    pub state: PresenceState,
    /// Whether the device can be reached directly right now. An offline device
    /// is never reachable.
    pub reachable: bool,
    /// Time of the last accepted announce, in milliseconds since the Unix
    /// epoch.
    pub last_seen_ms: i64,
    /// The device's reported link class.
    pub link: LinkKind,
    /// The device's reported power state. Local only; never published.
    pub power: PowerState,
}

impl Presence {
    /// An online, reachable presence for a fresh announce.
    pub fn announce(
        device_id: &str,
        link: LinkKind,
        power: PowerState,
        now_ms: i64,
    ) -> Self {
        Self {
            device_id: device_id.to_string(),
            state: PresenceState::Online,
            reachable: true,
            last_seen_ms: now_ms,
            link,
            power,
        }
    }

    /// Validate the device id and the battery percentage.
    pub fn validate(&self) -> Result<(), ZeroError> {
        validate_device_id(&self.device_id)?;
        self.power.validate()
    }

    /// True while the last announce is inside the offline window at `now_ms`.
    ///
    /// This mirrors [`PresenceTable::sweep`]: the entry is stale exactly when
    /// `now_ms - last_seen_ms >= offline_after_ms`.
    pub fn is_fresh(&self, now_ms: i64, offline_after_ms: i64) -> bool {
        now_ms.saturating_sub(self.last_seen_ms) < offline_after_ms.max(0)
    }
}

/// The narrow, per-device presence a caller may publish (MESH-13).
///
/// Deliberately absent: power state, battery percentage, last-seen time,
/// device name, addresses, locations, and any fleet-wide total. The struct is
/// per device; a list of them is not a fleet view and carries no aggregate
/// fields.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicPresence {
    /// The authenticated device id.
    pub device_id: String,
    /// Online or offline, reduced to a boolean.
    pub online: bool,
    /// Directly reachable. Always false while offline.
    pub reachable: bool,
    /// The coarse link class.
    pub link: LinkKind,
}

impl From<&Presence> for PublicPresence {
    fn from(presence: &Presence) -> Self {
        let online = presence.state == PresenceState::Online;
        Self {
            device_id: presence.device_id.clone(),
            online,
            reachable: online && presence.reachable,
            link: presence.link,
        }
    }
}

/// The local presence table, keyed by device id.
///
/// It holds no network state. `offline_after_ms` is the window
/// [`relay_candidates`] uses to reject a stale entry even when the caller has
/// not swept yet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PresenceTable {
    devices: BTreeMap<String, Presence>,
    offline_after_ms: i64,
}

impl PresenceTable {
    /// An empty table with the given offline window.
    pub fn new(offline_after_ms: i64) -> Self {
        Self {
            devices: BTreeMap::new(),
            offline_after_ms: offline_after_ms.max(0),
        }
    }

    /// The offline window this table uses for freshness checks.
    pub fn offline_after_ms(&self) -> i64 {
        self.offline_after_ms
    }

    /// Feed a presence record, treating it as an announce at `now_ms`.
    ///
    /// The device becomes [`PresenceState::Online`], `last_seen_ms` becomes
    /// `now_ms`, and reachability and cost fields are taken from the record.
    /// An invalid device id or a battery percentage above 100 is refused and
    /// the table is left unchanged.
    pub fn update(&mut self, presence: Presence, now_ms: i64) -> Result<(), ZeroError> {
        presence.validate()?;
        let mut stored = presence;
        stored.state = PresenceState::Online;
        stored.last_seen_ms = now_ms;
        self.devices.insert(stored.device_id.clone(), stored);
        Ok(())
    }

    /// Record a fresh online announce.
    pub fn announce(
        &mut self,
        device_id: &str,
        link: LinkKind,
        power: PowerState,
        now_ms: i64,
    ) -> Result<(), ZeroError> {
        self.update(Presence::announce(device_id, link, power, now_ms), now_ms)
    }

    /// Mark every online device whose last announce is at or past
    /// `offline_after_ms` as offline and unreachable.
    ///
    /// Returns how many devices changed, like
    /// [`discovery::sweep`](crate::discovery::sweep). A later
    /// [`update`](Self::update) makes the device online again.
    pub fn sweep(&mut self, now_ms: i64, offline_after_ms: i64) -> usize {
        let threshold = offline_after_ms.max(0);
        let mut marked = 0;
        for presence in self.devices.values_mut() {
            if presence.state == PresenceState::Online
                && now_ms.saturating_sub(presence.last_seen_ms) >= threshold
            {
                presence.state = PresenceState::Offline;
                presence.reachable = false;
                marked += 1;
            }
        }
        marked
    }

    /// The stored record for a device.
    pub fn get(&self, device_id: &str) -> Option<&Presence> {
        self.devices.get(device_id)
    }

    /// Drop a device and return its record, if it had one.
    ///
    /// Used when a signed revocation reaches this node: a revoked device must
    /// stop appearing in presence and cannot remain a relay candidate
    /// (T-MESH-08).
    pub fn remove(&mut self, device_id: &str) -> Option<Presence> {
        self.devices.remove(device_id)
    }

    /// The per-device public view, ascending by device id.
    ///
    /// One entry per device and no aggregate. Power and timing stay local.
    pub fn public_view(&self) -> Vec<PublicPresence> {
        self.devices.values().map(PublicPresence::from).collect()
    }
}

impl Default for PresenceTable {
    fn default() -> Self {
        Self::new(DEFAULT_OFFLINE_AFTER_MS)
    }
}

/// Local cost policy for sync and relay decisions (MESH-14).
///
/// The defaults are conservative: pause on metered links, pause at or below
/// 20% battery unless charging, and require a charging relay.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CostPolicy {
    /// Pause sync and relay on a metered link.
    pub metered_pause: bool,
    /// Defer work at or below this battery percentage unless charging.
    pub low_battery_pause_percent: u8,
    /// Require a charging (or plugged) device as a relay target.
    pub require_charging_for_relay: bool,
}

impl Default for CostPolicy {
    fn default() -> Self {
        Self {
            metered_pause: true,
            low_battery_pause_percent: 20,
            require_charging_for_relay: true,
        }
    }
}

impl CostPolicy {
    /// Build a policy, refusing a low-battery threshold above 100.
    pub fn new(
        metered_pause: bool,
        low_battery_pause_percent: u8,
        require_charging_for_relay: bool,
    ) -> Result<Self, ZeroError> {
        let policy = Self {
            metered_pause,
            low_battery_pause_percent,
            require_charging_for_relay,
        };
        policy.validate()?;
        Ok(policy)
    }

    /// Refuse a low-battery threshold above 100.
    pub fn validate(&self) -> Result<(), ZeroError> {
        if self.low_battery_pause_percent > 100 {
            return Err(invalid(format!(
                "low_battery_pause_percent {} is above 100",
                self.low_battery_pause_percent
            )));
        }
        Ok(())
    }
}

/// A cost decision.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Decision {
    /// The work may proceed.
    Allow,
    /// The work is paused, with a reason for logs and tests.
    Defer {
        /// Why the work was deferred.
        reason: String,
    },
}

impl Decision {
    /// True when the decision is [`Decision::Allow`].
    pub fn is_allow(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// The defer reason, when deferred.
    pub fn reason(&self) -> Option<&str> {
        match self {
            Self::Defer { reason } => Some(reason),
            Self::Allow => None,
        }
    }

    fn defer(reason: impl Into<String>) -> Self {
        Self::Defer {
            reason: reason.into(),
        }
    }
}

/// Whether this device should sync now.
///
/// Offline, unreachable, unknown-link, unknown-power, metered (when
/// configured), and low-battery (unless charging) presences all defer. The
/// check order is: policy, presence validity, online + reachable, link, power.
pub fn should_sync(presence: &Presence, policy: &CostPolicy) -> Decision {
    match check_cost(presence, policy, false) {
        Ok(()) => Decision::Allow,
        Err(reason) => Decision::defer(reason),
    }
}

/// Whether this device may act as a relay target now.
///
/// Same gates as [`should_sync`], plus
/// [`CostPolicy::require_charging_for_relay`]: with that flag set, a battery
/// device that is not charging is refused even at a healthy percentage. A
/// sleeping host defers because it is offline.
pub fn should_relay(presence: &Presence, policy: &CostPolicy) -> Decision {
    match check_cost(presence, policy, true) {
        Ok(()) => Decision::Allow,
        Err(reason) => Decision::defer(reason),
    }
}

fn check_cost(presence: &Presence, policy: &CostPolicy, for_relay: bool) -> Result<(), String> {
    if let Err(error) = policy.validate() {
        return Err(format!("cost policy is invalid: {}", error.message()));
    }
    if let Err(error) = presence.validate() {
        return Err(format!("presence is invalid: {}", error.message()));
    }
    if presence.state == PresenceState::Offline {
        return Err("device is offline; a sleeping host is not a source or relay".to_string());
    }
    if !presence.reachable {
        return Err("device is online but not reachable".to_string());
    }
    match presence.link {
        LinkKind::Unknown => {
            return Err(
                "link class is unknown; deferring rather than assume it is unmetered".to_string(),
            )
        }
        link if link.is_metered() && policy.metered_pause => {
            return Err(format!(
                "link `{}` is metered and metered_pause is on",
                link_label(link)
            ))
        }
        _ => {}
    }
    match presence.power {
        PowerState::Unknown => {
            Err("power state is unknown; deferring until the device reports it".to_string())
        }
        PowerState::Plugged => Ok(()),
        PowerState::Battery { percent, charging } => {
            if charging {
                return Ok(());
            }
            if for_relay && policy.require_charging_for_relay {
                return Err(format!(
                    "relay requires a charging device; battery is at {percent}% and not charging"
                ));
            }
            if percent <= policy.low_battery_pause_percent {
                return Err(format!(
                    "battery at {percent}% is at or below the low-battery threshold {}% and not charging",
                    policy.low_battery_pause_percent
                ));
            }
            Ok(())
        }
    }
}

/// Online, fresh, reachable, cost-allowed relay targets, ascending by device
/// id.
///
/// A device that has not announced inside the table's offline window is
/// excluded even if the caller never called [`PresenceTable::sweep`], so a
/// sleeping host is never offered as a relay (T-MESH-09 done criterion).
pub fn relay_candidates<'a>(
    table: &'a PresenceTable,
    policy: &CostPolicy,
    now_ms: i64,
) -> Vec<&'a Presence> {
    table
        .devices
        .values()
        .filter(|presence| presence.is_fresh(now_ms, table.offline_after_ms))
        .filter(|presence| should_relay(presence, policy).is_allow())
        .collect()
}

fn link_label(link: LinkKind) -> &'static str {
    match link {
        LinkKind::Wifi => "wifi",
        LinkKind::Ethernet => "ethernet",
        LinkKind::Cellular => "cellular",
        LinkKind::Metered => "metered",
        LinkKind::Unknown => "unknown",
    }
}

fn validate_device_id(device_id: &str) -> Result<(), ZeroError> {
    if device_id.len() != 64 || !device_id.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(invalid(
            "device id must be 64 hex characters (the blake3 hash of the public key)",
        ));
    }
    Ok(())
}

fn invalid(message: impl Into<String>) -> ZeroError {
    ZeroError::new(ErrorCode::InvalidInput, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_000;
    const WINDOW: i64 = 30_000;

    fn dev(index: u8) -> String {
        format!("{index:02x}").repeat(32)
    }

    fn battery(percent: u8, charging: bool) -> PowerState {
        PowerState::Battery { percent, charging }
    }

    fn table_with(presence: Presence, now_ms: i64) -> PresenceTable {
        let mut table = PresenceTable::new(WINDOW);
        table.update(presence, now_ms).expect("valid presence");
        table
    }

    #[test]
    fn a_fresh_announce_is_online_and_reachable() {
        let mut table = PresenceTable::new(WINDOW);
        table
            .announce(&dev(1), LinkKind::Wifi, PowerState::Plugged, NOW)
            .expect("fresh announce");

        let presence = table.get(&dev(1)).expect("stored");
        assert_eq!(presence.state, PresenceState::Online);
        assert!(presence.reachable);
        assert_eq!(presence.last_seen_ms, NOW);
        assert_eq!(presence.link, LinkKind::Wifi);
        assert_eq!(presence.power, PowerState::Plugged);
        assert!(presence.is_fresh(NOW, WINDOW));
    }

    #[test]
    fn a_sleeping_host_is_offline_and_not_a_relay_candidate() {
        let policy = CostPolicy::default();
        let mut table = table_with(
            Presence::announce(&dev(1), LinkKind::Ethernet, PowerState::Plugged, NOW),
            NOW,
        );
        assert_eq!(relay_candidates(&table, &policy, NOW).len(), 1);

        assert_eq!(table.sweep(NOW + WINDOW, WINDOW), 1);
        let sleeping = table.get(&dev(1)).expect("stored");
        assert_eq!(sleeping.state, PresenceState::Offline);
        assert!(!sleeping.reachable);
        assert_eq!(
            sleeping.last_seen_ms, NOW,
            "the last accepted announce is preserved"
        );
        assert!(relay_candidates(&table, &policy, NOW + WINDOW).is_empty());
        assert!(should_relay(sleeping, &policy).reason().is_some());

        // Even without a sweep, a stale entry is not offered as a relay: the
        // freshness window is checked again at candidate selection.
        let unswept = table_with(
            Presence::announce(&dev(2), LinkKind::Ethernet, PowerState::Plugged, NOW),
            NOW,
        );
        assert!(relay_candidates(&unswept, &policy, NOW + WINDOW).is_empty());

        // A new announce revives the same device.
        table
            .announce(
                &dev(1),
                LinkKind::Ethernet,
                PowerState::Plugged,
                NOW + WINDOW + 1,
            )
            .expect("reviving announce");
        assert_eq!(
            table.get(&dev(1)).expect("stored").state,
            PresenceState::Online
        );
        assert_eq!(
            relay_candidates(&table, &policy, NOW + WINDOW + 1).len(),
            1
        );
    }

    #[test]
    fn sweep_boundary_matches_the_offline_window() {
        let mut table = table_with(
            Presence::announce(&dev(1), LinkKind::Wifi, PowerState::Plugged, NOW),
            NOW,
        );

        assert_eq!(table.sweep(NOW + WINDOW - 1, WINDOW), 0);
        assert_eq!(
            table.get(&dev(1)).expect("stored").state,
            PresenceState::Online
        );

        assert_eq!(table.sweep(NOW + WINDOW, WINDOW), 1);
        assert_eq!(
            table.get(&dev(1)).expect("stored").state,
            PresenceState::Offline
        );

        // Sweeping an already-offline entry changes nothing.
        assert_eq!(table.sweep(NOW + 2 * WINDOW, WINDOW), 0);
    }

    #[test]
    fn an_unreachable_peer_is_not_a_relay_candidate() {
        let policy = CostPolicy::default();
        let mut presence = Presence::announce(&dev(1), LinkKind::Ethernet, PowerState::Plugged, NOW);
        presence.reachable = false;
        let table = table_with(presence, NOW);

        assert!(relay_candidates(&table, &policy, NOW).is_empty());
        assert_eq!(
            should_relay(table.get(&dev(1)).expect("stored"), &policy).reason(),
            Some("device is online but not reachable")
        );
    }

    #[test]
    fn a_metered_link_pauses_sync_and_relay_when_configured() {
        let strict = CostPolicy::default();
        assert!(strict.metered_pause);

        for link in [LinkKind::Cellular, LinkKind::Metered] {
            let presence = Presence::announce(&dev(1), link, PowerState::Plugged, NOW);
            let sync = should_sync(&presence, &strict);
            let reason = sync.reason().expect("metered sync is deferred");
            assert!(reason.contains("metered"), "{reason}");
            assert!(!should_relay(&presence, &strict).is_allow());
        }

        let wifi = Presence::announce(&dev(2), LinkKind::Wifi, PowerState::Plugged, NOW);
        assert!(should_sync(&wifi, &strict).is_allow());
        assert!(should_relay(&wifi, &strict).is_allow());

        let relaxed = CostPolicy {
            metered_pause: false,
            ..CostPolicy::default()
        };
        let cellular = Presence::announce(&dev(3), LinkKind::Cellular, PowerState::Plugged, NOW);
        assert!(should_sync(&cellular, &relaxed).is_allow());
        assert!(should_relay(&cellular, &relaxed).is_allow());
    }

    #[test]
    fn low_battery_defers_unless_charging() {
        let policy = CostPolicy::default();
        assert_eq!(policy.low_battery_pause_percent, 20);

        let low = Presence::announce(&dev(1), LinkKind::Wifi, battery(10, false), NOW);
        let sync = should_sync(&low, &policy);
        let reason = sync.reason().expect("low battery is deferred");
        assert!(reason.contains("low-battery"), "{reason}");

        let at_threshold = Presence::announce(&dev(2), LinkKind::Wifi, battery(20, false), NOW);
        assert!(!should_sync(&at_threshold, &policy).is_allow());

        let above = Presence::announce(&dev(3), LinkKind::Wifi, battery(21, false), NOW);
        assert!(should_sync(&above, &policy).is_allow());

        let charging = Presence::announce(&dev(4), LinkKind::Wifi, battery(10, true), NOW);
        assert!(should_sync(&charging, &policy).is_allow());

        let plugged = Presence::announce(&dev(5), LinkKind::Wifi, PowerState::Plugged, NOW);
        assert!(should_sync(&plugged, &policy).is_allow());
    }

    #[test]
    fn relay_requires_charging_when_configured() {
        let policy = CostPolicy::default();
        assert!(policy.require_charging_for_relay);

        let healthy = Presence::announce(&dev(1), LinkKind::Ethernet, battery(90, false), NOW);
        assert!(should_sync(&healthy, &policy).is_allow());
        let relay = should_relay(&healthy, &policy);
        let reason = relay.reason().expect("relay requires charging");
        assert!(reason.contains("charging"), "{reason}");

        let charging = Presence::announce(&dev(2), LinkKind::Ethernet, battery(90, true), NOW);
        assert!(should_relay(&charging, &policy).is_allow());

        let plugged = Presence::announce(&dev(3), LinkKind::Ethernet, PowerState::Plugged, NOW);
        assert!(should_relay(&plugged, &policy).is_allow());

        let relaxed = CostPolicy {
            require_charging_for_relay: false,
            ..CostPolicy::default()
        };
        let healthy = Presence::announce(&dev(4), LinkKind::Ethernet, battery(90, false), NOW);
        assert!(should_relay(&healthy, &relaxed).is_allow());
        let low = Presence::announce(&dev(5), LinkKind::Ethernet, battery(10, false), NOW);
        assert!(!should_relay(&low, &relaxed).is_allow());
    }

    #[test]
    fn unknown_power_and_link_are_conservatively_deferred() {
        let policy = CostPolicy::default();

        let unknown_power =
            Presence::announce(&dev(1), LinkKind::Ethernet, PowerState::Unknown, NOW);
        assert!(should_sync(&unknown_power, &policy).reason().is_some());
        assert!(should_relay(&unknown_power, &policy).reason().is_some());

        // Even with metered pausing off, an unknown link defers: the metered
        // status itself is unknown.
        let unknown_link = Presence::announce(&dev(2), LinkKind::Unknown, PowerState::Plugged, NOW);
        let relaxed = CostPolicy {
            metered_pause: false,
            low_battery_pause_percent: 0,
            require_charging_for_relay: false,
        };
        assert!(should_sync(&unknown_link, &policy).reason().is_some());
        assert!(should_sync(&unknown_link, &relaxed).reason().is_some());
        assert!(should_relay(&unknown_link, &relaxed).reason().is_some());
    }

    #[test]
    fn public_view_exposes_only_the_allowed_fields() {
        let mut table = PresenceTable::new(WINDOW);
        table
            .announce(
                &dev(1),
                LinkKind::Wifi,
                battery(55, true),
                NOW,
            )
            .expect("announce");

        let view = table.public_view();
        assert_eq!(view.len(), 1);
        let public = &view[0];
        assert_eq!(public.device_id, dev(1));
        assert!(public.online);
        assert!(public.reachable);
        assert_eq!(public.link, LinkKind::Wifi);

        let json = serde_json::to_value(public).expect("public presence serialises");
        let object = json.as_object().expect("object");
        let mut keys: Vec<&str> = object.keys().map(String::as_str).collect();
        keys.sort_unstable();
        assert_eq!(keys, ["device_id", "link", "online", "reachable"]);

        let text = json.to_string();
        for forbidden in ["power", "battery", "percent", "charging", "last_seen", "location"] {
            assert!(!text.contains(forbidden), "public view carries `{forbidden}`");
        }
    }

    #[test]
    fn percent_validation_refuses_above_one_hundred() {
        let bad = PowerState::Battery {
            percent: 101,
            charging: false,
        };
        assert_eq!(
            bad.validate().expect_err("101 percent").code(),
            ErrorCode::InvalidInput
        );
        assert!(PowerState::Battery {
            percent: 100,
            charging: false
        }
        .validate()
        .is_ok());

        let presence = Presence::announce(&dev(1), LinkKind::Wifi, bad, NOW);
        assert_eq!(
            presence.validate().expect_err("101 percent").code(),
            ErrorCode::InvalidInput
        );

        let mut table = PresenceTable::new(WINDOW);
        assert_eq!(
            table
                .update(presence, NOW)
                .expect_err("101 percent is refused")
                .code(),
            ErrorCode::InvalidInput
        );
        assert!(table.get(&dev(1)).is_none(), "refused record is not stored");
    }

    #[test]
    fn invalid_cost_policy_is_refused() {
        let bad = CostPolicy {
            metered_pause: true,
            low_battery_pause_percent: 101,
            require_charging_for_relay: false,
        };
        assert_eq!(
            bad.validate().expect_err("101 percent threshold").code(),
            ErrorCode::InvalidInput
        );
        assert_eq!(
            CostPolicy::new(true, 101, false)
                .expect_err("101 percent threshold")
                .code(),
            ErrorCode::InvalidInput
        );

        let presence = Presence::announce(&dev(1), LinkKind::Wifi, PowerState::Plugged, NOW);
        assert!(should_sync(&presence, &bad).reason().is_some());
        assert!(should_relay(&presence, &bad).reason().is_some());

        let good = CostPolicy::new(true, 20, true).expect("valid policy");
        assert!(should_sync(&presence, &good).is_allow());
    }

    #[test]
    fn the_public_view_is_per_device_with_no_fleet_aggregation() {
        let mut table = PresenceTable::new(WINDOW);
        table
            .announce(&dev(1), LinkKind::Wifi, PowerState::Plugged, NOW)
            .expect("device one");
        table
            .announce(&dev(2), LinkKind::Ethernet, battery(80, false), NOW + 20_000)
            .expect("device two");

        // Device one sleeps; device two was heard from ten seconds ago.
        assert_eq!(table.sweep(NOW + WINDOW, WINDOW), 1);
        let view = table.public_view();
        assert_eq!(view.len(), 2, "one entry per device, no aggregate row");
        assert_eq!(view[0].device_id, dev(1));
        assert!(!view[0].online);
        assert!(!view[0].reachable);
        assert_eq!(view[1].device_id, dev(2));
        assert!(view[1].online);
        assert!(view[1].reachable);

        // The published list is a flat array of per-device entries: no totals,
        // counts, or fleet-wide fields.
        let json = serde_json::to_value(&view).expect("view serialises");
        let array = json.as_array().expect("array of devices");
        assert_eq!(array.len(), 2);
        for entry in array {
            let object = entry.as_object().expect("per-device object");
            assert_eq!(object.len(), 4);
            assert!(!object.contains_key("total"));
            assert!(!object.contains_key("online_count"));
            assert!(!object.contains_key("devices_online"));
        }
    }
}
