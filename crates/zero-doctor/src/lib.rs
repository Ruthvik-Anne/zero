//! `zero-doctor` — see `architecture.md` section 5 for the module contract.
//!
//! The doctor must run while the daemon, kernel, and mesh are dead (DOC-09), so
//! the core is plugin-free and never opens a daemon socket. Checks, playbooks,
//! and repair arrive in T-DOC-02 through T-DOC-04; this module only owns the
//! report shape and the independent core.

use serde::{Deserialize, Serialize};

/// The crate version, shared by the binary banner and the report.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Whether the core reached the daemon.
///
/// The core never contacts the daemon on its own: diagnosis has to work with
/// the daemon dead. A later task may fill in the contacted states from a
/// caller-supplied probe, never from the core itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DaemonStatus {
    /// The core did not try to reach the daemon.
    NotContacted,
    /// A caller-supplied probe reached the daemon.
    Reachable,
    /// A caller-supplied probe found the daemon dead or unresponsive.
    Unreachable,
}

impl DaemonStatus {
    /// Human wording for the CLI, stable enough to assert on.
    pub fn label(self) -> &'static str {
        match self {
            DaemonStatus::NotContacted => "not contacted",
            DaemonStatus::Reachable => "reachable",
            DaemonStatus::Unreachable => "unreachable",
        }
    }
}

/// Outcome of one doctor check. Checks themselves land in T-DOC-02.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CheckStatus {
    /// The check passed.
    Ok,
    /// The check passed with something worth reading.
    Warn,
    /// The check failed.
    Fail,
}

/// One check result: a stable name, an outcome, and a redaction-safe detail.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckResult {
    pub name: String,
    pub status: CheckStatus,
    pub detail: String,
}

/// The diagnosis report. Serialized as `--json` and rendered for humans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DoctorReport {
    pub version: String,
    pub independent: bool,
    pub daemon: DaemonStatus,
    pub checks: Vec<CheckResult>,
}

impl DoctorReport {
    /// Human rendering. Keeps one `name: value` line per field so tests and
    /// operators can grep it.
    pub fn render_human(&self) -> String {
        let mut out = format!(
            "zero-doctor {}\nindependent: {}\ndaemon: {}\nchecks: {}\n",
            self.version,
            if self.independent { "yes" } else { "no" },
            self.daemon.label(),
            self.checks.len(),
        );
        for check in &self.checks {
            out.push_str(&format!(
                "  {} {}: {}\n",
                match check.status {
                    CheckStatus::Ok => "ok  ",
                    CheckStatus::Warn => "warn",
                    CheckStatus::Fail => "FAIL",
                },
                check.name,
                check.detail,
            ));
        }
        out
    }
}

/// Run the plugin-free core: no daemon socket, no config file, no plugin host.
pub fn run_core() -> DoctorReport {
    DoctorReport {
        version: VERSION.to_string(),
        independent: true,
        daemon: DaemonStatus::NotContacted,
        checks: Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_core_is_independent_and_does_not_contact_the_daemon() {
        let report = run_core();
        assert!(report.independent);
        assert_eq!(report.daemon, DaemonStatus::NotContacted);
        assert_eq!(report.version, VERSION);
        assert!(report.checks.is_empty());
    }

    #[test]
    fn human_output_names_the_version_and_the_dead_daemon() {
        let text = run_core().render_human();
        assert!(text.contains("zero-doctor 0.1.0"), "{text}");
        assert!(text.contains("daemon: not contacted"), "{text}");
    }
}
