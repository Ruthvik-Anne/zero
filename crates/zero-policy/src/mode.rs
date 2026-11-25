//! Modes, action classes, and the one mode-by-class matrix (POL-01, POL-02).

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Plan,
    Manual,
    SemiAuto,
    Auto,
    Headless,
}

impl Mode {
    pub const ALL: [Mode; 5] = [Mode::Plan, Mode::Manual, Mode::SemiAuto, Mode::Auto, Mode::Headless];

    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Plan => "plan",
            Mode::Manual => "manual",
            Mode::SemiAuto => "semi-auto",
            Mode::Auto => "auto",
            Mode::Headless => "headless",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|m| m.as_str() == s)
    }

    /// Authority rank for subagent inheritance. Plan is least; auto most.
    pub fn authority(self) -> u8 {
        match self {
            Mode::Plan => 0,
            Mode::Manual => 1,
            Mode::SemiAuto => 2,
            Mode::Auto => 3,
            Mode::Headless => 2,
        }
    }

    pub fn is_interactive(self) -> bool {
        !matches!(self, Mode::Headless)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Read,
    Write,
    ShellReadonly,
    ShellMutating,
    Delete,
    NetworkRead,
    NetworkWrite,
    McpRead,
    McpWrite,
    Subagent,
    Install,
    Computer,
    Credential,
    Mesh,
    ModeChange,
}

impl ActionClass {
    pub const ALL: [ActionClass; 15] = [
        ActionClass::Read,
        ActionClass::Write,
        ActionClass::ShellReadonly,
        ActionClass::ShellMutating,
        ActionClass::Delete,
        ActionClass::NetworkRead,
        ActionClass::NetworkWrite,
        ActionClass::McpRead,
        ActionClass::McpWrite,
        ActionClass::Subagent,
        ActionClass::Install,
        ActionClass::Computer,
        ActionClass::Credential,
        ActionClass::Mesh,
        ActionClass::ModeChange,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            ActionClass::Read => "read",
            ActionClass::Write => "write",
            ActionClass::ShellReadonly => "shell_readonly",
            ActionClass::ShellMutating => "shell_mutating",
            ActionClass::Delete => "delete",
            ActionClass::NetworkRead => "network_read",
            ActionClass::NetworkWrite => "network_write",
            ActionClass::McpRead => "mcp_read",
            ActionClass::McpWrite => "mcp_write",
            ActionClass::Subagent => "subagent",
            ActionClass::Install => "install",
            ActionClass::Computer => "computer",
            ActionClass::Credential => "credential",
            ActionClass::Mesh => "mesh",
            ActionClass::ModeChange => "mode_change",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Ask,
    Deny,
}

const PLAN: [Verdict; 15] = [
    Verdict::Allow, // read
    Verdict::Deny,  // write
    Verdict::Allow, // shell_readonly
    Verdict::Deny,  // shell_mutating
    Verdict::Deny,  // delete (trash)
    Verdict::Allow, // network_read
    Verdict::Deny,  // network_write
    Verdict::Allow, // mcp_read (verified only; evaluator asks otherwise)
    Verdict::Ask,   // mcp_write
    Verdict::Ask,   // subagent
    Verdict::Deny,  // install
    Verdict::Deny,  // computer
    Verdict::Deny,  // credential
    Verdict::Ask,   // mesh
    Verdict::Deny,  // mode_change
];

const MANUAL: [Verdict; 15] = [
    Verdict::Allow,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Deny,
];

const SEMI_AUTO: [Verdict; 15] = [
    Verdict::Allow, // read
    Verdict::Allow, // write
    Verdict::Ask,   // shell_readonly (bash is manual in semi-auto)
    Verdict::Ask,   // shell_mutating
    Verdict::Ask,   // delete
    Verdict::Ask,   // network_read
    Verdict::Ask,   // network_write
    Verdict::Allow, // mcp_read
    Verdict::Allow, // mcp_write
    Verdict::Ask,   // subagent
    Verdict::Ask,   // install
    Verdict::Ask,   // computer
    Verdict::Ask,   // credential
    Verdict::Ask,   // mesh
    Verdict::Deny,  // mode_change
];

const AUTO: [Verdict; 15] = [
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow, // delete is reversible trash, regulated by the code regulator
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Ask, // live computer use never runs silently
    Verdict::Ask, // credential use is never silent
    Verdict::Allow,
    Verdict::Deny,
];

const HEADLESS: [Verdict; 15] = [
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Ask,   // queued
    Verdict::Ask,   // queued unless a pre-existing allow rule exists
    Verdict::Allow,
    Verdict::Ask,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Allow,
    Verdict::Ask,
    Verdict::Deny,
    Verdict::Ask,
    Verdict::Ask,
    Verdict::Deny,
];

/// The defaults, in [`Mode::ALL`] × [`ActionClass::ALL`] order. This is the only
/// place default policy lives.
pub const MATRIX: [[Verdict; 15]; 5] = [PLAN, MANUAL, SEMI_AUTO, AUTO, HEADLESS];

pub fn default_verdict(mode: Mode, class: ActionClass) -> Verdict {
    let m = Mode::ALL.iter().position(|x| *x == mode).expect("mode in table");
    let c = ActionClass::ALL.iter().position(|x| *x == class).expect("class in table");
    MATRIX[m][c]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn matrix_is_exhaustive_and_matches_the_golden_defaults() {
        // Golden rows double as the regression gate: changing a default requires
        // changing this test and the docs.
        let expected: [[Verdict; 15]; 5] = [PLAN, MANUAL, SEMI_AUTO, AUTO, HEADLESS];
        let mut cells = 0;
        for (mi, mode) in Mode::ALL.iter().enumerate() {
            for (ci, class) in ActionClass::ALL.iter().enumerate() {
                assert_eq!(default_verdict(*mode, *class), expected[mi][ci], "{mode:?}/{class:?}");
                cells += 1;
            }
        }
        assert_eq!(cells, 5 * 15);
    }

    #[test]
    fn modes_and_classes_round_trip_their_names() {
        for mode in Mode::ALL {
            assert_eq!(Mode::parse(mode.as_str()), Some(mode));
        }
        for class in ActionClass::ALL {
            assert!(!class.as_str().is_empty());
        }
        assert_eq!(Mode::parse("nope"), None);
    }

    #[test]
    fn plan_denies_writes_deletes_and_mutating_shell() {
        for class in [ActionClass::Write, ActionClass::Delete, ActionClass::ShellMutating, ActionClass::Install, ActionClass::ModeChange] {
            assert_eq!(default_verdict(Mode::Plan, class), Verdict::Deny, "{class:?}");
        }
        assert_eq!(default_verdict(Mode::Plan, ActionClass::Read), Verdict::Allow);
        assert_eq!(default_verdict(Mode::Plan, ActionClass::ShellReadonly), Verdict::Allow);
        // Trash is denied in plan (DEL-10).
        assert_eq!(default_verdict(Mode::Plan, ActionClass::Delete), Verdict::Deny);
    }

    #[test]
    fn trash_mapping_matches_del10() {
        assert_eq!(default_verdict(Mode::Plan, ActionClass::Delete), Verdict::Deny);
        assert_eq!(default_verdict(Mode::Manual, ActionClass::Delete), Verdict::Ask);
        assert_eq!(default_verdict(Mode::SemiAuto, ActionClass::Delete), Verdict::Ask);
        assert_eq!(default_verdict(Mode::Auto, ActionClass::Delete), Verdict::Allow);
        assert_eq!(default_verdict(Mode::Headless, ActionClass::Delete), Verdict::Ask);
    }

    #[test]
    fn mode_change_is_never_allowed_by_the_matrix() {
        for mode in Mode::ALL {
            assert_eq!(default_verdict(mode, ActionClass::ModeChange), Verdict::Deny);
        }
    }
}
