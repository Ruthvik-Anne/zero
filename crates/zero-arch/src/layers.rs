//! Declared crate layers. Edges may only point to a strictly lower layer.
//!
//! This table is the machine-readable form of `architecture.md` Â§5. The
//! dependency-direction test fails on an upward edge or a cycle.

pub struct Layer {
    pub name: &'static str,
    pub level: u8,
    pub may_depend_on: &'static [&'static str],
}

pub const LAYERS: &[Layer] = &[
    Layer { name: "zero-types", level: 0, may_depend_on: &[] },
    Layer { name: "zero-store", level: 1, may_depend_on: &["zero-types"] },
    Layer {
        name: "zero-actions",
        level: 3,
        may_depend_on: &["zero-types", "zero-store", "zero-policy"],
    },
    Layer { name: "zero-tui", level: 1, may_depend_on: &["zero-types"] },
    Layer {
        name: "zero-policy",
        level: 2,
        may_depend_on: &["zero-types", "zero-store"],
    },
    Layer { name: "zero-fs", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer {
        name: "zero-tasks",
        level: 3,
        may_depend_on: &["zero-types", "zero-store", "zero-policy"],
    },
    Layer { name: "zero-sched", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer {
        name: "zero-secrets",
        level: 3,
        may_depend_on: &["zero-types", "zero-store", "zero-fs"],
    },
    Layer { name: "zero-model", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer { name: "zero-web", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer { name: "zero-mcp", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer { name: "zero-review", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer { name: "zero-halcyon", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer { name: "zero-mm", level: 2, may_depend_on: &["zero-types", "zero-store"] },
    Layer {
        name: "zero-mesh",
        level: 4,
        may_depend_on: &["zero-types", "zero-store", "zero-secrets"],
    },
    Layer {
        name: "zero-kernel",
        level: 3,
        may_depend_on: &["zero-types", "zero-store", "zero-policy"],
    },
    Layer {
        name: "zero-daemon-app",
        level: 4,
        may_depend_on: &["zero-types", "zero-actions", "zero-tui"],
    },
    Layer {
        name: "zero-agent",
        level: 4,
        may_depend_on: &[
            "zero-types",
            "zero-store",
            "zero-policy",
            "zero-actions",
            "zero-fs",
            "zero-tasks",
            "zero-sched",
            "zero-model",
        ],
    },
    Layer {
        name: "zero-daemon",
        level: 5,
        may_depend_on: &["zero-types", "zero-store", "zero-agent", "zero-policy", "zero-sched"],
    },
    Layer {
        name: "zero-doctor",
        level: 6,
        may_depend_on: &["zero-types", "zero-store", "zero-daemon"],
    },
    Layer {
        name: "zero-cli",
        level: 7,
        may_depend_on: &[
            "zero-types",
            "zero-store",
            "zero-agent",
            "zero-model",
            "zero-daemon",
            "zero-doctor",
            "zero-tui",
            "zero-actions",
            "zero-policy",
        ],
    },
];

pub fn layer_of(name: &str) -> Option<&'static Layer> {
    LAYERS.iter().find(|l| l.name == name)
}

/// All workspace crates that resolve to a declared layer.
pub fn declared_names() -> Vec<&'static str> {
    LAYERS.iter().map(|l| l.name).collect()
}

