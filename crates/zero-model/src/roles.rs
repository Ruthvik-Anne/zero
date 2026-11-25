//! Role defaults and assignment (MDL-07, T-MDL-04).
//!
//! A subagent declares a [`Role`]; the role maps to a [`classify::WorkClass`]
//! and therefore to the class's capability floor. A [`RoleTable`] holds one
//! documented default model per role, and [`assign`] turns a role plus an
//! optional user pin and upgrade request into a [`RoleAssignment`].
//!
//! Precedence, highest first:
//!
//! 1. **User pin** — wins over the role default and over an upgrade request.
//! 2. **Upgrade request** — needs budget approval and a non-empty reason, and
//!    the model must clear the role's floor.
//! 3. **Role default** — what a subagent uses with no pin and no upgrade.
//! 4. **Fallback** — only when the role default is unavailable or below the
//!    floor; the cheapest available model that clears the floor is recorded as
//!    [`RoleSource::Fallback`].
//!
//! A pin or an upgrade below the floor is refused with `zero.pol.denied`, so
//! no assignment can undercut its role's class floor. [`enforce_floor`] exposes
//! the same check for work classified directly, including the `security` and
//! `destructive` floors that no role maps to. The check reuses
//! [`classify::meets`] and [`classify::floor_for`], never a local copy. Errors
//! and reasons name roles, work classes, capabilities, grades, and model ids;
//! they never contain prompt text.
//!
//! Model ids in the seeded table are representative and configurable. They are
//! not a price list and they are not refreshed here; MDL-01/PRV-08 own the
//! catalogue data.

use crate::classify::{self, Classification, FloorResult, ModelGrades, WorkClass};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// The job a subagent is doing (MDL-07).
///
/// This is the agent role, not the provider message role. The message role is
/// [`crate::provider::Role`] and stays re-exported as `zero_model::Role`; this
/// enum is re-exported as `zero_model::AgentRole`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    /// Design, decomposition, and analysis.
    Planner,
    /// Change code or files.
    Coder,
    /// Read-only examination of existing work.
    Reviewer,
    /// Write or run tests.
    Tester,
    /// Gather and compare information.
    Researcher,
    /// Look at an image, screenshot, or rendered UI.
    Vision,
}

impl Role {
    /// Every role, in declaration order.
    pub const ALL: [Role; 6] = [
        Role::Planner,
        Role::Coder,
        Role::Reviewer,
        Role::Tester,
        Role::Researcher,
        Role::Vision,
    ];

    /// The work class this role is routed as.
    pub const fn work_class(self) -> WorkClass {
        match self {
            Role::Planner => WorkClass::Plan,
            Role::Coder => WorkClass::Edit,
            Role::Reviewer => WorkClass::Review,
            Role::Tester => WorkClass::Test,
            Role::Researcher => WorkClass::Research,
            Role::Vision => WorkClass::VisualInspection,
        }
    }

    /// Stable snake-case label used in reasons, errors, and stored data.
    pub const fn as_str(self) -> &'static str {
        match self {
            Role::Planner => "planner",
            Role::Coder => "coder",
            Role::Reviewer => "reviewer",
            Role::Tester => "tester",
            Role::Researcher => "researcher",
            Role::Vision => "vision",
        }
    }

    /// Parse a role case-insensitively, trimming surrounding whitespace.
    ///
    /// An unknown name is `zero.fnd.not_found` and the message lists the valid
    /// roles in declaration order.
    pub fn parse(text: &str) -> Result<Role> {
        match text.trim().to_ascii_lowercase().as_str() {
            "planner" => Ok(Role::Planner),
            "coder" => Ok(Role::Coder),
            "reviewer" => Ok(Role::Reviewer),
            "tester" => Ok(Role::Tester),
            "researcher" => Ok(Role::Researcher),
            "vision" => Ok(Role::Vision),
            _ => Err(ZeroError::new(
                ErrorCode::NotFound,
                format!("unknown role {text:?}; available roles: {}", role_list()),
            )),
        }
    }
}

impl std::str::FromStr for Role {
    type Err = ZeroError;

    fn from_str(text: &str) -> Result<Self> {
        Role::parse(text)
    }
}

impl std::fmt::Display for Role {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The roles in declaration order, joined for an error message.
fn role_list() -> String {
    Role::ALL.iter().map(|role| role.as_str()).collect::<Vec<_>>().join(", ")
}

/// The default model for one role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleDefault {
    pub role: Role,
    pub model: String,
    /// Provider id for the default, when the model is provider-specific.
    pub provider: Option<String>,
    /// Why this model is the default. Deterministic and free of prompt text.
    pub reason: String,
}

/// One documented default per role.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleTable {
    pub defaults: BTreeMap<Role, RoleDefault>,
}

impl Default for RoleTable {
    fn default() -> Self {
        Self::seeded()
    }
}

impl RoleTable {
    /// The documented default table.
    ///
    /// Model ids are representative and must be treated as configuration: the
    /// catalogue (MDL-01) holds the real availability, grades, limits, and
    /// prices. No price is encoded here.
    pub fn seeded() -> Self {
        let defaults = [
            entry(
                Role::Planner,
                "gpt-5",
                "openai",
                "planning needs the strongest reasoning and instruction following",
            ),
            entry(
                Role::Coder,
                "gpt-5-codex",
                "openai",
                "coding needs the top coding and tool-use grades",
            ),
            entry(
                Role::Reviewer,
                "claude-sonnet-4-5",
                "anthropic",
                "review needs coding, reasoning, and a long context window",
            ),
            entry(
                Role::Tester,
                "gpt-5-codex",
                "openai",
                "writing and running tests needs coding and tool use",
            ),
            entry(
                Role::Researcher,
                "gemini-2.5-pro",
                "google",
                "research needs tool use and a long context window",
            ),
            entry(
                Role::Vision,
                "claude-sonnet-4-5",
                "anthropic",
                "visual inspection needs a vision-capable model",
            ),
        ]
        .into_iter()
        .collect();
        Self { defaults }
    }

    /// Insert or replace one role default, returning the updated table.
    pub fn with_default(mut self, default: RoleDefault) -> Self {
        self.defaults.insert(default.role, default);
        self
    }

    /// The roles this table can resolve, in declaration order.
    pub fn roles(&self) -> Vec<Role> {
        self.defaults.keys().copied().collect()
    }
}

fn entry(role: Role, model: &str, provider: &str, reason: &str) -> (Role, RoleDefault) {
    (
        role,
        RoleDefault {
            role,
            model: model.to_owned(),
            provider: Some(provider.to_owned()),
            reason: reason.to_owned(),
        },
    )
}

/// Resolve a role's default, or fail with `zero.fnd.not_found` listing the
/// roles the table actually has.
pub fn resolve(role: Role, table: &RoleTable) -> Result<&RoleDefault> {
    table.defaults.get(&role).ok_or_else(|| {
        let available = if table.defaults.is_empty() {
            "none".to_owned()
        } else {
            table
                .defaults
                .keys()
                .map(|role| role.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        };
        ZeroError::new(
            ErrorCode::NotFound,
            format!("no default for role {}; available roles: {available}", role.as_str()),
        )
    })
}

/// A scheduler-approved request to run a role above its default.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeRequest {
    pub model: String,
    /// Why the default is insufficient. Empty or whitespace-only is refused.
    pub reason: String,
    /// The scheduler's budget decision. Only `true` permits the upgrade.
    pub budget_ok: bool,
}

/// Where an assignment's model came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoleSource {
    /// The role's configured default.
    Default,
    /// An explicit user pin.
    UserPinned,
    /// A scheduler-approved upgrade.
    UpgradeRequested,
    /// The default was unavailable and a permitted model replaced it.
    Fallback,
}

impl RoleSource {
    /// Stable snake-case label used in reasons and stored data.
    pub const fn as_str(self) -> &'static str {
        match self {
            RoleSource::Default => "default",
            RoleSource::UserPinned => "user_pinned",
            RoleSource::UpgradeRequested => "upgrade_requested",
            RoleSource::Fallback => "fallback",
        }
    }
}

/// The model a role will use and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoleAssignment {
    pub role: Role,
    pub model: String,
    pub source: RoleSource,
    /// Deterministic explanation. Never contains prompt text.
    pub reason: String,
}

/// The inputs to [`pick`]: an optional pin and an optional upgrade request.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RoleRequest {
    pub user_pin: Option<String>,
    pub upgrade: Option<UpgradeRequest>,
}

/// What the router knows about the models it may use.
///
/// A model is available exactly when the catalogue returns its grades, and the
/// same grades are what the security/destructive floor check reads. Implemented
/// for `BTreeMap<String, ModelGrades>` and for `[ModelGrades]`, so a caller can
/// hand over a pool entry set or a small slice.
pub trait ModelCatalogue {
    /// Grades for an available model; `None` means unknown or unavailable.
    fn grades(&self, model: &str) -> Option<ModelGrades>;

    /// Every model the catalogue can currently use, in its own order.
    fn models(&self) -> Vec<&ModelGrades>;

    /// Whether a model is available. Availability is grade knowledge.
    fn available(&self, model: &str) -> bool {
        self.grades(model).is_some()
    }
}

impl ModelCatalogue for BTreeMap<String, ModelGrades> {
    fn grades(&self, model: &str) -> Option<ModelGrades> {
        self.get(model).cloned()
    }

    fn models(&self) -> Vec<&ModelGrades> {
        self.values().collect()
    }
}

impl ModelCatalogue for [ModelGrades] {
    fn grades(&self, model: &str) -> Option<ModelGrades> {
        self.iter().find(|entry| entry.model == model).cloned()
    }

    fn models(&self) -> Vec<&ModelGrades> {
        self.iter().collect()
    }
}

/// Format missing capabilities deterministically, in capability order.
fn describe_missing(result: &FloorResult) -> String {
    result
        .missing
        .iter()
        .map(|(capability, required, actual)| {
            format!("{}>={} (has {})", capability.as_str(), required.get(), actual.get())
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Enforce a work class's floor on one model.
///
/// This is the check [`assign`] uses for a role's `work_class()`. It is public
/// so a caller can also enforce the floor of a task that classified as
/// `security` or `destructive` before dispatching it: a user pin or an upgrade
/// never undercuts the classifier floor (MDL-03). The check is `classify::meets`
/// against `classify::floor_for(class)`; nothing local re-implements floors.
pub fn enforce_floor(
    class: WorkClass,
    model: &str,
    requested_by: &str,
    catalogue: &dyn ModelCatalogue,
) -> Result<ModelGrades> {
    let grades = catalogue.grades(model).ok_or_else(|| {
        ZeroError::new(
            ErrorCode::NotFound,
            format!("{requested_by} model {model:?} is not in the model catalogue"),
        )
    })?;
    let result = classify::meets(&grades, &classify::floor_for(class));
    if result.ok {
        Ok(grades)
    } else {
        Err(ZeroError::new(
            ErrorCode::PolicyDenied,
            format!(
                "{requested_by} model {model:?} is below the {} floor: {}",
                class.as_str(),
                describe_missing(&result)
            ),
        ))
    }
}

/// Look a model up and enforce the role's class floor.
fn check_floor(
    role: Role,
    model: &str,
    requested_by: &str,
    catalogue: &dyn ModelCatalogue,
) -> Result<ModelGrades> {
    enforce_floor(
        role.work_class(),
        model,
        &format!("{requested_by} for role {}", role.as_str()),
        catalogue,
    )
}

/// The cheapest available model that clears `class`'s floor. Ties break by
/// model id, so fallback selection is deterministic.
fn cheapest_above_floor(class: WorkClass, catalogue: &dyn ModelCatalogue) -> Option<ModelGrades> {
    let floor = classify::floor_for(class);
    catalogue
        .models()
        .into_iter()
        .filter(|model| classify::meets(model, &floor).ok)
        .min_by(|a, b| a.cheapness().cmp(&b.cheapness()).then_with(|| a.model.cmp(&b.model)))
        .cloned()
}

/// Choose the model for a role (T-MDL-04).
///
/// Precedence: a non-empty user pin, then an upgrade request, then the role
/// default, then a fallback. A pin wins even when an upgrade is also present,
/// and an empty pin is ignored. Pins and upgrades must be available and clear
/// the role's work-class floor; otherwise the result is `zero.pol.denied`
/// (floor) or `zero.fnd.not_found` (unknown model). An upgrade additionally
/// needs `budget_ok` (`zero.pol.ask` when missing) and a non-empty reason
/// (`zero.pol.denied` when empty). The role default is used when it is
/// available and clears the floor; otherwise the cheapest available model that
/// clears the floor is recorded as [`RoleSource::Fallback`], and when no model
/// clears the floor the result is `zero.fnd.unavailable`.
pub fn assign(
    role: Role,
    table: &RoleTable,
    user_pin: Option<&str>,
    upgrade: Option<UpgradeRequest>,
    catalogue: &dyn ModelCatalogue,
) -> Result<RoleAssignment> {
    let default = resolve(role, table)?;
    let class = role.work_class();

    if let Some(pin) = user_pin.map(str::trim).filter(|pin| !pin.is_empty()) {
        check_floor(role, pin, "user pin", catalogue)?;
        return Ok(RoleAssignment {
            role,
            model: pin.to_owned(),
            source: RoleSource::UserPinned,
            reason: format!(
                "user pin {pin} wins over the {} default {}; the model clears the {} floor",
                role.as_str(),
                default.model,
                class.as_str()
            ),
        });
    }

    if let Some(request) = upgrade {
        let model = request.model.trim();
        if model.is_empty() {
            return Err(ZeroError::new(
                ErrorCode::InvalidInput,
                format!("upgrade request for role {} has an empty model id", role.as_str()),
            ));
        }
        if !request.budget_ok {
            return Err(ZeroError::new(
                ErrorCode::PolicyAskRequired,
                format!(
                    "upgrade to model {model:?} for role {} needs budget approval",
                    role.as_str()
                ),
            ));
        }
        if request.reason.trim().is_empty() {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                format!(
                    "upgrade to model {model:?} for role {} needs a non-empty reason",
                    role.as_str()
                ),
            ));
        }
        check_floor(role, model, "upgrade", catalogue)?;
        return Ok(RoleAssignment {
            role,
            model: model.to_owned(),
            source: RoleSource::UpgradeRequested,
            reason: format!(
                "upgrade to {model} approved within budget with a recorded reason; the model clears the {} floor",
                class.as_str()
            ),
        });
    }

    match catalogue.grades(&default.model) {
        Some(grades) if classify::meets(&grades, &classify::floor_for(class)).ok => {
            Ok(RoleAssignment {
                role,
                model: default.model.clone(),
                source: RoleSource::Default,
                reason: format!("role {} uses its default model {}", role.as_str(), default.model),
            })
        }
        Some(_) => fallback(role, default, class, catalogue, "is below the role floor"),
        None => fallback(role, default, class, catalogue, "is unavailable"),
    }
}

fn fallback(
    role: Role,
    default: &RoleDefault,
    class: WorkClass,
    catalogue: &dyn ModelCatalogue,
    cause: &str,
) -> Result<RoleAssignment> {
    match cheapest_above_floor(class, catalogue) {
        Some(model) => Ok(RoleAssignment {
            role,
            model: model.model.clone(),
            source: RoleSource::Fallback,
            reason: format!(
                "role {} default {} {cause}; fallback {} clears the {} floor",
                role.as_str(),
                default.model,
                model.model,
                class.as_str()
            ),
        }),
        None => Err(ZeroError::new(
            ErrorCode::Unavailable,
            format!(
                "role {} default {} {cause} and no available model clears the {} floor",
                role.as_str(),
                default.model,
                class.as_str()
            ),
        )),
    }
}

/// The role's default model first, then every available model that clears the
/// role's floor, cheapest first (ties by model id).
///
/// These are the models the scheduler may approve as an upgrade. Listing a
/// candidate is not permission: [`assign`] still requires budget approval and a
/// reason, and still enforces the floor. The configured default is always
/// listed first, even when it is currently unavailable, so callers can show
/// what the role is supposed to use.
pub fn role_candidates(
    role: Role,
    table: &RoleTable,
    catalogue: &dyn ModelCatalogue,
) -> Result<Vec<String>> {
    let default = resolve(role, table)?;
    let floor = classify::floor_for(role.work_class());
    let mut upgrades: Vec<&ModelGrades> = catalogue
        .models()
        .into_iter()
        .filter(|model| model.model != default.model && classify::meets(model, &floor).ok)
        .collect();
    upgrades.sort_by(|a, b| a.cheapness().cmp(&b.cheapness()).then_with(|| a.model.cmp(&b.model)));

    let mut candidates = Vec::with_capacity(upgrades.len() + 1);
    candidates.push(default.model.clone());
    candidates.extend(upgrades.into_iter().map(|model| model.model.clone()));
    Ok(candidates)
}

/// Assign a role and attach the classifier floor for the role's work class.
///
/// The classification carries deterministic reasons: the role-to-class mapping,
/// the assignment reason (pin, upgrade, default, or fallback), and the fact that
/// the chosen model clears the class floor. This is the classifier tie-in: a
/// role assignment can never be below the floor that [`classify::choose`] would
/// enforce for the same work.
pub fn pick(
    role: Role,
    table: &RoleTable,
    request: &RoleRequest,
    catalogue: &dyn ModelCatalogue,
) -> Result<(RoleAssignment, Classification)> {
    let class = role.work_class();
    let floor = classify::floor_for(class);
    let assignment =
        assign(role, table, request.user_pin.as_deref(), request.upgrade.clone(), catalogue)?;

    let mut reasons = vec![
        format!("role {} maps to work class {}", role.as_str(), class.as_str()),
        assignment.reason.clone(),
    ];
    if let Some(grades) = catalogue.grades(&assignment.model) {
        if classify::meets(&grades, &floor).ok {
            reasons.push(format!(
                "model {} clears the {} floor",
                assignment.model,
                class.as_str()
            ));
        }
    }

    Ok((assignment, Classification { class, reasons, floor }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::classify::{Capability, Grade};

    fn at_class_floor(name: &str, class: WorkClass) -> ModelGrades {
        ModelGrades { model: name.to_owned(), grades: classify::floor_for(class).minimums }
    }

    fn at_floor(name: &str, role: Role) -> ModelGrades {
        at_class_floor(name, role.work_class())
    }

    fn pool(entries: &[ModelGrades]) -> BTreeMap<String, ModelGrades> {
        entries.iter().map(|model| (model.model.clone(), model.clone())).collect()
    }

    /// The seeded table with each default graded at the floor of every role it
    /// serves (two roles may share one model id).
    fn seeded_pool() -> BTreeMap<String, ModelGrades> {
        let table = RoleTable::default();
        let mut pool: BTreeMap<String, ModelGrades> = BTreeMap::new();
        for default in table.defaults.values() {
            let floor = classify::floor_for(default.role.work_class());
            let entry = pool
                .entry(default.model.clone())
                .or_insert_with(|| ModelGrades { model: default.model.clone(), grades: BTreeMap::new() });
            for (capability, grade) in floor.minimums {
                let slot = entry.grades.entry(capability).or_insert(Grade::MIN);
                if *slot < grade {
                    *slot = grade;
                }
            }
        }
        pool
    }

    fn upgrade(model: &str, reason: &str, budget_ok: bool) -> UpgradeRequest {
        UpgradeRequest { model: model.to_owned(), reason: reason.to_owned(), budget_ok }
    }

    #[test]
    fn every_role_maps_to_a_work_class_and_parses() {
        let cases = [
            (Role::Planner, WorkClass::Plan),
            (Role::Coder, WorkClass::Edit),
            (Role::Reviewer, WorkClass::Review),
            (Role::Tester, WorkClass::Test),
            (Role::Researcher, WorkClass::Research),
            (Role::Vision, WorkClass::VisualInspection),
        ];
        assert_eq!(cases.len(), Role::ALL.len());
        for (role, class) in cases {
            assert_eq!(role.work_class(), class, "{role}");
            assert_eq!(Role::parse(role.as_str()).unwrap(), role);
        }

        assert_eq!(Role::parse(" Planner ").unwrap(), Role::Planner);
        assert_eq!(Role::parse("VISION").unwrap(), Role::Vision);
        assert_eq!("coder".parse::<Role>().unwrap(), Role::Coder);
        assert_eq!(Role::Coder.to_string(), "coder");
    }

    #[test]
    fn every_seeded_role_resolves_and_uses_its_default() {
        let table = RoleTable::default();
        let catalogue = seeded_pool();
        assert_eq!(table.defaults.len(), Role::ALL.len(), "one default per role");

        for role in Role::ALL {
            let default = resolve(role, &table).expect("seeded role resolves");
            assert_eq!(default.role, role);
            assert!(!default.model.is_empty());
            assert!(default.provider.is_some(), "{role} needs a provider");
            assert!(!default.reason.is_empty(), "{role} needs a documented reason");

            let assignment = assign(role, &table, None, None, &catalogue).expect("default assignment");
            assert_eq!(assignment.model, default.model, "{role} subagent default");
            assert_eq!(assignment.source, RoleSource::Default);
            assert_eq!(
                assignment.reason,
                format!("role {} uses its default model {}", role.as_str(), default.model)
            );
        }
    }

    #[test]
    fn missing_role_is_a_typed_not_found_listing_available_roles() {
        let table = RoleTable { defaults: BTreeMap::new() };
        let error = resolve(Role::Coder, &table).expect_err("an empty table has no coder");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert!(error.message().contains("coder"), "{}", error.message());
        assert!(error.message().contains("none"), "{}", error.message());

        let partial = RoleTable { defaults: BTreeMap::new() }.with_default(RoleDefault {
            role: Role::Vision,
            model: "vision-only".to_owned(),
            provider: None,
            reason: "test fixture".to_owned(),
        });
        let error = resolve(Role::Planner, &partial).expect_err("planner is missing");
        assert_eq!(error.code(), ErrorCode::NotFound);
        assert!(error.message().contains("vision"), "{}", error.message());
        assert!(!error.message().contains("coder"), "{}", error.message());

        let error = assign(Role::Planner, &partial, None, None, &pool(&[]))
            .expect_err("assign cannot invent a missing role");
        assert_eq!(error.code(), ErrorCode::NotFound);
    }

    #[test]
    fn user_pin_wins_over_default_and_upgrade() {
        let table = RoleTable::default();
        let mut catalogue = seeded_pool();
        catalogue.insert("pinned-coder".to_owned(), at_floor("pinned-coder", Role::Coder));
        catalogue.insert("upgrade-coder".to_owned(), at_floor("upgrade-coder", Role::Coder));

        let assignment = assign(
            Role::Coder,
            &table,
            Some("pinned-coder"),
            Some(upgrade("upgrade-coder", "needs a stronger model", true)),
            &catalogue,
        )
        .expect("pin is valid");
        assert_eq!(assignment.model, "pinned-coder");
        assert_eq!(assignment.source, RoleSource::UserPinned);
        assert!(assignment.reason.contains("wins over the coder default"));
    }

    #[test]
    fn pin_below_the_role_floor_is_refused() {
        let table = RoleTable::default();
        let mut weak = at_floor("weak-coder", Role::Coder);
        weak.grades.insert(Capability::Coding, Grade::new(1));
        weak.grades.insert(Capability::ToolUse, Grade::new(1));
        let catalogue = pool(&[weak]);

        let error = assign(Role::Coder, &table, Some("weak-coder"), None, &catalogue)
            .expect_err("a weak pin must not clear the edit floor");
        assert_eq!(error.code(), ErrorCode::PolicyDenied);
        assert!(error.message().contains("edit"), "{}", error.message());
        assert!(error.message().contains("coding>=4"), "{}", error.message());
        assert!(error.message().contains("tool_use>=4"), "{}", error.message());
    }

    #[test]
    fn security_and_destructive_floors_survive_a_pin_like_request() {
        for class in [WorkClass::Security, WorkClass::Destructive] {
            let strong = at_class_floor("strong", class);
            enforce_floor(class, "strong", "user pin", &pool(&[strong]))
                .expect("a model at the class floor is allowed");

            let mut weak = at_class_floor("weak", class);
            weak.grades.insert(Capability::Reasoning, Grade::new(4));
            let error = enforce_floor(class, "weak", "user pin", &pool(&[weak]))
                .expect_err("a below-floor model is refused");
            assert_eq!(error.code(), ErrorCode::PolicyDenied);
            assert!(error.message().contains(class.as_str()), "{}", error.message());
            assert!(error.message().contains("reasoning>=5"), "{}", error.message());
        }
    }

    #[test]
    fn upgrade_with_budget_and_reason_is_accepted() {
        let table = RoleTable::default();
        let mut catalogue = seeded_pool();
        catalogue.insert("strong-coder".to_owned(), at_floor("strong-coder", Role::Coder));

        let assignment = assign(
            Role::Coder,
            &table,
            None,
            Some(upgrade("strong-coder", "default failed the last two edits", true)),
            &catalogue,
        )
        .expect("a budgeted, reasoned upgrade is allowed");
        assert_eq!(assignment.model, "strong-coder");
        assert_eq!(assignment.source, RoleSource::UpgradeRequested);
        assert!(assignment.reason.contains("approved within budget"));
    }

    #[test]
    fn upgrade_without_budget_or_reason_is_refused() {
        let table = RoleTable::default();
        let mut catalogue = seeded_pool();
        catalogue.insert("strong-coder".to_owned(), at_floor("strong-coder", Role::Coder));

        let no_budget = assign(
            Role::Coder,
            &table,
            None,
            Some(upgrade("strong-coder", "needs a stronger model", false)),
            &catalogue,
        )
        .expect_err("budget approval is required");
        assert_eq!(no_budget.code(), ErrorCode::PolicyAskRequired);

        let empty_reason = assign(
            Role::Coder,
            &table,
            None,
            Some(upgrade("strong-coder", "   ", true)),
            &catalogue,
        )
        .expect_err("a reason is required");
        assert_eq!(empty_reason.code(), ErrorCode::PolicyDenied);

        let mut weak = at_floor("weak-upgrade", Role::Coder);
        weak.grades.insert(Capability::Coding, Grade::new(2));
        let mut weak_catalogue = catalogue.clone();
        weak_catalogue.insert("weak-upgrade".to_owned(), weak);
        let below_floor = assign(
            Role::Coder,
            &table,
            None,
            Some(upgrade("weak-upgrade", "cheaper but weaker", true)),
            &weak_catalogue,
        )
        .expect_err("an upgrade cannot undercut the floor");
        assert_eq!(below_floor.code(), ErrorCode::PolicyDenied);
        assert!(below_floor.message().contains("coding>=4"), "{}", below_floor.message());
    }

    #[test]
    fn fallback_used_only_when_the_default_is_unavailable() {
        let table = RoleTable::default();
        let default = resolve(Role::Planner, &table).expect("seeded planner");
        let catalogue = pool(&[at_floor("fallback-planner", Role::Planner)]);

        let assignment = assign(Role::Planner, &table, None, None, &catalogue)
            .expect("a clearing fallback is available");
        assert_eq!(assignment.model, "fallback-planner");
        assert_eq!(assignment.source, RoleSource::Fallback);
        assert!(
            assignment.reason.contains(&format!("default {} is unavailable", default.model)),
            "{}",
            assignment.reason
        );

        let mut weak = at_floor("weak-planner", Role::Planner);
        weak.grades.insert(Capability::Reasoning, Grade::new(1));
        let error = assign(Role::Planner, &table, None, None, &pool(&[weak]))
            .expect_err("no model clears the plan floor");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("plan"), "{}", error.message());
    }

    #[test]
    fn a_default_below_the_floor_is_not_used() {
        let table = RoleTable::default();
        let default = resolve(Role::Tester, &table).expect("seeded tester");
        let mut weak = at_floor(&default.model, Role::Tester);
        weak.grades.insert(Capability::ToolUse, Grade::new(1));
        let catalogue = pool(&[weak, at_floor("fallback-tester", Role::Tester)]);

        let assignment = assign(Role::Tester, &table, None, None, &catalogue).expect("fallback works");
        assert_eq!(assignment.model, "fallback-tester");
        assert_eq!(assignment.source, RoleSource::Fallback);
        assert!(assignment.reason.contains("below the role floor"), "{}", assignment.reason);
    }

    #[test]
    fn role_candidates_list_the_default_then_permitted_upgrades() {
        let table = RoleTable::default();
        let default = resolve(Role::Coder, &table).expect("seeded coder");
        let mut weak = at_floor("below-coder", Role::Coder);
        weak.grades.insert(Capability::Coding, Grade::new(1));
        let expensive = ModelGrades {
            model: "zzz-expensive".to_owned(),
            grades: Capability::ALL.iter().map(|capability| (*capability, Grade::MAX)).collect(),
        };
        let catalogue = pool(&[weak, expensive, at_floor("aaa-extra", Role::Coder)]);

        let candidates = role_candidates(Role::Coder, &table, &catalogue).expect("coder resolves");
        assert_eq!(candidates.first(), Some(&default.model));
        assert_eq!(candidates, vec![default.model.clone(), "aaa-extra".to_owned(), "zzz-expensive".to_owned()]);
        assert!(!candidates.iter().any(|model| model == "below-coder"));
    }

    #[test]
    fn pick_ties_the_assignment_to_the_classifier_floor() {
        let table = RoleTable::default();
        let catalogue = seeded_pool();
        let request = RoleRequest::default();

        let (assignment, classification) =
            pick(Role::Coder, &table, &request, &catalogue).expect("default pick");
        assert_eq!(assignment.source, RoleSource::Default);
        assert_eq!(classification.class, WorkClass::Edit);
        assert_eq!(classification.floor, classify::floor_for(WorkClass::Edit));
        assert!(
            classification.reasons.contains(&"role coder maps to work class edit".to_owned()),
            "{:?}",
            classification.reasons
        );
        assert!(
            classification
                .reasons
                .contains(&format!("model {} clears the edit floor", assignment.model)),
            "{:?}",
            classification.reasons
        );
    }

    #[test]
    fn role_table_round_trips_through_json() {
        assert_eq!(serde_json::to_string(&Role::Planner).unwrap(), "\"planner\"");
        assert_eq!(RoleSource::UpgradeRequested.as_str(), "upgrade_requested");
        assert_eq!(serde_json::to_string(&RoleSource::UpgradeRequested).unwrap(), "\"upgrade_requested\"");

        let table = RoleTable::default();
        let encoded = serde_json::to_string(&table).expect("roles are string map keys");
        let decoded: RoleTable = serde_json::from_str(&encoded).expect("round trip");
        assert_eq!(decoded, table);
    }

    #[test]
    fn reasons_are_deterministic() {
        let table = RoleTable::default();
        let catalogue = seeded_pool();
        let request = RoleRequest::default();

        let first = pick(Role::Reviewer, &table, &request, &catalogue).expect("first pick");
        let second = pick(Role::Reviewer, &table, &request, &catalogue).expect("second pick");
        assert_eq!(first, second);

        let first_candidates = role_candidates(Role::Reviewer, &table, &catalogue).expect("candidates");
        let second_candidates = role_candidates(Role::Reviewer, &table, &catalogue).expect("candidates");
        assert_eq!(first_candidates, second_candidates);

        let error = assign(Role::Vision, &table, Some("missing-vision"), None, &catalogue)
            .expect_err("unknown pin");
        let again = assign(Role::Vision, &table, Some("missing-vision"), None, &catalogue)
            .expect_err("unknown pin");
        assert_eq!(error, again);

        assert_eq!(Role::parse("architect").unwrap_err(), Role::parse("architect").unwrap_err());
        assert_eq!(Role::parse("architect").unwrap_err().code(), ErrorCode::NotFound);
    }
}
