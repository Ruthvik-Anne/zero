//! Work classification and capability floors (MDL-02, MDL-03).
//!
//! [`classify`] turns [`TaskSignals`] into a [`WorkClass`] with a deterministic
//! list of reasons and the class's [`CapabilityFloor`]. Security and destructive
//! signals outrank every other class, so a task that touches secrets or cannot be
//! undone can never be routed as an ordinary edit or plan.
//!
//! [`choose`] picks the cheapest candidate whose grades clear the floor. The
//! floor is a hard minimum for every class. An explicit downgrade request is
//! honoured only for classes with `may_downgrade = true`; `Security` and
//! `Destructive` refuse it with `zero.pol.denied`, naming the class and the
//! capability that would be lost. No prompt text is ever placed in an error or
//! in a reason: reasons name signals, fixed keywords, capabilities, and models
//! only.
//!
//! The full matrix, the floor table, and the downgrade policy live in
//! `docs/routing.md`.

use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use zero_types::error::{ErrorCode, Result, ZeroError};

/// What the work is, for routing purposes (MDL-02).
///
/// The declaration order is the documented priority order except that
/// `Security` and `Destructive` always win over the rest (see [`classify`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WorkClass {
    /// Design, decomposition, and analysis without edits.
    Plan,
    /// Change code or files.
    Edit,
    /// Read-only examination of existing work.
    Review,
    /// Write or run tests.
    Test,
    /// Gather and compare external or internal information.
    Research,
    /// Condense material into a shorter form.
    Summarize,
    /// Look at an image, screenshot, or rendered UI.
    VisualInspection,
    /// Security-sensitive work: secrets, credentials, auth, vulnerabilities.
    Security,
    /// Irreversible or destructive work.
    Destructive,
}

impl WorkClass {
    /// Every class, in declaration order.
    pub const ALL: [WorkClass; 9] = [
        WorkClass::Plan,
        WorkClass::Edit,
        WorkClass::Review,
        WorkClass::Test,
        WorkClass::Research,
        WorkClass::Summarize,
        WorkClass::VisualInspection,
        WorkClass::Security,
        WorkClass::Destructive,
    ];

    /// Stable snake-case label used in reasons, errors, and stored data.
    pub const fn as_str(self) -> &'static str {
        match self {
            WorkClass::Plan => "plan",
            WorkClass::Edit => "edit",
            WorkClass::Review => "review",
            WorkClass::Test => "test",
            WorkClass::Research => "research",
            WorkClass::Summarize => "summarize",
            WorkClass::VisualInspection => "visual_inspection",
            WorkClass::Security => "security",
            WorkClass::Destructive => "destructive",
        }
    }
}

/// The capability axes a model is graded on (MDL-01).
///
/// Higher is better on every axis. For [`Capability::Latency`] a higher grade
/// means a more responsive model, so a latency floor is a responsiveness floor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Capability {
    Coding,
    Reasoning,
    InstructionFollowing,
    ToolUse,
    Vision,
    LongContext,
    Latency,
}

impl Capability {
    /// Every capability, in declaration order (also the tie-break order).
    pub const ALL: [Capability; 7] = [
        Capability::Coding,
        Capability::Reasoning,
        Capability::InstructionFollowing,
        Capability::ToolUse,
        Capability::Vision,
        Capability::LongContext,
        Capability::Latency,
    ];

    /// Stable snake-case label used in reasons and errors.
    pub const fn as_str(self) -> &'static str {
        match self {
            Capability::Coding => "coding",
            Capability::Reasoning => "reasoning",
            Capability::InstructionFollowing => "instruction_following",
            Capability::ToolUse => "tool_use",
            Capability::Vision => "vision",
            Capability::LongContext => "long_context",
            Capability::Latency => "latency",
        }
    }
}

/// A capability grade on a closed 0..=5 scale.
///
/// [`Grade::new`] clamps out-of-range input. A capability that a model does not
/// declare is treated as [`Grade::MIN`], which is the fail-closed value.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct Grade(u8);

impl Grade {
    /// The lowest grade. Undeclared capabilities are graded this value.
    pub const MIN: Grade = Grade(0);

    /// The highest grade.
    pub const MAX: Grade = Grade(5);

    /// Construct a grade, clamping to the documented 0..=5 range.
    pub const fn new(value: u8) -> Self {
        if value > 5 {
            Grade(5)
        } else {
            Grade(value)
        }
    }

    /// The raw value in 0..=5.
    pub const fn get(self) -> u8 {
        self.0
    }
}

impl From<u8> for Grade {
    fn from(value: u8) -> Self {
        Grade::new(value)
    }
}

/// The minimum grades a work class needs, plus its downgrade policy.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapabilityFloor {
    /// Required grade per capability. A capability absent from the map requires
    /// nothing.
    pub minimums: BTreeMap<Capability, Grade>,
    /// Whether an explicit request may route below this floor. Always `false`
    /// for `Security` and `Destructive`.
    pub may_downgrade: bool,
}

impl CapabilityFloor {
    /// The required grade for one capability; zero when not specified.
    pub fn minimum(&self, capability: Capability) -> Grade {
        self.minimums.get(&capability).copied().unwrap_or(Grade::MIN)
    }
}

/// Build a floor from a compact table.
fn floor(may_downgrade: bool, minimums: &[(Capability, u8)]) -> CapabilityFloor {
    CapabilityFloor {
        minimums: minimums.iter().map(|(capability, grade)| (*capability, Grade::new(*grade))).collect(),
        may_downgrade,
    }
}

/// The documented floor for a work class.
///
/// Every class except `Security` and `Destructive` permits an explicit,
/// recorded downgrade. `Security` requires the top reasoning and instruction
/// grades; `Destructive` adds the top tool-use grade because the action is
/// irreversible.
pub fn floor_for(class: WorkClass) -> CapabilityFloor {
    use Capability::{
        Coding, InstructionFollowing, Latency, LongContext, Reasoning, ToolUse, Vision,
    };
    match class {
        WorkClass::Plan => floor(
            true,
            &[
                (Coding, 3),
                (Reasoning, 4),
                (InstructionFollowing, 4),
                (ToolUse, 2),
                (LongContext, 3),
                (Latency, 2),
            ],
        ),
        WorkClass::Edit => floor(
            true,
            &[
                (Coding, 4),
                (Reasoning, 3),
                (InstructionFollowing, 4),
                (ToolUse, 4),
                (LongContext, 2),
                (Latency, 2),
            ],
        ),
        WorkClass::Review => floor(
            true,
            &[
                (Coding, 4),
                (Reasoning, 4),
                (InstructionFollowing, 3),
                (LongContext, 4),
                (Latency, 2),
            ],
        ),
        WorkClass::Test => floor(
            true,
            &[
                (Coding, 4),
                (Reasoning, 3),
                (InstructionFollowing, 3),
                (ToolUse, 4),
                (Latency, 2),
            ],
        ),
        WorkClass::Research => floor(
            true,
            &[
                (Coding, 2),
                (Reasoning, 3),
                (InstructionFollowing, 3),
                (ToolUse, 4),
                (LongContext, 4),
                (Latency, 2),
            ],
        ),
        WorkClass::Summarize => floor(
            true,
            &[
                (Coding, 2),
                (Reasoning, 2),
                (InstructionFollowing, 3),
                (LongContext, 4),
                (Latency, 4),
            ],
        ),
        WorkClass::VisualInspection => floor(
            true,
            &[
                (Coding, 2),
                (Reasoning, 3),
                (InstructionFollowing, 3),
                (Vision, 4),
                (LongContext, 2),
                (Latency, 2),
            ],
        ),
        WorkClass::Security => floor(
            false,
            &[
                (Coding, 4),
                (Reasoning, 5),
                (InstructionFollowing, 5),
                (ToolUse, 4),
                (LongContext, 3),
                (Latency, 2),
            ],
        ),
        WorkClass::Destructive => floor(
            false,
            &[
                (Coding, 4),
                (Reasoning, 5),
                (InstructionFollowing, 5),
                (ToolUse, 5),
                (LongContext, 2),
                (Latency, 2),
            ],
        ),
    }
}

/// Signals the caller already knows about a task.
///
/// The boolean flags are authoritative: the classifier never inspects the
/// environment, the filesystem, or the network. `text` is only matched against
/// fixed keyword tables, and matched keywords (never the text itself) end up in
/// the reasons.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct TaskSignals {
    /// The user's request text. Used for keyword fallback only.
    pub text: String,
    /// The task reads, writes, or moves secrets.
    pub touches_secrets: bool,
    /// The task runs shell commands.
    pub touches_shell: bool,
    /// The task makes network requests.
    pub touches_network: bool,
    /// The task cannot be undone (delete, overwrite in place, force push).
    pub irreversible: bool,
    /// How many files the task is expected to change.
    pub files_changed: u32,
    /// Images, screenshots, or rendered UI are part of the input.
    pub has_images: bool,
    /// The request explicitly asks for a plan.
    pub asks_for_plan: bool,
    /// The request explicitly asks for a review.
    pub asks_for_review: bool,
    /// The request explicitly asks for tests.
    pub asks_for_tests: bool,
}

/// A class, the reasons it was chosen, and the floor that follows from it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Classification {
    pub class: WorkClass,
    /// Deterministic, ordered explanations. Contains no prompt text.
    pub reasons: Vec<String>,
    pub floor: CapabilityFloor,
}

impl Classification {
    fn note(&mut self, reason: impl Into<String>) {
        self.reasons.push(reason.into());
    }
}

/// Keywords that mark a shell action as destructive. Generic verbs such as
/// "delete" are deliberately absent: `TaskSignals::irreversible` is the
/// authoritative signal, and the keyword table is only a conservative backstop.
const DESTRUCTIVE_KEYWORDS: &[&str] = &[
    "rm -rf",
    "rm -r",
    "remove-item -recurse",
    "del /f",
    "drop table",
    "truncate table",
    "force push",
    "force-push",
    "mkfs",
    "diskpart",
    "purge",
    "wipe",
];

/// Keywords that turn network access into security-sensitive work.
const AUTH_KEYWORDS: &[&str] = &[
    "credential",
    "credentials",
    "api key",
    "api-key",
    "token",
    "password",
    "passwd",
    "secret",
    "oauth",
    "login",
    "sign in",
    "auth",
];

/// Keywords that mark security work even when no flag is set.
const SECURITY_KEYWORDS: &[&str] = &[
    "vulnerability",
    "vulnerabilities",
    "cve",
    "exploit",
    "threat model",
    "penetration test",
    "pentest",
    "security review",
    "security audit",
    "hardening",
    "privilege escalation",
    "sandbox escape",
    "supply chain attack",
];

const PLAN_KEYWORDS: &[&str] = &[
    "plan",
    "design",
    "architecture",
    "approach",
    "break down",
    "breakdown",
    "proposal",
    "spec",
    "specification",
    "strategy",
];

const REVIEW_KEYWORDS: &[&str] = &[
    "review",
    "audit",
    "critique",
    "look over",
    "code review",
    "inspect",
];

const TEST_KEYWORDS: &[&str] = &[
    "test",
    "tests",
    "testing",
    "unit test",
    "integration test",
    "coverage",
    "regression",
];

const VISUAL_KEYWORDS: &[&str] = &[
    "screenshot",
    "image",
    "images",
    "diagram",
    "mockup",
    "rendered ui",
    "visual",
];

const RESEARCH_KEYWORDS: &[&str] = &[
    "research",
    "look up",
    "lookup",
    "find out",
    "search the web",
    "search online",
    "investigate",
    "compare sources",
    "documentation search",
];

const SUMMARIZE_KEYWORDS: &[&str] = &[
    "summarize",
    "summarise",
    "summary",
    "tl;dr",
    "recap",
    "condense",
    "brief me",
];

/// True when `c` continues a word, used for whole-word keyword matching.
fn is_word_char(c: char) -> bool {
    c.is_alphanumeric() || c == '_'
}

/// Whole-word (or whole-phrase) match. This prevents `test` matching `latest`.
fn contains_keyword(text: &str, keyword: &str) -> bool {
    if keyword.is_empty() {
        return false;
    }
    text.match_indices(keyword).any(|(start, _)| {
        let before = text[..start].chars().next_back();
        let after = text[start + keyword.len()..].chars().next();
        !before.is_some_and(is_word_char) && !after.is_some_and(is_word_char)
    })
}

fn first_match(text: &str, keywords: &'static [&'static str]) -> Option<&'static str> {
    keywords.iter().copied().find(|keyword| contains_keyword(text, keyword))
}

fn finish(class: WorkClass, reasons: Vec<String>) -> Classification {
    Classification { class, reasons, floor: floor_for(class) }
}

/// Classify a task (MDL-02).
///
/// Rules, highest priority first:
///
/// 1. `irreversible` → `Destructive`.
/// 2. `touches_shell` plus a destructive keyword → `Destructive`.
/// 3. `touches_secrets` → `Security`.
/// 4. `touches_network` plus an auth keyword → `Security`.
/// 5. A security keyword → `Security`.
/// 6. Explicit asks, in order: plan, review, tests, images.
/// 7. Keyword fallback, in order: plan, review, test, visual, research,
///    summarize.
/// 8. Default: `Edit` when files change or a shell is used, otherwise `Plan`
///    (read-only).
///
/// Shell and network access alone do not raise the class: almost every edit
/// runs a shell, and research legitimately uses the network. They raise only
/// together with the keyword tables above, or through `irreversible` and
/// `touches_secrets`, which are authoritative.
pub fn classify(signals: &TaskSignals) -> Classification {
    let text = signals.text.to_ascii_lowercase();
    let mut reasons = Vec::new();

    if signals.irreversible {
        reasons.push("signal: irreversible".to_owned());
        return finish(WorkClass::Destructive, reasons);
    }
    if signals.touches_shell {
        if let Some(keyword) = first_match(&text, DESTRUCTIVE_KEYWORDS) {
            reasons.push(format!("signal: shell access with destructive keyword {keyword:?}"));
            return finish(WorkClass::Destructive, reasons);
        }
    }
    if signals.touches_secrets {
        reasons.push("signal: touches secrets".to_owned());
        return finish(WorkClass::Security, reasons);
    }
    if signals.touches_network {
        if let Some(keyword) = first_match(&text, AUTH_KEYWORDS) {
            reasons.push(format!("signal: network access with auth keyword {keyword:?}"));
            return finish(WorkClass::Security, reasons);
        }
    }
    if let Some(keyword) = first_match(&text, SECURITY_KEYWORDS) {
        reasons.push(format!("keyword: security keyword {keyword:?}"));
        return finish(WorkClass::Security, reasons);
    }

    if signals.asks_for_plan {
        reasons.push("signal: asks for a plan".to_owned());
        return finish(WorkClass::Plan, reasons);
    }
    if signals.asks_for_review {
        reasons.push("signal: asks for a review".to_owned());
        return finish(WorkClass::Review, reasons);
    }
    if signals.asks_for_tests {
        reasons.push("signal: asks for tests".to_owned());
        return finish(WorkClass::Test, reasons);
    }
    if signals.has_images {
        reasons.push("signal: includes images".to_owned());
        return finish(WorkClass::VisualInspection, reasons);
    }

    let keyword_classes: [(&'static [&'static str], WorkClass); 6] = [
        (PLAN_KEYWORDS, WorkClass::Plan),
        (REVIEW_KEYWORDS, WorkClass::Review),
        (TEST_KEYWORDS, WorkClass::Test),
        (VISUAL_KEYWORDS, WorkClass::VisualInspection),
        (RESEARCH_KEYWORDS, WorkClass::Research),
        (SUMMARIZE_KEYWORDS, WorkClass::Summarize),
    ];
    for (keywords, class) in keyword_classes {
        if let Some(keyword) = first_match(&text, keywords) {
            reasons.push(format!("keyword: {} {keyword:?}", class.as_str()));
            return finish(class, reasons);
        }
    }

    let read_only = signals.files_changed == 0 && !signals.touches_shell;
    if read_only {
        reasons.push("default: read-only task with no matching signal".to_owned());
        finish(WorkClass::Plan, reasons)
    } else {
        reasons.push("default: task changes files or runs a shell".to_owned());
        finish(WorkClass::Edit, reasons)
    }
}

/// A model's declared grades (MDL-01).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelGrades {
    pub model: String,
    /// Declared capability grades. An absent capability is graded zero.
    pub grades: BTreeMap<Capability, Grade>,
}

impl ModelGrades {
    /// The grade for one capability; zero when the model does not declare it.
    pub fn grade(&self, capability: Capability) -> Grade {
        self.grades.get(&capability).copied().unwrap_or(Grade::MIN)
    }

    /// Cost proxy used to pick the cheapest candidate: the sum of every
    /// declared grade. Undeclared capabilities count as zero, so omitting one
    /// cannot help a model pass a floor and can only make it look cheaper on
    /// axes the class does not require.
    pub fn cheapness(&self) -> u32 {
        self.grades.values().map(|grade| u32::from(grade.get())).sum()
    }
}

/// One unmet requirement: capability, required grade, actual grade.
pub type MissingCapability = (Capability, Grade, Grade);

/// The result of checking a model against a floor.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FloorResult {
    pub ok: bool,
    /// Ordered by [`Capability`], so the output is deterministic.
    pub missing: Vec<MissingCapability>,
}

fn meets_required(model: &ModelGrades, required: &BTreeMap<Capability, Grade>) -> FloorResult {
    let mut missing = Vec::new();
    for (capability, required_grade) in required {
        let actual = model.grade(*capability);
        if actual < *required_grade {
            missing.push((*capability, *required_grade, actual));
        }
    }
    FloorResult { ok: missing.is_empty(), missing }
}

/// Check a model against a floor. A capability the model does not declare is
/// graded zero, so it fails any non-zero requirement.
pub fn meets(model: &ModelGrades, floor: &CapabilityFloor) -> FloorResult {
    meets_required(model, &floor.minimums)
}

/// Pick the cheapest candidate that clears the classification's floor (MDL-02).
///
/// `requested_downgrade` is an explicit request to route at no more than that
/// grade. If the request is below the floor:
///
/// - a class with `may_downgrade = false` refuses with `zero.pol.denied`,
///   naming the class and the capability that would be lost, and records the
///   refusal in `classification.reasons`;
/// - any other class accepts the request within policy: the affected
///   requirements are lowered to the requested grade, the relaxation is
///   recorded, and selection continues against the lowered requirements.
///
/// A request at or above the floor changes nothing. Among eligible candidates
/// the lowest [`ModelGrades::cheapness`] wins; equal totals are broken by model
/// name. When nothing is eligible the result is `zero.fnd.unavailable` naming
/// the class and its requirements. Errors never contain task text.
pub fn choose<'a>(
    classification: &mut Classification,
    candidates: &'a [ModelGrades],
    requested_downgrade: Option<Grade>,
) -> Result<&'a ModelGrades> {
    let class = classification.class;
    let may_downgrade = classification.floor.may_downgrade;
    let mut required = classification.floor.minimums.clone();

    if let Some(requested) = requested_downgrade {
        // The capability with the largest requirement above the request. Ties
        // keep the earliest capability in declaration order.
        let mut worst: Option<(Capability, Grade)> = None;
        for (capability, required_grade) in &required {
            if *required_grade > requested {
                let replace = match worst {
                    None => true,
                    Some((_, current)) => *required_grade > current,
                };
                if replace {
                    worst = Some((*capability, *required_grade));
                }
            }
        }
        match worst {
            None => classification.note(format!(
                "requested grade {} is at or above every {} requirement",
                requested.get(),
                class.as_str()
            )),
            Some((capability, required_grade)) if !may_downgrade => {
                classification.note(format!(
                    "downgrade refused: {} requires {} grade {} but grade {} was requested",
                    class.as_str(),
                    capability.as_str(),
                    required_grade.get(),
                    requested.get()
                ));
                return Err(ZeroError::new(
                    ErrorCode::PolicyDenied,
                    format!(
                        "work class {} requires {} grade {}; a downgrade to grade {} is refused",
                        class.as_str(),
                        capability.as_str(),
                        required_grade.get(),
                        requested.get()
                    ),
                ));
            }
            Some(_) => {
                let mut lowered = Vec::new();
                for (capability, grade) in &mut required {
                    if *grade > requested {
                        lowered.push(format!(
                            "{} {}->{}",
                            capability.as_str(),
                            grade.get(),
                            requested.get()
                        ));
                        *grade = requested;
                    }
                }
                classification.note(format!(
                    "downgrade accepted within policy: {} lowered for {}",
                    lowered.join(", "),
                    class.as_str()
                ));
            }
        }
    }

    let selected = candidates
        .iter()
        .filter(|model| meets_required(model, &required).ok)
        .min_by(|a, b| a.cheapness().cmp(&b.cheapness()).then_with(|| a.model.cmp(&b.model)));

    match selected {
        Some(model) => {
            classification.note(format!(
                "selected {} (total grade {}) for work class {}",
                model.model,
                model.cheapness(),
                class.as_str()
            ));
            Ok(model)
        }
        None => {
            let requirements = required
                .iter()
                .map(|(capability, grade)| format!("{}>={}", capability.as_str(), grade.get()))
                .collect::<Vec<_>>()
                .join(", ");
            Err(ZeroError::new(
                ErrorCode::Unavailable,
                format!("no candidate clears the {} floor ({requirements})", class.as_str()),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signals(text: &str) -> TaskSignals {
        TaskSignals { text: text.to_owned(), ..TaskSignals::default() }
    }

    fn model(name: &str, grades: &[(Capability, u8)]) -> ModelGrades {
        ModelGrades {
            model: name.to_owned(),
            grades: grades.iter().map(|(capability, grade)| (*capability, Grade::new(*grade))).collect(),
        }
    }

    fn at_floor(name: &str, class: WorkClass) -> ModelGrades {
        ModelGrades { model: name.to_owned(), grades: floor_for(class).minimums }
    }

    fn with_grade(base: &ModelGrades, capability: Capability, grade: u8) -> ModelGrades {
        let mut copy = base.clone();
        copy.grades.insert(capability, Grade::new(grade));
        copy
    }

    #[test]
    fn every_class_is_reachable_and_carries_its_floor() {
        let cases: Vec<(TaskSignals, WorkClass)> = vec![
            (
                TaskSignals { asks_for_plan: true, ..TaskSignals::default() },
                WorkClass::Plan,
            ),
            (TaskSignals { files_changed: 2, ..TaskSignals::default() }, WorkClass::Edit),
            (
                TaskSignals { asks_for_review: true, ..TaskSignals::default() },
                WorkClass::Review,
            ),
            (
                TaskSignals { asks_for_tests: true, ..TaskSignals::default() },
                WorkClass::Test,
            ),
            (signals("research the crates.io API"), WorkClass::Research),
            (signals("summarize this changelog"), WorkClass::Summarize),
            (TaskSignals { has_images: true, ..TaskSignals::default() }, WorkClass::VisualInspection),
            (TaskSignals { touches_secrets: true, ..TaskSignals::default() }, WorkClass::Security),
            (TaskSignals { irreversible: true, ..TaskSignals::default() }, WorkClass::Destructive),
        ];

        let mut seen = std::collections::BTreeSet::new();
        for (input, expected) in cases {
            let classification = classify(&input);
            assert_eq!(classification.class, expected, "{expected:?}");
            assert_eq!(classification.floor, floor_for(expected));
            assert!(!classification.reasons.is_empty(), "{expected:?} has no reason");
            seen.insert(expected);
        }
        assert_eq!(seen.len(), WorkClass::ALL.len(), "every class is covered");
    }

    #[test]
    fn security_and_destructive_outrank_plan_review_and_edit() {
        let plan_with_secrets = classify(&TaskSignals {
            text: "plan the migration".to_owned(),
            asks_for_plan: true,
            files_changed: 4,
            touches_secrets: true,
            ..TaskSignals::default()
        });
        assert_eq!(plan_with_secrets.class, WorkClass::Security);
        assert!(!plan_with_secrets.floor.may_downgrade);

        let review_with_irreversible = classify(&TaskSignals {
            text: "review the schema and delete the old table".to_owned(),
            asks_for_review: true,
            asks_for_tests: true,
            touches_shell: true,
            irreversible: true,
            ..TaskSignals::default()
        });
        assert_eq!(review_with_irreversible.class, WorkClass::Destructive);
        assert!(!review_with_irreversible.floor.may_downgrade);

        let edit_with_network_auth = classify(&TaskSignals {
            text: "refresh the oauth token for the client".to_owned(),
            files_changed: 1,
            touches_network: true,
            ..TaskSignals::default()
        });
        assert_eq!(edit_with_network_auth.class, WorkClass::Security);

        let destructive_shell = classify(&TaskSignals {
            text: "run rm -rf build".to_owned(),
            files_changed: 1,
            touches_shell: true,
            ..TaskSignals::default()
        });
        assert_eq!(destructive_shell.class, WorkClass::Destructive);
    }

    #[test]
    fn explicit_asks_beat_keywords_and_keywords_beat_the_default() {
        let ask_beats_keyword = classify(&TaskSignals {
            text: "review the plan and add a test".to_owned(),
            asks_for_tests: true,
            ..TaskSignals::default()
        });
        assert_eq!(ask_beats_keyword.class, WorkClass::Test);
        assert_eq!(ask_beats_keyword.reasons, vec!["signal: asks for tests".to_owned()]);

        let keyword = classify(&signals("review this module for correctness"));
        assert_eq!(keyword.class, WorkClass::Review);

        let read_only_default = classify(&signals("what does this function return?"));
        assert_eq!(read_only_default.class, WorkClass::Plan);
        assert!(read_only_default.reasons[0].starts_with("default: read-only"));

        let edit_default = classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() });
        assert_eq!(edit_default.class, WorkClass::Edit);
        assert!(edit_default.reasons[0].starts_with("default: task changes files"));

        let shell_default = classify(&TaskSignals { touches_shell: true, ..TaskSignals::default() });
        assert_eq!(shell_default.class, WorkClass::Edit);
    }

    #[test]
    fn keywords_match_whole_words_not_substrings() {
        // "latest" contains "test" but is not the word "test".
        let classification = classify(&signals("read the latest release notes"));
        assert_eq!(classification.class, WorkClass::Plan);
        assert!(classification.reasons[0].starts_with("default: read-only"));
    }

    #[test]
    fn security_keywords_and_network_auth_raise_to_security() {
        let vulnerability = classify(&signals("check this dependency for a known cve"));
        assert_eq!(vulnerability.class, WorkClass::Security);
        assert!(vulnerability.reasons[0].starts_with("keyword: security keyword"));

        let network_without_auth = classify(&TaskSignals {
            text: "fetch the changelog".to_owned(),
            touches_network: true,
            ..TaskSignals::default()
        });
        assert_eq!(network_without_auth.class, WorkClass::Plan);
    }

    #[test]
    fn meets_reports_every_missing_capability_and_unknown_is_zero() {
        let empty = model("empty", &[]);
        assert_eq!(empty.grade(Capability::Vision), Grade::MIN);

        let floor = floor_for(WorkClass::Security);
        let result = meets(&empty, &floor);
        assert!(!result.ok);
        assert_eq!(result.missing.len(), floor.minimums.len());
        let vision = (Capability::Vision, Grade::new(4), Grade::MIN);
        let floor_with_vision =
            CapabilityFloor { minimums: [(Capability::Vision, Grade::new(4))].into(), may_downgrade: true };
        assert_eq!(meets(&empty, &floor_with_vision).missing, vec![vision]);

        let capable = at_floor("capable", WorkClass::Security);
        assert_eq!(meets(&capable, &floor), FloorResult { ok: true, missing: Vec::new() });

        let short = with_grade(&capable, Capability::Reasoning, 4);
        let result = meets(&short, &floor);
        assert!(!result.ok);
        assert_eq!(
            result.missing,
            vec![(Capability::Reasoning, Grade::new(5), Grade::new(4))]
        );
    }

    #[test]
    fn security_and_destructive_refuse_a_downgrade_even_when_asked() {
        let text = "TOP-SECRET-PLACEHOLDER-abc123";
        for (input, class) in [
            (
                TaskSignals { text: text.to_owned(), irreversible: true, ..TaskSignals::default() },
                WorkClass::Destructive,
            ),
            (
                TaskSignals { text: text.to_owned(), touches_secrets: true, ..TaskSignals::default() },
                WorkClass::Security,
            ),
        ] {
            // Even a near-floor request is refused: Security and Destructive
            // require Reasoning and ToolUse at grade 5.
            for request in [Grade::MIN, Grade::new(4)] {
                let mut classification = classify(&input);
                assert_eq!(classification.class, class);
                let candidates = vec![at_floor("top-tier", class)];
                let error = choose(&mut classification, &candidates, Some(request))
                    .expect_err("a security floor must not downgrade");
                assert_eq!(error.code(), ErrorCode::PolicyDenied);
                assert!(error.message().contains(class.as_str()), "{}", error.message());
                assert!(error.message().contains("grade 5"), "{}", error.message());
                assert!(!error.message().contains(text), "error leaked task text");
                assert!(
                    classification
                        .reasons
                        .iter()
                        .any(|reason| reason.starts_with("downgrade refused")),
                    "{:?}",
                    classification.reasons
                );
                assert!(classification.reasons.iter().all(|reason| !reason.contains(text)));
            }
        }
    }

    #[test]
    fn non_security_classes_downgrade_only_within_policy() {
        let mut classification = classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() });
        assert_eq!(classification.class, WorkClass::Edit);
        assert!(classification.floor.may_downgrade);

        let downgraded = model(
            "downgraded",
            &[
                (Capability::Coding, 2),
                (Capability::Reasoning, 2),
                (Capability::InstructionFollowing, 2),
                (Capability::ToolUse, 2),
                (Capability::LongContext, 2),
                (Capability::Latency, 2),
            ],
        );

        // Without the request the candidate is below the Edit floor.
        let mut strict = classification.clone();
        let error = choose(&mut strict, std::slice::from_ref(&downgraded), None)
            .expect_err("a grade-2 model is below the Edit floor");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("edit"), "{}", error.message());
        assert!(error.message().contains("coding>=4"), "{}", error.message());

        // The explicit request lowers the requirement and is recorded.
        let selected = choose(&mut classification, std::slice::from_ref(&downgraded), Some(Grade::new(2)))
            .expect("Edit permits a recorded downgrade");
        assert_eq!(selected.model, "downgraded");
        assert!(
            classification
                .reasons
                .iter()
                .any(|reason| reason.starts_with("downgrade accepted within policy")),
            "{:?}",
            classification.reasons
        );

        // A request at or above the floor changes nothing.
        let mut high_request = classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() });
        let candidates = vec![at_floor("at-floor", WorkClass::Edit)];
        choose(&mut high_request, &candidates, Some(Grade::MAX)).expect("grade 5 is not a downgrade");
        assert!(
            high_request
                .reasons
                .iter()
                .any(|reason| reason.starts_with("requested grade 5 is at or above")),
            "{:?}",
            high_request.reasons
        );
    }

    #[test]
    fn the_cheapest_model_above_the_floor_is_selected() {
        let base = at_floor("base", WorkClass::Edit);
        let expensive = model(
            "expensive",
            &Capability::ALL
                .iter()
                .map(|capability| (*capability, 5_u8))
                .collect::<Vec<_>>(),
        );
        let below = with_grade(&base, Capability::Coding, 3);
        let tie_a = ModelGrades { model: "aaa-cheap".to_owned(), grades: base.grades.clone() };
        let tie_b = ModelGrades { model: "zzz-cheap".to_owned(), grades: base.grades.clone() };
        let candidates = vec![expensive.clone(), below, tie_b, tie_a];

        let mut classification = classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() });
        let selected = choose(&mut classification, &candidates, None).expect("a candidate clears the floor");
        assert_eq!(selected.model, "aaa-cheap");
        assert!(
            classification
                .reasons
                .iter()
                .any(|reason| reason == "selected aaa-cheap (total grade 19) for work class edit"),
            "{:?}",
            classification.reasons
        );

        let only_expensive = vec![expensive];
        let mut other = classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() });
        assert_eq!(choose(&mut other, &only_expensive, None).unwrap().model, "expensive");

        let mut empty_floor = classify(&TaskSignals { files_changed: 1, ..TaskSignals::default() });
        let error = choose(&mut empty_floor, &[], None).expect_err("no candidates");
        assert_eq!(error.code(), ErrorCode::Unavailable);
        assert!(error.message().contains("no candidate clears the edit floor"));
    }

    #[test]
    fn reasons_are_deterministic() {
        let input = TaskSignals {
            text: "review the latest plan and check for a cve".to_owned(),
            touches_network: true,
            files_changed: 3,
            ..TaskSignals::default()
        };
        let first = classify(&input);
        let second = classify(&input);
        assert_eq!(first.reasons, second.reasons);
        assert_eq!(first, second);

        let candidates = vec![at_floor("a", WorkClass::Security), at_floor("b", WorkClass::Security)];
        let mut first_choice = first.clone();
        let mut second_choice = second;
        let a = choose(&mut first_choice, &candidates, None).unwrap().model.clone();
        let b = choose(&mut second_choice, &candidates, None).unwrap().model.clone();
        assert_eq!(a, b);
        assert_eq!(first_choice.reasons, second_choice.reasons);
    }

    #[test]
    fn grades_are_clamped_and_ordered() {
        assert_eq!(Grade::new(9), Grade::MAX);
        assert_eq!(Grade::new(0), Grade::MIN);
        assert!(Grade::new(2) < Grade::new(3));
        assert_eq!(floor_for(WorkClass::Security).minimum(Capability::Vision), Grade::MIN);
    }
}
