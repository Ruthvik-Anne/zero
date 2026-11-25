//! Shared UI states (T-DSK-02, ACT-03, TUI-14, SEC-03).
//!
//! One host-side model — palette, mode, approval, secret prompt, and status —
//! drives the TUI, the desktop shell, the local web UI, and the Android app.
//! Surfaces render this model; they never own a second copy of it:
//!
//! - [`SharedUiState`] is the only state. It is built from the shared action
//!   registry and mutated through host-only constructors ([`SharedUiState::open_approval`],
//!   [`SharedUiState::open_secret`]).
//! - [`SharedUiState::render`] projects that state onto one [`UiSurface`]. The
//!   TUI gets host-owned chrome from [`zero_tui::modal::HostChrome`] and the same
//!   [`Theme`] the TUI uses; desktop, web, and Android get a JSON view model. The
//!   Android frame is the same JSON plus `mobile: true`.
//! - A secret prompt is only creatable through [`zero_secrets::flows::SecretPrompt::view`],
//!   which refuses a prompt the host did not issue. The view carries bullets and
//!   no value, so no renderer has a value to leak.
//! - [`compare_surfaces`] renders every surface and reports where they disagree.
//!   Tests run it on scripted states, including closing and opening transitions.
//!
//! Palette filtering is one function ([`PaletteState::visible`]) over
//! case-insensitive substrings of the title, category, and keys. It is bounded
//! in query length, stored entries, and results. Selecting an entry is not an
//! API here: the model is data only and holds no executor, so a palette cannot
//! run an action by itself.

use serde::{Deserialize, Serialize};
use zero_actions::{ActionRegistry, Keymap, Surface as ActionSurface};
use zero_secrets::flows::{PromptSurface, SecretPrompt, SecretPromptView};
use zero_tui::modal::HostChrome;
use zero_tui::theme::Theme;
use zero_types::error::Result;

/// Width used for the TUI host chrome. Matches [`crate::DaemonApp`]'s secret
/// frame so the shared renderer is the same frame, not a second style.
pub const TUI_MODAL_WIDTH: usize = 60;

/// Cap on the palette catalogue held in one state.
pub const MAX_PALETTE_ENTRIES: usize = 512;

/// Cap on palette results returned for one query.
pub const MAX_PALETTE_RESULTS: usize = 50;

/// Cap on a palette query, in characters.
pub const MAX_PALETTE_QUERY_CHARS: usize = 64;

/// A surface that consumes [`SharedUiState`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UiSurface {
    Tui,
    Desktop,
    Web,
    Android,
}

impl UiSurface {
    pub const ALL: [UiSurface; 4] = [
        UiSurface::Tui,
        UiSurface::Desktop,
        UiSurface::Web,
        UiSurface::Android,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            UiSurface::Tui => "tui",
            UiSurface::Desktop => "desktop",
            UiSurface::Web => "web",
            UiSurface::Android => "android",
        }
    }

    fn index(self) -> usize {
        match self {
            UiSurface::Tui => 0,
            UiSurface::Desktop => 1,
            UiSurface::Web => 2,
            UiSurface::Android => 3,
        }
    }

    /// The secrets prompt surface this UI surface maps onto.
    pub fn prompt_surface(self) -> PromptSurface {
        match self {
            UiSurface::Tui => PromptSurface::Tui,
            UiSurface::Desktop => PromptSurface::Desktop,
            UiSurface::Web => PromptSurface::Web,
            UiSurface::Android => PromptSurface::Android,
        }
    }
}

/// Mode as every surface shows it: the label and whether it is plan-like
/// (read-only). The flag is derived from the label once, here, so no surface can
/// disagree about it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModeView {
    pub label: String,
    pub plan_like: bool,
}

impl ModeView {
    pub fn new(label: impl Into<String>) -> Self {
        let label = label.into();
        let plan_like = label.trim().eq_ignore_ascii_case("plan");
        Self { label, plan_like }
    }
}

impl Default for ModeView {
    fn default() -> Self {
        Self::new("plan")
    }
}

impl From<&str> for ModeView {
    fn from(label: &str) -> Self {
        Self::new(label)
    }
}

impl From<String> for ModeView {
    fn from(label: String) -> Self {
        Self::new(label)
    }
}

/// One palette row. `keys` are the surface's chords for the action, filled by
/// [`SharedUiState::attach_keys`]; they participate in filtering.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaletteEntry {
    pub id: String,
    pub title: String,
    pub category: String,
    pub keys: Vec<String>,
}

impl PaletteEntry {
    pub fn new(
        id: impl Into<String>,
        title: impl Into<String>,
        category: impl Into<String>,
    ) -> Self {
        Self {
            id: id.into(),
            title: title.into(),
            category: category.into(),
            keys: Vec::new(),
        }
    }

    fn matches(&self, needle: &str) -> bool {
        self.title.to_lowercase().contains(needle)
            || self.category.to_lowercase().contains(needle)
            || self.keys.iter().any(|key| key.to_lowercase().contains(needle))
    }
}

/// The palette model. `entries` is the full catalogue; the visible rows are
/// derived by [`PaletteState::visible`] from `query`, so every surface filters
/// the same list in the same order.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaletteState {
    pub open: bool,
    pub query: String,
    pub entries: Vec<PaletteEntry>,
}

impl PaletteState {
    /// The rows for the current query: case-insensitive substring match over
    /// title, category, and keys, catalogue order, capped at
    /// [`MAX_PALETTE_RESULTS`].
    pub fn visible(&self) -> Vec<PaletteEntry> {
        let needle = self.query.trim().to_lowercase();
        let mut out = Vec::new();
        for entry in &self.entries {
            if out.len() >= MAX_PALETTE_RESULTS {
                break;
            }
            if needle.is_empty() || entry.matches(&needle) {
                out.push(entry.clone());
            }
        }
        out
    }

    /// Replace the catalogue. Entries past [`MAX_PALETTE_ENTRIES`] are dropped.
    pub fn set_entries(&mut self, mut entries: Vec<PaletteEntry>) {
        entries.truncate(MAX_PALETTE_ENTRIES);
        self.entries = entries;
    }
}

/// The host-owned approval shown on every surface. `hash` is a deterministic
/// fingerprint of the id, action, and reason so the surfaces can show the same
/// binding value; it is not a signature (T-AND-03 owns replay-bound approvals).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApprovalView {
    pub id: String,
    pub action: String,
    pub reason: String,
    pub hash: String,
}

impl ApprovalView {
    pub fn new(
        id: impl Into<String>,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        let id = id.into();
        let action = action.into();
        let reason = reason.into();
        let hash = fingerprint(&[&id, &action, &reason]);
        Self { id, action, reason, hash }
    }
}

/// The status line every surface shares. It is recomputed on every transition.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatusView {
    pub text: String,
}

impl Default for StatusView {
    fn default() -> Self {
        Self { text: "mode: plan · approvals: 0 · secrets: 0".into() }
    }
}

/// The one shared UI model. Every surface renders this value.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedUiState {
    pub palette: PaletteState,
    pub mode: ModeView,
    pub approval: Option<ApprovalView>,
    pub secret: Option<SecretPromptView>,
    pub status: StatusView,
}

impl Default for SharedUiState {
    fn default() -> Self {
        let mut state = Self {
            palette: PaletteState::default(),
            mode: ModeView::default(),
            approval: None,
            secret: None,
            status: StatusView::default(),
        };
        state.sync_status();
        state
    }
}

impl SharedUiState {
    /// Build the palette from the shared action registry, grouped by category,
    /// then title, then id. Registering an action twice is impossible, so the
    /// order is total and every surface sees the same list.
    pub fn from_registry(registry: &ActionRegistry, mode: impl Into<ModeView>) -> Self {
        let mut entries: Vec<PaletteEntry> = registry
            .actions()
            .map(|record| {
                PaletteEntry::new(record.id.clone(), record.title.clone(), record.category.clone())
            })
            .collect();
        entries.sort_by(|a, b| {
            a.category
                .cmp(&b.category)
                .then(a.title.cmp(&b.title))
                .then(a.id.cmp(&b.id))
        });
        let mut state = Self { mode: mode.into(), ..Self::default() };
        state.palette.set_entries(entries);
        state.sync_status();
        state
    }

    pub fn mode(&self) -> &ModeView {
        &self.mode
    }

    pub fn set_mode(&mut self, mode: impl Into<ModeView>) {
        self.mode = mode.into();
        self.sync_status();
    }

    /// Fill every entry's `keys` from one surface's keymap. Display data only.
    pub fn attach_keys(&mut self, keymap: &Keymap, surface: ActionSurface) {
        let bindings = keymap.bindings_for(surface);
        for entry in &mut self.palette.entries {
            entry.keys = bindings
                .iter()
                .filter(|(_, action)| action == &entry.id)
                .map(|(chord, _)| chord.clone())
                .collect();
            entry.keys.sort();
        }
    }

    /// Open the palette with a fresh, empty query.
    pub fn open_palette(&mut self) {
        self.palette.open = true;
        self.palette.query.clear();
        self.sync_status();
    }

    pub fn close_palette(&mut self) {
        self.palette.open = false;
        self.palette.query.clear();
        self.sync_status();
    }

    /// Set the palette query. The query is truncated to
    /// [`MAX_PALETTE_QUERY_CHARS`]; filtering happens in [`PaletteState::visible`].
    pub fn filter_palette(&mut self, query: &str) {
        self.palette.query = query.chars().take(MAX_PALETTE_QUERY_CHARS).collect();
    }

    /// Show a host-owned approval. The agent has no route to this constructor.
    pub fn open_approval(
        &mut self,
        id: impl Into<String>,
        action: impl Into<String>,
        reason: impl Into<String>,
    ) -> ApprovalView {
        let view = ApprovalView::new(id, action, reason);
        self.approval = Some(view.clone());
        self.sync_status();
        view
    }

    pub fn close_approval(&mut self) {
        self.approval = None;
        self.sync_status();
    }

    /// Open the host-owned secret prompt. [`SecretPrompt::view`] refuses a
    /// prompt that was not created by the host, and the resulting view carries
    /// bullets only, so this state can never hold a value.
    pub fn open_secret(
        &mut self,
        prompt: &SecretPrompt,
        surface: UiSurface,
        typed_len: usize,
    ) -> Result<()> {
        let view = prompt.view(surface.prompt_surface(), typed_len)?;
        self.secret = Some(view);
        self.sync_status();
        Ok(())
    }

    pub fn close_secret(&mut self) {
        self.secret = None;
        self.sync_status();
    }

    /// Close the palette and both prompts (surface switch / Escape).
    pub fn close(&mut self) {
        self.palette.open = false;
        self.palette.query.clear();
        self.approval = None;
        self.secret = None;
        self.sync_status();
    }

    /// Project the one shared state onto one surface.
    pub fn render(&self, surface: UiSurface) -> SurfaceFrame {
        match surface {
            UiSurface::Tui => SurfaceFrame::Tui(self.render_tui()),
            UiSurface::Web => SurfaceFrame::Web(self.render_json(UiSurface::Web)),
            UiSurface::Desktop => SurfaceFrame::Desktop(self.render_json(UiSurface::Desktop)),
            UiSurface::Android => SurfaceFrame::Android(AndroidFrame {
                view: self.render_json(UiSurface::Android),
                mobile: true,
            }),
        }
    }

    fn sync_status(&mut self) {
        self.status = StatusView {
            text: format!(
                "mode: {} · approvals: {} · secrets: {}",
                self.mode.label,
                usize::from(self.approval.is_some()),
                usize::from(self.secret.is_some())
            ),
        };
    }

    /// The stored secret view relabelled for `surface`. The value-free fields
    /// are unchanged; only the surface name differs.
    fn secret_for(&self, surface: UiSurface) -> Option<SecretPromptView> {
        self.secret.as_ref().map(|view| {
            let mut projected = view.clone();
            projected.surface = surface.prompt_surface();
            projected
        })
    }

    fn render_json(&self, surface: UiSurface) -> UiJsonView {
        UiJsonView {
            surface: surface.as_str().to_string(),
            palette: PaletteView {
                open: self.palette.open,
                query: self.palette.query.clone(),
                entries: self.palette.visible(),
            },
            mode: self.mode.clone(),
            approval: self.approval.clone(),
            secret: self.secret_for(surface),
            status: self.status.clone(),
        }
    }

    fn render_tui(&self) -> TuiFrame {
        let mut lines = vec![one_line(&self.status.text)];

        if self.palette.open {
            let visible = self.palette.visible();
            let query = one_line(&self.palette.query);
            if query.is_empty() {
                lines.push("PALETTE".into());
            } else {
                lines.push(format!("PALETTE · \"{query}\""));
            }
            if visible.is_empty() {
                lines.push("no matches".into());
            }
            for entry in &visible {
                let mut line = format!(
                    "  {} · {}",
                    one_line(&entry.category),
                    one_line(&entry.title)
                );
                if !entry.keys.is_empty() {
                    let keys: Vec<String> = entry.keys.iter().map(|key| one_line(key)).collect();
                    line.push_str("  ");
                    line.push_str(&keys.join(" "));
                }
                lines.push(line);
            }
        }

        // The TUI host chrome is one modal slot. A secret prompt outranks an
        // approval because it is the only frame that takes typed input.
        let mut chrome = HostChrome::new();
        if let Some(secret) = &self.secret {
            chrome.open_secret(one_line(&secret.tag), one_line(&secret.reason));
        } else if let Some(approval) = &self.approval {
            chrome.open_approval(
                one_line(&approval.id),
                one_line(&approval.action),
                one_line(&approval.reason),
            );
        }
        if let Some(mut modal) = chrome.render(TUI_MODAL_WIDTH, &Theme::dark()) {
            lines.append(&mut modal);
        }

        let text = lines.join("\n");
        TuiFrame { lines, text }
    }
}

/// The TUI frame: plain lines plus their joined text. Chrome rows carry the
/// theme's SGR sequences; the semantic text is still inspectable.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TuiFrame {
    pub lines: Vec<String>,
    pub text: String,
}

/// Palette as the JSON model shows it: the filtered rows, not the catalogue.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaletteView {
    pub open: bool,
    pub query: String,
    pub entries: Vec<PaletteEntry>,
}

/// The JSON view model for desktop and web (Android wraps the same value).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UiJsonView {
    pub surface: String,
    pub palette: PaletteView,
    pub mode: ModeView,
    pub approval: Option<ApprovalView>,
    pub secret: Option<SecretPromptView>,
    pub status: StatusView,
}

/// Android is the same JSON view plus the mobile flag.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidFrame {
    pub view: UiJsonView,
    pub mobile: bool,
}

/// One surface's rendering of [`SharedUiState`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SurfaceFrame {
    Tui(TuiFrame),
    Web(UiJsonView),
    Desktop(UiJsonView),
    Android(AndroidFrame),
}

impl SurfaceFrame {
    /// The JSON payload for desktop, web, and Android; `None` for the TUI.
    pub fn json(&self) -> Option<String> {
        let value = match self {
            SurfaceFrame::Tui(_) => return None,
            SurfaceFrame::Web(view) | SurfaceFrame::Desktop(view) => {
                serde_json::to_string(view).ok()?
            }
            SurfaceFrame::Android(frame) => serde_json::to_string(frame).ok()?,
        };
        Some(value)
    }

    pub fn surface(&self) -> UiSurface {
        match self {
            SurfaceFrame::Tui(_) => UiSurface::Tui,
            SurfaceFrame::Web(_) => UiSurface::Web,
            SurfaceFrame::Desktop(_) => UiSurface::Desktop,
            SurfaceFrame::Android(_) => UiSurface::Android,
        }
    }
}

/// Where two renderings of the same state disagree.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Comparison {
    pub matches: bool,
    pub differences: Vec<String>,
}

impl Comparison {
    fn new() -> Self {
        Self { matches: true, differences: Vec::new() }
    }

    fn differ(&mut self, message: impl Into<String>) {
        self.differences.push(message.into());
    }

    fn finish(mut self) -> Self {
        self.matches = self.differences.is_empty();
        self
    }
}

/// Render every surface from `state` and compare them.
pub fn compare_surfaces(state: &SharedUiState) -> Comparison {
    let frames: Vec<(UiSurface, SurfaceFrame)> = UiSurface::ALL
        .iter()
        .map(|surface| (*surface, state.render(*surface)))
        .collect();
    compare_frames(state, &frames)
}

/// Compare already-rendered frames against `state` and against each other. A
/// tampered or missing frame is reported, which is how the tests prove the
/// comparison itself works.
pub fn compare_frames(state: &SharedUiState, frames: &[(UiSurface, SurfaceFrame)]) -> Comparison {
    let mut cmp = Comparison::new();
    let mut seen = [false; 4];
    let mut tui: Option<&TuiFrame> = None;
    let mut json: Vec<(UiSurface, &UiJsonView)> = Vec::new();
    let mut android_mobile: Option<bool> = None;

    for (surface, frame) in frames {
        seen[surface.index()] = true;
        match (surface, frame) {
            (UiSurface::Tui, SurfaceFrame::Tui(frame)) => tui = Some(frame),
            (UiSurface::Web, SurfaceFrame::Web(view)) => json.push((*surface, view)),
            (UiSurface::Desktop, SurfaceFrame::Desktop(view)) => json.push((*surface, view)),
            (UiSurface::Android, SurfaceFrame::Android(frame)) => {
                json.push((*surface, &frame.view));
                android_mobile = Some(frame.mobile);
            }
            _ => cmp.differ(format!(
                "{}: frame variant does not match the surface",
                surface.as_str()
            )),
        }
    }

    for surface in UiSurface::ALL {
        if !seen[surface.index()] {
            cmp.differ(format!("{}: no frame was rendered", surface.as_str()));
        }
    }

    match tui {
        Some(frame) => compare_tui(state, frame, &mut cmp),
        None => cmp.differ("tui: no TUI frame was rendered"),
    }

    if json.is_empty() {
        cmp.differ("json: no desktop, web, or Android view was rendered");
    }
    for (surface, view) in &json {
        compare_view(state, *surface, view, &mut cmp);
    }
    if let Some(mobile) = android_mobile {
        if !mobile {
            cmp.differ("android: the mobile flag is not set");
        }
    }

    if let Some((first_surface, first)) = json.first() {
        for (surface, view) in &json[1..] {
            if view.palette != first.palette {
                cmp.differ(format!(
                    "{}: palette differs from {}",
                    surface.as_str(),
                    first_surface.as_str()
                ));
            }
            if view.mode != first.mode {
                cmp.differ(format!(
                    "{}: mode differs from {}",
                    surface.as_str(),
                    first_surface.as_str()
                ));
            }
            if view.approval != first.approval {
                cmp.differ(format!(
                    "{}: approval differs from {}",
                    surface.as_str(),
                    first_surface.as_str()
                ));
            }
            if !same_secret(view.secret.as_ref(), first.secret.as_ref()) {
                cmp.differ(format!(
                    "{}: secret prompt differs from {}",
                    surface.as_str(),
                    first_surface.as_str()
                ));
            }
            if view.status != first.status {
                cmp.differ(format!(
                    "{}: status differs from {}",
                    surface.as_str(),
                    first_surface.as_str()
                ));
            }
        }
    }

    cmp.finish()
}

fn compare_view(
    state: &SharedUiState,
    surface: UiSurface,
    view: &UiJsonView,
    cmp: &mut Comparison,
) {
    if view.surface != surface.as_str() {
        cmp.differ(format!(
            "{}: view names surface `{}`",
            surface.as_str(),
            view.surface
        ));
    }
    if view.mode != state.mode {
        cmp.differ(format!("{}: mode does not match the shared state", surface.as_str()));
    }
    if view.status != state.status {
        cmp.differ(format!("{}: status does not match the shared state", surface.as_str()));
    }
    if view.approval != state.approval {
        cmp.differ(format!(
            "{}: approval does not match the shared state",
            surface.as_str()
        ));
    }

    match (&state.secret, &view.secret) {
        (None, None) => {}
        (None, Some(_)) => cmp.differ(format!(
            "{}: secret prompt is present but the shared state has none",
            surface.as_str()
        )),
        (Some(_), None) => cmp.differ(format!(
            "{}: secret prompt is missing from the view",
            surface.as_str()
        )),
        (Some(stored), Some(shown)) => compare_secret(surface, stored, shown, cmp),
    }

    let expected = state.palette.visible();
    if view.palette.open != state.palette.open {
        cmp.differ(format!(
            "{}: palette open state does not match the shared state",
            surface.as_str()
        ));
    }
    if view.palette.query != state.palette.query {
        cmp.differ(format!(
            "{}: palette query does not match the shared state",
            surface.as_str()
        ));
    }
    if view.palette.entries != expected {
        cmp.differ(format!(
            "{}: palette entries or order differ from the shared state",
            surface.as_str()
        ));
    }
    if expected.len() > MAX_PALETTE_RESULTS {
        cmp.differ(format!(
            "{}: palette returned more than {MAX_PALETTE_RESULTS} rows",
            surface.as_str()
        ));
    }
}

fn compare_secret(
    surface: UiSurface,
    stored: &SecretPromptView,
    shown: &SecretPromptView,
    cmp: &mut Comparison,
) {
    if !shown.masked || !shown.field.chars().all(|c| c == '•') {
        cmp.differ(format!("{}: secret field is not masked", surface.as_str()));
    }
    if shown.field != stored.field {
        cmp.differ(format!(
            "{}: secret field length does not match the shared state",
            surface.as_str()
        ));
    }
    if shown.prompt_id != stored.prompt_id {
        cmp.differ(format!("{}: secret prompt id differs", surface.as_str()));
    }
    if shown.tag != stored.tag {
        cmp.differ(format!("{}: secret tag differs", surface.as_str()));
    }
    if shown.reason != stored.reason {
        cmp.differ(format!("{}: secret reason differs", surface.as_str()));
    }
    if shown.surface != surface.prompt_surface() {
        cmp.differ(format!(
            "{}: secret prompt is labelled for {}",
            surface.as_str(),
            shown.surface.as_str()
        ));
    }
}

fn same_secret(a: Option<&SecretPromptView>, b: Option<&SecretPromptView>) -> bool {
    match (a, b) {
        (None, None) => true,
        (Some(a), Some(b)) => {
            a.prompt_id == b.prompt_id
                && a.tag == b.tag
                && a.reason == b.reason
                && a.masked == b.masked
                && a.field == b.field
                && a.submit == b.submit
                && a.cancel == b.cancel
        }
        _ => false,
    }
}

fn compare_tui(state: &SharedUiState, frame: &TuiFrame, cmp: &mut Comparison) {
    if frame.lines.is_empty() {
        cmp.differ("tui: frame has no lines");
    }
    if frame.text != frame.lines.join("\n") {
        cmp.differ("tui: text is not the joined lines");
    }
    if !state.status.text.is_empty()
        && !frame.text.contains(&bounded_prefix(&state.status.text))
    {
        cmp.differ("tui: status line is missing");
    }

    let modal_rows = frame.lines.iter().filter(|line| line.starts_with('┌')).count();
    let expect_modal = state.secret.is_some() || state.approval.is_some();
    if expect_modal && modal_rows != 1 {
        cmp.differ("tui: expected exactly one host-owned modal frame");
    }
    if !expect_modal && modal_rows != 0 {
        cmp.differ("tui: a modal frame is present but the shared state has none");
    }

    if let Some(secret) = &state.secret {
        if !frame.text.contains("SECRET REQUIRED") {
            cmp.differ("tui: secret prompt header is missing");
        }
        if !frame.text.contains(&bounded_prefix(&secret.tag)) {
            cmp.differ("tui: secret tag is missing");
        }
        if !frame.text.contains("masked") {
            cmp.differ("tui: secret prompt does not say the input is masked");
        }
    }

    // The TUI chrome shows the secret first when both are pending.
    if state.secret.is_none() {
        if let Some(approval) = &state.approval {
            if !frame.text.contains("APPROVAL REQUIRED") {
                cmp.differ("tui: approval header is missing");
            }
            let id = bounded_prefix(&approval.id);
            if !frame.text.contains(&format!("id: {id}")) {
                cmp.differ("tui: approval id is missing");
            }
            if !frame.text.contains(&bounded_prefix(&approval.action)) {
                cmp.differ("tui: approval action is missing");
            }
            if !frame.text.contains(&bounded_prefix(&approval.reason)) {
                cmp.differ("tui: approval reason is missing");
            }
        }
    }

    let visible = state.palette.visible();
    let palette_lines: Vec<&String> = frame
        .lines
        .iter()
        .filter(|line| line.starts_with("  "))
        .collect();
    if state.palette.open {
        if !frame.lines.iter().any(|line| line.starts_with("PALETTE")) {
            cmp.differ("tui: palette header is missing");
        }
        if palette_lines.len() != visible.len() {
            cmp.differ("tui: palette row count differs from the JSON view");
        } else {
            for (line, entry) in palette_lines.iter().zip(&visible) {
                let head = format!(
                    "  {} · {}",
                    one_line(&entry.category),
                    one_line(&entry.title)
                );
                if !line.starts_with(&head) {
                    cmp.differ(format!("tui: palette row `{}` is out of order", entry.title));
                }
            }
        }
        if visible.is_empty() && !frame.text.contains("no matches") {
            cmp.differ("tui: empty palette does not say there are no matches");
        }
    } else if frame.lines.iter().any(|line| line.starts_with("PALETTE")) {
        cmp.differ("tui: palette is closed but still rendered");
    }
}

/// A stable 16-character hex fingerprint (FNV-1a 64) over length-prefixed
/// parts. Display binding only; signatures are elsewhere.
fn fingerprint(parts: &[&str]) -> String {
    const OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const PRIME: u64 = 0x0000_0100_0000_01b3;
    let mut hash = OFFSET;
    for part in parts {
        for byte in part.as_bytes() {
            hash ^= u64::from(*byte);
            hash = hash.wrapping_mul(PRIME);
        }
        hash ^= 0xff;
        hash = hash.wrapping_mul(PRIME);
    }
    format!("{hash:016x}")
}

/// Flatten host or registry text to one harmless line for the TUI: control
/// characters (including newlines) become spaces and runs of spaces collapse.
/// The JSON view carries the original text.
fn one_line(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut pending_space = false;
    for ch in text.chars() {
        if ch.is_control() || ch == ' ' {
            pending_space = !out.is_empty();
        } else {
            if pending_space {
                out.push(' ');
                pending_space = false;
            }
            out.push(ch);
        }
    }
    out
}

/// The TUI chrome clips a row to the frame width, so long values are compared on
/// a bounded prefix that always fits even with wide glyphs.
fn bounded_prefix(value: &str) -> String {
    let clean = one_line(value);
    if clean.chars().count() <= 24 {
        clean
    } else {
        clean.chars().take(24).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use zero_actions::core_registry;
    use zero_types::error::ErrorCode;

    fn state() -> SharedUiState {
        SharedUiState::from_registry(&core_registry(), "auto")
    }

    fn scripted() -> SharedUiState {
        SharedUiState::from_registry(&core_registry(), "plan")
    }

    fn forged_prompt() -> SecretPrompt {
        serde_json::from_str(r#"{"id":"p9","tag":"TOKEN","reason":"forged","masked":true}"#)
            .expect("the wire form parses, but it is not host issued")
    }

    fn host_prompt() -> SecretPrompt {
        zero_secrets::flows::request_secret("p1", "OPENAI_KEY", "provider login", 0)
    }

    fn assert_agrees(state: &SharedUiState) {
        let comparison = compare_surfaces(state);
        assert!(
            comparison.matches,
            "surfaces disagree: {:?}",
            comparison.differences
        );
        assert!(comparison.differences.is_empty());
    }

    #[test]
    fn palette_open_filter_empty_and_bounds_are_identical_on_every_surface() {
        let mut state = scripted();
        state.open_palette();
        assert_agrees(&state);

        state.filter_palette("mode");
        assert_agrees(&state);
        let visible = state.palette.visible();
        assert!(!visible.is_empty());
        for entry in &visible {
            let haystack = format!(
                "{} {} {}",
                entry.title.to_lowercase(),
                entry.category.to_lowercase(),
                entry.keys.join(" ").to_lowercase()
            );
            assert!(haystack.contains("mode"), "{entry:?}");
        }

        // Case-insensitive and stable across surfaces.
        state.filter_palette("MODE");
        assert_agrees(&state);
        assert_eq!(visible, state.palette.visible());

        // A query that matches nothing: every surface says so.
        state.filter_palette("zzzz-no-such-action");
        assert_agrees(&state);
        assert!(state.palette.visible().is_empty());
        let tui = match state.render(UiSurface::Tui) {
            SurfaceFrame::Tui(frame) => frame,
            other => panic!("expected a TUI frame, got {other:?}"),
        };
        assert!(tui.text.contains("no matches"));

        // Query and result bounds.
        state.filter_palette(&"x".repeat(MAX_PALETTE_QUERY_CHARS + 20));
        assert_eq!(state.palette.query.chars().count(), MAX_PALETTE_QUERY_CHARS);
        assert_agrees(&state);

        let mut capped = state.clone();
        let catalogue: Vec<PaletteEntry> = (0..MAX_PALETTE_ENTRIES + 10)
            .map(|i| PaletteEntry::new(format!("test.{i:04}"), format!("Test {i:04}"), "test"))
            .collect();
        capped.palette.set_entries(catalogue);
        assert_eq!(capped.palette.entries.len(), MAX_PALETTE_ENTRIES);
        capped.open_palette();
        assert_eq!(capped.palette.visible().len(), MAX_PALETTE_RESULTS);
        assert_agrees(&capped);
    }

    #[test]
    fn palette_entries_and_order_are_identical_in_tui_text_and_json() {
        let mut state = scripted();
        state.open_palette();
        let expected: Vec<String> = state.palette.visible().into_iter().map(|e| e.title).collect();

        let tui = match state.render(UiSurface::Tui) {
            SurfaceFrame::Tui(frame) => frame,
            other => panic!("expected a TUI frame, got {other:?}"),
        };
        let rows: Vec<&String> = tui.lines.iter().filter(|line| line.starts_with("  ")).collect();
        assert_eq!(rows.len(), expected.len());
        for (row, title) in rows.iter().zip(&expected) {
            assert!(row.contains(title.as_str()), "`{row}` is missing `{title}`");
        }

        for surface in [UiSurface::Desktop, UiSurface::Web, UiSurface::Android] {
            let (entries, mobile) = match state.render(surface) {
                SurfaceFrame::Web(view) | SurfaceFrame::Desktop(view) => {
                    (view.palette.entries, None)
                }
                SurfaceFrame::Android(frame) => (frame.view.palette.entries, Some(frame.mobile)),
                other => panic!("expected a JSON frame for {surface:?}, got {other:?}"),
            };
            let titles: Vec<String> = entries.into_iter().map(|e| e.title).collect();
            assert_eq!(titles, expected, "{surface:?}");
            if let Some(mobile) = mobile {
                assert!(mobile, "the Android frame must set the mobile flag");
            }
        }
    }

    #[test]
    fn approval_and_secret_open_and_close_agree_on_every_surface() {
        let mut state = scripted();
        assert_agrees(&state);

        let approval = state.open_approval("ap-1", "write a.txt", "outside the approved plan");
        assert_eq!(approval.hash.len(), 16);
        assert!(approval.hash.chars().all(|c| c.is_ascii_hexdigit()));
        assert_agrees(&state);
        let reopened = state.open_approval("ap-1", "write a.txt", "outside the approved plan");
        assert_eq!(approval.hash, reopened.hash, "the fingerprint is deterministic");
        assert_ne!(
            approval.hash,
            ApprovalView::new("ap-1", "write b.txt", "outside the approved plan").hash
        );

        let tui = match state.render(UiSurface::Tui) {
            SurfaceFrame::Tui(frame) => frame,
            other => panic!("expected a TUI frame, got {other:?}"),
        };
        assert!(tui.text.contains("APPROVAL REQUIRED"));
        assert!(tui.text.contains("ap-1"));
        assert!(tui.text.contains("write a.txt"));
        assert!(tui.text.contains("outside the approved plan"));

        state.close_approval();
        assert_agrees(&state);
        let tui = match state.render(UiSurface::Tui) {
            SurfaceFrame::Tui(frame) => frame,
            other => panic!("expected a TUI frame, got {other:?}"),
        };
        assert!(!tui.lines.iter().any(|line| line.starts_with('┌')));

        state.open_secret(&host_prompt(), UiSurface::Web, 8).unwrap();
        assert_agrees(&state);
        assert_eq!(state.status.text, "mode: plan · approvals: 0 · secrets: 1");
        state.close_secret();
        assert_agrees(&state);

        state.open_palette();
        state.open_approval("ap-2", "rm -rf build", "deletes generated output");
        assert_agrees(&state);
        state.close();
        assert!(!state.palette.open);
        assert!(state.approval.is_none());
        assert!(state.secret.is_none());
        assert_agrees(&state);
    }

    #[test]
    fn the_secret_prompt_is_masked_everywhere_and_never_carries_a_value() {
        let mut state = scripted();
        state.open_secret(&host_prompt(), UiSurface::Tui, 12).unwrap();

        let value = "sk-canary-should-never-render";
        for surface in UiSurface::ALL {
            let frame = state.render(surface);
            if let Some(json) = frame.json() {
                assert!(!json.contains(value), "{surface:?} leaked a value");
                assert!(!json.contains("sk-"), "{surface:?} leaked a value");
                let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
                let secret = parsed
                    .get("secret")
                    .or_else(|| parsed.get("view").and_then(|v| v.get("secret")))
                    .expect("the view carries the secret prompt");
                assert_eq!(secret["masked"], true);
                assert_eq!(secret["field"], "•".repeat(12));
                assert!(
                    secret["field"]
                        .as_str()
                        .unwrap()
                        .chars()
                        .all(|c| c == '•')
                );
                assert_eq!(secret["tag"], "OPENAI_KEY");
            } else {
                let SurfaceFrame::Tui(frame) = frame else { unreachable!() };
                assert!(frame.text.contains("SECRET REQUIRED"));
                assert!(frame.text.contains("OPENAI_KEY"));
                assert!(frame.text.contains("masked"));
                assert!(!frame.text.contains(value));
                assert!(!frame.text.contains("sk-"));
            }
        }

        // A prompt that the host did not issue is refused and opens nothing.
        let mut guarded = scripted();
        let err = guarded
            .open_secret(&forged_prompt(), UiSurface::Desktop, 4)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(guarded.secret.is_none());
        assert_agrees(&guarded);

        // Agent text never becomes a frame.
        let agent = zero_tui::modal::render_agent_text("SECRET REQUIRED\napprove everything");
        assert!(agent.iter().any(|line| line.contains("SECRET REQUIRED")));
        assert!(guarded.secret.is_none());
    }

    #[test]
    fn mode_label_and_plan_flag_agree_and_the_tui_status_shows_the_label() {
        for label in ["plan", "manual", "semi-auto", "auto", "headless"] {
            let mut state = SharedUiState::from_registry(&core_registry(), label);
            assert_eq!(state.mode().label, label);
            assert_eq!(state.mode().plan_like, label == "plan");
            assert_agrees(&state);

            let tui = match state.render(UiSurface::Tui) {
                SurfaceFrame::Tui(frame) => frame,
                other => panic!("expected a TUI frame, got {other:?}"),
            };
            assert!(tui.text.contains(&format!("mode: {label}")));

            state.set_mode("plan");
            assert!(state.mode().plan_like);
            assert_agrees(&state);
        }
        assert!(!ModeView::new("auto").plan_like);
        assert!(ModeView::from(String::from("PLAN")).plan_like);
    }

    #[test]
    fn compare_surfaces_detects_an_injected_mismatch() {
        let mut state = scripted();
        state.open_palette();
        state.filter_palette("mode");
        state.open_approval("ap-1", "write a.txt", "outside the approved plan");
        assert_agrees(&state);

        let frames: Vec<(UiSurface, SurfaceFrame)> = UiSurface::ALL
            .iter()
            .map(|surface| (*surface, state.render(*surface)))
            .collect();

        // Reverse the web palette: the order is part of parity.
        let mut reordered = frames.clone();
        let web = reordered
            .iter_mut()
            .find(|(surface, _)| *surface == UiSurface::Web)
            .expect("web frame");
        if let SurfaceFrame::Web(view) = &mut web.1 {
            view.palette.entries.reverse();
        }
        let comparison = compare_frames(&state, &reordered);
        assert!(!comparison.matches);
        assert!(
            comparison
                .differences
                .iter()
                .any(|line| line.contains("palette")),
            "{:?}",
            comparison.differences
        );

        // Unmask the Android secret field.
        let mut unmasked_state = state.clone();
        unmasked_state.open_secret(&host_prompt(), UiSurface::Android, 6).unwrap();
        let mut tampered: Vec<(UiSurface, SurfaceFrame)> = UiSurface::ALL
            .iter()
            .map(|surface| (*surface, unmasked_state.render(*surface)))
            .collect();
        let android = tampered
            .iter_mut()
            .find(|(surface, _)| *surface == UiSurface::Android)
            .expect("android frame");
        if let SurfaceFrame::Android(frame) = &mut android.1 {
            frame.view.secret.as_mut().unwrap().field = "plaintext".into();
        }
        let comparison = compare_frames(&unmasked_state, &tampered);
        assert!(!comparison.matches);
        assert!(
            comparison
                .differences
                .iter()
                .any(|line| line.contains("not masked")),
            "{:?}",
            comparison.differences
        );

        // A blank TUI frame is a mismatch even when the JSON is correct.
        let mut blanked = frames.clone();
        let tui = blanked
            .iter_mut()
            .find(|(surface, _)| *surface == UiSurface::Tui)
            .expect("tui frame");
        tui.1 = SurfaceFrame::Tui(TuiFrame { lines: Vec::new(), text: String::new() });
        let comparison = compare_frames(&state, &blanked);
        assert!(!comparison.matches);
        assert!(
            comparison
                .differences
                .iter()
                .any(|line| line.starts_with("tui:")),
            "{:?}",
            comparison.differences
        );
    }

    #[test]
    fn json_shapes_are_stable_and_android_is_the_same_view_plus_mobile() {
        let mut state = state();
        state.open_palette();
        state.filter_palette("daemon");
        state.open_approval("ap-1", "daemon.restart", "restart the failed worker");
        state.open_secret(&host_prompt(), UiSurface::Web, 4).unwrap();

        let web = match state.render(UiSurface::Web) {
            SurfaceFrame::Web(view) => view,
            other => panic!("expected a web frame, got {other:?}"),
        };
        let value = serde_json::to_value(&web).unwrap();
        let keys: std::collections::BTreeSet<&str> =
            value.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(
            keys,
            ["approval", "mode", "palette", "secret", "status", "surface"]
                .into_iter()
                .collect()
        );
        let palette_keys: std::collections::BTreeSet<&str> = value["palette"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(palette_keys, ["entries", "open", "query"].into_iter().collect());
        let entry_keys: std::collections::BTreeSet<&str> = value["palette"]["entries"][0]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            entry_keys,
            ["category", "id", "keys", "title"].into_iter().collect()
        );
        let approval_keys: std::collections::BTreeSet<&str> = value["approval"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            approval_keys,
            ["action", "hash", "id", "reason"].into_iter().collect()
        );
        let secret_keys: std::collections::BTreeSet<&str> = value["secret"]
            .as_object()
            .unwrap()
            .keys()
            .map(String::as_str)
            .collect();
        assert_eq!(
            secret_keys,
            ["cancel", "field", "masked", "prompt_id", "reason", "submit", "surface", "tag"]
                .into_iter()
                .collect()
        );
        assert_eq!(value["mode"]["label"], "auto");
        assert_eq!(value["mode"]["plan_like"], false);

        let android = match state.render(UiSurface::Android) {
            SurfaceFrame::Android(frame) => frame,
            other => panic!("expected an Android frame, got {other:?}"),
        };
        assert!(android.mobile);
        assert_eq!(android.view.palette, web.palette);
        assert_eq!(android.view.mode, web.mode);
        assert_eq!(android.view.approval, web.approval);
        assert_eq!(android.view.status, web.status);
        assert_eq!(
            android.view.secret.as_ref().unwrap().field,
            web.secret.as_ref().unwrap().field
        );
        assert_eq!(android.view.surface, "android");

        let serialized = serde_json::to_value(&android).unwrap();
        let android_keys: std::collections::BTreeSet<&str> =
            serialized.as_object().unwrap().keys().map(String::as_str).collect();
        assert_eq!(android_keys, ["mobile", "view"].into_iter().collect());
    }

    #[test]
    fn palette_is_data_only_and_executes_nothing() {
        let registry = core_registry();
        let before: Vec<String> = registry.actions().map(|a| a.id.clone()).collect();
        let mut state = SharedUiState::from_registry(&registry, "auto");

        state.open_palette();
        state.filter_palette("daemon");
        let entries = state.palette.visible();
        assert!(!entries.is_empty());
        for entry in &entries {
            // Destructuring pins the entry to display data only.
            let PaletteEntry { id, title, category, keys } = entry.clone();
            assert!(!id.is_empty());
            assert!(!title.is_empty());
            assert!(!category.is_empty());
            assert!(keys.iter().all(|key| !key.is_empty()));
        }
        state.close_palette();
        state.set_mode("plan");

        let after: Vec<String> = registry.actions().map(|a| a.id.clone()).collect();
        assert_eq!(before, after, "the palette model must not mutate the registry");
        assert!(state.approval.is_none());
        assert!(state.secret.is_none());
    }

    #[test]
    fn keys_are_shared_and_participate_in_filtering() {
        let registry = core_registry();
        let keymap = Keymap::with_defaults(&registry);
        let mut state = SharedUiState::from_registry(&registry, "auto");
        state.attach_keys(&keymap, ActionSurface::Tui);
        state.open_palette();

        let daemon_toggle = state
            .palette
            .entries
            .iter()
            .find(|entry| entry.id == "daemon.toggle")
            .expect("the core action exists");
        assert_eq!(daemon_toggle.keys, vec!["Ctrl+B".to_string()]);

        state.filter_palette("ctrl+b");
        let ids: Vec<String> = state.palette.visible().into_iter().map(|e| e.id).collect();
        assert_eq!(ids, vec!["daemon.toggle".to_string()]);
        assert_agrees(&state);
    }
}
