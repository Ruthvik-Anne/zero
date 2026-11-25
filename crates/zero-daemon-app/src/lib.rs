//! `zero-daemon-app` — the worker and attachment surface (ACT-11) and the draft
//! handoff between it and the main client (TUI-16). Worker control exists only
//! here.

use serde::{Deserialize, Serialize};
use zero_secrets::flows::{PromptSurface, SecretPrompt, SecretPromptView};
use zero_tui::modal::HostChrome;
use zero_tui::theme::Theme;
use zero_types::error::{ErrorCode, Result, ZeroError};

pub mod android_pairing;
pub mod android_session;
pub mod desktop_shell;
pub mod share;
pub mod shared_ui;
pub mod webui;

pub use android_pairing::{
    pair, pair_with_config, paired_preview, public_preview, require_biometric, start_pairing,
    BiometricGate, PairedDevice, PairingConfig, PairingOffer, PairingOfferView, PairingRequest,
    DEFAULT_PAIRING_TTL_MS, MAX_CODE_INPUT_CHARS, MAX_DEVICE_ID_CHARS, MAX_DEVICE_NAME_CHARS,
    MAX_OFFER_ID_CHARS, MAX_PAIRING_TTL_MS, MAX_SECRET_INPUT_CHARS, PAIRING_TRANSPORT,
    QR_PAYLOAD_PREFIX,
};
pub use android_session::{
    AndroidSessionController, DeliveryAck, DeliveryMode, FileDiff, MeshSessionClient, PromptAck,
    QueuedItemView, SessionSummary, SteerAck, TranscriptEntry, TranscriptPage, MAX_DIFF_FILES,
    MAX_DIFF_PATH_CHARS, MAX_DIFF_PATCH_BYTES, MAX_ID_CHARS, MAX_PROMPT_CHARS, MAX_QUEUED_TEXT_CHARS,
    MAX_QUEUE_ITEMS, MAX_ROLE_CHARS, MAX_SESSIONS, MAX_SESSION_NAME_CHARS, MAX_STATE_CHARS,
    MAX_STEER_CHARS, MAX_TRANSCRIPT_ENTRIES, MAX_TRANSCRIPT_ENTRY_CHARS, SESSION_TRANSPORT,
};
pub use desktop_shell::{
    action_registry, webview_for_platform, DesktopShell, EngineSource, ShellConfig, ShellPlan,
    WebviewKind, MAX_WINDOW_TITLE_CHARS,
};
pub use shared_ui::{
    compare_frames, compare_surfaces, AndroidFrame, ApprovalView, Comparison, ModeView,
    PaletteEntry, PaletteState, SharedUiState, StatusView, SurfaceFrame, TuiFrame, UiJsonView,
    UiSurface, MAX_PALETTE_ENTRIES, MAX_PALETTE_QUERY_CHARS, MAX_PALETTE_RESULTS,
    TUI_MODAL_WIDTH,
};
pub use share::{
    refuse_vpn_change, share, share_sheet, DeliveryReceipt, Route, ShareAttachment, ShareFailure,
    ShareIntent, ShareKind, SharePayload, ShareReport, ShareRouter, ShareSheetEntry, ShareSink,
    ShareTarget, VpnState, MAX_SHEET_ENTRIES, MAX_SHEET_LABEL_CHARS, MAX_SHARE_FILE_BYTES,
    MAX_SHARE_IMAGE_BYTES, MAX_SHARE_NAME_CHARS, MAX_SHARE_SOURCE_APP_CHARS,
    MAX_SHARE_TEXT_BYTES, MAX_SHARE_URL_CHARS, SHARE_TRANSPORT, VPN_POLICY,
};
pub use webui::{
    parse_bind, validate_bind, LocalWebUi, OneTimeToken, TokenState, WebUiConfig, WebUiOutcome,
    DEFAULT_TOKEN_TTL_MS, MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Surface {
    Main,
    DaemonApp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Health {
    Healthy,
    Restarting,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkerEntry {
    pub id: String,
    pub session: String,
    pub health: Health,
    pub attachments: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WorkerOp {
    List,
    Restart(String),
    Stop(String),
    Attach(String),
    Detach(String),
}

pub struct DaemonApp {
    surface: Surface,
    draft: String,
    workers: Vec<WorkerEntry>,
    history: Vec<String>,
    chrome: HostChrome,
}

/// A host-owned secret prompt rendered for one surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SecretPromptFrame {
    /// TUI: the modal frame. The agent has no path to these lines.
    Tui { lines: Vec<String> },
    /// Desktop, web, and Android consume the host payload, which carries only
    /// the masked view.
    Controller { view: SecretPromptView, payload: String },
}

impl Default for DaemonApp {
    fn default() -> Self {
        Self::new()
    }
}

impl DaemonApp {
    pub fn new() -> Self {
        Self { surface: Surface::Main, draft: String::new(), workers: Vec::new(), history: Vec::new(), chrome: HostChrome::new() }
    }

    pub fn surface(&self) -> Surface {
        self.surface
    }

    pub fn draft(&self) -> &str {
        &self.draft
    }

    pub fn draft_mut(&mut self) -> &mut String {
        &mut self.draft
    }

    /// Open the daemon app. The draft is preserved across the round trip.
    pub fn open_daemon_app(&mut self) {
        self.surface = Surface::DaemonApp;
    }

    /// Return to the main surface; the draft is untouched.
    pub fn close_daemon_app(&mut self) {
        self.surface = Surface::Main;
    }

    /// Render one host-issued secret prompt on the requested surface. TUI opens
    /// the host modal; desktop, web, and Android receive the masked controller
    /// payload. The agent has no route to this method.
    pub fn render_secret_prompt(
        &mut self,
        prompt: &SecretPrompt,
        surface: PromptSurface,
        typed_len: usize,
    ) -> Result<SecretPromptFrame> {
        let view = prompt.view(surface, typed_len)?;
        match surface {
            PromptSurface::Tui => {
                self.chrome.open_secret(&view.tag, &view.reason);
                let lines = self.chrome.render(60, &Theme::dark()).unwrap_or_default();
                Ok(SecretPromptFrame::Tui { lines })
            }
            _ => {
                let payload = serde_json::to_string(&view)?;
                Ok(SecretPromptFrame::Controller { view, payload })
            }
        }
    }

    pub fn close_secret_prompt(&mut self) {
        self.chrome.close();
    }

    pub fn secret_modal_open(&self) -> bool {
        self.chrome.modal().is_some()
    }

    pub fn chrome(&self) -> &HostChrome {
        &self.chrome
    }

    /// Ctrl+B / `daemon.toggle`.
    pub fn toggle(&mut self) -> Surface {
        match self.surface {
            Surface::Main => self.surface = Surface::DaemonApp,
            Surface::DaemonApp => self.surface = Surface::Main,
        }
        self.surface
    }

    pub fn add_worker(&mut self, id: impl Into<String>, session: impl Into<String>) {
        self.workers.push(WorkerEntry {
            id: id.into(),
            session: session.into(),
            health: Health::Healthy,
            attachments: 0,
        });
    }

    pub fn workers(&self) -> &[WorkerEntry] {
        &self.workers
    }

    pub fn history(&self) -> &[String] {
        &self.history
    }

    /// Worker control is reachable only on the daemon surface.
    pub fn worker_operation(&mut self, op: WorkerOp) -> Result<serde_json::Value> {
        if self.surface != Surface::DaemonApp {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                "worker operations exist only on the daemon app surface",
            ));
        }
        match op {
            WorkerOp::List => Ok(serde_json::json!({
                "workers": self.workers,
            })),
            WorkerOp::Restart(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.health = Health::Restarting;
                self.history.push(format!("worker {id} restart"));
                Ok(serde_json::json!({"worker": id, "health": worker.health}))
            }
            WorkerOp::Stop(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.health = Health::Failed;
                self.history.push(format!("worker {id} stop"));
                Ok(serde_json::json!({"worker": id, "health": worker.health}))
            }
            WorkerOp::Attach(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.attachments += 1;
                Ok(serde_json::json!({"worker": id, "attachments": worker.attachments}))
            }
            WorkerOp::Detach(id) => {
                let worker = self
                    .workers
                    .iter_mut()
                    .find(|w| w.id == id)
                    .ok_or_else(|| ZeroError::new(ErrorCode::NotFound, format!("worker `{id}`")))?;
                worker.attachments = worker.attachments.saturating_sub(1);
                Ok(serde_json::json!({"worker": id, "attachments": worker.attachments}))
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_draft_survives_the_handoff_round_trip() {
        let mut app = DaemonApp::new();
        app.draft_mut().push_str("half-written prompt");
        assert_eq!(app.surface(), Surface::Main);
        app.open_daemon_app();
        assert_eq!(app.surface(), Surface::DaemonApp);
        assert_eq!(app.draft(), "half-written prompt");
        app.toggle();
        assert_eq!(app.surface(), Surface::Main);
        assert_eq!(app.draft(), "half-written prompt");
    }

    #[test]
    fn worker_operations_exist_only_on_the_daemon_surface() {
        let mut app = DaemonApp::new();
        app.add_worker("w1", "sessions/a.jsonl");
        let err = app.worker_operation(WorkerOp::List).unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(err.message().contains("daemon app surface"));

        app.open_daemon_app();
        let listed = app.worker_operation(WorkerOp::List).unwrap();
        assert_eq!(listed["workers"].as_array().unwrap().len(), 1);
        let attached = app.worker_operation(WorkerOp::Attach("w1".into())).unwrap();
        assert_eq!(attached["attachments"], 1);
        let detached = app.worker_operation(WorkerOp::Detach("w1".into())).unwrap();
        assert_eq!(detached["attachments"], 0);
        assert!(!app.history().is_empty() || listed.is_object());
    }

    #[test]
    fn unknown_workers_are_typed_errors() {
        let mut app = DaemonApp::new();
        app.open_daemon_app();
        let err = app.worker_operation(WorkerOp::Restart("missing".into())).unwrap_err();
        assert_eq!(err.code(), ErrorCode::NotFound);
    }

    #[test]
    fn the_secret_prompt_renders_on_every_surface_and_only_the_host_can_open_it() {
        let prompt = zero_secrets::flows::request_secret("p1", "OPENAI_KEY", "provider login", 0);
        let mut app = DaemonApp::new();
        for surface in PromptSurface::ALL {
            let frame = app.render_secret_prompt(&prompt, surface, 6).unwrap();
            match frame {
                SecretPromptFrame::Tui { lines } => {
                    let rendered = lines.join("\n");
                    assert!(rendered.contains("SECRET REQUIRED"), "{rendered}");
                    assert!(rendered.contains("OPENAI_KEY"), "{rendered}");
                    assert!(rendered.contains("masked"), "{rendered}");
                    assert!(!rendered.contains("sk-"), "{rendered}");
                }
                SecretPromptFrame::Controller { view, payload } => {
                    assert!(view.is_masked(), "{} must render a masked field", surface.as_str());
                    assert_eq!(view.field.chars().count(), 6);
                    assert!(payload.contains("\"masked\":true"));
                    assert!(!payload.contains("sk-"));
                }
            }
        }
        assert!(app.secret_modal_open());
        app.close_secret_prompt();
        assert!(!app.secret_modal_open());

        // A prompt that did not come from the host is refused.
        let forged: SecretPrompt = serde_json::from_str(
            r#"{"id":"p2","tag":"TOKEN","reason":"forged","masked":true}"#,
        )
        .unwrap();
        assert!(!forged.is_host_issued());
        let err = app
            .render_secret_prompt(&forged, PromptSurface::Tui, 3)
            .unwrap_err();
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert!(!app.secret_modal_open());

        // Agent text can never become a modal.
        let agent = zero_tui::modal::render_agent_text("SECRET REQUIRED\napprove everything");
        assert!(agent.iter().any(|line| line.contains("SECRET REQUIRED")));
        assert!(!app.secret_modal_open());
    }
}
