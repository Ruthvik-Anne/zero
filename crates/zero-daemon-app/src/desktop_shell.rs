//! Desktop shell (T-DSK-01, ACT-01, features.md 6.1).
//!
//! The desktop app is a thin host around the local UI. It renders the same
//! loopback page the local web surface serves (ACT-16) using the operating
//! system's own webview, and it renders the same action registry the TUI, the
//! web surface, and Android render (ACT-01). Three rules hold:
//!
//! - **System webview only.** [`EngineSource::Bundled`] is refused with
//!   `zero.pol.denied`: Zero never ships a browser engine. The requested
//!   [`WebviewKind`] must be the one [`webview_for_platform`] reports for the
//!   current OS; a mismatch or a platform without a system webview is a typed
//!   [`ErrorCode::Unsupported`] carrying install guidance, never a silent
//!   fallback.
//! - **Loopback only.** [`ShellConfig::validate`] reuses
//!   [`crate::webui::validate_bind`], so the desktop shell cannot point the
//!   webview at a public listener.
//! - **No second registry.** [`action_registry`] returns the shared entries in
//!   the same order as [`crate::shared_ui::SharedUiState`]'s palette, and
//!   [`DesktopShell::prepare`] hands exactly those entries to the listener.
//!
//! [`DesktopShell::prepare`] builds a [`ShellPlan`] but launches nothing: the
//! host opens the system webview at [`ShellPlan::url_with_token`]. The token is
//! single use (see [`crate::webui`]) and appears in no log line or `Debug`
//! output.

use std::fmt;

use serde::{Deserialize, Serialize};
use zero_actions::{ActionRecord, ActionRegistry};
use zero_types::error::{ErrorCode, Result, ZeroError};

use crate::webui::{validate_bind, LocalWebUi, OneTimeToken, TokenState, WebUiConfig, WebUiOutcome};

/// Cap on the desktop window title, in characters.
pub const MAX_WINDOW_TITLE_CHARS: usize = 120;

/// The system webview engine the desktop shell may use.
///
/// There is deliberately no bundled variant: a browser engine is an OS
/// component, not an artifact Zero ships. See [`EngineSource`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum WebviewKind {
    /// Microsoft Edge WebView2 on Windows.
    #[serde(rename = "webview2")]
    WebView2,
    /// WKWebView on macOS.
    #[serde(rename = "wkwebview")]
    WkWebView,
    /// WebKitGTK on Linux.
    #[serde(rename = "webkitgtk")]
    WebKitGtk,
}

impl WebviewKind {
    /// Every system engine the shell knows, in platform order.
    pub const ALL: [WebviewKind; 3] = [
        WebviewKind::WebView2,
        WebviewKind::WkWebView,
        WebviewKind::WebKitGtk,
    ];

    /// Stable identifier used in config, logs, and the launch line.
    pub fn as_str(self) -> &'static str {
        match self {
            WebviewKind::WebView2 => "webview2",
            WebviewKind::WkWebView => "wkwebview",
            WebviewKind::WebKitGtk => "webkitgtk",
        }
    }

    /// The install or platform guidance shown when this engine cannot run here.
    /// It names the prerequisite; it never offers to download an engine into the
    /// Zero install.
    pub fn install_guidance(self) -> &'static str {
        match self {
            WebviewKind::WebView2 => {
                "install the Microsoft Edge WebView2 Runtime (Evergreen) for Windows, then retry; \
                 Zero ships no browser engine"
            }
            WebviewKind::WkWebView => {
                "WkWebView is part of macOS, so run the macOS build on macOS and retry; \
                 Zero ships no browser engine"
            }
            WebviewKind::WebKitGtk => {
                "install the WebKitGTK 2.x runtime package for your distribution \
                 (for example libwebkit2gtk-4.1), then retry; Zero ships no browser engine"
            }
        }
    }
}

/// Whether the engine comes from the operating system or would be shipped with
/// the app. Only [`EngineSource::System`] is allowed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineSource {
    System,
    Bundled,
}

impl EngineSource {
    pub fn as_str(self) -> &'static str {
        match self {
            EngineSource::System => "system",
            EngineSource::Bundled => "bundled",
        }
    }
}

/// The system webview for the current OS.
///
/// `None` means this platform has no desktop-shell target. The caller must
/// surface [`WebviewKind::install_guidance`] or a platform explanation; it must
/// not substitute a bundled engine.
pub const fn webview_for_platform() -> Option<WebviewKind> {
    #[cfg(target_os = "windows")]
    {
        Some(WebviewKind::WebView2)
    }
    #[cfg(target_os = "macos")]
    {
        Some(WebviewKind::WkWebView)
    }
    #[cfg(target_os = "linux")]
    {
        Some(WebviewKind::WebKitGtk)
    }
    #[cfg(not(any(target_os = "windows", target_os = "macos", target_os = "linux")))]
    {
        None
    }
}

/// One desktop shell configuration: which system webview, which loopback UI,
/// and the window title.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellConfig {
    pub webview: WebviewKind,
    pub ui: WebUiConfig,
    pub window_title: String,
    pub engine_source: EngineSource,
}

impl ShellConfig {
    /// The shell this platform can actually run: the system webview, a loopback
    /// UI on an ephemeral port, and `title`.
    pub fn for_platform(title: impl Into<String>) -> Result<Self> {
        let webview = webview_for_platform().ok_or_else(|| {
            ZeroError::new(
                ErrorCode::Unsupported,
                format!(
                    "no system webview is available on `{}`; Zero ships no browser engine and \
                     has no desktop-shell target here",
                    std::env::consts::OS
                ),
            )
        })?;
        let config = Self {
            webview,
            ui: WebUiConfig::loopback(0),
            window_title: title.into(),
            engine_source: EngineSource::System,
        };
        config.validate()?;
        Ok(config)
    }

    /// Refuse a bundled engine, a non-loopback UI bind, an unusable title, or a
    /// webview that is not the current platform's system engine.
    ///
    /// A wrong-platform or unavailable engine is [`ErrorCode::Unsupported`] with
    /// install guidance, not a hidden fallback to another engine.
    pub fn validate(&self) -> Result<()> {
        if self.engine_source == EngineSource::Bundled {
            return Err(ZeroError::new(
                ErrorCode::PolicyDenied,
                "no bundled browser engine: the desktop shell renders in the system webview \
                 (WebView2, WkWebView, or WebKitGTK) and never ships one",
            ));
        }

        // The desktop webview opens the same loopback listener as the web
        // surface, so it inherits that policy unchanged.
        validate_bind(self.ui.bind)?;
        self.ui.validate()?;

        validate_window_title(&self.window_title)?;

        match webview_for_platform() {
            Some(supported) if supported == self.webview => Ok(()),
            Some(supported) => Err(ZeroError::new(
                ErrorCode::Unsupported,
                format!(
                    "webview `{}` cannot run on `{}`, where the system engine is `{}`. {}",
                    self.webview.as_str(),
                    std::env::consts::OS,
                    supported.as_str(),
                    self.webview.install_guidance()
                ),
            )),
            None => Err(ZeroError::new(
                ErrorCode::Unsupported,
                format!(
                    "no system webview is available on `{}`; Zero ships no browser engine. {}",
                    std::env::consts::OS,
                    self.webview.install_guidance()
                ),
            )),
        }
    }
}

fn validate_window_title(title: &str) -> Result<()> {
    if title.trim().is_empty() {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "desktop window title must not be empty",
        ));
    }
    let chars = title.chars().count();
    if chars > MAX_WINDOW_TITLE_CHARS {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            format!(
                "desktop window title is {chars} characters; the cap is {MAX_WINDOW_TITLE_CHARS}"
            ),
        ));
    }
    if title.chars().any(char::is_control) {
        return Err(ZeroError::new(
            ErrorCode::InvalidInput,
            "desktop window title must not contain control characters",
        ));
    }
    Ok(())
}

/// A prepared, not-yet-opened desktop window.
///
/// The plan owns the loopback listener, so the page is live as soon as the host
/// opens [`ShellPlan::url_with_token`]. `url` is the token-free address; `token`
/// is the single-use token that was issued for it. See [`ShellPlan::render_launch`].
pub struct ShellPlan {
    pub webview: WebviewKind,
    /// The loopback address as a URL, without a token. Safe to log.
    pub url: String,
    /// The one-time token issued for this plan. `Debug` redacts the value; the
    /// listener's own copy is what `authorize` spends.
    pub token: OneTimeToken,
    /// The shared registry entries, in the shared UI's order (ACT-01).
    pub actions: Vec<ActionRecord>,
    ui: LocalWebUi,
}

impl ShellPlan {
    /// The one-time URL the host hands to the system webview. This is the only
    /// place the token value appears; never log it.
    pub fn url_with_token(&self) -> String {
        self.ui.url()
    }

    /// The address the loopback listener actually bound.
    pub fn local_addr(&self) -> std::net::SocketAddr {
        self.ui.local_addr()
    }

    /// The listener's view of the token: `active`, `used`, or `expired`.
    pub fn token_state(&self, now_ms: u64) -> TokenState {
        self.ui.token_state(now_ms)
    }

    /// Accept and answer one connection. The host's webview loop drives this;
    /// tests call it directly.
    pub fn handle_once(&mut self) -> Result<WebUiOutcome> {
        self.ui.handle_once()
    }

    /// A deterministic, token-free launch line for logging:
    /// `shell=desktop webview=<engine> url=<loopback url>`.
    pub fn render_launch(&self) -> String {
        format!(
            "shell=desktop webview={} url={}",
            self.webview.as_str(),
            self.url
        )
    }
}

impl fmt::Debug for ShellPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // `token`'s own `Debug` prints the value as `<redacted>`, and the URL
        // carrying the token is never part of this or any other log line.
        f.debug_struct("ShellPlan")
            .field("webview", &self.webview)
            .field("url", &self.url)
            .field("token", &self.token)
            .field("actions", &self.actions.len())
            .finish()
    }
}

/// The desktop shell host. It holds one validated config and knows how to build
/// the launch plan; it never launches a process.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DesktopShell {
    config: ShellConfig,
}

impl DesktopShell {
    /// Validate and hold a shell config. The same checks run again in
    /// [`DesktopShell::prepare`], because a struct literal can be rebuilt.
    pub fn new(config: ShellConfig) -> Result<Self> {
        config.validate()?;
        Ok(Self { config })
    }

    pub fn config(&self) -> &ShellConfig {
        &self.config
    }

    /// Build the launch plan: a loopback listener serving the shared registry
    /// behind a fresh one-time token, plus the system webview kind the host
    /// opens. No process is launched and no public listener exists.
    pub fn prepare(config: ShellConfig) -> Result<ShellPlan> {
        config.validate()?;
        let actions = action_registry();
        let ui = LocalWebUi::start_with_actions(config.ui.clone(), actions.clone())?;
        let token = ui.token();
        let url = ui.bind_url();
        Ok(ShellPlan {
            webview: config.webview,
            url,
            token,
            actions,
            ui,
        })
    }

    /// The same entries [`action_registry`] returns. Present so callers that
    /// hold the shell can read the registry without importing the free function.
    pub fn action_registry() -> Vec<ActionRecord> {
        action_registry()
    }
}

/// The action registry the desktop shell renders, in the shared UI's palette
/// order: category, then title, then id.
///
/// This is the one `zero-actions` registry; the shell defines no command of its
/// own (ACT-01). The order matches
/// [`crate::shared_ui::SharedUiState::from_registry`] exactly, and a test pins
/// that.
pub fn action_registry() -> Vec<ActionRecord> {
    action_registry_from(&zero_actions::core_registry())
}

fn action_registry_from(registry: &ActionRegistry) -> Vec<ActionRecord> {
    let mut actions: Vec<ActionRecord> = registry.actions().cloned().collect();
    actions.sort_by(|a, b| {
        a.category
            .cmp(&b.category)
            .then(a.title.cmp(&b.title))
            .then(a.id.cmp(&b.id))
    });
    actions
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpStream;
    use std::time::Duration;

    use zero_actions::core_registry;

    use crate::shared_ui::SharedUiState;

    fn base() -> ShellConfig {
        ShellConfig::for_platform("Zero").expect("tests run on a platform with a system webview")
    }

    fn current() -> WebviewKind {
        webview_for_platform().expect("tests run on a platform with a system webview")
    }

    fn other_webview() -> WebviewKind {
        WebviewKind::ALL
            .into_iter()
            .find(|kind| *kind != current())
            .expect("there is more than one known engine")
    }

    fn token_value(plan: &ShellPlan) -> String {
        plan.url_with_token()
            .split_once("token=")
            .expect("the token URL carries the token")
            .1
            .to_string()
    }

    fn token_path(plan: &ShellPlan) -> String {
        let url = plan.url_with_token();
        let rest = url.strip_prefix("http://").expect("loopback http URL");
        let (_, query) = rest.split_once('/').expect("the URL has a path");
        format!("/{query}")
    }

    fn fetch(plan: &mut ShellPlan, target: &str) -> (u16, String) {
        let addr = plan.local_addr();
        let mut client = TcpStream::connect(addr).expect("connect to the loopback listener");
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("read timeout");
        client
            .write_all(
                format!("GET {target} HTTP/1.1\r\nHost: {addr}\r\nConnection: close\r\n\r\n")
                    .as_bytes(),
            )
            .expect("write request");
        let outcome = plan.handle_once().expect("answer one connection");
        let mut raw = String::new();
        let _ = client.read_to_string(&mut raw);
        (outcome.status, raw)
    }

    #[test]
    fn a_bundled_browser_engine_is_refused() {
        let mut config = base();
        config.engine_source = EngineSource::Bundled;
        let err = config.validate().expect_err("a bundled engine must be refused");
        assert_eq!(err.code(), ErrorCode::PolicyDenied);
        assert_eq!(err.code().as_str(), "zero.pol.denied");
        assert!(
            err.message().contains("no bundled browser engine"),
            "{}",
            err.message()
        );

        // The host refuses it too, before a listener exists.
        assert!(DesktopShell::new(config.clone()).is_err());
        let err = DesktopShell::prepare(config).expect_err("prepare must refuse");
        assert_eq!(err.code(), ErrorCode::PolicyDenied);

        // Only the system source is accepted, and it round-trips as such.
        let mut system = base();
        system.engine_source = EngineSource::System;
        system.validate().expect("the system engine is the shipping case");
        assert_eq!(EngineSource::System.as_str(), "system");
        assert_eq!(EngineSource::Bundled.as_str(), "bundled");
    }

    #[test]
    fn the_system_engine_is_accepted_on_the_matching_platform() {
        let config = base();
        assert_eq!(config.webview, current());
        config.validate().expect("the current platform's engine must pass");

        let plan = DesktopShell::prepare(config.clone()).expect("the shell prepares");
        assert_eq!(plan.webview, current());
        assert!(plan.url.starts_with("http://127.0.0.1:"));
        assert!(!plan.url.contains("token="), "the safe URL hides the token");
        assert_eq!(plan.actions.len(), action_registry().len());
        assert!(!plan.actions.is_empty(), "the shared registry is not empty");
    }

    #[test]
    fn a_non_loopback_ui_bind_is_refused() {
        for bind in ["0.0.0.0:0", "[::]:0", "192.168.1.20:8080"] {
            let mut config = base();
            config.ui.bind = bind.parse().expect("socket address");
            let err = config.validate().expect_err(bind);
            assert_eq!(err.code(), ErrorCode::PolicyDenied, "{bind}");
            assert!(err.message().contains("loopback"), "{bind}: {}", err.message());
            assert!(DesktopShell::prepare(config).is_err(), "{bind} must not prepare");
        }
    }

    #[test]
    fn a_wrong_platform_webview_is_unsupported_with_install_guidance() {
        let wrong = other_webview();
        let mut config = base();
        config.webview = wrong;
        let err = config.validate().expect_err("a foreign engine must be refused");
        assert_eq!(err.code(), ErrorCode::Unsupported);
        assert_eq!(err.code().as_str(), "zero.fnd.unsupported");
        assert!(
            err.message().contains(wrong.install_guidance()),
            "{}",
            err.message()
        );
        assert!(
            err.message().contains("Zero ships no browser engine"),
            "{}",
            err.message()
        );

        // No hidden fallback: the host refuses rather than picking the system
        // engine on the caller's behalf.
        let err = DesktopShell::prepare(config).expect_err("prepare must refuse");
        assert_eq!(err.code(), ErrorCode::Unsupported);
    }

    #[test]
    fn the_action_registry_matches_the_shared_palette_entries_and_order() {
        let registry = core_registry();
        let shared = SharedUiState::from_registry(&registry, "auto");
        let desktop = action_registry();

        assert_eq!(shared.palette.entries.len(), desktop.len());
        for (entry, record) in shared.palette.entries.iter().zip(&desktop) {
            assert_eq!(entry.id, record.id);
            assert_eq!(entry.title, record.title);
            assert_eq!(entry.category, record.category);
            assert!(entry.keys.is_empty(), "registry entries are not keyed here");
        }

        // The associated function is the same list.
        let via_shell: Vec<String> = DesktopShell::action_registry()
            .into_iter()
            .map(|record| record.id)
            .collect();
        let via_free: Vec<String> = desktop.into_iter().map(|record| record.id).collect();
        assert_eq!(via_shell, via_free);

        // No duplicate ids: the registry is keyed, and the shell adds nothing.
        let mut ids = via_free.clone();
        ids.sort();
        ids.dedup();
        assert_eq!(ids.len(), via_free.len());
    }

    #[test]
    fn the_one_time_token_is_issued_and_single_use() {
        let mut plan = DesktopShell::prepare(base()).expect("prepare");
        let target = token_path(&plan);
        let value = token_value(&plan);
        assert_eq!(value.len(), 64, "32 OS-entropy bytes as hex");
        assert!(value.chars().all(|c| c.is_ascii_hexdigit()));

        let (first, raw) = fetch(&mut plan, &target);
        assert_eq!(first, 200);
        assert!(raw.starts_with("HTTP/1.1 200 OK\r\n"), "{raw}");
        assert!(!raw.is_empty());
        assert_eq!(
            plan.token_state(u64::MAX / 2),
            TokenState::Used,
            "the first authorized request spends the token"
        );

        let (second, raw) = fetch(&mut plan, &target);
        assert_eq!(second, 401);
        assert!(raw.starts_with("HTTP/1.1 401 Unauthorized\r\n"), "{raw}");
        assert_eq!(plan.token_state(u64::MAX / 2), TokenState::Used);
    }

    #[test]
    fn the_launch_line_and_debug_hide_the_token() {
        let plan = DesktopShell::prepare(base()).expect("prepare");
        let value = token_value(&plan);
        let launch = plan.render_launch();
        assert_eq!(launch, plan.render_launch(), "the line is deterministic");
        assert!(launch.starts_with("shell=desktop webview="));
        assert!(launch.contains(&format!("webview={}", plan.webview.as_str())));
        assert!(launch.contains(&format!("url={}", plan.url)));
        assert!(!launch.contains(&value), "the launch line must not log the token");
        assert!(!launch.contains("token="));

        let debug = format!("{plan:?}");
        assert!(!debug.contains(&value), "Debug must redact the token");
        assert!(!debug.contains(&plan.url_with_token()));
        assert!(debug.contains("<redacted>"));
    }

    #[test]
    fn the_window_title_is_bounded() {
        let mut config = base();
        config.window_title = String::new();
        assert_eq!(
            config.validate().expect_err("empty").code(),
            ErrorCode::InvalidInput
        );

        config.window_title = "   ".into();
        assert_eq!(
            config.validate().expect_err("blank").code(),
            ErrorCode::InvalidInput
        );

        config.window_title = "Zero\nsecond line".into();
        assert_eq!(
            config.validate().expect_err("control character").code(),
            ErrorCode::InvalidInput
        );

        config.window_title = "t".repeat(MAX_WINDOW_TITLE_CHARS + 1);
        let err = config.validate().expect_err("too long");
        assert_eq!(err.code(), ErrorCode::InvalidInput);
        assert!(err.message().contains(&MAX_WINDOW_TITLE_CHARS.to_string()));

        config.window_title = "t".repeat(MAX_WINDOW_TITLE_CHARS);
        config.validate().expect("the bound itself is allowed");

        config.window_title = " Zero ".into();
        config.validate().expect("a non-blank title is allowed");
    }

    #[test]
    fn the_config_round_trips_through_serde_and_keeps_the_engine_source() {
        let mut config = base();
        config.window_title = "Zero desktop".into();
        let json = serde_json::to_string(&config).expect("serialize");
        let back: ShellConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back, config);
        assert_eq!(back.engine_source, EngineSource::System);
        assert!(json.contains("\"system\""));

        // Serde is not validation: a bundled config round-trips and is refused
        // by `validate`, which keeps the policy at the one gate.
        let mut bundled = config.clone();
        bundled.engine_source = EngineSource::Bundled;
        let json = serde_json::to_string(&bundled).expect("serialize");
        let back: ShellConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.engine_source, EngineSource::Bundled);
        assert!(json.contains("\"bundled\""));
        assert_eq!(
            back.validate().expect_err("still refused").code(),
            ErrorCode::PolicyDenied
        );

        // Engine names are a stable wire form.
        let names: Vec<String> = WebviewKind::ALL
            .iter()
            .map(|kind| serde_json::to_string(kind).expect("serialize"))
            .collect();
        assert_eq!(names, ["\"webview2\"", "\"wkwebview\"", "\"webkitgtk\""]);
    }

    #[test]
    fn no_browser_engine_binary_or_remote_asset_is_bundled() {
        // The shell renders in the OS webview, so the crate must not carry an
        // engine binary, a browser snapshot, or a remote asset reference.
        let manifest = std::path::Path::new(env!("CARGO_MANIFEST_DIR"));
        let mut stack = vec![manifest.to_path_buf()];
        while let Some(dir) = stack.pop() {
            for entry in std::fs::read_dir(&dir).expect("read crate directory") {
                let entry = entry.expect("crate entry");
                let path = entry.path();
                let name = entry.file_name().to_string_lossy().to_ascii_lowercase();
                if entry.file_type().expect("entry type").is_dir() {
                    assert!(
                        !matches!(name.as_str(), "node_modules" | "chromium" | "electron"),
                        "a bundled engine directory is present: {}",
                        path.display()
                    );
                    stack.push(path);
                    continue;
                }
                for engine in ["chromium", "electron", "webview2loader", "libcef", "cefsharp"] {
                    assert!(
                        !name.contains(engine),
                        "a bundled engine asset is present: {}",
                        path.display()
                    );
                }
                for ext in ["dll", "dylib", "so", "asar", "pak"] {
                    assert!(
                        !name.ends_with(&format!(".{ext}")),
                        "a bundled engine binary is present: {}",
                        path.display()
                    );
                }
            }
        }

        // The production half of this module (above `#[cfg(test)]`) must not
        // reference a bundled engine, a download, or a child process.
        let source = include_str!("desktop_shell.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("the module has a production section");
        let lower = production.to_ascii_lowercase();
        for marker in [
            "electron",
            "chromium",
            "libcef",
            "cefsharp",
            "webview2loader",
            "node_modules",
            ".dll",
            ".dylib",
            ".asar",
            ".pak",
        ] {
            assert!(
                !lower.contains(marker),
                "the desktop shell source references a bundled engine: {marker}"
            );
        }
        assert!(!production.contains("std::process"));
        assert!(!production.contains("Command::new"));

        // Any URL literal is loopback; there is no remote asset host.
        for scheme in ["http://", "https://"] {
            let mut rest = production;
            while let Some(index) = rest.find(scheme) {
                let after = &rest[index + scheme.len()..];
                let host: String = after
                    .chars()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | ':' | '[' | ']'))
                    .collect();
                assert!(
                    host.starts_with("127.0.0.1") || host.starts_with("[::1]"),
                    "the desktop shell source references a non-loopback URL: {scheme}{host}"
                );
                rest = after;
            }
        }
    }
}
