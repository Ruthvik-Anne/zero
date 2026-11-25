//! Service units and the service lifecycle seam (T-INST-05).
//!
//! Requirements: INST-05 (start, stop, and status without a TTY) and INST-09
//! (install systemd, Windows service, and launchd units).
//!
//! # What is modelled here
//!
//! A [`ServiceSpec`] describes one background agent service: the platform, the
//! absolute binary path and arguments, the working and log directories, an
//! optional service user, a [`RestartPolicy`], and a small environment map.
//! [`render_unit`] turns it into the text of the platform's unit:
//!
//! | Platform | Rendered file |
//! |---|---|
//! | [`ServicePlatform::Systemd`] | a systemd unit (`[Unit]`, `[Service]`, `[Install]`) |
//! | [`ServicePlatform::WindowsService`] | a JSON service wrapper config |
//! | [`ServicePlatform::Launchd`] | a launchd property list |
//!
//! Rendering is deterministic and validates first, so a relative path, an
//! over-long argument, an unsupported user, or a secret-looking environment
//! name is a typed refusal and never text. The property list is XML-escaped and
//! the JSON is JSON-escaped; systemd arguments and environment pairs are quoted
//! when they need it.
//!
//! # Management seam
//!
//! This module never runs a command and never writes to a system directory.
//! Installation, start, stop, status, and removal go through the injected
//! [`ServiceManager`] seam, so a real manager is free to call the platform
//! host (`systemctl`, the Windows service control manager, or `launchctl`)
//! while the tests use scripted managers.
//!
//! [`manage`] validates and renders a spec, asks the manager to install the
//! unit at the platform's default path, and reports the observed status.
//! [`lifecycle`] performs install, start, status, stop, and a final status and
//! returns a [`LifecycleReport`]. A failed start is reported once; it is never
//! retried here.
//!
//! # Non-interactivity
//!
//! Nothing in this module reads a terminal, prompts, or waits for input, so the
//! service path is safe in CI (INST-05). The host commands behind the manager
//! are the only place a TTY could ever be involved, and a manager is expected
//! to pass non-interactive flags.

use std::collections::BTreeMap;
use std::fmt;
use std::path::{Path, PathBuf};

/// The stable service name used for start, stop, and status calls.
pub const SERVICE_NAME: &str = "zero";

/// The human-readable service name written into units.
pub const SERVICE_DISPLAY_NAME: &str = "Zero";

/// The launchd job label.
pub const LAUNCHD_LABEL: &str = "com.zero.agent";

/// The systemd unit file name.
pub const SYSTEMD_UNIT: &str = "zero.service";

/// The Windows service wrapper config file name.
pub const WINDOWS_CONFIG: &str = "zero-service.json";

/// The launchd property list file name.
pub const LAUNCHD_PLIST: &str = "com.zero.agent.plist";

/// Upper bound on service arguments.
pub const MAX_SERVICE_ARGS: usize = 64;

/// Upper bound on one service argument.
pub const MAX_SERVICE_ARG_BYTES: usize = 512;

/// Upper bound on environment entries in one unit.
pub const MAX_SERVICE_ENV_ENTRIES: usize = 32;

/// Upper bound on one environment variable name.
pub const MAX_SERVICE_ENV_NAME_BYTES: usize = 64;

/// Upper bound on one environment variable value.
pub const MAX_SERVICE_ENV_VALUE_BYTES: usize = 512;

/// Upper bound on a binary, working, or log path.
pub const MAX_SERVICE_PATH_BYTES: usize = 512;

/// Upper bound on a service user name.
pub const MAX_SERVICE_USER_BYTES: usize = 64;

/// The unit format this build can install.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ServicePlatform {
    /// A systemd unit on Linux.
    Systemd,
    /// A Windows service wrapper config.
    WindowsService,
    /// A launchd property list on macOS.
    Launchd,
}

impl ServicePlatform {
    /// Stable platform string, e.g. `windows_service`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Systemd => "systemd",
            Self::WindowsService => "windows_service",
            Self::Launchd => "launchd",
        }
    }

    /// Whether this platform uses Windows path syntax.
    pub const fn is_windows(self) -> bool {
        matches!(self, Self::WindowsService)
    }
}

/// The unit file name for a platform.
pub fn unit_file_name(platform: ServicePlatform) -> &'static str {
    match platform {
        ServicePlatform::Systemd => SYSTEMD_UNIT,
        ServicePlatform::WindowsService => WINDOWS_CONFIG,
        ServicePlatform::Launchd => LAUNCHD_PLIST,
    }
}

/// The default location an installer writes the unit to before registering it.
///
/// The module only names the path; writing to a system directory and
/// registering the unit is host work behind [`ServiceManager::install`].
pub fn default_unit_path(platform: ServicePlatform) -> PathBuf {
    match platform {
        ServicePlatform::Systemd => PathBuf::from("/etc/systemd/system/zero.service"),
        ServicePlatform::WindowsService => PathBuf::from(r"C:\ProgramData\Zero\zero-service.json"),
        ServicePlatform::Launchd => PathBuf::from("/Library/LaunchDaemons/com.zero.agent.plist"),
    }
}

/// What to do when the service exits.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RestartPolicy {
    /// Always restart.
    Always,
    /// Restart only after a failure.
    OnFailure,
    /// Never restart.
    Never,
}

impl RestartPolicy {
    /// Stable policy string, e.g. `on_failure`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnFailure => "on_failure",
            Self::Never => "never",
        }
    }

    /// The systemd `Restart=` directive.
    const fn systemd_directive(self) -> &'static str {
        match self {
            Self::Always => "always",
            Self::OnFailure => "on-failure",
            Self::Never => "no",
        }
    }
}

/// One service unit to render and manage.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// The platform whose unit format is rendered and whose host installs it.
    pub platform: ServicePlatform,
    /// Absolute path to the service binary.
    pub binary_path: PathBuf,
    /// Arguments after the binary, bounded and free of control characters.
    pub args: Vec<String>,
    /// Absolute working directory.
    pub working_dir: PathBuf,
    /// Absolute directory for the service log files.
    pub log_dir: PathBuf,
    /// An optional service user. systemd and launchd only.
    pub user: Option<String>,
    /// The restart policy.
    pub restart: RestartPolicy,
    /// A small, non-secret environment map. `BTreeMap` keeps output stable.
    pub env: BTreeMap<String, String>,
}

impl ServiceSpec {
    /// A spec with no arguments, no user, no environment, and
    /// [`RestartPolicy::OnFailure`].
    pub fn new(
        platform: ServicePlatform,
        binary_path: impl Into<PathBuf>,
        working_dir: impl Into<PathBuf>,
        log_dir: impl Into<PathBuf>,
    ) -> Self {
        Self {
            platform,
            binary_path: binary_path.into(),
            args: Vec::new(),
            working_dir: working_dir.into(),
            log_dir: log_dir.into(),
            user: None,
            restart: RestartPolicy::OnFailure,
            env: BTreeMap::new(),
        }
    }

    /// Validate the platform, paths, arguments, user, and environment.
    pub fn validate(&self) -> ServiceResult<()> {
        validate_path(self.platform, &self.binary_path, "binary_path")?;
        validate_path(self.platform, &self.working_dir, "working_dir")?;
        validate_path(self.platform, &self.log_dir, "log_dir")?;
        validate_args(&self.args)?;
        validate_env(&self.env)?;
        if let Some(user) = &self.user {
            if self.platform == ServicePlatform::WindowsService {
                return Err(ServiceError::new(
                    ServiceErrorKind::SpecInvalid,
                    "a Windows service config cannot carry a service user; the service control manager owns the account",
                ));
            }
            validate_user(user)?;
        }
        Ok(())
    }
}

/// The observed state of a service.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ServiceStatus {
    /// The service is running.
    Running,
    /// The service is installed and stopped.
    Stopped,
    /// The service failed, with a bounded reason.
    Failed {
        /// What the manager reported, without secrets.
        reason: String,
    },
}

impl ServiceStatus {
    /// Stable status string, e.g. `failed`.
    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Running => "running",
            Self::Stopped => "stopped",
            Self::Failed { .. } => "failed",
        }
    }

    /// Whether the service is running.
    pub const fn is_running(&self) -> bool {
        matches!(self, Self::Running)
    }

    /// A failed status with a reason.
    pub fn failed(reason: impl Into<String>) -> Self {
        Self::Failed {
            reason: reason.into(),
        }
    }
}

impl fmt::Display for ServiceStatus {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Running => f.write_str("running"),
            Self::Stopped => f.write_str("stopped"),
            Self::Failed { reason } => write!(f, "failed: {reason}"),
        }
    }
}

/// Why a service spec was refused or a manager call failed.
///
/// Kinds are stable strings for logs and tests; they are local to the service
/// path and are not part of the `zero-types` error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServiceErrorKind {
    /// A field is empty, malformed, or inconsistent.
    SpecInvalid,
    /// A binary, working, or log path is not absolute for the target platform.
    PathNotAbsolute,
    /// A count, argument, or value exceeds its bound.
    LimitExceeded,
    /// An environment variable name looks like a secret.
    SecretInEnv,
    /// No unit format exists for the platform.
    Unsupported,
    /// The injected [`ServiceManager`] reported a failure.
    Manager,
}

impl ServiceErrorKind {
    /// Stable kind string, e.g. `secret_in_env`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::SpecInvalid => "spec_invalid",
            Self::PathNotAbsolute => "path_not_absolute",
            Self::LimitExceeded => "limit_exceeded",
            Self::SecretInEnv => "secret_in_env",
            Self::Unsupported => "unsupported",
            Self::Manager => "manager",
        }
    }
}

/// A typed service error with a stable kind and a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceError {
    kind: ServiceErrorKind,
    message: String,
}

impl ServiceError {
    /// Build an error. Public so a [`ServiceManager`] implementation can report
    /// its own failure in the shared type.
    pub fn new(kind: ServiceErrorKind, message: impl Into<String>) -> Self {
        Self {
            kind,
            message: message.into(),
        }
    }

    /// An unsupported-platform error for an OS name.
    pub fn unsupported(os: &str) -> Self {
        Self::new(
            ServiceErrorKind::Unsupported,
            format!(
                "no service unit format is implemented for OS `{os}`; supported: linux (systemd), macos (launchd), windows (service control manager)"
            ),
        )
    }

    /// A manager failure, prefixed with the operation that failed.
    pub fn manager(action: &str, message: impl fmt::Display) -> Self {
        Self::new(
            ServiceErrorKind::Manager,
            format!("service manager `{action}` failed: {message}"),
        )
    }

    /// The stable error kind.
    pub fn kind(&self) -> ServiceErrorKind {
        self.kind
    }

    /// The stable kind string.
    pub fn code(&self) -> &'static str {
        self.kind.as_str()
    }

    /// The human-readable message.
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for ServiceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "zero.service.{}: {}", self.kind.as_str(), self.message)
    }
}

impl std::error::Error for ServiceError {}

/// Result type used by validation and manager calls.
pub type ServiceResult<T> = std::result::Result<T, ServiceError>;

/// The host seam for installing and managing a service.
///
/// The module never executes anything itself: every operation is delegated to
/// an implementation of this trait. `install` receives the path the installer
/// staged the rendered unit at; a real manager writes or registers it and owns
/// the privileges that requires.
pub trait ServiceManager {
    /// Start the named service.
    fn start(&self, name: &str) -> ServiceResult<()>;

    /// Stop the named service.
    fn stop(&self, name: &str) -> ServiceResult<()>;

    /// Report the named service's state.
    fn status(&self, name: &str) -> ServiceResult<ServiceStatus>;

    /// Install (or register) the unit file at `unit_path`.
    fn install(&self, unit_path: &Path) -> ServiceResult<()>;

    /// Remove the named service.
    fn uninstall(&self, name: &str) -> ServiceResult<()>;
}

/// What [`manage`] prepared and observed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceReport {
    /// The platform the unit targets.
    pub platform: ServicePlatform,
    /// The unit file name.
    pub unit_file_name: String,
    /// The default path the unit must occupy for the host to register it.
    pub unit_path: PathBuf,
    /// The rendered unit text, ready to be written at [`Self::unit_path`].
    pub unit: String,
    /// True when the manager accepted the install call.
    pub installed: bool,
    /// The status observed after installation.
    pub status: ServiceStatus,
}

/// The outcome of a full install, start, status, stop, and status cycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LifecycleReport {
    /// The platform the unit targets.
    pub platform: ServicePlatform,
    /// The unit file name.
    pub unit_file_name: String,
    /// True when the manager accepted the install call.
    pub installed: bool,
    /// True when the manager accepted the start call.
    pub started: bool,
    /// The status observed right after the start call.
    pub status: ServiceStatus,
    /// True when the manager accepted the stop call.
    pub stopped: bool,
    /// The status observed after the stop call.
    pub final_status: ServiceStatus,
    /// The first failure, with its operation, or `None` when the whole cycle
    /// succeeded. A failed step stops the cycle; nothing is retried.
    pub failure: Option<String>,
}

/// Detect the platform for the running OS.
///
/// Only systemd (Linux), launchd (macOS), and the Windows service control
/// manager are implemented; anything else is a typed
/// [`ServiceErrorKind::Unsupported`] refusal.
pub fn platform_for_current_os() -> ServiceResult<ServicePlatform> {
    platform_for_os(std::env::consts::OS)
}

/// Map an OS name (`linux`, `macos`, `windows`, ...) to a platform.
pub fn platform_for_os(os: &str) -> ServiceResult<ServicePlatform> {
    match os {
        "linux" => Ok(ServicePlatform::Systemd),
        "macos" => Ok(ServicePlatform::Launchd),
        "windows" => Ok(ServicePlatform::WindowsService),
        other => Err(ServiceError::unsupported(other)),
    }
}

/// Render the platform unit for a spec.
///
/// The spec is validated first, so this returns a typed refusal instead of text
/// for a relative path, an over-long argument, a Windows spec with a user, or a
/// secret-looking environment name. Output is deterministic: the same spec
/// always renders byte-identically.
pub fn render_unit(spec: &ServiceSpec) -> ServiceResult<String> {
    spec.validate()?;
    Ok(match spec.platform {
        ServicePlatform::Systemd => render_systemd(spec),
        ServicePlatform::WindowsService => render_windows(spec),
        ServicePlatform::Launchd => render_launchd(spec),
    })
}

/// Validate and render a spec, install it through the manager, and report the
/// observed status.
///
/// The `platform` argument must match [`ServiceSpec::platform`]. The module
/// renders the unit but does not write to a system directory: the host manager
/// stages it at [`default_unit_path`] and registers it.
pub fn manage(
    platform: ServicePlatform,
    spec: &ServiceSpec,
    manager: &dyn ServiceManager,
) -> ServiceResult<ServiceReport> {
    if spec.platform != platform {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!(
                "the spec targets {} but the request is for {}",
                spec.platform.as_str(),
                platform.as_str()
            ),
        ));
    }
    let unit = render_unit(spec)?;
    let unit_path = default_unit_path(platform);
    manager.install(&unit_path)?;
    let status = manager.status(SERVICE_NAME)?;
    Ok(ServiceReport {
        platform,
        unit_file_name: unit_file_name(platform).to_string(),
        unit_path,
        unit,
        installed: true,
        status,
    })
}

/// Run install, start, status, stop, and a final status for a spec.
///
/// Failures are reported in [`LifecycleReport::failure`] and stop the cycle.
/// A failed start is reported once and is never retried; a failed install never
/// attempts a start; a successful cycle stops the service it started.
pub fn lifecycle(spec: &ServiceSpec, manager: &dyn ServiceManager) -> LifecycleReport {
    let platform = spec.platform;
    let mut report = LifecycleReport {
        platform,
        unit_file_name: unit_file_name(platform).to_string(),
        installed: false,
        started: false,
        status: ServiceStatus::Stopped,
        stopped: false,
        final_status: ServiceStatus::Stopped,
        failure: None,
    };

    if let Err(error) = render_unit(spec) {
        return refused(report, &error);
    }

    if let Err(error) = manager.install(&default_unit_path(platform)) {
        let error = ServiceError::manager("install", error);
        return refused(report, &error);
    }
    report.installed = true;

    if let Err(error) = manager.start(SERVICE_NAME) {
        // One attempt only: a failed start is reported, not retried.
        let error = ServiceError::manager("start", error);
        return refused(report, &error);
    }
    report.started = true;

    report.status = match manager.status(SERVICE_NAME) {
        Ok(status) => status,
        Err(error) => {
            let error = ServiceError::manager("status", error);
            report.failure = Some(error.to_string());
            ServiceStatus::failed(error.to_string())
        }
    };
    if report.failure.is_none() && !report.status.is_running() {
        report.failure = Some(format!(
            "start did not reach the running state (status {})",
            report.status
        ));
    }

    match manager.stop(SERVICE_NAME) {
        Ok(()) => report.stopped = true,
        Err(error) => {
            let error = ServiceError::manager("stop", error);
            if report.failure.is_none() {
                report.failure = Some(error.to_string());
            }
        }
    }

    report.final_status = match manager.status(SERVICE_NAME) {
        Ok(status) => status,
        Err(error) => ServiceStatus::failed(ServiceError::manager("status", error).to_string()),
    };

    report
}

fn refused(mut report: LifecycleReport, error: &ServiceError) -> LifecycleReport {
    report.failure = Some(error.to_string());
    report.status = ServiceStatus::failed(error.to_string());
    report.final_status = report.status.clone();
    report
}

fn validate_path(platform: ServicePlatform, path: &Path, field: &str) -> ServiceResult<()> {
    let Some(text) = path.to_str() else {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!("{field} must be valid UTF-8 because it is written into a unit file"),
        ));
    };
    if text.is_empty() {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!("{field} must not be empty"),
        ));
    }
    if text.len() > MAX_SERVICE_PATH_BYTES {
        return Err(ServiceError::new(
            ServiceErrorKind::LimitExceeded,
            format!(
                "{field} is {} bytes, above the {MAX_SERVICE_PATH_BYTES} byte service limit",
                text.len()
            ),
        ));
    }
    if text.chars().any(char::is_control) {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!("{field} must not contain control characters"),
        ));
    }
    if text.split(['/', '\\']).any(|component| component == "..") {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!("{field} `{text}` must not contain a `..` component"),
        ));
    }
    let absolute = if platform.is_windows() {
        is_windows_absolute(text)
    } else {
        text.starts_with('/')
    };
    if !absolute {
        return Err(ServiceError::new(
            ServiceErrorKind::PathNotAbsolute,
            format!(
                "{field} `{text}` must be an absolute {} path",
                platform.as_str()
            ),
        ));
    }
    Ok(())
}

fn is_windows_absolute(value: &str) -> bool {
    let bytes = value.as_bytes();
    let drive_absolute = bytes.len() >= 3
        && bytes[0].is_ascii_alphabetic()
        && bytes[1] == b':'
        && matches!(bytes[2], b'\\' | b'/');
    drive_absolute || value.starts_with(r"\\")
}

fn validate_args(args: &[String]) -> ServiceResult<()> {
    if args.len() > MAX_SERVICE_ARGS {
        return Err(ServiceError::new(
            ServiceErrorKind::LimitExceeded,
            format!(
                "{} arguments is above the {MAX_SERVICE_ARGS} argument service limit",
                args.len()
            ),
        ));
    }
    for arg in args {
        if arg.is_empty() {
            return Err(ServiceError::new(
                ServiceErrorKind::SpecInvalid,
                "a service argument must not be empty",
            ));
        }
        if arg.len() > MAX_SERVICE_ARG_BYTES {
            return Err(ServiceError::new(
                ServiceErrorKind::LimitExceeded,
                format!(
                    "a service argument is {} bytes, above the {MAX_SERVICE_ARG_BYTES} byte service limit",
                    arg.len()
                ),
            ));
        }
        if arg.chars().any(char::is_control) {
            return Err(ServiceError::new(
                ServiceErrorKind::SpecInvalid,
                "a service argument must not contain control characters",
            ));
        }
    }
    Ok(())
}

fn validate_env(env: &BTreeMap<String, String>) -> ServiceResult<()> {
    if env.len() > MAX_SERVICE_ENV_ENTRIES {
        return Err(ServiceError::new(
            ServiceErrorKind::LimitExceeded,
            format!(
                "{} environment entries is above the {MAX_SERVICE_ENV_ENTRIES} entry service limit",
                env.len()
            ),
        ));
    }
    for (name, value) in env {
        if name.len() > MAX_SERVICE_ENV_NAME_BYTES {
            return Err(ServiceError::new(
                ServiceErrorKind::LimitExceeded,
                format!(
                    "environment name is {} bytes, above the {MAX_SERVICE_ENV_NAME_BYTES} byte service limit",
                    name.len()
                ),
            ));
        }
        if !is_env_name(name) {
            return Err(ServiceError::new(
                ServiceErrorKind::SpecInvalid,
                format!(
                    "environment name `{name}` must start with a letter or `_` and contain only ASCII letters, digits, and `_`"
                ),
            ));
        }
        if looks_like_secret(name) {
            return Err(ServiceError::new(
                ServiceErrorKind::SecretInEnv,
                format!(
                    "environment name `{name}` looks like a secret; service units must not carry credentials or tokens (use the credential store)"
                ),
            ));
        }
        if value.len() > MAX_SERVICE_ENV_VALUE_BYTES {
            return Err(ServiceError::new(
                ServiceErrorKind::LimitExceeded,
                format!(
                    "environment value for `{name}` is {} bytes, above the {MAX_SERVICE_ENV_VALUE_BYTES} byte service limit",
                    value.len()
                ),
            ));
        }
        if value.chars().any(char::is_control) {
            return Err(ServiceError::new(
                ServiceErrorKind::SpecInvalid,
                format!("environment value for `{name}` must not contain control characters"),
            ));
        }
    }
    Ok(())
}

fn is_env_name(name: &str) -> bool {
    let Some(first) = name.as_bytes().first() else {
        return false;
    };
    if !first.is_ascii_alphabetic() && *first != b'_' {
        return false;
    }
    name.bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

/// Secret-looking names are refused by token so `MONKEY` is not caught while
/// `OPENAI_API_KEY` and `GITHUB_TOKEN` are.
fn looks_like_secret(name: &str) -> bool {
    const SECRET_TOKENS: [&str; 8] = [
        "SECRET",
        "TOKEN",
        "PASSWORD",
        "PASSWD",
        "CREDENTIAL",
        "CREDENTIALS",
        "PASSPHRASE",
        "KEY",
    ];
    name.split(|character: char| !character.is_ascii_alphanumeric())
        .filter(|token| !token.is_empty())
        .any(|token| {
            SECRET_TOKENS
                .iter()
                .any(|secret| token.eq_ignore_ascii_case(secret))
        })
}

fn validate_user(user: &str) -> ServiceResult<()> {
    if user.is_empty() {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            "a service user must not be empty",
        ));
    }
    if user.len() > MAX_SERVICE_USER_BYTES {
        return Err(ServiceError::new(
            ServiceErrorKind::LimitExceeded,
            format!(
                "service user is {} bytes, above the {MAX_SERVICE_USER_BYTES} byte service limit",
                user.len()
            ),
        ));
    }
    let Some(first) = user.as_bytes().first() else {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            "a service user must not be empty",
        ));
    };
    if !first.is_ascii_alphanumeric() {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!("service user `{user}` must start with a letter or digit"),
        ));
    }
    if !user
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b'@'))
    {
        return Err(ServiceError::new(
            ServiceErrorKind::SpecInvalid,
            format!(
                "service user `{user}` may contain only letters, digits, `.`, `_`, `-`, and `@`"
            ),
        ));
    }
    Ok(())
}

fn render_systemd(spec: &ServiceSpec) -> String {
    let mut out = String::new();
    out.push_str("[Unit]\n");
    out.push_str(&format!(
        "Description={SERVICE_DISPLAY_NAME} agent service\n"
    ));
    out.push_str("Documentation=man:zero(1)\n\n");
    out.push_str("[Service]\n");
    out.push_str("Type=simple\n");

    let mut exec = systemd_escape_arg(&path_text(&spec.binary_path));
    for arg in &spec.args {
        exec.push(' ');
        exec.push_str(&systemd_escape_arg(arg));
    }
    out.push_str(&format!("ExecStart={exec}\n"));
    out.push_str(&format!(
        "WorkingDirectory={}\n",
        systemd_escape_arg(&path_text(&spec.working_dir))
    ));
    for (name, value) in &spec.env {
        out.push_str(&format!(
            "Environment={}\n",
            systemd_escape_arg(&format!("{name}={value}"))
        ));
    }
    if let Some(user) = &spec.user {
        out.push_str(&format!("User={user}\n"));
    }
    out.push_str(&format!("Restart={}\n", spec.restart.systemd_directive()));
    out.push_str("RestartSec=5\n");
    out.push_str(&format!(
        "StandardOutput={}\n",
        systemd_escape_arg(&format!(
            "append:{}",
            log_file(spec.platform, &spec.log_dir, "zero.out.log")
        ))
    ));
    out.push_str(&format!(
        "StandardError={}\n",
        systemd_escape_arg(&format!(
            "append:{}",
            log_file(spec.platform, &spec.log_dir, "zero.err.log")
        ))
    ));
    out.push_str("NoNewPrivileges=true\n");
    out.push_str("\n[Install]\n");
    out.push_str("WantedBy=default.target\n");
    out
}

fn render_windows(spec: &ServiceSpec) -> String {
    let mut out = String::new();
    out.push_str("{\n");
    out.push_str(&format!("  \"name\": {},\n", json_string(SERVICE_NAME)));
    out.push_str(&format!(
        "  \"display_name\": {},\n",
        json_string(SERVICE_DISPLAY_NAME)
    ));
    out.push_str(&format!(
        "  \"binary_path\": {},\n",
        json_string(&path_text(&spec.binary_path))
    ));
    if spec.args.is_empty() {
        out.push_str("  \"args\": [],\n");
    } else {
        out.push_str("  \"args\": [\n");
        for (index, arg) in spec.args.iter().enumerate() {
            let comma = if index + 1 == spec.args.len() {
                ""
            } else {
                ","
            };
            out.push_str(&format!("    {}{comma}\n", json_string(arg)));
        }
        out.push_str("  ],\n");
    }
    out.push_str(&format!(
        "  \"working_dir\": {},\n",
        json_string(&path_text(&spec.working_dir))
    ));
    out.push_str(&format!(
        "  \"log_dir\": {},\n",
        json_string(&path_text(&spec.log_dir))
    ));
    out.push_str(&format!(
        "  \"restart\": {},\n",
        json_string(spec.restart.as_str())
    ));
    if spec.env.is_empty() {
        out.push_str("  \"env\": {}\n");
    } else {
        out.push_str("  \"env\": {\n");
        for (index, (name, value)) in spec.env.iter().enumerate() {
            let comma = if index + 1 == spec.env.len() { "" } else { "," };
            out.push_str(&format!(
                "    {}: {}{comma}\n",
                json_string(name),
                json_string(value)
            ));
        }
        out.push_str("  }\n");
    }
    out.push_str("}\n");
    out
}

fn render_launchd(spec: &ServiceSpec) -> String {
    let mut out = String::new();
    out.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    out.push_str(
        "<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n",
    );
    out.push_str("<plist version=\"1.0\">\n<dict>\n");
    out.push_str("  <key>Label</key>\n");
    out.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(LAUNCHD_LABEL)
    ));
    out.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    out.push_str(&format!(
        "    <string>{}</string>\n",
        xml_escape(&path_text(&spec.binary_path))
    ));
    for arg in &spec.args {
        out.push_str(&format!("    <string>{}</string>\n", xml_escape(arg)));
    }
    out.push_str("  </array>\n");
    out.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    out.push_str("  <key>KeepAlive</key>\n");
    match spec.restart {
        RestartPolicy::Always => out.push_str("  <true/>\n"),
        RestartPolicy::OnFailure => {
            out.push_str("  <dict>\n    <key>SuccessfulExit</key>\n    <false/>\n  </dict>\n");
        }
        RestartPolicy::Never => out.push_str("  <false/>\n"),
    }
    out.push_str("  <key>WorkingDirectory</key>\n");
    out.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&path_text(&spec.working_dir))
    ));
    out.push_str("  <key>StandardOutPath</key>\n");
    out.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&log_file(spec.platform, &spec.log_dir, "zero.out.log"))
    ));
    out.push_str("  <key>StandardErrorPath</key>\n");
    out.push_str(&format!(
        "  <string>{}</string>\n",
        xml_escape(&log_file(spec.platform, &spec.log_dir, "zero.err.log"))
    ));
    if !spec.env.is_empty() {
        out.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
        for (name, value) in &spec.env {
            out.push_str(&format!(
                "    <key>{}</key>\n    <string>{}</string>\n",
                xml_escape(name),
                xml_escape(value)
            ));
        }
        out.push_str("  </dict>\n");
    }
    if let Some(user) = &spec.user {
        out.push_str("  <key>UserName</key>\n");
        out.push_str(&format!("  <string>{}</string>\n", xml_escape(user)));
    }
    out.push_str("</dict>\n</plist>\n");
    out
}

fn path_text(path: &Path) -> String {
    path.to_string_lossy().into_owned()
}

fn log_file(platform: ServicePlatform, log_dir: &Path, name: &str) -> String {
    let separator = if platform.is_windows() { '\\' } else { '/' };
    let text = path_text(log_dir);
    let trimmed = text.trim_end_matches(['/', '\\']);
    format!("{trimmed}{separator}{name}")
}

/// Quote a systemd argument when needed and escape `"`, `\`, and `%`.
fn systemd_escape_arg(value: &str) -> String {
    let needs_quotes = value.is_empty()
        || value.chars().any(|character| {
            character.is_whitespace()
                || matches!(
                    character,
                    '"' | '\''
                        | '\\'
                        | ';'
                        | '$'
                        | '&'
                        | '|'
                        | '<'
                        | '>'
                        | '('
                        | ')'
                        | '*'
                        | '?'
                        | '['
                        | ']'
                        | '#'
                        | '~'
                        | '='
                        | '%'
                )
        });
    if !needs_quotes {
        return value.to_string();
    }
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' | '\\' => {
                out.push('\\');
                out.push(character);
            }
            '%' => out.push_str("%%"),
            _ => out.push(character),
        }
    }
    out.push('"');
    out
}

fn xml_escape(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for character in value.chars() {
        match character {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(character),
        }
    }
    out
}

fn json_string(value: &str) -> String {
    let mut out = String::with_capacity(value.len() + 2);
    out.push('"');
    for character in value.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            character if (character as u32) < 0x20 => {
                out.push_str(&format!("\\u{:04x}", character as u32));
            }
            character => out.push(character),
        }
    }
    out.push('"');
    out
}

#[cfg(test)]
mod tests {
    use std::cell::{Cell, RefCell};

    use super::*;

    const SYSTEMD_BINARY: &str = "/usr/local/bin/zero";
    const WINDOWS_BINARY: &str = r"C:\Program Files\Zero\zero.exe";
    const LAUNCHD_BINARY: &str = "/opt/zero/bin/zero";

    #[derive(Default)]
    struct ScriptedManager {
        calls: RefCell<Vec<String>>,
        running: Cell<bool>,
        installed: Cell<bool>,
        fail_start: Cell<bool>,
        fail_install: Cell<bool>,
        fail_stop: Cell<bool>,
    }

    impl ScriptedManager {
        fn record(&self, call: String) {
            self.calls.borrow_mut().push(call);
        }

        fn calls(&self) -> Vec<String> {
            self.calls.borrow().clone()
        }
    }

    impl ServiceManager for ScriptedManager {
        fn start(&self, name: &str) -> ServiceResult<()> {
            self.record(format!("start:{name}"));
            if self.fail_start.get() {
                return Err(ServiceError::new(ServiceErrorKind::Manager, "boom"));
            }
            self.running.set(true);
            Ok(())
        }

        fn stop(&self, name: &str) -> ServiceResult<()> {
            self.record(format!("stop:{name}"));
            if self.fail_stop.get() {
                return Err(ServiceError::new(ServiceErrorKind::Manager, "stop boom"));
            }
            self.running.set(false);
            Ok(())
        }

        fn status(&self, name: &str) -> ServiceResult<ServiceStatus> {
            self.record(format!("status:{name}"));
            if self.running.get() {
                Ok(ServiceStatus::Running)
            } else if self.installed.get() {
                Ok(ServiceStatus::Stopped)
            } else {
                Ok(ServiceStatus::failed("not installed"))
            }
        }

        fn install(&self, unit_path: &Path) -> ServiceResult<()> {
            self.record(format!("install:{}", unit_path.display()));
            if self.fail_install.get() {
                return Err(ServiceError::new(ServiceErrorKind::Manager, "install boom"));
            }
            self.installed.set(true);
            Ok(())
        }

        fn uninstall(&self, name: &str) -> ServiceResult<()> {
            self.record(format!("uninstall:{name}"));
            self.installed.set(false);
            self.running.set(false);
            Ok(())
        }
    }

    fn systemd_spec() -> ServiceSpec {
        let mut spec = ServiceSpec::new(
            ServicePlatform::Systemd,
            SYSTEMD_BINARY,
            "/var/lib/zero",
            "/var/log/zero",
        );
        spec.args = vec!["serve".to_string(), "--no-tty".to_string()];
        spec.user = Some("zero".to_string());
        spec.restart = RestartPolicy::Always;
        spec.env
            .insert("ZERO_LOG_LEVEL".to_string(), "info".to_string());
        spec
    }

    fn windows_spec() -> ServiceSpec {
        let mut spec = ServiceSpec::new(
            ServicePlatform::WindowsService,
            WINDOWS_BINARY,
            r"C:\ProgramData\Zero",
            r"C:\ProgramData\Zero\logs",
        );
        spec.args = vec!["serve".to_string(), "--no-tty".to_string()];
        spec.restart = RestartPolicy::Always;
        spec.env
            .insert("ZERO_LOG_LEVEL".to_string(), "info".to_string());
        spec
    }

    fn launchd_spec() -> ServiceSpec {
        let mut spec = ServiceSpec::new(
            ServicePlatform::Launchd,
            LAUNCHD_BINARY,
            "/usr/local/lib/zero",
            "/var/log/zero",
        );
        spec.args = vec!["serve".to_string(), "--no-tty".to_string()];
        spec.user = Some("zero".to_string());
        spec.restart = RestartPolicy::Always;
        spec.env
            .insert("ZERO_LOG_LEVEL".to_string(), "info".to_string());
        spec
    }

    #[test]
    fn systemd_unit_contains_every_required_field() {
        let text = render_unit(&systemd_spec()).expect("systemd unit renders");
        for required in [
            "[Unit]",
            "Description=Zero agent service",
            "[Service]",
            "Type=simple",
            "ExecStart=/usr/local/bin/zero serve --no-tty",
            "WorkingDirectory=/var/lib/zero",
            "User=zero",
            "Restart=always",
            "RestartSec=5",
            "StandardOutput=append:/var/log/zero/zero.out.log",
            "StandardError=append:/var/log/zero/zero.err.log",
            "NoNewPrivileges=true",
            "Environment=\"ZERO_LOG_LEVEL=info\"",
            "[Install]",
            "WantedBy=default.target",
        ] {
            assert!(text.contains(required), "missing `{required}` in:\n{text}");
        }
    }

    #[test]
    fn windows_service_config_contains_every_required_field() {
        let text = render_unit(&windows_spec()).expect("Windows config renders");
        let value: serde_json::Value =
            serde_json::from_str(&text).expect("the Windows service config is JSON");
        assert_eq!(value["name"], "zero");
        assert_eq!(value["display_name"], "Zero");
        assert_eq!(value["binary_path"], WINDOWS_BINARY);
        assert_eq!(value["args"][0], "serve");
        assert_eq!(value["args"][1], "--no-tty");
        assert_eq!(value["working_dir"], r"C:\ProgramData\Zero");
        assert_eq!(value["log_dir"], r"C:\ProgramData\Zero\logs");
        assert_eq!(value["restart"], "always");
        assert_eq!(value["env"]["ZERO_LOG_LEVEL"], "info");
        assert!(text.contains("\"display_name\""));
        assert!(text.contains("\"restart\""));
    }

    #[test]
    fn launchd_plist_contains_every_required_field() {
        let text = render_unit(&launchd_spec()).expect("launchd plist renders");
        for required in [
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>",
            "<key>Label</key>",
            "<string>com.zero.agent</string>",
            "<key>ProgramArguments</key>",
            "<string>/opt/zero/bin/zero</string>",
            "<string>--no-tty</string>",
            "<key>RunAtLoad</key>",
            "<true/>",
            "<key>KeepAlive</key>",
            "<key>WorkingDirectory</key>",
            "<string>/usr/local/lib/zero</string>",
            "<key>StandardOutPath</key>",
            "<string>/var/log/zero/zero.out.log</string>",
            "<key>StandardErrorPath</key>",
            "<string>/var/log/zero/zero.err.log</string>",
            "<key>EnvironmentVariables</key>",
            "<key>UserName</key>",
            "<string>zero</string>",
        ] {
            assert!(text.contains(required), "missing `{required}` in:\n{text}");
        }
    }

    #[test]
    fn launchd_plist_escapes_xml_values() {
        let mut spec = launchd_spec();
        spec.args = vec!["--label=a<b&c>d\"e'f".to_string()];
        spec.working_dir = PathBuf::from("/opt/zero & friends");
        let text = render_unit(&spec).expect("escaped plist renders");
        assert!(text.contains("a&lt;b&amp;c&gt;d&quot;e&apos;f"), "{text}");
        assert!(text.contains("/opt/zero &amp; friends"), "{text}");
        assert!(!text.contains("a<b&c>"), "raw XML leaked into the plist");
    }

    #[test]
    fn systemd_arguments_and_environment_are_quoted() {
        let mut spec = systemd_spec();
        spec.args = vec![
            "two words".to_string(),
            "50%".to_string(),
            "quote\"x".to_string(),
        ];
        spec.env
            .insert("ZERO_HOME".to_string(), "/opt/zero data".to_string());
        let text = render_unit(&spec).expect("quoted unit renders");
        assert!(text.contains("\"two words\""), "{text}");
        assert!(
            text.contains("\"50%%\""),
            "systemd percent is escaped: {text}"
        );
        assert!(text.contains("quote\\\"x"), "the quote is escaped: {text}");
        assert!(
            text.contains("Environment=\"ZERO_HOME=/opt/zero data\""),
            "{text}"
        );
    }

    #[test]
    fn restart_policy_is_rendered_for_every_platform() {
        let cases = [
            (RestartPolicy::Always, "always", "Restart=always"),
            (RestartPolicy::OnFailure, "on_failure", "Restart=on-failure"),
            (RestartPolicy::Never, "never", "Restart=no"),
        ];
        for (policy, windows_value, systemd_line) in cases {
            let mut systemd = systemd_spec();
            systemd.restart = policy;
            let text = render_unit(&systemd).expect("systemd renders");
            assert!(text.contains(systemd_line), "{text}");
            assert!(text.contains(&format!("Restart={}", policy.systemd_directive())));

            let mut windows = windows_spec();
            windows.restart = policy;
            let text = render_unit(&windows).expect("Windows config renders");
            assert!(
                text.contains(&format!("\"restart\": \"{windows_value}\"")),
                "{text}"
            );
            assert_eq!(policy.as_str(), windows_value);

            let mut launchd = launchd_spec();
            launchd.restart = policy;
            let text = render_unit(&launchd).expect("launchd plist renders");
            match policy {
                RestartPolicy::Always => {
                    assert!(text.contains("<key>KeepAlive</key>\n  <true/>"), "{text}");
                }
                RestartPolicy::OnFailure => {
                    assert!(
                        text.contains("<key>SuccessfulExit</key>\n    <false/>"),
                        "{text}"
                    );
                }
                RestartPolicy::Never => {
                    assert!(text.contains("<key>KeepAlive</key>\n  <false/>"), "{text}");
                }
            }
        }
    }

    #[test]
    fn env_validation_rejects_secret_looking_names() {
        for name in [
            "OPENAI_API_KEY",
            "GITHUB_TOKEN",
            "DB_PASSWORD",
            "AWS_SECRET_ACCESS_KEY",
            "CLIENT_CREDENTIALS",
            "SSH_PASSPHRASE",
            "NPM_KEY",
        ] {
            let mut spec = systemd_spec();
            spec.env
                .insert(name.to_string(), "not-a-real-value".to_string());
            let error = spec.validate().expect_err(name);
            assert_eq!(error.kind(), ServiceErrorKind::SecretInEnv, "{name}");
        }

        let mut benign = systemd_spec();
        benign
            .env
            .insert("MONKEY".to_string(), "banana".to_string());
        benign
            .env
            .insert("ZERO_LOG_LEVEL".to_string(), "debug".to_string());
        benign.validate().expect("benign names are allowed");
    }

    #[test]
    fn relative_and_non_native_paths_are_refused() {
        let mut spec = systemd_spec();
        spec.binary_path = PathBuf::from("bin/zero");
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::PathNotAbsolute
        );

        let mut spec = systemd_spec();
        spec.working_dir = PathBuf::from("./zero");
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::PathNotAbsolute
        );

        let mut spec = launchd_spec();
        spec.log_dir = PathBuf::from("logs");
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::PathNotAbsolute
        );

        let mut spec = systemd_spec();
        spec.binary_path = PathBuf::from(r"C:\Zero\zero.exe");
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::PathNotAbsolute
        );

        let mut spec = windows_spec();
        spec.binary_path = PathBuf::from("/usr/local/bin/zero");
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::PathNotAbsolute
        );

        let mut spec = systemd_spec();
        spec.binary_path = PathBuf::from("/usr/local/../zero");
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );
    }

    #[test]
    fn bounded_arguments_and_environment_are_enforced() {
        let mut spec = systemd_spec();
        spec.args = vec!["a".to_string(); MAX_SERVICE_ARGS + 1];
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::LimitExceeded
        );

        let mut spec = systemd_spec();
        spec.args = vec!["a".repeat(MAX_SERVICE_ARG_BYTES + 1)];
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::LimitExceeded
        );

        let mut spec = systemd_spec();
        spec.args = vec!["".to_string()];
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );

        let mut spec = systemd_spec();
        spec.args = vec!["line\nbreak".to_string()];
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );

        let mut spec = systemd_spec();
        for index in 0..=MAX_SERVICE_ENV_ENTRIES {
            spec.env
                .insert(format!("ZERO_{index}"), "value".to_string());
        }
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::LimitExceeded
        );

        let mut spec = systemd_spec();
        spec.env
            .insert("A".repeat(MAX_SERVICE_ENV_NAME_BYTES + 1), "v".to_string());
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::LimitExceeded
        );

        let mut spec = systemd_spec();
        spec.env.insert(
            "ZERO_VALUE".to_string(),
            "v".repeat(MAX_SERVICE_ENV_VALUE_BYTES + 1),
        );
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::LimitExceeded
        );

        let mut spec = systemd_spec();
        spec.env.insert("1BAD".to_string(), "v".to_string());
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );
    }

    #[test]
    fn user_is_refused_for_windows_service() {
        let mut spec = windows_spec();
        spec.user = Some("zero".to_string());
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );

        let mut spec = systemd_spec();
        spec.user = Some("-zero".to_string());
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );

        let mut spec = launchd_spec();
        spec.user = Some(String::new());
        assert_eq!(
            spec.validate().unwrap_err().kind(),
            ServiceErrorKind::SpecInvalid
        );
    }

    #[test]
    fn unsupported_platform_is_typed() {
        assert_eq!(
            platform_for_os("linux").expect("linux"),
            ServicePlatform::Systemd
        );
        assert_eq!(
            platform_for_os("macos").expect("macos"),
            ServicePlatform::Launchd
        );
        assert_eq!(
            platform_for_os("windows").expect("windows"),
            ServicePlatform::WindowsService
        );
        let error = platform_for_os("redox").expect_err("unsupported OS");
        assert_eq!(error.kind(), ServiceErrorKind::Unsupported);

        let expected = platform_for_os(std::env::consts::OS);
        assert_eq!(platform_for_current_os().is_ok(), expected.is_ok());
        if let Ok(platform) = expected {
            assert_eq!(platform_for_current_os().expect("host platform"), platform);
        }
    }

    #[test]
    fn unit_rendering_is_deterministic() {
        for spec in [systemd_spec(), windows_spec(), launchd_spec()] {
            let first = render_unit(&spec).expect("first render");
            let second = render_unit(&spec).expect("second render");
            assert_eq!(first, second);
        }

        let mut first = launchd_spec();
        first.env.insert("Z_LAST".to_string(), "1".to_string());
        first.env.insert("A_FIRST".to_string(), "2".to_string());
        let mut second = launchd_spec();
        second.env.insert("A_FIRST".to_string(), "2".to_string());
        second.env.insert("Z_LAST".to_string(), "1".to_string());
        assert_eq!(
            render_unit(&first).expect("first"),
            render_unit(&second).expect("second")
        );
    }

    #[test]
    fn lifecycle_starts_stops_and_reports_on_all_three_platforms() {
        for spec in [systemd_spec(), windows_spec(), launchd_spec()] {
            let manager = ScriptedManager::default();
            let report = lifecycle(&spec, &manager);

            assert!(report.installed, "{:?}", report.failure);
            assert!(report.started, "{:?}", report.failure);
            assert_eq!(report.status, ServiceStatus::Running);
            assert!(report.stopped, "{:?}", report.failure);
            assert_eq!(report.final_status, ServiceStatus::Stopped);
            assert_eq!(report.failure, None);
            assert_eq!(report.unit_file_name, unit_file_name(spec.platform));

            let calls = manager.calls();
            assert_eq!(
                calls,
                vec![
                    format!("install:{}", default_unit_path(spec.platform).display()),
                    format!("start:{SERVICE_NAME}"),
                    format!("status:{SERVICE_NAME}"),
                    format!("stop:{SERVICE_NAME}"),
                    format!("status:{SERVICE_NAME}"),
                ]
            );
        }
    }

    #[test]
    fn manage_installs_registers_and_reports_status() {
        let manager = ScriptedManager::default();
        let report =
            manage(ServicePlatform::Systemd, &systemd_spec(), &manager).expect("manage succeeds");
        assert!(report.installed);
        assert_eq!(report.platform, ServicePlatform::Systemd);
        assert_eq!(report.unit_file_name, SYSTEMD_UNIT);
        assert_eq!(
            report.unit_path,
            default_unit_path(ServicePlatform::Systemd)
        );
        assert!(report.unit.contains("ExecStart=/usr/local/bin/zero"));
        assert_eq!(report.status, ServiceStatus::Stopped);
        assert_eq!(
            manager.calls(),
            vec![
                format!("install:{}", report.unit_path.display()),
                format!("status:{SERVICE_NAME}"),
            ]
        );

        manager
            .uninstall(SERVICE_NAME)
            .expect("uninstall through the seam");
        assert_eq!(
            manager.calls().last(),
            Some(&format!("uninstall:{SERVICE_NAME}"))
        );
    }

    #[test]
    fn a_platform_mismatch_is_refused() {
        let manager = ScriptedManager::default();
        let error = manage(ServicePlatform::Launchd, &systemd_spec(), &manager)
            .expect_err("a mismatched platform is refused");
        assert_eq!(error.kind(), ServiceErrorKind::SpecInvalid);
        assert!(manager.calls().is_empty(), "nothing was installed");
    }

    #[test]
    fn a_failed_start_is_reported_and_not_retried() {
        let manager = ScriptedManager::default();
        manager.fail_start.set(true);
        let report = lifecycle(&systemd_spec(), &manager);

        assert!(report.installed);
        assert!(!report.started);
        assert!(!report.stopped);
        assert!(matches!(report.status, ServiceStatus::Failed { .. }));
        assert_eq!(report.final_status, report.status);
        let failure = report.failure.expect("the failed start is reported");
        assert!(failure.contains("start"), "{failure}");
        assert!(failure.contains("boom"), "{failure}");

        let calls = manager.calls();
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.starts_with("start:"))
                .count(),
            1,
            "a failed start is attempted once: {calls:?}"
        );
        assert_eq!(
            calls
                .iter()
                .filter(|call| call.starts_with("stop:"))
                .count(),
            0,
            "a failed start is not followed by a stop: {calls:?}"
        );
    }

    #[test]
    fn a_failed_install_is_reported_without_a_start() {
        let manager = ScriptedManager::default();
        manager.fail_install.set(true);
        let report = lifecycle(&launchd_spec(), &manager);

        assert!(!report.installed);
        assert!(!report.started);
        assert!(!report.stopped);
        assert!(matches!(report.status, ServiceStatus::Failed { .. }));
        let failure = report.failure.expect("the failed install is reported");
        assert!(failure.contains("install"), "{failure}");
        assert_eq!(manager.calls().len(), 1);
        assert!(!manager.calls()[0].starts_with("start:"));
    }

    #[test]
    fn a_failed_stop_is_reported_and_the_final_status_is_observed() {
        let manager = ScriptedManager::default();
        manager.fail_stop.set(true);
        let report = lifecycle(&windows_spec(), &manager);

        assert!(report.installed);
        assert!(report.started);
        assert_eq!(report.status, ServiceStatus::Running);
        assert!(!report.stopped);
        let failure = report.failure.expect("the failed stop is reported");
        assert!(failure.contains("stop"), "{failure}");
        assert_eq!(report.final_status, ServiceStatus::Running);
    }

    #[test]
    fn the_service_module_has_no_shell_or_execution_surface() {
        let source = include_str!("service.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or(source);
        for forbidden in [
            "Command::new",
            "std::process",
            "std::net",
            "TcpStream",
            "unsafe {",
            "reqwest",
        ] {
            assert!(
                !production.contains(forbidden),
                "service.rs must not contain `{forbidden}`"
            );
        }
        assert!(
            production.contains("ServiceManager"),
            "the manager seam must be documented"
        );
    }
}
