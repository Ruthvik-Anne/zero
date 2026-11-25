//! Windows installer script (T-INST-02; INST-02, INST-04, INST-05, INST-06).
//!
//! The installer itself is `installer/windows.ps1`, a PowerShell 5.1 script
//! that needs no Node and no runtime beyond Windows PowerShell. This module is
//! the Rust seam that names the script, checks the properties the task
//! requires, and builds the argument vector a caller runs.
//!
//! The module never executes a command and has no shell surface of its own: it
//! returns a `Vec<String>` and the host decides when to spawn it. `validate_script`
//! is deliberately a pure text check so the shipped script is audited by the
//! test suite and a regression in the safety markers fails a unit test.

use std::fmt;
use std::path::{Path, PathBuf};

/// Repository-relative location of the Windows installer.
pub const SCRIPT_RELATIVE_PATH: &str = "installer/windows.ps1";

/// Every parameter the script must declare.
pub const REQUIRED_PARAMETERS: &[&str] = &[
    "-Prefix",
    "-File",
    "-Name",
    "-Sha256",
    "-Force",
    "-Uninstall",
    "-NoPath",
    "-UpdatePath",
    "-WhatIf",
    "-Help",
];

const SHA256_HEX_BYTES: usize = 64;

/// Markers the script must contain, and what each one provides.
const REQUIRED_MARKERS: &[(&str, &str)] = &[
    ("#requires -Version 5.1", "a PowerShell 5.1 requirement"),
    ("[CmdletBinding()]", "advanced-function binding"),
    ("[string]$Prefix", "the `-Prefix` parameter"),
    ("[string]$File", "the `-File` parameter"),
    ("[string]$Name", "the `-Name` parameter"),
    ("[string]$Sha256", "the `-Sha256` parameter"),
    ("[switch]$Force", "the `-Force` switch"),
    ("[switch]$Uninstall", "the `-Uninstall` switch"),
    ("[switch]$NoPath", "the `-NoPath` switch"),
    ("[switch]$UpdatePath", "the `-UpdatePath` switch"),
    ("[switch]$WhatIf", "the `-WhatIf` switch"),
    ("[switch]$Help", "the `-Help` switch"),
    (
        "Get-FileHash -LiteralPath $File -Algorithm SHA256",
        "the `Get-FileHash` checksum check",
    ),
    ("checksum mismatch", "a checksum refusal"),
    (
        "[IO.File]::Open($Path, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)",
        "the exclusive install lock",
    ),
    ("Get-Process -Id $owner", "a live lock owner check"),
    ("[IO.File]::ReadAllText($Path)", "a stale-lock PID read"),
    (
        "Move-Item -LiteralPath $temp -Destination $target -Force",
        "the atomic rename",
    ),
    (
        "SetEnvironmentVariable('Path', $combined, 'User')",
        "the user PATH update",
    ),
    (
        "GetEnvironmentVariable('Path', 'User')",
        "the user PATH read",
    ),
    ("$env:LOCALAPPDATA", "the default-prefix guidance"),
    ("Program Files", "the Program Files refusal"),
    ("System32", "the System32 refusal"),
    ("never elevates", "the no-elevation statement"),
    ("non-interactive", "the non-interactive statement"),
    ("Stop-Installer 2", "a usage exit"),
    ("Stop-Installer 3", "a refusal exit"),
    ("finally", "a cleanup block"),
];

/// Constructs that would prompt, elevate, or write the machine PATH.
const FORBIDDEN_MARKERS: &[(&str, &str)] = &[
    ("runas", "privilege elevation (`RunAs`)"),
    ("start-process", "`Start-Process`"),
    ("read-host", "a stdin prompt"),
    ("[console]::readline", "a stdin prompt"),
    ("cmd /c pause", "a pause prompt"),
];

/// Why an installer input was refused. Kinds are stable strings for logs and
/// tests; they are local to this module and are not part of the `zero-types`
/// error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WindowsInstallErrorKind {
    /// The script text is missing a required PowerShell or safety property.
    ScriptInvalid,
    /// An argument to [`install_command`] is not usable.
    InvalidInput,
}

impl WindowsInstallErrorKind {
    /// Stable kind string, e.g. `script_invalid`.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ScriptInvalid => "script_invalid",
            Self::InvalidInput => "invalid_input",
        }
    }
}

/// A typed refusal with one message per problem found.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsInstallError {
    kind: WindowsInstallErrorKind,
    problems: Vec<String>,
}

impl WindowsInstallError {
    fn new(kind: WindowsInstallErrorKind, problems: Vec<String>) -> Self {
        Self { kind, problems }
    }

    /// The stable error kind.
    pub fn kind(&self) -> WindowsInstallErrorKind {
        self.kind
    }

    /// Every problem found, in the order the checks ran.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

impl fmt::Display for WindowsInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "zero.installer.{}: {}",
            self.kind.as_str(),
            self.problems.join("; ")
        )
    }
}

impl std::error::Error for WindowsInstallError {}

/// Absolute path of the shipped installer script.
///
/// Derived from `CARGO_MANIFEST_DIR`, so it works from the crate directory, a
/// workspace test run, and CI, on every host OS.
pub fn script_path() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(SCRIPT_RELATIVE_PATH)
}

/// Check the shipped script text against the T-INST-02 contract.
///
/// The check is structural and deliberately shallow: it asserts the PowerShell
/// 5.1 header, the required parameters, the checksum/lock/atomic-install/
/// user-PATH markers, and the absence of elevation, prompting, or machine-PATH
/// writes. Behaviour is exercised by running the script in CI and on Windows,
/// not by this function.
pub fn validate_script(text: &str) -> Result<(), WindowsInstallError> {
    let mut problems = Vec::new();

    if text.lines().next() != Some("#requires -Version 5.1") {
        problems.push("the first line must be `#requires -Version 5.1`".to_string());
    }

    for (needle, what) in REQUIRED_MARKERS {
        if !text.contains(needle) {
            problems.push(format!("missing {what} (`{needle}`)"));
        }
    }

    let lowered = text.to_ascii_lowercase();
    for (needle, what) in FORBIDDEN_MARKERS {
        if lowered.contains(needle) {
            problems.push(format!("the installer must not use {what} (`{needle}`)"));
        }
    }

    for line in lowered.lines() {
        if line.contains("setenvironmentvariable") && line.contains("'machine'") {
            problems.push(
                "the installer must never write the machine PATH (`SetEnvironmentVariable`, `'Machine'`)"
                    .to_string(),
            );
            break;
        }
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(WindowsInstallError::new(
            WindowsInstallErrorKind::ScriptInvalid,
            problems,
        ))
    }
}

/// Build the argv that installs `file` into `prefix`.
///
/// The result is `["powershell", "-NoProfile", "-NonInteractive",
/// "-ExecutionPolicy", "Bypass", "-File", <script path>, "-Prefix", prefix,
/// "-File", file, "-Sha256", sha256]`. The digest must already be 64 lowercase
/// hex characters, so a caller cannot pass an unverifiable artifact to the
/// script.
pub fn install_command(
    prefix: &Path,
    file: &Path,
    sha256: &str,
) -> Result<Vec<String>, WindowsInstallError> {
    let mut problems = Vec::new();
    let prefix_text = path_text(prefix, "-Prefix", &mut problems);
    let file_text = path_text(file, "-File", &mut problems);
    if !is_lower_hex_sha256(sha256) {
        problems.push(format!(
            "-Sha256 must be {SHA256_HEX_BYTES} lowercase hex characters"
        ));
    }
    if !problems.is_empty() {
        return Err(WindowsInstallError::new(
            WindowsInstallErrorKind::InvalidInput,
            problems,
        ));
    }
    Ok(vec![
        "powershell".to_string(),
        "-NoProfile".to_string(),
        "-NonInteractive".to_string(),
        "-ExecutionPolicy".to_string(),
        "Bypass".to_string(),
        "-File".to_string(),
        script_path().to_string_lossy().into_owned(),
        "-Prefix".to_string(),
        prefix_text,
        "-File".to_string(),
        file_text,
        "-Sha256".to_string(),
        sha256.to_string(),
    ])
}

fn path_text(path: &Path, flag: &str, problems: &mut Vec<String>) -> String {
    match path.to_str() {
        Some(text) if !text.is_empty() => text.to_string(),
        Some(_) => {
            problems.push(format!("{flag} must not be empty"));
            String::new()
        }
        None => {
            problems.push(format!("{flag} must be valid UTF-8"));
            String::new()
        }
    }
}

fn is_lower_hex_sha256(value: &str) -> bool {
    value.len() == SHA256_HEX_BYTES
        && value
            .bytes()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn shipped_script() -> String {
        let path = script_path();
        std::fs::read_to_string(&path)
            .unwrap_or_else(|error| panic!("read {}: {error}", path.display()))
    }

    #[test]
    fn script_path_points_at_the_repository_installer() {
        let path = script_path();
        assert!(
            path.ends_with(Path::new("installer").join("windows.ps1")),
            "unexpected script path: {}",
            path.display()
        );
        assert!(path.is_file(), "missing {}", path.display());
    }

    #[test]
    fn the_shipped_script_is_powershell_51_and_carries_every_requirement() {
        let text = shipped_script();
        validate_script(&text).expect("the shipped script satisfies T-INST-02");
        assert!(
            text.starts_with("#requires -Version 5.1\n"),
            "missing the PowerShell 5.1 requirement"
        );
    }

    #[test]
    fn every_parameter_is_documented_in_the_usage_text() {
        let text = shipped_script();
        for parameter in REQUIRED_PARAMETERS {
            let documented = text.lines().any(|line| {
                let trimmed = line.trim_start();
                trimmed.starts_with(parameter) && trimmed[parameter.len()..].starts_with(' ')
            });
            assert!(documented, "the usage text does not document {parameter}");
        }
    }

    #[test]
    fn validation_rejects_a_missing_parameter_or_safety_marker() {
        let text = shipped_script();
        let cases = [
            ("[switch]$UpdatePath", "-UpdatePath"),
            ("[switch]$WhatIf", "-WhatIf"),
            (
                "Get-FileHash -LiteralPath $File -Algorithm SHA256",
                "Get-FileHash",
            ),
            ("[IO.FileMode]::CreateNew", "exclusive install lock"),
            (
                "Move-Item -LiteralPath $temp -Destination $target -Force",
                "atomic rename",
            ),
            (
                "SetEnvironmentVariable('Path', $combined, 'User')",
                "user PATH update",
            ),
            ("$env:LOCALAPPDATA", "default-prefix guidance"),
            ("Program Files", "Program Files refusal"),
            ("System32", "System32 refusal"),
            ("finally", "cleanup block"),
        ];
        for (needle, expected) in cases {
            let mutated = text.replace(needle, "");
            assert_ne!(mutated, text, "fixture did not contain {needle}");
            let error = validate_script(&mutated)
                .expect_err(&format!("a removed `{needle}` must be refused"));
            assert_eq!(error.kind(), WindowsInstallErrorKind::ScriptInvalid);
            assert!(
                error.problems().iter().any(|p| p.contains(expected)),
                "no problem mentioned {expected}: {:?}",
                error.problems()
            );
        }
    }

    #[test]
    fn validation_rejects_elevation_prompts_and_machine_path_writes() {
        let text = shipped_script();
        let cases = [
            (
                "Start-Process -Verb RunAs powershell -Command 'whoami'",
                "elevation",
            ),
            ("$answer = Read-Host 'continue?'", "stdin prompt"),
            (
                "[Environment]::SetEnvironmentVariable('Path', $machine, 'Machine')",
                "machine path",
            ),
        ];
        for (snippet, expected) in cases {
            let mutated = format!("{text}\n{snippet}\n");
            let error =
                validate_script(&mutated).expect_err(&format!("`{snippet}` must be refused"));
            assert_eq!(error.kind(), WindowsInstallErrorKind::ScriptInvalid);
            assert!(
                error
                    .problems()
                    .iter()
                    .any(|p| p.to_ascii_lowercase().contains(expected)),
                "no problem mentioned {expected}: {:?}",
                error.problems()
            );
        }
    }

    #[test]
    fn install_command_builds_the_exact_argument_vector() {
        let sha = "0123456789abcdef".repeat(4);
        let argv = install_command(
            Path::new(r"C:\Users\user\AppData\Local\Zero"),
            Path::new(r"C:\Temp\zero.exe"),
            &sha,
        )
        .expect("valid install command");
        assert_eq!(
            argv,
            vec![
                "powershell".to_string(),
                "-NoProfile".to_string(),
                "-NonInteractive".to_string(),
                "-ExecutionPolicy".to_string(),
                "Bypass".to_string(),
                "-File".to_string(),
                script_path().to_string_lossy().into_owned(),
                "-Prefix".to_string(),
                r"C:\Users\user\AppData\Local\Zero".to_string(),
                "-File".to_string(),
                r"C:\Temp\zero.exe".to_string(),
                "-Sha256".to_string(),
                sha,
            ]
        );
    }

    #[test]
    fn install_command_refuses_an_invalid_checksum_or_path() {
        let good = "a".repeat(64);
        let bad_digests = vec![
            String::new(),
            "abc".to_string(),
            "A".repeat(64),
            "g".repeat(64),
        ];
        for digest in bad_digests {
            let error = install_command(Path::new(r"C:\Z"), Path::new(r"C:\f"), &digest)
                .expect_err("a bad digest must be refused");
            assert_eq!(error.kind(), WindowsInstallErrorKind::InvalidInput);
            assert!(error.problems().iter().any(|p| p.contains("-Sha256")));
        }

        let error = install_command(Path::new(""), Path::new(r"C:\f"), &good)
            .expect_err("an empty prefix must be refused");
        assert!(error.problems().iter().any(|p| p.contains("-Prefix")));

        let error = install_command(Path::new(r"C:\Z"), Path::new(""), &good)
            .expect_err("an empty file must be refused");
        assert!(error.problems().iter().any(|p| p.contains("-File")));
    }

    #[test]
    fn an_error_names_its_kind_and_every_problem() {
        let error = WindowsInstallError::new(
            WindowsInstallErrorKind::ScriptInvalid,
            vec!["one".to_string(), "two".to_string()],
        );
        assert_eq!(error.kind().as_str(), "script_invalid");
        let text = error.to_string();
        assert!(text.starts_with("zero.installer.script_invalid: "));
        assert!(text.contains("one") && text.contains("two"));
    }

    #[test]
    fn the_generator_does_not_execute_commands() {
        let source = include_str!("windows_install.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or_default();
        assert!(!production.contains("Command::new"));
        assert!(!production.contains("std::process"));
        assert!(!production.contains("powershell -c"));
    }
}
