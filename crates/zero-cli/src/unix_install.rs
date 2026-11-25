//! Unix installer script (T-INST-03; INST-03, INST-04, INST-05).
//!
//! The installer itself is `installer/unix.sh`, a POSIX `sh` script that needs
//! no Node and no runtime beyond the base system tools. This module is the Rust
//! seam that names the script, checks the properties the task requires, and
//! builds the argument vector a caller runs.
//!
//! The module never executes a command and has no shell surface of its own: it
//! returns a `Vec<String>` and the host decides when to spawn it. `validate_script`
//! is deliberately a pure text check so the shipped script is audited by the
//! test suite and a regression in the safety markers fails a unit test.

use std::fmt;
use std::path::{Path, PathBuf};

/// Repository-relative location of the Unix installer.
pub const SCRIPT_RELATIVE_PATH: &str = "installer/unix.sh";

/// Every long flag the script must accept.
pub const REQUIRED_FLAGS: &[&str] = &[
    "--prefix",
    "--file",
    "--name",
    "--sha256",
    "--force",
    "--uninstall",
    "--no-path",
    "--update-path",
    "--help",
];

const SHA256_HEX_BYTES: usize = 64;

/// Markers the script must contain, and what each one provides.
const REQUIRED_MARKERS: &[(&str, &str)] = &[
    ("set -eu", "strict mode (`set -eu`)"),
    ("trap cleanup EXIT", "an EXIT cleanup trap"),
    ("trap 'cleanup; exit 130' INT", "an INT cleanup trap"),
    ("trap 'cleanup; exit 143' TERM", "a TERM cleanup trap"),
    ("stty -g", "terminal state capture"),
    ("stty sane", "terminal restore"),
    ("-t 0", "stdin TTY detection"),
    (".zero-install.lock", "the install lock directory"),
    ("kill -0", "a live lock owner check"),
    ("mkdir \"$LOCK\"", "atomic lock creation"),
    ("sha256sum", "the `sha256sum` checksum path"),
    ("shasum -a 256", "the `shasum` checksum fallback"),
    ("checksum mismatch", "a checksum refusal"),
    ("chmod 755", "the executable bit"),
    ("mv -f", "the atomic rename"),
    ("TMP_FILE", "the staged temporary file"),
    ("$HOME/.local", "the default-prefix guidance"),
];

/// Constructs that are bash-only and must not appear in a POSIX script.
const BASH_ONLY: &[(&str, &str)] = &[
    ("[[", "double-bracket test"),
    ("]]", "double-bracket test"),
    ("function ", "`function` keyword"),
    ("&>", "`&>` redirect"),
    ("<<<", "here-string"),
    ("$'", "ANSI-C quoting"),
    ("=~", "regex match"),
    ("local ", "`local` keyword"),
    ("declare ", "`declare` keyword"),
    ("pipefail", "`pipefail`"),
    ("source ", "`source` builtin"),
];

/// Why an installer input was refused. Kinds are stable strings for logs and
/// tests; they are local to this module and are not part of the `zero-types`
/// error taxonomy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UnixInstallErrorKind {
    /// The script text is missing a required POSIX or safety property.
    ScriptInvalid,
    /// An argument to [`install_command`] is not usable.
    InvalidInput,
}

impl UnixInstallErrorKind {
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
pub struct UnixInstallError {
    kind: UnixInstallErrorKind,
    problems: Vec<String>,
}

impl UnixInstallError {
    fn new(kind: UnixInstallErrorKind, problems: Vec<String>) -> Self {
        Self { kind, problems }
    }

    /// The stable error kind.
    pub fn kind(&self) -> UnixInstallErrorKind {
        self.kind
    }

    /// Every problem found, in the order the checks ran.
    pub fn problems(&self) -> &[String] {
        &self.problems
    }
}

impl fmt::Display for UnixInstallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "zero.installer.{}: {}",
            self.kind.as_str(),
            self.problems.join("; ")
        )
    }
}

impl std::error::Error for UnixInstallError {}

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

/// Check the shipped script text against the T-INST-03 contract.
///
/// The check is structural and deliberately shallow: it asserts the POSIX
/// markers, the required flags, the lock/trap/checksum/atomic-install markers,
/// and the absence of bash-only constructs. Behaviour is exercised by running
/// the script in CI and in a local shell, not by this function.
pub fn validate_script(text: &str) -> Result<(), UnixInstallError> {
    let mut problems = Vec::new();

    if text.lines().next() != Some("#!/bin/sh") {
        problems.push("the first line must be `#!/bin/sh`".to_string());
    }

    for (needle, what) in REQUIRED_MARKERS {
        if !text.contains(needle) {
            problems.push(format!("missing {what} (`{needle}`)"));
        }
    }

    for flag in REQUIRED_FLAGS {
        let arm = format!("{flag})");
        if !text.lines().any(|line| line.trim() == arm) {
            problems.push(format!("missing the `{flag}` option arm (`{arm}`)"));
        }
    }

    for (needle, what) in BASH_ONLY {
        if text.contains(needle) {
            problems.push(format!("bash-only syntax `{needle}` ({what}) is not POSIX"));
        }
    }

    if text
        .lines()
        .any(|line| line.trim_start().starts_with("read "))
    {
        problems.push("the installer must not read from stdin (no prompts)".to_string());
    }

    if problems.is_empty() {
        Ok(())
    } else {
        Err(UnixInstallError::new(
            UnixInstallErrorKind::ScriptInvalid,
            problems,
        ))
    }
}

/// Build the argv that installs `file` into `prefix`.
///
/// The result is `["sh", <script path>, "--prefix", prefix, "--file", file,
/// "--sha256", sha256]`. The digest must already be 64 lowercase hex
/// characters, so a caller cannot pass an unverifiable artifact to the script.
pub fn install_command(
    prefix: &Path,
    file: &Path,
    sha256: &str,
) -> Result<Vec<String>, UnixInstallError> {
    let mut problems = Vec::new();
    let prefix_text = path_text(prefix, "--prefix", &mut problems);
    let file_text = path_text(file, "--file", &mut problems);
    if !is_lower_hex_sha256(sha256) {
        problems.push(format!(
            "--sha256 must be {SHA256_HEX_BYTES} lowercase hex characters"
        ));
    }
    if !problems.is_empty() {
        return Err(UnixInstallError::new(
            UnixInstallErrorKind::InvalidInput,
            problems,
        ));
    }
    Ok(vec![
        "sh".to_string(),
        script_path().to_string_lossy().into_owned(),
        "--prefix".to_string(),
        prefix_text,
        "--file".to_string(),
        file_text,
        "--sha256".to_string(),
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
            path.ends_with(Path::new("installer").join("unix.sh")),
            "unexpected script path: {}",
            path.display()
        );
        assert!(path.is_file(), "missing {}", path.display());
    }

    #[test]
    fn the_shipped_script_is_posix_and_carries_every_requirement() {
        let text = shipped_script();
        validate_script(&text).expect("the shipped script satisfies T-INST-03");
        assert!(text.starts_with("#!/bin/sh\n"), "missing POSIX shebang");
    }

    #[test]
    fn validation_rejects_bash_only_syntax() {
        let text = shipped_script();
        let cases = [
            ("[[ -n \"$HOME\" ]]", "double-bracket"),
            ("function helper() { :; }", "`function`"),
            ("local value=1", "`local`"),
            ("set -o pipefail", "pipefail"),
        ];
        for (snippet, needle) in cases {
            let mutated = format!("{text}\n{snippet}\n");
            let error = validate_script(&mutated).expect_err("bash syntax must be refused");
            assert_eq!(error.kind(), UnixInstallErrorKind::ScriptInvalid);
            assert!(
                error.problems().iter().any(|p| p.contains(needle)),
                "no problem mentioned {needle}: {:?}",
                error.problems()
            );
        }
    }

    #[test]
    fn validation_rejects_a_missing_flag_lock_trap_or_checksum() {
        let text = shipped_script();
        let cases = [
            ("        --uninstall)\n", "--uninstall"),
            ("trap cleanup EXIT", "EXIT cleanup trap"),
            ("mkdir \"$LOCK\"", "atomic lock creation"),
            ("shasum -a 256", "`shasum` checksum fallback"),
            ("stty sane", "terminal restore"),
            ("mv -f", "the atomic rename"),
        ];
        for (needle, expected) in cases {
            let mutated = text.replace(needle, "");
            assert_ne!(mutated, text, "fixture did not contain {needle}");
            let error = validate_script(&mutated)
                .expect_err(&format!("a removed `{needle}` must be refused"));
            assert!(
                error.problems().iter().any(|p| p.contains(expected)),
                "no problem mentioned {expected}: {:?}",
                error.problems()
            );
        }
    }

    #[test]
    fn validation_rejects_a_stdin_read() {
        let mutated = format!("{}\nread -r answer\n", shipped_script());
        let error = validate_script(&mutated).expect_err("a stdin prompt must be refused");
        assert!(error
            .problems()
            .iter()
            .any(|p| p.contains("must not read from stdin")));
    }

    #[test]
    fn install_command_builds_the_exact_argument_vector() {
        let sha = "0123456789abcdef".repeat(4);
        let argv = install_command(
            Path::new("/home/user/.local"),
            Path::new("/tmp/zero-download"),
            &sha,
        )
        .expect("valid install command");
        assert_eq!(
            argv,
            vec![
                "sh".to_string(),
                script_path().to_string_lossy().into_owned(),
                "--prefix".to_string(),
                "/home/user/.local".to_string(),
                "--file".to_string(),
                "/tmp/zero-download".to_string(),
                "--sha256".to_string(),
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
            let error = install_command(Path::new("/p"), Path::new("/f"), &digest)
                .expect_err("a bad digest must be refused");
            assert_eq!(error.kind(), UnixInstallErrorKind::InvalidInput);
            assert!(error.problems().iter().any(|p| p.contains("--sha256")));
        }

        let error = install_command(Path::new(""), Path::new("/f"), &good)
            .expect_err("an empty prefix must be refused");
        assert!(error.problems().iter().any(|p| p.contains("--prefix")));

        let error = install_command(Path::new("/p"), Path::new(""), &good)
            .expect_err("an empty file must be refused");
        assert!(error.problems().iter().any(|p| p.contains("--file")));
    }

    #[test]
    fn an_error_names_its_kind_and_every_problem() {
        let error = UnixInstallError::new(
            UnixInstallErrorKind::ScriptInvalid,
            vec!["one".to_string(), "two".to_string()],
        );
        assert_eq!(error.kind().as_str(), "script_invalid");
        let text = error.to_string();
        assert!(text.starts_with("zero.installer.script_invalid: "));
        assert!(text.contains("one") && text.contains("two"));
    }

    #[test]
    fn the_generator_does_not_execute_commands() {
        let source = include_str!("unix_install.rs");
        let production = source.split("#[cfg(test)]").next().unwrap_or_default();
        assert!(!production.contains("Command::new"));
        assert!(!production.contains("std::process"));
        assert!(!production.contains("sh -c"));
    }
}
