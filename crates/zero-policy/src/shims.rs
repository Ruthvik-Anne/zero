//! PATH and PowerShell function shims (DEL-03).
//!
//! Generated shims forward to `zero-guard`, which runs the same parser as the
//! evaluator. They catch deletions invoked from scripts (Makefiles, npm, CI)
//! that never pass through the agent's shell tool.

use std::path::{Path, PathBuf};
use zero_types::error::Result;

pub const POSIX_NAMES: &[&str] = &["rm", "rmdir", "unlink", "shred"];
pub const POWERSHELL_NAMES: &[&str] = &["Remove-Item", "del", "erase", "rd", "rmdir", "ri", "rm"];
pub const CMD_NAMES: &[&str] = &["del", "erase", "rd", "rmdir"];

pub fn posix_script(guard: &Path) -> String {
    format!(
        "#!/bin/sh\n# Zero deletion guard shim. The original tool is intentionally not called.\nexec '{}' posix \"$(basename \"$0\")\" \"$@\"\n",
        guard.display()
    )
}

pub fn powershell_script(guard: &Path) -> String {
    let mut out = String::from("# Zero deletion guard shims.\n");
    for name in POWERSHELL_NAMES {
        out.push_str(&format!(
            "function global:{name} {{ & '{guard}' powershell {name} @args; if ($LASTEXITCODE -ne 0) {{ throw 'blocked by the Zero deletion guard' }} }}\n",
            guard = guard.display()
        ));
    }
    out
}

pub fn cmd_script(guard: &Path) -> String {
    format!("@echo off\r\n\"{}\" cmd %~n0 %*\r\nexit /b %ERRORLEVEL%\r\n", guard.display())
}

pub fn install_posix(dir: &Path, guard: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut paths = Vec::new();
    for name in POSIX_NAMES {
        let path = dir.join(name);
        std::fs::write(&path, posix_script(guard))?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755))?;
        }
        paths.push(path);
    }
    Ok(paths)
}

pub fn install_powershell(dir: &Path, guard: &Path) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join("zero-shims.ps1");
    std::fs::write(&path, powershell_script(guard))?;
    Ok(path)
}

pub fn install_cmd(dir: &Path, guard: &Path) -> Result<Vec<PathBuf>> {
    std::fs::create_dir_all(dir)?;
    let mut paths = Vec::new();
    for name in CMD_NAMES {
        let path = dir.join(format!("{name}.bat"));
        std::fs::write(&path, cmd_script(guard))?;
        paths.push(path);
    }
    Ok(paths)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generated_shims_point_at_the_guard_and_cover_every_name() {
        let guard = Path::new(r"C:\zero\zero-guard.exe");
        let posix = posix_script(guard);
        assert!(posix.contains("zero-guard.exe"));
        assert!(posix.contains("\"$(basename \"$0\")\""));

        let ps = powershell_script(guard);
        for name in POWERSHELL_NAMES {
            assert!(ps.contains(&format!("function global:{name}")), "{name}");
        }
        let cmd = cmd_script(guard);
        assert!(cmd.contains("%~n0"));
    }

    #[test]
    fn installation_writes_every_shim() {
        let dir = tempfile::tempdir().unwrap();
        let guard = dir.path().join("zero-guard");
        let posix = install_posix(&dir.path().join("posix"), &guard).unwrap();
        assert_eq!(posix.len(), POSIX_NAMES.len());
        let ps = install_powershell(&dir.path().join("ps"), &guard).unwrap();
        assert!(ps.exists());
        let cmd = install_cmd(&dir.path().join("cmd"), &guard).unwrap();
        assert_eq!(cmd.len(), CMD_NAMES.len());
    }
}
