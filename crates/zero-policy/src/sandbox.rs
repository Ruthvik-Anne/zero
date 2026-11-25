//! Sandbox spike (TRU-03, TRU-06). Prototypes only; this does not replace the
//! guards. The decision record is `docs/decisions/0001-sandbox.md`.
//!
//! - Windows: a Job Object with a process-memory limit and kill-on-close.
//! - Linux: a Landlock ruleset that denies all handled write access.

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SandboxProbe {
    pub mechanism: &'static str,
    pub enforced: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SandboxError {
    Unsupported(String),
    Setup(String),
}

impl std::fmt::Display for SandboxError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SandboxError::Unsupported(reason) => write!(f, "unsupported: {reason}"),
            SandboxError::Setup(reason) => write!(f, "setup failed: {reason}"),
        }
    }
}

pub fn mechanism() -> &'static str {
    #[cfg(windows)]
    {
        "windows-job-object"
    }
    #[cfg(target_os = "linux")]
    {
        "linux-landlock"
    }
    #[cfg(not(any(windows, target_os = "linux")))]
    {
        "unavailable"
    }
}

#[cfg(windows)]
pub mod windows {
    use super::{SandboxError, SandboxProbe};
    use std::os::windows::io::AsRawHandle;
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::System::JobObjects::{
        AssignProcessToJobObject, CreateJobObjectW, JobObjectExtendedLimitInformation,
        SetInformationJobObject, TerminateJobObject, JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, JOB_OBJECT_LIMIT_PROCESS_MEMORY,
    };

    /// Start a child, put it in a Job Object with a 64 MiB memory cap and
    /// kill-on-close, then terminate the job and prove the child is gone.
    pub fn prototype() -> Result<SandboxProbe, SandboxError> {
        let mut child = std::process::Command::new("cmd")
            .args(["/c", "ping", "-n", "30", "127.0.0.1"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
            .map_err(|e| SandboxError::Setup(format!("spawn: {e}")))?;

        unsafe {
            let job = CreateJobObjectW(std::ptr::null_mut(), std::ptr::null());
            if job.is_null() {
                let _ = child.kill();
                return Err(SandboxError::Setup("CreateJobObjectW failed".into()));
            }
            let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            info.BasicLimitInformation.LimitFlags =
                JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE | JOB_OBJECT_LIMIT_PROCESS_MEMORY;
            info.ProcessMemoryLimit = 64 * 1024 * 1024;
            let size = std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32;
            let set = SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                size,
            );
            if set == 0 {
                CloseHandle(job);
                let _ = child.kill();
                return Err(SandboxError::Setup("SetInformationJobObject failed".into()));
            }
            let handle: HANDLE = child.as_raw_handle() as HANDLE;
            if AssignProcessToJobObject(job, handle) == 0 {
                CloseHandle(job);
                let _ = child.kill();
                return Err(SandboxError::Setup("AssignProcessToJobObject failed".into()));
            }
            // Terminating the job must end the child.
            TerminateJobObject(job, 1);
            CloseHandle(job);
        }

        let status = child.wait().map_err(|e| SandboxError::Setup(format!("wait: {e}")))?;
        Ok(SandboxProbe {
            mechanism: "windows-job-object",
            enforced: true,
            detail: format!(
                "memory cap 64 MiB, kill-on-close; child exited with {:?}",
                status.code()
            ),
        })
    }
}

#[cfg(target_os = "linux")]
pub mod linux {
    use super::{SandboxError, SandboxProbe};

    const SYS_CREATE_RULESET: libc::c_long = 444;
    const SYS_RESTRICT_SELF: libc::c_long = 446;
    const CREATE_VERSION: usize = 1;
    const PR_SET_NO_NEW_PRIVS: libc::c_int = 38;

    // LANDLOCK_ACCESS_FS_* bits: write_file, remove_dir, remove_file, make_*.
    const HANDLED: u64 = (1 << 1) | (1 << 4) | (1 << 5) | (1 << 6) | (1 << 7) | (1 << 8) | (1 << 9) | (1 << 10)
        | (1 << 11)
        | (1 << 12);

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
    }

    unsafe fn syscall3(number: libc::c_long, a: usize, b: usize, c: usize) -> libc::c_long {
        libc::syscall(number, a, b, c)
    }

    /// Query the Landlock ABI and deny every handled write access for this
    /// process and its children. Irreversible; call it in a throwaway process.
    pub fn confine_writes() -> Result<SandboxProbe, SandboxError> {
        let abi = unsafe { syscall3(SYS_CREATE_RULESET, 0, 0, CREATE_VERSION) };
        if abi < 1 {
            return Err(SandboxError::Unsupported(format!(
                "Landlock is not available (ABI query returned {abi})"
            )));
        }
        let attr = RulesetAttr { handled_access_fs: HANDLED };
        let fd = unsafe {
            syscall3(
                SYS_CREATE_RULESET,
                &attr as *const RulesetAttr as usize,
                std::mem::size_of::<RulesetAttr>(),
                0,
            )
        };
        if fd < 0 {
            return Err(SandboxError::Setup(format!("landlock_create_ruleset: errno {}", std::io::Error::last_os_error())));
        }
        if unsafe { libc::prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
            return Err(SandboxError::Setup("prctl(PR_SET_NO_NEW_PRIVS) failed".into()));
        }
        let restricted = unsafe { libc::syscall(SYS_RESTRICT_SELF, fd as libc::c_int, 0) };
        unsafe { libc::close(fd as libc::c_int) };
        if restricted != 0 {
            return Err(SandboxError::Setup(format!(
                "landlock_restrict_self: errno {}",
                std::io::Error::last_os_error()
            )));
        }
        Ok(SandboxProbe {
            mechanism: "linux-landlock",
            enforced: true,
            detail: format!("ABI {abi}; all handled write access denied"),
        })
    }
}
