//! Kernel host-request gate (KRN-02): every file, shell, and network effect is a
//! typed request evaluated by the live policy. There is no ambient authority.

use zero_policy::dispatch::{execute_host_request, FileOp, HostRequest, PolicyEngine};
use zero_types::error::Result;

pub struct KernelHost {
    pub engine: PolicyEngine,
}

impl KernelHost {
    pub fn new(engine: PolicyEngine) -> Self {
        Self { engine }
    }

    pub fn read_file(&mut self, path: impl Into<std::path::PathBuf>, now_ms: i64) -> Result<Vec<u8>> {
        let request = HostRequest::File { op: FileOp::Read, path: path.into() };
        execute_host_request(&mut self.engine, &request, now_ms, || {
            if let HostRequest::File { path, .. } = &request {
                return std::fs::read(path).map_err(Into::into);
            }
            unreachable!()
        })
    }

    pub fn write_file(&mut self, path: impl Into<std::path::PathBuf>, bytes: &[u8], now_ms: i64) -> Result<()> {
        let request = HostRequest::File { op: FileOp::Write, path: path.into() };
        let expected = bytes.to_vec();
        let mut written = false;
        execute_host_request(&mut self.engine, &request, now_ms, || {
            if let HostRequest::File { path, .. } = &request {
                std::fs::write(path, &expected)?;
                written = true;
            }
            Ok(())
        })?;
        debug_assert!(written);
        Ok(())
    }

    pub fn delete_file(&mut self, path: impl Into<std::path::PathBuf>, now_ms: i64) -> Result<()> {
        let request = HostRequest::File { op: FileOp::Delete, path: path.into() };
        execute_host_request(&mut self.engine, &request, now_ms, || Ok(()))
    }

    pub fn shell(&mut self, command: &str, now_ms: i64) -> Result<()> {
        let request = HostRequest::Shell { command: command.into() };
        execute_host_request(&mut self.engine, &request, now_ms, || Ok(()))
    }
}
