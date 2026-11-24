//! Resource limits for agent-launched work (FND-11).
//!
//! The governor is the single accounting point for memory, disk, process count,
//! CPU time, and per-file size. Exceeding a bound returns a typed error before
//! the work grows further; it never relies on the host dying first.

use crate::error::{ErrorCode, Result, ZeroError};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResourceLimits {
    pub max_memory_bytes: u64,
    pub max_disk_bytes: u64,
    pub max_processes: u32,
    pub max_file_bytes: u64,
    pub max_cpu_millis: u64,
}

impl Default for ResourceLimits {
    fn default() -> Self {
        Self {
            max_memory_bytes: 2 * 1024 * 1024 * 1024,
            max_disk_bytes: 20 * 1024 * 1024 * 1024,
            max_processes: 16,
            max_file_bytes: 512 * 1024 * 1024,
            max_cpu_millis: 30 * 60 * 1000,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Resource {
    Memory,
    Disk,
    Processes,
    FileSize,
    Cpu,
}

impl Resource {
    pub fn as_str(self) -> &'static str {
        match self {
            Resource::Memory => "memory",
            Resource::Disk => "disk",
            Resource::Processes => "processes",
            Resource::FileSize => "file_size",
            Resource::Cpu => "cpu",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Usage {
    pub memory_bytes: u64,
    pub disk_bytes: u64,
    pub processes: u32,
    pub largest_file_bytes: u64,
    pub cpu_millis: u64,
}

#[derive(Debug, Clone)]
pub struct Governor {
    limits: ResourceLimits,
    usage: Usage,
}

impl Governor {
    pub fn new(limits: ResourceLimits) -> Self {
        Self { limits, usage: Usage::default() }
    }

    pub fn limits(&self) -> &ResourceLimits {
        &self.limits
    }

    pub fn usage(&self) -> &Usage {
        &self.usage
    }

    fn exceeded(resource: Resource, value: u64, limit: u64) -> ZeroError {
        ZeroError::new(
            ErrorCode::LimitExceeded,
            format!("{} limit exceeded: {value} > {limit}", resource.as_str()),
        )
        .with_context(resource)
    }

    /// Reserve memory before allocating. On success the reservation is counted.
    pub fn reserve_memory(&mut self, bytes: u64) -> Result<()> {
        let next = self.usage.memory_bytes.saturating_add(bytes);
        if next > self.limits.max_memory_bytes {
            return Err(Self::exceeded(Resource::Memory, next, self.limits.max_memory_bytes));
        }
        self.usage.memory_bytes = next;
        Ok(())
    }

    pub fn release_memory(&mut self, bytes: u64) {
        self.usage.memory_bytes = self.usage.memory_bytes.saturating_sub(bytes);
    }

    /// Check a file size before writing it and account for the disk growth.
    pub fn write_file(&mut self, bytes: u64) -> Result<()> {
        if bytes > self.limits.max_file_bytes {
            return Err(Self::exceeded(Resource::FileSize, bytes, self.limits.max_file_bytes));
        }
        let next = self.usage.disk_bytes.saturating_add(bytes);
        if next > self.limits.max_disk_bytes {
            return Err(Self::exceeded(Resource::Disk, next, self.limits.max_disk_bytes));
        }
        self.usage.disk_bytes = next;
        self.usage.largest_file_bytes = self.usage.largest_file_bytes.max(bytes);
        Ok(())
    }

    /// Claim a process slot.
    pub fn spawn_process(&mut self) -> Result<ProcessSlot> {
        let next = self.usage.processes + 1;
        if next > self.limits.max_processes {
            return Err(Self::exceeded(Resource::Processes, next as u64, self.limits.max_processes as u64));
        }
        self.usage.processes = next;
        Ok(ProcessSlot { active: true })
    }

    pub fn release_process(&mut self) {
        self.usage.processes = self.usage.processes.saturating_sub(1);
    }

    /// Account CPU time. Returns a typed error once the budget is exhausted.
    pub fn account_cpu(&mut self, millis: u64) -> Result<()> {
        let next = self.usage.cpu_millis.saturating_add(millis);
        if next > self.limits.max_cpu_millis {
            return Err(Self::exceeded(Resource::Cpu, next, self.limits.max_cpu_millis));
        }
        self.usage.cpu_millis = next;
        Ok(())
    }
}

/// A process slot handle; releasing it returns capacity to the governor.
#[derive(Debug)]
pub struct ProcessSlot {
    active: bool,
}

impl ProcessSlot {
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Drop for ProcessSlot {
    fn drop(&mut self) {
        self.active = false;
    }
}

impl ZeroError {
    fn with_context(self, resource: Resource) -> Self {
        ZeroError::new(self.code(), format!("{} [{}]", self.message(), resource.as_str()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn small() -> Governor {
        Governor::new(ResourceLimits {
            max_memory_bytes: 1024,
            max_disk_bytes: 4096,
            max_processes: 2,
            max_file_bytes: 512,
            max_cpu_millis: 100,
        })
    }

    #[test]
    fn runaway_memory_returns_a_typed_error() {
        let mut g = small();
        let mut allocations = 0;
        loop {
            match g.reserve_memory(128) {
                Ok(()) => allocations += 1,
                Err(e) => {
                    assert_eq!(e.code(), ErrorCode::LimitExceeded);
                    assert!(e.message().contains("memory"));
                    break;
                }
            }
            assert!(allocations < 100, "governor did not stop the run");
        }
        assert_eq!(allocations, 8);
    }

    #[test]
    fn runaway_file_and_disk_return_typed_errors() {
        let mut g = small();
        let err = g.write_file(513).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(err.message().contains("file_size"));

        let mut g = small();
        for _ in 0..8 {
            g.write_file(512).unwrap();
        }
        let err = g.write_file(1).unwrap_err();
        assert!(err.message().contains("disk"));
    }

    #[test]
    fn runaway_processes_return_a_typed_error() {
        let mut g = small();
        let a = g.spawn_process().unwrap();
        let b = g.spawn_process().unwrap();
        assert_eq!(g.spawn_process().unwrap_err().code(), ErrorCode::LimitExceeded);
        assert!(a.is_active() && b.is_active());
        g.release_process();
        g.release_process();
        assert!(g.spawn_process().is_ok());
    }

    #[test]
    fn runaway_cpu_returns_a_typed_error() {
        let mut g = small();
        g.account_cpu(60).unwrap();
        let err = g.account_cpu(60).unwrap_err();
        assert_eq!(err.code(), ErrorCode::LimitExceeded);
        assert!(err.message().contains("cpu"));
    }

    #[test]
    fn every_resource_names_itself() {
        for r in [Resource::Memory, Resource::Disk, Resource::Processes, Resource::FileSize, Resource::Cpu] {
            assert!(!r.as_str().is_empty());
        }
    }
}
