use core::fmt::Debug;

use crate::{BpfError, Result};

pub trait PerfEventOps: Send + Sync + Debug {
    /// Set the bpf program for the perf event
    fn set_bpf_prog(&self, _bpf_prog: &[u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Enable the perf event
    fn enable(&self) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Disable the perf event
    fn disable(&self) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Whether the perf event is readable
    fn readable(&self) -> bool;
}
