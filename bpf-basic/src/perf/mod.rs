mod bpf;
mod util;
use alloc::boxed::Box;
use core::fmt::Debug;

use util::*;

use crate::{linux_bpf::*, BpfError, KernelAuxiliaryOps, Result};
pub trait PerfEventOps: Send + Sync + Debug {
    /// Set the bpf program for the perf event
    fn set_bpf_prog(&mut self, _bpf_prog: &[u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Enable the perf event
    fn enable(&mut self) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Disable the perf event
    fn disable(&mut self) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    /// Whether the perf event is readable
    fn readable(&self) -> bool;
}
