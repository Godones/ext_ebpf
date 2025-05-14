pub mod bpf;
mod util;
use alloc::{boxed::Box, sync::Arc};
use core::{any::Any, fmt::Debug};

use util::*;
pub use util::{PerfEventIoc, PerfProbeArgs};

use crate::{linux_bpf::*, BpfError, KernelAuxiliaryOps, Result};
pub trait PerfEventOps: Send + Sync + Debug {
    /// Set the bpf program for the perf event
    fn set_bpf_prog(&mut self, _bpf_prog: Arc<dyn Any + Send + Sync>) -> Result<()> {
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
    /// Whether the perf event is writable
    fn writeable(&self) -> bool;
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
}
