#![no_std]
#![feature(c_variadic)]
#![allow(unused)]
extern crate alloc;
use map::UnifiedMap;
mod helper;
mod linux_bpf;
pub mod map;

pub type Result<T> = core::result::Result<T, BpfError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfError {
    InvalidArgument,
    NotSupported,
    NotFound,
    NoSpace,
}

impl core::fmt::Display for BpfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            BpfError::InvalidArgument => write!(f, "Invalid argument"),
            BpfError::NotSupported => write!(f, "Not supported"),
            BpfError::NotFound => write!(f, "Not found"),
            BpfError::NoSpace => write!(f, "No space"),
        }
    }
}
impl core::error::Error for BpfError {}

/// The KernelAuxiliaryOps trait provides auxiliary operations which should
/// be implemented by the kernel or a kernel-like environment.
pub trait KernelAuxiliaryOps {
    /// Get a unified map from a pointer.
    fn get_unified_map_from_ptr<F, R>(ptr: *const u8, func: F) -> Result<R>
    where
        F: FnOnce(&mut UnifiedMap) -> Result<R>;
    /// Get a unified map from a file descriptor.
    fn get_unified_map_from_fd<F, R>(map_fd: u32, func: F) -> Result<R>
    where
        F: FnOnce(&mut UnifiedMap) -> Result<R>;
    /// Transmute a pointer to a buffer of bytes into a slice.
    fn transmute_buf<'a>(ptr: *const u8, size: usize) -> Result<&'a [u8]>;
    /// Transmute a mutable pointer to a buffer of bytes into a mutable slice.
    fn transmute_buf_mut<'a>(ptr: *mut u8, size: usize) -> Result<&'a mut [u8]>;
    /// Get the current CPU ID.
    fn current_cpu_id() -> u32;
    fn perf_event_output(
        ctx: *mut core::ffi::c_void,
        fd: u32,
        flags: u32,
        data: &[u8],
    ) -> Result<()>;
}
