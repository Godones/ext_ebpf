#![no_std]
#![feature(c_variadic)]
#![allow(unused)]
extern crate alloc;
use alloc::string::String;

use map::UnifiedMap;
pub mod helper;
pub mod linux_bpf;
pub mod map;
pub mod perf;
mod preprocessor;
pub mod prog;

pub use preprocessor::EBPFPreProcessor;

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
    /// Get a unified map pointer from a file descriptor.
    fn get_unified_map_ptr_from_fd(map_fd: u32) -> Result<*const u8>;
    /// Copy data from a user space pointer to a kernel space buffer.
    fn copy_from_user(src: *const u8, size: usize, dst: &mut [u8]) -> Result<()>;
    /// Copy data from a kernel space buffer to a user space pointer.
    fn copy_to_user(dest: *mut u8, size: usize, src: &[u8]) -> Result<()>;
    /// Get the current CPU ID.
    fn current_cpu_id() -> u32;
    /// Output some data to a perf buf
    fn perf_event_output(
        ctx: *mut core::ffi::c_void,
        fd: u32,
        flags: u32,
        data: &[u8],
    ) -> Result<()>;
    /// Read a string from a user space pointer.
    fn string_from_user_cstr(ptr: *const u8) -> Result<String>;
    /// For ebpf print helper functions
    fn ebpf_write_str(str: &str) -> Result<()>;
    // For ebpf ktime helper functions
    fn ebpf_time_ns() -> Result<u64>;
}
