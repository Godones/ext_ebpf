use crate::{BpfError, KernelAuxiliaryOps, Result, linux_bpf::*};
use alloc::string::String;
#[derive(Debug)]
pub struct BpfRawTracePointArg {
    pub name: String,
    pub prog_fd: u32,
}

impl BpfRawTracePointArg {
    pub fn try_from_bpf_attr<F: KernelAuxiliaryOps>(attr: &bpf_attr) -> Result<Self> {
        let (name_ptr, prog_fd) = unsafe {
            let name_ptr = attr.raw_tracepoint.name as *const u8;

            let prog_fd = attr.raw_tracepoint.prog_fd;
            (name_ptr, prog_fd)
        };
        let name = F::string_from_user_cstr(name_ptr)?;
        Ok(BpfRawTracePointArg { name, prog_fd })
    }
}
