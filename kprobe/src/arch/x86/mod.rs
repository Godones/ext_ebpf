use alloc::{string::ToString, sync::Arc};
use core::{
    alloc::Layout,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use lock_api::RawMutex;
use yaxpeax_arch::LengthedInstruction;

use crate::{
    kretprobe::{rethook_trampoline_handler, KretprobeInstance},
    KprobeAuxiliaryOps, KprobeBasic, KprobeBuilder, KprobeOps,
};

const EBREAK_INST: u8 = 0xcc; // x86_64: 0xcc
const MAX_INSTRUCTION_SIZE: usize = 15; // x86_64 max instruction length

pub struct Kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    basic: KprobeBasic<L>,
    point: Arc<X86KprobePoint<F>>,
}

#[derive(Debug)]
pub struct X86KprobePoint<F: KprobeAuxiliaryOps> {
    addr: usize,
    old_instruction_ptr: usize,
    old_instruction_len: usize,
    _marker: core::marker::PhantomData<F>,
}

impl<F: KprobeAuxiliaryOps> Drop for X86KprobePoint<F> {
    fn drop(&mut self) {
        let address = self.addr;
        unsafe {
            F::set_writeable_for_address(address, self.old_instruction_len, true);
            core::ptr::copy(
                self.old_instruction_ptr as *const u8,
                address as *mut u8,
                self.old_instruction_len,
            );
            F::set_writeable_for_address(address, self.old_instruction_len, false);
            core::arch::x86_64::_mm_mfence();
        }
        let decoder = yaxpeax_x86::amd64::InstDecoder::default();
        let buf = unsafe {
            core::slice::from_raw_parts(
                self.old_instruction_ptr as *const u8,
                self.old_instruction_len,
            )
        };
        let inst = decoder.decode_slice(buf).unwrap();

        F::dealloc_executable_memory(
            self.old_instruction_ptr as *mut u8,
            Layout::from_size_align(MAX_INSTRUCTION_SIZE + 1, 16).unwrap(),
        );
        log::trace!(
            "Kprobe::uninstall: address: {:#x}, old_instruction: {:?}",
            address,
            inst.to_string()
        );
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Debug for Kprobe<L, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kprobe")
            .field("basic", &self.basic)
            .field("point", &self.point)
            .finish()
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Deref for Kprobe<L, F> {
    type Target = KprobeBasic<L>;

    fn deref(&self) -> &Self::Target {
        &self.basic
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> DerefMut for Kprobe<L, F> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.basic
    }
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
    pub(crate) fn install<L: RawMutex + 'static>(self) -> (Kprobe<L, F>, Arc<X86KprobePoint<F>>) {
        let probe_point = match &self.probe_point {
            Some(point) => point.clone(),
            None => self.replace_inst(),
        };
        let kprobe = Kprobe {
            basic: KprobeBasic::from(self),
            point: probe_point.clone(),
        };
        (kprobe, probe_point)
    }

    /// Replace the instruction at the specified address with a breakpoint instruction.
    fn replace_inst(&self) -> Arc<X86KprobePoint<F>> {
        let address = self.symbol_addr + self.offset;
        let inst_tmp = F::alloc_executable_memory(
            Layout::from_size_align(MAX_INSTRUCTION_SIZE + 1, 16).unwrap(),
        );
        unsafe {
            core::ptr::copy(address as *const u8, inst_tmp, MAX_INSTRUCTION_SIZE);
        }

        let decoder = yaxpeax_x86::amd64::InstDecoder::default();
        let buf = unsafe { core::slice::from_raw_parts(inst_tmp, MAX_INSTRUCTION_SIZE) };
        let inst = decoder.decode_slice(&buf).unwrap();
        let len = inst.len().to_const();
        log::trace!("inst: {:?}, len: {:?}", inst.to_string(), len);

        let point = Arc::new(X86KprobePoint {
            addr: address,
            old_instruction_ptr: inst_tmp as usize,
            old_instruction_len: len as usize,
            _marker: core::marker::PhantomData,
        });

        unsafe {
            F::set_writeable_for_address(address, len as usize, true);
            core::ptr::write_volatile(address as *mut u8, EBREAK_INST);
            F::set_writeable_for_address(address, len as usize, false);
            core::arch::x86_64::_mm_mfence();
        }

        log::trace!(
            "Kprobe::install: address: {:#x}, func_name: {:?}",
            address,
            self.symbol
        );
        point
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Kprobe<L, F> {
    pub fn probe_point(&self) -> &Arc<X86KprobePoint<F>> {
        &self.point
    }
}

impl<F: KprobeAuxiliaryOps> KprobeOps for X86KprobePoint<F> {
    fn return_address(&self) -> usize {
        self.addr + self.old_instruction_len
    }
    fn single_step_address(&self) -> usize {
        self.old_instruction_ptr
    }
    fn debug_address(&self) -> usize {
        self.old_instruction_ptr + self.old_instruction_len
    }
    fn break_address(&self) -> usize {
        self.addr
    }
}

/// Set up a single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn setup_single_step(pt_regs: &mut PtRegs, single_step_address: usize) {
    pt_regs.update_pc(single_step_address);
    pt_regs.set_single_step(true);
}

/// Clear the single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn clear_single_step(pt_regs: &mut PtRegs, single_step_address: usize) {
    pt_regs.update_pc(single_step_address);
    pt_regs.set_single_step(false);
}

#[repr(C)]
#[derive(Debug, Copy, Clone)]
pub struct PtRegs {
    pub r15: usize,
    pub r14: usize,
    pub r13: usize,
    pub r12: usize,
    pub rbp: usize,
    pub rbx: usize,
    pub r11: usize,
    pub r10: usize,
    pub r9: usize,
    pub r8: usize,
    pub rax: usize,
    pub rcx: usize,
    pub rdx: usize,
    pub rsi: usize,
    pub rdi: usize,
    // On syscall entry, this is syscall#. On CPU exception, this is error code.
    // On hw interrupt, it's IRQ number
    pub orig_rax: usize,
    pub rip: usize,
    pub cs: usize,
    pub rflags: usize,
    pub rsp: usize,
    pub ss: usize,
}

impl PtRegs {
    pub(crate) fn break_address(&self) -> usize {
        (self.rip - 1) as usize // The breakpoint instruction is at the address of rip - 1
    }

    pub(crate) fn debug_address(&self) -> usize {
        self.rip as usize // The debug address is the current instruction pointer
    }

    pub(crate) fn update_pc(&mut self, pc: usize) {
        self.rip = pc as _;
    }

    pub(crate) fn set_single_step(&mut self, enable: bool) {
        if enable {
            self.rflags |= 0x100;
        } else {
            self.rflags &= !0x100;
        }
    }

    pub(crate) fn sp(&self) -> usize {
        self.rsp
    }

    pub fn ret_value(&self) -> usize {
        self.rax
    }
}


#[unsafe(naked)]
pub(crate) unsafe extern "C" fn arch_rethook_trampoline<
    L: RawMutex + 'static,
    F: KprobeAuxiliaryOps + 'static,
>() {
    core::arch::naked_asm!(
        // Push a fake return address to tell the unwinder it's a kretprobe.
        "pushq 0",
        "pushq {kernel_data_segment}", // fake ss
        // Save the 'sp - 16', this will be fixed later.
        "pushq %rsp",
        "pushfq", // rflags

        // SAVE_REGS_STRING
        "subq $24, %rsp", // skip cs, ip, orig_ax
        "pushq %rdi",
        "pushq %rsi",
        "pushq %rdx",
        "pushq %rcx",
        "pushq %rax",
        "pushq %r8",
        "pushq %r9",
        "pushq %r10",
        "pushq %r11",
        "pushq %rbx",
        "pushq %rbp",
        "pushq %r12",
        "pushq %r13",
        "pushq %r14",
        "pushq %r15",
        // ENCODE_FRAME_POINTER
        "lea 1(%rsp), %rbp",
        "movq %rsp, %rdi",
        "call {rethook_trampoline_callback}",
        // RESTORE_REGS_STRING
        "popq %r15",
        "popq %r14",
        "popq %r13",
        "popq %r12",
        "popq %rbp",
        "popq %rbx",
        "popq %r11",
        "popq %r10",
        "popq %r9",
        "popq %r8",
        "popq %rax",
        "popq %rcx",
        "popq %rdx",
        "popq %rsi",
        "popq %rdi",
        // Skip orig_ax, ip, cs
        "addq $24, %rsp",

        // In the callback function, 'regs->flags' is copied to 'regs->ss'.
        "addq $16, %rsp",

        "popfq",
        "ret",
        kernel_data_segment = const 0x10, // Kernel data segment
        // arch_rethook_trampoline = sym arch_rethook_trampoline::<L,F>,
        rethook_trampoline_callback = sym arch_rethook_trampoline_callback::<L, F>,
        options(att_syntax)
    )
}

pub(crate) fn arch_rethook_trampoline_callback<
    L: RawMutex + 'static,
    F: KprobeAuxiliaryOps + 'static,
>(
    pt_regs: &mut PtRegs,
) -> usize {
    pt_regs.rip = arch_rethook_trampoline::<L, F> as usize; // Set return address to trampoline
    pt_regs.orig_rax = usize::MAX;
    pt_regs.rsp += 16; // Adjust rsp to remove the fake return address

    let pt_regs_pointer = unsafe { (pt_regs as *mut PtRegs).add(1) as *mut usize };

    let correct_ret_addr = rethook_trampoline_handler::<L, F>(pt_regs, pt_regs_pointer as _);
    pt_regs.ss = pt_regs.rflags; // Copy eflags to ss
    correct_ret_addr
}

/// Fix up the return address in the pt_regs after a rethook.
pub(crate) fn arch_rethook_fixup_return(pt_regs: &mut PtRegs, correct_ret_addr: usize) {
    let pt_regs_pointer = unsafe { (pt_regs as *mut PtRegs).add(1) as *mut usize };
    unsafe {
        // Replace fake return address with real one.
        *pt_regs_pointer = correct_ret_addr as usize;
    }
}

/// Prepare the kretprobe instance for the rethook.
pub(crate) fn arch_rethook_prepare<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static>(
    kretprobe_instance: &mut KretprobeInstance,
    pt_regs: &mut PtRegs,
) {
    let sp = pt_regs.sp();
    let stack = unsafe { &mut *(sp as *mut usize) };
    // Prepare the kretprobe instance for the rethook
    // Get the return address from the stack
    kretprobe_instance.ret_addr = *stack;
    kretprobe_instance.frame = sp;
    *stack = arch_rethook_trampoline::<L, F> as _; // Set the return address to the trampoline
}
