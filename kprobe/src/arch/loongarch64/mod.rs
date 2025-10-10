use alloc::sync::Arc;
use core::{
    alloc::Layout,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use lock_api::RawMutex;

use super::KprobeAuxiliaryOps;
use crate::{
    KprobeBasic, KprobeBuilder, KprobeOps,
    kretprobe::{KretprobeInstance, rethook_trampoline_handler},
};
// const BRK_KPROBE_BP: u64 = 10;
// const BRK_KPROBE_SSTEPBP: u64 = 11;
const EBREAK_INST: u32 = 0x002a0000;

/// The kprobe structure.
pub struct Kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    basic: KprobeBasic<L>,
    point: Arc<LA64KprobePoint<F>>,
}

/// The kprobe point structure for LoongArch64 architecture.
#[derive(Debug)]
pub struct LA64KprobePoint<F: KprobeAuxiliaryOps> {
    addr: usize,
    inst_tmp_ptr: usize,
    _marker: core::marker::PhantomData<F>,
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

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Kprobe<L, F> {
    /// Get the probe point of the kprobe.
    pub fn probe_point(&self) -> &Arc<LA64KprobePoint<F>> {
        &self.point
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

impl<F: KprobeAuxiliaryOps> Drop for LA64KprobePoint<F> {
    fn drop(&mut self) {
        let address = self.addr;
        let inst_tmp_ptr = self.inst_tmp_ptr;
        let inst_32 = unsafe { core::ptr::read(inst_tmp_ptr as *const u32) };
        unsafe {
            F::set_writeable_for_address(address, 4, true);
            core::ptr::write(address as *mut u32, inst_32);
            F::set_writeable_for_address(address, 4, false);
        }
        // Deallocate the executable memory
        let layout = Layout::from_size_align(8, 8).unwrap();
        F::dealloc_executable_memory(inst_tmp_ptr as *mut u8, layout);
        log::trace!("Kprobe::uninstall: address: {address:#x}, old_instruction: {inst_32:?}");
    }
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
    /// Install the kprobe by replacing the instruction at the specified address with a breakpoint instruction.
    pub fn install<L: RawMutex + 'static>(self) -> (Kprobe<L, F>, Arc<LA64KprobePoint<F>>) {
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
    fn replace_inst(&self) -> Arc<LA64KprobePoint<F>> {
        let address = self.symbol_addr + self.offset;

        let inst_tmp_ptr =
            F::alloc_executable_memory(Layout::from_size_align(8, 8).unwrap()) as usize;

        let point = LA64KprobePoint {
            addr: address,
            inst_tmp_ptr,
            _marker: core::marker::PhantomData,
        };
        let inst_32 = unsafe { core::ptr::read(address as *const u32) };
        unsafe {
            F::set_writeable_for_address(address, 4, true);
            core::ptr::write(address as *mut u32, EBREAK_INST);
            F::set_writeable_for_address(address, 4, false);
            // inst_32 :0-32
            // ebreak  :32-64
            core::ptr::write(inst_tmp_ptr as *mut u32, inst_32);
            core::ptr::write((inst_tmp_ptr + 4) as *mut u32, EBREAK_INST);
        }
        log::trace!(
            "Kprobe::install: address: {:#x}, func_name: {:?}, opcode: {:x?}",
            address,
            self.symbol,
            inst_32
        );
        Arc::new(point)
    }
}

impl<F: KprobeAuxiliaryOps> KprobeOps for LA64KprobePoint<F> {
    fn return_address(&self) -> usize {
        self.addr + 4
    }

    fn single_step_address(&self) -> usize {
        self.inst_tmp_ptr
    }

    fn debug_address(&self) -> usize {
        self.inst_tmp_ptr + 4
    }

    fn break_address(&self) -> usize {
        self.addr
    }
}
/// The register state at the time of the probe.
#[repr(C)]
#[derive(Debug, Copy, Clone)]
#[repr(align(8))]
#[allow(missing_docs)]
pub struct PtRegs {
    pub regs: [usize; 32],
    pub orig_a0: usize,
    pub csr_era: usize,
    pub csr_badvaddr: usize,
    pub csr_crmd: usize,
    pub csr_prmd: usize,
    pub csr_euen: usize,
    pub csr_ecfg: usize,
    pub csr_estat: usize,
}

impl PtRegs {
    pub(crate) fn break_address(&self) -> usize {
        self.csr_era
    }

    pub(crate) fn debug_address(&self) -> usize {
        self.csr_era
    }

    pub(crate) fn update_pc(&mut self, pc: usize) {
        self.csr_era = pc;
    }

    /// Get the return value from the registers.
    pub fn ret_value(&self) -> usize {
        self.regs[4]
    }
}

/// Set up a single step for the given address.
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn setup_single_step(pt_regs: &mut PtRegs, single_step_address: usize) {
    pt_regs.update_pc(single_step_address);
}

/// Clear the single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn clear_single_step(pt_regs: &mut PtRegs, single_step_address: usize) {
    pt_regs.update_pc(single_step_address);
}

#[unsafe(naked)]
pub(crate) unsafe extern "C" fn arch_rethook_trampoline<
    L: RawMutex + 'static,
    F: KprobeAuxiliaryOps + 'static,
>() {
    core::arch::naked_asm!(
        "addi.d $sp, $sp, -{pt_regs_size}",
        "st.d $ra, $sp, 1*8",
        "st.d $tp, $sp, 2*8",
        "st.d $a0, $sp, 4*8",
        "st.d $a1, $sp, 5*8",
        "st.d $a2, $sp, 6*8",
        "st.d $a3, $sp, 7*8",
        "st.d $a4, $sp, 8*8",
        "st.d $a5, $sp, 9*8",
        "st.d $a6, $sp, 10*8",
        "st.d $a7, $sp, 11*8",
        "st.d $t0, $sp, 12*8",
        "st.d $t1, $sp, 13*8",
        "st.d $t2, $sp, 14*8",
        "st.d $t3, $sp, 15*8",
        "st.d $t4, $sp, 16*8",
        "st.d $t5, $sp, 17*8",
        "st.d $t6, $sp, 18*8",
        "st.d $t7, $sp, 19*8",
        "st.d $t8, $sp, 20*8",
        "st.d $r21, $sp, 21*8",
        "st.d $fp, $sp, 22*8",
        "st.d $s0, $sp, 23*8",
        "st.d $s1, $sp, 24*8",
        "st.d $s2, $sp, 25*8",
        "st.d $s3, $sp, 26*8",
        "st.d $s4, $sp, 27*8",
        "st.d $s5, $sp, 28*8",
        "st.d $s6, $sp, 29*8",
        "st.d $s7, $sp, 30*8",
        "st.d $s8, $sp, 31*8",

        "addi.d $t0, $sp, {pt_regs_size}",
        "st.d $t0, $sp, 3*8", // sp
        "move $a0, $sp", // pt_regs pointer

        "bl {callback}",

        "move $ra, $a0", // Restore return address
        "ld.d $tp, $sp, 2*8",
        "ld.d $a0, $sp, 4*8",
        "ld.d $a1, $sp, 5*8",
        "ld.d $a2, $sp, 6*8",
        "ld.d $a3, $sp, 7*8",
        "ld.d $a4, $sp, 8*8",
        "ld.d $a5, $sp, 9*8",
        "ld.d $a6, $sp, 10*8",
        "ld.d $a7, $sp, 11*8",
        "ld.d $t0, $sp, 12*8",
        "ld.d $t1, $sp, 13*8",
        "ld.d $t2, $sp, 14*8",
        "ld.d $t3, $sp, 15*8",
        "ld.d $t4, $sp, 16*8",
        "ld.d $t5, $sp, 17*8",
        "ld.d $t6, $sp, 18*8",
        "ld.d $t7, $sp, 19*8",
        "ld.d $t8, $sp, 20*8",
        "ld.d $r21, $sp, 21*8",
        "ld.d $fp, $sp, 22*8",
        "ld.d $s0, $sp, 23*8",
        "ld.d $s1, $sp, 24*8",
        "ld.d $s2, $sp, 25*8",
        "ld.d $s3, $sp, 26*8",
        "ld.d $s4, $sp, 27*8",
        "ld.d $s5, $sp, 28*8",
        "ld.d $s6, $sp, 29*8",
        "ld.d $s7, $sp, 30*8",
        "ld.d $s8, $sp, 31*8",
        "addi.d $sp, $sp, {pt_regs_size}",
        "jr $ra",
        pt_regs_size = const core::mem::size_of::<PtRegs>(),
        callback = sym arch_rethook_trampoline_callback::<L, F>,
    )
}

pub(crate) fn arch_rethook_trampoline_callback<
    L: RawMutex + 'static,
    F: KprobeAuxiliaryOps + 'static,
>(
    pt_regs: &mut PtRegs,
) -> usize {
    rethook_trampoline_handler::<L, F>(pt_regs, 0)
}

pub(crate) fn arch_rethook_fixup_return(_pt_regs: &mut PtRegs, _correct_ret_addr: usize) {
    // Set the return address to the correct one
    // pt_regs.ra = correct_ret_addr as usize; // we don't need to set ra,
}

/// Prepare the kretprobe instance for the rethook.
pub(crate) fn arch_rethook_prepare<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static>(
    kretprobe_instance: &mut KretprobeInstance,
    pt_regs: &mut PtRegs,
) {
    // Prepare the kretprobe instance for the rethook
    kretprobe_instance.ret_addr = pt_regs.regs[1];
    kretprobe_instance.frame = 0; // fp
    pt_regs.regs[1] = arch_rethook_trampoline::<L, F> as _; // Set the return address to the trampoline
}
