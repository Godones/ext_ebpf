use alloc::sync::Arc;
use core::{
    alloc::Layout,
    arch::riscv64::sfence_vma_all,
    fmt::Debug,
    ops::{Deref, DerefMut},
};

use lock_api::RawMutex;

use super::KprobeAuxiliaryOps;
use crate::{KprobeBasic, KprobeBuilder, KprobeOps, ProbeArgs};
const EBREAK_INST: u32 = 0x00100073; // ebreak
const C_EBREAK_INST: u32 = 0x9002; // c.ebreak
const INSN_LENGTH_MASK: u16 = 0x3;
const INSN_LENGTH_32: u16 = 0x3;

#[derive(Debug)]
pub struct Kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    basic: KprobeBasic<L>,
    point: Arc<Rv64KprobePoint<F>>,
}

#[derive(Debug)]
enum OpcodeTy {
    Inst16(u16),
    Inst32(u32),
}
#[derive(Debug)]
pub struct Rv64KprobePoint<F: KprobeAuxiliaryOps> {
    addr: usize,
    old_instruction: OpcodeTy,
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
    pub fn probe_point(&self) -> &Arc<Rv64KprobePoint<F>> {
        &self.point
    }
}

impl<F: KprobeAuxiliaryOps> Drop for Rv64KprobePoint<F> {
    fn drop(&mut self) {
        let address = self.addr;
        match self.old_instruction {
            OpcodeTy::Inst16(inst_16) => unsafe {
                F::set_writeable_for_address(address, 2, true);
                core::ptr::write(address as *mut u16, inst_16);
                F::set_writeable_for_address(address, 2, false);
            },
            OpcodeTy::Inst32(inst_32) => unsafe {
                F::set_writeable_for_address(address, 4, true);
                core::ptr::write(address as *mut u32, inst_32);
                F::set_writeable_for_address(address, 4, false);
            },
        }
        F::dealloc_executable_memory(
            self.inst_tmp_ptr as *mut u8,
            Layout::from_size_align(8, 8).unwrap(),
        );
        unsafe {
            sfence_vma_all();
        }
        log::trace!(
            "Kprobe::uninstall: address: {:#x}, old_instruction: {:?}",
            address,
            self.old_instruction
        );
    }
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
    pub fn install<L: RawMutex + 'static>(self) -> (Kprobe<L, F>, Arc<Rv64KprobePoint<F>>) {
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
    fn replace_inst(&self) -> Arc<Rv64KprobePoint<F>> {
        let address = self.symbol_addr + self.offset;
        let inst_16 = unsafe { core::ptr::read(address as *const u16) };
        // See <https://elixir.bootlin.com/linux/v6.10.2/source/arch/riscv/kernel/probes/kprobes.c#L68>
        let is_inst_16 = if (inst_16 & INSN_LENGTH_MASK) == INSN_LENGTH_32 {
            false
        } else {
            true
        };

        let inst_tmp_ptr =
            F::alloc_executable_memory(Layout::from_size_align(8, 8).unwrap()) as usize;
        let mut point = Rv64KprobePoint {
            old_instruction: OpcodeTy::Inst16(0),
            inst_tmp_ptr,
            addr: address,
            _marker: core::marker::PhantomData,
        };

        if is_inst_16 {
            point.old_instruction = OpcodeTy::Inst16(inst_16);
            unsafe {
                F::set_writeable_for_address(address, 2, true);
                core::ptr::write(address as *mut u16, C_EBREAK_INST as u16);
                F::set_writeable_for_address(address, 2, false);
                // inst_16 :0-16
                // c.ebreak:16-32
                core::ptr::write(inst_tmp_ptr as *mut u16, inst_16);
                core::ptr::write((inst_tmp_ptr + 2) as *mut u16, C_EBREAK_INST as u16);
            }
        } else {
            let inst_32 = unsafe { core::ptr::read(address as *const u32) };
            point.old_instruction = OpcodeTy::Inst32(inst_32);
            unsafe {
                F::set_writeable_for_address(address, 4, true);
                core::ptr::write(address as *mut u32, EBREAK_INST);
                F::set_writeable_for_address(address, 4, false);
                // inst_32 :0-32
                // ebreak  :32-64
                core::ptr::write(inst_tmp_ptr as *mut u32, inst_32);
                core::ptr::write((inst_tmp_ptr + 4) as *mut u32, EBREAK_INST);
            }
        }
        unsafe {
            sfence_vma_all();
        }
        log::trace!(
            "Kprobe::install: address: {:#x}, func_name: {:?}, opcode: {:x?}",
            address,
            self.symbol,
            point.old_instruction
        );
        Arc::new(point)
    }
}

impl<F: KprobeAuxiliaryOps> KprobeOps for Rv64KprobePoint<F> {
    fn return_address(&self) -> usize {
        let address = self.addr;
        match self.old_instruction {
            OpcodeTy::Inst16(_) => address + 2,
            OpcodeTy::Inst32(_) => address + 4,
        }
    }
    fn single_step_address(&self) -> usize {
        self.inst_tmp_ptr
    }
    fn debug_address(&self) -> usize {
        match self.old_instruction {
            OpcodeTy::Inst16(_) => self.inst_tmp_ptr + 2,
            OpcodeTy::Inst32(_) => self.inst_tmp_ptr + 4,
        }
    }
    fn break_address(&self) -> usize {
        self.addr
    }
}

/// Set up a single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn setup_single_step(frame: &mut dyn ProbeArgs, single_step_address: usize) {
    frame.update_pc(single_step_address);
}

/// Clear the single step for the given address.
///
/// This function updates the program counter (PC) to the specified address.
pub(crate) fn clear_single_step(frame: &mut dyn ProbeArgs, single_step_address: usize) {
    frame.update_pc(single_step_address);
}
