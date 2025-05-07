use alloc::sync::Arc;
use core::{
    alloc::Layout,
    ops::{Deref, DerefMut},
};

use lock_api::RawMutex;

use super::KprobeAuxiliaryOps;
use crate::{KprobeBasic, KprobeBuilder, KprobeOps, ProbeArgs};
const BRK_KPROBE_BP: u64 = 10;
const BRK_KPROBE_SSTEPBP: u64 = 11;
const EBREAK_INST: u32 = 0x002a0000;

#[derive(Debug)]
pub struct Kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    basic: KprobeBasic<L>,
    point: Arc<LA64KprobePoint<F>>,
}
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
    pub fn probe_point(&self) -> &Arc<LA64KprobePoint<F>> {
        &self.point
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
        log::trace!(
            "Kprobe::uninstall: address: {:#x}, old_instruction: {:?}",
            address,
            inst_32
        );
    }
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
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

/// Set up a single step for the given address.
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
