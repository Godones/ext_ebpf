use lock_api::RawMutex;

use crate::{
    KprobeAuxiliaryOps, KprobeOps, ProbeManager, PtRegs, arch::Probe, clear_single_step,
    setup_single_step,
};

/// The uprobe structure for the current architecture.
pub type Uprobe<L, F> = Probe<L, F>;

/// Run uprobe which has been registered on the address
///
/// # Parameters
/// - `uprobe_manager`: The uprobe manager.
/// - `pt_regs`: The trap pt_regs.
///
/// # Returns
/// - An `Option` containing the result of the uprobe handler. If no uprobe is found, it returns `None`.
///
pub fn uprobe_handler_from_break<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    uprobe_manager: &mut ProbeManager<L, F>,
    pt_regs: &mut PtRegs,
) -> Option<()> {
    let break_addr = pt_regs.break_address();
    // log::debug!("uprobe_handler_from_break: break_addr: {:#x}", break_addr);
    let uprobe_list = uprobe_manager.get_break_list(break_addr);
    if let Some(uprobe_list) = uprobe_list {
        for uprobe in uprobe_list {
            if uprobe.is_enabled() {
                uprobe.call_pre_handler(pt_regs);
            }
        }

        // TODO: For uprobe, we may need to adjust the user space instruction pointer here.
        let point = uprobe_list[0].probe_point();
        let dynamic_user_ptr = point.dynamic_user_ptr();
        if dynamic_user_ptr != 0 {
            setup_single_step(pt_regs, dynamic_user_ptr);
        } else {
            let old_instruction_len = point.old_instruction_len();
            let single_step_address = point.single_step_address() as *mut u8;
            let user_ptr = F::alloc_user_exec_memory(|ptr| {
                unsafe {
                    // Copy the old instruction back to user space
                    core::ptr::copy_nonoverlapping(single_step_address, ptr, old_instruction_len);
                }
            });
            point.set_dynamic_user_ptr(user_ptr as usize);
            // update the single step address to the copied instruction
            setup_single_step(pt_regs, user_ptr as usize);
        }

        Some(())
    } else {
        // For some architectures, they do not support single step execution,
        // and we need to use breakpoint exceptions to simulate
        uprobe_handler_from_debug(uprobe_manager, pt_regs)
    }
}

/// Run uprobe which has been registered on the address
///
/// # Parameters
/// - `uprobe_manager`: The uprobe manager.
/// - `pt_regs`: The trap pt_regs.
///
/// # Returns
/// - An `Option` containing the result of the uprobe handler. If no uprobe is found, it returns `None`.
///
pub fn uprobe_handler_from_debug<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    uprobe_manager: &mut ProbeManager<L, F>,
    pt_regs: &mut PtRegs,
) -> Option<()> {
    let pc = pt_regs.debug_address();
    if let Some(uprobe_list) = uprobe_manager.get_debug_list(pc) {
        for uprobe in uprobe_list {
            if uprobe.is_enabled() {
                uprobe.call_post_handler(pt_regs);
                uprobe.call_event_callback(pt_regs);
            }
        }
        let return_address = uprobe_list[0].probe_point().return_address();
        clear_single_step(pt_regs, return_address);
        Some(())
    } else {
        log::debug!("There is no uprobe on pc {pc:#x}");
        None
    }
}
