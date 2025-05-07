#![cfg_attr(target_arch = "riscv64", feature(riscv_ext_intrinsics))]
#![no_std]
extern crate alloc;

mod arch;
mod manager;

use alloc::sync::Arc;

pub use arch::*;
use lock_api::RawMutex;
pub use manager::*;

/// Register a kprobe.
///
/// # Parameters
/// - `manager`: The kprobe manager.
/// - `kprobe_point_list`: The list of kprobe points.
/// - `kprobe_builder`: The kprobe builder.
///
/// # Returns
/// - An `Arc` containing the registered kprobe.
///
pub fn register_kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    kprobe_point_list: &mut KprobePointList<F>,
    kprobe_builder: KprobeBuilder<F>,
) -> Arc<Kprobe<L, F>> {
    let address = kprobe_builder.probe_addr();
    let existed_point = kprobe_point_list.get(&address).map(Clone::clone);
    let kprobe = match existed_point {
        Some(existed_point) => kprobe_builder.with_probe_point(existed_point).install().0,
        None => {
            let (kprobe, probe_point) = kprobe_builder.install();
            kprobe_point_list.insert(address, probe_point);
            kprobe
        }
    };
    let kprobe = Arc::new(kprobe);
    manager.insert_kprobe(kprobe.clone());
    kprobe
}

/// Unregister a kprobe.
///
/// # Parameters
/// - `manager`: The kprobe manager.
/// - `kprobe_point_list`: The list of kprobe points.
/// - `kprobe`: The kprobe to unregister.
///
pub fn unregister_kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    kprobe_point_list: &mut KprobePointList<F>,
    kprobe: Arc<Kprobe<L, F>>,
) {
    let kprobe_addr = kprobe.probe_point().break_address();
    manager.remove_kprobe(&kprobe);

    if manager.kprobe_num(kprobe_addr) == 0 {
        kprobe_point_list.remove(&kprobe_addr);
    }
}

/// Run kprobe which has been registered on the address
///
/// # Parameters
/// - `manager`: The kprobe manager.
/// - `frame`: The trap frame.
///
/// # Returns
/// - An `Option` containing the result of the kprobe handler. If no kprobe is found, it returns `None`.
///
pub fn kprobe_handler_from_break<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    frame: &mut dyn ProbeArgs,
) -> Option<()> {
    let break_addr = frame.break_address();
    // log::debug!("EBreak: break_addr: {:#x}", break_addr);
    let kprobe_list = manager.get_break_list(break_addr);
    if let Some(kprobe_list) = kprobe_list {
        for kprobe in kprobe_list {
            if kprobe.is_enabled() {
                kprobe.call_pre_handler(frame);
            }
        }
        let single_step_address = kprobe_list[0].probe_point().single_step_address();
        // setup_single_step
        setup_single_step(frame, single_step_address);
        Some(())
    } else {
        // For some architectures, they do not support single step execution,
        // and we need to use breakpoint exceptions to simulate
        kprobe_handler_from_debug(manager, frame)
    }
}

/// Run kprobe which has been registered on the address
///
/// # Parameters
/// - `manager`: The kprobe manager.
/// - `frame`: The trap frame.
///
/// # Returns
/// - An `Option` containing the result of the kprobe handler. If no kprobe is found, it returns `None`.
///
pub fn kprobe_handler_from_debug<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    frame: &mut dyn ProbeArgs,
) -> Option<()> {
    let pc = frame.debug_address();
    if let Some(kprobe_list) = manager.get_debug_list(pc) {
        for kprobe in kprobe_list {
            if kprobe.is_enabled() {
                kprobe.call_post_handler(frame);
                kprobe.call_event_callback(frame);
            }
        }
        let return_address = kprobe_list[0].probe_point().return_address();
        clear_single_step(frame, return_address);
        Some(())
    } else {
        log::info!("There is no kprobe on pc {:#x}", pc);
        None
    }
}
