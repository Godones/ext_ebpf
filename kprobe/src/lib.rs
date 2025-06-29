#![no_std]
#![cfg_attr(target_arch = "riscv64", feature(riscv_ext_intrinsics))]
extern crate alloc;

mod arch;
mod kretprobe;
mod manager;

use alloc::sync::Arc;
use core::ops::Deref;

pub use arch::*;
pub use kretprobe::*;
use lock_api::RawMutex;
pub use manager::*;

#[derive(Debug)]
pub enum Probe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    Kprobe(Arc<Kprobe<L, F>>),
    Kretprobe(Arc<Kretprobe<L, F>>),
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Deref for Probe<L, F> {
    type Target = Kprobe<L, F>;
    fn deref(&self) -> &Self::Target {
        match self {
            Probe::Kprobe(kprobe) => kprobe,
            Probe::Kretprobe(kretprobe) => kretprobe.kprobe(),
        }
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Probe<L, F> {
    pub fn probe_point(&self) -> &Arc<KprobePoint<F>> {
        match self {
            Probe::Kprobe(kprobe) => kprobe.probe_point(),
            Probe::Kretprobe(kretprobe) => kretprobe.kprobe().probe_point(),
        }
    }

    pub fn is_kretprobe(&self) -> bool {
        matches!(self, Probe::Kretprobe(_))
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Clone for Probe<L, F> {
    fn clone(&self) -> Self {
        match self {
            Probe::Kprobe(kprobe) => Probe::Kprobe(kprobe.clone()),
            Probe::Kretprobe(kretprobe) => Probe::Kretprobe(kretprobe.clone()),
        }
    }
}

fn __register_kprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    kprobe_point_list: &mut KprobePointList<F>,
    kprobe_builder: KprobeBuilder<F>,
) -> Kprobe<L, F> {
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
    kprobe
}

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
    let kprobe = __register_kprobe(kprobe_point_list, kprobe_builder);
    let kprobe = Arc::new(kprobe);
    manager.insert_probe(Probe::Kprobe(kprobe.clone()));
    kprobe
}

/// Register a kretprobe.
///
/// See [`register_kprobe`] for more details.
pub fn register_kretprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static>(
    manager: &mut KprobeManager<L, F>,
    kprobe_point_list: &mut KprobePointList<F>,
    kretprobe_builder: KretprobeBuilder<L>,
) -> Arc<Kretprobe<L, F>> {
    let (entry_handler, ret_handler) = kretprobe_builder.handler();

    let kprobe_builder = KprobeBuilder::from(kretprobe_builder);
    let kprobe = __register_kprobe(kprobe_point_list, kprobe_builder);

    let kretprobe = Kretprobe::new(kprobe, entry_handler, ret_handler);
    let kretprobe = Arc::new(kretprobe);

    let data = kretprobe.kprobe().get_data();
    let data = data.as_any().downcast_ref::<KretprobeData<L, F>>().unwrap();
    *data.kretprobe.lock() = Arc::downgrade(&kretprobe);

    manager.insert_probe(Probe::Kretprobe(kretprobe.clone()));
    kretprobe
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
    manager.remove_kprobe(&Probe::Kprobe(kprobe));

    if manager.kprobe_num(kprobe_addr) == 0 {
        kprobe_point_list.remove(&kprobe_addr);
    }
}

/// Unregister a kretprobe.
///
/// See [`unregister_kprobe`] for more details.
pub fn unregister_kretprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    kprobe_point_list: &mut KprobePointList<F>,
    kretprobe: Arc<Kretprobe<L, F>>,
) {
    let kprobe = kretprobe.kprobe();
    let kprobe_addr = kprobe.probe_point().break_address();
    manager.remove_kprobe(&Probe::Kretprobe(kretprobe));

    if manager.kprobe_num(kprobe_addr) == 0 {
        kprobe_point_list.remove(&kprobe_addr);
    }
}

/// Run kprobe which has been registered on the address
///
/// # Parameters
/// - `manager`: The kprobe manager.
/// - `pt_regs`: The trap pt_regs.
///
/// # Returns
/// - An `Option` containing the result of the kprobe handler. If no kprobe is found, it returns `None`.
///
pub fn kprobe_handler_from_break<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    pt_regs: &mut PtRegs,
) -> Option<()> {
    let break_addr = pt_regs.break_address();
    // log::debug!("EBreak: break_addr: {:#x}", break_addr);
    let kprobe_list = manager.get_break_list(break_addr);
    if let Some(kprobe_list) = kprobe_list {
        for kprobe in kprobe_list {
            if kprobe.is_enabled() {
                kprobe.call_pre_handler(pt_regs);
            }
        }
        let single_step_address = kprobe_list[0].probe_point().single_step_address();
        // setup_single_step
        setup_single_step(pt_regs, single_step_address);
        Some(())
    } else {
        // For some architectures, they do not support single step execution,
        // and we need to use breakpoint exceptions to simulate
        kprobe_handler_from_debug(manager, pt_regs)
    }
}

/// Run kprobe which has been registered on the address
///
/// # Parameters
/// - `manager`: The kprobe manager.
/// - `pt_regs`: The trap pt_regs.
///
/// # Returns
/// - An `Option` containing the result of the kprobe handler. If no kprobe is found, it returns `None`.
///
pub fn kprobe_handler_from_debug<L: RawMutex + 'static, F: KprobeAuxiliaryOps>(
    manager: &mut KprobeManager<L, F>,
    pt_regs: &mut PtRegs,
) -> Option<()> {
    let pc = pt_regs.debug_address();
    if let Some(kprobe_list) = manager.get_debug_list(pc) {
        for kprobe in kprobe_list {
            if kprobe.is_enabled() {
                kprobe.call_post_handler(pt_regs);
                kprobe.call_event_callback(pt_regs);
            }
        }
        let return_address = kprobe_list[0].probe_point().return_address();
        clear_single_step(pt_regs, return_address);
        Some(())
    } else {
        log::info!("There is no kprobe on pc {:#x}", pc);
        None
    }
}
