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
pub fn register_kprobe<L: RawMutex + 'static>(
    manager: &mut KprobeManager<L>,
    kprobe_point_list: &mut KprobePointList,
    kprobe_builder: KprobeBuilder,
) -> Arc<Kprobe<L>> {
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
pub fn unregister_kprobe<L: RawMutex + 'static>(
    manager: &mut KprobeManager<L>,
    kprobe_point_list: &mut KprobePointList,
    kprobe: Arc<Kprobe<L>>,
) {
    let kprobe_addr = kprobe.probe_point().break_address();
    manager.remove_kprobe(&kprobe);

    if manager.kprobe_num(kprobe_addr) == 0 {
        kprobe_point_list.remove(&kprobe_addr);
    }
}
