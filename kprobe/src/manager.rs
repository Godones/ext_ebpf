use alloc::{collections::BTreeMap, sync::Arc, vec::Vec};

use lock_api::RawMutex;

use crate::{Kprobe, KprobeOps, KprobePoint};

/// A manager for kprobes.
#[derive(Debug)]
pub struct KprobeManager<L: RawMutex + 'static> {
    break_list: BTreeMap<usize, Vec<Arc<Kprobe<L>>>>,
    debug_list: BTreeMap<usize, Vec<Arc<Kprobe<L>>>>,
}

impl<L: RawMutex + 'static> KprobeManager<L> {
    pub const fn new() -> Self {
        KprobeManager {
            break_list: BTreeMap::new(),
            debug_list: BTreeMap::new(),
        }
    }
    /// Insert a kprobe into the manager.
    pub fn insert_kprobe(&mut self, kprobe: Arc<Kprobe<L>>) {
        let probe_point = kprobe.probe_point().clone();
        self.insert_break_point(probe_point.break_address(), kprobe.clone());
        self.insert_debug_point(probe_point.debug_address(), kprobe);
    }

    /// Insert a kprobe into the break_list.
    ///
    /// # Parameters
    /// - `address`: The address of the kprobe, obtained from `KprobePoint::break_address()` or `KprobeBuilder::probe_addr()`.
    /// - `kprobe`: The instance of the kprobe.
    fn insert_break_point(&mut self, address: usize, kprobe: Arc<Kprobe<L>>) {
        let list = self.break_list.entry(address).or_default();
        list.push(kprobe);
    }

    /// Insert a kprobe into the debug_list.
    ///
    /// # Parameters
    /// - `address`: The address of the kprobe, obtained from `KprobePoint::debug_address()`.
    /// - `kprobe`: The instance of the kprobe.
    ///
    fn insert_debug_point(&mut self, address: usize, kprobe: Arc<Kprobe<L>>) {
        let list = self.debug_list.entry(address).or_default();
        list.push(kprobe);
    }

    /// Get the list of kprobes registered at a breakpoint address.
    pub fn get_break_list(&self, address: usize) -> Option<&Vec<Arc<Kprobe<L>>>> {
        self.break_list.get(&address)
    }

    /// Get the list of kprobes registered at a debug address.
    pub fn get_debug_list(&self, address: usize) -> Option<&Vec<Arc<Kprobe<L>>>> {
        self.debug_list.get(&address)
    }

    /// Get the number of kprobes registered at a breakpoint address.
    pub fn kprobe_num(&self, address: usize) -> usize {
        self.break_list_len(address)
    }

    #[inline]
    fn break_list_len(&self, address: usize) -> usize {
        self.break_list
            .get(&address)
            .map(|list| list.len())
            .unwrap_or(0)
    }
    #[inline]
    fn debug_list_len(&self, address: usize) -> usize {
        self.debug_list
            .get(&address)
            .map(|list| list.len())
            .unwrap_or(0)
    }

    /// Remove a kprobe from the manager.
    pub fn remove_kprobe(&mut self, kprobe: &Arc<Kprobe<L>>) {
        let probe_point = kprobe.probe_point().clone();
        self.remove_one_break(probe_point.break_address(), kprobe);
        self.remove_one_debug(probe_point.debug_address(), kprobe);
    }

    /// Remove a kprobe from the break_list.
    fn remove_one_break(&mut self, address: usize, kprobe: &Arc<Kprobe<L>>) {
        if let Some(list) = self.break_list.get_mut(&address) {
            list.retain(|x| !Arc::ptr_eq(x, kprobe));
        }
        if self.break_list_len(address) == 0 {
            self.break_list.remove(&address);
        }
    }

    /// Remove a kprobe from the debug_list.
    fn remove_one_debug(&mut self, address: usize, kprobe: &Arc<Kprobe<L>>) {
        if let Some(list) = self.debug_list.get_mut(&address) {
            list.retain(|x| !Arc::ptr_eq(x, kprobe));
        }
        if self.debug_list_len(address) == 0 {
            self.debug_list.remove(&address);
        }
    }
}

/// A list of kprobe points.
pub type KprobePointList = BTreeMap<usize, Arc<KprobePoint>>;
