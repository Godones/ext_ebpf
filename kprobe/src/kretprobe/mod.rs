use alloc::{
    boxed::Box,
    collections::btree_map::BTreeMap,
    string::String,
    sync::{Arc, Weak},
    vec::Vec,
};
use core::{any::Any, fmt::Debug, sync::atomic::AtomicU64};

use lock_api::{Mutex, RawMutex};

use crate::{
    CallBackFunc, Kprobe, KprobeAuxiliaryOps, KprobeBuilder, ProbeData, ProbeHandler,
    ProbeHandlerFunc, PtRegs, arch_rethook_fixup_return, arch_rethook_prepare,
};

/// The kretprobe structure.
pub struct Kretprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    kprobe: Kprobe<L, F>,
    nmissed: AtomicU64,
    entry_handler: Option<ProbeHandler>,
    ret_handler: Option<ProbeHandler>,
    event_callbacks: Mutex<L, BTreeMap<u32, Box<dyn CallBackFunc>>>,
}

unsafe impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Send for Kretprobe<L, F> {}
unsafe impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Sync for Kretprobe<L, F> {}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Debug for Kretprobe<L, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kretprobe")
            .field("kprobe", &self.kprobe)
            .field("nmissed", &self.nmissed)
            .finish()
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Kretprobe<L, F> {
    pub(crate) fn new(
        kprobe: Kprobe<L, F>,
        entry_handler: Option<ProbeHandler>,
        ret_handler: Option<ProbeHandler>,
    ) -> Self {
        Kretprobe {
            kprobe,
            nmissed: AtomicU64::new(0),
            event_callbacks: Mutex::new(BTreeMap::new()),
            entry_handler,
            ret_handler,
        }
    }
    /// Get the underlying kprobe of the kretprobe.
    pub fn kprobe(&self) -> &Kprobe<L, F> {
        &self.kprobe
    }

    /// Register the event callback function.
    pub fn register_event_callback(&self, callback_id: u32, callback: Box<dyn CallBackFunc>) {
        self.event_callbacks.lock().insert(callback_id, callback);
    }

    /// Unregister the event callback function.
    pub fn unregister_event_callback(&self, callback_id: u32) {
        self.event_callbacks.lock().remove(&callback_id);
    }
}

pub(crate) struct KretprobeData<L: RawMutex + 'static, F: KprobeAuxiliaryOps> {
    free_instances: Mutex<L, Vec<KretprobeInstance>>,
    pub(crate) kretprobe: Mutex<L, Weak<Kretprobe<L, F>>>,
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Debug for KretprobeData<L, F> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("KretprobeData")
            .field("free_instances", &self.free_instances)
            .field("kretprobe", &self.kretprobe)
            .finish()
    }
}

unsafe impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Send for KretprobeData<L, F> {}
unsafe impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> Sync for KretprobeData<L, F> {}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static> ProbeData for KretprobeData<L, F> {
    fn as_any(&self) -> &dyn Any {
        self
    }
}

/// The instance of a kretprobe.
#[derive(Debug)]
pub struct KretprobeInstance {
    pub(crate) ret_addr: usize,
    pub(crate) frame: usize,
    user_data: Option<Box<dyn ProbeData>>,
    kretprobe: Weak<dyn Any + Send + Sync>,
}

/// The builder for creating a kretprobe.
pub struct KretprobeBuilder<L: RawMutex + 'static> {
    symbol: Option<String>,
    symbol_addr: usize,
    maxactive: u32,
    data: Vec<Box<dyn ProbeData>>,
    ret_handler: Option<ProbeHandler>,
    entry_handler: Option<ProbeHandler>,
    event_callbacks: BTreeMap<u32, ProbeHandler>,
    _marker: core::marker::PhantomData<L>,
}

impl<L: RawMutex + 'static> KretprobeBuilder<L> {
    /// Create a new kretprobe builder.
    pub fn new(symbol: Option<String>, symbol_addr: usize, maxactive: u32) -> Self {
        KretprobeBuilder {
            symbol,
            symbol_addr,
            maxactive,
            data: Vec::new(),
            ret_handler: None,
            entry_handler: None,
            event_callbacks: BTreeMap::new(),
            _marker: core::marker::PhantomData,
        }
    }

    pub(crate) fn handler(&self) -> (Option<ProbeHandler>, Option<ProbeHandler>) {
        (self.entry_handler, self.ret_handler)
    }

    /// Set the user data for the kretprobe.
    ///
    /// Remember that the data will be cloned for each instance of the kretprobe.
    /// This is useful for sharing data across multiple kretprobe instances.
    pub fn with_data<T: ProbeData + Clone>(mut self, data: T) -> Self {
        for _ in 0..self.maxactive {
            self.data.push(Box::new(data.clone()));
        }
        self
    }

    /// Build the kprobe with an event callback function.
    pub fn with_event_callback(
        mut self,
        callback_id: u32,
        event_callback: ProbeHandlerFunc,
    ) -> Self {
        self.event_callbacks
            .insert(callback_id, ProbeHandler::new(event_callback));
        self
    }

    /// Set the return handler for the kretprobe.
    pub fn with_ret_handler(mut self, func: ProbeHandlerFunc) -> Self {
        self.ret_handler = Some(ProbeHandler::new(func));
        self
    }

    /// Set the entry handler for the kretprobe.
    pub fn with_entry_handler(mut self, func: ProbeHandlerFunc) -> Self {
        self.entry_handler = Some(ProbeHandler::new(func));
        self
    }
}

impl<F: KprobeAuxiliaryOps + 'static, L: RawMutex + 'static> From<KretprobeBuilder<L>>
    for KprobeBuilder<F>
{
    fn from(mut value: KretprobeBuilder<L>) -> Self {
        let kretprobe_data = KretprobeData::<L, F> {
            free_instances: {
                let mut instances = Vec::with_capacity(value.maxactive as usize);
                for _ in 0..value.maxactive {
                    let data = value.data.pop();
                    instances.push(KretprobeInstance {
                        ret_addr: 0,
                        user_data: data,
                        frame: 0,
                        kretprobe: Weak::<Kretprobe<L, F>>::new(),
                    });
                }
                Mutex::new(instances)
            },
            kretprobe: Mutex::new(Weak::new()),
        };

        Self {
            symbol: value.symbol.clone(),
            symbol_addr: value.symbol_addr,
            offset: 0,
            pre_handler: Some(ProbeHandler::new(pre_handler_kretprobe::<L, F>)),
            post_handler: None,
            fault_handler: None,
            event_callbacks: BTreeMap::new(),
            probe_point: None,
            enable: true,
            data: Some(Box::new(kretprobe_data)),
            _marker: core::marker::PhantomData,
        }
    }
}

fn pre_handler_kretprobe<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static>(
    data: &(dyn ProbeData),
    pt_regs: &mut PtRegs,
) {
    let kretprobe_data = data.as_any().downcast_ref::<KretprobeData<L, F>>().unwrap();
    let free_instance = kretprobe_data.free_instances.lock().pop();
    if let Some(mut instance) = free_instance {
        arch_rethook_prepare::<L, F>(&mut instance, pt_regs);
        let user_data = instance.user_data.as_deref().unwrap_or(&());

        let kretprobe = kretprobe_data.kretprobe.lock();
        let kretprobe = kretprobe.upgrade().unwrap();
        if let Some(entry_handler) = kretprobe.entry_handler {
            entry_handler.call(user_data, pt_regs);
        }
        instance.kretprobe = Arc::downgrade(&(kretprobe as Arc<dyn Any + Send + Sync>));

        // insert the instance into the task
        F::insert_kretprobe_instance_to_task(instance);
    } else {
        log::warn!("No free KretprobeInstance available in pre_handler_kretprobe");
        let kretprobe = kretprobe_data.kretprobe.lock();
        let kretprobe = kretprobe.upgrade();
        let Some(kretprobe) = kretprobe else {
            panic!("Kretprobe is not available in pre_handler_kretprobe");
        };
        kretprobe
            .nmissed
            .fetch_add(1, core::sync::atomic::Ordering::Relaxed);
    }
}

pub(crate) fn rethook_trampoline_handler<L: RawMutex + 'static, F: KprobeAuxiliaryOps + 'static>(
    pt_regs: &mut PtRegs,
    frame: usize,
) -> usize {
    let kretprobe_instance = F::pop_kretprobe_instance_from_task();
    let correct_ret_addr = kretprobe_instance.ret_addr;
    assert_eq!(kretprobe_instance.frame, frame);
    let user_data = kretprobe_instance.user_data.as_deref().unwrap_or(&());

    let kretprobe = kretprobe_instance.kretprobe.upgrade().unwrap();
    let kretprobe = kretprobe
        .as_ref()
        .downcast_ref::<Kretprobe<L, F>>()
        .unwrap();

    // call the return handler if it exists
    if let Some(ret_handler) = kretprobe.ret_handler {
        ret_handler.call(user_data, pt_regs);
    }

    // call the event callbacks if they exist
    for callback in kretprobe.event_callbacks.lock().values() {
        callback.call(pt_regs);
    }

    arch_rethook_fixup_return(pt_regs, correct_ret_addr);
    correct_ret_addr
}
