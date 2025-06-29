use alloc::{boxed::Box, collections::btree_map::BTreeMap, string::String, sync::Arc};
use core::{
    alloc::Layout,
    any::Any,
    fmt::Debug,
    sync::atomic::{AtomicBool, Ordering},
};

use lock_api::{Mutex, RawMutex};
#[cfg(target_arch = "loongarch64")]
mod loongarch64;
#[cfg(target_arch = "riscv64")]
mod rv64;
#[cfg(target_arch = "x86_64")]
mod x86;

#[cfg(target_arch = "loongarch64")]
pub use loongarch64::*;
#[cfg(target_arch = "riscv64")]
pub use rv64::*;
#[cfg(target_arch = "x86_64")]
pub use x86::*;

use crate::kretprobe::KretprobeInstance;

#[cfg(target_arch = "x86_64")]
pub type KprobePoint<F> = X86KprobePoint<F>;
#[cfg(target_arch = "riscv64")]
pub type KprobePoint<F> = Rv64KprobePoint<F>;
#[cfg(target_arch = "loongarch64")]
pub type KprobePoint<F> = LA64KprobePoint<F>;

pub trait KprobeOps: Send {
    /// The address of the instruction that program should return to
    fn return_address(&self) -> usize;

    /// The address of the instruction that saved the original instruction
    ///
    /// Usually, the original instruction at the probe point is saved in an array.
    /// Depending on the architecture, necessary instructions may be filled in after
    /// the saved instruction. For example, x86 architecture supports single-step execution,
    /// while other architectures usually do not. Therefore, we use the break exception to
    /// simulate it, so a breakpoint instruction will be filled in.
    fn single_step_address(&self) -> usize;

    /// The address of the instruction that caused the single step exception
    fn debug_address(&self) -> usize;

    /// The address of the instruction that caused the break exception
    ///
    /// It is usually equal to the address of the instruction that used to set the probe point.
    fn break_address(&self) -> usize;
}

pub trait KprobeAuxiliaryOps: Send + Debug {
    /// Enable or disable write permission for the specified address.
    fn set_writeable_for_address(address: usize, len: usize, writable: bool);
    /// Allocate executable memory
    fn alloc_executable_memory(layout: Layout) -> *mut u8;
    /// Deallocate executable memory
    fn dealloc_executable_memory(ptr: *mut u8, layout: Layout);
    /// Insert a kretprobe instance to the current task
    fn insert_kretprobe_instance_to_task(instance: KretprobeInstance);
    /// Pop a kretprobe instance from the current task
    fn pop_kretprobe_instance_from_task() -> KretprobeInstance;
}

pub trait ProbeData: Any + Send + Sync + Debug {
    fn as_any(&self) -> &dyn Any;
}

pub type ProbeHandlerFunc = fn(&(dyn ProbeData), &mut PtRegs);

#[derive(Clone, Copy, Debug)]
pub(crate) struct ProbeHandler {
    pub(crate) func: ProbeHandlerFunc,
}

impl ProbeHandler {
    pub fn new(func: ProbeHandlerFunc) -> Self {
        ProbeHandler { func }
    }

    pub fn call(&self, data: &(dyn ProbeData), pt_regs: &mut PtRegs) {
        (self.func)(data, pt_regs);
    }
}

pub trait CallBackFunc: Send + Sync {
    fn call(&self, trap_frame: &mut PtRegs);
}

pub struct KprobeBuilder<F: KprobeAuxiliaryOps> {
    pub(crate) symbol: Option<String>,
    pub(crate) symbol_addr: usize,
    pub(crate) offset: usize,
    pub(crate) pre_handler: Option<ProbeHandler>,
    pub(crate) post_handler: Option<ProbeHandler>,
    pub(crate) fault_handler: Option<ProbeHandler>,
    pub(crate) event_callbacks: BTreeMap<u32, Box<dyn CallBackFunc>>,
    pub(crate) probe_point: Option<Arc<KprobePoint<F>>>,
    pub(crate) enable: bool,
    pub(crate) data: Option<Box<dyn ProbeData>>,
    pub(crate) _marker: core::marker::PhantomData<F>,
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
    pub fn new(symbol: Option<String>, symbol_addr: usize, offset: usize, enable: bool) -> Self {
        KprobeBuilder {
            symbol,
            symbol_addr,
            offset,
            pre_handler: None,
            post_handler: None,
            event_callbacks: BTreeMap::new(),
            fault_handler: None,
            probe_point: None,
            enable,
            data: None,
            _marker: core::marker::PhantomData,
        }
    }

    /// Build the kprobe with a specific user data.
    pub fn with_data<T: ProbeData>(mut self, data: T) -> Self {
        self.data = Some(Box::new(data));
        self
    }

    /// Build the kprobe with a pre handler function.
    pub fn with_pre_handler(mut self, func: ProbeHandlerFunc) -> Self {
        self.pre_handler = Some(ProbeHandler::new(func));
        self
    }

    /// Build the kprobe with a post handler function.
    pub fn with_post_handler(mut self, func: ProbeHandlerFunc) -> Self {
        self.post_handler = Some(ProbeHandler::new(func));
        self
    }

    /// Build the kprobe with a pre handler function.
    pub fn with_fault_handler(mut self, func: ProbeHandlerFunc) -> Self {
        self.fault_handler = Some(ProbeHandler::new(func));
        self
    }

    pub(crate) fn with_probe_point(mut self, point: Arc<KprobePoint<F>>) -> Self {
        self.probe_point = Some(point);
        self
    }

    /// Build the kprobe with an event callback function.
    pub fn with_event_callback(
        mut self,
        callback_id: u32,
        event_callback: Box<dyn CallBackFunc>,
    ) -> Self {
        self.event_callbacks.insert(callback_id, event_callback);
        self
    }

    /// Get the address of the instruction that should be probed.
    pub fn probe_addr(&self) -> usize {
        self.symbol_addr + self.offset
    }
}

pub struct KprobeBasic<L: RawMutex + 'static> {
    symbol: Option<String>,
    symbol_addr: usize,
    offset: usize,
    pre_handler: Option<ProbeHandler>,
    post_handler: Option<ProbeHandler>,
    fault_handler: Option<ProbeHandler>,
    event_callbacks: Mutex<L, BTreeMap<u32, Box<dyn CallBackFunc>>>,
    enable: AtomicBool,
    data: Box<dyn ProbeData>,
}

impl<L: RawMutex + 'static> Debug for KprobeBasic<L> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Kprobe")
            .field("symbol", &self.symbol)
            .field("symbol_addr", &self.symbol_addr)
            .field("offset", &self.offset)
            .finish()
    }
}

impl<L: RawMutex + 'static> KprobeBasic<L> {
    /// Call the pre handler function.
    pub fn call_pre_handler(&self, pt_regs: &mut PtRegs) {
        if let Some(ref handler) = self.pre_handler {
            handler.call(self.data.as_ref(), pt_regs);
        }
    }

    /// Call the post handler function.
    pub fn call_post_handler(&self, pt_regs: &mut PtRegs) {
        if let Some(ref handler) = self.post_handler {
            handler.call(self.data.as_ref(), pt_regs);
        }
    }

    /// Call the fault handler function.
    pub fn call_fault_handler(&self, pt_regs: &mut PtRegs) {
        if let Some(ref handler) = self.fault_handler {
            handler.call(self.data.as_ref(), pt_regs);
        }
    }

    /// Call the event callback function.
    pub fn call_event_callback(&self, pt_regs: &mut PtRegs) {
        let event_callbacks = self.event_callbacks.lock();
        for callback in event_callbacks.values() {
            callback.call(pt_regs);
        }
    }

    /// Register the event callback function.
    pub fn register_event_callback(&self, callback_id: u32, callback: Box<dyn CallBackFunc>) {
        self.event_callbacks.lock().insert(callback_id, callback);
    }

    /// Unregister the event callback function.
    pub fn unregister_event_callback(&self, callback_id: u32) {
        self.event_callbacks.lock().remove(&callback_id);
    }

    /// Disable the probe point.
    pub fn disable(&self) {
        self.enable.store(false, Ordering::Relaxed);
    }

    /// Enable the probe point.
    pub fn enable(&self) {
        self.enable.store(true, Ordering::Relaxed);
    }

    /// Check if the probe point is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enable.load(Ordering::Relaxed)
    }

    /// Get the function name of the probe point.
    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }

    pub(crate) fn get_data(&self) -> &(dyn ProbeData) {
        self.data.as_ref()
    }
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> From<KprobeBuilder<F>> for KprobeBasic<L> {
    fn from(value: KprobeBuilder<F>) -> Self {
        KprobeBasic {
            symbol: value.symbol,
            symbol_addr: value.symbol_addr,
            offset: value.offset,
            pre_handler: value.pre_handler,
            post_handler: value.post_handler,
            event_callbacks: Mutex::new(value.event_callbacks),
            fault_handler: value.fault_handler,
            enable: AtomicBool::new(value.enable),
            data: value.data.unwrap_or_else(|| Box::new(())),
        }
    }
}

impl ProbeData for () {
    fn as_any(&self) -> &dyn Any {
        self
    }
}
