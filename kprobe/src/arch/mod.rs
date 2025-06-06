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

#[cfg(target_arch = "x86_64")]
pub type KprobePoint<F> = X86KprobePoint<F>;
#[cfg(target_arch = "riscv64")]
pub type KprobePoint<F> = Rv64KprobePoint<F>;
#[cfg(target_arch = "loongarch64")]
pub type KprobePoint<F> = LA64KprobePoint<F>;

pub trait ProbeArgs: Send {
    /// User can down cast to get the real type
    fn as_any(&self) -> &dyn Any;
    /// User can down cast to get the real type
    fn as_any_mut(&mut self) -> &mut dyn Any;
    /// Return the address of the instruction that caused the break exception
    fn break_address(&self) -> usize;
    /// Return the address of the instruction that caused the single step exception
    ///
    /// For x86_64, it is the address of the instruction that caused the single step exception
    /// For other architectures, it is the address of the instruction that caused the break exception
    fn debug_address(&self) -> usize;
    fn update_pc(&mut self, pc: usize);
    #[cfg(target_arch = "x86_64")]
    /// Enable or disable single step execution. It's only used for x86_64 architecture.
    fn set_single_step(&mut self, enable: bool);
}

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
}

struct ProbeHandler {
    func: fn(&dyn ProbeArgs),
}

impl ProbeHandler {
    pub fn new(func: fn(&dyn ProbeArgs)) -> Self {
        ProbeHandler { func }
    }

    pub fn call(&self, trap_frame: &dyn ProbeArgs) {
        (self.func)(trap_frame);
    }
}

pub struct KprobeBuilder<F: KprobeAuxiliaryOps> {
    symbol: Option<String>,
    symbol_addr: usize,
    offset: usize,
    pre_handler: ProbeHandler,
    post_handler: ProbeHandler,
    fault_handler: Option<ProbeHandler>,
    event_callbacks: BTreeMap<u32, Box<dyn CallBackFunc>>,
    probe_point: Option<Arc<KprobePoint<F>>>,
    enable: bool,
    _marker: core::marker::PhantomData<F>,
}

pub trait EventCallback: Send {
    fn call(&self, trap_frame: &dyn ProbeArgs);
}

impl<F: KprobeAuxiliaryOps> KprobeBuilder<F> {
    pub fn new(
        symbol: Option<String>,
        symbol_addr: usize,
        offset: usize,
        pre_handler: fn(&dyn ProbeArgs),
        post_handler: fn(&dyn ProbeArgs),
        enable: bool,
    ) -> Self {
        KprobeBuilder {
            symbol,
            symbol_addr,
            offset,
            pre_handler: ProbeHandler::new(pre_handler),
            post_handler: ProbeHandler::new(post_handler),
            event_callbacks: BTreeMap::new(),
            fault_handler: None,
            probe_point: None,
            enable,
            _marker: core::marker::PhantomData,
        }
    }

    /// Build the kprobe with a pre handler function.
    pub fn with_fault_handler(mut self, func: fn(&dyn ProbeArgs)) -> Self {
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
    pre_handler: ProbeHandler,
    post_handler: ProbeHandler,
    fault_handler: ProbeHandler,
    event_callbacks: Mutex<L, BTreeMap<u32, Box<dyn CallBackFunc>>>,
    enable: AtomicBool,
}

pub trait CallBackFunc: Send + Sync {
    fn call(&self, trap_frame: &dyn ProbeArgs);
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
    pub fn call_pre_handler(&self, trap_frame: &dyn ProbeArgs) {
        self.pre_handler.call(trap_frame);
    }

    /// Call the post handler function.
    pub fn call_post_handler(&self, trap_frame: &dyn ProbeArgs) {
        self.post_handler.call(trap_frame);
    }

    /// Call the fault handler function.
    pub fn call_fault_handler(&self, trap_frame: &dyn ProbeArgs) {
        self.fault_handler.call(trap_frame);
    }

    /// Call the event callback function.
    pub fn call_event_callback(&self, trap_frame: &dyn ProbeArgs) {
        let event_callbacks = self.event_callbacks.lock();
        for callback in event_callbacks.values() {
            callback.call(trap_frame);
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
}

impl<L: RawMutex + 'static, F: KprobeAuxiliaryOps> From<KprobeBuilder<F>> for KprobeBasic<L> {
    fn from(value: KprobeBuilder<F>) -> Self {
        let fault_handler = value.fault_handler.unwrap_or(ProbeHandler::new(|_| {}));
        KprobeBasic {
            symbol: value.symbol,
            symbol_addr: value.symbol_addr,
            offset: value.offset,
            pre_handler: value.pre_handler,
            post_handler: value.post_handler,
            event_callbacks: Mutex::new(value.event_callbacks),
            fault_handler,
            enable: AtomicBool::new(value.enable),
        }
    }
}
