use alloc::{boxed::Box, string::String, sync::Arc};
use core::{any::Any, fmt::Debug};

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
pub type KprobePoint = X86KprobePoint;
#[cfg(target_arch = "riscv64")]
pub type KprobePoint = Rv64KprobePoint;
#[cfg(target_arch = "loongarch64")]
pub type KprobePoint = LA64KprobePoint;

pub trait ProbeArgs: Send {
    /// User can down cast to get the real type
    fn as_any(&self) -> &dyn Any;
    /// Return the address of the instruction that caused the break exception
    fn break_address(&self) -> usize;
    /// Return the address of the instruction that caused the single step exception
    ///
    /// For x86_64, it is the address of the instruction that caused the single step exception
    /// For other architectures, it is the address of the instruction that caused the break exception
    fn debug_address(&self) -> usize;
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

pub struct KprobeBuilder {
    symbol: Option<String>,
    symbol_addr: usize,
    offset: usize,
    pre_handler: ProbeHandler,
    post_handler: ProbeHandler,
    fault_handler: Option<ProbeHandler>,
    event_callback: Option<Box<dyn CallBackFunc>>,
    probe_point: Option<Arc<KprobePoint>>,
    enable: bool,
}

pub trait EventCallback: Send {
    fn call(&self, trap_frame: &dyn ProbeArgs);
}

impl KprobeBuilder {
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
            event_callback: None,
            fault_handler: None,
            probe_point: None,
            enable,
        }
    }

    pub fn with_fault_handler(mut self, func: fn(&dyn ProbeArgs)) -> Self {
        self.fault_handler = Some(ProbeHandler::new(func));
        self
    }

    pub fn with_probe_point(mut self, point: Arc<KprobePoint>) -> Self {
        self.probe_point = Some(point);
        self
    }

    pub fn with_event_callback(mut self, event_callback: Box<dyn CallBackFunc>) -> Self {
        self.event_callback = Some(event_callback);
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
    event_callback: Mutex<L, Option<Box<dyn CallBackFunc>>>,
    enable: bool,
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
        let guard = self.event_callback.lock();
        if let Some(ref call_back) = *guard {
            call_back.call(trap_frame);
        }
    }

    /// Set the event callback function.
    ///
    /// Likely to post_handler.
    pub fn update_event_callback(&mut self, callback: Box<dyn CallBackFunc>) {
        self.event_callback.lock().replace(callback);
    }

    /// Disable the probe point.
    pub fn disable(&mut self) {
        self.enable = false;
    }

    /// Enable the probe point.
    pub fn enable(&mut self) {
        self.enable = true;
    }

    /// Check if the probe point is enabled.
    pub fn is_enabled(&self) -> bool {
        self.enable
    }

    /// Get the function name of the probe point.
    pub fn symbol(&self) -> Option<&str> {
        self.symbol.as_deref()
    }
}

impl<L: RawMutex + 'static> From<KprobeBuilder> for KprobeBasic<L> {
    fn from(value: KprobeBuilder) -> Self {
        let fault_handler = value.fault_handler.unwrap_or(ProbeHandler::new(|_| {}));
        KprobeBasic {
            symbol: value.symbol,
            symbol_addr: value.symbol_addr,
            offset: value.offset,
            pre_handler: value.pre_handler,
            post_handler: value.post_handler,
            event_callback: Mutex::new(value.event_callback),
            fault_handler,
            enable: value.enable,
        }
    }
}
