use alloc::{boxed::Box, collections::BTreeMap};
use core::any::Any;

use lock_api::{Mutex, RawMutex};
use static_keys::StaticFalseKey;
pub struct TracePoint {
    name: &'static str,
    module_path: &'static str,
    key: &'static StaticFalseKey,
    register: Option<fn()>,
    unregister: Option<fn()>,
    callback: BTreeMap<usize, TracePointFunc>,
}

impl core::fmt::Debug for TracePoint {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TracePoint")
            .field("name", &self.name)
            .finish()
    }
}

#[derive(Debug)]
#[repr(C)]
pub struct CommonTracePointMeta<L: RawMutex + 'static> {
    pub trace_point: &'static Mutex<L, TracePoint>,
    pub print_func: fn(),
}

#[derive(Debug)]
pub struct TracePointFunc {
    pub func: fn(),
    pub data: Box<dyn Any + Send + Sync>,
}

impl TracePoint {
    pub const fn new(
        key: &'static StaticFalseKey,
        name: &'static str,
        module_path: &'static str,
        register: Option<fn()>,
        unregister: Option<fn()>,
    ) -> Self {
        Self {
            name,
            module_path,
            key,
            register,
            unregister,
            callback: BTreeMap::new(),
        }
    }

    pub fn name(&self) -> &'static str {
        self.name
    }

    pub fn module_path(&self) -> &'static str {
        self.module_path
    }

    /// Register a callback function to the tracepoint
    pub fn register(&mut self, func: fn(), data: Box<dyn Any + Sync + Send>) {
        let trace_point_func = TracePointFunc { func, data };
        if let Some(register) = self.register {
            register();
        }
        let ptr = func as usize;
        self.callback.entry(ptr).or_insert(trace_point_func);
    }

    /// Unregister a callback function from the tracepoint
    pub fn unregister(&mut self, func: fn()) {
        if let Some(unregister) = self.unregister {
            unregister();
        }
        let func_ptr = func as usize;
        self.callback.remove(&func_ptr);
    }

    /// Get the callback list
    pub fn callback_list(&self) -> impl Iterator<Item = &TracePointFunc> {
        self.callback.values()
    }

    /// Enable the tracepoint
    pub fn enable(&self) {
        unsafe {
            self.key.enable();
        }
    }

    /// Disable the tracepoint
    pub fn disable(&self) {
        unsafe {
            self.key.disable();
        }
    }

    /// Check if the tracepoint is enabled
    pub fn is_enabled(&self) -> bool {
        self.key.is_enabled()
    }
}
