#![no_std]
#![allow(clippy::new_without_default)]
extern crate alloc;

mod basic_macro;
mod point;
mod trace_pipe;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};

use lock_api::{Mutex, RawMutex};
pub use paste::paste;
pub use point::{CommonTracePointMeta, TracePoint};
pub use trace_pipe::TracePipe;

/// KernelTraceOps trait provides kernel-level operations for tracing.
pub trait KernelTraceOps {
    /// Get the current time in nanoseconds.
    fn time_now() -> u64;
    /// Get the current CPU ID.
    fn cpu_id() -> u32;
    /// Get the current process ID.
    fn current_pid() -> u32;
    /// Push a record to the trace pipe.
    fn trace_pipe_push_record(format: String);
}

#[derive(Debug)]
pub struct TracingEventsManager<L: RawMutex + 'static> {
    subsystems: Mutex<L, BTreeMap<String, Arc<EventsSubsystem<L>>>>,
}

impl<L: RawMutex + 'static> TracingEventsManager<L> {
    pub fn new() -> Self {
        Self {
            subsystems: Mutex::new(BTreeMap::new()),
        }
    }

    /// Create a subsystem by name
    ///
    /// If the subsystem already exists, return the existing subsystem.
    pub fn create_subsystem(&self, subsystem_name: &str) -> Arc<EventsSubsystem<L>> {
        if self.subsystems.lock().contains_key(subsystem_name) {
            return self
                .get_subsystem(subsystem_name)
                .expect("Subsystem should exist");
        }
        let subsystem = Arc::new(EventsSubsystem::new());
        self.subsystems
            .lock()
            .insert(subsystem_name.to_string(), subsystem.clone());
        subsystem
    }

    /// Get the subsystem by name
    pub fn get_subsystem(&self, subsystem_name: &str) -> Option<Arc<EventsSubsystem<L>>> {
        self.subsystems.lock().get(subsystem_name).cloned()
    }

    /// Remove the subsystem by name
    pub fn remove_subsystem(&self, subsystem_name: &str) -> Option<Arc<EventsSubsystem<L>>> {
        self.subsystems.lock().remove(subsystem_name)
    }

    /// Get all subsystems
    pub fn subsystem_names(&self) -> Vec<String> {
        let res = self
            .subsystems
            .lock()
            .keys()
            .cloned()
            .collect::<Vec<String>>();
        res
    }
}

#[derive(Debug)]
pub struct EventsSubsystem<L: RawMutex + 'static> {
    events: Mutex<L, BTreeMap<String, Arc<EventInfo<L>>>>,
}

impl<L: RawMutex + 'static> EventsSubsystem<L> {
    pub fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
        }
    }

    /// Create an event by name
    pub fn create_event(&self, event_name: &str, event_info: EventInfo<L>) {
        self.events
            .lock()
            .insert(event_name.to_string(), Arc::new(event_info));
    }

    /// Get the event by name
    pub fn get_event(&self, event_name: &str) -> Option<Arc<EventInfo<L>>> {
        self.events.lock().get(event_name).cloned()
    }

    /// Remove the event by name
    pub fn remove_event(&self, event_name: &str) -> Option<Arc<EventInfo<L>>> {
        self.events.lock().remove(event_name)
    }

    /// Get all events in the subsystem
    pub fn event_names(&self) -> Vec<String> {
        let res = self.events.lock().keys().cloned().collect::<Vec<String>>();
        res
    }
}
#[derive(Debug)]
pub struct EventInfo<L: RawMutex + 'static> {
    enable: TracePointEnableFile<L>,
    // filter:,
    // trigger:,
    tracepoint: &'static Mutex<L, TracePoint>,
}

impl<L: RawMutex + 'static> EventInfo<L> {
    pub fn new(tracepoint: &'static Mutex<L, TracePoint>) -> Self {
        let enable = TracePointEnableFile::new(tracepoint);
        Self { enable, tracepoint }
    }
    /// Get the tracepoint
    pub fn tracepoint(&self) -> &'static Mutex<L, TracePoint> {
        self.tracepoint
    }

    /// Get the enable file
    pub fn enable_file(&self) -> &TracePointEnableFile<L> {
        &self.enable
    }
}

#[derive(Debug)]
pub struct TracePointEnableFile<L: RawMutex + 'static> {
    tracepoint: &'static Mutex<L, TracePoint>,
}

impl<L: RawMutex + 'static> TracePointEnableFile<L> {
    pub fn new(tracepoint: &'static Mutex<L, TracePoint>) -> Self {
        Self { tracepoint }
    }
    /// Read the tracepoint status
    ///
    /// Returns true if the tracepoint is enabled, false otherwise.
    pub fn read(&self) -> bool {
        self.tracepoint.lock().is_enabled()
    }
    /// Enable or disable the tracepoint
    pub fn write(&self, enable: bool) {
        match enable {
            true => self.tracepoint.lock().enable(),
            false => self.tracepoint.lock().disable(),
        }
    }
}

extern "C" {
    fn __start_tracepoint();
    fn __stop_tracepoint();
}

/// Initialize the tracing events
pub fn global_init_events<L: RawMutex + 'static>() -> Result<TracingEventsManager<L>, &'static str>
{
    let events_manager = TracingEventsManager::new();
    let tracepoint_data_start = __start_tracepoint as usize as *mut CommonTracePointMeta<L>;
    let tracepoint_data_end = __stop_tracepoint as usize as *mut CommonTracePointMeta<L>;
    log::info!(
        "tracepoint_data_start: {:#x}, tracepoint_data_end: {:#x}",
        tracepoint_data_start as usize,
        tracepoint_data_end as usize
    );
    let tracepoint_data_len = (tracepoint_data_end as usize - tracepoint_data_start as usize)
        / size_of::<CommonTracePointMeta<L>>();
    let tracepoint_data =
        unsafe { core::slice::from_raw_parts_mut(tracepoint_data_start, tracepoint_data_len) };

    for tracepoint_meta in tracepoint_data {
        let mut tracepoint = tracepoint_meta.trace_point.lock();
        tracepoint.register(tracepoint_meta.print_func, Box::new(()));
        log::info!(
            "tracepoint name: {}, module path: {}",
            tracepoint.name(),
            tracepoint.module_path()
        );
        // kernel::{subsystem}::
        let mut subsys_name = tracepoint.module_path().split("::");
        let subsys_name = subsys_name.nth(1).ok_or("Invalid subsystem name")?;
        let subsys = events_manager.create_subsystem(subsys_name);
        let event_info = EventInfo::new(tracepoint_meta.trace_point);
        subsys.create_event(tracepoint.name(), event_info);
    }
    Ok(events_manager)
}
