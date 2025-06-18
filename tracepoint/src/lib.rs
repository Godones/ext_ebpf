#![no_std]
#![allow(clippy::new_without_default)]
extern crate alloc;

mod basic_macro;
mod point;
mod trace_pipe;

use alloc::{
    boxed::Box,
    collections::BTreeMap,
    format,
    string::{String, ToString},
    sync::Arc,
    vec::Vec,
};
use core::{
    ops::{Deref, DerefMut},
    sync::atomic::AtomicUsize,
};

use lock_api::{Mutex, MutexGuard, RawMutex};
pub use paste::paste;
pub use point::{
    CommonTracePointMeta, TraceEntry, TracePoint, TracePointCallBackFunc, TracePointFunc,
};
pub use trace_pipe::{
    TraceCmdLineCache, TraceEntryParser, TracePipeOps, TracePipeRaw, TracePipeSnapshot,
};

/// KernelTraceOps trait provides kernel-level operations for tracing.
pub trait KernelTraceOps {
    /// Get the current time in nanoseconds.
    fn time_now() -> u64;
    /// Get the current CPU ID.
    fn cpu_id() -> u32;
    /// Get the current process ID.
    fn current_pid() -> u32;
    /// Push a raw record to the trace pipe.
    fn trace_pipe_push_raw_record(buf: &[u8]);
    /// Cache the process name for a given PID.
    fn trace_cmdline_push(pid: u32);
}

#[derive(Debug)]
pub struct TracePointMap<L: RawMutex + 'static>(BTreeMap<u32, &'static TracePoint<L>>);

impl<L: RawMutex + 'static> TracePointMap<L> {
    /// Create a new TracePointMap
    fn new() -> Self {
        Self(BTreeMap::new())
    }
}

impl<L: RawMutex + 'static> Deref for TracePointMap<L> {
    type Target = BTreeMap<u32, &'static TracePoint<L>>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<L: RawMutex + 'static> DerefMut for TracePointMap<L> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Debug)]
pub struct TracingEventsManager<L: RawMutex + 'static> {
    subsystems: Mutex<L, BTreeMap<String, Arc<EventsSubsystem<L>>>>,
    map: Mutex<L, TracePointMap<L>>,
}

impl<L: RawMutex + 'static> TracingEventsManager<L> {
    fn new(map: TracePointMap<L>) -> Self {
        Self {
            subsystems: Mutex::new(BTreeMap::new()),
            map: Mutex::new(map),
        }
    }

    /// Get the tracepoint map
    pub fn tracepoint_map(&self) -> MutexGuard<L, TracePointMap<L>> {
        self.map.lock()
    }

    /// Create a subsystem by name
    ///
    /// If the subsystem already exists, return the existing subsystem.
    fn create_subsystem(&self, subsystem_name: &str) -> Arc<EventsSubsystem<L>> {
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
    fn new() -> Self {
        Self {
            events: Mutex::new(BTreeMap::new()),
        }
    }

    /// Create an event by name
    fn create_event(&self, event_name: &str, event_info: EventInfo<L>) {
        self.events
            .lock()
            .insert(event_name.to_string(), Arc::new(event_info));
    }

    /// Get the event by name
    pub fn get_event(&self, event_name: &str) -> Option<Arc<EventInfo<L>>> {
        self.events.lock().get(event_name).cloned()
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
    tracepoint: &'static TracePoint<L>,
    format: TracePointFormatFile<L>,
    id: TracePointIdFile<L>,
    // filter:,
    // trigger:,
}

impl<L: RawMutex + 'static> EventInfo<L> {
    fn new(tracepoint: &'static TracePoint<L>) -> Self {
        let enable = TracePointEnableFile::new(tracepoint);
        let format = TracePointFormatFile::new(tracepoint);
        let id = TracePointIdFile::new(tracepoint);
        Self {
            enable,
            tracepoint,
            format,
            id,
        }
    }

    /// Get the tracepoint
    pub fn tracepoint(&self) -> &'static TracePoint<L> {
        self.tracepoint
    }

    /// Get the enable file
    pub fn enable_file(&self) -> &TracePointEnableFile<L> {
        &self.enable
    }

    /// Get the format file
    pub fn format_file(&self) -> &TracePointFormatFile<L> {
        &self.format
    }

    /// Get the ID file
    pub fn id_file(&self) -> &TracePointIdFile<L> {
        &self.id
    }
}

/// TracePointFormatFile provides a way to get the format of the tracepoint.
#[derive(Debug, Clone)]
pub struct TracePointFormatFile<L: RawMutex + 'static> {
    tracepoint: &'static TracePoint<L>,
}

impl<L: RawMutex + 'static> TracePointFormatFile<L> {
    fn new(tracepoint: &'static TracePoint<L>) -> Self {
        Self { tracepoint }
    }

    /// Read the tracepoint format
    ///
    /// Returns the format string of the tracepoint.
    pub fn read(&self) -> String {
        self.tracepoint.print_fmt()
    }
}

#[derive(Debug, Clone)]
pub struct TracePointEnableFile<L: RawMutex + 'static> {
    tracepoint: &'static TracePoint<L>,
}

impl<L: RawMutex + 'static> TracePointEnableFile<L> {
    fn new(tracepoint: &'static TracePoint<L>) -> Self {
        Self { tracepoint }
    }

    /// Read the tracepoint status
    ///
    /// Returns true if the tracepoint is enabled, false otherwise.
    pub fn read(&self) -> &'static str {
        if self.tracepoint.is_enabled() {
            "1\n"
        } else {
            "0\n"
        }
    }
    /// Enable or disable the tracepoint
    pub fn write(&self, enable: char) {
        match enable {
            '1' => self.tracepoint.enable(),
            '0' => self.tracepoint.disable(),
            _ => {
                log::warn!("Invalid value for tracepoint enable: {}", enable);
            }
        }
    }
}

#[derive(Debug, Clone)]
pub struct TracePointIdFile<L: RawMutex + 'static> {
    tracepoint: &'static TracePoint<L>,
}

impl<L: RawMutex + 'static> TracePointIdFile<L> {
    fn new(tracepoint: &'static TracePoint<L>) -> Self {
        Self { tracepoint }
    }

    /// Read the tracepoint ID
    ///
    /// Returns the ID of the tracepoint.
    pub fn read(&self) -> String {
        format!("{}\n", self.tracepoint.id())
    }
}

extern "C" {
    fn __start_tracepoint();
    fn __stop_tracepoint();
}

/// Initialize the tracing events
pub fn global_init_events<L: RawMutex + 'static>() -> Result<TracingEventsManager<L>, &'static str>
{
    static TRACE_POINT_ID: AtomicUsize = AtomicUsize::new(0);
    let events_manager = TracingEventsManager::new(TracePointMap::<L>::new());
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
    tracepoint_data.sort_by(|a, b| {
        a.trace_point
            .name()
            .cmp(b.trace_point.name())
            .then(a.trace_point.system().cmp(b.trace_point.system()))
    });
    log::info!("tracepoint_data_len: {}", tracepoint_data_len);

    let mut tracepoint_map = events_manager.tracepoint_map();
    for tracepoint_meta in tracepoint_data {
        let tracepoint = tracepoint_meta.trace_point;
        let id = TRACE_POINT_ID.fetch_add(1, core::sync::atomic::Ordering::Relaxed);
        tracepoint.set_id(id as u32);
        tracepoint.register(tracepoint_meta.print_func, Box::new(()));
        tracepoint_map.insert(id as u32, tracepoint);
        log::info!(
            "tracepoint registered: {}:{}",
            tracepoint.system(),
            tracepoint.name(),
        );
        let subsys_name = tracepoint.system();
        let subsys = events_manager.create_subsystem(subsys_name);
        let event_info = EventInfo::new(tracepoint);
        subsys.create_event(tracepoint.name(), event_info);
    }
    drop(tracepoint_map); // Release the lock on the tracepoint map
    Ok(events_manager)
}
