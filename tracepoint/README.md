# tracepoint

A Rust crate for implementing tracepoints in kernel. This crate provides a flexible and efficient way to add tracing capabilities to your kernel, similar to Linux kernel's tracepoint mechanism.

## Features

- Define and manage kernel tracepoints with custom event data
- Hierarchical organization of tracepoints through subsystems
- Thread-safe implementation using mutexes
- Configurable tracepoint enable/disable functionality
- Customizable trace record formatting
- Support for tracing pipe for collecting trace records
- No-std compatible for kernel space usage



## Usage

### Basic Example

```rust
use spin::Mutex;
use tracepoint::{define_event_trace, KernelTraceOps};
// Define kernel operations
pub static TRACE_RAW_PIPE: Mutex<tracepoint::TracePipeRaw> =
    Mutex::new(tracepoint::TracePipeRaw::new(1024));

pub struct Kops;

impl KernelTraceOps for Kops {
    ... // Implement required methods
}

// Define tracepoint
define_event_trace!(
    TEST,
    TP_lock(Mutex<()>),
    TP_kops(Kops),
    TP_system(tracepoint_test),
    TP_PROTO(a: u32, b: u32),
    TP_STRUCT__entry{
        a: u32,
        b: u32
    },
    TP_fast_assign{
        a:a,
        b:b
    },
    TP_ident(__entry),
    TP_printk(format_args!("Hello from tracepoint! a={}, b={}", __entry.a, __entry.b))
);
// Use the tracepoint in kernel code
 pub fn test_trace(a: u32, b: u32) {
    // call the tracepoint
    trace_TEST(a, &x);
    println!("Tracepoint TEST called with a={}, b={}", a, b);
}
```

See example in `examples/usage.rs` for a complete example.
### Managing Tracepoints

```rust
// Initialize the tracing system in kernel module
let manager = global_init_events::<Mutex<()>>().unwrap();

// Enable/disable tracepoints
let subsystem = manager.get_subsystem("my_subsystem").unwrap();
let tracepoint_info = subsystem.get_event("my_event").unwrap();
tracepoint_info.enable_file().write(true); // Enable
tracepoint_info.enable_file().write(false); // Disable


// other operations
let tracepoint_map = manager.tracepoint_map();
// Iterate over all tracepoints
for (name, tracepoint) in tracepoint_map.iter() {
    println!("Tracepoint: {}, Enabled: {}", name, tracepoint.is_enabled());
}
```

## Architecture

The crate provides several key components:

1. `TracingEventsManager`: Manages subsystems and their tracepoints
2. `EventsSubsystem`: Groups related tracepoints
3. `EventInfo`: Contains tracepoint metadata and control
4. `TracePointEnableFile`: Controls tracepoint enable/disable state
5. `KernelTraceOps`: Trait for implementing kernel-level operations

## Safety

This crate is designed for kernel space usage and:
- Uses `#![no_std]` for kernel compatibility
- Provides safe abstractions for kernel tracepoint management


## Example
- See [DragonOS tracepoint](https://github.com/DragonOS-Community/DragonOS/blob/master/kernel/src/debug/tracing/mod.rs) for more details.
- See [Hermit tracepoint](https://github.com/os-module/hermit-kernel/blob/dev/src/tracepoint/mod.rs) for more details.