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
    fn cpu_id() -> u32 {
        0
    }

    fn current_pid() -> u32 {
        1
    }

    fn time_now() -> u64 {
        time::SystemTime::now()
            .duration_since(time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn trace_pipe_push_raw_record(buf: &[u8]) {
        let mut pipe = TRACE_RAW_PIPE.lock();
        pipe.push_event(buf.to_vec());
    }
}

// Define tracepoint
define_event_trace!(
    Mutex<()>,
    Kops,
    TEST,
    TP_PROTO(a: u32, b: &TestS),
    TP_STRUCT__entry{
        a: u32,
        b: u32,
    },
    TP_fast_assign{
        a: a,
        b: *b.b.deref().deref(),
    },
    TP_ident(__entry),
    // Custom tracepoint print format
    TP_printk{
        let arg1 = __entry.a;
        let arg2 = __entry.b;
        format!("Hello from tracepoint! a={:?}, b={}", arg1, arg2)
    }
);

define_event_trace!(
    Mutex<()>,
    Kops,
    TEST2,
    TP_PROTO(a: u32, b: u32),
    TP_STRUCT__entry{
        a: u32,
        b: u32,
    },
    TP_fast_assign{
        a:a,
        b:b,
    },
    TP_ident(__entry),
    // Custom tracepoint print format
    TP_printk{
        format_args!("Hello from tracepoint! a={}, b={}", __entry.a, __entry.b)
    }
);
// Use the tracepoint in kernel code
 pub fn test_trace(a: u32, b: u32) {
    let x = TestS {
        a,
        b: Box::new(Arc::new(b)),
    };
    // first tracepoint
    trace_TEST(a, &x);
    // second tracepoint
    trace_TEST2(a, b);
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
- Implements proper synchronization primitives for kernel thread safety
- Provides safe abstractions for kernel tracepoint management

