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
use tracepoint::{define_event_trace, define_trace_point, KernelTraceOps};

// Define kernel operations
struct Kops;
impl KernelTraceOps for Kops {
    fn cpu_id() -> u32 { 
        // Get current CPU ID from kernel
        unsafe { smp_processor_id() }
    }
    fn current_pid() -> u32 { 
        // Get current process ID from kernel
        current.pid
    }
    fn time_now() -> u64 { 
        // Get current kernel time
        ktime_get_ns()
    }
    fn trace_pipe_push_record(format: String) {
        // Push record to kernel trace pipe
        trace_printk(format.as_ptr())
    }
}

// Define a tracepoint
define_event_trace!(
    Mutex,
    Kops,
    TEST,
    (a: u32, b: u32),
    format_args!("Kernel tracepoint: a={}, b={}", a, b)
);

// Use the tracepoint in kernel code
trace_TEST(1, 2);
```

### Managing Tracepoints

```rust
// Initialize the tracing system in kernel module
let manager = global_init_events::<Mutex<()>>().unwrap();

// Enable/disable tracepoints
let subsystem = manager.get_subsystem("my_subsystem").unwrap();
let trace_point = subsystem.get_event("my_event").unwrap();
trace_point.enable_file().write(true); // Enable
trace_point.enable_file().write(false); // Disable
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

