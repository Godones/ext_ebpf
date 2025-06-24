# BPF-basic

A Rust library providing basic abstractions and utilities for eBPF (Extended Berkeley Packet Filter) programming.

## Overview

BPF-basic is a no_std Rust crate that provides essential abstractions and utilities for eBPF programming. It offers a unified interface for working with eBPF maps and helper functions, making it easier to write eBPF programs in Rust.

## Features

- **Unified Map Interface**: Provides a consistent interface for working with different types of eBPF maps
- **Map Types Support**:
  - Array maps
  - Hash maps
  - LRU maps
  - Queue maps
- **Helper Functions**: Common eBPF helper functions and utilities
- **Kernel Auxiliary Operations**: Trait for kernel-specific operations
- **Error Handling**: Custom error types for eBPF operations

## Usage

The crate is designed to be used in eBPF programs. Here's a basic example of how to use it:

```rust no_run
use bpf_basic::{KernelAuxiliaryOps, UnifiedMap, Result};

// Implement the KernelAuxiliaryOps trait for your environment
struct MyKernelOps;

impl KernelAuxiliaryOps for MyKernelOps {
    // Implement required methods
}

fn kernel_create_map_syscall(){
    let map = bpf_map_create::<MyKernelOps>();
}

```

## Error Handling

The crate defines a custom `BpfError` enum with the following variants:
- `InvalidArgument`: Invalid argument provided
- `NotSupported`: Operation not supported
- `NotFound`: Resource not found
- `NoSpace`: Insufficient space


## Example
- See [DragonOS eBPF with Kprobe](https://github.com/DragonOS-Community/DragonOS/blob/master/kernel/src/perf/kprobe.rs) for more details.
- See [DragonOS eBPF with Tracepoint](https://github.com/DragonOS-Community/DragonOS/blob/master/kernel/src/perf/tracepoint.rs) for more details.
- See [Alien eBPF with Kprobe](https://github.com/Godones/Alien/blob/main/kernel/src/perf/kprobe.rs) for more details.
- See [Hermit eBPF with Tracepoint](https://github.com/os-module/hermit-kernel/blob/dev/src/tracepoint/hook.rs)

