# Kprobe Crate

A Rust crate for implementing kernel probes (kprobes) in operating systems. This crate provides functionality for dynamically instrumenting kernel code by inserting breakpoints and debug points.

## Features
- Support for multiple architectures:
  - x86_64
  - RISC-V 64
  - LoongArch64

## Usage

### Basic Usage

```rust
use kprobe::{KprobeManager, KprobePointList, KprobeBuilder};

// Create a kprobe manager and point list
let mut manager = KprobeManager::new();
let mut point_list = KprobePointList::new();

// Create and register a kprobe
let kprobe = register_kprobe(
    &mut manager,
    &mut point_list,
    KprobeBuilder::new(probe_addr)
);

// Unregister the kprobe when done
unregister_kprobe(&mut manager, &mut point_list, kprobe);
```

## Example
- See [DragonOS Kprobe](https://github.com/DragonOS-Community/DragonOS/tree/master/kernel/src/debug/kprobe) for more details.
- See [Alien Kprobe](https://github.com/Godones/Alien/blob/main/kernel/src/kprobe/mod.rs) for more details.

## API Overview

### Core Types

- `KprobeManager` - Manages registered kprobes
- `KprobePointList` - Tracks kprobe points
- `Kprobe` - Represents a single kprobe
- `KprobeBuilder` - Builder for creating kprobes
- `KprobePoint` - Represents a probe point in memory

### Key Functions

- `register_kprobe` - Register a new kprobe
- `unregister_kprobe` - Remove a registered kprobe
- `KprobeManager::get_break_list` - Get the list of breakpoints
- `KprobeManager::get_debug_list` - Get the list of debug points

## Safety Considerations

- This crate uses `#![no_std]` and is designed for kernel-level code
- Proper synchronization is required when using kprobes in multi-threaded environments
- Care must be taken when instrumenting critical kernel paths

## Rust Version
Requires Rust 1.88 or later(nightly).