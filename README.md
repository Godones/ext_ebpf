# ext_ebpf

This project aims to provide a set of components for adding eBPF support to the Rust kernel.


## Components

- [tracepoint](tracepoint/): A Rust crate for implementing tracepoints in the kernel. This crate provides a flexible and efficient way to add tracing capabilities to your kernel, similar to Linux kernel's tracepoint mechanism.
- [kprobe](kprobe/): A Rust crate for implementing kprobes in the kernel. This crate provides a way to dynamically instrument kernel functions and collect data at runtime.
- [bpf-basic](bpf-basic/): A Rust library providing basic abstractions and utilities for eBPF (Extended Berkeley Packet Filter) programming.
- [rbpf](rbpf/): This crate contains a virtual machine for eBPF program execution.



## Unikernel Components

- [simple-ebpf](unikernel/simple-ebpf/): A minimal eBPF program example that demonstrates how to trace kernel events (such as `sys_enter_openat`) using tracepoints. It shows the full lifecycle management of eBPF programs (load, attach, enable, disable, unload) via a UDP channel to an eBPF server.
- [complex-ebpf](unikernel/complex-ebpf/): A more advanced eBPF program example that counts source IPs and ports from network packets, showcasing eBPF's application in network traffic analysis. It supports dynamic management and reading of eBPF map data via UDP communication with the server.
- [ebpf-command](unikernel/ebpf-command/): Defines the command protocol and data structures for communication between the eBPF server and client, supporting operations such as loading, attaching, enabling, disabling, and removing eBPF programs.
- [net-aya](unikernel/net-aya/): Provides abstractions for network communication, eBPF program loading and management, and map operations on the server side. It enables custom channels (such as UDP) for client-server interaction.
- [uebpf](unikernel/uebpf/): The main unikernel eBPF client program, integrating both simple and complex eBPF examples. It manages eBPF programs and maps remotely via UDP, enabling end-to-end eBPF management and data collection in unikernel environments.



## Roadmap
- [x] Implement basic kprobe support
- [x] Implement basic tracepoint support
- [x] Implement basic eBPF map and helper functions
- [x] Implement basic eBPF support in some kernels 
    - Monolithic kernels
        - [x] [DragonOS](https://github.com/DragonOS-Community/DragonOS)
        - [x] [Alien](https://github.com/Godones/Alien)
        - [x] [Starry](https://github.com/Starry-OS/StarryOS)
    - Unikernel
        - [x] [Hermit](https://github.com/os-module/hermit-rs/tree/dev) 
- [ ] Implement more eBPF maps and helper functions
  - [ ] ringbuf
- [ ] Implement other kernel hooks
  - [ ] rawtracepoint
  - [ ] uprobe/uretprobe
  - [ ] perf events


### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full license text.

## Reference
- https://docs.cilium.io/en/stable/reference-guides/bpf/architecture/
- https://blog.spoock.com/2024/01/11/bpf-tail-call-intro/