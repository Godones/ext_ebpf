# ext_ebpf

This project aims to provide a set of components for adding eBPF support to the Rust kernel.


## Components

- [tracepoint](tracepoint/): A Rust crate for implementing tracepoints in the kernel. This crate provides a flexible and efficient way to add tracing capabilities to your kernel, similar to Linux kernel's tracepoint mechanism.
- [kprobe](kprobe/): A Rust crate for implementing kprobes in the kernel. This crate provides a way to dynamically instrument kernel functions and collect data at runtime.
- [bpf-basic](bpf-basic/): A Rust library providing basic abstractions and utilities for eBPF (Extended Berkeley Packet Filter) programming.
- [rbpf](rbpf/): This crate contains a virtual machine for eBPF program execution.


## Roadmap
- [x] Implement basic kprobe support
- [x] Implement basic tracepoint support
- [x] Implement basic eBPF map and helper functions
- [ ] Implement basic eBPF support in some kernels 
    - Monolithic kernels
        - [x] [DragonOS](https://github.com/DragonOS-Community/DragonOS)
        - [x] [Alien](https://github.com/Godones/Alien)
    - Unikernel
        - [ ] [Hermit](https://github.com/hermit-os/kernel) 
- [ ] Implement more eBPF maps and helper functions
- [ ] Implement other kernel hooks

## Contributing

Contributions are welcome! Here are some guidelines to help you get started:

### Getting Started

1. Fork the repository
2. Create a new branch for your feature or bugfix
3. Make your changes
4. Run tests and ensure they pass
5. Submit a pull request

### Code Style

- Follow Rust's standard formatting guidelines
- Use `cargo fmt` to format your code
- Ensure your code passes `cargo clippy` checks
- Add appropriate documentation comments
- Include tests for new functionality

### License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for the full license text.

## Reference
- https://docs.cilium.io/en/stable/reference-guides/bpf/architecture/
- https://blog.spoock.com/2024/01/11/bpf-tail-call-intro/