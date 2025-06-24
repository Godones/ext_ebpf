# eBPF for Unikernels

## Unikernel Components

- [simple-ebpf](unikernel/simple-ebpf/): A minimal eBPF program example that demonstrates how to trace kernel events (such as `sys_enter_openat`) using tracepoints. 
- [complex-ebpf](unikernel/complex-ebpf/): A more advanced eBPF program example that counts source IPs and ports from network packets, showcasing eBPF's application in network traffic analysis. 
- [ebpf-command](unikernel/ebpf-command/): Defines the command protocol and data structures for communication between the eBPF server and client, supporting operations such as loading, attaching, enabling, disabling, and removing eBPF programs.
- [net-aya](unikernel/net-aya/): Provides abstractions for network communication, eBPF program loading and management, and map operations on the server side. It enables custom channels (such as UDP) for client-server interaction.
- [uebpf](unikernel/uebpf/): The main unikernel eBPF client program, integrating both simple and complex eBPF examples. It manages eBPF programs and maps remotely via UDP, enabling end-to-end eBPF management and data collection in unikernel environments.



## Usage
To use the unikernel eBPF components, follow these steps:
1. **Add tracepoints**: Ensure that the kernel supports tracepoints for the eBPF programs to function correctly.
    - See [Hermit tracepoint](https://github.com/os-module/hermit-kernel/blob/dev/src/tracepoint/mod.rs) for more details.
    - See [Hermit define tracepoint](https://github.com/os-module/hermit-kernel/blob/798ad302fd56bdcd149383c8e60dd3550009f5f2/src/drivers/net/virtio/mod.rs#L317) for an example of defining a tracepoint.
2. **Add UDP support**: Ensure that the unikernel environment supports UDP for communication between the eBPF server and client.
3. **Add a task as a server**: Implement a task that listens for commands from the eBPF client and manages eBPF programs and maps accordingly.
    - See [Hermit ebpf server](https://github.com/os-module/hermit-kernel/blob/dev/src/ebpf/server.rs) for an example of an eBPF server implementation.
4. **Add the eBPF commands**: The unikernel should execute the eBPF commands defined in the `ebpf-command` module to manage eBPF programs and maps.
    - See [Hermit ebpf command](https://github.com/os-module/hermit-kernel/blob/dev/src/ebpf/command/mod.rs) to understand how to execute eBPF commands.
5. **Run the unikernel**: Compile and run the unikernel with the eBPF components integrated. The unikernel will start the eBPF server to listen for commands.
6. **Interact with eBPF programs**: Use the eBPF client to send commands to the server, enabling or disabling eBPF programs, loading new programs, and managing maps.
    - See [Hermit ubpf](./uebpf/) for an example of how to interact with eBPF programs from the unikernel client.
