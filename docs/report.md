# ext-ebpf 技术报告

## 背景
eBPF（Extended Berkeley Packet Filter）是一种强大的内核技术，允许开发者在内核中运行沙箱化的代码。它最初用于网络数据包过滤，但现在已经扩展到许多其他领域，如性能监控、安全性和系统调试。eBPF 通过提供一个安全的执行环境，使得开发者可以在不修改内核源代码的情况下，动态地插入和执行代码。这种能力使得 eBPF 成为一个非常灵活和强大的工具。

然而，eBPF仅仅在Linux内核中拥有完备的支持，即使windows也开始支持eBPF([ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows)),在一些嵌入式系统和其他操作系统中，eBPF的支持仍然有限。为了在这些环境中使用eBPF，需要对其进行扩展和适配。但是，从Linux内核中将eBPF的功能移植到其他系统并不是一件容易的事情。不同的操作系统和硬件架构有不同的内核设计和API，这使得直接移植eBPF变得复杂。尽管类似[ubpf](https://github.com/iovisor/ubpf)的项目已经实现了一个用于运行eBPF字节码的虚拟器，但仅仅提供一个虚拟机并不足以满足所有需求。eBPF的强大之处在于它能够与内核的各种功能进行深度集成，如网络栈、文件系统和进程管理等。因此，单纯的虚拟机实现无法充分发挥eBPF的优势。

为了解决这个问题，我们需要一个更全面的解决方案。ext-ebpf项目旨在提供一个可移植的eBPF实现，能够在不同的操作系统和硬件架构上运行。它不仅包括一个eBPF虚拟机，还提供了与内核功能的集成接口，使得开发者可以在不同的环境中使用eBPF的强大功能。


## ext-ebpf的设计目标
1. **可移植性**：ext-ebpf旨在提供一系列小的用于支持eBPF的组件，能够在不同的操作系统和硬件架构上运行。它将eBPF的核心功能与特定平台的内核功能解耦，使得开发者可以在不同环境中使用eBPF。
2. **易用性**：ext-ebpf提供了简单易用的API，使得开发者可以轻松地在内核中添加诸如kprobe、tracepoint等功能。它还提供了丰富的文档和示例代码，帮助开发者快速上手。
3. **性能**：为了尽可能采用JIT编译技术，ext-ebpf向[rbpf](https://github.com/qmonnet/rbpf) 完善了JIT的支持，同时允许在no_std环境中使用。


## 技术路线
ext-ebpf的技术路线主要包括以下几个方面：

### 内核钩子
Linux内核提供了多种钩子机制，如kprobe、tracepoint、ftrace、uprobe等，允许开发者在内核中插入自定义代码。为了简单起见，ext-ebpf目前只实现了kprobe和tracepoint功能。

对于kprobe来说，ext-ebpf利用了不同架构上的断点异常机制，允许开发者在内核函数中执行自定义代码。通过kprobe，开发者可以在内核函数执行前或执行后插入代码，从而实现对内核行为的监控和修改。 

对于tracepoint，ext-ebpf提供了一种类似于Linux内核的tracepoint机制，允许开发者在内核中添加自定义的跟踪点。通过tracepoint，开发者可以在特定的内核事件发生时执行自定义代码，从而实现对内核事件的监控和分析。tracepoint是静态定义的，在编译时就确定了位置和参数。

### eBPF程序
eBPF程序是用来在内核中执行自定义代码的。ext-ebpf不限制编写eBPF程序的语言。为了尽可能重用现有的工具，开发者可以实现现有的工具编写和编译eBPF程序。在宏内核中，我们通常选择兼容Linux生态的方法在内核中引入eBPF程序。对于其它形态的内核，比如unikernel或者嵌入式系统，则需要改进一步的考量。


### eBPF映射
eBPF映射是eBPF程序与内核之间共享数据的机制。ext-ebpf提供了对多种类型的eBPF映射的支持，包括哈希表、数组、队列等。这些映射允许eBPF程序在内核中存储和检索数据。

### 辅助函数
辅助函数是eBPF程序可以调用的内核函数，用于执行特定的操作，如内存分配、时间戳获取等。ext-ebpf提供了一组常用的辅助函数，使得eBPF程序可以更方便地与内核交互。




## ext-ebpf的主要组件
- **tracepoint**：一个Rust crate，用于在内核中实现tracepoint功能。它提供了一种灵活高效的方式来添加跟踪能力，类似于Linux内核的tracepoint机制。
- **kprobe**：一个Rust crate，用于在内核中实现kprobe功能。它提供了一种动态插桩内核函数并在运行时收集数据的方式。
- **bpf-basic**：一个Rust库，提供eBPF编程的基本抽象和实用工具。它为开发者提供了一个简单的接口来编写和管理eBPF程序。
- **rbpf**：一个eBPF程序执行的虚拟机。它提供了一个高效的执行环境，支持JIT编译和no_std环境。

## Unikernel 相关组件
- simple-ebpf/：一个简单的 eBPF 程序示例，演示如何通过 tracepoint 追踪内核事件（如 sys_enter_openat）
- complex-ebpf/：一个复杂的 eBPF 程序示例，实现了对网络包的源 IP 和端口计数，展示了 eBPF 在网络流量分析中的应用。
- ebpf-command/：定义 eBPF server 与 client 之间的命令协议和数据结构，支持 eBPF 程序的加载、附加、启用、禁用、卸载等操作。
- net-aya/：提供 eBPF server 端的网络通信、eBPF 程序加载与管理、map 操作等功能的抽象，支持通过自定义通道（如 UDP）与 client 交互。
- uebpf/：unikernel eBPF 客户端主程序，集成 simple/complex eBPF 示例，负责通过 UDP 通道与 server 交互，远程管理 eBPF 程序和 map，实现端到端的 eBPF 管理与数据采集。

> 注意：unikernel的uebpf组件目前工作在hermit内核上，其他内核可能需要根据具体实现进行适配。


## eBPF的当前状态
目前，ext-ebpf已经在一些内核中实现了基本的eBPF支持，包括kprobe和tracepoint功能。我们正在逐步扩展对更多eBPF映射和辅助函数的支持，并计划在未来实现对其他内核钩子的支持。
在monolithic内核方面，ext-ebpf已经在以下内核中实现了基本的eBPF支持：
- [DragonOS](https://github.com/DragonOS-Community/DragonOS)
- [Alien](https://github.com/Godones/Alien)

这可以允许开发者在这些内核中使用eBPF进行性能监控和调试等任务。开发者可以使用Aya工具来编写和管理eBPF程序，这些内核提供了兼容Linux的功能。


## 如何在unikernel中使用eBPF

在宏内核中支持eBPF很容易，因为可以参考Linux内核的实现，并实现其兼容性。在unikernel中，eBPF存在的主要难点：

1. **内核钩子**：unikernel通常没有像Linux内核那样的丰富钩子机制。需要根据unikernel的特性，设计适合的钩子机制。
2. **user tools**：unikernel通常没有像Linux那样的用户空间工具链。需要提供适合unikernel的编译和加载eBPF程序的工具。
3. **eBPF程序**：unikernel通常将内核和应用程序打包在一起，缺乏像Linux那样的用户空间和内核空间的分离。需要设计一种机制，使得可以
将eBPF程序加载到unikernel的内核中。
4. **eBPF映射**：由于user tools的缺乏，如果在eBPF程序中使用复杂的Map，那么unikernel就需要自行处理这部分的内容


对于内核钩子来说，可以考虑在unikernel中实现tracepoint的功能。通过在unikernel的内核代码中插入钩子点，可以实现对特定事件的监控和处理。如果可以在unikernel中引入kprobe，则可以动态地插入代码到内核函数中，从而实现运行时的动态插桩。

对于用户工具，可以检查**是否可以重用现有的用户库**，比如eBPF代码的重定位处理。当编写的eBPF程序包含多个函数时，需要在加载到内核中前将多个函数合并到一段代码中，并在代码中添加跳转指令。Aya这样的库中似乎暴露了一些接口允许开发者单独调用从而完成这样的功能，但是为eBPF程序中使用的Map创建文件描述符的这些功能将不再可用。

对于eBPF程序，由于unikernel不提供交互式的界面。基于unikernel中通常支持网络的特性，可以考虑通过网络接口来加载eBPF程序。可以设计一个简单的协议，通过网络将eBPF程序发送到unikernel的内核中，并在内核中解析和加载。这里还需要解决的另一个问题是：
- 如何获取eBPF程序的输出？

如果采用网络的方式在unikernel中加载eBPF程序，那么尽管可以将普通的eBPF输出（如打印日志）发送到网络上，但是对于一些需要与内核交互的eBPF程序，比如获取Map中的数据，就需要设计一种机制来处理这些交互。
可能的解决方案是：
- 在unikernel中实现一个简单的RPC机制，允许eBPF程序通过网络与unikernel的内核进行通信。
- 在unikernel中实现一个简单的文件系统接口，允许eBPF程序将数据写入到文件中，然后通过网络读取这些文件。



## Hermit OS的实践

### eBPF Server 和 eBPF client
由于unikernel通常没有用户空间和内核空间的分离，因此在unikernel中实现eBPF程序的加载和执行需要一些特殊的处理。我们可以在unikernel中实现一个eBPF server和eBPF client的模型。通常，unikernel都会支持多任务和网络，因此，我们可以在内核中引入一个eBPF server任务，该任务负责监听来自eBPF client的请求，并根据请求加载、执行或管理eBPF程序。在客户端，我们可以在宿主机上编译eBPF程序，并通过网络将其发送到unikernel的eBPF server。eBPF server接收到eBPF程序后，可以将其加载到内核中，并执行相应的操作。

### 内核钩子
在hermit这样轻量级的内核中，引入kprobe比较重量级，且可能会影响内核性能，我们选择使用tracepoint来实现eBPF的钩子功能。我们使用tracepoint库来在内核中实现tracepoint功能。大多数功能已经在库中实现。在内核中要做的就是进一步实现tracepoint库定义的外部接口。

### eBPF程序
我们没有从零实现用户库来解析和处理eBPF程序。在客户端，我们重用了Aya库。由于Aya库通常只能工作在Linux内核上，因此我们将其在处理eBPF程序时设计到系统调用的部分替换为我们的实现。

比如当库在解析eBPF程序时，需要创建Map的文件描述符。我们需要将这个操作对应的系统调用转换为一个创建Map的命令，并通过网络发送到unikernel的eBPF server。eBPF server接收到命令后，创建Map并返回一个标识符给客户端。客户端可以使用这个标识符来访问Map。相应的，其它类似的系统调用也需要进行类似的处理。

目前已经支持的命令：
```rust
bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct eBPFCommandType: u32 {
        const LOAD_PROGRAM = 0x01;
        const REMOVE_PROGRAM = 0x02;
        const ATTACH_PROGRAM = 0x03;
        const DETACH_PROGRAM = 0x04;
        const GET_TP_INFO = 0x05;
        const ENABLE_TP = 0x06;
        const DISABLE_TP = 0x07;
        const CREATE_MAP = 0x08;
        const UPDATE_MAP = 0x09;
        const FREEZE_MAP = 0x0A;
        const DELETE_MAP = 0x0B;
        const MAP_GET_NEXT_KEY = 0x0C;
        const LOOKUP_MAP = 0x0D;
    }
}
```
尽管重用了Aya库，我们仍然需要对其进行一些修改，从而将其数据结构公开给我们的工具使用。

### eBPF映射
因为我们已经使用通过修改Aya来处理eBPF程序，这使得我们不用再在内核中手动解析eBPF程序使用的Map。我们直接参考在两个宏内核上的实现。

### eBPF Command

现在系统调用变成了一系列以网络进行传输的命令，内核就需要工具这些命令执行对应操作，这些操作可以和eBPF映射一样，参考在宏内核上的实现。


### 局限性

通过网络来传输信息和命令，意味着要占据网络带宽。除了获取Tracepoint的信息外，我们没有添加其它命令来传输内核的信息，比如获取eBPF程序使用printk输出到内核缓冲区的信息。我们认为，在unikernel进行这种输出是没有意义的。因此，我们更倾向于eBPF程序使用Map来收集数据，然后通过网络将Map中的数据发送到客户端。


## 工作进展

- [x] 在[Hermit](https://github.com/hermit-os/kernel) 中添加kprobe/tracepoint功能
- [x] 在[Hermit](https://github.com/hermit-os/kernel) 中实现eBPF程序的加载和执行

## Reference

