# ext-ebpf 技术报告

## 背景
eBPF（Extended Berkeley Packet Filter）是一种强大的内核技术，允许开发者在内核中运行沙箱化的代码。它最初用于网络数据包过滤，但现在已经扩展到许多其他领域，如性能监控、安全性和系统调试。eBPF 通过提供一个安全的执行环境，使得开发者可以在不修改内核源代码的情况下，动态地插入和执行代码。这种能力使得 eBPF 成为一个非常灵活和强大的工具。

然而，eBPF仅仅在Linux内核中拥有完备的支持，即使windows也开始支持eBPF([ebpf-for-windows](https://github.com/microsoft/ebpf-for-windows)),在一些嵌入式系统和其他操作系统中，eBPF的支持仍然有限。为了在这些环境中使用eBPF，需要对其进行扩展和适配。但是，从Linux内核中将eBPF的功能移植到其他系统并不是一件容易的事情。不同的操作系统和硬件架构有不同的内核设计和API，这使得直接移植eBPF变得复杂。尽管类似[ubpf](https://github.com/iovisor/ubpf)的项目已经实现了一个用于运行eBPF字节码的虚拟器，但仅仅提供一个虚拟机并不足以满足所有需求。eBPF的强大之处在于它能够与内核的各种功能进行深度集成，如网络栈、文件系统和进程管理等。因此，单纯的虚拟机实现无法充分发挥eBPF的优势。

为了解决这个问题，我们需要一个更全面的解决方案。ext-ebpf项目旨在提供一个可移植的eBPF实现，能够在不同的操作系统和硬件架构上运行。它不仅包括一个eBPF虚拟机，还提供了与内核功能的集成接口，使得开发者可以在不同的环境中使用eBPF的强大功能。


## ext-ebpf的设计目标
1. **可移植性**：ext-ebpf旨在提供一个跨平台的eBPF实现，能够在不同的操作系统和硬件架构上运行。它将eBPF的核心功能与特定平台的内核功能解耦，使得开发者可以在不同环境中使用eBPF。
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


## 下一步工作

- [ ] 在[Hermit](https://github.com/hermit-os/kernel) 中添加kprobe/tracepoint功能
- [ ] 在[Hermit](https://github.com/hermit-os/kernel) 中实现eBPF程序的加载和执行

## Reference

