# Write eBPF Tracepoints
使用Aya框架编写eBPF tracepoint的代码示例

第一步：查看Linux内核的tracepoint列表
```bash
sudo cat /sys/kernel/debug/tracing/available_events
```

以`syscalls:sys_enter_openat`为例，编写一个简单的eBPF程序来跟踪这个tracepoint。这个tracepoint在每次调用`openat`系统调用时触发。

第二步：使用模板创建一个项目

```bash
cargo generate https://github.com/aya-rs/aya-template
```

```
> cargo generate https://github.com/aya-rs/aya-template
⚠️   Favorite `https://github.com/aya-rs/aya-template` not found in config, using it as a git repository: https://github.com/aya-rs/aya-template
🤷   Project Name: tracepoint
🔧   Destination: /home/godones/projects/tracepoint ...
🔧   project-name: tracepoint ...
🔧   Generating template ...
✔ 🤷   Which type of eBPF program? · tracepoint
🤷   Which tracepoint category? (e.g sched, net etc...): syscalls
🤷   Which tracepoint name? (e.g sched_switch, net_dev_queue): sys_enter_openat
🔧   Moving generated files into: `/home/godones/projects/tracepoint`...
🔧   Initializing a fresh Git repository
✨   Done! New project created /home/godones/projects/tracepoin
```

第三步：运行模板生成的默认实现
```bash
RUST_LOG=info cargo run --release --config 'target."cfg(all())".runner="sudo -E"'
```

这会在每次调用`openat`系统调用时打印一条信息。



## 获取更多信息
为了从tracepoint中获取更多信息，需要了解内核在tracepoint触发时提供的上下文信息。可以通过查看`/sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format`文件来了解可用的字段。
```bash
cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
```

这将显示tracepoint的格式，包括可用的字段和它们的类型。
```
> sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
name: sys_enter_openat
ID: 703
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char __attribute__((btf_type_tag("user"))) * filename;      offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))
```

这里我们只关注其中的filename字段，可以看到它是一个指向用户空间的字符串指针。我们可以在eBPF程序中使用这个字段来获取打开的文件名。
第四步：修改eBPF程序以获取更多信息
```rust
fn try_aya_tracepoint_echo_open_small_file_path(ctx: &TracePointContext) -> Result<u32, i64> {
    const MAX_SMALL_PATH: usize = 16;
    let mut buf: [u8; MAX_SMALL_PATH] = [0; MAX_SMALL_PATH];

    // Load the pointer to the filename. The offset value can be found running:
    // sudo cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_open/format
    const FILENAME_OFFSET: usize = 24;
    if let Ok(filename_addr) = unsafe { ctx.read_at::<u64>(FILENAME_OFFSET) } {
        // read the filename
        let filename = unsafe {
            // Get an UTF-8 String from an array of bytes
            core::str::from_utf8_unchecked(
                // Use the address of the kernel's string  //

                // to copy its contents into the array named 'buf'
                match bpf_probe_read_user_str_bytes(filename_addr as *const u8, &mut buf) {
                    Ok(_) => &buf,
                    Err(e) => {
                        info!(
                            ctx,
                            "tracepoint sys_enter_openat called buf_probe failed {}", e
                        );
                        return Err(e);
                    }
                },
            )
        };
        info!(
            ctx,
            "tracepoint sys_enter_openat called, filename  {}", filename
        );
    }
    Ok(0)
}
```
简单起见，这里设置了最大路径长度为16字节，并在eBPF程序中读取filename字段的值。然后使用`bpf_probe_read_user_str_bytes`函数从用户空间读取字符串，并将其打印到日志中。

## Reference
https://mozillazg.com/2022/05/ebpf-libbpf-tracepoint-common-questions.html

