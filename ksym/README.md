# ksym
该模块提供内核符号表的支持。目前，有两种方式在内核中使用符号表。

## Usage
```
nm -n -C {your kernel file} | grep ' [Tt] ' | grep -v '\.L' | grep -v '$x' | cargo run --bin {type} --features="demangle"
```

其中 `{type}` 可以是 `gen_ksym` 或 `gen_ksym_assembly`。前者会生成一个文本文件，内核模块可以在运行时解析该文件以获取符号表。后者会生成一个汇编文件，可以与内核一起编译，内核启动时解析并初始化符号表。

使用第二种方式，内核需要开启`assembly` feature。

## Output
对于第一种方式，生成的文件格式如下(与/proc/kallsyms类似)：

``` 
ffffffc080200000 T _start
ffffffc080378070 T core::slice::index::slice_start_index_len_fail
ffffffc080379d12 T core::slice::index::slice_start_index_len_fail::do_panic::runtime
```

对于第二种方式，生成的汇编文件格式如下：

```
.section .rodata

.global ksyms_address
.align 8
ksyms_address:
	.quad

.global ksyms_num
.align 8
ksyms_num:
    .quad

.global ksyms_names_index
.align 8
ksyms_names_index:

.global ksyms_names
.align 8
ksyms_names:

```

## Interface
- `init_kernel_symbols(ksym: &str)`：从字符串`ksym`中解析符号表并初始化内核符号表。该字符串的格式与`/proc/kallsyms`相同。
- `init_kernel_symbols()`：使用第二种方式下，从嵌入的符号表中解析符号表并初始化内核符号表。
- `lookup_kallsyms(addr: usize) -> Option<(String, usize)>` ：根据地址`addr`查找符号表，返回符号名称和符号地址的元组。如果未找到符号，则返回`None`。注意，该符号可能是与传入地址不完全匹配的最近符号。
- `addr_from_symbol(symbol: &str) -> Option<usize>`：根据符号名称查找符号表，返回符号地址。如果未找到符号，则返回`None`。


### 类似Linux 的 kallsyms blob 结构

```
┌───────────────────────────────┐
│        kallsyms blob 文件       │
└───────────────────────────────┘
| Offset | 内容                        | 说明                           |
| ------ | --------------------------- | ------------------------------ |
| 0x00   | u64: kallsyms_num_syms      | 符号总数                       |
| 0x08   | u64: kallsyms_addresses.len | 地址数组长度（通常等于符号数） |

0x10    | kallsyms_addresses[u64]       | 符号地址数组（升序）
...     |                                | 用于地址二分查找
0x10 + 8*N_syms

...     | kallsyms_offsets[u64]         | 每个符号在 kallsyms_names 中的起始偏移
...     |                                | 用于对应压缩符号流

...     | kallsyms_names[u16]           | 压缩符号流（token_id + 原字符混合）
...     |                                | 解码出符号名

...     | kallsyms_seqs_of_names[u32]  | 符号序列号
...     |                                | 用于名字二分查找

...     | u64: token_table.len           | token_table 长度
...     | token_table[u8]               | token 字符串拼接

...     | token_index[u32]              | token 在 token_table 的起始偏移

示意说明：

1. 地址查找：
   - 二分查找 kallsyms_addresses[] 找到符号索引 i
   - kallsyms_offsets[i] → kallsyms_names 中符号起始位置
   - expand_symbol 解码符号名

2. 名字查找：
   - 二分查找 kallsyms_names（通过 seq_of_names 或解码得到名字）找到符号索引 i
   - kallsyms_addresses[i] → 符号地址

3. offset 是关键桥梁：
   - 符号在地址数组和名字数组之间的对应关系
   - 保证地址和符号名的二分查找都能正确返回结果

4. token_table + token_index：
   - 压缩符号流使用 token_id 替代高频子串
   - token_index 用于在 token_table 中快速定位 token 字符串

```
