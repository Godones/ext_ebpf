# ksym

## Usage
```
nm -n -C {your kernel file} | grep ' [Tt] ' | grep -v '\.L' | grep -v '$x' | cargo run --bin gen_ksym --features="demangle"
```

## Output
``` 
.section .rodata

.global ksyms_address
.align 8

ksyms_address:

.global ksyms_num
.align 8
ksyms_num:
        .quad   0

.global ksyms_names_index
.align 8
ksyms_names_index:

.global ksyms_names
.align 8
ksyms_names:

```