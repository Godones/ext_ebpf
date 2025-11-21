# tp-lexer: filter expression parsing and evaluation

A lightweight library for parsing and evaluating Linux tracepoint-like filter expressions. It supports numeric and string comparisons, glob matching, bit masking, and tri-state semantics, making it useful for filtering event records in eBPF/trace pipelines.

- Numeric operators: `== != < <= > >=`, with optional bit mask: `field & 0x10 == 0x10`
- String operators: `== != ~` (`~` performs glob matching: `* ? [..]`, supports `[!a]`/`[^a]`)
- Strings may be unquoted (e.g. `comm != bash`). Use quotes when spaces/special chars exist (e.g. `"C Program").
- Logical operators: `&& ||` with short-circuit. Precedence: parentheses > compare > `&&` > `||`.
- Missing fields at runtime yield `Unknown`; `Unknown` is true-neutral in `&&`, false-neutral in `||`, and top-level `Unknown` is treated as `true`.
- Unknown fields (not in schema) are compile-time errors.
- Numeric literals support decimal and hexadecimal (`0x..`).

## Quick Start

```rust
use std::collections::HashMap;
use tp_lexer::{Schema, compile_with_schema};

fn main() {
    // 1) Declare field types (e.g., for a tracepoint event)
    let schema = Schema::new()
        .with_int("sig")
        .with_str("comm")
        .with_int("flags");

    // 2) Compile the expression (unknown fields or type mismatches error out)
    let expr = "((sig >= 10 && sig < 15) || sig == 17) && comm != bash";
    let compiled = compile_with_schema(expr, schema).expect("compile filter");

    // 3) Runtime context (this crate implements Context for HashMap<String,String>)
    let mut ctx: HashMap<String, String> = HashMap::new();
    ctx.insert("sig".into(), "12".into());
    ctx.insert("comm".into(), "sh".into());

    // 4) Evaluate
    let ok = compiled.evaluate(&ctx);
    println!("match? {}", ok); // true
}
```

Glob example:
```rust
let schema = Schema::new().with_str("comm");
let compiled = compile_with_schema("comm ~ bash*", schema).unwrap();
let mut ctx = HashMap::from([(String::from("comm"), String::from("bashXYZ"))]);
assert!(compiled.evaluate(&ctx));
```

Bit mask example:
```rust
let schema = Schema::new().with_int("flags");
let cmp = compile_with_schema("flags & 0x10 == 0x10", schema).unwrap();
let ctx = HashMap::from([(String::from("flags"), format!("{}", 0x30))]);
assert!(cmp.evaluate(&ctx));
```

## Run & Test

From the workspace root:
```zsh
cargo test -p tp-lexer
cargo run  -p tp-lexer -- 'comm ~ bash* && (sig == 17 || sig >= 10)'
```

- Without arguments the demo binary runs a default expression.
- Adjust `Schema` and the event context construction to integrate this library into your trace pipeline.

## Errors & Semantics
- Compile-time errors:
  - Unknown fields (not defined in `Schema`)
  - Type mismatches (numeric compare on string fields, or vice versa)
  - Syntax errors (unknown operators, unterminated strings, etc.)
- Runtime semantics:
  - Missing fields return `Unknown`; with short-circuit and neutral behavior in `&&`/`||`; top-level `Unknown` is treated as `true` to avoid filtering out events solely due to missing fields.

## Integration Tips
- Precompile: parse filters from files into an AST once, and reuse compiled expressions for each event.
- Performance: intern field names, precompute masks and comparisons, and minimize string allocations.
- Extensions (optional): sets, ranges, helper functions/regex (intentionally not enabled to stay close to kernel docs).

## Reference
- [Linux tracepoint filter docs](https://www.kernel.org/doc/html/v4.17/trace/events.html)
- [The implementation of tracepoint filters in the Linux kernel](https://www.kernel.org/doc/html/v4.17/trace/events.html)