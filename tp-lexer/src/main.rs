use std::{collections::BTreeMap, env};

use tp_lexer::{Schema, compile_with_schema};

fn main() {
    let args: Vec<String> = env::args().collect();
    let expr: &str = if args.len() > 1 {
        &args[1]
    } else {
        "((sig >= 10 && sig < 15) || sig == 17) && comm != bash"
    };

    // Declare field types (e.g., for a tracepoint event)
    let schema = Schema::new()
        .with_int("sig")
        .with_str("comm")
        .with_int("flags");

    // Compile the expression (unknown fields or type mismatches error out)
    let compiled = match compile_with_schema(expr, schema) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("compile error: {} at pos {}", e.message, e.span.start);
            std::process::exit(2);
        }
    };

    // Construct a runtime context
    let mut ctx: BTreeMap<String, String> = BTreeMap::new();
    ctx.insert("sig".into(), "12".into());
    ctx.insert("comm".into(), "sh".into());
    ctx.insert("flags".into(), format!("{}", 0x30));

    // Evaluate the compiled expression against the context
    let ok = compiled.evaluate(&ctx);
    println!("expr: {}", expr);
    println!(
        "ctx: sig={}, comm={}, flags=0x{:x}",
        ctx["sig"],
        ctx["comm"],
        ctx["flags"].parse::<i64>().unwrap_or_default()
    );
    println!("match? {}", ok);
}
