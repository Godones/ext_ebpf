use std::{collections::BTreeMap, env, mem::offset_of};

use tp_lexer::{BufContext, FieldClassifier, compile_with_schema, schema};

macro_rules! get_field_type {
    ($entry_type:ty) => {
        <$entry_type>::FIELD_TYPE
    };
}

fn main() {
    let args: Vec<String> = env::args().collect();
    let expr: &str = if args.len() > 1 {
        &args[1]
    } else {
        "((sig >= 10 && sig < 15) || sig == 17) && comm == sh"
    };

    // Declare field types (e.g., for a tracepoint event)
    let schema = schema!(
        "sig" => (get_field_type!(u32), 0, 4),
        "comm" => (get_field_type!([u8; 16]), 4, 16),
        "flags" => (get_field_type!(i32), 20, 4),
    );

    println!("Schema: {:#?}", schema);

    // Compile the expression (unknown fields or type mismatches error out)
    let compiled = match compile_with_schema(expr, schema) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("compile error: {} at pos {}", e.message, e.span.start);
            std::process::exit(2);
        }
    };

    // Construct a runtime context
    let mut ctx = BTreeMap::<String, String>::new();
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

    #[repr(C)]
    struct Buf {
        sig: u32,
        comm: [u8; 16],
        flags: i32,
    }
    assert_eq!(offset_of!(Buf, sig), 0);
    assert_eq!(offset_of!(Buf, comm), 4);
    assert_eq!(offset_of!(Buf, flags), 20);

    // Test with another context
    let buf = Buf {
        sig: 17,
        comm: [b's', b'h', 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
        flags: 0x10,
    };
    let buf = unsafe {
        core::slice::from_raw_parts(&buf as *const Buf as *const u8, core::mem::size_of::<Buf>())
    };
    let buf_ctx = BufContext::new(buf, &schema);
    let ok = compiled.evaluate(&buf_ctx);
    println!(
        "buf ctx: sig={}, comm={}, flags=0x{:x}",
        u32::from_le_bytes(buf[0..4].try_into().unwrap()),
        {
            let end = buf[4..20]
                .iter()
                .position(|&b| b == 0)
                .map(|p| p + 4)
                .unwrap_or(20);
            String::from_utf8_lossy(&buf[4..end]).to_string()
        },
        i32::from_le_bytes(buf[20..24].try_into().unwrap())
    );
    println!("match? {}", ok);
}
