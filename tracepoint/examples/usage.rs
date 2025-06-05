#![feature(asm_goto)]

use spin::Mutex;
use tracepoint::{
    global_init_events, TraceCmdLineCache, TraceEntryParser, TracePipeOps, TracePointMap,
};
extern crate alloc;

mod tracepoint_test {
    use std::{ops::Deref, sync::Arc, time};

    use spin::Mutex;
    use tracepoint::{define_event_trace, KernelTraceOps, TraceCmdLineCache};

    pub static TRACE_RAW_PIPE: Mutex<tracepoint::TracePipeRaw> =
        Mutex::new(tracepoint::TracePipeRaw::new(1024));

    pub static TRACE_CMDLINE_CACHE: Mutex<TraceCmdLineCache> =
        Mutex::new(tracepoint::TraceCmdLineCache::new(128));
    pub struct Kops;

    impl KernelTraceOps for Kops {
        fn cpu_id() -> u32 {
            0
        }

        fn current_pid() -> u32 {
            1
        }
        fn time_now() -> u64 {
            time::SystemTime::now()
                .duration_since(time::UNIX_EPOCH)
                .unwrap()
                .as_nanos() as u64
        }

        fn trace_pipe_push_raw_record(buf: &[u8]) {
            let mut pipe = TRACE_RAW_PIPE.lock();
            pipe.push_event(buf.to_vec());
        }

        fn trace_cmdline_push(pid: u32) {
            let mut cache = TRACE_CMDLINE_CACHE.lock();
            cache.insert(pid, "test_process".to_string());
        }
    }

    #[repr(C)]
    #[derive(Debug)]
    struct TestS {
        a: u32,
        b: Box<Arc<u32>>,
    }

    define_event_trace!(
        TEST,
        TP_lock(Mutex<()>),
        TP_kops(Kops),
        TP_system(tracepoint_test),
        TP_PROTO(a: u32, b: &TestS),
        TP_STRUCT__entry{
            a: u32,
            pad:[u8;5],
            b: u32
        },
        TP_fast_assign{
            a: a,
            pad: [0; 5],
            b: *b.b.deref().deref()
        },
        TP_ident(__entry),
        TP_printk(
            {
                let arg1 = __entry.a;
                let arg2 = __entry.b;
                format!("Hello from tracepoint! a={:?}, b={}", arg1, arg2)
            }
        )
    );

    define_event_trace!(
        TEST2,
        TP_lock(Mutex<()>),
        TP_kops(Kops),
        TP_system(tracepoint_test),
        TP_PROTO(a: u32, b: u32),
        TP_STRUCT__entry{
            a: u32,
            b: u32
        },
        TP_fast_assign{
            a:a,
            b:b
        },
        TP_ident(__entry),
        TP_printk(format_args!("Hello from tracepoint! a={}, b={}", __entry.a, __entry.b))
    );

    pub fn test_trace(a: u32, b: u32) {
        let x = TestS {
            a,
            b: Box::new(Arc::new(b)),
        };
        trace_TEST(a, &x);
        trace_TEST2(a, b);
        println!("Tracepoint TEST called with a={}, b={}", a, b);
    }
}

fn print_trace_records(
    tracepoint_map: &TracePointMap<Mutex<()>>,
    trace_cmdline_cache: &TraceCmdLineCache,
) {
    let mut snapshot = tracepoint_test::TRACE_RAW_PIPE.lock().snapshot();
    print!("{}", snapshot.default_fmt_str());
    loop {
        let mut flag = false;
        if let Some(event) = snapshot.peek() {
            let trace_str = TraceEntryParser::parse::<tracepoint_test::Kops, _>(
                tracepoint_map,
                trace_cmdline_cache,
                event,
            );
            print!("{}", trace_str);
            flag = true;
        }
        if flag {
            snapshot.pop();
        } else {
            break;
        }
    }
}

fn main() {
    env_logger::try_init_from_env(env_logger::Env::default().default_filter_or("info"))
        .expect("Failed to initialize logger");

    // First, we need to initialize the static keys.
    static_keys::global_init();
    // Then, we need to initialize the tracepoint and events.
    // This will create a new events manager and register the tracepoint.
    // The events manager will be used to manage the tracepoints and events.
    let manager = global_init_events::<Mutex<()>>().unwrap();
    let tracepoint_map = manager.tracepoint_map();

    println!("---Before enabling tracepoints---");
    tracepoint_test::test_trace(1, 2);
    tracepoint_test::test_trace(3, 4);
    print_trace_records(
        &tracepoint_map,
        &tracepoint_test::TRACE_CMDLINE_CACHE.lock(),
    );

    println!();
    for sbs in manager.subsystem_names() {
        let subsystem = manager.get_subsystem(&sbs).unwrap();
        let events = subsystem.event_names();
        for event in events {
            let trace_point_info = subsystem.get_event(&event).unwrap();
            trace_point_info.enable_file().write('1');
            println!("Enabled tracepoint: {}.{}", sbs, event);
        }
    }

    println!("---After enabling tracepoints---");
    tracepoint_test::test_trace(1, 2);
    tracepoint_test::test_trace(3, 4);
    print_trace_records(
        &tracepoint_map,
        &tracepoint_test::TRACE_CMDLINE_CACHE.lock(),
    );

    for tracepoint in tracepoint_map.values() {
        println!("{}", tracepoint.print_fmt());
    }
}
