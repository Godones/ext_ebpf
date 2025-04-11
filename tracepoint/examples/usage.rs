#![feature(asm_goto)]
use spin::Mutex;
use tracepoint::global_init_events;

extern crate alloc;
static TRACE_PIPE: Mutex<tracepoint::TracePipe> = Mutex::new(tracepoint::TracePipe::new(1024));
mod tracepoint_test {
    use std::time;

    use spin::Mutex;
    use tracepoint::{define_event_trace, define_trace_point, KernelTraceOps};

    use crate::TRACE_PIPE;
    // define_trace_point!(Mutex, TEST);
    struct Kops;

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
        fn trace_pipe_push_record(format: String) {
            let mut pipe = TRACE_PIPE.lock();
            pipe.push_record(format);
        }
    }
    define_event_trace!(
        Mutex,
        Kops,
        TEST,
        (a: u32, b: u32),
        format_args!("Hello from tracepoint! a={}, b={}", a, b)
    );

    define_event_trace!(
        Mutex,
        Kops,
        TEST2,
        (a: u32, b: u32),
        format_args!("Hello from tracepoint2! a={}, b={}", a, b)
    );

    pub fn test_trace(a: u32, b: u32) {
        trace_TEST(a, b);
        trace_TEST2(a, b);
        println!("Tracepoint TEST called with a={}, b={}", a, b);
    }
}

fn print_trace_records() {
    let mut buf = [0u8; 1024];
    let pipe = TRACE_PIPE.lock();
    let size = pipe.read_at(&mut buf, 0).unwrap();
    if size == 0 {
        println!("No trace records found.");
        return;
    }
    let records = String::from_utf8_lossy(&buf[..size]);
    println!("Trace records:\n{}", records);
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

    println!("---Before enabling tracepoints---");
    tracepoint_test::test_trace(1, 2);
    tracepoint_test::test_trace(3, 4);
    print_trace_records();

    println!();
    for sbs in manager.subsystem_names() {
        let subsystem = manager.get_subsystem(&sbs).unwrap();
        let events = subsystem.event_names();
        for event in events {
            let trace_point = subsystem.get_event(&event).unwrap();
            trace_point.enable_file().write(true);
            println!("Enabled tracepoint: {}.{}", sbs, event);
        }
    }
    println!();
    println!("---After enabling tracepoints---");
    tracepoint_test::test_trace(1, 2);
    tracepoint_test::test_trace(3, 4);
    print_trace_records();
}
