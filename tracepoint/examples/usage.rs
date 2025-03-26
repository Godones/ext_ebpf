#![feature(asm_goto)]
use spin::Mutex;
use tracepoint::define_trace_point;
extern crate alloc;

define_trace_point!(Mutex, TEST,);

fn main() {
    println!("Hello, world!");
}
