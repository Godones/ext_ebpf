#![no_std]
#![no_main]

use aya_ebpf::{macros::classifier, programs::TcContext};
#[inline(never)]
#[no_mangle]
fn sub32(a: i32, b: i32) -> i32 {
    return a - b;
}

#[no_mangle]
#[inline(never)]
fn add32(a: i32, b: i32) -> i32 {
    return a + b;
}

// #[no_mangle]
#[classifier]
pub fn hello_world_filter(__ctx: TcContext) -> i32 {
    // let str = b"hello world!\0";
    let res = sub32(16, 1);
    // let local_var = local_var();
    return add32(1, res);
}

#[cfg(target_os = "none")]
#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
