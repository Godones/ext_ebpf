#![no_std]
#![no_main]

use core::{
    ffi::{c_char, c_int, CStr},
    mem::transmute,
};
#[inline(never)]
#[no_mangle]
fn bpf_trace_printk(msg: &CStr) -> i32 {
    // Unfortunately, at the moment this does not support
    // variadic printk
    let printk: fn(*const c_char, c_int) -> c_int = unsafe { transmute(6 as i64) };

    // return 0;
    return printk(msg.as_ptr(), msg.to_bytes().len() as i32);
}

#[inline(never)]
#[no_mangle]
fn bpf_trace_printk2(msg: &CStr) -> i32 {
    // Unfortunately, at the moment this does not support
    // variadic printk
    let printk: fn(*const c_char, c_int) -> c_int = unsafe { transmute(6 as i64) };

    // return 0;
    return printk(msg.as_ptr(), msg.to_bytes().len() as i32);
}

#[no_mangle]
#[inline(never)]
fn local_var() -> u32 {
    let mut local_buf: [u8; 128] = [0; 128];
    let rand: fn(c_int) -> c_int = unsafe { transmute(6 as i64) };
    for i in 0..128 {
        local_buf[i] = rand(0) as u8;
    }
    let mut local_var = 0u32;
    for i in 0..4 {
        local_var |= (local_buf[i] as u32) << (i * 8);
    }
    return local_var;
}

#[link_section = "license"]
/// str/String in rust are not null terminated, we have to put one in manually
pub static LICENSE: &[u8] = b"GPL\0";

#[no_mangle]
#[link_section = "hello_world"]
// LLVM has a bug where the section name cannot be same as function name
// LLVM ERROR: 'hello_world' label emitted multiple times to assembly file
// <https://patchwork.ozlabs.org/patch/808209/>
pub extern "C" fn hello_world_filter(_ctx: *mut u8) -> i32 {
    let str = b"hello world!\0";
    bpf_trace_printk(CStr::from_bytes_with_nul(str).unwrap());
    bpf_trace_printk2(CStr::from_bytes_with_nul(str).unwrap());
    let local_var = local_var();
    return local_var as i32;
}

#[panic_handler]
fn panic_handler(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
