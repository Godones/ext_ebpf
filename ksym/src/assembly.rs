use alloc::{string::ToString, vec::Vec};
use core::ffi::CStr;

use crate::KSYM;

#[linkage = "weak"]
#[unsafe(no_mangle)]
fn ksyms_address() {}
#[linkage = "weak"]
#[unsafe(no_mangle)]
fn ksyms_num() {}
#[linkage = "weak"]
#[unsafe(no_mangle)]
fn ksyms_names_index() {}
#[linkage = "weak"]
#[unsafe(no_mangle)]
fn ksyms_names() {}

/// Initialize the kernel symbol table from the embedded symbols.
/// After calling this function, kernel can reuse the memory of the
/// original symbol table.
pub fn init_kernel_symbols() {
    let mut symbol_table = Vec::new();

    let sym_names = ksyms_names as *const u8;
    let sym_num = ksyms_num as usize;
    let kallsyms_address_list =
        unsafe { core::slice::from_raw_parts(ksyms_address as *const u64, sym_num) };
    let sym_names_index = ksyms_names_index as *const u64;
    let sym_names_index = unsafe { core::slice::from_raw_parts(sym_names_index, sym_num) };
    for i in 0..sym_num {
        let sym_name_cstr =
            unsafe { CStr::from_ptr(sym_names.add(sym_names_index[i] as usize) as _) };
        let sym_name = sym_name_cstr.to_str().unwrap_or("unknown").to_string();
        symbol_table.push((sym_name, kallsyms_address_list[i] as usize));
    }

    KSYM.init_once(symbol_table);
}
