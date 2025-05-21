#![no_std]
#![feature(linkage)]

use alloc::format;
use alloc::string::String;
use core::ffi::CStr;
extern crate alloc;

#[linkage = "weak"]
#[no_mangle]
fn ksyms_address() {}
#[linkage = "weak"]
#[no_mangle]
fn ksyms_num() {}
#[linkage = "weak"]
#[no_mangle]
fn ksyms_names_index() {}
#[linkage = "weak"]
#[no_mangle]
fn ksyms_names() {}

/// Return the func infomation according to the pc address and
pub unsafe fn lookup_kallsyms(addr: u64, level: i32) -> String {
    let sym_names = ksyms_names as *const u8;
    let sym_num = ksyms_num as usize;
    let kallsyms_address_list = core::slice::from_raw_parts(ksyms_address as *const u64, sym_num);
    let sym_names_index = ksyms_names_index as *const u64;
    let sym_names_index = core::slice::from_raw_parts(sym_names_index, sym_num);
    let mut index = usize::MAX;
    for i in 0..sym_num - 1 {
        if addr > kallsyms_address_list[i] && addr <= kallsyms_address_list[i + 1] {
            index = i;
            break;
        }
    }
    if index < sym_num {
        let sym_name = CStr::from_ptr(sym_names.add(sym_names_index[index] as usize) as _)
            .to_str()
            .unwrap();
        format!(
            "[{}] function:{}() \t(+) {:04} address:{:#018x}",
            level,
            sym_name,
            addr - kallsyms_address_list[index],
            addr
        )
    } else {
        format!(
            "[{}] function:unknown \t(+) {:04} address:{:#018x}",
            level,
            addr - kallsyms_address_list[sym_num - 1],
            addr
        )
    }
}

/// Get the address of the symbol
pub unsafe fn addr_from_symbol(symbol: &str) -> Option<u64> {
    let sym_num = ksyms_num as usize;
    let sym_names = ksyms_names as *const u8;
    let kallsyms_address_list = core::slice::from_raw_parts(ksyms_address as *const u64, sym_num);
    let sym_names_index = ksyms_names_index as *const u64;
    let sym_names_index_list = core::slice::from_raw_parts(sym_names_index, sym_num);
    for i in 0..sym_num {
        let sym_name_cstr = CStr::from_ptr(sym_names.add(sym_names_index_list[i] as usize) as _);
        let sym_name = sym_name_cstr.to_str().unwrap();
        if sym_name == symbol {
            return Some(kallsyms_address_list[i]);
        }
    }
    None
}
