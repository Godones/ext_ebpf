#![no_std]
#![feature(linkage)]

#[cfg(feature = "assembly")]
mod assembly;
use alloc::{
    string::{String, ToString},
    vec::Vec,
};

#[cfg(feature = "assembly")]
pub use assembly::init_kernel_symbols;
use lazyinit::LazyInit;
extern crate alloc;

pub static KSYM: LazyInit<Vec<(String, usize)>> = LazyInit::new();

/// Initialize the kernel symbol table from a string in the format of
/// /proc/kallsyms
#[cfg(not(feature = "assembly"))]
pub fn init_kernel_symbols(ksym: &str) {
    let mut symbol_table = Vec::new();
    for line in ksym.lines() {
        let mut parts = line.split_whitespace();
        let vaddr = usize::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
        let symbol_type = parts.next().and_then(|s| s.chars().next()).unwrap_or(' ');
        let symbol = parts.collect::<Vec<_>>().join(" ");
        if symbol_type == 'T' || symbol_type == 't' {
            symbol_table.push((symbol, vaddr));
        }
    }

    KSYM.init_once(symbol_table);
}

/// Return the function information according to the pc address.
/// If not found, return None.
pub fn lookup_kallsyms(addr: usize) -> Option<(String, usize)> {
    let mut index = usize::MAX;
    let ksym = KSYM.get().unwrap();
    let sym_num = ksym.len();
    for i in 0..sym_num - 1 {
        if addr > ksym[i].1 && addr <= ksym[i + 1].1 {
            index = i;
            break;
        }
    }
    if index < sym_num {
        let sym_name = ksym[index].0.as_str();
        Some((sym_name.to_string(), ksym[index].1));
    }
    None
}

/// Get the address of the symbol.
/// If not found, return None.
pub fn addr_from_symbol(symbol: &str) -> Option<usize> {
    let ksym = KSYM.get().unwrap();
    for (name, addr) in ksym {
        if name == symbol {
            return Some(*addr);
        }
    }
    None
}
