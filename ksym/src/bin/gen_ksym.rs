use std::str;

use rustc_demangle::demangle;

#[derive(Debug, Clone)]
struct KernelSymbolEntry {
    vaddr: u64,
    symbol: String,
}

fn read_symbol(line: &str) -> Option<KernelSymbolEntry> {
    if line.len() > 512 {
        return None;
    } // skip line with length >= 512
    let mut parts = line.split_whitespace();
    let vaddr = u64::from_str_radix(parts.next()?, 16).ok()?;
    let symbol_type = parts.next()?.chars().next()?;
    let mut symbol = parts.collect::<Vec<_>>().join(" ");
    if symbol_type != 'T' && symbol_type != 't' {
        return None;
    } // local symbol or global symbol in text section
    if symbol.contains("$x") {
        return None;
    } // skip $x symbol
    if symbol.starts_with("_ZN") {
        symbol = format!("{:#}", demangle(&symbol));
    } else {
        symbol = format!("{}", symbol);
    }
    Some(KernelSymbolEntry { vaddr, symbol })
}

fn read_map() -> Vec<KernelSymbolEntry> {
    let mut symbol_table = Vec::new();
    let mut line = String::new();
    loop {
        let size = std::io::stdin().read_line(&mut line).unwrap();
        if size == 0 {
            break;
        }
        line = line.trim().to_string();
        if let Some(entry) = read_symbol(&line) {
            symbol_table.push(entry);
        }
        line.clear();
    }
    symbol_table
}

fn generate_result(symbol_table: &[KernelSymbolEntry]) {
    // Generate ksyms_address
    // like /proc/kallsyms
    for entry in symbol_table {
        print!("{:016x} T {}\n", entry.vaddr, entry.symbol);
    }
}

fn main() {
    let symbol_table = read_map();
    generate_result(&symbol_table);
}
