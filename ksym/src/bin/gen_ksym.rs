use std::str;

use rustc_demangle::demangle;

#[derive(Debug, Clone)]
struct KernelSymbolEntry {
    vaddr: u64,
    symbol: String,
    symbol_length: usize,
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
    let symbol_length = symbol.len() + 1; // +1 for null terminator
    Some(KernelSymbolEntry {
        vaddr,
        symbol,
        symbol_length,
    })
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
    println!(".section .rodata\n");
    println!(".global ksyms_address");
    println!(".align 8\n");
    println!("ksyms_address:");

    let mut last_vaddr = 0;
    let mut total_syms_to_write = 0;

    for entry in symbol_table {
        if entry.vaddr == last_vaddr {
            continue;
        }
        println!("\t.quad\t{:#x}", entry.vaddr);
        total_syms_to_write += 1;
        last_vaddr = entry.vaddr;
    }

    println!("\n.global ksyms_num");
    println!(".align 8");
    println!("ksyms_num:");
    println!("\t.quad\t{}", total_syms_to_write);

    println!("\n.global ksyms_names_index");
    println!(".align 8");
    println!("ksyms_names_index:");

    let mut position = 0;
    last_vaddr = 0;

    for entry in symbol_table {
        if entry.vaddr == last_vaddr {
            continue;
        }

        println!("\t.quad\t{}", position);
        position += entry.symbol_length;
        last_vaddr = entry.vaddr;
    }

    println!("\n.global ksyms_names");
    println!(".align 8");
    println!("ksyms_names:");

    last_vaddr = 0;

    for entry in symbol_table {
        if entry.vaddr == last_vaddr {
            continue;
        }

        println!("\t.asciz\t\"{}\"", entry.symbol);
        last_vaddr = entry.vaddr;
    }
}

fn main() {
    let symbol_table = read_map();
    generate_result(&symbol_table);
}
