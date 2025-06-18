#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    macros::{map, tracepoint},
    maps::HashMap,
    programs::TracePointContext,
};
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{IpProto, Ipv4Hdr},
    udp::UdpHdr,
};

#[map(name = "IP_COUNTERS")]
static IP_COUNTERS: HashMap<u64, u64> = HashMap::with_max_entries(1024, 0);

#[tracepoint]
pub fn count_ips(ctx: TracePointContext) -> u32 {
    match try_count_ips(&ctx) {
        Ok(_) => 0,
        Err(_) => -1 as _,
    }
}

fn try_count_ips(ctx: &TracePointContext) -> Result<(), ()> {
    const PACKET_LEN_OFFSET: usize = 16;
    const PACKET_BUF_PTR_OFFSET: usize = 8;

    let packet_len = unsafe { ctx.read_at::<u32>(PACKET_LEN_OFFSET) }.map_err(|_| ())?;
    if (packet_len as usize) < mem::size_of::<EthHdr>() + mem::size_of::<Ipv4Hdr>() {
        return Err(());
    }
    let buf_ptr = unsafe { ctx.read_at::<u64>(PACKET_BUF_PTR_OFFSET) }.map_err(|_| ())?;

    let data = buf_ptr;
    let data_end = buf_ptr + packet_len as u64;
    let mut ptr = data as *const u8;

    // read Ethernet header
    if (ptr as usize) + mem::size_of::<EthHdr>() > data_end as usize {
        return Err(());
    }
    let eth = unsafe { &*(ptr as *const EthHdr) };
    ptr = unsafe { ptr.add(mem::size_of::<EthHdr>()) };

    let eth_type = eth.ether_type;
    if eth_type != EtherType::Ipv4 {
        return Err(());
    }

    // read IPv4 header
    if (ptr as usize) + mem::size_of::<Ipv4Hdr>() > data_end as usize {
        return Err(());
    }
    let ip = unsafe { &*(ptr as *const Ipv4Hdr) };
    let src = u32::from_be_bytes(ip.src_addr);

    let ihl = ip.ihl();
    let proto = ip.proto;
    ptr = unsafe { ptr.add(ihl as usize * 4) };

    let src_port = match proto {
        IpProto::Udp => {
            if unsafe { ptr.add(mem::size_of::<UdpHdr>()) } > data_end as *const u8 {
                return Err(());
            }
            let udp = unsafe { &*(ptr as *const UdpHdr) };
            udp.source()
        }
        IpProto::Tcp => {
            if unsafe { ptr.add(mem::size_of::<UdpHdr>()) } > data_end as *const u8 {
                return Err(());
            }
            let udp = unsafe { &*(ptr as *const UdpHdr) };
            udp.source()
        }
        _ => u16::MAX,
    };

    let src = u64::from(src) << 16 | u64::from(src_port);
    unsafe {
        let count = IP_COUNTERS.get(&src).copied().unwrap_or(0);
        IP_COUNTERS.insert(&src, &(count + 1), 0).map_err(|_| ())?;
    }

    Ok(())
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}
