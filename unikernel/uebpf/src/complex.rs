use std::{error::Error, net::Ipv4Addr, thread::sleep};

use aya::{maps::HashMap, programs::TracePoint};
use ebpf_command::command::*;
use net_aya::{eBPFCommandSend, ExtractInstruction, NetEbpfLoader, NetHashMap};

use crate::UdpChannel;

pub fn complex_ebpf_test(server_addr: &str, server_port: u16) -> Result<(), Box<dyn Error>> {
    // Create a UDP socket
    // create an udp client that sends a message to the server
    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:60924").unwrap();
    // nc -u 10.0.5.3 9970
    let server_address = format!("{server_addr}:{server_port}");
    println!("Sending eBPF commands to server at {}", server_address);

    let udp_channel = UdpChannel::new(udp_socket, &server_address);

    let bytes = std::fs::read("./target/bpfel-unknown-none/release/complex-ebpf").unwrap();

    let mut net_ebpf = NetEbpfLoader::new(&udp_channel).set_cpus(1).load(&bytes)?;

    let program: &mut TracePoint = net_ebpf.program_mut("count_ips").unwrap().try_into()?;

    let info = program.extract_instruction()?;
    println!("Extracted instruction info: {:?}", info);

    let prog = &info.instructions;
    let prog_name = info.name.as_deref().unwrap_or("unknown");

    println!("Program size: {} bytes", prog.len());

    const TP_ID: u32 = 1;

    // First, we need to load the program into the eBPF server
    let load_program = LoadProgram::new(
        prog_name, // program name
        0x01,      // program type
        prog,      // program data
    );
    let load_command = eBPFCommand::LoadProgram(load_program);
    load_command.send_command(&udp_channel)?;

    // Optionally, we can retrieve the tracepoint info
    let tp_info = eBPFCommand::GetTPInfo.send_command(&udp_channel)?;
    println!("Tracepoint info:\n{}", tp_info);

    // Second, we can attach the program to a tracepoint
    let attach_program = AttachProgram::new(
        prog_name, // program name
        TP_ID,
    );
    let attach_program = eBPFCommand::AttachProgram(attach_program);
    // Server should respond with a bind ID
    let bind_id = attach_program.send_command(&udp_channel)?;
    let bind_id = bind_id
        .parse::<u64>()
        .map_err(|_| "Failed to parse bind ID")?;
    println!("Program attached with bind ID: {}", bind_id);

    // Third, Now we can enable  the tracepoint
    let enable_tp = eBPFCommand::EnableTP(TP_ID);
    enable_tp.send_command(&udp_channel)?;
    {
        // let _ = eBPFCommand::GetTPInfo.send_command(&udp_channel)?;
        // sleep(std::time::Duration::from_secs(10));
        rand_connect(format!("{server_addr}:9999").as_str());
    }

    let map: HashMap<_, u64, u64> = HashMap::try_from(net_ebpf.map_mut("IP_COUNTERS").unwrap())?;

    for entry in map.net_iter(&udp_channel) {
        let (key, value) = entry?;
        let src_addr = (key >> 16) as u32;
        let port = (key & 0xFFFF) as u16;
        let ip = Ipv4Addr::from_octets(src_addr.to_be_bytes());
        println!("IP: {}:{} - Count: {}", ip, port, value);
    }

    // Fourth, we can disable the tracepoint, which is optional
    // This is useful if we want to stop receiving events from the tracepoint
    let disable_tp = eBPFCommand::DisableTP(TP_ID);
    disable_tp.send_command(&udp_channel)?;

    // Five, we can detach the program from the tracepoint
    let detach_program = DetachProgram::new(bind_id);
    let detach_command = eBPFCommand::DetachProgram(detach_program);
    detach_command.send_command(&udp_channel)?;
    println!("Program detached successfully");

    // Finally, we can remove the program from the eBPF server
    let remove_program = eBPFCommand::RemoveProgram(prog_name);
    remove_program.send_command(&udp_channel)?;

    println!("complex_ebpf_test completed successfully");
    Ok(())
}

fn rand_connect(qemu_test_address: &str) {
    const TEST_ITER: usize = 10;
    for _ in 0..TEST_ITER {
        let port = rand::random::<u16>();
        // port: 55555-65535
        let port = port % (65535 - 55555) + 55555;
        let udp_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap();
        udp_socket
            .send_to(b"Hello, server!", qemu_test_address)
            .unwrap();
        println!(" {} Sent message to {}", port, qemu_test_address);
        sleep(std::time::Duration::from_secs(1));
    }
}
