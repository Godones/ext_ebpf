use std::{error::Error, net::Ipv4Addr, thread::sleep};

use aya::{maps::HashMap, programs::TracePoint};
use ebpf_command::command::*;
use net_aya::{eBPFCommandSend, ExtractInstruction, NetEbpfLoader, NetHashMap};

use crate::UdpChannel;

const SERVER_ADDRESS: &str = "10.0.5.3:9970";

pub fn complex_ebpf_test() -> Result<(), Box<dyn Error>> {
    // Create a UDP socket
    // create an udp client that sends a message to the server
    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:60924").unwrap();
    // nc -u 10.0.5.3 9970

    let udp_channel = UdpChannel::new(udp_socket, SERVER_ADDRESS);

    let bytes = std::fs::read("./target/bpfel-unknown-none/release/complex-ebpf").unwrap();

    let mut net_ebpf = NetEbpfLoader::new(&udp_channel).set_cpus(1).load(&bytes)?;

    let program: &mut TracePoint = net_ebpf.program_mut("count_ips").unwrap().try_into()?;

    let info = program.extract_instruction()?;
    println!("Extracted instruction info: {:?}", info);

    let prog = &info.instructions;
    let prog_name = info.name.as_deref().unwrap_or("unknown");

    println!("Sending eBPF commands to server at {}", SERVER_ADDRESS);
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
        rand_connect();
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

fn rand_connect() {
    const TEST_ITER: usize = 10;
    for _ in 0..TEST_ITER {
        let port = rand::random::<u16>();
        // port: 5555-65535
        let port = port % (65535 - 5555) + 5555;
        let udp_socket = std::net::UdpSocket::bind(format!("0.0.0.0:{}", port)).unwrap();
        udp_socket
            .send_to(b"Hello, server!", SERVER_ADDRESS)
            .unwrap();
        println!(" {} Sent message to {}", port, SERVER_ADDRESS);
        sleep(std::time::Duration::from_secs(1));
    }
}
