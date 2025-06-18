use std::{error::Error, thread::sleep};

use aya::programs::TracePoint;
use ebpf_command::command::*;
use net_aya::{eBPFCommandSend, ExtractInstruction, NetEbpfLoader};

use crate::UdpChannel;

const SERVER_ADDRESS: &str = "10.0.5.3:9970";

pub fn simple_ebpf_test() -> Result<(), Box<dyn Error>> {
    // Create a UDP socket
    // create an udp client that sends a message to the server
    let udp_socket = std::net::UdpSocket::bind("0.0.0.0:60924").unwrap();
    // nc -u 10.0.5.3 9970

    let udp_channel = UdpChannel::new(udp_socket, SERVER_ADDRESS);

    let bytes = std::fs::read("./target/bpfel-unknown-none/release/simple-ebpf").unwrap();

    let mut net_ebpf = NetEbpfLoader::new(&udp_channel).set_cpus(1).load(&bytes)?;

    let program: &mut TracePoint = net_ebpf.program_mut("mytrace").unwrap().try_into()?;

    let info = program.extract_instruction()?;
    println!("Extracted instruction info: {:?}", info);

    let prog = &info.instructions;
    let prog_name = info.name.as_deref().unwrap_or("unknown");

    // let prog = &[
    //     0xb4, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov32 r0, 0
    //     0xb4, 0x01, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, // mov32 r1, 2
    //     0x04, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // add32 r0, 1
    //     0x0c, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // add32 r0, r1
    //     0x95, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // exit and return r0
    // ];

    println!("Sending eBPF commands to server at {}", SERVER_ADDRESS);
    println!("Program size: {} bytes", prog.len());

    const TP_ID: u32 = 0;

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
        // let _ = eBPFCommand::GetTPInfo.send_command(&udp_socket, server_address)?;
        // let _ = eBPFCommand::GetTPInfo.send_command(&udp_socket, server_address)?;
        sleep(std::time::Duration::from_secs(10));
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

    println!("simple_ebpf_test completed successfully");
    Ok(())
}
