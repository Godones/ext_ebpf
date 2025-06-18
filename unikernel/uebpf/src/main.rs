#![feature(ip_from)]
use std::{error::Error, net::UdpSocket};

use net_aya::NetChannel;

mod complex;
mod simple;

#[derive(Debug)]
pub struct UdpChannel {
    socket: UdpSocket,
    server_address: String,
}

impl UdpChannel {
    pub fn new(socket: UdpSocket, server_address: &str) -> Self {
        UdpChannel {
            socket,
            server_address: server_address.to_string(),
        }
    }
}

impl NetChannel for UdpChannel {
    fn recv_response(&self, buf: &mut [u8]) -> Result<usize, &'static str> {
        self.socket
            .recv(buf)
            .map_err(|_| "Failed to receive response")
    }
    fn send_command(&self, command: &[u8]) -> Result<(), &'static str> {
        self.socket
            .send_to(command, &self.server_address)
            .map_err(|_| "Failed to send command")?;
        Ok(())
    }
}

fn main() -> Result<(), Box<dyn Error>> {
    env_logger::try_init_from_env(env_logger::Env::default().default_filter_or("debug"))?;
    simple::simple_ebpf_test()?;
    complex::complex_ebpf_test()?;
    Ok(())
}
