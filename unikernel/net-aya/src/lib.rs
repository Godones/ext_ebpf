mod loader;
mod map;
use std::fmt::Debug;

use ebpf_command::command::{eBPFCommand, eBPFCommandParser};
pub use loader::{ExtractInstruction, NetEbpfLoader};
pub use map::*;
pub trait NetChannel: Debug {
    fn send_command(&self, command: &[u8]) -> Result<(), &'static str>;
    fn recv_response(&self, buf: &mut [u8]) -> Result<usize, &'static str>;
}

#[allow(non_camel_case_types)]
pub trait eBPFCommandSend {
    /// Sends the command to the eBPF server.
    fn send_command(self, channel: &dyn NetChannel) -> Result<String, String>;
}

impl eBPFCommandSend for eBPFCommand<'_> {
    fn send_command(self, channel: &dyn NetChannel) -> Result<String, String> {
        let command = eBPFCommandParser::to_packet(self);
        // send the command to the server
        channel
            .send_command(&command)
            .map_err(|e| format!("Failed to send command: {}", e))?;
        // wait for a response from the server
        let mut buf = [0u8; 4096];
        let len = channel
            .recv_response(&mut buf)
            .map_err(|e| format!("Failed to receive response: {}", e))?;
        let response = &buf[..len];
        let response = unsafe { core::str::from_utf8_unchecked(response) };
        if response.starts_with("OK:") {
            Ok(response[3..].to_string())
        } else if response.starts_with("ERROR:") {
            Err(response[6..].to_string())
        } else {
            Err(format!("Server responded with error: {}", response))
        }
    }
}
