use alloc::vec::Vec;
use core::fmt::Debug;
pub struct LoadProgram<'a> {
    pub name: &'a str,
    pub program_type: u32,
    pub program_data: &'a [u8],
}

impl Debug for LoadProgram<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LoadProgram")
            .field("name", &self.name)
            .field("program_type", &self.program_type)
            .field("program_data_length", &self.program_data.len())
            .finish()
    }
}

impl<'a> LoadProgram<'a> {
    pub fn new(name: &'a str, program_type: u32, program_data: &'a [u8]) -> Self {
        LoadProgram {
            name,
            program_type,
            program_data,
        }
    }

    pub fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.len() < 4 {
            return Err("Invalid packet length");
        }
        let program_type = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let name = core::ffi::CStr::from_bytes_until_nul(&packet[4..])
            .map_err(|_| "Invalid name")?
            .to_str()
            .map_err(|_| "Invalid UTF-8 in name")?;
        let name_length = name.len() + 1; // +1 for the null terminator
        let program_data = &packet[4 + name_length..]; // Remaining bytes are the program data
        Ok(LoadProgram {
            name,
            program_type,
            program_data,
        })
    }

    pub fn to_packet(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(4 + self.program_data.len() + self.name.len() + 1);
        packet.extend_from_slice(&self.program_type.to_ne_bytes());
        packet.extend_from_slice(self.name.as_bytes());
        packet.push(0); // Null terminator for the name
                        // Append the program data
        packet.extend_from_slice(&self.program_data);
        packet
    }
}
