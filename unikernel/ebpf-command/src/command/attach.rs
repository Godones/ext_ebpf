use alloc::vec::Vec;

#[derive(Debug)]
pub struct AttachProgram<'a> {
    // tracepoint to attach to
    pub tracepoint_id: u32,
    // program name
    pub name: &'a str,
}

impl<'a> AttachProgram<'a> {
    pub fn new(name: &'a str, tracepoint_id: u32) -> Self {
        AttachProgram {
            name,
            tracepoint_id,
        }
    }

    pub fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.is_empty() {
            return Err("Invalid packet");
        }
        let tracepoint_id = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let name = core::ffi::CStr::from_bytes_until_nul(&packet[4..])
            .map_err(|_| "Invalid name")?
            .to_str()
            .map_err(|_| "Invalid UTF-8 in name")?;

        Ok(AttachProgram {
            name,
            tracepoint_id,
        })
    }

    pub fn to_packet(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(self.name.len() + 1 + 4); // 4 bytes for tracepoint_id
        packet.extend_from_slice(&self.tracepoint_id.to_ne_bytes());
        packet.extend_from_slice(self.name.as_bytes());
        packet.push(0); // Null terminator for the name
        packet
    }
}

// DetachProgram is similar to AttachProgram
#[derive(Debug)]
pub struct DetachProgram(pub u64);

impl DetachProgram {
    pub fn new(bind_id: u64) -> Self {
        DetachProgram(bind_id)
    }

    pub fn parse(packet: &[u8]) -> Result<Self, &'static str> {
        let bind_id = u64::from_ne_bytes(
            packet[0..8]
                .try_into()
                .map_err(|_| "Invalid packet length")?,
        );
        Ok(DetachProgram(bind_id))
    }

    pub fn to_packet(self) -> Vec<u8> {
        self.0.to_ne_bytes().to_vec()
    }
}
