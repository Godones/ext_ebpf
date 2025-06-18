use alloc::vec::Vec;

#[derive(Debug)]
pub struct CreateMap {
    pub map_type: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub map_flags: u32,
    pub map_name: [u8; 16],
}

impl CreateMap {
    pub fn parse(packet: &[u8]) -> Result<Self, &'static str> {
        if packet.len() < 16 + 20 {
            return Err("Invalid packet length");
        }
        let map_type = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let key_size = u32::from_ne_bytes(packet[4..8].try_into().unwrap());
        let value_size = u32::from_ne_bytes(packet[8..12].try_into().unwrap());
        let max_entries = u32::from_ne_bytes(packet[12..16].try_into().unwrap());
        let map_flags = u32::from_ne_bytes(packet[16..20].try_into().unwrap());
        let map_name = packet[20..36]
            .try_into()
            .map_err(|_| "Invalid map name length")?;
        Ok(CreateMap {
            map_type,
            key_size,
            value_size,
            max_entries,
            map_flags,
            map_name,
        })
    }

    pub fn to_packet(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(16 + 20);
        packet.extend_from_slice(&self.map_type.to_ne_bytes());
        packet.extend_from_slice(&self.key_size.to_ne_bytes());
        packet.extend_from_slice(&self.value_size.to_ne_bytes());
        packet.extend_from_slice(&self.max_entries.to_ne_bytes());
        packet.extend_from_slice(&self.map_flags.to_ne_bytes());
        packet.extend_from_slice(&self.map_name);
        packet
    }
}

#[derive(Debug)]
pub struct UpdateMap<'a> {
    pub map_fd: u32,
    pub flags: u64,
    pub key: &'a [u8],
    pub value: &'a [u8],
}

impl<'a> UpdateMap<'a> {
    pub fn new(map_fd: u32, flags: u64, key: &'a [u8], value: &'a [u8]) -> Self {
        UpdateMap {
            map_fd,
            flags,
            key,
            value,
        }
    }

    pub fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.len() < 16 {
            return Err("Invalid packet length");
        }
        let map_fd = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let flags = u64::from_ne_bytes(packet[4..12].try_into().unwrap());
        let key_len = u32::from_ne_bytes(packet[12..16].try_into().unwrap()) as usize;
        if packet.len() < 16 + key_len {
            return Err("Invalid packet length for key");
        }
        let key = &packet[16..16 + key_len];
        let value = &packet[16 + key_len..];
        Ok(UpdateMap {
            map_fd,
            flags,
            key,
            value,
        })
    }

    pub fn to_packet(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(16 + self.key.len() + self.value.len());
        packet.extend_from_slice(&self.map_fd.to_ne_bytes());
        packet.extend_from_slice(&self.flags.to_ne_bytes());
        packet.extend_from_slice(&(self.key.len() as u32).to_ne_bytes());
        packet.extend_from_slice(self.key);
        packet.extend_from_slice(self.value);
        packet
    }
}

#[derive(Debug)]
pub struct MapGetNextKey<'a> {
    pub map_fd: u32,
    pub key: Option<&'a [u8]>,
}

impl<'a> MapGetNextKey<'a> {
    pub fn new(map_fd: u32, key: Option<&'a [u8]>) -> Self {
        MapGetNextKey { map_fd, key }
    }

    pub fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.len() < 4 {
            return Err("Invalid packet length");
        }
        let map_fd = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let key = if packet.len() > 4 {
            Some(&packet[4..])
        } else {
            None
        };
        Ok(MapGetNextKey { map_fd, key })
    }

    pub fn to_packet(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(4 + self.key.map_or(0, |k| k.len()));
        packet.extend_from_slice(&self.map_fd.to_ne_bytes());
        if let Some(key) = self.key {
            packet.extend_from_slice(key);
        }
        packet
    }
}

#[derive(Debug)]
pub struct LookupMap<'a> {
    pub map_fd: u32,
    pub key: &'a [u8],
    pub flags: u64,
}

impl<'a> LookupMap<'a> {
    pub fn new(map_fd: u32, key: &'a [u8], flags: u64) -> Self {
        LookupMap { map_fd, key, flags }
    }

    pub fn parse(packet: &'a [u8]) -> Result<Self, &'static str> {
        if packet.len() < 16 {
            return Err("Invalid packet length");
        }
        let map_fd = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let flags = u64::from_ne_bytes(packet[4..12].try_into().unwrap());
        let key_len = u32::from_ne_bytes(packet[12..16].try_into().unwrap()) as usize;
        if packet.len() < 16 + key_len {
            return Err("Invalid packet length for key");
        }
        let key = &packet[16..16 + key_len];
        Ok(LookupMap { map_fd, key, flags })
    }

    pub fn to_packet(self) -> Vec<u8> {
        let mut packet = Vec::with_capacity(16 + self.key.len());
        packet.extend_from_slice(&self.map_fd.to_ne_bytes());
        packet.extend_from_slice(&self.flags.to_ne_bytes());
        packet.extend_from_slice(&(self.key.len() as u32).to_ne_bytes());
        packet.extend_from_slice(self.key);
        packet
    }
}
