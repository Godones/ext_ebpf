mod attach;
mod load;
mod map;

use alloc::vec::Vec;

pub use attach::*;
use bitflags::bitflags;
pub use load::*;
pub use map::*;
pub struct eBPFCommandParser;

#[derive(Debug)]
pub enum eBPFCommand<'a> {
    LoadProgram(load::LoadProgram<'a>),
    RemoveProgram(&'a str),
    AttachProgram(attach::AttachProgram<'a>),
    DetachProgram(attach::DetachProgram),
    // Get Tracepoint Info
    GetTPInfo,
    // Enable specific tracepoint
    EnableTP(u32),
    // Disable specific tracepoint
    DisableTP(u32),
    CreateMap(map::CreateMap),
    UpdateMap(map::UpdateMap<'a>),
    FreezeMap(u32),
    DeleteMap(u32),
    MapGetNextKey(map::MapGetNextKey<'a>),
    LookupMap(map::LookupMap<'a>),
    // GetMapInfo,
    // GetProgramInfo,
    // ListMaps,
    // ListPrograms,
}

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct eBPFCommandType: u32 {
        const LOAD_PROGRAM = 0x01;
        const REMOVE_PROGRAM = 0x02;
        const ATTACH_PROGRAM = 0x03;
        const DETACH_PROGRAM = 0x04;
        const GET_TP_INFO = 0x05;
        const ENABLE_TP = 0x06;
        const DISABLE_TP = 0x07;
        const CREATE_MAP = 0x08;
        const UPDATE_MAP = 0x09;
        const FREEZE_MAP = 0x0A;
        const DELETE_MAP = 0x0B;
        const MAP_GET_NEXT_KEY = 0x0C;
        const LOOKUP_MAP = 0x0D;
        // const UPDATE_MAP = 0x08;
        // const LOOKUP_MAP = 0x09;
        // const DELETE_MAP = 0x0A;
        // const GET_MAP_INFO = 0x0B;
        // const GET_PROGRAM_INFO = 0x0C;
        // const LIST_MAPS = 0x0D;
        // const LIST_PROGRAMS = 0x0E;
    }
}

fn common_parse_string<'a>(packet: &'a [u8]) -> Result<&'a str, &'static str> {
    if packet.is_empty() {
        return Err("Invalid packet");
    }
    let cstr = core::ffi::CStr::from_bytes_until_nul(packet).map_err(|_| "Invalid string")?;
    cstr.to_str().map_err(|_| "Invalid UTF-8 in string")
}

impl eBPFCommandParser {
    pub fn parse(packet: &[u8]) -> Result<eBPFCommand, &'static str> {
        if packet.is_empty() {
            return Err("Invalid packet");
        }
        let command_ty = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
        let command_ty = eBPFCommandType::from_bits(command_ty).ok_or("Invalid command")?;
        let packet = &packet[4..];
        match command_ty {
            eBPFCommandType::LOAD_PROGRAM => {
                let load_program = load::LoadProgram::parse(packet)?;
                Ok(eBPFCommand::LoadProgram(load_program))
            }
            eBPFCommandType::REMOVE_PROGRAM => {
                let name = common_parse_string(packet)?;
                Ok(eBPFCommand::RemoveProgram(name))
            }
            eBPFCommandType::ATTACH_PROGRAM => {
                let attach_program = attach::AttachProgram::parse(packet)?;
                Ok(eBPFCommand::AttachProgram(attach_program))
            }
            eBPFCommandType::DETACH_PROGRAM => {
                let detach_program = attach::DetachProgram::parse(packet)?;
                Ok(eBPFCommand::DetachProgram(detach_program))
            }
            eBPFCommandType::GET_TP_INFO => {
                // Placeholder for future implementation
                Ok(eBPFCommand::GetTPInfo)
            }
            eBPFCommandType::ENABLE_TP => {
                if packet.len() < 4 {
                    return Err("Invalid packet length for EnableTP");
                }
                let tracepoint_id = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
                Ok(eBPFCommand::EnableTP(tracepoint_id))
            }
            eBPFCommandType::DISABLE_TP => {
                if packet.len() < 4 {
                    return Err("Invalid packet length for DisableTP");
                }
                let tracepoint_id = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
                Ok(eBPFCommand::DisableTP(tracepoint_id))
            }
            eBPFCommandType::CREATE_MAP => {
                let create_map = map::CreateMap::parse(packet)?;
                Ok(eBPFCommand::CreateMap(create_map))
            }
            eBPFCommandType::UPDATE_MAP => {
                let update_map = map::UpdateMap::parse(packet)?;
                Ok(eBPFCommand::UpdateMap(update_map))
            }
            eBPFCommandType::FREEZE_MAP => {
                if packet.len() < 4 {
                    return Err("Invalid packet length for FreezeMap");
                }
                let map_fd = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
                Ok(eBPFCommand::FreezeMap(map_fd))
            }
            eBPFCommandType::DELETE_MAP => {
                if packet.len() < 4 {
                    return Err("Invalid packet length for DeleteMap");
                }
                let map_fd = u32::from_ne_bytes(packet[0..4].try_into().unwrap());
                Ok(eBPFCommand::DeleteMap(map_fd))
            }
            eBPFCommandType::MAP_GET_NEXT_KEY => {
                let map_get_next_key = map::MapGetNextKey::parse(packet)?;
                Ok(eBPFCommand::MapGetNextKey(map_get_next_key))
            }
            eBPFCommandType::LOOKUP_MAP => {
                let lookup_map = map::LookupMap::parse(packet)?;
                Ok(eBPFCommand::LookupMap(lookup_map))
            }
            _ => Err("Unsupported command type"),
        }
    }

    pub fn to_packet(result: eBPFCommand) -> Vec<u8> {
        let mut packet = Vec::new();
        match result {
            eBPFCommand::LoadProgram(load_program) => {
                packet.extend_from_slice(&eBPFCommandType::LOAD_PROGRAM.bits().to_ne_bytes());
                packet.extend_from_slice(load_program.to_packet().as_slice());
            }
            eBPFCommand::RemoveProgram(name) => {
                packet.extend_from_slice(&eBPFCommandType::REMOVE_PROGRAM.bits().to_ne_bytes());
                packet.extend_from_slice(name.as_bytes());
                packet.push(0); // Null terminator for the name
            }
            eBPFCommand::AttachProgram(attach_program) => {
                packet.extend_from_slice(&eBPFCommandType::ATTACH_PROGRAM.bits().to_ne_bytes());
                packet.extend_from_slice(attach_program.to_packet().as_slice());
            }
            eBPFCommand::DetachProgram(detach_program) => {
                packet.extend_from_slice(&eBPFCommandType::DETACH_PROGRAM.bits().to_ne_bytes());
                packet.extend_from_slice(detach_program.to_packet().as_slice());
            }
            eBPFCommand::GetTPInfo => {
                packet.extend_from_slice(&eBPFCommandType::GET_TP_INFO.bits().to_ne_bytes());
                // No additional data for GetTPInfo
            }
            eBPFCommand::EnableTP(tracepoint_id) => {
                packet.extend_from_slice(&eBPFCommandType::ENABLE_TP.bits().to_ne_bytes());
                packet.extend_from_slice(&tracepoint_id.to_ne_bytes());
            }
            eBPFCommand::DisableTP(tracepoint_id) => {
                packet.extend_from_slice(&eBPFCommandType::DISABLE_TP.bits().to_ne_bytes());
                packet.extend_from_slice(&tracepoint_id.to_ne_bytes());
            }
            eBPFCommand::CreateMap(create_map) => {
                packet.extend_from_slice(&eBPFCommandType::CREATE_MAP.bits().to_ne_bytes());
                packet.extend_from_slice(create_map.to_packet().as_slice());
            }
            eBPFCommand::UpdateMap(update_map) => {
                packet.extend_from_slice(&eBPFCommandType::UPDATE_MAP.bits().to_ne_bytes());
                packet.extend_from_slice(update_map.to_packet().as_slice());
            }
            eBPFCommand::FreezeMap(map_fd) => {
                packet.extend_from_slice(&eBPFCommandType::FREEZE_MAP.bits().to_ne_bytes());
                packet.extend_from_slice(&map_fd.to_ne_bytes());
            }
            eBPFCommand::DeleteMap(map_fd) => {
                packet.extend_from_slice(&eBPFCommandType::DELETE_MAP.bits().to_ne_bytes());
                packet.extend_from_slice(&map_fd.to_ne_bytes());
            }
            eBPFCommand::MapGetNextKey(map_get_next_key) => {
                packet.extend_from_slice(&eBPFCommandType::MAP_GET_NEXT_KEY.bits().to_ne_bytes());
                packet.extend_from_slice(map_get_next_key.to_packet().as_slice());
            }
            eBPFCommand::LookupMap(lookup_map) => {
                packet.extend_from_slice(&eBPFCommandType::LOOKUP_MAP.bits().to_ne_bytes());
                packet.extend_from_slice(lookup_map.to_packet().as_slice());
            }
        }
        packet
    }
}
