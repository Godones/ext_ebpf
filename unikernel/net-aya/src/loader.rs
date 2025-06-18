use core::panic;
use std::{
    borrow::Cow,
    cmp,
    collections::HashMap,
    ffi::{CStr, CString},
    fmt::Debug,
    ops::{Deref, DerefMut},
    os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd},
};

use aya::{
    maps::{Map, MapData, MapError},
    programs::{KProbe, ProbeKind, Program, ProgramData, TracePoint},
    Ebpf, EbpfError, PinningType, VerifierLogLevel,
};
use aya_obj::{
    generated::{bpf_map_type, BPF_OBJ_NAME_LEN},
    EbpfSectionKind, Object, ProgramSection,
};
use ebpf_command::command::{eBPFCommand, CreateMap, UpdateMap};

use crate::{eBPFCommandSend, NetChannel};

type Result<T, E = EbpfError> = std::result::Result<T, E>;

#[derive(Debug)]
pub struct NetEbpfLoader<'a> {
    globals: HashMap<&'a str, (&'a [u8], bool)>,
    max_entries: HashMap<&'a str, u32>,
    cpus: u32,
    net_channel: &'a dyn NetChannel,
}

/// A generic handle to a BPF map.
///
/// You should never need to use this unless you're implementing a new map type.
#[derive(Debug)]
pub struct NetMapData {
    /// The underlying map object.
    #[allow(dead_code)]
    pub obj: aya_obj::Map,
    /// The file descriptor for the map.
    pub fd: RawFd,
}

pub struct NetEbpf<'a> {
    ebpf: Ebpf,
    net_channel: &'a dyn NetChannel,
}

impl Deref for NetEbpf<'_> {
    type Target = Ebpf;

    fn deref(&self) -> &Self::Target {
        &self.ebpf
    }
}

impl DerefMut for NetEbpf<'_> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.ebpf
    }
}

impl<'a> NetEbpf<'a> {
    pub fn new(ebpf: Ebpf, net_channel: &'a dyn NetChannel) -> Self {
        NetEbpf { ebpf, net_channel }
    }
}

impl Drop for NetEbpf<'_> {
    fn drop(&mut self) {
        let map_names = self
            .ebpf
            .maps()
            .map(|(name, _map)| name.to_string())
            .collect::<Vec<_>>();
        for name in map_names {
            if let Some(map) = self.ebpf.take_map(&name) {
                log::info!("Dropping map: {}", name);
                // The map will be dropped automatically when it goes out of scope
                // due to the Drop implementation of NetMapData.
                let mapdata = match map {
                    Map::Array(mapdata) => mapdata,
                    Map::PerCpuArray(mapdata) => mapdata,
                    Map::ProgramArray(mapdata) => mapdata,
                    Map::HashMap(mapdata) => mapdata,
                    Map::LruHashMap(mapdata) => mapdata,
                    Map::PerCpuHashMap(mapdata) => mapdata,
                    Map::PerCpuLruHashMap(mapdata) => mapdata,
                    Map::PerfEventArray(mapdata) => mapdata,
                    Map::RingBuf(mapdata) => mapdata,
                    Map::SockHash(mapdata) => mapdata,
                    Map::SockMap(mapdata) => mapdata,
                    Map::BloomFilter(mapdata) => mapdata,
                    Map::LpmTrie(mapdata) => mapdata,
                    Map::Stack(mapdata) => mapdata,
                    Map::StackTraceMap(mapdata) => mapdata,
                    Map::Queue(mapdata) => mapdata,
                    Map::CpuMap(mapdata) => mapdata,
                    Map::DevMap(mapdata) => mapdata,
                    Map::DevMapHash(mapdata) => mapdata,
                    Map::XskMap(mapdata) => mapdata,
                    Map::Unsupported(mapdata) => mapdata,
                };
                let net_mapdata = unsafe { core::mem::transmute::<_, NetMapData>(mapdata) };
                log::info!("Dropping NetMapData with fd: {}", net_mapdata.fd);
                let delete_map_command = eBPFCommand::DeleteMap(net_mapdata.fd as u32);
                if let Err(e) = delete_map_command.send_command(self.net_channel) {
                    log::error!("Failed to delete map {}: {}", name, e);
                }
            }
        }
    }
}

impl<'a> NetEbpfLoader<'a> {
    pub fn new(net_channel: &'a dyn NetChannel) -> Self {
        NetEbpfLoader {
            globals: HashMap::new(),
            max_entries: HashMap::new(),
            cpus: 1, // Default to 1 CPU
            net_channel,
        }
    }

    pub fn set_cpus(&mut self, cpus: u32) -> &mut Self {
        self.cpus = cpus;
        self
    }

    pub fn set_max_entries(&mut self, name: &'a str, size: u32) -> &mut Self {
        self.max_entries.insert(name, size);
        self
    }

    pub fn set_global<T: Copy + 'static>(
        &mut self,
        name: &'a str,
        value: T,
        must_exist: bool,
    ) -> &mut Self {
        // Convert the value into bytes
        let value = unsafe {
            core::slice::from_raw_parts(&value as *const T as *const u8, core::mem::size_of::<T>())
        };
        self.globals.insert(name, (value, must_exist));
        self
    }

    pub fn load(&mut self, data: &[u8]) -> Result<NetEbpf<'a>> {
        let mut obj = Object::parse(&data)?;
        obj.patch_map_data(self.globals.clone())?;

        let mut maps = HashMap::new();
        for (name, mut obj) in obj.maps.drain() {
            let num_cpus = self.cpus;

            let map_type: bpf_map_type = obj.map_type().try_into().map_err(MapError::from)?;
            if let Some(max_entries) = max_entries_override(
                map_type,
                self.max_entries.get(name.as_str()).copied(),
                || obj.max_entries(),
                num_cpus as _,
                4096,
            )? {
                obj.set_max_entries(max_entries)
            }
            match obj.map_type().try_into() {
                Ok(bpf_map_type::BPF_MAP_TYPE_CPUMAP) => {
                    // obj.set_value_size(if FEATURES.cpumap_prog_id() { 8 } else { 4 })
                    panic!("CPU maps are not supported in this context");
                }
                Ok(bpf_map_type::BPF_MAP_TYPE_DEVMAP | bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH) => {
                    // obj.set_value_size(if FEATURES.devmap_prog_id() { 8 } else { 4 })
                    panic!("Device maps are not supported in this context");
                }
                _ => (),
            }
            let mut map = match obj.pinning() {
                PinningType::None => MapData::create_map(obj, &name, self.net_channel, self.cpus)?,
                PinningType::ByName => {
                    // pin maps in /sys/fs/bpf by default to align with libbpf
                    // behavior https://github.com/libbpf/libbpf/blob/v1.2.2/src/libbpf.c#L2161.
                    // let path = map_pin_path
                    //     .as_deref()
                    //     .unwrap_or_else(|| Path::new("/sys/fs/bpf"));

                    // MapData::create_pinned_by_name(path, obj, &name, btf_fd)?
                    panic!("Pinning by name is not supported in this context")
                }
            };
            map.finalize_map(self.net_channel)?;

            // let net_map = unsafe { core::mem::transmute::<_, NetMapData>(map) };
            maps.insert(name, map);
        }

        let text_sections = obj
            .functions
            .keys()
            .map(|(section_index, _)| *section_index)
            .collect();

        obj.relocate_maps(
            maps.iter()
                .map(|(s, data)| (s.as_str(), data.fd().as_fd().as_raw_fd(), data.obj())),
            &text_sections,
        )?;
        obj.relocate_calls(&text_sections)?;
        // obj.sanitize_functions(&FEATURES);

        let programs = obj
            .programs
            .drain()
            .map(|(name, prog_obj)| {
                let function_obj = obj.functions.get(&prog_obj.function_key()).unwrap().clone();

                let prog_name = Some(name.clone()).map(|s| Cow::Owned(s));

                let section = prog_obj.section.clone();
                let obj = (prog_obj, function_obj);

                let btf_fd = None;
                let program = match &section {
                    ProgramSection::KProbe => Program::KProbe(KProbe {
                        data: ProgramData::new(prog_name, obj, btf_fd, VerifierLogLevel::DISABLE),
                        kind: ProbeKind::KProbe,
                    }),
                    ProgramSection::TracePoint => Program::TracePoint(TracePoint {
                        data: ProgramData::new(prog_name, obj, btf_fd, VerifierLogLevel::DISABLE),
                    }),
                    _ => {
                        panic!("Unsupported program section type: {:?}", section);
                    }
                };
                (name, program)
            })
            .collect();

        let maps = maps
            .drain()
            .map(parse_map)
            .collect::<Result<HashMap<String, Map>, EbpfError>>()?;

        Ok(NetEbpf::new(Ebpf::new(maps, programs), self.net_channel))
    }
}

fn parse_map(data: (String, MapData)) -> Result<(String, Map), EbpfError> {
    let (name, map) = data;
    let map_type = bpf_map_type::try_from(map.obj().map_type()).map_err(MapError::from)?;
    let map = match map_type {
        bpf_map_type::BPF_MAP_TYPE_ARRAY => Map::Array(map),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_ARRAY => Map::PerCpuArray(map),
        bpf_map_type::BPF_MAP_TYPE_PROG_ARRAY => Map::ProgramArray(map),
        bpf_map_type::BPF_MAP_TYPE_HASH => Map::HashMap(map),
        bpf_map_type::BPF_MAP_TYPE_LRU_HASH => Map::LruHashMap(map),
        bpf_map_type::BPF_MAP_TYPE_PERCPU_HASH => Map::PerCpuHashMap(map),
        bpf_map_type::BPF_MAP_TYPE_LRU_PERCPU_HASH => Map::PerCpuLruHashMap(map),
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY => Map::PerfEventArray(map),
        bpf_map_type::BPF_MAP_TYPE_RINGBUF => Map::RingBuf(map),
        bpf_map_type::BPF_MAP_TYPE_SOCKHASH => Map::SockHash(map),
        bpf_map_type::BPF_MAP_TYPE_SOCKMAP => Map::SockMap(map),
        bpf_map_type::BPF_MAP_TYPE_BLOOM_FILTER => Map::BloomFilter(map),
        bpf_map_type::BPF_MAP_TYPE_LPM_TRIE => Map::LpmTrie(map),
        bpf_map_type::BPF_MAP_TYPE_STACK => Map::Stack(map),
        bpf_map_type::BPF_MAP_TYPE_STACK_TRACE => Map::StackTraceMap(map),
        bpf_map_type::BPF_MAP_TYPE_QUEUE => Map::Queue(map),
        bpf_map_type::BPF_MAP_TYPE_CPUMAP => Map::CpuMap(map),
        bpf_map_type::BPF_MAP_TYPE_DEVMAP => Map::DevMap(map),
        bpf_map_type::BPF_MAP_TYPE_DEVMAP_HASH => Map::DevMapHash(map),
        bpf_map_type::BPF_MAP_TYPE_XSKMAP => Map::XskMap(map),
        m => {
            log::warn!("The map {name} is of type {:#?} which is currently unsupported in Aya, use `allow_unsupported_maps()` to load it anyways", m);
            Map::Unsupported(map)
        }
    };

    Ok((name, map))
}
pub trait MapDataExt {
    fn create_map(
        obj: aya_obj::Map,
        name: &str,
        net_channel: &dyn NetChannel,
        nr_cpus: u32,
    ) -> Result<MapData, MapError>;
    fn finalize_map(&mut self, net_channel: &dyn NetChannel) -> Result<(), MapError>;
}

impl MapDataExt for MapData {
    fn create_map(
        mut obj: aya_obj::Map,
        name: &str,
        net_channel: &dyn NetChannel,
        nr_cpus: u32,
    ) -> Result<MapData, MapError> {
        let c_name = CString::new(name)
            .map_err(|std::ffi::NulError { .. }| MapError::InvalidName { name: name.into() })?;

        // BPF_MAP_TYPE_PERF_EVENT_ARRAY's max_entries should not exceed the number of
        // CPUs.
        //
        // By default, the newest versions of Aya, libbpf and cilium/ebpf define `max_entries` of
        // `PerfEventArray` as `0`, with an intention to get it replaced with a correct value
        // by the loader.
        //
        // We allow custom values (potentially coming either from older versions of aya-ebpf or
        // programs written in C) as long as they don't exceed the number of CPUs.
        //
        // Otherwise, when the value is `0` or too large, we set it to the number of CPUs.
        if obj.map_type() == bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY as u32 {
            if obj.max_entries() == 0 || obj.max_entries() > nr_cpus {
                obj.set_max_entries(nr_cpus);
            }
        };

        let fd = bpf_create_map(&c_name, &obj, net_channel).unwrap();
        let mapdata = MapData::new(obj, fd);
        Ok(mapdata)
    }

    fn finalize_map(&mut self, net_channel: &dyn NetChannel) -> Result<(), MapError> {
        let Self { obj, fd } = self;
        if !obj.data().is_empty() {
            let mut key = Vec::with_capacity(obj.key_size() as usize);
            let key = unsafe {
                std::slice::from_raw_parts_mut(key.as_mut_ptr(), obj.key_size() as usize)
            };
            key.fill(0);

            let mut value = Vec::with_capacity(obj.value_size() as usize);
            let value = unsafe {
                std::slice::from_raw_parts_mut(
                    value.as_mut_ptr() as *mut u8,
                    obj.value_size() as usize,
                )
            };
            value.copy_from_slice(obj.data().as_ref());
            bpf_map_update_elem_ptr(fd.as_fd(), key, value, 0, net_channel).unwrap();
        }
        if obj.section_kind() == EbpfSectionKind::Rodata {
            bpf_map_freeze(fd.as_fd(), net_channel).unwrap();
        }
        Ok(())
    }
}

fn bpf_create_map(name: &CStr, def: &aya_obj::Map, net_channel: &dyn NetChannel) -> Result<u32> {
    let mut create_map_command = CreateMap {
        map_type: def.map_type() as u32,
        key_size: def.key_size() as u32,
        value_size: def.value_size() as u32,
        max_entries: def.max_entries() as u32,
        map_flags: def.map_flags() as u32,
        map_name: [0; BPF_OBJ_NAME_LEN as usize],
    };

    // https://github.com/torvalds/linux/commit/ad5b177bd73f5107d97c36f56395c4281fb6f089
    // The map name was added as a parameter in kernel 4.15+ so we skip adding it on
    // older kernels for compatibility
    {
        // u.map_name is 16 bytes max and must be NULL terminated
        let name_len = cmp::min(name.to_bytes().len(), (BPF_OBJ_NAME_LEN - 1) as usize);
        create_map_command.map_name[..name_len]
            .copy_from_slice(unsafe { std::slice::from_raw_parts(name.as_ptr() as _, name_len) });
    }

    let command = eBPFCommand::CreateMap(create_map_command);
    let map_id = command.send_command(net_channel).unwrap();
    let map_id = map_id.parse().unwrap();

    Ok(map_id)
}

fn bpf_map_update_elem_ptr(
    fd: BorrowedFd<'_>,
    key: &[u8],
    value: &[u8],
    flags: u64,
    net_channel: &dyn NetChannel,
) -> Result<()> {
    let update_map_command = UpdateMap {
        map_fd: fd.as_raw_fd() as u32,
        flags,
        key,
        value,
    };
    let command = eBPFCommand::UpdateMap(update_map_command);
    let _result = command.send_command(net_channel).unwrap();
    Ok(())
}

fn bpf_map_freeze(fd: BorrowedFd<'_>, net_channel: &dyn NetChannel) -> Result<()> {
    let command = eBPFCommand::FreezeMap(fd.as_raw_fd() as u32);
    let _result = command.send_command(net_channel).unwrap();
    Ok(())
}

/// Computes the value which should be used to override the max_entries value of the map
/// based on the user-provided override and the rules for that map type.
fn max_entries_override(
    map_type: bpf_map_type,
    user_override: Option<u32>,
    current_value: impl Fn() -> u32,
    num_cpus: u32,
    page_size: u32,
) -> Result<Option<u32>, EbpfError> {
    let max_entries = || user_override.unwrap_or_else(&current_value);
    Ok(match map_type {
        bpf_map_type::BPF_MAP_TYPE_PERF_EVENT_ARRAY if max_entries() == 0 => Some(num_cpus),
        bpf_map_type::BPF_MAP_TYPE_RINGBUF => Some(adjust_to_page_size(max_entries(), page_size))
            .filter(|adjusted| *adjusted != max_entries())
            .or(user_override),
        _ => user_override,
    })
}

// Adjusts the byte size of a RingBuf map to match a power-of-two multiple of the page size.
//
// This mirrors the logic used by libbpf.
// See https://github.com/libbpf/libbpf/blob/ec6f716eda43/src/libbpf.c#L2461-L2463
fn adjust_to_page_size(byte_size: u32, page_size: u32) -> u32 {
    // If the byte_size is zero, return zero and let the verifier reject the map
    // when it is loaded. This is the behavior of libbpf.
    if byte_size == 0 {
        return 0;
    }
    // TODO: Replace with primitive method when int_roundings (https://github.com/rust-lang/rust/issues/88581)
    // is stabilized.
    fn div_ceil(n: u32, rhs: u32) -> u32 {
        let d = n / rhs;
        let r = n % rhs;
        if r > 0 && rhs > 0 {
            d + 1
        } else {
            d
        }
    }
    let pages_needed = div_ceil(byte_size, page_size);
    page_size * pages_needed.next_power_of_two()
}

pub struct SimpleProgramData {
    pub name: Option<String>,
    pub instructions: Vec<u8>,
}

impl Debug for SimpleProgramData {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SimpleProgramData")
            .field("name", &self.name)
            .field(
                "instructions",
                &format_args!("{} bytes", self.instructions.len()),
            )
            .finish()
    }
}

pub trait ExtractInstruction {
    fn extract_instruction(&mut self) -> Result<SimpleProgramData>;
}

impl ExtractInstruction for TracePoint {
    fn extract_instruction(&mut self) -> Result<SimpleProgramData> {
        let ProgramData { name, obj, .. } = &mut self.data;
        let obj = obj.as_ref().unwrap();
        let (aya_obj::Program { .. }, aya_obj::Function { instructions, .. }) = obj;

        let prog_name = if let Some(name) = name.as_deref() {
            let prog_name = CString::new(name).unwrap().to_str().unwrap().to_owned();
            Some(prog_name)
        } else {
            None
        };
        // to Vec<u8>
        let instructions = unsafe {
            core::slice::from_raw_parts(instructions.as_ptr() as *const u8, instructions.len() * 8)
        };
        Ok(SimpleProgramData {
            name: prog_name,
            instructions: instructions.to_vec(),
        })
    }
}
