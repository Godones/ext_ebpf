use alloc::{boxed::Box, vec, vec::Vec};
use core::ops::{Index, IndexMut, Range};

use super::{
    round_up, BpfCallBackFn, BpfMapCommonOps, BpfMapMeta, PerCpuVariants, PerCpuVariantsOps,
};
use crate::{BpfError, Result};

/// The array map type is a generic map type with no restrictions on the structure of the value.
/// Like a normal array, the array map has a numeric key starting at 0 and incrementing.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_ARRAY/>
#[derive(Debug, Clone)]
pub struct ArrayMap {
    data: ArrayMapData,
    max_entries: u32,
}

#[derive(Debug, Clone)]
struct ArrayMapData {
    elem_size: u32,
    /// The data is stored in a Vec<u8> with the size of elem_size * max_entries.
    data: Vec<u8>,
}
impl ArrayMapData {
    pub fn new(elem_size: u32, max_entries: u32) -> Self {
        debug_assert!(elem_size % 8 == 0);
        let total_size = elem_size * max_entries;
        let data = vec![0; total_size as usize];
        ArrayMapData { elem_size, data }
    }
}

impl Index<u32> for ArrayMapData {
    type Output = [u8];
    fn index(&self, index: u32) -> &Self::Output {
        let start = index * self.elem_size;
        &self.data[start as usize..(start + self.elem_size) as usize]
    }
}

impl IndexMut<u32> for ArrayMapData {
    fn index_mut(&mut self, index: u32) -> &mut Self::Output {
        let start = index * self.elem_size;
        &mut self.data[start as usize..(start + self.elem_size) as usize]
    }
}

impl ArrayMap {
    /// Create a new [ArrayMap] with the given key size, value size, and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        if map_meta.value_size == 0 || map_meta.max_entries == 0 || map_meta.key_size != 4 {
            return Err(BpfError::InvalidArgument);
        }
        let elem_size = round_up(map_meta.value_size as usize, 8);
        let data = ArrayMapData::new(elem_size as u32, map_meta.max_entries);
        Ok(ArrayMap {
            data,
            max_entries: map_meta.max_entries,
        })
    }
}

impl BpfMapCommonOps for ArrayMap {
    fn lookup_elem(&mut self, key: &[u8]) -> Result<Option<&[u8]>> {
        if key.len() != 4 {
            return Err(BpfError::InvalidArgument);
        }
        let index = u32::from_ne_bytes(key.try_into().map_err(|_| BpfError::InvalidArgument)?);
        if index >= self.max_entries {
            return Err(BpfError::InvalidArgument);
        }
        let val = self.data.index(index);
        Ok(Some(val))
    }
    fn update_elem(&mut self, key: &[u8], value: &[u8], _flags: u64) -> Result<()> {
        if key.len() != 4 {
            return Err(BpfError::InvalidArgument);
        }
        let index = u32::from_ne_bytes(key.try_into().map_err(|_| BpfError::InvalidArgument)?);
        if index >= self.max_entries {
            return Err(BpfError::InvalidArgument);
        }
        if value.len() > self.data.elem_size as usize {
            return Err(BpfError::InvalidArgument);
        }
        let old_value = self.data.index_mut(index);
        old_value[..value.len()].copy_from_slice(value);
        Ok(())
    }
    /// For ArrayMap, delete_elem is not supported.
    fn delete_elem(&mut self, _key: &[u8]) -> Result<()> {
        Err(BpfError::InvalidArgument)
    }
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: *const u8, flags: u64) -> Result<u32> {
        if flags != 0 {
            return Err(BpfError::InvalidArgument);
        }
        let mut total_used = 0;
        for i in 0..self.max_entries {
            let key = i.to_ne_bytes();
            let value = self.data.index(i);
            total_used += 1;
            let res = cb(&key, value, ctx);
            // return value: 0 - continue, 1 - stop and return
            if res != 0 {
                break;
            }
        }
        Ok(total_used)
    }

    fn lookup_and_delete_elem(&mut self, _key: &[u8], _value: &mut [u8]) -> Result<()> {
        Err(BpfError::InvalidArgument)
    }

    fn get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        if let Some(key) = key {
            if key.len() != 4 {
                return Err(BpfError::InvalidArgument);
            }
            let index = u32::from_ne_bytes(key.try_into().map_err(|_| BpfError::InvalidArgument)?);
            if index == self.max_entries - 1 {
                return Err(BpfError::NotFound);
            }
            let next_index = index + 1;
            next_key.copy_from_slice(&next_index.to_ne_bytes());
        } else {
            next_key.copy_from_slice(&0u32.to_ne_bytes());
        }
        Ok(())
    }

    fn freeze(&self) -> Result<()> {
        Ok(())
    }
    fn map_values_ptr_range(&self) -> Result<Range<usize>> {
        let start = self.data.data.as_ptr() as usize;
        Ok(start..start + self.data.data.len())
    }
}

/// This is the per-CPU variant of the [ArrayMap] map type.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_PERCPU_ARRAY/>
#[derive(Debug)]
pub struct PerCpuArrayMap<T: PerCpuVariantsOps> {
    per_cpu_data: Box<dyn PerCpuVariants<ArrayMap>>,
    _marker: core::marker::PhantomData<T>,
}

impl<T: PerCpuVariantsOps> PerCpuArrayMap<T> {
    /// Create a new [PerCpuArrayMap] with the given key size, value size, and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        let array_map = ArrayMap::new(map_meta)?;
        let per_cpu_data = T::create(array_map).ok_or(BpfError::InvalidArgument)?;
        Ok(PerCpuArrayMap {
            per_cpu_data,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<T: PerCpuVariantsOps> BpfMapCommonOps for PerCpuArrayMap<T> {
    fn lookup_elem(&mut self, key: &[u8]) -> Result<Option<&[u8]>> {
        self.per_cpu_data.get_mut().lookup_elem(key)
    }
    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<()> {
        self.per_cpu_data.get_mut().update_elem(key, value, flags)
    }
    fn delete_elem(&mut self, key: &[u8]) -> Result<()> {
        self.per_cpu_data.get_mut().delete_elem(key)
    }
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: *const u8, flags: u64) -> Result<u32> {
        self.per_cpu_data.get_mut().for_each_elem(cb, ctx, flags)
    }
    fn lookup_and_delete_elem(&mut self, _key: &[u8], _value: &mut [u8]) -> Result<()> {
        Err(BpfError::InvalidArgument)
    }
    fn lookup_percpu_elem(&mut self, key: &[u8], cpu: u32) -> Result<Option<&[u8]>> {
        unsafe { self.per_cpu_data.force_get_mut(cpu).lookup_elem(key) }
    }
    fn get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        self.per_cpu_data.get_mut().get_next_key(key, next_key)
    }
    fn map_values_ptr_range(&self) -> Result<Range<usize>> {
        self.per_cpu_data.get_mut().map_values_ptr_range()
    }
}

/// The perf event array map type is a special type of array map that is used to store file descriptors
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_PERF_EVENT_ARRAY/>
#[derive(Debug)]
pub struct PerfEventArrayMap {
    // The value is the file descriptor of the perf event.
    fds: ArrayMapData,
    num_cpus: u32,
}

impl PerfEventArrayMap {
    /// Create a new [PerfEventArrayMap] with the given key size, value size, and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta, num_cpus: u32) -> Result<Self> {
        if map_meta.key_size != 4 || map_meta.value_size != 4 || map_meta.max_entries != num_cpus {
            return Err(BpfError::InvalidArgument);
        }
        let fds = ArrayMapData::new(4, num_cpus);
        Ok(PerfEventArrayMap { fds, num_cpus })
    }
}

impl BpfMapCommonOps for PerfEventArrayMap {
    fn lookup_elem(&mut self, key: &[u8]) -> Result<Option<&[u8]>> {
        let cpu_id = u32::from_ne_bytes(key.try_into().map_err(|_| BpfError::InvalidArgument)?);
        let value = self.fds.index(cpu_id);
        Ok(Some(value))
    }
    fn update_elem(&mut self, key: &[u8], value: &[u8], _flags: u64) -> Result<()> {
        assert_eq!(value.len(), 4);
        let cpu_id = u32::from_ne_bytes(key.try_into().map_err(|_| BpfError::InvalidArgument)?);
        let old_value = self.fds.index_mut(cpu_id);
        old_value.copy_from_slice(value);
        Ok(())
    }
    fn delete_elem(&mut self, key: &[u8]) -> Result<()> {
        let cpu_id = u32::from_ne_bytes(key.try_into().map_err(|_| BpfError::InvalidArgument)?);
        self.fds.index_mut(cpu_id).copy_from_slice(&[0; 4]);
        Ok(())
    }
    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: *const u8, _flags: u64) -> Result<u32> {
        let mut total_used = 0;
        for i in 0..self.num_cpus {
            let key = i.to_ne_bytes();
            let value = self.fds.index(i);
            total_used += 1;
            let res = cb(&key, value, ctx);
            if res != 0 {
                break;
            }
        }
        Ok(total_used)
    }
    fn lookup_and_delete_elem(&mut self, _key: &[u8], _value: &mut [u8]) -> Result<()> {
        Err(BpfError::NotSupported)
    }
    fn map_values_ptr_range(&self) -> Result<Range<usize>> {
        let start = self.fds.data.as_ptr() as usize;
        Ok(start..start + self.fds.data.len())
    }
}
