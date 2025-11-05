use alloc::{boxed::Box, collections::BTreeMap, vec::Vec};

use super::{
    BpfCallBackFn, BpfMapCommonOps, BpfMapMeta, BpfMapUpdateElemFlags, PerCpuVariants,
    PerCpuVariantsOps, round_up,
};
use crate::{BpfError, Result};
type BpfHashMapKey = Vec<u8>;
type BpfHashMapValue = Vec<u8>;

/// The hash map type is a generic map type with no restrictions on the structure of the key and value.
/// Hash-maps are implemented using a hash table, allowing for lookups with arbitrary keys.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_HASH/>
#[derive(Debug, Clone)]
pub struct BpfHashMap {
    _max_entries: u32,
    _key_size: u32,
    _value_size: u32,
    data: BTreeMap<BpfHashMapKey, BpfHashMapValue>,
}

impl BpfHashMap {
    /// Create a new [BpfHashMap] with the given key size, value size, and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        if map_meta.value_size == 0 || map_meta.max_entries == 0 {
            return Err(BpfError::InvalidArgument);
        }
        let value_size = round_up(map_meta.value_size as usize, 8);
        Ok(Self {
            _max_entries: map_meta.max_entries,
            _key_size: map_meta.key_size,
            _value_size: value_size as u32,
            data: BTreeMap::new(),
        })
    }
}

impl BpfMapCommonOps for BpfHashMap {
    fn lookup_elem(&mut self, key: &[u8]) -> Result<Option<&[u8]>> {
        let value = self.data.get(key).map(|v| v.as_slice());
        Ok(value)
    }

    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<()> {
        let _flags = BpfMapUpdateElemFlags::from_bits_truncate(flags);
        self.data.insert(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete_elem(&mut self, key: &[u8]) -> Result<()> {
        self.data.remove(key);
        Ok(())
    }

    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: *const u8, flags: u64) -> Result<u32> {
        if flags != 0 {
            return Err(BpfError::InvalidArgument);
        }
        let mut total_used = 0;
        for (key, value) in self.data.iter() {
            let res = cb(key, value, ctx);
            // return value: 0 - continue, 1 - stop and return
            if res != 0 {
                break;
            }
            total_used += 1;
        }
        Ok(total_used)
    }

    fn lookup_and_delete_elem(&mut self, key: &[u8], value: &mut [u8]) -> Result<()> {
        let v = self
            .data
            .get(key)
            .map(|v| v.as_slice())
            .ok_or(BpfError::NotSupported)?;
        value.copy_from_slice(v);
        self.data.remove(key);
        Ok(())
    }

    fn get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        let mut iter = self.data.iter();
        if let Some(key) = key {
            for (k, _) in iter.by_ref() {
                if k.as_slice() == key {
                    break;
                }
            }
        }
        let res = iter.next();
        match res {
            Some((k, _)) => {
                next_key.copy_from_slice(k.as_slice());
                Ok(())
            }
            None => Err(BpfError::NotFound),
        }
    }

    fn map_mem_usage(&self) -> Result<usize> {
        let mut usage = 0;
        for (k, v) in self.data.iter() {
            usage += k.len() + v.len();
        }
        Ok(usage)
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}

/// This is the per-CPU variant of the [BpfHashMap] map type.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_PERCPU_HASH/>
#[derive(Debug)]
pub struct PerCpuHashMap<T: PerCpuVariantsOps> {
    per_cpu_maps: Box<dyn PerCpuVariants<BpfHashMap>>,
    _marker: core::marker::PhantomData<T>,
}

impl<T: PerCpuVariantsOps> PerCpuHashMap<T> {
    /// Create a new [PerCpuHashMap] with the given key size, value size, and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        let array_map = BpfHashMap::new(map_meta)?;
        let per_cpu_maps = T::create(array_map).ok_or(BpfError::InvalidArgument)?;
        Ok(PerCpuHashMap {
            per_cpu_maps,
            _marker: core::marker::PhantomData,
        })
    }
}
impl<T: PerCpuVariantsOps> BpfMapCommonOps for PerCpuHashMap<T> {
    fn lookup_elem(&mut self, key: &[u8]) -> Result<Option<&[u8]>> {
        self.per_cpu_maps.get_mut().lookup_elem(key)
    }

    fn update_elem(&mut self, key: &[u8], value: &[u8], flags: u64) -> Result<()> {
        self.per_cpu_maps.get_mut().update_elem(key, value, flags)
    }

    fn delete_elem(&mut self, key: &[u8]) -> Result<()> {
        self.per_cpu_maps.get_mut().delete_elem(key)
    }

    fn for_each_elem(&mut self, cb: BpfCallBackFn, ctx: *const u8, flags: u64) -> Result<u32> {
        self.per_cpu_maps.get_mut().for_each_elem(cb, ctx, flags)
    }

    fn lookup_and_delete_elem(&mut self, key: &[u8], value: &mut [u8]) -> Result<()> {
        self.per_cpu_maps
            .get_mut()
            .lookup_and_delete_elem(key, value)
    }

    fn lookup_percpu_elem(&mut self, key: &[u8], cpu: u32) -> Result<Option<&[u8]>> {
        unsafe { self.per_cpu_maps.force_get_mut(cpu).lookup_elem(key) }
    }

    fn get_next_key(&self, key: Option<&[u8]>, next_key: &mut [u8]) -> Result<()> {
        self.per_cpu_maps.get_mut().get_next_key(key, next_key)
    }

    fn map_mem_usage(&self) -> Result<usize> {
        self.per_cpu_maps.get().map_mem_usage()
    }

    fn as_any(&self) -> &dyn core::any::Any {
        self
    }

    fn as_any_mut(&mut self) -> &mut dyn core::any::Any {
        self
    }
}
