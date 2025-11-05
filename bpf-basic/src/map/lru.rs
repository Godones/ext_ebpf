use alloc::{boxed::Box, vec::Vec};
use core::num::NonZero;

use lru::LruCache;

use super::{BpfCallBackFn, BpfMapCommonOps, BpfMapMeta, PerCpuVariants, PerCpuVariantsOps};
use crate::{BpfError, Result};

type BpfHashMapKey = Vec<u8>;
type BpfHashMapValue = Vec<u8>;

/// This map is the LRU (Least Recently Used) variant of the BPF_MAP_TYPE_HASH.
/// It is a generic map type that stores a fixed maximum number of key/value pairs.
/// When the map starts to get at capacity, the approximately least recently
/// used elements is removed to make room for new elements.
///
/// See <https://docs.ebpf.io/linux/map-type/BPF_MAP_TYPE_LRU_HASH/>
#[derive(Debug, Clone)]
pub struct LruMap {
    _max_entries: u32,
    data: LruCache<BpfHashMapKey, BpfHashMapValue>,
}

impl LruMap {
    /// Create a new [LruMap] with the given value size and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        if map_meta.value_size == 0 || map_meta.max_entries == 0 || map_meta.key_size == 0 {
            return Err(BpfError::InvalidArgument);
        }
        Ok(Self {
            _max_entries: map_meta.max_entries,
            data: LruCache::new(NonZero::new(map_meta.max_entries as usize).unwrap()),
        })
    }
}

impl BpfMapCommonOps for LruMap {
    fn lookup_elem(&mut self, key: &[u8]) -> Result<Option<&[u8]>> {
        let value = self.data.get(key).map(|v| v.as_slice());
        Ok(value)
    }

    fn update_elem(&mut self, key: &[u8], value: &[u8], _flags: u64) -> Result<()> {
        self.data.put(key.to_vec(), value.to_vec());
        Ok(())
    }

    fn delete_elem(&mut self, key: &[u8]) -> Result<()> {
        self.data.pop(key);
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
            .ok_or(BpfError::NotFound)?;
        if v.len() > value.len() {
            return Err(BpfError::InvalidArgument);
        }
        value[..v.len()].copy_from_slice(v);
        self.data.pop(key);
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
                if next_key.len() < k.len() {
                    return Err(BpfError::InvalidArgument);
                }
                next_key[..k.len()].copy_from_slice(k);
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

/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_LRU_PERCPU_HASH/>
#[derive(Debug)]
pub struct PerCpuLruMap<T: PerCpuVariantsOps> {
    per_cpu_maps: Box<dyn PerCpuVariants<LruMap>>,
    _marker: core::marker::PhantomData<T>,
}

impl<T: PerCpuVariantsOps> PerCpuLruMap<T> {
    /// Create a new [PerCpuLruMap] with the given value size and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        let array_map = LruMap::new(map_meta)?;
        let per_cpu_maps = T::create(array_map).ok_or(BpfError::InvalidArgument)?;
        Ok(PerCpuLruMap {
            per_cpu_maps,
            _marker: core::marker::PhantomData,
        })
    }
}

impl<T: PerCpuVariantsOps> BpfMapCommonOps for PerCpuLruMap<T> {
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

#[cfg(test)]
mod tests {

    use core::ptr::null;

    use super::{super::tests::*, LruMap};
    use crate::{
        BpfError,
        map::{BpfMapCommonOps, BpfMapMeta, lru::PerCpuLruMap},
    };

    fn callback(_key: &[u8], _value: &[u8], _ctx: *const u8) -> i32 {
        0
    }

    fn callback_fail(key: &[u8], _value: &[u8], _ctx: *const u8) -> i32 {
        if key == b"3" {
            return -1;
        }
        0
    }

    fn test_common_lru(lru_map: &mut dyn BpfMapCommonOps) {
        assert_eq!(lru_map.lookup_elem(&[]), Ok(None));
        assert_eq!(lru_map.update_elem(b"1", b"first", 0), Ok(()));
        assert_eq!(lru_map.update_elem(b"2", b"second", 0), Ok(()));
        assert_eq!(lru_map.update_elem(b"3", b"third", 0), Ok(()));
        assert_eq!(lru_map.lookup_elem(b"1"), Ok(Some(b"first".as_slice()))); // 2 3 1
        assert_eq!(lru_map.update_elem(b"4", b"fourth", 0), Ok(())); // 3 1 4
        assert_eq!(lru_map.lookup_elem(b"2"), Ok(None));

        let mut value = [0; 5];
        assert_eq!(lru_map.lookup_and_delete_elem(b"1", &mut value), Ok(())); // 3 4
        assert_eq!(&value, &b"first"[..5]);
        assert_eq!(lru_map.lookup_elem(b"1"), Ok(None));

        let mut next_key = [0; 1];
        assert_eq!(lru_map.get_next_key(None, &mut next_key), Ok(())); // 3 4
        assert_eq!(&next_key, b"4");

        assert_eq!(lru_map.get_next_key(Some(b"4"), &mut next_key), Ok(())); // 3 4
        assert_eq!(&next_key, b"3");

        assert_eq!(
            lru_map.get_next_key(Some(b"3"), &mut next_key),
            Err(BpfError::NotFound)
        ); // 3 4

        let res = lru_map.for_each_elem(callback, null(), 0);
        assert_eq!(res, Ok(2)); // 3 4

        let res = lru_map.for_each_elem(callback_fail, null(), 0);
        assert_eq!(res, Ok(1)); // 3 4

        let res = lru_map.for_each_elem(callback, null(), 1);
        assert_eq!(res, Err(BpfError::InvalidArgument));

        let mut value = [0; 4];
        assert_eq!(
            (lru_map.lookup_and_delete_elem(b"3", &mut value)),
            Err(BpfError::InvalidArgument)
        );

        let mut next_key = [0; 0];
        assert_eq!(
            lru_map.get_next_key(Some(b"3"), &mut next_key),
            Err(BpfError::InvalidArgument)
        );

        assert_eq!(lru_map.delete_elem(b"1"), Ok(()));
    }

    #[test]
    fn test_lru_map() {
        let mut meta = BpfMapMeta::default();
        meta.key_size = 4;
        meta.value_size = 4;
        meta.max_entries = 3;
        let mut lru_map = LruMap::new(&meta).unwrap();
        test_common_lru(&mut lru_map);
    }

    #[test]
    fn test_per_cpu_lru_map() {
        let mut meta = BpfMapMeta::default();
        meta.key_size = 4;
        meta.value_size = 4;
        meta.max_entries = 3;
        let mut lru_map = PerCpuLruMap::<DummyPerCpuCreator>::new(&meta).unwrap();
        test_common_lru(&mut lru_map);
    }

    #[test]
    fn test_create_lru_fail() {
        let mut meta = BpfMapMeta::default();
        meta.value_size = 0;
        let res = LruMap::new(&meta);
        assert_eq!(res.err(), Some(BpfError::InvalidArgument));
        let res = PerCpuLruMap::<DummyPerCpuCreator>::new(&meta);
        assert_eq!(res.err(), Some(BpfError::InvalidArgument));

        meta.key_size = 4;
        meta.value_size = 4;
        meta.max_entries = 3;
        let res = PerCpuLruMap::<DummyPerCpuCreatorFalse>::new(&meta);
        assert_eq!(res.err(), Some(BpfError::InvalidArgument));
    }
}
