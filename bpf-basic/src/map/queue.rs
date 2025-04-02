use alloc::vec::Vec;
use core::fmt::Debug;

use super::{BpfMapCommonOps, BpfMapMeta, BpfMapUpdateElemFlags};
use crate::{BpfError, Result};

type BpfQueueValue = Vec<u8>;

/// BPF_MAP_TYPE_QUEUE provides FIFO storage and BPF_MAP_TYPE_STACK provides LIFO storage for BPF programs.
/// These maps support peek, pop and push operations that are exposed to BPF programs through the respective helpers.
/// These operations are exposed to userspace applications using the existing bpf syscall in the following way:
/// - `BPF_MAP_LOOKUP_ELEM` -> `peek`
/// - `BPF_MAP_UPDATE_ELEM` -> `push`
/// - `BPF_MAP_LOOKUP_AND_DELETE_ELEM ` -> `pop`
///
/// See <https://docs.kernel.org/bpf/map_queue_stack.html>
pub trait SpecialMap: Debug + Send + Sync + 'static {
    /// Returns the number of elements the queue can hold.
    fn push(&mut self, value: BpfQueueValue, flags: BpfMapUpdateElemFlags) -> Result<()>;
    /// Removes the first element and returns it.
    fn pop(&mut self) -> Option<BpfQueueValue>;
    /// Returns the first element without removing it.
    fn peek(&self) -> Option<&BpfQueueValue>;
}

/// The queue map type is a generic map type, resembling a FIFO (First-In First-Out) queue.
///
/// This map type has no keys, only values. The size and type of the values can be specified by the user
/// to fit a large variety of use cases. The typical use-case for this map type is to keep track of
/// a pool of elements such as available network ports when implementing NAT (network address translation).
///
/// As apposed to most map types, this map type uses a custom set of helpers to pop, peek and push elements.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_QUEUE/>
#[derive(Debug)]
pub struct QueueMap {
    max_entries: u32,
    data: Vec<BpfQueueValue>,
}

impl QueueMap {
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        if map_meta.value_size == 0 || map_meta.max_entries == 0 || map_meta.key_size != 0 {
            return Err(BpfError::InvalidArgument);
        }
        let data = Vec::with_capacity(map_meta.max_entries as usize);
        Ok(Self {
            max_entries: map_meta.max_entries,
            data,
        })
    }
}

impl SpecialMap for QueueMap {
    fn push(&mut self, value: BpfQueueValue, flags: BpfMapUpdateElemFlags) -> Result<()> {
        if self.data.len() == self.max_entries as usize {
            if flags.contains(BpfMapUpdateElemFlags::BPF_EXIST) {
                // remove the first element
                self.data.remove(0);
            } else {
                return Err(BpfError::NoSpace);
            }
        }
        self.data.push(value);
        Ok(())
    }
    fn pop(&mut self) -> Option<BpfQueueValue> {
        if self.data.is_empty() {
            return None;
        }
        Some(self.data.remove(0))
    }
    fn peek(&self) -> Option<&BpfQueueValue> {
        self.data.first()
    }
}
/// The stack map type is a generic map type, resembling a stack data structure.
///
/// See <https://ebpf-docs.dylanreimerink.nl/linux/map-type/BPF_MAP_TYPE_STACK/>
#[derive(Debug)]
pub struct StackMap(QueueMap);

impl StackMap {
    /// Create a new [StackMap] with the given key size, value size, and maximum number of entries.
    pub fn new(map_meta: &BpfMapMeta) -> Result<Self> {
        QueueMap::new(map_meta).map(StackMap)
    }
}

impl SpecialMap for StackMap {
    fn push(&mut self, value: BpfQueueValue, flags: BpfMapUpdateElemFlags) -> Result<()> {
        if self.0.data.len() == self.0.max_entries as usize {
            if flags.contains(BpfMapUpdateElemFlags::BPF_EXIST) {
                // remove the last element
                self.0.data.pop();
            } else {
                return Err(BpfError::NoSpace);
            }
        }
        self.0.data.push(value);
        Ok(())
    }
    fn pop(&mut self) -> Option<BpfQueueValue> {
        self.0.data.pop()
    }
    fn peek(&self) -> Option<&BpfQueueValue> {
        self.0.data.last()
    }
}

impl<T: SpecialMap> BpfMapCommonOps for T {
    /// Equal to QueueMap::peek
    fn lookup_elem(&mut self, _key: &[u8]) -> Result<Option<&[u8]>> {
        Ok(self.peek().map(|v| v.as_slice()))
    }
    /// Equal to QueueMap::push
    fn update_elem(&mut self, _key: &[u8], value: &[u8], flags: u64) -> Result<()> {
        let flag = BpfMapUpdateElemFlags::from_bits_truncate(flags);
        self.push(value.to_vec(), flag)
    }
    /// Equal to QueueMap::pop
    fn lookup_and_delete_elem(&mut self, _key: &[u8], value: &mut [u8]) -> Result<()> {
        if let Some(v) = self.pop() {
            value.copy_from_slice(&v);
            Ok(())
        } else {
            Err(BpfError::NotFound)
        }
    }
    fn push_elem(&mut self, value: &[u8], flags: u64) -> Result<()> {
        self.update_elem(&[], value, flags)
    }
    fn pop_elem(&mut self, value: &mut [u8]) -> Result<()> {
        self.lookup_and_delete_elem(&[], value)
    }
    fn peek_elem(&self, value: &mut [u8]) -> Result<()> {
        self.peek()
            .map(|v| value.copy_from_slice(v))
            .ok_or(BpfError::NotFound)
    }
}
