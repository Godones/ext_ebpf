use std::{
    borrow::Borrow,
    io,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd, BorrowedFd},
};

use aya::{
    maps::{HashMap, MapData, MapError},
    sys::SyscallError,
    Pod,
};
use ebpf_command::command::{eBPFCommand, LookupMap, MapGetNextKey};

use crate::{eBPFCommandSend, NetChannel};

/// An iterable map
pub trait NetIterableMap<K: Pod, V> {
    /// Get a generic map handle
    fn net_map(&self) -> &MapData;
    /// Get the value for the provided `key`
    fn net_get<'a>(&self, key: &K, net_channel: &'a dyn NetChannel) -> Result<V, MapError>;
}

/// Iterator returned by `map.keys()`.
pub struct NetMapKeys<'coll, K: Pod> {
    map: &'coll MapData,
    err: bool,
    key: Option<K>,
    net_channel: &'coll dyn NetChannel,
}

impl<'coll, K: Pod> NetMapKeys<'coll, K> {
    fn new(map: &'coll MapData, net_channel: &'coll dyn NetChannel) -> Self {
        Self {
            map,
            err: false,
            key: None,
            net_channel,
        }
    }
}

impl<K: Pod> Iterator for NetMapKeys<'_, K> {
    type Item = Result<K, MapError>;

    fn next(&mut self) -> Option<Result<K, MapError>> {
        if self.err {
            return None;
        }

        let fd = self.map.fd().as_fd();
        let key =
            bpf_map_get_next_key(fd, self.key.as_ref(), self.net_channel).map_err(|io_error| {
                SyscallError {
                    call: "bpf_map_get_next_key",
                    io_error,
                }
            });
        match key {
            Err(err) => {
                self.err = true;
                Some(Err(err.into()))
            }
            Ok(key) => {
                self.key = key;
                key.map(Ok)
            }
        }
    }
}

fn bpf_map_get_next_key<K: Pod>(
    fd: BorrowedFd<'_>,
    key: Option<&K>,
    net_channel: &dyn NetChannel,
) -> io::Result<Option<K>> {
    let key = if key.is_some() {
        Some(unsafe {
            core::slice::from_raw_parts(
                key.unwrap() as *const _ as *const u8,
                core::mem::size_of::<K>(),
            )
        })
    } else {
        None
    };
    let map_next_key_command = MapGetNextKey::new(fd.as_raw_fd() as u32, key);
    let command = eBPFCommand::MapGetNextKey(map_next_key_command);
    let res = command.send_command(net_channel).unwrap();
    let next_key = if res.is_empty() {
        None
    } else {
        let bytes = res.as_bytes();
        unsafe {
            Some(
                core::slice::from_raw_parts(
                    bytes.as_ptr() as *const K,
                    bytes.len() / core::mem::size_of::<K>(),
                )[0],
            )
        }
    };
    Ok(next_key)
}

fn lookup<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
    net_channel: &dyn NetChannel,
) -> io::Result<Option<V>> {
    let key = unsafe {
        core::slice::from_raw_parts(key as *const _ as *const u8, core::mem::size_of::<K>())
    };
    let lookup_command = LookupMap::new(fd.as_raw_fd() as u32, key, flags);

    let res = eBPFCommand::LookupMap(lookup_command)
        .send_command(net_channel)
        .unwrap();
    if res.is_empty() {
        return Ok(None);
    }
    let bytes = res.as_bytes();
    if bytes.len() < core::mem::size_of::<V>() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Received data is smaller than expected",
        ));
    }
    let value = unsafe {
        core::slice::from_raw_parts(
            bytes.as_ptr() as *const V,
            bytes.len() / core::mem::size_of::<V>(),
        )[0]
    };
    Ok(Some(value))
}

fn bpf_map_lookup_elem<K: Pod, V: Pod>(
    fd: BorrowedFd<'_>,
    key: &K,
    flags: u64,
    net_channel: &dyn NetChannel,
) -> io::Result<Option<V>> {
    lookup(fd, key, flags, net_channel)
}

/// Iterator returned by `map.iter()`.
pub struct NetMapIter<'coll, K: Pod, V, I: NetIterableMap<K, V>> {
    keys: NetMapKeys<'coll, K>,
    map: &'coll I,
    _v: PhantomData<V>,
}

impl<'coll, K: Pod, V, I: NetIterableMap<K, V>> NetMapIter<'coll, K, V, I> {
    fn new(map: &'coll I, net_channel: &'coll dyn NetChannel) -> Self {
        Self {
            keys: NetMapKeys::new(map.net_map(), net_channel),
            map,
            _v: PhantomData,
        }
    }
}

impl<K: Pod, V, I: NetIterableMap<K, V>> Iterator for NetMapIter<'_, K, V, I> {
    type Item = Result<(K, V), MapError>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            match self.keys.next() {
                Some(Ok(key)) => match self.map.net_get(&key, self.keys.net_channel) {
                    Ok(value) => return Some(Ok((key, value))),
                    Err(MapError::KeyNotFound) => continue,
                    Err(e) => return Some(Err(e)),
                },
                Some(Err(e)) => return Some(Err(e)),
                None => return None,
            }
        }
    }
}

pub trait NetHashMap<NK: Pod, NV: Pod> {
    type Map: NetIterableMap<NK, NV>;
    fn net_get(&self, net_channel: &dyn NetChannel, key: &NK, flags: u64) -> Result<NV, MapError>;
    fn net_keys<'a>(&'a self, net_channel: &'a dyn NetChannel) -> NetMapKeys<'a, NK>;
    fn net_iter<'a>(&'a self, net_channel: &'a dyn NetChannel)
        -> NetMapIter<'a, NK, NV, Self::Map>;
}

impl<T: Borrow<MapData>, K, V> NetIterableMap<K, V> for HashMap<T, K, V>
where
    K: Pod,
    V: Pod,
{
    fn net_map(&self) -> &MapData {
        self.inner.borrow()
    }

    fn net_get<'a>(&self, key: &K, net_channel: &'a dyn NetChannel) -> Result<V, MapError> {
        NetHashMap::net_get(self, net_channel, key, 0)
    }
}

impl<T: Borrow<MapData>, K: Pod, V: Pod> NetHashMap<K, V> for HashMap<T, K, V> {
    type Map = Self;
    fn net_get(&self, net_channel: &dyn NetChannel, key: &K, flags: u64) -> Result<V, MapError> {
        let fd = self.inner.borrow().fd().as_fd();
        let value =
            bpf_map_lookup_elem(fd, key, flags, net_channel).map_err(|io_error| SyscallError {
                call: "bpf_map_lookup_elem",
                io_error,
            })?;
        value.ok_or(MapError::KeyNotFound)
    }

    fn net_keys<'a>(&'a self, net_channel: &'a dyn NetChannel) -> NetMapKeys<'a, K> {
        let inner_ref = self.inner.borrow();
        NetMapKeys::new(inner_ref, net_channel)
    }

    fn net_iter<'a>(&'a self, net_channel: &'a dyn NetChannel) -> NetMapIter<'a, K, V, Self::Map> {
        NetMapIter::new(self, net_channel)
    }
}
