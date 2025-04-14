use core::ffi::c_void;

use consts::BPF_F_CURRENT_CPU;

use crate::{
    map::{BpfCallBackFn, UnifiedMap},
    BpfError, KernelAuxiliaryOps, Result,
};

pub mod consts;
mod print;

pub type RawBPFHelperFn = fn(u64, u64, u64, u64, u64) -> u64;

/// Transmute a function pointer to a RawBPFHelperFn.
macro_rules! helper_func {
    ($name:ident::<$($generic:ident),*>) => {
        unsafe {
            core::mem::transmute::<usize, RawBPFHelperFn>($name::<$($generic),*> as usize)
        }
    };
}

/// See <https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_lookup_elem/>
pub unsafe fn raw_map_lookup_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    key: *const c_void,
) -> *const c_void {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let key = core::slice::from_raw_parts(key as *const u8, key_size);
        let value = map_lookup_elem(unified_map, key)?;
        // log::info!("<raw_map_lookup_elem>: {:x?}", value);
        Ok(value)
    });
    match res {
        Ok(Some(value)) => value as _,
        _ => core::ptr::null(),
    }
}

/// Lookup an element in map.
pub fn map_lookup_elem(unified_map: &mut UnifiedMap, key: &[u8]) -> Result<Option<*const u8>> {
    let map = unified_map.map_mut();
    let value = map.lookup_elem(key);
    match value {
        Ok(Some(value)) => Ok(Some(value.as_ptr())),
        _ => Ok(None),
    }
}

/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_perf_event_output/
///
/// See https://man7.org/linux/man-pages/man7/bpf-helpers.7.html
pub unsafe fn raw_perf_event_output<F: KernelAuxiliaryOps>(
    ctx: *mut c_void,
    map: *mut c_void,
    flags: u64,
    data: *mut c_void,
    size: u64,
) -> i64 {
    // log::info!("<raw_perf_event_output>: {:x?}", data);
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let data = core::slice::from_raw_parts(data as *const u8, size as usize);
        perf_event_output::<F>(ctx, unified_map, flags, data)
    });

    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}

/// Output data to a perf event.
pub fn perf_event_output<F: KernelAuxiliaryOps>(
    ctx: *mut c_void,
    unified_map: &mut UnifiedMap,
    flags: u64,
    data: &[u8],
) -> Result<()> {
    let index = flags as u32;
    let flags = (flags >> 32) as u32;
    let key = if index == BPF_F_CURRENT_CPU as u32 {
        F::current_cpu_id()
    } else {
        index
    };
    let map = unified_map.map_mut();
    let fd = map
        .lookup_elem(&key.to_ne_bytes())?
        .ok_or(BpfError::NotFound)?;
    let fd = u32::from_ne_bytes(fd.try_into().map_err(|_| BpfError::InvalidArgument)?);
    F::perf_event_output(ctx, fd, flags, data)?;
    Ok(())
}

/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_probe_read/
fn raw_bpf_probe_read(dst: *mut c_void, size: u32, unsafe_ptr: *const c_void) -> i64 {
    log::info!(
        "raw_bpf_probe_read, dst:{:x}, size:{}, unsafe_ptr: {:x}",
        dst as usize,
        size,
        unsafe_ptr as usize
    );
    let (dst, src) = unsafe {
        let dst = core::slice::from_raw_parts_mut(dst as *mut u8, size as usize);
        let src = core::slice::from_raw_parts(unsafe_ptr as *const u8, size as usize);
        (dst, src)
    };
    let res = bpf_probe_read(dst, src);
    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}

/// For tracing programs, safely attempt to read size
/// bytes from kernel space address unsafe_ptr and
/// store the data in dst.
pub fn bpf_probe_read(dst: &mut [u8], src: &[u8]) -> Result<()> {
    log::info!("bpf_probe_read: len: {}", dst.len());
    dst.copy_from_slice(src);
    Ok(())
}

pub unsafe fn raw_map_update_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    key: *const c_void,
    value: *const c_void,
    flags: u64,
) -> i64 {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let value_size = meta.value_size as usize;
        // log::info!("<raw_map_update_elem>: flags: {:x?}", flags);
        let key = core::slice::from_raw_parts(key as *const u8, key_size);
        let value = core::slice::from_raw_parts(value as *const u8, value_size);
        map_update_elem(unified_map, key, value, flags)
    });
    match res {
        Ok(_) => 0,
        Err(e) => e as _,
    }
}

/// Update entry with key in map.
pub fn map_update_elem(
    unified_map: &mut UnifiedMap,
    key: &[u8],
    value: &[u8],
    flags: u64,
) -> Result<()> {
    let map = unified_map.map_mut();
    let value = map.update_elem(key, value, flags);
    value
}

/// Delete entry with key from map.
///
/// The delete map element helper call is used to delete values from maps.
pub unsafe fn raw_map_delete_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    key: *const c_void,
) -> i64 {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let key = core::slice::from_raw_parts(key as *const u8, key_size);
        map_delete_elem(unified_map, key)
    });
    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}

/// Delete entry with key from map.
pub fn map_delete_elem(unified_map: &mut UnifiedMap, key: &[u8]) -> Result<()> {
    let map = unified_map.map_mut();
    let value = map.delete_elem(key);
    value
}

/// For each element in map, call callback_fn function with map, callback_ctx and other map-specific
/// parameters. The callback_fn should be a static function and the callback_ctx should be a pointer
/// to the stack. The flags is used to control certain aspects of the helper.  Currently, the flags must
/// be 0.
///
/// The following are a list of supported map types and their respective expected callback signatures:
/// - BPF_MAP_TYPE_HASH
/// - BPF_MAP_TYPE_PERCPU_HASH
/// - BPF_MAP_TYPE_LRU_HASH
/// - BPF_MAP_TYPE_LRU_PERCPU_HASH
/// - BPF_MAP_TYPE_ARRAY
/// - BPF_MAP_TYPE_PERCPU_ARRAY
///
/// `long (*callback_fn)(struct bpf_map *map, const void key, void *value, void *ctx);`
///
/// For per_cpu maps, the map_value is the value on the cpu where the bpf_prog is running.
pub unsafe fn raw_map_for_each_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    cb: *const c_void,
    ctx: *const c_void,
    flags: u64,
) -> i64 {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let cb = *core::mem::transmute::<*const c_void, *const BpfCallBackFn>(cb);
        map_for_each_elem(unified_map, cb, ctx as _, flags)
    });
    match res {
        Ok(v) => v as i64,
        Err(e) => e as i64,
    }
}

/// Do some action for each element in map.
pub fn map_for_each_elem(
    unified_map: &mut UnifiedMap,
    cb: BpfCallBackFn,
    ctx: *const u8,
    flags: u64,
) -> Result<u32> {
    let map = unified_map.map_mut();
    let value = map.for_each_elem(cb, ctx, flags);
    value
}

/// Perform a lookup in percpu map for an entry associated to key on cpu.
///
/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_lookup_percpu_elem/
pub unsafe fn raw_map_lookup_percpu_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    key: *const c_void,
    cpu: u32,
) -> *const c_void {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let key_size = meta.key_size as usize;
        let key = core::slice::from_raw_parts(key as *const u8, key_size);
        map_lookup_percpu_elem(unified_map, key, cpu)
    });
    match res {
        Ok(Some(value)) => value as *const c_void,
        _ => core::ptr::null_mut(),
    }
}

/// Lookup an element in percpu map.
pub fn map_lookup_percpu_elem(
    unified_map: &mut UnifiedMap,
    key: &[u8],
    cpu: u32,
) -> Result<Option<*const u8>> {
    let map = unified_map.map_mut();
    let value = map.lookup_percpu_elem(key, cpu);
    match value {
        Ok(Some(value)) => Ok(Some(value.as_ptr())),
        _ => Ok(None),
    }
}
/// Push an element value in map.
///
/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_push_elem/
pub unsafe fn raw_map_push_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    value: *const c_void,
    flags: u64,
) -> i64 {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let value_size = meta.value_size as usize;
        let value = core::slice::from_raw_parts(value as *const u8, value_size);
        map_push_elem(unified_map, value, flags)
    });
    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}

/// Push an element value in map.
pub fn map_push_elem(unified_map: &mut UnifiedMap, value: &[u8], flags: u64) -> Result<()> {
    let map = unified_map.map_mut();
    let value = map.push_elem(value, flags);
    value
}

/// Pop an element from map.
///
/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_pop_elem/
pub unsafe fn raw_map_pop_elem<F: KernelAuxiliaryOps>(map: *mut c_void, value: *mut c_void) -> i64 {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let value_size = meta.value_size as usize;
        let value = core::slice::from_raw_parts_mut(value as *mut u8, value_size);
        map_pop_elem(unified_map, value)
    });
    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}

/// Pop an element from map.
pub fn map_pop_elem(unified_map: &mut UnifiedMap, value: &mut [u8]) -> Result<()> {
    let map = unified_map.map_mut();
    let value = map.pop_elem(value);
    value
}

/// Get an element from map without removing it.
///
/// See https://ebpf-docs.dylanreimerink.nl/linux/helper-function/bpf_map_peek_elem/
pub unsafe fn raw_map_peek_elem<F: KernelAuxiliaryOps>(
    map: *mut c_void,
    value: *mut c_void,
) -> i64 {
    let res = F::get_unified_map_from_ptr(map as *const u8, |unified_map| {
        let meta = unified_map.map_meta();
        let value_size = meta.value_size as usize;
        let value = core::slice::from_raw_parts_mut(value as *mut u8, value_size);
        map_peek_elem(unified_map, value)
    });
    match res {
        Ok(_) => 0,
        Err(e) => e as i64,
    }
}

/// Get an element from map without removing it.
pub fn map_peek_elem(unified_map: &mut UnifiedMap, value: &mut [u8]) -> Result<()> {
    let map = unified_map.map_mut();
    let value = map.peek_elem(value);
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeKernelAuxiliaryOps;
    impl KernelAuxiliaryOps for FakeKernelAuxiliaryOps {
        fn get_unified_map_from_ptr<F, R>(_ptr: *const u8, _func: F) -> Result<R>
        where
            F: FnOnce(&mut UnifiedMap) -> Result<R>,
        {
            Err(BpfError::NotSupported)
        }

        fn get_unified_map_from_fd<F, R>(_map_fd: u32, _func: F) -> Result<R>
        where
            F: FnOnce(&mut UnifiedMap) -> Result<R>,
        {
            Err(BpfError::NotSupported)
        }

        fn transmute_buf<'a>(_ptr: *const u8, _size: usize) -> Result<&'a [u8]> {
            Err(BpfError::NotSupported)
        }

        fn transmute_buf_mut<'a>(_ptr: *mut u8, _size: usize) -> Result<&'a mut [u8]> {
            Err(BpfError::NotSupported)
        }

        fn current_cpu_id() -> u32 {
            0
        }

        fn perf_event_output(
            _ctx: *mut core::ffi::c_void,
            _fd: u32,
            _flags: u32,
            _data: &[u8],
        ) -> Result<()> {
            Err(BpfError::NotSupported)
        }
    }

    #[test]
    fn define_bpf_helper() {
        let f = raw_map_lookup_elem::<FakeKernelAuxiliaryOps>;
        let bpf_helper = helper_func!(raw_map_lookup_elem::<FakeKernelAuxiliaryOps>);
        assert_eq!(f as usize, bpf_helper as usize);
    }
}
