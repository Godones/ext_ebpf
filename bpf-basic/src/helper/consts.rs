/// Helper function IDs for BPF programs.
pub const HELPER_MAP_LOOKUP_ELEM: u32 = 1;
pub const HELPER_MAP_UPDATE_ELEM: u32 = 2;
pub const HELPER_MAP_DELETE_ELEM: u32 = 3;
pub const HELPER_KTIME_GET_NS: u32 = 5;
pub const HELPER_MAP_FOR_EACH_ELEM: u32 = 164;
pub const HELPER_MAP_LOOKUP_PERCPU_ELEM: u32 = 195;
pub const HELPER_PERF_EVENT_OUTPUT: u32 = 25;
pub const HELPER_BPF_PROBE_READ: u32 = 4;
pub const HELPER_TRACE_PRINTF: u32 = 6;
pub const HELPER_MAP_PUSH_ELEM: u32 = 87;
pub const HELPER_MAP_POP_ELEM: u32 = 88;
pub const HELPER_MAP_PEEK_ELEM: u32 = 89;

/// Other constants used in BPF programs.
pub const BPF_F_CURRENT_CPU: u64 = 4294967295;
