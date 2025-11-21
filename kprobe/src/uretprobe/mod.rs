use crate::retprobe;

/// The uretprobe structure for the current architecture.
pub type Uretprobe<L, F> = retprobe::Retprobe<L, F>;
