use crate::retprobe;
/// The kretprobe structure for the current architecture.
pub type Kretprobe<L, F> = retprobe::Retprobe<L, F>;
/// The kretprobe builder for the current architecture.
pub type KretprobeBuilder<L> = retprobe::RetprobeBuilder<L>;
