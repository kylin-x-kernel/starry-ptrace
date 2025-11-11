#![allow(dead_code)]

// Architecture-specific register layout and helpers.

#[cfg(target_arch = "aarch64")]
pub mod aarch64;

// Default re-export for current target.
#[cfg(target_arch = "aarch64")]
pub use aarch64 as current;

/// Common trait to convert between kernel trap frame and ptrace user_regs.
pub trait RegAccess {
    /// Build the user-visible register set from a trap context.
    ///
    /// Some architectures keep SP outside the TrapFrame (e.g., AArch64 stores
    /// user SP in UserContext). So we pass it separately.
    fn from_ctx(tf: &axhal::context::TrapFrame, sp: u64) -> Self
    where
        Self: Sized;
    // fn write_to_trapframe(&self, tf: &mut axhal::context::TrapFrame);
}
