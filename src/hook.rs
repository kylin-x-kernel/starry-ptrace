extern crate alloc;
use axhal::uspace::UserContext;
use axlog::debug;
use core::sync::atomic::{AtomicBool, Ordering};
use starry_core::hooks::{SyscallHook, register_syscall_hook};

use crate::state::{StopReason, ensure_state_for_current, stop_current_and_wait};

pub struct SysHook;

impl SyscallHook for SysHook {
    /// Called on syscall entry.
    ///
    /// This hook checks if the current process is being traced and has syscall tracing enabled.
    /// If so, it stops the current process and waits for the tracer to resume it.
    ///
    /// # Arguments
    /// * `uctx` - The user context of the current task.
    fn on_syscall_entry(&self, uctx: &mut UserContext) {
        let Ok(st) = ensure_state_for_current() else {
            return;
        };
        let should_stop = st.with(|s| s.being_traced && s.syscall_trace);
        if should_stop {
            debug!(
                "ptrace: syscall_entry hook triggered, sysno={} (x8=0x{:x})",
                uctx.sysno(),
                uctx.sysno()
            );
            stop_current_and_wait(StopReason::SyscallEntry, uctx);
        }
    }

    /// Called on syscall exit.
    ///
    /// This hook checks if the current process is being traced and has syscall tracing enabled.
    /// If so, it stops the current process and waits for the tracer to resume it.
    ///
    /// # Arguments
    /// * `uctx` - The user context of the current task.
    fn on_syscall_exit(&self, uctx: &mut UserContext) {
        let Ok(st) = ensure_state_for_current() else {
            return;
        };
        let should_stop = st.with(|s| s.being_traced && s.syscall_trace);
        if should_stop {
            debug!(
                "ptrace: syscall_exit hook triggered, retval=0x{:x}",
                uctx.retval()
            );
            stop_current_and_wait(StopReason::SyscallExit, uctx);
        }
    }
}

/// Register ptrace hooks once.
static HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);

/// Register the ptrace syscall hooks if not already registered.
///
/// This function ensures that the syscall hooks for ptrace are registered only once.
pub fn register_hooks_once() {
    if HOOK_REGISTERED.load(Ordering::Relaxed) {
        return;
    }
    if register_syscall_hook(alloc::boxed::Box::new(SysHook)).is_ok() {
        HOOK_REGISTERED.store(true, Ordering::Relaxed);
    }
}
