extern crate alloc;
use axhal::uspace::UserContext;
use axlog::error;
use core::sync::atomic::{AtomicBool, Ordering};
use starry_core::hooks::{register_syscall_hook, SyscallHook};

use crate::state::{ensure_state_for_current, stop_current_and_wait, StopReason};

pub struct SysHook;

impl SyscallHook for SysHook {
    fn on_syscall_entry(&self, uctx: &mut UserContext) {
        let Ok(st) = ensure_state_for_current() else { return; };
        let should_stop = st.with(|s| s.being_traced && s.syscall_trace);
        if should_stop {
            error!("ptrace: syscall_entry hook triggered, sysno={} (x8=0x{:x})", uctx.sysno(), uctx.sysno());
            stop_current_and_wait(StopReason::SyscallEntry, uctx);
        }
    }

    fn on_syscall_exit(&self, uctx: &mut UserContext) {
        let Ok(st) = ensure_state_for_current() else { return; };
        let should_stop = st.with(|s| s.being_traced && s.syscall_trace);
        if should_stop {
            error!("ptrace: syscall_exit hook triggered, retval=0x{:x}", uctx.retval());
            stop_current_and_wait(StopReason::SyscallExit, uctx);
        }
    }
}

static HOOK_REGISTERED: AtomicBool = AtomicBool::new(false);

pub fn register_hooks_once() {
    if HOOK_REGISTERED.load(Ordering::Relaxed) {
        return;
    }
    if register_syscall_hook(alloc::boxed::Box::new(SysHook)).is_ok() {
        HOOK_REGISTERED.store(true, Ordering::Relaxed);
    }
}
