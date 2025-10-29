#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use event_listener::Event;
use axtask::future::{block_on, interruptible};
use axerrno::{AxError, AxResult};
use starry_core::task::get_process_data;
use starry_process::Pid;
use bitflags::bitflags;
use axlog::{info, warn};

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
    pub struct PtraceOptions: u32 {
        /// PTRACE_O_TRACESYSGOOD
        const TRACESYSGOOD = 0x00000001;
        /// PTRACE_O_TRACEFORK
        const TRACEFORK = 0x00000002;
        /// PTRACE_O_TRACEVFORK
        const TRACEVFORK = 0x00000004;
        /// PTRACE_O_TRACECLONE
        const TRACECLONE = 0x00000008;
        /// PTRACE_O_TRACEEXEC
        const TRACEEXEC = 0x00000010;
        /// PTRACE_O_TRACEEXIT
        const TRACEEXIT = 0x00000040;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    SyscallEntry,
    SyscallExit,
    Signal(i32),
}

pub struct PtraceState {
    pub being_traced: bool,
    pub syscall_trace: bool,
    pub stopped: bool,
    pub stop_reason: Option<StopReason>,
    pub event: Event,
    pub tracer: Option<Pid>,
    pub options: PtraceOptions,
    pub saved: Option<SavedCtx>,
    /// Whether the current stop has already been reported to the tracer via waitpid.
    pub stop_reported: bool,
}

#[derive(Debug, Clone, Copy)]
pub struct SavedCtx {
    pub tf: axhal::context::TrapFrame,
    pub sp: u64,
}

impl PtraceState {
    pub fn new() -> Self {
        Self {
            being_traced: false,
            syscall_trace: false,
            stopped: false,
            stop_reason: None,
            event: Event::new(),
            tracer: None,
            options: PtraceOptions::empty(),
            saved: None,
            stop_reported: false,
        }
    }
}

/// A lightweight handle bound to a process id, allowing state access helpers.
pub struct ProcState(pub Pid);

impl ProcState {
    /// Run a closure with mutable access to the per-process ptrace state.
    /// It lazily initializes the state if absent.
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut PtraceState) -> R) -> R {
        let pd = get_process_data(self.0).expect("process must exist");
        let mut guard = pd.ptrace_state.lock();
        if guard.is_none() {
            *guard = Some(Box::new(PtraceState::new()));
        }
        let st = guard
            .as_mut()
            .and_then(|b| b.as_mut().downcast_mut::<PtraceState>())
            .expect("ptrace_state is not PtraceState");
        f(st)
    }

    /// Run a closure with read-only access.
    /// If the state is not initialized yet, passes a temporary default
    /// `PtraceState` (treat as not traced) to avoid panics in early hooks.
    pub fn with<R>(&self, f: impl FnOnce(&PtraceState) -> R) -> R {
        let pd = get_process_data(self.0).expect("process must exist");
        let guard = pd.ptrace_state.lock();
        if let Some(st) = guard
            .as_ref()
            .and_then(|b| b.as_ref().downcast_ref::<PtraceState>())
        {
            f(st)
        } else {
            let temp = PtraceState::new();
            f(&temp)
        }
    }
}

pub fn ensure_state_for_current() -> AxResult<ProcState> {
    // pid=0 represents current in starry_core::task::get_process_data
    Ok(ProcState(0))
}

pub fn ensure_state_for_pid(pid: i32) -> AxResult<ProcState> {
    if pid < 0 { return Err(AxError::NoSuchProcess); }
    // probe existence
    let _ = get_process_data(pid as Pid)?;
    Ok(ProcState(pid as Pid))
}

pub fn set_syscall_tracing(st: &ProcState, on: bool) {
    st.with_mut(|s| s.syscall_trace = on);
}

/// Stop the current process for ptrace and block until resumed.
pub fn stop_current_and_wait(reason: StopReason, uctx: &axhal::uspace::UserContext) {
    // Prepare a listener under lock, then await notification.
    let listener_needed = {
        let pd = get_process_data(0).expect("current process");
        let mut guard = pd.ptrace_state.lock();
        if guard.is_none() {
            *guard = Some(Box::new(PtraceState::new()));
        }
        let st = guard
            .as_mut()
            .and_then(|b| b.as_mut().downcast_mut::<PtraceState>())
            .expect("ptrace_state is not PtraceState");
        // Mark stopped and record reason when tracing is enabled.
        // Syscall stops require `syscall_trace`; signal-delivery stops always stop.
        let should_stop = match reason {
            StopReason::SyscallEntry | StopReason::SyscallExit => st.being_traced && st.syscall_trace,
            StopReason::Signal(_) => st.being_traced,
        };
        if should_stop {
            st.stopped = true;
            st.stop_reason = Some(reason);
            st.saved = Some(SavedCtx { tf: **uctx, sp: uctx.sp });
            st.stop_reported = false;
            info!("ptrace: pid={} stopped for reason={:?}", pd.proc.pid(), reason);
            // Wake up tracer's waitpid if any; waitpid polls child_exit_event.
            if let Some(tracer) = st.tracer {
                if let Ok(tp) = get_process_data(tracer) {
                    tp.child_exit_event.wake();
                }
            }
            Some(st.event.listen())
        } else {
            None
        }
    };

    if let Some(listener) = listener_needed {
        // Block current task until resumed.
        let _ = block_on(interruptible(async move {
            listener.await;
            // Optionally re-check stopped flag; event guarantees progress.
            info!("ptrace: pid resumed (listener awakened)");
            ()
        }));
    }
}

/// Resume a stopped tracee and notify waiters.
pub fn resume_pid(pid: Pid) {
    let pd = get_process_data(pid).ok();
    if let Some(pd) = pd {
        let mut guard = pd.ptrace_state.lock();
        if let Some(b) = guard.as_mut() {
            if let Some(st) = b.as_mut().downcast_mut::<PtraceState>() {
                st.stopped = false;
                info!("ptrace: resume_pid pid={} clearing stop_reason={:?}", pid, st.stop_reason);
                st.stop_reason = None;
                st.saved = None;
                st.stop_reported = false;
                st.event.notify(1);
            }
        }
    }
}

/// Check if a pid is in a ptrace stop; return encoded wait status if so.
pub fn encode_ptrace_stop_status(pid: Pid) -> Option<i32> {
    let pd = get_process_data(pid).ok()?;
    let guard = pd.ptrace_state.lock();
    let st = guard.as_ref()?.as_ref().downcast_ref::<PtraceState>()?;
    if st.stopped {
        // Encode stop signal:
        // - Syscall stops report SIGTRAP (optionally OR 0x80 with TRACESYSGOOD)
        // - Signal-delivery stops report the actual signal number
        const SIGTRAP: i32 = 5;
        let mut sig = match st.stop_reason {
            Some(StopReason::SyscallEntry) | Some(StopReason::SyscallExit) => SIGTRAP,
            Some(StopReason::Signal(n)) => n,
            None => SIGTRAP,
        };
        if st.options.contains(PtraceOptions::TRACESYSGOOD)
            && matches!(st.stop_reason, Some(StopReason::SyscallEntry | StopReason::SyscallExit))
        {
            sig |= 0x80;
        }
        let status = (sig << 8) | 0x7f;
        info!("ptrace: encode stop status pid={} sig={} status=0x{:x}", pid, sig, status);
        Some(status)
    } else {
        None
    }
}

/// Encode a ptrace stop for a specific tracer, and mark it reported so it will
/// not be returned again until the tracee is resumed.
pub fn encode_ptrace_stop_status_for_tracer(pid: Pid, expected_tracer: Pid) -> Option<i32> {
    let pd = get_process_data(pid).ok()?;
    let mut guard = pd.ptrace_state.lock();
    let st = guard.as_mut()?.as_mut().downcast_mut::<PtraceState>()?;
    // Debug: print the current ptrace state to help diagnose tracer/tracee mismatches
    warn!("ptrace: encode_for_tracer pid={} stopped={} stop_reported={} st.tracer={:?} expected={}",
        pid, st.stopped, st.stop_reported, st.tracer, expected_tracer);

    if st.stopped && !st.stop_reported && st.tracer == Some(expected_tracer) {
        // Mark reported to avoid duplicate waits for the same stop.
        st.stop_reported = true;
        // Compute status using current state values.
        const SIGTRAP: i32 = 5;
        let mut sig = match st.stop_reason {
            Some(StopReason::SyscallEntry) | Some(StopReason::SyscallExit) => SIGTRAP,
            Some(StopReason::Signal(n)) => n,
            None => SIGTRAP,
        };
        if st.options.contains(PtraceOptions::TRACESYSGOOD)
            && matches!(st.stop_reason, Some(StopReason::SyscallEntry | StopReason::SyscallExit))
        {
            sig |= 0x80;
        }
        let status = (sig << 8) | 0x7f;
        warn!("ptrace: encode stop status pid={} reason={:?} sig={} status=0x{:x}", 
              pid, st.stop_reason, sig, status);
        Some(status)
    } else {
        None
    }
}
