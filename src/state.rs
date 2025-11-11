#![allow(dead_code)]

extern crate alloc;

use alloc::boxed::Box;
use axerrno::{AxError, AxResult};
use axlog::{debug, info};
use axtask::future::block_on;
use bitflags::bitflags;
use event_listener::Event;
use starry_core::task::get_process_data;
use starry_process::Pid;

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
    Exec,
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

pub fn ensure_state_for_pid(pid: Pid) -> AxResult<ProcState> {
    if pid <= 0 {
        return Err(AxError::NoSuchProcess);
    }
    // probe existence
    let _ = get_process_data(pid as Pid)?;
    Ok(ProcState(pid as Pid))
}

pub fn set_syscall_tracing(st: &ProcState, on: bool) {
    st.with_mut(|s| s.syscall_trace = on);
}

/// Stop the current process for ptrace and block until resumed.
///
/// This function would:
/// 1. Acquire the ptrace_state lock for the current process.
/// 2. Check if the process is being traced and should stop for the given reason.
/// 3. If so, set up the stop state, create an event listener, and wake the tracer.
/// 4. Release the lock and block the current task until resumed by the tracer.
///
/// In short, this function implements the core logic for ptrace stops, it would
/// not return until the tracer resumes the tracee. The stopping status of the tracee
/// is done by blocking on an event listener that is notified until the tracer resumes it
/// by notifying the event.
///
/// # Arguments
/// * `reason` - The reason for stopping (e.g., syscall entry/exit, signal delivery).
/// * `uctx` - The user context of the current process, used to save state.
pub fn stop_current_and_wait(reason: StopReason, uctx: &axhal::uspace::UserContext) {
    let pd = get_process_data(0).expect("current process");

    // Acquire lock and prepare to stop
    let mut guard = pd.ptrace_state.lock();
    if guard.is_none() {
        *guard = Some(Box::new(PtraceState::new()));
    }
    let st = guard
        .as_mut()
        .and_then(|b| b.as_mut().downcast_mut::<PtraceState>())
        .expect("ptrace_state is not PtraceState");

    // Check if we should stop based on reason and tracing state
    let should_stop = match reason {
        StopReason::SyscallEntry | StopReason::SyscallExit => st.being_traced && st.syscall_trace,
        StopReason::Signal(_) | StopReason::Exec => st.being_traced,
    };

    debug!(
        "[PTRACE-DEBUG] stop_current_and_wait pid={} reason={:?} being_traced={} should_stop={}",
        pd.proc.pid(),
        reason,
        st.being_traced,
        should_stop
    );

    if !should_stop {
        return;
    }

    // Create listener BEFORE releasing lock to prevent race condition
    // where tracer might resume us before we start waiting
    let listener = st.event.listen();

    // Set stop state, save context
    st.stopped = true;
    st.stop_reason = Some(reason);
    st.saved = Some(SavedCtx {
        tf: **uctx,
        sp: uctx.sp,
    });
    st.stop_reported = false;

    debug!(
        "[PTRACE-DEBUG] pid={} stopped for reason={:?}, waking tracer",
        pd.proc.pid(),
        reason
    );

    // Wake up tracer's waitpid if any; waitpid polls child_exit_event.
    if let Some(tracer) = st.tracer {
        if let Ok(tp) = get_process_data(tracer) {
            tp.child_exit_event.wake();
            debug!(
                "[PTRACE-DEBUG] pid={} woke up tracer pid={}",
                pd.proc.pid(),
                tracer
            );
        }
    }

    // Release lock before blocking - listener is already created
    drop(guard);

    debug!(
        "[PTRACE-DEBUG] pid={} about to block waiting for resume",
        pd.proc.pid()
    );

    // Clear interrupt flag before blocking - we're in a signal handler and don't want
    // the signal delivery to cause interruptible() to return early
    let curr = axtask::current();
    let was_interrupted = curr.interrupted();
    debug!(
        "[PTRACE-DEBUG] pid={} interrupt flag before wait: {}",
        pd.proc.pid(),
        was_interrupted
    );

    // Block current task until resumed - use non-interruptible wait
    // because we're in the middle of signal handling
    let _ = block_on(async move {
        listener.await;
        debug!("[PTRACE-DEBUG] pid resumed (listener awakened)");
    });
}

/// Resume a stopped tracee and notify waiters, clearing its stop state.
///
/// This function would:
/// 1. Acquire the ptrace_state lock for the given pid.
/// 2. Check if the process is in a stopped state.
/// 3. If so, clear the stop state and notify any waiters.
///
/// # Arguments
/// * `pid` - The process ID of the tracee to resume.
pub fn resume_pid(pid: Pid) {
    let pd = get_process_data(pid).ok();
    if let Some(pd) = pd {
        let mut guard = pd.ptrace_state.lock();
        if let Some(b) = guard.as_mut() {
            if let Some(st) = b.as_mut().downcast_mut::<PtraceState>() {
                debug!(
                    "[PTRACE-DEBUG] resume_pid pid={} was stopped={} reason={:?}",
                    pid, st.stopped, st.stop_reason
                );
                st.stopped = false;
                st.stop_reason = None;
                st.saved = None;
                st.stop_reported = false;
                st.event.notify(1);
                debug!("[PTRACE-DEBUG] resume_pid pid={} notified event", pid);
            }
        }
    }
}

/// Check if a pid is in a ptrace stop; return encoded wait status if so.
///
/// # Arguments
/// * `pid` - The process ID to check.
///
/// # Returns
/// * `Some(i32)` - Encoded wait status if the tracee is stopped.
/// * `None` - If the tracee is not stopped.
pub fn encode_ptrace_stop_status(pid: Pid) -> Option<i32> {
    let pd = get_process_data(pid).ok()?;
    let guard = pd.ptrace_state.lock();
    let st = guard.as_ref()?.as_ref().downcast_ref::<PtraceState>()?;
    if st.stopped {
        // Encode stop signal:
        // - Syscall stops report SIGTRAP (optionally OR 0x80 with TRACESYSGOOD)
        // - Exec stops report SIGTRAP
        // - Signal-delivery stops report the actual signal number
        const SIGTRAP: i32 = 5;
        let mut sig = match st.stop_reason {
            Some(StopReason::SyscallEntry) | Some(StopReason::SyscallExit) => SIGTRAP,
            Some(StopReason::Exec) => SIGTRAP,
            Some(StopReason::Signal(n)) => n,
            None => SIGTRAP,
        };

        // If TRACESYSGOOD is set and this is a syscall stop, set the 0x80 bit
        // By doing so, tracers can distinguish syscall stops from normal SIGTRAP
        if st.options.contains(PtraceOptions::TRACESYSGOOD)
            && matches!(
                st.stop_reason,
                Some(StopReason::SyscallEntry | StopReason::SyscallExit)
            )
        {
            sig |= 0x80;
        }
        let status = (sig << 8) | 0x7f;
        info!(
            "ptrace: encode stop status pid={} sig={} status=0x{:x}",
            pid, sig, status
        );
        Some(status)
    } else {
        None
    }
}

/// Encode a ptrace stop for a specific tracer, and mark it reported so it will
/// not be returned again until the tracee is resumed.
///
/// # Arguments
/// * `pid` - The process ID of the tracee.
/// * `expected_tracer` - The tracer PID expected to receive the stop.
///
/// # Returns
/// * `Some(i32)` - Encoded wait status if the tracee is stopped and matches the tracer.
/// * `None` - If the tracee is not stopped, already reported, or tracer
pub fn encode_ptrace_stop_status_for_tracer(pid: Pid, expected_tracer: Pid) -> Option<i32> {
    use axlog::debug;
    let pd = get_process_data(pid).ok()?;
    let mut guard = pd.ptrace_state.lock();
    let st = guard.as_mut()?.as_mut().downcast_mut::<PtraceState>()?;
    // Debug: print the current ptrace state to help diagnose tracer/tracee mismatches
    debug!(
        "[PTRACE-DEBUG] encode_for_tracer pid={} stopped={} stop_reported={} st.tracer={:?} expected={}",
        pid, st.stopped, st.stop_reported, st.tracer, expected_tracer
    );

    if st.stopped && !st.stop_reported && st.tracer == Some(expected_tracer) {
        // Mark reported to avoid duplicate waits for the same stop.
        st.stop_reported = true;
        // Compute status using current state values.
        const SIGTRAP: i32 = 5;
        let mut sig = match st.stop_reason {
            Some(StopReason::SyscallEntry) | Some(StopReason::SyscallExit) => SIGTRAP,
            Some(StopReason::Exec) => SIGTRAP,
            Some(StopReason::Signal(n)) => n,
            None => SIGTRAP,
        };
        if st.options.contains(PtraceOptions::TRACESYSGOOD)
            && matches!(
                st.stop_reason,
                Some(StopReason::SyscallEntry | StopReason::SyscallExit)
            )
        {
            sig |= 0x80;
        }
        let status = (sig << 8) | 0x7f;
        debug!(
            "[PTRACE-DEBUG] encode stop status pid={} reason={:?} sig={} status=0x{:x}",
            pid, st.stop_reason, sig, status
        );
        Some(status)
    } else {
        debug!(
            "[PTRACE-DEBUG] encode_for_tracer pid={} NOT returning stop (stopped={} reported={} tracer_match={})",
            pid,
            st.stopped,
            st.stop_reported,
            st.tracer == Some(expected_tracer)
        );
        None
    }
}
