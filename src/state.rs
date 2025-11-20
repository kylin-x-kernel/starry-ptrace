#![allow(dead_code)]

extern crate alloc;

use core::{future::poll_fn, task::Poll};

use alloc::boxed::Box;
use axerrno::{AxError, AxResult};
use axlog::info;
use axtask::future::block_on;
use bitflags::bitflags;
use starry_core::task::{get_process_data, get_task, AsThread};
use starry_process::Pid;

use crate::{PTRACE_EVENT_FORK, PTRACE_EVENT_VFORK, PTRACE_EVENT_VFORK_DONE, PTRACE_EVENT_CLONE, PTRACE_EVENT_EXIT, PTRACE_EVENT_EXEC};

const SIGTRAP: i32 = 5;
const SIG_BIT_MASK: i32 = 0x7f;

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
        /// PTRACE_O_TRACEVFORKDONE
        const TRACEVFORKDONE = 0x00000020;
        /// PTRACE_O_TRACEEXIT
        const TRACEEXIT = 0x00000040;
    }
}

/// Reasons for which a traced process may stop, 
/// which can be interpreted as an event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StopReason {
    SyscallEntry,
    SyscallExit,
    Signal(i32),
    Exec,
    Fork(Pid),
    Vfork(Pid),
    VforkDone(Pid),
    Clone(Pid),
    Exit(i32),
}

pub struct PtraceState {
    pub being_traced: bool,
    pub syscall_trace: bool,
    pub stopped: bool,
    pub stop_reason: Option<StopReason>,
    pub tracer: Option<Pid>,
    pub options: PtraceOptions,
    pub saved: Option<SavedCtx>,
    /// Whether the current stop has already been reported to the tracer via waitpid.
    pub stop_reported: bool,
    // tracer's signal decision, indicates whether the signal was injected by the tracer.
    pub injected_signal: Option<i32>,
    /// Track the child pid for which we should emit a VFORK_DONE event.
    pub pending_vfork_done: Option<Pid>,
}

/// Action to take after a signal-delivery-stop.
/// This tells the signal handler what to do with the signal.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignalAction {
    /// Suppress the signal (tracer passed data=0 to PTRACE_CONT)
    Suppress,
    /// Deliver the original signal unchanged
    DeliverOriginal,
    /// Deliver a modified signal (tracer changed the signal number)
    DeliverModified(i32),
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
            tracer: None,
            options: PtraceOptions::empty(),
            saved: None,
            stop_reported: false,
            injected_signal: None,
            pending_vfork_done: None,
        }
    }
}

/// A lightweight handle bound to a thread id, allowing state access helpers.
/// Note: In Linux ptrace semantics, the pid parameter is actually a TID (thread ID).
pub struct ProcState(pub Pid);

impl ProcState {
    /// Run a closure with mutable access to the per-thread ptrace state.
    /// It lazily initializes the state if absent.
    pub fn with_mut<R>(&self, f: impl FnOnce(&mut PtraceState) -> R) -> R {
        let task = get_task(self.0).expect("thread must exist");
        let thread = task.as_thread();
        let mut guard = thread.ptrace_state.lock();
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
        let task = get_task(self.0).expect("thread must exist");
        let thread = task.as_thread();
        let guard = thread.ptrace_state.lock();
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
    // pid=0 represents current in starry_core::task::get_task
    Ok(ProcState(0))
}

pub fn ensure_state_for_pid(pid: Pid) -> AxResult<ProcState> {
    if pid <= 0 {
        return Err(AxError::NoSuchProcess);
    }
    // probe existence - use get_task since ptrace state is now per-thread
    let _ = get_task(pid as Pid)?;
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
    let task = get_task(0).expect("current task");
    let thread = task.as_thread();
    let pd = thread.proc_data.clone();
    let curr_tid = task.id().as_u64() as Pid;

    // Acquire lock and prepare to stop
    let mut guard = thread.ptrace_state.lock();
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
        StopReason::Exec => st.being_traced && st.options.contains(PtraceOptions::TRACEEXEC),
        StopReason::Signal(_) => st.being_traced,
        // Fork/vfork/clone events are explicitly requested via options, so emit
        // them when the option is set.
        StopReason::Fork(_) => st.options.contains(PtraceOptions::TRACEFORK),
        StopReason::Vfork(_) => st.options.contains(PtraceOptions::TRACEVFORK),
        StopReason::Clone(_) => st.options.contains(PtraceOptions::TRACECLONE),
        StopReason::VforkDone(_) => st.options.contains(PtraceOptions::TRACEVFORKDONE),
        StopReason::Exit(_) => st.being_traced && st.options.contains(PtraceOptions::TRACEEXIT),
    };

    info!(
        "[PTRACE-DEBUG] stop_current_and_wait pid={} reason={:?} being_traced={} options={:?} should_stop={}",
        curr_tid,
        reason,
        st.being_traced,
        st.options,
        should_stop
    );

    if !should_stop {
        return;
    }

    // Set stop state, save context
    st.stopped = true;
    st.stop_reason = Some(reason);
    st.saved = Some(SavedCtx {
        tf: **uctx,
        sp: uctx.sp,
    });
    st.stop_reported = false;

    // Determine the signal to report for this stop
    // Syscall stops report SIGTRAP, possibly | 0x80 with TRACESYSGOOD
    const SIGTRAP: i32 = 5;
    let stop_signal = match reason {
        StopReason::SyscallEntry | StopReason::SyscallExit => SIGTRAP,
        StopReason::Exec => SIGTRAP,
        StopReason::Signal(sig) => sig,
        StopReason::Fork(_) | StopReason::Vfork(_) |
        StopReason::VforkDone(_) | StopReason::Clone(_) |
        StopReason::Exit(_) => SIGTRAP,
    };

    let tracer = st.tracer;
    drop(guard);

    info!(
        "[PTRACE-DEBUG] pid={} entering ptrace-stop with signal={}",
        curr_tid, stop_signal
    );

    // Update the tracee to be stopped by ptrace mech with the stop signal
    pd.proc.set_ptrace_stopped(stop_signal);

    // Wake up tracer's waitpid
    if let Some(tracer_pid) = tracer {
        if let Ok(tp) = get_process_data(tracer_pid) {
            tp.child_exit_event.wake();
            info!("[PTRACE-DEBUG] pid={} woke tracer pid={}", curr_tid, tracer_pid);
        }
    }

    // Block until resumed
    info!("[PTRACE-DEBUG] pid={} blocking in ptrace-stop", curr_tid);
    block_on(poll_fn(|cx| {
        if !pd.proc.is_ptrace_stopped() {
            info!("[PTRACE-DEBUG] pid={} resumed from ptrace-stop", curr_tid);
            Poll::Ready(())
        } else {
            pd.child_exit_event.register(cx.waker());
            Poll::Pending
        }
    }));

    info!("[PTRACE-DEBUG] pid={} exited ptrace-stop blocking", curr_tid);
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
    let task = get_task(pid).ok();
    if let Some(task) = task {
        let thread = task.as_thread();
        let pd = thread.proc_data.clone();

        let mut guard = thread.ptrace_state.lock();
        if let Some(b) = guard.as_mut() {
            if let Some(st) = b.as_mut().downcast_mut::<PtraceState>() {
               info!(
                    "[PTRACE-DEBUG] resume_pid pid={} clearing ptrace state (was stopped={}, reason={:?})",
                    pid, st.stopped, st.stop_reason
                );
                st.stopped = false;
                st.stop_reason = None;
                st.saved = None;
                st.stop_reported = false;
            }
        }
        drop(guard);

        // Transition process state from Stopped to Running
        // This will wake the blocked tracee
        pd.proc.resume_from_ptrace_stop();
        info!("[PTRACE-DEBUG] resume_pid pid={} transitioned to Running", pid);

        // Wake the tracee's blocking poll
        pd.child_exit_event.wake();
        info!("[PTRACE-DEBUG] resume_pid pid={} woke child_exit_event", pid);
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
    let task = get_task(pid).ok()?;
    let thread = task.as_thread();
    let guard = thread.ptrace_state.lock();
    let st = guard.as_ref()?.as_ref().downcast_ref::<PtraceState>()?;
    if st.stopped {
        // Encode stop signal:
        // - Syscall stops report SIGTRAP (optionally OR 0x80 with TRACESYSGOOD)
        // - Exec stops report SIGTRAP
        // - Signal-delivery stops report the actual signal number
        let status = match st.stop_reason {
            Some(StopReason::SyscallEntry) | Some(StopReason::SyscallExit) => {
                let mut sig = SIGTRAP;
                // If TRACESYSGOOD is set and this is a syscall stop, set the 0x80 bit
                // By doing so, tracers can distinguish syscall stops from normal SIGTRAP
                if st.options.contains(PtraceOptions::TRACESYSGOOD) {
                    sig |= 0x80;
                }
                sig << 8 | SIG_BIT_MASK
            },
            Some(StopReason::Exec) =>
                (crate::PTRACE_EVENT_EXEC << 16) | (SIGTRAP << 8) | SIG_BIT_MASK,
            Some(StopReason::Signal(n)) => (n << 8) | SIG_BIT_MASK,
            Some(StopReason::Fork(_)) =>
                (PTRACE_EVENT_FORK << 16) | (SIGTRAP << 8) | SIG_BIT_MASK,
            Some(StopReason::Vfork(_)) =>
                (PTRACE_EVENT_VFORK << 16) | (SIGTRAP << 8) | SIG_BIT_MASK,
            Some(StopReason::VforkDone(_)) =>
                (PTRACE_EVENT_VFORK_DONE << 16) | (SIGTRAP << 8) | SIG_BIT_MASK,
            Some(StopReason::Clone(_)) =>
                (PTRACE_EVENT_CLONE << 16) | (SIGTRAP << 8) | SIG_BIT_MASK,
            Some(StopReason::Exit(_)) =>
                (PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | SIG_BIT_MASK,
            None => (SIGTRAP << 8) | SIG_BIT_MASK,
        };
        info!(
            "[PTRACE-DEBUG] encode_ptrace_stop_status pid={} reason={:?} status=0x{:x}",
            pid,
            st.stop_reason,
            status
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
    let task = get_task(pid).ok()?;
    let thread = task.as_thread();
    let mut guard = thread.ptrace_state.lock();
    let st = guard.as_mut()?.as_mut().downcast_mut::<PtraceState>()?;
    // Debug: print the current ptrace state to help diagnose tracer/tracee mismatches
    info!(
        "[PTRACE-DEBUG] encode_for_tracer pid={} stopped={} stop_reported={} st.tracer={:?} expected={}",
        pid, st.stopped, st.stop_reported, st.tracer, expected_tracer
    );

    if st.stopped && !st.stop_reported && st.tracer == Some(expected_tracer) {
        // Mark reported to avoid duplicate waits for the same stop.
        st.stop_reported = true;
        // Compute status using current state values.
        const SIGTRAP: i32 = 5;
        let status = match st.stop_reason {
            Some(StopReason::SyscallEntry) | Some(StopReason::SyscallExit) => {
                let mut sig = SIGTRAP;
                if st.options.contains(PtraceOptions::TRACESYSGOOD) {
                    sig |= 0x80;
                }
                (sig << 8) | SIG_BIT_MASK
            }
            Some(StopReason::Exec) => {
                (crate::PTRACE_EVENT_EXEC << 16) | (SIGTRAP << 8) | SIG_BIT_MASK
            }
            Some(StopReason::Signal(n)) => {
                n << 8 | SIG_BIT_MASK
            }
            Some(StopReason::Fork(_)) => {
                (crate::PTRACE_EVENT_FORK << 16) | (SIGTRAP << 8) | SIG_BIT_MASK
            }

            Some(StopReason::Vfork(_)) => {
                (crate::PTRACE_EVENT_VFORK << 16) | (SIGTRAP << 8) | SIG_BIT_MASK
            }

            Some(StopReason::Clone(_)) => {
                (crate::PTRACE_EVENT_CLONE << 16) | (SIGTRAP << 8) | SIG_BIT_MASK
            }

            Some(StopReason::VforkDone(_)) => {
                (crate::PTRACE_EVENT_VFORK_DONE << 16) | (SIGTRAP << 8) | SIG_BIT_MASK
            }

            Some(StopReason::Exit(_)) => {
                (crate::PTRACE_EVENT_EXIT << 16) | (SIGTRAP << 8) | SIG_BIT_MASK
            }
            None => {
                SIGTRAP << 8 | SIG_BIT_MASK
            }
        };
        info!(
            "[PTRACE-DEBUG] encode stop status pid={} reason={:?} status=0x{:x}",
            pid, st.stop_reason, status
        );
        Some(status)
    } else {
        info!(
            "[PTRACE-DEBUG] encode_for_tracer pid={} NOT returning stop (stopped={} reported={} tracer_match={})",
            pid,
            st.stopped,
            st.stop_reported,
            st.tracer == Some(expected_tracer)
        );
        None
    }
}

/// Notify a traced parent that a vfork child has completed, delivering
/// PTRACE_EVENT_VFORK_DONE if the parent requested it.
pub fn notify_vfork_done(parent_pid: Pid, child_pid: Pid) {
    let Ok(task) = get_task(parent_pid) else {
        return;
    };
    let thread = task.as_thread();
    let pd = thread.proc_data.clone();

    let mut guard = thread.ptrace_state.lock();
    let Some(st) = guard
        .as_mut()
        .and_then(|b| b.as_mut().downcast_mut::<PtraceState>()) else {
        return;
    };

    if !st.being_traced
        || !st.options.contains(PtraceOptions::TRACEVFORKDONE)
        || st.pending_vfork_done != Some(child_pid)
    {
        return;
    }

    // Mark the parent as stopped for VFORK_DONE.
    st.pending_vfork_done = None;
    st.stopped = true;
    st.stop_reason = Some(StopReason::VforkDone(child_pid));
    st.saved = None;
    st.stop_reported = false;
    let tracer_pid = st.tracer;
    drop(guard);

    // Update process state and wake tracer waiters.
    pd.proc.set_ptrace_stopped(SIGTRAP);
    if let Some(tracer_pid) = tracer_pid {
        if let Ok(tp) = get_process_data(tracer_pid) {
            tp.child_exit_event.wake();
        }
    }
    pd.child_exit_event.wake();
}
