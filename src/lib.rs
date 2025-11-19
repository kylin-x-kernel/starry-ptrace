#![no_std]

pub mod arch;
mod hook;
mod mm;
mod state;

use crate::arch::RegAccess;
use arch::current::UserRegs;
use axerrno::{AxError, AxResult};
use axhal::uspace::UserContext;
use axlog::debug;
use axtask::current;
use starry_core::task::{AsThread, send_signal_to_process};
use starry_process::Pid;
use starry_signal::{SignalInfo, Signo};
use starry_vm::{vm_read_slice, vm_write_slice};

const REQ_TRACEME: u32 = 0;
const REQ_GETREGS: u32 = 12;
const REQ_DETACH: u32 = 17;
const REQ_CONT: u32 = 7;
const REQ_PEEKDATA: u32 = 2;
const REQ_ATTACH: u32 = 16;
const REQ_SYSCALL: u32 = 24;
// Linux request numbers (subset)
// PTRACE_SETOPTIONS is 0x4200 per uapi/ptrace.h
const REQ_SETOPTIONS: u32 = 0x4200;
// Used to get event message (e.g., new child PID)
const REQ_GETEVENTMSG: u32 = 0x4201;
// Regset-based register access (used by strace on AArch64)
const REQ_GETREGSET: u32 = 0x4204;
// Minimal note type for general-purpose regs
const NT_PRSTATUS: usize = 1;

pub const PTRACE_EVENT_FORK: i32 = 1;
pub const PTRACE_EVENT_VFORK: i32 = 2;
pub const PTRACE_EVENT_CLONE: i32 = 3;
pub const PTRACE_EVENT_EXEC: i32 = 4;
pub const PTRACE_EVENT_VFORK_DONE: i32 = 5;
pub const PTRACE_EVENT_EXIT: i32 = 6;
pub const PTRACE_EVENT_SECCOMP: i32 = 7;

pub use state::{
    PtraceOptions, ensure_state_for_current, ensure_state_for_pid, resume_pid, set_syscall_tracing, SignalAction
};

// Export for use in execve syscall
pub use state::{StopReason, stop_current_and_wait};

/// Main ptrace interface function, which would be called by the ptrace syscall handler.
///
/// Currently supported requests are:
/// - REQ_TRACEME: Mark the current process as being traced by its parent.
/// - REQ_GETREGS: Retrieve the general-purpose registers of a stopped tracee.
/// - REQ_CONT: Resume a stopped tracee, optionally injecting a signal.
/// - REQ_DETACH: Detach from a tracee and resume it.
/// - REQ_SYSCALL: Resume a tracee and stop at next syscall entry/exit.
/// - REQ_GETREGSET: Retrieve register sets (only NT_PRSTATUS supported).
/// - REQ_SETOPTIONS: Set ptrace options for a tracee.
/// - REQ_PEEKDATA: Read data from a tracee's memory.
///
/// # Arguments
/// * `request` - The ptrace request code.
/// * `pid` - The target process ID for the request.
/// * `addr` - An address or parameter, meaning depends on request.
/// * `data` - Additional data or parameter, meaning depends on request.
///
/// # Returns
/// * `AxResult<isize>` - Result of the ptrace operation, or error.
pub fn do_ptrace(request: u32, pid: Pid, addr: usize, data: usize) -> AxResult<isize> {
    hook::register_hooks_once();

    match request {
        REQ_TRACEME => {
            // Handle TRACEME request for the current process
            // First, get ptrace state, pid, and parent for current process
            let st = ensure_state_for_current()?;
            let curr_pid = current().as_thread().proc_data.proc.pid();
            let parent = {
                let curr = current();
                let proc = &curr.as_thread().proc_data.proc;
                proc.parent().map(|p| p.pid())
            };

            // If no parent, cannot trace, since the only process without a parent is init
            if parent.is_none() {
                debug!("ptrace: TRACEME called but no parent for pid={}", curr_pid);
                return Err(AxError::InvalidInput);
            }

            // Check if already being traced (prevent duplicate TRACEME)
            let already_traced = st.with(|s| s.being_traced);
            if already_traced {
                debug!(
                    "ptrace: TRACEME called but already traced, pid={}",
                    curr_pid
                );
                return Err(AxError::InvalidInput);
            }

            // Mark as being traced by parent
            st.with_mut(|s| {
                s.being_traced = true;
                s.tracer = parent;
            });
            // Debug: record that TRACEME was requested and which tracer we recorded.
            debug!(
                "[PTRACE-DEBUG] TRACEME success: pid={} tracer={}",
                curr_pid,
                parent.unwrap()
            );
            Ok(0)
        }
        REQ_GETREGS => {
            // Handle GETREGS request to retrieve general-purpose registers of a stopped tracee
            // This option won't work under AArch64; use GETREGSET instead.
            debug!("[PTRACE-DEBUG] PTRACE_GETREGS request for pid={}", pid);
            let st = ensure_state_for_pid(pid)?;
            let regs = st.with(|s| {
                if !s.stopped {
                    return Err(AxError::InvalidInput);
                }
                if let Some(saved) = s.saved {
                    Ok(UserRegs::from_ctx(&saved.tf, saved.sp))
                } else {
                    Err(AxError::InvalidInput)
                }
            })?;

            // Copy the registers to the user-space pointer `data`.
            // This assumes a kernel utility for safe user-space memory writes.
            let buf = unsafe {
                core::slice::from_raw_parts(
                    &regs as *const UserRegs as *const u8,
                    core::mem::size_of::<UserRegs>(),
                )
            };
            // Write to user space
            vm_write_slice(data as *mut u8, buf)?;
            Ok(0)
        }
        REQ_CONT => {
            // Handle CONT request to resume a stopped tracee
            // Resume the specified pid, optionally injecting a signal
            // The 'data' parameter contains the signal number to inject/deliver (0 = suppress)
            debug!(
                "[PTRACE-DEBUG] PTRACE_CONT request for pid={} with signal={}",
                pid, data
            );

            // Get ptrace state for the target pid
            let st = ensure_state_for_pid(pid)?;

            // Check if we're resuming from a signal-delivery-stop, extract the delayed-delivery signal
            let stop_signal = st.with(|s| {
                if let Some(state::StopReason::Signal(sig)) = s.stop_reason {
                    Some(sig)
                } else {
                    None
                }
            });

            // Clear stopped state and stop reason, store tracer's signal decision
            st.with_mut(|s| {
                debug!("[PTRACE-DEBUG] PTRACE_CONT clearing stopped state for pid={}, was stopped={} reason={:?}",
                       pid, s.stopped, s.stop_reason);
                s.stopped = false;
                s.stop_reason = None;
                s.saved = None;
                s.stop_reported = false;
                // Store tracer's signal decision (0 = suppress, otherwise the signal number)
                s.injected_signal = if data == 0 { None } else { Some(data as i32) };
            });

            // Handle signal injection/delivery based on stop reason
            if let Some(stopped_at_signal) = stop_signal {
                // We're resuming from a signal-delivery-stop, there is a pending signal
                debug!(
                    "[PTRACE-DEBUG] PTRACE_CONT resuming from signal-delivery-stop (sig={}), data={}",
                    stopped_at_signal, data
                );

                if data == 0 {
                    // data=0 means suppress the signal - the signal is already pending,
                    // and by not re-injecting it and just resuming, the check_signals
                    // has already returned, so the signal won't be processed, simply continue
                    debug!(
                        "[PTRACE-DEBUG] PTRACE_CONT suppressing signal {}",
                        stopped_at_signal
                    );
                } else if data as i32 == stopped_at_signal {
                    // data matches the stop signal - let it proceed (don't inject new one)
                    // The signal is already pending and will be processed after resume, so just continue
                    debug!(
                        "[PTRACE-DEBUG] PTRACE_CONT letting pending signal {} proceed",
                        stopped_at_signal
                    );
                } else {
                    // data is different - inject the new signal to replace the old one
                    if let Some(signo) = Signo::from_repr(data as u8) {
                        debug!(
                            "[PTRACE-DEBUG] PTRACE_CONT replacing signal {} with {:?}",
                            stopped_at_signal, signo
                        );
                        let sig_info = SignalInfo::new_kernel(signo);
                        if let Err(e) = send_signal_to_process(pid, Some(sig_info)) {
                            debug!("ptrace: PTRACE_CONT failed to inject signal: {:?}", e);
                            return Err(e);
                        }
                    } else {
                        debug!("ptrace: PTRACE_CONT invalid signal number: {}", data);
                        return Err(AxError::InvalidInput);
                    }
                }
            } else if data != 0 {
                // Not at a signal-delivery-stop, the request is to inject a new signal
                if let Some(signo) = Signo::from_repr(data as u8) {
                    debug!(
                        "[PTRACE-DEBUG] PTRACE_CONT injecting signal {:?} into pid={}",
                        signo, pid
                    );
                    let sig_info = SignalInfo::new_kernel(signo);
                    if let Err(e) = send_signal_to_process(pid, Some(sig_info)) {
                        debug!("ptrace: PTRACE_CONT failed to inject signal: {:?}", e);
                        return Err(e);
                    }
                    debug!(
                        "[PTRACE-DEBUG] PTRACE_CONT signal {:?} injected into pid={}",
                        signo, pid
                    );
                } else {
                    debug!("ptrace: PTRACE_CONT invalid signal number: {}", data);
                    return Err(AxError::InvalidInput);
                }
            }

            // After handling signal injection/delivery, resume the tracee
            resume_pid(pid as _);
            debug!("[PTRACE-DEBUG] PTRACE_CONT completed for pid={}", pid);
            Ok(0)
        }
        REQ_DETACH => {
            // Handle the DETACH request to stop tracing a tracee and resume it
            debug!("[PTRACE-DEBUG] PTRACE_DETACH request for pid={}", pid);
            // Clear tracing state and resume the task.
            let st = ensure_state_for_pid(pid)?;
            // Clear being_traced and syscall_trace flags
            st.with_mut(|s| {
                s.being_traced = false;
                s.syscall_trace = false;
                s.tracer = None;
            });
            // Resume the detached process
            resume_pid(pid as _);
            Ok(0)
        }
        REQ_SYSCALL => {
            // Handle the SYSCALL request to enable syscall tracing and resume the tracee
            // In Linux, this is typically called by the tracer on the tracee,
            // we now allow pid=0 to mean the current process.
            // The 'data' parameter contains optional signal to inject (0 = no signal)
            debug!(
                "[PTRACE-DEBUG] PTRACE_SYSCALL request for pid={} with signal={}",
                pid, data
            );
            let target_pid = if pid == 0 {
                // If pid=0, operate on current process
                let st = ensure_state_for_current()?;
                set_syscall_tracing(&st, true);
                debug!("[PTRACE-DEBUG] PTRACE_SYSCALL enabled syscall tracing for current process");
                0
            } else {
                // Operate on specified pid
                let st = ensure_state_for_pid(pid)?;
                set_syscall_tracing(&st, true);
                debug!(
                    "[PTRACE-DEBUG] PTRACE_SYSCALL enabled syscall tracing for pid={}",
                    pid
                );
                pid
            };

            // If data is non-zero, inject that signal into the tracee
            if data != 0 && target_pid != 0 {
                if let Some(signo) = Signo::from_repr(data as u8) {
                    debug!(
                        "[PTRACE-DEBUG] PTRACE_SYSCALL injecting signal {:?} into pid={}",
                        signo, target_pid
                    );
                    let sig_info = SignalInfo::new_kernel(signo);
                    if let Err(e) = send_signal_to_process(target_pid, Some(sig_info)) {
                        debug!("ptrace: PTRACE_SYSCALL failed to inject signal: {:?}", e);
                        return Err(e);
                    }
                    debug!(
                        "[PTRACE-DEBUG] PTRACE_SYSCALL signal {:?} injected into pid={}",
                        signo, target_pid
                    );
                } else {
                    debug!("ptrace: PTRACE_SYSCALL invalid signal number: {}", data);
                    return Err(AxError::InvalidInput);
                }
            }

            // After enabling syscall tracing (and optional signal injection), resume the tracee
            // This is required by ptrace semantics to continue execution, which would pause
            // the tracee at the next syscall entry/exit or signal delivery.
            debug!(
                "[PTRACE-DEBUG] PTRACE_SYSCALL resuming target pid={}",
                target_pid
            );
            resume_pid(target_pid);
            debug!(
                "[PTRACE-DEBUG] PTRACE_SYSCALL completed for target pid={}",
                target_pid
            );
            Ok(0)
        }
        REQ_GETREGSET => {
            // Handle GETREGSET request to retrieve register sets of a stopped tracee
            // This is used by strace on AArch64 instead of GETREGS
            debug!(
                "[PTRACE-DEBUG] PTRACE_GETREGSET request for pid={} addr={} data=0x{:x}",
                pid, addr, data
            );
            // Only support NT_PRSTATUS for now.
            if addr != NT_PRSTATUS {
                debug!("ptrace: GETREGSET unsupported note type addr={}", addr);
                return Err(AxError::Unsupported);
            }

            // Target must be stopped and have a saved context.
            let st = ensure_state_for_pid(pid)?;
            let regs = st.with(|s| {
                if !s.stopped {
                    debug!("ptrace: GETREGSET pid={} not stopped", pid);
                    return Err(AxError::InvalidInput);
                }
                if let Some(saved) = s.saved {
                    Ok(UserRegs::from_ctx(&saved.tf, saved.sp))
                } else {
                    debug!("ptrace: GETREGSET pid={} no saved context", pid);
                    Err(AxError::InvalidInput)
                }
            })?;

            debug!(
                "ptrace: GETREGSET pid={} returning registers: x8(syscall)=0x{:x} x0-x2=0x{:x},0x{:x},0x{:x} pc=0x{:x}",
                pid, regs.x[8], regs.x[0], regs.x[1], regs.x[2], regs.pc
            );

            // The user passes a pointer to a single iovec in its address space.
            #[repr(C)]
            struct IoVec {
                iov_base: *mut u8,
                iov_len: usize,
            }
            // Read tracer-provided iovec
            let mut iov = IoVec {
                iov_base: core::ptr::null_mut(),
                iov_len: 0,
            };
            unsafe {
                // Read user iovec into our local struct memory.
                let dst = core::slice::from_raw_parts_mut(
                    (&mut iov as *mut IoVec) as *mut core::mem::MaybeUninit<u8>,
                    core::mem::size_of::<IoVec>(),
                );
                vm_read_slice(data as *const u8, dst)?;
            }

            // Copy out regs up to iov_len
            let regs_bytes = unsafe {
                core::slice::from_raw_parts(
                    &regs as *const UserRegs as *const u8,
                    core::mem::size_of::<UserRegs>(),
                )
            };
            let copy_len = core::cmp::min(iov.iov_len, regs_bytes.len());
            vm_write_slice(iov.iov_base, &regs_bytes[..copy_len])?;
            // Update iov_len with the actual size written, like Linux does.
            iov.iov_len = copy_len;
            // Write iovec back
            unsafe {
                let bytes = core::slice::from_raw_parts(
                    &iov as *const IoVec as *const u8,
                    core::mem::size_of::<IoVec>(),
                );
                vm_write_slice(data as *mut u8, bytes)?;
            }
            Ok(0)
        }
        REQ_SETOPTIONS => {
            // Handle SETOPTIONS request to set ptrace options for a tracee
            debug!(
                "[PTRACE-DEBUG] PTRACE_SETOPTIONS request for pid={} options=0x{:x}",
                pid, data
            );
            // Set the options in the ptrace state
            let st = ensure_state_for_pid(pid)?;
            // Parse options from data, if valid, set them into the state
            if let Some(opts) = PtraceOptions::from_bits(data as u32) {
                st.with_mut(|s| s.options = opts);
                Ok(0)
            } else {
                Err(AxError::InvalidInput)
            }
        }
        REQ_PEEKDATA => {
            // Handle PEEKDATA request to read data from a tracee's memory
            debug!(
                "[PTRACE-DEBUG] PTRACE_PEEKDATA request for pid={} addr=0x{:x}",
                pid, addr
            );
            // Target must be stopped
            let st = ensure_state_for_pid(pid)?;
            let is_stopped = st.with(|s| s.stopped);

            if !is_stopped {
                debug!("ptrace: PEEKDATA pid={} not stopped", pid);
                return Err(AxError::InvalidInput);
            }

            // Read a word (8 bytes) from the tracee's memory at the specified address
            // The reason why we read 8 bytes is that on AArch64, ptrace PEEKDATA reads a word-sized value.
            let mut buf = [0u8; 8];
            mm::read_from_tracee(pid, addr, &mut buf)?;
            vm_write_slice(data as *mut u8, &buf)?;

            debug!(
                "ptrace: PEEKDATA pid={} addr=0x{:x} data=0x{:x}",
                pid,
                addr,
                u64::from_le_bytes(buf)
            );
            Ok(0)
        }
        REQ_ATTACH => {
            // Handle ATTACH request to begin tracing a target process
            // Currently, the granularity is per-process, so we mark the target as being traced by the current process
            // TODO: implement thread-level tracing if needed
            debug!("[PTRACE-DEBUG] PTRACE_ATTACH request for pid={}", pid);

            // Now we begin permission checking, any process, either in invalid states or already being traced, cannot be attached to.
            let st = ensure_state_for_pid(pid)?;
            let already_traced = st.with(|s| s.being_traced);
            if already_traced {
                debug!(
                    "[PTRACE-DEBUG] PTRACE_ATTACH failed: pid={} already being traced",
                    pid
                );
                return Err(AxError::InvalidInput);
            }

            // Also, attaching to init or the tracer itself is not allowed.
            let tracer_pid = current().as_thread().proc_data.proc.pid();
            if pid == 1 || pid == tracer_pid {
                debug!(
                    "[PTRACE-DEBUG] PTRACE_ATTACH failed: pid={} cannot attach to init or self",
                    pid
                );
                return Err(AxError::InvalidInput);
            }

            // TODO: Permission checks: (PTRACE_MODE_ATTACH_REALCREDS / CAP_SYS_PTRACE / LSM)
            // TODO: Check if the target process is in a state that allows attaching (not exiting, etc.)
            // Need to add functions to check process states in starry_process or starry_core.
            // let tracee_proc= get_process_data(pid)?;
            // if tracee_proc.is_exiting() {
            //     debug!("[PTRACE-DEBUG] PTRACE_ATTACH failed: pid={} is exiting", pid);
            //     return Err(AxError::InvalidInput);
            // }

            // Establish tracing relationship
            st.with_mut(|s| {
                s.being_traced = true;
                s.tracer = Some(tracer_pid);
            });
            debug!(
                "[PTRACE-DEBUG] PTRACE_ATTACH established tracing: pid={} tracer={}",
                pid, tracer_pid
            );

            // Send SIGSTOP to the target process to stop it
            // The reason why we set the tracer in the ProcState before sending SIGSTOP is to ensure that
            // when the target process stops and enters the signal handling path, it can correctly identify
            // the tracer and behave accordingly.
            // Also, if we send SIGSTOP before setting the tracer, there is a race condition that could lead to
            // the target tracee process being stopped but not recognized as being traced, causing the
            // `stop_current_and_wait` function fail to wake the tracer later, causing a hang.
            let sig_stop_info = SignalInfo::new_kernel(Signo::SIGSTOP);
            if let Err(e) = send_signal_to_process(pid, Some(sig_stop_info)) {
                debug!("ptrace: PTRACE_ATTACH failed to send SIGSTOP: {:?}", e);
                // Rollback tracing state on failure of delivering SIGSTOP to tracee
                st.with_mut(|s| {
                    s.being_traced = false;
                    s.tracer = None;
                });
                debug!(
                    "[PTRACE-DEBUG] PTRACE_ATTACH rolled back tracing state for pid={}",
                    pid
                );
                return Err(e);
            }
            debug!("[PTRACE-DEBUG] PTRACE_ATTACH sent SIGSTOP to pid={}", pid);
            debug!(
                "[PTRACE-DEBUG] PTRACE_ATTACH success: pid={} tracer={}",
                pid, tracer_pid
            );
            Ok(0)
        }
        REQ_GETEVENTMSG => {
            // Handle the GETEVENTMSG request to retrieve event message from a stopped tracee
            // This is used to get information about certain ptrace events, such as new child PIDs
            debug!(
                "[PTRACE-DEBUG] PTRACE_GETEVENTMSG request for pid={}",
                pid
            );
            // First, start with checking if the target is stopped
            let st = ensure_state_for_pid(pid)?;
            let event_msg = st.with(|s| {
                // We don't have an event message unless stopped
                if !s.stopped {
                    debug!("ptrace: GETEVENTMSG pid={} not stopped", pid);
                    return Err(AxError::InvalidInput);
                }

                match s.stop_reason {
                    // For fork/vfork/clone events, return the new child PID for the tracer who queries it
                    Some(StopReason::Fork(child_pid)) | Some(StopReason::Vfork(child_pid)) | Some(StopReason::Clone(child_pid)) => Ok(child_pid as usize),
                    // For exit event, return the exit status
                    Some(StopReason::Exit(exit_status)) => Ok(exit_status as usize),
                    // TODO: handle other event types like EXEC, SECCOMP if needed
                    _ => {
                        debug!("ptrace: GETEVENTMSG pid={} no event message available", pid);
                        Err(AxError::InvalidInput)
                    }
                }
            })?;

            // Write the event message back to user space
            vm_write_slice(data as *mut u8, &event_msg.to_ne_bytes())?;
            debug!(
                "[PTRACE-DEBUG] PTRACE_GETEVENTMSG pid={} event_msg=0x{:x}",
                pid, event_msg
            );
            Ok(0)
        }
        _ => Err(AxError::Unsupported),
    }
}

/// Check if a given pid is in ptrace-stop; return encoded wait status if so.
///
/// # Arguments
/// * `pid` - The process ID to check.
///
/// # Returns
/// * `Some(i32)` - Encoded wait status if the tracee is stopped.
/// * `None` - If the tracee is not stopped.
pub fn check_ptrace_stop(pid: Pid) -> Option<i32> {
    if pid == 0 {
        return None;
    }
    // Only report stops for children that are actually traced by the caller.
    let me = current();
    let tracer_pid = me.as_thread().proc_data.proc.pid();
    state::encode_ptrace_stop_status_for_tracer(pid, tracer_pid)
}

/// Check if the current process is being traced.
///
/// # Returns
/// * `bool` - True if the **current** process is being traced, false otherwise.
pub fn is_being_traced() -> bool {
    if let Ok(st) = state::ensure_state_for_current() {
        st.with(|s| s.being_traced)
    } else {
        false
    }
}

/// Check if a specific tracer PID is tracing a specific tracee PID.
///
/// This is used by waitpid to verify that the caller is the tracer of a process
/// before reporting ptrace stops (needed for `strace -p` on non-child processes).
///
/// # Arguments
/// * `tracer_pid` - The PID of the potential tracer
/// * `tracee_pid` - The PID of the potential tracee
///
/// # Returns
/// * `bool` - True if tracer_pid is tracing tracee_pid, false otherwise
pub fn is_tracer_of(tracer_pid: Pid, tracee_pid: Pid) -> bool {
    if let Ok(st) = state::ensure_state_for_pid(tracee_pid) {
        st.with(|s| s.tracer == Some(tracer_pid))
    } else {
        false
    }
}

/// Check if the current process is tracing a specific PID.
///
/// # Arguments
/// * `pid` - The process ID to check.
///
/// # Returns
/// * `bool` - True if the current process is tracing the specified PID, false otherwise.
pub fn is_tracing(pid: Pid) -> bool {
    let tracer_pid = current().as_thread().proc_data.proc.pid();
    if let Ok(st) = state::ensure_state_for_pid(pid) {
        let result = st.with(|s| {
            debug!(
                "[PTRACE-DEBUG] is_tracing: checking pid={} from tracer={} being_traced={} s.tracer={:?}",
                pid, tracer_pid, s.being_traced, s.tracer
            );
            s.being_traced && s.tracer == Some(tracer_pid)
        });
        debug!("[PTRACE-DEBUG] is_tracing: pid={} result={}", pid, result);
        result
    } else {
        debug!("[PTRACE-DEBUG] is_tracing: pid={} ensure_state_for_pid FAILED", pid);
        false
    }
}

/// Stop the current task in a ptrace signal-delivery-stop with given signal.
///
/// This is used by the signal handling path to emulate Linux ptrace behavior
/// where a tracee stops for signal delivery and waits for the tracer to decide
/// whether to deliver or suppress the signal.
///
/// Instead of sending a stop signal,
/// we directly enter a ptrace stop state and block the tracee until resumed by the tracer.
///
/// # Arguments
/// * `signo` - The signal number causing the stop.
/// * `uctx` - The user context of the current task.
///
/// # Returns
/// * `SignalAction` - The action to take with the signal (suppress, deliver original, or deliver modified)
#[inline]
pub fn signal_stop(signo: i32, uctx: &UserContext) -> state::SignalAction {
    // Best-effort: only stop if being traced; the helper handles checks.
    state::stop_current_and_wait(state::StopReason::Signal(signo), uctx);

    // After resume, check what the tracer decided
    let st = state::ensure_state_for_current().unwrap();
    st.with(|s| {
        match s.injected_signal {
            None => {
                // Tracer passed data=0 → suppress the signal
                state::SignalAction::Suppress
            }
            Some(new_sig) if new_sig == signo => {
                // Tracer passed the same signal → deliver original
                state::SignalAction::DeliverOriginal
            }
            Some(new_sig) => {
                // Tracer changed the signal number → deliver modified
                state::SignalAction::DeliverModified(new_sig)
            }
        }
    })
}

/// Clear ptrace state for the current process when it exits.
///
/// This prevents waitpid from seeing stale ptrace stop state when the process
/// becomes a zombie.
pub fn clear_on_exit() {
    let Ok(st) = state::ensure_state_for_current() else {
        return;
    };
    st.with_mut(|s| {
        s.stopped = false;
        s.stop_reason = None;
        s.saved = None;
        s.stop_reported = false;
    });
}

/// Get the corresponding tracer PID, if any, for a given process.
///
/// # Arguments
/// * `pid` - The process ID to check.
///
/// # Returns
/// * `Ok(Pid)` - The tracer PID if the process is being traced.
/// * `Err(AxError)` - If the process is not being traced or doesn't exist.
pub fn get_tracer(pid: Pid) -> AxResult<Pid> {
    let st = state::ensure_state_for_pid(pid)?;
    st.with(|s| {
        if s.being_traced {
            s.tracer.ok_or(AxError::NotFound)
        } else {
            Err(AxError::NotFound)
        }
    })
}
