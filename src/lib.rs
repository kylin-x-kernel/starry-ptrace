#![no_std]

mod state;
mod hook;
mod mm;
pub mod arch;

use axerrno::{AxError, AxResult};
use axtask::current;
use axlog::debug;
use arch::current::UserRegs;
use starry_process::Pid;
use crate::arch::RegAccess;
use starry_vm::{vm_read_slice, vm_write_slice};
use starry_core::task::{AsThread, send_signal_to_process};
use starry_signal::{SignalInfo, Signo};
use axhal::uspace::UserContext;


const REQ_TRACEME: u32 = 0;
const REQ_GETREGS: u32 = 12;
const REQ_DETACH: u32 = 17;
const REQ_CONT: u32 = 7;
const REQ_PEEKDATA: u32 = 2;
// Linux request numbers (subset)
// PTRACE_SETOPTIONS is 0x4200 per uapi/ptrace.h
const REQ_SETOPTIONS: u32 = 0x4200;
const REQ_SYSCALL: u32 = 24;
// Regset-based register access (used by strace on AArch64)
const REQ_GETREGSET: u32 = 0x4204;
// Minimal note type for general-purpose regs
const NT_PRSTATUS: usize = 1;
use state::{ensure_state_for_current, ensure_state_for_pid, set_syscall_tracing, resume_pid, PtraceOptions};

// Export for use in execve syscall
pub use state::{stop_current_and_wait, StopReason};

/// Minimal ptrace dispatcher for Phase 1.
///
/// - PTRACE_TRACEME: 标记当前进程被父进程跟踪（仅设置状态，不做唤醒/等待）。
/// - PTRACE_SYSCALL: 开启“下一次系统调用入口/出口停靠”的跟踪模式（仅设置状态）。
/// 其余请求暂返回 EINVAL，后续阶段逐步补齐。
pub fn do_ptrace(request: u32, pid: Pid, addr: usize, data: usize) -> AxResult<isize> {
    hook::register_hooks_once();

    match request {
        REQ_TRACEME => {
            let st = ensure_state_for_current()?;
            let curr_pid = current().as_thread().proc_data.proc.pid();
            let parent = {
                let curr = current();
                let proc = &curr.as_thread().proc_data.proc;
                proc.parent().map(|p| p.pid())
            };

            if parent.is_none() {
                debug!("ptrace: TRACEME called but no parent for pid={}", curr_pid);
                return Err(AxError::InvalidInput);
            }

            // Check if already being traced (prevent duplicate TRACEME)
            let already_traced = st.with(|s| s.being_traced);
            if already_traced {
                debug!("ptrace: TRACEME called but already traced, pid={}", curr_pid);
                return Err(AxError::InvalidInput);
            }

            st.with_mut(|s| {
                s.being_traced = true;
                s.tracer = parent;
            });
            // Debug: record that TRACEME was requested and which tracer we recorded.
            debug!("[PTRACE-DEBUG] TRACEME success: pid={} tracer={}", curr_pid, parent.unwrap());
            Ok(0)
        }
        REQ_GETREGS => {
            let st = ensure_state_for_pid(pid)?;
            let regs = st.with(|s| {
                if !s.stopped {
                    return Err(AxError::InvalidInput);
                }
                if let Some(saved) = s.saved {
                    Ok(UserRegs::from_ctx(&saved.tf, saved.sp))
                } else { Err(AxError::InvalidInput) }
            })?;

            // Copy the registers to the user-space pointer `data`.
            // This assumes a kernel utility for safe user-space memory writes.
            let buf = unsafe {
                core::slice::from_raw_parts(
                    &regs as *const UserRegs as *const u8,
                    core::mem::size_of::<UserRegs>(),
                )
            };
            vm_write_slice(data as *mut u8, buf)?;
            Ok(0)
        }
        REQ_CONT => {
            // Resume the specified pid, optionally injecting a signal
            // The 'data' parameter contains the signal number to inject/deliver (0 = suppress)
            debug!("[PTRACE-DEBUG] PTRACE_CONT request for pid={} with signal={}", pid, data);

            let st = ensure_state_for_pid(pid)?;

            // Check if we're resuming from a signal-delivery-stop
            let stop_signal = st.with(|s| {
                if let Some(state::StopReason::Signal(sig)) = s.stop_reason {
                    Some(sig)
                } else {
                    None
                }
            });

            st.with_mut(|s| {
                debug!("[PTRACE-DEBUG] PTRACE_CONT clearing stopped state for pid={}, was stopped={} reason={:?}",
                       pid, s.stopped, s.stop_reason);
                s.stopped = false;
                s.stop_reason = None;
                s.saved = None;
                s.stop_reported = false;
            });

            // Handle signal injection/delivery based on stop reason
            if let Some(stopped_at_signal) = stop_signal {
                // We're resuming from a signal-delivery-stop
                debug!("[PTRACE-DEBUG] PTRACE_CONT resuming from signal-delivery-stop (sig={}), data={}",
                       stopped_at_signal, data);

                if data == 0 {
                    // data=0 means suppress the signal - the signal is already pending,
                    // and by not re-injecting it and just resuming, the check_signals
                    // has already returned, so the signal won't be processed
                    debug!("[PTRACE-DEBUG] PTRACE_CONT suppressing signal {}", stopped_at_signal);
                } else if data as i32 == stopped_at_signal {
                    // data matches the stop signal - let it proceed (don't inject new one)
                    // The signal is already pending and will be processed after resume
                    debug!("[PTRACE-DEBUG] PTRACE_CONT letting pending signal {} proceed", stopped_at_signal);
                } else {
                    // data is different - inject the new signal to replace the old one
                    if let Some(signo) = Signo::from_repr(data as u8) {
                        debug!("[PTRACE-DEBUG] PTRACE_CONT replacing signal {} with {:?}", stopped_at_signal, signo);
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
                // Not at a signal-delivery-stop, inject new signal
                if let Some(signo) = Signo::from_repr(data as u8) {
                    debug!("[PTRACE-DEBUG] PTRACE_CONT injecting signal {:?} into pid={}", signo, pid);
                    let sig_info = SignalInfo::new_kernel(signo);
                    if let Err(e) = send_signal_to_process(pid, Some(sig_info)) {
                        debug!("ptrace: PTRACE_CONT failed to inject signal: {:?}", e);
                        return Err(e);
                    }
                    debug!("[PTRACE-DEBUG] PTRACE_CONT signal {:?} injected into pid={}", signo, pid);
                } else {
                    debug!("ptrace: PTRACE_CONT invalid signal number: {}", data);
                    return Err(AxError::InvalidInput);
                }
            }

            resume_pid(pid as _);
            debug!("[PTRACE-DEBUG] PTRACE_CONT completed for pid={}", pid);
            Ok(0)
        }
        REQ_DETACH => {
            // Clear tracing state and resume the task.
            let st = ensure_state_for_pid(pid)?;
            st.with_mut(|s| {
                s.being_traced = false;
                s.syscall_trace = false;
                s.tracer = None;
            });
            resume_pid(pid as _);
            Ok(0)
        }
        REQ_SYSCALL => {
            // Linux: 通常由 tracer 对 tracee 调用；Phase 1 允许 pid=0 代表当前。
            // The 'data' parameter contains optional signal to inject (0 = no signal)
            debug!("[PTRACE-DEBUG] PTRACE_SYSCALL request for pid={} with signal={}", pid, data);
            let target_pid = if pid == 0 {
                let st = ensure_state_for_current()?;
                set_syscall_tracing(&st, true);
                debug!("[PTRACE-DEBUG] PTRACE_SYSCALL enabled syscall tracing for current process");
                0
            } else {
                let st = ensure_state_for_pid(pid)?;
                set_syscall_tracing(&st, true);
                debug!("[PTRACE-DEBUG] PTRACE_SYSCALL enabled syscall tracing for pid={}", pid);
                pid
            };

            // If data is non-zero, inject that signal into the tracee
            if data != 0 && target_pid != 0 {
                if let Some(signo) = Signo::from_repr(data as u8) {
                    debug!("[PTRACE-DEBUG] PTRACE_SYSCALL injecting signal {:?} into pid={}", signo, target_pid);
                    let sig_info = SignalInfo::new_kernel(signo);
                    if let Err(e) = send_signal_to_process(target_pid, Some(sig_info)) {
                        debug!("ptrace: PTRACE_SYSCALL failed to inject signal: {:?}", e);
                        return Err(e);
                    }
                    debug!("[PTRACE-DEBUG] PTRACE_SYSCALL signal {:?} injected into pid={}", signo, target_pid);
                } else {
                    debug!("ptrace: PTRACE_SYSCALL invalid signal number: {}", data);
                    return Err(AxError::InvalidInput);
                }
            }

            // PTRACE_SYSCALL 语义包含"继续执行直到下一个系统调用入口/出口"。
            debug!("[PTRACE-DEBUG] PTRACE_SYSCALL resuming target pid={}", target_pid);
            resume_pid(target_pid);
            debug!("[PTRACE-DEBUG] PTRACE_SYSCALL completed for target pid={}", target_pid);
            Ok(0)
        }
        REQ_GETREGSET => {
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

            debug!("ptrace: GETREGSET pid={} returning registers: x8(syscall)=0x{:x} x0-x2=0x{:x},0x{:x},0x{:x} pc=0x{:x}",
                  pid, regs.x[8], regs.x[0], regs.x[1], regs.x[2], regs.pc);

            // The user passes a pointer to a single iovec in its address space.
            #[repr(C)]
            struct IoVec {
                iov_base: *mut u8,
                iov_len: usize,
            }
            // Read tracer-provided iovec
            let mut iov = IoVec { iov_base: core::ptr::null_mut(), iov_len: 0 };
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
            let st = ensure_state_for_pid(pid)?;
            if let Some(opts) = PtraceOptions::from_bits(data as u32) {
                st.with_mut(|s| s.options = opts);
                Ok(0)
            } else {
                Err(AxError::InvalidInput)
            }
        }
        REQ_PEEKDATA => {
            let st = ensure_state_for_pid(pid)?;
            let is_stopped = st.with(|s| s.stopped);

            if !is_stopped {
                debug!("ptrace: PEEKDATA pid={} not stopped", pid);
                return Err(AxError::InvalidInput);
            }

            let mut buf = [0u8; 8];
            mm::read_from_tracee(pid, addr, &mut buf)?;
            vm_write_slice(data as *mut u8, &buf)?;

            debug!("ptrace: PEEKDATA pid={} addr=0x{:x} data=0x{:x}", pid, addr, u64::from_le_bytes(buf));
            Ok(0)
        }
        _ => Err(AxError::Unsupported),
    }
}

/// Check if a given pid is in ptrace-stop; return encoded wait status if so.
pub fn check_ptrace_stop(pid: Pid) -> Option<i32> {
    if pid == 0 { return None; }
    // Only report stops for children that are actually traced by the caller.
    let me = current();
    let tracer_pid = me.as_thread().proc_data.proc.pid();
    state::encode_ptrace_stop_status_for_tracer(pid, tracer_pid)
}

/// Check if the current process is being traced.
pub fn is_being_traced() -> bool {
    if let Ok(st) = state::ensure_state_for_current() {
        st.with(|s| s.being_traced)
    } else {
        false
    }
}

/// Stop the current task in a ptrace signal-delivery-stop with given signal.
///
/// This is used by the signal handling path to emulate Linux ptrace behavior
/// where a tracee stops for signal delivery and waits for the tracer to decide
/// whether to deliver or suppress the signal.
#[inline]
pub fn signal_stop(signo: i32, uctx: &UserContext) {
    // Best-effort: only stop if being traced; the helper handles checks.
    state::stop_current_and_wait(state::StopReason::Signal(signo), uctx);
}

/// Clear ptrace state for the current process when it exits.
///
/// This prevents waitpid from seeing stale ptrace stop state when the process
/// becomes a zombie.
pub fn clear_on_exit() {
    let Ok(st) = state::ensure_state_for_current() else { return; };
    st.with_mut(|s| {
        s.stopped = false;
        s.stop_reason = None;
        s.saved = None;
        s.stop_reported = false;
    });
}
