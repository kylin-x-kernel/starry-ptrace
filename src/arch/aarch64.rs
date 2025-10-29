#![allow(dead_code)]

use super::RegAccess;

/// Placeholder for aarch64 user_regs layout for Phase 2.
#[repr(C)]
#[derive(Default)]
pub struct UserRegs {
    pub x: [u64; 31],
    pub sp: u64,
    pub pc: u64,
    pub pstate: u64,
}

impl RegAccess for UserRegs {
    fn from_ctx(tf: &axhal::context::TrapFrame, sp: u64) -> Self {
        let mut regs = UserRegs::default();
        regs.x.copy_from_slice(&tf.x[0..31]);
        regs.sp = sp;
        regs.pc = tf.elr;
        regs.pstate = tf.spsr;
        regs
    }
}
