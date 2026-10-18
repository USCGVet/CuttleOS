//! One-shot generator for DemoSyscallDispatch golden vectors. Run with
//! `cargo run -p cuttle-target-minimal --example gen_syscall_goldens`.
//! Prints lines suitable for appending to `golden.txt`. NOT part of the
//! morph contract — this file is build-system scaffolding.

use cuttle_contracts::SyscallDispatch;
use cuttle_target_minimal::{DemoErrno, DemoSyscallDispatch};

fn fmt_res(r: &Result<u64, DemoErrno>) -> String {
    match r {
        Ok(v) => format!("Ok={:016x}", v),
        Err(e) => format!("Err={:?}", e),
    }
}

fn emit(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) {
    let r = DemoSyscallDispatch::dispatch(nr, a0, a1, a2, a3, a4, a5);
    println!(
        "demo_syscall {} {:016x} {:016x} {:016x} {:016x} {:016x} {:016x} {}",
        nr,
        a0,
        a1,
        a2,
        a3,
        a4,
        a5,
        fmt_res(&r),
    );
}

fn main() {
    // 0: sys_noop
    emit(0, 0, 0, 0, 0, 0, 0);
    // 1: sys_identity
    emit(1, 0xdead_beef_cafe_babe, 0, 0, 0, 0, 0);
    // 2: sys_add, normal
    emit(2, 1, 2, 0, 0, 0, 0);
    // 2: sys_add, wrapping overflow
    emit(2, u64::MAX, 1, 0, 0, 0, 0);
    // 3: sys_mul, normal
    emit(3, 7, 6, 0, 0, 0, 0);
    // 3: sys_mul, wrapping overflow
    emit(3, u64::MAX, 2, 0, 0, 0, 0);
    // 4: sys_hash, success path (a3 == 0)
    emit(4, 0x0123_4567_89ab_cdef, 0xfedc_ba98_7654_3210, 0xaaaa_bbbb_cccc_dddd, 0, 0, 0);
    // 4: sys_hash, EFAULT (a3 != 0)
    emit(4, 0, 0, 0, 1, 0, 0);
    // 5: sys_xor_chain
    emit(5, 0x1111_1111_1111_1111, 0x2222_2222_2222_2222,
         0x4444_4444_4444_4444, 0x8888_8888_8888_8888,
         0xFFFF_0000_FFFF_0000, 0x0000_FFFF_0000_FFFF);
    // 6: sys_capability_check, success (required is subset of caller set)
    emit(6, 0b0000_0110, 0b1111_1111, 0, 0, 0, 0);
    // 6: sys_capability_check, fail (required has bit caller lacks)
    emit(6, 0b1000_0000, 0b0000_0001, 0, 0, 0, 0);
    // unmapped
    emit(999_999, 1, 2, 3, 4, 5, 6);
}
