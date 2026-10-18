//! Capability-table impl for `target_minimal`.
//!
//! Sister module to the morph-managed `lib.rs`. Lives in its own file
//! because the diversifier owns `lib.rs` and rewrites it every cycle;
//! keeping the cap table here insulates it from token-level morphing.
//!
//! The module exposes:
//! - `check_cap` — the free function that mints a [`CapProof`] on a
//!   successful capability check. Every privileged dispatch path must
//!   call this and pass the resulting proof by value to the handler.
//! - `dispatch_syscall` — the dispatcher fn that exemplifies the
//!   type-state pattern: it calls `check_cap`, gets a `CapProof`, and
//!   threads it into `dispatch_inner` by value.
//! - `MinimalCapTable` — the type that `impl
//!   cuttle_contracts::SyscallCapTable for` lives on. Overrides
//!   [`SyscallCapTable::check_raw`]; the default `check` provides the
//!   proof mint.
//!
//! # TASK-020 type-state refactor
//!
//! The previous design relied on a verifier-side AST walker checking
//! that the source string `check_cap` appeared inside the dispatcher
//! body. A morph candidate could defeat that walker by writing
//! `let _ = check_cap(...);` (result ignored) or by hiding the call
//! inside dead code (`if false { check_cap(...)?; }`). Either pattern
//! was accepted by the walker but silently bypassed the capability
//! gate at runtime.
//!
//! The new design closes that hole by making the Rust **compiler**
//! enforce the obligation. `check_cap` returns
//! `Result<CapProof, DemoErrno>`. `CapProof` is a zero-sized type from
//! `cuttle_contracts` whose constructor is private to that crate, so
//! no morph candidate can mint one. `dispatch_inner` takes
//! `_proof: CapProof` by value; the compiler refuses to compile any
//! caller that does not own a fresh proof. The verifier's AST walker
//! is therefore obsolete and is deleted in the same iteration.
//!
//! Backed by a permissive `[u64; 32]` static table. The morph engine
//! will tighten this in a later task.

use cuttle_contracts::{CapError, CapProof, SyscallCapTable};

use crate::DemoErrno;

/// Number of tasks tracked by the seed cap table. Locked at 32.
pub const CAP_TABLE_TASKS: usize = 32;

/// Permissive seed: every task gets every cap. Tightened in a later
/// morph task.
pub const PERMISSIVE_CAP_TABLE: [u64; CAP_TABLE_TASKS] = [u64::MAX; CAP_TABLE_TASKS];

/// Top of the locked syscall-number range mirrored from `target_enterprise`.
/// Numbers >= this bound return `ENOSYS` from `check_cap`.
pub const SYS_MAX: u64 = 12;

/// Per-syscall required-cap mask. Index = syscall number. `0` means
/// "no caps required". The morph engine MUST preserve this mapping.
pub const SYSCALL_REQUIRED_CAPS: [u64; SYS_MAX as usize] = [
    0,                                          // 0: SYS_EXIT
    0,                                          // 1: SYS_WRITE
    0,                                          // 2: SYS_GETPID
    0,                                          // 3: SYS_GETTIME_NS
    0,                                          // 4: SYS_READ_KEY
    cuttle_contracts::caps::FS_BYPASS,         // 5: SYS_OPEN
    0,                                          // 6: SYS_READ
    0,                                          // 7: SYS_CLOSE
    0,                                          // 8: SYS_SLEEP_MS
    0,                                          // 9: SYS_REALTIME_S
    0,                                          // 10: SYS_YIELD
    0,                                          // 11: SYS_CAP_CHECK
];

/// Capability check. Returns a freshly-minted [`CapProof`] iff
/// `cap_mask` includes every bit required by syscall `nr`. The proof
/// is the **only** way to call any of the privileged dispatch entry
/// points; the compiler refuses to type-check a call to
/// [`dispatch_inner`] that does not own a proof.
///
/// Routes through `MinimalCapTable::check`, which is the sole mint
/// site for `CapProof` in the contracts crate's type-state design.
/// A morph candidate cannot mint a `CapProof` by other means: the
/// inner field is private and the seal helper lives in a
/// `pub(crate)` module of `cuttle_contracts`.
pub fn check_cap(nr: u64, cap_mask: u64) -> Result<CapProof, DemoErrno> {
    let table = MinimalCapTable;
    // Route through the trait method so the proof comes from the
    // single sealed mint path in `cuttle_contracts`. The task-id is
    // pinned to 0 because target_minimal does not model multi-task
    // state — the production scheduler uses the real task-id.
    match table.check(0, cap_mask, nr as u32) {
        Ok(proof) => Ok(proof),
        Err(CapError::ENOSYS) => Err(DemoErrno::ENOSYS),
        Err(CapError::EPERM) => Err(DemoErrno::EINVAL),
    }
}

/// Top-level dispatcher demonstrating the type-state pattern. Obtains a
/// `CapProof` from `check_cap`, then hands it to [`dispatch_inner`] by
/// value. The compiler statically enforces that no caller can reach
/// `dispatch_inner` without first passing through `check_cap`.
pub fn dispatch_syscall(
    task_id: u64,
    cap_mask: u64,
    nr: u64,
    a0: u64,
    a1: u64,
    a2: u64,
) -> Result<u64, DemoErrno> {
    let proof: CapProof = check_cap(nr, cap_mask)?;
    let _ = task_id;
    dispatch_inner(nr, a0, a1, a2, proof)
}

/// Privileged dispatch. Takes the `CapProof` by value, consuming it.
/// The signature is the type-state gate: callers cannot fabricate a
/// `CapProof` (its constructor is private to `cuttle_contracts`), so
/// the only way to reach this function is through a successful
/// `check_cap` call.
pub fn dispatch_inner(
    nr: u64,
    a0: u64,
    a1: u64,
    _a2: u64,
    proof: CapProof,
) -> Result<u64, DemoErrno> {
    // Consume the proof. The body below is the privileged region;
    // any future migration to per-handler proofs would split this
    // match into separate fns each taking the proof, but for the
    // minimal target a single consumption point suffices.
    proof.consume();
    match nr {
        0 => Ok(0),
        1 => Ok(a0),
        2 => Ok(a0.wrapping_add(a1)),
        3 => Ok(a0.wrapping_mul(a1)),
        _ => Err(DemoErrno::ENOSYS),
    }
}

/// Concrete [`SyscallCapTable`] impl for `target_minimal`. Overrides
/// the trait's `check_raw` to consult the permissive seed table; the
/// default `check` body in the trait wraps a successful `check_raw`
/// with a [`CapProof`] mint.
pub struct MinimalCapTable;

impl SyscallCapTable for MinimalCapTable {
    type Cap = u64;

    fn check_raw(&self, task_id: u64, cap: u64, syscall_nr: u32) -> Result<(), CapError> {
        if (task_id as usize) >= CAP_TABLE_TASKS {
            return Err(CapError::EPERM);
        }
        if (syscall_nr as u64) >= SYS_MAX {
            return Err(CapError::ENOSYS);
        }
        let task_mask = PERMISSIVE_CAP_TABLE[task_id as usize];
        let effective = task_mask & cap;
        let required = SYSCALL_REQUIRED_CAPS[syscall_nr as usize];
        if (effective & required) == required {
            Ok(())
        } else {
            Err(CapError::EPERM)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permissive_table_allows_everything() {
        let t = MinimalCapTable;
        // task 0, any cap bits set, any syscall in range: allow.
        assert!(t.check(0, u64::MAX, 0).is_ok());
        assert!(t.check(0, u64::MAX, 2).is_ok());
    }

    #[test]
    fn out_of_range_task_is_rejected() {
        let t = MinimalCapTable;
        assert!(matches!(t.check(99, u64::MAX, 0), Err(CapError::EPERM)));
        assert!(matches!(t.check_raw(99, u64::MAX, 0), Err(CapError::EPERM)));
    }

    #[test]
    fn out_of_range_syscall_returns_enosys() {
        let t = MinimalCapTable;
        assert!(matches!(t.check(0, u64::MAX, 999), Err(CapError::ENOSYS)));
        assert!(matches!(t.check_raw(0, u64::MAX, 999), Err(CapError::ENOSYS)));
    }

    #[test]
    fn fs_bypass_required_for_sys_open() {
        // sys_open (nr=5) requires FS_BYPASS. With cap=0 the gate fails.
        assert!(matches!(check_cap(5, 0), Err(DemoErrno::EINVAL)));
        let proof = check_cap(5, cuttle_contracts::caps::FS_BYPASS).expect("Ok");
        proof.consume();
    }

    #[test]
    fn dispatch_syscall_routes_through_check_cap() {
        // Cap mask covers every bit — succeeds.
        assert_eq!(dispatch_syscall(0, u64::MAX, 0, 0, 0, 0), Ok(0));
        assert_eq!(dispatch_syscall(0, u64::MAX, 1, 0xDEAD, 0, 0), Ok(0xDEAD));
        // Unmapped syscall returns ENOSYS via check_cap.
        assert!(matches!(
            dispatch_syscall(0, u64::MAX, 99, 0, 0, 0),
            Err(DemoErrno::ENOSYS)
        ));
        // FS_BYPASS-required syscall denied with zero caps.
        assert!(matches!(
            dispatch_syscall(0, 0, 5, 0, 0, 0),
            Err(DemoErrno::EINVAL)
        ));
    }

    #[test]
    fn check_cap_mints_proof_on_success() {
        // Positive case: a permissive mask returns a CapProof that
        // can be threaded into dispatch_inner.
        let proof = check_cap(0, u64::MAX).expect("Ok");
        let r = dispatch_inner(0, 0, 0, 0, proof);
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn check_cap_rejects_missing_cap() {
        // sys_open requires FS_BYPASS. Calling with no caps returns
        // EINVAL and does NOT mint a proof.
        match check_cap(5, 0) {
            Ok(_) => panic!("unexpected mint of CapProof for forbidden syscall"),
            Err(e) => assert!(matches!(e, DemoErrno::EINVAL)),
        }
    }

    #[test]
    fn check_cap_rejects_out_of_range() {
        // Syscall numbers >= SYS_MAX return ENOSYS.
        assert!(matches!(check_cap(SYS_MAX, u64::MAX), Err(DemoErrno::ENOSYS)));
        assert!(matches!(check_cap(9_999, u64::MAX), Err(DemoErrno::ENOSYS)));
    }

    #[test]
    fn dispatch_inner_consumes_proof() {
        // dispatch_inner takes the proof by value. The compiler
        // enforces this; the runtime assertion is that no panic
        // happens during the consume.
        let proof = check_cap(1, u64::MAX).expect("Ok");
        let r = dispatch_inner(1, 42, 0, 0, proof);
        assert_eq!(r, Ok(42));
    }

    #[test]
    fn cap_table_check_is_provided_via_check_raw() {
        // The trait's `check` is a provided method; impls override
        // `check_raw`. Confirm both paths agree on the verdict.
        let t = MinimalCapTable;
        // Privileged syscall, no caps: check_raw should say EPERM
        // and check should propagate.
        assert!(matches!(t.check_raw(0, 0, 5), Err(CapError::EPERM)));
        assert!(matches!(t.check(0, 0, 5), Err(CapError::EPERM)));
        // With FS_BYPASS, both succeed.
        assert!(t.check_raw(0, cuttle_contracts::caps::FS_BYPASS, 5).is_ok());
        let proof = t.check(0, cuttle_contracts::caps::FS_BYPASS, 5).expect("Ok");
        proof.consume();
    }
}
