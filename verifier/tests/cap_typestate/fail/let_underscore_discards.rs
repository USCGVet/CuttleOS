//! Negative fixture: `let _ = check_cap(...)` discards the proof.
//!
//! The old AST walker accepted this candidate because the source
//! string `check_cap` did appear inside the dispatcher body. The
//! type-state contract rejects it because `privileged_action`
//! requires a `CapProof` by value, and `let _ = ...` consumed the
//! proof on the unrelated discard binding.

use cuttle_contracts::{CapError, CapProof, SyscallCapTable};

struct PermissiveTable;

impl SyscallCapTable for PermissiveTable {
    type Cap = u64;
    fn check_raw(&self, _t: u64, _c: u64, _n: u32) -> Result<(), CapError> {
        Ok(())
    }
}

fn privileged_action(_proof: CapProof, input: u64) -> u64 {
    input + 1
}

fn main() {
    let table = PermissiveTable;
    // Discards the proof on the `_` binding.
    let _ = table.check(0, u64::MAX, 0);
    // No CapProof in scope — this must FAIL to compile.
    let _ = privileged_action(42);
}
