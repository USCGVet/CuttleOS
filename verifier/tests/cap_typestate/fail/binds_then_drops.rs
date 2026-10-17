//! Negative fixture: bind the proof, then `drop()` it (or move it
//! into `consume()`) before calling the privileged action. The
//! borrow checker rejects the privileged-action call because the
//! proof has already been moved.

use proteus_contracts::{CapError, CapProof, SyscallCapTable};

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
    let proof = table.check(0, u64::MAX, 0).expect("Ok");
    // Move the proof into drop. The privileged-action call below
    // cannot reuse it.
    drop(proof);
    let _ = privileged_action(proof, 42);
}
