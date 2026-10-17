//! Negative fixture: move the proof into a discard helper that
//! does not pass it along, then try to use the privileged action.
//! The proof is gone after the move; the privileged-action call
//! cannot satisfy its `CapProof` parameter.

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

// The proof is consumed here but no proof comes back out.
fn discard_silently(_p: CapProof) {}

fn main() {
    let table = PermissiveTable;
    let proof = table.check(0, u64::MAX, 0).expect("Ok");
    discard_silently(proof);
    // Proof is gone; this must fail to compile.
    let _ = privileged_action(proof, 42);
}
