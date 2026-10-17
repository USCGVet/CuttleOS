//! Positive fixture: the canonical type-state usage MUST compile.
//!
//! Obtain a `CapProof` via `SyscallCapTable::check`, then pass it by
//! value into a privileged action. This is what every legitimate
//! morph candidate's dispatcher will look like under TASK-020.

use proteus_contracts::{CapError, CapProof, SyscallCapTable};

struct PermissiveTable;

impl SyscallCapTable for PermissiveTable {
    type Cap = u64;
    fn check_raw(&self, _t: u64, _c: u64, _n: u32) -> Result<(), CapError> {
        Ok(())
    }
}

fn privileged_action(_proof: CapProof, input: u64) -> u64 {
    input.wrapping_add(1)
}

fn main() {
    let table = PermissiveTable;
    let proof = table
        .check(0, proteus_contracts::caps::POWER, 0)
        .expect("permissive impl always succeeds");
    let result = privileged_action(proof, 41);
    assert_eq!(result, 42);
}
