//! Positive fixture: minting two proofs in sequence and consuming
//! each separately MUST compile. This pattern exercises the case
//! where a dispatcher loops over a batch of syscalls and calls
//! `check_cap` once per iteration.

use cuttle_contracts::{CapError, CapProof, SyscallCapTable};

struct PermissiveTable;

impl SyscallCapTable for PermissiveTable {
    type Cap = u64;
    fn check_raw(&self, _t: u64, _c: u64, _n: u32) -> Result<(), CapError> {
        Ok(())
    }
}

fn privileged_action(_proof: CapProof, input: u64) -> u64 {
    input ^ 0xA5A5_A5A5
}

fn main() {
    let table = PermissiveTable;
    let mut acc = 0u64;
    for nr in 0..4 {
        let proof = table.check(0, u64::MAX, nr).expect("permissive");
        acc = privileged_action(proof, acc.wrapping_add(nr as u64));
    }
    // We do something with acc so the loop is not entirely dead code.
    assert!(acc != u64::MAX);
}
