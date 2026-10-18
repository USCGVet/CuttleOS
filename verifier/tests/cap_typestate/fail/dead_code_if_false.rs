//! Negative fixture: `if false { check_cap()?; }` is dead code; no
//! proof reaches the privileged action. The old AST walker accepted
//! this because the source string `check_cap` was present; the
//! type-state contract rejects it because the proof never materialises
//! in a scope that reaches the privileged action.

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

fn main() -> Result<(), CapError> {
    let table = PermissiveTable;
    if false {
        // The proof is minted, then immediately discarded as the
        // `if`-block returns nothing.
        let _ = table.check(0, u64::MAX, 0)?;
    }
    // No proof reaches here.
    let _ = privileged_action(42);
    Ok(())
}
