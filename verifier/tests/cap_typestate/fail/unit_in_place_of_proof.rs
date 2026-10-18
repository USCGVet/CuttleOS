//! Negative fixture: pass the unit type `()` where a `CapProof` is
//! expected. Both are zero-sized; a confused candidate-author might
//! assume they are interchangeable. The type checker rejects.

use cuttle_contracts::CapProof;

fn privileged_action(_proof: CapProof, input: u64) -> u64 {
    input + 1
}

fn main() {
    // `()` is also a zero-sized type, but it is *not* a `CapProof`.
    // The morph candidate tried to fake the proof by substituting
    // unit; the type system catches it.
    let _ = privileged_action((), 42);
}
