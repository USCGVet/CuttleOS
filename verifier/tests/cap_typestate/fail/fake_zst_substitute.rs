//! Negative fixture: define a *local* zero-sized type with the same
//! name `CapProof` and try to substitute it for the real proof. The
//! local `CapProof` shadows the import within this scope, but the
//! `privileged_action` parameter is typed against the imported
//! `cuttle_contracts::CapProof`, so the substitution fails the
//! type checker.

use cuttle_contracts::CapProof as RealCapProof;

// A local, fake "CapProof". Same name, different module path. The
// morph candidate-author hoped this would slip past the type checker.
struct CapProof;

fn privileged_action(_proof: RealCapProof, input: u64) -> u64 {
    input + 1
}

fn main() {
    // The local `CapProof` is in scope; we try to construct one
    // (trivial: it's a unit struct, no privacy) and pass it where a
    // `cuttle_contracts::CapProof` is expected. Type mismatch.
    let fake = CapProof;
    let _ = privileged_action(fake, 42);
}
