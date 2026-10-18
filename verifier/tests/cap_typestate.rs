//! TASK-020 — Type-state capability proof tests (compile-time).
//!
//! The old TASK-004 verifier ran an AST walker that checked whether
//! the dispatcher source string syntactically referenced `check_cap`.
//! That walker accepted morph candidates that *called* `check_cap`
//! but discarded its result (`let _ = check_cap(...);`), buried the
//! call in dead code (`if false { check_cap(...)?; }`), or otherwise
//! routed around the gate. The result: the verifier reported ACCEPT
//! and the kernel ran without an enforced cap gate at all.
//!
//! TASK-020 replaces the AST walker with a Rust **type-state**
//! contract. `cuttle_contracts::CapProof` is a zero-sized type with
//! a private constructor (sealed via a `pub(crate)` mint helper in
//! the contracts crate). The privileged dispatch surface in
//! `target_minimal` and `target_enterprise` declares
//! `_proof: CapProof` in the handler signature; the Rust compiler
//! then **statically refuses** to compile any caller that does not
//! own a freshly-minted proof. The mint path is the trait's
//! provided `SyscallCapTable::check`, which wraps a successful
//! `check_raw` with a proof.
//!
//! This file drives the [trybuild] harness against a set of standalone
//! fixtures under `tests/cap_typestate/`:
//!
//!   `pass/` — fixtures that MUST compile. They exercise the happy
//!             path (obtain proof, consume it in a privileged action)
//!             and a couple of variations the compiler should permit.
//!
//!   `fail/` — fixtures that MUST NOT compile. Each fixture encodes
//!             one of the bypass patterns the old AST walker missed:
//!             (a) `let _ = check_cap(...)` — discards the proof
//!                 before calling the privileged action.
//!             (b) `if false { check_cap(...)?; }` — dead-code call
//!                 that never reaches the privileged action.
//!             (c) Binds proof, drops it via `drop()`, then tries
//!                 to use the privileged action.
//!             (d) Moves the proof into a discard helper that
//!                 doesn't pass it along.
//!             (e) Defines a *fake* zero-sized type with the same
//!                 name in local scope and tries to substitute it.
//!             (f) Calls the privileged action with `()` in place
//!                 of the proof (a structurally-similar ZST).
//!
//! [trybuild]: https://crates.io/crates/trybuild
//!
//! ## Why a single `#[test]` and not one per fixture
//!
//! `trybuild` is designed around a single test entry that batches
//! every fixture under a directory. The reported pass/fail per
//! fixture appears in the cargo test output as one logical test
//! result, but to the cargo test runner it counts as one test. The
//! per-fixture coverage is still exhaustive — adding a new pattern
//! is one new file, no test wiring required.

use trybuild::TestCases;

#[test]
fn cap_typestate_proof_is_compile_time_enforced() {
    let t = TestCases::new();
    // Positive fixtures: happy paths the compiler MUST accept.
    t.pass("tests/cap_typestate/pass/*.rs");
    // Negative fixtures: bypass patterns the compiler MUST reject.
    t.compile_fail("tests/cap_typestate/fail/*.rs");
}
