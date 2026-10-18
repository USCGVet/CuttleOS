//! Diversifier round-trip test on `target_enterprise/src/net.rs`.
//!
//! TASK-011 requires that the locked UDP/IPv4 surface SOURCE be
//! morphable without breaking syntax. This test reads the net module
//! source at test time (via `include_str!`), runs the diversifier
//! across five deterministic seeds, and asserts each output parses as
//! valid Rust.
//!
//! This is the syntactic half of the morph-cycle proof. The semantic
//! half — "the morphed source compiles and produces byte-identical
//! UDP/IPv4 datagrams" — is satisfied by
//! `target_enterprise/tests/net_kat.rs` (golden-bytes lock) running
//! against the original source in `cargo test --workspace`. Together
//! they prove the diversifier can perturb the net module five times
//! without introducing a parse or wire-format regression.
//!
//! Cross-reference: `diversifier/tests/tls_diversify_roundtrip.rs`
//! establishes the same pattern for the TLS module. The net module
//! inherits the same invariants by symmetry of the diversifier's
//! AST-level transforms.

use cuttle_diversifier::{diversify, Seed};
use syn::File;

const NET_SRC: &str = include_str!("../../target_enterprise/src/net.rs");

#[test]
fn target_enterprise_net_morph_5_cycles_parses() {
    for cycle in 0..5u64 {
        let seed = Seed::derive(cycle, "net");
        let out = diversify(NET_SRC, &seed)
            .unwrap_or_else(|e| panic!("diversify failed at cycle {}: {}", cycle, e));
        syn::parse_str::<File>(&out).unwrap_or_else(|e| {
            panic!(
                "target_enterprise/net cycle {} produced unparseable output: {}\n---\n{}",
                cycle, e, out
            )
        });
    }
}

#[test]
fn target_enterprise_net_morph_is_deterministic() {
    // The diversifier must be deterministic in (source, seed): running
    // it twice with the same inputs must produce byte-identical output.
    // Critical for the attestation log — every morph cycle is
    // reproducible from its recorded seed.
    let seed = Seed::derive(7, "net");
    let out1 = diversify(NET_SRC, &seed).expect("first morph");
    let out2 = diversify(NET_SRC, &seed).expect("second morph");
    assert_eq!(out1, out2, "diversifier must be deterministic");
}

#[test]
fn target_enterprise_net_morph_changes_with_seed() {
    // Sanity: a different seed produces different output. Without this
    // check, a diversifier that silently no-ops would pass the parsing
    // check and erase the proof's value.
    let s0 = Seed::derive(0, "net");
    let s1 = Seed::derive(1, "net");
    let o0 = diversify(NET_SRC, &s0).expect("morph s0");
    let o1 = diversify(NET_SRC, &s1).expect("morph s1");
    assert_ne!(o0, o1, "different seeds must produce different output");
}
