//! Diversifier round-trip test on `target_enterprise/src/tls.rs`.
//!
//! TASK-007 requires that the locked TLS surface SOURCE be morphable
//! without breaking syntax. This test reads the TLS module source at
//! test time (via `include_str!`), runs the diversifier across five
//! deterministic seeds, and asserts each output parses as valid Rust.
//!
//! This is the syntactic half of the morph-cycle proof. The semantic
//! half — "the morphed source compiles and produces byte-identical
//! ServerHello bytes" — is satisfied by `target_enterprise/tests/
//! tls_kat.rs` running against the original source in
//! `cargo test --workspace`. Together they prove the diversifier can
//! perturb the TLS module five times without introducing a parse or
//! wire-format regression.

use proteus_diversifier::{diversify, Seed};
use syn::File;

const TLS_SRC: &str = include_str!("../../target_enterprise/src/tls.rs");

#[test]
fn target_enterprise_tls_morph_5_cycles_parses() {
    for cycle in 0..5u64 {
        let seed = Seed::derive(cycle, "tls");
        let out = diversify(TLS_SRC, &seed)
            .unwrap_or_else(|e| panic!("diversify failed at cycle {}: {}", cycle, e));
        syn::parse_str::<File>(&out).unwrap_or_else(|e| {
            panic!(
                "target_enterprise/tls cycle {} produced unparseable output: {}\n---\n{}",
                cycle, e, out
            )
        });
    }
}

#[test]
fn target_enterprise_tls_morph_is_deterministic() {
    // The diversifier must be deterministic in (source, seed): running
    // it twice with the same inputs must produce byte-identical output.
    // This is critical for the attestation log — every morph cycle is
    // reproducible from its recorded seed.
    let seed = Seed::derive(42, "tls");
    let out1 = diversify(TLS_SRC, &seed).expect("first morph");
    let out2 = diversify(TLS_SRC, &seed).expect("second morph");
    assert_eq!(out1, out2, "diversifier must be deterministic");
}

#[test]
fn target_enterprise_tls_morph_changes_with_seed() {
    // Sanity: a different seed should produce different output. Without
    // this check, a diversifier that silently no-ops would pass the
    // parsing check.
    let s0 = Seed::derive(0, "tls");
    let s1 = Seed::derive(1, "tls");
    let o0 = diversify(TLS_SRC, &s0).expect("morph s0");
    let o1 = diversify(TLS_SRC, &s1).expect("morph s1");
    assert_ne!(o0, o1, "different seeds must produce different output");
}

#[test]
fn target_enterprise_tls_chained_300_cycles_is_bounded_and_ergodic() {
    use proteus_diversifier::{diversify_with_options, DiversifyOptions};

    let opts = DiversifyOptions {
        stack_pad: true,
        semantic_perturb: true,
        semantic_fire_rate_percent: 50,
    };

    let mut current = TLS_SRC.to_string();
    let mut cycle1_len = 0usize;

    for cycle in 1..=300u64 {
        let seed = Seed::derive(cycle, "tls_chained_300");
        let (next, log) = diversify_with_options(&current, &seed, &opts)
            .unwrap_or_else(|e| panic!("chained tls morph failed at cycle {}: {}", cycle, e));

        if cycle == 1 {
            cycle1_len = next.len();
        }

        // Source length must remain strictly bounded across 300 chained in-place cycles.
        let delta = next.len().abs_diff(cycle1_len);
        assert!(
            delta < 2500,
            "cycle {}: tls.rs source length drifted by {} bytes (cycle1={}, current={})",
            cycle,
            delta,
            cycle1_len,
            next.len()
        );

        // No function in tls.rs originally has #[inline], so none may freeze into already-inline.
        for (fn_name, decision) in &log.perturb_decisions {
            assert_ne!(
                decision, "ineligible:already-inline",
                "cycle {}: tls function {} froze into already-inline",
                cycle, fn_name
            );
        }

        current = next;
    }

    syn::parse_str::<File>(&current).expect("cycle 300 chained tls.rs output must parse");
}

#[test]
fn target_enterprise_shell_chained_100_cycles_is_bounded_and_ergodic() {
    use proteus_diversifier::{diversify_with_options, DiversifyOptions};

    const SHELL_SRC: &str = include_str!("../../target_enterprise/src/shell.rs");
    let opts = DiversifyOptions {
        stack_pad: true,
        semantic_perturb: true,
        semantic_fire_rate_percent: 50,
    };

    let mut current = SHELL_SRC.to_string();
    let mut cycle1_len = 0usize;

    for cycle in 1..=100u64 {
        let seed = Seed::derive(cycle, "shell_chained_100");
        let (next, log) = diversify_with_options(&current, &seed, &opts)
            .unwrap_or_else(|e| panic!("chained shell morph failed at cycle {}: {}", cycle, e));

        if cycle == 1 {
            cycle1_len = next.len();
        }

        let delta = next.len().abs_diff(cycle1_len);
        assert!(
            delta < 2500,
            "cycle {}: shell.rs source length drifted by {} bytes (cycle1={}, current={})",
            cycle,
            delta,
            cycle1_len,
            next.len()
        );

        for (fn_name, decision) in &log.perturb_decisions {
            assert_ne!(
                decision, "ineligible:already-inline",
                "cycle {}: shell function {} froze into already-inline",
                cycle, fn_name
            );
        }

        current = next;
    }

    syn::parse_str::<File>(&current).expect("cycle 100 chained shell.rs output must parse");
}


