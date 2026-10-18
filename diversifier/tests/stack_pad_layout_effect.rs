//! Regression test for TASK-029: stack-frame padding must produce
//! observably distinct first-statements across different seeds, so
//! the kernel ELF emitted from each candidate has different function
//! sizes (and therefore different downstream function offsets).
//!
//! This is a source-level approximation of the empirical measurement
//! in `experiments/diversity_demo/results/real_post029/REPORT.md`,
//! which is the full evidence: 20/20 distinct `.text` sha256, 0/19
//! synthetic-chain survival. This test asserts the necessary
//! source-level precondition.

use cuttle_diversifier::{diversify_with_options, DiversifyOptions, Seed};

fn diversify_padded(src: &str, seed: &Seed) -> String {
    diversify_with_options(src, seed, &DiversifyOptions::with_stack_pad())
        .expect("diversify_with_stack_pad must succeed")
        .0
}

/// Across N seeds against the same input, the diversifier's output
/// for a real `target_enterprise/src/tls.rs`-shaped function must
/// contain a stack pad whose size varies across seeds.
#[test]
fn pad_size_varies_across_seeds() {
    let src = r#"
        #![no_std]
        pub fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], out: &mut [u8]) {
            let total_label_len = 2usize + 6usize + label.len() + 1;
            assert!(total_label_len <= 255, "label too long");
            for (i, b) in out.iter_mut().enumerate() {
                *b = secret[i % 32] ^ (label[i % label.len()]);
            }
        }
    "#;

    // Run 32 seeds. Each output's pad-let statement carries the
    // emitted size as a literal `[u8; N]`. We extract N and assert
    // distinct values appear.
    let mut sizes = std::collections::BTreeSet::new();
    for seed_byte in 0u8..32 {
        let seed = Seed([seed_byte; 32]);
        let out = diversify_padded(src, &seed);
        let size = extract_first_pad_size(&out)
            .unwrap_or_else(|| panic!("no __cuttle_stack_pad_ in seed {}: {}", seed_byte, out));
        sizes.insert(size);
    }
    // 32 seeds against 192 buckets: collisions possible, but the
    // distribution must be diverse. The pre-TASK-029 baseline had
    // EVERY function at exactly the same size (no pad at all). Any
    // value > 1 here is qualitative proof that the pass biteq;
    // require > 15 to assert real distribution.
    assert!(
        sizes.len() >= 16,
        "expected ≥ 16 distinct pad sizes across 32 seeds, got {} (sizes: {:?})",
        sizes.len(),
        sizes
    );
}

/// The diversifier output for the same seed must be deterministic
/// (same pad size each time). This is the reproducibility-of-cycles
/// invariant.
#[test]
fn pad_size_is_deterministic_for_fixed_seed() {
    let src = "fn f() -> u32 { 0 }";
    let seed = Seed([42u8; 32]);
    let a = diversify_padded(src, &seed);
    let b = diversify_padded(src, &seed);
    let sa = extract_first_pad_size(&a).expect("pad missing in a");
    let sb = extract_first_pad_size(&b).expect("pad missing in b");
    assert_eq!(sa, sb, "diversify must be deterministic for fixed seed");
}

/// Two seeds that produce identical pad sizes for one fn name must
/// produce different sizes for at least *some* other fn names. This
/// is what breaks offset coalescence: even if a hash collision aligns
/// function A across two seeds, the cumulative `.text` layout still
/// diverges because some function B downstream gets different padding.
#[test]
fn cumulative_padding_diverges_across_seeds() {
    let src = r#"
        fn a() -> u32 { 0 }
        fn b() -> u32 { 1 }
        fn c() -> u32 { 2 }
        fn d() -> u32 { 3 }
        fn e() -> u32 { 4 }
        fn f() -> u32 { 5 }
        fn g() -> u32 { 6 }
        fn h() -> u32 { 7 }
    "#;
    // For each seed, sum the pad sizes across all 8 fns. The sum is a
    // proxy for cumulative `.text` size offset. Distinct sums across
    // seeds is what shifts downstream function offsets.
    let mut sums = std::collections::BTreeSet::new();
    for seed_byte in 0u8..40 {
        let seed = Seed([seed_byte; 32]);
        let out = diversify_padded(src, &seed);
        let total: usize = extract_all_pad_sizes(&out).iter().sum();
        sums.insert(total);
    }
    assert!(
        sums.len() >= 30,
        "expected ≥ 30 distinct cumulative pad sums across 40 seeds, got {} (sums: {:?})",
        sums.len(),
        sums
    );
}

fn extract_first_pad_size(out: &str) -> Option<usize> {
    extract_all_pad_sizes(out).first().copied()
}

fn extract_all_pad_sizes(out: &str) -> Vec<usize> {
    // Look for `__cuttle_stack_pad_<hex> : [u8 ; <N>usize]` in the
    // emitted token stream. The `quote` crate emits `[u8 ; 100usize]`
    // for parse_quote'd `[u8; 100]` because the literal is a usize.
    let mut sizes = Vec::new();
    let needle = "__cuttle_stack_pad_";
    let mut cursor = 0usize;
    while let Some(idx) = out[cursor..].find(needle) {
        let abs = cursor + idx;
        // Find the next `[u8 ; ` after this match.
        if let Some(bracket_idx) = out[abs..].find("[u8 ;") {
            let after_bracket = abs + bracket_idx + "[u8 ;".len();
            // Read digits.
            let rest = &out[after_bracket..];
            let trimmed = rest.trim_start();
            let digits: String = trimmed.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = digits.parse::<usize>() {
                sizes.push(n);
            }
            cursor = after_bracket;
        } else {
            cursor = abs + needle.len();
        }
    }
    sizes
}
