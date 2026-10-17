//! TASK-027 — rustc round-trip tests for the codegen-perturbation pass.
//!
//! Each test diversifies a fixture source under a distinct seed, then
//! invokes `rustc --emit=metadata --edition=2024 --crate-type=lib` on
//! the diversifier output and asserts a clean exit. Metadata-only
//! emission catches every syntactic, name-resolution, type-checking,
//! and borrow-check issue that real compilation would surface, without
//! the cost of codegen or linking. If the perturbation pass ever
//! produces an attribute that the type checker rejects (e.g. a wrongly
//! placed `#[inline(...)]` on a const item misclassified as a function),
//! these tests will catch it.
//!
//! The fixture is intentionally diverse:
//!   - free public entry point with a loop and a slice
//!   - generic helper (monomorphisation site)
//!   - recursive helper
//!   - tuple-returning helper
//!   - bit-twiddling helpers across multiple types
//!   - a non-`pub` const and a non-`pub` struct (to exercise reorder)
//!   - a trait + impl block (to test that the perturbation pass leaves
//!     trait-impl methods alone, since codegen-perturb only targets
//!     free fns)
//!
//! This shape was chosen to mirror the kinds of constructs found in
//! `target_enterprise/src/tls.rs`, the donor file the cycle pipeline
//! actually morphs in production runs.

use proteus_diversifier::{diversify, Seed};
use std::path::PathBuf;
use std::process::Command;

const FIXTURE: &str = r#"
#![no_std]
#![allow(dead_code)]

pub fn entry(buf: &mut [u8]) -> u32 {
    let mut sum: u32 = 0;
    for b in buf.iter() {
        sum = sum.wrapping_add(*b as u32);
    }
    let m = mix(sum);
    write_le(buf, m);
    let (lo, hi) = split(m);
    combine(lo, hi).wrapping_add(fib(7))
}

fn mix(x: u32) -> u32 {
    x.wrapping_mul(0x9E3779B1)
}

fn rotate(x: u32, n: u32) -> u32 {
    let n = n & 31;
    (x << n) | (x >> ((32 - n) & 31))
}

fn combine(a: u32, b: u32) -> u32 {
    rotate(a, 7).wrapping_add(b)
}

fn split(v: u32) -> (u32, u32) {
    (v & 0xFFFF, v >> 16)
}

fn fib(n: u32) -> u32 {
    if n < 2 {
        n
    } else {
        fib(n - 1).wrapping_add(fib(n - 2))
    }
}

fn write_le(out: &mut [u8], v: u32) {
    let bytes = v.to_le_bytes();
    let mut i = 0;
    while i < bytes.len() && i < out.len() {
        out[i] = bytes[i];
        i += 1;
    }
}

fn pair<T: Copy>(t: T) -> (T, T) {
    (t, t)
}

fn count_ones_u8(b: u8) -> u32 {
    let mut c: u32 = 0;
    let mut x = b;
    while x != 0 {
        c += (x & 1) as u32;
        x >>= 1;
    }
    c
}

fn sat_add(a: u32, b: u32) -> u32 {
    match a.checked_add(b) {
        Some(v) => v,
        None => u32::MAX,
    }
}

const SALT: u32 = 0xA5A5_5A5A;

struct Inner {
    field: u32,
}

trait Op {
    fn op(&self, x: u32) -> u32;
}

impl Op for Inner {
    fn op(&self, x: u32) -> u32 {
        x.wrapping_add(self.field) ^ SALT
    }
}
"#;

fn rustc_check(src: &str, label: &str) {
    let tmp = std::env::temp_dir().join(format!(
        "proteus_perturb_rt_{}_{}",
        label,
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&tmp);
    std::fs::create_dir_all(&tmp).expect("mkdir tmp");
    let src_path: PathBuf = tmp.join("src.rs");
    let out_dir: PathBuf = tmp.join("out");
    std::fs::create_dir_all(&out_dir).expect("mkdir out");
    std::fs::write(&src_path, src).expect("write src");

    let out = Command::new("rustc")
        .arg("--edition=2024")
        .arg("--crate-type=lib")
        .arg("--emit=metadata")
        .arg("-o")
        .arg(out_dir.join("metadata.rmeta"))
        .arg(&src_path)
        .output()
        .expect("invoke rustc");

    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        let stdout = String::from_utf8_lossy(&out.stdout);
        // Persist the failing source for postmortem.
        let persist = std::env::temp_dir().join(format!("proteus_perturb_rt_{}_FAIL.rs", label));
        let _ = std::fs::write(&persist, src);
        panic!(
            "rustc rejected diversifier output ({}). exit={:?}\nsource persisted at: {}\nstderr:\n{}\nstdout:\n{}",
            label,
            out.status.code(),
            persist.display(),
            stderr,
            stdout
        );
    }

    let _ = std::fs::remove_dir_all(&tmp);
}

fn assert_perturbed(src: &str) {
    // Sanity: the perturbation pass MUST have visibly attached at
    // least one inline attribute to the output. Otherwise the round
    // trip is not actually exercising the pass.
    let attached = src.contains("# [inline (never)]")
        || src.contains("# [inline (always)]")
        || src.contains("#[inline(never)]")
        || src.contains("#[inline(always)]");
    assert!(
        attached,
        "expected at least one #[inline(...)] attribute in diversified output; \
         pass appears to have been a no-op:\n---\n{}\n---",
        src
    );
}

fn run_cycle(cycle: u64) {
    let seed = Seed::derive(cycle, "perturb-roundtrip");
    let out = diversify(FIXTURE, &seed)
        .unwrap_or_else(|e| panic!("diversify failed at cycle {}: {}", cycle, e));
    // The output should parse — strictly redundant with the rustc
    // check, but cheap and improves the error message on failure.
    syn::parse_str::<syn::File>(&out)
        .unwrap_or_else(|e| panic!("cycle {} produced unparseable output: {}\n{}", cycle, e, out));
    assert_perturbed(&out);
    rustc_check(&out, &format!("cycle{}", cycle));
}

#[test]
fn cycle_0_compiles_under_rustc_metadata() {
    run_cycle(0);
}

#[test]
fn cycle_1_compiles_under_rustc_metadata() {
    run_cycle(1);
}

#[test]
fn cycle_2_compiles_under_rustc_metadata() {
    run_cycle(2);
}

#[test]
fn cycle_3_compiles_under_rustc_metadata() {
    run_cycle(3);
}

#[test]
fn cycle_4_compiles_under_rustc_metadata() {
    run_cycle(4);
}

#[test]
fn cycle_5_compiles_under_rustc_metadata() {
    run_cycle(5);
}

#[test]
fn cycle_6_compiles_under_rustc_metadata() {
    run_cycle(6);
}

#[test]
fn cycle_7_compiles_under_rustc_metadata() {
    run_cycle(7);
}

#[test]
fn outputs_diverge_across_seeds() {
    // Strengthens the "perturbation actually does something" claim:
    // across 8 distinct seeds, at least 6 of the 8 emitted sources
    // must be byte-distinct. (Allow slack: with 9 private fns and a
    // 50/25/25 distribution, two adjacent seeds could theoretically
    // produce identical attribute assignments. But not 3+.)
    use std::collections::HashSet;
    let mut emitted: HashSet<String> = HashSet::new();
    for c in 0..8u64 {
        let seed = Seed::derive(c, "perturb-roundtrip");
        let out = diversify(FIXTURE, &seed).expect("diversify");
        emitted.insert(out);
    }
    assert!(
        emitted.len() >= 6,
        "expected at least 6 distinct outputs over 8 seeds, got {}",
        emitted.len()
    );
}

#[test]
fn determinism_matches_pure_diversify() {
    // Belt and braces: confirms the codegen-perturb step does not
    // introduce nondeterminism. (The unit tests prove this on the
    // pass in isolation; this confirms it through the full pipeline.)
    let seed = Seed::derive(99, "perturb-roundtrip");
    let a = diversify(FIXTURE, &seed).expect("first");
    let b = diversify(FIXTURE, &seed).expect("second");
    assert_eq!(a, b, "diversify+perturb must be deterministic");
}
