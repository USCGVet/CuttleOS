//! End-to-end tests for the `verify` binary.
//!
//! These tests drive the real verifier binary via `std::process::Command`
//! and observe its exit code, which is the contract the morph engine
//! depends on:
//!   - 0 = accept candidate
//!   - 1 = reject candidate
//!   - 2 = infrastructure / argument error
//!
//! Each test invokes a real `cargo build` + `cargo test` chain inside an
//! isolated scratch dir, so wall-clock cost is dominated by rustc. They
//! are marked `#[ignore]` so `cargo test` stays fast; run them explicitly
//! with `cargo test -p proteus-verifier -- --ignored`.

use std::path::{Path, PathBuf};
use std::process::Command;

/// Find the Proteus workspace root (where `Cargo.toml` declares the
/// workspace members) and the `verify` binary that cargo built for us.
fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR is the verifier crate's directory at test build
    // time. The workspace root is its parent.
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("verifier crate must have a parent (the workspace root)")
        .to_path_buf()
}

fn verify_binary() -> PathBuf {
    // Prefer the path cargo passes us when it runs the test, falling
    // back to the conventional workspace layout. `CARGO_BIN_EXE_verify`
    // is only defined when the verifier's own integration tests are run
    // by cargo *and* the [[bin]] is named `verify`, which it is.
    if let Some(p) = option_env!("CARGO_BIN_EXE_verify") {
        return PathBuf::from(p);
    }
    let root = workspace_root();
    let exe = if cfg!(windows) { "verify.exe" } else { "verify" };
    root.join("target").join("debug").join(exe)
}

fn run_verify(candidate: &Path, previous: Option<&Path>) -> i32 {
    let mut cmd = Command::new(verify_binary());
    if let Some(p) = previous {
        cmd.arg("--previous").arg(p);
    }
    cmd.arg(candidate);
    let out = cmd.output().expect("spawn verify binary");
    // For debugging on failure.
    eprintln!(
        "verify stdout:\n{}\nverify stderr:\n{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    out.status.code().unwrap_or(-1)
}

fn scratch_file(name: &str, contents: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "proteus-verifier-test-{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    let p = dir.join(format!("{}.rs", name));
    std::fs::write(&p, contents).expect("write candidate");
    p
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn good_candidate_is_accepted() {
    let root = workspace_root();
    let candidate = root.join("target_minimal").join("src").join("lib.rs");
    assert!(
        candidate.exists(),
        "expected canonical candidate at {}",
        candidate.display()
    );
    // Run WITHOUT --previous: passing the candidate as its own previous
    // would trip the canonical-hash dedup. The compile-and-test stage is
    // the load-bearing check here.
    let code = run_verify(&candidate, None);
    assert_eq!(code, 0, "good candidate should be accepted");
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn broken_candidate_is_rejected() {
    // Sabotage fletcher32 to always return 0. The candidate parses,
    // exposes the right public surface, but breaks the locked semantics
    // — the golden test must catch it.
    let broken = r#"
#![no_std]
pub struct DemoHash;

pub fn fletcher32(_data: &[u8]) -> u32 {
    0
}

pub fn feistel_mix(state: u64) -> u64 {
    let mut left = (state >> 32) as u32;
    let mut right = state as u32;
    for round in 0..4u32 {
        let new_right = left ^ feistel_round(right, round);
        left = right;
        right = new_right;
    }
    ((left as u64) << 32) | (right as u64)
}

pub fn derive_byte(seed: u8, rounds: u32) -> u8 {
    let mut acc: u64 = seed as u64;
    let mut accumulator_low: u32 = 0;
    let mut accumulator_high: u32 = 0;
    let mut counter: u32 = 0;
    while counter < rounds {
        acc = feistel_mix(acc.wrapping_add(counter as u64));
        accumulator_low = accumulator_low.wrapping_add(acc as u32);
        accumulator_high = accumulator_high.wrapping_add((acc >> 32) as u32);
        counter += 1;
    }
    let folded = accumulator_low ^ accumulator_high;
    (folded & 0xFF) as u8
}

fn feistel_round(half: u32, round: u32) -> u32 {
    let mixed = half
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add(round.wrapping_mul(0x85EB_CA6B));
    mixed.rotate_left(13) ^ mixed.rotate_right(7)
}

impl proteus_contracts::Hash for DemoHash {
    const OUTPUT_LEN: usize = 4;
    fn hash(input: &[u8], out: &mut [u8]) {
        let h = fletcher32(input);
        out[0] = (h >> 24) as u8;
        out[1] = (h >> 16) as u8;
        out[2] = (h >> 8) as u8;
        out[3] = h as u8;
    }
}
"#;
    let cand = scratch_file("broken", broken);
    let code = run_verify(&cand, None);
    assert_eq!(
        code, 1,
        "candidate with sabotaged fletcher32 must be rejected with exit code 1"
    );
    let _ = std::fs::remove_dir_all(cand.parent().unwrap());
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn unparseable_candidate_is_rejected() {
    // Truly malformed Rust — the parse check at the top of `verify` must
    // reject this with exit code 1.
    let cand = scratch_file(
        "garbage",
        "this is not rust source @@@ {{ ;;; pub fn fletcher32",
    );
    let code = run_verify(&cand, None);
    assert_eq!(
        code, 1,
        "unparseable candidate must be rejected with exit code 1"
    );
    let _ = std::fs::remove_dir_all(cand.parent().unwrap());
}
