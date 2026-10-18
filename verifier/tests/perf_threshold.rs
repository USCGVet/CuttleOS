//! End-to-end tests for the perf-envelope gating added in Phase-2.
//!
//! Each test drives the real `verify` binary via `std::process::Command`
//! against the canonical good source in `target_minimal/src/lib.rs`,
//! varying the `--perf-baseline` / `--perf-threshold` / `--no-perf-check`
//! flags to exercise every branch of `enforce_perf_threshold`.
//!
//! Tests are `#[ignore]` because each one invokes a real `cargo build +
//! cargo test` chain inside the verifier's scratch dir (wall-clock cost
//! is rustc-dominated). Run them explicitly with:
//!
//!   `cargo test -p cuttle-verifier --test perf_threshold -- --ignored`
//!
//! Hermeticity: every test writes its baseline under
//! `std::env::temp_dir()` with a unique per-test suffix. None of these
//! tests touch the workspace `perf.jsonl`, so they are safe to run
//! against a live repository.

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .expect("verifier crate must have a parent (the workspace root)")
        .to_path_buf()
}

fn verify_binary() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_verify") {
        return PathBuf::from(p);
    }
    let root = workspace_root();
    let exe = if cfg!(windows) { "verify.exe" } else { "verify" };
    root.join("target").join("debug").join(exe)
}

/// Spawn `verify` with arbitrary args. Returns (exit_code, stdout, stderr).
fn run_verify_args(args: &[&str]) -> (i32, String, String) {
    let mut cmd = Command::new(verify_binary());
    for a in args {
        cmd.arg(a);
    }
    let out = cmd.output().expect("spawn verify binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!(
        "verify ({:?}) stdout:\n{}\nverify stderr:\n{}",
        args, stdout, stderr
    );
    (out.status.code().unwrap_or(-1), stdout, stderr)
}

/// Write a baseline file in a unique scratch path. The same `line` is
/// repeated `MIN_REPEATS` times so the windowed-median gate
/// (TASK-005) has enough entries to fire — a single-line baseline now
/// falls into the `NoBaseline` branch.
fn write_baseline(name: &str, line: &str) -> PathBuf {
    const MIN_REPEATS: usize = 10;
    let dir = std::env::temp_dir().join(format!(
        "cuttle-verify-perf-{}-{}",
        name,
        std::process::id()
    ));
    std::fs::create_dir_all(&dir).expect("create scratch baseline dir");
    let p = dir.join("baseline.jsonl");
    let mut body = String::new();
    for _ in 0..MIN_REPEATS {
        body.push_str(line.trim_end());
        body.push('\n');
    }
    std::fs::write(&p, body).expect("write baseline");
    p
}

fn good_candidate() -> PathBuf {
    workspace_root()
        .join("target_minimal")
        .join("src")
        .join("lib.rs")
}

fn good_manifest() -> PathBuf {
    workspace_root().join("target_minimal").join("manifest.txt")
}

fn s(p: &Path) -> String {
    p.to_string_lossy().into_owned()
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn accept_without_baseline_when_file_missing() {
    // Point --perf-baseline at a path that does not exist. The verifier
    // must emit the "no perf baseline available" warning and accept.
    let candidate = good_candidate();
    let manifest = good_manifest();
    let missing = std::env::temp_dir().join(format!(
        "cuttle-verify-perf-missing-{}-baseline.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&missing);
    assert!(!missing.exists(), "precondition: baseline path must not exist");

    let (code, _stdout, stderr) = run_verify_args(&[
        "--manifest",
        &s(&manifest),
        "--perf-baseline",
        &s(&missing),
        &s(&candidate),
    ]);
    assert_eq!(
        code, 0,
        "missing baseline must produce accept; got exit code {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("no perf baseline available"),
        "stderr must announce the missing-baseline path\nstderr:\n{}",
        stderr
    );
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn accept_within_threshold() {
    // Baseline declares 1000 ns/call for every canonical function. The
    // real target measures well under 1000 ns/call on any developer
    // machine, so the candidate is *faster* than baseline — within
    // envelope, accept.
    let candidate = good_candidate();
    let manifest = good_manifest();
    let baseline = write_baseline(
        "within",
        r#"{"ts_unix":1,"fletcher32_ns":1000,"feistel_mix_ns":1000,"derive_byte_ns":1000,"demohash_ns":1000}"#,
    );
    let (code, _stdout, stderr) = run_verify_args(&[
        "--manifest",
        &s(&manifest),
        "--perf-baseline",
        &s(&baseline),
        &s(&candidate),
    ]);
    assert_eq!(
        code, 0,
        "candidate within envelope must accept; got exit code {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        !stderr.contains("perf regression"),
        "stderr must not announce a regression when within envelope\nstderr:\n{}",
        stderr
    );
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn reject_when_function_exceeds_threshold() {
    // Baseline declares 1 ns/call for everything. Real measurements
    // dwarf that, so every function should trip the +50% threshold and
    // the verifier should REJECT with a regression message.
    let candidate = good_candidate();
    let manifest = good_manifest();
    let baseline = write_baseline(
        "tight",
        r#"{"ts_unix":1,"fletcher32_ns":1,"feistel_mix_ns":1,"derive_byte_ns":1,"demohash_ns":1}"#,
    );
    let (code, _stdout, stderr) = run_verify_args(&[
        "--manifest",
        &s(&manifest),
        "--perf-baseline",
        &s(&baseline),
        // Pin the threshold explicitly: TASK-005 dropped the default
        // from +50% to +20%, but this test exercises the +50% branch.
        "--perf-threshold",
        "50",
        &s(&candidate),
    ]);
    assert_eq!(
        code, 1,
        "candidate must be rejected against a tight baseline; got exit code {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("perf regression in"),
        "stderr must name the regressing function(s)\nstderr:\n{}",
        stderr
    );
    assert!(
        stderr.contains("exceeds threshold +50%"),
        "stderr must cite the threshold the candidate exceeded\nstderr:\n{}",
        stderr
    );
    // At least one of the four canonical functions must be named.
    let mentioned = ["fletcher32_ns", "feistel_mix_ns", "derive_byte_ns", "demohash_ns"]
        .iter()
        .any(|f| stderr.contains(f));
    assert!(
        mentioned,
        "stderr must mention at least one canonical function name\nstderr:\n{}",
        stderr
    );
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn no_perf_check_bypasses_gating() {
    // Same tight-baseline scenario as the reject case, plus
    // `--no-perf-check`. The verifier must accept and announce that
    // gating was disabled.
    let candidate = good_candidate();
    let manifest = good_manifest();
    let baseline = write_baseline(
        "tight-bypass",
        r#"{"ts_unix":1,"fletcher32_ns":1,"feistel_mix_ns":1,"derive_byte_ns":1,"demohash_ns":1}"#,
    );
    let (code, _stdout, stderr) = run_verify_args(&[
        "--manifest",
        &s(&manifest),
        "--perf-baseline",
        &s(&baseline),
        "--no-perf-check",
        &s(&candidate),
    ]);
    assert_eq!(
        code, 0,
        "--no-perf-check must bypass gating and accept; got exit code {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("perf gating disabled by --no-perf-check"),
        "stderr must announce that gating was disabled\nstderr:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("perf regression"),
        "no regression message expected when gating is disabled\nstderr:\n{}",
        stderr
    );
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn unknown_function_in_candidate_is_skipped() {
    // Baseline has only `fletcher32_ns`. Real measurement will produce
    // all four canonical fields. The three not in baseline must be
    // skipped with a stderr note; the one present must satisfy the
    // threshold. We give fletcher32 a generous baseline so the test
    // remains stable across measurement noise.
    let candidate = good_candidate();
    let manifest = good_manifest();
    let baseline = write_baseline(
        "partial",
        r#"{"ts_unix":1,"fletcher32_ns":1000}"#,
    );
    let (code, _stdout, stderr) = run_verify_args(&[
        "--manifest",
        &s(&manifest),
        "--perf-baseline",
        &s(&baseline),
        &s(&candidate),
    ]);
    assert_eq!(
        code, 0,
        "candidate must accept when only the matched function is within envelope; got exit code {}\nstderr:\n{}",
        code, stderr
    );
    // Each of the three unmatched canonical fields should get a
    // "present in candidate but absent from baseline" note.
    for field in ["feistel_mix_ns", "derive_byte_ns", "demohash_ns"] {
        assert!(
            stderr.contains(field),
            "stderr must note unmatched field {:?}\nstderr:\n{}",
            field,
            stderr
        );
    }
    assert!(
        stderr.contains("absent from baseline"),
        "stderr must use the canonical 'absent from baseline' phrasing\nstderr:\n{}",
        stderr
    );
}
