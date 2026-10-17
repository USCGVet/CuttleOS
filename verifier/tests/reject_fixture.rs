//! End-to-end tests that drive the real `verify` binary against
//! hand-crafted fixtures, observing both its exit code and its
//! side-effects (the `perf.jsonl` log).
//!
//! Unlike the inline-source tests in `verifier_e2e.rs`, the fixtures
//! used here live on disk under `tests/fixtures/` so they can be diffed,
//! reviewed, and held against the locked semantics by hand.
//!
//! These tests are `#[ignore]` because each one drives a full
//! `cargo build` + `cargo test` chain inside an isolated scratch dir
//! (wall-clock cost is rustc-dominated). Run them explicitly with:
//!   `cargo test -p proteus-verifier --test reject_fixture -- --ignored`

use std::path::{Path, PathBuf};
use std::process::Command;

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR points at `<workspace>/verifier`; the parent is
    // the workspace root that holds `target_minimal/` and `perf.jsonl`.
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

/// Spawn `verify` and return its exit code together with stderr. We
/// capture stderr (not just status) because the reject-fixture test
/// must distinguish "rejected at the golden-test stage" from "rejected
/// at the parse stage" — only the former proves compile-and-test is
/// load-bearing.
fn run_verify_captured(
    candidate: &Path,
    previous: Option<&Path>,
    manifest: Option<&Path>,
) -> (i32, String, String) {
    let mut cmd = Command::new(verify_binary());
    if let Some(p) = previous {
        cmd.arg("--previous").arg(p);
    }
    if let Some(m) = manifest {
        cmd.arg("--manifest").arg(m);
    }
    cmd.arg(candidate);
    let out = cmd.output().expect("spawn verify binary");
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    eprintln!("verify stdout:\n{}\nverify stderr:\n{}", stdout, stderr);
    (out.status.code().unwrap_or(-1), stdout, stderr)
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn broken_fletcher32_fixture_is_rejected_at_test_stage() {
    let root = workspace_root();
    let fixture = root
        .join("verifier")
        .join("tests")
        .join("fixtures")
        .join("broken_fletcher32.rs");
    assert!(
        fixture.exists(),
        "expected fixture at {}",
        fixture.display()
    );
    let previous = root.join("target_minimal").join("src").join("lib.rs");
    let manifest = root.join("target_minimal").join("manifest.txt");
    assert!(previous.exists(), "previous source missing");
    assert!(manifest.exists(), "manifest missing");

    let (code, _stdout, stderr) =
        run_verify_captured(&fixture, Some(&previous), Some(&manifest));

    // Exit code 1 is the documented REJECT contract.
    assert_eq!(
        code, 1,
        "broken_fletcher32 fixture must be rejected (exit code 1), got {}",
        code
    );

    // The fixture must NOT trip the parse stage. If it does, the file
    // has drifted from valid Rust and the assay is meaningless.
    assert!(
        !stderr.contains("parse failed"),
        "broken_fletcher32 was rejected at parse stage — fixture has a syntax error\nstderr:\n{}",
        stderr
    );

    // It must also not trip the static public-symbol or canonical-hash
    // checks. The whole point is that those passed and the *test* stage
    // caught it.
    assert!(
        !stderr.contains("missing required public symbols"),
        "broken_fletcher32 was rejected at public-symbol check, not test stage\nstderr:\n{}",
        stderr
    );
    assert!(
        !stderr.contains("canonical-equivalent to previous cycle"),
        "broken_fletcher32 was rejected as canonical-duplicate\nstderr:\n{}",
        stderr
    );

    // The verifier prints `failed the golden test in scratch dir ...`
    // when the test stage rejects. Cargo's own output also includes
    // `FAILED` and (in the assertion message) `assertion `left == right``.
    // Match any of those — be lenient about cargo's evolving format.
    let mentions_test_failure = stderr.contains("failed the golden test")
        || stderr.contains("FAILED")
        || stderr.contains("panicked")
        || stderr.contains("assertion");
    assert!(
        mentions_test_failure,
        "stderr did not mention a test failure — rejection may have come from a different stage\nstderr:\n{}",
        stderr
    );
}

#[test]
#[ignore = "invokes real cargo build + cargo test; slow"]
fn accept_writes_perf_jsonl_line() {
    // Drive verify against the canonical-good source and assert that a
    // new line is appended to `perf.jsonl`. The perf log lives at the
    // workspace root next to `attest.log.jsonl`.
    let root = workspace_root();
    let candidate = root.join("target_minimal").join("src").join("lib.rs");
    let manifest = root.join("target_minimal").join("manifest.txt");
    assert!(candidate.exists(), "good candidate missing");
    let perf_log = root.join("perf.jsonl");

    let before = std::fs::read_to_string(&perf_log).unwrap_or_default();
    let before_lines = before.lines().count();

    // No --previous: passing the candidate as its own previous would
    // trip canonical-hash dedup. We want the test stage AND perf stage
    // to both run.
    let (code, _stdout, stderr) = run_verify_captured(&candidate, None, Some(&manifest));
    assert_eq!(
        code, 0,
        "canonical good candidate must be accepted (exit code 0), got {}\nstderr:\n{}",
        code, stderr
    );

    let after = std::fs::read_to_string(&perf_log)
        .expect("perf.jsonl must exist after an accept");
    let after_lines = after.lines().count();
    assert!(
        after_lines == before_lines + 1,
        "perf.jsonl line count must grow by exactly 1 (before={}, after={})",
        before_lines,
        after_lines
    );

    // The newest line must be valid-shaped JSON with the four fields we
    // care about. We do a string-level check rather than pulling in a
    // JSON parser dep — the schema is small and stable.
    let last = after
        .lines()
        .last()
        .expect("perf.jsonl must have at least one line after accept");
    for field in [
        "ts_unix",
        "fletcher32_ns",
        "feistel_mix_ns",
        "derive_byte_ns",
        "demohash_ns",
    ] {
        assert!(
            last.contains(field),
            "perf.jsonl last line missing field {:?}: {}",
            field,
            last
        );
    }
}
