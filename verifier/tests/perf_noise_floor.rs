//! Empirical noise-floor test for the perf measurement infrastructure.
//!
//! Runs five back-to-back morph cycles against the canonical unmodified
//! `target_minimal/src/lib.rs`, captures the `perf:` output from each,
//! and asserts that the (max - min) spread for every metric is below
//! 40% of the minimum. If a function legitimately cannot hold 40%
//! repeatability we fix the measurement (more iterations, better warm-
//! up, larger black_box scope); we do not loosen the test threshold,
//! because anything wider than 40% drives the verifier into flap-
//! rejecting morph candidates on noise alone — which is the very
//! problem this whole sub-system exists to prevent.
//!
//! Excluded from default `cargo test` (#[ignore]) because each cycle
//! drives a real cargo build + cargo test inside the verifier scratch
//! dir, ~6-10s per cycle on debug-build Windows, ~30-50s total.
//!
//! Hermeticity: each cycle's perf record is captured into a per-test
//! `--perf-baseline` file under `std::env::temp_dir()`, so the
//! workspace `perf.jsonl` is never touched. The verifier still reads
//! and writes through its normal path inside the scratch directory;
//! we observe the metrics by snooping the verifier's stderr (which
//! prints the perf measurements as they arrive) and the appended log.
//!
//! Run with:
//!
//! ```text
//! cargo test -p proteus-verifier --test perf_noise_floor -- --ignored
//! ```

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

/// Parse one `perf:` line into (key, value). Mirrors the verifier's
/// own parser (`parse_perf_stdout` in `main.rs`) just enough to drive
/// the assertion. Returns `None` for lines that are not perf
/// measurements.
fn parse_perf_line(line: &str) -> Option<(String, u64)> {
    let rest = line.trim().strip_prefix("perf:")?.trim();
    let mut parts = rest.splitn(2, char::is_whitespace);
    let name = parts.next()?;
    let val_part = parts.next()?.trim().strip_prefix("ns_per_call=")?;
    let value: u64 = val_part.trim().parse().ok()?;
    let key = match name {
        "fletcher32" => "fletcher32_ns".to_string(),
        "feistel_mix" => "feistel_mix_ns".to_string(),
        "derive_byte" => "derive_byte_ns".to_string(),
        "DemoHash::hash" => "demohash_ns".to_string(),
        other => {
            let sanitised: String = other
                .chars()
                .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                .flat_map(|c| c.to_lowercase())
                .collect();
            format!("{}_ns", sanitised)
        }
    };
    Some((key, value))
}

/// Run a single verify invocation that exercises the full
/// compile-and-test + perf-measurement chain against the unmodified
/// target source. We point `--perf-baseline` at a non-existent file
/// so perf gating accepts every cycle (the threshold check sees no
/// baseline and skips gating). Returns the parsed perf measurements
/// for that cycle.
fn one_cycle(baseline_path: &Path) -> Vec<(String, u64)> {
    let candidate = good_candidate();
    let manifest = good_manifest();
    let out = Command::new(verify_binary())
        .arg("--manifest")
        .arg(s(&manifest))
        .arg("--perf-baseline")
        .arg(s(baseline_path))
        .arg(s(&candidate))
        .output()
        .expect("spawn verify binary");
    assert!(
        out.status.success(),
        "verify must accept unmodified source; exit={:?}\nstderr:\n{}",
        out.status.code(),
        String::from_utf8_lossy(&out.stderr),
    );
    // The perf measurements are printed to stdout by the perf test
    // binary; cargo captures and re-emits them when the test binary
    // is run with `--nocapture`. They appear in the verify
    // subprocess's stdout (forwarded through `cargo test`'s stdout).
    let stdout = String::from_utf8_lossy(&out.stdout);
    stdout.lines().filter_map(parse_perf_line).collect()
}

#[test]
#[ignore = "drives 5 full cargo build + cargo test cycles; slow"]
fn perf_max_min_spread_under_40_percent() {
    // Cycle count: 5 is the same count the perf test itself uses
    // for batch median, so the noise-floor test characterises one
    // layer up — what does the median look like across independent
    // cargo invocations. Five cycles is enough to see whether the
    // measurement is stable; fewer would let outliers drive the
    // assertion in either direction.
    const CYCLES: usize = 5;

    // Per-test scratch baseline file. The verifier reads it (finds
    // it absent → no baseline → accept) and we ignore the value;
    // the point is to keep verify from touching the real
    // workspace `perf.jsonl`.
    let baseline = std::env::temp_dir().join(format!(
        "proteus-noise-floor-baseline-{}.jsonl",
        std::process::id()
    ));
    let _ = std::fs::remove_file(&baseline);

    // Collect five independent measurement sets.
    let mut all: Vec<Vec<(String, u64)>> = Vec::with_capacity(CYCLES);
    for cycle in 0..CYCLES {
        let measurements = one_cycle(&baseline);
        assert!(
            !measurements.is_empty(),
            "cycle {}: no `perf:` lines were captured; \
             measurement infrastructure broken",
            cycle
        );
        all.push(measurements);
    }

    // Aggregate by key. Every cycle should produce the same keys;
    // if a key is missing from any cycle, that itself is a
    // measurement-infrastructure failure (the test compiled and ran
    // but printed nothing for one function — investigate the source
    // before relaxing the test).
    use std::collections::BTreeMap;
    let mut per_key: BTreeMap<String, Vec<u64>> = BTreeMap::new();
    for cycle in &all {
        for (k, v) in cycle {
            per_key.entry(k.clone()).or_default().push(*v);
        }
    }

    let mut failures: Vec<String> = Vec::new();
    for (key, vals) in &per_key {
        assert_eq!(
            vals.len(),
            CYCLES,
            "metric {:?} missing from at least one cycle; got {} of {} \
             samples; fix the measurement, do not loosen the test",
            key,
            vals.len(),
            CYCLES,
        );
        let mn = *vals.iter().min().unwrap();
        let mx = *vals.iter().max().unwrap();
        // Special case: if the minimum is zero, the function clocks
        // below ns granularity in at least one cycle. The (max-min)/min
        // ratio is undefined / unbounded; we use max-min in absolute ns
        // and require it stays under 5. Five ns of absolute drift on a
        // sub-ns function is the same scale of noise as 40% of a 10-ns
        // function — i.e., it represents the same "small enough" bar.
        if mn == 0 {
            let abs_drift = mx;
            if abs_drift > 5 {
                failures.push(format!(
                    "{} samples (min=0): max={} ns, absolute drift {} ns exceeds 5 ns",
                    key, mx, abs_drift,
                ));
            }
            continue;
        }
        let spread_pct = (mx - mn) * 100 / mn;
        if spread_pct >= 40 {
            failures.push(format!(
                "{} samples {:?}: max-min spread {}% (max={}, min={}) exceeds 40%",
                key, vals, spread_pct, mx, mn,
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "perf noise floor exceeded 40% spread on {} metric(s):\n  - {}\n\n\
             Per the task contract, fix the MEASUREMENT (more iterations, \
             better warm-up, larger black_box) — do not loosen this test.",
            failures.len(),
            failures.join("\n  - "),
        );
    }
}
