//! TASK-005 — windowed-median perf-gate property tests.
//!
//! These tests exercise the pure perf-gate functions from
//! `cuttle_verifier::perf` directly. They do NOT spin up a scratch
//! `cargo build + cargo test` chain, so they are fast (millisecond
//! range) and run as part of the default `cargo test --workspace`
//! sweep — no `#[ignore]`.
//!
//! Hermeticity: each test allocates a unique temp dir under
//! `std::env::temp_dir()` with the test name + PID + nanosecond clock
//! suffix. None of these tests touch the workspace `perf.jsonl`.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cuttle_verifier::cli::parse_args;
use cuttle_verifier::perf::{
    evaluate_perf_gate, parse_window_arg, parse_threshold_arg, read_baseline_window,
    PerfGateOutcome, PerfMetrics, DEFAULT_PERF_THRESHOLD_PCT, DEFAULT_PERF_WINDOW,
    MIN_BASELINE_ENTRIES,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

/// Allocate a unique temp dir. Mixing PID + nanos + a process-local
/// counter eliminates collisions even when several tests run in
/// parallel under one cargo-test invocation.
fn unique_dir(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cuttle-perf-gate-{}-{}-{}-{}",
        tag, pid, nanos, n
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// Write a multi-line `perf.jsonl` synthesised from per-line field
/// dictionaries. Each entry produces one JSON object with `ts_unix`
/// auto-incrementing and every `(key, value)` from the dictionary
/// rendered as `"<key>":<value>`.
fn write_perf_jsonl(path: &Path, entries: &[Vec<(&str, u64)>]) {
    let mut body = String::new();
    for (i, fields) in entries.iter().enumerate() {
        let mut parts: Vec<String> = vec![format!("\"ts_unix\":{}", 1_000_000_000u64 + i as u64)];
        for (k, v) in fields {
            parts.push(format!("\"{}\":{}", k, v));
        }
        body.push('{');
        body.push_str(&parts.join(","));
        body.push_str("}\n");
    }
    std::fs::write(path, body).expect("write perf.jsonl");
}

/// Convenience for the common "every line has the same fields with
/// values from a parallel vector" pattern.
fn write_lines_of(path: &Path, key: &str, values: &[u64]) {
    let entries: Vec<Vec<(&str, u64)>> = values
        .iter()
        .map(|v| vec![(key, *v)])
        .collect();
    write_perf_jsonl(path, &entries);
}

/// Build a candidate `PerfMetrics` from inline `(key, ns)` pairs.
fn candidate(pairs: &[(&str, u64)]) -> PerfMetrics {
    let mut m = PerfMetrics::default();
    for (k, v) in pairs {
        m.insert((*k).to_string(), *v);
    }
    m
}

// ---------------------------------------------------------------------
// Spec tests (TASK-005)
// ---------------------------------------------------------------------

#[test]
fn pass_on_equal_perf() {
    // Baseline median 100 ns, candidate at 100 ns → accept.
    let dir = unique_dir("equal");
    let baseline = dir.join("perf.jsonl");
    write_lines_of(&baseline, "demohash_ns", &[100; 10]);

    let cand = candidate(&[("demohash_ns", 100)]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("baseline file is readable");
    assert_eq!(outcome, PerfGateOutcome::Accept);
    assert!(outcome.is_accept());
}

#[test]
fn fail_on_30pct_regression_against_window_of_10() {
    // 10 lines of 100 ns. Candidate at 130 ns. Threshold default 20%.
    // 30% > 20% → reject.
    let dir = unique_dir("regress");
    let baseline = dir.join("perf.jsonl");
    write_lines_of(&baseline, "demohash_ns", &[100; 10]);

    let cand = candidate(&[("demohash_ns", 130)]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, DEFAULT_PERF_THRESHOLD_PCT)
        .expect("baseline file is readable");
    match outcome {
        PerfGateOutcome::Reject { reasons, threshold_pct } => {
            assert_eq!(threshold_pct, 20);
            assert_eq!(reasons.len(), 1);
            let (name, base, cand, delta) = &reasons[0];
            assert_eq!(name, "demohash_ns");
            assert_eq!(*base, 100);
            assert_eq!(*cand, 130);
            assert_eq!(*delta, 30);
        }
        other => panic!("expected Reject, got {:?}", other),
    }
}

#[test]
fn no_baseline_yet_accepts_when_missing() {
    // Missing file. First-cycle policy → accept.
    let dir = unique_dir("missing");
    let baseline = dir.join("perf.jsonl"); // never created

    let cand = candidate(&[("demohash_ns", 999)]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("missing file is not an error");
    assert_eq!(outcome, PerfGateOutcome::NoBaseline);
    assert!(outcome.is_accept());
}

#[test]
fn no_baseline_yet_accepts_when_below_min_entries() {
    // Single line — below MIN_BASELINE_ENTRIES. Still NoBaseline.
    assert!(MIN_BASELINE_ENTRIES >= 2);
    let dir = unique_dir("toofew");
    let baseline = dir.join("perf.jsonl");
    write_lines_of(&baseline, "demohash_ns", &[100]);

    let cand = candidate(&[("demohash_ns", 99999)]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("readable file");
    assert_eq!(outcome, PerfGateOutcome::NoBaseline);
}

#[test]
fn warm_up_jitter_tolerance() {
    // 10 lines varying ±8% of 100ns. Median is 100. Candidate at 105
    // ns is +5% → accept.
    let dir = unique_dir("jitter");
    let baseline = dir.join("perf.jsonl");
    // Symmetric jitter, sorted median is 100.
    write_lines_of(&baseline, "demohash_ns",
        &[92, 94, 96, 98, 100, 100, 102, 104, 106, 108]);

    let cand = candidate(&[("demohash_ns", 105)]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("readable file");
    assert_eq!(outcome, PerfGateOutcome::Accept, "candidate within 20% of median should accept");
}

#[test]
fn median_ignores_outliers() {
    // 9 lines at 100 ns, one outlier at 10000 ns. Median should be
    // 100, NOT the ~1090 average. Candidate at 115 ns = +15% < 20%
    // → accept. This proves the gate uses median, not mean.
    let dir = unique_dir("outlier");
    let baseline = dir.join("perf.jsonl");
    write_lines_of(&baseline, "demohash_ns",
        &[100, 100, 100, 100, 100, 100, 100, 100, 100, 10000]);

    let cand = candidate(&[("demohash_ns", 115)]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("readable file");
    assert_eq!(outcome, PerfGateOutcome::Accept,
        "median (=100) should ignore the 10000ns outlier; mean would have been ~1090");
}

#[test]
fn window_respects_n() {
    // 20 lines: first 10 at 500ns, last 10 at 100ns. With n=10 the
    // window is the trailing-10 → median 100 → candidate 130ns is
    // +30% → reject. With n=20 the full set is in play → sorted is
    // ten 100s then ten 500s, median is mean(100, 500) = 300 →
    // candidate 130ns is faster → accept. Demonstrates that
    // `--perf-window` actually changes the gate's decision boundary.
    let dir = unique_dir("window");
    let baseline = dir.join("perf.jsonl");
    let mut values: Vec<u64> = vec![500; 10];
    values.extend(vec![100; 10]);
    write_lines_of(&baseline, "demohash_ns", &values);

    let cand = candidate(&[("demohash_ns", 130)]);
    let with_window_10 = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("readable file");
    assert!(
        matches!(with_window_10, PerfGateOutcome::Reject { .. }),
        "window=10 should reject 130ns against trailing-10 median of 100ns, got {:?}",
        with_window_10
    );

    let with_window_20 = evaluate_perf_gate(&cand, &baseline, 20, 20)
        .expect("readable file");
    assert!(
        with_window_20.is_accept(),
        "window=20 should accept 130ns against the full-set median (~300); got {:?}",
        with_window_20
    );
}

#[test]
fn read_baseline_window_returns_per_field_median() {
    // Two fields. Lines: (10, 20), (10, 20), (10, 20). Median for
    // both should be the obvious single repeated value.
    let dir = unique_dir("perfield");
    let baseline = dir.join("perf.jsonl");
    write_perf_jsonl(&baseline, &[
        vec![("fletcher32_ns", 10), ("demohash_ns", 20)],
        vec![("fletcher32_ns", 10), ("demohash_ns", 20)],
        vec![("fletcher32_ns", 10), ("demohash_ns", 20)],
    ]);
    let b = read_baseline_window(&baseline, 10)
        .expect("readable")
        .expect("at least MIN_BASELINE_ENTRIES");
    assert_eq!(b.get("fletcher32_ns"), Some(10));
    assert_eq!(b.get("demohash_ns"), Some(20));
}

#[test]
fn unmatched_field_does_not_trigger_reject() {
    // Candidate has a field that the baseline never recorded. The
    // gate should skip it (schema-growth-friendly) and accept.
    let dir = unique_dir("unmatched");
    let baseline = dir.join("perf.jsonl");
    write_lines_of(&baseline, "fletcher32_ns", &[100; 5]);

    let cand = candidate(&[
        ("fletcher32_ns", 100),
        ("brand_new_metric_ns", 999999),
    ]);
    let outcome = evaluate_perf_gate(&cand, &baseline, 10, 20)
        .expect("readable file");
    assert_eq!(outcome, PerfGateOutcome::Accept);
}

// ---------------------------------------------------------------------
// CLI parsing tests
// ---------------------------------------------------------------------

fn argv(args: &[&str]) -> Vec<String> {
    let mut v = vec!["verify".to_string()];
    for a in args {
        v.push((*a).to_string());
    }
    v
}

#[test]
fn flag_parsing_decimal_ratio() {
    let p = parse_args(&argv(&["--perf-threshold", "1.2", "candidate.rs"]))
        .expect("parse ok");
    assert_eq!(p.perf_threshold, 20);
    let p = parse_args(&argv(&["--perf-threshold", "1.5", "candidate.rs"]))
        .expect("parse ok");
    assert_eq!(p.perf_threshold, 50);
    let p = parse_args(&argv(&["--perf-threshold", "2.0", "candidate.rs"]))
        .expect("parse ok");
    assert_eq!(p.perf_threshold, 100);
}

#[test]
fn flag_parsing_legacy_percent() {
    // Integer >= 10 keeps the legacy percent meaning.
    let p = parse_args(&argv(&["--perf-threshold", "50", "candidate.rs"]))
        .expect("parse ok");
    assert_eq!(p.perf_threshold, 50);
    let p = parse_args(&argv(&["--perf-threshold", "20", "candidate.rs"]))
        .expect("parse ok");
    assert_eq!(p.perf_threshold, 20);
}

#[test]
fn flag_parsing_window() {
    let p = parse_args(&argv(&["--perf-window", "5", "candidate.rs"]))
        .expect("parse ok");
    assert_eq!(p.perf_window, 5);
    assert!(parse_args(&argv(&["--perf-window", "0", "candidate.rs"])).is_err());
    assert!(parse_args(&argv(&["--perf-window", "1001", "candidate.rs"])).is_err());
    // Unit boundaries.
    let p = parse_args(&argv(&["--perf-window", "1", "candidate.rs"])).expect("ok");
    assert_eq!(p.perf_window, 1);
    let p = parse_args(&argv(&["--perf-window", "1000", "candidate.rs"])).expect("ok");
    assert_eq!(p.perf_window, 1000);
}

#[test]
fn flag_defaults_match_task_005_spec() {
    let p = parse_args(&argv(&["candidate.rs"])).expect("parse ok");
    assert_eq!(p.perf_threshold, DEFAULT_PERF_THRESHOLD_PCT);
    assert_eq!(p.perf_threshold, 20, "TASK-005 changes default to +20%");
    assert_eq!(p.perf_window, DEFAULT_PERF_WINDOW);
    assert_eq!(p.perf_window, 10);
}

#[test]
fn parse_threshold_arg_corner_cases() {
    // Negative numbers, NaN, infinity all rejected.
    assert!(parse_threshold_arg("-1").is_err());
    assert!(parse_threshold_arg("0.5").is_err());
    assert!(parse_threshold_arg("1.0").is_err());
    assert!(parse_threshold_arg("garbage").is_err());
}

#[test]
fn parse_window_arg_directly() {
    assert_eq!(parse_window_arg("10").unwrap(), 10);
    assert!(parse_window_arg("0").is_err());
    assert!(parse_window_arg("not-a-number").is_err());
}
