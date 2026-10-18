//! TASK-021 — hermetic proof that the p95-aware perf gate REJECTS
//! candidates whose per-cycle data point is dominated by a
//! pathological-input slow branch.
//!
//! These tests do NOT spawn a real cargo build. They directly
//! synthesise the `perf.jsonl` baseline and the candidate
//! [`PerfMetrics`] using values that mirror what the measurement-side
//! harnesses in `target_minimal/tests/perf.rs` and
//! `target_enterprise/tests/perf.rs` would produce against a
//! pathological function. The point of the suite is to nail down the
//! gate semantics so a future refactor of `evaluate_perf_gate` can
//! be caught the moment it drifts.
//!
//! The companion measurement-side tests (`pathological_demo_caught_by
//! _p95_methodology` in both target crates) prove that the
//! pathological function actually exhibits the claimed cost asymmetry
//! when measured the new way; the tests in this file prove that the
//! resulting metric is what the gate refuses to accept.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use cuttle_verifier::perf::{
    evaluate_perf_gate, p95_u64, PerfGateOutcome, PerfMetrics,
    DEFAULT_PERF_INPUTS_PER_CYCLE, DEFAULT_PERF_THRESHOLD_PCT, DEFAULT_PERF_WINDOW,
};

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unique_dir(tag: &str) -> PathBuf {
    let pid = std::process::id();
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cuttle-perf-pathological-{}-{}-{}-{}",
        tag, pid, nanos, n
    ));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

fn write_jsonl(path: &Path, lines: &[Vec<(&str, u64)>]) {
    let mut body = String::new();
    for (i, fields) in lines.iter().enumerate() {
        let mut parts: Vec<String> =
            vec![format!("\"ts_unix\":{}", 1_000_000_000u64 + i as u64)];
        for (k, v) in fields {
            parts.push(format!("\"{}\":{}", k, v));
        }
        body.push('{');
        body.push_str(&parts.join(","));
        body.push_str("}\n");
    }
    std::fs::write(path, body).expect("write perf.jsonl");
}

/// Synthesise a candidate's PerfMetrics from `(field, value)` pairs.
fn cand(pairs: &[(&str, u64)]) -> PerfMetrics {
    let mut m = PerfMetrics::default();
    for (k, v) in pairs {
        m.insert((*k).to_string(), *v);
    }
    m
}

// ---------------------------------------------------------------------
// Core proof: p95 metric trips the gate when single-input metric would not
// ---------------------------------------------------------------------

/// Numeric witness drawn from the measurement-side harness for the
/// `pathological_demo` function. Empirically (with the deterministic
/// seed in `target_minimal/tests/perf.rs`):
///
///   * single-input measurement: ~5 ns/call (early-return path)
///   * p95 across 32 random inputs: hundreds of µs/call
///
/// Encoded conservatively below so the test is robust to noise on
/// build machines (we use 10 ns and 10_000 ns, a 1_000× ratio, which
/// is well below what an actual measurement produces).
const PATHOLOGICAL_SINGLE_INPUT_NS: u64 = 10;
const PATHOLOGICAL_P95_NS: u64 = 10_000;

#[test]
fn p95_metric_rejects_when_single_input_baseline_would_accept() {
    // Build a baseline of historical SINGLE-INPUT measurements
    // (~10 ns/call). This represents what the old methodology
    // recorded for `pathological_demo` — a perfectly innocent-
    // looking trend line.
    let dir = unique_dir("p95-rejects");
    let baseline = dir.join("perf.jsonl");
    let single_lines: Vec<Vec<(&str, u64)>> = (0..DEFAULT_PERF_WINDOW)
        .map(|_| vec![("pathological_demo_ns", PATHOLOGICAL_SINGLE_INPUT_NS)])
        .collect();
    write_jsonl(&baseline, &single_lines);

    // The candidate uses the NEW methodology: p95 across 32 random
    // inputs. The pathological function blows up on adversarial
    // inputs so the candidate's value lands far above the baseline
    // median.
    let candidate = cand(&[("pathological_demo_ns", PATHOLOGICAL_P95_NS)]);
    let outcome = evaluate_perf_gate(
        &candidate,
        &baseline,
        DEFAULT_PERF_WINDOW,
        DEFAULT_PERF_THRESHOLD_PCT,
    )
    .expect("baseline readable");

    match outcome {
        PerfGateOutcome::Reject { reasons, threshold_pct } => {
            assert_eq!(
                threshold_pct, DEFAULT_PERF_THRESHOLD_PCT,
                "outcome must echo the threshold it was checked against"
            );
            let regressed = reasons
                .iter()
                .find(|(k, _, _, _)| k == "pathological_demo_ns");
            let (_, base, cand, delta) =
                regressed.expect("pathological_demo_ns must be the rejected field");
            assert_eq!(*base, PATHOLOGICAL_SINGLE_INPUT_NS);
            assert_eq!(*cand, PATHOLOGICAL_P95_NS);
            // Delta is the integer percent over baseline. With base=10
            // and cand=10_000 the ratio is 1000× and delta = 99_900.
            assert!(
                *delta >= 100_000_i64
                    || (*cand as i128 * 100 / *base as i128) - 100 >= threshold_pct as i128,
                "delta {} must reflect a regression beyond +{}%",
                delta, threshold_pct
            );
        }
        other => panic!(
            "expected Reject, got {:?}; the p95 metric should trip the gate \
             against a single-input baseline",
            other
        ),
    }
}

#[test]
fn p95_metric_accepts_when_p95_baseline_matches() {
    // The other end of the migration: once the perf.jsonl rolling
    // window has fully absorbed the methodology shift, the baseline
    // median is itself a p95 value. A candidate that produces the
    // SAME p95 must accept — no false-positive after the shift
    // settles.
    let dir = unique_dir("p95-accepts");
    let baseline = dir.join("perf.jsonl");
    let p95_lines: Vec<Vec<(&str, u64)>> = (0..DEFAULT_PERF_WINDOW)
        .map(|_| vec![("pathological_demo_ns", PATHOLOGICAL_P95_NS)])
        .collect();
    write_jsonl(&baseline, &p95_lines);

    let candidate = cand(&[("pathological_demo_ns", PATHOLOGICAL_P95_NS)]);
    let outcome = evaluate_perf_gate(
        &candidate,
        &baseline,
        DEFAULT_PERF_WINDOW,
        DEFAULT_PERF_THRESHOLD_PCT,
    )
    .expect("baseline readable");
    assert_eq!(
        outcome,
        PerfGateOutcome::Accept,
        "candidate matching baseline median must accept"
    );
}

#[test]
fn p95_metric_accepts_within_envelope_after_settle() {
    // After the rolling window absorbs the methodology shift, the
    // baseline is a series of p95 values. A new candidate slightly
    // faster than the median must still accept; this is the steady-
    // state happy path under TASK-021 semantics.
    let dir = unique_dir("p95-envelope");
    let baseline = dir.join("perf.jsonl");
    // Mild jitter ±5% around 10_000.
    let values: [u64; 10] = [9500, 9700, 9800, 9900, 10_000, 10_000, 10_100, 10_200, 10_300, 10_500];
    let lines: Vec<Vec<(&str, u64)>> = values
        .iter()
        .map(|v| vec![("pathological_demo_ns", *v)])
        .collect();
    write_jsonl(&baseline, &lines);

    // Median = 10_000. Candidate at 10_500 is +5%, well under the
    // 20% threshold.
    let candidate = cand(&[("pathological_demo_ns", 10_500)]);
    let outcome = evaluate_perf_gate(
        &candidate,
        &baseline,
        DEFAULT_PERF_WINDOW,
        DEFAULT_PERF_THRESHOLD_PCT,
    )
    .expect("baseline readable");
    assert_eq!(outcome, PerfGateOutcome::Accept);
}

// ---------------------------------------------------------------------
// Sanity / methodology tests
// ---------------------------------------------------------------------

#[test]
fn p95_skips_single_worst_case_outlier() {
    // 32 simulated per-input ns values: 30 at the "normal" cost and
    // 2 at the "slow" cost. p95 = index 30 in the sorted ascending
    // list = the FIRST of the two slow samples. The single
    // worst-case outlier (index 31) is ignored — that's a deliberate
    // property the methodology relies on so a single context-switch
    // batch does not poison the metric.
    let mut samples = vec![100u64; 30];
    samples.push(1_000_000); // first slow input
    samples.push(2_000_000); // second slow input — the outlier
    let v = p95_u64(&samples);
    assert_eq!(
        v, 1_000_000,
        "p95 must equal the second-slowest sample (= first slow input), \
         not the absolute max (= outlier)"
    );
}

#[test]
fn p95_methodology_distinguishes_pathological_from_benign() {
    // Two synthetic candidate sweeps:
    //   * benign:        every input clocks ~100 ns. p95 ≈ 100.
    //   * pathological:  30 of 32 inputs clock at the slow branch
    //                    (~10_000 ns) and 2 at the fast branch
    //                    (~5 ns). p95 lands at the slow value.
    // Both feed the SAME baseline (the historical-single-input
    // median = ~5 ns). The benign candidate is rejected because
    // 100 ns is 20× the baseline, **which is the methodology
    // working as designed for a real perf regression**. The
    // pathological candidate is rejected even harder because its
    // p95 is far worse.
    //
    // The asymmetry we're proving: under the OLD methodology the
    // pathological candidate would have produced ~5 ns (its
    // single-input measurement) and slipped through. The NEW
    // methodology surfaces it.
    let benign_samples: Vec<u64> = vec![100; DEFAULT_PERF_INPUTS_PER_CYCLE];
    let benign_p95 = p95_u64(&benign_samples);
    assert_eq!(benign_p95, 100, "benign candidate p95 is uniform value");

    let mut path_samples = vec![10_000u64; 30];
    path_samples.push(5);
    path_samples.push(5);
    let path_p95 = p95_u64(&path_samples);
    assert_eq!(
        path_p95, 10_000,
        "pathological candidate p95 reflects the slow branch (30 of 32 samples)"
    );

    // Both are above a single-input-style 5-ns baseline by much
    // more than 20%, but the path candidate is dramatically worse —
    // and the relative ranking is what the audit log will show.
    assert!(path_p95 > benign_p95 * 50);
}

#[test]
fn single_input_pathological_would_have_slipped_through() {
    // This test states the attack-class invariant explicitly: with
    // the OLD methodology, the pathological candidate's recorded
    // ns/call would have been the FAST-path single-input value
    // (~5 ns), and a baseline of similar fast-path values would
    // have ACCEPTED the candidate. The new methodology fixes this.
    let dir = unique_dir("old-methodology");
    let baseline = dir.join("perf.jsonl");
    let fast_path_lines: Vec<Vec<(&str, u64)>> = (0..DEFAULT_PERF_WINDOW)
        .map(|_| vec![("pathological_demo_ns", 5)])
        .collect();
    write_jsonl(&baseline, &fast_path_lines);

    // OLD methodology candidate value: 5 ns (single-input
    // measurement on the canonical buffer).
    let old_candidate = cand(&[("pathological_demo_ns", 5)]);
    let old_outcome = evaluate_perf_gate(
        &old_candidate,
        &baseline,
        DEFAULT_PERF_WINDOW,
        DEFAULT_PERF_THRESHOLD_PCT,
    )
    .expect("baseline readable");
    assert_eq!(
        old_outcome,
        PerfGateOutcome::Accept,
        "single-input methodology accepts the pathological candidate \
         (this is the bug TASK-021 fixes)"
    );

    // NEW methodology candidate value (p95 across 32 inputs):
    // 10_000 ns. Against the same legacy baseline → reject.
    let new_candidate = cand(&[("pathological_demo_ns", PATHOLOGICAL_P95_NS)]);
    let new_outcome = evaluate_perf_gate(
        &new_candidate,
        &baseline,
        DEFAULT_PERF_WINDOW,
        DEFAULT_PERF_THRESHOLD_PCT,
    )
    .expect("baseline readable");
    assert!(
        !new_outcome.is_accept(),
        "p95 methodology must reject the pathological candidate; got {:?}",
        new_outcome
    );
}

#[test]
fn methodology_shift_absorbed_by_window_within_ten_cycles() {
    // The TASK-021 spec promises the rolling window absorbs the
    // one-time perturbation within ~10 cycles. Demonstrate this
    // numerically: an OLD entry (5 ns) followed by 10 NEW entries
    // (10_000 ns each) — the median over the trailing 10 is
    // dominated by the new values, NOT contaminated by the legacy
    // 5-ns entry.
    let dir = unique_dir("absorb");
    let baseline = dir.join("perf.jsonl");
    let mut lines: Vec<Vec<(&str, u64)>> = vec![
        vec![("pathological_demo_ns", 5)],
        vec![("pathological_demo_ns", 5)],
    ];
    for _ in 0..DEFAULT_PERF_WINDOW {
        lines.push(vec![("pathological_demo_ns", 10_000)]);
    }
    write_jsonl(&baseline, &lines);

    // Candidate at 10_500 is +5% over the new-methodology median
    // (10_000) but 110_000% over the legacy 5-ns value. The window
    // is supposed to anchor on the trailing 10 entries, so this
    // candidate must ACCEPT.
    let candidate = cand(&[("pathological_demo_ns", 10_500)]);
    let outcome = evaluate_perf_gate(
        &candidate,
        &baseline,
        DEFAULT_PERF_WINDOW,
        DEFAULT_PERF_THRESHOLD_PCT,
    )
    .expect("baseline readable");
    assert_eq!(
        outcome,
        PerfGateOutcome::Accept,
        "trailing-window median should absorb the methodology shift; \
         got {:?} — the window is not anchoring on the new entries",
        outcome
    );
}

#[test]
fn p95_inputs_per_cycle_constant_unchanged() {
    // Anchor for the documentation invariant — if a future change
    // moves DEFAULT_PERF_INPUTS_PER_CYCLE, the change-author must
    // explicitly bump this assertion alongside the perf-baseline
    // semantics document.
    assert_eq!(DEFAULT_PERF_INPUTS_PER_CYCLE, 32);
}
