//! Pure performance-envelope gating helpers.
//!
//! These functions are the engine behind the `verify` binary's perf
//! gate. They live in `lib.rs` (re-exported here) so external integration
//! tests can drive them directly without spinning up a real
//! `cargo build + cargo test` scratch dir.
//!
//! # Threshold semantics
//!
//! The gate compares a candidate measurement against the **per-field
//! median of the last N accepted entries** in `perf.jsonl`. A candidate
//! is rejected if any field exceeds its baseline median by more than
//! `threshold_pct` percent. The default `threshold_pct` is 20 (= +20%
//! slower than the rolling median triggers reject), set in
//! [`DEFAULT_PERF_THRESHOLD_PCT`].
//!
//! # First-cycle bootstrap
//!
//! On the very first cycle there is no `perf.jsonl`, or the file exists
//! with fewer than the minimum-baseline-entries quota
//! ([`MIN_BASELINE_ENTRIES`]). In both cases
//! [`evaluate_perf_gate`] accepts unconditionally and emits the
//! `verify: no perf baseline available` line to stderr. The morph
//! engine therefore never needs to know about the bootstrap edge case.
//!
//! # TASK-021 — p95-across-inputs measurement semantics
//!
//! Through TASK-020 the per-cycle perf data point was a min-of-batches
//! measurement of one **fixed** input per function (`[0..16].into()` for
//! `fletcher32`, etc.). That is sound noise reduction for the function-
//! under-test on *that* input, but it is a known weak spot against
//! algorithmic-complexity attacks: a candidate is free to specialise its
//! implementation for the canonical test buffer (memoise the answer, or
//! pick a layout that's cache-friendly only for those exact 16 bytes)
//! while degrading to quadratic time on attacker-controlled inputs.
//!
//! Starting at TASK-021 the per-cycle data point for every benchmarked
//! function is the **p95 latency across 32 proptest-generated random
//! inputs**, all measured with the same min-of-batches inner protocol.
//! 32 inputs gives the p95 enough resolution to ignore the single
//! slowest outlier (often a cache-cold first call) while still
//! surfacing any algorithmic regression that affects roughly the worst
//! 5% of the input space — which is the regime any practical complexity
//! attack will live in. The percentile arithmetic is centralised in
//! [`p95_u64`] so the measurement crates (`target_minimal`,
//! `target_enterprise`) and the gate-side fixtures import the same
//! definition.
//!
//! The rolling-window-median comparison stays unchanged. The window
//! continues to be the trailing `DEFAULT_PERF_WINDOW` entries' median
//! per field — only the *meaning* of each entry's value shifts. Existing
//! pre-TASK-021 entries (single-input measurements) are absorbed by the
//! window over ~10 cycles; mixing them with the new p95 entries is
//! statistically benign because the median is robust to either source.

use anyhow::{Context, Result};
use std::fs;
use std::path::Path;

/// Default regression threshold expressed as a **percent over baseline
/// median**. `20` means "reject if any function is more than 20% slower
/// than the rolling-window median".
///
/// The previous default was 50% against a single-line baseline. TASK-005
/// tightens that to 20% against a windowed median; the median absorbs
/// the warm-up jitter the old single-line baseline could not.
pub const DEFAULT_PERF_THRESHOLD_PCT: u32 = 20;

/// Default rolling window. The gate reads the last N accepted entries
/// from `perf.jsonl` and computes a per-field median across them.
pub const DEFAULT_PERF_WINDOW: usize = 10;

/// Minimum entries required before the gate fires. With fewer accepted
/// lines on record we cannot form a statistically meaningful baseline,
/// so the gate accepts and emits the no-baseline diagnostic instead.
/// First-cycle policy from TASK-005 maps to this threshold.
pub const MIN_BASELINE_ENTRIES: usize = 2;

/// Parse the CLI string form of `--perf-threshold` into the integer
/// percent the gate uses internally.
///
/// Two input forms are accepted for backward compatibility:
///
/// * **Ratio form** (TASK-005 spec): a decimal value `>= 1.0`. `1.2`
///   means "20% over baseline". Detected when the value contains `.`
///   or its numeric magnitude is `< 10`.
/// * **Legacy percent form**: an integer `>= 10`. `50` means "50% over
///   baseline" — the original Phase-2 semantics.
///
/// The function rejects out-of-range inputs (`<1%` or `>1000%` in
/// percent terms, equivalently `<1.01` or `>11.0` in ratio terms).
pub fn parse_threshold_arg(s: &str) -> Result<u32> {
    // Decimal/ratio form — anything containing a '.' is unambiguously
    // a ratio.
    if s.contains('.') {
        let r: f64 = s.parse().with_context(|| {
            format!("--perf-threshold not a number: {}", s)
        })?;
        if !r.is_finite() || r <= 1.0 {
            anyhow::bail!(
                "--perf-threshold ratio {} must be > 1.0 (e.g. 1.2 = +20%)",
                s
            );
        }
        let pct = ((r - 1.0) * 100.0).round() as i64;
        if !(1..=1000).contains(&pct) {
            anyhow::bail!(
                "--perf-threshold ratio {} out of range; expected (1.0, 11.0]",
                s
            );
        }
        return Ok(pct as u32);
    }
    // No dot: integer. Values < 10 are interpreted as ratios too
    // (e.g. `2` = +100%); values >= 10 keep the legacy percent
    // semantics.
    let n: i64 = s
        .parse()
        .with_context(|| format!("--perf-threshold not an integer: {}", s))?;
    let pct = if n < 10 {
        if n <= 1 {
            anyhow::bail!(
                "--perf-threshold {} too small; must be a ratio > 1 or a percent >= 10",
                s
            );
        }
        (n - 1).saturating_mul(100)
    } else {
        n
    };
    if !(1..=1000).contains(&pct) {
        anyhow::bail!(
            "--perf-threshold {} out of range; expected 1..=1000 in percent terms",
            s
        );
    }
    Ok(pct as u32)
}

/// Parse the CLI string form of `--perf-window` into the integer count
/// the gate uses internally. Accepts `1..=1000`. Rejects `0`, anything
/// non-numeric, and values above the cap.
pub fn parse_window_arg(s: &str) -> Result<usize> {
    let n: usize = s
        .parse()
        .with_context(|| format!("--perf-window not an integer: {}", s))?;
    if n == 0 {
        anyhow::bail!("--perf-window must be >= 1 (got 0)");
    }
    if n > 1000 {
        anyhow::bail!("--perf-window {} exceeds cap of 1000", n);
    }
    Ok(n)
}

/// In-memory representation of one perf measurement. Keyed by
/// `*_ns` field name (matching the JSONL schema) so that adding a new
/// function on the target side surfaces here without an enum bump.
#[derive(Debug, Default, Clone)]
pub struct PerfMetrics {
    /// Map of `<fn>_ns` -> ns/call. Insertion order preserved for
    /// stable diagnostic output (no `IndexMap` dep; we re-sort on
    /// write).
    pub fields: Vec<(String, u64)>,
}

impl PerfMetrics {
    pub fn get(&self, key: &str) -> Option<u64> {
        self.fields
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| *v)
    }
    pub fn insert(&mut self, key: String, value: u64) {
        if let Some(slot) = self.fields.iter_mut().find(|(k, _)| *k == key) {
            slot.1 = value;
        } else {
            self.fields.push((key, value));
        }
    }
}

/// Hand-rolled JSON object parser specialised for the perf.jsonl schema.
/// Recognises top-level `"<key>": <integer-or-null>` pairs. Anything
/// else (strings, nested objects, floats) is silently skipped — the
/// schema for this file is the four `*_ns` fields plus `ts_unix`, all
/// integers or `null`. We avoid the `serde_json` dep to keep the
/// verifier's footprint small per the workspace constraint.
///
/// Forward-compatibility: any field whose name ends in `_ns` and whose
/// value parses as a non-negative integer is captured, regardless of
/// the canonical field set.
pub fn parse_jsonl_metrics(line: &str) -> PerfMetrics {
    let mut m = PerfMetrics::default();
    let bytes = line.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        i += 1;
        let key_start = i;
        while i < bytes.len() && bytes[i] != b'"' {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let key = &line[key_start..i];
        i += 1;
        while i < bytes.len() && (bytes[i] == b':' || bytes[i].is_ascii_whitespace()) {
            i += 1;
        }
        if i >= bytes.len() {
            break;
        }
        let val_start = i;
        while i < bytes.len() && bytes[i] != b',' && bytes[i] != b'}' {
            i += 1;
        }
        let val = line[val_start..i].trim();
        if key.ends_with("_ns") {
            if let Ok(n) = val.parse::<u64>() {
                m.insert(key.to_string(), n);
            }
        }
        if i < bytes.len() && bytes[i] == b',' {
            i += 1;
        }
    }
    m
}

/// Read the last non-empty line of a JSONL file and parse it. Kept as a
/// thin compatibility wrapper around [`read_baseline_window`] with
/// `n=1`; tests and the legacy `verify` flow still call this.
pub fn read_baseline(path: &Path) -> Result<Option<PerfMetrics>> {
    let lines = match read_jsonl_lines(path)? {
        Some(v) => v,
        None => return Ok(None),
    };
    match lines.last() {
        Some(last) => Ok(Some(parse_jsonl_metrics(last))),
        None => Ok(None),
    }
}

/// Read the last `n` non-empty lines of a JSONL file and compute the
/// per-field median across them. The median is computed independently
/// for every `*_ns` field; a field only contributes from the lines that
/// actually carry it. This is the rolling-window baseline TASK-005
/// demands.
///
/// Returns:
///   * `Ok(None)` — file absent, empty, or has fewer than
///     [`MIN_BASELINE_ENTRIES`] entries. Caller treats as "no
///     baseline" and accepts unconditionally.
///   * `Ok(Some(m))` — median across `min(n, available)` entries.
///   * `Err(_)` — infrastructure error (file unreadable for a reason
///     other than `NotFound`).
pub fn read_baseline_window(path: &Path, n: usize) -> Result<Option<PerfMetrics>> {
    let lines = match read_jsonl_lines(path)? {
        Some(v) => v,
        None => return Ok(None),
    };
    if lines.len() < MIN_BASELINE_ENTRIES {
        return Ok(None);
    }
    // Take the last `n` lines.
    let take = lines.len().min(n);
    let window: Vec<&String> = lines.iter().rev().take(take).collect();

    // Collect each field's samples across the window.
    let mut buckets: Vec<(String, Vec<u64>)> = Vec::new();
    for line in &window {
        let parsed = parse_jsonl_metrics(line);
        for (k, v) in &parsed.fields {
            if let Some(slot) = buckets.iter_mut().find(|(name, _)| name == k) {
                slot.1.push(*v);
            } else {
                buckets.push((k.clone(), vec![*v]));
            }
        }
    }
    let mut out = PerfMetrics::default();
    for (k, mut samples) in buckets.drain(..) {
        if samples.is_empty() {
            continue;
        }
        samples.sort_unstable();
        let median = median_u64(&samples);
        out.insert(k, median);
    }
    Ok(Some(out))
}

/// Percentile-95 across a slice of ns/call measurements, returning the
/// integer ns value at the p95 position. This is the centralised
/// definition the perf integration tests in `target_minimal` and
/// `target_enterprise` import via the `proteus_verifier` dev-dep — any
/// future change to the percentile formula propagates from one place to
/// both ends of the measurement pipeline.
///
/// Definition (Type-7, nearest-rank, zero-indexed):
/// for `n` samples the p95 index is `idx = floor((n * 95) / 100)`, capped
/// at `n - 1`. For the canonical TASK-021 sample count `n = 32` this is
/// `idx = 30`, which is the **second-slowest** of 32 sorted ascending
/// samples. That deliberately excludes a single worst-case outlier
/// (often a cold-cache first call or an interrupt-suspended batch) while
/// still tracking any regression that affects the slowest ~5% of the
/// input space.
///
/// Other sample counts work too — `n = 1` returns the only sample,
/// `n = 0` returns `0`. The function uses a sort-on-clone strategy so
/// callers can pass an immutable slice and not worry about whether it
/// is already sorted.
pub fn p95_u64(samples: &[u64]) -> u64 {
    let n = samples.len();
    if n == 0 {
        return 0;
    }
    if n == 1 {
        return samples[0];
    }
    let mut sorted: Vec<u64> = samples.to_vec();
    sorted.sort_unstable();
    let idx = (n.saturating_mul(95) / 100).min(n - 1);
    sorted[idx]
}

/// Sample count the TASK-021 perf harness drives each benchmarked
/// function through per cycle. 32 is a sweet spot: enough samples for
/// a well-defined p95 (the index lands at position 30, two away from
/// the max, so a single outlier batch does not push the metric up),
/// few enough that even ~2 µs/call functions like
/// `DemoSignatureVerify::verify` complete the full sweep in the
/// hundreds-of-ms range. Made `pub` so the measurement crates can
/// import it as the source of truth and a future tightening (say to
/// 64) propagates cleanly.
pub const DEFAULT_PERF_INPUTS_PER_CYCLE: usize = 32;

/// Median of a pre-sorted slice. Even-length slices are reduced by
/// integer-averaging the two middle elements (sum-then-divide, no
/// floats). For odd lengths the single middle element is returned.
/// Integer arithmetic only — perf field values are `u64` ns counts and
/// the perf log schema mandates integers throughout.
fn median_u64(sorted: &[u64]) -> u64 {
    let n = sorted.len();
    if n == 0 {
        return 0;
    }
    if n % 2 == 1 {
        sorted[n / 2]
    } else {
        // u128 widening so the sum cannot overflow even on adversarial
        // inputs.
        let lo = sorted[n / 2 - 1] as u128;
        let hi = sorted[n / 2] as u128;
        ((lo + hi) / 2) as u64
    }
}

/// Read all non-empty trimmed lines from a JSONL file. `Ok(None)` only
/// for `NotFound`; an empty-but-present file maps to `Ok(Some(vec![]))`
/// (the caller then decides whether emptiness counts as "no baseline").
fn read_jsonl_lines(path: &Path) -> Result<Option<Vec<String>>> {
    let contents = match fs::read_to_string(path) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(e) => {
            return Err(anyhow::Error::from(e).context(format!(
                "read perf baseline {}",
                path.display()
            )));
        }
    };
    let lines: Vec<String> = contents
        .lines()
        .map(|l| l.trim().to_string())
        .filter(|l| !l.is_empty())
        .collect();
    Ok(Some(lines))
}

/// Outcome of the perf threshold check. Distinguishes "no baseline so
/// accept" from "baseline present and candidate within envelope" from
/// "regression". The CLI maps `NoBaseline` and `Accept` to exit code 0
/// and `Reject` to exit code 1.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PerfGateOutcome {
    /// File missing, empty, or fewer than [`MIN_BASELINE_ENTRIES`]
    /// entries. First-cycle bootstrap path. Caller emits a stderr
    /// notice and accepts.
    NoBaseline,
    /// Baseline present, candidate within envelope on every field.
    Accept,
    /// At least one field regressed beyond threshold. The reasons
    /// vector carries the per-function diagnostics the caller logs.
    Reject {
        /// Per-regression record: (field name, baseline ns, candidate
        /// ns, observed percent delta).
        reasons: Vec<(String, u64, u64, i64)>,
        /// Threshold the candidate was checked against, in percent.
        /// Echoed so the caller can print the same number it parsed.
        threshold_pct: u32,
    },
}

impl PerfGateOutcome {
    /// `true` if the candidate should be accepted on the perf axis.
    pub fn is_accept(&self) -> bool {
        matches!(self, Self::NoBaseline | Self::Accept)
    }
}

/// Compare `candidate` against the windowed-median baseline at
/// `baseline_path` and decide whether the perf envelope is satisfied.
///
/// This is the pure entry point. The binary wraps it to also emit the
/// per-field stderr diagnostics; tests call it directly to assert the
/// outcome.
///
/// `window` is the number of trailing accepted entries the median is
/// computed across. `threshold_pct` is the integer percent overrun that
/// triggers reject (e.g. `20` = "+20%"); see [`parse_threshold_arg`]
/// for the dual-form CLI mapping.
pub fn evaluate_perf_gate(
    candidate: &PerfMetrics,
    baseline_path: &Path,
    window: usize,
    threshold_pct: u32,
) -> Result<PerfGateOutcome> {
    let baseline = match read_baseline_window(baseline_path, window)? {
        Some(b) => b,
        None => return Ok(PerfGateOutcome::NoBaseline),
    };

    let mut regressed: Vec<(String, u64, u64, i64)> = Vec::new();
    for (key, cand_ns) in &candidate.fields {
        let base_ns = match baseline.get(key) {
            Some(b) => b,
            None => continue,
        };
        if base_ns == 0 {
            if *cand_ns == 0 {
                continue;
            }
            let pct = (*cand_ns as i64).saturating_mul(100);
            if pct > threshold_pct as i64 {
                regressed.push((key.clone(), base_ns, *cand_ns, pct));
            }
            continue;
        }
        let ratio_pct = (*cand_ns as i128).saturating_mul(100) / (base_ns as i128);
        let delta_pct = ratio_pct - 100;
        if delta_pct > threshold_pct as i128 {
            regressed.push((key.clone(), base_ns, *cand_ns, delta_pct as i64));
        }
    }

    if regressed.is_empty() {
        Ok(PerfGateOutcome::Accept)
    } else {
        Ok(PerfGateOutcome::Reject {
            reasons: regressed,
            threshold_pct,
        })
    }
}

/// List the candidate's `*_ns` fields whose name does not appear in
/// `baseline`. Reported separately by the binary so the operator can
/// see schema growth.
pub fn unmatched_fields(candidate: &PerfMetrics, baseline: &PerfMetrics) -> Vec<String> {
    let mut out = Vec::new();
    for (k, _) in &candidate.fields {
        if baseline.get(k).is_none() {
            out.push(k.clone());
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn median_averages_two_middles_for_even() {
        let mut s = vec![1u64, 2, 3, 4];
        s.sort_unstable();
        // Average of 2 and 3 floored = 2.
        assert_eq!(median_u64(&s), 2);
    }

    #[test]
    fn median_even_length_balances_two_middles() {
        let mut s = vec![10u64, 20, 30, 40];
        s.sort_unstable();
        // (20 + 30) / 2 = 25.
        assert_eq!(median_u64(&s), 25);
    }

    #[test]
    fn median_picks_middle_for_odd() {
        let mut s = vec![1u64, 2, 3];
        s.sort_unstable();
        assert_eq!(median_u64(&s), 2);
    }

    #[test]
    fn parse_threshold_ratio_form() {
        assert_eq!(parse_threshold_arg("1.2").unwrap(), 20);
        assert_eq!(parse_threshold_arg("1.5").unwrap(), 50);
        assert_eq!(parse_threshold_arg("2.0").unwrap(), 100);
    }

    #[test]
    fn parse_threshold_legacy_percent() {
        assert_eq!(parse_threshold_arg("50").unwrap(), 50);
        assert_eq!(parse_threshold_arg("20").unwrap(), 20);
    }

    #[test]
    fn parse_threshold_small_int_is_ratio() {
        // `2` (no dot, < 10) is interpreted as a ratio of 2.0 = +100%.
        assert_eq!(parse_threshold_arg("2").unwrap(), 100);
    }

    #[test]
    fn parse_threshold_rejects_zero_or_one() {
        assert!(parse_threshold_arg("0").is_err());
        assert!(parse_threshold_arg("1").is_err());
        assert!(parse_threshold_arg("1.0").is_err());
    }

    #[test]
    fn parse_window_accepts_in_range() {
        assert_eq!(parse_window_arg("1").unwrap(), 1);
        assert_eq!(parse_window_arg("10").unwrap(), 10);
        assert_eq!(parse_window_arg("1000").unwrap(), 1000);
    }

    #[test]
    fn parse_window_rejects_zero_and_overflow() {
        assert!(parse_window_arg("0").is_err());
        assert!(parse_window_arg("1001").is_err());
        assert!(parse_window_arg("abc").is_err());
    }

    // ---------------------------------------------------------------------
    // p95_u64 — TASK-021 percentile arithmetic
    // ---------------------------------------------------------------------

    #[test]
    fn p95_of_thirty_two_picks_second_slowest() {
        // 32 samples, 30 fast (=10) and 2 slow (=1000, =1001). Sorted
        // index 30 is the second-slowest, i.e. value 1000. p95 must
        // therefore equal 1000 — not 1001 (which would be the max) and
        // not 10 (which would be every fast sample).
        let mut s: Vec<u64> = vec![10; 30];
        s.push(1000);
        s.push(1001);
        assert_eq!(p95_u64(&s), 1000,
            "p95 of 30 fast + 2 slow must equal the slower-but-not-slowest sample");
        // Order-insensitive: shuffle the inputs and assert the same answer.
        let mut s2 = s.clone();
        s2.reverse();
        assert_eq!(p95_u64(&s2), 1000, "p95 must be order-insensitive");
    }

    #[test]
    fn p95_empty_returns_zero() {
        assert_eq!(p95_u64(&[]), 0);
    }

    #[test]
    fn p95_single_sample_returns_it() {
        assert_eq!(p95_u64(&[42]), 42);
    }

    #[test]
    fn p95_of_uniform_returns_the_value() {
        let s = vec![5u64; 32];
        assert_eq!(p95_u64(&s), 5);
    }

    #[test]
    fn p95_thirty_two_matches_index_30() {
        // 32 samples 1..=32, sorted ascending. Index 30 = value 31.
        let s: Vec<u64> = (1..=32u64).collect();
        assert_eq!(p95_u64(&s), 31);
    }

    #[test]
    fn p95_one_hundred_matches_index_95() {
        // Sanity check for the n != 32 case: 100 samples, sorted, index 95
        // (zero-based) is value 96.
        let s: Vec<u64> = (1..=100u64).collect();
        assert_eq!(p95_u64(&s), 96);
    }

    #[test]
    fn p95_caps_at_max_when_index_would_overflow() {
        // n=2: floor((2*95)/100) = 1, capped at n-1 = 1 → second sample.
        let s = vec![10u64, 100];
        assert_eq!(p95_u64(&s), 100);
    }

    #[test]
    fn default_inputs_per_cycle_is_thirty_two() {
        // TASK-021 fixes the per-function input count at 32. A future
        // tightening (e.g., to 64) should be a deliberate edit that
        // updates this assertion alongside the constant.
        assert_eq!(DEFAULT_PERF_INPUTS_PER_CYCLE, 32);
    }
}
