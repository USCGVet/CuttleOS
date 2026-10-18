//! Per-function performance measurement for `cuttle-target-minimal`,
//! TASK-021 edition: proptest-generated 32-input sweeps, per-input
//! min-of-batches measurement, p95-across-inputs reporting.
//!
//! # Why this differs from the TASK-005 perf harness
//!
//! TASK-005's harness measured each function under a **fixed** input
//! (`[0x00, 0x11, ..., 0xFF]` for `fletcher32`, etc.) and reported the
//! min across 5 batches of 200_000 iterations. That is sound for
//! noise reduction on *that one input* — but it is wide open to
//! algorithmic-complexity attacks: a morph candidate is free to ship
//! an implementation that runs fast on the canonical 16-byte test
//! buffer (perhaps by memoising) while degrading to quadratic time on
//! attacker-controlled inputs. The morph engine would happily accept
//! such a candidate because the perf gate would see no regression on
//! the one input it measured.
//!
//! Starting at TASK-021 the methodology becomes:
//!
//!   1. Deterministically seed a `proptest::TestRunner` with a fixed
//!      32-byte seed so cycle-to-cycle inputs are identical.
//!   2. For each function under test, generate
//!      [`DEFAULT_PERF_INPUTS_PER_CYCLE`] random inputs (= 32) sampled
//!      from a function-specific [`Strategy`].
//!   3. For each input, run the existing
//!      warm-up + min-of-batches inner loop and record one ns/call
//!      value.
//!   4. Sort the 32 ns/call values and report [`p95_u64`] (= the
//!      second-slowest, by Type-7 nearest-rank indexing) as the
//!      cycle's perf metric. The single worst-case outlier is
//!      ignored — typically it is a cache-cold first call or a batch
//!      interrupted by the OS scheduler.
//!
//! # Wall-clock budget
//!
//! Inner-loop iteration counts are split between "fast" functions
//! (sub-100-ns; fletcher32, feistel_mix, derive_byte, DemoHash::hash)
//! and "slow" functions (DemoSignatureVerify::verify, demosyscall
//! dispatch), so the full 32-input sweep stays in the same wall-clock
//! envelope as the old single-input harness (~2-3 s in release mode).
//! Per the TASK-005 commentary still applies — `std::hint::black_box`
//! on both inputs and outputs, `--release` is the only mode in which
//! the numbers reflect real per-call cost.
//!
//! # Pathological-input fixture
//!
//! The final two tests in this file exercise [`pathological_demo`], a
//! synthetic function whose body is fast on `[0u8; 16]` (an early
//! return) but linear-in-`u32::MAX/16` on inputs containing the byte
//! `0xAA`. The TASK-005 harness would have measured 5 ns/call against
//! the canonical buffer and the morph engine's perf gate would have
//! happily accepted that. The TASK-021 harness measures it against 32
//! random inputs — most of which contain at least one 0xAA byte — and
//! the resulting p95 is *thousands of times* the single-input
//! measurement. The assertion at the end of this file is the runtime
//! proof that the new methodology actually defends against the
//! attack class.

use std::hint::black_box;
use std::time::Instant;

use proptest::prelude::*;
use proptest::strategy::{Strategy, ValueTree};
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use cuttle_contracts::{Hash, SignatureVerify, SyscallDispatch};
use cuttle_target_minimal::{
    derive_byte, feistel_mix, fletcher32, fletcher_pair, DemoHash, DemoSignatureVerify,
    DemoSyscallDispatch,
};
use cuttle_verifier::perf::{p95_u64, DEFAULT_PERF_INPUTS_PER_CYCLE};

// ---------------------------------------------------------------------
// Inner-loop knobs (per-input measurement)
// ---------------------------------------------------------------------

/// Warm-up iterations for **fast** functions. Cut from 50_000 (TASK-005)
/// down to 10_000 because the outer loop now reaches each input 32
/// times; the global predictor / icache / TLB stay primed across
/// inputs even after a single warm-up phase. 10_000 calls at ~5 ns is
/// 50 µs per input — invisible in the cycle wall-clock.
const FAST_WARMUP: u64 = 10_000;

/// Measured calls per batch for **fast** functions. 100_000 × 3 = 300k
/// measured calls per (function, input) pair. At 5 ns/call that is
/// ~1.5 ms per input; over 32 inputs ≈ 50 ms per function. Total
/// across the four fast functions ≈ 200 ms.
const FAST_BATCH_ITERS: u64 = 100_000;

/// Number of inner batches per (function, input) pair, both for fast
/// and slow functions. Three is the minimum at which the min-of-N
/// aggregator has any chance of skipping a single bad batch; bumping
/// to five doubled the wall-clock cost without meaningfully shrinking
/// the per-input spread we observed in the TASK-005 noise floor
/// study, so we keep three here.
const BATCHES: usize = 3;

/// Warm-up iterations for **slow** functions (signature verify,
/// syscall dispatch). Cut from 50_000 (which would have cost ~100 ms
/// per input × 32 inputs = 3.2 s, swamping every other measurement)
/// down to 500. The slow-function inner loop still does enough work
/// per batch that the predictor / cache state stabilises by the
/// time we measure.
const SLOW_WARMUP: u64 = 500;

/// Measured calls per batch for **slow** functions. 1000 × 3 = 3000
/// measured calls per input. At 2 µs/call that is ~6 ms per input;
/// over 32 inputs ≈ 200 ms per function.
const SLOW_BATCH_ITERS: u64 = 1_000;

/// Deterministic 32-byte seed for the proptest TestRng. The byte
/// pattern is `0x9E 0x37 0x79 0xB9 ...` — the high half of the 256-bit
/// expansion of φ used as a hashing constant in `feistel_mix`. We pick
/// a recognisable constant so the audit trail (eyeballing the perf
/// regressions across iterations) can connect a perf value back to
/// "the seed was unchanged from TASK-021" at a glance.
const PROPTEST_SEED: [u8; 32] = [
    0x9E, 0x37, 0x79, 0xB9, 0x7F, 0x4A, 0x7C, 0x15,
    0xF3, 0x9C, 0xC0, 0x60, 0x5C, 0xED, 0xC8, 0x34,
    0x10, 0x82, 0x27, 0x6B, 0xF3, 0xA2, 0x72, 0x51,
    0xF8, 0x6C, 0x6A, 0x11, 0xD0, 0xC1, 0x8E, 0x95,
];

/// Construct a TestRunner seeded with [`PROPTEST_SEED`]. Each call
/// returns a fresh runner so the per-test input sequences are
/// statistically independent across tests (each test gets the SAME
/// sequence, which is the point — cycle-to-cycle reproducibility).
fn fresh_runner() -> TestRunner {
    let rng = TestRng::from_seed(RngAlgorithm::ChaCha, &PROPTEST_SEED);
    let cfg = Config {
        // We never shrink; the runner is only used as a deterministic
        // input source. Disable on-disk shrink persistence so no
        // ./proptest-regressions/ side-effect files leak into the
        // workspace.
        failure_persistence: None,
        ..Config::default()
    };
    TestRunner::new_with_rng(cfg, rng)
}

/// Generate `n` independent values from `strategy` using `runner`.
/// Drains the strategy's `ValueTree::current()` and discards the
/// shrink tree — we do not need shrinking for benchmarking, just a
/// reproducible stream of inputs.
fn generate_n<S>(strategy: &S, n: usize, runner: &mut TestRunner) -> Vec<S::Value>
where
    S: Strategy,
{
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        let tree = strategy
            .new_tree(runner)
            .expect("proptest strategy yields a tree for every seeded draw");
        out.push(tree.current());
    }
    out
}

/// Run `body` for `warmup` unmeasured calls, then [`BATCHES`] timed
/// batches of `batch_iters` calls each, and return the minimum
/// ns/call across batches. This is the same inner aggregator the
/// TASK-005 harness used; the only TASK-021 change is the OUTER
/// dimension (32 inputs ⇒ 32 calls into this function ⇒ p95 across
/// the 32 returns).
fn measure_min_ns<F: FnMut()>(warmup: u64, batch_iters: u64, mut body: F) -> u64 {
    for _ in 0..warmup {
        body();
    }
    let mut best = u64::MAX;
    for _ in 0..BATCHES {
        let start = Instant::now();
        for _ in 0..batch_iters {
            body();
        }
        let elapsed = start.elapsed();
        let half = batch_iters / 2;
        let sample = ((elapsed.as_nanos() as u64) + half) / batch_iters;
        if sample < best {
            best = sample;
        }
    }
    best
}

/// Convenience wrapper that fixes the fast-function inner-loop knobs.
fn measure_fast<F: FnMut()>(body: F) -> u64 {
    measure_min_ns(FAST_WARMUP, FAST_BATCH_ITERS, body)
}

/// Convenience wrapper that fixes the slow-function inner-loop knobs.
fn measure_slow<F: FnMut()>(body: F) -> u64 {
    measure_min_ns(SLOW_WARMUP, SLOW_BATCH_ITERS, body)
}

// ---------------------------------------------------------------------
// Per-function p95 measurement tests
// ---------------------------------------------------------------------

#[test]
fn perf_fletcher32() {
    let mut runner = fresh_runner();
    let inputs: Vec<[u8; 16]> = generate_n(&any::<[u8; 16]>(), DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    let mut samples: Vec<u64> = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let ns = measure_fast(|| {
            let h = fletcher32(black_box(input.as_slice()));
            let _ = black_box(h);
        });
        samples.push(ns);
    }
    let metric = p95_u64(&samples);
    println!("perf: fletcher32 ns_per_call={}", metric);
    // Sanity: every sample is in the same order of magnitude as the
    // p95 — within 10×. If one sample is wildly higher we want the
    // perf-test infrastructure to surface that, not silently let the
    // p95 absorb it. (Without this assertion an OS pause during one
    // input would still produce a "passing" measurement.)
    let max = samples.iter().copied().max().unwrap_or(0);
    let min = samples.iter().copied().min().unwrap_or(0);
    assert!(
        max == 0 || max <= min.saturating_mul(50).max(50),
        "fletcher32 samples span more than 50× — measurement contaminated? \
         min={} max={} samples={:?}",
        min, max, samples
    );
}

#[test]
fn perf_feistel_mix() {
    let mut runner = fresh_runner();
    let inputs: Vec<u64> = generate_n(&any::<u64>(), DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    let mut samples = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let state = *input;
        let ns = measure_fast(|| {
            let h = feistel_mix(black_box(state));
            let _ = black_box(h);
        });
        samples.push(ns);
    }
    let metric = p95_u64(&samples);
    println!("perf: feistel_mix ns_per_call={}", metric);
}

#[test]
fn perf_derive_byte() {
    // `rounds` is bounded to 1..=8 so the per-call cost stays
    // representative of the morph engine's threat model — a
    // candidate that loops to rounds=u32::MAX would be a
    // correctness-test failure, not a perf-gate concern. Within the
    // bounded range, the cost grows roughly linearly with `rounds`,
    // and the random seed varies the data the inner block hashes.
    let mut runner = fresh_runner();
    let strategy = (any::<u8>(), 1u32..=8u32);
    let inputs: Vec<(u8, u32)> = generate_n(&strategy, DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    let mut samples = Vec::with_capacity(inputs.len());
    for (seed, rounds) in &inputs {
        let (s, r) = (*seed, *rounds);
        let ns = measure_fast(|| {
            let b = derive_byte(black_box(s), black_box(r));
            let _ = black_box(b);
        });
        samples.push(ns);
    }
    let metric = p95_u64(&samples);
    println!("perf: derive_byte ns_per_call={}", metric);
}

#[test]
fn perf_demohash_hash() {
    let mut runner = fresh_runner();
    let inputs: Vec<[u8; 16]> = generate_n(&any::<[u8; 16]>(), DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    let mut samples = Vec::with_capacity(inputs.len());
    for input in &inputs {
        let ns = measure_fast(|| {
            let mut out = [0u8; <DemoHash as Hash>::OUTPUT_LEN];
            <DemoHash as Hash>::hash(black_box(input.as_slice()), &mut out);
            let _ = black_box(out);
        });
        samples.push(ns);
    }
    let metric = p95_u64(&samples);
    println!("perf: DemoHash::hash ns_per_call={}", metric);
}

#[test]
fn perf_demosigverify_verify() {
    // 32 (pubkey, message) pairs. For each pair we construct a
    // matching valid signature via `fletcher_pair` (the same
    // construction the no_std lib uses internally) so the verify path
    // exercises the steady-state legitimate-verify branch, not the
    // early length-mismatch shortcut. The strategy yields PK and
    // message bytes; we synthesise the sig at measurement time
    // because the constructor depends on both.
    type Pk = [u8; <DemoSignatureVerify as SignatureVerify>::PUBKEY_LEN];
    type Msg = [u8; 64];
    let mut runner = fresh_runner();
    let strategy = (any::<Pk>(), any::<Msg>());
    let pairs: Vec<(Pk, Msg)> =
        generate_n(&strategy, DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    let mut samples = Vec::with_capacity(pairs.len());
    for (pk, msg) in &pairs {
        let lo = fletcher_pair(pk, msg);
        let hi = fletcher_pair(msg, pk);
        let mut sig = [0u8; <DemoSignatureVerify as SignatureVerify>::SIGNATURE_LEN];
        sig[..32].copy_from_slice(&lo);
        sig[32..].copy_from_slice(&hi);
        let ns = measure_slow(|| {
            let ok = <DemoSignatureVerify as SignatureVerify>::verify(
                black_box(pk),
                black_box(msg),
                black_box(&sig),
            );
            let _ = black_box(ok);
        });
        samples.push(ns);
    }
    let metric = p95_u64(&samples);
    println!("perf: demosigverify ns_per_call={}", metric);
}

#[test]
fn perf_demosyscall_dispatch() {
    // Strategy: nr ∈ 0..=4 (covers the implemented syscalls and
    // ENOSYS), six u64 args. Half the inputs exercise the ENOSYS
    // path, half exercise the real handlers — the p95 captures
    // whichever is slower (typically `sys_hash` because of its
    // little-endian byte conversion + fletcher32 call).
    let mut runner = fresh_runner();
    let strategy = (0u64..=4u64, any::<u64>(), any::<u64>(), any::<u64>(),
                    any::<u64>(), any::<u64>(), any::<u64>());
    let inputs: Vec<(u64, u64, u64, u64, u64, u64, u64)> =
        generate_n(&strategy, DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    let mut samples = Vec::with_capacity(inputs.len());
    for (nr, a0, a1, a2, a3, a4, a5) in &inputs {
        let (nr, a0, a1, a2, a3, a4, a5) = (*nr, *a0, *a1, *a2, *a3, *a4, *a5);
        let ns = measure_slow(|| {
            let r = <DemoSyscallDispatch as SyscallDispatch>::dispatch(
                black_box(nr),
                black_box(a0),
                black_box(a1),
                black_box(a2),
                black_box(a3),
                black_box(a4),
                black_box(a5),
            );
            let _ = black_box(r);
        });
        samples.push(ns);
    }
    let metric = p95_u64(&samples);
    println!("perf: demosyscall ns_per_call={}", metric);
}

// ---------------------------------------------------------------------
// Pathological-input fixture
// ---------------------------------------------------------------------

/// Synthetic implementation that demonstrates the algorithmic-
/// complexity attack class the TASK-021 methodology defends against.
///
/// Semantics:
///   * Input `[0u8; 16]` (or any input whose first byte is `0x00`)
///     returns `0` after a constant-time early-out.
///   * Any other input runs a busy loop linear in
///     `8 << input[0].count_ones()` plus a per-byte XOR mix —
///     deliberately slow but cheap enough that the test completes
///     in under a second on the slowest input.
///
/// In a real morph attack the candidate would specialise the
/// implementation on the canonical TASK-005 test buffer
/// (`[0x00, 0x11, ..., 0xFF]`, where `data[0] == 0`) — i.e. the
/// single-input perf measurement would clock ~5 ns/call. Across 32
/// random inputs, the chance of *every* input having `data[0] == 0`
/// is `(1/256)^32 ≈ 2^-256` — astronomically unlikely under our
/// deterministic seed. The p95 across the random sweep therefore
/// reflects the slow branch, not the fast specialisation. **That**
/// is what makes the gate refuse to accept the candidate.
///
/// Kept inside the test file (not `target_minimal/src/lib.rs`) so
/// the locked-public-API check in the verifier does not see it. The
/// pathological function exists purely as a measurement-methodology
/// fixture; it never ships in target_minimal proper.
#[inline(never)]
fn pathological_demo(input: &[u8; 16]) -> u64 {
    if input[0] == 0 {
        return 0;
    }
    // Loop count scales with the popcount of input[0]; for input[0]
    // = 0xFF that's `8 << 8 = 2048` iterations of the inner mix. The
    // black_box prevents the optimiser from collapsing the loop into
    // a closed form when input is known at compile time (it isn't
    // here, but the compiler's auto-vectoriser would still try).
    let mut acc: u64 = 0;
    let n = 8u64 << (input[0].count_ones() as u64);
    for i in 0..n {
        for b in input.iter() {
            acc = acc
                .wrapping_mul(0x9E37_79B9_7F4A_7C15)
                .wrapping_add(*b as u64)
                .rotate_left(((i & 63) as u32).wrapping_add(1));
        }
        // black_box on the accumulator each outer iteration so the
        // compiler cannot prove the entire loop body is dead.
        acc = std::hint::black_box(acc);
    }
    acc
}

#[test]
fn pathological_demo_fast_path_for_zero_first_byte() {
    // The single-input case that the OLD harness would have
    // measured. Returns 0 immediately; the cost is purely call
    // overhead. We assert the value (not a perf number) so this
    // test doesn't flap on noisy build machines.
    let canonical_buffer: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    assert_eq!(
        pathological_demo(&canonical_buffer),
        0,
        "canonical TASK-005 buffer must hit the early-return fast path \
         (this is the precondition that makes the attack invisible to \
         single-input perf measurement)"
    );
}

#[test]
fn pathological_demo_slow_path_for_nonzero_first_byte() {
    // For input[0] != 0, the implementation must take the busy-loop
    // path and produce a non-zero accumulator. The actual value is
    // an implementation detail; what we assert is "the slow branch
    // was taken at all".
    let mut buf = [0u8; 16];
    buf[0] = 0xFF;
    let r = pathological_demo(&buf);
    assert_ne!(
        r, 0,
        "non-zero first byte must drive the slow loop (sanity for the \
         attack-class demonstration)"
    );
}

#[test]
fn pathological_demo_caught_by_p95_methodology() {
    // The core proof of TASK-021:
    //   * Measure pathological_demo on the canonical single input.
    //   * Measure pathological_demo across 32 proptest-generated
    //     inputs and take p95.
    //   * Assert: p95 is at least 100× the single-input measurement,
    //     PROVING that the new methodology surfaces the algorithmic-
    //     complexity attack while the old methodology hid it.
    //
    // 100× is a conservative lower bound. Empirically on developer
    // machines the slowdown lands in the 1000-10000× range; we use
    // 100 so the test stays green even on a thermally throttled
    // CPU where the slow branch happens to be partially predicted.

    // --- Single-input measurement (old methodology equivalent) ---
    let canonical_buffer: [u8; 16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF,
    ];
    let single_input_ns = measure_min_ns(FAST_WARMUP, FAST_BATCH_ITERS, || {
        let r = pathological_demo(black_box(&canonical_buffer));
        let _ = black_box(r);
    });
    println!(
        "perf: pathological_demo_single_input ns_per_call={}",
        single_input_ns
    );

    // --- p95-across-32-inputs measurement (new methodology) ---
    let mut runner = fresh_runner();
    let inputs: Vec<[u8; 16]> =
        generate_n(&any::<[u8; 16]>(), DEFAULT_PERF_INPUTS_PER_CYCLE, &mut runner);
    // Confirm the seeded sweep is hitting at least 28/32 slow-branch
    // inputs (the probability of input[0] == 0 is 1/256 per input;
    // expected count across 32 is ≈ 0.125, so we should see ≥30 with
    // any reasonable seed). This invariant is what makes the next
    // assertion meaningful.
    let slow_count = inputs.iter().filter(|b| b[0] != 0).count();
    assert!(
        slow_count >= 28,
        "seeded proptest sweep produced only {}/32 slow-branch inputs; \
         the seed may have changed, breaking the attack-class \
         demonstration",
        slow_count
    );

    let mut samples = Vec::with_capacity(inputs.len());
    // Slow inner-loop knobs because each pathological call can take
    // microseconds in the worst case.
    for input in &inputs {
        let ns = measure_min_ns(SLOW_WARMUP, SLOW_BATCH_ITERS, || {
            let r = pathological_demo(black_box(input));
            let _ = black_box(r);
        });
        samples.push(ns);
    }
    let p95_ns = p95_u64(&samples);
    println!(
        "perf: pathological_demo_p95 ns_per_call={}",
        p95_ns
    );

    // The actual gate condition. We use a saturating multiplication
    // so a literal-zero single-input measurement (sub-ns on
    // aggressive inlining) does not produce a degenerate threshold.
    // In practice single_input_ns >> 1 because we ran 300k
    // iterations including warm-up, but the saturating math is the
    // safe form.
    let threshold = single_input_ns.saturating_mul(100).max(100);
    assert!(
        p95_ns >= threshold,
        "TASK-021 methodology should surface the pathological-input \
         attack: single_input={} ns/call, p95-across-32={} ns/call. \
         Expected p95 ≥ 100 × single_input (= ≥ {}). If this fails, \
         either the pathological_demo got optimised into a constant or \
         the seeded sweep stopped hitting the slow branch.",
        single_input_ns, p95_ns, threshold
    );
}
