//! `verify` CLI — runs the contract invariant battery against a candidate
//! source file. The morph engine invokes this binary during Stage 3 of the
//! factory pipeline.
//!
//! Today's skeleton runs **static** checks (parse, public-symbol
//! preservation, canonical-hash dedup, locked-surface scan). The full
//! property-test harness for trait implementations is gated behind a
//! `compile-and-link` step that requires a `cargo` toolchain on the host;
//! that step is stubbed here and noted as Phase-1 work.
//!
//! Exit code 0 = accept candidate. Exit code 1 = reject. The morph engine
//! depends on this exit-code contract.
//!
//! # Performance-envelope gating (TASK-005)
//!
//! After the golden test passes, the verifier measures per-function cost
//! and compares it against the **per-field median of the last N accepted
//! cycles** of `perf.jsonl` (N defaults to 10, configurable via
//! `--perf-window`). If any `*_ns` field in the candidate measurement
//! exceeds the median baseline by more than `--perf-threshold` percent
//! (default: 20% / ratio 1.2), the candidate is **REJECTED** and no
//! line is appended to `perf.jsonl`. Only accepted candidates produce a
//! perf log entry.
//!
//! `--perf-threshold` accepts two forms:
//!   * **Ratio form** (TASK-005 spec): a decimal `> 1.0`. `1.2` =
//!     "+20%". Detected when the value contains `.` or its magnitude
//!     is `< 10`.
//!   * **Legacy percent form**: an integer `>= 10`. `50` = "+50%".
//!
//! The threshold check now hard-rejects on regression. Infrastructure
//! errors during the check (file unreadable, etc.) still downgrade to
//! a warning + accept, since perf measurement infra failure is not
//! evidence of a candidate regression.
//!
//! # Bootstrap convention (important for the morph engine)
//!
//! On the very first cycle there is no `perf.jsonl`. The verifier handles
//! this by emitting a warning to stderr (`verify: no perf baseline
//! available; skipping perf gating`) and accepting on the perf axis. The
//! morph engine therefore does NOT need to know about the bootstrap edge
//! case — it always invokes `verify` the same way. An empty or missing
//! `perf.jsonl` means "no baseline yet"; the first successful accept
//! writes the seed line, and subsequent cycles enforce regression against
//! it.
//!
//! The threshold check also gracefully skips functions that exist in the
//! candidate measurement but not the baseline (e.g., a future Track 2
//! `demosignatureverify_ns` field added before its first baseline line is
//! written). This makes schema growth safe for downstream consumers.

use anyhow::{bail, Context, Result};
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};
use syn::File;

use proteus_verifier::cli::parse_args;
use proteus_verifier::perf::{
    evaluate_perf_gate, read_baseline_window, unmatched_fields, PerfGateOutcome, PerfMetrics,
};
use proteus_verifier::static_checks::{
    evaluate_static, parse_manifest_str, StaticCheckInput, StaticCheckOutcome,
};

/// Per-cycle performance log written alongside the attestation log.
/// One JSON object per accepted candidate. Append-only; never rewritten.
/// On reject, no line is written — perf is observation-only.
const PERF_LOG: &str = "perf.jsonl";

const LOCKED_PUBLIC_SYMBOLS_HINT: &[&str] = &[
    // Symbols the verifier expects to find in *some* candidate. The list
    // is intentionally permissive in the skeleton; production tightens it
    // to a per-module manifest pulled from the contracts crate.
];

fn main() -> ExitCode {
    match run() {
        Ok(true) => {
            eprintln!("verify: ACCEPT");
            ExitCode::SUCCESS
        }
        Ok(false) => {
            eprintln!("verify: REJECT");
            ExitCode::from(1)
        }
        Err(e) => {
            eprintln!("verify: ERROR {:#}", e);
            ExitCode::from(2)
        }
    }
}

fn run() -> Result<bool> {
    let args: Vec<String> = env::args().collect();
    let parsed = parse_args(&args)?;
    let previous = &parsed.previous;
    let manifest = &parsed.manifest;
    let perf_opts = PerfOptions {
        threshold_pct: parsed.perf_threshold,
        window: parsed.perf_window,
        baseline_override: parsed.perf_baseline.clone(),
        skip_check: parsed.no_perf_check,
    };

    // Resolve the substitution set: a Vec<(module_name, source_text)>.
    // Single-module mode → one entry; bundle mode → one per
    // --bundle-module pair, in command-line order.
    let subs: Vec<(String, String)> = if let Some(cand_path) = &parsed.candidate {
        let src = fs::read_to_string(cand_path)
            .with_context(|| format!("read candidate: {}", cand_path.display()))?;
        vec![(parsed.module.clone(), src)]
    } else {
        let mut out = Vec::with_capacity(parsed.bundle.len());
        for (name, path) in &parsed.bundle {
            let src = fs::read_to_string(path).with_context(|| {
                format!("read bundle candidate for module {}: {}", name, path.display())
            })?;
            out.push((name.clone(), src));
        }
        out
    };

    let prev_src = previous
        .as_ref()
        .map(|p| fs::read_to_string(p))
        .transpose()
        .context("read previous-cycle source")?;
    let required_pub: BTreeSet<String> = match manifest.as_ref() {
        Some(p) => {
            let body = fs::read_to_string(p).context("read manifest")?;
            parse_manifest_str(&body)
        }
        None => BTreeSet::new(),
    };

    // 1. Parse check — applies to every candidate in the substitution
    //    set. Failure on any one rejects the whole verify call.
    //    (Bundle members are parse-checked here; full static surface
    //    for single-module is evaluate_static below.)
    for (name, src) in &subs {
        if let Err(e) = syn::parse_str::<File>(src) {
            eprintln!("verify: parse failed for module {}: {}", name, e);
            return Ok(false);
        }
    }

    // 2..5: public-symbol / previous-surface / dedup checks. In Phase A
    //       these run only in single-module mode. Bundle mode's
    //       load-bearing check is the atomic compile-and-test of the
    //       substituted workspace below — manifest enforcement is a
    //       pre-compile shortcut, not a separate safety property. A
    //       follow-up task can extend these to per-module manifests
    //       within a bundle.
    //
    //       Logic lives in `proteus_verifier::static_checks` so the
    //       poison corpus can unit-test every reject class without
    //       spawning cargo.
    if parsed.bundle.is_empty() {
        let cand_src = &subs[0].1;
        match evaluate_static(&StaticCheckInput {
            candidate: cand_src,
            previous: prev_src.as_deref(),
            required_pub: &required_pub,
        }) {
            StaticCheckOutcome::Accept => {}
            StaticCheckOutcome::Reject { reason } => {
                eprintln!("{}", reason.stderr_line());
                return Ok(false);
            }
        }

        // Locked-surface stub (unchanged) — reserved for future per-
        // module locked-name enforcement.
        let _ = LOCKED_PUBLIC_SYMBOLS_HINT;
    }

    // 5b. (Removed in TASK-020.) The cap-check AST property is
    //     replaced by a compile-time type-state proof carried in
    //     `proteus_contracts::CapProof`. A morph candidate that
    //     attempts to bypass the cap gate fails to *compile* in the
    //     scratch workspace below, which the existing compile-and-
    //     test stage already catches. The dedicated trybuild suite
    //     `verifier/tests/cap_typestate.rs` exercises the negative
    //     cases (let-_-discard, if-false dead code, fake CapProof,
    //     etc.) end-to-end against the contracts crate.

    // 6. Compile-and-test stage. The candidate is dropped into a scratch
    //    workspace alongside copies of `contracts/` and `target_minimal/`,
    //    its `src/lib.rs` is overwritten with the candidate source, and
    //    cargo is invoked to (a) build the test target, then (b) run the
    //    `golden` integration test. Either step's non-zero exit rejects
    //    the candidate. This is the real semantic-preservation check —
    //    the trait-level harness from `proteus_contracts::harness` runs
    //    inside that test binary, against the candidate, in a real Rust
    //    runtime.
    //
    //    The perf measurement runs after golden, BEFORE writing anything
    //    to perf.jsonl. The threshold check happens here in `run()` so
    //    that a perf-regression reject leaves the log untouched.
    //
    //    Scratch dir cleanup is best-effort and runs on both paths.
    // Path used only to anchor the workspace-root walk. Single-module:
    // the positional candidate; bundle: the first --bundle-module's
    // candidate path. Both point inside the same workspace so either
    // resolves the same root.
    let anchor_path: PathBuf = parsed
        .candidate
        .clone()
        .or_else(|| parsed.bundle.first().map(|(_, p)| p.clone()))
        .expect("parse_args validated at least one candidate path is present");
    match compile_and_test(&anchor_path, &parsed.target_crate, &subs, &perf_opts) {
        Ok(true) => Ok(true),
        Ok(false) => Ok(false),
        Err(e) => Err(e),
    }
}

/// Options that govern the performance-envelope gating step. Threaded
/// from `parse_args` down through `compile_and_test`.
#[derive(Debug, Clone)]
struct PerfOptions {
    /// Percent regression that triggers reject. `20` means "reject if
    /// any function is more than 20% slower than the rolling-window
    /// baseline median". See `verifier::perf::parse_threshold_arg` for
    /// the dual ratio / legacy-percent CLI mapping.
    threshold_pct: u32,
    /// Rolling-window size. The gate compares the candidate against
    /// the per-field median of the last `window` accepted entries.
    window: usize,
    /// Optional override for the baseline JSONL file. `None` resolves to
    /// `<workspace_root>/perf.jsonl`.
    baseline_override: Option<PathBuf>,
    /// If true, skip the threshold check entirely. Used by the morph
    /// engine's first cycle (no baseline exists yet) and by tests that
    /// want to bypass perf gating.
    skip_check: bool,
}

/// Build the candidate(s) in an isolated scratch workspace.
///
/// - Single-module mode (`subs.len() == 1`, target_crate often
///   `target_minimal`): preserves the historical behaviour — substitute,
///   build, run the `golden` integration test, run perf gating against
///   `perf.jsonl`.
/// - Bundle mode (`subs.len() >= 1`, target_crate typically
///   `target_enterprise`): substitute every (module, source) pair into
///   the scratch crate's `src/<module>.rs`, build the workspace. No
///   golden test, no perf gating — those are target_minimal-specific
///   facilities. The atomic compile IS the verification: every member's
///   semantic preservation is exercised by the full workspace's type
///   system and existing test surfaces that depend on the morphed
///   modules. A future task can extend this to a per-crate test policy.
///
/// Returns `Ok(true)` on accept, `Ok(false)` on reject (compile or test
/// failure), `Err` only on infrastructure failure (cannot locate workspace
/// roots, cannot write scratch dir, etc).
fn compile_and_test(
    candidate_path: &Path,
    target_crate: &str,
    subs: &[(String, String)],
    perf_opts: &PerfOptions,
) -> Result<bool> {
    let workspace_root = locate_workspace_root(candidate_path)?;
    let contracts_src = workspace_root.join("contracts");
    let target_src = workspace_root.join(target_crate);
    // The perf log lives at the real workspace root, next to the
    // attestation log written by morph_engine. Stash the path now so
    // we can append after the scratch dir is cleaned up.
    let perf_log_path = workspace_root.join(PERF_LOG);
    // Baseline path: explicit override (tests) or the live perf.jsonl
    // (the morph engine's normal path).
    let baseline_path = perf_opts
        .baseline_override
        .clone()
        .unwrap_or_else(|| perf_log_path.clone());
    if !contracts_src.join("Cargo.toml").exists() {
        bail!(
            "could not find contracts crate at {}",
            contracts_src.display()
        );
    }
    if !target_src.join("Cargo.toml").exists() {
        bail!(
            "could not find {} crate at {}",
            target_crate,
            target_src.display()
        );
    }

    // target_minimal has a `golden` integration test and a `perf.rs`
    // benchmark; other crates don't yet. Restrict those steps to the
    // crate they were designed for. A future task can declare per-crate
    // verifier policies (which tests to run, which perf bench to use).
    let is_target_minimal = target_crate == "target_minimal";

    let scratch = make_scratch_dir()?;
    let result = (|| -> Result<bool> {
        // Copy contracts/ and the target crate into the scratch root.
        let scratch_contracts = scratch.join("contracts");
        let scratch_target = scratch.join(target_crate);
        copy_crate_tree(&contracts_src, &scratch_contracts)?;
        copy_crate_tree(&target_src, &scratch_target)?;

        // For non-target_minimal crates, strip `[dev-dependencies]`
        // from the scratch Cargo.toml. target_enterprise's dev-deps
        // reference `proteus-verifier = { path = "../verifier" }` and
        // similar workspace siblings we don't copy into the scratch
        // dir. We're not running tests in bundle mode (the compile
        // IS the verification), so dev-deps are dead weight that just
        // make cargo's manifest loader fail to resolve a path.
        //
        // target_minimal keeps its dev-deps (golden + perf). After
        // TASK-021 those include `proteus-verifier` (for `p95_u64`).
        // Copy diversifier + verifier into the scratch as workspace
        // members so `path = "../verifier"` resolves without the
        // package-collision that an absolute path into the live
        // workspace would create (two copies of proteus-contracts).
        if !is_target_minimal {
            strip_dev_dependencies(&scratch_target.join("Cargo.toml"))?;
        } else {
            let scratch_div = scratch.join("diversifier");
            let scratch_ver = scratch.join("verifier");
            copy_crate_tree(&workspace_root.join("diversifier"), &scratch_div)?;
            copy_crate_tree(&workspace_root.join("verifier"), &scratch_ver)?;
            // Verifier's own trybuild/proptest dev-deps are not needed
            // to *link* target_minimal's perf test against the lib.
            strip_dev_dependencies(&scratch_ver.join("Cargo.toml"))?;
        }

        // Substitute every (module, source) pair into the scratch crate.
        // For single-module mode this is one write; for bundle mode this
        // is N writes, atomic from the scratch dir's perspective — the
        // build that follows sees the full set or none (cleanup runs on
        // any failure).
        for (module_name, src) in subs {
            let cand_dest = scratch_target
                .join("src")
                .join(format!("{}.rs", module_name));
            fs::write(&cand_dest, src).with_context(|| {
                format!(
                    "write candidate for module {} to {}",
                    module_name,
                    cand_dest.display()
                )
            })?;
        }

        // Stage a minimal workspace Cargo.toml so cargo treats this as a
        // self-contained build. We do not include any other workspace
        // members — diversifier/verifier/morph_engine are not needed to
        // build the target's tests, and excluding them keeps the scratch
        // build cheap.
        write_scratch_workspace(&scratch, target_crate, &workspace_root)?;

        // The dev-dep on `proteus-contracts` in target_minimal already
        // points at `../contracts` — that resolves correctly inside the
        // scratch root because we copied both crates side-by-side.

        // Build the test target. Use a per-scratch target dir to avoid
        // racing concurrent verifier invocations and to keep cleanup
        // self-contained.
        //
        // `--release` is REQUIRED here for perf-envelope stability.
        // Debug builds add un-inlined wrappers and unconditional bounds
        // checks that dominate the per-call cost of cheap functions
        // (fletcher32, feistel_mix) and inflate measurement noise to
        // ~100% cycle-to-cycle, which flap-rejects morph candidates on
        // pure noise. Release brings that down below 20% on a quiet
        // host. Trade-off: scratch-build wall-clock grows from ~2s to
        // ~5-10s per verify cycle. At hourly cadence this is
        // negligible; at per-minute cadence we will need to reuse the
        // scratch target dir across cycles (the per-scratch isolation
        // exists today to avoid concurrent-cycle races, not for
        // correctness of a single cycle).
        //
        // The golden test below also runs --release for consistency:
        // mixing debug + release within one scratch dir would force
        // rustc to rebuild every dep tree twice, doubling the cost.
        let target_dir = scratch.join("build-target");
        let cargo = cargo_binary();
        // DEBUG instrumentation (temporary): list scratch contents.
        if std::env::var("PROTEUS_VERIFY_DEBUG_SCRATCH").is_ok() {
            for entry in fs::read_dir(&scratch)? {
                let e = entry?;
                eprintln!("scratch entry: {:?}", e.file_name());
            }
            eprintln!(
                "scratch verifier/Cargo.toml exists: {}",
                scratch.join("verifier").join("Cargo.toml").exists()
            );
        }
        // The `-p` value is the *package name* declared in the target
        // crate's Cargo.toml, which is conventionally
        // `proteus-target-<crate>` for target_minimal but plain
        // `target_enterprise` (no prefix) for target_enterprise. We
        // resolve the actual package name from the scratch crate's
        // Cargo.toml so the build command always names the right
        // package regardless of naming conventions.
        let package_name = read_package_name(&scratch_target.join("Cargo.toml"))?;
        let mut build = Command::new(&cargo);
        build
            .arg("build")
            .arg("-p")
            .arg(&package_name);
        // `--tests` pulls in dev-deps. For target_minimal we need the
        // `golden` integration test, so we keep it. For other crates
        // (target_enterprise et al) the dev-deps include things like
        // `proteus-verifier` that aren't copied into the scratch dir
        // (we only copy `contracts/` + the target crate); pulling
        // those would fail to resolve. Bundle-mode verification is the
        // library build itself — no test step needed.
        if is_target_minimal {
            build.arg("--tests");
        }
        build
            .arg("--release")
            .arg("--target-dir")
            .arg(&target_dir)
            .current_dir(&scratch);
        let build_status = build.status().with_context(|| {
            format!("invoke cargo build in {}", scratch.display())
        })?;
        if !build_status.success() {
            eprintln!(
                "verify: candidate failed to compile in scratch dir {}",
                scratch.display()
            );
            return Ok(false);
        }

        // Run the golden integration test — only for target_minimal,
        // which is where the golden suite lives. Other target crates
        // have their own test surfaces; for bundle mode against
        // target_enterprise the build step itself is the verification.
        if is_target_minimal {
            let mut test = Command::new(&cargo);
            test.arg("test")
                .arg("--release")
                .arg("--test")
                .arg("golden")
                .arg("-p")
                .arg(&package_name)
                .arg("--target-dir")
                .arg(&target_dir)
                .current_dir(&scratch);
            let test_status = test.status().with_context(|| {
                format!("invoke cargo test in {}", scratch.display())
            })?;
            if !test_status.success() {
                eprintln!(
                    "verify: candidate failed the golden test in scratch dir {}",
                    scratch.display()
                );
                return Ok(false);
            }
        }

        // Perf gating runs only for target_minimal — that's where the
        // `tests/perf.rs` benchmark exists and where `perf.jsonl` is
        // anchored. For bundle / non-target_minimal crates we skip
        // perf and accept on a clean compile (golden test was also
        // skipped above for the same reason). A future task can
        // declare a per-crate perf-bench policy and extend perf.jsonl
        // with per-crate fields.
        if !is_target_minimal {
            return Ok(true);
        }
        // Golden passed → run the perf test, capture stdout, parse
        // `perf:` lines, run the regression-threshold check against the
        // last baseline, and (only if accept) append a JSONL record to
        // the workspace-root perf log. Measurement failure is surfaced
        // as a warning and does NOT flip accept→reject; threshold
        // failure DOES flip accept→reject.
        match run_perf(&scratch, &target_dir, &cargo) {
            Ok(metrics) => {
                if !perf_opts.skip_check {
                    // Schema-growth diagnostic: warn about candidate
                    // fields that the baseline never recorded. Done
                    // before the gate call so the operator sees the
                    // notice even on reject. Infrastructure errors here
                    // are non-fatal — the gate call below will surface
                    // them.
                    if let Ok(Some(b)) =
                        read_baseline_window(&baseline_path, perf_opts.window)
                    {
                        for k in unmatched_fields(&metrics, &b) {
                            eprintln!(
                                "verify: perf field {:?} present in candidate but absent from baseline; skipping",
                                k
                            );
                        }
                    }
                    // Threshold check. Infrastructure errors (Err)
                    // degrade to warn+accept — a perf-infra failure
                    // is not evidence the candidate regressed. A
                    // Reject outcome, however, **hard-rejects**: the
                    // gate is the entire point of TASK-005.
                    match evaluate_perf_gate(
                        &metrics,
                        &baseline_path,
                        perf_opts.window,
                        perf_opts.threshold_pct,
                    ) {
                        Ok(PerfGateOutcome::Accept) => {}
                        Ok(PerfGateOutcome::NoBaseline) => {
                            eprintln!(
                                "verify: no perf baseline available; skipping perf gating"
                            );
                        }
                        Ok(PerfGateOutcome::Reject {
                            reasons,
                            threshold_pct,
                        }) => {
                            for (name, base_ns, cand_ns, delta_pct) in &reasons {
                                eprintln!(
                                    "verify: perf regression in {}: baseline {} ns, candidate {} ns (+{}%) exceeds threshold +{}%",
                                    name, base_ns, cand_ns, delta_pct, threshold_pct
                                );
                            }
                            // Regression detected; do not pollute perf.jsonl.
                            return Ok(false);
                        }
                        Err(e) => {
                            // Infrastructure failure (e.g. unreadable
                            // perf.jsonl other than NotFound). Warn but
                            // accept — perf measurement is observation
                            // infrastructure, not evidence of regression.
                            eprintln!(
                                "verify: perf threshold check failed: {:#}; accepting",
                                e
                            );
                        }
                    }
                } else {
                    eprintln!("verify: perf gating disabled by --no-perf-check");
                }
                // Accept path: append one line to the workspace perf log.
                if let Err(e) = append_perf_record(&perf_log_path, &metrics) {
                    eprintln!("verify: perf log append failed: {:#}", e);
                }
            }
            Err(e) => {
                // Warn but accept. Perf measurement is observation
                // infrastructure; if cargo cannot even run the perf
                // test (compile error, etc.) the morph engine still
                // gets a valid accept signal from the golden test.
                eprintln!("verify: perf measurement skipped: {:#}", e);
            }
        }
        Ok(true)
    })();

    // Best-effort cleanup on both success and failure. On Windows, AV or
    // the OS loader can briefly hold a handle on test `.exe`/`.pdb` files
    // right after process exit; retry a few times with a short backoff.
    remove_scratch_dir_with_retry(&scratch);
    result
}

/// Locate the workspace root containing the candidate. The candidate
/// path may be inside any workspace member crate; we walk upward
/// looking for a directory whose `contracts/Cargo.toml` exists — that
/// is the unambiguous Proteus root marker. We do NOT require
/// `target_minimal` to be present, because bundle-mode invocations
/// target other crates (e.g. `target_enterprise`) and the search must
/// succeed without assuming the legacy target is the live one.
fn locate_workspace_root(candidate: &Path) -> Result<PathBuf> {
    let abs = fs::canonicalize(candidate)
        .with_context(|| format!("canonicalize {}", candidate.display()))?;
    let mut cursor: Option<&Path> = abs.parent();
    while let Some(dir) = cursor {
        if dir.join("contracts").join("Cargo.toml").exists() {
            return Ok(dir.to_path_buf());
        }
        cursor = dir.parent();
    }
    // Fall back to the verifier binary's location.
    if let Ok(self_exe) = env::current_exe() {
        let mut p: Option<&Path> = self_exe.parent();
        while let Some(dir) = p {
            if dir.join("contracts").join("Cargo.toml").exists() {
                return Ok(dir.to_path_buf());
            }
            p = dir.parent();
        }
    }
    bail!(
        "could not locate Proteus workspace root from candidate path {} or verifier binary",
        candidate.display()
    );
}

/// Read the `name = "..."` field out of a `Cargo.toml`. Used to resolve
/// the cargo package name for a target crate independently of how the
/// directory is named — `target_minimal/`'s Cargo.toml declares
/// `name = "proteus-target-minimal"` (with prefix), `target_enterprise/`'s
/// declares `name = "target_enterprise"` (no prefix).
fn read_package_name(cargo_toml: &Path) -> Result<String> {
    let text = fs::read_to_string(cargo_toml)
        .with_context(|| format!("read {}", cargo_toml.display()))?;
    // Tiny ad-hoc scan: find the `[package]` table and the first
    // `name = "..."` line under it. Sufficient for the workspace's
    // hand-written Cargo.tomls; no need to pull in a TOML parser
    // (the morph_engine already has one but this is the verifier).
    let mut in_pkg = false;
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with('[') {
            in_pkg = trimmed == "[package]";
            continue;
        }
        if !in_pkg {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("name") {
            let rest = rest.trim_start();
            if let Some(after_eq) = rest.strip_prefix('=') {
                let v = after_eq.trim();
                if let Some(stripped) = v.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
                    return Ok(stripped.to_string());
                }
            }
        }
    }
    bail!(
        "could not parse name = \"...\" out of [package] in {}",
        cargo_toml.display()
    );
}

/// Allocate a randomly-suffixed scratch directory.
///
/// Default location is `std::env::temp_dir()`. On hosts where an
/// Application Control policy or similar EDR layer blocks execution of
/// freshly-built binaries out of the user's `%TEMP%` (Windows
/// AppLocker / Smart App Control / corporate WDAC profiles all do this
/// for unsigned exes under `C:\Users\*\AppData\Local\Temp\`), the
/// caller can override via the `PROTEUS_VERIFY_SCRATCH_ROOT` env var.
/// Pointing it at a directory under the project workspace (which the
/// policy already allows because that is where rustc itself runs)
/// sidesteps the issue without weakening the policy.
fn make_scratch_dir() -> Result<PathBuf> {
    let mut nonce_bytes = [0u8; 8];
    // Mix two clock sources into the suffix so concurrent invocations
    // do not collide. We deliberately avoid pulling in `rand` here —
    // this is an isolation aid, not a security guarantee.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let pid = std::process::id() as u128;
    let mix = now.wrapping_mul(0x9E37_79B9_7F4A_7C15).wrapping_add(pid);
    for (i, b) in nonce_bytes.iter_mut().enumerate() {
        *b = ((mix >> (i * 8)) & 0xFF) as u8;
    }
    let suffix: String = nonce_bytes.iter().map(|b| format!("{:02x}", b)).collect();
    let root: PathBuf = match env::var_os("PROTEUS_VERIFY_SCRATCH_ROOT") {
        Some(s) => {
            let p = PathBuf::from(s);
            // Ensure the override directory exists so the caller does
            // not have to.
            let _ = fs::create_dir_all(&p);
            p
        }
        None => env::temp_dir(),
    };
    sweep_stale_scratch_dirs(&root);
    let dir = root.join(format!("proteus-verify-{}", suffix));
    fs::create_dir_all(&dir).with_context(|| format!("create scratch dir {}", dir.display()))?;
    Ok(dir)
}

/// Remove a scratch directory, retrying briefly if Windows Defender /
/// handle teardown transiently blocks deletion of freshly-exited binaries.
fn remove_scratch_dir_with_retry(scratch: &Path) {
    for attempt in 0..5 {
        if !scratch.exists() || fs::remove_dir_all(scratch).is_ok() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(100 * (attempt + 1)));
    }
}

/// Sweep any orphaned `proteus-verify-*` directories in `root` older than
/// 15 minutes (e.g. left behind by a killed cycle or transient file lock).
fn sweep_stale_scratch_dirs(root: &Path) {
    let Ok(entries) = fs::read_dir(root) else {
        return;
    };
    let cutoff = std::time::Duration::from_secs(15 * 60);
    let now = SystemTime::now();
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        if !s.starts_with("proteus-verify-") {
            continue;
        }
        let stale = entry
            .metadata()
            .ok()
            .and_then(|m| m.modified().ok())
            .and_then(|t| now.duration_since(t).ok())
            .map(|age| age > cutoff)
            .unwrap_or(false);
        if stale {
            let _ = fs::remove_dir_all(entry.path());
        }
    }
}

fn cargo_binary() -> PathBuf {
    // Cargo sets $CARGO when invoking its own binaries (build scripts,
    // `cargo run` of our verifier), so we prefer that. The morph engine
    // does not invoke us under cargo, so fall back to "cargo" on PATH.
    if let Ok(c) = env::var("CARGO") {
        if !c.is_empty() {
            return PathBuf::from(c);
        }
    }
    PathBuf::from("cargo")
}

/// Recursive copy of a crate tree. Skips `target/`, `.git/`, and the
/// canonical IDE clutter that adds wall-clock cost without affecting
/// the build.
fn copy_crate_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst)
        .with_context(|| format!("create {}", dst.display()))?;
    for entry in fs::read_dir(src)
        .with_context(|| format!("read_dir {}", src.display()))?
    {
        let entry = entry?;
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        // Skip build artifacts and version-control noise.
        if matches!(name_s.as_ref(), "target" | ".git" | ".vscode" | ".idea") {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let ty = entry.file_type()?;
        if ty.is_dir() {
            copy_crate_tree(&from, &to)?;
        } else if ty.is_file() {
            fs::copy(&from, &to)
                .with_context(|| format!("copy {} -> {}", from.display(), to.display()))?;
        }
    }
    Ok(())
}

/// Write a minimal workspace Cargo.toml at the scratch root, listing
/// `contracts` + the target crate as the only members. Avoids dragging
/// in the verifier/morph_engine dep tree, which the candidate test
/// doesn't need.
///
/// **Inherits `[workspace.dependencies]` from the real workspace root.**
/// `target_enterprise` (and any future crate) declares dev-deps via
/// `proptest = { workspace = true }` etc.; without the inherited block
/// the scratch build fails with `workspace.dependencies was not defined`.
/// We copy the section verbatim — its content is whatever the real
/// workspace declared, which is what the morphed candidate was compiled
/// against in the real workspace.
fn write_scratch_workspace(scratch: &Path, target_crate: &str, workspace_root: &Path) -> Result<()> {
    let workspace_deps_block = extract_workspace_dependencies_block(workspace_root)?;
    // target_minimal's golden/perf tests need diversifier + verifier
    // as workspace members (see compile_and_test). Other targets do
    // not — keep the scratch minimal.
    let members = if target_crate == "target_minimal" {
        format!(
            "\"contracts\", \"{target}\", \"diversifier\", \"verifier\"",
            target = target_crate
        )
    } else {
        format!("\"contracts\", \"{target}\"", target = target_crate)
    };
    let toml = format!(
        "[workspace]\nresolver = \"2\"\nmembers = [{members}]\n\n\
[workspace.package]\nedition = \"2024\"\nversion = \"0.0.1\"\nauthors = [\"Proteus Verifier Scratch\"]\nlicense = \"Apache-2.0\"\n\n\
{deps}",
        members = members,
        deps = workspace_deps_block,
    );
    let path = scratch.join("Cargo.toml");
    fs::write(&path, &toml).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Rewrite a scratch crate's `Cargo.toml` in place with the
/// `[dev-dependencies]` section removed. The section ends at the next
/// `[`-prefixed header (or EOF). Preserves every other section
/// byte-for-byte — comments, ordering, the lot.
///
/// Cargo's manifest loader validates dev-deps' paths even when no
/// test target is being built, so a dev-dep on a sibling crate we
/// haven't copied to the scratch will fail the workspace's manifest
/// resolution. Bundle mode doesn't run dev-dep-pulling tests; this
/// strip is the cleanest way to keep cargo happy.
fn strip_dev_dependencies(cargo_toml: &Path) -> Result<()> {
    let raw = fs::read_to_string(cargo_toml)
        .with_context(|| format!("read {}", cargo_toml.display()))?;
    let mut out = String::with_capacity(raw.len());
    let mut in_dev = false;
    for line in raw.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[dev-dependencies]")
            || trimmed.starts_with("[dev-dependencies.")
            || trimmed.starts_with("[target.")
                && trimmed.contains("dev-dependencies")
        {
            in_dev = true;
            continue;
        }
        if in_dev {
            if trimmed.starts_with('[') {
                in_dev = false;
                // Fall through to emit this new section header.
            } else {
                continue;
            }
        }
        out.push_str(line);
        out.push('\n');
    }
    fs::write(cargo_toml, &out)
        .with_context(|| format!("write stripped {}", cargo_toml.display()))?;
    Ok(())
}

/// Read the real workspace's `Cargo.toml` and extract the
/// `[workspace.dependencies]` block (the header line plus every
/// following non-blank, non-`[`-prefixed line). Returns an empty
/// string if the section is missing (legacy workspaces without
/// shared dev-deps still work).
///
/// This is a stringly-typed extraction — we do not parse the TOML,
/// because we want to preserve comments and ordering byte-for-byte.
/// The downstream scratch build either compiles with the inherited
/// block or fails the same way it would in the real workspace.
fn extract_workspace_dependencies_block(workspace_root: &Path) -> Result<String> {
    let path = workspace_root.join("Cargo.toml");
    let raw = fs::read_to_string(&path)
        .with_context(|| format!("read workspace Cargo.toml at {}", path.display()))?;
    let mut out = String::new();
    let mut in_block = false;
    for line in raw.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("[workspace.dependencies]") {
            in_block = true;
            out.push_str(line);
            out.push('\n');
            continue;
        }
        if !in_block {
            continue;
        }
        // The block ends at the next `[`-prefixed section header. Any
        // blank lines + comment lines + `key = value` lines in between
        // are part of the block and get copied through.
        if trimmed.starts_with('[') {
            break;
        }
        out.push_str(line);
        out.push('\n');
    }
    Ok(out)
}

/// Run the `perf` integration test inside the scratch workspace and
/// return the parsed measurements. Does NOT append to any log; the
/// caller decides whether the candidate is accepted and only writes a
/// log line on accept.
///
/// Errors only on infrastructure failure (cargo cannot be invoked, the
/// perf test does not compile). The caller treats those as warnings —
/// perf measurement is observation infrastructure, not a hard gate.
///
/// Expected stdout format from `target_minimal/tests/perf.rs`:
///
/// ```text
/// perf: <fn-name> ns_per_call=<integer>
/// ```
///
/// Function-name mapping to the perf.jsonl schema keys:
///   `fletcher32`     -> `fletcher32_ns`
///   `feistel_mix`    -> `feistel_mix_ns`
///   `derive_byte`    -> `derive_byte_ns`
///   `DemoHash::hash` -> `demohash_ns`
///
/// Unknown function names are forwarded into the metrics map as
/// `<lowercased>_ns` so when Track 2 adds `DemoSignatureVerify`, the
/// fifth field appears automatically without a verifier change.
fn run_perf(
    scratch: &Path,
    target_dir: &Path,
    cargo: &Path,
) -> Result<PerfMetrics> {
    // `--no-fail-fast` is unnecessary here because the perf test has no
    // assertions, but `--nocapture` is critical: cargo swallows stdout
    // from passing tests by default, and we need the `perf:` lines.
    let mut perf = Command::new(cargo);
    perf.arg("test")
        .arg("--release")
        .arg("--test")
        .arg("perf")
        .arg("-p")
        .arg("proteus-target-minimal")
        .arg("--target-dir")
        .arg(target_dir)
        .arg("--")
        .arg("--nocapture")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .current_dir(scratch);
    let out = perf
        .output()
        .with_context(|| format!("invoke cargo test --test perf in {}", scratch.display()))?;
    if !out.status.success() {
        // Surface the cargo output so the morph engine operator can
        // diagnose without having to re-run the verifier by hand.
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "perf test exited non-zero in {}: {}",
            scratch.display(),
            stderr.lines().last().unwrap_or("<no stderr>")
        );
    }

    let stdout = String::from_utf8_lossy(&out.stdout);
    Ok(parse_perf_stdout(&stdout))
}

/// Parse the `perf:` lines from the test stdout into a `PerfMetrics`.
/// Pure function for testability.
fn parse_perf_stdout(stdout: &str) -> PerfMetrics {
    let mut m = PerfMetrics::default();
    for line in stdout.lines() {
        let line = line.trim();
        let rest = match line.strip_prefix("perf:") {
            Some(r) => r.trim(),
            None => continue,
        };
        let mut parts = rest.splitn(2, char::is_whitespace);
        let name = match parts.next() {
            Some(n) => n,
            None => continue,
        };
        let value_part = match parts.next() {
            Some(v) => v.trim(),
            None => continue,
        };
        let value: u64 = match value_part.strip_prefix("ns_per_call=") {
            Some(s) => match s.trim().parse() {
                Ok(v) => v,
                Err(_) => continue,
            },
            None => continue,
        };
        // Map well-known names to their JSONL keys; everything else is
        // forwarded as `<sanitised>_ns` so schema growth on the target
        // side is forward-compatible.
        let key = match name {
            "fletcher32" => "fletcher32_ns".to_string(),
            "feistel_mix" => "feistel_mix_ns".to_string(),
            "derive_byte" => "derive_byte_ns".to_string(),
            "DemoHash::hash" => "demohash_ns".to_string(),
            other => {
                // Strip `::` (e.g., `DemoSignatureVerify::verify` ->
                // `demosignatureverify_verify`), lowercase, append `_ns`.
                let sanitised: String = other
                    .chars()
                    .filter(|c| c.is_ascii_alphanumeric() || *c == '_')
                    .flat_map(|c| c.to_lowercase())
                    .collect();
                format!("{}_ns", sanitised)
            }
        };
        m.insert(key, value);
    }
    m
}

/// Append a JSONL record to the workspace perf log. Called only on
/// the accept path; reject paths must NOT pollute the log.
fn append_perf_record(perf_log_path: &Path, metrics: &PerfMetrics) -> Result<()> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Always emit the four canonical fields for backward-compatible
    // readers, then any extras in insertion order.
    //
    // null vs 0 policy: a present-but-zero measurement (function
    // clocked below `Instant`'s ns granularity, or median-of-batches
    // collapsed to zero) is written as the integer `0`. The literal
    // `null` is reserved for "function was not measured at all this
    // cycle" — e.g., the perf test failed to compile, or the function
    // didn't exist in this candidate's measurement set. The
    // `metrics.get(k).is_some()` check distinguishes the two:
    // `Some(0)` -> `0`, `None` -> `null`. Earlier verifier builds
    // emitted `null` ambiguously and that produced the
    // `fletcher32_ns: null` curiosity in old smoke tests.
    let canonical: &[&str] = &[
        "fletcher32_ns",
        "feistel_mix_ns",
        "derive_byte_ns",
        "demohash_ns",
    ];
    fn fmt(v: Option<u64>) -> String {
        match v {
            // Present measurement (including legitimately zero) writes
            // the integer.
            Some(n) => n.to_string(),
            // Absent measurement writes the JSON null literal.
            None => "null".to_string(),
        }
    }
    let mut parts = vec![format!("\"ts_unix\":{}", ts)];
    for k in canonical {
        parts.push(format!("\"{}\":{}", k, fmt(metrics.get(k))));
    }
    // Extras: any field present in `metrics.fields` that isn't in `canonical`.
    for (k, v) in &metrics.fields {
        if !canonical.contains(&k.as_str()) {
            parts.push(format!("\"{}\":{}", k, v));
        }
    }
    let record = format!("{{{}}}\n", parts.join(","));

    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(perf_log_path)
        .with_context(|| format!("open perf log {}", perf_log_path.display()))?;
    f.write_all(record.as_bytes())
        .with_context(|| format!("append to perf log {}", perf_log_path.display()))?;
    Ok(())
}

// `PerfMetrics`, `parse_jsonl_metrics`, `read_baseline`,
// `read_baseline_window`, and the new `evaluate_perf_gate` all live in
// `proteus_verifier::perf` (in `lib.rs`). Static reject stages live in
// `proteus_verifier::static_checks`. The binary just calls them.
