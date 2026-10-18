//! Library surface of the `cuttle-verifier` crate. The binary
//! (`src/main.rs`) is the user-facing CLI; this lib exists so external
//! tests (`tests/perf_gate.rs`, `tests/cap_typestate.rs`, etc.) can
//! exercise individual verifier properties in isolation without
//! spinning up a full cargo-build/test scratch dir.
//!
//! # Removed: `cap_check` (TASK-020)
//!
//! The `cap_check` AST-walker module is deleted in TASK-020. Its
//! purpose — confirming that a morph candidate's dispatcher body
//! syntactically references `check_cap` — is now enforced by the
//! Rust compiler via a type-state proof carried in
//! `cuttle_contracts::CapProof`. A privileged dispatch handler
//! declares `_proof: CapProof` in its signature; safe code cannot
//! mint a `CapProof` outside the contracts crate, so the only path
//! to the handler is through a successful `check_cap` call. The
//! AST walker was a false floor (it accepted `let _ = check_cap();`
//! and `if false { check_cap()?; }`); the type-state proof closes
//! the gap.

pub mod perf;
pub mod static_checks;

// Convenience re-exports for the perf gate. Tests and downstream tools
// can pull these from the crate root.
pub use perf::{
    evaluate_perf_gate, p95_u64, parse_jsonl_metrics, parse_threshold_arg, parse_window_arg,
    read_baseline, read_baseline_window, unmatched_fields, PerfGateOutcome, PerfMetrics,
    DEFAULT_PERF_INPUTS_PER_CYCLE, DEFAULT_PERF_THRESHOLD_PCT, DEFAULT_PERF_WINDOW,
    MIN_BASELINE_ENTRIES,
};

// Static (pre-compile) poison-corpus surface.
pub use static_checks::{
    collect_pub_idents, evaluate_static, parse_manifest_str, StaticCheckInput, StaticCheckOutcome,
    StaticRejectReason,
};

/// Argument parser exposed to integration tests so they can assert the
/// CLI's interpretation of `--perf-threshold` / `--perf-window` /
/// candidate path without spawning the binary.
pub mod cli {
    use anyhow::Result;
    use std::path::PathBuf;

    use crate::perf::{
        parse_threshold_arg, parse_window_arg, DEFAULT_PERF_THRESHOLD_PCT, DEFAULT_PERF_WINDOW,
    };

    /// Parsed CLI arguments. Mirror of the binary-internal `ParsedArgs`.
    ///
    /// # Single-module vs bundle mode
    ///
    /// - **Single-module** (legacy, backward-compatible): a positional
    ///   path argument is required. The candidate is substituted at
    ///   `<target_crate>/src/<module>.rs`. Defaults preserve the
    ///   historical `target_minimal/src/lib.rs` shape.
    /// - **Bundle**: one or more `--bundle-module NAME=PATH` pairs
    ///   declare an atomic multi-file substitution into
    ///   `<target_crate>/src/<NAME>.rs`. No positional candidate; the
    ///   bundle list IS the candidate. Either compile succeeds for the
    ///   whole bundle (accept) or it fails (reject); there is no
    ///   per-module accept/reject — that is the atomicity property.
    ///
    /// The two modes are mutually exclusive: passing both a positional
    /// candidate AND `--bundle-module` is an error.
    #[derive(Debug, Clone)]
    pub struct ParsedArgs {
        /// Single-module candidate path. `None` in bundle mode.
        pub candidate: Option<PathBuf>,
        /// Bundle mode: ordered `(module_name, candidate_path)` pairs.
        /// Empty in single-module mode. Preserved in insertion order
        /// for deterministic hash-computation downstream.
        pub bundle: Vec<(String, PathBuf)>,
        /// Workspace-member crate to substitute the candidate(s) into.
        /// Defaults to `target_minimal` so unconfigured single-module
        /// callers keep working bit-for-bit.
        pub target_crate: String,
        /// Module name inside `src/<module>.rs` in single-module mode.
        /// Ignored in bundle mode (each bundle entry brings its own).
        /// Defaults to `lib`.
        pub module: String,
        pub previous: Option<PathBuf>,
        pub manifest: Option<PathBuf>,
        /// Percent threshold. Defaults to
        /// [`DEFAULT_PERF_THRESHOLD_PCT`] (=20).
        pub perf_threshold: u32,
        /// Rolling window. Defaults to [`DEFAULT_PERF_WINDOW`] (=10).
        pub perf_window: usize,
        /// Override for the baseline JSONL file.
        pub perf_baseline: Option<PathBuf>,
        /// If true, skip perf gating entirely.
        pub no_perf_check: bool,
    }

    /// Parse the verifier's command-line argument vector. Returns an
    /// error rather than calling `std::process::exit` so tests can
    /// assert against bad inputs.
    pub fn parse_args(args: &[String]) -> Result<ParsedArgs> {
        let mut candidate: Option<PathBuf> = None;
        let mut bundle: Vec<(String, PathBuf)> = Vec::new();
        let mut target_crate: Option<String> = None;
        let mut module: Option<String> = None;
        let mut previous: Option<PathBuf> = None;
        let mut manifest: Option<PathBuf> = None;
        let mut perf_threshold: u32 = DEFAULT_PERF_THRESHOLD_PCT;
        let mut perf_window: usize = DEFAULT_PERF_WINDOW;
        let mut perf_baseline: Option<PathBuf> = None;
        let mut no_perf_check: bool = false;

        let mut i = 1;
        while i < args.len() {
            match args[i].as_str() {
                "--previous" => {
                    previous = Some(PathBuf::from(
                        args.get(i + 1).ok_or_else(|| {
                            anyhow::anyhow!("--previous needs value")
                        })?,
                    ));
                    i += 2;
                }
                "--manifest" => {
                    manifest = Some(PathBuf::from(
                        args.get(i + 1).ok_or_else(|| {
                            anyhow::anyhow!("--manifest needs value")
                        })?,
                    ));
                    i += 2;
                }
                "--target-crate" => {
                    target_crate = Some(
                        args.get(i + 1)
                            .ok_or_else(|| anyhow::anyhow!("--target-crate needs value"))?
                            .to_string(),
                    );
                    i += 2;
                }
                "--module" => {
                    module = Some(
                        args.get(i + 1)
                            .ok_or_else(|| anyhow::anyhow!("--module needs value"))?
                            .to_string(),
                    );
                    i += 2;
                }
                "--bundle-module" => {
                    // Form: --bundle-module NAME=PATH. Used for atomic
                    // multi-module bundle verification (TASK-036
                    // Phase A). Each entry substitutes one source file
                    // into the scratch crate; the substitution set is
                    // atomic — either all candidates compile together
                    // or the whole bundle is rejected.
                    let raw = args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--bundle-module needs NAME=PATH value")
                    })?;
                    let eq = raw.find('=').ok_or_else(|| {
                        anyhow::anyhow!(
                            "--bundle-module value {:?} missing '=' (expected NAME=PATH)",
                            raw
                        )
                    })?;
                    let (name, path) = raw.split_at(eq);
                    let path = &path[1..]; // strip '='
                    if name.is_empty() || path.is_empty() {
                        anyhow::bail!(
                            "--bundle-module value {:?} has empty NAME or PATH",
                            raw
                        );
                    }
                    bundle.push((name.to_string(), PathBuf::from(path)));
                    i += 2;
                }
                "--perf-threshold" => {
                    let v = args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--perf-threshold needs value")
                    })?;
                    perf_threshold = parse_threshold_arg(v)?;
                    i += 2;
                }
                "--perf-window" => {
                    let v = args.get(i + 1).ok_or_else(|| {
                        anyhow::anyhow!("--perf-window needs value")
                    })?;
                    perf_window = parse_window_arg(v)?;
                    i += 2;
                }
                "--perf-baseline" => {
                    perf_baseline = Some(PathBuf::from(
                        args.get(i + 1).ok_or_else(|| {
                            anyhow::anyhow!("--perf-baseline needs value")
                        })?,
                    ));
                    i += 2;
                }
                "--no-perf-check" => {
                    no_perf_check = true;
                    i += 1;
                }
                "-h" | "--help" => {
                    eprintln!(
                        "usage:\n  \
                         single-module:  verify [--target-crate <NAME>] [--module <NAME>] \\\n                          [--previous <prev.rs>] [--manifest <m.txt>] \\\n                          [--perf-threshold <V>] [--perf-window <N>] \\\n                          [--perf-baseline <P>] [--no-perf-check] \\\n                          <CANDIDATE.rs>\n  \
                         bundle mode:    verify --target-crate <NAME> \\\n                          --bundle-module <NAME>=<PATH> [--bundle-module ...] \\\n                          [--manifest <m.txt>] [--no-perf-check]\n\
                         \n\
                         Single-module: substitutes <CANDIDATE.rs> at \n\
                         <target-crate>/src/<module>.rs in the scratch workspace.\n\
                         Default target-crate is `target_minimal`, default module is `lib`.\n\
                         \n\
                         Bundle: one or more --bundle-module NAME=PATH pairs declare an\n\
                         atomic multi-file substitution. Verifier accepts iff EVERY \n\
                         candidate compiles together; one rejection rejects the whole bundle.\n\
                         \n\
                         --perf-threshold accepts either a decimal ratio (e.g. 1.2 = +20%) \n\
                         or an integer percent >= 10 (e.g. 50 = +50%). Defaults to 1.2."
                    );
                    std::process::exit(0);
                }
                other if !other.starts_with('-') => {
                    candidate = Some(PathBuf::from(other));
                    i += 1;
                }
                other => anyhow::bail!("unknown argument: {}", other),
            }
        }

        // Defaults preserve the legacy single-module invocation shape
        // bit-for-bit: `target_minimal/src/lib.rs` substitution.
        let target_crate = target_crate.unwrap_or_else(|| "target_minimal".to_string());
        let module = module.unwrap_or_else(|| "lib".to_string());

        // Mode validation: exactly one of (positional candidate, bundle)
        // must be non-empty.
        match (candidate.as_ref(), bundle.is_empty()) {
            (Some(_), true) => {}  // single-module: ok
            (None, false) => {}    // bundle: ok
            (Some(_), false) => anyhow::bail!(
                "verify: positional candidate AND --bundle-module are mutually exclusive"
            ),
            (None, true) => anyhow::bail!(
                "verify: either a positional candidate path OR ≥1 --bundle-module is required"
            ),
        }

        Ok(ParsedArgs {
            candidate,
            bundle,
            target_crate,
            module,
            previous,
            manifest,
            perf_threshold,
            perf_window,
            perf_baseline,
            no_perf_check,
        })
    }
}
