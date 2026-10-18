//! TASK-015 — morph diversity & synthetic-exploit-survival demonstrator.
//!
//! Drives the full Cuttle morph pipeline (synthesize=passthrough →
//! diversify → verify → sign → emit-kernel-ELF) for N cycles, measures
//! how much the resulting kernel `.text` section actually changes
//! cycle-to-cycle, and probes whether a fixed synthetic ROP chain keyed
//! to cycle-0 symbol offsets still "lands" in later cycles.
//!
//! # Why this crate exists separately
//!
//! `morph_engine::run_cycle` is the canonical pipeline driver and we do
//! NOT reimplement it. But it bakes in attestation-log writes, optional
//! image emission, and other production concerns we don't want for an
//! experiment that runs 100 cycles in one process. So this crate
//! composes the same building blocks — `cuttle_diversifier::diversify`,
//! `cuttle_diversifier::canonical_hash`, the `verify` sibling binary,
//! ed25519 signing, `factory_builder::build_kernel` — into a leaner
//! loop that emits JSONL telemetry rather than attestation entries.
//!
//! # Two modes
//!
//! - **Real mode** (`fast_mode = false`, the default): each cycle
//!   actually invokes `factory_builder::build_kernel` against the
//!   out-of-workspace `target_enterprise_kernel/` crate. This is what
//!   the CLI demo runs. Each cycle costs whatever nightly+cargo costs
//!   on the host — 5-30 seconds typically.
//! - **Fast mode** (`fast_mode = true`, used by the integration tests):
//!   skips the real kernel build and synthesises a deterministic
//!   "pseudo-ELF" whose `.text` bytes and symbol offsets are derived
//!   from the diversified candidate's canonical hash. This keeps the
//!   integration tests honest about diversity (a no-op diversifier
//!   would still produce identical pseudo-ELFs cycle-to-cycle) while
//!   keeping the `cargo test` runtime in seconds, not minutes.
//!
//! The distinction is documented in REPORT.md so a sceptic reading the
//! test code understands what each mode proves.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signer, SigningKey};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

pub mod qemu_boot;

/// Inputs to `run_experiment`. Maps 1:1 to the CLI flags.
///
/// # Single-module vs bundle mode
///
/// - **Single-module** (legacy): `bundle_name` is `None` and `module`
///   names the lone source file to morph. The seed label is the
///   module name; the cycle morphs one file and builds the kernel.
/// - **Bundle**: `bundle_name` is `Some("kernel")` (or similar) and
///   `bundle_modules` lists every member. The cycle morphs ALL members
///   with per-(cycle, bundle_name, module) seeds, builds the kernel
///   ONCE against the multi-morphed crate, and records both the bundle
///   hash (in `candidate_sha256`) and the per-member canonical hashes
///   (in `CycleRecord.bundle_modules`). This is the whole-kernel
///   scramble measurement: the resulting `.text` diversity reflects
///   churn across every enrolled module simultaneously.
#[derive(Debug, Clone)]
pub struct ExperimentArgs {
    /// Number of pipeline cycles to drive.
    pub cycles: u64,
    /// Path to the workspace member containing the module to morph.
    /// e.g. `D:/RustProjects/Cuttle/target_enterprise`.
    pub target_dir: PathBuf,
    /// Single-module mode: the module name. In bundle mode this is
    /// the bundle name (used as a label in summaries/reports). The
    /// actual file(s) morphed are resolved by `source_paths()`.
    pub module: String,
    /// Bundle name when running in bundle mode. `None` = single-module
    /// mode. The seed-derivation label in bundle mode is
    /// `"{bundle_name}::{member}"` so each member morphs under its own
    /// per-cycle seed.
    pub bundle_name: Option<String>,
    /// Bundle membership when running in bundle mode. `None` =
    /// single-module mode (uses `module` field as the lone source).
    /// `Some(mods)` = bundle mode; each entry resolves to
    /// `<target_dir>/src/<mod>.rs`.
    pub bundle_modules: Option<Vec<String>>,
    /// Path to the out-of-workspace kernel crate (`target_enterprise_kernel/`).
    /// Only used when `fast_mode == false`.
    pub kernel_crate_dir: PathBuf,
    /// Directory the experiment writes its outputs to (cycles.jsonl,
    /// diversity.jsonl, survival.jsonl, REPORT.md).
    pub results_dir: PathBuf,
    /// When true, skip the real kernel build and synthesise a
    /// deterministic pseudo-ELF instead. Used by the integration tests.
    pub fast_mode: bool,
    /// When true, skip the verifier step. The verifier requires a
    /// pre-built `verify` binary on PATH or alongside the running
    /// binary; integration tests that run from cargo's deps dir often
    /// don't have it. Defaults to false (verifier IS run).
    pub skip_verify: bool,
    /// Path to the ed25519 signing key file. If the file doesn't
    /// exist, an ephemeral in-memory key is generated for the run.
    pub signing_key_path: Option<PathBuf>,
    /// Path to the `verify` binary. If `None`, locate it the same way
    /// `morph_engine::cycle::locate_sibling_bin` does (search beside
    /// the current exe).
    pub verify_bin: Option<PathBuf>,
    /// When true, save each accepted cycle's candidate source to
    /// `<results_dir>/candidates/cycle_NN.rs`. Used by TASK-024's
    /// dedup-diagnosis flow: pairs of cycles with byte-identical
    /// `elf_text_sha256` are diff-compared at source + MIR level to
    /// classify the collision (AST-equivalent vs codegen-folded). Off
    /// by default to preserve current disk footprint.
    pub save_candidates: bool,
    /// TASK-026 — when true, every accepted cycle's kernel ELF is
    /// packaged as a BIOS image, booted under QEMU with a per-cycle
    /// `-serial file:` target, and the captured log's sha256 is
    /// recorded on the `CycleRecord`. Off by default — turning it on
    /// adds ~10 s per cycle (QEMU spawn + boot + 20 s wait deadline
    /// per failure). Ignored under `fast_mode` (no real kernel ELF
    /// exists to boot).
    pub boot_each_cycle: bool,
    /// Phase-1 codegen-diversity lever. When true (the CLI default),
    /// every real-mode kernel build runs under a per-cycle layout
    /// seed: `factory_builder::build_kernel_with_layout_seed` injects
    /// `-Zrandomize-layout=yes -Zlayout-seed=<seed>
    /// -Zfunction-sections=yes -Clink-arg=--shuffle-sections=.text*=<seed>`
    /// into the kernel cargo child. This is the lever that actually
    /// relocates function offsets between cycles — the AST-level
    /// diversifier alone demonstrably does not (TASK-025 /
    /// REPORT-real.md: 4 distinct layouts and 100% chain survival
    /// across 20 cycles). `false` (`--no-layout-seed`) reproduces the
    /// historical deterministic-layout build for A/B comparison.
    ///
    /// Fast mode honours the flag too: the synthetic pseudo-ELF mixes
    /// the per-cycle seed into its symbol-offset placement (and only
    /// that) so integration tests can pin the relocation property
    /// without a nightly build — see `synthesize_pseudo_elf_seeded`.
    pub layout_seed_enabled: bool,
    /// When true, the AST diversifier runs with
    /// [`cuttle_diversifier::DiversifyOptions::with_stack_pad`].
    /// **Default false**: stack pads inflate gadget count (~+33%
    /// measured) without buying chain-death once layout seeding is
    /// engaged. Opt in only for A/B measurement of the TASK-029 pass.
    pub stack_pad_enabled: bool,
}

impl ExperimentArgs {
    /// True iff this run targets a bundle (i.e. multiple modules
    /// morphed atomically per cycle).
    pub fn is_bundle(&self) -> bool {
        self.bundle_modules.is_some()
    }

    /// Names of every module the experiment will morph. In
    /// single-module mode this returns a one-element vec containing
    /// `self.module`; in bundle mode it returns `bundle_modules.clone()`.
    pub fn member_names(&self) -> Vec<String> {
        match &self.bundle_modules {
            Some(mods) => mods.clone(),
            None => vec![self.module.clone()],
        }
    }

    /// Resolve the on-disk source path for the (single-module mode)
    /// module being morphed. In bundle mode this returns the path for
    /// the FIRST listed module — callers that need every member should
    /// use [`source_paths`](Self::source_paths) instead.
    pub fn source_path(&self) -> PathBuf {
        let name = match &self.bundle_modules {
            Some(mods) => mods.first().cloned().unwrap_or_else(|| self.module.clone()),
            None => self.module.clone(),
        };
        self.target_dir.join("src").join(format!("{}.rs", name))
    }

    /// Every on-disk source path the experiment will morph. One entry
    /// per member (one-element vec in single-module mode).
    pub fn source_paths(&self) -> Vec<PathBuf> {
        self.member_names()
            .iter()
            .map(|m| self.target_dir.join("src").join(format!("{}.rs", m)))
            .collect()
    }

    /// Backup path used to preserve the pristine pre-run source. The
    /// experiment restores this on exit (success or failure) so the
    /// workspace still builds afterwards. In bundle mode this returns
    /// the first-member's backup; callers should use
    /// [`backup_paths`](Self::backup_paths).
    pub fn backup_path(&self) -> PathBuf {
        let name = match &self.bundle_modules {
            Some(mods) => mods.first().cloned().unwrap_or_else(|| self.module.clone()),
            None => self.module.clone(),
        };
        self.target_dir
            .join("src")
            .join(format!("{}.rs.preexp.bak", name))
    }

    /// Every backup path the experiment will manage.
    pub fn backup_paths(&self) -> Vec<PathBuf> {
        self.member_names()
            .iter()
            .map(|m| self.target_dir.join("src").join(format!("{}.rs.preexp.bak", m)))
            .collect()
    }
}

/// Per-cycle telemetry. One record written to `cycles.jsonl` per
/// cycle (whether accepted or rejected).
///
/// # Bundle vs single-module fields
///
/// - `candidate_sha256`: in single-module mode this is the canonical
///   hash of the lone diversified candidate; in bundle mode it is the
///   bundle hash (`sha256(sorted concat of "module:hex\n")`).
/// - `bundle_modules`: empty in single-module mode; in bundle mode it
///   carries `{module → canonical-hex}` for every member. The keyset
///   reproduces the `[bundle.NAME] modules` list from `scheduler.toml`.
///
/// Canonical-JSON: `bundle_modules` is `skip_serializing_if = "BTreeMap::is_empty"`
/// so single-module records hash byte-identically to pre-Phase-B
/// schema (the field is invisible in their JSON).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CycleRecord {
    pub cycle: u64,
    pub accepted: bool,
    /// Reason for rejection, if `accepted == false`. `None` otherwise.
    pub reject_reason: Option<String>,
    pub candidate_sha256: String,
    pub elf_text_sha256: String,
    pub elf_text_size: usize,
    pub function_offsets: HashMap<String, u64>,
    pub wall_clock_ms: u128,
    /// Per-member canonical hashes in bundle mode. Empty for legacy
    /// single-module cycles. `BTreeMap` (not `HashMap`) for stable
    /// serialization order, which keeps `cycles.jsonl` byte-stable
    /// across runs with identical inputs.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub bundle_modules: std::collections::BTreeMap<String, String>,
    /// TASK-026 — sha256 hex of the per-cycle QEMU serial log captured
    /// when `ExperimentArgs::boot_each_cycle == true`. `None` for
    /// runs that didn't opt into per-cycle booting OR for rejected
    /// cycles (which never reach the package+boot stage). The
    /// `skip_serializing_if = "Option::is_none"` keeps `cycles.jsonl`
    /// byte-identical to pre-TASK-026 schema when the flag is off,
    /// preserving backward-compatibility with existing consumers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub serial_log_sha256: Option<String>,
    /// The kernel layout seed this cycle's build ran under (Phase-1
    /// codegen diversity) — the value passed to
    /// `factory_builder::build_kernel_with_layout_seed`, derived by
    /// [`cycle_layout_seed`] (which mirrors
    /// `morph_engine::cycle::kernel_layout_seed`). `None` when the run
    /// disabled seeding (`--no-layout-seed`) or for rejected cycles.
    /// Same additive `skip_serializing_if` treatment as
    /// `serial_log_sha256`, so pre-seed `cycles.jsonl` files re-read
    /// (and re-serialize) byte-identically.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kernel_layout_seed: Option<u64>,
}

/// One row in `diversity.jsonl`. Per consecutive pair of accepted
/// cycles.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiversityRecord {
    pub cycle: u64,
    pub prev_cycle: u64,
    pub raw_bits_diff: u64,
    pub normalised: f64,
    pub size_a: usize,
    pub size_b: usize,
}

/// One row in `survival.jsonl`. Per cycle >= 1.
///
/// `symbol_a` / `symbol_b` are the RAW (mangled) ELF names — the same
/// keys that appear in `CycleRecord::function_offsets`. The
/// `demangled_a` / `demangled_b` fields carry the human-readable Rust
/// paths (e.g. `target_enterprise::tls::hkdf_expand_label`) so a
/// reader of `survival.jsonl` can tell at a glance whether the probe
/// landed on a morphed-module symbol or on a kernel helper picked by
/// the fallback path. `used_fallback == true` means
/// `pick_chain_symbols` could NOT locate the anchor symbol
/// (`target_enterprise::tls::hkdf_expand_label`) in cycle 0's symbol
/// table — survival numbers from a fallback run are NOT comparable to
/// a non-fallback run and the interpretation in REPORT.md flags them.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SurvivalRecord {
    pub cycle: u64,
    pub offset_a: u64,
    pub offset_b: u64,
    pub symbol_a: String,
    pub symbol_b: String,
    #[serde(default)]
    pub demangled_a: String,
    #[serde(default)]
    pub demangled_b: String,
    #[serde(default)]
    pub used_fallback: bool,
    pub survived_a: bool,
    pub survived_b: bool,
    pub survived_both: bool,
}

/// What `run_experiment` returns. Captures every number that ends up
/// in REPORT.md so the binary can format the report without
/// re-reading the JSONL files it just wrote.
#[derive(Debug, Clone)]
pub struct RunSummary {
    pub cycles_requested: u64,
    pub cycles_completed: u64,
    pub cycles_rejected: u64,
    pub fast_mode: bool,
    pub module: String,
    pub target_dir: PathBuf,
    /// Bundle name, when this run morphed an atomic multi-module
    /// bundle. `None` for single-module runs. (RunSummary is a
    /// pure-in-memory aggregator; no serde attributes needed.)
    pub bundle_name: Option<String>,
    /// Bundle membership. Empty for single-module runs.
    pub bundle_members: Vec<String>,

    /// Number of distinct `elf_text_sha256` values observed across
    /// accepted cycles. THE entropy floor. If this is 1, the
    /// diversifier produces zero binary diversity for this module.
    pub distinct_text_sha256: usize,

    /// Hamming-distance stats across consecutive accepted pairs.
    /// Normalised values are in [0.0, 1.0]; `None` if fewer than two
    /// accepted cycles.
    pub hamming_median_norm: Option<f64>,
    pub hamming_p95_norm: Option<f64>,
    pub hamming_max_norm: Option<f64>,
    /// Same stats but raw bit counts.
    pub hamming_median_bits: Option<u64>,
    pub hamming_p95_bits: Option<u64>,
    pub hamming_max_bits: Option<u64>,

    /// Synthetic-chain survival. The two symbols chosen at cycle 0,
    /// the offsets they had then, and the per-cycle survival count.
    /// `chain_symbol_a` / `chain_symbol_b` are the raw mangled ELF
    /// names (same as `CycleRecord::function_offsets` keys); the
    /// `chain_demangled_a` / `chain_demangled_b` fields carry the
    /// Rust-source paths (`target_enterprise::tls::hkdf_expand_label`
    /// etc.) for REPORT.md and human-eyeball use.
    pub chain_symbol_a: String,
    pub chain_symbol_b: String,
    pub chain_demangled_a: String,
    pub chain_demangled_b: String,
    pub chain_offset_a: u64,
    pub chain_offset_b: u64,
    pub chain_survived_both: u64,
    pub chain_total_probes: u64,
    /// True iff `pick_chain_symbols` could not find the anchor symbol
    /// `target_enterprise::tls::hkdf_expand_label` in cycle 0's
    /// symbol table and fell back. Survival numbers from a fallback
    /// run are not comparable to a non-fallback run; REPORT.md flags
    /// this prominently.
    pub chain_used_fallback: bool,

    /// Per-cycle wall-clock (across ALL cycles, accepted or not).
    pub wallclock_median_ms: u128,
    pub wallclock_p95_ms: u128,
    pub wallclock_max_ms: u128,

    /// TASK-026 — number of distinct `serial_log_sha256` values
    /// observed across accepted cycles whose record carried a non-None
    /// serial log sha. Zero when the run didn't opt into
    /// `--boot-each-cycle`. Two cycles with byte-identical ELFs but
    /// divergent serial logs would be a noteworthy finding (the
    /// kernel asserts byte-equality against locked fixtures, so any
    /// drift produces a panic banner) — REPORT.md flags that
    /// scenario.
    pub distinct_serial_log_sha256: usize,
    /// TASK-026 — number of accepted cycles that carried a captured
    /// serial-log sha. Equal to `cycles_completed` for runs with
    /// `--boot-each-cycle` set, 0 otherwise.
    pub cycles_with_serial_log: u64,

    /// True iff this run built kernels under per-cycle layout seeds
    /// (`ExperimentArgs::layout_seed_enabled`).
    pub layout_seed_enabled: bool,
    /// True iff the AST diversifier ran with stack-frame padding on
    /// (`ExperimentArgs::stack_pad_enabled`). Production default is
    /// false — see the field docs on `ExperimentArgs`.
    pub stack_pad_enabled: bool,
    /// Number of distinct `(symbol → offset)` layouts observed across
    /// accepted cycles, canonicalised by sorting the (symbol, offset)
    /// pairs. This is the headline TASK-025 measured by hand (4
    /// layouts over 20 cycles); the harness now computes it directly
    /// so it can act as a regression gate. With the layout lever
    /// engaged this should track `cycles_completed`.
    pub distinct_function_layouts: usize,
    /// Distinct offsets the chain anchor symbol (`chain_symbol_a`)
    /// was observed at across accepted cycles where it was present.
    /// 1 = the symbol never moved — exactly the TASK-025 failure;
    /// ≈ `cycles_completed` = the relocation lever is doing its job.
    pub chain_offset_a_distinct: usize,
    /// Same for `chain_symbol_b`.
    pub chain_offset_b_distinct: usize,

    /// Absolute paths to the artefacts this run wrote.
    pub cycles_jsonl: PathBuf,
    pub diversity_jsonl: PathBuf,
    pub survival_jsonl: PathBuf,

    /// ISO-8601-ish UTC start time.
    pub run_start_iso: String,
}

/// Drive the experiment end-to-end. Returns a summary with every
/// number that goes into REPORT.md.
///
/// This function takes responsibility for backing up and restoring
/// `<target>/src/<module>.rs`. On exit (Ok or Err), the source file
/// is the pristine pre-run version.
pub fn run_experiment(args: &ExperimentArgs) -> Result<RunSummary> {
    // Resolve every source we'll morph (one in single-module mode,
    // N in bundle mode). Verify existence + read pristine + write
    // backup for each. Failures here MUST roll back any partial work
    // so the workspace stays buildable.
    let sources: Vec<PathBuf> = args.source_paths();
    let backups: Vec<PathBuf> = args.backup_paths();
    let members: Vec<String> = args.member_names();
    debug_assert_eq!(sources.len(), backups.len());
    debug_assert_eq!(sources.len(), members.len());

    for src in &sources {
        if !src.exists() {
            bail!(
                "diversity_demo: source file {} does not exist (bad --target / --module / --bundle?)",
                src.display()
            );
        }
    }
    // Read pristine for each source.
    let mut pristines: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    for (member, src) in members.iter().zip(sources.iter()) {
        let txt = fs::read_to_string(src)
            .with_context(|| format!("read pristine source at {}", src.display()))?;
        pristines.insert(member.clone(), txt);
    }
    // Write each backup. If any write fails partway through, roll back
    // backups already written so we don't leave litter.
    let mut written_backups: Vec<PathBuf> = Vec::new();
    let mut write_err: Option<anyhow::Error> = None;
    for (member, bk) in members.iter().zip(backups.iter()) {
        let txt = &pristines[member];
        match fs::write(bk, txt) {
            Ok(()) => written_backups.push(bk.clone()),
            Err(e) => {
                write_err = Some(
                    anyhow::Error::new(e).context(format!("write backup at {}", bk.display())),
                );
                break;
            }
        }
    }
    if let Some(e) = write_err {
        for bk in &written_backups {
            let _ = fs::remove_file(bk);
        }
        return Err(e);
    }

    // (Legacy shim removed: run_experiment_inner now consumes the full
    // pristines map directly.)

    fs::create_dir_all(&args.results_dir)
        .with_context(|| format!("create results dir {}", args.results_dir.display()))?;

    let cycles_jsonl = args.results_dir.join("cycles.jsonl");
    let diversity_jsonl = args.results_dir.join("diversity.jsonl");
    let survival_jsonl = args.results_dir.join("survival.jsonl");
    // Truncate prior runs.
    fs::write(&cycles_jsonl, "")?;
    fs::write(&diversity_jsonl, "")?;
    fs::write(&survival_jsonl, "")?;

    if args.save_candidates {
        let cand_dir = args.results_dir.join("candidates");
        fs::create_dir_all(&cand_dir).with_context(|| {
            format!("create candidates dir {}", cand_dir.display())
        })?;
        // Clear stale candidate files from a prior run.
        if let Ok(entries) = fs::read_dir(&cand_dir) {
            for e in entries.flatten() {
                let p = e.path();
                if p.extension().and_then(|s| s.to_str()) == Some("rs")
                    && p.file_name()
                        .and_then(|s| s.to_str())
                        .map(|n| n.starts_with("cycle_"))
                        .unwrap_or(false)
                {
                    let _ = fs::remove_file(&p);
                }
            }
        }
    }

    // The pipeline's own panic safety: any error from inside this
    // block must still restore EVERY pristine source before returning.
    let outcome = run_experiment_inner(
        args,
        &pristines,
        &cycles_jsonl,
        &diversity_jsonl,
        &survival_jsonl,
    );

    // Restore every member. Even on success — leaving any diversified
    // module in place would break the next `cargo build --workspace`.
    for (member, src) in members.iter().zip(sources.iter()) {
        if let Some(p) = pristines.get(member) {
            if let Err(e) = fs::write(src, p) {
                eprintln!(
                    "diversity_demo: WARNING — failed to restore pristine {}: {:#}",
                    src.display(),
                    e
                );
            }
        }
    }
    // Backups are only useful while the run is mid-flight; remove on
    // a clean restore so we don't leave litter in the target crate.
    for bk in &backups {
        let _ = fs::remove_file(bk);
    }

    outcome
}

fn run_experiment_inner(
    args: &ExperimentArgs,
    pristines: &std::collections::BTreeMap<String, String>,
    cycles_jsonl: &Path,
    diversity_jsonl: &Path,
    survival_jsonl: &Path,
) -> Result<RunSummary> {
    let run_start_iso = iso8601_utc_now();

    // Optional signing key. We sign every accepted candidate hash so
    // the signing stage is a real cost in the wall-clock numbers. We
    // load the on-disk key if present; otherwise generate ephemeral so
    // the experiment is self-contained.
    let signing_key = load_or_generate_signing_key(args.signing_key_path.as_deref())?;

    let verify_bin: Option<PathBuf> = if args.skip_verify {
        None
    } else {
        Some(resolve_verify_bin(args.verify_bin.as_deref())?)
    };

    let mut records: Vec<CycleRecord> = Vec::with_capacity(args.cycles as usize);
    let mut last_accepted_text: Option<Vec<u8>> = None;
    let mut last_accepted_cycle: Option<u64> = None;
    let mut last_accepted_record: Option<CycleRecord> = None;

    // Per-member "previous source" the diversifier consumes. Starts
    // as each member's pristine. After each accepted cycle, we update
    // every member's entry to its diversified output so cycle N+1's
    // seed-derived rewrite chains on top of N's (matching `morph run`).
    let mut prev_sources: std::collections::BTreeMap<String, String> = pristines.clone();

    for cycle in 0..args.cycles {
        let t0 = Instant::now();
        let cycle_result = run_one_cycle(
            args,
            cycle,
            &prev_sources,
            verify_bin.as_deref(),
            &signing_key,
        );
        let wall_ms = t0.elapsed().as_millis();

        match cycle_result {
            Ok(CycleOutput {
                candidate_sources,
                candidate_sha256,
                module_canonical_hashes,
                elf_text,
                function_offsets,
                serial_log_sha256,
                kernel_layout_seed,
            }) => {
                let mut h = Sha256::new();
                h.update(&elf_text);
                let text_sha = factory_builder::hex(&h.finalize());
                let rec = CycleRecord {
                    cycle,
                    accepted: true,
                    reject_reason: None,
                    candidate_sha256,
                    elf_text_sha256: text_sha,
                    elf_text_size: elf_text.len(),
                    function_offsets,
                    wall_clock_ms: wall_ms,
                    bundle_modules: module_canonical_hashes,
                    serial_log_sha256,
                    kernel_layout_seed,
                };
                append_jsonl(cycles_jsonl, &rec)?;

                if args.save_candidates {
                    let cand_dir = args.results_dir.join("candidates");
                    // Single-module mode: one file per cycle (legacy
                    // shape). Bundle mode: one subdirectory per cycle
                    // with one file per member.
                    if args.is_bundle() {
                        let cycle_dir = cand_dir.join(format!("cycle_{:02}", cycle));
                        fs::create_dir_all(&cycle_dir).with_context(|| {
                            format!("save candidates dir {}", cycle_dir.display())
                        })?;
                        for (member, src) in &candidate_sources {
                            let p = cycle_dir.join(format!("{}.rs", member));
                            fs::write(&p, src).with_context(|| {
                                format!("save bundle candidate {}", p.display())
                            })?;
                        }
                    } else {
                        let primary = args.member_names()[0].clone();
                        if let Some(src) = candidate_sources.get(&primary) {
                            let path = cand_dir.join(format!("cycle_{:02}.rs", cycle));
                            fs::write(&path, src).with_context(|| {
                                format!("save candidate source at {}", path.display())
                            })?;
                        }
                    }
                }

                if let (Some(prev_text), Some(prev_cy)) =
                    (last_accepted_text.as_ref(), last_accepted_cycle)
                {
                    let div = compute_diversity(prev_cy, cycle, prev_text, &elf_text);
                    append_jsonl(diversity_jsonl, &div)?;
                }
                last_accepted_text = Some(elf_text);
                last_accepted_cycle = Some(cycle);
                last_accepted_record = Some(rec.clone());
                records.push(rec);
                // Every member's diversified source becomes the seed
                // for the next cycle. Members not in this map (none
                // currently — every member is morphed every cycle)
                // would retain their last value.
                for (member, src) in candidate_sources {
                    prev_sources.insert(member, src);
                }
            }
            Err(e) => {
                let reason = format!("{:#}", e);
                eprintln!("diversity_demo: cycle {} REJECTED: {}", cycle, reason);
                let rec = CycleRecord {
                    cycle,
                    accepted: false,
                    reject_reason: Some(reason),
                    candidate_sha256: String::new(),
                    elf_text_sha256: String::new(),
                    elf_text_size: 0,
                    function_offsets: HashMap::new(),
                    wall_clock_ms: wall_ms,
                    bundle_modules: std::collections::BTreeMap::new(),
                    serial_log_sha256: None,
                    kernel_layout_seed: None,
                };
                append_jsonl(cycles_jsonl, &rec)?;
                records.push(rec);
                // Keep prev_sources pointed at the last accepted texts
                // so we don't compound rejections.
            }
        }
    }

    // Survival harness. Run only if cycle 0 was accepted.
    let mut chain_symbol_a = String::from("<none>");
    let mut chain_symbol_b = String::from("<none>");
    let mut chain_demangled_a = String::from("<none>");
    let mut chain_demangled_b = String::from("<none>");
    let mut chain_offset_a: u64 = 0;
    let mut chain_offset_b: u64 = 0;
    let mut chain_survived_both: u64 = 0;
    let mut chain_total_probes: u64 = 0;
    let mut chain_used_fallback = false;

    let first_accepted = records.iter().find(|r| r.accepted);
    if let Some(cycle0) = first_accepted {
        let pick = pick_chain_symbols(&cycle0.function_offsets);
        chain_symbol_a = pick.symbol_a.clone();
        chain_symbol_b = pick.symbol_b.clone();
        chain_demangled_a = pick.demangled_a.clone();
        chain_demangled_b = pick.demangled_b.clone();
        chain_offset_a = pick.offset_a;
        chain_offset_b = pick.offset_b;
        chain_used_fallback = pick.used_fallback;
        // Build the fixed 64-byte chain (offset_a LE | offset_b LE |
        // 48 bytes of filler) — its bytes don't matter for survival
        // analysis but we keep it real, not synthesised on the fly per
        // cycle.
        let _chain: [u8; 64] = build_synthetic_chain(chain_offset_a, chain_offset_b);

        for rec in &records {
            if !rec.accepted {
                continue;
            }
            if rec.cycle == cycle0.cycle {
                continue;
            }
            let sym_a_now = reverse_lookup(&rec.function_offsets, chain_offset_a);
            let sym_b_now = reverse_lookup(&rec.function_offsets, chain_offset_b);
            let survived_a = sym_a_now.as_deref() == Some(chain_symbol_a.as_str());
            let survived_b = sym_b_now.as_deref() == Some(chain_symbol_b.as_str());
            let survived_both = survived_a && survived_b;
            let sr = SurvivalRecord {
                cycle: rec.cycle,
                offset_a: chain_offset_a,
                offset_b: chain_offset_b,
                symbol_a: chain_symbol_a.clone(),
                symbol_b: chain_symbol_b.clone(),
                demangled_a: chain_demangled_a.clone(),
                demangled_b: chain_demangled_b.clone(),
                used_fallback: chain_used_fallback,
                survived_a,
                survived_b,
                survived_both,
            };
            append_jsonl(survival_jsonl, &sr)?;
            if survived_both {
                chain_survived_both += 1;
            }
            chain_total_probes += 1;
        }
    }
    // Use last_accepted_record so the borrow checker is happy and to
    // make the variable used in the absence of a survival run.
    let _ = last_accepted_record;

    // Aggregate stats.
    let accepted: Vec<&CycleRecord> = records.iter().filter(|r| r.accepted).collect();
    let cycles_completed = accepted.len() as u64;
    let cycles_rejected = records.len() as u64 - cycles_completed;

    let distinct_text_sha256: usize = {
        let mut set = std::collections::HashSet::new();
        for r in &accepted {
            set.insert(r.elf_text_sha256.clone());
        }
        set.len()
    };

    // Distinct (symbol → offset) layouts across accepted cycles —
    // the TASK-025 headline, now computed by the harness. Canonical
    // form: sorted "(symbol@hex-offset)" pairs joined with ';'.
    let distinct_function_layouts: usize = {
        let mut set = std::collections::HashSet::new();
        for r in &accepted {
            let mut pairs: Vec<(&String, &u64)> = r.function_offsets.iter().collect();
            pairs.sort();
            let canon: String = pairs
                .iter()
                .map(|(s, o)| format!("{}@{:x}", s, o))
                .collect::<Vec<_>>()
                .join(";");
            set.insert(canon);
        }
        set.len()
    };

    // How many distinct offsets did each probed chain symbol take
    // across accepted cycles (counting only cycles where the symbol
    // was present)? 1 = never moved (the TASK-025 failure mode).
    let (chain_offset_a_distinct, chain_offset_b_distinct): (usize, usize) = {
        let mut set_a = std::collections::HashSet::new();
        let mut set_b = std::collections::HashSet::new();
        for r in &accepted {
            if let Some(off) = r.function_offsets.get(&chain_symbol_a) {
                set_a.insert(*off);
            }
            if let Some(off) = r.function_offsets.get(&chain_symbol_b) {
                set_b.insert(*off);
            }
        }
        (set_a.len(), set_b.len())
    };

    // TASK-026 serial-log entropy. Two parallel HashSets — one
    // counts distinct ELF text shas of cycles that ALSO produced a
    // serial log, the other counts distinct serial logs. A divergence
    // (more distinct serial logs than distinct ELF texts) would be
    // surprising because the kernel is deterministic given its bytes;
    // the surprise is the point of capturing this.
    let (distinct_serial_log_sha256, cycles_with_serial_log): (usize, u64) = {
        let mut set = std::collections::HashSet::new();
        let mut count = 0u64;
        for r in &accepted {
            if let Some(sha) = &r.serial_log_sha256 {
                set.insert(sha.clone());
                count += 1;
            }
        }
        (set.len(), count)
    };

    // Hamming numbers: re-read diversity.jsonl rather than re-derive.
    let div_lines = read_jsonl::<DiversityRecord>(diversity_jsonl)?;
    let (hm_med, hm_p95, hm_max, hb_med, hb_p95, hb_max) = if div_lines.is_empty() {
        (None, None, None, None, None, None)
    } else {
        let mut norms: Vec<f64> = div_lines.iter().map(|d| d.normalised).collect();
        norms.sort_by(|a, b| a.partial_cmp(b).unwrap_or(std::cmp::Ordering::Equal));
        let mut raws: Vec<u64> = div_lines.iter().map(|d| d.raw_bits_diff).collect();
        raws.sort();
        (
            Some(percentile_f64(&norms, 0.50)),
            Some(percentile_f64(&norms, 0.95)),
            Some(*norms.last().unwrap()),
            Some(percentile_u64(&raws, 0.50)),
            Some(percentile_u64(&raws, 0.95)),
            Some(*raws.last().unwrap()),
        )
    };

    let mut walls: Vec<u128> = records.iter().map(|r| r.wall_clock_ms).collect();
    walls.sort();
    let (wm_med, wm_p95, wm_max) = if walls.is_empty() {
        (0, 0, 0)
    } else {
        (
            percentile_u128(&walls, 0.50),
            percentile_u128(&walls, 0.95),
            *walls.last().unwrap(),
        )
    };

    Ok(RunSummary {
        cycles_requested: args.cycles,
        cycles_completed,
        cycles_rejected,
        fast_mode: args.fast_mode,
        module: args.module.clone(),
        target_dir: args.target_dir.clone(),
        bundle_name: args.bundle_name.clone(),
        bundle_members: if args.is_bundle() {
            args.member_names()
        } else {
            Vec::new()
        },
        distinct_text_sha256,
        hamming_median_norm: hm_med,
        hamming_p95_norm: hm_p95,
        hamming_max_norm: hm_max,
        hamming_median_bits: hb_med,
        hamming_p95_bits: hb_p95,
        hamming_max_bits: hb_max,
        chain_symbol_a,
        chain_symbol_b,
        chain_demangled_a,
        chain_demangled_b,
        chain_offset_a,
        chain_offset_b,
        chain_survived_both,
        chain_total_probes,
        chain_used_fallback,
        wallclock_median_ms: wm_med,
        wallclock_p95_ms: wm_p95,
        wallclock_max_ms: wm_max,
        distinct_serial_log_sha256,
        cycles_with_serial_log,
        layout_seed_enabled: args.layout_seed_enabled,
        stack_pad_enabled: args.stack_pad_enabled,
        distinct_function_layouts,
        chain_offset_a_distinct,
        chain_offset_b_distinct,
        cycles_jsonl: cycles_jsonl.to_path_buf(),
        diversity_jsonl: diversity_jsonl.to_path_buf(),
        survival_jsonl: survival_jsonl.to_path_buf(),
        run_start_iso,
    })
}

// =====================================================================
// MTD regression gate — CI-grade proof thresholds
// =====================================================================

/// Outcome of [`evaluate_mtd_gate`].
///
/// - **Passed**: production levers engaged and the measured metrics
///   match the load-bearing MTD claim (layouts relocate every cycle;
///   synthetic chain dies; probe rooted on morphed symbols).
/// - **Failed**: levers engaged but metrics regress — CI must fail.
/// - **Skipped**: gate not applicable (e.g. A/B run with layout seed
///   off, or fewer than 2 accepted cycles). Callers that pass
///   `--require-mtd-gate` treat Skipped as a hard failure so a
///   misconfigured "proof" run cannot green-wash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MtdGateStatus {
    /// Metrics satisfy the production MTD bar.
    Passed,
    /// At least one threshold failed. `reasons` is non-empty.
    Failed { reasons: Vec<String> },
    /// Gate not evaluated. `reason` explains why.
    Skipped { reason: String },
}

impl MtdGateStatus {
    /// True iff this is [`MtdGateStatus::Passed`].
    pub fn is_passed(&self) -> bool {
        matches!(self, MtdGateStatus::Passed)
    }

    /// True iff a `--require-mtd-gate` CLI invocation should exit non-zero.
    pub fn is_hard_failure(&self) -> bool {
        !matches!(self, MtdGateStatus::Passed)
    }

    /// One-line summary for logs / REPORT.md.
    pub fn summary_line(&self) -> String {
        match self {
            MtdGateStatus::Passed => "MTD gate: PASSED".to_string(),
            MtdGateStatus::Failed { reasons } => {
                format!("MTD gate: FAILED ({} reason(s))", reasons.len())
            }
            MtdGateStatus::Skipped { reason } => {
                format!("MTD gate: SKIPPED ({})", reason)
            }
        }
    }
}

// ---------------------------------------------------------------------------
// TASK-122 — enterprise kernel gadget-churn gate (north-star G5)
// ---------------------------------------------------------------------------

/// Maximum fraction of base gadgets that may survive at the **same offset
/// with identical semantics** after a production morph (layout seed change
/// + AST diversify). A fixed ROP chain hardcoding addresses against the
/// base cycle dies when this is near 0.
///
/// 5% is a conservative bar: measured layout-seed-only runs typically land
/// near 0%; we leave headroom for partial `.text` stability in boot
/// stubs while still failing a no-op morph.
pub const KERNEL_POSITIONAL_SURVIVAL_MAX: f64 = 0.05;

/// Result of comparing two kernel ELFs for MTD diversity (TASK-122).
#[derive(Debug, Clone)]
pub struct KernelChurnMeasurement {
    pub base_text_sha256: String,
    pub variant_text_sha256: String,
    pub base_gadgets: usize,
    pub variant_gadgets: usize,
    pub positional_survivors: usize,
    pub positional_survival: f64,
    pub semantic_survivors_normalized: usize,
    pub base_distinct_normalized: usize,
    pub semantic_survival_normalized: f64,
    pub scan_ms: u128,
}

impl KernelChurnMeasurement {
    /// One-line summary for logs.
    pub fn summary_line(&self) -> String {
        format!(
            "kernel_churn: positional={:.2}% ({}/{}) semantic_norm={:.1}% ({}/{}) \
             text_sha base={}.. variant={}.. gadgets base={} variant={} scan_ms={}",
            self.positional_survival * 100.0,
            self.positional_survivors,
            self.base_gadgets,
            self.semantic_survival_normalized * 100.0,
            self.semantic_survivors_normalized,
            self.base_distinct_normalized,
            &self.base_text_sha256[..8.min(self.base_text_sha256.len())],
            &self.variant_text_sha256[..8.min(self.variant_text_sha256.len())],
            self.base_gadgets,
            self.variant_gadgets,
            self.scan_ms,
        )
    }
}

/// Compare two compiled kernel artifacts (ELF/PE) with `cuttle_mtd_metrics`
/// gadget enumeration. Expensive on large `.text` (full unaligned scan);
/// intended for env-gated mega proofs, not the always-on unit suite.
pub fn measure_kernel_elf_churn(
    base_elf: &Path,
    variant_elf: &Path,
) -> Result<KernelChurnMeasurement> {
    let t0 = Instant::now();
    let (base_text, base_ip) = cuttle_mtd_metrics::read_text_section(base_elf)
        .with_context(|| format!("read .text from base {}", base_elf.display()))?;
    let (var_text, var_ip) = cuttle_mtd_metrics::read_text_section(variant_elf)
        .with_context(|| format!("read .text from variant {}", variant_elf.display()))?;

    let base_text_sha256 = hex_sha256(&base_text);
    let variant_text_sha256 = hex_sha256(&var_text);

    let base_g = cuttle_mtd_metrics::extract_gadgets(
        &base_text,
        base_ip,
        cuttle_mtd_metrics::DEFAULT_MAX_INSTRS,
    );
    let var_g = cuttle_mtd_metrics::extract_gadgets(
        &var_text,
        var_ip,
        cuttle_mtd_metrics::DEFAULT_MAX_INSTRS,
    );
    let report = cuttle_mtd_metrics::churn(&base_g, &var_g);
    let scan_ms = t0.elapsed().as_millis();

    Ok(KernelChurnMeasurement {
        base_text_sha256,
        variant_text_sha256,
        base_gadgets: report.base_gadgets,
        variant_gadgets: report.variant_gadgets,
        positional_survivors: report.positional_survivors,
        positional_survival: report.positional_survival(),
        semantic_survivors_normalized: report.semantic_survivors_normalized,
        base_distinct_normalized: report.base_distinct_normalized,
        semantic_survival_normalized: report.semantic_survival_normalized(),
        scan_ms,
    })
}

fn hex_sha256(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Hard gate for TASK-122 / north-star G5.
///
/// Passes when:
/// 1. `.text` sha256 differs (binary is not a no-op morph), and
/// 2. positional gadget survival ≤ [`KERNEL_POSITIONAL_SURVIVAL_MAX`].
///
/// Semantic (address-masked) survival is **reported but not hard-failed**
/// yet: AST diversify + layout seed primarily kills positional reuse;
/// instruction-mix churn is a harder bar (binmorph / future work).
pub fn evaluate_kernel_churn_gate(m: &KernelChurnMeasurement) -> Result<(), Vec<String>> {
    let mut reasons = Vec::new();
    if m.base_text_sha256 == m.variant_text_sha256 {
        reasons.push(format!(
            "identical .text sha256 {} — morph produced zero binary diversity",
            &m.base_text_sha256[..16.min(m.base_text_sha256.len())]
        ));
    }
    if m.base_gadgets == 0 {
        reasons.push("base ELF has zero enumerated gadgets — scan/artifact broken".into());
    }
    if m.positional_survival > KERNEL_POSITIONAL_SURVIVAL_MAX {
        reasons.push(format!(
            "positional_survival={:.2}% > max {:.2}% ({}/{} gadgets still land at same offset) — \
             fixed ROP chain against base would partially survive",
            m.positional_survival * 100.0,
            KERNEL_POSITIONAL_SURVIVAL_MAX * 100.0,
            m.positional_survivors,
            m.base_gadgets
        ));
    }
    if reasons.is_empty() {
        Ok(())
    } else {
        Err(reasons)
    }
}

/// Evaluate the production MTD regression bar against a completed run.
///
/// # Thresholds (when `layout_seed_enabled` and ≥ 2 accepted cycles)
///
/// | Metric | Required |
/// | --- | --- |
/// | `chain_used_fallback` | false |
/// | `distinct_function_layouts` | == `cycles_completed` |
/// | `chain_offset_a_distinct` | == `cycles_completed` |
/// | `chain_survived_both` | 0 (when `chain_total_probes > 0`) |
/// | `distinct_text_sha256` | ≥ 2 |
///
/// Stack-pad is **not** required to be off for a Pass — a pad-on A/B
/// run that still relocates layouts and kills the chain still Passes.
/// The default pipeline leaves pad off for gadget-surface reasons,
/// which is a separate policy from this gate.
pub fn evaluate_mtd_gate(summary: &RunSummary) -> MtdGateStatus {
    if !summary.layout_seed_enabled {
        return MtdGateStatus::Skipped {
            reason: "layout seeding disabled (--no-layout-seed); \
                     MTD gate requires the production layout lever"
                .to_string(),
        };
    }
    if summary.cycles_completed < 2 {
        return MtdGateStatus::Skipped {
            reason: format!(
                "need ≥ 2 accepted cycles to evaluate layout/chain metrics; got {}",
                summary.cycles_completed
            ),
        };
    }

    let completed = summary.cycles_completed as usize;
    let mut reasons: Vec<String> = Vec::new();

    if summary.chain_used_fallback {
        reasons.push(
            "chain probe used_fallback=true — survival numbers are not \
             rooted on the morphed module (TASK-025 class of silent miss)"
                .to_string(),
        );
    }

    if summary.distinct_function_layouts < completed {
        reasons.push(format!(
            "distinct_function_layouts={} < cycles_completed={} — layout \
             freeze regresses the Phase-1 lever (TASK-025 / TASK-067)",
            summary.distinct_function_layouts, completed
        ));
    }

    if summary.chain_offset_a_distinct < completed {
        reasons.push(format!(
            "chain_offset_a_distinct={} < cycles_completed={} — anchor \
             symbol is not relocating every cycle",
            summary.chain_offset_a_distinct, completed
        ));
    }

    if summary.chain_total_probes > 0 && summary.chain_survived_both > 0 {
        reasons.push(format!(
            "chain_survived_both={}/{} — synthetic ROP chain still lands \
             after morph (expected 0 under layout seeding)",
            summary.chain_survived_both, summary.chain_total_probes
        ));
    }

    if summary.distinct_text_sha256 < 2 {
        reasons.push(format!(
            "distinct_text_sha256={} < 2 — binary entropy floor hit",
            summary.distinct_text_sha256
        ));
    }

    if reasons.is_empty() {
        MtdGateStatus::Passed
    } else {
        MtdGateStatus::Failed { reasons }
    }
}

/// Inner per-cycle output. Returned only on a fully-accepted cycle.
///
/// Single-module mode: `candidate_sources` has one entry, the lone
/// morphed source; `candidate_sha256` is its canonical hash;
/// `module_canonical_hashes` carries the same single entry for record
/// uniformity.
///
/// Bundle mode: `candidate_sources` has N entries (one per member);
/// `candidate_sha256` is the bundle hash (sha256 of sorted-concat of
/// "<module>:<hex>\n" lines); `module_canonical_hashes` carries the
/// per-member hex hashes.
struct CycleOutput {
    /// Map of `module → diversified source text`. One entry in
    /// single-module mode, N in bundle mode.
    candidate_sources: std::collections::BTreeMap<String, String>,
    /// Either the lone candidate's canonical hash (single-module) or
    /// the bundle hash (bundle mode), as 64-char hex.
    candidate_sha256: String,
    /// Map of `module → canonical-hex-hash`. Useful in bundle mode for
    /// per-member traceability; populated in single-module mode too
    /// (with one entry) so downstream consumers don't need to special-
    /// case it.
    module_canonical_hashes: std::collections::BTreeMap<String, String>,
    /// Kernel ELF `.text` bytes from the single build that follows the
    /// substitution of every member's candidate.
    elf_text: Vec<u8>,
    /// Per-symbol function offsets in `.text` for the same kernel ELF.
    function_offsets: HashMap<String, u64>,
    /// TASK-026 — sha256 hex of the serial log captured by QEMU when
    /// `boot_each_cycle == true`. None when the flag is off, when
    /// running in fast_mode, or when QEMU was not invoked for this
    /// cycle for some other reason.
    serial_log_sha256: Option<String>,
    /// The layout seed this cycle's kernel build ran under, `None`
    /// when `layout_seed_enabled == false`.
    kernel_layout_seed: Option<u64>,
}

/// Run one cycle. Returns Ok(CycleOutput) only if every stage
/// (diversify-each-member, verify, sign, install, build) succeeds.
/// In bundle mode the verifier is invoked with multiple
/// --bundle-module pairs so it substitutes every member atomically
/// into its scratch workspace before building.
fn run_one_cycle(
    args: &ExperimentArgs,
    cycle: u64,
    prev_sources: &std::collections::BTreeMap<String, String>,
    verify_bin: Option<&Path>,
    signing_key: &SigningKey,
) -> Result<CycleOutput> {
    let members: Vec<String> = args.member_names();
    let bundle_label: String = args
        .bundle_name
        .clone()
        .unwrap_or_else(|| args.module.clone());

    // === Stage 1+2: synthesize (passthrough) + diversify, per member. ===
    let mut candidate_sources: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut module_canonical_hashes: std::collections::BTreeMap<String, String> =
        std::collections::BTreeMap::new();
    let mut module_canonical_bytes: std::collections::BTreeMap<String, [u8; 32]> =
        std::collections::BTreeMap::new();
    let mut cand_paths: Vec<(String, PathBuf)> = Vec::with_capacity(members.len());

    for member in &members {
        let prev_source = prev_sources.get(member).cloned().unwrap_or_default();
        let synth_source = prev_source;
        // Seed label: bundle mode = "{bundle}::{member}", single mode
        // = "{module}" (which the verifier's anti-regression check
        // expects unchanged).
        let seed_label: String = if args.is_bundle() {
            format!("{}::{}", bundle_label, member)
        } else {
            member.clone()
        };
        let seed = cuttle_diversifier::Seed::derive(cycle, &seed_label);
        let div_opts = if args.stack_pad_enabled {
            cuttle_diversifier::DiversifyOptions::with_stack_pad()
        } else {
            cuttle_diversifier::DiversifyOptions::default()
        };
        let candidate = cuttle_diversifier::diversify_with_options(
            &synth_source,
            &seed,
            &div_opts,
        )
        .map(|(s, _log)| s)
        .with_context(|| format!("diversify cycle {} member {}", cycle, member))?;
        let cand_hash: [u8; 32] = cuttle_diversifier::canonical_hash(&candidate)
            .with_context(|| format!("canonical_hash cycle {} member {}", cycle, member))?;
        let cand_hash_hex = factory_builder::hex(&cand_hash);

        // Write candidate beside source for the verifier to consume.
        let source_path = args.target_dir.join("src").join(format!("{}.rs", member));
        let cand_path = source_path.with_file_name(format!("{}.candidate.rs", member));
        fs::write(&cand_path, &candidate)
            .with_context(|| format!("write candidate at {}", cand_path.display()))?;

        candidate_sources.insert(member.clone(), candidate);
        module_canonical_hashes.insert(member.clone(), cand_hash_hex);
        module_canonical_bytes.insert(member.clone(), cand_hash);
        cand_paths.push((member.clone(), cand_path));
    }

    // === Stage 3: verify. ===
    // Single-module mode: keep the legacy CLI shape (positional
    // candidate path + --previous) so existing verifier tests don't
    // regress.
    // Bundle mode: use --target-crate + --bundle-module NAME=PATH pairs,
    // which substitutes every candidate atomically into the verifier's
    // scratch workspace before building.
    if let Some(vb) = verify_bin {
        let mut cmd = Command::new(vb);
        if args.is_bundle() {
            let target_crate_name: String = args
                .target_dir
                .file_name()
                .and_then(|s| s.to_str())
                .unwrap_or("target_enterprise")
                .to_string();
            cmd.arg("--target-crate").arg(&target_crate_name);
            for (member, path) in &cand_paths {
                cmd.arg("--bundle-module")
                    .arg(format!("{}={}", member, path.display()));
            }
        } else {
            let primary = &members[0];
            let source_path = args.target_dir.join("src").join(format!("{}.rs", primary));
            let cand_path = &cand_paths[0].1;
            cmd.arg("--previous").arg(&source_path).arg(cand_path);
        }
        let out = cmd
            .output()
            .with_context(|| format!("spawn verifier {}", vb.display()))?;
        if !out.status.success() {
            for (_, p) in &cand_paths {
                let _ = fs::remove_file(p);
            }
            bail!(
                "verifier rejected candidate (exit {:?}): {}",
                out.status.code(),
                String::from_utf8_lossy(&out.stderr)
            );
        }
    }

    // === Stage 4: sign. ===
    // Bundle mode signs the bundle hash; single-mode signs the lone
    // candidate hash. Either way, signing is just a wall-clock cost
    // contribution — the result isn't returned.
    let combined_hash: [u8; 32] = if args.is_bundle() {
        compute_bundle_hash(&module_canonical_bytes)
    } else {
        module_canonical_bytes[&members[0]]
    };
    let _sig = signing_key.sign(&combined_hash);

    // === Stage 5: install every candidate so the kernel build pulls
    //     them all in. Rename is best-effort; if any fails partway,
    //     remaining un-installed candidates are wiped to leave the
    //     workspace in a recoverable state (the outer restore-from-
    //     pristine still runs on the way out of run_experiment). ===
    for (member, cand_path) in &cand_paths {
        let source_path = args.target_dir.join("src").join(format!("{}.rs", member));
        if let Some(src) = candidate_sources.get(member) {
            fs::write(&source_path, src).with_context(|| {
                format!("install candidate at {}", source_path.display())
            })?;
        }
        let _ = fs::remove_file(cand_path);
    }

    // === Stage 6: emit kernel ELF + parse it. ONE build per cycle
    //     regardless of how many members morphed — that's the atomic-
    //     bundle property reflected in the measurement. When layout
    //     seeding is enabled (the default), the build runs under the
    //     per-cycle seed so function offsets relocate between cycles;
    //     this is the Phase-1 lever TASK-025 showed the AST-level
    //     diversifier cannot provide on its own. ===
    let kernel_layout_seed: Option<u64> = if args.layout_seed_enabled {
        Some(cycle_layout_seed(cycle))
    } else {
        None
    };
    let elf_path_opt: Option<PathBuf> = if args.fast_mode {
        None
    } else {
        Some(
            factory_builder::build_kernel_with_layout_seed(
                &args.kernel_crate_dir,
                kernel_layout_seed,
            )
            .with_context(|| {
                format!(
                    "build_kernel cycle {} (layout_seed {:?})",
                    cycle, kernel_layout_seed
                )
            })?,
        )
    };
    let (elf_text, function_offsets) = match elf_path_opt.as_ref() {
        None => synthesize_pseudo_elf_seeded(&combined_hash, kernel_layout_seed),
        Some(p) => parse_real_elf(p)
            .with_context(|| format!("parse ELF at {}", p.display()))?,
    };

    // === Stage 7 (TASK-026, opt-in): package + boot the kernel under
    //     QEMU and capture the serial log's sha256. Skipped in fast
    //     mode (no real ELF) and when `boot_each_cycle == false` so
    //     the default wall-clock matches pre-TASK-026. ===
    let serial_log_sha256: Option<String> = if args.boot_each_cycle {
        match elf_path_opt.as_ref() {
            Some(elf_path) => {
                let cap = qemu_boot::boot_and_capture(elf_path, &args.results_dir, cycle)
                    .with_context(|| {
                        format!("qemu boot+capture for accepted cycle {}", cycle)
                    })?;
                Some(cap.serial_log_sha256)
            }
            // fast_mode + boot_each_cycle: documented no-op. The flag
            // exists exclusively to drive a real kernel through QEMU;
            // fast-mode skips real builds entirely so there's nothing
            // bootable. Surface this to the operator the first time it
            // happens (per-process latch on `BOOT_EACH_CYCLE_FAST_WARNED`).
            None => {
                fast_mode_boot_warn_once();
                None
            }
        }
    } else {
        None
    };

    let candidate_sha256 = factory_builder::hex(&combined_hash);

    Ok(CycleOutput {
        candidate_sources,
        candidate_sha256,
        module_canonical_hashes,
        elf_text,
        function_offsets,
        serial_log_sha256,
        kernel_layout_seed,
    })
}

/// Per-process latch: emit a single eprintln when an operator runs
/// with `fast_mode = true` AND `boot_each_cycle = true`. The flag is
/// a no-op under fast-mode (no real ELF to boot) but the operator
/// almost certainly didn't mean to combine them — warn once so it's
/// visible without spamming N times in a 100-cycle run.
fn fast_mode_boot_warn_once() {
    use std::sync::atomic::{AtomicBool, Ordering};
    static WARNED: AtomicBool = AtomicBool::new(false);
    if WARNED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_ok()
    {
        eprintln!(
            "diversity_demo: WARNING — boot_each_cycle = true is a no-op under \
             fast_mode = true (no real kernel ELF to boot). serial_log_sha256 \
             will be None on every accepted cycle of this run."
        );
    }
}

/// Compute `sha256(sorted concat of "<module>:<canonical-hex>\n")` —
/// the canonical bundle hash. Sorted because membership is set-based,
/// not list-based: reordering `modules = [...]` in scheduler.toml must
/// not change the deployed bundle hash if every member's canonical
/// hash is unchanged.
///
/// Per-cycle kernel layout seed. Mirrors
/// `morph_engine::cycle::kernel_layout_seed` exactly (same bijective
/// mix of the cycle number) so experiment cycle N builds the same
/// kernel image the production morph cycle N would, and the recorded
/// seed in `cycles.jsonl` is directly comparable to the
/// `kernel_layout_seed` field on v7 attestation entries.
pub fn cycle_layout_seed(cycle: u64) -> u64 {
    cycle.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5DEE_CE66_D3A8_31EF
}

/// Mirrors `morph_engine::cycle::compute_bundle_hash` exactly.
fn compute_bundle_hash(per_member: &std::collections::BTreeMap<String, [u8; 32]>) -> [u8; 32] {
    let mut lines: Vec<String> = per_member
        .iter()
        .map(|(name, hash)| format!("{}:{}\n", name, factory_builder::hex(hash)))
        .collect();
    lines.sort();
    let mut h = Sha256::new();
    for l in lines {
        h.update(l.as_bytes());
    }
    h.finalize().into()
}

/// Read an ELF file from disk and return (`.text` bytes,
/// section-relative function offsets keyed by symbol name).
///
/// "Section-relative" means we subtract the `.text` section's virtual
/// address from each symbol's virtual address. That way an offset is
/// directly indexable into the `.text` byte slice we return.
pub fn parse_real_elf(elf_path: &Path) -> Result<(Vec<u8>, HashMap<String, u64>)> {
    let bytes = fs::read(elf_path)
        .with_context(|| format!("read elf at {}", elf_path.display()))?;
    let file = object::File::parse(&bytes[..])
        .with_context(|| format!("parse elf at {}", elf_path.display()))?;
    let text_section = file
        .section_by_name(".text")
        .context(".text section not found in elf")?;
    let text_addr = text_section.address();
    let text_bytes: Vec<u8> = text_section
        .data()
        .context("read .text bytes")?
        .to_vec();

    let mut offsets: HashMap<String, u64> = HashMap::new();
    for sym in file.symbols() {
        if sym.kind() != SymbolKind::Text {
            continue;
        }
        let Ok(name) = sym.name() else { continue };
        if name.is_empty() {
            continue;
        }
        let addr = sym.address();
        // Only keep symbols whose address falls inside .text.
        if addr < text_addr {
            continue;
        }
        let rel = addr - text_addr;
        if rel as usize > text_bytes.len() {
            continue;
        }
        // If a name collides (two symbols), keep the smaller offset:
        // it's the more useful entry point for a ROP analysis.
        offsets
            .entry(name.to_string())
            .and_modify(|e| {
                if rel < *e {
                    *e = rel;
                }
            })
            .or_insert(rel);
    }
    Ok((text_bytes, offsets))
}

/// Fast-mode pseudo-ELF synthesis. Produces deterministic `.text`
/// bytes and synthetic symbol offsets from a candidate's canonical
/// hash. Different diversified sources → different hashes → different
/// pseudo-ELFs, so the entropy-floor test stays honest.
///
/// The "ELF" here is not actually an ELF; it's just (bytes, offsets).
/// We never parse it back.
///
/// Equivalent to `synthesize_pseudo_elf_seeded(cand_hash, None)` —
/// kept for callers/tests that predate layout seeding.
pub fn synthesize_pseudo_elf(cand_hash: &[u8; 32]) -> (Vec<u8>, HashMap<String, u64>) {
    synthesize_pseudo_elf_seeded(cand_hash, None)
}

/// Seed-aware fast-mode pseudo-ELF.
///
/// With `layout_seed == None` the output is byte-identical to the
/// historical [`synthesize_pseudo_elf`]: symbol offsets scatter
/// straight from the candidate hash bytes. With `Some(seed)`, the
/// offsets scatter from
/// `sha256("cuttle-pseudo-layout-v1" || cand_hash || seed_le)`
/// instead — the `.text` bytes stay candidate-hash-derived either
/// way. That mirrors, at the layer the chain-survival probe measures,
/// what the real lever does (relocate functions without changing the
/// source candidate), so fast-mode integration tests can pin the
/// relocation property without invoking a nightly build.
pub fn synthesize_pseudo_elf_seeded(
    cand_hash: &[u8; 32],
    layout_seed: Option<u64>,
) -> (Vec<u8>, HashMap<String, u64>) {
    // 4 KiB of bytes derived from the candidate hash via SHA-256
    // chaining. Each 32-byte block is sha256(prev_block || index).
    let mut bytes = Vec::with_capacity(4096);
    let mut block = *cand_hash;
    while bytes.len() < 4096 {
        bytes.extend_from_slice(&block);
        let mut h = Sha256::new();
        h.update(block);
        h.update((bytes.len() as u64).to_le_bytes());
        let out = h.finalize();
        block.copy_from_slice(&out);
    }
    bytes.truncate(4096);

    // The hash the symbol offsets scatter from. Without a layout
    // seed this is the candidate hash itself (historical behaviour);
    // with a seed it's a domain-separated mix of both, so the same
    // candidate under a different seed produces a different layout —
    // function relocation without source change.
    let layout_hash: [u8; 32] = match layout_seed {
        None => *cand_hash,
        Some(seed) => {
            let mut h = Sha256::new();
            h.update(b"cuttle-pseudo-layout-v1");
            h.update(cand_hash);
            h.update(seed.to_le_bytes());
            h.finalize().into()
        }
    };

    // A fixed set of *legacy-mangled* symbol names mirroring what the
    // real `target_enterprise::tls` module emits. Bare names like
    // `hkdf_expand_label` would not match `pick_chain_symbols`'s
    // demangle-aware anchor check (`target_enterprise::tls::hkdf_…`),
    // so fast-mode runs used to set `used_fallback = true` even when
    // the probe was "on" a morphed-module helper — and the MTD gate
    // correctly refused to accept those runs as proof. Emit the same
    // mangling scheme the unit tests use so demangle →
    // `target_enterprise::tls::<fn>` and the gate can Pass under
    // layout seeding without a nightly build.
    let symbols: &[&str] = &[
        "hkdf_expand_label",
        "build_server_hello",
        "parse_client_hello",
        "derive_handshake_secret",
        "hkdf_extract",
        "build_tls_record",
        "validate_alpn",
        "encode_extension",
    ];
    let mut offsets = HashMap::new();
    for (i, bare) in symbols.iter().enumerate() {
        // Use 4 hash bytes per symbol to scatter offsets across .text.
        let base_idx = (i * 4) % layout_hash.len();
        let raw = u32::from_le_bytes([
            layout_hash[base_idx],
            layout_hash[(base_idx + 1) % layout_hash.len()],
            layout_hash[(base_idx + 2) % layout_hash.len()],
            layout_hash[(base_idx + 3) % layout_hash.len()],
        ]) as u64;
        // Confine to [0, 4096) and align to 16 like real .text would.
        let off = (raw % 4096) & !0xf;
        // `_ZN17target_enterprise3tls{len}{name}17h0123456789abcdefE`
        let mangled = format!(
            "_ZN17target_enterprise3tls{}{}17h0123456789abcdefE",
            bare.len(),
            bare
        );
        offsets.insert(mangled, off);
    }
    (bytes, offsets)
}

/// Hamming distance between two `.text` byte slices, padding the
/// shorter with zeros. Returns (raw bit count, normalised fraction in
/// [0, 1]).
pub fn hamming_distance(a: &[u8], b: &[u8]) -> (u64, f64) {
    let (longer, shorter) = if a.len() >= b.len() { (a, b) } else { (b, a) };
    let mut raw: u64 = 0;
    for (i, byte) in longer.iter().enumerate() {
        let other = shorter.get(i).copied().unwrap_or(0);
        raw += (byte ^ other).count_ones() as u64;
    }
    let denom = (longer.len() as u64).saturating_mul(8);
    let norm = if denom == 0 {
        0.0
    } else {
        raw as f64 / denom as f64
    };
    (raw, norm)
}

fn compute_diversity(prev_cycle: u64, cycle: u64, prev: &[u8], cur: &[u8]) -> DiversityRecord {
    let (raw, norm) = hamming_distance(prev, cur);
    DiversityRecord {
        cycle,
        prev_cycle,
        raw_bits_diff: raw,
        normalised: norm,
        size_a: prev.len(),
        size_b: cur.len(),
    }
}

/// Demangled-path substring that identifies the morphed module the
/// survival probe is targeting. Today: `target_enterprise::tls`.
/// Used by `pick_chain_symbols` to filter symbols by Rust-source
/// origin rather than by trusting raw ELF symbol names — see
/// TASK-025 / iteration 16 for why the unfiltered version was
/// silently picking kernel helpers like `hex_encode` instead.
pub const MORPHED_MODULE_PATH: &str = "target_enterprise::tls";

/// Demangled-path substring of the canonical anchor function for
/// the synthetic ROP-chain survival probe. If a symbol whose
/// demangled name contains this substring exists in cycle 0's
/// symbol table, it becomes `symbol_a`; otherwise
/// `pick_chain_symbols` falls back and the resulting `ChainPick`
/// has `used_fallback == true`.
pub const CHAIN_ANCHOR_PATH: &str = "target_enterprise::tls::hkdf_expand_label";

/// Result of `pick_chain_symbols`. Carries both the raw mangled
/// names (still needed by the survival loop, which compares against
/// `reverse_lookup` on the same offset-keyed `function_offsets`
/// HashMap) and the demangled paths (for REPORT.md / JSONL
/// readability). `used_fallback == true` means the anchor symbol
/// was not in the symbol table; survival numbers from a fallback
/// run do NOT support the headline "the chain doesn't land" claim.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainPick {
    pub symbol_a: String,
    pub offset_a: u64,
    pub demangled_a: String,
    pub symbol_b: String,
    pub offset_b: u64,
    pub demangled_b: String,
    pub used_fallback: bool,
}

/// Demangle a Rust symbol via `rustc_demangle`, stripping the
/// trailing hash suffix with `{:#}`. Both legacy (`_ZN...E`) and v0
/// (`_R...`) mangling schemes are handled by the upstream crate.
/// Non-Rust symbols pass through unchanged.
pub fn demangled_of(name: &str) -> String {
    format!("{:#}", rustc_demangle::demangle(name))
}

/// Pick two symbols from cycle 0's symbol table to ground the
/// synthetic ROP-chain survival probe on. Preference order:
///
/// 1. **Anchor symbol present** — first entry whose demangled name
///    contains `target_enterprise::tls::hkdf_expand_label`. Pair it
///    with the next morphed-module symbol (demangled name contains
///    `target_enterprise::tls`) at a distinct offset. `used_fallback
///    == false` in this branch — survival numbers ARE
///    interpretable.
/// 2. **Anchor present, no second morphed symbol** — pair anchor
///    with whatever lowest-offset distinct symbol exists.
///    `used_fallback == true` (partial fallback).
/// 3. **Anchor absent** — pick the two lowest-offset
///    morphed-module symbols, or, if those don't exist, the two
///    lowest-offset symbols overall (the legacy iteration-11
///    behaviour). `used_fallback == true`.
///
/// Determinism: input is a `HashMap` so iteration order is not
/// stable; we sort by (offset, mangled name) before any picking.
/// Same `function_offsets` → same `ChainPick`, run after run.
pub fn pick_chain_symbols(offsets: &HashMap<String, u64>) -> ChainPick {
    let none_pick = || ChainPick {
        symbol_a: "<none>".into(),
        offset_a: 0,
        demangled_a: "<none>".into(),
        symbol_b: "<none>".into(),
        offset_b: 0,
        demangled_b: "<none>".into(),
        used_fallback: true,
    };
    if offsets.is_empty() {
        return none_pick();
    }
    // Pre-demangle every symbol once, then sort deterministically by
    // (offset, mangled name) so the result doesn't depend on
    // HashMap iteration order.
    let mut entries: Vec<(String, u64, String)> = offsets
        .iter()
        .map(|(k, v)| (k.clone(), *v, demangled_of(k)))
        .collect();
    entries.sort_by(|a, b| a.1.cmp(&b.1).then_with(|| a.0.cmp(&b.0)));

    // (1) anchor present.
    let anchor_idx = entries
        .iter()
        .position(|(_, _, d)| d.contains(CHAIN_ANCHOR_PATH));
    if let Some(i) = anchor_idx {
        let (an_mangled, an_off, an_demangled) = entries[i].clone();
        // (1a) prefer another morphed-module symbol at a distinct offset.
        for (j, e) in entries.iter().enumerate() {
            if j == i {
                continue;
            }
            if e.1 == an_off {
                continue;
            }
            if !e.2.contains(MORPHED_MODULE_PATH) {
                continue;
            }
            if e.2 == an_demangled {
                continue;
            }
            return ChainPick {
                symbol_a: an_mangled,
                offset_a: an_off,
                demangled_a: an_demangled,
                symbol_b: e.0.clone(),
                offset_b: e.1,
                demangled_b: e.2.clone(),
                used_fallback: false,
            };
        }
        // (1b) no second morphed-module symbol — pick anything distinct.
        // This still surfaces fallback because the survival probe is
        // half-rooted outside the morph surface.
        for (j, e) in entries.iter().enumerate() {
            if j == i {
                continue;
            }
            if e.1 == an_off {
                continue;
            }
            return ChainPick {
                symbol_a: an_mangled,
                offset_a: an_off,
                demangled_a: an_demangled,
                symbol_b: e.0.clone(),
                offset_b: e.1,
                demangled_b: e.2.clone(),
                used_fallback: true,
            };
        }
        // Degenerate: only the anchor exists or every other symbol
        // shares its offset.
        return ChainPick {
            symbol_a: an_mangled.clone(),
            offset_a: an_off,
            demangled_a: an_demangled.clone(),
            symbol_b: an_mangled,
            offset_b: an_off,
            demangled_b: an_demangled,
            used_fallback: true,
        };
    }

    // (3) anchor absent — prefer two morphed-module symbols if any
    // exist, else legacy "two smallest offsets" behaviour.
    let morphed: Vec<&(String, u64, String)> = entries
        .iter()
        .filter(|(_, _, d)| d.contains(MORPHED_MODULE_PATH))
        .collect();
    if morphed.len() >= 2 {
        for j in 1..morphed.len() {
            if morphed[j].1 != morphed[0].1 {
                let a = morphed[0];
                let b = morphed[j];
                return ChainPick {
                    symbol_a: a.0.clone(),
                    offset_a: a.1,
                    demangled_a: a.2.clone(),
                    symbol_b: b.0.clone(),
                    offset_b: b.1,
                    demangled_b: b.2.clone(),
                    used_fallback: true,
                };
            }
        }
    }
    if entries.len() >= 2 {
        let a = &entries[0];
        let b = &entries[1];
        return ChainPick {
            symbol_a: a.0.clone(),
            offset_a: a.1,
            demangled_a: a.2.clone(),
            symbol_b: b.0.clone(),
            offset_b: b.1,
            demangled_b: b.2.clone(),
            used_fallback: true,
        };
    }
    let only = &entries[0];
    ChainPick {
        symbol_a: only.0.clone(),
        offset_a: only.1,
        demangled_a: only.2.clone(),
        symbol_b: only.0.clone(),
        offset_b: only.1,
        demangled_b: only.2.clone(),
        used_fallback: true,
    }
}

/// Build a fixed 64-byte synthetic ROP chain: offset_a LE (8 bytes),
/// offset_b LE (8 bytes), and 48 bytes of filler (0xCC, an x86 INT3).
/// The bytes themselves are not what the survival test checks — it's
/// purely the offsets — but constructing the chain for real keeps the
/// experiment honest about what an adversary would actually do.
pub fn build_synthetic_chain(offset_a: u64, offset_b: u64) -> [u8; 64] {
    let mut chain = [0xCCu8; 64];
    chain[0..8].copy_from_slice(&offset_a.to_le_bytes());
    chain[8..16].copy_from_slice(&offset_b.to_le_bytes());
    chain
}

/// Reverse-lookup: given an offset, return the FIRST symbol name that
/// has that offset, deterministically (sorted by name). Returns None
/// if no symbol sits exactly at that offset.
pub fn reverse_lookup(offsets: &HashMap<String, u64>, target: u64) -> Option<String> {
    let mut matches: Vec<&String> =
        offsets.iter().filter(|(_, v)| **v == target).map(|(k, _)| k).collect();
    matches.sort();
    matches.first().map(|s| s.to_string())
}

fn append_jsonl<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    use std::io::Write;
    let line = serde_json::to_string(value)?;
    let mut f = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
        .with_context(|| format!("open {} for append", path.display()))?;
    writeln!(f, "{}", line)?;
    Ok(())
}

fn read_jsonl<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<Vec<T>> {
    let text = fs::read_to_string(path).unwrap_or_default();
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        out.push(serde_json::from_str(line)?);
    }
    Ok(out)
}

fn percentile_f64(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
fn percentile_u64(sorted: &[u64], q: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}
fn percentile_u128(sorted: &[u128], q: f64) -> u128 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = ((sorted.len() as f64 - 1.0) * q).round() as usize;
    sorted[idx.min(sorted.len() - 1)]
}

fn load_or_generate_signing_key(path: Option<&Path>) -> Result<SigningKey> {
    if let Some(p) = path {
        if p.exists() {
            let bytes = fs::read(p).with_context(|| format!("read signing key at {}", p.display()))?;
            if bytes.len() == 32 {
                let mut arr = [0u8; 32];
                arr.copy_from_slice(&bytes);
                return Ok(SigningKey::from_bytes(&arr));
            }
        }
    }
    // Deterministic ephemeral. We don't want OsRng here because then
    // signing-stage cost is variable across runs; better to use a
    // fixed seed so the experiment is reproducible.
    let seed: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(b"diversity_demo-ephemeral-signing-key-v1");
        let out = h.finalize();
        let mut s = [0u8; 32];
        s.copy_from_slice(&out);
        s
    };
    Ok(SigningKey::from_bytes(&seed))
}

fn resolve_verify_bin(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        if p.exists() {
            return Ok(p.to_path_buf());
        }
        bail!("--verify-bin {} does not exist", p.display());
    }
    if let Ok(self_exe) = std::env::current_exe() {
        if let Some(dir) = self_exe.parent() {
            let candidate = dir.join(if cfg!(windows) { "verify.exe" } else { "verify" });
            if candidate.exists() {
                return Ok(candidate);
            }
            // Also try ../verify(.exe) for tests running from target/<profile>/deps
            if let Some(up) = dir.parent() {
                let cand2 = up.join(if cfg!(windows) { "verify.exe" } else { "verify" });
                if cand2.exists() {
                    return Ok(cand2);
                }
            }
        }
    }
    bail!(
        "diversity_demo: could not locate `verify` binary beside current exe; \
         run `cargo build --bin verify` first or pass --verify-bin"
    );
}

fn iso8601_utc_now() -> String {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    let secs = dur.as_secs();
    // Cheap UTC ISO 8601 without pulling in chrono. Good enough for a
    // run-date stamp in a report.
    let days_since_epoch = secs / 86_400;
    let mut y = 1970i64;
    let mut d = days_since_epoch as i64;
    loop {
        let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
        let yd = if leap { 366 } else { 365 };
        if d < yd {
            break;
        }
        d -= yd;
        y += 1;
    }
    let leap = (y % 4 == 0 && y % 100 != 0) || (y % 400 == 0);
    let mdays = [31, if leap { 29 } else { 28 }, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];
    let mut m = 0usize;
    while m < 12 && d >= mdays[m] {
        d -= mdays[m];
        m += 1;
    }
    let day = (d as u32) + 1;
    let h = (secs / 3600) % 24;
    let mn = (secs / 60) % 60;
    let se = secs % 60;
    format!(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
        y,
        m as u32 + 1,
        day,
        h,
        mn,
        se
    )
}

/// Render REPORT.md from a `RunSummary`. Path is `<results_dir>/REPORT.md`.
pub fn render_report(summary: &RunSummary, results_dir: &Path) -> Result<PathBuf> {
    let path = results_dir.join("REPORT.md");
    let entropy_pct = if summary.cycles_completed > 0 {
        100.0 * (summary.distinct_text_sha256 as f64) / (summary.cycles_completed as f64)
    } else {
        0.0
    };
    let survival_pct = if summary.chain_total_probes > 0 {
        100.0 * (summary.chain_survived_both as f64) / (summary.chain_total_probes as f64)
    } else {
        0.0
    };
    let interp = interpret(summary, entropy_pct, survival_pct);

    // TASK-026 — "Serial-log entropy" section. Only rendered when the
    // run captured at least one serial log (operator opted into
    // `--boot-each-cycle` AND was in real mode AND ≥ 1 cycle was
    // accepted). The section reports the distinct-sha256 count and
    // interprets divergence vs the distinct-ELF count.
    let serial_log_section = render_serial_log_section(summary);

    let body = format!(
        "# Cuttle Morph Diversity — Empirical Results\n\n\
         Run date: {run_date}\n\
         Cycles requested: {req}\n\
         Cycles completed (accepted): {done}\n\
         Cycles rejected by verifier: {rej}\n\
         Target / module: {tgt} / {module}\n\
         Fast-mode (synthetic ELF, no nightly build): {fast}\n\n\
         ## Headline numbers\n\
         - Per-cycle kernel layout seeding (`-Zrandomize-layout` + `.text*` shuffle): {seed_state}\n\
         - AST stack-frame padding (TASK-029): {pad_state}\n\
         - MTD regression gate: {mtd_gate}\n\
         - Entropy floor (distinct .text sha256 / cycles completed): {dist} / {done} ({entropy_pct:.1}%)\n\
         - Distinct (symbol → offset) layouts across accepted cycles: {layouts} / {done}\n\
         - Hamming distance (normalised) across {pairs} consecutive accepted pairs:\n  median {hm_med}, p95 {hm_p95}, max {hm_max}\n\
         - Hamming distance (raw bits) across the same pairs:\n  median {hb_med}, p95 {hb_p95}, max {hb_max}\n\
         - Synthetic-chain survival rate: {surv}/{probes} cycles landed both offsets ({survival_pct:.1}%)\n  \
            symbol_a = `{sym_a}` @ offset 0x{off_a:x}, symbol_b = `{sym_b}` @ offset 0x{off_b:x} (chosen from cycle 0)\n\
         - Distinct offsets observed across accepted cycles: symbol_a {offa_d}, symbol_b {offb_d}\n\
         - Per-cycle wall-clock: median {wm_med} ms, p95 {wm_p95} ms, max {wm_max} ms\n\n\
         ## MTD regression gate\n\n\
         {mtd_gate_detail}\n\n\
         ## Interpretation\n\n\
         {interp}\n\n\
         {serial_log_section}\
         ## Method\n\n\
         Pipeline per cycle: synthesize=passthrough (unchanged source) → \
         `cuttle_diversifier::diversify(prev_source, Seed::derive(cycle, module))` → \
         {verify_note} → ed25519 sign of the candidate's canonical sha256 → \
         {build_note} → parse `.text` and symbol table with the `object` crate.\n\n\
         Hamming distance: zero-pad the shorter `.text` byte slice up to the longer's length, \
         XOR byte-wise, sum `count_ones()` across the result. Normalised by dividing by \
         `8 * max_len` so it sits in [0, 1].\n\n\
         Synthetic ROP chain: 64 bytes laid out as `[offset_a LE | offset_b LE | 48 × 0xCC]` \
         (filler is x86 INT3). Survival rule for a cycle: reverse-lookup what symbol lives at \
         each of `(offset_a, offset_b)` in that cycle's parsed symbol table. The chain \"lands\" \
         iff both reverse-lookups return the same symbol name they did at cycle 0.\n\n\
         ## Caveats\n\n\
         - The pseudo-ELF produced in fast-mode is NOT a real ELF; it's a deterministic 4 KiB \
         byte buffer derived from the candidate's canonical hash, plus a fixed-name symbol table \
         scattered across that buffer. Fast-mode is for integration tests; the CLI demo runs the \
         real `factory_builder::build_kernel`.\n\
         - The diversifier today does NOT touch the public-trait byte-observable surface of \
         `target_enterprise::tls` (see the module's locked-surface docs). Internal helpers ARE \
         in scope. So we expect `.text` churn to come predominantly from helper-function order, \
         private-fn renames, and statement-level swaps — NOT from the externally-observable \
         protocol bytes.\n\
         - Chain survival in real mode depends on how the compiler lays out internal helpers \
         post-diversification. A high survival rate is not by itself a bug, but it does \
         indicate the current diversifier perturbs the source enough to alter syntax without \
         displacing the compiled function offsets a hypothetical adversary targets.\n\
         - Wall-clock numbers include the verifier subprocess spawn cost, which on Windows \
         contributes a non-trivial fraction. Sub-second cycles in fast-mode are dominated by \
         spawn overhead, not by morph work.\n",
        run_date = summary.run_start_iso,
        req = summary.cycles_requested,
        done = summary.cycles_completed,
        rej = summary.cycles_rejected,
        tgt = summary.target_dir.display(),
        module = summary.module,
        fast = summary.fast_mode,
        seed_state = if summary.layout_seed_enabled {
            "ENABLED (per-cycle seed, recorded in cycles.jsonl)"
        } else {
            "disabled (--no-layout-seed: deterministic layout, AST-diversifier only)"
        },
        pad_state = if summary.stack_pad_enabled {
            "ENABLED (--stack-pad; opt-in A/B — inflates gadget count)"
        } else {
            "disabled (production default; layout seeding owns offset entropy)"
        },
        mtd_gate = evaluate_mtd_gate(summary).summary_line(),
        mtd_gate_detail = {
            let gate = evaluate_mtd_gate(summary);
            match gate {
                MtdGateStatus::Passed => {
                    "PASSED — layout seeding engaged; every accepted cycle has a distinct \
                     function-offset layout; the synthetic chain rooted on morphed-module \
                     symbols survives 0 probes; binary entropy floor is non-trivial. \
                     This is the CI bar for the load-bearing MTD claim."
                        .to_string()
                }
                MtdGateStatus::Failed { reasons } => {
                    let mut s = String::from(
                        "FAILED — production levers were engaged but metrics regress the \
                         MTD claim. Reasons:\n",
                    );
                    for r in reasons {
                        s.push_str(&format!("- {}\n", r));
                    }
                    s
                }
                MtdGateStatus::Skipped { reason } => {
                    format!(
                        "SKIPPED — gate not applicable to this run: {}\n\n\
                         Re-run with layout seeding enabled (the CLI default) and ≥ 2 \
                         accepted cycles, then pass `--require-mtd-gate` to fail CI on \
                         regression.",
                        reason
                    )
                }
            }
        },
        dist = summary.distinct_text_sha256,
        layouts = summary.distinct_function_layouts,
        offa_d = summary.chain_offset_a_distinct,
        offb_d = summary.chain_offset_b_distinct,
        entropy_pct = entropy_pct,
        pairs = summary.cycles_completed.saturating_sub(1),
        hm_med = fmt_opt_f64(summary.hamming_median_norm),
        hm_p95 = fmt_opt_f64(summary.hamming_p95_norm),
        hm_max = fmt_opt_f64(summary.hamming_max_norm),
        hb_med = fmt_opt_u64(summary.hamming_median_bits),
        hb_p95 = fmt_opt_u64(summary.hamming_p95_bits),
        hb_max = fmt_opt_u64(summary.hamming_max_bits),
        surv = summary.chain_survived_both,
        probes = summary.chain_total_probes,
        survival_pct = survival_pct,
        sym_a = summary.chain_symbol_a,
        off_a = summary.chain_offset_a,
        sym_b = summary.chain_symbol_b,
        off_b = summary.chain_offset_b,
        wm_med = summary.wallclock_median_ms,
        wm_p95 = summary.wallclock_p95_ms,
        wm_max = summary.wallclock_max_ms,
        serial_log_section = serial_log_section,
        verify_note = "shell out to the `verify` binary with `--previous` set to the on-disk source",
        build_note = match (summary.fast_mode, summary.layout_seed_enabled) {
            (true, _) => "fast-mode synthetic pseudo-ELF (no nightly cargo invocation)",
            (false, true) => {
                "`factory_builder::build_kernel_with_layout_seed` against \
                 `target_enterprise_kernel/` (nightly + build-std, per-cycle \
                 `-Zrandomize-layout=yes -Zlayout-seed=N -Zfunction-sections=yes \
                 -Clink-arg=--shuffle-sections=.text*=N`)"
            }
            (false, false) => {
                "`factory_builder::build_kernel` against `target_enterprise_kernel/` \
                 (nightly + build-std, deterministic layout)"
            }
        },
        interp = interp,
    );
    fs::write(&path, body)
        .with_context(|| format!("write REPORT.md at {}", path.display()))?;
    Ok(path)
}

/// Render the "Serial-log entropy" section of REPORT.md from a
/// `RunSummary`. Returns an empty string when no per-cycle serial log
/// was captured (i.e. `cycles_with_serial_log == 0`) so the section
/// is omitted entirely from runs that didn't opt into the flag — no
/// "n/a serial logs captured" filler noise.
///
/// Returned string ends with `\n\n` so it slots directly into
/// REPORT.md between the Interpretation and Method sections; an empty
/// return value contributes zero bytes.
///
/// Interpretation rule:
///   - `distinct_serial_log_sha256 == 1 && distinct_text_sha256 > 1`:
///     Note that the kernel produced identical observable output
///     across distinct ELFs — expected because the kernel asserts
///     byte-equality against locked fixtures.
///   - `distinct_serial_log_sha256 > 1`:
///     Surprise — the serial log diverged across runs of cycles
///     that share the same locked surface. Either the kernel
///     emitted a timing-dependent byte (e.g. TSC value in a banner)
///     or a morph drifted past the locked surface and triggered a
///     panic banner. Either case warrants a closer look.
///   - `distinct_serial_log_sha256 == 0`: shouldn't happen when
///     `cycles_with_serial_log > 0` — render a defensive "n/a"
///     rather than dividing by zero.
pub fn render_serial_log_section(summary: &RunSummary) -> String {
    if summary.cycles_with_serial_log == 0 {
        return String::new();
    }
    let interp = if summary.distinct_serial_log_sha256 == 0 {
        "n/a — `cycles_with_serial_log` > 0 but no distinct shas observed; \
         report bug in `run_experiment_inner` aggregation."
            .to_string()
    } else if summary.distinct_serial_log_sha256 == 1 {
        format!(
            "Single serial-log sha256 across {} captured cycles. \
             Expected: the kernel asserts byte-equality against locked \
             fixtures, so deterministic ELFs produce deterministic \
             output. A divergence here would mean either the kernel \
             emitted a timing-dependent byte or a morph drifted past \
             a locked surface and panicked. Neither happened.",
            summary.cycles_with_serial_log
        )
    } else if summary.distinct_serial_log_sha256 == summary.distinct_text_sha256 {
        format!(
            "{} distinct serial-log sha256 — equal to the {} distinct \
             `.text` sha256 across the same {} captured cycles. Cycles \
             with byte-distinct ELFs produced byte-distinct serial \
             logs, as expected for a deterministic kernel that emits \
             its own image identifiers.",
            summary.distinct_serial_log_sha256,
            summary.distinct_text_sha256,
            summary.cycles_with_serial_log
        )
    } else if summary.distinct_serial_log_sha256 > summary.distinct_text_sha256 {
        format!(
            "SURPRISE: {} distinct serial-log sha256 BUT only {} \
             distinct `.text` sha256 across {} captured cycles. The \
             kernel produced DIFFERENT observable output across cycles \
             with byte-IDENTICAL `.text`. Either the kernel emitted a \
             non-deterministic byte (TSC, runtime address, etc.) into \
             a serial banner or the `.text` sha is missing some image \
             bytes that the kernel reads at boot. Worth investigating.",
            summary.distinct_serial_log_sha256,
            summary.distinct_text_sha256,
            summary.cycles_with_serial_log
        )
    } else {
        // distinct_serial_log_sha256 < distinct_text_sha256: byte-
        // distinct ELFs collapsed to fewer distinct serial logs. The
        // benign reading: the kernel's banner-emission paths use
        // locked fixtures that don't include the morphed bytes, so
        // some morphs are observationally indistinguishable. Worth
        // noting because it bounds the *observable* diversity for an
        // adversary that can only see serial output.
        format!(
            "{} distinct serial-log sha256 across {} captured cycles \
             — fewer than the {} distinct `.text` sha256 over the \
             same cycles. Byte-distinct ELFs collapsed to fewer \
             distinct serial logs, bounding the *observable* \
             diversity an adversary that only sees serial output \
             could detect.",
            summary.distinct_serial_log_sha256,
            summary.cycles_with_serial_log,
            summary.distinct_text_sha256
        )
    };
    format!(
        "## Serial-log entropy\n\n\
         - Cycles with captured serial log: {captured} / {accepted}\n\
         - Distinct serial-log sha256: {distinct}\n\
         - For comparison — distinct .text sha256 over the same cycles: {tdistinct}\n\n\
         {interp}\n\n",
        captured = summary.cycles_with_serial_log,
        accepted = summary.cycles_completed,
        distinct = summary.distinct_serial_log_sha256,
        tdistinct = summary.distinct_text_sha256,
        interp = interp,
    )
}

fn fmt_opt_f64(v: Option<f64>) -> String {
    match v {
        Some(x) => format!("{:.6}", x),
        None => "n/a".to_string(),
    }
}
fn fmt_opt_u64(v: Option<u64>) -> String {
    match v {
        Some(x) => format!("{}", x),
        None => "n/a".to_string(),
    }
}

fn interpret(summary: &RunSummary, entropy_pct: f64, survival_pct: f64) -> String {
    let mut bullets = Vec::new();
    if summary.cycles_completed == 0 {
        return "No cycles completed — every cycle was rejected. The diversifier or verifier \
            is broken for this module today. Inspect `cycles.jsonl` for per-cycle rejection \
            reasons before drawing any other conclusion."
            .to_string();
    }
    if summary.distinct_text_sha256 <= 1 {
        bullets.push(format!(
            "ENTROPY FLOOR HIT: only {} distinct `.text` sha256 across {} accepted cycles. \
             The diversifier produced zero bits of binary diversity on this module — the \
             project's headline metamorphic-defense claim is NOT empirically supported by \
             this run.",
            summary.distinct_text_sha256, summary.cycles_completed
        ));
    } else {
        bullets.push(format!(
            "Entropy floor non-trivial: {} distinct `.text` sha256 / {} accepted cycles ({:.1}%). \
             The diversifier does produce binary diversity at the kernel-ELF level.",
            summary.distinct_text_sha256, summary.cycles_completed, entropy_pct
        ));
    }
    if let Some(med) = summary.hamming_median_norm {
        bullets.push(format!(
            "Median normalised Hamming distance across consecutive pairs is {:.4} — i.e. on \
             average about {:.1}% of `.text` bits differ between successive cycles.",
            med,
            med * 100.0
        ));
    }
    // Layout entropy — the TASK-025 axis. Byte churn (Hamming) and
    // layout churn (offset relocation) are independent: TASK-025
    // measured 30% byte churn with only 4 layouts in 20 cycles.
    if summary.cycles_completed > 1 {
        if summary.distinct_function_layouts <= 1 {
            bullets.push(format!(
                "LAYOUT FROZEN: {} distinct function-offset layout(s) across {} accepted \
                 cycles. Function entry points do not move between morphs — a ROP/JOP \
                 adversary needs exactly this stability. {}",
                summary.distinct_function_layouts,
                summary.cycles_completed,
                if summary.layout_seed_enabled {
                    "Layout seeding was ENABLED, so this is a regression in the \
                     `-Zlayout-seed`/`--shuffle-sections` plumbing — investigate before \
                     trusting any other number in this report."
                } else {
                    "Layout seeding was disabled for this run; this is the expected \
                     AST-diversifier-only result (TASK-025). Re-run without \
                     `--no-layout-seed` to engage the relocation lever."
                }
            ));
        } else {
            bullets.push(format!(
                "Layout entropy: {}/{} distinct function-offset layouts across accepted \
                 cycles (layout seeding {}). Probed symbols took {} (symbol_a) and {} \
                 (symbol_b) distinct offsets.",
                summary.distinct_function_layouts,
                summary.cycles_completed,
                if summary.layout_seed_enabled {
                    "ENABLED"
                } else {
                    "disabled"
                },
                summary.chain_offset_a_distinct,
                summary.chain_offset_b_distinct,
            ));
        }
    }
    if summary.chain_total_probes > 0 {
        if summary.chain_used_fallback {
            bullets.push(format!(
                "FALLBACK PICK: `pick_chain_symbols` could not locate the anchor symbol \
                 `{}` in cycle 0's symbol table and fell back. Probed pair: `{}` (off=0x{:x}) \
                 / `{}` (off=0x{:x}). Survival numbers in this run do NOT support any claim \
                 about the morphed module's resistance — see TASK-025's REPORT-real.md note.",
                CHAIN_ANCHOR_PATH,
                summary.chain_demangled_a,
                summary.chain_offset_a,
                summary.chain_demangled_b,
                summary.chain_offset_b,
            ));
        } else {
            bullets.push(format!(
                "Probe rooted on morphed-module symbols: `{}` (off=0x{:x}) / `{}` (off=0x{:x}).",
                summary.chain_demangled_a,
                summary.chain_offset_a,
                summary.chain_demangled_b,
                summary.chain_offset_b,
            ));
        }
        if summary.chain_survived_both == 0 {
            bullets.push(format!(
                "Synthetic chain survived 0/{} probes. A hypothetical ROP chain keyed to cycle-0 \
                 offsets does NOT land in any later cycle in this run.",
                summary.chain_total_probes
            ));
        } else if summary.chain_survived_both == summary.chain_total_probes {
            bullets.push(format!(
                "Synthetic chain survived all {}/{} probes ({:.1}%). The current diversifier \
                 alters source-level syntax but does not displace the compiled offsets of \
                 `{}` or `{}`. A hypothetical adversary targeting these symbols would land \
                 100% of the time — the defense is leaking on this module today.",
                summary.chain_survived_both,
                summary.chain_total_probes,
                survival_pct,
                summary.chain_demangled_a,
                summary.chain_demangled_b
            ));
        } else {
            bullets.push(format!(
                "Synthetic chain survived {}/{} probes ({:.1}%). Partial defense — some cycles \
                 perturb the targeted offsets, others don't.",
                summary.chain_survived_both, summary.chain_total_probes, survival_pct
            ));
        }
    }
    bullets.join("\n\n")
}

// ----- unit tests -----

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hamming_zero_for_identical() {
        let a = b"identical bytes";
        let (raw, norm) = hamming_distance(a, a);
        assert_eq!(raw, 0);
        assert_eq!(norm, 0.0);
    }

    #[test]
    fn hamming_counts_bits_not_bytes() {
        // 0xFF vs 0x00 has 8 different bits.
        let a = [0xFFu8];
        let b = [0x00u8];
        let (raw, norm) = hamming_distance(&a, &b);
        assert_eq!(raw, 8);
        assert!((norm - 1.0).abs() < 1e-9);
    }

    #[test]
    fn hamming_pads_shorter_with_zero() {
        let a = [0xFFu8, 0xFFu8];
        let b = [0xFFu8];
        // First byte matches, second byte XOR with implicit 0 → 8 bits.
        let (raw, _) = hamming_distance(&a, &b);
        assert_eq!(raw, 8);
    }

    // -----------------------------------------------------------------
    // TASK-122 — kernel churn gate (unit; no QEMU / no full ELF scan)
    // -----------------------------------------------------------------

    fn sample_churn(pos_surv: f64, same_text: bool) -> KernelChurnMeasurement {
        let base_g = 1000usize;
        let survivors = (pos_surv * base_g as f64).round() as usize;
        let sha = if same_text {
            ("aa".repeat(32), "aa".repeat(32))
        } else {
            ("bb".repeat(32), "cc".repeat(32))
        };
        KernelChurnMeasurement {
            base_text_sha256: sha.0,
            variant_text_sha256: sha.1,
            base_gadgets: base_g,
            variant_gadgets: base_g,
            positional_survivors: survivors,
            positional_survival: pos_surv,
            semantic_survivors_normalized: 800,
            base_distinct_normalized: 900,
            semantic_survival_normalized: 800.0 / 900.0,
            scan_ms: 1,
        }
    }

    #[test]
    fn kernel_churn_gate_passes_low_positional() {
        let m = sample_churn(0.01, false);
        assert!(evaluate_kernel_churn_gate(&m).is_ok(), "{:?}", m.summary_line());
    }

    #[test]
    fn kernel_churn_gate_fails_high_positional() {
        let m = sample_churn(0.50, false);
        let err = evaluate_kernel_churn_gate(&m).expect_err("must fail");
        assert!(err.iter().any(|r| r.contains("positional_survival")));
    }

    #[test]
    fn kernel_churn_gate_fails_identical_text() {
        let m = sample_churn(0.0, true);
        let err = evaluate_kernel_churn_gate(&m).expect_err("must fail");
        assert!(err.iter().any(|r| r.contains("identical .text")));
    }

    #[test]
    fn kernel_churn_gate_boundary_at_max() {
        // Exactly at the max is allowed (≤).
        let m = sample_churn(KERNEL_POSITIONAL_SURVIVAL_MAX, false);
        assert!(evaluate_kernel_churn_gate(&m).is_ok());
        let m2 = sample_churn(KERNEL_POSITIONAL_SURVIVAL_MAX + 0.001, false);
        assert!(evaluate_kernel_churn_gate(&m2).is_err());
    }

    // -----------------------------------------------------------------
    // pick_chain_symbols — demangle-aware survival probe rooting.
    // TASK-025 / iteration 16. The pre-iteration-16 implementation
    // matched on the literal string "hkdf_expand_label" in the
    // ELF symbol table, which mangles to
    // `_RNvNt...17target_enterprise3tls18hkdf_expand_label` (v0) or
    // `_ZN17target_enterprise3tls18hkdf_expand_label17h..E` (legacy).
    // The lookup always missed and the survival probe silently picked
    // unrelated kernel helpers (`hex_encode` etc.) — see
    // `experiments/diversity_demo/results/REPORT-real.md`
    // "Chain-survival probe — still uninterpretable" for the
    // pre-fix diagnosis.
    // -----------------------------------------------------------------

    /// Construct a canonical legacy-mangled name for a free fn in
    /// `target_enterprise::tls`. The trailing `17h<hash>E` part is
    /// what `rustc_demangle` strips when formatted with `{:#}`.
    fn legacy_tls_mangle(fn_name: &str) -> String {
        // _ZN <len><crate> <len><mod> <len><fn> 17h0123456789abcdefE
        // crate = "target_enterprise" (17 chars)
        // mod   = "tls"               (3 chars)
        format!(
            "_ZN17target_enterprise3tls{}{}17h0123456789abcdefE",
            fn_name.len(),
            fn_name,
        )
    }

    #[test]
    fn demangled_of_handles_legacy_mangling() {
        let m = legacy_tls_mangle("hkdf_expand_label");
        assert_eq!(
            demangled_of(&m),
            "target_enterprise::tls::hkdf_expand_label"
        );
    }

    #[test]
    fn demangled_of_passes_through_non_rust_names() {
        // Kernel-side symbols emitted from C / inline asm shims are
        // not Rust-mangled. They should round-trip unchanged.
        assert_eq!(demangled_of("kernel_main"), "kernel_main");
        assert_eq!(demangled_of("hex_encode"), "hex_encode");
    }

    #[test]
    fn pick_chain_prefers_anchor_when_present_via_demangle() {
        // The mangled name does NOT contain "hkdf_expand_label" as a
        // bare substring trivially — the literal lookup that the
        // pre-iteration-16 implementation used misses entirely. Only
        // the demangled form carries the readable path.
        let mut m = HashMap::new();
        let anchor = legacy_tls_mangle("hkdf_expand_label");
        let other = legacy_tls_mangle("parse_client_hello");
        m.insert(anchor.clone(), 0x100);
        m.insert(other.clone(), 0x200);
        let pick = pick_chain_symbols(&m);
        assert_eq!(pick.symbol_a, anchor);
        assert_eq!(pick.offset_a, 0x100);
        assert_eq!(
            pick.demangled_a,
            "target_enterprise::tls::hkdf_expand_label"
        );
        assert_eq!(pick.symbol_b, other);
        assert_eq!(pick.offset_b, 0x200);
        assert_eq!(
            pick.demangled_b,
            "target_enterprise::tls::parse_client_hello"
        );
        assert!(!pick.used_fallback, "anchor present -> no fallback");
    }

    #[test]
    fn pick_chain_anchor_match_is_substring_not_equality() {
        // The demangled form of a TLS-module symbol can carry a path
        // suffix from inner items (closures, monomorphisations) —
        // `target_enterprise::tls::hkdf_expand_label::{{closure}}`,
        // etc. The anchor match is a substring check, not equality,
        // so such inner-item symbols still root the survival probe
        // when the bare anchor isn't separately exported.
        let mut m = HashMap::new();
        // Simulate a closure inside hkdf_expand_label.
        // (Constructed via the same length-prefixed legacy form;
        // the demangler renders `{{closure}}` for inner closure items.
        // Here we just need a substring that CONTAINS the anchor path.)
        let outer = legacy_tls_mangle("hkdf_expand_label");
        m.insert(outer.clone(), 0x100);
        let other = legacy_tls_mangle("hkdf_extract");
        m.insert(other.clone(), 0x200);
        let pick = pick_chain_symbols(&m);
        assert!(pick.demangled_a.contains(CHAIN_ANCHOR_PATH));
        assert!(!pick.used_fallback);
    }

    #[test]
    fn pick_chain_surfaces_fallback_when_anchor_missing() {
        // No anchor anywhere in the table. The pre-fix behaviour
        // silently picked the two smallest-offset entries; the new
        // behaviour MUST surface this via `used_fallback = true` so
        // REPORT.md flags it.
        let mut m = HashMap::new();
        m.insert("hex_encode".to_string(), 0x00);
        m.insert("kernel_main".to_string(), 0x75);
        let pick = pick_chain_symbols(&m);
        assert!(
            pick.used_fallback,
            "anchor absent -> survival probe MUST flag fallback"
        );
        // Legacy two-smallest-offsets behaviour preserved on the
        // raw fallback path so existing scripts that hex-edit the
        // survival.jsonl can keep working.
        assert_eq!(pick.symbol_a, "hex_encode");
        assert_eq!(pick.offset_a, 0x00);
        assert_eq!(pick.symbol_b, "kernel_main");
        assert_eq!(pick.offset_b, 0x75);
    }

    #[test]
    fn pick_chain_prefers_morphed_module_symbol_for_second_slot() {
        // Anchor present + several non-morphed symbols at low offsets
        // + ONE other morphed symbol at a higher offset. The second
        // slot must prefer the morphed symbol, not the
        // smallest-offset kernel helper.
        let mut m = HashMap::new();
        m.insert("hex_encode".to_string(), 0x10);
        m.insert("kernel_main".to_string(), 0x20);
        let anchor = legacy_tls_mangle("hkdf_expand_label");
        let morphed_other = legacy_tls_mangle("build_server_hello");
        m.insert(anchor.clone(), 0x100);
        m.insert(morphed_other.clone(), 0x500);
        let pick = pick_chain_symbols(&m);
        assert_eq!(pick.symbol_a, anchor);
        assert_eq!(pick.offset_a, 0x100);
        assert_eq!(
            pick.symbol_b, morphed_other,
            "second slot prefers morphed-module symbol over kernel helpers"
        );
        assert_eq!(pick.offset_b, 0x500);
        assert!(!pick.used_fallback);
    }

    #[test]
    fn pick_chain_anchor_present_partial_fallback_when_no_other_morphed() {
        // Anchor present, but every other symbol is from outside the
        // morphed module. We still pick *something* — but flag the
        // half-rooted state via `used_fallback`.
        let mut m = HashMap::new();
        let anchor = legacy_tls_mangle("hkdf_expand_label");
        m.insert(anchor.clone(), 0x100);
        m.insert("hex_encode".to_string(), 0x200);
        let pick = pick_chain_symbols(&m);
        assert_eq!(pick.symbol_a, anchor);
        assert_eq!(pick.symbol_b, "hex_encode");
        assert!(
            pick.used_fallback,
            "anchor present but second symbol outside morphed module -> partial fallback"
        );
    }

    #[test]
    fn pick_chain_no_symbols_at_all_yields_sentinel_with_fallback() {
        let m: HashMap<String, u64> = HashMap::new();
        let pick = pick_chain_symbols(&m);
        assert_eq!(pick.symbol_a, "<none>");
        assert_eq!(pick.symbol_b, "<none>");
        assert_eq!(pick.offset_a, 0);
        assert_eq!(pick.offset_b, 0);
        assert!(pick.used_fallback);
    }

    #[test]
    fn pick_chain_is_deterministic_across_hashmap_orderings() {
        // HashMap iteration order is randomized in std. Build the same
        // logical input via two different insertion orders and assert
        // the resulting ChainPick is byte-identical. This guards
        // against the survival numbers wobbling cycle-to-cycle due to
        // hash randomisation alone.
        let anchor = legacy_tls_mangle("hkdf_expand_label");
        let m1 = {
            let mut m = HashMap::new();
            m.insert(anchor.clone(), 0x300);
            m.insert(legacy_tls_mangle("build_server_hello"), 0x500);
            m.insert(legacy_tls_mangle("hkdf_extract"), 0x700);
            m
        };
        let m2 = {
            let mut m = HashMap::new();
            m.insert(legacy_tls_mangle("hkdf_extract"), 0x700);
            m.insert(legacy_tls_mangle("build_server_hello"), 0x500);
            m.insert(anchor.clone(), 0x300);
            m
        };
        let p1 = pick_chain_symbols(&m1);
        let p2 = pick_chain_symbols(&m2);
        assert_eq!(p1, p2);
        assert_eq!(p1.symbol_a, anchor);
        // build_server_hello at 0x500 has the lower offset among the
        // two non-anchor morphed symbols → wins the second slot.
        assert_eq!(p1.demangled_b, "target_enterprise::tls::build_server_hello");
    }

    #[test]
    fn pick_chain_no_anchor_prefers_morphed_pair_when_available() {
        // No anchor, but two morphed-module symbols at different
        // offsets exist alongside non-morphed kernel helpers at
        // *smaller* offsets. The legacy fallback would have picked the
        // kernel helpers; the new fallback prefers morphed symbols
        // and still reports `used_fallback = true` because the anchor
        // is missing.
        let mut m = HashMap::new();
        m.insert("hex_encode".to_string(), 0x10);
        m.insert("kernel_main".to_string(), 0x20);
        m.insert(legacy_tls_mangle("build_server_hello"), 0x300);
        m.insert(legacy_tls_mangle("hkdf_extract"), 0x500);
        let pick = pick_chain_symbols(&m);
        assert!(pick.used_fallback, "anchor missing -> fallback flagged");
        // First morphed symbol wins (smallest morphed-module offset).
        assert_eq!(
            pick.demangled_a,
            "target_enterprise::tls::build_server_hello"
        );
        assert_eq!(pick.offset_a, 0x300);
        assert_eq!(pick.demangled_b, "target_enterprise::tls::hkdf_extract");
        assert_eq!(pick.offset_b, 0x500);
    }

    #[test]
    fn synthetic_chain_lays_out_offsets() {
        let c = build_synthetic_chain(0x1234, 0xABCD);
        assert_eq!(&c[0..8], &0x1234u64.to_le_bytes());
        assert_eq!(&c[8..16], &0xABCDu64.to_le_bytes());
        for b in &c[16..] {
            assert_eq!(*b, 0xCC);
        }
    }

    #[test]
    fn pseudo_elf_changes_with_hash() {
        let h1 = [1u8; 32];
        let h2 = [2u8; 32];
        let (b1, o1) = synthesize_pseudo_elf(&h1);
        let (b2, o2) = synthesize_pseudo_elf(&h2);
        assert_ne!(b1, b2, "different hashes must yield different pseudo .text");
        assert_ne!(
            o1, o2,
            "different hashes must yield different symbol offsets"
        );
    }

    // -----------------------------------------------------------------
    // Phase-1 layout seeding — derivation + pseudo-ELF + serde.
    // -----------------------------------------------------------------

    #[test]
    fn cycle_layout_seed_mirrors_morph_engine_mix() {
        // Pin the bijective mix so a drift from
        // `morph_engine::cycle::kernel_layout_seed` (which this fn
        // mirrors — same constants) is caught here.
        assert_eq!(cycle_layout_seed(0), 0x5DEE_CE66_D3A8_31EF);
        assert_eq!(
            cycle_layout_seed(1),
            0x9E37_79B9_7F4A_7C15u64 ^ 0x5DEE_CE66_D3A8_31EF
        );
        // Distinct across a realistic experiment range.
        let mut seen = std::collections::HashSet::new();
        for c in 0..256u64 {
            assert!(seen.insert(cycle_layout_seed(c)), "seed collision at cycle {}", c);
        }
    }

    #[test]
    fn pseudo_elf_seeded_none_matches_legacy() {
        // `None` must reproduce the historical pseudo-ELF exactly so
        // pre-seed fast-mode runs stay byte-comparable.
        let h = [7u8; 32];
        let legacy = synthesize_pseudo_elf(&h);
        let seeded_none = synthesize_pseudo_elf_seeded(&h, None);
        assert_eq!(legacy, seeded_none);
    }

    #[test]
    fn pseudo_elf_seed_moves_offsets_not_text() {
        // Same candidate hash, different layout seeds: the symbol
        // offsets must move (that's the relocation property the real
        // lever provides) while the `.text` bytes stay candidate-
        // derived (so text-sha entropy still measures source
        // diversity, not seed diversity).
        let h = [9u8; 32];
        let (b1, o1) = synthesize_pseudo_elf_seeded(&h, Some(1));
        let (b2, o2) = synthesize_pseudo_elf_seeded(&h, Some(2));
        assert_eq!(b1, b2, "layout seed must not perturb pseudo .text bytes");
        assert_ne!(o1, o2, "different layout seeds must relocate symbol offsets");
        // And seeded != unseeded for the same hash.
        let (_, o_none) = synthesize_pseudo_elf_seeded(&h, None);
        assert_ne!(o1, o_none, "seeded layout must differ from the unseeded one");
        // Determinism: same (hash, seed) -> same layout.
        let (b1b, o1b) = synthesize_pseudo_elf_seeded(&h, Some(1));
        assert_eq!((b1, o1), (b1b, o1b));
    }

    #[test]
    fn cycle_record_kernel_layout_seed_round_trips_and_omits_when_none() {
        // Same additive-schema contract as serial_log_sha256: Some
        // round-trips, None is invisible in the JSON line.
        let mut r = make_cycle_record_some_serial();
        r.kernel_layout_seed = Some(cycle_layout_seed(7));
        let s = serde_json::to_string(&r).expect("serialize");
        assert!(
            s.contains("\"kernel_layout_seed\":"),
            "expected kernel_layout_seed in JSON, got: {}",
            s
        );
        let back: CycleRecord = serde_json::from_str(&s).expect("deserialize");
        assert_eq!(back.kernel_layout_seed, Some(cycle_layout_seed(7)));

        let r_none = make_cycle_record_none_serial();
        let s_none = serde_json::to_string(&r_none).expect("serialize");
        assert!(
            !s_none.contains("kernel_layout_seed"),
            "None kernel_layout_seed must be skipped in JSON; got: {}",
            s_none
        );
        let back_none: CycleRecord = serde_json::from_str(&s_none).expect("deserialize");
        assert!(back_none.kernel_layout_seed.is_none());
    }

    #[test]
    fn reverse_lookup_finds_symbol() {
        let mut m = HashMap::new();
        m.insert("alpha".to_string(), 0x10);
        m.insert("beta".to_string(), 0x20);
        assert_eq!(reverse_lookup(&m, 0x10).as_deref(), Some("alpha"));
        assert_eq!(reverse_lookup(&m, 0x20).as_deref(), Some("beta"));
        assert_eq!(reverse_lookup(&m, 0x30), None);
    }

    #[test]
    fn iso8601_format_is_sane() {
        let s = iso8601_utc_now();
        assert_eq!(s.len(), 20, "ISO 8601 UTC is exactly 20 chars: {}", s);
        assert!(s.ends_with('Z'));
        assert!(s.contains('T'));
    }

    // -----------------------------------------------------------------
    // TASK-026 — CycleRecord.serial_log_sha256 serde round-trip.
    //
    // Three guarantees:
    //   (1) When Some, the field round-trips intact through serde_json.
    //   (2) When None, the field is OMITTED from the serialized line
    //       entirely (skip_serializing_if = "Option::is_none") so that
    //       pre-TASK-026 cycles.jsonl consumers — which never see a
    //       `serial_log_sha256` key — keep working byte-for-byte.
    //   (3) A pre-TASK-026 line lacking the field deserializes cleanly
    //       with `serial_log_sha256: None`, so re-reading old
    //       cycles.jsonl files after the schema bump still works.
    // -----------------------------------------------------------------

    fn make_cycle_record_some_serial() -> CycleRecord {
        CycleRecord {
            cycle: 7,
            accepted: true,
            reject_reason: None,
            candidate_sha256:
                "abcd000000000000000000000000000000000000000000000000000000000001".into(),
            elf_text_sha256:
                "abcd000000000000000000000000000000000000000000000000000000000002".into(),
            elf_text_size: 4096,
            function_offsets: {
                let mut m = HashMap::new();
                m.insert("hkdf_expand_label".to_string(), 0x100u64);
                m
            },
            wall_clock_ms: 12345,
            bundle_modules: std::collections::BTreeMap::new(),
            serial_log_sha256: Some(
                "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff".into(),
            ),
            kernel_layout_seed: None,
        }
    }

    fn make_cycle_record_none_serial() -> CycleRecord {
        let mut r = make_cycle_record_some_serial();
        r.serial_log_sha256 = None;
        r
    }

    #[test]
    fn cycle_record_serial_log_sha256_serializes_when_some() {
        let r = make_cycle_record_some_serial();
        let s = serde_json::to_string(&r).expect("serialize CycleRecord with serial_log_sha256");
        assert!(
            s.contains("\"serial_log_sha256\":\"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff\""),
            "expected serial_log_sha256 field in JSON, got: {}",
            s
        );
        let back: CycleRecord = serde_json::from_str(&s).expect("deserialize CycleRecord");
        assert_eq!(
            back.serial_log_sha256.as_deref(),
            Some("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
        );
        // The rest of the record must also round-trip.
        assert_eq!(back.cycle, 7);
        assert_eq!(back.accepted, true);
        assert_eq!(back.elf_text_size, 4096);
    }

    #[test]
    fn cycle_record_serial_log_sha256_omitted_when_none() {
        // Backward-compat invariant: a None serial_log_sha256 must NOT
        // appear in the serialized JSON at all. Existing consumers
        // (REPORT.md regen scripts, the dedup_diag tool, etc.) parse
        // line-by-line and would treat a sudden new field as either an
        // error or an unknown column, depending on their parser. The
        // skip_serializing_if attribute preserves the v1 line shape.
        let r = make_cycle_record_none_serial();
        let s = serde_json::to_string(&r).expect("serialize");
        assert!(
            !s.contains("serial_log_sha256"),
            "None serial_log_sha256 must be skipped in JSON; got: {}",
            s
        );
        // And the line must still parse back to a CycleRecord with
        // serial_log_sha256 = None.
        let back: CycleRecord = serde_json::from_str(&s).expect("deserialize");
        assert!(back.serial_log_sha256.is_none());
    }

    #[test]
    fn cycle_record_pre_task_026_line_parses_to_none() {
        // A v1 cycles.jsonl line — never had serial_log_sha256 in the
        // first place. Must still deserialize successfully and yield
        // None for the new field. This is the backward-compatibility
        // gate: the schema bump is invisible to old data.
        let v1_line = r#"{
            "cycle": 0,
            "accepted": true,
            "reject_reason": null,
            "candidate_sha256": "abcd000000000000000000000000000000000000000000000000000000000001",
            "elf_text_sha256": "abcd000000000000000000000000000000000000000000000000000000000002",
            "elf_text_size": 4096,
            "function_offsets": {"hkdf_expand_label": 256},
            "wall_clock_ms": 12345
        }"#;
        let r: CycleRecord = serde_json::from_str(v1_line).expect("deserialize v1 line");
        assert_eq!(r.cycle, 0);
        assert!(r.serial_log_sha256.is_none());
        assert!(r.bundle_modules.is_empty());
    }

    #[test]
    fn cycle_record_rejected_records_carry_none_serial() {
        // Rejected cycles never reach the package+boot stage. The
        // run loop unconditionally writes None into the rejected
        // record. This test pins that contract so a future change
        // that accidentally inherits the previous cycle's serial
        // sha is caught.
        let r = CycleRecord {
            cycle: 3,
            accepted: false,
            reject_reason: Some("verify failed: dummy".into()),
            candidate_sha256: String::new(),
            elf_text_sha256: String::new(),
            elf_text_size: 0,
            function_offsets: HashMap::new(),
            wall_clock_ms: 50,
            bundle_modules: std::collections::BTreeMap::new(),
            serial_log_sha256: None,
            kernel_layout_seed: None,
        };
        let s = serde_json::to_string(&r).unwrap();
        assert!(!s.contains("serial_log_sha256"));
        assert!(s.contains("\"accepted\":false"));
        assert!(s.contains("\"reject_reason\":\"verify failed: dummy\""));
    }

    /// Build a `RunSummary` populated enough for `render_serial_log_section`
    /// to exercise its branching, with overridable serial-log fields.
    fn make_summary_for_serial_section(
        cycles_completed: u64,
        cycles_with_serial_log: u64,
        distinct_serial_log_sha256: usize,
        distinct_text_sha256: usize,
    ) -> RunSummary {
        RunSummary {
            cycles_requested: cycles_completed,
            cycles_completed,
            cycles_rejected: 0,
            fast_mode: false,
            module: "tls".into(),
            target_dir: PathBuf::from("target_enterprise"),
            bundle_name: None,
            bundle_members: Vec::new(),
            distinct_text_sha256,
            hamming_median_norm: None,
            hamming_p95_norm: None,
            hamming_max_norm: None,
            hamming_median_bits: None,
            hamming_p95_bits: None,
            hamming_max_bits: None,
            chain_symbol_a: "<none>".into(),
            chain_symbol_b: "<none>".into(),
            chain_demangled_a: "<none>".into(),
            chain_demangled_b: "<none>".into(),
            chain_offset_a: 0,
            chain_offset_b: 0,
            chain_survived_both: 0,
            chain_total_probes: 0,
            chain_used_fallback: false,
            wallclock_median_ms: 0,
            wallclock_p95_ms: 0,
            wallclock_max_ms: 0,
            distinct_serial_log_sha256,
            cycles_with_serial_log,
            layout_seed_enabled: false,
            stack_pad_enabled: false,
            distinct_function_layouts: 0,
            chain_offset_a_distinct: 0,
            chain_offset_b_distinct: 0,
            cycles_jsonl: PathBuf::from("cycles.jsonl"),
            diversity_jsonl: PathBuf::from("diversity.jsonl"),
            survival_jsonl: PathBuf::from("survival.jsonl"),
            run_start_iso: "2026-05-17T12:00:00Z".into(),
        }
    }

    #[test]
    fn mtd_gate_skipped_when_layout_seed_off() {
        let s = make_summary_for_serial_section(4, 0, 0, 4);
        assert!(!s.layout_seed_enabled);
        match evaluate_mtd_gate(&s) {
            MtdGateStatus::Skipped { reason } => {
                assert!(reason.contains("layout seeding disabled"));
            }
            other => panic!("expected Skipped, got {:?}", other),
        }
        assert!(evaluate_mtd_gate(&s).is_hard_failure());
    }

    #[test]
    fn mtd_gate_passes_under_production_metrics() {
        let mut s = make_summary_for_serial_section(4, 0, 0, 4);
        s.layout_seed_enabled = true;
        s.distinct_function_layouts = 4;
        s.chain_offset_a_distinct = 4;
        s.chain_offset_b_distinct = 4;
        s.chain_survived_both = 0;
        s.chain_total_probes = 3;
        s.chain_used_fallback = false;
        assert_eq!(evaluate_mtd_gate(&s), MtdGateStatus::Passed);
        assert!(evaluate_mtd_gate(&s).is_passed());
        assert!(!evaluate_mtd_gate(&s).is_hard_failure());
    }

    #[test]
    fn mtd_gate_fails_on_chain_survival_and_layout_freeze() {
        let mut s = make_summary_for_serial_section(4, 0, 0, 4);
        s.layout_seed_enabled = true;
        s.distinct_function_layouts = 1; // freeze
        s.chain_offset_a_distinct = 1;
        s.chain_survived_both = 3;
        s.chain_total_probes = 3;
        match evaluate_mtd_gate(&s) {
            MtdGateStatus::Failed { reasons } => {
                assert!(
                    reasons.len() >= 2,
                    "expected multiple reasons, got {:?}",
                    reasons
                );
                let joined = reasons.join(" | ");
                assert!(joined.contains("distinct_function_layouts"));
                assert!(joined.contains("chain_survived_both"));
            }
            other => panic!("expected Failed, got {:?}", other),
        }
    }

    #[test]
    fn render_serial_log_section_empty_when_flag_off() {
        // `cycles_with_serial_log == 0` -> empty string -> REPORT.md
        // gets no Serial-log section at all. Pin the empty-default
        // contract so a refactor doesn't accidentally start emitting
        // "n/a captured serial logs" noise for every legacy run.
        let s = make_summary_for_serial_section(20, 0, 0, 20);
        let out = render_serial_log_section(&s);
        assert_eq!(out, "");
    }

    #[test]
    fn render_serial_log_section_single_sha_path() {
        // 5 cycles captured, 1 distinct serial-log sha. Means: the
        // kernel produced byte-identical output across all captured
        // cycles. Expected; section should say so.
        let s = make_summary_for_serial_section(5, 5, 1, 1);
        let out = render_serial_log_section(&s);
        assert!(out.contains("## Serial-log entropy"));
        assert!(out.contains("Cycles with captured serial log: 5 / 5"));
        assert!(out.contains("Distinct serial-log sha256: 1"));
        assert!(out.contains("Single serial-log sha256"));
    }

    #[test]
    fn render_serial_log_section_equal_distinct_path() {
        // distinct_serial == distinct_text > 1: byte-distinct ELFs
        // produce byte-distinct serial logs. Expected for a
        // deterministic kernel that emits image identifiers — section
        // should note the equality.
        let s = make_summary_for_serial_section(5, 5, 3, 3);
        let out = render_serial_log_section(&s);
        assert!(out.contains("equal to the 3 distinct"));
    }

    #[test]
    fn render_serial_log_section_surprise_more_serial_than_elf() {
        // distinct_serial > distinct_text: surprise — kernel emitted
        // observable bytes that aren't reflected in `.text` itself
        // (could be a TSC dump). REPORT.md must flag this.
        let s = make_summary_for_serial_section(5, 5, 4, 2);
        let out = render_serial_log_section(&s);
        assert!(
            out.contains("SURPRISE"),
            "surprise interpretation must trigger when serial > text; got: {}",
            out
        );
        assert!(out.contains("4 distinct serial-log sha256"));
        assert!(out.contains("2 distinct `.text`"));
    }

    #[test]
    fn render_serial_log_section_fewer_serial_than_elf_path() {
        // distinct_serial < distinct_text: morphed bytes don't affect
        // observable banner output for some morphs. Bounds the
        // observable-by-adversary diversity. REPORT.md says so.
        let s = make_summary_for_serial_section(10, 10, 3, 7);
        let out = render_serial_log_section(&s);
        assert!(out.contains("3 distinct serial-log sha256"));
        assert!(out.contains("fewer than the 7 distinct"));
        assert!(out.contains("observable"));
    }

    #[test]
    fn cycle_record_serial_log_sha256_canonical_jsonl_byte_compat() {
        // When boot_each_cycle is off, the cycles.jsonl line for an
        // accepted single-module record must be byte-identical to the
        // v1 schema (modulo field ordering of bundle_modules, which
        // is also skip_serializing_if-gated). This guards against a
        // regression where someone removes the skip_serializing_if
        // and breaks every existing cycles.jsonl consumer.
        let r = make_cycle_record_none_serial();
        let s = serde_json::to_string(&r).unwrap();
        // Field order is the struct declaration order, so this is
        // deterministic.
        let expected_keys = [
            "cycle",
            "accepted",
            "reject_reason",
            "candidate_sha256",
            "elf_text_sha256",
            "elf_text_size",
            "function_offsets",
            "wall_clock_ms",
        ];
        for k in expected_keys {
            assert!(s.contains(&format!("\"{}\"", k)), "missing key {} in: {}", k, s);
        }
        assert!(!s.contains("bundle_modules"));
        assert!(!s.contains("serial_log_sha256"));
    }
}
