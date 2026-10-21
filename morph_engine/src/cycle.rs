//! Cycle-running logic, factored out of the CLI so `morph run` and
//! `morph tick` can both invoke it without re-spawning a process.

use anyhow::{bail, Context, Result};
use ed25519_dalek::Signer;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::attest::{self, AttestEntryFields};
use crate::factory;
use crate::federation::{self, Cosignature};
use crate::signing::{hex, load_signing_key};
use crate::synth::{
    read_contracts_source, read_manifest, AnthropicSynth, MutationBudget, PassThrough, PromptOnly,
    SynthRequest, Synthesizer,
};

const LAST_GOOD_SUFFIX: &str = ".last_good.rs";
const DEFAULT_PROMPT_OUT_DIR: &str = "prompts_out";

/// Which Stage 1 backend to run for this cycle. Maps 1:1 to the
/// `--synthesizer` CLI flag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SynthesizerKind {
    /// Return the previous source unchanged. The default; preserves the
    /// pre-refactor cycle behaviour bit-for-bit.
    PassThrough,
    /// Write the structured LLM prompt to `prompts_out/` and return the
    /// previous source unchanged.
    PromptOnly,
    /// Call the Anthropic Messages API and return the parsed candidate
    /// source. Requires `ANTHROPIC_API_KEY` in the environment; fails
    /// fast if absent (no silent fallback).
    Anthropic,
    /// Call the Fireworks AI OpenAI-compatible API. Requires
    /// `FIREWORKS_API_KEY`; `FIREWORKS_MODEL` optionally overrides the
    /// default model. No silent fallback.
    Fireworks,
}

impl SynthesizerKind {
    /// Parse a `--synthesizer` value. Accepts `passthrough`,
    /// `prompt-only`, and `anthropic`. Case-sensitive on purpose —
    /// keeps log entries stable.
    pub fn parse(s: &str) -> Result<Self> {
        match s {
            "passthrough" => Ok(SynthesizerKind::PassThrough),
            "prompt-only" => Ok(SynthesizerKind::PromptOnly),
            "anthropic" => Ok(SynthesizerKind::Anthropic),
            "fireworks" => Ok(SynthesizerKind::Fireworks),
            other => bail!(
                "unknown --synthesizer value '{}'; expected passthrough, prompt-only, anthropic, or fireworks",
                other
            ),
        }
    }
}

impl Default for SynthesizerKind {
    fn default() -> Self {
        SynthesizerKind::PassThrough
    }
}

/// Inputs for a single morph cycle. All paths are caller-resolved
/// (absolute in tests; workspace-relative when driven from the CLI).
#[derive(Debug, Clone)]
pub struct CycleArgs {
    pub cycle: u64,
    pub module: String,
    pub target_dir: PathBuf,
    pub manifest: Option<PathBuf>,
    /// Which Stage 1 backend to use. Defaults to `PassThrough` for
    /// backward compatibility with callers that pre-date this field.
    pub synthesizer: SynthesizerKind,
    /// When `true`, the deploy stage will (after the candidate is
    /// installed) build the kernel ELF for the morphed module, package
    /// it as a BIOS image via `factory_builder`, and record the
    /// resulting image's sha256 in the attestation entry. Default
    /// `false` so existing cycles and tests don't pay the build cost.
    /// Only meaningful for bootable targets (currently
    /// `target_enterprise`); other modules ignore it.
    pub emit_image: bool,
    /// When `true`, pass `--no-perf-check` to the verifier so the cycle
    /// skips the rolling-window performance gate. Used by the short
    /// morph-daemon soak (and any operator who wants semantics-only
    /// verification). Default `false` — production cycles enforce the
    /// perf envelope.
    pub no_perf_check: bool,
    /// Optional directory of DurableSeal JSON files to attach as
    /// `durable_seals` on the attestation entry (TASK-146). When
    /// `None`, falls back to `CUTTLE_DURABLE_SEALS_DIR` if set.
    pub durable_seals_dir: Option<PathBuf>,
}

impl CycleArgs {
    /// Parse the `args` slice produced by the CLI (`args[2..]` from the
    /// process argv, in the original main's calling convention).
    pub fn from_cli(args: &[String]) -> Result<Self> {
        let mut cycle: Option<u64> = None;
        let mut module: Option<String> = None;
        let mut target_dir: Option<PathBuf> = None;
        let mut manifest: Option<PathBuf> = None;
        let mut synthesizer: SynthesizerKind = SynthesizerKind::default();
        let mut emit_image: bool = false;
        let mut no_perf_check: bool = false;
        let mut durable_seals_dir: Option<PathBuf> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--cycle" => {
                    cycle = Some(args.get(i + 1).context("--cycle needs value")?.parse()?);
                    i += 2;
                }
                "--module" => {
                    module = Some(args.get(i + 1).context("--module needs value")?.clone());
                    i += 2;
                }
                "--target" => {
                    target_dir =
                        Some(PathBuf::from(args.get(i + 1).context("--target needs value")?));
                    i += 2;
                }
                "--manifest" => {
                    manifest =
                        Some(PathBuf::from(args.get(i + 1).context("--manifest needs value")?));
                    i += 2;
                }
                "--synthesizer" => {
                    let v = args
                        .get(i + 1)
                        .context("--synthesizer needs value")?
                        .as_str();
                    synthesizer = SynthesizerKind::parse(v)?;
                    i += 2;
                }
                "--emit-image" => {
                    emit_image = true;
                    i += 1;
                }
                "--no-perf-check" => {
                    no_perf_check = true;
                    i += 1;
                }
                "--durable-seals-dir" => {
                    durable_seals_dir = Some(PathBuf::from(
                        args.get(i + 1)
                            .context("--durable-seals-dir needs value")?,
                    ));
                    i += 2;
                }
                other => bail!("unknown argument: {}", other),
            }
        }
        Ok(CycleArgs {
            cycle: cycle.context("--cycle is required")?,
            module: module.context("--module is required")?,
            target_dir: target_dir.context("--target is required")?,
            manifest,
            synthesizer,
            emit_image,
            no_perf_check,
            durable_seals_dir,
        })
    }
}

impl Default for CycleArgs {
    fn default() -> Self {
        Self {
            cycle: 0,
            module: String::new(),
            target_dir: PathBuf::new(),
            manifest: None,
            synthesizer: SynthesizerKind::default(),
            emit_image: false,
            no_perf_check: false,
            durable_seals_dir: None,
        }
    }
}

/// Shared stages 1–2 of a morph cycle: synthesize → locked-check →
/// diversify → canonical-hash → stage the candidate file. Factored out
/// of [`run_cycle`] so the proposer role (`morph propose`) runs the
/// byte-identical pipeline the deploy path uses.
pub struct PreparedCandidate {
    pub source_path: PathBuf,
    pub cand_path: PathBuf,
    pub cand_hash: [u8; 32],
    pub synth_label: &'static str,
    pub prompt_path: Option<PathBuf>,
    pub attest_div_log: attest::DiversifierLog,
}

fn prepare_candidate(args: &CycleArgs) -> Result<PreparedCandidate> {
    // TASK-022 — touch the factory-fingerprint cache once per cycle so
    // accepted AND rejected entries both record which binaries
    // produced them. OnceLock-cached: subsequent calls in the same
    // process pay zero cost.
    let _ = factory::fingerprint();

    let source_path = args.target_dir.join(format!("{}.rs", args.module));
    let prev_source = fs::read_to_string(&source_path)
        .with_context(|| format!("read {}", source_path.display()))?;

    // === Stage 1: synthesize ===
    let manifest_vec: Vec<String> = match &args.manifest {
        // An operator-specified manifest that fails to load must surface,
        // not silently degrade to an empty locked-symbol list (which would
        // weaken the contract the synthesizer is told to honour).
        Some(p) => read_manifest(p)
            .with_context(|| format!("load --manifest {}", p.display()))?,
        None => Vec::new(),
    };
    let contracts_src: String = if matches!(args.synthesizer, SynthesizerKind::Fireworks) {
        // Cheap-model context discipline: the full contracts crate is
        // ~100k tokens, which blows past small-model context (and
        // budget). The verifier — not the model — is the trust anchor,
        // so the Fireworks path prompts with the previous source only.
        String::new()
    } else {
        read_contracts_source()
    };
    let req = SynthRequest {
        module_name: &args.module,
        cycle: args.cycle,
        previous_source: &prev_source,
        contracts_source: &contracts_src,
        manifest: &manifest_vec,
        mutation_budget: MutationBudget::default(),
    };

    let (synth_label, prompt_path, synth_source) = match args.synthesizer {
        SynthesizerKind::PassThrough => {
            eprintln!("morph: stage 1 synthesize (skeleton: pass-through)");
            let s = PassThrough;
            let resp = s.synthesize(&req)?;
            (s.name(), None, resp.candidate_source)
        }
        SynthesizerKind::PromptOnly => {
            eprintln!("morph: stage 1 synthesize (prompt-only)");
            let s = PromptOnly {
                prompt_out_dir: PathBuf::from(DEFAULT_PROMPT_OUT_DIR),
            };
            let path = s.prompt_path(args.cycle, &args.module);
            let resp = s.synthesize(&req)?;
            eprintln!("morph: wrote synthesis prompt to {}", path.display());
            (s.name(), Some(path), resp.candidate_source)
        }
        SynthesizerKind::Anthropic => {
            eprintln!("morph: stage 1 synthesize (anthropic)");
            // `from_env` bails out cleanly if `ANTHROPIC_API_KEY` is
            // unset — propagates through `run_cycle`, which is the
            // documented behaviour. No silent fallback.
            let s = AnthropicSynth::from_env(PathBuf::from(DEFAULT_PROMPT_OUT_DIR))?;
            let path = s.prompt_path(args.cycle, &args.module);
            let resp = s.synthesize(&req)?;
            eprintln!(
                "morph: wrote synthesis prompt to {} and parsed candidate to {}",
                path.display(),
                s.output_path(args.cycle, &args.module).display()
            );
            (s.name(), Some(path), resp.candidate_source)
        }
        SynthesizerKind::Fireworks => {
            eprintln!("morph: stage 1 synthesize (fireworks)");
            let s = crate::synth::FireworksSynth::from_env(PathBuf::from(DEFAULT_PROMPT_OUT_DIR))?;
            let path = s.prompt_path(args.cycle, &args.module);
            let resp = s.synthesize(&req)?;
            eprintln!(
                "morph: wrote synthesis prompt to {} and parsed candidate to {}",
                path.display(),
                s.output_path(args.cycle, &args.module).display()
            );
            (s.name(), Some(path), resp.candidate_source)
        }
    };

    // === Stage 2: diversify ===
    eprintln!("morph: stage 2 diversify");
    // Honour the locked-modules policy before morphing. The diversifier
    // operates on the synthesizer's output string, so the path-based lock
    // check can't live inside `diversify_with_log` — enforce it here.
    ensure_not_locked(&source_path)?;
    let seed = cuttle_diversifier::Seed::derive(args.cycle, &args.module);
    // Phase 1 lived defense: Rung-1 semantic perturbation is ON for
    // production cycles (instruction-mix diversity, not just layout).
    let (candidate, div_log) = cuttle_diversifier::diversify_with_log_and_options(
        &synth_source,
        &seed,
        &cuttle_diversifier::DiversifyOptions::with_semantic_perturb(),
    )?;
    let cand_hash = cuttle_diversifier::canonical_hash(&candidate)?;
    // TASK-031: persist the diversifier's per-cycle decision log on the
    // attestation entry so a future `verify-attest --replay-diversifier`
    // can reconstruct the candidate from `(seed, pad_log, perturb_log)`
    // and prove the entry is the deterministic result of the recorded
    // factory state.
    let attest_div_log = attest::diversifier_log_from(&div_log);
    eprintln!(
        "morph: diversifier log: {} pad decisions, {} perturb decisions",
        attest_div_log.pad_decisions.len(),
        attest_div_log.perturb_decisions.len()
    );

    let cand_path = args.target_dir.join(format!("{}.candidate.rs", args.module));
    fs::write(&cand_path, &candidate)?;

    Ok(PreparedCandidate {
        source_path,
        cand_path,
        cand_hash,
        synth_label,
        prompt_path,
        attest_div_log,
    })
}

/// Run the verify binary against a staged candidate. Returns `true` on
/// verifier ACCEPT (exit 0).
fn run_verifier(args: &CycleArgs, source_path: &Path, cand_path: &Path) -> Result<bool> {
    eprintln!("morph: stage 3 verify");
    let verify_exe = locate_sibling_bin("verify")?;
    let mut cmd = Command::new(&verify_exe);
    cmd.arg("--previous").arg(source_path);
    if let Some(m) = &args.manifest {
        cmd.arg("--manifest").arg(m);
    }
    if args.no_perf_check {
        cmd.arg("--no-perf-check");
    }
    cmd.arg(cand_path);
    let status = cmd
        .status()
        .with_context(|| format!("run {}", verify_exe.display()))?;
    Ok(status.success())
}

/// Run one full synthesize -> diversify -> verify -> sign -> deploy cycle
/// for the given module. Returns Ok(()) on a fully-accepted, deployed
/// candidate. Returns Err on any failure including verifier rejection.
pub fn run_cycle(args: &CycleArgs) -> Result<()> {
    let prep = prepare_candidate(args)?;
    let source_path = prep.source_path.clone();
    let last_good_path = args
        .target_dir
        .join(format!("{}{}", args.module, LAST_GOOD_SUFFIX));
    let cand_path = prep.cand_path.clone();
    let cand_hash = prep.cand_hash;
    let synth_label = prep.synth_label;
    let prompt_path = prep.prompt_path.clone();
    let attest_div_log = prep.attest_div_log.clone();

    // === Stage 3: verify ===
    let status_ok = run_verifier(args, &source_path, &cand_path)?;
    if !status_ok {
        eprintln!("morph: candidate REJECTED by verifier — rolling back");
        let rej_diversity = build_cycle_diversity(
            Some(&attest_div_log),
            None,
            None,
            args.cycle,
            &args.module,
        );
        emit_attestation(
            args.cycle,
            &args.module,
            &cand_hash,
            &[0u8; 64],
            false,
            synth_label,
            prompt_path.as_deref(),
            None,
            Some(attest_div_log.clone()),
            None, // rejected before any image build → no layout seed
            rej_diversity,
            args.durable_seals_dir.as_deref(),
            None, // rejected entries stay legacy-schema (zero sig, unsigned)
        )?;
        bail!("verifier rejected candidate for module {}", args.module);
    }

    // === Stage 4: sign ===
    eprintln!("morph: stage 4 sign");
    let key = load_signing_key()?;
    let sig = key.sign(&cand_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.to_bytes());

    // === Stage 5: deploy ===
    eprintln!("morph: stage 5 deploy (local file replace)");
    fs::copy(&source_path, &last_good_path)
        .with_context(|| format!("save last-good {}", last_good_path.display()))?;
    fs::rename(&cand_path, &source_path)
        .with_context(|| format!("install candidate at {}", source_path.display()))?;
    // TOCTOU guard: the bytes that passed the verifier were hashed
    // *before* signing and deploy. Anything with filesystem write (AV,
    // a racing build, an attacker) could have swapped the candidate in
    // the interim. Re-hash the actually-installed bytes and refuse to
    // attest if they differ from what was verified and signed.
    let installed = fs::read_to_string(&source_path)
        .with_context(|| format!("re-read installed {}", source_path.display()))?;
    let installed_hash = cuttle_diversifier::canonical_hash(&installed)
        .context("hash installed candidate")?;
    if installed_hash != cand_hash {
        bail!(
            "deploy corruption: installed {} hashes to {} but the verified+signed \
             candidate was {} — refusing to attest bytes that were not verified",
            source_path.display(),
            hex(&installed_hash),
            hex(&cand_hash)
        );
    }

    // Optional image emission: when `--emit-image` was set on the
    // cycle and the morphed module is a bootable target, package a
    // BIOS image via the `factory_builder` host binary and capture
    // its sha256. Off by default — adds ~minutes of build cost.
    // TASK-124: also returns diversified ELF path for diversity evidence.
    let emit_result = if args.emit_image && is_bootable_module(&args.module) {
        match emit_bootable_image(args, &source_path) {
            Ok(r) => {
                eprintln!(
                    "morph: emitted bootable image sha256={} elf={}",
                    r.image_sha256,
                    r.div_elf.display()
                );
                Some(r)
            }
            Err(e) => {
                // The candidate IS deployed — the log must say so. Record
                // an accepted entry with image_sha256 absent (the honest
                // "deployed but image step failed" signal), THEN surface
                // the failure. Withholding the attestation entirely would
                // leave the kernel running verified-but-unattested code
                // with no record in the chain at all.
                eprintln!("morph: image emission FAILED: {:#}", e);
                let div = build_cycle_diversity(
                    Some(&attest_div_log),
                    None,
                    None,
                    args.cycle,
                    &args.module,
                );
                emit_attestation(
                    args.cycle,
                    &args.module,
                    &cand_hash,
                    &sig_bytes,
                    true,
                    synth_label,
                    prompt_path.as_deref(),
                    None,
                    Some(attest_div_log.clone()),
                    None,
                    div,
                    args.durable_seals_dir.as_deref(),
                    Some(load_signing_key()?),
                )?;
                bail!(
                    "image emission failed after deploy; candidate installed and \
                     deployment attested (image_sha256 absent): {}",
                    e
                );
            }
        }
    } else {
        None
    };

    // The kernel layout seed is recorded only when an image was actually
    // emitted (the seed used inside `emit_bootable_image` is derived from
    // the same cycle, so it is reproducible here).
    let kernel_seed = emit_result.as_ref().map(|r| r.layout_seed);
    let image_sha256 = emit_result.as_ref().map(|r| r.image_sha256.clone());

    // TASK-124: diversity evidence — always source-side from diversifier;
    // when ELFs exist, measure variant .text and optional base churn.
    let diversity = build_cycle_diversity(
        Some(&attest_div_log),
        kernel_seed,
        emit_result.as_ref(),
        args.cycle,
        &args.module,
    );

    emit_attestation(
        args.cycle,
        &args.module,
        &cand_hash,
        &sig_bytes,
        true,
        synth_label,
        prompt_path.as_deref(),
        image_sha256.as_deref(),
        Some(attest_div_log),
        kernel_seed,
        diversity,
        args.durable_seals_dir.as_deref(),
        Some(key),
    )?;
    eprintln!(
        "morph: cycle {} module={} ACCEPTED hash={} sig={}",
        args.cycle,
        args.module,
        hex(&cand_hash),
        hex(&sig_bytes[..16])
    );
    if let Some(p) = &prompt_path {
        eprintln!("morph: synthesis prompt recorded at {}", p.display());
    }
    Ok(())
}

/// Locate a pipeline binary (`verify`, `factory_builder`, `binmorph`).
/// Sibling-of-the-current-exe ONLY — no PATH fallback. The verifier is
/// the security boundary of the factory: if it were resolved through
/// PATH, a hijacked PATH (or a stray `verify.exe` anywhere earlier in
/// PATH on a host where the sibling lookup failed) would let a
/// malicious binary rubber-stamp every candidate. Fail closed instead.
fn locate_sibling_bin(name: &str) -> Result<PathBuf> {
    let exe_name = if cfg!(windows) {
        format!("{}.exe", name)
    } else {
        name.to_string()
    };
    let self_exe = env::current_exe().context("locate current exe for sibling lookup")?;
    let candidates: Vec<PathBuf> = sibling_search_dirs(&self_exe)
        .into_iter()
        .map(|d| d.join(&exe_name))
        .collect();
    if candidates.is_empty() {
        bail!("current exe has no parent directory");
    }
    for candidate in &candidates {
        if candidate.exists() {
            return Ok(candidate.clone());
        }
    }
    bail!(
        "refusing to resolve '{}' via PATH: expected sibling binary at {} \
         (build the full workspace so all pipeline binaries co-locate)",
        name,
        candidates[0].display()
    )
}

/// Directories [`locate_sibling_bin`] searches, derived only from the
/// running exe's own path (never PATH, never an open-ended ancestor walk).
///
/// - `<profile>/morph(.exe)`: production — the exe's own directory.
/// - `<profile>/deps/` or `<profile>/examples/` (classic cargo layout for
///   test harnesses and examples): one level up.
/// - `<profile>/build/<pkg>/<hash>/<kind>/` (cargo's newer build-dir
///   layout, where test harnesses no longer live in `deps/`): the
///   `<profile>` directory four levels up, only when that shape matches.
fn sibling_search_dirs(self_exe: &Path) -> Vec<PathBuf> {
    let Some(dir) = self_exe.parent() else {
        return Vec::new();
    };
    let mut dirs = vec![dir.to_path_buf()];
    if let Some(up) = dir.parent() {
        dirs.push(up.to_path_buf());
    }
    let mut ancestors = dir.ancestors();
    if ancestors.nth(3).and_then(|p| p.file_name()) == Some(std::ffi::OsStr::new("build")) {
        if let Some(profile) = ancestors.next() {
            dirs.push(profile.to_path_buf());
        }
    }
    dirs
}

/// Append one v2 attestation entry. Thin wrapper around
/// [`attest::write_attestation`] so the cycle code keeps reading
/// linearly. Schema v2 adds hash-chain fields (`prev_entry_sha256`,
/// `entry_sha256`) and a periodic Merkle anchor file. The first call
/// after a v1 log migrates the old log aside (see `attest::migrate_if_pre_v2`).
#[allow(clippy::too_many_arguments)]
fn emit_attestation(
    cycle: u64,
    module: &str,
    hash: &[u8; 32],
    sig: &[u8; 64],
    accepted: bool,
    synthesizer: &'static str,
    prompt_path: Option<&Path>,
    image_sha256: Option<&str>,
    diversifier_log: Option<attest::DiversifierLog>,
    kernel_layout_seed: Option<u64>,
    diversity: Option<attest::DiversityEvidence>,
    durable_seals_dir: Option<&Path>,
    // Factory signing key for v11 entry-content signatures. `Some` for
    // accepted production cycles; `None` only for rejected entries
    // (zero sig, unsigned legacy schema) and legacy test callers.
    signing_key: Option<ed25519_dalek::SigningKey>,
) -> Result<()> {
    // Federation: attach the primary cosignature (a signature over the
    // candidate/bundle hash — federation cosign semantics are unchanged;
    // the v11 `sig_ed25519` field separately signs the full entry).
    // If the federation TOML is present it MUST parse: a corrupted
    // `factory_keys.toml` silently degrading minting to 1-of-1 is exactly
    // the "no silent fallback" violation the lock policy forbids.
    let fed_path = federation::resolve_federation_path();
    let (federation_threshold, cosignatures): (Option<u32>, Vec<Cosignature>) =
        if accepted && fed_path.exists() {
            let cfg = federation::load_federation(&fed_path).with_context(|| {
                format!(
                    "federation config {} is present but unparseable; refusing to mint \
                     a degraded single-signer entry — repair or remove the config",
                    fed_path.display()
                )
            })?;
            (
                Some(cfg.threshold),
                vec![Cosignature {
                    signer_id: "primary".to_string(),
                    sig_ed25519: hex(sig),
                }],
            )
        } else if accepted {
            (
                Some(1),
                vec![Cosignature {
                    signer_id: "primary".to_string(),
                    sig_ed25519: hex(sig),
                }],
            )
        } else {
            // Rejected entries (accepted=false) carry the zero-sig and
            // no cosignatures; threshold doesn't apply.
            (None, Vec::new())
        };

    // TASK-146: load operator seal directory (or CUTTLE_DURABLE_SEALS_DIR).
    let durable_seals = crate::durable_seal::resolve_durable_seals(durable_seals_dir)?;
    if !durable_seals.is_empty() {
        eprintln!(
            "morph: attaching {} durable seal(s) to attestation",
            durable_seals.len()
        );
    }

    attest::write_attestation(AttestEntryFields {
        cycle,
        module: module.to_string(),
        candidate_sha256: hex(hash),
        sig_ed25519: hex(sig),
        accepted,
        synthesizer: synthesizer.to_string(),
        prompt_path: prompt_path.map(|p| p.display().to_string()),
        image_sha256: image_sha256.map(|s| s.to_string()),
        cosignatures,
        federation_threshold,
        // TASK-022: every entry — accepted or rejected — records the
        // factory binaries that produced it. A `verify-attest
        // --strict-factory` audit can later reject entries minted by
        // a binary set the operator doesn't bless.
        factory_binaries: factory::fingerprint().clone(),
        // TASK-036 / Phase A: single-module entries (this code path)
        // leave the bundle fields absent. `run_bundle` writes its own
        // attestation entry with `bundle_name = Some(...)` and the
        // `modules` map populated.
        bundle_name: None,
        modules: std::collections::BTreeMap::new(),
        // TASK-031: per-cycle diversifier decision log. None for legacy
        // paths (and for tests that don't drive `diversify_with_log`);
        // populated for accepted+rejected entries minted by `run`.
        diversifier_log,
        // Phase 1: layout-seed of the kernel image build, when one was
        // emitted this cycle. None when no image was built.
        kernel_layout_seed,
        // TASK-102: None → write_attestation builds default TLV+Base64.
        ext_tlv_b64: None,
        // TASK-124: caller-built diversity evidence (or None → auto from log).
        diversity,
        // TASK-140/146: optional durable seals from dir/env.
        durable_seals,
        // v11: accepted entries are signed over their full content.
        signing_key,
    })
}

/// Result of packaging a bootable image + diversified kernel ELF.
struct BootImageEmit {
    image_sha256: String,
    div_elf: PathBuf,
    layout_seed: u64,
}

/// Build [`attest::DiversityEvidence`] for a single-module cycle.
///
/// Always includes diversifier decision counts when a log is present.
/// When `emit` is Some, records variant `.text` sha and layout seed;
/// when a prior-cycle diversified ELF is found on disk (or
/// `CUTTLE_DIVERSITY_BASE_ELF` is set), also records base sha +
/// positional/semantic survival bps.
fn build_cycle_diversity(
    div_log: Option<&attest::DiversifierLog>,
    layout_seed: Option<u64>,
    emit: Option<&BootImageEmit>,
    cycle: u64,
    module: &str,
) -> Option<attest::DiversityEvidence> {
    let mut d = crate::diversity::from_diversifier_log(div_log, layout_seed)
        .unwrap_or_default();

    if let Some(em) = emit {
        d.layout_seed = Some(em.layout_seed);
        match crate::diversity::text_sha256_of_elf(&em.div_elf) {
            Ok(sha) => {
                eprintln!(
                    "morph: diversity variant .text sha256={}…",
                    &sha[..16.min(sha.len())]
                );
                d.variant_text_sha256 = Some(sha);
            }
            Err(e) => {
                eprintln!(
                    "morph: diversity: could not hash variant ELF {}: {:#}",
                    em.div_elf.display(),
                    e
                );
            }
        }

        // Resolve base ELF: explicit env wins, else previous cycle's .div.elf.
        let base_path = std::env::var_os("CUTTLE_DIVERSITY_BASE_ELF")
            .map(PathBuf::from)
            .or_else(|| {
                if cycle == 0 {
                    return None;
                }
                em.div_elf.parent().map(|dir| {
                    dir.join(format!("{}-cycle{}.div.elf", module, cycle.saturating_sub(1)))
                })
            });

        if let Some(base) = base_path {
            if base.exists() && base != em.div_elf {
                match crate::diversity::from_elf_pair(&base, &em.div_elf) {
                    Ok(churn) => {
                        eprintln!(
                            "morph: diversity churn positional_bps={} semantic_norm_bps={} \
                             base={}…",
                            churn.positional_survival_bps.unwrap_or(0),
                            churn.semantic_survival_norm_bps.unwrap_or(0),
                            churn
                                .base_text_sha256
                                .as_ref()
                                .map(|s| &s[..8.min(s.len())])
                                .unwrap_or("?")
                        );
                        d = crate::diversity::merge(d, churn);
                    }
                    Err(e) => {
                        eprintln!(
                            "morph: diversity: ELF churn measure failed ({} vs {}): {:#}",
                            base.display(),
                            em.div_elf.display(),
                            e
                        );
                    }
                }
            }
        }
    }

    if d.is_empty() {
        None
    } else {
        Some(d)
    }
}

/// Derive the master kernel-diversity seed for a cycle. It drives ALL
/// reproducible binary diversity: `-Zrandomize-layout`/`-Zlayout-seed`,
/// LLD `--shuffle-sections`, AND the post-link `binmorph` instruction
/// rewrites — one seed reproduces the whole diversified binary. Recorded on
/// the attestation entry as `kernel_layout_seed` (the name is historical;
/// it is the master seed). Deterministic in the cycle so the build is
/// replayable, while successive cycles get independent diversity.
fn kernel_layout_seed(cycle: u64) -> u64 {
    // Mix so the seed isn't literally the cycle number; any bijection works.
    cycle.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5DEE_CE66_D3A8_31EF
}

/// Return `true` iff this module is a bootable target — i.e. the
/// deploy stage can ask `factory_builder` to package a kernel image
/// for it. Today only `target_enterprise` qualifies. Future bootable
/// targets should be added here.
fn is_bootable_module(module: &str) -> bool {
    module == "target_enterprise" || module == "target_enterprise_lib"
}

/// Build the kernel ELF for `target_enterprise` and run
/// `factory_builder` against it to produce a BIOS image. Returns the
/// hex sha256 of the produced image, parsed out of `factory_builder`'s
/// stdout. The image lands under `<workspace>/target/cuttle_images/`.
///
/// We deliberately call `factory_builder` as a subprocess (rather than
/// linking against its library) so a failure inside the bootloader
/// crate cannot crash the morph engine.
fn emit_bootable_image(args: &CycleArgs, _source_path: &Path) -> Result<BootImageEmit> {
    emit_kernel_image(&args.module, args.cycle)
}

/// Build layout-seeded kernel ELF → binmorph → BIOS package.
/// Shared by single-module (`run`) and bundle (`run-bundle --emit-image`)
/// paths (TASK-126). `label` is the module name or bundle name (used in
/// on-disk artifact filenames).
fn emit_kernel_image(label: &str, cycle: u64) -> Result<BootImageEmit> {
    // Locate the workspace root via this binary's path: morph is in
    // `<workspace>/target/<profile>/morph(.exe)`; go up twice. Falls
    // back to CWD if discovery fails.
    let workspace_root = workspace_root_guess()?;
    let kernel_crate = workspace_root.join("target_enterprise_kernel");
    let images_dir = workspace_root.join("target").join("cuttle_images");
    fs::create_dir_all(&images_dir).ok();
    let bios_out = images_dir.join(format!("{}-cycle{}-bios.img", label, cycle));

    // Step 1: build the kernel ELF.
    let fb = locate_sibling_bin("factory_builder")?;
    eprintln!(
        "morph: invoking {} build-kernel --kernel-crate {}",
        fb.display(),
        kernel_crate.display()
    );
    let seed = kernel_layout_seed(cycle);
    let bk = Command::new(&fb)
        .arg("build-kernel")
        .arg("--kernel-crate")
        .arg(&kernel_crate)
        // Phase 1: per-cycle, reproducible codegen layout randomization.
        // The seed is recorded on the attestation entry by the caller.
        .arg("--layout-seed")
        .arg(seed.to_string())
        .output()
        .with_context(|| format!("spawn {} build-kernel", fb.display()))?;
    if !bk.status.success() {
        bail!(
            "factory_builder build-kernel failed (exit {:?}): {}",
            bk.status.code(),
            String::from_utf8_lossy(&bk.stderr)
        );
    }
    let elf_path = PathBuf::from(
        String::from_utf8_lossy(&bk.stdout)
            .lines()
            .next()
            .context("factory_builder build-kernel produced no stdout")?
            .trim(),
    );

    // Step 1b: post-link binary diversification (Phase 1b). Shell out to
    // `binmorph` (separate binary — same crash-isolation rationale as
    // factory_builder) to apply size-preserving instruction-level rewrites
    // to the kernel's `.text` before packaging. This is where the factory's
    // *load-bearing* diversification now happens: the source-AST diversifier
    // (stage 2 of the cycle) is machine-cosmetic; the codegen layout/shuffle
    // levers and this post-link pass are what actually churn the binary.
    // Driven by the SAME master `seed` as build-kernel, so the entire
    // diversified binary (layout + function-shuffle + instruction rewrites)
    // is reproducible from the one `kernel_layout_seed` recorded on the
    // attestation entry — no extra schema field.
    let bm = locate_sibling_bin("binmorph")?;
    let div_elf = images_dir.join(format!("{}-cycle{}.div.elf", label, cycle));
    eprintln!(
        "morph: invoking {} --in {} --out {} --seed {}",
        bm.display(),
        elf_path.display(),
        div_elf.display(),
        seed
    );
    let bmout = Command::new(&bm)
        .arg("--in")
        .arg(&elf_path)
        .arg("--out")
        .arg(&div_elf)
        .arg("--seed")
        .arg(seed.to_string())
        .output()
        .with_context(|| format!("spawn {} (post-link diversify)", bm.display()))?;
    if !bmout.status.success() {
        bail!(
            "binmorph post-link diversify failed (exit {:?}): {}",
            bmout.status.code(),
            String::from_utf8_lossy(&bmout.stderr)
        );
    }
    // Surface binmorph's stats line (functions/instrs/swapped) for the log.
    eprint!("{}", String::from_utf8_lossy(&bmout.stderr));

    // Step 2: package the DIVERSIFIED ELF.
    eprintln!(
        "morph: invoking {} --candidate {} --out {}",
        fb.display(),
        div_elf.display(),
        bios_out.display()
    );
    let pkg = Command::new(&fb)
        .arg("--candidate")
        .arg(&div_elf)
        .arg("--out")
        .arg(&bios_out)
        .output()
        .with_context(|| format!("spawn {} (package mode)", fb.display()))?;
    if !pkg.status.success() {
        bail!(
            "factory_builder package mode failed (exit {:?}): {}",
            pkg.status.code(),
            String::from_utf8_lossy(&pkg.stderr)
        );
    }
    // Parse the bios line.
    for line in String::from_utf8_lossy(&pkg.stdout).lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        if let Some(rest) = line.strip_prefix("bios ") {
            // Last whitespace-separated token is the sha.
            let sha: &str = rest
                .split_whitespace()
                .next_back()
                .context("malformed bios line from factory_builder")?;
            if sha.len() == 64 && sha.chars().all(|c: char| c.is_ascii_hexdigit()) {
                // Rolling retention: `build_cycle_diversity` only ever
                // compares `cycle` against `cycle - 1`. Prune any older
                // `<label>-cycle<k>-bios.img` and `<label>-cycle<k>.div.elf`
                // so multi-cycle runs never accumulate unbounded images.
                prune_old_kernel_images(&images_dir, label, cycle);
                return Ok(BootImageEmit {
                    image_sha256: sha.to_string(),
                    div_elf,
                    layout_seed: seed,
                });
            }
        }
    }
    bail!(
        "factory_builder package mode succeeded but no parseable bios line in stdout: {}",
        String::from_utf8_lossy(&pkg.stdout)
    );
}

/// Remove `<label>-cycle<k>-bios.img` and `<label>-cycle<k>.div.elf` in
/// `images_dir` for all `k < cycle.saturating_sub(1)`, keeping only the
/// current cycle and immediate predecessor (`cycle - 1`).
fn prune_old_kernel_images(images_dir: &Path, label: &str, current_cycle: u64) {
    let keep_min = current_cycle.saturating_sub(1);
    let prefix = format!("{}-cycle", label);
    let Ok(entries) = fs::read_dir(images_dir) else {
        return;
    };
    for entry in entries.flatten() {
        let name = entry.file_name();
        let Some(s) = name.to_str() else {
            continue;
        };
        let Some(rest) = s.strip_prefix(&prefix) else {
            continue;
        };
        let num_str: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(c) = num_str.parse::<u64>() {
            if c < keep_min {
                let _ = fs::remove_file(entry.path());
            }
        }
    }
}

/// Best-effort: discover the Cuttle workspace root from the current
/// exe path. Used by image emission to locate sibling crates without
/// hard-coding an absolute path.
fn workspace_root_guess() -> Result<PathBuf> {
    let exe = env::current_exe().context("locate morph exe")?;
    // `<root>/target/<profile>/morph(.exe)` → go up twice.
    let two_up = exe
        .parent()
        .and_then(|p| p.parent())
        .and_then(|p| p.parent())
        .map(PathBuf::from);
    if let Some(p) = two_up {
        if p.join("Cargo.toml").exists() && p.join("morph_engine").exists() {
            return Ok(p);
        }
    }
    // Fallback: CWD.
    Ok(env::current_dir()?)
}

/// Enforce the locked-modules policy (TASK-017) before morphing a file.
///
/// `cuttle_diversifier::diversify_path` performs this check when it owns
/// the file read, but the morph engine diversifies the *synthesizer's
/// output string* (`diversify_with_log`), not the on-disk source, so it
/// must run the same check itself against the module's real source path.
/// Without this guard a locked module (`kpti.rs` CR3-swap discipline, the
/// `contracts` surface, the kernel boot shell) added to a single-module or
/// bundle morph set would be silently morphed — defeating the security
/// boundary the lock list exists to hold. Missing `locked_modules.toml`
/// is fatal: no silent fallback (an attacker must not be able to disable
/// the protection by deleting one file).
fn ensure_not_locked(source_path: &Path) -> Result<()> {
    let lock = cuttle_diversifier::load_locked_modules(source_path)
        .map_err(|e| anyhow::anyhow!("locked-modules policy: {}", e))?;
    if lock.is_locked(source_path) {
        bail!(
            "refusing to morph locked module {} (workspace root {}); \
             it is listed in locked_modules.toml — remove it from the morph \
             set or unlock it deliberately",
            source_path.display(),
            lock.workspace_root.display()
        );
    }
    Ok(())
}

// ============================================================================
// TASK-036 / Phase A: bundle cycle (atomic multi-module morph)
// ============================================================================

/// Inputs for a single **bundle** cycle. The bundle is the unit of
/// atomic deployment: every member is diversified with its own
/// per-(cycle, member) seed, the entire set is handed to the verifier
/// for one combined build, and a single attestation entry records the
/// bundle hash plus the per-module artefacts.
///
/// On reject the on-disk source files are NOT touched — the staging
/// candidates are wiped, the attestation log records the rejection,
/// the next cycle starts from the same on-disk state. On accept all
/// member source files are replaced together (each module's previous
/// source saved to `<workspace>/src/<module>.last_good.rs` first).
#[derive(Debug, Clone)]
pub struct BundleCycleArgs {
    pub cycle: u64,
    /// Bundle name as declared in `scheduler.toml`, e.g. `"kernel"`.
    pub bundle_name: String,
    /// Workspace member crate, e.g. `PathBuf::from("target_enterprise")`.
    /// Module source files resolve to `<workspace>/src/<module>.rs`.
    pub workspace: PathBuf,
    /// Module names that make up the bundle. Each must have a source
    /// file at `<workspace>/src/<module>.rs`.
    pub modules: Vec<String>,
    pub manifest: Option<PathBuf>,
    pub synthesizer: SynthesizerKind,
    pub emit_image: bool,
    /// See [`CycleArgs::no_perf_check`].
    pub no_perf_check: bool,
    /// See [`CycleArgs::durable_seals_dir`] (TASK-146).
    pub durable_seals_dir: Option<PathBuf>,
}

impl BundleCycleArgs {
    /// Parse a `--bundle <name>` invocation. Mirrors `CycleArgs::from_cli`
    /// for the bundle subcommand:
    ///
    /// `morph run-bundle --cycle N --bundle NAME --workspace DIR
    ///                   --module M1 [--module M2 ...]
    ///                   [--manifest FILE] [--synthesizer KIND]
    ///                   [--emit-image] [--no-perf-check]
    ///                   [--durable-seals-dir DIR]`
    pub fn from_cli(args: &[String]) -> Result<Self> {
        let mut cycle: Option<u64> = None;
        let mut bundle_name: Option<String> = None;
        let mut workspace: Option<PathBuf> = None;
        let mut modules: Vec<String> = Vec::new();
        let mut manifest: Option<PathBuf> = None;
        let mut synthesizer = SynthesizerKind::default();
        let mut emit_image = false;
        let mut no_perf_check = false;
        let mut durable_seals_dir: Option<PathBuf> = None;
        let mut i = 0;
        while i < args.len() {
            match args[i].as_str() {
                "--cycle" => {
                    cycle = Some(args.get(i + 1).context("--cycle needs value")?.parse()?);
                    i += 2;
                }
                "--bundle" => {
                    bundle_name = Some(args.get(i + 1).context("--bundle needs value")?.to_string());
                    i += 2;
                }
                "--workspace" => {
                    workspace = Some(PathBuf::from(args.get(i + 1).context("--workspace needs value")?));
                    i += 2;
                }
                "--module" => {
                    modules.push(args.get(i + 1).context("--module needs value")?.to_string());
                    i += 2;
                }
                "--manifest" => {
                    manifest = Some(PathBuf::from(args.get(i + 1).context("--manifest needs value")?));
                    i += 2;
                }
                "--synthesizer" => {
                    synthesizer = SynthesizerKind::parse(
                        args.get(i + 1).context("--synthesizer needs value")?,
                    )?;
                    i += 2;
                }
                "--emit-image" => {
                    emit_image = true;
                    i += 1;
                }
                "--no-perf-check" => {
                    no_perf_check = true;
                    i += 1;
                }
                "--durable-seals-dir" => {
                    durable_seals_dir = Some(PathBuf::from(
                        args.get(i + 1)
                            .context("--durable-seals-dir needs value")?,
                    ));
                    i += 2;
                }
                other => bail!("unknown arg to run-bundle: {}", other),
            }
        }
        Ok(BundleCycleArgs {
            cycle: cycle.context("--cycle is required")?,
            bundle_name: bundle_name.context("--bundle is required")?,
            workspace: workspace.context("--workspace is required")?,
            modules: {
                if modules.is_empty() {
                    bail!("at least one --module is required");
                }
                modules
            },
            manifest,
            synthesizer,
            emit_image,
            no_perf_check,
            durable_seals_dir,
        })
    }
}

/// Per-module staging produced during the diversify phase of a bundle
/// cycle. Source files on disk are NOT yet modified — `source_path` is
/// the live file, `candidate_path` is the staged sibling that will
/// either replace it (accept) or be deleted (reject).
struct StagedModule {
    /// Module name (e.g. `"tls"`).
    name: String,
    /// `<workspace>/src/<name>.rs` — the live file.
    source_path: PathBuf,
    /// `<workspace>/src/<name>.last_good.rs` — rollback anchor on
    /// accept.
    last_good_path: PathBuf,
    /// `<workspace>/src/<name>.candidate.rs` — staging file. Removed
    /// on reject; renamed over `source_path` on accept.
    candidate_path: PathBuf,
    /// Canonical hash of the candidate source.
    candidate_hash: [u8; 32],
}

/// Run one atomic bundle cycle.
///
/// Stages:
/// 1. **Diversify each member.** Read prev source, synthesize, enforce
///    the locked-modules policy (`ensure_not_locked`), diversify the
///    synth output, compute canonical hash, stage to
///    `<module>.candidate.rs`.
/// 2. **Compute bundle hash.** `sha256(sorted concat of
///    "<module>:<hex-canonical-hash>\n" lines)`.
/// 3. **Verify atomically.** Invoke the `verify` binary with
///    `--target-crate <workspace> --bundle-module NAME=PATH` for every
///    member. The verifier substitutes all candidates into a scratch
///    workspace and runs cargo build. One rejection rejects the bundle.
/// 4. **Sign bundle hash** with the factory key.
/// 5. **Atomic deploy.** For each module: save previous source to
///    `<module>.last_good.rs`, rename `<module>.candidate.rs` over
///    `<module>.rs`. The order is `save_all → rename_all`; an
///    interruption between these two phases leaves the workspace in a
///    self-consistent recoverable state (last_good points at the
///    previous accept's source).
/// 6. **Write attestation.** One v5 entry with `bundle_name`,
///    `candidate_sha256 = bundle_hash`, `modules` map populated.
pub fn run_bundle(args: &BundleCycleArgs) -> Result<()> {
    // Touch factory fingerprint cache (TASK-022) so this entry too
    // records which binaries produced it.
    let _ = factory::fingerprint();

    if args.modules.is_empty() {
        bail!("run_bundle: at least one module required");
    }
    // Locate workspace crate dir; src lives at workspace/src.
    let workspace_root = workspace_root_guess()?;
    let crate_dir: PathBuf = if args.workspace.is_absolute() {
        args.workspace.clone()
    } else {
        workspace_root.join(&args.workspace)
    };
    let src_dir = crate_dir.join("src");
    if !crate_dir.join("Cargo.toml").exists() {
        bail!(
            "run_bundle: workspace crate not found at {}",
            crate_dir.display()
        );
    }

    // Stage 1: diversify every member.
    eprintln!(
        "morph: bundle {} cycle {}: diversifying {} module(s)",
        args.bundle_name,
        args.cycle,
        args.modules.len()
    );
    let manifest_vec: Vec<String> = match &args.manifest {
        // Surface a failed manifest load rather than silently dropping the
        // locked-symbol list (no silent fallbacks).
        Some(p) => read_manifest(p)
            .with_context(|| format!("load --manifest {}", p.display()))?,
        None => Vec::new(),
    };
    let contracts_src: String = read_contracts_source();

    let mut staged: Vec<StagedModule> = Vec::with_capacity(args.modules.len());
    // TASK-031: per-bundle diversifier log. Keys are
    // `"{module}::{fn_name}"` so every member's decisions remain
    // attributable in the canonical-JSON entry. Merged across all
    // members below.
    let mut bundle_div_log = attest::DiversifierLog::default();
    for module in &args.modules {
        let source_path = src_dir.join(format!("{}.rs", module));
        let last_good_path = src_dir.join(format!("{}{}", module, LAST_GOOD_SUFFIX));
        let candidate_path = src_dir.join(format!("{}.candidate.rs", module));
        let prev_source = fs::read_to_string(&source_path).with_context(|| {
            format!("bundle: read prev source for {}: {}", module, source_path.display())
        })?;

        // Honour the locked-modules policy for every bundle member. A
        // locked module must never be morphed even as part of a bundle
        // (the doc for this fn long claimed `diversify_path` did this; it
        // never did — the engine diversifies the synth output string).
        ensure_not_locked(&source_path)
            .with_context(|| format!("bundle member {}", module))?;

        // Synthesize. Bundle cycles share the synthesizer-kind setting
        // across all members; per-member kinds can be added later if a
        // workflow ever needs them.
        let req = SynthRequest {
            module_name: module,
            cycle: args.cycle,
            previous_source: &prev_source,
            contracts_source: &contracts_src,
            manifest: &manifest_vec,
            mutation_budget: MutationBudget::default(),
        };
        let synth_source = match args.synthesizer {
            SynthesizerKind::PassThrough => {
                PassThrough.synthesize(&req)?.candidate_source
            }
            SynthesizerKind::PromptOnly => {
                let s = PromptOnly {
                    prompt_out_dir: PathBuf::from(DEFAULT_PROMPT_OUT_DIR),
                };
                s.synthesize(&req)?.candidate_source
            }
            SynthesizerKind::Anthropic => {
                let s = AnthropicSynth::from_env(PathBuf::from(DEFAULT_PROMPT_OUT_DIR))?;
                s.synthesize(&req)?.candidate_source
            }
            SynthesizerKind::Fireworks => {
                let s = crate::synth::FireworksSynth::from_env(PathBuf::from(DEFAULT_PROMPT_OUT_DIR))?;
                s.synthesize(&req)?.candidate_source
            }
        };

        // Per-(cycle, bundle, module) seed. Domain-separating on bundle
        // name AND module name keeps the per-module entropy independent
        // even when two bundles share a module name (e.g. a future
        // `[bundle.experimental]` with `tls` won't collide with
        // `[bundle.kernel]` with `tls`).
        let seed_label = format!("{}::{}", args.bundle_name, module);
        let seed = cuttle_diversifier::Seed::derive(args.cycle, &seed_label);
        let (candidate, member_div_log) =
            cuttle_diversifier::diversify_with_log_and_options(
                &synth_source,
                &seed,
                &cuttle_diversifier::DiversifyOptions::with_semantic_perturb(),
            )
            .with_context(|| format!("diversify bundle member {}", module))?;
        // Merge this member's log into the bundle log, prefixing keys
        // with `"{module}::"` so two members that morph fns of the
        // same name (e.g. two `init` fns) do not collide. Last-write
        // wins for any same-prefixed key — today's diversifier never
        // produces duplicates within a single member, so the policy
        // is documentary rather than load-bearing.
        for (fname, bytes) in member_div_log.pad_decisions {
            bundle_div_log
                .pad_decisions
                .insert(format!("{}::{}", module, fname), bytes);
        }
        for (fname, label) in member_div_log.perturb_decisions {
            bundle_div_log
                .perturb_decisions
                .insert(format!("{}::{}", module, fname), label);
        }
        // `canonical_hash` returns a 32-byte SHA-256; we use the bytes
        // directly to compute the bundle hash and emit the hex form
        // only when writing the attestation entry.
        let cand_hash: [u8; 32] = cuttle_diversifier::canonical_hash(&candidate)?;
        // Stage on disk so the verifier can read it back.
        fs::write(&candidate_path, &candidate).with_context(|| {
            format!("write staging candidate {}", candidate_path.display())
        })?;
        staged.push(StagedModule {
            name: module.clone(),
            source_path,
            last_good_path,
            candidate_path,
            candidate_hash: cand_hash,
        });
    }

    // Stage 2: compute bundle hash.
    let bundle_hash = compute_bundle_hash(&staged);

    // Stage 3: verify atomically. Invoke the verify binary with one
    // --bundle-module per member.
    eprintln!(
        "morph: bundle {} cycle {}: verifying atomically ({} candidates)",
        args.bundle_name,
        args.cycle,
        staged.len()
    );
    let verify_exe = locate_sibling_bin("verify")?;
    let target_crate_name = crate_dir
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("target_enterprise")
        .to_string();
    let mut cmd = Command::new(&verify_exe);
    cmd.arg("--target-crate").arg(&target_crate_name);
    if let Some(m) = &args.manifest {
        cmd.arg("--manifest").arg(m);
    }
    if args.no_perf_check {
        cmd.arg("--no-perf-check");
    }
    for s in &staged {
        cmd.arg("--bundle-module")
            .arg(format!("{}={}", s.name, s.candidate_path.display()));
    }
    let status = cmd
        .status()
        .with_context(|| format!("run {}", verify_exe.display()))?;
    if !status.success() {
        eprintln!(
            "morph: bundle {} REJECTED by verifier — wiping staged candidates",
            args.bundle_name
        );
        for s in &staged {
            let _ = fs::remove_file(&s.candidate_path);
        }
        let rej_div = crate::diversity::from_diversifier_log(
            Some(&bundle_div_log),
            None,
        );
        emit_attestation_bundle(
            args,
            &staged,
            &bundle_hash,
            &[0u8; 64],
            false,
            None,
            Some(bundle_div_log.clone()),
            None,
            rej_div,
            None, // rejected entries stay legacy-schema (zero sig, unsigned)
        )?;
        bail!(
            "verifier rejected bundle {} (cycle {})",
            args.bundle_name,
            args.cycle
        );
    }

    // Stage 4: sign the BUNDLE hash. Every member's canonical hash
    // contributes to it; signing the bundle hash is equivalent to
    // signing all members together with no chance of substitution.
    eprintln!("morph: bundle {} cycle {}: signing", args.bundle_name, args.cycle);
    let key = load_signing_key()?;
    let sig = key.sign(&bundle_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.to_bytes());

    // Stage 5: atomic deploy. Save_all-then-rename_all gives us a
    // recoverable mid-failure state: every module either has its new
    // source AND its last_good of the previous, or its previous source
    // AND a (stale, but harmless) last_good.
    eprintln!(
        "morph: bundle {} cycle {}: deploying {} candidate(s)",
        args.bundle_name,
        args.cycle,
        staged.len()
    );
    for s in &staged {
        fs::copy(&s.source_path, &s.last_good_path).with_context(|| {
            format!(
                "save last-good for {}: {}",
                s.name,
                s.last_good_path.display()
            )
        })?;
    }
    for s in &staged {
        fs::rename(&s.candidate_path, &s.source_path).with_context(|| {
            format!(
                "install candidate for {}: {}",
                s.name,
                s.source_path.display()
            )
        })?;
    }
    // TOCTOU guard (same rationale as the single-module path): the
    // verifier hashed the staged candidates; between verify and this
    // rename anything with filesystem write could have swapped them.
    // Re-hash every installed module and refuse to attest on mismatch.
    for s in &staged {
        let installed = fs::read_to_string(&s.source_path).with_context(|| {
            format!("re-read installed {}", s.source_path.display())
        })?;
        let installed_hash = cuttle_diversifier::canonical_hash(&installed)
            .context("hash installed bundle candidate")?;
        if installed_hash != s.candidate_hash {
            bail!(
                "deploy corruption: installed {} hashes to {} but the verified+signed \
                 candidate was {} — refusing to attest bytes that were not verified",
                s.source_path.display(),
                hex::encode(installed_hash),
                hex::encode(s.candidate_hash)
            );
        }
    }

    // TASK-126: bundle image emission — build layout-seeded kernel ELF,
    // binmorph, package BIOS; record image_sha + diversity (ELF churn
    // vs prior cycle when available). Same failure policy as single-
    // module: deploy already landed; withhold attestation and fail.
    let (image_sha256, kernel_seed, diversity) = if args.emit_image {
        match emit_kernel_image(&args.bundle_name, args.cycle) {
            Ok(em) => {
                eprintln!(
                    "morph: bundle {} emitted image sha256={} elf={}",
                    args.bundle_name,
                    em.image_sha256,
                    em.div_elf.display()
                );
                let div = build_cycle_diversity(
                    Some(&bundle_div_log),
                    Some(em.layout_seed),
                    Some(&em),
                    args.cycle,
                    &args.bundle_name,
                );
                (Some(em.image_sha256), Some(em.layout_seed), div)
            }
            Err(e) => {
                // Deploy landed — the log must record it. Write the
                // accepted entry with image_sha256 absent, THEN fail.
                eprintln!("morph: bundle image emission FAILED: {:#}", e);
                let div = crate::diversity::from_diversifier_log(
                    Some(&bundle_div_log),
                    None,
                );
                emit_attestation_bundle(
                    args,
                    &staged,
                    &bundle_hash,
                    &sig_bytes,
                    true,
                    None,
                    Some(bundle_div_log.clone()),
                    None,
                    div,
                    Some(load_signing_key()?),
                )?;
                bail!(
                    "bundle image emission failed after deploy; candidates installed and \
                     deployment attested (image_sha256 absent): {}",
                    e
                );
            }
        }
    } else {
        (
            None,
            None,
            // Source-side diversity auto-fill still applies in write_attestation.
            None,
        )
    };

    emit_attestation_bundle(
        args,
        &staged,
        &bundle_hash,
        &sig_bytes,
        true,
        image_sha256,
        Some(bundle_div_log),
        kernel_seed,
        diversity,
        Some(key),
    )?;
    eprintln!(
        "morph: bundle {} cycle {} ACCEPTED ({} modules deployed)",
        args.bundle_name,
        args.cycle,
        staged.len()
    );
    Ok(())
}

/// Compute `sha256(sorted concat of "<module>:<canonical-hex>\n")` —
/// the canonical bundle hash. Sorted because we want bundle-membership
/// (set semantics), not list-order, to drive the signature; an
/// operator reordering `modules = [...]` in scheduler.toml must NOT
/// change the deployed bundle hash if every member's canonical hash
/// is unchanged.
fn compute_bundle_hash(staged: &[StagedModule]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut entries: Vec<String> = staged
        .iter()
        .map(|s| format!("{}:{}\n", s.name, hex::encode(s.candidate_hash)))
        .collect();
    entries.sort();
    let mut h = Sha256::new();
    for e in entries {
        h.update(e.as_bytes());
    }
    h.finalize().into()
}

/// Append one v6 bundle attestation entry. The `diversifier_log` is
/// the per-bundle merged log (keys prefixed with `"{module}::"`) so a
/// single entry covers every member's diversifier decisions. `None`
/// for callers that don't have one to record.
#[allow(clippy::too_many_arguments)]
fn emit_attestation_bundle(
    args: &BundleCycleArgs,
    staged: &[StagedModule],
    bundle_hash: &[u8; 32],
    sig: &[u8; 64],
    accepted: bool,
    image_sha256: Option<String>,
    diversifier_log: Option<attest::DiversifierLog>,
    kernel_layout_seed: Option<u64>,
    diversity: Option<attest::DiversityEvidence>,
    // Factory signing key for v11 entry-content signatures (see
    // `emit_attestation`). `None` for rejected entries.
    signing_key: Option<ed25519_dalek::SigningKey>,
) -> Result<()> {
    // Federation: attach primary cosignature if config exists. Present
    // but unparseable config is fatal — no degraded 1-of-1 minting.
    let fed_path = federation::resolve_federation_path();
    let (federation_threshold, cosignatures): (Option<u32>, Vec<Cosignature>) =
        if accepted && fed_path.exists() {
            let cfg = federation::load_federation(&fed_path).with_context(|| {
                format!(
                    "federation config {} is present but unparseable; refusing to mint \
                     a degraded single-signer entry — repair or remove the config",
                    fed_path.display()
                )
            })?;
            (
                Some(cfg.threshold),
                vec![Cosignature {
                    signer_id: "primary".to_string(),
                    sig_ed25519: hex::encode(sig),
                }],
            )
        } else if accepted {
            (
                Some(1),
                vec![Cosignature {
                    signer_id: "primary".to_string(),
                    sig_ed25519: hex::encode(sig),
                }],
            )
        } else {
            (None, Vec::new())
        };

    let mut modules_map: std::collections::BTreeMap<String, attest::ModuleArtifact> =
        std::collections::BTreeMap::new();
    for s in staged {
        modules_map.insert(
            s.name.clone(),
            attest::ModuleArtifact {
                candidate_sha256: hex::encode(s.candidate_hash),
                elf_text_sha256: image_sha256.clone(),
            },
        );
    }

    attest::write_attestation(AttestEntryFields {
        cycle: args.cycle,
        // Top-level `module` carries the bundle name as a denormalised
        // copy so legacy single-module tooling that reads
        // `entry.module` keeps working with bundle entries.
        module: args.bundle_name.clone(),
        candidate_sha256: hex::encode(bundle_hash),
        sig_ed25519: hex::encode(sig),
        accepted,
        synthesizer: synthesizer_name(args.synthesizer),
        prompt_path: None, // bundle-wide prompt audit deferred to a follow-up
        image_sha256,
        cosignatures,
        federation_threshold,
        factory_binaries: factory::fingerprint().clone(),
        bundle_name: Some(args.bundle_name.clone()),
        modules: modules_map,
        diversifier_log,
        // TASK-126: layout seed when bundle --emit-image built a kernel.
        kernel_layout_seed,
        // TASK-102: default TLV+Base64 extension built at write time.
        ext_tlv_b64: None,
        // TASK-124/126: explicit diversity (or None → auto from diversifier_log).
        diversity,
        // TASK-140/146: durable seals from --durable-seals-dir / env.
        durable_seals: crate::durable_seal::resolve_durable_seals(
            args.durable_seals_dir.as_deref(),
        )?,
        // v11: accepted bundle entries are signed over their full content.
        signing_key,
    })
}

fn synthesizer_name(kind: SynthesizerKind) -> String {
    match kind {
        SynthesizerKind::PassThrough => "passthrough".to_string(),
        SynthesizerKind::PromptOnly => "prompt-only".to_string(),
        SynthesizerKind::Anthropic => "anthropic".to_string(),
        SynthesizerKind::Fireworks => "fireworks".to_string(),
    }
}

// ============================================================================
// Proposer / verifier split (factory TCB reduction)
// ============================================================================
//
// Design invariant: **no component whose output is not independently
// verified may influence deployed bytes.** The classic `morph run` path
// synthesizes, diversifies, verifies, signs, and deploys in one process
// — so a compromised proposer (LLM API, rustc, dependency, diversifier)
// could in principle push bytes all the way to deployment. The split:
//
//   morph propose            (proposer machine — UNTRUSTED, no key)
//     stages 1–3: synthesize → diversify → verify, then writes a
//     Proposal JSON. If the proposer is compromised the worst it can
//     mint is a garbage proposal.
//
//   morph attest-proposal    (verifier machine — holds the signing key)
//     re-reads the candidate and re-hashes (proposer cannot swap bytes
//     after the fact), RE-RUNS the verifier independently (the proposer
//     cannot fake a verify transcript), deploys with a post-deploy
//     re-hash, then signs a v11 entry. The signing key is only ever
//     needed here.
//
// A fully compromised proposer degrades to denial-of-service (every
// proposal rejected), never to code execution.

/// On-disk proposal from the proposer role. Self-describing but NOT
/// self-authenticating — every load-bearing field is re-derived by
/// `attest_proposal`.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Proposal {
    pub schema_version: u64,
    pub cycle: u64,
    pub module: String,
    pub candidate_path: String,
    pub candidate_sha256: String,
    pub synthesizer: String,
    pub diversifier_log: attest::DiversifierLog,
    pub proposer_verified_ok: bool,
    pub ts_unix: u64,
}

pub const PROPOSAL_SCHEMA_VERSION: u64 = 1;

/// Proposer role: run stages 1–3 and write the proposal. No signing
/// key is touched or required. On verifier rejection no proposal is
/// written (the full `morph run` path remains the one that attests
/// rejections).
pub fn propose_cycle(args: &CycleArgs, out_path: &Path) -> Result<()> {
    let prep = prepare_candidate(args)?;
    let ok = run_verifier(args, &prep.source_path, &prep.cand_path)?;
    if !ok {
        bail!(
            "proposer: verifier rejected candidate for module {} — no proposal written",
            args.module
        );
    }
    let proposal = Proposal {
        schema_version: PROPOSAL_SCHEMA_VERSION,
        cycle: args.cycle,
        module: args.module.clone(),
        candidate_path: prep.cand_path.display().to_string(),
        candidate_sha256: hex(&prep.cand_hash),
        synthesizer: prep.synth_label.to_string(),
        diversifier_log: prep.attest_div_log,
        proposer_verified_ok: true,
        ts_unix: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    };
    let json = serde_json::to_string_pretty(&proposal).context("serialize proposal")?;
    fs::write(out_path, json).with_context(|| format!("write proposal {}", out_path.display()))?;
    eprintln!(
        "morph: proposal written to {} (module={} cycle={} hash={})",
        out_path.display(),
        proposal.module,
        proposal.cycle,
        proposal.candidate_sha256
    );
    Ok(())
}

/// Verifier role: independently re-verify a proposal and, only if every
/// check passes, deploy + sign + attest. Requires the signing key.
pub fn attest_proposal(args: &CycleArgs, proposal_path: &Path) -> Result<()> {
    let raw = fs::read_to_string(proposal_path)
        .with_context(|| format!("read proposal {}", proposal_path.display()))?;
    let proposal: Proposal =
        serde_json::from_str(&raw).with_context(|| "parse proposal JSON")?;
    if proposal.schema_version != PROPOSAL_SCHEMA_VERSION {
        bail!(
            "proposal schema_version {} (expected {})",
            proposal.schema_version,
            PROPOSAL_SCHEMA_VERSION
        );
    }
    if proposal.module != args.module {
        bail!(
            "proposal module {} does not match invocation module {}",
            proposal.module,
            args.module
        );
    }

    // --- Independent check 1: the candidate bytes on disk must hash to
    // the recorded value. A proposer that swapped content after verify
    // fails here.
    let cand_path = PathBuf::from(&proposal.candidate_path);
    let candidate = fs::read_to_string(&cand_path)
        .with_context(|| format!("read candidate {}", cand_path.display()))?;
    let cand_hash = cuttle_diversifier::canonical_hash(&candidate)?;
    if hex(&cand_hash) != proposal.candidate_sha256 {
        bail!(
            "proposer tamper: candidate on disk hashes to {} but proposal records {}",
            hex(&cand_hash),
            proposal.candidate_sha256
        );
    }

    // --- Independent check 2: re-run the verifier ourselves. The
    // proposer's `proposer_verified_ok` flag is treated as a claim,
    // never as evidence.
    let source_path = args.target_dir.join(format!("{}.rs", args.module));
    let ok = run_verifier(args, &source_path, &cand_path)?;
    if !ok {
        bail!(
            "independent re-verification REJECTED the proposal candidate (module {})",
            args.module
        );
    }

    // --- Deploy with the same post-deploy re-hash discipline as
    // run_cycle (TOCTOU guard).
    let last_good_path = args
        .target_dir
        .join(format!("{}{}", args.module, LAST_GOOD_SUFFIX));
    fs::copy(&source_path, &last_good_path)
        .with_context(|| format!("save last-good {}", last_good_path.display()))?;
    fs::rename(&cand_path, &source_path)
        .with_context(|| format!("install candidate at {}", source_path.display()))?;
    let installed = fs::read_to_string(&source_path)
        .with_context(|| format!("re-read installed {}", source_path.display()))?;
    let installed_hash = cuttle_diversifier::canonical_hash(&installed)?;
    if installed_hash != cand_hash {
        bail!(
            "deploy corruption: installed bytes differ from the verified candidate"
        );
    }

    // --- Sign (v11 entry-content signature) and attest.
    let key = load_signing_key()?;
    let sig = key.sign(&cand_hash);
    let mut sig_bytes = [0u8; 64];
    sig_bytes.copy_from_slice(&sig.to_bytes());
    let diversity = crate::diversity::from_diversifier_log(
        Some(&proposal.diversifier_log),
        None,
    );
    emit_attestation(
        proposal.cycle,
        &args.module,
        &cand_hash,
        &sig_bytes,
        true,
        // Proposer's recorded label is informational; the attested bytes
        // are what the verifier re-derived. Preserve known labels.
        match proposal.synthesizer.as_str() {
            "prompt-only" => "prompt-only",
            "anthropic" => "anthropic",
            _ => "passthrough",
        },
        None,
        None,
        Some(proposal.diversifier_log),
        None,
        diversity,
        args.durable_seals_dir.as_deref(),
        Some(key),
    )?;
    eprintln!(
        "morph: proposal ACCEPTED and attested (module={} cycle={} hash={})",
        args.module,
        proposal.cycle,
        hex(&cand_hash)
    );
    Ok(())
}

/// Tiny hex helper used by the bundle code paths. Mirrors
/// `signing::hex` but lives here because the signing module's `hex`
/// is `pub(crate)` and importing it across the bundle code's
/// non-trivial call sites is more friction than this 6-line copy.
mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        let bytes = bytes.as_ref();
        let mut s = String::with_capacity(bytes.len() * 2);
        for b in bytes {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &[&str]) -> Vec<String> {
        v.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn sibling_search_dirs_production_exe_dir_first() {
        let dirs = sibling_search_dirs(Path::new("/w/target/release/morph.exe"));
        assert_eq!(dirs[0], Path::new("/w/target/release"));
    }

    #[test]
    fn sibling_search_dirs_classic_deps_layout() {
        let dirs = sibling_search_dirs(Path::new("/w/target/debug/deps/cycle_x-0123abcd.exe"));
        assert!(dirs.contains(&PathBuf::from("/w/target/debug")), "{dirs:?}");
    }

    #[test]
    fn sibling_search_dirs_new_build_dir_layout() {
        // Cargo's newer build-dir layout puts test harnesses here; the
        // pipeline binaries (`verify`, ...) stay in `<profile>/`.
        let dirs = sibling_search_dirs(Path::new(
            "/w/target/debug/build/cuttle-morph-engine/06ec4af14dd67749/out/cycle_x-06ec4af14dd67749.exe",
        ));
        assert!(dirs.contains(&PathBuf::from("/w/target/debug")), "{dirs:?}");
    }

    #[test]
    fn sibling_search_dirs_no_open_ended_ancestor_walk() {
        // Without the build-dir shape, only the exe dir and its parent.
        let dirs = sibling_search_dirs(Path::new("/a/b/c/d/e/f.exe"));
        assert_eq!(dirs, vec![PathBuf::from("/a/b/c/d/e"), PathBuf::from("/a/b/c/d")]);
    }

    #[test]
    fn emit_image_defaults_false() {
        let cargs = CycleArgs::from_cli(&s(&[
            "--cycle", "1", "--module", "lib", "--target", "D:/x",
        ]))
        .unwrap();
        assert!(!cargs.emit_image, "emit_image must default false");
        assert!(cargs.durable_seals_dir.is_none());
    }

    #[test]
    fn durable_seals_dir_parsed() {
        let cargs = CycleArgs::from_cli(&s(&[
            "--cycle",
            "1",
            "--module",
            "lib",
            "--target",
            "D:/x",
            "--durable-seals-dir",
            "D:/seals",
        ]))
        .unwrap();
        assert_eq!(
            cargs.durable_seals_dir.as_deref(),
            Some(Path::new("D:/seals"))
        );
    }

    #[test]
    fn emit_image_parsed_when_present() {
        let cargs = CycleArgs::from_cli(&s(&[
            "--cycle",
            "1",
            "--module",
            "target_enterprise",
            "--target",
            "D:/x",
            "--emit-image",
        ]))
        .unwrap();
        assert!(cargs.emit_image);
        assert_eq!(cargs.module, "target_enterprise");
    }

    #[test]
    fn emit_image_combines_with_synthesizer() {
        let cargs = CycleArgs::from_cli(&s(&[
            "--cycle",
            "5",
            "--module",
            "target_enterprise",
            "--target",
            "D:/x",
            "--synthesizer",
            "prompt-only",
            "--emit-image",
        ]))
        .unwrap();
        assert!(cargs.emit_image);
        assert_eq!(cargs.synthesizer, SynthesizerKind::PromptOnly);
    }

    #[test]
    fn is_bootable_module_target_enterprise_only() {
        assert!(is_bootable_module("target_enterprise"));
        assert!(!is_bootable_module("target_minimal"));
        assert!(!is_bootable_module("contracts"));
        assert!(!is_bootable_module(""));
    }

    #[test]
    fn cycle_args_default_emit_image_false() {
        let d = CycleArgs::default();
        assert!(!d.emit_image);
    }

    #[test]
    fn unknown_flag_rejected_in_cli_parse() {
        let r = CycleArgs::from_cli(&s(&[
            "--cycle", "1", "--module", "lib", "--target", "D:/x", "--frobnicate",
        ]));
        assert!(r.is_err());
    }
}
