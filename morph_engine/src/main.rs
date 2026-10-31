//! `morph` — the factory orchestrator CLI.
//!
//! Subcommands:
//!
//! - `morph init-key` — generate the software factory signing key.
//! - `morph run --cycle N --module NAME --target DIR [--manifest FILE]`
//!   Run one explicit morph cycle for one operator-specified module.
//! - `morph next` — consult `scheduler.toml` + `scheduler_state.json`,
//!   print the next due module and the cycle number that would be used,
//!   or exit 64 if nothing is due.
//! - `morph tick` — combined `next` + `run`. Runs the picked cycle
//!   in-process and updates `scheduler_state.json` on success.
//!
//! The library half (`cuttle_morph_engine`) exposes the cycle logic
//! and the scheduler so both `run` and `tick` use the same code path
//! without re-spawning a process.

use anyhow::{bail, Context, Result};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use cuttle_morph_engine::{
    attest::{
        load_anchors, load_entries, parse_hex32, rebuild_anchors_after_cosign,
        rebuild_chain_after_cosign, write_chain_atomic,
    },
    daemon::{run_daemon, DaemonArgs},
    durable_seal_file, durable_verify_file, factory,
    federation::{self, Cosignature},
    init_signing_key, load_state, pick_next, pick_next_work, recompute_merkle_root_from_disk,
    run_bundle, run_cycle, save_state,
    scheduler::{load_config, record_success, record_success_bundle},
    verify_chain_with_options, BundleCycleArgs, CycleArgs, MerkleRootStatus, NextWork,
    VerifyOptions, EX_NOINPUT, SCHEDULER_CONFIG, SCHEDULER_STATE,
};

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
        std::process::exit(2);
    }
    match args[1].as_str() {
        "run" => {
            let cargs = CycleArgs::from_cli(&args[2..])?;
            run_cycle(&cargs)
        }
        "run-bundle" => {
            let bargs = BundleCycleArgs::from_cli(&args[2..])?;
            run_bundle(&bargs)
        }
        "propose" => {
            // Proposer role (no signing key): stages 1–3, write proposal.
            let (cargs, out) = parse_propose_cli(&args[2..])?;
            cuttle_morph_engine::propose_cycle(&cargs, &out)
        }
        "attest-proposal" => {
            // Verifier role (holds the key): independent re-verify,
            // deploy, sign, attest.
            let (cargs, file) = parse_attest_proposal_cli(&args[2..])?;
            cuttle_morph_engine::attest_proposal(&cargs, &file)
        }
        "init-key" => init_signing_key(),
        "next" => cmd_next(),
        "tick" => cmd_tick(),
        "daemon" => cmd_daemon(&args[2..]),
        "verify-attest" => cmd_verify_attest(&args[2..]),
        "seal" => cmd_seal(&args[2..]),
        "verify-seal" => cmd_verify_seal(&args[2..]),
        "recompute-merkle-root" => cmd_recompute_merkle_root(),
        "factory-fingerprint" => cmd_factory_fingerprint(&args[2..]),
        "cosign" => cmd_cosign(&args[2..]),
        "rollback-bundle" => cmd_rollback_bundle(&args[2..]),
        "sign-policy" => cmd_sign_policy(&args[2..]),
        "tui" => cmd_tui(&args[2..]),
        "-h" | "--help" => {
            usage();
            Ok(())
        }
        other => bail!("unknown subcommand: {}", other),
    }
}

fn usage() {
    eprintln!(
        "usage:\n  \
         morph run --cycle <N> --module <NAME> --target <DIR> [--manifest <FILE>] [--synthesizer <KIND>] [--emit-image] [--durable-seals-dir DIR]\n    \
           --synthesizer: passthrough (default) | prompt-only | anthropic\n    \
           anthropic requires ANTHROPIC_API_KEY (optional ANTHROPIC_MODEL override)\n    \
           --emit-image: for bootable targets (target_enterprise), package a BIOS image\n    \
                          via factory_builder + record image_sha256 in attestation\n    \
           --durable-seals-dir: attach DurableSeal JSON files as durable_seals on attest (TASK-146);\n    \
                          or set CUTTLE_DURABLE_SEALS_DIR (daemon uses env only)\n  \
         morph run-bundle --cycle <N> --bundle <NAME> --workspace <DIR> --module <M1> [--module <M2> ...] [--manifest <FILE>] [--synthesizer <KIND>] [--durable-seals-dir DIR]\n    \
           atomic multi-module morph cycle. Every member diversifies under its own seed,\n    \
           the whole set verifies as one workspace build, the attestation entry records\n    \
           the bundle hash + per-module artefacts (schema v5).\n  \
         morph rollback-bundle <NAME> [--config <PATH>]\n    \
           atomically restore every module in bundle <NAME> from <module>.last_good.rs.\n  \
         morph init-key\n  \
         morph next\n  \
         morph tick      (now also handles [bundle.NAME] entries in scheduler.toml)\n  \
         morph daemon [--root <DIR>] [--max-iters <N>] [--max-cycle-secs <N>] [--heartbeat-secs <N>] [--poll-secs <N>] [--synthesizer <KIND>] [--emit-image] [--no-perf-check]\n    \
           run cycles continuously per scheduler.toml. --max-iters 0 (default) = forever.\n    \
           heartbeats land in <root>/daemon.log; cycle accept/reject events too.\n    \
           --no-perf-check: skip verifier perf gate (short soaks / semantics-only).\n  \
         morph verify-attest [--require-threshold] [--require-merkle-root] [--strict-factory]\n    \
           [--factory-expected <PATH>] [--require-ext-tlv] [--allow-missing-ext-tlv]\n    \
           [--require-diversity] [--require-durable-seals] [--production]\n    \
           default: require ext_tlv_b64 (schema v8+). Use --allow-missing-ext-tlv for pre-v8 logs.\n    \
           --require-diversity: accepted entries must carry non-empty diversity (TASK-125).\n    \
           --require-durable-seals: accepted entries must carry non-empty durable_seals (TASK-144).\n    \
           --production: enforce M-of-N threshold >= 2, merkle-root, strict-factory, and signed policy TOMLs.\n  \
         morph seal --label <L> --in <PATH> --out <SEAL.json>\n    \
           hash-seal a durable blob (TASK-143); writes DurableSeal JSON.\n  \
         morph verify-seal --seal <SEAL.json> --in <PATH>\n    \
           verify file bytes match a seal (TASK-143).\n  \
         morph recompute-merkle-root\n  \
         morph factory-fingerprint [--toml]\n    \
           prints per-component sha256 of the current factory binaries (TASK-022).\n    \
           --toml emits a starter factory_expected.toml block ready to paste.\n  \
         morph cosign --signer <ID> --seed-file <PATH> [--all]\n  \
         morph tui [--root <PATH>] [--ticks <N>]\n    \
           live operator dashboard (4 tabs). --ticks N is a hidden\n    \
           CI-friendly mode that draws N frames against a TestBackend\n    \
           and exits — no real terminal needed."
    );
}

/// Parse `morph propose` args: standard cycle args plus `--out FILE`.
fn parse_propose_cli(args: &[String]) -> Result<(CycleArgs, PathBuf)> {
    let mut filtered: Vec<String> = Vec::new();
    let mut out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--out" {
            out = Some(PathBuf::from(args.get(i + 1).context("--out needs value")?));
            i += 2;
        } else {
            filtered.push(args[i].clone());
            i += 1;
        }
    }
    let cargs = CycleArgs::from_cli(&filtered)?;
    Ok((cargs, out.context("--out is required")?))
}

/// Parse `morph attest-proposal` args: standard cycle args plus `--file FILE`.
fn parse_attest_proposal_cli(args: &[String]) -> Result<(CycleArgs, PathBuf)> {
    let mut filtered: Vec<String> = Vec::new();
    let mut file: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        if args[i] == "--file" {
            file = Some(PathBuf::from(args.get(i + 1).context("--file needs value")?));
            i += 2;
        } else {
            filtered.push(args[i].clone());
            i += 1;
        }
    }
    let cargs = CycleArgs::from_cli(&filtered)?;
    Ok((cargs, file.context("--file is required")?))
}

/// `morph next`: print the next due module + cycle number, or exit 64.
fn cmd_next() -> Result<()> {    let cfg = match load_config(Path::new(SCHEDULER_CONFIG)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("morph: {:#}", e);
            std::process::exit(1);
        }
    };
    let state = match load_state(Path::new(SCHEDULER_STATE)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("morph: {:#}", e);
            std::process::exit(1);
        }
    };
    match pick_next(&cfg, &state) {
        Some(choice) => {
            println!("module={} next_cycle={}", choice.module, choice.next_cycle);
            Ok(())
        }
        None => std::process::exit(EX_NOINPUT),
    }
}

/// `morph tick`: pick the next due module and run a full cycle for it
/// in-process, updating scheduler state on success.
fn cmd_tick() -> Result<()> {
    let cfg = match load_config(Path::new(SCHEDULER_CONFIG)) {
        Ok(c) => c,
        Err(e) => {
            eprintln!("morph: {:#}", e);
            std::process::exit(1);
        }
    };
    let mut state = match load_state(Path::new(SCHEDULER_STATE)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("morph: {:#}", e);
            std::process::exit(1);
        }
    };
    // Use the unified picker so `[bundle.NAME]` entries in
    // scheduler.toml compete with `[modules.NAME]` entries on the same
    // priority/age scoring. Whichever is highest-priority among due
    // items runs this tick. Falls back to `pick_next` semantics when
    // no bundles are declared (the legacy single-module flow).
    let work = match pick_next_work(&cfg, &state) {
        Some(w) => w,
        None => std::process::exit(EX_NOINPUT),
    };

    match work {
        NextWork::Module(choice) => {
            let cargs = CycleArgs {
                cycle: choice.next_cycle,
                module: choice.module.clone(),
                target_dir: choice.config.target_dir.clone(),
                manifest: choice.config.manifest.clone(),
                synthesizer: Default::default(),
                emit_image: false,
                no_perf_check: false,
                durable_seals_dir: None,
            };
            if let Err(e) = run_cycle(&cargs) {
                eprintln!("morph: cycle failed: {:#}", e);
                std::process::exit(1);
            }
            record_success(&mut state, &choice.module, choice.next_cycle);
        }
        NextWork::Bundle(choice) => {
            let bargs = BundleCycleArgs {
                cycle: choice.next_cycle,
                bundle_name: choice.bundle.clone(),
                workspace: choice.config.workspace.clone(),
                modules: choice.config.modules.clone(),
                manifest: choice.config.manifest.clone(),
                synthesizer: Default::default(),
                emit_image: false,
                no_perf_check: false,
                durable_seals_dir: None,
            };
            if let Err(e) = run_bundle(&bargs) {
                eprintln!("morph: bundle cycle failed: {:#}", e);
                std::process::exit(1);
            }
            record_success_bundle(&mut state, &choice.bundle, choice.next_cycle);
        }
    }
    save_state(Path::new(SCHEDULER_STATE), &state)?;
    Ok(())
}

/// `morph daemon …`: TASK-012 live morph-cycle orchestrator. Loops
/// over `pick_next_work`, runs the picked cycle in-process, writes
/// events + heartbeats to `<root>/daemon.log`, and exits cleanly when
/// `--max-iters` is reached (or never, with the default `0`).
fn cmd_daemon(args: &[String]) -> Result<()> {
    let dargs = DaemonArgs::from_cli(args)?;
    let report = run_daemon(&dargs)?;
    println!(
        "morph: daemon stopped. ticks={} accepted={} rejected={} overrun={} heartbeats={} idle={}",
        report.ticks_executed,
        report.cycles_accepted,
        report.cycles_rejected,
        report.cycles_overrun,
        report.heartbeats_written,
        report.idle_ticks,
    );
    Ok(())
}

/// `morph tui [--root <PATH>] [--ticks <N>]`: launch the operator
/// dashboard. `--root` defaults to `.`. `--ticks <N>` is a hidden
/// CI-only mode: instead of opening the terminal, render `N` frames
/// to a `TestBackend` and exit `Ok(())`. This lets the smoke test
/// exercise every render path on a headless Windows runner without a
/// real TTY.
fn cmd_tui(args: &[String]) -> Result<()> {
    let mut root = PathBuf::from(".");
    let mut ticks: Option<usize> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--root" => {
                root = PathBuf::from(args.get(i + 1).context("--root needs value")?);
                i += 2;
            }
            "--ticks" => {
                let n: usize = args
                    .get(i + 1)
                    .context("--ticks needs value")?
                    .parse()
                    .context("--ticks must be a non-negative integer")?;
                ticks = Some(n);
                i += 2;
            }
            other => bail!("unknown argument to tui: {}", other),
        }
    }
    cuttle_morph_engine::tui::run_tui_with_options(&root, ticks)
}

/// `morph verify-attest`: walk the attestation log + Merkle-anchor log
/// and verify hash-chain + Merkle-root integrity.
///
/// **Defaults (TASK-106):** `ext_tlv_b64` presence is **required**
/// (every post-v8 write emits it). Pass `--allow-missing-ext-tlv` to
/// verify pre-v8 historical chains. Corrupt TLV/Base64 always fails.
///
/// Optional: `--require-threshold`, `--require-merkle-root`,
/// `--strict-factory`, `--require-ext-tlv` (explicit; same as default),
/// `--require-diversity` (TASK-125), `--require-durable-seals` (TASK-144).
fn cmd_verify_attest(args: &[String]) -> Result<()> {
    let mut opts = VerifyOptions::default();
    let mut production = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--production" => {
                production = true;
                opts.require_threshold = true;
                opts.require_merkle_root = true;
                opts.require_strict_factory = true;
                opts.require_ext_tlv = true;
                i += 1;
            }
            "--require-threshold" => {
                opts.require_threshold = true;
                i += 1;
            }
            "--require-merkle-root" => {
                opts.require_merkle_root = true;
                i += 1;
            }
            "--strict-factory" => {
                opts.require_strict_factory = true;
                i += 1;
            }
            "--require-ext-tlv" => {
                // Explicit (default is already true since TASK-106).
                opts.require_ext_tlv = true;
                i += 1;
            }
            "--allow-missing-ext-tlv" => {
                // Legacy cutover: pre-v8 logs without ext_tlv_b64.
                opts.require_ext_tlv = false;
                i += 1;
            }
            "--require-diversity" => {
                // TASK-125: accepted entries must carry diversity evidence.
                opts.require_diversity = true;
                i += 1;
            }
            "--require-durable-seals" => {
                // TASK-144: accepted entries must carry durable_seals.
                opts.require_durable_seals = true;
                i += 1;
            }
            "--factory-expected" => {
                opts.factory_expected_path = Some(PathBuf::from(
                    args.get(i + 1).context("--factory-expected needs value")?,
                ));
                i += 2;
            }
            "--federation-config" => {
                opts.federation_config =
                    Some(PathBuf::from(args.get(i + 1).context("--federation-config needs value")?));
                i += 2;
            }
            other => bail!("unknown argument to verify-attest: {}", other),
        }
    }
    if production {
        let fed_path = opts
            .federation_config
            .clone()
            .unwrap_or_else(federation::resolve_federation_path);
        let fed = federation::load_federation(&fed_path)
            .with_context(|| format!("load federation config {}", fed_path.display()))?;
        federation::verify_production_keyset(&fed)?;
        let exp_path = opts
            .factory_expected_path
            .clone()
            .unwrap_or_else(factory::resolve_factory_expected_path);
        factory::load_and_verify_signed_factory_expected(&exp_path, &fed)?;
        let locked_path = PathBuf::from("locked_modules.toml");
        if locked_path.exists() {
            factory::verify_signed_locked_modules(&locked_path, &fed)?;
        }
    }
    match verify_chain_with_options(&opts) {
        Ok(report) => {
            let root_note = match report.merkle_root_verified {
                Some(MerkleRootStatus::Ok) => " (rolling root OK)",
                Some(MerkleRootStatus::Absent) => " (rolling root absent — legacy log)",
                None => "",
            };
            let factory_note = match report.factory_verified {
                Some(n) => format!(" (strict-factory: {} entries verified)", n),
                None => String::new(),
            };
            let ext_note = if opts.require_ext_tlv {
                " (ext_tlv required)"
            } else {
                " (ext_tlv optional — legacy mode)"
            };
            let div_note = if opts.require_diversity {
                " (diversity required)"
            } else {
                ""
            };
            let seal_note = if opts.require_durable_seals {
                " (durable_seals required)"
            } else {
                ""
            };
            println!(
                "verify-attest: {} entries OK, {} anchors OK{}{}{}{}{}{}",
                report.entries_ok,
                report.anchors_ok,
                if opts.require_threshold {
                    " (threshold enforced)"
                } else {
                    ""
                },
                root_note,
                factory_note,
                ext_note,
                div_note,
                seal_note,
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("{:#}", e);
            std::process::exit(1);
        }
    }
}

/// `morph seal --label L --in PATH --out SEAL.json` (TASK-143).
fn cmd_seal(args: &[String]) -> Result<()> {
    let mut label: Option<String> = None;
    let mut in_path: Option<PathBuf> = None;
    let mut out_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--label" => {
                label = Some(args.get(i + 1).context("--label needs value")?.clone());
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).context("--in needs value")?,
                ));
                i += 2;
            }
            "--out" => {
                out_path = Some(PathBuf::from(
                    args.get(i + 1).context("--out needs value")?,
                ));
                i += 2;
            }
            other => bail!("unknown argument to seal: {}", other),
        }
    }
    let label = label.context("morph seal requires --label")?;
    let in_path = in_path.context("morph seal requires --in")?;
    let out_path = out_path.context("morph seal requires --out")?;
    let seal = durable_seal_file(&label, &in_path)?;
    seal.write_file(&out_path)?;
    println!(
        "seal: label={} len={} sha256={} out={}",
        seal.label,
        seal.len,
        seal.sha256,
        out_path.display()
    );
    Ok(())
}

/// `morph verify-seal --seal SEAL.json --in PATH` (TASK-143).
fn cmd_verify_seal(args: &[String]) -> Result<()> {
    let mut seal_path: Option<PathBuf> = None;
    let mut in_path: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--seal" => {
                seal_path = Some(PathBuf::from(
                    args.get(i + 1).context("--seal needs value")?,
                ));
                i += 2;
            }
            "--in" => {
                in_path = Some(PathBuf::from(
                    args.get(i + 1).context("--in needs value")?,
                ));
                i += 2;
            }
            other => bail!("unknown argument to verify-seal: {}", other),
        }
    }
    let seal_path = seal_path.context("morph verify-seal requires --seal")?;
    let in_path = in_path.context("morph verify-seal requires --in")?;
    durable_verify_file(&seal_path, &in_path)?;
    println!(
        "verify-seal: OK seal={} data={}",
        seal_path.display(),
        in_path.display()
    );
    Ok(())
}

/// `morph recompute-merkle-root`: re-derive the rolling root from the
/// current on-disk attest log and rewrite the sidecar. The hourly loop
/// keeps the sidecar in lock-step on its own; this subcommand exists for
/// the upgrade path (existing factory state from before TASK-013) and
/// for operators who repaired a corrupt log by hand.
fn cmd_recompute_merkle_root() -> Result<()> {
    let f = recompute_merkle_root_from_disk()?;
    println!(
        "recompute-merkle-root: entry_count={} merkle_root={}",
        f.entry_count, f.merkle_root
    );
    Ok(())
}

/// `morph factory-fingerprint [--toml]`
///
/// Print the live factory-binary SHA-256 fingerprint, one component
/// per line in `component=hex` form. Use `--toml` to emit a
/// `factory_expected.toml`-ready block. Operators bootstrap a fresh
/// `factory_expected.toml` by:
///
///   1. Building the workspace.
///   2. Running `morph factory-fingerprint --toml > factory_expected.toml`.
///   3. Reviewing — every hash is a commitment.
///   4. Adding alternative hashes for any tool whose build is expected
///      to change soon (e.g. rustc updates).
///
/// The subcommand always re-fingerprints (no cache) so it reflects the
/// current binary set, not a stale state from earlier in the process.
fn cmd_factory_fingerprint(args: &[String]) -> Result<()> {
    let mut emit_toml = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--toml" => {
                emit_toml = true;
                i += 1;
            }
            other => bail!("unknown argument to factory-fingerprint: {}", other),
        }
    }
    let map = factory::fingerprint_uncached();
    if map.is_empty() {
        bail!("factory-fingerprint: no components could be hashed");
    }
    if emit_toml {
        println!("# Generated by `morph factory-fingerprint --toml`. Review every");
        println!("# entry before committing — these hashes are the strict-mode trust root.");
        let required: Vec<String> = map.keys().cloned().collect();
        let required_toml = required
            .iter()
            .map(|s| format!("\"{}\"", s))
            .collect::<Vec<_>>()
            .join(", ");
        println!("required = [{}]", required_toml);
        println!();
        println!("[components]");
        for (k, v) in &map {
            println!("{} = [\"{}\"]", k, v);
        }
    } else {
        for (k, v) in &map {
            println!("{}={}", k, v);
        }
    }
    Ok(())
}

/// `morph cosign --signer <ID> --seed-file <PATH> [--all]`
///
/// Append a cosignature from the named federation signer to attestation
/// entries. Without `--all`, only the most recent entry is touched;
/// with `--all`, every entry that does not yet carry a cosig from this
/// signer is touched. After modification we rebuild the hash chain
/// forward from the first modified entry and regenerate any Merkle
/// anchors that intersect the modified range, then atomically rewrite
/// both logs.
fn cmd_cosign(args: &[String]) -> Result<()> {
    let mut signer_id: Option<String> = None;
    let mut seed_file: Option<PathBuf> = None;
    let mut all = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--signer" => {
                signer_id = Some(args.get(i + 1).context("--signer needs value")?.clone());
                i += 2;
            }
            "--seed-file" => {
                seed_file =
                    Some(PathBuf::from(args.get(i + 1).context("--seed-file needs value")?));
                i += 2;
            }
            "--all" => {
                all = true;
                i += 1;
            }
            other => bail!("unknown argument to cosign: {}", other),
        }
    }
    let signer_id = signer_id.context("--signer is required")?;
    let seed_file = seed_file.context("--seed-file is required")?;

    let fed_path = federation::resolve_federation_path();
    let fed = federation::load_federation(&fed_path)
        .with_context(|| format!("load federation config {}", fed_path.display()))?;
    let signer = fed
        .signers
        .iter()
        .find(|s| s.id == signer_id)
        .ok_or_else(|| anyhow::anyhow!("signer '{}' not found in {}", signer_id, fed_path.display()))?;

    let seed_bytes = fs::read(&seed_file)
        .with_context(|| format!("read seed file {}", seed_file.display()))?;
    if seed_bytes.len() != 32 {
        bail!(
            "seed file {} has wrong length {} (expected 32)",
            seed_file.display(),
            seed_bytes.len()
        );
    }
    let mut seed = [0u8; 32];
    seed.copy_from_slice(&seed_bytes);
    let sk = ed25519_dalek::SigningKey::from_bytes(&seed);
    let derived_pk: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    if derived_pk != signer.pubkey_hex {
        bail!(
            "seed file {} produces pubkey {} but federation config has {} for signer '{}'",
            seed_file.display(),
            derived_pk,
            signer.pubkey_hex,
            signer_id
        );
    }

    let mut entries = load_entries()?;
    if entries.is_empty() {
        bail!("no attestation entries to cosign");
    }
    let mut anchors = load_anchors()?;

    let targets: Vec<usize> = if all {
        (0..entries.len()).collect()
    } else {
        vec![entries.len() - 1]
    };
    let mut first_modified: Option<usize> = None;
    let mut touched = 0usize;
    let mut skipped = 0usize;
    use ed25519_dalek::Signer as _;
    for idx in targets {
        if entries[idx]
            .cosignatures
            .iter()
            .any(|c| c.signer_id == signer_id)
        {
            skipped += 1;
            continue;
        }
        let cand = parse_hex32(&entries[idx].candidate_sha256).with_context(|| {
            format!("entry {} candidate_sha256 malformed", idx)
        })?;
        let sig = sk.sign(&cand);
        let sig_hex: String = sig.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
        entries[idx].cosignatures.push(Cosignature {
            signer_id: signer_id.clone(),
            sig_ed25519: sig_hex,
        });
        if first_modified.map_or(true, |f| idx < f) {
            first_modified = Some(idx);
        }
        touched += 1;
    }
    if let Some(start) = first_modified {
        rebuild_chain_after_cosign(&mut entries, start)?;
        rebuild_anchors_after_cosign(&entries, &mut anchors, start)?;
        write_chain_atomic(&entries, &anchors)?;
    }
    eprintln!(
        "morph: cosign signer={} touched={} skipped={} (already-cosigned)",
        signer_id, touched, skipped
    );
    Ok(())
}

/// `morph rollback-bundle <NAME> [--config <PATH>]` (`R15`).
fn cmd_rollback_bundle(args: &[String]) -> Result<()> {
    let mut bundle_name: Option<String> = None;
    let mut cfg_path = PathBuf::from(SCHEDULER_CONFIG);
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--config" => {
                cfg_path = PathBuf::from(args.get(i + 1).context("--config needs value")?);
                i += 2;
            }
            s if !s.starts_with('-') && bundle_name.is_none() => {
                bundle_name = Some(s.to_string());
                i += 1;
            }
            other => bail!("unknown argument to rollback-bundle: {}", other),
        }
    }
    let bundle_name = bundle_name.context("morph rollback-bundle requires <NAME>")?;
    let cfg = load_config(&cfg_path)?;
    let restored = cuttle_morph_engine::rollback_bundle(&cfg, &bundle_name)?;
    println!(
        "rollback-bundle: bundle={} restored_modules={}",
        bundle_name, restored
    );
    Ok(())
}

/// `morph sign-policy <PATH> [--signer <ID>]` (`R3`).
fn cmd_sign_policy(args: &[String]) -> Result<()> {
    let mut path: Option<PathBuf> = None;
    let mut signer_id = String::from("primary");
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--signer" => {
                signer_id = args.get(i + 1).context("--signer needs value")?.clone();
                i += 2;
            }
            s if !s.starts_with('-') && path.is_none() => {
                path = Some(PathBuf::from(s));
                i += 1;
            }
            other => bail!("unknown argument to sign-policy: {}", other),
        }
    }
    let path = path.context("morph sign-policy requires <PATH>")?;
    let raw = fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
    let stripped: Vec<&str> = raw
        .lines()
        .filter(|l| !l.trim().starts_with(factory::POLICY_SIG_PREFIX))
        .collect();
    let base = stripped.join("\n") + "\n";
    let sk = cuttle_morph_engine::load_signing_key()?;
    let signed = factory::sign_policy_toml_str(&base, &signer_id, &sk);
    fs::write(&path, signed).with_context(|| format!("write {}", path.display()))?;
    println!("sign-policy: signed {} with signer={}", path.display(), signer_id);
    Ok(())
}
