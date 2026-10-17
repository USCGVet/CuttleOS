//! `diversity_demo` binary — thin CLI wrapper around `run_experiment`.
//!
//! Example:
//!   cargo run -p diversity_demo -- \
//!     --cycles 100 --target target_enterprise --module tls
//!
//! Output files land in `<crate>/results/` (relative to this crate's
//! `CARGO_MANIFEST_DIR`, so the same paths resolve from any CWD).

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use diversity_demo::{
    evaluate_mtd_gate, render_report, run_experiment, ExperimentArgs, MtdGateStatus,
};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let (parsed, require_mtd_gate) = parse_cli(&args[1..])?;
    eprintln!(
        "diversity_demo: cycles={} target={} module={} fast={} layout_seed={} \
         stack_pad={} require_mtd_gate={} kernel_crate={}",
        parsed.cycles,
        parsed.target_dir.display(),
        parsed.module,
        parsed.fast_mode,
        parsed.layout_seed_enabled,
        parsed.stack_pad_enabled,
        require_mtd_gate,
        parsed.kernel_crate_dir.display(),
    );
    let summary = run_experiment(&parsed)?;
    let report_path = render_report(&summary, &parsed.results_dir)?;
    eprintln!(
        "diversity_demo: REPORT written to {}",
        report_path.display()
    );
    eprintln!(
        "diversity_demo: cycles requested={} completed={} rejected={} \
         distinct_text_sha256={} chain_survived_both={}/{}",
        summary.cycles_requested,
        summary.cycles_completed,
        summary.cycles_rejected,
        summary.distinct_text_sha256,
        summary.chain_survived_both,
        summary.chain_total_probes,
    );
    let gate = evaluate_mtd_gate(&summary);
    eprintln!("diversity_demo: {}", gate.summary_line());
    if let MtdGateStatus::Failed { reasons } = &gate {
        for r in reasons {
            eprintln!("diversity_demo:   - {}", r);
        }
    }
    if require_mtd_gate && gate.is_hard_failure() {
        bail!(
            "MTD regression gate did not PASS (got: {}). \
             Re-run with layout seeding enabled (default) and ≥ 2 accepted cycles, \
             or drop --require-mtd-gate for A/B measurement runs.",
            gate.summary_line()
        );
    }
    Ok(())
}

fn parse_cli(args: &[String]) -> Result<(ExperimentArgs, bool)> {
    let mut cycles: u64 = 20;
    let mut target_dir: Option<PathBuf> = None;
    let mut module: Option<String> = None;
    let mut bundle_name: Option<String> = None;
    let mut kernel_crate_dir: Option<PathBuf> = None;
    let mut results_dir: Option<PathBuf> = None;
    let mut fast_mode = false;
    let mut skip_verify = false;
    let mut signing_key_path: Option<PathBuf> = None;
    let mut verify_bin: Option<PathBuf> = None;
    let mut save_candidates = false;
    let mut boot_each_cycle = false;
    let mut layout_seed_enabled = true;
    let mut stack_pad_enabled = false;
    let mut require_mtd_gate = false;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cycles" => {
                cycles = args
                    .get(i + 1)
                    .context("--cycles needs value")?
                    .parse()
                    .context("--cycles must be a non-negative integer")?;
                i += 2;
            }
            "--target" => {
                target_dir = Some(PathBuf::from(args.get(i + 1).context("--target needs value")?));
                i += 2;
            }
            "--module" => {
                module = Some(args.get(i + 1).context("--module needs value")?.clone());
                i += 2;
            }
            "--bundle" => {
                bundle_name = Some(args.get(i + 1).context("--bundle needs value")?.clone());
                i += 2;
            }
            "--kernel-crate" => {
                kernel_crate_dir =
                    Some(PathBuf::from(args.get(i + 1).context("--kernel-crate needs value")?));
                i += 2;
            }
            "--results" => {
                results_dir = Some(PathBuf::from(args.get(i + 1).context("--results needs value")?));
                i += 2;
            }
            "--fast-mode" => {
                fast_mode = true;
                i += 1;
            }
            "--skip-verify" => {
                skip_verify = true;
                i += 1;
            }
            "--save-candidates" => {
                save_candidates = true;
                i += 1;
            }
            "--boot-each-cycle" => {
                boot_each_cycle = true;
                i += 1;
            }
            "--no-layout-seed" => {
                layout_seed_enabled = false;
                i += 1;
            }
            "--stack-pad" => {
                stack_pad_enabled = true;
                i += 1;
            }
            "--require-mtd-gate" => {
                require_mtd_gate = true;
                i += 1;
            }
            "--signing-key" => {
                signing_key_path =
                    Some(PathBuf::from(args.get(i + 1).context("--signing-key needs value")?));
                i += 2;
            }
            "--verify-bin" => {
                verify_bin =
                    Some(PathBuf::from(args.get(i + 1).context("--verify-bin needs value")?));
                i += 2;
            }
            "-h" | "--help" => {
                eprintln!("{}", USAGE);
                std::process::exit(0);
            }
            other => bail!("unknown argument: {} (use --help)", other),
        }
    }

    // Mode resolution:
    //
    //  - --bundle <name>  : look up `[bundle.<name>]` in scheduler.toml
    //                       to resolve membership + target_dir (the
    //                       bundle's declared `workspace` field
    //                       overrides --target if --target is absent).
    //  - --module <name>  : single-module mode (legacy).
    //
    // Either is required. Both are an error.
    let (target_dir, module, bundle_modules) = match (bundle_name.clone(), module.clone()) {
        (Some(b), None) => {
            let (workspace, members) = resolve_bundle_from_scheduler_toml(&b)?;
            // --target overrides the scheduler.toml workspace if both
            // are given; otherwise the bundle's declared workspace wins.
            let td = target_dir.unwrap_or(workspace);
            // The `module` field in bundle mode is just a label used
            // in summaries/reports. Set it to the bundle name.
            (td, b, Some(members))
        }
        (None, Some(m)) => {
            let td = target_dir.context("--target is required (in single-module mode)")?;
            (td, m, None)
        }
        (Some(_), Some(_)) => bail!("--bundle and --module are mutually exclusive"),
        (None, None) => bail!("either --bundle <name> or --module <name> is required"),
    };

    // Resolve target_dir: if user passed a bare name like
    // "target_enterprise", look it up relative to the workspace root
    // (which we discover via this crate's CARGO_MANIFEST_DIR).
    let target_dir = resolve_workspace_relative(target_dir)?;

    let kernel_crate_dir = kernel_crate_dir
        .map(resolve_workspace_relative)
        .transpose()?
        .unwrap_or_else(default_kernel_crate);

    let results_dir = results_dir.unwrap_or_else(default_results_dir);
    let signing_key_path =
        signing_key_path.or_else(|| Some(workspace_root().join("factory_signing_key.bin")));

    Ok((
        ExperimentArgs {
            cycles,
            target_dir,
            module,
            bundle_name,
            bundle_modules,
            kernel_crate_dir,
            results_dir,
            fast_mode,
            skip_verify,
            signing_key_path,
            verify_bin,
            save_candidates,
            boot_each_cycle,
            layout_seed_enabled,
            stack_pad_enabled,
        },
        require_mtd_gate,
    ))
}

/// Read `scheduler.toml` at the workspace root and resolve a
/// `[bundle.<name>]` section to `(workspace_dir, member_list)`. Returns
/// an error if the bundle doesn't exist or the section is malformed.
///
/// Deliberately hand-parses with the `toml` crate so we don't pull in
/// the heavier `proteus_morph_engine::scheduler` crate-resolution path
/// (which would also work but adds a dep).
fn resolve_bundle_from_scheduler_toml(name: &str) -> Result<(PathBuf, Vec<String>)> {
    let path = workspace_root().join("scheduler.toml");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("read scheduler.toml at {}", path.display()))?;
    let value: toml::Value = toml::from_str(&raw)
        .with_context(|| format!("parse scheduler.toml at {}", path.display()))?;
    let bundle_section = value
        .get("bundle")
        .and_then(|v| v.as_table())
        .ok_or_else(|| anyhow::anyhow!("scheduler.toml has no [bundle.*] sections"))?;
    let bundle = bundle_section
        .get(name)
        .ok_or_else(|| anyhow::anyhow!("[bundle.{}] not found in scheduler.toml", name))?;
    let workspace = bundle
        .get("workspace")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("[bundle.{}] missing `workspace` field", name))?
        .to_string();
    let modules_arr = bundle
        .get("modules")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("[bundle.{}] missing `modules` array", name))?;
    let mut modules: Vec<String> = Vec::with_capacity(modules_arr.len());
    for m in modules_arr {
        modules.push(
            m.as_str()
                .ok_or_else(|| anyhow::anyhow!("[bundle.{}] modules entry is not a string: {:?}", name, m))?
                .to_string(),
        );
    }
    if modules.is_empty() {
        bail!("[bundle.{}] modules array is empty", name);
    }
    Ok((PathBuf::from(workspace), modules))
}

fn workspace_root() -> PathBuf {
    // This crate sits at `<root>/experiments/diversity_demo/`. Go up twice.
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    PathBuf::from(manifest_dir)
        .parent()
        .and_then(|p| p.parent())
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(manifest_dir))
}

fn default_kernel_crate() -> PathBuf {
    workspace_root().join("target_enterprise_kernel")
}

fn default_results_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results")
}

fn resolve_workspace_relative(p: PathBuf) -> Result<PathBuf> {
    if p.is_absolute() && p.exists() {
        return Ok(p);
    }
    // If it's a bare name, prefix with workspace root.
    let candidate = workspace_root().join(&p);
    if candidate.exists() {
        return Ok(candidate);
    }
    // Maybe relative to CWD?
    if p.exists() {
        return Ok(p);
    }
    bail!(
        "diversity_demo: could not resolve path {} (tried as absolute, \
         workspace-relative, and CWD-relative)",
        p.display()
    );
}

const USAGE: &str = "diversity_demo — measure morph diversity + synthetic-chain survival

USAGE:
  diversity_demo --cycles N --target <DIR_OR_NAME> --module <NAME> [options]

REQUIRED:
  --cycles N            Number of cycles to drive.
  --target <P>          Path to the workspace member dir (e.g. target_enterprise)
                        or its bare name. The source file morphed is
                        <P>/src/<MODULE>.rs.
  --module <NAME>       Module name (e.g. tls).

OPTIONAL:
  --kernel-crate <P>    Path to the out-of-workspace kernel crate.
                        Defaults to <workspace>/target_enterprise_kernel.
  --results <DIR>       Where cycles.jsonl, diversity.jsonl, survival.jsonl,
                        REPORT.md land. Defaults to <crate>/results.
  --fast-mode           Skip the real kernel build; synthesise a
                        deterministic pseudo-ELF from the candidate hash.
                        For tests only.
  --skip-verify         Skip the verifier subprocess. Useful when the
                        verify binary isn't on PATH (CI without prebuild).
  --signing-key <P>     Path to ed25519 signing key. Defaults to
                        <workspace>/factory_signing_key.bin if it exists,
                        otherwise an ephemeral deterministic key is used.
  --verify-bin <P>      Override the verifier-binary discovery.
  --save-candidates     Save each accepted cycle's diversified source
                        to <results>/candidates/cycle_NN.rs. Used by
                        the `dedup_diag` tool (TASK-024) to classify
                        ELF-`.text` collisions into AST-equivalent vs
                        codegen-folded buckets. Off by default.
  --boot-each-cycle     TASK-026: after each accepted cycle, package
                        the kernel ELF as a BIOS image, boot it under
                        QEMU with a per-cycle `-serial file:` target,
                        and record the captured log's sha256 in
                        cycles.jsonl. Adds ~10 s/cycle. Ignored when
                        --fast-mode is also set (no real ELF exists).
                        Off by default to preserve current wall-clock.
  --no-layout-seed      Disable the per-cycle kernel layout seed
                        (Phase-1 codegen diversity:
                        -Zrandomize-layout=yes -Zlayout-seed=N
                        -Zfunction-sections=yes
                        -Clink-arg=--shuffle-sections=.text*=N).
                        Seeding is ON by default — it is the lever
                        that actually relocates function offsets
                        between cycles (TASK-025 showed the AST-level
                        diversifier alone leaves them frozen). Use
                        this flag to reproduce the historical
                        deterministic-layout build for A/B runs.
  --stack-pad           Opt in to TASK-029 stack-frame padding in the
                        AST diversifier. OFF by default: pads inflate
                        gadget count (~+33% measured) without buying
                        chain-death once layout seeding is engaged.
  --require-mtd-gate    Exit non-zero unless the MTD regression gate
                        PASSES (layout seed on, layouts relocate every
                        cycle, synthetic chain survival 0, probe not
                        on fallback). Use this for CI proof runs:
                          cargo run -p diversity_demo --release -- \
                            --cycles 4 --target target_enterprise \
                            --module tls --fast-mode --skip-verify \
                            --require-mtd-gate
                        NOTE: changing RUSTFLAGS per cycle invalidates
                        cargo's cache, so seeded cycles rebuild
                        build-std from cold (~tens of seconds/cycle
                        instead of ~1.5 s).
";
