//! `dedup_diag` binary — TASK-024 entry point.
//!
//! Reads `cycles.jsonl` from a `diversity_demo` run, groups accepted
//! cycles by their `elf_text_sha256`, surfaces every collision
//! cluster, and (when candidate source files have been preserved via
//! `diversity_demo --save-candidates`) runs `cargo rustc --emit=mir`
//! against each colliding candidate pair to classify the collision as
//! AST-equivalent (MIR identical → diversifier produced semantically-
//! redundant rewrites) or codegen-folded (MIR distinct → LLVM folded
//! morphs back into the same machine code).
//!
//! USAGE:
//!   dedup_diag --cycles-jsonl <path> [options]
//!
//! See `--help` for the full flag list.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

use dedup_diag::{run_diagnosis, MirSettings};

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let parsed = parse_cli(&args[1..])?;

    let mir_settings = if parsed.mir_check {
        let workspace_root = parsed
            .workspace_root
            .clone()
            .context("--mir-check requires --workspace-root")?;
        let target_dir = workspace_root.join("target_enterprise");
        Some(MirSettings {
            workspace_root,
            target_enterprise_dir: target_dir,
            module_filename: parsed.module_filename.clone(),
        })
    } else {
        None
    };

    let summary = run_diagnosis(
        &parsed.cycles_jsonl,
        parsed.candidates_dir.as_deref(),
        mir_settings.as_ref(),
    )?;

    if let Some(out) = &parsed.output_markdown {
        std::fs::write(out, &summary.markdown)
            .with_context(|| format!("write markdown to {}", out.display()))?;
        eprintln!("dedup_diag: markdown written to {}", out.display());
    } else {
        print!("{}", summary.markdown);
    }

    eprintln!(
        "dedup_diag: accepted={} distinct={} clusters={} redundant={} \
         labels: ast_equivalent={} codegen_folded={} indeterminate={}",
        summary.total_accepted_cycles,
        summary.distinct_elf_text_sha256,
        summary.cluster_count,
        summary.redundant_cycle_count,
        summary.ast_equivalent_pairs,
        summary.codegen_folded_pairs,
        summary.indeterminate_pairs,
    );
    if let Some(out) = &parsed.output_json {
        let bytes = serde_json::to_vec_pretty(&summary)?;
        std::fs::write(out, &bytes)
            .with_context(|| format!("write JSON to {}", out.display()))?;
        eprintln!("dedup_diag: JSON written to {}", out.display());
    }
    Ok(())
}

struct Cli {
    cycles_jsonl: PathBuf,
    candidates_dir: Option<PathBuf>,
    mir_check: bool,
    workspace_root: Option<PathBuf>,
    module_filename: String,
    output_markdown: Option<PathBuf>,
    output_json: Option<PathBuf>,
}

fn parse_cli(args: &[String]) -> Result<Cli> {
    let mut cycles_jsonl: Option<PathBuf> = None;
    let mut candidates_dir: Option<PathBuf> = None;
    let mut mir_check = false;
    let mut workspace_root: Option<PathBuf> = None;
    let mut module_filename = String::from("tls.rs");
    let mut output_markdown: Option<PathBuf> = None;
    let mut output_json: Option<PathBuf> = None;

    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--cycles-jsonl" => {
                cycles_jsonl = Some(PathBuf::from(
                    args.get(i + 1).context("--cycles-jsonl needs value")?,
                ));
                i += 2;
            }
            "--candidates-dir" => {
                candidates_dir = Some(PathBuf::from(
                    args.get(i + 1).context("--candidates-dir needs value")?,
                ));
                i += 2;
            }
            "--mir-check" => {
                mir_check = true;
                i += 1;
            }
            "--workspace-root" => {
                workspace_root = Some(PathBuf::from(
                    args.get(i + 1).context("--workspace-root needs value")?,
                ));
                i += 2;
            }
            "--module-filename" => {
                module_filename =
                    args.get(i + 1).context("--module-filename needs value")?.clone();
                i += 2;
            }
            "--output-markdown" => {
                output_markdown = Some(PathBuf::from(
                    args.get(i + 1).context("--output-markdown needs value")?,
                ));
                i += 2;
            }
            "--output-json" => {
                output_json = Some(PathBuf::from(
                    args.get(i + 1).context("--output-json needs value")?,
                ));
                i += 2;
            }
            "-h" | "--help" => {
                eprintln!("{}", USAGE);
                std::process::exit(0);
            }
            other => bail!("dedup_diag: unknown argument: {}", other),
        }
    }

    let cycles_jsonl = cycles_jsonl.context("--cycles-jsonl is required")?;

    Ok(Cli {
        cycles_jsonl,
        candidates_dir,
        mir_check,
        workspace_root,
        module_filename,
        output_markdown,
        output_json,
    })
}

const USAGE: &str = "dedup_diag — classify ELF .text collisions in a diversity_demo run

USAGE:
  dedup_diag --cycles-jsonl <path> [--candidates-dir <path>] [--mir-check]
             [--workspace-root <path>] [--module-filename <name>]
             [--output-markdown <path>] [--output-json <path>]

REQUIRED:
  --cycles-jsonl <P>     Path to the cycles.jsonl produced by
                         `diversity_demo`. Required.

OPTIONAL:
  --candidates-dir <P>   Directory of saved per-cycle candidate sources
                         (cycle_NN.rs). Produced by `diversity_demo
                         --save-candidates`. Without this, source diffs
                         and MIR classification are skipped.
  --mir-check            Run the MIR-emit classification step: for each
                         colliding pair, install the candidate at
                         <workspace>/target_enterprise/src/<module>,
                         run `cargo rustc --emit=mir`, sha256 the result,
                         compare. Requires --workspace-root.
  --workspace-root <P>   Path to the Proteus workspace root. Required
                         when --mir-check is set.
  --module-filename <N>  Source filename inside target_enterprise/src/
                         that the diversifier rewrites. Default `tls.rs`.
  --output-markdown <P>  Write Markdown report to file. Default stdout.
  --output-json <P>      Write full structured summary as JSON to file.
                         Useful for downstream tooling.
";
