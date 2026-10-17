//! `diversify` CLI — runs the AST diversifier against a single input file
//! and prints the result to stdout. The morph engine invokes this binary
//! during Stage 2 of the factory pipeline.
//!
//! Usage:
//!
//! ```text
//! diversify --cycle <N> --module <NAME> [--stack-pad] <INPUT.rs>
//! ```

use anyhow::{bail, Context, Result};
use std::env;
use std::path::PathBuf;

fn main() -> Result<()> {
    let args: Vec<String> = env::args().collect();
    let (cycle, module, input, stack_pad) = parse_args(&args)?;

    let seed = proteus_diversifier::Seed::derive(cycle, &module);
    // Path-aware entry point enforces `locked_modules.toml`. Stack-pad
    // is OFF by default (gadget-count inflation vs layout seeding);
    // `--stack-pad` re-enables the TASK-029 pass for A/B measurement.
    let options = if stack_pad {
        proteus_diversifier::DiversifyOptions::with_stack_pad()
    } else {
        proteus_diversifier::DiversifyOptions::default()
    };
    let (out, _log) =
        proteus_diversifier::diversify_path_with_log_and_options(&input, &seed, &options)
            .map_err(|e| anyhow::anyhow!("{}", e))?;
    let hash = proteus_diversifier::canonical_hash(&out)?;

    eprintln!(
        "diversified module={} cycle={} stack_pad={} canonical_sha256={}",
        module,
        cycle,
        stack_pad,
        hex(&hash),
    );
    print!("{}", out);
    Ok(())
}

fn parse_args(args: &[String]) -> Result<(u64, String, PathBuf, bool)> {
    let mut cycle: Option<u64> = None;
    let mut module: Option<String> = None;
    let mut input: Option<PathBuf> = None;
    let mut stack_pad = false;

    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--cycle" => {
                cycle = Some(args.get(i + 1).context("--cycle requires a value")?.parse()?);
                i += 2;
            }
            "--module" => {
                module = Some(args.get(i + 1).context("--module requires a value")?.clone());
                i += 2;
            }
            "--stack-pad" => {
                stack_pad = true;
                i += 1;
            }
            "-h" | "--help" => {
                eprintln!(
                    "usage: diversify --cycle <N> --module <NAME> [--stack-pad] <INPUT.rs>\n\
                     \n\
                     --stack-pad   Opt in to TASK-029 stack-frame padding (OFF by default;\n\
                                   production uses layout seeding for offset entropy)."
                );
                std::process::exit(0);
            }
            other if !other.starts_with('-') => {
                input = Some(PathBuf::from(other));
                i += 1;
            }
            other => bail!("unknown argument: {}", other),
        }
    }

    Ok((
        cycle.context("--cycle is required")?,
        module.context("--module is required")?,
        input.context("input source path is required")?,
        stack_pad,
    ))
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
