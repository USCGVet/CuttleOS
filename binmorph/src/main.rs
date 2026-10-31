//! `binmorph` — apply the post-link instruction-level diversifier to a
//! compiled ELF, producing a semantically identical but byte-diverse copy.
//!
//!   binmorph --in <kernel.elf> --out <kernel.diversified.elf> --seed <N>
//!
//! Only `.text` bytes inside `STT_FUNC` symbol ranges are rewritten, and
//! only via size-preserving equivalent re-encodings (see the library), so
//! the ELF structure, symbols, relocations, and every address are
//! untouched — the output is a drop-in replacement.

use std::path::Path;

use anyhow::{Context, Result};
pub use cuttle_binmorph::diversify_elf;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let input = flag(&args, "--in").context("--in <elf> required")?;
    let output = flag(&args, "--out").context("--out <elf> required")?;
    let seed: u64 = flag(&args, "--seed")
        .context("--seed <N> required")?
        .parse()
        .context("--seed must be a u64")?;

    let stats = diversify_elf(Path::new(&input), Path::new(&output), seed)?;
    eprintln!(
        "binmorph: seed={} functions={} instrs={} candidates={} swapped={} ({:.1}%) reg_swapped_fns={} reg_remapped_instrs={}",
        seed,
        stats.functions,
        stats.instrs,
        stats.candidates,
        stats.swapped,
        if stats.candidates == 0 {
            0.0
        } else {
            stats.swapped as f64 / stats.candidates as f64 * 100.0
        },
        stats.reg_swapped_fns,
        stats.reg_remapped_instrs,
    );
    // Stdout: the output path, mirroring factory_builder's convention so
    // this can be piped into the packaging step.
    println!("{}", Path::new(&output).display());
    Ok(())
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
