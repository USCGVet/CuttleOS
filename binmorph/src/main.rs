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

use anyhow::{bail, Context, Result};
use object::{Object, ObjectSection, ObjectSymbol, SymbolKind};
use cuttle_binmorph::{rewrite_function, Prng, Stats};

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

/// Read `input`, rewrite the code inside every `.text` function, write
/// `output`. Returns the rewrite statistics.
pub fn diversify_elf(input: &Path, output: &Path, seed: u64) -> Result<Stats> {
    let data = std::fs::read(input).with_context(|| format!("read {}", input.display()))?;

    // Determine `.text`'s file range + virtual address, and gather the
    // function symbol ranges — all from an immutable parse, so the borrow
    // ends before we mutate the bytes.
    let (text_off, text_size, text_vaddr, funcs) = {
        let file = object::File::parse(&*data)
            .with_context(|| format!("parse ELF {}", input.display()))?;
        let text = file
            .section_by_name(".text")
            .context("no .text section")?;
        let (off, size) = text
            .file_range()
            .context(".text section has no file range (NOBITS?)")?;
        let vaddr = text.address();

        // Collect (vaddr, size) of every function symbol that lies wholly
        // within .text. Bounding edits to real functions avoids treating
        // embedded data/jump-tables as code.
        let mut funcs: Vec<(u64, u64)> = file
            .symbols()
            .filter(|s| s.kind() == SymbolKind::Text && s.size() > 0)
            .map(|s| (s.address(), s.size()))
            .filter(|&(a, sz)| a >= vaddr && a + sz <= vaddr + size)
            .collect();
        funcs.sort_unstable();
        funcs.dedup();
        (off as usize, size as usize, vaddr, funcs)
    };

    if funcs.is_empty() {
        bail!(
            "no .text function symbols found in {} — refusing to linear-sweep \
             a stripped binary (would risk rewriting embedded data)",
            input.display()
        );
    }

    let mut out = data;
    let mut prng = Prng::new(seed);
    let mut stats = Stats::default();
    for (vaddr, size) in funcs {
        let start = text_off + (vaddr - text_vaddr) as usize;
        let end = start + size as usize;
        if end > text_off + text_size || end > out.len() {
            continue; // defensive: skip anything that would run past .text
        }
        rewrite_function(&mut out[start..end], vaddr, &mut prng, &mut stats);
    }

    std::fs::write(output, &out).with_context(|| format!("write {}", output.display()))?;
    Ok(stats)
}

fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}
