//! `mtd` — the moving-target-defense chronograph.
//!
//! Subcommands:
//!
//! * `mtd specimen [--variants N] [--max-instrs M] [--keep] [--semantic]`
//!     With `--semantic`, runs the pipeline twice — once with default
//!     `DiversifyOptions` (Rung-1 semantic perturbation OFF) and once
//!     with `semantic_perturb: true` — and prints semantic-normalized
//!     survival for both, so the Rung-1 effect is directly measurable.
//!     Diversify a built-in specimen N ways through the project's real
//!     `cuttle_diversifier` pipeline, compile each with `rustc -O`, and
//!     report ROP/JOP gadget survival across the morphs. This is the
//!     headline measurement: it turns "morphing perturbs the attack
//!     surface" into a percentage.
//!
//! * `mtd churn <artifactA> <artifactB> [--max-instrs N]`
//!     Compare the `.text` gadget sets of two already-compiled artifacts
//!     (e.g. two kernel ELFs from real morph cycles).
//!
//! * `mtd gadgets <artifact> [--max-instrs N] [--limit K]`
//!     Dump the gadget set of one artifact (diagnostic).

use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use cuttle_mtd_metrics::chainsim;
use cuttle_mtd_metrics::{churn, extract_gadgets, read_text_section, ChurnReport, DEFAULT_MAX_INSTRS};

/// Built-in specimen: dependency-free `std` Rust with enough branchy
/// control flow (loops, a range `match`, pointer arithmetic, a binary
/// search) to produce a realistic gadget population after `-O`. The
/// `#[no_mangle] pub extern "C"` functions survive optimization so the
/// morph's effect on real codegen is what we measure.
const SPECIMEN: &str = r##"
#![allow(dead_code)]

#[no_mangle]
pub extern "C" fn mix(a: u64, b: u64, c: u64) -> u64 {
    let mut acc = a ^ b.rotate_left(13);
    let mut i = 0u64;
    while i < (c & 15) {
        acc = acc.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(i);
        if acc & 1 == 0 {
            acc = acc.rotate_left(7) ^ a;
        } else {
            acc = acc.rotate_right(3).wrapping_add(b);
        }
        i += 1;
    }
    acc.wrapping_sub(c)
}

#[no_mangle]
pub extern "C" fn classify(x: i64) -> i64 {
    match x {
        i64::MIN..=-1 => x.wrapping_mul(3).wrapping_neg(),
        0 => 42,
        1..=9 => x + 100,
        10..=99 => x.wrapping_mul(x),
        _ => x.wrapping_shr(2).wrapping_add(7),
    }
}

#[no_mangle]
pub extern "C" fn checksum(ptr: *const u8, len: usize) -> u32 {
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i < len {
        let byte = unsafe { *ptr.add(i) } as u32;
        sum = sum.wrapping_add(byte).rotate_left(1);
        if byte & 0x80 != 0 {
            sum ^= 0xA5A5_A5A5;
        }
        i += 1;
    }
    sum
}

#[no_mangle]
pub extern "C" fn search(table: *const u64, n: usize, key: u64) -> i64 {
    let mut lo = 0usize;
    let mut hi = n;
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        let v = unsafe { *table.add(mid) };
        if v == key {
            return mid as i64;
        } else if v < key {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    -1
}

// Rung-1 semantic-diversity targets: plain `pub fn`s (no `extern` abi)
// whose bodies carry the three patterns the `semantic_perturb` pass
// rewrites — power-of-two multiplies, invertible if/else comparisons,
// and `0..n` for-loops. `#[inline(never)]` keeps them as distinct
// codegen units so their gadget contribution is visible in `.text`.

#[inline(never)]
pub fn scale_mix(x: u64, y: u64) -> u64 {
    let a = x * 8 + y * 4;
    let b = (a << 2).wrapping_add(x * 16);
    if a >= b {
        b.wrapping_mul(2)
    } else {
        a ^ (y * 2)
    }
}

#[inline(never)]
pub fn accumulate(table: &[u64; 64], n: usize) -> u64 {
    let mut acc = 0u64;
    for i in 0..n {
        let v = table[i & 63];
        if v == 0 {
            acc = acc.wrapping_add(1);
        } else {
            acc = acc.wrapping_add(v * 8);
        }
    }
    acc
}

#[inline(never)]
pub fn threshold(x: i64, limit: i64) -> i64 {
    if x <= limit {
        x.wrapping_mul(4)
    } else {
        limit.wrapping_neg()
    }
}
"##;

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str);
    match cmd {
        Some("specimen") => cmd_specimen(&args[2..]),
        Some("churn") => cmd_churn(&args[2..]),
        Some("gadgets") => cmd_gadgets(&args[2..]),
        Some("chainsim") => cmd_chainsim(&args[2..]),
        Some("cadence") => cmd_cadence(&args[2..]),
        _ => {
            eprintln!(
                "usage:\n  \
                 mtd specimen [--variants N] [--max-instrs M] [--keep] [--semantic]\n  \
                 mtd churn <artifactA> <artifactB> [--max-instrs N]\n  \
                 mtd gadgets <artifact> [--max-instrs N] [--limit K]\n  \
                 mtd chainsim <baseElf> <variantElf> [--label S] [--chains K] [--len L] [--seed S]\n  \
                 mtd cadence [--window SECS --period SECS | --curve]"
            );
            std::process::exit(2);
        }
    }
}

// ---------------------------------------------------------------------------
// `chainsim` — the red-team instrument: does a developed ROP chain survive
// a morph cycle? And can a leak-and-rebase attacker rebuild it?
// ---------------------------------------------------------------------------

fn cmd_chainsim(args: &[String]) -> Result<()> {
    let base = args
        .first()
        .filter(|a| !a.starts_with("--"))
        .context("chainsim: base ELF path required")?;
    let variant = args
        .get(1)
        .filter(|a| !a.starts_with("--"))
        .context("chainsim: variant ELF path required")?;
    let label: String = flag_value(args, "--label")?
        .unwrap_or_else(|| variant.clone());
    let chains: usize = flag_value(args, "--chains")?.unwrap_or(2000);
    let len: usize = flag_value(args, "--len")?.unwrap_or(8);
    let seed: u64 = flag_value(args, "--seed")?.unwrap_or(0xC0FFEE);

    let rep = chainsim::run_experiment_on_elves(
        &label,
        Path::new(base),
        Path::new(variant),
        chains,
        len,
        seed,
    )?;
    println!("{}", serde_json::to_string_pretty(&rep)?);
    Ok(())
}

// ---------------------------------------------------------------------------
// `cadence` — attacker C break-even curve (closed form, no ELF needed)
// ---------------------------------------------------------------------------

fn cmd_cadence(args: &[String]) -> Result<()> {
    if args.iter().any(|a| a == "--curve") {
        let ratios: Vec<f64> = vec![
            0.001, 0.01, 0.05, 0.1, 0.25, 0.5, 0.75, 0.9, 0.99, 1.0, 1.5, 2.0,
        ];
        println!("window/period,P(attack succeeds)");
        for (r, p) in chainsim::cadence_curve(&ratios) {
            println!("{:.3},{:.4}", r, p);
        }
        return Ok(());
    }
    let window: f64 = flag_value(args, "--window")?.context("cadence: --window SECS required")?;
    let period: f64 = flag_value(args, "--period")?.context("cadence: --period SECS required")?;
    let p = chainsim::cadence_break_even(window, period);
    println!(
        "P(success) = {:.6}  (window={}s period={}s)",
        p, window, period
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// `specimen` — the chronograph
// ---------------------------------------------------------------------------

fn cmd_specimen(args: &[String]) -> Result<()> {
    let variants: usize = flag_value(args, "--variants")?.unwrap_or(8);
    let max_instrs: usize = flag_value(args, "--max-instrs")?.unwrap_or(DEFAULT_MAX_INSTRS);
    let keep = args.iter().any(|a| a == "--keep");
    let semantic = args.iter().any(|a| a == "--semantic");
    if variants < 2 {
        bail!("--variants must be >= 2 (need a base plus at least one morph to compare)");
    }

    if semantic {
        // A/B measurement: default options (Rung-1 OFF) vs
        // `semantic_perturb: true` (Rung-1 ON). Same seeds, same
        // specimen, same compiler — the only delta is the pass.
        println!("\n########## A/B: Rung-1 semantic perturbation ##########");
        let base = run_specimen_pipeline(
            variants,
            max_instrs,
            keep,
            "baseline",
            &cuttle_diversifier::DiversifyOptions::default(),
        )?;
        let sem = run_specimen_pipeline(
            variants,
            max_instrs,
            keep,
            "semantic",
            &cuttle_diversifier::DiversifyOptions::with_semantic_perturb(),
        )?;
        println!("\n=== Rung-1 A/B summary ===");
        println!(
            "baseline   mean semantic-normalized survival: {:.1}%",
            base * 100.0
        );
        println!(
            "rung-1     mean semantic-normalized survival: {:.1}%",
            sem * 100.0
        );
        println!(
            "delta                                              : {:+.1} percentage points",
            (sem - base) * 100.0
        );
        return Ok(());
    }

    run_specimen_pipeline(
        variants,
        max_instrs,
        keep,
        "run",
        &cuttle_diversifier::DiversifyOptions::default(),
    )?;
    Ok(())
}

/// Diversify the specimen `variants` ways under `options`, compile each
/// with `rustc -O`, extract gadgets, and print the churn report.
/// Returns the mean semantic-normalized survival across morph pairs.
fn run_specimen_pipeline(
    variants: usize,
    max_instrs: usize,
    keep: bool,
    label: &str,
    options: &cuttle_diversifier::DiversifyOptions,
) -> Result<f64> {
    let work = std::env::temp_dir().join(format!(
        "cuttle_mtd_{}_{}",
        std::process::id(),
        label
    ));
    std::fs::create_dir_all(&work).with_context(|| format!("create {}", work.display()))?;

    eprintln!(
        "mtd: [{}] diversifying the specimen into {} variants and compiling each with `rustc -O`...",
        label, variants
    );

    // Diversify + compile each variant. Each variant gets a distinct
    // (cycle, module) seed, exactly as a real morph cycle would.
    let mut compiled: Vec<(usize, PathBuf, [u8; 32])> = Vec::new();
    for v in 0..variants {
        let seed = cuttle_diversifier::Seed::derive(v as u64, "mtd_specimen");
        let (morphed, dlog) = cuttle_diversifier::diversify_with_options(SPECIMEN, &seed, options)
            .with_context(|| format!("diversify variant {}", v))?;
        if options.semantic_perturb && v == 0 {
            eprintln!(
                "mtd: [semantic] variant 0 decisions: {:?}",
                dlog.semantic_decisions
            );
        }
        let canon = cuttle_diversifier::canonical_hash(&morphed)
            .with_context(|| format!("hash variant {}", v))?;

        let src = work.join(format!("variant_{}.rs", v));
        std::fs::write(&src, &morphed).with_context(|| format!("write {}", src.display()))?;
        let obj = work.join(format!("variant_{}.o", v));
        compile_obj(&src, &obj)?;
        compiled.push((v, obj, canon));
    }

    // Sanity: confirm the morphs are genuinely distinct source (different
    // canonical hashes). If two collide, the diversifier produced
    // identical output for two seeds — worth surfacing, not hiding.
    let distinct_sources = {
        let mut s = std::collections::HashSet::new();
        for (_, _, h) in &compiled {
            s.insert(*h);
        }
        s.len()
    };
    eprintln!(
        "mtd: {}/{} variants are distinct at the source level",
        distinct_sources, variants
    );

    // Extract the gadget set of each compiled variant.
    let mut sets = Vec::with_capacity(compiled.len());
    for (v, obj, _) in &compiled {
        let (text, base) = read_text_section(obj)?;
        let g = extract_gadgets(&text, base, max_instrs);
        eprintln!("mtd: variant {} -> .text {} bytes, {} gadgets", v, text.len(), g.len());
        sets.push(g);
    }

    // Compare every later variant against variant 0 (the "base cycle").
    println!(
        "\n=== [{}] gadget churn vs. base cycle (variant 0), max_instrs={} ===\n",
        label, max_instrs
    );
    let base = &sets[0];
    let mut pos_rates = Vec::new();
    let mut sem_rates = Vec::new();
    let mut reports: Vec<ChurnReport> = Vec::new();
    for i in 1..sets.len() {
        let r = churn(base, &sets[i]);
        pos_rates.push(r.positional_survival());
        sem_rates.push(r.semantic_survival());
        println!("variant {} vs 0:", i);
        println!("{}\n", indent(&r.to_string()));
        reports.push(r);
    }

    let mean_pos = mean(&pos_rates);
    let mean_sem = mean(&sem_rates);
    let worst_pos = pos_rates.iter().cloned().fold(0.0_f64, f64::max);

    println!("=== summary ({} morph pairs) ===", reports.len());
    println!("mean positional survival : {:.1}%   (lower = better; this is the headline thesis number)", mean_pos * 100.0);
    println!("worst positional survival: {:.1}%   (the most exploit-friendly single morph observed)", worst_pos * 100.0);
    println!("mean semantic   survival : {:.1}%   (expected high under offset-only diversity)", mean_sem * 100.0);
    println!();
    println!("interpretation:");
    println!("  positional survival is the fraction of a ROP chain hardcoded against the base");
    println!("  cycle that would still land against a morphed cycle. The thesis needs this near 0.");
    if mean_pos > 0.5 {
        println!("  -> CURRENT VERDICT: WEAK. Over half the fixed attack surface survives each morph.");
        println!("     This is the gap Phase 1 (real layout/codegen entropy) must close.");
    } else if mean_pos > 0.1 {
        println!("  -> CURRENT VERDICT: PARTIAL. Meaningful churn, but a fixed chain still has usable residue.");
    } else {
        println!("  -> CURRENT VERDICT: STRONG. Little of a fixed chain survives a morph.");
    }

    if keep {
        eprintln!("\nmtd: kept artifacts in {}", work.display());
    } else {
        let _ = std::fs::remove_dir_all(&work);
    }
    Ok(mean_sem)
}

/// Compile a single `.rs` file to an object with realistic, deterministic
/// codegen. `-O` so we measure optimized code; `panic=abort` to strip
/// unwind-table noise; one codegen unit so the output is a single object
/// and the morph's effect isn't masked by CGU scheduling nondeterminism.
fn compile_obj(src: &Path, obj: &Path) -> Result<()> {
    let out = Command::new("rustc")
        .args([
            "--edition",
            "2021",
            "-O",
            "-C",
            "panic=abort",
            "-C",
            "codegen-units=1",
            "--crate-type",
            "lib",
            "--emit",
            "obj",
            "-o",
        ])
        .arg(obj)
        .arg(src)
        .output()
        .context("invoke rustc")?;
    if !out.status.success() {
        bail!(
            "rustc failed for {}:\n{}",
            src.display(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// `churn` / `gadgets`
// ---------------------------------------------------------------------------

fn cmd_churn(args: &[String]) -> Result<()> {
    let positionals = positional_args(args, &["--max-instrs", "--buckets"]);
    if positionals.len() != 2 {
        bail!("churn requires exactly two artifact paths");
    }
    let max_instrs: usize = flag_value(args, "--max-instrs")?.unwrap_or(DEFAULT_MAX_INSTRS);
    let (ta, ba) = read_text_section(Path::new(positionals[0]))?;
    let (tb, bb) = read_text_section(Path::new(positionals[1]))?;
    let ga = extract_gadgets(&ta, ba, max_instrs);
    let gb = extract_gadgets(&tb, bb, max_instrs);
    println!("{}", churn(&ga, &gb));

    if let Some(n) = flag_value::<usize>(args, "--buckets")? {
        println!("\npositional survival by .text offset ({} buckets):", n);
        for b in cuttle_mtd_metrics::survivor_offset_buckets(&ga, &gb, n) {
            let rate = if b.total == 0 {
                0.0
            } else {
                b.survived as f64 / b.total as f64
            };
            let bar_len = (rate * 30.0).round() as usize;
            println!(
                "  [{:#08x}..{:#08x})  {:>5}/{:<5}  {:>5.1}%  {}",
                b.lo,
                b.hi,
                b.survived,
                b.total,
                rate * 100.0,
                "#".repeat(bar_len)
            );
        }
    }
    Ok(())
}

fn cmd_gadgets(args: &[String]) -> Result<()> {
    let positionals = positional_args(args, &["--max-instrs", "--limit"]);
    if positionals.len() != 1 {
        bail!("gadgets requires exactly one artifact path");
    }
    let max_instrs: usize = flag_value(args, "--max-instrs")?.unwrap_or(DEFAULT_MAX_INSTRS);
    let limit: usize = flag_value(args, "--limit")?.unwrap_or(40);
    let (text, base) = read_text_section(Path::new(positionals[0]))?;
    let g = extract_gadgets(&text, base, max_instrs);
    println!(".text {} bytes, {} gadgets ({} distinct)", text.len(), g.len(), g.distinct().len());
    for (off, gadget) in g.by_offset.iter().take(limit) {
        println!("  +{:#06x}  {}", off, gadget);
    }
    if g.len() > limit {
        println!("  ... ({} more)", g.len() - limit);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn flag_value<T: std::str::FromStr>(args: &[String], flag: &str) -> Result<Option<T>>
where
    T::Err: std::fmt::Display,
{
    if let Some(pos) = args.iter().position(|a| a == flag) {
        let raw = args
            .get(pos + 1)
            .with_context(|| format!("{} requires a value", flag))?;
        let v = raw
            .parse::<T>()
            .map_err(|e| anyhow::anyhow!("{} value '{}' invalid: {}", flag, raw, e))?;
        Ok(Some(v))
    } else {
        Ok(None)
    }
}

/// Collect positional (non-flag) arguments, skipping value-taking flags
/// and the token that follows each. Without this, the value after e.g.
/// `--limit 5` is mistaken for a positional path.
fn positional_args<'a>(args: &'a [String], value_flags: &[&str]) -> Vec<&'a String> {
    let mut out = Vec::new();
    let mut skip = false;
    for a in args {
        if skip {
            skip = false;
            continue;
        }
        if a.starts_with("--") {
            if value_flags.contains(&a.as_str()) {
                skip = true;
            }
            continue;
        }
        out.push(a);
    }
    out
}

fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        0.0
    } else {
        xs.iter().sum::<f64>() / xs.len() as f64
    }
}

fn indent(s: &str) -> String {
    s.lines().map(|l| format!("  {}", l)).collect::<Vec<_>>().join("\n")
}
