//! `factory_builder` CLI.
//!
//! Usage:
//!
//!   factory_builder --candidate <kernel.elf> --out <bios.img> [--uefi <uefi.img>]
//!   factory_builder build-kernel --kernel-crate <path-to-kernel-crate-dir>
//!
//! Modes:
//!
//! - default (`--candidate / --out`): validate the kernel ELF magic,
//!   then call `bootloader::BiosBoot::create_disk_image` (and
//!   `UefiBoot::create_disk_image` if `--uefi` is given), sha256 each
//!   image, and print one `<kind> <abs-path> <hex-sha256>` line per
//!   produced image to stdout. The morph engine's deploy stage parses
//!   that stdout.
//!
//! - `build-kernel`: shell out to `cargo build --release
//!   --manifest-path <kernel-crate>/Cargo.toml` and print the absolute
//!   path of the produced ELF on stdout. Used by the QEMU smoke test
//!   and (optionally) by the morph deploy stage to locate the ELF
//!   without hard-coding paths.
//!
//! No silent fallbacks: every failure exits with a non-zero code and a
//! stderr message that names the path that failed.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;
use std::process::ExitCode;

use factory_builder::{
    build_kernel_with_layout_seed_and_prod, format_image_line, locate_pkg_crate,
    package_kernel_via_pkg, validate_elf,
};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().collect();
    match run(&args[1..]) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("factory_builder: {:#}", e);
            ExitCode::from(1)
        }
    }
}

fn run(args: &[String]) -> Result<()> {
    if args.is_empty() {
        usage();
        bail!("no arguments provided");
    }
    match args[0].as_str() {
        "build-kernel" => cmd_build_kernel(&args[1..]),
        "-h" | "--help" => {
            usage();
            Ok(())
        }
        _ => cmd_package(args),
    }
}

fn usage() {
    eprintln!(
        "usage:\n  \
         factory_builder --candidate <kernel.elf> --out <bios.img> [--uefi <uefi.img>]\n  \
         factory_builder build-kernel --kernel-crate <dir> [--layout-seed <u64>] [--prod]\n\n\
         Output format (one per emitted image, parsed by morph_engine):\n  \
         <kind> <abs-path> <hex-sha256>\n    \
         where kind ∈ {{bios, uefi}}"
    );
}

fn cmd_package(args: &[String]) -> Result<()> {
    let mut candidate: Option<PathBuf> = None;
    let mut bios_out: Option<PathBuf> = None;
    let mut uefi_out: Option<PathBuf> = None;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--candidate" => {
                candidate =
                    Some(PathBuf::from(args.get(i + 1).context("--candidate needs value")?));
                i += 2;
            }
            "--out" => {
                bios_out =
                    Some(PathBuf::from(args.get(i + 1).context("--out needs value")?));
                i += 2;
            }
            "--uefi" => {
                uefi_out =
                    Some(PathBuf::from(args.get(i + 1).context("--uefi needs value")?));
                i += 2;
            }
            other => bail!("unknown argument: {}", other),
        }
    }
    let candidate = candidate.context("--candidate is required")?;
    let bios_out = bios_out.context("--out is required")?;

    let elf_abs = validate_elf(&candidate)?;
    eprintln!("factory_builder: validated ELF magic at {}", elf_abs.display());

    let pkg = locate_pkg_crate()?;
    let emitted = package_kernel_via_pkg(&pkg, &elf_abs, &bios_out, uefi_out.as_deref())?;
    for (kind, path, sha) in &emitted {
        println!("{}", format_image_line(*kind, path, sha));
    }
    eprintln!("factory_builder: emitted {} image(s)", emitted.len());
    Ok(())
}

fn cmd_build_kernel(args: &[String]) -> Result<()> {
    let mut crate_dir: Option<PathBuf> = None;
    let mut layout_seed: Option<u64> = None;
    let mut prod = false;
    let mut i = 0;
    while i < args.len() {
        match args[i].as_str() {
            "--kernel-crate" => {
                crate_dir = Some(PathBuf::from(
                    args.get(i + 1).context("--kernel-crate needs value")?,
                ));
                i += 2;
            }
            "--layout-seed" => {
                layout_seed = Some(
                    args.get(i + 1)
                        .context("--layout-seed needs value")?
                        .parse()
                        .context("--layout-seed must be a u64")?,
                );
                i += 2;
            }
            "--prod" => {
                prod = true;
                i += 1;
            }
            other => bail!("unknown argument: {}", other),
        }
    }
    let dir = crate_dir.context("--kernel-crate is required")?;
    let elf = build_kernel_with_layout_seed_and_prod(&dir, layout_seed, prod)?;
    // Stdout = one line, the absolute path. The smoke test pipes this
    // straight into the package mode.
    println!("{}", elf.display());
    Ok(())
}
