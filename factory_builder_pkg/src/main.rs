//! `factory_builder_pkg` — heavy packager binary.
//!
//! This crate lives OUT of the Cuttle workspace because the
//! `bootloader = "0.11"` build.rs spawns nested cargo invocations with
//! `-Z` flags that require nightly. Keeping it isolated lets the main
//! workspace stay on stable.
//!
//! Mirrors `rustos-builder/src/main.rs` almost line-for-line, with a
//! richer argv parser so the workspace-member `factory_builder` crate
//! can shell out cleanly. Output format on stdout:
//!
//!   bios <abs-path-to-bios-image>
//!   uefi <abs-path-to-uefi-image>   (only if --uefi given)
//!
//! The caller (workspace `factory_builder`) computes sha256 itself —
//! we don't, so the canonical hash is computed in exactly one place.

use anyhow::{bail, Context, Result};
use std::path::PathBuf;

fn main() -> std::process::ExitCode {
    match run() {
        Ok(()) => std::process::ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("factory_builder_pkg: {:#}", e);
            std::process::ExitCode::from(1)
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let mut candidate: Option<PathBuf> = None;
    let mut bios_out: Option<PathBuf> = None;
    let mut uefi_out: Option<PathBuf> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--candidate" => {
                candidate = Some(PathBuf::from(
                    args.get(i + 1).context("--candidate needs value")?,
                ));
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
    if !candidate.exists() {
        bail!("kernel ELF not found: {}", candidate.display());
    }

    // Light sanity check at this layer too — the workspace crate
    // already validated magic, but defence in depth is cheap.
    let head = std::fs::read(&candidate)?;
    if head.len() < 4 || head[..4] != [0x7F, b'E', b'L', b'F'] {
        bail!("not an ELF file: {}", candidate.display());
    }

    bootloader::BiosBoot::new(&candidate)
        .create_disk_image(&bios_out)
        .with_context(|| {
            format!(
                "BIOS disk image creation failed (kernel={}, out={})",
                candidate.display(),
                bios_out.display()
            )
        })?;
    let bios_abs = std::fs::canonicalize(&bios_out)?;
    println!("bios {}", bios_abs.display());

    if let Some(uefi_out) = uefi_out {
        bootloader::UefiBoot::new(&candidate)
            .create_disk_image(&uefi_out)
            .with_context(|| {
                format!("UEFI disk image creation failed (out={})", uefi_out.display())
            })?;
        let uefi_abs = std::fs::canonicalize(&uefi_out)?;
        println!("uefi {}", uefi_abs.display());
    }

    Ok(())
}
