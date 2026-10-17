//! TASK-026 — per-cycle QEMU serial-log capture.
//!
//! When `ExperimentArgs::boot_each_cycle` is set, every accepted cycle's
//! kernel ELF is packaged as a BIOS image via `factory_builder::package_
//! kernel_via_pkg`, booted under QEMU with a per-cycle `-serial file:`
//! target, and the captured log's sha256 is recorded on the
//! `CycleRecord`. Two cycles with byte-identical ELFs but divergent
//! serial logs would be a noteworthy finding — the kernel asserts
//! byte-equality against locked fixtures, so any drift produces both
//! a panic banner AND a divergent ELF.
//!
//! Skipped under fast-mode (no real kernel ELF exists in fast-mode —
//! we synthesise a pseudo-ELF whose `.text` is a 4 KiB sha-256 chain,
//! not a bootable image). The flag is also a no-op when the operator
//! didn't ask for it, so the default wall-clock matches pre-TASK-026.
//!
//! Borrowed shape from `factory_builder/tests/qemu_smoke.rs` — same
//! QEMU command-line (`-drive`, `-serial file:`, `-display none`,
//! `-no-reboot`, `-m 256M`, `-d cpu_reset`). The wait loop watches
//! for `PROTEUS-TE HALT` to know the kernel reached its self-test
//! exit point, then kills QEMU.

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Outcome of a per-cycle QEMU boot. The log path is exposed for
/// callers that want to grep the raw bytes (REPORT-real.md generation
/// re-reads the logs to compute the distinct-sha256 count).
#[derive(Debug, Clone)]
pub struct BootCapture {
    pub serial_log_path: PathBuf,
    pub serial_log_sha256: String,
}

/// Locate `qemu-system-x86_64`. Mirrors `factory_builder/tests/qemu_
/// smoke.rs::find_qemu` so both code paths discover the same binary.
pub fn find_qemu() -> Option<PathBuf> {
    // Try PATH via `where` (Windows) / shell `command -v` doesn't ship
    // as an exe so we keep the `where` shim — it's also fine to fail
    // and let the canonical path catch the install.
    if let Ok(out) = Command::new("where").arg("qemu-system-x86_64").output() {
        if out.status.success() {
            if let Some(line) = String::from_utf8_lossy(&out.stdout).lines().next() {
                let p = PathBuf::from(line.trim());
                if p.exists() {
                    return Some(p);
                }
            }
        }
    }
    let win_default = PathBuf::from("C:/Program Files/qemu/qemu-system-x86_64.exe");
    if win_default.exists() {
        return Some(win_default);
    }
    None
}

/// Package the kernel ELF and boot it under QEMU. Captures the serial
/// log to `<results_dir>/serial_logs/cycle_NN.log` and returns the
/// log's sha256.
///
/// Fails fast (no silent skip) — when the operator opts into
/// `--boot-each-cycle`, missing QEMU is a clear error rather than a
/// silently-empty `serial_log_sha256` column.
///
/// Wait deadline is 20 seconds — generous because the kernel boot
/// itself is ~half a second and the rest is QEMU startup + UEFI/BIOS
/// firmware. The smoke test in `factory_builder/tests/qemu_smoke.rs`
/// uses 10s, but it polls the same already-built image; this path
/// also pays the per-cycle packaging cost amortised inside QEMU's
/// startup window, so a small buffer is justified.
pub fn boot_and_capture(
    elf_path: &Path,
    results_dir: &Path,
    cycle: u64,
) -> Result<BootCapture> {
    let qemu = find_qemu().context(
        "qemu-system-x86_64 not found on PATH nor at C:/Program Files/qemu/; \
         install QEMU or run without --boot-each-cycle",
    )?;
    let pkg_crate = factory_builder::locate_pkg_crate()
        .context("factory_builder_pkg out-of-workspace crate missing")?;

    let logs_dir = results_dir.join("serial_logs");
    std::fs::create_dir_all(&logs_dir)
        .with_context(|| format!("create serial_logs dir at {}", logs_dir.display()))?;
    let images_dir = results_dir.join("images");
    std::fs::create_dir_all(&images_dir)
        .with_context(|| format!("create images dir at {}", images_dir.display()))?;

    let bios = images_dir.join(format!("cycle_{:02}.img", cycle));
    let _ = std::fs::remove_file(&bios);
    let serial_log = logs_dir.join(format!("cycle_{:02}.log", cycle));
    let _ = std::fs::remove_file(&serial_log);

    factory_builder::package_kernel_via_pkg(&pkg_crate, elf_path, &bios, None)
        .with_context(|| format!("package cycle {} kernel ELF as BIOS image", cycle))?;
    if !bios.exists() {
        bail!(
            "factory_builder_pkg reported success but BIOS image is missing at {}",
            bios.display()
        );
    }

    // TASK-104: attach real virtio-blk-pci so `banner_virtio_hw` can
    // probe via PCI config I/O. Boot image stays on IDE.
    let virtio_disk = images_dir.join("virtio_hw.img");
    if !virtio_disk.exists()
        || std::fs::metadata(&virtio_disk)
            .map(|m| m.len())
            .unwrap_or(0)
            < 1024 * 1024
    {
        std::fs::write(&virtio_disk, vec![0u8; 1024 * 1024])
            .context("create virtio_hw.img for hardware-truth probe")?;
    }
    let ahci_disk = images_dir.join("ahci_hw.img");
    if !ahci_disk.exists()
        || std::fs::metadata(&ahci_disk)
            .map(|m| m.len())
            .unwrap_or(0)
            < 1024 * 1024
    {
        std::fs::write(&ahci_disk, vec![0u8; 1024 * 1024])
            .context("create ahci_hw.img for AHCI hardware-truth")?;
    }
    let nvme_disk = images_dir.join("nvme_hw.img");
    if !nvme_disk.exists()
        || std::fs::metadata(&nvme_disk)
            .map(|m| m.len())
            .unwrap_or(0)
            < 1024 * 1024
    {
        std::fs::write(&nvme_disk, vec![0u8; 1024 * 1024])
            .context("create nvme_hw.img for NVMe hardware-truth")?;
    }
    let mut qproc = Command::new(&qemu)
        .arg("-accel")
        .arg("tcg")
        .arg("-drive")
        .arg(format!("format=raw,file={},if=ide", bios.display()))
        .arg("-drive")
        .arg(format!(
            "if=none,id=vd0,format=raw,file={}",
            virtio_disk.display()
        ))
        .arg("-device")
        .arg("virtio-blk-pci,drive=vd0,disable-legacy=off,disable-modern=on")
        // TASK-111: dual hubport virtio-net for in-guest TX→RX proof.
        .arg("-netdev")
        .arg("hubport,id=n0,hubid=1")
        .arg("-device")
        .arg("virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on")
        .arg("-netdev")
        .arg("hubport,id=n1,hubid=1")
        .arg("-device")
        .arg("virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on")
        // TASK-113/117: real AHCI + IDENTIFY / sector DMA disk.
        .arg("-drive")
        .arg(format!(
            "if=none,id=ahd0,format=raw,file={}",
            ahci_disk.display()
        ))
        .arg("-device")
        .arg("ahci,id=ahci0")
        .arg("-device")
        .arg("ide-hd,drive=ahd0,bus=ahci0.0")
        // TASK-116/120/132: dual e1000 hub for MAC + TX + RX.
        .arg("-netdev")
        .arg("hubport,id=e0,hubid=2")
        .arg("-device")
        .arg("e1000,netdev=e0")
        .arg("-netdev")
        .arg("hubport,id=e1,hubid=2")
        .arg("-device")
        .arg("e1000,netdev=e1")
        // TASK-119: real NVMe admin identify.
        .arg("-drive")
        .arg(format!(
            "if=none,id=nvme0,format=raw,file={}",
            nvme_disk.display()
        ))
        .arg("-device")
        .arg("nvme,drive=nvme0,serial=PROTEUS-NVME-HW")
        .arg("-serial")
        .arg(format!("file:{}", serial_log.display()))
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-m")
        .arg("256M")
        .arg("-d")
        .arg("cpu_reset")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .with_context(|| format!("spawn qemu for cycle {}", cycle))?;

    let deadline = Instant::now() + Duration::from_secs(20);
    let mut halted = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(s) = std::fs::read_to_string(&serial_log) {
            if s.contains("PROTEUS-TE HALT") {
                halted = true;
                break;
            }
        }
    }
    let _ = qproc.kill();
    let _ = qproc.wait();

    let log_bytes = std::fs::read(&serial_log)
        .with_context(|| format!("read serial log at {}", serial_log.display()))?;
    if !halted {
        let preview: String = String::from_utf8_lossy(&log_bytes)
            .chars()
            .take(2000)
            .collect();
        bail!(
            "QEMU cycle {} did not emit PROTEUS-TE HALT within 20s; serial log preview:\n{}",
            cycle,
            preview
        );
    }

    let mut h = Sha256::new();
    h.update(&log_bytes);
    let sha = factory_builder::hex(&h.finalize());
    Ok(BootCapture {
        serial_log_path: serial_log,
        serial_log_sha256: sha,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn find_qemu_returns_option() {
        // Smoke: the function shouldn't panic regardless of whether
        // QEMU is installed. Returning either Some or None is fine.
        let _ = find_qemu();
    }

    #[test]
    fn boot_capture_struct_is_debug_and_clone() {
        // Compile-time check: BootCapture implements Debug + Clone so
        // it can be threaded through #[derive(Debug)] structs in the
        // morph engine / experiment record layer.
        let bc = BootCapture {
            serial_log_path: PathBuf::from("/tmp/x.log"),
            serial_log_sha256: "deadbeef".into(),
        };
        let cloned = bc.clone();
        assert_eq!(cloned.serial_log_sha256, "deadbeef");
        assert_eq!(format!("{:?}", bc).contains("deadbeef"), true);
    }
}
