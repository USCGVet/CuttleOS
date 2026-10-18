//! phase2_daemon — lived Phase-2 cadence loop on a single node.
//!
//! Each cycle, unattended:
//!   1. `run_bundle` — atomic morph of the enrolled kernel modules
//!      (Rung-1 semantic perturb on), verifier-gated, v11-signed,
//!      deployed in place.
//!   2. build-kernel --prod with a fresh layout seed → slim prod image.
//!   3. Rotate QEMU: kill the previous instance, boot the new image
//!      against the SAME continuity disk. The successor kernel resumes
//!      the WAL its morphed predecessor wrote — durable state crossing
//!      the cadence boundary every cycle.
//!   4. Append a per-cycle verdict line to phase2_scorecard.jsonl.
//!
//! This is the "fleet of one" Phase-2 proof: cadence lived, not
//! scaffolded. Cycle wall-time is the honest measurement of what
//! per-minute cadence costs on this host.
//!
//! Usage:
//!   phase2_daemon --cycles N --workspace <dir> --workdir <dir>
//!                 [--modules m1,m2,…] [--layout-seed-base S] [--boot-timeout-secs N]

use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{bail, Context, Result};
use cuttle_morph_engine::{run_bundle, BundleCycleArgs, SynthesizerKind};

const DEFAULT_MODULES: &[&str] = &[
    "tls", "wal", "iommu", "net", "nvme", "tcp", "http", "dns", "icmp", "shell", "lived_net",
];

fn arg_value(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1).cloned())
}

fn sibling_bin(name: &str) -> Result<PathBuf> {
    let exe = std::env::current_exe()?;
    let dir = exe.parent().and_then(|p| p.parent()).context("exe parent")?;
    let p = dir.join(if cfg!(windows) { format!("{}.exe", name) } else { name.to_string() });
    if p.exists() {
        Ok(p)
    } else {
        bail!("sibling binary not found: {}", p.display())
    }
}

fn spawn_qemu(img: &Path, work: &Path, serial_log: &Path) -> Result<std::process::Child> {
    // Scratch disks: ahd0 is the PERSISTENT continuity disk (never
    // recreated per cycle — that's the point); others are scratch.
    for (name, size_mb) in [("vd0.img", 1usize), ("nvme0.img", 1usize)] {
        let p = work.join(name);
        if !p.exists() {
            fs::write(&p, vec![0u8; size_mb << 20])?;
        }
    }
    let ahd = work.join("ahd0.img");
    if !ahd.exists() {
        fs::write(&ahd, vec![0u8; 1 << 20])?;
    }
    let key_path = work.join("device_secret_key.bin");
    let _ = cuttle_morph_engine::durable_seal::load_or_generate_device_seal_key(&key_path)?;
    let qemu = r"C:\Program Files\qemu\qemu-system-x86_64.exe";
    let qemu = if Path::new(qemu).exists() { qemu.to_string() } else { "qemu-system-x86_64".to_string() };
    let child = Command::new(&qemu)
        .arg("-accel").arg("tcg")
        .arg("-drive").arg(format!("format=raw,file={},if=ide", img.display()))
        .arg("-drive").arg(format!("if=none,id=vd0,format=raw,file={}", work.join("vd0.img").display()))
        .arg("-device").arg("virtio-blk-pci,drive=vd0,disable-legacy=off,disable-modern=on")
        .arg("-netdev").arg("hubport,id=n0,hubid=1")
        .arg("-device").arg("virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on")
        .arg("-netdev").arg("hubport,id=n1,hubid=1")
        .arg("-device").arg("virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on")
        .arg("-drive").arg(format!("if=none,id=ahd0,format=raw,file={}", ahd.display()))
        .arg("-device").arg("ahci,id=ahci0")
        .arg("-device").arg("ide-hd,drive=ahd0,bus=ahci0.0")
        .arg("-netdev").arg("hubport,id=e0,hubid=2")
        .arg("-device").arg("e1000,netdev=e0")
        .arg("-netdev").arg("hubport,id=e1,hubid=2")
        .arg("-device").arg("e1000,netdev=e1")
        .arg("-drive").arg(format!("if=none,id=nvme0,format=raw,file={}", work.join("nvme0.img").display()))
        .arg("-device").arg("nvme,drive=nvme0,serial=CUTTLE-NVME-HW")
        .arg("-fw_cfg").arg(format!("name=opt/cuttle_device_key,file={}", key_path.display()))
        .arg("-serial").arg(format!("file:{}", serial_log.display()))
        .arg("-display").arg("none")
        .arg("-no-reboot")
        .arg("-m").arg("256M")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .context("spawn qemu")?;
    Ok(child)
}

fn wait_for_marker(log: &Path, timeout: Duration) -> Option<String> {
    let start = Instant::now();
    while start.elapsed() < timeout {
        if let Ok(s) = fs::read_to_string(log) {
            for marker in ["CUTTLE-TE HALT", "PANIC"] {
                if s.contains(marker) {
                    return Some(marker.to_string());
                }
            }
        }
        std::thread::sleep(Duration::from_secs(2));
    }
    None
}

fn extract_continuity(log: &str) -> Option<String> {
    log.lines().find(|l| l.starts_with("CONTINUITY")).map(|l| l.to_string())
}

fn main() -> Result<()> {
    // Run the whole soak in a big-stack thread: syn's recursive AST
    // visitors overflow the default 8MB main stack once sources have
    // accumulated hundreds of cycles of diversifier nesting (observed:
    // deterministic 'main has overflowed its stack' kill at cycle ~244).
    let handle = std::thread::Builder::new()
        .name("phase2-soak".to_string())
        .stack_size(256 << 20) // 256 MiB — headroom for worst-case nesting
        .spawn(real_main)
        .context("spawn phase2 soak thread")?;
    match handle.join() {
        Ok(r) => r,
        Err(e) => std::panic::resume_unwind(e),
    }
}

fn real_main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cycles: u64 = arg_value(&args, "--cycles").context("--cycles N required")?.parse()?;
    let workspace = PathBuf::from(arg_value(&args, "--workspace").context("--workspace required")?);
    let work = PathBuf::from(arg_value(&args, "--workdir").context("--workdir required")?);
    fs::create_dir_all(&work)?;
    let work = fs::canonicalize(&work)?;
    let seed_base: u64 = arg_value(&args, "--layout-seed-base")
        .map(|s| s.parse().unwrap_or(10000))
        .unwrap_or(10000);
    let boot_timeout: u64 = arg_value(&args, "--boot-timeout-secs")
        .map(|s| s.parse().unwrap_or(240))
        .unwrap_or(240);
    let modules: Vec<String> = arg_value(&args, "--modules")
        .map(|s| s.split(',').map(|m| m.trim().to_string()).collect())
        .unwrap_or_else(|| DEFAULT_MODULES.iter().map(|m| m.to_string()).collect());

    let fb = sibling_bin("factory_builder")?;
    let bm = sibling_bin("binmorph")?;
    let scorecard = work.join("phase2_scorecard.jsonl");
    let kernel_crate = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .context("manifest parent")?
        .join("target_enterprise_kernel");

    eprintln!(
        "phase2: starting {} cycle(s), modules={}, workdir={}",
        cycles,
        modules.len(),
        work.display()
    );

    for cycle in 1..=cycles {
        let t0 = Instant::now();
        let ts = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        let layout_seed = seed_base + cycle;

        // Stage 1: atomic morph cycle (verifier-gated, v11-signed).
        let morph_t = Instant::now();
        let bargs = BundleCycleArgs {
            cycle,
            bundle_name: "kernel".to_string(),
            workspace: workspace.clone(),
            modules: modules.clone(),
            synthesizer: SynthesizerKind::PassThrough,
            emit_image: false,
            manifest: None,
            no_perf_check: true,
            durable_seals_dir: None,
        };
        let morph_ok = match run_bundle(&bargs) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("phase2: cycle {} morph REJECTED: {:#}", cycle, e);
                false
            }
        };
        let morph_secs = morph_t.elapsed().as_secs_f64();
        if !morph_ok {
            let line = format!(
                "{{\"cycle\":{},\"ts\":{},\"morph\":\"rejected\",\"morph_secs\":{:.1}}}\n",
                cycle, ts, morph_secs
            );
            use std::io::Write as _;
            let mut f = fs::OpenOptions::new().create(true).append(true).open(&scorecard)?;
            f.write_all(line.as_bytes())?;
            continue;
        }

        // Stage 2: prod image build with fresh layout seed + post-link binmorph.
        let build_t = Instant::now();
        let out = Command::new(&fb)
            .arg("build-kernel")
            .arg("--kernel-crate").arg(&kernel_crate)
            .arg("--layout-seed").arg(layout_seed.to_string())
            .arg("--prod")
            .output()
            .context("factory_builder build-kernel")?;
        if !out.status.success() {
            bail!(
                "cycle {}: prod kernel build failed: {}",
                cycle,
                String::from_utf8_lossy(&out.stderr)
            );
        }
        let elf = kernel_crate.join("target/x86_64-unknown-none/release/target_enterprise_kernel");
        let div_elf = work.join(format!("div_c{}.elf", cycle));
        let bm_out = Command::new(&bm)
            .arg("--in").arg(&elf)
            .arg("--out").arg(&div_elf)
            .arg("--seed").arg(layout_seed.to_string())
            .output()
            .context("binmorph post-link diversify")?;
        if !bm_out.status.success() {
            bail!(
                "cycle {}: binmorph failed: {}",
                cycle,
                String::from_utf8_lossy(&bm_out.stderr)
            );
        }
        let img = work.join(format!("prod_c{}.img", cycle));
        let out = Command::new(&fb)
            .arg("--candidate").arg(&div_elf)
            .arg("--out").arg(&img)
            .output()
            .context("factory_builder package")?;
        let _ = fs::remove_file(&div_elf);
        if !out.status.success() {
            bail!("cycle {}: image package failed", cycle);
        }
        let build_secs = build_t.elapsed().as_secs_f64();

        // Stage 3: boot rotation against the persistent continuity disk.
        let boot_t = Instant::now();
        let serial = work.join(format!("boot_c{}.log", cycle));
        // Stale logs from prior runs contain "CUTTLE-TE HALT" and would
        // make wait_for_marker return instantly — always boot into a
        // fresh file.
        let _ = fs::remove_file(&serial);
        let mut qemu = spawn_qemu(&img, &work, &serial)?;
        let marker = wait_for_marker(&serial, Duration::from_secs(boot_timeout));
        let _ = qemu.kill();
        let _ = qemu.wait();
        let boot_secs = boot_t.elapsed().as_secs_f64();

        let log = fs::read_to_string(&serial).unwrap_or_default();
        let continuity = extract_continuity(&log).unwrap_or_else(|| "none".to_string());
        let prod = log.contains("CUTTLE-TE PROD");
        let halt = marker.as_deref() == Some("CUTTLE-TE HALT");
        let shell_compose = log.contains("SHELL compose OK tasks=5 files=5 audit=5");
        let shell_resume = log.contains("SHELL resume OK");

        let total = t0.elapsed().as_secs_f64();
        let line = format!(
            "{{\"cycle\":{},\"ts\":{},\"layout_seed\":{},\"morph\":\"accepted\",\"morph_secs\":{:.1},\"build_secs\":{:.1},\"boot_secs\":{:.1},\"total_secs\":{:.1},\"prod\":{},\"halt\":{},\"shell_compose\":{},\"shell_resume\":{},\"continuity\":\"{}\"}}\n",
            cycle, ts, layout_seed, morph_secs, build_secs, boot_secs, total, prod, halt,
            shell_compose, shell_resume, continuity.replace('"', "'")
        );
        use std::io::Write as _;
        let mut f = fs::OpenOptions::new().create(true).append(true).open(&scorecard)?;
        f.write_all(line.as_bytes())?;
        eprintln!(
            "phase2: cycle {} done in {:.1}s (morph {:.1} build {:.1} boot {:.1}) shell_compose={} shell_resume={} continuity: {}",
            cycle, total, morph_secs, build_secs, boot_secs, shell_compose, shell_resume, continuity
        );
        // Ephemeral retention: once cycle N completes, prune cycle N-1's
        // disk image and serial log so multi-hundred-cycle soaks stay
        // flat on disk.
        if cycle > 1 {
            let prev = cycle - 1;
            let _ = fs::remove_file(work.join(format!("prod_c{}.img", prev)));
            let _ = fs::remove_file(work.join(format!("boot_c{}.log", prev)));
        }
    }

    eprintln!("phase2: scorecard at {}", scorecard.display());
    Ok(())
}
