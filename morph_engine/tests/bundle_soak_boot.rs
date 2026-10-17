//! Bundle soak **then** QEMU boot — strongest short factory proof.
//!
//! Closes the gap between:
//! - mini-bundle daemon soak (morph + attest, no boot)
//! - one-shot morphed_qemu_proof (diversify + boot, no daemon/attest)
//!
//! Sequence:
//! 1. Snapshot `tls` / `wal` / `net`
//! 2. Run the production daemon for N mini-bundle cycles
//!    (passthrough → diversify → verify → sign → deploy → attest)
//! 3. **Leave sources morphed**
//! 4. Build kernel under layout seed from the last cycle number
//! 5. Package + boot under QEMU; assert TLS/WAL/NET banners + HALT
//! 6. Restore pristines
//!
//! # Invocation
//!
//! ```text
//! $env:PROTEUS_BUNDLE_SOAK_BOOT = "1"
//! $env:PROTEUS_SOAK_ITERS = "2"   # optional; default 2
//! cargo test -p proteus-morph-engine --test bundle_soak_boot -- --nocapture
//! ```
//!
//! Or: `tools\bundle_soak_boot.ps1`

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proteus_morph_engine::{
    daemon::{run_daemon, DaemonArgs, DAEMON_LOG},
    verify_chain_with_options, SynthesizerKind, VerifyOptions, ATTEST_DIR_ENV,
};

static MUTEX: Mutex<()> = Mutex::new(());

const MODULES: &[&str] = &["tls", "wal", "net"];

const REQUIRED_BANNERS: &[&str] = &[
    "PROTEUS-TE OK",
    "TLS hkdf OK prk_sha=",
    "TLS server_hello OK len=",
    "WAL replay OK frames=",
    "NET build OK len=38 ip_cksum=63c7 udp_cksum=fa94",
    "PROTEUS-TE HALT",
];

/// Same bijective mix as `diversity_demo::cycle_layout_seed` /
/// `morph_engine::cycle::kernel_layout_seed`.
fn cycle_layout_seed(cycle: u64) -> u64 {
    const C1: u64 = 0x9E37_79B9_7F4A_7C15;
    const C2: u64 = 0x5DEE_CE66_D3A8_31EF;
    cycle.wrapping_mul(C1) ^ C2
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

fn soak_root() -> PathBuf {
    workspace_root().join("experiments").join("soak_bundle_mini")
}

fn find_qemu() -> Option<PathBuf> {
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
    let win = PathBuf::from("C:/Program Files/qemu/qemu-system-x86_64.exe");
    if win.exists() {
        Some(win)
    } else {
        None
    }
}

fn snapshot_modules(root: &Path) -> Vec<(PathBuf, String)> {
    let src = root.join("target_enterprise").join("src");
    MODULES
        .iter()
        .map(|m| {
            let p = src.join(format!("{}.rs", m));
            let body = fs::read_to_string(&p).unwrap_or_else(|e| panic!("read {}: {}", p.display(), e));
            (p, body)
        })
        .collect()
}

fn restore_modules(snaps: &[(PathBuf, String)]) {
    for (p, body) in snaps {
        let _ = fs::write(p, body);
        let _ = fs::remove_file(p.with_extension("candidate.rs"));
    }
}

fn count_kind(events: &[serde_json::Value], kind: &str) -> usize {
    events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .count()
}

fn read_jsonl(path: &Path) -> Vec<serde_json::Value> {
    fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Package ELF + boot QEMU until PROTEUS-TE HALT (or timeout).
fn boot_kernel(elf: &Path, results_dir: &Path, cycle: u64) -> Result<PathBuf, String> {
    let qemu = find_qemu().ok_or_else(|| "qemu-system-x86_64 not found".to_string())?;
    let pkg = factory_builder::locate_pkg_crate().map_err(|e| format!("{:#}", e))?;

    let logs = results_dir.join("serial_logs");
    let images = results_dir.join("images");
    fs::create_dir_all(&logs).ok();
    fs::create_dir_all(&images).ok();
    let bios = images.join(format!("cycle_{}.img", cycle));
    let serial = logs.join(format!("cycle_{}.log", cycle));
    let _ = fs::remove_file(&bios);
    let _ = fs::remove_file(&serial);

    factory_builder::package_kernel_via_pkg(&pkg, elf, &bios, None)
        .map_err(|e| format!("package: {:#}", e))?;

    let device_key_file = results_dir.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    let _ = factory_builder::ensure_device_secret_key(&device_key_file)
        .map_err(|e| format!("{:#}", e))?;

    let mut qproc = Command::new(&qemu)
        .arg("-drive")
        .arg(format!("format=raw,file={}", bios.display()))
        .arg("-fw_cfg")
        .arg(format!(
            "name={},file={}",
            factory_builder::FW_CFG_DEVICE_KEY_NAME,
            device_key_file.display()
        ))
        .arg("-serial")
        .arg(format!("file:{}", serial.display()))
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-m")
        .arg("256M")
        .arg("-d")
        .arg("cpu_reset")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .map_err(|e| format!("spawn qemu: {}", e))?;

    let deadline = Instant::now() + Duration::from_secs(25);
    let mut halted = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(s) = fs::read_to_string(&serial) {
            if s.contains("PROTEUS-TE HALT") {
                halted = true;
                break;
            }
        }
    }
    let _ = qproc.kill();
    let _ = qproc.wait();

    if !halted {
        let preview: String = fs::read_to_string(&serial)
            .unwrap_or_default()
            .chars()
            .take(2000)
            .collect();
        return Err(format!(
            "no PROTEUS-TE HALT within 25s; serial preview:\n{}",
            preview
        ));
    }
    Ok(serial)
}

#[test]
fn mini_bundle_soak_then_qemu_boot() {
    if std::env::var("PROTEUS_BUNDLE_SOAK_BOOT").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: set PROTEUS_BUNDLE_SOAK_BOOT=1 to run mini-bundle soak + QEMU boot \
             (needs QEMU + nightly kernel build; several minutes)"
        );
        return;
    }

    let _g = MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let soak = soak_root();
    assert!(
        soak.join("scheduler.toml").exists(),
        "missing soak_bundle_mini/scheduler.toml"
    );

    let iters: u64 = std::env::var("PROTEUS_SOAK_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    assert!((1..=5).contains(&iters));

    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = root.join("factory_builder_pkg");
    if !kernel_crate.join("Cargo.toml").exists() {
        eprintln!("SKIP: target_enterprise_kernel missing");
        return;
    }
    if !pkg_crate.join("Cargo.toml").exists() {
        eprintln!("SKIP: factory_builder_pkg missing");
        return;
    }
    if find_qemu().is_none() {
        eprintln!("SKIP: QEMU not found");
        return;
    }
    assert!(
        root.join("factory_signing_key.bin").exists(),
        "factory_signing_key.bin missing"
    );

    let st = Command::new("cargo")
        .args(["build", "-p", "proteus-verifier", "--bin", "verify"])
        .current_dir(&root)
        .status()
        .expect("build verify");
    assert!(st.success());

    let snaps = snapshot_modules(&root);
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let results_dir = soak
        .join("results")
        .join(format!("boot_run_{}", run_id));
    fs::create_dir_all(&results_dir).ok();

    let prev_attest = std::env::var_os(ATTEST_DIR_ENV);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &results_dir);
    }

    let state_path = soak.join("scheduler_state.json");
    let daemon_log = soak.join(DAEMON_LOG);
    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&daemon_log);

    let prev_cwd = std::env::current_dir().unwrap();
    std::env::set_current_dir(&root).unwrap();

    let daemon_args = DaemonArgs {
        root: soak.clone(),
        max_iters: iters,
        max_cycle_secs: 900,
        heartbeat_secs: 3600,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: true,
    };

    eprintln!(
        "bundle_soak_boot: phase 1 daemon max_iters={} modules={:?}",
        iters, MODULES
    );

    let report = match run_daemon(&daemon_args) {
        Ok(r) => r,
        Err(e) => {
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            restore_modules(&snaps);
            panic!("daemon failed: {:#}", e);
        }
    };

    eprintln!(
        "bundle_soak_boot: daemon accepted={} rejected={}",
        report.cycles_accepted, report.cycles_rejected
    );
    assert_eq!(report.cycles_rejected, 0, "daemon must not reject");
    assert!(
        report.cycles_accepted >= iters,
        "accepted {} < {}",
        report.cycles_accepted,
        iters
    );

    let events = read_jsonl(&daemon_log);
    assert!(
        count_kind(&events, "cycle_accept") >= iters as usize,
        "missing cycle_accept events"
    );

    let attest_ok = verify_chain_with_options(&VerifyOptions::default()).is_ok();
    assert!(attest_ok, "attest chain must verify after soak");

    // Last accepted cycle number for layout seed (global_cycle after N accepts).
    let last_cycle = {
        let state_txt = fs::read_to_string(&state_path).unwrap_or_default();
        // scheduler_state.json: { "global_cycle": N, ... }
        serde_json::from_str::<serde_json::Value>(&state_txt)
            .ok()
            .and_then(|v| v.get("global_cycle").and_then(|c| c.as_u64()))
            .unwrap_or(iters)
    };
    let layout_seed = cycle_layout_seed(last_cycle);
    eprintln!(
        "bundle_soak_boot: phase 2 build kernel layout_seed={:#x} (cycle {})",
        layout_seed, last_cycle
    );

    // Sources are still morphed on disk — that is the point.
    let elf = match factory_builder::build_kernel_with_layout_seed(
        &kernel_crate,
        Some(layout_seed),
    ) {
        Ok(p) => p,
        Err(e) => {
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            restore_modules(&snaps);
            eprintln!("SKIP: kernel build failed: {:#}", e);
            return;
        }
    };

    eprintln!("bundle_soak_boot: phase 3 QEMU boot {}", elf.display());
    let serial = match boot_kernel(&elf, &results_dir, last_cycle) {
        Ok(p) => p,
        Err(e) => {
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            restore_modules(&snaps);
            panic!("QEMU boot failed after morphed bundle soak: {}", e);
        }
    };

    let log_text = fs::read_to_string(&serial).expect("read serial");
    let mut missing = Vec::new();
    for b in REQUIRED_BANNERS {
        if !log_text.contains(b) {
            missing.push(*b);
        } else {
            eprintln!("bundle_soak_boot: observed: {}", b);
        }
    }
    if !missing.is_empty() {
        std::env::set_current_dir(&prev_cwd).ok();
        unsafe {
            match prev_attest {
                Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                None => std::env::remove_var(ATTEST_DIR_ENV),
            }
        }
        restore_modules(&snaps);
        panic!(
            "missing banners after bundle soak + boot: {:?}\nlog tail:\n{}",
            missing,
            log_text.chars().rev().take(1500).collect::<String>().chars().rev().collect::<String>()
        );
    }

    // Archive daemon log
    if daemon_log.exists() {
        let _ = fs::copy(&daemon_log, results_dir.join(DAEMON_LOG));
    }
    let report_md = format!(
        "# Bundle soak + QEMU boot REPORT\n\n\
         - iters: {iters}\n\
         - cycles_accepted: {acc}\n\
         - cycles_rejected: {rej}\n\
         - last_cycle: {last}\n\
         - layout_seed: {seed:#x}\n\
         - modules: {mods:?}\n\
         - banners: all {nb} required present\n\
         - attest: PASS\n\
         - serial_log: {log}\n\n\
         **PASS**\n",
        iters = iters,
        acc = report.cycles_accepted,
        rej = report.cycles_rejected,
        last = last_cycle,
        seed = layout_seed,
        mods = MODULES,
        nb = REQUIRED_BANNERS.len(),
        log = serial.display(),
    );
    let _ = fs::write(results_dir.join("REPORT.md"), report_md);

    restore_modules(&snaps);
    std::env::set_current_dir(&prev_cwd).ok();
    unsafe {
        match prev_attest {
            Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
            None => std::env::remove_var(ATTEST_DIR_ENV),
        }
    }

    for (p, before) in &snaps {
        let after = fs::read_to_string(p).unwrap();
        assert_eq!(&after, before, "restore failed for {}", p.display());
    }

    eprintln!(
        "bundle_soak_boot: PASS results={}",
        results_dir.display()
    );
}
