//! North-star cadence soak — N consecutive full `[bundle.kernel]` cycles.
//!
//! TASK-123 / gates G1–G6 (diversify-first, no LLM required):
//!
//! ```text
//! daemon tick × N:
//!   pick [bundle.kernel] → diversify×M → verify → sign → deploy → attest
//! [optional TASK-127] leave sources morphed → layout-seeded kernel → QEMU
//! ```
//!
//! # Invocation
//!
//! ```text
//! $env:PROTEUS_NORTH_STAR_SOAK = "1"
//! $env:PROTEUS_SOAK_ITERS = "5"   # optional; default 5
//! cargo test -p proteus-morph-engine --test north_star_soak -- --nocapture
//!
//! # Cadence + boot (TASK-127):
//! $env:PROTEUS_NORTH_STAR_BOOT = "1"
//! tools\north_star_soak.ps1 -Iters 1 -Boot
//!
//! # Optional durable seals gate (TASK-150; needs seals dir attached):
//! $env:PROTEUS_DURABLE_SEALS_DIR = "path\to\seals"
//! $env:PROTEUS_SOAK_REQUIRE_DURABLE_SEALS = "1"
//! ```
//!
//! Or: `tools/north_star_soak.ps1`
//!
//! # Always-on checks
//!
//! Without the env gate, the suite still runs cheap unit-style tests
//! that parse production `scheduler.toml` and validate report helpers
//! so the north-star driver stays wired in CI.

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use proteus_morph_engine::{
    daemon::{run_daemon, DaemonArgs, DaemonReport, DAEMON_LOG},
    verify_chain_with_options, SynthesizerKind, VerifyOptions, ATTEST_DIR_ENV,
};

static SOAK_MUTEX: Mutex<()> = Mutex::new(());

const DEFAULT_ITERS: u64 = 5;
const MAX_ITERS: u64 = 20;
/// Full-bundle verify can take many minutes per cycle on cold TCG/host.
const MAX_CYCLE_SECS: u64 = 1800;
/// Full enterprise kernel under TCG (HW devices + banner inventory).
const QEMU_BOOT_TIMEOUT_SECS: u64 = 180;

/// Core banners proving morphed full-bundle sources still boot (TASK-127).
/// Same high-value set as mini-bundle soak-boot; full enrollment is covered
/// by separate qemu_smoke / morphed_qemu_proof banner inventories.
const BOOT_REQUIRED_BANNERS: &[&str] = &[
    "PROTEUS-TE OK",
    "TLS hkdf OK prk_sha=",
    "TLS server_hello OK len=",
    "WAL replay OK frames=",
    "NET build OK len=38 ip_cksum=63c7 udp_cksum=fa94",
    "PROTEUS-TE HALT",
];

/// Hardware-truth lines reported in REPORT when `-Boot` (TASK-135).
/// Not all are hard-fail gates here (full set is qemu_smoke / morphed
/// proof); missing ones are listed so operators can triage without a
/// second QEMU run.
const BOOT_HW_FORENSIC_BANNERS: &[&str] = &[
    "VIRTIO_HW probe OK blk=found slot=",
    "VIRTIO_HW sector OK first_byte=a5",
    "VIRTIO_NET_HW probe OK slot=",
    "VIRTIO_NET_HW tx OK bytes=76",
    "VIRTIO_NET_HW rx OK bytes=",
    "AHCI_HW probe OK slot=",
    "AHCI_HW identify OK sectors=2048",
    "AHCI_HW sector OK first_byte=5a",
    "E1000_HW probe OK slot=",
    "E1000_HW tx OK bytes=64",
    "E1000_HW rx OK bytes=",
    "NVME_HW probe OK slot=",
    "NVME_HW identify OK sn=",
    "NVME_HW sector OK first_byte=5a",
];

/// Minimal HW subset hard-failed when `PROTEUS_NORTH_STAR_REQUIRE_HW=1`
/// (TASK-139). Default off so cadence+boot stays lean; enable for
/// ops that want storage+net HW on the north-star path.
const BOOT_HW_REQUIRED_MIN: &[&str] = &[
    "VIRTIO_HW sector OK first_byte=a5",
    "VIRTIO_NET_HW tx OK bytes=76",
    "E1000_HW tx OK bytes=64",
    "NVME_HW sector OK first_byte=5a",
];

/// Same bijective mix as `morph_engine::cycle::kernel_layout_seed`.
fn cycle_layout_seed(cycle: u64) -> u64 {
    const C1: u64 = 0x9E37_79B9_7F4A_7C15;
    const C2: u64 = 0x5DEE_CE66_D3A8_31EF;
    cycle.wrapping_mul(C1) ^ C2
}

/// TASK-150: whether soak post-verify should require durable_seals.
/// True when either env is exactly `"1"`. Default off (empty seals green).
fn soak_require_durable_seals(soak_env: Option<&str>, verify_env: Option<&str>) -> bool {
    soak_env == Some("1") || verify_env == Some("1")
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

/// Package ELF + boot QEMU until PROTEUS-TE HALT (or timeout).
///
/// Device set matches `factory_builder` qemu_smoke / diversity_demo
/// (virtio-blk, dual virtio-net hub, AHCI, e1000). Without these the
/// full kernel panics on `VIRTIO_HW` / net / AHCI banners before HALT.
fn boot_kernel(elf: &Path, results_dir: &Path, cycle: u64) -> Result<PathBuf, String> {
    let qemu = find_qemu().ok_or_else(|| "qemu-system-x86_64 not found".to_string())?;
    let pkg = factory_builder::locate_pkg_crate().map_err(|e| format!("{:#}", e))?;

    let logs = results_dir.join("serial_logs");
    let images = results_dir.join("images");
    fs::create_dir_all(&logs).ok();
    fs::create_dir_all(&images).ok();
    let bios = images.join(format!("north_star_cycle_{}.img", cycle));
    let serial = logs.join(format!("north_star_cycle_{}.log", cycle));
    let _ = fs::remove_file(&bios);
    let _ = fs::remove_file(&serial);

    factory_builder::package_kernel_via_pkg(&pkg, elf, &bios, None)
        .map_err(|e| format!("package: {:#}", e))?;

    // Shared 1 MiB disks (same layout as qemu_smoke).
    let virtio_disk = images.join("virtio_hw.img");
    if !virtio_disk.exists()
        || fs::metadata(&virtio_disk).map(|m| m.len()).unwrap_or(0) < 1024 * 1024
    {
        fs::write(&virtio_disk, vec![0u8; 1024 * 1024]).map_err(|e| e.to_string())?;
    }
    let ahci_disk = images.join("ahci_hw.img");
    if !ahci_disk.exists() || fs::metadata(&ahci_disk).map(|m| m.len()).unwrap_or(0) < 1024 * 1024 {
        fs::write(&ahci_disk, vec![0u8; 1024 * 1024]).map_err(|e| e.to_string())?;
    }
    let nvme_disk = images.join("nvme_hw.img");
    if !nvme_disk.exists() || fs::metadata(&nvme_disk).map(|m| m.len()).unwrap_or(0) < 1024 * 1024 {
        fs::write(&nvme_disk, vec![0u8; 1024 * 1024]).map_err(|e| e.to_string())?;
    }

    let device_key_file = results_dir.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    let _ = factory_builder::ensure_device_secret_key(&device_key_file)
        .map_err(|e| format!("{:#}", e))?;

    // Force TCG — WHPX on some Windows hosts never advances BIOS.
    // Boot BIOS on IDE; virtio-blk is a second disk for hardware-truth.
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
        .arg("-netdev")
        .arg("hubport,id=n0,hubid=1")
        .arg("-device")
        .arg("virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on")
        .arg("-netdev")
        .arg("hubport,id=n1,hubid=1")
        .arg("-device")
        .arg("virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on")
        .arg("-drive")
        .arg(format!(
            "if=none,id=ahd0,format=raw,file={}",
            ahci_disk.display()
        ))
        .arg("-device")
        .arg("ahci,id=ahci0")
        .arg("-device")
        .arg("ide-hd,drive=ahd0,bus=ahci0.0")
        .arg("-netdev")
        .arg("hubport,id=e0,hubid=2")
        .arg("-device")
        .arg("e1000,netdev=e0")
        .arg("-netdev")
        .arg("hubport,id=e1,hubid=2")
        .arg("-device")
        .arg("e1000,netdev=e1")
        .arg("-drive")
        .arg(format!(
            "if=none,id=nvme0,format=raw,file={}",
            nvme_disk.display()
        ))
        .arg("-device")
        .arg("nvme,drive=nvme0,serial=PROTEUS-NVME-HW")
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

    let deadline = Instant::now() + Duration::from_secs(QEMU_BOOT_TIMEOUT_SECS);
    let mut halted = false;
    while Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(250));
        if let Ok(s) = fs::read_to_string(&serial) {
            if s.contains("PROTEUS-TE HALT") {
                halted = true;
                break;
            }
            // Fail fast on panic so we do not burn the full timeout.
            if s.contains("PROTEUS-TE PANIC") {
                let _ = qproc.kill();
                let _ = qproc.wait();
                return Err(format!(
                    "kernel panicked before HALT; serial tail:\n{}",
                    s.chars()
                        .rev()
                        .take(1500)
                        .collect::<String>()
                        .chars()
                        .rev()
                        .collect::<String>()
                ));
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
            "no PROTEUS-TE HALT within {}s; serial preview:\n{}",
            QEMU_BOOT_TIMEOUT_SECS, preview
        ));
    }
    Ok(serial)
}

struct BootProof {
    last_cycle: u64,
    layout_seed: u64,
    serial_log: PathBuf,
    banners_ok: usize,
    /// TASK-135: HW prefixes observed (subset of BOOT_HW_FORENSIC_BANNERS).
    hw_observed: Vec<String>,
    /// TASK-135: HW prefixes missing from serial (forensics only).
    hw_missing: Vec<String>,
}

fn scan_hw_forensics(log_text: &str) -> (Vec<String>, Vec<String>) {
    let mut observed = Vec::new();
    let mut missing = Vec::new();
    for b in BOOT_HW_FORENSIC_BANNERS {
        if log_text.contains(b) {
            observed.push((*b).to_string());
        } else {
            missing.push((*b).to_string());
        }
    }
    (observed, missing)
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("morph_engine parent")
        .to_path_buf()
}

fn soak_root() -> PathBuf {
    workspace_root().join("experiments").join("north_star_soak")
}

/// Load `[bundle.kernel].modules` from the production workspace
/// `scheduler.toml` so the soak always tracks enrollment (no stale
/// module list in experiments/).
fn load_bundle_kernel_modules(root: &Path) -> Vec<String> {
    let path = root.join("scheduler.toml");
    let text = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
    let value: toml::Value = text
        .parse()
        .unwrap_or_else(|e| panic!("parse scheduler.toml: {}", e));
    let modules = value
        .get("bundle")
        .and_then(|b| b.get("kernel"))
        .and_then(|k| k.get("modules"))
        .and_then(|m| m.as_array())
        .unwrap_or_else(|| panic!("scheduler.toml missing [bundle.kernel].modules"));
    modules
        .iter()
        .map(|v| {
            v.as_str()
                .unwrap_or_else(|| panic!("module entry not a string: {:?}", v))
                .to_string()
        })
        .collect()
}

/// Write a soak-local scheduler that only declares `[bundle.kernel]`
/// with `max_age_secs = 0` so every daemon tick picks the full bundle.
fn write_soak_scheduler(path: &Path, modules: &[String]) {
    let mut body = String::from(
        "# Auto-generated by north_star_soak — do not hand-edit.\n\
         # Full production [bundle.kernel] enrollment; due every tick.\n\
         # Paths are workspace-relative; daemon --root points here.\n\n\
         [bundle.kernel]\n\
         priority = 1000\n\
         max_age_secs = 0\n\
         workspace = \"target_enterprise\"\n\
         modules = [\n",
    );
    for m in modules {
        body.push_str(&format!("    \"{}\",\n", m));
    }
    body.push_str("]\n");
    fs::write(path, body).unwrap_or_else(|e| panic!("write {}: {}", path.display(), e));
}

fn count_kind(events: &[serde_json::Value], kind: &str) -> usize {
    events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .count()
}

fn count_bundle_accepts(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|e| {
            e.get("kind").and_then(|v| v.as_str()) == Some("cycle_accept")
                && e.get("work_kind").and_then(|v| v.as_str()) == Some("bundle")
        })
        .count()
}

fn read_jsonl_events(path: &Path) -> Vec<serde_json::Value> {
    let txt = fs::read_to_string(path).unwrap_or_default();
    txt.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

/// Distinct accepted bundle hashes from the soak attest chain.
fn collect_bundle_hashes(attest_path: &Path) -> Vec<String> {
    let txt = fs::read_to_string(attest_path).unwrap_or_default();
    let mut out = Vec::new();
    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let accepted = v.get("accepted").and_then(|a| a.as_bool()).unwrap_or(false);
        let is_bundle = v.get("bundle_name").and_then(|b| b.as_str()).is_some();
        if !accepted || !is_bundle {
            continue;
        }
        if let Some(h) = v.get("candidate_sha256").and_then(|c| c.as_str()) {
            out.push(h.to_string());
        }
    }
    out
}

/// Count diversifier decisions recorded on accepted bundle entries
/// (stack_pad + codegen_perturb keys across the log maps).
fn diversifier_decision_count(attest_path: &Path) -> usize {
    let txt = fs::read_to_string(attest_path).unwrap_or_default();
    let mut n = 0usize;
    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        let Some(log) = v.get("diversifier_log") else {
            continue;
        };
        // Serde field names on DiversifierLog (attest.rs).
        for key in ["pad_decisions", "perturb_decisions"] {
            if let Some(map) = log.get(key).and_then(|m| m.as_object()) {
                n += map.len();
            }
        }
    }
    n
}

fn snapshot_modules(root: &Path, modules: &[String]) -> Vec<(PathBuf, String)> {
    let src = root.join("target_enterprise").join("src");
    modules
        .iter()
        .map(|m| {
            let p = src.join(format!("{}.rs", m));
            let body = fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("read {}: {}", p.display(), e));
            (p, body)
        })
        .collect()
}

fn restore_modules(snaps: &[(PathBuf, String)]) {
    for (p, body) in snaps {
        let _ = fs::write(p, body);
        let cand = p.with_extension("candidate.rs");
        let _ = fs::remove_file(cand);
        // diversify may leave .preexp.bak
        let bak = p.with_extension("rs.preexp.bak");
        let _ = fs::remove_file(bak);
    }
}

/// Summary of diversity fields across accepted attest entries (TASK-125).
struct DiversitySummary {
    entries_with_diversity: usize,
    pad_sum: u64,
    perturb_sum: u64,
    with_elf_metrics: usize,
    with_positional_bps: usize,
    min_positional_bps: Option<u32>,
}

fn summarize_diversity(attest_path: &Path) -> DiversitySummary {
    let txt = fs::read_to_string(attest_path).unwrap_or_default();
    let mut s = DiversitySummary {
        entries_with_diversity: 0,
        pad_sum: 0,
        perturb_sum: 0,
        with_elf_metrics: 0,
        with_positional_bps: 0,
        min_positional_bps: None,
    };
    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("accepted").and_then(|a| a.as_bool()) != Some(true) {
            continue;
        }
        let Some(d) = v.get("diversity") else {
            continue;
        };
        s.entries_with_diversity += 1;
        if let Some(p) = d.get("pad_decision_count").and_then(|x| x.as_u64()) {
            s.pad_sum += p;
        }
        if let Some(p) = d.get("perturb_decision_count").and_then(|x| x.as_u64()) {
            s.perturb_sum += p;
        }
        let has_elf = d.get("base_text_sha256").is_some()
            || d.get("variant_text_sha256").is_some()
            || d.get("positional_survival_bps").is_some();
        if has_elf {
            s.with_elf_metrics += 1;
        }
        if let Some(bps) = d
            .get("positional_survival_bps")
            .and_then(|x| x.as_u64())
            .map(|u| u as u32)
        {
            s.with_positional_bps += 1;
            s.min_positional_bps = Some(match s.min_positional_bps {
                Some(m) => m.min(bps),
                None => bps,
            });
        }
    }
    s
}

/// TASK-152: durable_seals forensics on accepted attest entries.
#[derive(Debug, Default, Clone)]
struct DurableSealsSummary {
    /// Accepted entries scanned.
    accepted: usize,
    /// Accepted entries with non-empty `durable_seals` map.
    with_seals: usize,
    /// Union of seal labels across those entries (sorted).
    labels: Vec<String>,
}

fn summarize_durable_seals(attest_path: &Path) -> DurableSealsSummary {
    let txt = fs::read_to_string(attest_path).unwrap_or_default();
    let mut s = DurableSealsSummary::default();
    let mut label_set: BTreeSet<String> = BTreeSet::new();
    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let Ok(v) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if v.get("accepted").and_then(|a| a.as_bool()) != Some(true) {
            continue;
        }
        s.accepted += 1;
        let Some(map) = v.get("durable_seals").and_then(|d| d.as_object()) else {
            continue;
        };
        if map.is_empty() {
            continue;
        }
        s.with_seals += 1;
        for k in map.keys() {
            label_set.insert(k.clone());
        }
    }
    s.labels = label_set.into_iter().collect();
    s
}

/// Format REPORT line for durable seals (TASK-152).
fn format_durable_seals_report(sum: &DurableSealsSummary) -> String {
    if sum.accepted == 0 {
        return "durable_seals: no accepted entries".into();
    }
    if sum.with_seals == 0 {
        return format!(
            "durable_seals: present on 0/{} accepted | labels=(none)",
            sum.accepted
        );
    }
    let labels = if sum.labels.is_empty() {
        "(none)".into()
    } else {
        sum.labels.join(",")
    };
    format!(
        "durable_seals: present on {}/{} accepted | labels={}",
        sum.with_seals, sum.accepted, labels
    )
}

fn write_report(
    results_dir: &Path,
    report: &DaemonReport,
    events: &[serde_json::Value],
    attest_ok: bool,
    iters: u64,
    modules: &[String],
    wall_secs: f64,
    bundle_hashes: &[String],
    div_decisions: usize,
    div_sum: &DiversitySummary,
    seals_sum: &DurableSealsSummary,
    boot: Option<&BootProof>,
    boot_requested: bool,
) {
    let accepts = count_kind(events, "cycle_accept");
    let rejects = count_kind(events, "cycle_reject");
    let bundle_acc = count_bundle_accepts(events);
    let distinct: BTreeSet<&str> = bundle_hashes.iter().map(|s| s.as_str()).collect();
    let unique_n = distinct.len();
    let image_note = "source-side diversity always; ELF metrics when --emit-image \
                      / PROTEUS_SOAK_EMIT_IMAGE=1 (TASK-126)";

    let boot_ok = !boot_requested || boot.is_some();
    let pass = report.cycles_accepted >= iters
        && report.cycles_rejected == 0
        && bundle_acc >= iters as usize
        && rejects == 0
        && attest_ok
        && unique_n >= iters as usize
        && div_sum.entries_with_diversity >= iters as usize
        && boot_ok;

    let boot_section = match boot {
        Some(b) => {
            let hw_ok: String = b
                .hw_observed
                .iter()
                .map(|s| format!("  - `{s}`"))
                .collect::<Vec<_>>()
                .join("\n");
            let hw_miss: String = if b.hw_missing.is_empty() {
                "  (none)".into()
            } else {
                b.hw_missing
                    .iter()
                    .map(|s| format!("  - `{s}`"))
                    .collect::<Vec<_>>()
                    .join("\n")
            };
            format!(
                "## QEMU boot (TASK-127/135)\n\n\
                 - requested: yes\n\
                 - last_cycle: {last}\n\
                 - layout_seed: {seed:#x}\n\
                 - core banners_ok: {nb}/{need}\n\
                 - HW forensic observed: {hwo}/{hwt}\n\
                 - serial_log: `{log}`\n\n\
                 ### HW lines observed\n\n\
                 {hw_ok}\n\n\
                 ### HW lines missing (forensics; not core gate)\n\n\
                 {hw_miss}\n\n",
                last = b.last_cycle,
                seed = b.layout_seed,
                nb = b.banners_ok,
                need = BOOT_REQUIRED_BANNERS.len(),
                hwo = b.hw_observed.len(),
                hwt = BOOT_HW_FORENSIC_BANNERS.len(),
                log = b.serial_log.display(),
                hw_ok = if hw_ok.is_empty() {
                    "  (none)".into()
                } else {
                    hw_ok
                },
                hw_miss = hw_miss,
            )
        }
        None if boot_requested => {
            "## QEMU boot (TASK-127)\n\n- requested: yes\n- result: **FAIL / not completed**\n\n"
                .into()
        }
        None => {
            "## QEMU boot (TASK-127)\n\n- requested: no (set PROTEUS_NORTH_STAR_BOOT=1 or -Boot)\n\n"
                .into()
        }
    };

    let body = format!(
        "# North-star cadence soak REPORT (TASK-123/125/127)\n\n\
         ## Config\n\n\
         - Bundle: `[bundle.kernel]` ({nmod} modules)\n\
         - Workspace: `target_enterprise`\n\
         - Synthesizer: passthrough + diversify (no LLM)\n\
         - Requested accepted cycles: {iters}\n\
         - Wall-clock (s): {wall:.1}\n\
         - Results dir: `{results}`\n\n\
         ## DaemonReport\n\n\
         - ticks_executed: {ticks}\n\
         - cycles_accepted: {acc}\n\
         - cycles_rejected: {rej}\n\
         - cycles_overrun: {ovr}\n\
         - idle_ticks: {idle}\n\n\
         ## daemon.log\n\n\
         - cycle_accept: {elog_acc} (bundle: {bundle_acc})\n\
         - cycle_reject: {elog_rej}\n\n\
         ## Attestation\n\n\
         - verify-attest (require_ext_tlv + require_diversity): {attest}\n\
         - accepted bundle entries: {nhash}\n\
         - distinct candidate_sha256: {unique}\n\
         - diversifier decision keys (sum): {div}\n\
         - entries with diversity: {dwith}\n\
         - pad_decision_count sum: {pad}\n\
         - perturb_decision_count sum: {pert}\n\
         - entries with ELF metrics: {elf}\n\
         - entries with positional_bps: {posn} (min={posmin})\n\
         - image note: {image_note}\n\
         - {seals_line}\n\n\
         {boot_section}\
         ## Modules\n\n\
         ```\n{mods}\n```\n\n\
         ## Verdict\n\n\
         {verdict}\n",
        nmod = modules.len(),
        iters = iters,
        wall = wall_secs,
        results = results_dir.display(),
        ticks = report.ticks_executed,
        acc = report.cycles_accepted,
        rej = report.cycles_rejected,
        ovr = report.cycles_overrun,
        idle = report.idle_ticks,
        elog_acc = accepts,
        bundle_acc = bundle_acc,
        elog_rej = rejects,
        attest = if attest_ok { "PASS" } else { "FAIL" },
        nhash = bundle_hashes.len(),
        unique = unique_n,
        div = div_decisions,
        dwith = div_sum.entries_with_diversity,
        pad = div_sum.pad_sum,
        pert = div_sum.perturb_sum,
        elf = div_sum.with_elf_metrics,
        posn = div_sum.with_positional_bps,
        posmin = div_sum
            .min_positional_bps
            .map(|b| b.to_string())
            .unwrap_or_else(|| "n/a".into()),
        image_note = image_note,
        seals_line = format_durable_seals_report(seals_sum),
        boot_section = boot_section,
        mods = modules.join(", "),
        verdict = if pass {
            "**PASS** — north-star cadence (+boot if requested) met acceptance criteria."
        } else {
            "**FAIL** — see counters above."
        },
    );
    let _ = fs::write(results_dir.join("REPORT.md"), body);
}

// ---------------------------------------------------------------------------
// Always-on: enrollment parse + helper smoke (no daemon, no cargo verify)
// ---------------------------------------------------------------------------

#[test]
fn production_bundle_kernel_modules_nonempty() {
    let mods = load_bundle_kernel_modules(&workspace_root());
    assert!(
        mods.len() >= 3,
        "expected production [bundle.kernel] to enroll ≥3 modules, got {}",
        mods.len()
    );
    // Stable anchors that have been in the bundle since early TASK-036.
    for must in ["tls", "wal", "net"] {
        assert!(
            mods.iter().any(|m| m == must),
            "bundle.kernel missing required module {:?}",
            must
        );
    }
    // No empty names / duplicates.
    let set: BTreeSet<&str> = mods.iter().map(|s| s.as_str()).collect();
    assert_eq!(set.len(), mods.len(), "duplicate module names in bundle.kernel");
    assert!(mods.iter().all(|m| !m.is_empty()));
}

#[test]
fn write_soak_scheduler_roundtrip() {
    let dir = std::env::temp_dir().join(format!(
        "proteus_nss_sched_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("tempdir");
    let path = dir.join("scheduler.toml");
    let mods = vec!["tls".into(), "wal".into(), "net".into()];
    write_soak_scheduler(&path, &mods);
    let text = fs::read_to_string(&path).expect("read back");
    assert!(text.contains("[bundle.kernel]"));
    assert!(text.contains("max_age_secs = 0"));
    assert!(text.contains("\"tls\""));
    assert!(text.contains("workspace = \"target_enterprise\""));

    let value: toml::Value = text.parse().expect("parse soak scheduler");
    let loaded: Vec<String> = value
        .get("bundle")
        .and_then(|b| b.get("kernel"))
        .and_then(|k| k.get("modules"))
        .and_then(|m| m.as_array())
        .expect("modules")
        .iter()
        .map(|v| v.as_str().unwrap().to_string())
        .collect();
    assert_eq!(loaded, mods);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn count_bundle_accepts_filters_work_kind() {
    let events = vec![
        serde_json::json!({"kind": "cycle_accept", "work_kind": "bundle"}),
        serde_json::json!({"kind": "cycle_accept", "work_kind": "module"}),
        serde_json::json!({"kind": "cycle_reject", "work_kind": "bundle"}),
        serde_json::json!({"kind": "heartbeat"}),
    ];
    assert_eq!(count_bundle_accepts(&events), 1);
    assert_eq!(count_kind(&events, "cycle_accept"), 2);
    assert_eq!(count_kind(&events, "cycle_reject"), 1);
}

#[test]
fn cycle_layout_seed_deterministic() {
    assert_eq!(cycle_layout_seed(1), cycle_layout_seed(1));
    assert_ne!(cycle_layout_seed(1), cycle_layout_seed(2));
    // Known mix constants — non-zero for cycle 1.
    assert_ne!(cycle_layout_seed(1), 0);
}

#[test]
fn soak_require_durable_seals_env_matrix() {
    // TASK-150: default off; either env = "1" enables.
    assert!(!soak_require_durable_seals(None, None));
    assert!(!soak_require_durable_seals(Some("0"), Some("0")));
    assert!(!soak_require_durable_seals(Some(""), None));
    assert!(soak_require_durable_seals(Some("1"), None));
    assert!(soak_require_durable_seals(None, Some("1")));
    assert!(soak_require_durable_seals(Some("1"), Some("1")));
    assert!(!soak_require_durable_seals(Some("true"), None));
}

#[test]
fn summarize_durable_seals_empty_and_present() {
    // TASK-152: forensics helper — empty vs non-empty durable_seals.
    let dir = std::env::temp_dir().join(format!(
        "proteus_nss_seals_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("attest.log.jsonl");

    // Empty file
    fs::write(&path, "").unwrap();
    let empty = summarize_durable_seals(&path);
    assert_eq!(empty.accepted, 0);
    assert_eq!(empty.with_seals, 0);
    assert!(format_durable_seals_report(&empty).contains("no accepted"));

    // Two accepted: one with seals, one without; one rejected with seals ignored.
    let lines = [
        r#"{"accepted":true,"durable_seals":{"factory_expected":"aa","scheduler":"bb"}}"#,
        r#"{"accepted":true}"#,
        r#"{"accepted":false,"durable_seals":{"ignore_me":"cc"}}"#,
        r#"{"accepted":true,"durable_seals":{}}"#,
    ];
    fs::write(&path, lines.join("\n")).unwrap();
    let sum = summarize_durable_seals(&path);
    assert_eq!(sum.accepted, 3);
    assert_eq!(sum.with_seals, 1);
    assert_eq!(
        sum.labels,
        vec![
            "factory_expected".to_string(),
            "scheduler".to_string()
        ]
    );
    let line = format_durable_seals_report(&sum);
    assert!(
        line.contains("present on 1/3 accepted"),
        "line={line}"
    );
    assert!(line.contains("factory_expected") && line.contains("scheduler"));

    // All accepted without seals
    fs::write(
        &path,
        r#"{"accepted":true}
{"accepted":true}"#,
    )
    .unwrap();
    let none = summarize_durable_seals(&path);
    assert_eq!(none.with_seals, 0);
    assert_eq!(none.accepted, 2);
    assert!(format_durable_seals_report(&none).contains("0/2"));

    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn boot_required_banners_include_halt() {
    assert!(BOOT_REQUIRED_BANNERS.iter().any(|b| b.contains("HALT")));
    assert!(BOOT_REQUIRED_BANNERS.iter().any(|b| b.contains("PROTEUS-TE OK")));
    assert!(BOOT_REQUIRED_BANNERS.len() >= 4);
}

#[test]
fn boot_hw_forensic_list_covers_closed_hw() {
    // TASK-135: forensic list tracks closed hardware-truth families.
    for must in [
        "AHCI_HW",
        "E1000_HW",
        "NVME_HW",
        "VIRTIO_HW",
        "VIRTIO_NET_HW",
    ] {
        assert!(
            BOOT_HW_FORENSIC_BANNERS.iter().any(|b| b.contains(must)),
            "BOOT_HW_FORENSIC_BANNERS missing family {must}"
        );
    }
    let (obs, miss) = scan_hw_forensics("AHCI_HW probe OK slot=1\nE1000_HW tx OK bytes=64\n");
    assert!(obs.iter().any(|s| s.contains("AHCI_HW probe")));
    assert!(obs.iter().any(|s| s.contains("E1000_HW tx")));
    assert!(miss.iter().any(|s| s.contains("NVME_HW")));
}

#[test]
fn boot_hw_required_min_is_subset_of_forensic() {
    // TASK-139: hard-gate lines must be covered by forensic inventory.
    for b in BOOT_HW_REQUIRED_MIN {
        assert!(
            BOOT_HW_FORENSIC_BANNERS.iter().any(|f| f == b),
            "REQUIRE_HW line not in forensic list: {b}"
        );
    }
    assert!(BOOT_HW_REQUIRED_MIN.len() >= 3);
}

#[test]
fn collect_bundle_hashes_distinct_and_accepted_only() {
    let dir = std::env::temp_dir().join(format!(
        "proteus_nss_attest_{}",
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    fs::create_dir_all(&dir).expect("tempdir");
    let path = dir.join("attest.log.jsonl");
    let lines = [
        r#"{"accepted":true,"bundle_name":"kernel","candidate_sha256":"aaa"}"#,
        r#"{"accepted":false,"bundle_name":"kernel","candidate_sha256":"bbb"}"#,
        r#"{"accepted":true,"candidate_sha256":"ccc"}"#, // single-module
        r#"{"accepted":true,"bundle_name":"kernel","candidate_sha256":"ddd"}"#,
        r#"{"accepted":true,"bundle_name":"kernel","candidate_sha256":"aaa"}"#,
    ];
    fs::write(&path, lines.join("\n")).expect("write");
    let hashes = collect_bundle_hashes(&path);
    assert_eq!(hashes, vec!["aaa", "ddd", "aaa"]);
    let distinct: BTreeSet<&str> = hashes.iter().map(|s| s.as_str()).collect();
    assert_eq!(distinct.len(), 2);
    let _ = fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------------
// Gated multi-cycle daemon soak
// ---------------------------------------------------------------------------

#[test]
fn north_star_bundle_kernel_daemon_soak() {
    if std::env::var("PROTEUS_NORTH_STAR_SOAK").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: set PROTEUS_NORTH_STAR_SOAK=1 to run the north-star cadence soak \
             (full [bundle.kernel] × N; tens of minutes). Always-on helpers still run."
        );
        return;
    }

    let _g = SOAK_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let soak = soak_root();
    fs::create_dir_all(&soak).expect("soak root");
    fs::create_dir_all(soak.join("results")).expect("results parent");

    let modules = load_bundle_kernel_modules(&root);
    assert!(
        !modules.is_empty(),
        "production [bundle.kernel].modules is empty"
    );

    let iters: u64 = std::env::var("PROTEUS_SOAK_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(DEFAULT_ITERS);
    assert!(
        (1..=MAX_ITERS).contains(&iters),
        "PROTEUS_SOAK_ITERS out of range 1..={MAX_ITERS}"
    );

    assert!(
        root.join("factory_signing_key.bin").exists(),
        "factory_signing_key.bin missing; run morph init-key"
    );

    let verify_status = Command::new("cargo")
        .args(["build", "-p", "proteus-verifier", "--bin", "verify"])
        .current_dir(&root)
        .status()
        .expect("build verify");
    assert!(verify_status.success(), "failed to build verify binary");

    // Snapshot every enrolled module so we can restore after morph deploys.
    let snaps = snapshot_modules(&root, &modules);

    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let results_dir = soak.join("results").join(format!("run_{}", run_id));
    fs::create_dir_all(&results_dir).expect("results dir");

    // Soak-local scheduler: only full kernel bundle, due every tick.
    let sched_path = soak.join("scheduler.toml");
    write_soak_scheduler(&sched_path, &modules);
    let _ = fs::copy(&sched_path, results_dir.join("scheduler.toml"));

    let prev_attest = std::env::var_os(ATTEST_DIR_ENV);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &results_dir);
    }

    let state_path = soak.join("scheduler_state.json");
    let daemon_log = soak.join(DAEMON_LOG);
    let _ = fs::remove_file(&state_path);
    let _ = fs::remove_file(&daemon_log);

    let prev_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&root).expect("cd workspace");

    // TASK-126: optional kernel ELF emit + churn (expensive). Opt in via
    // PROTEUS_SOAK_EMIT_IMAGE=1 when measuring positional bps on cadence.
    let emit_image = std::env::var("PROTEUS_SOAK_EMIT_IMAGE").as_deref() == Ok("1");
    if emit_image {
        eprintln!(
            "north_star_soak: PROTEUS_SOAK_EMIT_IMAGE=1 — each cycle builds \
             kernel ELF + binmorph (long wall-clock)"
        );
    }

    // Durable seals attach via PROTEUS_DURABLE_SEALS_DIR (TASK-146/147);
    // DaemonArgs has no separate field.
    let args = DaemonArgs {
        root: soak.clone(),
        max_iters: iters,
        max_cycle_secs: MAX_CYCLE_SECS,
        heartbeat_secs: 3600,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image,
        no_perf_check: true,
    };

    eprintln!(
        "north_star_soak: max_iters={} modules={} root={}",
        iters,
        modules.len(),
        soak.display()
    );

    let t0 = Instant::now();
    let report = match run_daemon(&args) {
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
            panic!("run_daemon failed: {:#}", e);
        }
    };
    let wall_secs = t0.elapsed().as_secs_f64();

    eprintln!(
        "north_star_soak: accepted={} rejected={} ticks={} wall_s={:.1}",
        report.cycles_accepted, report.cycles_rejected, report.ticks_executed, wall_secs
    );

    if daemon_log.exists() {
        let _ = fs::copy(&daemon_log, results_dir.join(DAEMON_LOG));
    }
    if state_path.exists() {
        let _ = fs::copy(&state_path, results_dir.join("scheduler_state.json"));
    }

    let events = read_jsonl_events(&daemon_log);
    let accepts = count_kind(&events, "cycle_accept");
    let rejects = count_kind(&events, "cycle_reject");
    let bundle_acc = count_bundle_accepts(&events);

    let attest_path = results_dir.join("attest.log.jsonl");
    let bundle_hashes = collect_bundle_hashes(&attest_path);
    let div_decisions = diversifier_decision_count(&attest_path);
    let distinct: BTreeSet<&str> = bundle_hashes.iter().map(|s| s.as_str()).collect();

    let div_sum = summarize_diversity(&attest_path);
    // TASK-152: seals forensics for REPORT (not a hard gate).
    let seals_sum = summarize_durable_seals(&attest_path);
    eprintln!(
        "north_star_soak: {}",
        format_durable_seals_report(&seals_sum)
    );

    // TASK-125: require ext_tlv + diversity on every accepted entry.
    // TASK-150: optional durable seals (default off). Meaningful only
    // when PROTEUS_DURABLE_SEALS_DIR was set during soak cycles.
    let require_durable_seals = soak_require_durable_seals(
        std::env::var("PROTEUS_SOAK_REQUIRE_DURABLE_SEALS")
            .ok()
            .as_deref(),
        std::env::var("PROTEUS_VERIFY_REQUIRE_DURABLE_SEALS")
            .ok()
            .as_deref(),
    );
    if require_durable_seals {
        eprintln!(
            "north_star_soak: require_durable_seals=ON \
             (PROTEUS_SOAK_REQUIRE_DURABLE_SEALS or PROTEUS_VERIFY_REQUIRE_DURABLE_SEALS)"
        );
    }
    let attest_ok = match verify_chain_with_options(&VerifyOptions {
        require_threshold: false,
        require_merkle_root: false,
        require_strict_factory: false,
        federation_config: None,
        factory_expected_path: None,
        require_ext_tlv: true,
        require_diversity: true,
        require_durable_seals,
    }) {
        Ok(rep) => {
            let seal_note = if require_durable_seals {
                " + durable_seals"
            } else {
                ""
            };
            eprintln!(
                "north_star_soak: verify-attest ok entries_ok={} \
                 (ext_tlv + diversity required{})",
                rep.entries_ok, seal_note
            );
            true
        }
        Err(e) => {
            eprintln!("north_star_soak: verify-attest FAILED: {:#}", e);
            false
        }
    };

    // TASK-127: optional QEMU boot while sources are still morphed.
    let boot_requested = std::env::var("PROTEUS_NORTH_STAR_BOOT").as_deref() == Ok("1");
    let boot_proof: Option<BootProof> = if boot_requested {
        let last_cycle = {
            let state_txt = fs::read_to_string(&state_path).unwrap_or_default();
            serde_json::from_str::<serde_json::Value>(&state_txt)
                .ok()
                .and_then(|v| v.get("global_cycle").and_then(|c| c.as_u64()))
                .unwrap_or(iters)
        };
        let layout_seed = cycle_layout_seed(last_cycle);
        let kernel_crate = root.join("target_enterprise_kernel");
        eprintln!(
            "north_star_soak: phase boot layout_seed={:#x} last_cycle={} \
             (sources still morphed)",
            layout_seed, last_cycle
        );

        if !kernel_crate.join("Cargo.toml").exists() {
            restore_modules(&snaps);
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            panic!("PROTEUS_NORTH_STAR_BOOT=1 but target_enterprise_kernel missing");
        }
        if find_qemu().is_none() {
            restore_modules(&snaps);
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            panic!("PROTEUS_NORTH_STAR_BOOT=1 but qemu-system-x86_64 not found");
        }

        let elf = match factory_builder::build_kernel_with_layout_seed(
            &kernel_crate,
            Some(layout_seed),
        ) {
            Ok(p) => p,
            Err(e) => {
                restore_modules(&snaps);
                std::env::set_current_dir(&prev_cwd).ok();
                unsafe {
                    match prev_attest {
                        Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                        None => std::env::remove_var(ATTEST_DIR_ENV),
                    }
                }
                panic!("north-star boot: kernel build failed: {:#}", e);
            }
        };
        eprintln!("north_star_soak: QEMU boot {}", elf.display());
        let serial = match boot_kernel(&elf, &results_dir, last_cycle) {
            Ok(p) => p,
            Err(e) => {
                restore_modules(&snaps);
                std::env::set_current_dir(&prev_cwd).ok();
                unsafe {
                    match prev_attest {
                        Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                        None => std::env::remove_var(ATTEST_DIR_ENV),
                    }
                }
                panic!("north-star QEMU boot failed after full-bundle soak: {}", e);
            }
        };
        let log_text = fs::read_to_string(&serial).expect("read serial");
        let mut missing = Vec::new();
        let mut banners_ok = 0usize;
        for b in BOOT_REQUIRED_BANNERS {
            if log_text.contains(b) {
                banners_ok += 1;
                eprintln!("north_star_soak: boot observed: {}", b);
            } else {
                missing.push(*b);
            }
        }
        let (hw_observed, hw_missing) = scan_hw_forensics(&log_text);
        for h in &hw_observed {
            eprintln!("north_star_soak: HW forensic: {}", h);
        }
        if !hw_missing.is_empty() {
            eprintln!(
                "north_star_soak: HW forensic missing {}/{} (not core gate): {:?}",
                hw_missing.len(),
                BOOT_HW_FORENSIC_BANNERS.len(),
                hw_missing
            );
        }
        // TASK-139: optional hard-fail on minimal HW subset.
        let require_hw = std::env::var("PROTEUS_NORTH_STAR_REQUIRE_HW").as_deref() == Ok("1");
        if require_hw {
            let mut hw_gate_missing = Vec::new();
            for b in BOOT_HW_REQUIRED_MIN {
                if !log_text.contains(b) {
                    hw_gate_missing.push(*b);
                }
            }
            if !hw_gate_missing.is_empty() {
                restore_modules(&snaps);
                std::env::set_current_dir(&prev_cwd).ok();
                unsafe {
                    match prev_attest {
                        Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                        None => std::env::remove_var(ATTEST_DIR_ENV),
                    }
                }
                panic!(
                    "north-star boot REQUIRE_HW missing: {:?} \
                     (unset PROTEUS_NORTH_STAR_REQUIRE_HW to disable)",
                    hw_gate_missing
                );
            }
            eprintln!(
                "north_star_soak: REQUIRE_HW PASS ({} lines)",
                BOOT_HW_REQUIRED_MIN.len()
            );
        }
        if !missing.is_empty() {
            restore_modules(&snaps);
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            panic!(
                "north-star boot missing banners: {:?}\nlog tail:\n{}",
                missing,
                log_text
                    .chars()
                    .rev()
                    .take(2000)
                    .collect::<String>()
                    .chars()
                    .rev()
                    .collect::<String>()
            );
        }
        Some(BootProof {
            last_cycle,
            layout_seed,
            serial_log: serial,
            banners_ok,
            hw_observed,
            hw_missing,
        })
    } else {
        None
    };

    write_report(
        &results_dir,
        &report,
        &events,
        attest_ok,
        iters,
        &modules,
        wall_secs,
        &bundle_hashes,
        div_decisions,
        &div_sum,
        &seals_sum,
        boot_proof.as_ref(),
        boot_requested,
    );
    eprintln!(
        "north_star_soak: REPORT {}",
        results_dir.join("REPORT.md").display()
    );

    restore_modules(&snaps);

    std::env::set_current_dir(&prev_cwd).ok();
    unsafe {
        match prev_attest {
            Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
            None => std::env::remove_var(ATTEST_DIR_ENV),
        }
    }

    for (p, before) in &snaps {
        let after = fs::read_to_string(p).expect("re-read");
        assert_eq!(
            &after, before,
            "{} not restored after north-star soak",
            p.display()
        );
    }

    assert_eq!(
        report.ticks_executed, iters,
        "daemon should run exactly max_iters ticks"
    );
    assert!(
        report.cycles_accepted >= iters,
        "accepted {} < {}",
        report.cycles_accepted,
        iters
    );
    assert_eq!(
        report.cycles_rejected, 0,
        "north-star soak must have zero rejects; got {}",
        report.cycles_rejected
    );
    assert!(
        bundle_acc >= iters as usize,
        "bundle cycle_accept {} < {}",
        bundle_acc,
        iters
    );
    assert_eq!(rejects, 0, "daemon.log has cycle_reject events");
    assert!(accepts >= iters as usize);
    assert!(
        attest_ok,
        "attest chain failed verify-attest (require_ext_tlv + require_diversity)"
    );
    assert!(
        distinct.len() >= iters as usize,
        "expected ≥ {} distinct bundle candidate_sha256 (diversity), got {} (hashes={:?})",
        iters,
        distinct.len(),
        bundle_hashes
    );
    assert!(
        div_decisions > 0,
        "expected diversifier_log decisions on accepted entries"
    );
    assert!(
        div_sum.entries_with_diversity >= iters as usize,
        "expected diversity on ≥ {} accepted entries, got {}",
        iters,
        div_sum.entries_with_diversity
    );
    assert!(
        div_sum.pad_sum + div_sum.perturb_sum > 0,
        "expected non-zero pad+perturb decision counts across soak"
    );

    if boot_requested {
        let b = boot_proof.as_ref().expect("boot requested but no proof");
        assert_eq!(
            b.banners_ok,
            BOOT_REQUIRED_BANNERS.len(),
            "boot banner count"
        );
    }

    eprintln!(
        "north_star_soak: PASS iters={} modules={} accepted={} distinct_hashes={} \
         div_decisions={} diversity_entries={} pad_sum={} perturb_sum={} \
         boot={} wall_s={:.1} results={}",
        iters,
        modules.len(),
        report.cycles_accepted,
        distinct.len(),
        div_decisions,
        div_sum.entries_with_diversity,
        div_sum.pad_sum,
        div_sum.perturb_sum,
        if boot_requested { "OK" } else { "skipped" },
        wall_secs,
        results_dir.display()
    );
}
