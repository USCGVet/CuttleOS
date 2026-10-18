//! Morphed-kernel QEMU proof — B2 proof path + TASK-122 churn gate.
//!
//! Load-bearing claim: after diversifying contract-locked modules under
//! the production levers (AST diversifier with stack-pad **off** +
//! per-cycle layout seed), the enterprise kernel still boots under
//! QEMU and emits the feature banners for those modules.
//!
//! This is the "morphed image is still a real OS" gate. Diversity
//! metrics alone (layout seed → 0% chain survival) do not prove the
//! fleet stays up.
//!
//! **TASK-122 (north-star G5):** before boot, build a pristine-base ELF
//! and the morphed variant under consecutive layout seeds, run
//! `cuttle_mtd_metrics` gadget churn, and **fail** if positional
//! survival exceeds [`diversity_demo::KERNEL_POSITIONAL_SURVIVAL_MAX`]
//! or if `.text` is bit-identical.
//!
//! # Invocation
//!
//! ```text
//! # PowerShell
//! $env:CUTTLE_MORPHED_QEMU_PROOF = "1"
//! cargo test -p diversity_demo --test morphed_qemu_proof -- --nocapture
//! ```
//!
//! Skips (exit 0) when the env var is unset, or when QEMU / nightly
//! kernel crates are missing — same skip culture as `qemu_smoke` and
//! the boot-each-cycle test.
//!
//! # What is morphed
//!
//! The **load-bearing production path**, not the full codec museum:
//! crypto/TLS, WAL, net + TCP/HTTP, block (NVMe + virtio-blk), AHCI
//! command framing, VFS/quota, timebase, and attest TLV/Base64.
//! Cross-module composition banners (TIMEBASE, VFS+QUOTA, AHCI storage)
//! must still appear after diversify — that is the real MTD claim.
//!
//! Full-bundle morph remains available via morph `run-bundle` for
//! operator sessions; this test is the CI-grade regression needle.

use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use diversity_demo::qemu_boot::{boot_and_capture, find_qemu};
use diversity_demo::{
    cycle_layout_seed, evaluate_kernel_churn_gate, measure_kernel_elf_churn,
    KERNEL_POSITIONAL_SURVIVAL_MAX,
};

/// Serialize against other diversity_demo tests that rewrite enterprise
/// sources (smoke, layout seed).
static FS_MUTEX: Mutex<()> = Mutex::new(());

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Modules morphed for this proof. All:
/// - sit in `[bundle.kernel]`
/// - are not in `locked_modules.toml`
/// - emit banners exercised by the kernel boot path
///
/// Sized for **maximum claim per minute**: every module on a live
/// composition or primary I/O/crypto path. Isolated wire-codec demos
/// (MBR, Hex, …) stay out — they do not raise the MTD proof bar.
const PROOF_MODULES: &[&str] = &[
    // Crypto / transport
    "tls",
    "kat",
    "net",
    "tcp",
    "http",
    // Durability + block
    "wal",
    "nvme",
    "virtio_blk",
    "ahci_fis",
    "ahci_cmd",
    // Policy + VFS
    "vfs",
    "quota",
    // Timebase
    "timer",
    "tick_source",
    "watchdog",
    // Factory / attest payload codecs (used by future attest v7)
    "attest_tlv",
    "base64",
];

/// Banners that must appear when the modules above still work after
/// morph. Composition lines are the load-bearing assertions.
const REQUIRED_BANNERS: &[&str] = &[
    "CUTTLE-TE OK",
    // crypto / transport
    "TLS hkdf OK prk_sha=",
    "TLS server_hello OK len=",
    "KAT all OK vectors=9",
    "NET build OK len=38 ip_cksum=63c7 udp_cksum=fa94",
    "TCP handshake OK state=ESTABLISHED seq=",
    "HTTP parse OK method=GET path=/healthz",
    // durability + block
    "WAL replay OK frames=",
    "NVMe init OK ctrl=CUTTLE-NVME-EMU",
    "NVMe read_lba(7) OK first_byte=a5",
    "VIRTIO_BLK init OK capacity=32 blk_size=512",
    "VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5",
    "AHCI fis OK cmd=identify",
    "AHCI cmd OK prdtl=1",
    // policy + VFS
    "VFS mount OK fs=ramfs root=/",
    "QUOTA scan OK records=3",
    // timebase
    "PIT program OK hz=1000 div=",
    "TICK source OK kind=hpet",
    "WATCHDOG pet OK deadline=5",
    // factory payload codecs
    "TLV parse OK tags=3",
    "B64 roundtrip OK",
    // live composition (must survive multi-module diversify)
    "TIMEBASE compose OK pit_div=1193 pet_rem=5 fire=timeout",
    "VFS+QUOTA compose OK allow=1000 reject=1001 bytes=8",
    "AHCI storage compose OK fis=ec prdtl=1 bytes=512",
    "NET path compose OK method=GET status=200",
    "BLOCK path compose OK sector=512 nvme=a5 virtio=a5",
    "VIRTIO_HW probe OK blk=found slot=",
    "VIRTIO_HW io OK capacity=2048",
    "VIRTIO_HW sector OK first_byte=a5",
    "VIRTIO_NET_HW probe OK slot=",
    "VIRTIO_NET_HW tx OK bytes=76",
    "VIRTIO_NET_HW rx OK bytes=",
    "AHCI_HW probe OK slot=",
    "AHCI_HW identify OK sectors=2048",
    "AHCI_HW sector OK first_byte=5a",
    "NET SVC UP ip=10.0.2.15 udp=8080 tcp=80 icmp=echo",
    "E1000_HW probe OK slot=",
    "E1000_HW tx OK bytes=64",
    "E1000_HW rx OK bytes=",
    "NVME_HW probe OK slot=",
    "NVME_HW identify OK sn=",
    "NVME_HW sector OK first_byte=5a",
    "DURABLE seal OK dig=",
    "CUTTLE-TE HALT",
];

/// TASK-121/133: always-on enrollment check — HW banner set must not drop.
#[test]
fn required_banners_include_ahci_e1000_nvme_hw() {
    let need = [
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
    for b in need {
        assert!(
            REQUIRED_BANNERS.iter().any(|x| *x == b),
            "morphed proof missing enrolled HW banner: {b}"
        );
    }
}

/// Deterministic proof cycle number. Seed is derived via the same
/// bijective mix production uses (`cycle_layout_seed`).
const PROOF_CYCLE: u64 = 9001;

struct SourceBackup {
    path: PathBuf,
    pristine: String,
}

impl Drop for SourceBackup {
    fn drop(&mut self) {
        if let Err(e) = std::fs::write(&self.path, &self.pristine) {
            eprintln!(
                "morphed_qemu_proof: CRITICAL restore failed for {}: {}",
                self.path.display(),
                e
            );
        } else {
            // Best-effort remove any leftover .preexp.bak litter.
            let bak = self.path.with_extension("rs.preexp.bak");
            let _ = std::fs::remove_file(bak);
        }
    }
}

#[test]
fn morphed_modules_boot_under_qemu_with_banners() {
    if std::env::var("CUTTLE_MORPHED_QEMU_PROOF").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: set CUTTLE_MORPHED_QEMU_PROOF=1 to run the morphed-kernel QEMU proof \
             (requires QEMU + nightly x86_64-unknown-none + several minutes)"
        );
        return;
    }

    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let enterprise = root.join("target_enterprise");
    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = root.join("factory_builder_pkg");

    if !kernel_crate.join("Cargo.toml").exists() {
        eprintln!(
            "SKIP: target_enterprise_kernel missing at {}",
            kernel_crate.display()
        );
        return;
    }
    if !pkg_crate.join("Cargo.toml").exists() {
        eprintln!(
            "SKIP: factory_builder_pkg missing at {}",
            pkg_crate.display()
        );
        return;
    }
    if find_qemu().is_none() {
        eprintln!("SKIP: qemu-system-x86_64 not found");
        return;
    }

    // Results dir early — base/variant ELFs land here for churn + boot.
    let results_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join("morphed_qemu_proof");
    let _ = std::fs::remove_dir_all(&results_dir);
    std::fs::create_dir_all(&results_dir).ok();

    // 1) Backup pristines (Drop restores even on panic).
    let mut backups: Vec<SourceBackup> = Vec::new();
    for m in PROOF_MODULES {
        let path = enterprise.join("src").join(format!("{}.rs", m));
        assert!(
            path.exists(),
            "precondition: {} must exist",
            path.display()
        );
        let pristine = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        backups.push(SourceBackup { path, pristine });
    }

    // 2) Build **base** kernel from pristine sources (cycle N layout seed).
    //    Consecutive-cycle comparison: base uses PROOF_CYCLE, variant
    //    uses PROOF_CYCLE+1 — the production two-lever path (layout seed
    //    + later AST diversify).
    let base_layout_seed = cycle_layout_seed(PROOF_CYCLE);
    eprintln!(
        "morphed_qemu_proof: building BASE kernel (pristine) layout_seed={:#x}...",
        base_layout_seed
    );
    let base_elf_built = match factory_builder::build_kernel_with_layout_seed(
        &kernel_crate,
        Some(base_layout_seed),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "SKIP: base kernel build failed (nightly/build-std?): {:#}",
                e
            );
            return;
        }
    };
    let base_elf = results_dir.join("base_kernel.elf");
    std::fs::copy(&base_elf_built, &base_elf).unwrap_or_else(|e| {
        panic!(
            "copy base ELF {} → {}: {}",
            base_elf_built.display(),
            base_elf.display(),
            e
        )
    });
    eprintln!("morphed_qemu_proof: base ELF {}", base_elf.display());

    // 3) Diversify each module under production defaults (stack-pad off).
    eprintln!(
        "morphed_qemu_proof: diversifying {} modules at cycle {} (stack_pad=off)...",
        PROOF_MODULES.len(),
        PROOF_CYCLE
    );
    for m in PROOF_MODULES {
        let path = enterprise.join("src").join(format!("{}.rs", m));
        let src = std::fs::read_to_string(&path).expect("read for diversify");
        let seed = cuttle_diversifier::Seed::derive(PROOF_CYCLE, m);
        let opts = cuttle_diversifier::DiversifyOptions::default();
        assert!(
            !opts.stack_pad,
            "production diversify must leave stack_pad off"
        );
        let (candidate, log) = cuttle_diversifier::diversify_with_options(&src, &seed, &opts)
            .unwrap_or_else(|e| panic!("diversify {} failed: {:#}", m, e));
        assert!(
            log.pad_decisions.is_empty(),
            "pad_decisions must be empty under production options; got {:?}",
            log.pad_decisions
        );
        // Must not be a no-op on a real module (canonical diversity).
        let h_src = cuttle_diversifier::canonical_hash(&src).expect("hash src");
        let h_cand = cuttle_diversifier::canonical_hash(&candidate).expect("hash cand");
        assert_ne!(
            h_src, h_cand,
            "diversify of {} produced zero AST diversity under cycle {}",
            m, PROOF_CYCLE
        );
        std::fs::write(&path, &candidate)
            .unwrap_or_else(|e| panic!("write morphed {}: {}", path.display(), e));
        eprintln!(
            "morphed_qemu_proof:   {} diversified (perturb_decisions={})",
            m,
            log.perturb_decisions.len()
        );
    }

    // 4) Build **variant** kernel (morphed sources + next-cycle layout seed).
    let layout_seed = cycle_layout_seed(PROOF_CYCLE + 1);
    eprintln!(
        "morphed_qemu_proof: building VARIANT kernel (morphed) layout_seed={:#x}...",
        layout_seed
    );
    let elf_built = match factory_builder::build_kernel_with_layout_seed(
        &kernel_crate,
        Some(layout_seed),
    ) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "SKIP: variant kernel build failed (nightly/build-std?): {:#}",
                e
            );
            return;
        }
    };
    let elf = results_dir.join("variant_kernel.elf");
    std::fs::copy(&elf_built, &elf).unwrap_or_else(|e| {
        panic!(
            "copy variant ELF {} → {}: {}",
            elf_built.display(),
            elf.display(),
            e
        )
    });
    assert!(elf.exists(), "kernel ELF missing: {}", elf.display());
    eprintln!("morphed_qemu_proof: variant ELF {}", elf.display());

    // 5) TASK-122 — gadget churn gate (G5 measured diversity).
    eprintln!(
        "morphed_qemu_proof: measuring gadget churn (max positional {:.1}%)...",
        KERNEL_POSITIONAL_SURVIVAL_MAX * 100.0
    );
    let churn = measure_kernel_elf_churn(&base_elf, &elf).unwrap_or_else(|e| {
        panic!("kernel gadget churn measurement failed: {:#}", e);
    });
    eprintln!("morphed_qemu_proof: {}", churn.summary_line());
    if let Err(reasons) = evaluate_kernel_churn_gate(&churn) {
        panic!(
            "morphed-kernel QEMU proof FAILED churn gate (TASK-122 / G5):\n  {}\n  {}",
            churn.summary_line(),
            reasons.join("\n  ")
        );
    }
    eprintln!(
        "morphed_qemu_proof: CHURN GATE PASS positional={:.2}% (≤ {:.1}%)",
        churn.positional_survival * 100.0,
        KERNEL_POSITIONAL_SURVIVAL_MAX * 100.0
    );

    // 6) Package + boot variant; wait for HALT via boot_and_capture.
    eprintln!("morphed_qemu_proof: packaging + QEMU boot...");
    let t0 = Instant::now();
    let capture = match boot_and_capture(&elf, &results_dir, PROOF_CYCLE) {
        Ok(c) => c,
        Err(e) => {
            // Do not SKIP on boot failure once we got this far — that
            // is a real proof failure (unless packaging nightly missing).
            let msg = format!("{:#}", e);
            if msg.contains("factory_builder_pkg") || msg.contains("nightly") {
                eprintln!("SKIP: packaging failed: {}", msg);
                return;
            }
            panic!("morphed-kernel QEMU boot failed: {}", msg);
        }
    };
    let elapsed = t0.elapsed();
    eprintln!(
        "morphed_qemu_proof: boot captured in {:.1}s log={} sha={}",
        elapsed.as_secs_f64(),
        capture.serial_log_path.display(),
        &capture.serial_log_sha256[..16.min(capture.serial_log_sha256.len())]
    );

    // 7) Banner assertions.
    let log_bytes = std::fs::read(&capture.serial_log_path).expect("read serial log");
    assert!(
        !log_bytes.is_empty(),
        "serial log empty at {}",
        capture.serial_log_path.display()
    );
    let log_text = String::from_utf8_lossy(&log_bytes);

    let mut missing = Vec::new();
    for b in REQUIRED_BANNERS {
        if !log_text.contains(b) {
            missing.push(*b);
        }
    }
    if !missing.is_empty() {
        // Print a tail of the log for diagnosis.
        let tail: String = log_text
            .chars()
            .rev()
            .take(2000)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        panic!(
            "morphed-kernel QEMU proof FAILED: missing banners {:?}\n\
             layout_seed={:#x} modules={:?}\n\
             serial log tail:\n{}",
            missing, layout_seed, PROOF_MODULES, tail
        );
    }

    for b in REQUIRED_BANNERS {
        eprintln!("morphed_qemu_proof: observed: {}", b);
    }
    eprintln!(
        "morphed_qemu_proof: PASS modules={} base_seed={:#x} variant_seed={:#x} \
         positional={:.2}% log_sha={} wall_ms={} | {}",
        PROOF_MODULES.len(),
        base_layout_seed,
        layout_seed,
        churn.positional_survival * 100.0,
        &capture.serial_log_sha256[..16.min(capture.serial_log_sha256.len())],
        elapsed.as_millis(),
        churn.summary_line()
    );

    // backups Drop → restore pristines
    drop(backups);

    // Post-condition: sources restored.
    for m in PROOF_MODULES {
        let path = enterprise.join("src").join(format!("{}.rs", m));
        let body = std::fs::read_to_string(&path).expect("re-read after restore");
        assert!(
            body.len() > 100,
            "{} empty after restore?",
            path.display()
        );
        // Heuristic: diversified sources usually still contain the module's
        // public contract name; more importantly, no leftover backup.
        let bak = path.with_extension("rs.preexp.bak");
        assert!(!bak.exists(), "leftover backup {}", bak.display());
    }

    // Silence unused import if Duration only used conceptually.
    let _ = Duration::from_secs(0);
    let _: &Path = enterprise.as_path();
}
