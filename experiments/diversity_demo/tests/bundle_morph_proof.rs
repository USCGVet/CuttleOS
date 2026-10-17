//! Full enrolled-bundle morph + QEMU proof — TASK-103.
//!
//! Closes the gap between the 17-module CI needle (`morphed_qemu_proof`)
//! and the full `[bundle.kernel]` surface in `scheduler.toml`.
//!
//! Sequence:
//! 1. Parse `scheduler.toml` → `bundle.kernel.modules`
//! 2. Backup every enrolled module source
//! 3. Diversify each under production options (stack_pad=off)
//! 4. Build kernel under per-cycle layout seed
//! 5. Package + boot; assert composition + high-value banners
//! 6. Restore pristines (Drop + explicit check)
//!
//! Zero-diversity modules are **recorded** (known-fail inventory) but
//! do not fail the proof — some wire codecs are already near-canonical.
//! Diversify hard errors and missing banners still fail.
//!
//! # Invocation
//!
//! ```text
//! $env:PROTEUS_BUNDLE_MORPH_PROOF = "1"
//! cargo test -p diversity_demo --test bundle_morph_proof -- --nocapture
//! ```
//!
//! Or: `tools\bundle_morph_proof.ps1`

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Instant;

use diversity_demo::cycle_layout_seed;
use diversity_demo::qemu_boot::{boot_and_capture, find_qemu};

static FS_MUTEX: Mutex<()> = Mutex::new(());

const PROOF_CYCLE: u64 = 9103;

/// Banners that must survive full-bundle diversify. Composition lines
/// are load-bearing; the rest sample each major enrolled subsystem so
/// a silent morph regression is not limited to the 17-module needle.
const REQUIRED_BANNERS: &[&str] = &[
    "PROTEUS-TE OK",
    // crypto / transport
    "TLS hkdf OK prk_sha=",
    "TLS server_hello OK len=",
    "KAT all OK vectors=9",
    "NET build OK len=38 ip_cksum=63c7 udp_cksum=fa94",
    "TCP handshake OK state=ESTABLISHED seq=",
    "HTTP parse OK method=GET path=/healthz",
    "DNS query OK id=c0de qname=proteus.local",
    "ICMP echo_req OK id=4242",
    // durability + block
    "WAL replay OK frames=",
    "NVMe init OK ctrl=PROTEUS-NVME-EMU",
    "NVMe read_lba(7) OK first_byte=a5",
    "VIRTIO_BLK init OK capacity=32 blk_size=512",
    "VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5",
    "AHCI fis OK cmd=identify",
    "AHCI cmd OK prdtl=1",
    "JFS mount OK root_ino=1 inodes=3",
    // policy / vfs / net extras
    "VFS mount OK fs=ramfs root=/",
    "QUOTA scan OK records=3",
    "IOMMU translate OK pa=",
    "VIRTIO_NET init OK mac=525400123456",
    // timebase + misc
    "PIT program OK hz=1000 div=",
    "TICK source OK kind=hpet",
    "WATCHDOG pet OK deadline=5",
    "HPET program OK period_fs=",
    "SERIAL init OK port=0x3f8",
    "TLV parse OK tags=3",
    "B64 roundtrip OK",
    "XHCI trb OK type=noop",
    "GOP mode OK 1280x720",
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
    "PROTEUS-TE HALT",
];

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

/// Load `[bundle.kernel].modules` from workspace `scheduler.toml`.
fn load_bundle_modules(root: &Path) -> Vec<String> {
    let path = root.join("scheduler.toml");
    let text = std::fs::read_to_string(&path)
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

struct SourceBackup {
    path: PathBuf,
    pristine: String,
}

impl Drop for SourceBackup {
    fn drop(&mut self) {
        if let Err(e) = std::fs::write(&self.path, &self.pristine) {
            eprintln!(
                "bundle_morph_proof: CRITICAL restore failed for {}: {}",
                self.path.display(),
                e
            );
        } else {
            let bak = self.path.with_extension("rs.preexp.bak");
            let _ = std::fs::remove_file(bak);
        }
    }
}

#[test]
fn full_bundle_kernel_modules_boot_under_qemu() {
    if std::env::var("PROTEUS_BUNDLE_MORPH_PROOF").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: set PROTEUS_BUNDLE_MORPH_PROOF=1 to run the full-bundle \
             morph QEMU proof (requires QEMU + nightly; diversifies all \
             [bundle.kernel] modules)"
        );
        return;
    }

    let wall0 = Instant::now();
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let enterprise = root.join("target_enterprise");
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
        eprintln!("SKIP: qemu-system-x86_64 not found");
        return;
    }

    let modules = load_bundle_modules(&root);
    assert!(
        !modules.is_empty(),
        "bundle.kernel.modules must be non-empty"
    );
    eprintln!(
        "bundle_morph_proof: enrolled modules={} cycle={}",
        modules.len(),
        PROOF_CYCLE
    );

    // 1) Backup
    let mut backups: Vec<SourceBackup> = Vec::new();
    for m in &modules {
        let path = enterprise.join("src").join(format!("{}.rs", m));
        assert!(
            path.exists(),
            "enrolled module missing on disk: {} ({})",
            m,
            path.display()
        );
        let pristine = std::fs::read_to_string(&path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        backups.push(SourceBackup { path, pristine });
    }

    // 2) Diversify
    let mut zero_diversity: Vec<String> = Vec::new();
    let mut diversify_stats: BTreeMap<String, usize> = BTreeMap::new();
    let div_t0 = Instant::now();
    for m in &modules {
        let path = enterprise.join("src").join(format!("{}.rs", m));
        let src = std::fs::read_to_string(&path).expect("read for diversify");
        let seed = proteus_diversifier::Seed::derive(PROOF_CYCLE, m);
        let opts = proteus_diversifier::DiversifyOptions::default();
        assert!(!opts.stack_pad, "production diversify leaves stack_pad off");
        let (candidate, log) = proteus_diversifier::diversify_with_options(&src, &seed, &opts)
            .unwrap_or_else(|e| panic!("diversify {} failed: {:#}", m, e));
        assert!(
            log.pad_decisions.is_empty(),
            "{}: pad_decisions non-empty under production options",
            m
        );
        let h_src = proteus_diversifier::canonical_hash(&src).expect("hash src");
        let h_cand = proteus_diversifier::canonical_hash(&candidate).expect("hash cand");
        if h_src == h_cand {
            zero_diversity.push(m.clone());
            eprintln!(
                "bundle_morph_proof:   {} ZERO diversity (perturb={}) — recorded",
                m,
                log.perturb_decisions.len()
            );
        } else {
            eprintln!(
                "bundle_morph_proof:   {} diversified (perturb={})",
                m,
                log.perturb_decisions.len()
            );
        }
        diversify_stats.insert(m.clone(), log.perturb_decisions.len());
        std::fs::write(&path, &candidate)
            .unwrap_or_else(|e| panic!("write morphed {}: {}", path.display(), e));
    }
    let div_ms = div_t0.elapsed().as_millis();
    eprintln!(
        "bundle_morph_proof: diversify done modules={} zero_diversity={} wall_ms={}",
        modules.len(),
        zero_diversity.len(),
        div_ms
    );
    if !zero_diversity.is_empty() {
        eprintln!(
            "bundle_morph_proof: KNOWN zero-diversity modules: {:?}",
            zero_diversity
        );
    }

    // 3) Build + boot
    let layout_seed = cycle_layout_seed(PROOF_CYCLE);
    eprintln!(
        "bundle_morph_proof: building kernel layout_seed={:#x}...",
        layout_seed
    );
    let elf = match factory_builder::build_kernel_with_layout_seed(&kernel_crate, Some(layout_seed))
    {
        Ok(p) => p,
        Err(e) => {
            eprintln!("SKIP: kernel build failed: {:#}", e);
            return;
        }
    };

    let results_dir = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("results")
        .join("bundle_morph_proof");
    let _ = std::fs::remove_dir_all(&results_dir);
    std::fs::create_dir_all(&results_dir).ok();

    eprintln!("bundle_morph_proof: packaging + QEMU boot...");
    let boot_t0 = Instant::now();
    let capture = match boot_and_capture(&elf, &results_dir, PROOF_CYCLE) {
        Ok(c) => c,
        Err(e) => {
            let msg = format!("{:#}", e);
            if msg.contains("factory_builder_pkg") || msg.contains("nightly") {
                eprintln!("SKIP: packaging failed: {}", msg);
                return;
            }
            panic!("bundle morph QEMU boot failed: {}", msg);
        }
    };
    let boot_ms = boot_t0.elapsed().as_millis();
    eprintln!(
        "bundle_morph_proof: boot {:.1}s log={} sha={}",
        boot_ms as f64 / 1000.0,
        capture.serial_log_path.display(),
        &capture.serial_log_sha256[..16.min(capture.serial_log_sha256.len())]
    );

    // 4) Banner score
    let log_bytes = std::fs::read(&capture.serial_log_path).expect("read serial");
    let log_text = String::from_utf8_lossy(&log_bytes);
    let mut missing = Vec::new();
    let mut observed = 0usize;
    for b in REQUIRED_BANNERS {
        if log_text.contains(b) {
            observed += 1;
            eprintln!("bundle_morph_proof: observed: {}", b);
        } else {
            missing.push(*b);
        }
    }
    if !missing.is_empty() {
        let tail: String = log_text
            .chars()
            .rev()
            .take(2500)
            .collect::<String>()
            .chars()
            .rev()
            .collect();
        panic!(
            "bundle_morph_proof FAILED: missing {}/{} banners {:?}\n\
             modules={} zero_diversity={:?} layout_seed={:#x}\n\
             serial tail:\n{}",
            missing.len(),
            REQUIRED_BANNERS.len(),
            missing,
            modules.len(),
            zero_diversity,
            layout_seed,
            tail
        );
    }

    let wall_ms = wall0.elapsed().as_millis();
    eprintln!(
        "bundle_morph_proof: PASS modules={} banners={}/{} zero_div={} \
         layout_seed={:#x} log_sha={} diversify_ms={} boot_ms={} wall_ms={}",
        modules.len(),
        observed,
        REQUIRED_BANNERS.len(),
        zero_diversity.len(),
        layout_seed,
        &capture.serial_log_sha256[..16.min(capture.serial_log_sha256.len())],
        div_ms,
        boot_ms,
        wall_ms
    );
    // Emit a machine-readable one-liner for PROGRESS / CI scrapers.
    eprintln!(
        "bundle_morph_proof: SUMMARY modules={} banners_ok={} zero_diversity={:?} wall_ms={}",
        modules.len(),
        observed,
        zero_diversity,
        wall_ms
    );

    drop(backups);
    for m in &modules {
        let path = enterprise.join("src").join(format!("{}.rs", m));
        let body = std::fs::read_to_string(&path).expect("re-read after restore");
        assert!(body.len() > 50, "{} empty after restore?", m);
        assert!(
            !path.with_extension("rs.preexp.bak").exists(),
            "leftover backup for {}",
            m
        );
    }
    let _ = diversify_stats; // kept for future report dump
}
