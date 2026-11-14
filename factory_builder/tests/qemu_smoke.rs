//! End-to-end smoke test: build the kernel ELF, package it as a BIOS
//! image via `factory_builder`, boot it under QEMU (TCG), and assert
//! the kernel's serial banners appear on the serial log within 45s.
//!
//! `#[ignore]`-gated — invocation:
//!
//!   cargo test -p factory_builder --test qemu_smoke -- --ignored
//!
//! Skips (rather than fails) when:
//!   - QEMU isn't on PATH and isn't at the canonical Windows install
//!     location (`C:/Program Files/qemu/qemu-system-x86_64.exe`).
//!   - The out-of-workspace `target_enterprise_kernel/` or
//!     `factory_builder_pkg/` crate is missing.
//!
//! Mirrors the skip-pattern used by Iteration 2's
//! `anthropic_live_round_trip` test.

use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

fn workspace_root() -> PathBuf {
    // CARGO_MANIFEST_DIR for this crate is `<root>/factory_builder/`.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("CARGO_MANIFEST_DIR has no parent")
        .to_path_buf()
}

fn find_qemu_in_path_var(path_var: Option<&std::ffi::OsStr>) -> Option<PathBuf> {
    let path_var = path_var?;
    for dir in std::env::split_paths(path_var) {
        for exe_name in ["qemu-system-x86_64", "qemu-system-x86_64.exe"] {
            let candidate = dir.join(exe_name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
    }
    None
}

fn find_qemu() -> Option<PathBuf> {
    if let Some(p) = find_qemu_in_path_var(std::env::var_os("PATH").as_deref()) {
        return Some(p);
    }
    for fallback in [
        "/usr/bin/qemu-system-x86_64",
        "/usr/local/bin/qemu-system-x86_64",
        "C:/Program Files/qemu/qemu-system-x86_64.exe",
    ] {
        let p = PathBuf::from(fallback);
        if p.is_file() {
            return Some(p);
        }
    }
    None
}

/// Pinned QEMU CPU model (`R9`): named `qemu64` baseline with explicit
/// `rdrand`, `fsgsbase`, `smap`, and `smep` capabilities instead of `-cpu max`.
const PINNED_QEMU_CPU_MODEL: &str = "qemu64,+rdrand,+fsgsbase,+smap,+smep";

/// QEMU accelerator arguments for the smoke boots. Default TCG: slower but deterministic,
/// and on some Windows hosts WHPX accepts the guest but never advances the BIOS past reset
/// (serial stays empty and the banner sweep fails). `CUTTLE_QEMU_ACCEL=whpx` runs the same
/// assertions under Hyper-V hardware virtualization; `auto` tries WHPX, then QEMU falls
/// back to TCG if WHPX cannot initialize.
fn smoke_accel_args() -> Vec<&'static str> {
    match std::env::var("CUTTLE_QEMU_ACCEL").as_deref() {
        Err(_) | Ok("") | Ok("tcg") => vec!["-accel", "tcg"],
        Ok("whpx") => vec!["-accel", "whpx"],
        Ok("auto") => vec!["-accel", "whpx", "-accel", "tcg"],
        Ok(other) => panic!("CUTTLE_QEMU_ACCEL must be tcg, whpx or auto, got {other:?}"),
    }
}

fn factory_builder_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_factory_builder"))
}

static QEMU_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

#[test]
#[ignore]
fn boots_under_qemu_and_emits_banner() {
    let _guard = QEMU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = root.join("factory_builder_pkg");

    let require_qemu = std::env::var("CUTTLE_REQUIRE_QEMU").as_deref() == Ok("1");
    if !kernel_crate.join("Cargo.toml").exists() {
        if require_qemu {
            panic!(
                "CUTTLE_REQUIRE_QEMU=1: target_enterprise_kernel/ not present at {}",
                kernel_crate.display()
            );
        }
        eprintln!(
            "SKIP: target_enterprise_kernel/ not present at {} — out-of-workspace kernel crate missing",
            kernel_crate.display()
        );
        return;
    }
    if !pkg_crate.join("Cargo.toml").exists() {
        if require_qemu {
            panic!(
                "CUTTLE_REQUIRE_QEMU=1: factory_builder_pkg/ not present at {}",
                pkg_crate.display()
            );
        }
        eprintln!(
            "SKIP: factory_builder_pkg/ not present at {} — out-of-workspace packager missing",
            pkg_crate.display()
        );
        return;
    }
    let qemu = match find_qemu() {
        Some(p) => p,
        None => {
            if require_qemu {
                panic!(
                    "CUTTLE_REQUIRE_QEMU=1: qemu-system-x86_64 not found on PATH or standard install locations"
                );
            }
            eprintln!(
                "SKIP: qemu-system-x86_64 not found on PATH or standard install locations"
            );
            return;
        }
    };

    // 1) Build the kernel ELF via `factory_builder build-kernel`.
    eprintln!("smoke: building kernel ELF...");
    let bk = Command::new(factory_builder_bin())
        .arg("build-kernel")
        .arg("--kernel-crate")
        .arg(&kernel_crate)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .expect("spawn factory_builder build-kernel");
    if !bk.status.success() {
        if require_qemu {
            panic!(
                "CUTTLE_REQUIRE_QEMU=1: kernel build failed. exit={:?}",
                bk.status.code()
            );
        }
        eprintln!(
            "SKIP: kernel build failed (likely missing nightly + rust-src). exit={:?}",
            bk.status.code()
        );
        return;
    }
    let elf = PathBuf::from(
        String::from_utf8_lossy(&bk.stdout)
            .lines()
            .next()
            .expect("no stdout from build-kernel")
            .trim(),
    );
    assert!(elf.exists(), "kernel ELF reported missing: {}", elf.display());
    eprintln!("smoke: built kernel ELF: {}", elf.display());

    // 2) Package as BIOS image via `factory_builder` (package mode).
    let images_dir = root.join("target").join("cuttle_images");
    std::fs::create_dir_all(&images_dir).ok();
    let bios = images_dir.join("qemu_smoke_bios.img");
    let pkg_out = Command::new(factory_builder_bin())
        .arg("--candidate")
        .arg(&elf)
        .arg("--out")
        .arg(&bios)
        .output()
        .expect("spawn factory_builder package");
    if !pkg_out.status.success() {
        if require_qemu {
            panic!(
                "CUTTLE_REQUIRE_QEMU=1: factory_builder_pkg packaging failed.\nstderr:\n{}",
                String::from_utf8_lossy(&pkg_out.stderr)
            );
        }
        eprintln!(
            "SKIP: factory_builder_pkg packaging failed (likely missing nightly toolchain).\n\
             stderr:\n{}",
            String::from_utf8_lossy(&pkg_out.stderr)
        );
        return;
    }
    assert!(bios.exists(), "BIOS image missing: {}", bios.display());
    let bios_size = std::fs::metadata(&bios).unwrap().len();
    assert!(
        bios_size > 1024 * 1024,
        "BIOS image suspiciously small ({} bytes)",
        bios_size
    );
    eprintln!("smoke: BIOS image OK ({} bytes)", bios_size);

    let stdout = String::from_utf8_lossy(&pkg_out.stdout);
    assert!(
        stdout.lines().any(|l| l.starts_with("bios ")),
        "factory_builder stdout missing 'bios ' line: {}",
        stdout
    );

    // 3) Boot in QEMU with a serial-file log, watch for the banner.
    let serial_log = images_dir.join("qemu_smoke_serial.log");
    // TASK-104: real virtio-blk-pci disk (not MemBus). Kernel
    // `banner_virtio_hw` probes it via 0xCF8/0xCFC config I/O.
    let virtio_disk = images_dir.join("virtio_hw.img");
    if !virtio_disk.exists() || std::fs::metadata(&virtio_disk).map(|m| m.len()).unwrap_or(0) < 1024 * 1024
    {
        // 1 MiB zero image — capacity only; we do not read sectors yet.
        std::fs::write(&virtio_disk, vec![0u8; 1024 * 1024]).expect("create virtio_hw.img");
    }
    // TASK-113: 1 MiB disk on a real AHCI HBA (IDENTIFY → 2048 sectors).
    // Always start with a clean 1 MiB image so Boot 1 (provision) and Boot 2 (resume) are deterministic.
    let ahci_disk = images_dir.join("ahci_hw.img");
    std::fs::write(&ahci_disk, vec![0u8; 1024 * 1024]).expect("create ahci_hw.img");
    // TASK-119: 1 MiB NVMe namespace for real admin identify.
    let nvme_disk = images_dir.join("nvme_hw.img");
    if !nvme_disk.exists() || std::fs::metadata(&nvme_disk).map(|m| m.len()).unwrap_or(0) < 1024 * 1024
    {
        std::fs::write(&nvme_disk, vec![0u8; 1024 * 1024]).expect("create nvme_hw.img");
    }
    // Provision a 32-byte OS-CSPRNG device secret key outside the kernel
    // image and outside the AHCI disk, delivered via QEMU fw_cfg.
    let device_key_path = root.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    factory_builder::ensure_device_secret_key(&device_key_path)
        .expect("provision 32-byte CSPRNG device_secret_key.bin");

    let vm = SmokeVm {
        qemu: &qemu,
        bios: &bios,
        virtio_disk: &virtio_disk,
        ahci_disk: &ahci_disk,
        nvme_disk: &nvme_disk,
        device_key: &device_key_path,
    };

    // TASK-023: the kernel now exercises every morphed surface
    // (TLS hkdf, TLS KAT + cert, WAL replay, IOMMU translate,
    // HashImpl digest) BEFORE emitting `CUTTLE-TE HALT`. Waiting for
    // the HALT line is the gate: if it appears, every preceding
    // banner is also present because the kernel panics on any drift
    // and the HALT line is suppressed.
    let required_banners: &[&str] = REQUIRED_BANNERS;
    eprintln!(
        "smoke: launching QEMU {:?} (+4x SMP +virtio-blk +2x net hub +ahci +nvme +fw_cfg device key)...",
        smoke_accel_args()
    );
    let (log_contents, all_seen) =
        vm.boot(&serial_log, |s| required_banners.iter().all(|b| s.contains(b)));
    if !all_seen {
        // Report which banners are present vs missing so the failure is
        // actionable.
        let missing: Vec<&&str> = required_banners
            .iter()
            .filter(|b| !log_contents.contains(**b))
            .collect();
        panic!(
            "QEMU smoke: required banner(s) missing within 45s: {:?}\n\
             Required: {:?}\n\
             Serial log:\n{}",
            missing, required_banners, log_contents
        );
    }
    // Banners must appear in order — proof the proof sequence ran
    // top-to-bottom rather than e.g. a partial boot loop.
    let mut cursor = 0usize;
    for b in required_banners {
        match log_contents[cursor..].find(b) {
            Some(rel) => cursor += rel + b.len(),
            None => panic!(
                "QEMU smoke: banner {:?} not found at-or-after offset {} (out-of-order or missing).\nSerial log:\n{}",
                b, cursor, log_contents
            ),
        }
    }
    if log_contents.contains("SHELL resume REJECTED") {
        panic!(
            "QEMU smoke: unexpected SHELL resume REJECTED on clean disk!\nSerial log:\n{}",
            log_contents
        );
    }
    assert!(
        log_contents.contains("tlb_ipi=3 vtd_slpt=ok ap_crypto=3 ioapic=1 vtd_drhd=ok"),
        "QEMU smoke: expected OS_ARMOR tlb_ipi=3 vtd_slpt=ok ap_crypto=3 ioapic=1 vtd_drhd=ok!\nSerial log:\n{}",
        log_contents
    );
    {
        let ahci_bytes = std::fs::read(&ahci_disk).expect("read ahci_hw.img after boot 1");
        let commit_off = 1149 * 512;
        assert_eq!(
            &ahci_bytes[commit_off..commit_off + 8],
            b"CTTLAB01",
            "QEMU smoke: expected CTTLAB01 atomic journal commit sector at LBA 1149"
        );
        assert_eq!(
            ahci_bytes[commit_off + 8],
            0x02,
            "QEMU smoke: expected AB_STATE_QUIESCENT (0x02) at LBA 1149 after clean commit"
        );
        assert_eq!(
            ahci_bytes[commit_off + 9],
            0x03,
            "QEMU smoke: expected AB_FORMAT_V3 (0x03) at LBA 1149 after clean AEAD commit"
        );
    }
    if log_contents.contains("CONTINUITY resume OK") {
        assert!(
            log_contents.contains("SHELL resume OK"),
            "QEMU smoke: expected SHELL resume OK on boot > 1 (CONTINUITY resume OK present), but it was missing!\nSerial log:\n{}",
            log_contents
        );
    } else if log_contents.contains("CONTINUITY genesis") {
        // First boot on a freshly initialized ahci_hw.img: boot a second time to
        // prove cross-boot SHELL resume OK works with the provisioned fw_cfg key.
        let resume_log_path = images_dir.join("qemu_smoke_resume_serial.log");
        let (resume_log, _) = vm.boot(&resume_log_path, halted);
        assert!(
            !resume_log.contains("SHELL resume REJECTED"),
            "QEMU smoke (boot 2): unexpected SHELL resume REJECTED!\nSerial log:\n{}",
            resume_log
        );
        assert!(
            resume_log.contains("CONTINUITY resume OK") && resume_log.contains("SHELL resume OK"),
            "QEMU smoke (boot 2): expected CONTINUITY resume OK + SHELL resume OK!\nSerial log:\n{}",
            resume_log
        );
    }
    eprintln!(
        "smoke: all {} required banners + SHELL resume OK verified in order; QEMU smoke test PASSED",
        required_banners.len()
    );
}

const REQUIRED_BANNERS: &[&str] = &[
    "CUTTLE-TE OK",
    "TLS hkdf OK prk_sha=",
    "TLS kat OK aead=2 kx=2 sig=1",
    "TLS cert OK alg=ecdsa-p256 sha=c1a5d92d1e129087",
    "WAL replay OK frames=",
    "IOMMU translate OK pa=",
    "HASH OK digest_sha=",
    "NET build OK len=37 ip_cksum=63c8 udp_cksum=50c2",
    "KPTI build_user_view OK secrets=4",
    "KPTI validate_user_view OK violations=0",
    "DMA_MAP test OK",
    "DMA_UNMAP test OK",
    "RING3 transition OK cpl=3->0 vec=0x80 ist1=ok rsp0=ok syscall=43",
    "NVMe init OK ctrl=CUTTLE-NVME-EMU",
    "NVMe read_lba(7) OK first_byte=a5",
    "TCP handshake OK state=ESTABLISHED seq=",
    "TCP teardown OK state=CLOSED snd_nxt=",
    "TCP_IPV6_TRIAD OK cwnd=grow fast_retx=1 ooo=8 ipv6=echo+ndp rpc=hmac",
    "HTTP parse OK method=GET path=/healthz",
    "HTTP build OK status=200 bytes=",
    "DNS query OK id=c0de qname=cuttle.local",
    "DNS response OK id=c0de ans=10.0.0.42 bytes=",
    "ICMP echo_req OK id=4242 seq=7 cksum=",
    "ICMP echo_rep OK id=4242 seq=7",
    "ETH build OK len=51 ethertype=0800",
    "ETH parse OK src=00aabbccddee dst=123456789abc",
    "ETH vlan OK tci=6064 vid=100 pcp=3",
    "ARP request OK target_ip=10.0.0.42 op=1",
    "ARP cache OK entries=1",
    "DHCP discover OK xid=deadbeef",
    "DHCP bound OK yiaddr=10.0.0.42 lease=86400",
    "VIRTIO_NET init OK mac=525400123456",
    "VIRTIO_NET roundtrip OK tx=1 rx=1",
    "VIRTIO_BLK init OK capacity=32 blk_size=512",
    "VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5",
    "E1000 init OK mac=525400123456 link=up_1000",
    "E1000 frame OK tx_bytes=64 rx_bytes=64",
    "FW eval OK rules=3 verdicts=accept,accept,drop",
    "FW default OK action=Drop",
    "TPM startup OK len=12 tag=8001",
    "TPM getrandom OK len=12 cc=0000017b",
    "TPM parse OK rc=00000000 random_len=16",
    "TPM2_TIS driver OK did_vid=000115d1 locality=0 pcr10=extended",
    "AUDIT append OK events=3",
    "AUDIT snapshot OK bytes=308",
    "SNTP request OK mode=3 vn=4 xmt=429496729600",
    "SNTP reply OK offset_ns=0 delay_ns=1000000000",
    "VFS mount OK fs=ramfs root=/",
    "VFS read OK path=/etc/hostname bytes=10",
    "EBPF program OK insns=6 verdicts=1,0,1",
    "EBPF stack OK bytes=512",
    "SMP discover OK bsp=0 aps=3",
    "SMP wake OK ipis=9 vec=0x08",
    "TFTP rrq OK len=25 mode=octet",
    "TFTP data OK block=2 bytes=10",
    "PCI scan OK devices=2 e1000=found nvme=found",
    "PCI bar OK e1000_io=0xc020",
    "X509 parse OK len=255 serial=42",
    "X509 cn OK cn=cuttle-te-x509-kernel-fixture",
    "PIT program OK hz=1000 div=1193",
    "RTC read OK unix=1773578096 date=2026-03-15",
    "KAT all OK vectors=9",
    "JFS mount OK root_ino=1 inodes=3",
    "JFS read OK path=/hello.txt bytes=15 sha=7e76bd63",
    "GDBSTUB parse OK cmd=g cksum=67",
    "QUOTA scan OK records=3",
    "QUOTA reject OK uid=1001 reason=block_limit",
    "HPET program OK period_fs=69841279 cmp=14318",
    "CANARY mint OK tok=",
    "CANARY fail OK reason=mismatch",
    "KBD decode OK keys=2 last=b",
    "FAT mount OK fats=2 root_clus=2",
    "FAT read OK name=HELLO.TXT bytes=13",
    "WATCHDOG pet OK deadline=5",
    "WATCHDOG fire OK reason=timeout",
    "RNG kat OK seed=0102 out=",
    "POWER s5 OK slp_typ=5",
    "ELF parse OK phnum=1 entry=4198400",
    "SERIAL init OK port=0x3f8",
    "TICK source OK kind=hpet",
    "VIRTIO caps OK common=found",
    "SIGKAT all OK vectors=2",
    "MB2 parse OK tags=1",
    "CRC32C kat OK",
    "RSDP parse OK oem=BOCHS",
    "FRAME alloc OK free=4094",
    "IOAPIC entry OK vec=0x30",
    "LAPIC icr OK delivery=init",
    "GPT parse OK parts=1",
    "DNS name OK labels=2",
    "DRBG kat OK",
    "AHCI fis OK cmd=identify",
    "XHCI trb OK type=noop",
    "GOP mode OK 1280x720",
    "TLV parse OK tags=3",
    "B64 roundtrip OK",
    "AHCI cmd OK prdtl=1",
    "TIMEBASE compose OK pit_div=1193 pet_rem=5 fire=timeout",
    "VFS+QUOTA compose OK allow=1000 reject=1001 bytes=7",
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
    "HTTPS UP port=443 tls13=rustls entropy=rdrand provisioned=1 cert_sha256=",
    "E1000_HW probe OK slot=",
    "E1000_HW tx OK bytes=64",
    "E1000_HW rx OK bytes=",
    "NVME_HW probe OK slot=",
    "NVME_HW identify OK sn=",
    "NVME_HW sector OK first_byte=5a",
    "DURABLE seal OK dig=",
    "CRASH_DUMP wrote 16384 bytes to lba=1024 crc=659ece68",
    "SYMBOL resolve OK kernel_main+0x42 (5 frames)",
    "WEB+SQL+SESSION compose OK tables=2 rows=6 magic=CTTLSQL1",
    "SECCOMP: OK engine=ebpf filter=enforced",
    "ATTEST: OK seed=",
    "FS partition OK lba=1045..1076 sectors=32 files=1 magic=CTTLFS01",
    "HTTPS compose OK slots=16 port=443 tls13=rustls bytes=882 sha=83e47624",
    "SVC_RUNTIME: OK role=full->wfe->full svcs=3 kpti=isolated seccomp=deny-default rot=1",
    "SHELL compose OK tasks=5 files=5 audit=5",
    "SMP_HW init OK cpus=4 threads=4 ctx_sw=4",
    "OS_ARMOR OK mmio_nx=1 guarded_stacks=16 tss_ltr=4",
    "PHYS_MM_SLAB OK pt_burst=128 scrub=zero leak=0 usable_frames=",
    "RING3_ELF_MP OK procs=11 preempts=",
    "faults_isolated=4 respawn=1 leak=0",
    "ASYNC_DMA_IRQ OK blk_irqs=",
    "PAGED_STORE OK lsn=2 dirty=1 merkle=ok",
    "CUTTLE-TE HALT",
];

/// Host-side files attached to QEMU for one smoke boot. The smoke test and
/// the tamper test each point this at their own boot image and disks, so
/// the two can run in parallel without sharing a file.
struct SmokeVm<'a> {
    qemu: &'a Path,
    bios: &'a Path,
    virtio_disk: &'a Path,
    ahci_disk: &'a Path,
    nvme_disk: &'a Path,
    device_key: &'a Path,
}

impl SmokeVm<'_> {
    /// Boot once with serial output in `serial_log`, polling until
    /// `done(log)` holds or 45s pass, then kill QEMU. Returns the final
    /// log and whether `done` was reached.
    fn boot(&self, serial_log: &Path, done: impl Fn(&str) -> bool) -> (String, bool) {
        let _ = std::fs::remove_file(serial_log);
        // Accelerator: TCG unless CUTTLE_QEMU_ACCEL says otherwise (see `smoke_accel_args`).
        // Boot image on IDE so virtio-blk-pci is a *second* disk the
        // kernel can discover without fighting the bootloader drive.
        let mut qproc = Command::new(self.qemu)
            .args(smoke_accel_args())
            .arg("-cpu")
            .arg(PINNED_QEMU_CPU_MODEL)
            .arg("-smp")
            .arg("4")
            .arg("-fw_cfg")
            .arg(format!(
                "name={},file={}",
                factory_builder::FW_CFG_DEVICE_KEY_NAME,
                self.device_key.display()
            ))
            .arg("-drive")
            .arg(format!("format=raw,file={},if=ide", self.bios.display()))
            .arg("-drive")
            .arg(format!(
                "if=none,id=vd0,format=raw,file={}",
                self.virtio_disk.display()
            ))
            .arg("-device")
            // Force legacy virtio-pci (QUEUE_PFN + I/O BAR) so the kernel
            // hardware path can drive a real virtqueue without modern caps.
            .arg("virtio-blk-pci,drive=vd0,disable-legacy=off,disable-modern=on")
            // TASK-111: two hubport NICs so guest TX on peer B is delivered
            // as RX on peer A (in-guest loopback; no host inject race).
            .arg("-netdev")
            .arg("hubport,id=n0,hubid=1")
            .arg("-device")
            .arg("virtio-net-pci,netdev=n0,disable-legacy=off,disable-modern=on")
            .arg("-netdev")
            .arg("hubport,id=n1,hubid=1")
            .arg("-device")
            .arg("virtio-net-pci,netdev=n1,disable-legacy=off,disable-modern=on")
            // TASK-113: real AHCI HBA + ide-hd for ATA IDENTIFY / sector DMA.
            .arg("-drive")
            .arg(format!(
                "if=none,id=ahd0,format=raw,file={}",
                self.ahci_disk.display()
            ))
            .arg("-device")
            .arg("ahci,id=ahci0")
            .arg("-device")
            .arg("ide-hd,drive=ahd0,bus=ahci0.0")
            // TASK-116/120/132: dual e1000 on hub for TX + RX hardware-truth.
            .arg("-netdev")
            .arg("hubport,id=e0,hubid=2")
            .arg("-device")
            .arg("e1000,netdev=e0")
            .arg("-netdev")
            .arg("hubport,id=e1,hubid=2")
            .arg("-device")
            .arg("e1000,netdev=e1")
            // TASK-119: real NVMe controller + namespace for admin identify.
            .arg("-drive")
            .arg(format!(
                "if=none,id=nvme0,format=raw,file={}",
                self.nvme_disk.display()
            ))
            .arg("-device")
            .arg("nvme,drive=nvme0,serial=CUTTLE-NVME-HW")
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
            .expect("spawn qemu");

        // TCG needs more wall-clock than WHPX; 45s covers a full banner
        // sweep on a cold cache. Exit early as soon as `done` holds.
        let deadline = Instant::now() + Duration::from_secs(45);
        let mut reached = false;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(250));
            if let Ok(s) = std::fs::read_to_string(serial_log) {
                if done(&s) {
                    reached = true;
                    break;
                }
            }
        }
        // Kill QEMU regardless of outcome.
        let _ = qproc.kill();
        let _ = qproc.wait();
        (std::fs::read_to_string(serial_log).unwrap_or_default(), reached)
    }

    /// Boot with piped `-serial stdio`, wait until `interactive shell ready.` appears,
    /// feed `commands` line-by-line (pausing briefly between lines), wait until `done(log)`
    /// holds or 45s pass, then kill QEMU and return `(log, reached)`.
    fn boot_interactive(
        &self,
        commands: &[&str],
        done: impl Fn(&str) -> bool,
    ) -> (String, bool) {
        self.boot_interactive_opts(true, commands, done)
    }

    fn boot_interactive_opts(
        &self,
        provisioned: bool,
        commands: &[&str],
        done: impl Fn(&str) -> bool,
    ) -> (String, bool) {
        use std::io::{Read, Write};
        use std::sync::{Arc, Mutex};

        let mut cmd = Command::new(self.qemu);
        cmd.args(smoke_accel_args())
            .arg("-cpu")
            .arg(PINNED_QEMU_CPU_MODEL)
            .arg("-smp")
            .arg("4");
        if provisioned {
            cmd.arg("-fw_cfg").arg(format!(
                "name={},file={}",
                factory_builder::FW_CFG_DEVICE_KEY_NAME,
                self.device_key.display()
            ));
        }
        let mut qproc = cmd
            .arg("-drive")
            .arg(format!("format=raw,file={},if=ide", self.bios.display()))
            .arg("-drive")
            .arg(format!(
                "if=none,id=vd0,format=raw,file={}",
                self.virtio_disk.display()
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
                self.ahci_disk.display()
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
                self.nvme_disk.display()
            ))
            .arg("-device")
            .arg("nvme,drive=nvme0,serial=CUTTLE-NVME-HW")
            .arg("-serial")
            .arg("stdio")
            .arg("-display")
            .arg("none")
            .arg("-no-reboot")
            .arg("-m")
            .arg("256M")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn interactive qemu");

        let mut stdout = qproc.stdout.take().expect("qemu stdout");
        let mut stdin = qproc.stdin.take().expect("qemu stdin");
        let buf = Arc::new(Mutex::new(String::new()));
        let buf_reader = Arc::clone(&buf);
        let reader_handle = std::thread::spawn(move || {
            let mut chunk = [0u8; 512];
            while let Ok(n) = stdout.read(&mut chunk) {
                if n == 0 {
                    break;
                }
                let text = String::from_utf8_lossy(&chunk[..n]);
                if let Ok(mut g) = buf_reader.lock() {
                    g.push_str(&text);
                }
            }
        });

        let deadline = Instant::now() + Duration::from_secs(60);
        let mut commands_sent = false;
        let mut reached = false;
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(120));
            let snapshot = buf.lock().map(|g| g.clone()).unwrap_or_default();
            if !commands_sent && snapshot.contains("cuttle> ") {
                std::thread::sleep(Duration::from_millis(60));
                for cmd in commands {
                    let prompts_before = buf
                        .lock()
                        .map(|g| g.matches("cuttle> ").count())
                        .unwrap_or(0);
                    let payload = format!("{cmd}\n");
                    for chunk in payload.as_bytes().chunks(6) {
                        let _ = stdin.write_all(chunk);
                        let _ = stdin.flush();
                        std::thread::sleep(Duration::from_millis(30));
                    }
                    let is_terminal = matches!(*cmd, "halt" | "reboot" | "poweroff")
                        || cmd.starts_with("__selftest_");
                    if !is_terminal {
                        let cmd_wait = Instant::now() + Duration::from_secs(12);
                        while Instant::now() < cmd_wait {
                            let cur = buf
                                .lock()
                                .map(|g| g.matches("cuttle> ").count())
                                .unwrap_or(0);
                            if cur > prompts_before {
                                break;
                            }
                            std::thread::sleep(Duration::from_millis(35));
                        }
                    } else {
                        std::thread::sleep(Duration::from_millis(250));
                    }
                }
                commands_sent = true;
            }
            if commands_sent && done(&snapshot) {
                reached = true;
                break;
            }
        }
        drop(stdin);
        let _ = qproc.kill();
        let _ = qproc.wait();
        let _ = reader_handle.join();
        let final_log = buf.lock().map(|g| g.clone()).unwrap_or_default();
        (final_log, reached)
    }
}

fn halted(log: &str) -> bool {
    log.contains("CUTTLE-TE HALT")
}

#[test]
#[ignore = "requires nightly rust-src + factory_builder_pkg + qemu-system-x86_64"]
fn tampered_ahci_seal_is_rejected_under_qemu() {
    let _guard = QEMU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    let Some(qemu) = find_qemu() else {
        panic!("qemu-system-x86_64 not found");
    };
    let root = workspace_root();
    let images_dir = root.join("target").join("cuttle_images");
    std::fs::create_dir_all(&images_dir).expect("create images_dir");
    // Build a dedicated boot image from the current source on every run.
    // Reusing qemu_smoke_bios.img would boot whatever kernel the last smoke
    // run left behind, and race the smoke test rewriting it in parallel.
    let bios = images_dir.join("qemu_tamper_bios.img");
    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = factory_builder::locate_pkg_crate().expect("locate_pkg_crate");
    let elf = factory_builder::build_kernel(&kernel_crate).expect("build_kernel");
    let morphed_elf = images_dir.join("qemu_tamper_morphed.elf");
    let bm = Command::new("cargo")
        .current_dir(&root)
        .args(["run", "--release", "-p", "cuttle-binmorph", "--", "--in"])
        .arg(&elf)
        .arg("--out")
        .arg(&morphed_elf)
        .args(["--seed", "42"])
        .output()
        .expect("run cuttle-binmorph");
    assert!(
        bm.status.success(),
        "cuttle-binmorph failed: {}",
        String::from_utf8_lossy(&bm.stderr)
    );
    factory_builder::package_kernel_via_pkg(&pkg_crate, &morphed_elf, &bios, None)
        .expect("package_kernel_via_pkg");

    // Fresh scratch disks for this test only, so it never shares a disk with
    // the smoke test or touches its persistent *_hw.img images.
    let virtio_disk = images_dir.join("virtio_tamper_test.img");
    let tampered_disk = images_dir.join("ahci_tamper_test.img");
    let nvme_disk = images_dir.join("nvme_tamper_test.img");
    let scratch_disks = [&virtio_disk, &tampered_disk, &nvme_disk];
    for disk in scratch_disks {
        std::fs::write(disk, vec![0u8; 1024 * 1024]).expect("init tamper-test scratch disk");
    }
    let device_key_path = root.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    factory_builder::ensure_device_secret_key(&device_key_path)
        .expect("provision 32-byte CSPRNG device_secret_key.bin");

    let vm = SmokeVm {
        qemu: &qemu,
        bios: &bios,
        virtio_disk: &virtio_disk,
        ahci_disk: &tampered_disk,
        nvme_disk: &nvme_disk,
        device_key: &device_key_path,
    };
    let tamper_log = images_dir.join("qemu_tamper_serial.log");

    // Boot 1 (7-pass binmorphed kernel): verify all required banners and write valid sealed state.
    let (log1, reached1) = vm.boot(&tamper_log, halted);
    assert!(
        reached1,
        "binmorphed kernel boot 1 did not reach CUTTLE-TE HALT within 45s!\nSerial log:\n{}",
        log1
    );
    for &expected in REQUIRED_BANNERS {
        assert!(
            log1.contains(expected),
            "binmorphed kernel boot 1 missing '{}'!\nSerial log:\n{}",
            expected,
            log1
        );
    }

    // The store keeps two copies of the state (primary slot LBA 1040..=1092,
    // shadow slot LBA 1096..=1148) under one HMAC-sealed commit record at LBA 1149.
    //
    // Case 1: damage one copy. Flip a byte of the sealed journal sector in the
    // primary slot (LBA 1041, offset 8). The tampered bytes must never be
    // used, and one damaged copy must not cost the node its state: boot 2
    // has to restore from the intact shadow copy and say that it did.
    let mut disk_bytes = std::fs::read(&tampered_disk).expect("read ahci_tamper_test.img");
    let primary_wal = 1041 * 512 + 8;
    disk_bytes[primary_wal] ^= 0xFF;
    std::fs::write(&tampered_disk, &disk_bytes).expect("write tampered ahci_tamper_test.img");

    let (log2, reached2) = vm.boot(&tamper_log, halted);
    assert!(
        reached2,
        "tamper test boot 2 did not reach CUTTLE-TE HALT within 45s!\nSerial log:\n{}",
        log2
    );
    assert!(
        log2.contains("SHELL resume REPAIRED: primary slot failed verification; state restored from shadow slot"),
        "tamper test boot 2 did not report the repair of the tampered primary slot!\nSerial log:\n{}",
        log2
    );
    assert!(
        log2.contains("SHELL resume OK") && !log2.contains("SHELL resume REJECTED"),
        "tamper test boot 2 must resume from the intact shadow copy!\nSerial log:\n{}",
        log2
    );
    let healed = std::fs::read(&tampered_disk).expect("read ahci_tamper_test.img after boot 2");
    assert_eq!(
        &healed[1040 * 512..1040 * 512 + 8],
        b"CTTLAE03",
        "boot 2 did not leave an AEAD-encrypted CTTLAE03 primary slot behind"
    );
    assert_eq!(
        &healed[1040 * 512..1093 * 512],
        &healed[1096 * 512..1149 * 512],
        "after the repair both slots must hold the same image"
    );

    // Case 2: damage both copies (the same journal sector in each slot).
    // Nothing on the disk can be authenticated any more, so boot 3 must
    // reject it and must NOT resume, exactly as before. What changes is
    // that the rejected sectors are set aside instead of being overwritten.
    let mut disk_bytes = healed;
    let shadow_wal = 1097 * 512 + 8;
    disk_bytes[primary_wal] ^= 0xFF;
    disk_bytes[shadow_wal] ^= 0xFF;
    let rejected_primary = disk_bytes[1040 * 512..1093 * 512].to_vec();
    let rejected_shadow = disk_bytes[1096 * 512..1149 * 512].to_vec();
    std::fs::write(&tampered_disk, &disk_bytes).expect("write doubly tampered ahci_tamper_test.img");

    let (log3, reached3) = vm.boot(&tamper_log, halted);
    let after3 = std::fs::read(&tampered_disk).expect("read ahci_tamper_test.img after boot 3");

    // Case 3: unprovisioned keyless boot (`opt/cuttle_device_key` omitted).
    // Must warn explicitly, enter ephemeral mode, refuse durable mutations with EROFS,
    // and leave the AHCI state + quarantine regions (`LBA 1040..1324`) completely untouched.
    let (log4, reached4) = vm.boot_interactive_opts(
        false,
        &["write /var/ephemeral.txt denied", "halt"],
        |s| s.contains("system halting..."),
    );
    let after4 = std::fs::read(&tampered_disk).expect("read ahci_tamper_test.img after keyless boot");

    // Case 4: Ring-0 hardware CPU exception (`ud2` = `#UD` vector 6) on a provisioned boot.
    // Must trap through `ISR_CPU_EXC_STUBS` -> `kernel_cpu_exception_handler` (never `iretq`-looping),
    // emit `CUTTLE-TE PANIC: CPU FAULT: vec=6` on COM1, and persist an AEAD-encrypted `CTTLPENC`
    // crash dump via isolated AHCI Slot 1 (`LBA 1536..1568`) with zero plaintext leakage on disk.
    std::fs::write(&tampered_disk, vec![0u8; 1024 * 1024]).expect("reset disk for CPU fault test");
    let (log5, reached5) = vm.boot_interactive_opts(
        true,
        &["__selftest_ud2_fault"],
        |s| {
            s.contains("CUTTLE-TE PANIC: CPU FAULT: vec=6")
                && s.contains("CRASH_DUMP emergency slot=1 lba=1536..1568")
        },
    );
    let after5 = std::fs::read(&tampered_disk).expect("read ahci_tamper_test.img after CPU fault");

    for disk in scratch_disks {
        let _ = std::fs::remove_file(disk);
    }
    let _ = std::fs::remove_file(&bios);
    let _ = std::fs::remove_file(&morphed_elf);
    assert!(
        reached3,
        "tamper test boot 3 did not reach CUTTLE-TE HALT within 45s!\nSerial log:\n{}",
        log3
    );
    assert!(
        log3.contains("SHELL resume REJECTED: HMAC-SHA256 seal verification failed (tampered disk)"),
        "tamper test boot 3 did not emit SHELL resume REJECTED!\nSerial log:\n{}",
        log3
    );
    assert!(
        !log3.contains("SHELL resume OK"),
        "tamper test boot 3 unexpectedly emitted SHELL resume OK on a tampered disk!\nSerial log:\n{}",
        log3
    );
    assert!(
        log3.contains("SHELL resume NOTICE: unverifiable state preserved in quarantine (LBA 1216..1323)"),
        "tamper test boot 3 did not report preserving the rejected state!\nSerial log:\n{}",
        log3
    );
    // Quarantine area: primary copy at LBA 1216..1269, shadow copy at 1269..1322, marker at 1323.
    assert_eq!(
        &after3[1323 * 512..1323 * 512 + 8],
        b"CTTLQUA1",
        "quarantine marker missing at LBA 1323"
    );
    assert!(
        after3[1216 * 512..1269 * 512] == rejected_primary[..]
            && after3[1269 * 512..1322 * 512] == rejected_shadow[..],
        "the quarantine area does not hold the rejected slots byte for byte"
    );
    assert!(
        reached4,
        "unprovisioned keyless boot did not respond to interactive halt!\nSerial log:\n{}",
        log4
    );
    assert!(
        log4.contains("PROVISIONING WARNING: fw_cfg opt/cuttle_device_key absent; durable writes refused (ephemeral mode)")
            && log4.contains("SHELL resume EPHEMERAL: device key not provisioned; durable writes refused (EROFS)"),
        "unprovisioned keyless boot did not emit expected warning + ephemeral banner!\nSerial log:\n{}",
        log4
    );
    assert!(
        log4.contains("EROFS (device key not provisioned; durable writes refused)"),
        "unprovisioned keyless boot did not refuse `write` with EROFS!\nSerial log:\n{}",
        log4
    );
    assert_eq!(
        &after4[1024 * 512..1324 * 512],
        &after3[1024 * 512..1324 * 512],
        "unprovisioned keyless boot modified AHCI continuity, state, or quarantine sectors!"
    );
    assert!(
        reached5 && log5.contains("CUTTLE-TE PANIC: CPU FAULT: vec=6"),
        "Ring-0 `#UD` fault did not report `CUTTLE-TE PANIC: CPU FAULT: vec=6`!\nSerial log:\n{}",
        log5
    );
    let mut dump_slice = after5[1536 * 512..1568 * 512].to_vec();
    assert_eq!(
        &dump_slice[..8],
        b"CTTLPENC",
        "Ring-0 CPU fault did not persist encrypted CTTLPENC crash dump at AHCI LBA 1536"
    );
    assert!(
        !dump_slice.windows(9).any(|w| w == b"CPU FAULT"),
        "raw AHCI crash dump leaked plaintext CPU FAULT string!"
    );
    {
        use target_enterprise::durable_seal::{derive_crash_dump_aead_key, derive_seal_key};
        use target_enterprise::panic_dump::{CrashDump, PanicDumpImpl};
        let master_key: [u8; 32] = std::fs::read(&device_key_path)
            .expect("read device_secret_key.bin")
            .try_into()
            .expect("32-byte device_secret_key.bin");
        let seal_key = derive_seal_key(&master_key, b"cuttle-ahci-wal-seal-v1");
        let crash_key = derive_crash_dump_aead_key(&seal_key);
        PanicDumpImpl::decrypt_dump_in_place(&crash_key, &mut dump_slice)
            .expect("decrypt CTTLPENC crash dump written by Ring-0 CPU exception handler");
        PanicDumpImpl::verify_crc(&dump_slice).expect("verify decrypted crash dump CRC32-C");
        let hdr = PanicDumpImpl::parse_header(&dump_slice).expect("parse decrypted crash dump header");
        assert!(
            hdr.message.as_bytes().starts_with(b"CPU FAULT: vec=6"),
            "decrypted crash dump message did not record CPU FAULT: vec=6: {:?}",
            hdr.message
        );
    }
    eprintln!("smoke: one tampered copy was repaired, two were rejected and preserved, keyless EROFS & Ring-0 CPU fault dump verified; TAMPER TEST PASSED");
}

#[test]
#[ignore = "requires nightly rust-src + factory_builder_pkg + qemu-system-x86_64"]
fn morphed_kernel_boots_and_persists_state_across_multiple_seeds_under_qemu() {
    let _guard = QEMU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use sha2::{Digest, Sha256};
    use std::collections::HashSet;

    let Some(qemu) = find_qemu() else {
        panic!("qemu-system-x86_64 not found");
    };
    let root = workspace_root();
    let images_dir = root.join("target").join("cuttle_images");
    std::fs::create_dir_all(&images_dir).expect("create images_dir");

    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = factory_builder::locate_pkg_crate().expect("locate_pkg_crate");
    let base_elf = factory_builder::build_kernel(&kernel_crate).expect("build_kernel");
    let base_elf_bytes = std::fs::read(&base_elf).expect("read base kernel ELF");

    // 1. Run `cuttle-binmorph` across 10 distinct seeds and prove all 10 morphed kernel ELFs
    //    have mutually distinct SHA-256 digests and identical byte size.
    let all_seeds: [u64; 10] = [101, 202, 303, 404, 505, 606, 707, 808, 909, 1010];
    let mut seen_digests: HashSet<[u8; 32]> = HashSet::new();
    let mut boot_elf_bytes: Vec<(u64, Vec<u8>)> = Vec::new();

    for &seed in &all_seeds {
        let out_elf = images_dir.join(format!("qemu_multiseed_{seed}.elf"));
        let bm = Command::new("cargo")
            .current_dir(&root)
            .args(["run", "--release", "-p", "cuttle-binmorph", "--", "--in"])
            .arg(&base_elf)
            .arg("--out")
            .arg(&out_elf)
            .arg("--seed")
            .arg(seed.to_string())
            .output()
            .expect("run cuttle-binmorph for multi-seed test");
        assert!(
            bm.status.success(),
            "cuttle-binmorph failed on seed {seed}: {}",
            String::from_utf8_lossy(&bm.stderr)
        );
        let morphed = std::fs::read(&out_elf).expect("read morphed ELF");
        assert_eq!(
            morphed.len(),
            base_elf_bytes.len(),
            "in-place morphed ELF size changed on seed {seed}"
        );
        let dig: [u8; 32] = Sha256::digest(&morphed).into();
        assert!(
            seen_digests.insert(dig),
            "duplicate SHA-256 digest produced for morphed kernel seed {seed}"
        );
        if seed == 101 || seed == 202 || seed == 303 {
            boot_elf_bytes.push((seed, morphed));
        } else {
            let _ = std::fs::remove_file(&out_elf);
        }
    }
    assert_eq!(seen_digests.len(), all_seeds.len());

    // 2. Package seed 101 into a bootable BIOS image and locate the contiguous kernel ELF slice
    //    so seeds 202 and 303 can be spliced into their own BIOS images (matching Triad hot-swap).
    let elf_101_path = images_dir.join("qemu_multiseed_101.elf");
    let bios_101_path = images_dir.join("qemu_multiseed_bios_101.img");
    factory_builder::package_kernel_via_pkg(&pkg_crate, &elf_101_path, &bios_101_path, None)
        .expect("package_kernel_via_pkg for seed 101");
    let base_bios_bytes = std::fs::read(&bios_101_path).expect("read bios_101");
    let elf_101_bytes = &boot_elf_bytes[0].1;
    let elf_offset = base_bios_bytes
        .windows(elf_101_bytes.len())
        .position(|w| w == elf_101_bytes.as_slice())
        .expect("locate contiguous kernel ELF inside packaged BIOS image");

    // 3. Create fresh persistent scratch disks shared across the 3 consecutive cross-seed boots:
    let virtio_disk = images_dir.join("virtio_multiseed_test.img");
    let ahci_disk = images_dir.join("ahci_multiseed_test.img");
    let nvme_disk = images_dir.join("nvme_multiseed_test.img");
    let scratch_disks = [&virtio_disk, &ahci_disk, &nvme_disk];
    for disk in scratch_disks {
        std::fs::write(disk, vec![0u8; 1024 * 1024]).expect("init multiseed scratch disk");
    }
    let device_key_path = root.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    factory_builder::ensure_device_secret_key(&device_key_path)
        .expect("provision 32-byte CSPRNG device_secret_key.bin");

    let mut boot_1_shell_sector: Option<Vec<u8>> = None;
    let mut boot_1_fs_magic: Option<Vec<u8>> = None;
    let mut boot_1_sql_magic: Option<Vec<u8>> = None;

    for (boot_idx, (seed, elf_bytes)) in boot_elf_bytes.iter().enumerate() {
        let boot_num = boot_idx + 1;
        let bios_path = images_dir.join(format!("qemu_multiseed_bios_{seed}.img"));
        if *seed != 101 {
            let mut spliced = base_bios_bytes.clone();
            spliced[elf_offset..elf_offset + elf_bytes.len()].copy_from_slice(elf_bytes);
            std::fs::write(&bios_path, &spliced).expect("write spliced morphed BIOS image");
        }
        let serial_log = images_dir.join(format!("qemu_multiseed_serial_{seed}.log"));
        let vm = SmokeVm {
            qemu: &qemu,
            bios: &bios_path,
            virtio_disk: &virtio_disk,
            ahci_disk: &ahci_disk,
            nvme_disk: &nvme_disk,
            device_key: &device_key_path,
        };
        eprintln!(
            "smoke[multiseed]: booting morphed kernel #{boot_num} (seed={seed}) against persistent disks..."
        );
        let (log, reached) = vm.boot(&serial_log, halted);
        assert!(
            reached,
            "morphed kernel seed={seed} (boot #{boot_num}) did not reach CUTTLE-TE HALT within 45s!\nSerial log:\n{log}"
        );
        // Assert ALL 130 REQUIRED_BANNERS in order on every cross-seed boot (Claude #13).
        let mut cursor = 0usize;
        for &banner in REQUIRED_BANNERS {
            match log[cursor..].find(banner) {
                Some(rel) => cursor += rel + banner.len(),
                None => panic!(
                    "morphed kernel seed={seed} (boot #{boot_num}) missing or out-of-order required banner {banner:?} at-or-after offset {cursor}!\nSerial log:\n{log}"
                ),
            }
        }
        assert!(
            !log.contains("SHELL resume REJECTED"),
            "morphed kernel seed={seed} (boot #{boot_num}) unexpectedly rejected sealed disk state!\nSerial log:\n{log}"
        );
        // Inspect the persistent AHCI disk sectors for AEAD-encrypted `CTTLAE03` envelope (LBA 1040..=1092),
        // prove zero plaintext leakage on raw disk, then authenticate + decrypt with `device_secret_key.bin`
        // and verify CTTLSHL1 header, WAL record, CTTLFS01, and CTTLSQL1 across boots 1 -> 2 -> 3 (Claude #13).
        let ahci_bytes = std::fs::read(&ahci_disk).expect("read persistent ahci_multiseed_test.img");
        let raw_slots = &ahci_bytes[1040 * 512..1149 * 512];
        assert_eq!(
            &raw_slots[..8],
            b"CTTLAE03",
            "boot #{boot_num} (seed={seed}): missing CTTLAE03 AEAD envelope magic at AHCI LBA 1040"
        );
        for forbidden in [
            b"CTTLSHL1".as_slice(),
            b"CTTLFS01".as_slice(),
            b"CTTLSQL1".as_slice(),
            b"/var/boot.ok".as_slice(),
        ] {
            assert!(
                !raw_slots.windows(forbidden.len()).any(|w| w == forbidden),
                "boot #{boot_num} (seed={seed}): plaintext {:?} leaked onto raw AHCI disk!",
                core::str::from_utf8(forbidden).unwrap_or("bytes")
            );
        }
        let master_key: [u8; 32] = std::fs::read(&device_key_path)
            .expect("read device_secret_key.bin")
            .try_into()
            .expect("32-byte device_secret_key.bin");
        let seal_key =
            target_enterprise::durable_seal::derive_seal_key(&master_key, b"cuttle-ahci-wal-seal-v1");
        let mut img = target_enterprise::state_store::StateImage::zeroed();
        for s in 0..5 {
            img.wal[s].copy_from_slice(&ahci_bytes[(1040 + s) * 512..(1041 + s) * 512]);
        }
        for s in 0..32 {
            img.fs[s].copy_from_slice(&ahci_bytes[(1045 + s) * 512..(1046 + s) * 512]);
        }
        for s in 0..16 {
            img.sql[s].copy_from_slice(&ahci_bytes[(1077 + s) * 512..(1078 + s) * 512]);
        }
        assert!(
            img.decrypt_in_place(&seal_key),
            "boot #{boot_num} (seed={seed}): Poly1305 AEAD decryption of primary slot failed"
        );
        let shl_hdr = &img.wal[0][..];
        let shl_wal = &img.wal[1][..];
        let fs_slice = &img.fs[0][..8];
        let sql_slice = &img.sql[0][..8];
        assert_eq!(
            &shl_hdr[..8],
            b"CTTLSHL1",
            "boot #{boot_num} (seed={seed}): missing decrypted CTTLSHL1 magic at wal[0]"
        );
        assert_eq!(
            fs_slice,
            b"CTTLFS01",
            "boot #{boot_num} (seed={seed}): missing decrypted CTTLFS01 magic at fs[0]"
        );
        assert_eq!(
            sql_slice,
            b"CTTLSQL1",
            "boot #{boot_num} (seed={seed}): missing decrypted CTTLSQL1 magic at sql[0]"
        );
        let saved_boots = u64::from_le_bytes(shl_hdr[8..16].try_into().unwrap());
        assert_eq!(
            saved_boots, boot_num as u64,
            "boot #{boot_num} (seed={seed}): expected CTTLSHL1 saved_boots == {boot_num}, got {saved_boots}"
        );
        assert_eq!(
            &shl_wal[8..28],
            b"F\x0c/var/boot.okready\n",
            "boot #{boot_num} (seed={seed}): missing /var/boot.ok WAL record in decrypted wal[1]"
        );
        if boot_num == 1 {
            assert!(
                log.contains("CONTINUITY genesis"),
                "boot #1 (seed={seed}) expected CONTINUITY genesis!\nSerial log:\n{log}"
            );
            boot_1_shell_sector = Some(shl_wal[..28].to_vec());
            boot_1_fs_magic = Some(fs_slice.to_vec());
            boot_1_sql_magic = Some(sql_slice.to_vec());
        } else {
            assert!(
                log.contains("CONTINUITY resume OK") && log.contains("SHELL resume OK"),
                "cross-seed boot #{boot_num} (seed={seed}) failed to resume sealed state written by prior seed!\nSerial log:\n{log}"
            );
            assert_eq!(
                Some(&shl_wal[..28]),
                boot_1_shell_sector.as_deref(),
                "cross-seed boot #{boot_num} (seed={seed}) did not preserve sealed /var/boot.ok WAL record from boot #1"
            );
            assert_eq!(Some(fs_slice), boot_1_fs_magic.as_deref());
            assert_eq!(Some(sql_slice), boot_1_sql_magic.as_deref());
        }
        let _ = std::fs::remove_file(images_dir.join(format!("qemu_multiseed_{seed}.elf")));
    }

    // 4. Interactive cross-morph operator state continuity (Boot #4 seed=202 -> Boot #5 seed=303):
    //    Write a custom VFS file, CIDR firewall rule, and scheduled cron job on seed=202, sync to AHCI,
    //    then boot morphed seed=303 and prove all three survived across the binary variant swap!
    let bios_202 = images_dir.join("qemu_multiseed_bios_202.img");
    let bios_303 = images_dir.join("qemu_multiseed_bios_303.img");
    let vm_202 = SmokeVm {
        qemu: &qemu,
        bios: &bios_202,
        virtio_disk: &virtio_disk,
        ahci_disk: &ahci_disk,
        nvme_disk: &nvme_disk,
        device_key: &device_key_path,
    };
    let (log_202_rw, synced_202) = vm_202.boot_interactive(
        &[
            "write /var/morph.cfg persisted-across-morph",
            "fw block 198.51.100.0/24",
            "cron add 40 status",
            "sync",
            "halt",
        ],
        |s| s.contains("system halting..."),
    );
    assert!(
        synced_202 && log_202_rw.contains("sync: ok "),
        "interactive seed=202 failed to complete sync!\nSerial log:\n{log_202_rw}"
    );

    let vm_303 = SmokeVm {
        qemu: &qemu,
        bios: &bios_303,
        virtio_disk: &virtio_disk,
        ahci_disk: &ahci_disk,
        nvme_disk: &nvme_disk,
        device_key: &device_key_path,
    };
    let (log_303_ro, verified_303) = vm_303.boot_interactive(
        &["cat /var/morph.cfg", "fw", "cron list", "uname", "halt"],
        |s| s.contains("system halting..."),
    );
    for seed_bios in [
        images_dir.join("qemu_multiseed_bios_101.img"),
        bios_202,
        bios_303,
    ] {
        let _ = std::fs::remove_file(seed_bios);
    }
    for disk in scratch_disks {
        let _ = std::fs::remove_file(disk);
    }
    assert!(
        verified_303,
        "interactive seed=303 did not respond to verification commands!\nSerial log:\n{log_303_ro}"
    );
    assert!(
        log_303_ro.contains("persisted-across-morph"),
        "custom VFS file /var/morph.cfg was wiped on morphed kernel reboot (seed 202 -> 303)!\nSerial log:\n{log_303_ro}"
    );
    assert!(
        log_303_ro.contains("198.51.100.0/24"),
        "custom CIDR firewall rule was wiped on morphed kernel reboot (seed 202 -> 303)!\nSerial log:\n{log_303_ro}"
    );
    assert!(
        log_303_ro.contains("every=40") && log_303_ro.contains("cmd=\"status\""),
        "scheduled cron job was wiped on morphed kernel reboot (seed 202 -> 303)!\nSerial log:\n{log_303_ro}"
    );
    eprintln!(
        "smoke[multiseed]: 10 morphed seeds verified distinct & cross-seed QEMU boots preserved VFS, firewall, cron, and SQL state; MULTI-SEED QEMU TEST PASSED"
    );
}

#[test]
#[ignore = "requires nightly rust-src + factory_builder_pkg + qemu-system-x86_64"]
fn nvme_only_persistence_and_network_flood_resilience_under_qemu() {
    let _guard = QEMU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use std::io::{Read, Write};
    use std::net::{TcpListener, UdpSocket};
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    };

    let Some(qemu) = find_qemu() else {
        panic!("qemu-system-x86_64 not found");
    };
    let root = workspace_root();
    let images_dir = root.join("target").join("cuttle_images");
    std::fs::create_dir_all(&images_dir).expect("create images_dir");

    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = factory_builder::locate_pkg_crate().expect("locate_pkg_crate");
    let elf = factory_builder::build_kernel(&kernel_crate).expect("build_kernel");
    let bios = images_dir.join("qemu_nvme_only_bios.img");
    factory_builder::package_kernel_via_pkg(&pkg_crate, &elf, &bios, None)
        .expect("package_kernel_via_pkg for NVMe-only appliance");

    let nvme_disk = images_dir.join("nvme_only_state_test.img");
    std::fs::write(&nvme_disk, vec![0u8; 1024 * 1024]).expect("init 1 MiB nvme_only_state_test.img");
    let device_key_path = root.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    factory_builder::ensure_device_secret_key(&device_key_path)
        .expect("provision 32-byte CSPRNG device_secret_key.bin");

    // Reserve ephemeral localhost ports for QEMU user-mode networking (`hostfwd`).
    let udp8080 = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP 8080");
        s.local_addr().unwrap().port()
    };
    let udp8081 = {
        let s = UdpSocket::bind("127.0.0.1:0").expect("bind ephemeral UDP 8081");
        s.local_addr().unwrap().port()
    };
    let tcp80 = {
        let l = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral TCP 80");
        l.local_addr().unwrap().port()
    };

    // Start a continuous host UDP flood BEFORE Boot #1 reaches `service_udp_status()`
    // and keep flooding right through `live_os_console_loop()`:
    // - Proves Medium #5: steady traffic + mutating UDP payloads during the boot service
    //   window cannot stall boot (`UDP SVC DOWN window-closed` fires on deadline) and
    //   cannot mutate durable state before boot self-tests finish.
    // - Proves Medium #7: continuous inbound RX traffic suppressing `HLT` neither starves
    //   COM1 interactive console commands nor stalls calibrated TSC ~1 s cron epochs.
    let stop_flood = Arc::new(AtomicBool::new(false));
    let stop_flood_bg = Arc::clone(&stop_flood);
    let flooder = std::thread::spawn(move || {
        let sock = UdpSocket::bind("127.0.0.1:0").expect("bind host UDP flood socket");
        let _ = sock.set_write_timeout(Some(Duration::from_millis(20)));
        let dst_status = format!("127.0.0.1:{udp8080}");
        let dst_ctrl = format!("127.0.0.1:{udp8081}");
        let mut seq = 0u64;
        while !stop_flood_bg.load(Ordering::Relaxed) {
            let _ = sock.send_to(b"status\n", &dst_status);
            let _ = sock.send_to(b"write /var/boot_hijack.txt pwned\n", &dst_status);
            let _ = sock.send_to(b"CMD write /var/boot_hijack.txt pwned\n", &dst_ctrl);
            seq = seq.wrapping_add(1);
            if (seq & 0x3) == 0 {
                std::thread::sleep(Duration::from_millis(1));
            }
        }
    });

    let spawn_nvme_only_qemu = |with_user_net: bool| -> std::process::Child {
        let mut cmd = Command::new(&qemu);
        cmd.args(smoke_accel_args())
            .arg("-cpu")
            .arg(PINNED_QEMU_CPU_MODEL)
            .arg("-smp")
            .arg("4")
            .arg("-fw_cfg")
            .arg(format!(
                "name={},file={}",
                factory_builder::FW_CFG_DEVICE_KEY_NAME,
                device_key_path.display()
            ))
            .arg("-drive")
            .arg(format!("format=raw,file={},if=ide", bios.display()))
            // ZERO AHCI, ZERO VirtIO-blk, ZERO e1000: NVMe is the ONLY persistence disk!
            .arg("-drive")
            .arg(format!(
                "if=none,id=nvme0,format=raw,file={}",
                nvme_disk.display()
            ))
            .arg("-device")
            .arg("nvme,drive=nvme0,serial=CUTTLE-NVME-ONLY");
        if with_user_net {
            cmd.arg("-netdev")
                .arg(format!(
                    "user,id=unet0,hostfwd=udp:127.0.0.1:{udp8080}-:8080,hostfwd=udp:127.0.0.1:{udp8081}-:8081,hostfwd=tcp:127.0.0.1:{tcp80}-:80"
                ))
                .arg("-device")
                .arg("virtio-net-pci,netdev=unet0,disable-legacy=on,disable-modern=off");
        }
        cmd.arg("-serial")
            .arg("stdio")
            .arg("-display")
            .arg("none")
            .arg("-no-reboot")
            .arg("-m")
            .arg("256M")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn NVMe-only QEMU")
    };

    // Boot #1 under continuous UDP flood:
    let mut q1 = spawn_nvme_only_qemu(true);
    let mut out1 = q1.stdout.take().expect("q1 stdout");
    let mut in1 = q1.stdin.take().expect("q1 stdin");
    let buf1 = Arc::new(Mutex::new(String::new()));
    let buf1_bg = Arc::clone(&buf1);
    let r1 = std::thread::spawn(move || {
        let mut chunk = [0u8; 512];
        while let Ok(n) = out1.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut g) = buf1_bg.lock() {
                g.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        }
    });

    let send_console_line = |stdin: &mut std::process::ChildStdin,
                             log_buf: &Arc<Mutex<String>>,
                             line: &str| {
        let prompts_before = log_buf
            .lock()
            .map(|g| g.matches("cuttle> ").count())
            .unwrap_or(0);
        let payload = format!("{line}\n");
        for chunk in payload.as_bytes().chunks(6) {
            let _ = stdin.write_all(chunk);
            let _ = stdin.flush();
            std::thread::sleep(Duration::from_millis(30));
        }
        let is_terminal =
            matches!(line, "halt" | "reboot" | "poweroff") || line.starts_with("__selftest_");
        if !is_terminal {
            let cmd_wait = Instant::now() + Duration::from_secs(12);
            while Instant::now() < cmd_wait {
                let cur = log_buf
                    .lock()
                    .map(|g| g.matches("cuttle> ").count())
                    .unwrap_or(0);
                if cur > prompts_before {
                    break;
                }
                std::thread::sleep(Duration::from_millis(35));
            }
        } else {
            std::thread::sleep(Duration::from_millis(250));
        }
    };

    let deadline1 = Instant::now() + Duration::from_secs(65);
    let mut phase = 0u8;
    let mut cron_armed_at = Instant::now();
    let mut boot1_done = false;
    while Instant::now() < deadline1 {
        std::thread::sleep(Duration::from_millis(120));
        let snap = buf1.lock().map(|g| g.clone()).unwrap_or_default();
        if phase == 0 && snap.contains("cuttle> ") {
            std::thread::sleep(Duration::from_millis(60));
            // Arm a 1-epoch (~1 s) cron job while the UDP packet flood is continuously active!
            send_console_line(&mut in1, &buf1, "cron add 1 status");
            cron_armed_at = Instant::now();
            phase = 1;
        } else if phase == 1 && cron_armed_at.elapsed() >= Duration::from_millis(2400) {
            for cmd in [
                "cron list",
                "cat /var/boot_hijack.txt",
                "write /var/nvme.ok nvme-durable-v1",
                "sql CREATE TABLE nv (id INT, v TEXT)",
                "sql INSERT INTO nv VALUES (7, 'nvme-persisted')",
                "sync",
                "status",
                "halt",
            ] {
                send_console_line(&mut in1, &buf1, cmd);
            }
            phase = 2;
        } else if phase == 2 && snap.contains("system halting...") {
            boot1_done = true;
            break;
        }
    }

    stop_flood.store(true, Ordering::Relaxed);
    let _ = flooder.join();
    drop(in1);
    let _ = q1.kill();
    let _ = q1.wait();
    let _ = r1.join();
    let log1 = buf1
        .lock()
        .map(|g| g.replace("\r\n", "\n"))
        .unwrap_or_default();

    assert!(
        boot1_done,
        "NVMe-only Boot #1 under continuous UDP flood did not reach `system halting...` within 55s!\nSerial log:\n{log1}"
    );
    assert!(
        log1.contains("AHCI_HW skipped (no AHCI HBA attached)")
            && log1.contains("VIRTIO_HW skipped (no virtio-blk attached)")
            && log1.contains("E1000_HW skipped (no e1000 attached)"),
        "NVMe-only Boot #1 did not skip absent AHCI/VirtIO-blk/e1000 cleanly!\nSerial log:\n{log1}"
    );
    assert!(
        log1.contains("UDP SVC DOWN window-closed"),
        "Medium #5 regression: boot service window did not close under steady UDP flood!\nSerial log:\n{log1}"
    );
    assert!(
        log1.contains("error: file not found"),
        "Medium #5 regression: UDP payload mutated state during boot window or unauthenticated flood!\nSerial log:\n{log1}"
    );
    // Verify PCI MSI-X interrupts fired for BOTH NVMe (`blk_irqs > 0`) and modern VirtIO-net (`net_irqs > 0`).
    {
        let irq_line = log1
            .lines()
            .find(|l| l.starts_with("ASYNC_DMA_IRQ OK "))
            .unwrap_or_else(|| panic!("missing ASYNC_DMA_IRQ OK line!\nSerial log:\n{log1}"));
        let parse_kv = |key: &str| -> u64 {
            irq_line
                .split_whitespace()
                .find_map(|tok| tok.strip_prefix(key))
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or_else(|| panic!("malformed {key} in {irq_line:?}"))
        };
        let blk_irqs = parse_kv("blk_irqs=");
        let net_irqs = parse_kv("net_irqs=");
        let ring_done = parse_kv("ring_done=");
        assert!(
            blk_irqs > 0 && net_irqs > 0 && ring_done > 0,
            "expected nonzero NVMe MSI-X blk_irqs ({blk_irqs}) and VirtIO-net MSI-X net_irqs ({net_irqs})!\nLine: {irq_line}"
        );
    }
    // Verify Medium #7: under continuous UDP flood, calibrated TSC epochs advanced cron (`runs=` >= 1)
    // and multi-character console commands + `sync` completed without starvation or dropped bytes.
    {
        let cron_ran = log1.lines().any(|l| {
            l.contains("every=1")
                && l.contains("cmd=\"status\"")
                && l.split_whitespace()
                    .find_map(|t| t.strip_prefix("runs="))
                    .and_then(|v| v.parse::<u64>().ok())
                    .unwrap_or(0)
                    >= 1
        });
        assert!(
            cron_ran,
            "Medium #7 regression: cron job did not advance (`runs >= 1`) under continuous UDP packet flood!\nSerial log:\n{log1}"
        );
        assert!(
            log1.contains("sync: ok "),
            "Medium #7 / NVMe persistence regression: `sync` did not complete on NVMe under UDP flood!\nSerial log:\n{log1}"
        );
    }

    // Host audit of raw `nvme_only_state_test.img`: verify `AB_FORMAT_V3` (`CTTLAE03` + `CTTLAB01`)
    // and zero plaintext leakage on the NVMe namespace!
    let nvme_bytes_1 = std::fs::read(&nvme_disk).expect("read nvme_only_state_test.img after Boot #1");
    assert_eq!(
        &nvme_bytes_1[1149 * 512..1149 * 512 + 8],
        b"CTTLAB01",
        "NVMe-only Boot #1 did not write CTTLAB01 atomic commit sector at LBA 1149"
    );
    assert_eq!(nvme_bytes_1[1149 * 512 + 8], 0x02);
    assert_eq!(nvme_bytes_1[1149 * 512 + 9], 0x03);
    assert_eq!(
        &nvme_bytes_1[1040 * 512..1040 * 512 + 8],
        b"CTTLAE03",
        "NVMe-only Boot #1 did not write AEAD-encrypted CTTLAE03 primary slot at LBA 1040"
    );
    assert!(
        !nvme_bytes_1[1040 * 512..1149 * 512]
            .windows(b"nvme-persisted".len())
            .any(|w| w == b"nvme-persisted"),
        "raw NVMe disk leaked plaintext SQL value!"
    );

    // Boot #2 on the SAME `nvme_only_state_test.img` (still zero AHCI!):
    // Verify `CONTINUITY resume OK`, `SHELL resume OK`, VFS + SQL state survival, AND
    // lock-free emergency NVMe crash dump (`__selftest_ud2_fault` -> `CTTLPENC` at LBA 1536).
    let mut q2 = spawn_nvme_only_qemu(false);
    let mut out2 = q2.stdout.take().expect("q2 stdout");
    let mut in2 = q2.stdin.take().expect("q2 stdin");
    let buf2 = Arc::new(Mutex::new(String::new()));
    let buf2_bg = Arc::clone(&buf2);
    let r2 = std::thread::spawn(move || {
        let mut chunk = [0u8; 512];
        while let Ok(n) = out2.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut g) = buf2_bg.lock() {
                g.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        }
    });

    let deadline2 = Instant::now() + Duration::from_secs(55);
    let mut sent2 = false;
    let mut boot2_done = false;
    while Instant::now() < deadline2 {
        std::thread::sleep(Duration::from_millis(120));
        let snap = buf2.lock().map(|g| g.clone()).unwrap_or_default();
        if !sent2 && snap.contains("cuttle> ") {
            std::thread::sleep(Duration::from_millis(60));
            for cmd in [
                "cat /var/nvme.ok",
                "sql SELECT id, v FROM nv",
                "__selftest_ud2_fault",
            ] {
                send_console_line(&mut in2, &buf2, cmd);
            }
            sent2 = true;
        }
        if sent2
            && snap.contains("CUTTLE-TE PANIC: CPU FAULT: vec=6")
            && snap.contains("CRASH_DUMP emergency slot=1 lba=1536..1568")
        {
            boot2_done = true;
            break;
        }
    }

    drop(in2);
    let _ = q2.kill();
    let _ = q2.wait();
    let _ = r2.join();
    let log2 = buf2.lock().map(|g| g.clone()).unwrap_or_default();
    let nvme_bytes_2 = std::fs::read(&nvme_disk).expect("read nvme_only_state_test.img after Boot #2");

    let _ = std::fs::remove_file(&nvme_disk);
    let _ = std::fs::remove_file(&bios);

    assert!(
        boot2_done,
        "NVMe-only Boot #2 did not complete verification + emergency crash dump within 45s!\nSerial log:\n{log2}"
    );
    assert!(
        log2.contains("AHCI_HW skipped (no AHCI HBA attached)")
            && log2.contains("CONTINUITY resume OK")
            && log2.contains("SHELL resume OK"),
        "NVMe-only Boot #2 did not resume sealed state cleanly without AHCI!\nSerial log:\n{log2}"
    );
    assert!(
        log2.contains("nvme-durable-v1"),
        "NVMe-only Boot #2 lost /var/nvme.ok across reboot!\nSerial log:\n{log2}"
    );
    assert!(
        log2.contains("7|nvme-persisted"),
        "NVMe-only Boot #2 lost SQL row (7, 'nvme-persisted') across reboot!\nSerial log:\n{log2}"
    );
    assert_eq!(
        &nvme_bytes_2[1536 * 512..1536 * 512 + 8],
        b"CTTLPENC",
        "NVMe-only emergency crash dump did not persist encrypted CTTLPENC header at LBA 1536"
    );
    eprintln!(
        "smoke[nvme+flood]: AHCI-less NVMe persistence, MSI-X blk+net IRQs, emergency NVMe crash dump, and Medium #5/#7 UDP flood resilience PASSED"
    );
}

#[test]
#[ignore = "requires nightly rust-src + factory_builder_pkg + qemu-system-x86_64"]
fn enterprise_paged_store_4mib_sql_and_vfs_scale_persists_across_qemu_reboot() {
    let _guard = QEMU_TEST_LOCK.lock().unwrap_or_else(|e| e.into_inner());
    use std::io::{Read, Write};
    use std::sync::{Arc, Mutex};

    let Some(qemu) = find_qemu() else {
        panic!("qemu-system-x86_64 not found");
    };
    let root = workspace_root();
    let images_dir = root.join("target").join("cuttle_images");
    std::fs::create_dir_all(&images_dir).expect("create images_dir");

    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = factory_builder::locate_pkg_crate().expect("locate_pkg_crate");
    let elf = factory_builder::build_kernel(&kernel_crate).expect("build_kernel");
    let bios = images_dir.join("qemu_paged_4mib_bios.img");
    factory_builder::package_kernel_via_pkg(&pkg_crate, &elf, &bios, None)
        .expect("package_kernel_via_pkg for 4 MiB paged store test");

    // 4 MiB (8192-sector) AHCI disk activates `PagedBlockStore` (`LBA 2048..`) automatically!
    let ahci_disk = images_dir.join("paged_4mib_ahci_test.img");
    std::fs::write(&ahci_disk, vec![0u8; 4 * 1024 * 1024]).expect("init 4 MiB paged_4mib_ahci_test.img");
    let virtio_disk = images_dir.join("paged_4mib_virtio_test.img");
    std::fs::write(&virtio_disk, vec![0u8; 1024 * 1024]).expect("init 1 MiB paged_4mib_virtio_test.img");
    let nvme_disk = images_dir.join("paged_4mib_nvme_test.img");
    std::fs::write(&nvme_disk, vec![0u8; 1024 * 1024]).expect("init 1 MiB paged_4mib_nvme_test.img");

    let device_key_path = root.join(factory_builder::DEVICE_SECRET_KEY_FILENAME);
    factory_builder::ensure_device_secret_key(&device_key_path)
        .expect("provision 32-byte CSPRNG device_secret_key.bin");

    let spawn_paged_qemu = || -> std::process::Child {
        Command::new(&qemu)
            .args(smoke_accel_args())
            .arg("-cpu")
            .arg(PINNED_QEMU_CPU_MODEL)
            .arg("-smp")
            .arg("4")
            .arg("-fw_cfg")
            .arg(format!(
                "name={},file={}",
                factory_builder::FW_CFG_DEVICE_KEY_NAME,
                device_key_path.display()
            ))
            .arg("-drive")
            .arg(format!("format=raw,file={},if=ide", bios.display()))
            .arg("-drive")
            .arg(format!("if=none,id=vd0,format=raw,file={}", virtio_disk.display()))
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
            .arg(format!("if=none,id=ahd0,format=raw,file={}", ahci_disk.display()))
            .arg("-device")
            .arg("ahci,id=ahci0")
            .arg("-device")
            .arg("ide-hd,drive=ahd0,bus=ahci0.0")
            .arg("-drive")
            .arg(format!("if=none,id=nvme0,format=raw,file={}", nvme_disk.display()))
            .arg("-device")
            .arg("nvme,drive=nvme0,serial=CUTTLE-NVME-HW")
            .arg("-serial")
            .arg("stdio")
            .arg("-display")
            .arg("none")
            .arg("-no-reboot")
            .arg("-m")
            .arg("256M")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn 4 MiB paged-store QEMU")
    };

    let send_fast_line = |stdin: &mut std::process::ChildStdin,
                          log_buf: &Arc<Mutex<String>>,
                          line: &str| {
        assert!(
            line.len() < 256,
            "interactive console command exceeds SHELL_LINE_MAX (256): len={}",
            line.len()
        );
        let prompts_before = log_buf
            .lock()
            .map(|g| g.matches("cuttle> ").count())
            .unwrap_or(0);
        let payload = format!("{line}\n");
        for chunk in payload.as_bytes().chunks(10) {
            let _ = stdin.write_all(chunk);
            let _ = stdin.flush();
            std::thread::sleep(Duration::from_millis(6));
        }
        let is_terminal = matches!(line, "halt" | "reboot" | "poweroff");
        if !is_terminal {
            let cmd_wait = Instant::now() + Duration::from_secs(15);
            while Instant::now() < cmd_wait {
                let cur = log_buf
                    .lock()
                    .map(|g| g.matches("cuttle> ").count())
                    .unwrap_or(0);
                if cur > prompts_before {
                    break;
                }
                std::thread::sleep(Duration::from_millis(10));
            }
        } else {
            std::thread::sleep(Duration::from_millis(250));
        }
    };

    // Boot #1 on 4 MiB AHCI disk:
    // - Exceed legacy 4-table cap (6 tables total: kv, audit, e, t3, t4, t5)
    // - Exceed legacy 64-row cap by >16x (1,060 rows in `e` + B+Tree INT index)
    // - Exceed legacy 24-inode cap (`5` boot/system + `30` user files = `35/96` inodes) using `write`, `append`, and `cp`
    let mut q1 = spawn_paged_qemu();
    let mut out1 = q1.stdout.take().expect("q1 stdout");
    let mut in1 = q1.stdin.take().expect("q1 stdin");
    let buf1 = Arc::new(Mutex::new(String::new()));
    let buf1_bg = Arc::clone(&buf1);
    let r1 = std::thread::spawn(move || {
        let mut chunk = [0u8; 512];
        while let Ok(n) = out1.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut g) = buf1_bg.lock() {
                g.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        }
    });

    let deadline1 = Instant::now() + Duration::from_secs(120);
    let mut sent1 = false;
    let mut boot1_done = false;
    while Instant::now() < deadline1 {
        std::thread::sleep(Duration::from_millis(100));
        let snap = buf1.lock().map(|g| g.clone()).unwrap_or_default();
        if !sent1 && snap.contains("cuttle> ") {
            std::thread::sleep(Duration::from_millis(50));
            send_fast_line(&mut in1, &buf1, "df");
            send_fast_line(&mut in1, &buf1, "sql CREATE TABLE e (id INT, v TEXT)");
            send_fast_line(&mut in1, &buf1, "sql CREATE INDEX idx_e ON e (id)");
            send_fast_line(&mut in1, &buf1, "sql CREATE TABLE t3 (k INT)");
            send_fast_line(&mut in1, &buf1, "sql CREATE TABLE t4 (k INT)");
            send_fast_line(&mut in1, &buf1, "sql CREATE TABLE t5 (k INT)");
            send_fast_line(&mut in1, &buf1, "sql INSERT INTO t5 VALUES (99)");

            // Insert 1,060 rows via 53 atomic multi-tuple INSERT batches of 20 tuples each (`<= 245` bytes/line).
            for batch in 0..53usize {
                let base = batch * 20;
                let mut cmd = String::from("sql INSERT INTO e VALUES ");
                for off in 0..20usize {
                    let id = base + off;
                    if off > 0 {
                        cmd.push(',');
                    }
                    cmd.push_str(&format!("({id},'x')"));
                }
                send_fast_line(&mut in1, &buf1, &cmd);
            }
            send_fast_line(
                &mut in1,
                &buf1,
                "sql UPDATE e SET v = 'tail-1059' WHERE id = 1059",
            );

            // Create 30 additional user files (`f00..f28` + `copied.txt`; total user files = 31 including `/var/boot.ok`, total inodes = 35/96).
            for f in 0..29usize {
                send_fast_line(
                    &mut in1,
                    &buf1,
                    &format!("write /var/f{f:02}.txt vfs-val-{f:02}"),
                );
            }
            send_fast_line(&mut in1, &buf1, "append /var/f28.txt appended-line");
            send_fast_line(&mut in1, &buf1, "cp /var/f28.txt /var/copied.txt");
            send_fast_line(&mut in1, &buf1, "sql SELECT COUNT(*) FROM e");
            send_fast_line(&mut in1, &buf1, "df");
            send_fast_line(&mut in1, &buf1, "sync");
            send_fast_line(&mut in1, &buf1, "halt");
            sent1 = true;
        }
        if sent1 && snap.contains("system halting...") {
            boot1_done = true;
            break;
        }
    }

    drop(in1);
    let _ = q1.kill();
    let _ = q1.wait();
    let _ = r1.join();
    let log1 = buf1
        .lock()
        .map(|g| g.replace("\r\n", "\n"))
        .unwrap_or_default();

    assert!(
        boot1_done,
        "4 MiB paged-store Boot #1 did not complete within 120s!\nSerial log tail:\n{}",
        &log1[log1.len().saturating_sub(2000)..]
    );
    assert!(
        log1.contains("AHCI_HW identify OK sectors=8192")
            && log1.contains("fs: magic=CTTLPGS1 inodes=37/96 ")
            && log1.contains("count\n1060"),
        "4 MiB Boot #1 did not reach 8192 sectors, 37/96 inodes, and 1060 SQL rows!\nSerial log tail:\n{}",
        &log1[log1.len().saturating_sub(2000)..]
    );

    // Host inspection of raw 4 MiB AHCI disk: verify `CTTLPGS1` superblock at LBA 2048 or 2049
    // and zero plaintext leakage of `'tail-1059'` or `'appended-line'` in the encrypted page pool (`LBA 2080..`).
    let ahci_bytes_1 = std::fs::read(&ahci_disk).expect("read 4 MiB ahci_disk after Boot #1");
    let sb_a_ok = &ahci_bytes_1[2048 * 512..2048 * 512 + 8] == b"CTTLPGS1";
    let sb_b_ok = &ahci_bytes_1[2049 * 512..2049 * 512 + 8] == b"CTTLPGS1";
    assert!(
        sb_a_ok || sb_b_ok,
        "4 MiB AHCI disk missing CTTLPGS1 superblock at LBA 2048/2049"
    );
    for secret in [&b"tail-1059"[..], &b"appended-line"[..]] {
        assert!(
            !ahci_bytes_1[2080 * 512..]
                .windows(secret.len())
                .any(|w| w == secret),
            "raw 4 MiB AHCI page pool leaked plaintext {:?}",
            core::str::from_utf8(secret)
        );
    }

    // Boot #2 on the SAME 4 MiB AHCI disk: verify 100% persistence across physical VM reboot!
    let mut q2 = spawn_paged_qemu();
    let mut out2 = q2.stdout.take().expect("q2 stdout");
    let mut in2 = q2.stdin.take().expect("q2 stdin");
    let buf2 = Arc::new(Mutex::new(String::new()));
    let buf2_bg = Arc::clone(&buf2);
    let r2 = std::thread::spawn(move || {
        let mut chunk = [0u8; 512];
        while let Ok(n) = out2.read(&mut chunk) {
            if n == 0 {
                break;
            }
            if let Ok(mut g) = buf2_bg.lock() {
                g.push_str(&String::from_utf8_lossy(&chunk[..n]));
            }
        }
    });

    let deadline2 = Instant::now() + Duration::from_secs(60);
    let mut sent2 = false;
    let mut boot2_done = false;
    while Instant::now() < deadline2 {
        std::thread::sleep(Duration::from_millis(100));
        let snap = buf2.lock().map(|g| g.clone()).unwrap_or_default();
        if !sent2 && snap.contains("cuttle> ") {
            std::thread::sleep(Duration::from_millis(50));
            for cmd in [
                "df",
                "sql SELECT COUNT(*) FROM e",
                "sql SELECT v FROM e WHERE id >= 1059",
                "sql SELECT k FROM t5",
                "cat /var/copied.txt",
                "halt",
            ] {
                send_fast_line(&mut in2, &buf2, cmd);
            }
            sent2 = true;
        }
        if sent2 && snap.contains("system halting...") {
            boot2_done = true;
            break;
        }
    }

    drop(in2);
    let _ = q2.kill();
    let _ = q2.wait();
    let _ = r2.join();
    let log2 = buf2
        .lock()
        .map(|g| g.replace("\r\n", "\n"))
        .unwrap_or_default();

    for f in [&ahci_disk, &virtio_disk, &nvme_disk, &bios] {
        let _ = std::fs::remove_file(f);
    }

    assert!(
        boot2_done,
        "4 MiB paged-store Boot #2 did not complete within 60s!\nSerial log:\n{log2}"
    );
    assert!(
        log2.contains("CONTINUITY resume OK") && log2.contains("SHELL resume OK"),
        "4 MiB Boot #2 did not resume sealed paged state cleanly!\nSerial log:\n{log2}"
    );
    assert!(
        log2.contains("fs: magic=CTTLPGS1 inodes=35/96 pool_bytes=812/262144 tx_lsn=92")
            && log2.contains("count\n1060")
            && log2.contains("tail-1059")
            && log2.contains("99")
            && log2.contains("vfs-val-28\nappended-line"),
        "4 MiB Boot #2 did not preserve 1060 SQL rows, 6 tables, and 31 user VFS files (35/96 inodes) across reboot!\nSerial log:\n{log2}"
    );
    eprintln!(
        "smoke[paged_4mib]: 4 MiB PagedBlockStore (6 SQL tables, 1060 rows, B+Tree range query, 37/96 VFS inodes, append+cp) persisted across QEMU reboot PASSED"
    );
}

#[test]
fn workspace_root_has_kernel_and_pkg_dirs() {
    // Cheap non-ignored test: at least confirm the directory layout is
    // intact. Useful so we catch a missing kernel crate even when
    // QEMU itself is unavailable.
    let root = workspace_root();
    let _ = Path::new(&root);
    for name in ["target_enterprise_kernel", "factory_builder_pkg"] {
        let p = root.join(name);
        if !p.exists() {
            // Don't fail — these are deliberately optional / on-disk
            // artifacts that may be cleaned. But emit a hint so
            // operators investigating the smoke skip know why.
            eprintln!("note: {} missing at {}", name, p.display());
        }
    }
}

#[test]
fn required_banners_include_https_up_with_rdrand_and_provisioned() {
    assert!(REQUIRED_BANNERS.contains(
        &"HTTPS UP port=443 tls13=rustls entropy=rdrand provisioned=1 cert_sha256="
    ));
}

#[test]
fn find_qemu_searches_path_portably() {
    let dir = std::env::temp_dir().join(format!(
        "cuttle_find_qemu_test_{}",
        std::process::id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Create a portable Unix-style `qemu-system-x86_64` (no `.exe` extension)
    // and verify `find_qemu_in_path_var` locates it via `std::env::split_paths`.
    let fake_qemu = dir.join("qemu-system-x86_64");
    std::fs::write(&fake_qemu, b"#!/bin/sh\n").unwrap();
    let path_joined = std::env::join_paths([&dir]).unwrap();
    let found = find_qemu_in_path_var(Some(&path_joined))
        .expect("find_qemu_in_path_var must locate qemu-system-x86_64 on PATH without `where`");
    assert_eq!(found, fake_qemu);
    let _ = std::fs::remove_dir_all(&dir);
}
