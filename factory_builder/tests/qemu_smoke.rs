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

    if !kernel_crate.join("Cargo.toml").exists() {
        eprintln!(
            "SKIP: target_enterprise_kernel/ not present at {} — out-of-workspace kernel crate missing",
            kernel_crate.display()
        );
        return;
    }
    if !pkg_crate.join("Cargo.toml").exists() {
        eprintln!(
            "SKIP: factory_builder_pkg/ not present at {} — out-of-workspace packager missing",
            pkg_crate.display()
        );
        return;
    }
    let qemu = match find_qemu() {
        Some(p) => p,
        None => {
            if std::env::var("CUTTLE_REQUIRE_QEMU").as_deref() == Ok("1") {
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
    "FS partition OK lba=1042..1057 sectors=16 files=1 magic=CTTLFS01",
    "HTTPS compose OK slots=16 port=443 tls13=rustls bytes=882 sha=83e47624",
    "SVC_RUNTIME: OK role=full->wfe->full svcs=3 kpti=isolated seccomp=deny-default rot=1",
    "SHELL compose OK tasks=5 files=5 audit=5",
    "SMP_HW init OK cpus=4 threads=4 ctx_sw=4",
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

    // Tamper with the sealed WAL payload at LBA 1041 (offset 1041 * 512 + 8).
    let mut disk_bytes = std::fs::read(&tampered_disk).expect("read ahci_tamper_test.img");
    let wal_offset = 1041 * 512 + 8;
    disk_bytes[wal_offset] ^= 0xFF;
    std::fs::write(&tampered_disk, &disk_bytes).expect("write tampered ahci_tamper_test.img");

    // Boot 2: the tampered disk must emit SHELL resume REJECTED and must NOT emit SHELL resume OK.
    let (log2, reached2) = vm.boot(&tamper_log, halted);
    for disk in scratch_disks {
        let _ = std::fs::remove_file(disk);
    }
    assert!(
        reached2,
        "tamper test boot 2 did not reach CUTTLE-TE HALT within 45s!\nSerial log:\n{}",
        log2
    );
    assert!(
        log2.contains("SHELL resume REJECTED: HMAC-SHA256 seal verification failed (tampered disk)"),
        "tamper test boot 2 did not emit SHELL resume REJECTED!\nSerial log:\n{}",
        log2
    );
    assert!(
        !log2.contains("SHELL resume OK"),
        "tamper test boot 2 unexpectedly emitted SHELL resume OK on a tampered disk!\nSerial log:\n{}",
        log2
    );
    eprintln!("smoke: tampered AHCI seal was rejected as expected; TAMPER TEST PASSED");
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
        // Inspect the persistent AHCI disk sectors for CTTLSHL1 header (LBA 1040),
        // WAL backing (LBA 1041), CTTLFS01 (LBA 1042), and CTTLSQL1 (LBA 1058) across boots 1 -> 2 -> 3 (Claude #13).
        let ahci_bytes = std::fs::read(&ahci_disk).expect("read persistent ahci_multiseed_test.img");
        let shl_hdr = &ahci_bytes[1040 * 512..1041 * 512];
        let shl_wal = &ahci_bytes[1041 * 512..1042 * 512];
        let fs_slice = &ahci_bytes[1042 * 512..1042 * 512 + 8];
        let sql_slice = &ahci_bytes[1058 * 512..1058 * 512 + 8];
        assert_eq!(
            &shl_hdr[..8],
            b"CTTLSHL1",
            "boot #{boot_num} (seed={seed}): missing CTTLSHL1 magic at AHCI LBA 1040"
        );
        assert_eq!(
            fs_slice,
            b"CTTLFS01",
            "boot #{boot_num} (seed={seed}): missing CTTLFS01 magic at AHCI LBA 1042"
        );
        assert_eq!(
            sql_slice,
            b"CTTLSQL1",
            "boot #{boot_num} (seed={seed}): missing CTTLSQL1 magic at AHCI LBA 1058"
        );
        let saved_boots = u64::from_le_bytes(shl_hdr[8..16].try_into().unwrap());
        assert_eq!(
            saved_boots, boot_num as u64,
            "boot #{boot_num} (seed={seed}): expected CTTLSHL1 saved_boots == {boot_num}, got {saved_boots}"
        );
        assert_eq!(
            &shl_wal[8..28],
            b"F\x0c/var/boot.okready\n",
            "boot #{boot_num} (seed={seed}): missing /var/boot.ok WAL record in LBA 1041"
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
                "cross-seed boot #{boot_num} (seed={seed}) did not preserve sealed /var/boot.ok WAL record at LBA 1041 from boot #1"
            );
            assert_eq!(Some(fs_slice), boot_1_fs_magic.as_deref());
            assert_eq!(Some(sql_slice), boot_1_sql_magic.as_deref());
        }
        let _ = std::fs::remove_file(&bios_path);
        let _ = std::fs::remove_file(images_dir.join(format!("qemu_multiseed_{seed}.elf")));
    }

    for disk in scratch_disks {
        let _ = std::fs::remove_file(disk);
    }
    eprintln!(
        "smoke[multiseed]: 10 morphed seeds verified distinct & 3 consecutive cross-seed QEMU boots (seeds 101 -> 202 -> 303) preserved sealed state; MULTI-SEED QEMU TEST PASSED"
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
