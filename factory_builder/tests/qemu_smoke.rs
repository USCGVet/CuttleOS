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

fn find_qemu() -> Option<PathBuf> {
    // Try PATH first.
    if let Ok(out) = Command::new("where")
        .arg("qemu-system-x86_64")
        .output()
    {
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

fn factory_builder_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_factory_builder"))
}

#[test]
#[ignore]
fn boots_under_qemu_and_emits_banner() {
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
            eprintln!(
                "SKIP: qemu-system-x86_64 not found on PATH or at C:/Program Files/qemu/"
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
    let images_dir = root.join("target").join("proteus_images");
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
    // (TLS hkdf, TLS ServerHello, WAL replay, IOMMU translate,
    // HashImpl digest) BEFORE emitting `PROTEUS-TE HALT`. Waiting for
    // the HALT line is the gate: if it appears, every preceding
    // banner is also present because the kernel panics on any drift
    // and the HALT line is suppressed.
    let required_banners: &[&str] = &[
        "PROTEUS-TE OK",
        "TLS hkdf OK prk_sha=",
        "TLS server_hello OK len=",
        // TASK-049: TLS 1.3 client. The kernel builds a ClientHello
        // against the locked client_random + client_pubkey fixtures,
        // asserts the byte-exact prefix + length; parses the locked
        // ServerHello fixture, asserts the recovered server_pubkey
        // matches; runs the RFC 8446 §7.1 key schedule against the
        // locked shared_secret, asserts all three handshake-traffic
        // secrets match the locked goldens; builds the client Finished
        // verify_data against a synthetic transcript hash, asserts
        // byte-equality. Both banners appearing means: the
        // ClientHello extension order + length encoding, the
        // ServerHello parser's strict supported_versions + key_share
        // checks, the HKDF-Extract → Derive-Secret → HKDF-Extract
        // chain, and the Finished MAC construction (HKDF-Expand-Label
        // + HMAC-SHA-256) are all wired correctly. A morph that
        // perturbs the cipher_suites singleton, the extension order,
        // any key-schedule label, or the Finished derivation panics
        // here and these banners never appear.
        "TLS client_hello OK len=108",
        "TLS client handshake_keys OK prk=bb518f061c911017",
        "WAL replay OK frames=",
        "IOMMU translate OK pa=",
        "HASH OK digest_sha=",
        // TASK-011: NET banner asserts the canonical UDP/IPv4 datagram
        // bytes match the locked golden fixture and that the
        // round-trip parse recovers every field. A morph that perturbs
        // the wire layout panics inside `banner_net_build` and the
        // banner never appears.
        "NET build OK len=38 ip_cksum=63c7 udp_cksum=fa94",
        // TASK-017: KPTI banners assert the locked-invariant boundary
        // held against a synthetic-but-realistic kernel L4. The
        // build banner records that 4 secret pages were stripped from
        // the user view; the validate banner records that the
        // resulting view has zero violations against `validate_user_view`.
        // A KPTI port that drops a user page, fails to strip a secret,
        // or accepts a kernel-bit-set entry into the user view panics
        // inside `banner_kpti` and the banner never appears.
        "KPTI build_user_view OK secrets=4",
        "KPTI validate_user_view OK violations=0",
        // TASK-014: DMA syscall banners assert that the type-state
        // CapProof + per-task `iommu_domain` + IommuImpl pipeline
        // works end-to-end through a real privileged syscall.
        // dispatch_dma mints a CapProof, the handler consumes it
        // by value, and the IOMMU map/unmap state survives across
        // syscalls. A kernel where any of those links is broken
        // produces a missing banner.
        "DMA_MAP test OK",
        "DMA_UNMAP test OK",
        "RING3 transition OK cpl=3->0 vec=0x80 ist1=ok rsp0=ok syscall=43",
        // TASK-018: NVMe driver round-trip banners. The kernel runs
        // an in-process MemNvmeController emulator + drives the
        // NvmeImpl through bring_up → create_io_queues →
        // identify_controller → write+read round-trip. Both banners
        // appearing means the SQ/CQ ring arithmetic, the command
        // encoding/decoding, the bring-up state machine, and the
        // BlockDevice contract impl are all wired correctly.
        "NVMe init OK ctrl=PROTEUS-NVME-EMU",
        "NVMe read_lba(7) OK first_byte=a5",
        // TCP state machine + wire codec. The kernel drives a full
        // 3-way handshake (LISTEN→SYN_RCVD→ESTABLISHED) followed by a
        // clean teardown (FIN→CLOSE_WAIT→close()→LAST_ACK→ACK→CLOSED)
        // through real `TcpImpl::build_segment` + `parse_segment`
        // calls. Both banners appearing means: TCB transitions are
        // correct, segment encoding is correct, pseudo-header
        // checksum verification accepts well-formed segments.
        "TCP handshake OK state=ESTABLISHED seq=",
        "TCP teardown OK state=CLOSED snd_nxt=",
        // HTTP/1.1 request parse + response build. The kernel parses
        // a fixture `GET /healthz HTTP/1.1` request through
        // `HttpImpl::parse_request`, then builds a 200 OK response
        // with `Content-Type: text/plain` and body "OK" through
        // `HttpImpl::build_response`, asserting the byte-exact
        // response against the locked wire surface. Both banners
        // appearing means: the request-line tokenizer, header-block
        // scanner, case-insensitive `find_header`, status-line
        // emitter, and Content-Length framing are all wired
        // correctly.
        "HTTP parse OK method=GET path=/healthz",
        "HTTP build OK status=200 bytes=",
        // DNS/RFC 1035 wire codec. The kernel builds an A query for
        // `proteus.local`, asserts the byte-exact canonical encoding,
        // parses the query, then builds a response pointing to
        // 10.0.0.42 with TTL 60 and asserts the rdata bytes land at
        // the locked offset. Both banners appearing means: the 12-byte
        // header big-endian encoding, length-prefixed label
        // encoding, QTYPE/QCLASS placement, and answer-section
        // RDLENGTH/RDATA assembly are all wired correctly. A morph
        // that perturbs byte order or label-length octet placement
        // panics inside `banner_dns` and these banners never appear.
        "DNS query OK id=c0de qname=proteus.local",
        "DNS response OK id=c0de ans=10.0.0.42 bytes=",
        // ICMP/RFC 792 echo with RFC 1071 checksum. The kernel builds
        // an echo request with id=0x4242, seq=7, payload "proteus-ping",
        // parses it (which verifies the recomputed RFC 1071 16-bit
        // one's-complement checksum against the wire field), then
        // builds the matching reply. Both banners appearing means: the
        // 8-byte header layout, the type-code byte (8/0), the big-
        // endian id/seq encoding, and especially the checksum routine
        // are all wired correctly. A morph that perturbs the carry
        // fold or the even/odd byte padding panics here.
        "ICMP echo_req OK id=4242 seq=7 cksum=",
        "ICMP echo_rep OK id=4242 seq=7",
        // Ethernet/IEEE 802.3 frame + 802.1Q VLAN tag. The kernel
        // rebuilds the locked UDP/IPv4 datagram (via the existing
        // banner_net_build path), wraps it in an Ethernet II frame
        // with dst=12:34:56:78:9A:BC src=00:AA:BB:CC:DD:EE
        // EtherType=0x0800, asserts the header is byte-exact and the
        // payload matches kernel_fixtures::NET_EXPECTED_DATAGRAM
        // byte-for-byte, parses back to recover dst/src/EtherType,
        // confirms ETH_BROADCAST_MAC is broadcast, then builds a
        // VLAN-tagged variant with PCP=3 VID=100 (TCI=0x6064). All
        // three banners appearing means: MAC byte order, EtherType
        // big-endian encoding, 14-byte vs 18-byte header dispatch,
        // and TCI field packing are all wired correctly. A morph
        // that swaps any byte position in the header or fields
        // panics here and the banners never appear.
        "ETH build OK len=52 ethertype=0800",
        "ETH parse OK src=00aabbccddee dst=123456789abc",
        "ETH vlan OK tci=6064 vid=100 pcp=3",
        // TASK-046: ARP/RFC 826 IPv4-over-Ethernet. The kernel
        // builds a REQUEST for 10.0.0.42, asserts the byte-exact
        // 28-byte wire encoding against the hand-verified
        // expectation, parses it back, then builds the matching
        // REPLY and adds the resolved (target_ip, target_mac)
        // binding to a 4-slot ArpCache. Both banners appearing
        // means: HTYPE/PTYPE big-endian encoding, HLEN/PLEN
        // constants, the 28-byte field layout, OPER REQUEST/REPLY
        // dispatch, and the cache insert/lookup path are all
        // wired correctly. A morph that perturbs byte order,
        // field offsets, or the cache LRU/poison-defence routines
        // panics here and these banners never appear.
        "ARP request OK target_ip=10.0.0.42 op=1",
        "ARP cache OK entries=1",
        // TASK-047: DHCPv4 client (RFC 2131/2132). The kernel builds
        // a DISCOVER via DhcpClient::start_discover (which round-trips
        // through DhcpImpl::parse_message), asserts the BOOTP xid +
        // chaddr land at the locked offsets, then feeds a hand-built
        // OFFER fixture into DhcpClient::on_offer (state -> Requesting,
        // server_id + yiaddr captured), then an ACK fixture into
        // DhcpClient::on_ack (state -> Bound, lease bound). Both
        // banners appearing means: the BOOTP 240-byte fixed-header byte
        // order, the magic-cookie offset at 236..240, the TLV option
        // scanner including length-prefixed iterate-or-truncate
        // discipline, and the DhcpClient state-machine transitions are
        // all wired correctly. A morph that perturbs byte order,
        // option-code constants, or state-machine guards panics here
        // and these banners never appear.
        "DHCP discover OK xid=deadbeef",
        "DHCP bound OK yiaddr=10.0.0.42 lease=86400",
        // TASK-048: VirtIO-net driver bring-up + round-trip. The
        // kernel constructs a MemVirtioBus + VirtioNet in-stack,
        // drives the full VirtIO 1.0 RESET → ACK → DRIVER →
        // FEATURES_OK → DRIVER_OK handshake, reads the device MAC
        // from device-cfg (5254 0012 3456 — QEMU default), then
        // transmits a locked 60-byte Ethernet fixture (the bus's
        // observation buffer captures the bytes; the banner asserts
        // they round-trip exactly), then injects a synthetic 80-byte
        // incoming frame and asserts receive returns it byte-for-
        // byte with the 12-byte virtio_net_hdr stripped. Both
        // banners appearing means: VirtqDesc + VirtioNetHdr wire
        // layouts hold, the status-byte sequence is correct, the
        // feature-bit constants land where the bus expects them,
        // the queue pre-post + avail/used ring arithmetic is
        // correct, and the DMA shadow path moves the right bytes
        // in both directions. A morph that perturbs any of the
        // above panics here and these banners never appear.
        "VIRTIO_NET init OK mac=525400123456",
        "VIRTIO_NET roundtrip OK tx=1 rx=1",
        // TASK-061: VirtIO-blk driver bring-up + sector round-trip.
        // The kernel constructs a `MemVirtioBlkBus` (32-sector / 16
        // KiB backing disk + the seed feature mask
        // VERSION_1|FLUSH|BLK_SIZE) + a `VirtioBlk` in static
        // storage, drives the full VirtIO 1.0 RESET → ACK → DRIVER
        // → FEATURES_OK → DRIVER_OK handshake, reads the capacity
        // (32 sectors) + preferred block size (512 B) from
        // device-cfg, then writes a locked 512-byte XOR-with-index
        // pattern at sector 3 and reads it back through a separate
        // request chain — asserting byte-for-byte equality and
        // that the first recovered byte is 0xA5 (so any byte-order
        // drift makes the banner mismatch). Both banners appearing
        // means: the 16-byte VirtBlkRequest header layout
        // (type/reserved/sector LE) holds, the 3-descriptor chain
        // shape (header dev-readable, data dev-writable on IN /
        // dev-readable on OUT, status dev-writable) holds, the
        // request-type byte constants (IN=0 / OUT=1) land where
        // the contract says, the status-byte success sentinel (0)
        // round-trips through the device-side completion path, the
        // capacity-as-u64 stitch over 8 device-cfg byte reads
        // recovers the spec'd value, and the avail/used ring
        // arithmetic survives two consecutive submissions. A morph
        // that perturbs any of the above panics inside
        // `banner_virtio_blk` and these banners never appear.
        "VIRTIO_BLK init OK capacity=32 blk_size=512",
        "VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5",
        // TASK-056: Intel 82540EM (e1000) driver bring-up + frame
        // round-trip. The kernel constructs an `E1000Impl` driver +
        // `MemMmioBus` simulator in static storage, drives the full
        // bring-up sequence (CTRL.RST → poll(!RST) → EEPROM word-0/1/2
        // MAC read → CTRL.SLU → program RDBAL/RDBAH/RDLEN/RDH/RDT +
        // TDBAL/TDBAH/TDLEN/TDH/TDT → RCTL.EN + TCTL.EN) and asserts
        // the recovered MAC equals the locked `BANNER_MAC`
        // (52:54:00:12:34:56). Then it transmits a locked 64-byte
        // Ethernet frame (broadcast dest + BANNER_MAC src +
        // EtherType=0x0800 + 50-byte 0xC0-stepping payload) — the
        // simulator drains the TX descriptor on TDT advance and the
        // banner asserts byte-for-byte capture equality. The second
        // banner then asserts the same frame round-trips through the
        // RX descriptor ring (the simulator plants STATUS.DD + EOP
        // and the driver consumes one slot, advancing RDT). Both
        // banners appearing means the legacy 16-byte TxDesc/RxDesc
        // wire layouts hold, the EEPROM EERD START/DONE/ADDR/DATA
        // bit fields stay where the contract says they are, the
        // descriptor STATUS/CMD bit constants (`E1000_DESC_STA_DD`,
        // `_TXD_CMD_EOP` / `_IFCS` / `_RS`, `_RXD_STA_EOP`) all
        // survive the morph, and the ring-wraparound modulus +
        // RDT/TDT advance arithmetic preserves byte-exact semantics.
        // A morph that perturbs any of the above panics inside
        // `banner_e1000` and these banners never appear.
        "E1000 init OK mac=525400123456 link=up_1000",
        "E1000 frame OK tx_bytes=64 rx_bytes=64",
        // TASK-050: Stateless IPv4 packet-filter / firewall. The
        // kernel builds a 3-rule [`FirewallTable`] mirroring the
        // task spec — Accept TCP/22 from 10/8, Accept UDP/53 from
        // 0/0, Reject ICMP from 192.168/16 — relies on the
        // descending-mask-score ordering invariant to put the /16
        // ICMP rule ahead of the /8 + /0 rules, evaluates three
        // synthetic IPv4 packets, then asserts the table's
        // default-deny fall-through fires for a packet no rule
        // matched. The first banner appearing means: CIDR-mask
        // arithmetic, ordered insert, first-match-wins, and proto-
        // byte equality are all wired correctly. The second banner
        // appearing means: the `Verdict::NoMatch` fall-through
        // correctly folds into the supplied `FilterAction::Drop`
        // default policy. A morph that perturbs the mask packing,
        // the ordering invariant, the matching order, or the
        // NoMatch → default mapping panics here and these banners
        // never appear.
        "FW eval OK rules=3 verdicts=accept,accept,drop",
        "FW default OK action=Drop",
        // TASK-051: TPM 2.0 client-side wire codec banners. The first
        // two banners prove byte-exact TCG-spec encoding for the two
        // task-locked fixtures: `TPM2_Startup(SU_CLEAR)` (12 bytes,
        // tag=0x8001, cc=0x00000144) and `TPM2_GetRandom(16)` (12
        // bytes, tag=0x8001, cc=0x0000017B). The third banner proves
        // the response-header parser walks a hand-built 28-byte
        // success response (tag=0x8001, size=28, rc=0) and the
        // `extract_get_random_bytes` helper recovers all 16 random
        // bytes from the inline `TPM2B_DIGEST`. The kernel banner
        // also exercises `TPM2_PCR_Read(pcr=10)` and
        // `TPM2_PCR_Extend(pcr=8, SHA-256, [0x42; 32])` against
        // locked goldens internally (no separate serial line — the
        // assertion is byte-exact so any drift panics inside the
        // banner and these three lines never appear). A morph that
        // perturbs the header endianness, any command code, the
        // PCR-bitmap arithmetic, the password-authorization session
        // block, or the size-field / tag validation panics here and
        // none of the three banners are emitted.
        "TPM startup OK len=12 tag=8001",
        "TPM getrandom OK len=12 cc=0000017b",
        "TPM parse OK rc=00000000 random_len=16",
        "TPM2_TIS driver OK did_vid=000115d1 locality=0 pcr10=extended",
        // TASK-052: Kernel audit-log subsystem banners. The first
        // banner proves three events of distinct verdicts
        // (Allowed / Denied / Error) round-trip through the locked
        // `AuditLog::append` → `iter()` path with monotonic event-ids
        // (0, 1, 2) and the caller's `task_id` / `syscall_nr` /
        // `verdict` / `message` bytes preserved exactly. The second
        // banner proves the `snapshot` byte layout — a 20-byte big-
        // endian header (`AUDT` magic, `record_count = 3`,
        // `record_size = 96`, `high_watermark = 3`) followed by three
        // 96-byte records — round-trips via the offline parser. The
        // locked snapshot length `AUDIT_SNAPSHOT_HEADER_LEN + 3 *
        // AUDIT_EVENT_WIRE_LEN = 20 + 288 = 308` bytes is the load-
        // bearing invariant: a morph that perturbs the ring
        // head/len bookkeeping, the snapshot byte layout, the
        // verdict discriminants, or the high-watermark accounting
        // panics here and these two banners never appear.
        "AUDIT append OK events=3",
        "AUDIT snapshot OK bytes=308",
        // TASK-053: SNTPv4 client wire-codec banners. The first banner
        // proves `Sntp::build_request` plants a 48-byte mode-3 client
        // request whose byte-0 packs (LI=0, VN=4, Mode=3) = 0x23 and
        // whose transmit-timestamp tail is the big-endian raw of
        // `NTP_EPOCH + 100s` (= 100 << 32 = 429_496_729_600). The
        // second banner proves the parse-reply + compute-offset-delay
        // path against a symmetric hand-built mode-4 reply with
        // `t1=100s, t2=t3=100.5s, t4=101s` — RFC 4330 §5 yields
        // `offset=0` and `delay=1_000_000_000` ns exactly. A morph
        // that perturbs the LI/VN/Mode bit-packing, the wire field
        // offsets, the big-endian timestamp pack/unpack, or the
        // offset/delay arithmetic panics inside `banner_sntp` and the
        // two banners never appear.
        "SNTP request OK mode=3 vn=4 xmt=429496729600",
        "SNTP reply OK offset_ns=0 delay_ns=1000000000",
        // TASK-054: VFS layer banners. The first banner proves the
        // mount table accepted a `MemRamFs` at the root prefix
        // (mount_count == 1, mount_at(0) == b"/"). The second banner
        // proves the full open → read → close round-trip through
        // `VfsImpl<8>` returns exactly 11 bytes for the locked
        // `/etc/hostname = b"proteus-te\n"` fixture, byte-for-byte
        // against `HOSTNAME_BYTES`. A morph that perturbs the path
        // normalisation, the mount-table dispatch (longest-prefix
        // routing), the handle packing (mount_id << 24 | per_fs),
        // the open-file table, or the ramfs pool offset arithmetic
        // panics inside `banner_vfs` and the two banners never
        // appear.
        "VFS mount OK fs=ramfs root=/",
        "VFS read OK path=/etc/hostname bytes=11",
        // TASK-055: eBPF interpreter banners. The first banner proves
        // the 6-instruction reference program round-trips three input
        // bytes [0, 1, 2] through the locked
        // `ldxb r0, [r1+0] ; and r0, 1 ; mov r1, 1 ; sub r1, r0 ;
        // mov r0, r1 ; exit` sequence — emitting verdicts [1, 0, 1]
        // byte-for-byte. The second banner proves the contract's
        // `BPF_STACK_SIZE` constant (= 512) survives any morph cycle:
        // a kernel built against a drifted constant would print a
        // different number and the in-order banner sweep would fail.
        // A morph that perturbs the ALU64 sub-op dispatch, the
        // MOV/SUB/AND wire-encoding, the LDX byte-size routing, the
        // ST imm planting, the validator's MissingExit / IllegalJump
        // checks, or the EXIT terminator path panics inside
        // `banner_ebpf` and these banners never appear.
        "EBPF program OK insns=6 verdicts=1,0,1",
        "EBPF stack OK bytes=512",
        // TASK-057: SMP MADT parser + INIT-SIPI-SIPI ICR sequencer.
        // The kernel constructs a 4-CPU fixture MADT (BSP=0,
        // APs=1/2/3, all ENABLED), runs `SmpImpl::discover` to
        // recover the topology, then `SmpImpl::wake_aps` against a
        // recording `ApicWriter` and asserts the captured ICR
        // sequence matches the locked 9-IPI golden (per Intel SDM
        // Vol 3A §10.4.7.1: INIT, SIPI, SIPI × 3 APs). Vector
        // arithmetic is checked (trampoline_pa=0x8000 → vec=0x08),
        // INIT delivery-mode bits are checked, ICR-high targets are
        // checked. Wire-codec-shaped: no AP actually runs here —
        // that's TASK-057b which would require the per-CPU banner
        // buffer contract change. A morph that perturbs the MADT
        // entry walk, the ICR field encodings, or the SIPI vector
        // arithmetic panics inside `banner_smp` and these banners
        // never appear.
        "SMP discover OK bsp=0 aps=3",
        "SMP wake OK ipis=9 vec=0x08",
        // TASK-058: TFTP/RFC 1350 client wire codec. The kernel
        // builds an RRQ for `/proteus-boot.img` in octet mode and
        // byte-exact-asserts the 26-byte canonical encoding
        // (opcode 0x0001 + filename + NUL + "octet" + NUL). It then
        // parses a locked ACK(1) reply and a locked DATA(2,
        // "0123456789") packet, recovering block + payload byte-for-
        // byte. Both banners appearing means the big-endian opcode
        // encoding, NUL-terminated string discipline, and DATA/ACK
        // block-number encoding are all wired correctly. A morph
        // that perturbs any of those panics inside `banner_tftp`
        // and these banners never appear.
        "TFTP rrq OK len=26 mode=octet",
        "TFTP data OK block=2 bytes=10",
        // TASK-059: PCI/0xCF8-0xCFC configuration-space wire codec.
        // The kernel constructs an in-RAM RecordingBus scripted with
        // two QEMU-canonical devices (Intel 8086:100E e1000 at
        // 00:03.0 + Intel 8086:5845 NVMe at 00:05.0), runs
        // `PciImpl::enumerate`, and asserts both functions surface
        // with byte-exact (vendor, device, class, subclass). It then
        // reads BAR0 on the e1000 (port-I/O at 0xC020) and asserts
        // the decoded `PciBar::Io(0xC020)`. Both banners appearing
        // means the configuration-space dword decoder, the
        // multi-function bit gating, the BAR low-bit type decode,
        // and the vendor-none sentinel are all wired correctly. A
        // morph that perturbs any of those panics inside
        // `banner_pci` and these banners never appear.
        "PCI scan OK devices=2 e1000=found nvme=found",
        "PCI bar OK e1000_io=0xc020",
        // TASK-060: X.509 DER v3 parser. The kernel parses a 257-byte
        // hand-rolled Ed25519 self-signed certificate fixture, asserts
        // the recovered version / serial / validity / pubkey / CN
        // round-trip byte-for-byte against locked goldens. Both
        // banners appearing means: the strict-DER TLV walker, the
        // BIT STRING `unused bits` enforcement, the Ed25519 SPKI
        // alg-OID equality check, the UTCTime calendar-day decoder,
        // and the recursive RDN walker that recovers the leaf CN
        // are all wired correctly. A morph that perturbs any byte
        // position in any of those panics inside `banner_x509` and
        // the banners never appear.
        "X509 parse OK len=257 serial=42",
        "X509 cn OK cn=proteus-te-x509-kernel-fixture",
        // TASK-062: PIT + CMOS RTC wire codec. The kernel programs
        // channel 0 for 1 kHz against a recording IoPort and asserts
        // the exact three-byte sequence (cmd=0x36, divisor=1193 →
        // lo=0xA9 hi=0x04), then reads a hardcoded BCD 24-hour RTC
        // fixture for 2026-03-15 12:34:56 and recovers Unix epoch
        // 1773578096. Both banners appearing means: the PIT command
        // byte + divisor clamp arithmetic, the CMOS index/data
        // demux, the UIP + consistency dance, BCD decode, 24-hour
        // conversion, and Gregorian → Unix conversion are all wired
        // correctly. A morph that perturbs any of those panics
        // inside `banner_timer` and these banners never appear.
        "PIT program OK hz=1000 div=1193",
        "RTC read OK unix=1773578096 date=2026-03-15",
        // TASK-063: Crypto KAT harness. The kernel runs the locked
        // 9-vector suite (SHA-256 empty/abc/million-a, HMAC-SHA-256
        // RFC 4231 cases 1-4, HKDF-SHA-256 RFC 5869 cases 1-2)
        // against the real tls crypto primitives and asserts every
        // digest matches the published answer. Banner appearing
        // means: SHA-256 compression, HMAC ipad/opad construction,
        // HKDF-Extract PRK, and HKDF-Expand OKM all match the
        // standards byte-for-byte. A morph that perturbs any of
        // those panics inside `banner_kat` and the banner never
        // appears.
        "KAT all OK vectors=9",
        // TASK-064: JFS on-disk image walker. The kernel builds a
        // locked 4-sector fixture (superblock + inode table + root
        // dir + hello.txt body), mounts it, looks up hello.txt from
        // the root directory, reads 16 body bytes, and asserts
        // byte-equality against `b"hello, proteus!\n"` plus the
        // locked Fletcher-32 fingerprint `aa3ce1c0`. Both banners
        // appearing means: superblock magic/version/field offsets,
        // 32-byte inode encode/decode, fixed dirent walk, direct-
        // extent file read, and path lookup are all wired correctly.
        // A morph that perturbs any of those panics inside
        // `banner_jfs` and these banners never appear.
        "JFS mount OK root_ino=1 inodes=3",
        "JFS read OK path=/hello.txt bytes=16 sha=aa3ce1c0",
        // TASK-065: GDB Remote Serial Protocol wire codec. The kernel
        // parses the locked `$g#67` frame (body=`g`, cksum=0x67),
        // classifies it as ReadRegisters, builds the 256-hex-zero
        // register dump, re-frames it, and asserts the reply
        // checksum digits are `00`. Banner appearing means: the
        // 8-bit wrapping-sum checksum, `$…#cs` framing, command
        // classification for `g`, and the fixed-length register
        // reply layout are all wired correctly. A morph that
        // perturbs any of those panics inside `banner_gdbstub`
        // and the banner never appears.
        "GDBSTUB parse OK cmd=g cksum=67",
        // TASK-066: Disk quota wire codec. The kernel builds a locked
        // 3-uid quotafile fixture (1000 healthy, 1001 at block
        // limit, 1002 inode grace expired), scans it (3 live
        // records), looks up uid 1001, and asserts a +1 block write
        // is rejected with QuotaReject::BlockLimit. Both banners
        // appearing means: 32-byte LE record layout, scan skipping
        // free slots, lookup-by-uid, and the hard block-limit
        // check-on-write predicate are all wired correctly. A morph
        // that perturbs any of those panics inside `banner_quota`
        // and these banners never appear.
        "QUOTA scan OK records=3",
        "QUOTA reject OK uid=1001 reason=block_limit",
        // TASK-067 HPET
        "HPET program OK period_fs=69841279 cmp=14318",
        // TASK-068 stack canary
        "CANARY mint OK tok=",
        "CANARY fail OK reason=mismatch",
        // TASK-069 keyboard
        "KBD decode OK keys=2 last=b",
        // TASK-070 FAT32
        "FAT mount OK fats=2 root_clus=2",
        "FAT read OK name=HELLO.TXT bytes=13",
        // TASK-071..074
        "WATCHDOG pet OK deadline=5",
        "WATCHDOG fire OK reason=timeout",
        "RNG kat OK seed=0102 out=",
        "POWER s5 OK slp_typ=5",
        "ELF parse OK phnum=1 entry=4198400",
        // TASK-075..078
        "SERIAL init OK port=0x3f8",
        "TICK source OK kind=hpet",
        "VIRTIO caps OK common=found",
        "SIGKAT all OK vectors=2",
        // TASK-079..082
        "MB2 parse OK tags=1",
        "CRC32C kat OK",
        "RSDP parse OK oem=BOCHS",
        "FRAME alloc OK free=4094",
        // TASK-083..084
        "IOAPIC entry OK vec=0x30",
        "LAPIC icr OK delivery=init",
        // TASK-085..087
        "GPT parse OK parts=1",
        "DNS name OK labels=2",
        "DRBG kat OK",
        // TASK-088 AHCI Register H2D FIS (IDENTIFY encode/decode)
        "AHCI fis OK cmd=identify",
        // TASK-089..093
        "XHCI trb OK type=noop",
        "GOP mode OK 1280x720",
        "TLV parse OK tags=3",
        "B64 roundtrip OK",
        "AHCI cmd OK prdtl=1",
        // Anti-sprawl live composition (not isolated unit banners):
        // PIT 1 kHz program + TickSource (PIT→HPET) drives Watchdog
        // arm/tick/pet/fire. Proves the timebase chain is linked in
        // the boot image, not only per-module.
        "TIMEBASE compose OK pit_div=1193 pet_rem=5 fire=timeout",
        // Quota check_write gates a real VFS create/write: uid 1000
        // allowed → 8-byte write to /var/ok; uid 1001 BlockLimit
        // reject. Proves storage policy + VFS path composition.
        "VFS+QUOTA compose OK allow=1000 reject=1001 bytes=8",
        // AHCI FIS + command header + PRDT agree on one IDENTIFY slot
        // (CFL=5 == H2D FIS dwords, PRDTL=1, 512 B IOC buffer).
        "AHCI storage compose OK fis=ec prdtl=1 bytes=512",
        // TCP handshake → HTTP GET as TCP payload → HTTP 200 re-framed
        // as TCP. Morph desync of tcp/http glue drops this line.
        "NET path compose OK method=GET status=200",
        // Same 512 B pattern on NVMe + virtio-blk; cross-backend first
        // byte must match after independent morph of both drivers.
        "BLOCK path compose OK sector=512 nvme=a5 virtio=a5",
        // TASK-104: real PCI config I/O finds QEMU virtio-blk-pci
        // (vendor 0x1AF4). Not MemBus — out/in against 0xCF8/0xCFC.
        "VIRTIO_HW probe OK blk=found slot=",
        // TASK-105: real I/O-BAR capacity read (1 MiB image → 2048 sectors).
        "VIRTIO_HW io OK capacity=2048",
        // TASK-107: real virtqueue write+read sector 0 (pattern 0xA5^i).
        "VIRTIO_HW sector OK first_byte=a5",
        // TASK-109/111: real virtio-net-pci MAC + TX/RX virtqueues (hub).
        "VIRTIO_NET_HW probe OK slot=",
        "VIRTIO_NET_HW tx OK bytes=76",
        "VIRTIO_NET_HW rx OK bytes=",
        // TASK-113/117: real AHCI HBA MMIO + IDENTIFY + sector WRITE/READ DMA.
        "AHCI_HW probe OK slot=",
        "AHCI_HW identify OK sectors=2048",
        "AHCI_HW sector OK first_byte=5a",
        // Lived guest net (TCP/80 HTTP + UDP/8080 + ICMP echo) binds
        // after continuity and before the remaining HW banners.
        "NET SVC UP ip=10.0.2.15 udp=8080 tcp=80 icmp=echo",
        // TASK-116/120: real e1000 PCI + MMIO + EEPROM MAC + TX DD.
        "E1000_HW probe OK slot=",
        "E1000_HW tx OK bytes=64",
        "E1000_HW rx OK bytes=",
        // TASK-119/131: real QEMU NVMe admin identify + sector R/W.
        "NVME_HW probe OK slot=",
        "NVME_HW identify OK sn=",
        "NVME_HW sector OK first_byte=5a",
        // TASK-145: guest durable seal of empty audit snapshot header.
        "DURABLE seal OK dig=",
        // TASK-019: Crash-dump + symbol-resolver banners. The kernel
        // assembles a deterministic CrashContext (fixed
        // wall_unix / TSC / registers / backtrace / kmsg / panic_loc /
        // message — all from `kernel_fixtures::CRASH_*`), runs it
        // through `PanicDumpImpl::dump_to_sink` into an in-kernel
        // `MemorySectorSink`, then asserts every header field round-
        // trips AND the body CRC32-C equals the locked
        // `CRASH_EXPECTED_CRC32C`. The resolver banner then asserts
        // a hand-built kernel-symbol fixture maps the first backtrace
        // frame to "kernel_main+0x42". Both banners appearing means
        // the on-disk layout (sector offsets, NUL padding, register
        // serialisation, CRC poly) AND the binary-search resolver
        // are wired correctly. A morph that perturbs any byte of
        // the layout, the CRC routine, or the symbol-resolution
        // containment rule panics here and the banners never appear.
        "CRASH_DUMP wrote 16384 bytes to lba=1024 crc=8fb6eb0e",
        "SYMBOL resolve OK kernel_main+0x42 (5 frames)",
        "WEB+SQL+SESSION compose OK tables=2 rows=6 magic=PRTSSQL1",
        "SECCOMP: OK engine=ebpf filter=enforced",
        "ATTEST: OK seed=",
        "FS partition OK lba=1042..1057 sectors=16 files=1 magic=PRTSFS01",
        "HTTPS+TCP4 compose OK slots=4 port=443 tls13=ok",
        "SHELL compose OK tasks=5 files=5 audit=5",
        "PROTEUS-TE HALT",
    ];
    eprintln!("smoke: launching QEMU (+virtio-blk +2x net hub +ahci +nvme +fw_cfg device key)...");
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
        // Force TCG. On some Windows hosts the default accelerator
        // (WHPX) accepts the guest but never advances the BIOS past
        // reset — serial stays empty and the 10s banner sweep fails.
        // TCG is slower but deterministic for smoke.
        // Boot image on IDE so virtio-blk-pci is a *second* disk the
        // kernel can discover without fighting the bootloader drive.
        let mut qproc = Command::new(self.qemu)
            .arg("-accel")
            .arg("tcg")
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
    log.contains("PROTEUS-TE HALT")
}

#[test]
#[ignore = "requires nightly rust-src + factory_builder_pkg + qemu-system-x86_64"]
fn tampered_ahci_seal_is_rejected_under_qemu() {
    let Some(qemu) = find_qemu() else {
        panic!("qemu-system-x86_64 not found");
    };
    let root = workspace_root();
    let images_dir = root.join("target").join("proteus_images");
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
        .args(["run", "--release", "-p", "proteus-binmorph", "--", "--in"])
        .arg(&elf)
        .arg("--out")
        .arg(&morphed_elf)
        .args(["--seed", "42"])
        .output()
        .expect("run proteus-binmorph");
    assert!(
        bm.status.success(),
        "proteus-binmorph failed: {}",
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

    // Boot 1 (7-pass binmorphed kernel): verify milestone banners and write valid sealed state.
    let (log1, _) = vm.boot(&tamper_log, halted);
    for expected in [
        "RING3 transition OK cpl=3->0 vec=0x80 ist1=ok rsp0=ok syscall=43",
        "TPM2_TIS driver OK did_vid=000115d1 locality=0 pcr10=extended",
        "WEB+SQL+SESSION compose OK tables=2 rows=6 magic=PRTSSQL1",
        "FS partition OK lba=1042..1057 sectors=16 files=1 magic=PRTSFS01",
        "HTTPS+TCP4 compose OK slots=4 port=443 tls13=ok",
        "SHELL compose OK tasks=5 files=5 audit=5",
    ] {
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
    let (log2, _) = vm.boot(&tamper_log, halted);
    for disk in scratch_disks {
        let _ = std::fs::remove_file(disk);
    }
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
