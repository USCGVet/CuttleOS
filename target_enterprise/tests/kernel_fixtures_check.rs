//! Host-side shadow of the bare-metal kernel's per-feature proof
//! sequence (`target_enterprise_kernel/src/main.rs`).
//!
//! Every check the kernel performs against a `kernel_fixtures::EXPECTED_*`
//! array is duplicated here. The kernel cannot run cargo's test
//! harness — once we ship a kernel binary that asserts against
//! `HASH_EXPECTED`, drift between the algorithm and the embedded
//! expected bytes would only surface as a missing serial banner.
//! Running these checks under `cargo test --workspace` catches the
//! drift on the host and fails fast.
//!
//! These tests also serve as the population mechanism: when a fixture
//! input changes (e.g., we pick a new `HASH_INPUT`), update the
//! corresponding `EXPECTED_*` constant and rely on these tests to
//! verify the new value is consistent with the algorithm.

use cuttle_contracts::{AccessKind, Hash, Iommu, NetStack, PagePerms, WriteAheadLog};
use target_enterprise::iommu::{DeviceId, IommuImpl};
use target_enterprise::kernel_fixtures as kf;
use target_enterprise::net::{build_udp_datagram, parse_ipv4_header, parse_udp_datagram};
use target_enterprise::tls::{hkdf_expand_label, hkdf_extract};
use target_enterprise::wal::WalImpl;
use target_enterprise::{HashImpl, NetStackImpl};

#[test]
fn hkdf_extract_matches_expected_prk() {
    let mut prk = [0u8; 32];
    hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk);
    assert_eq!(
        prk, kf::HKDF_EXPECTED_PRK,
        "HKDF-Extract drift — RFC 5869 §A.1 case 1 vector regressed"
    );
}

#[test]
fn hkdf_expand_label_matches_expected_prefix() {
    let mut prk = [0u8; 32];
    hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk);
    let mut out = [0u8; kf::HKDF_EXPAND_OUT_LEN];
    hkdf_expand_label(&prk, kf::HKDF_EXPAND_LABEL, &kf::HKDF_INFO, &mut out);
    assert_eq!(
        &out[..8],
        &kf::HKDF_EXPECTED_EXPAND_PREFIX8,
        "HKDF-Expand-Label drift — actual prefix = {:02x?}",
        &out[..8]
    );
}

#[test]
fn https_golden_certificate_matches_fixture() {
    // The kernel's `TLS cert` banner asserts this fingerprint.
    let identity = target_enterprise::https::ServerIdentity::derive(
        &target_enterprise::https::golden::IDENTITY_SECRET,
        target_enterprise::https::golden::MAC,
    );
    assert_eq!(identity.fingerprint(), kf::HTTPS_GOLDEN_CERT_SHA256);
}

#[test]
fn https_golden_session_replays_against_fixture() {
    // The kernel's `HTTPS compose` banner runs exactly this replay.
    let report = target_enterprise::https::replay_golden_session().expect("golden TLS session drift");
    assert_eq!(report.server_bytes, kf::HTTPS_GOLDEN_SERVER_LEN);
    assert_eq!(report.sha256, kf::HTTPS_GOLDEN_SERVER_SHA256);
}

#[test]
fn wal_replay_visits_all_16_frames_in_order() {
    let mut wal: WalImpl<{ kf::WAL_CAPACITY }> = WalImpl::new();
    for i in 0..kf::WAL_FRAMES {
        let payload = [i as u8; kf::WAL_PAYLOAD_LEN];
        wal.append(&payload).expect("append fixture frame");
    }
    wal.flush(target_enterprise::wal::durable_wal_proof_init())
        .expect("flush WAL");
    assert_eq!(wal.next_lsn(), kf::WAL_EXPECTED_NEXT_LSN);

    let mut seen: u64 = 0;
    let mut last_lsn: u64 = 0;
    let mut order_ok = true;
    wal.replay(&mut |lsn, payload| {
        seen += 1;
        if lsn != last_lsn + 1 {
            order_ok = false;
        }
        last_lsn = lsn;
        // payload at index i is [i; 4]; the LSN was assigned in
        // append order, so the payload's first byte should equal
        // (lsn - 1) mod 256.
        let expected_byte = (lsn - 1) as u8;
        assert_eq!(payload.len(), kf::WAL_PAYLOAD_LEN);
        assert_eq!(payload[0], expected_byte);
        assert_eq!(payload[1], expected_byte);
        assert_eq!(payload[2], expected_byte);
        assert_eq!(payload[3], expected_byte);
    });
    assert!(order_ok, "WAL replay must visit frames in strict LSN order");
    assert_eq!(seen as usize, kf::WAL_FRAMES);
    assert_eq!(last_lsn, kf::WAL_FRAMES as u64);
}

#[test]
fn iommu_translate_returns_expected_host_phys() {
    let mut iommu: IommuImpl<
        { kf::IOMMU_DOMAINS },
        { kf::IOMMU_DEVICES },
        { kf::IOMMU_ENTRIES_PER_DOMAIN },
    > = IommuImpl::new();

    let domain = iommu.create_domain().expect("create domain");
    let device = DeviceId::from_bdf(
        kf::IOMMU_DEVICE_SEGMENT,
        kf::IOMMU_DEVICE_BUS,
        kf::IOMMU_DEVICE_DEVICE,
        kf::IOMMU_DEVICE_FUNCTION,
    );
    iommu.bind_device(device, domain).expect("bind device");
    iommu
        .map(domain, kf::IOMMU_DMA_ADDR, kf::IOMMU_HOST_PHYS, PagePerms::RW)
        .expect("map DMA page");
    let probe = kf::IOMMU_DMA_ADDR + kf::IOMMU_PAGE_OFFSET;
    let pa = iommu
        .translate(device, probe, AccessKind::Read)
        .expect("translate succeeds for mapped page");
    assert_eq!(pa, kf::IOMMU_EXPECTED_PA);
}

#[test]
fn hash_impl_over_fixture_matches_expected_digest() {
    let mut got = [0u8; 32];
    HashImpl::hash(kf::HASH_INPUT, &mut got);
    assert_eq!(
        got, kf::HASH_EXPECTED,
        "HashImpl drift over locked fixture — actual = {:02x?}",
        got
    );
}

// ============================================================
// NET — host shadow of the kernel's `banner_net_build` check
// ============================================================

#[test]
fn net_build_over_fixture_matches_expected_datagram() {
    let mut buf = [0u8; kf::NET_EXPECTED_LEN];
    let n = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut buf,
    )
    .expect("build canonical net fixture");
    assert_eq!(n, kf::NET_EXPECTED_LEN);
    assert_eq!(
        &buf[..n],
        &kf::NET_EXPECTED_DATAGRAM[..],
        "NET build drift over locked fixture"
    );
}

#[test]
fn net_build_via_trait_matches_expected_datagram() {
    let mut buf = [0u8; kf::NET_EXPECTED_LEN];
    let n = <NetStackImpl as NetStack>::build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut buf,
    )
    .expect("trait build");
    assert_eq!(&buf[..n], &kf::NET_EXPECTED_DATAGRAM[..]);
}

#[test]
fn net_parse_recovers_fixture_inputs() {
    let ip = parse_ipv4_header(&kf::NET_EXPECTED_DATAGRAM).expect("parse ipv4");
    assert_eq!(ip.src_ip, kf::NET_SRC_IP);
    assert_eq!(ip.dst_ip, kf::NET_DST_IP);
    assert_eq!(ip.ttl, kf::NET_TTL);
    assert_eq!(ip.identification, kf::NET_IDENT);
    assert_eq!(ip.header_checksum, kf::NET_EXPECTED_IP_CHECKSUM);

    let udp = parse_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        &kf::NET_EXPECTED_DATAGRAM[20..],
    )
    .expect("parse udp");
    assert_eq!(udp.src_port, kf::NET_SRC_PORT);
    assert_eq!(udp.dst_port, kf::NET_DST_PORT);
    assert_eq!(udp.checksum, kf::NET_EXPECTED_UDP_CHECKSUM);
    assert_eq!(udp.payload_len, kf::NET_PAYLOAD.len());
}

// ============================================================
// TASK-019 — host shadow of `banner_panic_dump`
// ============================================================

#[test]
fn panic_dump_crc_matches_expected_locked_value() {
    use cuttle_contracts::{CrashContext, CrashDump};
    use target_enterprise::panic_dump::PanicDumpImpl;

    let ctx = CrashContext {
        wall_unix: kf::CRASH_WALL_UNIX,
        tsc: kf::CRASH_TSC,
        panic_loc: kf::CRASH_PANIC_LOC,
        message: kf::CRASH_MESSAGE,
        registers: &kf::CRASH_REGISTERS,
        backtrace: &kf::CRASH_BACKTRACE,
        kmsg: kf::CRASH_KMSG,
    };
    let mut buf = [0u8; cuttle_contracts::CRASH_DUMP_BYTES];
    PanicDumpImpl::build_dump(&ctx, &mut buf).expect("build_dump");

    // The CRC slot was written to the header by build_dump.
    let header = PanicDumpImpl::parse_header(&buf).expect("parse_header");
    assert_eq!(
        header.body_crc32c, kf::CRASH_EXPECTED_CRC32C,
        "CRC32-C body checksum drift — got {:#010x}, expected {:#010x}",
        header.body_crc32c, kf::CRASH_EXPECTED_CRC32C
    );

    // Body CRC must verify.
    PanicDumpImpl::verify_crc(&buf).expect("verify_crc clean");
}

#[test]
fn symbol_resolver_recovers_expected_name_and_offset() {
    use cuttle_contracts::SymbolResolve;
    use target_enterprise::symbols::{StaticSymbolResolver, SymbolEntry};

    // Hand-built kernel symbol fixture matching CRASH_BACKTRACE.
    const SYMBOLS: &[SymbolEntry] = &[
        SymbolEntry::new(0xFFFF_FFFF_8010_0000, 0x100, "kernel_main"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0500, 0x200, "schedule_next_task"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0800, 0x100, "handle_irq_timer"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0A00, 0x080, "halt_forever"),
    ];
    assert!(
        StaticSymbolResolver::is_sorted_by_addr(SYMBOLS),
        "kernel symbol fixture must be sorted"
    );
    let resolver = StaticSymbolResolver::new(SYMBOLS);

    let (name, off) = resolver
        .resolve(kf::CRASH_BACKTRACE[0])
        .expect("first backtrace frame must resolve");
    assert_eq!(name, kf::CRASH_EXPECTED_RESOLVE_NAME);
    assert_eq!(off, kf::CRASH_EXPECTED_RESOLVE_OFFSET);

    // Every frame in the backtrace must resolve to a non-empty name.
    let mut i = 0usize;
    while i < kf::CRASH_BACKTRACE.len() {
        let r = resolver.resolve(kf::CRASH_BACKTRACE[i]);
        assert!(
            r.is_some(),
            "backtrace[{}] = {:#x} did not resolve",
            i,
            kf::CRASH_BACKTRACE[i]
        );
        i += 1;
    }
}
