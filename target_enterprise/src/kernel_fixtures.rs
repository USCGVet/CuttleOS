//! Locked-in fixture inputs + expected outputs used by both the host
//! integration test `tests/kernel_fixtures_check.rs` and the bare-metal
//! kernel binary in `target_enterprise_kernel/src/main.rs`.
//!
//! Centralising the fixtures here ensures the bare-metal kernel and the
//! host-side verifier exercise byte-identical inputs against byte-
//! identical expected outputs. Any drift in either consumer is caught
//! by `kernel_fixtures_check`, which acts as the host shadow of the
//! kernel's per-feature proof banner.
//!
//! Locked surface: every `pub const` in this module is part of the
//! contract surface the diversifier MUST NOT mutate. The values are
//! either RFC vectors (HKDF), hand-computed against the locked
//! algorithm contract (HashImpl, WAL framing, IOMMU walk), or recorded
//! from a real TLS session (the HTTPS golden transcript).
//!
//! The kernel does not link the host std library and runs under
//! `panic=abort`; its only heap user is the HTTPS stack. Every check
//! the kernel performs is a `==` against a value here; failure path
//! is `panic!`, which the kernel's `panic_handler` writes to serial
//! before halting. The QEMU smoke test then sees the absent banner.

#![allow(missing_docs)]

// ============================================================
// TLS — HKDF-Extract: RFC 5869 §A.1 test case 1
// ============================================================

/// IKM for RFC 5869 §A.1 case 1: 22 bytes of `0x0b`.
pub const HKDF_IKM: [u8; 22] = [0x0b; 22];

/// Salt for RFC 5869 §A.1 case 1: 13 bytes `0x00..0x0c`.
pub const HKDF_SALT: [u8; 13] = [
    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
];

/// Expected PRK = `HMAC-SHA256(salt, IKM)` per RFC 5869 §A.1 case 1.
pub const HKDF_EXPECTED_PRK: [u8; 32] = [
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba, 0x63,
    0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2, 0xb3, 0xe5,
];

/// Info-context for the HKDF-Expand-Label step: RFC 5869 §A.1 case 1
/// info value.
pub const HKDF_INFO: [u8; 10] = [0xf0, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9];

/// Label for the HKDF-Expand-Label step. RFC 8446 prepends `"tls13 "`
/// inside `hkdf_expand_label`; we pass only the label proper.
pub const HKDF_EXPAND_LABEL: &[u8] = b"cuttle-te-key";

/// Output length the kernel asks `hkdf_expand_label` to produce.
pub const HKDF_EXPAND_OUT_LEN: usize = 16;

/// First 8 bytes of [`HKDF_EXPAND_OUT_LEN`] bytes produced by
/// `hkdf_expand_label(prk, b"cuttle-te-key", HKDF_INFO, &mut out)`.
/// Populated by `tests/kernel_fixtures_check.rs`.
pub const HKDF_EXPECTED_EXPAND_PREFIX8: [u8; 8] = [
    0xad, 0x2b, 0xe6, 0xc8, 0x9e, 0xae, 0x85, 0xe2,
];

// ============================================================
// HTTPS — golden TLS 1.3 session (rustls + RustCrypto provider)
//
// The client side of one real TLS 1.3 session, recorded from a rustls
// client (ring crypto) talking to the golden LivedNet server
// (`https::golden_server`: deterministic RNG, fixture identity). The
// boot self-test and `tests/https_interop.rs` replay these flights
// through `LivedNet::handle_frame` and require the server's entire
// byte stream to hash to HTTPS_GOLDEN_SERVER_SHA256.
//
// Regenerate (only after a deliberate change to rustls, the provider,
// the certificate, or the HTTP response) with:
//   cargo test -p target_enterprise --test https_interop -- --ignored --nocapture record_golden
// ============================================================

include!("https_golden_fixture.rs");

// ============================================================
// WAL — 16 fixture frames
// ============================================================

/// Capacity of the kernel's WalImpl backing store. Each fixture record
/// is 4 bytes of payload + 8 bytes of frame header = 12 bytes; with
/// 16 records that is 192 bytes durable — well inside 4 KiB.
pub const WAL_CAPACITY: usize = 4096;

/// Number of fixture frames the kernel appends to the WAL.
pub const WAL_FRAMES: usize = 16;

/// Bytes per fixture frame payload (LSN low-byte, repeating). The
/// frame at index `i` carries payload `[i, i, i, i]` so the CRC differs
/// per frame and replay must visit them in append order.
pub const WAL_PAYLOAD_LEN: usize = 4;

/// LSN that `next_lsn()` reports after the kernel appends 16 frames.
/// Locked by the contract: next_lsn starts at 1, advances by 1 per
/// successful append.
pub const WAL_EXPECTED_NEXT_LSN: u64 = (WAL_FRAMES as u64) + 1;

// ============================================================
// IOMMU — fixed-shape walk
// ============================================================

/// Kernel uses an `IommuImpl<4, 8, 16>`: 4 domain slots, 8 device slots,
/// 16 page-table entries per domain. The map below uses page-frame
/// index 1 (DMA = `0x1000`, host = `0x4000`), well inside the 16-entry
/// cap.
pub const IOMMU_DOMAINS: usize = 4;
pub const IOMMU_DEVICES: usize = 8;
pub const IOMMU_ENTRIES_PER_DOMAIN: usize = 16;

/// BDF the kernel binds: segment=0, bus=0, device=1, function=0.
pub const IOMMU_DEVICE_SEGMENT: u16 = 0;
pub const IOMMU_DEVICE_BUS: u8 = 0;
pub const IOMMU_DEVICE_DEVICE: u8 = 1;
pub const IOMMU_DEVICE_FUNCTION: u8 = 0;

/// DMA address the kernel maps. Page-aligned by construction.
pub const IOMMU_DMA_ADDR: u64 = 0x1000;
/// Host physical address the DMA mapping resolves to.
pub const IOMMU_HOST_PHYS: u64 = 0x4000;
/// Page-offset the kernel passes to `translate` (within the page).
pub const IOMMU_PAGE_OFFSET: u64 = 0x123;
/// Expected return from `translate(device, DMA + offset, Read)`.
pub const IOMMU_EXPECTED_PA: u64 = IOMMU_HOST_PHYS | IOMMU_PAGE_OFFSET;

// ============================================================
// HASH — HashImpl over a fixture byte string
// ============================================================

/// Input the kernel hashes with `target_enterprise::HashImpl`.
pub const HASH_INPUT: &[u8] = b"cuttle-te-fixture-2026-05-16";

/// Expected 32-byte digest produced by `HashImpl::hash(HASH_INPUT, &mut out)`.
/// HashImpl is the locked Fletcher-32-chained construction described in
/// `target_enterprise/src/lib.rs::HashImpl`. Populated by
/// `tests/kernel_fixtures_check.rs`.
pub const HASH_EXPECTED: [u8; 32] = [
    0xb9, 0x1f, 0x88, 0xd0, 0xba, 0x20, 0x89, 0xd1, 0xbb, 0x21, 0x8a, 0xd2, 0xbc, 0x22, 0x8b, 0xd3,
    0xbd, 0x23, 0x8c, 0xd4, 0xbe, 0x24, 0x8d, 0xd5, 0xbf, 0x25, 0x8e, 0xd6, 0xc0, 0x26, 0x8f, 0xd7,
];

// ============================================================
// NET — UDP/IPv4 datagram build + parse (TASK-011)
// ============================================================

/// Source IPv4 address the kernel uses to build the canonical UDP
/// datagram. Matches the QEMU user-mode-networking guest IP (the
/// donor RustOSa kernel used the same address for its smoltcp seed).
pub const NET_SRC_IP: [u8; 4] = [10, 0, 2, 15];

/// Destination IPv4 address the kernel uses to build the canonical
/// UDP datagram. Matches the QEMU slirp gateway.
pub const NET_DST_IP: [u8; 4] = [10, 0, 2, 2];

/// UDP source port (caller-chosen ephemeral; locked here for the
/// fixture). Above 1024 by convention.
pub const NET_SRC_PORT: u16 = 49152;

/// UDP destination port (locked at 53 — DNS — for the fixture; the
/// kernel never actually queries DNS, but the value is deterministic
/// and recognisable in a hex dump).
pub const NET_DST_PORT: u16 = 53;

/// IPv4 TTL value the kernel emits.
pub const NET_TTL: u8 = 64;

/// IPv4 identification field the kernel emits.
pub const NET_IDENT: u16 = 0xBEEF;

/// Payload the kernel embeds in the UDP datagram.
pub const NET_PAYLOAD: &[u8] = b"cuttle-te";

/// Expected total datagram length: 20 (IPv4) + 8 (UDP) + 10 (payload).
pub const NET_EXPECTED_LEN: usize = 37;

/// Locked golden bytes for the canonical UDP/IPv4 datagram.
///
/// Computed by `target_enterprise::net::build_udp_datagram` against
/// the constants above. The `kernel_fixtures_check` host test asserts
/// this byte-for-byte AND the bare-metal kernel asserts the same on
/// boot before emitting the `NET build OK len=37 …` banner. Any morph
/// candidate that drifts from this byte string fails both shadows.
pub const NET_EXPECTED_DATAGRAM: [u8; NET_EXPECTED_LEN] = [
    // IPv4 header
    0x45, 0x00, // version/IHL, DSCP/ECN
    0x00, 0x25, // total_length = 37
    0xBE, 0xEF, // identification
    0x40, 0x00, // flags=DF, frag=0
    0x40, // TTL = 64
    0x11, // protocol = UDP (17)
    0x63, 0xC8, // header checksum (RFC 1071)
    0x0A, 0x00, 0x02, 0x0F, // src_ip = 10.0.2.15
    0x0A, 0x00, 0x02, 0x02, // dst_ip = 10.0.2.2
    // UDP header
    0xC0, 0x00, // src_port = 49152
    0x00, 0x35, // dst_port = 53
    0x00, 0x11, // length = 17 = UDP_HEADER(8) + PAYLOAD(9)
    0x50, 0xC2, // UDP checksum (RFC 768)
    // Payload "cuttle-te"
    b'c', b'u', b't', b't', b'l', b'e', b'-', b't', b'e',
];

/// Expected IPv4 header checksum (host order) — exposed separately so
/// the kernel banner can hex-encode it for the serial log.
pub const NET_EXPECTED_IP_CHECKSUM: u16 = 0x63C8;

/// Expected UDP checksum (host order).
pub const NET_EXPECTED_UDP_CHECKSUM: u16 = 0x50C2;

// ============================================================
// Crash dump / symbol resolution — TASK-019
//
// The kernel's `banner_panic_dump` builds a deterministic
// CrashContext (same inputs every boot), writes it via
// PanicDumpImpl::dump_to_sink into a MemorySectorSink, verifies
// the body CRC, parses every field, and resolves a backtrace
// address against a hand-built kernel-symbol fixture. The
// banner asserts byte-equality on the CRC and on the resolved
// (name, offset) pair.
// ============================================================

/// Wall-clock used by the panic-dump banner (Unix seconds for a
/// fixed historical timestamp — chosen for stable bytes across
/// boots).
pub const CRASH_WALL_UNIX: u64 = 1_700_000_000;

/// CPU timestamp used by the panic-dump banner. Locked.
pub const CRASH_TSC: u64 = 0x0123_4567_89AB_CDEF;

/// Synthetic panic location for the kernel's panic-dump banner.
pub const CRASH_PANIC_LOC: &str = "target_enterprise/src/scheduler.rs:117:9";

/// Synthetic panic message for the kernel's panic-dump banner.
pub const CRASH_MESSAGE: &str = "kernel BUG: scheduler invariant violated";

/// 24 architectural-register slots captured into the dump. The
/// values are arbitrary but locked so the body CRC is stable.
pub const CRASH_REGISTERS: [u64; 24] = [
    0x0000_0000_0000_0001, // RAX
    0x0000_0000_0000_0002, // RBX
    0x0000_0000_0000_0003, // RCX
    0x0000_0000_0000_0004, // RDX
    0x0000_0000_0000_0005, // RSI
    0x0000_0000_0000_0006, // RDI
    0xFFFF_FFFF_8000_FF00, // RBP
    0xFFFF_FFFF_8000_FE00, // RSP
    0x0000_0000_0000_0008, // R8
    0x0000_0000_0000_0009, // R9
    0x0000_0000_0000_000A, // R10
    0x0000_0000_0000_000B, // R11
    0x0000_0000_0000_000C, // R12
    0x0000_0000_0000_000D, // R13
    0x0000_0000_0000_000E, // R14
    0x0000_0000_0000_000F, // R15
    0xFFFF_FFFF_8010_0042, // RIP — equals CRASH_BACKTRACE[0]
    0x0000_0000_0000_0202, // RFLAGS
    0x0000_0000_0000_0000, // CR2
    0x0000_0000_0010_2000, // CR3
    0x0000_0000_0000_0000, // FS_BASE
    0xFFFF_8000_0000_0000, // GS_BASE
    0xFFFF_FFFF_FFFF_8000, // KERNEL_GS_BASE
    0x0000_0000_D000_0901, // MSR_EFER (LMA|LME|SCE)
];

/// Backtrace frame addresses captured into the dump. Every address
/// is calibrated so it lands inside one of the symbols in
/// [`CRASH_SYMBOLS`] — the resolver test then has a definite hit.
pub const CRASH_BACKTRACE: [u64; 5] = [
    0xFFFF_FFFF_8010_0042, // → kernel_main+0x42
    0xFFFF_FFFF_8010_0500, // → schedule_next_task+0x00
    0xFFFF_FFFF_8010_0530, // → schedule_next_task+0x30
    0xFFFF_FFFF_8010_0810, // → handle_irq_timer+0x10
    0xFFFF_FFFF_8010_0A20, // → halt_forever+0x20
];

/// Sample kmsg ring tail bytes captured into the dump.
pub const CRASH_KMSG: &[u8] = b"[INFO ] cuttle-te boot\n[WARN ] scheduler queue near full\n";

/// Locked CRC32-C body checksum that
/// [`PanicDumpImpl::build_dump`] emits for the canonical
/// CrashContext built from the constants above. The kernel
/// banner asserts against this exact value; the host shadow
/// in `tests/kernel_fixtures_check.rs` does the same.
///
/// Computed by the host shadow on first run and locked here.
/// Any morph that perturbs the layout, register order, kmsg
/// pad, or the CRC32-C polynomial changes this and the banner
/// suppresses itself.
pub const CRASH_EXPECTED_CRC32C: u32 = 0x659E_CE68;

/// Resolved (name, offset) for the FIRST address in
/// [`CRASH_BACKTRACE`]. The kernel banner formats this exactly
/// and the QEMU smoke test asserts on the literal bytes.
pub const CRASH_EXPECTED_RESOLVE_NAME: &str = "kernel_main";

/// Offset-into-function for the same first frame.
pub const CRASH_EXPECTED_RESOLVE_OFFSET: u64 = 0x42;

// ============================================================
// X.509 — hand-rolled minimal Ed25519 v3 certificate (TASK-060)
// ============================================================
//
// 257-byte DER-encoded X.509 v3 self-signed Ed25519 certificate.
// Hand-laid out byte-by-byte so the QEMU smoke test can prove the
// kernel's no-alloc parser walks every field of a real cert
// shape: version, serial, TBS-level sig alg, issuer SEQUENCE,
// validity (two UTCTime), subject SEQUENCE, SPKI (Ed25519
// algorithm OID + 32-byte BIT STRING), outer sig alg, signature
// BIT STRING.
//
// Layout (offsets in bytes):
//
//   [0..3]     Outer SEQUENCE header (0x30 0x81 0xFE)
//   [3..183]   TBSCertificate (180 bytes, starts with 0x30 0x81 0xB1)
//     [6..11]   version=v3 via [0] EXPLICIT INTEGER
//     [11..14]  serial INTEGER = 42 (0x2A)
//     [14..21]  TBS sig alg: id-Ed25519
//     [21..64]  Issuer Name SEQUENCE (CN = "cuttle-te-x509-kernel-fixture")
//     [64..96]  Validity (notBefore 1970-01-01, notAfter 2049-12-31)
//     [96..139] Subject Name (same CN)
//     [139..183] SubjectPublicKeyInfo (Ed25519 + 32-byte pubkey)
//   [183..190] Outer sig alg: id-Ed25519
//   [190..257] Signature BIT STRING (64 bytes Ed25519 signature)
//
// The signature value does NOT verify against the pubkey — this is
// a parser fixture, not a crypto fixture. The kernel banner asserts
// the parser recovers the field structure byte-exact, plus the
// embedded Ed25519 pubkey + Common Name.
//
// Any diversifier that perturbs the parser's recovery of those
// fields fails the banner — see `target_enterprise_kernel/src/main.rs`
// `banner_x509()`.

/// Locked DER bytes of the kernel's X.509 v3 fixture certificate.
/// 257 bytes — Ed25519 self-signed, fixed serial, fixed validity
/// window of 1970-01-01..2049-12-31.
pub const X509_FIXTURE_DER: &[u8] = &[
    // Outer SEQUENCE header (3 bytes): tag, long-form length 0xFC
    0x30, 0x81, 0xFC,
    // TBSCertificate SEQUENCE header (3 bytes): tag, long-form 0xAF
    0x30, 0x81, 0xAF,
    // version = [0] EXPLICIT INTEGER 2 (5 bytes)
    0xA0, 0x03, 0x02, 0x01, 0x02,
    // serialNumber INTEGER = 0x2A (3 bytes)
    0x02, 0x01, 0x2A,
    // TBS sig alg: SEQUENCE { OID(id-Ed25519) } (7 bytes)
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
    // Issuer Name (42 bytes): SEQUENCE { SET { SEQ { OID(CN), PrintableString } } }
    0x30, 0x28,                         // Name SEQUENCE, length 40
    0x31, 0x26,                         // RDN SET, length 38
    0x30, 0x24,                         // ATV SEQ, length 36
    0x06, 0x03, 0x55, 0x04, 0x03,       // OID(commonName) = 2.5.4.3
    0x13, 0x1D,                         // PrintableString, length 29
    // "cuttle-te-x509-kernel-fixture" — 29 bytes
    0x63, 0x75, 0x74, 0x74, 0x6C, 0x65, 0x2D,
    0x74, 0x65, 0x2D, 0x78, 0x35, 0x30, 0x39, 0x2D,
    0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x2D, 0x66,
    0x69, 0x78, 0x74, 0x75, 0x72, 0x65,
    // Validity SEQUENCE (32 bytes)
    0x30, 0x1E,
    0x17, 0x0D, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, // "700101000000Z"
    0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31,
    0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, // "491231235959Z"
    // Subject Name (42 bytes) — same CN as issuer
    0x30, 0x28, 0x31, 0x26, 0x30, 0x24,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x1D,
    0x63, 0x75, 0x74, 0x74, 0x6C, 0x65, 0x2D,
    0x74, 0x65, 0x2D, 0x78, 0x35, 0x30, 0x39, 0x2D,
    0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x2D, 0x66,
    0x69, 0x78, 0x74, 0x75, 0x72, 0x65,
    // SubjectPublicKeyInfo SEQUENCE (44 bytes)
    0x30, 0x2A,
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,    // Ed25519 alg
    0x03, 0x21, 0x00,                            // BIT STRING (32 + 1 unused-bits)
    // 32-byte pubkey (0x01..0x20)
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
    // Outer signatureAlgorithm SEQUENCE { OID(Ed25519) } (7 bytes)
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
    // Signature BIT STRING (67 bytes): 0x03 0x41 0x00 + 64 sig bytes
    0x03, 0x41, 0x00,
    // 64-byte signature: i ^ 0xA5 for i = 0..64
    0xA5, 0xA4, 0xA7, 0xA6, 0xA1, 0xA0, 0xA3, 0xA2,
    0xAD, 0xAC, 0xAF, 0xAE, 0xA9, 0xA8, 0xAB, 0xAA,
    0xB5, 0xB4, 0xB7, 0xB6, 0xB1, 0xB0, 0xB3, 0xB2,
    0xBD, 0xBC, 0xBF, 0xBE, 0xB9, 0xB8, 0xBB, 0xBA,
    0x85, 0x84, 0x87, 0x86, 0x81, 0x80, 0x83, 0x82,
    0x8D, 0x8C, 0x8F, 0x8E, 0x89, 0x88, 0x8B, 0x8A,
    0x95, 0x94, 0x97, 0x96, 0x91, 0x90, 0x93, 0x92,
    0x9D, 0x9C, 0x9F, 0x9E, 0x99, 0x98, 0x9B, 0x9A,
];

/// Expected Ed25519 public-key bytes embedded in [`X509_FIXTURE_DER`]
/// at byte offset 151. The kernel banner asserts byte-equality
/// against this constant after walking the parser-recovered SPKI.
pub const X509_FIXTURE_PUBKEY: &[u8] = &[
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
    0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10,
    0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
    0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20,
];

/// Expected Common Name string bytes inside the parsed subject DN.
/// The kernel banner uses `X509Impl::find_cn(cert.subject)` to
/// recover it and asserts byte-equality.
pub const X509_FIXTURE_SUBJECT_CN: &[u8] = b"cuttle-te-x509-kernel-fixture";

/// Expected serial-number magnitude byte. Fixture uses a 1-byte serial.
pub const X509_FIXTURE_SERIAL: u8 = 0x2A;

/// Expected `notBefore` Unix-epoch seconds for the fixture
/// (`700101000000Z` → 1970-01-01T00:00:00Z).
pub const X509_FIXTURE_NOT_BEFORE_UNIX: u64 = 0;

/// Expected `notAfter` Unix-epoch seconds for the fixture
/// (`491231235959Z` → 2049-12-31T23:59:59Z).
pub const X509_FIXTURE_NOT_AFTER_UNIX: u64 = 2_524_607_999;

