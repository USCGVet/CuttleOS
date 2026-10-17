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
//! either RFC vectors (HKDF) or hand-computed against the locked
//! algorithm contract (HashImpl, WAL framing, IOMMU walk).
//!
//! The kernel does not allocate, does not link the host std library,
//! and runs under `panic=abort`. Every check the kernel performs is
//! a `==` against one of the `EXPECTED_*` arrays here; failure path
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
pub const HKDF_EXPAND_LABEL: &[u8] = b"proteus-te-key";

/// Output length the kernel asks `hkdf_expand_label` to produce.
pub const HKDF_EXPAND_OUT_LEN: usize = 16;

/// First 8 bytes of [`HKDF_EXPAND_OUT_LEN`] bytes produced by
/// `hkdf_expand_label(prk, b"proteus-te-key", HKDF_INFO, &mut out)`.
/// Populated by `tests/kernel_fixtures_check.rs`.
pub const HKDF_EXPECTED_EXPAND_PREFIX8: [u8; 8] = [
    0x52, 0xb3, 0xc8, 0x0c, 0x79, 0x70, 0xae, 0x5f,
];

// ============================================================
// TLS — ServerHello golden round-trip
// ============================================================

/// Hand-constructed ClientHello matching the shape that
/// `target_enterprise::tls::parse_client_hello` accepts: legacy
/// version 0x0303, 32-byte zero random, empty session_id, single
/// cipher suite TLS_AES_128_GCM_SHA256, supported_versions advertising
/// TLS 1.3, key_share carrying a 32-byte x25519 public of `[7u8; 32]`.
///
/// Layout (96 bytes total):
/// - handshake header: `01 00 00 5C` (ClientHello, body_len=92)
/// - body (92 bytes): see comments at end-of-file.
pub const CLIENT_HELLO: [u8; 96] = [
    // handshake header: ClientHello, body_len = 92 = 0x5C
    0x01, 0x00, 0x00, 0x5C,
    // legacy_version
    0x03, 0x03,
    // random (32)
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    // session_id_len, cipher_suites_len, suites
    0x00,
    0x00, 0x02, 0x13, 0x01,
    // compression: count + null
    0x01, 0x00,
    // extensions_total_len = 49
    0x00, 0x31,
    // ext: supported_versions (type=0x002B, ext_len=3, body=[0x02, 0x03, 0x04])
    0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04,
    // ext: key_share (type=0x0033, ext_len=38)
    //   client_shares_len(u16)=36, entry { group=x25519(0x001D), key_len=32, key=[7u8; 32] }
    0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
    0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07, 0x07,
];

/// Deterministic 32-byte server-random the kernel passes to
/// `build_server_hello`. Locked at all-zero for byte stability.
pub const SERVER_RANDOM: [u8; 32] = [0u8; 32];

/// Deterministic 32-byte server x25519 public key. Locked at all `0x09`.
pub const SERVER_PUBKEY: [u8; 32] = [0x09u8; 32];

/// Byte length the kernel expects from `build_server_hello` against
/// the above fixtures with `selected_alpn = None`.
pub const SERVER_HELLO_EXPECTED_LEN: usize = 90;

/// First 8 bytes of the ServerHello produced from the above fixtures.
pub const SERVER_HELLO_EXPECTED_PREFIX8: [u8; 8] = [
    0x02, 0x00, 0x00, 0x56, 0x03, 0x03, 0x00, 0x00,
];

// ============================================================
// TLS 1.3 client (TASK-049) — outbound handshake fixtures
// ============================================================

/// Locked client_random fed to `build_client_hello`. All-zero for byte
/// stability (paired with TLS_CLIENT_PUBKEY below).
pub const TLS_CLIENT_RANDOM: [u8; 32] = [0u8; 32];

/// Locked client x25519 ephemeral public key. Locked at all `0x07`.
pub const TLS_CLIENT_PUBKEY: [u8; 32] = [0x07u8; 32];

/// Locked ECDHE shared secret feeding the handshake_secret derivation.
/// In a real session this is `x25519(client_priv, server_pub)`. We
/// stand it in with `[0x42; 32]` so the entire key schedule is
/// byte-deterministic without dragging in a curve25519 implementation
/// (that is a future task).
pub const TLS_SHARED_SECRET: [u8; 32] = [0x42u8; 32];

/// Byte length the kernel expects from `build_client_hello` against
/// `(TLS_CLIENT_RANDOM, TLS_CLIENT_PUBKEY)`.
///
/// Breakdown:
///   handshake header 4 +
///   legacy_version 2 + random 32 + sid_len 1 +
///   cipher_suites (2+2) + compression (1+1) +
///   ext_len 2 +
///   extensions (sv 7 + sa 12 + ks 42) = 108
pub const TLS_CLIENT_HELLO_EXPECTED_LEN: usize = 108;

/// First 8 bytes of the ClientHello produced from the locked fixtures.
/// `01 00 00 68 03 03 00 00` — handshake type 0x01 (ClientHello), body
/// length 0x000068 = 104, legacy_version 0x0303, first two of 32
/// random bytes.
pub const TLS_CLIENT_HELLO_EXPECTED_PREFIX8: [u8; 8] = [
    0x01, 0x00, 0x00, 0x68, 0x03, 0x03, 0x00, 0x00,
];

/// Hand-constructed ServerHello matching the shape the client parses.
/// Locked at 90 bytes: same layout as the test fixture in
/// `tls::tests::TEST_SERVER_HELLO`. Mirrored here so the kernel and
/// the test suite share the byte-exact input.
///
/// Layout (90 bytes total):
/// - handshake header: `02 00 00 56` (ServerHello, body_len = 86)
/// - legacy_version: `03 03`
/// - server_random (32 × `0x00`)
/// - legacy_session_id_echo: empty (`00`)
/// - cipher_suite: `13 01`
/// - legacy_compression_method: `00`
/// - extensions length: `00 2E` (46)
/// - supported_versions ext: `00 2B 00 02 03 04` (6 bytes)
/// - key_share ext: `00 33 00 24 00 1D 00 20` + 32 × `0x09`
pub const TLS_SERVER_HELLO_FIXTURE: [u8; 90] = [
    0x02, 0x00, 0x00, 0x56,
    0x03, 0x03,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00,
    0x00,
    0x13, 0x01,
    0x00,
    0x00, 0x2E,
    0x00, 0x2B, 0x00, 0x02, 0x03, 0x04,
    0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
    0x09, 0x09,
];

/// Locked HKDF-Extract output that anchors the TLS 1.3 handshake
/// secret. Mirrors `HANDSHAKE_SECRET_GOLDEN` in
/// `tls::tests`; reproduced here so the kernel assertion targets the
/// byte-exact value without crossing the test-module boundary.
pub const TLS_HANDSHAKE_SECRET_EXPECTED: [u8; 32] = [
    0xbb, 0x51, 0x8f, 0x06, 0x1c, 0x91, 0x10, 0x17,
    0xf1, 0xd2, 0x64, 0x03, 0x16, 0x55, 0x41, 0x25,
    0xae, 0xc1, 0x21, 0x03, 0x60, 0xff, 0x49, 0xb8,
    0x91, 0x94, 0x57, 0xef, 0x57, 0xae, 0xce, 0xc1,
];

/// First 8 bytes of [`TLS_HANDSHAKE_SECRET_EXPECTED`], emitted on the
/// kernel banner as `prk=<hex16>` for quick post-mortem inspection.
pub const TLS_HANDSHAKE_SECRET_PREFIX8: [u8; 8] = [
    0xbb, 0x51, 0x8f, 0x06, 0x1c, 0x91, 0x10, 0x17,
];

/// Client handshake-traffic secret. Mirrors `CLIENT_HS_TRAFFIC_GOLDEN`.
pub const TLS_CLIENT_HS_TRAFFIC_EXPECTED: [u8; 32] = [
    0x52, 0xf3, 0xd2, 0x06, 0x34, 0x12, 0x0d, 0x17,
    0xc4, 0x62, 0x28, 0x39, 0x9b, 0x69, 0x69, 0x2d,
    0x69, 0x96, 0x54, 0x4a, 0x64, 0x5f, 0xc1, 0x48,
    0x2e, 0x0b, 0xe8, 0x4c, 0x60, 0x4c, 0xf7, 0xa2,
];

/// Server handshake-traffic secret. Mirrors `SERVER_HS_TRAFFIC_GOLDEN`.
pub const TLS_SERVER_HS_TRAFFIC_EXPECTED: [u8; 32] = [
    0x85, 0x91, 0x69, 0x4b, 0x50, 0xd6, 0x4a, 0x5f,
    0x0f, 0x8f, 0x23, 0xf6, 0x1f, 0x10, 0x62, 0xb4,
    0xa9, 0xa9, 0xe0, 0xad, 0xa0, 0x58, 0x1b, 0xc1,
    0xe7, 0x3a, 0x6f, 0x61, 0x17, 0x46, 0x6f, 0xfd,
];

/// Synthetic transcript hash for the client Finished MAC banner. The
/// real protocol uses SHA-256 over CH..server_Finished; this fixture
/// is a constant 32 × `0xAB` byte block so the verify_data is
/// reproducible without packaging the full handshake transcript.
pub const TLS_FINISHED_TRANSCRIPT_HASH: [u8; 32] = [0xABu8; 32];

/// Client Finished verify_data computed against
/// `(TLS_CLIENT_HS_TRAFFIC_EXPECTED, TLS_FINISHED_TRANSCRIPT_HASH)`.
/// Mirrors `CLIENT_FINISHED_GOLDEN` in the tls test module.
pub const TLS_CLIENT_FINISHED_EXPECTED: [u8; 32] = [
    0xf6, 0xd3, 0x7f, 0x34, 0x5e, 0xe9, 0x64, 0xd2,
    0x52, 0x7d, 0xed, 0x19, 0x7f, 0xb0, 0x7e, 0x62,
    0x7d, 0x44, 0x56, 0x5b, 0x6a, 0x26, 0x16, 0xb5,
    0x52, 0xc7, 0xca, 0x0e, 0xb2, 0xfd, 0xad, 0x65,
];

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
pub const HASH_INPUT: &[u8] = b"proteus-te-fixture-2026-05-16";

/// Expected 32-byte digest produced by `HashImpl::hash(HASH_INPUT, &mut out)`.
/// HashImpl is the locked Fletcher-32-chained construction described in
/// `target_enterprise/src/lib.rs::HashImpl`. Populated by
/// `tests/kernel_fixtures_check.rs`.
pub const HASH_EXPECTED: [u8; 32] = [
    0xe7, 0xb1, 0x71, 0xa1, 0xe8, 0xb3, 0x72, 0xa2, 0xe9, 0xb5, 0x73, 0xa3, 0xea, 0xb7, 0x74, 0xa4,
    0xeb, 0xb9, 0x75, 0xa5, 0xec, 0xbb, 0x76, 0xa6, 0xed, 0xbd, 0x77, 0xa7, 0xee, 0xbf, 0x78, 0xa8,
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
pub const NET_PAYLOAD: &[u8] = b"proteus-te";

/// Expected total datagram length: 20 (IPv4) + 8 (UDP) + 10 (payload).
pub const NET_EXPECTED_LEN: usize = 38;

/// Locked golden bytes for the canonical UDP/IPv4 datagram.
///
/// Computed by `target_enterprise::net::build_udp_datagram` against
/// the constants above. The `kernel_fixtures_check` host test asserts
/// this byte-for-byte AND the bare-metal kernel asserts the same on
/// boot before emitting the `NET build OK len=38 …` banner. Any morph
/// candidate that drifts from this byte string fails both shadows.
pub const NET_EXPECTED_DATAGRAM: [u8; NET_EXPECTED_LEN] = [
    // IPv4 header
    0x45, 0x00, // version/IHL, DSCP/ECN
    0x00, 0x26, // total_length = 38
    0xBE, 0xEF, // identification
    0x40, 0x00, // flags=DF, frag=0
    0x40, // TTL = 64
    0x11, // protocol = UDP (17)
    0x63, 0xC7, // header checksum (RFC 1071)
    0x0A, 0x00, 0x02, 0x0F, // src_ip = 10.0.2.15
    0x0A, 0x00, 0x02, 0x02, // dst_ip = 10.0.2.2
    // UDP header
    0xC0, 0x00, // src_port = 49152
    0x00, 0x35, // dst_port = 53
    0x00, 0x12, // length = 18 = UDP_HEADER(8) + PAYLOAD(10)
    0xFA, 0x94, // UDP checksum (RFC 768)
    // Payload "proteus-te"
    b'p', b'r', b'o', b't', b'e', b'u', b's', b'-', b't', b'e',
];

/// Expected IPv4 header checksum (host order) — exposed separately so
/// the kernel banner can hex-encode it for the serial log.
pub const NET_EXPECTED_IP_CHECKSUM: u16 = 0x63C7;

/// Expected UDP checksum (host order).
pub const NET_EXPECTED_UDP_CHECKSUM: u16 = 0xFA94;

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
pub const CRASH_KMSG: &[u8] = b"[INFO ] proteus-te boot\n[WARN ] scheduler queue near full\n";

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
pub const CRASH_EXPECTED_CRC32C: u32 = 0x8FB6_EB0E;

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
//     [21..64]  Issuer Name SEQUENCE (CN = "proteus-te-x509-kernel-fixture")
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
    // Outer SEQUENCE header (3 bytes): tag, long-form length 0xFE
    0x30, 0x81, 0xFE,
    // TBSCertificate SEQUENCE header (3 bytes): tag, long-form 0xB1
    0x30, 0x81, 0xB1,
    // version = [0] EXPLICIT INTEGER 2 (5 bytes)
    0xA0, 0x03, 0x02, 0x01, 0x02,
    // serialNumber INTEGER = 0x2A (3 bytes)
    0x02, 0x01, 0x2A,
    // TBS sig alg: SEQUENCE { OID(id-Ed25519) } (7 bytes)
    0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
    // Issuer Name (43 bytes): SEQUENCE { SET { SEQ { OID(CN), PrintableString } } }
    0x30, 0x29,                         // Name SEQUENCE, length 41
    0x31, 0x27,                         // RDN SET, length 39
    0x30, 0x25,                         // ATV SEQ, length 37
    0x06, 0x03, 0x55, 0x04, 0x03,       // OID(commonName) = 2.5.4.3
    0x13, 0x1E,                         // PrintableString, length 30
    // "proteus-te-x509-kernel-fixture" — 30 bytes
    0x70, 0x72, 0x6F, 0x74, 0x65, 0x75, 0x73, 0x2D,
    0x74, 0x65, 0x2D, 0x78, 0x35, 0x30, 0x39, 0x2D,
    0x6B, 0x65, 0x72, 0x6E, 0x65, 0x6C, 0x2D, 0x66,
    0x69, 0x78, 0x74, 0x75, 0x72, 0x65,
    // Validity SEQUENCE (32 bytes)
    0x30, 0x1E,
    0x17, 0x0D, 0x37, 0x30, 0x30, 0x31, 0x30, 0x31,
    0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, // "700101000000Z"
    0x17, 0x0D, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31,
    0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5A, // "491231235959Z"
    // Subject Name (43 bytes) — same CN as issuer
    0x30, 0x29, 0x31, 0x27, 0x30, 0x25,
    0x06, 0x03, 0x55, 0x04, 0x03,
    0x13, 0x1E,
    0x70, 0x72, 0x6F, 0x74, 0x65, 0x75, 0x73, 0x2D,
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
pub const X509_FIXTURE_SUBJECT_CN: &[u8] = b"proteus-te-x509-kernel-fixture";

/// Expected serial-number magnitude byte. Fixture uses a 1-byte serial.
pub const X509_FIXTURE_SERIAL: u8 = 0x2A;

/// Expected `notBefore` Unix-epoch seconds for the fixture
/// (`700101000000Z` → 1970-01-01T00:00:00Z).
pub const X509_FIXTURE_NOT_BEFORE_UNIX: u64 = 0;

/// Expected `notAfter` Unix-epoch seconds for the fixture
/// (`491231235959Z` → 2049-12-31T23:59:59Z).
pub const X509_FIXTURE_NOT_AFTER_UNIX: u64 = 2_524_607_999;

