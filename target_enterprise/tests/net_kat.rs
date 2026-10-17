//! Known-Answer Tests for the in-target UDP/IPv4 network module.
//!
//! These tests lock the wire-observable surface introduced by TASK-011.
//!
//! 1. **Golden-bytes test** — a canonical
//!    `(src_ip, dst_ip, src_port, dst_port, payload, ttl, ident)`
//!    tuple is fed to `build_udp_datagram`. The resulting 28+N bytes
//!    are compared byte-for-byte against the constant captured below.
//!    A morph candidate that drifts from this output is rejected.
//!
//! 2. **Cross-cycle stability** — the same tuple is fed to the builder
//!    five times in a row. Every emission must be byte-identical. This
//!    encodes the wire-equivalence contract for an in-process repeat
//!    invocation; the diversifier round-trip in
//!    `diversifier/tests/net_diversify_roundtrip.rs` extends the
//!    same property across morph cycles of the source.
//!
//! 3. **Parser-strictness coverage** — a small battery of malformed
//!    inputs exercises the documented rejection variants.
//!
//! 4. **Trait + free function agreement** — every wire-level routine
//!    is reachable through both the [`proteus_contracts::NetStack`]
//!    trait surface and the corresponding free function. The two MUST
//!    produce identical outputs on every input.

use proteus_contracts::{ipv4_flags, NetError, NetStack, IP_PROTO_UDP};
use target_enterprise::net::{
    build_udp_datagram, ipv4_header_checksum, parse_ipv4_header, parse_udp_datagram, udp_checksum,
    IPV4_CHECKSUM_OFFSET, IPV4_FLAGS_FRAG_OFFSET, IPV4_HEADER_LEN, IPV4_PROTO_OFFSET,
    IPV4_TTL_OFFSET, NetStackImpl, UDP_CHECKSUM_OFFSET, UDP_HEADER_LEN,
};

// ============================================================
// Canonical inputs for the golden-bytes lock
// ============================================================

const SRC_IP: [u8; 4] = [10, 0, 2, 15];
const DST_IP: [u8; 4] = [10, 0, 2, 2];
const SRC_PORT: u16 = 49152;
const DST_PORT: u16 = 53;
const PAYLOAD: &[u8] = b"proteus-te";
const TTL: u8 = 64;
const IDENT: u16 = 0xBEEF;

/// Captured wire bytes for the canonical tuple. Computed by running
/// `build_udp_datagram` once with the locked surface; future morph
/// cycles MUST reproduce this byte-for-byte.
///
/// Layout (38 bytes total: 20 IPv4 + 8 UDP + 10 payload):
///
/// - `0x45 0x00`                — version/IHL=0x45, DSCP/ECN=0
/// - `0x00 0x26`                — total_length = 38
/// - `0xBE 0xEF`                — identification
/// - `0x40 0x00`                — flags=DF, fragment_offset=0
/// - `0x40`                     — TTL = 64
/// - `0x11`                     — protocol = 17 (UDP)
/// - `0xAC 0x7B`                — header checksum (locked here)
/// - `0x0A 0x00 0x02 0x0F`      — src_ip = 10.0.2.15
/// - `0x0A 0x00 0x02 0x02`      — dst_ip = 10.0.2.2
/// - `0xC0 0x00`                — UDP src_port = 49152
/// - `0x00 0x35`                — UDP dst_port = 53
/// - `0x00 0x12`                — UDP length = 18
/// - `0x?? 0x??`                — UDP checksum (locked here)
/// - `"proteus-te"`             — payload (10 bytes)
///
/// The header_checksum and UDP checksum bytes are filled in by running
/// the impl once and capturing the values. Both are derived
/// deterministically from the other inputs (no entropy / time source),
/// so a future morph that produces different bytes IS a regression.
const GOLDEN_DATAGRAM: [u8; 38] = [
    // IPv4 header
    0x45, 0x00, // version/IHL, DSCP/ECN
    0x00, 0x26, // total_length = 38
    0xBE, 0xEF, // identification
    0x40, 0x00, // flags=DF, frag=0
    0x40, // TTL
    0x11, // protocol = UDP
    0x63, 0xC7, // header checksum (RFC 1071 over the locked bytes)
    0x0A, 0x00, 0x02, 0x0F, // src_ip
    0x0A, 0x00, 0x02, 0x02, // dst_ip
    // UDP header
    0xC0, 0x00, // src_port = 49152
    0x00, 0x35, // dst_port = 53
    0x00, 0x12, // length = 18
    0xFA, 0x94, // checksum (RFC 768 over pseudo-header + segment)
    // Payload
    b'p', b'r', b'o', b't', b'e', b'u', b's', b'-', b't', b'e',
];

// ============================================================
// Golden-bytes lock
// ============================================================

#[test]
fn build_emits_golden_bytes() {
    let mut buf = [0u8; 128];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build canonical");
    assert_eq!(n, GOLDEN_DATAGRAM.len(), "datagram length");
    assert_eq!(
        &buf[..n],
        &GOLDEN_DATAGRAM[..],
        "byte-exact match against locked golden datagram"
    );
}

#[test]
fn build_via_trait_emits_golden_bytes() {
    // The trait routes to the free function but must produce identical
    // output — exercise both paths.
    let mut buf = [0u8; 128];
    let n = <NetStackImpl as NetStack>::build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("trait build");
    assert_eq!(&buf[..n], &GOLDEN_DATAGRAM[..]);
}

// ============================================================
// Cross-cycle stability (the per-process wire-equivalence proof)
// ============================================================

#[test]
fn five_invocations_produce_identical_bytes() {
    // The diversifier round-trip in diversifier/tests covers the
    // morph-cycle dimension. This test proves the simpler "no
    // hidden state between invocations" property: five back-to-back
    // builds with the same inputs yield byte-identical output.
    let mut prev: Option<[u8; 64]> = None;
    let mut prev_len = 0usize;
    for cycle in 0..5 {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
        )
        .unwrap_or_else(|e| panic!("cycle {} build: {:?}", cycle, e));
        if let Some(p) = prev {
            assert_eq!(
                &p[..prev_len],
                &buf[..n],
                "cycle {} produced different bytes than cycle 0",
                cycle
            );
        }
        prev = Some(buf);
        prev_len = n;
    }
}

// ============================================================
// Round-trip — built bytes parse cleanly back to their inputs
// ============================================================

#[test]
fn round_trip_recovers_all_fields() {
    let mut buf = [0u8; 128];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    let ip = parse_ipv4_header(&buf[..n]).expect("parse ipv4");
    assert_eq!(ip.src_ip, SRC_IP);
    assert_eq!(ip.dst_ip, DST_IP);
    assert_eq!(ip.ttl, TTL);
    assert_eq!(ip.identification, IDENT);
    assert_eq!(ip.protocol, IP_PROTO_UDP);
    assert_eq!(ip.flags, ipv4_flags::DF);
    assert_eq!(ip.total_length as usize, n);

    let udp =
        parse_udp_datagram(SRC_IP, DST_IP, &buf[IPV4_HEADER_LEN..n]).expect("parse udp");
    assert_eq!(udp.src_port, SRC_PORT);
    assert_eq!(udp.dst_port, DST_PORT);
    assert_eq!(udp.payload_len, PAYLOAD.len());
    let payload =
        &buf[IPV4_HEADER_LEN + udp.payload_off..IPV4_HEADER_LEN + udp.payload_off + udp.payload_len];
    assert_eq!(payload, PAYLOAD);
}

// ============================================================
// Parser strictness — each documented rejection variant
// ============================================================

#[test]
fn header_checksum_self_validates() {
    // A freshly built datagram MUST parse cleanly — that is the
    // simplest expression of "the builder's checksum agrees with
    // the parser's checksum".
    let mut buf = [0u8; 128];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    parse_ipv4_header(&buf[..n]).expect("parse should accept own output");
}

#[test]
fn malformed_inputs_match_documented_variants() {
    // Truncated.
    assert_eq!(parse_ipv4_header(&[0x45]), Err(NetError::Truncated));

    // Bad version (IPv6).
    let mut hdr = [0u8; IPV4_HEADER_LEN];
    hdr[0] = 0x65;
    hdr[3] = IPV4_HEADER_LEN as u8;
    assert_eq!(parse_ipv4_header(&hdr), Err(NetError::BadVersion));

    // Bad header length (IHL=4).
    let mut hdr = [0u8; IPV4_HEADER_LEN];
    hdr[0] = 0x44;
    hdr[3] = IPV4_HEADER_LEN as u8;
    assert_eq!(parse_ipv4_header(&hdr), Err(NetError::BadHeaderLength));

    // Options present (IHL=6).
    let mut hdr = [0u8; IPV4_HEADER_LEN];
    hdr[0] = 0x46;
    hdr[3] = IPV4_HEADER_LEN as u8;
    assert_eq!(parse_ipv4_header(&hdr), Err(NetError::OptionsPresent));

    // Bad total_length (says 40, but slice is 20).
    let mut hdr = [0u8; IPV4_HEADER_LEN];
    hdr[0] = 0x45;
    hdr[3] = 40;
    assert_eq!(parse_ipv4_header(&hdr), Err(NetError::BadTotalLength));
}

#[test]
fn fragmented_packet_rejected() {
    let mut buf = [0u8; 64];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    // Set MF bit. MF = bit 5 of byte 6 (flag bit 0).
    buf[IPV4_FLAGS_FRAG_OFFSET] |= ipv4_flags::MF << 5;
    // Refresh header checksum.
    buf[IPV4_CHECKSUM_OFFSET] = 0;
    buf[IPV4_CHECKSUM_OFFSET + 1] = 0;
    let cksum = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
    buf[IPV4_CHECKSUM_OFFSET] = (cksum >> 8) as u8;
    buf[IPV4_CHECKSUM_OFFSET + 1] = (cksum & 0xFF) as u8;

    assert_eq!(parse_ipv4_header(&buf[..n]), Err(NetError::Fragmented));
}

#[test]
fn ttl_zero_rejected() {
    let mut buf = [0u8; 64];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    buf[IPV4_TTL_OFFSET] = 0;
    buf[IPV4_CHECKSUM_OFFSET] = 0;
    buf[IPV4_CHECKSUM_OFFSET + 1] = 0;
    let cksum = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
    buf[IPV4_CHECKSUM_OFFSET] = (cksum >> 8) as u8;
    buf[IPV4_CHECKSUM_OFFSET + 1] = (cksum & 0xFF) as u8;
    assert_eq!(parse_ipv4_header(&buf[..n]), Err(NetError::HopLimitZero));
}

#[test]
fn protocol_not_udp_reflected_in_view() {
    // The IPv4 parser itself doesn't reject non-UDP protocols — that
    // is left to the caller's protocol-dispatch. But the view should
    // surface the byte faithfully so a switch on `protocol` works.
    let mut buf = [0u8; 64];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    buf[IPV4_PROTO_OFFSET] = 6; // TCP, not UDP
    buf[IPV4_CHECKSUM_OFFSET] = 0;
    buf[IPV4_CHECKSUM_OFFSET + 1] = 0;
    let cksum = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
    buf[IPV4_CHECKSUM_OFFSET] = (cksum >> 8) as u8;
    buf[IPV4_CHECKSUM_OFFSET + 1] = (cksum & 0xFF) as u8;
    let ip = parse_ipv4_header(&buf[..n]).expect("parse non-UDP");
    assert_eq!(ip.protocol, 6);
}

#[test]
fn udp_zero_checksum_rejected() {
    let mut buf = [0u8; 64];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    let udp_start = IPV4_HEADER_LEN;
    buf[udp_start + UDP_CHECKSUM_OFFSET] = 0;
    buf[udp_start + UDP_CHECKSUM_OFFSET + 1] = 0;
    assert_eq!(
        parse_udp_datagram(SRC_IP, DST_IP, &buf[IPV4_HEADER_LEN..n]),
        Err(NetError::BadUdpChecksum)
    );
}

#[test]
fn udp_checksum_must_validate_against_pseudo_header() {
    // Build with one src_ip, then parse claiming a different src_ip:
    // the pseudo-header changes, so the checksum no longer agrees.
    let mut buf = [0u8; 64];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .expect("build");
    let wrong_src = [99, 99, 99, 99];
    assert_eq!(
        parse_udp_datagram(wrong_src, DST_IP, &buf[IPV4_HEADER_LEN..n]),
        Err(NetError::BadUdpChecksum)
    );
}

#[test]
fn empty_payload_emits_28_byte_datagram() {
    let mut buf = [0u8; 28];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, &[], TTL, IDENT, &mut buf,
    )
    .expect("build empty");
    assert_eq!(n, 28);
    let ip = parse_ipv4_header(&buf[..n]).expect("parse empty");
    assert_eq!(ip.total_length, 28);
    let udp =
        parse_udp_datagram(SRC_IP, DST_IP, &buf[IPV4_HEADER_LEN..n]).expect("parse udp empty");
    assert_eq!(udp.length, 8);
    assert_eq!(udp.payload_len, 0);
}

#[test]
fn max_size_payload_round_trips() {
    // Maximum payload that fits in a single un-fragmented IPv4
    // datagram. We use a 1472-byte payload (the standard MTU minus
    // headers, i.e. what fits on stock Ethernet) — verifies the
    // builder/parser handle realistic kernel-sized buffers.
    const N: usize = 1472;
    let payload = [0xA5u8; N];
    let mut buf = [0u8; IPV4_HEADER_LEN + UDP_HEADER_LEN + N];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, &payload, TTL, IDENT, &mut buf,
    )
    .expect("build mtu");
    assert_eq!(n, buf.len());
    let ip = parse_ipv4_header(&buf[..n]).expect("parse mtu");
    assert_eq!(ip.total_length as usize, n);
    let udp =
        parse_udp_datagram(SRC_IP, DST_IP, &buf[IPV4_HEADER_LEN..n]).expect("parse udp mtu");
    assert_eq!(udp.payload_len, N);
}

#[test]
fn checksum_free_function_and_trait_agree() {
    let mut buf = [0u8; 64];
    let n = build_udp_datagram(
        SRC_IP, DST_IP, SRC_PORT, DST_PORT, PAYLOAD, TTL, IDENT, &mut buf,
    )
    .unwrap();
    let hdr_via_fn = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
    let hdr_via_trait =
        <NetStackImpl as NetStack>::ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
    assert_eq!(hdr_via_fn, hdr_via_trait);

    let udp_via_fn = udp_checksum(SRC_IP, DST_IP, &buf[IPV4_HEADER_LEN..n]);
    let udp_via_trait =
        <NetStackImpl as NetStack>::udp_checksum(SRC_IP, DST_IP, &buf[IPV4_HEADER_LEN..n]);
    assert_eq!(udp_via_fn, udp_via_trait);
}

#[test]
fn bitwise_field_extraction_matches_rfc791_layout() {
    // Independent decoder: parse the locked golden bytes by hand,
    // bit-by-bit, and verify every field. This is the cross-check
    // that the in-tree parser hasn't drifted from the RFC.
    let buf = &GOLDEN_DATAGRAM;
    assert_eq!(buf[0] >> 4, 4, "version");
    assert_eq!(buf[0] & 0x0F, 5, "IHL");
    let total_length = ((buf[2] as u16) << 8) | (buf[3] as u16);
    assert_eq!(total_length as usize, buf.len());
    let ident = ((buf[4] as u16) << 8) | (buf[5] as u16);
    assert_eq!(ident, IDENT);
    assert_eq!(buf[6] >> 5, ipv4_flags::DF, "DF flag set");
    assert_eq!(buf[8], TTL);
    assert_eq!(buf[9], IP_PROTO_UDP);
    assert_eq!(&buf[12..16], &SRC_IP);
    assert_eq!(&buf[16..20], &DST_IP);
    let src_port = ((buf[20] as u16) << 8) | (buf[21] as u16);
    assert_eq!(src_port, SRC_PORT);
    let dst_port = ((buf[22] as u16) << 8) | (buf[23] as u16);
    assert_eq!(dst_port, DST_PORT);
    let udp_len = ((buf[24] as u16) << 8) | (buf[25] as u16);
    assert_eq!(udp_len as usize, UDP_HEADER_LEN + PAYLOAD.len());
    assert_eq!(&buf[28..38], PAYLOAD);
}
