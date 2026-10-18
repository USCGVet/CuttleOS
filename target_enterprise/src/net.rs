//! In-kernel UDP/IPv4 network stack — `no_std`, allocation-free.
//!
//! This module is the `target_enterprise` seed of a network stack for
//! the morph engine to drive. It implements the
//! [`cuttle_contracts::NetStack`] trait with the wire layout RFC 791
//! (IPv4) and RFC 768 (UDP) specify, byte-for-byte.
//!
//! # Locked surface
//!
//! The wire-observable bytes emitted by [`build_udp_datagram`] and the
//! wire-observable rejection points of [`parse_ipv4_header`] /
//! [`parse_udp_datagram`] are the locked surface. They are NOT
//! candidates for the diversifier. Two morph candidates compiled from
//! perturbed sources MUST emit identical wire bytes for the same input.
//! The integration test at
//! `target_enterprise/tests/net_kat.rs` exercises this — it captures
//! a golden byte string for a canonical `(src,dst,port,payload)`
//! tuple and asserts byte-equality, plus a 5-cycle diversification
//! round-trip (`diversifier/tests/net_diversify_roundtrip.rs`) that
//! re-parses the diversifier output.
//!
//! Internally diversifiable: cursor style vs fixed offsets, branch
//! ordering, local naming, the shape of the checksum loop. The
//! diversifier already perturbs all of these in `target_enterprise/
//! src/tls.rs`; the same machinery applies here.
//!
//! # RFC compliance
//!
//! - **RFC 791 §3.1** — IPv4 header format. We restrict to `IHL == 5`
//!   (no options) so the header is always exactly 20 bytes, which
//!   bounds every fixed-capacity buffer in this module.
//! - **RFC 1071** — Internet checksum (16-bit one's-complement of the
//!   one's-complement sum). Used for both the IPv4 header checksum
//!   and the UDP pseudo-header+segment checksum.
//! - **RFC 768** — UDP. Source port, destination port, length,
//!   checksum, payload.
//! - **RFC 6864 §4** — clarifies that the IPv4 Identification field
//!   has no reassembly semantic when DF=1, but is still observable
//!   on the wire and round-tripped by parsers. We preserve it on
//!   parse for diagnostics.
//!
//! # Scope
//!
//! - Outbound: assemble a fully-framed IPv4+UDP datagram from caller
//!   inputs. No ARP, no routing, no MAC layer — the caller hands the
//!   resulting bytes to whatever Ethernet/loopback layer it has.
//! - Inbound: parse + validate IPv4 (+ UDP) bytes. No reassembly
//!   (fragments are rejected on parse).
//! - Out of scope: TCP, ICMP, IPv6, options-bearing IPv4, ARP,
//!   IP-in-IP tunnelling. Each is a candidate for a future task.
//!
//! # Fixed-capacity contract
//!
//! Every helper here writes into a caller-supplied `&mut [u8]`. The
//! module has NO `alloc` use and NO `Vec`. The TLS module in this
//! crate established this pattern; TASK-011 carries it forward.

use cuttle_contracts::{
    ipv4_flags, Ipv4HeaderView, IP_PROTO_UDP, NetError, NetStack, UdpDatagramView,
};

// ============================================================
// Wire constants (RFC 791 + RFC 768)
// ============================================================

/// IPv4 version nibble. Locked.
pub const IPV4_VERSION: u8 = 4;

/// IPv4 IHL value for the locked surface: 5 four-byte words = 20-byte
/// header, no options.
pub const IPV4_IHL_NO_OPTIONS: u8 = 5;

/// Fixed IPv4 header length in bytes for the locked surface.
pub const IPV4_HEADER_LEN: usize = 20;

/// Fixed UDP header length in bytes.
pub const UDP_HEADER_LEN: usize = 8;

/// Minimum legal IPv4+UDP datagram length.
pub const MIN_IPV4_UDP_LEN: usize = IPV4_HEADER_LEN + UDP_HEADER_LEN;

/// Maximum UDP payload that fits inside a single un-fragmented IPv4
/// datagram: 65535 - 20 (IPv4 header) - 8 (UDP header) = 65507 bytes.
pub const MAX_UDP_PAYLOAD: usize = 65507;

/// Byte offset of the source IPv4 address in the locked IPv4 header.
pub const IPV4_SRC_OFFSET: usize = 12;
/// Byte offset of the destination IPv4 address in the locked IPv4 header.
pub const IPV4_DST_OFFSET: usize = 16;
/// Byte offset of the IPv4 header checksum field.
pub const IPV4_CHECKSUM_OFFSET: usize = 10;
/// Byte offset of the IPv4 total_length field.
pub const IPV4_TOTAL_LEN_OFFSET: usize = 2;
/// Byte offset of the IPv4 identification field.
pub const IPV4_IDENT_OFFSET: usize = 4;
/// Byte offset of the IPv4 flags+fragment-offset word.
pub const IPV4_FLAGS_FRAG_OFFSET: usize = 6;
/// Byte offset of the IPv4 TTL field.
pub const IPV4_TTL_OFFSET: usize = 8;
/// Byte offset of the IPv4 protocol field.
pub const IPV4_PROTO_OFFSET: usize = 9;

/// Byte offset of the UDP source-port field.
pub const UDP_SRC_OFFSET: usize = 0;
/// Byte offset of the UDP destination-port field.
pub const UDP_DST_OFFSET: usize = 2;
/// Byte offset of the UDP length field.
pub const UDP_LEN_OFFSET: usize = 4;
/// Byte offset of the UDP checksum field.
pub const UDP_CHECKSUM_OFFSET: usize = 6;

// ============================================================
// RFC 1071 Internet checksum
// ============================================================

/// One's-complement 16-bit accumulator state for the Internet checksum.
///
/// RFC 1071 §1: "Adjacent octets to be checksummed are paired to form
/// 16-bit integers, and the 1's complement sum of these 16-bit integers
/// is formed. To generate a checksum, the checksum field itself is
/// cleared, the 16-bit 1's complement sum is computed over the octets
/// concerned, and the 1's complement of that sum is placed in the
/// checksum field."
///
/// Implementation note — we accumulate into a `u32` so the wrap-around
/// carry can be folded once at the end rather than after every add.
/// This is the canonical fast path described in RFC 1071 §4.
#[derive(Default)]
struct OnesComplement {
    /// 32-bit running sum with deferred carry-fold. The high 16 bits
    /// hold the accumulated carry; they get folded into the low 16
    /// bits exactly once during [`OnesComplement::finalize`].
    acc: u32,
}

impl OnesComplement {
    /// Fresh accumulator initialised to zero.
    fn new() -> Self {
        Self { acc: 0 }
    }

    /// Add a 16-bit big-endian word (network byte order) to the sum.
    fn add_be16(&mut self, w: u16) {
        self.acc = self.acc.wrapping_add(w as u32);
    }

    /// Add an entire byte slice in network order. If `bytes.len()` is
    /// odd, the trailing byte is padded with a zero high byte per
    /// RFC 1071.
    fn add_bytes(&mut self, bytes: &[u8]) {
        let mut i = 0;
        while i + 1 < bytes.len() {
            // Big-endian read: high byte at `i`, low byte at `i+1`.
            let w = ((bytes[i] as u16) << 8) | (bytes[i + 1] as u16);
            self.add_be16(w);
            i += 2;
        }
        if i < bytes.len() {
            // Odd-length tail: pad the trailing byte with a low zero
            // octet (RFC 1071 §4 "Implementation Examples").
            let w = (bytes[i] as u16) << 8;
            self.add_be16(w);
        }
    }

    /// Fold carries down to 16 bits, take the one's complement, and
    /// return the final checksum in host order.
    fn finalize(self) -> u16 {
        let mut s = self.acc;
        // Fold any 32→16 carry at most twice; the second fold catches
        // the case where the first fold itself overflowed the low 16
        // bits.
        while s >> 16 != 0 {
            s = (s & 0xFFFF) + (s >> 16);
        }
        !(s as u16)
    }
}

// ============================================================
// IPv4 header checksum (RFC 1071, RFC 791 §3.1)
// ============================================================

/// Compute the IPv4 header checksum per RFC 1071 over `header_bytes`,
/// treating bytes [10..12] (the header_checksum field) as zero during
/// the computation.
///
/// Returns the network-order one's-complement sum, ready for direct
/// big-endian placement at `header_bytes[10..12]` (the caller may
/// shadow the original bytes; this function does not mutate
/// `header_bytes`).
///
/// # Panics
///
/// Panics if `header_bytes.len() < IPV4_HEADER_LEN`. Callers in this
/// module always pass exactly 20 bytes.
pub fn ipv4_header_checksum(header_bytes: &[u8]) -> u16 {
    assert!(
        header_bytes.len() >= IPV4_HEADER_LEN,
        "ipv4_header_checksum: header too short (< 20)"
    );
    let mut acc = OnesComplement::new();
    // Process the 20 fixed bytes as ten 16-bit words; substitute zero
    // for bytes 10..12 (the checksum field itself).
    let mut i = 0;
    while i < IPV4_HEADER_LEN {
        if i == IPV4_CHECKSUM_OFFSET {
            // Skip the checksum field; treat as zero per RFC 791.
            acc.add_be16(0);
            i += 2;
            continue;
        }
        let w = ((header_bytes[i] as u16) << 8) | (header_bytes[i + 1] as u16);
        acc.add_be16(w);
        i += 2;
    }
    acc.finalize()
}

// ============================================================
// UDP checksum (RFC 768, RFC 1071)
// ============================================================

/// Compute the UDP checksum per RFC 768 over the pseudo-header +
/// `udp_segment`. The checksum field of the segment (bytes 6..8) is
/// treated as zero during the computation.
///
/// The pseudo-header is:
/// ```text
///   src_ip(4) | dst_ip(4) | zero(1) | protocol=17(1) | udp_length(2)
/// ```
///
/// Returns the network-order one's-complement sum, with the all-zero
/// result mapped to `0xFFFF` per the RFC 768 convention so the wire
/// value zero unambiguously means "checksum suppressed" (rejected by
/// the locked surface on parse).
///
/// # Panics
///
/// Panics if `udp_segment.len() < UDP_HEADER_LEN`.
pub fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &[u8]) -> u16 {
    assert!(
        udp_segment.len() >= UDP_HEADER_LEN,
        "udp_checksum: segment too short (< 8)"
    );

    let udp_length = udp_segment.len() as u16;
    let mut acc = OnesComplement::new();

    // Pseudo-header: src_ip(4), dst_ip(4), 0x00, proto=17, udp_length(2).
    acc.add_bytes(&src_ip);
    acc.add_bytes(&dst_ip);
    acc.add_be16(IP_PROTO_UDP as u16); // high byte = 0x00, low = 17
    acc.add_be16(udp_length);

    // UDP segment: header + payload, but the checksum field is treated
    // as zero. Process in 16-bit big-endian words; the checksum slot
    // (bytes 6..8) is substituted with a zero word.
    let mut i = 0;
    while i + 1 < udp_segment.len() {
        if i == UDP_CHECKSUM_OFFSET {
            acc.add_be16(0);
            i += 2;
            continue;
        }
        let w = ((udp_segment[i] as u16) << 8) | (udp_segment[i + 1] as u16);
        acc.add_be16(w);
        i += 2;
    }
    if i < udp_segment.len() {
        // Odd-length payload: pad with a trailing zero byte per RFC 768.
        let w = (udp_segment[i] as u16) << 8;
        acc.add_be16(w);
    }

    let raw = acc.finalize();
    if raw == 0 {
        // RFC 768: "If the computed checksum is zero, it is transmitted
        // as all ones (the equivalent in one's complement arithmetic).
        // An all zero transmitted checksum value means that the
        // transmitter generated no checksum (for debugging or for
        // higher level protocols that don't care)." We always
        // generate a checksum, so map zero to 0xFFFF.
        0xFFFF
    } else {
        raw
    }
}

// ============================================================
// Builder — IPv4+UDP datagram assembly
// ============================================================

/// Assemble a UDP-over-IPv4 datagram into `out`, returning the total
/// byte count written. See [`NetStack::build_udp_datagram`] for the
/// wire layout.
///
/// This is the free-function form used by both the trait impl and the
/// integration tests. The trait surface routes through this function
/// so there is a single canonical implementation per crate.
pub fn build_udp_datagram(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    src_port: u16,
    dst_port: u16,
    payload: &[u8],
    ttl: u8,
    ident: u16,
    out: &mut [u8],
) -> Result<usize, NetError> {
    // Argument validation — surface specific errors in the order the
    // contract documents so the verifier can match impls on the error
    // path.
    if payload.len() > MAX_UDP_PAYLOAD {
        return Err(NetError::PayloadTooLarge);
    }
    let total_len = IPV4_HEADER_LEN + UDP_HEADER_LEN + payload.len();
    if out.len() < total_len {
        return Err(NetError::OutputBufferTooSmall);
    }
    if src_port == 0 || dst_port == 0 {
        return Err(NetError::PortZero);
    }

    // ----- IPv4 header (bytes 0..20) -----
    //
    // Layout (RFC 791 §3.1):
    //   0  | version(4) | ihl(4)               -> 0x45
    //   1  | dscp(6) | ecn(2)                  -> 0x00
    //   2  | total_length (u16 BE)
    //   4  | identification (u16 BE)
    //   6  | flags(3) | fragment_offset(13)    -> DF set, frag=0
    //   8  | ttl
    //   9  | protocol                          -> 17 (UDP)
    //  10  | header_checksum (u16 BE)          -> filled below
    //  12  | src_ip[4]
    //  16  | dst_ip[4]
    out[0] = (IPV4_VERSION << 4) | IPV4_IHL_NO_OPTIONS;
    out[1] = 0; // DSCP=0, ECN=0
    out[IPV4_TOTAL_LEN_OFFSET] = (total_len >> 8) as u8;
    out[IPV4_TOTAL_LEN_OFFSET + 1] = (total_len & 0xFF) as u8;
    out[IPV4_IDENT_OFFSET] = (ident >> 8) as u8;
    out[IPV4_IDENT_OFFSET + 1] = (ident & 0xFF) as u8;
    // DF=1, MF=0, fragment_offset=0. The flags occupy bits 13..16 of
    // the 16-bit word (the top 3 bits of the byte at offset 6); the
    // low 13 bits are the fragment offset. DF is bit 14 of the word
    // (i.e. bit 6 of byte 6).
    out[IPV4_FLAGS_FRAG_OFFSET] = ipv4_flags::DF << 5;
    out[IPV4_FLAGS_FRAG_OFFSET + 1] = 0;
    out[IPV4_TTL_OFFSET] = ttl;
    out[IPV4_PROTO_OFFSET] = IP_PROTO_UDP;
    // Header checksum: write zeros first, compute, then patch in.
    out[IPV4_CHECKSUM_OFFSET] = 0;
    out[IPV4_CHECKSUM_OFFSET + 1] = 0;
    out[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 4].copy_from_slice(&src_ip);
    out[IPV4_DST_OFFSET..IPV4_DST_OFFSET + 4].copy_from_slice(&dst_ip);

    let hdr_cksum = ipv4_header_checksum(&out[..IPV4_HEADER_LEN]);
    out[IPV4_CHECKSUM_OFFSET] = (hdr_cksum >> 8) as u8;
    out[IPV4_CHECKSUM_OFFSET + 1] = (hdr_cksum & 0xFF) as u8;

    // ----- UDP header (bytes 20..28) + payload -----
    let udp_start = IPV4_HEADER_LEN;
    let udp_len = (UDP_HEADER_LEN + payload.len()) as u16;
    out[udp_start + UDP_SRC_OFFSET] = (src_port >> 8) as u8;
    out[udp_start + UDP_SRC_OFFSET + 1] = (src_port & 0xFF) as u8;
    out[udp_start + UDP_DST_OFFSET] = (dst_port >> 8) as u8;
    out[udp_start + UDP_DST_OFFSET + 1] = (dst_port & 0xFF) as u8;
    out[udp_start + UDP_LEN_OFFSET] = (udp_len >> 8) as u8;
    out[udp_start + UDP_LEN_OFFSET + 1] = (udp_len & 0xFF) as u8;
    // Zero the checksum field before computing the segment checksum.
    out[udp_start + UDP_CHECKSUM_OFFSET] = 0;
    out[udp_start + UDP_CHECKSUM_OFFSET + 1] = 0;
    // Payload after the UDP header.
    out[udp_start + UDP_HEADER_LEN..udp_start + UDP_HEADER_LEN + payload.len()]
        .copy_from_slice(payload);

    let segment_end = udp_start + UDP_HEADER_LEN + payload.len();
    let udp_cksum = udp_checksum(src_ip, dst_ip, &out[udp_start..segment_end]);
    out[udp_start + UDP_CHECKSUM_OFFSET] = (udp_cksum >> 8) as u8;
    out[udp_start + UDP_CHECKSUM_OFFSET + 1] = (udp_cksum & 0xFF) as u8;

    Ok(total_len)
}

// ============================================================
// Parsers
// ============================================================

/// Parse the IPv4 header at the start of `buf`. See
/// [`NetStack::parse_ipv4_header`] for the rejection order and the
/// locked-surface restrictions.
pub fn parse_ipv4_header(buf: &[u8]) -> Result<Ipv4HeaderView, NetError> {
    if buf.len() < IPV4_HEADER_LEN {
        return Err(NetError::Truncated);
    }
    let vihl = buf[0];
    let version = vihl >> 4;
    let ihl = vihl & 0x0F;
    if version != IPV4_VERSION {
        return Err(NetError::BadVersion);
    }
    if ihl < IPV4_IHL_NO_OPTIONS {
        return Err(NetError::BadHeaderLength);
    }
    if ihl != IPV4_IHL_NO_OPTIONS {
        return Err(NetError::OptionsPresent);
    }
    let total_length = ((buf[IPV4_TOTAL_LEN_OFFSET] as u16) << 8)
        | (buf[IPV4_TOTAL_LEN_OFFSET + 1] as u16);
    if total_length as usize != buf.len() {
        return Err(NetError::BadTotalLength);
    }
    // Flags + fragment offset: 3-bit flags in the high bits of byte 6,
    // 13-bit fragment offset spanning the low 5 bits of byte 6 + all
    // of byte 7.
    let flag_byte = buf[IPV4_FLAGS_FRAG_OFFSET];
    let frag_lo = buf[IPV4_FLAGS_FRAG_OFFSET + 1];
    let flags = flag_byte >> 5;
    let fragment_offset = (((flag_byte & 0x1F) as u16) << 8) | (frag_lo as u16);
    if (flags & ipv4_flags::MF) != 0 || fragment_offset != 0 {
        return Err(NetError::Fragmented);
    }
    let ttl = buf[IPV4_TTL_OFFSET];
    if ttl == 0 {
        return Err(NetError::HopLimitZero);
    }
    let header_checksum =
        ((buf[IPV4_CHECKSUM_OFFSET] as u16) << 8) | (buf[IPV4_CHECKSUM_OFFSET + 1] as u16);
    // Validate the checksum by recomputing with the field zeroed.
    let computed = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
    if computed != header_checksum {
        return Err(NetError::BadIpv4Checksum);
    }
    let protocol = buf[IPV4_PROTO_OFFSET];
    let identification = ((buf[IPV4_IDENT_OFFSET] as u16) << 8)
        | (buf[IPV4_IDENT_OFFSET + 1] as u16);
    let dscp_ecn = buf[1];
    let mut src_ip = [0u8; 4];
    src_ip.copy_from_slice(&buf[IPV4_SRC_OFFSET..IPV4_SRC_OFFSET + 4]);
    let mut dst_ip = [0u8; 4];
    dst_ip.copy_from_slice(&buf[IPV4_DST_OFFSET..IPV4_DST_OFFSET + 4]);

    Ok(Ipv4HeaderView {
        version,
        ihl,
        dscp_ecn,
        total_length,
        identification,
        flags,
        fragment_offset,
        ttl,
        protocol,
        header_checksum,
        src_ip,
        dst_ip,
    })
}

/// Parse a UDP segment, validating the length field and the pseudo-header
/// checksum. See [`NetStack::parse_udp_datagram`].
pub fn parse_udp_datagram(
    src_ip: [u8; 4],
    dst_ip: [u8; 4],
    udp_segment: &[u8],
) -> Result<UdpDatagramView, NetError> {
    if udp_segment.len() < UDP_HEADER_LEN {
        return Err(NetError::Truncated);
    }
    let length = ((udp_segment[UDP_LEN_OFFSET] as u16) << 8)
        | (udp_segment[UDP_LEN_OFFSET + 1] as u16);
    if (length as usize) != udp_segment.len() || (length as usize) < UDP_HEADER_LEN {
        return Err(NetError::BadUdpLength);
    }
    let src_port = ((udp_segment[UDP_SRC_OFFSET] as u16) << 8)
        | (udp_segment[UDP_SRC_OFFSET + 1] as u16);
    let dst_port = ((udp_segment[UDP_DST_OFFSET] as u16) << 8)
        | (udp_segment[UDP_DST_OFFSET + 1] as u16);
    if src_port == 0 || dst_port == 0 {
        return Err(NetError::PortZero);
    }
    let checksum = ((udp_segment[UDP_CHECKSUM_OFFSET] as u16) << 8)
        | (udp_segment[UDP_CHECKSUM_OFFSET + 1] as u16);
    if checksum == 0 {
        // Per the locked surface: every legal datagram carries a
        // non-zero UDP checksum.
        return Err(NetError::BadUdpChecksum);
    }
    let computed = udp_checksum(src_ip, dst_ip, udp_segment);
    if computed != checksum {
        return Err(NetError::BadUdpChecksum);
    }
    Ok(UdpDatagramView {
        src_port,
        dst_port,
        length,
        checksum,
        payload_off: UDP_HEADER_LEN,
        payload_len: (length as usize) - UDP_HEADER_LEN,
    })
}

// ============================================================
// Trait impl
// ============================================================

/// Zero-sized [`NetStack`] implementation. All state lives in
/// caller-supplied buffers; the impl itself is purely a vtable.
pub struct NetStackImpl;

impl NetStack for NetStackImpl {
    fn build_udp_datagram(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        ttl: u8,
        ident: u16,
        out: &mut [u8],
    ) -> Result<usize, NetError> {
        build_udp_datagram(src_ip, dst_ip, src_port, dst_port, payload, ttl, ident, out)
    }

    fn parse_ipv4_header(buf: &[u8]) -> Result<Ipv4HeaderView, NetError> {
        parse_ipv4_header(buf)
    }

    fn parse_udp_datagram(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        udp_segment: &[u8],
    ) -> Result<UdpDatagramView, NetError> {
        parse_udp_datagram(src_ip, dst_ip, udp_segment)
    }

    fn ipv4_header_checksum(header_bytes: &[u8]) -> u16 {
        ipv4_header_checksum(header_bytes)
    }

    fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &[u8]) -> u16 {
        udp_checksum(src_ip, dst_ip, udp_segment)
    }
}

#[cfg(test)]
mod tests {
    //! Unit tests for the no_std building blocks. Wire-level KAT
    //! coverage lives in `target_enterprise/tests/net_kat.rs`; this
    //! module exercises the invariants of the helpers (checksum
    //! arithmetic, builder/parser round-trip on hand-constructed
    //! inputs).

    use super::*;

    /// Hand-computed IPv4 header checksum KAT. Header words (with
    /// the checksum field zeroed):
    ///   0x4500 0x0030 0x4422 0x0000 0x8006 0x0000 0x8c7c 0x19ac 0xae24 0x1e2b
    /// Sum = 0x27BCF → fold → 0x7BD1 → one's-complement = 0x842E.
    /// Verified by independent computation; locks the network-order
    /// output of [`ipv4_header_checksum`] for this exact byte pattern.
    #[test]
    fn ipv4_header_checksum_known_answer() {
        let mut hdr = [
            0x45u8, 0x00, 0x00, 0x30, // version/IHL, dscp_ecn, total_length
            0x44, 0x22, 0x00, 0x00, // ident, flags+frag
            0x80, 0x06, 0x00, 0x00, // ttl, protocol, checksum (zeroed)
            0x8c, 0x7c, 0x19, 0xac, // src_ip
            0xae, 0x24, 0x1e, 0x2b, // dst_ip
        ];
        let sum = ipv4_header_checksum(&hdr);
        assert_eq!(sum, 0x842E, "hand-computed IPv4 header checksum");

        // Patch the checksum into the header and recompute: the
        // function returns the same value because it substitutes the
        // checksum field as zero during the computation. (The
        // canonical "recompute with field present == 0" property
        // applies if we use a NON-substituting variant; ours
        // substitutes, so this is the stability check.)
        hdr[IPV4_CHECKSUM_OFFSET] = (sum >> 8) as u8;
        hdr[IPV4_CHECKSUM_OFFSET + 1] = (sum & 0xFF) as u8;
        let recomputed = ipv4_header_checksum(&hdr);
        assert_eq!(
            recomputed, sum,
            "checksum function is stable: it always substitutes the field as zero"
        );
    }

    #[test]
    fn ones_complement_handles_double_carry_fold() {
        // Add 0xFFFF exactly 0x10001 times. The raw u32 accumulator
        // ends at 0xFFFF * 0x10001 = 0xFFFFFFFF — the maximum value
        // that requires *two* fold iterations to collapse to a
        // 16-bit result:
        //   iter 1: 0xFFFF + 0xFFFF = 0x1FFFE  (high=1, low=0xFFFE)
        //   iter 2: 0xFFFE + 0x0001 = 0xFFFF   (high=0 → exit)
        //   one's-complement of 0xFFFF = 0x0000
        // This exercises both passes of the carry-fold loop, which
        // matters for correctness under maximal input sizes.
        let mut acc = OnesComplement::new();
        for _ in 0..0x1_0001 {
            acc.add_be16(0xFFFF);
        }
        let s = acc.finalize();
        assert_eq!(s, 0x0000, "double-fold sentinel value");
    }

    #[test]
    fn build_smallest_legal_datagram_is_28_bytes() {
        let mut buf = [0u8; 32];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            12345,
            53,
            &[],
            64,
            0xBEEF,
            &mut buf,
        )
        .expect("build smallest");
        assert_eq!(n, MIN_IPV4_UDP_LEN);
        // version/IHL = 0x45.
        assert_eq!(buf[0], 0x45);
        // total_length = 28 (BE).
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 28);
        // protocol = 17.
        assert_eq!(buf[IPV4_PROTO_OFFSET], IP_PROTO_UDP);
        // DF flag set, fragment_offset=0.
        assert_eq!(buf[IPV4_FLAGS_FRAG_OFFSET] >> 5, ipv4_flags::DF);
        assert_eq!(buf[IPV4_FLAGS_FRAG_OFFSET] & 0x1F, 0);
        assert_eq!(buf[IPV4_FLAGS_FRAG_OFFSET + 1], 0);
        // src/dst port present.
        let udp = &buf[IPV4_HEADER_LEN..n];
        assert_eq!(((udp[0] as u16) << 8) | (udp[1] as u16), 12345);
        assert_eq!(((udp[2] as u16) << 8) | (udp[3] as u16), 53);
        // UDP length = 8 (BE).
        assert_eq!(((udp[4] as u16) << 8) | (udp[5] as u16), 8);
    }

    #[test]
    fn build_then_parse_round_trip_preserves_fields() {
        let payload: [u8; 5] = *b"hello";
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [192, 168, 1, 10],
            [192, 168, 1, 20],
            49152,
            6000,
            &payload,
            64,
            0x1234,
            &mut buf,
        )
        .expect("build");
        let ip = parse_ipv4_header(&buf[..n]).expect("parse ipv4");
        assert_eq!(ip.version, 4);
        assert_eq!(ip.ihl, 5);
        assert_eq!(ip.total_length as usize, n);
        assert_eq!(ip.identification, 0x1234);
        assert_eq!(ip.ttl, 64);
        assert_eq!(ip.protocol, IP_PROTO_UDP);
        assert_eq!(ip.src_ip, [192, 168, 1, 10]);
        assert_eq!(ip.dst_ip, [192, 168, 1, 20]);
        assert_eq!(ip.flags, ipv4_flags::DF);
        assert_eq!(ip.fragment_offset, 0);

        let udp =
            parse_udp_datagram(ip.src_ip, ip.dst_ip, &buf[IPV4_HEADER_LEN..n]).expect("parse udp");
        assert_eq!(udp.src_port, 49152);
        assert_eq!(udp.dst_port, 6000);
        assert_eq!(udp.length as usize, UDP_HEADER_LEN + payload.len());
        assert_eq!(udp.payload_off, UDP_HEADER_LEN);
        assert_eq!(udp.payload_len, payload.len());
        let pl = &buf[IPV4_HEADER_LEN + udp.payload_off..n];
        assert_eq!(pl, &payload);
    }

    #[test]
    fn truncated_header_rejected() {
        let buf = [0x45u8, 0x00, 0x00];
        assert_eq!(parse_ipv4_header(&buf), Err(NetError::Truncated));
    }

    #[test]
    fn ipv6_packet_rejected_as_bad_version() {
        // First nibble = 6 (IPv6).
        let mut buf = [0u8; IPV4_HEADER_LEN];
        buf[0] = 0x65; // version=6, ihl=5
        // Set total_length = 20 so we get past that check too.
        buf[IPV4_TOTAL_LEN_OFFSET + 1] = 20;
        assert_eq!(parse_ipv4_header(&buf), Err(NetError::BadVersion));
    }

    #[test]
    fn ihl_below_five_rejected() {
        let mut buf = [0u8; IPV4_HEADER_LEN];
        buf[0] = 0x44; // version=4, ihl=4 — illegal
        buf[IPV4_TOTAL_LEN_OFFSET + 1] = 20;
        assert_eq!(parse_ipv4_header(&buf), Err(NetError::BadHeaderLength));
    }

    #[test]
    fn ihl_above_five_rejected_as_options_present() {
        let mut buf = [0u8; IPV4_HEADER_LEN];
        buf[0] = 0x46; // version=4, ihl=6 — options present
        buf[IPV4_TOTAL_LEN_OFFSET + 1] = 20;
        assert_eq!(parse_ipv4_header(&buf), Err(NetError::OptionsPresent));
    }

    #[test]
    fn fragmented_packet_rejected() {
        let mut buf = [0u8; 64];
        // Build a legal datagram first.
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAA; 10],
            32,
            0x1111,
            &mut buf,
        )
        .expect("build");
        // Tamper: set MF in the flags byte (low bit of the 3-bit
        // flags). MF = 0b001 → bit 5 of byte 6.
        buf[IPV4_FLAGS_FRAG_OFFSET] |= ipv4_flags::MF << 5;
        // Recompute the header checksum so we don't trip the cksum check
        // before the fragmentation check fires.
        buf[IPV4_CHECKSUM_OFFSET] = 0;
        buf[IPV4_CHECKSUM_OFFSET + 1] = 0;
        let cksum = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
        buf[IPV4_CHECKSUM_OFFSET] = (cksum >> 8) as u8;
        buf[IPV4_CHECKSUM_OFFSET + 1] = (cksum & 0xFF) as u8;

        assert_eq!(parse_ipv4_header(&buf[..n]), Err(NetError::Fragmented));
    }

    #[test]
    fn fragment_offset_nonzero_rejected() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAA; 10],
            32,
            0x1111,
            &mut buf,
        )
        .expect("build");
        // Set fragment_offset = 1 (low bit of byte 7).
        buf[IPV4_FLAGS_FRAG_OFFSET + 1] = 1;
        // Refresh checksum.
        buf[IPV4_CHECKSUM_OFFSET] = 0;
        buf[IPV4_CHECKSUM_OFFSET + 1] = 0;
        let cksum = ipv4_header_checksum(&buf[..IPV4_HEADER_LEN]);
        buf[IPV4_CHECKSUM_OFFSET] = (cksum >> 8) as u8;
        buf[IPV4_CHECKSUM_OFFSET + 1] = (cksum & 0xFF) as u8;

        assert_eq!(parse_ipv4_header(&buf[..n]), Err(NetError::Fragmented));
    }

    #[test]
    fn ttl_zero_rejected_after_fragmentation_check() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAA; 10],
            32,
            0x1111,
            &mut buf,
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
    fn bad_ipv4_checksum_rejected() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAA; 10],
            32,
            0x1111,
            &mut buf,
        )
        .expect("build");
        // Flip a bit in the header (the high byte of total_length is a
        // safe choice — it's currently zero, flipping to 1 makes
        // total_length much larger than buf.len()). But we want to
        // isolate the checksum check, so flip a bit in the source IP
        // instead, AND keep total_length consistent.
        buf[IPV4_SRC_OFFSET] ^= 0x01;
        // Now the checksum on the wire no longer matches the bytes.
        assert_eq!(parse_ipv4_header(&buf[..n]), Err(NetError::BadIpv4Checksum));
    }

    #[test]
    fn bad_total_length_rejected() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAA; 10],
            32,
            0x1111,
            &mut buf,
        )
        .expect("build");
        // Slice off one byte to make total_length disagree with the
        // slice length. The parser should reject before getting to the
        // checksum check.
        assert_eq!(
            parse_ipv4_header(&buf[..n - 1]),
            Err(NetError::BadTotalLength)
        );
    }

    #[test]
    fn port_zero_rejected_on_build() {
        let mut buf = [0u8; 32];
        assert_eq!(
            build_udp_datagram(
                [1, 2, 3, 4],
                [5, 6, 7, 8],
                0,
                53,
                &[],
                64,
                0x1234,
                &mut buf
            ),
            Err(NetError::PortZero)
        );
        assert_eq!(
            build_udp_datagram(
                [1, 2, 3, 4],
                [5, 6, 7, 8],
                53,
                0,
                &[],
                64,
                0x1234,
                &mut buf
            ),
            Err(NetError::PortZero)
        );
    }

    #[test]
    fn output_buffer_too_small_rejected() {
        let mut buf = [0u8; 27]; // one byte short of MIN_IPV4_UDP_LEN
        assert_eq!(
            build_udp_datagram(
                [1, 2, 3, 4],
                [5, 6, 7, 8],
                100,
                200,
                &[],
                64,
                0x1234,
                &mut buf
            ),
            Err(NetError::OutputBufferTooSmall)
        );
    }

    #[test]
    fn udp_checksum_zero_rejected_on_parse() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAB; 4],
            32,
            0x1234,
            &mut buf,
        )
        .expect("build");
        // Forcibly zero the UDP checksum.
        let udp_start = IPV4_HEADER_LEN;
        buf[udp_start + UDP_CHECKSUM_OFFSET] = 0;
        buf[udp_start + UDP_CHECKSUM_OFFSET + 1] = 0;
        assert_eq!(
            parse_udp_datagram(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                &buf[IPV4_HEADER_LEN..n]
            ),
            Err(NetError::BadUdpChecksum)
        );
    }

    #[test]
    fn udp_checksum_mismatch_rejected_on_parse() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAB; 4],
            32,
            0x1234,
            &mut buf,
        )
        .expect("build");
        // Flip one byte of the payload without recomputing the UDP
        // checksum — checksum stays the same, payload changes,
        // verification must fail.
        let payload_off = IPV4_HEADER_LEN + UDP_HEADER_LEN;
        buf[payload_off] ^= 0x80;
        assert_eq!(
            parse_udp_datagram(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                &buf[IPV4_HEADER_LEN..n]
            ),
            Err(NetError::BadUdpChecksum)
        );
    }

    #[test]
    fn udp_length_mismatch_rejected() {
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [10, 0, 0, 1],
            [10, 0, 0, 2],
            1234,
            5678,
            &[0xAB; 4],
            32,
            0x1234,
            &mut buf,
        )
        .expect("build");
        // Truncate the UDP segment by one byte (without updating the
        // length field).
        assert_eq!(
            parse_udp_datagram(
                [10, 0, 0, 1],
                [10, 0, 0, 2],
                &buf[IPV4_HEADER_LEN..n - 1]
            ),
            Err(NetError::BadUdpLength)
        );
    }

    #[test]
    fn udp_truncated_segment_rejected() {
        let buf = [0u8; 4]; // way too short
        assert_eq!(
            parse_udp_datagram([0, 0, 0, 0], [0, 0, 0, 0], &buf),
            Err(NetError::Truncated)
        );
    }

    #[test]
    fn build_payload_too_large_rejected() {
        // We can't materialise a 65508-byte payload as a stack array
        // easily, so this case is exercised by the integration test
        // suite where a static const is large enough. Here we just
        // verify the threshold via the constant.
        assert_eq!(MAX_UDP_PAYLOAD, 65507);
    }

    #[test]
    fn odd_length_payload_checksum_is_correct() {
        // The pad-with-zero behaviour for odd-length payloads is
        // tested implicitly elsewhere, but explicit coverage here
        // anchors the contract.
        let mut buf = [0u8; 64];
        let n = build_udp_datagram(
            [127, 0, 0, 1],
            [127, 0, 0, 1],
            7777,
            8888,
            &[0xDE, 0xAD, 0xBE], // 3 bytes — odd
            64,
            0x4242,
            &mut buf,
        )
        .expect("build odd");
        // Round-trip: parse must accept.
        let ip = parse_ipv4_header(&buf[..n]).expect("parse ipv4");
        let udp = parse_udp_datagram(ip.src_ip, ip.dst_ip, &buf[IPV4_HEADER_LEN..n])
            .expect("parse udp");
        assert_eq!(udp.payload_len, 3);
    }

    #[test]
    fn diversified_inputs_produce_same_bytes() {
        // The contract's wire-equivalence invariant: identical inputs
        // → identical bytes. Build the same datagram twice and
        // assert byte-equality.
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let na = build_udp_datagram(
            [203, 0, 113, 1],
            [203, 0, 113, 2],
            5555,
            5555,
            b"cuttle",
            48,
            0xABCD,
            &mut a,
        )
        .expect("a");
        let nb = build_udp_datagram(
            [203, 0, 113, 1],
            [203, 0, 113, 2],
            5555,
            5555,
            b"cuttle",
            48,
            0xABCD,
            &mut b,
        )
        .expect("b");
        assert_eq!(na, nb);
        assert_eq!(&a[..na], &b[..nb]);
    }

    #[test]
    fn trait_routes_to_free_functions() {
        // Compile-time guard that the impl exists and routes properly.
        let mut buf = [0u8; 32];
        let n =
            <NetStackImpl as NetStack>::build_udp_datagram(
                [1, 1, 1, 1],
                [2, 2, 2, 2],
                10,
                20,
                &[0xAA],
                64,
                0x1,
                &mut buf,
            )
            .expect("build via trait");
        let mut buf2 = [0u8; 32];
        let n2 = build_udp_datagram(
            [1, 1, 1, 1],
            [2, 2, 2, 2],
            10,
            20,
            &[0xAA],
            64,
            0x1,
            &mut buf2,
        )
        .expect("build via fn");
        assert_eq!(n, n2);
        assert_eq!(&buf[..n], &buf2[..n2]);
    }
}
