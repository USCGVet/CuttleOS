//! ICMP — RFC 792 echo request / reply.
//!
//! `no_std`, no `alloc`, fixed-capacity scratch in the impl. Echo is
//! the only ICMP message-type the seed handles end-to-end — that's
//! enough for ping support and the kernel banner test.
//!
//! # Wire format (8-byte header + payload)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Type      |     Code      |          Checksum             |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |           Identifier          |        Sequence Number        |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |     Data ...
//! +-+-+-+-+-+-+
//! ```
//!
//! Checksum is the RFC 1071 16-bit one's-complement sum over the full
//! ICMP message (header + data), with the checksum field set to 0
//! during computation.

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{icmp_type, Icmp, IcmpEchoView, IcmpError};

/// Length of the ICMP echo header on the wire.
pub const ICMP_HEADER_LEN: usize = 8;

/// Wire codec impl. Stateless.
pub struct IcmpImpl;

impl Icmp for IcmpImpl {
    fn build_echo_request(
        identifier: u16,
        sequence_number: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, IcmpError> {
        build_echo(icmp_type::ECHO_REQUEST, identifier, sequence_number, payload, out)
    }

    fn build_echo_reply(
        identifier: u16,
        sequence_number: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, IcmpError> {
        build_echo(icmp_type::ECHO_REPLY, identifier, sequence_number, payload, out)
    }

    fn parse_echo(bytes: &[u8]) -> Result<IcmpEchoView<'_>, IcmpError> {
        if bytes.len() < ICMP_HEADER_LEN {
            return Err(IcmpError::Truncated);
        }
        let t = bytes[0];
        if t != icmp_type::ECHO_REQUEST && t != icmp_type::ECHO_REPLY {
            return Err(IcmpError::NotEcho);
        }
        let code = bytes[1];
        let wire_cksum = read_u16_be(&bytes[2..4]);
        let id = read_u16_be(&bytes[4..6]);
        let seq = read_u16_be(&bytes[6..8]);
        let payload = &bytes[ICMP_HEADER_LEN..];

        // Recompute checksum: zero the field, sum, compare.
        let computed = icmp_checksum_split(&bytes[..2], &[0u8, 0u8], &bytes[4..]);
        if computed != wire_cksum {
            return Err(IcmpError::ChecksumMismatch);
        }

        Ok(IcmpEchoView {
            icmp_type: t,
            code,
            checksum: wire_cksum,
            identifier: id,
            sequence_number: seq,
            payload,
        })
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn build_echo(
    t: u8,
    identifier: u16,
    sequence_number: u16,
    payload: &[u8],
    out: &mut [u8],
) -> Result<usize, IcmpError> {
    let total = ICMP_HEADER_LEN + payload.len();
    if out.len() < total {
        return Err(IcmpError::OutputBufferTooSmall);
    }
    out[0] = t;
    out[1] = 0; // code
    out[2] = 0; // checksum hi (placeholder)
    out[3] = 0; // checksum lo
    write_u16_be(&mut out[4..6], identifier);
    write_u16_be(&mut out[6..8], sequence_number);
    for i in 0..payload.len() {
        out[ICMP_HEADER_LEN + i] = payload[i];
    }
    // Compute checksum over the message with checksum field zeroed.
    let cksum = icmp_checksum_inplace(&out[..total]);
    write_u16_be(&mut out[2..4], cksum);
    Ok(total)
}

#[inline]
fn read_u16_be(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | (b[1] as u16)
}

#[inline]
fn write_u16_be(b: &mut [u8], v: u16) {
    b[0] = (v >> 8) as u8;
    b[1] = v as u8;
}

/// RFC 1071 16-bit one's-complement sum over `data`. Pure — used by
/// both the build and parse paths.
fn icmp_checksum_inplace(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum = sum.wrapping_add(word);
        i += 2;
    }
    if i < data.len() {
        // Odd-length: pad the final byte with zero (per RFC 1071).
        let word = (data[i] as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    // Fold carries.
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Like `icmp_checksum_inplace` but reads three slices virtually
/// concatenated. Lets `parse_echo` compute the checksum without
/// having to mutate a copy of `bytes`.
fn icmp_checksum_split(a: &[u8], b: &[u8], c: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut have_hi = false;
    let mut hi: u8 = 0;
    let runs: [&[u8]; 3] = [a, b, c];
    let mut r = 0;
    while r < runs.len() {
        let bytes = runs[r];
        let mut k = 0;
        while k < bytes.len() {
            if have_hi {
                let word = ((hi as u32) << 8) | (bytes[k] as u32);
                sum = sum.wrapping_add(word);
                have_hi = false;
            } else {
                hi = bytes[k];
                have_hi = true;
            }
            k += 1;
        }
        r += 1;
    }
    if have_hi {
        let word = (hi as u32) << 8;
        sum = sum.wrapping_add(word);
    }
    while sum >> 16 != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn echo_request_round_trip() {
        let mut buf = [0u8; 32];
        let n = IcmpImpl::build_echo_request(0xABCD, 1, b"hello", &mut buf).unwrap();
        assert_eq!(n, ICMP_HEADER_LEN + 5);
        let view = IcmpImpl::parse_echo(&buf[..n]).unwrap();
        assert_eq!(view.icmp_type, icmp_type::ECHO_REQUEST);
        assert_eq!(view.identifier, 0xABCD);
        assert_eq!(view.sequence_number, 1);
        assert_eq!(view.payload, b"hello");
    }

    #[test]
    fn echo_reply_round_trip() {
        let mut buf = [0u8; 32];
        let n = IcmpImpl::build_echo_reply(0xDEAD, 42, b"world!", &mut buf).unwrap();
        let view = IcmpImpl::parse_echo(&buf[..n]).unwrap();
        assert_eq!(view.icmp_type, icmp_type::ECHO_REPLY);
        assert_eq!(view.identifier, 0xDEAD);
        assert_eq!(view.sequence_number, 42);
        assert_eq!(view.payload, b"world!");
    }

    #[test]
    fn parse_rejects_truncated() {
        let bytes = [0u8; 4];
        assert!(matches!(
            IcmpImpl::parse_echo(&bytes),
            Err(IcmpError::Truncated)
        ));
    }

    #[test]
    fn parse_rejects_non_echo_type() {
        let mut buf = [0u8; ICMP_HEADER_LEN];
        buf[0] = icmp_type::DEST_UNREACHABLE;
        // Compute a valid checksum for this otherwise-malformed input
        // so we surface NotEcho, not ChecksumMismatch.
        let cksum = icmp_checksum_inplace(&buf);
        write_u16_be(&mut buf[2..4], cksum);
        assert!(matches!(IcmpImpl::parse_echo(&buf), Err(IcmpError::NotEcho)));
    }

    #[test]
    fn parse_rejects_tampered_checksum() {
        let mut buf = [0u8; 32];
        let n = IcmpImpl::build_echo_request(1, 1, b"abc", &mut buf).unwrap();
        // Flip a payload byte; checksum no longer matches.
        buf[ICMP_HEADER_LEN] ^= 0xFF;
        assert!(matches!(
            IcmpImpl::parse_echo(&buf[..n]),
            Err(IcmpError::ChecksumMismatch)
        ));
    }

    #[test]
    fn build_rejects_small_buffer() {
        let mut buf = [0u8; 7];
        assert!(matches!(
            IcmpImpl::build_echo_request(1, 1, b"", &mut buf),
            Err(IcmpError::OutputBufferTooSmall)
        ));
    }

    #[test]
    fn empty_payload() {
        let mut buf = [0u8; ICMP_HEADER_LEN];
        let n = IcmpImpl::build_echo_request(0, 0, b"", &mut buf).unwrap();
        assert_eq!(n, ICMP_HEADER_LEN);
        let view = IcmpImpl::parse_echo(&buf[..n]).unwrap();
        assert_eq!(view.payload, b"");
    }

    #[test]
    fn odd_length_payload_checksum() {
        // 1-byte payload exercises the odd-byte-padding branch of the
        // checksum routine. A miscoded padding step would fail the
        // round-trip verification.
        let mut buf = [0u8; 16];
        let n = IcmpImpl::build_echo_request(0xBEEF, 5, &[0xAA], &mut buf).unwrap();
        let view = IcmpImpl::parse_echo(&buf[..n]).unwrap();
        assert_eq!(view.payload, &[0xAA]);
    }

    #[test]
    fn known_checksum_vector() {
        // Tiny canonical fixture for a 0-payload echo request with
        // id=0 seq=0: header bytes are 08 00 ?? ?? 00 00 00 00.
        // The 16-bit checksum is the one's-complement sum of:
        //   0x0800 + 0x0000 + 0x0000 = 0x0800
        //   complement = 0xF7FF
        let mut buf = [0u8; 8];
        let _ = IcmpImpl::build_echo_request(0, 0, b"", &mut buf).unwrap();
        assert_eq!(buf[0], 0x08); // type
        assert_eq!(buf[1], 0x00); // code
        assert_eq!(read_u16_be(&buf[2..4]), 0xF7FF);
    }

    #[test]
    fn parse_recovers_zero_checksum_field() {
        // After building with checksum X, the wire bytes have X in the
        // checksum field. Recomputing the checksum over the message
        // with the field zeroed yields the same X.
        let mut buf = [0u8; 32];
        let n = IcmpImpl::build_echo_request(0xCAFE, 99, b"test-payload", &mut buf).unwrap();
        let wire_cksum = read_u16_be(&buf[2..4]);
        let view = IcmpImpl::parse_echo(&buf[..n]).unwrap();
        assert_eq!(view.checksum, wire_cksum);
    }
}
