//! DNS — RFC 1035 query/response wire codec.
//!
//! `no_std`, no `alloc`, fixed-capacity scratch in the impl. Server-
//! and client-side helpers covering exactly enough surface for the
//! seed's banner test + a single A-record lookup or response.
//!
//! # What's covered
//!
//! - 12-byte header (RFC 1035 §4.1.1): id, flags, qdcount, ancount,
//!   nscount, arcount, all big-endian
//! - Question section (RFC 1035 §4.1.2): length-prefixed labels
//!   terminated by `0x00`, followed by QTYPE/QCLASS
//! - Answer section (RFC 1035 §4.1.3): NAME + TYPE + CLASS + TTL +
//!   RDLENGTH + RDATA
//! - Name parsing: handles both inline labels AND pointer compression
//!   (RFC 1035 §4.1.4). Writers only emit uncompressed names.
//!
//! # What's not (yet)
//!
//! - EDNS(0) / OPT records (RFC 6891)
//! - DNSSEC (RRSIG, DS, DNSKEY)
//! - Multi-question messages (RFC permits, but no real caller emits)
//! - Building responses with non-A records (NS/MX/TXT etc.)
//! - Internationalized domain names (IDN / punycode)
//!
//! These are explicit future tasks. The surface today handles enough
//! DNS to do an A-record lookup against an upstream resolver, or to
//! reply to a single A query as an authoritative server.

#![allow(clippy::needless_range_loop)]

use cuttle_contracts::{
    dns_class, dns_flags, Dns, DnsError, DnsHeader, DnsMessageView, DnsRecordType,
};

/// Length of the wire-format header in bytes.
pub const DNS_HEADER_LEN: usize = 12;
/// Maximum length of an encoded name on the wire including length
/// octets (RFC 1035 §2.3.4).
pub const MAX_NAME_LEN: usize = 255;
/// Maximum length of a single label (RFC 1035 §2.3.4).
pub const MAX_LABEL_LEN: usize = 63;

/// Wire codec impl. Stateless.
pub struct DnsImpl;

impl Dns for DnsImpl {
    fn build_a_query(id: u16, name: &[u8], out: &mut [u8]) -> Result<usize, DnsError> {
        if out.len() < DNS_HEADER_LEN {
            return Err(DnsError::OutputBufferTooSmall);
        }

        // Header: id, RD=1, qdcount=1.
        let flags = dns_flags::OPCODE_QUERY | dns_flags::RD;
        write_u16_be(&mut out[0..2], id);
        write_u16_be(&mut out[2..4], flags);
        write_u16_be(&mut out[4..6], 1); // qdcount
        write_u16_be(&mut out[6..8], 0); // ancount
        write_u16_be(&mut out[8..10], 0); // nscount
        write_u16_be(&mut out[10..12], 0); // arcount
        let mut pos = DNS_HEADER_LEN;

        // QNAME (encode the ASCII dotted name as length-prefixed labels).
        pos += encode_name_ascii(name, &mut out[pos..])?;

        // QTYPE = A, QCLASS = IN.
        if pos + 4 > out.len() {
            return Err(DnsError::OutputBufferTooSmall);
        }
        write_u16_be(&mut out[pos..pos + 2], DnsRecordType::A as u16);
        write_u16_be(&mut out[pos + 2..pos + 4], dns_class::IN);
        pos += 4;

        Ok(pos)
    }

    fn parse_message(bytes: &[u8]) -> Result<DnsMessageView<'_>, DnsError> {
        if bytes.len() < DNS_HEADER_LEN {
            return Err(DnsError::Truncated);
        }

        let header = DnsHeader {
            id: read_u16_be(&bytes[0..2]),
            flags: read_u16_be(&bytes[2..4]),
            qdcount: read_u16_be(&bytes[4..6]),
            ancount: read_u16_be(&bytes[6..8]),
            nscount: read_u16_be(&bytes[8..10]),
            arcount: read_u16_be(&bytes[10..12]),
        };

        if header.qdcount == 0 {
            return Ok(DnsMessageView {
                header,
                first_question_name: None,
                first_question_type: 0,
                first_question_class: 0,
            });
        }

        // Walk the first question's name. Compressed pointers are
        // resolved transparently; the returned slice is the
        // _uncompressed_ inline label sequence from the question
        // section. (Real-world queries don't compress in the question
        // section, so the slice equals what was on the wire.)
        let name_start = DNS_HEADER_LEN;
        let name_end = scan_name(bytes, name_start)?;
        if name_end + 4 > bytes.len() {
            return Err(DnsError::Truncated);
        }
        let q_name = &bytes[name_start..name_end];
        let q_type = read_u16_be(&bytes[name_end..name_end + 2]);
        let q_class = read_u16_be(&bytes[name_end + 2..name_end + 4]);

        Ok(DnsMessageView {
            header,
            first_question_name: Some(q_name),
            first_question_type: q_type,
            first_question_class: q_class,
        })
    }

    fn build_a_response(
        id: u16,
        question_wire_name: &[u8],
        ip: [u8; 4],
        ttl: u32,
        out: &mut [u8],
    ) -> Result<usize, DnsError> {
        // Validate the wire name first so we don't half-write a
        // malformed response.
        if question_wire_name.is_empty() || question_wire_name.len() > MAX_NAME_LEN {
            return Err(DnsError::InvalidLabel);
        }
        if *question_wire_name.last().unwrap() != 0 {
            return Err(DnsError::InvalidLabel);
        }
        // Walk labels to verify each length octet is in bounds.
        {
            let mut i = 0usize;
            while i < question_wire_name.len() {
                let n = question_wire_name[i] as usize;
                if n == 0 {
                    if i + 1 != question_wire_name.len() {
                        return Err(DnsError::InvalidLabel);
                    }
                    break;
                }
                if n > MAX_LABEL_LEN {
                    return Err(DnsError::LabelTooLong);
                }
                if i + 1 + n > question_wire_name.len() {
                    return Err(DnsError::InvalidLabel);
                }
                i += 1 + n;
            }
        }

        let qname_len = question_wire_name.len();

        // Required size: header (12) + question (qname + 4) + answer
        // (qname + 2 + 2 + 4 + 2 + 4)
        let need = DNS_HEADER_LEN + qname_len + 4 + qname_len + 2 + 2 + 4 + 2 + 4;
        if out.len() < need {
            return Err(DnsError::OutputBufferTooSmall);
        }

        // Header: QR=1, RA=0, AA=1, RCODE=NOERROR, qdcount=1, ancount=1.
        let flags = dns_flags::QR_RESPONSE | dns_flags::AA | dns_flags::RCODE_NOERROR;
        write_u16_be(&mut out[0..2], id);
        write_u16_be(&mut out[2..4], flags);
        write_u16_be(&mut out[4..6], 1);
        write_u16_be(&mut out[6..8], 1);
        write_u16_be(&mut out[8..10], 0);
        write_u16_be(&mut out[10..12], 0);
        let mut pos = DNS_HEADER_LEN;

        // Question: echo qname + QTYPE=A + QCLASS=IN.
        out[pos..pos + qname_len].copy_from_slice(question_wire_name);
        pos += qname_len;
        write_u16_be(&mut out[pos..pos + 2], DnsRecordType::A as u16);
        write_u16_be(&mut out[pos + 2..pos + 4], dns_class::IN);
        pos += 4;

        // Answer: NAME (uncompressed echo) + TYPE=A + CLASS=IN + TTL + RDLENGTH=4 + RDATA.
        out[pos..pos + qname_len].copy_from_slice(question_wire_name);
        pos += qname_len;
        write_u16_be(&mut out[pos..pos + 2], DnsRecordType::A as u16);
        write_u16_be(&mut out[pos + 2..pos + 4], dns_class::IN);
        pos += 4;
        write_u32_be(&mut out[pos..pos + 4], ttl);
        pos += 4;
        write_u16_be(&mut out[pos..pos + 2], 4); // RDLENGTH = 4 (IPv4 addr)
        pos += 2;
        out[pos] = ip[0];
        out[pos + 1] = ip[1];
        out[pos + 2] = ip[2];
        out[pos + 3] = ip[3];
        pos += 4;

        Ok(pos)
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_u16_be(b: &[u8]) -> u16 {
    ((b[0] as u16) << 8) | (b[1] as u16)
}

#[inline]
fn write_u16_be(b: &mut [u8], v: u16) {
    b[0] = (v >> 8) as u8;
    b[1] = v as u8;
}

#[inline]
fn write_u32_be(b: &mut [u8], v: u32) {
    b[0] = (v >> 24) as u8;
    b[1] = (v >> 16) as u8;
    b[2] = (v >> 8) as u8;
    b[3] = v as u8;
}

/// Encode an ASCII dotted name like `b"example.com"` into wire form
/// `0x07 e x a m p l e 0x03 c o m 0x00`. Returns bytes written into
/// `out`. Rejects empty input, empty labels, labels > 63 bytes, and
/// total encoded length > 255.
fn encode_name_ascii(name: &[u8], out: &mut [u8]) -> Result<usize, DnsError> {
    if name.is_empty() {
        return Err(DnsError::InvalidLabel);
    }

    let mut pos = 0usize;
    let mut label_start = 0usize;
    let mut i = 0usize;
    while i < name.len() {
        if name[i] == b'.' {
            if i == label_start {
                return Err(DnsError::InvalidLabel);
            }
            let label_len = i - label_start;
            if label_len > MAX_LABEL_LEN {
                return Err(DnsError::LabelTooLong);
            }
            if pos + 1 + label_len > out.len() {
                return Err(DnsError::OutputBufferTooSmall);
            }
            out[pos] = label_len as u8;
            for k in 0..label_len {
                out[pos + 1 + k] = name[label_start + k];
            }
            pos += 1 + label_len;
            label_start = i + 1;
        }
        i += 1;
    }
    // Final label.
    if label_start == name.len() {
        return Err(DnsError::InvalidLabel);
    }
    let label_len = name.len() - label_start;
    if label_len > MAX_LABEL_LEN {
        return Err(DnsError::LabelTooLong);
    }
    if pos + 1 + label_len + 1 > out.len() {
        return Err(DnsError::OutputBufferTooSmall);
    }
    out[pos] = label_len as u8;
    for k in 0..label_len {
        out[pos + 1 + k] = name[label_start + k];
    }
    pos += 1 + label_len;

    // Zero terminator.
    out[pos] = 0;
    pos += 1;

    if pos > MAX_NAME_LEN {
        return Err(DnsError::NameTooLong);
    }

    Ok(pos)
}

/// Scan a wire-form name starting at `start`. Handles inline labels
/// AND pointer compression (the top 2 bits set on a length byte means
/// the following byte completes a 14-bit offset to elsewhere in the
/// message). Returns the byte just past the name's terminator (or
/// just past the 2-byte pointer if the name is a pure pointer).
///
/// The returned offset is the position where TYPE/CLASS continue in
/// the *caller's* iteration, NOT where the pointer led to.
fn scan_name(bytes: &[u8], start: usize) -> Result<usize, DnsError> {
    let mut pos = start;
    // Loop-detector: a single message can't have more than MAX_NAME_LEN
    // jumps without forming a cycle.
    let mut hops = 0usize;
    let mut following_pointer = false;
    let mut name_bytes: usize = 0;
    let mut return_after_first_pointer: usize = pos;

    loop {
        if pos >= bytes.len() {
            return Err(DnsError::Truncated);
        }
        let b = bytes[pos];
        if b == 0 {
            if !following_pointer {
                return Ok(pos + 1);
            }
            return Ok(return_after_first_pointer);
        }
        if b & 0xC0 == 0xC0 {
            // Pointer.
            if pos + 1 >= bytes.len() {
                return Err(DnsError::Truncated);
            }
            let new_pos =
                (((b as usize) & 0x3F) << 8) | (bytes[pos + 1] as usize);
            if new_pos >= bytes.len() {
                return Err(DnsError::Truncated);
            }
            if !following_pointer {
                return_after_first_pointer = pos + 2;
            }
            if new_pos >= pos {
                // RFC 1035 §4.1.4: pointers MUST be backward (to
                // earlier in the message). Forward / equal pointers
                // are malformed and a likely loop attack.
                return Err(DnsError::CompressionLoop);
            }
            following_pointer = true;
            pos = new_pos;
            hops += 1;
            if hops > MAX_NAME_LEN {
                return Err(DnsError::CompressionLoop);
            }
            continue;
        }
        if b & 0xC0 != 0 {
            // 10xxxxxx / 01xxxxxx reserved.
            return Err(DnsError::BadHeader);
        }
        let label_len = b as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(DnsError::LabelTooLong);
        }
        if pos + 1 + label_len >= bytes.len() {
            return Err(DnsError::Truncated);
        }
        name_bytes += 1 + label_len;
        if name_bytes > MAX_NAME_LEN {
            return Err(DnsError::NameTooLong);
        }
        pos += 1 + label_len;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_round_trip() {
        // Build a query, parse it, recover the header fields.
        let mut buf = [0u8; 64];
        let n = DnsImpl::build_a_query(0xCAFE, b"example.com", &mut buf).unwrap();
        let view = DnsImpl::parse_message(&buf[..n]).unwrap();
        assert_eq!(view.header.id, 0xCAFE);
        assert_eq!(view.header.qdcount, 1);
        assert_eq!(view.header.ancount, 0);
        // RD flag must be set on a query.
        assert_ne!(view.header.flags & dns_flags::RD, 0);
        // QR must be clear (this is a query).
        assert_eq!(view.header.flags & dns_flags::QR_RESPONSE, 0);
    }

    #[test]
    fn build_query_wire_bytes() {
        // The query for "example.com" is well-known. Verify the
        // emitted bytes match the canonical encoding.
        let mut buf = [0u8; 64];
        let n = DnsImpl::build_a_query(0x1234, b"example.com", &mut buf).unwrap();
        // Header: id=0x1234, flags=0x0100 (RD), qd=1, an=0, ns=0, ar=0.
        let expected: &[u8] = &[
            0x12, 0x34, // id
            0x01, 0x00, // flags (RD set)
            0x00, 0x01, // qdcount
            0x00, 0x00, // ancount
            0x00, 0x00, // nscount
            0x00, 0x00, // arcount
            // QNAME: \x07example\x03com\x00
            7, b'e', b'x', b'a', b'm', b'p', b'l', b'e', 3, b'c', b'o', b'm', 0,
            // QTYPE=A, QCLASS=IN
            0x00, 0x01, 0x00, 0x01,
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn parse_recovers_question() {
        let mut buf = [0u8; 64];
        let n = DnsImpl::build_a_query(0xABCD, b"foo.bar.baz", &mut buf).unwrap();
        let view = DnsImpl::parse_message(&buf[..n]).unwrap();
        let qname = view.first_question_name.unwrap();
        // Wire form: \x03foo\x03bar\x03baz\x00
        assert_eq!(
            qname,
            &[3, b'f', b'o', b'o', 3, b'b', b'a', b'r', 3, b'b', b'a', b'z', 0]
        );
        assert_eq!(view.first_question_type, DnsRecordType::A as u16);
        assert_eq!(view.first_question_class, dns_class::IN);
    }

    #[test]
    fn parse_rejects_truncated_header() {
        let bytes = [0u8; 4];
        assert!(matches!(
            DnsImpl::parse_message(&bytes),
            Err(DnsError::Truncated)
        ));
    }

    #[test]
    fn parse_rejects_truncated_question() {
        // Header says qdcount=1 but no question follows.
        let mut bytes = [0u8; DNS_HEADER_LEN];
        write_u16_be(&mut bytes[4..6], 1); // qdcount
        let r = DnsImpl::parse_message(&bytes);
        assert!(matches!(r, Err(DnsError::Truncated)));
    }

    #[test]
    fn build_response_round_trip() {
        let mut q = [0u8; 64];
        let qn = DnsImpl::build_a_query(0xBEEF, b"healthz.local", &mut q).unwrap();
        let qview = DnsImpl::parse_message(&q[..qn]).unwrap();
        let qname = qview.first_question_name.unwrap();

        let mut r = [0u8; 128];
        let rn =
            DnsImpl::build_a_response(0xBEEF, qname, [10, 0, 0, 1], 60, &mut r).unwrap();
        let rview = DnsImpl::parse_message(&r[..rn]).unwrap();

        assert_eq!(rview.header.id, 0xBEEF);
        assert_ne!(rview.header.flags & dns_flags::QR_RESPONSE, 0);
        assert_ne!(rview.header.flags & dns_flags::AA, 0);
        assert_eq!(rview.header.flags & 0xF, dns_flags::RCODE_NOERROR);
        assert_eq!(rview.header.qdcount, 1);
        assert_eq!(rview.header.ancount, 1);

        // Verify the answer rdata is the IP we put in.
        // Position of rdata: 12 (header) + qname.len() + 4 (qtype/qclass)
        //                  + qname.len() + 2 (type) + 2 (class) + 4 (ttl)
        //                  + 2 (rdlength) = 26 + 2*qname.len()
        let rdata_start = DNS_HEADER_LEN + qname.len() + 4 + qname.len() + 2 + 2 + 4 + 2;
        assert_eq!(&r[rdata_start..rdata_start + 4], &[10, 0, 0, 1]);
    }

    #[test]
    fn build_response_byte_exact() {
        // Use a tiny name so we can hand-check every byte.
        let mut q = [0u8; 64];
        let qn = DnsImpl::build_a_query(0x0001, b"a.b", &mut q).unwrap();
        let qview = DnsImpl::parse_message(&q[..qn]).unwrap();
        let qname = qview.first_question_name.unwrap();

        let mut r = [0u8; 128];
        let rn = DnsImpl::build_a_response(0x0001, qname, [1, 2, 3, 4], 300, &mut r)
            .unwrap();
        // Expected:
        //   header: 0001 8400 0001 0001 0000 0000
        //   qname:  01 'a' 01 'b' 00
        //   qtype/qclass: 0001 0001
        //   answer name (echoed): 01 'a' 01 'b' 00
        //   answer type/class:    0001 0001
        //   ttl: 0000 012C
        //   rdlength: 0004
        //   rdata: 01 02 03 04
        let expected: &[u8] = &[
            0x00, 0x01, // id
            0x84, 0x00, // QR + AA + NOERROR
            0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, // qdcount=1, ancount=1
            1, b'a', 1, b'b', 0, // QNAME
            0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
            1, b'a', 1, b'b', 0, // ANSWER NAME (echoed)
            0x00, 0x01, 0x00, 0x01, // TYPE=A, CLASS=IN
            0x00, 0x00, 0x01, 0x2C, // TTL=300
            0x00, 0x04, // RDLENGTH=4
            1, 2, 3, 4, // RDATA
        ];
        assert_eq!(&r[..rn], expected);
    }

    #[test]
    fn encode_name_rejects_double_dot() {
        let mut out = [0u8; 64];
        assert_eq!(
            encode_name_ascii(b"foo..bar", &mut out),
            Err(DnsError::InvalidLabel)
        );
    }

    #[test]
    fn encode_name_rejects_leading_dot() {
        let mut out = [0u8; 64];
        assert_eq!(
            encode_name_ascii(b".foo", &mut out),
            Err(DnsError::InvalidLabel)
        );
    }

    #[test]
    fn encode_name_rejects_trailing_dot() {
        let mut out = [0u8; 64];
        assert_eq!(
            encode_name_ascii(b"foo.", &mut out),
            Err(DnsError::InvalidLabel)
        );
    }

    #[test]
    fn encode_name_rejects_empty() {
        let mut out = [0u8; 64];
        assert_eq!(encode_name_ascii(b"", &mut out), Err(DnsError::InvalidLabel));
    }

    #[test]
    fn encode_name_rejects_overlong_label() {
        // 64-character label (limit is 63).
        let label = [b'x'; 64];
        let mut out = [0u8; 256];
        assert_eq!(
            encode_name_ascii(&label, &mut out),
            Err(DnsError::LabelTooLong)
        );
    }

    #[test]
    fn encode_name_rejects_small_buffer() {
        // 4-byte buf can't fit "abc" + 0 = 5 bytes (0x03 a b c 0x00).
        let mut out = [0u8; 4];
        assert_eq!(
            encode_name_ascii(b"abc", &mut out),
            Err(DnsError::OutputBufferTooSmall)
        );
    }

    #[test]
    fn build_a_query_rejects_small_buffer() {
        let mut out = [0u8; 10]; // Less than DNS_HEADER_LEN (12).
        assert_eq!(
            DnsImpl::build_a_query(1, b"a.b", &mut out),
            Err(DnsError::OutputBufferTooSmall)
        );
    }

    #[test]
    fn build_a_response_rejects_malformed_qname() {
        // No zero terminator.
        let bad: &[u8] = &[1, b'a', 1, b'b']; // missing trailing 0
        let mut out = [0u8; 128];
        let r = DnsImpl::build_a_response(1, bad, [0, 0, 0, 0], 0, &mut out);
        assert_eq!(r, Err(DnsError::InvalidLabel));
    }

    #[test]
    fn scan_name_detects_forward_pointer_loop() {
        // Construct a message where the question name starts at offset
        // 12 and is a pointer to offset 12 itself (self-cycle). The
        // backward-only rule should catch this immediately.
        let mut bytes = [0u8; 16];
        // Header.
        write_u16_be(&mut bytes[0..2], 0);
        write_u16_be(&mut bytes[2..4], 0);
        write_u16_be(&mut bytes[4..6], 1); // qdcount
        // Pointer at offset 12 -> offset 12 (self).
        bytes[12] = 0xC0;
        bytes[13] = 12;
        let r = DnsImpl::parse_message(&bytes);
        assert!(matches!(r, Err(DnsError::CompressionLoop)));
    }

    #[test]
    fn scan_name_accepts_backward_pointer() {
        // Build a synthetic message: header + inline name "a.b" + pointer-to-name.
        // We'll then call scan_name at the pointer location.
        let mut bytes = [0u8; 32];
        write_u16_be(&mut bytes[4..6], 1); // qdcount=1
        // Inline name at offset 12: 01 'a' 01 'b' 00 → 5 bytes
        bytes[12] = 1;
        bytes[13] = b'a';
        bytes[14] = 1;
        bytes[15] = b'b';
        bytes[16] = 0;
        // QTYPE/QCLASS at 17..21
        write_u16_be(&mut bytes[17..19], DnsRecordType::A as u16);
        write_u16_be(&mut bytes[19..21], dns_class::IN);
        // Now place a pointer at offset 21 → 12 (backward).
        bytes[21] = 0xC0;
        bytes[22] = 12;
        // scan_name starting at 21 should return 23 (just past the pointer).
        let end = scan_name(&bytes, 21).unwrap();
        assert_eq!(end, 23);
    }

    #[test]
    fn parse_message_qdcount_zero() {
        // Some responses (e.g. NOTIFY) can have qdcount=0.
        let mut bytes = [0u8; DNS_HEADER_LEN];
        write_u16_be(&mut bytes[0..2], 0xDEAD);
        let view = DnsImpl::parse_message(&bytes).unwrap();
        assert_eq!(view.header.id, 0xDEAD);
        assert_eq!(view.header.qdcount, 0);
        assert!(view.first_question_name.is_none());
    }

    #[test]
    fn build_a_query_handles_max_label() {
        // 63-char label is the limit and must be accepted.
        let mut name = [0u8; 65];
        for i in 0..63 {
            name[i] = b'x';
        }
        name[63] = b'.';
        name[64] = b'a';
        let mut out = [0u8; 256];
        let n = DnsImpl::build_a_query(1, &name[..65], &mut out).unwrap();
        // Confirm parseable.
        let view = DnsImpl::parse_message(&out[..n]).unwrap();
        assert_eq!(view.header.qdcount, 1);
    }
}
