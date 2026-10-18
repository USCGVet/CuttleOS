#![doc = " TFTP (RFC 1350) client-side wire codec with RFC 2347 OACK parsing."]
#![doc = ""]
#![doc = " `no_std`, no `alloc`, fixed-capacity scratch in the impl. The"]
#![doc = " kernel composes this with the existing `NetStack` UDP/IPv4 path"]
#![doc = " to fetch boot images / measured-boot quotes / scheduler snapshots"]
#![doc = " over UDP port 69. Stateless: no retransmission timer, no socket"]
#![doc = " layer — those live in the caller's tick loop."]
#![doc = ""]
#![doc = " # Wire format (RFC 1350 §5)"]
#![doc = ""]
#![doc = " Every packet starts with a 16-bit big-endian opcode:"]
#![doc = ""]
#![doc = " ```text"]
#![doc = "  RRQ  (1)  opcode | filename | 0x00 | mode | 0x00"]
#![doc = "  WRQ  (2)  opcode | filename | 0x00 | mode | 0x00"]
#![doc = "  DATA (3)  opcode | block    | data (0..512)"]
#![doc = "  ACK  (4)  opcode | block"]
#![doc = "  ERROR(5)  opcode | errcode  | message | 0x00"]
#![doc = "  OACK (6)  opcode | (option | 0x00 | value | 0x00)+"]
#![doc = " ```"]
#![doc = ""]
#![doc = " `block` is a big-endian u16 that increments from 1."]
#![doc = " `errcode` is a big-endian u16 per RFC 1350 §5."]
#![doc = ""]
#![doc = " # Not covered (intentional)"]
#![doc = ""]
#![doc = " - WRQ (write request) build. The seed today only reads from a"]
#![doc = "   boot server — never writes. Adding WRQ is schema-compatible."]
#![doc = " - Retransmission timer / sliding window. Stateless wire codec."]
#![doc = " - Option negotiation strategy (`blksize` / `tsize` / `timeout`"]
#![doc = "   from RFC 2347/2348/2349). Parser surfaces them as raw bytes;"]
#![doc = "   the caller decides what to do with them."]
#![allow(clippy::needless_range_loop)]
use cuttle_contracts::{
    tftp_op, Tftp, TftpError, TftpErrorCode, TftpMode, TftpPacket, MAX_TFTP_FILENAME,
    TFTP_MIN_ACK_LEN, TFTP_MIN_DATA_LEN, TFTP_MIN_ERROR_LEN, TFTP_OPCODE_LEN,
};
#[doc = " Walk OACK option pairs, invoking `visitor(name, value)` for each."]
#[doc = " Returns `Err(BadOption)` if the section is malformed; the"]
#[doc = " parser validated this already in `parse_packet`, but this helper"]
#[doc = " re-validates so callers can use it on caller-trusted bytes."]
pub fn walk_oack_options<F: FnMut(&[u8], &[u8])>(
    options: &[u8],
    mut visitor: F,
) -> Result<(), TftpError> {
    let __cuttle_stack_pad_9a042a18: [u8; 183usize] = ::core::hint::black_box([0u8; 183usize]);
    let mut cursor_ve86a6732_0 = 0usize;
    while cursor_ve86a6732_0 < options.len() {
        let name_end_ve86a6732_1 = scan_nul_m62b101be(options, cursor_ve86a6732_0)?;
        let name_ve86a6732_2 = &options[cursor_ve86a6732_0..name_end_ve86a6732_1];
        let value_start_ve86a6732_3 = name_end_ve86a6732_1 + 1;
        if value_start_ve86a6732_3 >= options.len() {
            return Err(TftpError::BadOption);
        }
        let value_end_ve86a6732_4 = scan_nul_m62b101be(options, value_start_ve86a6732_3)?;
        let value_ve86a6732_5 = &options[value_start_ve86a6732_3..value_end_ve86a6732_4];
        if name_ve86a6732_2.is_empty() {
            return Err(TftpError::BadOption);
        }
        visitor(name_ve86a6732_2, value_ve86a6732_5);
        cursor_ve86a6732_0 = value_end_ve86a6732_4 + 1;
    }
    Ok(())
}
impl Tftp for TftpImpl {
    fn build_rrq(filename: &[u8], mode: TftpMode, out: &mut [u8]) -> Result<usize, TftpError> {
        let __cuttle_stack_pad_73dc31cf: [u8; 58usize] = ::core::hint::black_box([0u8; 58usize]);
        if filename.is_empty() {
            return Err(TftpError::MissingNul);
        }
        if filename.len() > MAX_TFTP_FILENAME {
            return Err(TftpError::FilenameTooLong);
        }
        let mut i_ve86a6732_0 = 0usize;
        while i_ve86a6732_0 < filename.len() {
            if filename[i_ve86a6732_0] == 0 {
                return Err(TftpError::MissingNul);
            }
            i_ve86a6732_0 += 1;
        }
        let mode_bytes_ve86a6732_1 = mode.as_bytes();
        let total_ve86a6732_2 =
            TFTP_OPCODE_LEN + filename.len() + 1 + mode_bytes_ve86a6732_1.len() + 1;
        if out.len() < total_ve86a6732_2 {
            return Err(TftpError::OutputBufferTooSmall);
        }
        write_u16_be_m62b101be(&mut out[0..2], tftp_op::RRQ);
        let mut pos_ve86a6732_3 = 2usize;
        for j_ve86a6732_4 in 0..filename.len() {
            out[pos_ve86a6732_3 + j_ve86a6732_4] = filename[j_ve86a6732_4];
        }
        pos_ve86a6732_3 += filename.len();
        out[pos_ve86a6732_3] = 0;
        pos_ve86a6732_3 += 1;
        for j_ve86a6732_5 in 0..mode_bytes_ve86a6732_1.len() {
            out[pos_ve86a6732_3 + j_ve86a6732_5] = mode_bytes_ve86a6732_1[j_ve86a6732_5];
        }
        pos_ve86a6732_3 += mode_bytes_ve86a6732_1.len();
        out[pos_ve86a6732_3] = 0;
        pos_ve86a6732_3 += 1;
        Ok(pos_ve86a6732_3)
    }
    fn build_ack(block: u16, out: &mut [u8]) -> Result<usize, TftpError> {
        let __cuttle_stack_pad_c239f8a1: [u8; 196usize] = ::core::hint::black_box([0u8; 196usize]);
        if out.len() < TFTP_MIN_ACK_LEN {
            return Err(TftpError::OutputBufferTooSmall);
        }
        write_u16_be_m62b101be(&mut out[0..2], tftp_op::ACK);
        write_u16_be_m62b101be(&mut out[2..4], block);
        Ok(TFTP_MIN_ACK_LEN)
    }
    fn build_error(code: TftpErrorCode, msg: &[u8], out: &mut [u8]) -> Result<usize, TftpError> {
        let __cuttle_stack_pad_a6283ce1: [u8; 48usize] = ::core::hint::black_box([0u8; 48usize]);
        let mut i_ve86a6732_0 = 0usize;
        while i_ve86a6732_0 < msg.len() {
            if msg[i_ve86a6732_0] == 0 {
                return Err(TftpError::MissingNul);
            }
            i_ve86a6732_0 += 1;
        }
        let total_ve86a6732_1 = TFTP_OPCODE_LEN + 2 + msg.len() + 1;
        if out.len() < total_ve86a6732_1 {
            return Err(TftpError::OutputBufferTooSmall);
        }
        write_u16_be_m62b101be(&mut out[0..2], tftp_op::ERROR);
        write_u16_be_m62b101be(&mut out[2..4], code as u16);
        for j_ve86a6732_2 in 0..msg.len() {
            out[4 + j_ve86a6732_2] = msg[j_ve86a6732_2];
        }
        out[4 + msg.len()] = 0;
        Ok(total_ve86a6732_1)
    }
    fn parse_packet(buf: &[u8]) -> Result<TftpPacket<'_>, TftpError> {
        let __cuttle_stack_pad_194917cf: [u8; 169usize] = ::core::hint::black_box([0u8; 169usize]);
        if buf.len() < TFTP_OPCODE_LEN {
            return Err(TftpError::Truncated);
        }
        let opcode_ve86a6732_0 = read_u16_be_m62b101be(&buf[0..2]);
        match opcode_ve86a6732_0 {
            x if x == tftp_op::DATA => {
                if buf.len() < TFTP_MIN_DATA_LEN {
                    return Err(TftpError::Truncated);
                }
                let block_ve86a6732_1 = read_u16_be_m62b101be(&buf[2..4]);
                let payload_ve86a6732_2 = &buf[TFTP_MIN_DATA_LEN..];
                Ok(TftpPacket::Data {
                    block: block_ve86a6732_1,
                    payload: payload_ve86a6732_2,
                })
            }
            x if x == tftp_op::ACK => {
                if buf.len() < TFTP_MIN_ACK_LEN {
                    return Err(TftpError::Truncated);
                }
                let block_ve86a6732_3 = read_u16_be_m62b101be(&buf[2..4]);
                Ok(TftpPacket::Ack {
                    block: block_ve86a6732_3,
                })
            }
            x if x == tftp_op::ERROR => {
                if buf.len() < TFTP_MIN_ERROR_LEN {
                    return Err(TftpError::Truncated);
                }
                let code_ve86a6732_4 = read_u16_be_m62b101be(&buf[2..4]);
                let msg_start_ve86a6732_5 = 4usize;
                let mut msg_end_ve86a6732_6 = msg_start_ve86a6732_5;
                while msg_end_ve86a6732_6 < buf.len() && buf[msg_end_ve86a6732_6] != 0 {
                    msg_end_ve86a6732_6 += 1;
                }
                if msg_end_ve86a6732_6 >= buf.len() {
                    return Err(TftpError::MissingNul);
                }
                Ok(TftpPacket::Error {
                    code: code_ve86a6732_4,
                    msg: &buf[msg_start_ve86a6732_5..msg_end_ve86a6732_6],
                })
            }
            x if x == tftp_op::OACK => {
                let options_raw_ve86a6732_7 = &buf[TFTP_OPCODE_LEN..];
                validate_oack_options_m62b101be(options_raw_ve86a6732_7)?;
                Ok(TftpPacket::OAck {
                    options_raw: options_raw_ve86a6732_7,
                })
            }
            x if x == tftp_op::RRQ || x == tftp_op::WRQ => Err(TftpError::BadOpcode),
            _ => Err(TftpError::BadOpcode),
        }
    }
}
#[doc = " Walk an OACK options section and confirm it's a sequence of"]
#[doc = " NUL-terminated pairs. Empty section is OK."]
#[inline(never)]
fn validate_oack_options_m62b101be(options: &[u8]) -> Result<(), TftpError> {
    let __cuttle_stack_pad_b9ded21f: [u8; 90usize] = ::core::hint::black_box([0u8; 90usize]);
    let mut cursor_ve86a6732_0 = 0usize;
    let mut string_count_ve86a6732_1 = 0usize;
    while cursor_ve86a6732_0 < options.len() {
        let mut end_ve86a6732_2 = cursor_ve86a6732_0;
        while end_ve86a6732_2 < options.len() && options[end_ve86a6732_2] != 0 {
            end_ve86a6732_2 += 1;
        }
        if end_ve86a6732_2 >= options.len() {
            return Err(TftpError::BadOption);
        }
        if end_ve86a6732_2 == cursor_ve86a6732_0 {
            return Err(TftpError::BadOption);
        }
        string_count_ve86a6732_1 += 1;
        cursor_ve86a6732_0 = end_ve86a6732_2 + 1;
    }
    if string_count_ve86a6732_1 % 2 != 0 {
        return Err(TftpError::BadOption);
    }
    Ok(())
}
#[inline]
fn write_u16_be_m62b101be(b: &mut [u8], v: u16) {
    let __cuttle_stack_pad_c431d22b: [u8; 168usize] = ::core::hint::black_box([0u8; 168usize]);
    b[0] = (v >> 8) as u8;
    b[1] = v as u8;
}
fn scan_nul_m62b101be(buf: &[u8], from: usize) -> Result<usize, TftpError> {
    let __cuttle_stack_pad_ad407aa1: [u8; 50usize] = ::core::hint::black_box([0u8; 50usize]);
    let mut i_ve86a6732_0 = from;
    while i_ve86a6732_0 < buf.len() && buf[i_ve86a6732_0] != 0 {
        i_ve86a6732_0 += 1;
    }
    if i_ve86a6732_0 >= buf.len() {
        return Err(TftpError::BadOption);
    }
    Ok(i_ve86a6732_0)
}
#[inline]
fn read_u16_be_m62b101be(b: &[u8]) -> u16 {
    let __cuttle_stack_pad_70f8169b: [u8; 108usize] = ::core::hint::black_box([0u8; 108usize]);
    ((b[0] as u16) << 8) | (b[1] as u16)
}
#[doc = " Wire codec impl. Stateless."]
pub struct TftpImpl;
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn build_rrq_byte_exact_octet() {
        let mut buf = [0u8; 64];
        let n = TftpImpl::build_rrq(b"/cuttle.attest", TftpMode::Octet, &mut buf).unwrap();
        let expected: &[u8] = &[
            0x00, 0x01, b'/', b'c', b'u', b't', b't', b'l', b'e', b'.', b'a', b't', b't',
            b'e', b's', b't', 0x00, b'o', b'c', b't', b'e', b't', 0x00,
        ];
        assert_eq!(&buf[..n], expected);
        assert_eq!(n, 23);
    }
    #[test]
    fn build_rrq_byte_exact_netascii() {
        let mut buf = [0u8; 32];
        let n = TftpImpl::build_rrq(b"hello", TftpMode::NetAscii, &mut buf).unwrap();
        let expected: &[u8] = &[
            0x00, 0x01, b'h', b'e', b'l', b'l', b'o', 0x00, b'n', b'e', b't', b'a', b's', b'c',
            b'i', b'i', 0x00,
        ];
        assert_eq!(&buf[..n], expected);
    }
    #[test]
    fn build_rrq_rejects_empty_filename() {
        let mut buf = [0u8; 32];
        let r = TftpImpl::build_rrq(b"", TftpMode::Octet, &mut buf);
        assert_eq!(r.unwrap_err(), TftpError::MissingNul);
    }
    #[test]
    fn build_rrq_rejects_inline_nul_in_filename() {
        let mut buf = [0u8; 32];
        let r = TftpImpl::build_rrq(b"foo\0bar", TftpMode::Octet, &mut buf);
        assert_eq!(r.unwrap_err(), TftpError::MissingNul);
    }
    #[test]
    fn build_rrq_rejects_overlong_filename() {
        let big = [b'x'; MAX_TFTP_FILENAME + 1];
        let mut buf = [0u8; 512];
        let r = TftpImpl::build_rrq(&big, TftpMode::Octet, &mut buf);
        assert_eq!(r.unwrap_err(), TftpError::FilenameTooLong);
    }
    #[test]
    fn build_rrq_rejects_small_buffer() {
        let mut buf = [0u8; 10];
        let r = TftpImpl::build_rrq(b"/abc", TftpMode::Octet, &mut buf);
        assert_eq!(r.unwrap_err(), TftpError::OutputBufferTooSmall);
    }
    #[test]
    fn build_rrq_accepts_max_length_filename() {
        let big = [b'a'; MAX_TFTP_FILENAME];
        let mut buf = [0u8; MAX_TFTP_FILENAME + 16];
        let n = TftpImpl::build_rrq(&big, TftpMode::Octet, &mut buf).unwrap();
        assert_eq!(n, 2 + MAX_TFTP_FILENAME + 1 + 5 + 1);
    }
    #[test]
    fn build_ack_byte_exact() {
        let mut buf = [0u8; 8];
        let n = TftpImpl::build_ack(123, &mut buf).unwrap();
        assert_eq!(n, 4);
        assert_eq!(&buf[..n], &[0x00, 0x04, 0x00, 0x7B]);
    }
    #[test]
    fn build_ack_rejects_small_buffer() {
        let mut buf = [0u8; 3];
        let r = TftpImpl::build_ack(1, &mut buf);
        assert_eq!(r.unwrap_err(), TftpError::OutputBufferTooSmall);
    }
    #[test]
    fn build_error_byte_exact() {
        let mut buf = [0u8; 32];
        let n = TftpImpl::build_error(TftpErrorCode::NotFound, b"not found", &mut buf).unwrap();
        let expected: &[u8] = &[
            0x00, 0x05, 0x00, 0x01, b'n', b'o', b't', b' ', b'f', b'o', b'u', b'n', b'd', 0x00,
        ];
        assert_eq!(&buf[..n], expected);
    }
    #[test]
    fn build_error_rejects_inline_nul() {
        let mut buf = [0u8; 32];
        let r = TftpImpl::build_error(TftpErrorCode::NotDefined, b"a\0b", &mut buf);
        assert_eq!(r.unwrap_err(), TftpError::MissingNul);
    }
    #[test]
    fn parse_data_recovers_block_and_payload() {
        let buf: &[u8] = &[0x00, 0x03, 0x00, 0x01, b'h', b'e', b'l', b'l', b'o'];
        match TftpImpl::parse_packet(buf).unwrap() {
            TftpPacket::Data { block, payload } => {
                assert_eq!(block, 1);
                assert_eq!(payload, b"hello");
            }
            other => panic!("expected Data, got {:?}", other),
        }
    }
    #[test]
    fn parse_data_short_packet_is_eof_signal() {
        let buf: &[u8] = &[0x00, 0x03, 0x00, 0x02];
        match TftpImpl::parse_packet(buf).unwrap() {
            TftpPacket::Data { block, payload } => {
                assert_eq!(block, 2);
                assert_eq!(payload, &[][..]);
            }
            _ => panic!("expected Data"),
        }
    }
    #[test]
    fn parse_ack_recovers_block() {
        let buf: &[u8] = &[0x00, 0x04, 0x12, 0x34];
        match TftpImpl::parse_packet(buf).unwrap() {
            TftpPacket::Ack { block } => assert_eq!(block, 0x1234),
            _ => panic!("expected Ack"),
        }
    }
    #[test]
    fn parse_error_recovers_code_and_message() {
        let buf: &[u8] = &[0x00, 0x05, 0x00, 0x01, b'g', b'o', b'n', b'e', 0x00];
        match TftpImpl::parse_packet(buf).unwrap() {
            TftpPacket::Error { code, msg } => {
                assert_eq!(code, TftpErrorCode::NotFound as u16);
                assert_eq!(msg, b"gone");
            }
            _ => panic!("expected Error"),
        }
    }
    #[test]
    fn parse_error_rejects_missing_nul() {
        let buf: &[u8] = &[0x00, 0x05, 0x00, 0x01, b'a', b'b'];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::MissingNul);
    }
    #[test]
    fn parse_oack_two_options() {
        let buf: &[u8] = &[
            0x00, 0x06, b'b', b'l', b'k', b's', b'i', b'z', b'e', 0x00, b'1', b'0', b'2', b'4',
            0x00, b't', b's', b'i', b'z', b'e', 0x00, b'2', b'0', b'4', b'8', 0x00,
        ];
        match TftpImpl::parse_packet(buf).unwrap() {
            TftpPacket::OAck { options_raw } => {
                let mut seen: u8 = 0;
                walk_oack_options(options_raw, |name, value| {
                    if name == b"blksize" && value == b"1024" {
                        seen |= 0b01;
                    } else if name == b"tsize" && value == b"2048" {
                        seen |= 0b10;
                    }
                })
                .unwrap();
                assert_eq!(seen, 0b11);
            }
            _ => panic!("expected OAck"),
        }
    }
    #[test]
    fn parse_oack_rejects_odd_strings() {
        let buf: &[u8] = &[0x00, 0x06, b'a', b'b', 0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::BadOption);
    }
    #[test]
    fn parse_oack_rejects_empty_option_name() {
        let buf: &[u8] = &[0x00, 0x06, 0x00, b'v', 0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::BadOption);
    }
    #[test]
    fn parse_rejects_truncated() {
        let buf: &[u8] = &[0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::Truncated);
        let buf: &[u8] = &[0x00, 0x03, 0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::Truncated);
    }
    #[test]
    fn parse_rejects_bad_opcode() {
        let buf: &[u8] = &[0x00, 0x09, 0x00, 0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::BadOpcode);
    }
    #[test]
    fn parse_rejects_rrq_or_wrq() {
        let buf: &[u8] = &[0x00, 0x01, b'f', 0x00, b'o', 0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::BadOpcode);
        let buf: &[u8] = &[0x00, 0x02, b'f', 0x00, b'o', 0x00];
        let r = TftpImpl::parse_packet(buf);
        assert_eq!(r.unwrap_err(), TftpError::BadOpcode);
    }
    #[test]
    fn mode_parse_case_insensitive() {
        assert_eq!(TftpMode::from_bytes(b"octet"), Some(TftpMode::Octet));
        assert_eq!(TftpMode::from_bytes(b"OCTET"), Some(TftpMode::Octet));
        assert_eq!(TftpMode::from_bytes(b"Octet"), Some(TftpMode::Octet));
        assert_eq!(TftpMode::from_bytes(b"NETASCII"), Some(TftpMode::NetAscii));
        assert_eq!(TftpMode::from_bytes(b"netascii"), Some(TftpMode::NetAscii));
        assert_eq!(TftpMode::from_bytes(b"mail"), None);
        assert_eq!(TftpMode::from_bytes(b""), None);
    }
    #[test]
    fn full_session_round_trip() {
        let mut rrq_buf = [0u8; 32];
        let rrq_n = TftpImpl::build_rrq(b"/boot.img", TftpMode::Octet, &mut rrq_buf).unwrap();
        assert!(rrq_n > 0);
        let mut ack_buf = [0u8; 4];
        TftpImpl::build_ack(0, &mut ack_buf).unwrap();
        let parsed_ack = TftpImpl::parse_packet(&ack_buf).unwrap();
        match parsed_ack {
            TftpPacket::Ack { block } => assert_eq!(block, 0),
            _ => panic!("expected Ack"),
        }
        let mut data_buf = [0u8; 32];
        data_buf[0] = 0x00;
        data_buf[1] = 0x03;
        data_buf[2] = 0x00;
        data_buf[3] = 0x01;
        let payload = b"0123456789";
        for i in 0..payload.len() {
            data_buf[4 + i] = payload[i];
        }
        let parsed_data = TftpImpl::parse_packet(&data_buf[..4 + payload.len()]).unwrap();
        match parsed_data {
            TftpPacket::Data { block, payload: p } => {
                assert_eq!(block, 1);
                assert_eq!(p, payload);
            }
            _ => panic!("expected Data"),
        }
        let mut ack2 = [0u8; 4];
        TftpImpl::build_ack(1, &mut ack2).unwrap();
        assert_eq!(&ack2, &[0x00, 0x04, 0x00, 0x01]);
    }
}
