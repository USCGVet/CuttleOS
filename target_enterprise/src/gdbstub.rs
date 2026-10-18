//! GDB Remote Serial Protocol (RSP) wire codec — TASK-065.
//!
//! Pure, allocation-free framing + command classification + canned
//! reply bodies. No live target halt, no INT3 rewrite, no serial
//! I/O — those compose on top of this surface.
//!
//! # Wire shape
//!
//! ```text
//!   $ <body-bytes> # <cs-hi> <cs-lo>
//! ```
//!
//! where `<cs>` is the 8-bit wrapping sum of every body byte,
//! encoded as two lowercase ASCII hex digits. The stub ACKs a
//! well-framed packet with `+` and NACKs a bad checksum with `-`.
//!
//! # Banner fixture
//!
//! `$g#67` — body = `g` (0x67), checksum digits `67`. The canned
//! `g` reply is 256 hex `0` characters (16 × 8-byte zeroed GPRs).

#![allow(clippy::needless_range_loop)]

use cuttle_contracts::{
    GdbCommand, GdbError, GdbPacket, GdbStub, GDB_ACK, GDB_INTERRUPT, GDB_MAX_BODY,
    GDB_MAX_MEM_READ, GDB_NACK, GDB_PACKET_END, GDB_PACKET_START, GDB_REG_HEX_LEN, GDB_SIGTRAP,
};

// ---------------------------------------------------------------------------
// Hex helpers
// ---------------------------------------------------------------------------

/// Decode one ASCII hex nibble. Accepts `0-9` / `a-f` / `A-F`.
#[inline]
pub fn hex_nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Encode one byte as two lowercase hex digits into `out[0..2]`.
#[inline]
pub fn put_hex_byte(out: &mut [u8], b: u8) {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    out[0] = LUT[(b >> 4) as usize];
    out[1] = LUT[(b & 0x0f) as usize];
}

/// Parse an unsigned hex integer (1..=16 digits). Empty → `None`.
pub fn parse_hex_u64(s: &[u8]) -> Option<u64> {
    if s.is_empty() || s.len() > 16 {
        return None;
    }
    let mut acc: u64 = 0;
    let mut i = 0usize;
    while i < s.len() {
        let n = hex_nibble(s[i])?;
        acc = (acc << 4) | (n as u64);
        i += 1;
    }
    Some(acc)
}

// ---------------------------------------------------------------------------
// Free functions (diversifier alias-safe)
// ---------------------------------------------------------------------------

/// RSP checksum: 8-bit wrapping sum of body bytes.
pub fn checksum_impl(body: &[u8]) -> u8 {
    let mut sum: u8 = 0;
    let mut i = 0usize;
    while i < body.len() {
        sum = sum.wrapping_add(body[i]);
        i += 1;
    }
    sum
}

/// Parse a complete `$body#cs` frame.
pub fn parse_frame_impl(frame: &[u8]) -> Result<GdbPacket<'_>, GdbError> {
    // Minimum: $#00 → 4 bytes.
    if frame.len() < 4 {
        return Err(GdbError::Truncated);
    }
    if frame[0] != GDB_PACKET_START {
        return Err(GdbError::BadFraming);
    }
    // Find '#'.
    let mut hash_at = None;
    let mut i = 1usize;
    while i < frame.len() {
        if frame[i] == GDB_PACKET_END {
            hash_at = Some(i);
            break;
        }
        i += 1;
    }
    let hash_at = match hash_at {
        Some(p) => p,
        None => return Err(GdbError::Truncated),
    };
    if frame.len() < hash_at + 3 {
        return Err(GdbError::Truncated);
    }
    let body = &frame[1..hash_at];
    if body.len() > GDB_MAX_BODY {
        return Err(GdbError::BodyTooLong);
    }
    let hi = match hex_nibble(frame[hash_at + 1]) {
        Some(v) => v,
        None => return Err(GdbError::BadChecksum),
    };
    let lo = match hex_nibble(frame[hash_at + 2]) {
        Some(v) => v,
        None => return Err(GdbError::BadChecksum),
    };
    let got = (hi << 4) | lo;
    let expected = checksum_impl(body);
    if got != expected {
        return Err(GdbError::BadChecksum);
    }
    Ok(GdbPacket {
        body,
        checksum: got,
    })
}

/// Frame `body` as `$body#cs` into `out`.
pub fn build_frame_impl(body: &[u8], out: &mut [u8]) -> Result<usize, GdbError> {
    if body.len() > GDB_MAX_BODY {
        return Err(GdbError::BodyTooLong);
    }
    let need = 1 + body.len() + 1 + 2;
    if out.len() < need {
        return Err(GdbError::BufferTooSmall);
    }
    out[0] = GDB_PACKET_START;
    out[1..1 + body.len()].copy_from_slice(body);
    out[1 + body.len()] = GDB_PACKET_END;
    let cs = checksum_impl(body);
    put_hex_byte(&mut out[2 + body.len()..], cs);
    Ok(need)
}

/// Classify a packet body into a [`GdbCommand`].
pub fn classify_impl(body: &[u8]) -> GdbCommand {
    if body.is_empty() {
        return GdbCommand::Empty;
    }
    match body[0] {
        b'g' if body.len() == 1 => GdbCommand::ReadRegisters,
        b'G' => GdbCommand::WriteRegisters,
        b'm' => match parse_mem_args(&body[1..]) {
            Some((addr, len)) => GdbCommand::ReadMemory { addr, len },
            None => GdbCommand::Unknown,
        },
        b'M' => GdbCommand::WriteMemory,
        b'Z' => match parse_breakpoint_args(&body[1..]) {
            Some(addr) => GdbCommand::SetBreakpoint { addr },
            None => GdbCommand::Unknown,
        },
        b'c' if body.len() == 1 || body[1] == b';' || body[1].is_ascii_hexdigit() => {
            GdbCommand::Continue
        }
        b's' if body.len() == 1 || body[1].is_ascii_hexdigit() => GdbCommand::Step,
        b'D' if body.len() == 1 => GdbCommand::Detach,
        b'?' if body.len() == 1 => GdbCommand::HaltReason,
        b'q' => {
            if body.len() >= 10 && &body[1..10] == b"Supported" {
                GdbCommand::QuerySupported
            } else if body == b"qC" {
                GdbCommand::QueryCurrentThread
            } else {
                GdbCommand::Unknown
            }
        }
        b'v' => {
            if body == b"vMustReplyEmpty" {
                GdbCommand::VMustReplyEmpty
            } else {
                GdbCommand::Unknown
            }
        }
        _ => GdbCommand::Unknown,
    }
}

/// Parse `addr,len` after the `m` command byte.
fn parse_mem_args(args: &[u8]) -> Option<(u64, u64)> {
    let mut comma = None;
    let mut i = 0usize;
    while i < args.len() {
        if args[i] == b',' {
            comma = Some(i);
            break;
        }
        i += 1;
    }
    let comma = comma?;
    let addr = parse_hex_u64(&args[..comma])?;
    let len = parse_hex_u64(&args[comma + 1..])?;
    Some((addr, len))
}

/// Parse `0,addr,kind` after the `Z` command byte (software BP).
fn parse_breakpoint_args(args: &[u8]) -> Option<u64> {
    // Expect "0,<addr>,<kind>"
    if args.is_empty() || args[0] != b'0' {
        return None;
    }
    if args.len() < 3 || args[1] != b',' {
        return None;
    }
    let rest = &args[2..];
    let mut comma2 = None;
    let mut i = 0usize;
    while i < rest.len() {
        if rest[i] == b',' {
            comma2 = Some(i);
            break;
        }
        i += 1;
    }
    let comma2 = comma2?;
    parse_hex_u64(&rest[..comma2])
}

/// Build the reply body for a classified command.
pub fn reply_body_impl(cmd: &GdbCommand, out: &mut [u8]) -> Result<usize, GdbError> {
    match *cmd {
        GdbCommand::ReadRegisters => {
            if out.len() < GDB_REG_HEX_LEN {
                return Err(GdbError::BufferTooSmall);
            }
            let mut i = 0usize;
            while i < GDB_REG_HEX_LEN {
                out[i] = b'0';
                i += 1;
            }
            Ok(GDB_REG_HEX_LEN)
        }
        GdbCommand::WriteRegisters
        | GdbCommand::SetBreakpoint { .. }
        | GdbCommand::Detach => {
            if out.len() < 2 {
                return Err(GdbError::BufferTooSmall);
            }
            out[0] = b'O';
            out[1] = b'K';
            Ok(2)
        }
        GdbCommand::WriteMemory => {
            // Refuse writes in the seed stub.
            if out.len() < 3 {
                return Err(GdbError::BufferTooSmall);
            }
            out[0] = b'E';
            out[1] = b'0';
            out[2] = b'1';
            Ok(3)
        }
        GdbCommand::ReadMemory { len, .. } => {
            if len == 0 {
                return Ok(0);
            }
            if len > GDB_MAX_MEM_READ {
                if out.len() < 3 {
                    return Err(GdbError::BufferTooSmall);
                }
                out[0] = b'E';
                out[1] = b'0';
                out[2] = b'1';
                return Ok(3);
            }
            // No live target: return zeros of the requested length
            // (hex-encoded) so the wire shape is still exercisable.
            let need = (len as usize) * 2;
            if out.len() < need {
                return Err(GdbError::BufferTooSmall);
            }
            let mut i = 0usize;
            while i < need {
                out[i] = b'0';
                i += 1;
            }
            Ok(need)
        }
        GdbCommand::Continue | GdbCommand::Step | GdbCommand::HaltReason | GdbCommand::Interrupt => {
            // S05 = SIGTRAP.
            if out.len() < 3 {
                return Err(GdbError::BufferTooSmall);
            }
            out[0] = b'S';
            put_hex_byte(&mut out[1..], GDB_SIGTRAP);
            Ok(3)
        }
        GdbCommand::QuerySupported => {
            // PacketSize=400
            const REPLY: &[u8] = b"PacketSize=400";
            if out.len() < REPLY.len() {
                return Err(GdbError::BufferTooSmall);
            }
            out[..REPLY.len()].copy_from_slice(REPLY);
            Ok(REPLY.len())
        }
        GdbCommand::QueryCurrentThread => {
            const REPLY: &[u8] = b"QC00";
            if out.len() < REPLY.len() {
                return Err(GdbError::BufferTooSmall);
            }
            out[..REPLY.len()].copy_from_slice(REPLY);
            Ok(REPLY.len())
        }
        GdbCommand::VMustReplyEmpty
        | GdbCommand::Empty
        | GdbCommand::Unknown
        | GdbCommand::Ack
        | GdbCommand::Nack => Ok(0),
    }
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

/// Stateless GDB RSP wire-codec impl.
pub struct GdbStubImpl;

impl GdbStub for GdbStubImpl {
    fn checksum(body: &[u8]) -> u8 {
        checksum_impl(body)
    }

    fn parse_frame(frame: &[u8]) -> Result<GdbPacket<'_>, GdbError> {
        parse_frame_impl(frame)
    }

    fn build_frame(body: &[u8], out: &mut [u8]) -> Result<usize, GdbError> {
        build_frame_impl(body, out)
    }

    fn classify(body: &[u8]) -> GdbCommand {
        classify_impl(body)
    }

    fn reply_body(cmd: &GdbCommand, out: &mut [u8]) -> Result<usize, GdbError> {
        reply_body_impl(cmd, out)
    }
}

/// Classify a standalone control byte (`+` / `-` / `0x03`).
pub fn classify_control(b: u8) -> GdbCommand {
    match b {
        GDB_ACK => GdbCommand::Ack,
        GDB_NACK => GdbCommand::Nack,
        GDB_INTERRUPT => GdbCommand::Interrupt,
        _ => GdbCommand::Unknown,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::GdbStub;

    #[test]
    fn constants_locked() {
        assert_eq!(GDB_ACK, b'+');
        assert_eq!(GDB_NACK, b'-');
        assert_eq!(GDB_PACKET_START, b'$');
        assert_eq!(GDB_PACKET_END, b'#');
        assert_eq!(GDB_INTERRUPT, 0x03);
        assert_eq!(GDB_MAX_BODY, 400);
        assert_eq!(GDB_REG_HEX_LEN, 256);
        assert_eq!(GDB_MAX_MEM_READ, 256);
        assert_eq!(GDB_SIGTRAP, 0x05);
    }

    #[test]
    fn checksum_of_g_is_0x67() {
        assert_eq!(GdbStubImpl::checksum(b"g"), 0x67);
        assert_eq!(checksum_impl(b"g"), 0x67);
    }

    #[test]
    fn checksum_empty_is_zero() {
        assert_eq!(GdbStubImpl::checksum(b""), 0);
    }

    #[test]
    fn checksum_wrapping() {
        // 0xFF + 0x02 = 0x01 wrapping
        assert_eq!(GdbStubImpl::checksum(&[0xFF, 0x02]), 0x01);
    }

    #[test]
    fn parse_banner_packet_g() {
        let frame = b"$g#67";
        let pkt = GdbStubImpl::parse_frame(frame).unwrap();
        assert_eq!(pkt.body, b"g");
        assert_eq!(pkt.checksum, 0x67);
    }

    #[test]
    fn build_frame_g_matches_banner() {
        let mut out = [0u8; 16];
        let n = GdbStubImpl::build_frame(b"g", &mut out).unwrap();
        assert_eq!(n, 5);
        assert_eq!(&out[..n], b"$g#67");
    }

    #[test]
    fn parse_rejects_bad_checksum() {
        assert_eq!(
            GdbStubImpl::parse_frame(b"$g#00"),
            Err(GdbError::BadChecksum)
        );
    }

    #[test]
    fn parse_rejects_truncated() {
        assert_eq!(GdbStubImpl::parse_frame(b"$g#6"), Err(GdbError::Truncated));
        assert_eq!(GdbStubImpl::parse_frame(b"$g"), Err(GdbError::Truncated));
        assert_eq!(GdbStubImpl::parse_frame(b""), Err(GdbError::Truncated));
    }

    #[test]
    fn parse_rejects_bad_framing() {
        assert_eq!(
            GdbStubImpl::parse_frame(b"g#67"),
            Err(GdbError::BadFraming)
        );
    }

    #[test]
    fn parse_rejects_non_hex_checksum() {
        assert_eq!(
            GdbStubImpl::parse_frame(b"$g#zz"),
            Err(GdbError::BadChecksum)
        );
    }

    #[test]
    fn parse_empty_body() {
        // checksum of "" is 0 → #00
        let pkt = GdbStubImpl::parse_frame(b"$#00").unwrap();
        assert!(pkt.body.is_empty());
        assert_eq!(pkt.checksum, 0);
    }

    #[test]
    fn round_trip_frame() {
        let bodies: &[&[u8]] = &[b"g", b"?", b"S05", b"PacketSize=400", b"m1000,10", b""];
        for body in bodies {
            let mut frame = [0u8; 64];
            let n = GdbStubImpl::build_frame(body, &mut frame).unwrap();
            let pkt = GdbStubImpl::parse_frame(&frame[..n]).unwrap();
            assert_eq!(pkt.body, *body);
            assert_eq!(pkt.checksum, GdbStubImpl::checksum(body));
        }
    }

    #[test]
    fn classify_read_registers() {
        assert_eq!(
            GdbStubImpl::classify(b"g"),
            GdbCommand::ReadRegisters
        );
    }

    #[test]
    fn classify_halt_continue_step_detach() {
        assert_eq!(GdbStubImpl::classify(b"?"), GdbCommand::HaltReason);
        assert_eq!(GdbStubImpl::classify(b"c"), GdbCommand::Continue);
        assert_eq!(GdbStubImpl::classify(b"s"), GdbCommand::Step);
        assert_eq!(GdbStubImpl::classify(b"D"), GdbCommand::Detach);
    }

    #[test]
    fn classify_qsupported() {
        assert_eq!(
            GdbStubImpl::classify(b"qSupported"),
            GdbCommand::QuerySupported
        );
        assert_eq!(
            GdbStubImpl::classify(b"qSupported:multiprocess+"),
            GdbCommand::QuerySupported
        );
    }

    #[test]
    fn classify_vmustreplyempty() {
        assert_eq!(
            GdbStubImpl::classify(b"vMustReplyEmpty"),
            GdbCommand::VMustReplyEmpty
        );
    }

    #[test]
    fn classify_memory_read() {
        match GdbStubImpl::classify(b"m1000,20") {
            GdbCommand::ReadMemory { addr, len } => {
                assert_eq!(addr, 0x1000);
                assert_eq!(len, 0x20);
            }
            other => panic!("expected ReadMemory, got {:?}", other),
        }
    }

    #[test]
    fn classify_memory_write() {
        assert_eq!(
            GdbStubImpl::classify(b"M1000,2:00ff"),
            GdbCommand::WriteMemory
        );
    }

    #[test]
    fn classify_breakpoint() {
        match GdbStubImpl::classify(b"Z0,401000,1") {
            GdbCommand::SetBreakpoint { addr } => assert_eq!(addr, 0x401000),
            other => panic!("expected SetBreakpoint, got {:?}", other),
        }
    }

    #[test]
    fn classify_empty_and_unknown() {
        assert_eq!(GdbStubImpl::classify(b""), GdbCommand::Empty);
        assert_eq!(GdbStubImpl::classify(b"xyz"), GdbCommand::Unknown);
    }

    #[test]
    fn classify_control_bytes() {
        assert_eq!(classify_control(GDB_ACK), GdbCommand::Ack);
        assert_eq!(classify_control(GDB_NACK), GdbCommand::Nack);
        assert_eq!(classify_control(GDB_INTERRUPT), GdbCommand::Interrupt);
    }

    #[test]
    fn reply_read_registers_is_256_zeros() {
        let mut out = [0u8; GDB_REG_HEX_LEN];
        let n = GdbStubImpl::reply_body(&GdbCommand::ReadRegisters, &mut out).unwrap();
        assert_eq!(n, 256);
        assert!(out.iter().all(|&b| b == b'0'));
    }

    #[test]
    fn reply_read_registers_frame_checksum() {
        let mut body = [0u8; GDB_REG_HEX_LEN];
        let n = GdbStubImpl::reply_body(&GdbCommand::ReadRegisters, &mut body).unwrap();
        let cs = GdbStubImpl::checksum(&body[..n]);
        // 256 × '0' (0x30) = 256 * 0x30 = 0x3000 → low byte 0x00
        assert_eq!(cs, 0x00);
        let mut frame = [0u8; 512];
        let flen = GdbStubImpl::build_frame(&body[..n], &mut frame).unwrap();
        assert_eq!(frame[flen - 2], b'0');
        assert_eq!(frame[flen - 1], b'0');
        // Round-trip parse.
        let pkt = GdbStubImpl::parse_frame(&frame[..flen]).unwrap();
        assert_eq!(pkt.body.len(), 256);
    }

    #[test]
    fn reply_halt_is_s05() {
        let mut out = [0u8; 8];
        let n = GdbStubImpl::reply_body(&GdbCommand::HaltReason, &mut out).unwrap();
        assert_eq!(&out[..n], b"S05");
    }

    #[test]
    fn reply_continue_and_step_are_s05() {
        let mut out = [0u8; 8];
        assert_eq!(
            GdbStubImpl::reply_body(&GdbCommand::Continue, &mut out).unwrap(),
            3
        );
        assert_eq!(&out[..3], b"S05");
        assert_eq!(
            GdbStubImpl::reply_body(&GdbCommand::Step, &mut out).unwrap(),
            3
        );
        assert_eq!(&out[..3], b"S05");
    }

    #[test]
    fn reply_write_memory_is_e01() {
        let mut out = [0u8; 8];
        let n = GdbStubImpl::reply_body(&GdbCommand::WriteMemory, &mut out).unwrap();
        assert_eq!(&out[..n], b"E01");
    }

    #[test]
    fn reply_ok_commands() {
        let mut out = [0u8; 8];
        for cmd in [
            GdbCommand::WriteRegisters,
            GdbCommand::Detach,
            GdbCommand::SetBreakpoint { addr: 0x1000 },
        ] {
            let n = GdbStubImpl::reply_body(&cmd, &mut out).unwrap();
            assert_eq!(&out[..n], b"OK");
        }
    }

    #[test]
    fn reply_qsupported() {
        let mut out = [0u8; 32];
        let n = GdbStubImpl::reply_body(&GdbCommand::QuerySupported, &mut out).unwrap();
        assert_eq!(&out[..n], b"PacketSize=400");
    }

    #[test]
    fn reply_vmustreplyempty_is_empty() {
        let mut out = [0u8; 8];
        let n = GdbStubImpl::reply_body(&GdbCommand::VMustReplyEmpty, &mut out).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn reply_mem_read_zeros() {
        let mut out = [0u8; 64];
        let n = GdbStubImpl::reply_body(
            &GdbCommand::ReadMemory {
                addr: 0x1000,
                len: 4,
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(n, 8);
        assert_eq!(&out[..8], b"00000000");
    }

    #[test]
    fn reply_mem_read_oversize_is_e01() {
        let mut out = [0u8; 8];
        let n = GdbStubImpl::reply_body(
            &GdbCommand::ReadMemory {
                addr: 0,
                len: GDB_MAX_MEM_READ + 1,
            },
            &mut out,
        )
        .unwrap();
        assert_eq!(&out[..n], b"E01");
    }

    #[test]
    fn parse_hex_u64_basic() {
        assert_eq!(parse_hex_u64(b"0"), Some(0));
        assert_eq!(parse_hex_u64(b"ff"), Some(0xFF));
        assert_eq!(parse_hex_u64(b"1000"), Some(0x1000));
        assert_eq!(parse_hex_u64(b""), None);
        assert_eq!(parse_hex_u64(b"gg"), None);
    }

    #[test]
    fn hex_nibble_cases() {
        assert_eq!(hex_nibble(b'0'), Some(0));
        assert_eq!(hex_nibble(b'9'), Some(9));
        assert_eq!(hex_nibble(b'a'), Some(10));
        assert_eq!(hex_nibble(b'F'), Some(15));
        assert_eq!(hex_nibble(b'x'), None);
    }

    #[test]
    fn build_frame_buffer_too_small() {
        let mut out = [0u8; 3];
        assert_eq!(
            GdbStubImpl::build_frame(b"g", &mut out),
            Err(GdbError::BufferTooSmall)
        );
    }

    #[test]
    fn body_too_long_rejected() {
        let big = [b'a'; GDB_MAX_BODY + 1];
        let mut out = [0u8; 512];
        assert_eq!(
            GdbStubImpl::build_frame(&big, &mut out),
            Err(GdbError::BodyTooLong)
        );
    }

    #[test]
    fn free_functions_match_trait() {
        assert_eq!(
            checksum_impl(b"hello"),
            GdbStubImpl::checksum(b"hello")
        );
        assert_eq!(
            classify_impl(b"g"),
            GdbStubImpl::classify(b"g")
        );
    }

    #[test]
    fn end_to_end_banner_scenario() {
        // Parse $g#67, classify, build reply, frame it, re-parse.
        let pkt = GdbStubImpl::parse_frame(b"$g#67").unwrap();
        assert_eq!(pkt.body, b"g");
        assert_eq!(pkt.checksum, 0x67);
        let cmd = GdbStubImpl::classify(pkt.body);
        assert_eq!(cmd, GdbCommand::ReadRegisters);
        let mut body = [0u8; GDB_REG_HEX_LEN];
        let n = GdbStubImpl::reply_body(&cmd, &mut body).unwrap();
        assert_eq!(n, GDB_REG_HEX_LEN);
        let mut frame = [0u8; 512];
        let flen = GdbStubImpl::build_frame(&body[..n], &mut frame).unwrap();
        let again = GdbStubImpl::parse_frame(&frame[..flen]).unwrap();
        assert_eq!(again.body.len(), 256);
        assert_eq!(again.checksum, 0x00);
    }

    #[test]
    fn query_current_thread() {
        assert_eq!(
            GdbStubImpl::classify(b"qC"),
            GdbCommand::QueryCurrentThread
        );
        let mut out = [0u8; 8];
        let n = GdbStubImpl::reply_body(&GdbCommand::QueryCurrentThread, &mut out).unwrap();
        assert_eq!(&out[..n], b"QC00");
    }
}
