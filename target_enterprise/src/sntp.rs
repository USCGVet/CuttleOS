//! SNTPv4 client wire codec — RFC 4330.
//!
//! Stateless 48-byte big-endian packet builder + parser. The kernel
//! composes this with the existing [`crate::net::NetStackImpl`] UDP
//! path to fetch wall-clock time during boot or routine
//! resynchronisation.
//!
//! No `alloc`, no `std`, no global state. Pure functions over
//! caller-supplied byte buffers + the [`NtpTimestamp`] fixed-point
//! type. Every wire field is read/written byte-by-byte with explicit
//! big-endian helpers — no `from_be_bytes` on `&buf[i..i+4]` slice
//! patterns, so the morph engine's fixed-array vs slice-projection
//! rewrites preserve the same wire layout regardless of how the
//! internals choose to spell the byte fetches.
//!
//! # Wire layout (48 bytes, RFC 4330 §3)
//!
//! ```text
//!  0                   1                   2                   3
//!  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |LI | VN  |Mode |   Stratum     |     Poll      |  Precision    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                          Root Delay                           |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                       Root Dispersion                         |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Reference Identifier                      |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Reference Timestamp (64)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                    Originate Timestamp (64)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Receive Timestamp (64)                    |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! |                     Transmit Timestamp (64)                   |
//! +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//! ```

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    NtpClockSkew, NtpReply, NtpTimestamp, Sntp, SntpError, SNTP_LEAP_ALARM, SNTP_MAX_STRATUM,
    SNTP_MODE_CLIENT, SNTP_MODE_SERVER, SNTP_OFFSET_ORIGIN_TS, SNTP_OFFSET_RECEIVE_TS,
    SNTP_OFFSET_REFERENCE_TS, SNTP_OFFSET_REF_ID, SNTP_OFFSET_TRANSMIT_TS, SNTP_PACKET_LEN,
    SNTP_VERSION,
};

/// Stateless wire codec impl.
///
/// The struct itself carries no state — every method is associated.
/// The kernel constructs `SntpImpl` as a marker for the `Sntp` impl
/// at the call site; no runtime allocation.
pub struct SntpImpl;

impl Sntp for SntpImpl {
    fn build_request(client_now: NtpTimestamp, out: &mut [u8]) -> Result<usize, SntpError> {
        build_request_impl(client_now, out)
    }

    fn parse_reply(buf: &[u8]) -> Result<NtpReply, SntpError> {
        parse_reply_impl(buf)
    }

    fn compute_offset_delay(reply: &NtpReply, t4: NtpTimestamp) -> NtpClockSkew {
        compute_offset_delay_impl(reply, t4)
    }
}

// ---------------------------------------------------------------------------
// Free functions (also `pub` so the kernel banner can exercise them
// directly through their fixed names — this keeps the diversifier's
// alias-rewrite safe: the locked surface lives on the trait, the
// kernel's call-graph anchors land on these names).
// ---------------------------------------------------------------------------

/// Build a mode-3 SNTPv4 request. Writes exactly
/// [`SNTP_PACKET_LEN`] bytes into `out`. See the trait doc for the
/// locked invariants.
pub fn build_request_impl(
    client_now: NtpTimestamp,
    out: &mut [u8],
) -> Result<usize, SntpError> {
    if out.len() < SNTP_PACKET_LEN {
        return Err(SntpError::Truncated);
    }

    // Zero every byte first — every field except byte 0 + the
    // transmit-timestamp tail is zero in a stock client request.
    let mut i = 0usize;
    while i < SNTP_PACKET_LEN {
        out[i] = 0;
        i += 1;
    }

    // Byte 0: LI=0 (clock OK), VN=4, Mode=3 (client).
    //   bit layout: LL_VVV_MMM
    //   = (0 << 6) | (4 << 3) | 3
    //   = 0b00_100_011
    //   = 0x23
    out[0] = pack_li_vn_mode(0, SNTP_VERSION, SNTP_MODE_CLIENT);

    // Plant the transmit timestamp (`t1`) so the server can echo it
    // back in the originate field for transaction correlation.
    write_u64_be(&mut out[SNTP_OFFSET_TRANSMIT_TS..SNTP_OFFSET_TRANSMIT_TS + 8], client_now.raw);

    Ok(SNTP_PACKET_LEN)
}

/// Parse a mode-4 SNTPv4 reply. Returns `Ok(NtpReply)` iff every
/// header invariant from RFC 4330 §5 passes; otherwise returns an
/// [`SntpError`] without partial state.
pub fn parse_reply_impl(buf: &[u8]) -> Result<NtpReply, SntpError> {
    if buf.len() != SNTP_PACKET_LEN {
        return Err(SntpError::Truncated);
    }

    let (li, vn, mode) = unpack_li_vn_mode(buf[0]);
    if vn != SNTP_VERSION {
        return Err(SntpError::BadVersion);
    }
    if mode != SNTP_MODE_SERVER {
        return Err(SntpError::BadMode);
    }
    if li == SNTP_LEAP_ALARM {
        return Err(SntpError::BadLeapIndicator);
    }

    let stratum = buf[1];
    if stratum == 0 || stratum > SNTP_MAX_STRATUM {
        return Err(SntpError::BadStratum);
    }

    let mut ref_id = [0u8; 4];
    let mut k = 0usize;
    while k < 4 {
        ref_id[k] = buf[SNTP_OFFSET_REF_ID + k];
        k += 1;
    }

    let reference_timestamp = NtpTimestamp::from_raw(read_u64_be(
        &buf[SNTP_OFFSET_REFERENCE_TS..SNTP_OFFSET_REFERENCE_TS + 8],
    ));
    let origin_timestamp = NtpTimestamp::from_raw(read_u64_be(
        &buf[SNTP_OFFSET_ORIGIN_TS..SNTP_OFFSET_ORIGIN_TS + 8],
    ));
    let receive_timestamp = NtpTimestamp::from_raw(read_u64_be(
        &buf[SNTP_OFFSET_RECEIVE_TS..SNTP_OFFSET_RECEIVE_TS + 8],
    ));
    let transmit_timestamp = NtpTimestamp::from_raw(read_u64_be(
        &buf[SNTP_OFFSET_TRANSMIT_TS..SNTP_OFFSET_TRANSMIT_TS + 8],
    ));

    Ok(NtpReply {
        leap_indicator: li,
        version: vn,
        stratum,
        ref_id,
        reference_timestamp,
        origin_timestamp,
        receive_timestamp,
        transmit_timestamp,
    })
}

/// Compute the SNTP offset + round-trip delay from the four
/// timestamps `(t1, t2, t3, t4)`. Pure arithmetic — no clock reads,
/// no allocation. Folds through `i128` internally so a multi-year
/// skew is representable without saturation.
pub fn compute_offset_delay_impl(reply: &NtpReply, t4: NtpTimestamp) -> NtpClockSkew {
    let t1 = ntp_to_ns(reply.origin_timestamp);
    let t2 = ntp_to_ns(reply.receive_timestamp);
    let t3 = ntp_to_ns(reply.transmit_timestamp);
    let t4 = ntp_to_ns(t4);

    // offset = ((t2 - t1) + (t3 - t4)) / 2
    // delay  = (t4 - t1) - (t3 - t2)
    //
    // Both operands of the differences are bounded by the NTP epoch
    // (NTP raw is 64-bit, so secs is < 2^32 — `ntp_to_ns` returns an
    // i128 that fits in i64 once converted, but we keep i128 here so
    // the subtractions cannot wrap.
    let s = (t2 - t1) + (t3 - t4);
    let offset = s / 2;
    let delay = (t4 - t1) - (t3 - t2);

    NtpClockSkew {
        offset_ns: clamp_i128_to_i64(offset),
        delay_ns: clamp_i128_to_i64(delay),
    }
}

// ---------------------------------------------------------------------------
// Internal helpers (private — internals are diversifiable; the wire
// surface is locked by the trait + RFC).
// ---------------------------------------------------------------------------

/// Pack the leap-indicator (2 bits), version (3 bits), mode (3 bits)
/// into byte 0 of an SNTP packet. RFC 4330 §3.
#[inline]
fn pack_li_vn_mode(li: u8, vn: u8, mode: u8) -> u8 {
    ((li & 0x3) << 6) | ((vn & 0x7) << 3) | (mode & 0x7)
}

/// Unpack byte 0 of an SNTP packet into `(LI, VN, Mode)`. RFC 4330 §3.
#[inline]
fn unpack_li_vn_mode(b: u8) -> (u8, u8, u8) {
    let li = (b >> 6) & 0x3;
    let vn = (b >> 3) & 0x7;
    let mode = b & 0x7;
    (li, vn, mode)
}

/// Read a big-endian u64 from `b` (must be ≥ 8 bytes). Panics in
/// debug builds if shorter; the codec's callers always slice exactly
/// 8 bytes so the panic is a structural assertion, not a runtime
/// error.
#[inline]
fn read_u64_be(b: &[u8]) -> u64 {
    ((b[0] as u64) << 56)
        | ((b[1] as u64) << 48)
        | ((b[2] as u64) << 40)
        | ((b[3] as u64) << 32)
        | ((b[4] as u64) << 24)
        | ((b[5] as u64) << 16)
        | ((b[6] as u64) << 8)
        | (b[7] as u64)
}

/// Write a big-endian u64 into `b` (must be ≥ 8 bytes).
#[inline]
fn write_u64_be(b: &mut [u8], v: u64) {
    b[0] = (v >> 56) as u8;
    b[1] = (v >> 48) as u8;
    b[2] = (v >> 40) as u8;
    b[3] = (v >> 32) as u8;
    b[4] = (v >> 24) as u8;
    b[5] = (v >> 16) as u8;
    b[6] = (v >> 8) as u8;
    b[7] = v as u8;
}

/// Convert an NTP 64-bit fixed-point timestamp to signed nanoseconds
/// since the NTP epoch (1 Jan 1900). Result is an `i128` so the
/// caller's arithmetic on differences cannot overflow.
///
/// Math: `ns = secs * 1_000_000_000 + (frac * 1_000_000_000) >> 32`.
/// For a max NTP timestamp (`raw = u64::MAX`):
///   secs = 2^32 - 1, frac = 2^32 - 1
///   ns ≈ 4.29e9 * 1e9 + just-under-1e9
///       ≈ 4.29e18
/// which fits in i128 with ~1.7e20 to spare. After folding through
/// differences `(t2 - t1) + (t3 - t4)`, the magnitude stays under
/// 1.72e19; the final divide-by-2 + clamp to i64 keeps the public
/// API in a 64-bit-friendly range while protecting against
/// pathological inputs.
#[inline]
fn ntp_to_ns(ts: NtpTimestamp) -> i128 {
    let secs = (ts.raw >> 32) as i128;
    let frac = (ts.raw & 0xFFFF_FFFF) as i128;
    secs * 1_000_000_000 + (frac * 1_000_000_000) / (1i128 << 32)
}

/// Saturate an `i128` to the `i64` range. Used at the public-API
/// boundary so the kernel's downstream `i64` clock-smoother sees
/// well-defined values even for adversarial inputs.
#[inline]
fn clamp_i128_to_i64(v: i128) -> i64 {
    if v > i64::MAX as i128 {
        i64::MAX
    } else if v < i64::MIN as i128 {
        i64::MIN
    } else {
        v as i64
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// NTP raw for `(secs, 0)`.
    const fn ntp(secs: u32) -> NtpTimestamp {
        NtpTimestamp::from_secs_frac(secs, 0)
    }

    /// NTP raw for `(secs, frac)`.
    const fn ntpf(secs: u32, frac: u32) -> NtpTimestamp {
        NtpTimestamp::from_secs_frac(secs, frac)
    }

    // -----------------------------------------------------------------
    // build_request — byte-exact wire encoding
    // -----------------------------------------------------------------

    #[test]
    fn build_request_byte_exact_golden() {
        // client_now = NTP_EPOCH + 100s, raw = 100 << 32 = 0x0000_0064_0000_0000.
        let client_now = ntp(100);
        let mut buf = [0xAAu8; SNTP_PACKET_LEN];
        let n = SntpImpl::build_request(client_now, &mut buf).unwrap();
        assert_eq!(n, SNTP_PACKET_LEN);

        // Byte 0 packs LI=0 (00), VN=4 (100), Mode=3 (011) -> 0b00_100_011 = 0x23.
        assert_eq!(buf[0], 0x23);

        // Bytes 1..40 are zero in a stock client request.
        for i in 1..SNTP_OFFSET_TRANSMIT_TS {
            assert_eq!(buf[i], 0, "byte {} should be 0", i);
        }

        // Bytes 40..48: big-endian client_now.raw = 100 << 32.
        let expected_xmt = [0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(&buf[SNTP_OFFSET_TRANSMIT_TS..SNTP_OFFSET_TRANSMIT_TS + 8], &expected_xmt);
    }

    #[test]
    fn build_request_zeroes_caller_garbage() {
        // out arrives pre-filled with 0xFF; build_request must clear
        // every byte it isn't planting a value into. A morph that
        // skips the zero pre-pass would leave 0xFF where the wire
        // expects 0x00 and an upstream server would parse a bogus
        // stratum / poll / precision / reference-id.
        let client_now = ntp(0xDEAD_BEEF);
        let mut buf = [0xFFu8; SNTP_PACKET_LEN];
        let n = SntpImpl::build_request(client_now, &mut buf).unwrap();
        assert_eq!(n, SNTP_PACKET_LEN);
        assert_eq!(buf[0], 0x23);
        // Stratum / poll / precision — all must be zero.
        assert_eq!(buf[1], 0);
        assert_eq!(buf[2], 0);
        assert_eq!(buf[3], 0);
        // Root delay / dispersion / ref-id / reference / origin /
        // receive — all 36 bytes must be zero.
        for i in 4..SNTP_OFFSET_TRANSMIT_TS {
            assert_eq!(buf[i], 0, "byte {} not zeroed", i);
        }
        // Transmit timestamp = big-endian of 0xDEAD_BEEF_0000_0000.
        let expected_xmt = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00, 0x00, 0x00];
        assert_eq!(&buf[SNTP_OFFSET_TRANSMIT_TS..SNTP_OFFSET_TRANSMIT_TS + 8], &expected_xmt);
    }

    #[test]
    fn build_request_rejects_short_buffer() {
        let mut buf = [0u8; SNTP_PACKET_LEN - 1];
        let r = SntpImpl::build_request(ntp(1), &mut buf);
        assert!(matches!(r, Err(SntpError::Truncated)));
    }

    #[test]
    fn build_request_accepts_oversized_buffer() {
        // Excess bytes past 48 must be left untouched. The caller may
        // be building a wider Ethernet frame and the trailing bytes
        // are the IP header / padding.
        let mut buf = [0xCDu8; SNTP_PACKET_LEN + 12];
        let n = SntpImpl::build_request(ntp(0), &mut buf).unwrap();
        assert_eq!(n, SNTP_PACKET_LEN);
        // First 48 bytes overwritten; trailing 12 bytes untouched.
        for i in SNTP_PACKET_LEN..SNTP_PACKET_LEN + 12 {
            assert_eq!(buf[i], 0xCD, "byte {} overwritten beyond packet end", i);
        }
    }

    // -----------------------------------------------------------------
    // parse_reply — happy path + every error
    // -----------------------------------------------------------------

    /// Build a synthetic mode-4 reply with the given fields. Used as
    /// the test fixture builder.
    fn fixture_reply(
        li: u8,
        vn: u8,
        mode: u8,
        stratum: u8,
        ref_id: [u8; 4],
        ref_ts: NtpTimestamp,
        origin_ts: NtpTimestamp,
        receive_ts: NtpTimestamp,
        transmit_ts: NtpTimestamp,
    ) -> [u8; SNTP_PACKET_LEN] {
        let mut buf = [0u8; SNTP_PACKET_LEN];
        buf[0] = pack_li_vn_mode(li, vn, mode);
        buf[1] = stratum;
        buf[2] = 6; // poll
        buf[3] = 0xEC; // precision = -20
                       // root delay / dispersion stay zero.
        buf[SNTP_OFFSET_REF_ID..SNTP_OFFSET_REF_ID + 4].copy_from_slice(&ref_id);
        write_u64_be(
            &mut buf[SNTP_OFFSET_REFERENCE_TS..SNTP_OFFSET_REFERENCE_TS + 8],
            ref_ts.raw,
        );
        write_u64_be(
            &mut buf[SNTP_OFFSET_ORIGIN_TS..SNTP_OFFSET_ORIGIN_TS + 8],
            origin_ts.raw,
        );
        write_u64_be(
            &mut buf[SNTP_OFFSET_RECEIVE_TS..SNTP_OFFSET_RECEIVE_TS + 8],
            receive_ts.raw,
        );
        write_u64_be(
            &mut buf[SNTP_OFFSET_TRANSMIT_TS..SNTP_OFFSET_TRANSMIT_TS + 8],
            transmit_ts.raw,
        );
        buf
    }

    #[test]
    fn parse_reply_happy_path() {
        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            SNTP_MODE_SERVER,
            3,
            *b"GPS\0",
            ntp(3_000_000_000),
            ntp(100),
            ntpf(100, 0x8000_0000),
            ntpf(100, 0x8000_0000),
        );
        let reply = SntpImpl::parse_reply(&buf).unwrap();
        assert_eq!(reply.leap_indicator, 0);
        assert_eq!(reply.version, SNTP_VERSION);
        assert_eq!(reply.stratum, 3);
        assert_eq!(reply.ref_id, *b"GPS\0");
        assert_eq!(reply.reference_timestamp.raw, ntp(3_000_000_000).raw);
        assert_eq!(reply.origin_timestamp, ntp(100));
        assert_eq!(reply.receive_timestamp, ntpf(100, 0x8000_0000));
        assert_eq!(reply.transmit_timestamp, ntpf(100, 0x8000_0000));
    }

    #[test]
    fn parse_reply_rejects_truncated() {
        let short = [0u8; SNTP_PACKET_LEN - 1];
        assert!(matches!(
            SntpImpl::parse_reply(&short),
            Err(SntpError::Truncated)
        ));
        let too_long = [0u8; SNTP_PACKET_LEN + 1];
        assert!(matches!(
            SntpImpl::parse_reply(&too_long),
            Err(SntpError::Truncated)
        ));
    }

    #[test]
    fn parse_reply_rejects_bad_version() {
        let buf = fixture_reply(
            0,
            3,
            SNTP_MODE_SERVER,
            3,
            *b"GPS\0",
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        assert!(matches!(
            SntpImpl::parse_reply(&buf),
            Err(SntpError::BadVersion)
        ));
    }

    #[test]
    fn parse_reply_rejects_mode_7_private() {
        // Mode 7 is the legacy NTP private/control-mode the kernel
        // refuses outright.
        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            7,
            3,
            *b"GPS\0",
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        assert!(matches!(SntpImpl::parse_reply(&buf), Err(SntpError::BadMode)));
    }

    #[test]
    fn parse_reply_rejects_mode_3_client_loopback() {
        // A client request reflected back at us is mode-3, not
        // mode-4; reject as BadMode so a misconfigured peer can't
        // adopt our own t1 as the wall clock.
        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            SNTP_MODE_CLIENT,
            3,
            *b"GPS\0",
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        assert!(matches!(SntpImpl::parse_reply(&buf), Err(SntpError::BadMode)));
    }

    #[test]
    fn parse_reply_rejects_stratum_zero_kiss_o_death() {
        // Stratum 0 in NTP-speak is a "kiss-o'-death" packet: the
        // server refuses to serve us. Reject as BadStratum so the
        // kernel does not adopt the timestamps.
        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            SNTP_MODE_SERVER,
            0,
            *b"DENY",
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        assert!(matches!(
            SntpImpl::parse_reply(&buf),
            Err(SntpError::BadStratum)
        ));
    }

    #[test]
    fn parse_reply_rejects_stratum_16_unsynchronised() {
        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            SNTP_MODE_SERVER,
            16,
            *b"INIT",
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        assert!(matches!(
            SntpImpl::parse_reply(&buf),
            Err(SntpError::BadStratum)
        ));
    }

    #[test]
    fn parse_reply_rejects_leap_alarm() {
        // LI=3 (alarm) signals an unsynchronised server. Reject.
        let buf = fixture_reply(
            SNTP_LEAP_ALARM,
            SNTP_VERSION,
            SNTP_MODE_SERVER,
            3,
            *b"GPS\0",
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        assert!(matches!(
            SntpImpl::parse_reply(&buf),
            Err(SntpError::BadLeapIndicator)
        ));
    }

    #[test]
    fn parse_reply_accepts_leap_warnings() {
        // LI=1 (last minute has 61s) and LI=2 (59s) are valid
        // synchronisation warnings — the kernel should accept the
        // reply and surface the warning for the smoother to fold in.
        for li in [1u8, 2] {
            let buf = fixture_reply(
                li,
                SNTP_VERSION,
                SNTP_MODE_SERVER,
                3,
                *b"GPS\0",
                ntp(0),
                ntp(0),
                ntp(0),
                ntp(0),
            );
            let r = SntpImpl::parse_reply(&buf).unwrap();
            assert_eq!(r.leap_indicator, li);
        }
    }

    #[test]
    fn parse_reply_recovers_ref_id_for_stratum_2_ipv4_form() {
        // RFC 4330 §5: for stratum > 1, ref_id is the upstream IPv4
        // address. Verify byte-exact recovery — kernel code uses
        // these bytes to graph the synchronisation topology.
        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            SNTP_MODE_SERVER,
            2,
            [10, 0, 0, 42],
            ntp(0),
            ntp(0),
            ntp(0),
            ntp(0),
        );
        let r = SntpImpl::parse_reply(&buf).unwrap();
        assert_eq!(r.stratum, 2);
        assert_eq!(r.ref_id, [10, 0, 0, 42]);
    }

    // -----------------------------------------------------------------
    // compute_offset_delay — locked goldens
    // -----------------------------------------------------------------

    #[test]
    fn compute_symmetric_zero_offset_one_second_delay() {
        // t1 = 100.0s, t2 = 100.5s, t3 = 100.5s, t4 = 101.0s.
        // offset = ((0.5) + (-0.5)) / 2 = 0
        // delay  = (1.0) - (0) = 1.0s = 1_000_000_000 ns.
        let reply = NtpReply {
            leap_indicator: 0,
            version: SNTP_VERSION,
            stratum: 3,
            ref_id: *b"GPS\0",
            reference_timestamp: ntp(99),
            origin_timestamp: ntp(100),
            receive_timestamp: ntpf(100, 0x8000_0000),
            transmit_timestamp: ntpf(100, 0x8000_0000),
        };
        let skew = SntpImpl::compute_offset_delay(&reply, ntp(101));
        assert_eq!(skew.offset_ns, 0, "expected zero offset, got {}", skew.offset_ns);
        assert_eq!(
            skew.delay_ns, 1_000_000_000,
            "expected 1s delay, got {}", skew.delay_ns
        );
    }

    #[test]
    fn compute_positive_offset() {
        // Server clock is 100ms AHEAD of client.
        //   t1 = 100.0s, t4 = 100.4s (client measures 400ms RTT)
        //   t2 = 100.2s (server got pkt at t=100.2 = client_t+100ms+100ms transit)
        //   t3 = 100.3s (server emitted reply, 100ms processing)
        //
        // offset = ((t2 - t1) + (t3 - t4)) / 2
        //        = ((0.2) + (-0.1)) / 2 = 0.05s = 50_000_000 ns
        // delay  = (t4 - t1) - (t3 - t2)
        //        = (0.4) - (0.1) = 0.3s = 300_000_000 ns
        //
        // Use 100ms = 0.1s ≈ frac 0x1999_9999 / 2^32 ≈ 0.09999... — to
        // get clean nanoseconds, use exact fixed-point increments
        // representable in 2^-32 units:
        //   100ms = 100_000_000 ns. In 2^-32 fractional units:
        //   frac = (100_000_000 * 2^32) / 10^9 = 0x1999_9999 (rounded down).
        // The round-trip back to ns through `ntp_to_ns` yields:
        //   ((0x1999_9999 * 1e9) / 2^32) ≈ 99_999_999 ns.
        // To keep the assertion exact, pick fractions that are exact
        // multiples of 2^-32 of a nanosecond. Easier: drive everything
        // in whole nanoseconds via a helper.
        let t1 = ntp_from_ns(100 * 1_000_000_000);
        let t2 = ntp_from_ns(100 * 1_000_000_000 + 200_000_000);
        let t3 = ntp_from_ns(100 * 1_000_000_000 + 300_000_000);
        let t4 = ntp_from_ns(100 * 1_000_000_000 + 400_000_000);

        let reply = NtpReply {
            leap_indicator: 0,
            version: SNTP_VERSION,
            stratum: 3,
            ref_id: *b"GPS\0",
            reference_timestamp: ntp(99),
            origin_timestamp: t1,
            receive_timestamp: t2,
            transmit_timestamp: t3,
        };
        let skew = SntpImpl::compute_offset_delay(&reply, t4);

        // Tolerate a 1ns rounding wobble from the fixed-point
        // conversion in the helper.
        let off_err = (skew.offset_ns - 50_000_000).abs();
        let del_err = (skew.delay_ns - 300_000_000).abs();
        assert!(off_err <= 1, "offset_ns drift: {}", skew.offset_ns);
        assert!(del_err <= 1, "delay_ns drift: {}", skew.delay_ns);
    }

    #[test]
    fn compute_negative_offset() {
        // Server clock is 100ms BEHIND client.
        //   t1 = 100.0s, t4 = 100.4s
        //   t2 = 100.0s + (server_clock_skew = -100ms) + 100ms transit = 100.0s
        //   t3 = t2 + 100ms processing = 100.1s
        //
        // offset = ((0.0) + (-0.3)) / 2 = -0.15s = -150_000_000 ns
        // delay  = (0.4) - (0.1) = 0.3s = 300_000_000 ns
        let t1 = ntp_from_ns(100 * 1_000_000_000);
        let t2 = ntp_from_ns(100 * 1_000_000_000); // server saw it at "100.0"
        let t3 = ntp_from_ns(100 * 1_000_000_000 + 100_000_000);
        let t4 = ntp_from_ns(100 * 1_000_000_000 + 400_000_000);

        let reply = NtpReply {
            leap_indicator: 0,
            version: SNTP_VERSION,
            stratum: 3,
            ref_id: *b"GPS\0",
            reference_timestamp: ntp(99),
            origin_timestamp: t1,
            receive_timestamp: t2,
            transmit_timestamp: t3,
        };
        let skew = SntpImpl::compute_offset_delay(&reply, t4);

        let off_err = (skew.offset_ns - (-150_000_000)).abs();
        let del_err = (skew.delay_ns - 300_000_000).abs();
        assert!(off_err <= 1, "offset_ns drift: {}", skew.offset_ns);
        assert!(del_err <= 1, "delay_ns drift: {}", skew.delay_ns);
    }

    #[test]
    fn compute_sub_microsecond_skew() {
        // Microsecond-level skew exercises the low-bit precision of
        // the fixed-point conversion. The original task spec calls
        // out sub-millisecond skew tolerance as the bar.
        //   t1 = 100s, t4 = 100s + 2us, t2 = t1 + 1us + 50ns,
        //   t3 = t2 + 100ns.
        let t1 = ntp_from_ns(100 * 1_000_000_000);
        let t2 = ntp_from_ns(100 * 1_000_000_000 + 1_050);
        let t3 = ntp_from_ns(100 * 1_000_000_000 + 1_150);
        let t4 = ntp_from_ns(100 * 1_000_000_000 + 2_000);
        let reply = NtpReply {
            leap_indicator: 0,
            version: SNTP_VERSION,
            stratum: 3,
            ref_id: *b"GPS\0",
            reference_timestamp: ntp(99),
            origin_timestamp: t1,
            receive_timestamp: t2,
            transmit_timestamp: t3,
        };
        let skew = SntpImpl::compute_offset_delay(&reply, t4);
        // offset = ((1050) + (1150-2000))/2 = (1050 + -850)/2 = 100 ns
        // delay  = (2000) - (1150 - 1050) = 2000 - 100 = 1900 ns
        let off_err = (skew.offset_ns - 100).abs();
        let del_err = (skew.delay_ns - 1900).abs();
        assert!(off_err <= 2, "offset_ns drift: {}", skew.offset_ns);
        assert!(del_err <= 2, "delay_ns drift: {}", skew.delay_ns);
    }

    // -----------------------------------------------------------------
    // Round-trip — build a reply, parse it, compute, verify against
    // the source timestamps.
    // -----------------------------------------------------------------

    #[test]
    fn round_trip_build_reply_parse_compute() {
        // Client builds request at t1, server's pretend-timestamps
        // are t2/t3; we hand-craft the reply and feed it through
        // parse_reply. The recovered timestamps must equal the
        // originals byte-for-byte and the computed offset must match
        // the analytic value.
        let t1 = ntp_from_ns(50 * 1_000_000_000);
        let t2 = ntp_from_ns(50 * 1_000_000_000 + 500_000_000);
        let t3 = ntp_from_ns(50 * 1_000_000_000 + 500_000_000);
        let t4 = ntp_from_ns(51 * 1_000_000_000);

        let buf = fixture_reply(
            0,
            SNTP_VERSION,
            SNTP_MODE_SERVER,
            2,
            [10, 0, 0, 1],
            ntp(49),
            t1,
            t2,
            t3,
        );
        let reply = SntpImpl::parse_reply(&buf).unwrap();
        assert_eq!(reply.origin_timestamp, t1);
        assert_eq!(reply.receive_timestamp, t2);
        assert_eq!(reply.transmit_timestamp, t3);
        let skew = SntpImpl::compute_offset_delay(&reply, t4);
        assert!(skew.offset_ns.abs() <= 1, "offset {}", skew.offset_ns);
        let del_err = (skew.delay_ns - 1_000_000_000).abs();
        assert!(del_err <= 1, "delay {}", skew.delay_ns);
    }

    // -----------------------------------------------------------------
    // Wire-constant + bit-packing sanity (locked discriminants)
    // -----------------------------------------------------------------

    #[test]
    fn locked_wire_constants() {
        assert_eq!(SNTP_PACKET_LEN, 48);
        assert_eq!(SNTP_VERSION, 4);
        assert_eq!(SNTP_MODE_CLIENT, 3);
        assert_eq!(SNTP_MODE_SERVER, 4);
        assert_eq!(SNTP_LEAP_ALARM, 3);
        assert_eq!(SNTP_MAX_STRATUM, 15);
        assert_eq!(SNTP_OFFSET_REF_ID, 12);
        assert_eq!(SNTP_OFFSET_REFERENCE_TS, 16);
        assert_eq!(SNTP_OFFSET_ORIGIN_TS, 24);
        assert_eq!(SNTP_OFFSET_RECEIVE_TS, 32);
        assert_eq!(SNTP_OFFSET_TRANSMIT_TS, 40);
    }

    #[test]
    fn li_vn_mode_pack_unpack_round_trip() {
        // Exercise every (li, vn, mode) triple in the legal range so
        // a morph that botches the shift/mask widths surfaces a
        // discrepancy here.
        for li in 0u8..=3 {
            for vn in 0u8..=7 {
                for mode in 0u8..=7 {
                    let b = pack_li_vn_mode(li, vn, mode);
                    let (li2, vn2, mode2) = unpack_li_vn_mode(b);
                    assert_eq!(li2, li, "li round-trip {} -> {}", li, li2);
                    assert_eq!(vn2, vn, "vn round-trip {} -> {}", vn, vn2);
                    assert_eq!(mode2, mode, "mode round-trip {} -> {}", mode, mode2);
                }
            }
        }
    }

    #[test]
    fn ntp_timestamp_secs_frac_accessors() {
        let t = NtpTimestamp::from_secs_frac(0x1234_5678, 0xABCD_EF01);
        assert_eq!(t.seconds(), 0x1234_5678);
        assert_eq!(t.fraction(), 0xABCD_EF01);
        assert_eq!(t.raw, 0x1234_5678_ABCD_EF01);
        let zero = NtpTimestamp::zero();
        assert_eq!(zero.raw, 0);
    }

    #[test]
    fn build_request_byte_0_layout() {
        // Independent of the rest of the buffer, byte 0 packs
        // exactly LI=0, VN=4, Mode=3 -> 0x23. A morph that flips the
        // mask order or drops the version field would land 0x18
        // (mode=0) or 0x03 (vn=0).
        let mut buf = [0u8; SNTP_PACKET_LEN];
        SntpImpl::build_request(NtpTimestamp::zero(), &mut buf).unwrap();
        assert_eq!(buf[0] & 0xC0, 0); // LI bits = 0
        assert_eq!((buf[0] >> 3) & 0x7, SNTP_VERSION);
        assert_eq!(buf[0] & 0x7, SNTP_MODE_CLIENT);
    }

    #[test]
    fn ntp_to_ns_known_values() {
        // 0 -> 0 ns.
        assert_eq!(ntp_to_ns(NtpTimestamp::zero()), 0);
        // 1 second + 0 frac -> 1e9 ns.
        assert_eq!(ntp_to_ns(ntp(1)), 1_000_000_000);
        // 0 sec + half-frac (0x8000_0000) -> 0.5e9 ns.
        assert_eq!(ntp_to_ns(ntpf(0, 0x8000_0000)), 500_000_000);
        // 0 sec + quarter-frac (0x4000_0000) -> 0.25e9 ns.
        assert_eq!(ntp_to_ns(ntpf(0, 0x4000_0000)), 250_000_000);
    }

    // -----------------------------------------------------------------
    // helper: build an NtpTimestamp that approximates a target ns
    // value. Inverse of ntp_to_ns. Used only by the offset/delay
    // tests; the inverse is lossy due to fixed-point rounding.
    // -----------------------------------------------------------------

    fn ntp_from_ns(total_ns: i128) -> NtpTimestamp {
        // total_ns assumed non-negative for tests.
        let secs = total_ns / 1_000_000_000;
        let rem_ns = total_ns - secs * 1_000_000_000;
        // frac = (rem_ns * 2^32) / 1e9
        let frac = (rem_ns * (1i128 << 32)) / 1_000_000_000;
        NtpTimestamp::from_secs_frac(secs as u32, frac as u32)
    }
}
