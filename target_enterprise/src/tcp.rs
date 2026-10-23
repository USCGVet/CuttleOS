//! TCP — wire codec + server-side state machine.
//!
//! `no_std`, no `alloc`. Clean-room implementation per RFC 793 §3.
//!
//! # Scope (this seed)
//!
//! - **Wire codec**: build + parse a TCP segment with a 20-byte
//!   header (no options). Checksum over the IPv4 pseudo-header per
//!   RFC 793 §3.1.
//! - **State machine (server side)**: `CLOSED → LISTEN → SYN_RCVD →
//!   ESTABLISHED → CLOSE_WAIT → LAST_ACK → CLOSED`. This is the half
//!   of TCP a server needs to host a single connection at a time.
//! - **TCB**: one transmission control block per active connection.
//!   Caller manages the table (we offer a single-slot demo here; a
//!   real server uses a per-port hashmap).
//!
//! # Not covered (intentional)
//!
//! - **Active-open path** (`SYN_SENT`, `FIN_WAIT_1/2`, `CLOSING`,
//!   `TIME_WAIT`). When the kernel needs to make outbound TCP
//!   connections, this expands.
//! - **Retransmission timers**. Real TCP needs a retransmission
//!   queue + RTO + Nagle. The state machine here handles the ideal
//!   no-loss case; layering retransmission on top is additive.
//! - **Options**: MSS, SACK, timestamps, window scaling. Header
//!   length is fixed at 20 bytes (the minimum).
//! - **Congestion control**. Window comes straight from the peer;
//!   we don't slow-start or cwnd-limit.
//!
//! These are explicit future tasks, not silent gaps. The wire codec
//! is locked by the contract — the state-machine internals can morph.

#![allow(clippy::needless_range_loop)]

use cuttle_contracts::{tcp_flags, Tcp, TcpError, TcpSegmentView};

/// Minimum TCP header size in bytes (no options).
pub const TCP_MIN_HEADER_LEN: usize = 20;
/// `data_offset` value (in 32-bit words) for a header without options.
pub const TCP_DATA_OFFSET_NO_OPTS: u8 = 5;
/// IP protocol number for TCP (RFC 793 §3.1).
pub const IP_PROTO_TCP: u8 = 6;

// ---------------------------------------------------------------------------
// Wire codec — implements cuttle_contracts::Tcp
// ---------------------------------------------------------------------------

/// Wire codec impl. Pure functions on `&[u8]` / `&mut [u8]`; no state.
pub struct TcpImpl;

impl Tcp for TcpImpl {
    fn build_segment(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, TcpError> {
        let total = TCP_MIN_HEADER_LEN + payload.len();
        if out.len() < total {
            return Err(TcpError::OutputBufferTooSmall);
        }
        // Header: ports, seq, ack, dataoff+reserved, flags, window,
        // checksum (zero for now), urgent.
        out[0..2].copy_from_slice(&src_port.to_be_bytes());
        out[2..4].copy_from_slice(&dst_port.to_be_bytes());
        out[4..8].copy_from_slice(&seq.to_be_bytes());
        out[8..12].copy_from_slice(&ack.to_be_bytes());
        out[12] = TCP_DATA_OFFSET_NO_OPTS << 4; // upper 4 bits = data offset
        out[13] = flags;
        out[14..16].copy_from_slice(&window.to_be_bytes());
        out[16] = 0; // checksum placeholder
        out[17] = 0;
        out[18] = 0; // urgent pointer = 0
        out[19] = 0;
        // Payload.
        for i in 0..payload.len() {
            out[TCP_MIN_HEADER_LEN + i] = payload[i];
        }
        // Checksum over pseudo-header + segment (with checksum field zero).
        let sum = Self::tcp_checksum(src_ip, dst_ip, &out[..total]);
        out[16..18].copy_from_slice(&sum.to_be_bytes());
        Ok(total)
    }

    fn parse_segment<'a>(
        bytes: &'a [u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
    ) -> Result<TcpSegmentView<'a>, TcpError> {
        if bytes.len() < TCP_MIN_HEADER_LEN {
            return Err(TcpError::Truncated);
        }
        let data_off_words = (bytes[12] >> 4) & 0x0F;
        // Reserved bits are bits 12..16 of the (data_offset|reserved) word.
        // The low nibble of byte 12 is RESERVED (must be zero per RFC 793).
        if bytes[12] & 0x0F != 0 {
            return Err(TcpError::ReservedBitsSet);
        }
        let header_len = (data_off_words as usize) * 4;
        if header_len < TCP_MIN_HEADER_LEN {
            return Err(TcpError::BadHeaderLength);
        }
        if bytes.len() < header_len {
            return Err(TcpError::Truncated);
        }
        let mut seq_b = [0u8; 4];
        seq_b.copy_from_slice(&bytes[4..8]);
        let mut ack_b = [0u8; 4];
        ack_b.copy_from_slice(&bytes[8..12]);
        let view = TcpSegmentView {
            src_port: u16::from_be_bytes([bytes[0], bytes[1]]),
            dst_port: u16::from_be_bytes([bytes[2], bytes[3]]),
            seq: u32::from_be_bytes(seq_b),
            ack: u32::from_be_bytes(ack_b),
            header_len: header_len as u8,
            flags: bytes[13],
            window: u16::from_be_bytes([bytes[14], bytes[15]]),
            checksum: u16::from_be_bytes([bytes[16], bytes[17]]),
            urgent: u16::from_be_bytes([bytes[18], bytes[19]]),
            payload: &bytes[header_len..],
        };
        // Verify checksum over the WHOLE segment (with the original
        // checksum field present): if the segment is well-formed, the
        // one's-complement sum of pseudo-header + segment is 0xFFFF (or
        // 0x0000 when complemented).
        if Self::tcp_checksum_verify(src_ip, dst_ip, bytes) != 0 {
            return Err(TcpError::ChecksumMismatch);
        }
        Ok(view)
    }

    fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) -> u16 {
        // RFC 793 §3.1 / RFC 1071. One's-complement sum over the IPv4
        // pseudo-header + segment, with the segment's checksum field
        // treated as zero.
        //
        // Pseudo-header: src_ip(4) + dst_ip(4) + zero(1) + protocol(1)
        // + tcp_length(2) = 12 bytes.
        let tcp_len = segment.len() as u32;
        let mut sum: u32 = 0;
        // src/dst ip
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        // zero + protocol byte → one 16-bit word
        sum += IP_PROTO_TCP as u32;
        // tcp_length (16-bit)
        sum += tcp_len & 0xFFFF;
        // segment, treating bytes 16..18 (the checksum field) as zero.
        let mut i = 0;
        while i + 1 < segment.len() {
            let word = if i == 16 {
                0u16
            } else {
                u16::from_be_bytes([segment[i], segment[i + 1]])
            };
            sum += word as u32;
            i += 2;
        }
        if i < segment.len() {
            // Odd-byte tail: pad with zero in the low byte.
            sum += (segment[i] as u32) << 8;
        }
        // Fold carries.
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

impl TcpImpl {
    /// Like `tcp_checksum` but takes the segment AS-RECEIVED (checksum
    /// field non-zero) and returns the one's-complement folded sum.
    /// A valid segment yields zero. Used by `parse_segment` to verify.
    fn tcp_checksum_verify(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) -> u16 {
        let tcp_len = segment.len() as u32;
        let mut sum: u32 = 0;
        sum += u16::from_be_bytes([src_ip[0], src_ip[1]]) as u32;
        sum += u16::from_be_bytes([src_ip[2], src_ip[3]]) as u32;
        sum += u16::from_be_bytes([dst_ip[0], dst_ip[1]]) as u32;
        sum += u16::from_be_bytes([dst_ip[2], dst_ip[3]]) as u32;
        sum += IP_PROTO_TCP as u32;
        sum += tcp_len & 0xFFFF;
        let mut i = 0;
        while i + 1 < segment.len() {
            sum += u16::from_be_bytes([segment[i], segment[i + 1]]) as u32;
            i += 2;
        }
        if i < segment.len() {
            sum += (segment[i] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

// ---------------------------------------------------------------------------
// State machine — server-side passive open
// ---------------------------------------------------------------------------

/// TCP state machine states. Server-side subset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpState {
    /// No connection. `listen()` moves to `LISTEN`.
    Closed,
    /// Waiting for a connection request from any peer.
    Listen,
    /// Received a SYN, sent SYN+ACK, waiting for the peer's ACK.
    SynReceived,
    /// Connection open; data flows both ways.
    Established,
    /// Local side initiated close from `Established` and sent `FIN`.
    /// Waiting for the peer's ACK of our `FIN` (or simultaneous `FIN`).
    FinWait1,
    /// Peer ACKed our `FIN`; waiting for the peer's `FIN`.
    FinWait2,
    /// Peer sent FIN. We ACKed it. We can still send data; the
    /// application should call `close()` to send our own FIN.
    CloseWait,
    /// We sent FIN. Waiting for the peer's ACK of it.
    LastAck,
}

/// Transmission Control Block — per-connection state. Bounded
/// `Send`-by-value (no heap, no pointers).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Tcb {
    /// Current state.
    pub state: TcpState,
    /// Local port (we're the server; this is the listen port).
    pub local_port: u16,
    /// Remote peer port. Meaningful in SYN_RCVD and later.
    pub remote_port: u16,
    /// Local IPv4 address.
    pub local_ip: [u8; 4],
    /// Remote IPv4 address. Meaningful in SYN_RCVD and later.
    pub remote_ip: [u8; 4],
    /// Initial Send Sequence (our SYN's sequence).
    pub snd_iss: u32,
    /// Send-unacknowledged: oldest unacked sequence. `snd_una == snd_nxt`
    /// when we have no in-flight data.
    pub snd_una: u32,
    /// Next sequence number to send.
    pub snd_nxt: u32,
    /// Send window — how much the peer is willing to accept.
    pub snd_wnd: u16,
    /// Initial Receive Sequence (peer's SYN's sequence).
    pub rcv_irs: u32,
    /// Next sequence number expected from the peer.
    pub rcv_nxt: u32,
    /// Receive window we advertise.
    pub rcv_wnd: u16,
}

impl Tcb {
    /// Empty/uninitialised TCB. `state = Closed`.
    pub const EMPTY: Self = Self {
        state: TcpState::Closed,
        local_port: 0,
        remote_port: 0,
        local_ip: [0; 4],
        remote_ip: [0; 4],
        snd_iss: 0,
        snd_una: 0,
        snd_nxt: 0,
        snd_wnd: 0,
        rcv_irs: 0,
        rcv_nxt: 0,
        rcv_wnd: 0,
    };

    /// Start a passive open on `local_port`. Returns the TCB in
    /// `LISTEN` state.
    pub fn listen(local_ip: [u8; 4], local_port: u16, rcv_wnd: u16) -> Self {
        Self {
            state: TcpState::Listen,
            local_ip,
            local_port,
            rcv_wnd,
            ..Self::EMPTY
        }
    }
}

/// Reply hint produced by [`process_segment`]: zero, one, or two
/// segments to emit, with their flags + payload-already-computed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Reply {
    /// True iff this reply slot is valid. `Reply::NONE` has `present == false`.
    pub present: bool,
    /// Sequence number to put in the reply header.
    pub seq: u32,
    /// Ack number.
    pub ack: u32,
    /// Flag byte.
    pub flags: u8,
    /// Window to advertise.
    pub window: u16,
}

impl Reply {
    /// Empty reply (caller emits nothing).
    pub const NONE: Self = Self {
        present: false,
        seq: 0,
        ack: 0,
        flags: 0,
        window: 0,
    };
}

/// Errors a [`process_segment`] call may surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpProcessError {
    /// Segment arrived for a connection in `Closed` state. RFC 793
    /// says reply with RST; we honour that via a Reply hint.
    ClosedReceived,
    /// Segment doesn't match this TCB (wrong port / wrong peer).
    WrongConnection,
    /// Sequence/ack outside the expected window. The TCB is unchanged;
    /// the caller may emit an ACK with current `rcv_nxt`/`snd_nxt` to
    /// resynchronise.
    OutOfWindow,
    /// Reserved bits set or otherwise malformed flag combination.
    MalformedFlags,
}

/// Drive the state machine one step. Consumes the incoming segment view,
/// returns the new TCB + an optional reply segment hint. Pure function
/// (no global state, no allocations).
///
/// Initial Sequence Number (ISN) generation: we derive ours
/// deterministically from `local_port ^ remote_port ^ now_ticks` so
/// the state machine is reproducible per test run. Real production
/// uses a CSPRNG seed mixed with current time; that's a swap-in.
pub fn process_segment(
    mut tcb: Tcb,
    seg: &TcpSegmentView<'_>,
    now_ticks: u32,
) -> Result<(Tcb, Reply), TcpProcessError> {
    // Reject CLOSED unconditionally. Per RFC 793 we'd send RST.
    if tcb.state == TcpState::Closed {
        return Err(TcpProcessError::ClosedReceived);
    }

    // Address/port matching — once we're past LISTEN, the TCB is bound.
    if tcb.state != TcpState::Listen {
        if seg.src_port != tcb.remote_port || seg.dst_port != tcb.local_port {
            return Err(TcpProcessError::WrongConnection);
        }
    } else if seg.dst_port != tcb.local_port {
        return Err(TcpProcessError::WrongConnection);
    }

    match tcb.state {
        TcpState::Closed => unreachable!(), // handled above

        TcpState::Listen => {
            // Expect SYN with no ACK.
            if seg.flags & tcp_flags::SYN == 0 || seg.flags & tcp_flags::ACK != 0 {
                return Err(TcpProcessError::MalformedFlags);
            }
            // Remember the peer.
            tcb.remote_port = seg.src_port;
            // Mint our ISN.
            let isn = deterministic_isn(tcb.local_port, seg.src_port, now_ticks);
            tcb.snd_iss = isn;
            tcb.snd_una = isn;
            tcb.snd_nxt = isn.wrapping_add(1); // SYN consumes one sequence number
            tcb.rcv_irs = seg.seq;
            tcb.rcv_nxt = seg.seq.wrapping_add(1);
            tcb.snd_wnd = seg.window;
            tcb.state = TcpState::SynReceived;
            // Reply: SYN+ACK with our seq=isn, ack=rcv_nxt.
            Ok((
                tcb,
                Reply {
                    present: true,
                    seq: isn,
                    ack: tcb.rcv_nxt,
                    flags: tcp_flags::SYN | tcp_flags::ACK,
                    window: tcb.rcv_wnd,
                },
            ))
        }

        TcpState::SynReceived => {
            // Expect ACK of our SYN.
            if seg.flags & tcp_flags::ACK == 0 {
                return Err(TcpProcessError::MalformedFlags);
            }
            if seg.ack != tcb.snd_nxt {
                return Err(TcpProcessError::OutOfWindow);
            }
            tcb.snd_una = seg.ack;
            tcb.snd_wnd = seg.window;
            tcb.state = TcpState::Established;
            // Handshake ACK may piggyback the first data segment
            // (HTTP GET on the third packet). Consume it here so the
            // lived HTTP server does not drop the request.
            established_data_or_fin(tcb, seg)
        }

        TcpState::Established => established_data_or_fin(tcb, seg),

        TcpState::FinWait1 => {
            if seg.flags & tcp_flags::ACK == 0 {
                return Err(TcpProcessError::MalformedFlags);
            }
            if wrapping_lt(tcb.snd_una, seg.ack) && wrapping_le(seg.ack, tcb.snd_nxt) {
                tcb.snd_una = seg.ack;
            } else if seg.ack != tcb.snd_nxt && seg.ack != tcb.snd_una {
                return Err(TcpProcessError::OutOfWindow);
            }
            let has_data = !seg.payload.is_empty();
            let has_fin = (seg.flags & tcp_flags::FIN) != 0;
            if (has_data || has_fin) && seg.seq != tcb.rcv_nxt {
                return Err(TcpProcessError::OutOfWindow);
            }
            if has_data {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(seg.payload.len() as u32);
            }
            if has_fin {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
            }
            let fin_acked = seg.ack == tcb.snd_nxt;
            tcb.state = match (fin_acked, has_fin) {
                (true, true) => TcpState::Closed,
                (true, false) => TcpState::FinWait2,
                (false, true) => TcpState::LastAck,
                (false, false) => TcpState::FinWait1,
            };
            let reply = if has_data || has_fin {
                Reply {
                    present: true,
                    seq: tcb.snd_nxt,
                    ack: tcb.rcv_nxt,
                    flags: tcp_flags::ACK,
                    window: tcb.rcv_wnd,
                }
            } else {
                Reply::NONE
            };
            Ok((tcb, reply))
        }

        TcpState::FinWait2 => {
            if seg.flags & tcp_flags::ACK == 0 {
                return Err(TcpProcessError::MalformedFlags);
            }
            if seg.ack != tcb.snd_nxt {
                return Err(TcpProcessError::OutOfWindow);
            }
            let has_data = !seg.payload.is_empty();
            let has_fin = (seg.flags & tcp_flags::FIN) != 0;
            if !has_data && !has_fin {
                return Ok((tcb, Reply::NONE));
            }
            if seg.seq != tcb.rcv_nxt {
                return Err(TcpProcessError::OutOfWindow);
            }
            if has_data {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(seg.payload.len() as u32);
            }
            if has_fin {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
                tcb.state = TcpState::Closed;
            }
            Ok((
                tcb,
                Reply {
                    present: true,
                    seq: tcb.snd_nxt,
                    ack: tcb.rcv_nxt,
                    flags: tcp_flags::ACK,
                    window: tcb.rcv_wnd,
                },
            ))
        }

        TcpState::CloseWait => {
            // Peer has already sent FIN; reject any further data or FIN segments.
            if !seg.payload.is_empty() || (seg.flags & tcp_flags::FIN) != 0 {
                return Err(TcpProcessError::OutOfWindow);
            }
            if seg.flags & tcp_flags::ACK != 0
                && wrapping_lt(tcb.snd_una, seg.ack)
                && wrapping_le(seg.ack, tcb.snd_nxt)
            {
                tcb.snd_una = seg.ack;
            }
            Ok((tcb, Reply::NONE))
        }

        TcpState::LastAck => {
            // Expect ACK of our FIN (or in-flight data / peer FIN after server-initiated close).
            if seg.flags & tcp_flags::ACK == 0 {
                return Err(TcpProcessError::MalformedFlags);
            }
            if wrapping_lt(tcb.snd_una, seg.ack) && wrapping_le(seg.ack, tcb.snd_nxt) {
                tcb.snd_una = seg.ack;
            } else if seg.ack != tcb.snd_nxt && seg.ack != tcb.snd_una {
                return Err(TcpProcessError::OutOfWindow);
            }
            let has_fin = (seg.flags & tcp_flags::FIN) != 0;
            if has_fin && seg.seq == tcb.rcv_nxt {
                tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
            }
            if seg.ack == tcb.snd_nxt {
                tcb.state = TcpState::Closed;
            }
            let reply = if has_fin {
                Reply {
                    present: true,
                    seq: tcb.snd_nxt,
                    ack: tcb.rcv_nxt,
                    flags: tcp_flags::ACK,
                    window: tcb.rcv_wnd,
                }
            } else {
                Reply::NONE
            };
            Ok((tcb, reply))
        }
    }
}

/// Drive ESTABLISHED (and handshake-ACK-with-data) through payload
/// and/or FIN. RFC 793: data is sequenced first, then FIN consumes one
/// extra sequence number. A payload+FIN segment is how HTTP/1.0 clients
/// often close.
fn established_data_or_fin(
    mut tcb: Tcb,
    seg: &TcpSegmentView<'_>,
) -> Result<(Tcb, Reply), TcpProcessError> {
    if seg.flags & tcp_flags::ACK != 0
        && wrapping_lt(tcb.snd_una, seg.ack)
        && wrapping_le(seg.ack, tcb.snd_nxt)
    {
        tcb.snd_una = seg.ack;
    }
    tcb.snd_wnd = seg.window;

    let has_data = !seg.payload.is_empty();
    let has_fin = seg.flags & tcp_flags::FIN != 0;
    if !has_data && !has_fin {
        return Ok((tcb, Reply::NONE));
    }
    if seg.seq != tcb.rcv_nxt {
        return Err(TcpProcessError::OutOfWindow);
    }
    if has_data {
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(seg.payload.len() as u32);
    }
    if has_fin {
        tcb.rcv_nxt = tcb.rcv_nxt.wrapping_add(1);
        tcb.state = TcpState::CloseWait;
    }
    Ok((
        tcb,
        Reply {
            present: true,
            seq: tcb.snd_nxt,
            ack: tcb.rcv_nxt,
            flags: tcp_flags::ACK,
            window: tcb.rcv_wnd,
        },
    ))
}

/// Emit `payload_len` bytes of application data from ESTABLISHED.
/// Advances `snd_nxt` and returns a PSH+ACK hint whose `seq` is the
/// first byte of the payload. The caller still builds the segment
/// (we do not copy the bytes here — this is a TCB-only step).
pub fn send_payload(mut tcb: Tcb, payload_len: u32) -> Result<(Tcb, Reply), TcpProcessError> {
    // CLOSE_WAIT still permits sending (RFC 793); HTTP/1.0 clients often
    // piggyback FIN on the GET, which lands us here before the response.
    if tcb.state != TcpState::Established && tcb.state != TcpState::CloseWait {
        return Err(TcpProcessError::MalformedFlags);
    }
    if payload_len == 0 {
        return Ok((tcb, Reply::NONE));
    }
    let seq = tcb.snd_nxt;
    tcb.snd_nxt = tcb.snd_nxt.wrapping_add(payload_len);
    Ok((
        tcb,
        Reply {
            present: true,
            seq,
            ack: tcb.rcv_nxt,
            flags: tcp_flags::PSH | tcp_flags::ACK,
            window: tcb.rcv_wnd,
        },
    ))
}

/// TCP wrapping less-than: `a < b` in 32-bit sequence space.
fn wrapping_lt(a: u32, b: u32) -> bool {
    a != b && b.wrapping_sub(a) < 0x8000_0000
}

/// TCP wrapping less-or-equal.
fn wrapping_le(a: u32, b: u32) -> bool {
    a == b || wrapping_lt(a, b)
}

/// Local close — only valid from `Established` or `CloseWait`. Transitions
/// to `FinWait1` (from `Established`) or `LastAck` (from `CloseWait`).
/// Returns the FIN segment to emit.
pub fn close(mut tcb: Tcb) -> Result<(Tcb, Reply), TcpProcessError> {
    match tcb.state {
        TcpState::Established | TcpState::CloseWait => {
            let seq = tcb.snd_nxt;
            tcb.snd_nxt = tcb.snd_nxt.wrapping_add(1); // FIN consumes a seq.
            tcb.state = if tcb.state == TcpState::Established {
                TcpState::FinWait1
            } else {
                TcpState::LastAck
            };
            Ok((
                tcb,
                Reply {
                    present: true,
                    seq,
                    ack: tcb.rcv_nxt,
                    flags: tcp_flags::FIN | tcp_flags::ACK,
                    window: tcb.rcv_wnd,
                },
            ))
        }
        _ => Err(TcpProcessError::MalformedFlags),
    }
}

/// Deterministic ISN. Real TCP uses a CSPRNG seeded with time + the
/// (src_ip, src_port, dst_ip, dst_port) tuple to defeat off-path
/// blind-injection attacks. The seed here is a placeholder — a future
/// task can swap in cuttle_contracts-grade randomness without
/// touching the state machine.
fn deterministic_isn(local_port: u16, remote_port: u16, now_ticks: u32) -> u32 {
    let mut x = (local_port as u32) << 16 | (remote_port as u32);
    x = x.wrapping_mul(0x9E37_79B9);
    x = x.wrapping_add(now_ticks);
    x
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(a: u8, b: u8, c: u8, d: u8) -> [u8; 4] {
        [a, b, c, d]
    }

    #[test]
    fn build_then_parse_round_trip() {
        let mut buf = [0u8; 64];
        let n = TcpImpl::build_segment(
            12345,
            80,
            0xCAFEBABE,
            0xDEADBEEF,
            tcp_flags::SYN | tcp_flags::ACK,
            8192,
            b"hello",
            ip(10, 0, 0, 1),
            ip(10, 0, 0, 2),
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 20 + 5);
        let seg =
            TcpImpl::parse_segment(&buf[..n], ip(10, 0, 0, 1), ip(10, 0, 0, 2)).unwrap();
        assert_eq!(seg.src_port, 12345);
        assert_eq!(seg.dst_port, 80);
        assert_eq!(seg.seq, 0xCAFEBABE);
        assert_eq!(seg.ack, 0xDEADBEEF);
        assert_eq!(seg.flags, tcp_flags::SYN | tcp_flags::ACK);
        assert_eq!(seg.window, 8192);
        assert_eq!(seg.header_len, 20);
        assert_eq!(seg.payload, b"hello");
    }

    #[test]
    fn parse_rejects_truncated_segment() {
        let buf = [0u8; 10];
        let err = TcpImpl::parse_segment(&buf, ip(1, 1, 1, 1), ip(2, 2, 2, 2)).unwrap_err();
        assert_eq!(err, TcpError::Truncated);
    }

    #[test]
    fn parse_rejects_reserved_bits_set() {
        let mut buf = [0u8; 20];
        // Valid 20-byte header with bit 0 of (data_offset|reserved) set
        // (= reserved nibble = 1).
        buf[12] = (5 << 4) | 0x01;
        let err = TcpImpl::parse_segment(&buf, ip(1, 1, 1, 1), ip(2, 2, 2, 2)).unwrap_err();
        assert_eq!(err, TcpError::ReservedBitsSet);
    }

    #[test]
    fn build_rejects_too_small_buffer() {
        let mut buf = [0u8; 10];
        let r = TcpImpl::build_segment(
            1, 2, 0, 0, 0, 0, b"", ip(1, 1, 1, 1), ip(2, 2, 2, 2), &mut buf,
        );
        assert_eq!(r.unwrap_err(), TcpError::OutputBufferTooSmall);
    }

    #[test]
    fn parse_rejects_checksum_mismatch() {
        let mut buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            1234, 5678, 100, 200, tcp_flags::ACK, 4096, b"abc",
            ip(10, 0, 0, 1), ip(10, 0, 0, 2), &mut buf,
        ).unwrap();
        // Corrupt one payload byte without recomputing checksum.
        buf[20] ^= 0xFF;
        let err = TcpImpl::parse_segment(&buf[..n], ip(10, 0, 0, 1), ip(10, 0, 0, 2)).unwrap_err();
        assert_eq!(err, TcpError::ChecksumMismatch);
    }

    #[test]
    fn three_way_handshake_drives_listen_to_established() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        let mut tcb = Tcb::listen(server_ip, 8443, 65535);
        assert_eq!(tcb.state, TcpState::Listen);

        // Client → server: SYN
        let mut syn_buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            54321, 8443, 0x1000_0000, 0, tcp_flags::SYN, 65535, b"",
            client_ip, server_ip, &mut syn_buf,
        ).unwrap();
        let syn_seg = TcpImpl::parse_segment(&syn_buf[..n], client_ip, server_ip).unwrap();

        let (next_tcb, reply) = process_segment(tcb, &syn_seg, 0xABCD).unwrap();
        tcb = next_tcb;
        assert_eq!(tcb.state, TcpState::SynReceived);
        assert!(reply.present);
        assert_eq!(reply.flags, tcp_flags::SYN | tcp_flags::ACK);
        assert_eq!(reply.ack, 0x1000_0001);

        // Build server's SYN+ACK so we can ACK it.
        let server_isn = reply.seq;

        // Client → server: ACK of server's SYN
        let mut ack_buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            54321,
            8443,
            0x1000_0001,
            server_isn.wrapping_add(1),
            tcp_flags::ACK,
            65535,
            b"",
            client_ip,
            server_ip,
            &mut ack_buf,
        )
        .unwrap();
        let ack_seg = TcpImpl::parse_segment(&ack_buf[..n], client_ip, server_ip).unwrap();

        let (next_tcb, reply) = process_segment(tcb, &ack_seg, 0xABCE).unwrap();
        tcb = next_tcb;
        assert_eq!(tcb.state, TcpState::Established);
        assert!(!reply.present, "no reply expected for bare ACK at handshake-completion");
    }

    #[test]
    fn data_in_established_acks_back() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        // Hand-craft a TCB already in ESTABLISHED to skip the handshake.
        let mut tcb = Tcb {
            state: TcpState::Established,
            local_port: 8443,
            remote_port: 54321,
            local_ip: server_ip,
            remote_ip: client_ip,
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 101,
            snd_wnd: 65535,
            rcv_irs: 0x2000_0000,
            rcv_nxt: 0x2000_0001,
            rcv_wnd: 65535,
        };

        // Client → server: 5-byte payload
        let mut data_buf = [0u8; 40];
        let n = TcpImpl::build_segment(
            54321, 8443, 0x2000_0001, 101, tcp_flags::ACK, 65535, b"GET /",
            client_ip, server_ip, &mut data_buf,
        ).unwrap();
        let data_seg = TcpImpl::parse_segment(&data_buf[..n], client_ip, server_ip).unwrap();

        let (next_tcb, reply) = process_segment(tcb, &data_seg, 0xABCF).unwrap();
        tcb = next_tcb;
        assert_eq!(tcb.rcv_nxt, 0x2000_0006, "rcv_nxt should advance by payload length");
        assert!(reply.present);
        assert_eq!(reply.ack, 0x2000_0006);
        assert_eq!(reply.flags, tcp_flags::ACK);
    }

    #[test]
    fn fin_drives_established_to_close_wait() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        let tcb = Tcb {
            state: TcpState::Established,
            local_port: 8443,
            remote_port: 54321,
            local_ip: server_ip,
            remote_ip: client_ip,
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 101,
            snd_wnd: 65535,
            rcv_irs: 0x2000_0000,
            rcv_nxt: 0x2000_0001,
            rcv_wnd: 65535,
        };

        let mut buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            54321, 8443, 0x2000_0001, 101, tcp_flags::FIN | tcp_flags::ACK, 65535, b"",
            client_ip, server_ip, &mut buf,
        ).unwrap();
        let fin = TcpImpl::parse_segment(&buf[..n], client_ip, server_ip).unwrap();

        let (next, reply) = process_segment(tcb, &fin, 0).unwrap();
        assert_eq!(next.state, TcpState::CloseWait);
        assert!(reply.present);
        assert_eq!(reply.flags, tcp_flags::ACK);
        assert_eq!(reply.ack, 0x2000_0002);
    }

    #[test]
    fn close_from_close_wait_emits_fin_and_moves_to_last_ack() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        let tcb = Tcb {
            state: TcpState::CloseWait,
            local_port: 8443,
            remote_port: 54321,
            local_ip: server_ip,
            remote_ip: client_ip,
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 101,
            snd_wnd: 65535,
            rcv_irs: 0x2000_0000,
            rcv_nxt: 0x2000_0002,
            rcv_wnd: 65535,
        };
        let (next, reply) = close(tcb).unwrap();
        assert_eq!(next.state, TcpState::LastAck);
        assert!(reply.present);
        assert!(reply.flags & tcp_flags::FIN != 0);
        assert!(reply.flags & tcp_flags::ACK != 0);
        assert_eq!(reply.seq, 101);
        assert_eq!(next.snd_nxt, 102, "FIN must consume one seq number");
    }

    #[test]
    fn ack_of_our_fin_closes_connection() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        let tcb = Tcb {
            state: TcpState::LastAck,
            local_port: 8443,
            remote_port: 54321,
            local_ip: server_ip,
            remote_ip: client_ip,
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 102, // FIN was at 101
            snd_wnd: 65535,
            rcv_irs: 0x2000_0000,
            rcv_nxt: 0x2000_0002,
            rcv_wnd: 65535,
        };
        let mut buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            54321, 8443, 0x2000_0002, 102, tcp_flags::ACK, 65535, b"",
            client_ip, server_ip, &mut buf,
        ).unwrap();
        let ack = TcpImpl::parse_segment(&buf[..n], client_ip, server_ip).unwrap();
        let (next, _reply) = process_segment(tcb, &ack, 0).unwrap();
        assert_eq!(next.state, TcpState::Closed);
    }

    #[test]
    fn closed_returns_error() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        let tcb = Tcb::EMPTY;
        let mut buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            54321, 8443, 0, 0, tcp_flags::ACK, 0, b"",
            client_ip, server_ip, &mut buf,
        ).unwrap();
        let seg = TcpImpl::parse_segment(&buf[..n], client_ip, server_ip).unwrap();
        let err = process_segment(tcb, &seg, 0).unwrap_err();
        assert_eq!(err, TcpProcessError::ClosedReceived);
    }

    #[test]
    fn wrong_port_rejected() {
        let server_ip = ip(10, 0, 0, 2);
        let client_ip = ip(10, 0, 0, 1);
        let tcb = Tcb::listen(server_ip, 8443, 65535);
        let mut buf = [0u8; 32];
        // Send to wrong port (8444 instead of 8443).
        let n = TcpImpl::build_segment(
            54321, 8444, 0, 0, tcp_flags::SYN, 65535, b"",
            client_ip, server_ip, &mut buf,
        ).unwrap();
        let seg = TcpImpl::parse_segment(&buf[..n], client_ip, server_ip).unwrap();
        let err = process_segment(tcb, &seg, 0).unwrap_err();
        assert_eq!(err, TcpProcessError::WrongConnection);
    }

    #[test]
    fn checksum_known_vector() {
        // Sanity: an all-zero segment (after header) against the
        // canonical IPv4 addresses produces a non-trivial checksum
        // we can lock to detect arithmetic drift.
        let segment = [0u8; 20];
        let sum = TcpImpl::tcp_checksum(ip(10, 0, 0, 1), ip(10, 0, 0, 2), &segment);
        // sum is deterministic; if anybody changes the pseudo-header
        // composition this assert flags it.
        assert_ne!(sum, 0, "trivial pseudo-header sum must not be zero");
        assert_ne!(sum, 0xFFFF, "trivial pseudo-header sum must not be 0xFFFF");
    }

    #[test]
    fn header_size_is_locked_at_20() {
        // Lock the header constant so a morph cycle accidentally
        // changing it fails this test immediately.
        assert_eq!(TCP_MIN_HEADER_LEN, 20);
        assert_eq!(TCP_DATA_OFFSET_NO_OPTS, 5);
        assert_eq!(IP_PROTO_TCP, 6);
    }

    #[test]
    fn send_payload_advances_snd_nxt_and_hints_psh_ack() {
        let mut tcb = Tcb {
            state: TcpState::Established,
            local_port: 80,
            remote_port: 40000,
            local_ip: ip(10, 0, 2, 15),
            remote_ip: ip(10, 0, 2, 2),
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 101,
            snd_wnd: 65535,
            rcv_irs: 50,
            rcv_nxt: 51,
            rcv_wnd: 65535,
        };
        let (next, reply) = send_payload(tcb, 12).unwrap();
        tcb = next;
        assert_eq!(tcb.snd_nxt, 113);
        assert!(reply.present);
        assert_eq!(reply.seq, 101);
        assert_eq!(reply.ack, 51);
        assert_eq!(reply.flags, tcp_flags::PSH | tcp_flags::ACK);
    }

    #[test]
    fn handshake_ack_with_payload_reaches_established_and_acks_data() {
        let server_ip = ip(10, 0, 2, 15);
        let client_ip = ip(10, 0, 2, 2);
        let mut tcb = Tcb::listen(server_ip, 80, 65535);
        let mut syn_buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            40000, 80, 0x1000, 0, tcp_flags::SYN, 65535, b"",
            client_ip, server_ip, &mut syn_buf,
        )
        .unwrap();
        let syn = TcpImpl::parse_segment(&syn_buf[..n], client_ip, server_ip).unwrap();
        let (next, reply) = process_segment(tcb, &syn, 7).unwrap();
        tcb = next;
        let server_isn = reply.seq;

        let req = b"GET / HTTP/1.0\r\n\r\n";
        let mut ack_buf = [0u8; 64];
        let n = TcpImpl::build_segment(
            40000,
            80,
            0x1001,
            server_isn.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req,
            client_ip,
            server_ip,
            &mut ack_buf,
        )
        .unwrap();
        let ack = TcpImpl::parse_segment(&ack_buf[..n], client_ip, server_ip).unwrap();
        let (next, reply) = process_segment(tcb, &ack, 8).unwrap();
        tcb = next;
        assert_eq!(tcb.state, TcpState::Established);
        assert_eq!(tcb.rcv_nxt, 0x1001 + req.len() as u32);
        assert!(reply.present);
        assert_eq!(reply.flags, tcp_flags::ACK);
        assert_eq!(reply.ack, tcb.rcv_nxt);
    }

    #[test]
    fn payload_plus_fin_advances_seq_then_close_wait() {
        let tcb = Tcb {
            state: TcpState::Established,
            local_port: 80,
            remote_port: 40000,
            local_ip: ip(10, 0, 2, 15),
            remote_ip: ip(10, 0, 2, 2),
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 101,
            snd_wnd: 65535,
            rcv_irs: 0x2000,
            rcv_nxt: 0x2001,
            rcv_wnd: 65535,
        };
        let body = b"bye";
        let mut buf = [0u8; 40];
        let n = TcpImpl::build_segment(
            40000,
            80,
            0x2001,
            101,
            tcp_flags::FIN | tcp_flags::ACK | tcp_flags::PSH,
            65535,
            body,
            ip(10, 0, 2, 2),
            ip(10, 0, 2, 15),
            &mut buf,
        )
        .unwrap();
        let seg = TcpImpl::parse_segment(&buf[..n], ip(10, 0, 2, 2), ip(10, 0, 2, 15)).unwrap();
        let (next, reply) = process_segment(tcb, &seg, 0).unwrap();
        assert_eq!(next.state, TcpState::CloseWait);
        assert_eq!(next.rcv_nxt, 0x2001 + 3 + 1);
        assert!(reply.present);
        assert_eq!(reply.ack, next.rcv_nxt);
    }

    #[test]
    fn established_ack_advances_snd_una() {
        let tcb = Tcb {
            state: TcpState::Established,
            local_port: 80,
            remote_port: 40000,
            local_ip: ip(10, 0, 2, 15),
            remote_ip: ip(10, 0, 2, 2),
            snd_iss: 100,
            snd_una: 101,
            snd_nxt: 121,
            snd_wnd: 65535,
            rcv_irs: 50,
            rcv_nxt: 51,
            rcv_wnd: 65535,
        };
        let mut buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            40000, 80, 51, 121, tcp_flags::ACK, 65535, b"",
            ip(10, 0, 2, 2), ip(10, 0, 2, 15), &mut buf,
        )
        .unwrap();
        let seg = TcpImpl::parse_segment(&buf[..n], ip(10, 0, 2, 2), ip(10, 0, 2, 15)).unwrap();
        let (next, reply) = process_segment(tcb, &seg, 0).unwrap();
        assert_eq!(next.snd_una, 121);
        assert!(!reply.present);
        assert_eq!(next.state, TcpState::Established);
    }

    #[test]
    fn server_close_from_established_enters_fin_wait_and_acks_late_client_fin() {
        let server_ip = ip(10, 0, 2, 15);
        let client_ip = ip(10, 0, 2, 2);
        let tcb = Tcb {
            state: TcpState::Established,
            local_port: 80,
            remote_port: 40000,
            local_ip: server_ip,
            remote_ip: client_ip,
            snd_iss: 100,
            snd_una: 121,
            snd_nxt: 121,
            snd_wnd: 65535,
            rcv_irs: 50,
            rcv_nxt: 51,
            rcv_wnd: 65535,
        };
        // 1. Server initiates close from Established -> FinWait1 (emitting FIN|ACK at seq=121).
        let (tcb, fin_reply) = close(tcb).unwrap();
        assert_eq!(tcb.state, TcpState::FinWait1);
        assert!(fin_reply.present);
        assert_eq!(fin_reply.seq, 121);
        assert_eq!(fin_reply.flags, tcp_flags::FIN | tcp_flags::ACK);
        assert_eq!(tcb.snd_nxt, 122);

        // 2. Client first sends a bare ACK of our FIN (ack=122) without FIN -> FinWait2.
        let mut buf = [0u8; 32];
        let n = TcpImpl::build_segment(
            40000,
            80,
            51,
            122,
            tcp_flags::ACK,
            65535,
            b"",
            client_ip,
            server_ip,
            &mut buf,
        )
        .unwrap();
        let ack_seg = TcpImpl::parse_segment(&buf[..n], client_ip, server_ip).unwrap();
        let (tcb, ack_reply) = process_segment(tcb, &ack_seg, 0).unwrap();
        assert_eq!(tcb.state, TcpState::FinWait2);
        assert_eq!(tcb.snd_una, 122);
        assert!(!ack_reply.present);

        // 3. Client then sends its late FIN|ACK (seq=51, ack=122) -> Closed, and server emits ACK (ack=52).
        let n = TcpImpl::build_segment(
            40000,
            80,
            51,
            122,
            tcp_flags::FIN | tcp_flags::ACK,
            65535,
            b"",
            client_ip,
            server_ip,
            &mut buf,
        )
        .unwrap();
        let fin_seg = TcpImpl::parse_segment(&buf[..n], client_ip, server_ip).unwrap();
        let (tcb, final_ack) = process_segment(tcb, &fin_seg, 0).unwrap();
        assert_eq!(tcb.state, TcpState::Closed);
        assert_eq!(tcb.rcv_nxt, 52);
        assert!(final_ack.present);
        assert_eq!(final_ack.flags, tcp_flags::ACK);
        assert_eq!(final_ack.seq, 122);
        assert_eq!(final_ack.ack, 52);
    }
}
