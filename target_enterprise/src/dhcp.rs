//! DHCPv4 client — RFC 2131 / RFC 2132 boot-time IP acquisition.
//!
//! `no_std`, no `alloc`. Every scratch buffer is fixed-capacity and
//! supplied by the caller. The port lives on top of `target_enterprise::net`
//! (which produces UDP datagrams over IPv4) and TASK-045 Ethernet
//! framing: the call sequence is DISCOVER (broadcast UDP 68 → 67) →
//! receive OFFER → REQUEST (broadcast UDP 68 → 67) → receive ACK →
//! BOUND.
//!
//! # Scope of this seed
//!
//! - Wire format encoder + parser for DHCPv4 messages. Both halves
//!   are exercised byte-exact against a hand-verified locked golden
//!   in the tests below; OFFER + ACK parsing recover yiaddr, lease,
//!   server_id, subnet mask, router, and DNS via RFC 2132 options.
//! - `DhcpClient` state machine covering the canonical six-state
//!   sequence: Init → Selecting → Requesting → Bound (+ Renewing,
//!   Rebinding).
//! - Lease-time accounting via caller-supplied `now_secs`.
//!
//! # Not in scope
//!
//! - Live UDP send/receive — the kernel composes this codec with
//!   `target_enterprise::net::build_udp_datagram`.
//! - DHCPv6 — different wire format.
//! - RFC 3203 FORCERENEW — security model unsuitable for a kernel seed.
//!
//! # Wire format (RFC 2131 §2)
//!
//! ```text
//!  offset  field         width  notes
//!     0    op            1      1=BOOTREQUEST (client), 2=BOOTREPLY
//!     1    htype         1      1 = Ethernet
//!     2    hlen          1      6 = Ethernet MAC length
//!     3    hops          1      0 (no relay)
//!     4    xid           4      transaction id, network order
//!     8    secs          2      0 (don't disclose timing)
//!    10    flags         2      0x8000 = broadcast reply request
//!    12    ciaddr        4      client's known IP (zero before BOUND)
//!    16    yiaddr        4      "your" IP (server-offered/assigned)
//!    20    siaddr        4      next server in boot sequence (0)
//!    24    giaddr        4      relay-agent IP (0 on direct LANs)
//!    28    chaddr        16     client HW address (first 6 = MAC)
//!    44    sname         64     server hostname (zeros)
//!   108    file          128    boot filename (zeros)
//!   236    magic-cookie  4      0x63 0x82 0x53 0x63
//!   240    options       n      TLV; option 53 carries the DHCP msg-
//!                                type; terminate with 255 (END).
//! ```

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    dhcp_msg_type, dhcp_option, Dhcp, DhcpClientState, DhcpError, DhcpMessageView,
    DHCP_FIXED_HEADER_LEN, DHCP_FLAG_BROADCAST, DHCP_HLEN_ETHERNET, DHCP_HTYPE_ETHERNET,
    DHCP_MAGIC_COOKIE, DHCP_OP_BOOTREPLY, DHCP_OP_BOOTREQUEST,
};

/// Maximum DHCPv4 message size the seed will emit or parse. RFC 2131
/// permits up to 576 bytes for an unfragmented UDP carrier; this is
/// the safe upper bound and matches what most clients use.
pub const DHCP_MAX_MESSAGE_LEN: usize = 576;

/// Re-export of the fixed-header length for ergonomic call sites.
pub const FIXED_HEADER_LEN: usize = DHCP_FIXED_HEADER_LEN;

/// Stateless wire codec implementation.
///
/// # Locked surface
///
/// The three methods on this impl are the entire wire-observable
/// contract for the DHCPv4 boot path. Internals (the order in which
/// options are written, the scratch-buffer layout, the option-parser
/// state machine) are intentionally diversifiable — the verifier
/// proves wire equivalence against the locked invariants in
/// `proteus_contracts::Dhcp`.
pub struct DhcpImpl;

impl Dhcp for DhcpImpl {
    fn build_discover(mac: [u8; 6], xid: u32, out: &mut [u8]) -> Result<usize, DhcpError> {
        // Layout: fixed header (240) + opt53(1) + opt55(req-list) + END(1).
        // Total: 240 + 3 + 5 + 1 = 249 bytes minimum.
        let opt_len = 3 /* opt53 */ + 5 /* opt55 with 3 params */ + 1 /* END */;
        let total = DHCP_FIXED_HEADER_LEN + opt_len;
        if out.len() < total {
            return Err(DhcpError::OutputBufferTooSmall);
        }
        write_fixed_header(out, mac, xid, [0u8; 4])?;
        let mut pos = DHCP_FIXED_HEADER_LEN;
        pos += write_option(&mut out[pos..], dhcp_option::MSG_TYPE, &[dhcp_msg_type::DISCOVER])?;
        pos += write_option(
            &mut out[pos..],
            dhcp_option::PARAM_REQUEST_LIST,
            &[dhcp_option::SUBNET_MASK, dhcp_option::ROUTER, dhcp_option::DNS],
        )?;
        out[pos] = dhcp_option::END;
        pos += 1;
        Ok(pos)
    }

    fn build_request(
        mac: [u8; 6],
        xid: u32,
        requested_ip: [u8; 4],
        server_id: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, DhcpError> {
        // Layout: fixed header (240) + opt53(1) + opt50(4) + opt54(4)
        // + opt55(3) + END(1). Total: 240 + 3 + 6 + 6 + 5 + 1 = 261.
        let opt_len = 3 + 6 + 6 + 5 + 1;
        let total = DHCP_FIXED_HEADER_LEN + opt_len;
        if out.len() < total {
            return Err(DhcpError::OutputBufferTooSmall);
        }
        write_fixed_header(out, mac, xid, [0u8; 4])?;
        let mut pos = DHCP_FIXED_HEADER_LEN;
        pos += write_option(&mut out[pos..], dhcp_option::MSG_TYPE, &[dhcp_msg_type::REQUEST])?;
        pos += write_option(&mut out[pos..], dhcp_option::REQUESTED_IP, &requested_ip)?;
        pos += write_option(&mut out[pos..], dhcp_option::SERVER_ID, &server_id)?;
        pos += write_option(
            &mut out[pos..],
            dhcp_option::PARAM_REQUEST_LIST,
            &[dhcp_option::SUBNET_MASK, dhcp_option::ROUTER, dhcp_option::DNS],
        )?;
        out[pos] = dhcp_option::END;
        pos += 1;
        Ok(pos)
    }

    fn parse_message(bytes: &[u8]) -> Result<DhcpMessageView<'_>, DhcpError> {
        if bytes.len() < DHCP_FIXED_HEADER_LEN {
            return Err(DhcpError::Truncated);
        }
        let op = bytes[0];
        if op != DHCP_OP_BOOTREQUEST && op != DHCP_OP_BOOTREPLY {
            return Err(DhcpError::InvalidOp);
        }
        if bytes[1] != DHCP_HTYPE_ETHERNET {
            return Err(DhcpError::InvalidHardwareType);
        }
        if bytes[2] != DHCP_HLEN_ETHERNET {
            return Err(DhcpError::InvalidHardwareLength);
        }
        if bytes[236..240] != DHCP_MAGIC_COOKIE {
            return Err(DhcpError::BadMagicCookie);
        }

        let xid = u32::from_be_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
        let flags = u16::from_be_bytes([bytes[10], bytes[11]]);

        let ciaddr = [bytes[12], bytes[13], bytes[14], bytes[15]];
        let yiaddr = [bytes[16], bytes[17], bytes[18], bytes[19]];
        let siaddr = [bytes[20], bytes[21], bytes[22], bytes[23]];
        let giaddr = [bytes[24], bytes[25], bytes[26], bytes[27]];
        let mut chaddr = [0u8; 6];
        chaddr.copy_from_slice(&bytes[28..34]);

        let options_raw = &bytes[DHCP_FIXED_HEADER_LEN..];

        // Scan options. The parser collects only the fields the seed
        // needs and tolerates unknown option codes by skipping past
        // their length+data span.
        let mut msg_type: Option<u8> = None;
        let mut server_id: Option<[u8; 4]> = None;
        let mut subnet_mask: Option<[u8; 4]> = None;
        let mut router: Option<[u8; 4]> = None;
        let mut dns: Option<[u8; 4]> = None;
        let mut lease_secs: Option<u32> = None;
        let mut requested_ip: Option<[u8; 4]> = None;

        let mut off = 0usize;
        while off < options_raw.len() {
            let code = options_raw[off];
            if code == dhcp_option::END {
                break;
            }
            if code == dhcp_option::PAD {
                off += 1;
                continue;
            }
            // Every other code is TLV: [code:1][len:1][data:len].
            if off + 1 >= options_raw.len() {
                return Err(DhcpError::TruncatedOption);
            }
            let len = options_raw[off + 1] as usize;
            let data_start = off + 2;
            let data_end = data_start.checked_add(len).ok_or(DhcpError::TruncatedOption)?;
            if data_end > options_raw.len() {
                return Err(DhcpError::TruncatedOption);
            }
            let data = &options_raw[data_start..data_end];
            match code {
                dhcp_option::MSG_TYPE => {
                    if len != 1 {
                        return Err(DhcpError::InvalidMessageTypeLength);
                    }
                    msg_type = Some(data[0]);
                }
                dhcp_option::SERVER_ID if len == 4 => {
                    server_id = Some([data[0], data[1], data[2], data[3]]);
                }
                dhcp_option::SUBNET_MASK if len == 4 => {
                    subnet_mask = Some([data[0], data[1], data[2], data[3]]);
                }
                dhcp_option::ROUTER if len >= 4 => {
                    router = Some([data[0], data[1], data[2], data[3]]);
                }
                dhcp_option::DNS if len >= 4 => {
                    dns = Some([data[0], data[1], data[2], data[3]]);
                }
                dhcp_option::LEASE_TIME if len == 4 => {
                    lease_secs = Some(u32::from_be_bytes([data[0], data[1], data[2], data[3]]));
                }
                dhcp_option::REQUESTED_IP if len == 4 => {
                    requested_ip = Some([data[0], data[1], data[2], data[3]]);
                }
                _ => { /* unknown / unhandled option — skip past it */ }
            }
            off = data_end;
        }

        let mt = msg_type.ok_or(DhcpError::MissingMessageType)?;

        Ok(DhcpMessageView {
            op,
            xid,
            flags,
            ciaddr,
            yiaddr,
            siaddr,
            giaddr,
            chaddr,
            msg_type: mt,
            server_id,
            subnet_mask,
            router,
            dns,
            lease_secs,
            requested_ip,
            options_raw,
        })
    }
}

/// Recovered network configuration after a successful DISCOVER→ACK
/// cycle. Lives in the impl crate (not contracts) because it's a
/// post-cycle convenience rather than a wire surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct DhcpLease {
    /// IP assigned by the server (the OFFER's `yiaddr`, confirmed by
    /// ACK).
    pub assigned_ip: [u8; 4],
    /// Subnet mask (option 1), zeros if the server didn't supply one.
    pub subnet_mask: [u8; 4],
    /// First gateway (option 3), zeros if absent.
    pub gateway: [u8; 4],
    /// First DNS server (option 6), zeros if absent.
    pub dns: [u8; 4],
    /// Server identifier (option 54) — needed for REQUEST / RELEASE.
    pub server_id: [u8; 4],
    /// Lease duration in seconds (option 51), 0 if absent.
    pub lease_secs: u32,
    /// Wall-clock second at which the lease was bound. Caller-supplied
    /// via `DhcpClient::set_now` at the moment ACK is consumed.
    pub bound_at_secs: u64,
}

impl DhcpLease {
    /// Compute the wall-clock second after which the lease expires.
    /// Returns `u64::MAX` if `lease_secs == 0` (a "permanent" lease,
    /// per RFC 2131 §3.3 — interpret with caution).
    pub fn expires_at_secs(&self) -> u64 {
        if self.lease_secs == 0 {
            u64::MAX
        } else {
            self.bound_at_secs.saturating_add(self.lease_secs as u64)
        }
    }

    /// RFC 2131 §4.4.5: T1 — the moment the client should attempt
    /// RENEW. Defaults to 50% of the lease.
    pub fn renew_at_secs(&self) -> u64 {
        let half = (self.lease_secs as u64) / 2;
        self.bound_at_secs.saturating_add(half)
    }

    /// RFC 2131 §4.4.5: T2 — the moment the client should attempt
    /// REBIND if renew failed. Defaults to 87.5% of the lease.
    pub fn rebind_at_secs(&self) -> u64 {
        // 7/8 of lease_secs. Use 128-bit-style maths to avoid u32
        // overflow on a very long lease.
        let secs = self.lease_secs as u64;
        let t2 = (secs * 7) / 8;
        self.bound_at_secs.saturating_add(t2)
    }
}

/// Client state machine. RFC 2131 §4.4 figure 5.
///
/// Wraps the wire codec and a small amount of per-cycle state:
/// the chosen `xid`, the offered IP captured at OFFER time, the
/// server-id, the bound lease. The `now_secs` clock is supplied
/// externally so the kernel can use any monotonic counter.
pub struct DhcpClient {
    state: DhcpClientState,
    mac: [u8; 6],
    xid: u32,
    /// `yiaddr` captured from the most-recent OFFER. Cleared on
    /// re-entry to `Init`.
    offered_ip: [u8; 4],
    /// `server_id` captured from the most-recent OFFER. Cleared on
    /// re-entry to `Init`.
    server_id: [u8; 4],
    /// Authoritative lease, populated when entering BOUND.
    lease: DhcpLease,
}

impl DhcpClient {
    /// Build a fresh client in `Init` state with the given hardware
    /// address. `xid` is supplied at `start_discover` time so the
    /// caller controls entropy.
    pub fn new(mac: [u8; 6]) -> Self {
        Self {
            state: DhcpClientState::Init,
            mac,
            xid: 0,
            offered_ip: [0; 4],
            server_id: [0; 4],
            lease: DhcpLease::default(),
        }
    }

    /// Current state.
    pub fn state(&self) -> DhcpClientState {
        self.state
    }

    /// Currently-committed transaction id (zero in `Init`).
    pub fn xid(&self) -> u32 {
        self.xid
    }

    /// MAC address this client was constructed with.
    pub fn mac(&self) -> [u8; 6] {
        self.mac
    }

    /// IP captured from the most-recent OFFER (zeros if none seen).
    pub fn offered_ip(&self) -> [u8; 4] {
        self.offered_ip
    }

    /// The DHCP server's own IP from the most-recent OFFER's option 54
    /// (zeros if none seen).
    pub fn server_id(&self) -> [u8; 4] {
        self.server_id
    }

    /// Authoritative lease (valid only after BOUND; all-zeros earlier).
    pub fn lease(&self) -> DhcpLease {
        self.lease
    }

    /// Init → Selecting: commit `xid`, emit a DISCOVER into `out`.
    pub fn start_discover(&mut self, xid: u32, out: &mut [u8]) -> Result<usize, DhcpError> {
        if self.state != DhcpClientState::Init {
            return Err(DhcpError::UnexpectedState);
        }
        let n = DhcpImpl::build_discover(self.mac, xid, out)?;
        self.xid = xid;
        self.offered_ip = [0; 4];
        self.server_id = [0; 4];
        self.lease = DhcpLease::default();
        self.state = DhcpClientState::Selecting;
        Ok(n)
    }

    /// Selecting → Requesting: consume an OFFER (must match committed
    /// `xid`, must carry option 54, must have non-zero `yiaddr`),
    /// emit the matching REQUEST into `out`.
    pub fn on_offer(
        &mut self,
        offer_bytes: &[u8],
        out: &mut [u8],
    ) -> Result<usize, DhcpError> {
        if self.state != DhcpClientState::Selecting {
            return Err(DhcpError::UnexpectedState);
        }
        let view = DhcpImpl::parse_message(offer_bytes)?;
        if view.op != DHCP_OP_BOOTREPLY {
            return Err(DhcpError::InvalidOp);
        }
        if view.msg_type != dhcp_msg_type::OFFER {
            return Err(DhcpError::UnexpectedState);
        }
        if view.xid != self.xid {
            return Err(DhcpError::XidMismatch);
        }
        if view.yiaddr == [0u8; 4] {
            return Err(DhcpError::EmptyYiaddr);
        }
        let server_id = view.server_id.ok_or(DhcpError::MissingMessageType)?;
        // Cache for later.
        self.offered_ip = view.yiaddr;
        self.server_id = server_id;
        // Pre-populate lease fields the OFFER already disclosed; ACK
        // will overwrite if it disagrees.
        if let Some(sm) = view.subnet_mask {
            self.lease.subnet_mask = sm;
        }
        if let Some(rt) = view.router {
            self.lease.gateway = rt;
        }
        if let Some(d) = view.dns {
            self.lease.dns = d;
        }
        if let Some(lt) = view.lease_secs {
            self.lease.lease_secs = lt;
        }

        let n = DhcpImpl::build_request(self.mac, self.xid, view.yiaddr, server_id, out)?;
        self.state = DhcpClientState::Requesting;
        Ok(n)
    }

    /// Requesting → Bound: consume an ACK (xid match, yiaddr match
    /// the captured offered IP, msg_type = ACK), capture full lease.
    /// `now_secs` is the caller's monotonic-clock wall time.
    pub fn on_ack(&mut self, ack_bytes: &[u8], now_secs: u64) -> Result<DhcpLease, DhcpError> {
        if self.state != DhcpClientState::Requesting {
            return Err(DhcpError::UnexpectedState);
        }
        let view = DhcpImpl::parse_message(ack_bytes)?;
        if view.op != DHCP_OP_BOOTREPLY {
            return Err(DhcpError::InvalidOp);
        }
        if view.msg_type != dhcp_msg_type::ACK {
            return Err(DhcpError::UnexpectedState);
        }
        if view.xid != self.xid {
            return Err(DhcpError::XidMismatch);
        }
        if view.yiaddr == [0u8; 4] {
            return Err(DhcpError::EmptyYiaddr);
        }
        // Per RFC 2131 §4.3.2: server MAY assign a different IP in
        // ACK than in OFFER (rare but allowed). The seed accepts
        // the ACK's yiaddr as authoritative.
        let server_id = view.server_id.unwrap_or(self.server_id);
        let lease_secs = view.lease_secs.unwrap_or(self.lease.lease_secs);
        let subnet_mask = view.subnet_mask.unwrap_or(self.lease.subnet_mask);
        let gateway = view.router.unwrap_or(self.lease.gateway);
        let dns = view.dns.unwrap_or(self.lease.dns);

        self.lease = DhcpLease {
            assigned_ip: view.yiaddr,
            subnet_mask,
            gateway,
            dns,
            server_id,
            lease_secs,
            bound_at_secs: now_secs,
        };
        self.state = DhcpClientState::Bound;
        Ok(self.lease)
    }

    /// Receive a NAK while in `Requesting` — drop back to `Init`.
    /// RFC 2131 §4.4.5 last paragraph: a NAK invalidates the
    /// current attempt; client must restart with a new `xid`.
    pub fn on_nak(&mut self, nak_bytes: &[u8]) -> Result<(), DhcpError> {
        if self.state != DhcpClientState::Requesting {
            return Err(DhcpError::UnexpectedState);
        }
        let view = DhcpImpl::parse_message(nak_bytes)?;
        if view.msg_type != dhcp_msg_type::NAK {
            return Err(DhcpError::UnexpectedState);
        }
        if view.xid != self.xid {
            return Err(DhcpError::XidMismatch);
        }
        self.xid = 0;
        self.offered_ip = [0; 4];
        self.server_id = [0; 4];
        self.lease = DhcpLease::default();
        self.state = DhcpClientState::Init;
        Ok(())
    }

    /// Bound → Renewing or Rebinding once enough time has passed.
    /// `now_secs` is the same monotonic clock used by `on_ack`. Does
    /// not emit a packet — `tick` only advances state when the
    /// configured thresholds are reached. The caller is responsible
    /// for emitting the REQUEST/REBIND on the state transition.
    pub fn tick(&mut self, now_secs: u64) {
        if !matches!(
            self.state,
            DhcpClientState::Bound | DhcpClientState::Renewing | DhcpClientState::Rebinding
        ) {
            return;
        }
        let t1 = self.lease.renew_at_secs();
        let t2 = self.lease.rebind_at_secs();
        let exp = self.lease.expires_at_secs();
        if now_secs >= exp {
            // Lease fully expired — drop to Init regardless of which
            // sub-state we were in.
            self.xid = 0;
            self.offered_ip = [0; 4];
            self.server_id = [0; 4];
            self.lease = DhcpLease::default();
            self.state = DhcpClientState::Init;
        } else if now_secs >= t2 && self.state != DhcpClientState::Rebinding {
            self.state = DhcpClientState::Rebinding;
        } else if now_secs >= t1 && self.state == DhcpClientState::Bound {
            self.state = DhcpClientState::Renewing;
        }
    }

    /// Drop back to `Init` without emitting a RELEASE. Used by callers
    /// that want to start fresh (e.g. interface re-init).
    pub fn reset(&mut self) {
        self.xid = 0;
        self.offered_ip = [0; 4];
        self.server_id = [0; 4];
        self.lease = DhcpLease::default();
        self.state = DhcpClientState::Init;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn write_fixed_header(
    out: &mut [u8],
    mac: [u8; 6],
    xid: u32,
    ciaddr: [u8; 4],
) -> Result<(), DhcpError> {
    if out.len() < DHCP_FIXED_HEADER_LEN {
        return Err(DhcpError::OutputBufferTooSmall);
    }
    // Zero the entire fixed header first — sname, file, padding all
    // need to be zero on the wire per BOOTP convention.
    for b in &mut out[..DHCP_FIXED_HEADER_LEN] {
        *b = 0;
    }
    out[0] = DHCP_OP_BOOTREQUEST;
    out[1] = DHCP_HTYPE_ETHERNET;
    out[2] = DHCP_HLEN_ETHERNET;
    out[3] = 0; // hops
    out[4..8].copy_from_slice(&xid.to_be_bytes());
    out[8..10].copy_from_slice(&0u16.to_be_bytes()); // secs
    out[10..12].copy_from_slice(&DHCP_FLAG_BROADCAST.to_be_bytes());
    out[12..16].copy_from_slice(&ciaddr);
    // yiaddr, siaddr, giaddr already zeroed above.
    out[28..34].copy_from_slice(&mac);
    out[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    Ok(())
}

fn write_option(buf: &mut [u8], code: u8, data: &[u8]) -> Result<usize, DhcpError> {
    let needed = 2 + data.len();
    if buf.len() < needed {
        return Err(DhcpError::OutputBufferTooSmall);
    }
    buf[0] = code;
    buf[1] = data.len() as u8;
    for (i, b) in data.iter().enumerate() {
        buf[2 + i] = *b;
    }
    Ok(needed)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_MAC: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const TEST_XID: u32 = 0xDEAD_BEEF;
    const TEST_OFFERED_IP: [u8; 4] = [10, 0, 0, 42];
    const TEST_SERVER_ID: [u8; 4] = [10, 0, 0, 1];
    const TEST_LEASE_SECS: u32 = 86_400; // 24h
    const TEST_SUBNET: [u8; 4] = [255, 255, 255, 0];
    const TEST_ROUTER: [u8; 4] = [10, 0, 0, 1];
    const TEST_DNS: [u8; 4] = [10, 0, 0, 53];

    // ===== build_discover golden bytes =====

    #[test]
    fn discover_emits_expected_length() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_discover(TEST_MAC, TEST_XID, &mut buf).unwrap();
        assert_eq!(n, 249);
    }

    #[test]
    fn discover_header_byte_exact() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_discover(TEST_MAC, TEST_XID, &mut buf).unwrap();
        // op=1 htype=1 hlen=6 hops=0
        assert_eq!(buf[0..4], [1, 1, 6, 0]);
        // xid big-endian
        assert_eq!(buf[4..8], [0xDE, 0xAD, 0xBE, 0xEF]);
        // secs=0
        assert_eq!(buf[8..10], [0, 0]);
        // flags = 0x8000 broadcast
        assert_eq!(buf[10..12], [0x80, 0x00]);
        // ciaddr, yiaddr, siaddr, giaddr all zero
        assert_eq!(buf[12..28], [0u8; 16]);
        // chaddr first 6 = TEST_MAC, rest zero
        assert_eq!(buf[28..34], TEST_MAC);
        assert_eq!(buf[34..44], [0u8; 10]);
        // sname (44..108) + file (108..236) all zero
        for b in &buf[44..236] {
            assert_eq!(*b, 0);
        }
        // magic cookie
        assert_eq!(buf[236..240], DHCP_MAGIC_COOKIE);
        // Last byte is END
        assert_eq!(buf[n - 1], 255);
    }

    #[test]
    fn discover_options_byte_exact() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_discover(TEST_MAC, TEST_XID, &mut buf).unwrap();
        // Options begin at offset 240.
        // opt53 (msg_type) = DISCOVER (1)
        assert_eq!(buf[240], dhcp_option::MSG_TYPE);
        assert_eq!(buf[241], 1);
        assert_eq!(buf[242], dhcp_msg_type::DISCOVER);
        // opt55 (PARAM_REQUEST_LIST) length 3
        assert_eq!(buf[243], dhcp_option::PARAM_REQUEST_LIST);
        assert_eq!(buf[244], 3);
        assert_eq!(
            buf[245..248],
            [dhcp_option::SUBNET_MASK, dhcp_option::ROUTER, dhcp_option::DNS]
        );
        // END
        assert_eq!(buf[248], dhcp_option::END);
        assert_eq!(n, 249);
    }

    #[test]
    fn discover_rejects_small_buffer() {
        let mut tiny = [0u8; 200];
        assert_eq!(
            DhcpImpl::build_discover(TEST_MAC, TEST_XID, &mut tiny),
            Err(DhcpError::OutputBufferTooSmall)
        );
    }

    // ===== build_request golden bytes =====

    #[test]
    fn request_emits_expected_length() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_request(
            TEST_MAC,
            TEST_XID,
            TEST_OFFERED_IP,
            TEST_SERVER_ID,
            &mut buf,
        )
        .unwrap();
        assert_eq!(n, 261);
    }

    #[test]
    fn request_options_byte_exact() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_request(
            TEST_MAC,
            TEST_XID,
            TEST_OFFERED_IP,
            TEST_SERVER_ID,
            &mut buf,
        )
        .unwrap();
        // opt53 (msg_type) = REQUEST (3)
        assert_eq!(buf[240], dhcp_option::MSG_TYPE);
        assert_eq!(buf[241], 1);
        assert_eq!(buf[242], dhcp_msg_type::REQUEST);
        // opt50 (REQUESTED_IP) length 4 = TEST_OFFERED_IP
        assert_eq!(buf[243], dhcp_option::REQUESTED_IP);
        assert_eq!(buf[244], 4);
        assert_eq!(buf[245..249], TEST_OFFERED_IP);
        // opt54 (SERVER_ID) length 4 = TEST_SERVER_ID
        assert_eq!(buf[249], dhcp_option::SERVER_ID);
        assert_eq!(buf[250], 4);
        assert_eq!(buf[251..255], TEST_SERVER_ID);
        // opt55 (PARAM_REQUEST_LIST) length 3
        assert_eq!(buf[255], dhcp_option::PARAM_REQUEST_LIST);
        assert_eq!(buf[256], 3);
        // END
        assert_eq!(buf[260], dhcp_option::END);
        assert_eq!(n, 261);
    }

    #[test]
    fn request_rejects_small_buffer() {
        let mut tiny = [0u8; 200];
        assert_eq!(
            DhcpImpl::build_request(
                TEST_MAC,
                TEST_XID,
                TEST_OFFERED_IP,
                TEST_SERVER_ID,
                &mut tiny
            ),
            Err(DhcpError::OutputBufferTooSmall)
        );
    }

    // ===== parse_message =====

    /// Construct a synthetic OFFER reply: op=2, htype=1, hlen=6,
    /// xid=TEST_XID, yiaddr=TEST_OFFERED_IP, chaddr=TEST_MAC, magic
    /// cookie, then options 53=OFFER, 1=mask, 3=router, 6=dns,
    /// 51=lease, 54=server_id, END.
    fn build_offer_fixture(buf: &mut [u8]) -> usize {
        for b in &mut buf[..DHCP_FIXED_HEADER_LEN] {
            *b = 0;
        }
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[4..8].copy_from_slice(&TEST_XID.to_be_bytes());
        buf[16..20].copy_from_slice(&TEST_OFFERED_IP);
        buf[28..34].copy_from_slice(&TEST_MAC);
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        let mut pos = 240;
        // opt53 OFFER
        buf[pos] = dhcp_option::MSG_TYPE;
        buf[pos + 1] = 1;
        buf[pos + 2] = dhcp_msg_type::OFFER;
        pos += 3;
        // opt1 subnet mask
        buf[pos] = dhcp_option::SUBNET_MASK;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&TEST_SUBNET);
        pos += 6;
        // opt3 router
        buf[pos] = dhcp_option::ROUTER;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&TEST_ROUTER);
        pos += 6;
        // opt6 dns
        buf[pos] = dhcp_option::DNS;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&TEST_DNS);
        pos += 6;
        // opt51 lease time
        buf[pos] = dhcp_option::LEASE_TIME;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&TEST_LEASE_SECS.to_be_bytes());
        pos += 6;
        // opt54 server-id
        buf[pos] = dhcp_option::SERVER_ID;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&TEST_SERVER_ID);
        pos += 6;
        // END
        buf[pos] = dhcp_option::END;
        pos + 1
    }

    fn build_ack_fixture(buf: &mut [u8]) -> usize {
        let n = build_offer_fixture(buf);
        // Replace the MSG_TYPE option's value byte (offset 242) with ACK.
        buf[242] = dhcp_msg_type::ACK;
        n
    }

    #[test]
    fn parse_offer_recovers_every_field() {
        let mut fixture = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = build_offer_fixture(&mut fixture);
        let view = DhcpImpl::parse_message(&fixture[..n]).unwrap();
        assert_eq!(view.op, DHCP_OP_BOOTREPLY);
        assert_eq!(view.xid, TEST_XID);
        assert_eq!(view.flags, 0);
        assert_eq!(view.yiaddr, TEST_OFFERED_IP);
        assert_eq!(view.chaddr, TEST_MAC);
        assert_eq!(view.msg_type, dhcp_msg_type::OFFER);
        assert_eq!(view.subnet_mask, Some(TEST_SUBNET));
        assert_eq!(view.router, Some(TEST_ROUTER));
        assert_eq!(view.dns, Some(TEST_DNS));
        assert_eq!(view.lease_secs, Some(TEST_LEASE_SECS));
        assert_eq!(view.server_id, Some(TEST_SERVER_ID));
        assert_eq!(view.requested_ip, None);
    }

    #[test]
    fn parse_rejects_truncated() {
        let short = [0u8; 100];
        assert_eq!(DhcpImpl::parse_message(&short), Err(DhcpError::Truncated));
    }

    #[test]
    fn parse_rejects_bad_magic_cookie() {
        let mut fixture = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = build_offer_fixture(&mut fixture);
        fixture[236] ^= 0xFF; // corrupt the cookie
        assert_eq!(
            DhcpImpl::parse_message(&fixture[..n]),
            Err(DhcpError::BadMagicCookie)
        );
    }

    #[test]
    fn parse_rejects_invalid_op() {
        let mut fixture = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = build_offer_fixture(&mut fixture);
        fixture[0] = 99;
        assert_eq!(DhcpImpl::parse_message(&fixture[..n]), Err(DhcpError::InvalidOp));
    }

    #[test]
    fn parse_rejects_invalid_htype() {
        let mut fixture = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = build_offer_fixture(&mut fixture);
        fixture[1] = 99;
        assert_eq!(
            DhcpImpl::parse_message(&fixture[..n]),
            Err(DhcpError::InvalidHardwareType)
        );
    }

    #[test]
    fn parse_rejects_invalid_hlen() {
        let mut fixture = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = build_offer_fixture(&mut fixture);
        fixture[2] = 99;
        assert_eq!(
            DhcpImpl::parse_message(&fixture[..n]),
            Err(DhcpError::InvalidHardwareLength)
        );
    }

    #[test]
    fn parse_rejects_missing_msg_type() {
        // Build a fixture with no options at all beyond the magic cookie.
        let mut buf = [0u8; DHCP_FIXED_HEADER_LEN + 1];
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        buf[240] = dhcp_option::END;
        assert_eq!(
            DhcpImpl::parse_message(&buf),
            Err(DhcpError::MissingMessageType)
        );
    }

    #[test]
    fn parse_rejects_invalid_msg_type_length() {
        let mut fixture = [0u8; DHCP_MAX_MESSAGE_LEN];
        build_offer_fixture(&mut fixture);
        // Corrupt the MSG_TYPE length (offset 241) to 2.
        fixture[241] = 2;
        // Parser must reject before scanning past it.
        let result = DhcpImpl::parse_message(&fixture);
        assert!(matches!(
            result,
            Err(DhcpError::InvalidMessageTypeLength)
                | Err(DhcpError::TruncatedOption)
                | Err(DhcpError::MissingMessageType)
        ));
        // Reset and explicitly test the InvalidMessageTypeLength path
        // with a clean fixture that ends after the truncated option.
        let mut buf = [0u8; DHCP_FIXED_HEADER_LEN + 5];
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        buf[240] = dhcp_option::MSG_TYPE;
        buf[241] = 2; // wrong — must be 1
        buf[242] = dhcp_msg_type::OFFER;
        buf[243] = 0;
        buf[244] = dhcp_option::END;
        assert_eq!(
            DhcpImpl::parse_message(&buf),
            Err(DhcpError::InvalidMessageTypeLength)
        );
    }

    #[test]
    fn parse_rejects_truncated_option() {
        let mut buf = [0u8; DHCP_FIXED_HEADER_LEN + 3];
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        buf[240] = dhcp_option::SUBNET_MASK;
        buf[241] = 10; // claims 10 bytes but only 1 byte after
        buf[242] = 0xFF;
        assert_eq!(
            DhcpImpl::parse_message(&buf),
            Err(DhcpError::TruncatedOption)
        );
    }

    #[test]
    fn parse_skips_unknown_options() {
        let mut buf = [0u8; DHCP_FIXED_HEADER_LEN + 16];
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[4..8].copy_from_slice(&TEST_XID.to_be_bytes());
        buf[16..20].copy_from_slice(&TEST_OFFERED_IP);
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        // Unknown opt 99 with 4-byte payload, then opt53.
        buf[240] = 99;
        buf[241] = 4;
        // 242..246 are scratch.
        buf[246] = dhcp_option::MSG_TYPE;
        buf[247] = 1;
        buf[248] = dhcp_msg_type::ACK;
        buf[249] = dhcp_option::END;
        let view = DhcpImpl::parse_message(&buf).unwrap();
        assert_eq!(view.msg_type, dhcp_msg_type::ACK);
        assert_eq!(view.yiaddr, TEST_OFFERED_IP);
    }

    #[test]
    fn parse_tolerates_pad_options() {
        let mut buf = [0u8; DHCP_FIXED_HEADER_LEN + 8];
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        buf[240] = dhcp_option::PAD;
        buf[241] = dhcp_option::PAD;
        buf[242] = dhcp_option::MSG_TYPE;
        buf[243] = 1;
        buf[244] = dhcp_msg_type::ACK;
        buf[245] = dhcp_option::END;
        let view = DhcpImpl::parse_message(&buf).unwrap();
        assert_eq!(view.msg_type, dhcp_msg_type::ACK);
    }

    // ===== round-trip: build_discover then parse_message =====

    #[test]
    fn build_discover_parse_round_trip() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_discover(TEST_MAC, TEST_XID, &mut buf).unwrap();
        let view = DhcpImpl::parse_message(&buf[..n]).unwrap();
        assert_eq!(view.op, DHCP_OP_BOOTREQUEST);
        assert_eq!(view.xid, TEST_XID);
        assert_eq!(view.chaddr, TEST_MAC);
        assert_eq!(view.msg_type, dhcp_msg_type::DISCOVER);
        assert_eq!(view.flags, DHCP_FLAG_BROADCAST);
        assert_eq!(view.yiaddr, [0u8; 4]);
        assert_eq!(view.ciaddr, [0u8; 4]);
    }

    #[test]
    fn build_request_parse_round_trip() {
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = DhcpImpl::build_request(
            TEST_MAC,
            TEST_XID,
            TEST_OFFERED_IP,
            TEST_SERVER_ID,
            &mut buf,
        )
        .unwrap();
        let view = DhcpImpl::parse_message(&buf[..n]).unwrap();
        assert_eq!(view.op, DHCP_OP_BOOTREQUEST);
        assert_eq!(view.msg_type, dhcp_msg_type::REQUEST);
        assert_eq!(view.requested_ip, Some(TEST_OFFERED_IP));
        assert_eq!(view.server_id, Some(TEST_SERVER_ID));
    }

    // ===== DhcpClient state machine =====

    #[test]
    fn client_starts_in_init() {
        let cli = DhcpClient::new(TEST_MAC);
        assert_eq!(cli.state(), DhcpClientState::Init);
        assert_eq!(cli.xid(), 0);
        assert_eq!(cli.mac(), TEST_MAC);
        assert_eq!(cli.lease(), DhcpLease::default());
    }

    #[test]
    fn client_init_to_selecting_via_discover() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = cli.start_discover(TEST_XID, &mut buf).unwrap();
        assert!(n >= DHCP_FIXED_HEADER_LEN);
        assert_eq!(cli.state(), DhcpClientState::Selecting);
        assert_eq!(cli.xid(), TEST_XID);
        // The DISCOVER bytes can be parsed back.
        let view = DhcpImpl::parse_message(&buf[..n]).unwrap();
        assert_eq!(view.msg_type, dhcp_msg_type::DISCOVER);
    }

    #[test]
    fn client_rejects_discover_outside_init() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut buf = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut buf).unwrap();
        // Now in Selecting — second start_discover must fail.
        let mut buf2 = [0u8; DHCP_MAX_MESSAGE_LEN];
        assert_eq!(
            cli.start_discover(TEST_XID, &mut buf2),
            Err(DhcpError::UnexpectedState)
        );
    }

    #[test]
    fn client_selecting_to_requesting_on_offer() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_req = cli.on_offer(&offer[..n_off], &mut req).unwrap();
        assert!(n_req >= DHCP_FIXED_HEADER_LEN);
        assert_eq!(cli.state(), DhcpClientState::Requesting);
        assert_eq!(cli.offered_ip(), TEST_OFFERED_IP);
        assert_eq!(cli.server_id(), TEST_SERVER_ID);
        // Pre-populated lease fields from OFFER.
        assert_eq!(cli.lease().subnet_mask, TEST_SUBNET);
        assert_eq!(cli.lease().gateway, TEST_ROUTER);
        assert_eq!(cli.lease().dns, TEST_DNS);
        assert_eq!(cli.lease().lease_secs, TEST_LEASE_SECS);
        // REQUEST body recovers the offered IP + server-id.
        let view = DhcpImpl::parse_message(&req[..n_req]).unwrap();
        assert_eq!(view.msg_type, dhcp_msg_type::REQUEST);
        assert_eq!(view.requested_ip, Some(TEST_OFFERED_IP));
        assert_eq!(view.server_id, Some(TEST_SERVER_ID));
    }

    #[test]
    fn client_rejects_offer_with_xid_mismatch() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        offer[4..8].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        assert_eq!(
            cli.on_offer(&offer[..n_off], &mut req),
            Err(DhcpError::XidMismatch)
        );
        // State unchanged.
        assert_eq!(cli.state(), DhcpClientState::Selecting);
    }

    #[test]
    fn client_rejects_offer_with_empty_yiaddr() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        offer[16..20].copy_from_slice(&[0u8; 4]);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        assert_eq!(
            cli.on_offer(&offer[..n_off], &mut req),
            Err(DhcpError::EmptyYiaddr)
        );
    }

    #[test]
    fn client_rejects_offer_outside_selecting() {
        let mut cli = DhcpClient::new(TEST_MAC);
        // Still in Init — any OFFER must reject.
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        assert_eq!(
            cli.on_offer(&offer[..n_off], &mut req),
            Err(DhcpError::UnexpectedState)
        );
    }

    #[test]
    fn client_requesting_to_bound_on_ack() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.on_offer(&offer[..n_off], &mut req).unwrap();
        let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_ack = build_ack_fixture(&mut ack);
        let lease = cli.on_ack(&ack[..n_ack], 1_000_000).unwrap();
        assert_eq!(cli.state(), DhcpClientState::Bound);
        assert_eq!(lease.assigned_ip, TEST_OFFERED_IP);
        assert_eq!(lease.subnet_mask, TEST_SUBNET);
        assert_eq!(lease.gateway, TEST_ROUTER);
        assert_eq!(lease.dns, TEST_DNS);
        assert_eq!(lease.server_id, TEST_SERVER_ID);
        assert_eq!(lease.lease_secs, TEST_LEASE_SECS);
        assert_eq!(lease.bound_at_secs, 1_000_000);
    }

    #[test]
    fn client_rejects_ack_with_xid_mismatch() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.on_offer(&offer[..n_off], &mut req).unwrap();
        let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_ack = build_ack_fixture(&mut ack);
        ack[4..8].copy_from_slice(&0xCAFEBABEu32.to_be_bytes());
        assert_eq!(cli.on_ack(&ack[..n_ack], 1_000).err(), Some(DhcpError::XidMismatch));
        assert_eq!(cli.state(), DhcpClientState::Requesting);
    }

    #[test]
    fn client_nak_returns_to_init() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.on_offer(&offer[..n_off], &mut req).unwrap();
        // Build a NAK fixture.
        let mut nak = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n = build_ack_fixture(&mut nak);
        nak[242] = dhcp_msg_type::NAK;
        cli.on_nak(&nak[..n]).unwrap();
        assert_eq!(cli.state(), DhcpClientState::Init);
        assert_eq!(cli.xid(), 0);
        assert_eq!(cli.offered_ip(), [0u8; 4]);
        assert_eq!(cli.server_id(), [0u8; 4]);
    }

    #[test]
    fn client_lease_renew_threshold() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.on_offer(&offer[..n_off], &mut req).unwrap();
        let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_ack = build_ack_fixture(&mut ack);
        cli.on_ack(&ack[..n_ack], 0).unwrap();

        // Just before T1 — still Bound.
        cli.tick(TEST_LEASE_SECS as u64 / 2 - 1);
        assert_eq!(cli.state(), DhcpClientState::Bound);
        // At T1 — Renewing.
        cli.tick(TEST_LEASE_SECS as u64 / 2);
        assert_eq!(cli.state(), DhcpClientState::Renewing);
        // At T2 — Rebinding.
        let t2 = (TEST_LEASE_SECS as u64 * 7) / 8;
        cli.tick(t2);
        assert_eq!(cli.state(), DhcpClientState::Rebinding);
        // After expiry — back to Init.
        cli.tick(TEST_LEASE_SECS as u64 + 1);
        assert_eq!(cli.state(), DhcpClientState::Init);
    }

    #[test]
    fn client_reset_returns_to_init() {
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        cli.start_discover(TEST_XID, &mut disc).unwrap();
        cli.reset();
        assert_eq!(cli.state(), DhcpClientState::Init);
        assert_eq!(cli.xid(), 0);
    }

    #[test]
    fn lease_expiry_computations() {
        let lease = DhcpLease {
            assigned_ip: TEST_OFFERED_IP,
            subnet_mask: TEST_SUBNET,
            gateway: TEST_ROUTER,
            dns: TEST_DNS,
            server_id: TEST_SERVER_ID,
            lease_secs: 1000,
            bound_at_secs: 100,
        };
        assert_eq!(lease.expires_at_secs(), 1100);
        assert_eq!(lease.renew_at_secs(), 600); // 50%
        assert_eq!(lease.rebind_at_secs(), 100 + 875); // 87.5%
    }

    #[test]
    fn lease_permanent_when_lease_secs_zero() {
        let lease = DhcpLease {
            lease_secs: 0,
            bound_at_secs: 100,
            ..DhcpLease::default()
        };
        assert_eq!(lease.expires_at_secs(), u64::MAX);
    }

    #[test]
    fn parse_offer_with_minimal_options() {
        // OFFER lacking router + dns + subnet — still parseable, lease
        // pre-populated via OFFER, options fields are None where absent.
        let mut buf = [0u8; DHCP_FIXED_HEADER_LEN + 16];
        buf[0] = DHCP_OP_BOOTREPLY;
        buf[1] = DHCP_HTYPE_ETHERNET;
        buf[2] = DHCP_HLEN_ETHERNET;
        buf[4..8].copy_from_slice(&TEST_XID.to_be_bytes());
        buf[16..20].copy_from_slice(&TEST_OFFERED_IP);
        buf[28..34].copy_from_slice(&TEST_MAC);
        buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
        buf[240] = dhcp_option::MSG_TYPE;
        buf[241] = 1;
        buf[242] = dhcp_msg_type::OFFER;
        buf[243] = dhcp_option::SERVER_ID;
        buf[244] = 4;
        buf[245..249].copy_from_slice(&TEST_SERVER_ID);
        buf[249] = dhcp_option::END;
        let view = DhcpImpl::parse_message(&buf).unwrap();
        assert_eq!(view.msg_type, dhcp_msg_type::OFFER);
        assert_eq!(view.yiaddr, TEST_OFFERED_IP);
        assert_eq!(view.subnet_mask, None);
        assert_eq!(view.router, None);
        assert_eq!(view.dns, None);
        assert_eq!(view.lease_secs, None);
    }

    #[test]
    fn full_cycle_init_to_bound_chains_xid() {
        // End-to-end: Init -> Selecting -> Requesting -> Bound, with
        // the xid threaded through every transition.
        let mut cli = DhcpClient::new(TEST_MAC);
        let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_disc = cli.start_discover(TEST_XID, &mut disc).unwrap();
        let dv = DhcpImpl::parse_message(&disc[..n_disc]).unwrap();
        assert_eq!(dv.xid, TEST_XID);

        let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_off = build_offer_fixture(&mut offer);
        let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_req = cli.on_offer(&offer[..n_off], &mut req).unwrap();
        let rv = DhcpImpl::parse_message(&req[..n_req]).unwrap();
        assert_eq!(rv.xid, TEST_XID);

        let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
        let n_ack = build_ack_fixture(&mut ack);
        let lease = cli.on_ack(&ack[..n_ack], 42).unwrap();
        assert_eq!(lease.assigned_ip, TEST_OFFERED_IP);
        assert_eq!(cli.state(), DhcpClientState::Bound);
    }
}
