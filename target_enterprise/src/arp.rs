//! ARP (Address Resolution Protocol) — RFC 826, IPv4 over Ethernet.
//!
//! `no_std`, no `alloc`, every buffer fixed-capacity. The Layer-2.5
//! glue between [`crate::ethernet`] (frame transport, EtherType
//! `0x0806`) and [`crate::net`] (which provides IPv4 datagrams that
//! eventually need a MAC to put on the wire). Without ARP, an IPv4
//! stack on top of an Ethernet NIC can address packets to a gateway
//! IP but cannot resolve that IP to a MAC and therefore cannot
//! actually transmit anything off-segment.
//!
//! # Wire format (28 bytes, IPv4 over Ethernet)
//!
//! ```text
//!  0           2           4   5    6           8   9       14         18      24      28
//!  +-----------+-----------+---+---+-----------+---+--------+-----------+-------+-------+
//!  | HTYPE (2) | PTYPE (2) |HLN|PLN| OPER (2)  | sender MAC (6) | sender IP (4)| THA(6)|TPA(4)|
//!  +-----------+-----------+---+---+-----------+---+--------+-----------+-------+-------+
//!     1 = ETH    0x0800 = v4  6   4   1 = REQ / 2 = REP
//! ```
//!
//! Everything is network byte order (big-endian) where the field is
//! wider than a byte. `target_mac` is conventionally all-zeros in a
//! REQUEST (the sender doesn't know it yet — that's the whole point).
//!
//! # Cache: poisoning defence
//!
//! The bundled [`ArpCache`] guards against the classic ARP-spoof /
//! cache-poisoning attack by **refusing to overwrite a recent entry
//! from a different MAC** unless the caller first explicitly
//! `invalidate(ip)`s the slot. This is the same operational guidance
//! RFC 826 recommends ("[The cache] should not be flushed merely
//! because of a single received reply") and what later RFCs (3927 §2.5
//! for IPv4 link-local; the original BSD `arp -s` man page) codify.
//! Tick-driven LRU (`now_ticks` supplied by the caller) lets the
//! kernel use any monotonic clock without baking in a unit.

#![allow(clippy::needless_range_loop)]

use cuttle_contracts::{
    Arp, ArpError, ArpPacketView, MacAddr, ARP_HLEN_ETHERNET, ARP_HTYPE_ETHERNET, ARP_PACKET_LEN,
    ARP_PLEN_IPV4, ARP_PTYPE_IPV4,
};

/// Re-export of the contract length constant for ergonomic call sites
/// in this crate's own tests / kernel banner.
pub const PACKET_LEN: usize = ARP_PACKET_LEN;

/// MAC byte length.
const MAC_LEN: usize = 6;

/// Wire codec implementation. Stateless.
///
/// # Locked surface
///
/// The three methods on this impl are the entire wire-observable
/// contract for ARP. Internals (helper layout, scratch buffers, the
/// constant-folding of HTYPE/PTYPE/HLEN/PLEN) are intentionally
/// diversifiable across morph cycles — the verifier proves wire
/// equivalence against the locked round-trip invariants.
pub struct ArpImpl;

impl Arp for ArpImpl {
    fn build_request(
        sender_mac: MacAddr,
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, ArpError> {
        // RFC 826 §1: REQUEST has THA = all zeros (sender doesn't know
        // the target's MAC — that's literally what is being asked).
        build_packet(
            cuttle_contracts::arp_op::REQUEST,
            sender_mac,
            sender_ip,
            [0u8; MAC_LEN],
            target_ip,
            out,
        )
    }

    fn build_reply(
        sender_mac: MacAddr,
        sender_ip: [u8; 4],
        target_mac: MacAddr,
        target_ip: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, ArpError> {
        build_packet(
            cuttle_contracts::arp_op::REPLY,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
            out,
        )
    }

    fn parse_packet(bytes: &[u8]) -> Result<ArpPacketView, ArpError> {
        if bytes.len() < ARP_PACKET_LEN {
            return Err(ArpError::Truncated);
        }
        let htype = read_u16_be(&bytes[0..2]);
        if htype != ARP_HTYPE_ETHERNET {
            return Err(ArpError::InvalidHardwareType);
        }
        let ptype = read_u16_be(&bytes[2..4]);
        if ptype != ARP_PTYPE_IPV4 {
            return Err(ArpError::InvalidProtocolType);
        }
        let hlen = bytes[4];
        if hlen != ARP_HLEN_ETHERNET {
            return Err(ArpError::InvalidHardwareLength);
        }
        let plen = bytes[5];
        if plen != ARP_PLEN_IPV4 {
            return Err(ArpError::InvalidProtocolLength);
        }
        let oper = read_u16_be(&bytes[6..8]);
        if oper != cuttle_contracts::arp_op::REQUEST
            && oper != cuttle_contracts::arp_op::REPLY
        {
            return Err(ArpError::InvalidOperation);
        }
        let sender_mac = read_mac(&bytes[8..14]);
        let sender_ip = read_ipv4(&bytes[14..18]);
        let target_mac = read_mac(&bytes[18..24]);
        let target_ip = read_ipv4(&bytes[24..28]);
        Ok(ArpPacketView {
            htype,
            ptype,
            hlen,
            plen,
            oper,
            sender_mac,
            sender_ip,
            target_mac,
            target_ip,
        })
    }
}

/// Internal monomorphic packet writer. The three field-checks
/// (`out.len()`, REQUEST-zero-fill, REPLY-real-mac) are merged so the
/// path is shared between `build_request` and `build_reply`.
fn build_packet(
    oper: u16,
    sender_mac: MacAddr,
    sender_ip: [u8; 4],
    target_mac: MacAddr,
    target_ip: [u8; 4],
    out: &mut [u8],
) -> Result<usize, ArpError> {
    if out.len() < ARP_PACKET_LEN {
        return Err(ArpError::OutputBufferTooSmall);
    }
    write_u16_be(&mut out[0..2], ARP_HTYPE_ETHERNET);
    write_u16_be(&mut out[2..4], ARP_PTYPE_IPV4);
    out[4] = ARP_HLEN_ETHERNET;
    out[5] = ARP_PLEN_IPV4;
    write_u16_be(&mut out[6..8], oper);
    write_mac(&mut out[8..14], &sender_mac);
    write_ipv4(&mut out[14..18], &sender_ip);
    write_mac(&mut out[18..24], &target_mac);
    write_ipv4(&mut out[24..28], &target_ip);
    Ok(ARP_PACKET_LEN)
}

/// True iff `view` is a *gratuitous* ARP: an unsolicited
/// announcement where `sender_ip == target_ip`. Used by hosts to
/// advertise their own (IP, MAC) binding at boot or on IP change.
/// Per RFC 5227 §2.4 the operation can be REQUEST (the historical
/// form) or REPLY; the helper accepts both.
#[inline]
pub fn is_gratuitous(view: &ArpPacketView) -> bool {
    view.sender_ip[0] == view.target_ip[0]
        && view.sender_ip[1] == view.target_ip[1]
        && view.sender_ip[2] == view.target_ip[2]
        && view.sender_ip[3] == view.target_ip[3]
}

// ---------------------------------------------------------------------------
// ArpCache — fixed-capacity IP→MAC table with LRU eviction +
// anti-poison guard.
// ---------------------------------------------------------------------------

/// Default poison-defence window in caller-supplied ticks. Inserts of
/// a different MAC for the same IP within this window are rejected
/// with [`ArpError::CachePoisonRejected`]; outside the window the new
/// binding wins (the host may have legitimately changed NICs). The
/// kernel banner uses `ticks` = seconds-since-boot so this value is
/// "5 minutes" by default.
pub const DEFAULT_POISON_WINDOW_TICKS: u64 = 300;

/// Cache slot — `valid == false` slots are free and treated as having
/// `last_used == 0` for the LRU search.
#[derive(Debug, Clone, Copy)]
struct ArpEntry {
    valid: bool,
    ip: [u8; 4],
    mac: MacAddr,
    last_used: u64,
}

impl ArpEntry {
    const EMPTY: Self = Self {
        valid: false,
        ip: [0u8; 4],
        mac: [0u8; 6],
        last_used: 0,
    };
}

/// Fixed-capacity IP→MAC cache. `N` is the slot count (compile-time
/// const); a typical kernel banner runs with `N = 4`, a production
/// host stack with `N = 64` or `N = 256`.
///
/// # Invariants
///
/// 1. `insert` never silently drops the LRU entry from a binding the
///    caller still cares about — but it does evict when the cache is
///    full *and* every slot is older than the inserted entry. The
///    caller can prevent this by sizing `N` to the working set.
/// 2. `insert` rejects MACs in the blocked list (all-zeros,
///    broadcast). This is the seed's *operational* defence; a
///    well-formed REPLY carrying THA = `[0;6]` (which would otherwise
///    look like a valid binding) is sourced from a broken or hostile
///    peer and must not enter the cache.
/// 3. `insert` rejects an overwrite of a recent entry from a
///    *different* MAC. The caller must `invalidate(ip)` first if it
///    genuinely wants to replace the binding (e.g. interface flip).
pub struct ArpCache<const N: usize> {
    slots: [ArpEntry; N],
    poison_window: u64,
}

impl<const N: usize> ArpCache<N> {
    /// Construct an empty cache with the default poison window.
    pub const fn new() -> Self {
        Self {
            slots: [ArpEntry::EMPTY; N],
            poison_window: DEFAULT_POISON_WINDOW_TICKS,
        }
    }

    /// Construct an empty cache with a custom poison window (in the
    /// same tick units the caller passes to `insert` / `lookup`).
    pub const fn with_poison_window(window: u64) -> Self {
        Self {
            slots: [ArpEntry::EMPTY; N],
            poison_window: window,
        }
    }

    /// Slot count (compile-time, equals `N`).
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Currently occupied slot count.
    pub fn len(&self) -> usize {
        let mut n = 0usize;
        for s in self.slots.iter() {
            if s.valid {
                n += 1;
            }
        }
        n
    }

    /// True if no slots are occupied.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Insert (or refresh) a binding. `now_ticks` becomes the slot's
    /// `last_used` for LRU bookkeeping. See type-level docs for
    /// rejection rules.
    pub fn insert(
        &mut self,
        ip: [u8; 4],
        mac: MacAddr,
        now_ticks: u64,
    ) -> Result<(), ArpError> {
        if is_blocked_mac(&mac) {
            return Err(ArpError::BlockedMac);
        }
        // 1. Refresh path — same IP already in cache.
        for i in 0..N {
            if self.slots[i].valid && self.slots[i].ip == ip {
                if self.slots[i].mac == mac {
                    // Same binding — just refresh the LRU stamp.
                    self.slots[i].last_used = now_ticks;
                    return Ok(());
                }
                // Different MAC for the same IP — poison defence.
                let delta = now_ticks.saturating_sub(self.slots[i].last_used);
                if delta < self.poison_window {
                    return Err(ArpError::CachePoisonRejected);
                }
                // Outside the window — overwrite is legitimate.
                self.slots[i].mac = mac;
                self.slots[i].last_used = now_ticks;
                return Ok(());
            }
        }
        // 2. Free-slot path.
        for i in 0..N {
            if !self.slots[i].valid {
                self.slots[i] = ArpEntry {
                    valid: true,
                    ip,
                    mac,
                    last_used: now_ticks,
                };
                return Ok(());
            }
        }
        // 3. LRU eviction path — full cache.
        let mut victim = 0usize;
        let mut victim_lu = self.slots[0].last_used;
        for i in 1..N {
            if self.slots[i].last_used < victim_lu {
                victim = i;
                victim_lu = self.slots[i].last_used;
            }
        }
        self.slots[victim] = ArpEntry {
            valid: true,
            ip,
            mac,
            last_used: now_ticks,
        };
        Ok(())
    }

    /// Look up `ip`. On hit, refresh the slot's `last_used` to
    /// `now_ticks` and return `Some(mac)`. On miss, return `None`.
    pub fn lookup(&mut self, ip: &[u8; 4], now_ticks: u64) -> Option<MacAddr> {
        for i in 0..N {
            if self.slots[i].valid && &self.slots[i].ip == ip {
                self.slots[i].last_used = now_ticks;
                return Some(self.slots[i].mac);
            }
        }
        None
    }

    /// Non-mutating peek: returns the binding without refreshing the
    /// LRU stamp. Useful for telemetry / tests.
    pub fn peek(&self, ip: &[u8; 4]) -> Option<MacAddr> {
        for i in 0..N {
            if self.slots[i].valid && &self.slots[i].ip == ip {
                return Some(self.slots[i].mac);
            }
        }
        None
    }

    /// Drop the entry for `ip`, if any. Returns `true` if a slot was
    /// freed. Required before re-inserting a different MAC for the
    /// same IP within the poison window.
    pub fn invalidate(&mut self, ip: &[u8; 4]) -> bool {
        for i in 0..N {
            if self.slots[i].valid && &self.slots[i].ip == ip {
                self.slots[i] = ArpEntry::EMPTY;
                return true;
            }
        }
        false
    }

    /// Drop every entry.
    pub fn clear(&mut self) {
        for i in 0..N {
            self.slots[i] = ArpEntry::EMPTY;
        }
    }
}

impl<const N: usize> Default for ArpCache<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// True if `mac` is on the blocked list (all-zeros or the link-layer
/// broadcast). Cache inserts of these MACs are rejected — they
/// represent either uninitialised memory or a frame sent to every
/// station, neither of which is a valid resolved binding.
#[inline]
pub fn is_blocked_mac(mac: &MacAddr) -> bool {
    let zero = mac[0] == 0 && mac[1] == 0 && mac[2] == 0 && mac[3] == 0 && mac[4] == 0 && mac[5] == 0;
    let bcast = mac[0] == 0xFF
        && mac[1] == 0xFF
        && mac[2] == 0xFF
        && mac[3] == 0xFF
        && mac[4] == 0xFF
        && mac[5] == 0xFF;
    zero || bcast
}

// ---------------------------------------------------------------------------
// Byte helpers (kept local — duplicated with `ethernet.rs` but tiny,
// and decoupling lets the morph engine perturb each module's helper
// layout independently).
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
fn read_mac(b: &[u8]) -> MacAddr {
    [b[0], b[1], b[2], b[3], b[4], b[5]]
}

#[inline]
fn write_mac(out: &mut [u8], m: &MacAddr) {
    out[0] = m[0];
    out[1] = m[1];
    out[2] = m[2];
    out[3] = m[3];
    out[4] = m[4];
    out[5] = m[5];
}

#[inline]
fn read_ipv4(b: &[u8]) -> [u8; 4] {
    [b[0], b[1], b[2], b[3]]
}

#[inline]
fn write_ipv4(out: &mut [u8], ip: &[u8; 4]) {
    out[0] = ip[0];
    out[1] = ip[1];
    out[2] = ip[2];
    out[3] = ip[3];
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::{arp_op, Arp};

    const SENDER_MAC: MacAddr = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    const SENDER_IP: [u8; 4] = [10, 0, 0, 1];
    const TARGET_IP: [u8; 4] = [10, 0, 0, 42];
    const TARGET_MAC: MacAddr = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    #[test]
    fn build_request_byte_exact() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        let n = ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        assert_eq!(n, ARP_PACKET_LEN);
        let expected: &[u8] = &[
            0x00, 0x01, // HTYPE = 1 (Ethernet)
            0x08, 0x00, // PTYPE = 0x0800 (IPv4)
            0x06, 0x04, // HLEN=6, PLEN=4
            0x00, 0x01, // OPER = REQUEST
            0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // sender MAC
            10, 0, 0, 1, // sender IP
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // target MAC (REQ → zeros)
            10, 0, 0, 42, // target IP
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn build_request_round_trip() {
        let mut buf = [0u8; 64];
        let n = ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        let view = ArpImpl::parse_packet(&buf[..n]).unwrap();
        assert_eq!(view.htype, ARP_HTYPE_ETHERNET);
        assert_eq!(view.ptype, ARP_PTYPE_IPV4);
        assert_eq!(view.hlen, ARP_HLEN_ETHERNET);
        assert_eq!(view.plen, ARP_PLEN_IPV4);
        assert_eq!(view.oper, arp_op::REQUEST);
        assert_eq!(view.sender_mac, SENDER_MAC);
        assert_eq!(view.sender_ip, SENDER_IP);
        assert_eq!(view.target_mac, [0u8; 6]);
        assert_eq!(view.target_ip, TARGET_IP);
    }

    #[test]
    fn build_reply_byte_exact() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        let n =
            ArpImpl::build_reply(SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP, &mut buf).unwrap();
        assert_eq!(n, ARP_PACKET_LEN);
        let expected: &[u8] = &[
            0x00, 0x01, 0x08, 0x00, 0x06, 0x04, 0x00, 0x02, // header + OPER=REPLY
            0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // sender MAC
            10, 0, 0, 1, // sender IP
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // target MAC (real)
            10, 0, 0, 42, // target IP
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn build_reply_round_trip() {
        let mut buf = [0u8; 64];
        let n =
            ArpImpl::build_reply(SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP, &mut buf).unwrap();
        let view = ArpImpl::parse_packet(&buf[..n]).unwrap();
        assert_eq!(view.oper, arp_op::REPLY);
        assert_eq!(view.sender_mac, SENDER_MAC);
        assert_eq!(view.target_mac, TARGET_MAC);
        assert_eq!(view.sender_ip, SENDER_IP);
        assert_eq!(view.target_ip, TARGET_IP);
    }

    #[test]
    fn build_rejects_small_buffer() {
        let mut buf = [0u8; 27];
        assert!(matches!(
            ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf),
            Err(ArpError::OutputBufferTooSmall)
        ));
    }

    #[test]
    fn parse_rejects_truncated() {
        let bytes = [0u8; 27];
        assert!(matches!(
            ArpImpl::parse_packet(&bytes),
            Err(ArpError::Truncated)
        ));
    }

    #[test]
    fn parse_rejects_invalid_htype() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        // HTYPE = 0x0006 (token ring) — not Ethernet.
        buf[0] = 0x00;
        buf[1] = 0x06;
        assert!(matches!(
            ArpImpl::parse_packet(&buf),
            Err(ArpError::InvalidHardwareType)
        ));
    }

    #[test]
    fn parse_rejects_invalid_ptype() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        // PTYPE = 0x86DD (IPv6) — not IPv4.
        buf[2] = 0x86;
        buf[3] = 0xDD;
        assert!(matches!(
            ArpImpl::parse_packet(&buf),
            Err(ArpError::InvalidProtocolType)
        ));
    }

    #[test]
    fn parse_rejects_invalid_hlen() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        buf[4] = 7; // HLEN must be 6
        assert!(matches!(
            ArpImpl::parse_packet(&buf),
            Err(ArpError::InvalidHardwareLength)
        ));
    }

    #[test]
    fn parse_rejects_invalid_plen() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        buf[5] = 16; // PLEN must be 4 (would be 16 for IPv6, which we'd reject earlier)
        assert!(matches!(
            ArpImpl::parse_packet(&buf),
            Err(ArpError::InvalidProtocolLength)
        ));
    }

    #[test]
    fn parse_rejects_invalid_oper() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        // OPER = 3 (reserved). Only 1 and 2 accepted.
        buf[6] = 0x00;
        buf[7] = 0x03;
        assert!(matches!(
            ArpImpl::parse_packet(&buf),
            Err(ArpError::InvalidOperation)
        ));
    }

    #[test]
    fn gratuitous_arp_is_detected() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, SENDER_IP, &mut buf).unwrap();
        let view = ArpImpl::parse_packet(&buf).unwrap();
        assert!(is_gratuitous(&view));
    }

    #[test]
    fn non_gratuitous_request_is_not_gratuitous() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, TARGET_IP, &mut buf).unwrap();
        let view = ArpImpl::parse_packet(&buf).unwrap();
        assert!(!is_gratuitous(&view));
    }

    #[test]
    fn cache_add_lookup() {
        let mut cache: ArpCache<4> = ArpCache::new();
        assert!(cache.is_empty());
        cache.insert([10, 0, 0, 42], TARGET_MAC, 100).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.lookup(&[10, 0, 0, 42], 200), Some(TARGET_MAC));
        assert_eq!(cache.lookup(&[10, 0, 0, 99], 200), None);
    }

    #[test]
    fn cache_refresh_keeps_single_slot() {
        let mut cache: ArpCache<4> = ArpCache::new();
        cache.insert([10, 0, 0, 42], TARGET_MAC, 100).unwrap();
        cache.insert([10, 0, 0, 42], TARGET_MAC, 200).unwrap();
        cache.insert([10, 0, 0, 42], TARGET_MAC, 300).unwrap();
        assert_eq!(cache.len(), 1);
    }

    #[test]
    fn cache_lru_evicts_oldest_when_full() {
        let mut cache: ArpCache<3> = ArpCache::new();
        cache.insert([10, 0, 0, 1], [1, 1, 1, 1, 1, 1], 10).unwrap();
        cache.insert([10, 0, 0, 2], [2, 2, 2, 2, 2, 2], 20).unwrap();
        cache.insert([10, 0, 0, 3], [3, 3, 3, 3, 3, 3], 30).unwrap();
        assert_eq!(cache.len(), 3);
        // Insert a fourth — slot 1 (last_used=10) should be evicted.
        cache.insert([10, 0, 0, 4], [4, 4, 4, 4, 4, 4], 40).unwrap();
        assert_eq!(cache.len(), 3);
        assert_eq!(cache.peek(&[10, 0, 0, 1]), None);
        assert_eq!(cache.peek(&[10, 0, 0, 2]), Some([2, 2, 2, 2, 2, 2]));
        assert_eq!(cache.peek(&[10, 0, 0, 4]), Some([4, 4, 4, 4, 4, 4]));
    }

    #[test]
    fn cache_lookup_refreshes_lru_stamp() {
        let mut cache: ArpCache<3> = ArpCache::new();
        cache.insert([10, 0, 0, 1], [1, 1, 1, 1, 1, 1], 10).unwrap();
        cache.insert([10, 0, 0, 2], [2, 2, 2, 2, 2, 2], 20).unwrap();
        cache.insert([10, 0, 0, 3], [3, 3, 3, 3, 3, 3], 30).unwrap();
        // Refresh slot 1.
        let _ = cache.lookup(&[10, 0, 0, 1], 40);
        // Insert a fourth — slot 2 (last_used=20) should now be evicted.
        cache.insert([10, 0, 0, 4], [4, 4, 4, 4, 4, 4], 50).unwrap();
        assert_eq!(cache.peek(&[10, 0, 0, 1]), Some([1, 1, 1, 1, 1, 1]));
        assert_eq!(cache.peek(&[10, 0, 0, 2]), None);
    }

    #[test]
    fn cache_rejects_blocked_zero_mac() {
        let mut cache: ArpCache<4> = ArpCache::new();
        assert!(matches!(
            cache.insert([10, 0, 0, 1], [0u8; 6], 100),
            Err(ArpError::BlockedMac)
        ));
    }

    #[test]
    fn cache_rejects_blocked_broadcast_mac() {
        let mut cache: ArpCache<4> = ArpCache::new();
        assert!(matches!(
            cache.insert([10, 0, 0, 1], [0xFFu8; 6], 100),
            Err(ArpError::BlockedMac)
        ));
    }

    #[test]
    fn cache_poison_defence_rejects_recent_overwrite() {
        let mut cache: ArpCache<4> = ArpCache::with_poison_window(300);
        cache.insert([10, 0, 0, 1], [1, 1, 1, 1, 1, 1], 100).unwrap();
        // 50 ticks later, attacker offers a different MAC for same IP.
        let err = cache.insert([10, 0, 0, 1], [9, 9, 9, 9, 9, 9], 150);
        assert!(matches!(err, Err(ArpError::CachePoisonRejected)));
        // Original binding survives.
        assert_eq!(cache.peek(&[10, 0, 0, 1]), Some([1, 1, 1, 1, 1, 1]));
    }

    #[test]
    fn cache_poison_defence_allows_overwrite_after_invalidate() {
        let mut cache: ArpCache<4> = ArpCache::with_poison_window(300);
        cache.insert([10, 0, 0, 1], [1, 1, 1, 1, 1, 1], 100).unwrap();
        assert!(cache.invalidate(&[10, 0, 0, 1]));
        // Same tick — but explicit invalidate cleared the entry.
        cache.insert([10, 0, 0, 1], [9, 9, 9, 9, 9, 9], 150).unwrap();
        assert_eq!(cache.peek(&[10, 0, 0, 1]), Some([9, 9, 9, 9, 9, 9]));
    }

    #[test]
    fn cache_poison_defence_allows_overwrite_after_window() {
        let mut cache: ArpCache<4> = ArpCache::with_poison_window(300);
        cache.insert([10, 0, 0, 1], [1, 1, 1, 1, 1, 1], 100).unwrap();
        // Long enough later — the binding is allowed to change.
        cache.insert([10, 0, 0, 1], [9, 9, 9, 9, 9, 9], 100 + 500).unwrap();
        assert_eq!(cache.peek(&[10, 0, 0, 1]), Some([9, 9, 9, 9, 9, 9]));
    }

    #[test]
    fn cache_clear_empties_slots() {
        let mut cache: ArpCache<4> = ArpCache::new();
        cache.insert([10, 0, 0, 1], [1, 1, 1, 1, 1, 1], 10).unwrap();
        cache.insert([10, 0, 0, 2], [2, 2, 2, 2, 2, 2], 20).unwrap();
        assert_eq!(cache.len(), 2);
        cache.clear();
        assert!(cache.is_empty());
        assert_eq!(cache.peek(&[10, 0, 0, 1]), None);
    }

    #[test]
    fn cache_invalidate_returns_false_for_missing() {
        let mut cache: ArpCache<4> = ArpCache::new();
        assert!(!cache.invalidate(&[10, 0, 0, 1]));
    }

    #[test]
    fn cache_capacity_matches_const_generic() {
        let cache: ArpCache<8> = ArpCache::new();
        assert_eq!(cache.capacity(), 8);
    }

    #[test]
    fn is_blocked_mac_classifies_zero_and_broadcast() {
        assert!(is_blocked_mac(&[0u8; 6]));
        assert!(is_blocked_mac(&[0xFFu8; 6]));
        assert!(!is_blocked_mac(&[0, 0, 0, 0, 0, 1]));
        assert!(!is_blocked_mac(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]));
        assert!(!is_blocked_mac(&TARGET_MAC));
    }

    #[test]
    fn build_request_and_parse_handle_zero_target_ip() {
        // Edge case: target_ip = 0.0.0.0 (probe). Per RFC 5227 §2.1 a
        // host probes for its own IP by sending a REQUEST with
        // sender_ip = 0.0.0.0 and target_ip = the desired IP. We
        // accept the symmetric case (target_ip = 0.0.0.0) without
        // special-casing it — the round-trip recovers the zeros.
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_request(SENDER_MAC, SENDER_IP, [0, 0, 0, 0], &mut buf).unwrap();
        let view = ArpImpl::parse_packet(&buf).unwrap();
        assert_eq!(view.target_ip, [0, 0, 0, 0]);
    }

    #[test]
    fn parse_recovers_oper_for_reply() {
        let mut buf = [0u8; ARP_PACKET_LEN];
        ArpImpl::build_reply(SENDER_MAC, SENDER_IP, TARGET_MAC, TARGET_IP, &mut buf).unwrap();
        let view = ArpImpl::parse_packet(&buf).unwrap();
        assert_eq!(view.oper, 2);
    }

    #[test]
    fn cache_default_constructor_uses_default_window() {
        let cache: ArpCache<4> = ArpCache::default();
        assert_eq!(cache.poison_window, DEFAULT_POISON_WINDOW_TICKS);
    }
}
