//! Ethernet II / IEEE 802.3 frame wire codec — with single 802.1Q
//! VLAN tag support.
//!
//! `no_std`, no `alloc`, fixed-capacity scratch in the impl. The
//! load-bearing Layer-2 framing under [`crate::net`]'s IPv4/UDP
//! payloads; without this, none of the higher-layer wire codecs can
//! actually ride a NIC.
//!
//! # Frame layout (untagged, 14-byte header)
//!
//! ```text
//!  0                   6                   12              14
//!  +---------------------------------------+---------------+
//!  | Destination MAC (6)| Source MAC (6)    | EtherType (2)|
//!  +---------------------------------------+---------------+
//!  | Payload (variable)                                    |
//!  +-------------------------------------------------------+
//! ```
//!
//! # Frame layout (802.1Q VLAN-tagged, 18-byte header)
//!
//! ```text
//!  0       6       12      14      16      18
//!  +-------+-------+-------+-------+-------+
//!  | DST(6)| SRC(6)|TPID(2)|TCI (2)| ET (2)|
//!  +-------+-------+-------+-------+-------+
//!     TPID = 0x8100
//!     TCI  = PCP(3) | DEI(1) | VID(12)   — packed big-endian
//!     ET   = inner EtherType (e.g. 0x0800 for IPv4)
//! ```
//!
//! # What's not covered
//!
//! - Frame Check Sequence (FCS / CRC-32). Hardware NICs compute it;
//!   software emission would be wasted CPU. A future "raw socket
//!   without NIC offload" caller can add it as a separate trait.
//! - Minimum-size padding (60 bytes without FCS / 64 with). Same
//!   hardware-handles-it reasoning.
//! - 802.1ad Q-in-Q double tagging. Single 802.1Q only.
//! - 802.3 SNAP / LLC encapsulation. EtherType II only.

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{Eth, EthError, EthFrameView, MacAddr};

/// Length of the Ethernet II header (untagged).
pub const ETH_HEADER_LEN: usize = 14;

/// Length of an 802.1Q VLAN-tagged Ethernet header (TPID + TCI added).
pub const ETH_HEADER_LEN_VLAN: usize = 18;

/// Length of a MAC address in bytes.
pub const MAC_ADDR_LEN: usize = 6;

/// TPID value that signals an 802.1Q VLAN tag (RFC 7042 §2.3.1).
pub const VLAN_TPID: u16 = 0x8100;

/// Mask + shift for the 3-bit PCP (Priority Code Point) within the
/// 16-bit TCI. Bits 13..16.
pub const VLAN_PCP_SHIFT: u32 = 13;
/// Mask + shift for the 1-bit DEI (Drop Eligible Indicator). Bit 12.
pub const VLAN_DEI_SHIFT: u32 = 12;
/// 12-bit VID mask. Bits 0..12.
pub const VLAN_VID_MASK: u16 = 0x0FFF;
/// Reserved VID values per IEEE 802.1Q. `0x000` = priority-tagged
/// frame (no VLAN), `0xFFF` = reserved.
pub const VLAN_VID_RESERVED_NULL: u16 = 0x000;
/// Reserved VID per IEEE 802.1Q.
pub const VLAN_VID_RESERVED_MAX: u16 = 0xFFF;

/// Wire codec impl. Stateless.
pub struct EthImpl;

impl Eth for EthImpl {
    fn build_frame(
        dst: MacAddr,
        src: MacAddr,
        ether_type: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, EthError> {
        let total = ETH_HEADER_LEN + payload.len();
        if out.len() < total {
            return Err(EthError::OutputBufferTooSmall);
        }
        write_mac(&mut out[0..6], &dst);
        write_mac(&mut out[6..12], &src);
        write_u16_be(&mut out[12..14], ether_type);
        for i in 0..payload.len() {
            out[ETH_HEADER_LEN + i] = payload[i];
        }
        Ok(total)
    }

    fn build_frame_vlan(
        dst: MacAddr,
        src: MacAddr,
        vlan_tci: u16,
        inner_ether_type: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, EthError> {
        let total = ETH_HEADER_LEN_VLAN + payload.len();
        if out.len() < total {
            return Err(EthError::OutputBufferTooSmall);
        }
        write_mac(&mut out[0..6], &dst);
        write_mac(&mut out[6..12], &src);
        write_u16_be(&mut out[12..14], VLAN_TPID);
        write_u16_be(&mut out[14..16], vlan_tci);
        write_u16_be(&mut out[16..18], inner_ether_type);
        for i in 0..payload.len() {
            out[ETH_HEADER_LEN_VLAN + i] = payload[i];
        }
        Ok(total)
    }

    fn parse_frame(bytes: &[u8]) -> Result<EthFrameView<'_>, EthError> {
        if bytes.len() < ETH_HEADER_LEN {
            return Err(EthError::Truncated);
        }
        let dst = read_mac(&bytes[0..6]);
        let src = read_mac(&bytes[6..12]);
        let first_ethertype = read_u16_be(&bytes[12..14]);

        if first_ethertype == VLAN_TPID {
            // 802.1Q tagged frame.
            if bytes.len() < ETH_HEADER_LEN_VLAN {
                return Err(EthError::Truncated);
            }
            let tci = read_u16_be(&bytes[14..16]);
            let inner_ether_type = read_u16_be(&bytes[16..18]);
            // Reject another VLAN tag immediately — Q-in-Q is out of
            // scope for the seed.
            if inner_ether_type == VLAN_TPID {
                return Err(EthError::InvalidTag);
            }
            return Ok(EthFrameView {
                dst,
                src,
                ether_type: inner_ether_type,
                vlan_tci: Some(tci),
                payload: &bytes[ETH_HEADER_LEN_VLAN..],
            });
        }

        Ok(EthFrameView {
            dst,
            src,
            ether_type: first_ethertype,
            vlan_tci: None,
            payload: &bytes[ETH_HEADER_LEN..],
        })
    }
}

// ---------------------------------------------------------------------------
// MAC-address helpers (pure / freestanding)
// ---------------------------------------------------------------------------

/// True if `mac` is the all-1s broadcast address.
#[inline]
pub fn is_broadcast(mac: &MacAddr) -> bool {
    mac[0] == 0xFF
        && mac[1] == 0xFF
        && mac[2] == 0xFF
        && mac[3] == 0xFF
        && mac[4] == 0xFF
        && mac[5] == 0xFF
}

/// True if `mac` has its group/individual bit set — i.e. it's a
/// multicast address. Broadcast is the all-1s special case of
/// multicast and also returns true here.
#[inline]
pub fn is_multicast(mac: &MacAddr) -> bool {
    (mac[0] & 0x01) == 0x01
}

/// True if `mac` is a unicast address (its group/individual bit is
/// clear). Mutually exclusive with [`is_multicast`].
#[inline]
pub fn is_unicast(mac: &MacAddr) -> bool {
    !is_multicast(mac)
}

/// Extract the 3-bit PCP (Priority Code Point) from a 16-bit TCI.
#[inline]
pub fn vlan_pcp(tci: u16) -> u8 {
    ((tci >> VLAN_PCP_SHIFT) & 0x07) as u8
}

/// Extract the 1-bit DEI (Drop Eligible Indicator) from a TCI.
#[inline]
pub fn vlan_dei(tci: u16) -> bool {
    ((tci >> VLAN_DEI_SHIFT) & 0x01) == 1
}

/// Extract the 12-bit VID (VLAN Identifier) from a TCI.
#[inline]
pub fn vlan_vid(tci: u16) -> u16 {
    tci & VLAN_VID_MASK
}

/// Pack `(pcp, dei, vid)` into a 16-bit TCI. Caller is responsible
/// for keeping `pcp <= 7` and `vid <= 0xFFF`; the helper masks each
/// to its field width.
#[inline]
pub fn pack_vlan_tci(pcp: u8, dei: bool, vid: u16) -> u16 {
    let pcp = ((pcp & 0x07) as u16) << VLAN_PCP_SHIFT;
    let dei = if dei { 1u16 << VLAN_DEI_SHIFT } else { 0 };
    let vid = vid & VLAN_VID_MASK;
    pcp | dei | vid
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::ether_type;

    const DST: MacAddr = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    const SRC: MacAddr = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    #[test]
    fn build_frame_round_trip() {
        let payload = b"hello-eth";
        let mut buf = [0u8; 64];
        let n = EthImpl::build_frame(DST, SRC, ether_type::IPV4, payload, &mut buf).unwrap();
        assert_eq!(n, ETH_HEADER_LEN + payload.len());
        let view = EthImpl::parse_frame(&buf[..n]).unwrap();
        assert_eq!(view.dst, DST);
        assert_eq!(view.src, SRC);
        assert_eq!(view.ether_type, ether_type::IPV4);
        assert_eq!(view.vlan_tci, None);
        assert_eq!(view.payload, payload);
    }

    #[test]
    fn build_frame_byte_exact_for_ipv4_minimum() {
        // Empty payload to make the bytes hand-verifiable.
        let mut buf = [0u8; 16];
        let n = EthImpl::build_frame(DST, SRC, ether_type::IPV4, b"", &mut buf).unwrap();
        let expected: &[u8] = &[
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // dst
            0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // src
            0x08, 0x00, // EtherType IPv4
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn build_frame_arp_ethertype_round_trip() {
        let mut buf = [0u8; 64];
        let payload = b"arp-bytes-here";
        let n = EthImpl::build_frame(DST, SRC, ether_type::ARP, payload, &mut buf).unwrap();
        let view = EthImpl::parse_frame(&buf[..n]).unwrap();
        assert_eq!(view.ether_type, ether_type::ARP);
        assert_eq!(view.ether_type, 0x0806);
    }

    #[test]
    fn parse_rejects_truncated() {
        // 13 bytes < ETH_HEADER_LEN (14).
        let bytes = [0u8; 13];
        assert!(matches!(
            EthImpl::parse_frame(&bytes),
            Err(EthError::Truncated)
        ));
    }

    #[test]
    fn build_rejects_small_buffer() {
        // 10 bytes < ETH_HEADER_LEN.
        let mut buf = [0u8; 10];
        assert!(matches!(
            EthImpl::build_frame(DST, SRC, ether_type::IPV4, b"", &mut buf),
            Err(EthError::OutputBufferTooSmall)
        ));
    }

    #[test]
    fn empty_payload_is_legal() {
        let mut buf = [0u8; 16];
        let n = EthImpl::build_frame(DST, SRC, ether_type::IPV6, b"", &mut buf).unwrap();
        assert_eq!(n, ETH_HEADER_LEN);
        let view = EthImpl::parse_frame(&buf[..n]).unwrap();
        assert_eq!(view.payload, &[][..]);
        assert_eq!(view.ether_type, ether_type::IPV6);
    }

    #[test]
    fn vlan_tagged_frame_round_trip() {
        let tci = pack_vlan_tci(3, false, 100); // PCP=3, DEI=0, VID=100
        let payload = b"vlan-payload";
        let mut buf = [0u8; 64];
        let n = EthImpl::build_frame_vlan(DST, SRC, tci, ether_type::IPV4, payload, &mut buf)
            .unwrap();
        assert_eq!(n, ETH_HEADER_LEN_VLAN + payload.len());
        let view = EthImpl::parse_frame(&buf[..n]).unwrap();
        assert_eq!(view.dst, DST);
        assert_eq!(view.src, SRC);
        assert_eq!(view.ether_type, ether_type::IPV4);
        assert_eq!(view.vlan_tci, Some(tci));
        assert_eq!(view.payload, payload);
    }

    #[test]
    fn vlan_tci_field_extraction() {
        // Pack & unpack PCP, DEI, VID across the full range.
        let cases: &[(u8, bool, u16)] = &[
            (0, false, 0),
            (7, true, 0xFFF),
            (3, false, 1234),
            (5, true, 100),
            (0, true, 1),
            (7, false, 4094),
        ];
        for &(pcp, dei, vid) in cases {
            let tci = pack_vlan_tci(pcp, dei, vid);
            assert_eq!(vlan_pcp(tci), pcp);
            assert_eq!(vlan_dei(tci), dei);
            assert_eq!(vlan_vid(tci), vid);
        }
    }

    #[test]
    fn vlan_tagged_byte_exact() {
        // tci = PCP=3 (bits 13..16 = 011), DEI=0 (bit 12 = 0), VID=100 (0x064)
        // tci = 0b0110_0000_0110_0100 = 0x6064
        let tci = pack_vlan_tci(3, false, 100);
        assert_eq!(tci, 0x6064);
        let mut buf = [0u8; 32];
        let n =
            EthImpl::build_frame_vlan(DST, SRC, tci, ether_type::IPV4, b"", &mut buf).unwrap();
        let expected: &[u8] = &[
            0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, // dst
            0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // src
            0x81, 0x00, // TPID
            0x60, 0x64, // TCI
            0x08, 0x00, // inner EtherType = IPv4
        ];
        assert_eq!(&buf[..n], expected);
    }

    #[test]
    fn parse_rejects_truncated_vlan() {
        // 14 bytes of header showing VLAN TPID but no room for TCI +
        // inner EtherType.
        let mut bytes = [0u8; 14];
        bytes[12] = 0x81;
        bytes[13] = 0x00;
        assert!(matches!(
            EthImpl::parse_frame(&bytes),
            Err(EthError::Truncated)
        ));
    }

    #[test]
    fn parse_rejects_qinq_double_tag() {
        // Synthesize a Q-in-Q frame: outer TPID + inner TPID (rather
        // than inner EtherType). Reject as InvalidTag because the seed
        // doesn't speak 802.1ad.
        let mut buf = [0u8; 24];
        EthImpl::build_frame_vlan(DST, SRC, 0x0001, 0x8100, b"x", &mut buf).unwrap();
        let r = EthImpl::parse_frame(&buf[..19]);
        assert!(matches!(r, Err(EthError::InvalidTag)));
    }

    #[test]
    fn is_broadcast_detects_all_ones() {
        assert!(is_broadcast(&proteus_contracts::ETH_BROADCAST_MAC));
        assert!(is_broadcast(&[0xFF; 6]));
        assert!(!is_broadcast(&DST));
        assert!(!is_broadcast(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE]));
    }

    #[test]
    fn multicast_unicast_classification() {
        // Multicast (group bit set in first byte).
        let multicast: MacAddr = [0x01, 0x00, 0x5E, 0x00, 0x00, 0x01]; // IPv4 multicast
        let ipv6_multi: MacAddr = [0x33, 0x33, 0x00, 0x00, 0x00, 0x01]; // IPv6 multicast
        let bcast = proteus_contracts::ETH_BROADCAST_MAC;
        // Unicast.
        let unicast: MacAddr = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

        assert!(is_multicast(&multicast));
        assert!(is_multicast(&ipv6_multi));
        assert!(is_multicast(&bcast)); // broadcast is a multicast
        assert!(!is_multicast(&unicast));

        assert!(is_unicast(&unicast));
        assert!(!is_unicast(&multicast));
        assert!(!is_unicast(&bcast));
    }

    #[test]
    fn wrapping_ipv4_datagram_in_eth_round_trips() {
        // Sanity for the kernel banner: build a frame whose payload is
        // the locked NET fixture-sized array, parse it back, recover
        // the payload byte-for-byte.
        let mut udp_like = [0u8; 38]; // matches kernel_fixtures::NET_EXPECTED_LEN
        for i in 0..udp_like.len() {
            udp_like[i] = (i as u8).wrapping_mul(7).wrapping_add(0x1B);
        }
        let mut buf = [0u8; 64];
        let n =
            EthImpl::build_frame(DST, SRC, ether_type::IPV4, &udp_like, &mut buf).unwrap();
        assert_eq!(n, ETH_HEADER_LEN + 38);
        let view = EthImpl::parse_frame(&buf[..n]).unwrap();
        assert_eq!(view.ether_type, ether_type::IPV4);
        assert_eq!(view.payload, &udp_like);
    }
}
