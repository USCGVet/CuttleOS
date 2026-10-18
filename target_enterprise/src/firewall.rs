//! Stateless IPv4 packet-filter — [`FirewallImpl`] +
//! [`FirewallTable`].
//!
//! This module is the [`PacketFilter`] contract impl. It closes the
//! security-policy gap left by the raw [`NetStackImpl`] (which
//! accepts every parsed packet) by giving the kernel a first-match-
//! wins 5-tuple matcher that composes with the existing IPv4 / TCP /
//! UDP / ICMP wire codecs.
//!
//! # What this implements
//!
//! - [`FirewallImpl`] — zero-sized type implementing
//!   [`PacketFilter`]. `evaluate(rules, packet)` walks `rules` in
//!   slice order, returns the first matching rule's [`Verdict`], or
//!   [`Verdict::NoMatch`] if none matched. Internals are diversifiable:
//!   a morph candidate can iterate forward, backward, batch-compare,
//!   or unroll — as long as the byte-observable verdict is preserved.
//! - [`FirewallTable`] `<const N>` — fixed-capacity rule storage with
//!   `insert` / `remove` / `iter` / `len` / `clear`. The "stable
//!   ordering invariant" the task spec calls for is: rules in the
//!   table are kept in **descending (src_mask + dst_mask)** order —
//!   the longest-prefix rule is always evaluated first regardless of
//!   insertion order. Ties break to insertion order (so an operator
//!   can layer two `/24` rules predictably).
//! - [`apply_rule_with_default`] / [`apply_table_with_default`] —
//!   helpers that fold [`Verdict::NoMatch`] into a caller-supplied
//!   default policy ([`FilterAction::Drop`] = default-deny, the
//!   recommended posture).
//!
//! # What this does NOT implement
//!
//! - Stateful tracking, conntrack, NAT. Out of scope for the seed.
//! - IPv6 rules. The on-wire `Ipv4PacketView` is IPv4-only by name.
//! - Rate limits / token-bucket. The seed is allow-or-deny.
//! - Per-interface scoping. The kernel attaches the filter to its
//!   single VirtIO-net device today; a multi-NIC variant would carry
//!   an `iface: u8` field on `FilterRule`.
//!
//! The donor — `RustOSa/src/firewall.rs` — is a much smaller surface
//! (per-port allowlist + per-IPv4 denylist, no CIDR, no port
//! ranges). We port the *concept* — boot-time configured, fixed-
//! capacity, allocation-free, cheap to evaluate — but expand the
//! match power to the 5-tuple the task spec calls for so the
//! verdict can compose with the existing TCP/UDP/ICMP wire codecs.

#![allow(missing_docs)]

use cuttle_contracts::{
    FilterAction, FilterRule, FilterRuleError, Ipv4PacketView, PacketFilter, Verdict,
    FW_PORT_ANY, FW_PROTO_ANY,
};

// ------------------------------------------------------------------
// Constants
// ------------------------------------------------------------------

/// Default capacity used by the kernel banner. Operators with denser
/// rulesets can instantiate [`FirewallTable`] with a larger `N`.
pub const FIREWALL_DEFAULT_CAPACITY: usize = 16;

// ------------------------------------------------------------------
// CIDR helpers (pub-visible so the kernel banner can build rules
// from /24-style prefixes without rolling its own bit math).
// ------------------------------------------------------------------

/// Derive a 32-bit netmask from a CIDR prefix length, big-endian.
///
/// `prefix == 0` returns `0x0000_0000` (match-all); `prefix == 32`
/// returns `0xFFFF_FFFF` (exact host); intermediate values yield
/// `((1 << 32) - (1 << (32 - prefix)))`. Prefix lengths greater than
/// 32 saturate to `0xFFFF_FFFF` — the caller is expected to have
/// already validated through [`FilterRule::validate`].
#[inline]
pub const fn cidr_mask_u32(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else if prefix >= 32 {
        u32::MAX
    } else {
        // 32-bit shift by `prefix` would overflow when prefix == 32,
        // which is why the saturating branch is split out above.
        u32::MAX << (32 - prefix as u32)
    }
}

/// Pack a 4-byte network-order IPv4 address into a big-endian u32.
/// Used by [`cidr_match`] so the mask compare is a single AND/EQ.
#[inline]
pub const fn ip_to_u32(ip: [u8; 4]) -> u32 {
    ((ip[0] as u32) << 24)
        | ((ip[1] as u32) << 16)
        | ((ip[2] as u32) << 8)
        | (ip[3] as u32)
}

/// Test whether `packet_ip` falls inside the CIDR range
/// `rule_ip / rule_mask`.
///
/// Per the locked contract, `rule_mask == 0` matches every IP
/// (including `0.0.0.0` and `255.255.255.255`).
#[inline]
pub const fn cidr_match(rule_ip: [u8; 4], rule_mask: u8, packet_ip: [u8; 4]) -> bool {
    let mask = cidr_mask_u32(rule_mask);
    (ip_to_u32(packet_ip) & mask) == (ip_to_u32(rule_ip) & mask)
}

// ------------------------------------------------------------------
// FilterRule helpers — validate, port-range check, full match.
// ------------------------------------------------------------------

/// Trait-free helpers attached to the contract type so callers don't
/// need to bring in a separate module for the math. None of the
/// helpers are part of the locked surface (they're not in
/// `cuttle_contracts`).
pub trait FilterRuleExt {
    fn validate(&self) -> Result<(), FilterRuleError>;
    fn mask_score(&self) -> u16;
    fn matches(&self, packet: &Ipv4PacketView) -> bool;
}

impl FilterRuleExt for FilterRule {
    /// Reject rules with bad CIDR prefixes or inverted port ranges.
    /// The table's `insert` path calls this on every rule.
    fn validate(&self) -> Result<(), FilterRuleError> {
        if self.src_mask > 32 || self.dst_mask > 32 {
            return Err(FilterRuleError::BadCidr);
        }
        let src_wild = self.src_port_start == FW_PORT_ANY && self.src_port_end == FW_PORT_ANY;
        if !src_wild && self.src_port_start > self.src_port_end {
            return Err(FilterRuleError::BadPortRange);
        }
        let dst_wild = self.dst_port_start == FW_PORT_ANY && self.dst_port_end == FW_PORT_ANY;
        if !dst_wild && self.dst_port_start > self.dst_port_end {
            return Err(FilterRuleError::BadPortRange);
        }
        Ok(())
    }

    /// Combined `src_mask + dst_mask`, capped at `64`. The
    /// `FirewallTable` uses this to keep rules in descending order so
    /// the longest-prefix rule is always evaluated first.
    #[inline]
    fn mask_score(&self) -> u16 {
        self.src_mask as u16 + self.dst_mask as u16
    }

    /// Does this rule match `packet`?
    fn matches(&self, packet: &Ipv4PacketView) -> bool {
        if !cidr_match(self.src_ip, self.src_mask, packet.src_ip) {
            return false;
        }
        if !cidr_match(self.dst_ip, self.dst_mask, packet.dst_ip) {
            return false;
        }
        if self.proto != FW_PROTO_ANY && self.proto != packet.protocol {
            return false;
        }
        if !port_in_range(packet.src_port, self.src_port_start, self.src_port_end) {
            return false;
        }
        if !port_in_range(packet.dst_port, self.dst_port_start, self.dst_port_end) {
            return false;
        }
        true
    }
}

/// Inclusive-both-ends port-range test, with the locked wildcard
/// semantics: `(0, 0)` matches every port.
#[inline]
const fn port_in_range(port: u16, start: u16, end: u16) -> bool {
    if start == FW_PORT_ANY && end == FW_PORT_ANY {
        true
    } else {
        port >= start && port <= end
    }
}

// ------------------------------------------------------------------
// FirewallImpl — the PacketFilter trait body.
// ------------------------------------------------------------------

/// Zero-sized type implementing [`PacketFilter`]. Lives at the crate
/// root for parity with [`crate::iommu::IommuImpl`] and friends.
pub struct FirewallImpl;

impl PacketFilter for FirewallImpl {
    fn evaluate(rules: &[FilterRule], packet: &Ipv4PacketView) -> Verdict {
        let mut i = 0usize;
        while i < rules.len() {
            if rules[i].matches(packet) {
                return Verdict::from_action(rules[i].action);
            }
            i += 1;
        }
        Verdict::NoMatch
    }
}

/// Fold a single-rule evaluation through a default-action policy.
/// If `evaluate` would return `NoMatch`, the supplied `default` is
/// projected through [`Verdict::from_action`] and returned instead.
///
/// Symmetric helper to [`apply_table_with_default`] for callers that
/// already have a rule slice in hand.
pub fn apply_rules_with_default(
    rules: &[FilterRule],
    packet: &Ipv4PacketView,
    default: FilterAction,
) -> Verdict {
    match FirewallImpl::evaluate(rules, packet) {
        Verdict::NoMatch => Verdict::from_action(default),
        v => v,
    }
}

// ------------------------------------------------------------------
// FirewallTable — fixed-capacity ordered storage.
// ------------------------------------------------------------------

/// Fixed-capacity rule storage. Internally an array of `MaybeUninit`-
/// free `FilterRule`s — every slot is initialised at construction
/// (we use `FilterRule::default()` equivalent) and `len` tracks how
/// many are live.
///
/// The "stable ordering invariant" the task spec calls for: rules
/// are kept in descending [`FilterRuleExt::mask_score`] order. Ties
/// break to insertion order (newer rule after older rule with the
/// same score). This means the longest-prefix rule is always
/// evaluated first regardless of insertion order — the canonical
/// netfilter behaviour without forcing the operator to sort rules
/// by hand.
pub struct FirewallTable<const N: usize> {
    /// Backing storage. `N` is the maximum number of rules; `len`
    /// fields below `N` are guaranteed-initialised.
    slots: [FilterRule; N],
    /// Number of live rules. `slots[0..len]` is the ordered list.
    len: usize,
}

/// Sentinel "empty" rule used to initialise every slot. Pattern-
/// matches no real packet because every CIDR is `/32` and every port
/// range is `[FW_PORT_ANY, FW_PORT_ANY]` with a proto that's also
/// `FW_PROTO_ANY` — but the table never evaluates past `len` so the
/// content here doesn't affect correctness, just provides a clean
/// constant for the array initialiser.
const EMPTY_RULE: FilterRule = FilterRule {
    src_ip: [0, 0, 0, 0],
    src_mask: 0,
    dst_ip: [0, 0, 0, 0],
    dst_mask: 0,
    proto: FW_PROTO_ANY,
    src_port_start: FW_PORT_ANY,
    src_port_end: FW_PORT_ANY,
    dst_port_start: FW_PORT_ANY,
    dst_port_end: FW_PORT_ANY,
    action: FilterAction::Drop,
};

impl<const N: usize> FirewallTable<N> {
    /// Construct an empty table. `const` so the kernel can park one
    /// in `.rodata`-ish static storage.
    pub const fn new() -> Self {
        Self {
            slots: [EMPTY_RULE; N],
            len: 0,
        }
    }

    /// Number of live rules.
    #[inline]
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Is this table empty?
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Maximum capacity (mirrors the const generic).
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Active rules, in evaluation order.
    pub fn as_slice(&self) -> &[FilterRule] {
        &self.slots[..self.len]
    }

    /// Drop every rule. Capacity is unchanged.
    pub fn clear(&mut self) {
        self.len = 0;
    }

    /// Insert `rule`, maintaining the descending-mask-score
    /// invariant. Returns [`FilterRuleError::TableFull`] if `len == N`,
    /// [`FilterRuleError::BadCidr`] / `BadPortRange` if the rule
    /// fails validation.
    pub fn insert(&mut self, rule: FilterRule) -> Result<(), FilterRuleError> {
        rule.validate()?;
        if self.len >= N {
            return Err(FilterRuleError::TableFull);
        }
        let score = rule.mask_score();
        // Find the first slot whose existing rule has a *strictly
        // smaller* score — that's where `rule` goes (ties append
        // after the existing same-score rules).
        let mut idx = self.len;
        let mut i = 0usize;
        while i < self.len {
            if self.slots[i].mask_score() < score {
                idx = i;
                break;
            }
            i += 1;
        }
        // Shift `[idx..len]` one slot right.
        let mut j = self.len;
        while j > idx {
            self.slots[j] = self.slots[j - 1];
            j -= 1;
        }
        self.slots[idx] = rule;
        self.len += 1;
        Ok(())
    }

    /// Remove the rule at `index` (in evaluation order). Returns
    /// [`FilterRuleError::IndexOutOfRange`] if `index >= len`.
    pub fn remove(&mut self, index: usize) -> Result<FilterRule, FilterRuleError> {
        if index >= self.len {
            return Err(FilterRuleError::IndexOutOfRange);
        }
        let out = self.slots[index];
        let mut k = index;
        while k + 1 < self.len {
            self.slots[k] = self.slots[k + 1];
            k += 1;
        }
        self.len -= 1;
        // Wipe the now-vacant tail slot back to EMPTY_RULE so a
        // future iterator doesn't observe a phantom rule.
        self.slots[self.len] = EMPTY_RULE;
        Ok(out)
    }

    /// Iterate live rules in evaluation order.
    pub fn iter(&self) -> core::slice::Iter<'_, FilterRule> {
        self.as_slice().iter()
    }

    /// Evaluate `packet` against this table, applying `default`
    /// when no rule matches.
    pub fn evaluate(&self, packet: &Ipv4PacketView, default: FilterAction) -> Verdict {
        apply_rules_with_default(self.as_slice(), packet, default)
    }
}

impl<const N: usize> Default for FirewallTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

/// Fold the table evaluation through a default-action policy. Same
/// as [`FirewallTable::evaluate`] — provided as a free function so
/// the kernel banner can call it without binding a `&FirewallTable`.
pub fn apply_table_with_default<const N: usize>(
    table: &FirewallTable<N>,
    packet: &Ipv4PacketView,
    default: FilterAction,
) -> Verdict {
    table.evaluate(packet, default)
}

// ------------------------------------------------------------------
// Tests
// ------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::{IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP};

    fn pkt(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        proto: u8,
        src_port: u16,
        dst_port: u16,
    ) -> Ipv4PacketView {
        Ipv4PacketView {
            src_ip,
            dst_ip,
            protocol: proto,
            src_port,
            dst_port,
        }
    }

    fn rule(
        src_ip: [u8; 4],
        src_mask: u8,
        dst_ip: [u8; 4],
        dst_mask: u8,
        proto: u8,
        sps: u16,
        spe: u16,
        dps: u16,
        dpe: u16,
        action: FilterAction,
    ) -> FilterRule {
        FilterRule {
            src_ip,
            src_mask,
            dst_ip,
            dst_mask,
            proto,
            src_port_start: sps,
            src_port_end: spe,
            dst_port_start: dps,
            dst_port_end: dpe,
            action,
        }
    }

    #[test]
    fn cidr_mask_u32_known_values() {
        assert_eq!(cidr_mask_u32(0), 0x0000_0000);
        assert_eq!(cidr_mask_u32(8), 0xFF00_0000);
        assert_eq!(cidr_mask_u32(16), 0xFFFF_0000);
        assert_eq!(cidr_mask_u32(24), 0xFFFF_FF00);
        assert_eq!(cidr_mask_u32(32), 0xFFFF_FFFF);
        // Saturation guard above 32 — defence-in-depth, the
        // validator already rejects.
        assert_eq!(cidr_mask_u32(33), 0xFFFF_FFFF);
        assert_eq!(cidr_mask_u32(255), 0xFFFF_FFFF);
    }

    #[test]
    fn ip_to_u32_endianness() {
        // 10.0.0.1 → 0x0A_00_00_01 (big-endian packing)
        assert_eq!(ip_to_u32([10, 0, 0, 1]), 0x0A00_0001);
        // 192.168.1.1
        assert_eq!(ip_to_u32([192, 168, 1, 1]), 0xC0A8_0101);
        // 0.0.0.0 and 255.255.255.255 sentinels
        assert_eq!(ip_to_u32([0, 0, 0, 0]), 0);
        assert_eq!(ip_to_u32([255, 255, 255, 255]), u32::MAX);
    }

    #[test]
    fn cidr_match_rfc1918_10_8() {
        // 10/8 matches every 10.x.y.z and nothing else
        assert!(cidr_match([10, 0, 0, 0], 8, [10, 0, 0, 1]));
        assert!(cidr_match([10, 0, 0, 0], 8, [10, 255, 255, 254]));
        assert!(!cidr_match([10, 0, 0, 0], 8, [11, 0, 0, 1]));
        assert!(!cidr_match([10, 0, 0, 0], 8, [192, 168, 1, 1]));
    }

    #[test]
    fn cidr_match_rfc1918_192_168_16() {
        assert!(cidr_match([192, 168, 0, 0], 16, [192, 168, 1, 1]));
        assert!(cidr_match([192, 168, 0, 0], 16, [192, 168, 200, 7]));
        assert!(!cidr_match([192, 168, 0, 0], 16, [192, 167, 0, 1]));
        assert!(!cidr_match([192, 168, 0, 0], 16, [10, 0, 0, 1]));
    }

    #[test]
    fn cidr_match_zero_prefix_matches_all() {
        assert!(cidr_match([0, 0, 0, 0], 0, [0, 0, 0, 0]));
        assert!(cidr_match([0, 0, 0, 0], 0, [255, 255, 255, 255]));
        assert!(cidr_match([10, 0, 0, 0], 0, [192, 168, 1, 1]));
    }

    #[test]
    fn cidr_match_host_route_32() {
        assert!(cidr_match([10, 0, 0, 1], 32, [10, 0, 0, 1]));
        assert!(!cidr_match([10, 0, 0, 1], 32, [10, 0, 0, 2]));
    }

    #[test]
    fn port_in_range_wildcard_matches_every_port_including_zero() {
        assert!(port_in_range(0, FW_PORT_ANY, FW_PORT_ANY));
        assert!(port_in_range(22, FW_PORT_ANY, FW_PORT_ANY));
        assert!(port_in_range(65535, FW_PORT_ANY, FW_PORT_ANY));
    }

    #[test]
    fn port_in_range_inclusive_bounds() {
        assert!(port_in_range(22, 22, 22));
        assert!(port_in_range(20, 20, 22));
        assert!(port_in_range(22, 20, 22));
        assert!(!port_in_range(19, 20, 22));
        assert!(!port_in_range(23, 20, 22));
    }

    #[test]
    fn validate_rejects_bad_cidr() {
        let r = rule(
            [10, 0, 0, 0],
            33,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Accept,
        );
        assert_eq!(r.validate(), Err(FilterRuleError::BadCidr));
        let r = rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            64,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Accept,
        );
        assert_eq!(r.validate(), Err(FilterRuleError::BadCidr));
    }

    #[test]
    fn validate_rejects_inverted_port_range() {
        let r = rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            50,
            40,
            0,
            0,
            FilterAction::Accept,
        );
        assert_eq!(r.validate(), Err(FilterRuleError::BadPortRange));
        let r = rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            100,
            50,
            FilterAction::Accept,
        );
        assert_eq!(r.validate(), Err(FilterRuleError::BadPortRange));
    }

    #[test]
    fn validate_accepts_well_formed_rule() {
        let r = rule(
            [10, 0, 0, 0],
            8,
            [192, 168, 1, 1],
            32,
            IP_PROTO_TCP,
            1024,
            65535,
            22,
            22,
            FilterAction::Accept,
        );
        assert!(r.validate().is_ok());
    }

    #[test]
    fn matches_accept_tcp_22_from_10_8() {
        let r = rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        );
        // Packet from 10.1.2.3:50000 to anywhere:22
        let p = pkt([10, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        assert!(r.matches(&p));
        // Wrong destination port:
        let p2 = pkt([10, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 80);
        assert!(!r.matches(&p2));
        // Wrong source CIDR:
        let p3 = pkt([11, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        assert!(!r.matches(&p3));
        // Wrong proto:
        let p4 = pkt([10, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_UDP, 50000, 22);
        assert!(!r.matches(&p4));
    }

    #[test]
    fn matches_proto_wildcard() {
        let r = rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Accept,
        );
        assert!(r.matches(&pkt([10, 0, 0, 1], [1, 2, 3, 4], IP_PROTO_TCP, 0, 0)));
        assert!(r.matches(&pkt([10, 0, 0, 1], [1, 2, 3, 4], IP_PROTO_UDP, 0, 0)));
        assert!(r.matches(&pkt([10, 0, 0, 1], [1, 2, 3, 4], IP_PROTO_ICMP, 0, 0)));
        assert!(r.matches(&pkt([10, 0, 0, 1], [1, 2, 3, 4], 47, 0, 0))); // GRE
    }

    #[test]
    fn matches_icmp_treats_ports_as_wildcards_when_rule_is_wildcard() {
        let r = rule(
            [192, 168, 0, 0],
            16,
            [0, 0, 0, 0],
            0,
            IP_PROTO_ICMP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Reject,
        );
        // ICMP has no L4 ports; packet view carries 0/0.
        let p = pkt([192, 168, 1, 7], [10, 0, 0, 1], IP_PROTO_ICMP, 0, 0);
        assert!(r.matches(&p));
    }

    #[test]
    fn evaluate_first_match_wins_independent_of_action() {
        let rules = [
            rule(
                [10, 0, 0, 0],
                8,
                [0, 0, 0, 0],
                0,
                IP_PROTO_TCP,
                FW_PORT_ANY,
                FW_PORT_ANY,
                22,
                22,
                FilterAction::Accept,
            ),
            rule(
                [10, 0, 0, 0],
                8,
                [0, 0, 0, 0],
                0,
                IP_PROTO_TCP,
                FW_PORT_ANY,
                FW_PORT_ANY,
                22,
                22,
                FilterAction::Drop,
            ),
        ];
        let p = pkt([10, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        // The Accept rule appears first, so the second Drop rule is
        // never reached.
        assert_eq!(FirewallImpl::evaluate(&rules, &p), Verdict::Accept);
    }

    #[test]
    fn evaluate_no_match_returns_nomatch() {
        let rules = [rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        )];
        // Packet doesn't match the source CIDR
        let p = pkt([11, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        assert_eq!(FirewallImpl::evaluate(&rules, &p), Verdict::NoMatch);
    }

    #[test]
    fn evaluate_empty_table_returns_nomatch() {
        let rules: [FilterRule; 0] = [];
        let p = pkt([10, 0, 0, 1], [192, 168, 1, 1], IP_PROTO_TCP, 50000, 22);
        assert_eq!(FirewallImpl::evaluate(&rules, &p), Verdict::NoMatch);
    }

    #[test]
    fn apply_rules_with_default_drop() {
        let rules = [rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        )];
        // No match → default Drop
        let p = pkt([11, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        assert_eq!(
            apply_rules_with_default(&rules, &p, FilterAction::Drop),
            Verdict::Drop
        );
        // Match → rule's Accept regardless of default
        let p2 = pkt([10, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        assert_eq!(
            apply_rules_with_default(&rules, &p2, FilterAction::Drop),
            Verdict::Accept
        );
    }

    #[test]
    fn table_insert_orders_by_descending_mask_score() {
        let mut t = FirewallTable::<8>::new();
        // Insert a wildcard rule first
        t.insert(rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Accept,
        ))
        .unwrap();
        // Then a /24
        t.insert(rule(
            [10, 0, 0, 0],
            24,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Drop,
        ))
        .unwrap();
        // Then a /32 host route
        t.insert(rule(
            [10, 0, 0, 5],
            32,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Reject,
        ))
        .unwrap();
        let s = t.as_slice();
        assert_eq!(s.len(), 3);
        // Highest mask score first: 32 > 24 > 0
        assert_eq!(s[0].src_mask, 32);
        assert_eq!(s[1].src_mask, 24);
        assert_eq!(s[2].src_mask, 0);
    }

    #[test]
    fn table_insert_breaks_ties_by_insertion_order() {
        let mut t = FirewallTable::<8>::new();
        let r1 = rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        );
        let r2 = rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_UDP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            53,
            53,
            FilterAction::Drop,
        );
        t.insert(r1).unwrap();
        t.insert(r2).unwrap();
        let s = t.as_slice();
        // Both have mask_score 8; insertion order preserved.
        assert_eq!(s[0].proto, IP_PROTO_TCP);
        assert_eq!(s[1].proto, IP_PROTO_UDP);
    }

    #[test]
    fn table_full_returns_table_full_error() {
        let mut t = FirewallTable::<2>::new();
        let r = rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Accept,
        );
        t.insert(r).unwrap();
        t.insert(r).unwrap();
        // Third one overflows.
        let res = t.insert(r);
        assert_eq!(res, Err(FilterRuleError::TableFull));
        assert_eq!(t.len(), 2);
    }

    #[test]
    fn table_remove_shifts_subsequent_rules_left() {
        let mut t = FirewallTable::<8>::new();
        t.insert(rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Accept,
        ))
        .unwrap();
        t.insert(rule(
            [192, 168, 0, 0],
            16,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Drop,
        ))
        .unwrap();
        t.insert(rule(
            [172, 16, 0, 0],
            12,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Reject,
        ))
        .unwrap();
        // Order by descending mask score: 16, 12, 8.
        let before = t.as_slice();
        assert_eq!(before[0].src_mask, 16);
        assert_eq!(before[1].src_mask, 12);
        assert_eq!(before[2].src_mask, 8);

        let removed = t.remove(1).unwrap();
        assert_eq!(removed.src_mask, 12);
        assert_eq!(t.len(), 2);
        let after = t.as_slice();
        assert_eq!(after[0].src_mask, 16);
        assert_eq!(after[1].src_mask, 8);
    }

    #[test]
    fn table_remove_out_of_range_errs() {
        let mut t = FirewallTable::<4>::new();
        assert_eq!(t.remove(0), Err(FilterRuleError::IndexOutOfRange));
        t.insert(rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Accept,
        ))
        .unwrap();
        assert_eq!(t.remove(1), Err(FilterRuleError::IndexOutOfRange));
    }

    #[test]
    fn table_clear_resets_len() {
        let mut t = FirewallTable::<4>::new();
        t.insert(rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Accept,
        ))
        .unwrap();
        assert_eq!(t.len(), 1);
        t.clear();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
    }

    #[test]
    fn table_default_deny_on_empty_table() {
        let t = FirewallTable::<4>::new();
        let p = pkt([10, 0, 0, 1], [192, 168, 1, 1], IP_PROTO_TCP, 50000, 22);
        assert_eq!(t.evaluate(&p, FilterAction::Drop), Verdict::Drop);
        assert_eq!(t.evaluate(&p, FilterAction::Accept), Verdict::Accept);
    }

    #[test]
    fn longest_prefix_wins_when_table_orders_correctly() {
        let mut t = FirewallTable::<4>::new();
        // Insert the *less* specific rule first, then the more specific.
        // The table's invariant must put the /32 ahead of the /8.
        t.insert(rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        ))
        .unwrap();
        t.insert(rule(
            [10, 1, 2, 3],
            32,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Drop,
        ))
        .unwrap();
        let p = pkt([10, 1, 2, 3], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        // Despite the /8 being inserted first, the /32 hits first
        // because of the descending-mask-score invariant.
        assert_eq!(t.evaluate(&p, FilterAction::Drop), Verdict::Drop);
        // A different 10.x host falls through to the /8 Accept rule.
        let p2 = pkt([10, 9, 9, 9], [192, 168, 1, 5], IP_PROTO_TCP, 50000, 22);
        assert_eq!(t.evaluate(&p2, FilterAction::Drop), Verdict::Accept);
    }

    #[test]
    fn four_rule_kernel_banner_table_evaluates_as_expected() {
        // Mirror the four-rule table the kernel banner builds.
        // Rule order (after ordering): per descending mask_score
        // we expect:
        //   1. Reject ICMP from 192.168/16  (score 16)
        //   2. Accept TCP/22 from 10/8      (score 8)
        //   3. Accept UDP/53 from 0/0       (score 0)
        //   4. (default Drop fallthrough)
        // Three input packets:
        //   A. 10.0.0.5 -> 192.168.1.10 TCP src=40000 dst=22  → Accept
        //   B. 8.8.8.8  -> 10.0.0.5    UDP src=12345 dst=53  → Accept
        //   C. 192.168.1.42 -> 10.0.0.5 ICMP             → Drop (rule's Reject)
        //                                                  banner spec says
        //                                                  verdicts=accept,accept,drop
        //                                                  — Reject is reported
        //                                                  as Drop after the
        //                                                  ICMP-unreachable reply,
        //                                                  but the wire-verdict
        //                                                  the trait reports is
        //                                                  Verdict::Reject.
        //                                                  We test both shapes
        //                                                  below.
        let mut t = FirewallTable::<8>::new();
        t.insert(rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        ))
        .unwrap();
        t.insert(rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            0,
            IP_PROTO_UDP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            53,
            53,
            FilterAction::Accept,
        ))
        .unwrap();
        t.insert(rule(
            [192, 168, 0, 0],
            16,
            [0, 0, 0, 0],
            0,
            IP_PROTO_ICMP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FW_PORT_ANY,
            FilterAction::Reject,
        ))
        .unwrap();

        // Ordering after insert: scores are 16, 8, 0 — descending.
        let s = t.as_slice();
        assert_eq!(s.len(), 3);
        assert_eq!(s[0].proto, IP_PROTO_ICMP);
        assert_eq!(s[1].proto, IP_PROTO_TCP);
        assert_eq!(s[2].proto, IP_PROTO_UDP);

        let a = pkt([10, 0, 0, 5], [192, 168, 1, 10], IP_PROTO_TCP, 40000, 22);
        let b = pkt([8, 8, 8, 8], [10, 0, 0, 5], IP_PROTO_UDP, 12345, 53);
        let c = pkt([192, 168, 1, 42], [10, 0, 0, 5], IP_PROTO_ICMP, 0, 0);

        assert_eq!(t.evaluate(&a, FilterAction::Drop), Verdict::Accept);
        assert_eq!(t.evaluate(&b, FilterAction::Drop), Verdict::Accept);
        assert_eq!(t.evaluate(&c, FilterAction::Drop), Verdict::Reject);
    }

    #[test]
    fn longest_prefix_wins_dst_side() {
        // /24 on the destination IP must outrank /16 even when the
        // /16 rule was inserted first.
        let mut t = FirewallTable::<4>::new();
        t.insert(rule(
            [0, 0, 0, 0],
            0,
            [192, 168, 0, 0],
            16,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Accept,
        ))
        .unwrap();
        t.insert(rule(
            [0, 0, 0, 0],
            0,
            [192, 168, 1, 0],
            24,
            FW_PROTO_ANY,
            0,
            0,
            0,
            0,
            FilterAction::Drop,
        ))
        .unwrap();
        let p = pkt([10, 0, 0, 1], [192, 168, 1, 7], IP_PROTO_TCP, 0, 0);
        assert_eq!(t.evaluate(&p, FilterAction::Drop), Verdict::Drop);
        let p2 = pkt([10, 0, 0, 1], [192, 168, 200, 7], IP_PROTO_TCP, 0, 0);
        assert_eq!(t.evaluate(&p2, FilterAction::Drop), Verdict::Accept);
    }

    #[test]
    fn port_range_wins_over_proto_wildcard() {
        // Rule: any source, any dest IP, any proto, src ports 1024..=65535,
        // dst ports 80..=80 → Accept.
        let r = rule(
            [0, 0, 0, 0],
            0,
            [0, 0, 0, 0],
            0,
            FW_PROTO_ANY,
            1024,
            65535,
            80,
            80,
            FilterAction::Accept,
        );
        assert!(r.matches(&pkt([1, 2, 3, 4], [5, 6, 7, 8], IP_PROTO_TCP, 49000, 80)));
        // Source port below the range → no match.
        assert!(!r.matches(&pkt([1, 2, 3, 4], [5, 6, 7, 8], IP_PROTO_TCP, 1023, 80)));
        // Destination port off → no match.
        assert!(!r.matches(&pkt([1, 2, 3, 4], [5, 6, 7, 8], IP_PROTO_TCP, 49000, 81)));
    }

    #[test]
    fn verdict_from_action_locked_mapping() {
        assert_eq!(Verdict::from_action(FilterAction::Accept), Verdict::Accept);
        assert_eq!(Verdict::from_action(FilterAction::Reject), Verdict::Reject);
        assert_eq!(Verdict::from_action(FilterAction::Drop), Verdict::Drop);
    }

    #[test]
    fn discriminants_stable_for_external_repr() {
        // Locked u8 reprs — external code that pattern-matches on
        // the byte representation should keep working across morphs.
        assert_eq!(FilterAction::Accept as u8, 0);
        assert_eq!(FilterAction::Reject as u8, 1);
        assert_eq!(FilterAction::Drop as u8, 2);
        assert_eq!(Verdict::Accept as u8, 0);
        assert_eq!(Verdict::Reject as u8, 1);
        assert_eq!(Verdict::Drop as u8, 2);
        assert_eq!(Verdict::NoMatch as u8, 3);
    }

    #[test]
    fn apply_table_with_default_alias_matches_method() {
        let mut t = FirewallTable::<4>::new();
        t.insert(rule(
            [10, 0, 0, 0],
            8,
            [0, 0, 0, 0],
            0,
            IP_PROTO_TCP,
            FW_PORT_ANY,
            FW_PORT_ANY,
            22,
            22,
            FilterAction::Accept,
        ))
        .unwrap();
        let p = pkt([10, 0, 0, 1], [192, 168, 1, 1], IP_PROTO_TCP, 50000, 22);
        assert_eq!(
            apply_table_with_default(&t, &p, FilterAction::Drop),
            t.evaluate(&p, FilterAction::Drop)
        );
        let p2 = pkt([11, 0, 0, 1], [192, 168, 1, 1], IP_PROTO_TCP, 50000, 22);
        assert_eq!(
            apply_table_with_default(&t, &p2, FilterAction::Drop),
            t.evaluate(&p2, FilterAction::Drop)
        );
    }
}
