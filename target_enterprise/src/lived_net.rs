//! Lived guest network service — ARP + ICMP echo + UDP status + HTTP/TCP.
//!
//! Pure `no_std` packet demux. The kernel virtio (or any other) poll
//! loop feeds Ethernet frames in and transmits the reply frames out.
//! This is the OS's actual job, not a banner: a host can `GET /status`
//! over TCP/80, `STATUS?` over UDP/8080, or ping (ICMP echo).
//!
//! Locked wire codecs (`TcpImpl`, `HttpImpl`, `IcmpImpl`, UDP/IPv4)
//! do the encoding. This module is the glue that binds them into one
//! connection-oriented service with a single TCB.

#![allow(clippy::needless_range_loop)]

use alloc::boxed::Box;
use alloc::sync::Arc;

use cuttle_contracts::{
    icmp_type, tcp_flags, AuditVerdict, Http, HttpMethod, Icmp, Ipv4PacketView, PacketFilter,
    Tcp, Verdict, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
};
use rustls::server::ServerConfig;

use crate::firewall::FirewallImpl;
use crate::http::HttpImpl;
use crate::icmp::IcmpImpl;
use crate::net::ipv4_header_checksum;
use crate::tcp::{close, process_segment, send_payload, Tcb, TcpImpl, TcpState};
use crate::https::TlsSession;
use crate::tls::hmac_sha256;

/// Guest IPv4 the service claims (QEMU slirp default guest).
pub const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// UDP status port (existing hostfwd).
pub const UDP_STATUS_PORT: u16 = 8080;
/// In-guest Peer-to-Peer Triad replication & 2-of-3 TMR quorum UDP port.
pub const TRIAD_REPL_PORT: u16 = 8081;
/// HTTP status port.
pub const HTTP_PORT: u16 = 80;
/// HTTPS / TLS 1.3 port.
pub const HTTPS_PORT: u16 = 443;
/// Maximum number of concurrent TCP connections tracked in [`LivedNet`].
pub const TCP_MAX_SLOTS: usize = 16;
/// Ethernet II header length.
pub const ETH_HEADER_LEN: usize = 14;
/// IPv4 header length (no options).
pub const IPV4_HEADER_LEN: usize = 20;
/// IPv6 fixed header length (`40` bytes, RFC 8200).
pub const IPV6_HEADER_LEN: usize = 40;
/// Ethernet II EtherType for IPv6 (`0x86DD`).
pub const ETHERTYPE_IPV6: u16 = 0x86DD;
/// IPv6 Next Header protocol number for ICMPv6 (`58`, RFC 4443).
pub const IP_PROTO_ICMPV6: u8 = 58;
/// Deterministic Unique Local IPv6 Address (`fd00::10:2:0:15`) claimed alongside link-local EUI-64.
pub const GUEST_IPV6_ULA: [u8; 16] = [
    0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0x10, 0, 0x02, 0, 0, 0, 0x15,
];
/// Maximum Ethernet payload + header we emit (untagged, no FCS).
pub const MAX_FRAME: usize = 1514;
/// Max replies produced from one inbound frame (`8` frames for multi-segment sliding-window bursts).
pub const MAX_REPLIES: usize = 8;
/// Maximum HTTP request size (headers + body) accepted on port 80 or 443
/// before returning `413 Content Too Large`.
pub const MAX_HTTP_REQUEST_BYTES: usize = 8 * 1024;
/// Maximum unread HTTP input bytes buffered per port-80 TCP slot so pipelined
/// requests that are individually `<= MAX_HTTP_REQUEST_BYTES` can queue without
/// being wiped while outbound segments drain.
pub const MAX_HTTP_BUFFER_BYTES: usize = 64 * 1024;
/// Maximum aggregate buffered HTTP/TLS bytes across all 16 [`TCP_MAX_SLOTS`]
/// connection slots (`512 KiB`), bounding total network buffer memory well
/// inside the 8 MiB kernel heap even when all 16 slots are active concurrently.
pub const MAX_TOTAL_BUFFERED_BYTES: usize = 512 * 1024;
/// Maximum aggregate buffered HTTP/TLS bytes permitted for any single remote
/// IPv4 peer (`256 KiB`, half of [`MAX_TOTAL_BUFFERED_BYTES`]), preventing one
/// client IP from exhausting the entire 512 KiB buffer budget across slots.
pub const MAX_PEER_BUFFERED_BYTES: usize = 256 * 1024;
/// High-water mark on a [`TlsSession`]'s outbound ciphertext queue (`pending_tx`)
/// above which `handle_https_slot` pauses draining new decrypted HTTP requests.
pub const HTTPS_TX_HIGH_WATER: usize = 16 * 1024;
/// Default calibrated Local APIC timer interrupt rate (`250 Hz`, matching
/// [`crate::timer::calibrate_apic_irqs_per_sec`] default).
pub const DEFAULT_TIMER_HZ: u32 = 250;
/// Retransmission Timeout (RTO) interval in milliseconds (`1,000 ms` = 1 s)
/// for half-open (`SynReceived`) and closing (`LastAck`) TCP slots.
pub const TCP_RTO_RETRANSMIT_MS: u32 = 1_000;
/// Half-open (`SynReceived`) and closing (`LastAck`) slot reclamation timeout
/// in milliseconds (`2,000 ms` = 2 s).
pub const TCP_HALF_OPEN_RECLAIM_MS: u32 = 2_000;
/// Idle connection reclamation timeout in milliseconds (`16,384 ms` = ~16.4 s).
pub const HTTPS_IDLE_TIMEOUT_MS: u32 = 16_384;
/// Idle tick threshold at [`DEFAULT_TIMER_HZ`] (`250 Hz` -> `4,096` ticks).
pub const HTTPS_IDLE_TIMEOUT_TICKS: u32 =
    ms_to_timer_ticks(HTTPS_IDLE_TIMEOUT_MS, DEFAULT_TIMER_HZ as u64);

/// Convert a timeout in milliseconds (`ms`) to Local APIC timer interrupt ticks
/// using the hardware-calibrated interrupt rate (`irqs_per_sec` from
/// [`crate::timer::calibrate_apic_irqs_per_sec`]).
#[inline]
pub const fn ms_to_timer_ticks(ms: u32, irqs_per_sec: u64) -> u32 {
    let hz = if irqs_per_sec < 16 {
        16
    } else if irqs_per_sec > 4096 {
        4096
    } else {
        irqs_per_sec
    };
    let ticks = ((ms as u64) * hz + 999) / 1000;
    if ticks < 1 {
        1
    } else if ticks > (u32::MAX as u64) {
        u32::MAX
    } else {
        ticks as u32
    }
}
/// Largest TCP payload emitted per segment.
pub const TCP_SEGMENT_PAYLOAD: usize = 1380;
/// Initial RFC 3390 / RFC 5681 TCP congestion window (`4 * SMSS = 5,520` bytes).
pub const TCP_INIT_CWND: u32 = (4 * TCP_SEGMENT_PAYLOAD) as u32;
/// Initial TCP slow-start threshold (`65,535` bytes).
pub const TCP_INIT_SSTHRESH: u32 = 65_535;
/// Deterministic 256-bit HMAC-SHA256 fixture key used only by in-memory unit
/// tests (`LivedNet::new`). Limited to `#[cfg(test)]` so production and kernel
/// code can never fall back to a public constant.
#[cfg(test)]
pub const DEFAULT_NET_AUTH_KEY: [u8; 32] = *b"Cuttle-Enterprise-NetAuth-Key001";

/// Outgoing Ethernet frames produced by [`LivedNet::handle_frame`].
///
/// Uses lazily allocated `Box<[u8; MAX_FRAME]>` frame slots so `ReplySet` itself
/// occupies only `136` bytes on the kernel stack while reusing warm slab buffers
/// across frames via [`ReplySet::clear`].
pub struct ReplySet {
    frames: [Option<Box<[u8; MAX_FRAME]>>; MAX_REPLIES],
    lens: [usize; MAX_REPLIES],
    count: u8,
}

impl ReplySet {
    /// Empty set (zero heap allocations until a frame is pushed).
    pub const fn new() -> Self {
        Self {
            frames: [const { None }; MAX_REPLIES],
            lens: [0; MAX_REPLIES],
            count: 0,
        }
    }

    /// Reset queued frame count to zero while retaining any already-allocated
    /// `MAX_FRAME` backing buffers for zero-allocation steady-state reuse.
    pub fn clear(&mut self) {
        self.count = 0;
        self.lens = [0; MAX_REPLIES];
    }

    /// Number of frames queued.
    pub fn len(&self) -> usize {
        self.count as usize
    }

    /// True if no frames queued.
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Frame bytes at `i`, if present.
    pub fn get(&self, i: usize) -> Option<&[u8]> {
        if i < self.count as usize {
            self.frames[i]
                .as_ref()
                .map(|buf| &buf[..self.lens[i]])
        } else {
            None
        }
    }

    fn push(&mut self, frame: &[u8]) -> bool {
        if self.count as usize >= MAX_REPLIES || frame.len() > MAX_FRAME || frame.is_empty() {
            return false;
        }
        let i = self.count as usize;
        let slot = self.frames[i].get_or_insert_with(|| Box::new([0u8; MAX_FRAME]));
        slot[..frame.len()].copy_from_slice(frame);
        self.lens[i] = frame.len();
        self.count += 1;
        true
    }
}

/// Maximum out-of-order TCP segments buffered per connection slot for WAN gap reassembly.
pub const OOO_SLOTS_PER_CONN: usize = 8;
/// Maximum forward sequence gap (`32 KiB`) accepted for out-of-order TCP reassembly.
pub const OOO_MAX_GAP_BYTES: u32 = 32_768;
/// Maximum unacknowledged server payload bytes (`36 KiB`) retained per slot for retransmission.
pub const MAX_TX_INFLIGHT_PER_SLOT: usize = 36_864;

struct OooSegment {
    present: bool,
    seq: u32,
    fin: bool,
    data: alloc::vec::Vec<u8>,
}

impl OooSegment {
    const fn empty() -> Self {
        Self {
            present: false,
            seq: 0,
            fin: false,
            data: alloc::vec::Vec::new(),
        }
    }
}

/// Multi-connection guest network service supporting ARP, ICMP echo,
/// authenticated UDP control plane (`8080`), Peer-to-Peer Triad replication (`8081`),
/// HTTP/1.1 (`80`), and HTTPS (`443`, TLS 1.3 via rustls once
/// [`enable_tls`](LivedNet::enable_tls) is called) across a 16-slot
/// concurrent TCP table.
pub struct LivedNet {
    /// Guest MAC (copied into Ethernet source).
    pub mac: [u8; 6],
    /// Guest IPv4.
    pub ip: [u8; 4],
    /// Shared 256-bit HMAC-SHA256 key for authenticated UDP control-plane commands.
    pub auth_key: [u8; 32],
    /// Whether an out-of-band device secret was provisioned; when `false`, all
    /// `AUTH` commands are refused unconditionally.
    pub auth_enabled: bool,
    /// Highest accepted monotonic sequence number for anti-replay protection on UDP `AUTH`.
    pub last_auth_seq: u64,
    /// Highest accepted monotonic sequence number for anti-replay protection on HTTP `/session/login`.
    pub last_http_login_seq: u64,
    /// Highest accepted monotonic sequence number for network-native HTTP/HTTPS `POST /triad/rpc`.
    pub last_triad_rpc_seq: u64,
    /// Minimum accepted Triad coordinator fencing epoch (`R6`) on `TRIAD_PREPARE` and `/triad/rpc`.
    pub triad_min_epoch: u64,
    /// Total authenticated `POST /triad/rpc` commands accepted across HTTP/HTTPS.
    pub triad_rpcs_accepted: u64,
    /// TLS connections started on port 443 since boot.
    pub tls_sessions_started: u64,
    /// Total TCP retransmission / half-open reclamation events triggered by RTO timers.
    pub rto_retransmits: u64,
    /// Total RFC 5681 3-duplicate-ACK fast retransmissions triggered before RTO expiry.
    pub fast_retransmits: u64,
    /// Total stateless HMAC-SHA256 SYN Cookie `SYN|ACK` challenges emitted under slot saturation.
    pub syn_cookies_sent: u64,
    /// Total stateless HMAC-SHA256 SYN Cookie handshakes verified and promoted to `Established`.
    pub syn_cookies_accepted: u64,
    /// Total out-of-order TCP segments coalesced into contiguous stream order.
    pub ooo_reassembled: u64,
    /// Total unacknowledged server TCP payload segments re-emitted on RTO timeout.
    pub payload_retransmits: u64,
    /// Total valid IPv6 ICMPv6 Echo Requests (`type 128`) answered with Echo Replies (`type 129`).
    pub ipv6_icmp_echos: u64,
    /// Total valid IPv6 Neighbor Solicitations (`type 135`) answered with Neighbor Advertisements (`type 136`).
    pub ipv6_ndp_replies: u64,
    syn_cookie_threshold: usize,
    active_http_peer_ip: [u8; 4],
    login_rl_ips: [[u8; 4]; 8],
    login_rl_streaks: [u8; 8],
    login_rl_cooldowns: [u16; 8],
    login_rl_backoffs: [u8; 8],
    tcbs: [Tcb; TCP_MAX_SLOTS],
    slot_cwnd: [u32; TCP_MAX_SLOTS],
    slot_ssthresh: [u32; TCP_MAX_SLOTS],
    slot_dup_acks: [u8; TCP_MAX_SLOTS],
    peak_cwnd: u32,
    slot_last_tick: [u32; TCP_MAX_SLOTS],
    slot_rto_ticks: [u32; TCP_MAX_SLOTS],
    slot_rto_shift: [u8; TCP_MAX_SLOTS],
    slot_remote_mac: [[u8; 6]; TCP_MAX_SLOTS],
    slot_conn_epoch: [u64; TCP_MAX_SLOTS],
    next_conn_epoch: u64,
    http_input_closed: [bool; TCP_MAX_SLOTS],
    ticks: u32,
    timer_hz: u32,
    ip_ident: u16,
    http_bufs: [alloc::vec::Vec<u8>; TCP_MAX_SLOTS],
    http_tx: [alloc::vec::Vec<u8>; TCP_MAX_SLOTS],
    tx_inflight_seq: [u32; TCP_MAX_SLOTS],
    tx_inflight_buf: [alloc::vec::Vec<u8>; TCP_MAX_SLOTS],
    ooo_segs: [[OooSegment; OOO_SLOTS_PER_CONN]; TCP_MAX_SLOTS],
    slot_tls_buffered: [usize; TCP_MAX_SLOTS],
    peak_tls_pending_tx: usize,
    heap_headroom_fn: Option<fn(usize) -> bool>,
    tls_config: Option<Arc<ServerConfig>>,
    tls: [Option<Box<TlsSession>>; TCP_MAX_SLOTS],
}

impl LivedNet {
    /// Minimum Ring-0 heap headroom (`64 KiB` beyond emergency reserve) required before
    /// accepting and allocating a new TLS 1.3 handshake state on port 443.
    pub const TLS_SESSION_MIN_HEAP_HEADROOM: usize = 64 * 1024;

    /// Zero-initialized BSS constructor suitable for `static spin::Mutex<LivedNet>`.
    pub const fn empty() -> Self {
        Self {
            mac: [0u8; 6],
            ip: GUEST_IP,
            auth_key: [0u8; 32],
            auth_enabled: false,
            last_auth_seq: 0,
            last_http_login_seq: 0,
            last_triad_rpc_seq: 0,
            triad_min_epoch: 0,
            triad_rpcs_accepted: 0,
            tls_sessions_started: 0,
            rto_retransmits: 0,
            fast_retransmits: 0,
            syn_cookies_sent: 0,
            syn_cookies_accepted: 0,
            ooo_reassembled: 0,
            payload_retransmits: 0,
            ipv6_icmp_echos: 0,
            ipv6_ndp_replies: 0,
            syn_cookie_threshold: TCP_MAX_SLOTS,
            active_http_peer_ip: [0u8; 4],
            login_rl_ips: [[0u8; 4]; 8],
            login_rl_streaks: [0u8; 8],
            login_rl_cooldowns: [0u16; 8],
            login_rl_backoffs: [0u8; 8],
            tcbs: [Tcb::EMPTY; TCP_MAX_SLOTS],
            slot_cwnd: [TCP_INIT_CWND; TCP_MAX_SLOTS],
            slot_ssthresh: [TCP_INIT_SSTHRESH; TCP_MAX_SLOTS],
            slot_dup_acks: [0u8; TCP_MAX_SLOTS],
            peak_cwnd: TCP_INIT_CWND,
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            slot_rto_ticks: [0u32; TCP_MAX_SLOTS],
            slot_rto_shift: [0u8; TCP_MAX_SLOTS],
            slot_remote_mac: [[0u8; 6]; TCP_MAX_SLOTS],
            slot_conn_epoch: [0u64; TCP_MAX_SLOTS],
            next_conn_epoch: 1,
            http_input_closed: [false; TCP_MAX_SLOTS],
            ticks: 1,
            timer_hz: DEFAULT_TIMER_HZ,
            ip_ident: 1,
            http_bufs: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            http_tx: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            tx_inflight_seq: [0u32; TCP_MAX_SLOTS],
            tx_inflight_buf: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            ooo_segs: [const { [const { OooSegment::empty() }; OOO_SLOTS_PER_CONN] };
                TCP_MAX_SLOTS],
            slot_tls_buffered: [0usize; TCP_MAX_SLOTS],
            peak_tls_pending_tx: usize::MIN,
            heap_headroom_fn: None,
            tls_config: None,
            tls: [const { None }; TCP_MAX_SLOTS],
        }
    }

    /// Test-only constructor binding `mac` / `GUEST_IP` with [`DEFAULT_NET_AUTH_KEY`].
    #[cfg(test)]
    pub fn new(mac: [u8; 6]) -> Self {
        Self::with_auth_key(mac, DEFAULT_NET_AUTH_KEY)
    }

    /// Bind `mac` / `GUEST_IP` with an explicit per-device 256-bit `auth_key`.
    pub fn with_auth_key(mac: [u8; 6], auth_key: [u8; 32]) -> Self {
        Self {
            mac,
            ip: GUEST_IP,
            auth_key,
            auth_enabled: true,
            last_auth_seq: 0,
            last_http_login_seq: 0,
            last_triad_rpc_seq: 0,
            triad_min_epoch: 0,
            triad_rpcs_accepted: 0,
            tls_sessions_started: 0,
            rto_retransmits: 0,
            fast_retransmits: 0,
            syn_cookies_sent: 0,
            syn_cookies_accepted: 0,
            ooo_reassembled: 0,
            payload_retransmits: 0,
            ipv6_icmp_echos: 0,
            ipv6_ndp_replies: 0,
            syn_cookie_threshold: TCP_MAX_SLOTS,
            active_http_peer_ip: [0u8; 4],
            login_rl_ips: [[0u8; 4]; 8],
            login_rl_streaks: [0u8; 8],
            login_rl_cooldowns: [0u16; 8],
            login_rl_backoffs: [0u8; 8],
            tcbs: [Tcb::listen(GUEST_IP, HTTP_PORT, 65535); TCP_MAX_SLOTS],
            slot_cwnd: [TCP_INIT_CWND; TCP_MAX_SLOTS],
            slot_ssthresh: [TCP_INIT_SSTHRESH; TCP_MAX_SLOTS],
            slot_dup_acks: [0u8; TCP_MAX_SLOTS],
            peak_cwnd: TCP_INIT_CWND,
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            slot_rto_ticks: [0u32; TCP_MAX_SLOTS],
            slot_rto_shift: [0u8; TCP_MAX_SLOTS],
            slot_remote_mac: [[0u8; 6]; TCP_MAX_SLOTS],
            slot_conn_epoch: [0u64; TCP_MAX_SLOTS],
            next_conn_epoch: 1,
            http_input_closed: [false; TCP_MAX_SLOTS],
            ticks: 1,
            timer_hz: DEFAULT_TIMER_HZ,
            ip_ident: 1,
            http_bufs: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            http_tx: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            tx_inflight_seq: [0u32; TCP_MAX_SLOTS],
            tx_inflight_buf: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            ooo_segs: [const { [const { OooSegment::empty() }; OOO_SLOTS_PER_CONN] };
                TCP_MAX_SLOTS],
            slot_tls_buffered: [0usize; TCP_MAX_SLOTS],
            peak_tls_pending_tx: 0,
            heap_headroom_fn: None,
            tls_config: None,
            tls: [const { None }; TCP_MAX_SLOTS],
        }
    }

    /// Bind `mac` / `GUEST_IP` when no out-of-band device secret key was
    /// provisioned (`auth_enabled = false`), refusing all `AUTH` commands.
    pub fn new_unprovisioned(mac: [u8; 6]) -> Self {
        Self {
            mac,
            ip: GUEST_IP,
            auth_key: [0u8; 32],
            auth_enabled: false,
            last_auth_seq: 0,
            last_http_login_seq: 0,
            last_triad_rpc_seq: 0,
            triad_min_epoch: 0,
            triad_rpcs_accepted: 0,
            tls_sessions_started: 0,
            rto_retransmits: 0,
            fast_retransmits: 0,
            syn_cookies_sent: 0,
            syn_cookies_accepted: 0,
            ooo_reassembled: 0,
            payload_retransmits: 0,
            ipv6_icmp_echos: 0,
            ipv6_ndp_replies: 0,
            syn_cookie_threshold: TCP_MAX_SLOTS,
            active_http_peer_ip: [0u8; 4],
            login_rl_ips: [[0u8; 4]; 8],
            login_rl_streaks: [0u8; 8],
            login_rl_cooldowns: [0u16; 8],
            login_rl_backoffs: [0u8; 8],
            tcbs: [Tcb::listen(GUEST_IP, HTTP_PORT, 65535); TCP_MAX_SLOTS],
            slot_cwnd: [TCP_INIT_CWND; TCP_MAX_SLOTS],
            slot_ssthresh: [TCP_INIT_SSTHRESH; TCP_MAX_SLOTS],
            slot_dup_acks: [0u8; TCP_MAX_SLOTS],
            peak_cwnd: TCP_INIT_CWND,
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            slot_rto_ticks: [0u32; TCP_MAX_SLOTS],
            slot_rto_shift: [0u8; TCP_MAX_SLOTS],
            slot_remote_mac: [[0u8; 6]; TCP_MAX_SLOTS],
            slot_conn_epoch: [0u64; TCP_MAX_SLOTS],
            next_conn_epoch: 1,
            http_input_closed: [false; TCP_MAX_SLOTS],
            ticks: 1,
            timer_hz: DEFAULT_TIMER_HZ,
            ip_ident: 1,
            http_bufs: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            http_tx: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            tx_inflight_seq: [0u32; TCP_MAX_SLOTS],
            tx_inflight_buf: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            ooo_segs: [const { [const { OooSegment::empty() }; OOO_SLOTS_PER_CONN] };
                TCP_MAX_SLOTS],
            slot_tls_buffered: [0usize; TCP_MAX_SLOTS],
            peak_tls_pending_tx: 0,
            heap_headroom_fn: None,
            tls_config: None,
            tls: [const { None }; TCP_MAX_SLOTS],
        }
    }

    fn is_peer_login_rate_limited(&self, peer_ip: [u8; 4]) -> bool {
        let mut i = 0usize;
        while i < 8 {
            if self.login_rl_ips[i] == peer_ip && self.login_rl_cooldowns[i] > 0 {
                return true;
            }
            i += 1;
        }
        false
    }

    fn record_peer_login_failure(&mut self, peer_ip: [u8; 4]) {
        let mut slot: Option<usize> = None;
        let mut free_slot: Option<usize> = None;
        let mut quiet_slot: Option<usize> = None;
        let mut i = 0usize;
        while i < 8 {
            if self.login_rl_ips[i] == peer_ip {
                slot = Some(i);
                break;
            }
            if free_slot.is_none() && self.login_rl_ips[i] == [0, 0, 0, 0] {
                free_slot = Some(i);
            }
            if quiet_slot.is_none() && self.login_rl_cooldowns[i] == 0 {
                quiet_slot = Some(i);
            }
            i += 1;
        }
        let idx = slot.or(free_slot).or(quiet_slot).unwrap_or(0);
        if self.login_rl_ips[idx] != peer_ip {
            self.login_rl_ips[idx] = peer_ip;
            self.login_rl_streaks[idx] = 0;
            self.login_rl_cooldowns[idx] = 0;
            self.login_rl_backoffs[idx] = 0;
        }
        self.login_rl_streaks[idx] = self.login_rl_streaks[idx].saturating_add(1);
        if self.login_rl_streaks[idx] >= 5 {
            self.login_rl_streaks[idx] = 0;
            let shift = self.login_rl_backoffs[idx].min(4);
            self.login_rl_cooldowns[idx] = 8u16 << shift;
            self.login_rl_backoffs[idx] = self.login_rl_backoffs[idx].saturating_add(1).min(4);
        }
    }

    fn reset_peer_login_streak(&mut self, peer_ip: [u8; 4]) {
        let mut i = 0usize;
        while i < 8 {
            if self.login_rl_ips[i] == peer_ip {
                self.login_rl_streaks[i] = 0;
                self.login_rl_backoffs[i] = 0;
                break;
            }
            i += 1;
        }
    }

    /// Return the high-water mark of `TlsSession::pending_tx().len()` observed
    /// across `handle_https_slot` runs.
    pub fn peak_tls_pending_tx(&self) -> usize {
        self.peak_tls_pending_tx
    }

    /// Configure the hardware-calibrated Local APIC timer interrupt frequency
    /// (`irqs_per_sec` from [`crate::timer::calibrate_apic_irqs_per_sec`]) used
    /// to convert [`TCP_RTO_RETRANSMIT_MS`], [`TCP_HALF_OPEN_RECLAIM_MS`], and
    /// [`HTTPS_IDLE_TIMEOUT_MS`] into timer ticks.
    pub fn set_timer_hz(&mut self, irqs_per_sec: u64) {
        self.timer_hz = irqs_per_sec.clamp(16, 4096) as u32;
    }

    /// Return the configured Local APIC timer interrupt frequency in Hz.
    pub fn timer_hz(&self) -> u32 {
        self.timer_hz
    }

    /// Return the calibrated RTO retransmit interval (`1,000 ms`) in timer ticks.
    pub fn rto_retransmit_ticks(&self) -> u32 {
        ms_to_timer_ticks(TCP_RTO_RETRANSMIT_MS, self.timer_hz as u64)
    }

    /// Return the calibrated half-open (`SynReceived`) / `LastAck` slot
    /// reclamation timeout (`2,000 ms`) in timer ticks.
    pub fn half_open_reclaim_ticks(&self) -> u32 {
        ms_to_timer_ticks(TCP_HALF_OPEN_RECLAIM_MS, self.timer_hz as u64)
    }

    /// Return the calibrated idle connection reclamation timeout (`16,384 ms`)
    /// in timer ticks.
    pub fn idle_timeout_ticks(&self) -> u32 {
        ms_to_timer_ticks(HTTPS_IDLE_TIMEOUT_MS, self.timer_hz as u64)
    }

    /// Return the number of currently active (non-`Closed`, non-`Listen`) TCP connection slots.
    pub fn active_tcp_slots(&self) -> usize {
        let mut count = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            let st = self.tcbs[i].state;
            if st != TcpState::Closed && st != TcpState::Listen {
                count += 1;
            }
            i += 1;
        }
        count
    }

    /// Configure the active-slot threshold at or above which incoming `SYN` frames switch to
    /// zero-state HMAC-SHA256 SYN Cookies (`0..=TCP_MAX_SLOTS`, default `TCP_MAX_SLOTS`).
    pub fn set_syn_cookie_threshold(&mut self, threshold: usize) {
        self.syn_cookie_threshold = threshold.min(TCP_MAX_SLOTS);
    }

    /// Return total unacknowledged server payload bytes retained for RTO retransmission.
    pub fn total_inflight_tx_bytes(&self) -> usize {
        let mut total = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            total = total.saturating_add(self.tx_inflight_buf[i].len());
            i += 1;
        }
        total
    }

    fn slot_ooo_bytes(&self, idx: usize) -> usize {
        let mut n = 0usize;
        let mut k = 0usize;
        while k < OOO_SLOTS_PER_CONN {
            if self.ooo_segs[idx][k].present {
                n = n.saturating_add(self.ooo_segs[idx][k].data.len());
            }
            k += 1;
        }
        n
    }

    /// Return total unread input and queued output bytes buffered across all
    /// [`TCP_MAX_SLOTS`] HTTP and HTTPS connection slots.
    pub fn total_buffered_bytes(&self) -> usize {
        let mut total = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            total = total
                .saturating_add(self.http_bufs[i].len())
                .saturating_add(self.http_tx[i].len())
                .saturating_add(self.slot_ooo_bytes(i))
                .saturating_add(self.slot_tls_buffered[i]);
            i += 1;
        }
        total
    }

    /// Return total unread input and queued output bytes buffered across all
    /// connection slots belonging to `peer_ip`.
    pub fn peer_buffered_bytes(&self, peer_ip: [u8; 4]) -> usize {
        let mut total = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            let st = self.tcbs[i].state;
            if st != TcpState::Closed
                && st != TcpState::Listen
                && self.tcbs[i].remote_ip == peer_ip
            {
                total = total
                    .saturating_add(self.http_bufs[i].len())
                    .saturating_add(self.http_tx[i].len())
                    .saturating_add(self.slot_ooo_bytes(i))
                    .saturating_add(self.slot_tls_buffered[i]);
            }
            i += 1;
        }
        total
    }

    /// Return total heap capacity (`Vec::capacity`) held by HTTP/HTTPS buffers
    /// across all [`TCP_MAX_SLOTS`] connection slots.
    pub fn total_buffered_capacity(&self) -> usize {
        let mut total = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            let mut ooo_cap = 0usize;
            let mut k = 0usize;
            while k < OOO_SLOTS_PER_CONN {
                ooo_cap = ooo_cap.saturating_add(self.ooo_segs[i][k].data.capacity());
                k += 1;
            }
            total = total
                .saturating_add(self.http_bufs[i].capacity())
                .saturating_add(self.http_tx[i].capacity())
                .saturating_add(ooo_cap)
                .saturating_add(self.slot_tls_buffered[i]);
            i += 1;
        }
        total
    }

    fn release_slot_buffers(&mut self, idx: usize) {
        self.http_input_closed[idx] = false;
        self.slot_rto_shift[idx] = 0;
        self.tx_inflight_seq[idx] = 0;
        self.slot_cwnd[idx] = TCP_INIT_CWND;
        self.slot_ssthresh[idx] = TCP_INIT_SSTHRESH;
        self.slot_dup_acks[idx] = 0;
        crate::https::scrub_vec_all_bytes(&mut self.http_bufs[idx]);
        self.http_bufs[idx].shrink_to_fit();
        crate::https::scrub_vec_all_bytes(&mut self.http_tx[idx]);
        self.http_tx[idx].shrink_to_fit();
        crate::https::scrub_vec_all_bytes(&mut self.tx_inflight_buf[idx]);
        self.tx_inflight_buf[idx].shrink_to_fit();
        let mut k = 0usize;
        while k < OOO_SLOTS_PER_CONN {
            self.ooo_segs[idx][k].present = false;
            self.ooo_segs[idx][k].seq = 0;
            self.ooo_segs[idx][k].fin = false;
            crate::https::scrub_vec_all_bytes(&mut self.ooo_segs[idx][k].data);
            self.ooo_segs[idx][k].data.shrink_to_fit();
            k += 1;
        }
        self.slot_tls_buffered[idx] = 0;
        self.tls[idx] = None;
    }

    #[inline(never)]
    fn retransmit_inflight_chunk(&mut self, idx: usize, out: &mut ReplySet) -> bool {
        if self.tx_inflight_buf[idx].is_empty() || out.len() >= MAX_REPLIES {
            return false;
        }
        let tcb = self.tcbs[idx];
        if tcb.remote_ip == [0, 0, 0, 0] {
            return false;
        }
        let n = self.tx_inflight_buf[idx].len().min(TCP_SEGMENT_PAYLOAD);
        let mut chunk = [0u8; TCP_SEGMENT_PAYLOAD];
        chunk[..n].copy_from_slice(&self.tx_inflight_buf[idx][..n]);
        let dst_mac = self.slot_remote_mac[idx];
        let reply_ip = nat_reply_ip(tcb.remote_ip);
        let before = out.len();
        self.emit_tcp(
            tcb.local_port,
            tcb.remote_port,
            dst_mac,
            reply_ip,
            self.tx_inflight_seq[idx],
            tcb.rcv_nxt,
            tcp_flags::PSH | tcp_flags::ACK,
            tcb.rcv_wnd,
            &chunk[..n],
            out,
        );
        out.len() > before
    }

    /// Advance per-slot TCP Retransmission Timeout (RTO) timers by one calibrated
    /// Local APIC timer interrupt (`vector 0x40`), reclaiming stale half-open
    /// (`SynReceived`) or closing (`FinWait1`, `FinWait2`, `LastAck`) slots after
    /// [`TCP_HALF_OPEN_RECLAIM_MS`] (`2,000 ms`) and idle `Established` / `CloseWait`
    /// slots after [`HTTPS_IDLE_TIMEOUT_MS`] (`16,384 ms`).
    pub fn tick_tcp_rto(&mut self) -> usize {
        let mut discard = ReplySet::new();
        self.tick_tcp_rto_with_replies(&mut discard)
    }

    /// Advance per-slot TCP RTO timers by one calibrated Local APIC timer interrupt,
    /// retransmit unacknowledged server TCP payloads with RFC 6298 exponential backoff,
    /// and emit a `RST | ACK` segment into `out` whenever an idle `Established` or
    /// `CloseWait` connection slot is reclaimed.
    pub fn tick_tcp_rto_with_replies(&mut self, out: &mut ReplySet) -> usize {
        self.ticks = self.ticks.wrapping_add(1);
        let rto_ticks = self.rto_retransmit_ticks();
        let reclaim_ticks = self.half_open_reclaim_ticks();
        let idle_ticks = self.idle_timeout_ticks();
        let mut rli = 0usize;
        while rli < 8 {
            if self.login_rl_cooldowns[rli] > 0 {
                self.login_rl_cooldowns[rli] -= 1;
            }
            rli += 1;
        }
        let mut actions = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            let st = self.tcbs[i].state;
            if st == TcpState::SynReceived
                || st == TcpState::FinWait1
                || st == TcpState::FinWait2
                || st == TcpState::LastAck
            {
                let elapsed = self.ticks.wrapping_sub(self.slot_rto_ticks[i]);
                if elapsed >= rto_ticks {
                    self.rto_retransmits = self.rto_retransmits.wrapping_add(1);
                    actions += 1;
                    if self.ticks.wrapping_sub(self.slot_last_tick[i]) >= reclaim_ticks {
                        self.tcbs[i] = Tcb::EMPTY;
                        self.slot_remote_mac[i] = [0u8; 6];
                        self.release_slot_buffers(i);
                    } else {
                        if (st == TcpState::FinWait1 || st == TcpState::LastAck)
                            && self.retransmit_inflight_chunk(i, out)
                        {
                            self.payload_retransmits = self.payload_retransmits.wrapping_add(1);
                            self.slot_rto_shift[i] = (self.slot_rto_shift[i] + 1).min(4);
                        }
                        self.slot_rto_ticks[i] = self.ticks;
                    }
                }
            } else if st == TcpState::Established || st == TcpState::CloseWait {
                if self.ticks.wrapping_sub(self.slot_last_tick[i]) >= idle_ticks {
                    let tcb = self.tcbs[i];
                    if tcb.remote_ip != [0, 0, 0, 0] && out.len() < MAX_REPLIES {
                        let dst_mac = self.slot_remote_mac[i];
                        let reply_ip = nat_reply_ip(tcb.remote_ip);
                        self.emit_tcp(
                            tcb.local_port,
                            tcb.remote_port,
                            dst_mac,
                            reply_ip,
                            tcb.snd_nxt,
                            tcb.rcv_nxt,
                            tcp_flags::RST | tcp_flags::ACK,
                            0,
                            b"",
                            out,
                        );
                    }
                    self.tcbs[i] = Tcb::EMPTY;
                    self.slot_remote_mac[i] = [0u8; 6];
                    self.release_slot_buffers(i);
                    actions += 1;
                } else if !self.tx_inflight_buf[i].is_empty() {
                    let backoff_rto = rto_ticks << (self.slot_rto_shift[i].min(4) as u32);
                    if self.ticks.wrapping_sub(self.slot_rto_ticks[i]) >= backoff_rto {
                        let flight = self.tcbs[i].snd_nxt.wrapping_sub(self.tcbs[i].snd_una);
                        let mss = TCP_SEGMENT_PAYLOAD as u32;
                        self.slot_ssthresh[i] = (flight / 2).max(2 * mss);
                        self.slot_cwnd[i] = mss;
                        self.slot_dup_acks[i] = 0;
                        if self.retransmit_inflight_chunk(i, out) {
                            self.payload_retransmits = self.payload_retransmits.wrapping_add(1);
                        }
                        self.rto_retransmits = self.rto_retransmits.wrapping_add(1);
                        self.slot_rto_ticks[i] = self.ticks;
                        self.slot_rto_shift[i] = (self.slot_rto_shift[i] + 1).min(4);
                        actions += 1;
                    }
                }
            }
            i += 1;
        }
        actions
    }

    /// Serve HTTPS on port 443 with `config` (see [`crate::https::server_config`]).
    /// Until this is called, connections to 443 are not accepted.
    pub fn enable_tls(&mut self, config: Arc<ServerConfig>) {
        self.tls_config = Some(config);
    }

    /// Install a kernel heap headroom callback invoked before allocating new TLS 1.3
    /// session state so connection floods fail closed instead of panicking Ring-0 on OOM.
    pub fn set_heap_headroom_guard(&mut self, guard: fn(usize) -> bool) {
        self.heap_headroom_fn = Some(guard);
    }

    /// True once [`enable_tls`](Self::enable_tls) has been called.
    pub fn tls_enabled(&self) -> bool {
        self.tls_config.is_some()
    }

    /// Derive a unique per-device 256-bit `HMAC-SHA256` control-plane key from a fleet/factory
    /// root secret and the device's hardware MAC address (`HMAC-SHA256(root_secret, "cuttle-net-auth-v1:" || mac)`).
    pub fn derive_node_key(root_secret: &[u8; 32], mac: [u8; 6]) -> [u8; 32] {
        const LABEL: &[u8] = b"cuttle-net-auth-v1:";
        let mut msg = [0u8; 25];
        msg[..19].copy_from_slice(LABEL);
        msg[19..25].copy_from_slice(&mac);
        let mut out = [0u8; 32];
        hmac_sha256(root_secret, &msg, &mut out);
        out
    }

    /// Compute the 32-byte HMAC-SHA256 tag over `"<seq_ascii>:<cmd>"` for `AUTH` datagrams.
    pub fn compute_auth_tag(
        key: &[u8; 32],
        seq_ascii: &[u8],
        cmd: &[u8],
        out: &mut [u8; 32],
    ) {
        crate::tls::hmac_sha256_parts(key, &[seq_ascii, b":", cmd], out);
    }

    /// Compute the domain-separated 32-byte HMAC-SHA256 tag over
    /// `"cuttle-http-login-v1:<seq_ascii>:<user>"` for `POST /session/login`.
    pub fn compute_http_login_tag(
        key: &[u8; 32],
        seq_ascii: &[u8],
        user: &[u8],
        out: &mut [u8; 32],
    ) {
        crate::tls::hmac_sha256_parts(
            key,
            &[b"cuttle-http-login-v1:", seq_ascii, b":", user],
            out,
        );
    }

    /// Compute the 32-byte HMAC-SHA256 tag over `"cuttle-triad-prep-v1:<seq>:<node_id>:<sql>"`
    /// for in-guest Peer-to-Peer Triad replication (`TRIAD_PREPARE`) datagrams on UDP `:8081`.
    pub fn compute_triad_prepare_tag(
        key: &[u8; 32],
        seq_ascii: &[u8],
        node_ascii: &[u8],
        sql: &[u8],
        out: &mut [u8; 32],
    ) {
        crate::tls::hmac_sha256_parts(
            key,
            &[b"cuttle-triad-prep-v1:", seq_ascii, b":", node_ascii, b":", sql],
            out,
        );
    }

    /// Compute the 32-byte HMAC-SHA256 tag over `"cuttle-triad-prep-v2:<epoch>:<seq>:<node_id>:<sql>"`
    /// for epoch-fenced (`R6`) Triad replication (`TRIAD_PREPARE epoch=<epoch> <seq> <node_id> <hmac> <sql>`)
    /// datagrams on UDP `:8081`.
    pub fn compute_triad_prepare_tag_with_epoch(
        key: &[u8; 32],
        epoch_ascii: &[u8],
        seq_ascii: &[u8],
        node_ascii: &[u8],
        sql: &[u8],
        out: &mut [u8; 32],
    ) {
        crate::tls::hmac_sha256_parts(
            key,
            &[
                b"cuttle-triad-prep-v2:",
                epoch_ascii,
                b":",
                seq_ascii,
                b":",
                node_ascii,
                b":",
                sql,
            ],
            out,
        );
    }

    /// Compute the 32-byte HMAC-SHA256 tag over `"cuttle-triad-ack-v1:<seq>:<peer_id>:<hash_hex16>"`
    /// for in-guest Peer-to-Peer Triad quorum acknowledgment (`TRIAD_ACK`) datagrams on UDP `:8081`.
    pub fn compute_triad_ack_tag(
        key: &[u8; 32],
        seq_ascii: &[u8],
        peer_ascii: &[u8],
        hash_hex16: &[u8],
        out: &mut [u8; 32],
    ) {
        crate::tls::hmac_sha256_parts(
            key,
            &[b"cuttle-triad-ack-v1:", seq_ascii, b":", peer_ascii, b":", hash_hex16],
            out,
        );
    }

    /// Compute the domain-separated 32-byte HMAC-SHA256 tag over
    /// `"cuttle-triad-rpc-v1:<epoch>:<seq>:<cmd>"` for network-native `POST /triad/rpc`.
    pub fn compute_triad_rpc_tag(
        key: &[u8; 32],
        epoch_ascii: &[u8],
        seq_ascii: &[u8],
        cmd: &[u8],
        out: &mut [u8; 32],
    ) {
        crate::tls::hmac_sha256_parts(
            key,
            &[
                b"cuttle-triad-rpc-v1:",
                epoch_ascii,
                b":",
                seq_ascii,
                b":",
                cmd,
            ],
            out,
        );
    }

    /// Return the current RFC 5681 congestion window (`cwnd`, in bytes) of TCP slot `idx`.
    pub fn slot_cwnd(&self, idx: usize) -> u32 {
        self.slot_cwnd[idx]
    }

    /// Return the current RFC 5681 slow-start threshold (`ssthresh`, in bytes) of TCP slot `idx`.
    pub fn slot_ssthresh(&self, idx: usize) -> u32 {
        self.slot_ssthresh[idx]
    }

    /// Return the peak RFC 5681 congestion window (`cwnd`, in bytes) observed across all connections.
    pub fn max_observed_cwnd(&self) -> u32 {
        self.peak_cwnd
    }

    /// Derive the guest's RFC 4291 Modified EUI-64 IPv6 link-local address (`fe80::/64`)
    /// from its 48-bit Ethernet MAC address.
    pub fn ipv6_link_local(&self) -> [u8; 16] {
        [
            0xfe,
            0x80,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            0x00,
            self.mac[0] ^ 0x02,
            self.mac[1],
            self.mac[2],
            0xff,
            0xfe,
            self.mac[3],
            self.mac[4],
            self.mac[5],
        ]
    }

    /// Compute the RFC 8200 §8.1 16-bit one's-complement upper-layer checksum over the
    /// 40-byte IPv6 pseudo-header (`src`, `dst`, 32-bit upper-layer length, `next_header`)
    /// and `payload`.
    pub fn ipv6_upper_layer_checksum(
        src: &[u8; 16],
        dst: &[u8; 16],
        next_header: u8,
        payload: &[u8],
    ) -> u16 {
        let mut sum: u32 = 0;
        let mut i = 0usize;
        while i < 16 {
            sum += u16::from_be_bytes([src[i], src[i + 1]]) as u32;
            sum += u16::from_be_bytes([dst[i], dst[i + 1]]) as u32;
            i += 2;
        }
        let plen = payload.len() as u32;
        sum += plen >> 16;
        sum += plen & 0xFFFF;
        sum += next_header as u32;
        let mut p = 0usize;
        while p + 1 < payload.len() {
            sum += u16::from_be_bytes([payload[p], payload[p + 1]]) as u32;
            p += 2;
        }
        if p < payload.len() {
            sum += (payload[p] as u32) << 8;
        }
        while (sum >> 16) != 0 {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }

    /// Gratuitous ARP (broadcast who-has ourselves) so slirp/bridges
    /// learn the guest MAC. Emits one 42-byte frame.
    pub fn announce(&self, out: &mut ReplySet) {
        let mut garp = [0u8; 42];
        garp[..6].copy_from_slice(&[0xffu8; 6]);
        garp[6..12].copy_from_slice(&self.mac);
        garp[12] = 0x08;
        garp[13] = 0x06;
        garp[14] = 0;
        garp[15] = 1;
        garp[16] = 0x08;
        garp[17] = 0;
        garp[18] = 6;
        garp[19] = 4;
        garp[20] = 0;
        garp[21] = 1;
        garp[22..28].copy_from_slice(&self.mac);
        garp[28..32].copy_from_slice(&self.ip);
        garp[32..38].copy_from_slice(&[0u8; 6]);
        garp[38..42].copy_from_slice(&self.ip);
        out.push(&garp);
    }

    /// Process one Ethernet frame. `boots` is the continuity counter
    /// published in UDP/HTTP status bodies.
    pub fn handle_frame(&mut self, frame: &[u8], boots: u64, out: &mut ReplySet) {
        self.handle_frame_opt(frame, boots, None, out);
    }

    /// Process one Ethernet frame with live [`crate::shell::OsShell`] integration:
    /// - Enforces [`FirewallImpl`] CIDR rules before ICMP/UDP/TCP protocol demux.
    /// - UDP/8080 `CMD <line>` executes strictly read-only inspection commands in `shell`.
    /// - UDP/8080 `AUTH <seq> <hmac_hex64> <cmd>` verifies monotonic anti-replay `seq`
    ///   and constant-time HMAC-SHA256 before executing privileged/mutating commands.
    /// - TCP/80 `GET /ps`, `GET /ls`, `GET /audit`, `GET /uname`, `GET /ima`, `GET /fw` returns live kernel tables.
    pub fn handle_frame_with_shell(
        &mut self,
        frame: &[u8],
        boots: u64,
        shell: &mut crate::shell::OsShell,
        out: &mut ReplySet,
    ) {
        self.handle_frame_opt(frame, boots, Some(shell), out);
    }

    #[inline(never)]
    fn handle_frame_opt(
        &mut self,
        frame: &[u8],
        boots: u64,
        mut shell: Option<&mut crate::shell::OsShell>,
        out: &mut ReplySet,
    ) {
        self.ticks = self.ticks.wrapping_add(1);
        if frame.len() < ETH_HEADER_LEN {
            return;
        }
        let etype = u16::from_be_bytes([frame[12], frame[13]]);
        if etype == 0x0806 {
            self.handle_arp(frame, out);
            return;
        }
        if etype == ETHERTYPE_IPV6 {
            self.handle_ipv6(frame, shell, out);
            return;
        }
        if etype != 0x0800 {
            return;
        }
        if frame.len() < ETH_HEADER_LEN + IPV4_HEADER_LEN {
            return;
        }
        let ip = &frame[ETH_HEADER_LEN..];
        if ip[0] >> 4 != 4 {
            return;
        }
        let ihl = ((ip[0] & 0x0F) as usize) * 4;
        if ihl < IPV4_HEADER_LEN || ip.len() < ihl {
            return;
        }
        let total = u16::from_be_bytes([ip[2], ip[3]]) as usize;
        if total < ihl || ETH_HEADER_LEN + total > frame.len() {
            return;
        }
        // Enforce RFC 791 / RFC 1071 IPv4 wire invariants BEFORE L4 firewall evaluation:
        // reject TTL=0, fragmented packets (MF=0x2000 or non-zero fragment offset),
        // corrupt IPv4 header checksums, Martian source IPs, and zero/multicast sender MACs.
        if ip[8] == 0 {
            return;
        }
        let flags_frag = u16::from_be_bytes([ip[6], ip[7]]);
        if (flags_frag & 0x3FFF) != 0 {
            return;
        }
        if !ipv4_header_checksum_valid(&ip[..ihl]) {
            return;
        }
        let dst_ip = [ip[16], ip[17], ip[18], ip[19]];
        if dst_ip != self.ip {
            return;
        }
        let src_ip = [ip[12], ip[13], ip[14], ip[15]];
        if src_ip == [0, 0, 0, 0]
            || src_ip == [255, 255, 255, 255]
            || (src_ip[0] & 0xF0) == 0xE0
            || src_ip == self.ip
        {
            return;
        }
        let proto = ip[9];
        let payload = &ip[ihl..total];
        let sender_mac: [u8; 6] = match frame[6..12].try_into() {
            Ok(m) => m,
            Err(_) => return,
        };
        if sender_mac == [0u8; 6] || (sender_mac[0] & 0x01) != 0 {
            return;
        }

        // Wire-boundary 5-tuple stateless CIDR packet filter enforcement.
        if let Some(sh) = shell.as_deref_mut() {
            let (src_port, dst_port) =
                if (proto == IP_PROTO_UDP || proto == IP_PROTO_TCP) && payload.len() >= 4 {
                    (
                        u16::from_be_bytes([payload[0], payload[1]]),
                        u16::from_be_bytes([payload[2], payload[3]]),
                    )
                } else {
                    (0, 0)
                };
            let pkt_view = Ipv4PacketView {
                src_ip,
                dst_ip,
                protocol: proto,
                src_port,
                dst_port,
            };
            if matches!(
                FirewallImpl::evaluate(sh.fw.as_slice(), &pkt_view),
                Verdict::Drop | Verdict::Reject
            ) {
                sh.record_net_audit(AuditVerdict::Denied, b"net:fw:drop");
                return;
            }
        }

        let reply_ip = nat_reply_ip(src_ip);
        match proto {
            x if x == IP_PROTO_ICMP => self.handle_icmp(payload, sender_mac, src_ip, reply_ip, out),
            x if x == IP_PROTO_UDP => {
                self.handle_udp(payload, sender_mac, src_ip, reply_ip, boots, shell, out)
            }
            x if x == IP_PROTO_TCP => {
                self.handle_tcp(payload, sender_mac, src_ip, reply_ip, boots, shell, out)
            }
            _ => {}
        }
    }

    fn handle_arp(&self, frame: &[u8], out: &mut ReplySet) {
        if frame.len() < 42 {
            return;
        }
        let eth_src = &frame[6..12];
        if eth_src == [0u8; 6] || (eth_src[0] & 0x01) != 0 {
            return;
        }
        let arp = &frame[14..42];
        let htype = u16::from_be_bytes([arp[0], arp[1]]);
        let ptype = u16::from_be_bytes([arp[2], arp[3]]);
        if htype != 1 || ptype != 0x0800 || arp[4] != 6 || arp[5] != 4 {
            return;
        }
        let sha = &arp[8..14];
        if sha == [0u8; 6] || (sha[0] & 0x01) != 0 {
            return;
        }
        let op = u16::from_be_bytes([arp[6], arp[7]]);
        let tip = [arp[24], arp[25], arp[26], arp[27]];
        if op != 1 || tip != self.ip {
            return;
        }
        let mut reply = [0u8; 42];
        reply[..6].copy_from_slice(&frame[6..12]);
        reply[6..12].copy_from_slice(&self.mac);
        reply[12] = 0x08;
        reply[13] = 0x06;
        reply[14..16].copy_from_slice(&arp[0..2]);
        reply[16..18].copy_from_slice(&arp[2..4]);
        reply[18] = arp[4];
        reply[19] = arp[5];
        reply[20] = 0;
        reply[21] = 2;
        reply[22..28].copy_from_slice(&self.mac);
        reply[28..32].copy_from_slice(&self.ip);
        reply[32..38].copy_from_slice(&arp[8..14]);
        reply[38..42].copy_from_slice(&arp[14..18]);
        out.push(&reply);
    }

    fn handle_icmp(
        &mut self,
        icmp: &[u8],
        dst_mac: [u8; 6],
        _src_ip: [u8; 4],
        reply_ip: [u8; 4],
        out: &mut ReplySet,
    ) {
        let view = match IcmpImpl::parse_echo(icmp) {
            Ok(v) => v,
            Err(_) => return,
        };
        if view.icmp_type != icmp_type::ECHO_REQUEST {
            return;
        }
        let mut body = [0u8; 576];
        let n = match IcmpImpl::build_echo_reply(
            view.identifier,
            view.sequence_number,
            view.payload,
            &mut body,
        ) {
            Ok(n) => n,
            Err(_) => return,
        };
        self.emit_ipv4(dst_mac, reply_ip, IP_PROTO_ICMP, &body[..n], out);
    }

    #[inline(never)]
    fn handle_ipv6(
        &mut self,
        frame: &[u8],
        mut shell: Option<&mut crate::shell::OsShell>,
        out: &mut ReplySet,
    ) {
        if frame.len() < ETH_HEADER_LEN + IPV6_HEADER_LEN {
            return;
        }
        let sender_mac: [u8; 6] = match frame[6..12].try_into() {
            Ok(m) => m,
            Err(_) => return,
        };
        if sender_mac == [0u8; 6] || (sender_mac[0] & 0x01) != 0 {
            return;
        }
        let ip6 = &frame[ETH_HEADER_LEN..];
        if (ip6[0] >> 4) != 6 {
            return;
        }
        let payload_len = u16::from_be_bytes([ip6[4], ip6[5]]) as usize;
        if payload_len < 8 || ETH_HEADER_LEN + IPV6_HEADER_LEN + payload_len > frame.len() {
            return;
        }
        let next_hdr = ip6[6];
        let hop_limit = ip6[7];
        if hop_limit == 0 {
            return;
        }
        let mut src_v6 = [0u8; 16];
        src_v6.copy_from_slice(&ip6[8..24]);
        let mut dst_v6 = [0u8; 16];
        dst_v6.copy_from_slice(&ip6[24..40]);
        let ll = self.ipv6_link_local();
        let loopback_v6 = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        if src_v6[0] == 0xff
            || src_v6 == [0u8; 16]
            || src_v6 == loopback_v6
            || src_v6 == ll
            || src_v6 == GUEST_IPV6_ULA
        {
            return;
        }
        if let Some(sh) = shell.as_deref_mut() {
            if sh.guard_lockdown {
                sh.record_net_audit(AuditVerdict::Denied, b"net:fw6:lockdown");
                return;
            }
        }
        if next_hdr != IP_PROTO_ICMPV6 {
            return;
        }
        let icmp6 = &ip6[IPV6_HEADER_LEN..IPV6_HEADER_LEN + payload_len];
        let wire_ck = u16::from_be_bytes([icmp6[2], icmp6[3]]);
        if wire_ck == 0 {
            return;
        }
        let mut sum_payload = alloc::vec::Vec::from(icmp6);
        sum_payload[2] = 0;
        sum_payload[3] = 0;
        let expected_ck =
            Self::ipv6_upper_layer_checksum(&src_v6, &dst_v6, IP_PROTO_ICMPV6, &sum_payload);
        if wire_ck != expected_ck {
            return;
        }

        let icmp_type = icmp6[0];
        let icmp_code = icmp6[1];
        if icmp_type == 128 && icmp_code == 0 {
            let all_nodes_mc = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
            if dst_v6 != ll && dst_v6 != GUEST_IPV6_ULA && dst_v6 != all_nodes_mc {
                return;
            }
            if ETH_HEADER_LEN + IPV6_HEADER_LEN + icmp6.len() > MAX_FRAME {
                return;
            }
            let reply_src = if dst_v6 == GUEST_IPV6_ULA {
                GUEST_IPV6_ULA
            } else {
                ll
            };
            sum_payload[0] = 129;
            sum_payload[1] = 0;
            sum_payload[2] = 0;
            sum_payload[3] = 0;
            let ck =
                Self::ipv6_upper_layer_checksum(&reply_src, &src_v6, IP_PROTO_ICMPV6, &sum_payload);
            sum_payload[2..4].copy_from_slice(&ck.to_be_bytes());
            self.emit_ipv6(
                sender_mac,
                reply_src,
                src_v6,
                IP_PROTO_ICMPV6,
                64,
                &sum_payload,
                out,
            );
            self.ipv6_icmp_echos = self.ipv6_icmp_echos.wrapping_add(1);
        } else if icmp_type == 135 && icmp_code == 0 {
            // RFC 4861 §7.1.1 Neighbor Solicitation validation.
            if hop_limit != 255 || icmp6.len() < 24 {
                return;
            }
            let mut target = [0u8; 16];
            target.copy_from_slice(&icmp6[8..24]);
            if target[0] == 0xff || (target != ll && target != GUEST_IPV6_ULA) {
                return;
            }
            let solicited_mc = [
                0xff,
                0x02,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0,
                0x01,
                0xff,
                target[13],
                target[14],
                target[15],
            ];
            if dst_v6 != target && dst_v6 != solicited_mc {
                return;
            }
            let mut opt_pos = 24usize;
            while opt_pos < icmp6.len() {
                if opt_pos + 2 > icmp6.len() {
                    return;
                }
                let opt_units = icmp6[opt_pos + 1] as usize;
                if opt_units == 0 {
                    return;
                }
                let opt_bytes = opt_units * 8;
                if opt_pos + opt_bytes > icmp6.len() {
                    return;
                }
                opt_pos += opt_bytes;
            }
            let mut na = [0u8; 32];
            na[0] = 136; // Neighbor Advertisement
            na[1] = 0;
            na[4..8].copy_from_slice(&0x6000_0000u32.to_be_bytes()); // Solicited | Override
            na[8..24].copy_from_slice(&target);
            na[24] = 2; // Target Link-Layer Address option
            na[25] = 1; // 1 * 8 octets
            na[26..32].copy_from_slice(&self.mac);
            let ck = Self::ipv6_upper_layer_checksum(&target, &src_v6, IP_PROTO_ICMPV6, &na);
            na[2..4].copy_from_slice(&ck.to_be_bytes());
            self.emit_ipv6(sender_mac, target, src_v6, IP_PROTO_ICMPV6, 255, &na, out);
            self.ipv6_ndp_replies = self.ipv6_ndp_replies.wrapping_add(1);
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_ipv6(
        &mut self,
        dst_mac: [u8; 6],
        src_v6: [u8; 16],
        dst_v6: [u8; 16],
        next_header: u8,
        hop_limit: u8,
        payload: &[u8],
        out: &mut ReplySet,
    ) {
        let eth_len = ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len();
        if eth_len > MAX_FRAME || payload.len() > u16::MAX as usize {
            return;
        }
        let mut eth = [0u8; MAX_FRAME];
        eth[0..6].copy_from_slice(&dst_mac);
        eth[6..12].copy_from_slice(&self.mac);
        eth[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
        let ip6 = &mut eth[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN];
        ip6[0] = 0x60;
        ip6[1] = 0;
        ip6[2] = 0;
        ip6[3] = 0;
        ip6[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
        ip6[6] = next_header;
        ip6[7] = hop_limit;
        ip6[8..24].copy_from_slice(&src_v6);
        ip6[24..40].copy_from_slice(&dst_v6);
        eth[ETH_HEADER_LEN + IPV6_HEADER_LEN..eth_len].copy_from_slice(payload);
        out.push(&eth[..eth_len]);
    }

    #[inline(never)]
    fn handle_udp(
        &mut self,
        udp: &[u8],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        reply_ip: [u8; 4],
        boots: u64,
        shell: Option<&mut crate::shell::OsShell>,
        out: &mut ReplySet,
    ) {
        if udp.len() < 8 {
            return;
        }
        let src_port = u16::from_be_bytes([udp[0], udp[1]]);
        let dst_port = u16::from_be_bytes([udp[2], udp[3]]);
        let ulen = u16::from_be_bytes([udp[4], udp[5]]) as usize;
        if ulen < 8 || ulen > udp.len() {
            return;
        }
        let wire_ck = u16::from_be_bytes([udp[6], udp[7]]);
        if wire_ck != 0 && crate::net::udp_checksum(src_ip, self.ip, &udp[..ulen]) != wire_ck {
            return;
        }
        if (dst_port != UDP_STATUS_PORT && dst_port != TRIAD_REPL_PORT) || src_port < 1024 {
            return;
        }
        let payload_len = ulen - 8;
        let payload = &udp[8..ulen];
        // slirp bounce guard (same as the original UDP service).
        if payload_len >= 7 && payload.starts_with(b"CUTTLE-") {
            return;
        }
        let _ = src_ip;
        let mut body = [0u8; 512];
        let blen = if dst_port == TRIAD_REPL_PORT {
            if let Some(sh) = shell {
                self.handle_udp_triad(payload, sh, &mut body)
            } else {
                status_body(boots, &mut body)
            }
        } else if payload.len() >= 4 && payload.starts_with(b"CMD ") {
            if let Some(sh) = shell {
                let cmd_line = &payload[4..];
                if crate::shell::OsShell::is_readonly_command(cmd_line) {
                    let prev_owner = sh.sql_owner_override;
                    sh.sql_owner_override = crate::sql::SQL_OWNER_UDP;
                    let n = sh
                        .exec_line(cmd_line, boots, 0, 0, &mut body)
                        .bytes_written();
                    sh.sql_owner_override = prev_owner;
                    n
                } else {
                    sh.record_net_audit(AuditVerdict::Denied, b"net:udp:unauth");
                    copy_msg(
                        b"error: EACCES (unauthenticated UDP; use AUTH <seq> <hmac> <cmd>)\n",
                        &mut body,
                    )
                }
            } else {
                status_body(boots, &mut body)
            }
        } else if payload.len() >= 5 && payload.starts_with(b"AUTH ") {
            if let Some(sh) = shell {
                self.handle_udp_auth(&payload[5..], boots, sh, &mut body)
            } else {
                status_body(boots, &mut body)
            }
        } else {
            status_body(boots, &mut body)
        };
        if blen == 0 {
            return;
        }
        let mut udp_full = [0u8; 536];
        let udp_len = 8 + blen;
        udp_full[0..2].copy_from_slice(&dst_port.to_be_bytes());
        udp_full[2..4].copy_from_slice(&src_port.to_be_bytes());
        udp_full[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp_full[8..udp_len].copy_from_slice(&body[..blen]);
        let uc = crate::net::udp_checksum(self.ip, reply_ip, &udp_full[..udp_len]);
        udp_full[6..8].copy_from_slice(&uc.to_be_bytes());
        self.emit_ipv4(dst_mac, reply_ip, IP_PROTO_UDP, &udp_full[..udp_len], out);
    }

    #[inline(never)]
    fn handle_udp_triad(
        &mut self,
        payload: &[u8],
        sh: &mut crate::shell::OsShell,
        body: &mut [u8],
    ) -> usize {
        use crate::svc_runtime::IpcOp;

        let trimmed = trim_ws(payload);
        if !self.auth_enabled {
            sh.record_net_audit(AuditVerdict::Denied, b"net:triad:unprovisioned");
            return copy_msg(
                b"error: EACCES (device key not provisioned; TRIAD disabled)\n",
                body,
            );
        }
        if trimmed == b"TRIAD_STATUS" {
            return sh.cmd_triad(b"status", body);
        }

        if trimmed.len() > 14 && trimmed.starts_with(b"TRIAD_PREPARE ") {
            let rest = &trimmed[14..];
            let (first_tok, after_first) = split_ws(rest);
            let (epoch_opt, seq_tok, after_seq) =
                if first_tok.len() > 6 && first_tok.starts_with(b"epoch=") {
                    (Some(&first_tok[6..]), split_ws(after_first).0, split_ws(after_first).1)
                } else {
                    (None, first_tok, after_first)
                };
            let (node_tok, after_node) = split_ws(after_seq);
            let (hmac_tok, sql_raw) = split_ws(after_node);
            let sql = trim_ws(sql_raw);
            let (Some(seq), Some(leader_id)) = (parse_u64_dec(seq_tok), parse_u64_dec(node_tok))
            else {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:prep-syntax");
                return copy_msg(
                    b"usage: TRIAD_PREPARE [epoch=<u64>] <seq> <node_id> <hmac_hex64> <sql>\n",
                    body,
                );
            };
            if leader_id > 2 || hmac_tok.len() != 64 || sql.is_empty() {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:prep-syntax");
                return copy_msg(
                    b"usage: TRIAD_PREPARE [epoch=<u64>] <seq> <node_id> <hmac_hex64> <sql>\n",
                    body,
                );
            }
            if sql.len() > crate::svc_runtime::IPC_MAILBOX_BODY_CAP {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:sql-oversize");
                return copy_msg(b"error: E2BIG (triad SQL exceeds 256 bytes)\n", body);
            }
            if (leader_id as u8) == (sh.triad_node_id % 3) {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:self-peer");
                return copy_msg(
                    b"error: EACCES (triad PREPARE self-peer loop rejected)\n",
                    body,
                );
            }
            let min_epoch = self.triad_min_epoch.max(sh.triad_min_epoch);
            let parsed_epoch = if let Some(ep_ascii) = epoch_opt {
                let Some(ep) = parse_u64_dec(ep_ascii) else {
                    sh.record_net_audit(AuditVerdict::Error, b"net:triad:prep-syntax");
                    return copy_msg(
                        b"usage: TRIAD_PREPARE [epoch=<u64>] <seq> <node_id> <hmac_hex64> <sql>\n",
                        body,
                    );
                };
                if ep == 0 || ep < min_epoch {
                    sh.record_net_audit(AuditVerdict::Denied, b"net:triad:stale-epoch");
                    return copy_msg(
                        b"error: EACCES (stale triad coordinator epoch)\n",
                        body,
                    );
                }
                Some((ep, ep_ascii))
            } else {
                if min_epoch > 0 {
                    sh.record_net_audit(AuditVerdict::Denied, b"net:triad:stale-epoch");
                    return copy_msg(
                        b"error: EACCES (stale triad coordinator epoch)\n",
                        body,
                    );
                }
                None
            };
            if seq <= sh.triad_tx_seq {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:replay");
                return copy_msg(
                    b"error: EACCES (triad replay detected: sequence not monotonic)\n",
                    body,
                );
            }
            let mut provided_mac = [0u8; 32];
            if !decode_hex_32(hmac_tok, &mut provided_mac) {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:bad-hex");
                return copy_msg(b"error: EACCES (invalid triad HMAC hex)\n", body);
            }
            let mut expected_mac = [0u8; 32];
            if let Some((_, ep_ascii)) = parsed_epoch {
                Self::compute_triad_prepare_tag_with_epoch(
                    &self.auth_key,
                    ep_ascii,
                    seq_tok,
                    node_tok,
                    sql,
                    &mut expected_mac,
                );
            } else {
                Self::compute_triad_prepare_tag(
                    &self.auth_key,
                    seq_tok,
                    node_tok,
                    sql,
                    &mut expected_mac,
                );
            }
            let mut diff = 0u8;
            let mut i = 0usize;
            while i < 32 {
                diff |= provided_mac[i] ^ expected_mac[i];
                i += 1;
            }
            if diff != 0 {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:bad-hmac");
                return copy_msg(
                    b"error: EACCES (triad HMAC-SHA256 verification failed)\n",
                    body,
                );
            }
            if crate::sql::SqlDb::is_readonly_query(sql) {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:ro-sql");
                return copy_msg(b"error: EINVAL (TRIAD_PREPARE requires mutating SQL)\n", body);
            }
            let mut sql_out = [0u8; 192];
            let prev_owner = sh.sql_owner_override;
            sh.sql_owner_override = crate::sql::SQL_OWNER_TRIAD;
            let mb_res = sh.dispatch_mailbox_op(
                IpcOp::SqlMutate,
                false,
                true,
                1,
                b"/triad/prepare",
                sql,
                &mut sql_out,
            );
            sh.sql_owner_override = prev_owner;
            let Ok((_, slen)) = mb_res else {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:role-denied");
                return copy_msg(
                    b"error: EACCES (svc-sql disabled by node role or policy)\n",
                    body,
                );
            };
            if sql_out[..slen].starts_with(b"error:") {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:sql-err");
                return copy_msg(&sql_out[..slen], body);
            }
            if let Some((ep, _)) = parsed_epoch {
                self.triad_min_epoch = ep;
                sh.triad_min_epoch = ep;
            }
            sh.triad_tx_seq = seq;
            let state_hash = sh.db.state_hash();
            sh.triad_peer_seq[leader_id as usize] = seq;
            sh.triad_peer_hash[leader_id as usize] = state_hash;
            sh.sync_triad_local();
            if (leader_id as u8) != (sh.triad_node_id % 3) {
                sh.triad_quorum_commits = sh.triad_quorum_commits.wrapping_add(1);
            }
            sh.record_net_audit(AuditVerdict::Allowed, b"net:triad:prep-ok");

            let my_id = (sh.triad_node_id % 3) as u64;
            let mut my_id_ascii = [0u8; 4];
            let my_id_len = dec_u64(my_id, &mut my_id_ascii);
            let mut hash_hex = [0u8; 16];
            hex_encode_bytes(&state_hash.to_be_bytes(), &mut hash_hex);
            let mut ack_mac = [0u8; 32];
            Self::compute_triad_ack_tag(
                &self.auth_key,
                seq_tok,
                &my_id_ascii[..my_id_len],
                &hash_hex,
                &mut ack_mac,
            );
            let mut ack_hex = [0u8; 64];
            hex_encode_bytes(&ack_mac, &mut ack_hex);

            let mut pos = 0usize;
            pos += copy_msg(b"TRIAD_ACK ", &mut body[pos..]);
            pos += copy_msg(seq_tok, &mut body[pos..]);
            pos += copy_msg(b" ", &mut body[pos..]);
            pos += copy_msg(&my_id_ascii[..my_id_len], &mut body[pos..]);
            pos += copy_msg(b" ", &mut body[pos..]);
            pos += copy_msg(&hash_hex, &mut body[pos..]);
            pos += copy_msg(b" ", &mut body[pos..]);
            pos += copy_msg(&ack_hex, &mut body[pos..]);
            pos += copy_msg(b"\n", &mut body[pos..]);
            return pos;
        }

        if trimmed.len() > 10 && trimmed.starts_with(b"TRIAD_ACK ") {
            let rest = &trimmed[10..];
            let (seq_tok, after_seq) = split_ws(rest);
            let (peer_tok, after_peer) = split_ws(after_seq);
            let (hash_tok, after_hash) = split_ws(after_peer);
            let (hmac_tok, _) = split_ws(after_hash);
            let (Some(seq), Some(peer_id), Some(peer_hash)) = (
                parse_u64_dec(seq_tok),
                parse_u64_dec(peer_tok),
                decode_hex_u64(hash_tok),
            ) else {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:ack-syntax");
                return copy_msg(
                    b"usage: TRIAD_ACK <seq> <peer_id> <state_hash_hex16> <hmac_hex64>\n",
                    body,
                );
            };
            if peer_id > 2 || hmac_tok.len() != 64 {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:ack-syntax");
                return copy_msg(
                    b"usage: TRIAD_ACK <seq> <peer_id> <state_hash_hex16> <hmac_hex64>\n",
                    body,
                );
            }
            if peer_id as usize == (sh.triad_node_id as usize) % 3 {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:ack-self");
                return copy_msg(b"error: EACCES (triad ACK self-peer loop rejected)\n", body);
            }
            if seq != sh.triad_tx_seq || seq == 0 {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:ack-stale");
                return copy_msg(b"error: EACCES (stale triad ACK sequence)\n", body);
            }
            let mut provided_mac = [0u8; 32];
            if !decode_hex_32(hmac_tok, &mut provided_mac) {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:ack-hex");
                return copy_msg(b"error: EACCES (invalid triad ACK HMAC hex)\n", body);
            }
            let mut expected_mac = [0u8; 32];
            Self::compute_triad_ack_tag(
                &self.auth_key,
                seq_tok,
                peer_tok,
                hash_tok,
                &mut expected_mac,
            );
            let mut diff = 0u8;
            let mut i = 0usize;
            while i < 32 {
                diff |= provided_mac[i] ^ expected_mac[i];
                i += 1;
            }
            if diff != 0 {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:ack-bad-hmac");
                return copy_msg(b"error: EACCES (triad ACK HMAC verification failed)\n", body);
            }

            sh.sync_triad_local();
            let already_recorded = sh.triad_peer_seq[peer_id as usize] == seq
                && sh.triad_peer_hash[peer_id as usize] == peer_hash;
            sh.triad_peer_seq[peer_id as usize] = seq;
            sh.triad_peer_hash[peer_id as usize] = peer_hash;
            let local_hash = sh.db.state_hash();
            if seq == sh.triad_tx_seq && peer_hash != local_hash {
                if !already_recorded {
                    sh.triad_divergences = sh.triad_divergences.wrapping_add(1);
                }
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:tmr-divergence");
                let mut loc_hex = [0u8; 16];
                hex_encode_bytes(&local_hash.to_be_bytes(), &mut loc_hex);
                let mut pos = 0usize;
                pos += copy_msg(b"TRIAD_ALERT seq=", &mut body[pos..]);
                pos += copy_msg(seq_tok, &mut body[pos..]);
                pos += copy_msg(b" peer=", &mut body[pos..]);
                pos += copy_msg(peer_tok, &mut body[pos..]);
                pos += copy_msg(b" status=DIVERGENCE local_hash=", &mut body[pos..]);
                pos += copy_msg(&loc_hex, &mut body[pos..]);
                pos += copy_msg(b" peer_hash=", &mut body[pos..]);
                pos += copy_msg(hash_tok, &mut body[pos..]);
                pos += copy_msg(b"\n", &mut body[pos..]);
                return pos;
            }
            let quorum = sh.triad_quorum_count();
            if quorum >= 2 && !already_recorded {
                sh.triad_quorum_commits = sh.triad_quorum_commits.wrapping_add(1);
            }
            sh.record_net_audit(AuditVerdict::Allowed, b"net:triad:quorum-ok");
            let mut loc_hex = [0u8; 16];
            hex_encode_bytes(&local_hash.to_be_bytes(), &mut loc_hex);
            let mut pos = 0usize;
            pos += copy_msg(b"TRIAD_QUORUM seq=", &mut body[pos..]);
            pos += copy_msg(seq_tok, &mut body[pos..]);
            pos += copy_msg(b" quorum=", &mut body[pos..]);
            pos += dec_u64(quorum as u64, &mut body[pos..]);
            pos += copy_msg(b"/3 hash=", &mut body[pos..]);
            pos += copy_msg(&loc_hex, &mut body[pos..]);
            pos += copy_msg(b" commits=", &mut body[pos..]);
            pos += dec_u64(sh.triad_quorum_commits, &mut body[pos..]);
            pos += copy_msg(b"\n", &mut body[pos..]);
            return pos;
        }

        sh.record_net_audit(AuditVerdict::Error, b"net:triad:unknown");
        copy_msg(
            b"usage: TRIAD_PREPARE <seq> <node> <hmac> <sql> | TRIAD_ACK <seq> <peer> <hash> <hmac> | TRIAD_STATUS\n",
            body,
        )
    }

    fn handle_udp_auth(
        &mut self,
        rest: &[u8],
        boots: u64,
        sh: &mut crate::shell::OsShell,
        body: &mut [u8],
    ) -> usize {
        if !self.auth_enabled {
            sh.record_net_audit(AuditVerdict::Denied, b"net:udp:unprovisioned");
            return copy_msg(
                b"error: EACCES (device key not provisioned; AUTH disabled)\n",
                body,
            );
        }
        let (seq_tok, after_seq) = split_ws(rest);
        let (hmac_tok, cmd_raw) = split_ws(after_seq);
        let cmd = trim_ws(cmd_raw);
        let seq = match parse_u64_dec(seq_tok) {
            Some(s) if !cmd.is_empty() && hmac_tok.len() == 64 => s,
            _ => {
                sh.record_net_audit(AuditVerdict::Error, b"net:udp:auth-syntax");
                return copy_msg(b"usage: AUTH <seq> <hmac_hex64> <cmd>\n", body);
            }
        };
        if cmd.len() > 512 {
            sh.record_net_audit(AuditVerdict::Denied, b"net:udp:cmd-oversize");
            return copy_msg(b"error: E2BIG (AUTH command exceeds 512 bytes)\n", body);
        }
        let watermark = self.last_auth_seq.max(sh.auth_seq);
        if seq <= watermark {
            sh.record_net_audit(AuditVerdict::Denied, b"net:udp:replay");
            return copy_msg(
                b"error: EACCES (replay detected: sequence not monotonic)\n",
                body,
            );
        }
        let mut provided_mac = [0u8; 32];
        if !decode_hex_32(hmac_tok, &mut provided_mac) {
            sh.record_net_audit(AuditVerdict::Denied, b"net:udp:bad-hex");
            return copy_msg(b"error: EACCES (invalid HMAC hex encoding)\n", body);
        }
        let mut expected_mac = [0u8; 32];
        Self::compute_auth_tag(&self.auth_key, seq_tok, cmd, &mut expected_mac);
        let mut diff = 0u8;
        let mut i = 0usize;
        while i < 32 {
            diff |= provided_mac[i] ^ expected_mac[i];
            i += 1;
        }
        if diff != 0 {
            sh.record_net_audit(AuditVerdict::Denied, b"net:udp:bad-hmac");
            return copy_msg(b"error: EACCES (HMAC-SHA256 verification failed)\n", body);
        }
        self.last_auth_seq = seq;
        sh.auth_seq = seq;
        sh.record_net_audit(AuditVerdict::Allowed, b"net:udp:auth-ok");
        let prev_owner = sh.sql_owner_override;
        sh.sql_owner_override = crate::sql::SQL_OWNER_UDP;
        let n = sh.exec_line(cmd, boots, 0, 0, body).bytes_written();
        sh.sql_owner_override = prev_owner;
        n
    }

    fn syn_cookie_epoch(&self) -> u32 {
        let window_ticks = self.timer_hz.max(1).saturating_mul(32);
        self.ticks / window_ticks.max(1)
    }

    fn syn_cookie_secret(&self) -> [u8; 32] {
        let mut key = self.auth_key;
        let mut i = 0usize;
        while i < 6 {
            key[i] ^= self.mac[i].wrapping_mul(0x5B);
            key[i + 16] ^= self.mac[i] ^ 0xA5;
            i += 1;
        }
        key[31] ^= 0xC7;
        key
    }

    /// Compute a stateless RFC 4987 32-bit TCP Initial Sequence Number (SYN Cookie) via
    /// `HMAC-SHA256` over `(mac, src_ip, dst_ip, src_port, dst_port, client_isn, epoch)`.
    pub fn compute_syn_cookie_isn(
        &self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        client_isn: u32,
        epoch: u32,
    ) -> u32 {
        let secret = self.syn_cookie_secret();
        let mut msg = [0u8; 44];
        msg[..20].copy_from_slice(b"cuttle-syn-cookie-v1");
        msg[20..26].copy_from_slice(&self.mac);
        msg[26..30].copy_from_slice(&src_ip);
        msg[30..34].copy_from_slice(&self.ip);
        msg[34..36].copy_from_slice(&src_port.to_be_bytes());
        msg[36..38].copy_from_slice(&dst_port.to_be_bytes());
        msg[38..42].copy_from_slice(&client_isn.to_be_bytes());
        let ep_bytes = epoch.to_be_bytes();
        let mut tag = [0u8; 32];
        crate::tls::hmac_sha256_parts(&secret, &[&msg[..42], &ep_bytes], &mut tag);
        u32::from_be_bytes([tag[0], tag[1], tag[2], tag[3]])
    }

    fn verify_syn_cookie_ack(
        &self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        ack_seq: u32,
        ack_num: u32,
    ) -> Option<u32> {
        let client_isn = ack_seq.wrapping_sub(1);
        let candidate = ack_num.wrapping_sub(1);
        let ep = self.syn_cookie_epoch();
        let cur = self.compute_syn_cookie_isn(src_ip, src_port, dst_port, client_isn, ep);
        let prev =
            self.compute_syn_cookie_isn(src_ip, src_port, dst_port, client_isn, ep.wrapping_sub(1));
        if (candidate ^ cur) == 0 || (candidate ^ prev) == 0 {
            Some(candidate)
        } else {
            None
        }
    }

    fn find_existing_tcp_slot(
        &self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
    ) -> Option<usize> {
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            let st = self.tcbs[i].state;
            if st != TcpState::Closed
                && st != TcpState::Listen
                && self.tcbs[i].remote_ip == src_ip
                && self.tcbs[i].remote_port == src_port
                && self.tcbs[i].local_port == dst_port
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn can_accept_syn_cookie(&self) -> bool {
        let idle_ticks = self.idle_timeout_ticks();
        let mut j = 0usize;
        while j < TCP_MAX_SLOTS {
            let st = self.tcbs[j].state;
            if st != TcpState::Established
                || self.ticks.wrapping_sub(self.slot_last_tick[j]) >= idle_ticks
            {
                return true;
            }
            j += 1;
        }
        false
    }

    fn claim_verified_tcp_slot(&mut self, dst_port: u16, allow_evict_half_open: bool) -> Option<usize> {
        let mut free_slot: Option<usize> = None;
        let mut half_open_slot: Option<usize> = None;
        let mut half_open_tick = u32::MAX;
        let mut lru_slot = 0usize;
        let mut lru_tick = u32::MAX;
        let mut j = 0usize;
        while j < TCP_MAX_SLOTS {
            let st = self.tcbs[j].state;
            if st == TcpState::Closed || st == TcpState::Listen {
                free_slot = Some(j);
                break;
            }
            if st != TcpState::Established && self.slot_last_tick[j] < half_open_tick {
                half_open_tick = self.slot_last_tick[j];
                half_open_slot = Some(j);
            }
            if self.slot_last_tick[j] < lru_tick {
                lru_tick = self.slot_last_tick[j];
                lru_slot = j;
            }
            j += 1;
        }
        let idx = if let Some(s) = free_slot {
            s
        } else if allow_evict_half_open {
            if let Some(s) = half_open_slot {
                s
            } else if self.ticks.wrapping_sub(self.slot_last_tick[lru_slot])
                >= self.idle_timeout_ticks()
            {
                lru_slot
            } else {
                return None;
            }
        } else {
            return None;
        };
        self.tcbs[idx] = Tcb::listen(self.ip, dst_port, 65535);
        self.slot_rto_ticks[idx] = self.ticks;
        self.slot_remote_mac[idx] = [0u8; 6];
        let epoch = self.next_conn_epoch.max(1);
        self.next_conn_epoch = epoch.wrapping_add(1).max(1);
        self.slot_conn_epoch[idx] = epoch;
        self.release_slot_buffers(idx);
        Some(idx)
    }

    #[inline]
    fn slot_anon_sql_owner(&self, idx: usize) -> u64 {
        let ep = self.slot_conn_epoch[idx].max(1) & 0x00FF_FFFF;
        0x1_0000_0000u64 | (ep << 8) | ((idx & 0xFF) as u64)
    }

    fn record_inflight_tx(&mut self, idx: usize, seq: u32, payload: &[u8]) {
        if payload.is_empty() {
            return;
        }
        if self.tx_inflight_buf[idx].is_empty() {
            self.tx_inflight_seq[idx] = seq;
        }
        let expected_end =
            self.tx_inflight_seq[idx].wrapping_add(self.tx_inflight_buf[idx].len() as u32);
        if expected_end == seq
            && self.tx_inflight_buf[idx]
                .len()
                .saturating_add(payload.len())
                <= MAX_TX_INFLIGHT_PER_SLOT
        {
            self.tx_inflight_buf[idx].extend_from_slice(payload);
            self.slot_rto_ticks[idx] = self.ticks;
        }
    }

    fn trim_inflight_tx(&mut self, idx: usize) {
        if self.tx_inflight_buf[idx].is_empty() {
            return;
        }
        let snd_una = self.tcbs[idx].snd_una;
        let base = self.tx_inflight_seq[idx];
        let delta = snd_una.wrapping_sub(base);
        if delta > 0 && delta < 0x8000_0000 {
            let acked = (delta as usize).min(self.tx_inflight_buf[idx].len());
            if acked > 0 {
                self.tx_inflight_buf[idx].drain(..acked);
                self.tx_inflight_seq[idx] = base.wrapping_add(acked as u32);
                self.slot_rto_shift[idx] = 0;
                self.slot_rto_ticks[idx] = self.ticks;
                let mss = TCP_SEGMENT_PAYLOAD as u32;
                let cap = MAX_TX_INFLIGHT_PER_SLOT as u32;
                if self.slot_dup_acks[idx] >= 3 {
                    // RFC 5681 §3.2 Step 6: exit Fast Recovery by deflating cwnd to ssthresh.
                    self.slot_cwnd[idx] = self.slot_ssthresh[idx].min(cap);
                } else if self.slot_cwnd[idx] < self.slot_ssthresh[idx] {
                    // RFC 5681 §3.1 / RFC 3465 Slow Start (`L = 2 * SMSS`).
                    let inc = (acked as u32).min(2 * mss);
                    self.slot_cwnd[idx] = self.slot_cwnd[idx].saturating_add(inc).min(cap);
                } else {
                    // RFC 5681 §3.1 Congestion Avoidance (`cwnd += SMSS*SMSS/cwnd`).
                    let inc = ((mss * mss) / self.slot_cwnd[idx].max(1)).max(1);
                    self.slot_cwnd[idx] = self.slot_cwnd[idx].saturating_add(inc).min(cap);
                }
                self.peak_cwnd = self.peak_cwnd.max(self.slot_cwnd[idx]);
                self.slot_dup_acks[idx] = 0;
                if self.tx_inflight_buf[idx].is_empty() && self.tx_inflight_buf[idx].capacity() > 4096
                {
                    self.tx_inflight_buf[idx].shrink_to_fit();
                }
            }
        }
    }

    fn has_staged_ooo(&self, idx: usize) -> bool {
        let mut k = 0usize;
        while k < OOO_SLOTS_PER_CONN {
            if self.ooo_segs[idx][k].present {
                return true;
            }
            k += 1;
        }
        false
    }

    #[inline(never)]
    fn handle_ooo_or_dup_segment(
        &mut self,
        idx: usize,
        seg: &cuttle_contracts::TcpSegmentView<'_>,
        dst_mac: [u8; 6],
        reply_ip: [u8; 4],
        out: &mut ReplySet,
    ) {
        if (seg.flags & tcp_flags::ACK) != 0 {
            let una = self.tcbs[idx].snd_una;
            let nxt = self.tcbs[idx].snd_nxt;
            let d_una = seg.ack.wrapping_sub(una);
            let d_nxt = nxt.wrapping_sub(seg.ack);
            if d_una > 0 && d_una < 0x8000_0000 && d_nxt < 0x8000_0000 {
                self.tcbs[idx].snd_una = seg.ack;
                self.trim_inflight_tx(idx);
            }
        }
        let rcv_nxt = self.tcbs[idx].rcv_nxt;
        let forward_gap = seg.seq.wrapping_sub(rcv_nxt);
        if forward_gap > 0
            && forward_gap <= OOO_MAX_GAP_BYTES
            && seg.payload.len() <= TCP_SEGMENT_PAYLOAD
        {
            let slot_used = self.http_bufs[idx]
                .len()
                .saturating_add(self.slot_ooo_bytes(idx));
            if slot_used.saturating_add(seg.payload.len()) <= MAX_HTTP_BUFFER_BYTES
                && self
                    .total_buffered_bytes()
                    .saturating_add(seg.payload.len())
                    <= MAX_TOTAL_BUFFERED_BYTES
            {
                let mut target_k: Option<usize> = None;
                let mut k = 0usize;
                while k < OOO_SLOTS_PER_CONN {
                    if self.ooo_segs[idx][k].present && self.ooo_segs[idx][k].seq == seg.seq {
                        target_k = Some(k);
                        break;
                    }
                    if !self.ooo_segs[idx][k].present && target_k.is_none() {
                        target_k = Some(k);
                    }
                    k += 1;
                }
                if let Some(slot_k) = target_k {
                    self.ooo_segs[idx][slot_k].present = true;
                    self.ooo_segs[idx][slot_k].seq = seg.seq;
                    self.ooo_segs[idx][slot_k].fin = (seg.flags & tcp_flags::FIN) != 0;
                    self.ooo_segs[idx][slot_k].data.clear();
                    self.ooo_segs[idx][slot_k].data.extend_from_slice(seg.payload);
                }
            }
            let tcb = self.tcbs[idx];
            self.emit_tcp(
                tcb.local_port,
                tcb.remote_port,
                dst_mac,
                reply_ip,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                tcp_flags::ACK,
                tcb.rcv_wnd,
                b"",
                out,
            );
        } else if rcv_nxt.wrapping_sub(seg.seq) <= 16_384 {
            let tcb = self.tcbs[idx];
            self.emit_tcp(
                tcb.local_port,
                tcb.remote_port,
                dst_mac,
                reply_ip,
                tcb.snd_nxt,
                tcb.rcv_nxt,
                tcp_flags::ACK,
                tcb.rcv_wnd,
                b"",
                out,
            );
        }
    }

    #[inline(never)]
    fn coalesce_staged_ooo(
        &mut self,
        idx: usize,
        head: &[u8],
        hint: &mut crate::tcp::Reply,
    ) -> alloc::vec::Vec<u8> {
        let mut merged = alloc::vec::Vec::from(head);
        let mut pass = 0usize;
        while pass < OOO_SLOTS_PER_CONN {
            let mut progressed = false;
            let mut k = 0usize;
            while k < OOO_SLOTS_PER_CONN {
                if self.ooo_segs[idx][k].present {
                    let rcv_nxt = self.tcbs[idx].rcv_nxt;
                    let seg_seq = self.ooo_segs[idx][k].seq;
                    let seg_len = self.ooo_segs[idx][k].data.len() as u32;
                    let behind = rcv_nxt.wrapping_sub(seg_seq);
                    if behind <= seg_len {
                        let overlap = behind as usize;
                        let tail_len = self.ooo_segs[idx][k].data.len() - overlap;
                        if tail_len > 0 {
                            merged.extend_from_slice(&self.ooo_segs[idx][k].data[overlap..]);
                            self.tcbs[idx].rcv_nxt = rcv_nxt.wrapping_add(tail_len as u32);
                        }
                        if self.ooo_segs[idx][k].fin {
                            self.tcbs[idx].rcv_nxt = self.tcbs[idx].rcv_nxt.wrapping_add(1);
                            self.tcbs[idx].state = TcpState::CloseWait;
                        }
                        self.ooo_segs[idx][k].present = false;
                        self.ooo_segs[idx][k].seq = 0;
                        self.ooo_segs[idx][k].fin = false;
                        crate::https::scrub_vec_all_bytes(&mut self.ooo_segs[idx][k].data);
                        self.ooo_segs[idx][k].data.shrink_to_fit();
                        self.ooo_reassembled = self.ooo_reassembled.wrapping_add(1);
                        hint.present = true;
                        hint.seq = self.tcbs[idx].snd_nxt;
                        hint.ack = self.tcbs[idx].rcv_nxt;
                        hint.flags = tcp_flags::ACK;
                        hint.window = self.tcbs[idx].rcv_wnd;
                        progressed = true;
                    }
                }
                k += 1;
            }
            if !progressed {
                break;
            }
            pass += 1;
        }
        merged
    }

    #[inline(never)]
    fn handle_tcp(
        &mut self,
        tcp: &[u8],
        dst_mac: [u8; 6],
        src_ip: [u8; 4],
        reply_ip: [u8; 4],
        boots: u64,
        mut shell: Option<&mut crate::shell::OsShell>,
        out: &mut ReplySet,
    ) {
        let seg = match TcpImpl::parse_segment(tcp, src_ip, self.ip) {
            Ok(s) => s,
            Err(_) => return,
        };
        if seg.dst_port != HTTP_PORT && seg.dst_port != HTTPS_PORT {
            return;
        }
        if seg.dst_port == HTTPS_PORT && self.tls_config.is_none() {
            return;
        }
        let idx = if let Some(existing) =
            self.find_existing_tcp_slot(src_ip, seg.src_port, seg.dst_port)
        {
            existing
        } else if (seg.flags & tcp_flags::SYN) != 0
            && (seg.flags & (tcp_flags::ACK | tcp_flags::RST | tcp_flags::FIN)) == 0
        {
            let alloc_slot = if self.active_tcp_slots() < self.syn_cookie_threshold {
                self.claim_verified_tcp_slot(seg.dst_port, false)
            } else {
                None
            };
            match alloc_slot {
                Some(s) => s,
                None => {
                    if !self.can_accept_syn_cookie() {
                        return;
                    }
                    let cookie_isn = self.compute_syn_cookie_isn(
                        src_ip,
                        seg.src_port,
                        seg.dst_port,
                        seg.seq,
                        self.syn_cookie_epoch(),
                    );
                    self.syn_cookies_sent = self.syn_cookies_sent.wrapping_add(1);
                    self.emit_tcp(
                        seg.dst_port,
                        seg.src_port,
                        dst_mac,
                        reply_ip,
                        cookie_isn,
                        seg.seq.wrapping_add(1),
                        tcp_flags::SYN | tcp_flags::ACK,
                        65535,
                        b"",
                        out,
                    );
                    return;
                }
            }
        } else if (seg.flags & tcp_flags::ACK) != 0
            && (seg.flags & (tcp_flags::SYN | tcp_flags::RST)) == 0
        {
            let Some(cookie_isn) = self.verify_syn_cookie_ack(
                src_ip,
                seg.src_port,
                seg.dst_port,
                seg.seq,
                seg.ack,
            ) else {
                return;
            };
            let Some(s) = self.claim_verified_tcp_slot(seg.dst_port, true) else {
                return;
            };
            self.tcbs[s] = Tcb {
                state: TcpState::Established,
                local_ip: self.ip,
                local_port: seg.dst_port,
                remote_ip: src_ip,
                remote_port: seg.src_port,
                snd_iss: cookie_isn,
                snd_una: seg.ack,
                snd_nxt: seg.ack,
                snd_wnd: seg.window,
                rcv_irs: seg.seq.wrapping_sub(1),
                rcv_nxt: seg.seq,
                rcv_wnd: 65535,
            };
            self.slot_last_tick[s] = self.ticks;
            self.slot_rto_ticks[s] = self.ticks;
            self.slot_remote_mac[s] = dst_mac;
            self.syn_cookies_accepted = self.syn_cookies_accepted.wrapping_add(1);
            s
        } else {
            return;
        };

        if self.tcbs[idx].state == TcpState::Established
            && (seg.flags & tcp_flags::RST) == 0
            && (!seg.payload.is_empty() || (seg.flags & tcp_flags::FIN) != 0)
            && seg.seq != self.tcbs[idx].rcv_nxt
        {
            self.handle_ooo_or_dup_segment(idx, &seg, dst_mac, reply_ip, out);
            return;
        }

        // RFC 5681 §2 / §3.2: 3-Duplicate-ACK Fast Retransmit & Fast Recovery
        // (including `FinWait1` / `LastAck` when server `FIN` was already queued behind in-flight data).
        if matches!(
            self.tcbs[idx].state,
            TcpState::Established
                | TcpState::CloseWait
                | TcpState::FinWait1
                | TcpState::LastAck
        ) && (seg.flags & tcp_flags::ACK) != 0
            && (seg.flags & (tcp_flags::SYN | tcp_flags::FIN | tcp_flags::RST)) == 0
            && seg.payload.is_empty()
            && seg.seq == self.tcbs[idx].rcv_nxt
            && seg.ack == self.tcbs[idx].snd_una
            && seg.window == self.tcbs[idx].snd_wnd
            && !self.tx_inflight_buf[idx].is_empty()
        {
            self.slot_last_tick[idx] = self.ticks;
            self.slot_dup_acks[idx] = self.slot_dup_acks[idx].saturating_add(1);
            let mss = TCP_SEGMENT_PAYLOAD as u32;
            let cap = MAX_TX_INFLIGHT_PER_SLOT as u32;
            if self.slot_dup_acks[idx] == 3 {
                let flight = self.tcbs[idx].snd_nxt.wrapping_sub(self.tcbs[idx].snd_una);
                let ssthresh = (flight / 2).max(2 * mss);
                self.slot_ssthresh[idx] = ssthresh;
                self.slot_cwnd[idx] = ssthresh.saturating_add(3 * mss).min(cap);
                self.peak_cwnd = self.peak_cwnd.max(self.slot_cwnd[idx]);
                self.fast_retransmits = self.fast_retransmits.wrapping_add(1);
                if self.retransmit_inflight_chunk(idx, out) {
                    self.payload_retransmits = self.payload_retransmits.wrapping_add(1);
                }
                self.slot_rto_ticks[idx] = self.ticks;
            } else if self.slot_dup_acks[idx] > 3 {
                self.slot_cwnd[idx] = self.slot_cwnd[idx].saturating_add(mss).min(cap);
                self.peak_cwnd = self.peak_cwnd.max(self.slot_cwnd[idx]);
                if seg.dst_port == HTTPS_PORT {
                    let _ = self.flush_https_tx(idx, dst_mac, reply_ip, out);
                } else {
                    let _ = self.flush_http_tx(idx, dst_mac, reply_ip, out);
                }
            }
            return;
        }

        let was_close_wait = matches!(
            self.tcbs[idx].state,
            TcpState::CloseWait | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::LastAck
        );
        let inbound_payload = seg.payload;
        let (next, mut hint) = match process_segment(self.tcbs[idx], &seg, self.ticks) {
            Ok(t) => t,
            Err(_) => return,
        };
        self.slot_last_tick[idx] = self.ticks;
        self.slot_rto_ticks[idx] = self.ticks;
        self.slot_remote_mac[idx] = dst_mac;
        self.tcbs[idx] = next;
        if self.tcbs[idx].state == TcpState::CloseWait && (seg.flags & tcp_flags::ACK) != 0 {
            self.tcbs[idx].snd_wnd = seg.window;
        }
        if self.tcbs[idx].remote_ip == [0, 0, 0, 0] {
            self.tcbs[idx].remote_ip = src_ip;
        }
        self.trim_inflight_tx(idx);

        let raw_payload = if was_close_wait || self.http_input_closed[idx] {
            &[][..]
        } else {
            inbound_payload
        };
        let ooo_merged = if !was_close_wait
            && !self.http_input_closed[idx]
            && self.has_staged_ooo(idx)
        {
            Some(self.coalesce_staged_ooo(idx, raw_payload, &mut hint))
        } else {
            None
        };
        let effective_payload: &[u8] = match &ooo_merged {
            Some(v) => v.as_slice(),
            None => raw_payload,
        };

        if seg.dst_port == HTTPS_PORT {
            self.handle_https_slot(
                idx,
                effective_payload,
                hint,
                dst_mac,
                reply_ip,
                boots,
                shell,
                out,
            );
            return;
        }

        let mut overflow_413 = false;
        let mut busy_503 = false;
        if !effective_payload.is_empty() && self.tcbs[idx].state != TcpState::Listen {
            let next_slot_len = self.http_bufs[idx]
                .len()
                .saturating_add(effective_payload.len());
            let peer_ip = self.tcbs[idx].remote_ip;
            let next_peer_len = self
                .peer_buffered_bytes(peer_ip)
                .saturating_add(effective_payload.len());
            let next_total_len = self
                .total_buffered_bytes()
                .saturating_add(effective_payload.len());
            if next_slot_len > MAX_HTTP_BUFFER_BYTES {
                self.http_bufs[idx].clear();
                self.http_bufs[idx].shrink_to_fit();
                self.http_input_closed[idx] = true;
                overflow_413 = true;
            } else if next_peer_len > MAX_PEER_BUFFERED_BYTES
                || next_total_len > MAX_TOTAL_BUFFERED_BYTES
            {
                self.http_bufs[idx].clear();
                self.http_bufs[idx].shrink_to_fit();
                self.http_input_closed[idx] = true;
                busy_503 = true;
            } else {
                self.http_bufs[idx].extend_from_slice(effective_payload);
            }
        }

        let mut framing_exhausted = false;
        if overflow_413 || busy_503 {
            self.http_input_closed[idx] = true;
            self.http_bufs[idx].clear();
            self.http_bufs[idx].shrink_to_fit();
            let mut single = [0u8; TCP_SEGMENT_PAYLOAD];
            let n = if busy_503 {
                build_http_503_response(&mut single)
            } else {
                build_http_413_response(&mut single)
            };
            if n > 0 {
                self.http_tx[idx].extend_from_slice(&single[..n]);
            }
            framing_exhausted = true;
        } else if !self.http_input_closed[idx] {
            let mut responses = 0usize;
            while responses < 8 && self.http_tx[idx].len() < HTTPS_TX_HIGH_WATER {
                let mut single = alloc::vec![0u8; 34_816];
                let close_after;
                let n = match frame_next_http_request(&mut self.http_bufs[idx]) {
                    HttpFrameOutcome::Incomplete => {
                        framing_exhausted = true;
                        break;
                    }
                    HttpFrameOutcome::PayloadTooLarge => {
                        close_after = true;
                        build_http_413_response(&mut single)
                    }
                    HttpFrameOutcome::LengthRequired => {
                        close_after = true;
                        build_http_length_required_response(&mut single)
                    }
                    HttpFrameOutcome::BadRequest => {
                        close_after = true;
                        build_http_bad_request_response(&mut single)
                    }
                    HttpFrameOutcome::NotImplemented => {
                        close_after = true;
                        build_http_not_implemented_response(&mut single)
                    }
                    HttpFrameOutcome::Complete(req) => {
                        close_after = http_wants_close(&req);
                        self.active_http_peer_ip = self.tcbs[idx].remote_ip;
                        let anon_owner = self.slot_anon_sql_owner(idx);
                        let prev_owner = shell.as_deref_mut().map(|s| {
                            let p = s.sql_owner_override;
                            if p == crate::sql::SQL_OWNER_CONSOLE {
                                s.sql_owner_override = anon_owner;
                            }
                            p
                        });
                        let written =
                            self.handle_http_request(&req, boots, shell.as_deref_mut(), &mut single);
                        if let (Some(s), Some(p)) = (shell.as_deref_mut(), prev_owner) {
                            s.sql_owner_override = p;
                        }
                        self.active_http_peer_ip = [0u8; 4];
                        written
                    }
                };
                if n > 0 {
                    self.http_tx[idx].extend_from_slice(&single[..n]);
                }
                responses += 1;
                if close_after {
                    self.http_input_closed[idx] = true;
                    self.http_bufs[idx].clear();
                    self.http_bufs[idx].shrink_to_fit();
                    framing_exhausted = true;
                    break;
                }
            }
        } else {
            framing_exhausted = true;
        }

        let sent = self.flush_http_tx(idx, dst_mac, reply_ip, out);
        if !sent && hint.present {
            let local_port = self.tcbs[idx].local_port;
            let remote_port = self.tcbs[idx].remote_port;
            self.emit_tcp(
                local_port,
                remote_port,
                dst_mac,
                reply_ip,
                hint.seq,
                hint.ack,
                hint.flags,
                hint.window,
                b"",
                out,
            );
        }

        let drained = self.http_tx[idx].is_empty();
        if drained && self.http_tx[idx].capacity() > 4096 {
            self.http_tx[idx].shrink_to_fit();
        }
        if self.http_bufs[idx].is_empty() && self.http_bufs[idx].capacity() > 4096 {
            self.http_bufs[idx].shrink_to_fit();
        }
        let ready_to_close = (self.tcbs[idx].state == TcpState::CloseWait
            && (framing_exhausted || self.http_input_closed[idx]))
            || (self.http_input_closed[idx] && self.tcbs[idx].state == TcpState::Established);
        if ready_to_close && drained && out.len() < MAX_REPLIES {
            self.emit_fin(idx, dst_mac, reply_ip, out);
        }
        if self.tcbs[idx].state == TcpState::Closed {
            self.release_slot_buffers(idx);
        }
    }

    /// Move queued HTTP response bytes for slot `idx` into TCP segments while
    /// the reply set has room, keeping one frame free for a FIN. Returns
    /// whether any data segment was emitted.
    fn flush_http_tx(
        &mut self,
        idx: usize,
        dst_mac: [u8; 6],
        reply_ip: [u8; 4],
        out: &mut ReplySet,
    ) -> bool {
        let state = self.tcbs[idx].state;
        if state != TcpState::Established && state != TcpState::CloseWait {
            return false;
        }
        let mut sent = false;
        let local_port = self.tcbs[idx].local_port;
        let remote_port = self.tcbs[idx].remote_port;
        let mut chunk = [0u8; TCP_SEGMENT_PAYLOAD];
        while out.len() + 1 < MAX_REPLIES {
            let in_flight = self.tcbs[idx].snd_nxt.wrapping_sub(self.tcbs[idx].snd_una);
            let eff_wnd = self.slot_cwnd[idx].min(self.tcbs[idx].snd_wnd as u32);
            if in_flight >= eff_wnd {
                break;
            }
            let wnd_room = (eff_wnd - in_flight) as usize;
            let n = self.http_tx[idx]
                .len()
                .min(TCP_SEGMENT_PAYLOAD)
                .min(wnd_room);
            if n == 0 {
                break;
            }
            chunk[..n].copy_from_slice(&self.http_tx[idx][..n]);
            let Ok((next, data_hint)) = send_payload(self.tcbs[idx], n as u32) else {
                break;
            };
            if !data_hint.present {
                break;
            }
            let before = out.len();
            self.emit_tcp(
                local_port,
                remote_port,
                dst_mac,
                reply_ip,
                data_hint.seq,
                data_hint.ack,
                data_hint.flags,
                data_hint.window,
                &chunk[..n],
                out,
            );
            if out.len() == before {
                break;
            }
            self.tcbs[idx] = next;
            self.record_inflight_tx(idx, data_hint.seq, &chunk[..n]);
            self.http_tx[idx].drain(..n);
            sent = true;
        }
        sent
    }

    /// Send our FIN from `CloseWait` or `Established`.
    fn emit_fin(&mut self, idx: usize, dst_mac: [u8; 6], reply_ip: [u8; 4], out: &mut ReplySet) {
        let local_port = self.tcbs[idx].local_port;
        let remote_port = self.tcbs[idx].remote_port;
        if let Ok((next, fin_hint)) = close(self.tcbs[idx]) {
            self.tcbs[idx] = next;
            if fin_hint.present {
                self.emit_tcp(
                    local_port,
                    remote_port,
                    dst_mac,
                    reply_ip,
                    fin_hint.seq,
                    fin_hint.ack,
                    fin_hint.flags,
                    fin_hint.window,
                    b"",
                    out,
                );
            }
        }
    }

    /// Port 443: feed the segment's payload to the slot's [`TlsSession`],
    /// answer each complete decrypted HTTP request exactly as port 80 would,
    /// and transmit queued TLS bytes as TCP segments (as many as this reply
    /// set has room for; the rest go out as the peer ACKs).
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    fn handle_https_slot(
        &mut self,
        idx: usize,
        inbound: &[u8],
        hint: crate::tcp::Reply,
        dst_mac: [u8; 6],
        reply_ip: [u8; 4],
        boots: u64,
        mut shell: Option<&mut crate::shell::OsShell>,
        out: &mut ReplySet,
    ) {
        let state = self.tcbs[idx].state;
        let open = state == TcpState::Established || state == TcpState::CloseWait;
        if self.tls[idx].is_none() && open && !inbound.is_empty() && !self.http_input_closed[idx] {
            let has_heap = self
                .heap_headroom_fn
                .is_none_or(|f| f(Self::TLS_SESSION_MIN_HEAP_HEADROOM));
            if !has_heap {
                if let Some(sh) = shell.as_deref_mut() {
                    sh.record_net_audit(AuditVerdict::Denied, b"net:tls:heap_reserve");
                }
                self.http_input_closed[idx] = true;
            } else if let Some(config) = self.tls_config.clone() {
                if let Ok(session) = TlsSession::new(config) {
                    self.tls[idx] = Some(Box::new(session));
                    self.tls_sessions_started = self.tls_sessions_started.wrapping_add(1);
                }
            }
        }

        if let Some(mut session) = self.tls[idx].take() {
            let mut overflow_413 = false;
            let mut busy_503 = false;
            if !inbound.is_empty() && !self.http_input_closed[idx] {
                let other_slots_buffered =
                    self.total_buffered_bytes().saturating_sub(self.slot_tls_buffered[idx]);
                let other_peer_buffered = self
                    .peer_buffered_bytes(self.tcbs[idx].remote_ip)
                    .saturating_sub(self.slot_tls_buffered[idx]);
                let projected_slot = session
                    .rx_len()
                    .saturating_add(session.plaintext().len())
                    .saturating_add(session.pending_tx().len())
                    .saturating_add(inbound.len());
                if other_peer_buffered.saturating_add(projected_slot) > MAX_PEER_BUFFERED_BYTES
                    || other_slots_buffered.saturating_add(projected_slot)
                        > MAX_TOTAL_BUFFERED_BYTES
                {
                    let is_http_overflow = session.is_established() && !session.is_failed();
                    if let Some(sh) = shell.as_deref_mut() {
                        sh.record_net_audit(
                            AuditVerdict::Denied,
                            if is_http_overflow {
                                b"net:https:overflow"
                            } else {
                                b"net:tls:rejected"
                            },
                        );
                    }
                    if is_http_overflow {
                        busy_503 = true;
                    } else {
                        self.http_input_closed[idx] = true;
                    }
                } else if let Err(err) = session.receive(inbound) {
                    let is_http_overflow = err == crate::https::SessionError::Overflow
                        && session.is_established()
                        && !session.is_failed();
                    if let Some(sh) = shell.as_deref_mut() {
                        sh.record_net_audit(
                            AuditVerdict::Denied,
                            if is_http_overflow {
                                b"net:https:overflow"
                            } else {
                                b"net:tls:rejected"
                            },
                        );
                    }
                    if is_http_overflow {
                        overflow_413 = true;
                    }
                }
            }
            let mut framing_exhausted = false;
            if overflow_413 || busy_503 {
                self.http_input_closed[idx] = true;
                session.clear_plaintext_and_scrub();
                session.plaintext().shrink_to_fit();
                let mut response = [0u8; TCP_SEGMENT_PAYLOAD];
                let n = if overflow_413 {
                    build_http_413_response(&mut response)
                } else {
                    build_http_503_response(&mut response)
                };
                if n > 0 {
                    let _ = session.send(&response[..n]);
                }
                session.close();
                framing_exhausted = true;
            }
            let mut responses = 0usize;
            while !session.is_failed()
                && !session.close_sent()
                && !self.http_input_closed[idx]
                && responses < 8
                && session.pending_tx().len() < HTTPS_TX_HIGH_WATER
            {
                let mut response = alloc::vec![0u8; 34_816];
                let close_after;
                let n = match frame_next_http_request(session.plaintext()) {
                    HttpFrameOutcome::Incomplete => {
                        framing_exhausted = true;
                        break;
                    }
                    HttpFrameOutcome::PayloadTooLarge => {
                        close_after = true;
                        build_http_413_response(&mut response)
                    }
                    HttpFrameOutcome::LengthRequired => {
                        close_after = true;
                        build_http_length_required_response(&mut response)
                    }
                    HttpFrameOutcome::BadRequest => {
                        close_after = true;
                        build_http_bad_request_response(&mut response)
                    }
                    HttpFrameOutcome::NotImplemented => {
                        close_after = true;
                        build_http_not_implemented_response(&mut response)
                    }
                    HttpFrameOutcome::Complete(mut request) => {
                        close_after = http_wants_close(&request);
                        self.active_http_peer_ip = self.tcbs[idx].remote_ip;
                        let anon_owner = self.slot_anon_sql_owner(idx);
                        let prev_owner = shell.as_deref_mut().map(|s| {
                            let p = s.sql_owner_override;
                            if p == crate::sql::SQL_OWNER_CONSOLE {
                                s.sql_owner_override = anon_owner;
                            }
                            p
                        });
                        let written = self.handle_http_request(
                            &request,
                            boots,
                            shell.as_deref_mut(),
                            &mut response,
                        );
                        if let (Some(s), Some(p)) = (shell.as_deref_mut(), prev_owner) {
                            s.sql_owner_override = p;
                        }
                        self.active_http_peer_ip = [0u8; 4];
                        crate::https::scrub_vec_all_bytes(&mut request);
                        written
                    }
                };
                if n > 0 {
                    let mut send_failed = false;
                    for rec in response[..n].chunks(16_384) {
                        if session.send(rec).is_err() {
                            send_failed = true;
                            break;
                        }
                    }
                    crate::durable_seal::zeroize_secret_bytes(&mut response[..n]);
                    if send_failed {
                        break;
                    }
                }
                responses += 1;
                // `Connection: close`, malformed, or oversized request: end
                // the TLS session after this response and discard trailing input.
                if close_after {
                    self.http_input_closed[idx] = true;
                    session.clear_plaintext_and_scrub();
                    session.plaintext().shrink_to_fit();
                    session.close();
                    framing_exhausted = true;
                    break;
                }
            }
            if self.http_input_closed[idx] || session.close_sent() {
                framing_exhausted = true;
            }
            // Answer the peer's close_notify, or its FIN (once buffered requests are drained), with ours.
            if session.peer_closed()
                || (state == TcpState::CloseWait
                    && (framing_exhausted || self.http_input_closed[idx]))
            {
                session.close();
            }
            if session.plaintext().is_empty() && session.plaintext().capacity() > 4096 {
                session.clear_plaintext_and_scrub();
                session.plaintext().shrink_to_fit();
            }
            if session.pending_tx().len() > self.peak_tls_pending_tx {
                self.peak_tls_pending_tx = session.pending_tx().len();
            }
            self.slot_tls_buffered[idx] = session
                .rx_len()
                .saturating_add(session.plaintext().len())
                .saturating_add(session.pending_tx().len());
            self.tls[idx] = Some(session);
        }

        let sent = self.flush_https_tx(idx, dst_mac, reply_ip, out);
        if !sent && hint.present {
            let (local_port, remote_port) = (self.tcbs[idx].local_port, self.tcbs[idx].remote_port);
            self.emit_tcp(
                local_port,
                remote_port,
                dst_mac,
                reply_ip,
                hint.seq,
                hint.ack,
                hint.flags,
                hint.window,
                b"",
                out,
            );
        }
        let (drained, ready_for_fin) = match &self.tls[idx] {
            Some(session) => (
                session.pending_tx().is_empty(),
                session.close_sent() || session.is_failed() || self.http_input_closed[idx],
            ),
            None => (true, true),
        };
        if (self.tcbs[idx].state == TcpState::CloseWait
            || (self.tcbs[idx].state == TcpState::Established
                && self.tls[idx].is_none()
                && self.http_input_closed[idx]))
            && drained
            && ready_for_fin
            && out.len() < MAX_REPLIES
        {
            self.emit_fin(idx, dst_mac, reply_ip, out);
        }
        if self.tcbs[idx].state == TcpState::Closed {
            self.release_slot_buffers(idx);
        }
    }

    /// Move queued TLS bytes for slot `idx` into TCP segments while the reply
    /// set has room, keeping one frame free for a FIN. Returns whether any data
    /// segment was emitted.
    fn flush_https_tx(
        &mut self,
        idx: usize,
        dst_mac: [u8; 6],
        reply_ip: [u8; 4],
        out: &mut ReplySet,
    ) -> bool {
        let mut sent = false;
        let local_port = self.tcbs[idx].local_port;
        let remote_port = self.tcbs[idx].remote_port;
        let mut chunk = [0u8; TCP_SEGMENT_PAYLOAD];
        while out.len() + 1 < MAX_REPLIES {
            let in_flight = self.tcbs[idx].snd_nxt.wrapping_sub(self.tcbs[idx].snd_una);
            let eff_wnd = self.slot_cwnd[idx].min(self.tcbs[idx].snd_wnd as u32);
            if in_flight >= eff_wnd {
                break;
            }
            let wnd_room = (eff_wnd - in_flight) as usize;
            let n = match &self.tls[idx] {
                Some(session) => {
                    let n = session
                        .pending_tx()
                        .len()
                        .min(TCP_SEGMENT_PAYLOAD)
                        .min(wnd_room);
                    chunk[..n].copy_from_slice(&session.pending_tx()[..n]);
                    n
                }
                None => 0,
            };
            if n == 0 {
                break;
            }
            let Ok((next, data_hint)) = send_payload(self.tcbs[idx], n as u32) else {
                break;
            };
            let before = out.len();
            self.emit_tcp(
                local_port,
                remote_port,
                dst_mac,
                reply_ip,
                data_hint.seq,
                data_hint.ack,
                data_hint.flags,
                data_hint.window,
                &chunk[..n],
                out,
            );
            if out.len() == before {
                // Not emitted: leave the TCB and the queue untouched.
                break;
            }
            self.tcbs[idx] = next;
            self.record_inflight_tx(idx, data_hint.seq, &chunk[..n]);
            if let Some(session) = self.tls[idx].as_mut() {
                session.consume_tx(n);
                self.slot_tls_buffered[idx] = session
                    .rx_len()
                    .saturating_add(session.plaintext().len())
                    .saturating_add(session.pending_tx().len());
            }
            sent = true;
        }
        sent
    }

    #[inline(never)]
    fn handle_http_request(
        &mut self,
        req: &[u8],
        boots: u64,
        mut shell: Option<&mut crate::shell::OsShell>,
        out: &mut [u8],
    ) -> usize {
        use crate::svc_runtime::IpcOp;

        let view = match HttpImpl::parse_request(req) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let ok_path = view.path == b"/status"
            || view.path == b"/healthz"
            || view.path == b"/";
        if view.method == HttpMethod::Get && ok_path {
            let mut body = [0u8; 48];
            if let Some(sh) = shell.as_deref_mut() {
                match sh.dispatch_mailbox_op(
                    IpcOp::HttpGetStatus,
                    true,
                    false,
                    boots,
                    view.path,
                    b"",
                    &mut body,
                ) {
                    Ok((status, blen)) => {
                        return HttpImpl::build_response(status, b"text/plain", &body[..blen], out)
                            .unwrap_or(0);
                    }
                    Err(e) => return build_service_error_response(e, out),
                }
            }
            let blen = status_body(boots, &mut body);
            return HttpImpl::build_response(200, b"text/plain", &body[..blen], out).unwrap_or(0);
        }

        let Some(sh) = shell else {
            return HttpImpl::build_response(404, b"text/plain", b"not found\n", out).unwrap_or(0);
        };

        // 1. Built-in read-only telemetry endpoints (dispatched via `svc-http` mailbox).
        if view.method == HttpMethod::Get {
            let is_shell_endpoint = view.path == b"/ps"
                || view.path == b"/smp"
                || view.path == b"/threads"
                || view.path == b"/service"
                || view.path == b"/ls"
                || view.path == b"/df"
                || view.path == b"/audit"
                || view.path == b"/uname"
                || view.path == b"/seal"
                || view.path == b"/attest"
                || view.path == b"/seccomp"
                || view.path == b"/ima"
                || view.path == b"/fw"
                || view.path == b"/session"
                || view.path == b"/triad";
            if is_shell_endpoint {
                let mut sh_body = [0u8; 440];
                return match sh.dispatch_mailbox_op(
                    IpcOp::HttpGetTelemetry,
                    true,
                    false,
                    boots,
                    view.path,
                    &view.path[1..],
                    &mut sh_body,
                ) {
                    Ok((status, slen)) => {
                        HttpImpl::build_response(status, b"text/plain", &sh_body[..slen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
        }

        // 2. Dynamic HTML5 Web Application Dashboard (`GET /app` or `GET /dashboard`, dispatched via `svc-http` mailbox).
        if view.method == HttpMethod::Get
            && (view.path == b"/app" || view.path == b"/dashboard")
        {
            let tok = extract_session_token(view.headers_raw).unwrap_or(b"");
            let sess_idx = sh.validate_session(tok);
            let mut html = [0u8; 1310];
            return match sh.dispatch_mailbox_op(
                IpcOp::HttpGetDashboard,
                true,
                sess_idx.is_some(),
                boots,
                view.path,
                if sess_idx.is_some() { tok } else { b"" },
                &mut html,
            ) {
                Ok((status, pos)) => {
                    HttpImpl::build_response(status, b"text/html", &html[..pos], out).unwrap_or(0)
                }
                Err(e) => build_service_error_response(e, out),
            };
        }

        // 3. Dynamic Session Management (`/session/login`, `/session/whoami`, `/session/logout`).
        if view.method == HttpMethod::Post && view.path == b"/session/login" {
            let mut login_mb = [0u8; 8];
            if let Err(e) = sh.dispatch_mailbox_op(
                IpcOp::SessionLogin,
                true,
                false,
                boots,
                view.path,
                b"",
                &mut login_mb,
            ) {
                return build_service_error_response(e, out);
            }
            if !self.auth_enabled {
                sh.record_net_audit(AuditVerdict::Denied, b"net:http:unprovisioned");
                return HttpImpl::build_response(
                    403,
                    b"text/plain",
                    b"error: EACCES (device key not provisioned)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let peer_ip = self.active_http_peer_ip;
            let rate_limited = if peer_ip != [0, 0, 0, 0] {
                self.is_peer_login_rate_limited(peer_ip)
            } else {
                sh.is_login_rate_limited()
            };
            if rate_limited {
                sh.record_net_audit(AuditVerdict::Denied, b"net:http:login-ratelimit");
                return HttpImpl::build_response(
                    429,
                    b"text/plain",
                    b"error: EAGAIN (too many failed login attempts)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let (seq_tok, after_seq) = split_ws(view.body);
            let (hmac_tok, user_raw) = split_ws(after_seq);
            let user = trim_ws(user_raw);
            let Some(seq) = parse_u64_dec(seq_tok) else {
                sh.record_net_audit(AuditVerdict::Error, b"net:http:login-syntax");
                return HttpImpl::build_response(
                    400,
                    b"text/plain",
                    b"usage: <seq> <hmac_hex64> <user>\n",
                    out,
                )
                .unwrap_or(0);
            };
            let valid_user = !user.is_empty()
                && user.len() <= 16
                && user
                    .iter()
                    .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'.' || b == b'-');
            if !valid_user || hmac_tok.len() != 64 {
                sh.record_net_audit(AuditVerdict::Error, b"net:http:login-syntax");
                return HttpImpl::build_response(
                    400,
                    b"text/plain",
                    b"usage: <seq> <hmac_hex64> <user[1..=16:[A-Za-z0-9_.-]]>\n",
                    out,
                )
                .unwrap_or(0);
            }
            let watermark = self.last_http_login_seq.max(sh.http_login_seq);
            if seq <= watermark {
                sh.record_net_audit(AuditVerdict::Denied, b"net:http:login-replay");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: replay detected\n",
                    out,
                )
                .unwrap_or(0);
            }
            let mut provided_mac = [0u8; 32];
            if !decode_hex_32(hmac_tok, &mut provided_mac) {
                if peer_ip != [0, 0, 0, 0] {
                    self.record_peer_login_failure(peer_ip);
                } else {
                    sh.record_login_failure();
                }
                sh.record_net_audit(AuditVerdict::Denied, b"net:http:login-hex");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: invalid hmac hex\n",
                    out,
                )
                .unwrap_or(0);
            }
            let mut expected_mac = [0u8; 32];
            Self::compute_http_login_tag(&self.auth_key, seq_tok, user, &mut expected_mac);
            let mut diff = 0u8;
            let mut i = 0usize;
            while i < 32 {
                diff |= provided_mac[i] ^ expected_mac[i];
                i += 1;
            }
            if diff != 0 {
                if peer_ip != [0, 0, 0, 0] {
                    self.record_peer_login_failure(peer_ip);
                } else {
                    sh.record_login_failure();
                }
                sh.record_net_audit(AuditVerdict::Denied, b"net:http:login-hmac");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: hmac verification failed\n",
                    out,
                )
                .unwrap_or(0);
            }
            if peer_ip != [0, 0, 0, 0] {
                self.reset_peer_login_streak(peer_ip);
            }
            self.last_http_login_seq = seq;
            sh.http_login_seq = seq;
            let Some(sid) = sh.try_create_session(user, seq_tok) else {
                return HttpImpl::build_response(
                    503,
                    b"text/plain",
                    b"error: session key not provisioned\n",
                    out,
                )
                .unwrap_or(0);
            };
            let mut body = [0u8; 128];
            let mut bpos = 0usize;
            bpos += copy_msg(b"session: ok user=", &mut body[bpos..]);
            bpos += copy_msg(user, &mut body[bpos..]);
            bpos += copy_msg(b" sid=", &mut body[bpos..]);
            bpos += copy_msg(&sid, &mut body[bpos..]);
            bpos += copy_msg(b"\n", &mut body[bpos..]);
            return build_response_with_cookie(&sid, &body[..bpos], out);
        }

        if view.method == HttpMethod::Get && view.path == b"/session/whoami" {
            let tok = extract_session_token(view.headers_raw).unwrap_or(b"");
            let s_idx = sh.validate_session(tok);
            let mut body = [0u8; 128];
            return match sh.dispatch_mailbox_op(
                IpcOp::SessionWhoami,
                true,
                s_idx.is_some(),
                boots,
                view.path,
                tok,
                &mut body,
            ) {
                Ok((status, bpos)) => {
                    HttpImpl::build_response(status, b"text/plain", &body[..bpos], out).unwrap_or(0)
                }
                Err(e) => build_service_error_response(e, out),
            };
        }

        if view.method == HttpMethod::Post && view.path == b"/session/logout" {
            let tok = extract_session_token(view.headers_raw).unwrap_or(b"");
            let has_valid = sh.validate_session(tok).is_some();
            let mut body = [0u8; 64];
            return match sh.dispatch_mailbox_op(
                IpcOp::SessionLogout,
                true,
                has_valid,
                boots,
                view.path,
                tok,
                &mut body,
            ) {
                Ok((status, bpos)) => {
                    HttpImpl::build_response(status, b"text/plain", &body[..bpos], out).unwrap_or(0)
                }
                Err(e) => build_service_error_response(e, out),
            };
        }

        // 4. Embedded Relational SQL Database Server (`GET /sql[?<query>]`, `POST /sql`, `GET /db[?<query>]`, `POST /db`).
        //    Routed from `svc-http` across `IpcBus` to `svc-sql`'s mailbox.
        let is_sql_base = view.path == b"/sql"
            || view.path == b"/db"
            || view.path.starts_with(b"/sql?")
            || view.path.starts_with(b"/db?");
        if is_sql_base {
            if view.method == HttpMethod::Get {
                let mut body = [0u8; 384];
                let q_opt = if view.path.starts_with(b"/sql?") {
                    Some(&view.path[5..])
                } else if view.path.starts_with(b"/db?") {
                    Some(&view.path[4..])
                } else {
                    None
                };
                if let Some(raw_q) = q_opt {
                    let mut decoded = [0u8; crate::svc_runtime::IPC_MAILBOX_BODY_CAP + 1];
                    let mut dlen = 0usize;
                    let mut qi = 0usize;
                    while qi < raw_q.len() && dlen < decoded.len() {
                        if raw_q[qi] == b'+' {
                            decoded[dlen] = b' ';
                            dlen += 1;
                            qi += 1;
                        } else if raw_q[qi] == b'%' && qi + 2 < raw_q.len() {
                            if let (Some(hi), Some(lo)) =
                                (hex_nibble(raw_q[qi + 1]), hex_nibble(raw_q[qi + 2]))
                            {
                                decoded[dlen] = (hi << 4) | lo;
                                dlen += 1;
                                qi += 3;
                            } else {
                                decoded[dlen] = raw_q[qi];
                                dlen += 1;
                                qi += 1;
                            }
                        } else {
                            decoded[dlen] = raw_q[qi];
                            dlen += 1;
                            qi += 1;
                        }
                    }
                    let q_slice = &decoded[..dlen];
                    let sql_path = if view.path.starts_with(b"/db?") {
                        &b"/db"[..]
                    } else {
                        &b"/sql"[..]
                    };
                    if !crate::sql::SqlDb::is_readonly_query(q_slice) {
                        if let Err(e) = sh.dispatch_mailbox_op(
                            IpcOp::SqlMutate,
                            true,
                            false,
                            boots,
                            sql_path,
                            q_slice,
                            &mut body,
                        ) {
                            if e != crate::svc_runtime::ServiceError::Unauthenticated {
                                return build_service_error_response(e, out);
                            }
                        }
                        return HttpImpl::build_response(
                            401,
                            b"text/plain",
                            b"error: unauthorized (use authenticated POST /sql for mutations)\n",
                            out,
                        )
                        .unwrap_or(0);
                    }
                    let authed = extract_session_token(view.headers_raw)
                        .and_then(|tok| sh.validate_session(tok))
                        .is_some();
                    return match sh.dispatch_mailbox_op(
                        IpcOp::SqlQuery,
                        true,
                        authed,
                        boots,
                        sql_path,
                        q_slice,
                        &mut body,
                    ) {
                        Ok((status, blen)) => {
                            HttpImpl::build_response(status, b"text/plain", &body[..blen], out)
                                .unwrap_or(0)
                        }
                        Err(e) => build_service_error_response(e, out),
                    };
                }
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                return match sh.dispatch_mailbox_op(
                    IpcOp::SqlQuery,
                    true,
                    authed,
                    boots,
                    view.path,
                    b".tables",
                    &mut body,
                ) {
                    Ok((status, blen)) => {
                        HttpImpl::build_response(status, b"text/plain", &body[..blen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Post {
                let is_ro = crate::sql::SqlDb::is_readonly_query(view.body);
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                let op = if is_ro {
                    IpcOp::SqlQuery
                } else {
                    IpcOp::SqlMutate
                };
                let mut body = [0u8; 384];
                return match sh.dispatch_mailbox_op(
                    op,
                    true,
                    authed,
                    boots,
                    view.path,
                    view.body,
                    &mut body,
                ) {
                    Ok((status, blen)) => {
                        HttpImpl::build_response(status, b"text/plain", &body[..blen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
        }

        // 5a. Interactive Web Shell Console (`POST /sh`, routed `svc-http -> svc-sh` mailbox).
        if view.method == HttpMethod::Post && view.path == b"/sh" {
            let authed = extract_session_token(view.headers_raw)
                .and_then(|tok| sh.validate_session(tok))
                .is_some();
            let mut sh_body = [0u8; 768];
            return match sh.dispatch_mailbox_op(
                IpcOp::ShellExec,
                true,
                authed,
                boots,
                view.path,
                trim_ws(view.body),
                &mut sh_body,
            ) {
                Ok((status, slen)) => {
                    HttpImpl::build_response(status, b"text/plain", &sh_body[..slen], out)
                        .unwrap_or(0)
                }
                Err(e) => build_service_error_response(e, out),
            };
        }

        // 5. Sandboxed Remote Code Execution (`POST /exec`, routed `svc-http -> svc-sh` mailbox).
        if view.method == HttpMethod::Post && view.path == b"/exec" {
            let authed = extract_session_token(view.headers_raw)
                .and_then(|tok| sh.validate_session(tok))
                .is_some();
            let mut sh_body = [0u8; 384];
            return match sh.dispatch_mailbox_op(
                IpcOp::UserElfExec,
                true,
                authed,
                boots,
                view.path,
                trim_ws(view.body),
                &mut sh_body,
            ) {
                Ok((status, slen)) => {
                    HttpImpl::build_response(status, b"text/plain", &sh_body[..slen], out)
                        .unwrap_or(0)
                }
                Err(e) => build_service_error_response(e, out),
            };
        }

        // 6. VFS Static & Dynamic File Server (`GET /fs/<path>`, `PUT /fs/<path>`, `DELETE /fs/<path>`).
        if view.path.len() > 4 && view.path.starts_with(b"/fs/") {
            let vfs_path = &view.path[3..]; // includes leading `/`
            if view.method == HttpMethod::Get {
                return serve_vfs_get_response(sh, boots, vfs_path, out);
            }
            if view.method == HttpMethod::Put {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                let mut msg = [0u8; 96];
                return match sh.dispatch_mailbox_op(
                    IpcOp::VfsWrite,
                    true,
                    authed,
                    boots,
                    vfs_path,
                    view.body,
                    &mut msg,
                ) {
                    Ok((status, mpos)) => {
                        HttpImpl::build_response(status, b"text/plain", &msg[..mpos], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Delete {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                let mut msg = [0u8; 32];
                return match sh.dispatch_mailbox_op(
                    IpcOp::VfsDelete,
                    true,
                    authed,
                    boots,
                    vfs_path,
                    b"",
                    &mut msg,
                ) {
                    Ok((status, mpos)) => {
                        HttpImpl::build_response(status, b"text/plain", &msg[..mpos], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
        }

        // 7. CuttleVault Encrypted Secrets Manager (`GET /vault`, `GET /vault/list`, `GET /vault/<key>`, `POST /vault`).
        if view.path == b"/vault" || view.path.starts_with(b"/vault/") {
            let mut vbuf = [0u8; 384];
            if view.method == HttpMethod::Get {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                if view.path == b"/vault" || view.path == b"/vault/status" {
                    return match sh.dispatch_mailbox_op(
                        IpcOp::VaultRead,
                        true,
                        authed,
                        boots,
                        view.path,
                        b"status",
                        &mut vbuf,
                    ) {
                        Ok((status, vlen)) => {
                            HttpImpl::build_response(status, b"text/plain", &vbuf[..vlen], out)
                                .unwrap_or(0)
                        }
                        Err(e) => build_service_error_response(e, out),
                    };
                }
                if view.path == b"/vault/list" {
                    return match sh.dispatch_mailbox_op(
                        IpcOp::VaultRead,
                        true,
                        authed,
                        boots,
                        view.path,
                        b"list",
                        &mut vbuf,
                    ) {
                        Ok((status, vlen)) => {
                            HttpImpl::build_response(status, b"text/plain", &vbuf[..vlen], out)
                                .unwrap_or(0)
                        }
                        Err(e) => build_service_error_response(e, out),
                    };
                }
                if !authed {
                    return build_service_error_response(
                        crate::svc_runtime::ServiceError::Unauthenticated,
                        out,
                    );
                }
                let kname = &view.path[7..];
                let mut cmd = [0u8; 72];
                let mut cp = 0usize;
                cp += copy_msg(b"get ", &mut cmd[cp..]);
                cp += copy_msg(kname, &mut cmd[cp..]);
                return match sh.dispatch_mailbox_op(
                    IpcOp::VaultRead,
                    true,
                    true,
                    boots,
                    view.path,
                    &cmd[..cp],
                    &mut vbuf,
                ) {
                    Ok((status, vlen)) => {
                        HttpImpl::build_response(status, b"text/plain", &vbuf[..vlen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Put && view.path.len() > 7 {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                let kname = &view.path[7..];
                let mut cmd = [0u8; crate::svc_runtime::IPC_MAILBOX_BODY_CAP + 8];
                let mut cp = 0usize;
                cp += copy_msg(b"put ", &mut cmd[cp..]);
                cp += copy_msg(kname, &mut cmd[cp..]);
                cp += copy_msg(b" ", &mut cmd[cp..]);
                cp += copy_msg(trim_ws(view.body), &mut cmd[cp..]);
                return match sh.dispatch_mailbox_op(
                    IpcOp::VaultWrite,
                    true,
                    authed,
                    boots,
                    view.path,
                    &cmd[..cp],
                    &mut vbuf,
                ) {
                    Ok((status, vlen)) => {
                        HttpImpl::build_response(status, b"text/plain", &vbuf[..vlen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Delete && view.path.len() > 7 {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                let kname = &view.path[7..];
                let mut cmd = [0u8; 72];
                let mut cp = 0usize;
                cp += copy_msg(b"del ", &mut cmd[cp..]);
                cp += copy_msg(kname, &mut cmd[cp..]);
                return match sh.dispatch_mailbox_op(
                    IpcOp::VaultWrite,
                    true,
                    authed,
                    boots,
                    view.path,
                    &cmd[..cp],
                    &mut vbuf,
                ) {
                    Ok((status, vlen)) => {
                        HttpImpl::build_response(status, b"text/plain", &vbuf[..vlen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Post {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                return match sh.dispatch_mailbox_op(
                    IpcOp::VaultWrite,
                    true,
                    authed,
                    boots,
                    view.path,
                    trim_ws(view.body),
                    &mut vbuf,
                ) {
                    Ok((status, vlen)) => {
                        HttpImpl::build_response(status, b"text/plain", &vbuf[..vlen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
        }

        // 8. CuttleGuard Security Posture & Lockdown (`GET /guard`, `GET /guard/alerts`, `POST /guard`).
        if view.path == b"/guard" || view.path == b"/guard/alerts" {
            let mut gbuf = [0u8; 384];
            if view.method == HttpMethod::Get {
                let q = if view.path == b"/guard/alerts" {
                    &b"alerts"[..]
                } else {
                    &b"status"[..]
                };
                return match sh.dispatch_mailbox_op(
                    IpcOp::GuardQuery,
                    true,
                    false,
                    boots,
                    view.path,
                    q,
                    &mut gbuf,
                ) {
                    Ok((status, glen)) => {
                        HttpImpl::build_response(status, b"text/plain", &gbuf[..glen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Post {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                return match sh.dispatch_mailbox_op(
                    IpcOp::GuardControl,
                    true,
                    authed,
                    boots,
                    view.path,
                    trim_ws(view.body),
                    &mut gbuf,
                ) {
                    Ok((status, glen)) => {
                        HttpImpl::build_response(status, b"text/plain", &gbuf[..glen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
        }

        // 9. CuttleChronos Periodic Task Scheduler (`GET /cron`, `POST /cron`).
        if view.path == b"/cron" {
            let mut cbuf = [0u8; 384];
            if view.method == HttpMethod::Get {
                return match sh.dispatch_mailbox_op(
                    IpcOp::CronQuery,
                    true,
                    false,
                    boots,
                    view.path,
                    b"list",
                    &mut cbuf,
                ) {
                    Ok((status, clen)) => {
                        HttpImpl::build_response(status, b"text/plain", &cbuf[..clen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
            if view.method == HttpMethod::Post {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                return match sh.dispatch_mailbox_op(
                    IpcOp::CronControl,
                    true,
                    authed,
                    boots,
                    view.path,
                    trim_ws(view.body),
                    &mut cbuf,
                ) {
                    Ok((status, clen)) => {
                        HttpImpl::build_response(status, b"text/plain", &cbuf[..clen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
            }
        }

        // 10. Authenticated Network-Native Triad Coordinator RPC (`POST /triad/rpc`).
        //     Body format: `<epoch> <seq> <hmac_hex64> <cmd>`
        //     Domain-separated HMAC-SHA256: `"cuttle-triad-rpc-v1:<epoch>:<seq>:<cmd>"`.
        if view.path == b"/triad/rpc" {
            if view.method != HttpMethod::Post {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-method");
                return HttpImpl::build_response(
                    405,
                    b"text/plain",
                    b"error: method not allowed (use POST /triad/rpc)\n",
                    out,
                )
                .unwrap_or(0);
            }
            if !self.auth_enabled {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-unprovisioned");
                return HttpImpl::build_response(
                    403,
                    b"text/plain",
                    b"error: EACCES (device key not provisioned; TRIAD RPC disabled)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let (epoch_tok, after_ep) = split_ws(view.body);
            let (seq_tok, after_seq) = split_ws(after_ep);
            let (hmac_tok, cmd_raw) = split_ws(after_seq);
            let cmd = trim_ws(cmd_raw);
            let has_ctrl = cmd.iter().any(|&b| b < 0x20 || b == 0x7f);
            let (Some(epoch), Some(seq)) = (parse_u64_dec(epoch_tok), parse_u64_dec(seq_tok))
            else {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:rpc-syntax");
                return HttpImpl::build_response(
                    400,
                    b"text/plain",
                    b"usage: <epoch> <seq> <hmac_hex64> <cmd>\n",
                    out,
                )
                .unwrap_or(0);
            };
            if hmac_tok.len() != 64 || cmd.is_empty() || has_ctrl {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:rpc-syntax");
                return HttpImpl::build_response(
                    400,
                    b"text/plain",
                    b"usage: <epoch> <seq> <hmac_hex64> <cmd>\n",
                    out,
                )
                .unwrap_or(0);
            }
            if cmd.len() > 512 {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-oversize");
                return HttpImpl::build_response(
                    413,
                    b"text/plain",
                    b"error: E2BIG (triad RPC command exceeds 512 bytes)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let mut provided_mac = [0u8; 32];
            if !decode_hex_32(hmac_tok, &mut provided_mac) {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-hex");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: EACCES (invalid triad RPC HMAC hex)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let mut expected_mac = [0u8; 32];
            Self::compute_triad_rpc_tag(
                &self.auth_key,
                epoch_tok,
                seq_tok,
                cmd,
                &mut expected_mac,
            );
            let mut diff = 0u8;
            let mut i = 0usize;
            while i < 32 {
                diff |= provided_mac[i] ^ expected_mac[i];
                i += 1;
            }
            if diff != 0 {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-hmac");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: EACCES (triad RPC HMAC-SHA256 verification failed)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let min_epoch = self.triad_min_epoch.max(sh.triad_min_epoch);
            if epoch == 0 || epoch < min_epoch {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-stale-epoch");
                return HttpImpl::build_response(
                    409,
                    b"text/plain",
                    b"error: EACCES (stale triad coordinator epoch)\n",
                    out,
                )
                .unwrap_or(0);
            }
            let watermark = self.last_triad_rpc_seq.max(sh.triad_rpc_seq);
            if seq <= watermark {
                sh.record_net_audit(AuditVerdict::Denied, b"net:triad:rpc-replay");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: EACCES (triad RPC replay detected)\n",
                    out,
                )
                .unwrap_or(0);
            }
            self.triad_min_epoch = epoch;
            sh.triad_min_epoch = epoch;
            self.last_triad_rpc_seq = seq;
            sh.triad_rpc_seq = seq;
            self.triad_rpcs_accepted = self.triad_rpcs_accepted.wrapping_add(1);
            sh.record_net_audit(AuditVerdict::Allowed, b"net:triad:rpc-ok");

            let mut rpc_out = alloc::vec![0u8; 8192];
            let prev_owner = sh.sql_owner_override;
            sh.sql_owner_override = crate::sql::SQL_OWNER_TRIAD;
            let n = sh.exec_line(cmd, boots, 0, 0, &mut rpc_out).bytes_written();
            sh.sql_owner_override = prev_owner;
            let status = if rpc_out[..n].starts_with(b"error: EACCES (")
                && rpc_out[..n]
                    .windows(21)
                    .any(|w| w == b"disabled by node role")
            {
                503u16
            } else {
                200u16
            };
            return HttpImpl::build_response(status, b"text/plain", &rpc_out[..n], out)
                .unwrap_or(0);
        }

        HttpImpl::build_response(404, b"text/plain", b"not found\n", out).unwrap_or(0)
    }

    #[allow(clippy::too_many_arguments)]
    fn emit_tcp(
        &mut self,
        src_port: u16,
        dst_port: u16,
        dst_mac: [u8; 6],
        reply_ip: [u8; 4],
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
        out: &mut ReplySet,
    ) {
        let mut seg = [0u8; 1440];
        let n = match TcpImpl::build_segment(
            src_port,
            dst_port,
            seq,
            ack,
            flags,
            window,
            payload,
            self.ip,
            reply_ip,
            &mut seg,
        ) {
            Ok(n) => n,
            Err(_) => return,
        };
        self.emit_ipv4(dst_mac, reply_ip, IP_PROTO_TCP, &seg[..n], out);
    }

    fn emit_ipv4(
        &mut self,
        dst_mac: [u8; 6],
        dst_ip: [u8; 4],
        proto: u8,
        payload: &[u8],
        out: &mut ReplySet,
    ) {
        let ip_len = IPV4_HEADER_LEN + payload.len();
        let eth_len = ETH_HEADER_LEN + ip_len;
        if eth_len > MAX_FRAME {
            return;
        }
        let mut eth = [0u8; MAX_FRAME];
        eth[..6].copy_from_slice(&dst_mac);
        eth[6..12].copy_from_slice(&self.mac);
        eth[12] = 0x08;
        eth[13] = 0x00;
        let ip = &mut eth[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN];
        ip[0] = 0x45;
        ip[1] = 0;
        ip[2..4].copy_from_slice(&(ip_len as u16).to_be_bytes());
        let ident = self.ip_ident;
        self.ip_ident = self.ip_ident.wrapping_add(1);
        ip[4..6].copy_from_slice(&ident.to_be_bytes());
        ip[6] = 0x40; // DF
        ip[7] = 0;
        ip[8] = 64;
        ip[9] = proto;
        ip[10] = 0;
        ip[11] = 0;
        ip[12..16].copy_from_slice(&self.ip);
        ip[16..20].copy_from_slice(&dst_ip);
        let ck = ipv4_header_checksum(&eth[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV4_HEADER_LEN]);
        eth[ETH_HEADER_LEN + 10..ETH_HEADER_LEN + 12].copy_from_slice(&ck.to_be_bytes());
        eth[ETH_HEADER_LEN + IPV4_HEADER_LEN..eth_len].copy_from_slice(payload);
        out.push(&eth[..eth_len]);
    }
}

/// slirp hostfwd sources from internal addresses (≥ 10.0.2.3). Replies
/// must target the gateway (10.0.2.2) so slirp NATs them back to the
/// host — same rule as the original UDP status path.
pub fn nat_reply_ip(src: [u8; 4]) -> [u8; 4] {
    if src[0] == 10 && src[1] == 0 && src[2] == 2 && src[3] >= 3 {
        [10, 0, 2, 2]
    } else {
        src
    }
}

/// Lifecycle and availability state of a node inside [`TriadIngressVoter`].
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TriadNodeHealth {
    /// Healthy and participating in 2-of-3 / 3-of-3 TMR voting.
    Online = 0,
    /// Draining in-flight requests prior to a rolling binary morph.
    Draining = 1,
    /// Rebooting into a freshly diversified binary variant (`seed'`).
    Morphing = 2,
    /// Replaying WAL delta entries from the 2 online quorum peers before rejoining.
    CatchingUp = 3,
    /// Automatically isolated after returning a Byzantine divergent state hash or body.
    Isolated = 4,
}

/// Result of a 3-node Triple-Modular-Redundancy (TMR) ingress vote in [`TriadIngressVoter`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum TriadVoteOutcome {
    /// All 3 online nodes returned identical `(status_code, state_hash, body)`.
    Unanimous3of3 {
        /// Agreed HTTP/control-plane status code.
        status_code: u16,
        /// Agreed 64-bit SQL/system state hash.
        state_hash: u64,
    },
    /// 2 of 3 nodes returned identical `(status_code, state_hash, body)`; the 3rd node
    /// (`outlier_node`) was either offline/morphing or diverged (and was automatically isolated).
    Majority2of3 {
        /// Agreed 2-of-3 majority status code.
        status_code: u16,
        /// Agreed 2-of-3 majority state hash.
        state_hash: u64,
        /// Node index (`0..=2`) that diverged or was unavailable.
        outlier_node: u8,
    },
    /// Fewer than 2 online nodes agreed (`0/3`, `1/3`, or 3-way split-brain $N_0 \neq N_1 \neq N_2$).
    SplitBrainOrQuorumLost,
    /// Request refused because the ingress voter's [`crate::svc_runtime::NodeRole`] disables HTTP ingress (`503`).
    RoleDisabled,
    /// Mutating request refused because no valid operator session/HMAC credential was presented (`401`).
    Unauthenticated,
}

/// Per-node response candidate submitted to [`TriadIngressVoter::vote_ingress_request`].
#[derive(Copy, Clone, Debug)]
pub struct TriadNodeVoteInput<'a> {
    /// Node index (`0..=2`).
    pub node_id: u8,
    /// Whether this node responded within the ingress timeout window.
    pub available: bool,
    /// HTTP or control-plane status code returned by this node.
    pub status_code: u16,
    /// 64-bit FNV-1a SQL/system state hash reported by this node.
    pub state_hash: u64,
    /// Response payload bytes returned by this node.
    pub body: &'a [u8],
}

/// Standalone `#![no_std]` Pure-Rust Triad Ingress Quorum Voter & Rolling Morph Library Component.
///
/// Provides a self-contained pure-Rust model for 2-of-3 TMR response voting, automatic Byzantine
/// node isolation, rolling binary morph state tracking, and 4 KiB (`CTTLSQL1`) RAID-5 XOR parity
/// reconstruction. Note: this struct is a standalone library component exercised by unit tests;
/// the live 3-VM Triad uses `tools/triad_controller.py` and UDP `:8080` `TRIAD_PREPARE` / `TRIAD_ACK`.
#[derive(Copy, Clone, Debug)]
pub struct TriadIngressVoter {
    /// Active appliance role profile (`Wfe` or `Full` required to serve ingress traffic).
    pub role: crate::svc_runtime::NodeRole,
    /// Shared 256-bit `HMAC-SHA256` cluster key used to verify sealed `CTTLSQL1` partitions.
    pub cluster_key: [u8; 32],
    /// Whether a non-zero `cluster_key` has been provisioned.
    pub key_provisioned: bool,
    /// Per-node health state (`Online`, `Draining`, `Morphing`, `CatchingUp`, `Isolated`).
    pub health: [TriadNodeHealth; 3],
    /// Active binary diversification seed on each Triad node (`0..3`).
    pub variant_seeds: [u64; 3],
    /// Latest committed SQL `tx_seq` per node (`0..3`), initialized to [`crate::sql::SQL_GENESIS_TX_SEQ`].
    pub node_seq: [u64; 3],
    /// Latest verified 64-bit state hash per node (`0..3`).
    pub node_hash: [u64; 3],
    /// Previous committed quorum state hash (used to detect and reject 2-node state rollbacks).
    pub prev_quorum_hash: u64,
    /// Total 3-of-3 unanimous TMR votes completed.
    pub unanimous_votes: u64,
    /// Total 2-of-3 majority TMR votes completed (degraded or Byzantine outlier masked).
    pub majority_2of3_votes: u64,
    /// Total requests refused due to quorum loss (`< 2` nodes) or 3-way split-brain.
    pub split_brain_refusals: u64,
    /// Total mutating or administrative requests refused due to missing credentials.
    pub unauth_refusals: u64,
    /// Total 4 KiB `CTTLSQL1` partitions reconstructed and healed via RAID-5 XOR parity.
    pub parity_reconstructions: u64,
    /// Total zero-downtime rolling node morph rotations completed.
    pub rolling_morphs_completed: u64,
}

impl TriadIngressVoter {
    /// Construct an unprovisioned ingress voter (`key_provisioned = false`).
    pub const fn empty() -> Self {
        Self {
            role: crate::svc_runtime::NodeRole::Wfe,
            cluster_key: [0u8; 32],
            key_provisioned: false,
            health: [TriadNodeHealth::Online; 3],
            variant_seeds: [0u64; 3],
            node_seq: [crate::sql::SQL_GENESIS_TX_SEQ; 3],
            node_hash: [0u64; 3],
            prev_quorum_hash: 0,
            unanimous_votes: 0,
            majority_2of3_votes: 0,
            split_brain_refusals: 0,
            unauth_refusals: 0,
            parity_reconstructions: 0,
            rolling_morphs_completed: 0,
        }
    }

    /// Construct a provisioned 3-node ingress voter bound to `role`, `cluster_key`, and distinct `variant_seeds`.
    pub fn new(
        role: crate::svc_runtime::NodeRole,
        cluster_key: [u8; 32],
        variant_seeds: [u64; 3],
    ) -> Self {
        let key_ok = crate::durable_seal::is_seal_key_set(&cluster_key);
        Self {
            role,
            cluster_key,
            key_provisioned: key_ok,
            health: [TriadNodeHealth::Online; 3],
            variant_seeds,
            node_seq: [crate::sql::SQL_GENESIS_TX_SEQ; 3],
            node_hash: [0u64; 3],
            prev_quorum_hash: 0,
            unanimous_votes: 0,
            majority_2of3_votes: 0,
            split_brain_refusals: 0,
            unauth_refusals: 0,
            parity_reconstructions: 0,
            rolling_morphs_completed: 0,
        }
    }

    /// Count of nodes currently in [`TriadNodeHealth::Online`].
    pub fn online_count(&self) -> usize {
        let mut c = 0usize;
        let mut i = 0usize;
        while i < 3 {
            if self.health[i] == TriadNodeHealth::Online {
                c += 1;
            }
            i += 1;
        }
        c
    }

    fn responses_match(a: &TriadNodeVoteInput<'_>, b: &TriadNodeVoteInput<'_>) -> bool {
        a.status_code == b.status_code
            && a.state_hash == b.state_hash
            && bytes_eq_const(a.body, b.body)
    }

    /// Perform a 2-of-3 Triple-Modular-Redundancy (TMR) majority vote across the 3 Triad nodes:
    /// - Enforces [`crate::svc_runtime::NodeRole`] availability first (`Wfe` or `Full` required;
    ///   `Sql` and `Shell` roles refuse ingress routing with [`TriadVoteOutcome::RoleDisabled`]).
    /// - Enforces the standing credential gate: any mutating request (`is_mutating == true`)
    ///   without `session_authenticated == true` (or on an unprovisioned voter) is refused with
    ///   [`TriadVoteOutcome::Unauthenticated`].
    /// - If 3 of 3 online nodes agree, returns [`TriadVoteOutcome::Unanimous3of3`].
    /// - If 2 of 3 online nodes agree and the 3rd node returned a divergent response, automatically
    ///   marks the divergent node [`TriadNodeHealth::Isolated`] and returns [`TriadVoteOutcome::Majority2of3`].
    /// - If fewer than 2 online nodes agree (`0/3`, `1/3`, or 3-way split-brain $N_0 \neq N_1 \neq N_2$),
    ///   refuses the response with [`TriadVoteOutcome::SplitBrainOrQuorumLost`].
    pub fn vote_ingress_request(
        &mut self,
        is_mutating: bool,
        session_authenticated: bool,
        responses: &[TriadNodeVoteInput<'_>; 3],
        winning_body_out: &mut [u8],
    ) -> (TriadVoteOutcome, usize) {
        if !self.role.allows(crate::svc_runtime::ServiceId::Http) {
            return (TriadVoteOutcome::RoleDisabled, 0);
        }
        if is_mutating && (!self.key_provisioned || !session_authenticated) {
            self.unauth_refusals = self.unauth_refusals.wrapping_add(1);
            return (TriadVoteOutcome::Unauthenticated, 0);
        }

        let mut active = [false; 3];
        let mut i = 0usize;
        while i < 3 {
            let r = &responses[i];
            if r.available
                && (r.node_id as usize) == i
                && self.health[i] == TriadNodeHealth::Online
                && r.body.len() <= winning_body_out.len()
            {
                // Anti-rollback on read-only votes: an Online node that already has a committed
                // `node_hash[i] != 0` must report that exact `state_hash` on a non-mutating read.
                if !is_mutating && self.node_hash[i] != 0 && r.state_hash != self.node_hash[i] {
                    self.health[i] = TriadNodeHealth::Isolated;
                } else {
                    active[i] = true;
                }
            }
            i += 1;
        }

        // Case 1: All 3 nodes are online, available, and unanimous (`0 == 1 == 2`).
        if active[0]
            && active[1]
            && active[2]
            && Self::responses_match(&responses[0], &responses[1])
            && Self::responses_match(&responses[1], &responses[2])
        {
            let win = &responses[0];
            let commit_ok = is_mutating
                && win.status_code >= 200
                && win.status_code < 300
                && !win.body.starts_with(b"error:")
                && !win.body.starts_with(b"usage:");
            winning_body_out[..win.body.len()].copy_from_slice(win.body);
            if commit_ok {
                if self.node_hash[0] != 0 && self.node_hash[0] != win.state_hash {
                    self.prev_quorum_hash = self.node_hash[0];
                }
                self.node_hash = [win.state_hash; 3];
                self.node_seq[0] = self.node_seq[0].wrapping_add(1);
                self.node_seq[1] = self.node_seq[1].wrapping_add(1);
                self.node_seq[2] = self.node_seq[2].wrapping_add(1);
            } else if !is_mutating {
                self.node_hash = [win.state_hash; 3];
            }
            self.unanimous_votes = self.unanimous_votes.wrapping_add(1);
            return (
                TriadVoteOutcome::Unanimous3of3 {
                    status_code: win.status_code,
                    state_hash: win.state_hash,
                },
                win.body.len(),
            );
        }

        // Case 2: 2-of-3 majority match (`(0, 1)`, `(0, 2)`, or `(1, 2)`).
        let pair_match: Option<(usize, usize, usize)> =
            if active[0] && active[1] && Self::responses_match(&responses[0], &responses[1]) {
                Some((0, 1, 2))
            } else if active[0] && active[2] && Self::responses_match(&responses[0], &responses[2])
            {
                Some((0, 2, 1))
            } else if active[1] && active[2] && Self::responses_match(&responses[1], &responses[2])
            {
                Some((1, 2, 0))
            } else {
                None
            };

        if let Some((a, b, outlier)) = pair_match {
            let win = &responses[a];
            let commit_ok = is_mutating
                && win.status_code >= 200
                && win.status_code < 300
                && !win.body.starts_with(b"error:")
                && !win.body.starts_with(b"usage:");
            winning_body_out[..win.body.len()].copy_from_slice(win.body);
            if commit_ok {
                if self.node_hash[a] != 0 && self.node_hash[a] != win.state_hash {
                    self.prev_quorum_hash = self.node_hash[a];
                }
                self.node_hash[a] = win.state_hash;
                self.node_hash[b] = win.state_hash;
                self.node_seq[a] = self.node_seq[a].wrapping_add(1);
                self.node_seq[b] = self.node_seq[b].wrapping_add(1);
            } else if !is_mutating {
                self.node_hash[a] = win.state_hash;
                self.node_hash[b] = win.state_hash;
            }
            // Isolate the 3rd node if it was Online and:
            // - returned an incompatible or oversized response (`responses[outlier].available`), OR
            // - dropped mid-commit during a mutating write (`commit_ok && !responses[outlier].available`),
            //   leaving its committed state behind the 2-of-3 quorum (`node_seq[a]` / `node_seq[b]`).
            // Note: A node in `TriadNodeHealth::Morphing` remains `Morphing` so it can replay WAL
            // deltas via `complete_rolling_morph_catchup`.
            if active[outlier]
                || (self.health[outlier] == TriadNodeHealth::Online
                    && (responses[outlier].available || commit_ok))
            {
                self.health[outlier] = TriadNodeHealth::Isolated;
            }
            self.majority_2of3_votes = self.majority_2of3_votes.wrapping_add(1);
            return (
                TriadVoteOutcome::Majority2of3 {
                    status_code: win.status_code,
                    state_hash: win.state_hash,
                    outlier_node: outlier as u8,
                },
                win.body.len(),
            );
        }

        // Case 3: Split-brain (`0 != 1 != 2`) or fewer than 2 online nodes available.
        self.split_brain_refusals = self.split_brain_refusals.wrapping_add(1);
        (TriadVoteOutcome::SplitBrainOrQuorumLost, 0)
    }

    /// Initiate a zero-downtime rolling binary morph on `node_id` (`0..=2`), transitioning it
    /// to [`TriadNodeHealth::Morphing`] only if the remaining 2 peer nodes are both [`TriadNodeHealth::Online`].
    pub fn begin_rolling_morph(
        &mut self,
        node_id: u8,
        session_authenticated: bool,
    ) -> Result<(), crate::svc_runtime::ServiceError> {
        use crate::svc_runtime::{ServiceError, ServiceId};
        if !self.role.allows(ServiceId::Http) {
            return Err(ServiceError::RoleDisabled);
        }
        if !self.key_provisioned || !session_authenticated {
            self.unauth_refusals = self.unauth_refusals.wrapping_add(1);
            return Err(ServiceError::Unauthenticated);
        }
        let idx = node_id as usize;
        if idx >= 3 || self.health[idx] != TriadNodeHealth::Online {
            return Err(ServiceError::SandboxTrap);
        }
        // Ensure the other 2 nodes are Online so 2-of-3 quorum is preserved during the morph:
        let mut peers_online = 0usize;
        let mut i = 0usize;
        while i < 3 {
            if i != idx && self.health[i] == TriadNodeHealth::Online {
                peers_online += 1;
            }
            i += 1;
        }
        if peers_online < 2 {
            return Err(ServiceError::SandboxTrap);
        }
        self.health[idx] = TriadNodeHealth::Morphing;
        Ok(())
    }

    /// Complete a rolling binary morph on `node_id` after it boots with `new_seed` (which must
    /// differ from both peer nodes' seeds) and replays WAL delta entries to match the 2-of-3
    /// quorum `synced_hash`.
    pub fn complete_rolling_morph_catchup(
        &mut self,
        node_id: u8,
        new_seed: u64,
        synced_seq: u64,
        synced_hash: u64,
        session_authenticated: bool,
    ) -> Result<(), crate::svc_runtime::ServiceError> {
        use crate::svc_runtime::{ServiceError, ServiceId};
        if !self.role.allows(ServiceId::Http) {
            return Err(ServiceError::RoleDisabled);
        }
        if !self.key_provisioned || !session_authenticated {
            self.unauth_refusals = self.unauth_refusals.wrapping_add(1);
            return Err(ServiceError::Unauthenticated);
        }
        let idx = node_id as usize;
        if idx >= 3 || new_seed == 0 || self.health[idx] != TriadNodeHealth::Morphing {
            return Err(ServiceError::SandboxTrap);
        }
        // Enforce heterogenous MTD invariant and WAL catch-up anti-rollback:
        // - Both peer nodes must still be `Online` (2-of-3 quorum intact).
        // - `new_seed` must differ from both peer seeds.
        // - `synced_hash` must match the online quorum peers' state hash, and `synced_seq`
        //   must be at least as recent as the online quorum peers' `node_seq`.
        let mut peers_online = 0usize;
        let mut i = 0usize;
        while i < 3 {
            if i != idx {
                if self.variant_seeds[i] == new_seed {
                    return Err(ServiceError::SandboxTrap);
                }
                if self.health[i] == TriadNodeHealth::Online {
                    peers_online += 1;
                    if (self.node_hash[i] != 0 && self.node_hash[i] != synced_hash)
                        || synced_seq != self.node_seq[i]
                    {
                        return Err(ServiceError::SandboxTrap);
                    }
                }
            }
            i += 1;
        }
        if peers_online < 2 {
            return Err(ServiceError::SandboxTrap);
        }
        self.variant_seeds[idx] = new_seed;
        self.node_seq[idx] = synced_seq;
        self.node_hash[idx] = synced_hash;
        self.health[idx] = TriadNodeHealth::Online;
        self.rolling_morphs_completed = self.rolling_morphs_completed.wrapping_add(1);
        Ok(())
    }

    /// Reconstruct an isolated or disk-corrupted node's 4 KiB (`8 × 512B`) `CTTLSQL1` SQL
    /// partition from a surviving peer's 8 sectors and the 8 RAID-5 XOR parity sectors
    /// ($D_{\text{lost}} = D_{\text{peer}} \oplus P$), verifying the constant-time keyed
    /// `HMAC-SHA256` partition seal before re-admitting `lost_node` to [`TriadNodeHealth::Online`].
    pub fn heal_isolated_node_via_raid5_xor(
        &mut self,
        lost_node: u8,
        peer_node: u8,
        session_authenticated: bool,
        peer_sectors: &[[u8; 512]; crate::sql::SQL_PART_SECTORS],
        parity_sectors: &[[u8; 512]; crate::sql::SQL_PART_SECTORS],
        recovered_db_out: &mut crate::sql::SqlDb,
    ) -> Result<u64, crate::svc_runtime::ServiceError> {
        use crate::svc_runtime::{ServiceError, ServiceId};
        if !self.role.allows(ServiceId::Http) {
            return Err(ServiceError::RoleDisabled);
        }
        if !self.key_provisioned || !session_authenticated {
            self.unauth_refusals = self.unauth_refusals.wrapping_add(1);
            return Err(ServiceError::Unauthenticated);
        }
        let l_idx = lost_node as usize;
        let p_idx = peer_node as usize;
        if l_idx >= 3
            || p_idx >= 3
            || l_idx == p_idx
            || self.health[p_idx] != TriadNodeHealth::Online
            || self.health[l_idx] == TriadNodeHealth::Online
        {
            return Err(ServiceError::SandboxTrap);
        }
        let mut reconstructed = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        let mut s = 0usize;
        while s < crate::sql::SQL_PART_SECTORS {
            let mut b = 0usize;
            while b < 512 {
                reconstructed[s][b] = peer_sectors[s][b] ^ parity_sectors[s][b];
                b += 1;
            }
            s += 1;
        }
        if !recovered_db_out.load_partition(&self.cluster_key, &reconstructed) {
            return Err(ServiceError::ImaVerificationFailed);
        }
        let healed_hash = recovered_db_out.state_hash();
        if (self.node_hash[p_idx] != 0 && healed_hash != self.node_hash[p_idx])
            || recovered_db_out.tx_seq != self.node_seq[p_idx]
        {
            return Err(ServiceError::ImaVerificationFailed);
        }
        self.node_hash[l_idx] = healed_hash;
        self.node_seq[l_idx] = recovered_db_out.tx_seq;
        self.health[l_idx] = TriadNodeHealth::Online;
        self.parity_reconstructions = self.parity_reconstructions.wrapping_add(1);
        Ok(healed_hash)
    }
}

fn bytes_eq_const(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < a.len() {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

fn status_body(boots: u64, out: &mut [u8]) -> usize {
    let p = b"CUTTLE-STATUS boots=";
    if out.len() < p.len() + 22 {
        return 0;
    }
    out[..p.len()].copy_from_slice(p);
    let mut n = p.len();
    n += dec_u64(boots, &mut out[n..]);
    out[n] = b'\n';
    n + 1
}

fn build_service_error_response(err: crate::svc_runtime::ServiceError, out: &mut [u8]) -> usize {
    use crate::svc_runtime::ServiceError;
    match err {
        ServiceError::BadRequest => HttpImpl::build_response(
            400,
            b"text/plain",
            b"error: EINVAL (malformed request path or body)\n",
            out,
        )
        .unwrap_or(0),
        ServiceError::Unauthenticated => {
            HttpImpl::build_response(401, b"text/plain", b"error: unauthorized\n", out).unwrap_or(0)
        }
        ServiceError::PayloadTooLarge => HttpImpl::build_response(
            413,
            b"text/plain",
            b"error: EMSGSIZE (request path or body exceeds IPC mailbox capacity)\n",
            out,
        )
        .unwrap_or(0),
        ServiceError::RoleDisabled => HttpImpl::build_response(
            503,
            b"text/plain",
            b"error: EACCES (service disabled by node role policy)\n",
            out,
        )
        .unwrap_or(0),
        ServiceError::CapabilityDenied
        | ServiceError::SeccompDenied
        | ServiceError::ImaVerificationFailed
        | ServiceError::KptiIsolationFailed
        | ServiceError::SandboxTrap => HttpImpl::build_response(
            403,
            b"text/plain",
            b"error: EPERM (service isolation policy violation)\n",
            out,
        )
        .unwrap_or(0),
    }
}

fn build_http_413_response(out: &mut [u8]) -> usize {
    HttpImpl::build_response(
        413,
        b"text/plain",
        b"error: EMSGSIZE (HTTP request exceeds buffer capacity)\n",
        out,
    )
    .unwrap_or(0)
}

fn build_http_503_response(out: &mut [u8]) -> usize {
    HttpImpl::build_response(
        503,
        b"text/plain",
        b"error: EBUSY (server or per-peer HTTP buffer budget exhausted)\n",
        out,
    )
    .unwrap_or(0)
}

fn build_http_length_required_response(out: &mut [u8]) -> usize {
    HttpImpl::build_response(
        400,
        b"text/plain",
        b"error: Content-Length required for POST/PUT\n",
        out,
    )
    .unwrap_or(0)
}

fn build_http_bad_request_response(out: &mut [u8]) -> usize {
    HttpImpl::build_response(
        400,
        b"text/plain",
        b"error: malformed HTTP request\n",
        out,
    )
    .unwrap_or(0)
}

fn build_http_not_implemented_response(out: &mut [u8]) -> usize {
    HttpImpl::build_response(
        501,
        b"text/plain",
        b"error: Transfer-Encoding not supported\n",
        out,
    )
    .unwrap_or(0)
}

enum HttpFrameOutcome {
    Incomplete,
    Complete(alloc::vec::Vec<u8>),
    PayloadTooLarge,
    LengthRequired,
    BadRequest,
    NotImplemented,
}

/// Unified HTTP/1.1 request framer shared by plain HTTP (`:80`) and HTTPS (`:443`).
/// - Rejects any request whose header or total length exceeds [`MAX_HTTP_REQUEST_BYTES`]
///   with [`HttpFrameOutcome::PayloadTooLarge`] (`413`).
/// - Rejects `Transfer-Encoding` with [`HttpFrameOutcome::NotImplemented`] (`501`)
///   and malformed request lines, non-numeric `Content-Length`, or duplicate
///   `Content-Length` headers with [`HttpFrameOutcome::BadRequest`] (`400`).
/// - Requires an explicit `Content-Length` header on `POST` and `PUT` requests so
///   a split request body is never silently truncated.
fn frame_next_http_request(buf: &mut alloc::vec::Vec<u8>) -> HttpFrameOutcome {
    let Some(hdr_end) = find_double_crlf(buf) else {
        if buf.len() > MAX_HTTP_REQUEST_BYTES {
            buf.clear();
            return HttpFrameOutcome::PayloadTooLarge;
        }
        return HttpFrameOutcome::Incomplete;
    };
    let body_start = hdr_end + 4;
    if body_start > MAX_HTTP_REQUEST_BYTES {
        buf.clear();
        return HttpFrameOutcome::PayloadTooLarge;
    }
    if buf.len() < crate::http::MIN_REQUEST_LEN {
        buf.clear();
        return HttpFrameOutcome::BadRequest;
    }
    match HttpImpl::parse_request(&buf[..]) {
        Ok(view) => {
            if HttpImpl::find_header(view.headers_raw, b"Content-Length").is_some() {
                let total = body_start + view.body.len();
                if total > MAX_HTTP_REQUEST_BYTES {
                    buf.clear();
                    return HttpFrameOutcome::PayloadTooLarge;
                }
                HttpFrameOutcome::Complete(buf.drain(..total).collect())
            } else if matches!(view.method, HttpMethod::Post | HttpMethod::Put) {
                buf.clear();
                HttpFrameOutcome::LengthRequired
            } else {
                HttpFrameOutcome::Complete(buf.drain(..body_start).collect())
            }
        }
        Err(cuttle_contracts::HttpError::Truncated) => {
            // Headers were valid and `Content-Length` exceeded the currently buffered body;
            // check `body_start + cl` upfront so oversized `Content-Length` fails immediately with 413.
            let hdr_slice = &buf[..hdr_end];
            if let Some(rl_end) = hdr_slice.windows(2).position(|w| w == b"\r\n") {
                let headers_raw = &hdr_slice[rl_end + 2..];
                if let Some(cl_raw) = HttpImpl::find_header(headers_raw, b"Content-Length") {
                    let Some(cl) = parse_u64_dec(trim_ws(cl_raw)) else {
                        buf.clear();
                        return HttpFrameOutcome::BadRequest;
                    };
                    let Some(total) = body_start.checked_add(cl as usize) else {
                        buf.clear();
                        return HttpFrameOutcome::PayloadTooLarge;
                    };
                    if total > MAX_HTTP_REQUEST_BYTES {
                        buf.clear();
                        return HttpFrameOutcome::PayloadTooLarge;
                    }
                    return HttpFrameOutcome::Incomplete;
                }
            }
            buf.clear();
            HttpFrameOutcome::BadRequest
        }
        Err(cuttle_contracts::HttpError::UnsupportedVersion) => {
            let hdr_slice = &buf[..hdr_end];
            let has_te = hdr_slice
                .split(|&b| b == b'\n')
                .skip(1)
                .any(|line| {
                    let line = line.strip_suffix(b"\r").unwrap_or(line);
                    line.iter()
                        .position(|&b| b == b':')
                        .is_some_and(|c| line[..c].eq_ignore_ascii_case(b"Transfer-Encoding"))
                });
            buf.clear();
            if has_te {
                HttpFrameOutcome::NotImplemented
            } else {
                HttpFrameOutcome::BadRequest
            }
        }
        Err(_) => {
            buf.clear();
            HttpFrameOutcome::BadRequest
        }
    }
}

/// True if the request carries a `close` token in any `Connection` header
/// (RFC 9112 §9.6, including comma-separated lists like `keep-alive, close`).
fn http_wants_close(req: &[u8]) -> bool {
    let Ok(view) = HttpImpl::parse_request(req) else {
        return false;
    };
    for line in view.headers_raw.split(|&b| b == b'\n') {
        let line = line.strip_suffix(b"\r").unwrap_or(line);
        let Some(colon) = line.iter().position(|&b| b == b':') else {
            continue;
        };
        let name = trim_ws(&line[..colon]);
        if !name.eq_ignore_ascii_case(b"Connection") {
            continue;
        }
        let val = &line[colon + 1..];
        for tok in val.split(|&b| b == b',') {
            if trim_ws(tok).eq_ignore_ascii_case(b"close") {
                return true;
            }
        }
    }
    false
}

fn extract_session_token(headers_raw: &[u8]) -> Option<&[u8]> {
    if let Some(tok) = HttpImpl::find_header(headers_raw, b"X-Session-Token") {
        let tok = trim_ws(tok);
        if tok.len() == 32 && tok.iter().all(|b| b.is_ascii_hexdigit()) {
            return Some(tok);
        }
    }
    if let Some(cookie) = HttpImpl::find_header(headers_raw, b"Cookie") {
        for pair in cookie.split(|&b| b == b';') {
            let pair = trim_ws(pair);
            if let Some(val) = pair.strip_prefix(b"sid=") {
                let val = val
                    .strip_prefix(b"\"")
                    .and_then(|v| v.strip_suffix(b"\""))
                    .unwrap_or(val);
                if val.len() == 32 && val.iter().all(|b| b.is_ascii_hexdigit()) {
                    return Some(val);
                }
            }
        }
    }
    None
}

fn build_response_with_cookie(sid: &[u8; 32], body: &[u8], out: &mut [u8]) -> usize {
    let mut pos = 0usize;
    pos += copy_msg(
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: sid=",
        &mut out[pos..],
    );
    pos += copy_msg(sid, &mut out[pos..]);
    pos += copy_msg(b"; HttpOnly; Path=/\r\nContent-Length: ", &mut out[pos..]);
    pos += dec_u64(body.len() as u64, &mut out[pos..]);
    pos += copy_msg(b"\r\n\r\n", &mut out[pos..]);
    pos += copy_msg(body, &mut out[pos..]);
    pos
}

fn find_double_crlf(b: &[u8]) -> Option<usize> {
    if b.len() < 4 {
        return None;
    }
    let mut i = 0;
    while i + 3 < b.len() {
        if b[i] == b'\r' && b[i + 1] == b'\n' && b[i + 2] == b'\r' && b[i + 3] == b'\n' {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn copy_msg(src: &[u8], dst: &mut [u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

fn trim_ws(s: &[u8]) -> &[u8] {
    let mut start = 0usize;
    while start < s.len()
        && (s[start] == b' ' || s[start] == b'\t' || s[start] == b'\r' || s[start] == b'\n')
    {
        start += 1;
    }
    let mut end = s.len();
    while end > start
        && (s[end - 1] == b' '
            || s[end - 1] == b'\t'
            || s[end - 1] == b'\r'
            || s[end - 1] == b'\n')
    {
        end -= 1;
    }
    &s[start..end]
}

fn split_ws(s: &[u8]) -> (&[u8], &[u8]) {
    let trimmed = trim_ws(s);
    let mut i = 0usize;
    while i < trimmed.len() && trimmed[i] != b' ' && trimmed[i] != b'\t' {
        i += 1;
    }
    let first = &trimmed[..i];
    let rest = if i < trimmed.len() {
        trim_ws(&trimmed[i + 1..])
    } else {
        &[]
    };
    (first, rest)
}

#[inline(never)]
fn serve_vfs_get_response(
    sh: &mut crate::shell::OsShell,
    boots: u64,
    vfs_path: &[u8],
    out: &mut [u8],
) -> usize {
    let mut fbuf = alloc::vec![0u8; crate::vfs::PAGED_VFS_MAX_FILE_BYTES];
    match sh.dispatch_mailbox_op(
        crate::svc_runtime::IpcOp::VfsRead,
        true,
        false,
        boots,
        vfs_path,
        b"",
        &mut fbuf,
    ) {
        Ok((200, flen)) => {
            let ctype: &[u8] = if vfs_path.ends_with(b".html") {
                b"text/html"
            } else if vfs_path.ends_with(b".json") {
                b"application/json"
            } else {
                b"text/plain"
            };
            HttpImpl::build_response(200, ctype, &fbuf[..flen], out).unwrap_or(0)
        }
        Ok((status, flen)) => {
            HttpImpl::build_response(status, b"text/plain", &fbuf[..flen], out).unwrap_or(0)
        }
        Err(e) => build_service_error_response(e, out),
    }
}

fn ipv4_header_checksum_valid(hdr: &[u8]) -> bool {
    if hdr.len() < IPV4_HEADER_LEN || (hdr.len() & 1) != 0 {
        return false;
    }
    let mut sum: u32 = 0;
    let mut i = 0usize;
    while i + 1 < hdr.len() {
        let w = ((hdr[i] as u32) << 8) | (hdr[i + 1] as u32);
        sum += w;
        i += 2;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    (sum as u16) == 0xFFFF
}

fn parse_u64_dec(s: &[u8]) -> Option<u64> {
    if s.is_empty() || (s.len() > 1 && s[0] == b'0') {
        return None;
    }
    let mut acc: u64 = 0;
    let mut i = 0usize;
    while i < s.len() {
        let c = s[i];
        if !c.is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((c - b'0') as u64)?;
        i += 1;
    }
    Some(acc)
}

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn decode_hex_32(hex: &[u8], out: &mut [u8; 32]) -> bool {
    if hex.len() != 64 {
        return false;
    }
    let mut i = 0usize;
    while i < 32 {
        let hi = match hex_nibble(hex[i * 2]) {
            Some(v) => v,
            None => return false,
        };
        let lo = match hex_nibble(hex[i * 2 + 1]) {
            Some(v) => v,
            None => return false,
        };
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    true
}

fn decode_hex_u64(hex: &[u8]) -> Option<u64> {
    if hex.len() != 16 {
        return None;
    }
    let mut bytes = [0u8; 8];
    let mut i = 0usize;
    while i < 8 {
        let hi = hex_nibble(hex[i * 2])?;
        let lo = hex_nibble(hex[i * 2 + 1])?;
        bytes[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(u64::from_be_bytes(bytes))
}

fn hex_encode_bytes(src: &[u8], out: &mut [u8]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut i = 0usize;
    while i < src.len() && (i * 2 + 1) < out.len() {
        out[i * 2] = HEX[(src[i] >> 4) as usize];
        out[i * 2 + 1] = HEX[(src[i] & 0x0F) as usize];
        i += 1;
    }
}

fn dec_u64(mut v: u64, out: &mut [u8]) -> usize {
    if out.is_empty() {
        return 0;
    }
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    while v > 0 && n < tmp.len() {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut i = 0;
    while i < n && i < out.len() {
        out[i] = tmp[n - 1 - i];
        i += 1;
    }
    i
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::{tcp_flags, Icmp, Tcp};

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    const PEER_IP: [u8; 4] = [10, 0, 2, 2];

    fn eth_ip(proto: u8, src_ip: [u8; 4], dst_ip: [u8; 4], payload: &[u8]) -> ([u8; MAX_FRAME], usize) {
        let ip_len = IPV4_HEADER_LEN + payload.len();
        let eth_len = ETH_HEADER_LEN + ip_len;
        let mut eth = [0u8; MAX_FRAME];
        eth[..6].copy_from_slice(&MAC);
        eth[6..12].copy_from_slice(&PEER_MAC);
        eth[12] = 0x08;
        eth[13] = 0x00;
        eth[14] = 0x45;
        eth[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
        eth[22] = 64;
        eth[23] = proto;
        eth[26..30].copy_from_slice(&src_ip);
        eth[30..34].copy_from_slice(&dst_ip);
        let ck = ipv4_header_checksum(&eth[14..34]);
        eth[24..26].copy_from_slice(&ck.to_be_bytes());
        eth[34..eth_len].copy_from_slice(payload);
        (eth, eth_len)
    }

    #[test]
    fn nat_rewrites_slirp_internal_to_gateway() {
        assert_eq!(nat_reply_ip([10, 0, 2, 3]), [10, 0, 2, 2]);
        assert_eq!(nat_reply_ip([10, 0, 2, 2]), [10, 0, 2, 2]);
        assert_eq!(nat_reply_ip([192, 168, 1, 9]), [192, 168, 1, 9]);
    }

    #[test]
    fn arp_who_has_guest_gets_reply() {
        let mut net = LivedNet::new(MAC);
        let mut req = [0u8; 42];
        req[..6].copy_from_slice(&MAC);
        req[6..12].copy_from_slice(&PEER_MAC);
        req[12] = 0x08;
        req[13] = 0x06;
        req[14] = 0;
        req[15] = 1;
        req[16] = 0x08;
        req[17] = 0;
        req[18] = 6;
        req[19] = 4;
        req[20] = 0;
        req[21] = 1;
        req[22..28].copy_from_slice(&PEER_MAC);
        req[28..32].copy_from_slice(&PEER_IP);
        req[38..42].copy_from_slice(&GUEST_IP);
        let mut out = ReplySet::new();
        net.handle_frame(&req, 0, &mut out);
        assert_eq!(out.len(), 1);
        let r = out.get(0).unwrap();
        assert_eq!(&r[20..22], &[0, 2]); // ARP reply
        assert_eq!(&r[28..32], &GUEST_IP);
    }

    #[test]
    fn icmp_echo_request_gets_echo_reply() {
        let mut net = LivedNet::new(MAC);
        let mut icmp = [0u8; 16];
        let n = IcmpImpl::build_echo_request(0x4242, 7, b"ping!", &mut icmp).unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_ICMP, PEER_IP, GUEST_IP, &icmp[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 0, &mut out);
        assert_eq!(out.len(), 1);
        let r = out.get(0).unwrap();
        assert_eq!(r[23], IP_PROTO_ICMP);
        let reply = IcmpImpl::parse_echo(&r[34..]).unwrap();
        assert_eq!(reply.icmp_type, icmp_type::ECHO_REPLY);
        assert_eq!(reply.identifier, 0x4242);
        assert_eq!(reply.sequence_number, 7);
        assert_eq!(reply.payload, b"ping!");
    }

    #[test]
    fn udp_status_replies_with_boot_counter() {
        let mut net = LivedNet::new(MAC);
        let payload = b"STATUS?";
        let udp_len = 8 + payload.len();
        let mut udp = [0u8; 32];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[8..udp_len].copy_from_slice(payload);
        let uc = crate::net::udp_checksum(PEER_IP, GUEST_IP, &udp[..udp_len]);
        udp[6..8].copy_from_slice(&uc.to_be_bytes());
        let (frame, flen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &udp[..udp_len]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 279, &mut out);
        assert_eq!(out.len(), 1);
        let r = out.get(0).unwrap();
        let body = core::str::from_utf8(&r[42..]).unwrap();
        assert!(body.starts_with("CUTTLE-STATUS boots=279"), "got {body:?}");
    }

    #[test]
    fn http_get_status_over_tcp_returns_200() {
        let mut net = LivedNet::new(MAC);
        let client_isn: u32 = 0x1000_0000;
        let client_port: u16 = 54321;

        // SYN
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 4, &mut out);
        assert_eq!(out.len(), 1);
        let synack = out.get(0).unwrap();
        let sa = TcpImpl::parse_segment(&synack[34..], GUEST_IP, PEER_IP).unwrap();
        assert_eq!(sa.flags, tcp_flags::SYN | tcp_flags::ACK);
        let server_isn = sa.seq;

        // ACK + GET /status
        let req = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut ack = [0u8; 128];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn.wrapping_add(1),
            server_isn.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req,
            PEER_IP,
            GUEST_IP,
            &mut ack,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ack[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 4, &mut out);
        assert!(out.len() >= 1, "expected HTTP response frame");
        let resp = out.get(0).unwrap();
        let seg = TcpImpl::parse_segment(&resp[34..], GUEST_IP, PEER_IP).unwrap();
        let body = core::str::from_utf8(seg.payload).unwrap();
        assert!(body.starts_with("HTTP/1.1 200"), "got {body:?}");
        assert!(body.contains("CUTTLE-STATUS boots=4"), "got {body:?}");
    }

    #[test]
    fn http_get_plus_fin_still_returns_200() {
        let mut net = LivedNet::new(MAC);
        let client_isn: u32 = 0x2000_0000;
        let client_port: u16 = 40001;
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            client_port, HTTP_PORT, client_isn, 0, tcp_flags::SYN, 65535, b"",
            PEER_IP, GUEST_IP, &mut syn,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 1, &mut out);
        let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let req = b"GET /healthz HTTP/1.0\r\n\r\n";
        let mut pkt = [0u8; 128];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn.wrapping_add(1),
            sa.seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH | tcp_flags::FIN,
            65535,
            req,
            PEER_IP,
            GUEST_IP,
            &mut pkt,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &pkt[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 1, &mut out);
        assert!(out.len() >= 1);
        let mut saw_200 = false;
        let mut i = 0;
        while i < out.len() {
            let r = out.get(i).unwrap();
            if let Ok(seg) = TcpImpl::parse_segment(&r[34..], GUEST_IP, PEER_IP) {
                if let Ok(s) = core::str::from_utf8(seg.payload) {
                    if s.contains("HTTP/1.1 200") && s.contains("CUTTLE-STATUS boots=1") {
                        saw_200 = true;
                    }
                }
            }
            i += 1;
        }
        assert!(saw_200, "GET+FIN must still produce HTTP 200");
    }

    #[test]
    fn announce_emits_gratuitous_arp() {
        let net = LivedNet::new(MAC);
        let mut out = ReplySet::new();
        net.announce(&mut out);
        assert_eq!(out.len(), 1);
        let f = out.get(0).unwrap();
        assert_eq!(&f[..6], &[0xffu8; 6]);
        assert_eq!(&f[28..32], &GUEST_IP);
    }

    #[test]
    fn udp_cmd_and_http_shell_endpoints_work() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();

        // 1. UDP CMD cat /etc/hostname
        let payload = b"CMD cat /etc/hostname";
        let udp_len = 8 + payload.len();
        let mut udp = [0u8; 64];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[8..udp_len].copy_from_slice(payload);
        let uc = crate::net::udp_checksum(PEER_IP, GUEST_IP, &udp[..udp_len]);
        udp[6..8].copy_from_slice(&uc.to_be_bytes());
        let (frame, flen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &udp[..udp_len]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 3, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        let r = out.get(0).unwrap();
        assert_eq!(&r[42..], b"cuttle-te\n");

        // 2. HTTP GET /uname over TCP/80
        let client_isn: u32 = 0x3000_0000;
        let client_port: u16 = 40002;
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 3, &mut sh, &mut out);
        let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();

        let req = b"GET /uname HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut ack = [0u8; 128];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn.wrapping_add(1),
            sa.seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req,
            PEER_IP,
            GUEST_IP,
            &mut ack,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ack[..n]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 3, &mut sh, &mut out);
        let resp = out.get(0).unwrap();
        let seg = TcpImpl::parse_segment(&resp[34..], GUEST_IP, PEER_IP).unwrap();
        let body = core::str::from_utf8(seg.payload).unwrap();
        assert!(body.contains("HTTP/1.1 200"));
        assert!(body.contains("Cuttle-TE x86_64 1.0-mtd"));
    }

    #[test]
    fn firewall_cidr_drop_and_hmac_anti_replay_auth_work() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();

        // Helper to send a UDP payload from `src_ip` to `GUEST_IP:8080`.
        let send_udp = |net: &mut LivedNet,
                        sh: &mut crate::shell::OsShell,
                        src_ip: [u8; 4],
                        payload: &[u8]|
         -> ReplySet {
            let udp_len = 8 + payload.len();
            let mut udp = [0u8; 256];
            udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
            udp[2..4].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
            udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            udp[8..udp_len].copy_from_slice(payload);
            let uc = crate::net::udp_checksum(src_ip, GUEST_IP, &udp[..udp_len]);
            udp[6..8].copy_from_slice(&uc.to_be_bytes());
            let (frame, flen) = eth_ip(IP_PROTO_UDP, src_ip, GUEST_IP, &udp[..udp_len]);
            let mut out = ReplySet::new();
            net.handle_frame_with_shell(&frame[..flen], 5, sh, &mut out);
            out
        };

        // 1. Unauthenticated mutating UDP command (`CMD write /var/pwned x`) is denied with EACCES.
        let out = send_udp(&mut net, &mut sh, PEER_IP, b"CMD write /var/pwned x");
        assert_eq!(out.len(), 1);
        let reply_str = core::str::from_utf8(&out.get(0).unwrap()[42..]).unwrap();
        assert!(reply_str.starts_with("error: EACCES (unauthenticated UDP"));

        // 2. Authenticated `AUTH 1 <hmac_hex> write /var/ok trusted` succeeds!
        let cmd1 = b"write /var/ok trusted";
        let mut tag1 = [0u8; 32];
        LivedNet::compute_auth_tag(&net.auth_key, b"1", cmd1, &mut tag1);
        let mut auth_pkt = [0u8; 160];
        let mut pos = 0usize;
        pos += copy_msg(b"AUTH 1 ", &mut auth_pkt[pos..]);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in &tag1 {
            auth_pkt[pos] = HEX[(b >> 4) as usize];
            auth_pkt[pos + 1] = HEX[(b & 0x0F) as usize];
            pos += 2;
        }
        pos += copy_msg(b" ", &mut auth_pkt[pos..]);
        pos += copy_msg(cmd1, &mut auth_pkt[pos..]);

        let out = send_udp(&mut net, &mut sh, PEER_IP, &auth_pkt[..pos]);
        assert_eq!(out.len(), 1);
        assert_eq!(&out.get(0).unwrap()[42..], b"wrote 8 bytes to /var/ok\n");

        // 3. Replaying the exact same `AUTH 1 ...` packet is rejected by monotonic sequence check!
        let out_replay = send_udp(&mut net, &mut sh, PEER_IP, &auth_pkt[..pos]);
        assert_eq!(out_replay.len(), 1);
        assert_eq!(
            &out_replay.get(0).unwrap()[42..],
            b"error: EACCES (replay detected: sequence not monotonic)\n"
        );

        // 4. Block attacker CIDR 192.168.99.0/24 via `fw block 192.168.99.0/24` and verify wire drop.
        let mut sh_out = [0u8; 128];
        let _ = sh.exec_line(b"fw block 192.168.99.0/24", 5, 0, 0, &mut sh_out);
        let blocked_out = send_udp(&mut net, &mut sh, [192, 168, 99, 42], b"CMD uname");
        assert_eq!(
            blocked_out.len(),
            0,
            "packet from blocked CIDR must be silently dropped at wire boundary"
        );

        // 5. Simulate morph reboot: pack disk image from Boot 1 and unpack into fresh Boot 2 LivedNet + OsShell.
        let mut hdr_sec = [0u8; 512];
        let mut wal_sec = [0u8; 512];
        let _ = sh.pack_disk_image(5, &mut hdr_sec, &mut wal_sec).unwrap();
        let mut net2 = LivedNet::new(MAC);
        let mut sh2 = crate::shell::OsShell::new();
        let _ = sh2.unpack_disk_image(&hdr_sec, &wal_sec).unwrap();

        // Cross-reboot replay of `AUTH 1 ...` into fresh `net2` (`last_auth_seq == 0`) is defeated by `sh2.auth_seq == 1`!
        let out_cross_replay = send_udp(&mut net2, &mut sh2, PEER_IP, &auth_pkt[..pos]);
        assert_eq!(out_cross_replay.len(), 1);
        assert_eq!(
            &out_cross_replay.get(0).unwrap()[42..],
            b"error: EACCES (replay detected: sequence not monotonic)\n"
        );

        // Blocked CIDR 192.168.99.0/24 remains blocked at the wire boundary on Boot 2!
        let blocked_out2 = send_udp(&mut net2, &mut sh2, [192, 168, 99, 42], b"CMD uname");
        assert_eq!(blocked_out2.len(), 0);
    }

    #[test]
    fn unprovisioned_lived_net_refuses_all_auth_commands() {
        let mut net = LivedNet::new_unprovisioned(MAC);
        let mut sh = crate::shell::OsShell::new();
        let cmd = b"write /var/pwned no";
        let mut tag = [0u8; 32];
        LivedNet::compute_auth_tag(&[0u8; 32], b"1", cmd, &mut tag);
        let mut auth_pkt = [0u8; 160];
        let mut pos = 0usize;
        pos += copy_msg(b"AUTH 1 ", &mut auth_pkt[pos..]);
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for &b in &tag {
            auth_pkt[pos] = HEX[(b >> 4) as usize];
            auth_pkt[pos + 1] = HEX[(b & 0x0F) as usize];
            pos += 2;
        }
        pos += copy_msg(b" ", &mut auth_pkt[pos..]);
        pos += copy_msg(cmd, &mut auth_pkt[pos..]);

        let udp_len = 8 + pos;
        let mut udp = [0u8; 256];
        udp[0..2].copy_from_slice(&40000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp[8..udp_len].copy_from_slice(&auth_pkt[..pos]);
        let uc = crate::net::udp_checksum(PEER_IP, GUEST_IP, &udp[..udp_len]);
        udp[6..8].copy_from_slice(&uc.to_be_bytes());
        let (frame, flen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &udp[..udp_len]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 5, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            &out.get(0).unwrap()[42..],
            b"error: EACCES (device key not provisioned; AUTH disabled)\n"
        );
    }

    #[test]
    fn concurrent_16_slot_tcp_connections_syn_flood_priority_and_rto_work() {
        let mut net = LivedNet::new(MAC);
        let mut server_isns = [0u32; TCP_MAX_SLOTS];

        // 1. Open 16 simultaneous TCP connections on ports 50000..50015 without closing any:
        for slot in 0..TCP_MAX_SLOTS {
            let cport = 50000 + (slot as u16);
            let cisn = 0x1000_0000 + ((slot as u32) << 16);
            let mut syn = [0u8; 40];
            let n = TcpImpl::build_segment(
                cport,
                HTTP_PORT,
                cisn,
                0,
                tcp_flags::SYN,
                65535,
                b"",
                PEER_IP,
                GUEST_IP,
                &mut syn,
            )
            .unwrap();
            let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
            let mut out = ReplySet::new();
            net.handle_frame(&frame[..flen], 7, &mut out);
            assert_eq!(out.len(), 1);
            let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            assert_eq!(sa.flags, tcp_flags::SYN | tcp_flags::ACK);
            server_isns[slot] = sa.seq;
        }
        assert_eq!(net.active_tcp_slots(), 16);

        // 2. Complete the 3-way handshake + HTTP GET on slot 0 (port 50000) so it is `Established`,
        //    leaving slots 1..15 in half-open `SynReceived` state:
        let req = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";
        let mut pkt0 = [0u8; 128];
        let n0 = TcpImpl::build_segment(
            50000,
            HTTP_PORT,
            0x1000_0001,
            server_isns[0].wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req,
            PEER_IP,
            GUEST_IP,
            &mut pkt0,
        )
        .unwrap();
        let (frame0, flen0) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &pkt0[..n0]);
        let mut out0 = ReplySet::new();
        net.handle_frame(&frame0[..flen0], 7, &mut out0);
        assert_eq!(out0.len(), 1);

        // 3. Red Team SYN-flood resistance: even if we touch slots 1..15 or send a burst of
        //    20 new half-open SYN flood packets, slot 0 (`Established`) MUST NEVER be evicted
        //    while any half-open `SynReceived` slot exists!
        for flood in 0..20u16 {
            let mut syn_f = [0u8; 40];
            let nf = TcpImpl::build_segment(
                55000 + flood,
                HTTP_PORT,
                0x8000_0000 + (flood as u32),
                0,
                tcp_flags::SYN,
                65535,
                b"",
                PEER_IP,
                GUEST_IP,
                &mut syn_f,
            )
            .unwrap();
            let (ff, fflen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn_f[..nf]);
            let mut fout = ReplySet::new();
            net.handle_frame(&ff[..fflen], 7, &mut fout);
            assert_eq!(fout.len(), 1);
        }
        assert_eq!(
            net.tcbs[0].state,
            TcpState::Established,
            "Red Team SYN flood must evict half-open SynReceived slots before Established slot 0"
        );
        assert_eq!(net.tcbs[0].remote_port, 50000);

        // 4. Advance RTO timer (`tick_tcp_rto`): after 20 ticks (~80 ms at 250 Hz), half-open
        //    `SynReceived` slots MUST still be alive (since `TCP_HALF_OPEN_RECLAIM_MS = 2,000 ms`),
        //    and after reaching `net.half_open_reclaim_ticks()` (`500` ticks = 2.0 s), all 15
        //    half-open `SynReceived` slots are reclaimed while `Established` slot 0 remains active:
        for _ in 0..20 {
            let _ = net.tick_tcp_rto();
        }
        assert_eq!(
            net.active_tcp_slots(),
            16,
            "Half-open SynReceived slots must not be reclaimed after only 20 ticks (~80 ms at 250 Hz)"
        );
        for _ in 20..net.half_open_reclaim_ticks() {
            let _ = net.tick_tcp_rto();
        }
        assert!(net.rto_retransmits >= 30);
        assert_eq!(
            net.active_tcp_slots(),
            1,
            "RTO reclamation must clean up all stale half-open SynReceived slots after 2 s while preserving Established slot 0"
        );
    }

    #[test]
    fn tcp_timers_scale_with_calibrated_apic_hz_and_keep_half_open_for_2s() {
        use crate::timer::{
            calibrate_apic_irqs_per_sec, LAPIC_TIMER_PERIOD_COUNT, PIT_CALIBRATION_TICKS_10MS,
        };

        // 1. Default 250 Hz calibration (~625,000 LAPIC ticks in 10 ms at 250,000 period):
        let hz_250 = calibrate_apic_irqs_per_sec(
            625_000,
            PIT_CALIBRATION_TICKS_10MS as u32,
            LAPIC_TIMER_PERIOD_COUNT,
        );
        assert_eq!(hz_250, 250);
        let mut net250 = LivedNet::new(MAC);
        net250.set_timer_hz(hz_250);
        assert_eq!(net250.rto_retransmit_ticks(), 250); // 1,000 ms @ 250 Hz
        assert_eq!(net250.half_open_reclaim_ticks(), 500); // 2,000 ms @ 250 Hz
        assert_eq!(net250.idle_timeout_ticks(), 4096); // 16,384 ms @ 250 Hz

        // 2. Slower 62 Hz APIC bus (~155,000 LAPIC ticks in 10 ms at 250,000 period):
        let hz_62 = calibrate_apic_irqs_per_sec(
            155_000,
            PIT_CALIBRATION_TICKS_10MS as u32,
            LAPIC_TIMER_PERIOD_COUNT,
        );
        assert_eq!(hz_62, 62);
        let mut net62 = LivedNet::new(MAC);
        net62.set_timer_hz(hz_62);
        assert_eq!(net62.rto_retransmit_ticks(), 62); // 1,000 ms @ 62 Hz
        assert_eq!(net62.half_open_reclaim_ticks(), 124); // 2,000 ms @ 62 Hz
        assert_eq!(net62.idle_timeout_ticks(), 1016); // ~16.39 s @ 62 Hz (not 66 s!)

        // Open a half-open SynReceived slot on `net62` and verify it survives 123 ticks (1.98 s)
        // and is reclaimed on tick 124 (2.00 s):
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            51234,
            HTTP_PORT,
            0x2222_0000,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net62.handle_frame(&frame[..flen], 1, &mut out);
        assert_eq!(net62.active_tcp_slots(), 1);
        for _ in 0..123 {
            let _ = net62.tick_tcp_rto();
        }
        assert_eq!(
            net62.active_tcp_slots(),
            1,
            "Half-open slot at 62 Hz must survive 123 ticks (1.98 s)"
        );
        let _ = net62.tick_tcp_rto();
        assert_eq!(
            net62.active_tcp_slots(),
            0,
            "Half-open slot at 62 Hz must be reclaimed at tick 124 (2.00 s)"
        );
    }

    #[test]
    fn https_port_is_closed_until_tls_is_enabled() {
        let mut net = LivedNet::new(MAC);
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            54443, HTTPS_PORT, 0x4430_0000, 0, tcp_flags::SYN, 65535, b"", PEER_IP, GUEST_IP, &mut syn,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 1, &mut out);
        assert!(out.is_empty(), "no SYN-ACK on 443 before enable_tls");
        assert_eq!(net.active_tcp_slots(), 0);
        assert!(!net.tls_enabled());
    }

    #[test]
    fn triad_peer_to_peer_replication_2_of_3_quorum_and_redteam_divergence_work() {
        // Construct 3 independent in-guest Triad nodes (Node 0, Node 1, Node 2) sharing the cluster key:
        let mut net0 = LivedNet::new(MAC);
        let mut sh0 = crate::shell::OsShell::new();
        sh0.triad_node_id = 0;

        let mut net1 = LivedNet::new(MAC);
        let mut sh1 = crate::shell::OsShell::new();
        sh1.triad_node_id = 1;

        let mut net2 = LivedNet::new(MAC);
        let mut sh2 = crate::shell::OsShell::new();
        sh2.triad_node_id = 2;

        let send_triad_udp = |net: &mut LivedNet,
                              sh: &mut crate::shell::OsShell,
                              payload: &[u8]|
         -> ReplySet {
            let udp_len = 8 + payload.len();
            let mut udp = [0u8; 512];
            udp[0..2].copy_from_slice(&41000u16.to_be_bytes());
            udp[2..4].copy_from_slice(&TRIAD_REPL_PORT.to_be_bytes());
            udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            udp[8..udp_len].copy_from_slice(payload);
            let uc = crate::net::udp_checksum(PEER_IP, GUEST_IP, &udp[..udp_len]);
            udp[6..8].copy_from_slice(&uc.to_be_bytes());
            let (frame, flen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &udp[..udp_len]);
            let mut out = ReplySet::new();
            net.handle_frame_with_shell(&frame[..flen], 1, sh, &mut out);
            out
        };

        // 1. Leader (Node 0) proposes a SQL mutation (`triad propose INSERT ...`):
        let sql = b"INSERT INTO kv VALUES ('cluster.leader', 'node0', 1)";
        let mut cmd_buf = [0u8; 128];
        let mut cpos = 0usize;
        cpos += copy_msg(b"triad propose ", &mut cmd_buf[cpos..]);
        cpos += copy_msg(sql, &mut cmd_buf[cpos..]);
        let mut sh_out = [0u8; 256];
        let n = sh0.exec_line(&cmd_buf[..cpos], 1, 0, 0, &mut sh_out).bytes_written();
        let prop_str = core::str::from_utf8(&sh_out[..n]).unwrap();
        assert!(prop_str.starts_with("triad: proposed seq=1 node=0 hash="), "got {prop_str:?}");

        // 2. Build signed `TRIAD_PREPARE 1 0 <hmac_hex64> <sql>` and replicate to Follower Node 1:
        let mut prep_mac = [0u8; 32];
        LivedNet::compute_triad_prepare_tag(&DEFAULT_NET_AUTH_KEY, b"1", b"0", sql, &mut prep_mac);
        let mut prep_hex = [0u8; 64];
        hex_encode_bytes(&prep_mac, &mut prep_hex);
        let mut prep_pkt = [0u8; 256];
        let mut ppos = 0usize;
        ppos += copy_msg(b"TRIAD_PREPARE 1 0 ", &mut prep_pkt[ppos..]);
        ppos += copy_msg(&prep_hex, &mut prep_pkt[ppos..]);
        ppos += copy_msg(b" ", &mut prep_pkt[ppos..]);
        ppos += copy_msg(sql, &mut prep_pkt[ppos..]);

        let ack1_out = send_triad_udp(&mut net1, &mut sh1, &prep_pkt[..ppos]);
        assert_eq!(ack1_out.len(), 1);
        let ack1_payload = &ack1_out.get(0).unwrap()[42..];
        let ack1_str = core::str::from_utf8(ack1_payload).unwrap();
        assert!(ack1_str.starts_with("TRIAD_ACK 1 1 "), "got {ack1_str:?}");
        assert_eq!(sh1.db.state_hash(), sh0.db.state_hash());

        // 3. Red Team Replay Check: re-sending `TRIAD_PREPARE 1 ...` to Node 1 is rejected!
        let replay_out = send_triad_udp(&mut net1, &mut sh1, &prep_pkt[..ppos]);
        let replay_str = core::str::from_utf8(&replay_out.get(0).unwrap()[42..]).unwrap();
        assert!(replay_str.starts_with("error: EACCES (triad replay detected"));

        // 4. Feed Follower Node 1's signed `TRIAD_ACK` back to Leader Node 0 on UDP `:8081`:
        let q_out = send_triad_udp(&mut net0, &mut sh0, ack1_payload);
        let q_str = core::str::from_utf8(&q_out.get(0).unwrap()[42..]).unwrap();
        assert!(
            q_str.starts_with("TRIAD_QUORUM seq=1 quorum=2/3 hash="),
            "expected 2-of-3 quorum commit on Node 0, got {q_str:?}"
        );
        assert_eq!(sh0.triad_quorum_count(), 2);
        assert_eq!(sh0.triad_quorum_commits, 1);

        // 5. Red Team Split-Brain / Tampered Follower Detection:
        //    Suppose Node 2 has a diverging SQL state hash (`0xdeadbeefcafebabe`) at `seq=1`
        //    and sends a validly signed `TRIAD_ACK 1 2 deadbeefcafebabe <hmac>` to Node 0:
        let bad_hash_hex = b"deadbeefcafebabe";
        let mut ack2_mac = [0u8; 32];
        LivedNet::compute_triad_ack_tag(
            &DEFAULT_NET_AUTH_KEY,
            b"1",
            b"2",
            bad_hash_hex,
            &mut ack2_mac,
        );
        let mut ack2_hex = [0u8; 64];
        hex_encode_bytes(&ack2_mac, &mut ack2_hex);
        let mut ack2_pkt = [0u8; 160];
        let mut a2pos = 0usize;
        a2pos += copy_msg(b"TRIAD_ACK 1 2 ", &mut ack2_pkt[a2pos..]);
        a2pos += copy_msg(bad_hash_hex, &mut ack2_pkt[a2pos..]);
        a2pos += copy_msg(b" ", &mut ack2_pkt[a2pos..]);
        a2pos += copy_msg(&ack2_hex, &mut ack2_pkt[a2pos..]);

        let div_out = send_triad_udp(&mut net0, &mut sh0, &ack2_pkt[..a2pos]);
        let div_str = core::str::from_utf8(&div_out.get(0).unwrap()[42..]).unwrap();
        assert!(
            div_str.contains("TRIAD_ALERT seq=1 peer=2 status=DIVERGENCE"),
            "divergent peer state hash must trigger TRIAD_ALERT, got {div_str:?}"
        );
        assert_eq!(sh0.triad_divergences, 1);

        // 6. Replicate `TRIAD_PREPARE 1` to Node 2 so all 3 nodes converge to 3-of-3 quorum:
        let ack2_good = send_triad_udp(&mut net2, &mut sh2, &prep_pkt[..ppos]);
        let q3_out = send_triad_udp(&mut net0, &mut sh0, &ack2_good.get(0).unwrap()[42..]);
        let q3_str = core::str::from_utf8(&q3_out.get(0).unwrap()[42..]).unwrap();
        assert!(q3_str.starts_with("TRIAD_QUORUM seq=1 quorum=3/3 hash="));
        assert_eq!(sh0.triad_quorum_count(), 3);
    }

    #[test]
    fn dynamic_web_sessions_sql_db_exec_and_vfs_server_work() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();
        let mut out = [0u8; 1380];

        // 1. Dynamic HTML dashboard before login:
        let n = net.handle_http_request(
            b"GET /app HTTP/1.1\r\nHost: x\r\n\r\n",
            4,
            Some(&mut sh),
            &mut out,
        );
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"));
        assert!(s.contains("boots=4 files=4 sql_tables=2 sql_rows=5 sessions=0"));
        assert!(s.ends_with("</script></body></html>\n"));

        // 2. Unauthenticated mutating SQL and remote exec are rejected with 401:
        let n = net.handle_http_request(
            b"POST /sql HTTP/1.1\r\nHost: x\r\n\r\nINSERT INTO kv VALUES ('x', 'y', 1)",
            4,
            Some(&mut sh),
            &mut out,
        );
        assert!(out[..n].starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));

        let n = net.handle_http_request(
            b"POST /exec HTTP/1.1\r\nHost: x\r\n\r\n/bin/fib 12",
            4,
            Some(&mut sh),
            &mut out,
        );
        assert!(out[..n].starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));

        // 3. Read-only SQL SELECT succeeds without a session:
        let n = net.handle_http_request(
            b"POST /sql HTTP/1.1\r\nHost: x\r\n\r\nSELECT name, port FROM services WHERE id = 2",
            4,
            Some(&mut sh),
            &mut out,
        );
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.ends_with("\r\n\r\nname|port\nhttps-tls13|443\n"));

        // 4. Authenticate and mint a dynamic session via POST /session/login:
        let mut mac = [0u8; 32];
        LivedNet::compute_http_login_tag(&DEFAULT_NET_AUTH_KEY, b"1", b"admin", &mut mac);
        let mut hex_mac = [0u8; 64];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, &b) in mac.iter().enumerate() {
            hex_mac[i * 2] = HEX[(b >> 4) as usize];
            hex_mac[i * 2 + 1] = HEX[(b & 0x0F) as usize];
        }
        let mut login_req = [0u8; 256];
        let mut pos = 0usize;
        pos += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n1 ", &mut login_req[pos..]);
        pos += copy_msg(&hex_mac, &mut login_req[pos..]);
        pos += copy_msg(b" admin", &mut login_req[pos..]);
        let n = net.handle_http_request(&login_req[..pos], 4, Some(&mut sh), &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nSet-Cookie: sid="));
        let view = HttpImpl::parse_request(
            b"GET / HTTP/1.1\r\nHost: x\r\n\r\n",
        ).unwrap();
        let _ = view;
        // Extract the 32-char sid from "sid=<32hex>" in body:
        let sid_pos = s.find("sid=").unwrap() + 4;
        let mut sid_buf = [0u8; 32];
        sid_buf.copy_from_slice(&s.as_bytes()[sid_pos..sid_pos + 32]);
        let sid = &sid_buf;

        // 5. Verify GET /session/whoami using `Cookie: sid=<32hex>`:
        let mut who_req = [0u8; 256];
        let mut wpos = 0usize;
        wpos += copy_msg(b"GET /session/whoami HTTP/1.1\r\nCookie: sid=", &mut who_req[wpos..]);
        wpos += copy_msg(sid, &mut who_req[wpos..]);
        wpos += copy_msg(b"\r\n\r\n", &mut who_req[wpos..]);
        let n = net.handle_http_request(&who_req[..wpos], 4, Some(&mut sh), &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.contains("whoami: user=admin reqs=1 sid="));

        // 5b. Verify unauthenticated GET /app does NOT leak the active session token,
        // while authenticated GET /app with Cookie: sid=<32hex> populates session_user:
        let n_unauth = net.handle_http_request(
            b"GET /app HTTP/1.1\r\nHost: x\r\n\r\n",
            4,
            Some(&mut sh),
            &mut out,
        );
        let s_unauth = core::str::from_utf8(&out[..n_unauth]).unwrap();
        let sid_str = core::str::from_utf8(sid).unwrap();
        assert!(
            !s_unauth.contains(sid_str),
            "unauthenticated GET /app must never leak an active session token"
        );

        let mut app_req = [0u8; 256];
        let mut apos = 0usize;
        apos += copy_msg(b"GET /app HTTP/1.1\r\nCookie: sid=", &mut app_req[apos..]);
        apos += copy_msg(sid, &mut app_req[apos..]);
        apos += copy_msg(b"\r\n\r\n", &mut app_req[apos..]);
        let n = net.handle_http_request(&app_req[..apos], 4, Some(&mut sh), &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.contains("session_user=admin"));
        assert!(s.ends_with("</script></body></html>\n"));

        let mut sh_req = [0u8; 256];
        let mut shpos = 0usize;
        shpos += copy_msg(b"POST /sh HTTP/1.1\r\nX-Session-Token: ", &mut sh_req[shpos..]);
        shpos += copy_msg(sid, &mut sh_req[shpos..]);
        shpos += copy_msg(b"\r\n\r\nstatus", &mut sh_req[shpos..]);
        let n = net.handle_http_request(&sh_req[..shpos], 4, Some(&mut sh), &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(s.contains("boots=4"));

        // 6. Execute authenticated mutating SQL INSERT + SELECT over HTTP:
        let mut sql_req = [0u8; 256];
        let mut spos = 0usize;
        spos += copy_msg(b"POST /sql HTTP/1.1\r\nCookie: sid=", &mut sql_req[spos..]);
        spos += copy_msg(sid, &mut sql_req[spos..]);
        spos += copy_msg(
            b"\r\n\r\nINSERT INTO kv VALUES ('web.user', 'admin', 3)",
            &mut sql_req[spos..],
        );
        let n = net.handle_http_request(&sql_req[..spos], 4, Some(&mut sh), &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.ends_with("\r\n\r\nINSERT 1\n"));
        // Verify that `svc-sql`'s mailbox staged and executed the exact SQL mutation:
        let sql_mb = &sh.svc.services[crate::svc_runtime::ServiceId::Sql.index()].mailbox;
        assert_eq!(sql_mb.last_op, crate::svc_runtime::IpcOp::SqlMutate as u8);
        assert_eq!(sql_mb.last_status, 200);
        assert_eq!(
            &sql_mb.req_body[..sql_mb.req_body_len as usize],
            b"INSERT INTO kv VALUES ('web.user', 'admin', 3)"
        );

        let n = net.handle_http_request(
            b"POST /sql HTTP/1.1\r\nHost: x\r\n\r\nSELECT v, rev FROM kv WHERE k = 'web.user'",
            4,
            Some(&mut sh),
            &mut out,
        );
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.ends_with("\r\n\r\nv|rev\nadmin|3\n"));

        // 7. Execute authenticated sandboxed ELF64/eBPF code via POST /exec:
        let mut exec_req = [0u8; 256];
        let mut epos = 0usize;
        epos += copy_msg(b"POST /exec HTTP/1.1\r\nCookie: sid=", &mut exec_req[epos..]);
        epos += copy_msg(sid, &mut exec_req[epos..]);
        epos += copy_msg(b"\r\n\r\n/bin/fib 12", &mut exec_req[epos..]);
        let n = net.handle_http_request(&exec_req[..epos], 4, Some(&mut sh), &mut out);
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.ends_with("\r\n\r\nexec: path=/bin/fib entry=4198400 kpti=isolated insns=11 ret=144\n"));

        // 8. Author and serve an HTML page from the VFS via PUT/GET /fs/var/index.html:
        let mut put_req = [0u8; 256];
        let mut ppos = 0usize;
        ppos += copy_msg(b"PUT /fs/var/index.html HTTP/1.1\r\nCookie: sid=", &mut put_req[ppos..]);
        ppos += copy_msg(sid, &mut put_req[ppos..]);
        ppos += copy_msg(b"\r\n\r\n<h1>Hello Cuttle</h1>", &mut put_req[ppos..]);
        let n = net.handle_http_request(&put_req[..ppos], 4, Some(&mut sh), &mut out);
        assert!(out[..n].starts_with(b"HTTP/1.1 201 Created\r\n"));
        // Verify `svc-sh`'s mailbox staged the VFS path and body and recorded status 201:
        let sh_mb = &sh.svc.services[crate::svc_runtime::ServiceId::Shell.index()].mailbox;
        assert_eq!(sh_mb.last_op, crate::svc_runtime::IpcOp::VfsWrite as u8);
        assert_eq!(sh_mb.last_status, 201);
        assert_eq!(&sh_mb.req_path[..sh_mb.req_path_len as usize], b"/var/index.html");
        assert_eq!(&sh_mb.req_body[..sh_mb.req_body_len as usize], b"<h1>Hello Cuttle</h1>");

        let n = net.handle_http_request(
            b"GET /fs/var/index.html HTTP/1.1\r\nHost: x\r\n\r\n",
            4,
            Some(&mut sh),
            &mut out,
        );
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"));
        assert!(s.ends_with("\r\n\r\n<h1>Hello Cuttle</h1>"));
    }

    #[test]
    fn every_endpoint_without_credentials_and_role_isolated_services_are_refused() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();
        let mut out = [0u8; 1380];

        // 1. Standing Rule (Step 6): Call EVERY credentialed endpoint with NO credentials and with FORGED credentials;
        //    every single one must be refused with 401 Unauthorized.
        let unauthed_requests: &[&[u8]] = &[
            b"GET /session/whoami HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /session/whoami HTTP/1.1\r\nCookie: sid=00000000000000000000000000000000\r\n\r\n",
            b"POST /session/logout HTTP/1.1\r\nHost: x\r\n\r\n",
            b"POST /session/logout HTTP/1.1\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\n\r\n",
            b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n1 0000000000000000000000000000000000000000000000000000000000000000 admin",
            b"GET /sql?DELETE+FROM+kv HTTP/1.1\r\nHost: x\r\n\r\n",
            b"GET /db?DROP+TABLE+kv HTTP/1.1\r\nHost: x\r\n\r\n",
            b"POST /sql HTTP/1.1\r\nHost: x\r\n\r\nINSERT INTO kv VALUES ('pwn', '1', 1)",
            b"POST /db HTTP/1.1\r\nHost: x\r\n\r\nDELETE FROM kv",
            b"POST /sh HTTP/1.1\r\nHost: x\r\n\r\nstatus",
            b"POST /sh HTTP/1.1\r\nX-Session-Token: 11111111111111111111111111111111\r\n\r\nwrite /var/x 1",
            b"POST /exec HTTP/1.1\r\nHost: x\r\n\r\n/bin/fib 10",
            b"PUT /fs/var/pwn.txt HTTP/1.1\r\nHost: x\r\n\r\npwned",
            b"DELETE /fs/etc/hostname HTTP/1.1\r\nHost: x\r\n\r\n",
        ];
        for req in unauthed_requests {
            let n = net.handle_http_request(req, 1, Some(&mut sh), &mut out);
            assert!(
                out[..n].starts_with(b"HTTP/1.1 401 Unauthorized\r\n"),
                "endpoint {:?} must return 401 Unauthorized when called without valid credentials, got: {:?}",
                core::str::from_utf8(req).unwrap(),
                core::str::from_utf8(&out[..n]).unwrap()
            );
        }

        // 2. Role Isolation (`NodeRole::Wfe`): only `svc-http` is loaded in memory (`svc-sql` and `svc-sh` unloaded).
        let sid = sh.create_session(b"admin", b"role-test");
        sh.svc.set_role(crate::svc_runtime::NodeRole::Wfe, &mut sh.audit);
        // `svc-http` endpoints (`GET /status`, `GET /app`) remain 200 OK:
        let n_ok = net.handle_http_request(
            b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n",
            1,
            Some(&mut sh),
            &mut out,
        );
        assert!(out[..n_ok].starts_with(b"HTTP/1.1 200 OK\r\n"));

        // Unauthenticated `svc-http` credentialed endpoints (`GET /session/whoami`, `POST /session/logout`) still return 401 on `Wfe`:
        let n_wfe_401 = net.handle_http_request(
            b"GET /session/whoami HTTP/1.1\r\nHost: x\r\n\r\n",
            1,
            Some(&mut sh),
            &mut out,
        );
        assert!(out[..n_wfe_401].starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));

        // Unauthenticated `svc-sql` and `svc-sh` endpoints on `Wfe` return 503 Service Unavailable (role disabled precedes 401):
        for wfe_disabled_req in &[
            &b"GET /sql?SELECT+*+FROM+kv HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"GET /sql?DELETE+FROM+kv HTTP/1.1\r\nHost: x\r\n\r\n"[..],
            &b"POST /sql HTTP/1.1\r\nHost: x\r\n\r\nINSERT INTO kv VALUES ('pwn', '1', 1)"[..],
            &b"POST /sh HTTP/1.1\r\nHost: x\r\n\r\nstatus"[..],
            &b"POST /exec HTTP/1.1\r\nHost: x\r\n\r\n/bin/fib 10"[..],
            &b"PUT /fs/var/pwn.txt HTTP/1.1\r\nHost: x\r\n\r\npwned"[..],
            &b"DELETE /fs/etc/hostname HTTP/1.1\r\nHost: x\r\n\r\n"[..],
        ] {
            let n_dis = net.handle_http_request(wfe_disabled_req, 1, Some(&mut sh), &mut out);
            assert!(
                out[..n_dis].starts_with(b"HTTP/1.1 503 "),
                "Wfe disabled endpoint {:?} must return 503, got {:?}",
                core::str::from_utf8(wfe_disabled_req).unwrap(),
                core::str::from_utf8(&out[..n_dis]).unwrap()
            );
        }

        // Authenticated `svc-sh` request on `Wfe` is also refused with 503:
        let mut sh_req = [0u8; 256];
        let mut p = 0usize;
        p += copy_msg(b"POST /sh HTTP/1.1\r\nCookie: sid=", &mut sh_req[p..]);
        p += copy_msg(&sid, &mut sh_req[p..]);
        p += copy_msg(b"\r\n\r\nstatus", &mut sh_req[p..]);
        let n_sh = net.handle_http_request(&sh_req[..p], 1, Some(&mut sh), &mut out);
        assert!(out[..n_sh].starts_with(b"HTTP/1.1 503 "));

        // 3. Role Isolation (`NodeRole::Sql` and `NodeRole::Shell`): `svc-http` is unloaded, so all HTTP endpoints return 503.
        //    Verify that `POST /session/logout` on a `Sql` node returns 503 WITHOUT revoking the active session!
        for role in [crate::svc_runtime::NodeRole::Sql, crate::svc_runtime::NodeRole::Shell] {
            sh.svc.set_role(role, &mut sh.audit);
            let n_http_off = net.handle_http_request(
                b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n",
                1,
                Some(&mut sh),
                &mut out,
            );
            assert!(out[..n_http_off].starts_with(b"HTTP/1.1 503 "));

            let mut logout_req = [0u8; 256];
            let mut lp = 0usize;
            lp += copy_msg(b"POST /session/logout HTTP/1.1\r\nCookie: sid=", &mut logout_req[lp..]);
            lp += copy_msg(&sid, &mut logout_req[lp..]);
            lp += copy_msg(b"\r\n\r\n", &mut logout_req[lp..]);
            let n_logout = net.handle_http_request(&logout_req[..lp], 1, Some(&mut sh), &mut out);
            assert!(out[..n_logout].starts_with(b"HTTP/1.1 503 "));
            assert!(
                sh.validate_session(&sid).is_some(),
                "session must not be revoked when POST /session/logout is refused by role policy"
            );
        }

        // 4. Brute-force login rate limiting (Red Team timer-vs-request test):
        //    5 consecutive failed logins trigger an 8-tick hardware timer cooldown (429).
        //    Verify that flooding 32 HTTP `GET /healthz` / `GET /status` requests does NOT
        //    advance or clear the cooldown — only hardware timer ticks (`sh.tick_login_cooldown()`) do!
        sh.svc.set_role(crate::svc_runtime::NodeRole::Full, &mut sh.audit);
        for seq in 2..=6 {
            let mut bad_login = [0u8; 160];
            let mut bp = 0usize;
            bp += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n", &mut bad_login[bp..]);
            bp += dec_u64(seq, &mut bad_login[bp..]);
            bp += copy_msg(
                b" 0000000000000000000000000000000000000000000000000000000000000000 admin",
                &mut bad_login[bp..],
            );
            let n_bad = net.handle_http_request(&bad_login[..bp], 1, Some(&mut sh), &mut out);
            assert!(out[..n_bad].starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        }
        assert!(sh.is_login_rate_limited());
        assert_eq!(sh.login_cooldown_ticks, 8);

        // Red Team: Flood 32 fast `GET /healthz` and `GET /status` requests and verify
        // that `login_cooldown_ticks` remains pinned at 8!
        for _ in 0..32 {
            let _ = net.handle_http_request(
                b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
                1,
                Some(&mut sh),
                &mut out,
            );
        }
        assert!(sh.is_login_rate_limited());
        assert_eq!(
            sh.login_cooldown_ticks, 8,
            "non-login HTTP requests must never advance or clear the login brute-force cooldown"
        );

        let n_ratelimited = net.handle_http_request(
            b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n99 0000000000000000000000000000000000000000000000000000000000000000 admin",
            1,
            Some(&mut sh),
            &mut out,
        );
        assert!(out[..n_ratelimited].starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
        assert_eq!(
            sh.login_cooldown_ticks, 8,
            "rate-limited POST /session/login must not advance the login cooldown either"
        );

        // Now advance the timer 8 ticks (driven in the kernel by Local APIC timer IRQs):
        for _ in 0..8 {
            sh.tick_login_cooldown();
        }
        assert!(!sh.is_login_rate_limited());
        let mut mac_ok = [0u8; 32];
        LivedNet::compute_http_login_tag(&DEFAULT_NET_AUTH_KEY, b"100", b"admin", &mut mac_ok);
        let mut hex_ok = [0u8; 64];
        const HEX: &[u8; 16] = b"0123456789abcdef";
        for (i, &b) in mac_ok.iter().enumerate() {
            hex_ok[i * 2] = HEX[(b >> 4) as usize];
            hex_ok[i * 2 + 1] = HEX[(b & 0x0F) as usize];
        }
        let mut ok_login = [0u8; 180];
        let mut op = 0usize;
        op += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n100 ", &mut ok_login[op..]);
        op += copy_msg(&hex_ok, &mut ok_login[op..]);
        op += copy_msg(b" admin", &mut ok_login[op..]);
        let n_login_ok = net.handle_http_request(&ok_login[..op], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_login_ok].starts_with(b"HTTP/1.1 200 OK\r\n"),
            "valid login must succeed after the brute-force cooldown window expires"
        );
    }

    #[test]
    fn http_vault_guard_and_cron_endpoints_work() {
        let mut net = LivedNet::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let mut sh = crate::shell::OsShell::new();
        let mut out = [0u8; 1500];
        let sid = sh.create_session(b"admin", b"app-test");

        let mk_req = |method: &[u8], path: &[u8], body: &[u8]| -> ([u8; 320], usize) {
            let mut buf = [0u8; 320];
            let mut p = 0usize;
            p += copy_msg(method, &mut buf[p..]);
            p += copy_msg(b" ", &mut buf[p..]);
            p += copy_msg(path, &mut buf[p..]);
            p += copy_msg(b" HTTP/1.1\r\nCookie: sid=", &mut buf[p..]);
            p += copy_msg(&sid, &mut buf[p..]);
            p += copy_msg(b"\r\n\r\n", &mut buf[p..]);
            p += copy_msg(body, &mut buf[p..]);
            (buf, p)
        };

        // 1. CuttleVault HTTP endpoints (`PUT /vault/<key>`, `GET /vault/<key>`, `GET /vault/list`, `DELETE /vault/<key>`)
        let (req, rlen) = mk_req(b"PUT", b"/vault/master_pw", b"top_secret_9");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.starts_with("HTTP/1.1 200 OK\r\n")
                && resp.contains("vault: sealed key=master_pw ct="),
            "got: {resp}"
        );

        let (req, rlen) = mk_req(b"GET", b"/vault/master_pw", b"");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.contains("vault: key=master_pw value=top_secret_9 verified=true"),
            "got: {resp}"
        );

        let (req, rlen) = mk_req(b"GET", b"/vault/list", b"");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.contains("k|v|rev\nv:master_pw|"),
            "got: {resp}"
        );

        // 2. CuttleGuard HTTP endpoints (`GET /guard`, `POST /guard`, `GET /guard/alerts`)
        let (req, rlen) = mk_req(b"GET", b"/guard", b"");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(resp.contains("guard: posture=NORMAL"), "got: {resp}");

        let (req, rlen) = mk_req(b"POST", b"/guard", b"lockdown");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.contains("guard: posture=LOCKDOWN vault=sealed"),
            "got: {resp}"
        );

        // Vault unseal is blocked while Guard lockdown is active:
        let (req, rlen) = mk_req(b"GET", b"/vault/master_pw", b"");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.contains("error: EACCES (vault sealed by CuttleGuard lockdown)"),
            "got: {resp}"
        );

        let (req, rlen) = mk_req(b"POST", b"/guard", b"unlock");
        let _ = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);

        // 3. CuttleChronos HTTP endpoints (`POST /cron`, `GET /cron`)
        let (req, rlen) = mk_req(b"POST", b"/cron", b"add 2 status");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.contains("cron: scheduled id=1 every=2t cmd=\"status\""),
            "got: {resp}"
        );

        let (req, rlen) = mk_req(b"GET", b"/cron", b"");
        let n = net.handle_http_request(&req[..rlen], 1, Some(&mut sh), &mut out);
        let resp = core::str::from_utf8(&out[..n]).unwrap();
        assert!(
            resp.contains("id=1 every=2t elapsed=0t runs=0 cmd=\"status\""),
            "got: {resp}"
        );

        // 4. Oversized IPC mailbox path (> 64 bytes) or body (> 256 bytes) returns 413 Payload Too Large:
        let mut big_sql = [b'A'; 360];
        let mut p = 0usize;
        p += copy_msg(b"POST /sql HTTP/1.1\r\nCookie: sid=", &mut big_sql[p..]);
        p += copy_msg(&sid, &mut big_sql[p..]);
        p += copy_msg(b"\r\n\r\nSELECT '", &mut big_sql[p..]);
        p += 260;
        let n_413 = net.handle_http_request(&big_sql[..p], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_413].starts_with(b"HTTP/1.1 413 "),
            "oversized POST /sql body must return HTTP 413, got {:?}",
            core::str::from_utf8(&out[..n_413]).unwrap()
        );

        let mut big_fs = [b'a'; 160];
        let mut fp = 0usize;
        fp += copy_msg(b"PUT /fs/", &mut big_fs[fp..]);
        fp += 68;
        fp += copy_msg(b" HTTP/1.1\r\nCookie: sid=", &mut big_fs[fp..]);
        fp += copy_msg(&sid, &mut big_fs[fp..]);
        fp += copy_msg(b"\r\n\r\nhi", &mut big_fs[fp..]);
        let n_fs_413 = net.handle_http_request(&big_fs[..fp], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_fs_413].starts_with(b"HTTP/1.1 413 "),
            "oversized VFS path (> 64 bytes) must return HTTP 413, got {:?}",
            core::str::from_utf8(&out[..n_fs_413]).unwrap()
        );

        // 5. Multi-session SQL transaction isolation over HTTP:
        let sid2 = sh.create_session(b"admin", b"app-test-2");
        let (req_begin, rlen_b) = mk_req(b"POST", b"/sql", b"BEGIN");
        let _ = net.handle_http_request(&req_begin[..rlen_b], 1, Some(&mut sh), &mut out);
        let mut s2_req = [0u8; 256];
        let mut s2p = 0usize;
        s2p += copy_msg(b"POST /sql HTTP/1.1\r\nCookie: sid=", &mut s2_req[s2p..]);
        s2p += copy_msg(&sid2, &mut s2_req[s2p..]);
        s2p += copy_msg(
            b"\r\n\r\nINSERT INTO kv VALUES ('hijack', 'x', 1)",
            &mut s2_req[s2p..],
        );
        let n_busy = net.handle_http_request(&s2_req[..s2p], 1, Some(&mut sh), &mut out);
        let resp_busy = core::str::from_utf8(&out[..n_busy]).unwrap();
        assert!(
            resp_busy.contains("error: EBUSY (database locked by another session's transaction)"),
            "got: {resp_busy}"
        );
        let (req_rb, rlen_rb) = mk_req(b"POST", b"/sql", b"ROLLBACK");
        let _ = net.handle_http_request(&req_rb[..rlen_rb], 1, Some(&mut sh), &mut out);
    }

    #[test]
    fn regression_item2_http_oversized_body_returns_413() {
        let mut net = LivedNet::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x9A]);
        let mut sh = crate::shell::OsShell::new();
        let sid = sh.create_session(b"admin", b"item2-http");
        let mut out = [0u8; 768];

        let mut big_sql = [b'A'; 360];
        let mut p = 0usize;
        p += copy_msg(b"POST /sql HTTP/1.1\r\nCookie: sid=", &mut big_sql[p..]);
        p += copy_msg(&sid, &mut big_sql[p..]);
        p += copy_msg(b"\r\n\r\nSELECT '", &mut big_sql[p..]);
        p += 260;
        let n_413 = net.handle_http_request(&big_sql[..p], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_413].starts_with(b"HTTP/1.1 413 "),
            "oversized POST /sql body (> 256B) must return HTTP 413, got {:?}",
            core::str::from_utf8(&out[..n_413]).unwrap()
        );

        let mut big_fs = [b'a'; 160];
        let mut fp = 0usize;
        fp += copy_msg(b"PUT /fs/", &mut big_fs[fp..]);
        fp += 68;
        fp += copy_msg(b" HTTP/1.1\r\nCookie: sid=", &mut big_fs[fp..]);
        fp += copy_msg(&sid, &mut big_fs[fp..]);
        fp += copy_msg(b"\r\n\r\nhi", &mut big_fs[fp..]);
        let n_fs_413 = net.handle_http_request(&big_fs[..fp], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_fs_413].starts_with(b"HTTP/1.1 413 "),
            "oversized PUT /fs/ path (> 64B) must return HTTP 413, got {:?}",
            core::str::from_utf8(&out[..n_fs_413]).unwrap()
        );
    }

    #[test]
    fn regression_item3_http_session_sql_isolation_and_read_committed() {
        let mut net = LivedNet::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x9B]);
        let mut sh = crate::shell::OsShell::new();
        let sid1 = sh.create_session(b"admin", b"s1");
        let sid2 = sh.create_session(b"admin", b"s2");
        let mut out = [0u8; 768];

        let mk_sid_req = |sid: &[u8; 32], body: &[u8]| -> ([u8; 256], usize) {
            let mut buf = [0u8; 256];
            let mut p = 0usize;
            p += copy_msg(b"POST /sql HTTP/1.1\r\nCookie: sid=", &mut buf[p..]);
            p += copy_msg(sid, &mut buf[p..]);
            p += copy_msg(b"\r\n\r\n", &mut buf[p..]);
            p += copy_msg(body, &mut buf[p..]);
            (buf, p)
        };

        let (r1, l1) = mk_sid_req(&sid1, b"BEGIN");
        let _ = net.handle_http_request(&r1[..l1], 1, Some(&mut sh), &mut out);
        let (r2, l2) = mk_sid_req(&sid1, b"UPDATE kv SET v = 'dirty-s1' WHERE k = 'cluster.role'");
        let _ = net.handle_http_request(&r2[..l2], 1, Some(&mut sh), &mut out);

        // Session 2 SELECT must see committed 'primary', not Session 1's uncommitted 'dirty-s1':
        let (r3, l3) = mk_sid_req(&sid2, b"SELECT v FROM kv WHERE k = 'cluster.role'");
        let n_sel = net.handle_http_request(&r3[..l3], 1, Some(&mut sh), &mut out);
        let resp_sel = core::str::from_utf8(&out[..n_sel]).unwrap();
        assert!(
            resp_sel.contains("v\nprimary\n") && !resp_sel.contains("dirty-s1"),
            "Session 2 must see Read Committed snapshot, got: {resp_sel}"
        );

        // Session 2 write attempt during Session 1's transaction is refused with EBUSY:
        let (r4, l4) = mk_sid_req(&sid2, b"INSERT INTO kv VALUES ('x', 'y', 1)");
        let n_busy = net.handle_http_request(&r4[..l4], 1, Some(&mut sh), &mut out);
        let resp_busy = core::str::from_utf8(&out[..n_busy]).unwrap();
        assert!(
            resp_busy.contains("error: EBUSY (database locked by another session's transaction)"),
            "got: {resp_busy}"
        );

        let (r5, l5) = mk_sid_req(&sid1, b"ROLLBACK");
        let _ = net.handle_http_request(&r5[..l5], 1, Some(&mut sh), &mut out);
    }

    #[test]
    fn triad_byzantine_fault_injection_and_4k_raid_xor_wal_reconstruction_work() {
        let mut net0 = LivedNet::new(MAC);
        let mut sh0 = crate::shell::OsShell::new();
        sh0.triad_node_id = 0;

        let mut net1 = LivedNet::new(MAC);
        let mut sh1 = crate::shell::OsShell::new();
        sh1.triad_node_id = 1;

        let mut net2 = LivedNet::new(MAC);
        let mut sh2 = crate::shell::OsShell::new();
        sh2.triad_node_id = 2;

        let send_triad_udp = |net: &mut LivedNet,
                              sh: &mut crate::shell::OsShell,
                              payload: &[u8]|
         -> ReplySet {
            let udp_len = 8 + payload.len();
            let mut udp = [0u8; 512];
            udp[0..2].copy_from_slice(&41000u16.to_be_bytes());
            udp[2..4].copy_from_slice(&TRIAD_REPL_PORT.to_be_bytes());
            udp[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
            udp[8..udp_len].copy_from_slice(payload);
            let uc = crate::net::udp_checksum(PEER_IP, GUEST_IP, &udp[..udp_len]);
            udp[6..8].copy_from_slice(&uc.to_be_bytes());
            let (frame, flen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &udp[..udp_len]);
            let mut out = ReplySet::new();
            net.handle_frame_with_shell(&frame[..flen], 1, sh, &mut out);
            out
        };

        // 1. Node 0 proposes seq=1:
        let sql1 = b"INSERT INTO kv VALUES ('byz.test', 'v1', 1)";
        let mut cmd = [0u8; 128];
        let mut cp = 0usize;
        cp += copy_msg(b"triad propose ", &mut cmd[cp..]);
        cp += copy_msg(sql1, &mut cmd[cp..]);
        let mut sh_out = [0u8; 256];
        let _ = sh0.exec_line(&cmd[..cp], 1, 0, 0, &mut sh_out);
        let h0 = sh0.db.state_hash();
        let mut h0_hex = [0u8; 16];
        hex_encode_bytes(&h0.to_be_bytes(), &mut h0_hex);

        // 2. Fault A: Bit-flipped HMAC on `TRIAD_PREPARE` is rejected with EACCES:
        let mut prep_mac = [0u8; 32];
        LivedNet::compute_triad_prepare_tag(&DEFAULT_NET_AUTH_KEY, b"1", b"0", sql1, &mut prep_mac);
        prep_mac[15] ^= 0x01; // single-bit flip in HMAC
        let mut bad_prep_hex = [0u8; 64];
        hex_encode_bytes(&prep_mac, &mut bad_prep_hex);
        let mut bad_prep = [0u8; 256];
        let mut bp = 0usize;
        bp += copy_msg(b"TRIAD_PREPARE 1 0 ", &mut bad_prep[bp..]);
        bp += copy_msg(&bad_prep_hex, &mut bad_prep[bp..]);
        bp += copy_msg(b" ", &mut bad_prep[bp..]);
        bp += copy_msg(sql1, &mut bad_prep[bp..]);
        let r_bad_prep = send_triad_udp(&mut net1, &mut sh1, &bad_prep[..bp]);
        let s_bad_prep = core::str::from_utf8(&r_bad_prep.get(0).unwrap()[42..]).unwrap();
        assert!(
            s_bad_prep.contains("error: EACCES (triad HMAC-SHA256 verification failed)"),
            "got: {s_bad_prep}"
        );

        // 3. Fault B: Self-peer loop spoofing (`peer_id == 0` sent to Node 0) is rejected!
        //    Without this check, a single compromised node could forge or replay its own ACK to itself.
        let mut self_ack_mac = [0u8; 32];
        LivedNet::compute_triad_ack_tag(
            &DEFAULT_NET_AUTH_KEY,
            b"1",
            b"0",
            &h0_hex,
            &mut self_ack_mac,
        );
        let mut self_ack_hex = [0u8; 64];
        hex_encode_bytes(&self_ack_mac, &mut self_ack_hex);
        let mut self_ack = [0u8; 160];
        let mut sap = 0usize;
        sap += copy_msg(b"TRIAD_ACK 1 0 ", &mut self_ack[sap..]);
        sap += copy_msg(&h0_hex, &mut self_ack[sap..]);
        sap += copy_msg(b" ", &mut self_ack[sap..]);
        sap += copy_msg(&self_ack_hex, &mut self_ack[sap..]);
        let r_self_ack = send_triad_udp(&mut net0, &mut sh0, &self_ack[..sap]);
        let s_self_ack = core::str::from_utf8(&r_self_ack.get(0).unwrap()[42..]).unwrap();
        assert!(
            s_self_ack.contains("error: EACCES (triad ACK self-peer loop rejected)"),
            "self-peer TRIAD_ACK must be rejected, got: {s_self_ack}"
        );
        assert_eq!(sh0.triad_quorum_count(), 1);
        assert_eq!(sh0.triad_quorum_commits, 0);

        // 4. Fault C: Future sequence ACK (`seq = 99 != sh0.triad_tx_seq`) is rejected!
        let mut fut_ack_mac = [0u8; 32];
        LivedNet::compute_triad_ack_tag(
            &DEFAULT_NET_AUTH_KEY,
            b"99",
            b"1",
            &h0_hex,
            &mut fut_ack_mac,
        );
        let mut fut_ack_hex = [0u8; 64];
        hex_encode_bytes(&fut_ack_mac, &mut fut_ack_hex);
        let mut fut_ack = [0u8; 160];
        let mut fap = 0usize;
        fap += copy_msg(b"TRIAD_ACK 99 1 ", &mut fut_ack[fap..]);
        fap += copy_msg(&h0_hex, &mut fut_ack[fap..]);
        fap += copy_msg(b" ", &mut fut_ack[fap..]);
        fap += copy_msg(&fut_ack_hex, &mut fut_ack[fap..]);
        let r_fut_ack = send_triad_udp(&mut net0, &mut sh0, &fut_ack[..fap]);
        let s_fut_ack = core::str::from_utf8(&r_fut_ack.get(0).unwrap()[42..]).unwrap();
        assert!(
            s_fut_ack.contains("error: EACCES (stale triad ACK sequence)"),
            "future sequence TRIAD_ACK must be rejected, got: {s_fut_ack}"
        );

        // 5. Fault D: 3-Way Byzantine Split-Brain (`H0 != H1 != H2`):
        //    Node 1 reports state hash `1111111111111111` and Node 2 reports `2222222222222222`.
        //    Neither matches Node 0 (`h0_hex`), so quorum MUST stay 1/3 and `triad_quorum_commits == 0`.
        for (peer_tok, bad_hash) in [
            (b"1".as_slice(), b"1111111111111111".as_slice()),
            (b"2".as_slice(), b"2222222222222222".as_slice()),
        ] {
            let mut bmac = [0u8; 32];
            LivedNet::compute_triad_ack_tag(&DEFAULT_NET_AUTH_KEY, b"1", peer_tok, bad_hash, &mut bmac);
            let mut bhex = [0u8; 64];
            hex_encode_bytes(&bmac, &mut bhex);
            let mut bpkt = [0u8; 160];
            let mut p = 0usize;
            p += copy_msg(b"TRIAD_ACK 1 ", &mut bpkt[p..]);
            p += copy_msg(peer_tok, &mut bpkt[p..]);
            p += copy_msg(b" ", &mut bpkt[p..]);
            p += copy_msg(bad_hash, &mut bpkt[p..]);
            p += copy_msg(b" ", &mut bpkt[p..]);
            p += copy_msg(&bhex, &mut bpkt[p..]);
            let r_div = send_triad_udp(&mut net0, &mut sh0, &bpkt[..p]);
            let s_div = core::str::from_utf8(&r_div.get(0).unwrap()[42..]).unwrap();
            assert!(s_div.contains("TRIAD_ALERT seq=1"), "got: {s_div}");
        }
        assert_eq!(sh0.triad_quorum_count(), 1, "3-way split-brain must have 1/3 quorum");
        assert_eq!(sh0.triad_quorum_commits, 0, "3-way split-brain must never commit");
        assert_eq!(sh0.triad_divergences, 2);

        // 6. Fault E: Duplicate `TRIAD_ACK` replay idempotence:
        //    When Node 1 legitimately replicates `seq=1` and sends its valid `TRIAD_ACK 1 1`,
        //    `triad_quorum_commits` increments to 1. Replaying that exact `TRIAD_ACK 1 1` packet
        //    5 times must NOT inflate `triad_quorum_commits` beyond 1!
        let mut good_prep_mac = [0u8; 32];
        LivedNet::compute_triad_prepare_tag(
            &DEFAULT_NET_AUTH_KEY,
            b"1",
            b"0",
            sql1,
            &mut good_prep_mac,
        );
        let mut good_prep_hex = [0u8; 64];
        hex_encode_bytes(&good_prep_mac, &mut good_prep_hex);
        let mut good_prep = [0u8; 256];
        let mut gp = 0usize;
        gp += copy_msg(b"TRIAD_PREPARE 1 0 ", &mut good_prep[gp..]);
        gp += copy_msg(&good_prep_hex, &mut good_prep[gp..]);
        gp += copy_msg(b" ", &mut good_prep[gp..]);
        gp += copy_msg(sql1, &mut good_prep[gp..]);
        let ack1_reply = send_triad_udp(&mut net1, &mut sh1, &good_prep[..gp]);
        let ack1_pkt = &ack1_reply.get(0).unwrap()[42..];

        for _ in 0..5 {
            let q_rep = send_triad_udp(&mut net0, &mut sh0, ack1_pkt);
            let q_str = core::str::from_utf8(&q_rep.get(0).unwrap()[42..]).unwrap();
            assert!(q_str.starts_with("TRIAD_QUORUM seq=1 quorum=2/3"), "got: {q_str}");
        }
        assert_eq!(
            sh0.triad_quorum_commits, 1,
            "Replaying identical TRIAD_ACK must be idempotent and not inflate triad_quorum_commits"
        );

        // 7. Fault F: 4 KiB (`8 × 512B`) Sealed `CTTLSQL1` Partition RAID-5 XOR Parity Reconstruction:
        //    Save Node 0's SQL DB (`D1`) and Node 2's SQL DB (`D2`) to 8-sector (4 KiB) partitions,
        //    compute RAID-5 XOR parity `P = D1 ^ D2`, corrupt 3 sectors of `D1` (including header
        //    and row payload), verify `SqlDb::load_partition` rejects the corrupted image's
        //    HMAC-SHA256 seal, reconstruct `D1 = D2 ^ P`, and verify `SqlDb::load_partition`
        //    restores Node 0's exact SQL state hash and rows!
        let _ = send_triad_udp(&mut net2, &mut sh2, &good_prep[..gp]);
        let mut sql_out = [0u8; 128];
        let _ = sh2
            .db
            .exec(b"INSERT INTO kv VALUES ('node2.local', 'paritypeer', 2)", &mut sql_out);

        let seal_key: [u8; 32] = *b"cuttle-raid5-xor-sql-seal-key-v1";
        let mut d1_sectors = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        let mut d2_sectors = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        sh0.db.save_partition(&seal_key, &mut d1_sectors);
        sh2.db.save_partition(&seal_key, &mut d2_sectors);

        // Compute 8-sector (4 KiB) XOR parity P = D1 ^ D2:
        let mut parity_sectors = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        for s in 0..crate::sql::SQL_PART_SECTORS {
            for b in 0..512 {
                parity_sectors[s][b] = d1_sectors[s][b] ^ d2_sectors[s][b];
            }
        }

        // Inject catastrophic multi-sector disk corruption into D1 (sectors 0, 1, and 3):
        let mut d1_corrupted = d1_sectors;
        d1_corrupted[0][24] ^= 0x80; // flip 1 bit in HMAC-SHA256 tag
        d1_corrupted[1] = [0xFFu8; 512]; // wipe entire sector 1
        d1_corrupted[3] = [0xAAu8; 512]; // wipe entire sector 3

        let mut test_db = crate::sql::SqlDb::empty();
        assert!(
            !test_db.load_partition(&seal_key, &d1_corrupted),
            "Corrupted 4 KiB CTTLSQL1 partition must be rejected by keyed HMAC-SHA256 verification"
        );

        // Reconstruct D1 from surviving D2 and XOR parity P (`D1_rec = D2 ^ P`):
        let mut d1_reconstructed = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        for s in 0..crate::sql::SQL_PART_SECTORS {
            for b in 0..512 {
                d1_reconstructed[s][b] = d2_sectors[s][b] ^ parity_sectors[s][b];
            }
        }
        assert_eq!(d1_reconstructed, d1_sectors);
        assert!(
            test_db.load_partition(&seal_key, &d1_reconstructed),
            "RAID-5 XOR reconstructed 4 KiB CTTLSQL1 partition must pass keyed HMAC-SHA256 verification"
        );
        assert_eq!(test_db.state_hash(), sh0.db.state_hash());
        let n_sel = test_db.exec(b"SELECT v FROM kv WHERE k = 'byz.test'", &mut sql_out);
        assert_eq!(&sql_out[..n_sel], b"v\nv1\n");
    }

    #[test]
    fn http_framer_rejects_transfer_encoding_bad_content_length_and_malformed_requests() {
        // 1. Transfer-Encoding is rejected with 501 Not Implemented and clears the buffer.
        let mut buf = b"POST /sql HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n".to_vec();
        assert!(matches!(
            frame_next_http_request(&mut buf),
            HttpFrameOutcome::NotImplemented
        ));
        assert!(buf.is_empty());

        // 2. Non-numeric Content-Length is rejected with 400 Bad Request (never treated as 0).
        let mut buf2 =
            b"GET /status HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5abc\r\n\r\nhello".to_vec();
        assert!(matches!(
            frame_next_http_request(&mut buf2),
            HttpFrameOutcome::BadRequest
        ));
        assert!(buf2.is_empty());

        // 3. Duplicate Content-Length headers are rejected with 400 Bad Request.
        let mut buf3 = b"POST /sql HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello".to_vec();
        assert!(matches!(
            frame_next_http_request(&mut buf3),
            HttpFrameOutcome::BadRequest
        ));
        assert!(buf3.is_empty());

        // 4. Malformed request line is rejected with 400 Bad Request and clears trailing bytes.
        let mut buf4 = b"GARBAGE\r\n\r\nGET /status HTTP/1.1\r\nHost: localhost\r\n\r\n".to_vec();
        assert!(matches!(
            frame_next_http_request(&mut buf4),
            HttpFrameOutcome::BadRequest
        ));
        assert!(buf4.is_empty());

        // 5. Connection header token list parsing (`keep-alive, close`).
        let req_close = b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive, close\r\n\r\n";
        assert!(http_wants_close(req_close));
        let req_keep = b"GET /status HTTP/1.1\r\nHost: localhost\r\nConnection: keep-alive\r\n\r\n";
        assert!(!http_wants_close(req_keep));
    }

    #[test]
    fn close_wait_ignores_data_after_fin_and_finishes_pipelined_requests() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x9C];
        let peer_mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let peer_ip = [10, 0, 2, 2];
        let mut net = LivedNet::new(mac);
        let mut out = ReplySet::new();

        let build_tcp_frame =
            |sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]| -> alloc::vec::Vec<u8> {
                let mut frame = alloc::vec![0u8; 54 + payload.len()];
                let tcp_len = TcpImpl::build_segment(
                    sport,
                    dport,
                    seq,
                    ack,
                    flags,
                    65535,
                    payload,
                    peer_ip,
                    GUEST_IP,
                    &mut frame[34..],
                )
                .unwrap();
                let ip_len = 20 + tcp_len;
                frame.truncate(14 + ip_len);
                frame[..6].copy_from_slice(&mac);
                frame[6..12].copy_from_slice(&peer_mac);
                frame[12..14].copy_from_slice(&[0x08, 0x00]);
                frame[14] = 0x45;
                frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
                frame[20] = 0x40;
                frame[22] = 64;
                frame[23] = IP_PROTO_TCP;
                frame[26..30].copy_from_slice(&peer_ip);
                frame[30..34].copy_from_slice(&GUEST_IP);
                let ck = ipv4_header_checksum(&frame[14..34]);
                frame[24..26].copy_from_slice(&ck.to_be_bytes());
                frame
            };

        // Handshake to port 80.
        let syn = build_tcp_frame(41000, 80, 1000, 0, tcp_flags::SYN, b"");
        net.handle_frame(&syn, 1, &mut out);
        let synack = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
        let client_seq = 1001u32;
        let mut server_seq = synack.seq.wrapping_add(1);
        out = ReplySet::new();
        let ack = build_tcp_frame(41000, 80, client_seq, server_seq, tcp_flags::ACK, b"");
        net.handle_frame(&ack, 1, &mut out);

        // Send a segment carrying 12 (> 8, the per-segment response cap) pipelined GET requests plus a FIN.
        let single_req = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
        let mut req_burst = alloc::vec::Vec::new();
        for _ in 0..12 {
            req_burst.extend_from_slice(single_req);
        }
        out = ReplySet::new();
        let fin_seg = build_tcp_frame(
            41000,
            80,
            client_seq,
            server_seq,
            tcp_flags::ACK | tcp_flags::PSH | tcp_flags::FIN,
            &req_burst,
        );
        net.handle_frame(&fin_seg, 1, &mut out);
        let client_after_fin = client_seq.wrapping_add(req_burst.len() as u32 + 1);

        // First pass frames at most 8 requests in CloseWait and must NOT emit the server FIN yet.
        let mut total_200 = 0usize;
        let mut saw_server_fin = false;
        for i in 0..out.len() {
            let s = TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
            if !s.payload.is_empty() {
                total_200 += core::str::from_utf8(s.payload)
                    .unwrap()
                    .matches("HTTP/1.1 200 OK\r\n")
                    .count();
                server_seq = server_seq.wrapping_add(s.payload.len() as u32);
            }
            if s.flags & tcp_flags::FIN != 0 {
                saw_server_fin = true;
                server_seq = server_seq.wrapping_add(1);
            }
        }
        assert_eq!(
            total_200, 8,
            "first pass must pause at the 8-response per-segment cap"
        );
        assert!(
            !saw_server_fin,
            "server must not emit FIN while 4 pipelined requests remain queued in CloseWait"
        );

        // Send a bare ACK in CloseWait so the server drains the remaining 4 queued requests and then emits FIN.
        out = ReplySet::new();
        let drain_ack = build_tcp_frame(
            41000,
            80,
            client_after_fin,
            server_seq,
            tcp_flags::ACK,
            b"",
        );
        net.handle_frame(&drain_ack, 1, &mut out);
        for i in 0..out.len() {
            let s = TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
            if !s.payload.is_empty() {
                assert!(
                    !saw_server_fin,
                    "all pipelined HTTP responses must be emitted before the server's FIN"
                );
                total_200 += core::str::from_utf8(s.payload)
                    .unwrap()
                    .matches("HTTP/1.1 200 OK\r\n")
                    .count();
                server_seq = server_seq.wrapping_add(s.payload.len() as u32);
            }
            if s.flags & tcp_flags::FIN != 0 {
                saw_server_fin = true;
                server_seq = server_seq.wrapping_add(1);
            }
        }
        assert_eq!(
            total_200, 12,
            "all 12 pipelined requests must be answered in CloseWait before server FIN"
        );
        assert!(
            saw_server_fin,
            "server must emit FIN once all 12 pipelined responses have drained"
        );

        // Now test a second connection where client sends FIN first, then tries to smuggle payload in CloseWait:
        let syn2 = build_tcp_frame(41001, 80, 2000, 0, tcp_flags::SYN, b"");
        out = ReplySet::new();
        net.handle_frame(&syn2, 1, &mut out);
        let synack2 = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
        let cseq2 = 2001u32;
        let sseq2 = synack2.seq.wrapping_add(1);
        out = ReplySet::new();
        let ack2 = build_tcp_frame(41001, 80, cseq2, sseq2, tcp_flags::ACK, b"");
        net.handle_frame(&ack2, 1, &mut out);

        // Send an incomplete request header + FIN so the connection stays in CloseWait (not yet framed).
        let partial = b"GET /healthz HTTP/1.1\r\n";
        out = ReplySet::new();
        let fin2 = build_tcp_frame(
            41001,
            80,
            cseq2,
            sseq2,
            tcp_flags::ACK | tcp_flags::FIN,
            partial,
        );
        net.handle_frame(&fin2, 1, &mut out);

        // Attempt to send the rest of the request AFTER FIN (while in CloseWait): must be rejected!
        out = ReplySet::new();
        let post_fin_data = build_tcp_frame(
            41001,
            80,
            cseq2.wrapping_add(partial.len() as u32 + 1),
            sseq2,
            tcp_flags::ACK | tcp_flags::PSH,
            b"Host: localhost\r\n\r\n",
        );
        net.handle_frame(&post_fin_data, 1, &mut out);
        assert!(
            out.is_empty(),
            "CloseWait must reject post-FIN data segments without generating an HTTP response"
        );
    }

    #[test]
    fn rejected_tcp_segments_do_not_reset_idle_timer_and_rto_emits_rst() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x9D];
        let peer_mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let peer_ip = [10, 0, 2, 2];
        let mut net = LivedNet::new(mac);
        let mut out = ReplySet::new();

        let build_tcp_frame =
            |sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]| -> alloc::vec::Vec<u8> {
                let mut frame = alloc::vec![0u8; 54 + payload.len()];
                let tcp_len = TcpImpl::build_segment(
                    sport,
                    dport,
                    seq,
                    ack,
                    flags,
                    65535,
                    payload,
                    peer_ip,
                    GUEST_IP,
                    &mut frame[34..],
                )
                .unwrap();
                let ip_len = 20 + tcp_len;
                frame.truncate(14 + ip_len);
                frame[..6].copy_from_slice(&mac);
                frame[6..12].copy_from_slice(&peer_mac);
                frame[12..14].copy_from_slice(&[0x08, 0x00]);
                frame[14] = 0x45;
                frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
                frame[20] = 0x40;
                frame[22] = 64;
                frame[23] = IP_PROTO_TCP;
                frame[26..30].copy_from_slice(&peer_ip);
                frame[30..34].copy_from_slice(&GUEST_IP);
                let ck = ipv4_header_checksum(&frame[14..34]);
                frame[24..26].copy_from_slice(&ck.to_be_bytes());
                frame
            };

        // Establish connection on port 80 with a partial HTTP request buffered.
        let syn = build_tcp_frame(42000, 80, 5000, 0, tcp_flags::SYN, b"");
        net.handle_frame(&syn, 1, &mut out);
        let synack = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
        let sseq = synack.seq.wrapping_add(1);
        out = ReplySet::new();
        let ack = build_tcp_frame(42000, 80, 5001, sseq, tcp_flags::ACK | tcp_flags::PSH, b"GET /");
        net.handle_frame(&ack, 1, &mut out);
        assert_eq!(net.active_tcp_slots(), 1);

        // Advance ticks halfway to HTTPS_IDLE_TIMEOUT_TICKS, then send an out-of-window segment.
        for _ in 0..(HTTPS_IDLE_TIMEOUT_TICKS / 2) {
            net.tick_tcp_rto();
        }
        let bad_seg = build_tcp_frame(42000, 80, 999_999, sseq, tcp_flags::ACK | tcp_flags::PSH, b"bad");
        out = ReplySet::new();
        net.handle_frame(&bad_seg, 1, &mut out);

        // Advance the remaining half of HTTPS_IDLE_TIMEOUT_TICKS: the rejected segment must NOT have reset slot_last_tick!
        let mut rst_replies = ReplySet::new();
        for _ in 0..(HTTPS_IDLE_TIMEOUT_TICKS / 2 + 2) {
            let mut step = ReplySet::new();
            net.tick_tcp_rto_with_replies(&mut step);
            for i in 0..step.len() {
                rst_replies.push(step.get(i).unwrap());
            }
        }
        assert_eq!(
            net.active_tcp_slots(),
            0,
            "rejected out-of-window segment must not keep an idle slot alive"
        );
        assert!(
            !rst_replies.is_empty(),
            "tick_tcp_rto_with_replies must emit a RST segment when reclaiming an Established slot"
        );
        let rst_seg =
            TcpImpl::parse_segment(&rst_replies.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
        assert_ne!(rst_seg.flags & tcp_flags::RST, 0, "expected RST flag on reclaimed slot");
    }

    #[test]
    fn connection_close_header_enters_fin_wait_and_acks_late_client_fin() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x9E];
        let peer_mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let peer_ip = [10, 0, 2, 2];
        let mut net = LivedNet::new(mac);
        let mut out = ReplySet::new();

        let build_tcp_frame =
            |sport: u16, dport: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]| -> alloc::vec::Vec<u8> {
                let mut frame = alloc::vec![0u8; 54 + payload.len()];
                let tcp_len = TcpImpl::build_segment(
                    sport,
                    dport,
                    seq,
                    ack,
                    flags,
                    65535,
                    payload,
                    peer_ip,
                    GUEST_IP,
                    &mut frame[34..],
                )
                .unwrap();
                let ip_len = 20 + tcp_len;
                frame.truncate(14 + ip_len);
                frame[..6].copy_from_slice(&mac);
                frame[6..12].copy_from_slice(&peer_mac);
                frame[12..14].copy_from_slice(&[0x08, 0x00]);
                frame[14] = 0x45;
                frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
                frame[20] = 0x40;
                frame[22] = 64;
                frame[23] = IP_PROTO_TCP;
                frame[26..30].copy_from_slice(&peer_ip);
                frame[30..34].copy_from_slice(&GUEST_IP);
                let ck = ipv4_header_checksum(&frame[14..34]);
                frame[24..26].copy_from_slice(&ck.to_be_bytes());
                frame
            };

        // 1. Handshake to port 80.
        let syn = build_tcp_frame(43000, 80, 10_000, 0, tcp_flags::SYN, b"");
        net.handle_frame(&syn, 1, &mut out);
        let synack = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
        let mut cseq = 10_001u32;
        let mut sseq = synack.seq.wrapping_add(1);
        out = ReplySet::new();
        let ack = build_tcp_frame(43000, 80, cseq, sseq, tcp_flags::ACK, b"");
        net.handle_frame(&ack, 1, &mut out);

        // 2. Client sends `Connection: close` request WITHOUT a TCP FIN.
        let req = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
        out = ReplySet::new();
        let req_seg = build_tcp_frame(43000, 80, cseq, sseq, tcp_flags::ACK | tcp_flags::PSH, req);
        net.handle_frame(&req_seg, 1, &mut out);
        cseq = cseq.wrapping_add(req.len() as u32);

        let mut saw_server_fin = false;
        for i in 0..out.len() {
            let s = TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
            if !s.payload.is_empty() {
                sseq = sseq.wrapping_add(s.payload.len() as u32);
            }
            if (s.flags & tcp_flags::FIN) != 0 {
                saw_server_fin = true;
                sseq = sseq.wrapping_add(1);
            }
        }
        assert!(saw_server_fin, "server must emit FIN after Connection: close response");
        assert_eq!(net.tcbs[0].state, TcpState::FinWait1);

        // 3. Client first ACKs the server's FIN without sending its own FIN yet -> FinWait2.
        out = ReplySet::new();
        let bare_ack = build_tcp_frame(43000, 80, cseq, sseq, tcp_flags::ACK, b"");
        net.handle_frame(&bare_ack, 1, &mut out);
        assert_eq!(
            net.tcbs[0].state,
            TcpState::FinWait2,
            "slot must stay in FinWait2 after bare ACK of server FIN so a late client FIN is answered"
        );
        assert!(out.is_empty());

        // 4. Client now sends its late FIN|ACK -> server answers with ACK and closes the slot.
        out = ReplySet::new();
        let client_fin = build_tcp_frame(
            43000,
            80,
            cseq,
            sseq,
            tcp_flags::FIN | tcp_flags::ACK,
            b"",
        );
        net.handle_frame(&client_fin, 1, &mut out);
        assert_eq!(out.len(), 1, "server must emit an ACK for the late client FIN");
        let fin_ack =
            TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
        assert_eq!(fin_ack.flags, tcp_flags::ACK);
        assert_eq!(fin_ack.ack, cseq.wrapping_add(1));
        assert_eq!(net.tcbs[0].state, TcpState::Closed);
        assert_eq!(net.active_tcp_slots(), 0);
    }

    #[test]
    fn cross_slot_buffer_cap_and_capacity_shrink_bound_heap_footprint() {
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x9F];
        let peer_mac = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let peer_a = [10, 0, 2, 2];
        let peer_b = [192, 168, 1, 10];
        let peer_c = [192, 168, 1, 11];
        let mut net = LivedNet::new(mac);

        let build_tcp_frame = |peer_ip: [u8; 4],
                               sport: u16,
                               dport: u16,
                               seq: u32,
                               ack: u32,
                               flags: u8,
                               payload: &[u8]|
         -> alloc::vec::Vec<u8> {
            let mut frame = alloc::vec![0u8; 54 + payload.len()];
            let tcp_len = TcpImpl::build_segment(
                sport,
                dport,
                seq,
                ack,
                flags,
                65535,
                payload,
                peer_ip,
                GUEST_IP,
                &mut frame[34..],
            )
            .unwrap();
            let ip_len = 20 + tcp_len;
            frame.truncate(14 + ip_len);
            frame[..6].copy_from_slice(&mac);
            frame[6..12].copy_from_slice(&peer_mac);
            frame[12..14].copy_from_slice(&[0x08, 0x00]);
            frame[14] = 0x45;
            frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
            frame[20] = 0x40;
            frame[22] = 64;
            frame[23] = IP_PROTO_TCP;
            frame[26..30].copy_from_slice(&peer_ip);
            frame[30..34].copy_from_slice(&GUEST_IP);
            let ck = ipv4_header_checksum(&frame[14..34]);
            frame[24..26].copy_from_slice(&ck.to_be_bytes());
            frame
        };

        let open_conn =
            |net: &mut LivedNet, peer_ip: [u8; 4], sport: u16, init_seq: u32| -> (u32, u32) {
                let mut out = ReplySet::new();
                let syn = build_tcp_frame(peer_ip, sport, 80, init_seq, 0, tcp_flags::SYN, b"");
                net.handle_frame(&syn, 1, &mut out);
                let synack =
                    TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
                let cseq = init_seq.wrapping_add(1);
                let sseq = synack.seq.wrapping_add(1);
                out = ReplySet::new();
                let ack = build_tcp_frame(peer_ip, sport, 80, cseq, sseq, tcp_flags::ACK, b"");
                net.handle_frame(&ack, 1, &mut out);
                (cseq, sseq)
            };

        let single_req = b"GET /healthz HTTP/1.1\r\nHost: a\r\n\r\n"; // 34 bytes
        let mut batch = alloc::vec::Vec::new();
        while batch.len() + single_req.len() <= 1360 {
            batch.extend_from_slice(single_req);
        }
        // Each `batch` has 40 requests (1,360 bytes), and each segment drains 8 requests (272 bytes),
        // leaving +1,088 bytes in `http_bufs[slot]` per segment!
        // 50 segments on each slot accumulates ~54,400 bytes per slot.

        // 1. Peer A (`10.0.2.2`) buffers ~54.4 KiB on each of 4 connections (~217.6 KiB total)
        //    and then opens a 5th connection that exceeds `MAX_PEER_BUFFERED_BYTES` (256 KiB).
        let mut a_cseqs = [0u32; 5];
        let mut a_sseqs = [0u32; 5];
        for i in 0..5usize {
            let sport = 44000 + i as u16;
            let (cseq, sseq) = open_conn(&mut net, peer_a, sport, 20_000 + (i as u32) * 100_000);
            a_cseqs[i] = cseq;
            a_sseqs[i] = sseq;
        }
        for i in 0..4usize {
            let sport = 44000 + i as u16;
            for _ in 0..50 {
                let mut out = ReplySet::new();
                let seg = build_tcp_frame(
                    peer_a,
                    sport,
                    80,
                    a_cseqs[i],
                    a_sseqs[i],
                    tcp_flags::ACK | tcp_flags::PSH,
                    &batch,
                );
                net.handle_frame(&seg, 1, &mut out);
                a_cseqs[i] = a_cseqs[i].wrapping_add(batch.len() as u32);
                for j in 0..out.len() {
                    let s = TcpImpl::parse_segment(&out.get(j).unwrap()[34..], GUEST_IP, peer_a)
                        .unwrap();
                    a_sseqs[i] = a_sseqs[i].wrapping_add(s.payload.len() as u32);
                }
            }
        }
        assert!(net.peer_buffered_bytes(peer_a) > 200 * 1024);
        assert!(net.peer_buffered_bytes(peer_a) <= MAX_PEER_BUFFERED_BYTES);

        // Push Peer A's 5th connection over `MAX_PEER_BUFFERED_BYTES` (256 KiB) while its per-slot
        // buffer stays well below `MAX_HTTP_BUFFER_BYTES` (64 KiB) and global total stays well below
        // `MAX_TOTAL_BUFFERED_BYTES` (512 KiB). Must emit `503 Service Unavailable` (not 413).
        let mut hit_peer_503 = false;
        let mut hit_peer_413 = false;
        for _ in 0..45 {
            let mut out = ReplySet::new();
            let seg = build_tcp_frame(
                peer_a,
                44004,
                80,
                a_cseqs[4],
                a_sseqs[4],
                tcp_flags::ACK | tcp_flags::PSH,
                &batch,
            );
            net.handle_frame(&seg, 1, &mut out);
            a_cseqs[4] = a_cseqs[4].wrapping_add(batch.len() as u32);
            for j in 0..out.len() {
                let s =
                    TcpImpl::parse_segment(&out.get(j).unwrap()[34..], GUEST_IP, peer_a).unwrap();
                a_sseqs[4] = a_sseqs[4].wrapping_add(s.payload.len() as u32);
                let text = core::str::from_utf8(s.payload).unwrap_or("");
                if text.contains("HTTP/1.1 503 ") {
                    hit_peer_503 = true;
                }
                if text.contains("HTTP/1.1 413 ") {
                    hit_peer_413 = true;
                }
            }
            if hit_peer_503 {
                break;
            }
        }
        assert!(
            hit_peer_503 && !hit_peer_413,
            "exceeding MAX_PEER_BUFFERED_BYTES must emit 503 Service Unavailable (not 413)"
        );
        assert!(net.peer_buffered_bytes(peer_a) <= MAX_PEER_BUFFERED_BYTES);

        // Complete the close handshake on Peer A's rejected 5th connection so the slot is free.
        {
            let mut out = ReplySet::new();
            let fin = build_tcp_frame(
                peer_a,
                44004,
                80,
                a_cseqs[4],
                a_sseqs[4],
                tcp_flags::FIN | tcp_flags::ACK,
                b"",
            );
            net.handle_frame(&fin, 1, &mut out);
        }

        // 2. Verify another client IP (`peer_b = 10.0.2.3`) is NOT starved when Peer A hits its
        //    per-peer cap, and can still open connections and receive `200 OK`.
        let mut b_cseqs = [0u32; 4];
        let mut b_sseqs = [0u32; 4];
        for i in 0..4usize {
            let sport = 45000 + i as u16;
            let (cseq, sseq) = open_conn(&mut net, peer_b, sport, 90_000 + (i as u32) * 100_000);
            b_cseqs[i] = cseq;
            b_sseqs[i] = sseq;
        }
        for i in 0..4usize {
            let sport = 45000 + i as u16;
            for _ in 0..50 {
                let mut out = ReplySet::new();
                let seg = build_tcp_frame(
                    peer_b,
                    sport,
                    80,
                    b_cseqs[i],
                    b_sseqs[i],
                    tcp_flags::ACK | tcp_flags::PSH,
                    &batch,
                );
                net.handle_frame(&seg, 1, &mut out);
                b_cseqs[i] = b_cseqs[i].wrapping_add(batch.len() as u32);
                for j in 0..out.len() {
                    let s = TcpImpl::parse_segment(&out.get(j).unwrap()[34..], GUEST_IP, peer_b)
                        .unwrap();
                    b_sseqs[i] = b_sseqs[i].wrapping_add(s.payload.len() as u32);
                }
            }
        }
        assert!(net.peer_buffered_bytes(peer_b) > 200 * 1024);
        assert!(net.peer_buffered_bytes(peer_b) <= MAX_PEER_BUFFERED_BYTES);

        // 3. Peer C (`10.0.2.4`) opens 2 connections; its own per-peer buffered bytes stay < 80 KiB
        //    (well under `MAX_PEER_BUFFERED_BYTES = 256 KiB`), and each slot stays < 64 KiB, but
        //    combined with Peer A + Peer B (~435 KiB), Peer C's second connection crosses the global
        //    `MAX_TOTAL_BUFFERED_BYTES` (512 KiB) cap and receives `503 Service Unavailable`.
        let (mut c0_cseq, mut c0_sseq) = open_conn(&mut net, peer_c, 46000, 200_000);
        let (mut c1_cseq, mut c1_sseq) = open_conn(&mut net, peer_c, 46001, 300_000);
        for _ in 0..50 {
            let mut out = ReplySet::new();
            let seg = build_tcp_frame(
                peer_c,
                46000,
                80,
                c0_cseq,
                c0_sseq,
                tcp_flags::ACK | tcp_flags::PSH,
                &batch,
            );
            net.handle_frame(&seg, 1, &mut out);
            c0_cseq = c0_cseq.wrapping_add(batch.len() as u32);
            for j in 0..out.len() {
                let s =
                    TcpImpl::parse_segment(&out.get(j).unwrap()[34..], GUEST_IP, peer_c).unwrap();
                c0_sseq = c0_sseq.wrapping_add(s.payload.len() as u32);
            }
        }
        assert!(
            net.total_buffered_bytes() <= MAX_TOTAL_BUFFERED_BYTES,
            "buffered bytes ({}) must stay within MAX_TOTAL_BUFFERED_BYTES ({})",
            net.total_buffered_bytes(),
            MAX_TOTAL_BUFFERED_BYTES
        );
        assert!(net.total_buffered_bytes() > 450 * 1024);

        let mut hit_global_503 = false;
        let mut hit_global_413 = false;
        for _ in 0..40 {
            let mut out = ReplySet::new();
            let seg = build_tcp_frame(
                peer_c,
                46001,
                80,
                c1_cseq,
                c1_sseq,
                tcp_flags::ACK | tcp_flags::PSH,
                &batch,
            );
            net.handle_frame(&seg, 1, &mut out);
            c1_cseq = c1_cseq.wrapping_add(batch.len() as u32);
            for j in 0..out.len() {
                let s =
                    TcpImpl::parse_segment(&out.get(j).unwrap()[34..], GUEST_IP, peer_c).unwrap();
                c1_sseq = c1_sseq.wrapping_add(s.payload.len() as u32);
                let text = core::str::from_utf8(s.payload).unwrap_or("");
                if text.contains("HTTP/1.1 503 ") {
                    hit_global_503 = true;
                }
                if text.contains("HTTP/1.1 413 ") {
                    hit_global_413 = true;
                }
            }
            if hit_global_503 {
                break;
            }
        }
        assert!(
            hit_global_503 && !hit_global_413,
            "exceeding MAX_TOTAL_BUFFERED_BYTES across slots must trigger 503 Service Unavailable (not 413)"
        );
        assert!(net.total_buffered_bytes() <= MAX_TOTAL_BUFFERED_BYTES);

        // Reclaim all slots via idle timeout and verify heap capacity shrinks back to 0.
        for _ in 0..(net.idle_timeout_ticks() + 4) {
            net.tick_tcp_rto();
        }
        assert_eq!(net.total_buffered_bytes(), 0);
        assert_eq!(
            net.total_buffered_capacity(),
            0,
            "reclaimed slots must release inflated Vec capacities via shrink_to_fit"
        );
    }

    #[test]
    fn triad_ingress_voter_enforces_2of3_tmr_byzantine_isolation_rolling_morph_and_role_auth() {
        use crate::svc_runtime::{NodeRole, ServiceError};

        let cluster_key: [u8; 32] = *b"Cuttle-Triad-Ingress-Voter-Key01";
        let mut out = [0u8; 128];

        // 1. Standing Rule: Verify unauthenticated refusal in every applicable role (`Wfe`, `Full`),
        //    and `RoleDisabled` refusal on non-ingress roles (`Sql`, `Shell`):
        let dummy_resps = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: 0xAA11,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: 0xAA11,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: 0xAA11,
                body: b"INSERT 1\n",
            },
        ];

        for non_ingress_role in [NodeRole::Sql, NodeRole::Shell] {
            let mut v_dis = TriadIngressVoter::new(non_ingress_role, cluster_key, [101, 202, 303]);
            assert_eq!(
                v_dis.vote_ingress_request(false, false, &dummy_resps, &mut out),
                (TriadVoteOutcome::RoleDisabled, 0)
            );
            assert_eq!(
                v_dis.vote_ingress_request(true, true, &dummy_resps, &mut out),
                (TriadVoteOutcome::RoleDisabled, 0)
            );
            assert_eq!(
                v_dis.begin_rolling_morph(0, true),
                Err(ServiceError::RoleDisabled)
            );
            assert_eq!(
                v_dis.complete_rolling_morph_catchup(0, 404, 1, 0xAA11, true),
                Err(ServiceError::RoleDisabled)
            );
        }

        for ingress_role in [NodeRole::Wfe, NodeRole::Full] {
            let mut v = TriadIngressVoter::new(ingress_role, cluster_key, [101, 202, 303]);
            assert_eq!(
                v.vote_ingress_request(true, false, &dummy_resps, &mut out),
                (TriadVoteOutcome::Unauthenticated, 0),
                "unauthenticated mutating vote on {ingress_role:?} must be refused"
            );
            assert_eq!(
                v.begin_rolling_morph(0, false),
                Err(ServiceError::Unauthenticated)
            );
            assert_eq!(
                v.complete_rolling_morph_catchup(0, 404, 1, 0xAA11, false),
                Err(ServiceError::Unauthenticated)
            );
            let mut dummy_db = crate::sql::SqlDb::empty();
            let empty_secs = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
            assert_eq!(
                v.heal_isolated_node_via_raid5_xor(
                    2,
                    0,
                    false,
                    &empty_secs,
                    &empty_secs,
                    &mut dummy_db,
                ),
                Err(ServiceError::Unauthenticated)
            );
        }

        // 2. 3-of-3 Unanimous TMR Vote on a `Wfe` gateway appliance:
        let mut voter = TriadIngressVoter::new(NodeRole::Wfe, cluster_key, [101, 202, 303]);
        let (outcome_3of3, len_3of3) =
            voter.vote_ingress_request(true, true, &dummy_resps, &mut out);
        assert_eq!(
            outcome_3of3,
            TriadVoteOutcome::Unanimous3of3 {
                status_code: 200,
                state_hash: 0xAA11,
            }
        );
        assert_eq!(&out[..len_3of3], b"INSERT 1\n");
        assert_eq!(voter.unanimous_votes, 1);

        // 3. Zero-Downtime Rolling Morph of Node 1 while Nodes 0 & 2 serve 2-of-3 Quorum:
        voter.begin_rolling_morph(1, true).unwrap();
        assert_eq!(voter.health[1], TriadNodeHealth::Morphing);
        // Attempting to morph a second node while Node 1 is already Morphing is refused to preserve 2-of-3 quorum:
        assert_eq!(
            voter.begin_rolling_morph(2, true),
            Err(ServiceError::SandboxTrap)
        );
        let morph_resps = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: 0xAA11,
                body: b"k|v\nrole|leader\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: false,
                status_code: 0,
                state_hash: 0,
                body: b"",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: 0xAA11,
                body: b"k|v\nrole|leader\n",
            },
        ];
        let (outcome_morph, len_m) =
            voter.vote_ingress_request(false, false, &morph_resps, &mut out);
        assert_eq!(
            outcome_morph,
            TriadVoteOutcome::Majority2of3 {
                status_code: 200,
                state_hash: 0xAA11,
                outlier_node: 1,
            }
        );
        assert_eq!(&out[..len_m], b"k|v\nrole|leader\n");
        assert_eq!(
            voter.health[1],
            TriadNodeHealth::Morphing,
            "unavailable morphing node must remain Morphing until catchup completes"
        );

        // Complete Node 1 catch-up with fresh seed `909` and synced hash `0xAA11` at `tx_seq == 8`:
        voter
            .complete_rolling_morph_catchup(
                1,
                909,
                crate::sql::SQL_GENESIS_TX_SEQ + 1,
                0xAA11,
                true,
            )
            .unwrap();
        assert_eq!(voter.health[1], TriadNodeHealth::Online);
        assert_eq!(voter.variant_seeds[1], 909);
        assert_eq!(voter.rolling_morphs_completed, 1);

        // 4. Byzantine Single-Node Divergence -> Automatic Isolation of Node 2 + 2-of-3 Majority Masking:
        let mut db0 = crate::sql::SqlDb::new();
        let mut db2_expected = crate::sql::SqlDb::new();
        let mut sql_scratch = [0u8; 128];
        let _ = db0.exec(
            b"INSERT INTO kv VALUES ('init.key', 'v0', 1)",
            &mut sql_scratch,
        );
        let _ = db2_expected.exec(
            b"INSERT INTO kv VALUES ('init.key', 'v0', 1)",
            &mut sql_scratch,
        );
        let _ = db0.exec(
            b"INSERT INTO kv VALUES ('healed.key', 'raid5_ok', 7)",
            &mut sql_scratch,
        );
        let _ = db2_expected.exec(
            b"INSERT INTO kv VALUES ('healed.key', 'raid5_ok', 7)",
            &mut sql_scratch,
        );
        let clean_hash = db0.state_hash();
        let byz_resps = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: clean_hash,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: clean_hash,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: 0xDEAD_BEEF,
                body: b"status=compromised\n",
            },
        ];
        let (outcome_byz, len_byz) =
            voter.vote_ingress_request(true, true, &byz_resps, &mut out);
        assert_eq!(
            outcome_byz,
            TriadVoteOutcome::Majority2of3 {
                status_code: 200,
                state_hash: clean_hash,
                outlier_node: 2,
            }
        );
        assert_eq!(&out[..len_byz], b"INSERT 1\n");
        assert_eq!(
            voter.health[2],
            TriadNodeHealth::Isolated,
            "Byzantine outlier Node 2 must be automatically isolated by TriadIngressVoter"
        );
        assert_eq!(
            voter.begin_rolling_morph(2, true),
            Err(ServiceError::SandboxTrap),
            "Isolated Node 2 must not be allowed to enter Morphing without RAID-5 XOR healing"
        );

        // 5. Heal Isolated Node 2 via 4 KiB (`8 × 512B`) RAID-5 XOR Parity Reconstruction:
        let mut d0_secs = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        let mut d2_secs = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        db0.save_partition(&cluster_key, &mut d0_secs);
        db2_expected.save_partition(&cluster_key, &mut d2_secs);
        let mut parity_secs = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        for s in 0..crate::sql::SQL_PART_SECTORS {
            for b in 0..512 {
                parity_secs[s][b] = d0_secs[s][b] ^ d2_secs[s][b];
            }
        }
        let mut recovered_db2 = crate::sql::SqlDb::empty();
        let healed_hash = voter
            .heal_isolated_node_via_raid5_xor(
                2,
                0,
                true,
                &d0_secs,
                &parity_secs,
                &mut recovered_db2,
            )
            .expect("heal Node 2 via 4 KiB RAID-5 XOR parity");
        assert_eq!(healed_hash, db2_expected.state_hash());
        assert_eq!(voter.health[2], TriadNodeHealth::Online);
        assert_eq!(voter.parity_reconstructions, 1);

        // 6. 3-Way Split-Brain ($N_0 \neq N_1 \neq N_2$) is refused with `SplitBrainOrQuorumLost`:
        let split_resps = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: 0x1111,
                body: b"a\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: 0x2222,
                body: b"b\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: 0x3333,
                body: b"c\n",
            },
        ];
        assert_eq!(
            voter.vote_ingress_request(false, false, &split_resps, &mut out),
            (TriadVoteOutcome::SplitBrainOrQuorumLost, 0)
        );
        assert_eq!(voter.split_brain_refusals, 1);
    }

    #[test]
    fn triad_ingress_voter_sustained_multi_fault_mid_commit_drop_and_tampered_parity_campaigns() {
        use crate::svc_runtime::{NodeRole, ServiceError};

        let cluster_key = [0x91u8; 32];
        let mut voter = TriadIngressVoter::new(NodeRole::Wfe, cluster_key, [111, 222, 333]);
        assert_eq!(voter.node_seq, [crate::sql::SQL_GENESIS_TX_SEQ; 3]);
        let mut out = [0u8; 64];

        // 1. Real SQL partitions across 3 nodes: Commit #1 (unanimous 3-of-3, advancing `tx_seq` from 7 to 8).
        let mut db0 = crate::sql::SqlDb::new();
        let mut db1 = crate::sql::SqlDb::new();
        let mut db2 = crate::sql::SqlDb::new();
        let mut scratch = [0u8; 128];
        let _ = db0.exec(b"INSERT INTO kv VALUES ('epoch', 'v1', 1)", &mut scratch);
        let _ = db1.exec(b"INSERT INTO kv VALUES ('epoch', 'v1', 1)", &mut scratch);
        let _ = db2.exec(b"INSERT INTO kv VALUES ('epoch', 'v1', 1)", &mut scratch);
        let h1 = db0.state_hash();
        let seq1 = db0.tx_seq;
        assert_eq!(seq1, crate::sql::SQL_GENESIS_TX_SEQ + 1);

        // Save snapshot of stale `tx_seq == 8` partition from Node 2 for later anti-rollback test:
        let mut d0_seq1 = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        let mut d2_seq1 = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        db0.save_partition(&cluster_key, &mut d0_seq1);
        db2.save_partition(&cluster_key, &mut d2_seq1);
        let mut stale_parity_seq1 = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        for s in 0..crate::sql::SQL_PART_SECTORS {
            for b in 0..512 {
                stale_parity_seq1[s][b] = d0_seq1[s][b] ^ d2_seq1[s][b];
            }
        }

        let commit1 = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"INSERT 1\n",
            },
        ];
        let (out1, _) = voter.vote_ingress_request(true, true, &commit1, &mut out);
        assert_eq!(
            out1,
            TriadVoteOutcome::Unanimous3of3 {
                status_code: 200,
                state_hash: h1,
            }
        );
        assert_eq!(voter.node_seq, [seq1, seq1, seq1]);

        // 1b. A mutating request that all nodes reject (`error:` or `status_code >= 400`) must NOT advance `node_seq`:
        let rejected_mut = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"error: syntax error\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"error: syntax error\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"error: syntax error\n",
            },
        ];
        let _ = voter.vote_ingress_request(true, true, &rejected_mut, &mut out);
        assert_eq!(
            voter.node_seq,
            [seq1, seq1, seq1],
            "rejected mutating request must not advance node_seq"
        );

        // 2. Mid-Commit Node Drop on Mutating Write #2:
        // Nodes 0 and 1 commit `tx_seq == 9`, while Node 2 drops mid-commit (`available: false`).
        let _ = db0.exec(b"INSERT INTO kv VALUES ('cfg', 'strict', 2)", &mut scratch);
        let _ = db1.exec(b"INSERT INTO kv VALUES ('cfg', 'strict', 2)", &mut scratch);
        let h2 = db0.state_hash();
        let seq2 = db0.tx_seq;
        let commit2_drop = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: h2,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: h2,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: false,
                status_code: 0,
                state_hash: h1,
                body: b"",
            },
        ];
        let (out2, _) = voter.vote_ingress_request(true, true, &commit2_drop, &mut out);
        assert_eq!(
            out2,
            TriadVoteOutcome::Majority2of3 {
                status_code: 200,
                state_hash: h2,
                outlier_node: 2,
            }
        );
        assert_eq!(
            voter.health[2],
            TriadNodeHealth::Isolated,
            "Node 2 dropping mid-commit on a mutating request must transition to Isolated"
        );
        assert_eq!(voter.node_seq, [seq2, seq2, seq1]);

        // 3. Stale Node 2 comes back on the wire claiming `available: true` with stale `h1` while
        // Node 1 has a transient read timeout (`available: false`):
        let stale_rejoin = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: h2,
                body: b"epoch|v1\ncfg|strict\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: false,
                status_code: 0,
                state_hash: 0,
                body: b"",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: h1,
                body: b"epoch|v1\n",
            },
        ];
        assert_eq!(
            voter.vote_ingress_request(false, false, &stale_rejoin, &mut out),
            (TriadVoteOutcome::SplitBrainOrQuorumLost, 0)
        );

        // 4. Isolated Node 2 cannot bypass RAID-5 XOR healing via `begin_rolling_morph` or `complete_rolling_morph_catchup`:
        assert_eq!(
            voter.begin_rolling_morph(2, true),
            Err(ServiceError::SandboxTrap)
        );
        assert_eq!(
            voter.complete_rolling_morph_catchup(2, 444, seq2, h2, true),
            Err(ServiceError::SandboxTrap)
        );

        // 5. Anti-Rollback RAID-5 XOR Check:
        // Attempting to heal Node 2 using the old `tx_seq == 8` partition + parity (`seq1 < seq2`)
        // must be refused with `ImaVerificationFailed`!
        let mut recovered = crate::sql::SqlDb::empty();
        assert_eq!(
            voter.heal_isolated_node_via_raid5_xor(
                2,
                0,
                true,
                &d0_seq1,
                &stale_parity_seq1,
                &mut recovered,
            ),
            Err(ServiceError::ImaVerificationFailed),
            "replay of older valid-HMAC partition (tx_seq=8 < donor node_seq=9) must be rejected"
        );
        assert_eq!(voter.health[2], TriadNodeHealth::Isolated);

        // 6. Bit-Flipped RAID-5 XOR Parity Rejection + Valid `tx_seq == 9` Reconstruction:
        let _ = db2.exec(b"INSERT INTO kv VALUES ('cfg', 'strict', 2)", &mut scratch);
        let mut d0_seq2 = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        let mut d2_seq2 = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        db0.save_partition(&cluster_key, &mut d0_seq2);
        db2.save_partition(&cluster_key, &mut d2_seq2);
        let mut parity_seq2 = [[0u8; 512]; crate::sql::SQL_PART_SECTORS];
        for s in 0..crate::sql::SQL_PART_SECTORS {
            for b in 0..512 {
                parity_seq2[s][b] = d0_seq2[s][b] ^ d2_seq2[s][b];
            }
        }
        // Flip 1 bit in sector 3 of parity:
        let mut corrupted_parity = parity_seq2;
        corrupted_parity[3][127] ^= 0x01;
        assert_eq!(
            voter.heal_isolated_node_via_raid5_xor(
                2,
                0,
                true,
                &d0_seq2,
                &corrupted_parity,
                &mut recovered,
            ),
            Err(ServiceError::ImaVerificationFailed)
        );
        assert_eq!(voter.health[2], TriadNodeHealth::Isolated);

        // Valid RAID-5 heal at `tx_seq == 9` succeeds and leaves `voter.node_seq == [9, 9, 9]` WITHOUT manual patching:
        let healed_h = voter
            .heal_isolated_node_via_raid5_xor(2, 0, true, &d0_seq2, &parity_seq2, &mut recovered)
            .expect("valid tx_seq=9 RAID-5 XOR heal must succeed");
        assert_eq!(healed_h, h2);
        assert_eq!(voter.health[2], TriadNodeHealth::Online);
        assert_eq!(voter.node_seq, [seq2, seq2, seq2]);

        // 7. Rolling Morph with Concurrent Write Advancement:
        // Start rolling morph on Node 0 -> Nodes 1 & 2 commit Write #3 (`tx_seq` advances to 10) ->
        // Node 0 tries to complete morph catch-up with stale `synced_seq == 9` or stale `h2` -> refused!
        voter.begin_rolling_morph(0, true).unwrap();
        let _ = db1.exec(b"INSERT INTO kv VALUES ('rot', 'ok', 3)", &mut scratch);
        let _ = db2.exec(b"INSERT INTO kv VALUES ('rot', 'ok', 3)", &mut scratch);
        let h3 = db1.state_hash();
        let seq3 = db1.tx_seq;
        let commit3 = [
            TriadNodeVoteInput {
                node_id: 0,
                available: false,
                status_code: 0,
                state_hash: 0,
                body: b"",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: h3,
                body: b"INSERT 1\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: h3,
                body: b"INSERT 1\n",
            },
        ];
        let (out3, _) = voter.vote_ingress_request(true, true, &commit3, &mut out);
        assert_eq!(
            out3,
            TriadVoteOutcome::Majority2of3 {
                status_code: 200,
                state_hash: h3,
                outlier_node: 0,
            }
        );
        assert_eq!(
            voter.health[0],
            TriadNodeHealth::Morphing,
            "Morphing node must stay Morphing (not Isolated) when peers commit a write during rotation"
        );
        assert_eq!(voter.node_seq, [seq2, seq3, seq3]);

        // Stale catch-up (`synced_seq = 9 < 10` or `synced_hash = h2 != h3`) is rejected:
        assert_eq!(
            voter.complete_rolling_morph_catchup(0, 777, seq2, h3, true),
            Err(ServiceError::SandboxTrap)
        );
        assert_eq!(
            voter.complete_rolling_morph_catchup(0, 777, seq3, h2, true),
            Err(ServiceError::SandboxTrap)
        );
        // Up-to-date catch-up (`synced_seq = 10`, `synced_hash = h3`, fresh seed `777`) succeeds:
        voter
            .complete_rolling_morph_catchup(0, 777, seq3, h3, true)
            .expect("up-to-date morph catchup must succeed");
        assert_eq!(voter.health, [TriadNodeHealth::Online; 3]);
        assert_eq!(voter.node_seq, [seq3, seq3, seq3]);

        // 7b. Two-node rollback to a prior committed state hash (`h2`) is refused on both reads and writes:
        let mut voter_rb = voter;
        let rb_read = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: h2,
                body: b"stale\n",
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: h2,
                body: b"stale\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: h3,
                body: b"fresh\n",
            },
        ];
        assert_eq!(
            voter_rb.vote_ingress_request(false, false, &rb_read, &mut out),
            (TriadVoteOutcome::SplitBrainOrQuorumLost, 0),
            "2-node rollback on read must be refused and must not move node_hash backwards"
        );
        assert_eq!(voter_rb.node_hash, [h3, h3, h3]);

        // 8. Oversized response body (> `winning_body_out.len()`) from a Byzantine node is isolated:
        let oversized_body = [b'X'; 128];
        let byz_oversized = [
            TriadNodeVoteInput {
                node_id: 0,
                available: true,
                status_code: 200,
                state_hash: h3,
                body: &oversized_body,
            },
            TriadNodeVoteInput {
                node_id: 1,
                available: true,
                status_code: 200,
                state_hash: h3,
                body: b"OK\n",
            },
            TriadNodeVoteInput {
                node_id: 2,
                available: true,
                status_code: 200,
                state_hash: h3,
                body: b"OK\n",
            },
        ];
        let (out4, len4) = voter.vote_ingress_request(false, false, &byz_oversized, &mut out);
        assert_eq!(
            out4,
            TriadVoteOutcome::Majority2of3 {
                status_code: 200,
                state_hash: h3,
                outlier_node: 0,
            }
        );
        assert_eq!(&out[..len4], b"OK\n");
        assert_eq!(voter.health[0], TriadNodeHealth::Isolated);
    }

    #[test]
    fn http_request_prefilter_accepts_binary_vfs_valid_sql_and_shell_and_returns_400_without_counter_inflation()
    {
        use crate::svc_runtime::ServiceId;

        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();
        let sid = sh.create_session(b"admin", b"prefilter-test");
        let mut sid_hdr = [0u8; 64];
        sid_hdr[..17].copy_from_slice(b"X-Session-Token: ");
        sid_hdr[17..49].copy_from_slice(&sid);
        sid_hdr[49..51].copy_from_slice(b"\r\n");

        let http_call = |net: &mut LivedNet,
                         sh: &mut crate::shell::OsShell,
                         method: &[u8],
                         path: &[u8],
                         extra_hdr: &[u8],
                         body: &[u8]|
         -> ([u8; 1380], usize) {
            let mut req = [0u8; 1024];
            let mut p = 0usize;
            p += copy_msg(method, &mut req[p..]);
            p += copy_msg(b" ", &mut req[p..]);
            p += copy_msg(path, &mut req[p..]);
            p += copy_msg(b" HTTP/1.1\r\nHost: x\r\n", &mut req[p..]);
            p += copy_msg(extra_hdr, &mut req[p..]);
            p += copy_msg(b"\r\n", &mut req[p..]);
            p += copy_msg(body, &mut req[p..]);
            let mut out = [0u8; 1380];
            let n = net.handle_http_request(&req[..p], 1, Some(sh), &mut out);
            (out, n)
        };

        // 1. Binary `PUT /fs/var/blob.bin` succeeds (`201 Created`) and `GET /fs/var/blob.bin` round-trips exact bytes:
        let bin_payload: &[u8] = b"\x00\x01\x02\x7f\xfe\xffCUTTLE_BIN";
        let (resp_put, n_put) = http_call(
            &mut net,
            &mut sh,
            b"PUT",
            b"/fs/var/blob.bin",
            &sid_hdr[..51],
            bin_payload,
        );
        assert!(
            resp_put[..n_put].starts_with(b"HTTP/1.1 201 Created\r\n")
                || resp_put[..n_put].starts_with(b"HTTP/1.1 200 OK\r\n"),
            "binary PUT /fs must succeed: {:?}",
            core::str::from_utf8(&resp_put[..n_put])
        );
        let (resp_get, n_get) = http_call(
            &mut net,
            &mut sh,
            b"GET",
            b"/fs/var/blob.bin",
            b"",
            b"",
        );
        assert!(resp_get[..n_get].starts_with(b"HTTP/1.1 200 OK\r\n"));
        assert!(resp_get[..n_get].ends_with(bin_payload));

        // 2. `POST /sh` accepts `write /var/note it's`, `write /var/note a;b`, and `write /var/note fish&chips`:
        for (cmd, expected_txt) in [
            (b"write /var/note it's".as_slice(), b"it's\n".as_slice()),
            (b"write /var/note a;b".as_slice(), b"a;b\n".as_slice()),
            (
                b"write /var/note fish&chips".as_slice(),
                b"fish&chips\n".as_slice(),
            ),
        ] {
            let (r_sh, n_sh) = http_call(
                &mut net,
                &mut sh,
                b"POST",
                b"/sh",
                &sid_hdr[..51],
                cmd,
            );
            assert!(
                r_sh[..n_sh].starts_with(b"HTTP/1.1 200 OK\r\n"),
                "POST /sh {:?} must return 200 OK, got {:?}",
                core::str::from_utf8(cmd).unwrap(),
                core::str::from_utf8(&r_sh[..n_sh])
            );
            let (r_cat, n_cat) = http_call(
                &mut net,
                &mut sh,
                b"GET",
                b"/fs/var/note",
                b"",
                b"",
            );
            assert!(r_cat[..n_cat].ends_with(expected_txt));
        }

        // 3. `POST /sql` accepts empty body (`""`), `SELECT * FROM kv ;;`, `.TABLES`, and `.dump kv` without session auth:
        for (sql_q, expected_sub) in [
            (
                b"".as_slice(),
                b"services (rows=3, cols=4)\nkv (rows=2, cols=3)\n".as_slice(),
            ),
            (
                b"SELECT v FROM kv WHERE k = 'cluster.role' ;;".as_slice(),
                b"v\nprimary\n".as_slice(),
            ),
            (
                b".TABLES".as_slice(),
                b"services (rows=3, cols=4)\nkv (rows=2, cols=3)\n".as_slice(),
            ),
            (
                b".dump kv".as_slice(),
                b"sqldump table=kv ".as_slice(),
            ),
        ] {
            let (r_sql, n_sql) = http_call(
                &mut net,
                &mut sh,
                b"POST",
                b"/sql",
                b"",
                sql_q,
            );
            assert!(
                r_sql[..n_sql].starts_with(b"HTTP/1.1 200 OK\r\n"),
                "POST /sql {:?} must succeed with 200 OK, got {:?}",
                core::str::from_utf8(sql_q).unwrap(),
                core::str::from_utf8(&r_sql[..n_sql])
            );
            assert!(
                r_sql[..n_sql].windows(expected_sub.len()).any(|w| w == expected_sub),
                "POST /sql {:?} missing expected substring {:?} in {:?}",
                core::str::from_utf8(sql_q).unwrap(),
                core::str::from_utf8(expected_sub).unwrap(),
                core::str::from_utf8(&r_sql[..n_sql])
            );
        }

        // 4. `/*triad*/` and `/*t*/` prefixes over HTTP are refused even with an authenticated session:
        let (r_triad_unauth, n_tu) = http_call(
            &mut net,
            &mut sh,
            b"POST",
            b"/sql",
            b"",
            b"/*triad*/ SELECT * FROM kv",
        );
        assert!(r_triad_unauth[..n_tu].starts_with(b"HTTP/1.1 401 Unauthorized\r\n"));
        let (r_triad_auth, n_ta) = http_call(
            &mut net,
            &mut sh,
            b"POST",
            b"/sql",
            &sid_hdr[..51],
            b"/*t*/ INSERT INTO kv VALUES ('pwn', '1', 1)",
        );
        assert!(
            r_triad_auth[..n_ta]
                .windows(b"error: EACCES (/*triad*/ prefix reserved for Triad controller)\n".len())
                .any(|w| w == b"error: EACCES (/*triad*/ prefix reserved for Triad controller)\n"),
            "authenticated HTTP caller must be refused /*t*/ prefix: {:?}",
            core::str::from_utf8(&r_triad_auth[..n_ta])
        );

        // 5. Malformed requests return HTTP `400 Bad Request` BEFORE incrementing `requests_served` or `policy_denials`:
        let sql_served_before = sh.svc.services[ServiceId::Sql.index()].requests_served;
        let sql_denials_before = sh.svc.services[ServiceId::Sql.index()].policy_denials;
        let (r_bad_sql, n_bad) = http_call(
            &mut net,
            &mut sh,
            b"POST",
            b"/sql",
            &sid_hdr[..51],
            b"SELECT * FROM kv WHERE k = 'unterminated",
        );
        assert!(
            r_bad_sql[..n_bad].starts_with(b"HTTP/1.1 400 Bad Request\r\n"),
            "malformed SQL must return 400 Bad Request, got {:?}",
            core::str::from_utf8(&r_bad_sql[..n_bad])
        );
        assert_eq!(
            sh.svc.services[ServiceId::Sql.index()].requests_served,
            sql_served_before,
            "400 Bad Request must not increment requests_served"
        );
        assert_eq!(
            sh.svc.services[ServiceId::Sql.index()].policy_denials,
            sql_denials_before,
            "400 Bad Request must not increment policy_denials"
        );
    }

    #[test]
    fn triad_prepare_with_stale_epoch_rejected() {
        let mut net = LivedNet::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let mut sh = crate::shell::OsShell::new();
        sh.triad_node_id = 1;

        let build_prep_datagram = |epoch_opt: Option<&[u8]>, seq: &[u8], node: &[u8], sql: &[u8]| {
            let mut mac = [0u8; 32];
            if let Some(ep) = epoch_opt {
                LivedNet::compute_triad_prepare_tag_with_epoch(
                    &DEFAULT_NET_AUTH_KEY,
                    ep,
                    seq,
                    node,
                    sql,
                    &mut mac,
                );
            } else {
                LivedNet::compute_triad_prepare_tag(&DEFAULT_NET_AUTH_KEY, seq, node, sql, &mut mac);
            }
            let mut hex_mac = [0u8; 64];
            hex_encode_bytes(&mac, &mut hex_mac);
            let mut payload = alloc::vec::Vec::new();
            payload.extend_from_slice(b"TRIAD_PREPARE ");
            if let Some(ep) = epoch_opt {
                payload.extend_from_slice(b"epoch=");
                payload.extend_from_slice(ep);
                payload.push(b' ');
            }
            payload.extend_from_slice(seq);
            payload.push(b' ');
            payload.extend_from_slice(node);
            payload.push(b' ');
            payload.extend_from_slice(&hex_mac);
            payload.push(b' ');
            payload.extend_from_slice(sql);
            payload
        };

        // 1. Coordinator epoch 2 commits seq=1:
        let mut body = [0u8; 512];
        let p_ep2 = build_prep_datagram(
            Some(b"2"),
            b"1",
            b"0",
            b"INSERT INTO kv VALUES ('fenced.k1', 'ep2', 1)",
        );
        let n1 = net.handle_udp_triad(&p_ep2, &mut sh, &mut body);
        assert!(
            body[..n1].starts_with(b"TRIAD_ACK 1 1 "),
            "epoch=2 TRIAD_PREPARE must succeed, got {:?}",
            core::str::from_utf8(&body[..n1])
        );
        assert_eq!(net.triad_min_epoch, 2);
        assert_eq!(sh.triad_min_epoch, 2);

        // 2. Stale coordinator at epoch=1 with a valid HMAC and higher seq=2 must be rejected:
        let p_stale_ep1 = build_prep_datagram(
            Some(b"1"),
            b"2",
            b"0",
            b"INSERT INTO kv VALUES ('fenced.k2', 'stale_ep1', 1)",
        );
        let n2 = net.handle_udp_triad(&p_stale_ep1, &mut sh, &mut body);
        assert_eq!(
            &body[..n2],
            b"error: EACCES (stale triad coordinator epoch)\n",
            "stale epoch=1 must be rejected"
        );
        assert_eq!(sh.triad_tx_seq, 1, "stale epoch must not advance triad_tx_seq");

        // 3. Legacy epoch-less TRIAD_PREPARE after epoch=2 is active must also be rejected:
        let p_no_ep = build_prep_datagram(
            None,
            b"2",
            b"0",
            b"INSERT INTO kv VALUES ('fenced.k2', 'no_epoch', 1)",
        );
        let n3 = net.handle_udp_triad(&p_no_ep, &mut sh, &mut body);
        assert_eq!(
            &body[..n3],
            b"error: EACCES (stale triad coordinator epoch)\n",
            "epoch-less TRIAD_PREPARE must be rejected once triad_min_epoch > 0"
        );

        // 4. Coordinator advancing to epoch=3 with seq=2 succeeds and advances triad_min_epoch to 3:
        let p_ep3 = build_prep_datagram(
            Some(b"3"),
            b"2",
            b"0",
            b"INSERT INTO kv VALUES ('fenced.k2', 'ep3', 1)",
        );
        let n4 = net.handle_udp_triad(&p_ep3, &mut sh, &mut body);
        assert!(
            body[..n4].starts_with(b"TRIAD_ACK 2 1 "),
            "epoch=3 TRIAD_PREPARE must succeed, got {:?}",
            core::str::from_utf8(&body[..n4])
        );
        assert_eq!(net.triad_min_epoch, 3);
        assert_eq!(sh.triad_min_epoch, 3);
        assert_eq!(sh.triad_tx_seq, 2);
    }

    #[test]
    fn https_slot_buffered_accounting_includes_unparsed_tls_rx_bytes() {
        let _guard = crate::tls_provider::GOLDEN_LOCK.lock();
        let net = crate::https::golden_server().expect("golden_server");
        let mut client =
            crate::https::LoopbackClient::connect(net, None, 54019, 1).expect("connect :443");

        // Send a TLS 1.2/1.3 handshake record header claiming 8192 bytes (0x2000), followed by
        // only 4100 bytes of incomplete record payload so rustls retains all 4105 bytes in `TlsSession.rx`.
        let mut partial_record = alloc::vec![0x16, 0x03, 0x03, 0x20, 0x00];
        partial_record.extend_from_slice(&[0x41u8; 4100]);
        let _ = client.send(&partial_record).expect("send partial TLS record");

        assert!(
            client.net().total_buffered_bytes() >= partial_record.len(),
            "total_buffered_bytes ({}) must account for {} unparsed TLS rx bytes",
            client.net().total_buffered_bytes(),
            partial_record.len()
        );
        assert!(
            client
                .net()
                .peer_buffered_bytes(crate::https::LOOPBACK_PEER_IP)
                >= partial_record.len(),
            "peer_buffered_bytes must account for unparsed TLS rx bytes"
        );
    }

    #[test]
    fn http_login_enforces_domain_separation_strict_cookie_and_per_ip_lockout() {
        let mut net = LivedNet::new([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        let mut sh = crate::shell::OsShell::new();
        let mut out = [0u8; 1500];

        // 1. Replaying a UDP `AUTH` HMAC tag (`compute_auth_tag`) onto `POST /session/login` MUST fail!
        let mut udp_mac = [0u8; 32];
        LivedNet::compute_auth_tag(&DEFAULT_NET_AUTH_KEY, b"1", b"admin", &mut udp_mac);
        let mut hex_udp = [0u8; 64];
        hex_encode_bytes(&udp_mac, &mut hex_udp);
        let mut bad_login = [0u8; 200];
        let mut p = 0usize;
        p += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n1 ", &mut bad_login[p..]);
        p += copy_msg(&hex_udp, &mut bad_login[p..]);
        p += copy_msg(b" admin", &mut bad_login[p..]);
        let n_replay = net.handle_http_request(&bad_login[..p], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_replay].starts_with(b"HTTP/1.1 401 "),
            "UDP AUTH tag must not authenticate POST /session/login: {:?}",
            core::str::from_utf8(&out[..n_replay])
        );

        // 2. Domain-separated `compute_http_login_tag` succeeds, while oversized (>16B) or invalid-charset
        //    usernames are rejected with 400 Bad Request instead of silent truncation!
        let mut ok_mac = [0u8; 32];
        LivedNet::compute_http_login_tag(
            &DEFAULT_NET_AUTH_KEY,
            b"2",
            b"admin_long_username_99",
            &mut ok_mac,
        );
        let mut hex_long = [0u8; 64];
        hex_encode_bytes(&ok_mac, &mut hex_long);
        let mut long_req = [0u8; 220];
        let mut lp = 0usize;
        lp += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n2 ", &mut long_req[lp..]);
        lp += copy_msg(&hex_long, &mut long_req[lp..]);
        lp += copy_msg(b" admin_long_username_99", &mut long_req[lp..]);
        let n_long = net.handle_http_request(&long_req[..lp], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_long].starts_with(b"HTTP/1.1 400 "),
            "oversized username (>16B) must be rejected with 400, not truncated: {:?}",
            core::str::from_utf8(&out[..n_long])
        );

        LivedNet::compute_http_login_tag(&DEFAULT_NET_AUTH_KEY, b"3", b"admin", &mut ok_mac);
        let mut hex_ok = [0u8; 64];
        hex_encode_bytes(&ok_mac, &mut hex_ok);
        let mut ok_req = [0u8; 200];
        let mut op = 0usize;
        op += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n3 ", &mut ok_req[op..]);
        op += copy_msg(&hex_ok, &mut ok_req[op..]);
        op += copy_msg(b" admin", &mut ok_req[op..]);
        let n_ok = net.handle_http_request(&ok_req[..op], 1, Some(&mut sh), &mut out);
        let s_ok = core::str::from_utf8(&out[..n_ok]).unwrap();
        assert!(s_ok.starts_with("HTTP/1.1 200 OK\r\n"));
        let sid_pos = s_ok.find("sid=").unwrap() + 4;
        let mut sid = [0u8; 32];
        sid.copy_from_slice(&s_ok.as_bytes()[sid_pos..sid_pos + 32]);

        // 3. Strict `;`-delimited Cookie parsing: `Cookie: not_sid=<sid>` MUST NOT authenticate!
        let mut spoof_cookie = [0u8; 200];
        let mut cp = 0usize;
        cp += copy_msg(
            b"GET /session/whoami HTTP/1.1\r\nCookie: not_sid=",
            &mut spoof_cookie[cp..],
        );
        cp += copy_msg(&sid, &mut spoof_cookie[cp..]);
        cp += copy_msg(b"\r\n\r\n", &mut spoof_cookie[cp..]);
        let n_spoof = net.handle_http_request(&spoof_cookie[..cp], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_spoof].starts_with(b"HTTP/1.1 401 "),
            "not_sid=<hex> must not match Cookie sid=: {:?}",
            core::str::from_utf8(&out[..n_spoof])
        );

        // 4. Per-IP login rate-limiting: 5 failed login attempts from `10.0.2.99` lock out ONLY `10.0.2.99` (`429`),
        //    while legitimate peer `10.0.2.2` still logs in with `200 OK`!
        let attacker_ip = [10, 0, 2, 99];
        net.active_http_peer_ip = attacker_ip;
        for seq in 10..15u64 {
            let mut bad_req = [0u8; 200];
            let mut bp = 0usize;
            bp += copy_msg(b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n", &mut bad_req[bp..]);
            bp += dec_u64(seq, &mut bad_req[bp..]);
            bp += copy_msg(
                b" 0000000000000000000000000000000000000000000000000000000000000000 admin",
                &mut bad_req[bp..],
            );
            let nb = net.handle_http_request(&bad_req[..bp], 1, Some(&mut sh), &mut out);
            assert!(out[..nb].starts_with(b"HTTP/1.1 401 "));
        }
        let n_locked = net.handle_http_request(
            b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n16 0000000000000000000000000000000000000000000000000000000000000000 admin",
            1,
            Some(&mut sh),
            &mut out,
        );
        assert!(
            out[..n_locked].starts_with(b"HTTP/1.1 429 "),
            "attacker IP must be rate-limited after 5 failed logins: {:?}",
            core::str::from_utf8(&out[..n_locked])
        );

        // Legitimate peer `10.0.2.2` is NOT locked out:
        net.active_http_peer_ip = PEER_IP;
        LivedNet::compute_http_login_tag(&DEFAULT_NET_AUTH_KEY, b"20", b"admin", &mut ok_mac);
        hex_encode_bytes(&ok_mac, &mut hex_ok);
        let mut ok_peer_req = [0u8; 200];
        let mut opp = 0usize;
        opp += copy_msg(
            b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n20 ",
            &mut ok_peer_req[opp..],
        );
        opp += copy_msg(&hex_ok, &mut ok_peer_req[opp..]);
        opp += copy_msg(b" admin", &mut ok_peer_req[opp..]);
        let n_legit = net.handle_http_request(&ok_peer_req[..opp], 1, Some(&mut sh), &mut out);
        assert!(
            out[..n_legit].starts_with(b"HTTP/1.1 200 OK\r\n"),
            "legitimate peer IP must not be locked out by attacker IP's failed logins: {:?}",
            core::str::from_utf8(&out[..n_legit])
        );
        net.active_http_peer_ip = [0, 0, 0, 0];
    }

    #[test]
    fn triad_voter_allows_aba_value_transition_and_tcp_preserves_established_slots_on_syn_flood() {
        // 1. TriadIngressVoter must allow legitimate A -> B -> A state transitions (e.g. toggling a flag
        //    or INSERT followed by DELETE returning `state_hash` to its original hash `0xAAAA`):
        let mut voter = TriadIngressVoter::new(
            crate::svc_runtime::NodeRole::Full,
            [0x42u8; 32],
            [101, 202, 303],
        );
        let mut out_body = [0u8; 64];
        let mk_votes = |state_hash: u64, body: &'static [u8]| {
            [
                TriadNodeVoteInput {
                    node_id: 0,
                    available: true,
                    status_code: 200,
                    state_hash,
                    body,
                },
                TriadNodeVoteInput {
                    node_id: 1,
                    available: true,
                    status_code: 200,
                    state_hash,
                    body,
                },
                TriadNodeVoteInput {
                    node_id: 2,
                    available: true,
                    status_code: 200,
                    state_hash,
                    body,
                },
            ]
        };
        let r_a = mk_votes(0xAAAA_1111_2222_3333, b"INSERT 1\n");
        let (v1, _) = voter.vote_ingress_request(true, true, &r_a, &mut out_body);
        assert!(matches!(v1, TriadVoteOutcome::Unanimous3of3 { .. }));

        let r_b = mk_votes(0xBBBB_4444_5555_6666, b"UPDATE 1\n");
        let (v2, _) = voter.vote_ingress_request(true, true, &r_b, &mut out_body);
        assert!(matches!(v2, TriadVoteOutcome::Unanimous3of3 { .. }));

        let r_back_to_a = mk_votes(0xAAAA_1111_2222_3333, b"UPDATE 1\n");
        let (v3, _) = voter.vote_ingress_request(true, true, &r_back_to_a, &mut out_body);
        assert!(
            matches!(v3, TriadVoteOutcome::Unanimous3of3 { .. }),
            "A -> B -> A state hash return must not be falsely rejected as rollback: {v3:?}"
        );

        // 2. When all 16 TCP slots hold active `Established` connections, a 17th `SYN` flood packet
        //    must NOT evict an `Established` connection!
        let mut net = LivedNet::new(MAC);
        for slot_i in 0..TCP_MAX_SLOTS {
            let sport = 41000u16 + slot_i as u16;
            let mut seg_buf = [0u8; 40];
            let n_syn = TcpImpl::build_segment(
                sport,
                HTTP_PORT,
                1000,
                0,
                tcp_flags::SYN,
                65535,
                b"",
                PEER_IP,
                GUEST_IP,
                &mut seg_buf,
            )
            .unwrap();
            let (syn_frame, syn_len) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &seg_buf[..n_syn]);
            let mut replies = ReplySet::new();
            net.handle_frame(&syn_frame[..syn_len], 1, &mut replies);
            assert_eq!(replies.len(), 1);
            let syn_ack_tcp = &replies.get(0).unwrap()[ETH_HEADER_LEN + IPV4_HEADER_LEN..];
            let srv_isn = u32::from_be_bytes([
                syn_ack_tcp[4],
                syn_ack_tcp[5],
                syn_ack_tcp[6],
                syn_ack_tcp[7],
            ]);
            let n_ack = TcpImpl::build_segment(
                sport,
                HTTP_PORT,
                1001,
                srv_isn.wrapping_add(1),
                tcp_flags::ACK,
                65535,
                b"",
                PEER_IP,
                GUEST_IP,
                &mut seg_buf,
            )
            .unwrap();
            let (ack_frame, ack_len) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &seg_buf[..n_ack]);
            let mut ack_replies = ReplySet::new();
            net.handle_frame(&ack_frame[..ack_len], 1, &mut ack_replies);
        }
        assert_eq!(net.active_tcp_slots(), TCP_MAX_SLOTS);

        // Now send a SYN from a 17th port: none of the 16 Established slots may be evicted!
        let flood_ip = [10, 0, 2, 99];
        let mut flood_seg = [0u8; 40];
        let nf = TcpImpl::build_segment(
            55555,
            HTTP_PORT,
            9000,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            flood_ip,
            GUEST_IP,
            &mut flood_seg,
        )
        .unwrap();
        let (flood_frame, flood_len) = eth_ip(IP_PROTO_TCP, flood_ip, GUEST_IP, &flood_seg[..nf]);
        let mut flood_replies = ReplySet::new();
        net.handle_frame(&flood_frame[..flood_len], 1, &mut flood_replies);
        assert_eq!(
            flood_replies.len(),
            0,
            "17th SYN must be dropped when all 16 slots are active Established connections"
        );
        assert!(
            net.tcbs.iter().all(|t| t.state == TcpState::Established),
            "SYN flood must never evict an active Established TCB"
        );
    }

    #[test]
    fn wire_hardening_rejects_fragments_bad_checksums_martians_bad_arp_and_hmac_truncation() {
        let key = [0x5Au8; 32];
        let mut net = LivedNet::with_auth_key(MAC, key);
        let mut sh = crate::shell::OsShell::with_seal_key(key);

        // 1. ARP reply target IP (`r[38..42]`) must equal requester SPA (`PEER_IP`), not `[0; 4]`,
        //    and ARP request from a multicast SHA (`01:...`) must be ignored.
        let mut arp_req = [0u8; 42];
        arp_req[..6].copy_from_slice(&[0xFF; 6]);
        arp_req[6..12].copy_from_slice(&PEER_MAC);
        arp_req[12..14].copy_from_slice(&[0x08, 0x06]);
        arp_req[14..22].copy_from_slice(&[0, 1, 0x08, 0x00, 6, 4, 0, 1]);
        arp_req[22..28].copy_from_slice(&PEER_MAC);
        arp_req[28..32].copy_from_slice(&PEER_IP);
        arp_req[38..42].copy_from_slice(&GUEST_IP);
        let mut out = ReplySet::new();
        net.handle_frame(&arp_req, 1, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(
            &out.get(0).unwrap()[38..42],
            &PEER_IP,
            "ARP reply TPA must carry requester SPA, not zeroed THA"
        );

        let mut mcast_arp = arp_req;
        mcast_arp[6] = 0x01;
        mcast_arp[22] = 0x01; // multicast SHA bit set
        let mut mcast_out = ReplySet::new();
        net.handle_frame(&mcast_arp, 1, &mut mcast_out);
        assert_eq!(mcast_out.len(), 0, "multicast SHA ARP request must be dropped");

        // 2. IPv4 header validation: fragment (`MF=1` or `frag_offset != 0`), bad IPv4 checksum,
        //    `TTL == 0`, and Martian `src_ip = 0.0.0.0` must all be dropped.
        let mut icmp = [0u8; 16];
        let nicmp = IcmpImpl::build_echo_request(0x1111, 1, b"x", &mut icmp).unwrap();
        let (good_ip_frame, good_len) = eth_ip(IP_PROTO_ICMP, PEER_IP, GUEST_IP, &icmp[..nicmp]);

        // 2a. Fragmented packet (`MF = 1`, flags_frag = 0x2000)
        let mut frag_frame = good_ip_frame;
        frag_frame[20] = 0x20;
        frag_frame[21] = 0x00;
        frag_frame[24..26].copy_from_slice(&[0, 0]);
        let ck = ipv4_header_checksum(&frag_frame[14..34]);
        frag_frame[24..26].copy_from_slice(&ck.to_be_bytes());
        out = ReplySet::new();
        net.handle_frame(&frag_frame[..good_len], 1, &mut out);
        assert_eq!(out.len(), 0, "fragmented IPv4 packet must be dropped");

        // 2b. Corrupt IPv4 header checksum
        let mut bad_ck_frame = good_ip_frame;
        bad_ck_frame[24] ^= 0xFF;
        out = ReplySet::new();
        net.handle_frame(&bad_ck_frame[..good_len], 1, &mut out);
        assert_eq!(out.len(), 0, "corrupt IPv4 header checksum must be dropped");

        // 2c. Zero TTL
        let mut ttl0_frame = good_ip_frame;
        ttl0_frame[22] = 0;
        ttl0_frame[24..26].copy_from_slice(&[0, 0]);
        let ck0 = ipv4_header_checksum(&ttl0_frame[14..34]);
        ttl0_frame[24..26].copy_from_slice(&ck0.to_be_bytes());
        out = ReplySet::new();
        net.handle_frame(&ttl0_frame[..good_len], 1, &mut out);
        assert_eq!(out.len(), 0, "TTL=0 IPv4 packet must be dropped");

        // 2d. Martian `0.0.0.0` source IP
        let (martian_frame, mlen) = eth_ip(IP_PROTO_ICMP, [0, 0, 0, 0], GUEST_IP, &icmp[..nicmp]);
        out = ReplySet::new();
        net.handle_frame(&martian_frame[..mlen], 1, &mut out);
        assert_eq!(out.len(), 0, "Martian 0.0.0.0 source IP must be dropped");

        // 3. UDP length > slice and bad non-zero UDP checksum must be dropped.
        let payload = b"STATUS?";
        let ulen = 8 + payload.len();
        let mut udp = [0u8; 32];
        udp[0..2].copy_from_slice(&42000u16.to_be_bytes());
        udp[2..4].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
        udp[4..6].copy_from_slice(&(ulen as u16).to_be_bytes());
        udp[8..ulen].copy_from_slice(payload);
        let uc = crate::net::udp_checksum(PEER_IP, GUEST_IP, &udp[..ulen]);
        udp[6..8].copy_from_slice(&(uc ^ 0x00FF).to_be_bytes());
        let (bad_udp_frame, bad_ulen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &udp[..ulen]);
        out = ReplySet::new();
        net.handle_frame(&bad_udp_frame[..bad_ulen], 1, &mut out);
        assert_eq!(out.len(), 0, "corrupt non-zero UDP checksum must be dropped");

        let mut trunc_udp = udp;
        trunc_udp[4..6].copy_from_slice(&((ulen + 8) as u16).to_be_bytes());
        trunc_udp[6..8].copy_from_slice(&[0, 0]);
        let (trunc_udp_frame, trunc_ulen) = eth_ip(IP_PROTO_UDP, PEER_IP, GUEST_IP, &trunc_udp[..ulen]);
        out = ReplySet::new();
        net.handle_frame(&trunc_udp_frame[..trunc_ulen], 1, &mut out);
        assert_eq!(out.len(), 0, "UDP packet with ulen > actual payload must be dropped");

        // 4. Streaming HMAC (zero truncation) & canonical decimal sequence numbers:
        //    `compute_auth_tag` on two >320-byte commands differing ONLY after byte 320 MUST NOT collide!
        let mut long_a = [b'a'; 360];
        long_a[..16].copy_from_slice(b"write /var/long ");
        let mut long_b = long_a;
        long_b[355] = b'Z';
        let (mut tag_a, mut tag_b) = ([0u8; 32], [0u8; 32]);
        LivedNet::compute_auth_tag(&key, b"1", &long_a, &mut tag_a);
        LivedNet::compute_auth_tag(&key, b"1", &long_b, &mut tag_b);
        assert_ne!(
            tag_a, tag_b,
            "compute_auth_tag must authenticate the entire command with zero 320-byte truncation"
        );

        // Non-canonical leading-zero sequence `01` must be rejected by UDP AUTH.
        let mut tag_01 = [0u8; 32];
        LivedNet::compute_auth_tag(&key, b"01", b"uname", &mut tag_01);
        let mut hex_01 = [0u8; 64];
        hex_encode_bytes(&tag_01, &mut hex_01);
        let mut auth_01 = alloc::vec::Vec::from(&b"AUTH 01 "[..]);
        auth_01.extend_from_slice(&hex_01);
        auth_01.extend_from_slice(b" uname");
        let mut resp_buf = [0u8; 256];
        let rn = net.handle_udp_auth(&auth_01[5..], 1, &mut sh, &mut resp_buf);
        assert!(
            resp_buf[..rn].starts_with(b"usage:"),
            "non-canonical leading-zero sequence '01' must be rejected, got: {:?}",
            core::str::from_utf8(&resp_buf[..rn])
        );

        // 5. UDP `:8081` Triad hardening:
        //    - Unprovisioned `TRIAD_STATUS` refused
        //    - Self-peer `TRIAD_PREPARE` (`leader_id == triad_node_id`) refused
        //    - Read-only `TRIAD_PREPARE epoch=999 ... SELECT 1` rejected WITHOUT advancing `triad_min_epoch`!
        let mut unprov_net = LivedNet::new_unprovisioned(MAC);
        let mut unprov_out = [0u8; 256];
        let un_len = unprov_net.handle_udp_triad(b"TRIAD_STATUS", &mut sh, &mut unprov_out);
        assert!(
            unprov_out[..un_len].starts_with(b"error: EACCES"),
            "unprovisioned node must refuse TRIAD_STATUS on :8081"
        );

        sh.triad_node_id = 1;
        // Self-peer loop (`leader_id = 1` sent to `triad_node_id = 1`)
        let mut self_mac = [0u8; 32];
        LivedNet::compute_triad_prepare_tag_with_epoch(
            &key,
            b"5",
            b"1",
            b"1",
            b"INSERT INTO kv VALUES ('self', 'x', 1)",
            &mut self_mac,
        );
        let mut self_hex = [0u8; 64];
        hex_encode_bytes(&self_mac, &mut self_hex);
        let mut self_prep = alloc::vec::Vec::from(&b"TRIAD_PREPARE epoch=5 1 1 "[..]);
        self_prep.extend_from_slice(&self_hex);
        self_prep.extend_from_slice(b" INSERT INTO kv VALUES ('self', 'x', 1)");
        let self_n = net.handle_udp_triad(&self_prep, &mut sh, &mut resp_buf);
        assert!(
            resp_buf[..self_n].starts_with(b"error: EACCES"),
            "self-peer TRIAD_PREPARE must be rejected"
        );
        assert_eq!(net.triad_min_epoch, 0);

        // Read-only SQL with `epoch=999` from valid peer `0` must fail WITHOUT poisoning `triad_min_epoch`!
        let mut ro_mac = [0u8; 32];
        LivedNet::compute_triad_prepare_tag_with_epoch(
            &key,
            b"999",
            b"1",
            b"0",
            b"SELECT * FROM kv",
            &mut ro_mac,
        );
        let mut ro_hex = [0u8; 64];
        hex_encode_bytes(&ro_mac, &mut ro_hex);
        let mut ro_prep = alloc::vec::Vec::from(&b"TRIAD_PREPARE epoch=999 1 0 "[..]);
        ro_prep.extend_from_slice(&ro_hex);
        ro_prep.extend_from_slice(b" SELECT * FROM kv");
        let ro_n = net.handle_udp_triad(&ro_prep, &mut sh, &mut resp_buf);
        assert!(resp_buf[..ro_n].starts_with(b"error: EINVAL"));
        assert_eq!(
            net.triad_min_epoch, 0,
            "rejected read-only TRIAD_PREPARE must not advance triad_min_epoch"
        );
        assert_eq!(sh.triad_min_epoch, 0);
    }

    #[test]
    fn stage9_udp_threads_run_refused_unauth_all_roles_and_http_sql_tx_session_visibility() {
        const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        let key = [0x33u8; 32];

        // 1. Unauthenticated UDP `:8080` `CMD threads run 8` and `CMD smp run 8` MUST be refused
        //    with `error: EACCES` across ALL 4 node roles (`Wfe`, `Sql`, `Shell`, `Full`)!
        for role in [
            crate::svc_runtime::NodeRole::Wfe,
            crate::svc_runtime::NodeRole::Sql,
            crate::svc_runtime::NodeRole::Shell,
            crate::svc_runtime::NodeRole::Full,
        ] {
            let mut net = LivedNet::with_auth_key(MAC, key);
            let mut sh = crate::shell::OsShell::new();
            sh.svc.set_role(role, &mut sh.audit);
            let before_ipis = sh.smp_ipi_doorbells;

            for raw_cmd in [b"CMD threads run 8".as_slice(), b"CMD smp run 8".as_slice()] {
                let ulen = (8 + raw_cmd.len()) as u16;
                let mut udp = alloc::vec![0u8; ulen as usize];
                udp[0..2].copy_from_slice(&50000u16.to_be_bytes());
                udp[2..4].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
                udp[4..6].copy_from_slice(&ulen.to_be_bytes());
                udp[6..8].copy_from_slice(&0u16.to_be_bytes());
                udp[8..].copy_from_slice(raw_cmd);

                let mut replies = ReplySet::new();
                net.handle_udp(
                    &udp,
                    [0xaa; 6],
                    [10, 0, 2, 2],
                    [10, 0, 2, 2],
                    1,
                    Some(&mut sh),
                    &mut replies,
                );
                assert_eq!(replies.count, 1);
                let frame = replies.get(0).unwrap();
                let udp_body = &frame[42..];
                assert!(
                    udp_body.starts_with(b"error: EACCES"),
                    "role {role:?} must refuse unauthenticated {:?} on UDP :8080, got {:?}",
                    core::str::from_utf8(raw_cmd),
                    core::str::from_utf8(udp_body)
                );
                assert_eq!(sh.smp_ipi_doorbells, before_ipis);
            }
        }

        // 2. Authenticated HTTP `POST /sql` and `GET /sql?...` inside an active `BEGIN` transaction
        //    must preserve session ownership so the transaction owner sees its uncommitted writes,
        //    while unauthenticated readers stay isolated on the committed snapshot!
        let mut net = LivedNet::with_auth_key(MAC, key);
        let mut sh = crate::shell::OsShell::new();
        let sid_bytes = sh.try_create_session(b"alice", b"nonce1").unwrap();
        let sid_str = core::str::from_utf8(&sid_bytes).unwrap();
        let mut out = [0u8; 1024];

        let req_begin = alloc::format!("POST /sql HTTP/1.1\r\nCookie: sid={sid_str}\r\n\r\nBEGIN");
        let nb = net.handle_http_request(req_begin.as_bytes(), 1, Some(&mut sh), &mut out);
        assert!(core::str::from_utf8(&out[..nb]).unwrap().ends_with("\r\n\r\nBEGIN OK\n"));

        let req_ins = alloc::format!(
            "POST /sql HTTP/1.1\r\nCookie: sid={sid_str}\r\n\r\nINSERT INTO kv VALUES ('tx.key', 'tx.val', 7)"
        );
        let ni = net.handle_http_request(req_ins.as_bytes(), 1, Some(&mut sh), &mut out);
        assert!(core::str::from_utf8(&out[..ni]).unwrap().ends_with("\r\n\r\nINSERT 1\n"));

        // Unauthenticated reader MUST NOT see uncommitted row:
        let nu = net.handle_http_request(
            b"POST /sql HTTP/1.1\r\nHost: x\r\n\r\nSELECT v FROM kv WHERE k = 'tx.key'",
            1,
            Some(&mut sh),
            &mut out,
        );
        assert!(
            core::str::from_utf8(&out[..nu]).unwrap().ends_with("\r\n\r\nv\n"),
            "unauthenticated reader must not see uncommitted row: {:?}",
            core::str::from_utf8(&out[..nu])
        );

        // Authenticated transaction owner MUST see its own uncommitted row on both POST /sql and GET /sql:
        let req_post_sel = alloc::format!(
            "POST /sql HTTP/1.1\r\nCookie: sid={sid_str}\r\n\r\nSELECT v FROM kv WHERE k = 'tx.key'"
        );
        let nps = net.handle_http_request(req_post_sel.as_bytes(), 1, Some(&mut sh), &mut out);
        assert!(
            core::str::from_utf8(&out[..nps])
                .unwrap()
                .ends_with("\r\n\r\nv\ntx.val\n"),
            "authenticated POST /sql owner must read its own uncommitted write: {:?}",
            core::str::from_utf8(&out[..nps])
        );

        let req_get_sel = alloc::format!(
            "GET /sql?SELECT%20v%20FROM%20kv%20WHERE%20k%20=%20%27tx.key%27 HTTP/1.1\r\nCookie: sid={sid_str}\r\n\r\n"
        );
        let ngs = net.handle_http_request(req_get_sel.as_bytes(), 1, Some(&mut sh), &mut out);
        assert!(
            core::str::from_utf8(&out[..ngs])
                .unwrap()
                .ends_with("\r\n\r\nv\ntx.val\n"),
            "authenticated GET /sql owner must read its own uncommitted write: {:?}",
            core::str::from_utf8(&out[..ngs])
        );

        let req_rb = alloc::format!("POST /sql HTTP/1.1\r\nCookie: sid={sid_str}\r\n\r\nROLLBACK");
        let nrb = net.handle_http_request(req_rb.as_bytes(), 1, Some(&mut sh), &mut out);
        assert!(core::str::from_utf8(&out[..nrb]).unwrap().ends_with("\r\n\r\nROLLBACK OK\n"));
    }

    #[test]
    fn stage12_https_connection_flood_refused_when_heap_reserve_low() {
        crate::tls_provider::SYSTEM_RNG.reseed([0x5Au8; 32]);
        let secret = [0x42u8; 32];
        let identity = crate::https::ServerIdentity::derive(&secret, MAC);
        let cfg = crate::https::server_config(&identity, crate::tls_provider::system_provider())
            .expect("TLS 1.3 server_config");

        let mut net = LivedNet::with_auth_key(MAC, secret);
        net.enable_tls(cfg);
        // Simulate Ring-0 heap emergency reserve threshold reached (`has_headroom -> false`).
        net.set_heap_headroom_guard(|_| false);
        let mut sh = crate::shell::OsShell::new();

        // 1. Complete TCP 3-way SYN -> SYN/ACK -> ClientHello PSH|ACK on port 443 (`HTTPS_PORT`).
        let client_isn: u32 = 0x7100_0000;
        let client_port: u16 = 54443;
        let mut syn = [0u8; 40];
        let ns = TcpImpl::build_segment(
            client_port,
            HTTPS_PORT,
            client_isn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let (f_syn, flen_syn) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..ns]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&f_syn[..flen_syn], 1, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();

        let fake_client_hello = [0x16u8, 0x03, 0x01, 0x00, 0x05, 0x01, 0x00, 0x00, 0x01, 0x00];
        let mut psh = [0u8; 80];
        let np = TcpImpl::build_segment(
            client_port,
            HTTPS_PORT,
            client_isn.wrapping_add(1),
            sa.seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            &fake_client_hello,
            PEER_IP,
            GUEST_IP,
            &mut psh,
        )
        .unwrap();
        let (f_psh, flen_psh) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &psh[..np]);
        let mut out2 = ReplySet::new();
        net.handle_frame_with_shell(&f_psh[..flen_psh], 1, &mut sh, &mut out2);

        // Zero `TlsSession` heap allocations occurred, `FIN` was emitted to close the TCP slot,
        // and `net:tls:heap_reserve` denial was recorded in the kernel audit ring!
        assert_eq!(
            net.tls_sessions_started, 0,
            "TLS session allocation must be refused when Ring-0 emergency heap reserve is low"
        );
        let mut saw_fin = false;
        for idx in 0..out2.len() {
            let seg = TcpImpl::parse_segment(&out2.get(idx).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            if (seg.flags & tcp_flags::FIN) != 0 {
                saw_fin = true;
            }
        }
        assert!(saw_fin, "refused HTTPS slot must actively emit TCP FIN");

        let mut audit_buf = [0u8; 4096];
        let crate::shell::ShellAction::Continue(an) = sh.exec_line(b"audit", 1, 0, 0, &mut audit_buf) else {
            panic!("audit command must return ShellAction::Continue");
        };
        let audit_str = core::str::from_utf8(&audit_buf[..an]).unwrap();
        assert!(
            audit_str.contains("net:tls:heap_reserve"),
            "audit log must record net:tls:heap_reserve denial, got: {audit_str}"
        );
    }

    #[test]
    fn stage18_wan_tcp_syn_cookies_ooo_reassembly_and_payload_rto_retransmit() {
        let mut net = LivedNet::with_auth_key(MAC, [0x77u8; 32]);
        net.set_syn_cookie_threshold(4);
        let mut sh = crate::shell::OsShell::new();

        // --- Part 1: 64-SYN flood with stateless HMAC-SHA256 SYN Cookies ---
        let mut saved_cookie_sa_seq: u32 = 0;
        let flood_base_port: u16 = 40000;
        for i in 0..64u16 {
            let cport = flood_base_port + i;
            let cisn = 0x1000_0000u32.wrapping_add((i as u32) * 0x1000);
            let mut syn = [0u8; 40];
            let ns = TcpImpl::build_segment(
                cport,
                HTTP_PORT,
                cisn,
                0,
                tcp_flags::SYN,
                65535,
                b"",
                PEER_IP,
                GUEST_IP,
                &mut syn,
            )
            .unwrap();
            let (f, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..ns]);
            let mut out = ReplySet::new();
            net.handle_frame_with_shell(&f[..flen], 1, &mut sh, &mut out);
            assert_eq!(out.len(), 1, "SYN #{i} must receive SYN-ACK");
            let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            assert_eq!(sa.flags, tcp_flags::SYN | tcp_flags::ACK);
            if i == 50 {
                saved_cookie_sa_seq = sa.seq;
            }
        }
        assert_eq!(net.active_tcp_slots(), 4, "SYN cookies must cap half-open slot usage at threshold");
        assert_eq!(net.syn_cookies_sent, 60);

        // Forged cookie ACK must be dropped without allocating a TCB slot.
        let c50_port = flood_base_port + 50;
        let c50_isn = 0x1000_0000u32.wrapping_add(50 * 0x1000);
        let req_get = b"GET /healthz HTTP/1.1\r\nHost: cuttle\r\n\r\n";
        let mut forged = [0u8; 128];
        let nf = TcpImpl::build_segment(
            c50_port,
            HTTP_PORT,
            c50_isn.wrapping_add(1),
            saved_cookie_sa_seq.wrapping_add(0xDEAD),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req_get,
            PEER_IP,
            GUEST_IP,
            &mut forged,
        )
        .unwrap();
        let (ff, fflen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &forged[..nf]);
        let mut fout = ReplySet::new();
        net.handle_frame_with_shell(&ff[..fflen], 1, &mut sh, &mut fout);
        assert_eq!(net.syn_cookies_accepted, 0);
        assert_eq!(net.active_tcp_slots(), 4);

        // Valid cookie ACK+PSH promotes statelessly into Slot #5 and serves `200 OK` immediately!
        let mut valid_ack = [0u8; 128];
        let nv = TcpImpl::build_segment(
            c50_port,
            HTTP_PORT,
            c50_isn.wrapping_add(1),
            saved_cookie_sa_seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req_get,
            PEER_IP,
            GUEST_IP,
            &mut valid_ack,
        )
        .unwrap();
        let (vf, vflen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &valid_ack[..nv]);
        let mut vout = ReplySet::new();
        net.handle_frame_with_shell(&vf[..vflen], 1, &mut sh, &mut vout);
        assert_eq!(net.syn_cookies_accepted, 1);
        let mut saw_cookie_200 = false;
        for idx in 0..vout.len() {
            let seg = TcpImpl::parse_segment(&vout.get(idx).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            if seg.payload.starts_with(b"HTTP/1.1 200 OK") {
                saw_cookie_200 = true;
            }
        }
        assert!(saw_cookie_200, "stateless SYN cookie promotion must deliver HTTP 200 OK");

        // --- Part 2: Out-of-Order (`OOO`) TCP reassembly + RFC 5681 duplicate ACK ---
        let mut net2 = LivedNet::with_auth_key(MAC, [0x88u8; 32]);
        let ooo_port: u16 = 41000;
        let ooo_isn: u32 = 0x2200_0000;
        let mut syn2 = [0u8; 40];
        let ns2 = TcpImpl::build_segment(
            ooo_port,
            HTTP_PORT,
            ooo_isn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn2,
        )
        .unwrap();
        let (fs2, fls2) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn2[..ns2]);
        let mut out_sa2 = ReplySet::new();
        net2.handle_frame_with_shell(&fs2[..fls2], 1, &mut sh, &mut out_sa2);
        let sa2 = TcpImpl::parse_segment(&out_sa2.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();

        let mut ack3 = [0u8; 40];
        let na3 = TcpImpl::build_segment(
            ooo_port,
            HTTP_PORT,
            ooo_isn.wrapping_add(1),
            sa2.seq.wrapping_add(1),
            tcp_flags::ACK,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut ack3,
        )
        .unwrap();
        let (fa3, fla3) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ack3[..na3]);
        let mut out_a3 = ReplySet::new();
        net2.handle_frame_with_shell(&fa3[..fla3], 1, &mut sh, &mut out_a3);

        let part1 = b"GET /healthz ";
        let part2 = b"HTTP/1.1\r\nHost: cuttle\r\n\r\n";

        // Send `part2` FIRST (out-of-order forward gap = `part1.len()`): expect Dup-ACK for `ooo_isn + 1`.
        let mut seg_p2 = [0u8; 128];
        let np2 = TcpImpl::build_segment(
            ooo_port,
            HTTP_PORT,
            ooo_isn.wrapping_add(1 + part1.len() as u32),
            sa2.seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            part2,
            PEER_IP,
            GUEST_IP,
            &mut seg_p2,
        )
        .unwrap();
        let (fp2, flp2) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &seg_p2[..np2]);
        let mut out_dup = ReplySet::new();
        net2.handle_frame_with_shell(&fp2[..flp2], 1, &mut sh, &mut out_dup);
        assert_eq!(out_dup.len(), 1, "OOO segment must trigger immediate RFC 5681 duplicate ACK");
        let dup_ack = TcpImpl::parse_segment(&out_dup.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        assert_eq!(dup_ack.ack, ooo_isn.wrapping_add(1));
        assert!(dup_ack.payload.is_empty());

        // Now send missing `part1`: OOO queue coalesces `part1 + part2` and emits `HTTP/1.1 200 OK`!
        let mut seg_p1 = [0u8; 128];
        let np1 = TcpImpl::build_segment(
            ooo_port,
            HTTP_PORT,
            ooo_isn.wrapping_add(1),
            sa2.seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            part1,
            PEER_IP,
            GUEST_IP,
            &mut seg_p1,
        )
        .unwrap();
        let (fp1, flp1) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &seg_p1[..np1]);
        let mut out_coal = ReplySet::new();
        net2.handle_frame_with_shell(&fp1[..flp1], 1, &mut sh, &mut out_coal);
        assert_eq!(net2.ooo_reassembled, 1);

        let mut resp_seq: u32 = 0;
        let mut resp_len: u32 = 0;
        for idx in 0..out_coal.len() {
            let seg = TcpImpl::parse_segment(&out_coal.get(idx).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            if seg.payload.starts_with(b"HTTP/1.1 200 OK") {
                assert_eq!(
                    seg.ack,
                    ooo_isn.wrapping_add(1 + (part1.len() + part2.len()) as u32)
                );
                resp_seq = seg.seq;
                resp_len = seg.payload.len() as u32;
            }
        }
        assert!(resp_len > 0, "coalesced OOO HTTP request must produce HTTP 200 OK");

        // --- Part 3: Unacknowledged Server Payload RTO Retransmit + RFC 6298 Backoff ---
        assert_eq!(net2.total_inflight_tx_bytes(), resp_len as usize);
        let base_rto = net2.rto_retransmit_ticks();
        let mut rto_out = ReplySet::new();
        for _ in 0..base_rto {
            let _ = net2.tick_tcp_rto_with_replies(&mut rto_out);
        }
        assert_eq!(net2.payload_retransmits, 1, "first RTO expiry must retransmit dropped HTTP response");
        let rtx_seg = TcpImpl::parse_segment(&rto_out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        assert_eq!(rtx_seg.seq, resp_seq);
        assert!(rtx_seg.payload.starts_with(b"HTTP/1.1 200 OK"));

        // Exponential backoff (`2 * base_rto` required before 2nd retransmit):
        let mut half_backoff = ReplySet::new();
        for _ in 0..base_rto {
            let _ = net2.tick_tcp_rto_with_replies(&mut half_backoff);
        }
        assert_eq!(
            net2.payload_retransmits, 1,
            "exponential backoff must double RTO interval before 2nd retransmit"
        );
        for _ in 0..base_rto {
            let _ = net2.tick_tcp_rto_with_replies(&mut half_backoff);
        }
        assert_eq!(net2.payload_retransmits, 2);

        // Peer cumulative ACK clears `tx_inflight_buf` to 0 bytes!
        let mut final_ack = [0u8; 40];
        let nfa = TcpImpl::build_segment(
            ooo_port,
            HTTP_PORT,
            ooo_isn.wrapping_add(1 + (part1.len() + part2.len()) as u32),
            resp_seq.wrapping_add(resp_len),
            tcp_flags::ACK,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut final_ack,
        )
        .unwrap();
        let (ffa, flfa) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &final_ack[..nfa]);
        let mut ack_out = ReplySet::new();
        net2.handle_frame_with_shell(&ffa[..flfa], 1, &mut sh, &mut ack_out);
        assert_eq!(net2.total_inflight_tx_bytes(), 0);
    }

    #[test]
    fn http_tcp_slots_and_recycled_sessions_use_isolated_sql_owners() {
        let mut net = LivedNet::new([0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let mut sh = crate::shell::OsShell::new();

        // 1. Two concurrent TCP slots receive strictly distinct anonymous SQL owner IDs,
        //    and a recycled slot receives a monotonically bumped epoch owner ID.
        let s0 = net.claim_verified_tcp_slot(HTTP_PORT, false).unwrap();
        net.tcbs[s0].state = TcpState::Established;
        let s1 = net.claim_verified_tcp_slot(HTTP_PORT, false).unwrap();
        net.tcbs[s1].state = TcpState::Established;
        assert_ne!(s0, s1);
        let owner_s0_first = net.slot_anon_sql_owner(s0);
        let owner_s1 = net.slot_anon_sql_owner(s1);
        assert_ne!(owner_s0_first, owner_s1);
        assert_ne!(owner_s0_first, crate::sql::SQL_OWNER_HTTP_ANON);
        assert_ne!(owner_s1, crate::sql::SQL_OWNER_HTTP_ANON);

        net.tcbs[s0] = Tcb::EMPTY;
        let s0_reused = net.claim_verified_tcp_slot(HTTP_PORT, false).unwrap();
        assert_eq!(s0_reused, s0);
        let owner_s0_second = net.slot_anon_sql_owner(s0_reused);
        assert_ne!(
            owner_s0_first, owner_s0_second,
            "recycled TCP slot must get a fresh anonymous SQL owner ID"
        );

        // 2. Session A opens a transaction via HTTP POST /sql, times out (leaving Session A's
        //    SQL owner in `tx_aborted`), and logs out. Session B is then minted in the same
        //    recycled session slot 0 — Session B MUST receive a fresh owner ID and succeed!
        let sid_a = sh.try_create_session(b"alice", b"chal-a").expect("mint sid_a");
        let req_begin = alloc::format!(
            "POST /sql HTTP/1.1\r\nHost: cuttle\r\nCookie: sid={}\r\nContent-Length: 5\r\n\r\nBEGIN",
            core::str::from_utf8(&sid_a).unwrap()
        );
        let mut resp = [0u8; 1024];
        let n = net.handle_http_request(req_begin.as_bytes(), 1, Some(&mut sh), &mut resp);
        assert!(core::str::from_utf8(&resp[..n]).unwrap().contains("BEGIN OK"));

        for _ in 0..16 {
            let _ = sh.db.tick_transaction_timeout();
        }
        assert!(sh.db.tx_aborted);
        assert!(sh.revoke_session(&sid_a));

        let sid_b = sh.try_create_session(b"bob", b"chal-b").expect("mint sid_b in slot 0");
        let body_ins = "INSERT INTO kv VALUES ('bob.iso', 'ok', 1)";
        let req_ins = alloc::format!(
            "POST /sql HTTP/1.1\r\nHost: cuttle\r\nCookie: sid={}\r\nContent-Length: {}\r\n\r\n{}",
            core::str::from_utf8(&sid_b).unwrap(),
            body_ins.len(),
            body_ins
        );
        let n2 = net.handle_http_request(req_ins.as_bytes(), 1, Some(&mut sh), &mut resp);
        let s2 = core::str::from_utf8(&resp[..n2]).unwrap();
        assert!(
            s2.contains("INSERT 1"),
            "recycled session slot must not inherit previous session's aborted SQL state: {s2}"
        );
    }

    #[test]
    fn triad_rpc_refuses_unauthenticated_unprovisioned_replay_and_stale_epoch_across_all_roles() {
        use crate::svc_runtime::NodeRole;

        let roles = [
            NodeRole::Full,
            NodeRole::Wfe,
            NodeRole::Sql,
            NodeRole::Shell,
        ];
        let auth_key = [0x5Au8; 32];

        for role in roles {
            // 1. Unprovisioned node refuses POST /triad/rpc with 403 in every role.
            let mut unprov = LivedNet::new_unprovisioned(MAC);
            let mut sh_u = crate::shell::OsShell::new();
            sh_u.svc.set_role(role, &mut sh_u.audit);
            let mut resp = alloc::vec![0u8; 4096];
            let req_unprov =
                b"POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: 5\r\n\r\nuname";
            let n = unprov.handle_http_request(req_unprov, 1, Some(&mut sh_u), &mut resp);
            let s = core::str::from_utf8(&resp[..n]).unwrap();
            assert!(
                s.starts_with("HTTP/1.1 403"),
                "role {role:?} unprovisioned must return 403, got: {s}"
            );

            // 2. Provisioned node refuses GET /triad/rpc (405), empty body (400),
            //    credential-free command (400), control-char smuggling (400),
            //    oversized command >512B (413), invalid hex (401), and wrong HMAC (401)
            //    across EVERY node role.
            let mut net = LivedNet::with_auth_key(MAC, auth_key);
            let mut sh = crate::shell::OsShell::new();
            sh.svc.set_role(role, &mut sh.audit);

            let get_req = b"GET /triad/rpc HTTP/1.1\r\nHost: cuttle\r\n\r\n";
            let ng = net.handle_http_request(get_req, 1, Some(&mut sh), &mut resp);
            assert!(
                core::str::from_utf8(&resp[..ng])
                    .unwrap()
                    .starts_with("HTTP/1.1 405"),
                "role {role:?} GET /triad/rpc must return 405"
            );

            for bad_body in [
                &b""[..],
                &b"uname"[..],
                &b"0 1 "
                    [..],
                &b"1 1 0000000000000000000000000000000000000000000000000000000000000000 uname\x07"[..],
            ] {
                let req = alloc::format!(
                    "POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: {}\r\n\r\n",
                    bad_body.len()
                );
                let mut raw = req.into_bytes();
                raw.extend_from_slice(bad_body);
                let nb = net.handle_http_request(&raw, 1, Some(&mut sh), &mut resp);
                let sb = core::str::from_utf8(&resp[..nb]).unwrap();
                assert!(
                    sb.starts_with("HTTP/1.1 400"),
                    "role {role:?} malformed body must return 400, got: {sb}"
                );
            }

            let over_cmd = alloc::vec![b'a'; 513];
            let over_hdr = alloc::format!(
                "1 1 {} ",
                "aa".repeat(32)
            );
            let mut over_body = over_hdr.into_bytes();
            over_body.extend_from_slice(&over_cmd);
            let over_req_hdr = alloc::format!(
                "POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: {}\r\n\r\n",
                over_body.len()
            );
            let mut over_raw = over_req_hdr.into_bytes();
            over_raw.extend_from_slice(&over_body);
            let no = net.handle_http_request(&over_raw, 1, Some(&mut sh), &mut resp);
            assert!(
                core::str::from_utf8(&resp[..no])
                    .unwrap()
                    .starts_with("HTTP/1.1 413"),
                "role {role:?} >512B RPC command must be rejected with 413, never truncated"
            );

            let bad_hex_body = alloc::format!("1 1 {} uname", "zz".repeat(32));
            let bad_hex_req = alloc::format!(
                "POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: {}\r\n\r\n{}",
                bad_hex_body.len(),
                bad_hex_body
            );
            let nh = net.handle_http_request(bad_hex_req.as_bytes(), 1, Some(&mut sh), &mut resp);
            assert!(
                core::str::from_utf8(&resp[..nh])
                    .unwrap()
                    .starts_with("HTTP/1.1 401"),
                "role {role:?} bad HMAC hex must return 401"
            );

            let wrong_hmac_body = alloc::format!("1 1 {} uname", "11".repeat(32));
            let wrong_hmac_req = alloc::format!(
                "POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: {}\r\n\r\n{}",
                wrong_hmac_body.len(),
                wrong_hmac_body
            );
            let nw =
                net.handle_http_request(wrong_hmac_req.as_bytes(), 1, Some(&mut sh), &mut resp);
            assert!(
                core::str::from_utf8(&resp[..nw])
                    .unwrap()
                    .starts_with("HTTP/1.1 401"),
                "role {role:?} wrong HMAC must return 401"
            );
            assert_eq!(net.triad_rpcs_accepted, 0);

            // 3. Authenticated SQL command succeeds on Full & Sql (200) and is refused by
            //    service role mediation (503) on Wfe & Shell.
            let cmd = b"sql INSERT INTO kv VALUES ('rpc.k', 'ok', 7)";
            let mut tag = [0u8; 32];
            LivedNet::compute_triad_rpc_tag(&auth_key, b"2", b"1", cmd, &mut tag);
            let mut hex = [0u8; 64];
            hex_encode_bytes(&tag, &mut hex);
            let valid_body = alloc::format!(
                "2 1 {} {}",
                core::str::from_utf8(&hex).unwrap(),
                core::str::from_utf8(cmd).unwrap()
            );
            let valid_req = alloc::format!(
                "POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: {}\r\n\r\n{}",
                valid_body.len(),
                valid_body
            );
            let nv = net.handle_http_request(valid_req.as_bytes(), 1, Some(&mut sh), &mut resp);
            let sv = core::str::from_utf8(&resp[..nv]).unwrap();
            match role {
                NodeRole::Full | NodeRole::Sql => {
                    assert!(
                        sv.starts_with("HTTP/1.1 200") && sv.contains("INSERT 1"),
                        "role {role:?} must execute authenticated SQL RPC: {sv}"
                    );
                }
                NodeRole::Wfe | NodeRole::Shell => {
                    assert!(
                        sv.starts_with("HTTP/1.1 503") && sv.contains("disabled by node role"),
                        "role {role:?} must return 503 when svc-sql is disabled: {sv}"
                    );
                }
            }
        }

        // 4. Epoch fencing (409), sequence replay rejection (401), and WAL S-record persistence.
        let mut net = LivedNet::with_auth_key(MAC, auth_key);
        let mut sh = crate::shell::OsShell::new();
        let mut resp = alloc::vec![0u8; 4096];

        let send_rpc = |net: &mut LivedNet,
                        sh: &mut crate::shell::OsShell,
                        ep: &str,
                        sq: &str,
                        cmd: &str,
                        out: &mut [u8]|
         -> alloc::string::String {
            let mut tag = [0u8; 32];
            LivedNet::compute_triad_rpc_tag(
                &auth_key,
                ep.as_bytes(),
                sq.as_bytes(),
                cmd.as_bytes(),
                &mut tag,
            );
            let mut hex = [0u8; 64];
            hex_encode_bytes(&tag, &mut hex);
            let body = alloc::format!(
                "{} {} {} {}",
                ep,
                sq,
                core::str::from_utf8(&hex).unwrap(),
                cmd
            );
            let req = alloc::format!(
                "POST /triad/rpc HTTP/1.1\r\nHost: cuttle\r\nContent-Length: {}\r\n\r\n{}",
                body.len(),
                body
            );
            let n = net.handle_http_request(req.as_bytes(), 1, Some(sh), out);
            alloc::string::String::from(core::str::from_utf8(&out[..n]).unwrap())
        };

        let r1 = send_rpc(&mut net, &mut sh, "2", "10", "uname", &mut resp);
        assert!(r1.starts_with("HTTP/1.1 200"));
        assert_eq!(sh.triad_rpc_seq, 10);
        assert_eq!(sh.triad_min_epoch, 2);

        // Replay seq=10 -> 401.
        let r_rep = send_rpc(&mut net, &mut sh, "2", "10", "uname", &mut resp);
        assert!(r_rep.starts_with("HTTP/1.1 401"));

        // Stale epoch=1 (< 2) with higher seq=11 -> 409 Conflict!
        let r_stale = send_rpc(&mut net, &mut sh, "1", "11", "uname", &mut resp);
        assert!(r_stale.starts_with("HTTP/1.1 409 Conflict"));

        // Standby coordinator promotes to epoch=3, seq=11 -> 200 OK and fences epoch=2!
        let r_prom = send_rpc(&mut net, &mut sh, "3", "11", "uname", &mut resp);
        assert!(r_prom.starts_with("HTTP/1.1 200"));
        let r_fenced = send_rpc(&mut net, &mut sh, "2", "12", "uname", &mut resp);
        assert!(r_fenced.starts_with("HTTP/1.1 409 Conflict"));

        // Persist across simulated reboot and verify seq<=11 and epoch<3 remain fenced!
        let mut wal_secs = [[0u8; 512]; crate::shell::SHELL_JOURNAL_PART_SECTORS];
        sh.pack_journal_sectors(2, &mut wal_secs).unwrap();
        let mut sh2 = crate::shell::OsShell::new();
        sh2.unpack_journal_sectors(&wal_secs).unwrap();
        assert_eq!(sh2.triad_rpc_seq, 11);
        assert_eq!(sh2.triad_min_epoch, 3);
        let mut net2 = LivedNet::with_auth_key(MAC, auth_key);
        let r_after_reboot_replay = send_rpc(&mut net2, &mut sh2, "3", "11", "uname", &mut resp);
        assert!(r_after_reboot_replay.starts_with("HTTP/1.1 401"));
    }

    #[test]
    fn ipv6_icmpv6_echo_and_ndp_kat_and_edge_case_parsers() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();
        let ll = net.ipv6_link_local();
        assert_eq!(
            ll,
            [
                0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0x12, 0x34, 0x56
            ]
        );
        let peer_v6 = [
            0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x50, 0x54, 0x00, 0xff, 0xfe, 0xaa, 0xbb, 0xcc,
        ];
        let peer_ula = [0xfd, 0x00, 0, 0, 0, 0, 0, 0, 0, 0, 0x10, 0x02, 0, 0, 0, 0x02];

        // 1. RFC 8200 §8.1 checksum Known-Answer Test: Echo Request [128, 0, 0, 0, 0x12, 0x34, 0, 1, b'A', b'B']
        let mut echo = [128u8, 0, 0, 0, 0x12, 0x34, 0x00, 0x01, b'A', b'B'];
        let ck = LivedNet::ipv6_upper_layer_checksum(&peer_v6, &ll, IP_PROTO_ICMPV6, &echo);
        echo[2..4].copy_from_slice(&ck.to_be_bytes());
        assert_eq!(
            LivedNet::ipv6_upper_layer_checksum(&peer_v6, &ll, IP_PROTO_ICMPV6, &echo),
            0,
            "RFC 8200 ones-complement verification of signed ICMPv6 packet must fold to 0"
        );

        let build_v6_frame =
            |src_mac: [u8; 6], src: [u8; 16], dst: [u8; 16], hop: u8, payload: &[u8]| {
                let mut f = alloc::vec![0u8; ETH_HEADER_LEN + IPV6_HEADER_LEN + payload.len()];
                f[0..6].copy_from_slice(&MAC);
                f[6..12].copy_from_slice(&src_mac);
                f[12..14].copy_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
                let ip6 = &mut f[ETH_HEADER_LEN..ETH_HEADER_LEN + IPV6_HEADER_LEN];
                ip6[0] = 0x60;
                ip6[4..6].copy_from_slice(&(payload.len() as u16).to_be_bytes());
                ip6[6] = IP_PROTO_ICMPV6;
                ip6[7] = hop;
                ip6[8..24].copy_from_slice(&src);
                ip6[24..40].copy_from_slice(&dst);
                f[ETH_HEADER_LEN + IPV6_HEADER_LEN..].copy_from_slice(payload);
                f
            };

        // 2. Link-local Echo Request -> Echo Reply (type=129, hop_limit=64).
        let frame_echo = build_v6_frame(PEER_MAC, peer_v6, ll, 64, &echo);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame_echo, 1, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        assert_eq!(net.ipv6_icmp_echos, 1);
        let rep = out.get(0).unwrap();
        assert_eq!(u16::from_be_bytes([rep[12], rep[13]]), ETHERTYPE_IPV6);
        assert_eq!(&rep[22..38], &ll);
        assert_eq!(&rep[38..54], &peer_v6);
        assert_eq!(rep[54], 129);
        assert_eq!(&rep[62..64], b"AB");

        // 3. ULA Echo Request -> Echo Reply sourced from GUEST_IPV6_ULA.
        let mut echo_ula = [128u8, 0, 0, 0, 0xbe, 0xef, 0x00, 0x02, b'U', b'L', b'A'];
        let ck_u = LivedNet::ipv6_upper_layer_checksum(
            &peer_ula,
            &GUEST_IPV6_ULA,
            IP_PROTO_ICMPV6,
            &echo_ula,
        );
        echo_ula[2..4].copy_from_slice(&ck_u.to_be_bytes());
        out.clear();
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_ula, GUEST_IPV6_ULA, 64, &echo_ula),
            1,
            &mut sh,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(&out.get(0).unwrap()[22..38], &GUEST_IPV6_ULA);

        // 4. RFC 4861 Neighbor Solicitation on Solicited-Node Multicast -> Neighbor Advertisement.
        let sol_mc = [
            0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xff, ll[13], ll[14], ll[15],
        ];
        let mut ns = [0u8; 32];
        ns[0] = 135;
        ns[8..24].copy_from_slice(&ll);
        ns[24] = 1; // Source Link-Layer Address option
        ns[25] = 1;
        ns[26..32].copy_from_slice(&PEER_MAC);
        let ck_ns = LivedNet::ipv6_upper_layer_checksum(&peer_v6, &sol_mc, IP_PROTO_ICMPV6, &ns);
        ns[2..4].copy_from_slice(&ck_ns.to_be_bytes());
        out.clear();
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_v6, sol_mc, 255, &ns),
            1,
            &mut sh,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        assert_eq!(net.ipv6_ndp_replies, 1);
        let na_frame = out.get(0).unwrap();
        assert_eq!(na_frame[21], 255); // hop_limit = 255
        let na_icmp = &na_frame[54..86];
        assert_eq!(na_icmp[0], 136);
        assert_eq!(&na_icmp[4..8], &[0x60, 0x00, 0x00, 0x00]); // Solicited | Override
        assert_eq!(&na_icmp[8..24], &ll);
        assert_eq!(na_icmp[24], 2); // Target Link-Layer Address
        assert_eq!(na_icmp[25], 1);
        assert_eq!(&na_icmp[26..32], &MAC);

        // 5. Edge cases: empty, truncated, hop_limit=0, bad checksum, multicast source,
        //    NS hop_limit!=255, zero-length NDP option, oversized Echo >MAX_FRAME, and guard lockdown.
        out.clear();
        net.handle_frame_with_shell(&[], 1, &mut sh, &mut out);
        net.handle_frame_with_shell(&frame_echo[..30], 1, &mut sh, &mut out);
        let mut trunc_plen = frame_echo.clone();
        trunc_plen[18..20].copy_from_slice(&500u16.to_be_bytes());
        net.handle_frame_with_shell(&trunc_plen, 1, &mut sh, &mut out);
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_v6, ll, 0, &echo),
            1,
            &mut sh,
            &mut out,
        );
        let mut bad_ck = echo;
        bad_ck[3] ^= 0x01;
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_v6, ll, 64, &bad_ck),
            1,
            &mut sh,
            &mut out,
        );
        // Multicast source spoof
        let mc_src = [0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, mc_src, ll, 64, &echo),
            1,
            &mut sh,
            &mut out,
        );
        // NS with hop_limit = 64 != 255 MUST be discarded per RFC 4861 §7.1.1
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_v6, sol_mc, 64, &ns),
            1,
            &mut sh,
            &mut out,
        );
        // NS with zero-length option MUST be discarded per RFC 4861 §7.1.1
        let mut ns_zero_opt = ns;
        ns_zero_opt[25] = 0;
        ns_zero_opt[2..4].copy_from_slice(&[0, 0]);
        let ck_z =
            LivedNet::ipv6_upper_layer_checksum(&peer_v6, &sol_mc, IP_PROTO_ICMPV6, &ns_zero_opt);
        ns_zero_opt[2..4].copy_from_slice(&ck_z.to_be_bytes());
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_v6, sol_mc, 255, &ns_zero_opt),
            1,
            &mut sh,
            &mut out,
        );
        // Oversized Echo exceeding MAX_FRAME (1514 B) MUST be dropped, never truncated
        let mut huge_echo = alloc::vec![0u8; 1500];
        huge_echo[0] = 128;
        let ck_h =
            LivedNet::ipv6_upper_layer_checksum(&peer_v6, &ll, IP_PROTO_ICMPV6, &huge_echo);
        huge_echo[2..4].copy_from_slice(&ck_h.to_be_bytes());
        net.handle_frame_with_shell(
            &build_v6_frame(PEER_MAC, peer_v6, ll, 64, &huge_echo),
            1,
            &mut sh,
            &mut out,
        );
        assert_eq!(out.len(), 0, "all malformed/hostile IPv6 inputs must be dropped");

        // Guard lockdown drops valid IPv6 traffic too!
        let mut lock_buf = [0u8; 256];
        let _ = sh.exec_line(b"guard lockdown", 1, 0, 0, &mut lock_buf);
        assert!(sh.guard_lockdown);
        net.handle_frame_with_shell(&frame_echo, 1, &mut sh, &mut out);
        assert_eq!(out.len(), 0, "guard lockdown must block IPv6 frames");
    }

    #[test]
    fn sliding_window_multi_segment_http_8slot_ooo_and_3dupack_fast_retransmit() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();
        sh.set_paged_mode(true);

        // 1. Seed a 12 KiB file in `/www/big.txt` (~9 TCP segments) and fetch over HTTP/1.1.
        let mut big_payload = alloc::vec![0u8; 12_288];
        for (i, b) in big_payload.iter_mut().enumerate() {
            *b = b'A' + ((i * 7 + 3) % 26) as u8;
        }
        sh.fs
            .seed_file(b"/www/big.txt", &big_payload, big_payload.len(), 1)
            .expect("seed 12 KiB VFS file");

        let client_isn = 0x4100_0000u32;
        let client_port = 51200u16;
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let (fsyn, flsyn) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&fsyn[..flsyn], 1, &mut sh, &mut out);
        let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let server_isn = sa.seq;

        let req = b"GET /fs/www/big.txt HTTP/1.1\r\nHost: cuttle\r\nConnection: close\r\n\r\n";
        let mut pkt = [0u8; 256];
        let n = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            client_isn.wrapping_add(1),
            server_isn.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            req,
            PEER_IP,
            GUEST_IP,
            &mut pkt,
        )
        .unwrap();
        let (freq, flreq) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &pkt[..n]);
        out.clear();
        net.handle_frame_with_shell(&freq[..flreq], 1, &mut sh, &mut out);

        // Initial flight MUST respect TCP_INIT_CWND = 4 * SMSS (4 data segments = 5520 bytes).
        assert_eq!(
            out.len(),
            4,
            "initial burst must be bounded by TCP_INIT_CWND = 4 * SMSS"
        );
        let mut assembled = alloc::vec::Vec::new();
        let mut rcv_next = server_isn.wrapping_add(1);
        // Simulate receiving first 3 segments, dropping segment #4 (`drop_seq`), then sending 3 dup ACKs!
        for seg_i in 0..3 {
            let f = out.get(seg_i).unwrap();
            let s = TcpImpl::parse_segment(&f[34..], GUEST_IP, PEER_IP).unwrap();
            assert_eq!(s.seq, rcv_next);
            assembled.extend_from_slice(s.payload);
            rcv_next = rcv_next.wrapping_add(s.payload.len() as u32);
        }
        let dropped_seg_seq = rcv_next;
        let c_seq = client_isn.wrapping_add(1 + req.len() as u32);

        // First cumulative ACK advances `snd_una` to `dropped_seg_seq`, growing `cwnd` and emitting next segments.
        let mut ack_buf = [0u8; 64];
        let na = TcpImpl::build_segment(
            client_port,
            HTTP_PORT,
            c_seq,
            dropped_seg_seq,
            tcp_flags::ACK,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut ack_buf,
        )
        .unwrap();
        let (fack, flack) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ack_buf[..na]);
        let mut later_segs: alloc::vec::Vec<(u32, alloc::vec::Vec<u8>, bool)> =
            alloc::vec::Vec::new();
        out.clear();
        net.handle_frame_with_shell(&fack[..flack], 1, &mut sh, &mut out);
        assert!(
            net.max_observed_cwnd() > TCP_INIT_CWND,
            "Slow Start must grow cwnd above TCP_INIT_CWND upon cumulative ACK"
        );
        for i in 0..out.len() {
            let s = TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            later_segs.push((
                s.seq,
                alloc::vec::Vec::from(s.payload),
                (s.flags & tcp_flags::FIN) != 0,
            ));
        }

        // Now send 3 duplicate ACKs for `dropped_seg_seq`: the 3rd dup ACK MUST trigger Fast Retransmit!
        for dup in 1..=3 {
            out.clear();
            net.handle_frame_with_shell(&fack[..flack], 1, &mut sh, &mut out);
            if dup < 3 {
                assert_eq!(net.fast_retransmits, 0);
            } else {
                assert_eq!(net.fast_retransmits, 1, "3rd dup ACK must trigger Fast Retransmit");
                assert_eq!(net.rto_retransmits, 0, "Fast Retransmit must not wait for RTO");
                assert!(out.len() >= 1);
                let retx =
                    TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
                assert_eq!(retx.seq, dropped_seg_seq);
                assembled.extend_from_slice(retx.payload);
                rcv_next = rcv_next.wrapping_add(retx.payload.len() as u32);
            }
        }

        // Coalesce any segments already received above `dropped_seg_seq` and ACK until FIN!
        let mut saw_fin = false;
        for _round in 0..8 {
            later_segs.sort_by_key(|e| e.0);
            for (sq, data, fin) in later_segs.iter() {
                if *sq == rcv_next {
                    assembled.extend_from_slice(data);
                    rcv_next = rcv_next.wrapping_add(data.len() as u32);
                    if *fin {
                        rcv_next = rcv_next.wrapping_add(1);
                        saw_fin = true;
                    }
                }
            }
            let na2 = TcpImpl::build_segment(
                client_port,
                HTTP_PORT,
                c_seq,
                rcv_next,
                tcp_flags::ACK,
                65535,
                b"",
                PEER_IP,
                GUEST_IP,
                &mut ack_buf,
            )
            .unwrap();
            let (fa2, fla2) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ack_buf[..na2]);
            out.clear();
            net.handle_frame_with_shell(&fa2[..fla2], 1, &mut sh, &mut out);
            for i in 0..out.len() {
                let s =
                    TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
                later_segs.push((
                    s.seq,
                    alloc::vec::Vec::from(s.payload),
                    (s.flags & tcp_flags::FIN) != 0,
                ));
            }
            if saw_fin && out.len() == 0 {
                break;
            }
        }
        let hdr_end = find_double_crlf(&assembled).expect("HTTP response headers") + 4;
        assert!(core::str::from_utf8(&assembled[..hdr_end])
            .unwrap()
            .starts_with("HTTP/1.1 200 OK"));
        assert_eq!(&assembled[hdr_end..], big_payload.as_slice());

        // 2. 8-slot Out-of-Order TCP segment reassembly: deliver 8 segments in reverse order (8..=1)!
        let c2_isn = 0x5200_0000u32;
        let c2_port = 51201u16;
        let n = TcpImpl::build_segment(
            c2_port,
            HTTP_PORT,
            c2_isn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let (fs2, fls2) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        out.clear();
        net.handle_frame_with_shell(&fs2[..fls2], 1, &mut sh, &mut out);
        let sa2_seq =
            TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap().seq;
        // Complete handshake first.
        let n = TcpImpl::build_segment(
            c2_port,
            HTTP_PORT,
            c2_isn.wrapping_add(1),
            sa2_seq.wrapping_add(1),
            tcp_flags::ACK,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut ack_buf,
        )
        .unwrap();
        let (fa_hs, fla_hs) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ack_buf[..n]);
        out.clear();
        net.handle_frame_with_shell(&fa_hs[..fla_hs], 1, &mut sh, &mut out);

        // Split a request across 8 segments (segments 1..=7 sit in the 8 OOO slots while segment 0 arrives last).
        let padded_req = alloc::format!(
            "GET /uname HTTP/1.1\r\nHost: cuttle\r\nX-Pad: {}\r\n\r\n",
            "P".repeat(160)
        );
        let req_bytes = padded_req.as_bytes();
        let chunk_sz = req_bytes.len().div_ceil(8);
        let chunks: alloc::vec::Vec<&[u8]> = req_bytes.chunks(chunk_sz).collect();
        assert_eq!(chunks.len(), 8);
        let before_ooo = net.ooo_reassembled;
        for idx_rev in (0..8).rev() {
            let mut offset = 0usize;
            for c in chunks.iter().take(idx_rev) {
                offset += c.len();
            }
            let seg_seq = c2_isn.wrapping_add(1 + offset as u32);
            let mut seg_buf = [0u8; 256];
            let ns = TcpImpl::build_segment(
                c2_port,
                HTTP_PORT,
                seg_seq,
                sa2_seq.wrapping_add(1),
                tcp_flags::ACK | tcp_flags::PSH,
                65535,
                chunks[idx_rev],
                PEER_IP,
                GUEST_IP,
                &mut seg_buf,
            )
            .unwrap();
            let (fseg, flseg) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &seg_buf[..ns]);
            out.clear();
            net.handle_frame_with_shell(&fseg[..flseg], 1, &mut sh, &mut out);
        }
        assert!(
            net.ooo_reassembled >= before_ooo + 7,
            "all 7 future OOO segments must coalesce when segment 0 fills the gap (got {})",
            net.ooo_reassembled - before_ooo
        );
        assert!(out.len() >= 1);
        let ooo_resp =
            TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let ooo_str = core::str::from_utf8(ooo_resp.payload).unwrap();
        assert!(ooo_str.starts_with("HTTP/1.1 200 OK") && ooo_str.contains("Cuttle-TE"));
    }
}
