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
/// Maximum Ethernet payload + header we emit (untagged, no FCS).
pub const MAX_FRAME: usize = 1514;
/// Max replies produced from one inbound frame.
pub const MAX_REPLIES: usize = 3;
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
const TCP_SEGMENT_PAYLOAD: usize = 1380;
/// Deterministic 256-bit HMAC-SHA256 fixture key used only by in-memory unit
/// tests (`LivedNet::new`). Limited to `#[cfg(test)]` so production and kernel
/// code can never fall back to a public constant.
#[cfg(test)]
pub const DEFAULT_NET_AUTH_KEY: [u8; 32] = *b"Cuttle-Enterprise-NetAuth-Key001";

/// Outgoing Ethernet frames produced by [`LivedNet::handle_frame`].
pub struct ReplySet {
    frames: [[u8; MAX_FRAME]; MAX_REPLIES],
    lens: [usize; MAX_REPLIES],
    count: u8,
}

impl ReplySet {
    /// Empty set.
    pub const fn new() -> Self {
        Self {
            frames: [[0u8; MAX_FRAME]; MAX_REPLIES],
            lens: [0; MAX_REPLIES],
            count: 0,
        }
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
            Some(&self.frames[i][..self.lens[i]])
        } else {
            None
        }
    }

    fn push(&mut self, frame: &[u8]) -> bool {
        if self.count as usize >= MAX_REPLIES || frame.len() > MAX_FRAME || frame.is_empty() {
            return false;
        }
        let i = self.count as usize;
        self.frames[i][..frame.len()].copy_from_slice(frame);
        self.lens[i] = frame.len();
        self.count += 1;
        true
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
    /// Highest accepted monotonic sequence number for anti-replay protection.
    pub last_auth_seq: u64,
    /// TLS connections started on port 443 since boot.
    pub tls_sessions_started: u64,
    /// Total TCP retransmission / half-open reclamation events triggered by RTO timers.
    pub rto_retransmits: u64,
    tcbs: [Tcb; TCP_MAX_SLOTS],
    slot_last_tick: [u32; TCP_MAX_SLOTS],
    slot_rto_ticks: [u32; TCP_MAX_SLOTS],
    slot_remote_mac: [[u8; 6]; TCP_MAX_SLOTS],
    http_input_closed: [bool; TCP_MAX_SLOTS],
    ticks: u32,
    timer_hz: u32,
    ip_ident: u16,
    http_bufs: [alloc::vec::Vec<u8>; TCP_MAX_SLOTS],
    http_tx: [alloc::vec::Vec<u8>; TCP_MAX_SLOTS],
    slot_tls_buffered: [usize; TCP_MAX_SLOTS],
    peak_tls_pending_tx: usize,
    tls_config: Option<Arc<ServerConfig>>,
    tls: [Option<Box<TlsSession>>; TCP_MAX_SLOTS],
}

impl LivedNet {
    /// Zero-initialized BSS constructor suitable for `static spin::Mutex<LivedNet>`.
    pub const fn empty() -> Self {
        Self {
            mac: [0u8; 6],
            ip: GUEST_IP,
            auth_key: [0u8; 32],
            auth_enabled: false,
            last_auth_seq: 0,
            tls_sessions_started: 0,
            rto_retransmits: 0,
            tcbs: [Tcb::EMPTY; TCP_MAX_SLOTS],
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            slot_rto_ticks: [0u32; TCP_MAX_SLOTS],
            slot_remote_mac: [[0u8; 6]; TCP_MAX_SLOTS],
            http_input_closed: [false; TCP_MAX_SLOTS],
            ticks: 1,
            timer_hz: DEFAULT_TIMER_HZ,
            ip_ident: 1,
            http_bufs: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            http_tx: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            slot_tls_buffered: [0usize; TCP_MAX_SLOTS],
            peak_tls_pending_tx: 0,
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
            tls_sessions_started: 0,
            rto_retransmits: 0,
            tcbs: [Tcb::listen(GUEST_IP, HTTP_PORT, 65535); TCP_MAX_SLOTS],
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            slot_rto_ticks: [0u32; TCP_MAX_SLOTS],
            slot_remote_mac: [[0u8; 6]; TCP_MAX_SLOTS],
            http_input_closed: [false; TCP_MAX_SLOTS],
            ticks: 1,
            timer_hz: DEFAULT_TIMER_HZ,
            ip_ident: 1,
            http_bufs: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            http_tx: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            slot_tls_buffered: [0usize; TCP_MAX_SLOTS],
            peak_tls_pending_tx: 0,
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
            tls_sessions_started: 0,
            rto_retransmits: 0,
            tcbs: [Tcb::listen(GUEST_IP, HTTP_PORT, 65535); TCP_MAX_SLOTS],
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            slot_rto_ticks: [0u32; TCP_MAX_SLOTS],
            slot_remote_mac: [[0u8; 6]; TCP_MAX_SLOTS],
            http_input_closed: [false; TCP_MAX_SLOTS],
            ticks: 1,
            timer_hz: DEFAULT_TIMER_HZ,
            ip_ident: 1,
            http_bufs: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            http_tx: [const { alloc::vec::Vec::new() }; TCP_MAX_SLOTS],
            slot_tls_buffered: [0usize; TCP_MAX_SLOTS],
            peak_tls_pending_tx: 0,
            tls_config: None,
            tls: [const { None }; TCP_MAX_SLOTS],
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

    /// Return total unread input and queued output bytes buffered across all
    /// [`TCP_MAX_SLOTS`] HTTP and HTTPS connection slots.
    pub fn total_buffered_bytes(&self) -> usize {
        let mut total = 0usize;
        let mut i = 0usize;
        while i < TCP_MAX_SLOTS {
            total = total
                .saturating_add(self.http_bufs[i].len())
                .saturating_add(self.http_tx[i].len())
                .saturating_add(self.slot_tls_buffered[i]);
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
            total = total
                .saturating_add(self.http_bufs[i].capacity())
                .saturating_add(self.http_tx[i].capacity())
                .saturating_add(self.slot_tls_buffered[i]);
            i += 1;
        }
        total
    }

    fn release_slot_buffers(&mut self, idx: usize) {
        self.http_input_closed[idx] = false;
        self.http_bufs[idx].clear();
        self.http_bufs[idx].shrink_to_fit();
        self.http_tx[idx].clear();
        self.http_tx[idx].shrink_to_fit();
        self.slot_tls_buffered[idx] = 0;
        self.tls[idx] = None;
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

    /// Advance per-slot TCP RTO timers by one calibrated Local APIC timer interrupt
    /// and emit a `RST | ACK` segment into `out` whenever an idle `Established` or
    /// `CloseWait` connection slot is reclaimed.
    pub fn tick_tcp_rto_with_replies(&mut self, out: &mut ReplySet) -> usize {
        self.ticks = self.ticks.wrapping_add(1);
        let rto_ticks = self.rto_retransmit_ticks();
        let reclaim_ticks = self.half_open_reclaim_ticks();
        let idle_ticks = self.idle_timeout_ticks();
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
                        self.slot_rto_ticks[i] = self.ticks;
                    }
                }
            } else if (st == TcpState::Established || st == TcpState::CloseWait)
                && (self.tcbs[i].local_port == HTTPS_PORT
                    || self.tls[i].is_some()
                    || !self.http_bufs[i].is_empty()
                    || !self.http_tx[i].is_empty())
                && self.ticks.wrapping_sub(self.slot_last_tick[i]) >= idle_ticks
            {
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
        let mut msg = [0u8; 320];
        let mut pos = 0usize;
        let s_len = seq_ascii.len().min(32);
        msg[..s_len].copy_from_slice(&seq_ascii[..s_len]);
        pos += s_len;
        msg[pos] = b':';
        pos += 1;
        let c_len = cmd.len().min(msg.len() - pos);
        msg[pos..pos + c_len].copy_from_slice(&cmd[..c_len]);
        pos += c_len;
        hmac_sha256(key, &msg[..pos], out);
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
        let mut msg = [0u8; 384];
        let mut pos = 0usize;
        pos += copy_msg(b"cuttle-triad-prep-v1:", &mut msg[pos..]);
        pos += copy_msg(&seq_ascii[..seq_ascii.len().min(24)], &mut msg[pos..]);
        pos += copy_msg(b":", &mut msg[pos..]);
        pos += copy_msg(&node_ascii[..node_ascii.len().min(8)], &mut msg[pos..]);
        pos += copy_msg(b":", &mut msg[pos..]);
        pos += copy_msg(sql, &mut msg[pos..]);
        hmac_sha256(key, &msg[..pos], out);
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
        let mut msg = [0u8; 160];
        let mut pos = 0usize;
        pos += copy_msg(b"cuttle-triad-ack-v1:", &mut msg[pos..]);
        pos += copy_msg(&seq_ascii[..seq_ascii.len().min(24)], &mut msg[pos..]);
        pos += copy_msg(b":", &mut msg[pos..]);
        pos += copy_msg(&peer_ascii[..peer_ascii.len().min(8)], &mut msg[pos..]);
        pos += copy_msg(b":", &mut msg[pos..]);
        pos += copy_msg(&hash_hex16[..hash_hex16.len().min(16)], &mut msg[pos..]);
        hmac_sha256(key, &msg[..pos], out);
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
        let dst_ip = [ip[16], ip[17], ip[18], ip[19]];
        if dst_ip != self.ip {
            return;
        }
        let src_ip = [ip[12], ip[13], ip[14], ip[15]];
        let proto = ip[9];
        let payload = &ip[ihl..total];
        let sender_mac: [u8; 6] = match frame[6..12].try_into() {
            Ok(m) => m,
            Err(_) => return,
        };

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
        let arp = &frame[14..42];
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
        reply[38..42].copy_from_slice(&arp[18..22]);
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
        if (dst_port != UDP_STATUS_PORT && dst_port != TRIAD_REPL_PORT) || src_port < 1024 {
            return;
        }
        let payload_len = ulen.saturating_sub(8).min(udp.len().saturating_sub(8));
        let payload = &udp[8..8 + payload_len];
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
        if trimmed == b"TRIAD_STATUS" {
            return sh.cmd_triad(b"status", body);
        }
        if !self.auth_enabled {
            sh.record_net_audit(AuditVerdict::Denied, b"net:triad:unprovisioned");
            return copy_msg(
                b"error: EACCES (device key not provisioned; TRIAD disabled)\n",
                body,
            );
        }

        if trimmed.len() > 14 && trimmed.starts_with(b"TRIAD_PREPARE ") {
            let rest = &trimmed[14..];
            let (seq_tok, after_seq) = split_ws(rest);
            let (node_tok, after_node) = split_ws(after_seq);
            let (hmac_tok, sql_raw) = split_ws(after_node);
            let sql = trim_ws(sql_raw);
            let (Some(seq), Some(leader_id)) = (parse_u64_dec(seq_tok), parse_u64_dec(node_tok))
            else {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:prep-syntax");
                return copy_msg(
                    b"usage: TRIAD_PREPARE <seq> <node_id> <hmac_hex64> <sql>\n",
                    body,
                );
            };
            if leader_id > 2 || hmac_tok.len() != 64 || sql.is_empty() {
                sh.record_net_audit(AuditVerdict::Error, b"net:triad:prep-syntax");
                return copy_msg(
                    b"usage: TRIAD_PREPARE <seq> <node_id> <hmac_hex64> <sql>\n",
                    body,
                );
            }
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
            Self::compute_triad_prepare_tag(
                &self.auth_key,
                seq_tok,
                node_tok,
                sql,
                &mut expected_mac,
            );
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

    fn select_tcp_slot(
        &mut self,
        src_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        flags: u8,
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
        if (flags & tcp_flags::SYN) == 0 || (flags & tcp_flags::ACK) != 0 {
            return None;
        }
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
            // Red Team SYN-flood mitigation: prefer evicting half-open (`SynReceived`)
            // or closing (`CloseWait`, `LastAck`) slots before any `Established` connection.
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
        let idx = free_slot.or(half_open_slot).unwrap_or(lru_slot);
        self.tcbs[idx] = Tcb::listen(self.ip, dst_port, 65535);
        self.slot_rto_ticks[idx] = self.ticks;
        self.slot_remote_mac[idx] = [0u8; 6];
        self.release_slot_buffers(idx);
        Some(idx)
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
        let idx = match self.select_tcp_slot(src_ip, seg.src_port, seg.dst_port, seg.flags) {
            Some(i) => i,
            None => return,
        };
        let was_close_wait = matches!(
            self.tcbs[idx].state,
            TcpState::CloseWait | TcpState::FinWait1 | TcpState::FinWait2 | TcpState::LastAck
        );
        let inbound_payload = seg.payload;
        let (next, hint) = match process_segment(self.tcbs[idx], &seg, self.ticks) {
            Ok(t) => t,
            Err(_) => return,
        };
        self.slot_last_tick[idx] = self.ticks;
        self.slot_rto_ticks[idx] = self.ticks;
        self.slot_remote_mac[idx] = dst_mac;
        self.tcbs[idx] = next;
        if self.tcbs[idx].remote_ip == [0, 0, 0, 0] {
            self.tcbs[idx].remote_ip = src_ip;
        }
        let effective_payload = if was_close_wait || self.http_input_closed[idx] {
            &[][..]
        } else {
            inbound_payload
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
        if !effective_payload.is_empty() && self.tcbs[idx].state != TcpState::Listen {
            let next_slot_len = self.http_bufs[idx]
                .len()
                .saturating_add(effective_payload.len());
            let next_total_len = self
                .total_buffered_bytes()
                .saturating_add(effective_payload.len());
            if next_slot_len > MAX_HTTP_BUFFER_BYTES || next_total_len > MAX_TOTAL_BUFFERED_BYTES {
                self.http_bufs[idx].clear();
                self.http_bufs[idx].shrink_to_fit();
                self.http_input_closed[idx] = true;
                overflow_413 = true;
            } else {
                self.http_bufs[idx].extend_from_slice(effective_payload);
            }
        }

        let mut framing_exhausted = false;
        if overflow_413 {
            self.http_input_closed[idx] = true;
            self.http_bufs[idx].clear();
            self.http_bufs[idx].shrink_to_fit();
            let mut single = [0u8; TCP_SEGMENT_PAYLOAD];
            let n = build_http_413_response(&mut single);
            if n > 0 {
                self.http_tx[idx].extend_from_slice(&single[..n]);
            }
            framing_exhausted = true;
        } else if !self.http_input_closed[idx] {
            let mut responses = 0usize;
            while responses < 8 && self.http_tx[idx].len() < HTTPS_TX_HIGH_WATER {
                let mut single = [0u8; TCP_SEGMENT_PAYLOAD];
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
                        self.handle_http_request(&req, boots, shell.as_deref_mut(), &mut single)
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
            let n = self.http_tx[idx].len().min(TCP_SEGMENT_PAYLOAD);
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
        if self.tls[idx].is_none() && open && !inbound.is_empty() {
            if let Some(config) = self.tls_config.clone() {
                if let Ok(session) = TlsSession::new(config) {
                    self.tls[idx] = Some(Box::new(session));
                    self.tls_sessions_started = self.tls_sessions_started.wrapping_add(1);
                }
            }
        }

        if let Some(mut session) = self.tls[idx].take() {
            let mut overflow_413 = false;
            if !inbound.is_empty() && !self.http_input_closed[idx] {
                let other_slots_buffered =
                    self.total_buffered_bytes().saturating_sub(self.slot_tls_buffered[idx]);
                let projected_slot = session
                    .plaintext()
                    .len()
                    .saturating_add(session.pending_tx().len())
                    .saturating_add(inbound.len());
                if other_slots_buffered.saturating_add(projected_slot) > MAX_TOTAL_BUFFERED_BYTES {
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
                        overflow_413 = true;
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
            if overflow_413 {
                self.http_input_closed[idx] = true;
                session.plaintext().clear();
                session.plaintext().shrink_to_fit();
                let mut response = [0u8; TCP_SEGMENT_PAYLOAD];
                let n = build_http_413_response(&mut response);
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
                let mut response = [0u8; TCP_SEGMENT_PAYLOAD];
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
                    HttpFrameOutcome::Complete(request) => {
                        close_after = http_wants_close(&request);
                        self.handle_http_request(
                            &request,
                            boots,
                            shell.as_deref_mut(),
                            &mut response,
                        )
                    }
                };
                if n > 0 && session.send(&response[..n]).is_err() {
                    break;
                }
                responses += 1;
                // `Connection: close`, malformed, or oversized request: end
                // the TLS session after this response and discard trailing input.
                if close_after {
                    self.http_input_closed[idx] = true;
                    session.plaintext().clear();
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
                session.plaintext().shrink_to_fit();
            }
            if session.pending_tx().len() > self.peak_tls_pending_tx {
                self.peak_tls_pending_tx = session.pending_tx().len();
            }
            self.slot_tls_buffered[idx] = session
                .plaintext()
                .len()
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
        if self.tcbs[idx].state == TcpState::CloseWait
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
            let n = match &self.tls[idx] {
                Some(session) => {
                    let n = session.pending_tx().len().min(TCP_SEGMENT_PAYLOAD);
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
            if let Some(session) = self.tls[idx].as_mut() {
                session.consume_tx(n);
                self.slot_tls_buffered[idx] = session
                    .plaintext()
                    .len()
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
            if sh.is_login_rate_limited() {
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
            if user.is_empty() || hmac_tok.len() != 64 {
                sh.record_net_audit(AuditVerdict::Error, b"net:http:login-syntax");
                return HttpImpl::build_response(
                    400,
                    b"text/plain",
                    b"usage: <seq> <hmac_hex64> <user>\n",
                    out,
                )
                .unwrap_or(0);
            }
            let watermark = self.last_auth_seq.max(sh.auth_seq);
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
                sh.record_login_failure();
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
            Self::compute_auth_tag(&self.auth_key, seq_tok, user, &mut expected_mac);
            let mut diff = 0u8;
            let mut i = 0usize;
            while i < 32 {
                diff |= provided_mac[i] ^ expected_mac[i];
                i += 1;
            }
            if diff != 0 {
                sh.record_login_failure();
                sh.record_net_audit(AuditVerdict::Denied, b"net:http:login-hmac");
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: hmac verification failed\n",
                    out,
                )
                .unwrap_or(0);
            }
            self.last_auth_seq = seq;
            sh.auth_seq = seq;
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
            bpos += copy_msg(&user[..user.len().min(16)], &mut body[bpos..]);
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
                    return match sh.dispatch_mailbox_op(
                        IpcOp::SqlQuery,
                        true,
                        false,
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
                return match sh.dispatch_mailbox_op(
                    IpcOp::SqlQuery,
                    true,
                    false,
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
                let (op, authed) = if is_ro {
                    (IpcOp::SqlQuery, false)
                } else {
                    let ok = extract_session_token(view.headers_raw)
                        .and_then(|tok| sh.validate_session(tok))
                        .is_some();
                    (IpcOp::SqlMutate, ok)
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
                let mut fbuf = [0u8; 384];
                return match sh.dispatch_mailbox_op(
                    IpcOp::VfsRead,
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
                        HttpImpl::build_response(status, b"text/plain", &fbuf[..flen], out)
                            .unwrap_or(0)
                    }
                    Err(e) => build_service_error_response(e, out),
                };
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
    let total = match HttpImpl::parse_request(&buf[..body_start]) {
        Ok(view) => {
            let mut content_length: Option<u64> = None;
            let mut cl_count = 0usize;
            for line in view.headers_raw.split(|&b| b == b'\n') {
                let line = line.strip_suffix(b"\r").unwrap_or(line);
                if line.is_empty() {
                    continue;
                }
                let Some(colon) = line.iter().position(|&b| b == b':') else {
                    buf.clear();
                    return HttpFrameOutcome::BadRequest;
                };
                let name = trim_ws(&line[..colon]);
                let val = trim_ws(&line[colon + 1..]);
                if name.eq_ignore_ascii_case(b"Transfer-Encoding") {
                    buf.clear();
                    return HttpFrameOutcome::NotImplemented;
                }
                if name.eq_ignore_ascii_case(b"Content-Length") {
                    cl_count += 1;
                    let Some(parsed) = parse_u64_dec(val) else {
                        buf.clear();
                        return HttpFrameOutcome::BadRequest;
                    };
                    if cl_count > 1 {
                        buf.clear();
                        return HttpFrameOutcome::BadRequest;
                    }
                    content_length = Some(parsed);
                }
            }
            match (content_length, view.method) {
                (Some(cl), _) => {
                    let Some(total) = body_start.checked_add(cl as usize) else {
                        buf.clear();
                        return HttpFrameOutcome::PayloadTooLarge;
                    };
                    if total > MAX_HTTP_REQUEST_BYTES {
                        buf.clear();
                        return HttpFrameOutcome::PayloadTooLarge;
                    }
                    total
                }
                (None, HttpMethod::Post | HttpMethod::Put) => {
                    buf.clear();
                    return HttpFrameOutcome::LengthRequired;
                }
                (None, _) => body_start,
            }
        }
        Err(_) => {
            buf.clear();
            return HttpFrameOutcome::BadRequest;
        }
    };
    if buf.len() >= total {
        HttpFrameOutcome::Complete(buf.drain(..total).collect())
    } else if buf.len() > MAX_HTTP_REQUEST_BYTES {
        buf.clear();
        HttpFrameOutcome::PayloadTooLarge
    } else {
        HttpFrameOutcome::Incomplete
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
        if tok.len() == 32 {
            return Some(tok);
        }
    }
    if let Some(cookie) = HttpImpl::find_header(headers_raw, b"Cookie") {
        let mut i = 0usize;
        while i + 4 <= cookie.len() {
            if &cookie[i..i + 4] == b"sid=" {
                let start = i + 4;
                if start + 32 <= cookie.len() {
                    return Some(&cookie[start..start + 32]);
                }
            }
            i += 1;
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

fn parse_u64_dec(s: &[u8]) -> Option<u64> {
    if s.is_empty() {
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
        LivedNet::compute_auth_tag(&DEFAULT_NET_AUTH_KEY, b"1", b"admin", &mut mac);
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
        LivedNet::compute_auth_tag(&DEFAULT_NET_AUTH_KEY, b"100", b"admin", &mut mac_ok);
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
        let peer_ip = [10, 0, 2, 2];
        let mut net = LivedNet::new(mac);

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

        // Open 10 concurrent TCP connections on port 80 and buffer ~56 KiB of incomplete pipelined
        // HTTP headers on the first 9 slots (`9 * 56 KiB = 504 KiB <= MAX_TOTAL_BUFFERED_BYTES`).
        let mut cseqs = [0u32; 10];
        let mut sseqs = [0u32; 10];
        for slot in 0..10usize {
            let sport = 44000 + slot as u16;
            let mut out = ReplySet::new();
            let syn = build_tcp_frame(sport, 80, 20_000 + (slot as u32) * 100_000, 0, tcp_flags::SYN, b"");
            net.handle_frame(&syn, 1, &mut out);
            let synack =
                TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
            cseqs[slot] = 20_001 + (slot as u32) * 100_000;
            sseqs[slot] = synack.seq.wrapping_add(1);
            out = ReplySet::new();
            let ack = build_tcp_frame(sport, 80, cseqs[slot], sseqs[slot], tcp_flags::ACK, b"");
            net.handle_frame(&ack, 1, &mut out);
        }

        // Each 1,024-byte chunk is a valid complete `GET /healthz` request EXCEPT we keep a
        // trailing incomplete request at the head so `frame_next_http_request` stops at Incomplete.
        // Wait: if the first request is incomplete (>8 KiB would 413), how can a slot hold 56 KiB?
        // In `handle_tcp`, `while responses < 8` drains at most 8 requests per inbound segment!
        // So if we send 40 tiny 40-byte `GET /healthz` requests per segment across multiple segments,
        // `http_bufs[slot]` accumulates the remaining unread requests up to 56 KiB!
        let single_req = b"GET /healthz HTTP/1.1\r\nHost: a\r\n\r\n"; // 34 bytes
        let mut batch = alloc::vec::Vec::new();
        while batch.len() + single_req.len() <= 1360 {
            batch.extend_from_slice(single_req);
        }
        // Each `batch` has 40 requests (1,360 bytes), and each segment drains 8 requests (272 bytes),
        // leaving +1,088 bytes in `http_bufs[slot]` per segment!
        // 50 segments on each of slots 0..9 accumulates ~54,400 bytes per slot (~489,600 bytes total).
        for slot in 0..9usize {
            let sport = 44000 + slot as u16;
            for _ in 0..50 {
                let mut out = ReplySet::new();
                let seg = build_tcp_frame(
                    sport,
                    80,
                    cseqs[slot],
                    sseqs[slot],
                    tcp_flags::ACK | tcp_flags::PSH,
                    &batch,
                );
                net.handle_frame(&seg, 1, &mut out);
                cseqs[slot] = cseqs[slot].wrapping_add(batch.len() as u32);
                for i in 0..out.len() {
                    let s = TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, peer_ip)
                        .unwrap();
                    sseqs[slot] = sseqs[slot].wrapping_add(s.payload.len() as u32);
                }
            }
        }
        assert!(
            net.total_buffered_bytes() <= MAX_TOTAL_BUFFERED_BYTES,
            "buffered bytes ({}) must stay within MAX_TOTAL_BUFFERED_BYTES ({})",
            net.total_buffered_bytes(),
            MAX_TOTAL_BUFFERED_BYTES
        );
        assert!(net.total_buffered_bytes() > 450 * 1024);

        // Now push slot 9 over the global `MAX_TOTAL_BUFFERED_BYTES` (512 KiB) cap even though
        // slot 9's per-slot buffer is well below `MAX_HTTP_BUFFER_BYTES` (64 KiB):
        let sport9 = 44009u16;
        let mut hit_global_413 = false;
        for _ in 0..40 {
            let mut out = ReplySet::new();
            let seg = build_tcp_frame(
                sport9,
                80,
                cseqs[9],
                sseqs[9],
                tcp_flags::ACK | tcp_flags::PSH,
                &batch,
            );
            net.handle_frame(&seg, 1, &mut out);
            cseqs[9] = cseqs[9].wrapping_add(batch.len() as u32);
            for i in 0..out.len() {
                let s =
                    TcpImpl::parse_segment(&out.get(i).unwrap()[34..], GUEST_IP, peer_ip).unwrap();
                sseqs[9] = sseqs[9].wrapping_add(s.payload.len() as u32);
                if core::str::from_utf8(s.payload)
                    .unwrap_or("")
                    .contains("HTTP/1.1 413 ")
                {
                    hit_global_413 = true;
                }
            }
            if hit_global_413 {
                break;
            }
        }
        assert!(
            hit_global_413,
            "exceeding MAX_TOTAL_BUFFERED_BYTES across slots must trigger 413 Content Too Large"
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
}
