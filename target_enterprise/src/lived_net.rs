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

use proteus_contracts::{
    icmp_type, tcp_flags, Aead, AuditVerdict, HandshakeKeys, Http, HttpMethod, Icmp,
    Ipv4PacketView, PacketFilter, Tcp, Verdict, IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
};

use crate::firewall::FirewallImpl;
use crate::http::HttpImpl;
use crate::icmp::IcmpImpl;
use crate::net::ipv4_header_checksum;
use crate::tcp::{close, process_segment, send_payload, Tcb, TcpImpl, TcpState};
use crate::tls::{
    build_server_hello, decode_record_header, derive_handshake_keys, encode_record_header,
    hkdf_expand_label, hmac_sha256, parse_client_hello, parse_server_hello, CONTENT_TYPE_HANDSHAKE,
    LEGACY_VERSION, MAX_SERVER_HELLO_LEN, RECORD_HEADER_LEN,
};

/// Guest IPv4 the service claims (QEMU slirp default guest).
pub const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// UDP status port (existing hostfwd).
pub const UDP_STATUS_PORT: u16 = 8080;
/// HTTP status port.
pub const HTTP_PORT: u16 = 80;
/// HTTPS / TLS 1.3 port.
pub const HTTPS_PORT: u16 = 443;
/// Maximum number of concurrent TCP connections tracked in [`LivedNet`].
pub const TCP_MAX_SLOTS: usize = 4;
/// TLS 1.3 content-type byte for encrypted `ApplicationData` records (RFC 8446 §5.1).
pub const TLS_CONTENT_APPLICATION_DATA: u8 = 23;
/// Domain-separation root seed for per-connection TLS 1.3 `server_random` derivation on port 443.
pub const TLS_SERVER_RANDOM: [u8; 32] = [0x53u8; 32];
/// Domain-separation root seed for per-connection ephemeral X25519 `server_pubkey` derivation in `ServerHello`.
pub const TLS_SERVER_PUBKEY: [u8; 32] = [0xA5u8; 32];
/// Ethernet II header length.
pub const ETH_HEADER_LEN: usize = 14;
/// IPv4 header length (no options).
pub const IPV4_HEADER_LEN: usize = 20;
/// Maximum Ethernet payload + header we emit (untagged, no FCS).
pub const MAX_FRAME: usize = 1514;
/// Max replies produced from one inbound frame.
pub const MAX_REPLIES: usize = 3;
/// Per-slot scratch buffer for an in-progress HTTP or TLS 1.3 request.
const SLOT_BUF: usize = 1024;
/// Deterministic 256-bit HMAC-SHA256 fixture key used only by in-memory unit
/// tests (`LivedNet::new`). Limited to `#[cfg(test)]` so production and kernel
/// code can never fall back to a public constant.
#[cfg(test)]
pub const DEFAULT_NET_AUTH_KEY: [u8; 32] = *b"Proteus-Enterprise-NetAuth-Key01";

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
/// authenticated UDP control plane (`8080`), HTTP/1.1 (`80`), and
/// TLS 1.3 (`443`) across a 4-slot concurrent TCP table.
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
    /// Monotonic counter of TLS 1.3 handshakes used to derive fresh per-connection keyshares.
    pub tls_handshake_seq: u64,
    tcbs: [Tcb; TCP_MAX_SLOTS],
    slot_last_tick: [u32; TCP_MAX_SLOTS],
    ticks: u32,
    ip_ident: u16,
    http_bufs: [[u8; SLOT_BUF]; TCP_MAX_SLOTS],
    http_lens: [usize; TCP_MAX_SLOTS],
    tls_keys: [[u8; 16]; TCP_MAX_SLOTS],
    tls_ready: [bool; TCP_MAX_SLOTS],
}

impl LivedNet {
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
            tls_handshake_seq: 0,
            tcbs: [Tcb::listen(GUEST_IP, HTTP_PORT, 65535); TCP_MAX_SLOTS],
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            ticks: 1,
            ip_ident: 1,
            http_bufs: [[0u8; SLOT_BUF]; TCP_MAX_SLOTS],
            http_lens: [0usize; TCP_MAX_SLOTS],
            tls_keys: [[0u8; 16]; TCP_MAX_SLOTS],
            tls_ready: [false; TCP_MAX_SLOTS],
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
            tls_handshake_seq: 0,
            tcbs: [Tcb::listen(GUEST_IP, HTTP_PORT, 65535); TCP_MAX_SLOTS],
            slot_last_tick: [0u32; TCP_MAX_SLOTS],
            ticks: 1,
            ip_ident: 1,
            http_bufs: [[0u8; SLOT_BUF]; TCP_MAX_SLOTS],
            http_lens: [0usize; TCP_MAX_SLOTS],
            tls_keys: [[0u8; 16]; TCP_MAX_SLOTS],
            tls_ready: [false; TCP_MAX_SLOTS],
        }
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

    /// Derive the 32-byte ECDHE shared secret and 16-byte record AEAD key for a
    /// TLS 1.3 handshake (`ClientHello` + `ServerHello`) against [`LivedNet`] on port 443,
    /// extracting the ephemeral X25519 `server_pubkey` directly from `server_hello`.
    pub fn derive_tls13_record_key(
        client_pubkey: &[u8; 32],
        client_hello: &[u8],
        server_hello: &[u8],
        key_out: &mut [u8; 16],
    ) -> HandshakeKeys {
        let server_pub = match parse_server_hello(server_hello) {
            Ok(sh) => sh.server_pubkey,
            Err(_) => TLS_SERVER_PUBKEY,
        };
        let mut shared_secret = [0u8; 32];
        hmac_sha256(&server_pub, client_pubkey, &mut shared_secret);
        let mut hs = HandshakeKeys {
            handshake_secret: [0u8; 32],
            client_handshake_traffic_secret: [0u8; 32],
            server_handshake_traffic_secret: [0u8; 32],
        };
        derive_handshake_keys(&shared_secret, client_hello, server_hello, &mut hs);
        hkdf_expand_label(&hs.server_handshake_traffic_secret, b"key", b"", key_out);
        hs
    }

    /// Derive a unique per-device 256-bit `HMAC-SHA256` control-plane key from a fleet/factory
    /// root secret and the device's hardware MAC address (`HMAC-SHA256(root_secret, "proteus-net-auth-v1:" || mac)`).
    pub fn derive_node_key(root_secret: &[u8; 32], mac: [u8; 6]) -> [u8; 32] {
        const LABEL: &[u8] = b"proteus-net-auth-v1:";
        let mut msg = [0u8; 26];
        msg[..20].copy_from_slice(LABEL);
        msg[20..26].copy_from_slice(&mac);
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
        if dst_port != UDP_STATUS_PORT || src_port < 1024 {
            return;
        }
        let payload_len = ulen.saturating_sub(8).min(udp.len().saturating_sub(8));
        let payload = &udp[8..8 + payload_len];
        // slirp bounce guard (same as the original UDP service).
        if payload_len >= 8 && payload.starts_with(b"PROTEUS-") {
            return;
        }
        let _ = src_ip;
        let mut body = [0u8; 512];
        let blen = if payload.len() >= 4 && payload.starts_with(b"CMD ") {
            if let Some(sh) = shell {
                let cmd_line = &payload[4..];
                if crate::shell::OsShell::is_readonly_command(cmd_line) {
                    sh.exec_line(cmd_line, boots, 0, 0, &mut body)
                        .bytes_written()
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
        let mut udp_full = [0u8; 536];
        let udp_len = 8 + blen;
        udp_full[0..2].copy_from_slice(&UDP_STATUS_PORT.to_be_bytes());
        udp_full[2..4].copy_from_slice(&src_port.to_be_bytes());
        udp_full[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        udp_full[8..udp_len].copy_from_slice(&body[..blen]);
        let uc = crate::net::udp_checksum(self.ip, reply_ip, &udp_full[..udp_len]);
        udp_full[6..8].copy_from_slice(&uc.to_be_bytes());
        self.emit_ipv4(dst_mac, reply_ip, IP_PROTO_UDP, &udp_full[..udp_len], out);
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
        sh.exec_line(cmd, boots, 0, 0, body).bytes_written()
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
        let mut lru_slot = 0usize;
        let mut lru_tick = u32::MAX;
        let mut j = 0usize;
        while j < TCP_MAX_SLOTS {
            let st = self.tcbs[j].state;
            if st == TcpState::Closed || st == TcpState::Listen {
                free_slot = Some(j);
                break;
            }
            if self.slot_last_tick[j] < lru_tick {
                lru_tick = self.slot_last_tick[j];
                lru_slot = j;
            }
            j += 1;
        }
        let idx = free_slot.unwrap_or(lru_slot);
        self.tcbs[idx] = Tcb::listen(self.ip, dst_port, 65535);
        self.http_lens[idx] = 0;
        self.tls_ready[idx] = false;
        self.tls_keys[idx] = [0u8; 16];
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
        shell: Option<&mut crate::shell::OsShell>,
        out: &mut ReplySet,
    ) {
        let seg = match TcpImpl::parse_segment(tcp, src_ip, self.ip) {
            Ok(s) => s,
            Err(_) => return,
        };
        if seg.dst_port != HTTP_PORT && seg.dst_port != HTTPS_PORT {
            return;
        }
        let idx = match self.select_tcp_slot(src_ip, seg.src_port, seg.dst_port, seg.flags) {
            Some(i) => i,
            None => return,
        };
        self.slot_last_tick[idx] = self.ticks;
        let inbound_payload = seg.payload;
        let (next, hint) = match process_segment(self.tcbs[idx], &seg, self.ticks) {
            Ok(t) => t,
            Err(_) => return,
        };
        self.tcbs[idx] = next;
        if self.tcbs[idx].remote_ip == [0, 0, 0, 0] {
            self.tcbs[idx].remote_ip = src_ip;
        }

        if !inbound_payload.is_empty() && self.tcbs[idx].state != TcpState::Listen {
            let cur = self.http_lens[idx];
            let room = SLOT_BUF.saturating_sub(cur);
            let n = inbound_payload.len().min(room);
            self.http_bufs[idx][cur..cur + n].copy_from_slice(&inbound_payload[..n]);
            self.http_lens[idx] = cur + n;
        }

        let mut app_out = [0u8; 1380];
        let mut app_n = 0usize;
        if seg.dst_port == HTTP_PORT {
            let cur = self.http_lens[idx];
            if cur >= 18 && http_request_complete(&self.http_bufs[idx][..cur]) {
                let mut req_copy = [0u8; SLOT_BUF];
                req_copy[..cur].copy_from_slice(&self.http_bufs[idx][..cur]);
                self.http_lens[idx] = 0;
                app_n = self.handle_http_request(&req_copy[..cur], boots, shell, &mut app_out);
            }
        } else {
            app_n = self.process_tls13_slot(idx, boots, shell, &mut app_out);
        }

        let local_port = self.tcbs[idx].local_port;
        let remote_port = self.tcbs[idx].remote_port;
        if app_n > 0
            && (self.tcbs[idx].state == TcpState::Established
                || self.tcbs[idx].state == TcpState::CloseWait)
        {
            if let Ok((next, data_hint)) = send_payload(self.tcbs[idx], app_n as u32) {
                self.tcbs[idx] = next;
                if data_hint.present {
                    self.emit_tcp(
                        local_port,
                        remote_port,
                        dst_mac,
                        reply_ip,
                        data_hint.seq,
                        data_hint.ack,
                        data_hint.flags,
                        data_hint.window,
                        &app_out[..app_n],
                        out,
                    );
                }
            }
        } else if hint.present {
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

        if self.tcbs[idx].state == TcpState::CloseWait {
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
    }

    #[inline(never)]
    fn process_tls13_slot(
        &mut self,
        idx: usize,
        boots: u64,
        shell: Option<&mut crate::shell::OsShell>,
        out: &mut [u8],
    ) -> usize {
        let cur = self.http_lens[idx];
        if cur < RECORD_HEADER_LEN {
            return 0;
        }
        let Some((ctype, _ver, frag_len_u16)) =
            decode_record_header(&self.http_bufs[idx][..cur])
        else {
            return 0;
        };
        let frag_len = frag_len_u16 as usize;
        let total_rec = RECORD_HEADER_LEN + frag_len;
        if total_rec > SLOT_BUF {
            self.http_lens[idx] = 0;
            return 0;
        }
        if cur < total_rec {
            return 0;
        }

        if ctype == CONTENT_TYPE_HANDSHAKE {
            let mut ch_copy = [0u8; SLOT_BUF];
            ch_copy[..frag_len].copy_from_slice(&self.http_bufs[idx][RECORD_HEADER_LEN..total_rec]);
            self.http_lens[idx] = 0;
            let ch_msg = &ch_copy[..frag_len];
            let Ok(ch_view) = parse_client_hello(ch_msg) else {
                return 0;
            };
            let Some(client_pub) = ch_view.x25519_pub else {
                return 0;
            };
            // Derive a fresh per-handshake ephemeral server_random and X25519 server_pubkey.
            self.tls_handshake_seq = self.tls_handshake_seq.wrapping_add(1);
            let mut seed_buf = [0u8; 48];
            seed_buf[..32].copy_from_slice(&client_pub);
            seed_buf[32..40].copy_from_slice(&self.tls_handshake_seq.to_le_bytes());
            seed_buf[40..46].copy_from_slice(&self.mac);
            seed_buf[46] = idx as u8;
            seed_buf[47] = (self.ticks & 0xFF) as u8;
            let mut ephemeral_random = [0u8; 32];
            hmac_sha256(&TLS_SERVER_RANDOM, &seed_buf, &mut ephemeral_random);
            let mut ephemeral_pubkey = [0u8; 32];
            hmac_sha256(&TLS_SERVER_PUBKEY, &ephemeral_random, &mut ephemeral_pubkey);

            let mut sh_msg = [0u8; MAX_SERVER_HELLO_LEN];
            let Ok(sh_len) = build_server_hello(
                ch_msg,
                &ephemeral_random,
                &ephemeral_pubkey,
                None,
                &mut sh_msg,
            ) else {
                return 0;
            };
            let _ = Self::derive_tls13_record_key(
                &client_pub,
                ch_msg,
                &sh_msg[..sh_len],
                &mut self.tls_keys[idx],
            );
            self.tls_ready[idx] = true;

            let mut pos = 0usize;
            pos += encode_record_header(
                CONTENT_TYPE_HANDSHAKE,
                LEGACY_VERSION,
                sh_len as u16,
                &mut out[pos..],
            );
            out[pos..pos + sh_len].copy_from_slice(&sh_msg[..sh_len]);
            pos += sh_len;

            let mut plain = [0u8; 48];
            let plen = status_body(boots, &mut plain);
            let ctext_len = plen + crate::AeadImpl::TAG_LEN;
            let mut app_hdr = [0u8; RECORD_HEADER_LEN];
            let _ = encode_record_header(
                TLS_CONTENT_APPLICATION_DATA,
                LEGACY_VERSION,
                ctext_len as u16,
                &mut app_hdr,
            );
            out[pos..pos + RECORD_HEADER_LEN].copy_from_slice(&app_hdr);
            pos += RECORD_HEADER_LEN;
            let written = crate::AeadImpl::encrypt(
                &self.tls_keys[idx],
                &[0u8; 8],
                &plain[..plen],
                &app_hdr,
                &mut out[pos..],
            );
            pos += written;
            return pos;
        }

        if ctype == TLS_CONTENT_APPLICATION_DATA && self.tls_ready[idx] {
            let mut rec_hdr = [0u8; RECORD_HEADER_LEN];
            rec_hdr.copy_from_slice(&self.http_bufs[idx][..RECORD_HEADER_LEN]);
            let mut ctext = [0u8; SLOT_BUF];
            ctext[..frag_len].copy_from_slice(&self.http_bufs[idx][RECORD_HEADER_LEN..total_rec]);
            self.http_lens[idx] = 0;

            let mut req_plain = [0u8; SLOT_BUF];
            let Ok(req_len) = crate::AeadImpl::decrypt(
                &self.tls_keys[idx],
                &[1u8; 8],
                &ctext[..frag_len],
                &rec_hdr,
                &mut req_plain,
            ) else {
                return 0;
            };
            let mut http_resp = [0u8; 480];
            let resp_len =
                self.handle_http_request(&req_plain[..req_len], boots, shell, &mut http_resp);
            if resp_len == 0 {
                return 0;
            }
            let out_ctext_len = resp_len + crate::AeadImpl::TAG_LEN;
            let mut resp_hdr = [0u8; RECORD_HEADER_LEN];
            let _ = encode_record_header(
                TLS_CONTENT_APPLICATION_DATA,
                LEGACY_VERSION,
                out_ctext_len as u16,
                &mut resp_hdr,
            );
            out[..RECORD_HEADER_LEN].copy_from_slice(&resp_hdr);
            let written = crate::AeadImpl::encrypt(
                &self.tls_keys[idx],
                &[2u8; 8],
                &http_resp[..resp_len],
                &resp_hdr,
                &mut out[RECORD_HEADER_LEN..],
            );
            return RECORD_HEADER_LEN + written;
        }

        self.http_lens[idx] = 0;
        0
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
        use proteus_contracts::{FS_O_CREATE, FS_O_RDONLY, FS_O_RDWR, FS_O_TRUNC, Filesystem};

        let view = match HttpImpl::parse_request(req) {
            Ok(v) => v,
            Err(_) => return 0,
        };
        let is_login_req = view.method == HttpMethod::Post && view.path == b"/session/login";
        if !is_login_req {
            if let Some(sh) = shell.as_deref_mut() {
                sh.tick_login_cooldown();
            }
        }
        let ok_path = view.path == b"/status"
            || view.path == b"/healthz"
            || view.path == b"/";
        if view.method == HttpMethod::Get && ok_path {
            if let Some(sh) = shell.as_deref_mut() {
                if let Err(e) = sh
                    .svc
                    .mediate_endpoint(IpcOp::HttpGetStatus, true, false, &mut sh.audit)
                {
                    return build_service_error_response(e, out);
                }
            }
            let mut body = [0u8; 48];
            let blen = status_body(boots, &mut body);
            return HttpImpl::build_response(200, b"text/plain", &body[..blen], out).unwrap_or(0);
        }

        let Some(sh) = shell else {
            return HttpImpl::build_response(404, b"text/plain", b"not found\n", out).unwrap_or(0);
        };

        // 1. Built-in read-only telemetry endpoints (mediated via `svc-http`).
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
                || view.path == b"/session";
            if is_shell_endpoint {
                if let Err(e) = sh.svc.mediate_endpoint(
                    IpcOp::HttpGetTelemetry,
                    true,
                    false,
                    &mut sh.audit,
                ) {
                    return build_service_error_response(e, out);
                }
                let mut sh_body = [0u8; 440];
                let slen = sh
                    .exec_line(&view.path[1..], boots, 0, 0, &mut sh_body)
                    .bytes_written();
                return HttpImpl::build_response(200, b"text/plain", &sh_body[..slen], out)
                    .unwrap_or(0);
            }
        }

        // 2. Dynamic HTML5 Web Application Dashboard (`GET /app` or `GET /dashboard`, mediated via `svc-http`).
        if view.method == HttpMethod::Get
            && (view.path == b"/app" || view.path == b"/dashboard")
        {
            let sess_idx = extract_session_token(view.headers_raw)
                .and_then(|tok| sh.validate_session(tok));
            if let Err(e) = sh.svc.mediate_endpoint(
                IpcOp::HttpGetDashboard,
                true,
                sess_idx.is_some(),
                &mut sh.audit,
            ) {
                return build_service_error_response(e, out);
            }
            let mut default_tok: &[u8] = b"";
            if let Some(si) = sess_idx {
                default_tok = &sh.sessions[si].token_hex;
            }
            let mut html = [0u8; 1310];
            let mut pos = 0usize;
            pos += copy_msg(
                b"<!doctype html><html><head><meta charset=utf-8><title>Proteus</title><style>body{background:#0b1020;color:#e2e8f0;font:14px monospace}h1{color:#38bdf8}p,pre,input,button{background:#1e293b;color:#38bdf8;border:1px solid #475569;padding:4px}button{background:#0284c7;color:#fff}</style></head><body><h1>Proteus MTD OS</h1><p>boots=",
                &mut html[pos..],
            );
            pos += dec_u64(boots, &mut html[pos..]);
            pos += copy_msg(b" files=", &mut html[pos..]);
            pos += dec_u64(sh.fs.inode_count() as u64, &mut html[pos..]);
            pos += copy_msg(b" sql_tables=", &mut html[pos..]);
            pos += dec_u64(sh.db.table_count() as u64, &mut html[pos..]);
            pos += copy_msg(b" sql_rows=", &mut html[pos..]);
            pos += dec_u64(sh.db.total_rows() as u64, &mut html[pos..]);
            pos += copy_msg(b" sessions=", &mut html[pos..]);
            pos += dec_u64(sh.active_session_count() as u64, &mut html[pos..]);
            pos += copy_msg(b"</p>", &mut html[pos..]);
            if let Some(s_idx) = sess_idx {
                pos += copy_msg(b"<p>session_user=", &mut html[pos..]);
                pos += copy_msg(sh.sessions[s_idx].user_bytes(), &mut html[pos..]);
                pos += copy_msg(b" reqs=", &mut html[pos..]);
                pos += dec_u64(sh.sessions[s_idx].requests as u64, &mut html[pos..]);
                pos += copy_msg(b"</p>", &mut html[pos..]);
            }
            pos += copy_msg(b"<div>SID:<input id=t size=33 value=\"", &mut html[pos..]);
            pos += copy_msg(default_tok, &mut html[pos..]);
            pos += copy_msg(
                b"\"><br>Sh:<input id=c size=22 value=\"status\"><button onclick=\"S(c.value)\">Run</button><button onclick=\"S('smp')\">smp</button><button onclick=\"S('ps')\">ps</button><button onclick=\"S('ls')\">ls</button><button onclick=\"S('audit')\">audit</button><br>SQL:<input id=q size=30 value=\"SELECT * FROM kv\"><button onclick=\"R('/sql?'+encodeURIComponent(q.value))\">Query</button><button onclick=\"P('/sql',q.value)\">Mutate</button><br>ELF:<input id=x size=14 value=\"/bin/fib 10\"><button onclick=\"P('/exec',x.value)\">Exec</button> VFS:<input id=f size=10 value=\"etc/motd\"><button onclick=\"R('/fs/'+f.value)\">Cat</button></div><pre id=o>proteus&gt; ready</pre><script>R=async(u,b)=>{o.textContent=await(await fetch(u,{method:b?'POST':'GET',headers:{'X-Session-Token':t.value},body:b})).text()};P=R;S=x=>P('/sh',x)</script></body></html>\n",
                &mut html[pos..],
            );
            return HttpImpl::build_response(200, b"text/html", &html[..pos], out).unwrap_or(0);
        }

        // 3. Dynamic Session Management (`/session/login`, `/session/whoami`, `/session/logout`).
        if view.method == HttpMethod::Post && view.path == b"/session/login" {
            if let Err(e) = sh
                .svc
                .mediate_endpoint(IpcOp::SessionLogin, true, false, &mut sh.audit)
            {
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
                sh.tick_login_cooldown();
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
            let sid = sh.create_session(user, seq_tok);
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
            let s_idx = extract_session_token(view.headers_raw)
                .and_then(|tok| sh.validate_session(tok));
            if let Err(e) = sh.svc.mediate_endpoint(
                IpcOp::SessionWhoami,
                true,
                s_idx.is_some(),
                &mut sh.audit,
            ) {
                return build_service_error_response(e, out);
            }
            let Some(s_idx) = s_idx else {
                return HttpImpl::build_response(
                    401,
                    b"text/plain",
                    b"error: unauthorized\n",
                    out,
                )
                .unwrap_or(0);
            };
            let mut body = [0u8; 128];
            let mut bpos = 0usize;
            bpos += copy_msg(b"whoami: user=", &mut body[bpos..]);
            bpos += copy_msg(sh.sessions[s_idx].user_bytes(), &mut body[bpos..]);
            bpos += copy_msg(b" reqs=", &mut body[bpos..]);
            bpos += dec_u64(sh.sessions[s_idx].requests as u64, &mut body[bpos..]);
            bpos += copy_msg(b" sid=", &mut body[bpos..]);
            bpos += copy_msg(&sh.sessions[s_idx].token_hex, &mut body[bpos..]);
            bpos += copy_msg(b"\n", &mut body[bpos..]);
            return HttpImpl::build_response(200, b"text/plain", &body[..bpos], out).unwrap_or(0);
        }

        if view.method == HttpMethod::Post && view.path == b"/session/logout" {
            let tok_opt = extract_session_token(view.headers_raw);
            let has_valid = tok_opt
                .and_then(|tok| sh.validate_session(tok))
                .is_some();
            if let Err(e) = sh.svc.mediate_endpoint(
                IpcOp::SessionLogout,
                true,
                has_valid,
                &mut sh.audit,
            ) {
                return build_service_error_response(e, out);
            }
            if let Some(tok) = tok_opt {
                let _ = sh.revoke_session(tok);
            }
            return HttpImpl::build_response(
                200,
                b"text/plain",
                b"session: logged out\n",
                out,
            )
            .unwrap_or(0);
        }

        // 4. Embedded Relational SQL Database Server (`GET /sql[?<query>]`, `POST /sql`, `GET /db[?<query>]`, `POST /db`).
        //    Routed from `svc-http` across `IpcBus` to `svc-sql`.
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
                    let mut decoded = [0u8; 192];
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
                    if !crate::sql::SqlDb::is_readonly_query(q_slice) {
                        if let Err(e) = sh.svc.mediate_endpoint(
                            IpcOp::SqlMutate,
                            true,
                            false,
                            &mut sh.audit,
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
                    if let Err(e) = sh.svc.mediate_endpoint(
                        IpcOp::SqlQuery,
                        true,
                        false,
                        &mut sh.audit,
                    ) {
                        return build_service_error_response(e, out);
                    }
                    let blen = sh.db.exec(q_slice, &mut body);
                    return HttpImpl::build_response(200, b"text/plain", &body[..blen], out)
                        .unwrap_or(0);
                }
                if let Err(e) = sh
                    .svc
                    .mediate_endpoint(IpcOp::SqlQuery, true, false, &mut sh.audit)
                {
                    return build_service_error_response(e, out);
                }
                let blen = sh.db.exec(b".tables", &mut body);
                return HttpImpl::build_response(200, b"text/plain", &body[..blen], out)
                    .unwrap_or(0);
            }
            if view.method == HttpMethod::Post {
                let is_ro = crate::sql::SqlDb::is_readonly_query(view.body);
                if is_ro {
                    if let Err(e) = sh.svc.mediate_endpoint(
                        IpcOp::SqlQuery,
                        true,
                        false,
                        &mut sh.audit,
                    ) {
                        return build_service_error_response(e, out);
                    }
                } else {
                    let authed = extract_session_token(view.headers_raw)
                        .and_then(|tok| sh.validate_session(tok))
                        .is_some();
                    if let Err(e) = sh.svc.mediate_endpoint(
                        IpcOp::SqlMutate,
                        true,
                        authed,
                        &mut sh.audit,
                    ) {
                        return build_service_error_response(e, out);
                    }
                    sh.record_net_audit(AuditVerdict::Allowed, b"net:http:sql-write");
                }
                let mut body = [0u8; 384];
                let blen = sh.db.exec(view.body, &mut body);
                return HttpImpl::build_response(200, b"text/plain", &body[..blen], out)
                    .unwrap_or(0);
            }
        }

        // 5a. Interactive Web Shell Console (`POST /sh`, routed `svc-http -> svc-sh`).
        if view.method == HttpMethod::Post && view.path == b"/sh" {
            let authed = extract_session_token(view.headers_raw)
                .and_then(|tok| sh.validate_session(tok))
                .is_some();
            if let Err(e) = sh
                .svc
                .mediate_endpoint(IpcOp::ShellExec, true, authed, &mut sh.audit)
            {
                return build_service_error_response(e, out);
            }
            let mut sh_body = [0u8; 768];
            let slen = sh
                .exec_line(trim_ws(view.body), boots, 0, 0, &mut sh_body)
                .bytes_written();
            return HttpImpl::build_response(200, b"text/plain", &sh_body[..slen], out)
                .unwrap_or(0);
        }

        // 5. Sandboxed Remote Code Execution (`POST /exec`, routed `svc-http -> svc-sh`).
        if view.method == HttpMethod::Post && view.path == b"/exec" {
            let authed = extract_session_token(view.headers_raw)
                .and_then(|tok| sh.validate_session(tok))
                .is_some();
            if let Err(e) = sh
                .svc
                .mediate_endpoint(IpcOp::UserElfExec, true, authed, &mut sh.audit)
            {
                return build_service_error_response(e, out);
            }
            let mut cmd_line = [0u8; 128];
            let mut cpos = 0usize;
            cpos += copy_msg(b"exec ", &mut cmd_line[cpos..]);
            cpos += copy_msg(trim_ws(view.body), &mut cmd_line[cpos..]);
            let mut sh_body = [0u8; 384];
            let slen = sh
                .exec_line(&cmd_line[..cpos], boots, 0, 0, &mut sh_body)
                .bytes_written();
            return HttpImpl::build_response(200, b"text/plain", &sh_body[..slen], out)
                .unwrap_or(0);
        }

        // 6. VFS Static & Dynamic File Server (`GET /fs/<path>`, `PUT /fs/<path>`, `DELETE /fs/<path>`).
        if view.path.len() > 4 && view.path.starts_with(b"/fs/") {
            let vfs_path = &view.path[3..]; // includes leading `/`
            if view.method == HttpMethod::Get {
                if let Err(e) = sh
                    .svc
                    .mediate_endpoint(IpcOp::VfsRead, true, false, &mut sh.audit)
                {
                    return build_service_error_response(e, out);
                }
                let Ok(fh) = sh.fs.open(vfs_path, FS_O_RDONLY) else {
                    return HttpImpl::build_response(404, b"text/plain", b"not found\n", out)
                        .unwrap_or(0);
                };
                let mut fbuf = [0u8; 384];
                let flen = sh.fs.read(fh, 0, &mut fbuf).unwrap_or(0);
                let _ = sh.fs.close(fh);
                let ctype: &[u8] = if vfs_path.ends_with(b".html") {
                    b"text/html"
                } else if vfs_path.ends_with(b".json") {
                    b"application/json"
                } else {
                    b"text/plain"
                };
                return HttpImpl::build_response(200, ctype, &fbuf[..flen], out).unwrap_or(0);
            }
            if view.method == HttpMethod::Put {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                if let Err(e) = sh
                    .svc
                    .mediate_endpoint(IpcOp::VfsWrite, true, authed, &mut sh.audit)
                {
                    return build_service_error_response(e, out);
                }
                if vfs_path == b"/etc/os-release" {
                    sh.record_net_audit(AuditVerdict::Denied, b"net:http:fs-protected");
                    return HttpImpl::build_response(
                        403,
                        b"text/plain",
                        b"error: immutable system file\n",
                        out,
                    )
                    .unwrap_or(0);
                }
                let Ok(fh) = sh.fs.open(vfs_path, FS_O_RDWR | FS_O_CREATE | FS_O_TRUNC) else {
                    return HttpImpl::build_response(
                        500,
                        b"text/plain",
                        b"error: open failed\n",
                        out,
                    )
                    .unwrap_or(0);
                };
                let written = sh.fs.write(fh, 0, view.body).unwrap_or(0);
                let _ = sh.fs.close(fh);
                sh.record_net_audit(AuditVerdict::Allowed, b"net:http:fs-put");
                let mut msg = [0u8; 96];
                let mut mpos = 0usize;
                mpos += copy_msg(b"wrote ", &mut msg[mpos..]);
                mpos += dec_u64(written as u64, &mut msg[mpos..]);
                mpos += copy_msg(b" bytes to ", &mut msg[mpos..]);
                mpos += copy_msg(vfs_path, &mut msg[mpos..]);
                mpos += copy_msg(b"\n", &mut msg[mpos..]);
                return HttpImpl::build_response(201, b"text/plain", &msg[..mpos], out)
                    .unwrap_or(0);
            }
            if view.method == HttpMethod::Delete {
                let authed = extract_session_token(view.headers_raw)
                    .and_then(|tok| sh.validate_session(tok))
                    .is_some();
                if let Err(e) = sh
                    .svc
                    .mediate_endpoint(IpcOp::VfsDelete, true, authed, &mut sh.audit)
                {
                    return build_service_error_response(e, out);
                }
                if sh.fs.unlink(vfs_path).is_ok() {
                    sh.record_net_audit(AuditVerdict::Allowed, b"net:http:fs-del");
                    return HttpImpl::build_response(200, b"text/plain", b"removed\n", out)
                        .unwrap_or(0);
                }
                return HttpImpl::build_response(404, b"text/plain", b"not found\n", out)
                    .unwrap_or(0);
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
    let p = b"PROTEUS-STATUS boots=";
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

fn http_request_complete(buf: &[u8]) -> bool {
    let Some(hdr_end) = find_double_crlf(buf) else {
        return false;
    };
    let body_start = hdr_end + 4;
    if let Ok(view) = HttpImpl::parse_request(buf) {
        if let Some(cl_raw) = HttpImpl::find_header(view.headers_raw, b"Content-Length") {
            if let Some(cl) = parse_u64_dec(trim_ws(cl_raw)) {
                return buf.len() >= body_start.saturating_add(cl as usize);
            }
        }
    }
    true
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
    use proteus_contracts::{tcp_flags, Icmp, Tcp};

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
        assert!(body.starts_with("PROTEUS-STATUS boots=279"), "got {body:?}");
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
        assert!(body.contains("PROTEUS-STATUS boots=4"), "got {body:?}");
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
                    if s.contains("HTTP/1.1 200") && s.contains("PROTEUS-STATUS boots=1") {
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
        assert_eq!(&r[42..], b"proteus-te\n");

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
        assert!(body.contains("Proteus-TE x86_64 1.0-mtd"));
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
    fn concurrent_four_slot_tcp_connections_and_lru_eviction() {
        let mut net = LivedNet::new(MAC);
        let mut server_isns = [0u32; TCP_MAX_SLOTS];

        // Open 4 simultaneous TCP connections on ports 50000..50003 without closing any:
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
        assert_eq!(net.active_tcp_slots(), 4);

        // Interleave HTTP GET requests across all 4 established connections:
        for slot in (0..TCP_MAX_SLOTS).rev() {
            let cport = 50000 + (slot as u16);
            let cisn = 0x1000_0000 + ((slot as u32) << 16);
            let req = b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n";
            let mut pkt = [0u8; 128];
            let n = TcpImpl::build_segment(
                cport,
                HTTP_PORT,
                cisn.wrapping_add(1),
                server_isns[slot].wrapping_add(1),
                tcp_flags::ACK | tcp_flags::PSH,
                65535,
                req,
                PEER_IP,
                GUEST_IP,
                &mut pkt,
            )
            .unwrap();
            let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &pkt[..n]);
            let mut out = ReplySet::new();
            net.handle_frame(&frame[..flen], 7, &mut out);
            assert_eq!(out.len(), 1);
            let seg = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
            assert_eq!(seg.dst_port, cport);
            let body = core::str::from_utf8(seg.payload).unwrap();
            assert!(body.contains("PROTEUS-STATUS boots=7"));
        }

        // Opening a 5th concurrent connection evicts the oldest LRU slot cleanly:
        let mut syn5 = [0u8; 40];
        let n = TcpImpl::build_segment(
            50099,
            HTTP_PORT,
            0x9000_0000,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn5,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn5[..n]);
        let mut out = ReplySet::new();
        net.handle_frame(&frame[..flen], 7, &mut out);
        assert_eq!(out.len(), 1);
        let sa5 = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        assert_eq!(sa5.flags, tcp_flags::SYN | tcp_flags::ACK);
        assert_eq!(sa5.dst_port, 50099);
        assert_eq!(net.active_tcp_slots(), 4);
    }

    #[test]
    fn tls13_port_443_handshake_and_encrypted_application_data_roundtrip() {
        let mut net = LivedNet::new(MAC);
        let mut sh = crate::shell::OsShell::new();
        let client_port: u16 = 54443;
        let client_isn: u32 = 0x4430_0000;

        // 1. TCP SYN on HTTPS_PORT (443):
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
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
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn[..n]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 9, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        let sa = TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        assert_eq!(sa.flags, tcp_flags::SYN | tcp_flags::ACK);
        let server_isn = sa.seq;

        // 2. Build a TLS 1.3 ClientHello record and send over TCP/443:
        let client_random = [0x11u8; 32];
        let client_pubkey = [0x22u8; 32];
        let mut ch_msg = [0u8; 256];
        let ch_len =
            crate::tls::build_client_hello(&client_random, &client_pubkey, &mut ch_msg).unwrap();
        let mut tls_rec = [0u8; 264];
        let _ = encode_record_header(
            CONTENT_TYPE_HANDSHAKE,
            LEGACY_VERSION,
            ch_len as u16,
            &mut tls_rec,
        );
        tls_rec[RECORD_HEADER_LEN..RECORD_HEADER_LEN + ch_len].copy_from_slice(&ch_msg[..ch_len]);
        let rec_total = RECORD_HEADER_LEN + ch_len;

        let mut ch_seg = [0u8; 320];
        let n = TcpImpl::build_segment(
            client_port,
            HTTPS_PORT,
            client_isn.wrapping_add(1),
            server_isn.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            &tls_rec[..rec_total],
            PEER_IP,
            GUEST_IP,
            &mut ch_seg,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ch_seg[..n]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 9, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        let resp_seg =
            TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let payload = resp_seg.payload;

        // 3. Parse ServerHello record + decrypt ApplicationData status record:
        let (r1_type, r1_ver, r1_len_u16) = decode_record_header(payload).unwrap();
        assert_eq!(r1_type, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(r1_ver, LEGACY_VERSION);
        let r1_len = r1_len_u16 as usize;
        let sh_slice = &payload[RECORD_HEADER_LEN..RECORD_HEADER_LEN + r1_len];
        let parsed_sh = crate::tls::parse_server_hello(sh_slice).unwrap();
        assert_ne!(
            parsed_sh.server_pubkey, TLS_SERVER_PUBKEY,
            "TLS 1.3 ServerHello must advertise a fresh ephemeral X25519 keyshare"
        );
        assert_ne!(
            parsed_sh.server_random, TLS_SERVER_RANDOM,
            "TLS 1.3 ServerHello must advertise a fresh per-handshake server_random"
        );

        let mut record_key = [0u8; 16];
        let _ = LivedNet::derive_tls13_record_key(
            &client_pubkey,
            &ch_msg[..ch_len],
            sh_slice,
            &mut record_key,
        );

        let r2_slice = &payload[RECORD_HEADER_LEN + r1_len..];
        let (r2_type, _r2_ver, r2_len_u16) = decode_record_header(r2_slice).unwrap();
        assert_eq!(r2_type, TLS_CONTENT_APPLICATION_DATA);
        let r2_len = r2_len_u16 as usize;
        let mut plain_status = [0u8; 64];
        let plen = crate::AeadImpl::decrypt(
            &record_key,
            &[0u8; 8],
            &r2_slice[RECORD_HEADER_LEN..RECORD_HEADER_LEN + r2_len],
            &r2_slice[..RECORD_HEADER_LEN],
            &mut plain_status,
        )
        .unwrap();
        assert_eq!(&plain_status[..plen], b"PROTEUS-STATUS boots=9\n");

        // 4. Send an encrypted HTTP GET /uname inside a TLS ApplicationData record:
        let req_http = b"GET /uname HTTP/1.1\r\nHost: x\r\n\r\n";
        let req_ctext_len = req_http.len() + crate::AeadImpl::TAG_LEN;
        let mut req_rec = [0u8; 128];
        let _ = encode_record_header(
            TLS_CONTENT_APPLICATION_DATA,
            LEGACY_VERSION,
            req_ctext_len as u16,
            &mut req_rec,
        );
        let mut aad_hdr = [0u8; RECORD_HEADER_LEN];
        aad_hdr.copy_from_slice(&req_rec[..RECORD_HEADER_LEN]);
        let w = crate::AeadImpl::encrypt(
            &record_key,
            &[1u8; 8],
            req_http,
            &aad_hdr,
            &mut req_rec[RECORD_HEADER_LEN..],
        );
        let req_rec_total = RECORD_HEADER_LEN + w;

        let next_c_seq = client_isn.wrapping_add(1 + (rec_total as u32));
        let next_s_seq = server_isn.wrapping_add(1 + (payload.len() as u32));
        let mut app_seg = [0u8; 192];
        let n = TcpImpl::build_segment(
            client_port,
            HTTPS_PORT,
            next_c_seq,
            next_s_seq,
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            &req_rec[..req_rec_total],
            PEER_IP,
            GUEST_IP,
            &mut app_seg,
        )
        .unwrap();
        let (frame, flen) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &app_seg[..n]);
        let mut out = ReplySet::new();
        net.handle_frame_with_shell(&frame[..flen], 9, &mut sh, &mut out);
        assert_eq!(out.len(), 1);
        let app_resp_seg =
            TcpImpl::parse_segment(&out.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let r3 = app_resp_seg.payload;
        let (r3_type, _, r3_len_u16) = decode_record_header(r3).unwrap();
        assert_eq!(r3_type, TLS_CONTENT_APPLICATION_DATA);
        let r3_len = r3_len_u16 as usize;
        let mut dec_http = [0u8; 256];
        let dlen = crate::AeadImpl::decrypt(
            &record_key,
            &[2u8; 8],
            &r3[RECORD_HEADER_LEN..RECORD_HEADER_LEN + r3_len],
            &r3[..RECORD_HEADER_LEN],
            &mut dec_http,
        )
        .unwrap();
        let http_str = core::str::from_utf8(&dec_http[..dlen]).unwrap();
        assert!(http_str.starts_with("HTTP/1.1 200"));
        assert!(http_str.contains("Proteus-TE x86_64 1.0-mtd"));

        // 5. Open a second TLS 1.3 connection on port 443 and verify it generates a
        //    distinct ephemeral server_random, distinct server_pubkey, and distinct AEAD record key:
        let client_port2 = 51002u16;
        let client_isn2 = 0x2000_0000u32;
        let mut syn2 = [0u8; 40];
        let n = TcpImpl::build_segment(
            client_port2,
            HTTPS_PORT,
            client_isn2,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn2,
        )
        .unwrap();
        let (frame2, flen2) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &syn2[..n]);
        let mut out2 = ReplySet::new();
        net.handle_frame_with_shell(&frame2[..flen2], 9, &mut sh, &mut out2);
        let sa2 = TcpImpl::parse_segment(&out2.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let mut ch_seg2 = [0u8; 320];
        let n = TcpImpl::build_segment(
            client_port2,
            HTTPS_PORT,
            client_isn2.wrapping_add(1),
            sa2.seq.wrapping_add(1),
            tcp_flags::ACK | tcp_flags::PSH,
            65535,
            &tls_rec[..rec_total],
            PEER_IP,
            GUEST_IP,
            &mut ch_seg2,
        )
        .unwrap();
        let (frame2b, flen2b) = eth_ip(IP_PROTO_TCP, PEER_IP, GUEST_IP, &ch_seg2[..n]);
        let mut out2b = ReplySet::new();
        net.handle_frame_with_shell(&frame2b[..flen2b], 9, &mut sh, &mut out2b);
        let resp_seg2 =
            TcpImpl::parse_segment(&out2b.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        let (_, _, r1_len2_u16) = decode_record_header(resp_seg2.payload).unwrap();
        let sh_slice2 = &resp_seg2.payload[RECORD_HEADER_LEN..RECORD_HEADER_LEN + (r1_len2_u16 as usize)];
        let parsed_sh2 = crate::tls::parse_server_hello(sh_slice2).unwrap();
        assert_ne!(parsed_sh2.server_pubkey, parsed_sh.server_pubkey);
        assert_ne!(parsed_sh2.server_random, parsed_sh.server_random);
        let mut record_key2 = [0u8; 16];
        let _ = LivedNet::derive_tls13_record_key(
            &client_pubkey,
            &ch_msg[..ch_len],
            sh_slice2,
            &mut record_key2,
        );
        assert_ne!(record_key2, record_key);
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
        ppos += copy_msg(b"\r\n\r\n<h1>Hello Proteus</h1>", &mut put_req[ppos..]);
        let n = net.handle_http_request(&put_req[..ppos], 4, Some(&mut sh), &mut out);
        assert!(out[..n].starts_with(b"HTTP/1.1 201 Created\r\n"));

        let n = net.handle_http_request(
            b"GET /fs/var/index.html HTTP/1.1\r\nHost: x\r\n\r\n",
            4,
            Some(&mut sh),
            &mut out,
        );
        let s = core::str::from_utf8(&out[..n]).unwrap();
        assert!(s.starts_with("HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n"));
        assert!(s.ends_with("\r\n\r\n<h1>Hello Proteus</h1>"));
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

        // 4. Brute-force login rate limiting: 5 consecutive failed logins trigger a bounded 429 cooldown
        //    that automatically expires after 8 ticks/requests so a legitimate login succeeds!
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
        let n_ratelimited = net.handle_http_request(
            b"POST /session/login HTTP/1.1\r\nHost: x\r\n\r\n99 0000000000000000000000000000000000000000000000000000000000000000 admin",
            1,
            Some(&mut sh),
            &mut out,
        );
        assert!(out[..n_ratelimited].starts_with(b"HTTP/1.1 429 Too Many Requests\r\n"));
        // The 429 request above ticked cooldown from 8 -> 7; send 7 GET /status requests to expire the cooldown:
        for _ in 0..7 {
            let _ = net.handle_http_request(
                b"GET /status HTTP/1.1\r\nHost: x\r\n\r\n",
                1,
                Some(&mut sh),
                &mut out,
            );
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
}
