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
    icmp_type, AuditVerdict, Http, HttpMethod, Icmp, Ipv4PacketView, PacketFilter, Tcp, Verdict,
    IP_PROTO_ICMP, IP_PROTO_TCP, IP_PROTO_UDP,
};

use crate::firewall::FirewallImpl;
use crate::http::HttpImpl;
use crate::icmp::IcmpImpl;
use crate::net::ipv4_header_checksum;
use crate::tcp::{close, process_segment, send_payload, Tcb, TcpImpl, TcpState};
use crate::tls::hmac_sha256;

/// Guest IPv4 the service claims (QEMU slirp default guest).
pub const GUEST_IP: [u8; 4] = [10, 0, 2, 15];
/// UDP status port (existing hostfwd).
pub const UDP_STATUS_PORT: u16 = 8080;
/// HTTP status port.
pub const HTTP_PORT: u16 = 80;
/// Ethernet II header length.
pub const ETH_HEADER_LEN: usize = 14;
/// IPv4 header length (no options).
pub const IPV4_HEADER_LEN: usize = 20;
/// Maximum Ethernet payload + header we emit (untagged, no FCS).
pub const MAX_FRAME: usize = 1514;
/// Max replies produced from one inbound frame.
pub const MAX_REPLIES: usize = 3;
/// Scratch for an in-progress HTTP request (one TCB).
const HTTP_BUF: usize = 1024;
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

/// One-connection guest network service.
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
    tcb: Tcb,
    ticks: u32,
    ip_ident: u16,
    http_buf: [u8; HTTP_BUF],
    http_len: usize,
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
            tcb: Tcb::listen(GUEST_IP, HTTP_PORT, 65535),
            ticks: 1,
            ip_ident: 1,
            http_buf: [0u8; HTTP_BUF],
            http_len: 0,
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
            tcb: Tcb::listen(GUEST_IP, HTTP_PORT, 65535),
            ticks: 1,
            ip_ident: 1,
            http_buf: [0u8; HTTP_BUF],
            http_len: 0,
        }
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
        if self.tcb.state == TcpState::Closed {
            self.tcb = Tcb::listen(self.ip, HTTP_PORT, 65535);
            self.http_len = 0;
        }
        let seg = match TcpImpl::parse_segment(tcp, src_ip, self.ip) {
            Ok(s) => s,
            Err(_) => return,
        };
        if seg.dst_port != HTTP_PORT {
            return;
        }
        let inbound_payload = seg.payload;
        let (next, hint) = match process_segment(self.tcb, &seg, self.ticks) {
            Ok(t) => t,
            Err(_) => return,
        };
        self.tcb = next;
        if self.tcb.remote_ip == [0, 0, 0, 0] {
            self.tcb.remote_ip = src_ip;
        }

        if !inbound_payload.is_empty() && self.tcb.state != TcpState::Listen {
            let room = HTTP_BUF.saturating_sub(self.http_len);
            let n = inbound_payload.len().min(room);
            self.http_buf[self.http_len..self.http_len + n]
                .copy_from_slice(&inbound_payload[..n]);
            self.http_len += n;
        }

        let mut http_out = [0u8; 512];
        let mut http_n = 0usize;
        if self.http_len >= 18 && find_double_crlf(&self.http_buf[..self.http_len]).is_some() {
            http_n = build_status_http(&self.http_buf[..self.http_len], boots, shell, &mut http_out);
            self.http_len = 0;
        }

        if http_n > 0
            && (self.tcb.state == TcpState::Established || self.tcb.state == TcpState::CloseWait)
        {
            if let Ok((next, data_hint)) = send_payload(self.tcb, http_n as u32) {
                self.tcb = next;
                if data_hint.present {
                    self.emit_tcp(
                        dst_mac,
                        reply_ip,
                        data_hint.seq,
                        data_hint.ack,
                        data_hint.flags,
                        data_hint.window,
                        &http_out[..http_n],
                        out,
                    );
                }
            }
        } else if hint.present {
            self.emit_tcp(
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

        if self.tcb.state == TcpState::CloseWait {
            if let Ok((next, fin_hint)) = close(self.tcb) {
                self.tcb = next;
                if fin_hint.present {
                    self.emit_tcp(
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

    fn emit_tcp(
        &mut self,
        dst_mac: [u8; 6],
        reply_ip: [u8; 4],
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
        out: &mut ReplySet,
    ) {
        let mut seg = [0u8; 560];
        let n = match TcpImpl::build_segment(
            HTTP_PORT,
            self.tcb.remote_port,
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

fn build_status_http(
    req: &[u8],
    boots: u64,
    shell: Option<&mut crate::shell::OsShell>,
    out: &mut [u8],
) -> usize {
    let view = match HttpImpl::parse_request(req) {
        Ok(v) => v,
        Err(_) => return 0,
    };
    let ok_path = view.path == b"/status"
        || view.path == b"/healthz"
        || view.path == b"/";
    if view.method == HttpMethod::Get && ok_path {
        let mut body = [0u8; 48];
        let blen = status_body(boots, &mut body);
        return HttpImpl::build_response(200, b"text/plain", &body[..blen], out).unwrap_or(0);
    }
    if view.method == HttpMethod::Get {
        if let Some(sh) = shell {
            let is_shell_endpoint = view.path == b"/ps"
                || view.path == b"/ls"
                || view.path == b"/audit"
                || view.path == b"/uname"
                || view.path == b"/seal"
                || view.path == b"/ima"
                || view.path == b"/fw";
            if is_shell_endpoint {
                let mut sh_body = [0u8; 384];
                let slen = sh
                    .exec_line(&view.path[1..], boots, 0, 0, &mut sh_body)
                    .bytes_written();
                return HttpImpl::build_response(200, b"text/plain", &sh_body[..slen], out)
                    .unwrap_or(0);
            }
        }
    }
    HttpImpl::build_response(404, b"text/plain", b"not found\n", out).unwrap_or(0)
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
}
