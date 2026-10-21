//! TLS 1.3 and network protocol boot self-proof banners.

pub(crate) use crate::*;

/// TLS: run HKDF-Extract + HKDF-Expand-Label against the locked
/// fixtures, assert byte-equality, emit
/// `TLS hkdf OK prk_sha=<hex16>\n`.
///
/// Returns the PRK so a follow-on banner could chain off it; the kernel
/// does not need it again here.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_tls_hkdf() {
    let mut prk = [0u8; 32];
    hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk);
    assert_eq_bytes(&prk, &kf::HKDF_EXPECTED_PRK, "TLS HKDF-Extract");

    let mut expanded = [0u8; kf::HKDF_EXPAND_OUT_LEN];
    hkdf_expand_label(&prk, kf::HKDF_EXPAND_LABEL, &kf::HKDF_INFO, &mut expanded);
    assert_eq_bytes(
        &expanded[..8],
        &kf::HKDF_EXPECTED_EXPAND_PREFIX8,
        "TLS HKDF-Expand-Label",
    );

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"TLS hkdf OK prk_sha=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += hex_encode(&prk, 8, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// TLS: run the RustCrypto provider's known-answer self-test — AES-128-GCM
/// (GCM spec cases 1–2), ChaCha20-Poly1305 (RFC 8439 §2.8.2), X25519
/// (RFC 7748 §6.1), ECDSA P-256 / SHA-256 (RFC 6979 §A.2.5), P-256 ECDH and a
/// record-layer round trip with tamper rejection — then emit
/// `TLS kat OK aead=2 kx=2 sig=1\n`. These are the exact primitives rustls
/// calls for HTTPS on port 443; a morph that perturbs any of them panics
/// here and the banner never appears.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_tls_kat() {
    let report = match target_enterprise::tls_provider::self_test() {
        Ok(r) => r,
        Err(why) => {
            serial_write_str("TLS kat FAIL ");
            serial_write_str(why);
            serial_write_str("\n");
            panic!("TLS provider known-answer test failed");
        }
    };
    let mut line = [0u8; 48];
    let mut pos = 0usize;
    for (label, n) in [(&b"TLS kat OK aead="[..], report.aead), (b" kx=", report.kx), (b" sig=", report.sig)] {
        line[pos..pos + label.len()].copy_from_slice(label);
        pos += label.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
    }
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// TLS: derive the golden node identity, generate its self-signed X.509 v3
/// certificate, parse it back with the in-tree DER parser, check the
/// subject/issuer, validity window and ECDSA P-256 public key, and verify the
/// certificate's self-signature. Emits
/// `TLS cert OK alg=ecdsa-p256 sha=<hex16>\n` (first 8 bytes of the DER
/// SHA-256 fingerprint; RFC 6979 signing makes it identical every boot).
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_tls_cert() {
    use cuttle_contracts::{X509PubKey, X509};
    use target_enterprise::https::{golden, ServerIdentity};
    use target_enterprise::x509::X509Impl;

    let identity = ServerIdentity::derive(&golden::IDENTITY_SECRET, golden::MAC);
    let cert = match X509Impl::parse(identity.cert_der()) {
        Ok(c) => c,
        Err(_) => panic!("TLS cert: generated certificate does not parse"),
    };
    if cert.subject != cert.issuer {
        panic!("TLS cert: not self-issued");
    }
    if cert.not_before.unix != 1_735_689_600 || cert.not_after.unix != 4_102_444_799 {
        panic!("TLS cert: validity window drift");
    }
    let public = identity.public_key_sec1();
    match cert.pubkey {
        X509PubKey::EcdsaP256 { point } if point == &public[..] => {}
        _ => panic!("TLS cert: SPKI is not the identity's P-256 key"),
    }
    if !target_enterprise::tls_provider::ecdsa_p256_sha256_verify(&public, cert.tbs, cert.signature) {
        panic!("TLS cert: self-signature does not verify");
    }
    assert_eq_bytes(&identity.fingerprint(), &kf::HTTPS_GOLDEN_CERT_SHA256, "TLS cert fingerprint");

    let mut line = [0u8; 64];
    let prefix = b"TLS cert OK alg=ecdsa-p256 sha=";
    line[..prefix.len()].copy_from_slice(prefix);
    let mut pos = prefix.len();
    pos += hex_encode(&identity.fingerprint(), 8, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// NET: build the canonical UDP/IPv4 datagram through
/// [`target_enterprise::net::build_udp_datagram`], assert the 38 emitted
/// bytes match the locked golden fixture in `kernel_fixtures`, parse
/// the datagram back through `parse_ipv4_header` + `parse_udp_datagram`
/// and assert the recovered src_ip / dst_ip / ttl / ident / port
/// fields, then emit
/// `NET build OK len=<dec> ip_cksum=<hex4> udp_cksum=<hex4>\n`.
///
/// The byte-equality check against `NET_EXPECTED_DATAGRAM` is the
/// load-bearing wire-equivalence proof inside the kernel: a morph
/// candidate that produces different bytes panics here rather than
/// reaching the trailing CUTTLE-TE HALT banner — the QEMU smoke test
/// then surfaces the missing banner as a failure.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_net_build() {
    let mut buf = [0u8; kf::NET_EXPECTED_LEN];
    let n = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut buf,
    )
    .unwrap_or_else(|_| panic!("NET build_udp_datagram failed"));
    if n != kf::NET_EXPECTED_LEN {
        panic!("NET emitted length drift");
    }
    assert_eq_bytes(&buf[..n], &kf::NET_EXPECTED_DATAGRAM, "NET datagram");

    let ip = parse_ipv4_header(&buf[..n])
        .unwrap_or_else(|_| panic!("NET parse_ipv4_header rejected own output"));
    if ip.src_ip != kf::NET_SRC_IP
        || ip.dst_ip != kf::NET_DST_IP
        || ip.ttl != kf::NET_TTL
        || ip.identification != kf::NET_IDENT
        || ip.header_checksum != kf::NET_EXPECTED_IP_CHECKSUM
    {
        panic!("NET IPv4 parse drift");
    }

    let udp = parse_udp_datagram(kf::NET_SRC_IP, kf::NET_DST_IP, &buf[20..n])
        .unwrap_or_else(|_| panic!("NET parse_udp_datagram rejected own output"));
    if udp.src_port != kf::NET_SRC_PORT
        || udp.dst_port != kf::NET_DST_PORT
        || udp.checksum != kf::NET_EXPECTED_UDP_CHECKSUM
        || udp.payload_len != kf::NET_PAYLOAD.len()
    {
        panic!("NET UDP parse drift");
    }

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"NET build OK len=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    let mid = b" ip_cksum=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    let mut hex_ip = [0u8; 8];
    hex_u32(kf::NET_EXPECTED_IP_CHECKSUM as u32, &mut hex_ip);
    // Take the low 4 chars (16-bit value).
    line[pos..pos + 4].copy_from_slice(&hex_ip[4..]);
    pos += 4;
    let mid2 = b" udp_cksum=";
    line[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    let mut hex_udp = [0u8; 8];
    hex_u32(kf::NET_EXPECTED_UDP_CHECKSUM as u32, &mut hex_udp);
    line[pos..pos + 4].copy_from_slice(&hex_udp[4..]);
    pos += 4;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// TCP: drive a full 3-way handshake (LISTEN → SYN_RCVD → ESTABLISHED)
// then a clean teardown (FIN-from-peer → CLOSE_WAIT → close() → LAST_ACK
// → ACK → CLOSED). Every transition exercises real TCB state arithmetic
// AND a real wire-byte round-trip through `TcpImpl::build_segment` +
// `TcpImpl::parse_segment` (checksum-verified). Emits:
//   `TCP handshake OK state=ESTABLISHED seq=<hex8>\n`
//   `TCP teardown OK state=CLOSED snd_nxt=<hex8>\n`
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_tcp() {
    use cuttle_contracts::{tcp_flags, Tcp};
    use target_enterprise::tcp::{close, process_segment, Tcb, TcpImpl, TcpState};

    let server_ip: [u8; 4] = [10, 0, 0, 2];
    let client_ip: [u8; 4] = [10, 0, 0, 1];
    let server_port: u16 = 8443;
    let client_port: u16 = 54321;
    let client_isn: u32 = 0x1000_0000;

    // Step 1: passive open.
    let mut tcb = Tcb::listen(server_ip, server_port, 65535);
    if tcb.state != TcpState::Listen {
        panic!("TCP listen did not produce Listen state");
    }

    // Step 2: client → server SYN.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn,
        0,
        tcp_flags::SYN,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build SYN failed"),
    };
    let syn = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse SYN failed (checksum?)"),
    };
    let (next_tcb, syn_ack_hint) = match process_segment(tcb, &syn, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process SYN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::SynReceived {
        panic!("TCP SYN did not move TCB to SynReceived");
    }
    if !syn_ack_hint.present {
        panic!("TCP process SYN must produce a SYN+ACK reply hint");
    }
    let server_isn = syn_ack_hint.seq;

    // Step 3: client → server ACK of SYN+ACK.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build ACK-of-SYN failed"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse ACK-of-SYN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &ack, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process ACK-of-SYN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::Established {
        panic!("TCP 3-way handshake did not reach Established");
    }
    let established_seq = tcb.snd_nxt;

    // Emit handshake banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TCP handshake OK state=ESTABLISHED seq=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let bytes = established_seq.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&bytes, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Step 4: client → server FIN (peer initiating close).
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::FIN | tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build FIN failed"),
    };
    let fin = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse FIN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &fin, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process FIN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::CloseWait {
        panic!("TCP FIN did not move TCB to CloseWait");
    }

    // Step 5: local close() → LastAck.
    let (next_tcb, fin_hint) = match close(tcb) {
        Ok(t) => t,
        Err(_) => panic!("TCP close() failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::LastAck {
        panic!("TCP close() did not produce LastAck");
    }
    if !fin_hint.present {
        panic!("TCP close() must produce FIN reply hint");
    }

    // Step 6: client → server ACK of our FIN.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(2),
        tcb.snd_nxt,
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build ACK-of-our-FIN failed"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse ACK-of-our-FIN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &ack, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process ACK-of-our-FIN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::Closed {
        panic!("TCP teardown did not reach Closed");
    }

    // Emit teardown banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TCP teardown OK state=CLOSED snd_nxt=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let bytes = tcb.snd_nxt.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&bytes, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// HTTP/1.1: parse a fixture `GET /healthz HTTP/1.1` request through
// `HttpImpl::parse_request`, then build a 200 OK response with
// `Content-Type: text/plain` and body "OK" through
// `HttpImpl::build_response`. Asserts the parsed method/path AND the
// byte-exact response prefix. Emits:
//   `HTTP parse OK method=GET path=/healthz\n`
//   `HTTP build OK status=200 bytes=<N>\n`
//
// A morph that perturbs the request-line tokenizer, the header-block
// scanner, or the response status-line emitter panics inside this
// banner and the trailing `CUTTLE-TE HALT` is suppressed.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_http() {
    use cuttle_contracts::{Http, HttpMethod};
    use target_enterprise::http::HttpImpl;

    // --- parse ---
    let req: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\n\r\n";
    let view = match HttpImpl::parse_request(req) {
        Ok(v) => v,
        Err(_) => panic!("HTTP parse_request returned Err for healthz fixture"),
    };
    if view.method != HttpMethod::Get {
        panic!("HTTP parse: method drift");
    }
    if view.path != b"/healthz" {
        panic!("HTTP parse: path drift");
    }
    if view.version_minor != 1 {
        panic!("HTTP parse: version drift");
    }
    // Header lookup must find Host case-insensitively.
    match HttpImpl::find_header(view.headers_raw, b"host") {
        Some(v) if v == b"localhost" => {}
        Some(_) => panic!("HTTP find_header: host value drift"),
        None => panic!("HTTP find_header: missing Host"),
    }
    serial_write_str("HTTP parse OK method=GET path=/healthz\n");

    // --- build ---
    let mut out = [0u8; 96];
    let n = match HttpImpl::build_response(200, b"text/plain", b"OK", &mut out) {
        Ok(n) => n,
        Err(_) => panic!("HTTP build_response returned Err"),
    };
    // Byte-exact assert on the full response we expect from the locked
    // wire surface.
    let expected: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK";
    if n != expected.len() {
        panic!("HTTP build: length drift");
    }
    assert_eq_bytes(&out[..n], expected, "HTTP response");

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"HTTP build OK status=200 bytes=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// DNS/RFC 1035: build an A-record query for `cuttle.local`, parse it
// to recover the question name byte-for-byte, then build a response
// pointing to 10.0.0.42 and assert the resulting bytes match the
// locked golden encoding. Emits:
//   `DNS query OK id=<hex4> qname=cuttle.local\n`
//   `DNS response OK id=<hex4> ans=10.0.0.42 bytes=<N>\n`
//
// A morph that perturbs name encoding, header byte order, or the
// answer-section assembly panics here and the trailing banners are
// suppressed.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_dns() {
    use cuttle_contracts::{dns_class, dns_flags, Dns, DnsRecordType};
    use target_enterprise::dns::DnsImpl;

    let qid: u16 = 0xC0DE;

    // --- query build ---
    let mut qbuf = [0u8; 64];
    let qn = match DnsImpl::build_a_query(qid, b"cuttle.local", &mut qbuf) {
        Ok(n) => n,
        Err(_) => panic!("DNS build_a_query returned Err"),
    };
    // Byte-exact assertion: known canonical encoding of "cuttle.local"
    // as an A query with RD set.
    let qexpected: &[u8] = &[
        0xC0, 0xDE, // id
        0x01, 0x00, // flags (RD)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qd=1, an/ns/ar=0
        6, b'c', b'u', b't', b't', b'l', b'e',
        5, b'l', b'o', b'c', b'a', b'l', 0, // QNAME
        0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
    ];
    if qn != qexpected.len() {
        panic!("DNS query length drift");
    }
    assert_eq_bytes(&qbuf[..qn], qexpected, "DNS A query");

    // --- parse round-trip ---
    let qview = match DnsImpl::parse_message(&qbuf[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("DNS parse_message rejected own query"),
    };
    if qview.header.id != qid {
        panic!("DNS parse: id drift");
    }
    if qview.header.qdcount != 1 {
        panic!("DNS parse: qdcount drift");
    }
    if qview.first_question_type != DnsRecordType::A as u16 {
        panic!("DNS parse: qtype drift");
    }
    if qview.first_question_class != dns_class::IN {
        panic!("DNS parse: qclass drift");
    }
    let qname_wire = match qview.first_question_name {
        Some(n) => n,
        None => panic!("DNS parse: missing first question name"),
    };

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"DNS query OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let id_be = qid.to_be_bytes();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" qname=cuttle.local";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);

    // --- response build (echo of the parsed qname + 10.0.0.42 / TTL 60) ---
    let mut rbuf = [0u8; 96];
    let rn = match DnsImpl::build_a_response(qid, qname_wire, [10, 0, 0, 42], 60, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("DNS build_a_response returned Err"),
    };
    // Parse the response and verify the recovered fields.
    let rview = match DnsImpl::parse_message(&rbuf[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("DNS parse_message rejected own response"),
    };
    if rview.header.id != qid {
        panic!("DNS response: id drift");
    }
    if rview.header.flags & dns_flags::QR_RESPONSE == 0 {
        panic!("DNS response: QR bit clear");
    }
    if rview.header.qdcount != 1 || rview.header.ancount != 1 {
        panic!("DNS response: section count drift");
    }
    // Confirm the rdata bytes 10.0.0.42 land at the locked offset.
    // header(12) + qname + 4 (qtype/qclass) + qname + 2 + 2 + 4 + 2
    let qn_len = qname_wire.len();
    let rdata_off = 12 + qn_len + 4 + qn_len + 2 + 2 + 4 + 2;
    if rbuf[rdata_off] != 10
        || rbuf[rdata_off + 1] != 0
        || rbuf[rdata_off + 2] != 0
        || rbuf[rdata_off + 3] != 42
    {
        panic!("DNS response: rdata drift");
    }

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"DNS response OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" ans=10.0.0.42 bytes=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(rn as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// ICMP/RFC 792: build an echo request (ping) with id=0x4242, seq=7,
// payload "cuttle-ping", parse it (which verifies the RFC 1071
// checksum), then build the matching echo reply and confirm the
// reply parses with type=ECHO_REPLY and identical id/seq. Emits:
//   `ICMP echo_req OK id=4242 seq=7 cksum=<hex4>\n`
//   `ICMP echo_rep OK id=4242 seq=7\n`
//
// A morph that perturbs the checksum routine, the type-code byte, or
// the identifier/sequence byte order panics inside `banner_icmp` and
// these banners never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_icmp() {
    use cuttle_contracts::{icmp_type, Icmp};
    use target_enterprise::icmp::IcmpImpl;

    let id: u16 = 0x4242;
    let seq: u16 = 7;
    let payload: &[u8] = b"cuttle-ping";

    // --- build + parse echo request ---
    let mut qbuf = [0u8; 32];
    let qn = match IcmpImpl::build_echo_request(id, seq, payload, &mut qbuf) {
        Ok(n) => n,
        Err(_) => panic!("ICMP build_echo_request returned Err"),
    };
    let qview = match IcmpImpl::parse_echo(&qbuf[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("ICMP parse_echo rejected own request (checksum?)"),
    };
    if qview.icmp_type != icmp_type::ECHO_REQUEST {
        panic!("ICMP echo request: type drift");
    }
    if qview.identifier != id || qview.sequence_number != seq {
        panic!("ICMP echo request: id/seq drift");
    }
    if qview.payload != payload {
        panic!("ICMP echo request: payload drift");
    }

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"ICMP echo_req OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let id_be = id.to_be_bytes();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" seq=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(seq as u64, &mut line[pos..]);
    let mid2 = b" cksum=";
    line[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    let cksum_be = qview.checksum.to_be_bytes();
    let mut cks_hex = [0u8; 4];
    hex_encode(&cksum_be, 2, &mut cks_hex);
    line[pos..pos + 4].copy_from_slice(&cks_hex);
    pos += 4;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);

    // --- build + parse echo reply ---
    let mut rbuf = [0u8; 32];
    let rn = match IcmpImpl::build_echo_reply(id, seq, payload, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("ICMP build_echo_reply returned Err"),
    };
    let rview = match IcmpImpl::parse_echo(&rbuf[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("ICMP parse_echo rejected own reply"),
    };
    if rview.icmp_type != icmp_type::ECHO_REPLY {
        panic!("ICMP echo reply: type drift");
    }
    if rview.identifier != id || rview.sequence_number != seq {
        panic!("ICMP echo reply: id/seq drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"ICMP echo_rep OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" seq=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(seq as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// Ethernet/IEEE 802.3: wrap the locked NET fixture (the
// 38-byte UDP/IPv4 datagram from kernel_fixtures) inside an Ethernet
// II frame, byte-exact assert against the locked golden bytes
// (header + payload), parse it back through `EthImpl::parse_frame`,
// confirm dst/src/EtherType/payload are recovered. Then build a
// VLAN-tagged version with PCP=3/VID=100 and round-trip it. Emits:
//   `ETH build OK len=52 ethertype=0800`
//   `ETH parse OK src=00aabbccddee dst=1234567890bc`
//   `ETH vlan OK tci=6064 vid=100 pcp=3`
//
// A morph that perturbs MAC byte order, EtherType big-endian
// encoding, VLAN TCI field packing, or the header byte layout
// panics in `banner_eth` and the banners never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_eth() {
    use cuttle_contracts::{ether_type, Eth};
    use target_enterprise::ethernet::{
        is_broadcast, pack_vlan_tci, vlan_pcp, vlan_vid, EthImpl, ETH_HEADER_LEN,
    };
    use target_enterprise::net::build_udp_datagram;

    let dst: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let src: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    // Rebuild the canonical UDP/IPv4 datagram so we have a real wire
    // payload to wrap — not just synthetic bytes.
    let mut ipv4 = [0u8; kf::NET_EXPECTED_LEN];
    let ipv4_len = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut ipv4,
    )
    .unwrap_or_else(|_| panic!("ETH banner: net build failed"));
    if ipv4_len != kf::NET_EXPECTED_LEN {
        panic!("ETH banner: net length drift");
    }

    // --- build untagged frame ---
    let mut frame = [0u8; 64];
    let n = match EthImpl::build_frame(dst, src, ether_type::IPV4, &ipv4[..ipv4_len], &mut frame)
    {
        Ok(n) => n,
        Err(_) => panic!("ETH build_frame returned Err"),
    };
    if n != ETH_HEADER_LEN + ipv4_len {
        panic!("ETH build_frame length drift");
    }
    // Header bytes byte-exact.
    let mut header_expected = [0u8; 14];
    header_expected[..6].copy_from_slice(&dst);
    header_expected[6..12].copy_from_slice(&src);
    header_expected[12] = 0x08;
    header_expected[13] = 0x00;
    assert_eq_bytes(&frame[..14], &header_expected, "ETH header");
    // Payload bytes byte-exact (against the locked NET fixture).
    assert_eq_bytes(&frame[14..n], &kf::NET_EXPECTED_DATAGRAM, "ETH payload");

    // Broadcast detection sanity — used by the eventual NIC driver to
    // short-circuit the unicast-filter path.
    let bcast = cuttle_contracts::ETH_BROADCAST_MAC;
    if !is_broadcast(&bcast) {
        panic!("ETH is_broadcast(ETH_BROADCAST_MAC) returned false");
    }

    // Emit build banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"ETH build OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        let mid = b" ethertype=0800";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- parse + recover ---
    let view = match EthImpl::parse_frame(&frame[..n]) {
        Ok(v) => v,
        Err(_) => panic!("ETH parse_frame rejected own output"),
    };
    if view.dst != dst {
        panic!("ETH parse: dst MAC drift");
    }
    if view.src != src {
        panic!("ETH parse: src MAC drift");
    }
    if view.ether_type != ether_type::IPV4 {
        panic!("ETH parse: ethertype drift");
    }
    if view.vlan_tci.is_some() {
        panic!("ETH parse: untagged frame claimed VLAN");
    }
    if view.payload.len() != ipv4_len {
        panic!("ETH parse: payload length drift");
    }
    if &view.payload[..] != &kf::NET_EXPECTED_DATAGRAM[..] {
        panic!("ETH parse: payload byte drift");
    }

    // Emit parse banner with src/dst MACs as hex12.
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"ETH parse OK src=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&src, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        let mid = b" dst=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        hex_encode(&dst, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- 802.1Q VLAN tagged round-trip ---
    let tci = pack_vlan_tci(3, false, 100); // PCP=3, DEI=0, VID=100
    if tci != 0x6064 {
        panic!("ETH pack_vlan_tci drift");
    }
    let mut vbuf = [0u8; 64];
    let vn = match EthImpl::build_frame_vlan(dst, src, tci, ether_type::IPV4, &[], &mut vbuf) {
        Ok(n) => n,
        Err(_) => panic!("ETH build_frame_vlan returned Err"),
    };
    let vview = match EthImpl::parse_frame(&vbuf[..vn]) {
        Ok(v) => v,
        Err(_) => panic!("ETH parse rejected own VLAN frame"),
    };
    match vview.vlan_tci {
        Some(t) if t == tci => {}
        Some(_) => panic!("ETH VLAN tci drift"),
        None => panic!("ETH parse missed VLAN tag"),
    }
    if vlan_pcp(tci) != 3 || vlan_vid(tci) != 100 {
        panic!("ETH VLAN field decode drift");
    }

    // Emit VLAN banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"ETH vlan OK tci=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let tci_be = tci.to_be_bytes();
        let mut hex = [0u8; 4];
        hex_encode(&tci_be, 2, &mut hex);
        line[pos..pos + 4].copy_from_slice(&hex);
        pos += 4;
        let mid = b" vid=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(vlan_vid(tci) as u64, &mut line[pos..]);
        let mid2 = b" pcp=";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(vlan_pcp(tci) as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-046: ARP / RFC 826 over Ethernet. Build a REQUEST asking
// "who has 10.0.0.42? tell 10.0.0.1 / 00:AA:BB:CC:DD:EE", assert
// the wire bytes are byte-exact against the locked 28-byte
// expectation, parse them back through `ArpImpl::parse_packet`,
// confirm the round-trip recovers OPER/sender/target. Then build
// the matching REPLY (target_mac = 12:34:56:78:9A:BC) and add it
// to a 4-slot ArpCache; confirm lookup hits. Emits:
//   `ARP request OK target_ip=10.0.0.42 op=1`
//   `ARP cache OK entries=1`
//
// A morph that perturbs HTYPE/PTYPE big-endian encoding, the
// HLEN/PLEN constants, the 28-byte field layout, or the cache LRU /
// poison-defence routine panics inside `banner_arp` and the
// banners never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_arp() {
    use cuttle_contracts::{arp_op, Arp};
    use target_enterprise::arp::{ArpCache, ArpImpl, PACKET_LEN};

    let sender_mac: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let sender_ip: [u8; 4] = [10, 0, 0, 1];
    let target_ip: [u8; 4] = [10, 0, 0, 42];
    let target_mac: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    // --- build REQUEST ---
    let mut req = [0u8; 32];
    let qn = match ArpImpl::build_request(sender_mac, sender_ip, target_ip, &mut req) {
        Ok(n) => n,
        Err(_) => panic!("ARP build_request returned Err"),
    };
    if qn != PACKET_LEN {
        panic!("ARP build_request length drift");
    }
    let expected_req: [u8; 28] = [
        0x00, 0x01, // HTYPE = 1
        0x08, 0x00, // PTYPE = 0x0800
        0x06, 0x04, // HLEN=6, PLEN=4
        0x00, 0x01, // OPER = REQUEST
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // sender MAC
        10, 0, 0, 1, // sender IP
        0, 0, 0, 0, 0, 0, // target MAC zeros
        10, 0, 0, 42, // target IP
    ];
    assert_eq_bytes(&req[..qn], &expected_req, "ARP REQUEST bytes");

    // Parse + recover.
    let qview = match ArpImpl::parse_packet(&req[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("ARP parse_packet rejected own REQUEST"),
    };
    if qview.oper != arp_op::REQUEST {
        panic!("ARP REQUEST: oper drift");
    }
    if qview.sender_mac != sender_mac {
        panic!("ARP REQUEST: sender_mac drift");
    }
    if qview.sender_ip != sender_ip {
        panic!("ARP REQUEST: sender_ip drift");
    }
    if qview.target_ip != target_ip {
        panic!("ARP REQUEST: target_ip drift");
    }
    if qview.target_mac != [0u8; 6] {
        panic!("ARP REQUEST: target_mac not all-zeros");
    }

    // Emit request banner.
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"ARP request OK target_ip=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Format the dotted-decimal IP in-line — keeps the banner
        // grep-friendly for the qemu_smoke required-banner check.
        let octets = [target_ip[0], target_ip[1], target_ip[2], target_ip[3]];
        for (i, oct) in octets.iter().enumerate() {
            pos += dec_u64(*oct as u64, &mut line[pos..]);
            if i < 3 {
                line[pos] = b'.';
                pos += 1;
            }
        }
        let mid = b" op=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(qview.oper as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- build matching REPLY + populate cache ---
    let mut rep = [0u8; 32];
    let rn = match ArpImpl::build_reply(target_mac, target_ip, sender_mac, sender_ip, &mut rep) {
        Ok(n) => n,
        Err(_) => panic!("ARP build_reply returned Err"),
    };
    let rview = match ArpImpl::parse_packet(&rep[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("ARP parse_packet rejected own REPLY"),
    };
    if rview.oper != arp_op::REPLY {
        panic!("ARP REPLY: oper drift");
    }
    if rview.sender_mac != target_mac {
        panic!("ARP REPLY: sender_mac drift");
    }
    if rview.sender_ip != target_ip {
        panic!("ARP REPLY: sender_ip drift");
    }
    if rview.target_mac != sender_mac {
        panic!("ARP REPLY: target_mac drift");
    }

    let mut cache: ArpCache<4> = ArpCache::new();
    // Use the parsed REPLY's (sender_ip, sender_mac) — that's the
    // canonical "we now know IP X is at MAC Y" pattern.
    if cache
        .insert(rview.sender_ip, rview.sender_mac, 100)
        .is_err()
    {
        panic!("ARP cache insert failed");
    }
    if cache.len() != 1 {
        panic!("ARP cache: post-insert len drift");
    }
    match cache.lookup(&target_ip, 200) {
        Some(m) if m == target_mac => {}
        Some(_) => panic!("ARP cache: lookup returned wrong MAC"),
        None => panic!("ARP cache: lookup missed inserted entry"),
    }

    // Emit cache banner.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"ARP cache OK entries=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(cache.len() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-047: DHCPv4 client (RFC 2131/2132). Drive a synthetic
// INIT → DISCOVER → (parse OFFER fixture) → REQUEST → (parse ACK
// fixture) → BOUND sequence. Asserts:
//   - DISCOVER bytes round-trip through parse_message (xid +
//     msg_type recovered).
//   - OFFER fixture is accepted: state -> Requesting, yiaddr +
//     server_id captured.
//   - ACK fixture binds the lease with the expected yiaddr.
//
// Emits:
//   `DHCP discover OK xid=<hex8>\n`
//   `DHCP bound OK yiaddr=10.0.0.42 lease=86400\n`
//
// A kernel that perturbs the BOOTP byte order, mishandles the
// magic-cookie offset, or breaks the option TLV scan panics here
// and the trailing banners never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_dhcp() {
    use cuttle_contracts::{dhcp_msg_type, Dhcp, DhcpClientState, DHCP_FIXED_HEADER_LEN};
    use target_enterprise::dhcp::{DhcpClient, DhcpImpl, DHCP_MAX_MESSAGE_LEN};

    let mac: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let xid: u32 = 0xDEAD_BEEF;
    let offered_ip: [u8; 4] = [10, 0, 0, 42];
    let server_id: [u8; 4] = [10, 0, 0, 1];
    let subnet: [u8; 4] = [255, 255, 255, 0];
    let router: [u8; 4] = [10, 0, 0, 1];
    let dns: [u8; 4] = [10, 0, 0, 53];
    let lease_secs: u32 = 86_400;

    // --- Step 1: build a DISCOVER, parse it back, assert msg_type. ---
    let mut cli = DhcpClient::new(mac);
    let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
    let n_disc = match cli.start_discover(xid, &mut disc) {
        Ok(n) => n,
        Err(_) => panic!("DHCP start_discover returned Err"),
    };
    if n_disc < DHCP_FIXED_HEADER_LEN {
        panic!("DHCP DISCOVER undersized");
    }
    let dview = match DhcpImpl::parse_message(&disc[..n_disc]) {
        Ok(v) => v,
        Err(_) => panic!("DHCP parse_message rejected own DISCOVER"),
    };
    if dview.msg_type != dhcp_msg_type::DISCOVER {
        panic!("DHCP DISCOVER msg_type drift");
    }
    if dview.xid != xid {
        panic!("DHCP DISCOVER xid drift");
    }
    if dview.chaddr != mac {
        panic!("DHCP DISCOVER chaddr drift");
    }
    if cli.state() != DhcpClientState::Selecting {
        panic!("DHCP client state != Selecting after DISCOVER");
    }

    // Emit discover banner with the xid in hex.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"DHCP discover OK xid=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 8];
        hex_u32(xid, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- Step 2: build an OFFER fixture by hand, feed it into the client. ---
    let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
    let offer_len = build_dhcp_reply_fixture(
        &mut offer,
        dhcp_msg_type::OFFER,
        xid,
        mac,
        offered_ip,
        Some(server_id),
        Some(subnet),
        Some(router),
        Some(dns),
        Some(lease_secs),
    );
    let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
    let _n_req = match cli.on_offer(&offer[..offer_len], &mut req) {
        Ok(n) => n,
        Err(_) => panic!("DHCP on_offer rejected fixture"),
    };
    if cli.state() != DhcpClientState::Requesting {
        panic!("DHCP client state != Requesting after OFFER");
    }
    if cli.offered_ip() != offered_ip {
        panic!("DHCP captured offered_ip drift");
    }
    if cli.server_id() != server_id {
        panic!("DHCP captured server_id drift");
    }

    // --- Step 3: build an ACK fixture, bind. ---
    let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
    let ack_len = build_dhcp_reply_fixture(
        &mut ack,
        dhcp_msg_type::ACK,
        xid,
        mac,
        offered_ip,
        Some(server_id),
        Some(subnet),
        Some(router),
        Some(dns),
        Some(lease_secs),
    );
    let lease = match cli.on_ack(&ack[..ack_len], 1_700_000_000) {
        Ok(l) => l,
        Err(_) => panic!("DHCP on_ack rejected fixture"),
    };
    if cli.state() != DhcpClientState::Bound {
        panic!("DHCP client state != Bound after ACK");
    }
    if lease.assigned_ip != offered_ip {
        panic!("DHCP lease.assigned_ip drift");
    }
    if lease.lease_secs != lease_secs {
        panic!("DHCP lease.lease_secs drift");
    }
    if lease.server_id != server_id {
        panic!("DHCP lease.server_id drift");
    }
    if lease.gateway != router {
        panic!("DHCP lease.gateway drift");
    }
    if lease.dns != dns {
        panic!("DHCP lease.dns drift");
    }

    // Emit bound banner: `DHCP bound OK yiaddr=10.0.0.42 lease=86400`
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"DHCP bound OK yiaddr=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let octs = [
            lease.assigned_ip[0],
            lease.assigned_ip[1],
            lease.assigned_ip[2],
            lease.assigned_ip[3],
        ];
        for (i, o) in octs.iter().enumerate() {
            pos += dec_u64(*o as u64, &mut line[pos..]);
            if i < 3 {
                line[pos] = b'.';
                pos += 1;
            }
        }
        let mid = b" lease=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(lease.lease_secs as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Build a DHCP reply fixture in `buf`. Returns the byte length
/// written. Helper exists only for `banner_dhcp` — the per-option
/// matrix is hand-built so the banner doesn't depend on the impl's
/// reply-builder (the impl only emits client→server messages).
#[allow(clippy::too_many_arguments)]
pub(crate) fn build_dhcp_reply_fixture(
    buf: &mut [u8],
    msg_type: u8,
    xid: u32,
    mac: [u8; 6],
    yiaddr: [u8; 4],
    server_id: Option<[u8; 4]>,
    subnet_mask: Option<[u8; 4]>,
    router: Option<[u8; 4]>,
    dns: Option<[u8; 4]>,
    lease_secs: Option<u32>,
) -> usize {
    use cuttle_contracts::{
        dhcp_option, DHCP_FIXED_HEADER_LEN, DHCP_HLEN_ETHERNET, DHCP_HTYPE_ETHERNET,
        DHCP_MAGIC_COOKIE, DHCP_OP_BOOTREPLY,
    };
    // Zero the fixed header span.
    for b in &mut buf[..DHCP_FIXED_HEADER_LEN] {
        *b = 0;
    }
    buf[0] = DHCP_OP_BOOTREPLY;
    buf[1] = DHCP_HTYPE_ETHERNET;
    buf[2] = DHCP_HLEN_ETHERNET;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[16..20].copy_from_slice(&yiaddr);
    buf[28..34].copy_from_slice(&mac);
    buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut pos = DHCP_FIXED_HEADER_LEN;
    // opt53 msg_type
    buf[pos] = dhcp_option::MSG_TYPE;
    buf[pos + 1] = 1;
    buf[pos + 2] = msg_type;
    pos += 3;
    if let Some(sm) = subnet_mask {
        buf[pos] = dhcp_option::SUBNET_MASK;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&sm);
        pos += 6;
    }
    if let Some(rt) = router {
        buf[pos] = dhcp_option::ROUTER;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&rt);
        pos += 6;
    }
    if let Some(d) = dns {
        buf[pos] = dhcp_option::DNS;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&d);
        pos += 6;
    }
    if let Some(lt) = lease_secs {
        buf[pos] = dhcp_option::LEASE_TIME;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&lt.to_be_bytes());
        pos += 6;
    }
    if let Some(sid) = server_id {
        buf[pos] = dhcp_option::SERVER_ID;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&sid);
        pos += 6;
    }
    buf[pos] = dhcp_option::END;
    pos + 1
}

// ============================================================
// TASK-019: Panic-dump capture + symbol resolution. Build a
// deterministic CrashContext from the locked fixtures, package it
// via `PanicDumpImpl::dump_to_sink` into an in-kernel
// `MemorySectorSink`, verify the body CRC32-C matches
// `kf::CRASH_EXPECTED_CRC32C`, parse the header back, then resolve
// the first backtrace frame through a `StaticSymbolResolver` over a
// hand-built kernel-symbol fixture and assert (name, offset) match
// the locked expectations.
//
// Emits:
//   `CRASH_DUMP wrote 16384 bytes to lba=1024 crc=<hex8>\n`
//   `SYMBOL resolve OK kernel_main+0x42 (5 frames)\n`
//
// A kernel that perturbs the dump layout (sector offsets, CRC poly,
// header byte order) or the symbol-resolver binary search panics in
// this banner and the trailing `CUTTLE-TE HALT` is suppressed.
// ============================================================
// ============================================================
// TASK-048: VirtIO-net driver (VirtIO 1.0 §5.1). Drive a complete
// bring-up + roundtrip exercise against the in-process MemVirtioBus
// emulator:
//   - construct bus + driver, run init: asserts status sequence,
//     feature negotiation, MAC read, queue setup, RX pre-post.
//   - transmit a locked 60-byte fixture frame: asserts the captured
//     TX observation is byte-identical to the input.
//   - inject a synthetic incoming frame, deliver into the RX ring,
//     receive: asserts the returned bytes equal the injected frame
//     byte-for-byte and that the virtio_net header was stripped.
//
// Emits:
//   `VIRTIO_NET init OK mac=525400123456\n`
//   `VIRTIO_NET roundtrip OK tx=1 rx=1\n`
//
// A kernel that perturbs the descriptor wire layout, the bring-up
// status sequence, the feature-bit constants, or the TX/RX ring
// arithmetic panics here and these banners never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_net() {
    use cuttle_contracts::NetDevice;
    use target_enterprise::virtio_net::{MemVirtioBus, VirtioNet, MAX_FRAME_LEN};

    // The MemVirtioBus carries a 64 KiB shadow + observation/pending
    // FIFOs (~85 KiB total). That's too large for the kernel-main
    // stack (the bootloader allocates a modest stack and we're
    // already deep into the banner sequence). Park it in static
    // storage guarded by a spin::Mutex.
    static BUS_STORAGE: spin::Mutex<MemVirtioBus> = spin::Mutex::new(MemVirtioBus::new());
    let mut bus_guard = BUS_STORAGE.lock();
    let bus: &mut MemVirtioBus = &mut *bus_guard;
    let mut drv = VirtioNet::new();

    if drv.init(bus).is_err() {
        panic!("virtio-net init failed");
    }
    let mac = drv.mac_address();
    if mac != [0x52, 0x54, 0x00, 0x12, 0x34, 0x56] {
        panic!("virtio-net MAC drift");
    }
    if !drv.link_up() {
        panic!("virtio-net link_up drift (expected true after init on default bus)");
    }

    // Emit init banner: `VIRTIO_NET init OK mac=525400123456`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET init OK mac=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Build a locked 60-byte TX fixture: dst=broadcast, src=our MAC,
    // EtherType=0x0800, then a recognisable payload.
    let mut tx_frame = [0u8; 60];
    tx_frame[0] = 0xFF;
    tx_frame[1] = 0xFF;
    tx_frame[2] = 0xFF;
    tx_frame[3] = 0xFF;
    tx_frame[4] = 0xFF;
    tx_frame[5] = 0xFF;
    tx_frame[6] = mac[0];
    tx_frame[7] = mac[1];
    tx_frame[8] = mac[2];
    tx_frame[9] = mac[3];
    tx_frame[10] = mac[4];
    tx_frame[11] = mac[5];
    tx_frame[12] = 0x08; // EtherType high
    tx_frame[13] = 0x00; // EtherType low
    let mut i = 14;
    while i < 60 {
        tx_frame[i] = (i as u8).wrapping_mul(7).wrapping_add(11);
        i += 1;
    }

    if drv.transmit(bus, &tx_frame).is_err() {
        panic!("virtio-net transmit failed");
    }

    // Confirm the bus captured the TX frame byte-for-byte.
    let obs = bus.tx_observations();
    if obs.len() != 1 {
        panic!("virtio-net TX observation count drift");
    }
    if obs[0].len != 60 {
        panic!("virtio-net TX observation len drift");
    }
    let mut j = 0usize;
    while j < 60 {
        if obs[0].bytes[j] != tx_frame[j] {
            panic!("virtio-net TX byte drift");
        }
        j += 1;
    }

    // Inject an incoming frame. Use a different recognisable
    // payload so it cannot be confused with the TX bytes.
    let mut rx_inject = [0u8; 80];
    rx_inject[0] = mac[0];
    rx_inject[1] = mac[1];
    rx_inject[2] = mac[2];
    rx_inject[3] = mac[3];
    rx_inject[4] = mac[4];
    rx_inject[5] = mac[5];
    rx_inject[6] = 0xDE;
    rx_inject[7] = 0xAD;
    rx_inject[8] = 0xBE;
    rx_inject[9] = 0xEF;
    rx_inject[10] = 0xCA;
    rx_inject[11] = 0xFE;
    rx_inject[12] = 0x08;
    rx_inject[13] = 0x06; // EtherType = ARP — irrelevant to RX path.
    let mut k = 14usize;
    while k < 80 {
        rx_inject[k] = (k as u8) ^ 0x5A;
        k += 1;
    }

    if !bus.enqueue_rx(&rx_inject) {
        panic!("virtio-net RX enqueue refused");
    }
    if !bus.deliver_pending_rx() {
        panic!("virtio-net RX delivery refused");
    }

    let mut rx_out = [0u8; MAX_FRAME_LEN];
    let n = match drv.receive(bus, &mut rx_out) {
        Ok(n) => n,
        Err(_) => panic!("virtio-net receive failed"),
    };
    if n != 80 {
        panic!("virtio-net RX length drift");
    }
    let mut m = 0usize;
    while m < 80 {
        if rx_out[m] != rx_inject[m] {
            panic!("virtio-net RX byte drift");
        }
        m += 1;
    }

    // Emit roundtrip banner: `VIRTIO_NET roundtrip OK tx=1 rx=1`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET roundtrip OK tx=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.tx_count() as u64, &mut line[pos..]);
        let mid = b" rx=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(drv.rx_count() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}


/// Kernel SNTPv4 client banner (TASK-053).
///
/// Exercises the locked [`Sntp`] surface: builds a mode-3 client
/// request with `client_now = NTP_EPOCH + 100s`, asserts the wire
/// byte-0 carries (LI=0, VN=4, Mode=3) = 0x23, and asserts the
/// transmit-timestamp tail equals `100 << 32` in big-endian; then
/// parses a hand-built mode-4 reply with locked timestamps that yield
/// `offset_ns = 0`, `delay_ns = 1_000_000_000`, and asserts both
/// values byte-for-byte against the SNTP algorithm in RFC 4330 §5.
/// A morph that perturbs the bit-packing, the field offsets, or the
/// offset/delay arithmetic panics inside `banner_sntp` and the two
/// banners never appear.
///
/// Emits two banners:
/// - `SNTP request OK mode=3 vn=4 xmt=429496729600` — the transmit
///   timestamp raw value (decimal) recovered from the planted u64.
/// - `SNTP reply OK offset_ns=0 delay_ns=1000000000` — the locked
///   skew computed from the symmetric reply timestamps.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_sntp() {
    // ------------------------------------------------------------------
    // build_request — t1 = NTP_EPOCH + 100s -> raw = 100 << 32.
    // ------------------------------------------------------------------
    let t1 = NtpTimestamp::from_secs_frac(100, 0);
    let mut req = [0u8; SNTP_PACKET_LEN];
    let n = match <SntpImpl as Sntp>::build_request(t1, &mut req) {
        Ok(n) => n,
        Err(_) => panic!("sntp: build_request returned Err"),
    };
    if n != SNTP_PACKET_LEN {
        panic!("sntp: build_request length drift");
    }
    // Byte 0: LI=0, VN=4, Mode=3 -> 0x23.
    if req[0] != 0x23 {
        panic!("sntp: byte0 LI/VN/Mode drift");
    }
    // Bytes 1..40 must be zero in a stock client request.
    let mut k = 1usize;
    while k < 40 {
        if req[k] != 0 {
            panic!("sntp: non-zero filler byte");
        }
        k += 1;
    }
    // Bytes 40..48: big-endian of 100 << 32 = 0x0000_0064_0000_0000.
    let expected_xmt = [0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00];
    let mut j = 0usize;
    while j < 8 {
        if req[40 + j] != expected_xmt[j] {
            panic!("sntp: transmit timestamp wire drift");
        }
        j += 1;
    }

    // First banner: xmt raw is t1.raw = 100 << 32 = 429_496_729_600.
    {
        let mut line = [0u8; 96];
        let prefix = b"SNTP request OK mode=3 vn=4 xmt=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(t1.raw, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ------------------------------------------------------------------
    // parse_reply + compute_offset_delay — symmetric goldens.
    //   t1 = 100s, t2 = 100.5s, t3 = 100.5s, t4 = 101s.
    //   offset = ((t2-t1) + (t3-t4)) / 2 = (500e6 + -500e6)/2 = 0.
    //   delay  = (t4-t1) - (t3-t2)       = 1e9 - 0 = 1_000_000_000.
    // ------------------------------------------------------------------
    let t2 = NtpTimestamp::from_secs_frac(100, 0x8000_0000); // 100.5s
    let t3 = NtpTimestamp::from_secs_frac(100, 0x8000_0000); // 100.5s
    let t4 = NtpTimestamp::from_secs_frac(101, 0);

    // Hand-build a mode-4 reply: byte 0 = LI=0, VN=4, Mode=4 = 0x24.
    let mut reply_buf = [0u8; SNTP_PACKET_LEN];
    reply_buf[0] = (0u8 << 6) | ((SNTP_VERSION & 0x7) << 3) | (SNTP_MODE_SERVER & 0x7);
    reply_buf[1] = 3; // stratum
    reply_buf[2] = 6; // poll
    reply_buf[3] = 0xEC; // precision = -20
    // Reference identifier "GPS\0" — stratum 1 primary-reference style.
    reply_buf[12] = b'G';
    reply_buf[13] = b'P';
    reply_buf[14] = b'S';
    reply_buf[15] = 0;
    // Reference + origin + receive + transmit timestamps (big-endian).
    let plant = |buf: &mut [u8; SNTP_PACKET_LEN], at: usize, v: u64| {
        buf[at] = (v >> 56) as u8;
        buf[at + 1] = (v >> 48) as u8;
        buf[at + 2] = (v >> 40) as u8;
        buf[at + 3] = (v >> 32) as u8;
        buf[at + 4] = (v >> 24) as u8;
        buf[at + 5] = (v >> 16) as u8;
        buf[at + 6] = (v >> 8) as u8;
        buf[at + 7] = v as u8;
    };
    plant(&mut reply_buf, 16, NtpTimestamp::from_secs_frac(99, 0).raw); // ref
    plant(&mut reply_buf, 24, t1.raw); // origin
    plant(&mut reply_buf, 32, t2.raw); // receive
    plant(&mut reply_buf, 40, t3.raw); // transmit

    let reply: NtpReply = match <SntpImpl as Sntp>::parse_reply(&reply_buf) {
        Ok(r) => r,
        Err(_) => panic!("sntp: parse_reply returned Err"),
    };
    if reply.stratum != 3 {
        panic!("sntp: reply stratum drift");
    }
    if reply.version != SNTP_VERSION {
        panic!("sntp: reply version drift");
    }
    if reply.leap_indicator != 0 {
        panic!("sntp: reply LI drift");
    }
    if reply.origin_timestamp != t1 {
        panic!("sntp: reply origin drift");
    }
    if reply.receive_timestamp != t2 {
        panic!("sntp: reply receive drift");
    }
    if reply.transmit_timestamp != t3 {
        panic!("sntp: reply transmit drift");
    }
    if reply.ref_id != [b'G', b'P', b'S', 0] {
        panic!("sntp: reply ref_id drift");
    }

    let skew = <SntpImpl as Sntp>::compute_offset_delay(&reply, t4);
    if skew.offset_ns != 0 {
        panic!("sntp: offset_ns drift");
    }
    if skew.delay_ns != 1_000_000_000 {
        panic!("sntp: delay_ns drift");
    }

    // Second banner — offset_ns is exactly zero, delay_ns is exactly
    // 1_000_000_000. dec_u64 handles the unsigned case; the offset is
    // nonneg here so no sign handling is needed.
    {
        let mut line = [0u8; 96];
        let prefix = b"SNTP reply OK offset_ns=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        let off = skew.offset_ns;
        if off < 0 {
            line[pos] = b'-';
            pos += 1;
            pos += dec_u64((-(off as i128)) as u64, &mut line[pos..]);
        } else {
            pos += dec_u64(off as u64, &mut line[pos..]);
        }
        let mid = b" delay_ns=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(skew.delay_ns as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Silence the import-unused warning in case the morph rewrites the
    // call site to avoid the constant.
    let _ = SNTP_MODE_CLIENT;
}

/// Intel e1000 NIC driver banner — TASK-056.
///
/// Runs the locked round-trip:
///
/// 1. Construct a `MemMmioBus` pre-seeded with the locked
///    `BANNER_MAC` in EEPROM words 0/1/2 and STATUS bits encoding
///    `LU + FD + Up @ 1 Gbit`.
/// 2. Drive `E1000Impl::init` through the bring-up sequence (reset
///    → poll(!RST) → EEPROM MAC read → CTRL.SLU → program RX/TX
///    rings → RCTL.EN + TCTL.EN).
/// 3. Transmit a locked 64-byte Ethernet frame (broadcast dest,
///    `BANNER_MAC` source, EtherType=0x0800, deterministic payload).
///    The bus captures the frame from the TX descriptor on TDT
///    advance — byte-for-byte equality is asserted before continuing.
/// 4. Inject the same frame on the RX side and consume it via
///    `E1000Impl::receive`. Bytes recovered must equal the frame
///    bytes.
///
/// On any drift — descriptor byte packing, EEPROM word index order,
/// MAC read endianness, CTRL.RST poll path, link-state decode,
/// ring wrap modulus, RDT/TDT lag arithmetic — one of the asserts
/// inside `run_banner_round_trip` panics and the QEMU log emits a
/// PANIC line instead of the expected two `E1000 ...` banners.
///
/// A morph that perturbs these internals while leaving the
/// `EthernetController` contract methods, the `MmioRegBus` trait,
/// the descriptor STATUS/CMD constants, or the register-offset
/// constants intact will preserve the banner; a morph that perturbs
/// the wire surface will fail the in-order sweep on this banner.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_e1000() {
    // The driver embeds two 16-slot ring arrays of 1518-byte buffers
    // (~48 KiB) plus the `MemMmioBus` (128 KiB shadow + capture log
    // — ~180 KiB total) — well over the kernel-main stack budget.
    // Park BOTH in static storage initialised through `const fn`
    // constructors guarded by spin::Mutex so no large value ever lives on the stack.
    use target_enterprise::e1000::{build_banner_frame, E1000Impl, MemMmioBus};
    use cuttle_contracts::{EthernetController, LinkState};

    static DRIVER_STORAGE: spin::Mutex<E1000Impl> = spin::Mutex::new(E1000Impl::new());
    static BUS_STORAGE: spin::Mutex<MemMmioBus> = spin::Mutex::new(MemMmioBus::zeroed());

    let mut driver_guard = DRIVER_STORAGE.lock();
    let driver: &mut E1000Impl = &mut *driver_guard;
    let mut bus_guard = BUS_STORAGE.lock();
    let bus: &mut MemMmioBus = &mut *bus_guard;

    // Seed the EEPROM with the locked banner MAC. STATUS was set by
    // `MemMmioBus::zeroed` to LU + FD + Up @ 1G.
    bus.set_eeprom_mac(BANNER_MAC);

    let mut mac = [0u8; 6];
    if driver.init(bus, &mut mac).is_err() {
        panic!("e1000: init failed");
    }
    if mac != BANNER_MAC {
        panic!("e1000: MAC drift");
    }
    if driver.link_state() != LinkState::Up1000 {
        panic!("e1000: link state drift (expected Up1000)");
    }

    // Transmit a 64-byte fixture frame; the bus drains the TX
    // descriptor on TDT advance and captures the bytes.
    let frame = build_banner_frame();
    if driver.transmit(bus, &frame).is_err() {
        panic!("e1000: transmit failed");
    }
    let caps = bus.tx_captures();
    if caps.len() != 1 || caps[0].len != 64 {
        panic!("e1000: TX capture count or length drift");
    }
    {
        let mut i = 0usize;
        while i < 64 {
            if caps[0].bytes[i] != frame[i] {
                panic!("e1000: TX capture byte drift");
            }
            i += 1;
        }
    }

    // Inject the same frame back on the RX side and round-trip it
    // through `receive`.
    if bus.inject_rx_frame(&frame).is_err() {
        panic!("e1000: RX inject failed");
    }
    let mut rx_buf = [0u8; 64];
    let rx_len = match driver.receive(bus, &mut rx_buf) {
        Ok(Some(n)) => n,
        _ => panic!("e1000: receive failed"),
    };
    if rx_len != 64 {
        panic!("e1000: RX length drift");
    }
    {
        let mut i = 0usize;
        while i < rx_len {
            if rx_buf[i] != frame[i] {
                panic!("e1000: RX byte drift");
            }
            i += 1;
        }
    }

    // Emit banner 1: init OK with the recovered MAC + link speed.
    {
        let mut line = [0u8; 80];
        let prefix = b"E1000 init OK mac=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        let mid = b" link=up_1000";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Emit banner 2: frame round-trip OK with byte counts.
    {
        let mut line = [0u8; 80];
        let prefix = b"E1000 frame OK tx_bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(64, &mut line[pos..]);
        let mid = b" rx_bytes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(rx_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TFTP / TASK-058: RFC 1350 client-side wire codec. The kernel
// builds an RRQ for `/cuttle-boot.img` in octet mode, asserts
// the byte-exact request; parses a locked ACK(1) reply, recovers
// block=1; parses a locked DATA(2, "0123456789") packet, recovers
// block=2 + 10-byte payload byte-for-byte. Emits:
//   `TFTP rrq OK len=33 mode=octet\n`
//   `TFTP data OK block=2 bytes=10\n`
//
// A morph that perturbs the opcode big-endian encoding, the
// NUL-terminated string discipline, or the block-number byte
// order panics inside `banner_tftp` and these banners never
// appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_tftp() {
    use cuttle_contracts::{Tftp, TftpMode, TftpPacket};
    use target_enterprise::tftp::TftpImpl;

    // --- build RRQ ---
    let mut rrq_buf = [0u8; 64];
    let rrq_n =
        match TftpImpl::build_rrq(b"/cuttle-boot.img", TftpMode::Octet, &mut rrq_buf) {
            Ok(n) => n,
            Err(_) => panic!("TFTP banner: build_rrq failed"),
        };
    // Expected: opcode(0x0001) + "/cuttle-boot.img"(17) + NUL +
    // "octet"(5) + NUL = 2 + 17 + 1 + 5 + 1 = 26.
    // Wait, /cuttle-boot.img is 17 chars. So 2+17+1+5+1 = 26.
    // The banner text uses dec_u64 so we just need consistency.
    // Locked expected bytes:
    let expected_rrq: &[u8] = &[
        0x00, 0x01, // opcode = RRQ
        b'/', b'c', b'u', b't', b't', b'l', b'e', b'-', b'b', b'o', b'o', b't', b'.',
        b'i', b'm', b'g', // filename (17 bytes)
        0x00, // NUL
        b'o', b'c', b't', b'e', b't', // mode
        0x00, // NUL
    ];
    if rrq_n != expected_rrq.len() {
        panic!("TFTP banner: RRQ length drift");
    }
    assert_eq_bytes(&rrq_buf[..rrq_n], expected_rrq, "TFTP RRQ");

    // Emit RRQ banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TFTP rrq OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rrq_n as u64, &mut line[pos..]);
        let mid = b" mode=octet";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- parse locked ACK(1) reply ---
    let ack_bytes: &[u8] = &[0x00, 0x04, 0x00, 0x01];
    match TftpImpl::parse_packet(ack_bytes) {
        Ok(TftpPacket::Ack { block }) => {
            if block != 1 {
                panic!("TFTP banner: ACK block drift");
            }
        }
        Ok(_) => panic!("TFTP banner: ACK parsed as wrong variant"),
        Err(_) => panic!("TFTP banner: ACK parse failed"),
    }

    // --- parse locked DATA(2, "0123456789") packet ---
    let data_bytes: &[u8] = &[
        0x00, 0x03, // opcode = DATA
        0x00, 0x02, // block = 2
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
    ];
    let (rec_block, rec_payload_len) = match TftpImpl::parse_packet(data_bytes) {
        Ok(TftpPacket::Data { block, payload }) => {
            // Byte-equality on the payload.
            if payload.len() != 10 {
                panic!("TFTP banner: DATA payload length drift");
            }
            let expected_payload = b"0123456789";
            let mut i = 0usize;
            while i < payload.len() {
                if payload[i] != expected_payload[i] {
                    panic!("TFTP banner: DATA payload byte drift");
                }
                i += 1;
            }
            (block, payload.len())
        }
        _ => panic!("TFTP banner: DATA parse failed"),
    };
    if rec_block != 2 {
        panic!("TFTP banner: DATA block drift");
    }

    // Emit DATA banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TFTP data OK block=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rec_block as u64, &mut line[pos..]);
        let mid = b" bytes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(rec_payload_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-086 DNS name
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_dns_name() {
    use cuttle_contracts::{DnsName, DNS_MAX_LABELS};
    use target_enterprise::dns_name::DnsNameImpl;

    let mut wire = [0u8; 32];
    let n = DnsNameImpl::encode(&[b"a", b"b"], &mut wire).unwrap();
    let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
    let mut lens = [0usize; DNS_MAX_LABELS];
    let (c, _) = DnsNameImpl::decode(&wire[..n], 0, &mut labs, &mut lens).unwrap();
    if c != 2 {
        panic!("DNS name banner: labels");
    }
    serial_write_bytes(b"DNS name OK labels=2\n");
}
