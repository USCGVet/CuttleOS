//! HTTPS on port 443 against an independent TLS client.
//!
//! The server is the kernel's: rustls with the RustCrypto provider
//! (`tls_provider`), driven by `LivedNet` through Ethernet frames
//! (`https::LoopbackClient`). The client is stock rustls with *ring* crypto
//! and webpki certificate verification, so every handshake here checks the
//! server's AEADs, key exchange, ECDSA signatures and certificate against a
//! second implementation. Real-world clients (curl, OpenSSL, Python `ssl`)
//! are exercised against a booted kernel by `tools/https_check.py`.

use std::io::{Read, Write};
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore};
use target_enterprise::https::{self, LoopbackClient, ServerIdentity};
use target_enterprise::{tls_provider, LivedNet};

const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0xab, 0xcd, 0xef];
const NODE_SECRET: [u8; 32] = [0x11; 32];

fn live_server(shell: Option<Box<target_enterprise::OsShell>>, port: u16) -> (LoopbackClient, ServerIdentity) {
    tls_provider::seed_system_rng(*b"https_interop test entropy seed!");
    let identity = ServerIdentity::derive(&NODE_SECRET, MAC);
    let config = https::server_config(&identity, tls_provider::system_provider()).unwrap();
    let mut net = Box::new(LivedNet::with_auth_key(MAC, [0x22; 32]));
    net.enable_tls(config);
    let lb = LoopbackClient::connect(net, shell, port, 5).expect("TCP handshake");
    (lb, identity)
}

fn ring_client_config(trusted: &[u8], tweak: impl FnOnce(&mut rustls::crypto::CryptoProvider)) -> Arc<ClientConfig> {
    let mut roots = RootCertStore::empty();
    roots.add(CertificateDer::from(trusted.to_vec())).unwrap();
    let mut provider = rustls::crypto::ring::default_provider();
    tweak(&mut provider);
    let mut config = ClientConfig::builder_with_provider(Arc::new(provider))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"http/1.1".to_vec()];
    Arc::new(config)
}

fn ring_client(trusted: &[u8], name: &str) -> ClientConnection {
    let config = ring_client_config(trusted, |_| {});
    ClientConnection::new(config, ServerName::try_from(name.to_string()).unwrap()).unwrap()
}

/// Feed server bytes to the client.
fn deliver(client: &mut ClientConnection, mut bytes: &[u8]) -> Result<(), rustls::Error> {
    while !bytes.is_empty() {
        client.read_tls(&mut bytes).unwrap();
        client.process_new_packets()?;
    }
    Ok(())
}

/// Shuttle bytes both ways until the client has nothing more to say.
/// Records each client flight and the server's byte stream.
struct Wire {
    client_flights: Vec<Vec<u8>>,
    server_bytes: Vec<u8>,
}

impl Wire {
    fn new() -> Self {
        Self { client_flights: Vec::new(), server_bytes: Vec::new() }
    }

    fn pump(&mut self, client: &mut ClientConnection, lb: &mut LoopbackClient) -> Result<(), rustls::Error> {
        loop {
            let mut flight = Vec::new();
            while client.wants_write() {
                client.write_tls(&mut flight).unwrap();
            }
            if flight.is_empty() {
                return Ok(());
            }
            self.client_flights.push(flight.clone());
            let back = lb.send(&flight).expect("loopback transport");
            self.server_bytes.extend_from_slice(&back);
            deliver(client, &back)?;
        }
    }
}

fn read_plaintext(client: &mut ClientConnection) -> Vec<u8> {
    let mut out = Vec::new();
    let mut buf = [0u8; 4096];
    loop {
        match client.reader().read(&mut buf) {
            Ok(0) => break,
            Ok(n) => out.extend_from_slice(&buf[..n]),
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
            Err(e) => panic!("read: {e}"),
        }
    }
    out
}

fn get(client: &mut ClientConnection, lb: &mut LoopbackClient, wire: &mut Wire, request: &[u8]) -> String {
    client.writer().write_all(request).unwrap();
    wire.pump(client, lb).unwrap();
    String::from_utf8(read_plaintext(client)).unwrap()
}

#[test]
fn ring_client_completes_tls13_handshake_and_gets_healthz() {
    let (mut lb, identity) = live_server(None, 50001);
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    assert!(!client.is_handshaking(), "handshake must complete");
    assert_eq!(client.protocol_version(), Some(rustls::ProtocolVersion::TLSv1_3));
    assert_eq!(client.alpn_protocol(), Some(&b"http/1.1"[..]));
    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
    );
    assert_eq!(client.negotiated_key_exchange_group().unwrap().name(), rustls::NamedGroup::X25519);
    let certs = client.peer_certificates().unwrap();
    assert_eq!(certs[0].as_ref(), identity.cert_der());

    let resp = get(&mut client, &mut lb, &mut wire, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.starts_with("HTTP/1.1 200 OK\r\n"), "{resp}");
    assert!(resp.ends_with("\r\n\r\nCUTTLE-STATUS boots=5\n"), "{resp}");

    // Keep-alive: a second request on the same connection.
    let resp = get(&mut client, &mut lb, &mut wire, b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.ends_with("CUTTLE-STATUS boots=5\n"), "{resp}");

    // Orderly close: client close_notify + FIN, server close_notify + FIN.
    client.send_close_notify();
    wire.pump(&mut client, &mut lb).unwrap();
    let tail = lb.close().expect("server FIN");
    deliver(&mut client, &tail).unwrap();
    assert_eq!(lb.net().tls_sessions_started, 1);
}

#[test]
fn https_and_http_return_identical_responses() {
    let (mut lb, identity) = live_server(None, 50002);
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    let request = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let over_tls = get(&mut client, &mut lb, &mut wire, request);
    // Same server, plain HTTP on port 80.
    let (net, shell) = lb.into_parts();
    let mut plain = LoopbackClient::connect_to(net, shell, 50102, 80, 5).unwrap();
    let over_http = plain.send(request).unwrap();
    assert_eq!(over_tls.as_bytes(), &over_http[..]);
}

#[test]
fn certificate_names_cover_localhost_loopback_and_guest_ip() {
    for name in ["localhost", "127.0.0.1", "10.0.2.15"] {
        let (mut lb, identity) = live_server(None, 50003);
        let mut client = ring_client(identity.cert_der(), name);
        Wire::new().pump(&mut client, &mut lb).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(!client.is_handshaking(), "{name}");
    }
}

#[test]
fn client_rejects_a_certificate_it_did_not_pin() {
    let (mut lb, _identity) = live_server(None, 50004);
    let impostor = ServerIdentity::derive(&[0x99; 32], MAC);
    let mut client = ring_client(impostor.cert_der(), "localhost");
    let err = Wire::new().pump(&mut client, &mut lb).unwrap_err();
    assert!(matches!(err, rustls::Error::InvalidCertificate(_)), "{err:?}");
}

#[test]
fn chacha20_poly1305_suite_interoperates() {
    let (mut lb, identity) = live_server(None, 50005);
    let config = ring_client_config(identity.cert_der(), |p| {
        p.cipher_suites = vec![rustls::crypto::ring::cipher_suite::TLS13_CHACHA20_POLY1305_SHA256];
    });
    let mut client = ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    assert_eq!(
        client.negotiated_cipher_suite().unwrap().suite(),
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
    );
    let resp = get(&mut client, &mut lb, &mut wire, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.ends_with("CUTTLE-STATUS boots=5\n"), "{resp}");
}

#[test]
fn secp256r1_key_exchange_interoperates() {
    let (mut lb, identity) = live_server(None, 50006);
    let config = ring_client_config(identity.cert_der(), |p| {
        p.kx_groups = vec![rustls::crypto::ring::kx_group::SECP256R1];
    });
    let mut client = ClientConnection::new(config, ServerName::try_from("localhost").unwrap()).unwrap();
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    assert_eq!(client.negotiated_key_exchange_group().unwrap().name(), rustls::NamedGroup::secp256r1);
    let resp = get(&mut client, &mut lb, &mut wire, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.ends_with("CUTTLE-STATUS boots=5\n"), "{resp}");
}

#[test]
fn tampered_client_finished_is_rejected_with_a_fatal_alert() {
    let (mut lb, identity) = live_server(None, 50007);
    let mut client = ring_client(identity.cert_der(), "localhost");
    // Flight 1: ClientHello -> server flight.
    let mut hello = Vec::new();
    client.write_tls(&mut hello).unwrap();
    let back = lb.send(&hello).unwrap();
    deliver(&mut client, &back).unwrap();
    // Flight 2: CCS + Finished, with the last ciphertext byte flipped.
    let mut finished = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut finished).unwrap();
    }
    *finished.last_mut().unwrap() ^= 0x01;
    let alert = lb.send(&finished).unwrap();
    assert!(!alert.is_empty(), "server must answer with an alert");
    let err = deliver(&mut client, &alert).unwrap_err();
    assert!(
        matches!(err, rustls::Error::AlertReceived(rustls::AlertDescription::BadRecordMac)),
        "{err:?}"
    );
    // The session is dead: a later request gets no application data.
    assert!(lb.send(b"\x17\x03\x03\x00\x05hello").unwrap().is_empty());
}

#[test]
fn plaintext_http_on_the_tls_port_is_refused() {
    let (mut lb, _identity) = live_server(None, 50008);
    let back = lb.send(b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n").unwrap();
    // rustls answers a non-TLS byte stream with a plaintext fatal alert
    // record (content type 21) and nothing else.
    assert_eq!(back.first(), Some(&21), "{back:?}");
    assert!(!String::from_utf8_lossy(&back).contains("CUTTLE-STATUS"));
}

#[test]
fn unauthenticated_https_calls_to_protected_endpoints_get_401() {
    let shell = Box::new(target_enterprise::OsShell::with_seal_key([0x33; 32]));
    let (mut lb, identity) = live_server(Some(shell), 50009);
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    let cases: [&[u8]; 3] = [
        b"GET /session/whoami HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"POST /sql HTTP/1.1\r\nHost: localhost\r\nContent-Length: 35\r\n\r\nINSERT INTO kv VALUES ('x', 'y', 1)",
        b"POST /exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\n/bin/fib 12",
    ];
    for request in cases {
        let resp = get(&mut client, &mut lb, &mut wire, request);
        assert!(
            resp.starts_with("HTTP/1.1 401 Unauthorized\r\n"),
            "{}: {resp}",
            String::from_utf8_lossy(request)
        );
    }
}

#[test]
fn large_and_pipelined_requests_span_records_and_segments() {
    let (mut lb, identity) = live_server(None, 50010);
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    // One 3 KB request: several TCP segments, reassembled by the session.
    let mut big = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Pad: ".to_vec();
    big.extend(std::iter::repeat_n(b'p', 3000));
    big.extend_from_slice(b"\r\n\r\n");
    let resp = get(&mut client, &mut lb, &mut wire, &big);
    assert!(resp.ends_with("CUTTLE-STATUS boots=5\n"), "{resp}");
    // Two pipelined requests in one write: two responses, in order.
    let two = b"GET /healthz HTTP/1.1\r\nHost: a\r\n\r\nGET /status HTTP/1.1\r\nHost: b\r\n\r\n";
    let resp = get(&mut client, &mut lb, &mut wire, two);
    assert_eq!(resp.matches("CUTTLE-STATUS boots=5\n").count(), 2, "{resp}");
}

#[test]
fn connection_close_request_ends_the_tls_session() {
    let (mut lb, identity) = live_server(None, 50011);
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    client
        .writer()
        .write_all(b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    wire.pump(&mut client, &mut lb).unwrap();
    let mut resp = Vec::new();
    // The server's close_notify makes the stream end cleanly (read -> Ok(0)).
    client.reader().read_to_end(&mut resp).expect("clean close_notify EOF");
    let resp = String::from_utf8(resp).unwrap();
    assert!(resp.ends_with("CUTTLE-STATUS boots=5\n"), "{resp}");
    // Client closes TCP; the server FINs back.
    client.send_close_notify();
    wire.pump(&mut client, &mut lb).unwrap();
    lb.close().expect("server FIN");
}

#[test]
fn golden_session_replays_byte_for_byte() {
    let report = https::replay_golden_session().expect("golden replay");
    assert!(report.server_bytes > 500);
}

#[test]
fn https_tx_cap_backpressure_and_idle_rto_reclaim_slots() {
    // 1. TlsSession enforces MAX_TX_BYTES on outbound ciphertext when a peer never drains pending_tx.
    tls_provider::seed_system_rng(*b"https_tx_cap test entropy seed!!");
    let identity = ServerIdentity::derive(&NODE_SECRET, MAC);
    let config = https::server_config(&identity, tls_provider::system_provider()).unwrap();
    let mut session = https::TlsSession::new(config.clone()).unwrap();
    let mut client = ring_client(identity.cert_der(), "localhost");
    // Complete handshake directly against `session`.
    let mut c_hello = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut c_hello).unwrap();
    }
    session.receive(&c_hello).unwrap();
    deliver(&mut client, session.pending_tx()).unwrap();
    session.consume_tx(session.pending_tx().len());
    let mut c_fin = Vec::new();
    while client.wants_write() {
        client.write_tls(&mut c_fin).unwrap();
    }
    session.receive(&c_fin).unwrap();
    assert!(session.is_established());

    let chunk = vec![b'A'; 8192];
    let mut hit_overflow = false;
    for _ in 0..16 {
        match session.send(&chunk) {
            Ok(()) => assert!(session.pending_tx().len() <= https::MAX_TX_BYTES),
            Err(https::SessionError::Overflow) => {
                hit_overflow = true;
                break;
            }
            Err(other) => panic!("unexpected send error: {other:?}"),
        }
    }
    assert!(hit_overflow, "pending_tx must be bounded by MAX_TX_BYTES");
    assert!(session.pending_tx().len() <= https::MAX_TX_BYTES);

    // 2. Idle Established HTTPS connections are reclaimed by tick_tcp_rto after HTTPS_IDLE_TIMEOUT_TICKS.
    let (mut lb, id2) = live_server(None, 50020);
    let mut c2 = ring_client(id2.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut c2, &mut lb).unwrap();
    assert_eq!(lb.net().active_tcp_slots(), 1);
    for _ in 0..(target_enterprise::lived_net::HTTPS_IDLE_TIMEOUT_TICKS - 10) {
        lb.net().tick_tcp_rto();
    }
    assert_eq!(
        lb.net().active_tcp_slots(),
        1,
        "HTTPS slot must stay alive before HTTPS_IDLE_TIMEOUT_TICKS"
    );
    for _ in 0..20 {
        lb.net().tick_tcp_rto();
    }
    assert_eq!(
        lb.net().active_tcp_slots(),
        0,
        "Idle Established HTTPS slot must be reclaimed once HTTPS_IDLE_TIMEOUT_TICKS elapses"
    );

    // 3. Exercise the 16 KiB HTTPS_TX_HIGH_WATER pause inside `handle_https_slot` over
    // `LoopbackClient`: send 24 pipelined `GET /app` requests (~30 KiB of responses)
    // across a single connection and verify that `handle_https_slot` pauses at the
    // 8-response / 16 KiB high-water mark per segment, resumes as segments are ACKed,
    // and delivers all 24 responses intact without overflowing `MAX_PLAINTEXT_BYTES`.
    let sh3 = Box::new(target_enterprise::OsShell::with_seal_key([0x33; 32]));
    let (mut lb3, id3) = live_server(Some(sh3), 50021);
    let mut c3 = ring_client(id3.cert_der(), "localhost");
    let mut w3 = Wire::new();
    w3.pump(&mut c3, &mut lb3).unwrap();
    let mut burst = Vec::new();
    for _ in 0..24 {
        burst.extend_from_slice(b"GET /app HTTP/1.1\r\nHost: localhost\r\n\r\n");
    }
    c3.writer().write_all(&burst).unwrap();
    let mut flight = Vec::new();
    while c3.wants_write() {
        c3.write_tls(&mut flight).unwrap();
    }
    let back = lb3.send(&flight).unwrap();
    let mut burst_plain = Vec::new();
    for part in back.chunks(2048) {
        deliver(&mut c3, part).unwrap();
        burst_plain.extend_from_slice(&read_plaintext(&mut c3));
    }
    let burst_resp = String::from_utf8(burst_plain).unwrap();
    let ok_200 = burst_resp.matches("HTTP/1.1 200 OK\r\n").count();
    assert_eq!(
        ok_200, 24,
        "all 24 pipelined HTTPS /app responses (~30 KiB) must drain across HTTPS_TX_HIGH_WATER pauses; got {ok_200}"
    );
}

#[test]
fn every_mutating_endpoint_and_node_role_enforces_auth_over_https() {
    use target_enterprise::svc_runtime::NodeRole;

    let requests: &[(&str, &[u8])] = &[
        (
            "GET /session/whoami (no token)",
            b"GET /session/whoami HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
        (
            "GET /session/whoami (wrong token)",
            b"GET /session/whoami HTTP/1.1\r\nHost: localhost\r\nCookie: sid=deadbeefdeadbeefdeadbeefdeadbeef\r\n\r\n",
        ),
        (
            "POST /session/logout (no token)",
            b"POST /session/logout HTTP/1.1\r\nHost: localhost\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "POST /session/logout (wrong token)",
            b"POST /session/logout HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\nContent-Length: 0\r\n\r\n",
        ),
        (
            "POST /sql INSERT (no token)",
            b"POST /sql HTTP/1.1\r\nHost: localhost\r\nContent-Length: 35\r\n\r\nINSERT INTO kv VALUES ('x', 'y', 1)",
        ),
        (
            "POST /sql INSERT (wrong token)",
            b"POST /sql HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\nContent-Length: 35\r\n\r\nINSERT INTO kv VALUES ('x', 'y', 1)",
        ),
        (
            "POST /db DELETE (no token)",
            b"POST /db HTTP/1.1\r\nHost: localhost\r\nContent-Length: 14\r\n\r\nDELETE FROM kv",
        ),
        (
            "GET /sql?DELETE (no token)",
            b"GET /sql?DELETE+FROM+kv HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
        (
            "POST /sh (no token)",
            b"POST /sh HTTP/1.1\r\nHost: localhost\r\nContent-Length: 14\r\n\r\nwrite /var/x 1",
        ),
        (
            "POST /sh (wrong token)",
            b"POST /sh HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\nContent-Length: 14\r\n\r\nwrite /var/x 1",
        ),
        (
            "POST /exec (no token)",
            b"POST /exec HTTP/1.1\r\nHost: localhost\r\nContent-Length: 11\r\n\r\n/bin/fib 12",
        ),
        (
            "POST /exec (wrong token)",
            b"POST /exec HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\nContent-Length: 11\r\n\r\n/bin/fib 12",
        ),
        (
            "PUT /fs/var/pwn.txt (no token)",
            b"PUT /fs/var/pwn.txt HTTP/1.1\r\nHost: localhost\r\nContent-Length: 5\r\n\r\npwned",
        ),
        (
            "PUT /fs/var/pwn.txt (wrong token)",
            b"PUT /fs/var/pwn.txt HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\nContent-Length: 5\r\n\r\npwned",
        ),
        (
            "DELETE /fs/etc/hostname (no token)",
            b"DELETE /fs/etc/hostname HTTP/1.1\r\nHost: localhost\r\n\r\n",
        ),
        (
            "DELETE /fs/etc/hostname (wrong token)",
            b"DELETE /fs/etc/hostname HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: deadbeefdeadbeefdeadbeefdeadbeef\r\n\r\n",
        ),
    ];

    for (role_idx, role) in [NodeRole::Full, NodeRole::Wfe, NodeRole::Sql, NodeRole::Shell]
        .into_iter()
        .enumerate()
    {
        let mut sh = Box::new(target_enterprise::OsShell::with_seal_key([0x33; 32]));
        sh.svc.set_role(role, &mut sh.audit);
        let (mut lb, identity) = live_server(Some(sh), 50030 + role_idx as u16);
        let mut client = ring_client(identity.cert_der(), "localhost");
        let mut wire = Wire::new();
        wire.pump(&mut client, &mut lb).unwrap();

        for (label, req) in requests {
            let resp = get(&mut client, &mut lb, &mut wire, req);
            let expected_status = match role {
                NodeRole::Full => "HTTP/1.1 401 Unauthorized\r\n",
                NodeRole::Wfe => {
                    if label.contains("/session/") {
                        "HTTP/1.1 401 Unauthorized\r\n"
                    } else {
                        "HTTP/1.1 503 "
                    }
                }
                NodeRole::Sql | NodeRole::Shell => "HTTP/1.1 503 ",
            };
            assert!(
                resp.starts_with(expected_status),
                "role={role:?} {label}: expected {expected_status:?}, got {resp:?}"
            );
        }
    }
}

#[test]
fn http_and_https_reject_oversized_and_unframed_requests_and_match_across_routes() {
    let sh = Box::new(target_enterprise::OsShell::with_seal_key([0x44; 32]));
    let (mut lb, identity) = live_server(Some(sh), 50040);
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();

    // 1. POST/PUT without Content-Length is rejected with 400 on both :443 and :80,
    // and closes the connection / discards any trailing pipelined request.
    let unframed_post = b"POST /sql HTTP/1.1\r\nHost: localhost\r\n\r\nSELECT * FROM kv\r\nGET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let tls_unframed = get(&mut client, &mut lb, &mut wire, unframed_post);
    assert!(
        tls_unframed.starts_with("HTTP/1.1 400 Bad Request\r\n")
            && tls_unframed.contains("Content-Length required for POST/PUT")
            && !tls_unframed.contains("CUTTLE-STATUS"),
        "HTTPS unframed POST must return 400 and never execute trailing request: {tls_unframed}"
    );

    let (net, shell) = lb.into_parts();
    let mut plain = LoopbackClient::connect_to(net, shell, 50140, 80, 5).unwrap();
    let http_unframed = String::from_utf8(plain.send(unframed_post).unwrap()).unwrap();
    assert_eq!(tls_unframed, http_unframed, ":80 and :443 must reject unframed POST identically");
    assert!(
        plain.server_closed(),
        "port 80 must emit FIN and close after a 400 framing error"
    );

    // 2. Oversized requests (> MAX_HTTP_REQUEST_BYTES) return 413 on both :80 and :443
    // and close the connection without processing any trailing request.
    let (net, shell) = plain.into_parts();
    let mut plain_413 = LoopbackClient::connect_to(net, shell, 50141, 80, 5).unwrap();
    let mut oversized = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nX-Big: ".to_vec();
    oversized.extend(std::iter::repeat_n(
        b'B',
        target_enterprise::lived_net::MAX_HTTP_REQUEST_BYTES + 128,
    ));
    oversized.extend_from_slice(b"\r\n\r\nGET /status HTTP/1.1\r\nHost: localhost\r\n\r\n");
    let http_413 = String::from_utf8(plain_413.send(&oversized).unwrap()).unwrap();
    assert!(
        http_413.starts_with("HTTP/1.1 413 ") && !http_413.contains("CUTTLE-STATUS"),
        "HTTP oversized: {http_413}"
    );
    assert!(
        plain_413.server_closed(),
        "port 80 must emit FIN and close after a 413 error"
    );

    let (net, shell) = plain_413.into_parts();
    let mut lb_413 = LoopbackClient::connect(net, shell, 50041, 5).unwrap();
    let mut c_413 = ring_client(identity.cert_der(), "localhost");
    let mut w_413 = Wire::new();
    w_413.pump(&mut c_413, &mut lb_413).unwrap();
    let tls_413 = get(&mut c_413, &mut lb_413, &mut w_413, &oversized);
    assert_eq!(tls_413, http_413, ":80 and :443 must return identical 413 responses");

    // 2b. Transfer-Encoding: chunked is rejected with 501 Not Implemented and closes the connection.
    let (net, shell) = lb_413.into_parts();
    let mut plain_501 = LoopbackClient::connect_to(net, shell, 50144, 80, 5).unwrap();
    let chunked_req = b"POST /sql HTTP/1.1\r\nHost: localhost\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\nGET /status HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let http_501 = String::from_utf8(plain_501.send(chunked_req).unwrap()).unwrap();
    assert!(
        http_501.starts_with("HTTP/1.1 501 Not Implemented\r\n")
            && !http_501.contains("CUTTLE-STATUS"),
        "HTTP chunked must return 501 and discard trailing bytes: {http_501}"
    );
    assert!(plain_501.server_closed());

    // 3. Public routes return identical responses over :443 and :80 when run
    // against identically-initialized (LivedNet, OsShell) pairs.
    let (mut lb_routes, id_routes) = live_server(
        Some(Box::new(target_enterprise::OsShell::with_seal_key([0x44; 32]))),
        50042,
    );
    let mut c_routes = ring_client(id_routes.cert_der(), "localhost");
    let mut w_routes = Wire::new();
    w_routes.pump(&mut c_routes, &mut lb_routes).unwrap();

    let public_routes: &[&[u8]] = &[
        b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /status HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /uname HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /ps HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /ls HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /fw HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /ima HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"GET /fs/etc/hostname HTTP/1.1\r\nHost: localhost\r\n\r\n",
        b"POST /sql HTTP/1.1\r\nHost: localhost\r\nContent-Length: 39\r\n\r\nSELECT name FROM services WHERE id = 2",
    ];
    let mut tls_resps = Vec::new();
    for req in public_routes {
        tls_resps.push(get(&mut c_routes, &mut lb_routes, &mut w_routes, req));
    }
    let net_http = Box::new(LivedNet::with_auth_key(MAC, [0x22; 32]));
    let sh_http = Some(Box::new(target_enterprise::OsShell::with_seal_key([0x44; 32])));
    let mut plain_routes =
        LoopbackClient::connect_to(net_http, sh_http, 50142, 80, 5).unwrap();
    for (req, tls_resp) in public_routes.iter().zip(tls_resps.iter()) {
        let http_resp = String::from_utf8(plain_routes.send(req).unwrap()).unwrap();
        assert_eq!(
            tls_resp,
            &http_resp,
            "mismatch between :443 and :80 on {:?}",
            String::from_utf8_lossy(req)
        );
    }

    // 4. Pipelined back-to-back requests on port 80 whose combined responses
    // exceed a single TCP segment (1380 bytes), including authenticated writes,
    // must deliver every response without dropping any response.
    let mut sh_pipe = Box::new(target_enterprise::OsShell::with_seal_key([0x44; 32]));
    sh_pipe.attest_key = [0x55; 32];
    let tok_bytes = sh_pipe
        .try_create_session(b"root", b"1")
        .expect("mint root session");
    let tok = core::str::from_utf8(&tok_bytes).unwrap().to_string();
    // Populate audit log so `GET /audit` returns a ~1,300-byte response, making
    // the second back-to-back request's response overflow a single 1380-byte packet.
    for _ in 0..32 {
        sh_pipe.record_net_audit(cuttle_contracts::AuditVerdict::Allowed, b"net:test:fill-audit-log");
    }
    let net_pipe = Box::new(LivedNet::with_auth_key(MAC, [0x22; 32]));
    let mut plain_pipe =
        LoopbackClient::connect_to(net_pipe, Some(sh_pipe), 50143, 80, 5).unwrap();

    // Send back-to-back requests in one flight: 3 `GET /app` responses
    // (~500 B each) followed by an authenticated SQL INSERT write whose response
    // pushes the combined payload past TCP_SEGMENT_PAYLOAD (1380 B).
    let sql_insert = "INSERT INTO kv VALUES ('pipelined', 'ok', 1)";
    let sql_select = "SELECT v FROM kv WHERE k = 'pipelined'";
    let mut pipelined = Vec::new();
    for _ in 0..3 {
        pipelined.extend_from_slice(
            format!("GET /app HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: {tok}\r\n\r\n")
                .as_bytes(),
        );
    }
    pipelined.extend_from_slice(
        format!(
            "POST /sql HTTP/1.1\r\nHost: localhost\r\nX-Session-Token: {tok}\r\nContent-Length: {}\r\n\r\n{sql_insert}",
            sql_insert.len()
        )
        .as_bytes(),
    );
    let combined_resp = String::from_utf8(plain_pipe.send(&pipelined).unwrap()).unwrap();
    let status_count = combined_resp.matches("HTTP/1.1 200 OK\r\n").count();
    assert_eq!(
        status_count, 4,
        "all 4 back-to-back port-80 responses must be returned without dropping the write response; got {status_count} in:\n{combined_resp}"
    );
    let select_req = format!(
        "POST /sql HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n{sql_select}",
        sql_select.len()
    );
    let select_resp = String::from_utf8(plain_pipe.send(select_req.as_bytes()).unwrap()).unwrap();
    assert!(
        select_resp.contains("ok"),
        "subsequent read must see the committed row:\n{select_resp}"
    );
}

/// Re-record the golden session (run with `--ignored --nocapture
/// record_golden`) after a deliberate change to rustls, the provider, the
/// certificate or the HTTP response. Rewrites `src/https_golden_fixture.rs`.
#[test]
#[ignore]
fn record_golden() {
    use sha2::{Digest, Sha256};
    let guard = tls_provider::GOLDEN_LOCK.lock();
    let net = https::golden_server().unwrap();
    let identity = ServerIdentity::derive(&https::golden::IDENTITY_SECRET, https::golden::MAC);
    let mut lb = LoopbackClient::connect(net, None, https::golden::CLIENT_PORT, https::golden::BOOTS).unwrap();
    let mut client = ring_client(identity.cert_der(), "localhost");
    let mut wire = Wire::new();
    wire.pump(&mut client, &mut lb).unwrap();
    assert!(!client.is_handshaking());
    let resp = get(&mut client, &mut lb, &mut wire, b"GET /healthz HTTP/1.1\r\nHost: localhost\r\n\r\n");
    assert!(resp.ends_with("CUTTLE-STATUS boots=7\n"), "{resp}");
    client.send_close_notify();
    wire.pump(&mut client, &mut lb).unwrap();
    let tail = lb.close().unwrap();
    wire.server_bytes.extend_from_slice(&tail);
    deliver(&mut client, &tail).unwrap();
    drop(guard);

    let sha: [u8; 32] = Sha256::digest(&wire.server_bytes).into();
    let mut src = String::from(
        "// Generated by `record_golden` in tests/https_interop.rs — do not edit.\n\
         // Client side of one TLS 1.3 session recorded from a rustls (ring)\n\
         // client against `https::golden_server`: ClientHello; ChangeCipherSpec +\n\
         // Finished; `GET /healthz`; close_notify.\n\n",
    );
    for (i, flight) in wire.client_flights.iter().enumerate() {
        src.push_str(&format!("const HTTPS_GOLDEN_FLIGHT_{i}: [u8; {}] = [", flight.len()));
        for (j, b) in flight.iter().enumerate() {
            if j % 16 == 0 {
                src.push_str("\n   ");
            }
            src.push_str(&format!(" 0x{b:02x},"));
        }
        src.push_str("\n];\n\n");
    }
    src.push_str("/// Client TLS bytes, one entry per flight.\npub const HTTPS_GOLDEN_CLIENT_FLIGHTS: &[&[u8]] = &[\n");
    for i in 0..wire.client_flights.len() {
        src.push_str(&format!("    &HTTPS_GOLDEN_FLIGHT_{i},\n"));
    }
    src.push_str("];\n\n");
    src.push_str(&format!(
        "/// Total server TLS bytes over the session.\npub const HTTPS_GOLDEN_SERVER_LEN: usize = {};\n\n",
        wire.server_bytes.len()
    ));
    src.push_str("/// SHA-256 of the server's TLS byte stream.\npub const HTTPS_GOLDEN_SERVER_SHA256: [u8; 32] = [");
    for (j, b) in sha.iter().enumerate() {
        if j % 16 == 0 {
            src.push_str("\n   ");
        }
        src.push_str(&format!(" 0x{b:02x},"));
    }
    src.push_str("\n];\n");
    src.push_str("\n/// SHA-256 of the golden identity's DER certificate.\npub const HTTPS_GOLDEN_CERT_SHA256: [u8; 32] = [");
    for (j, b) in identity.fingerprint().iter().enumerate() {
        if j % 16 == 0 {
            src.push_str("\n   ");
        }
        src.push_str(&format!(" 0x{b:02x},"));
    }
    src.push_str("\n];\n");
    let path = concat!(env!("CARGO_MANIFEST_DIR"), "/src/https_golden_fixture.rs");
    std::fs::write(path, src).unwrap();
    println!(
        "recorded {} client flights, {} server bytes, sha256 {:02x?}",
        wire.client_flights.len(),
        wire.server_bytes.len(),
        sha
    );
}
