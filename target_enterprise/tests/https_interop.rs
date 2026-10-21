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
