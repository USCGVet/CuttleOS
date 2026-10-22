//! HTTPS on port 443: TLS 1.3 by rustls, cryptography by
//! [`crate::tls_provider`].
//!
//! - [`ServerIdentity`]: the node's P-256 key, derived from a 32-byte secret,
//!   and a self-signed X.509 v3 certificate for it (SAN `localhost`,
//!   `127.0.0.1`, `10.0.2.15`). Clients pin the certificate (or its SHA-256
//!   fingerprint, which the kernel prints at boot).
//! - [`server_config`]: a TLS 1.3-only rustls `ServerConfig` — no client
//!   authentication, no session tickets, no resumption, no 0-RTT.
//! - [`TlsSession`]: one rustls `UnbufferedServerConnection` per TCP slot,
//!   fed the slot's inbound bytes and drained into outbound TCP segments by
//!   [`crate::lived_net::LivedNet`].
//! - [`LoopbackClient`] and [`replay_golden_session`]: drive a `LivedNet`
//!   with Ethernet frames, so the boot self-test can replay a recorded TLS
//!   session through the real network path and compare every server byte.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;

use cuttle_contracts::{tcp_flags, Tcp, IP_PROTO_TCP};
use rustls::pki_types::{alg_id, CertificateDer};
use rustls::server::{NoServerSessionStorage, ServerConfig, UnbufferedServerConnection};
use rustls::sign::{public_key_to_spki, CertifiedKey, SingleCertAndKey};
use rustls::unbuffered::{
    ConnectionState, EncodeError, EncryptError, InsufficientSizeError, UnbufferedStatus,
};
use sha2::{Digest, Sha256};

use crate::kernel_fixtures as kf;
use crate::lived_net::{LivedNet, ReplySet, GUEST_IP, HTTPS_PORT};
use crate::tcp::TcpImpl;
use crate::tls::hmac_sha256;
use crate::tls_provider::{EcdsaP256SigningKey, KernelTime};

// ------------------------------------------------------------------
// Identity and certificate
// ------------------------------------------------------------------

/// The node's TLS identity: a P-256 key and its self-signed certificate.
pub struct ServerIdentity {
    key: p256::ecdsa::SigningKey,
    cert_der: Vec<u8>,
    fingerprint: [u8; 32],
}

impl ServerIdentity {
    /// Derive the identity from a 32-byte secret (the device key on a
    /// provisioned node). The same secret always yields the same key and
    /// certificate, so a pinned certificate survives reboots and morph cycles.
    pub fn derive(secret: &[u8; 32], mac: [u8; 6]) -> Self {
        let key = derive_p256_key(secret);
        let cert_der = build_self_signed_cert(&key, mac);
        let mut fingerprint = [0u8; 32];
        fingerprint.copy_from_slice(&Sha256::digest(&cert_der));
        Self { key, cert_der, fingerprint }
    }

    /// DER certificate.
    pub fn cert_der(&self) -> &[u8] {
        &self.cert_der
    }

    /// SHA-256 over the DER certificate — what
    /// `openssl x509 -noout -fingerprint -sha256` prints.
    pub fn fingerprint(&self) -> [u8; 32] {
        self.fingerprint
    }

    /// Uncompressed SEC1 public key (65 bytes).
    pub fn public_key_sec1(&self) -> [u8; 65] {
        EcdsaP256SigningKey::new(self.key.clone()).public_key_sec1()
    }
}

/// Derive the 32-byte secret behind a node's [`ServerIdentity`]:
/// - When `provisioned_master` is `Some(master)`, computes
///   `HMAC-SHA256(master, "cuttle-tls-identity-v1:" || mac)` and returns
///   `(secret, true)` so the certificate is stable across reboots and morphs.
/// - When `provisioned_master` is `None` (unprovisioned boot), draws 32 bytes
///   directly from the seeded `rng` ([`crate::tls_provider::SYSTEM_RNG`]),
///   mixes `mac`, and returns `(secret, false)` so the certificate key is
///   never derived from the unprovisioned master-key fallback.
pub fn derive_tls_identity_secret(
    provisioned_master: Option<&[u8; 32]>,
    mac: [u8; 6],
    rng: &crate::tls_provider::KernelRng,
) -> Result<([u8; 32], bool), rustls::crypto::GetRandomFailed> {
    use rustls::crypto::SecureRandom as _;
    use zeroize::Zeroize as _;
    let mut out = [0u8; 32];
    if let Some(master) = provisioned_master {
        let mut msg = [0u8; 29];
        msg[..23].copy_from_slice(b"cuttle-tls-identity-v1:");
        msg[23..].copy_from_slice(&mac);
        hmac_sha256(master, &msg, &mut out);
        msg.zeroize();
        Ok((out, true))
    } else {
        let mut random = [0u8; 32];
        rng.fill(&mut random)?;
        let mut msg = [0u8; 39];
        msg[..33].copy_from_slice(b"cuttle-tls-ephemeral-identity-v1:");
        msg[33..].copy_from_slice(&mac);
        hmac_sha256(&random, &msg, &mut out);
        random.zeroize();
        msg.zeroize();
        Ok((out, false))
    }
}

/// Domain-separated HMAC expansion of `secret` into a valid P-256 scalar
/// (rejection sampling; a 32-byte HMAC output is out of range with
/// probability ~2^-32, so the loop almost never runs twice).
fn derive_p256_key(secret: &[u8; 32]) -> p256::ecdsa::SigningKey {
    let mut msg = *b"cuttle-tls-identity-v1:\x00";
    let mut counter = 0u8;
    loop {
        msg[msg.len() - 1] = counter;
        let mut candidate = [0u8; 32];
        hmac_sha256(secret, &msg, &mut candidate);
        let key = p256::ecdsa::SigningKey::from_slice(&candidate);
        zeroize::Zeroize::zeroize(&mut candidate);
        if let Ok(key) = key {
            return key;
        }
        counter = counter.wrapping_add(1);
    }
}

// DER object identifiers (content bytes).
const OID_ECDSA_WITH_SHA256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02];
const OID_COMMON_NAME: &[u8] = &[0x55, 0x04, 0x03];
const OID_SUBJECT_KEY_ID: &[u8] = &[0x55, 0x1d, 0x0e];
const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
const OID_AUTHORITY_KEY_ID: &[u8] = &[0x55, 0x1d, 0x23];
const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
const OID_SERVER_AUTH: &[u8] = &[0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01];

/// Append one DER TLV. Panics if `content.len() > 0xffff` so a 2-byte length
/// field can never silently truncate oversized content.
fn der(tag: u8, content: &[u8], out: &mut Vec<u8>) {
    assert!(content.len() <= 0xffff, "DER TLV content exceeds 65535 bytes");
    out.push(tag);
    let len = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else if len <= 0xff {
        out.extend_from_slice(&[0x81, len as u8]);
    } else {
        out.extend_from_slice(&[0x82, (len >> 8) as u8, len as u8]);
    }
    out.extend_from_slice(content);
}

fn der_vec(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(content.len() + 4);
    der(tag, content, &mut out);
    out
}

fn extension(oid: &[u8], value: &[u8]) -> Vec<u8> {
    let mut body = der_vec(0x06, oid);
    der(0x04, value, &mut body);
    der_vec(0x30, &body)
}

/// Self-signed X.509 v3 certificate, ecdsa-with-SHA256, `CN=cuttle-<mac>`,
/// valid 2025-01-01 through 2099-12-31, SAN `localhost` / `127.0.0.1` /
/// `10.0.2.15`, EKU serverAuth, SKID = AKID. No basicConstraints and no
/// keyUsage: it is an end-entity certificate that clients pin directly.
fn build_self_signed_cert(key: &p256::ecdsa::SigningKey, mac: [u8; 6]) -> Vec<u8> {
    let signer = EcdsaP256SigningKey::new(key.clone());
    let public = signer.public_key_sec1();
    let spki = public_key_to_spki(&alg_id::ECDSA_P256, public);
    let key_hash = Sha256::digest(public);
    let key_id = &key_hash[..20];

    // Serial: 16 bytes from the key hash, forced positive and non-zero-led.
    let mut serial = [0u8; 16];
    serial.copy_from_slice(&key_hash[12..28]);
    serial[0] = (serial[0] & 0x7f) | 0x40;

    let sig_alg = der_vec(0x30, &der_vec(0x06, OID_ECDSA_WITH_SHA256));

    let mut cn = *b"cuttle-000000000000";
    const HEX: &[u8; 16] = b"0123456789abcdef";
    for (i, b) in mac.iter().enumerate() {
        cn[7 + 2 * i] = HEX[(b >> 4) as usize];
        cn[8 + 2 * i] = HEX[(b & 0xf) as usize];
    }
    let mut atv = der_vec(0x06, OID_COMMON_NAME);
    der(0x0c, &cn, &mut atv);
    let name = der_vec(0x30, &der_vec(0x31, &der_vec(0x30, &atv)));

    let mut validity = der_vec(0x17, b"250101000000Z");
    der(0x18, b"20991231235959Z", &mut validity);

    let mut san = der_vec(0x82, b"localhost");
    der(0x87, &[127, 0, 0, 1], &mut san);
    der(0x87, &GUEST_IP, &mut san);

    let mut exts = extension(OID_SUBJECT_KEY_ID, &der_vec(0x04, key_id));
    exts.extend_from_slice(&extension(OID_AUTHORITY_KEY_ID, &der_vec(0x30, &der_vec(0x80, key_id))));
    exts.extend_from_slice(&extension(OID_SUBJECT_ALT_NAME, &der_vec(0x30, &san)));
    exts.extend_from_slice(&extension(
        OID_EXT_KEY_USAGE,
        &der_vec(0x30, &der_vec(0x06, OID_SERVER_AUTH)),
    ));

    let mut tbs_body = der_vec(0xa0, &der_vec(0x02, &[2])); // version v3
    der(0x02, &serial, &mut tbs_body);
    tbs_body.extend_from_slice(&sig_alg);
    tbs_body.extend_from_slice(&name); // issuer
    der(0x30, &validity, &mut tbs_body);
    tbs_body.extend_from_slice(&name); // subject
    tbs_body.extend_from_slice(spki.as_ref());
    der(0xa3, &der_vec(0x30, &exts), &mut tbs_body);
    let tbs = der_vec(0x30, &tbs_body);

    let mut sig_bits = alloc::vec![0u8]; // BIT STRING: no unused bits
    sig_bits.extend_from_slice(&signer.sign_der(&tbs));

    let mut cert_body = tbs;
    cert_body.extend_from_slice(&sig_alg);
    der(0x03, &sig_bits, &mut cert_body);
    der_vec(0x30, &cert_body)
}

// ------------------------------------------------------------------
// Server configuration
// ------------------------------------------------------------------

/// TLS 1.3-only server configuration for `identity`, using `provider`
/// ([`crate::tls_provider::system_provider`] for live traffic). ALPN offers
/// `http/1.1`; tickets, session storage and early data are all off.
pub fn server_config(
    identity: &ServerIdentity,
    provider: rustls::crypto::CryptoProvider,
) -> Result<Arc<ServerConfig>, rustls::Error> {
    let signing_key = Arc::new(EcdsaP256SigningKey::new(identity.key.clone()));
    let certified = CertifiedKey::new(alloc::vec![CertificateDer::from(identity.cert_der.clone())], signing_key);
    let mut config = ServerConfig::builder_with_details(Arc::new(provider), Arc::new(KernelTime))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(SingleCertAndKey::from(certified)));
    config.alpn_protocols = alloc::vec![b"http/1.1".to_vec()];
    config.send_tls13_tickets = 0;
    config.session_storage = Arc::new(NoServerSessionStorage {});
    config.max_early_data_size = 0;
    Ok(Arc::new(config))
}

// ------------------------------------------------------------------
// Per-connection session
// ------------------------------------------------------------------

/// Largest buffered ciphertext: one maximal TLS record (16 KiB + 256 + 5)
/// plus slack. A peer that sends more without completing a record is cut off.
pub const MAX_RX_BYTES: usize = 18 * 1024;
/// Largest buffered decrypted request data (HTTP request head + body).
pub const MAX_PLAINTEXT_BYTES: usize = 16 * 1024;
/// Largest buffered outbound ciphertext queued in [`TlsSession::pending_tx`]
/// before a stalled peer triggers [`SessionError::Overflow`].
pub const MAX_TX_BYTES: usize = 64 * 1024;
/// Upper bound on state-machine steps per call (each step makes progress).
const MAX_STEPS: usize = 64;

/// Why a [`TlsSession`] stopped accepting input.
#[derive(Debug, Clone, PartialEq)]
pub enum SessionError {
    /// rustls rejected the peer (bad record, bad handshake, failed MAC…);
    /// any alert it generated has been queued for transmission.
    Tls(rustls::Error),
    /// The peer sent more than [`MAX_RX_BYTES`] / [`MAX_PLAINTEXT_BYTES`], or
    /// outbound ciphertext exceeded [`MAX_TX_BYTES`].
    Overflow,
    /// Application data was offered before the handshake completed.
    NotReady,
    /// The session already failed; input is ignored.
    Failed,
}

/// What to do in the next `WriteTraffic` state.
enum Outbound<'a> {
    Data(&'a [u8]),
    CloseNotify,
}

/// A TLS 1.3 server connection plus its byte queues. LivedNet feeds it TCP
/// payloads with [`receive`](Self::receive), reads decrypted request bytes from
/// [`plaintext`](Self::plaintext), answers with [`send`](Self::send), and
/// transmits [`pending_tx`](Self::pending_tx).
pub struct TlsSession {
    conn: UnbufferedServerConnection,
    rx: Vec<u8>,
    tx: Vec<u8>,
    plaintext: Vec<u8>,
    handshake_done: bool,
    peer_closed: bool,
    close_sent: bool,
    failed: bool,
}

impl TlsSession {
    /// A fresh server connection.
    pub fn new(config: Arc<ServerConfig>) -> Result<Self, rustls::Error> {
        Ok(Self {
            conn: UnbufferedServerConnection::new(config)?,
            rx: Vec::new(),
            tx: Vec::new(),
            plaintext: Vec::new(),
            handshake_done: false,
            peer_closed: false,
            close_sent: false,
            failed: false,
        })
    }

    /// Feed ciphertext received from the peer and advance the handshake /
    /// decrypt whatever records are complete.
    pub fn receive(&mut self, data: &[u8]) -> Result<(), SessionError> {
        if self.failed {
            return Err(SessionError::Failed);
        }
        if self.rx.len() + data.len() > MAX_RX_BYTES {
            self.failed = true;
            return Err(SessionError::Overflow);
        }
        self.rx.extend_from_slice(data);
        self.pump(None)
    }

    /// Encrypt `data` as application data. Fails with
    /// [`SessionError::NotReady`] before the handshake completes.
    pub fn send(&mut self, data: &[u8]) -> Result<(), SessionError> {
        if self.failed {
            return Err(SessionError::Failed);
        }
        self.pump(Some(Outbound::Data(data)))
    }

    /// Queue a `close_notify` alert (once; a no-op before the handshake
    /// completes or after a failure).
    pub fn close(&mut self) {
        if !self.close_sent && !self.failed && self.handshake_done {
            let _ = self.pump(Some(Outbound::CloseNotify));
        }
    }

    /// Decrypted application bytes not yet consumed by the caller.
    pub fn plaintext(&mut self) -> &mut Vec<u8> {
        &mut self.plaintext
    }

    /// Ciphertext waiting to be transmitted.
    pub fn pending_tx(&self) -> &[u8] {
        &self.tx
    }

    /// Drop the first `n` transmitted bytes from the queue.
    pub fn consume_tx(&mut self, n: usize) {
        self.tx.drain(..n.min(self.tx.len()));
    }

    /// The handshake has completed (application data may flow).
    pub fn is_established(&self) -> bool {
        self.handshake_done
    }

    /// The peer sent `close_notify`.
    pub fn peer_closed(&self) -> bool {
        self.peer_closed
    }

    /// We queued our `close_notify`.
    pub fn close_sent(&self) -> bool {
        self.close_sent
    }

    /// The session hit a fatal error.
    pub fn is_failed(&self) -> bool {
        self.failed
    }

    fn pump(&mut self, mut outbound: Option<Outbound<'_>>) -> Result<(), SessionError> {
        let mut steps = 0usize;
        while steps < MAX_STEPS {
            steps += 1;
            let UnbufferedStatus { mut discard, state } = self.conn.process_tls_records(&mut self.rx);
            let state = match state {
                Ok(state) => state,
                Err(err) => {
                    self.rx.drain(..discard.min(self.rx.len()));
                    self.failed = true;
                    self.flush_alerts();
                    return Err(SessionError::Tls(err));
                }
            };
            let mut stop = false;
            let mut overflow = false;
            let mut plaintext_overflow = false;
            let mut tls_error = None;
            match state {
                ConnectionState::ReadTraffic(mut traffic) => {
                    self.handshake_done = true;
                    while let Some(record) = traffic.next_record() {
                        match record {
                            Ok(record) => {
                                discard += record.discard;
                                if self.plaintext.len() + record.payload.len() > MAX_PLAINTEXT_BYTES {
                                    plaintext_overflow = true;
                                    break;
                                }
                                self.plaintext.extend_from_slice(record.payload);
                            }
                            Err(err) => {
                                tls_error = Some(err);
                                break;
                            }
                        }
                    }
                }
                ConnectionState::EncodeTlsData(mut encoder) => {
                    let start = self.tx.len();
                    let mut room = 4096usize;
                    loop {
                        if start.saturating_add(room) > MAX_TX_BYTES {
                            self.tx.truncate(start);
                            overflow = true;
                            break;
                        }
                        self.tx.resize(start + room, 0);
                        match encoder.encode(&mut self.tx[start..]) {
                            Ok(n) => {
                                self.tx.truncate(start + n);
                                break;
                            }
                            Err(EncodeError::InsufficientSize(InsufficientSizeError { required_size })) => {
                                room = required_size;
                            }
                            Err(_) => {
                                self.tx.truncate(start);
                                break;
                            }
                        }
                    }
                }
                ConnectionState::TransmitTlsData(transmit) => {
                    // The bytes are already in `tx`; LivedNet sends them.
                    transmit.done();
                }
                ConnectionState::BlockedHandshake => stop = true,
                ConnectionState::WriteTraffic(mut writer) => {
                    self.handshake_done = true;
                    match outbound.take() {
                        Some(Outbound::Data(data)) => {
                            if self.tx.len().saturating_add(data.len()).saturating_add(32) > MAX_TX_BYTES {
                                overflow = true;
                            } else if let Err(err) = encrypt_into(&mut self.tx, |buf| writer.encrypt(data, buf)) {
                                if matches!(err, rustls::Error::General(_)) {
                                    overflow = true;
                                } else {
                                    tls_error = Some(err);
                                }
                            }
                        }
                        Some(Outbound::CloseNotify) => {
                            if encrypt_into(&mut self.tx, |buf| writer.queue_close_notify(buf)).is_ok() {
                                self.close_sent = true;
                            }
                        }
                        None => {}
                    }
                    stop = true;
                }
                ConnectionState::PeerClosed => self.peer_closed = true,
                ConnectionState::Closed => stop = true,
                // Early data is disabled (`max_early_data_size = 0`); any other
                // state is a future rustls addition we do not drive.
                _ => stop = true,
            }
            self.rx.drain(..discard.min(self.rx.len()));
            if plaintext_overflow {
                self.plaintext.clear();
                return Err(SessionError::Overflow);
            }
            if overflow {
                self.failed = true;
                return Err(SessionError::Overflow);
            }
            if let Some(err) = tls_error {
                self.failed = true;
                self.flush_alerts();
                return Err(SessionError::Tls(err));
            }
            if stop {
                break;
            }
        }
        match outbound {
            Some(_) => Err(SessionError::NotReady),
            None => Ok(()),
        }
    }

    /// After a fatal error rustls queues an alert; encode it into `tx`.
    fn flush_alerts(&mut self) {
        let mut empty = [0u8; 0];
        for _ in 0..8 {
            let status = self.conn.process_tls_records(&mut empty);
            match status.state {
                Ok(ConnectionState::EncodeTlsData(mut encoder)) => {
                    let start = self.tx.len();
                    self.tx.resize(start + 64, 0);
                    match encoder.encode(&mut self.tx[start..]) {
                        Ok(n) => self.tx.truncate(start + n),
                        Err(_) => self.tx.truncate(start),
                    }
                }
                Ok(ConnectionState::TransmitTlsData(transmit)) => transmit.done(),
                _ => break,
            }
        }
    }
}

/// Run `encrypt` against the tail of `tx`, growing it until the record fits.
fn encrypt_into(
    tx: &mut Vec<u8>,
    mut encrypt: impl FnMut(&mut [u8]) -> Result<usize, EncryptError>,
) -> Result<(), rustls::Error> {
    let start = tx.len();
    let mut room = 2048usize;
    loop {
        if start.saturating_add(room) > MAX_TX_BYTES {
            tx.truncate(start);
            return Err(rustls::Error::General("outbound TLS buffer exceeds MAX_TX_BYTES".into()));
        }
        tx.resize(start + room, 0);
        match encrypt(&mut tx[start..]) {
            Ok(n) => {
                tx.truncate(start + n);
                return Ok(());
            }
            Err(EncryptError::InsufficientSize(InsufficientSizeError { required_size })) => {
                room = required_size;
            }
            Err(_) => {
                tx.truncate(start);
                return Err(rustls::Error::EncryptError);
            }
        }
    }
}

// ------------------------------------------------------------------
// Loopback client harness and the golden-transcript replay
// ------------------------------------------------------------------

/// Peer (client) addresses used by [`LoopbackClient`]: QEMU slirp's gateway.
pub const LOOPBACK_PEER_IP: [u8; 4] = [10, 0, 2, 2];
const LOOPBACK_PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
/// Largest TCP payload the harness sends per segment (well under the MTU).
const LOOPBACK_SEGMENT: usize = 1200;

/// A minimal TCP client that talks to a [`LivedNet`] port 443 through
/// Ethernet frames. Used by the boot self-test and host tests; it exercises
/// the same `handle_frame` path a real NIC frame takes.
pub struct LoopbackClient {
    net: Box<LivedNet>,
    shell: Option<Box<crate::shell::OsShell>>,
    replies: Box<ReplySet>,
    mac: [u8; 6],
    port: u16,
    dst_port: u16,
    seq: u32,
    server_next: u32,
    boots: u64,
    server_fin: bool,
}

impl LoopbackClient {
    /// Open a TCP connection from `port` to port 443 (SYN, SYN-ACK, ACK). With a
    /// `shell`, frames go through `handle_frame_with_shell` (the kernel's
    /// path, including authenticated endpoints); without, `handle_frame`.
    pub fn connect(
        net: Box<LivedNet>,
        shell: Option<Box<crate::shell::OsShell>>,
        port: u16,
        boots: u64,
    ) -> Result<Self, &'static str> {
        Self::connect_to(net, shell, port, HTTPS_PORT, boots)
    }

    /// [`connect`](Self::connect) to an arbitrary `dst_port` (e.g. 80, to
    /// compare plain HTTP with HTTPS).
    pub fn connect_to(
        net: Box<LivedNet>,
        shell: Option<Box<crate::shell::OsShell>>,
        port: u16,
        dst_port: u16,
        boots: u64,
    ) -> Result<Self, &'static str> {
        let mac = net.mac;
        let mut client = Self {
            net,
            shell,
            replies: Box::new(ReplySet::new()),
            mac,
            port,
            dst_port,
            seq: 0x6000_0000 ^ ((port as u32) << 8),
            server_next: 0,
            boots,
            server_fin: false,
        };
        let isn = client.seq;
        client.transmit(isn, 0, tcp_flags::SYN, b"")?;
        let synack = client.replies.get(0).ok_or("loopback: no SYN-ACK")?;
        let seg = TcpImpl::parse_segment(&synack[34..], GUEST_IP, LOOPBACK_PEER_IP)
            .map_err(|_| "loopback: bad SYN-ACK")?;
        if seg.flags != (tcp_flags::SYN | tcp_flags::ACK) || seg.ack != isn.wrapping_add(1) {
            return Err("loopback: unexpected SYN-ACK");
        }
        client.seq = isn.wrapping_add(1);
        client.server_next = seg.seq.wrapping_add(1);
        let (seq, ack) = (client.seq, client.server_next);
        client.transmit(seq, ack, tcp_flags::ACK, b"")?;
        Ok(client)
    }

    /// Send `data` and return every byte the server sends back before it
    /// goes quiet (acknowledging each segment so queued data keeps flowing).
    pub fn send(&mut self, data: &[u8]) -> Result<Vec<u8>, &'static str> {
        let mut received = Vec::new();
        for chunk in data.chunks(LOOPBACK_SEGMENT) {
            let (seq, ack) = (self.seq, self.server_next);
            self.transmit(seq, ack, tcp_flags::ACK | tcp_flags::PSH, chunk)?;
            self.seq = self.seq.wrapping_add(chunk.len() as u32);
            self.collect(&mut received)?;
        }
        Ok(received)
    }

    /// Send FIN; return the server's remaining bytes (e.g. its `close_notify`)
    /// and require its FIN.
    pub fn close(&mut self) -> Result<Vec<u8>, &'static str> {
        let mut received = Vec::new();
        let (seq, ack) = (self.seq, self.server_next);
        self.transmit(seq, ack, tcp_flags::ACK | tcp_flags::FIN, b"")?;
        self.seq = self.seq.wrapping_add(1);
        self.collect(&mut received)?;
        if !self.server_fin {
            return Err("loopback: server did not send FIN");
        }
        Ok(received)
    }

    /// The server under test.
    pub fn net(&mut self) -> &mut LivedNet {
        &mut self.net
    }

    /// Hand the server (and shell) back, e.g. to open another connection.
    pub fn into_parts(self) -> (Box<LivedNet>, Option<Box<crate::shell::OsShell>>) {
        (self.net, self.shell)
    }

    /// Absorb the current reply set, ACK any data, and repeat until the
    /// server stops sending.
    fn collect(&mut self, received: &mut Vec<u8>) -> Result<(), &'static str> {
        for _ in 0..64 {
            let mut got_data = false;
            let mut i = 0usize;
            while let Some(frame) = self.replies.get(i) {
                i += 1;
                if frame.len() < 34 || frame[23] != IP_PROTO_TCP {
                    continue;
                }
                let seg = TcpImpl::parse_segment(&frame[34..], GUEST_IP, LOOPBACK_PEER_IP)
                    .map_err(|_| "loopback: bad server segment")?;
                if seg.seq != self.server_next {
                    return Err("loopback: server segment out of order");
                }
                if !seg.payload.is_empty() {
                    received.extend_from_slice(seg.payload);
                    self.server_next = self.server_next.wrapping_add(seg.payload.len() as u32);
                    got_data = true;
                }
                if seg.flags & tcp_flags::FIN != 0 {
                    self.server_next = self.server_next.wrapping_add(1);
                    self.server_fin = true;
                    got_data = true;
                }
            }
            if !got_data {
                return Ok(());
            }
            let (seq, ack) = (self.seq, self.server_next);
            self.transmit(seq, ack, tcp_flags::ACK, b"")?;
        }
        Err("loopback: server never went quiet")
    }

    fn transmit(&mut self, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Result<(), &'static str> {
        let mut frame = alloc::vec![0u8; 54 + payload.len()];
        let tcp_len = TcpImpl::build_segment(
            self.port,
            self.dst_port,
            seq,
            ack,
            flags,
            65535,
            payload,
            LOOPBACK_PEER_IP,
            GUEST_IP,
            &mut frame[34..],
        )
        .map_err(|_| "loopback: segment build failed")?;
        let ip_len = 20 + tcp_len;
        frame.truncate(14 + ip_len);
        frame[..6].copy_from_slice(&self.mac);
        frame[6..12].copy_from_slice(&LOOPBACK_PEER_MAC);
        frame[12..14].copy_from_slice(&[0x08, 0x00]);
        frame[14] = 0x45;
        frame[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
        frame[20] = 0x40; // don't fragment
        frame[22] = 64;
        frame[23] = IP_PROTO_TCP;
        frame[26..30].copy_from_slice(&LOOPBACK_PEER_IP);
        frame[30..34].copy_from_slice(&GUEST_IP);
        let checksum = crate::net::ipv4_header_checksum(&frame[14..34]);
        frame[24..26].copy_from_slice(&checksum.to_be_bytes());
        *self.replies = ReplySet::new();
        match self.shell.as_deref_mut() {
            Some(shell) => self.net.handle_frame_with_shell(&frame, self.boots, shell, &mut self.replies),
            None => self.net.handle_frame(&frame, self.boots, &mut self.replies),
        }
        Ok(())
    }
}

/// Fixed inputs of the golden session: everything the server's output
/// depends on besides the recorded client bytes.
#[cfg(any(test, not(cuttle_prod)))]
pub mod golden {
    /// Seed for the deterministic RNG (server random, key share).
    pub const RNG_SEED: [u8; 32] = *b"cuttle-https-golden-rng-seed-v1!";
    /// Identity secret (stands in for the device key).
    pub const IDENTITY_SECRET: [u8; 32] = *b"cuttle-https-golden-identity-v1!";
    /// Node MAC (goes into the certificate CN).
    pub const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    /// Control-plane key for the LivedNet instance.
    pub const AUTH_KEY: [u8; 32] = *b"cuttle-https-golden-netauth-v1!!";
    /// Boot counter reported by `GET /healthz`.
    pub const BOOTS: u64 = 7;
    /// Client TCP port.
    pub const CLIENT_PORT: u16 = 52015;
}

/// Build the golden LivedNet: deterministic provider, fixture identity.
/// Callers must hold [`crate::tls_provider::GOLDEN_LOCK`].
#[cfg(any(test, not(cuttle_prod)))]
pub fn golden_server() -> Result<Box<LivedNet>, &'static str> {
    crate::tls_provider::reset_golden_rng(golden::RNG_SEED);
    let identity = ServerIdentity::derive(&golden::IDENTITY_SECRET, golden::MAC);
    let config = server_config(&identity, crate::tls_provider::golden_provider())
        .map_err(|_| "golden: server config")?;
    let mut net = Box::new(LivedNet::with_auth_key(golden::MAC, golden::AUTH_KEY));
    net.enable_tls(config);
    Ok(net)
}

/// Result of [`replay_golden_session`].
#[cfg(any(test, not(cuttle_prod)))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GoldenReport {
    /// Server TLS bytes produced over the whole session.
    pub server_bytes: usize,
    /// SHA-256 of those bytes.
    pub sha256: [u8; 32],
}

/// Replay the recorded client side of a TLS 1.3 session
/// ([`kf::HTTPS_GOLDEN_CLIENT_FLIGHTS`]: ClientHello; Finished; an encrypted
/// `GET /healthz`; `close_notify`) against the golden server through
/// Ethernet frames, then require the server's byte stream — ServerHello,
/// encrypted certificate, CertificateVerify, Finished, the encrypted HTTP
/// response and its `close_notify` — to hash to
/// [`kf::HTTPS_GOLDEN_SERVER_SHA256`]. Any change to rustls, the provider,
/// the certificate, LivedNet or TCP that alters one server byte fails it.
#[cfg(any(test, not(cuttle_prod)))]
pub fn replay_golden_session() -> Result<GoldenReport, &'static str> {
    let _guard = crate::tls_provider::GOLDEN_LOCK.lock();
    let net = golden_server()?;
    let mut client = LoopbackClient::connect(net, None, golden::CLIENT_PORT, golden::BOOTS)?;
    replay_golden_flights(&mut client)
}

/// The replay half of [`replay_golden_session`], for a caller that built the
/// golden server itself (holding [`crate::tls_provider::GOLDEN_LOCK`]) and
/// connected `client` to it — e.g. the kernel's boot check, which first
/// fills the other fifteen TCP slots.
#[cfg(any(test, not(cuttle_prod)))]
pub fn replay_golden_flights(client: &mut LoopbackClient) -> Result<GoldenReport, &'static str> {
    let mut server = Vec::new();
    for flight in kf::HTTPS_GOLDEN_CLIENT_FLIGHTS {
        server.extend_from_slice(&client.send(flight)?);
    }
    server.extend_from_slice(&client.close()?);
    let mut sha256 = [0u8; 32];
    sha256.copy_from_slice(&Sha256::digest(&server));
    if server.len() != kf::HTTPS_GOLDEN_SERVER_LEN {
        return Err("golden: server byte count drift");
    }
    if sha256 != kf::HTTPS_GOLDEN_SERVER_SHA256 {
        return Err("golden: server bytes drift");
    }
    Ok(GoldenReport { server_bytes: server.len(), sha256 })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_is_deterministic_and_secret_dependent() {
        let a = ServerIdentity::derive(&[1u8; 32], [0, 1, 2, 3, 4, 5]);
        let b = ServerIdentity::derive(&[1u8; 32], [0, 1, 2, 3, 4, 5]);
        let c = ServerIdentity::derive(&[2u8; 32], [0, 1, 2, 3, 4, 5]);
        assert_eq!(a.cert_der(), b.cert_der());
        assert_eq!(a.fingerprint(), b.fingerprint());
        assert_ne!(a.public_key_sec1(), c.public_key_sec1());
    }

    #[test]
    fn certificate_parses_and_self_signature_verifies() {
        use cuttle_contracts::X509;
        let id = ServerIdentity::derive(&[7u8; 32], [0x52, 0x54, 0, 0x12, 0x34, 0x56]);
        let cert = crate::x509::X509Impl::parse(id.cert_der()).expect("in-tree X.509 parser accepts it");
        assert_eq!(cert.version, 2, "v3 is encoded as 2");
        assert!(cert.subject.windows(19).any(|w| w == b"cuttle-525400123456"));
        assert_eq!(cert.subject, cert.issuer);
        assert_eq!(cert.not_before.unix, 1_735_689_600); // 2025-01-01
        assert_eq!(cert.not_after.unix, 4_102_444_799); // 2099-12-31 23:59:59
        assert!(crate::tls_provider::ecdsa_p256_sha256_verify(
            &id.public_key_sec1(),
            cert.tbs,
            cert.signature,
        ));
    }

    #[test]
    fn session_rejects_garbage_with_an_alert() {
        let _guard = crate::tls_provider::GOLDEN_LOCK.lock();
        crate::tls_provider::reset_golden_rng([5u8; 32]);
        let id = ServerIdentity::derive(&[3u8; 32], [0; 6]);
        let config = server_config(&id, crate::tls_provider::golden_provider()).unwrap();
        let mut session = TlsSession::new(config).unwrap();
        // A plaintext HTTP request on the TLS port is not a TLS record.
        let err = session.receive(b"GET / HTTP/1.1\r\nHost: x\r\n\r\n").unwrap_err();
        assert!(matches!(err, SessionError::Tls(_)));
        assert!(session.is_failed());
        // rustls queued a fatal alert record (content type 21).
        assert_eq!(session.pending_tx().first(), Some(&21));
        assert_eq!(session.receive(b"more"), Err(SessionError::Failed));
    }

    #[test]
    fn send_before_handshake_is_not_ready() {
        let _guard = crate::tls_provider::GOLDEN_LOCK.lock();
        crate::tls_provider::reset_golden_rng([5u8; 32]);
        let id = ServerIdentity::derive(&[3u8; 32], [0; 6]);
        let config = server_config(&id, crate::tls_provider::golden_provider()).unwrap();
        let mut session = TlsSession::new(config).unwrap();
        assert_eq!(session.send(b"hello"), Err(SessionError::NotReady));
        assert!(session.pending_tx().is_empty());
    }

    #[test]
    fn derive_tls_identity_secret_uses_rng_when_unprovisioned_and_master_when_provisioned() {
        let rng = crate::tls_provider::KernelRng::unseeded();
        let mac = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
        // Unseeded RNG fails closed on unprovisioned boots.
        assert!(derive_tls_identity_secret(None, mac, &rng).is_err());

        rng.reseed([0x77; 32]);
        let (ephem1, prov1) = derive_tls_identity_secret(None, mac, &rng).unwrap();
        let (ephem2, prov2) = derive_tls_identity_secret(None, mac, &rng).unwrap();
        assert!(!prov1 && !prov2);
        assert_ne!(ephem1, ephem2, "unprovisioned identity draws fresh entropy per call");

        let master = [0x99; 32];
        let (p1, is_prov1) = derive_tls_identity_secret(Some(&master), mac, &rng).unwrap();
        let (p2, is_prov2) = derive_tls_identity_secret(Some(&master), mac, &rng).unwrap();
        assert!(is_prov1 && is_prov2);
        assert_eq!(p1, p2, "provisioned identity is deterministic for certificate pinning");
        assert_ne!(p1, ephem1);
    }

    #[test]
    #[should_panic(expected = "DER TLV content exceeds 65535 bytes")]
    fn der_panics_on_content_over_65535_bytes() {
        let oversized = alloc::vec![0u8; 0x1_0000];
        let mut out = Vec::new();
        der(0x04, &oversized, &mut out);
    }
}
