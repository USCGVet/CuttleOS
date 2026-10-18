//! In-kernel TLS 1.3 server primitives — `no_std`, allocation-free.
//!
//! This module is the `target_enterprise` port of the donor TLS module
//! at `RustOSa/src/tls.rs`. The donor uses `alloc::vec::Vec` freely; we
//! cannot. Every helper here writes into a caller-supplied `&mut [u8]`
//! and returns the number of bytes written. Fixed-capacity stack
//! buffers replace the donor's `Vec<u8>` working scratch.
//!
//! # Locked surface
//!
//! The byte-observable surface — ServerHello layout, HKDF-Extract /
//! HKDF-Expand-Label outputs, TLS record header encoding — is the
//! [`proteus_contracts::Tls13Server`] contract and **does not morph
//! across cycles**. The internal helpers (cursor parser, scratch buffer
//! sizing, branch ordering, local naming) ARE candidates for the
//! diversifier; see `diversifier/tests/tls_diversify_roundtrip.rs`.
//!
//! # Cipher suite choice
//!
//! This module emits ServerHello with `cipher_suite =
//! TLS_AES_128_GCM_SHA256` (0x1301). It is the simplest TLS 1.3 suite
//! whose KAT vectors are widely published; AES-128-GCM is the suite the
//! donor's KAT battery in `RustOSa/src/kat.rs` exercises for record
//! framing. ChaCha20-Poly1305 (0x1303) is left for a future task.
//!
//! # Scope
//!
//! This is a partial port covering the **handshake-message layer**
//! (HKDF key schedule + ServerHello build + ClientHello parse). The
//! AEAD record-layer encryption is provided by [`crate::AeadImpl`]
//! (toy, not RFC-compliant) and is intentionally out of scope for this
//! module — wiring the in-target AEAD up to the donor's TLS 1.3 record
//! sequencing is TASK-008+.
//!
//! # Limits
//!
//! `MAX_SERVER_HELLO_LEN` (256 bytes) bounds the largest ServerHello we
//! can emit. With one `key_share` x25519 (40 bytes), one
//! `supported_versions` (6 bytes), one optional ALPN extension (9..264
//! bytes), and the fixed prelude, 256 is comfortable for every shape
//! the trait allows.

use proteus_contracts::{HandshakeKeys, ParsedServerHello, Tls13Client, Tls13Server};
use sha2::{Digest, Sha256};

/// SHA-256 output length in bytes. Matches
/// [`Tls13Server::HASH_LEN`](proteus_contracts::Tls13Server::HASH_LEN).
pub const HASH_LEN: usize = 32;

/// TLS record header length: type(1) + version(2) + length(2).
pub const RECORD_HEADER_LEN: usize = 5;

/// Wire constant for the TLS 1.3 protocol version inside extensions.
pub const TLS_1_3: u16 = 0x0304;

/// Wire constant for legacy_version in ClientHello/ServerHello records.
pub const LEGACY_VERSION: u16 = 0x0303;

/// Cipher suite identifier for TLS_AES_128_GCM_SHA256.
pub const CIPHER_TLS_AES_128_GCM_SHA256: u16 = 0x1301;

/// Cipher suite identifier for TLS_CHACHA20_POLY1305_SHA256.
pub const CIPHER_TLS_CHACHA20_POLY1305_SHA256: u16 = 0x1303;

/// Named-group identifier for X25519 per RFC 8446 §4.2.7.
pub const NAMED_GROUP_X25519: u16 = 0x001D;

/// Handshake message type byte for ServerHello (RFC 8446 §4).
pub const HANDSHAKE_TYPE_SERVER_HELLO: u8 = 2;

/// Handshake message type byte for ClientHello (RFC 8446 §4).
pub const HANDSHAKE_TYPE_CLIENT_HELLO: u8 = 1;

/// Extension type: supported_versions (RFC 8446 §4.2.1).
pub const EXT_SUPPORTED_VERSIONS: u16 = 43;
/// Extension type: key_share (RFC 8446 §4.2.8).
pub const EXT_KEY_SHARE: u16 = 51;
/// Extension type: application_layer_protocol_negotiation (RFC 7301).
pub const EXT_ALPN: u16 = 16;

/// Content-type byte for a Handshake record (RFC 8446 §5.1).
pub const CONTENT_TYPE_HANDSHAKE: u8 = 22;

/// Maximum ServerHello length this module will emit. Caller-supplied
/// `out` buffers must be at least this large for any input shape the
/// trait allows.
pub const MAX_SERVER_HELLO_LEN: usize = 256;

// ============================================================
// Error type
// ============================================================

/// Errors returned by the TLS 1.3 server primitives.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TlsError {
    /// The ClientHello payload was shorter than its declared length, or
    /// an internal length field overflowed the surrounding container.
    Truncated,
    /// The ClientHello's handshake type byte was not 0x01.
    NotClientHello,
    /// The ClientHello did not include an x25519 key_share entry, so
    /// the server cannot complete the (EC)DHE.
    MissingX25519KeyShare,
    /// The caller-supplied output buffer was too small to hold the
    /// ServerHello this module would emit.
    OutputBufferTooSmall,
    /// The selected ALPN protocol identifier had length 0 or > 255.
    InvalidAlpn,
    /// A caller-supplied input buffer was shorter than the fixed size
    /// the operation requires (sealed-blob parsing).
    BufferTooSmall,
    /// A sealed blob failed magic or integrity checks.
    DecodeFailed,
}

// ============================================================
// HMAC-SHA-256 (RFC 2104)
// ============================================================

/// HMAC-SHA-256 over `key || data`. Writes 32 bytes to `out`.
///
/// Construction (RFC 2104): the key is first reduced to ≤ 64 bytes
/// (the SHA-256 block size) — if longer than 64 bytes the key is
/// pre-hashed; otherwise zero-padded. The reduced key is XORed with
/// 0x36 / 0x5C (`ipad` / `opad`) to form the inner / outer prefixes.
pub fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; HASH_LEN]) {
    const BLOCK: usize = 64;
    let mut k_block = [0u8; BLOCK];
    if key.len() > BLOCK {
        let digest = Sha256::digest(key);
        k_block[..HASH_LEN].copy_from_slice(&digest);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK];
    let mut opad = [0x5Cu8; BLOCK];
    let mut i = 0;
    while i < BLOCK {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
        i += 1;
    }
    // inner = SHA-256(ipad || data)
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_digest = inner.finalize();
    // outer = SHA-256(opad || inner_digest)
    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_digest);
    let outer_digest = outer.finalize();
    out.copy_from_slice(&outer_digest);
}

// ============================================================
// HKDF (RFC 5869) — fixed-buffer flavour
// ============================================================

/// HKDF-Extract over SHA-256 per RFC 5869 §2.2. PRK = HMAC(salt, IKM).
/// If `salt` is empty it is treated as 32 zero bytes per the RFC.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8], out: &mut [u8; HASH_LEN]) {
    let zero = [0u8; HASH_LEN];
    let effective_salt: &[u8] = if salt.is_empty() { &zero } else { salt };
    hmac_sha256(effective_salt, ikm, out);
}

/// HKDF-Expand over SHA-256 per RFC 5869 §2.3. Writes `out.len()` bytes
/// (≤ 255 × HASH_LEN = 8160) of pseudorandom output.
///
/// # Panics
/// Panics if `out.len() > 255 * HASH_LEN`. The trait surface bounds
/// callers to this anyway.
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * HASH_LEN, "hkdf_expand: output too long");
    // T(0) is empty; T(n) = HMAC(prk, T(n-1) || info || [n]).
    let mut t_prev = [0u8; HASH_LEN];
    let mut counter: u8 = 1;
    let mut written = 0usize;
    let mut first = true;
    while written < out.len() {
        // Compose the inner buffer: T(n-1) || info || [counter].
        // Maximum: 32 + 256 + 1 = 289 bytes for the labelled HKDF.
        // We size the scratch generously to accept any info ≤ 512 bytes
        // (well above HKDF-Expand-Label's hard cap of 2+1+255+1+255 = 514).
        let mut buf = [0u8; 32 + 514 + 1];
        let mut pos = 0usize;
        if !first {
            buf[..HASH_LEN].copy_from_slice(&t_prev);
            pos = HASH_LEN;
        }
        // info — copy in chunks to avoid an out-of-bounds panic if a
        // misuse passes huge info; we bound info conservatively here.
        assert!(info.len() <= 514, "hkdf_expand: info too long");
        buf[pos..pos + info.len()].copy_from_slice(info);
        pos += info.len();
        buf[pos] = counter;
        pos += 1;

        let mut t_next = [0u8; HASH_LEN];
        hmac_sha256(prk, &buf[..pos], &mut t_next);

        let take = core::cmp::min(HASH_LEN, out.len() - written);
        out[written..written + take].copy_from_slice(&t_next[..take]);
        written += take;
        t_prev = t_next;
        counter = counter.wrapping_add(1);
        first = false;
    }
}

/// HKDF-Expand-Label per RFC 8446 §7.1. The `HkdfLabel` struct on the
/// wire is:
///
/// ```text
///   uint16  length
///   uint8   label_len      // includes the "tls13 " prefix
///   opaque  label[label_len]
///   uint8   context_len
///   opaque  context[context_len]
/// ```
pub fn hkdf_expand_label(
    secret: &[u8; HASH_LEN],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) {
    const PREFIX: &[u8] = b"tls13 ";
    let total_label_len = PREFIX.len() + label.len();
    assert!(total_label_len <= 255, "hkdf_expand_label: label too long");
    assert!(context.len() <= 255, "hkdf_expand_label: context too long");
    // info layout: 2 + 1 + total_label_len + 1 + context_len.
    // Hard cap: 2 + 1 + 255 + 1 + 255 = 514.
    let mut info = [0u8; 514];
    let mut pos = 0usize;
    let len_be = (out.len() as u16).to_be_bytes();
    info[pos] = len_be[0];
    info[pos + 1] = len_be[1];
    pos += 2;
    info[pos] = total_label_len as u8;
    pos += 1;
    info[pos..pos + PREFIX.len()].copy_from_slice(PREFIX);
    pos += PREFIX.len();
    info[pos..pos + label.len()].copy_from_slice(label);
    pos += label.len();
    info[pos] = context.len() as u8;
    pos += 1;
    info[pos..pos + context.len()].copy_from_slice(context);
    pos += context.len();
    hkdf_expand(secret, &info[..pos], out);
}

/// Derive-Secret(secret, label, messages) per RFC 8446 §7.1.
///
/// Hashes the transcript `messages` with SHA-256 first, then calls
/// `hkdf_expand_label` with the hash as the context. Writes 32 bytes
/// to `out`.
pub fn derive_secret(secret: &[u8; HASH_LEN], label: &[u8], messages: &[u8], out: &mut [u8; HASH_LEN]) {
    let transcript_hash = Sha256::digest(messages);
    let mut th = [0u8; HASH_LEN];
    th.copy_from_slice(&transcript_hash);
    hkdf_expand_label(secret, label, &th, out);
}

// ============================================================
// Record framing helpers
// ============================================================

/// Encode a TLS record header into the first 5 bytes of `out`. Returns
/// the number of bytes written (always [`RECORD_HEADER_LEN`]).
///
/// # Panics
/// Panics if `out.len() < RECORD_HEADER_LEN`. Caller's responsibility.
pub fn encode_record_header(content_type: u8, version: u16, fragment_len: u16, out: &mut [u8]) -> usize {
    assert!(out.len() >= RECORD_HEADER_LEN, "encode_record_header: short out buffer");
    out[0] = content_type;
    let v = version.to_be_bytes();
    out[1] = v[0];
    out[2] = v[1];
    let l = fragment_len.to_be_bytes();
    out[3] = l[0];
    out[4] = l[1];
    RECORD_HEADER_LEN
}

/// Decode a TLS record header from `buf`. Returns `(content_type,
/// version, fragment_len)` on success, or `None` if `buf` is shorter
/// than [`RECORD_HEADER_LEN`].
pub fn decode_record_header(buf: &[u8]) -> Option<(u8, u16, u16)> {
    if buf.len() < RECORD_HEADER_LEN {
        return None;
    }
    let version = u16::from_be_bytes([buf[1], buf[2]]);
    let len = u16::from_be_bytes([buf[3], buf[4]]);
    Some((buf[0], version, len))
}

// ============================================================
// ClientHello parser (minimal — extracts session_id_echo + x25519 keyshare)
// ============================================================

/// A minimal view of a parsed ClientHello. Held over the parser's input
/// slice via byte indices so no allocation is needed.
///
/// Only the fields needed to construct a valid ServerHello are kept;
/// the donor's `ClientHelloView` carries additional fields (ALPN
/// offers, signature algorithms, server name) that we do not need here
/// because the caller already supplies the ALPN selection externally.
#[derive(Clone, Copy)]
pub struct ClientHelloView<'a> {
    /// Slice of the client's `legacy_session_id` (0..=32 bytes).
    pub session_id: &'a [u8],
    /// Client's offered x25519 public key. 32 bytes when present.
    pub x25519_pub: Option<[u8; 32]>,
}

/// Parse a Handshake-typed ClientHello payload (without the outer
/// record header). Strict on length checks — any out-of-bounds read
/// returns `Err(TlsError::Truncated)`.
pub fn parse_client_hello<'a>(buf: &'a [u8]) -> Result<ClientHelloView<'a>, TlsError> {
    // Handshake = uint8 type + uint24 length + body.
    if buf.len() < 4 {
        return Err(TlsError::Truncated);
    }
    if buf[0] != HANDSHAKE_TYPE_CLIENT_HELLO {
        return Err(TlsError::NotClientHello);
    }
    let body_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    if buf.len() < 4 + body_len {
        return Err(TlsError::Truncated);
    }
    let body = &buf[4..4 + body_len];
    let mut p = Cursor::new(body);

    // legacy_version (u16) — ignored; supported_versions is the source.
    let _ = p.read_u16()?;
    // random (32)
    let _ = p.read_n(32)?;
    // legacy_session_id (opaque<0..32>)
    let sid_len = p.read_u8()? as usize;
    if sid_len > 32 {
        return Err(TlsError::Truncated);
    }
    let sid_start = p.pos;
    let _ = p.read_n(sid_len)?;
    let session_id = &body[sid_start..sid_start + sid_len];
    // cipher_suites (uint16 length)
    let cs_len = p.read_u16()? as usize;
    if cs_len % 2 != 0 {
        return Err(TlsError::Truncated);
    }
    let _ = p.read_n(cs_len)?;
    // legacy_compression_methods (opaque<1..255>)
    let cm_len = p.read_u8()? as usize;
    let _ = p.read_n(cm_len)?;
    // extensions (uint16 length)
    let ext_total = p.read_u16()? as usize;
    let ext_bytes = p.read_n(ext_total)?;

    let mut x25519_pub: Option<[u8; 32]> = None;
    let mut ep = Cursor::new(ext_bytes);
    while ep.remaining() > 0 {
        let etype = ep.read_u16()?;
        let elen = ep.read_u16()? as usize;
        let edata = ep.read_n(elen)?;
        if etype == EXT_KEY_SHARE {
            // ClientHello variant: client_shares = uint16 length prefix
            // + list of KeyShareEntry { group(u16), key_exchange<1..2^16-1> }.
            if edata.len() >= 2 {
                let inner_len = u16::from_be_bytes([edata[0], edata[1]]) as usize;
                if 2 + inner_len <= edata.len() {
                    let mut kp = Cursor::new(&edata[2..2 + inner_len]);
                    while kp.remaining() >= 4 {
                        let group = kp.read_u16()?;
                        let klen = kp.read_u16()? as usize;
                        let key = kp.read_n(klen)?;
                        if group == NAMED_GROUP_X25519 && klen == 32 {
                            let mut k = [0u8; 32];
                            k.copy_from_slice(key);
                            x25519_pub = Some(k);
                        }
                    }
                }
            }
        }
    }

    Ok(ClientHelloView { session_id, x25519_pub })
}

// ============================================================
// ServerHello builder
// ============================================================

/// Build a ServerHello handshake message into `out`. Returns the number
/// of bytes written.
///
/// The cipher_suite chosen is `TLS_AES_128_GCM_SHA256` (0x1301).
/// Extensions emitted: `supported_versions` (TLS 1.3),
/// `key_share` (x25519, `server_pubkey`), and optionally `ALPN`
/// (if `selected_alpn` is `Some`).
pub fn build_server_hello(
    client_hello: &[u8],
    server_random: &[u8; 32],
    server_pubkey: &[u8; 32],
    selected_alpn: Option<&[u8]>,
    out: &mut [u8],
) -> Result<usize, TlsError> {
    let ch = parse_client_hello(client_hello)?;
    if ch.x25519_pub.is_none() {
        return Err(TlsError::MissingX25519KeyShare);
    }
    if let Some(a) = selected_alpn {
        if a.is_empty() || a.len() > 255 {
            return Err(TlsError::InvalidAlpn);
        }
    }
    if out.len() < MAX_SERVER_HELLO_LEN {
        return Err(TlsError::OutputBufferTooSmall);
    }

    // Stage the handshake-body fields into a stack scratch.
    let mut body = [0u8; MAX_SERVER_HELLO_LEN];
    let mut bpos = 0usize;

    // legacy_version 0x0303
    let lv = LEGACY_VERSION.to_be_bytes();
    body[bpos] = lv[0];
    body[bpos + 1] = lv[1];
    bpos += 2;
    // random (32)
    body[bpos..bpos + 32].copy_from_slice(server_random);
    bpos += 32;
    // legacy_session_id_echo (opaque<0..32>)
    body[bpos] = ch.session_id.len() as u8;
    bpos += 1;
    body[bpos..bpos + ch.session_id.len()].copy_from_slice(ch.session_id);
    bpos += ch.session_id.len();
    // cipher_suite
    let cs = CIPHER_TLS_AES_128_GCM_SHA256.to_be_bytes();
    body[bpos] = cs[0];
    body[bpos + 1] = cs[1];
    bpos += 2;
    // legacy_compression_method = 0
    body[bpos] = 0x00;
    bpos += 1;

    // Build extensions into a separate scratch, then splice in with
    // length prefix.
    let mut ext = [0u8; MAX_SERVER_HELLO_LEN];
    let mut epos = 0usize;

    // supported_versions ServerHello variant: bare uint16 (0x0304).
    let sv_type = EXT_SUPPORTED_VERSIONS.to_be_bytes();
    ext[epos] = sv_type[0];
    ext[epos + 1] = sv_type[1];
    epos += 2;
    let sv_len = 2u16.to_be_bytes();
    ext[epos] = sv_len[0];
    ext[epos + 1] = sv_len[1];
    epos += 2;
    let tv = TLS_1_3.to_be_bytes();
    ext[epos] = tv[0];
    ext[epos + 1] = tv[1];
    epos += 2;

    // key_share ServerHello variant: KeyShareEntry { group, key_exchange<1..2^16-1> }.
    let ks_type = EXT_KEY_SHARE.to_be_bytes();
    ext[epos] = ks_type[0];
    ext[epos + 1] = ks_type[1];
    epos += 2;
    // key_share content length: 2 (group) + 2 (key_len) + 32 (key) = 36.
    let ks_len = 36u16.to_be_bytes();
    ext[epos] = ks_len[0];
    ext[epos + 1] = ks_len[1];
    epos += 2;
    let group = NAMED_GROUP_X25519.to_be_bytes();
    ext[epos] = group[0];
    ext[epos + 1] = group[1];
    epos += 2;
    let kl = 32u16.to_be_bytes();
    ext[epos] = kl[0];
    ext[epos + 1] = kl[1];
    epos += 2;
    ext[epos..epos + 32].copy_from_slice(server_pubkey);
    epos += 32;

    // Optional ALPN (RFC 7301): ext_type(2) + ext_len(2) +
    // protocol_name_list_len(2) + name_len(1) + name(name_len).
    if let Some(name) = selected_alpn {
        let at = EXT_ALPN.to_be_bytes();
        ext[epos] = at[0];
        ext[epos + 1] = at[1];
        epos += 2;
        let payload_len = 2 + 1 + name.len();
        let al = (payload_len as u16).to_be_bytes();
        ext[epos] = al[0];
        ext[epos + 1] = al[1];
        epos += 2;
        let inner_len = (1 + name.len()) as u16;
        let il = inner_len.to_be_bytes();
        ext[epos] = il[0];
        ext[epos + 1] = il[1];
        epos += 2;
        ext[epos] = name.len() as u8;
        epos += 1;
        ext[epos..epos + name.len()].copy_from_slice(name);
        epos += name.len();
    }

    // Splice extensions into body with uint16 length prefix.
    let elen = (epos as u16).to_be_bytes();
    body[bpos] = elen[0];
    body[bpos + 1] = elen[1];
    bpos += 2;
    body[bpos..bpos + epos].copy_from_slice(&ext[..epos]);
    bpos += epos;

    // Wrap body in Handshake header: type(1) + uint24 length + body.
    if out.len() < 4 + bpos {
        return Err(TlsError::OutputBufferTooSmall);
    }
    out[0] = HANDSHAKE_TYPE_SERVER_HELLO;
    let body_len = bpos as u32;
    out[1] = (body_len >> 16) as u8;
    out[2] = (body_len >> 8) as u8;
    out[3] = body_len as u8;
    out[4..4 + bpos].copy_from_slice(&body[..bpos]);
    Ok(4 + bpos)
}

// ============================================================
// Cursor — bounds-checked reader
// ============================================================

/// Bounds-checked byte reader over a borrowed slice. Every read returns
/// `Err(TlsError::Truncated)` on over-read; no panic path is reachable.
struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }
    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }
    fn read_u8(&mut self) -> Result<u8, TlsError> {
        if self.remaining() < 1 {
            return Err(TlsError::Truncated);
        }
        let b = self.buf[self.pos];
        self.pos += 1;
        Ok(b)
    }
    fn read_u16(&mut self) -> Result<u16, TlsError> {
        if self.remaining() < 2 {
            return Err(TlsError::Truncated);
        }
        let v = u16::from_be_bytes([self.buf[self.pos], self.buf[self.pos + 1]]);
        self.pos += 2;
        Ok(v)
    }
    fn read_n(&mut self, n: usize) -> Result<&'a [u8], TlsError> {
        if self.remaining() < n {
            return Err(TlsError::Truncated);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }
}

// ============================================================
// Tls13Server impl — the contract surface
// ============================================================

/// Concrete [`proteus_contracts::Tls13Server`] impl. Wraps the free
/// functions above in a zero-sized type so callers can name the
/// contract surface explicitly.
pub struct Tls13ServerImpl;

impl Tls13Server for Tls13ServerImpl {
    const RECORD_HEADER_LEN: usize = RECORD_HEADER_LEN;
    const HASH_LEN: usize = HASH_LEN;
    type Error = TlsError;

    fn build_server_hello(
        client_hello: &[u8],
        server_random: &[u8; 32],
        server_pubkey: &[u8; 32],
        selected_alpn: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        build_server_hello(client_hello, server_random, server_pubkey, selected_alpn, out)
    }

    fn hkdf_extract(salt: &[u8], ikm: &[u8], out: &mut [u8; 32]) {
        hkdf_extract(salt, ikm, out);
    }

    fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]) {
        hkdf_expand_label(secret, label, context, out);
    }
}

// ============================================================
// TLS 1.3 session resumption (RFC 8446 §4.6.1) — cross-morph
// session continuity (Class B of the cadence program).
// ============================================================
//
// The cadence problem: a morph cycle reboots the kernel, killing every
// live TLS session. TLS 1.3's answer is resumption PSKs — if the PSK
// crosses the reboot in durable state, clients resume without a full
// handshake and the application session survives the morph. This module
// implements the exact key-schedule path:
//
//   resumption_master_secret = Derive-Secret(MasterSecret, "res_master",
//                                            transcript)
//   resumption PSK           = HKDF-Expand-Label(rms, "resumption",
//                                                ticket_nonce, Hash.len)
//   early_secret (next boot) = HKDF-Extract(salt = 0, ikm = PSK)
//
// plus a sealed-blob format for persisting the PSK across the morph
// boundary (magic || nonce || PSK || crc32). The NewSessionTicket
// handshake machinery and client-side binder validation are follow-on
// work; what is proven here is the load-bearing crypto property: the
// resumed early secret derived from durable state is byte-identical to
// the one a continuous process would have used.

/// Derive the resumption master secret from a completed handshake's
/// master secret and the handshake transcript (RFC 8446 §4.6.1,
/// Derive-Secret label "res_master").
pub fn derive_resumption_master_secret(
    master_secret: &[u8; HASH_LEN],
    transcript: &[u8],
    out: &mut [u8; HASH_LEN],
) {
    derive_secret(master_secret, b"res_master", transcript, out);
}

/// Derive a resumption PSK from the resumption master secret and a
/// per-ticket nonce (RFC 8446 §4.6.1: HKDF-Expand-Label with label
/// "resumption", context = ticket_nonce, length = Hash.length).
pub fn derive_resumption_psk(
    resumption_master_secret: &[u8; HASH_LEN],
    ticket_nonce: &[u8],
    out: &mut [u8; HASH_LEN],
) {
    hkdf_expand_label(resumption_master_secret, b"resumption", ticket_nonce, out);
}

/// The early secret for a resumption handshake (RFC 8446 §7.1:
/// early_secret = HKDF-Extract(salt = 0, IKM = PSK)). On a morphed-
// successor boot the PSK comes from durable state; the derived early
/// secret must be byte-identical to the continuous-process value.
pub fn early_secret_from_psk(psk: &[u8; HASH_LEN], out: &mut [u8; HASH_LEN]) {
    hkdf_extract(&[0u8; HASH_LEN], psk, out);
}

/// Sealed resumption blob: `magic(8) || nonce(32) || psk(32) || crc32(4)`.
/// CRC is over magic||nonce||psk (72 bytes). Total 76 bytes — small
/// enough to ride in any durable seal / WAL frame / fw_cfg blob.
pub const RESUMPTION_BLOB_MAGIC: &[u8; 8] = b"PRTSPSK1";
/// Total byte length of the sealed resumption blob.
pub const RESUMPTION_BLOB_LEN: usize = 8 + 32 + 32 + 4;

/// Serialize a resumption PSK + its ticket nonce into the sealed blob.
pub fn seal_resumption_psk(
    psk: &[u8; HASH_LEN],
    ticket_nonce: &[u8; 32],
    out: &mut [u8; RESUMPTION_BLOB_LEN],
) {
    out[..8].copy_from_slice(RESUMPTION_BLOB_MAGIC);
    out[8..40].copy_from_slice(ticket_nonce);
    out[40..72].copy_from_slice(psk);
    let crc = crate::wal::crc32_ieee(&out[..72]);
    out[72..76].copy_from_slice(&crc.to_le_bytes());
}

/// Parse a sealed resumption blob. Returns (ticket_nonce, psk). Fails
/// closed on magic mismatch, length mismatch, or CRC drift — a corrupt
/// durable PSK must never silently produce a wrong early secret.
pub fn open_resumption_psk(
    blob: &[u8],
) -> Result<([u8; 32], [u8; HASH_LEN]), TlsError> {
    if blob.len() != RESUMPTION_BLOB_LEN {
        return Err(TlsError::BufferTooSmall);
    }
    if blob[..8] != RESUMPTION_BLOB_MAGIC[..] {
        return Err(TlsError::DecodeFailed);
    }
    let want_crc = u32::from_le_bytes([blob[72], blob[73], blob[74], blob[75]]);
    if crate::wal::crc32_ieee(&blob[..72]) != want_crc {
        return Err(TlsError::DecodeFailed);
    }
    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&blob[8..40]);
    let mut psk = [0u8; HASH_LEN];
    psk.copy_from_slice(&blob[40..72]);
    Ok((nonce, psk))
}

// ============================================================
// TLS 1.3 client — TASK-049
// ============================================================
//
// The client side mirrors the server: handshake-message-layer encode /
// decode + RFC 8446 §7.1 key schedule through the two handshake-traffic
// secrets + RFC 8446 §4.4.4 Finished MAC. AEAD record-layer encryption,
// certificate-chain validation, and curve25519 scalar-multiplication
// are intentionally out of scope (the latter two are future tasks; AEAD
// is the existing `AeadImpl` surface).
//
// Wire-byte locks (matches the contract):
//   - cipher_suites list = [TLS_AES_128_GCM_SHA256] (singleton).
//   - extension order in ClientHello =
//     [supported_versions, signature_algorithms, key_share].
//   - signature_algorithms = [ecdsa_secp256r1_sha256, rsa_pss_rsae_sha256,
//     ed25519]. The client does not perform certificate validation yet,
//     but the offer must be present per RFC 8446 §9.2 ("MUST send
//     signature_algorithms in ClientHello").
//
// Per-test-vector verification: the key-schedule golden values are
// reproduced from a self-consistent run of the existing HMAC-SHA-256 /
// HKDF-Extract primitives (which themselves match RFC 4231 / RFC 5869
// test vectors — see `hmac_sha256_rfc4231_test_case_1` and
// `hkdf_rfc5869_case1_extract` below). Any future drift in those
// primitives surfaces immediately in the client-side test suite because
// the golden bytes are written-down rather than re-computed at test
// time.

/// Maximum ClientHello length this module will emit. With the locked
/// extension set (`supported_versions` 7 bytes,
/// `signature_algorithms` 12 bytes, `key_share` 44 bytes) plus the
/// fixed 41-byte prelude (handshake header + legacy_version + random +
/// session_id_len + cipher_suites + compression + ext_len), the actual
/// emitted length is comfortably under 200 bytes. The 256-byte cap
/// matches `MAX_SERVER_HELLO_LEN` for symmetric buffer sizing.
pub const MAX_CLIENT_HELLO_LEN: usize = 256;

/// Extension type: signature_algorithms (RFC 8446 §4.2.3).
pub const EXT_SIGNATURE_ALGORITHMS: u16 = 13;

/// SignatureScheme: ecdsa_secp256r1_sha256 (RFC 8446 §4.2.3).
pub const SIG_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
/// SignatureScheme: rsa_pss_rsae_sha256 (RFC 8446 §4.2.3).
pub const SIG_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
/// SignatureScheme: ed25519 (RFC 8446 §4.2.3).
pub const SIG_ED25519: u16 = 0x0807;

// ----------------------------------------------------------------
// SHA-256 helper — wrap the sha2 crate so call sites stay terse.
// ----------------------------------------------------------------

/// SHA-256 over `data`. Writes 32 bytes to `out`.
pub fn sha256_into(data: &[u8], out: &mut [u8; HASH_LEN]) {
    let d = Sha256::digest(data);
    out.copy_from_slice(&d);
}

/// SHA-256 over `(a || b)`. Writes 32 bytes to `out`. Used to compute
/// the ClientHello||ServerHello transcript hash without copying the
/// two slices into a temporary buffer.
pub fn sha256_concat_into(a: &[u8], b: &[u8], out: &mut [u8; HASH_LEN]) {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    let d = h.finalize();
    out.copy_from_slice(&d);
}

// ----------------------------------------------------------------
// ClientHello builder
// ----------------------------------------------------------------

/// Build a ClientHello handshake message into `out`. Returns the
/// number of bytes written.
///
/// Emitted shape (locked across morph cycles):
/// - handshake header: `01 00 00 <body_len:u24>`
/// - legacy_version: 0x0303
/// - random: 32 bytes (caller-supplied)
/// - legacy_session_id: empty (0x00)
/// - cipher_suites: 0x0002 0x1301 (singleton)
/// - legacy_compression_methods: 0x01 0x00
/// - extensions length: u16
/// - extensions:
///     - supported_versions (type=0x002B): list of one — 0x0304
///     - signature_algorithms (type=0x000D): list of three —
///       0x0403, 0x0804, 0x0807
///     - key_share (type=0x0033): client_shares with one
///       KeyShareEntry { group=0x001D, key_exchange=<32 bytes> }
pub fn build_client_hello(
    client_random: &[u8; 32],
    client_pubkey: &[u8; 32],
    out: &mut [u8],
) -> Result<usize, TlsError> {
    if out.len() < MAX_CLIENT_HELLO_LEN {
        return Err(TlsError::OutputBufferTooSmall);
    }

    // Stage the body separately so the handshake header can record the
    // exact body length.
    let mut body = [0u8; MAX_CLIENT_HELLO_LEN];
    let mut bpos = 0usize;

    // legacy_version
    let lv = LEGACY_VERSION.to_be_bytes();
    body[bpos] = lv[0];
    body[bpos + 1] = lv[1];
    bpos += 2;
    // random
    body[bpos..bpos + 32].copy_from_slice(client_random);
    bpos += 32;
    // legacy_session_id (empty)
    body[bpos] = 0x00;
    bpos += 1;
    // cipher_suites: one suite (2 bytes), length prefix u16.
    let cs_len = 2u16.to_be_bytes();
    body[bpos] = cs_len[0];
    body[bpos + 1] = cs_len[1];
    bpos += 2;
    let cs = CIPHER_TLS_AES_128_GCM_SHA256.to_be_bytes();
    body[bpos] = cs[0];
    body[bpos + 1] = cs[1];
    bpos += 2;
    // legacy_compression_methods: { 0x00 }
    body[bpos] = 0x01;
    body[bpos + 1] = 0x00;
    bpos += 2;

    // Build extensions into a scratch buffer first so the u16 length
    // prefix can record their total length.
    let mut ext = [0u8; MAX_CLIENT_HELLO_LEN];
    let mut epos = 0usize;

    // supported_versions: ext_type(2) + ext_len(2) + list_len(1) +
    // 0x0304.  list_len=2 bytes; ext_len=3.
    let sv_type = EXT_SUPPORTED_VERSIONS.to_be_bytes();
    ext[epos] = sv_type[0];
    ext[epos + 1] = sv_type[1];
    epos += 2;
    let sv_len = 3u16.to_be_bytes();
    ext[epos] = sv_len[0];
    ext[epos + 1] = sv_len[1];
    epos += 2;
    ext[epos] = 0x02; // list byte-length
    epos += 1;
    let tv = TLS_1_3.to_be_bytes();
    ext[epos] = tv[0];
    ext[epos + 1] = tv[1];
    epos += 2;

    // signature_algorithms: ext_type(2) + ext_len(2) + list_len(2) +
    // [scheme(2)] * 3. list_len = 6, ext_len = 8.
    let sa_type = EXT_SIGNATURE_ALGORITHMS.to_be_bytes();
    ext[epos] = sa_type[0];
    ext[epos + 1] = sa_type[1];
    epos += 2;
    let sa_len = 8u16.to_be_bytes();
    ext[epos] = sa_len[0];
    ext[epos + 1] = sa_len[1];
    epos += 2;
    let list_len = 6u16.to_be_bytes();
    ext[epos] = list_len[0];
    ext[epos + 1] = list_len[1];
    epos += 2;
    let s1 = SIG_ECDSA_SECP256R1_SHA256.to_be_bytes();
    let s2 = SIG_RSA_PSS_RSAE_SHA256.to_be_bytes();
    let s3 = SIG_ED25519.to_be_bytes();
    ext[epos] = s1[0];
    ext[epos + 1] = s1[1];
    ext[epos + 2] = s2[0];
    ext[epos + 3] = s2[1];
    ext[epos + 4] = s3[0];
    ext[epos + 5] = s3[1];
    epos += 6;

    // key_share: ext_type(2) + ext_len(2) + client_shares_len(2) +
    // KeyShareEntry { group(2) + key_len(2) + key(32) }.
    // client_shares_len = 2+2+32 = 36; ext_len = 2+36 = 38.
    let ks_type = EXT_KEY_SHARE.to_be_bytes();
    ext[epos] = ks_type[0];
    ext[epos + 1] = ks_type[1];
    epos += 2;
    let ks_ext_len = 38u16.to_be_bytes();
    ext[epos] = ks_ext_len[0];
    ext[epos + 1] = ks_ext_len[1];
    epos += 2;
    let cs_inner = 36u16.to_be_bytes();
    ext[epos] = cs_inner[0];
    ext[epos + 1] = cs_inner[1];
    epos += 2;
    let group = NAMED_GROUP_X25519.to_be_bytes();
    ext[epos] = group[0];
    ext[epos + 1] = group[1];
    epos += 2;
    let kl = 32u16.to_be_bytes();
    ext[epos] = kl[0];
    ext[epos + 1] = kl[1];
    epos += 2;
    ext[epos..epos + 32].copy_from_slice(client_pubkey);
    epos += 32;

    // Splice extensions into body with their length prefix.
    let elen = (epos as u16).to_be_bytes();
    body[bpos] = elen[0];
    body[bpos + 1] = elen[1];
    bpos += 2;
    body[bpos..bpos + epos].copy_from_slice(&ext[..epos]);
    bpos += epos;

    // Handshake header: type(1) + uint24 length + body.
    if out.len() < 4 + bpos {
        return Err(TlsError::OutputBufferTooSmall);
    }
    out[0] = HANDSHAKE_TYPE_CLIENT_HELLO;
    let body_len = bpos as u32;
    out[1] = (body_len >> 16) as u8;
    out[2] = (body_len >> 8) as u8;
    out[3] = body_len as u8;
    out[4..4 + bpos].copy_from_slice(&body[..bpos]);
    Ok(4 + bpos)
}

// ----------------------------------------------------------------
// ServerHello parser (client-side)
// ----------------------------------------------------------------

/// Parse a Handshake-typed ServerHello payload (no outer record
/// header). Strict on every length field; any over-read returns
/// `Err(TlsError::Truncated)`.
///
/// On success, returns a [`ParsedServerHello`] carrying server_random,
/// cipher_suite, and the x25519 server_pubkey recovered from the
/// `key_share` extension.
///
/// Strictness:
/// - The `supported_versions` extension MUST advertise 0x0304 (TLS
///   1.3); a value of 0x0303 (TLS 1.2 fallback) is rejected with
///   `Truncated` rather than a dedicated variant — we keep the error
///   taxonomy small per the trait's "discriminants not locked" clause.
/// - The `key_share` extension MUST carry exactly one entry, group =
///   x25519 (0x001D), key length = 32. Any other shape rejects.
/// - The cipher_suite field is recovered verbatim; the client accepts
///   only `TLS_AES_128_GCM_SHA256` (0x1301) for downstream key
///   derivation but the parser does not enforce this so a future suite
///   addition is a pure schema extension.
pub fn parse_server_hello(buf: &[u8]) -> Result<ParsedServerHello, TlsError> {
    if buf.len() < 4 {
        return Err(TlsError::Truncated);
    }
    if buf[0] != HANDSHAKE_TYPE_SERVER_HELLO {
        return Err(TlsError::NotClientHello);
    }
    let body_len = ((buf[1] as usize) << 16) | ((buf[2] as usize) << 8) | (buf[3] as usize);
    if buf.len() < 4 + body_len {
        return Err(TlsError::Truncated);
    }
    let body = &buf[4..4 + body_len];
    let mut p = Cursor::new(body);

    // legacy_version (u16) — ignored.
    let _ = p.read_u16()?;
    // server_random (32)
    let random_slice = p.read_n(32)?;
    let mut server_random = [0u8; 32];
    server_random.copy_from_slice(random_slice);
    // legacy_session_id_echo (opaque<0..32>) — skip.
    let sid_len = p.read_u8()? as usize;
    if sid_len > 32 {
        return Err(TlsError::Truncated);
    }
    let _ = p.read_n(sid_len)?;
    // cipher_suite (u16)
    let cipher_suite = p.read_u16()?;
    // legacy_compression_method (u8) — must be 0; per RFC 8446 §4.1.3
    // a non-zero value is a fatal alert, but the contract surface
    // only requires we *recover* the field; the higher-level state
    // machine can decide what to do.
    let _ = p.read_u8()?;
    // extensions (uint16 length)
    let ext_total = p.read_u16()? as usize;
    let ext_bytes = p.read_n(ext_total)?;

    let mut server_pubkey: Option<[u8; 32]> = None;
    let mut seen_supported_version = false;
    let mut ep = Cursor::new(ext_bytes);
    while ep.remaining() > 0 {
        let etype = ep.read_u16()?;
        let elen = ep.read_u16()? as usize;
        let edata = ep.read_n(elen)?;
        if etype == EXT_SUPPORTED_VERSIONS {
            // ServerHello variant: bare u16 (no list prefix).
            if edata.len() != 2 {
                return Err(TlsError::Truncated);
            }
            let v = u16::from_be_bytes([edata[0], edata[1]]);
            if v != TLS_1_3 {
                return Err(TlsError::Truncated);
            }
            seen_supported_version = true;
        } else if etype == EXT_KEY_SHARE {
            // ServerHello variant: KeyShareEntry { group(u16),
            // key_exchange<1..2^16-1> }. No outer length prefix.
            if edata.len() < 4 {
                return Err(TlsError::Truncated);
            }
            let group = u16::from_be_bytes([edata[0], edata[1]]);
            let klen = u16::from_be_bytes([edata[2], edata[3]]) as usize;
            if 4 + klen != edata.len() {
                return Err(TlsError::Truncated);
            }
            if group == NAMED_GROUP_X25519 && klen == 32 {
                let mut k = [0u8; 32];
                k.copy_from_slice(&edata[4..36]);
                server_pubkey = Some(k);
            } else {
                return Err(TlsError::MissingX25519KeyShare);
            }
        }
    }

    if !seen_supported_version {
        return Err(TlsError::Truncated);
    }
    let server_pubkey = server_pubkey.ok_or(TlsError::MissingX25519KeyShare)?;
    Ok(ParsedServerHello {
        server_random,
        cipher_suite,
        server_pubkey,
    })
}

// ----------------------------------------------------------------
// Key schedule (RFC 8446 §7.1)
// ----------------------------------------------------------------

/// All-zero 32-byte buffer used as the PSK IKM in the early_secret
/// step (RFC 8446 §7.1, "0 = a string of Hash.length bytes set to
/// zeros").
pub const ZERO_HASH: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// Empty SHA-256 transcript-hash — `SHA-256("")`. Used as the context
/// for the `derived` Derive-Secret call before the handshake-secret
/// HKDF-Extract.
///
/// Value is the well-known constant
/// `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855`.
pub const SHA256_EMPTY: [u8; HASH_LEN] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// Run the TLS 1.3 key schedule (RFC 8446 §7.1) through the two
/// handshake-traffic secrets. Writes the locked outputs into `out`.
///
/// The schedule:
///
/// ```text
/// early_secret = HKDF-Extract(salt = 0..0, IKM = 0..0)
/// derived      = Derive-Secret(early_secret, "derived", "")
/// HS           = HKDF-Extract(salt = derived, IKM = shared_secret)
/// c_hs_traffic = Derive-Secret(HS, "c hs traffic", CH || SH)
/// s_hs_traffic = Derive-Secret(HS, "s hs traffic", CH || SH)
/// ```
///
/// `client_hello` and `server_hello` are the Handshake-message
/// encodings (the byte slices the caller built / received). The
/// transcript hash fed to Derive-Secret is `SHA-256(CH || SH)`.
pub fn derive_handshake_keys(
    shared_secret: &[u8; HASH_LEN],
    client_hello: &[u8],
    server_hello: &[u8],
    out: &mut HandshakeKeys,
) {
    let mut early_secret = [0u8; HASH_LEN];
    hkdf_extract(&ZERO_HASH, &ZERO_HASH, &mut early_secret);

    // Derive-Secret(early_secret, "derived", "") = HKDF-Expand-Label
    // with context = SHA-256("") = SHA256_EMPTY.
    let mut derived = [0u8; HASH_LEN];
    hkdf_expand_label(&early_secret, b"derived", &SHA256_EMPTY, &mut derived);

    let mut handshake_secret = [0u8; HASH_LEN];
    hkdf_extract(&derived, shared_secret, &mut handshake_secret);

    // Transcript hash over CH || SH for the two traffic-secret
    // derivations. The same bytes go into both; computing once is
    // sufficient.
    let mut transcript = [0u8; HASH_LEN];
    sha256_concat_into(client_hello, server_hello, &mut transcript);

    let mut c_hs = [0u8; HASH_LEN];
    hkdf_expand_label(&handshake_secret, b"c hs traffic", &transcript, &mut c_hs);
    let mut s_hs = [0u8; HASH_LEN];
    hkdf_expand_label(&handshake_secret, b"s hs traffic", &transcript, &mut s_hs);

    out.handshake_secret = handshake_secret;
    out.client_handshake_traffic_secret = c_hs;
    out.server_handshake_traffic_secret = s_hs;
}

/// Compute the client Finished `verify_data` per RFC 8446 §4.4.4:
///
/// ```text
/// finished_key = HKDF-Expand-Label(c_hs_traffic, "finished", "", 32)
/// verify_data  = HMAC-SHA-256(finished_key, transcript_hash)
/// ```
///
/// `transcript_hash` is SHA-256 over every handshake message from
/// ClientHello through the server's Finished (inclusive). The caller
/// is responsible for accumulating that hash.
pub fn build_client_finished(
    client_handshake_traffic_secret: &[u8; HASH_LEN],
    transcript_hash: &[u8; HASH_LEN],
    out: &mut [u8; HASH_LEN],
) {
    let mut finished_key = [0u8; HASH_LEN];
    hkdf_expand_label(client_handshake_traffic_secret, b"finished", &[], &mut finished_key);
    hmac_sha256(&finished_key, transcript_hash, out);
}

// ----------------------------------------------------------------
// Tls13Client trait impl
// ----------------------------------------------------------------

/// Concrete [`proteus_contracts::Tls13Client`] impl. Wraps the free
/// functions above in a zero-sized type so callers can name the
/// contract surface explicitly.
pub struct Tls13ClientImpl;

impl Tls13Client for Tls13ClientImpl {
    const RECORD_HEADER_LEN: usize = RECORD_HEADER_LEN;
    const HASH_LEN: usize = HASH_LEN;
    type Error = TlsError;

    fn build_client_hello(
        client_random: &[u8; 32],
        client_pubkey: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        build_client_hello(client_random, client_pubkey, out)
    }

    fn parse_server_hello(server_hello: &[u8]) -> Result<ParsedServerHello, Self::Error> {
        parse_server_hello(server_hello)
    }

    fn derive_handshake_keys(
        shared_secret: &[u8; 32],
        client_hello: &[u8],
        server_hello: &[u8],
        out: &mut HandshakeKeys,
    ) {
        derive_handshake_keys(shared_secret, client_hello, server_hello, out);
    }

    fn build_client_finished(
        client_handshake_traffic_secret: &[u8; 32],
        transcript_hash: &[u8; 32],
        out: &mut [u8; 32],
    ) {
        build_client_finished(client_handshake_traffic_secret, transcript_hash, out);
    }
}

// ============================================================
// RFC 7748 X25519 Curve25519 Elliptic-Curve Diffie-Hellman
// ============================================================

fn fe_car25519(o: &mut [i64; 16]) {
    let mut i = 0usize;
    while i < 16 {
        o[i] += 1i64 << 16;
        let c = o[i] >> 16;
        if i < 15 {
            o[i + 1] += c - 1;
        } else {
            o[0] += 38 * (c - 1);
        }
        o[i] -= c << 16;
        i += 1;
    }
}

fn fe_sel25519(p: &mut [i64; 16], q: &mut [i64; 16], b: i64) {
    let c = !(b - 1);
    let mut i = 0usize;
    while i < 16 {
        let t = c & (p[i] ^ q[i]);
        p[i] ^= t;
        q[i] ^= t;
        i += 1;
    }
}

fn fe_unpack25519(o: &mut [i64; 16], n: &[u8; 32]) {
    let mut i = 0usize;
    while i < 16 {
        o[i] = (n[2 * i] as i64) + ((n[2 * i + 1] as i64) << 8);
        i += 1;
    }
    o[15] &= 0x7fff;
}

fn fe_pack25519(o: &mut [u8; 32], n: &[i64; 16]) {
    let mut t = *n;
    fe_car25519(&mut t);
    fe_car25519(&mut t);
    fe_car25519(&mut t);
    let mut m = [0i64; 16];
    let mut j = 0usize;
    while j < 2 {
        m[0] = t[0] - 0xffed;
        let mut i = 1usize;
        while i < 15 {
            m[i] = t[i] - 0xffff - ((m[i - 1] >> 16) & 1);
            m[i - 1] &= 0xffff;
            i += 1;
        }
        m[15] = t[15] - 0x7fff - ((m[14] >> 16) & 1);
        let b = (m[15] >> 16) & 1;
        m[14] &= 0xffff;
        fe_sel25519(&mut t, &mut m, 1 - b);
        j += 1;
    }
    let mut i = 0usize;
    while i < 16 {
        o[2 * i] = (t[i] & 0xff) as u8;
        o[2 * i + 1] = (t[i] >> 8) as u8;
        i += 1;
    }
}

fn fe_add25519(a: &[i64; 16], b: &[i64; 16]) -> [i64; 16] {
    let mut o = [0i64; 16];
    let mut i = 0usize;
    while i < 16 {
        o[i] = a[i] + b[i];
        i += 1;
    }
    o
}

fn fe_sub25519(a: &[i64; 16], b: &[i64; 16]) -> [i64; 16] {
    let mut o = [0i64; 16];
    let mut i = 0usize;
    while i < 16 {
        o[i] = a[i] - b[i];
        i += 1;
    }
    o
}

fn fe_mul25519(a: &[i64; 16], b: &[i64; 16]) -> [i64; 16] {
    let mut t = [0i64; 31];
    let mut i = 0usize;
    while i < 16 {
        let mut j = 0usize;
        while j < 16 {
            t[i + j] += a[i] * b[j];
            j += 1;
        }
        i += 1;
    }
    let mut k = 0usize;
    while k < 15 {
        t[k] += 38 * t[k + 16];
        k += 1;
    }
    let mut o = [0i64; 16];
    let mut idx = 0usize;
    while idx < 16 {
        o[idx] = t[idx];
        idx += 1;
    }
    fe_car25519(&mut o);
    fe_car25519(&mut o);
    o
}

fn fe_inv25519(inp: &[i64; 16]) -> [i64; 16] {
    let mut c = *inp;
    let mut a = 253i32;
    while a >= 0 {
        c = fe_mul25519(&c, &c);
        if a != 2 && a != 4 {
            c = fe_mul25519(&c, inp);
        }
        a -= 1;
    }
    c
}

/// Constant-time RFC 7748 §5 X25519 scalar multiplication over $GF(2^{255}-19)$.
///
/// Computes `out = X25519(scalar, point)` using a 255-step Montgomery ladder and
/// returns `true` if the resulting shared secret is non-zero, or `false` if `point`
/// is a low-order torsion point producing the all-zero shared secret (RFC 8446 §7.4.2).
pub fn x25519_scalarmult(scalar: &[u8; 32], point: &[u8; 32], out: &mut [u8; 32]) -> bool {
    let mut z = *scalar;
    z[0] &= 248;
    z[31] = (z[31] & 127) | 64;

    let mut x = [0i64; 16];
    fe_unpack25519(&mut x, point);

    let mut a = [0i64; 16];
    let mut b = x;
    let mut c = [0i64; 16];
    let mut d = [0i64; 16];
    a[0] = 1;
    d[0] = 1;

    let mut c121665 = [0i64; 16];
    c121665[0] = 0xdb41;
    c121665[1] = 1;

    let mut i = 254i32;
    while i >= 0 {
        let bit_idx = i as usize;
        let r = ((z[bit_idx >> 3] >> (bit_idx & 7)) & 1) as i64;
        fe_sel25519(&mut a, &mut b, r);
        fe_sel25519(&mut c, &mut d, r);

        let e = fe_add25519(&a, &c);
        a = fe_sub25519(&a, &c);
        c = fe_add25519(&b, &d);
        b = fe_sub25519(&b, &d);
        d = fe_mul25519(&e, &e);
        let f = fe_mul25519(&a, &a);
        a = fe_mul25519(&c, &a);
        c = fe_mul25519(&b, &e);
        let e2 = fe_add25519(&a, &c);
        a = fe_sub25519(&a, &c);
        b = fe_mul25519(&a, &a);
        c = fe_sub25519(&d, &f);
        a = fe_mul25519(&c, &c121665);
        a = fe_add25519(&a, &d);
        c = fe_mul25519(&c, &a);
        a = fe_mul25519(&d, &f);
        d = fe_mul25519(&b, &x);
        b = fe_mul25519(&e2, &e2);

        fe_sel25519(&mut a, &mut b, r);
        fe_sel25519(&mut c, &mut d, r);
        i -= 1;
    }

    let inv_c = fe_inv25519(&c);
    let res = fe_mul25519(&a, &inv_c);
    fe_pack25519(out, &res);

    let mut nz = 0u8;
    let mut k = 0usize;
    while k < 32 {
        nz |= out[k];
        k += 1;
    }
    nz != 0
}

/// Derive an X25519 public key `X25519(scalar, 9)` from `scalar`.
pub fn x25519_basepoint(scalar: &[u8; 32]) -> [u8; 32] {
    let mut base = [0u8; 32];
    base[0] = 9;
    let mut out = [0u8; 32];
    let _ = x25519_scalarmult(scalar, &base, &mut out);
    out
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_rfc7748_section_6_1_kat_and_low_order_rejection() {
        let alice_priv: [u8; 32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let alice_pub_expected: [u8; 32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];
        let bob_priv: [u8; 32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pub_expected: [u8; 32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
        ];
        let shared_expected: [u8; 32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
            0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
            0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
            0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
        ];

        let alice_pub = x25519_basepoint(&alice_priv);
        let bob_pub = x25519_basepoint(&bob_priv);
        assert_eq!(alice_pub, alice_pub_expected);
        assert_eq!(bob_pub, bob_pub_expected);

        let mut shared_ab = [0u8; 32];
        let mut shared_ba = [0u8; 32];
        assert!(x25519_scalarmult(&alice_priv, &bob_pub, &mut shared_ab));
        assert!(x25519_scalarmult(&bob_priv, &alice_pub, &mut shared_ba));
        assert_eq!(shared_ab, shared_expected);
        assert_eq!(shared_ba, shared_expected);

        // Red Team: low-order torsion points (0 and 1) must be rejected (`false`).
        let mut bad_out = [0u8; 32];
        assert!(!x25519_scalarmult(&alice_priv, &[0u8; 32], &mut bad_out));
        let mut order2 = [0u8; 32];
        order2[0] = 1;
        assert!(!x25519_scalarmult(&alice_priv, &order2, &mut bad_out));
    }

    // ---- resumption (RFC 8446 §4.6.1) ----

    /// End-to-end resumption continuity: derive rms → PSK, seal, then
    /// simulate the morph reboot by parsing the blob back and deriving
    /// the early secret. The early secret from the RELOADED psk must be
    /// byte-identical to the one from the in-memory psk — that equality
    /// is the Class-B claim.
    #[test]
    fn resumption_psk_survives_sealed_roundtrip() {
        let master_secret = [0x42u8; HASH_LEN];
        let transcript = b"fake handshake transcript for resumption test";
        let nonce = [0x07u8; 32];

        let mut rms = [0u8; HASH_LEN];
        derive_resumption_master_secret(&master_secret, transcript, &mut rms);
        let mut psk = [0u8; HASH_LEN];
        derive_resumption_psk(&rms, &nonce, &mut psk);

        let mut early_direct = [0u8; HASH_LEN];
        early_secret_from_psk(&psk, &mut early_direct);

        // --- simulated morph boundary: everything above this line is
        // "old kernel"; only the sealed blob crosses ---
        let mut blob = [0u8; RESUMPTION_BLOB_LEN];
        seal_resumption_psk(&psk, &nonce, &mut blob);

        let (nonce2, psk2) = open_resumption_psk(&blob).unwrap();
        assert_eq!(nonce2, nonce);
        assert_eq!(psk2, psk);
        let mut early_reloaded = [0u8; HASH_LEN];
        early_secret_from_psk(&psk2, &mut early_reloaded);

        assert_eq!(early_direct, early_reloaded);
    }

    /// Golden-vector lock on the resumption derivation chain (guards
    /// against HKDF/label drift in a future morph). Values were computed
    /// once from the RFC-4231/RFC-5869-verified primitives above and are
    /// written down, matching the module's golden-test convention.
    #[test]
    fn resumption_derivation_golden() {
        let master_secret = [0x42u8; HASH_LEN];
        let transcript = b"fake handshake transcript for resumption test";
        let nonce = [0x07u8; 32];
        let mut rms = [0u8; HASH_LEN];
        derive_resumption_master_secret(&master_secret, transcript, &mut rms);
        let mut psk = [0u8; HASH_LEN];
        derive_resumption_psk(&rms, &nonce, &mut psk);
        let mut early = [0u8; HASH_LEN];
        early_secret_from_psk(&psk, &mut early);
        // Golden bytes pinned below (generated from this implementation
        // on 2026-07-27; any primitive drift perturbs them and fails).
        const GOLDEN_PSK: [u8; 32] = [
            0xbc, 0x9b, 0x00, 0x32, 0x63, 0x7c, 0x8d, 0x93, 0x10, 0x7e, 0x6a, 0x13, 0xa2, 0xc7,
            0x3f, 0x8e, 0xb5, 0xb3, 0x27, 0x3c, 0x71, 0xd3, 0xa1, 0x62, 0x73, 0x0b, 0x98, 0xcf,
            0x60, 0x85, 0x32, 0x7a,
        ];
        const GOLDEN_EARLY: [u8; 32] = [
            0x3d, 0x36, 0x7f, 0x73, 0xd5, 0x77, 0xfe, 0x53, 0x04, 0xf8, 0x50, 0x63, 0x30, 0x44,
            0xf3, 0xb2, 0x2e, 0x37, 0xed, 0x2f, 0x49, 0x1a, 0xcc, 0xdb, 0xc7, 0xea, 0x39, 0xd9,
            0x5b, 0x42, 0x75, 0x40,
        ];
        assert_eq!(psk, GOLDEN_PSK, "resumption PSK drift");
        assert_eq!(early, GOLDEN_EARLY, "resumption early secret drift");
    }

    #[test]
    fn sealed_blob_rejects_corruption() {
        let psk = [0x11u8; HASH_LEN];
        let nonce = [0x22u8; 32];
        let mut blob = [0u8; RESUMPTION_BLOB_LEN];
        seal_resumption_psk(&psk, &nonce, &mut blob);
        // Wrong length.
        assert!(matches!(
            open_resumption_psk(&blob[..RESUMPTION_BLOB_LEN - 1]),
            Err(TlsError::BufferTooSmall)
        ));
        // Magic corruption.
        let mut bad = blob;
        bad[0] ^= 0x01;
        assert!(matches!(
            open_resumption_psk(&bad),
            Err(TlsError::DecodeFailed)
        ));
        // Payload corruption (CRC catches it).
        let mut bad2 = blob;
        bad2[50] ^= 0x80;
        assert!(matches!(
            open_resumption_psk(&bad2),
            Err(TlsError::DecodeFailed)
        ));
    }

    /// Nonce separation: different ticket nonces yield different PSKs
    /// from the same resumption master secret (RFC 8446 §4.6.1 requires
    /// per-ticket uniqueness).
    #[test]
    fn resumption_psk_nonce_separation() {
        let rms = [0x99u8; HASH_LEN];
        let mut psk_a = [0u8; HASH_LEN];
        let mut psk_b = [0u8; HASH_LEN];
        derive_resumption_psk(&rms, &[0x01], &mut psk_a);
        derive_resumption_psk(&rms, &[0x02], &mut psk_b);
        assert_ne!(psk_a, psk_b);
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        // RFC 4231 §4.2: key = 20 bytes of 0x0b, data = b"Hi There".
        let key = [0x0bu8; 20];
        let data = b"Hi There";
        let expected: [u8; 32] = [
            0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b,
            0xf1, 0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c,
            0x2e, 0x32, 0xcf, 0xf7,
        ];
        let mut got = [0u8; 32];
        hmac_sha256(&key, data, &mut got);
        assert_eq!(got, expected);
    }

    #[test]
    fn hkdf_rfc5869_case1_extract() {
        let ikm = [0x0bu8; 22];
        let salt = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
        ];
        let expected_prk: [u8; 32] = [
            0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b,
            0xba, 0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a,
            0xd7, 0xc2, 0xb3, 0xe5,
        ];
        let mut prk = [0u8; 32];
        hkdf_extract(&salt, &ikm, &mut prk);
        assert_eq!(prk, expected_prk);
    }

    // ----------------------------------------------------------------
    // TLS 1.3 client tests (TASK-049)
    // ----------------------------------------------------------------

    /// Locked client_random the test suite (and the kernel banner)
    /// passes to `build_client_hello`. All-zero for byte stability.
    const TEST_CLIENT_RANDOM: [u8; 32] = [0u8; 32];

    /// Locked client x25519 ephemeral public key. All `0x07`.
    const TEST_CLIENT_PUBKEY: [u8; 32] = [0x07u8; 32];

    /// Locked server x25519 ephemeral public key. All `0x09`.
    const TEST_SERVER_PUBKEY: [u8; 32] = [0x09u8; 32];

    /// Locked server_random the ServerHello fixture carries. All-zero.
    const TEST_SERVER_RANDOM: [u8; 32] = [0u8; 32];

    /// Locked ECDHE shared secret feeding the handshake_secret step.
    /// In a real session this is `x25519(client_priv, server_pub)`;
    /// the locked fixture stands in for the byte-stable shared secret
    /// so the key schedule is deterministic.
    const TEST_SHARED_SECRET: [u8; 32] = [0x42u8; 32];

    /// Hand-computed ServerHello matching the `parse_server_hello`
    /// surface. Layout (94 bytes total):
    /// - handshake header: `02 00 00 5A` (ServerHello, body_len=90)
    /// - legacy_version: `03 03`
    /// - server_random: 32 × `0x00`
    /// - legacy_session_id_echo: empty (`00`)
    /// - cipher_suite: `13 01`
    /// - legacy_compression_method: `00`
    /// - extensions length: `00 4E` (78 bytes) wait — recompute
    ///   - supported_versions ext: 2+2+2 = 6 bytes
    ///   - key_share ext: 2+2+2+2+32 = 40 bytes (group + keylen + key)
    ///   - total: 46 bytes; len_be = `00 2E`
    /// - body total: 2+32+1+2+1+2+46 = 86. body_len = 86.
    /// - handshake header: `02 00 00 56` (body_len=86), full message
    ///   length = 90.
    const TEST_SERVER_HELLO: [u8; 90] = [
        // handshake header: ServerHello, body_len = 86 = 0x56
        0x02, 0x00, 0x00, 0x56,
        // legacy_version
        0x03, 0x03,
        // server_random (32)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        // legacy_session_id_echo (empty)
        0x00,
        // cipher_suite = TLS_AES_128_GCM_SHA256
        0x13, 0x01,
        // legacy_compression_method
        0x00,
        // extensions total length = 46 = 0x002E
        0x00, 0x2E,
        // supported_versions (type=0x002B, ext_len=2, value=0x0304)
        0x00, 0x2B, 0x00, 0x02, 0x03, 0x04,
        // key_share (type=0x0033, ext_len=36):
        //   group=x25519, key_len=32, key=[0x09; 32]
        0x00, 0x33, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20,
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
        0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09, 0x09,
        0x09, 0x09,
    ];

    #[test]
    fn sha256_empty_matches_known_constant() {
        // Sanity: confirm the embedded SHA256_EMPTY matches a freshly
        // computed sha256_into(""). A drift here would invalidate the
        // entire key-schedule derivation tree.
        let mut got = [0u8; 32];
        sha256_into(&[], &mut got);
        assert_eq!(got, SHA256_EMPTY);
    }

    #[test]
    fn build_client_hello_total_length_locked() {
        // The locked extension set is fixed-size so the emitted
        // ClientHello has a single, predictable length. If this drifts,
        // the wire-equivalence contract is broken before any further
        // assertion needs to fire.
        let mut out = [0u8; 256];
        let n = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // handshake header 4 + body:
        //   legacy_version 2 + random 32 + sid_len 1 + cs_len 2 +
        //   cs 2 + comp 2 + ext_len 2 + ext (sv 7 + sa 12 + ks 42) = 104
        // grand total: 4 + 104 = 108
        assert_eq!(n, 108);
    }

    #[test]
    fn build_client_hello_handshake_header_locked() {
        // First four bytes are the Handshake-message header. The body
        // length should match the per-byte breakdown above.
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        assert_eq!(out[0], HANDSHAKE_TYPE_CLIENT_HELLO);
        // body_len encoded as u24 big-endian: 0x000068 = 104.
        assert_eq!(out[1], 0x00);
        assert_eq!(out[2], 0x00);
        assert_eq!(out[3], 0x68);
    }

    #[test]
    fn build_client_hello_legacy_version_and_random() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // body bytes start at offset 4.
        // legacy_version
        assert_eq!(&out[4..6], &[0x03, 0x03]);
        // random echoes TEST_CLIENT_RANDOM = all-zero.
        for b in &out[6..38] {
            assert_eq!(*b, 0);
        }
        // empty session id
        assert_eq!(out[38], 0);
    }

    #[test]
    fn build_client_hello_cipher_suites_locked() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // After 4-byte header + 2-byte legacy + 32-byte random + 1-byte
        // sid_len, cipher_suites starts at offset 39.
        // [0x00, 0x02, 0x13, 0x01]
        assert_eq!(&out[39..43], &[0x00, 0x02, 0x13, 0x01]);
    }

    #[test]
    fn build_client_hello_compression_methods_locked() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // 39 (cs start) + 4 = 43. legacy_compression_methods = [1, 0].
        assert_eq!(&out[43..45], &[0x01, 0x00]);
    }

    #[test]
    fn build_client_hello_extensions_length_locked() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // Extensions length prefix at offset 45 = 0x003D (61 bytes).
        // (sv 7 + sa 12 + ks 42 = 61.)
        assert_eq!(&out[45..47], &[0x00, 0x3D]);
    }

    #[test]
    fn build_client_hello_supported_versions_extension() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // First extension starts at offset 47.
        // Bytes: 0x00 0x2B 0x00 0x03 0x02 0x03 0x04
        assert_eq!(&out[47..54], &[0x00, 0x2B, 0x00, 0x03, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn build_client_hello_signature_algorithms_extension() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // Second extension at offset 54.
        // Bytes: 0x00 0x0D 0x00 0x08 0x00 0x06 0x04 0x03 0x08 0x04 0x08 0x07
        assert_eq!(
            &out[54..66],
            &[0x00, 0x0D, 0x00, 0x08, 0x00, 0x06, 0x04, 0x03, 0x08, 0x04, 0x08, 0x07]
        );
    }

    #[test]
    fn build_client_hello_key_share_extension() {
        let mut out = [0u8; 256];
        let _ = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out).unwrap();
        // Third extension at offset 66.
        // Header bytes: 0x00 0x33 0x00 0x26 0x00 0x24 0x00 0x1D 0x00 0x20
        assert_eq!(
            &out[66..76],
            &[0x00, 0x33, 0x00, 0x26, 0x00, 0x24, 0x00, 0x1D, 0x00, 0x20]
        );
        // Then 32 bytes of client_pubkey at offset 76.
        for (i, b) in out[76..108].iter().enumerate() {
            assert_eq!(*b, 0x07, "client_pubkey byte {} drift", i);
        }
    }

    #[test]
    fn build_client_hello_rejects_short_buffer() {
        let mut out = [0u8; 100];
        let r = build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut out);
        assert_eq!(r, Err(TlsError::OutputBufferTooSmall));
    }

    #[test]
    fn parse_server_hello_recovers_random_and_pubkey() {
        let parsed = parse_server_hello(&TEST_SERVER_HELLO).unwrap();
        assert_eq!(parsed.server_random, TEST_SERVER_RANDOM);
        assert_eq!(parsed.server_pubkey, TEST_SERVER_PUBKEY);
        assert_eq!(parsed.cipher_suite, CIPHER_TLS_AES_128_GCM_SHA256);
    }

    #[test]
    fn parse_server_hello_rejects_truncated_header() {
        let r = parse_server_hello(&TEST_SERVER_HELLO[..3]);
        assert!(matches!(r, Err(TlsError::Truncated)));
    }

    #[test]
    fn parse_server_hello_rejects_truncated_body() {
        // Cut off the last 5 bytes of the key.
        let r = parse_server_hello(&TEST_SERVER_HELLO[..TEST_SERVER_HELLO.len() - 5]);
        assert!(matches!(r, Err(TlsError::Truncated)));
    }

    #[test]
    fn parse_server_hello_rejects_wrong_handshake_type() {
        let mut bad = TEST_SERVER_HELLO;
        bad[0] = HANDSHAKE_TYPE_CLIENT_HELLO;
        let r = parse_server_hello(&bad);
        assert!(matches!(r, Err(TlsError::NotClientHello)));
    }

    #[test]
    fn parse_server_hello_rejects_tls12_fallback() {
        // Flip the supported_versions value to TLS 1.2 (0x0303).
        // offset of supported_versions value bytes:
        //   4 header + 2 legacy + 32 random + 1 sid + 2 cs + 1 comp
        //   + 2 ext_len + 4 (sv type+len) = 48,49 inside the 90-byte
        //   message.
        let mut bad = TEST_SERVER_HELLO;
        bad[48] = 0x03;
        bad[49] = 0x03;
        let r = parse_server_hello(&bad);
        assert!(matches!(r, Err(TlsError::Truncated)));
    }

    #[test]
    fn parse_server_hello_rejects_missing_x25519() {
        // Flip the key_share group from x25519 (0x001D) to secp256r1
        // (0x0017). The supported_versions ext occupies [44..50], the
        // key_share ext type+len at [50..54], the inner KeyShareEntry
        // group bytes at [54..56].
        let mut bad = TEST_SERVER_HELLO;
        bad[54] = 0x00;
        bad[55] = 0x17;
        let r = parse_server_hello(&bad);
        assert!(matches!(r, Err(TlsError::MissingX25519KeyShare)));
    }

    #[test]
    fn key_schedule_handshake_secret_locked() {
        // Build the CH+SH pair from the locked fixtures and run the
        // schedule. The handshake_secret is the load-bearing root of
        // the two traffic secrets; locking its bytes here guarantees
        // every morph cycle produces byte-identical downstream key
        // material.
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut keys = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        derive_handshake_keys(
            &TEST_SHARED_SECRET,
            &ch[..ch_len],
            &TEST_SERVER_HELLO,
            &mut keys,
        );
        // Golden handshake_secret — frozen from the first build. The
        // value comes from the deterministic composition of:
        //   early_secret = HKDF-Extract(0..0, 0..0)
        //   derived = Derive-Secret(early_secret, "derived", "")
        //   HS = HKDF-Extract(derived, TEST_SHARED_SECRET)
        // The HMAC-SHA-256 primitive is RFC 4231 §4.2 verified
        // (`hmac_sha256_rfc4231_test_case_1` above), so the golden
        // bytes are reproducible from the RFC primitives alone.
        let golden_hs: [u8; 32] = HANDSHAKE_SECRET_GOLDEN;
        assert_eq!(keys.handshake_secret, golden_hs);
    }

    #[test]
    fn key_schedule_client_traffic_secret_locked() {
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut keys = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        derive_handshake_keys(
            &TEST_SHARED_SECRET,
            &ch[..ch_len],
            &TEST_SERVER_HELLO,
            &mut keys,
        );
        assert_eq!(
            keys.client_handshake_traffic_secret,
            CLIENT_HS_TRAFFIC_GOLDEN
        );
    }

    #[test]
    fn key_schedule_server_traffic_secret_locked() {
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut keys = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        derive_handshake_keys(
            &TEST_SHARED_SECRET,
            &ch[..ch_len],
            &TEST_SERVER_HELLO,
            &mut keys,
        );
        assert_eq!(
            keys.server_handshake_traffic_secret,
            SERVER_HS_TRAFFIC_GOLDEN
        );
    }

    #[test]
    fn key_schedule_is_deterministic() {
        // Two independent runs on identical inputs must produce
        // byte-identical outputs — the morph-cycle equivalence claim
        // in miniature.
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut k1 = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        let mut k2 = k1;
        derive_handshake_keys(&TEST_SHARED_SECRET, &ch[..ch_len], &TEST_SERVER_HELLO, &mut k1);
        derive_handshake_keys(&TEST_SHARED_SECRET, &ch[..ch_len], &TEST_SERVER_HELLO, &mut k2);
        assert_eq!(k1, k2);
    }

    #[test]
    fn key_schedule_sensitive_to_shared_secret() {
        // Flipping a single bit of the shared_secret must perturb the
        // handshake_secret and both traffic secrets (HKDF avalanche).
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut k1 = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        let mut k2 = k1;
        derive_handshake_keys(&TEST_SHARED_SECRET, &ch[..ch_len], &TEST_SERVER_HELLO, &mut k1);
        let mut perturbed = TEST_SHARED_SECRET;
        perturbed[0] ^= 0x01;
        derive_handshake_keys(&perturbed, &ch[..ch_len], &TEST_SERVER_HELLO, &mut k2);
        assert_ne!(k1.handshake_secret, k2.handshake_secret);
        assert_ne!(
            k1.client_handshake_traffic_secret,
            k2.client_handshake_traffic_secret
        );
        assert_ne!(
            k1.server_handshake_traffic_secret,
            k2.server_handshake_traffic_secret
        );
    }

    #[test]
    fn key_schedule_sensitive_to_server_hello() {
        // Modifying the ServerHello must change the transcript hash
        // and therefore both traffic secrets (handshake_secret only
        // depends on shared_secret, so it stays the same).
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut k1 = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        let mut k2 = k1;
        derive_handshake_keys(&TEST_SHARED_SECRET, &ch[..ch_len], &TEST_SERVER_HELLO, &mut k1);
        let mut perturbed = TEST_SERVER_HELLO;
        // Flip a server_random byte.
        perturbed[6] ^= 0x80;
        derive_handshake_keys(&TEST_SHARED_SECRET, &ch[..ch_len], &perturbed, &mut k2);
        assert_eq!(k1.handshake_secret, k2.handshake_secret);
        assert_ne!(
            k1.client_handshake_traffic_secret,
            k2.client_handshake_traffic_secret
        );
        assert_ne!(
            k1.server_handshake_traffic_secret,
            k2.server_handshake_traffic_secret
        );
    }

    #[test]
    fn client_finished_verify_data_locked() {
        // RFC 8446 §4.4.4: verify_data = HMAC-SHA-256(finished_key,
        // transcript_hash). Lock the bytes against a frozen golden
        // computed from CLIENT_HS_TRAFFIC_GOLDEN + a synthetic
        // transcript hash.
        let transcript_hash: [u8; 32] = [0xAB; 32];
        let mut vd = [0u8; 32];
        build_client_finished(&CLIENT_HS_TRAFFIC_GOLDEN, &transcript_hash, &mut vd);
        assert_eq!(vd, CLIENT_FINISHED_GOLDEN);
    }

    #[test]
    fn client_finished_changes_with_transcript() {
        let t1 = [0xABu8; 32];
        let mut t2 = t1;
        t2[15] ^= 0x01;
        let mut vd1 = [0u8; 32];
        let mut vd2 = [0u8; 32];
        build_client_finished(&CLIENT_HS_TRAFFIC_GOLDEN, &t1, &mut vd1);
        build_client_finished(&CLIENT_HS_TRAFFIC_GOLDEN, &t2, &mut vd2);
        assert_ne!(vd1, vd2);
    }

    #[test]
    fn round_trip_client_then_server_recovers_keys() {
        // End-to-end shape check: build_client_hello + parse_server_hello
        // + derive_handshake_keys should yield the same keys as a
        // direct derivation against the raw bytes. (A negative version
        // of this is implicit in the byte-locked tests above.)
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let parsed = parse_server_hello(&TEST_SERVER_HELLO).unwrap();
        assert_eq!(parsed.server_pubkey, TEST_SERVER_PUBKEY);
        let mut k = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        derive_handshake_keys(
            &TEST_SHARED_SECRET,
            &ch[..ch_len],
            &TEST_SERVER_HELLO,
            &mut k,
        );
        assert_eq!(k.handshake_secret, HANDSHAKE_SECRET_GOLDEN);
    }

    // ------------------------------------------------------------
    // Golden constants (TASK-049). Frozen from a one-shot run of the
    // RFC-verified HMAC-SHA-256 / HKDF-Extract primitives against the
    // locked TEST_* inputs above. Any drift in the primitives surfaces
    // here as a byte mismatch.
    // ------------------------------------------------------------

    /// HS = HKDF-Extract(derived, TEST_SHARED_SECRET) where derived =
    /// Derive-Secret(early_secret, "derived", "").
    const HANDSHAKE_SECRET_GOLDEN: [u8; 32] = [
        0xbb, 0x51, 0x8f, 0x06, 0x1c, 0x91, 0x10, 0x17,
        0xf1, 0xd2, 0x64, 0x03, 0x16, 0x55, 0x41, 0x25,
        0xae, 0xc1, 0x21, 0x03, 0x60, 0xff, 0x49, 0xb8,
        0x91, 0x94, 0x57, 0xef, 0x57, 0xae, 0xce, 0xc1,
    ];

    /// c_hs_traffic = Derive-Secret(HS, "c hs traffic",
    /// SHA-256(CH || TEST_SERVER_HELLO)).
    const CLIENT_HS_TRAFFIC_GOLDEN: [u8; 32] = [
        0x52, 0xf3, 0xd2, 0x06, 0x34, 0x12, 0x0d, 0x17,
        0xc4, 0x62, 0x28, 0x39, 0x9b, 0x69, 0x69, 0x2d,
        0x69, 0x96, 0x54, 0x4a, 0x64, 0x5f, 0xc1, 0x48,
        0x2e, 0x0b, 0xe8, 0x4c, 0x60, 0x4c, 0xf7, 0xa2,
    ];

    /// s_hs_traffic = Derive-Secret(HS, "s hs traffic",
    /// SHA-256(CH || TEST_SERVER_HELLO)).
    const SERVER_HS_TRAFFIC_GOLDEN: [u8; 32] = [
        0x85, 0x91, 0x69, 0x4b, 0x50, 0xd6, 0x4a, 0x5f,
        0x0f, 0x8f, 0x23, 0xf6, 0x1f, 0x10, 0x62, 0xb4,
        0xa9, 0xa9, 0xe0, 0xad, 0xa0, 0x58, 0x1b, 0xc1,
        0xe7, 0x3a, 0x6f, 0x61, 0x17, 0x46, 0x6f, 0xfd,
    ];

    /// HMAC-SHA-256(HKDF-Expand-Label(CLIENT_HS_TRAFFIC_GOLDEN,
    /// "finished", "", 32), [0xAB; 32]).
    const CLIENT_FINISHED_GOLDEN: [u8; 32] = [
        0xf6, 0xd3, 0x7f, 0x34, 0x5e, 0xe9, 0x64, 0xd2,
        0x52, 0x7d, 0xed, 0x19, 0x7f, 0xb0, 0x7e, 0x62,
        0x7d, 0x44, 0x56, 0x5b, 0x6a, 0x26, 0x16, 0xb5,
        0x52, 0xc7, 0xca, 0x0e, 0xb2, 0xfd, 0xad, 0x65,
    ];

    /// One-shot probe: print the golden bytes so they can be baked
    /// into the four constants above. Ignored by default — invoke with
    /// `cargo test -p target_enterprise tls::tests::__dump_golden_bytes
    /// -- --ignored --nocapture` to reproduce. This stays in-tree
    /// rather than as a throwaway binary so the regeneration recipe
    /// is discoverable by any future operator who needs to refresh
    /// the goldens after a primitive-level change.
    #[test]
    #[ignore]
    fn __dump_golden_bytes() {
        extern crate std;
        let mut ch = [0u8; 256];
        let ch_len =
            build_client_hello(&TEST_CLIENT_RANDOM, &TEST_CLIENT_PUBKEY, &mut ch).unwrap();
        let mut keys = HandshakeKeys {
            handshake_secret: [0; 32],
            client_handshake_traffic_secret: [0; 32],
            server_handshake_traffic_secret: [0; 32],
        };
        derive_handshake_keys(
            &TEST_SHARED_SECRET,
            &ch[..ch_len],
            &TEST_SERVER_HELLO,
            &mut keys,
        );
        let mut vd = [0u8; 32];
        build_client_finished(&keys.client_handshake_traffic_secret, &[0xAB; 32], &mut vd);

        fn dump(label: &str, b: &[u8; 32]) {
            extern crate std;
            use std::{eprint, eprintln};
            eprint!("    const {}: [u8; 32] = [\n        ", label);
            for (i, v) in b.iter().enumerate() {
                eprint!("0x{:02x},", v);
                if i % 8 == 7 {
                    if i == 31 {
                        eprintln!();
                    } else {
                        eprint!("\n        ");
                    }
                } else {
                    eprint!(" ");
                }
            }
            eprintln!("    ];");
        }
        dump("HANDSHAKE_SECRET_GOLDEN", &keys.handshake_secret);
        dump("CLIENT_HS_TRAFFIC_GOLDEN", &keys.client_handshake_traffic_secret);
        dump("SERVER_HS_TRAFFIC_GOLDEN", &keys.server_handshake_traffic_secret);
        dump("CLIENT_FINISHED_GOLDEN", &vd);
    }

    #[test]
    fn record_header_round_trip() {
        let mut buf = [0u8; 5];
        let n = encode_record_header(CONTENT_TYPE_HANDSHAKE, LEGACY_VERSION, 0x1234, &mut buf);
        assert_eq!(n, 5);
        let (ct, ver, len) = decode_record_header(&buf).unwrap();
        assert_eq!(ct, CONTENT_TYPE_HANDSHAKE);
        assert_eq!(ver, LEGACY_VERSION);
        assert_eq!(len, 0x1234);
    }
}
