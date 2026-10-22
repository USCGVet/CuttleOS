//! RustCrypto-backed [`rustls::crypto::CryptoProvider`] for the kernel
//! (`no_std` + `alloc`, no C, no assembly, no SIMD).
//!
//! rustls implements the TLS 1.3 protocol; this module supplies the
//! cryptography it calls into:
//!
//! | rustls slot        | Algorithm                                   | Crate                |
//! |--------------------|---------------------------------------------|----------------------|
//! | cipher suites      | `TLS_AES_128_GCM_SHA256`, `TLS_CHACHA20_POLY1305_SHA256` | `aes-gcm`, `chacha20poly1305` |
//! | hash / HMAC / HKDF | SHA-256 (HKDF via rustls' `HkdfUsingHmac`)  | `sha2`, `hmac`       |
//! | key exchange       | X25519, secp256r1                           | `x25519-dalek`, `p256` |
//! | signatures         | ECDSA P-256 + SHA-256 (RFC 6979 nonces)     | `p256`               |
//! | randomness         | ChaCha20 CSPRNG seeded from hardware entropy | `rand_chacha`        |
//!
//! Only TLS 1.3 is offered. The suite list is deliberately short: every entry
//! is covered by a published known-answer vector in [`self_test`], and the
//! kernel runs that self-test at every boot.
//!
//! # Randomness
//!
//! [`system_provider`] draws from [`SYSTEM_RNG`], which fails closed (TLS
//! handshakes error out) until the kernel seeds it from hardware entropy with
//! [`seed_system_rng`]. [`golden_provider`] draws from a separate,
//! deterministic RNG that exists only so the boot self-test can replay a
//! recorded TLS session and compare every server byte; it must never serve
//! live traffic.

use alloc::boxed::Box;
use alloc::sync::Arc;
use alloc::vec::Vec;
use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};
use core::time::Duration;

use aes_gcm::aead::generic_array::GenericArray;
use aes_gcm::aead::AeadInPlace;
use aes_gcm::{Aes128Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use p256::ecdsa::signature::{Signer as _, Verifier as _};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use rand_chacha::ChaCha20Rng;
use rand_core::{RngCore, SeedableRng};
use rustls::crypto::cipher::{
    make_tls13_aad, AeadKey, InboundOpaqueMessage, InboundPlainMessage, Iv, MessageDecrypter,
    MessageEncrypter, Nonce, OutboundOpaqueMessage, OutboundPlainMessage, PrefixedPayload,
    Tls13AeadAlgorithm, UnsupportedOperationError,
};
use rustls::crypto::tls13::{Hkdf, HkdfUsingHmac};
use rustls::crypto::{
    hash, hmac, ActiveKeyExchange, CryptoProvider, GetRandomFailed, KeyProvider, SecureRandom,
    SharedSecret, SupportedKxGroup, WebPkiSupportedAlgorithms,
};
use rustls::pki_types::{
    alg_id, AlgorithmIdentifier, InvalidSignature, PrivateKeyDer, SignatureVerificationAlgorithm,
    SubjectPublicKeyInfoDer, UnixTime,
};
use rustls::sign::{public_key_to_spki, Signer, SigningKey};
use rustls::time_provider::TimeProvider;
use rustls::{
    CipherSuite, CipherSuiteCommon, ConnectionTrafficSecrets, ContentType, Error, NamedGroup,
    PeerMisbehaved, ProtocolVersion, SignatureAlgorithm, SignatureScheme, SupportedCipherSuite,
    Tls13CipherSuite,
};
use sha2::{Digest, Sha256};
use zeroize::Zeroize;

// ------------------------------------------------------------------
// Randomness
// ------------------------------------------------------------------

/// A ChaCha20 CSPRNG behind a spin lock. Unseeded, it refuses to produce
/// output, so a kernel that forgot to seed it cannot run a TLS handshake.
pub struct KernelRng {
    inner: spin::Mutex<Option<ChaCha20Rng>>,
    rekey_on_fill: bool,
}

impl KernelRng {
    /// An unseeded generator (fills fail until seeded). Rekeys after each
    /// [`SecureRandom::fill`] so a later memory read cannot roll back past
    /// handshakes.
    pub const fn unseeded() -> Self {
        Self {
            inner: spin::Mutex::new(None),
            rekey_on_fill: true,
        }
    }

    /// Deterministic generator used only by [`GOLDEN_RNG`] so multi-draw
    /// golden-transcript replays remain byte-reproducible.
    #[cfg(any(test, not(cuttle_prod)))]
    const fn unseeded_deterministic() -> Self {
        Self {
            inner: spin::Mutex::new(None),
            rekey_on_fill: false,
        }
    }

    /// Replace the generator state with one keyed by `seed`.
    pub(crate) fn reseed(&self, mut seed: [u8; 32]) {
        *self.inner.lock() = Some(ChaCha20Rng::from_seed(seed));
        seed.zeroize();
    }

    /// True once seeded.
    pub fn is_seeded(&self) -> bool {
        self.inner.lock().is_some()
    }
}

impl fmt::Debug for KernelRng {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("KernelRng")
    }
}

impl SecureRandom for KernelRng {
    fn fill(&self, buf: &mut [u8]) -> Result<(), GetRandomFailed> {
        let mut guard = self.inner.lock();
        match guard.as_mut() {
            Some(rng) => {
                rng.fill_bytes(buf);
                if self.rekey_on_fill {
                    let mut next_seed = [0u8; 32];
                    rng.fill_bytes(&mut next_seed);
                    *guard = Some(ChaCha20Rng::from_seed(next_seed));
                    next_seed.zeroize();
                }
                Ok(())
            }
            None => Err(GetRandomFailed),
        }
    }
}

/// Live-traffic RNG. Seed it from hardware entropy with [`seed_system_rng`].
pub static SYSTEM_RNG: KernelRng = KernelRng::unseeded();

/// Deterministic RNG for the boot golden-transcript self-test only.
#[cfg(any(test, not(cuttle_prod)))]
static GOLDEN_RNG: KernelRng = KernelRng::unseeded_deterministic();

/// Serializes users of [`GOLDEN_RNG`] so two replays cannot interleave draws.
#[cfg(any(test, not(cuttle_prod)))]
pub static GOLDEN_LOCK: spin::Mutex<()> = spin::Mutex::new(());

/// Seed (or re-seed) the live-traffic RNG. When it is already seeded, the new
/// seed is mixed with 32 bytes of current output, so a weak later seed never
/// replaces a strong earlier one.
pub fn seed_system_rng(mut seed: [u8; 32]) {
    let mut current = [0u8; 32];
    let mut mixed: [u8; 32] = if SYSTEM_RNG.fill(&mut current).is_ok() {
        let mut h = Sha256::new();
        h.update(b"cuttle-rng-reseed-v1");
        h.update(current);
        h.update(seed);
        h.finalize().into()
    } else {
        seed
    };
    current.zeroize();
    seed.zeroize();
    SYSTEM_RNG.reseed(mixed);
    mixed.zeroize();
}

/// Validate a QEMU `fw_cfg` device-key blob (`opt/cuttle_device_key`).
/// Requires the directory-advertised `size` to be exactly 32 bytes, `raw` to
/// be 32 bytes long, and at least one byte to be non-zero.
pub fn validate_fw_cfg_device_key(size: u32, raw: &[u8]) -> Option<[u8; 32]> {
    if size != 32 || raw.len() != 32 || !raw.iter().any(|&b| b != 0) {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(raw);
    Some(out)
}

/// Derive a 32-byte seed for [`SYSTEM_RNG`] from hardware entropy sources and
/// per-node context. Fails closed (`None`) when neither CPU `RDRAND` nor a
/// hardware/virtual TPM 2.0 RNG was available, so the caller can refuse to
/// enable HTTPS rather than seeding TLS from predictable timer/RTC fallback
/// words.
pub fn derive_tls_rng_seed(
    hw_words: &[u64; 16],
    has_rdrand: bool,
    tpm_random: Option<[u8; 16]>,
    master_key: &[u8; 32],
    mac: [u8; 6],
    boot_count: u64,
) -> Option<([u8; 32], &'static str)> {
    let source = match (has_rdrand, tpm_random.is_some()) {
        (true, true) => "rdrand+tpm",
        (true, false) => "rdrand",
        (false, true) => "tpm",
        (false, false) => return None,
    };
    let mut raw = [0u8; 190];
    for (i, w) in hw_words.iter().enumerate() {
        raw[i * 8..i * 8 + 8].copy_from_slice(&w.to_le_bytes());
    }
    if let Some(tpm) = tpm_random {
        raw[128..144].copy_from_slice(&tpm);
    }
    raw[144..176].copy_from_slice(master_key);
    raw[176..182].copy_from_slice(&mac);
    raw[182..190].copy_from_slice(&boot_count.to_le_bytes());
    let mut out = [0u8; 32];
    crate::tls::hmac_sha256(b"cuttle-tls-rng-seed-v2", &raw, &mut out);
    raw.zeroize();
    Some((out, source))
}

/// Reset the deterministic golden-test RNG to `seed`. Callers must hold
/// [`GOLDEN_LOCK`].
#[cfg(any(test, not(cuttle_prod)))]
pub fn reset_golden_rng(seed: [u8; 32]) {
    GOLDEN_RNG.reseed(seed);
}

// ------------------------------------------------------------------
// Clock
// ------------------------------------------------------------------

/// Fallback wall clock until the kernel learns the real time: 2026-01-01.
pub const DEFAULT_UNIX_TIME: u64 = 1_767_225_600;

static UNIX_TIME: AtomicU64 = AtomicU64::new(DEFAULT_UNIX_TIME);

/// Set the wall clock rustls sees (seconds since the Unix epoch).
pub fn set_unix_time(secs: u64) {
    UNIX_TIME.store(secs, Ordering::Relaxed);
}

/// Wall clock for rustls. A TLS 1.3 server with tickets and session storage
/// disabled reads it only for bookkeeping, never for a security decision.
#[derive(Debug)]
pub struct KernelTime;

impl TimeProvider for KernelTime {
    fn current_time(&self) -> Option<UnixTime> {
        Some(UnixTime::since_unix_epoch(Duration::from_secs(UNIX_TIME.load(Ordering::Relaxed))))
    }
}

// ------------------------------------------------------------------
// Hash, HMAC
// ------------------------------------------------------------------

struct Sha256Hash;

static SHA256: Sha256Hash = Sha256Hash;

impl hash::Hash for Sha256Hash {
    fn start(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(Sha256::new()))
    }

    fn hash(&self, data: &[u8]) -> hash::Output {
        hash::Output::new(&Sha256::digest(data))
    }

    fn output_len(&self) -> usize {
        32
    }

    fn algorithm(&self) -> hash::HashAlgorithm {
        hash::HashAlgorithm::SHA256
    }
}

struct Sha256Context(Sha256);

impl hash::Context for Sha256Context {
    fn fork_finish(&self) -> hash::Output {
        hash::Output::new(&self.0.clone().finalize())
    }

    fn fork(&self) -> Box<dyn hash::Context> {
        Box::new(Sha256Context(self.0.clone()))
    }

    fn finish(self: Box<Self>) -> hash::Output {
        hash::Output::new(&self.0.finalize())
    }

    fn update(&mut self, data: &[u8]) {
        self.0.update(data);
    }
}

type HmacSha256Impl = ::hmac::Hmac<Sha256>;

struct HmacSha256;

static HMAC_SHA256: HmacSha256 = HmacSha256;

impl hmac::Hmac for HmacSha256 {
    fn with_key(&self, key: &[u8]) -> Box<dyn hmac::Key> {
        let mac = <HmacSha256Impl as ::hmac::Mac>::new_from_slice(key)
            .expect("HMAC accepts any key length");
        Box::new(HmacSha256Key(mac))
    }

    fn hash_output_len(&self) -> usize {
        32
    }
}

struct HmacSha256Key(HmacSha256Impl);

impl hmac::Key for HmacSha256Key {
    fn sign_concat(&self, first: &[u8], middle: &[&[u8]], last: &[u8]) -> hmac::Tag {
        use ::hmac::Mac;
        let mut mac = self.0.clone();
        mac.update(first);
        for part in middle {
            mac.update(part);
        }
        mac.update(last);
        hmac::Tag::new(&mac.finalize().into_bytes())
    }

    fn tag_len(&self) -> usize {
        32
    }
}

// ------------------------------------------------------------------
// AEAD record protection (RFC 8446 §5.2)
// ------------------------------------------------------------------

const AEAD_TAG_LEN: usize = 16;

/// The two RustCrypto AEADs behind one in-place interface.
enum AeadCipher {
    Aes128Gcm(Box<Aes128Gcm>),
    ChaCha20Poly1305(Box<ChaCha20Poly1305>),
}

impl AeadCipher {
    fn seal(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8]) -> Result<[u8; AEAD_TAG_LEN], Error> {
        let nonce = GenericArray::from_slice(nonce);
        let tag = match self {
            Self::Aes128Gcm(c) => c.encrypt_in_place_detached(nonce, aad, buf),
            Self::ChaCha20Poly1305(c) => c.encrypt_in_place_detached(nonce, aad, buf),
        }
        .map_err(|_| Error::EncryptError)?;
        Ok(tag.into())
    }

    fn open(&self, nonce: &[u8; 12], aad: &[u8], buf: &mut [u8], tag: &[u8]) -> Result<(), Error> {
        let nonce = GenericArray::from_slice(nonce);
        let tag = GenericArray::from_slice(tag);
        match self {
            Self::Aes128Gcm(c) => c.decrypt_in_place_detached(nonce, aad, buf, tag),
            Self::ChaCha20Poly1305(c) => c.decrypt_in_place_detached(nonce, aad, buf, tag),
        }
        .map_err(|_| Error::DecryptError)
    }
}

#[derive(Clone, Copy)]
enum AeadKind {
    Aes128Gcm,
    ChaCha20Poly1305,
}

impl AeadKind {
    fn cipher(self, key: &[u8]) -> AeadCipher {
        // rustls hands exactly `key_len()` bytes, so `new_from_slice` cannot fail.
        match self {
            Self::Aes128Gcm => AeadCipher::Aes128Gcm(Box::new(
                Aes128Gcm::new_from_slice(key).expect("16-byte AES-128 key"),
            )),
            Self::ChaCha20Poly1305 => AeadCipher::ChaCha20Poly1305(Box::new(
                ChaCha20Poly1305::new_from_slice(key).expect("32-byte ChaCha20 key"),
            )),
        }
    }
}

struct Tls13Aead(AeadKind);

impl Tls13AeadAlgorithm for Tls13Aead {
    fn encrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageEncrypter> {
        Box::new(Tls13Encrypter { cipher: self.0.cipher(key.as_ref()), iv })
    }

    fn decrypter(&self, key: AeadKey, iv: Iv) -> Box<dyn MessageDecrypter> {
        Box::new(Tls13Decrypter { cipher: self.0.cipher(key.as_ref()), iv })
    }

    fn key_len(&self) -> usize {
        match self.0 {
            AeadKind::Aes128Gcm => 16,
            AeadKind::ChaCha20Poly1305 => 32,
        }
    }

    fn extract_keys(
        &self,
        key: AeadKey,
        iv: Iv,
    ) -> Result<ConnectionTrafficSecrets, UnsupportedOperationError> {
        Ok(match self.0 {
            AeadKind::Aes128Gcm => ConnectionTrafficSecrets::Aes128Gcm { key, iv },
            AeadKind::ChaCha20Poly1305 => ConnectionTrafficSecrets::Chacha20Poly1305 { key, iv },
        })
    }
}

struct Tls13Encrypter {
    cipher: AeadCipher,
    iv: Iv,
}

impl MessageEncrypter for Tls13Encrypter {
    fn encrypt(
        &mut self,
        msg: OutboundPlainMessage<'_>,
        seq: u64,
    ) -> Result<OutboundOpaqueMessage, Error> {
        let total_len = self.encrypted_payload_len(msg.payload.len());
        let mut payload = PrefixedPayload::with_capacity(total_len);
        payload.extend_from_chunks(&msg.payload);
        payload.extend_from_slice(&msg.typ.to_array());
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let tag = self.cipher.seal(&nonce, &aad, payload.as_mut())?;
        payload.extend_from_slice(&tag);
        // TLS 1.3 records carry the legacy 0x0303 version (RFC 8446 §5.1).
        Ok(OutboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, payload))
    }

    fn encrypted_payload_len(&self, payload_len: usize) -> usize {
        payload_len + 1 + AEAD_TAG_LEN
    }
}

struct Tls13Decrypter {
    cipher: AeadCipher,
    iv: Iv,
}

impl MessageDecrypter for Tls13Decrypter {
    fn decrypt<'a>(
        &mut self,
        mut msg: InboundOpaqueMessage<'a>,
        seq: u64,
    ) -> Result<InboundPlainMessage<'a>, Error> {
        let payload = &mut msg.payload;
        let total_len = payload.len();
        if total_len < AEAD_TAG_LEN {
            return Err(Error::DecryptError);
        }
        let nonce = Nonce::new(&self.iv, seq).0;
        let aad = make_tls13_aad(total_len);
        let plain_len = total_len - AEAD_TAG_LEN;
        let (body, tag) = payload.split_at_mut(plain_len);
        self.cipher.open(&nonce, &aad, body, tag)?;
        payload.truncate(plain_len);
        msg.into_tls13_unpadded_message()
    }
}

static AES_128_GCM: Tls13Aead = Tls13Aead(AeadKind::Aes128Gcm);
static CHACHA20_POLY1305: Tls13Aead = Tls13Aead(AeadKind::ChaCha20Poly1305);
static HKDF_SHA256: HkdfUsingHmac<'static> = HkdfUsingHmac(&HMAC_SHA256);

/// `TLS_AES_128_GCM_SHA256` (mandatory-to-implement, RFC 8446 §9.1).
pub static TLS13_AES_128_GCM_SHA256: SupportedCipherSuite = SupportedCipherSuite::Tls13(&Tls13CipherSuite {
    common: CipherSuiteCommon {
        suite: CipherSuite::TLS13_AES_128_GCM_SHA256,
        hash_provider: &SHA256,
        confidentiality_limit: 1 << 24,
    },
    hkdf_provider: &HKDF_SHA256,
    aead_alg: &AES_128_GCM,
    quic: None,
});

/// `TLS_CHACHA20_POLY1305_SHA256` (fast without AES hardware, as here).
pub static TLS13_CHACHA20_POLY1305_SHA256: SupportedCipherSuite =
    SupportedCipherSuite::Tls13(&Tls13CipherSuite {
        common: CipherSuiteCommon {
            suite: CipherSuite::TLS13_CHACHA20_POLY1305_SHA256,
            hash_provider: &SHA256,
            confidentiality_limit: u64::MAX,
        },
        hkdf_provider: &HKDF_SHA256,
        aead_alg: &CHACHA20_POLY1305,
        quic: None,
    });

// ------------------------------------------------------------------
// Key exchange (RFC 8446 §4.2.8)
// ------------------------------------------------------------------

/// X25519 (RFC 7748). The ephemeral secret comes from `rng`.
pub struct X25519 {
    rng: &'static KernelRng,
}

impl fmt::Debug for X25519 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("X25519")
    }
}

impl SupportedKxGroup for X25519 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let mut sk = [0u8; 32];
        self.rng.fill(&mut sk).map_err(|_| Error::FailedToGetRandomBytes)?;
        let secret = x25519_dalek::StaticSecret::from(sk);
        sk.zeroize();
        let public = x25519_dalek::PublicKey::from(&secret);
        Ok(Box::new(X25519Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

struct X25519Exchange {
    secret: x25519_dalek::StaticSecret,
    public: x25519_dalek::PublicKey,
}

impl ActiveKeyExchange for X25519Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        let peer: [u8; 32] = peer_pub_key
            .try_into()
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = self.secret.diffie_hellman(&x25519_dalek::PublicKey::from(peer));
        // An all-zero output means a low-order peer point (RFC 7748 §6.1).
        if !shared.was_contributory() {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        Ok(SharedSecret::from(&shared.as_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        self.public.as_bytes()
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::X25519
    }
}

/// secp256r1 ECDHE with uncompressed points (RFC 8446 §4.2.8.2).
pub struct Secp256r1 {
    rng: &'static KernelRng,
}

impl fmt::Debug for Secp256r1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("secp256r1")
    }
}

impl SupportedKxGroup for Secp256r1 {
    fn start(&self) -> Result<Box<dyn ActiveKeyExchange>, Error> {
        let secret = p256_secret_from_rng(self.rng)?;
        let public = secret.public_key().to_encoded_point(false).as_bytes().to_vec();
        Ok(Box::new(Secp256r1Exchange { secret, public }))
    }

    fn name(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

/// Rejection-sample a P-256 scalar in `[1, n)` from `rng`.
fn p256_secret_from_rng(rng: &KernelRng) -> Result<p256::SecretKey, Error> {
    let mut bytes = [0u8; 32];
    for _ in 0..64 {
        rng.fill(&mut bytes).map_err(|_| Error::FailedToGetRandomBytes)?;
        if let Ok(secret) = p256::SecretKey::from_slice(&bytes) {
            bytes.zeroize();
            return Ok(secret);
        }
    }
    bytes.zeroize();
    Err(Error::FailedToGetRandomBytes)
}

struct Secp256r1Exchange {
    secret: p256::SecretKey,
    public: Vec<u8>,
}

impl ActiveKeyExchange for Secp256r1Exchange {
    fn complete(self: Box<Self>, peer_pub_key: &[u8]) -> Result<SharedSecret, Error> {
        if peer_pub_key.len() != 65 || peer_pub_key[0] != 0x04 {
            return Err(PeerMisbehaved::InvalidKeyShare.into());
        }
        // `from_sec1_bytes` rejects points not on the curve and the identity.
        let peer = p256::PublicKey::from_sec1_bytes(peer_pub_key)
            .map_err(|_| Error::from(PeerMisbehaved::InvalidKeyShare))?;
        let shared = p256::ecdh::diffie_hellman(self.secret.to_nonzero_scalar(), peer.as_affine());
        Ok(SharedSecret::from(&shared.raw_secret_bytes()[..]))
    }

    fn pub_key(&self) -> &[u8] {
        &self.public
    }

    fn group(&self) -> NamedGroup {
        NamedGroup::secp256r1
    }
}

static SYSTEM_X25519: X25519 = X25519 { rng: &SYSTEM_RNG };
static SYSTEM_SECP256R1: Secp256r1 = Secp256r1 { rng: &SYSTEM_RNG };
#[cfg(any(test, not(cuttle_prod)))]
static GOLDEN_X25519: X25519 = X25519 { rng: &GOLDEN_RNG };
#[cfg(any(test, not(cuttle_prod)))]
static GOLDEN_SECP256R1: Secp256r1 = Secp256r1 { rng: &GOLDEN_RNG };

// ------------------------------------------------------------------
// ECDSA P-256 / SHA-256
// ------------------------------------------------------------------

/// The server's signing key. ECDSA nonces are derived per RFC 6979, so
/// signing needs no RNG and a given (key, message) always signs identically.
pub struct EcdsaP256SigningKey(p256::ecdsa::SigningKey);

impl EcdsaP256SigningKey {
    /// Wrap a P-256 signing key.
    pub fn new(key: p256::ecdsa::SigningKey) -> Self {
        Self(key)
    }

    /// Uncompressed SEC1 public key (65 bytes).
    pub fn public_key_sec1(&self) -> [u8; 65] {
        let point = self.0.verifying_key().to_encoded_point(false);
        let mut out = [0u8; 65];
        out.copy_from_slice(point.as_bytes());
        out
    }

    /// DER-encoded ECDSA-SHA256 signature over `message`.
    pub fn sign_der(&self, message: &[u8]) -> Vec<u8> {
        let sig: p256::ecdsa::Signature = self.0.sign(message);
        self.0
            .verifying_key()
            .verify(message, &sig)
            .expect("ECDSA P-256 self-verification failed");
        sig.to_der().as_bytes().to_vec()
    }
}

impl fmt::Debug for EcdsaP256SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaP256SigningKey")
    }
}

impl SigningKey for EcdsaP256SigningKey {
    fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
        if offered.contains(&SignatureScheme::ECDSA_NISTP256_SHA256) {
            Some(Box::new(EcdsaP256Signer(self.0.clone())))
        } else {
            None
        }
    }

    fn public_key(&self) -> Option<SubjectPublicKeyInfoDer<'_>> {
        Some(public_key_to_spki(&alg_id::ECDSA_P256, self.public_key_sec1()))
    }

    fn algorithm(&self) -> SignatureAlgorithm {
        SignatureAlgorithm::ECDSA
    }
}

struct EcdsaP256Signer(p256::ecdsa::SigningKey);

impl fmt::Debug for EcdsaP256Signer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("EcdsaP256Signer")
    }
}

impl Signer for EcdsaP256Signer {
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, Error> {
        let sig: p256::ecdsa::Signature = self
            .0
            .try_sign(message)
            .map_err(|_| Error::General("ECDSA signing failed".into()))?;
        self.0
            .verifying_key()
            .verify(message, &sig)
            .map_err(|_| Error::General("ECDSA signature self-verification failed".into()))?;
        Ok(sig.to_der().as_bytes().to_vec())
    }

    fn scheme(&self) -> SignatureScheme {
        SignatureScheme::ECDSA_NISTP256_SHA256
    }
}

/// ECDSA P-256 / SHA-256 verification (DER signature, SEC1 public key).
#[derive(Debug)]
pub struct EcdsaP256Sha256Verify;

/// Verify `signature` (DER) over `message` with a SEC1 P-256 `public_key`.
pub fn ecdsa_p256_sha256_verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
    let Ok(key) = p256::ecdsa::VerifyingKey::from_sec1_bytes(public_key) else {
        return false;
    };
    let Ok(sig) = p256::ecdsa::Signature::from_der(signature) else {
        return false;
    };
    key.verify(message, &sig).is_ok()
}

impl SignatureVerificationAlgorithm for EcdsaP256Sha256Verify {
    fn verify_signature(
        &self,
        public_key: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Result<(), InvalidSignature> {
        if ecdsa_p256_sha256_verify(public_key, message, signature) {
            Ok(())
        } else {
            Err(InvalidSignature)
        }
    }

    fn public_key_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_P256
    }

    fn signature_alg_id(&self) -> AlgorithmIdentifier {
        alg_id::ECDSA_SHA256
    }
}

static ECDSA_P256_SHA256: EcdsaP256Sha256Verify = EcdsaP256Sha256Verify;

static SIGNATURE_ALGORITHMS: WebPkiSupportedAlgorithms = WebPkiSupportedAlgorithms {
    all: &[&ECDSA_P256_SHA256],
    mapping: &[(SignatureScheme::ECDSA_NISTP256_SHA256, &[&ECDSA_P256_SHA256])],
};

/// The server key comes from [`crate::https::ServerIdentity`]; loading PEM/DER
/// private keys is not supported.
#[derive(Debug)]
struct NoKeyLoading;

impl KeyProvider for NoKeyLoading {
    fn load_private_key(&self, _key_der: PrivateKeyDer<'static>) -> Result<Arc<dyn SigningKey>, Error> {
        Err(Error::General("private-key loading is not supported; use https::ServerIdentity".into()))
    }
}

// ------------------------------------------------------------------
// Providers
// ------------------------------------------------------------------

fn provider_with(
    rng: &'static KernelRng,
    x25519: &'static X25519,
    secp256r1: &'static Secp256r1,
) -> CryptoProvider {
    CryptoProvider {
        cipher_suites: alloc::vec![TLS13_AES_128_GCM_SHA256, TLS13_CHACHA20_POLY1305_SHA256],
        kx_groups: alloc::vec![x25519 as &dyn SupportedKxGroup, secp256r1],
        signature_verification_algorithms: SIGNATURE_ALGORITHMS,
        secure_random: rng,
        key_provider: &NoKeyLoading,
    }
}

/// Provider for live traffic, drawing randomness from [`SYSTEM_RNG`].
pub fn system_provider() -> CryptoProvider {
    provider_with(&SYSTEM_RNG, &SYSTEM_X25519, &SYSTEM_SECP256R1)
}

/// Provider for the boot golden-transcript self-test ONLY: its randomness is
/// the deterministic [`reset_golden_rng`] stream, so every handshake it runs
/// is predictable. Never use it for a listening service.
#[cfg(any(test, not(cuttle_prod)))]
pub fn golden_provider() -> CryptoProvider {
    provider_with(&GOLDEN_RNG, &GOLDEN_X25519, &GOLDEN_SECP256R1)
}

// ------------------------------------------------------------------
// Known-answer self-test
// ------------------------------------------------------------------

/// What [`self_test`] covered.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SelfTestReport {
    /// AEAD vectors checked (AES-128-GCM, ChaCha20-Poly1305).
    pub aead: u8,
    /// Key-exchange vectors checked (X25519, P-256 ECDH RFC 5903).
    pub kx: u8,
    /// Signature vectors checked (ECDSA P-256 RFC 6979).
    pub sig: u8,
}

fn hex32(s: &str) -> [u8; 32] {
    let mut out = [0u8; 32];
    hex_into(s, &mut out);
    out
}

fn hex_into(s: &str, out: &mut [u8]) {
    let b = s.as_bytes();
    for (i, o) in out.iter_mut().enumerate() {
        let nib = |c: u8| match c {
            b'0'..=b'9' => c - b'0',
            b'a'..=b'f' => c - b'a' + 10,
            b'A'..=b'F' => c - b'A' + 10,
            _ => 0,
        };
        *o = (nib(b[2 * i]) << 4) | nib(b[2 * i + 1]);
    }
}

/// Run published known-answer vectors through the exact primitives this
/// provider uses, plus a TLS record round trip with tamper rejection:
///
/// - AES-128-GCM: McGrew & Viega GCM spec test cases 1, 2, and 4 (multi-block
///   with non-zero key/IV, 20-byte AAD, and partial final block).
/// - ChaCha20-Poly1305: RFC 8439 §2.8.2.
/// - HMAC-SHA256: RFC 4231 test case 2 via `HMAC_SHA256`.
/// - HKDF-SHA256: RFC 5869 test case 1 via `HKDF_SHA256`.
/// - X25519: RFC 7748 §6.1 (both public keys and the shared secret).
/// - ECDSA P-256 / SHA-256: RFC 6979 §A.2.5 deterministic signature of
///   "sample", then verification, then rejection of a flipped bit.
/// - P-256 ECDH: RFC 5903 §8.1 published key pair and shared secret `Z`.
/// - Record layer: each suite's encrypter/decrypter round-trips a record
///   and rejects a modified one.
pub fn self_test() -> Result<SelfTestReport, &'static str> {
    // AES-128-GCM, test case 1 (empty), 2 (one zero block), and 4 (multi-block + AAD + partial block).
    let gcm = AeadKind::Aes128Gcm.cipher(&[0u8; 16]);
    let mut empty = [0u8; 0];
    let tag1 = gcm.seal(&[0u8; 12], &[], &mut empty).map_err(|_| "AES-GCM seal")?;
    if tag1[..] != hex32("58e2fccefa7e3061367f1d57a4e7455a00000000000000000000000000000000")[..16] {
        return Err("AES-128-GCM test case 1");
    }
    let mut block = [0u8; 16];
    let tag2 = gcm.seal(&[0u8; 12], &[], &mut block).map_err(|_| "AES-GCM seal")?;
    let expect2 = hex32("0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
    if block[..] != expect2[..16] || tag2[..] != expect2[16..] {
        return Err("AES-128-GCM test case 2");
    }
    let mut key4 = [0u8; 16];
    hex_into("feffe9928665731c6d6a8f9467308308", &mut key4);
    let mut iv4 = [0u8; 12];
    hex_into("cafebabefacedbaddecaf888", &mut iv4);
    let mut aad4 = [0u8; 20];
    hex_into("feedfacedeadbeeffeedfacedeadbeefabaddad2", &mut aad4);
    let mut pt4_orig = [0u8; 60];
    hex_into(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        &mut pt4_orig,
    );
    let mut pt4 = pt4_orig;
    let mut expect_ct4 = [0u8; 60];
    hex_into(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        &mut expect_ct4,
    );
    let mut expect_tag4 = [0u8; 16];
    hex_into("5bc94fbc3221a5db94fae95ae7121a47", &mut expect_tag4);
    let gcm4 = AeadKind::Aes128Gcm.cipher(&key4);
    let tag4 = gcm4.seal(&iv4, &aad4, &mut pt4).map_err(|_| "AES-GCM case 4 seal")?;
    if pt4 != expect_ct4 || tag4 != expect_tag4 {
        return Err("AES-128-GCM test case 4");
    }
    gcm4.open(&iv4, &aad4, &mut pt4, &tag4).map_err(|_| "AES-GCM case 4 open")?;
    if pt4 != pt4_orig {
        return Err("AES-128-GCM test case 4 decrypt");
    }

    // HMAC-SHA256 RFC 4231 test case 2 via `HMAC_SHA256` (`hmac::Hmac`).
    let hmac_key = hmac::Hmac::with_key(&HMAC_SHA256, b"Jefe");
    let hmac_tag = hmac_key.sign_concat(b"what do ", &[b"ya want "], b"for nothing?");
    if hmac_tag.as_ref() != hex32("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843") {
        return Err("HMAC-SHA256 RFC 4231 test case 2");
    }

    // HKDF-SHA256 RFC 5869 test case 1 via `HKDF_SHA256` (`rustls::crypto::tls13::Hkdf`).
    let hkdf_salt: [u8; 13] = core::array::from_fn(|i| i as u8);
    let hkdf_info: [u8; 10] = core::array::from_fn(|i| 0xf0 + i as u8);
    let hkdf_expander = HKDF_SHA256.extract_from_secret(Some(&hkdf_salt), &[0x0b; 22]);
    let mut hkdf_okm = [0u8; 42];
    hkdf_expander
        .expand_slice(&[&hkdf_info[..5], &hkdf_info[5..]], &mut hkdf_okm)
        .map_err(|_| "HKDF-SHA256 expand")?;
    let mut expect_okm = [0u8; 42];
    hex_into(
        "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
        &mut expect_okm,
    );
    if hkdf_okm != expect_okm {
        return Err("HKDF-SHA256 RFC 5869 test case 1");
    }

    // ChaCha20-Poly1305, RFC 8439 §2.8.2.
    let mut key = [0u8; 32];
    for (i, k) in key.iter_mut().enumerate() {
        *k = 0x80 + i as u8;
    }
    let chacha = AeadKind::ChaCha20Poly1305.cipher(&key);
    let mut nonce = [0u8; 12];
    hex_into("070000004041424344454647", &mut nonce);
    let mut aad = [0u8; 12];
    hex_into("50515253c0c1c2c3c4c5c6c7", &mut aad);
    let mut text = *b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    let tag = chacha.seal(&nonce, &aad, &mut text).map_err(|_| "ChaCha20-Poly1305 seal")?;
    let mut expect_ct = [0u8; 114];
    hex_into(
        "d31a8d34648e60db7b86afbc53ef7ec2a4aded51296e08fea9e2b5a736ee62d63dbea45e8ca9671282fafb69da92728b1a71de0a9e060b2905d6a5b67ecd3b3692ddbd7f2d778b8c9803aee328091b58fab324e4fad675945585808b4831d7bc3ff4def08e4b7a9de576d26586cec64b6116",
        &mut expect_ct,
    );
    let mut expect_tag = [0u8; 16];
    hex_into("1ae10b594f09e26a7e902ecbd0600691", &mut expect_tag);
    if text != expect_ct || tag != expect_tag {
        return Err("ChaCha20-Poly1305 RFC 8439 2.8.2");
    }
    chacha.open(&nonce, &aad, &mut text, &tag).map_err(|_| "ChaCha20-Poly1305 open")?;
    if !text.starts_with(b"Ladies and Gentlemen") {
        return Err("ChaCha20-Poly1305 decrypt");
    }

    // X25519, RFC 7748 §6.1.
    let alice = x25519_dalek::StaticSecret::from(hex32(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let bob = x25519_dalek::StaticSecret::from(hex32(
        "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
    ));
    let alice_pub = x25519_dalek::PublicKey::from(&alice);
    let bob_pub = x25519_dalek::PublicKey::from(&bob);
    if *alice_pub.as_bytes() != hex32("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
        || *bob_pub.as_bytes() != hex32("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
    {
        return Err("X25519 RFC 7748 public keys");
    }
    let shared = hex32("4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742");
    let exchange = Box::new(X25519Exchange { secret: alice, public: alice_pub });
    let got = exchange.complete(bob_pub.as_bytes()).map_err(|_| "X25519 complete")?;
    if got.secret_bytes() != shared {
        return Err("X25519 RFC 7748 shared secret");
    }
    let low_order = Box::new(X25519Exchange { secret: bob, public: bob_pub });
    if low_order.complete(&[0u8; 32]).is_ok() {
        return Err("X25519 accepted a low-order point");
    }

    // ECDSA P-256 / SHA-256, RFC 6979 §A.2.5, message "sample".
    let sk = p256::ecdsa::SigningKey::from_slice(&hex32(
        "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721",
    ))
    .map_err(|_| "ECDSA key")?;
    let key = EcdsaP256SigningKey::new(sk);
    let pub_sec1 = key.public_key_sec1();
    if pub_sec1[1..33] != hex32("60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6")
        || pub_sec1[33..] != hex32("7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299")
    {
        return Err("ECDSA RFC 6979 public key");
    }
    let signer = key
        .choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256])
        .ok_or("ECDSA scheme not offered")?;
    let der = signer.sign(b"sample").map_err(|_| "ECDSA sign")?;
    let mut expect_der = [0u8; 72];
    hex_into(
        "3046022100efd48b2aacb6a8fd1140dd9cd45e81d69d2c877b56aaf991c34d0ea84eaf3716022100f7cb1c942d657c41d436c7a1b6e29f65f3e900dbb9aff4064dc4ab2f843acda8",
        &mut expect_der,
    );
    if der[..] != expect_der[..] {
        return Err("ECDSA RFC 6979 A.2.5 signature");
    }
    if !ecdsa_p256_sha256_verify(&pub_sec1, b"sample", &der) {
        return Err("ECDSA verify rejected a good signature");
    }
    let mut bad = der.clone();
    let last = bad.len() - 1;
    bad[last] ^= 0x01;
    if ecdsa_p256_sha256_verify(&pub_sec1, b"sample", &bad) {
        return Err("ECDSA verify accepted a bad signature");
    }

    // P-256 ECDH: published RFC 5903 §8.1 test vector (initiator i, responder r, shared secret Z).
    let a = p256::SecretKey::from_slice(&hex32(
        "c88f01f510d9ac3f70a292daa2316de544e9aab8afe84049c62a9c57862d1433",
    ))
    .map_err(|_| "P-256 RFC 5903 key i")?;
    let b = p256::SecretKey::from_slice(&hex32(
        "c6ef9c5d78ae012a011164acb397ce2088685d8f06bf9be0b283ab46476bee53",
    ))
    .map_err(|_| "P-256 RFC 5903 key r")?;
    let a_pub = a.public_key().to_encoded_point(false).as_bytes().to_vec();
    let b_pub = b.public_key().to_encoded_point(false).as_bytes().to_vec();
    if a_pub[1..33] != hex32("dad0b65394221cf9b051e1feca5787d098dfe637fc90b9ef945d0c3772581180")
        || a_pub[33..65] != hex32("5271a0461cdb8252d61f1c456fa3e59ab1f45b33accf5f58389e0577b8990bb3")
        || b_pub[1..33] != hex32("d12dfb5289c8d4f81208b70270398c342296970a0bccb74c736fc7554494bf63")
        || b_pub[33..65] != hex32("56fbf3ca366cc23e8157854c13c58d6aac23f046ada30f8353e74f33039872ab")
    {
        return Err("P-256 ECDH RFC 5903 public keys");
    }
    let expect_p256_shared = hex32("d6840f6b42f6edafd13116e0e12565202fef8e9ece7dce03812464d04b9442de");
    let ab = Box::new(Secp256r1Exchange { secret: a, public: a_pub.clone() })
        .complete(&b_pub)
        .map_err(|_| "P-256 ECDH a")?;
    let ba = Box::new(Secp256r1Exchange { secret: b, public: b_pub })
        .complete(&a_pub)
        .map_err(|_| "P-256 ECDH b")?;
    if ab.secret_bytes() != expect_p256_shared || ba.secret_bytes() != expect_p256_shared {
        return Err("P-256 ECDH RFC 5903 shared secret");
    }

    // Record layer: round trip and tamper rejection for both suites.
    for alg in [&AES_128_GCM, &CHACHA20_POLY1305] {
        record_round_trip(alg)?;
    }

    Ok(SelfTestReport { aead: 2, kx: 2, sig: 1 })
}

fn record_round_trip(alg: &Tls13Aead) -> Result<(), &'static str> {
    let key = [0x42u8; 32];
    let key = &key[..alg.key_len()];
    let iv = || Iv::from([0x24u8; 12]);
    let mut enc = Tls13Encrypter { cipher: alg.0.cipher(key), iv: iv() };
    let mut dec = Tls13Decrypter { cipher: alg.0.cipher(key), iv: iv() };
    let request: &[u8] = b"GET /healthz HTTP/1.1

";
    let plain = OutboundPlainMessage {
        typ: ContentType::ApplicationData,
        version: ProtocolVersion::TLSv1_2,
        payload: request.into(),
    };
    let sealed = enc.encrypt(plain, 7).map_err(|_| "record encrypt")?.encode();
    let mut good = sealed.clone();
    let opened = dec
        .decrypt(
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut good[5..]),
            7,
        )
        .map_err(|_| "record decrypt")?;
    if opened.payload != request || opened.typ != ContentType::ApplicationData {
        return Err("record round trip");
    }
    let mut tampered = sealed;
    tampered[9] ^= 0x01;
    let mut dec2 = Tls13Decrypter { cipher: alg.0.cipher(key), iv: iv() };
    let rejected = dec2
        .decrypt(
            InboundOpaqueMessage::new(ContentType::ApplicationData, ProtocolVersion::TLSv1_2, &mut tampered[5..]),
            7,
        )
        .is_err();
    if !rejected {
        return Err("record tamper accepted");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn known_answer_self_test_passes() {
        assert_eq!(self_test(), Ok(SelfTestReport { aead: 2, kx: 2, sig: 1 }));
    }

    #[test]
    fn unseeded_rng_fails_closed() {
        let rng = KernelRng::unseeded();
        let mut buf = [0u8; 8];
        assert!(rng.fill(&mut buf).is_err());
        rng.reseed([1u8; 32]);
        assert!(rng.fill(&mut buf).is_ok());
    }

    #[test]
    fn golden_rng_is_deterministic() {
        let _g = GOLDEN_LOCK.lock();
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        reset_golden_rng([9u8; 32]);
        GOLDEN_RNG.fill(&mut a).unwrap();
        reset_golden_rng([9u8; 32]);
        GOLDEN_RNG.fill(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn providers_offer_only_tls13_suites() {
        for p in [system_provider(), golden_provider()] {
            assert_eq!(p.cipher_suites.len(), 2);
            assert!(p.cipher_suites.iter().all(|s| s.tls13().is_some()));
            assert_eq!(p.kx_groups[0].name(), NamedGroup::X25519);
        }
    }

    #[test]
    fn secp256r1_rejects_compressed_and_off_curve_points() {
        let rng: &'static KernelRng = Box::leak(Box::new(KernelRng::unseeded()));
        rng.reseed([3u8; 32]);
        let group = Secp256r1 { rng };
        let kx = group.start().unwrap();
        let mut off_curve = [0u8; 65];
        off_curve[0] = 0x04;
        off_curve[64] = 1;
        assert!(kx.complete(&off_curve).is_err());
        let kx = group.start().unwrap();
        assert!(kx.complete(&[0x02; 33]).is_err());
    }

    #[test]
    fn kernel_rng_rekeys_after_every_fill() {
        let rng = KernelRng::unseeded();
        rng.reseed([0x42; 32]);
        let mut raw = ChaCha20Rng::from_seed([0x42; 32]);

        let mut d1 = [0u8; 32];
        let mut r1 = [0u8; 32];
        rng.fill(&mut d1).unwrap();
        raw.fill_bytes(&mut r1);
        assert_eq!(d1, r1, "first fill comes from initial seed");

        // Advance `raw` past the 32-byte rekey draw and check that a naive
        // continuation of the initial ChaCha20 stream does NOT match the
        // rekeyed generator's next output.
        let mut raw_next_seed = [0u8; 32];
        raw.fill_bytes(&mut raw_next_seed);
        let mut raw_continued = [0u8; 32];
        raw.fill_bytes(&mut raw_continued);

        let mut d2 = [0u8; 32];
        rng.fill(&mut d2).unwrap();
        assert_ne!(d2, raw_continued, "second fill must come from a fresh ChaCha20 key");

        let mut expected_rekeyed = ChaCha20Rng::from_seed(raw_next_seed);
        let mut r2 = [0u8; 32];
        expected_rekeyed.fill_bytes(&mut r2);
        assert_eq!(d2, r2, "second fill must match the rekeyed ChaCha20 instance");
    }

    #[test]
    fn validate_fw_cfg_device_key_rejects_wrong_size_and_zero_keys() {
        assert_eq!(validate_fw_cfg_device_key(31, &[1u8; 32]), None);
        assert_eq!(validate_fw_cfg_device_key(33, &[1u8; 32]), None);
        assert_eq!(validate_fw_cfg_device_key(32, &[1u8; 31]), None);
        assert_eq!(validate_fw_cfg_device_key(32, &[0u8; 32]), None);
        assert_eq!(validate_fw_cfg_device_key(32, &[7u8; 32]), Some([7u8; 32]));
    }

    #[test]
    fn derive_tls_rng_seed_requires_rdrand_or_tpm_and_mixes_node_context() {
        let words = [0x1122_3344_5566_7788u64; 16];
        let master = [0xAAu8; 32];
        let mac = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
        assert_eq!(
            derive_tls_rng_seed(&words, false, None, &master, mac, 1),
            None,
            "must fail closed when neither RDRAND nor TPM is available"
        );
        let (s_rdrand, src1) =
            derive_tls_rng_seed(&words, true, None, &master, mac, 1).expect("rdrand seed");
        assert_eq!(src1, "rdrand");
        let (s_tpm, src2) =
            derive_tls_rng_seed(&words, false, Some([0x55; 16]), &master, mac, 1).expect("tpm seed");
        assert_eq!(src2, "tpm");
        let (s_both, src3) =
            derive_tls_rng_seed(&words, true, Some([0x55; 16]), &master, mac, 1).expect("both seed");
        assert_eq!(src3, "rdrand+tpm");
        assert_ne!(s_rdrand, s_tpm);
        assert_ne!(s_rdrand, s_both);

        // Changing master key, MAC, or boot count must produce distinct seeds.
        let (s_mac2, _) =
            derive_tls_rng_seed(&words, true, None, &master, [0x52, 0x54, 0, 0, 0, 1], 1).unwrap();
        let (s_boot2, _) = derive_tls_rng_seed(&words, true, None, &master, mac, 2).unwrap();
        let (s_key2, _) = derive_tls_rng_seed(&words, true, None, &[0xBB; 32], mac, 1).unwrap();
        assert_ne!(s_rdrand, s_mac2);
        assert_ne!(s_rdrand, s_boot2);
        assert_ne!(s_rdrand, s_key2);
    }
}
