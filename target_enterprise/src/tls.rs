//! TLS 1.3 key-schedule helpers (RFC 5869 HKDF, RFC 8446 §7.1) — `no_std`,
//! allocation-free, built on RustCrypto (`sha2`, `hmac`, `hkdf`).
//!
//! The TLS 1.3 *protocol* (handshake, record layer, alerts) is rustls, driven
//! by [`crate::https`] with the RustCrypto provider in [`crate::tls_provider`].
//! The hand-written handshake, the hand-written X25519 and the toy record cipher
//! this module used to contain have been removed.
//!
//! What stays here is the standard key-derivation plumbing that other kernel
//! subsystems share: durable seals, the HMAC-DRBG expander, boot KATs, device-key
//! provisioning and the morph experiments all call these by name. Every function
//! keeps its original signature and output bytes; the KATs below pin them to the
//! published RFC vectors.

use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

/// SHA-256 output length in bytes.
pub const HASH_LEN: usize = 32;

/// All-zero 32-byte buffer: the PSK IKM in the TLS 1.3 early-secret step
/// (RFC 8446 §7.1, "a string of Hash.length bytes set to zeros").
pub const ZERO_HASH: [u8; HASH_LEN] = [0u8; HASH_LEN];

/// `SHA-256("")`, the transcript hash used for the `derived` Derive-Secret.
pub const SHA256_EMPTY: [u8; HASH_LEN] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

/// HMAC-SHA-256 (RFC 2104) of `data` under `key`. Writes 32 bytes to `out`.
pub fn hmac_sha256(key: &[u8], data: &[u8], out: &mut [u8; HASH_LEN]) {
    // `new_from_slice` accepts keys of any length (long keys are pre-hashed).
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC accepts any key length");
    mac.update(data);
    out.copy_from_slice(&mac.finalize().into_bytes());
}

/// HKDF-Extract over SHA-256 (RFC 5869 §2.2): PRK = HMAC(salt, IKM). An empty
/// `salt` means 32 zero bytes, per the RFC.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8], out: &mut [u8; HASH_LEN]) {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let (prk, _) = Hkdf::<Sha256>::extract(salt, ikm);
    out.copy_from_slice(&prk);
}

/// HKDF-Expand over SHA-256 (RFC 5869 §2.3). Writes `out.len()` bytes.
///
/// # Panics
/// If `out.len() > 255 * HASH_LEN` (8160), the RFC's limit.
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * HASH_LEN, "hkdf_expand: output too long");
    let hk = Hkdf::<Sha256>::from_prk(prk).expect("a 32-byte PRK is valid for SHA-256");
    hk.expand(info, out).expect("output length checked above");
}

/// HKDF-Expand-Label (RFC 8446 §7.1). The `HkdfLabel` info is
/// `u16 length || u8 label_len || "tls13 " || label || u8 context_len || context`.
///
/// # Panics
/// If `"tls13 " + label` or `context` is longer than 255 bytes.
pub fn hkdf_expand_label(secret: &[u8; HASH_LEN], label: &[u8], context: &[u8], out: &mut [u8]) {
    const PREFIX: &[u8] = b"tls13 ";
    let total_label_len = PREFIX.len() + label.len();
    assert!(total_label_len <= 255, "hkdf_expand_label: label too long");
    assert!(context.len() <= 255, "hkdf_expand_label: context too long");
    let len_be = (out.len() as u16).to_be_bytes();
    let hk = Hkdf::<Sha256>::from_prk(secret).expect("a 32-byte secret is valid for SHA-256");
    hk.expand_multi_info(
        &[&len_be, &[total_label_len as u8], PREFIX, label, &[context.len() as u8], context],
        out,
    )
    .expect("TLS 1.3 labels never exceed the HKDF output limit");
}

/// Derive-Secret(secret, label, messages) (RFC 8446 §7.1): HKDF-Expand-Label
/// with `SHA-256(messages)` as the context. Writes 32 bytes to `out`.
pub fn derive_secret(secret: &[u8; HASH_LEN], label: &[u8], messages: &[u8], out: &mut [u8; HASH_LEN]) {
    let mut transcript_hash = [0u8; HASH_LEN];
    sha256_into(messages, &mut transcript_hash);
    hkdf_expand_label(secret, label, &transcript_hash, out);
}

/// SHA-256 of `data`. Writes 32 bytes to `out`.
pub fn sha256_into(data: &[u8], out: &mut [u8; HASH_LEN]) {
    out.copy_from_slice(&Sha256::digest(data));
}

/// SHA-256 of `a || b`, without concatenating into a temporary buffer.
pub fn sha256_concat_into(a: &[u8], b: &[u8], out: &mut [u8; HASH_LEN]) {
    let mut h = Sha256::new();
    h.update(a);
    h.update(b);
    out.copy_from_slice(&h.finalize());
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(s: &str) -> [u8; 32] {
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_1() {
        let mut out = [0u8; 32];
        hmac_sha256(&[0x0b; 20], b"Hi There", &mut out);
        assert_eq!(out, hex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"));
    }

    #[test]
    fn hmac_sha256_rfc4231_test_case_6_long_key_is_prehashed() {
        let mut out = [0u8; 32];
        hmac_sha256(&[0xaa; 131], b"Test Using Larger Than Block-Size Key - Hash Key First", &mut out);
        assert_eq!(out, hex("60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54"));
    }

    #[test]
    fn hkdf_rfc5869_test_case_1() {
        let salt: [u8; 13] = core::array::from_fn(|i| i as u8);
        let info: [u8; 10] = core::array::from_fn(|i| 0xf0 + i as u8);
        let mut prk = [0u8; 32];
        hkdf_extract(&salt, &[0x0b; 22], &mut prk);
        assert_eq!(prk, hex("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
        let mut okm = [0u8; 42];
        hkdf_expand(&prk, &info, &mut okm);
        assert_eq!(&okm[..32], &hex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"));
        assert_eq!(&okm[32..], &[0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65]);
    }

    #[test]
    fn hkdf_extract_empty_salt_equals_zero_salt() {
        let (mut a, mut b) = ([0u8; 32], [0u8; 32]);
        hkdf_extract(&[], b"ikm", &mut a);
        hkdf_extract(&[0u8; 32], b"ikm", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn rfc8448_early_secret_and_derived_secret() {
        // RFC 8448 §3 (simple 1-RTT handshake): early secret and the "derived" secret.
        let mut early = [0u8; 32];
        hkdf_extract(&[], &ZERO_HASH, &mut early);
        assert_eq!(early, hex("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));
        let mut derived = [0u8; 32];
        derive_secret(&early, b"derived", b"", &mut derived);
        assert_eq!(derived, hex("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));
    }

    #[test]
    fn sha256_empty_matches_known_constant() {
        let mut out = [0u8; 32];
        sha256_into(b"", &mut out);
        assert_eq!(out, SHA256_EMPTY);
        let mut cat = [0u8; 32];
        sha256_concat_into(b"", b"", &mut cat);
        assert_eq!(cat, SHA256_EMPTY);
    }

    #[test]
    #[should_panic(expected = "output too long")]
    fn hkdf_expand_rejects_oversized_output() {
        let mut out = [0u8; 255 * 32 + 1];
        hkdf_expand(&[0u8; 32], b"", &mut out);
    }

    #[test]
    #[should_panic(expected = "label too long")]
    fn hkdf_expand_label_rejects_oversized_label() {
        let mut out = [0u8; 16];
        hkdf_expand_label(&[0u8; 32], &[b'a'; 250], b"", &mut out);
    }
}
