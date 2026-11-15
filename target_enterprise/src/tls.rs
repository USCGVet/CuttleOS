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

use sha2::{Digest, Sha256};

/// SHA-256 output length in bytes.
pub const HASH_LEN: usize = 32;
/// SHA-256 compression block length in bytes (RFC 2104).
const BLOCK_LEN: usize = 64;

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
    hmac_sha256_parts(key, &[data], out);
}

/// Streaming multi-part HMAC-SHA-256 (RFC 2104) over the concatenation of `parts` under `key`,
/// without intermediate fixed-size buffer copies, `.expect(...)`, or truncation. Writes 32 bytes to `out`.
pub fn hmac_sha256_parts(key: &[u8], parts: &[&[u8]], out: &mut [u8; HASH_LEN]) {
    let mut k_block = [0u8; BLOCK_LEN];
    if key.len() > BLOCK_LEN {
        let mut hashed: [u8; HASH_LEN] = Sha256::digest(key).into();
        k_block[..HASH_LEN].copy_from_slice(&hashed);
        crate::durable_seal::zeroize_secret_bytes(&mut hashed);
    } else {
        k_block[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    let mut i = 0usize;
    while i < BLOCK_LEN {
        ipad[i] ^= k_block[i];
        opad[i] ^= k_block[i];
        i += 1;
    }
    crate::durable_seal::zeroize_secret_bytes(&mut k_block);

    let mut inner = Sha256::new();
    inner.update(ipad);
    for part in parts {
        inner.update(part);
    }
    let mut inner_digest: [u8; HASH_LEN] = inner.finalize().into();
    crate::durable_seal::zeroize_secret_bytes(&mut ipad);

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    out.copy_from_slice(&outer.finalize());
    crate::durable_seal::zeroize_secret_bytes(&mut opad);
    crate::durable_seal::zeroize_secret_bytes(&mut inner_digest);
}

/// HKDF-Extract over SHA-256 (RFC 5869 §2.2): PRK = HMAC(salt, IKM). An empty
/// `salt` means 32 zero bytes, per the RFC.
pub fn hkdf_extract(salt: &[u8], ikm: &[u8], out: &mut [u8; HASH_LEN]) {
    if salt.is_empty() {
        hmac_sha256(&ZERO_HASH, ikm, out);
    } else {
        hmac_sha256(salt, ikm, out);
    }
}

fn hkdf_expand_multi_step(
    prk: &[u8; HASH_LEN],
    prev: &[u8],
    info_parts: &[&[u8]],
    counter: u8,
    out: &mut [u8; HASH_LEN],
) {
    let mut ipad = [0x36u8; BLOCK_LEN];
    let mut opad = [0x5cu8; BLOCK_LEN];
    let mut i = 0usize;
    while i < HASH_LEN {
        ipad[i] ^= prk[i];
        opad[i] ^= prk[i];
        i += 1;
    }
    let mut inner = Sha256::new();
    inner.update(ipad);
    inner.update(prev);
    for part in info_parts {
        inner.update(part);
    }
    inner.update([counter]);
    let mut inner_digest: [u8; HASH_LEN] = inner.finalize().into();
    crate::durable_seal::zeroize_secret_bytes(&mut ipad);

    let mut outer = Sha256::new();
    outer.update(opad);
    outer.update(inner_digest);
    out.copy_from_slice(&outer.finalize());
    crate::durable_seal::zeroize_secret_bytes(&mut opad);
    crate::durable_seal::zeroize_secret_bytes(&mut inner_digest);
}

/// Fallible HKDF-Expand over multi-part `info_parts` (RFC 5869 §2.3).
/// Returns `Err` without modifying `out` if `out.len() > 255 * HASH_LEN`.
pub fn try_hkdf_expand_multi(
    prk: &[u8; HASH_LEN],
    info_parts: &[&[u8]],
    out: &mut [u8],
) -> Result<(), &'static str> {
    if out.len() > 255 * HASH_LEN {
        return Err("hkdf_expand: output too long");
    }
    let mut t_block = [0u8; HASH_LEN];
    let mut written = 0usize;
    let mut counter = 1u8;
    while written < out.len() {
        let mut next_block = [0u8; HASH_LEN];
        let prev = if counter == 1 { &[][..] } else { &t_block[..] };
        hkdf_expand_multi_step(prk, prev, info_parts, counter, &mut next_block);
        t_block = next_block;
        crate::durable_seal::zeroize_secret_bytes(&mut next_block);
        let take = (out.len() - written).min(HASH_LEN);
        out[written..written + take].copy_from_slice(&t_block[..take]);
        written += take;
        counter = counter.wrapping_add(1);
    }
    crate::durable_seal::zeroize_secret_bytes(&mut t_block);
    Ok(())
}

/// Fallible HKDF-Expand over SHA-256 (RFC 5869 §2.3).
pub fn try_hkdf_expand(
    prk: &[u8; HASH_LEN],
    info: &[u8],
    out: &mut [u8],
) -> Result<(), &'static str> {
    try_hkdf_expand_multi(prk, &[info], out)
}

/// HKDF-Expand over SHA-256 (RFC 5869 §2.3). Writes `out.len()` bytes.
///
/// # Panics
/// If `out.len() > 255 * HASH_LEN` (8160), the RFC's limit.
pub fn hkdf_expand(prk: &[u8; HASH_LEN], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 255 * HASH_LEN, "hkdf_expand: output too long");
    let _ = try_hkdf_expand(prk, info, out);
}

/// Fallible HKDF-Expand-Label (RFC 8446 §7.1).
pub fn try_hkdf_expand_label(
    secret: &[u8; HASH_LEN],
    label: &[u8],
    context: &[u8],
    out: &mut [u8],
) -> Result<(), &'static str> {
    const PREFIX: &[u8] = b"tls13 ";
    let total_label_len = PREFIX
        .len()
        .checked_add(label.len())
        .filter(|&n| n <= 255)
        .ok_or("hkdf_expand_label: label too long")?;
    if context.len() > 255 {
        return Err("hkdf_expand_label: context too long");
    }
    let out_u16 = u16::try_from(out.len()).map_err(|_| "hkdf_expand_label: output too long")?;
    let len_be = out_u16.to_be_bytes();
    try_hkdf_expand_multi(
        secret,
        &[
            &len_be,
            &[total_label_len as u8],
            PREFIX,
            label,
            &[context.len() as u8],
            context,
        ],
        out,
    )
}

/// HKDF-Expand-Label (RFC 8446 §7.1). The `HkdfLabel` info is
/// `u16 length || u8 label_len || "tls13 " || label || u8 context_len || context`.
///
/// # Panics
/// If `"tls13 " + label` or `context` is longer than 255 bytes.
pub fn hkdf_expand_label(secret: &[u8; HASH_LEN], label: &[u8], context: &[u8], out: &mut [u8]) {
    const PREFIX: &[u8] = b"tls13 ";
    let total_label_len = PREFIX.len().saturating_add(label.len());
    assert!(total_label_len <= 255, "hkdf_expand_label: label too long");
    assert!(context.len() <= 255, "hkdf_expand_label: context too long");
    assert!(out.len() <= 255 * HASH_LEN, "hkdf_expand_label: output too long");
    let _ = try_hkdf_expand_label(secret, label, context, out);
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
    fn hmac_sha256_parts_rfc4231_test_case_2_streaming() {
        let mut out = [0u8; 32];
        hmac_sha256_parts(
            b"Jefe",
            &[b"what do ", b"ya want ", b"for ", b"nothing?"],
            &mut out,
        );
        assert_eq!(
            out,
            hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        );
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

    #[test]
    fn try_hkdf_expand_and_label_return_err_without_modifying_output() {
        let mut oversized = [0xAAu8; 255 * 32 + 1];
        assert!(try_hkdf_expand(&[0u8; 32], b"info", &mut oversized).is_err());
        assert!(oversized.iter().all(|&b| b == 0xAA));

        let mut out = [0xBBu8; 16];
        assert!(try_hkdf_expand_label(&[0u8; 32], &[b'x'; 250], b"", &mut out).is_err());
        assert!(try_hkdf_expand_label(&[0u8; 32], b"key", &[b'y'; 256], &mut out).is_err());
        assert_eq!(out, [0xBBu8; 16]);
    }
}
