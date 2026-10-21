//! Known-answer tests for the TLS 1.3 building blocks.
//!
//! 1. **Key schedule** (`target_enterprise::tls`): RFC 5869 HKDF test cases
//!    1 and 3, and the RFC 8448 §3 early secret → `derived` → handshake
//!    secret chain, byte-for-byte.
//! 2. **Provider** (`target_enterprise::tls_provider`): AES-128-GCM (GCM spec
//!    test cases 1–2), ChaCha20-Poly1305 (RFC 8439 §2.8.2), X25519 (RFC 7748
//!    §6.1), ECDSA P-256 / SHA-256 (RFC 6979 §A.2.5) and a record-layer
//!    round trip — the same self-test the kernel runs at every boot.
//!
//! The TLS 1.3 protocol itself is rustls; its interoperability with an
//! independent client is covered by `tests/https_interop.rs`.

use target_enterprise::tls::{derive_secret, hkdf_expand, hkdf_expand_label, hkdf_extract, ZERO_HASH};
use target_enterprise::tls_provider;

fn hex<const N: usize>(s: &str) -> [u8; N] {
    let mut out = [0u8; N];
    for (i, b) in out.iter_mut().enumerate() {
        *b = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap();
    }
    out
}

#[test]
fn hkdf_rfc5869_test_case_1() {
    let salt: [u8; 13] = core::array::from_fn(|i| i as u8);
    let info: [u8; 10] = core::array::from_fn(|i| 0xf0 + i as u8);
    let mut prk = [0u8; 32];
    hkdf_extract(&salt, &[0x0b; 22], &mut prk);
    assert_eq!(prk, hex::<32>("077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"));
    let mut okm = [0u8; 42];
    hkdf_expand(&prk, &info, &mut okm);
    assert_eq!(
        okm,
        hex::<42>("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    );
}

#[test]
fn hkdf_rfc5869_test_case_3_empty_salt_and_info() {
    let mut prk = [0u8; 32];
    hkdf_extract(&[], &[0x0b; 22], &mut prk);
    assert_eq!(prk, hex::<32>("19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"));
    let mut okm = [0u8; 42];
    hkdf_expand(&prk, &[], &mut okm);
    assert_eq!(
        okm,
        hex::<42>("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8")
    );
}

#[test]
fn rfc8448_key_schedule_through_handshake_secret() {
    // RFC 8448 §3 "Simple 1-RTT Handshake".
    let mut early = [0u8; 32];
    hkdf_extract(&[], &ZERO_HASH, &mut early);
    assert_eq!(early, hex::<32>("33ad0a1c607ec03b09e6cd9893680ce210adf300aa1f2660e1b22e10f170f92a"));

    let mut derived = [0u8; 32];
    derive_secret(&early, b"derived", b"", &mut derived);
    assert_eq!(derived, hex::<32>("6f2615a108c702c5678f54fc9dbab69716c076189c48250cebeac3576c3611ba"));

    // Same step through hkdf_expand_label with SHA-256("") as the context.
    let mut via_label = [0u8; 32];
    hkdf_expand_label(&early, b"derived", &target_enterprise::tls::SHA256_EMPTY, &mut via_label);
    assert_eq!(via_label, derived);

    let ecdhe = hex::<32>("8bd4054fb55b9d63fdfbacf9f04b9f0d35e6d63f537563efd46272900f89492d");
    let mut handshake = [0u8; 32];
    hkdf_extract(&derived, &ecdhe, &mut handshake);
    assert_eq!(handshake, hex::<32>("1dc826e93606aa6fdc0aadc12f741b01046aa6b99f691ed221a9f0ca043fbeac"));
}

#[test]
fn provider_known_answer_self_test() {
    let report = tls_provider::self_test().expect("provider KATs");
    assert_eq!((report.aead, report.kx, report.sig), (2, 2, 1));
}

#[test]
fn provider_offers_tls13_aes_gcm_and_chacha_with_x25519_first() {
    let p = tls_provider::system_provider();
    let suites: Vec<_> = p.cipher_suites.iter().map(|s| s.suite()).collect();
    assert_eq!(
        suites,
        [rustls::CipherSuite::TLS13_AES_128_GCM_SHA256, rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256]
    );
    let groups: Vec<_> = p.kx_groups.iter().map(|g| g.name()).collect();
    assert_eq!(groups, [rustls::NamedGroup::X25519, rustls::NamedGroup::secp256r1]);
}
