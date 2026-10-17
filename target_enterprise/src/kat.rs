//! Known-Answer Test harness for kernel crypto — TASK-063.
//!
//! Runs the locked suite of FIPS 180-4 / RFC 4231 / RFC 5869
//! published vectors against the real SHA-256 / HMAC-SHA-256 /
//! HKDF primitives already living in [`crate::tls`]. A morph that
//! perturbs any of those algorithms fails a published vector in the
//! same cycle it is deployed.
//!
//! # Suite (exactly [`KAT_VECTOR_COUNT`] = 9)
//!
//! | Id | Name | Source |
//! |----|------|--------|
//! | 0 | sha256_empty | FIPS 180-4 |
//! | 1 | sha256_abc | FIPS 180-4 |
//! | 2 | sha256_million_a | FIPS 180-4 |
//! | 3–6 | hmac_rfc4231_1..4 | RFC 4231 §4.2–§4.5 |
//! | 7–8 | hkdf_rfc5869_1..2 | RFC 5869 §A.1–§A.2 |
//!
//! # Design notes
//!
//! * No `alloc`. Every expected digest is a compile-time constant.
//! * Million-`a` is hashed incrementally (64-byte chunks) so the
//!   kernel never materialises a 1 MiB buffer.
//! * HKDF vectors assert both PRK (Extract) and OKM (Expand).

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    KatId, KatResult, KatRunner, KatSuiteResult, KAT_DIGEST_LEN, KAT_VECTOR_COUNT,
};
use sha2::{Digest, Sha256};

use crate::tls::{hkdf_expand, hkdf_extract, hmac_sha256, sha256_into};

// ---------------------------------------------------------------------------
// Published digests (byte-exact against the standards)
// ---------------------------------------------------------------------------

/// SHA-256("") — FIPS 180-4 / RFC 6234.
pub const EXP_SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
    0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
    0xb8, 0x55,
];

/// SHA-256("abc") — FIPS 180-4 / RFC 6234.
pub const EXP_SHA256_ABC: [u8; 32] = [
    0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22,
    0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00,
    0x15, 0xad,
];

/// SHA-256 of 1_000_000 ASCII `'a'` bytes — FIPS 180-4.
pub const EXP_SHA256_MILLION_A: [u8; 32] = [
    0xcd, 0xc7, 0x6e, 0x5c, 0x99, 0x14, 0xfb, 0x92, 0x81, 0xa1, 0xc7, 0xe2, 0x84, 0xd7, 0x3e,
    0x67, 0xf1, 0x80, 0x9a, 0x48, 0xa4, 0x97, 0x20, 0x0e, 0x04, 0x6d, 0x39, 0xcc, 0xc7, 0x11,
    0x2c, 0xd0,
];

/// RFC 4231 §4.2 test case 1 expected HMAC.
pub const EXP_HMAC_RFC4231_1: [u8; 32] = [
    0xb0, 0x34, 0x4c, 0x61, 0xd8, 0xdb, 0x38, 0x53, 0x5c, 0xa8, 0xaf, 0xce, 0xaf, 0x0b, 0xf1,
    0x2b, 0x88, 0x1d, 0xc2, 0x00, 0xc9, 0x83, 0x3d, 0xa7, 0x26, 0xe9, 0x37, 0x6c, 0x2e, 0x32,
    0xcf, 0xf7,
];

/// RFC 4231 §4.3 test case 2 expected HMAC.
pub const EXP_HMAC_RFC4231_2: [u8; 32] = [
    0x5b, 0xdc, 0xc1, 0x46, 0xbf, 0x60, 0x75, 0x4e, 0x6a, 0x04, 0x24, 0x26, 0x08, 0x95, 0x75,
    0xc7, 0x5a, 0x00, 0x3f, 0x08, 0x9d, 0x27, 0x39, 0x83, 0x9d, 0xec, 0x58, 0xb9, 0x64, 0xec,
    0x38, 0x43,
];

/// RFC 4231 §4.4 test case 3 expected HMAC.
pub const EXP_HMAC_RFC4231_3: [u8; 32] = [
    0x77, 0x3e, 0xa9, 0x1e, 0x36, 0x80, 0x0e, 0x46, 0x85, 0x4d, 0xb8, 0xeb, 0xd0, 0x91, 0x81,
    0xa7, 0x29, 0x59, 0x09, 0x8b, 0x3e, 0xf8, 0xc1, 0x22, 0xd9, 0x63, 0x55, 0x14, 0xce, 0xd5,
    0x65, 0xfe,
];

/// RFC 4231 §4.5 test case 4 expected HMAC.
pub const EXP_HMAC_RFC4231_4: [u8; 32] = [
    0x82, 0x55, 0x8a, 0x38, 0x9a, 0x44, 0x3c, 0x0e, 0xa4, 0xcc, 0x81, 0x98, 0x99, 0xf2, 0x08,
    0x3a, 0x85, 0xf0, 0xfa, 0xa3, 0xe5, 0x78, 0xf8, 0x07, 0x7a, 0x2e, 0x3f, 0xf4, 0x67, 0x29,
    0x66, 0x5b,
];

/// RFC 5869 §A.1 case 1 PRK.
pub const EXP_HKDF1_PRK: [u8; 32] = [
    0x07, 0x77, 0x09, 0x36, 0x2c, 0x2e, 0x32, 0xdf, 0x0d, 0xdc, 0x3f, 0x0d, 0xc4, 0x7b, 0xba,
    0x63, 0x90, 0xb6, 0xc7, 0x3b, 0xb5, 0x0f, 0x9c, 0x31, 0x22, 0xec, 0x84, 0x4a, 0xd7, 0xc2,
    0xb3, 0xe5,
];

/// RFC 5869 §A.1 case 1 OKM (L=42).
pub const EXP_HKDF1_OKM: [u8; 42] = [
    0x3c, 0xb2, 0x5f, 0x25, 0xfa, 0xac, 0xd5, 0x7a, 0x90, 0x43, 0x4f, 0x64, 0xd0, 0x36, 0x2f,
    0x2a, 0x2d, 0x2d, 0x0a, 0x90, 0xcf, 0x1a, 0x5a, 0x4c, 0x5d, 0xb0, 0x2d, 0x56, 0xec, 0xc4,
    0xc5, 0xbf, 0x34, 0x00, 0x72, 0x08, 0xd5, 0xb8, 0x87, 0x18, 0x58, 0x65,
];

/// RFC 5869 §A.2 case 2 PRK.
pub const EXP_HKDF2_PRK: [u8; 32] = [
    0x06, 0xa6, 0xb8, 0x8c, 0x58, 0x53, 0x36, 0x1a, 0x06, 0x10, 0x4c, 0x9c, 0xeb, 0x35, 0xb4,
    0x5c, 0xef, 0x76, 0x00, 0x14, 0x90, 0x46, 0x71, 0x01, 0x4a, 0x19, 0x3f, 0x40, 0xc1, 0x5f,
    0xc2, 0x44,
];

/// RFC 5869 §A.2 case 2 OKM (L=82).
pub const EXP_HKDF2_OKM: [u8; 82] = [
    0xb1, 0x1e, 0x39, 0x8d, 0xc8, 0x03, 0x27, 0xa1, 0xc8, 0xe7, 0xf7, 0x8c, 0x59, 0x6a, 0x49,
    0x34, 0x4f, 0x01, 0x2e, 0xda, 0x2d, 0x4e, 0xfa, 0xd8, 0xa0, 0x50, 0xcc, 0x4c, 0x19, 0xaf,
    0xa9, 0x7c, 0x59, 0x04, 0x5a, 0x99, 0xca, 0xc7, 0x82, 0x72, 0x71, 0xcb, 0x41, 0xc6, 0x5e,
    0x59, 0x0e, 0x09, 0xda, 0x32, 0x75, 0x60, 0x0c, 0x2f, 0x09, 0xb8, 0x36, 0x77, 0x93, 0xa9,
    0xac, 0xa3, 0xdb, 0x71, 0xcc, 0x30, 0xc5, 0x81, 0x79, 0xec, 0x3e, 0x87, 0xc1, 0x4c, 0x01,
    0xd5, 0xc1, 0xf3, 0x43, 0x4f, 0x1d, 0x87,
];

// ---------------------------------------------------------------------------
// Primitive wrappers (thin, diversifiable)
// ---------------------------------------------------------------------------

/// SHA-256 of one million ASCII `'a'` bytes without materialising
/// the full input. Feeds 64-byte chunks of `0x61` into the hasher.
pub fn sha256_million_a(out: &mut [u8; KAT_DIGEST_LEN]) {
    let mut h = Sha256::new();
    let chunk = [b'a'; 64];
    let total: u32 = 1_000_000;
    let mut remaining = total;
    while remaining >= 64 {
        h.update(&chunk);
        remaining -= 64;
    }
    if remaining > 0 {
        h.update(&chunk[..remaining as usize]);
    }
    let d = h.finalize();
    out.copy_from_slice(&d);
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

/// Stateless KAT harness. Marker type for [`KatRunner`].
pub struct KatImpl;

impl KatRunner for KatImpl {
    fn run_all() -> KatSuiteResult {
        run_all_impl()
    }

    fn run_one(id: KatId) -> KatResult {
        run_one_impl(id)
    }
}

/// Free-function entry used by the kernel banner (diversifier alias-safe).
pub fn run_all_impl() -> KatSuiteResult {
    let mut passed: u8 = 0;
    let mut first_fail: Option<KatId> = None;
    let mut i: u8 = 0;
    while i < KAT_VECTOR_COUNT {
        let id = match KatId::from_u8(i) {
            Some(v) => v,
            None => break,
        };
        let r = run_one_impl(id);
        if r.pass {
            passed = passed.wrapping_add(1);
        } else if first_fail.is_none() {
            first_fail = Some(id);
        }
        i = i.wrapping_add(1);
    }
    KatSuiteResult {
        total: KAT_VECTOR_COUNT,
        passed,
        first_fail,
    }
}

/// Run a single locked vector.
pub fn run_one_impl(id: KatId) -> KatResult {
    match id {
        KatId::Sha256Empty => sha_vector(id, &[], &EXP_SHA256_EMPTY),
        KatId::Sha256Abc => sha_vector(id, b"abc", &EXP_SHA256_ABC),
        KatId::Sha256MillionA => {
            let mut actual = [0u8; KAT_DIGEST_LEN];
            sha256_million_a(&mut actual);
            KatResult {
                id,
                pass: actual == EXP_SHA256_MILLION_A,
                actual,
                expected: EXP_SHA256_MILLION_A,
                okm_match: true,
            }
        }
        KatId::HmacRfc4231Case1 => {
            let key = [0x0bu8; 20];
            hmac_vector(id, &key, b"Hi There", &EXP_HMAC_RFC4231_1)
        }
        KatId::HmacRfc4231Case2 => {
            hmac_vector(id, b"Jefe", b"what do ya want for nothing?", &EXP_HMAC_RFC4231_2)
        }
        KatId::HmacRfc4231Case3 => {
            let key = [0xaau8; 20];
            let mut data = [0xddu8; 50];
            // data is all 0xdd already
            let _ = &mut data;
            hmac_vector(id, &key, &data, &EXP_HMAC_RFC4231_3)
        }
        KatId::HmacRfc4231Case4 => {
            let mut key = [0u8; 25];
            let mut k = 0u8;
            while k < 25 {
                key[k as usize] = k.wrapping_add(1);
                k = k.wrapping_add(1);
            }
            let data = [0xcdu8; 50];
            hmac_vector(id, &key, &data, &EXP_HMAC_RFC4231_4)
        }
        KatId::HkdfRfc5869Case1 => {
            let ikm = [0x0bu8; 22];
            let salt = [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c,
            ];
            let info = [
                0xf0u8, 0xf1, 0xf2, 0xf3, 0xf4, 0xf5, 0xf6, 0xf7, 0xf8, 0xf9,
            ];
            hkdf_vector(
                id,
                &salt,
                &ikm,
                &info,
                &EXP_HKDF1_PRK,
                &EXP_HKDF1_OKM,
            )
        }
        KatId::HkdfRfc5869Case2 => {
            // IKM / salt / info are sequential 0x00.. / 0x60.. / 0xb0..
            let mut ikm = [0u8; 80];
            let mut salt = [0u8; 80];
            let mut info = [0u8; 80];
            let mut i = 0u8;
            while (i as usize) < 80 {
                ikm[i as usize] = i;
                salt[i as usize] = i.wrapping_add(0x60);
                info[i as usize] = i.wrapping_add(0xb0);
                i = i.wrapping_add(1);
            }
            hkdf_vector(
                id,
                &salt,
                &ikm,
                &info,
                &EXP_HKDF2_PRK,
                &EXP_HKDF2_OKM,
            )
        }
    }
}

fn sha_vector(id: KatId, data: &[u8], expected: &[u8; 32]) -> KatResult {
    let mut actual = [0u8; KAT_DIGEST_LEN];
    sha256_into(data, &mut actual);
    KatResult {
        id,
        pass: &actual == expected,
        actual,
        expected: *expected,
        okm_match: true,
    }
}

fn hmac_vector(id: KatId, key: &[u8], data: &[u8], expected: &[u8; 32]) -> KatResult {
    let mut actual = [0u8; KAT_DIGEST_LEN];
    hmac_sha256(key, data, &mut actual);
    KatResult {
        id,
        pass: &actual == expected,
        actual,
        expected: *expected,
        okm_match: true,
    }
}

fn hkdf_vector(
    id: KatId,
    salt: &[u8],
    ikm: &[u8],
    info: &[u8],
    exp_prk: &[u8; 32],
    exp_okm: &[u8],
) -> KatResult {
    let mut prk = [0u8; KAT_DIGEST_LEN];
    hkdf_extract(salt, ikm, &mut prk);
    // OKM buffer sized to the larger of the two cases (82).
    let mut okm = [0u8; 82];
    let n = exp_okm.len();
    assert!(n <= 82);
    hkdf_expand(&prk, info, &mut okm[..n]);
    let prk_ok = &prk == exp_prk;
    let okm_ok = &okm[..n] == exp_okm;
    KatResult {
        id,
        pass: prk_ok && okm_ok,
        actual: prk,
        expected: *exp_prk,
        okm_match: okm_ok,
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::{KatPrimitive, KatRunner, KAT_VECTOR_COUNT};

    #[test]
    fn suite_cardinality_locked() {
        assert_eq!(KAT_VECTOR_COUNT, 9);
        assert_eq!(KAT_DIGEST_LEN, 32);
    }

    #[test]
    fn kat_id_round_trips_0_through_8() {
        let mut i = 0u8;
        while i < KAT_VECTOR_COUNT {
            let id = KatId::from_u8(i).expect("id in range");
            assert_eq!(id as u8, i);
            i += 1;
        }
        assert!(KatId::from_u8(9).is_none());
        assert!(KatId::from_u8(255).is_none());
    }

    #[test]
    fn kat_id_primitive_classification() {
        assert_eq!(KatId::Sha256Empty.primitive(), KatPrimitive::Sha256);
        assert_eq!(KatId::Sha256Abc.primitive(), KatPrimitive::Sha256);
        assert_eq!(KatId::Sha256MillionA.primitive(), KatPrimitive::Sha256);
        assert_eq!(KatId::HmacRfc4231Case1.primitive(), KatPrimitive::HmacSha256);
        assert_eq!(KatId::HmacRfc4231Case4.primitive(), KatPrimitive::HmacSha256);
        assert_eq!(KatId::HkdfRfc5869Case1.primitive(), KatPrimitive::HkdfSha256);
        assert_eq!(KatId::HkdfRfc5869Case2.primitive(), KatPrimitive::HkdfSha256);
    }

    #[test]
    fn kat_id_names_are_stable() {
        assert_eq!(KatId::Sha256Empty.name(), "sha256_empty");
        assert_eq!(KatId::Sha256Abc.name(), "sha256_abc");
        assert_eq!(KatId::Sha256MillionA.name(), "sha256_million_a");
        assert_eq!(KatId::HmacRfc4231Case1.name(), "hmac_rfc4231_1");
        assert_eq!(KatId::HmacRfc4231Case2.name(), "hmac_rfc4231_2");
        assert_eq!(KatId::HmacRfc4231Case3.name(), "hmac_rfc4231_3");
        assert_eq!(KatId::HmacRfc4231Case4.name(), "hmac_rfc4231_4");
        assert_eq!(KatId::HkdfRfc5869Case1.name(), "hkdf_rfc5869_1");
        assert_eq!(KatId::HkdfRfc5869Case2.name(), "hkdf_rfc5869_2");
    }

    #[test]
    fn sha256_empty() {
        let r = KatImpl::run_one(KatId::Sha256Empty);
        assert!(r.pass, "actual={:02x?}", r.actual);
        assert_eq!(r.actual, EXP_SHA256_EMPTY);
        assert_eq!(r.expected, EXP_SHA256_EMPTY);
    }

    #[test]
    fn sha256_abc() {
        let r = KatImpl::run_one(KatId::Sha256Abc);
        assert!(r.pass);
        assert_eq!(r.actual, EXP_SHA256_ABC);
    }

    #[test]
    fn sha256_million_a_vector_passes() {
        let r = KatImpl::run_one(KatId::Sha256MillionA);
        assert!(r.pass, "actual={:02x?}", r.actual);
        assert_eq!(r.actual, EXP_SHA256_MILLION_A);
    }

    #[test]
    fn sha256_million_a_chunked_is_deterministic() {
        // Re-run the free function twice and demand equality against
        // the FIPS published digest (no 1 MiB allocation needed).
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        super::sha256_million_a(&mut a);
        super::sha256_million_a(&mut b);
        assert_eq!(a, b);
        assert_eq!(a, EXP_SHA256_MILLION_A);
    }

    #[test]
    fn hmac_rfc4231_case1() {
        let r = KatImpl::run_one(KatId::HmacRfc4231Case1);
        assert!(r.pass, "actual={:02x?}", r.actual);
        assert_eq!(r.actual, EXP_HMAC_RFC4231_1);
    }

    #[test]
    fn hmac_rfc4231_case2() {
        let r = KatImpl::run_one(KatId::HmacRfc4231Case2);
        assert!(r.pass, "actual={:02x?}", r.actual);
        assert_eq!(r.actual, EXP_HMAC_RFC4231_2);
    }

    #[test]
    fn hmac_rfc4231_case3() {
        let r = KatImpl::run_one(KatId::HmacRfc4231Case3);
        assert!(r.pass, "actual={:02x?}", r.actual);
        assert_eq!(r.actual, EXP_HMAC_RFC4231_3);
    }

    #[test]
    fn hmac_rfc4231_case4() {
        let r = KatImpl::run_one(KatId::HmacRfc4231Case4);
        assert!(r.pass, "actual={:02x?}", r.actual);
        assert_eq!(r.actual, EXP_HMAC_RFC4231_4);
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let r = KatImpl::run_one(KatId::HkdfRfc5869Case1);
        assert!(r.pass, "prk={:02x?} okm_match={}", r.actual, r.okm_match);
        assert_eq!(r.actual, EXP_HKDF1_PRK);
        assert!(r.okm_match);
    }

    #[test]
    fn hkdf_rfc5869_case2() {
        let r = KatImpl::run_one(KatId::HkdfRfc5869Case2);
        assert!(r.pass, "prk={:02x?} okm_match={}", r.actual, r.okm_match);
        assert_eq!(r.actual, EXP_HKDF2_PRK);
        assert!(r.okm_match);
    }

    #[test]
    fn run_all_passes_every_vector() {
        let suite = KatImpl::run_all();
        assert_eq!(suite.total, KAT_VECTOR_COUNT);
        assert_eq!(suite.passed, KAT_VECTOR_COUNT);
        assert!(suite.first_fail.is_none());
        assert!(suite.all_ok());
    }

    #[test]
    fn run_all_impl_matches_trait() {
        let a = run_all_impl();
        let b = KatImpl::run_all();
        assert_eq!(a, b);
    }

    #[test]
    fn each_vector_id_round_trips_through_run_one() {
        let mut i = 0u8;
        while i < KAT_VECTOR_COUNT {
            let id = KatId::from_u8(i).unwrap();
            let r = KatImpl::run_one(id);
            assert_eq!(r.id, id);
            assert!(r.pass, "vector {} failed", id.name());
            i += 1;
        }
    }

    #[test]
    fn expected_digests_are_nonzero_and_distinct() {
        // Sanity: the locked goldens are not all-zero and pairwise
        // distinct, so a zero-returning stub cannot pass by accident.
        let digests: [[u8; 32]; 7] = [
            EXP_SHA256_EMPTY,
            EXP_SHA256_ABC,
            EXP_SHA256_MILLION_A,
            EXP_HMAC_RFC4231_1,
            EXP_HMAC_RFC4231_2,
            EXP_HMAC_RFC4231_3,
            EXP_HMAC_RFC4231_4,
        ];
        for (i, d) in digests.iter().enumerate() {
            assert_ne!(*d, [0u8; 32], "digest {} is all-zero", i);
            let mut j = i + 1;
            while j < digests.len() {
                assert_ne!(d, &digests[j], "digest {} equals {}", i, j);
                j += 1;
            }
        }
    }

    #[test]
    fn sha256_empty_differs_from_abc() {
        assert_ne!(EXP_SHA256_EMPTY, EXP_SHA256_ABC);
    }

    #[test]
    fn hkdf_case1_okm_length_is_42() {
        assert_eq!(EXP_HKDF1_OKM.len(), 42);
    }

    #[test]
    fn hkdf_case2_okm_length_is_82() {
        assert_eq!(EXP_HKDF2_OKM.len(), 82);
    }

    #[test]
    fn source_citations_locked() {
        assert_eq!(KatId::Sha256Empty.source(), "FIPS 180-4 / RFC 6234");
        assert_eq!(KatId::HmacRfc4231Case1.source(), "RFC 4231");
        assert_eq!(KatId::HkdfRfc5869Case1.source(), "RFC 5869");
    }

    #[test]
    fn suite_result_all_ok_false_when_fail() {
        let bad = KatSuiteResult {
            total: 9,
            passed: 8,
            first_fail: Some(KatId::Sha256Abc),
        };
        assert!(!bad.all_ok());
    }

    #[test]
    fn free_function_run_one_matches_trait() {
        let a = run_one_impl(KatId::Sha256Abc);
        let b = KatImpl::run_one(KatId::Sha256Abc);
        assert_eq!(a, b);
    }

    #[test]
    fn hmac_case4_key_is_1_through_25() {
        // Guard the key-construction loop used inside run_one.
        let mut key = [0u8; 25];
        let mut k = 0u8;
        while k < 25 {
            key[k as usize] = k.wrapping_add(1);
            k += 1;
        }
        assert_eq!(key[0], 1);
        assert_eq!(key[24], 25);
        let mut got = [0u8; 32];
        hmac_sha256(&key, &[0xcdu8; 50], &mut got);
        assert_eq!(got, EXP_HMAC_RFC4231_4);
    }

    #[test]
    fn run_all_is_deterministic() {
        let a = KatImpl::run_all();
        let b = KatImpl::run_all();
        assert_eq!(a, b);
        assert!(a.all_ok());
    }
}
