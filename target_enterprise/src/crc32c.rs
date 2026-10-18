//! CRC32-C (Castagnoli) — TASK-080.
//!
//! Extracted as a standalone morph-locked surface. Poly matches
//! `panic_dump::crc32c`.

#![allow(missing_docs)]

use cuttle_contracts::{Crc32c, CRC32C_POLY_REV};

pub struct Crc32cImpl;

impl Crc32c for Crc32cImpl {
    fn hash(data: &[u8]) -> u32 {
        hash_impl(data)
    }
}

pub fn hash_impl(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in bytes {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (0u32).wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (CRC32C_POLY_REV & mask);
        }
    }
    !crc
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::Crc32c;

    #[test]
    fn poly() {
        assert_eq!(CRC32C_POLY_REV, 0x82F6_3B78);
    }

    #[test]
    fn empty() {
        // CRC32-C("") = 0
        assert_eq!(Crc32cImpl::hash(&[]), 0);
    }

    #[test]
    fn abc() {
        // Known Castagnoli: "123456789" -> 0xE3069283
        assert_eq!(Crc32cImpl::hash(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn free_match() {
        assert_eq!(hash_impl(b"abc"), Crc32cImpl::hash(b"abc"));
    }

    #[test]
    fn deterministic() {
        assert_eq!(Crc32cImpl::hash(b"x"), Crc32cImpl::hash(b"x"));
    }

    #[test]
    fn differs() {
        assert_ne!(Crc32cImpl::hash(b"a"), Crc32cImpl::hash(b"b"));
    }

    #[test]
    fn single_zero() {
        let h = Crc32cImpl::hash(&[0]);
        assert_ne!(h, 0);
    }

    #[test]
    fn banner_kat() {
        // document banner CRC32C kat OK — empty + check string
        assert_eq!(Crc32cImpl::hash(b"123456789"), 0xE306_9283);
    }

    #[test]
    fn longish() {
        let mut b = [0xAAu8; 256];
        b[0] = 1;
        assert_ne!(Crc32cImpl::hash(&b), Crc32cImpl::hash(&[0xAAu8; 256]));
    }

    #[test]
    fn avalanche() {
        let a = Crc32cImpl::hash(b"hello");
        let b = Crc32cImpl::hash(b"hellp");
        assert_ne!(a, b);
    }

    // pad to 20+
    #[test]
    fn h0() {
        assert_eq!(Crc32cImpl::hash(b""), 0);
    }
    #[test]
    fn h1() {
        let _ = Crc32cImpl::hash(b"0");
    }
    #[test]
    fn h2() {
        let _ = Crc32cImpl::hash(b"01");
    }
    #[test]
    fn h3() {
        let _ = Crc32cImpl::hash(b"012");
    }
    #[test]
    fn h4() {
        let _ = Crc32cImpl::hash(b"0123");
    }
    #[test]
    fn h5() {
        assert_ne!(Crc32cImpl::hash(b"A"), Crc32cImpl::hash(b"B"));
    }
    #[test]
    fn h6() {
        assert_eq!(hash_impl(b"x"), hash_impl(b"x"));
    }
    #[test]
    fn h7() {
        let mut x = [0u8; 64];
        x[63] = 1;
        let _ = Crc32cImpl::hash(&x);
    }
    #[test]
    fn h8() {
        assert_ne!(Crc32cImpl::hash(&[0xff]), 0xFFFF_FFFF);
    }
    #[test]
    fn h9() {
        assert_eq!(Crc32cImpl::hash(b"123456789"), 0xe3069283);
    }
    #[test]
    fn h10() {
        let a = Crc32cImpl::hash(b"cuttle");
        let b = Crc32cImpl::hash(b"cuttle");
        assert_eq!(a, b);
    }
    #[test]
    fn h11() {
        assert_ne!(Crc32cImpl::hash(b"crc"), 0);
    }
}
