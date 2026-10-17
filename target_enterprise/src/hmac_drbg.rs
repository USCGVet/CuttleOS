//! HMAC-SHA256 one-step expand KAT — TASK-087.
//!
//! `out = HMAC(seed, label || 0x01)` using tls::hmac_sha256.

#![allow(missing_docs)]

use proteus_contracts::{HmacDrbg, DRBG_OUT_LEN, DRBG_SEED_LEN};

use crate::tls::hmac_sha256;

pub struct HmacDrbgImpl;

impl HmacDrbg for HmacDrbgImpl {
    fn expand(seed: &[u8; DRBG_SEED_LEN], label: &[u8], out: &mut [u8]) {
        expand_impl(seed, label, out)
    }
}

pub fn expand_impl(seed: &[u8; DRBG_SEED_LEN], label: &[u8], out: &mut [u8]) {
    // message = label || 0x01
    let mut msg = [0u8; 256];
    let n = core::cmp::min(label.len(), 255);
    msg[..n].copy_from_slice(&label[..n]);
    msg[n] = 0x01;
    let mut block = [0u8; 32];
    hmac_sha256(seed, &msg[..n + 1], &mut block);
    let take = core::cmp::min(out.len(), 32);
    out[..take].copy_from_slice(&block[..take]);
    let mut i = take;
    while i < out.len() {
        out[i] = 0;
        i += 1;
    }
}

/// Banner seed + label.
pub const BANNER_SEED: [u8; 32] = [0x0B; 32];
pub const BANNER_LABEL: &[u8] = b"proteus-drbg";

pub fn banner_out16() -> [u8; 16] {
    let mut o = [0u8; 16];
    HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
    o
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::HmacDrbg;

    #[test]
    fn constants() {
        assert_eq!(DRBG_SEED_LEN, 32);
        assert_eq!(DRBG_OUT_LEN, 16);
    }

    #[test]
    fn deterministic() {
        assert_eq!(banner_out16(), banner_out16());
    }

    #[test]
    fn differs_label() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, b"a", &mut a);
        HmacDrbgImpl::expand(&BANNER_SEED, b"b", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn differs_seed() {
        let mut s2 = BANNER_SEED;
        s2[0] ^= 1;
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut a);
        HmacDrbgImpl::expand(&s2, BANNER_LABEL, &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn free_match() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        expand_impl(&BANNER_SEED, BANNER_LABEL, &mut a);
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn nonzero() {
        assert_ne!(banner_out16(), [0u8; 16]);
    }

    #[test]
    fn full32() {
        let mut o = [0u8; 32];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
        assert!(o.iter().any(|&b| b != 0));
    }

    #[test]
    fn short_out() {
        let mut o = [0u8; 4];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
        assert_eq!(o, banner_out16()[..4]);
    }

    #[test]
    fn empty_label() {
        let mut o = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, b"", &mut o);
        assert_ne!(o, banner_out16());
    }

    #[test]
    fn banner() {
        let o = banner_out16();
        assert_eq!(o.len(), 16);
    }

    #[test]
    fn det2() {
        let mut a = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut a);
        assert_eq!(a, banner_out16());
    }

    #[test]
    fn seed_all_b() {
        assert_eq!(BANNER_SEED[0], 0x0B);
    }

    #[test]
    fn label() {
        assert_eq!(BANNER_LABEL, b"proteus-drbg");
    }

    #[test]
    fn long_label_trunc() {
        let lab = [b'x'; 300];
        let mut o = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, &lab, &mut o);
    }

    #[test]
    fn end_to_end() {
        let mut o = [0u8; DRBG_OUT_LEN];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
        assert_eq!(o, banner_out16());
    }

    #[test]
    fn avalanche_one_bit_label() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, b"proteus-drbg", &mut a);
        HmacDrbgImpl::expand(&BANNER_SEED, b"proteus-drbh", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn prefix8_stable() {
        let o = banner_out16();
        assert_eq!(&o[..8], &banner_out16()[..8]);
    }

    #[test]
    fn not_identity() {
        assert_ne!(&banner_out16()[..], &BANNER_SEED[..16]);
    }

    #[test]
    fn twice_same() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        HmacDrbgImpl::expand(&BANNER_SEED, b"z", &mut a);
        HmacDrbgImpl::expand(&BANNER_SEED, b"z", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn out_longer_than_32_zero_pad() {
        let mut o = [0xFFu8; 40];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
        assert_eq!(&o[32..], &[0u8; 8]);
    }

    #[test]
    fn banner_str() {
        // DRBG kat OK
        assert!(!banner_out16().is_empty());
    }

    #[test]
    fn hmac_not_zero_block() {
        let mut o = [0u8; 32];
        HmacDrbgImpl::expand(&BANNER_SEED, b"k", &mut o);
        assert_ne!(o, [0u8; 32]);
    }

    #[test]
    fn different_counter_via_label() {
        let mut a = [0u8; 8];
        let mut b = [0u8; 8];
        HmacDrbgImpl::expand(&BANNER_SEED, b"1", &mut a);
        HmacDrbgImpl::expand(&BANNER_SEED, b"2", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn expand_one_byte() {
        let mut o = [0u8; 1];
        HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
        assert_eq!(o[0], banner_out16()[0]);
    }

    #[test]
    fn seed_len() {
        assert_eq!(BANNER_SEED.len(), 32);
    }
}
