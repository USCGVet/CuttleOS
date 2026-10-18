//! Stack canary / SSP token surface — TASK-068.
//!
//! Mint a distinct 8-byte token from a seed, verify, and produce a
//! fail fingerprint on mismatch. No live stack placement.

#![allow(missing_docs)]

use cuttle_contracts::{CanaryError, CanaryToken, StackCanary, STACK_CANARY_LEN};

/// Stateless stack-canary impl.
pub struct StackCanaryImpl;

impl StackCanary for StackCanaryImpl {
    fn mint(seed: &[u8; STACK_CANARY_LEN]) -> Result<CanaryToken, CanaryError> {
        mint_impl(seed)
    }
    fn verify(expected: &CanaryToken, got: &CanaryToken) -> Result<(), CanaryError> {
        verify_impl(expected, got)
    }
    fn fail_fingerprint(expected: &CanaryToken, got: &CanaryToken) -> u64 {
        fail_fingerprint_impl(expected, got)
    }
}

/// Mix seed into a canary: rotate + XOR with a locked constant so
/// identical seeds still differ from the raw seed (harder to leak).
pub fn mint_impl(seed: &[u8; STACK_CANARY_LEN]) -> Result<CanaryToken, CanaryError> {
    let mut all_zero = true;
    let mut i = 0usize;
    while i < STACK_CANARY_LEN {
        if seed[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    if all_zero {
        return Err(CanaryError::WeakSeed);
    }
    // Locked mix constant (not a secret — just diversifies the token).
    const MIX: [u8; 8] = [0xCA, 0xFE, 0xF0, 0x0D, 0xDE, 0xAD, 0xBE, 0xEF];
    let mut bytes = [0u8; STACK_CANARY_LEN];
    i = 0;
    while i < STACK_CANARY_LEN {
        let s = seed[i];
        let rot = s.rotate_left((i as u32) + 1);
        bytes[i] = rot ^ MIX[i] ^ (i as u8).wrapping_mul(0x1B);
        i += 1;
    }
    // Ensure terminator-style high bit on last byte (classic SSP).
    bytes[STACK_CANARY_LEN - 1] |= 0x80;
    Ok(CanaryToken { bytes })
}

pub fn verify_impl(expected: &CanaryToken, got: &CanaryToken) -> Result<(), CanaryError> {
    let mut i = 0usize;
    while i < STACK_CANARY_LEN {
        if expected.bytes[i] != got.bytes[i] {
            return Err(CanaryError::Mismatch);
        }
        i += 1;
    }
    Ok(())
}

pub fn fail_fingerprint_impl(expected: &CanaryToken, got: &CanaryToken) -> u64 {
    let mut x = [0u8; 8];
    let mut i = 0usize;
    while i < 8 {
        x[i] = expected.bytes[i] ^ got.bytes[i];
        i += 1;
    }
    u64::from_le_bytes(x)
}

/// Locked banner seed.
pub const BANNER_SEED: [u8; 8] = [0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF];

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::StackCanary;

    #[test]
    fn len_is_8() {
        assert_eq!(STACK_CANARY_LEN, 8);
    }

    #[test]
    fn mint_rejects_zero_seed() {
        assert_eq!(
            StackCanaryImpl::mint(&[0; 8]),
            Err(CanaryError::WeakSeed)
        );
    }

    #[test]
    fn mint_deterministic() {
        let a = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let b = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn mint_differs_from_seed() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        assert_ne!(t.bytes, BANNER_SEED);
    }

    #[test]
    fn mint_differs_across_seeds() {
        let a = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let mut s2 = BANNER_SEED;
        s2[0] ^= 1;
        let b = StackCanaryImpl::mint(&s2).unwrap();
        assert_ne!(a.bytes, b.bytes);
    }

    #[test]
    fn verify_ok() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        assert!(StackCanaryImpl::verify(&t, &t).is_ok());
    }

    #[test]
    fn verify_mismatch() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let mut bad = t;
        bad.bytes[0] ^= 0xFF;
        assert_eq!(
            StackCanaryImpl::verify(&t, &bad),
            Err(CanaryError::Mismatch)
        );
    }

    #[test]
    fn fingerprint_zero_on_match() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        assert_eq!(StackCanaryImpl::fail_fingerprint(&t, &t), 0);
    }

    #[test]
    fn fingerprint_nonzero_on_mismatch() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let mut bad = t;
        bad.bytes[3] ^= 0x11;
        let fp = StackCanaryImpl::fail_fingerprint(&t, &bad);
        assert_ne!(fp, 0);
        // byte index 3 in LE layout → shift 24
        assert_eq!((fp >> 24) & 0xFF, 0x11);
    }

    #[test]
    fn last_byte_has_high_bit() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        assert_ne!(t.bytes[7] & 0x80, 0);
    }

    #[test]
    fn free_match_trait() {
        let t = mint_impl(&BANNER_SEED).unwrap();
        assert_eq!(t, StackCanaryImpl::mint(&BANNER_SEED).unwrap());
    }

    #[test]
    fn banner_scenario() {
        let tok = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        assert!(StackCanaryImpl::verify(&tok, &tok).is_ok());
        let mut bad = tok;
        bad.bytes[0] ^= 1;
        assert!(StackCanaryImpl::verify(&tok, &bad).is_err());
        let fp = StackCanaryImpl::fail_fingerprint(&tok, &bad);
        assert_eq!(fp & 0xFF, 1);
    }

    #[test]
    fn different_positions_flip_fingerprint() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let mut b0 = t;
        b0.bytes[0] ^= 0x01;
        let mut b1 = t;
        b1.bytes[1] ^= 0x01;
        assert_ne!(
            StackCanaryImpl::fail_fingerprint(&t, &b0),
            StackCanaryImpl::fail_fingerprint(&t, &b1)
        );
    }

    #[test]
    fn weak_seed_all_zero_only() {
        let mut s = [0u8; 8];
        s[7] = 1;
        assert!(StackCanaryImpl::mint(&s).is_ok());
    }

    #[test]
    fn token_copy_eq() {
        let t = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let c = t;
        assert_eq!(t, c);
    }

    #[test]
    fn mix_is_not_identity() {
        // seed of 0x01.. should not equal mint output
        let seed = [1u8; 8];
        let t = StackCanaryImpl::mint(&seed).unwrap();
        assert_ne!(t.bytes, seed);
    }

    #[test]
    fn verify_symmetric_fail() {
        let a = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let mut b = a;
        b.bytes[2] = b.bytes[2].wrapping_add(1);
        assert!(StackCanaryImpl::verify(&a, &b).is_err());
        assert!(StackCanaryImpl::verify(&b, &a).is_err());
    }

    #[test]
    fn fingerprint_is_xor_le() {
        let a = CanaryToken {
            bytes: [0x10, 0, 0, 0, 0, 0, 0, 0],
        };
        let b = CanaryToken {
            bytes: [0x01, 0, 0, 0, 0, 0, 0, 0],
        };
        assert_eq!(fail_fingerprint_impl(&a, &b), 0x11);
    }

    #[test]
    fn banner_seed_not_weak() {
        assert!(StackCanaryImpl::mint(&BANNER_SEED).is_ok());
    }

    #[test]
    fn mint_avalanche_one_bit() {
        let a = StackCanaryImpl::mint(&BANNER_SEED).unwrap();
        let mut s = BANNER_SEED;
        s[4] ^= 0x80;
        let b = StackCanaryImpl::mint(&s).unwrap();
        let mut diff = 0u32;
        for i in 0..8 {
            if a.bytes[i] != b.bytes[i] {
                diff += 1;
            }
        }
        assert!(diff >= 1);
    }
}
