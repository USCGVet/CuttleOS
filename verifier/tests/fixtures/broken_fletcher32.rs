//! Hand-crafted reject fixture for the Proteus verifier.
//!
//! This file is a drop-in replacement for `target_minimal/src/lib.rs` that
//! is otherwise faithful to the canonical source but contains one subtle
//! semantic bug in `fletcher32`: the two 16-bit checksum halves are packed
//! in the wrong order — `(sum1 << 16) | sum2` instead of the locked
//! `(sum2 << 16) | sum1`.
//!
//! The whole point of this fixture is to prove that the verifier's
//! compile-and-test stage catches what the static checks cannot:
//!   - It parses cleanly (no syntax errors).
//!   - It compiles cleanly (no type errors, no warnings that block build).
//!   - All four required public symbols (`fletcher32`, `feistel_mix`,
//!     `derive_byte`, `DemoHash`) are present, plus the wider surface
//!     `DemoAead`, `AeadError` that the canonical source has been
//!     extended with — the public-symbol-preservation check refuses
//!     to shrink the API, so we must mirror it here.
//!   - It is canonical-distinct from the previous cycle (different bytes
//!     under the diversifier's canonical hash).
//!   - BUT: `fletcher32` produces wrong outputs against `golden.txt`, so
//!     the cargo-test stage MUST reject.
//!
//! If the verifier rejects this with `parse failed`, a missing-public-
//! symbol message, or a compile error, the fixture has drifted from the
//! canonical surface and must be repaired — the whole assay is invalid
//! otherwise.
//!
//! `DemoAead`'s tag is derived via a separate inlined fletcher32 (the
//! `tag_fletcher32` helper). To keep the bug surgical, that helper is
//! left UNCHANGED — the tag bytes still match the canonical contract.
//! This way the AEAD round-trip test still passes; only the bare
//! `fletcher32` golden vectors and `DemoHash::hash` (which wraps
//! `fletcher32`) fail. If both were broken the failure cause would be
//! ambiguous and a future maintainer might mis-diagnose the test stage.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

/// Placeholder hash carrier — the trait impl below is what the verifier
/// holds against `proteus_contracts::Hash` invariants.
pub struct DemoHash;

/// TOY authenticated-encryption carrier. Wired to `proteus_contracts::Aead`
/// so the canonical surface is preserved across the morph.
pub struct DemoAead;

/// Error returned by [`DemoAead::decrypt`] when tag verification fails.
pub struct AeadError;

impl core::fmt::Debug for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadError")
    }
}

/// Fletcher-32 checksum of `data` — **deliberately broken**. The two
/// 16-bit halves are packed in the wrong order (`sum1` high, `sum2` low
/// instead of the locked `sum2` high, `sum1` low). Every other line is
/// identical to the canonical implementation, so the bug is small and
/// targeted: the loop math, the trailing-odd-byte handling, and the
/// modular reduction all match the locked contract.
pub fn fletcher32(data: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum1 = (sum1 + word) % 0xFFFF;
        i += 2;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
    if i < data.len() {
        let word = (data[i] as u32) << 8;
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
    // BUG: halves swapped. Locked contract requires (sum2 << 16) | sum1.
    (sum1 << 16) | sum2
}

/// Derive one byte from `seed` by running `rounds` Feistel mixes and
/// folding the high/low 32 bits of the accumulator. Unchanged from the
/// canonical implementation.
pub fn derive_byte(seed: u8, rounds: u32) -> u8 {
    let mut acc: u64 = seed as u64;
    let mut accumulator_low: u32 = 0;
    let mut accumulator_high: u32 = 0;
    let mut counter: u32 = 0;
    while counter < rounds {
        acc = feistel_mix(acc.wrapping_add(counter as u64));
        accumulator_low = accumulator_low.wrapping_add(acc as u32);
        accumulator_high = accumulator_high.wrapping_add((acc >> 32) as u32);
        counter += 1;
    }
    let folded = accumulator_low ^ accumulator_high;
    (folded & 0xFF) as u8
}

/// Mix `state` through a 4-round fixed-key Feistel construction.
/// Unchanged from the canonical implementation.
pub fn feistel_mix(state: u64) -> u64 {
    let mut left = (state >> 32) as u32;
    let mut right = state as u32;
    for round in 0..4u32 {
        let new_right = left ^ feistel_round_fn(right, round);
        left = right;
        right = new_right;
    }
    ((left as u64) << 32) | (right as u64)
}

fn feistel_round_fn(half: u32, round: u32) -> u32 {
    let mixed = half
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add(round.wrapping_mul(0x85EB_CA6B));
    mixed.rotate_left(13) ^ mixed.rotate_right(7)
}

#[inline]
fn u64_le_from(bytes: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    let mut i = 0;
    while i < 8 {
        acc |= (bytes[i] as u64) << (i * 8);
        i += 1;
    }
    acc
}

#[inline]
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    let mut i = 0;
    while i < a.len() {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    acc == 0
}

impl proteus_contracts::Hash for DemoHash {
    const OUTPUT_LEN: usize = 4;
    fn hash(input: &[u8], out: &mut [u8]) {
        let h = fletcher32(input);
        out[0] = (h >> 24) as u8;
        out[1] = (h >> 16) as u8;
        out[2] = (h >> 8) as u8;
        out[3] = h as u8;
    }
}

impl proteus_contracts::Aead for DemoAead {
    const KEY_LEN: usize = 16;
    const NONCE_LEN: usize = 8;
    const TAG_LEN: usize = 4;

    type Error = AeadError;

    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> usize {
        let key_lo = u64_le_from(&key[0..8]);
        let nonce_word = u64_le_from(&nonce[0..8]);
        let mut state = feistel_mix(key_lo ^ nonce_word);

        let mut ks_block: [u8; 8] = [0; 8];
        let mut block_pos: usize = 8;
        let mut i = 0;
        while i < plaintext.len() {
            if block_pos == 8 {
                state = feistel_mix(state);
                let mut j = 0;
                while j < 8 {
                    ks_block[j] = (state >> (j * 8)) as u8;
                    j += 1;
                }
                block_pos = 0;
            }
            out[i] = plaintext[i] ^ ks_block[block_pos];
            block_pos += 1;
            i += 1;
        }

        let tag = tag_fletcher32(&out[..plaintext.len()], aad, key);
        out[plaintext.len()] = (tag >> 24) as u8;
        out[plaintext.len() + 1] = (tag >> 16) as u8;
        out[plaintext.len() + 2] = (tag >> 8) as u8;
        out[plaintext.len() + 3] = tag as u8;

        plaintext.len() + 4
    }

    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Self::Error> {
        if ciphertext.len() < 4 {
            return Err(AeadError);
        }
        let body_len = ciphertext.len() - 4;
        let body = &ciphertext[..body_len];
        let recv_tag = &ciphertext[body_len..];

        let expect_tag_u32 = tag_fletcher32(body, aad, key);
        let expect_tag = [
            (expect_tag_u32 >> 24) as u8,
            (expect_tag_u32 >> 16) as u8,
            (expect_tag_u32 >> 8) as u8,
            expect_tag_u32 as u8,
        ];
        if !ct_eq(recv_tag, &expect_tag) {
            return Err(AeadError);
        }

        let key_lo = u64_le_from(&key[0..8]);
        let nonce_word = u64_le_from(&nonce[0..8]);
        let mut state = feistel_mix(key_lo ^ nonce_word);
        let mut ks_block: [u8; 8] = [0; 8];
        let mut block_pos: usize = 8;
        let mut i = 0;
        while i < body_len {
            if block_pos == 8 {
                state = feistel_mix(state);
                let mut j = 0;
                while j < 8 {
                    ks_block[j] = (state >> (j * 8)) as u8;
                    j += 1;
                }
                block_pos = 0;
            }
            out[i] = body[i] ^ ks_block[block_pos];
            block_pos += 1;
            i += 1;
        }
        Ok(body_len)
    }
}

/// Compute the DemoAead authenticator over `(ciphertext || aad || key)`.
/// Implemented inline (independent of the broken top-level `fletcher32`)
/// so the AEAD tag stays consistent with the canonical contract. This
/// keeps the bug surgical: only the *bare* `fletcher32` and the
/// `DemoHash::hash` wrapper produce wrong output, so the test failure
/// localises cleanly to the fletcher32 vectors.
fn tag_fletcher32(ciphertext: &[u8], aad: &[u8], key: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut prev: Option<u8> = None;

    let feed_byte = |b: u8, sum1: &mut u32, sum2: &mut u32, prev: &mut Option<u8>| {
        match *prev {
            None => {
                *prev = Some(b);
            }
            Some(hi) => {
                let word = ((hi as u32) << 8) | (b as u32);
                *sum1 = (*sum1 + word) % 0xFFFF;
                *sum2 = (*sum2 + *sum1) % 0xFFFF;
                *prev = None;
            }
        }
    };

    let mut feed_slice = |s: &[u8], sum1: &mut u32, sum2: &mut u32, prev: &mut Option<u8>| {
        let mut k = 0;
        while k < s.len() {
            feed_byte(s[k], sum1, sum2, prev);
            k += 1;
        }
    };

    feed_slice(ciphertext, &mut sum1, &mut sum2, &mut prev);
    feed_slice(aad, &mut sum1, &mut sum2, &mut prev);
    feed_slice(key, &mut sum1, &mut sum2, &mut prev);

    if let Some(hi) = prev {
        let word = (hi as u32) << 8;
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }

    // Tag uses the canonical packing: this helper is intentionally NOT
    // broken. Only the public-surface `fletcher32` is.
    (sum2 << 16) | sum1
}
