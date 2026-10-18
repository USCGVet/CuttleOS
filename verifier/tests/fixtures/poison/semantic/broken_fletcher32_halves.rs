//! POISON: fletcher32 packs (sum1<<16)|sum2 instead of (sum2<<16)|sum1. Golden fletcher32 + DemoHash fail.
//! Semantic corpus baseline — a complete, readable `target_minimal` lib
//! surface that satisfies golden.txt + harness invariants.
//!
//! Poisons in this directory are surgical mutations of this file. Each
//! poison must:
//!   - pass static checks (parse, manifest, previous-surface, diversity)
//!   - compile in the scratch workspace
//!   - FAIL the golden / harness battery for a documented reason
//!
//! This file itself is NOT a poison; the e2e runner may ACCEPT it as a
//! positive control.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]

/// Errno enum for DemoSyscallDispatch.
#[derive(Copy, Clone, PartialEq, Eq)]
pub enum DemoErrno {
    /// Unrecognised syscall number.
    ENOSYS,
    /// Bad argument.
    EINVAL,
    /// Bad pointer (sys_hash with a3 != 0).
    EFAULT,
}

impl core::fmt::Debug for DemoErrno {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(match *self {
            DemoErrno::ENOSYS => "ENOSYS",
            DemoErrno::EINVAL => "EINVAL",
            DemoErrno::EFAULT => "EFAULT",
        })
    }
}

/// Fletcher-32 checksum (locked packing: `(sum2 << 16) | sum1`).
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
    (sum1 << 16) | sum2 // BUG: halves swapped
}

/// 4-round fixed-key Feistel mixer.
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

/// Derive one byte from seed over `rounds` Feistel mixes.
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

/// 32-byte fletcher-pair construction used by DemoSignatureVerify.
pub fn fletcher_pair(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    let mut i: u8 = 0;
    while i < 8 {
        let h = fletcher_pair_one(a, b, i);
        let base = (i as usize) * 4;
        out[base] = (h >> 24) as u8;
        out[base + 1] = (h >> 16) as u8;
        out[base + 2] = (h >> 8) as u8;
        out[base + 3] = h as u8;
        i += 1;
    }
    out
}

fn fletcher_pair_one(a: &[u8], b: &[u8], salt: u8) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut have_hi = false;
    let mut hi_byte: u8 = 0;

    let feed = |bb: u8, sum1: &mut u32, sum2: &mut u32, have_hi: &mut bool, hi_byte: &mut u8| {
        if !*have_hi {
            *hi_byte = bb;
            *have_hi = true;
        } else {
            let word = ((*hi_byte as u32) << 8) | (bb as u32);
            *sum1 = (*sum1 + word) % 0xFFFF;
            *sum2 = (*sum2 + *sum1) % 0xFFFF;
            *have_hi = false;
        }
    };

    let mut k = 0;
    while k < a.len() {
        feed(a[k], &mut sum1, &mut sum2, &mut have_hi, &mut hi_byte);
        k += 1;
    }
    k = 0;
    while k < b.len() {
        feed(b[k], &mut sum1, &mut sum2, &mut have_hi, &mut hi_byte);
        k += 1;
    }
    feed(salt, &mut sum1, &mut sum2, &mut have_hi, &mut hi_byte);
    if have_hi {
        let word = (hi_byte as u32) << 8;
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
    (sum2 << 16) | sum1
}

/// Hash carrier.
pub struct DemoHash;

impl cuttle_contracts::Hash for DemoHash {
    const OUTPUT_LEN: usize = 4;
    fn hash(input: &[u8], out: &mut [u8]) {
        let h = fletcher32(input);
        out[0] = (h >> 24) as u8;
        out[1] = (h >> 16) as u8;
        out[2] = (h >> 8) as u8;
        out[3] = h as u8;
    }
}

/// AEAD error.
pub struct AeadError;

impl core::fmt::Debug for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadError")
    }
}

/// TOY AEAD carrier.
pub struct DemoAead;

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

fn tag_fletcher32(ciphertext: &[u8], aad: &[u8], key: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut prev: Option<u8> = None;

    let feed_byte = |b: u8, sum1: &mut u32, sum2: &mut u32, prev: &mut Option<u8>| match *prev {
        None => {
            *prev = Some(b);
        }
        Some(hi) => {
            let word = ((hi as u32) << 8) | (b as u32);
            *sum1 = (*sum1 + word) % 0xFFFF;
            *sum2 = (*sum2 + *sum1) % 0xFFFF;
            *prev = None;
        }
    };

    let feed_slice = |s: &[u8], sum1: &mut u32, sum2: &mut u32, prev: &mut Option<u8>| {
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
    (sum2 << 16) | sum1
}

impl cuttle_contracts::Aead for DemoAead {
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

/// TOY signature verify carrier.
pub struct DemoSignatureVerify;

impl cuttle_contracts::SignatureVerify for DemoSignatureVerify {
    const PUBKEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if public_key.len() != Self::PUBKEY_LEN {
            return false;
        }
        if signature.len() != Self::SIGNATURE_LEN {
            return false;
        }
        let lo = fletcher_pair(public_key, message);
        let hi = fletcher_pair(message, public_key);
        let mut acc: u8 = 0;
        let mut i = 0;
        while i < 32 {
            acc |= signature[i] ^ lo[i];
            i += 1;
        }
        let mut j = 0;
        while j < 32 {
            acc |= signature[32 + j] ^ hi[j];
            j += 1;
        }
        acc == 0
    }
}

/// Syscall dispatch carrier.
pub struct DemoSyscallDispatch;

fn syscall_u64_le_bytes(v: u64, out: &mut [u8; 8]) {
    let mut k = 0;
    while k < 8 {
        out[k] = (v >> (k * 8)) as u8;
        k += 1;
    }
}

fn syscall_hash_three(a0: u64, a1: u64, a2: u64) -> u32 {
    let mut chunk = [0u8; 8];
    let mut buf = [0u8; 24];
    syscall_u64_le_bytes(a0, &mut chunk);
    let mut k = 0;
    while k < 8 {
        buf[k] = chunk[k];
        k += 1;
    }
    syscall_u64_le_bytes(a1, &mut chunk);
    k = 0;
    while k < 8 {
        buf[8 + k] = chunk[k];
        k += 1;
    }
    syscall_u64_le_bytes(a2, &mut chunk);
    k = 0;
    while k < 8 {
        buf[16 + k] = chunk[k];
        k += 1;
    }
    fletcher32(&buf)
}

impl cuttle_contracts::SyscallDispatch for DemoSyscallDispatch {
    type Result = core::result::Result<u64, DemoErrno>;

    fn dispatch(
        nr: u64,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> Self::Result {
        match nr {
            0 => Ok(0),
            1 => Ok(a0),
            2 => Ok(a0.wrapping_add(a1)),
            3 => Ok(a0.wrapping_mul(a1)),
            4 => {
                if a3 != 0 {
                    Err(DemoErrno::EFAULT)
                } else {
                    Ok(syscall_hash_three(a0, a1, a2) as u64)
                }
            }
            5 => Ok(a0 ^ a1 ^ a2 ^ a3 ^ a4 ^ a5),
            6 => {
                if (a0 & a1) == a0 {
                    Ok(1)
                } else {
                    Err(DemoErrno::EINVAL)
                }
            }
            _ => Err(DemoErrno::ENOSYS),
        }
    }
}

/// Capability table lives in its own file; keep the module declaration.
pub mod caps;
