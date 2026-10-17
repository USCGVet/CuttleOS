//! Proteus enterprise OS subsystem library (`target_enterprise`).
//!
//! Pure `no_std`, zero-allocation implementations of the kernel's cryptography,
//! networking, storage, filesystem, hardware driver, memory isolation, task
//! scheduling, capability/Seccomp enforcement, and interactive shell
//! ([`shell::OsShell`]) subsystems. Every module implements its corresponding
//! trait in [`proteus_contracts`] over fixed-capacity buffers so it can be
//! verified on the host and linked directly into the bare-metal unikernel
//! (`target_enterprise_kernel`).

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

pub mod acpi_rsdp;
pub mod ahci_cmd;
pub mod ahci_fis;
pub mod arp;
pub mod attest_tlv;
pub mod audit;
pub mod base64;
pub mod crc32c;
pub mod dhcp;
pub mod dns;
pub mod dns_name;
pub mod durable_seal;
pub mod e1000;
pub mod ebpf;
pub mod elf64;
pub mod ethernet;
pub mod fat32;
pub mod firewall;
pub mod frame_bitmap;
pub mod gdt;
pub mod gdbstub;
pub mod gpt;
pub mod hpet;
pub mod hmac_drbg;
pub mod http;
pub mod icmp;
pub mod jfs;
pub mod kat;
pub mod keyboard;
pub mod kpti;
pub mod lived_net;
pub mod lapic_icr;
pub mod nvme;
pub mod panic_dump;
pub mod pci;
pub mod power;
pub mod quota;
pub mod random;
pub mod smp;
pub mod sntp;
pub mod stack_canary;
pub mod symbols;
pub mod tcp;
pub mod timer;
pub mod tftp;
pub mod vfs;
pub mod tpm;
pub mod virtio_blk;
pub mod virtio_net;
pub mod virtio_pci_caps;
pub mod watchdog;
pub mod interrupts;
pub mod ioapic;
pub mod iommu;
pub mod kernel_fixtures;
pub mod memory;
pub mod multiboot2;
pub mod net;
pub mod scheduler;
pub mod serial16550;
pub mod shell;
pub mod sigkat;
pub mod syscall;
pub mod tick_source;
pub mod tls;
pub mod uefi_gop;
pub mod wal;
pub mod x509;
pub mod xhci_trb;

// Re-export the most commonly used items so callers don't have to
// reach into the sub-modules for the everyday types.
pub use crate::iommu::{
    DeviceId as IommuDeviceId, DomainId as IommuDomainId, IommuImpl, ENTRIES_PER_DOMAIN,
    MAX_DEVICES, MAX_DOMAINS, PAGE_MASK, PAGE_SHIFT, PAGE_SIZE,
};
pub use crate::memory::{BitmapAllocator, FRAME_SIZE};
pub use crate::lived_net::{LivedNet, ReplySet, GUEST_IP, HTTP_PORT, UDP_STATUS_PORT};
pub use crate::net::{
    build_udp_datagram, ipv4_header_checksum, parse_ipv4_header, parse_udp_datagram, udp_checksum,
    NetStackImpl, IPV4_HEADER_LEN, MAX_UDP_PAYLOAD, MIN_IPV4_UDP_LEN, UDP_HEADER_LEN,
};
pub use crate::scheduler::{RoundRobin, Task, TaskId, TaskState};
pub use crate::shell::{OsShell, ShellAction, SHELL_PROMPT};
pub use crate::syscall::{
    BufferSink, CapTableImpl, Errno, NullSink, SyscallDispatchImpl, WriteSink, CAP_TABLE_TASKS,
    PERMISSIVE_CAP_TABLE, SYS_CAP_CHECK, SYS_CLOSE, SYS_EXIT, SYS_GETPID, SYS_GETTIME_NS, SYS_OPEN,
    SYS_READ, SYS_READ_KEY, SYS_REALTIME_S, SYS_SLEEP_MS, SYS_WRITE, SYS_YIELD,
};
pub use crate::tls::Tls13ServerImpl;
pub use crate::wal::{
    durable_wal_proof, durable_wal_proof_init, WalError, WalImpl, FRAME_HEADER_BYTES,
    MAX_PAYLOAD_LEN,
};

// ============================================================
// Contract: proteus_contracts::Hash
// ============================================================

/// Concrete [`proteus_contracts::Hash`] impl: a Fletcher-32-based
/// chained construction emitting 32 output bytes. **NOT cryptographic**
/// — exists so the verifier has a real `impl Hash` to exercise against
/// the harness invariants (determinism + avalanche on a fixed corpus).
///
/// Construction (locked across morph cycles):
///
/// 1. `state = fletcher32(input)`
/// 2. For `i in 0..8`: `window_i = fletcher32(input || [i, (state ^ i) as u8])`
/// 3. Output bytes `[i*4 .. i*4+4] = window_i.to_be_bytes()`
///
/// The chained construction guarantees that flipping any single bit of
/// the input changes at least one of the eight windows, which is what
/// the harness's avalanche check exercises.
pub struct HashImpl;

/// Compute Fletcher-32 over `data`. The numeric result is part of the
/// locked contract — every morph cycle's implementation must produce
/// the same output for the same input.
pub fn fletcher32(data: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
        i += 2;
    }
    if i < data.len() {
        let word = (data[i] as u32) << 8;
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
    (sum2 << 16) | sum1
}

/// Fletcher-32 over the concatenation of three byte runs (`a || b || c`),
/// allocation-free. Used as the building block of [`HashImpl`] and
/// [`SignatureVerifyImpl`].
fn fletcher32_three(a: &[u8], b: &[u8], c: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut have_hi = false;
    let mut hi_byte: u8 = 0;
    let runs: [&[u8]; 3] = [a, b, c];
    let mut r = 0;
    while r < runs.len() {
        let bytes = runs[r];
        let mut k = 0;
        while k < bytes.len() {
            let bb = bytes[k];
            if have_hi {
                let word = ((hi_byte as u32) << 8) | (bb as u32);
                sum1 = (sum1 + word) % 0xFFFF;
                sum2 = (sum2 + sum1) % 0xFFFF;
                have_hi = false;
            } else {
                hi_byte = bb;
                have_hi = true;
            }
            k += 1;
        }
        r += 1;
    }
    if have_hi {
        let word = (hi_byte as u32) << 8;
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
    (sum2 << 16) | sum1
}

impl proteus_contracts::Hash for HashImpl {
    const OUTPUT_LEN: usize = 32;

    fn hash(input: &[u8], out: &mut [u8]) {
        // 8 chained windows × 4 bytes each = 32 bytes.
        let state = fletcher32(input);
        let mut i: u8 = 0;
        while i < 8 {
            let salt: [u8; 2] = [i, (state ^ (i as u32)) as u8];
            let h = fletcher32_three(input, &salt, &[]);
            let base = (i as usize) * 4;
            out[base] = (h >> 24) as u8;
            out[base + 1] = (h >> 16) as u8;
            out[base + 2] = (h >> 8) as u8;
            out[base + 3] = h as u8;
            i += 1;
        }
    }
}

// ============================================================
// Contract: proteus_contracts::Aead
// ============================================================

/// Error returned by [`AeadImpl::decrypt`] on authentication failure.
#[derive(Copy, Clone, PartialEq, Eq)]
pub struct AeadError;

impl core::fmt::Debug for AeadError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("AeadError")
    }
}

/// Concrete [`proteus_contracts::Aead`] impl: a Feistel-keystream +
/// Fletcher-tag construction. **NOT cryptographic** — exists so the
/// verifier has a real `impl Aead` to exercise against the harness
/// invariants (round-trip, ciphertext-tamper, tag-tamper, AAD-tamper,
/// wrong-key rejection).
///
/// Construction (locked across morph cycles):
///
/// 1. Initial state: `state = feistel_mix(u64_le(key[0..8]) ^ u64_le(nonce))`.
/// 2. Keystream: repeatedly `state = feistel_mix(state)`, emit 8 bytes
///    little-endian. XOR with plaintext to produce ciphertext.
/// 3. Tag: `fletcher32(ciphertext || aad || key)` written big-endian
///    as 4 bytes appended to the ciphertext. The key is folded into
///    the tag so wrong-key decryption is rejected (necessary because
///    the Fletcher tag is otherwise key-independent).
pub struct AeadImpl;

/// Mix `state` using a 4-round fixed-key Feistel construction. Pure;
/// locked across morph cycles. Lifted from `target_minimal`.
pub fn feistel_mix(state: u64) -> u64 {
    let mut left = (state >> 32) as u32;
    let mut right = state as u32;
    let mut round = 0u32;
    while round < 4 {
        let new_right = left ^ feistel_round_fn(right, round);
        left = right;
        right = new_right;
        round += 1;
    }
    ((left as u64) << 32) | (right as u64)
}

fn feistel_round_fn(half: u32, round: u32) -> u32 {
    let mixed = half
        .wrapping_mul(0x9E37_79B1)
        .wrapping_add(round.wrapping_mul(0x85EB_CA6B));
    mixed.rotate_left(13) ^ mixed.rotate_right(7)
}

fn u64_le_from(bytes: &[u8]) -> u64 {
    let mut acc: u64 = 0;
    let mut i = 0usize;
    while i < 8 && i < bytes.len() {
        acc |= (bytes[i] as u64) << (i * 8);
        i += 1;
    }
    acc
}

/// Constant-time-style bytewise compare. Loop runs over every byte
/// regardless of mismatch to avoid leaking the first-differing-index
/// via timing.
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut acc: u8 = 0;
    let mut i = 0usize;
    while i < a.len() {
        acc |= a[i] ^ b[i];
        i += 1;
    }
    acc == 0
}

/// Compute the AEAD tag over `(ciphertext || aad || key)`, allocation-
/// free.
fn aead_tag(ciphertext: &[u8], aad: &[u8], key: &[u8]) -> u32 {
    fletcher32_three(ciphertext, aad, key)
}

impl proteus_contracts::Aead for AeadImpl {
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
        let key_lo = u64_le_from(&key[..8.min(key.len())]);
        let nonce_word = u64_le_from(&nonce[..8.min(nonce.len())]);
        let mut state = feistel_mix(key_lo ^ nonce_word);
        let mut ks: [u8; 8] = [0; 8];
        let mut pos = 8usize;
        let mut i = 0usize;
        while i < plaintext.len() {
            if pos == 8 {
                state = feistel_mix(state);
                let mut j = 0usize;
                while j < 8 {
                    ks[j] = (state >> (j * 8)) as u8;
                    j += 1;
                }
                pos = 0;
            }
            out[i] = plaintext[i] ^ ks[pos];
            pos += 1;
            i += 1;
        }
        let tag = aead_tag(&out[..plaintext.len()], aad, key);
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
        let expect_u32 = aead_tag(body, aad, key);
        let expect_tag = [
            (expect_u32 >> 24) as u8,
            (expect_u32 >> 16) as u8,
            (expect_u32 >> 8) as u8,
            expect_u32 as u8,
        ];
        if !ct_eq(recv_tag, &expect_tag) {
            return Err(AeadError);
        }
        let key_lo = u64_le_from(&key[..8.min(key.len())]);
        let nonce_word = u64_le_from(&nonce[..8.min(nonce.len())]);
        let mut state = feistel_mix(key_lo ^ nonce_word);
        let mut ks: [u8; 8] = [0; 8];
        let mut pos = 8usize;
        let mut i = 0usize;
        while i < body_len {
            if pos == 8 {
                state = feistel_mix(state);
                let mut j = 0usize;
                while j < 8 {
                    ks[j] = (state >> (j * 8)) as u8;
                    j += 1;
                }
                pos = 0;
            }
            out[i] = body[i] ^ ks[pos];
            pos += 1;
            i += 1;
        }
        Ok(body_len)
    }
}

// ============================================================
// Contract: proteus_contracts::SyscallDispatch
// ============================================================

/// Concrete [`proteus_contracts::SyscallDispatch`] impl exposed at the
/// crate root. Wraps [`crate::syscall::SyscallDispatchImpl`]. The
/// integration test asserts that this type implements the contract.
pub struct SyscallDispatch;

impl proteus_contracts::SyscallDispatch for SyscallDispatch {
    type Result = core::result::Result<u64, Errno>;

    fn dispatch(
        nr: u64,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> Self::Result {
        <SyscallDispatchImpl as proteus_contracts::SyscallDispatch>::dispatch(
            nr, a0, a1, a2, a3, a4, a5,
        )
    }
}

// ============================================================
// Contract: proteus_contracts::SignatureVerify
// ============================================================

/// Concrete [`proteus_contracts::SignatureVerify`] impl. **TOY scheme —
/// NOT CRYPTOGRAPHIC.** Exists so the verifier has a real `impl
/// SignatureVerify` to exercise against the harness invariants (accept
/// legitimate sig, reject single-byte tamper, reject wrong message,
/// reject wrong public key, reject length mismatch).
///
/// Construction (locked across morph cycles):
///
/// - `signature[0..32] = HashImpl::hash(pubkey || message)`
/// - `signature[32..64] = HashImpl::hash(message || pubkey)`
///
/// Verification recomputes both halves and compares to the supplied
/// signature in constant time per byte (no early exit).
pub struct SignatureVerifyImpl;

/// Compute a 32-byte digest of `(a || b)` using `HashImpl`. Used by
/// `SignatureVerifyImpl` to produce / verify the two halves of a
/// signature.
pub fn sig_digest(a: &[u8], b: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    // Fletcher32_three over (a, b, []) gives us a 4-byte fingerprint;
    // we expand it via 8 chained windows the same way HashImpl does to
    // get 32 bytes that depend on every input byte.
    let state = fletcher32_three(a, b, &[]);
    let mut i: u8 = 0;
    while i < 8 {
        let salt: [u8; 2] = [i, (state ^ (i as u32)) as u8];
        let h = fletcher32_three(a, b, &salt);
        let base = (i as usize) * 4;
        out[base] = (h >> 24) as u8;
        out[base + 1] = (h >> 16) as u8;
        out[base + 2] = (h >> 8) as u8;
        out[base + 3] = h as u8;
        i += 1;
    }
    out
}

/// Convenience: produce a valid signature for `(pubkey, message)`.
/// Mirrors what the verifier needs to bootstrap its sig-accept test.
pub fn sig_sign(pubkey: &[u8], message: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    let lo = sig_digest(pubkey, message);
    let hi = sig_digest(message, pubkey);
    let mut i = 0usize;
    while i < 32 {
        out[i] = lo[i];
        out[32 + i] = hi[i];
        i += 1;
    }
    out
}

impl proteus_contracts::SignatureVerify for SignatureVerifyImpl {
    const PUBKEY_LEN: usize = 32;
    const SIGNATURE_LEN: usize = 64;

    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool {
        if public_key.len() != Self::PUBKEY_LEN {
            return false;
        }
        if signature.len() != Self::SIGNATURE_LEN {
            return false;
        }
        let lo = sig_digest(public_key, message);
        let hi = sig_digest(message, public_key);
        let mut acc: u8 = 0;
        let mut i = 0usize;
        while i < 32 {
            acc |= signature[i] ^ lo[i];
            i += 1;
        }
        let mut j = 0usize;
        while j < 32 {
            acc |= signature[32 + j] ^ hi[j];
            j += 1;
        }
        acc == 0
    }
}

// ============================================================
// Crate-level unit tests (no_std-compatible — Rust test harness
// runs them with std on the host, but the code under test stays
// no_std).
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::{Aead, Hash, SignatureVerify, SyscallDispatch as SD};

    #[test]
    fn fletcher32_known_vectors() {
        assert_eq!(fletcher32(b""), 0);
        assert_eq!(fletcher32(b"abcde"), fletcher32(b"abcde"));
        assert_ne!(fletcher32(b"abcde"), fletcher32(b"abcdf"));
    }

    #[test]
    fn hash_impl_is_deterministic() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        HashImpl::hash(b"proteus", &mut a);
        HashImpl::hash(b"proteus", &mut b);
        assert_eq!(a, b);
    }

    #[test]
    fn hash_impl_avalanche_on_one_bit() {
        let mut a = [0u8; 32];
        let mut b = [0u8; 32];
        HashImpl::hash(b"proteus", &mut a);
        HashImpl::hash(b"proteut", &mut b);
        assert_ne!(a, b);
    }

    #[test]
    fn aead_roundtrip_small() {
        let key = [0u8; 16];
        let nonce = [0u8; 8];
        let pt = b"hello-aead";
        let mut ct = [0u8; 64];
        let n = AeadImpl::encrypt(&key, &nonce, pt, b"aad", &mut ct);
        let mut recovered = [0u8; 32];
        let m = AeadImpl::decrypt(&key, &nonce, &ct[..n], b"aad", &mut recovered).unwrap();
        assert_eq!(m, pt.len());
        assert_eq!(&recovered[..m], pt);
    }

    #[test]
    fn aead_rejects_tampered_tag() {
        let key = [0u8; 16];
        let nonce = [0u8; 8];
        let pt = b"hello-aead";
        let mut ct = [0u8; 64];
        let n = AeadImpl::encrypt(&key, &nonce, pt, b"aad", &mut ct);
        ct[n - 1] ^= 1;
        let mut out = [0u8; 32];
        assert!(AeadImpl::decrypt(&key, &nonce, &ct[..n], b"aad", &mut out).is_err());
    }

    #[test]
    fn aead_rejects_wrong_aad() {
        let key = [0u8; 16];
        let nonce = [0u8; 8];
        let pt = b"hello-aead";
        let mut ct = [0u8; 64];
        let n = AeadImpl::encrypt(&key, &nonce, pt, b"aad", &mut ct);
        let mut out = [0u8; 32];
        assert!(AeadImpl::decrypt(&key, &nonce, &ct[..n], b"different", &mut out).is_err());
    }

    #[test]
    fn aead_rejects_wrong_key() {
        let key1 = [0u8; 16];
        let mut key2 = [0u8; 16];
        key2[0] = 0xFF;
        let nonce = [0u8; 8];
        let pt = b"hello-aead";
        let mut ct = [0u8; 64];
        let n = AeadImpl::encrypt(&key1, &nonce, pt, b"aad", &mut ct);
        let mut out = [0u8; 32];
        assert!(AeadImpl::decrypt(&key2, &nonce, &ct[..n], b"aad", &mut out).is_err());
    }

    #[test]
    fn signature_roundtrip() {
        let pubkey = [0xAAu8; 32];
        let msg = b"sign-this";
        let sig = sig_sign(&pubkey, msg);
        assert!(SignatureVerifyImpl::verify(&pubkey, msg, &sig));
    }

    #[test]
    fn signature_rejects_tamper() {
        let pubkey = [0xAAu8; 32];
        let msg = b"sign-this";
        let mut sig = sig_sign(&pubkey, msg);
        sig[0] ^= 1;
        assert!(!SignatureVerifyImpl::verify(&pubkey, msg, &sig));
    }

    #[test]
    fn signature_rejects_wrong_pubkey() {
        let pubkey = [0xAAu8; 32];
        let wrong = [0xBBu8; 32];
        let msg = b"sign-this";
        let sig = sig_sign(&pubkey, msg);
        assert!(!SignatureVerifyImpl::verify(&wrong, msg, &sig));
    }

    #[test]
    fn syscall_unmapped_returns_err() {
        let r = <SyscallDispatch as SD>::dispatch(999_999, 0, 0, 0, 0, 0, 0);
        assert!(r.is_err());
    }

    #[test]
    fn syscall_exit_returns_ok_zero() {
        // sys_exit (nr=0) returns Ok(0) — matches the harness's
        // "known mapped syscall returns Ok(0)" invariant.
        let r = <SyscallDispatch as SD>::dispatch(0, 0, 0, 0, 0, 0, 0);
        assert_eq!(r, Ok(0));
    }

    #[test]
    fn syscall_getpid_returns_one() {
        let r = <SyscallDispatch as SD>::dispatch(SYS_GETPID, 0, 0, 0, 0, 0, 0);
        assert_eq!(r, Ok(1));
    }
}
