//! Integration test asserting the `target_enterprise` crate exposes
//! at least four `cuttle_contracts::*` trait implementations at its
//! public API surface.
//!
//! This is the acceptance criterion for TASK-001: "the new crate's
//! public API references at least 4 `contracts::*` traits". The four
//! the seed exposes are `Hash`, `Aead`, `SyscallDispatch`, and
//! `SignatureVerify`.

use cuttle_contracts::{Aead, Hash, NetStack, SignatureVerify, SyscallDispatch, WriteAheadLog};
use target_enterprise::{
    AeadImpl, HashImpl, NetStackImpl, SignatureVerifyImpl, SyscallDispatch as TeSyscall, WalImpl,
};

/// Compile-time witness that `T` implements `Hash`. The function body
/// never runs; the trait bound itself is the assertion.
fn _assert_hash<T: Hash>() {}
/// Compile-time witness that `T` implements `Aead`.
fn _assert_aead<T: Aead>() {}
/// Compile-time witness that `T` implements `SignatureVerify`.
fn _assert_sig<T: SignatureVerify>() {}
/// Compile-time witness that `T` implements `SyscallDispatch`.
fn _assert_syscall<T: SyscallDispatch>() {}
/// Compile-time witness that `T` implements `WriteAheadLog`.
fn _assert_wal<T: WriteAheadLog>() {}
/// Compile-time witness that `T` implements `NetStack`.
fn _assert_net<T: NetStack>() {}

#[test]
fn four_contract_traits_visible_from_public_api() {
    // Compile-time. If any of these lines fails to type-check, the
    // crate has violated its contract.
    _assert_hash::<HashImpl>();
    _assert_aead::<AeadImpl>();
    _assert_sig::<SignatureVerifyImpl>();
    _assert_syscall::<TeSyscall>();
    // Post-TASK-008 the crate exposes a fifth trait impl:
    // `WriteAheadLog` via `WalImpl<CAPACITY>`. The const-generic
    // requires a concrete capacity here.
    _assert_wal::<WalImpl<128>>();
    // Post-TASK-011 the crate exposes a sixth trait impl: `NetStack`
    // via `NetStackImpl`. Zero-sized — all state lives in
    // caller-supplied buffers, so no const generics needed.
    _assert_net::<NetStackImpl>();
}

#[test]
fn wal_impl_basic_durability() {
    // Smoke check from the contract-surface viewpoint: append + flush +
    // replay round-trip. Full property test lives in `wal_replay.rs`.
    let mut wal: WalImpl<256> = WalImpl::new();
    let lsn1 = wal.append(b"contract-record-1").unwrap();
    let lsn2 = wal.append(b"contract-record-2").unwrap();
    assert_eq!(lsn1, 1);
    assert_eq!(lsn2, 2);
    wal.flush(target_enterprise::wal::durable_wal_proof_init())
        .unwrap();
    let mut count = 0usize;
    wal.replay(&mut |lsn, payload| {
        count += 1;
        match lsn {
            1 => assert_eq!(payload, b"contract-record-1"),
            2 => assert_eq!(payload, b"contract-record-2"),
            other => panic!("unexpected lsn {}", other),
        }
    });
    assert_eq!(count, 2);
}

#[test]
fn hash_impl_round_trip_kat() {
    // Sanity: HashImpl::hash is deterministic across runs and
    // produces the documented `OUTPUT_LEN` bytes.
    assert_eq!(HashImpl::OUTPUT_LEN, 32);
    let mut a = [0u8; 32];
    let mut b = [0u8; 32];
    HashImpl::hash(b"contract-surface", &mut a);
    HashImpl::hash(b"contract-surface", &mut b);
    assert_eq!(a, b, "HashImpl must be deterministic");
    // Avalanche: change one byte of input → at least one output byte
    // differs.
    let mut c = [0u8; 32];
    HashImpl::hash(b"contract-surfaCe", &mut c);
    assert_ne!(a, c, "HashImpl must show avalanche");
}

#[test]
fn aead_impl_round_trip() {
    // AES-128-GCM: 16-byte key, 12-byte nonce, 16-byte tag.
    let key = b"a-16-byte-key!!!";
    assert_eq!(AeadImpl::KEY_LEN, 16);
    assert_eq!(AeadImpl::NONCE_LEN, 12);
    assert_eq!(AeadImpl::TAG_LEN, 16);
    let nonce = b"nonce-12byte";
    let pt = b"the eagle has landed";
    let aad = b"meta";
    let mut ct = [0u8; 64];
    let n = AeadImpl::encrypt(key, nonce, pt, aad, &mut ct);
    assert_eq!(n, pt.len() + AeadImpl::TAG_LEN);
    let mut recovered = [0u8; 32];
    let m = AeadImpl::decrypt(key, nonce, &ct[..n], aad, &mut recovered)
        .expect("legitimate ciphertext must decrypt");
    assert_eq!(m, pt.len());
    assert_eq!(&recovered[..m], pt);

    // Tamper rejects.
    let mut tampered = [0u8; 64];
    tampered[..n].copy_from_slice(&ct[..n]);
    tampered[0] ^= 1;
    assert!(AeadImpl::decrypt(key, nonce, &tampered[..n], aad, &mut recovered).is_err());
}

#[test]
fn aead_impl_passes_contract_invariant_battery() {
    use cuttle_contracts::harness::{check_aead, Verdict};
    match check_aead::<AeadImpl>() {
        Verdict::Pass => {}
        Verdict::Fail(why) => panic!("AES-128-GCM AeadImpl failed harness invariant: {why}"),
        Verdict::Invalid(why) => panic!("AES-128-GCM AeadImpl was invalid: {why}"),
    }
}

#[test]
fn signature_round_trip() {
    use target_enterprise::sig_sign;
    assert_eq!(SignatureVerifyImpl::PUBKEY_LEN, 32);
    assert_eq!(SignatureVerifyImpl::SIGNATURE_LEN, 64);
    let pubkey = [0x55u8; 32];
    let msg = b"contract-witness";
    let sig = sig_sign(&pubkey, msg);
    assert!(SignatureVerifyImpl::verify(&pubkey, msg, &sig));
    // Reject single-bit tamper.
    let mut bad = sig;
    bad[3] ^= 0x40;
    assert!(!SignatureVerifyImpl::verify(&pubkey, msg, &bad));
    // Reject wrong pubkey.
    let wrong = [0xAAu8; 32];
    assert!(!SignatureVerifyImpl::verify(&wrong, msg, &sig));
    // Reject length mismatch (truncated by 1 byte).
    assert!(!SignatureVerifyImpl::verify(&pubkey, msg, &sig[..63]));
}

#[test]
fn syscall_dispatch_smoke() {
    // The contract harness exercises three invariants:
    // 1. nr=0 with all-zero args returns Ok(0).
    let r = <TeSyscall as SyscallDispatch>::dispatch(0, 0, 0, 0, 0, 0, 0);
    assert_eq!(r, Ok(0));
    // 2. A deliberately-large unmapped nr returns Err.
    let r2 = <TeSyscall as SyscallDispatch>::dispatch(999_999, 0, 0, 0, 0, 0, 0);
    assert!(r2.is_err());
    // 3. Determinism across two calls.
    let r3a = <TeSyscall as SyscallDispatch>::dispatch(2, 1, 2, 3, 4, 5, 6);
    let r3b = <TeSyscall as SyscallDispatch>::dispatch(2, 1, 2, 3, 4, 5, 6);
    assert_eq!(r3a, r3b);
}

#[test]
fn syscall_capability_gate_blocks_open_without_caps() {
    // SYS_OPEN requires FS_BYPASS. Without that bit, check_cap rejects.
    use target_enterprise::syscall::{check_cap, SYS_OPEN};
    assert!(check_cap(SYS_OPEN, 0).is_err());
    assert!(check_cap(SYS_OPEN, cuttle_contracts::caps::FS_BYPASS).is_ok());
}

#[test]
fn scheduler_round_robin_is_fifo() {
    use target_enterprise::scheduler::RoundRobin;
    let mut s: RoundRobin<8> = RoundRobin::new();
    assert!(s.enqueue(1));
    assert!(s.enqueue(2));
    assert!(s.enqueue(3));
    let mut order = [0u32; 6];
    for slot in order.iter_mut() {
        *slot = s.pick_next().expect("ready queue should never be empty");
    }
    // The first pass through (1, 2, 3) must be in FIFO order; the
    // second pass through is also (1, 2, 3) because round-robin.
    assert_eq!(&order[..3], &[1u32, 2, 3]);
    assert_eq!(&order[3..], &[1u32, 2, 3]);
}

#[test]
fn memory_bitmap_allocator_roundtrip() {
    use target_enterprise::memory::{BitmapAllocator, FRAME_SIZE};
    let mut buf = [0u8; 16]; // 128 frames
    let mut alloc = BitmapAllocator::new(&mut buf);
    assert_eq!(alloc.capacity(), 128);
    assert_eq!(alloc.free_count(), 128);
    let p1 = alloc.alloc_frame().unwrap();
    let p2 = alloc.alloc_frame().unwrap();
    assert_ne!(p1, p2);
    assert_eq!(p1 % FRAME_SIZE, 0);
    alloc.free_frame(p1);
    assert_eq!(alloc.alloc_frame().unwrap(), p1);
}
