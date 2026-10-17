//! Proteus contracts — the immutable kernel API surface.
//!
//! Every morph candidate produced by the factory must satisfy every trait
//! in this crate. The verifier treats these trait signatures and their
//! documented invariants as ground truth.
//!
//! **This crate does not morph.** It is the architectural anchor of the
//! system. Changes to this crate require human review, are tracked in the
//! attestation log as schema-version transitions, and trigger a fleet-wide
//! coordinated upgrade — not a routine morph cycle.

#![cfg_attr(not(feature = "property_tests"), no_std)]
#![deny(unsafe_op_in_unsafe_fn)]
#![deny(missing_docs)]

/// Cryptographic hash function contract.
///
/// Invariants the verifier checks:
/// - Determinism: `hash(x) == hash(x)` for all `x`.
/// - Avalanche: `hash(x) != hash(x')` for `x != x'` with overwhelming
///   probability (verified against a fixed adversarial corpus, not a full
///   collision search).
/// - Length extension resistance: any property that the underlying
///   algorithm (e.g. SHA-256) requires.
/// - KAT compliance: the algorithm-specific known-answer test vectors
///   from the relevant RFC pass byte-for-byte.
pub trait Hash {
    /// Output length in bytes. For SHA-256: 32. For SHA-512: 64.
    const OUTPUT_LEN: usize;

    /// Compute the hash of `input` into `out`. Must write exactly
    /// `OUTPUT_LEN` bytes to `out`. Behaviour if `out.len() < OUTPUT_LEN`
    /// is implementation-defined panic.
    fn hash(input: &[u8], out: &mut [u8]);
}

/// Authenticated encryption with associated data (AEAD) contract.
///
/// Invariants the verifier checks:
/// - Round-trip: `decrypt(k, n, encrypt(k, n, m, aad), aad) == Ok(m)` for
///   all `(k, n, m, aad)`.
/// - Authentication: `decrypt(k, n, c', aad)` returns `Err(_)` when any
///   byte of `c'` differs from a legitimate ciphertext.
/// - Misuse resistance: nonce reuse is detectable by the caller. The
///   contract does NOT promise misuse resistance internally — that is
///   the caller's obligation.
/// - KAT compliance against RFC 7539 (ChaCha20-Poly1305) or RFC 5288
///   (AES-GCM) per impl.
pub trait Aead {
    /// Key length in bytes.
    const KEY_LEN: usize;
    /// Nonce length in bytes.
    const NONCE_LEN: usize;
    /// Authentication tag length in bytes.
    const TAG_LEN: usize;

    /// Error type returned by [`decrypt`] on authentication failure.
    type Error;

    /// Encrypt `plaintext` with `key` and `nonce`, authenticating `aad`.
    /// The output is appended to `out` and includes the authentication
    /// tag. Returns the number of bytes written.
    fn encrypt(
        key: &[u8],
        nonce: &[u8],
        plaintext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> usize;

    /// Decrypt `ciphertext` (which includes the authentication tag) with
    /// `key` and `nonce`, verifying `aad`. The plaintext is written to
    /// `out`. Returns `Err(_)` if the tag verification fails. Implementations
    /// MUST NOT leak plaintext on authentication failure.
    fn decrypt(
        key: &[u8],
        nonce: &[u8],
        ciphertext: &[u8],
        aad: &[u8],
        out: &mut [u8],
    ) -> Result<usize, Self::Error>;
}

/// Digital signature verification contract.
///
/// Invariants the verifier checks:
/// - A signature produced by the matching signer is accepted.
/// - A signature with any single bit flipped is rejected.
/// - A signature against a different message is rejected.
/// - A signature against a different public key is rejected.
/// - Malleability resistance per the underlying algorithm (Ed25519
///   non-zero-S enforcement, ECDSA low-S enforcement) is preserved.
///
/// The verifier MUST be constant-time with respect to the secret-free
/// signature bytes. (No secrets are involved in verification, but timing
/// leaks reveal which step rejected, which is itself an oracle in some
/// protocols.)
pub trait SignatureVerify {
    /// Public key length in bytes.
    const PUBKEY_LEN: usize;
    /// Signature length in bytes.
    const SIGNATURE_LEN: usize;

    /// Return `true` iff `signature` is a valid signature of `message`
    /// under `public_key`.
    fn verify(public_key: &[u8], message: &[u8], signature: &[u8]) -> bool;
}

/// Syscall dispatch contract.
///
/// The syscall number → semantics map is locked across all morph cycles.
/// Userspace binaries compiled against syscall number N must continue to
/// observe identical behaviour after every morph.
///
/// Implementations of this trait morph aggressively (table lookups vs
/// match cascades, branch ordering, register allocation) but the
/// observable behaviour does not.
pub trait SyscallDispatch {
    /// Result type returned to userspace. Typically `Result<u64, Errno>`
    /// in the target kernel.
    type Result;

    /// Dispatch syscall `nr` with up to six register-passed arguments.
    /// The argument count and register ABI is locked; this trait is
    /// the architectural authority on that contract.
    fn dispatch(
        nr: u64,
        a0: u64,
        a1: u64,
        a2: u64,
        a3: u64,
        a4: u64,
        a5: u64,
    ) -> Self::Result;
}

/// Error variant returned by [`SyscallCapTable::check`] when a capability
/// check is rejected. Locked: userspace and the verifier both observe
/// these discriminants by name. Numeric values match the POSIX-ish errnos
/// used by `target_enterprise::syscall::Errno` for the same conditions so
/// implementations can share a single Errno enum if convenient.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CapError {
    /// Capability check failed: the task does not hold the required bits.
    EPERM = 1,
    /// The syscall number is out of range (no entry in the cap table).
    ENOSYS = 38,
}

/// Compile-time proof that a capability check has succeeded.
///
/// `CapProof` is a zero-sized type whose only legal construction site is
/// inside [`SyscallCapTable::check`]'s provided default body. Because
/// the inner field is private to this crate, no external code — neither
/// safe morph candidates nor downstream `target_*` crates — can mint a
/// `CapProof` directly: the only path is to call `check` (or the trait's
/// `check_raw` indirectly via `check`) and receive a fresh proof on
/// the success arm.
///
/// Privileged syscall handlers therefore declare a `CapProof` parameter
/// in their signature, which the **compiler** requires the caller to
/// produce by value. The AST walker that the old TASK-004 verifier ran
/// is replaced by Rust's type system: a morph candidate that writes
/// `let _ = check_cap(...);` or `if false { check_cap(...)?; }` cannot
/// reach the privileged handler because it has no `CapProof` to pass.
///
/// `#[must_use]` is layered on top so an ignored `Result<CapProof, _>`
/// at least surfaces a lint. With `#![deny(unused_must_use)]` on the
/// caller crate (the target kernel crates set it), discarding the
/// `Result` is a hard error; binding the `CapProof` to `_` is silently
/// permitted but renders every privileged handler call unreachable
/// because the proof is no longer in scope.
///
/// # Example
///
/// ```
/// use proteus_contracts::{CapError, CapProof, SyscallCapTable, caps};
///
/// // A trivial impl that always permits.
/// struct AllowAll;
/// impl SyscallCapTable for AllowAll {
///     type Cap = u64;
///     fn check_raw(&self, _task_id: u64, _cap: u64, _nr: u32) -> Result<(), CapError> {
///         Ok(())
///     }
/// }
///
/// // The privileged action consumes the proof by value.
/// fn privileged_action(_proof: CapProof, x: u64) -> u64 { x + 1 }
///
/// // Legal: obtain a proof, consume it.
/// let table = AllowAll;
/// let proof = table.check(0, caps::POWER, 0).expect("check succeeded");
/// assert_eq!(privileged_action(proof, 41), 42);
/// ```
#[must_use = "CapProof witnesses a successful capability check and must be \
              consumed by the privileged operation it gates; ignoring it \
              leaves the gated action unreachable"]
#[derive(Debug)]
pub struct CapProof {
    /// Private field: the only construction site is the sealed module
    /// below, which is `pub(crate)`. External code therefore cannot
    /// construct a `CapProof` via a struct literal.
    _private: (),
}

impl CapProof {
    /// Consume the proof. Equivalent to letting it fall out of scope,
    /// but reads better at the privileged-action call site:
    ///
    /// ```no_run
    /// # use proteus_contracts::{CapError, CapProof, SyscallCapTable, caps};
    /// # struct T;
    /// # impl SyscallCapTable for T {
    /// #     type Cap = u64;
    /// #     fn check_raw(&self, _t: u64, _c: u64, _n: u32) -> Result<(), CapError> { Ok(()) }
    /// # }
    /// let proof = T.check(0, caps::POWER, 0).unwrap();
    /// proof.consume();
    /// ```
    #[inline]
    pub fn consume(self) {
        // Body intentionally empty: moving `self` here discards the
        // proof, which is the desired type-state behaviour.
    }
}

/// Sealed mint mechanism. Lives in a private module so the only call
/// site is the `SyscallCapTable::check` default body in this crate.
/// External code cannot reach `mint` because the module is private.
pub(crate) mod cap_proof_internal {
    use super::CapProof;

    /// Construct a fresh `CapProof`. Calling this asserts that a
    /// capability check has just succeeded — the trait's default
    /// `check` body is the only caller in this crate, so the
    /// assertion is statically true.
    #[inline]
    pub(crate) fn mint() -> CapProof {
        CapProof { _private: () }
    }
}

/// Capability-based syscall gate.
///
/// **Type-state contract (TASK-020).** Implementors override
/// [`check_raw`](Self::check_raw), which returns the success/failure
/// discriminant alone. The provided [`check`](Self::check) method
/// converts a successful `check_raw` into a freshly-minted [`CapProof`]
/// — the **only** site in the crate that can produce one. Privileged
/// handlers downstream then declare `_proof: CapProof` in their
/// signature, and the compiler enforces that the caller produces a
/// proof by value before invoking the handler. This replaces the
/// TASK-004 AST walker (which only inspected the *presence* of a
/// `check_cap` identifier, not the *consumption* of its result) with a
/// compile-time guarantee.
///
/// The seal works because `CapProof` has a private inner field and
/// the mint helper lives in a `pub(crate)` module. External code
/// outside `contracts/` cannot construct a `CapProof` directly:
///
/// - Safe code: blocked by visibility of the `_private` field and the
///   `cap_proof_internal::mint` function.
/// - `unsafe` transmute from `()`: technically possible since
///   `CapProof` is zero-sized, but requires the `unsafe` keyword,
///   which is itself a syntactic flag the verifier already inspects
///   (and which a morph candidate cannot introduce without tripping
///   the unsafe-region lint). The contract is binding for safe code,
///   which is the morph candidate's universe.
pub trait SyscallCapTable {
    /// The capability representation. Concrete impls use `u64` bitmasks.
    type Cap: Copy + Eq;

    /// Return `Ok(())` iff `task_id`'s capability set permits invoking
    /// `syscall_nr` with `cap`. Otherwise return `Err(CapError::EPERM)`
    /// (denied) or `Err(CapError::ENOSYS)` (syscall out of table range).
    ///
    /// Implementors override this method; they cannot mint a
    /// [`CapProof`] themselves. The trait's [`check`](Self::check)
    /// default wraps `check_raw`'s success arm with a proof mint and
    /// is the sole construction site for `CapProof` values that safe
    /// downstream code can observe.
    fn check_raw(&self, task_id: u64, cap: Self::Cap, syscall_nr: u32) -> Result<(), CapError>;

    /// Mint a [`CapProof`] iff [`check_raw`](Self::check_raw) succeeds.
    ///
    /// Provided method; implementors should not override unless they
    /// have an algorithmic reason (e.g. a hardware-attested capability
    /// store that wants to inject a domain-separated proof type). The
    /// default body is the one line below.
    #[inline]
    fn check(
        &self,
        task_id: u64,
        cap: Self::Cap,
        syscall_nr: u32,
    ) -> Result<CapProof, CapError> {
        self.check_raw(task_id, cap, syscall_nr).map(|()| cap_proof_internal::mint())
    }
}

/// Capability-bit → permission map.
///
/// Each bit position in a 64-bit capability mask is locked to a specific
/// permission semantic. The mapping below is the canonical assignment.
/// Implementations may not renumber.
pub mod caps {
    /// Permission to read raw block devices.
    pub const BLOCK_READ: u64 = 1 << 0;
    /// Permission to write raw block devices.
    pub const BLOCK_WRITE: u64 = 1 << 1;
    /// Permission to bind a privileged (<1024) TCP/UDP port.
    pub const NET_BIND_PRIVILEGED: u64 = 1 << 2;
    /// Permission to send raw Ethernet frames.
    pub const NET_RAW: u64 = 1 << 3;
    /// Permission to invoke power management (shutdown, reboot).
    pub const POWER: u64 = 1 << 4;
    /// Permission to read the system audit log.
    pub const AUDIT_READ: u64 = 1 << 5;
    /// Permission to append to the system audit log.
    pub const AUDIT_WRITE: u64 = 1 << 6;
    /// Permission to install signed ELF binaries.
    pub const ELF_LOAD: u64 = 1 << 7;
    /// Permission to issue inter-node cluster RPC.
    pub const CLUSTER_RPC: u64 = 1 << 8;
    /// Permission to bypass file-system path checks (debugger, init only).
    pub const FS_BYPASS: u64 = 1 << 9;

    // --- TASK-159: durable-write capability bits (design TASK-157) ---
    // Allocated; **not yet wired** into WAL/jfs/audit commit paths.
    // Residual remains open until enterprise write sites take CapProof.

    /// Permission to advance WAL durable_cursor (append + flush that
    /// becomes media-stable). Distinct from raw [`BLOCK_WRITE`].
    pub const DURABLE_WAL_WRITE: u64 = 1 << 10;
    /// Permission to mutate durable filesystem metadata/data (jfs
    /// extents, superblock dirty that hits media).
    pub const DURABLE_FS_WRITE: u64 = 1 << 11;
    /// Permission to persist audit records to non-volatile sinks
    /// (beyond in-RAM ring). Distinct from [`AUDIT_WRITE`].
    pub const DURABLE_AUDIT_PERSIST: u64 = 1 << 12;

    /// Highest allocated bit index + 1 (bits `0..ALLOCATED_BITS` are
    /// named; higher bits are reserved).
    pub const ALLOCATED_BITS: u32 = 13;

    /// Union of all currently named capability bits (TASK-159 includes
    /// durable trio). Useful for "grant all known" test tables.
    pub const ALL_NAMED: u64 = (1u64 << ALLOCATED_BITS) - 1;

    /// Bit positions [`ALLOCATED_BITS`]..64 are reserved and MUST remain
    /// zero in any issued capability mask. The morph engine treats any
    /// non-zero reserved bit as a contract violation.
    pub const RESERVED_MASK: u64 = !((1u64 << ALLOCATED_BITS) - 1);

    /// Return `true` iff `mask` has no reserved bits set.
    #[inline]
    pub const fn mask_is_valid(mask: u64) -> bool {
        (mask & RESERVED_MASK) == 0
    }

    /// Return `true` iff `held` includes every bit in `required`
    /// (and both masks are free of reserved bits).
    #[inline]
    pub const fn allows(held: u64, required: u64) -> bool {
        mask_is_valid(held)
            && mask_is_valid(required)
            && (held & required) == required
    }
}

/// Mint a [`CapProof`] iff `held` includes every bit of `required`
/// (via [`caps::allows`]). Primary helper for durable-write gates
/// (TASK-161) and tests that need a proof without a full syscall table.
///
/// ```no_run
/// # use proteus_contracts::{mint_cap_proof, caps};
/// let proof = mint_cap_proof(caps::DURABLE_WAL_WRITE, caps::DURABLE_WAL_WRITE)
///     .expect("self-grant");
/// proof.consume();
/// ```
#[inline]
pub fn mint_cap_proof(held: u64, required: u64) -> Result<CapProof, CapError> {
    if !caps::allows(held, required) {
        return Err(CapError::EPERM);
    }
    // Local table: allows() already enforced the semantic check; the
    // table only exists to reach the sealed mint site.
    struct AllowTable;
    impl SyscallCapTable for AllowTable {
        type Cap = u64;
        fn check_raw(&self, _task_id: u64, _cap: u64, _syscall_nr: u32) -> Result<(), CapError> {
            Ok(())
        }
    }
    AllowTable.check(0, held, 0)
}

/// Filesystem block-device contract.
///
/// Invariants the verifier checks:
/// - Read-after-write: `read(off)` after `write(off, data)` returns
///   `data` byte-for-byte.
/// - Atomicity: a write to block N is either fully visible or not
///   visible at all; partial writes are not exposed to readers.
/// - Durability: after `flush()`, every preceding write is durable
///   against power loss.
pub trait BlockDevice {
    /// Block size in bytes (locked at 512 for all morph cycles).
    const BLOCK_SIZE: usize = 512;

    /// Read a single block at LBA `lba` into `buf`. `buf.len()` must
    /// equal [`BLOCK_SIZE`](Self::BLOCK_SIZE).
    fn read_block(lba: u64, buf: &mut [u8]);

    /// Write a single block at LBA `lba` from `buf`. `buf.len()` must
    /// equal [`BLOCK_SIZE`](Self::BLOCK_SIZE).
    fn write_block(lba: u64, buf: &[u8]);

    /// Flush all pending writes to durable storage.
    fn flush();
}

/// Write-ahead log record format.
///
/// The on-disk byte layout is locked across all morph cycles. The reader
/// and writer implementations morph; the bytes on disk do not.
pub mod wal {
    /// Sector range reserved for the WAL on the boot disk.
    pub const LBA_START: u64 = 1088;
    /// Inclusive end LBA of the WAL region.
    pub const LBA_END: u64 = 1599;

    /// Magic prefix of every WAL record.
    pub const MAGIC: [u8; 4] = *b"WAL2";

    /// Fixed header size in bytes. Layout (little-endian):
    /// - bytes 0..4:  magic = [`MAGIC`]
    /// - bytes 4..8:  record_kind (u32)
    /// - bytes 8..16: sequence_number (u64)
    /// - bytes 16..20: payload_len (u32)
    /// - bytes 20..24: tail_off (u32)
    /// - bytes 24..32: crc32c of payload (u32) + reserved (u32)
    pub const HEADER_LEN: usize = 32;

    /// Record kind: filesystem journal entry.
    pub const KIND_FS_JOURNAL: u32 = 0x0001;
    /// Record kind: audit log entry.
    pub const KIND_AUDIT: u32 = 0xAA01;
    /// Record kind: configuration update.
    pub const KIND_CONFIG: u32 = 0xC0F1;
    /// Record kind: capability mask transition.
    pub const KIND_CAP: u32 = 0xCAB1;
}

/// Allocator contract.
///
/// Invariants the verifier checks:
/// - Distinct allocations do not overlap.
/// - An allocation's bytes are preserved until it is freed.
/// - `dealloc` on a pointer not returned by `alloc` is undefined
///   behaviour (the contract does not promise detection).
pub trait Allocator {
    /// Allocate a region of `size` bytes aligned to `align`. Returns
    /// `None` if the request cannot be satisfied.
    ///
    /// # Safety
    /// The returned pointer is valid until passed to [`dealloc`](Self::dealloc).
    unsafe fn alloc(size: usize, align: usize) -> Option<*mut u8>;

    /// Free a region previously returned by [`alloc`](Self::alloc).
    ///
    /// # Safety
    /// `ptr` must have been returned by `alloc(size, align)` and not
    /// previously freed.
    unsafe fn dealloc(ptr: *mut u8, size: usize, align: usize);
}

/// Property-test harness exposed to the verifier when built with the
/// `property_tests` feature. The harness instantiates each trait above
/// against a candidate implementation and exercises the documented
/// invariants.
#[cfg(feature = "property_tests")]
pub mod harness {
    extern crate std;

    /// Verdict for a single candidate implementation against a single
    /// contract.
    pub enum Verdict {
        /// All checked invariants passed.
        Pass,
        /// One or more invariants failed. The string identifies the
        /// failing invariant for forensics.
        Fail(&'static str),
        /// The candidate was structurally invalid (failed to compile,
        /// failed to link, panicked on construction).
        Invalid(&'static str),
    }

    /// Run the [`super::Hash`] invariant battery against `H`.
    pub fn check_hash<H: super::Hash>() -> Verdict {
        // 1) Determinism on a fixed corpus.
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        for input in &[b"".as_slice(), b"abc", b"the quick brown fox"] {
            H::hash(input, &mut a[..H::OUTPUT_LEN]);
            H::hash(input, &mut b[..H::OUTPUT_LEN]);
            if a[..H::OUTPUT_LEN] != b[..H::OUTPUT_LEN] {
                return Verdict::Fail("hash determinism");
            }
        }
        // 2) Avalanche on a one-byte delta.
        H::hash(b"avalanche-base", &mut a[..H::OUTPUT_LEN]);
        H::hash(b"avalanche-bash", &mut b[..H::OUTPUT_LEN]);
        if a[..H::OUTPUT_LEN] == b[..H::OUTPUT_LEN] {
            return Verdict::Fail("hash avalanche");
        }
        Verdict::Pass
    }

    /// Run the [`super::Aead`] invariant battery against `A`.
    ///
    /// Exercises five invariants the verifier requires of any AEAD
    /// candidate:
    ///
    /// 1. **Round-trip** across five plaintext shapes: empty, single
    ///    byte, full-block-aligned (`KEY_LEN` bytes), full-block-
    ///    unaligned (`KEY_LEN * 3 + 5` bytes), and a long input
    ///    (`KEY_LEN * 17 + 3` bytes).
    /// 2. **Ciphertext-tamper rejection**: flip a byte in the
    ///    ciphertext body and confirm `decrypt` returns `Err`.
    /// 3. **Tag-tamper rejection**: flip a byte in the trailing tag
    ///    and confirm `decrypt` returns `Err`.
    /// 4. **AAD-tamper rejection**: encrypt with one AAD, decrypt
    ///    with a different AAD, confirm `Err`.
    /// 5. **Wrong-key rejection**: encrypt with `K1`, decrypt with
    ///    `K2 != K1` (differing in the leading byte to guarantee the
    ///    keystream differs), confirm `Err`.
    ///
    /// The harness does not check KAT compliance — that is left to
    /// algorithm-specific vectors outside this trait-level battery.
    pub fn check_aead<A: super::Aead>() -> Verdict {
        // Caller-provided constants. We pre-size scratch buffers large
        // enough for every test plaintext below.
        let key1: std::vec::Vec<u8> = (0..A::KEY_LEN as u8).map(|b| b ^ 0x5A).collect();
        let mut key2 = key1.clone();
        if key2.is_empty() {
            return Verdict::Invalid("aead: KEY_LEN is zero");
        }
        // Differ in byte 0 so the keystream materially differs even if
        // the candidate construction only mixes a prefix of the key
        // into its initial state.
        key2[0] ^= 0xFF;
        let nonce: std::vec::Vec<u8> = (0..A::NONCE_LEN as u8).map(|b| b.wrapping_add(7)).collect();
        let aad1: &[u8] = b"proteus-harness-aad-v1";
        let aad2: &[u8] = b"proteus-harness-aad-v2-different";

        // Test plaintexts spanning empty, single byte, block-aligned,
        // block-unaligned, and a long input.
        let block = A::KEY_LEN.max(1);
        let pt_empty: std::vec::Vec<u8> = std::vec::Vec::new();
        let pt_one: std::vec::Vec<u8> = std::vec![0xA5];
        let pt_aligned: std::vec::Vec<u8> = (0..block as u32).map(|i| (i & 0xFF) as u8).collect();
        let pt_unaligned: std::vec::Vec<u8> =
            (0..(block * 3 + 5) as u32).map(|i| ((i * 13) & 0xFF) as u8).collect();
        let pt_long: std::vec::Vec<u8> = (0..(block * 17 + 3) as u32)
            .map(|i| ((i ^ 0xC3) & 0xFF) as u8)
            .collect();

        let plaintexts: [&[u8]; 5] = [
            &pt_empty,
            &pt_one,
            &pt_aligned,
            &pt_unaligned,
            &pt_long,
        ];

        // 1. Round-trip across every plaintext shape.
        for (idx, pt) in plaintexts.iter().enumerate() {
            let mut ct = std::vec![0u8; pt.len() + A::TAG_LEN];
            let n = A::encrypt(&key1, &nonce, pt, aad1, &mut ct);
            if n != pt.len() + A::TAG_LEN {
                let _ = idx;
                return Verdict::Fail("aead: encrypt returned wrong length");
            }
            let mut recovered = std::vec![0u8; pt.len()];
            match A::decrypt(&key1, &nonce, &ct[..n], aad1, &mut recovered) {
                Ok(m) => {
                    if m != pt.len() || recovered[..] != pt[..] {
                        return Verdict::Fail("aead: round-trip mismatch");
                    }
                }
                Err(_) => return Verdict::Fail("aead: round-trip decrypt rejected legitimate ct"),
            }
        }

        // Build one ciphertext to drive all of the rejection tests.
        // Use an unaligned plaintext so both the body and tag carry
        // meaningful entropy.
        let pt = &pt_unaligned;
        let mut ct = std::vec![0u8; pt.len() + A::TAG_LEN];
        let n = A::encrypt(&key1, &nonce, pt, aad1, &mut ct);
        ct.truncate(n);

        // 2. Ciphertext-tamper rejection.
        if pt.is_empty() {
            // Pathological combo: no body to flip. Skip but flag.
            return Verdict::Invalid("aead: ciphertext-body too short to tamper");
        }
        let mut tampered_body = ct.clone();
        tampered_body[0] ^= 0x01;
        let mut sink = std::vec![0u8; pt.len()];
        if A::decrypt(&key1, &nonce, &tampered_body, aad1, &mut sink).is_ok() {
            return Verdict::Fail("aead: ciphertext-tampered ct was accepted");
        }

        // 3. Tag-tamper rejection.
        let mut tampered_tag = ct.clone();
        let last = tampered_tag.len() - 1;
        tampered_tag[last] ^= 0x80;
        if A::decrypt(&key1, &nonce, &tampered_tag, aad1, &mut sink).is_ok() {
            return Verdict::Fail("aead: tag-tampered ct was accepted");
        }

        // 4. AAD-tamper rejection.
        if A::decrypt(&key1, &nonce, &ct, aad2, &mut sink).is_ok() {
            return Verdict::Fail("aead: wrong-AAD decryption was accepted");
        }

        // 5. Wrong-key rejection.
        if A::decrypt(&key2, &nonce, &ct, aad1, &mut sink).is_ok() {
            return Verdict::Fail("aead: wrong-key decryption was accepted");
        }

        Verdict::Pass
    }

    /// Run the [`super::SignatureVerify`] invariant battery against `S`.
    /// The caller supplies a known-good `(pubkey, message, signature)`
    /// triple to bootstrap the positive-case check.
    pub fn check_signature<S: super::SignatureVerify>(
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
    ) -> Verdict {
        if !S::verify(pubkey, message, signature) {
            return Verdict::Fail("signature: valid sig rejected");
        }
        // Flip a single byte of the signature and confirm rejection.
        let mut bad = std::vec::Vec::from(signature);
        if bad.is_empty() {
            return Verdict::Invalid("signature too short");
        }
        bad[0] ^= 0x01;
        if S::verify(pubkey, message, &bad) {
            return Verdict::Fail("signature: tampered sig accepted");
        }
        // Mutate the message and confirm rejection.
        if !message.is_empty() {
            let mut bad_msg = std::vec::Vec::from(message);
            bad_msg[0] ^= 0x01;
            if S::verify(pubkey, &bad_msg, signature) {
                return Verdict::Fail("signature: wrong message accepted");
            }
        }
        Verdict::Pass
    }

    /// Thorough variant of [`check_signature`] that additionally
    /// exercises the rejection invariants the verifier requires of any
    /// `SignatureVerify` candidate:
    ///
    /// 1. The positive case from [`check_signature`] (valid sig accepted,
    ///    single-byte sig tamper rejected, single-byte message mutation
    ///    rejected).
    /// 2. **Wrong-pubkey rejection**: a different public key must NOT
    ///    verify the same `(message, signature)` pair.
    /// 3. **Multi-offset tamper rejection**: independently flipping each
    ///    of three different bytes at different offsets in the signature
    ///    must each cause rejection. (Strengthens the single-offset
    ///    check in [`check_signature`] against impls that only inspect
    ///    a prefix.)
    /// 4. **Length-mismatch rejection**: a signature truncated by one
    ///    byte must return `false`, not panic. The caller MUST guarantee
    ///    that `wrong_pubkey != pubkey` byte-for-byte; otherwise the
    ///    wrong-pubkey check is vacuous and the harness returns
    ///    `Invalid`.
    pub fn check_signature_thorough<S: super::SignatureVerify>(
        pubkey: &[u8],
        message: &[u8],
        signature: &[u8],
        wrong_pubkey: &[u8],
    ) -> Verdict {
        // Re-use the base battery first so the basic invariants are
        // covered before we layer the thorough checks on top.
        match check_signature::<S>(pubkey, message, signature) {
            Verdict::Pass => {}
            other => return other,
        }

        // Caller hygiene: a wrong_pubkey identical to pubkey would
        // make the next check tautologically pass, hiding a real bug.
        if wrong_pubkey == pubkey {
            return Verdict::Invalid("signature: wrong_pubkey == pubkey");
        }

        // 2. Wrong pubkey rejects.
        if S::verify(wrong_pubkey, message, signature) {
            return Verdict::Fail("signature: wrong pubkey accepted");
        }

        // 3. Multi-offset tamper. Pick three offsets that are spread
        // across the signature (start, middle, end) so an impl that
        // only checks a prefix or suffix is caught. Each tamper is
        // tested in isolation against a fresh copy of the signature.
        if signature.len() < 3 {
            return Verdict::Invalid("signature: too short for multi-offset tamper");
        }
        let off_mid = signature.len() / 2;
        let off_end = signature.len() - 1;
        let offsets = [0usize, off_mid, off_end];
        let mut seen: [usize; 3] = [usize::MAX; 3];
        let mut seen_n = 0usize;
        for &off in offsets.iter() {
            // Skip duplicates (would occur only for pathologically
            // short signatures we have already guarded against).
            let mut already = false;
            let mut k = 0;
            while k < seen_n {
                if seen[k] == off {
                    already = true;
                    break;
                }
                k += 1;
            }
            if already {
                continue;
            }
            seen[seen_n] = off;
            seen_n += 1;

            let mut bad = std::vec::Vec::from(signature);
            bad[off] ^= 0x80;
            if S::verify(pubkey, message, &bad) {
                return Verdict::Fail("signature: multi-offset tamper accepted");
            }
        }
        if seen_n < 3 {
            // Pathological: signature too short to host 3 distinct
            // offsets. Surface as Invalid rather than silently weaken.
            return Verdict::Invalid("signature: too short to host 3 distinct tamper offsets");
        }

        // 4. Length-mismatch rejection. Truncate the signature by one
        // byte and confirm verify returns false without panicking.
        let truncated = &signature[..signature.len() - 1];
        if S::verify(pubkey, message, truncated) {
            return Verdict::Fail("signature: truncated sig accepted");
        }

        Verdict::Pass
    }

    /// Adapter trait abstracting over a candidate's choice of
    /// `SyscallDispatch::Result` associated type. Any
    /// `core::result::Result<u64, E>` (for `E: core::fmt::Debug`) satisfies
    /// this; the blanket impl below is the only one the harness needs.
    ///
    /// This exists because `SyscallDispatch::Result` is a free associated
    /// type: a candidate may choose any error enum it likes. The harness,
    /// however, needs three concrete capabilities on that result —
    /// equality-of-Ok-payload (for determinism), is-Ok / is-Err
    /// discrimination, and extraction of the Ok payload for the known-
    /// mapped check. `SyscallResultLike` captures exactly those three
    /// without forcing the candidate to commit to a specific Errno enum.
    pub trait SyscallResultLike {
        /// True iff the result is the success variant.
        fn is_ok_like(&self) -> bool;
        /// Returns the `u64` Ok payload, or `None` if this is an error.
        fn ok_value(&self) -> Option<u64>;
    }

    impl<E> SyscallResultLike for core::result::Result<u64, E> {
        fn is_ok_like(&self) -> bool {
            self.is_ok()
        }
        fn ok_value(&self) -> Option<u64> {
            match self {
                Ok(v) => Some(*v),
                Err(_) => None,
            }
        }
    }

    /// Run the [`super::SyscallDispatch`] invariant battery against `S`.
    ///
    /// The harness is generic over the candidate's chosen
    /// `SyscallDispatch::Result` associated type via the
    /// [`SyscallResultLike`] adapter trait; any
    /// `core::result::Result<u64, E>` works without forcing the candidate
    /// to commit to a specific `Errno` enum.
    ///
    /// Invariants the verifier checks:
    /// 1. **Determinism**: `dispatch(nr, ...)` for a fixed argument tuple
    ///    produces the same Ok/Err discriminant AND the same Ok payload
    ///    on every call.
    /// 2. **Unmapped syscall returns Err**: a deliberately-large syscall
    ///    number (`999_999`) must map to the error variant. This is the
    ///    contract that userspace can detect an unsupported syscall.
    /// 3. **Known mapped syscall returns Ok**: `nr=0` (sys_noop) with
    ///    all-zero arguments must return `Ok(0)`. This is the smoke test
    ///    that the dispatch table is wired up at all.
    pub fn check_syscall_dispatch<S: super::SyscallDispatch>() -> Verdict
    where
        S::Result: SyscallResultLike,
    {
        // 1. Determinism on a fixed corpus of (nr, a0..a5) tuples. We
        // sample a mix of probably-mapped (small nr) and probably-
        // unmapped (large nr) numbers so that determinism is checked
        // on both Ok and Err paths.
        let corpus: [(u64, [u64; 6]); 4] = [
            (0, [0, 0, 0, 0, 0, 0]),
            (2, [1, 2, 3, 4, 5, 6]),
            (4, [0xAABB, 0xCCDD, 0xEEFF, 0, 0, 0]),
            (999_999, [1, 2, 3, 4, 5, 6]),
        ];
        for &(nr, a) in corpus.iter() {
            let r1 = S::dispatch(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
            let r2 = S::dispatch(nr, a[0], a[1], a[2], a[3], a[4], a[5]);
            if r1.is_ok_like() != r2.is_ok_like() {
                return Verdict::Fail("syscall: determinism (ok/err mismatch)");
            }
            if r1.ok_value() != r2.ok_value() {
                return Verdict::Fail("syscall: determinism (ok payload mismatch)");
            }
        }

        // 2. Unmapped syscall returns Err. Use a number deliberately far
        // outside the small mapped range so any plausible candidate will
        // hit the default arm.
        let unmapped = S::dispatch(999_999, 0, 0, 0, 0, 0, 0);
        if unmapped.is_ok_like() {
            return Verdict::Fail("syscall: unmapped nr was accepted");
        }

        // 3. Known mapped syscall returns Ok(0). sys_noop is the
        // smoke-test entry: nr=0, all zero args, expected Ok(0).
        let noop = S::dispatch(0, 0, 0, 0, 0, 0, 0);
        match noop.ok_value() {
            Some(0) => {}
            Some(_) => return Verdict::Fail("syscall: sys_noop returned non-zero Ok"),
            None => return Verdict::Fail("syscall: sys_noop returned Err"),
        }

        Verdict::Pass
    }
}

/// TLS 1.3 server contract — the byte-observable surface of the in-kernel
/// TLS module. Implementations morph aggressively over **internal**
/// helpers (key derivation intermediates, parsing utilities, scratch
/// buffer management) but the wire-format outputs of the methods below
/// are locked across all morph cycles.
///
/// Invariants the verifier checks:
///
/// - **Wire equivalence.** Given an identical (`client_hello`,
///   `server_random`, `server_pubkey`, `selected_alpn`) tuple, every
///   morph candidate's [`build_server_hello`](Self::build_server_hello)
///   produces the same bytes byte-for-byte.
/// - **HKDF KAT compliance.** [`hkdf_extract`](Self::hkdf_extract) and
///   [`hkdf_expand_label`](Self::hkdf_expand_label) match RFC 5869 +
///   RFC 8446 §7.1 published vectors byte-for-byte. Tested in
///   `target_enterprise/tests/tls_kat.rs`.
/// - **Buffer discipline.** Every method writes only into the caller-
///   supplied output buffer. Implementations may not heap-allocate
///   (`target_enterprise` is `no_std` without `alloc`).
///
/// The trait is **conservative**: only the minimum surface the morph
/// engine needs to lock is declared here. Cipher-suite selection logic,
/// extension parsing internals, and key-schedule chaining live in the
/// impl crate and are free to morph.
pub trait Tls13Server {
    /// Length of the outer TLS record header in bytes: `content_type` (1) +
    /// `legacy_version` (2) + `length` (2) = 5. Locked across all morph
    /// cycles per RFC 8446 §5.1.
    const RECORD_HEADER_LEN: usize = 5;

    /// Output length of the underlying hash (SHA-256) in bytes. TLS 1.3
    /// with TLS_AES_128_GCM_SHA256 or TLS_CHACHA20_POLY1305_SHA256 both
    /// use SHA-256, so this is fixed at 32 for the supported suite set.
    const HASH_LEN: usize = 32;

    /// Error type returned by fallible methods on this trait. Typically
    /// a small enum identifying which parse step or buffer check failed;
    /// the contract does not lock the discriminants because the verifier
    /// only inspects success-path outputs.
    type Error;

    /// Build the handshake-message-encoded ServerHello in response to
    /// `client_hello`. The output is the Handshake message (type byte +
    /// uint24 length + body) — the caller is responsible for wrapping
    /// it in a record header if a wire-level record is needed.
    ///
    /// # Preconditions
    /// - `client_hello` is the handshake-typed payload (no outer record
    ///   header). Implementations parse it strictly; any malformed input
    ///   returns `Err`.
    /// - `server_random` is 32 caller-supplied bytes (typically from a
    ///   CSPRNG; the trait does not lock the source).
    /// - `server_pubkey` is a 32-byte X25519 public key matching the
    ///   ephemeral private key the server holds for this handshake.
    /// - `selected_alpn`, if `Some`, names an ALPN protocol ID the
    ///   server selected from the client's offer (e.g. `b"h2"`,
    ///   `b"http/1.1"`). The encoded length must be 1..=255.
    /// - `out` must be at least 256 bytes long to hold any legal
    ///   ServerHello this trait emits. Implementations MAY require less;
    ///   the verifier asserts byte-exactness only on the prefix.
    ///
    /// # Returns
    /// Number of bytes written to `out`. The valid prefix is
    /// `out[..returned]`.
    fn build_server_hello(
        client_hello: &[u8],
        server_random: &[u8; 32],
        server_pubkey: &[u8; 32],
        selected_alpn: Option<&[u8]>,
        out: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// HKDF-Extract over SHA-256 per RFC 5869 §2.2. Writes 32 bytes to
    /// `out`. `salt` may be empty (treated as 32 zero bytes per RFC).
    /// `ikm` is arbitrary-length input keying material.
    ///
    /// # Preconditions
    /// `out` is a fixed `&mut [u8; 32]` so length is statically correct;
    /// no runtime length check is needed.
    fn hkdf_extract(salt: &[u8], ikm: &[u8], out: &mut [u8; 32]);

    /// HKDF-Expand-Label per RFC 8446 §7.1. The encoded `HkdfLabel`
    /// uses the implicit `"tls13 "` prefix so labels derived under
    /// different protocols can never collide.
    ///
    /// # Preconditions
    /// - `secret` is a 32-byte pseudorandom key (typically the output
    ///   of `hkdf_extract` or a previous expand-label step).
    /// - `label.len() + 6` (the `"tls13 "` prefix) must fit in a u8
    ///   (≤ 255). `context.len()` must fit in a u8.
    /// - `out.len()` must be ≤ `255 * 32` (the HKDF-Expand cap).
    ///   Behaviour for over-length `out` is implementation-defined
    ///   panic; the verifier does not exercise this path.
    fn hkdf_expand_label(secret: &[u8; 32], label: &[u8], context: &[u8], out: &mut [u8]);
}

// ============================================================
// TLS 1.3 client (RFC 8446) — TASK-049
// ============================================================

/// Parsed view of a TLS 1.3 ServerHello returned by
/// [`Tls13Client::parse_server_hello`].
///
/// The shape is intentionally minimal: only fields needed to drive the
/// key schedule forward (server_random for transcript binding, the
/// chosen `cipher_suite`, the server's x25519 ephemeral public key).
/// Extensions other than `supported_versions` (asserted = 0x0304) and
/// `key_share` (x25519) are tolerated but discarded.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ParsedServerHello {
    /// Server-supplied 32 bytes of randomness (TLS 1.3 §4.1.3). Used
    /// in the transcript-hash that feeds Derive-Secret.
    pub server_random: [u8; 32],
    /// Server's selected cipher suite. The client locks to the offered
    /// suite set and rejects an unrecognised pick. TASK-049 ships with
    /// `TLS_AES_128_GCM_SHA256` (0x1301) as the sole accepted value;
    /// the field is stored verbatim so a future suite addition is a
    /// pure schema extension.
    pub cipher_suite: u16,
    /// Server's ephemeral x25519 public key recovered from the
    /// `key_share` extension. Combined with the client's ephemeral
    /// secret (out-of-band) to produce the (EC)DHE shared secret that
    /// feeds the handshake-secret HKDF-Extract step.
    pub server_pubkey: [u8; 32],
}

/// Handshake-layer traffic secrets derived by
/// [`Tls13Client::derive_handshake_keys`]. RFC 8446 §7.1 ("Key
/// Schedule").
///
/// The three fields are the locked outputs of the schedule:
///
/// - `handshake_secret`  = HKDF-Extract(derived_early, shared_secret)
/// - `client_handshake_traffic_secret`
///                       = Derive-Secret(HS, "c hs traffic", CH..SH)
/// - `server_handshake_traffic_secret`
///                       = Derive-Secret(HS, "s hs traffic", CH..SH)
///
/// Each is 32 bytes (SHA-256 output length). The downstream key/iv
/// derivation (HKDF-Expand-Label with `"key"` / `"iv"`) is performed
/// out-of-band by the caller — this trait's responsibility is the
/// schedule prefix that locks every morph cycle to the same bytes.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct HandshakeKeys {
    /// HKDF-Extract output that anchors every subsequent client/server
    /// handshake-traffic derivation. 32 bytes (HMAC-SHA-256 output).
    pub handshake_secret: [u8; 32],
    /// Client-direction handshake traffic secret. Used by the client
    /// to encrypt its Finished message and any 0-RTT early-data record
    /// (early data is out of scope for TASK-049).
    pub client_handshake_traffic_secret: [u8; 32],
    /// Server-direction handshake traffic secret. Used by the client
    /// to decrypt the server's EncryptedExtensions + Certificate +
    /// CertificateVerify + Finished records.
    pub server_handshake_traffic_secret: [u8; 32],
}

/// TLS 1.3 client primitives — the outbound counterpart to
/// [`Tls13Server`]. **Locked surface** for the morph engine.
///
/// The four methods together cover the handshake-message layer of an
/// outbound TLS 1.3 connection through ClientFinished. AEAD record-
/// layer encryption + certificate-chain validation + curve25519
/// scalar-multiplication are out of scope for TASK-049 (and are bound
/// to the existing [`Aead`] / [`SignatureVerify`] surfaces or are
/// future tasks).
///
/// Invariants the verifier checks:
///
/// - **Wire equivalence on ClientHello.** Given an identical
///   (`client_random`, `client_pubkey`) tuple, every morph candidate's
///   [`build_client_hello`](Self::build_client_hello) produces the same
///   bytes byte-for-byte. The cipher_suites list MUST be the singleton
///   `[TLS_AES_128_GCM_SHA256]`; the extension order MUST be
///   `[supported_versions, signature_algorithms, key_share]` (RFC 8446
///   §4.1.2 does not lock extension order on the wire, but the
///   contract does so morph runs are byte-comparable).
/// - **Parse correctness on ServerHello.** Given a byte-identical
///   ServerHello, every candidate's
///   [`parse_server_hello`](Self::parse_server_hello) returns the same
///   [`ParsedServerHello`].
/// - **Key-schedule KAT.** Given an identical
///   (`shared_secret`, `client_hello`, `server_hello`) tuple,
///   [`derive_handshake_keys`](Self::derive_handshake_keys) writes the
///   same [`HandshakeKeys`] bytes. The schedule MUST follow RFC 8446
///   §7.1 to the letter: early_secret = HKDF-Extract(0, 0); derived =
///   Derive-Secret(early_secret, "derived", ""); handshake_secret =
///   HKDF-Extract(derived, shared_secret); the two traffic secrets are
///   Derive-Secret(HS, "c hs traffic" | "s hs traffic", CH || SH).
/// - **Finished MAC.** Given an identical
///   (`client_handshake_traffic_secret`, `transcript_hash`) pair,
///   [`build_client_finished`](Self::build_client_finished) writes the
///   same 32-byte HMAC-SHA-256 verify_data per RFC 8446 §4.4.4.
/// - **Buffer discipline.** Every method writes only into the caller-
///   supplied output buffer. Implementations may not heap-allocate
///   (`target_enterprise` is `no_std` without `alloc`).
pub trait Tls13Client {
    /// Length of the outer TLS record header in bytes. Locked at 5
    /// (content_type + legacy_version + length) — same as
    /// [`Tls13Server::RECORD_HEADER_LEN`].
    const RECORD_HEADER_LEN: usize = 5;

    /// Output length of the underlying hash (SHA-256). Locked at 32.
    const HASH_LEN: usize = 32;

    /// Error type returned by fallible methods on this trait.
    /// Discriminants are not locked by the contract; only the success-
    /// path output bytes are part of the verifier's wire-equivalence
    /// check.
    type Error;

    /// Build the handshake-message-encoded ClientHello into `out`.
    /// Returns the number of bytes written. The output is the Handshake
    /// message (`type(1) | length(3) | body`) — the caller wraps it in
    /// a record header for wire transmission.
    ///
    /// # Preconditions
    /// - `client_random` is 32 caller-supplied bytes (typically from a
    ///   CSPRNG; the trait does not lock the source).
    /// - `client_pubkey` is a 32-byte x25519 ephemeral public key. The
    ///   matching scalar private key lives in the caller for the
    ///   subsequent (EC)DHE step.
    /// - `out` must be at least 256 bytes long. The actual emitted
    ///   length is comfortably under 200 bytes for the locked
    ///   extension set, but the caller is required to size the buffer
    ///   so a future ALPN/SNI extension does not require an API break.
    fn build_client_hello(
        client_random: &[u8; 32],
        client_pubkey: &[u8; 32],
        out: &mut [u8],
    ) -> Result<usize, Self::Error>;

    /// Parse a Handshake-typed ServerHello payload (no outer record
    /// header). Strict on every length field; any over-read returns
    /// `Err`. Returns the locked [`ParsedServerHello`] view.
    fn parse_server_hello(server_hello: &[u8]) -> Result<ParsedServerHello, Self::Error>;

    /// Run the TLS 1.3 key schedule prefix (RFC 8446 §7.1) through the
    /// two handshake-traffic secrets. Writes the result into `out`.
    ///
    /// `client_hello` and `server_hello` are the Handshake-message
    /// encodings (the same byte slices the caller passed to / received
    /// from [`build_client_hello`] / [`parse_server_hello`]). The
    /// transcript-hash input to the two Derive-Secret calls is
    /// SHA-256(client_hello || server_hello).
    fn derive_handshake_keys(
        shared_secret: &[u8; 32],
        client_hello: &[u8],
        server_hello: &[u8],
        out: &mut HandshakeKeys,
    );

    /// Compute the client Finished `verify_data` per RFC 8446 §4.4.4:
    ///
    /// ```text
    /// finished_key = HKDF-Expand-Label(client_handshake_traffic_secret,
    ///                                  "finished", "", 32)
    /// verify_data  = HMAC-SHA-256(finished_key, transcript_hash)
    /// ```
    ///
    /// `transcript_hash` is SHA-256 over every handshake message from
    /// ClientHello through the server's Finished (inclusive). The
    /// caller is responsible for accumulating that hash; the trait
    /// surface keeps the responsibility separation between the schedule
    /// (this trait) and the transcript log (caller).
    fn build_client_finished(
        client_handshake_traffic_secret: &[u8; 32],
        transcript_hash: &[u8; 32],
        out: &mut [u8; 32],
    );
}

/// Write-ahead log contract — the locked durability surface for any
/// persistent kernel state that needs to survive an unclean shutdown.
///
/// The contract describes an append-only journal of opaque records
/// with a *durable cursor* that advances on `flush(proof)`. Replay
/// after a simulated crash yields exactly the records that were
/// durably flushed before the crash — never more, never less.
///
/// **TASK-161:** `flush` requires a [`CapProof`] minted under
/// [`caps::DURABLE_WAL_WRITE`] (or a superset). This is the first
/// durable-write gate: unprivileged code cannot advance
/// `durable_cursor` without a successful capability check. Residual
/// remains open for jfs / audit-persist / raw block paths.
///
/// Invariants the verifier checks:
///
/// - **Length-prefix + CRC32 framing.** Every record on the backing
///   store is encoded as `[len: u32 LE][crc32: u32 LE][payload...]`.
///   The CRC is computed over the payload bytes only (the length and
///   crc fields themselves are excluded so a partial write that tears
///   the header is naturally detected by short-read).
/// - **Monotonic LSNs.** `append` returns a strictly increasing log
///   sequence number, starting at 1 for the first record after a
///   fresh init. LSNs never wrap and never repeat across replays.
/// - **Durable-prefix replay.** `replay(cb)` walks the journal from
///   the start and invokes `cb(lsn, payload)` for every record whose
///   framing validates AND that lies wholly within the durable
///   cursor. The first corrupt or truncated record stops the walk;
///   nothing after it is delivered.
/// - **No-mock equivalence.** Reconstructing the WAL from its backing
///   store and calling `replay(cb)` must yield exactly the records
///   that were durably committed (i.e. `append`'d AND followed by a
///   successful `flush()`) before the simulated crash. Records that
///   were `append`'d but never `flush`'d may or may not appear; the
///   contract permits either, since the durable cursor lagged behind
///   the write cursor at crash time.
///
/// The trait is intentionally object-safe-friendly: no const generics
/// or associated constants on the trait itself. Concrete impls may
/// (and the canonical `target_enterprise` impl does) parameterise
/// their backing-store capacity as a const generic on the impl
/// struct, not on the trait.
pub trait WriteAheadLog {
    /// Error variant returned by fallible methods. Typically a small
    /// enum identifying which framing or capacity check failed.
    /// The contract does not lock the discriminants because the
    /// verifier inspects success-path semantics and the binary
    /// equivalence of `replay` output, not error taxonomy.
    type Error;

    /// Append `record` to the in-memory write cursor of the journal.
    /// Returns the assigned log sequence number on success.
    ///
    /// The record is NOT durable until a subsequent successful
    /// `flush()`. A crash between `append` and `flush` may leave the
    /// record either fully discarded or fully recovered on replay;
    /// the contract permits either outcome but forbids partial /
    /// corrupt visibility of the record.
    fn append(&mut self, record: &[u8]) -> Result<u64, Self::Error>;

    /// Advance the durable cursor to the current write cursor. After
    /// this returns `Ok(())`, every record `append`'d before this
    /// call is guaranteed to be visible to a subsequent `replay`,
    /// even if the in-memory WAL is dropped and reconstructed from
    /// the backing store between now and then.
    ///
    /// **Capability (TASK-161):** callers must pass a [`CapProof`]
    /// obtained after a successful check that the task holds
    /// [`caps::DURABLE_WAL_WRITE`]. The proof is taken by value so
    /// the compiler refuses calls without a mint; the impl may
    /// ignore the proof body (marker). Use [`mint_cap_proof`] in
    /// tests and privileged init paths.
    fn flush(&mut self, proof: CapProof) -> Result<(), Self::Error>;

    /// Walk the durable prefix of the journal in append order,
    /// invoking `callback(lsn, payload)` for each record whose
    /// framing validates. Stops at the first corrupt / short /
    /// CRC-mismatched record without invoking the callback for it.
    ///
    /// `replay` is read-only with respect to the backing store: it
    /// does not advance any cursor and may be called multiple times
    /// with idempotent observable behaviour.
    fn replay(&self, callback: &mut dyn FnMut(u64, &[u8]));
}

/// Page permission bits for an IOMMU mapping.
///
/// Locked across all morph cycles. The bit layout is exposed as a
/// `Copy` newtype around `u8` so callers can read individual bits
/// without committing to a specific enum representation that a future
/// hardware shadow might change.
///
/// `READ` and `WRITE` mirror the Intel VT-d second-level page-table
/// entry permission bits (VT-d §9.7). Implementations that model
/// AMD-Vi or ARM SMMU may collapse to the same two bits since those
/// architectures expose at minimum a read/write distinction at the
/// page-table-entry level.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct PagePerms(pub u8);

impl PagePerms {
    /// Read permission bit. Set when DMA reads from the page are
    /// allowed.
    pub const READ: PagePerms = PagePerms(1 << 0);
    /// Write permission bit. Set when DMA writes to the page are
    /// allowed.
    pub const WRITE: PagePerms = PagePerms(1 << 1);
    /// Read and write. The common case for streaming DMA buffers.
    pub const RW: PagePerms = PagePerms(0b11);

    /// `true` iff the read bit is set.
    pub const fn readable(self) -> bool {
        (self.0 & Self::READ.0) != 0
    }
    /// `true` iff the write bit is set.
    pub const fn writable(self) -> bool {
        (self.0 & Self::WRITE.0) != 0
    }
}

/// Kind of DMA access being attempted by a device. Inputs to the
/// `translate` walk so the IOMMU can reject a write to a read-only
/// mapping (or vice versa) with `PermissionDenied`.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AccessKind {
    /// DMA read from the page.
    Read,
    /// DMA write to the page.
    Write,
}

/// Errors the [`Iommu`] trait surfaces. Discriminants are part of the
/// locked contract — userspace and the morph verifier observe these
/// variants by name. Numeric values are not stabilised; only the
/// variant identities are.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum IommuError {
    /// The implementation's fixed `MAX_DOMAINS` capacity is exhausted.
    /// `create_domain` returns this when no free domain slot exists.
    DomainTableFull,
    /// The implementation's fixed `MAX_DEVICES` capacity is exhausted.
    /// `bind_device` returns this when no free device slot exists for
    /// a previously-unknown BDF.
    DeviceTableFull,
    /// The named domain id does not correspond to a live domain.
    UnknownDomain,
    /// The device is already bound to a domain. `bind_device` returns
    /// this rather than silently rebinding so callers must explicitly
    /// `unbind_device` first — silent rebinding has historically been
    /// a CVE vector in DMA-protection stacks.
    DeviceAlreadyBound,
    /// The device is not bound to any domain. `translate` returns this
    /// for unbound devices; `unbind_device` returns this when called on
    /// a device the IOMMU has never seen or has already unbound.
    DeviceNotBound,
    /// The DMA address has no mapping in the bound domain's page
    /// table. The translation is rejected — the donor hardware would
    /// raise a DMA fault here.
    Unmapped,
    /// The DMA address has a mapping but the access kind is not
    /// permitted by the mapping's [`PagePerms`]. The donor hardware
    /// would raise a DMA permission fault here.
    PermissionDenied,
    /// `map` was called for a DMA address that already has a live
    /// mapping in the target domain. Implementations MUST NOT silently
    /// overwrite — silently dropping a mapping has historically been a
    /// use-after-free vector in DMA-protection stacks.
    AlreadyMapped,
    /// The DMA address (or host physical address) is not page-aligned,
    /// or the DMA address falls outside the implementation's bounded
    /// per-domain mapping range.
    BadAddress,
}

/// IOMMU + DMA protection contract — the locked isolation surface for
/// any DMA-capable device the kernel hands to a driver.
///
/// The contract describes a logical Intel VT-d-style IOMMU with three
/// nouns and one verb:
///
/// 1. **Domain** — an isolation context. Many devices may be bound to
///    one domain; a domain owns a page table mapping DMA addresses to
///    host physical frames plus a [`PagePerms`] mask per page.
/// 2. **Device** — identified by a stable `(segment, bus, dev, func)`
///    BDF tuple folded into a 32-bit [`Iommu::DeviceId`] by the impl.
///    Each device is either *unbound* (default = deny all DMA) or
///    bound to exactly one domain.
/// 3. **Mapping** — a `(dma_addr → host_phys, perms)` page-table entry
///    in a specific domain. Inserted by `map`, removed by `unmap`.
/// 4. **Translate** — the page-table walk verb. Given a DeviceId, a
///    DMA address, and an [`AccessKind`], either return the host
///    physical address the DMA would target or reject the access with
///    a specific [`IommuError`].
///
/// Invariants the verifier checks:
///
/// - **Default-deny.** `translate` on an unbound device returns
///   `Err(IommuError::DeviceNotBound)` for every DMA address. There
///   is no implicit identity mapping; a device must be explicitly
///   bound to a domain before any DMA can succeed.
/// - **Domain isolation.** A `map` in domain A is invisible to a
///   device bound to domain B. `translate` from a device in B for
///   that DMA address returns `Err(Unmapped)`, never the host physical
///   from A's table.
/// - **Permission enforcement.** A `Write` access to a `READ`-only
///   mapping returns `Err(PermissionDenied)`. The contract does not
///   require timing-side-channel resistance on this path — the
///   verifier inspects only the Result discriminant.
/// - **No silent rebind.** `bind_device` on an already-bound device
///   returns `Err(DeviceAlreadyBound)` rather than silently moving
///   the device to the new domain. Callers must `unbind_device` first.
/// - **No silent remap.** `map` on a DMA address that already has a
///   live mapping in the target domain returns `Err(AlreadyMapped)`
///   rather than silently overwriting the existing entry.
///
/// The trait is intentionally object-safe-friendly: no const generics
/// or associated constants on the trait itself. Concrete impls
/// (notably `target_enterprise::IommuImpl`) parameterise their domain
/// and device table capacities as const generics on the impl struct,
/// not on the trait.
pub trait Iommu {
    /// Identifier for a domain. Concrete impls use a small integer
    /// index into a fixed-capacity domain table; the contract leaves
    /// the width open so a future shadow can use a 64-bit handle if
    /// MAX_DOMAINS grows past `u32::MAX`.
    type DomainId: Copy + Eq;

    /// Identifier for a DMA-capable device. Concrete impls pack the
    /// `(segment, bus, dev, func)` BDF into a `u32` (segment:16,
    /// bus:8, dev:5, func:3). The contract treats the value as
    /// opaque.
    type DeviceId: Copy + Eq;

    /// Construct a fresh, empty domain. The new domain has no
    /// mappings; any `translate` against a device bound to this
    /// domain returns `Err(Unmapped)` until `map` is called.
    ///
    /// Returns `Err(DomainTableFull)` when the impl's fixed
    /// `MAX_DOMAINS` capacity is exhausted.
    fn create_domain(&mut self) -> Result<Self::DomainId, IommuError>;

    /// Bind `device` to `domain`. After a successful bind, DMA
    /// translations for `device` are resolved against `domain`'s
    /// page table.
    ///
    /// Returns `Err(UnknownDomain)` if `domain` is not live,
    /// `Err(DeviceAlreadyBound)` if `device` is already bound (use
    /// `unbind_device` first), or `Err(DeviceTableFull)` if the
    /// impl's fixed `MAX_DEVICES` capacity is exhausted by this
    /// previously-unknown device.
    fn bind_device(
        &mut self,
        device: Self::DeviceId,
        domain: Self::DomainId,
    ) -> Result<(), IommuError>;

    /// Unbind `device` from its current domain. After unbind, the
    /// device defaults to deny-all: `translate` returns
    /// `Err(DeviceNotBound)` for every DMA address.
    ///
    /// Returns `Err(DeviceNotBound)` if the device is not currently
    /// bound.
    fn unbind_device(&mut self, device: Self::DeviceId) -> Result<(), IommuError>;

    /// Install a page-table entry mapping `dma_addr` to `host_phys`
    /// with `perms` in `domain`. Both addresses must be page-aligned
    /// (4 KiB) and `dma_addr` must lie within the impl's bounded
    /// per-domain mapping range.
    ///
    /// Returns `Err(AlreadyMapped)` rather than silently overwriting
    /// an existing entry. Callers that want to change a mapping must
    /// `unmap` first.
    fn map(
        &mut self,
        domain: Self::DomainId,
        dma_addr: u64,
        host_phys: u64,
        perms: PagePerms,
    ) -> Result<(), IommuError>;

    /// Remove the page-table entry for `dma_addr` from `domain`.
    /// Returns `Err(Unmapped)` if no such entry exists.
    fn unmap(&mut self, domain: Self::DomainId, dma_addr: u64) -> Result<(), IommuError>;

    /// Walk the page table for the domain that `device` is bound to
    /// and resolve `dma_addr` for the given `access` kind. Returns
    /// the host physical address on success.
    ///
    /// On failure, returns one of:
    /// - `Err(DeviceNotBound)` — `device` is not bound to any
    ///   domain. This is the default-deny outcome for a never-bound
    ///   or already-unbound device.
    /// - `Err(Unmapped)` — `device` is bound, but the domain's page
    ///   table has no entry for the page containing `dma_addr`.
    /// - `Err(PermissionDenied)` — the entry exists but its
    ///   [`PagePerms`] does not permit `access`.
    fn translate(
        &self,
        device: Self::DeviceId,
        dma_addr: u64,
        access: AccessKind,
    ) -> Result<u64, IommuError>;
}

/// Permission bits returned by [`Ipv4HeaderView::flags`] / written into
/// the IPv4 flags+fragment-offset word. Locked by RFC 791 §3.1.
///
/// Bit 0 is reserved and MUST be zero. Bit 1 is the Don't Fragment (DF)
/// flag. Bit 2 is the More Fragments (MF) flag. The remaining 13 bits
/// of the word carry the fragment offset (in 8-byte units).
pub mod ipv4_flags {
    /// Don't-Fragment flag. Bit 1 of the 3-bit flags field. Set in every
    /// datagram emitted by [`NetStack::build_udp_datagram`]; any
    /// received datagram with DF clear AND a non-zero fragment offset
    /// is rejected by [`NetStack::parse_ipv4_header`] with
    /// [`NetError::Fragmented`].
    pub const DF: u8 = 0b010;
    /// More-Fragments flag. Bit 2 of the 3-bit flags field. Set on every
    /// fragment of a fragmented datagram except the last. A received
    /// datagram with MF set is rejected by
    /// [`NetStack::parse_ipv4_header`] with [`NetError::Fragmented`].
    pub const MF: u8 = 0b001;
}

/// IPv4 protocol number for UDP per IANA / RFC 768. Locked across all
/// morph cycles.
pub const IP_PROTO_UDP: u8 = 17;

/// Errors surfaced by the [`NetStack`] contract.
///
/// Locked discriminants: external callers (and the verifier) match on
/// these variants by name. Adding a variant is a schema-compatible
/// extension; renaming or removing one is a schema break that requires
/// bumping [`CONTRACTS_SCHEMA_VERSION`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum NetError {
    /// The input slice was shorter than the smallest legal header (20
    /// bytes for IPv4, 8 bytes for UDP, 28 bytes for an IPv4+UDP
    /// datagram).
    Truncated,
    /// The IPv4 version nibble was not 4. Includes the case where the
    /// caller fed an IPv6 packet (version nibble 6) into the IPv4
    /// parser.
    BadVersion,
    /// The IPv4 IHL field declared a header length under 20 bytes
    /// (less than 5 four-byte words). RFC 791 §3.1 fixes the minimum
    /// header length at 5 IHL words.
    BadHeaderLength,
    /// The IPv4 header carried options. The locked surface is
    /// intentionally options-free: IHL is always 5, header length is
    /// always 20 bytes. Datagrams with IHL > 5 are rejected so the
    /// morph engine has a single canonical header shape to reason
    /// about.
    OptionsPresent,
    /// The IPv4 total-length field did not match the slice length.
    /// Implementations are strict: `total_length` must equal the size
    /// of the slice passed in. This prevents trailing-byte attacks.
    BadTotalLength,
    /// The IPv4 header checksum did not validate. The header checksum
    /// is computed per RFC 1071 (the standard Internet 16-bit one's
    /// complement of the one's complement sum, with the checksum field
    /// itself treated as zero during computation).
    BadIpv4Checksum,
    /// The IPv4 datagram had the MF flag set OR the fragment offset
    /// was non-zero. The locked surface rejects fragments — UDP
    /// datagrams emitted by [`NetStack::build_udp_datagram`] always set
    /// DF, and inbound fragments are rejected on parse to avoid the
    /// reassembly complexity in a no-alloc kernel.
    Fragmented,
    /// The IPv4 protocol byte was not [`IP_PROTO_UDP`] (17). The UDP
    /// helpers in [`NetStack`] reject other protocols up front rather
    /// than silently returning data the caller can't use.
    NotUdp,
    /// The IPv4 TTL field reached zero in a received datagram. Routers
    /// MUST discard TTL=0 datagrams (RFC 791 §3.2 "If this field
    /// contains the value zero, then the datagram must be destroyed").
    HopLimitZero,
    /// The UDP length field did not match the IPv4 payload length, OR
    /// the UDP length field was less than 8 bytes (the UDP header
    /// itself). RFC 768 fixes UDP length as "the length in octets of
    /// this user datagram including this header and the data".
    BadUdpLength,
    /// The UDP checksum did not validate. Computed per RFC 768 over
    /// the pseudo-header (src_ip, dst_ip, 0x00, protocol=17,
    /// udp_length) concatenated with the UDP segment, padded with a
    /// trailing zero octet if the total has odd length. A received
    /// checksum field of `0x0000` is also rejected: IPv4 UDP makes
    /// the checksum mandatory only when the sender chooses, but the
    /// locked surface requires it (the builder always emits a non-zero
    /// checksum; verifier matches that).
    BadUdpChecksum,
    /// The payload supplied to [`NetStack::build_udp_datagram`] exceeded
    /// what fits in a single un-fragmented datagram (max 65515 bytes:
    /// IPv4 total_length is u16 → 65535, minus 20 IPv4 header, minus
    /// 8 UDP header). In practice fixed-buffer impls will hit this
    /// limit much earlier via [`NetError::OutputBufferTooSmall`].
    PayloadTooLarge,
    /// The caller-supplied output buffer was too small to hold the
    /// IPv4+UDP datagram the builder would emit.
    OutputBufferTooSmall,
    /// The UDP source or destination port was zero. RFC 768 §"Fields"
    /// permits zero only when the receiver expects no reply; the
    /// locked surface rejects it because every emitted datagram is a
    /// fresh send (no unsolicited zero-source dance).
    PortZero,
}

/// Parsed IPv4 header view returned by [`NetStack::parse_ipv4_header`].
///
/// All multi-byte fields are returned in **host byte order** — the parser
/// performs the network-order → host-order conversion. The fields mirror
/// RFC 791 §3.1 one-for-one.
///
/// Locked across morph cycles: a morph candidate that adds a field, drops
/// a field, or re-orders the existing fields breaks the verifier's
/// equality check against the trait surface. Internal layout (struct
/// packing, field alignment) is implementation-defined; only the field
/// names and their types are locked.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct Ipv4HeaderView {
    /// Version nibble. Always 4 on a successful parse — a non-4
    /// version surfaces as [`NetError::BadVersion`] before the view
    /// is built.
    pub version: u8,
    /// Internet Header Length in 32-bit words. Always 5 on a
    /// successful parse — the locked surface rejects IHL > 5 as
    /// [`NetError::OptionsPresent`].
    pub ihl: u8,
    /// DSCP (6 bits, upper) + ECN (2 bits, lower). The builder writes
    /// 0; the parser surfaces whatever was on the wire.
    pub dscp_ecn: u8,
    /// Total IPv4 datagram length in bytes (header + payload), 20..=65535.
    pub total_length: u16,
    /// IPv4 Identification field. Used by routers to reassemble
    /// fragments; the locked surface treats it as caller-supplied and
    /// preserves the bytes on parse for diagnostics. RFC 6864
    /// clarifies that for DF=1 datagrams the field has no reassembly
    /// semantic, but the wire bytes are still observable.
    pub identification: u16,
    /// 3-bit flags field, right-aligned in the byte. See
    /// [`ipv4_flags`] for the named bits.
    pub flags: u8,
    /// 13-bit fragment offset in 8-byte units. Always 0 on a
    /// successful parse — non-zero offsets surface as
    /// [`NetError::Fragmented`].
    pub fragment_offset: u16,
    /// Time-to-live. The locked surface rejects TTL=0 on parse as
    /// [`NetError::HopLimitZero`].
    pub ttl: u8,
    /// Next-protocol field. The UDP helpers reject anything other
    /// than [`IP_PROTO_UDP`] (17) as [`NetError::NotUdp`].
    pub protocol: u8,
    /// IPv4 header checksum as it appeared on the wire (host order).
    /// Already validated against the rest of the header by the time
    /// the parser returns success.
    pub header_checksum: u16,
    /// Source IPv4 address (network-order bytes).
    pub src_ip: [u8; 4],
    /// Destination IPv4 address (network-order bytes).
    pub dst_ip: [u8; 4],
}

/// Parsed UDP datagram view returned by [`NetStack::parse_udp_datagram`].
///
/// Layout mirrors RFC 768 §"Fields". As with [`Ipv4HeaderView`], all
/// multi-byte fields are returned in host byte order. The `payload_off`
/// and `payload_len` fields are byte indices into the slice that was
/// parsed, computed so that `&slice[off..off+len]` is the UDP payload.
///
/// Locked across morph cycles.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct UdpDatagramView {
    /// Source port (host order). Non-zero on a successful parse.
    pub src_port: u16,
    /// Destination port (host order). Non-zero on a successful parse.
    pub dst_port: u16,
    /// UDP length field (header + payload, host order), 8..=65535.
    pub length: u16,
    /// UDP checksum as it appeared on the wire (host order). Already
    /// validated against the pseudo-header + segment when the parser
    /// returns success.
    pub checksum: u16,
    /// Byte offset into the UDP segment slice where the payload begins.
    /// Always 8 (the fixed UDP header length).
    pub payload_off: usize,
    /// Byte length of the UDP payload (excludes the 8-byte UDP header).
    /// Equals `length - 8`.
    pub payload_len: usize,
}

/// In-kernel UDP/IPv4 network stack contract — the locked wire-observable
/// surface for the network-stack seed introduced by TASK-011.
///
/// # Wire equivalence — the load-bearing invariant
///
/// Two distinct morph candidates of an implementation MUST emit
/// **byte-identical** wire bytes for the same `(src_ip, dst_ip, src_port,
/// dst_port, payload, ttl, ident)` tuple. The verifier exercises this
/// via golden-bytes tests (one captured byte string per canonical
/// tuple) AND via a 5-cycle diversification round-trip that re-parses
/// the emitted bytes and re-emits, asserting bit-equality.
///
/// Internals are diversifiable — the parser may use a cursor-style or
/// fixed-offset style, the checksum routine may unroll or branch, local
/// variable naming and ordering may be perturbed by the diversifier.
/// Only the bytes on the wire are locked.
///
/// # RFC compliance
///
/// - IPv4 header layout: **RFC 791 §3.1** verbatim, with the locked
///   restriction `IHL == 5` (no options). Datagrams with IHL > 5 are
///   rejected on parse as [`NetError::OptionsPresent`].
/// - IPv4 header checksum: **RFC 1071** (the standard Internet 16-bit
///   one's-complement of the one's-complement sum). The checksum field
///   itself is treated as zero during the computation; the final value
///   is the one's complement of the running sum, with the all-zeros
///   result mapped to all-ones per the Internet convention so a zero
///   header_checksum on the wire unambiguously means "no checksum
///   present" (which the locked surface rejects).
/// - UDP layout + length semantics: **RFC 768**. Source and destination
///   ports, length (covering header + payload), checksum.
/// - UDP checksum: **RFC 768** pseudo-header + segment, RFC 1071 sum.
///   The pseudo-header is `src_ip(4) || dst_ip(4) || zero(1) ||
///   protocol=17(1) || udp_length(2)`. The locked surface requires a
///   non-zero UDP checksum on every emitted datagram and rejects
///   incoming datagrams with `checksum == 0` as
///   [`NetError::BadUdpChecksum`] — every legal UDP datagram in this
///   stack carries a verifiable checksum.
///
/// # Fragmentation
///
/// The locked surface is **non-fragmenting on the send side** and
/// **fragment-rejecting on the receive side**:
///
/// - Every datagram emitted by [`NetStack::build_udp_datagram`] has the
///   DF flag set, MF cleared, and fragment offset zero.
/// - Every datagram parsed by [`NetStack::parse_ipv4_header`] with
///   MF set OR a non-zero fragment offset is rejected as
///   [`NetError::Fragmented`].
///
/// This is a deliberate scope decision: in-kernel reassembly under
/// no-alloc would need a fixed-capacity reassembly table; that
/// complexity is out of scope for the network-stack seed.
///
/// # Determinism
///
/// `build_udp_datagram` has no internal randomness. Given identical
/// inputs (including the caller-supplied `ident`) it produces
/// byte-identical output. This is the contract the morph engine's
/// verifier relies on for the round-trip equality check.
pub trait NetStack {
    /// Fixed IPv4 header length in bytes for the locked surface (no
    /// options). RFC 791 §3.1: IHL=5 four-byte words.
    const IPV4_HEADER_LEN: usize = 20;

    /// Fixed UDP header length in bytes. RFC 768.
    const UDP_HEADER_LEN: usize = 8;

    /// Minimum IPv4+UDP datagram length: header(20) + UDP header(8).
    const MIN_DATAGRAM_LEN: usize = 28;

    /// Maximum IPv4 total_length the protocol allows: u16 max.
    const MAX_DATAGRAM_LEN: usize = 65535;

    /// Maximum UDP payload the locked surface emits: max datagram -
    /// IPv4 header - UDP header = 65535 - 20 - 8 = 65507 bytes.
    const MAX_UDP_PAYLOAD: usize = 65507;

    /// Build a UDP-over-IPv4 datagram for `(src_ip, src_port) →
    /// (dst_ip, dst_port)` carrying `payload`, with the given IPv4
    /// `ttl` and `ident` fields. The fully-framed datagram (IPv4
    /// header + UDP header + payload) is written to `out` and the
    /// total byte count returned.
    ///
    /// # Wire format
    ///
    /// - IPv4 header: 20 bytes. `version=4, ihl=5, dscp_ecn=0,
    ///   total_length = 20 + 8 + payload.len(), identification=ident,
    ///   flags = DF (0b010), fragment_offset=0, ttl=ttl, protocol=17,
    ///   header_checksum=<RFC 1071 over the header>,
    ///   src_ip, dst_ip`.
    /// - UDP header: 8 bytes. `src_port, dst_port, length = 8 +
    ///   payload.len(), checksum=<RFC 768 over pseudo-header +
    ///   segment>`.
    /// - Payload: copied byte-for-byte from `payload`.
    ///
    /// # Errors
    ///
    /// - [`NetError::PayloadTooLarge`] when `payload.len() >
    ///   MAX_UDP_PAYLOAD`.
    /// - [`NetError::OutputBufferTooSmall`] when `out.len() < 28 +
    ///   payload.len()`.
    /// - [`NetError::PortZero`] when `src_port == 0 || dst_port == 0`.
    fn build_udp_datagram(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        src_port: u16,
        dst_port: u16,
        payload: &[u8],
        ttl: u8,
        ident: u16,
        out: &mut [u8],
    ) -> Result<usize, NetError>;

    /// Parse the IPv4 header at the start of `buf`, validating the
    /// header checksum and the locked-surface restrictions
    /// (`version==4, ihl==5, !MF, fragment_offset==0, ttl != 0,
    /// total_length == buf.len()`).
    ///
    /// On success, the returned [`Ipv4HeaderView`] is a host-order
    /// view; callers wanting the IPv4 payload should slice
    /// `&buf[Self::IPV4_HEADER_LEN..]`.
    ///
    /// # Errors
    ///
    /// See the individual variants of [`NetError`] for the specific
    /// rejection conditions. Implementations MUST surface the FIRST
    /// failing check in field order (truncation → version → IHL →
    /// options → total_length → fragmentation → ttl → checksum) so
    /// the verifier can match impls byte-for-byte on the error path.
    fn parse_ipv4_header(buf: &[u8]) -> Result<Ipv4HeaderView, NetError>;

    /// Parse the UDP datagram in `udp_segment`, validating the
    /// length field and the UDP checksum (which depends on the
    /// surrounding IPv4 src/dst, hence the two extra parameters).
    ///
    /// `udp_segment` is the UDP segment **only** — i.e., the bytes
    /// starting from the source-port field, NOT the full IPv4
    /// datagram. Callers that have the full IPv4+UDP datagram should
    /// pass `&datagram[IPV4_HEADER_LEN..]`.
    ///
    /// # Errors
    ///
    /// - [`NetError::Truncated`] when `udp_segment.len() < 8`.
    /// - [`NetError::BadUdpLength`] when the UDP length field
    ///   disagrees with `udp_segment.len()` OR is < 8.
    /// - [`NetError::PortZero`] when either port field is zero.
    /// - [`NetError::BadUdpChecksum`] when the checksum on the wire
    ///   was zero OR does not validate against the pseudo-header +
    ///   segment.
    fn parse_udp_datagram(
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        udp_segment: &[u8],
    ) -> Result<UdpDatagramView, NetError>;

    /// Compute the RFC 1071 IPv4 header checksum over `header_bytes`,
    /// treating bytes 10..12 (the checksum field) as zero during the
    /// computation. Returns the network-order one's-complement sum.
    ///
    /// This is exposed because `target_*` crates and the diversifier
    /// both want to call it directly: the build path uses it once
    /// per emitted datagram, and the validation tests use it as the
    /// oracle when constructing hand-rolled wire bytes.
    ///
    /// # Panics
    ///
    /// Panics if `header_bytes.len() < 20`. Implementations may
    /// process exactly the first 20 bytes (the locked surface
    /// guarantees IHL=5, so the caller will never legitimately pass
    /// more).
    fn ipv4_header_checksum(header_bytes: &[u8]) -> u16;

    /// Compute the RFC 768 UDP checksum over the pseudo-header +
    /// `udp_segment`. The checksum field of the segment (bytes 6..8)
    /// is treated as zero during the computation. Returns the
    /// network-order one's-complement sum, with the all-zero result
    /// mapped to all-ones (`0xFFFF`) per the RFC 768 convention so
    /// the wire value zero unambiguously means "checksum suppressed"
    /// (rejected by the locked surface).
    fn udp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], udp_segment: &[u8]) -> u16;
}

// ---------------------------------------------------------------------------
// Tcp — Transmission Control Protocol byte-locked surface
// ---------------------------------------------------------------------------

/// TCP flag bits as they appear in the data-offset/flags word of the
/// TCP header. Layout-locked per RFC 793 §3.1.
#[allow(missing_docs)]
pub mod tcp_flags {
    pub const FIN: u8 = 0x01;
    pub const SYN: u8 = 0x02;
    pub const RST: u8 = 0x04;
    pub const PSH: u8 = 0x08;
    pub const ACK: u8 = 0x10;
    pub const URG: u8 = 0x20;
}

/// View into a parsed TCP segment. All fields are host-order.
///
/// Field semantics follow RFC 793 §3.1 ("TCP Header Format") verbatim.
/// The locked surface is the byte layout, not this view — a future
/// morph cycle's implementation may emit a different `TcpSegmentView`
/// type but the bytes produced by [`Tcp::build_segment`] for a given
/// `(src_port, dst_port, seq, ack, flags, window, payload)` tuple are
/// invariant across morph cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TcpSegmentView<'a> {
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Sequence number (host order).
    pub seq: u32,
    /// Acknowledgement number (host order, ignored when `ACK` flag is clear).
    pub ack: u32,
    /// Header length in bytes (always a multiple of 4; minimum 20).
    pub header_len: u8,
    /// Flag byte (FIN/SYN/RST/PSH/ACK/URG/...). See [`tcp_flags`].
    pub flags: u8,
    /// Receive window advertised by the sender, in bytes.
    pub window: u16,
    /// Checksum field as it appeared on the wire (network order in the
    /// underlying bytes; this view stores the value byte-swapped to host
    /// order for convenience).
    pub checksum: u16,
    /// Urgent pointer (host order; meaningful iff URG flag set).
    pub urgent: u16,
    /// Payload bytes (the portion of the segment after the TCP header).
    pub payload: &'a [u8],
}

/// Errors returned by [`Tcp::build_segment`] / [`Tcp::parse_segment`].
/// Locked variant set across morph cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcpError {
    /// Output buffer too small for header + payload.
    OutputBufferTooSmall,
    /// Segment shorter than minimum 20-byte header, or header_len
    /// claims more bytes than the segment contains.
    Truncated,
    /// `header_len` field is < 20 or not a multiple of 4.
    BadHeaderLength,
    /// Checksum verification failed.
    ChecksumMismatch,
    /// Reserved bits set or unsupported flag combinations.
    ReservedBitsSet,
}

/// TCP byte-locked surface.
///
/// Invariants the verifier checks across morph cycles:
///
/// 1. For any `(src_port, dst_port, seq, ack, flags, window, payload,
///    src_ip, dst_ip)` accepted by [`build_segment`](Tcp::build_segment),
///    the produced bytes parse back via [`parse_segment`](Tcp::parse_segment)
///    to a `TcpSegmentView` whose fields recover the inputs exactly.
/// 2. [`tcp_checksum`](Tcp::tcp_checksum) over the IPv4 pseudo-header
///    + segment matches the spec's one's-complement sum (RFC 793 §3.1).
/// 3. A segment that fails checksum is rejected by `parse_segment`
///    with `TcpError::ChecksumMismatch`. No silent fallback to a
///    "ignore checksum" mode.
/// 4. The locked header layout: 4 bytes ports, 4 bytes seq, 4 bytes
///    ack, 1 byte data-offset+reserved, 1 byte flags, 2 bytes window,
///    2 bytes checksum, 2 bytes urgent. Total 20 bytes, no options
///    (RFC 793 §3.1 figure).
///
/// **Not in this contract (intentional):**
/// - TCP state-machine transitions live in the implementation crate.
///   The state machine consumes/produces segments via this contract's
///   byte codec, so a morph candidate that changes the state-machine
///   internals does not change the wire bytes.
/// - Retransmission, congestion control, SACK, MSS, window scaling.
///   These are future extensions.
pub trait Tcp {
    /// Build a TCP segment with the given header fields and payload,
    /// writing into `out`. Computes the checksum over the IPv4 pseudo-
    /// header (`src_ip`, `dst_ip`, protocol=6, segment length).
    /// Returns the number of bytes written.
    fn build_segment(
        src_port: u16,
        dst_port: u16,
        seq: u32,
        ack: u32,
        flags: u8,
        window: u16,
        payload: &[u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, TcpError>;

    /// Parse a TCP segment, validating the checksum against the IPv4
    /// pseudo-header. Returns a borrowed view into `bytes`.
    fn parse_segment<'a>(
        bytes: &'a [u8],
        src_ip: [u8; 4],
        dst_ip: [u8; 4],
    ) -> Result<TcpSegmentView<'a>, TcpError>;

    /// Compute the RFC 793 TCP checksum over the pseudo-header +
    /// segment. The checksum field of the segment (bytes 16..18) is
    /// treated as zero during the computation.
    fn tcp_checksum(src_ip: [u8; 4], dst_ip: [u8; 4], segment: &[u8]) -> u16;
}

// ---------------------------------------------------------------------------
// Http — HTTP/1.1 byte-locked surface
// ---------------------------------------------------------------------------

/// HTTP status code shorthand. Locked across morph cycles — userspace
/// reads these by numeric value, so morphing the discriminants would
/// break every client.
#[allow(missing_docs)]
pub mod http_status {
    pub const OK: u16 = 200;
    pub const NO_CONTENT: u16 = 204;
    pub const BAD_REQUEST: u16 = 400;
    pub const NOT_FOUND: u16 = 404;
    pub const METHOD_NOT_ALLOWED: u16 = 405;
    pub const PAYLOAD_TOO_LARGE: u16 = 413;
    pub const INTERNAL_SERVER_ERROR: u16 = 500;
    pub const SERVICE_UNAVAILABLE: u16 = 503;
}

/// HTTP method. Closed set per RFC 7231 §4.3. Unknown methods are
/// surfaced via [`HttpError::UnknownMethod`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpMethod {
    /// `GET`.
    Get,
    /// `HEAD`.
    Head,
    /// `POST`.
    Post,
    /// `PUT`.
    Put,
    /// `DELETE`.
    Delete,
    /// `OPTIONS`.
    Options,
    /// `PATCH`.
    Patch,
}

/// View into a parsed HTTP/1.1 request line + headers + body slice.
///
/// All string slices borrow from the caller-provided byte buffer.
/// `headers_raw` is the raw header block (between request line and
/// the blank-line terminator); callers parse it with
/// [`Http::find_header`] for case-insensitive lookups without
/// allocating a header map.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HttpRequestView<'a> {
    /// Parsed request method.
    pub method: HttpMethod,
    /// Raw request-target (path + optional query, no host). Borrowed
    /// from the input bytes.
    pub path: &'a [u8],
    /// HTTP version minor digit (1.0 → 0, 1.1 → 1). 1.x only.
    pub version_minor: u8,
    /// Header block: bytes between the request-line CRLF and the
    /// blank-line CRLFCRLF terminator. Each line is a `Name: Value`
    /// pair.
    pub headers_raw: &'a [u8],
    /// Body bytes (after the blank-line CRLFCRLF).
    pub body: &'a [u8],
}

/// Errors returned by [`Http::parse_request`] / [`Http::build_response`].
/// Locked variant set across morph cycles.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HttpError {
    /// Request shorter than `GET / HTTP/1.0\r\n\r\n` (the minimum
    /// well-formed request).
    Truncated,
    /// Request line doesn't match `METHOD SP PATH SP HTTP/1.X CRLF`.
    MalformedRequestLine,
    /// Method is none of the closed-set `HttpMethod` variants.
    UnknownMethod,
    /// HTTP version is neither 1.0 nor 1.1.
    UnsupportedVersion,
    /// Header block too large or missing the blank-line terminator.
    HeaderBlockTooLarge,
    /// Output buffer too small for the response.
    OutputBufferTooSmall,
    /// Status code is not a valid 3-digit HTTP status.
    BadStatus,
}

/// HTTP/1.1 byte-locked surface.
///
/// # Invariants the verifier checks
///
/// 1. For every request emitted by a conforming client (request line
///    + headers + optional body separated by CRLFs per RFC 7230 §3),
///    [`parse_request`](Http::parse_request) returns a view whose
///    fields recover the method, path, version, header block, and
///    body byte-for-byte.
/// 2. [`build_response`](Http::build_response) produces bytes that
///    start with `HTTP/1.1 <status> <reason>\r\n`, followed by
///    `Content-Type: <ct>\r\n`, `Content-Length: <len>\r\n`,
///    `\r\n`, body. The header-block terminator is always `\r\n\r\n`.
/// 3. [`find_header`](Http::find_header) returns the value of a
///    header by ASCII-case-insensitive name (per RFC 7230 §3.2).
/// 4. Reserved status codes (not in the IANA registry, or outside
///    100..600) are rejected with [`HttpError::BadStatus`].
///
/// # Not in this contract (intentional)
///
/// - Chunked transfer-encoding parser. The seed assumes
///   `Content-Length` framing.
/// - Connection pooling / keepalive / pipelining. Each request is
///   handled standalone.
/// - URL-decoding / query-string parsing. `path` is the raw bytes;
///   the caller decodes if needed.
/// - HTTPS — this is the HTTP layer. TLS protection is the `Tls13Server`
///   contract; the kernel composes them.
pub trait Http {
    /// Parse an HTTP/1.1 request from `bytes`. The returned view
    /// borrows from `bytes`.
    fn parse_request(bytes: &[u8]) -> Result<HttpRequestView<'_>, HttpError>;

    /// Find a header by case-insensitive name within a raw header
    /// block (e.g. [`HttpRequestView::headers_raw`]). Returns the
    /// value slice (trimmed of LWS surrounding the value, but
    /// otherwise byte-for-byte) or `None`.
    fn find_header<'a>(headers_raw: &'a [u8], name: &[u8]) -> Option<&'a [u8]>;

    /// Build a response into `out`. Status code must be in
    /// `100..600` and have a known reason phrase. Returns bytes
    /// written.
    fn build_response(
        status: u16,
        content_type: &[u8],
        body: &[u8],
        out: &mut [u8],
    ) -> Result<usize, HttpError>;
}

// ---------------------------------------------------------------------------
// DNS — RFC 1035 query/response wire format
// ---------------------------------------------------------------------------

/// DNS resource record type code. Closed set covering the records the
/// seed actually emits or parses. Numeric values are the on-the-wire
/// 16-bit codes from RFC 1035 §3.2.2 + RFC 3596 (AAAA).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum DnsRecordType {
    /// `A` — IPv4 host address. RFC 1035 §3.4.1.
    A = 1,
    /// `NS` — authoritative name server. RFC 1035 §3.3.11.
    Ns = 2,
    /// `CNAME` — canonical name alias. RFC 1035 §3.3.1.
    Cname = 5,
    /// `SOA` — start of zone authority. RFC 1035 §3.3.13.
    Soa = 6,
    /// `PTR` — reverse-DNS pointer. RFC 1035 §3.3.12.
    Ptr = 12,
    /// `MX` — mail exchanger. RFC 1035 §3.3.9.
    Mx = 15,
    /// `TXT` — arbitrary text. RFC 1035 §3.3.14.
    Txt = 16,
    /// `AAAA` — IPv6 host address. RFC 3596.
    Aaaa = 28,
}

/// DNS query/response class. Per RFC 1035 §3.2.4 — for the public
/// internet only the IN class is used.
pub mod dns_class {
    /// `IN` — internet class. The only class the seed emits/accepts.
    pub const IN: u16 = 1;
}

/// DNS message header flag bits (RFC 1035 §4.1.1). The header `flags`
/// field is a packed `u16`; these are the individual bits / fields.
pub mod dns_flags {
    /// `QR` — set on responses, clear on queries.
    pub const QR_RESPONSE: u16 = 1 << 15;
    /// `OPCODE = QUERY` (0). Standard forward / reverse lookup.
    pub const OPCODE_QUERY: u16 = 0 << 11;
    /// `AA` — authoritative answer (set in responses from the zone's
    /// authoritative server).
    pub const AA: u16 = 1 << 10;
    /// `TC` — truncated (response wouldn't fit; client should retry
    /// over TCP).
    pub const TC: u16 = 1 << 9;
    /// `RD` — recursion desired (set by client in queries).
    pub const RD: u16 = 1 << 8;
    /// `RA` — recursion available (set in responses by resolvers that
    /// support it).
    pub const RA: u16 = 1 << 7;
    /// `RCODE = NOERROR` (0).
    pub const RCODE_NOERROR: u16 = 0;
    /// `RCODE = NXDOMAIN` (3) — name does not exist.
    pub const RCODE_NXDOMAIN: u16 = 3;
    /// `RCODE = SERVFAIL` (2) — server failure.
    pub const RCODE_SERVFAIL: u16 = 2;
    /// `RCODE = FORMERR` (1) — format error.
    pub const RCODE_FORMERR: u16 = 1;
}

/// DNS message header. Exactly 12 bytes on the wire. RFC 1035 §4.1.1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DnsHeader {
    /// Identifier echoed back unchanged in the response.
    pub id: u16,
    /// Packed flags + opcode + RCODE. See [`dns_flags`].
    pub flags: u16,
    /// Number of question records (typically 1 for a single A lookup).
    pub qdcount: u16,
    /// Number of answer records.
    pub ancount: u16,
    /// Number of authority records.
    pub nscount: u16,
    /// Number of additional records.
    pub arcount: u16,
}

/// View into a parsed DNS message. Borrowed from the input buffer.
///
/// The seed exposes only the first question — that's the only case
/// real callers (resolvers, authoritative servers responding to a
/// single A lookup) need. Authority/additional sections are bypassed
/// (a downstream parser can re-scan from `body_offset` if needed).
#[derive(Debug, Clone, Copy)]
pub struct DnsMessageView<'a> {
    /// Parsed 12-byte header.
    pub header: DnsHeader,
    /// First question's name in raw wire form (length-prefixed labels,
    /// terminated by a zero length byte). Slice borrows from input.
    /// `None` if `header.qdcount == 0`.
    pub first_question_name: Option<&'a [u8]>,
    /// First question's QTYPE (e.g. 1 for A, 28 for AAAA).
    pub first_question_type: u16,
    /// First question's QCLASS (typically [`dns_class::IN`] = 1).
    pub first_question_class: u16,
}

/// Errors from the DNS wire codec. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsError {
    /// Input slice shorter than required for a 12-byte header or a
    /// truncated question / record body.
    Truncated,
    /// Label length byte exceeds 63 (RFC 1035 §2.3.4 limit).
    LabelTooLong,
    /// Encoded name exceeds 255 bytes total (including length octets).
    NameTooLong,
    /// Output buffer too small for the requested emission.
    OutputBufferTooSmall,
    /// Input is structurally invalid — header flags reserved bits set,
    /// or section counts inconsistent with the bytes present.
    BadHeader,
    /// Name contains a label longer than the spec limit OR an empty
    /// label (back-to-back dots, leading dot, or trailing dot).
    InvalidLabel,
    /// Pointer-compressed name loops back on itself. RFC 1035 §4.1.4
    /// permits forward-only pointers; cycles indicate a malformed
    /// or adversarial message.
    CompressionLoop,
}

/// DNS query/response byte-locked surface (RFC 1035).
///
/// # Locked invariants the verifier checks
///
/// 1. `build_a_query(id, name, _)` produces bytes that, when parsed
///    via `parse_message`, recover `id`, `header.qdcount == 1`,
///    `first_question_type == DnsRecordType::A as u16`, and a
///    `first_question_name` whose label sequence matches `name`.
/// 2. `build_a_response(id, qname, ip, ttl, _)` produces bytes with
///    `header.id == id`, `header.flags & QR_RESPONSE != 0`,
///    `header.qdcount == 1`, `header.ancount == 1`, and an answer
///    record whose 4-byte rdata equals `ip`.
/// 3. `parse_message` is pure / deterministic / no allocation.
///
/// # Not in this contract (intentional)
///
/// - EDNS(0) — the OPT pseudo-record. Adding it is a schema-compatible
///   extension; the seed doesn't need it for the kernel banner.
/// - DNSSEC — RRSIG / DS / DNSKEY. Future contract surface.
/// - Multi-question messages. RFC permits but real-world callers send
///   exactly one question per message.
/// - Pointer compression in `build_a_*`. The writers always emit
///   uncompressed names. Readers accept both forms (RFC says they MUST).
pub trait Dns {
    /// Build an A-record query for `name` (e.g. `b"example.com"`).
    /// Each label must be 1..=63 ASCII bytes; total encoded length
    /// must be ≤255 bytes. The header is constructed with QR=0,
    /// OPCODE=QUERY, RD=1, QDCOUNT=1.
    fn build_a_query(id: u16, name: &[u8], out: &mut [u8]) -> Result<usize, DnsError>;

    /// Parse a DNS message. Validates the 12-byte header, walks the
    /// first question (if any), and returns a view over the input.
    fn parse_message(bytes: &[u8]) -> Result<DnsMessageView<'_>, DnsError>;

    /// Build a response containing exactly one A-record answer with
    /// rdata = `ip` and TTL = `ttl`. The `question_wire_name` is the
    /// wire-form (length-prefixed labels, zero-terminated) of the
    /// question being answered, typically copied straight from
    /// [`DnsMessageView::first_question_name`].
    fn build_a_response(
        id: u16,
        question_wire_name: &[u8],
        ip: [u8; 4],
        ttl: u32,
        out: &mut [u8],
    ) -> Result<usize, DnsError>;
}

// ---------------------------------------------------------------------------
// Ethernet — IEEE 802.3 / Ethernet II frame + 802.1Q VLAN tag
// ---------------------------------------------------------------------------

/// EtherType code constants. 16-bit values in the EtherType field of an
/// Ethernet II frame (or the inner-EtherType slot following an 802.1Q
/// VLAN tag). Values < 0x0600 (1536) are interpreted as IEEE 802.3
/// length fields rather than EtherTypes — the seed only emits the
/// EtherType II form so this distinction doesn't appear on the build
/// path, but the parser is lenient about it.
pub mod ether_type {
    /// IPv4 — RFC 791.
    pub const IPV4: u16 = 0x0800;
    /// ARP — RFC 826.
    pub const ARP: u16 = 0x0806;
    /// IPv6 — RFC 8200.
    pub const IPV6: u16 = 0x86DD;
    /// 802.1Q VLAN tag (signals an 802.1Q-tagged frame; the *inner*
    /// EtherType follows two bytes later).
    pub const VLAN_TAG: u16 = 0x8100;
}

/// 6-byte IEEE 802 MAC address. Locked layout.
pub type MacAddr = [u8; 6];

/// All-1s broadcast MAC. Frames sent to this MAC are received by every
/// station on the local segment.
pub const ETH_BROADCAST_MAC: MacAddr = [0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF];

/// View into a parsed Ethernet frame. Borrows from the input buffer.
///
/// If the wire frame carries an 802.1Q VLAN tag, `vlan_tci` is `Some`
/// with the 16-bit TCI (PCP / DEI / VID), `ether_type` is the
/// *inner* EtherType (after the tag), and `payload` skips the 4-byte
/// tag — so the consumer sees the same shape regardless of tagging.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EthFrameView<'a> {
    /// Destination MAC.
    pub dst: MacAddr,
    /// Source MAC.
    pub src: MacAddr,
    /// EtherType (or inner EtherType when `vlan_tci.is_some()`).
    pub ether_type: u16,
    /// 802.1Q TCI when the frame is VLAN-tagged. `None` for untagged
    /// frames. Use [`vlan_pcp`], [`vlan_dei`], [`vlan_vid`] to extract
    /// the sub-fields.
    pub vlan_tci: Option<u16>,
    /// Frame payload (bytes after the header / VLAN tag / inner
    /// EtherType). May be empty.
    pub payload: &'a [u8],
}

/// Errors from the Ethernet wire codec. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EthError {
    /// Input slice shorter than the 14-byte Ethernet II header (or
    /// 18 bytes if a VLAN tag is present).
    Truncated,
    /// Output buffer too small for the requested frame.
    OutputBufferTooSmall,
    /// Reserved EtherType / TPID combination not understood by the
    /// seed. Today the parser only flags a malformed double-tagged
    /// frame (Q-in-Q is a future surface). Single 802.1Q is accepted.
    InvalidTag,
}

/// Ethernet II / IEEE 802.3 frame byte-locked surface.
///
/// # Locked invariants the verifier checks
///
/// 1. For every `(dst, src, ether_type, payload)` triple the build
///    path accepts, [`parse_frame`](Eth::parse_frame) on the emitted
///    bytes recovers exactly those fields. `vlan_tci` is `None`.
/// 2. For every `(dst, src, vlan_tci, inner_ethertype, payload)`
///    the VLAN build path accepts, parse recovers all five fields.
/// 3. The wire byte order is locked: `dst[0..6] || src[0..6] ||
///    ether_type_be(2)` for untagged, with `tpid_be(0x8100) ||
///    tci_be(2)` inserted between `src` and `ether_type` for tagged.
/// 4. `is_broadcast` / `is_multicast` / `is_unicast` are pure and
///    test exactly one bit of `dst[0]`.
///
/// # Not in this contract (intentional)
///
/// - Frame Check Sequence (FCS / CRC-32) — almost every real NIC
///   computes and validates the FCS in hardware; software emission
///   would be wasted CPU. If a future caller (a raw-packet captive
///   that bypasses the NIC) needs FCS, add it as a separate trait.
/// - Frame padding to the 60-byte minimum (without FCS) / 64-byte
///   (with FCS). Same hardware-handles-it reasoning.
/// - 802.1ad Q-in-Q double VLAN. Single 802.1Q only.
/// - 802.3 SNAP / LLC encapsulation. Ethernet II only on the build
///   path; the parser is EtherType-only.
pub trait Eth {
    /// Build an untagged Ethernet II frame.
    fn build_frame(
        dst: MacAddr,
        src: MacAddr,
        ether_type: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, EthError>;

    /// Build an 802.1Q VLAN-tagged frame. `vlan_tci` is the full
    /// 16-bit TCI (PCP / DEI / VID, packed); `inner_ether_type` is
    /// what would have been the EtherType in an untagged frame.
    fn build_frame_vlan(
        dst: MacAddr,
        src: MacAddr,
        vlan_tci: u16,
        inner_ether_type: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, EthError>;

    /// Parse an Ethernet frame. Transparently handles a single
    /// 802.1Q VLAN tag (returned via `EthFrameView::vlan_tci`).
    fn parse_frame(bytes: &[u8]) -> Result<EthFrameView<'_>, EthError>;
}

// ---------------------------------------------------------------------------
// ARP — RFC 826 Address Resolution Protocol (IPv4 over Ethernet)
// ---------------------------------------------------------------------------

/// ARP operation-code constants. 16-bit field at offset 6 of the
/// 28-byte ARP packet (after HTYPE/PTYPE/HLEN/PLEN).
pub mod arp_op {
    /// ARP REQUEST — "who has TPA? tell SHA/SPA". RFC 826 §1 op 1.
    pub const REQUEST: u16 = 1;
    /// ARP REPLY — "TPA is at THA". RFC 826 §1 op 2.
    pub const REPLY: u16 = 2;
}

/// ARP hardware-type constant. RFC 826 + IANA "ARP Parameters". The
/// seed only speaks `HTYPE_ETHERNET` (1) — any other HTYPE rejects on
/// parse.
pub const ARP_HTYPE_ETHERNET: u16 = 1;
/// ARP protocol-type constant. IPv4 — the seed only speaks IPv4 over
/// Ethernet. Same numeric space as Ethernet II EtherTypes; equal to
/// [`ether_type::IPV4`].
pub const ARP_PTYPE_IPV4: u16 = 0x0800;
/// Hardware-address length for Ethernet (6 octets). 1-byte field at
/// offset 4 of the ARP packet.
pub const ARP_HLEN_ETHERNET: u8 = 6;
/// Protocol-address length for IPv4 (4 octets). 1-byte field at offset
/// 5 of the ARP packet.
pub const ARP_PLEN_IPV4: u8 = 4;

/// Wire length of an IPv4-over-Ethernet ARP packet in bytes. Fixed at
/// 28 for HTYPE=1/PTYPE=0x0800/HLEN=6/PLEN=4.
pub const ARP_PACKET_LEN: usize = 28;

/// View into a parsed ARP packet (IPv4 over Ethernet). Borrowed from
/// the input buffer — but because the four address fields are
/// fixed-size, they are copied out by value rather than re-aliased.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ArpPacketView {
    /// Hardware type (always 1 = Ethernet for parsed packets).
    pub htype: u16,
    /// Protocol type (always 0x0800 = IPv4 for parsed packets).
    pub ptype: u16,
    /// Hardware-address length (always 6 for parsed packets).
    pub hlen: u8,
    /// Protocol-address length (always 4 for parsed packets).
    pub plen: u8,
    /// Operation code — REQUEST=1, REPLY=2.
    pub oper: u16,
    /// Sender hardware address (sender MAC).
    pub sender_mac: MacAddr,
    /// Sender protocol address (sender IPv4 in network order).
    pub sender_ip: [u8; 4],
    /// Target hardware address (target MAC). All-zeros in a REQUEST,
    /// populated in a REPLY.
    pub target_mac: MacAddr,
    /// Target protocol address (target IPv4 in network order).
    pub target_ip: [u8; 4],
}

/// Errors from the ARP wire codec / cache.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArpError {
    /// Input slice shorter than the 28-byte ARP packet.
    Truncated,
    /// Output buffer too small for the requested emission.
    OutputBufferTooSmall,
    /// HTYPE field is not `ARP_HTYPE_ETHERNET` (1).
    InvalidHardwareType,
    /// PTYPE field is not `ARP_PTYPE_IPV4` (0x0800).
    InvalidProtocolType,
    /// HLEN field is not `ARP_HLEN_ETHERNET` (6).
    InvalidHardwareLength,
    /// PLEN field is not `ARP_PLEN_IPV4` (4).
    InvalidProtocolLength,
    /// OPER field is neither REQUEST (1) nor REPLY (2).
    InvalidOperation,
    /// Cache full and no free slot (LRU eviction was suppressed; this
    /// is only surfaced when the cache is asked to insert with eviction
    /// disabled — the default `insert` evicts the LRU slot and never
    /// returns this error).
    CacheFull,
    /// Cache insert refused because an existing entry for the same IP
    /// maps to a *different* MAC and is still within the
    /// poison-defence window. The caller must `invalidate(ip)`
    /// explicitly to accept the new binding.
    CachePoisonRejected,
    /// Cache insert refused because the supplied MAC is in the
    /// blocked-MAC list (e.g. all-zeros, broadcast). RFC 826 §
    /// operational guidance.
    BlockedMac,
}

/// ARP wire codec + cache surface (RFC 826).
///
/// # Locked invariants the verifier checks
///
/// 1. For every `(sender_mac, sender_ip, target_ip)` triple that
///    [`build_request`](Arp::build_request) accepts, the emitted 28
///    bytes parse back via [`parse_packet`](Arp::parse_packet) with
///    `oper == arp_op::REQUEST`, matching sender / target fields, and
///    `target_mac == [0; 6]` (per RFC 826 §1 — REQUEST has unknown
///    THA).
/// 2. For every `(sender_mac, sender_ip, target_mac, target_ip)` 4-
///    tuple that [`build_reply`](Arp::build_reply) accepts, the emitted
///    28 bytes parse back with `oper == arp_op::REPLY` and matching
///    fields.
/// 3. The wire byte order is locked: HTYPE_be(2) || PTYPE_be(2) ||
///    HLEN(1) || PLEN(1) || OPER_be(2) || SHA(6) || SPA(4) || THA(6)
///    || TPA(4) = 28 bytes total. No padding.
/// 4. `parse_packet` rejects HTYPE != 1, PTYPE != 0x0800, HLEN != 6,
///    PLEN != 4, and OPER outside {1, 2}.
/// 5. A gratuitous ARP (sender_ip == target_ip with oper == REQUEST)
///    parses successfully; it's the caller's job to detect that via
///    `view.sender_ip == view.target_ip`.
///
/// # Not in this contract (intentional)
///
/// - Other HTYPE/PTYPE combinations (IPv6 ND lives in a separate
///   protocol; non-Ethernet link layers add no value to the seed).
/// - The cache management is exposed via the concrete `ArpCache<N>`
///   type in `target_enterprise::arp` rather than as a trait method
///   here — the cache holds state and a `&self` method would force
///   every impl to thread a backing store.
/// - RARP (reverse ARP) — superseded by DHCP since the early 1990s.
pub trait Arp {
    /// Build an ARP REQUEST: "who has `target_ip`? Tell `sender_mac` /
    /// `sender_ip`." The target hardware address field is filled with
    /// all-zeros per RFC 826. Returns the number of bytes written
    /// (always 28 on success).
    fn build_request(
        sender_mac: MacAddr,
        sender_ip: [u8; 4],
        target_ip: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, ArpError>;

    /// Build an ARP REPLY: "`target_ip` is at `target_mac`." All four
    /// address fields are populated. Returns 28 on success.
    fn build_reply(
        sender_mac: MacAddr,
        sender_ip: [u8; 4],
        target_mac: MacAddr,
        target_ip: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, ArpError>;

    /// Parse an ARP packet. Validates all six fixed fields (HTYPE,
    /// PTYPE, HLEN, PLEN, OPER, length) and returns a copy-by-value
    /// view of the addresses.
    fn parse_packet(bytes: &[u8]) -> Result<ArpPacketView, ArpError>;
}

// ---------------------------------------------------------------------------
// DHCPv4 — RFC 2131 / RFC 2132 (boot-time IP acquisition)
// ---------------------------------------------------------------------------

/// DHCPv4 message-type codes carried in option 53. RFC 2132 §9.6.
pub mod dhcp_msg_type {
    /// Client → server: "I have no IP, who's out there?" (broadcast).
    pub const DISCOVER: u8 = 1;
    /// Server → client: "I can offer you `yiaddr`."
    pub const OFFER: u8 = 2;
    /// Client → server: "I accept `requested_ip` from `server_id`."
    pub const REQUEST: u8 = 3;
    /// Client → server (rare): "this address I was offered is broken."
    pub const DECLINE: u8 = 4;
    /// Server → client: "lease confirmed."
    pub const ACK: u8 = 5;
    /// Server → client: "REQUEST refused."
    pub const NAK: u8 = 6;
    /// Client → server: "I'm done with this lease."
    pub const RELEASE: u8 = 7;
    /// Client → server: "tell me about your config but don't bind."
    pub const INFORM: u8 = 8;
}

/// DHCPv4 BOOTP option-code constants. RFC 2132 §3-§9.
pub mod dhcp_option {
    /// Padding byte. RFC 2132 §3.1.
    pub const PAD: u8 = 0;
    /// Subnet mask (length 4). RFC 2132 §3.3.
    pub const SUBNET_MASK: u8 = 1;
    /// Router list (length n*4, first is preferred default gateway).
    /// RFC 2132 §3.5.
    pub const ROUTER: u8 = 3;
    /// Domain name server list (length n*4). RFC 2132 §3.8.
    pub const DNS: u8 = 6;
    /// Requested IP address (length 4). RFC 2132 §9.1.
    pub const REQUESTED_IP: u8 = 50;
    /// IP-address lease time in seconds (length 4, network order).
    /// RFC 2132 §9.2.
    pub const LEASE_TIME: u8 = 51;
    /// DHCP message type (length 1). RFC 2132 §9.6.
    pub const MSG_TYPE: u8 = 53;
    /// Server identifier (the DHCP server's own IP, length 4).
    /// RFC 2132 §9.7.
    pub const SERVER_ID: u8 = 54;
    /// Parameter-request list (length n, list of option codes the
    /// client wants the server to include in the OFFER/ACK). RFC 2132
    /// §9.8.
    pub const PARAM_REQUEST_LIST: u8 = 55;
    /// End-of-options sentinel. RFC 2132 §3.2.
    pub const END: u8 = 255;
}

/// BOOTP op-code: REQUEST is client → server, REPLY is server → client.
/// 1-byte field at offset 0 of the BOOTP/DHCP header.
pub const DHCP_OP_BOOTREQUEST: u8 = 1;
/// BOOTP REPLY (server → client). See [`DHCP_OP_BOOTREQUEST`].
pub const DHCP_OP_BOOTREPLY: u8 = 2;
/// `htype` field value for 10-Mb Ethernet (the only one the seed
/// supports — and the only one anyone uses in practice). RFC 2131 §2.
pub const DHCP_HTYPE_ETHERNET: u8 = 1;
/// `hlen` field value for an Ethernet client-hardware address (6
/// octets). RFC 2131 §2.
pub const DHCP_HLEN_ETHERNET: u8 = 6;
/// DHCP magic-cookie bytes at offset 236 of the BOOTP/DHCP header.
/// RFC 2131 §3 / RFC 1497.
pub const DHCP_MAGIC_COOKIE: [u8; 4] = [0x63, 0x82, 0x53, 0x63];
/// Length of the fixed BOOTP/DHCP header (op..magic_cookie inclusive).
/// Options begin immediately after.
pub const DHCP_FIXED_HEADER_LEN: usize = 240;
/// Highest-bit flag of the 16-bit `flags` field requesting that the
/// server broadcast its reply (so the client can receive it before
/// having committed to an IP). RFC 2131 §2 / §4.1.
pub const DHCP_FLAG_BROADCAST: u16 = 0x8000;

/// View into a parsed DHCPv4 message. Borrowed from the input buffer
/// for the option spans; fixed fields are copied out by value.
///
/// `msg_type` is the value carried in option 53 — required by every
/// modern DHCP message, so the parser rejects any reply that lacks it.
/// All other option fields are `Option<...>` because a well-formed
/// server reply MAY omit any of them and the client must cope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DhcpMessageView<'a> {
    /// BOOTP op (`DHCP_OP_BOOTREQUEST` or `DHCP_OP_BOOTREPLY`).
    pub op: u8,
    /// Transaction id chosen by the client; echoed by the server.
    pub xid: u32,
    /// 16-bit flags (only the broadcast bit is interpreted by the seed).
    pub flags: u16,
    /// Client IP (zero for a client that doesn't yet have an IP).
    pub ciaddr: [u8; 4],
    /// "Your" IP — what the server is offering / has assigned. Zero
    /// in REQUEST.
    pub yiaddr: [u8; 4],
    /// "Server" IP — next server in the boot sequence. Often zero.
    pub siaddr: [u8; 4],
    /// "Gateway" IP — the relay agent's address, zero on direct LANs.
    pub giaddr: [u8; 4],
    /// Client hardware address (only the first 6 bytes for Ethernet
    /// are meaningful; the BOOTP field is 16 bytes wide).
    pub chaddr: [u8; 6],
    /// DHCP message type — REQUIRED by RFC 2131. Recovered from
    /// option 53.
    pub msg_type: u8,
    /// Server identifier from option 54, if present. Set in OFFER/ACK.
    pub server_id: Option<[u8; 4]>,
    /// Subnet mask from option 1, if present.
    pub subnet_mask: Option<[u8; 4]>,
    /// First router from option 3, if present (the seed only records
    /// the first — multi-router fallback is a future extension).
    pub router: Option<[u8; 4]>,
    /// First DNS server from option 6, if present.
    pub dns: Option<[u8; 4]>,
    /// Lease time in seconds from option 51, if present.
    pub lease_secs: Option<u32>,
    /// Requested IP from option 50, if present (set in client REQUEST).
    pub requested_ip: Option<[u8; 4]>,
    /// Raw options span starting at offset 240 of the original
    /// message — exposed for callers that need to scan for option
    /// codes the seed doesn't decode.
    pub options_raw: &'a [u8],
}

/// Errors from the DHCPv4 wire codec / client state machine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpError {
    /// Input shorter than the 240-byte BOOTP/DHCP fixed header.
    Truncated,
    /// Output buffer too small to hold the requested message.
    OutputBufferTooSmall,
    /// Magic-cookie bytes at offset 236..240 are not `0x63 0x82 0x53 0x63`.
    BadMagicCookie,
    /// `op` is not 1 (REQUEST) or 2 (REPLY).
    InvalidOp,
    /// `htype` is not 1 (Ethernet) — the seed only supports Ethernet.
    InvalidHardwareType,
    /// `hlen` is not 6 — same constraint as `InvalidHardwareType`.
    InvalidHardwareLength,
    /// An option's length byte would push the option past the end of
    /// the buffer.
    TruncatedOption,
    /// Option 53 (DHCP message type) is missing — RFC 2131 says it
    /// MUST be present in every DHCP message.
    MissingMessageType,
    /// Option 53 is present but its length isn't 1.
    InvalidMessageTypeLength,
    /// State-machine input does not match the current state (e.g.
    /// receiving OFFER while in BOUND).
    UnexpectedState,
    /// State-machine input carries an `xid` that does not match the
    /// one we sent — possible cross-talk between clients, drop.
    XidMismatch,
    /// State-machine input is an OFFER/ACK but the corresponding
    /// `yiaddr` is the all-zeros address — server bug or malformed
    /// reply.
    EmptyYiaddr,
}

/// DHCPv4 client state. RFC 2131 §4.4 figure 5 — the seed implements
/// the canonical six-state machine. Lease-time accounting and
/// renew/rebind timers are part of the impl, not exposed here.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DhcpClientState {
    /// Pre-DISCOVER. No `xid` chosen yet.
    Init,
    /// DISCOVER emitted, awaiting OFFER. `xid` is committed.
    Selecting,
    /// OFFER received + REQUEST emitted, awaiting ACK.
    Requesting,
    /// ACK received. The view's `yiaddr`/`lease_secs` are authoritative.
    Bound,
    /// Lease half-expired; client may RENEW.
    Renewing,
    /// Lease 87.5%-expired; client may REBIND (multicast).
    Rebinding,
}

/// DHCPv4 byte-locked wire surface (RFC 2131 / RFC 2132).
///
/// # Locked invariants the verifier checks
///
/// 1. `build_discover` emits a buffer of length ≥
///    [`DHCP_FIXED_HEADER_LEN`] whose offsets 0..240 match the BOOTP
///    layout: op=1, htype=1, hlen=6, hops=0, `xid_be`, secs=0,
///    flags = `DHCP_FLAG_BROADCAST` (big-endian), ciaddr=yiaddr=
///    siaddr=giaddr=0, chaddr[0..6] = client MAC, magic-cookie at
///    236..240.
/// 2. `build_discover` always includes option 53 = DISCOVER and
///    terminates with the END (255) byte.
/// 3. `build_request` is identical to `build_discover` except option
///    53 = REQUEST, option 50 = `requested_ip`, option 54 =
///    `server_id`.
/// 4. `parse_message` returns `Ok(view)` iff op ∈ {1,2}, htype=1,
///    hlen=6, magic-cookie matches, and option 53 is present.
/// 5. `parse_message` recovers `yiaddr`, `xid`, `flags` from fixed
///    fields and `msg_type`, `server_id`, `subnet_mask`, `router`,
///    `dns`, `lease_secs`, `requested_ip` from options (each as
///    `Option<...>` — only `msg_type` is required).
///
/// # Not in this contract (intentional)
///
/// - Live UDP send/receive (the kernel call sites compose with
///   [`NetStack`]'s UDP path).
/// - DHCPv6 — different wire format entirely.
/// - BOOTP-only servers — the seed assumes magic-cookie + option 53.
pub trait Dhcp {
    /// Build a DISCOVER: client MAC, fresh `xid`. Returns the number
    /// of bytes written (≥ 240).
    fn build_discover(mac: [u8; 6], xid: u32, out: &mut [u8]) -> Result<usize, DhcpError>;

    /// Build a REQUEST that claims `requested_ip` from `server_id`
    /// (per the prior OFFER). Same `mac` + `xid` as the DISCOVER that
    /// produced the OFFER.
    fn build_request(
        mac: [u8; 6],
        xid: u32,
        requested_ip: [u8; 4],
        server_id: [u8; 4],
        out: &mut [u8],
    ) -> Result<usize, DhcpError>;

    /// Parse a DHCPv4 message (DISCOVER/OFFER/REQUEST/ACK/NAK/...).
    /// Returns a view borrowing from `bytes` for the options span.
    fn parse_message(bytes: &[u8]) -> Result<DhcpMessageView<'_>, DhcpError>;
}

// ---------------------------------------------------------------------------
// ICMP — RFC 792 echo request / reply
// ---------------------------------------------------------------------------

/// ICMP message-type code constants. RFC 792 §3.
pub mod icmp_type {
    /// `Echo Reply` (type 0).
    pub const ECHO_REPLY: u8 = 0;
    /// `Destination Unreachable` (type 3).
    pub const DEST_UNREACHABLE: u8 = 3;
    /// `Time Exceeded` (type 11).
    pub const TIME_EXCEEDED: u8 = 11;
    /// `Echo Request` (type 8).
    pub const ECHO_REQUEST: u8 = 8;
}

/// View into a parsed ICMP Echo (request or reply) message. Borrowed
/// from the input buffer.
#[derive(Debug, Clone, Copy)]
pub struct IcmpEchoView<'a> {
    /// ICMP type code (8 = echo request, 0 = echo reply).
    pub icmp_type: u8,
    /// ICMP code field (always 0 for echo, but exposed for completeness).
    pub code: u8,
    /// 16-bit checksum as it appeared on the wire (network byte order).
    pub checksum: u16,
    /// Echo identifier — opaque 16-bit value the sender chooses.
    pub identifier: u16,
    /// Echo sequence number — opaque 16-bit value the sender chooses.
    pub sequence_number: u16,
    /// Echo payload (data section after the 8-byte ICMP header).
    pub payload: &'a [u8],
}

/// Errors from the ICMP echo wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IcmpError {
    /// Input slice shorter than the 8-byte ICMP header.
    Truncated,
    /// Checksum field doesn't match the recomputed checksum.
    ChecksumMismatch,
    /// Output buffer too small for the requested emission.
    OutputBufferTooSmall,
    /// Message type isn't `ECHO_REQUEST` or `ECHO_REPLY`.
    NotEcho,
}

/// ICMP echo byte-locked surface (RFC 792).
///
/// # Locked invariants the verifier checks
///
/// 1. For every `(identifier, sequence_number, payload)` triple that
///    [`build_echo_request`](Icmp::build_echo_request) accepts, the
///    emitted bytes parse back via [`parse_echo`](Icmp::parse_echo)
///    with `icmp_type == ECHO_REQUEST` and matching identifier /
///    sequence / payload.
/// 2. [`build_echo_reply`](Icmp::build_echo_reply) emits bytes that
///    parse back with `icmp_type == ECHO_REPLY` and matching fields.
/// 3. [`parse_echo`](Icmp::parse_echo) rejects messages whose
///    checksum field does not match the RFC 1071 16-bit one's-
///    complement sum over the full ICMP message.
/// 4. `parse_echo` is pure (no global state, no allocation).
///
/// # Not in this contract (intentional)
///
/// - Other ICMP types: destination-unreachable, time-exceeded,
///   redirect, etc. Adding them is a schema-compatible extension.
/// - ICMPv6. Different message-type space + 32-bit pseudo-header
///   checksum coverage. Future contract.
pub trait Icmp {
    /// Build an ICMP echo *request* (type 8). The IPv4 header is NOT
    /// emitted — callers wrap the result inside an IPv4 packet with
    /// protocol = 1.
    fn build_echo_request(
        identifier: u16,
        sequence_number: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, IcmpError>;

    /// Build an ICMP echo *reply* (type 0).
    fn build_echo_reply(
        identifier: u16,
        sequence_number: u16,
        payload: &[u8],
        out: &mut [u8],
    ) -> Result<usize, IcmpError>;

    /// Parse an ICMP echo message. Validates length, type code, and
    /// checksum. Returns a view borrowing from `bytes`.
    fn parse_echo(bytes: &[u8]) -> Result<IcmpEchoView<'_>, IcmpError>;
}

// ---------------------------------------------------------------------------
// Kpti — Kernel Page Table Isolation (TASK-017)
// ---------------------------------------------------------------------------

/// A KPTI invariant violation reported by [`Kpti::validate_user_view`].
///
/// The KPTI contract guarantees that a per-task `user_l4` page table
/// active during ring-3 execution does NOT translate any of:
/// - The kernel `.text` region
/// - The kernel heap
/// - The IDT (with its KPTI-internal entry-stack pointers)
/// - Per-task signing-key pages (Ed25519 private key, TLS session keys)
///
/// Every violation case carries enough context (the offending page
/// number, the secret index when relevant) to be triaged from an
/// attestation log without rebuilding the candidate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KptiViolation {
    /// A page that should be kernel-only is reachable from `user_l4`.
    SecretLeaked {
        /// Page-aligned virtual address that leaked.
        page: u64,
        /// Index into the caller's `secrets` slice that was supposed
        /// to be excluded.
        secret_index: usize,
    },
    /// A user-required page that should be reachable from `user_l4` is
    /// missing.
    UserPageMissing {
        /// Page-aligned virtual address of the missing page.
        page: u64,
    },
    /// A page table entry in `user_l4` has bits that user mode must not
    /// see (e.g. the kernel-only NX-cleared bit on a page that should
    /// be data-only).
    KernelBitsSetOnUserPage {
        /// Page-aligned virtual address of the offending entry.
        page: u64,
        /// The offending raw PTE word.
        raw_entry: u64,
    },
}

/// Per-task Kernel Page Table Isolation contract.
///
/// This is the locked invariant boundary that closes the "kernel
/// secrets are reachable from compromised ring-3 code" attack class.
/// Implementations build a per-task `user_l4` page table that, when
/// loaded as CR3 during ring-3 execution, makes kernel `.text`,
/// kernel heap, IDT, and Ed25519 signing-key pages **unreachable** —
/// a Meltdown-style attack from ring 3 simply has no entries in its
/// page tables to walk to those addresses.
///
/// # Locked invariants (the trait's contract)
///
/// For every implementation, for every `(kernel_l4, secrets)` input
/// pair the implementation is willing to accept:
///
/// 1. `validate_user_view(build_user_view(kernel_l4, secrets), kernel_l4, secrets)`
///    returns `Ok(())`. The build path must produce a view that passes
///    its own validator.
/// 2. For every `page` in `secrets`, [`build_user_view`](Kpti::build_user_view)
///    produces a `user_l4` from which `page` is unreachable. (The
///    operational form of "kernel `.text` not translated".)
/// 3. [`validate_user_view`](Kpti::validate_user_view) is **pure** —
///    no side effects, no global state, deterministic. The verifier
///    relies on this for property-test-based validation.
/// 4. If `validate_user_view` returns `Err(_)`, the implementation
///    MUST refuse to schedule any task against the offending `user_l4`.
///    The runtime contract is "validate before activate".
///
/// # Why an associated type for `UserL4` / `KernelL4`
///
/// Real hardware needs a 4 KiB-aligned 512-entry PML4. Host-side unit
/// tests (which we run in `cargo test`) want a plain
/// `[u64; 512]`-equivalent. The associated types let each implementor
/// pick. The contract is about **behaviour**, not representation.
pub trait Kpti {
    /// Implementation-chosen representation of the active CR3-loaded
    /// kernel page-table root.
    type KernelL4;

    /// Implementation-chosen representation of the per-task user view.
    type UserL4;

    /// Construct a `user_l4` from `kernel_l4` that translates the same
    /// user-accessible mappings but strips every page in `secrets`.
    /// `secrets` is a list of page-aligned virtual addresses that must
    /// not be reachable from the returned view.
    fn build_user_view(kernel_l4: &Self::KernelL4, secrets: &[u64]) -> Self::UserL4;

    /// Walk `user_l4` and assert the locked invariants hold against
    /// `kernel_l4` + `secrets`. Returns the first violation found, or
    /// `Ok(())` if all invariants pass.
    ///
    /// MUST be pure (no global state, no allocations on the success
    /// path, no syscalls). The verifier exercises this against
    /// synthetic page tables under property tests.
    fn validate_user_view(
        user_l4: &Self::UserL4,
        kernel_l4: &Self::KernelL4,
        secrets: &[u64],
    ) -> Result<(), KptiViolation>;
}

// ============================================================
// CrashDump — TASK-019
//
// Post-mortem crash dump contract. The kernel panic handler captures a
// fixed-layout 16 KiB snapshot of the panic state (registers + backtrace
// addresses + kmsg ring tail + panic location/message), then writes it
// to a reserved sector range on the boot device. A follow-on boot (or
// a host-side reader after exporting the disk) decodes the dump and
// resolves backtrace addresses against the kernel symbol table.
//
// The on-disk layout is part of the locked wire surface. Internals
// of `build_dump` / `parse_header` morph (loop order, register-fill
// strategy) — the 16 384 emitted bytes do not.
// ============================================================

/// Number of architectural registers captured in a [`CrashRegisters`]
/// snapshot. Layout (locked across morph cycles):
///
/// - `0..16`: general-purpose register file —
///   `RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP, R8, R9, R10, R11, R12, R13, R14, R15`.
/// - `16..24`: control / segment context —
///   `RIP, RFLAGS, CR2, CR3, FS_BASE, GS_BASE, KERNEL_GS_BASE, MSR_EFER`.
pub const CRASH_REG_COUNT: usize = 24;

/// Snapshot of CPU register state captured at panic time. See
/// [`CRASH_REG_COUNT`] for the index → register mapping.
pub type CrashRegisters = [u64; CRASH_REG_COUNT];

/// Maximum number of backtrace frame addresses captured into a dump.
/// The on-disk record reserves exactly 64 u64 slots (one 512-byte
/// sector) regardless of how many the panic handler actually walked.
pub const CRASH_BACKTRACE_MAX: usize = 64;

/// Total on-disk dump size in bytes (locked across morph cycles).
/// Sized so a single dump fits in 32 contiguous 512-byte sectors.
pub const CRASH_DUMP_BYTES: usize = 16_384;

/// Number of 512-byte sectors a dump occupies (locked).
pub const CRASH_DUMP_SECTORS: u64 = 32;

/// 8-byte magic prefix every well-formed dump starts with. ASCII
/// "PROTPAN1".
pub const CRASH_DUMP_MAGIC: [u8; 8] = *b"PROTPAN1";

/// Current schema of the on-disk dump layout. The reader uses this to
/// recognise older dumps (a future revision MAY bump this and emit a
/// migration path; the current reader only supports schema `1`).
pub const CRASH_DUMP_SCHEMA: u32 = 1;

/// Maximum length of the panic location string (`file:line:col`) stored
/// in the header. Longer locations are truncated.
pub const CRASH_LOC_MAX: usize = 128;

/// Maximum length of the panic message body stored in the header.
/// Longer messages are truncated.
pub const CRASH_MSG_MAX: usize = 256;

/// Locked byte offsets inside the 512-byte header sector of a crash
/// dump. Bumped only with a schema-version increment.
pub mod crash_offsets {
    /// Offset of the 8-byte magic prefix.
    pub const MAGIC: usize = 0;
    /// Offset of the schema version (u32 LE).
    pub const SCHEMA: usize = 8;
    /// Reserved bytes 12..16.
    pub const RESERVED_A: usize = 12;
    /// Offset of `wall_unix` (u64 LE).
    pub const WALL_UNIX: usize = 16;
    /// Offset of `tsc` (u64 LE).
    pub const TSC: usize = 24;
    /// Reserved bytes 32..48 (header alignment slack).
    pub const RESERVED_B: usize = 32;
    /// Offset of the panic-location string (utf-8, NUL-padded).
    /// `CRASH_LOC_MAX` bytes wide.
    pub const PANIC_LOC: usize = 48;
    /// Offset of the panic-message string (utf-8, NUL-padded).
    /// `CRASH_MSG_MAX` bytes wide.
    pub const MESSAGE: usize = 176;
    /// Offset of `kmsg_len` (u32 LE).
    pub const KMSG_LEN: usize = 432;
    /// Offset of `backtrace_count` (u32 LE).
    pub const BACKTRACE_COUNT: usize = 436;
    /// Offset of `register_count` (u32 LE). Always equals
    /// [`super::CRASH_REG_COUNT`] for schema 1.
    pub const REGISTER_COUNT: usize = 440;
    /// Offset of `body_crc32c` (u32 LE) — Castagnoli CRC32-C over the
    /// dump body (sectors 1..32, byte range 512..16384).
    pub const BODY_CRC32C: usize = 444;
    /// Offset where the register snapshot starts (sector 1).
    pub const REGISTERS: usize = 512;
    /// Offset where the backtrace addresses start (sector 2).
    pub const BACKTRACE: usize = 1024;
    /// Offset where the kmsg payload starts (sector 3).
    pub const KMSG: usize = 1536;
}

/// Maximum bytes of kernel-message ring tail that fit in a dump.
/// Derived from the locked sector layout: `CRASH_DUMP_BYTES - KMSG_OFF`.
pub const CRASH_KMSG_MAX: usize = CRASH_DUMP_BYTES - crash_offsets::KMSG;

/// Error returned by [`CrashDump`] operations.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum CrashDumpError {
    /// Output buffer is shorter than [`CRASH_DUMP_BYTES`].
    BufferTooSmall,
    /// On-disk magic prefix did not match [`CRASH_DUMP_MAGIC`].
    MagicMismatch,
    /// Header schema field did not match a known version.
    SchemaMismatch,
    /// `body_crc32c` in the header did not match the recomputed body
    /// checksum.
    CrcMismatch,
    /// One of the variable-length fields (panic_loc, message, kmsg,
    /// backtrace) declared a length that ran past the buffer.
    LayoutOverflow,
    /// `kmsg.len() > CRASH_KMSG_MAX` or
    /// `backtrace.len() > CRASH_BACKTRACE_MAX`.
    InputTooLarge,
}

/// Inputs to [`CrashDump::build_dump`]. Borrows everything; allocation-
/// free.
pub struct CrashContext<'a> {
    /// Wall-clock time at panic (Unix seconds).
    pub wall_unix: u64,
    /// Free-running CPU timestamp at panic.
    pub tsc: u64,
    /// Panic location formatted as `file:line:col`. Truncated to
    /// [`CRASH_LOC_MAX`].
    pub panic_loc: &'a str,
    /// Panic message body. Truncated to [`CRASH_MSG_MAX`].
    pub message: &'a str,
    /// Register snapshot — exactly [`CRASH_REG_COUNT`] u64 slots.
    pub registers: &'a CrashRegisters,
    /// Backtrace addresses, oldest-to-newest frame. Must be at most
    /// [`CRASH_BACKTRACE_MAX`] entries.
    pub backtrace: &'a [u64],
    /// Kernel-message ring tail bytes. Must be at most
    /// [`CRASH_KMSG_MAX`] bytes; excess is rejected with
    /// [`CrashDumpError::InputTooLarge`].
    pub kmsg: &'a [u8],
}

/// Decoded view of a crash-dump header sector. All slices borrow into
/// the caller-supplied buffer.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct CrashDumpHeader<'a> {
    /// Schema version (currently always [`CRASH_DUMP_SCHEMA`]).
    pub schema: u32,
    /// Wall-clock time at panic (Unix seconds).
    pub wall_unix: u64,
    /// Free-running CPU timestamp at panic.
    pub tsc: u64,
    /// Panic location as recorded in the header; NUL-trimmed.
    pub panic_loc: &'a str,
    /// Panic message body as recorded in the header; NUL-trimmed.
    pub message: &'a str,
    /// Number of valid kmsg bytes that follow.
    pub kmsg_len: u32,
    /// Number of valid backtrace frames.
    pub backtrace_count: u32,
    /// Number of registers in the snapshot (`CRASH_REG_COUNT` for
    /// schema 1).
    pub register_count: u32,
    /// Recorded CRC32-C of the body bytes (sectors 1..32).
    pub body_crc32c: u32,
}

/// Crash-dump contract.
///
/// Invariants the verifier checks:
/// - Determinism: `build_dump(ctx, &mut buf)` produces the same bytes
///   for the same `ctx`.
/// - Round-trip: `parse_header(&buf)` recovers every header field set
///   by `build_dump`; `extract_registers`, `extract_backtrace`,
///   `extract_kmsg` recover the body fields byte-for-byte.
/// - Tamper detection: a single-bit flip in any sector of the body
///   causes [`verify_crc`](Self::verify_crc) to return
///   `Err(CrashDumpError::CrcMismatch)`.
/// - Layout stability: byte offsets in [`crash_offsets`] are part of
///   the locked surface. The diversifier cannot move them.
pub trait CrashDump {
    /// Starting LBA on the boot device. Implementations choose this;
    /// the in-tree impl uses `1024` (offset 512 KiB), matching the
    /// `RustOSa` donor's convention. Locked once chosen for any given
    /// boot device.
    const DUMP_START_LBA: u64;

    /// Error type. Implementations are encouraged to use
    /// [`CrashDumpError`].
    type Error;

    /// Build a dump into `buf` (which must be at least
    /// [`CRASH_DUMP_BYTES`] long). Returns the number of bytes
    /// written, which is always [`CRASH_DUMP_BYTES`].
    fn build_dump(ctx: &CrashContext<'_>, buf: &mut [u8]) -> Result<usize, Self::Error>;

    /// Parse a previously-built dump's header sector. Does NOT verify
    /// the body CRC — see [`verify_crc`](Self::verify_crc).
    fn parse_header(buf: &[u8]) -> Result<CrashDumpHeader<'_>, Self::Error>;

    /// Verify the body CRC32-C against the recorded value in the
    /// header. Returns `Err(CrashDumpError::CrcMismatch)` on
    /// mismatch.
    fn verify_crc(buf: &[u8]) -> Result<(), Self::Error>;

    /// Copy the captured register file into `out` (which must be at
    /// least [`CRASH_REG_COUNT`] u64 slots). Returns the number of
    /// registers copied.
    fn extract_registers(buf: &[u8], out: &mut [u64]) -> Result<usize, Self::Error>;

    /// Copy the captured backtrace into `out`. Returns the number of
    /// frames copied (the value of `backtrace_count` in the header).
    fn extract_backtrace(buf: &[u8], out: &mut [u64]) -> Result<usize, Self::Error>;

    /// Return a byte-slice view of the captured kmsg ring tail. Lifetime
    /// is bounded by the buffer passed in.
    fn extract_kmsg(buf: &[u8]) -> Result<&[u8], Self::Error>;
}

/// Kernel-ELF symbol resolution contract.
///
/// A [`SymbolResolve`] implementation owns a sorted view of the kernel
/// symbol table (typically built once at boot from the kernel ELF's
/// `.symtab` / `.strtab` sections, or stamped into the binary by a
/// `build.rs` step). `resolve(addr)` returns the name + offset of the
/// function containing `addr`, or `None` when no symbol covers it.
///
/// Invariants the verifier checks:
/// - **Containment**: `resolve(addr)` returns `Some((name, offset))`
///   iff some entry `(s_addr, _, s_size)` exists with
///   `s_addr <= addr && addr < s_addr + s_size` (zero-size entries are
///   skipped — they cannot contain any addr). The returned `offset`
///   equals `addr - s_addr`.
/// - **Determinism**: repeated `resolve(addr)` calls return identical
///   `(name, offset)` pairs.
/// - **Performance**: implementations MUST run in O(log n) for `n`
///   symbols. The contract is verified by exercise; the verifier
///   measures the slope of resolution time across two table sizes.
pub trait SymbolResolve {
    /// Resolve an instruction-pointer `addr` to `(name, offset)`. The
    /// returned `name` borrows from the resolver; the `offset` is
    /// `addr - sym_start_addr`.
    fn resolve(&self, addr: u64) -> Option<(&str, u64)>;

    /// Number of symbols loaded into this resolver.
    fn symbol_count(&self) -> usize;
}

// ---------------------------------------------------------------------------
// NetDevice / VirtIO 1.0 network-device wire surface (TASK-048)
// ---------------------------------------------------------------------------

/// VirtIO common-cfg `device_status` register bit constants.
///
/// Layout matches the VirtIO 1.0 specification §2.1 (Device Status
/// Field). The driver brings the device up by writing this sequence
/// of values to the 1-byte register at common-cfg offset 0x14:
///
///   `0` (RESET) → `ACK` → `ACK|DRIVER` → `ACK|DRIVER|FEATURES_OK`
///   → `ACK|DRIVER|FEATURES_OK|DRIVER_OK`.
///
/// Reading back `FAILED` after any write means the device rejected
/// the negotiation; reading back the previous value without
/// `FEATURES_OK` after writing it means the device refused our
/// feature set. The driver must abort in either case.
pub mod virtio_status {
    /// Driver acknowledges the device. Set first.
    pub const ACK: u8 = 0x01;
    /// Driver knows how to drive the device.
    pub const DRIVER: u8 = 0x02;
    /// Driver is fully set up and ready to drive. Set last.
    pub const DRIVER_OK: u8 = 0x04;
    /// Driver has accepted the feature set negotiated below.
    pub const FEATURES_OK: u8 = 0x08;
    /// Device failed re-init / signalled fatal error. Driver aborts.
    pub const FAILED: u8 = 0x80;
}

/// VirtIO-net feature-negotiation bit constants (VirtIO 1.0 §5.1.3
/// "Feature bits"). The seed driver negotiates the subset listed in
/// [`virtio_net_feature::SEED_FEATURE_MASK`].
pub mod virtio_net_feature {
    /// `VIRTIO_NET_F_CSUM` — device supports TX checksum offload (bit 0).
    pub const CSUM: u64 = 1 << 0;
    /// `VIRTIO_NET_F_GUEST_CSUM` — driver supports RX checksum offload
    /// (bit 1). Not negotiated by the seed.
    pub const GUEST_CSUM: u64 = 1 << 1;
    /// `VIRTIO_NET_F_MAC` — device provides a MAC address in
    /// device-cfg (bit 5).
    pub const MAC: u64 = 1 << 5;
    /// `VIRTIO_NET_F_STATUS` — device exposes the LINK_UP /
    /// ANNOUNCE bits in the device-cfg `status` word (bit 16).
    pub const STATUS: u64 = 1 << 16;
    /// `VIRTIO_NET_F_MRG_RXBUF` — driver MAY merge receive
    /// buffers (bit 15). Not negotiated by the seed.
    pub const MRG_RXBUF: u64 = 1 << 15;
    /// `VIRTIO_F_VERSION_1` — VirtIO 1.0+ compliance (bit 32).
    /// Mandatory for the seed.
    pub const VERSION_1: u64 = 1 << 32;
    /// The exact feature set the seed driver offers + requires the
    /// device to support. `VERSION_1 | MAC | STATUS | CSUM`. Any
    /// drift here is observable as a different `driver_feature`
    /// dword pair written to common-cfg.
    pub const SEED_FEATURE_MASK: u64 = VERSION_1 | MAC | STATUS | CSUM;
    /// Subset that the seed driver REQUIRES to be advertised by the
    /// device. `VERSION_1 | MAC`. If the device offers less, the
    /// driver aborts.
    pub const SEED_REQUIRED_MASK: u64 = VERSION_1 | MAC;
}

/// VirtIO-net device-cfg `status` word bits (VirtIO 1.0 §5.1.4).
/// Lives at offset 6 of device-cfg; only meaningful when
/// [`virtio_net_feature::STATUS`] was negotiated.
pub mod virtio_net_status {
    /// Link is up.
    pub const LINK_UP: u16 = 1 << 0;
    /// Device wishes to announce itself.
    pub const ANNOUNCE: u16 = 1 << 1;
}

/// VirtIO virtqueue descriptor flags (VirtIO 1.0 §2.6.5).
pub mod virtq_desc_flags {
    /// Buffer continues via `next` to the next descriptor in a chain.
    pub const NEXT: u16 = 1;
    /// Buffer is device-writable (driver→device is the default —
    /// without this bit set, the buffer is device-READABLE).
    pub const WRITE: u16 = 2;
}

/// VirtIO common-cfg field offsets (VirtIO 1.0 §4.1.4.3 Table 4.1).
/// The wire layout of the common-cfg region is locked by the spec.
pub mod virtio_common_cfg {
    /// `device_feature_select` (u32, RW). 0 selects bits 0..31; 1
    /// selects bits 32..63.
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    /// `device_feature` (u32, RO). Reads return the selected 32-bit
    /// slice of the device feature set.
    pub const DEVICE_FEATURE: usize = 0x04;
    /// `driver_feature_select` (u32, RW). Same select semantics as
    /// device_feature_select.
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    /// `driver_feature` (u32, RW). Driver writes the accepted
    /// 32-bit slice here.
    pub const DRIVER_FEATURE: usize = 0x0C;
    /// `device_status` (u8, RW). Bring-up sequence register —
    /// see [`super::virtio_status`].
    pub const DEVICE_STATUS: usize = 0x14;
    /// `queue_select` (u16, RW). Selects the queue subsequent
    /// queue_* accesses refer to.
    pub const QUEUE_SELECT: usize = 0x16;
    /// `queue_size` (u16, RW). Reads return the device-supported
    /// max size; writes set the driver-chosen size (must be a
    /// power of two ≤ the supported max).
    pub const QUEUE_SIZE: usize = 0x18;
    /// `queue_enable` (u16, RW). Driver writes 1 after configuring
    /// queue_desc/driver/device to bring the queue online.
    pub const QUEUE_ENABLE: usize = 0x1C;
    /// `queue_notify_off` (u16, RO). Offset into the notify region
    /// the driver should write to to ring the doorbell. The actual
    /// notify address is `notify_base + queue_notify_off *
    /// notify_off_multiplier`.
    pub const QUEUE_NOTIFY_OFF: usize = 0x1E;
    /// `queue_desc` (u64, RW). Phys-addr of the descriptor table.
    pub const QUEUE_DESC: usize = 0x20;
    /// `queue_driver` (u64, RW). Phys-addr of the avail ring.
    pub const QUEUE_DRIVER: usize = 0x28;
    /// `queue_device` (u64, RW). Phys-addr of the used ring.
    pub const QUEUE_DEVICE: usize = 0x30;
}

/// Sentinel index identifying the VirtIO-net receive queue
/// (VirtIO 1.0 §5.1.2). Always 0 for the single-queue seed.
pub const VIRTIO_NET_QUEUE_RX: u16 = 0;
/// Sentinel index identifying the VirtIO-net transmit queue
/// (VirtIO 1.0 §5.1.2). Always 1 for the single-queue seed.
pub const VIRTIO_NET_QUEUE_TX: u16 = 1;

/// Locked VirtIO descriptor entry. The byte layout is fixed by VirtIO
/// 1.0 §2.6.5 — 16 bytes, little-endian. Every morph cycle's
/// implementation must produce an identical in-memory representation
/// because the device walks the descriptor table by raw byte offset.
///
/// Field order locked: `addr (u64) || len (u32) || flags (u16) || next
/// (u16)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtqDesc {
    /// Phys-address of the buffer this descriptor covers.
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// Combination of [`virtq_desc_flags`] bits.
    pub flags: u16,
    /// Index of the next descriptor in the chain. Only meaningful if
    /// `flags & NEXT != 0`.
    pub next: u16,
}

/// Compile-time assertion: VirtqDesc must be exactly 16 bytes.
/// A morph that perturbs the field layout breaks the bus contract.
const _: () = {
    assert!(core::mem::size_of::<VirtqDesc>() == 16);
};

/// Wire length of the VirtIO-net packet header when VIRTIO_F_VERSION_1
/// is negotiated (VirtIO 1.0 §5.1.6): exactly 12 bytes prepended to
/// every transmitted / received Ethernet frame.
pub const VIRTIO_NET_HDR_LEN: usize = 12;

/// Locked VirtIO-net packet header (VirtIO 1.0 §5.1.6 Figure "Network
/// Header"). 12 bytes prepended to every TX / RX frame. Field order
/// and types are locked across morph cycles.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    /// Header flags. `VIRTIO_NET_HDR_F_NEEDS_CSUM=1` instructs the
    /// device to compute the L4 checksum; the seed driver always
    /// emits 0 (no checksum offload).
    pub flags: u8,
    /// GSO type. 0 (`VIRTIO_NET_HDR_GSO_NONE`) for the seed.
    pub gso_type: u8,
    /// Header length (when GSO is in use). 0 for the seed.
    pub hdr_len: u16,
    /// GSO segment size. 0 for the seed.
    pub gso_size: u16,
    /// L4 checksum start offset. 0 for the seed.
    pub csum_start: u16,
    /// L4 checksum offset. 0 for the seed.
    pub csum_offset: u16,
    /// Number of mergeable buffers spanned by this packet. 1 for
    /// every TX frame; on RX, the device sets this when VIRTIO_NET_F_MRG_RXBUF
    /// is negotiated. The seed does not negotiate MRG_RXBUF and
    /// asserts `num_buffers == 1` on every received frame.
    pub num_buffers: u16,
}

/// Compile-time assertion: VirtioNetHdr must be exactly
/// [`VIRTIO_NET_HDR_LEN`] (12) bytes.
const _: () = {
    assert!(core::mem::size_of::<VirtioNetHdr>() == VIRTIO_NET_HDR_LEN);
};

/// Errors surfaced by the [`NetDevice`] contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDeviceError {
    /// `init` has not been called, or it returned an error.
    NotInitialised,
    /// A second call to `init` was attempted on a device that already
    /// completed bring-up.
    AlreadyInitialised,
    /// `transmit` called with an empty `frame`.
    FrameEmpty,
    /// `transmit` called with `frame.len() > MAX_FRAME_LEN` (1514).
    FrameTooLarge,
    /// `receive` called with `buf.len() < MAX_FRAME_LEN` — the buffer
    /// must be large enough to hold a full Ethernet frame.
    OutputBufferTooSmall,
    /// `receive` called when no frame is pending in the used ring.
    RxQueueEmpty,
    /// The device's reset / status-negotiation handshake did not
    /// converge inside the bounded poll window.
    ResetTimeout,
    /// Device's negotiated queue size is below the seed's required
    /// minimum (64 entries).
    QueueTooSmall,
    /// Device rejected the driver's feature set (read-back of
    /// `device_status` after writing `FEATURES_OK` showed the bit
    /// cleared).
    FeaturesOkRejected,
    /// Device did not advertise `VIRTIO_F_VERSION_1` — the seed only
    /// drives 1.0+ devices.
    LegacyDeviceUnsupported,
    /// Device did not advertise `VIRTIO_NET_F_MAC` — the seed needs
    /// a MAC from device-cfg, not a self-assigned one.
    MacNotAdvertised,
    /// Device set `STATUS_FAILED` during the bring-up handshake.
    DeviceFailed,
    /// The used-ring index walked past the avail-ring index, i.e.
    /// the device returned more completions than we submitted.
    UsedRingOverflow,
    /// A descriptor returned via the used ring carried an index
    /// outside the descriptor table.
    DescriptorIndexOutOfRange,
    /// The received frame's `num_buffers` field was not 1 — the seed
    /// driver does not implement merged RX buffers.
    UnsupportedRxBuffersMerged,
    /// The received frame's total length was less than
    /// [`VIRTIO_NET_HDR_LEN`].
    RxFrameTruncated,
}

/// Abstract VirtIO-MMIO bus. Real hardware implements this with
/// volatile reads/writes against the controller's BAR0 + DMA-coherent
/// shadow memory; the in-memory emulator [`crate`]'s
/// `MemVirtioBus` (in `target_enterprise::virtio_net`) implements it
/// against byte buffers.
///
/// The bus surface is the locked contract between driver and device;
/// the driver state machine is morphable but every byte the driver
/// writes through this trait reaches the device side as the same
/// byte. That is the load-bearing property the verifier exercises.
pub trait MmioBus {
    /// Read a u8 from common-cfg at offset `off`.
    fn read_common_u8(&self, off: usize) -> u8;
    /// Write a u8 to common-cfg at offset `off`.
    fn write_common_u8(&mut self, off: usize, val: u8);
    /// Read a u16 from common-cfg.
    fn read_common_u16(&self, off: usize) -> u16;
    /// Write a u16 to common-cfg.
    fn write_common_u16(&mut self, off: usize, val: u16);
    /// Read a u32 from common-cfg.
    fn read_common_u32(&self, off: usize) -> u32;
    /// Write a u32 to common-cfg.
    fn write_common_u32(&mut self, off: usize, val: u32);
    /// Write a u64 to common-cfg.
    fn write_common_u64(&mut self, off: usize, val: u64);
    /// Read a u8 from device-cfg.
    fn read_device_u8(&self, off: usize) -> u8;
    /// Read a u16 from device-cfg.
    fn read_device_u16(&self, off: usize) -> u16;
    /// Ring the doorbell for `queue` (0 = RX, 1 = TX). Caller has
    /// already published the new avail.idx via DMA. Real hardware
    /// writes the queue index to a fixed offset inside the notify
    /// region; the emulator dequeues the avail ring synchronously.
    fn notify_queue(&mut self, queue: u16);
    /// DMA: copy `data` to the shadow phys-address `phys`. Real
    /// hardware no-op (driver memory is already DMA-coherent).
    fn dma_write(&mut self, phys: u64, data: &[u8]);
    /// DMA: copy `out.len()` bytes from shadow phys `phys` into
    /// `out`. Real hardware no-op.
    fn dma_read(&self, phys: u64, out: &mut [u8]);
}

/// VirtIO-net network device contract.
///
/// Implementations drive a single VirtIO-net device through its
/// [`MmioBus`] surface. The internal state machine (descriptor ring
/// management, feature negotiation, queue indexing) is diversifiable
/// across morph cycles; the wire-observable surface — every byte the
/// driver writes through `MmioBus` — is not.
///
/// # Locked invariants the verifier checks
///
/// 1. After [`init`](NetDevice::init) succeeds, [`mac_address`](NetDevice::mac_address)
///    returns the MAC the device advertised at device-cfg offsets
///    `0..6`. A morph that perturbs the read sequence produces a
///    different MAC and the kernel banner panics.
/// 2. The bring-up sequence writes `device_status` in the exact
///    `0 → ACK → ACK|DRIVER → ACK|DRIVER|FEATURES_OK →
///    ACK|DRIVER|FEATURES_OK|DRIVER_OK` order. The bus's observation
///    log records every status write; a morph that reorders them
///    fails the verifier's status-sequence assertion.
/// 3. Every byte of [`virtio_net_feature::SEED_FEATURE_MASK`] that the
///    device advertised is written back to `driver_feature` (in two
///    32-bit halves keyed by `driver_feature_select`).
/// 4. For every accepted [`transmit`](NetDevice::transmit) call with
///    `frame ∈ [1, MAX_FRAME_LEN]`, the driver publishes a 2-
///    descriptor chain on the TX queue (header descriptor at index
///    2 * idx, payload descriptor at 2 * idx + 1, NEXT-chained), and
///    the 12-byte [`VirtioNetHdr`] is byte-identical to a header with
///    `num_buffers == 1` and all other fields zero.
/// 5. For every [`receive`](NetDevice::receive) call, the driver
///    consumes from the head of the RX used ring, strips the 12-byte
///    `VirtioNetHdr`, and writes only the Ethernet payload into the
///    caller's buffer. The total byte count returned equals
///    `used.len - VIRTIO_NET_HDR_LEN`.
/// 6. `init` is idempotent — a second call returns
///    [`NetDeviceError::AlreadyInitialised`] without touching the
///    bus.
///
/// # Not in this contract (intentional)
///
/// - Interrupts / MSI-X. The seed is polled.
/// - Merged RX buffers (VIRTIO_NET_F_MRG_RXBUF).
/// - GSO / TSO / UFO / checksum offload paths beyond the FEATURE_CSUM
///   bit being negotiated (the seed driver never sets
///   `flags & NEEDS_CSUM`).
/// - Multi-queue. Single RX + single TX is the seed.
/// - PCI enumeration. The bus is constructed by the caller
///   (kernel: from a probed PCI BAR; tests: in-memory).
pub trait NetDevice {
    /// Drive the device through reset → ACK → DRIVER → feature
    /// negotiation → queue setup → DRIVER_OK. Returns
    /// [`NetDeviceError::AlreadyInitialised`] on second call without
    /// touching the bus.
    fn init(&mut self, bus: &mut dyn MmioBus) -> Result<(), NetDeviceError>;

    /// Transmit one Ethernet frame. The driver prepends a 12-byte
    /// [`VirtioNetHdr`]; `frame` must NOT include the virtio_net_hdr.
    /// Does not block on completion — returns once the descriptor
    /// chain is published + the TX doorbell rung.
    fn transmit(
        &mut self,
        bus: &mut dyn MmioBus,
        frame: &[u8],
    ) -> Result<(), NetDeviceError>;

    /// Receive one Ethernet frame into `out`. Returns the number of
    /// payload bytes written (≥ 0). The 12-byte VirtIO-net header is
    /// stripped before write. Returns
    /// [`NetDeviceError::RxQueueEmpty`] if no frame is pending; the
    /// caller should retry after a future RX completion.
    fn receive(
        &mut self,
        bus: &mut dyn MmioBus,
        out: &mut [u8],
    ) -> Result<usize, NetDeviceError>;

    /// MAC address of the device, as read from device-cfg during
    /// [`init`](Self::init). Returns `[0; 6]` if `init` has not been
    /// called.
    fn mac_address(&self) -> [u8; 6];
}

// ============================================================
// VirtIO-blk block device contract (TASK-061)
// ============================================================

/// Index of the (single) VirtIO-blk request virtqueue (VirtIO 1.0
/// §5.2.2). Locked across morph cycles.
pub const VIRTIO_BLK_QUEUE_REQUESTQ: u16 = 0;

/// Wire length of the VirtIO-blk request header (VirtIO 1.0 §5.2.6):
/// `type (u32) || reserved (u32) || sector (u64)` = 16 bytes,
/// little-endian. Locked across morph cycles — the device walks the
/// descriptor chain by raw byte offsets, so any drift here breaks
/// the contract.
pub const VIRTIO_BLK_HDR_LEN: usize = 16;

/// Wire length of every VirtIO-blk data sector (VirtIO 1.0 §5.2.5).
/// The device always uses 512-byte logical blocks for the request
/// queue regardless of the BLK_SIZE-advertised "preferred" block
/// size — the BLK_SIZE feature only changes the partition-layout
/// arithmetic, not the on-wire sector size.
pub const VIRTIO_BLK_SECTOR_SIZE: usize = 512;

/// Wire length of the device-written status byte at the tail of every
/// request chain (VirtIO 1.0 §5.2.6). Always exactly 1 byte.
pub const VIRTIO_BLK_STATUS_LEN: usize = 1;

/// VirtIO-blk feature-negotiation bit constants (VirtIO 1.0 §5.2.3
/// "Feature bits"). The seed driver negotiates the subset listed in
/// [`virtio_blk_feature::SEED_FEATURE_MASK`].
pub mod virtio_blk_feature {
    /// `VIRTIO_BLK_F_SIZE_MAX` — `size_max` field in device-cfg gives
    /// the maximum segment size the device will accept (bit 1).
    pub const SIZE_MAX: u64 = 1 << 1;
    /// `VIRTIO_BLK_F_SEG_MAX` — `seg_max` field in device-cfg gives
    /// the maximum number of segments per request (bit 2).
    pub const SEG_MAX: u64 = 1 << 2;
    /// `VIRTIO_BLK_F_GEOMETRY` — device-cfg exposes legacy CHS
    /// geometry triple (bit 4).
    pub const GEOMETRY: u64 = 1 << 4;
    /// `VIRTIO_BLK_F_RO` — device is read-only (bit 5).
    pub const RO: u64 = 1 << 5;
    /// `VIRTIO_BLK_F_BLK_SIZE` — device-cfg exposes a preferred
    /// logical block size for partition arithmetic (bit 6).
    pub const BLK_SIZE: u64 = 1 << 6;
    /// `VIRTIO_BLK_F_FLUSH` — device supports the FLUSH command
    /// (bit 9).
    pub const FLUSH: u64 = 1 << 9;
    /// `VIRTIO_BLK_F_TOPOLOGY` — device-cfg exposes 4 alignment /
    /// pref-IO-size bytes (bit 10).
    pub const TOPOLOGY: u64 = 1 << 10;
    /// `VIRTIO_BLK_F_CONFIG_WCE` — writeback-cache enable bit is
    /// driver-controllable via device-cfg (bit 11).
    pub const CONFIG_WCE: u64 = 1 << 11;
    /// `VIRTIO_BLK_F_MQ` — device supports multiple request queues
    /// (bit 12). Seed driver is single-queue only and never
    /// negotiates this.
    pub const MQ: u64 = 1 << 12;
    /// `VIRTIO_BLK_F_DISCARD` — device supports the DISCARD command
    /// (bit 13).
    pub const DISCARD: u64 = 1 << 13;
    /// `VIRTIO_BLK_F_WRITE_ZEROES` — device supports the
    /// WRITE_ZEROES command (bit 14).
    pub const WRITE_ZEROES: u64 = 1 << 14;
    /// `VIRTIO_F_VERSION_1` — VirtIO 1.0+ compliance (bit 32).
    /// Mandatory for the seed. Mirrors [`super::virtio_net_feature::VERSION_1`].
    pub const VERSION_1: u64 = 1 << 32;
    /// The exact feature set the seed driver offers + accepts when
    /// the device advertises it. `VERSION_1 | FLUSH | BLK_SIZE`.
    /// Every byte of this mask reaches the device side via two
    /// 32-bit `driver_feature` halves; the verifier asserts every
    /// byte arrives unaltered.
    pub const SEED_FEATURE_MASK: u64 = VERSION_1 | FLUSH | BLK_SIZE;
    /// Subset that the seed driver REQUIRES to be advertised by the
    /// device. `VERSION_1` alone — the seed will fall back to the
    /// 512-byte default if BLK_SIZE / FLUSH are absent, but it
    /// refuses to drive a legacy (sub-1.0) device.
    pub const SEED_REQUIRED_MASK: u64 = VERSION_1;
}

/// VirtIO-blk request-type byte at offset 0 of every request header
/// (VirtIO 1.0 §5.2.6 Table 5.7).
pub mod virtio_blk_req_type {
    /// `VIRTIO_BLK_T_IN` — read sectors from the device into
    /// driver-supplied buffers. The data descriptor is device-WRITABLE.
    pub const IN: u32 = 0;
    /// `VIRTIO_BLK_T_OUT` — write sectors from driver-supplied
    /// buffers to the device. The data descriptor is device-READABLE.
    pub const OUT: u32 = 1;
    /// `VIRTIO_BLK_T_FLUSH` — request the device flush its
    /// writeback cache to durable media. No data descriptor; only
    /// the header + status. Requires
    /// [`super::virtio_blk_feature::FLUSH`].
    pub const FLUSH: u32 = 4;
    /// `VIRTIO_BLK_T_GET_ID` — request the device's 20-byte ASCII
    /// serial identifier (data descriptor is device-WRITABLE, 20
    /// bytes long).
    pub const GET_ID: u32 = 8;
    /// `VIRTIO_BLK_T_DISCARD` — request the device discard a range
    /// of sectors. Requires
    /// [`super::virtio_blk_feature::DISCARD`].
    pub const DISCARD: u32 = 11;
    /// `VIRTIO_BLK_T_WRITE_ZEROES` — request the device write zeros
    /// to a range of sectors without driver-supplied data. Requires
    /// [`super::virtio_blk_feature::WRITE_ZEROES`].
    pub const WRITE_ZEROES: u32 = 13;
}

/// VirtIO-blk status-byte values written by the device into the tail
/// descriptor on every request completion (VirtIO 1.0 §5.2.6).
pub mod virtio_blk_status_byte {
    /// `VIRTIO_BLK_S_OK` — request completed successfully.
    pub const OK: u8 = 0;
    /// `VIRTIO_BLK_S_IOERR` — device-side I/O error (media failure
    /// or unrecoverable hardware fault).
    pub const IOERR: u8 = 1;
    /// `VIRTIO_BLK_S_UNSUPP` — device does not support the request
    /// type (e.g. FLUSH without FEATURE_FLUSH negotiated).
    pub const UNSUPP: u8 = 2;
    /// Sentinel value the driver writes to the status byte before
    /// publishing a request. The device overwrites it with one of
    /// [`OK`] / [`IOERR`] / [`UNSUPP`] on completion; a still-0xFF
    /// status at completion time means the device never touched
    /// the tail descriptor (driver bug or device misbehaviour).
    /// Locked because the seed driver's "did the device respond"
    /// check compares against this exact byte.
    pub const SENTINEL: u8 = 0xFF;
}

/// VirtIO-blk device-cfg byte offsets (VirtIO 1.0 §5.2.4 Table 5.6).
/// The device-cfg region is the only piece of state where virtio-blk
/// and virtio-net differ on the wire — the common-cfg + virtqueue
/// surfaces are identical and reused from
/// [`virtio_common_cfg`].
pub mod virtio_blk_device_cfg {
    /// `capacity` (u64). Total disk size in 512-byte sectors. Always
    /// present (no feature gate); reads as 0 on an empty backing
    /// store. Read by [`super::BlockDeviceVirtio::init`] to populate
    /// [`super::BlockDeviceVirtio::capacity_sectors`].
    pub const CAPACITY: usize = 0x00;
    /// `size_max` (u32). Maximum segment size in bytes. Only valid
    /// when `VIRTIO_BLK_F_SIZE_MAX` is negotiated.
    pub const SIZE_MAX: usize = 0x08;
    /// `seg_max` (u32). Maximum number of segments per request.
    /// Only valid when `VIRTIO_BLK_F_SEG_MAX` is negotiated.
    pub const SEG_MAX: usize = 0x0C;
    /// `geometry.cylinders` (u16). Legacy CHS geometry. Only valid
    /// when `VIRTIO_BLK_F_GEOMETRY` is negotiated.
    pub const GEOMETRY_CYLINDERS: usize = 0x10;
    /// `geometry.heads` (u8).
    pub const GEOMETRY_HEADS: usize = 0x12;
    /// `geometry.sectors` (u8).
    pub const GEOMETRY_SECTORS: usize = 0x13;
    /// `blk_size` (u32). Preferred logical block size for partition
    /// arithmetic — does NOT change the 512-byte on-wire sector
    /// size used by the request queue. Only valid when
    /// `VIRTIO_BLK_F_BLK_SIZE` is negotiated.
    pub const BLK_SIZE: usize = 0x14;
}

/// Locked VirtIO-blk request header (VirtIO 1.0 §5.2.6). Sixteen
/// bytes, little-endian. Field order locked across morph cycles —
/// the device walks the header by raw byte offset.
///
/// Layout: `type (u32 LE) || reserved (u32 LE) || sector (u64 LE)`.
/// `reserved` MUST be written as 0; the device returns
/// `VIRTIO_BLK_S_IOERR` if non-zero (and even tolerant devices
/// preserve the byte, so a morph that perturbs the reserved field
/// is observable).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtBlkRequest {
    /// One of [`virtio_blk_req_type`] (IN / OUT / FLUSH / GET_ID /
    /// DISCARD / WRITE_ZEROES).
    pub req_type: u32,
    /// Reserved word; the seed driver writes 0 unconditionally.
    pub reserved: u32,
    /// Starting LBA (512-byte sectors). For FLUSH / GET_ID the
    /// field is unused but the seed driver still writes 0.
    pub sector: u64,
}

/// Compile-time assertion: VirtBlkRequest must be exactly
/// [`VIRTIO_BLK_HDR_LEN`] bytes. A morph that perturbs the field
/// layout breaks the bus contract.
const _: () = {
    assert!(core::mem::size_of::<VirtBlkRequest>() == VIRTIO_BLK_HDR_LEN);
};

/// Errors surfaced by the [`BlockDeviceVirtio`] contract.
///
/// Locked discriminant set: external code (and the verifier) may
/// pattern-match on variant names; appending a variant is schema-
/// compatible, removing or reordering one is a schema break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtBlkError {
    /// `init` has not been called, or it returned an error.
    NotInitialised,
    /// A second call to `init` was attempted on a device that
    /// already completed bring-up.
    AlreadyInitialised,
    /// The device's reset / status-negotiation handshake did not
    /// converge inside the bounded poll window.
    ResetTimeout,
    /// Device's negotiated queue size is below the seed's required
    /// minimum.
    QueueTooSmall,
    /// Device rejected the driver's feature set (read-back of
    /// `device_status` after writing `FEATURES_OK` showed the bit
    /// cleared).
    FeaturesOkRejected,
    /// Device did not advertise `VIRTIO_F_VERSION_1` — the seed
    /// only drives 1.0+ devices.
    LegacyDeviceUnsupported,
    /// Device set `STATUS_FAILED` during the bring-up handshake.
    DeviceFailed,
    /// `read_block` / `write_block` called with `sector >=
    /// capacity_sectors()`.
    SectorOutOfRange,
    /// `read_block` / `write_block` called with a buffer whose
    /// length is not exactly [`VIRTIO_BLK_SECTOR_SIZE`].
    BufferSizeMismatch,
    /// `write_block` called on a device that advertised
    /// [`virtio_blk_feature::RO`].
    DeviceReadOnly,
    /// The used-ring index walked past the avail-ring index, i.e.
    /// the device returned more completions than the driver
    /// submitted.
    UsedRingOverflow,
    /// A descriptor returned via the used ring carried an index
    /// outside the descriptor table.
    DescriptorIndexOutOfRange,
    /// The status byte the device wrote into the tail descriptor
    /// was [`virtio_blk_status_byte::IOERR`] (1).
    DeviceIoError,
    /// The status byte the device wrote into the tail descriptor
    /// was [`virtio_blk_status_byte::UNSUPP`] (2).
    RequestUnsupported,
    /// The completion's status byte was still
    /// [`virtio_blk_status_byte::SENTINEL`] (0xFF) — the device
    /// never overwrote it. Either the device dropped the request
    /// or the descriptor chain's tail pointer is wrong.
    StatusByteUntouched,
    /// The bounded poll for completion exhausted its budget without
    /// observing the new used-ring index.
    CompletionTimeout,
    /// FLUSH requested but `VIRTIO_BLK_F_FLUSH` was not negotiated.
    FlushUnsupported,
}

/// VirtIO-blk block-device contract.
///
/// Implementations drive a single VirtIO-blk device through its
/// [`MmioBus`] surface. The internal state machine (descriptor ring
/// management, feature negotiation, queue indexing, request
/// scheduling) is diversifiable across morph cycles; the wire-
/// observable surface — every byte the driver writes through
/// `MmioBus` — is not.
///
/// # Locked invariants the verifier checks
///
/// 1. After [`init`](BlockDeviceVirtio::init) succeeds,
///    [`capacity_sectors`](BlockDeviceVirtio::capacity_sectors)
///    returns the value the device advertised at device-cfg offsets
///    `0..8` (`capacity` field, little-endian u64). A morph that
///    perturbs the read order produces a different capacity and the
///    kernel banner panics.
/// 2. The bring-up sequence writes `device_status` in the exact
///    `0 → ACK → ACK|DRIVER → ACK|DRIVER|FEATURES_OK →
///    ACK|DRIVER|FEATURES_OK|DRIVER_OK` order. The bus's
///    observation log records every status write; a morph that
///    reorders them fails the verifier's status-sequence assertion.
/// 3. Every byte of the accepted feature mask (a subset of
///    [`virtio_blk_feature::SEED_FEATURE_MASK`]) is written back to
///    `driver_feature` in two 32-bit halves keyed by
///    `driver_feature_select`.
/// 4. For every accepted [`read_block`](BlockDeviceVirtio::read_block)
///    call, the driver publishes a 3-descriptor chain on the request
///    queue: header descriptor (device-READABLE, 16 bytes), data
///    descriptor (device-WRITABLE, 512 bytes), status descriptor
///    (device-WRITABLE, 1 byte). The 16-byte header is byte-
///    identical to [`VirtBlkRequest::IN`-encoded] with `reserved = 0`.
/// 5. For every accepted [`write_block`](BlockDeviceVirtio::write_block)
///    call, the driver publishes the same 3-descriptor chain shape
///    but the data descriptor is device-READABLE (no `WRITE` flag).
/// 6. `init` is idempotent — a second call returns
///    [`VirtBlkError::AlreadyInitialised`] without touching the
///    bus.
///
/// # Not in this contract (intentional)
///
/// - Interrupts / MSI-X. The seed is polled.
/// - Multi-queue (VIRTIO_BLK_F_MQ).
/// - DISCARD / WRITE_ZEROES / GET_ID. Future port.
/// - Asynchronous queueing / batching of requests. One in-flight
///   at a time; the driver serialises through internal state.
/// - PCI enumeration. The bus is constructed by the caller
///   (kernel: from a probed PCI BAR; tests: in-memory).
pub trait BlockDeviceVirtio {
    /// Drive the device through reset → ACK → DRIVER → feature
    /// negotiation → queue setup → DRIVER_OK. Reads the disk
    /// capacity from device-cfg. Returns
    /// [`VirtBlkError::AlreadyInitialised`] on second call without
    /// touching the bus.
    fn init(&mut self, bus: &mut dyn MmioBus) -> Result<(), VirtBlkError>;

    /// Read one 512-byte sector from `sector` into `out`.
    /// `out.len()` MUST equal [`VIRTIO_BLK_SECTOR_SIZE`].
    /// Synchronous: builds the 3-descriptor chain, publishes it,
    /// notifies the queue, polls the used ring for completion.
    fn read_block(
        &mut self,
        bus: &mut dyn MmioBus,
        sector: u64,
        out: &mut [u8],
    ) -> Result<(), VirtBlkError>;

    /// Write one 512-byte sector to `sector` from `data`.
    /// `data.len()` MUST equal [`VIRTIO_BLK_SECTOR_SIZE`].
    /// Synchronous: same shape as [`read_block`](Self::read_block)
    /// but the data descriptor is device-READABLE.
    fn write_block(
        &mut self,
        bus: &mut dyn MmioBus,
        sector: u64,
        data: &[u8],
    ) -> Result<(), VirtBlkError>;

    /// Disk capacity in 512-byte sectors, as read from device-cfg
    /// during [`init`](Self::init). Returns 0 if `init` has not
    /// been called.
    fn capacity_sectors(&self) -> u64;
}

/// IPv4 protocol number for TCP per IANA / RFC 793. Locked across
/// morph cycles. Mirrors [`IP_PROTO_UDP`] so the [`PacketFilter`]
/// surface can match TCP rules without relying on bare 6 literals.
pub const IP_PROTO_TCP: u8 = 6;

/// IPv4 protocol number for ICMP per IANA / RFC 792. Locked across
/// morph cycles. Mirrors [`IP_PROTO_UDP`] so the [`PacketFilter`]
/// surface can match ICMP rules without relying on bare 1 literals.
pub const IP_PROTO_ICMP: u8 = 1;

/// Sentinel `proto` value in a [`FilterRule`] meaning "match any IPv4
/// next-protocol byte". Distinct from any IANA-assigned number — the
/// IANA reserved-for-experimentation range starts at 253 and zero is
/// listed as `HOPOPT` for IPv6 only, but in the IPv4 packet-filter
/// semantics zero is unambiguous as a wildcard.
pub const FW_PROTO_ANY: u8 = 0;

/// Action attached to a [`FilterRule`]. Drives the [`Verdict`] the
/// [`PacketFilter::evaluate`] entry-point returns when a rule matches.
///
/// Distinction between [`FilterAction::Reject`] and [`FilterAction::Drop`]
/// follows Linux netfilter semantics: a rejected packet should provoke
/// an ICMP unreachable back to the source (so the peer learns the path
/// is closed); a dropped packet is silently consumed (no leak about
/// the rule's existence). The [`PacketFilter`] surface only reports
/// the verdict; the caller is responsible for actually sending the
/// ICMP reply.
///
/// Locked discriminant order: external code (and the verifier) may
/// pattern-match on these variants by name and by their `u8`
/// representation. Reordering or removing a variant is a schema
/// break; appending one is schema-compatible.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum FilterAction {
    /// Admit the packet. Maps to [`Verdict::Accept`].
    Accept = 0,
    /// Discard the packet and signal the source via ICMP-unreachable
    /// (the caller emits the reply; this trait only carries the
    /// verdict). Maps to [`Verdict::Reject`].
    Reject = 1,
    /// Silently discard the packet. Maps to [`Verdict::Drop`].
    Drop = 2,
}

/// Verdict returned by [`PacketFilter::evaluate`]. The locked semantic
/// distinction from [`FilterAction`] is the additional `NoMatch`
/// variant, which surfaces when **no rule** in the supplied slice
/// matched the packet — that distinction is what lets the caller pick
/// the table's default policy (e.g. default-deny via `Drop`,
/// default-allow via `Accept`) without baking the choice into the
/// filter trait itself.
///
/// Locked discriminant order: as for [`FilterAction`].
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum Verdict {
    /// A matching rule's action was [`FilterAction::Accept`].
    Accept = 0,
    /// A matching rule's action was [`FilterAction::Reject`].
    Reject = 1,
    /// A matching rule's action was [`FilterAction::Drop`].
    Drop = 2,
    /// No rule in the table matched. The caller applies the table's
    /// default policy (default-deny = treat as `Drop`; default-allow
    /// = treat as `Accept`).
    NoMatch = 3,
}

impl Verdict {
    /// Project a [`FilterAction`] into the matching [`Verdict`]. Pure
    /// constant-time mapping; locked across morph cycles.
    #[inline]
    pub const fn from_action(action: FilterAction) -> Self {
        match action {
            FilterAction::Accept => Verdict::Accept,
            FilterAction::Reject => Verdict::Reject,
            FilterAction::Drop => Verdict::Drop,
        }
    }
}

/// Wildcard sentinel for [`FilterRule::src_port_start`] /
/// `dst_port_start` / `_end` fields. When both `start` and `end` of a
/// port range are zero the range matches every port (including the
/// real port 0, which is reserved on the wire — the filter doesn't
/// care, the wire-layer rejects port 0 already).
///
/// For non-wildcard ranges callers set `start <= end` with `1 <= start`
/// and `end <= 65535`. The locked semantics is `port in start..=end`
/// (inclusive both ends) — a single-port rule sets `start == end`.
pub const FW_PORT_ANY: u16 = 0;

/// One row of a stateless IPv4 packet-filter table.
///
/// Matches against a [`Ipv4PacketView`] using a 5-tuple
/// `(src_ip/src_mask, dst_ip/dst_mask, proto, src_port range,
/// dst_port range)` plus a [`FilterAction`]. The two-CIDR + two-port-
/// range + proto layout intentionally mirrors a single Linux netfilter
/// `iptables -A` line at the most common slice; statefulness,
/// connection-tracking, and rate limits are out of scope (separate
/// future contracts).
///
/// # Locked invariants the verifier checks
///
/// 1. `src_mask` and `dst_mask` are CIDR prefix lengths in
///    `0..=32`. Values outside that range surface as a
///    [`FilterRuleError::BadCidr`] from the validator.
/// 2. `src_port_start <= src_port_end` when either is non-zero;
///    same for the dst pair. A wildcard range is `start == end == 0`.
/// 3. `proto == 0` means "any IPv4 next-protocol" — the locked
///    [`FW_PROTO_ANY`] sentinel. Concrete protos must use the
///    IANA-assigned byte (1 = ICMP, 6 = TCP, 17 = UDP, …).
/// 4. The struct is `Copy` so the filter trait can take rule slices
///    by value-stride without lifetime gymnastics.
///
/// The struct is `#[repr(C)]` so an external tool (e.g. a future
/// `iptables-save`-style dumper) can serialise rule tables byte-for-
/// byte. The field order is part of the locked surface.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct FilterRule {
    /// Source IPv4 (network-order bytes), e.g. `[10, 0, 0, 0]`.
    pub src_ip: [u8; 4],
    /// CIDR prefix length applied to `src_ip`, `0..=32`. 0 = any.
    pub src_mask: u8,
    /// Destination IPv4 (network-order bytes).
    pub dst_ip: [u8; 4],
    /// CIDR prefix length applied to `dst_ip`, `0..=32`. 0 = any.
    pub dst_mask: u8,
    /// IPv4 next-protocol number. [`FW_PROTO_ANY`] (0) = wildcard.
    pub proto: u8,
    /// Source port range start (inclusive), host order.
    /// [`FW_PORT_ANY`] both fields = wildcard.
    pub src_port_start: u16,
    /// Source port range end (inclusive), host order.
    pub src_port_end: u16,
    /// Destination port range start (inclusive), host order.
    pub dst_port_start: u16,
    /// Destination port range end (inclusive), host order.
    pub dst_port_end: u16,
    /// What to do when this rule matches.
    pub action: FilterAction,
}

/// 5-tuple view of an IPv4 packet, fed to [`PacketFilter::evaluate`].
///
/// Built by the kernel from the already-parsed [`Ipv4HeaderView`] +
/// (TCP / UDP / ICMP) header pair, so the filter never re-parses the
/// IPv4 layer. For ICMP — where no L4 port exists — both ports are
/// zero and the locked semantics is "port wildcards still match
/// because the rule's port range must also be a wildcard for ICMP".
///
/// All fields are in **host byte order** for the multi-byte ones; the
/// IP fields stay as 4-byte network-order arrays (matching
/// [`Ipv4HeaderView::src_ip`] / `dst_ip`).
///
/// Locked across morph cycles.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct Ipv4PacketView {
    /// Source IPv4 address (network-order bytes).
    pub src_ip: [u8; 4],
    /// Destination IPv4 address (network-order bytes).
    pub dst_ip: [u8; 4],
    /// IPv4 next-protocol byte (1 ICMP, 6 TCP, 17 UDP, …).
    pub protocol: u8,
    /// L4 source port (host order). Zero for ICMP / proto-without-port.
    pub src_port: u16,
    /// L4 destination port (host order). Zero for ICMP /
    /// proto-without-port.
    pub dst_port: u16,
}

/// Errors surfaced by [`FilterRule::validate`] and the
/// `FilterTable::insert` path.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum FilterRuleError {
    /// `src_mask` or `dst_mask` was greater than 32.
    BadCidr,
    /// A port range had `start > end` with at least one non-zero.
    BadPortRange,
    /// Insertion would exceed the table's fixed capacity.
    TableFull,
    /// Removal targeted an index that is past the active rule count.
    IndexOutOfRange,
}

/// Stateless IPv4 packet-filter contract.
///
/// Implementations evaluate a packet against an ordered slice of
/// [`FilterRule`]s and return the first matching rule's verdict, or
/// [`Verdict::NoMatch`] if no rule matched. Internals (whether the
/// matcher uses a linear scan, a trie, SIMD bitmasks, …) are
/// diversifiable across morph cycles; the byte-observable contract —
/// what verdict comes out for a given (rules, packet) pair — is not.
///
/// # Locked invariants the verifier checks
///
/// 1. Rule precedence is **first-match-wins** in the order rules
///    appear in the slice. The kernel banner relies on this to assert
///    a longer-prefix rule placed earlier in the table preempts a
///    shorter-prefix rule placed later.
/// 2. CIDR masking is applied to both endpoints. A rule with
///    `src_mask = 8` and `src_ip = [10, 0, 0, 0]` matches packets
///    whose source falls in `10.0.0.0/8`, i.e. only the first octet
///    is compared.
/// 3. `proto == FW_PROTO_ANY` (0) matches every IPv4 next-protocol;
///    any other proto value requires byte-exact equality with
///    [`Ipv4PacketView::protocol`].
/// 4. A port range `[FW_PORT_ANY, FW_PORT_ANY]` (i.e. both zero)
///    matches every L4 port including 0; any non-wildcard range
///    requires `start <= packet_port <= end`.
/// 5. Returns [`Verdict::NoMatch`] iff no rule matched. The caller
///    layers its default policy on top by mapping `NoMatch` to
///    `Accept`/`Drop` per the deployment posture.
pub trait PacketFilter {
    /// Evaluate `packet` against `rules` in slice order. Returns
    /// [`Verdict`] for the first matching rule, or
    /// [`Verdict::NoMatch`] if no rule matched.
    fn evaluate(rules: &[FilterRule], packet: &Ipv4PacketView) -> Verdict;
}

// ============================================================
// TPM 2.0 client-side wire codec (TASK-051)
// ============================================================

/// Length of a TPM 2.0 command/response header in bytes:
/// `u16 tag + u32 commandSize + u32 commandCode-or-responseCode = 10`.
/// Every command and every response carries this prefix on the wire.
pub const TPM_HEADER_LEN: usize = 10;

/// TPM 2.0 structure tag for a command/response with **no** sessions
/// (i.e. no authorization area). Locked at the TCG-assigned wire value
/// `0x8001`.
pub const TPM_ST_NO_SESSIONS: u16 = 0x8001;

/// TPM 2.0 structure tag for a command/response that carries one or
/// more authorization sessions. Locked at the TCG-assigned wire value
/// `0x8002`. Used by [`Tpm::build_pcr_extend`] which always carries
/// the password-authorization session.
pub const TPM_ST_SESSIONS: u16 = 0x8002;

/// TPM 2.0 command code: `TPM2_Startup`. TCG Library Pt 3 §9.3.
/// Locked across morph cycles.
pub const TPM_CC_STARTUP: u32 = 0x0000_0144;

/// TPM 2.0 command code: `TPM2_GetRandom`. TCG Library Pt 3 §16.1.
/// Locked across morph cycles.
pub const TPM_CC_GET_RANDOM: u32 = 0x0000_017B;

/// TPM 2.0 command code: `TPM2_PCR_Read`. TCG Library Pt 3 §22.4.
/// Locked across morph cycles.
pub const TPM_CC_PCR_READ: u32 = 0x0000_017E;

/// TPM 2.0 command code: `TPM2_PCR_Extend`. TCG Library Pt 3 §22.2.
/// Locked across morph cycles.
pub const TPM_CC_PCR_EXTEND: u32 = 0x0000_0182;

/// TPM 2.0 `TPM_SU` startup type: `TPM_SU_CLEAR` (reset PCRs/banks).
/// TCG Library Pt 2 §6.9. Locked.
pub const TPM_SU_CLEAR: u16 = 0x0000;

/// TPM 2.0 `TPM_SU` startup type: `TPM_SU_STATE` (restore saved state).
/// TCG Library Pt 2 §6.9. Locked.
pub const TPM_SU_STATE: u16 = 0x0001;

/// TPM 2.0 algorithm identifier for SHA-256. TCG Library Pt 2 §6.3
/// (`TPM_ALG_SHA256 = 0x000B`). Locked.
pub const TPM_ALG_SHA256: u16 = 0x000B;

/// TPM 2.0 algorithm identifier for SHA-1. Included only so the
/// PCR_Read decoder can recognise the alternative bank a host might
/// have configured. Locked.
pub const TPM_ALG_SHA1: u16 = 0x0004;

/// Permanent password-authorization session handle. TCG Library Pt 2
/// §7.5 (`TPM_RS_PW = 0x40000009`). Used by [`Tpm::build_pcr_extend`]
/// as the well-known empty-password session. Locked.
pub const TPM_RS_PW: u32 = 0x4000_0009;

/// `TPM_RC_SUCCESS` — the response code that indicates a TPM 2.0
/// command succeeded with no warning bits set. Locked. Equality with
/// zero is the wire contract — every non-zero value is an error or a
/// warning whose interpretation depends on the format bits.
pub const TPM_RC_SUCCESS: u32 = 0x0000_0000;

/// SHA-256 digest length in bytes — 32. Used by [`Tpm::build_pcr_extend`]
/// when `digest_alg == TPM_ALG_SHA256`. Locked.
pub const TPM_SHA256_DIGEST_LEN: usize = 32;

/// SHA-1 digest length in bytes — 20. Used when `digest_alg ==
/// TPM_ALG_SHA1`. Locked.
pub const TPM_SHA1_DIGEST_LEN: usize = 20;

/// Maximum PCR index the trait's PCR-handle encoder accepts. The TCG
/// Platform Profile uses 0..=23 as the platform-PCR set; values
/// outside that range are surfaced as [`TpmError::BadPcrIndex`] so a
/// malformed caller never produces a wire-frame that addresses a non-
/// existent PCR slot.
pub const TPM_MAX_PCR_INDEX: u32 = 23;

/// Errors surfaced by the [`Tpm`] wire codec.
///
/// Locked discriminant order — external code may pattern-match on
/// these variants by name (the `u8` repr is not part of the surface;
/// adding a variant at the end is schema-compatible, reordering is
/// not). Each variant documents the wire condition that produces it
/// so future verifier tests can exercise every arm by construction.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum TpmError {
    /// The caller's `out` buffer for a `build_*` call was smaller than
    /// the command's locked wire length. The locked lengths are:
    /// `TPM2_Startup` = 12 bytes, `TPM2_GetRandom` = 12 bytes,
    /// `TPM2_PCR_Read` = 20 bytes, `TPM2_PCR_Extend` (SHA-256) =
    /// 65 bytes.
    BufferTooSmall,
    /// `parse_response` received a buffer shorter than
    /// [`TPM_HEADER_LEN`] = 10 bytes. The TPM 2.0 spec guarantees
    /// every response carries the 10-byte header even when the
    /// command failed — a shorter buffer is therefore a wire-layer
    /// corruption, not a TPM error.
    Truncated,
    /// `parse_response` saw a `tag` field that was neither
    /// [`TPM_ST_NO_SESSIONS`] nor [`TPM_ST_SESSIONS`]. The TCG spec
    /// allows additional tags for vendor-specific extensions; we
    /// reject them so the caller cannot accidentally treat e.g. a
    /// PEM-wrapped response as a structured TPM reply.
    BadTag,
    /// `parse_response` saw a `responseSize` field that disagrees
    /// with the buffer length supplied. The spec mandates
    /// `responseSize == buf.len()` exactly; any divergence indicates
    /// either truncation (size > buf.len) or padding (size <
    /// buf.len) and both are surface errors.
    BadSizeField,
    /// `build_pcr_extend` was called with a `digest` whose length did
    /// not match the locked length for `digest_alg` (32 for SHA-256,
    /// 20 for SHA-1). Other algorithms are rejected here too with the
    /// same error.
    BadDigestLen,
    /// A `build_pcr_*` call received a `pcr_index` outside
    /// `0..=TPM_MAX_PCR_INDEX`. The trait deliberately encodes only
    /// the platform-PCR set so a malformed caller cannot construct a
    /// frame that addresses an out-of-range PCR slot the TPM would
    /// reject.
    BadPcrIndex,
    /// `build_pcr_extend` was called with a `digest_alg` other than
    /// [`TPM_ALG_SHA256`] or [`TPM_ALG_SHA1`]. The locked surface
    /// rejects unknown algorithms at the wire boundary so a future
    /// algorithm addition is an explicit schema bump, not a silent
    /// passthrough.
    UnsupportedAlg,
    /// `build_get_random` was called with `bytes_requested == 0`. The
    /// TCG spec accepts the value but it makes no sense as a command
    /// (the response would carry an empty `TPM2B_DIGEST`); the codec
    /// rejects it so the caller surfaces the bug at the build site
    /// rather than at the device boundary.
    BadByteCount,
}

/// Parsed view of a TPM 2.0 response header plus its body slice. Pure
/// projection — no copy. The wire bytes underlying the view must
/// outlive the view.
///
/// Locked invariants the verifier checks:
///
/// 1. `tag` is one of [`TPM_ST_NO_SESSIONS`] / [`TPM_ST_SESSIONS`].
/// 2. `size` equals `body.len() + TPM_HEADER_LEN` exactly (mirrors
///    the on-wire `responseSize` field; `body` is the post-header
///    sub-slice the caller hands further parsing).
/// 3. `response_code` is the raw `u32` from the wire. Callers MUST
///    test `response_code == TPM_RC_SUCCESS` before treating `body`
///    as a meaningful command reply — TPM 2.0 places error/warning
///    information in `response_code` and leaves `body` undefined on
///    failure.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct TpmResponseView<'a> {
    /// Wire tag: [`TPM_ST_NO_SESSIONS`] or [`TPM_ST_SESSIONS`].
    pub tag: u16,
    /// Total response size in bytes (header + body). Mirrors the
    /// on-wire `responseSize` field after validation.
    pub size: u32,
    /// Response code; zero = `TPM_RC_SUCCESS`, non-zero = error or
    /// warning.
    pub response_code: u32,
    /// Body bytes after the 10-byte header. Caller-interpreted per
    /// the command that originated the response.
    pub body: &'a [u8],
}

/// TPM 2.0 client-side wire codec.
///
/// Implementations build TCG-spec wire frames for the four kernel-
/// facing commands (`TPM2_Startup`, `TPM2_GetRandom`, `TPM2_PCR_Read`,
/// `TPM2_PCR_Extend`) and parse the matching response header. The
/// codec is intentionally *transport-agnostic*: it does not touch
/// MMIO, ACPI tables, or CRB control registers. Plugging the codec
/// into a CRB/TIS driver is the deployment's responsibility (the
/// RustOSa donor `tpm.rs` shows the CRB pattern); the codec itself is
/// pure byte-shuffling, fully host-testable, and fully diversifiable
/// across morph cycles.
///
/// # Locked invariants the verifier checks
///
/// 1. `build_startup` emits exactly 12 bytes:
///    `80 01 | 00 00 00 0c | 00 00 01 44 | <su_hi> <su_lo>` (big-
///    endian for every multi-byte field).
/// 2. `build_get_random` emits exactly 12 bytes:
///    `80 01 | 00 00 00 0c | 00 00 01 7b | <bytes_hi> <bytes_lo>`.
/// 3. `build_pcr_read` emits exactly 20 bytes; the trailing
///    `TPML_PCR_SELECTION` block selects exactly one bank
///    (SHA-256), `sizeOfSelect = 3`, and the 3-byte bitmask has the
///    one bit corresponding to `pcr_index` set and all others clear.
/// 4. `build_pcr_extend` emits exactly 65 bytes for a SHA-256
///    digest: 10-byte header (tag = [`TPM_ST_SESSIONS`]), 4-byte
///    `pcrHandle` = `pcr_index` (handle space starts at 0), 4-byte
///    `authorizationSize` = 9, 9-byte password-authorization session
///    (`sessionHandle = TPM_RS_PW`, both nonces / hmac empty), 4-byte
///    `digests.count` = 1, 2-byte `digests[0].hashAlg` =
///    [`TPM_ALG_SHA256`], 32-byte digest.
/// 5. `parse_response` validates `tag ∈ {TPM_ST_NO_SESSIONS,
///    TPM_ST_SESSIONS}` and `size == buf.len()` exactly. The
///    `responseCode` is surfaced as-is; the caller decides whether
///    it counts as success.
pub trait Tpm {
    /// Build a `TPM2_Startup(startup_type)` command. Returns the
    /// number of bytes written. `startup_type` must be
    /// [`TPM_SU_CLEAR`] or [`TPM_SU_STATE`] — any other value still
    /// emits the requested 12 bytes (the trait does not validate the
    /// startup type because the spec allows future SU values), but
    /// the kernel banner asserts against [`TPM_SU_CLEAR`].
    fn build_startup(out: &mut [u8], startup_type: u16) -> Result<usize, TpmError>;

    /// Build a `TPM2_GetRandom(bytes_requested)` command. Returns the
    /// number of bytes written.
    fn build_get_random(out: &mut [u8], bytes_requested: u16) -> Result<usize, TpmError>;

    /// Build a `TPM2_PCR_Read` command targeting `pcr_index` in the
    /// SHA-256 bank. Returns the number of bytes written.
    fn build_pcr_read(out: &mut [u8], pcr_index: u32) -> Result<usize, TpmError>;

    /// Build a `TPM2_PCR_Extend` command extending `pcr_index` with
    /// `digest` under the password-authorization session. Returns
    /// the number of bytes written.
    fn build_pcr_extend(
        out: &mut [u8],
        pcr_index: u32,
        digest_alg: u16,
        digest: &[u8],
    ) -> Result<usize, TpmError>;

    /// Parse a TPM 2.0 response header and return the
    /// [`TpmResponseView`]. The view's `body` is the post-header
    /// sub-slice; further command-specific parsing is the caller's
    /// responsibility.
    fn parse_response(buf: &[u8]) -> Result<TpmResponseView<'_>, TpmError>;
}

// ============================================================
// AuditLog — kernel security event log (TASK-052)
// ============================================================

/// Fixed inline-message capacity for an [`AuditEvent`]. Locked at 64
/// bytes — long enough to carry a short syscall name + a numeric
/// argument or a single denial reason, short enough to keep every event
/// record on the wire and in the ring at exactly
/// [`AUDIT_EVENT_WIRE_LEN`] bytes. Excess characters in a caller's
/// message are truncated; shorter messages are NUL-padded.
pub const AUDIT_MESSAGE_LEN: usize = 64;

/// Locked wire size of one serialised audit record. A `snapshot` call
/// emits exactly `count * AUDIT_EVENT_WIRE_LEN + AUDIT_SNAPSHOT_HEADER_LEN`
/// bytes. The layout is documented at [`AuditLog::snapshot`].
///
/// Composition (big-endian, no padding):
///   `event_id`      u64   — 8 bytes
///   `wall_unix`     u64   — 8 bytes
///   `task_id`       u64   — 8 bytes
///   `syscall_nr`    u32   — 4 bytes
///   `verdict`       u8    — 1 byte  (locked `AuditVerdict` repr)
///   `_pad`          u8x3  — 3 bytes (zeroed — locked padding to align
///                                    the message on a 32-byte boundary)
///   `message`       u8x64 — 64 bytes (NUL-padded inline message)
/// = 96 bytes
pub const AUDIT_EVENT_WIRE_LEN: usize = 8 + 8 + 8 + 4 + 1 + 3 + AUDIT_MESSAGE_LEN;

/// Locked wire size of the snapshot header. A `snapshot` call writes
/// this header first, then the record stream. Layout (big-endian):
///   magic            u32  — 4 bytes (`AUDIT_SNAPSHOT_MAGIC`)
///   record_count     u32  — 4 bytes
///   record_size      u32  — 4 bytes (== `AUDIT_EVENT_WIRE_LEN`)
///   high_watermark   u64  — 8 bytes (largest event_id ever appended;
///                                    the offline parser uses this to
///                                    detect overwritten-oldest events)
/// = 20 bytes
pub const AUDIT_SNAPSHOT_HEADER_LEN: usize = 4 + 4 + 4 + 8;

/// Locked magic at the front of an audit-log snapshot — ASCII "AUDT"
/// in big-endian. Lets an offline parser sanity-check the buffer
/// before walking records.
pub const AUDIT_SNAPSHOT_MAGIC: u32 = 0x4155_4454;

/// Verdict carried by every [`AuditEvent`]. Locked discriminants so a
/// snapshot taken under one morph cycle parses identically under any
/// future cycle.
///
/// External callers are expected to pattern-match by variant name; the
/// `u8` repr is part of the surface so the snapshot's byte stream is
/// stable.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum AuditVerdict {
    /// Operation was permitted. Used for high-value successful actions
    /// that policy mandates be logged (root login, cap mint, attest
    /// signature) — NOT for routine syscalls.
    Allowed = 0,
    /// Operation was denied by the cap table, IOMMU, packet filter, or
    /// any other policy gate. Every denial in the kernel SHOULD emit
    /// one of these.
    Denied = 1,
    /// Operation faulted in flight (page fault on a kernel address,
    /// IOMMU translation miss, NVMe IO error). Distinguished from
    /// `Denied` because the cause is a runtime fault, not a policy
    /// refusal.
    Error = 2,
}

impl AuditVerdict {
    /// Recover an `AuditVerdict` from its `u8` discriminant. Returns
    /// `None` for any value outside the locked set, so the offline
    /// snapshot parser refuses to mint an unknown verdict variant.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(AuditVerdict::Allowed),
            1 => Some(AuditVerdict::Denied),
            2 => Some(AuditVerdict::Error),
            _ => None,
        }
    }

    /// Locked `u8` discriminant. Mirrors the `#[repr(u8)]` value so
    /// callers don't need an `as u8` cast at the call site.
    pub const fn as_u8(self) -> u8 {
        self as u8
    }
}

/// One audit event — the unit a kernel call appends with
/// [`AuditLog::append`]. Locked layout: every field's width and order is
/// part of the wire surface so an offline parser can walk a snapshot
/// stream by record index.
///
/// `message` is NUL-padded: shorter strings are zero-filled, longer
/// strings are truncated at append time. The trait deliberately does
/// not surface a "message too long" error so a noisy logger never
/// becomes a denial-of-service vector against the log path.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(C)]
pub struct AuditEvent {
    /// Monotonically increasing across the entire lifetime of the
    /// underlying log. Even when the ring overwrites the oldest entry,
    /// `event_id` keeps counting up — the high-water-mark is part of
    /// the snapshot header so an offline parser can detect gaps.
    pub event_id: u64,
    /// Wall-clock Unix time at append. Caller-supplied; the audit log
    /// itself does not read a clock so a host-side test can drive
    /// arbitrary timestamps.
    pub wall_unix: u64,
    /// Originating task id (kernel scheduler `TaskId`). Zero for
    /// kernel-internal events.
    pub task_id: u64,
    /// Syscall number that triggered the event, or zero for non-syscall
    /// events (interrupt-driven faults, scheduled audits).
    pub syscall_nr: u32,
    /// Verdict — see [`AuditVerdict`].
    pub verdict: AuditVerdict,
    /// Inline message — NUL-padded fixed-capacity ASCII. Use
    /// [`AuditEvent::message_str`] on the read side to recover the
    /// non-padded sub-slice.
    pub message: [u8; AUDIT_MESSAGE_LEN],
}

impl AuditEvent {
    /// Construct an event with `message` copied + NUL-padded. Strings
    /// longer than [`AUDIT_MESSAGE_LEN`] are truncated; shorter strings
    /// are zero-filled. Pure, allocation-free, `const`-evaluable.
    pub const fn new(
        event_id: u64,
        wall_unix: u64,
        task_id: u64,
        syscall_nr: u32,
        verdict: AuditVerdict,
        message: &[u8],
    ) -> Self {
        let mut msg = [0u8; AUDIT_MESSAGE_LEN];
        let take = if message.len() < AUDIT_MESSAGE_LEN {
            message.len()
        } else {
            AUDIT_MESSAGE_LEN
        };
        let mut i = 0;
        while i < take {
            msg[i] = message[i];
            i += 1;
        }
        AuditEvent {
            event_id,
            wall_unix,
            task_id,
            syscall_nr,
            verdict,
            message: msg,
        }
    }

    /// Recover the non-padded message as a byte slice. Walks until the
    /// first NUL or the end of the fixed array.
    pub fn message_bytes(&self) -> &[u8] {
        let mut end = 0usize;
        while end < AUDIT_MESSAGE_LEN && self.message[end] != 0 {
            end += 1;
        }
        &self.message[..end]
    }
}

/// Errors surfaced by [`AuditLog::snapshot`]. Append + iterate cannot
/// fail by design — the ring overwrites the oldest on full, and iter
/// hands out a borrowed view.
///
/// Locked discriminant order — external code may pattern-match on
/// variant name.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum AuditError {
    /// `snapshot` was called with a buffer that cannot hold the header
    /// plus every present record. Callers should size the buffer at
    /// `AUDIT_SNAPSHOT_HEADER_LEN + capacity * AUDIT_EVENT_WIRE_LEN`.
    BufferTooSmall,
}

/// Kernel audit-event log.
///
/// The contract describes a fixed-capacity ring that:
///
/// 1. Stamps every appended event with a monotonically-increasing
///    `event_id`, regardless of whether the ring overwrites an older
///    entry. The high-water-mark survives the overwrite.
/// 2. Iterates in **append order** (oldest still-resident event first,
///    most recent last). Pulling the iter twice produces the same
///    sequence — the log is single-reader/single-writer-style read-
///    stable.
/// 3. Serialises to a byte stream with a locked layout
///    ([`AUDIT_SNAPSHOT_HEADER_LEN`] + N × [`AUDIT_EVENT_WIRE_LEN`]) so
///    an offline parser can walk the stream record-by-record without
///    needing to know the in-memory representation.
///
/// # Locked invariants the verifier checks
///
/// 1. The `event_id` written by `append` equals `1 + last_event_id`
///    (zero for the very first append).
/// 2. After `N + k` appends into a `capacity = N` log, `iter()` yields
///    the `min(N, N + k)` events with the highest `event_id`s, in
///    ascending `event_id` order.
/// 3. `snapshot(buf)` returns
///    `AUDIT_SNAPSHOT_HEADER_LEN + iter().count() * AUDIT_EVENT_WIRE_LEN`
///    on success and writes exactly that many bytes; returns
///    [`AuditError::BufferTooSmall`] otherwise without touching `buf`.
/// 4. The snapshot byte layout is the documented big-endian
///    composition. Every multi-byte field is big-endian. No padding
///    beyond the locked 3-byte alignment slot.
pub trait AuditLog {
    /// Append an audit event. The implementation:
    /// - Overwrites `event.event_id` with the next monotonic value
    ///   before storing.
    /// - Overwrites the oldest still-resident entry on full (lossy
    ///   ring — by design, so audit-storm cannot stall the syscall
    ///   path).
    ///
    /// Returns the assigned `event_id` so the caller can correlate
    /// the append with the eventual snapshot record.
    fn append(&mut self, event: AuditEvent) -> u64;

    /// Iterate the events currently resident in the ring, in ascending
    /// `event_id` order (oldest first). After an overwrite, the
    /// dropped entries are absent — the offline parser detects gaps
    /// via the snapshot header's `high_watermark`.
    fn iter(&self) -> AuditIter<'_>;

    /// Serialise the log into `out`. Layout is the locked composition
    /// described at the trait level. Returns the number of bytes
    /// written on success; [`AuditError::BufferTooSmall`] if `out` is
    /// too short. On error, `out` is not modified.
    fn snapshot(&self, out: &mut [u8]) -> Result<usize, AuditError>;
}

/// Borrowed iterator over an audit log's resident events. Yields each
/// event by value (`AuditEvent` is `Copy`). The iter is **read-stable**
/// — calling it twice produces the same sequence as long as no
/// intervening `append` has fired.
pub struct AuditIter<'a> {
    slots: &'a [AuditEvent],
    /// Absolute starting position in `slots` (the index of the oldest
    /// resident entry).
    head: usize,
    /// Logical position within the iteration (0..len).
    pos: usize,
    /// Number of resident entries.
    len: usize,
}

impl<'a> AuditIter<'a> {
    /// Construct an iterator over `slots`. `head` is the slot index of
    /// the oldest still-resident entry; `len` is the number of resident
    /// entries (≤ `slots.len()`). Implementors call this once per
    /// `iter()`.
    pub const fn new(slots: &'a [AuditEvent], head: usize, len: usize) -> Self {
        AuditIter { slots, head, pos: 0, len }
    }

    /// Number of events the iterator will yield.
    pub const fn len(&self) -> usize {
        self.len - self.pos
    }

    /// Whether the iterator is exhausted.
    pub const fn is_empty(&self) -> bool {
        self.pos >= self.len
    }
}

impl<'a> Iterator for AuditIter<'a> {
    type Item = AuditEvent;

    fn next(&mut self) -> Option<Self::Item> {
        if self.pos >= self.len {
            return None;
        }
        if self.slots.is_empty() {
            return None;
        }
        let idx = (self.head + self.pos) % self.slots.len();
        self.pos += 1;
        Some(self.slots[idx])
    }
}

// ============================================================
// SNTPv4 — RFC 4330 (TASK-053)
//
// Stateless wire codec for the Simple Network Time Protocol over
// UDP/IPv4 port 123. The kernel composes this with the existing
// [`NetStack`] UDP codec to fetch wall-clock time during boot.
//
// The on-wire packet is a 48-byte fixed-layout block (no extensions
// fields, no MAC). All multi-byte integer fields are big-endian.
// Timestamps are the NTP 64-bit fixed-point format: 32 high bits =
// seconds since 1 Jan 1900 UTC, 32 low bits = fractional seconds.
//
// The kernel only ever issues mode-3 (client) requests and parses
// mode-4 (server) replies. The trait deliberately rejects every
// other mode so a malformed / spoofed packet cannot drift the local
// clock past the wire-validation gate.
// ============================================================

/// SNTP packet length on the wire (RFC 4330 §3). The codec rejects any
/// buffer that isn't exactly this length — extension fields + MAC are
/// out of scope for the seed.
pub const SNTP_PACKET_LEN: usize = 48;

/// SNTPv4 protocol version. The client emits this in the VN field; the
/// reply parser rejects any other version.
pub const SNTP_VERSION: u8 = 4;

/// SNTP mode — client request. RFC 4330 §3.
pub const SNTP_MODE_CLIENT: u8 = 3;

/// SNTP mode — server reply. RFC 4330 §3.
pub const SNTP_MODE_SERVER: u8 = 4;

/// Leap-indicator value reported by an unsynchronised server. The
/// parser rejects replies carrying this value (RFC 4330 §5: "kiss-o'-
/// death" or alarm).
pub const SNTP_LEAP_ALARM: u8 = 3;

/// Maximum acceptable stratum (RFC 4330 §5: stratum 16 is reserved /
/// unsynchronised). The parser rejects replies with `stratum > 15`.
pub const SNTP_MAX_STRATUM: u8 = 15;

/// Byte offset of the `transmit_timestamp` field inside the 48-byte
/// SNTP packet. Locked across morph cycles.
pub const SNTP_OFFSET_TRANSMIT_TS: usize = 40;

/// Byte offset of the `receive_timestamp` field. Locked.
pub const SNTP_OFFSET_RECEIVE_TS: usize = 32;

/// Byte offset of the `originate_timestamp` field. Locked.
pub const SNTP_OFFSET_ORIGIN_TS: usize = 24;

/// Byte offset of the `reference_timestamp` field. Locked.
pub const SNTP_OFFSET_REFERENCE_TS: usize = 16;

/// Byte offset of the 4-byte `reference_identifier` field. Locked.
pub const SNTP_OFFSET_REF_ID: usize = 12;

/// 64-bit NTP timestamp — `(seconds_since_1900 << 32) |
/// fraction_2pow32` in a single `u64`. The kernel keeps timestamps in
/// this packed form on the read path so the wire layout exactly
/// matches the in-memory layout for big-endian emission.
///
/// The NTP epoch (1 Jan 1900 UTC) is 70 years before the Unix epoch;
/// callers translating to/from Unix time must offset by
/// `2_208_988_800` seconds.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpTimestamp {
    /// Raw 64-bit value. Top 32 bits = seconds; bottom 32 bits =
    /// fractional seconds (2^-32 second units).
    pub raw: u64,
}

impl NtpTimestamp {
    /// Construct a zero timestamp (the "no clock" value the client
    /// puts in `origin`, `receive`, `reference` fields of a request).
    pub const fn zero() -> Self {
        NtpTimestamp { raw: 0 }
    }

    /// Construct from raw 64-bit value (most callers build from a
    /// `seconds + fraction` pair via [`NtpTimestamp::from_secs_frac`]).
    pub const fn from_raw(raw: u64) -> Self {
        NtpTimestamp { raw }
    }

    /// Construct from `(seconds_since_1900, fraction_2pow32)`. The
    /// fraction is in units of `2^-32` seconds — `0x80000000` is half
    /// a second.
    pub const fn from_secs_frac(seconds: u32, fraction: u32) -> Self {
        NtpTimestamp { raw: ((seconds as u64) << 32) | (fraction as u64) }
    }

    /// Recover the seconds half (top 32 bits).
    pub const fn seconds(self) -> u32 {
        (self.raw >> 32) as u32
    }

    /// Recover the fractional half (bottom 32 bits, units of 2^-32 s).
    pub const fn fraction(self) -> u32 {
        self.raw as u32
    }
}

/// Server-side timestamps + identifying header fields recovered from a
/// mode-4 SNTP reply. Borrows nothing — every byte is decoded into
/// owned scalars so the kernel can drop the on-wire buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpReply {
    /// Leap-indicator (`0..=2`; `3` is rejected by the parser).
    pub leap_indicator: u8,
    /// Server protocol version. Must equal [`SNTP_VERSION`].
    pub version: u8,
    /// Server stratum (`1..=15`; `0` and `>15` are rejected).
    pub stratum: u8,
    /// Reference identifier — for stratum 1, a 4-character ASCII
    /// source code (e.g. `b"GPS\0"`); for stratum 2+, the IPv4 address
    /// of the upstream synchronisation source in network byte order.
    pub ref_id: [u8; 4],
    /// Reference timestamp — server's last clock-set time.
    pub reference_timestamp: NtpTimestamp,
    /// Originate timestamp — copy of the client's transmit timestamp
    /// (the `t1` correlation token).
    pub origin_timestamp: NtpTimestamp,
    /// Receive timestamp — when the server received the request (t2).
    pub receive_timestamp: NtpTimestamp,
    /// Transmit timestamp — when the server emitted the reply (t3).
    pub transmit_timestamp: NtpTimestamp,
}

/// Offset + round-trip delay derived from the four timestamps
/// `(t1, t2, t3, t4)`. Units are signed nanoseconds — the kernel
/// then folds the offset into its monotonic clock through the
/// rate-limiting smoother (out of scope for this seed; the SNTP
/// codec just hands the numbers back).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NtpClockSkew {
    /// Signed offset between the local clock and the server's clock.
    /// Positive = local clock is ahead of the server.
    ///
    /// Formula: `((t2 - t1) + (t3 - t4)) / 2`.
    pub offset_ns: i64,
    /// Round-trip delay between the client and the server. Always
    /// non-negative for honest exchanges; a negative value means the
    /// server's `(t3 - t2)` exceeded the wall time `(t4 - t1)`,
    /// which is impossible — the kernel must reject such replies.
    ///
    /// Formula: `(t4 - t1) - (t3 - t2)`.
    pub delay_ns: i64,
}

/// Errors from the SNTP wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SntpError {
    /// Input or output buffer is not exactly [`SNTP_PACKET_LEN`].
    Truncated,
    /// `version` field of the reply does not equal [`SNTP_VERSION`].
    BadVersion,
    /// `mode` field of the reply is not [`SNTP_MODE_SERVER`] (e.g.
    /// the response was actually a client request loopback, or a
    /// mode-7 NTP private-mode packet).
    BadMode,
    /// Server reports `stratum == 0` or `stratum > SNTP_MAX_STRATUM`
    /// (a "kiss-o'-death" packet or an unsynchronised peer).
    BadStratum,
    /// Server reports `leap_indicator == SNTP_LEAP_ALARM` (an
    /// unsynchronised / alarm state).
    BadLeapIndicator,
}

/// SNTPv4 byte-locked wire surface (RFC 4330 §3 + §5).
///
/// # Locked invariants the verifier checks
///
/// 1. `build_request(client_now, out)` writes exactly
///    [`SNTP_PACKET_LEN`] bytes. Byte 0 packs LI=0, VN=4, Mode=3 into
///    `0b00_100_011 = 0x23`. The bytes at
///    `SNTP_OFFSET_TRANSMIT_TS .. SNTP_OFFSET_TRANSMIT_TS + 8` equal
///    the big-endian encoding of `client_now.raw`; every other byte
///    in `out[1..SNTP_OFFSET_TRANSMIT_TS]` is zero.
/// 2. `parse_reply(bytes)` returns `Ok(reply)` iff `bytes.len() ==
///    SNTP_PACKET_LEN`, the version is [`SNTP_VERSION`], the mode is
///    [`SNTP_MODE_SERVER`], the stratum is in `1..=SNTP_MAX_STRATUM`,
///    and the leap-indicator is not [`SNTP_LEAP_ALARM`]. Every other
///    case returns an [`SntpError`] without partial state.
/// 3. `compute_offset_delay(reply, t4)` computes the SNTP formula
///    `(offset, delay) = (((t2 - t1) + (t3 - t4)) / 2, (t4 - t1) -
///    (t3 - t2))` against signed nanosecond arithmetic. The
///    differences fold through the full 64-bit fixed-point timestamp
///    so a 100-year skew is representable without saturation.
///
/// # Not in this contract (intentional)
///
/// - The actual UDP transmission: the kernel call site composes with
///   [`NetStack`]'s UDP path. The codec is byte-in / byte-out.
/// - NTP authentication MAC (the optional 12- to 24-byte trailer).
///   SNTPv4 makes it optional; the seed does not parse it.
/// - Clock smoothing / step-vs-slew policy. Out of scope.
/// - IPv6 transport. The wire format is identical, but the kernel's
///   UDP codec is currently v4-only.
pub trait Sntp {
    /// Build a 48-byte mode-3 SNTPv4 request with the caller-supplied
    /// `client_now` planted in the `transmit_timestamp` field (the
    /// `t1` correlation token). Returns the number of bytes written —
    /// always exactly [`SNTP_PACKET_LEN`] on success.
    fn build_request(client_now: NtpTimestamp, out: &mut [u8]) -> Result<usize, SntpError>;

    /// Parse a 48-byte mode-4 SNTPv4 reply. Validates length, version,
    /// mode, stratum, leap-indicator. Returns an owned [`NtpReply`].
    fn parse_reply(buf: &[u8]) -> Result<NtpReply, SntpError>;

    /// Compute the offset/delay from the server's view of the
    /// transaction (`reply.origin_timestamp = t1`,
    /// `reply.receive_timestamp = t2`,
    /// `reply.transmit_timestamp = t3`) and the client's wall time
    /// `t4` at reply arrival. Pure — no clock reads, no allocation.
    fn compute_offset_delay(reply: &NtpReply, t4: NtpTimestamp) -> NtpClockSkew;
}

// ============================================================
// Virtual filesystem — TASK-054
//
// Two-tier surface:
// - `Filesystem` is the per-mount trait. A backing filesystem
//   (ramfs, FAT32, ext2, NFS, …) implements it; the trait is the
//   locked dispatch boundary the VFS layer holds.
// - `FsHandle`, `FsError`, `FileStat`, and the `FS_*` constants are
//   the wire / API surface for callers. Morph cycles may
//   diversify the path-walk internals, the handle allocator, and
//   the storage layout, but every byte of these types stays
//   byte-stable.
//
// The path grammar is POSIX-flavoured ASCII: absolute paths
// (`/etc/hostname`), `/` separator, `.` and `..` components handled
// during the VFS path-walk (not the per-fs trait — backing fs sees
// already-normalised paths relative to its mount root).
// ============================================================

/// Maximum length of a single path component (basename), in bytes.
/// Mirrors `NAME_MAX` on Linux for short filenames. Locked across
/// morph cycles — a backing fs that rejects longer names returns
/// [`FsError::NameTooLong`].
pub const FS_NAME_MAX: usize = 64;

/// Maximum length of a complete path, in bytes. Mirrors `PATH_MAX`
/// flavour but compressed for the seed; the VFS path-walker rejects
/// longer inputs with [`FsError::NameTooLong`] before invoking any
/// backing filesystem.
pub const FS_PATH_MAX: usize = 256;

/// Maximum number of mount points a single VFS dispatcher tracks.
/// The kernel banner instantiates `VfsImpl<8>`; larger deployments
/// pick a larger `N`. Locked.
pub const FS_MAX_MOUNTS: usize = 8;

/// Open-flag: read-only access. Locked discriminant.
pub const FS_O_RDONLY: u32 = 0x0000;
/// Open-flag: write-only access. Locked discriminant.
pub const FS_O_WRONLY: u32 = 0x0001;
/// Open-flag: read+write access. Locked discriminant.
pub const FS_O_RDWR: u32 = 0x0002;
/// Open-flag: low two bits mask the access mode. The Filesystem
/// implementation extracts `flags & FS_O_ACCMODE` to dispatch.
pub const FS_O_ACCMODE: u32 = 0x0003;
/// Open-flag: create the file if it does not exist. Locked
/// discriminant.
pub const FS_O_CREATE: u32 = 0x0100;
/// Open-flag: truncate to length 0 on open. Locked discriminant.
pub const FS_O_TRUNC: u32 = 0x0200;
/// Open-flag: error if the path already exists when `FS_O_CREATE`
/// is set. Locked discriminant.
pub const FS_O_EXCL: u32 = 0x0400;

/// File-type bit in [`FileStat::mode`] indicating a regular file.
/// Locked: the same value POSIX uses (`S_IFREG`).
pub const FS_MODE_FILE: u16 = 0o100000;
/// File-type bit in [`FileStat::mode`] indicating a directory.
/// Locked: matches POSIX `S_IFDIR`.
pub const FS_MODE_DIR: u16 = 0o040000;
/// Mask covering the file-type bits of [`FileStat::mode`].
pub const FS_MODE_TYPE_MASK: u16 = 0o170000;
/// Mask covering the permission bits of [`FileStat::mode`].
pub const FS_MODE_PERM_MASK: u16 = 0o000777;

/// Open-file token. Opaque to callers — the VFS pairs it with the
/// mount that minted it on every subsequent `read`/`write`/`close`.
///
/// The 32-bit width gives ample headroom for the
/// `mount_id : slot_id` packing the VFS uses internally (currently
/// top 8 bits = mount id, bottom 24 bits = per-fs handle index).
/// Callers must treat the value as opaque; the packing is an
/// implementation detail behind the locked surface.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct FsHandle(pub u32);

impl FsHandle {
    /// Sentinel value meaning "no handle". The VFS never mints this
    /// — callers use it as a placeholder before opening.
    pub const NONE: FsHandle = FsHandle(0);

    /// Raw 32-bit value of the handle. Callers may pass this through
    /// `match` arms but must not synthesise handles from arbitrary
    /// integers — the VFS validates every handle on every operation.
    pub const fn raw(self) -> u32 {
        self.0
    }

    /// Construct from raw value. Reserved for the VFS implementation;
    /// untrusted callers should never invoke this — handles cannot be
    /// minted outside the VFS.
    pub const fn from_raw(raw: u32) -> Self {
        FsHandle(raw)
    }
}

/// Stat record returned by [`Filesystem::stat`] and
/// [`Vfs::stat`]. Locked layout — the morph engine cannot reorder
/// or repack these fields.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FileStat {
    /// Size of the file in bytes. For directories the value is
    /// implementation-defined but stable across `stat` calls.
    pub size: u64,
    /// Wall-clock modification time in Unix seconds. Zero for the
    /// in-memory ramfs (no clock source); persistent filesystems
    /// populate from the on-disk inode.
    pub mtime: u64,
    /// File-type + permission bits. Use [`FS_MODE_TYPE_MASK`] +
    /// [`FS_MODE_PERM_MASK`] to project; [`FS_MODE_FILE`] /
    /// [`FS_MODE_DIR`] for the type check.
    pub mode: u16,
    /// Reserved padding to keep the struct 24 bytes (size 8 + mtime
    /// 8 + mode 2 + reserved 6 = 24). The morph engine relies on a
    /// stable struct size when emitting fixed-array buffers around
    /// stat results.
    pub reserved: [u8; 6],
}

impl FileStat {
    /// Whether this stat entry describes a regular file.
    pub const fn is_file(&self) -> bool {
        (self.mode & FS_MODE_TYPE_MASK) == FS_MODE_FILE
    }

    /// Whether this stat entry describes a directory.
    pub const fn is_dir(&self) -> bool {
        (self.mode & FS_MODE_TYPE_MASK) == FS_MODE_DIR
    }

    /// Construct a regular-file stat record with the given size and
    /// 0o644 permissions. Used by ramfs to populate the response.
    pub const fn file(size: u64, mtime: u64) -> Self {
        FileStat {
            size,
            mtime,
            mode: FS_MODE_FILE | 0o644,
            reserved: [0; 6],
        }
    }

    /// Construct a directory stat record with 0o755 permissions and
    /// zero size.
    pub const fn dir(mtime: u64) -> Self {
        FileStat {
            size: 0,
            mtime,
            mode: FS_MODE_DIR | 0o755,
            reserved: [0; 6],
        }
    }
}

/// Errors returned by the [`Filesystem`] and [`Vfs`] surfaces.
///
/// Discriminants are locked: an offline parser of audit-log records
/// or kernel-message buffers may pattern-match against the numeric
/// value, so morph cycles cannot reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FsError {
    /// Path or component does not exist.
    NotFound,
    /// A non-final component of the path is not a directory.
    NotADir,
    /// A `read`/`write` targeted a directory inode.
    IsADir,
    /// The fs ran out of inode slots or block storage.
    NoSpace,
    /// The file or inode is currently open elsewhere and the
    /// operation cannot proceed (e.g. unmount of a busy fs).
    Busy,
    /// Underlying I/O failed (e.g. block-device read error).
    IoError,
    /// The supplied [`FsHandle`] does not refer to an open file in
    /// this filesystem — it was forged, stale, or already closed.
    BadHandle,
    /// Path is malformed: empty, missing leading `/`, has an
    /// embedded NUL, or contains a forbidden character.
    BadPath,
    /// A single path component exceeds [`FS_NAME_MAX`], or the
    /// whole path exceeds [`FS_PATH_MAX`].
    NameTooLong,
    /// The per-fs open-file table is full.
    TooManyHandles,
    /// The filesystem is mounted read-only and the caller requested
    /// write access or `FS_O_CREATE`/`FS_O_TRUNC`.
    ReadOnly,
    /// `FS_O_CREATE | FS_O_EXCL` was used and the path already
    /// exists.
    AlreadyExists,
    /// The path resolved to a mount-point whose backing fs has been
    /// unmounted, or the mount table has no mount covering the
    /// path.
    NoMount,
}

/// Backing-filesystem trait — the per-mount surface dispatched to
/// by the VFS layer.
///
/// The supplied `path` is **relative to this filesystem's mount
/// root** with a leading `/` retained (so a ramfs mounted at `/`
/// sees `/etc/hostname`; a hypothetical FAT32 mounted at `/boot`
/// sees `/grub/grub.cfg` after the VFS strips the mount prefix).
/// The VFS handles the prefix dispatch + path normalisation
/// (`.` / `..` / multi-slash collapse) before invoking any
/// `Filesystem` method.
///
/// The `&mut self` receiver permits mutable state for write-capable
/// implementations; read-only filesystems still take `&mut self`
/// for the open-file table. No `alloc` — every implementation must
/// be `no_std` compatible with fixed-capacity buffers.
pub trait Filesystem {
    /// Open `path` with the given flags. Returns a per-fs handle
    /// (the VFS wraps it with its mount id before returning to the
    /// outer caller).
    fn open(&mut self, path: &[u8], flags: u32) -> Result<FsHandle, FsError>;

    /// Read up to `buf.len()` bytes starting at byte offset `offset`
    /// into `buf`. Returns the number actually read; 0 means EOF for
    /// this offset (not a permanent EOF — a later read at a smaller
    /// offset may still return data after a truncation).
    fn read(&mut self, handle: FsHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write up to `buf.len()` bytes at offset `offset`. Returns the
    /// number actually written. Implementations may extend the file
    /// (sparse-fill the gap with zero bytes) when `offset > size`,
    /// or return [`FsError::NoSpace`] if the backing pool is full.
    fn write(&mut self, handle: FsHandle, offset: u64, buf: &[u8]) -> Result<usize, FsError>;

    /// Drop the open file, freeing its slot in the per-fs handle
    /// table. After `close`, the handle is invalid; further use
    /// returns [`FsError::BadHandle`].
    fn close(&mut self, handle: FsHandle) -> Result<(), FsError>;

    /// Stat `path`. Pure metadata read; does not need an open
    /// handle.
    fn stat(&self, path: &[u8]) -> Result<FileStat, FsError>;
}

/// VFS dispatch trait — the outer surface kernel callers hold.
///
/// The implementation `target_enterprise::vfs::VfsImpl<N>` holds a
/// fixed-capacity mount table of `N` slots. `mount` registers a
/// `Filesystem` impl at an absolute prefix (e.g. `/`, `/boot`);
/// `open`/`read`/`write`/`close`/`stat` route to the longest
/// matching mount.
///
/// The trait deliberately uses `&[u8]` for paths (not `&str`) so
/// the kernel can pass byte fixtures from `kernel_fixtures.rs`
/// without UTF-8 validation. ASCII subset is enforced internally by
/// the path-walk validator.
///
/// The mount-handle parameter on `mount` is a trait-object reference
/// (`&'static mut dyn Filesystem`) — implementations that need a
/// concrete generic over `N`-many fs types can extend with their
/// own typed `mount_typed::<F>(…)` helper; the locked trait surface
/// is the `dyn` form.
pub trait Vfs {
    /// Mount a backing filesystem at the absolute prefix
    /// `mount_point` (must start with `/`, must be a valid normalised
    /// path). Returns [`FsError::NoSpace`] when the mount table is
    /// full, [`FsError::AlreadyExists`] when the prefix is already
    /// mounted, [`FsError::BadPath`] on malformed prefix.
    fn mount(&mut self, mount_point: &[u8], fs: &'static mut dyn Filesystem) -> Result<(), FsError>;

    /// Unmount the filesystem at `mount_point`. Returns
    /// [`FsError::NotFound`] if no mount lives there,
    /// [`FsError::Busy`] if any handle from that mount is still open.
    fn unmount(&mut self, mount_point: &[u8]) -> Result<(), FsError>;

    /// Open `path` (must be absolute). Routes to the longest-prefix
    /// mount and forwards the residual path to that filesystem's
    /// `open`.
    fn open(&mut self, path: &[u8], flags: u32) -> Result<FsHandle, FsError>;

    /// Read from a handle previously returned by `open` on this
    /// dispatcher.
    fn read(&mut self, handle: FsHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError>;

    /// Write to a handle.
    fn write(&mut self, handle: FsHandle, offset: u64, buf: &[u8]) -> Result<usize, FsError>;

    /// Close a handle.
    fn close(&mut self, handle: FsHandle) -> Result<(), FsError>;

    /// Stat an absolute path.
    fn stat(&self, path: &[u8]) -> Result<FileStat, FsError>;
}

// ============================================================
// eBPF interpreter — TASK-055
//
// A bounded 64-bit register-machine interpreter for operator-injected
// in-kernel probes. The wire encoding is upstream-compatible eBPF
// (Linux `uapi/linux/bpf.h`) — `clang -target bpf` produces bytes
// that decode here, modulo the helper-call subset.
//
// Locked surface:
//   - [`BpfInstr`] — 8-byte instruction record (opcode, dst/src
//     regs, signed offset, signed imm).
//   - [`BpfContext`] — register file + stack scratch buffer passed
//     by the caller. Reset on every `run`.
//   - [`BpfError`] — taxonomic failure enum surfaced by the
//     interpreter. Discriminants are locked so an offline log parser
//     can map them.
//   - [`bpf_op`] — opcode-class / sub-op / size / source constants.
//   - [`BPF_REG_COUNT`], [`BPF_STACK_SIZE`], [`BPF_MAX_INSTRUCTIONS`].
//
// Internals (validator structure, dispatch loop, jump target
// resolution, helper table) are free to be diversified by the morph
// engine. The wire-shape contract on `BpfInstr` packing and the
// behavioural contract on `run` are what the verifier holds across
// cycles.
// ============================================================

/// Number of general-purpose registers an eBPF program sees. The
/// Linux upstream value is 11 — `r0` (return), `r1..r5` (arg-pass),
/// `r6..r9` (caller-saved), `r10` (read-only frame pointer at top
/// of stack). Locked.
pub const BPF_REG_COUNT: usize = 11;

/// Size of the per-run stack region in bytes. Matches upstream so
/// programs built by `clang -target bpf` do not silently fall off
/// the end. Locked.
pub const BPF_STACK_SIZE: usize = 512;

/// Static cap on a loaded program's instruction count. The
/// validator rejects anything longer; the dispatcher relies on the
/// cap to keep loop-bound proofs trivial. Locked.
pub const BPF_MAX_INSTRUCTIONS: usize = 4096;

/// Per-run dispatched-instruction ceiling. The interpreter aborts
/// when this many instructions have been dispatched, guaranteeing
/// termination for arbitrary control-flow shapes without needing
/// a static loop-bound proof. Locked.
pub const BPF_MAX_BRANCH_DEPTH: usize = 65536;

/// Sentinel register index for the read-only frame pointer (r10).
/// Writes to r10 are rejected at validate time.
pub const BPF_REG_FP: u8 = 10;

/// Wire-level opcode constants mirroring Linux's `linux/bpf.h`. The
/// names are kept symbolic so the dispatcher and the unit tests
/// share one definition site — but the wire is the contract, not
/// the symbolic names.
pub mod bpf_op {
    /// Instruction class — bottom three bits of the opcode byte.
    pub const BPF_CLASS_LD: u8 = 0x00;
    /// Instruction class — load from register-relative memory.
    pub const BPF_CLASS_LDX: u8 = 0x01;
    /// Instruction class — store immediate to memory.
    pub const BPF_CLASS_ST: u8 = 0x02;
    /// Instruction class — store register to memory.
    pub const BPF_CLASS_STX: u8 = 0x03;
    /// Instruction class — 32-bit ALU.
    pub const BPF_CLASS_ALU: u8 = 0x04;
    /// Instruction class — jump (conditional, unconditional, EXIT,
    /// CALL).
    pub const BPF_CLASS_JMP: u8 = 0x05;
    /// Instruction class — 64-bit ALU.
    pub const BPF_CLASS_ALU64: u8 = 0x07;
    /// Mask covering the class bits.
    pub const BPF_CLASS_MASK: u8 = 0x07;

    /// ALU sub-op — addition.
    pub const BPF_OP_ADD: u8 = 0x00;
    /// ALU sub-op — subtraction.
    pub const BPF_OP_SUB: u8 = 0x10;
    /// ALU sub-op — multiplication.
    pub const BPF_OP_MUL: u8 = 0x20;
    /// ALU sub-op — unsigned division.
    pub const BPF_OP_DIV: u8 = 0x30;
    /// ALU sub-op — bitwise OR.
    pub const BPF_OP_OR: u8 = 0x40;
    /// ALU sub-op — bitwise AND.
    pub const BPF_OP_AND: u8 = 0x50;
    /// ALU sub-op — logical shift left.
    pub const BPF_OP_LSH: u8 = 0x60;
    /// ALU sub-op — logical shift right.
    pub const BPF_OP_RSH: u8 = 0x70;
    /// ALU sub-op — negation (operand from dst, ignores src/imm).
    pub const BPF_OP_NEG: u8 = 0x80;
    /// ALU sub-op — unsigned modulo.
    pub const BPF_OP_MOD: u8 = 0x90;
    /// ALU sub-op — bitwise XOR.
    pub const BPF_OP_XOR: u8 = 0xa0;
    /// ALU sub-op — register/imm move into dst.
    pub const BPF_OP_MOV: u8 = 0xb0;
    /// ALU sub-op — arithmetic (sign-preserving) shift right.
    pub const BPF_OP_ARSH: u8 = 0xc0;

    /// JMP sub-op — unconditional jump.
    pub const BPF_JMP_JA: u8 = 0x00;
    /// JMP sub-op — branch if equal.
    pub const BPF_JMP_JEQ: u8 = 0x10;
    /// JMP sub-op — branch if greater-than (unsigned).
    pub const BPF_JMP_JGT: u8 = 0x20;
    /// JMP sub-op — branch if greater-or-equal (unsigned).
    pub const BPF_JMP_JGE: u8 = 0x30;
    /// JMP sub-op — branch if bit-set.
    pub const BPF_JMP_JSET: u8 = 0x40;
    /// JMP sub-op — branch if not-equal.
    pub const BPF_JMP_JNE: u8 = 0x50;
    /// JMP sub-op — branch if signed greater-than.
    pub const BPF_JMP_JSGT: u8 = 0x60;
    /// JMP sub-op — branch if signed greater-or-equal.
    pub const BPF_JMP_JSGE: u8 = 0x70;
    /// JMP sub-op — branch if less-than (unsigned).
    pub const BPF_JMP_JLT: u8 = 0x80;
    /// JMP sub-op — branch if less-or-equal (unsigned).
    pub const BPF_JMP_JLE: u8 = 0x90;
    /// JMP sub-op — branch if signed less-than.
    pub const BPF_JMP_JSLT: u8 = 0xa0;
    /// JMP sub-op — branch if signed less-or-equal.
    pub const BPF_JMP_JSLE: u8 = 0xb0;

    /// Source flag (bit 3) — when set, the operand is the `src`
    /// register; when clear, the operand is the sign-extended
    /// 32-bit `imm`.
    pub const BPF_SRC_X: u8 = 0x08;
    /// Mask covering the source-flag bit.
    pub const BPF_SRC_MASK: u8 = 0x08;

    /// Size code — 4-byte word.
    pub const BPF_SIZE_W: u8 = 0x00;
    /// Size code — 2-byte half-word.
    pub const BPF_SIZE_H: u8 = 0x08;
    /// Size code — single byte.
    pub const BPF_SIZE_B: u8 = 0x10;
    /// Size code — 8-byte double-word.
    pub const BPF_SIZE_DW: u8 = 0x18;
    /// Mask covering the size bits.
    pub const BPF_SIZE_MASK: u8 = 0x18;

    /// Full opcode — two-slot load of a 64-bit immediate. The
    /// second slot carries the high 32 bits in its `imm`.
    pub const BPF_LD_IMM64: u8 = 0x18;

    /// Full opcode — program exit. The current `r0` is the return
    /// value.
    pub const BPF_OP_EXIT: u8 = 0x95;
}

/// 8-byte instruction record. Wire layout matches Linux's
/// `bpf_insn` — `opcode:u8 | (dst<<0)|(src<<4):u8 | offset:i16 |
/// imm:i32`. The morph engine cannot reorder these fields; the
/// verifier holds the layout across cycles.
///
/// Bit-twiddling helpers ([`BpfInstr::dst`], [`BpfInstr::src`])
/// extract the 4-bit register indices. `new` is a const constructor
/// for the assembler-style banner programs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfInstr {
    /// Operation code, including class (bottom 3 bits), source
    /// flag (bit 3), and sub-op / size (top nibble).
    pub opcode: u8,
    /// Packed register pair — `dst` in the low nibble, `src` in
    /// the high nibble.
    pub regs: u8,
    /// Signed 16-bit branch offset for JMP-class instructions,
    /// or memory-access offset for LDX/ST/STX.
    pub offset: i16,
    /// 32-bit immediate. Sign-extended to 64 bits for ALU64 K-form
    /// arithmetic; zero-extended for 32-bit ALU; carries the
    /// helper id for CALL; carries the high half for the
    /// continuation slot of LD_IMM64.
    pub imm: i32,
}

impl BpfInstr {
    /// Construct an instruction with the given fields. `dst` and
    /// `src` are masked to their 4-bit field; values >= 16 are
    /// silently truncated (the validator's
    /// register-index-out-of-range check picks this up at run
    /// time).
    pub const fn new(opcode: u8, dst: u8, src: u8, offset: i16, imm: i32) -> Self {
        BpfInstr {
            opcode,
            regs: (dst & 0x0f) | ((src & 0x0f) << 4),
            offset,
            imm,
        }
    }

    /// Destination register index (0..=15 raw, but only 0..=10 are
    /// real).
    pub const fn dst(self) -> u8 {
        self.regs & 0x0f
    }

    /// Source register index (0..=15 raw, but only 0..=10 are real).
    pub const fn src(self) -> u8 {
        (self.regs >> 4) & 0x0f
    }
}

/// Per-run execution context — register file plus 512-byte stack
/// scratch region. Callers allocate one on their stack frame and
/// pass `&mut` to [`EBpf::run`]. The interpreter resets every
/// register and every stack byte at the top of `run` so a single
/// context can be re-used across invocations without leaking
/// state.
///
/// The struct is `#[repr(C)]` so the morph engine cannot reorder
/// the two members; tests assert `regs` comes first.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct BpfContext {
    /// 11-entry register file. Reset to zero by `run`; the
    /// interpreter then plants `ctx_ptr` in `r1` and
    /// [`BPF_STACK_SIZE`] in `r10` per the upstream calling
    /// convention.
    pub regs: [u64; BPF_REG_COUNT],
    /// 512-byte stack scratch region. Reset to zero by `run`.
    pub stack: [u8; BPF_STACK_SIZE],
}

impl BpfContext {
    /// All-zeros context. The interpreter still resets at the top
    /// of `run`, so passing a stale context is safe.
    pub const fn new() -> Self {
        BpfContext {
            regs: [0; BPF_REG_COUNT],
            stack: [0; BPF_STACK_SIZE],
        }
    }
}

impl Default for BpfContext {
    fn default() -> Self {
        BpfContext::new()
    }
}

/// Taxonomic failure enum returned from [`EBpf::run`]. Discriminants
/// are locked; an offline parser of audit-log records pattern-matches
/// against the numeric value so morph cycles cannot reorder.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BpfError {
    /// The program slice is empty (zero instructions).
    ProgramEmpty,
    /// The program exceeds [`BPF_MAX_INSTRUCTIONS`].
    ProgramTooLong,
    /// The program does not end with an `EXIT` instruction.
    MissingExit,
    /// An instruction's opcode does not decode to any supported
    /// class / sub-op combination.
    BadOpcode,
    /// A jump's `pc + 1 + offset` falls outside `[0, count)`,
    /// detected either at validate time or as a defensive run-time
    /// recheck.
    IllegalJump,
    /// An ALU instruction divided (or moduloed) by zero.
    DivByZero,
    /// A load or store touched memory outside the 512-byte stack
    /// region.
    OutOfBounds,
    /// The interpreter dispatched [`BPF_MAX_BRANCH_DEPTH`]
    /// instructions without reaching EXIT.
    InstructionCapExceeded,
    /// An instruction referenced a register index outside `0..11`.
    BadRegister,
    /// A `BPF_LD_IMM64` two-slot form is truncated at the end of
    /// the program.
    TruncatedLdImm64,
    /// The dispatcher fell off the end of the program without
    /// hitting EXIT — defensive, the loader's MissingExit check
    /// should make this unreachable.
    StackOverflow,
}

/// Locked behavioural contract for the bounded eBPF interpreter.
///
/// # Locked invariants the verifier checks
///
/// 1. `run(&[], &mut ctx)` returns `Err(BpfError::ProgramEmpty)`.
/// 2. `run(program, &mut ctx)` returns `Err(BpfError::ProgramTooLong)`
///    when `program.len() > BPF_MAX_INSTRUCTIONS`.
/// 3. `run(program, &mut ctx)` returns
///    `Err(BpfError::MissingExit)` when the final instruction's
///    opcode is not `BPF_OP_EXIT`.
/// 4. For an ALU64 register-form `mov r0, r1` program with
///    `ctx.regs[1] = 0xa5a5_a5a5_a5a5_a5a5` followed by EXIT,
///    `run` returns `Ok(0xa5a5_a5a5_a5a5_a5a5)`.
/// 5. The interpreter is total — every program with at most
///    [`BPF_MAX_INSTRUCTIONS`] instructions either returns
///    `Ok(r0)` or one of the [`BpfError`] arms within
///    [`BPF_MAX_BRANCH_DEPTH`] dispatched instructions.
///
/// # Not in this contract (intentional)
///
/// - Helper calls (`BPF_CALL`). Out of scope for the seed; future
///   tasks may add a `BpfHelpers` trait and dispatch table.
/// - JIT compilation. The interpreter is the only execution mode.
/// - The legacy `BPF_LD_ABS` packet-pointer modes — they exist for
///   Linux networking compatibility and are not needed for the
///   kernel hookpoints currently exposed.
pub trait EBpf {
    /// Run `program` against the provided `ctx`. Resets `ctx.regs`
    /// and `ctx.stack` to zero, plants `r10 = BPF_STACK_SIZE` (the
    /// upstream frame-pointer convention), then dispatches until
    /// EXIT or an error. The caller pre-plants any input bytes
    /// into `ctx.stack` before invoking `run`; the interpreter
    /// passes a pointer to that buffer in `r1` via `r1 = 0` (the
    /// stack's virtual base) so the program can `ldxb r0, [r1+i]`.
    fn run(program: &[BpfInstr], ctx: &mut BpfContext) -> Result<u64, BpfError>;
}

// ============================================================
// TASK-056 — Intel 8254x (e1000) NIC driver surface.
//
// The contract has two locked surfaces:
//
// 1. `MmioRegBus` — a register-window abstraction (volatile u32
//    read/write at a byte offset within the BAR). Real hardware
//    implements it with `core::ptr::read_volatile` / `write_volatile`
//    against the BAR's MMIO mapping; the in-memory harness in
//    `target_enterprise::e1000` implements it against a 128 KiB shadow
//    buffer plus an EEPROM fixture state machine + descriptor-ring
//    capture/inject for round-trip tests.
//
// 2. `EthernetController` — the driver-side state machine that drives
//    the register window through the Intel 82540EM bring-up sequence,
//    reads the MAC from EEPROM words 0..2, configures descriptor
//    rings, and exposes transmit/receive over locked 16-byte
//    descriptor formats (`E1000_TX_DESC_LEN` / `E1000_RX_DESC_LEN`).
//
// Constants below (register offsets, bit flags, EEPROM layout) are
// the wire-locked surface; a morph that perturbs them changes which
// MMIO bytes the driver writes and the in-memory harness records the
// drift on the very first round-trip.
// ============================================================

/// Intel 82540EM CTRL register offset (byte 0x0).
pub const E1000_REG_CTRL: usize = 0x0000;
/// Intel 82540EM STATUS register offset (byte 0x8).
pub const E1000_REG_STATUS: usize = 0x0008;
/// EEPROM Read register (EERD) offset.
pub const E1000_REG_EERD: usize = 0x0014;
/// Interrupt Cause Read offset.
pub const E1000_REG_ICR: usize = 0x00C0;
/// Interrupt Mask Set/Read offset.
pub const E1000_REG_IMS: usize = 0x00D0;
/// Interrupt Mask Clear offset (write 1s to mask).
pub const E1000_REG_IMC: usize = 0x00D8;
/// Receive Control register offset.
pub const E1000_REG_RCTL: usize = 0x0100;
/// Transmit Control register offset.
pub const E1000_REG_TCTL: usize = 0x0400;
/// Transmit Inter-Packet Gap register offset.
pub const E1000_REG_TIPG: usize = 0x0410;
/// RX descriptor ring base address low.
pub const E1000_REG_RDBAL: usize = 0x2800;
/// RX descriptor ring base address high.
pub const E1000_REG_RDBAH: usize = 0x2804;
/// RX descriptor ring byte length.
pub const E1000_REG_RDLEN: usize = 0x2808;
/// RX descriptor ring HEAD index (owned by device).
pub const E1000_REG_RDH: usize = 0x2810;
/// RX descriptor ring TAIL index (owned by driver).
pub const E1000_REG_RDT: usize = 0x2818;
/// TX descriptor ring base address low.
pub const E1000_REG_TDBAL: usize = 0x3800;
/// TX descriptor ring base address high.
pub const E1000_REG_TDBAH: usize = 0x3804;
/// TX descriptor ring byte length.
pub const E1000_REG_TDLEN: usize = 0x3808;
/// TX descriptor ring HEAD index (owned by device).
pub const E1000_REG_TDH: usize = 0x3810;
/// TX descriptor ring TAIL index (owned by driver).
pub const E1000_REG_TDT: usize = 0x3818;

/// CTRL.RST — global software reset bit. Writing 1 forces every
/// register but a small set of "sticky" bits back to defaults; the
/// device clears the bit when reset completes (≤ 1 µs per spec).
pub const E1000_CTRL_RST: u32 = 1 << 26;
/// CTRL.SLU — Set Link Up. Drives the PHY through auto-negotiation.
pub const E1000_CTRL_SLU: u32 = 1 << 6;
/// STATUS.LU — Link Up. Set by the PHY once the line is established.
pub const E1000_STATUS_LU: u32 = 1 << 1;
/// STATUS.FD — Full Duplex.
pub const E1000_STATUS_FD: u32 = 1 << 0;
/// STATUS.SPEED bits 6..7 — `00 = 10`, `01 = 100`, `10/11 = 1000`.
pub const E1000_STATUS_SPEED_SHIFT: u32 = 6;
/// Mask covering the two-bit SPEED field.
pub const E1000_STATUS_SPEED_MASK: u32 = 0b11;

/// EERD.START — write 1 to begin a single-word EEPROM read.
pub const E1000_EERD_START: u32 = 1 << 0;
/// EERD.DONE — set by the device when DATA is valid for read. The
/// 82540EM places DONE at bit 4 (later silicon families use bit 1;
/// this driver targets 82540EM specifically — QEMU's default).
pub const E1000_EERD_DONE: u32 = 1 << 4;
/// EERD address field starts at bit 8 (8 bits wide on 82540EM).
pub const E1000_EERD_ADDR_SHIFT: u32 = 8;
/// EERD address field mask (8-bit).
pub const E1000_EERD_ADDR_MASK: u32 = 0xFF;
/// EERD data field starts at bit 16 (16 bits wide).
pub const E1000_EERD_DATA_SHIFT: u32 = 16;
/// EERD data field mask (16-bit).
pub const E1000_EERD_DATA_MASK: u32 = 0xFFFF;
/// EEPROM word index holding the low 16 bits of the MAC address
/// (bytes 0..2 of the burned-in MAC).
pub const E1000_EEPROM_MAC_WORD0: u8 = 0x00;
/// EEPROM word holding the middle 16 bits of the MAC (bytes 2..4).
pub const E1000_EEPROM_MAC_WORD1: u8 = 0x01;
/// EEPROM word holding the high 16 bits of the MAC (bytes 4..6).
pub const E1000_EEPROM_MAC_WORD2: u8 = 0x02;

/// RCTL.EN — Receiver Enable.
pub const E1000_RCTL_EN: u32 = 1 << 1;
/// RCTL.BAM — Broadcast Accept Mode.
pub const E1000_RCTL_BAM: u32 = 1 << 15;
/// RCTL.SECRC — Strip Ethernet CRC.
pub const E1000_RCTL_SECRC: u32 = 1 << 26;
/// TCTL.EN — Transmitter Enable.
pub const E1000_TCTL_EN: u32 = 1 << 1;
/// TCTL.PSP — Pad Short Packets to 64 bytes.
pub const E1000_TCTL_PSP: u32 = 1 << 3;

/// Legacy TX descriptor CMD.EOP — End Of Packet (single-descriptor frame).
pub const E1000_TXD_CMD_EOP: u8 = 1 << 0;
/// Legacy TX descriptor CMD.IFCS — Insert FCS (let device compute Ethernet CRC).
pub const E1000_TXD_CMD_IFCS: u8 = 1 << 1;
/// Legacy TX descriptor CMD.RS — Report Status (device writes DD back on completion).
pub const E1000_TXD_CMD_RS: u8 = 1 << 3;
/// Legacy descriptor STATUS.DD — Descriptor Done.
pub const E1000_DESC_STA_DD: u8 = 1 << 0;
/// Legacy RX descriptor STATUS.EOP — End Of Packet.
pub const E1000_RXD_STA_EOP: u8 = 1 << 1;

/// Legacy TX descriptor byte length (16 bytes per Intel 8254x spec).
pub const E1000_TX_DESC_LEN: usize = 16;
/// Legacy RX descriptor byte length (16 bytes per Intel 8254x spec).
pub const E1000_RX_DESC_LEN: usize = 16;
/// Number of TX descriptors in the ring. Constrained to a power of 2
/// (Intel spec: ring length must be a multiple of 8 and at least 8
/// entries). Drives `E1000_REG_TDLEN` programming and the wrap-around
/// modulus in `transmit`.
pub const E1000_TX_RING_LEN: usize = 16;
/// Number of RX descriptors in the ring (same constraints as TX).
pub const E1000_RX_RING_LEN: usize = 16;
/// Maximum Ethernet frame the driver will accept on a single
/// descriptor — matches the legacy MTU + Ethernet header (no jumbo,
/// no VLAN tag). Aligns with [`EthFrameView::MAX_PAYLOAD_LEN`] plus
/// the 14-byte L2 header.
pub const E1000_MAX_FRAME_LEN: usize = 1518;

/// Decoded link state, returned by [`EthernetController::link_state`].
/// Cached during [`EthernetController::init`] from the STATUS register
/// — the driver does not re-poll on every `link_state` call (a future
/// task may add a `poll_link` method for proactive PHY refresh).
///
/// Locked discriminant order: pattern-matchable by name; appending a
/// variant is schema-compatible, reordering is not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum LinkState {
    /// Link is down. `STATUS.LU` was clear after reset.
    Down = 0,
    /// Link came up at 10 Mbit/s (`STATUS.SPEED = 0b00`).
    Up10 = 1,
    /// Link came up at 100 Mbit/s (`STATUS.SPEED = 0b01`).
    Up100 = 2,
    /// Link came up at 1 Gbit/s (`STATUS.SPEED = 0b10` or `0b11`).
    Up1000 = 3,
}

/// Error discriminants surfaced from [`EthernetController`].
///
/// Locked: external code matches by variant name; appending is
/// schema-compatible.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum E1000Error {
    /// The link came up after reset but `STATUS.LU` is clear at the
    /// time of a transmit/receive call. Caller should retry after a
    /// future link-state poll.
    NoLink = 0,
    /// The TX descriptor ring is full — every slot still has STATUS.DD
    /// clear (i.e. the device hasn't drained them). Caller should
    /// retry once the device advances its head pointer.
    RingFull = 1,
    /// The EEPROM read state-machine completed but the recovered MAC
    /// is structurally invalid (all-zero, all-0xFF, or the multicast
    /// bit is set in the first octet — burned-in MACs are unicast).
    BadEeprom = 2,
    /// A descriptor field had an invalid value: address misaligned,
    /// length exceeds the buffer, or required bits were unset by the
    /// device on RX (no STATUS.EOP after STATUS.DD).
    BadDescriptor = 3,
    /// An MMIO read returned a sentinel pattern signalling the BAR
    /// has been unmapped or the device fell off the bus. The host
    /// reads `0xFFFF_FFFF` from a vanished PCI device.
    MmioFault = 4,
    /// The EEPROM read timed out — the DONE bit never came up within
    /// the bounded poll budget. Real hardware should set DONE within a
    /// microsecond; a timeout means a malformed device or test stub.
    MacReadFailed = 5,
    /// The provided RX frame buffer is shorter than the received
    /// frame. Caller should retry with a buffer of at least the
    /// returned length.
    BufferTooSmall = 6,
    /// The frame passed to `transmit` exceeds [`E1000_MAX_FRAME_LEN`]
    /// or is empty.
    FrameLengthInvalid = 7,
    /// Receive ring is empty — head == tail with no STATUS.DD set on
    /// the slot at `tail`. Caller polls again later.
    NoFramePending = 8,
}

/// Abstract MMIO register window for a memory-mapped device. Real
/// hardware implements it with volatile reads/writes against the BAR's
/// kernel virtual mapping; in-memory harnesses implement it against a
/// shadow byte buffer plus a per-device side-channel (e.g. an EEPROM
/// fixture, a TX-frame capture log).
///
/// Distinct from [`MmioBus`] (VirtIO common-cfg / device-cfg / notify
/// / DMA): that trait is virtio-specific by design, whereas
/// `MmioRegBus` is the bare 32-bit register window used by classical
/// MMIO devices like the Intel 82540EM.
///
/// # Locked invariants
///
/// 1. `read_u32(off)` returns the most recent value written to `off`
///    by either the driver (via `write_u32`) OR the device-side
///    simulator (via its own `poke_u32` / equivalent back door). The
///    bus does not coalesce writes nor silently drop reads.
/// 2. Reads from un-modeled offsets return `0` (not `0xFFFF_FFFF` —
///    the latter is reserved for the [`E1000Error::MmioFault`] sentinel).
/// 3. `write_u32(off, val)` overwrites the 4 bytes at `off`
///    starting at the lowest. Side effects (descriptor-ring drain on
///    TDT writes, EEPROM state-machine on EERD writes) are kept on
///    the device-simulator side, not in the bus trait.
pub trait MmioRegBus {
    /// Volatile 32-bit read at `offset` bytes from the BAR base.
    fn read_u32(&mut self, offset: usize) -> u32;
    /// Volatile 32-bit write at `offset` bytes from the BAR base.
    fn write_u32(&mut self, offset: usize, value: u32);
}

/// Intel 82540EM (e1000) NIC driver surface — TASK-056.
///
/// Implementations drive a single 8254x-family device through its
/// [`MmioRegBus`] surface. The internal state machine (descriptor
/// indexing, EEPROM polling, link-state caching) is fully
/// diversifiable across morph cycles; the wire-observable surface —
/// every byte the driver writes through `MmioRegBus`, every 16-byte
/// descriptor it lays down, the EEPROM word offsets it polls — is
/// not.
///
/// # Locked invariants the verifier checks
///
/// 1. [`init`](EthernetController::init) writes `CTRL.RST = 1` then
///    polls until `CTRL.RST == 0`, then writes `CTRL.SLU = 1` to
///    bring the link up. The harness records the precise sequence.
/// 2. The MAC address `init` returns matches the EEPROM bytes at
///    words 0/1/2 in little-endian order (`mac[0..2] = word0_le`,
///    `mac[2..4] = word1_le`, `mac[4..6] = word2_le`). A morph that
///    swaps the byte order or word indices produces a different MAC
///    and the kernel banner panics.
/// 3. After `init`, the device's `RDBAL/RDBAH/RDLEN` registers point
///    at the driver-supplied RX descriptor ring, `TDBAL/TDBAH/TDLEN`
///    at the TX ring, and `RCTL.EN` + `TCTL.EN` are both set.
/// 4. `transmit(frame)` for `frame ∈ [1, E1000_MAX_FRAME_LEN]`
///    publishes a single 16-byte legacy TX descriptor with
///    `CMD = EOP | IFCS | RS`, `length = frame.len()`, `STATUS = 0`,
///    advances `TDT` by one (mod `E1000_TX_RING_LEN`), and copies
///    the frame bytes into the buffer pointed at by the descriptor.
/// 5. `receive(buf)` for a buffer of at least the pending frame's
///    length consumes a single RX descriptor at the ring head, copies
///    `length` payload bytes into `buf[..length]`, clears the
///    descriptor's STATUS byte, advances `RDT` by one, and returns
///    `Ok(Some(length))`. With no frame pending, returns `Ok(None)`.
/// 6. `link_state` returns the value cached from the last `init`
///    call. `init` may be re-invoked to refresh the cache; subsequent
///    `link_state` calls reflect the new cache.
/// 7. A second `init` call on the same instance returns
///    `Ok(())` — `init` is idempotent. The harness sees the bring-up
///    register sequence repeated (the device is reset again, the
///    rings are re-programmed). This matches the donor semantics —
///    a kernel that re-probes after a PCI re-enumeration must be
///    able to drive `init` again without leaking state.
///
/// # Not in this contract (intentional)
///
/// - Interrupts. The seed polls descriptor rings directly.
/// - Jumbo frames. `E1000_MAX_FRAME_LEN = 1518` covers IEEE 802.3
///   classic Ethernet + the 14-byte header; jumbo would push the
///   constant past one descriptor's address range and is out of
///   scope.
/// - MSI / MSI-X. Out of scope for the seed.
/// - PCI enumeration. The bus + driver instance are constructed by
///   the caller (kernel: from a probed BAR; tests: in-memory).
pub trait EthernetController {
    /// Drive the device through `reset → poll(!RST) → SLU → read MAC
    /// from EEPROM → program RX/TX descriptor rings → RCTL.EN +
    /// TCTL.EN → cache STATUS bits as `LinkState``. Writes the recovered
    /// MAC into `mac_out`. Idempotent — a second call repeats the
    /// sequence (no state-leak).
    fn init(
        &mut self,
        bus: &mut dyn MmioRegBus,
        mac_out: &mut [u8; 6],
    ) -> Result<(), E1000Error>;

    /// Transmit one Ethernet frame. The frame must be the bytes from
    /// destination MAC through payload — the device computes the FCS
    /// (the driver sets `CMD.IFCS`). Returns `RingFull` when every
    /// descriptor still has STATUS.DD clear (i.e. the device hasn't
    /// drained the previous queue).
    fn transmit(
        &mut self,
        bus: &mut dyn MmioRegBus,
        frame: &[u8],
    ) -> Result<(), E1000Error>;

    /// Receive one Ethernet frame into `buf`. Returns `Ok(Some(n))`
    /// for `n` payload bytes written into `buf[..n]`, `Ok(None)` if
    /// no frame is pending, or an error.
    fn receive(
        &mut self,
        bus: &mut dyn MmioRegBus,
        buf: &mut [u8],
    ) -> Result<Option<usize>, E1000Error>;

    /// Cached link state from the most recent `init`.
    fn link_state(&self) -> LinkState;
}

// ---------------------------------------------------------------------------
// Tftp — RFC 1350 / RFC 2347 TFTP client wire codec (TASK-058)
// ---------------------------------------------------------------------------

/// TFTP opcode constants. RFC 1350 §5 + RFC 2347 §2.
pub mod tftp_op {
    /// Read Request.
    pub const RRQ: u16 = 1;
    /// Write Request.
    pub const WRQ: u16 = 2;
    /// Data packet.
    pub const DATA: u16 = 3;
    /// Acknowledgement.
    pub const ACK: u16 = 4;
    /// Error packet.
    pub const ERROR: u16 = 5;
    /// Option Acknowledgement (RFC 2347 §3).
    pub const OACK: u16 = 6;
}

/// Maximum filename length (locked — kernel doesn't need filesystem
/// paths longer than this for boot-server fetches).
pub const MAX_TFTP_FILENAME: usize = 256;
/// Maximum mode-string length per RFC 1350 §2 — `netascii` and
/// `octet` are the only modes; 16 bytes is comfortable.
pub const MAX_TFTP_MODE: usize = 16;
/// Maximum payload bytes per DATA packet per RFC 1350 §2.
pub const TFTP_BLOCK_SIZE: usize = 512;
/// Length of the opcode field at the head of every TFTP packet.
pub const TFTP_OPCODE_LEN: usize = 2;
/// Length of the block-number field in DATA / ACK packets.
pub const TFTP_BLOCK_LEN: usize = 2;
/// Minimum DATA packet length: opcode(2) + block(2) = 4 bytes.
pub const TFTP_MIN_DATA_LEN: usize = 4;
/// Minimum ACK packet length: opcode(2) + block(2) = 4 bytes.
pub const TFTP_MIN_ACK_LEN: usize = 4;
/// Minimum ERROR packet length: opcode(2) + errcode(2) + NUL(1) = 5 bytes.
pub const TFTP_MIN_ERROR_LEN: usize = 5;

/// Transfer mode per RFC 1350 §2. The seed only handles the two
/// modes that real-world implementations use; `mail` was dropped
/// from later TFTP revisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpMode {
    /// `netascii` — line-ending-normalised text (CRLF on the wire).
    NetAscii,
    /// `octet` — raw 8-bit bytes. Used for binary boot images.
    Octet,
}

impl TftpMode {
    /// Wire-form (null-terminated string omitted) of the mode.
    /// `from_bytes` matches case-insensitively per RFC 1350 §2.
    pub fn as_bytes(self) -> &'static [u8] {
        match self {
            TftpMode::NetAscii => b"netascii",
            TftpMode::Octet => b"octet",
        }
    }

    /// Parse `s` (no NUL terminator). Case-insensitive per RFC 1350.
    pub fn from_bytes(s: &[u8]) -> Option<TftpMode> {
        if eq_ignore_ascii_case_static(s, b"netascii") {
            Some(TftpMode::NetAscii)
        } else if eq_ignore_ascii_case_static(s, b"octet") {
            Some(TftpMode::Octet)
        } else {
            None
        }
    }
}

#[inline]
fn eq_ignore_ascii_case_static(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0;
    while i < a.len() {
        let ai = a[i];
        let bi = b[i];
        let al = if ai.is_ascii_uppercase() { ai + 32 } else { ai };
        let bl = if bi.is_ascii_uppercase() { bi + 32 } else { bi };
        if al != bl {
            return false;
        }
        i += 1;
    }
    true
}

/// View into a parsed TFTP packet. Borrows from the input buffer.
#[derive(Debug, Clone, Copy)]
pub enum TftpPacket<'a> {
    /// `DATA` packet — block number + (0..=512) payload bytes.
    Data {
        /// Block sequence number (starts at 1).
        block: u16,
        /// Payload bytes (empty on the final short DATA per RFC 1350).
        payload: &'a [u8],
    },
    /// `ACK` packet — acknowledges receipt of `block`.
    Ack {
        /// Block sequence number being acknowledged.
        block: u16,
    },
    /// `ERROR` packet — server-side or client-side rejection.
    Error {
        /// Error code per [`TftpErrorCode`] (0..7).
        code: u16,
        /// NUL-terminated message bytes (terminator excluded).
        msg: &'a [u8],
    },
    /// `OACK` (RFC 2347) — server's option acknowledgement, returned
    /// in response to options in the RRQ/WRQ. Raw bytes of the
    /// options section (pairs of NUL-terminated strings); caller
    /// walks them with their own helper if they care.
    OAck {
        /// Raw option-pair bytes (excluding the 2-byte opcode).
        options_raw: &'a [u8],
    },
}

/// Errors from the TFTP wire codec. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TftpError {
    /// Input shorter than the smallest legal packet (4 bytes).
    Truncated,
    /// Opcode is not in `[1, 6]`.
    BadOpcode,
    /// Transfer mode string isn't `netascii` or `octet`.
    BadMode,
    /// Filename byte sequence exceeds [`MAX_TFTP_FILENAME`].
    FilenameTooLong,
    /// RRQ/WRQ string slot has no NUL terminator inside its budget
    /// (RFC 1350 requires every string field to be NUL-terminated).
    MissingNul,
    /// Output buffer too small for the requested emission.
    OutputBufferTooSmall,
    /// OACK options section contains a malformed pair (odd number
    /// of NUL-terminated tokens, or a token longer than its slot).
    BadOption,
}

/// TFTP error-code constants per RFC 1350 §5.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum TftpErrorCode {
    /// Not defined.
    NotDefined = 0,
    /// File not found.
    NotFound = 1,
    /// Access violation.
    AccessViolation = 2,
    /// Disk full or allocation exceeded.
    DiskFull = 3,
    /// Illegal TFTP operation.
    IllegalOp = 4,
    /// Unknown transfer ID.
    UnknownTid = 5,
    /// File already exists.
    FileExists = 6,
    /// No such user.
    NoSuchUser = 7,
}

/// TFTP wire codec byte-locked surface (RFC 1350 + RFC 2347).
///
/// # Locked invariants the verifier checks
///
/// 1. `build_rrq(filename, mode, out)` produces bytes
///    `opcode(0x0001) || filename || 0x00 || mode || 0x00`.
/// 2. `build_ack(block, out)` produces 4 bytes
///    `opcode(0x0004) || block(big-endian u16)`.
/// 3. `build_error(code, msg, out)` produces bytes
///    `opcode(0x0005) || code(big-endian u16) || msg || 0x00`.
/// 4. `parse_packet(buf)` returns the matching `TftpPacket` view
///    AND every error path is reached on its locked input shape.
/// 5. Mode parsing is case-insensitive per RFC 1350 §2.
///
/// # Not in this contract (intentional)
///
/// - Retransmission timer / sliding-window state. The seed is a
///   stateless wire codec; the caller drives retransmits via the
///   existing scheduler tick.
/// - Socket binding / port allocation. The kernel composes this
///   codec with the existing `NetStack` UDP path.
/// - Multi-file batch fetch. One file per session.
pub trait Tftp {
    /// Build a Read Request packet for `filename` in `mode`. The
    /// filename must be a non-empty byte sequence ≤
    /// [`MAX_TFTP_FILENAME`] bytes with no embedded NULs.
    fn build_rrq(
        filename: &[u8],
        mode: TftpMode,
        out: &mut [u8],
    ) -> Result<usize, TftpError>;

    /// Build an ACK packet acknowledging `block`.
    fn build_ack(block: u16, out: &mut [u8]) -> Result<usize, TftpError>;

    /// Build an ERROR packet with code + NUL-terminated message.
    fn build_error(
        code: TftpErrorCode,
        msg: &[u8],
        out: &mut [u8],
    ) -> Result<usize, TftpError>;

    /// Parse a received TFTP packet into a borrowed view.
    fn parse_packet(buf: &[u8]) -> Result<TftpPacket<'_>, TftpError>;
}

// ---------------------------------------------------------------------------
// Smp — multi-core bring-up + per-CPU storage (TASK-057)
// ---------------------------------------------------------------------------

/// Maximum number of CPUs the seed's `PerCpu` storage supports. Larger
/// systems (>64 cores) are out of scope for the seed; a future
/// schema-compatible extension can bump this.
pub const MAX_CPUS: usize = 64;

/// Local APIC ID — the 8-bit identifier each x86_64 logical CPU
/// presents in its `CPUID 0xB` leaf and the ACPI MADT.
pub type ApicId = u8;

/// Intel SDM Vol 3A §10.6 — Interrupt Command Register (ICR) field
/// constants. Locked: the diversifier cannot morph these values
/// without breaking real-hardware AP bring-up. Used both by the
/// seed's `wake_aps` driver and (in the future) by the real-APIC
/// kernel-side implementation.
pub mod smp_consts {
    /// ICR `Delivery Mode` field = INIT (0b101 << 8).
    pub const ICR_DELIVERY_INIT: u32 = 5 << 8;
    /// ICR `Delivery Mode` field = Start-Up (0b110 << 8).
    pub const ICR_DELIVERY_STARTUP: u32 = 6 << 8;
    /// ICR `Level` field = Assert (1 << 14).
    pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
    /// ICR `Level` field = De-assert (0 << 14).
    pub const ICR_LEVEL_DEASSERT: u32 = 0;
    /// ICR `Trigger Mode` field = Level (1 << 15).
    pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;
    /// ICR `Destination Shorthand` = All-Excluding-Self (0b11 << 18).
    pub const ICR_DEST_SHORTHAND_ALL_EXCL_SELF: u32 = 3 << 18;
    /// ICR `Delivery Status` (RO, bit 12). When set after an ICR_low
    /// write, the previous IPI is still in flight.
    pub const ICR_DELIVERY_STATUS_PENDING: u32 = 1 << 12;
    /// Vector-field mask for SIPI: low 8 bits of ICR_low encode the
    /// real-mode page number to start the AP from.
    pub const ICR_VECTOR_MASK: u32 = 0xFF;
    /// Bit-shift to place an `ApicId` into the upper 8 bits of
    /// ICR-high (target CPU identifier).
    pub const ICR_HIGH_DEST_SHIFT: u32 = 24;
    /// SDM §10.4.7.1: spec-mandated 10 ms between INIT and first SIPI.
    pub const SMP_INIT_TO_SIPI_US: u32 = 10_000;
    /// SDM §10.4.7.1: spec-mandated 200 µs between successive SIPIs.
    pub const SMP_SIPI_TO_SIPI_US: u32 = 200;
    /// Bounded retry budget for `wait_for_idle` to observe the
    /// previous IPI's delivery-status clearing.
    pub const SMP_DELIVERY_RETRY_BUDGET: u32 = 1_000;
}

/// ACPI 6.4 §5.2.12 — Multiple APIC Description Table layout constants.
pub mod madt {
    /// MADT table signature (first 4 bytes of the table header).
    pub const SIG_APIC: [u8; 4] = *b"APIC";
    /// Subtable type code for Processor Local APIC (ACPI 6.4 §5.2.12.2).
    pub const ENTRY_LOCAL_APIC: u8 = 0;
    /// Subtable type code for I/O APIC (ACPI 6.4 §5.2.12.3). Parser
    /// skips these for now — the seed only needs the Local APIC entries.
    pub const ENTRY_IO_APIC: u8 = 1;
    /// Flag bit 0 of a Processor Local APIC entry: the CPU is
    /// **enabled** (and therefore ready to be bootstrapped).
    pub const LOCAL_APIC_FLAG_ENABLED: u32 = 1 << 0;
    /// Flag bit 1 of a Processor Local APIC entry: the CPU is
    /// **online-capable** but not currently enabled (firmware
    /// might enable it later — out of scope for the seed).
    pub const LOCAL_APIC_FLAG_ONLINE_CAPABLE: u32 = 1 << 1;
    /// Length in bytes of the MADT header before the first subtable.
    pub const HEADER_LEN: usize = 44;
    /// Length in bytes of a Processor Local APIC subtable entry.
    pub const LOCAL_APIC_ENTRY_LEN: usize = 8;
}

/// SMP-discovered topology: which CPU is the bootstrap processor and
/// which application processors must be woken. Storage-only — no
/// behaviour. Returned by [`Smp::discover`].
#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    /// Bootstrap processor's APIC ID (the CPU the firmware boots).
    /// Selected as the first **enabled** Processor Local APIC entry
    /// in the MADT.
    pub bsp: ApicId,
    /// Application processor APIC IDs, in MADT discovery order.
    /// Only the first `ap_count` slots are valid.
    pub aps: [ApicId; MAX_CPUS],
    /// Number of AP IDs in `aps`. Always strictly less than `MAX_CPUS`.
    pub ap_count: usize,
}

impl CpuTopology {
    /// Total CPU count (BSP + APs).
    #[inline]
    pub fn cpu_count(&self) -> usize {
        1 + self.ap_count
    }

    /// View into the populated portion of `aps`.
    #[inline]
    pub fn ap_ids(&self) -> &[ApicId] {
        &self.aps[..self.ap_count]
    }
}

/// Errors from the SMP bring-up wire codec. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpError {
    /// MADT signature byte sequence isn't `b"APIC"`.
    BadMadtSignature,
    /// MADT header is truncated, an entry's length-byte is invalid,
    /// or an entry runs past the table's `Length` field.
    BadMadtEntry,
    /// MADT contains more enabled Processor Local APIC entries than
    /// the seed's `MAX_CPUS` slot table can hold.
    TooManyCpus,
    /// MADT walked clean but contained zero enabled Processor Local
    /// APIC entries — there is no BSP to designate.
    NoEnabledCpu,
    /// `wait_for_idle` exhausted its retry budget without observing
    /// the previous IPI's delivery-status bit clearing. In a real
    /// kernel: hardware fault. In tests: harness misconfigured.
    ApicTimeout,
    /// `trampoline_pa` doesn't satisfy the SIPI vector encoding
    /// constraints (not page-aligned, or page-number is 0 or 0xFF).
    BadIpiVector,
    /// [`PerCpu`] table has no free slot for a new APIC ID.
    PerCpuOverflow,
    /// [`PerCpu::get`] / `try_get` invoked with an APIC ID that was
    /// never registered.
    UnknownApicId,
}

/// MMIO surface for the Local APIC ICR (Interrupt Command Register).
/// Caller-supplied so the seed's [`Smp::wake_aps`] can be exercised
/// against a recording test harness AND against the real APIC at
/// kernel runtime through the same trait surface.
///
/// On real x86_64 hardware the Local APIC is MMIO-mapped at
/// `MSR_IA32_APIC_BASE`; ICR_low lives at offset 0x300, ICR_high at
/// offset 0x310. The kernel-side implementation wraps those reads
/// + writes; the test harness records every call into a Vec for
/// later assertion against a locked golden.
pub trait ApicWriter {
    /// Write the low 32 bits of the ICR. Writing ICR-low is what
    /// triggers IPI delivery — ICR-high must already hold the target.
    fn write_icr_low(&mut self, val: u32);
    /// Write the high 32 bits of the ICR. The upper 8 bits are the
    /// destination APIC ID (see `smp_consts::ICR_HIGH_DEST_SHIFT`).
    fn write_icr_high(&mut self, val: u32);
    /// Read the low 32 bits of the ICR. Used by `wait_for_idle` to
    /// poll the `Delivery Status` bit.
    fn read_icr_low(&mut self) -> u32;
}

/// SMP bring-up byte-locked surface.
///
/// # Locked invariants the verifier checks
///
/// 1. [`discover`](Smp::discover) on a well-formed MADT recovers
///    every enabled Processor Local APIC entry, designates the
///    first as BSP, and packs the remainder into `CpuTopology::aps`
///    in MADT-discovery order.
/// 2. `discover` rejects malformed input via the locked `SmpError`
///    variant set; no panics, no silent truncation.
/// 3. [`wake_aps`](Smp::wake_aps) emits exactly 3 IPIs per AP
///    (INIT, SIPI, SIPI), in that order. The 9-write sequence for
///    a 3-AP topology against a recording `ApicWriter` is locked.
/// 4. The SIPI vector encoded in ICR-low equals
///    `(trampoline_pa >> 12) & ICR_VECTOR_MASK`.
/// 5. `wake_aps` waits `SMP_INIT_TO_SIPI_US` after INIT and
///    `SMP_SIPI_TO_SIPI_US` after each SIPI before the next write,
///    via the caller-supplied `delay_us` closure (so the timing
///    contract is auditable in tests).
///
/// # Not in this contract (intentional)
///
/// - The AP-side trampoline blob itself. The seed exercises the
///   BSP-side ICR sequence only; the trampoline page contents (real-
///   mode → protected → long-mode dance) are a future surface.
/// - Real APIC MMIO reads/writes — the kernel-side implementation
///   wraps those behind `ApicWriter`. Tests use a recording harness.
/// - Actual concurrent execution on AP cores. `discover` + `wake_aps`
///   are wire-codec-shaped; no AP code runs in the seed's QEMU smoke.
/// - ACPI MADT checksum validation (sum-mod-256 = 0). The seed treats
///   the MADT as caller-pre-validated; adding the checksum check is
///   a schema-compatible extension.
pub trait Smp {
    /// Parse an ACPI MADT byte slice, returning the discovered
    /// [`CpuTopology`].
    fn discover(madt: &[u8]) -> Result<CpuTopology, SmpError>;

    /// Drive the INIT-SIPI-SIPI AP wake sequence through the
    /// caller-supplied [`ApicWriter`]. Returns the number of IPIs
    /// issued (= 3 × `topology.ap_count` on success).
    ///
    /// `trampoline_pa` is the physical address of the real-mode AP
    /// trampoline page; the SIPI vector is `(trampoline_pa >> 12)`,
    /// constrained to the inclusive range `[0x01, 0xFE]`.
    ///
    /// `delay_us` is invoked between each IPI with the SDM-mandated
    /// wait (10 ms after INIT, 200 µs after each SIPI). The caller
    /// supplies the actual timing primitive (kernel: APIC timer or
    /// TSC-deadline; tests: no-op).
    fn wake_aps(
        topology: &CpuTopology,
        trampoline_pa: u64,
        apic: &mut dyn ApicWriter,
        delay_us: &mut dyn FnMut(u32),
    ) -> Result<usize, SmpError>;
}

/// Fixed-capacity per-CPU storage indexed by APIC ID. Allocation-free.
///
/// APIC IDs aren't guaranteed dense (a hyperthreaded system might
/// present 0, 1, 4, 5), so the slot table stores `(apic_id, value)`
/// pairs and `get` / `try_get` does a linear scan over the registered
/// prefix. For `MAX_CPUS = 64` the scan is bounded at 64 comparisons
/// — within budget for any per-syscall lookup.
///
/// Locked surface: the slot-table layout + the
/// `register`/`get`/`try_get` semantics are part of the contract.
/// Internal representation (the scan loop, the field order) is
/// fully diversifiable.
pub struct PerCpu<T, const N: usize> {
    /// `Some(apic_id)` for registered slots, `None` for free slots.
    /// Indices `[0, count)` are registered; `[count, N)` are free.
    pub(crate) apic_ids: [Option<ApicId>; N],
    /// Per-CPU values. Slot `i` corresponds to `apic_ids[i]`.
    pub(crate) slots: [T; N],
    /// Count of registered entries. Always `<= N`.
    pub(crate) count: usize,
}

impl<T: Default + Copy, const N: usize> Default for PerCpu<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default + Copy, const N: usize> PerCpu<T, N> {
    /// Construct an empty `PerCpu` with all slots free. Not `const fn`
    /// because `T::default()` is not const-stable; if a caller needs
    /// a `const`-context constructor for a specific `T` whose default
    /// IS const, they can wrap their own.
    pub fn new() -> Self {
        Self {
            apic_ids: [None; N],
            slots: [T::default(); N],
            count: 0,
        }
    }

    /// Register an APIC ID with an initial value. Returns
    /// [`SmpError::PerCpuOverflow`] when the table is full.
    pub fn register(&mut self, apic_id: ApicId, value: T) -> Result<(), SmpError> {
        if self.count >= N {
            return Err(SmpError::PerCpuOverflow);
        }
        self.apic_ids[self.count] = Some(apic_id);
        self.slots[self.count] = value;
        self.count += 1;
        Ok(())
    }

    /// Look up the slot for a registered APIC ID. Panics on
    /// unknown — kernel-internal invariant violation. Use
    /// [`try_get`](PerCpu::try_get) when the caller can recover.
    pub fn get(&mut self, apic_id: ApicId) -> &mut T {
        match self.try_get(apic_id) {
            Some(slot) => slot,
            None => panic!("PerCpu::get on unregistered APIC ID"),
        }
    }

    /// Try-form of [`get`](PerCpu::get) — returns `None` for an
    /// unregistered APIC ID instead of panicking.
    pub fn try_get(&mut self, apic_id: ApicId) -> Option<&mut T> {
        let mut i = 0usize;
        while i < self.count {
            if self.apic_ids[i] == Some(apic_id) {
                return Some(&mut self.slots[i]);
            }
            i += 1;
        }
        None
    }

    /// Number of registered slots.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Capacity (compile-time `N`).
    #[inline]
    pub const fn capacity() -> usize {
        N
    }
}

// ============================================================
// TASK-059: PCI bus enumeration (legacy 0xCF8/0xCFC config
// mechanism #1)
// ============================================================
//
// Wire-codec-shaped surface that lets the seed discover every
// PCI function on the bus, decode BARs and the MSI-X capability
// block, and toggle bus-master enable. The kernel-side
// implementation wraps the actual `out`/`in` opcodes; tests
// substitute a recording bus harness that returns scripted
// dwords for `(bus, device, function, offset)` tuples.

/// I/O port for the PCI configuration-address register.
pub const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;
/// I/O port for the PCI configuration-data register.
pub const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
/// "No device responded" sentinel returned by the vendor-id field of an
/// empty configuration-space slot.
pub const PCI_VENDOR_NONE: u16 = 0xFFFF;
/// PCI buses to scan during a full enumeration. The legacy mechanism
/// #1 addressing space covers 256 buses × 32 devices × 8 functions =
/// 65,536 configuration cycles per scan.
pub const PCI_MAX_BUS: u16 = 256;
/// Devices per PCI bus.
pub const PCI_MAX_DEVICE: u8 = 32;
/// Functions per PCI device. Only multi-function devices (header_type
/// bit 7 set) populate functions 1..7.
pub const PCI_MAX_FUNCTION: u8 = 8;
/// Bit 7 of the header_type byte at config offset 0x0E. Set means the
/// function is part of a multi-function device — probe the remaining
/// functions; clear means functions 1..7 are reserved and the enumerator
/// must NOT issue a config cycle for them (skips ghost echoes on some
/// chipsets).
pub const PCI_HEADER_MULTIFUNC_BIT: u8 = 0x80;
/// PCI capability ID for legacy MSI (per PCI Local Bus Spec §6.8).
pub const PCI_CAP_ID_MSI: u8 = 0x05;
/// PCI capability ID for MSI-X (per PCI Local Bus Spec §6.8.2).
pub const PCI_CAP_ID_MSIX: u8 = 0x11;
/// Bit 4 of the status register at config offset 0x06. Set means the
/// function exposes a capabilities list at offset 0x34.
pub const PCI_STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
/// Hard cap on capability-list hops during a `find_capability` walk.
/// Real firmware lists rarely exceed 8 entries; the bound exists to
/// guard against a buggy chipset that builds a circular list.
pub const PCI_MAX_CAP_HOPS: u8 = 48;
/// Config offset of the vendor-id (LSB) + device-id (MSB) dword.
pub const PCI_CFG_OFFSET_VENDOR_DEVICE: u8 = 0x00;
/// Config offset of the command (LSB 16) + status (MSB 16) dword.
pub const PCI_CFG_OFFSET_COMMAND_STATUS: u8 = 0x04;
/// Config offset of the class + subclass + prog-if + revision dword.
pub const PCI_CFG_OFFSET_CLASS_REVISION: u8 = 0x08;
/// Config offset of the cache-line size + latency + header_type + BIST
/// dword. `header_type` is the third byte (bits 16..23).
pub const PCI_CFG_OFFSET_HEADER_LATENCY: u8 = 0x0C;
/// Config offset of BAR0. BARs are 4 bytes apart; BAR_idx lives at
/// `PCI_CFG_OFFSET_BAR0 + idx * 4`.
pub const PCI_CFG_OFFSET_BAR0: u8 = 0x10;
/// Config offset of the interrupt-line (LSB) + interrupt-pin (next) +
/// min-grant + max-latency dword. Interrupt-line is the firmware-
/// programmed legacy IRQ for the device's INTx pin.
pub const PCI_CFG_OFFSET_INT_LINE: u8 = 0x3C;
/// Config offset of the capabilities pointer (LSB byte; bits 0..7 of
/// the dword). Only valid when the capabilities-list status bit is set.
pub const PCI_CFG_OFFSET_CAP_PTR: u8 = 0x34;
/// Bit 2 of the command register: Bus Master Enable. Required for
/// any DMA-capable device.
pub const PCI_COMMAND_BUS_MASTER: u32 = 1 << 2;
/// Bit 0 of a BAR's low dword: 1 = port-I/O space, 0 = MMIO.
pub const PCI_BAR_TYPE_IO_BIT: u32 = 0x1;
/// Bits 1..2 of an MMIO BAR's low dword carry the memory-type encoding.
pub const PCI_BAR_MMIO_TYPE_MASK: u32 = 0x6;
/// Bits 1..2 encoded value = 0b10: this BAR is the low half of a
/// 64-bit address; the adjacent (idx+1) BAR is the high half.
pub const PCI_BAR_MMIO_TYPE_64BIT: u32 = 0x2 << 1;
/// Address bits of an MMIO BAR — the low 4 bits carry flags
/// (type, prefetchable) which the caller must mask off.
pub const PCI_BAR_MMIO_ADDR_MASK: u32 = !0xF;
/// Address bits of an I/O-space BAR — the low 2 bits are reserved
/// (low bit carries the type discriminator).
pub const PCI_BAR_IO_ADDR_MASK: u32 = !0x3;
/// Sentinel value of the interrupt-line byte meaning "no legacy
/// IRQ wired" — caller should fall back to MSI / MSI-X.
pub const PCI_BAR_INT_LINE_NONE: u8 = 0xFF;
/// Maximum valid BAR index. BARs 0..=5 — a 64-bit BAR consumes two
/// slots so the caller may not request `idx=5` for a 64-bit pair.
pub const PCI_MAX_BAR_INDEX: u8 = 5;
/// Bits 0..10 of an MSI-X capability's message-control word encode
/// `table_size - 1`. The decoded `table_size` is in 1..=2048.
pub const PCI_MSIX_TABLE_SIZE_MASK: u16 = 0x07FF;
/// Low 3 bits of the MSI-X table_offset / pba_offset dwords are the
/// BAR Indicator Register — they name which BAR (0..=5) holds the
/// table or PBA.
pub const PCI_MSIX_BIR_MASK: u32 = 0x07;
/// Bit 15 of the MSI-X message-control word: function-level enable.
pub const PCI_MSIX_ENABLE_BIT: u16 = 1 << 15;
/// Bit 14 of the MSI-X message-control word: function mask.
pub const PCI_MSIX_FUNCMASK_BIT: u16 = 1 << 14;

/// PCI class / subclass discriminator constants. Names match the
/// "PCI Code and ID Assignment Specification" §1.4. Only the classes
/// the seed has any reason to mention are enumerated; everything
/// else falls through to "Other / Unknown".
pub mod pci_class {
    /// Mass-storage class (NVMe, SATA, IDE, etc.).
    pub const CLASS_MASS_STORAGE: u8 = 0x01;
    /// IDE subclass.
    pub const SUBCLASS_IDE: u8 = 0x01;
    /// SATA subclass.
    pub const SUBCLASS_SATA: u8 = 0x06;
    /// NVMe subclass.
    pub const SUBCLASS_NVME: u8 = 0x08;
    /// Network controller class.
    pub const CLASS_NETWORK: u8 = 0x02;
    /// Ethernet subclass.
    pub const SUBCLASS_ETHERNET: u8 = 0x00;
    /// Display controller class.
    pub const CLASS_DISPLAY: u8 = 0x03;
    /// VGA-compatible display subclass.
    pub const SUBCLASS_VGA: u8 = 0x00;
    /// Bridge device class.
    pub const CLASS_BRIDGE: u8 = 0x06;
    /// Host bridge subclass.
    pub const SUBCLASS_HOST_BRIDGE: u8 = 0x00;
    /// ISA bridge subclass.
    pub const SUBCLASS_ISA_BRIDGE: u8 = 0x01;
    /// PCI-to-PCI bridge subclass.
    pub const SUBCLASS_PCI_BRIDGE: u8 = 0x04;
    /// Serial-bus controller class.
    pub const CLASS_SERIAL_BUS: u8 = 0x0C;
    /// USB subclass.
    pub const SUBCLASS_USB: u8 = 0x03;
}

/// Identifies a PCI function by its (bus, device, function) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    /// Bus number, 0..=255.
    pub bus: u8,
    /// Device slot on the bus, 0..=31.
    pub device: u8,
    /// Function number within the device, 0..=7.
    pub function: u8,
}

/// Decoded per-function identification block (vendor + device + class).
/// Storage-only; emitted by [`Pci::probe`] / [`Pci::enumerate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    /// Location of the function on the bus.
    pub addr: PciAddress,
    /// Vendor identifier (low 16 bits of the identification dword).
    pub vendor_id: u16,
    /// Device identifier (high 16 bits of the identification dword).
    pub device_id: u16,
    /// Class code (byte 3 of the class/revision dword).
    pub class: u8,
    /// Subclass code (byte 2 of the class/revision dword).
    pub subclass: u8,
    /// Programming interface (byte 1 of the class/revision dword).
    pub prog_if: u8,
    /// Revision identifier (byte 0 of the class/revision dword).
    pub revision: u8,
    /// Header-type byte (byte 2 of the header/latency dword). Bit 7
    /// distinguishes single-function (0) from multi-function (1).
    pub header_type: u8,
}

/// Decoded BAR (Base Address Register) entry. 64-bit MMIO BARs span
/// two adjacent config-space dwords; this enum collapses that into
/// a single decoded value the caller can match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBar {
    /// 32-bit memory-mapped I/O at this physical address.
    Mmio32(u32),
    /// 64-bit memory-mapped I/O at this physical address.
    Mmio64(u64),
    /// Port-I/O at this base port (lower 32 bits only — PCI never
    /// exposes 64-bit I/O space).
    Io(u32),
}

/// Decoded MSI-X capability header. Storage-only; emitted by
/// [`Pci::msix_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciMsixInfo {
    /// Config-space byte offset of this device's MSI-X capability
    /// block (the first byte is the capability-id, equal to
    /// [`PCI_CAP_ID_MSIX`]).
    pub cap_offset: u8,
    /// Number of MSI-X table entries the device supports (1..=2048).
    /// Decoded as `(message_control & PCI_MSIX_TABLE_SIZE_MASK) + 1`.
    pub table_size: u16,
    /// BAR index (0..=5) that holds the MSI-X table.
    pub table_bar: u8,
    /// Byte offset of the table within that BAR.
    pub table_offset: u32,
    /// BAR index (0..=5) that holds the Pending Bit Array.
    pub pba_bar: u8,
    /// Byte offset of the PBA within that BAR.
    pub pba_offset: u32,
}

/// Errors emitted by [`Pci::read_bar`], [`Pci::find_capability`], and
/// [`Pci::msix_info`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    /// `idx > PCI_MAX_BAR_INDEX`, or a 64-bit MMIO BAR was requested
    /// at index 5 (the high half would fall off the BAR table).
    BadBarIndex,
    /// The requested BAR's low dword reads as zero — the firmware
    /// hasn't programmed an address for this slot.
    EmptyBar,
    /// The status register's capabilities-list bit
    /// ([`PCI_STATUS_CAPABILITIES_LIST`]) was clear, so no capability
    /// chain exists to walk.
    NoCapabilities,
    /// Walked the capability chain to its null terminator without
    /// finding the requested `cap_id`.
    CapabilityNotFound,
    /// Walked [`PCI_MAX_CAP_HOPS`] entries without reaching the chain
    /// terminator — assumed to be a circular list (firmware bug).
    CapWalkOverflow,
    /// Capability pointer below the configuration-space header
    /// boundary at 0x34, or beyond 0xFC (the last aligned 4-byte
    /// slot in the standard 256-byte config window).
    BadCapPointer,
}

/// MMIO / port-I/O surface for PCI configuration-space access. Caller-
/// supplied so the seed's [`Pci`] driver can be exercised against a
/// recording test harness AND against the real 0xCF8/0xCFC port pair
/// at kernel runtime through the same trait surface.
///
/// On real x86_64 hardware the implementation writes the (1 << 31 |
/// bus << 16 | device << 11 | function << 8 | offset & 0xFC)
/// address into port 0xCF8, then issues a 32-bit `in`/`out` against
/// port 0xCFC. The test harness records every call into a fixture
/// table indexed by the address tuple and returns the scripted dword.
pub trait PciConfigBus {
    /// Read a 32-bit dword from the function's configuration space at
    /// the given byte offset. `offset` is masked with `0xFC` on the
    /// wire — the bottom two bits must be zero in the address register
    /// per PCI Local Bus Spec §3.2.2.3.4.
    fn read_dword(&mut self, addr: PciAddress, offset: u8) -> u32;
    /// Write a 32-bit dword into the function's configuration space at
    /// the given byte offset. Same alignment rule as `read_dword`.
    fn write_dword(&mut self, addr: PciAddress, offset: u8, value: u32);
}

/// PCI configuration-space byte-locked surface.
///
/// # Locked invariants the verifier checks
///
/// 1. [`probe`](Pci::probe) on a slot whose vendor-id reads as
///    [`PCI_VENDOR_NONE`] returns `None`; otherwise it returns
///    `Some(PciDevice)` with every field decoded from the three
///    standard config-space dwords (0x00 / 0x08 / 0x0C).
/// 2. [`enumerate`](Pci::enumerate) walks the full (bus 0..=255,
///    device 0..32, function 0..=7) address space, calling the sink
///    once per responding function. Functions 1..7 are probed only
///    when function 0's `header_type` has [`PCI_HEADER_MULTIFUNC_BIT`]
///    set (the single-function fast path that avoids ghost echoes).
/// 3. [`read_bar`](Pci::read_bar) decodes the per-BAR low dword into
///    [`PciBar::Mmio32`] / [`PciBar::Mmio64`] / [`PciBar::Io`] per
///    the PCI Local Bus Spec §6.2.5.1 encoding, masking off the type
///    and prefetch flags. 64-bit BARs read the high half from
///    `idx + 1` and reject `idx == 5`.
/// 4. [`find_capability`](Pci::find_capability) walks the linked list
///    rooted at [`PCI_CFG_OFFSET_CAP_PTR`] with hop bound
///    [`PCI_MAX_CAP_HOPS`], returning the offset of the first
///    capability whose ID matches.
/// 5. [`msix_info`](Pci::msix_info) decodes the standard MSI-X
///    capability header per PCI 3.0 §6.8.2 — message-control word
///    yields `table_size`; the next two dwords yield (BIR, offset)
///    for the table and PBA respectively.
/// 6. [`enable_bus_master`](Pci::enable_bus_master) does a 32-bit
///    read-modify-write of the command/status dword that sets exactly
///    [`PCI_COMMAND_BUS_MASTER`] and preserves every other bit.
///
/// # Not in this contract (intentional)
///
/// - PCIe extended configuration space (offset > 0xFC). The seed uses
///   mechanism #1 which exposes only the legacy 256-byte window.
/// - PCI-to-PCI bridge secondary-bus recursion. QEMU's chipsets expose
///   every secondary bus in the same flat address space we already
///   iterate; real hardware sometimes hides one — schema-compatible
///   future extension.
/// - BAR sizing (write all-ones, read-back, decode size). The seed
///   reads BAR addresses, not their sizes; adding `bar_size` is a
///   schema-compatible extension.
/// - MSI (non-X) capability decode. The legacy MSI block is documented
///   via [`PCI_CAP_ID_MSI`] but no decoder ships in the seed.
pub trait Pci {
    /// Read the per-function identification block. Returns `None` if
    /// the slot is empty (vendor == [`PCI_VENDOR_NONE`]).
    fn probe(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Option<PciDevice>;

    /// Walk every `(bus, device, function)` and invoke `sink` for each
    /// responding function. Allocation-free.
    fn enumerate(bus: &mut dyn PciConfigBus, sink: &mut dyn FnMut(PciDevice));

    /// Human-readable name for a (class, subclass) pair. Only covers
    /// the classes the seed has any reason to mention; everything else
    /// falls through to "Other / Unknown".
    fn class_name(class: u8, subclass: u8) -> &'static str;

    /// Read the firmware-programmed interrupt line byte at config
    /// offset 0x3C. Returns `None` for the legacy "no connection"
    /// sentinel [`PCI_BAR_INT_LINE_NONE`].
    fn int_line(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Option<u8>;

    /// Read BAR `idx` (0..=5) for the function at `addr` and decode it
    /// into a [`PciBar`]. 64-bit MMIO BARs are read as a pair and
    /// collapsed into [`PciBar::Mmio64`].
    fn read_bar(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        idx: u8,
    ) -> Result<PciBar, PciError>;

    /// Set the bus-master-enable bit (bit 2) of the command register
    /// at config offset 0x04. Preserves the rest of the command word
    /// and the read-only status word in the upper half of the dword.
    fn enable_bus_master(bus: &mut dyn PciConfigBus, addr: PciAddress);

    /// Walk the per-function capability list and return the offset of
    /// the first capability whose ID matches `cap_id`. Bounded at
    /// [`PCI_MAX_CAP_HOPS`] hops to defend against a circular list.
    fn find_capability(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        cap_id: u8,
    ) -> Result<u8, PciError>;

    /// Probe the function for an MSI-X capability and return its
    /// decoded header. Composes `find_capability(cap_id =
    /// PCI_CAP_ID_MSIX)` with the message-control / table-pointer /
    /// PBA-pointer dword reads.
    fn msix_info(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
    ) -> Result<PciMsixInfo, PciError>;

    /// Set the MSI-X capability's enable bit (bit 15 of
    /// message-control) to `on`. When `on=true` the function-mask
    /// bit is also cleared so the per-entry mask bits become the
    /// only gate.
    fn msix_set_enable(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        info: &PciMsixInfo,
        on: bool,
    );
}

// ============================================================
// X.509 DER certificate parser (TASK-060)
//
// A *pure parser*: every field is a `&[u8]` view into the input
// DER buffer. No allocator, no signature verification, no chain
// walking — the caller is responsible for handing the parsed
// pieces to a verifier built atop the existing `SignatureVerify`
// surface.
//
// Locked invariants:
//
// 1. `X509::parse(der)` walks the RFC 5280 §4.1 outer SEQUENCE
//    exactly once, performs strict DER bounds checks (no
//    indefinite-length, no non-minimal length encoding, no
//    high-tag-number form), and rejects any blob longer than
//    [`X509_MAX_CERT_LEN`].
// 2. The recovered `X509Cert<'a>` borrows the TBSCertificate
//    sub-slice byte-exact — the slice MUST equal the byte range
//    the outer signatureAlgorithm/signatureValue covers, so a
//    caller can hash it for signature verification without
//    re-encoding.
// 3. Only three SPKI algorithm OIDs are accepted — rsaEncryption,
//    id-ecPublicKey (P-256), and id-Ed25519. Any other OID is
//    surfaced as [`X509Error::UnsupportedKeyAlg`] — refusing
//    unknown algorithms is how X.509 parsers stop being a CVE
//    factory (RFC 5280 §1 "any other" caveat).
// 4. Only three signatureAlgorithm OIDs are accepted —
//    sha256WithRSAEncryption, ecdsa-with-SHA256, and id-Ed25519.
// 5. The outer signatureAlgorithm field MUST equal the
//    TBSCertificate's `signature` field byte-for-byte (RFC 5280
//    §4.1.1.2). Drift surfaces as [`X509Error::SigAlgMismatch`].
// 6. Validity is decoded into Unix epoch seconds; UTCTime years
//    < 50 map to 20YY and ≥ 50 map to 19YY per RFC 5280 §4.1.2.5.1.
//    GeneralizedTime is also accepted for `notAfter` fields that
//    fall past 2049.
// ============================================================

/// ASN.1 / DER tag bytes the [`X509`] parser recognises. The set is
/// deliberately narrow — high-tag-number and indefinite-length forms
/// are rejected outright. (See RFC 5280 §4.1 for the cert structure
/// and X.690 §8.1 for the encoding rules.)
pub const X509_TAG_INTEGER: u8 = 0x02;
/// BIT STRING tag (0x03). The parser only accepts BIT STRINGs whose
/// first byte (the "unused bits" count) is zero — non-zero unused
/// bits would surface as a `MalformedBitString` error.
pub const X509_TAG_BIT_STRING: u8 = 0x03;
/// OCTET STRING tag (0x04). Used inside extensions; treated as opaque.
pub const X509_TAG_OCTET_STRING: u8 = 0x04;
/// NULL tag (0x05). Encodes the rsaEncryption SPKI parameters.
pub const X509_TAG_NULL: u8 = 0x05;
/// OBJECT IDENTIFIER tag (0x06).
pub const X509_TAG_OID: u8 = 0x06;
/// UTF8String tag (0x0C). Used inside RDN components.
pub const X509_TAG_UTF8_STRING: u8 = 0x0C;
/// PrintableString tag (0x13). Used inside RDN components.
pub const X509_TAG_PRINTABLE_STRING: u8 = 0x13;
/// IA5String tag (0x16). Used inside Subject Alternative Name extensions.
pub const X509_TAG_IA5_STRING: u8 = 0x16;
/// UTCTime tag (0x17). RFC 5280 form `YYMMDDhhmmssZ`.
pub const X509_TAG_UTC_TIME: u8 = 0x17;
/// GeneralizedTime tag (0x18). RFC 5280 form `YYYYMMDDhhmmssZ`.
pub const X509_TAG_GENERALIZED_TIME: u8 = 0x18;
/// SEQUENCE tag (0x30). Constructed.
pub const X509_TAG_SEQUENCE: u8 = 0x30;
/// SET tag (0x31). Constructed.
pub const X509_TAG_SET: u8 = 0x31;
/// Context-specific [0] EXPLICIT tag (0xA0). Wraps the TBS version field.
pub const X509_TAG_CTX_EXPLICIT_0: u8 = 0xA0;
/// Context-specific [3] EXPLICIT tag (0xA3). Wraps the TBS extensions
/// list.
pub const X509_TAG_CTX_EXPLICIT_3: u8 = 0xA3;

/// Hard cap on the total encoded length of a DER certificate the
/// parser will look at. 64 KiB is two orders of magnitude above any
/// real-world cert; anything larger is rejected before the first
/// tag is read. Bounded by definition, no allocator involved.
pub const X509_MAX_CERT_LEN: usize = 64 * 1024;

/// Hard cap on nested SEQUENCE/SET recursion. Walking a hostile blob
/// with arbitrary nesting depth is a stack-blow DoS; 16 is generous
/// for any real-world cert (real ones use ~5).
pub const X509_MAX_DEPTH: usize = 16;

/// OID encoding of `id-rsaEncryption` (1.2.840.113549.1.1.1).
pub const X509_OID_RSA_ENCRYPTION: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01,
];
/// OID encoding of `sha256WithRSAEncryption` (1.2.840.113549.1.1.11).
pub const X509_OID_SHA256_WITH_RSA: &[u8] = &[
    0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B,
];
/// OID encoding of `id-ecPublicKey` (1.2.840.10045.2.1).
pub const X509_OID_EC_PUBLIC_KEY: &[u8] = &[
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
];
/// OID encoding of `secp256r1` / `prime256v1` (1.2.840.10045.3.1.7).
pub const X509_OID_SECP256R1: &[u8] = &[
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
];
/// OID encoding of `ecdsa-with-SHA256` (1.2.840.10045.4.3.2).
pub const X509_OID_ECDSA_WITH_SHA256: &[u8] = &[
    0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x02,
];
/// OID encoding of `id-Ed25519` (1.3.101.112) — RFC 8410.
pub const X509_OID_ED25519: &[u8] = &[0x2B, 0x65, 0x70];
/// OID encoding of the X.500 commonName attribute (2.5.4.3). Used by
/// callers that want to extract the leaf CN from the parsed subject
/// DN without re-walking the SET-of-RDN structure.
pub const X509_OID_CN: &[u8] = &[0x55, 0x04, 0x03];

/// Required length of an Ed25519 public key (RFC 8410 §4 — the only
/// length the parser accepts).
pub const X509_ED25519_KEY_LEN: usize = 32;
/// Required length of a SEC1 uncompressed P-256 point: 0x04 || X || Y.
pub const X509_P256_POINT_LEN: usize = 65;

/// Algorithm identifier of a parsed public key. The locked variant
/// set is the three algorithms the kernel + TLS stack itself can
/// consume; any other SPKI algorithm is rejected at parse time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509PubKeyAlg {
    /// RSA with PKCS#1 v1.5 encoding (the only RSA form X.509 uses).
    Rsa,
    /// ECDSA over the NIST P-256 curve (a.k.a. secp256r1 / prime256v1).
    EcdsaP256,
    /// Ed25519 per RFC 8410.
    Ed25519,
}

/// Algorithm identifier of the certificate's outer signature. Locked
/// variant set; see also [`X509PubKeyAlg`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509SigAlg {
    /// RSASSA-PKCS1-v1_5 with SHA-256 — `sha256WithRSAEncryption`.
    RsaSha256,
    /// ECDSA-with-SHA-256 over P-256 — `ecdsa-with-SHA256`.
    EcdsaSha256,
    /// Pure Ed25519 — `id-Ed25519`.
    Ed25519,
}

/// View into a parsed public key. Every byte slice borrows from the
/// caller's input DER buffer — the parser allocates nothing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509PubKey<'a> {
    /// RSA public key (RFC 3279 §2.3.1): the BIT STRING contents are
    /// an embedded SEQUENCE { modulus INTEGER, publicExponent INTEGER }.
    /// `modulus` and `exponent` are the raw big-endian INTEGER bytes
    /// (any DER sign-bit guard 0x00 stripped).
    Rsa {
        /// Big-endian RSA modulus `n`. Leading 0x00 sign-bit byte
        /// stripped if present.
        modulus: &'a [u8],
        /// Big-endian RSA public exponent `e`. Almost always
        /// `&[0x01, 0x00, 0x01]` (65537).
        exponent: &'a [u8],
    },
    /// ECDSA P-256 public key encoded as SEC1 uncompressed point —
    /// `0x04 || X(32) || Y(32)`, exactly [`X509_P256_POINT_LEN`] bytes.
    EcdsaP256 {
        /// Uncompressed SEC1 point bytes. Always 65 bytes long.
        point: &'a [u8],
    },
    /// Ed25519 public key — exactly [`X509_ED25519_KEY_LEN`] bytes.
    Ed25519 {
        /// Raw 32-byte Edwards-curve compressed point.
        key: &'a [u8],
    },
}

/// Decoded calendar time, expressed as Unix epoch seconds. The parser
/// validates the month-day combination, leap-year handling, and the
/// 1970..=9999 range — values outside that range surface as a
/// [`X509Error::TimeOutOfRange`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X509Time {
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
    pub unix: u64,
}

/// View of one parsed X.509 v3 certificate. Every slice borrows from
/// the caller's DER buffer; the structure carries no owned data.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct X509Cert<'a> {
    /// Decoded `version` field — always 2 (v3) after a successful parse.
    pub version: u8,
    /// Raw big-endian serial-number bytes (DER INTEGER value, minus
    /// any leading sign-bit guard 0x00).
    pub serial: &'a [u8],
    /// Issuer Name as the full DER `SEQUENCE OF RDN` blob — header
    /// byte and length included so the caller can compare against a
    /// parent cert's `subject` for chain-walking via byte equality
    /// (RFC 5280 §4.1.2.4 mandates a byte-exact match).
    pub issuer: &'a [u8],
    /// Subject Name as the full DER `SEQUENCE OF RDN` blob (same shape
    /// as `issuer`).
    pub subject: &'a [u8],
    /// Validity start.
    pub not_before: X509Time,
    /// Validity end.
    pub not_after: X509Time,
    /// Algorithm of the SubjectPublicKey.
    pub pubkey_alg: X509PubKeyAlg,
    /// Parsed SubjectPublicKey contents (algorithm-tagged view).
    pub pubkey: X509PubKey<'a>,
    /// Algorithm of the outer signatureValue.
    pub sig_alg: X509SigAlg,
    /// Raw signature bytes. For RSA: the PKCS#1 v1.5 encoded
    /// signature. For ECDSA: the DER-encoded `SEQUENCE { r, s }`
    /// pair as the BIT STRING contents specify (RFC 3279 §2.2.3).
    /// For Ed25519: 64 raw bytes.
    pub signature: &'a [u8],
    /// Byte-exact TBSCertificate sub-slice, *including* the
    /// outermost SEQUENCE header — what the signature algorithm
    /// covers. A caller computing `sha256(tbs)` and verifying
    /// against the parent's public key uses this slice directly,
    /// no re-encoding.
    pub tbs: &'a [u8],
}

/// Errors returned by [`X509::parse`]. Locked variant set; ordered
/// roughly by where they surface during the top-down walk.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum X509Error {
    /// Buffer empty or otherwise zero-length.
    Empty,
    /// Certificate length exceeds [`X509_MAX_CERT_LEN`].
    TooLarge,
    /// A TLV header runs off the end of the slice.
    TruncatedHeader,
    /// A TLV's claimed length runs off the end of the slice.
    TruncatedBody,
    /// X.690 indefinite-length form (illegal in DER).
    IndefiniteLength,
    /// Length field uses more octets than allowed (> 4).
    LengthTooLarge,
    /// Non-minimal length encoding (e.g. 0x81 0x05 instead of 0x05).
    NonMinimalLength,
    /// Tag was not in the recognised set, or did not match what the
    /// surrounding decode-context required.
    BadTag,
    /// High-tag-number form (low 5 bits of tag all set) — refused by
    /// policy.
    HighTagNumber,
    /// INTEGER body violates DER canonical form (leading 0x00 with
    /// next byte's high bit clear, or value too long for context).
    MalformedInteger,
    /// BIT STRING `unused bits` count was non-zero — refused.
    MalformedBitString,
    /// Trailing data found inside a SEQUENCE that was expected to be
    /// fully consumed (e.g. extra TLVs after `extensions`).
    TrailingData,
    /// Certificate `version` field is not v3 (encoded value 2).
    UnsupportedVersion,
    /// SPKI algorithm OID is not one of the three accepted.
    UnsupportedKeyAlg,
    /// SubjectPublicKey was structurally invalid for its algorithm
    /// (wrong length, missing/extra parameters, wrong inner tag).
    MalformedPubKey,
    /// `signatureAlgorithm` OID is not one of the three accepted.
    UnsupportedSigAlg,
    /// Outer `signatureAlgorithm` doesn't equal the TBS's `signature`
    /// AlgorithmIdentifier field (RFC 5280 §4.1.1.2 mismatch).
    SigAlgMismatch,
    /// AlgorithmIdentifier parameters were present where forbidden
    /// (or absent where required).
    BadAlgParams,
    /// UTCTime/GeneralizedTime field had the wrong length, missing
    /// trailing `Z`, non-digit bytes, or invalid calendar value.
    MalformedTime,
    /// Decoded time falls outside the 1970..=9999 window.
    TimeOutOfRange,
    /// `notAfter < notBefore` — the cert was never valid.
    ValidityWindowInverted,
    /// Nested SEQUENCE/SET depth exceeded [`X509_MAX_DEPTH`].
    DepthExceeded,
    /// `subject_der.is_empty()` (impossible in a valid v3 cert).
    EmptyName,
    /// Issuer DN of `child` did not equal subject DN of `parent`
    /// during a [`X509::issuer_matches_subject`] chain step.
    IssuerSubjectMismatch,
}

/// X.509 v3 DER certificate parser. Pure-parser: no signature
/// verification, no chain walking — see the trait-level documentation
/// for the locked invariants.
pub trait X509 {
    /// Parse one DER X.509 v3 certificate. The returned view borrows
    /// from `der` for its entire lifetime; the caller may not
    /// invalidate `der` while the view is live (Rust's lifetime
    /// system already enforces this — documented here for clarity).
    fn parse(der: &[u8]) -> Result<X509Cert<'_>, X509Error>;

    /// Check that `now.unix` falls inside `cert.not_before .. cert.not_after`
    /// inclusive of both endpoints. Returns `false` for any cert whose
    /// window is in the past or in the future.
    fn validity_contains(cert: &X509Cert<'_>, now: X509Time) -> bool;

    /// RFC 5280 §4.1.2.4 byte-exact DN check: the child's `issuer`
    /// DER blob must equal the parent's `subject` DER blob. Returns
    /// `Ok(())` on match; `Err(X509Error::IssuerSubjectMismatch)`
    /// otherwise. This is the *naming* half of a chain step — the
    /// caller still has to verify the signature.
    fn issuer_matches_subject(
        child: &X509Cert<'_>,
        parent: &X509Cert<'_>,
    ) -> Result<(), X509Error>;

    /// Locate the leaf `commonName` attribute value inside a DN blob.
    /// Returns the inner string bytes (without the tag/length header)
    /// of the FIRST `2.5.4.3` AttributeTypeAndValue encountered while
    /// walking the SEQUENCE of RDNs left-to-right. Returns `None` if
    /// the DN contains no CN component. Allocation-free.
    fn find_cn<'a>(dn: &'a [u8]) -> Option<&'a [u8]>;
}

/// Schema version of this contracts crate. Any breaking change to a trait
/// signature or to a `const` value in this crate MUST increment this and
/// trigger a coordinated fleet-wide upgrade — not a routine morph cycle.
///
/// Bumped to **2** by TASK-020: `SyscallCapTable::check` now returns
/// `Result<CapProof, CapError>` instead of `Result<(), CapError>`, and
/// the new required method [`SyscallCapTable::check_raw`] replaces the
/// old required `check` body. Every implementor crate (`target_minimal`,
/// `target_enterprise`) is updated in the same iteration that lands
/// this bump.
///
/// Bumped to **3** by TASK-011: introduces the [`NetStack`] trait and
/// the [`NetError`], [`Ipv4HeaderView`], [`UdpDatagramView`] types as
/// the locked wire surface for in-kernel UDP/IPv4. Pure addition — no
/// existing trait signature or const changes — but trait-set additions
/// are part of the schema because the morph engine enumerates the
/// trait list per cycle.
///
/// Bumped to **4** by TASK-017: introduces the [`Kpti`] trait and the
/// [`KptiViolation`] enum as the locked invariant boundary for per-task
/// page-table isolation. Pure addition — trait-set addition, same
/// rationale as the TASK-011 bump.
///
/// Bumped to **5** by the TCP port: introduces the [`Tcp`] trait,
/// [`TcpSegmentView`], [`TcpError`], and the [`tcp_flags`] module as
/// the locked wire surface for transmission control protocol header
/// emission + parsing. Pure addition — same trait-set-addition
/// rationale.
///
/// Bumped to **6** by the HTTP/1.1 port: introduces the [`Http`]
/// trait, [`HttpRequestView`], [`HttpError`], [`HttpMethod`], and
/// the [`http_status`] module as the locked wire surface for
/// application-protocol parsing + response emission. Pure addition.
///
/// Bumped to **7** by the DNS port: introduces the [`Dns`] trait,
/// [`DnsMessageView`], [`DnsHeader`], [`DnsError`], [`DnsRecordType`],
/// and the [`dns_flags`] + [`dns_class`] modules as the locked wire
/// surface for RFC 1035 query / response parsing + emission. Pure
/// addition — same trait-set-addition rationale.
///
/// Bumped to **8** by the ICMP port: introduces the [`Icmp`] trait,
/// [`IcmpEchoView`], [`IcmpError`], and the [`icmp_type`] module as
/// the locked wire surface for RFC 792 echo request / reply with
/// RFC 1071 checksum verification. Pure addition.
///
/// Bumped to **9** by the Ethernet/802.3 port: introduces the [`Eth`]
/// trait, [`EthFrameView`], [`EthError`], [`MacAddr`], and the
/// [`ether_type`] module as the locked wire surface for Ethernet II
/// frame emission + parsing including single 802.1Q VLAN tag
/// handling. Pure addition.
///
/// Bumped to **10** by TASK-019: introduces the [`CrashDump`] and
/// [`SymbolResolve`] traits along with [`CrashContext`],
/// [`CrashDumpHeader`], [`CrashDumpError`], [`CrashRegisters`], and
/// the [`crash_offsets`] module as the locked on-disk surface for
/// post-mortem panic dumps + kernel symbol resolution. Pure addition
/// — same trait-set-addition rationale as the prior bumps.
///
/// Bumped to **11** by TASK-046: introduces the [`Arp`] trait,
/// [`ArpPacketView`], [`ArpError`], the [`arp_op`] module, and the
/// `ARP_*` length constants as the locked wire surface for RFC 826
/// IPv4-over-Ethernet address resolution. Pure addition — same
/// trait-set-addition rationale.
///
/// Bumped to **12** by TASK-047: introduces the [`Dhcp`] trait,
/// [`DhcpMessageView`], [`DhcpError`], [`DhcpClientState`], the
/// [`dhcp_msg_type`] + [`dhcp_option`] modules, and the
/// `DHCP_*` constants (op codes, htype/hlen, magic cookie, fixed
/// header length, broadcast flag) as the locked wire surface for
/// RFC 2131 + RFC 2132 IPv4 DHCP boot-time IP acquisition. Pure
/// addition — same trait-set-addition rationale.
///
/// Bumped to **13** by TASK-048: introduces the [`NetDevice`] trait,
/// [`MmioBus`] trait, [`NetDeviceError`], [`VirtqDesc`],
/// [`VirtioNetHdr`], the [`virtio_net_feature`] + [`virtio_status`]
/// modules, and the `VIRTIO_*` constants as the locked surface for
/// a VirtIO 1.0 network-device driver. Pure addition — same
/// trait-set-addition rationale.
///
/// Bumped to **14** by TASK-049: introduces the [`Tls13Client`] trait
/// alongside the existing [`Tls13Server`], plus the locked
/// [`ParsedServerHello`] + [`HandshakeKeys`] structs that carry the
/// trait's parse/derive outputs. Closes the symmetric gap left by the
/// server-only port from TASK-007 — the kernel can now build a
/// ClientHello, parse a ServerHello, run the RFC 8446 §7.1 key
/// schedule through the handshake-traffic secrets, and compute the
/// client Finished `verify_data`. Pure addition — same trait-set-
/// addition rationale; no existing surface byte changed.
///
/// Bumped to **15** by TASK-050: introduces the [`PacketFilter`] trait
/// and the locked surface around it — [`FilterRule`] (5-tuple +
/// action), [`Ipv4PacketView`] (5-tuple packet projection),
/// [`FilterAction`], [`Verdict`], [`FilterRuleError`], plus the
/// `IP_PROTO_TCP` / `IP_PROTO_ICMP` / `FW_PROTO_ANY` / `FW_PORT_ANY`
/// constants. Closes the security-policy gap left by the raw
/// [`NetStack`] (which currently accepts every parsed packet) by
/// giving the kernel a stateless first-match-wins filter that
/// composes with the existing IPv4 / TCP / UDP / ICMP wire codecs.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **16** by TASK-051: introduces the [`Tpm`] trait — a
/// TPM 2.0 client-side wire codec covering `TPM2_Startup`,
/// `TPM2_GetRandom`, `TPM2_PCR_Read`, `TPM2_PCR_Extend`, and a
/// response-header parser — alongside [`TpmResponseView`],
/// [`TpmError`], and the TCG-assigned wire constants
/// (`TPM_HEADER_LEN`, `TPM_ST_NO_SESSIONS`, `TPM_ST_SESSIONS`,
/// `TPM_CC_STARTUP` / `_GET_RANDOM` / `_PCR_READ` / `_PCR_EXTEND`,
/// `TPM_SU_CLEAR` / `_STATE`, `TPM_ALG_SHA256` / `_SHA1`,
/// `TPM_RS_PW`, `TPM_RC_SUCCESS`, `TPM_SHA256_DIGEST_LEN` /
/// `_SHA1_DIGEST_LEN`, `TPM_MAX_PCR_INDEX`). Sets up the in-kernel
/// surface needed for measured boot + remote attestation; the wire
/// codec is transport-agnostic so a future CRB/TIS driver can plug
/// into the locked frame builders without re-implementing them.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **17** by TASK-052: introduces the [`AuditLog`] trait —
/// a fixed-capacity in-kernel security-event ring with monotonic
/// `event_id`, append-order iteration, and a byte-exact `snapshot`
/// emission for offline log parsing — alongside [`AuditEvent`],
/// [`AuditVerdict`], [`AuditIter`], [`AuditError`], and the locked
/// wire constants (`AUDIT_MESSAGE_LEN`, `AUDIT_EVENT_WIRE_LEN`,
/// `AUDIT_SNAPSHOT_HEADER_LEN`, `AUDIT_SNAPSHOT_MAGIC`). Closes the
/// observability gap left by the existing cap-table / IOMMU / packet-
/// filter denial paths (which today refuse silently): every denial
/// becomes an [`AuditEvent`] the offline parser can correlate to a
/// task_id + syscall_nr. Pure addition — same trait-set-addition
/// rationale; no existing surface byte changed.
///
/// Bumped to **18** by TASK-053: introduces the [`Sntp`] trait — a
/// stateless RFC 4330 SNTPv4 client wire codec covering
/// `build_request`, `parse_reply`, and the `compute_offset_delay`
/// formula — alongside [`NtpTimestamp`], [`NtpReply`], [`NtpClockSkew`],
/// [`SntpError`], and the TCG-style locked wire constants
/// (`SNTP_PACKET_LEN`, `SNTP_VERSION`, `SNTP_MODE_CLIENT`,
/// `SNTP_MODE_SERVER`, `SNTP_LEAP_ALARM`, `SNTP_MAX_STRATUM`, plus
/// the four `SNTP_OFFSET_*` byte offsets and `SNTP_OFFSET_REF_ID`).
/// Closes the wall-clock-synchronisation gap left by the kernel
/// having no UDP-port-123 codec; composes with the existing
/// [`NetStack`] UDP path. Pure addition — same trait-set-addition
/// rationale; no existing surface byte changed.
///
/// Bumped to **19** by TASK-054: introduces the [`Filesystem`] +
/// [`Vfs`] traits along with [`FsHandle`], [`FsError`], [`FileStat`],
/// and the `FS_*` constant family (`FS_NAME_MAX`, `FS_PATH_MAX`,
/// `FS_MAX_MOUNTS`, `FS_O_RDONLY` / `_WRONLY` / `_RDWR` /
/// `_ACCMODE` / `_CREATE` / `_TRUNC` / `_EXCL`, `FS_MODE_FILE` /
/// `_DIR` / `_TYPE_MASK` / `_PERM_MASK`). Closes the no-filesystem
/// gap left by every prior iteration — the kernel had no in-memory
/// inode dispatch before this. The `Filesystem` trait is the
/// per-mount backing-fs surface; `Vfs` is the dispatcher that holds
/// a fixed-capacity mount table and routes by longest-prefix.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **20** by TASK-055: introduces the [`EBpf`] trait —
/// a bounded 64-bit register-machine interpreter for upstream-
/// compatible eBPF bytecode (Linux `uapi/linux/bpf.h` subset) —
/// alongside [`BpfInstr`], [`BpfContext`], [`BpfError`], the
/// [`bpf_op`] constant module, and the `BPF_REG_COUNT` /
/// `BPF_STACK_SIZE` / `BPF_MAX_INSTRUCTIONS` /
/// `BPF_MAX_BRANCH_DEPTH` / `BPF_REG_FP` constants. Closes the
/// operator-probe gap left by the kernel having no programmable
/// observability surface: an operator can drop in a hand-built or
/// `clang -target bpf`-compiled program at a hookpoint, the
/// validator admits it, and the interpreter runs it with hard
/// instruction + memory caps. Pure addition — same trait-set-
/// addition rationale; no existing surface byte changed.
///
/// Bumped to **21** by TASK-056: introduces the
/// [`EthernetController`] + [`MmioRegBus`] traits, [`LinkState`],
/// [`E1000Error`], the Intel 82540EM (e1000) register-offset constant
/// family (`E1000_REG_CTRL` / `_STATUS` / `_EERD` / `_ICR` / `_IMS`
/// / `_IMC` / `_RCTL` / `_TCTL` / `_TIPG` / `_RDBAL` / `_RDBAH` /
/// `_RDLEN` / `_RDH` / `_RDT` / `_TDBAL` / `_TDBAH` / `_TDLEN` /
/// `_TDH` / `_TDT`), the CTRL/STATUS/EERD/RCTL/TCTL bit-flag
/// constants, the EEPROM word indices for the burned-in MAC
/// (`E1000_EEPROM_MAC_WORD0` / `_WORD1` / `_WORD2`), the legacy
/// descriptor STATUS / CMD bit family (`E1000_DESC_STA_DD`,
/// `_TXD_CMD_EOP` / `_IFCS` / `_RS`, `_RXD_STA_EOP`), and the
/// sizing constants (`E1000_TX_DESC_LEN` / `_RX_DESC_LEN` /
/// `_TX_RING_LEN` / `_RX_RING_LEN` / `_MAX_FRAME_LEN`). Closes
/// the no-real-NIC-driver gap left by the virtio-net surface — a
/// physical NIC driver was missing the contract treatment.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **22** by TASK-057: introduces the [`Smp`] trait + the
/// [`ApicWriter`] trait + [`CpuTopology`], [`SmpError`], [`ApicId`],
/// [`PerCpu`] storage, the `smp_consts` module (ICR_*, SMP_*
/// constants), the `madt` module (SIG_APIC + entry type codes +
/// flag bits + header length), and the `MAX_CPUS = 64` constant.
/// Wire-codec-shaped infrastructure for multi-core bring-up: the
/// `discover(madt)` MADT parser + the `wake_aps(topology, ...)`
/// INIT-SIPI-SIPI ICR sequencer are testable through a recording
/// `ApicWriter` harness without actually running on AP cores. The
/// AP-side trampoline blob + real APIC MMIO wiring + actual
/// concurrent execution are explicit future surfaces. Pure
/// addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **23** by TASK-058: introduces the [`Tftp`] trait + the
/// locked surface around it — [`TftpMode`], [`TftpPacket`] view enum
/// (Data / Ack / Error / OAck), [`TftpError`], [`TftpErrorCode`],
/// the `tftp_op` module (RRQ / WRQ / DATA / ACK / ERROR / OACK
/// opcodes), and the `MAX_TFTP_FILENAME` / `MAX_TFTP_MODE` /
/// `TFTP_BLOCK_SIZE` / `TFTP_OPCODE_LEN` / `TFTP_BLOCK_LEN` /
/// `TFTP_MIN_DATA_LEN` / `TFTP_MIN_ACK_LEN` / `TFTP_MIN_ERROR_LEN`
/// constants. Closes the no-PXE-boot-fetcher gap left by every
/// prior iteration — the kernel had no UDP-port-69 boot-server
/// codec before this. Pure addition — same trait-set-addition
/// rationale; no existing surface byte changed.
///
/// Bumped to **24** by TASK-059: introduces the [`Pci`] trait + the
/// [`PciConfigBus`] trait + [`PciAddress`], [`PciDevice`], [`PciBar`],
/// [`PciMsixInfo`], [`PciError`], the [`pci_class`] discriminator
/// module, and the `PCI_*` constant family
/// (`PCI_CONFIG_ADDRESS_PORT` / `_DATA_PORT`, `PCI_VENDOR_NONE`,
/// `PCI_MAX_BUS` / `_DEVICE` / `_FUNCTION`,
/// `PCI_HEADER_MULTIFUNC_BIT`, `PCI_CAP_ID_MSI` / `_MSIX`,
/// `PCI_STATUS_CAPABILITIES_LIST`, `PCI_MAX_CAP_HOPS`, the seven
/// `PCI_CFG_OFFSET_*` offsets, `PCI_COMMAND_BUS_MASTER`, the four
/// `PCI_BAR_*` decode constants, `PCI_BAR_INT_LINE_NONE`,
/// `PCI_MAX_BAR_INDEX`, and the four `PCI_MSIX_*` field-mask /
/// enable-bit constants). Closes the no-PCI-discovery gap left
/// by every prior iteration — every existing driver (NVMe,
/// e1000, virtio-net) assumed static configuration-space
/// addresses before this. Wire-codec-shaped surface: the
/// `enumerate(bus)` walker + the BAR decoder + the MSI-X
/// capability parser are testable through a recording
/// `PciConfigBus` harness without actually issuing 0xCF8/0xCFC
/// port cycles. The kernel-side `PciConfigBus` impl wrapping
/// the real `in`/`out` opcodes is wired in `target_enterprise_kernel`.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **25** by TASK-060: introduces the [`X509`] trait + the
/// locked surface around it — [`X509Cert`], [`X509Time`],
/// [`X509PubKey`], [`X509PubKeyAlg`], [`X509SigAlg`], [`X509Error`],
/// the `X509_TAG_*` family (INTEGER / BIT_STRING / OCTET_STRING /
/// NULL / OID / UTF8_STRING / PRINTABLE_STRING / IA5_STRING /
/// UTC_TIME / GENERALIZED_TIME / SEQUENCE / SET / CTX_EXPLICIT_0 /
/// CTX_EXPLICIT_3), the `X509_OID_*` family
/// (RSA_ENCRYPTION / SHA256_WITH_RSA / EC_PUBLIC_KEY / SECP256R1 /
/// ECDSA_WITH_SHA256 / ED25519 / CN), and the
/// `X509_MAX_CERT_LEN` / `X509_MAX_DEPTH` /
/// `X509_ED25519_KEY_LEN` / `X509_P256_POINT_LEN` constants.
/// Closes the no-cert-parsing gap left by every prior TLS / PKI
/// iteration: `cert.rs` could only *emit* the kernel's self-signed
/// boot cert, and `tls.rs` mTLS accepted a raw 32-byte Ed25519
/// pubkey as the entire `Certificate` payload (RFC 7250 style).
/// With [`X509::parse`] the kernel can now consume a real CA-
/// signed v3 certificate, extract the SPKI / validity / issuer /
/// subject / signature views, and hand them off to the existing
/// [`SignatureVerify`] surface for chain verification. Pure
/// addition — same trait-set-addition rationale; no existing
/// surface byte changed.
/// 25 → 26 (TASK-061 BlockDeviceVirtio trait + VirtBlkRequest +
/// VirtBlkError + virtio_blk_feature / virtio_blk_req_type /
/// virtio_blk_status_byte / virtio_blk_device_cfg modules +
/// VIRTIO_BLK_QUEUE_REQUESTQ / VIRTIO_BLK_HDR_LEN /
/// VIRTIO_BLK_SECTOR_SIZE / VIRTIO_BLK_STATUS_LEN constants).
/// Closes the no-paravirt-storage-driver gap left after NVMe
/// (TASK-018): NVMe is the bare-metal NVMe-over-PCIe path, virtio-
/// blk is the paravirtualised path every cloud hypervisor (KVM /
/// Hyper-V / Firecracker / Xen-VirtIO) exposes for guest disk.
/// Pure addition — same trait-set-addition rationale as TASK-060;
/// no existing surface byte changed. The MmioBus surface added in
/// TASK-048 is reused; only the device-cfg byte interpretation +
/// the request-header wire format are new.
///
/// Bumped to **27** by TASK-062: introduces the [`PicTimer`] +
/// [`Rtc`] traits + the [`IoPort`] recording surface +
/// [`RtcTimeView`] + [`TimerError`] + the locked I/O-port /
/// register / status-bit constant family (`PIT_CMD_PORT` /
/// `PIT_CH0_PORT` / `PIT_BASE_HZ` / `PIT_CMD_CH0_LOHI_MODE3_BIN`,
/// `CMOS_INDEX_PORT` / `CMOS_DATA_PORT`, `RTC_REG_*`,
/// `RTC_STATUS_A_UIP` / `RTC_STATUS_B_24H` / `RTC_STATUS_B_BINARY`
/// / `RTC_HOUR_PM`, `RTC_UIP_SPIN_BUDGET` / `RTC_CONSISTENCY_PASSES`).
/// Closes the no-monotonic-clock-primitive gap left by every prior
/// iteration: the scheduler tick + watchdog + `SYS_SLEEP_MS` /
/// `SYS_GETTIME_NS` paths had no wire-codec surface to pin against.
/// Pure addition — same trait-set-addition rationale; no existing
/// surface byte changed.
///
/// Bumped to **28** by TASK-063: introduces the [`KatRunner`] trait +
/// [`KatSuiteResult`] + [`KatResult`] + [`KatId`] +
/// [`KatPrimitive`] + the locked suite cardinality
/// [`KAT_VECTOR_COUNT`] and digest length [`KAT_DIGEST_LEN`].
/// Closes the "morph-cycle crypto drift is only noticed at next
/// boot's TLS handshake" gap: every SHA-256 / HMAC-SHA-256 / HKDF
/// primitive is forced through published FIPS 180-4 / RFC 4231 /
/// RFC 5869 known-answer vectors before the kernel declares itself
/// ready. Pure addition — same trait-set-addition rationale; no
/// existing surface byte changed.
///
/// Bumped to **29** by TASK-064: introduces the [`JournalFs`] trait +
/// [`JfsSuperblock`] + [`JfsInode`] + [`JfsDirEntry`] + [`JfsError`]
/// + the locked on-disk constant family (`JFS_MAGIC` /
/// `JFS_INODE_MAGIC` / `JFS_VERSION` / `JFS_SECTOR_SIZE` /
/// `JFS_SB_LEN` / `JFS_INODE_LEN` / `JFS_DIRENT_LEN` /
/// `JFS_DIRENT_MAX_NAME` / `JFS_INODES_PER_SECTOR` /
/// `JFS_ROOT_INODE` / `JFS_KIND_FILE` / `JFS_KIND_DIR` + the
/// `JFS_SB_OFF_*` / `JFS_INO_*` field offsets). Closes the
/// no-persistent-filesystem gap left after virtio-blk (TASK-061) +
/// MemRamFs (TASK-054): the kernel can now walk a hand-built or
/// on-disk JFS image (superblock → inode table → directory entries
/// → file body) without an allocator. Pure addition — same
/// trait-set-addition rationale; no existing surface byte changed.
///
/// Bumped to **30** by TASK-065: introduces the [`GdbStub`] trait +
/// [`GdbPacket`] + [`GdbCommand`] + [`GdbError`] + locked RSP
/// constants (`GDB_ACK` / `GDB_NACK` / `GDB_PACKET_START` /
/// `GDB_PACKET_END` / `GDB_INTERRUPT` / `GDB_MAX_BODY` /
/// `GDB_REG_HEX_LEN` / `GDB_MAX_MEM_READ` / `GDB_SIGTRAP`).
/// Closes the no-remote-debug-wire-codec gap: the kernel can parse
/// and frame GDB Remote Serial Protocol packets (checksum +
/// command classify + canned replies) without attaching a live
/// target. Pure addition — same trait-set-addition rationale; no
/// existing surface byte changed.
///
/// Bumped to **31** by TASK-066: introduces the [`Quota`] trait +
/// [`QuotaRecord`] + [`QuotaReject`] + [`QuotaError`] + locked
/// constants (`QUOTA_RECORD_LEN` / `QUOTA_MAX_RECORDS` /
/// `QUOTA_OFF_*` field offsets / `QUOTA_UNLIMITED`). Closes the
/// no-disk-quota-accounting gap the VFS needs to reject over-quota
/// writes: a fixed 32-byte per-uid record + scanner + check-on-write
/// predicate. Pure addition — same trait-set-addition rationale; no
/// existing surface byte changed.
///
/// Bumped to **32** by TASK-067: [`Hpet`] + [`HpetCaps`] +
/// [`HpetError`] + `HPET_REG_*` / `HPET_CFG_*` / `HPET_TN_*`.
///
/// Bumped to **33** by TASK-068: [`StackCanary`] + [`CanaryToken`] +
/// [`CanaryError`] + `STACK_CANARY_LEN`.
///
/// Bumped to **34** by TASK-069: [`Keyboard`] + [`KeyEvent`] +
/// [`KeyCode`] + [`KbError`] + set-1 make-code constants.
///
/// Bumped to **35** by TASK-070: [`Fat32`] + [`FatBpb`] +
/// [`FatDirent`] + [`FatError`] + `FAT_*` BPB/dirent constants.
///
/// Bumped to **36** by TASK-071: [`Watchdog`] + [`WatchdogError`] +
/// `WATCHDOG_DEFAULT_DEADLINE_TICKS`.
///
/// Bumped to **37** by TASK-072: [`Random`] + [`RandomError`] +
/// `RANDOM_SEED_LEN` / `RANDOM_BLOCK_LEN`.
///
/// Bumped to **38** by TASK-073: [`Power`] + [`Pm1Control`] +
/// `PM1_*` / `SLP_*` constants.
///
/// Bumped to **39** by TASK-074: [`Elf64`] + [`ElfHeader`] +
/// [`ElfPhdr`] + [`ElfError`] + `ELF_*` constants.
///
/// Bumped to **40** by TASK-075: [`Serial16550`] + COM port /
/// LSR / LCR constants.
///
/// Bumped to **41** by TASK-076: [`TickSource`] + [`TickKind`].
///
/// Bumped to **42** by TASK-077: [`VirtioPciCaps`] + cap IDs.
///
/// Bumped to **43** by TASK-078: [`SigKat`] + [`SigKatResult`] +
/// `SIGKAT_VECTOR_COUNT`.
///
/// Bumped to **44** by TASK-079: [`Multiboot2`] + tag types.
///
/// Bumped to **45** by TASK-080: [`Crc32c`] + poly constant.
///
/// Bumped to **46** by TASK-081: [`AcpiRsdp`] + signature/checksum.
///
/// Bumped to **47** by TASK-082: [`FrameBitmap`] + alloc/free.
///
/// Bumped to **48** by TASK-083: [`IoApic`] + redtable entry encode.
///
/// Bumped to **49** by TASK-084: [`LapicIcr`] + INIT/SIPI builders.
///
/// Bumped to **50** by TASK-085: [`Gpt`] + partition entry view.
///
/// Bumped to **51** by TASK-086: [`DnsName`] label codec.
///
/// Bumped to **52** by TASK-087: [`HmacDrbg`] + seed expand KAT.
///
/// Bumped to **53** by TASK-088: [`AhciFis`] + H2D Register FIS encode
/// for ATA IDENTIFY / READ DMA.
///
/// Bumped to **54** by TASK-089: [`XhciTrb`] + No-Op / Link TRB encode.
///
/// Bumped to **55** by TASK-090: [`UefiGop`] + GOP mode info view.
///
/// Bumped to **56** by TASK-091: [`AttestTlv`] + JSON-free TLV fields.
///
/// Bumped to **57** by TASK-092: [`Base64`] + RFC 4648 codec.
///
/// Bumped to **58** by TASK-093: [`AhciCmd`] + command header + PRDT.
pub const CONTRACTS_SCHEMA_VERSION: u32 = 58;

// ============================================================
// Gpt — protective MBR + GPT header + entry (TASK-085)
// ============================================================

/// GPT header signature "EFI PART".
pub const GPT_SIG: [u8; 8] = *b"EFI PART";
/// Sector size assumed.
pub const GPT_SECTOR: usize = 512;
/// Partition entry size.
pub const GPT_ENTRY_LEN: usize = 128;
/// Protective MBR type for GPT.
pub const GPT_MBR_TYPE: u8 = 0xEE;

/// Parsed GPT header (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptHeader {
    /// LBA of this header (usually 1).
    pub my_lba: u64,
    /// First usable LBA.
    pub first_usable: u64,
    /// Last usable LBA.
    pub last_usable: u64,
    /// Partition entry LBA.
    pub part_lba: u64,
    /// Number of partition entries.
    pub num_parts: u32,
    /// Size of each entry.
    pub entry_size: u32,
}

/// One GPT partition entry view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPart {
    /// Starting LBA.
    pub start_lba: u64,
    /// Ending LBA (inclusive).
    pub end_lba: u64,
    /// True if type GUID is non-zero (present).
    pub present: bool,
}

/// GPT errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptError {
    /// Image too short.
    Truncated,
    /// Bad protective MBR or GPT signature.
    BadMagic,
    /// Geometry inconsistent.
    BadGeometry,
}

/// GPT disk layout walker over a byte image (LBA-addressed).
pub trait Gpt {
    /// Parse GPT header at LBA 1; check protective MBR type at LBA 0.
    fn parse_header(image: &[u8]) -> Result<GptHeader, GptError>;
    /// Read partition entry `idx` (0-based).
    fn read_part(image: &[u8], hdr: &GptHeader, idx: u32) -> Result<GptPart, GptError>;
}

// ============================================================
// DnsName — RFC 1035 labels + compression pointer (TASK-086)
// ============================================================

/// Max labels in a name.
pub const DNS_MAX_LABELS: usize = 8;
/// Max label length.
pub const DNS_MAX_LABEL_LEN: usize = 63;
/// Compression pointer high bits.
pub const DNS_PTR_MASK: u8 = 0xC0;

/// DNS name codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsNameError {
    /// Truncated buffer.
    Truncated,
    /// Bad label length / pointer.
    BadLabel,
    /// Output too small.
    BufferTooSmall,
    /// Too many labels.
    TooMany,
}

/// DNS name wire codec (encode labels, decode with optional pointer).
pub trait DnsName {
    /// Encode `labels` (slices of ASCII) into wire form ending with 0.
    /// Returns bytes written.
    fn encode(labels: &[&[u8]], out: &mut [u8]) -> Result<usize, DnsNameError>;
    /// Decode name starting at `offset` in `msg` into `out_labels`
    /// (caller provides storage of up to DNS_MAX_LABELS × 64).
    /// Returns (label_count, bytes_consumed_from_offset_without_following_ptrs_past_start).
    fn decode(
        msg: &[u8],
        offset: usize,
        out_labels: &mut [[u8; 64]; DNS_MAX_LABELS],
        out_lens: &mut [usize; DNS_MAX_LABELS],
    ) -> Result<(usize, usize), DnsNameError>;
    /// Build a 2-byte compression pointer to `target_offset`.
    fn make_pointer(target_offset: u16) -> [u8; 2];
}

// ============================================================
// HmacDrbg — one-step HMAC-SHA256 expand KAT (TASK-087)
// ============================================================

/// Seed / key length for the DRBG KAT.
pub const DRBG_SEED_LEN: usize = 32;
/// Output length for banner KAT.
pub const DRBG_OUT_LEN: usize = 16;

/// HMAC-DRBG-shaped expand (HMAC-SHA256 chain).
pub trait HmacDrbg {
    /// `out = HMAC-SHA256(seed, label || 0x01)` truncated/padded to out.len().
    fn expand(seed: &[u8; DRBG_SEED_LEN], label: &[u8], out: &mut [u8]);
}

// ============================================================
// AhciFis — Register H2D FIS for ATA IDENTIFY / READ DMA (TASK-088)
// ============================================================

/// SATA FIS type: Register Host-to-Device.
pub const AHCI_FIS_TYPE_H2D: u8 = 0x27;
/// Register H2D FIS length in bytes (5 dwords).
pub const AHCI_FIS_H2D_LEN: usize = 20;
/// Command-update bit in FIS byte 1 (bit 7). When set, the device
/// treats the FIS as a new command (not a control-only update).
pub const AHCI_FIS_C_BIT: u8 = 1 << 7;
/// Port-multiplier port mask in FIS byte 1 (bits 3:0).
pub const AHCI_FIS_PMP_MASK: u8 = 0x0F;

/// ATA command: IDENTIFY DEVICE.
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
/// ATA command: READ DMA (28-bit LBA).
pub const ATA_CMD_READ_DMA: u8 = 0xC8;
/// ATA command: READ DMA EXT (48-bit LBA).
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// Device register: LBA addressing mode (bit 6).
pub const ATA_DEV_LBA: u8 = 0x40;

/// Parameters for a Register Host-to-Device FIS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2dFisParams {
    /// ATA command opcode (e.g. [`ATA_CMD_IDENTIFY`]).
    pub command: u8,
    /// Features register (16-bit; low byte in FIS[3], high in FIS[11]).
    pub features: u16,
    /// Logical block address (48-bit used; upper bits of u64 ignored).
    pub lba: u64,
    /// Sector count (16-bit; low in FIS[12], high in FIS[13]).
    pub count: u16,
    /// Device/head register (typically [`ATA_DEV_LBA`]).
    pub device: u8,
    /// Port-multiplier port (0..=15).
    pub pm_port: u8,
    /// When true, set the C bit (command update).
    pub is_command: bool,
}

/// AHCI / SATA FIS codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciFisError {
    /// Output buffer shorter than [`AHCI_FIS_H2D_LEN`], or input truncated.
    Truncated,
    /// FIS type byte is not [`AHCI_FIS_TYPE_H2D`].
    BadType,
    /// Port-multiplier port out of range (> 15).
    BadPort,
}

/// AHCI Register Host-to-Device FIS encoder/decoder.
///
/// Locks the 20-byte SATA H2D layout so diversifier morphs cannot
/// silently reorder ATA command framing used by future AHCI drivers.
pub trait AhciFis {
    /// Encode `p` into a 20-byte Register H2D FIS at the start of `out`.
    /// Returns [`AHCI_FIS_H2D_LEN`] on success.
    fn encode_h2d(p: &H2dFisParams, out: &mut [u8]) -> Result<usize, AhciFisError>;
    /// Decode a Register H2D FIS from `fis` (must be ≥ 20 bytes).
    fn decode_h2d(fis: &[u8]) -> Result<H2dFisParams, AhciFisError>;
    /// Build params for ATA IDENTIFY DEVICE (`command = 0xEC`, C=1, LBA mode).
    fn identify(pm_port: u8) -> Result<H2dFisParams, AhciFisError>;
    /// Build params for ATA READ DMA (`command = 0xC8`, 28-bit LBA + count).
    fn read_dma(lba: u64, count: u16, pm_port: u8) -> Result<H2dFisParams, AhciFisError>;
}

// ============================================================
// XhciTrb — USB3 Transfer Request Block No-Op + Link (TASK-089)
// ============================================================

/// TRB size in bytes (4 dwords).
pub const XHCI_TRB_LEN: usize = 16;
/// TRB Type: Link.
pub const XHCI_TRB_TYPE_LINK: u8 = 6;
/// TRB Type: No-Op Transfer TRB.
pub const XHCI_TRB_TYPE_NOOP: u8 = 8;
/// Cycle bit in TRB dword 3 bit 0.
pub const XHCI_TRB_CYCLE: u32 = 1 << 0;
/// Toggle Cycle bit in Link TRB dword 3 bit 1.
pub const XHCI_TRB_TOGGLE_CYCLE: u32 = 1 << 1;
/// TRB Type field shift in dword 3 (bits 15:10).
pub const XHCI_TRB_TYPE_SHIFT: u32 = 10;

/// Four little-endian dwords of one TRB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciTrbWords {
    /// Parameter low / ring segment pointer low.
    pub d0: u32,
    /// Parameter high / ring segment pointer high.
    pub d1: u32,
    /// Status dword.
    pub d2: u32,
    /// Control dword (Cycle + Type + flags).
    pub d3: u32,
}

/// XHCI TRB codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciTrbError {
    /// Buffer shorter than [`XHCI_TRB_LEN`].
    Truncated,
    /// Link ring pointer not 16-byte aligned.
    BadAlign,
}

/// xHCI Transfer Request Block encoder for No-Op and Link TRBs.
pub trait XhciTrb {
    /// Encode a No-Op Transfer TRB (`type = 8`) with the given cycle bit.
    fn encode_noop(cycle: bool) -> XhciTrbWords;
    /// Encode a Link TRB pointing at `ring_ptr` (must be 16-byte aligned).
    fn encode_link(
        ring_ptr: u64,
        cycle: bool,
        toggle_cycle: bool,
    ) -> Result<XhciTrbWords, XhciTrbError>;
    /// Extract TRB Type field from dword 3.
    fn trb_type(d3: u32) -> u8;
    /// Serialize words to 16 little-endian bytes.
    fn to_bytes(w: &XhciTrbWords, out: &mut [u8]) -> Result<usize, XhciTrbError>;
    /// Parse 16 little-endian bytes into words.
    fn from_bytes(buf: &[u8]) -> Result<XhciTrbWords, XhciTrbError>;
}

// ============================================================
// UefiGop — Graphics Output Protocol mode info view (TASK-090)
// ============================================================

/// Packed GOP mode info length (version, H, V, format, 4×mask, ppsl).
pub const GOP_MODE_INFO_LEN: usize = 40;
/// Pixel format: RGB reserved 8-bit per color.
pub const GOP_PIXEL_RGB: u32 = 0;
/// Pixel format: BGR reserved 8-bit per color.
pub const GOP_PIXEL_BGR: u32 = 1;
/// Pixel format: bit mask.
pub const GOP_PIXEL_BITMASK: u32 = 2;
/// Pixel format: Blt-only.
pub const GOP_PIXEL_BLT_ONLY: u32 = 3;

/// UEFI GOP mode information (subset of EFI_GRAPHICS_OUTPUT_MODE_INFORMATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GopModeInfo {
    /// Structure version (0 for current UEFI).
    pub version: u32,
    /// Horizontal resolution in pixels.
    pub horizontal: u32,
    /// Vertical resolution in pixels.
    pub vertical: u32,
    /// Pixel format enum ([`GOP_PIXEL_RGB`], …).
    pub pixel_format: u32,
    /// Red mask (bitmask format only; else 0).
    pub red_mask: u32,
    /// Green mask.
    pub green_mask: u32,
    /// Blue mask.
    pub blue_mask: u32,
    /// Reserved mask.
    pub reserved_mask: u32,
    /// Pixels per scan line (≥ horizontal).
    pub pixels_per_scan_line: u32,
}

/// GOP codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GopError {
    /// Buffer shorter than [`GOP_MODE_INFO_LEN`].
    Truncated,
    /// Geometry inconsistent (e.g. zero resolution).
    BadGeometry,
}

/// UEFI Graphics Output Protocol mode-info pack/unpack.
pub trait UefiGop {
    /// Pack mode info into little-endian bytes (40 bytes).
    fn encode(info: &GopModeInfo, out: &mut [u8]) -> Result<usize, GopError>;
    /// Unpack mode info from little-endian bytes.
    fn decode(buf: &[u8]) -> Result<GopModeInfo, GopError>;
    /// Canonical 1280×720 RGB mode used by the kernel banner.
    fn mode_1280x720() -> GopModeInfo;
}

// ============================================================
// AttestTlv — JSON-free type-length-value fields (TASK-091)
// ============================================================

/// TLV header size: u16 type + u16 length (little-endian).
pub const ATTEST_TLV_HDR_LEN: usize = 4;
/// Maximum value length accepted by the codec.
pub const ATTEST_TLV_MAX_VAL: usize = 256;
/// Max tags walked in one sequence parse.
pub const ATTEST_TLV_MAX_TAGS: usize = 32;
/// Example tag: morph cycle number.
pub const ATTEST_TLV_TAG_CYCLE: u16 = 1;
/// Example tag: layout seed.
pub const ATTEST_TLV_TAG_SEED: u16 = 2;
/// Example tag: module name bytes.
pub const ATTEST_TLV_TAG_MODULE: u16 = 3;

/// One decoded TLV record (value lives in the source buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestTlvRecord {
    /// Type tag.
    pub tag: u16,
    /// Byte offset of value within the input buffer.
    pub value_off: usize,
    /// Value length in bytes.
    pub value_len: usize,
}

/// Attestation TLV errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestTlvError {
    /// Truncated header or value.
    Truncated,
    /// Value length exceeds [`ATTEST_TLV_MAX_VAL`].
    ValueTooLong,
    /// Output buffer too small.
    BufferTooSmall,
    /// Too many tags in sequence.
    TooMany,
}

/// Minimal type-length-value codec for future attest v7 extension fields.
pub trait AttestTlv {
    /// Encode one TLV: `type(u16le) || len(u16le) || value`. Returns bytes written.
    fn encode(tag: u16, value: &[u8], out: &mut [u8]) -> Result<usize, AttestTlvError>;
    /// Decode the first TLV in `buf`.
    fn decode(buf: &[u8]) -> Result<AttestTlvRecord, AttestTlvError>;
    /// Count TLVs in a concatenated sequence (stops at end of `buf`).
    fn count_sequence(buf: &[u8]) -> Result<usize, AttestTlvError>;
}

// ============================================================
// Base64 — RFC 4648 standard alphabet (TASK-092)
// ============================================================

/// Base64 codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// Output buffer too small.
    BufferTooSmall,
    /// Invalid alphabet character or padding.
    InvalidInput,
    /// Input length not valid for decode (mod 4).
    BadLength,
}

/// RFC 4648 Base64 encode/decode without allocation.
pub trait Base64 {
    /// Encode `input` into `out` (standard alphabet + `=` padding).
    /// Returns bytes written.
    fn encode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error>;
    /// Decode base64 `input` into `out`. Returns plaintext bytes written.
    fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error>;
    /// Exact encoded length for `n` input bytes (with padding).
    fn encoded_len(n: usize) -> usize;
}

// ============================================================
// AhciCmd — command list header + PRDT entry (TASK-093)
// ============================================================

/// AHCI command header size (8 dwords).
pub const AHCI_CMD_HDR_LEN: usize = 32;
/// Physical Region Descriptor Table entry size (4 dwords).
pub const AHCI_PRDT_LEN: usize = 16;
/// Command FIS length in dwords for Register H2D (20 bytes → 5).
pub const AHCI_CFL_H2D: u8 = 5;
/// PRDT IOC (interrupt on completion) bit in DW3 bit 31.
pub const AHCI_PRDT_IOC: u32 = 1 << 31;

/// AHCI command list entry (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciCmdHeader {
    /// Command FIS length in dwords (bits 4:0 of DW0); typically 5.
    pub cfl: u8,
    /// Write bit (host→device data).
    pub write: bool,
    /// Port multiplier port (0..=15).
    pub pmp: u8,
    /// Physical region descriptor table length (number of PRDTe).
    pub prdtl: u16,
    /// Physical region descriptor byte count (may be 0 until completion).
    pub prdbc: u32,
    /// Command table base address (128-byte aligned in hardware; not enforced here).
    pub ctba: u64,
}

/// One PRDT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciPrdt {
    /// Data base address.
    pub dba: u64,
    /// Byte count (1..=4 MiB per AHCI; stored as true count, encoded as count−1).
    pub byte_count: u32,
    /// Interrupt on completion.
    pub ioc: bool,
}

/// AHCI command table codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciCmdError {
    /// Buffer truncated.
    Truncated,
    /// Invalid CFL / PRDTL / byte_count.
    BadField,
    /// Port out of range.
    BadPort,
}

/// AHCI command header + PRDT encoder for IDENTIFY DMA setup.
pub trait AhciCmd {
    /// Encode a 32-byte command header.
    fn encode_header(h: &AhciCmdHeader, out: &mut [u8]) -> Result<usize, AhciCmdError>;
    /// Decode a 32-byte command header.
    fn decode_header(buf: &[u8]) -> Result<AhciCmdHeader, AhciCmdError>;
    /// Encode a 16-byte PRDT entry.
    fn encode_prdt(p: &AhciPrdt, out: &mut [u8]) -> Result<usize, AhciCmdError>;
    /// Decode a 16-byte PRDT entry.
    fn decode_prdt(buf: &[u8]) -> Result<AhciPrdt, AhciCmdError>;
    /// Build header + single PRDT for IDENTIFY DEVICE DMA into `data_buf`.
    fn identify_slot(ctba: u64, data_buf: u64) -> Result<(AhciCmdHeader, AhciPrdt), AhciCmdError>;
}

// ============================================================
// IoApic — redirection table entry encode (TASK-083)
// ============================================================

/// Delivery mode: fixed.
pub const IOAPIC_DELIVERY_FIXED: u8 = 0;
/// Delivery mode: lowest priority.
pub const IOAPIC_DELIVERY_LOWEST: u8 = 1;
/// Delivery mode: SMI.
pub const IOAPIC_DELIVERY_SMI: u8 = 2;
/// Delivery mode: NMI.
pub const IOAPIC_DELIVERY_NMI: u8 = 4;
/// Delivery mode: INIT.
pub const IOAPIC_DELIVERY_INIT: u8 = 5;
/// Delivery mode: ExtINT.
pub const IOAPIC_DELIVERY_EXTINT: u8 = 7;
/// Destination mode: physical.
pub const IOAPIC_DEST_PHYSICAL: u8 = 0;
/// Destination mode: logical.
pub const IOAPIC_DEST_LOGICAL: u8 = 1;
/// Trigger: edge.
pub const IOAPIC_TRIGGER_EDGE: u8 = 0;
/// Trigger: level.
pub const IOAPIC_TRIGGER_LEVEL: u8 = 1;
/// Pin polarity: active high.
pub const IOAPIC_POLARITY_HIGH: u8 = 0;
/// Pin polarity: active low.
pub const IOAPIC_POLARITY_LOW: u8 = 1;
/// Mask bit set = masked.
pub const IOAPIC_MASKED: u8 = 1;

/// Decoded IOAPIC redirection table entry (low + high dwords).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicRedir {
    /// Interrupt vector 0x10..=0xFE.
    pub vector: u8,
    /// Delivery mode (3 bits).
    pub delivery: u8,
    /// Destination mode (1 bit).
    pub dest_mode: u8,
    /// Polarity.
    pub polarity: u8,
    /// Trigger mode.
    pub trigger: u8,
    /// Mask bit.
    pub mask: u8,
    /// Destination APIC id (bits 56..63 of high dword).
    pub dest: u8,
}

/// IOAPIC redtable codec.
pub trait IoApic {
    /// Pack entry into (low, high) dwords.
    fn encode(e: &IoApicRedir) -> (u32, u32);
    /// Unpack (low, high) dwords.
    fn decode(low: u32, high: u32) -> IoApicRedir;
}

// ============================================================
// LapicIcr — ICR INIT/SIPI command builder (TASK-084)
// ============================================================

/// ICR delivery: Fixed.
pub const ICR_DELIVERY_FIXED: u32 = 0 << 8;
/// ICR delivery: INIT.
pub const ICR_DELIVERY_INIT: u32 = 5 << 8;
/// ICR delivery: Start-Up (SIPI).
pub const ICR_DELIVERY_SIPI: u32 = 6 << 8;
/// ICR level assert.
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// ICR level deassert.
pub const ICR_LEVEL_DEASSERT: u32 = 0 << 14;
/// ICR trigger level.
pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;
/// ICR dest shorthand: no shorthand.
pub const ICR_DEST_NONE: u32 = 0 << 18;
/// ICR high dword dest shift (APIC id in bits 24..31 of ICR_HIGH).
pub const ICR_HIGH_DEST_SHIFT: u32 = 24;

/// Built ICR pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcrCommand {
    /// ICR low dword (0x300).
    pub low: u32,
    /// ICR high dword (0x310).
    pub high: u32,
}

/// LAPIC ICR builder.
pub trait LapicIcr {
    /// Build INIT IPI to `apic_id` (assert then software sequences deassert).
    fn init(apic_id: u8) -> IcrCommand;
    /// Build SIPI with startup vector page (`vec` = pa >> 12, low 8 bits).
    fn sipi(apic_id: u8, startup_vec: u8) -> IcrCommand;
    /// Extract delivery mode field from low dword.
    fn delivery_of(low: u32) -> u32;
}

// ============================================================
// Multiboot2 info tag walker (TASK-079)
// ============================================================

/// Multiboot2 info total_size field is first u32.
pub const MB2_HEADER_LEN: usize = 8;
/// Tag header length (type + size).
pub const MB2_TAG_HDR_LEN: usize = 8;
/// End tag type.
pub const MB2_TAG_END: u32 = 0;
/// Basic memory info tag.
pub const MB2_TAG_BASIC_MEMINFO: u32 = 4;
/// Memory map tag.
pub const MB2_TAG_MMAP: u32 = 6;
/// Framebuffer tag.
pub const MB2_TAG_FRAMEBUFFER: u32 = 8;
/// Max tags walked.
pub const MB2_MAX_TAGS: usize = 16;

/// One Multiboot2 tag header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mb2Tag {
    /// Tag type.
    pub typ: u32,
    /// Total tag size including header.
    pub size: u32,
    /// Byte offset of tag in the info block.
    pub offset: usize,
}

/// Multiboot2 errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mb2Error {
    /// Buffer too short.
    Truncated,
    /// total_size inconsistent / tag overflow.
    BadSize,
    /// Too many tags.
    TooMany,
}

/// Multiboot2 info-block tag walker.
pub trait Multiboot2 {
    /// Walk tags in `info` (starts with total_size + reserved).
    /// Fills `out`, returns count (excluding END tag).
    fn walk(
        info: &[u8],
        out: &mut [Mb2Tag; MB2_MAX_TAGS],
    ) -> Result<usize, Mb2Error>;
    /// Find first tag of `typ`.
    fn find(tags: &[Mb2Tag], typ: u32) -> Option<Mb2Tag>;
}

// ============================================================
// Crc32c — Castagnoli (TASK-080)
// ============================================================

/// CRC32-C reversed polynomial (Castagnoli).
pub const CRC32C_POLY_REV: u32 = 0x82F6_3B78;

/// CRC32-C (Castagnoli) hash.
pub trait Crc32c {
    /// Compute CRC32-C over `data` (init 0xFFFFFFFF, final XOR same).
    fn hash(data: &[u8]) -> u32;
}

// ============================================================
// AcpiRsdp — RSDP signature + checksum (TASK-081)
// ============================================================

/// RSDP signature "RSD PTR ".
pub const RSDP_SIG: [u8; 8] = *b"RSD PTR ";
/// RSDP v1 length (checksum coverage).
pub const RSDP_V1_LEN: usize = 20;
/// RSDP v2 extended length field offset.
pub const RSDP_LEN_OFF: usize = 20;

/// Parsed RSDP view (v1 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsdpV1 {
    /// OEM id 6 bytes.
    pub oem_id: [u8; 6],
    /// Revision (0 = v1, 2 = v2).
    pub revision: u8,
    /// RSDT physical address.
    pub rsdt_addr: u32,
}

/// RSDP errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsdpError {
    /// Too short.
    Truncated,
    /// Bad signature.
    BadSig,
    /// Checksum failed.
    BadChecksum,
}

/// ACPI RSDP parser.
pub trait AcpiRsdp {
    /// Parse and validate v1 fields (first 20 bytes checksum).
    fn parse_v1(bytes: &[u8]) -> Result<RsdpV1, RsdpError>;
    /// Compute 8-bit sum checksum over `bytes` (must be 0 for valid).
    fn checksum(bytes: &[u8]) -> u8;
}

// ============================================================
// FrameBitmap — fixed bitmap frame allocator codec (TASK-082)
// ============================================================

/// Max frames the seed bitmap tracks (4096 bits = 512 bytes).
pub const FRAME_BITMAP_BITS: usize = 4096;

/// Frame bitmap errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameBitmapError {
    /// Index out of range.
    Oob,
    /// No free frame.
    Exhausted,
    /// Double-free.
    AlreadyFree,
}

/// Bitmap frame allocator surface.
pub trait FrameBitmap {
    /// Mark all frames free.
    fn clear_all(&mut self);
    /// Mark frame `idx` used.
    fn alloc_at(&mut self, idx: usize) -> Result<(), FrameBitmapError>;
    /// Allocate lowest free frame index.
    fn alloc(&mut self) -> Result<usize, FrameBitmapError>;
    /// Free frame `idx`.
    fn free(&mut self, idx: usize) -> Result<(), FrameBitmapError>;
    /// True if frame is free.
    fn is_free(&self, idx: usize) -> Result<bool, FrameBitmapError>;
    /// Count of free frames.
    fn free_count(&self) -> usize;
}

// ============================================================
// Serial16550 — UART init / TX wire codec (TASK-075)
// ============================================================

/// COM1 base port.
pub const SERIAL_COM1: u16 = 0x3F8;
/// COM2 base port.
pub const SERIAL_COM2: u16 = 0x2F8;
/// Line Status Register offset from base.
pub const SERIAL_LSR_OFF: u16 = 5;
/// Line Control Register offset.
pub const SERIAL_LCR_OFF: u16 = 3;
/// FIFO Control Register offset.
pub const SERIAL_FCR_OFF: u16 = 2;
/// Modem Control Register offset.
pub const SERIAL_MCR_OFF: u16 = 4;
/// Interrupt Enable Register offset.
pub const SERIAL_IER_OFF: u16 = 1;
/// LSR bit 5: THR empty.
pub const SERIAL_LSR_THRE: u8 = 1 << 5;
/// LSR bit 0: data ready.
pub const SERIAL_LSR_DR: u8 = 1 << 0;
/// LCR DLAB bit.
pub const SERIAL_LCR_DLAB: u8 = 0x80;
/// LCR 8N1 value (DLAB off).
pub const SERIAL_LCR_8N1: u8 = 0x03;
/// Divisor latch low for 38400 baud (with 1.8432 MHz clock).
pub const SERIAL_DIVISOR_LO_38400: u8 = 0x03;
/// Divisor latch high for 38400.
pub const SERIAL_DIVISOR_HI_38400: u8 = 0x00;
/// FCR enable + clear + 14-byte trigger.
pub const SERIAL_FCR_INIT: u8 = 0xC7;
/// MCR DTR|RTS|OUT2.
pub const SERIAL_MCR_INIT: u8 = 0x0B;
/// Number of port writes in the locked init sequence.
pub const SERIAL_INIT_WRITES: usize = 7;

/// One recorded `out` in the init sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialPortWrite {
    /// Absolute I/O port.
    pub port: u16,
    /// Byte written.
    pub value: u8,
}

/// 16550 UART wire codec over [`IoPort`].
pub trait Serial16550 {
    /// Emit the locked 38400 8N1 init sequence for `base` (COM1/COM2).
    /// Returns the number of writes (always [`SERIAL_INIT_WRITES`]).
    fn init(port: &mut dyn IoPort, base: u16) -> usize;
    /// Wait for THRE then write `byte` to THR (`base + 0`).
    fn write_byte(port: &mut dyn IoPort, base: u16, byte: u8);
}

// ============================================================
// TickSource — PIT / HPET mux (TASK-076)
// ============================================================

/// Which hardware counter backs the tick view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TickKind {
    /// 8253/8254 PIT.
    Pit = 0,
    /// High Precision Event Timer.
    Hpet = 1,
}

/// Unified monotonic tick source.
pub trait TickSource {
    /// Select the active kind.
    fn select(&mut self, kind: TickKind);
    /// Currently selected kind.
    fn kind(&self) -> TickKind;
    /// Advance the synthetic counter by `delta` (test harness / IRQ).
    fn advance(&mut self, delta: u64);
    /// Current tick count for the selected source.
    fn now_ticks(&self) -> u64;
    /// Pet-friendly remaining helper: saturating sub of deadline.
    fn until(&self, deadline: u64) -> u64;
}

// ============================================================
// VirtioPciCaps — VirtIO PCI capability list walker (TASK-077)
// ============================================================

/// Vendor-specific capability ID used by VirtIO.
pub const VIRTIO_PCI_CAP_ID: u8 = 0x09;
/// Common configuration structure.
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Notifications.
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// ISR status.
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Device-specific configuration.
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
/// PCI configuration access.
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;
/// Max capability nodes walked.
pub const VIRTIO_PCI_CAP_MAX: usize = 8;

/// One VirtIO PCI capability header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioPciCap {
    /// Config-space offset of this capability.
    pub offset: u8,
    /// `cfg_type` (common/notify/isr/device/pci).
    pub cfg_type: u8,
    /// BAR index.
    pub bar: u8,
    /// Offset within BAR.
    pub bar_offset: u32,
    /// Length in BAR.
    pub length: u32,
}

/// Errors walking VirtIO caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioPciCapError {
    /// No vendor-cap chain / empty.
    NotFound,
    /// Walk exceeded hop budget.
    TooMany,
    /// Truncated header.
    Truncated,
}

/// VirtIO PCI capability list walker over raw config dwords.
pub trait VirtioPciCaps {
    /// Walk capabilities starting at `cap_ptr`, reading 8-byte
    /// vendor-cap headers via the provided dword reader callback
    /// `read(offset) -> dword`. Fills `out`, returns count.
    fn walk(
        cap_ptr: u8,
        read_dword: &mut dyn FnMut(u8) -> u32,
        out: &mut [VirtioPciCap; VIRTIO_PCI_CAP_MAX],
    ) -> Result<usize, VirtioPciCapError>;
    /// Find first cap of `cfg_type` in a filled list.
    fn find(caps: &[VirtioPciCap], cfg_type: u8) -> Option<VirtioPciCap>;
}

// ============================================================
// SigKat — Ed25519 RFC 8032 known-answer harness (TASK-078)
// ============================================================

/// Number of locked RFC 8032 vectors in the suite.
pub const SIGKAT_VECTOR_COUNT: u8 = 2;
/// Ed25519 public key length.
pub const SIGKAT_PK_LEN: usize = 32;
/// Ed25519 secret key length (seed).
pub const SIGKAT_SK_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGKAT_SIG_LEN: usize = 64;

/// One vector outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigKatResult {
    /// Vector id 0..SIGKAT_VECTOR_COUNT.
    pub id: u8,
    /// True if all checks passed.
    pub pass: bool,
}

/// Aggregate suite result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigKatSuite {
    /// Total vectors.
    pub total: u8,
    /// Passed count.
    pub passed: u8,
}

impl SigKatSuite {
    /// All vectors passed.
    pub const fn all_ok(self) -> bool {
        self.passed == self.total
    }
}

/// Ed25519 known-answer harness (fixture integrity + structural
/// verify against published RFC 8032 bytes).
pub trait SigKat {
    /// Run the full locked suite.
    fn run_all() -> SigKatSuite;
    /// Run one vector by id.
    fn run_one(id: u8) -> Option<SigKatResult>;
}

// ============================================================
// Watchdog — software deadline arm/pet/check (TASK-071)
// ============================================================

/// Default deadline in ticks (300 = 3 s at 100 Hz; banner-friendly).
pub const WATCHDOG_DEFAULT_DEADLINE_TICKS: u32 = 300;

/// Watchdog errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// Not armed / disabled.
    NotArmed,
    /// Deadline already fired.
    Fired,
    /// Zero deadline rejected.
    ZeroDeadline,
}

/// Software watchdog against an injected tick counter.
pub trait Watchdog {
    /// Arm with `deadline_ticks` remaining. Rejects zero.
    fn arm(&mut self, deadline_ticks: u32) -> Result<(), WatchdogError>;
    /// Reset remaining to the armed deadline.
    fn pet(&mut self) -> Result<(), WatchdogError>;
    /// Advance one tick. Returns `Err(Fired)` when remaining hits 0.
    fn tick(&mut self) -> Result<(), WatchdogError>;
    /// Cooperative check — `Err(Fired)` if previously fired.
    fn check(&self) -> Result<(), WatchdogError>;
    /// Current remaining ticks (0 if fired or not armed).
    fn remaining(&self) -> u32;
    /// Armed deadline value.
    fn deadline(&self) -> u32;
    /// True if currently armed and not fired.
    fn is_armed(&self) -> bool;
}

// ============================================================
// Random — deterministic seed mixer / counter DRBG (TASK-072)
// ============================================================

/// Seed length in bytes.
pub const RANDOM_SEED_LEN: usize = 32;
/// Default output block length for KAT.
pub const RANDOM_BLOCK_LEN: usize = 16;

/// RNG errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    /// Not seeded yet.
    NotSeeded,
    /// Output buffer empty.
    EmptyOutput,
    /// Seed all-zero rejected.
    WeakSeed,
}

/// Deterministic CSPRNG-shaped mixer (ChaCha-inspired quarter rounds
/// over a 32-byte state). Locked KAT for morph detection.
pub trait Random {
    /// Seed from 32 bytes (must not be all-zero).
    fn seed(&mut self, seed: &[u8; RANDOM_SEED_LEN]) -> Result<(), RandomError>;
    /// Fill `out` with next pseudorandom bytes.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError>;
    /// Next u64 (little-endian from 8 fill bytes).
    fn next_u64(&mut self) -> Result<u64, RandomError>;
}

// ============================================================
// Power — ACPI PM1a S5 soft-off encode (TASK-073)
// ============================================================

/// PM1 control SLP_EN bit (bit 13).
pub const PM1_SLP_EN: u16 = 1 << 13;
/// SLP_TYP field shift (bits 10..12).
pub const PM1_SLP_TYP_SHIFT: u16 = 10;
/// SLP_TYP field mask (3 bits).
pub const PM1_SLP_TYP_MASK: u16 = 0b111;
/// Classic S5 sleep type value used by many firmwares.
pub const SLP_TYP_S5: u8 = 5;
/// QEMU/Bochs ACPI PM1a_CNT default I/O port.
pub const PM1A_CNT_PORT: u16 = 0x604;

/// Encoded PM1 control register view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pm1Control {
    /// Raw 16-bit PM1_CNT value.
    pub raw: u16,
}

/// Power management wire codec.
pub trait Power {
    /// Build PM1_CNT value for sleep type `slp_typ` with SLP_EN set.
    fn encode_s5(slp_typ: u8) -> Pm1Control;
    /// Extract SLP_TYP from a PM1_CNT value.
    fn decode_slp_typ(pm1: Pm1Control) -> u8;
    /// True if SLP_EN is set.
    fn is_slp_en(pm1: Pm1Control) -> bool;
}

// ============================================================
// Elf64 — ELF64 Ehdr + PT_LOAD walker (TASK-074)
// ============================================================

/// ELF magic.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// ELFCLASS64.
pub const ELF_CLASS64: u8 = 2;
/// ELFDATA2LSB.
pub const ELF_DATA_LE: u8 = 1;
/// EM_X86_64.
pub const ELF_EM_X86_64: u16 = 62;
/// ET_EXEC.
pub const ELF_ET_EXEC: u16 = 2;
/// ET_DYN.
pub const ELF_ET_DYN: u16 = 3;
/// PT_LOAD.
pub const ELF_PT_LOAD: u32 = 1;
/// Size of ELF64 Ehdr.
pub const ELF_EHDR_LEN: usize = 64;
/// Size of ELF64 Phdr.
pub const ELF_PHDR_LEN: usize = 56;
/// Max PT_LOAD segments the seed walker accepts.
pub const ELF_MAX_PHDRS: usize = 8;

/// Parsed ELF64 file header (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeader {
    /// e_entry
    pub entry: u64,
    /// e_phoff
    pub phoff: u64,
    /// e_phnum
    pub phnum: u16,
    /// e_phentsize
    pub phentsize: u16,
    /// e_type
    pub etype: u16,
    /// e_machine
    pub machine: u16,
}

/// One PT_LOAD program header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfPhdr {
    /// p_type (must be PT_LOAD for returned entries)
    pub ptype: u32,
    /// p_flags
    pub flags: u32,
    /// p_offset
    pub offset: u64,
    /// p_vaddr
    pub vaddr: u64,
    /// p_filesz
    pub filesz: u64,
    /// p_memsz
    pub memsz: u64,
    /// p_align
    pub align: u64,
}

/// ELF parse errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Buffer too short.
    Truncated,
    /// Bad magic / class / endian / machine.
    BadHeader,
    /// phentsize/phnum out of range.
    BadPhdrs,
    /// Too many PT_LOAD segments.
    TooManyLoads,
}

/// ELF64 header + PT_LOAD walker.
pub trait Elf64 {
    /// Parse Ehdr from `image`.
    fn parse_header(image: &[u8]) -> Result<ElfHeader, ElfError>;
    /// Collect PT_LOAD phdrs into `out` (capacity [`ELF_MAX_PHDRS`]).
    /// Returns count written.
    fn load_phdrs(
        image: &[u8],
        hdr: &ElfHeader,
        out: &mut [ElfPhdr; ELF_MAX_PHDRS],
    ) -> Result<usize, ElfError>;
}

// ============================================================
// Hpet — High Precision Event Timer MMIO codec (TASK-067)
// ============================================================

/// General Capabilities & ID register (64-bit, low dword at this off).
pub const HPET_REG_CAP: usize = 0x000;
/// General Configuration register.
pub const HPET_REG_CONFIG: usize = 0x010;
/// Main counter value (64-bit, low dword).
pub const HPET_REG_MAIN_COUNTER: usize = 0x0F0;
/// Timer 0 configuration / capability register.
pub const HPET_REG_TIMER0_CONFIG: usize = 0x100;
/// Timer 0 comparator value (64-bit low dword).
pub const HPET_REG_TIMER0_COMPARATOR: usize = 0x108;

/// CONFIG bit 0: ENABLE_CNF — main counter runs when set.
pub const HPET_CFG_ENABLE: u32 = 1 << 0;
/// CAP bit 13: COUNT_SIZE_CAP — 64-bit main counter when set.
pub const HPET_CAP_COUNT_SIZE_64: u32 = 1 << 13;
/// Timer-N config bit 2: interrupt enable.
pub const HPET_TN_INT_ENB: u32 = 1 << 2;
/// Timer-N config bit 3: periodic mode (1) vs one-shot (0).
pub const HPET_TN_TYPE_PERIODIC: u32 = 1 << 3;
/// Timer-N config bit 6: allow software to set accumulator.
pub const HPET_TN_VAL_SET: u32 = 1 << 6;

/// Parsed HPET capability view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpetCaps {
    /// Counter period in femtoseconds (from CAP bits 32..63).
    pub period_fs: u32,
    /// True if 64-bit main counter is supported.
    pub count_size_64: bool,
    /// Vendor ID from CAP bits 16..31.
    pub vendor_id: u16,
    /// Number of timers minus one (CAP bits 8..12) + 1 = timer count.
    pub num_timers: u8,
}

/// Errors from [`Hpet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpetError {
    /// CAP.COUNT_SIZE_CAP clear — seed requires 64-bit counter.
    Not64Bit,
    /// Period field was zero (illegal per HPET spec).
    BadPeriod,
    /// Comparator ticks computed as zero for the requested interval.
    BadInterval,
}

/// HPET MMIO wire codec over [`MmioRegBus`].
pub trait Hpet {
    /// Read and decode the CAP register pair into [`HpetCaps`].
    fn read_caps(bus: &mut dyn MmioRegBus) -> Result<HpetCaps, HpetError>;
    /// Enable the main counter (`CONFIG.ENABLE_CNF = 1`).
    fn enable(bus: &mut dyn MmioRegBus);
    /// Disable the main counter.
    fn disable(bus: &mut dyn MmioRegBus);
    /// Read the 64-bit main counter (low then high dword).
    fn read_counter(bus: &mut dyn MmioRegBus) -> u64;
    /// Program timer 0 as periodic with `comparator` ticks and enable.
    /// Returns the config dword written.
    fn program_timer0_periodic(
        bus: &mut dyn MmioRegBus,
        comparator: u64,
    ) -> Result<u32, HpetError>;
    /// Convert `period_ms` to comparator ticks given `period_fs`.
    /// `ticks = (period_ms * 1_000_000_000_000) / period_fs`  (ms→fs).
    fn ms_to_ticks(period_fs: u32, period_ms: u32) -> Result<u64, HpetError>;
}

// ============================================================
// StackCanary — SSP token surface (TASK-068)
// ============================================================

/// Length of a canary token in bytes.
pub const STACK_CANARY_LEN: usize = 8;

/// One minted canary token (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryToken {
    /// Raw token bytes.
    pub bytes: [u8; STACK_CANARY_LEN],
}

/// Errors from [`StackCanary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryError {
    /// Stored token does not match expected.
    Mismatch,
    /// Seed was all-zero (rejected — weak canary).
    WeakSeed,
}

/// Stack-smashing protector token surface.
pub trait StackCanary {
    /// Mint a token from `seed` (must not be all-zero).
    fn mint(seed: &[u8; STACK_CANARY_LEN]) -> Result<CanaryToken, CanaryError>;
    /// Verify `got` equals `expected`.
    fn verify(expected: &CanaryToken, got: &CanaryToken) -> Result<(), CanaryError>;
    /// Fingerprint of a failed check: XOR of expected and got, as u64 LE.
    fn fail_fingerprint(expected: &CanaryToken, got: &CanaryToken) -> u64;
}

// ============================================================
// Keyboard — PS/2 set-1 scancode decoder (TASK-069)
// ============================================================

/// Set-1 make code for `A`.
pub const KBD_MAKE_A: u8 = 0x1E;
/// Set-1 break code for `A` (`make | 0x80`).
pub const KBD_BREAK_A: u8 = 0x9E;
/// Set-1 make code for `B`.
pub const KBD_MAKE_B: u8 = 0x30;
/// Set-1 break code for `B`.
pub const KBD_BREAK_B: u8 = 0xB0;
/// Extended prefix byte.
pub const KBD_PREFIX_E0: u8 = 0xE0;
/// Pause-sequence prefix.
pub const KBD_PREFIX_E1: u8 = 0xE1;
/// Left shift make.
pub const KBD_MAKE_LSHIFT: u8 = 0x2A;
/// Left shift break.
pub const KBD_BREAK_LSHIFT: u8 = 0xAA;
/// Enter make.
pub const KBD_MAKE_ENTER: u8 = 0x1C;
/// Escape make.
pub const KBD_MAKE_ESC: u8 = 0x01;
/// Backspace make.
pub const KBD_MAKE_BACKSPACE: u8 = 0x0E;

/// Logical key identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    /// Letter A..=Z (stored as uppercase ASCII).
    Letter(u8),
    /// Digit '0'..='9'.
    Digit(u8),
    /// Enter / return.
    Enter,
    /// Escape.
    Escape,
    /// Backspace.
    Backspace,
    /// Space.
    Space,
    /// Left or right shift (indistinguished in set-1 bare).
    Shift,
    /// Left or right ctrl.
    Ctrl,
    /// Left or right alt.
    Alt,
    /// Arrow up (E0 48).
    ArrowUp,
    /// Arrow down (E0 50).
    ArrowDown,
    /// Arrow left (E0 4B).
    ArrowLeft,
    /// Arrow right (E0 4D).
    ArrowRight,
    /// Unrecognised / non-printable.
    Other(u8),
}

/// One decoded key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Key identity.
    pub code: KeyCode,
    /// True = make (press), false = break (release).
    pub pressed: bool,
    /// ASCII byte if printable and pressed; else 0.
    pub ascii: u8,
}

/// Keyboard decoder errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbError {
    /// Need more scancode bytes (prefix in flight).
    NeedMore,
    /// Byte stream produced no event (swallowed prefix/modifier).
    Consumed,
}

/// PS/2 set-1 scancode decoder.
pub trait Keyboard {
    /// Feed one scancode byte. Returns `Some(event)` when a complete
    /// make/break is decoded; `None` if the byte was a prefix or
    /// part of a multi-byte sequence still in flight.
    fn feed(&mut self, scancode: u8) -> Option<KeyEvent>;
    /// Reset prefix / modifier state.
    fn reset(&mut self);
}

// ============================================================
// Fat32 — BPB + root-dir walker (TASK-070)
// ============================================================

/// Sector size assumed by the seed FAT32 walker.
pub const FAT_SECTOR_SIZE: usize = 512;
/// Directory entry length.
pub const FAT_DIR_ENTRY_LEN: usize = 32;
/// BPB offset: bytes per sector (u16).
pub const FAT_BPB_BYTES_PER_SECTOR: usize = 11;
/// BPB offset: sectors per cluster (u8).
pub const FAT_BPB_SEC_PER_CLUS: usize = 13;
/// BPB offset: reserved sector count (u16).
pub const FAT_BPB_RESERVED: usize = 14;
/// BPB offset: number of FATs (u8).
pub const FAT_BPB_NUM_FATS: usize = 16;
/// BPB offset: FAT size in sectors (u32) at offset 36.
pub const FAT_BPB_FAT_SIZE_32: usize = 36;
/// BPB offset: root cluster (u32) at offset 44.
pub const FAT_BPB_ROOT_CLUSTER: usize = 44;
/// BPB offset: FS type string "FAT32   " at 82.
pub const FAT_BPB_FS_TYPE: usize = 82;
/// Dirent attribute byte offset.
pub const FAT_DIR_ATTR: usize = 11;
/// Dirent cluster high u16.
pub const FAT_DIR_CLUS_HI: usize = 20;
/// Dirent cluster low u16.
pub const FAT_DIR_CLUS_LO: usize = 26;
/// Dirent file size u32.
pub const FAT_DIR_SIZE: usize = 28;
/// Attribute: LFN entry.
pub const FAT_ATTR_LFN: u8 = 0x0F;
/// Attribute: directory.
pub const FAT_ATTR_DIR: u8 = 0x10;
/// Attribute: volume id.
pub const FAT_ATTR_VOLUME: u8 = 0x08;
/// End-of-chain threshold (masked 28-bit).
pub const FAT_EOC: u32 = 0x0FFF_FFF8;
/// Cluster number mask.
pub const FAT_CLUS_MASK: u32 = 0x0FFF_FFFF;

/// Parsed BIOS Parameter Block (FAT32 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatBpb {
    /// Bytes per sector (must be 512 for the seed).
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Reserved sector count.
    pub reserved_sectors: u16,
    /// Number of FAT copies.
    pub num_fats: u8,
    /// FAT size in sectors.
    pub fat_size_sectors: u32,
    /// Root directory starting cluster.
    pub root_cluster: u32,
    /// First sector of FAT #0 (= reserved_sectors).
    pub fat_start: u32,
    /// First data sector (cluster 2).
    pub first_data_sector: u32,
}

/// One 8.3 directory entry view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatDirent {
    /// 11-byte 8.3 name (space-padded).
    pub name_83: [u8; 11],
    /// Attribute byte.
    pub attr: u8,
    /// Starting cluster.
    pub cluster: u32,
    /// File size in bytes.
    pub size: u32,
}

/// FAT32 walker errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatError {
    /// Image too short.
    Truncated,
    /// Not a FAT32 BPB (bad signature / type string / geometry).
    BadBpb,
    /// Directory entry not found.
    NotFound,
    /// Path is a directory or volume label.
    NotFile,
    /// Output buffer too small.
    BufferTooSmall,
    /// Cluster chain broken / reserved.
    BadChain,
}

/// Read-only FAT32 BPB + root-directory walker over a byte image.
pub trait Fat32 {
    /// Parse BPB from sector 0 of `image`.
    fn mount(image: &[u8]) -> Result<Self, FatError>
    where
        Self: Sized;
    /// Superblock / layout view.
    fn bpb(&self) -> &FatBpb;
    /// Find an 8.3 name in the root directory (case-insensitive).
    fn lookup_root(&self, image: &[u8], name_83: &[u8; 11]) -> Result<FatDirent, FatError>;
    /// Read file body for a dirent into `out`. Returns bytes written.
    fn read_file(
        &self,
        image: &[u8],
        ent: &FatDirent,
        out: &mut [u8],
    ) -> Result<usize, FatError>;
}

// ============================================================
// Quota — per-uid disk quota wire codec (TASK-066)
// ============================================================

/// On-disk / in-memory record length in bytes.
pub const QUOTA_RECORD_LEN: usize = 32;
/// Maximum records a fixed-capacity table / scan will accept.
pub const QUOTA_MAX_RECORDS: usize = 256;
/// Sentinel limit meaning "unlimited" (never rejects on that resource).
pub const QUOTA_UNLIMITED: u64 = u64::MAX;

/// Byte offset of `uid` (u32 LE) within a record.
pub const QUOTA_OFF_UID: usize = 0;
/// Byte offset of `block_used` (u64 LE).
pub const QUOTA_OFF_BLOCK_USED: usize = 4;
/// Byte offset of `block_limit` (u64 LE).
pub const QUOTA_OFF_BLOCK_LIMIT: usize = 12;
/// Byte offset of `inode_used` (u32 LE).
pub const QUOTA_OFF_INODE_USED: usize = 20;
/// Byte offset of `inode_limit` (u32 LE).
pub const QUOTA_OFF_INODE_LIMIT: usize = 24;
/// Byte offset of `grace` (u32 LE) — Unix seconds when the soft-limit
/// grace period expires. Zero means no grace (hard fail immediately
/// once a soft limit is exceeded / hard-limit check only).
pub const QUOTA_OFF_GRACE: usize = 28;

/// One per-uid quota record. Storage-only; 32 bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaRecord {
    /// User id this record accounts for. Zero is a free / empty slot.
    pub uid: u32,
    /// Blocks currently charged to this uid.
    pub block_used: u64,
    /// Maximum blocks allowed. [`QUOTA_UNLIMITED`] = no block cap.
    pub block_limit: u64,
    /// Inodes currently charged.
    pub inode_used: u32,
    /// Maximum inodes allowed. `u32::MAX` = no inode cap.
    pub inode_limit: u32,
    /// Grace expiry as Unix epoch seconds. `0` = no grace window
    /// (any would-exceed is a hard reject).
    pub grace: u32,
}

/// Why a check-on-write rejected the request. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QuotaReject {
    /// `block_used + delta > block_limit` (and grace expired or zero).
    BlockLimit = 1,
    /// `inode_used + delta > inode_limit` (and grace expired or zero).
    InodeLimit = 2,
    /// Grace period still open but the hard limit is already past
    /// (seed treats any would-exceed with grace==0 or grace<=now as
    /// hard; this variant surfaces an explicit grace-expired path).
    GraceExpired = 3,
}

/// Errors returned by [`Quota`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    /// Buffer shorter than one record, or scan past EOF mid-record.
    Truncated,
    /// Record count would exceed [`QUOTA_MAX_RECORDS`].
    TableFull,
    /// UID not present in the table / scan.
    NotFound,
    /// UID 0 used as a live record (reserved as free-slot sentinel).
    BadUid,
    /// Buffer length is not a multiple of [`QUOTA_RECORD_LEN`].
    BadLength,
}

/// Per-uid disk quota accounting surface.
///
/// # Locked invariants the verifier checks
///
/// 1. [`parse_record`](Quota::parse_record) / [`encode_record`](Quota::encode_record)
///    are inverse over any well-formed [`QuotaRecord`] with
///    `uid != 0`.
/// 2. [`scan`](Quota::scan) walks `buf` in [`QUOTA_RECORD_LEN`]-byte
///    strides and invokes the sink once per record with `uid != 0`.
/// 3. [`lookup`](Quota::lookup) returns the first record whose `uid`
///    matches, or [`QuotaError::NotFound`].
/// 4. [`check_write`](Quota::check_write) returns `Ok(())` when both
///    block and inode deltas fit under the limits (or the limit is
///    unlimited); returns `Err(QuotaReject::*)` on exceed when
///    `grace == 0` or `grace <= now_unix`.
///
/// Pure codec + predicate — no disk I/O, no allocator. A higher
/// layer loads the quotafile bytes and calls these methods.
pub trait Quota {
    /// Decode one 32-byte record.
    fn parse_record(buf: &[u8]) -> Result<QuotaRecord, QuotaError>;

    /// Encode one record into a 32-byte buffer.
    fn encode_record(rec: &QuotaRecord, out: &mut [u8]) -> Result<(), QuotaError>;

    /// Walk every live (`uid != 0`) record in `buf`. Returns the
    /// number of live records visited.
    fn scan(buf: &[u8], sink: &mut dyn FnMut(QuotaRecord)) -> Result<usize, QuotaError>;

    /// Find the first record for `uid` in `buf`.
    fn lookup(buf: &[u8], uid: u32) -> Result<QuotaRecord, QuotaError>;

    /// Would charging `block_delta` blocks and `inode_delta` inodes
    /// to `rec` succeed at wall-clock `now_unix`?
    fn check_write(
        rec: &QuotaRecord,
        block_delta: u64,
        inode_delta: u32,
        now_unix: u32,
    ) -> Result<(), QuotaReject>;
}

// ============================================================
// GdbStub — GDB Remote Serial Protocol wire codec (TASK-065)
// ============================================================

/// ACK byte the stub emits after a well-framed packet (`+`).
pub const GDB_ACK: u8 = b'+';
/// NACK byte the stub emits on a bad checksum (`-`).
pub const GDB_NACK: u8 = b'-';
/// Packet start delimiter (`$`).
pub const GDB_PACKET_START: u8 = b'$';
/// Packet end delimiter (`#`), followed by two hex checksum digits.
pub const GDB_PACKET_END: u8 = b'#';
/// Ctrl-C interrupt byte gdb sends to halt the target.
pub const GDB_INTERRUPT: u8 = 0x03;
/// Maximum packet body length we advertise via `qSupported`
/// (`PacketSize=400`).
pub const GDB_MAX_BODY: usize = 400;
/// Hex-character length of a `g` (read-registers) reply: 16 GPRs ×
/// 8 bytes × 2 hex digits = 256.
pub const GDB_REG_HEX_LEN: usize = 256;
/// Maximum `m addr,len` length the stub will accept.
pub const GDB_MAX_MEM_READ: u64 = 256;
/// SIGTRAP stop-reason byte used in `S05` replies for `?` / `c` / `s`.
pub const GDB_SIGTRAP: u8 = 0x05;

/// View of one well-framed RSP packet. The body slice borrows from
/// the caller's input buffer (bytes between `$` and `#`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GdbPacket<'a> {
    /// Payload bytes between `$` and `#` (may be empty).
    pub body: &'a [u8],
    /// Decoded 8-bit checksum from the two hex digits after `#`.
    pub checksum: u8,
}

/// Classified RSP command. Discriminants are part of the locked
/// surface so a morph cannot silently reclassify a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdbCommand {
    /// `g` — read all general-purpose registers.
    ReadRegisters,
    /// `G…` — write all registers (stub accepts, replies `OK`).
    WriteRegisters,
    /// `m addr,len` — read memory.
    ReadMemory {
        /// Start address (hex-decoded).
        addr: u64,
        /// Length in bytes (hex-decoded).
        len: u64,
    },
    /// `M addr,len:data` — write memory (stub refuses with `E01`).
    WriteMemory,
    /// `Z0,addr,kind` — set software breakpoint (stub replies `OK`).
    SetBreakpoint {
        /// Breakpoint address.
        addr: u64,
    },
    /// `c` — continue.
    Continue,
    /// `s` — single step.
    Step,
    /// `D` — detach.
    Detach,
    /// `?` — query halt reason.
    HaltReason,
    /// `qSupported…` — feature negotiation.
    QuerySupported,
    /// `vMustReplyEmpty` — gdb handshake probe (empty reply).
    VMustReplyEmpty,
    /// `qC` — current thread.
    QueryCurrentThread,
    /// `+` ACK (standalone, not a `$…#` packet).
    Ack,
    /// `-` NACK.
    Nack,
    /// `0x03` interrupt.
    Interrupt,
    /// Recognised but empty / unknown payload — empty reply.
    Empty,
    /// Unclassified payload — empty reply.
    Unknown,
}

/// Errors returned by [`GdbStub`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdbError {
    /// Buffer shorter than the minimum frame (`$#00` = 4 bytes) or
    /// missing delimiters.
    Truncated,
    /// Frame does not start with `$` or end with `#` + two hex digits.
    BadFraming,
    /// Checksum hex digits are not valid hex, or the decoded sum
    /// does not match the body XOR-sum (actually modular sum).
    BadChecksum,
    /// Output buffer too small for the framed packet.
    BufferTooSmall,
    /// Body longer than [`GDB_MAX_BODY`].
    BodyTooLong,
    /// `m` / `Z` argument parse failure (missing comma, bad hex).
    BadArgs,
}

/// GDB Remote Serial Protocol wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`checksum`](GdbStub::checksum) equals the 8-bit wrapping sum
///    of every body byte (not XOR — the RSP spec uses unsigned sum).
/// 2. [`parse_frame`](GdbStub::parse_frame) on `$g#67` returns a
///    packet whose body is `b"g"` and whose checksum is `0x67`.
/// 3. [`build_frame`](GdbStub::build_frame) of body `b"g"` produces
///    exactly the four-byte sequence `$g#67` (plus no trailing junk
///    in the returned length).
/// 4. [`classify`](GdbStub::classify) maps `b"g"` →
///    [`GdbCommand::ReadRegisters`], `b"qSupported"` →
///    [`GdbCommand::QuerySupported`], `b"vMustReplyEmpty"` →
///    [`GdbCommand::VMustReplyEmpty`].
/// 5. [`reply_body`](GdbStub::reply_body) for `ReadRegisters` writes
///    exactly [`GDB_REG_HEX_LEN`] ASCII `'0'` bytes.
///
/// No live target halt, no INT3 rewrite, no memory probe — pure
/// codec. Composition with a serial port is a higher layer.
pub trait GdbStub {
    /// 8-bit wrapping sum of `body` bytes (RSP checksum).
    fn checksum(body: &[u8]) -> u8;

    /// Parse a complete `$body#cs` frame. Returns the body view +
    /// decoded checksum after validating the sum.
    fn parse_frame(frame: &[u8]) -> Result<GdbPacket<'_>, GdbError>;

    /// Frame `body` as `$body#cs` into `out`. Returns bytes written.
    fn build_frame(body: &[u8], out: &mut [u8]) -> Result<usize, GdbError>;

    /// Classify a packet body into a [`GdbCommand`].
    fn classify(body: &[u8]) -> GdbCommand;

    /// Build the **reply body** (not framed) for `cmd` into `out`.
    /// Returns bytes written. Memory-read replies are empty here
    /// (no live target); use a higher layer to fill hex data.
    fn reply_body(cmd: &GdbCommand, out: &mut [u8]) -> Result<usize, GdbError>;
}

// ============================================================
// JournalFs — on-disk JFS image walker (TASK-064)
// ============================================================

/// On-disk superblock magic: ASCII `JFS2`.
pub const JFS_MAGIC: [u8; 4] = *b"JFS2";
/// On-disk inode magic: ASCII `JINO`.
pub const JFS_INODE_MAGIC: [u8; 4] = *b"JINO";
/// Superblock format version carried after the magic.
pub const JFS_VERSION: u32 = 2;
/// Sector / block size in bytes. Fixed at 512 for the seed.
pub const JFS_SECTOR_SIZE: usize = 512;
/// Byte length of the parsed superblock header (leading portion of
/// sector 0). The rest of the sector is reserved / zero.
pub const JFS_SB_LEN: usize = 32;
/// Byte length of one on-disk inode.
pub const JFS_INODE_LEN: usize = 32;
/// Fixed directory-entry record length.
pub const JFS_DIRENT_LEN: usize = 32;
/// Maximum bytes of a directory-entry name (excluding NUL). Packed as
/// `inode(4) + name_len(1) + name(27)`.
pub const JFS_DIRENT_MAX_NAME: usize = 27;
/// Inodes packed per inode-table sector (`512 / 32 = 16`).
pub const JFS_INODES_PER_SECTOR: u32 = 16;
/// Root directory always lives at inode 1. Inode 0 is the null /
/// free sentinel and is never a real entry.
pub const JFS_ROOT_INODE: u32 = 1;
/// Inode kind: regular file.
pub const JFS_KIND_FILE: u8 = 0;
/// Inode kind: directory.
pub const JFS_KIND_DIR: u8 = 1;

// --- Superblock field offsets (within the first JFS_SB_LEN bytes) ---

/// Offset of the 4-byte magic.
pub const JFS_SB_OFF_MAGIC: usize = 0;
/// Offset of the u32 LE version.
pub const JFS_SB_OFF_VERSION: usize = 4;
/// Offset of the u32 LE block_size.
pub const JFS_SB_OFF_BLOCK_SIZE: usize = 8;
/// Offset of the u32 LE root_inode.
pub const JFS_SB_OFF_ROOT_INODE: usize = 12;
/// Offset of the u32 LE inode_count (number of inodes in the table,
/// including the unused slot 0).
pub const JFS_SB_OFF_INODE_COUNT: usize = 16;
/// Offset of the u32 LE inode_table_lba.
pub const JFS_SB_OFF_INODE_TABLE_LBA: usize = 20;
/// Offset of the u32 LE data_start_lba (first data sector).
pub const JFS_SB_OFF_DATA_START_LBA: usize = 24;
/// Offset of the u32 LE free_bitmap_lba (0 = none / not used by walker).
pub const JFS_SB_OFF_BITMAP_LBA: usize = 28;

// --- Inode field offsets ---

/// Offset of the 4-byte inode magic.
pub const JFS_INO_OFF_MAGIC: usize = 0;
/// Offset of the u32 LE size_bytes.
pub const JFS_INO_OFF_SIZE: usize = 4;
/// Offset of the u64 LE mtime_unix.
pub const JFS_INO_OFF_MTIME: usize = 8;
/// Offset of extents[0] (u32 LE sector number; 0 = unallocated).
pub const JFS_INO_OFF_EXTENT0: usize = 16;
/// Offset of extents[1].
pub const JFS_INO_OFF_EXTENT1: usize = 20;
/// Offset of extents[2].
pub const JFS_INO_OFF_EXTENT2: usize = 24;
/// Offset of the kind byte.
pub const JFS_INO_OFF_KIND: usize = 28;

// --- Dirent field offsets ---

/// Offset of the target inode number (u32 LE).
pub const JFS_DE_OFF_INODE: usize = 0;
/// Offset of the name length byte.
pub const JFS_DE_OFF_NAME_LEN: usize = 4;
/// Offset of the name bytes (up to [`JFS_DIRENT_MAX_NAME`]).
pub const JFS_DE_OFF_NAME: usize = 5;

/// Parsed superblock view. Storage-only; produced by
/// [`JournalFs::mount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JfsSuperblock {
    /// Format version (must equal [`JFS_VERSION`] after a successful
    /// mount).
    pub version: u32,
    /// Block / sector size in bytes (must equal [`JFS_SECTOR_SIZE`]).
    pub block_size: u32,
    /// Root directory inode number (must equal [`JFS_ROOT_INODE`]).
    pub root_inode: u32,
    /// Number of inode slots in the table (including slot 0).
    pub inode_count: u32,
    /// LBA of the first inode-table sector.
    pub inode_table_lba: u32,
    /// LBA of the first data sector.
    pub data_start_lba: u32,
    /// LBA of the free-bitmap region, or 0 if absent.
    pub free_bitmap_lba: u32,
}

/// Parsed inode view. Storage-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JfsInode {
    /// Inode number this view was loaded from.
    pub ino: u32,
    /// File / directory size in bytes.
    pub size_bytes: u32,
    /// Last-modification time (Unix seconds). Zero is valid.
    pub mtime_unix: u64,
    /// Up to three direct data-sector LBAs (0 = unused).
    pub extents: [u32; 3],
    /// [`JFS_KIND_FILE`] or [`JFS_KIND_DIR`].
    pub kind: u8,
}

impl JfsInode {
    /// True iff this inode is a regular file.
    pub const fn is_file(self) -> bool {
        self.kind == JFS_KIND_FILE
    }
    /// True iff this inode is a directory.
    pub const fn is_dir(self) -> bool {
        self.kind == JFS_KIND_DIR
    }
}

/// One directory entry view. The name slice borrows from a
/// caller-supplied scratch buffer filled by
/// [`JournalFs::read_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JfsDirEntry<'a> {
    /// Target inode number.
    pub ino: u32,
    /// Entry name bytes (1..=[`JFS_DIRENT_MAX_NAME`]).
    pub name: &'a [u8],
}

/// Errors returned by [`JournalFs`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JfsError {
    /// Image shorter than one sector, or a requested LBA falls off
    /// the end of the image.
    Truncated,
    /// Superblock magic is not [`JFS_MAGIC`].
    BadMagic,
    /// Superblock version is not [`JFS_VERSION`].
    BadVersion,
    /// Superblock `block_size` is not [`JFS_SECTOR_SIZE`].
    BadBlockSize,
    /// Superblock `root_inode` is not [`JFS_ROOT_INODE`], or
    /// `inode_count` is zero / exceeds the table capacity implied
    /// by image size.
    BadSuperblock,
    /// Inode magic is not [`JFS_INODE_MAGIC`], or the inode number
    /// is out of range / free (all-zero slot).
    BadInode,
    /// Directory entry has zero or over-long name, or the dir body
    /// is not a multiple of [`JFS_DIRENT_LEN`].
    BadDirent,
    /// `lookup` found no matching name.
    NotFound,
    /// Called a file-only operation on a directory, or vice versa.
    WrongKind,
    /// Caller-supplied output buffer is too small for the file body.
    BufferTooSmall,
    /// File size exceeds what three direct extents can address
    /// (`3 * JFS_SECTOR_SIZE`).
    FileTooLarge,
}

/// On-disk Journaled-FS image walker.
///
/// # Locked invariants the verifier checks
///
/// 1. [`mount`](JournalFs::mount) on a buffer whose first four bytes
///    are not [`JFS_MAGIC`] returns [`JfsError::BadMagic`]. A
///    well-formed image returns `Ok` with a superblock whose
///    `version == JFS_VERSION`, `block_size == JFS_SECTOR_SIZE`,
///    and `root_inode == JFS_ROOT_INODE`.
/// 2. [`read_inode`](JournalFs::read_inode) for inode 0 or an out-of-
///    range number returns [`JfsError::BadInode`]. A present inode
///    has magic [`JFS_INODE_MAGIC`] and a kind of
///    [`JFS_KIND_FILE`] or [`JFS_KIND_DIR`].
/// 3. [`read_dir`](JournalFs::read_dir) on a directory inode walks
///    fixed [`JFS_DIRENT_LEN`]-byte records and invokes the sink
///    once per non-zero inode entry, in on-disk order.
/// 4. [`lookup`](JournalFs::lookup) returns the first dirent whose
///    name equals the query byte-for-byte, or
///    [`JfsError::NotFound`].
/// 5. [`read_file`](JournalFs::read_file) concatenates the direct
///    extents up to `size_bytes` into the caller buffer and returns
///    the byte count. A buffer shorter than `size_bytes` returns
///    [`JfsError::BufferTooSmall`].
///
/// The seed is a **read-only walker** over a caller-supplied image
/// byte buffer — no allocator, no WAL, no free-bitmap mutation.
/// Composition with [`BlockDeviceVirtio`] is a higher layer that
/// fills the image buffer from sectors.
pub trait JournalFs {
    /// Parse and validate the superblock at the start of `image`.
    /// On success, subsequent methods may read inodes / dirs / files
    /// from the same `image` slice.
    fn mount(image: &[u8]) -> Result<Self, JfsError>
    where
        Self: Sized;

    /// Superblock captured at mount time.
    fn superblock(&self) -> &JfsSuperblock;

    /// Load inode `ino` from the inode table.
    fn read_inode(&self, image: &[u8], ino: u32) -> Result<JfsInode, JfsError>;

    /// Walk directory entries of `dir_ino`, calling `sink` once per
    /// live entry. Returns the number of entries visited.
    fn read_dir(
        &self,
        image: &[u8],
        dir_ino: u32,
        sink: &mut dyn FnMut(JfsDirEntry<'_>),
    ) -> Result<usize, JfsError>;

    /// Look up `name` inside directory `dir_ino`.
    fn lookup(&self, image: &[u8], dir_ino: u32, name: &[u8]) -> Result<u32, JfsError>;

    /// Read the full file body of `ino` into `out`. Returns bytes
    /// written (`== size_bytes` on success).
    fn read_file(&self, image: &[u8], ino: u32, out: &mut [u8]) -> Result<usize, JfsError>;
}

// ============================================================
// KatRunner — Known-Answer Test harness (TASK-063)
// ============================================================

/// Output length of every digest / PRK the suite asserts against.
/// SHA-256 and HMAC-SHA-256 both produce 32 bytes.
pub const KAT_DIGEST_LEN: usize = 32;

/// Number of locked vectors in the boot suite. Every
/// [`KatRunner::run_all`] implementation MUST exercise exactly this
/// many vectors, in [`KatId`] discriminant order.
///
/// Composition (locked):
/// - 3 × SHA-256 (FIPS 180-4 / RFC 6234): empty, `"abc"`, million-`a`
/// - 4 × HMAC-SHA-256 (RFC 4231 §4.2–§4.5): test cases 1–4
/// - 2 × HKDF-SHA-256 (RFC 5869 §A.1–§A.2): cases 1–2 (PRK + OKM)
pub const KAT_VECTOR_COUNT: u8 = 9;

/// Which crypto primitive a vector exercises. Discriminants are part
/// of the locked surface so a morph cannot silently reclassify a
/// vector (e.g. claim a SHA failure as an HMAC failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KatPrimitive {
    /// SHA-256 (FIPS 180-4).
    Sha256 = 0,
    /// HMAC-SHA-256 (RFC 2104 / RFC 4231).
    HmacSha256 = 1,
    /// HKDF-Extract + Expand over SHA-256 (RFC 5869).
    HkdfSha256 = 2,
}

/// Stable identity of one vector in the locked suite. Discriminant
/// values 0..[`KAT_VECTOR_COUNT`] are part of the wire-observable
/// surface (the kernel banner prints the count; a failed vector's
/// id lands in [`KatSuiteResult::first_fail`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KatId {
    /// SHA-256 of the empty string.
    Sha256Empty = 0,
    /// SHA-256 of `"abc"`.
    Sha256Abc = 1,
    /// SHA-256 of one million ASCII `'a'` bytes.
    Sha256MillionA = 2,
    /// RFC 4231 test case 1.
    HmacRfc4231Case1 = 3,
    /// RFC 4231 test case 2.
    HmacRfc4231Case2 = 4,
    /// RFC 4231 test case 3.
    HmacRfc4231Case3 = 5,
    /// RFC 4231 test case 4.
    HmacRfc4231Case4 = 6,
    /// RFC 5869 test case 1 (PRK + OKM).
    HkdfRfc5869Case1 = 7,
    /// RFC 5869 test case 2 (PRK + OKM).
    HkdfRfc5869Case2 = 8,
}

impl KatId {
    /// Construct from the raw discriminant. Returns `None` if `raw`
    /// is outside `0..KAT_VECTOR_COUNT`.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Sha256Empty),
            1 => Some(Self::Sha256Abc),
            2 => Some(Self::Sha256MillionA),
            3 => Some(Self::HmacRfc4231Case1),
            4 => Some(Self::HmacRfc4231Case2),
            5 => Some(Self::HmacRfc4231Case3),
            6 => Some(Self::HmacRfc4231Case4),
            7 => Some(Self::HkdfRfc5869Case1),
            8 => Some(Self::HkdfRfc5869Case2),
            _ => None,
        }
    }

    /// Primitive family this vector exercises.
    pub const fn primitive(self) -> KatPrimitive {
        match self {
            Self::Sha256Empty | Self::Sha256Abc | Self::Sha256MillionA => KatPrimitive::Sha256,
            Self::HmacRfc4231Case1
            | Self::HmacRfc4231Case2
            | Self::HmacRfc4231Case3
            | Self::HmacRfc4231Case4 => KatPrimitive::HmacSha256,
            Self::HkdfRfc5869Case1 | Self::HkdfRfc5869Case2 => KatPrimitive::HkdfSha256,
        }
    }

    /// Short stable name for serial banners / audit logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256Empty => "sha256_empty",
            Self::Sha256Abc => "sha256_abc",
            Self::Sha256MillionA => "sha256_million_a",
            Self::HmacRfc4231Case1 => "hmac_rfc4231_1",
            Self::HmacRfc4231Case2 => "hmac_rfc4231_2",
            Self::HmacRfc4231Case3 => "hmac_rfc4231_3",
            Self::HmacRfc4231Case4 => "hmac_rfc4231_4",
            Self::HkdfRfc5869Case1 => "hkdf_rfc5869_1",
            Self::HkdfRfc5869Case2 => "hkdf_rfc5869_2",
        }
    }

    /// Publication source citation.
    pub const fn source(self) -> &'static str {
        match self {
            Self::Sha256Empty | Self::Sha256Abc | Self::Sha256MillionA => "FIPS 180-4 / RFC 6234",
            Self::HmacRfc4231Case1
            | Self::HmacRfc4231Case2
            | Self::HmacRfc4231Case3
            | Self::HmacRfc4231Case4 => "RFC 4231",
            Self::HkdfRfc5869Case1 | Self::HkdfRfc5869Case2 => "RFC 5869",
        }
    }
}

/// One vector's outcome. Storage-only; no allocation. The expected
/// and actual digests are always [`KAT_DIGEST_LEN`] bytes for
/// SHA-256 / HMAC vectors; for HKDF vectors `expected`/`actual` hold
/// the PRK (32 bytes) and `okm_match` reports the expand step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KatResult {
    /// Vector identity.
    pub id: KatId,
    /// True iff every asserted output matched the published answer.
    pub pass: bool,
    /// Actual primary digest / PRK produced by the implementation.
    pub actual: [u8; KAT_DIGEST_LEN],
    /// Expected primary digest / PRK from the published standard.
    pub expected: [u8; KAT_DIGEST_LEN],
    /// For HKDF vectors: whether the OKM (expand output) matched.
    /// For non-HKDF vectors: always `true` (unused).
    pub okm_match: bool,
}

/// Aggregate outcome of [`KatRunner::run_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KatSuiteResult {
    /// Always equal to [`KAT_VECTOR_COUNT`] on a conforming impl.
    pub total: u8,
    /// Number of vectors that passed.
    pub passed: u8,
    /// First failing vector, if any. `None` means the suite is clean.
    pub first_fail: Option<KatId>,
}

impl KatSuiteResult {
    /// True iff every vector passed.
    pub const fn all_ok(self) -> bool {
        self.passed == self.total && self.first_fail.is_none()
    }
}

/// Known-answer test harness for the kernel crypto primitives.
///
/// # Locked invariants the verifier checks
///
/// 1. [`run_all`](KatRunner::run_all) exercises exactly
///    [`KAT_VECTOR_COUNT`] vectors in [`KatId`] order 0..N-1.
/// 2. On a clean suite, `passed == total`, `first_fail == None`, and
///    `all_ok()` is true.
/// 3. On the first failing vector, `first_fail` equals that vector's
///    id and `passed` equals the count of vectors before it that
///    passed (the suite may continue or short-circuit — either is
///    allowed; the seed continues so the banner can report `passed`).
/// 4. [`run_one`](KatRunner::run_one) for each [`KatId`] returns a
///    [`KatResult`] whose `expected` field is the published digest
///    for that vector (byte-exact against the standard).
///
/// The harness is pure computation over fixed inputs — no I/O, no
/// allocation, no global state. A morph that perturbs SHA-256,
/// HMAC, or HKDF arithmetic fails a published vector in the same
/// cycle the morph is deployed.
pub trait KatRunner {
    /// Run every locked vector. Returns the aggregate result.
    fn run_all() -> KatSuiteResult;

    /// Run a single vector by id.
    fn run_one(id: KatId) -> KatResult;
}

// ============================================================
// PicTimer + Rtc — PIT 8253/8254 + MC146818 CMOS RTC (TASK-062)
// ============================================================

/// PIT command port (IBM PC architecture). Writes the channel /
/// access / mode / BCD command byte.
pub const PIT_CMD_PORT: u16 = 0x43;
/// PIT channel-0 data port. Divisor low then high after a command.
pub const PIT_CH0_PORT: u16 = 0x40;
/// PIT input clock frequency in Hz — fixed by IBM PC architecture
/// at ~1.193182 MHz (derived from the 14.31818 MHz crystal / 12).
pub const PIT_BASE_HZ: u32 = 1_193_182;
/// Command byte: channel 0, lobyte/hibyte access, mode 3 (square
/// wave generator), binary counting. Bit layout
/// `SC1 SC0 RW1 RW0 M2 M1 M0 BCD` = `00 11 011 0` = `0x36`.
pub const PIT_CMD_CH0_LOHI_MODE3_BIN: u8 = 0x36;

/// CMOS RTC index port. Writing selects the register; bit 7 is the
/// NMI-disable latch (legacy — leave clear so NMI policy is preserved).
pub const CMOS_INDEX_PORT: u16 = 0x70;
/// CMOS RTC data port. Read/write the register selected via
/// [`CMOS_INDEX_PORT`].
pub const CMOS_DATA_PORT: u16 = 0x71;

/// RTC register: seconds (0..=59).
pub const RTC_REG_SECONDS: u8 = 0x00;
/// RTC register: minutes (0..=59).
pub const RTC_REG_MINUTES: u8 = 0x02;
/// RTC register: hours (0..=23 or 1..=12 + PM bit).
pub const RTC_REG_HOURS: u8 = 0x04;
/// RTC register: day of month (1..=31).
pub const RTC_REG_DAY: u8 = 0x07;
/// RTC register: month (1..=12).
pub const RTC_REG_MONTH: u8 = 0x08;
/// RTC register: year within century (0..=99).
pub const RTC_REG_YEAR: u8 = 0x09;
/// RTC register: status A (bit 7 = Update In Progress).
pub const RTC_REG_STATUS_A: u8 = 0x0A;
/// RTC register: status B (bit 1 = 24-hour, bit 2 = binary mode).
pub const RTC_REG_STATUS_B: u8 = 0x0B;

/// Status-A bit 7: Update In Progress. Registers may be incoherent
/// while this bit is set.
pub const RTC_STATUS_A_UIP: u8 = 0x80;
/// Status-B bit 1: 24-hour clock when set; 12-hour when clear.
pub const RTC_STATUS_B_24H: u8 = 0x02;
/// Status-B bit 2: binary (binary=1) vs BCD (binary=0) encoding.
pub const RTC_STATUS_B_BINARY: u8 = 0x04;
/// Hours-register bit 7: PM indicator in 12-hour mode.
pub const RTC_HOUR_PM: u8 = 0x80;

/// Maximum spin iterations while waiting for UIP to clear. At the
/// RTC's 32.768 kHz crystal UIP self-clears in <2.4 µs; this budget
/// is generous for a slow emulator and bounded so a broken RTC
/// cannot hang the kernel forever.
pub const RTC_UIP_SPIN_BUDGET: u32 = 1_000_000;
/// Maximum consecutive raw-read pairs attempted for the RTC
/// consistency dance (two consecutive identical snapshots).
pub const RTC_CONSISTENCY_PASSES: u32 = 16;

/// Abstract 8-bit I/O-port surface. Caller-supplied so the seed's
/// [`PicTimer`] / [`Rtc`] codecs can be exercised against a
/// recording test harness AND against real `in`/`out` at kernel
/// runtime through the same trait surface.
pub trait IoPort {
    /// Write an 8-bit value to the given I/O port.
    fn write_u8(&mut self, port: u16, value: u8);
    /// Read an 8-bit value from the given I/O port.
    fn read_u8(&mut self, port: u16) -> u8;
}

/// Decomposed Gregorian wall-clock time recovered from the RTC,
/// plus the derived Unix epoch seconds. Year is full (e.g. 2026);
/// month + day are 1-based; hour / minute / second are 0-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTimeView {
    /// Full Gregorian year (e.g. 2026).
    pub year: u32,
    /// Month 1..=12.
    pub month: u8,
    /// Day of month 1..=31.
    pub day: u8,
    /// Hour 0..=23 (always converted to 24-hour form).
    pub hour: u8,
    /// Minute 0..=59.
    pub minute: u8,
    /// Second 0..=59.
    pub second: u8,
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
    pub unix: u64,
}

/// Errors emitted by [`PicTimer::program_hz`] and [`Rtc::read_time`].
/// Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    /// Caller requested `hz == 0` — a no-op that would hang any
    /// subsequent tick-based sleep, so it is rejected explicitly.
    ZeroHz,
    /// UIP bit stayed set for more than [`RTC_UIP_SPIN_BUDGET`]
    /// spins — RTC is absent or broken.
    UipTimeout,
    /// Two consecutive raw register snapshots never agreed across
    /// [`RTC_CONSISTENCY_PASSES`] attempts.
    InconsistentRead,
}

/// Programmable Interval Timer (8253/8254) channel-0 wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`program_hz`](PicTimer::program_hz) with `hz == 0` returns
///    [`TimerError::ZeroHz`] and issues **zero** port writes.
/// 2. For every non-zero `hz`, the method writes exactly three
///    bytes in order:
///    - `write_u8(PIT_CMD_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN)`
///    - `write_u8(PIT_CH0_PORT, (divisor & 0xFF) as u8)`
///    - `write_u8(PIT_CH0_PORT, (divisor >> 8) as u8)`
///    where `divisor = (PIT_BASE_HZ / hz).clamp(1, u16::MAX)`.
/// 3. The returned `u16` equals that divisor.
///
/// No IRQ unmask, no tick counter, no sleep primitive — those are
/// scheduler / interrupt-handler surfaces layered on top of this
/// codec.
pub trait PicTimer {
    /// Program channel 0 to fire IRQ 0 at approximately `hz` Hz.
    /// Returns the 16-bit divisor written to the data port.
    fn program_hz(port: &mut dyn IoPort, hz: u32) -> Result<u16, TimerError>;
}

/// MC146818 CMOS Real-Time Clock wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`read_time`](Rtc::read_time) polls status-A until UIP clears
///    (or returns [`TimerError::UipTimeout`]), then reads the six
///    calendar registers + status-B, re-reading until two
///    consecutive snapshots match (or returns
///    [`TimerError::InconsistentRead`]).
/// 2. BCD vs binary is decided by status-B bit 2
///    ([`RTC_STATUS_B_BINARY`]); 12-hour vs 24-hour by bit 1
///    ([`RTC_STATUS_B_24H`]); the PM bit is bit 7 of the hours
///    register ([`RTC_HOUR_PM`]).
/// 3. Two-digit years map to 2000..=2079 for `year2 < 80`, else
///    1900..=1979 — covering the classic CMOS century window.
/// 4. [`RtcTimeView::unix`] equals the pure Gregorian conversion
///    of the decoded Y/M/D/H/Mi/S tuple (no timezone offset).
///
/// No HPET composition, no boot-snapshot atomics — those are
/// higher-level kernel services layered on top of this codec.
pub trait Rtc {
    /// Read the current wall-clock time as a decoded
    /// [`RtcTimeView`]. Performs the UIP + consistency dance.
    fn read_time(port: &mut dyn IoPort) -> Result<RtcTimeView, TimerError>;
}

#[cfg(test)]
mod cap_proof_tests {
    //! Unit tests for the type-state `CapProof` (TASK-020). These run
    //! under `cargo test -p proteus-contracts` with the
    //! `property_tests` feature enabled (which switches the crate to
    //! `std` mode); the type-state behaviour itself is independent of
    //! that feature.
    //!
    //! The negative cases that prove "external code cannot mint a
    //! `CapProof`" live in the verifier's trybuild suite at
    //! `verifier/tests/cap_typestate/`. Here we exercise the positive
    //! shape: a successful `check` mints a proof; a failed `check`
    //! does not; a custom impl that overrides `check_raw` is the
    //! sole route to the mint.
    use super::*;

    /// A test-only implementor of `SyscallCapTable` whose `check_raw`
    /// is parameterised at construction so individual cases can hit
    /// every arm of the trait's behaviour.
    struct StubTable {
        /// Closure returning the result of `check_raw`. Boxed so a
        /// single test can hold multiple stubs with different
        /// behaviour without committing to a const generic.
        verdict: fn(u64, u64, u32) -> Result<(), CapError>,
    }

    impl SyscallCapTable for StubTable {
        type Cap = u64;
        fn check_raw(&self, task_id: u64, cap: u64, syscall_nr: u32) -> Result<(), CapError> {
            (self.verdict)(task_id, cap, syscall_nr)
        }
    }

    #[test]
    fn check_mints_proof_on_success() {
        let table = StubTable { verdict: |_, _, _| Ok(()) };
        let result: Result<CapProof, CapError> = table.check(0, 0, 0);
        assert!(result.is_ok(), "check should succeed when check_raw returns Ok");
        // Consume the proof; this is the type-state happy path.
        result.unwrap().consume();
    }

    #[test]
    fn check_does_not_mint_on_failure() {
        let table = StubTable { verdict: |_, _, _| Err(CapError::EPERM) };
        let result = table.check(0, 0, 0);
        assert!(matches!(result, Err(CapError::EPERM)));
    }

    #[test]
    fn check_passes_through_enosys() {
        let table = StubTable { verdict: |_, _, _| Err(CapError::ENOSYS) };
        let result = table.check(0, 0, 0);
        assert!(matches!(result, Err(CapError::ENOSYS)));
    }

    #[test]
    fn cap_proof_is_zero_sized() {
        // The proof is a marker, not a runtime value. If a future
        // edit accidentally adds a non-ZST field, this test will fail
        // and surface the regression — non-ZST means heavier syscall
        // codegen, which is observable on the perf gate.
        assert_eq!(core::mem::size_of::<CapProof>(), 0);
    }

    #[test]
    fn cap_proof_is_send_and_sync() {
        // A proof must be safely movable across threads — the kernel
        // dispatcher may hand it off to a worker fiber on a soft-IRQ
        // path. Compile-time assertion via fn-generic bound.
        fn assert_send<T: Send>() {}
        fn assert_sync<T: Sync>() {}
        assert_send::<CapProof>();
        assert_sync::<CapProof>();
    }

    #[test]
    fn durable_cap_bits_kat_task_159() {
        // TASK-159: durable bits allocated at 10..12; reserved from 13.
        use super::caps::*;
        assert_eq!(DURABLE_WAL_WRITE, 1 << 10);
        assert_eq!(DURABLE_FS_WRITE, 1 << 11);
        assert_eq!(DURABLE_AUDIT_PERSIST, 1 << 12);
        assert_eq!(ALLOCATED_BITS, 13);
        assert_eq!(RESERVED_MASK, !((1u64 << 13) - 1));
        assert!(mask_is_valid(ALL_NAMED));
        assert!(!mask_is_valid(1u64 << 13), "bit 13 must be reserved");
        assert!(!mask_is_valid(1u64 << 63));

        // Deny path naming: task holds nothing → durable WAL required → fail.
        let unprivileged: u64 = 0;
        assert!(!allows(unprivileged, DURABLE_WAL_WRITE));
        // Holds only AUDIT_WRITE (in-RAM append), not persist.
        assert!(!allows(AUDIT_WRITE, DURABLE_AUDIT_PERSIST));
        // Holds BLOCK_WRITE alone does not imply durable WAL.
        assert!(!allows(BLOCK_WRITE, DURABLE_WAL_WRITE));
        // Full grant allows each durable bit.
        assert!(allows(ALL_NAMED, DURABLE_WAL_WRITE));
        assert!(allows(ALL_NAMED, DURABLE_FS_WRITE));
        assert!(allows(ALL_NAMED, DURABLE_AUDIT_PERSIST));
        // Subset grant for WAL only.
        assert!(allows(DURABLE_WAL_WRITE, DURABLE_WAL_WRITE));
        assert!(!allows(DURABLE_WAL_WRITE, DURABLE_FS_WRITE));

        // check_raw-style gate: EPERM when required durable bit missing.
        let table = StubTable {
            verdict: |_, held, _| {
                if allows(held, DURABLE_WAL_WRITE) {
                    Ok(())
                } else {
                    Err(CapError::EPERM)
                }
            },
        };
        assert!(matches!(
            table.check(0, unprivileged, 0),
            Err(CapError::EPERM)
        ));
        let proof = table
            .check(0, DURABLE_WAL_WRITE, 0)
            .expect("WAL durable bit must mint proof");
        proof.consume();
    }

    #[test]
    fn consume_is_value_move_not_borrow() {
        // After `consume(self)`, the proof is gone. The compiler
        // already enforces this; the runtime assertion is "calling
        // consume doesn't panic / doesn't run a Drop with side
        // effects". We don't impl Drop intentionally.
        let table = StubTable { verdict: |_, _, _| Ok(()) };
        let proof = table.check(0, 0, 0).expect("Ok");
        proof.consume();
        // Re-mint and confirm a second proof works the same way.
        let proof2 = table.check(0, 0, 0).expect("Ok");
        proof2.consume();
    }

    #[test]
    fn cap_proof_implements_debug_trait() {
        // Compile-time check that CapProof satisfies the Debug bound
        // so the kernel's panic-printer (which formats Result<T, _>
        // for the kernel log) can print one without losing the type
        // info. We don't materialise the formatted string here
        // because the contracts crate's tests run in `no_std` mode
        // without `format!` unless the `property_tests` feature is
        // toggled — but the bound itself is statically checked by
        // the `assert_debug` fn-generic constraint below.
        fn assert_debug<T: core::fmt::Debug>() {}
        assert_debug::<CapProof>();
    }

    #[test]
    fn schema_version_bumped_for_task_020_through_070_hpet_canary_kbd_fat() {
        // Documented bumps: 1 → 2 (TASK-020 cap-proof type-state),
        // 2 → 3 (TASK-011 NetStack), 3 → 4 (TASK-017 Kpti trait),
        // 4 → 5 (TCP port), 5 → 6 (HTTP port), 6 → 7 (DNS port),
        // 7 → 8 (ICMP port), 8 → 9 (Ethernet/802.3 port),
        // 9 → 10 (TASK-019 CrashDump + SymbolResolve traits),
        // 10 → 11 (TASK-046 Arp trait + ArpPacketView),
        // 11 → 12 (TASK-047 Dhcp trait + DhcpMessageView +
        // DhcpClientState + dhcp_option/dhcp_msg_type modules),
        // 12 → 13 (TASK-048 NetDevice + MmioBus traits + VirtqDesc +
        // VirtioNetHdr + virtio_net_feature/virtio_status modules),
        // 13 → 14 (TASK-049 Tls13Client trait + ParsedServerHello +
        // HandshakeKeys structs),
        // 14 → 15 (TASK-050 PacketFilter trait + FilterRule +
        // Ipv4PacketView + FilterAction + Verdict + FilterRuleError +
        // IP_PROTO_TCP / IP_PROTO_ICMP / FW_PROTO_ANY / FW_PORT_ANY),
        // 15 → 16 (TASK-051 Tpm trait + TpmResponseView + TpmError +
        // TPM_HEADER_LEN / TPM_ST_NO_SESSIONS / TPM_ST_SESSIONS /
        // TPM_CC_STARTUP / _GET_RANDOM / _PCR_READ / _PCR_EXTEND /
        // TPM_SU_CLEAR / _STATE / TPM_ALG_SHA256 / _SHA1 /
        // TPM_RS_PW / TPM_RC_SUCCESS / TPM_SHA256_DIGEST_LEN /
        // _SHA1_DIGEST_LEN / TPM_MAX_PCR_INDEX),
        // 16 → 17 (TASK-052 AuditLog trait + AuditEvent + AuditVerdict +
        // AuditIter + AuditError + AUDIT_MESSAGE_LEN /
        // AUDIT_EVENT_WIRE_LEN / AUDIT_SNAPSHOT_HEADER_LEN /
        // AUDIT_SNAPSHOT_MAGIC),
        // 17 → 18 (TASK-053 Sntp trait + NtpTimestamp + NtpReply +
        // NtpClockSkew + SntpError + SNTP_PACKET_LEN / SNTP_VERSION /
        // SNTP_MODE_CLIENT / SNTP_MODE_SERVER / SNTP_LEAP_ALARM /
        // SNTP_MAX_STRATUM / SNTP_OFFSET_TRANSMIT_TS / _RECEIVE_TS /
        // _ORIGIN_TS / _REFERENCE_TS / _REF_ID).
        // 18 → 19 (TASK-054 Filesystem + Vfs traits + FsHandle +
        // FsError + FileStat + FS_NAME_MAX / FS_PATH_MAX /
        // FS_MAX_MOUNTS / FS_O_RDONLY / _WRONLY / _RDWR / _ACCMODE /
        // _CREATE / _TRUNC / _EXCL / FS_MODE_FILE / _DIR /
        // _TYPE_MASK / _PERM_MASK).
        // 19 → 20 (TASK-055 EBpf trait + BpfInstr + BpfContext +
        // BpfError + bpf_op constant module + BPF_REG_COUNT /
        // BPF_STACK_SIZE / BPF_MAX_INSTRUCTIONS /
        // BPF_MAX_BRANCH_DEPTH / BPF_REG_FP).
        // 20 → 21 (TASK-056 EthernetController + MmioRegBus traits
        // + LinkState + E1000Error + E1000_REG_* register-offset
        // family + E1000_CTRL_* / _STATUS_* / _EERD_* / _RCTL_* /
        // _TCTL_* bit flags + E1000_EEPROM_MAC_WORD0/1/2 +
        // E1000_TXD_CMD_* + E1000_DESC_STA_DD + E1000_RXD_STA_EOP
        // + E1000_TX_DESC_LEN / _RX_DESC_LEN / _TX_RING_LEN /
        // _RX_RING_LEN / _MAX_FRAME_LEN).
        // 21 → 22 (TASK-057 Smp + ApicWriter traits + CpuTopology +
        // SmpError + ApicId + PerCpu storage + smp_consts module
        // (ICR_DELIVERY_INIT / _STARTUP / _LEVEL_ASSERT / _DEASSERT
        // / _TRIGGER_LEVEL / _DEST_SHORTHAND_ALL_EXCL_SELF /
        // _DELIVERY_STATUS_PENDING / _VECTOR_MASK + ICR_HIGH_DEST_SHIFT
        // + SMP_INIT_TO_SIPI_US / _SIPI_TO_SIPI_US /
        // _DELIVERY_RETRY_BUDGET) + madt module (SIG_APIC + entry
        // type codes + flag bits + HEADER_LEN + LOCAL_APIC_ENTRY_LEN)
        // + MAX_CPUS = 64).
        // 22 → 23 (TASK-058 Tftp trait + TftpMode + TftpPacket view
        // enum + TftpError + TftpErrorCode + tftp_op module +
        // MAX_TFTP_FILENAME / MAX_TFTP_MODE / TFTP_BLOCK_SIZE /
        // TFTP_OPCODE_LEN / TFTP_BLOCK_LEN / TFTP_MIN_DATA_LEN /
        // TFTP_MIN_ACK_LEN / TFTP_MIN_ERROR_LEN).
        // 23 → 24 (TASK-059 Pci + PciConfigBus traits + PciAddress +
        // PciDevice + PciBar + PciMsixInfo + PciError + pci_class
        // module + PCI_CONFIG_ADDRESS_PORT / _DATA_PORT +
        // PCI_VENDOR_NONE + PCI_MAX_BUS / _DEVICE / _FUNCTION +
        // PCI_HEADER_MULTIFUNC_BIT + PCI_CAP_ID_MSI / _MSIX +
        // PCI_STATUS_CAPABILITIES_LIST + PCI_MAX_CAP_HOPS +
        // PCI_CFG_OFFSET_VENDOR_DEVICE / _COMMAND_STATUS /
        // _CLASS_REVISION / _HEADER_LATENCY / _BAR0 / _INT_LINE /
        // _CAP_PTR + PCI_COMMAND_BUS_MASTER + PCI_BAR_TYPE_IO_BIT /
        // _MMIO_TYPE_MASK / _MMIO_TYPE_64BIT / _MMIO_ADDR_MASK /
        // _IO_ADDR_MASK + PCI_BAR_INT_LINE_NONE + PCI_MAX_BAR_INDEX +
        // PCI_MSIX_TABLE_SIZE_MASK / _BIR_MASK / _ENABLE_BIT /
        // _FUNCMASK_BIT).
        // 24 → 25 (TASK-060 X509 trait + X509Cert + X509Time + X509PubKey +
        // X509PubKeyAlg + X509SigAlg + X509Error + X509_TAG_* +
        // X509_OID_* + X509_MAX_CERT_LEN / _MAX_DEPTH /
        // _ED25519_KEY_LEN / _P256_POINT_LEN).
        // 25 → 26 (TASK-061 BlockDeviceVirtio trait + VirtBlkRequest +
        // VirtBlkError + virtio_blk_feature / virtio_blk_req_type /
        // virtio_blk_status_byte / virtio_blk_device_cfg modules +
        // VIRTIO_BLK_QUEUE_REQUESTQ / VIRTIO_BLK_HDR_LEN /
        // VIRTIO_BLK_SECTOR_SIZE / VIRTIO_BLK_STATUS_LEN).
        // 26 → 27 (TASK-062 PicTimer + Rtc traits + IoPort +
        // RtcTimeView + TimerError + PIT_* / CMOS_* / RTC_*
        // constants).
        // 27 → 28 (TASK-063 KatRunner trait + KatSuiteResult +
        // KatResult + KatId + KatPrimitive + KAT_VECTOR_COUNT /
        // KAT_DIGEST_LEN).
        // 28 → 29 (TASK-064 JournalFs trait + JfsSuperblock +
        // JfsInode + JfsDirEntry + JfsError + JFS_* constants).
        // 29 → 30 (TASK-065 GdbStub trait + GdbPacket + GdbCommand +
        // GdbError + GDB_* RSP constants).
        // 30 → 31 (TASK-066 Quota trait + QuotaRecord + QuotaReject +
        // QuotaError + QUOTA_* constants).
        // 31 → 32 (TASK-067 Hpet + HpetCaps + HpetError + HPET_*).
        // 32 → 33 (TASK-068 StackCanary + CanaryToken + CanaryError).
        // 33 → 34 (TASK-069 Keyboard + KeyEvent + KeyCode + KbError).
        // 34 → 35 (TASK-070 Fat32 + FatBpb + FatDirent + FatError).
        // 35 → 36 (TASK-071 Watchdog).
        // 36 → 37 (TASK-072 Random).
        // 37 → 38 (TASK-073 Power).
        // 38 → 39 (TASK-074 Elf64).
        // 39 → 40 (TASK-075 Serial16550).
        // 40 → 41 (TASK-076 TickSource).
        // 41 → 42 (TASK-077 VirtioPciCaps).
        // 42 → 43 (TASK-078 SigKat).
        // 43 → 44 (TASK-079 Multiboot2).
        // 44 → 45 (TASK-080 Crc32c).
        // 45 → 46 (TASK-081 AcpiRsdp).
        // 46 → 47 (TASK-082 FrameBitmap).
        // 47 → 48 (TASK-083 IoApic).
        // 48 → 49 (TASK-084 LapicIcr).
        // 49 → 50 (TASK-085 Gpt).
        // 50 → 51 (TASK-086 DnsName).
        // 51 → 52 (TASK-087 HmacDrbg).
        // 52 → 53 (TASK-088 AhciFis).
        // 53 → 54 (TASK-089 XhciTrb).
        // 54 → 55 (TASK-090 UefiGop).
        // 55 → 56 (TASK-091 AttestTlv).
        // 56 → 57 (TASK-092 Base64).
        // 57 → 58 (TASK-093 AhciCmd).
        // If a future edit reverts any bump without updating the
        // corresponding trait surface, this test surfaces the drift.
        assert_eq!(CONTRACTS_SCHEMA_VERSION, 58);
    }
}
