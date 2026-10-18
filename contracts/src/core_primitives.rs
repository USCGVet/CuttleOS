//! Core primitives: hash, AEAD, signature verification, syscalls, capabilities, block device, and allocator.

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
/// use cuttle_contracts::{CapError, CapProof, SyscallCapTable, caps};
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
    /// # use cuttle_contracts::{CapError, CapProof, SyscallCapTable, caps};
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
/// # use cuttle_contracts::{mint_cap_proof, caps};
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
        let aad1: &[u8] = b"cuttle-harness-aad-v1";
        let aad2: &[u8] = b"cuttle-harness-aad-v2-different";

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
