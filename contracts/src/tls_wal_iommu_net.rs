//! TLS 1.3, Write-Ahead Log, IOMMU, and core network protocol contracts.
use crate::*;
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

