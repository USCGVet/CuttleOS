//! Memory management and hardware isolation contracts: IOMMU, KPTI, and FrameBitmap.


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

