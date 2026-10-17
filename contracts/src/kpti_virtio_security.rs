//! KPTI, crash/symbol diagnostics, VirtIO MMIO/ring, firewall, TPM, audit, and SNTP contracts.
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

