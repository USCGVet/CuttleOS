//! Security, policy, and diagnostic contracts: PacketFilter, TPM 2.0, AuditLog, eBPF, StackCanary, CrashDump, SymbolResolve, and GdbStub.

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

