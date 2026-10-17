//! VFS/filesystem, eBPF, Ethernet controller, TFTP, SMP/APIC, PCI, and X.509 contracts.
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

