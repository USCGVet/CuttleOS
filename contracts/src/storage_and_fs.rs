//! Storage and filesystem contracts: WriteAheadLog, VFS, JournalFs, Fat32, Quota, GPT, AhciFis, and AhciCmd.

use super::*;


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

