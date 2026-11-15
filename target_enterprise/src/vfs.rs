//! Virtual filesystem layer — [`VfsImpl`] dispatcher + [`MemRamFs`].
//!
//! This module is the [`cuttle_contracts::Vfs`] +
//! [`cuttle_contracts::Filesystem`] contract impl. Closes the
//! no-filesystem gap left by every prior iteration — the kernel had no
//! inode dispatch before this, and the donor `RustOSa/src/vfs.rs`
//! shipped only a per-process file-descriptor table that slurped whole
//! files off a FAT32 reader into `Vec<u8>` buffers. This port replaces
//! the heap-backed flat-FD table with:
//!
//! - **`VfsImpl<N>`** — fixed-capacity mount table (`N` slots). Mounts
//!   register absolute path prefixes; `open`/`stat` route to the
//!   longest-matching prefix. `read`/`write`/`close` route by the mount
//!   id packed into the [`FsHandle`].
//! - **`MemRamFs<I, P>`** — in-memory reference filesystem backed by
//!   `I`-many inodes and a `P`-byte block pool. Supports a small flat
//!   namespace (`/etc/hostname`, `/var/log/messages.0`) with `open`
//!   honouring `FS_O_RDONLY` / `_WRONLY` / `_RDWR` / `_CREATE` /
//!   `_TRUNC` / `_EXCL`, `read`/`write` at arbitrary offsets,
//!   `stat` returning a [`FileStat`].
//!
//! The handle packing is `mount_id : per_fs_handle` with 8 bits for
//! the mount and 24 bits for the handle (top 8 + bottom 24). The
//! VFS strips the mount id on the way in and re-asserts it on the way
//! back out so callers cannot forge cross-mount accesses.
//!
//! # What this does NOT implement (intentional)
//!
//! - On-disk persistence. The block pool lives entirely in RAM.
//! - Directory iteration / `readdir`. The seed exposes a flat
//!   "file-by-path" namespace; directories appear in `stat` purely as
//!   metadata when the path is the literal mount root.
//! - Hard links / symlinks / inodes with multiple names.
//! - Case-insensitive path matching. Paths are byte-exact.
//! - User-id / group-id permission checks. `FileStat::mode` carries
//!   the perm bits but the trait surface deliberately does not
//!   enforce them (out of scope; a future syscall-side `creds`
//!   layer will).
//!
//! The donor's `Vec`-backed slurp is replaced with offset-addressed
//! reads against the block pool, so a future streaming-FAT32
//! `Filesystem` impl can swap in without changing the dispatcher.

#![allow(missing_docs)]
#![allow(clippy::needless_range_loop)]

use alloc::vec::Vec;
use cuttle_contracts::{
    FileStat, Filesystem, FsError, FsHandle, Vfs, FS_MAX_MOUNTS, FS_NAME_MAX, FS_O_ACCMODE,
    FS_O_CREATE, FS_O_EXCL, FS_O_RDONLY, FS_O_RDWR, FS_O_TRUNC, FS_O_WRONLY, FS_PATH_MAX,
};

/// Maximum number of VFS inodes supported when [`MemRamFs::is_paged_mode`] is active.
pub const PAGED_VFS_MAX_INODES: usize = 96;
/// Maximum total VFS pool bytes supported when [`MemRamFs::is_paged_mode`] is active (`256 KiB`).
pub const PAGED_VFS_MAX_POOL: usize = 262_144;
/// Maximum byte length of a single regular file in paged VFS mode (`32 KiB` = `8` x 4 KiB pages).
pub const PAGED_VFS_MAX_FILE_BYTES: usize = 32_768;

// ============================================================
// Handle packing
// ============================================================

/// Number of bits in [`FsHandle`] reserved for the mount id.
pub const VFS_MOUNT_ID_BITS: u32 = 8;
/// Mask of the per-fs handle bits (low 24 bits).
pub const VFS_PER_FS_MASK: u32 = (1 << (32 - VFS_MOUNT_ID_BITS)) - 1;
/// Maximum value the mount id can carry (`2^8 - 1 = 255`).
pub const VFS_MAX_MOUNT_ID: u32 = (1 << VFS_MOUNT_ID_BITS) - 1;

/// Combine `mount_id` (1..=255 — id 0 is reserved as the
/// [`FsHandle::NONE`] sentinel) and `per_fs` (0..=(2^24 - 1)) into a
/// single 32-bit handle.
pub const fn pack_handle(mount_id: u8, per_fs: u32) -> FsHandle {
    let m = (mount_id as u32) << (32 - VFS_MOUNT_ID_BITS);
    FsHandle::from_raw(m | (per_fs & VFS_PER_FS_MASK))
}

/// Inverse of [`pack_handle`]. Returns `(mount_id, per_fs)`.
pub const fn unpack_handle(h: FsHandle) -> (u8, u32) {
    let raw = h.raw();
    let m = (raw >> (32 - VFS_MOUNT_ID_BITS)) as u8;
    let p = raw & VFS_PER_FS_MASK;
    (m, p)
}

// ============================================================
// Path validation + normalisation
// ============================================================

/// Whether `path` is a valid absolute path.
///
/// Rules:
/// - non-empty
/// - starts with `b'/'`
/// - length ≤ [`FS_PATH_MAX`]
/// - every component ≤ [`FS_NAME_MAX`] bytes
/// - no embedded NUL (`b'\0'`)
/// - bytes are ASCII printable (`0x20..=0x7E`) excluding the chars
///   `<`, `>`, `:`, `"`, `\`, `|`, `?`, `*` (Windows-style guard so
///   the kernel never produces a path that round-trips poorly when
///   logged to a host audit collector).
pub fn validate_path(path: &[u8]) -> Result<(), FsError> {
    if path.is_empty() || path.len() > FS_PATH_MAX {
        return Err(if path.is_empty() {
            FsError::BadPath
        } else {
            FsError::NameTooLong
        });
    }
    if path[0] != b'/' {
        return Err(FsError::BadPath);
    }
    let mut comp_len = 0usize;
    let mut i = 0usize;
    while i < path.len() {
        let c = path[i];
        if c == 0 {
            return Err(FsError::BadPath);
        }
        if c < 0x20 || c > 0x7E {
            return Err(FsError::BadPath);
        }
        match c {
            b'<' | b'>' | b':' | b'"' | b'\\' | b'|' | b'?' | b'*' => {
                return Err(FsError::BadPath);
            }
            _ => {}
        }
        if c == b'/' {
            if comp_len > FS_NAME_MAX {
                return Err(FsError::NameTooLong);
            }
            comp_len = 0;
        } else {
            comp_len += 1;
            if comp_len > FS_NAME_MAX {
                return Err(FsError::NameTooLong);
            }
        }
        i += 1;
    }
    Ok(())
}

/// Normalise an absolute path in-place into `out`: collapse repeated
/// slashes, strip trailing slash (except for the literal root `/`),
/// resolve `.` and `..` segments.
///
/// Returns the byte length written to `out`. On invalid input
/// (escapes above the root, malformed) returns [`FsError::BadPath`].
pub fn normalise_path(path: &[u8], out: &mut [u8]) -> Result<usize, FsError> {
    validate_path(path)?;
    // Stack of segment byte ranges (start, len) within `out`.
    // `FS_PATH_MAX / 2 + 1` is the worst-case segment count when every
    // component is a single byte; 130 is enough for FS_PATH_MAX = 256.
    let mut starts = [0usize; 130];
    let mut lens = [0usize; 130];
    let mut n_segs = 0usize;

    let mut cursor = 1usize; // skip leading '/'
    while cursor <= path.len() {
        // find next '/' or end
        let mut end = cursor;
        while end < path.len() && path[end] != b'/' {
            end += 1;
        }
        let seg = &path[cursor..end];
        match seg {
            b"" | b"." => { /* skip */ }
            b".." => {
                if n_segs == 0 {
                    return Err(FsError::BadPath);
                }
                n_segs -= 1;
            }
            _ => {
                if n_segs >= starts.len() {
                    return Err(FsError::NameTooLong);
                }
                // Reuse `out` as the scratch byte arena. We can't yet
                // commit because re-traversing would clobber; instead
                // record (offset, len) tuples that point into `path`
                // and stitch at the end.
                starts[n_segs] = cursor;
                lens[n_segs] = end - cursor;
                n_segs += 1;
            }
        }
        cursor = end + 1;
    }

    if n_segs == 0 {
        // Pure root.
        if out.is_empty() {
            return Err(FsError::NameTooLong);
        }
        out[0] = b'/';
        return Ok(1);
    }

    // Stitch segments separated by '/', leading '/'.
    let mut w = 0usize;
    let mut s = 0usize;
    while s < n_segs {
        if w >= out.len() {
            return Err(FsError::NameTooLong);
        }
        out[w] = b'/';
        w += 1;
        let start = starts[s];
        let len = lens[s];
        if w + len > out.len() {
            return Err(FsError::NameTooLong);
        }
        let mut k = 0usize;
        while k < len {
            out[w + k] = path[start + k];
            k += 1;
        }
        w += len;
        s += 1;
    }
    Ok(w)
}

/// Byte-compare two slices for equality.
fn bytes_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len() {
        if a[i] != b[i] {
            return false;
        }
        i += 1;
    }
    true
}

/// Return `true` if `path` (normalized) names one of the 4 read-only system files
/// unconditionally created during `seed_defaults_for_boot` (`0..4`).
pub fn is_boot_seeded_system_file(path: &[u8]) -> bool {
    bytes_eq(path, b"/etc/hostname")
        || bytes_eq(path, b"/etc/os-release")
        || bytes_eq(path, b"/etc/motd")
        || bytes_eq(path, b"/proc/net")
}

/// Maximum normalized path length permitted in `paged_mode` (`200` bytes, matching `SHELL_MAX_WRITABLE_PATH`).
pub const PAGED_VFS_MAX_PATH: usize = 200;

/// Return `true` if `path` (normalized) names a built-in Cuttle system file that is
/// recreated on every boot and excluded from `PageDomain::VfsDir` / `PageDomain::VfsData`.
pub fn is_builtin_system_file(path: &[u8]) -> bool {
    is_boot_seeded_system_file(path)
        || bytes_eq(path, b"/bin/fib")
        || bytes_eq(path, b"/bin/sum")
        || bytes_eq(path, b"/sbin/svc-http")
        || bytes_eq(path, b"/sbin/svc-sql")
        || bytes_eq(path, b"/sbin/svc-sh")
}

/// True iff `path` (already normalised) starts with `prefix` (also
/// already normalised) on a path-component boundary.
///
/// Examples (with normalised inputs):
/// - `/` is a prefix of `/etc/hostname`.
/// - `/etc` is a prefix of `/etc/hostname`.
/// - `/et` is NOT a prefix of `/etc/hostname` (no component boundary).
fn path_has_prefix(path: &[u8], prefix: &[u8]) -> bool {
    if prefix.len() > path.len() {
        return false;
    }
    let mut i = 0usize;
    while i < prefix.len() {
        if path[i] != prefix[i] {
            return false;
        }
        i += 1;
    }
    // Boundary check: prefix must end on '/', or `path[prefix.len()]`
    // must be '/' or end-of-string.
    if prefix.len() == 1 && prefix[0] == b'/' {
        return true;
    }
    if path.len() == prefix.len() {
        return true;
    }
    path[prefix.len()] == b'/'
}

/// Compute the residual path after stripping `mount_point` from `path`.
/// Both inputs are already normalised. The residual always begins
/// with `/` (the mount root contains `/`).
fn strip_mount_prefix<'a>(path: &'a [u8], mount_point: &[u8]) -> &'a [u8] {
    if mount_point.len() == 1 && mount_point[0] == b'/' {
        return path;
    }
    if path.len() == mount_point.len() {
        return b"/";
    }
    &path[mount_point.len()..]
}

// ============================================================
// MemRamFs — in-memory reference Filesystem impl
// ============================================================

/// Per-inode entry. Compact fixed layout so the morph engine has a
/// stable shape to diversify around.
#[derive(Clone, Copy)]
struct RamInode {
    /// Whether this inode slot is in use.
    used: bool,
    /// Path bytes (absolute, normalised). `path_len` is the live
    /// portion; bytes past it are zero.
    path: [u8; FS_PATH_MAX],
    path_len: u16,
    /// Offset into the parent `MemRamFs::pool` where this file's
    /// data begins.
    data_off: u32,
    /// Live byte count of the file.
    data_len: u32,
    /// Capacity reserved in the pool (>= data_len). Once allocated
    /// it does not move — write growth is bounded by this capacity.
    capacity: u32,
    /// Modification time in Unix seconds (caller-supplied at create
    /// time; the ramfs has no clock source of its own).
    mtime: u64,
}

const EMPTY_INODE: RamInode = RamInode {
    used: false,
    path: [0u8; FS_PATH_MAX],
    path_len: 0,
    data_off: 0,
    data_len: 0,
    capacity: 0,
    mtime: 0,
};

/// Per-open-file table entry.
#[derive(Clone, Copy)]
struct RamOpenFile {
    used: bool,
    inode_idx: u32,
    /// `flags & FS_O_ACCMODE` — cached for write-permission check.
    access_mode: u32,
}

const EMPTY_OPEN: RamOpenFile = RamOpenFile {
    used: false,
    inode_idx: 0,
    access_mode: 0,
};

/// In-memory reference [`Filesystem`] backed by `I` inodes and a
/// `P`-byte block pool.
///
/// Typical kernel-banner instantiation is `MemRamFs::<8, 4096>::new()`
/// — eight files in 4 KiB. Tests use smaller capacities to exercise
/// the [`FsError::NoSpace`] / [`FsError::TooManyHandles`] paths.
pub struct MemRamFs<const I: usize, const P: usize> {
    inodes: [RamInode; I],
    /// Open-file table per filesystem. Sized to `I` because the worst
    /// case is "every inode open once"; the dispatcher's mount id
    /// gives extra headroom.
    open: [RamOpenFile; I],
    pool: [u8; P],
    /// High-water mark for the pool in inline mode.
    pool_used: u32,
    /// Whether this filesystem is mounted read-only. The mount call
    /// sets this; `open` honours it.
    read_only: bool,
    /// Advanced by every call that creates, truncates, writes or removes a
    /// file. Never decreases while the filesystem is alive.
    mutation_seq: u64,
    /// Whether page-granular extended capacity (`96` inodes, `256 KiB` pool) is enabled.
    paged_mode: bool,
    /// Total bytes reserved/consumed across all inodes in `paged_mode`.
    paged_pool_used: u32,
    /// Overflow inode slots (`I..PAGED_VFS_MAX_INODES`) allocated lazily in `paged_mode`.
    overflow_inodes: Vec<RamInode>,
    /// Overflow open-file handle slots (`I..PAGED_VFS_MAX_INODES`) in `paged_mode`.
    overflow_open: Vec<RamOpenFile>,
    /// Per-inode heap extents (`0..PAGED_VFS_MAX_INODES`) storing file data in `paged_mode`.
    paged_extents: Vec<Vec<u8>>,
    /// 128-bit dirty bitmask over `0..96` inode slots since last `PagedBlockStore` sync.
    dirty_inode_mask: [u64; 2],
    /// Whether directory metadata (`path`, `data_len`, `mtime`, or existence) changed since last sync.
    dir_dirty: bool,
    /// Optional logical-page cap (`PageDomain::VfsDir` + `PageDomain::VfsData`) enforced in `paged_mode`.
    paged_page_budget: Option<usize>,
}

impl<const I: usize, const P: usize> MemRamFs<I, P> {
    /// Construct an empty ramfs (`const fn`, zero heap allocations).
    pub const fn new() -> Self {
        MemRamFs {
            inodes: [EMPTY_INODE; I],
            open: [EMPTY_OPEN; I],
            pool: [0u8; P],
            pool_used: 0,
            read_only: false,
            mutation_seq: 0,
            paged_mode: false,
            paged_pool_used: 0,
            overflow_inodes: Vec::new(),
            overflow_open: Vec::new(),
            paged_extents: Vec::new(),
            dirty_inode_mask: [0u64; 2],
            dir_dirty: false,
            paged_page_budget: None,
        }
    }

    /// Set or clear the maximum logical 4 KiB pages (`VfsDir` + `VfsData`) this VFS may occupy in `paged_mode`.
    pub fn set_paged_page_budget(&mut self, budget: Option<usize>) {
        self.paged_page_budget = budget;
    }

    /// Return the configured logical-page budget in `paged_mode`, if any.
    pub const fn paged_page_budget(&self) -> Option<usize> {
        self.paged_page_budget
    }

    /// Exact number of `PagedBlockStore` logical pages (`PageDomain::VfsDir` + `PageDomain::VfsData`)
    /// required to persist the current non-builtin files in `paged_mode`.
    pub fn paged_pages_needed(&self) -> usize {
        if !self.paged_mode {
            return 0;
        }
        self.paged_pages_with_override(None)
    }

    fn paged_pages_with_override(&self, override_slot: Option<(usize, &[u8], usize)>) -> usize {
        const VFS_DIR_GROUPS: usize = 8;
        const VFS_INODES_PER_DIR_PAGE: usize = 12;
        const VFS_DATA_CHUNK_CAP: usize = 4000;
        let slots_len = self.inode_slots_len();
        let mut total = 0usize;
        let mut group_idx = 0usize;
        while group_idx < VFS_DIR_GROUPS {
            let base = group_idx * VFS_INODES_PER_DIR_PAGE;
            let mut has_user_entry = false;
            let mut group_data_pages = 0usize;
            let mut off = 0usize;
            while off < VFS_INODES_PER_DIR_PAGE {
                let slot_idx = base + off;
                let (used, path_slice, bytes_len): (bool, &[u8], usize) = match override_slot {
                    Some((ov_idx, ov_path, ov_len)) if ov_idx == slot_idx => {
                        (true, ov_path, ov_len)
                    }
                    _ if slot_idx < slots_len && self.inode_at(slot_idx).used => {
                        let ino = self.inode_at(slot_idx);
                        (
                            true,
                            &ino.path[..ino.path_len as usize],
                            ino.data_len.max(ino.capacity) as usize,
                        )
                    }
                    _ => (false, &[], 0),
                };
                if used && !is_builtin_system_file(path_slice) {
                    has_user_entry = true;
                    if bytes_len > 0 {
                        group_data_pages += (bytes_len + VFS_DATA_CHUNK_CAP - 1) / VFS_DATA_CHUNK_CAP;
                    }
                }
                off += 1;
            }
            if has_user_entry {
                total += 1 + group_data_pages;
            }
            group_idx += 1;
        }
        total
    }

    /// `true` when page-granular extended capacity (`96` files, `256 KiB` pool) is active.
    #[inline]
    pub const fn is_paged_mode(&self) -> bool {
        self.paged_mode
    }

    /// Enable or disable page-granular VFS mode (`<= 96` inodes, `<= 256 KiB` pool).
    ///
    /// When transitioning from inline to paged mode, any already-seeded inline files
    /// in `0..I` are migrated lossless into `paged_extents`.
    pub fn set_paged_mode(&mut self, enabled: bool) {
        if enabled && !self.paged_mode {
            if self.paged_extents.len() < PAGED_VFS_MAX_INODES {
                self.paged_extents
                    .resize_with(PAGED_VFS_MAX_INODES, Vec::new);
            }
            let mut total = 0u32;
            let mut i = 0usize;
            while i < I {
                if self.inodes[i].used {
                    let off = self.inodes[i].data_off as usize;
                    let len = (self.inodes[i].data_len as usize).min(P.saturating_sub(off));
                    if i < PAGED_VFS_MAX_INODES {
                        self.paged_extents[i].clear();
                        self.paged_extents[i].extend_from_slice(&self.pool[off..off + len]);
                    }
                    self.inodes[i].data_off = 0;
                    let cap = self.inodes[i].capacity.max(len as u32);
                    self.inodes[i].capacity = cap;
                    total = total.saturating_add(cap);
                    self.mark_inode_dirty(i);
                }
                i += 1;
            }
            self.pool = [0u8; P];
            self.pool_used = 0;
            self.paged_pool_used = total;
            self.paged_mode = true;
            self.dir_dirty = true;
        } else if !enabled && self.paged_mode {
            // Refuse to exit `paged_mode` if any overflow inode (`I..`) or overflow handle is active,
            // or if total inline capacities do not fit inside the fixed `P`-byte inline pool.
            if self.overflow_inodes.iter().any(|ino| ino.used)
                || self.overflow_open.iter().any(|op| op.used)
            {
                return;
            }
            let mut needed_pool = 0usize;
            let mut i = 0usize;
            while i < I {
                if self.inodes[i].used {
                    let ext_len = self
                        .paged_extents
                        .get(i)
                        .map(|v| v.len())
                        .unwrap_or(self.inodes[i].data_len as usize);
                    let cap = (self.inodes[i].capacity as usize).max(ext_len);
                    let Some(next_total) = needed_pool.checked_add(cap) else {
                        return;
                    };
                    if next_total > P {
                        return;
                    }
                    needed_pool = next_total;
                }
                i += 1;
            }
            self.pool = [0u8; P];
            let mut cursor = 0usize;
            let mut slot = 0usize;
            while slot < I {
                if self.inodes[slot].used {
                    let ext_slice = self
                        .paged_extents
                        .get(slot)
                        .map(|v| v.as_slice())
                        .unwrap_or(&[]);
                    let copy_len = ext_slice.len().min(self.inodes[slot].data_len as usize);
                    let cap = (self.inodes[slot].capacity as usize).max(copy_len);
                    self.pool[cursor..cursor + copy_len].copy_from_slice(&ext_slice[..copy_len]);
                    self.inodes[slot].data_off = cursor as u32;
                    self.inodes[slot].data_len = copy_len as u32;
                    self.inodes[slot].capacity = cap as u32;
                    cursor += cap;
                }
                slot += 1;
            }
            self.pool_used = cursor as u32;
            self.paged_pool_used = 0;
            self.paged_extents.clear();
            self.overflow_inodes.clear();
            self.overflow_open.clear();
            self.paged_page_budget = None;
            self.paged_mode = false;
        }
    }

    /// Maximum inode count supported in the current mode (`I` inline, `96` paged).
    #[inline]
    pub const fn max_inodes(&self) -> usize {
        if self.paged_mode && PAGED_VFS_MAX_INODES > I {
            PAGED_VFS_MAX_INODES
        } else {
            I
        }
    }

    #[inline]
    fn inode_slots_len(&self) -> usize {
        if self.paged_mode {
            I + self.overflow_inodes.len()
        } else {
            I
        }
    }

    #[inline]
    fn inode_at(&self, idx: usize) -> &RamInode {
        if idx < I {
            &self.inodes[idx]
        } else {
            self.overflow_inodes
                .get(idx - I)
                .unwrap_or(&EMPTY_INODE)
        }
    }

    #[inline]
    fn inode_mut(&mut self, idx: usize) -> &mut RamInode {
        if idx < I {
            &mut self.inodes[idx]
        } else {
            let ext = idx - I;
            if self.overflow_inodes.len() <= ext {
                self.overflow_inodes.resize(ext + 1, EMPTY_INODE);
            }
            &mut self.overflow_inodes[ext]
        }
    }

    #[inline]
    fn open_slots_len(&self) -> usize {
        if self.paged_mode {
            I + self.overflow_open.len()
        } else {
            I
        }
    }

    #[inline]
    fn open_at(&self, slot: usize) -> &RamOpenFile {
        if slot < I {
            &self.open[slot]
        } else {
            self.overflow_open.get(slot - I).unwrap_or(&EMPTY_OPEN)
        }
    }

    #[inline]
    fn open_mut(&mut self, slot: usize) -> &mut RamOpenFile {
        if slot < I {
            &mut self.open[slot]
        } else {
            let ext = slot - I;
            if self.overflow_open.len() <= ext {
                self.overflow_open.resize(ext + 1, EMPTY_OPEN);
            }
            &mut self.overflow_open[ext]
        }
    }

    #[inline]
    fn ensure_paged_extent(&mut self, idx: usize) {
        if self.paged_extents.len() <= idx {
            self.paged_extents.resize_with(idx + 1, Vec::new);
        }
    }

    #[inline]
    fn mark_inode_dirty(&mut self, idx: usize) {
        let w = idx / 64;
        if w < 2 {
            self.dirty_inode_mask[w] |= 1u64 << (idx % 64);
        }
        self.dir_dirty = true;
    }

    /// `true` if directory metadata changed since the last paged-store sync.
    #[inline]
    pub const fn is_dir_dirty(&self) -> bool {
        self.dir_dirty
    }

    /// `true` if inode slot `idx` changed since the last paged-store sync.
    #[inline]
    pub const fn is_inode_dirty(&self, idx: usize) -> bool {
        let w = idx / 64;
        if w < 2 {
            (self.dirty_inode_mask[w] & (1u64 << (idx % 64))) != 0
        } else {
            false
        }
    }

    /// Re-mark all inode slots and directory metadata dirty (e.g., after a device I/O fault).
    pub fn mark_all_paged_dirty(&mut self) {
        self.dirty_inode_mask = [u64::MAX, u64::MAX];
        self.dir_dirty = true;
    }

    /// Clear dirty inode and directory flags after a successful `PagedBlockStore` sync.
    pub fn clear_paged_dirty(&mut self) {
        self.dirty_inode_mask = [0u64; 2];
        self.dir_dirty = false;
    }

    /// A counter that advances whenever file contents or the set of files
    /// may have changed (`seed_file`, a creating or truncating `open`,
    /// `write`, `unlink`).
    ///
    /// Callers that persist the filesystem compare it against the value at
    /// their last save to learn that a save is due. Because the inode table
    /// and pool are private, these calls are the only way to change them, so
    /// an unchanged counter means unchanged contents. The reverse does not
    /// hold: a write of identical bytes still advances it.
    pub const fn mutation_seq(&self) -> u64 {
        self.mutation_seq
    }

    /// Number of inodes currently in use.
    pub fn inode_count(&self) -> usize {
        let mut n = 0usize;
        let len = self.inode_slots_len();
        let mut i = 0usize;
        while i < len {
            if self.inode_at(i).used {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Bytes of pool consumed.
    pub const fn pool_used(&self) -> u32 {
        if self.paged_mode {
            self.paged_pool_used
        } else {
            self.pool_used
        }
    }

    /// Total pool capacity (`P` inline, `262,144` in `paged_mode`).
    pub const fn pool_capacity(&self) -> usize {
        if self.paged_mode && PAGED_VFS_MAX_POOL > P {
            PAGED_VFS_MAX_POOL
        } else {
            P
        }
    }

    /// Flip the read-only flag.
    pub fn set_read_only(&mut self, ro: bool) {
        self.read_only = ro;
    }

    /// Whether this filesystem is read-only.
    pub const fn is_read_only(&self) -> bool {
        self.read_only
    }

    /// Seed an existing path with the given bytes. Used by callers
    /// who need a populated fixture before mounting (the kernel
    /// banner does this with `/etc/hostname`). Returns
    /// [`FsError::NoSpace`] if the pool or inode table is full,
    /// [`FsError::AlreadyExists`] if the path is already populated.
    ///
    /// The `capacity` is the reservation in the pool: future writes
    /// at offset 0 may extend up to `capacity` without re-allocating.
    pub fn seed_file(
        &mut self,
        path: &[u8],
        contents: &[u8],
        capacity: usize,
        mtime: u64,
    ) -> Result<u32, FsError> {
        validate_path(path)?;
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        if self.paged_mode && n > PAGED_VFS_MAX_PATH {
            return Err(FsError::NameTooLong);
        }
        let max_ino = self.max_inodes();
        let mut free_idx: Option<usize> = None;
        let mut i = 0usize;
        while i < max_ino {
            let slot_ref = self.inode_at(i);
            if slot_ref.used {
                if bytes_eq(&slot_ref.path[..slot_ref.path_len as usize], &norm[..n]) {
                    return Err(FsError::AlreadyExists);
                }
            } else if free_idx.is_none() {
                free_idx = Some(i);
            }
            i += 1;
        }
        let idx = free_idx.ok_or(FsError::NoSpace)?;
        let cap = if contents.len() > capacity {
            contents.len()
        } else {
            capacity
        };
        if cap > u32::MAX as usize {
            return Err(FsError::NoSpace);
        }
        if self.paged_mode {
            if contents.len() > PAGED_VFS_MAX_FILE_BYTES
                || cap > PAGED_VFS_MAX_FILE_BYTES
                || (self.paged_pool_used as usize).saturating_add(cap) > self.pool_capacity()
            {
                return Err(FsError::NoSpace);
            }
            if let Some(budget) = self.paged_page_budget {
                if self.paged_pages_with_override(Some((idx, &norm[..n], cap))) > budget {
                    return Err(FsError::NoSpace);
                }
            }
            self.ensure_paged_extent(idx);
            self.paged_extents[idx].clear();
            self.paged_extents[idx].extend_from_slice(contents);
            self.paged_pool_used += cap as u32;
            let slot = self.inode_mut(idx);
            slot.used = true;
            slot.path = [0u8; FS_PATH_MAX];
            slot.path[..n].copy_from_slice(&norm[..n]);
            slot.path_len = n as u16;
            slot.data_off = 0;
            slot.data_len = contents.len() as u32;
            slot.capacity = cap as u32;
            slot.mtime = mtime;
            self.mark_inode_dirty(idx);
            self.mutation_seq = self.mutation_seq.wrapping_add(1);
            return Ok(idx as u32);
        }

        if (self.pool_used as usize) + cap > P {
            return Err(FsError::NoSpace);
        }
        let off = self.pool_used as usize;
        let mut k = 0usize;
        while k < contents.len() {
            self.pool[off + k] = contents[k];
            k += 1;
        }
        self.pool_used += cap as u32;
        let slot = &mut self.inodes[idx];
        slot.used = true;
        slot.path_len = n as u16;
        let mut p = 0usize;
        while p < FS_PATH_MAX {
            slot.path[p] = 0;
            p += 1;
        }
        let mut p = 0usize;
        while p < n {
            slot.path[p] = norm[p];
            p += 1;
        }
        slot.data_off = off as u32;
        slot.data_len = contents.len() as u32;
        slot.capacity = cap as u32;
        slot.mtime = mtime;
        self.mutation_seq = self.mutation_seq.wrapping_add(1);
        Ok(idx as u32)
    }

    /// Restore a file directly into `slot_idx` (`paged_mode` only) so inode-to-`PageDomain::VfsData`
    /// `owner_id` mappings remain 100% stable across `unlink` holes and reboots.
    pub fn seed_file_at_slot(
        &mut self,
        slot_idx: usize,
        path: &[u8],
        contents: &[u8],
        mtime: u64,
    ) -> Result<(), FsError> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        if !self.paged_mode || slot_idx >= self.max_inodes() {
            return Err(FsError::BadPath);
        }
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        if n > PAGED_VFS_MAX_PATH {
            return Err(FsError::NameTooLong);
        }
        if &norm[..n] == b"/" {
            return Err(FsError::IsADir);
        }
        if self.inode_at(slot_idx).used || self.find_inode(&norm[..n]).is_some() {
            return Err(FsError::AlreadyExists);
        }
        let dlen = contents.len();
        if dlen > PAGED_VFS_MAX_FILE_BYTES
            || (self.paged_pool_used as usize).saturating_add(dlen) > self.pool_capacity()
        {
            return Err(FsError::NoSpace);
        }
        if let Some(budget) = self.paged_page_budget {
            if self.paged_pages_with_override(Some((slot_idx, &norm[..n], dlen))) > budget {
                return Err(FsError::NoSpace);
            }
        }
        self.ensure_paged_extent(slot_idx);
        self.paged_extents[slot_idx].clear();
        self.paged_extents[slot_idx].extend_from_slice(contents);
        self.paged_pool_used += dlen as u32;
        let slot = self.inode_mut(slot_idx);
        slot.used = true;
        slot.path = [0u8; FS_PATH_MAX];
        slot.path[..n].copy_from_slice(&norm[..n]);
        slot.path_len = n as u16;
        slot.data_off = 0;
        slot.data_len = dlen as u32;
        slot.capacity = dlen as u32;
        slot.mtime = mtime;
        self.mark_inode_dirty(slot_idx);
        self.mutation_seq = self.mutation_seq.wrapping_add(1);
        Ok(())
    }

    /// `true` iff replacing the whole contents of `path` with `len` bytes is
    /// certain to succeed: an `open` with `FS_O_RDWR | FS_O_CREATE |
    /// FS_O_TRUNC` followed by one `write` of `len` bytes at offset 0.
    ///
    /// Truncation discards the old contents before the write is attempted,
    /// so a caller that must not lose the old file on a full pool asks this
    /// first. The answer accounts for the pool bytes the existing file gives
    /// back when it is truncated.
    pub fn can_replace(&self, path: &[u8], len: usize) -> bool {
        if self.read_only || len > u32::MAX as usize {
            return false;
        }
        if self.paged_mode && len > PAGED_VFS_MAX_FILE_BYTES {
            return false;
        }
        let mut norm = [0u8; FS_PATH_MAX];
        let Ok(n) = normalise_path(path, &mut norm) else {
            return false;
        };
        if self.paged_mode && n > PAGED_VFS_MAX_PATH {
            return false;
        }
        if &norm[..n] == b"/" {
            return false;
        }
        let max_ino = self.max_inodes();
        let mut open_slot_free = false;
        let mut first_free_inode: Option<usize> = None;
        let mut i = 0usize;
        while i < max_ino {
            open_slot_free |= !self.open_at(i).used;
            if first_free_inode.is_none() && !self.inode_at(i).used {
                first_free_inode = Some(i);
            }
            i += 1;
        }
        if !open_slot_free {
            return false;
        }
        let free = self
            .pool_capacity()
            .saturating_sub(self.pool_used() as usize);
        match self.find_inode(&norm[..n]) {
            Some(idx) => {
                if len > free + self.inode_at(idx).capacity as usize {
                    return false;
                }
                if self.paged_mode {
                    if let Some(budget) = self.paged_page_budget {
                        if self.paged_pages_with_override(Some((idx, &norm[..n], len))) > budget {
                            return false;
                        }
                    }
                }
                true
            }
            None => {
                let Some(free_idx) = first_free_inode else {
                    return false;
                };
                if !(free > 0 && len <= free) {
                    return false;
                }
                if self.paged_mode {
                    if let Some(budget) = self.paged_page_budget {
                        if self.paged_pages_with_override(Some((free_idx, &norm[..n], len)))
                            > budget
                        {
                            return false;
                        }
                    }
                }
                true
            }
        }
    }

    /// Inspect an inode slot by index (`0..max_inodes()`). Returns `Some((path_bytes, data_len))`
    /// if the slot is currently occupied.
    pub fn inode_entry(&self, idx: usize) -> Option<(&[u8], u32)> {
        if idx >= self.inode_slots_len() || !self.inode_at(idx).used {
            return None;
        }
        let slot = self.inode_at(idx);
        Some((&slot.path[..slot.path_len as usize], slot.data_len))
    }

    /// Borrow both `(path_bytes, data_bytes)` for an occupied inode slot (`0..max_inodes()`).
    pub fn inode_data(&self, idx: usize) -> Option<(&[u8], &[u8])> {
        if idx >= self.inode_slots_len() || !self.inode_at(idx).used {
            return None;
        }
        let slot = self.inode_at(idx);
        if self.paged_mode {
            let ext = self.paged_extents.get(idx)?;
            let end = (slot.data_len as usize).min(ext.len());
            return Some((&slot.path[..slot.path_len as usize], &ext[..end]));
        }
        let start = slot.data_off as usize;
        let end = start.saturating_add(slot.data_len as usize);
        if end > P {
            return None;
        }
        Some((&slot.path[..slot.path_len as usize], &self.pool[start..end]))
    }

    /// Inspect the modification timestamp (`mtime`) of an occupied inode slot (`0..max_inodes()`).
    pub fn inode_mtime(&self, idx: usize) -> Option<u64> {
        if idx >= self.inode_slots_len() || !self.inode_at(idx).used {
            return None;
        }
        Some(self.inode_at(idx).mtime)
    }

    /// Update the modification timestamp (`mtime`) of an existing regular file.
    pub fn set_mtime(&mut self, path: &[u8], mtime: u64) -> Result<(), FsError> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        if &norm[..n] == b"/" {
            return Err(FsError::IsADir);
        }
        let idx = self.find_inode(&norm[..n]).ok_or(FsError::NotFound)?;
        self.inode_mut(idx).mtime = mtime;
        if self.paged_mode {
            self.mark_inode_dirty(idx);
        }
        self.mutation_seq = self.mutation_seq.wrapping_add(1);
        Ok(())
    }

    /// Remove a file by path. Returns [`FsError::ReadOnly`] if mounted read-only,
    /// [`FsError::NotFound`] if absent, or [`FsError::Busy`] if any open handle
    /// references the inode.
    pub fn unlink(&mut self, path: &[u8]) -> Result<(), FsError> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        if &norm[..n] == b"/" {
            return Err(FsError::IsADir);
        }
        let idx = self.find_inode(&norm[..n]).ok_or(FsError::NotFound)?;
        let open_len = self.open_slots_len();
        let mut i = 0usize;
        while i < open_len {
            let op = self.open_at(i);
            if op.used && op.inode_idx as usize == idx {
                return Err(FsError::Busy);
            }
            i += 1;
        }
        if self.paged_mode {
            let old_cap = self.inode_at(idx).capacity;
            self.paged_pool_used = self.paged_pool_used.saturating_sub(old_cap);
            if let Some(ext) = self.paged_extents.get_mut(idx) {
                ext.fill(0);
                ext.clear();
            }
            *self.inode_mut(idx) = EMPTY_INODE;
            self.mark_inode_dirty(idx);
            self.mutation_seq = self.mutation_seq.wrapping_add(1);
            return Ok(());
        }
        self.reclaim_inode_capacity(idx);
        self.inodes[idx] = EMPTY_INODE;
        self.mutation_seq = self.mutation_seq.wrapping_add(1);
        Ok(())
    }

    fn truncate_inode(&mut self, idx: usize) {
        self.mutation_seq = self.mutation_seq.wrapping_add(1);
        if self.paged_mode {
            let old_cap = self.inode_at(idx).capacity;
            self.paged_pool_used = self.paged_pool_used.saturating_sub(old_cap);
            if let Some(ext) = self.paged_extents.get_mut(idx) {
                ext.fill(0);
                ext.clear();
            }
            let slot = self.inode_mut(idx);
            slot.data_len = 0;
            slot.capacity = 0;
            self.mark_inode_dirty(idx);
            return;
        }
        if self.inodes[idx].capacity > 256 {
            self.reclaim_inode_capacity(idx);
            let remaining = (P as u64).saturating_sub(self.pool_used as u64);
            let init_cap = 256u64.min(remaining) as u32;
            self.inodes[idx].data_off = self.pool_used;
            self.inodes[idx].capacity = init_cap;
            self.pool_used += init_cap;
        } else {
            let off = self.inodes[idx].data_off as usize;
            let cap = self.inodes[idx].capacity as usize;
            let mut z = 0usize;
            while z < cap && off + z < P {
                self.pool[off + z] = 0;
                z += 1;
            }
            self.inodes[idx].data_len = 0;
        }
    }

    fn reclaim_inode_capacity(&mut self, idx: usize) {
        let removed_off = self.inodes[idx].data_off;
        let removed_cap = self.inodes[idx].capacity;
        self.inodes[idx].data_len = 0;
        if removed_cap > 0
            && (removed_off as usize).saturating_add(removed_cap as usize)
                <= self.pool_used as usize
        {
            let src_start = (removed_off + removed_cap) as usize;
            let dst_start = removed_off as usize;
            let move_len = (self.pool_used as usize).saturating_sub(src_start);
            let mut m = 0usize;
            while m < move_len {
                self.pool[dst_start + m] = self.pool[src_start + m];
                m += 1;
            }
            let new_used = (self.pool_used - removed_cap) as usize;
            let mut z = new_used;
            while z < self.pool_used as usize {
                self.pool[z] = 0;
                z += 1;
            }
            let mut k = 0usize;
            while k < I {
                if self.inodes[k].used
                    && k != idx
                    && self.inodes[k].data_off >= removed_off + removed_cap
                {
                    self.inodes[k].data_off -= removed_cap;
                }
                k += 1;
            }
            self.pool_used -= removed_cap;
        }
        self.inodes[idx].capacity = 0;
        self.inodes[idx].data_off = self.pool_used;
    }

    fn find_inode(&self, norm_path: &[u8]) -> Option<usize> {
        let len = self.inode_slots_len();
        let mut i = 0usize;
        while i < len {
            let slot = self.inode_at(i);
            if slot.used && bytes_eq(&slot.path[..slot.path_len as usize], norm_path) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn allocate_open_slot(&mut self) -> Option<usize> {
        let max_ino = self.max_inodes();
        let mut i = 0usize;
        while i < max_ino {
            if !self.open_at(i).used {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

impl<const I: usize, const P: usize> Default for MemRamFs<I, P> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const I: usize, const P: usize> Filesystem for MemRamFs<I, P> {
    fn open(&mut self, path: &[u8], flags: u32) -> Result<FsHandle, FsError> {
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        let norm_slice = &norm[..n];
        let access = flags & FS_O_ACCMODE;
        if access != FS_O_RDONLY && access != FS_O_WRONLY && access != FS_O_RDWR {
            return Err(FsError::BadPath);
        }
        let wants_write = access == FS_O_WRONLY || access == FS_O_RDWR;
        let create = (flags & FS_O_CREATE) != 0;
        if self.paged_mode && create && n > PAGED_VFS_MAX_PATH {
            return Err(FsError::NameTooLong);
        }
        let excl = (flags & FS_O_EXCL) != 0;
        let trunc = (flags & FS_O_TRUNC) != 0;

        if self.read_only && (wants_write || create || trunc) {
            return Err(FsError::ReadOnly);
        }
        if trunc && !wants_write {
            return Err(FsError::ReadOnly);
        }

        // Refuse to open the literal root as a regular file.
        if norm_slice == b"/" {
            return Err(FsError::IsADir);
        }

        // Reserve the open-file table slot BEFORE mutating or allocating any inode
        // so `TooManyHandles` never truncates an existing file or leaks a new inode.
        let slot = self.allocate_open_slot().ok_or(FsError::TooManyHandles)?;

        let existing = self.find_inode(norm_slice);
        let inode_idx = match (existing, create) {
            (Some(i), false) => {
                if trunc {
                    self.truncate_inode(i);
                }
                i
            }
            (Some(i), true) => {
                if excl {
                    return Err(FsError::AlreadyExists);
                }
                if trunc {
                    self.truncate_inode(i);
                }
                i
            }
            (None, false) => return Err(FsError::NotFound),
            (None, true) => {
                let max_ino = self.max_inodes();
                let mut free_idx: Option<usize> = None;
                let mut k = 0usize;
                while k < max_ino {
                    if !self.inode_at(k).used {
                        free_idx = Some(k);
                        break;
                    }
                    k += 1;
                }
                let idx = free_idx.ok_or(FsError::NoSpace)?;
                if self.paged_mode {
                    let remaining = self
                        .pool_capacity()
                        .saturating_sub(self.paged_pool_used as usize);
                    if remaining == 0 {
                        return Err(FsError::NoSpace);
                    }
                    if let Some(budget) = self.paged_page_budget {
                        if self.paged_pages_with_override(Some((idx, &norm[..n], 0))) > budget {
                            return Err(FsError::NoSpace);
                        }
                    }
                    self.ensure_paged_extent(idx);
                    self.paged_extents[idx].clear();
                    let inode_slot = self.inode_mut(idx);
                    inode_slot.used = true;
                    inode_slot.path = [0u8; FS_PATH_MAX];
                    inode_slot.path[..n].copy_from_slice(&norm[..n]);
                    inode_slot.path_len = n as u16;
                    inode_slot.data_off = 0;
                    inode_slot.data_len = 0;
                    inode_slot.capacity = 0;
                    inode_slot.mtime = 0;
                    self.mark_inode_dirty(idx);
                    self.mutation_seq = self.mutation_seq.wrapping_add(1);
                    idx
                } else {
                    // Allocate a fresh inode + zero-length file (growing pool capacity on demand in `write`).
                    let remaining = (P as u64).saturating_sub(self.pool_used as u64);
                    if remaining == 0 {
                        return Err(FsError::NoSpace);
                    }
                    let init_cap = 256u64.min(remaining) as u32;
                    let off = self.pool_used;
                    self.pool_used += init_cap;
                    let inode_slot = &mut self.inodes[idx];
                    inode_slot.used = true;
                    inode_slot.path_len = n as u16;
                    let mut p = 0usize;
                    while p < FS_PATH_MAX {
                        inode_slot.path[p] = 0;
                        p += 1;
                    }
                    let mut p = 0usize;
                    while p < n {
                        inode_slot.path[p] = norm[p];
                        p += 1;
                    }
                    inode_slot.data_off = off;
                    inode_slot.data_len = 0;
                    inode_slot.capacity = init_cap;
                    inode_slot.mtime = 0;
                    self.mutation_seq = self.mutation_seq.wrapping_add(1);
                    idx
                }
            }
        };

        *self.open_mut(slot) = RamOpenFile {
            used: true,
            inode_idx: inode_idx as u32,
            access_mode: access,
        };
        // Per-fs handle: 1-based to keep raw=0 reserved as "no handle".
        Ok(FsHandle::from_raw((slot as u32) + 1))
    }

    fn read(&mut self, handle: FsHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let slot = handle.raw().checked_sub(1).ok_or(FsError::BadHandle)? as usize;
        if slot >= self.open_slots_len() || !self.open_at(slot).used {
            return Err(FsError::BadHandle);
        }
        let entry = *self.open_at(slot);
        if entry.access_mode == FS_O_WRONLY {
            return Err(FsError::BadHandle);
        }
        let inode_idx = entry.inode_idx as usize;
        let inode = self.inode_at(inode_idx);
        let len = inode.data_len as u64;
        if offset >= len {
            return Ok(0);
        }
        let remaining = (len - offset) as usize;
        let n = if remaining < buf.len() {
            remaining
        } else {
            buf.len()
        };
        if self.paged_mode {
            let ext = self.paged_extents.get(inode_idx).ok_or(FsError::BadHandle)?;
            let start = offset as usize;
            if start + n > ext.len() {
                return Err(FsError::BadHandle);
            }
            buf[..n].copy_from_slice(&ext[start..start + n]);
            return Ok(n);
        }
        let base = inode.data_off as usize + offset as usize;
        let mut i = 0usize;
        while i < n {
            buf[i] = self.pool[base + i];
            i += 1;
        }
        Ok(n)
    }

    fn write(&mut self, handle: FsHandle, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        if self.read_only {
            return Err(FsError::ReadOnly);
        }
        let slot = handle.raw().checked_sub(1).ok_or(FsError::BadHandle)? as usize;
        if slot >= self.open_slots_len() || !self.open_at(slot).used {
            return Err(FsError::BadHandle);
        }
        let entry = *self.open_at(slot);
        if entry.access_mode == FS_O_RDONLY {
            return Err(FsError::BadHandle);
        }
        let inode_idx = entry.inode_idx as usize;
        let end = offset.saturating_add(buf.len() as u64);

        if self.paged_mode {
            if offset > PAGED_VFS_MAX_FILE_BYTES as u64 || end > PAGED_VFS_MAX_FILE_BYTES as u64 {
                return Err(FsError::NoSpace);
            }
            let old_cap = self.inode_at(inode_idx).capacity as u64;
            let new_cap = old_cap.max(end);
            let growth = new_cap - old_cap;
            if (self.paged_pool_used as u64).saturating_add(growth) > self.pool_capacity() as u64 {
                return Err(FsError::NoSpace);
            }
            if let Some(budget) = self.paged_page_budget {
                let ino = self.inode_at(inode_idx);
                let plen = ino.path_len as usize;
                let mut pbuf = [0u8; FS_PATH_MAX];
                pbuf[..plen].copy_from_slice(&ino.path[..plen]);
                let new_len = (ino.data_len as u64).max(new_cap) as usize;
                if self.paged_pages_with_override(Some((inode_idx, &pbuf[..plen], new_len)))
                    > budget
                {
                    return Err(FsError::NoSpace);
                }
            }
            self.ensure_paged_extent(inode_idx);
            let end_usize = end as usize;
            let off_usize = offset as usize;
            if self.paged_extents[inode_idx].len() < end_usize {
                self.paged_extents[inode_idx].resize(end_usize, 0);
            }
            self.paged_extents[inode_idx][off_usize..end_usize].copy_from_slice(buf);
            self.paged_pool_used += growth as u32;
            let slot_mut = self.inode_mut(inode_idx);
            if end as u32 > slot_mut.data_len {
                slot_mut.data_len = end as u32;
            }
            slot_mut.capacity = new_cap as u32;
            self.mark_inode_dirty(inode_idx);
            self.mutation_seq = self.mutation_seq.wrapping_add(1);
            return Ok(buf.len());
        }

        let mut cap = self.inodes[inode_idx].capacity as u64;
        if end > cap && end <= u32::MAX as u64 {
            let needed = end - cap;
            if (self.pool_used as u64).saturating_add(needed) <= P as u64 {
                let needed_u32 = needed as u32;
                let old_tail = self.inodes[inode_idx]
                    .data_off
                    .saturating_add(self.inodes[inode_idx].capacity);
                let move_len = (self.pool_used as usize).saturating_sub(old_tail as usize);
                let mut m = move_len;
                while m > 0 {
                    m -= 1;
                    self.pool[old_tail as usize + needed as usize + m] =
                        self.pool[old_tail as usize + m];
                }
                let mut k = 0usize;
                while k < I {
                    if self.inodes[k].used
                        && k != inode_idx
                        && self.inodes[k].data_off >= old_tail
                    {
                        self.inodes[k].data_off += needed_u32;
                    }
                    k += 1;
                }
                self.inodes[inode_idx].capacity += needed_u32;
                self.pool_used += needed_u32;
                cap = end;
            }
        }
        if offset > cap {
            return Err(FsError::NoSpace);
        }
        if end > cap {
            return Err(FsError::NoSpace);
        }
        let base = self.inodes[inode_idx].data_off as usize + offset as usize;
        let mut i = 0usize;
        while i < buf.len() {
            self.pool[base + i] = buf[i];
            i += 1;
        }
        if end > self.inodes[inode_idx].data_len as u64 {
            let old_len = self.inodes[inode_idx].data_len as u64;
            if offset > old_len {
                let pad_base = self.inodes[inode_idx].data_off as usize + old_len as usize;
                let pad_n = (offset - old_len) as usize;
                let mut k = 0usize;
                while k < pad_n {
                    self.pool[pad_base + k] = 0;
                    k += 1;
                }
            }
            self.inodes[inode_idx].data_len = end as u32;
        }
        self.mutation_seq = self.mutation_seq.wrapping_add(1);
        Ok(buf.len())
    }

    fn close(&mut self, handle: FsHandle) -> Result<(), FsError> {
        let slot = handle.raw().checked_sub(1).ok_or(FsError::BadHandle)? as usize;
        if slot >= self.open_slots_len() || !self.open_at(slot).used {
            return Err(FsError::BadHandle);
        }
        *self.open_mut(slot) = EMPTY_OPEN;
        Ok(())
    }

    fn stat(&self, path: &[u8]) -> Result<FileStat, FsError> {
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        if &norm[..n] == b"/" {
            return Ok(FileStat::dir(0));
        }
        let idx = self.find_inode(&norm[..n]).ok_or(FsError::NotFound)?;
        let inode = self.inode_at(idx);
        Ok(FileStat::file(inode.data_len as u64, inode.mtime))
    }
}

// ============================================================
// VfsImpl — fixed-capacity mount-table dispatcher
// ============================================================

/// One entry in the [`VfsImpl`] mount table.
struct MountEntry {
    used: bool,
    /// Normalised absolute prefix (e.g. `/`, `/boot`).
    mount_point: [u8; FS_PATH_MAX],
    mount_len: u16,
    /// The backing filesystem. `'static` so the VFS does not need a
    /// lifetime parameter; the kernel banner stores ramfs instances
    /// in `static mut` arenas.
    fs: Option<&'static mut dyn Filesystem>,
    /// Number of handles currently open against this mount. Used to
    /// reject `unmount` while busy.
    open_count: u32,
    /// 1-based mount-id this slot vends. Stable across the slot's
    /// lifetime so packed handles stay valid until `unmount`.
    mount_id: u8,
}

impl MountEntry {
    const fn empty() -> Self {
        MountEntry {
            used: false,
            mount_point: [0u8; FS_PATH_MAX],
            mount_len: 0,
            fs: None,
            open_count: 0,
            mount_id: 0,
        }
    }
}

/// Fixed-capacity VFS dispatcher with `N` mount slots.
///
/// `N` ≤ `255` (the mount id is packed into 8 bits of the handle).
/// `N` ≤ [`FS_MAX_MOUNTS`] is the locked default — operators can pick
/// a smaller `N` for tighter footprints.
///
/// Routing rule: `open` / `stat` pick the *longest* mount prefix that
/// covers the absolute path. Reads, writes, and closes route by the
/// mount id packed into the handle, bypassing path resolution
/// entirely.
pub struct VfsImpl<const N: usize> {
    mounts: [MountEntry; N],
    /// Monotonically rising next mount id. Wraps to 1 on overflow;
    /// the morph engine never expects more than `N` mounts so wrap
    /// is purely defensive.
    next_mount_id: u32,
}

impl<const N: usize> VfsImpl<N> {
    /// Construct an empty dispatcher.
    pub const fn new() -> Self {
        // We can't use `[MountEntry::empty(); N]` because MountEntry
        // is not `Copy` (it holds `Option<&'static mut dyn ...>`).
        // Use the const-fn helper via `core::array::from_fn`-less
        // workaround: a const block expression in a temporary.
        let mut arr: [MountEntry; N] = [const { MountEntry::empty() }; N];
        // Silence the unused-mut warning when N==0 by touching the slice.
        let _ = arr.as_mut_ptr();
        VfsImpl {
            mounts: arr,
            next_mount_id: 1,
        }
    }

    /// Current number of active mounts.
    pub fn mount_count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0usize;
        while i < N {
            if self.mounts[i].used {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Returns the mount-point bytes for slot `i`, or `None` if the
    /// slot is empty / out of range. Read-only inspection used by
    /// the unit tests.
    pub fn mount_at(&self, i: usize) -> Option<&[u8]> {
        if i >= N || !self.mounts[i].used {
            return None;
        }
        Some(&self.mounts[i].mount_point[..self.mounts[i].mount_len as usize])
    }

    fn find_longest_prefix(&self, norm: &[u8]) -> Option<usize> {
        let mut best: Option<usize> = None;
        let mut best_len = 0usize;
        let mut i = 0usize;
        while i < N {
            if self.mounts[i].used {
                let mp = &self.mounts[i].mount_point[..self.mounts[i].mount_len as usize];
                if path_has_prefix(norm, mp) && mp.len() >= best_len {
                    best = Some(i);
                    best_len = mp.len();
                }
            }
            i += 1;
        }
        best
    }

    fn mount_index_for_id(&self, mount_id: u8) -> Option<usize> {
        let mut i = 0usize;
        while i < N {
            if self.mounts[i].used && self.mounts[i].mount_id == mount_id {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

impl<const N: usize> Default for VfsImpl<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Vfs for VfsImpl<N> {
    fn mount(
        &mut self,
        mount_point: &[u8],
        fs: &'static mut dyn Filesystem,
    ) -> Result<(), FsError> {
        if N == 0 {
            return Err(FsError::NoSpace);
        }
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(mount_point, &mut norm)?;
        // Reject duplicates and find a free slot.
        let mut free_idx: Option<usize> = None;
        let mut i = 0usize;
        while i < N {
            if self.mounts[i].used {
                let mp = &self.mounts[i].mount_point[..self.mounts[i].mount_len as usize];
                if bytes_eq(mp, &norm[..n]) {
                    return Err(FsError::AlreadyExists);
                }
            } else if free_idx.is_none() {
                free_idx = Some(i);
            }
            i += 1;
        }
        let idx = free_idx.ok_or(FsError::NoSpace)?;
        let mut chosen_id: Option<u8> = None;
        let mut step = 0u32;
        while step < VFS_MAX_MOUNT_ID {
            let mut cand = self.next_mount_id.wrapping_add(step);
            if cand == 0 || cand > VFS_MAX_MOUNT_ID {
                cand = ((cand.saturating_sub(1)) % VFS_MAX_MOUNT_ID) + 1;
            }
            let cand_u8 = cand as u8;
            if self.mount_index_for_id(cand_u8).is_none() {
                chosen_id = Some(cand_u8);
                let mut next = (cand_u8 as u32) + 1;
                if next == 0 || next > VFS_MAX_MOUNT_ID {
                    next = 1;
                }
                self.next_mount_id = next;
                break;
            }
            step += 1;
        }
        let mount_id = chosen_id.ok_or(FsError::NoSpace)?;
        let slot = &mut self.mounts[idx];
        slot.used = true;
        let mut p = 0usize;
        while p < FS_PATH_MAX {
            slot.mount_point[p] = 0;
            p += 1;
        }
        let mut p = 0usize;
        while p < n {
            slot.mount_point[p] = norm[p];
            p += 1;
        }
        slot.mount_len = n as u16;
        slot.fs = Some(fs);
        slot.open_count = 0;
        slot.mount_id = mount_id;
        Ok(())
    }

    fn unmount(&mut self, mount_point: &[u8]) -> Result<(), FsError> {
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(mount_point, &mut norm)?;
        let mut i = 0usize;
        while i < N {
            if self.mounts[i].used {
                let mp = &self.mounts[i].mount_point[..self.mounts[i].mount_len as usize];
                if bytes_eq(mp, &norm[..n]) {
                    if self.mounts[i].open_count > 0 {
                        return Err(FsError::Busy);
                    }
                    // Drop the slot. Replacing via `mem::replace` is
                    // not available in const contexts, but normal
                    // assignment is fine here.
                    self.mounts[i].used = false;
                    self.mounts[i].mount_len = 0;
                    self.mounts[i].fs = None;
                    self.mounts[i].mount_id = 0;
                    return Ok(());
                }
            }
            i += 1;
        }
        Err(FsError::NotFound)
    }

    fn open(&mut self, path: &[u8], flags: u32) -> Result<FsHandle, FsError> {
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        let idx = self.find_longest_prefix(&norm[..n]).ok_or(FsError::NoMount)?;
        let mp_len = self.mounts[idx].mount_len as usize;
        let mp = {
            let mut tmp = [0u8; FS_PATH_MAX];
            let mut k = 0usize;
            while k < mp_len {
                tmp[k] = self.mounts[idx].mount_point[k];
                k += 1;
            }
            tmp
        };
        let residual = strip_mount_prefix(&norm[..n], &mp[..mp_len]);
        let mount_id = self.mounts[idx].mount_id;
        let fs = self.mounts[idx]
            .fs
            .as_deref_mut()
            .ok_or(FsError::NoMount)?;
        let per_fs = fs.open(residual, flags)?;
        if per_fs.raw() > VFS_PER_FS_MASK {
            // Backing fs minted a per-fs handle that doesn't fit in
            // 24 bits. Close it immediately and surface the failure;
            // the kernel must not vend a truncated handle.
            let _ = fs.close(per_fs);
            return Err(FsError::BadHandle);
        }
        self.mounts[idx].open_count = self.mounts[idx].open_count.wrapping_add(1);
        Ok(pack_handle(mount_id, per_fs.raw()))
    }

    fn read(&mut self, handle: FsHandle, offset: u64, buf: &mut [u8]) -> Result<usize, FsError> {
        let (mount_id, per_fs_raw) = unpack_handle(handle);
        if mount_id == 0 {
            return Err(FsError::BadHandle);
        }
        let idx = self.mount_index_for_id(mount_id).ok_or(FsError::BadHandle)?;
        let fs = self.mounts[idx]
            .fs
            .as_deref_mut()
            .ok_or(FsError::BadHandle)?;
        fs.read(FsHandle::from_raw(per_fs_raw), offset, buf)
    }

    fn write(&mut self, handle: FsHandle, offset: u64, buf: &[u8]) -> Result<usize, FsError> {
        let (mount_id, per_fs_raw) = unpack_handle(handle);
        if mount_id == 0 {
            return Err(FsError::BadHandle);
        }
        let idx = self.mount_index_for_id(mount_id).ok_or(FsError::BadHandle)?;
        let fs = self.mounts[idx]
            .fs
            .as_deref_mut()
            .ok_or(FsError::BadHandle)?;
        fs.write(FsHandle::from_raw(per_fs_raw), offset, buf)
    }

    fn close(&mut self, handle: FsHandle) -> Result<(), FsError> {
        let (mount_id, per_fs_raw) = unpack_handle(handle);
        if mount_id == 0 {
            return Err(FsError::BadHandle);
        }
        let idx = self.mount_index_for_id(mount_id).ok_or(FsError::BadHandle)?;
        let result = {
            let fs = self.mounts[idx]
                .fs
                .as_deref_mut()
                .ok_or(FsError::BadHandle)?;
            fs.close(FsHandle::from_raw(per_fs_raw))
        };
        if result.is_ok() {
            self.mounts[idx].open_count = self.mounts[idx].open_count.saturating_sub(1);
        }
        result
    }

    fn stat(&self, path: &[u8]) -> Result<FileStat, FsError> {
        let mut norm = [0u8; FS_PATH_MAX];
        let n = normalise_path(path, &mut norm)?;
        let idx = self.find_longest_prefix(&norm[..n]).ok_or(FsError::NoMount)?;
        let mp_len = self.mounts[idx].mount_len as usize;
        let mp = &self.mounts[idx].mount_point[..mp_len];
        let residual = strip_mount_prefix(&norm[..n], mp);
        let fs = self.mounts[idx]
            .fs
            .as_deref()
            .ok_or(FsError::NoMount)?;
        fs.stat(residual)
    }
}

/// Compile-time assertion that the locked handle packing fits the
/// surface contract (mount-id bits = 8, per-fs bits = 24, sum = 32).
const _: () = {
    if VFS_MOUNT_ID_BITS + 24 != 32 {
        panic!("VFS handle packing must total 32 bits");
    }
    if (VFS_PER_FS_MASK as u64) != ((1u64 << 24) - 1) {
        panic!("VFS per-fs mask must cover 24 bits");
    }
    if VFS_MAX_MOUNT_ID != 255 {
        panic!("VFS max mount id must be 255 with 8-bit packing");
    }
    if FS_MAX_MOUNTS > 255 {
        panic!("FS_MAX_MOUNTS exceeds VFS handle packing");
    }
};

// ============================================================
// Unit tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::{FS_MODE_DIR as MODE_DIR, FS_MODE_FILE as MODE_FILE, FS_MODE_TYPE_MASK};

    // --- path validation + normalisation -------------------------

    #[test]
    fn validate_rejects_empty_path() {
        assert_eq!(validate_path(b""), Err(FsError::BadPath));
    }

    #[test]
    fn validate_rejects_relative_path() {
        assert_eq!(validate_path(b"etc/hostname"), Err(FsError::BadPath));
    }

    #[test]
    fn validate_rejects_embedded_nul() {
        assert_eq!(validate_path(b"/etc/host\0name"), Err(FsError::BadPath));
    }

    #[test]
    fn validate_rejects_oversized_component() {
        let mut p = [b'/'; FS_NAME_MAX + 4];
        p[0] = b'/';
        let mut i = 1usize;
        while i < FS_NAME_MAX + 4 {
            p[i] = b'a';
            i += 1;
        }
        assert_eq!(validate_path(&p), Err(FsError::NameTooLong));
    }

    #[test]
    fn validate_rejects_oversized_path() {
        let big = [b'/'; FS_PATH_MAX + 1];
        assert_eq!(validate_path(&big), Err(FsError::NameTooLong));
    }

    #[test]
    fn normalise_collapses_repeated_slashes() {
        let mut out = [0u8; FS_PATH_MAX];
        let n = normalise_path(b"//etc//hostname///", &mut out).unwrap();
        assert_eq!(&out[..n], b"/etc/hostname");
    }

    #[test]
    fn normalise_resolves_dot_components() {
        let mut out = [0u8; FS_PATH_MAX];
        let n = normalise_path(b"/etc/./hostname", &mut out).unwrap();
        assert_eq!(&out[..n], b"/etc/hostname");
    }

    #[test]
    fn normalise_resolves_dotdot_components() {
        let mut out = [0u8; FS_PATH_MAX];
        let n = normalise_path(b"/var/log/../tmp", &mut out).unwrap();
        assert_eq!(&out[..n], b"/var/tmp");
    }

    #[test]
    fn normalise_root_returns_root() {
        let mut out = [0u8; FS_PATH_MAX];
        let n = normalise_path(b"/", &mut out).unwrap();
        assert_eq!(&out[..n], b"/");
    }

    #[test]
    fn normalise_root_with_dot_components_returns_root() {
        let mut out = [0u8; FS_PATH_MAX];
        let n = normalise_path(b"/.//./", &mut out).unwrap();
        assert_eq!(&out[..n], b"/");
    }

    #[test]
    fn normalise_rejects_escape_above_root() {
        let mut out = [0u8; FS_PATH_MAX];
        assert_eq!(normalise_path(b"/..", &mut out), Err(FsError::BadPath));
    }

    #[test]
    fn path_has_prefix_root_matches_everything() {
        assert!(path_has_prefix(b"/etc/hostname", b"/"));
        assert!(path_has_prefix(b"/", b"/"));
    }

    #[test]
    fn path_has_prefix_respects_component_boundary() {
        assert!(path_has_prefix(b"/boot/grub.cfg", b"/boot"));
        assert!(!path_has_prefix(b"/booting", b"/boot"));
    }

    #[test]
    fn strip_mount_prefix_handles_root_mount() {
        assert_eq!(strip_mount_prefix(b"/etc/hostname", b"/"), b"/etc/hostname");
    }

    #[test]
    fn strip_mount_prefix_strips_nested_mount() {
        assert_eq!(strip_mount_prefix(b"/boot/grub.cfg", b"/boot"), b"/grub.cfg");
    }

    #[test]
    fn strip_mount_prefix_at_mount_root_returns_slash() {
        assert_eq!(strip_mount_prefix(b"/boot", b"/boot"), b"/");
    }

    // --- handle packing ------------------------------------------

    #[test]
    fn pack_unpack_roundtrip() {
        let h = pack_handle(7, 0x00DEAD);
        let (m, p) = unpack_handle(h);
        assert_eq!(m, 7);
        assert_eq!(p, 0x00DEAD);
    }

    #[test]
    fn pack_truncates_overflow_per_fs() {
        // High bit set in the per-fs value gets masked out — this
        // is defensive only, the dispatcher refuses to vend such
        // handles in `open`.
        let h = pack_handle(1, 0xFF_FF_FF_FF);
        let (m, p) = unpack_handle(h);
        assert_eq!(m, 1);
        assert_eq!(p, VFS_PER_FS_MASK);
    }

    // --- MemRamFs ------------------------------------------------

    #[test]
    fn memramfs_seed_then_open_then_read() {
        let mut fs = MemRamFs::<4, 256>::new();
        let _ = fs.seed_file(b"/etc/hostname", b"cuttle-te\n", 32, 0).unwrap();
        let h = fs.open(b"/etc/hostname", FS_O_RDONLY).unwrap();
        let mut buf = [0u8; 32];
        let n = fs.read(h, 0, &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], b"cuttle-te\n");
        fs.close(h).unwrap();
    }

    #[test]
    fn memramfs_open_nonexistent_returns_notfound() {
        let mut fs = MemRamFs::<4, 256>::new();
        assert_eq!(
            fs.open(b"/nope", FS_O_RDONLY),
            Err(FsError::NotFound)
        );
    }

    #[test]
    fn memramfs_create_then_write_then_read() {
        let mut fs = MemRamFs::<4, 512>::new();
        let h = fs.open(b"/tmp/scratch", FS_O_RDWR | FS_O_CREATE).unwrap();
        let n = fs.write(h, 0, b"hello").unwrap();
        assert_eq!(n, 5);
        let mut buf = [0u8; 16];
        let r = fs.read(h, 0, &mut buf).unwrap();
        assert_eq!(r, 5);
        assert_eq!(&buf[..r], b"hello");
        fs.close(h).unwrap();
    }

    #[test]
    fn memramfs_open_excl_on_existing_fails() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/etc/hostname", b"x", 32, 0).unwrap();
        assert_eq!(
            fs.open(b"/etc/hostname", FS_O_RDWR | FS_O_CREATE | FS_O_EXCL),
            Err(FsError::AlreadyExists)
        );
    }

    #[test]
    fn memramfs_truncate_on_open_zeroes_length() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/a", b"hello", 32, 0).unwrap();
        let h = fs.open(b"/a", FS_O_RDWR | FS_O_TRUNC).unwrap();
        let mut buf = [0u8; 16];
        assert_eq!(fs.read(h, 0, &mut buf).unwrap(), 0);
        fs.close(h).unwrap();
    }

    #[test]
    fn memramfs_read_only_blocks_writes() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/etc/hostname", b"x", 32, 0).unwrap();
        fs.set_read_only(true);
        assert_eq!(
            fs.open(b"/etc/hostname", FS_O_RDWR),
            Err(FsError::ReadOnly)
        );
    }

    #[test]
    fn memramfs_read_handle_rejects_writeonly_open() {
        let mut fs = MemRamFs::<4, 256>::new();
        let h = fs.open(b"/x", FS_O_WRONLY | FS_O_CREATE).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(fs.read(h, 0, &mut buf), Err(FsError::BadHandle));
    }

    #[test]
    fn memramfs_write_handle_rejects_readonly_open() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/a", b"x", 8, 0).unwrap();
        let h = fs.open(b"/a", FS_O_RDONLY).unwrap();
        assert_eq!(fs.write(h, 0, b"y"), Err(FsError::BadHandle));
    }

    #[test]
    fn memramfs_write_past_capacity_returns_nospace() {
        let mut fs = MemRamFs::<4, 16>::new();
        let h = fs.open(b"/big", FS_O_RDWR | FS_O_CREATE).unwrap();
        // The default new-file capacity is 256, but the pool is 16
        // bytes so allocate-on-create itself fails. Use a tighter
        // seed instead.
        assert!(matches!(h.raw(), 1..));
        let r = fs.write(h, 0, &[0u8; 1024]);
        assert_eq!(r, Err(FsError::NoSpace));
        fs.close(h).unwrap();
    }

    #[test]
    fn memramfs_too_many_open_handles() {
        let mut fs = MemRamFs::<2, 256>::new();
        fs.seed_file(b"/a", b"x", 8, 0).unwrap();
        let h1 = fs.open(b"/a", FS_O_RDONLY).unwrap();
        let h2 = fs.open(b"/a", FS_O_RDONLY).unwrap();
        // The fs has I = 2 open slots; both are now taken.
        assert_eq!(fs.open(b"/a", FS_O_RDONLY), Err(FsError::TooManyHandles));
        fs.close(h1).unwrap();
        fs.close(h2).unwrap();
    }

    #[test]
    fn memramfs_close_twice_returns_badhandle() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/a", b"x", 8, 0).unwrap();
        let h = fs.open(b"/a", FS_O_RDONLY).unwrap();
        fs.close(h).unwrap();
        assert_eq!(fs.close(h), Err(FsError::BadHandle));
    }

    #[test]
    fn memramfs_stat_root_is_directory() {
        let fs = MemRamFs::<4, 256>::new();
        let st = fs.stat(b"/").unwrap();
        assert!(st.is_dir());
        assert_eq!(st.mode & FS_MODE_TYPE_MASK, MODE_DIR);
    }

    #[test]
    fn memramfs_stat_file_returns_size() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/etc/hostname", b"cuttle-te\n", 32, 1700000000).unwrap();
        let st = fs.stat(b"/etc/hostname").unwrap();
        assert_eq!(st.size, 10);
        assert_eq!(st.mtime, 1700000000);
        assert!(st.is_file());
        assert_eq!(st.mode & FS_MODE_TYPE_MASK, MODE_FILE);
    }

    #[test]
    fn memramfs_read_at_offset_past_eof_returns_zero() {
        let mut fs = MemRamFs::<4, 256>::new();
        fs.seed_file(b"/a", b"hello", 32, 0).unwrap();
        let h = fs.open(b"/a", FS_O_RDONLY).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(fs.read(h, 99, &mut buf).unwrap(), 0);
        fs.close(h).unwrap();
    }

    #[test]
    fn memramfs_write_at_offset_extends_with_sparse_zero_fill() {
        let mut fs = MemRamFs::<4, 256>::new();
        let h = fs.open(b"/a", FS_O_RDWR | FS_O_CREATE).unwrap();
        // Default capacity is 256, so writing at offset 8 is in range.
        let n = fs.write(h, 8, b"X").unwrap();
        assert_eq!(n, 1);
        let mut buf = [0u8; 16];
        let r = fs.read(h, 0, &mut buf).unwrap();
        assert_eq!(r, 9);
        assert_eq!(&buf[..8], &[0u8; 8]);
        assert_eq!(buf[8], b'X');
        fs.close(h).unwrap();
    }

    // --- VfsImpl -------------------------------------------------

    fn make_static_ramfs() -> &'static mut MemRamFs<4, 256> {
        // Box::leak gives us the 'static lifetime the Vfs trait
        // requires. This is host-tests-only — the no_std kernel
        // banner instantiates ramfs in a `static mut`.
        let fs: Box<MemRamFs<4, 256>> = Box::new(MemRamFs::new());
        Box::leak(fs)
    }

    extern crate alloc;
    use alloc::boxed::Box;

    #[test]
    fn vfsimpl_mount_then_unmount_cycle() {
        let mut vfs = VfsImpl::<4>::new();
        let fs = make_static_ramfs();
        assert_eq!(vfs.mount_count(), 0);
        vfs.mount(b"/", fs as &mut dyn Filesystem).unwrap();
        assert_eq!(vfs.mount_count(), 1);
        assert_eq!(vfs.mount_at(0), Some(b"/".as_ref()));
        vfs.unmount(b"/").unwrap();
        assert_eq!(vfs.mount_count(), 0);
    }

    #[test]
    fn vfsimpl_mount_duplicate_rejected() {
        let mut vfs = VfsImpl::<4>::new();
        let fs1 = make_static_ramfs();
        let fs2 = make_static_ramfs();
        vfs.mount(b"/", fs1 as &mut dyn Filesystem).unwrap();
        assert_eq!(
            vfs.mount(b"/", fs2 as &mut dyn Filesystem),
            Err(FsError::AlreadyExists)
        );
    }

    #[test]
    fn vfsimpl_open_read_close_on_root_mount() {
        let mut vfs = VfsImpl::<2>::new();
        let fs = make_static_ramfs();
        fs.seed_file(b"/etc/hostname", b"cuttle-te\n", 32, 0).unwrap();
        vfs.mount(b"/", fs as &mut dyn Filesystem).unwrap();
        let h = vfs.open(b"/etc/hostname", FS_O_RDONLY).unwrap();
        let mut buf = [0u8; 32];
        let n = vfs.read(h, 0, &mut buf).unwrap();
        assert_eq!(n, 10);
        assert_eq!(&buf[..n], b"cuttle-te\n");
        vfs.close(h).unwrap();
    }

    #[test]
    fn vfsimpl_unmount_while_busy_returns_busy() {
        let mut vfs = VfsImpl::<2>::new();
        let fs = make_static_ramfs();
        fs.seed_file(b"/a", b"x", 8, 0).unwrap();
        vfs.mount(b"/", fs as &mut dyn Filesystem).unwrap();
        let h = vfs.open(b"/a", FS_O_RDONLY).unwrap();
        assert_eq!(vfs.unmount(b"/"), Err(FsError::Busy));
        vfs.close(h).unwrap();
        vfs.unmount(b"/").unwrap();
    }

    #[test]
    fn vfsimpl_longest_prefix_routes_to_nested_mount() {
        let mut vfs = VfsImpl::<4>::new();
        let root_fs = make_static_ramfs();
        let boot_fs = make_static_ramfs();
        root_fs.seed_file(b"/etc/hostname", b"R\n", 8, 0).unwrap();
        boot_fs.seed_file(b"/grub.cfg", b"B\n", 8, 0).unwrap();
        vfs.mount(b"/", root_fs as &mut dyn Filesystem).unwrap();
        vfs.mount(b"/boot", boot_fs as &mut dyn Filesystem).unwrap();
        // /etc/hostname routes to root mount.
        let h1 = vfs.open(b"/etc/hostname", FS_O_RDONLY).unwrap();
        let mut buf = [0u8; 4];
        let n1 = vfs.read(h1, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n1], b"R\n");
        vfs.close(h1).unwrap();
        // /boot/grub.cfg routes to /boot mount and the residual is
        // /grub.cfg.
        let h2 = vfs.open(b"/boot/grub.cfg", FS_O_RDONLY).unwrap();
        let mut buf2 = [0u8; 4];
        let n2 = vfs.read(h2, 0, &mut buf2).unwrap();
        assert_eq!(&buf2[..n2], b"B\n");
        vfs.close(h2).unwrap();
    }

    #[test]
    fn vfsimpl_open_with_no_mount_returns_no_mount() {
        let mut vfs = VfsImpl::<2>::new();
        assert_eq!(vfs.open(b"/etc/hostname", FS_O_RDONLY), Err(FsError::NoMount));
    }

    #[test]
    fn vfsimpl_handles_carry_mount_id() {
        let mut vfs = VfsImpl::<4>::new();
        let fs_a = make_static_ramfs();
        let fs_b = make_static_ramfs();
        fs_a.seed_file(b"/x", b"A", 8, 0).unwrap();
        fs_b.seed_file(b"/y", b"B", 8, 0).unwrap();
        vfs.mount(b"/", fs_a as &mut dyn Filesystem).unwrap();
        vfs.mount(b"/sub", fs_b as &mut dyn Filesystem).unwrap();
        let h1 = vfs.open(b"/x", FS_O_RDONLY).unwrap();
        let h2 = vfs.open(b"/sub/y", FS_O_RDONLY).unwrap();
        let (m1, _) = unpack_handle(h1);
        let (m2, _) = unpack_handle(h2);
        assert!(m1 != m2, "distinct mounts must vend distinct mount ids");
        let mut buf = [0u8; 4];
        let n1 = vfs.read(h1, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n1], b"A");
        let n2 = vfs.read(h2, 0, &mut buf).unwrap();
        assert_eq!(&buf[..n2], b"B");
        vfs.close(h1).unwrap();
        vfs.close(h2).unwrap();
    }

    #[test]
    fn vfsimpl_stat_routes_by_longest_prefix() {
        let mut vfs = VfsImpl::<4>::new();
        let root_fs = make_static_ramfs();
        let boot_fs = make_static_ramfs();
        boot_fs.seed_file(b"/grub.cfg", b"XYZ", 8, 1700000001).unwrap();
        vfs.mount(b"/", root_fs as &mut dyn Filesystem).unwrap();
        vfs.mount(b"/boot", boot_fs as &mut dyn Filesystem).unwrap();
        let st = vfs.stat(b"/boot/grub.cfg").unwrap();
        assert_eq!(st.size, 3);
        assert_eq!(st.mtime, 1700000001);
    }

    #[test]
    fn vfsimpl_read_with_forged_handle_returns_badhandle() {
        let mut vfs = VfsImpl::<2>::new();
        let fs = make_static_ramfs();
        vfs.mount(b"/", fs as &mut dyn Filesystem).unwrap();
        let mut buf = [0u8; 4];
        assert_eq!(
            vfs.read(FsHandle::from_raw(0xFFFF_FFFF), 0, &mut buf),
            Err(FsError::BadHandle)
        );
    }

    #[test]
    fn vfsimpl_mount_table_full_returns_nospace() {
        let mut vfs = VfsImpl::<1>::new();
        let fs_a = make_static_ramfs();
        let fs_b = make_static_ramfs();
        vfs.mount(b"/", fs_a as &mut dyn Filesystem).unwrap();
        assert_eq!(
            vfs.mount(b"/data", fs_b as &mut dyn Filesystem),
            Err(FsError::NoSpace)
        );
    }

    /// `can_replace` must predict exactly what a truncating open followed
    /// by one write does, for existing and new files around the pool limit.
    #[test]
    fn can_replace_predicts_truncating_overwrite_exactly() {
        fn build() -> MemRamFs<4, 512> {
            let mut fs = MemRamFs::<4, 512>::new();
            fs.seed_file(b"/small", b"0123456789", 16, 1).unwrap();
            fs.seed_file(b"/large", &[7u8; 300], 300, 2).unwrap();
            fs.seed_file(b"/other", b"keep", 100, 3).unwrap();
            fs
        }
        let free = 512 - build().pool_used() as usize;
        assert_eq!(free, 96);
        let data = [0x5Au8; 600];
        for (path, len) in [
            (&b"/small"[..], 0usize),
            (b"/small", 16),
            (b"/small", 16 + free),
            (b"/small", 16 + free + 1),
            (b"/large", 300 + free),
            (b"/large", 300 + free + 1),
            (b"/new", 1),
            (b"/new", free),
            (b"/new", free + 1),
        ] {
            let predicted = build().can_replace(path, len);
            let mut fs = build();
            let actual = match fs.open(path, FS_O_RDWR | FS_O_CREATE | FS_O_TRUNC) {
                Ok(h) => fs.write(h, 0, &data[..len]) == Ok(len),
                Err(_) => false,
            };
            assert_eq!(
                predicted,
                actual,
                "can_replace({:?}, {len}) disagrees with open+write",
                core::str::from_utf8(path)
            );
        }
        let fs = build();
        assert!(!fs.can_replace(b"/", 1));
        assert!(!fs.can_replace(b"relative", 1));
        // No free inode for a fourth file once the table is full.
        let mut full = build();
        full.seed_file(b"/fourth", b"x", 1, 4).unwrap();
        assert!(!full.can_replace(b"/fifth", 1));
        assert!(full.can_replace(b"/fourth", 2));
        // Read-only filesystems accept nothing.
        let mut ro = build();
        ro.set_read_only(true);
        assert!(!ro.can_replace(b"/small", 1));
    }

    #[test]
    fn growing_and_unlinking_middle_file_shifts_and_compacts_neighbors_intact() {
        let mut fs = MemRamFs::<8, 512>::new();
        fs.seed_file(b"/a", b"ALPHA-HEAD", 16, 10).unwrap();
        fs.seed_file(b"/b", b"MID", 8, 20).unwrap();
        fs.seed_file(b"/c", b"OMEGA-TAIL-99", 16, 30).unwrap();
        assert_eq!(fs.pool_used, 40);

        // 1. Grow the middle file `/b` past its 8-byte capacity twice (`8 -> 24 -> 64`)
        // and verify `/a` before it and `/c` after it remain byte-for-byte intact.
        let hb = fs.open(b"/b", FS_O_RDWR).unwrap();
        let grown1 = b"MIDDLE-EXPANDED-24-BYTES";
        assert_eq!(fs.write(hb, 0, grown1).unwrap(), 24);
        assert_eq!(fs.pool_used, 40 + 16);
        let grown2 = [b'M'; 64];
        assert_eq!(fs.write(hb, 0, &grown2).unwrap(), 64);
        fs.close(hb).unwrap();
        assert_eq!(fs.pool_used, 40 + 56);

        let mut buf = [0u8; 128];
        let ha = fs.open(b"/a", FS_O_RDONLY).unwrap();
        let na = fs.read(ha, 0, &mut buf).unwrap();
        assert_eq!(&buf[..na], b"ALPHA-HEAD");
        fs.close(ha).unwrap();

        let hb2 = fs.open(b"/b", FS_O_RDONLY).unwrap();
        let nb = fs.read(hb2, 0, &mut buf).unwrap();
        assert_eq!(&buf[..nb], &grown2[..]);
        fs.close(hb2).unwrap();

        let hc = fs.open(b"/c", FS_O_RDONLY).unwrap();
        let nc = fs.read(hc, 0, &mut buf).unwrap();
        assert_eq!(&buf[..nc], b"OMEGA-TAIL-99");
        fs.close(hc).unwrap();

        // 2. Unlink `/b` in the middle and verify `/c` shifts down to compact `pool_used`
        // without corrupting `/a` or `/c`, and that a new file `/d` can claim the freed pool space.
        fs.unlink(b"/b").unwrap();
        assert_eq!(fs.pool_used, 32);
        assert_eq!(fs.stat(b"/b"), Err(FsError::NotFound));

        let ha = fs.open(b"/a", FS_O_RDONLY).unwrap();
        let na = fs.read(ha, 0, &mut buf).unwrap();
        assert_eq!(&buf[..na], b"ALPHA-HEAD");
        fs.close(ha).unwrap();

        let hc = fs.open(b"/c", FS_O_RDONLY).unwrap();
        let nc = fs.read(hc, 0, &mut buf).unwrap();
        assert_eq!(&buf[..nc], b"OMEGA-TAIL-99");
        fs.close(hc).unwrap();

        let hd = fs.open(b"/d", FS_O_CREATE | FS_O_RDWR).unwrap();
        let payload_d = [b'D'; 460];
        assert_eq!(fs.write(hd, 0, &payload_d).unwrap(), 460);
        fs.close(hd).unwrap();
        assert_eq!(fs.pool_used, 32 + 460);
    }

    #[test]
    fn open_trunc_reclaims_pool_capacity_across_repeated_overwrites() {
        let mut fs: MemRamFs<8, 1024> = MemRamFs::new();
        let h1 = fs.open(b"/log", FS_O_CREATE | FS_O_RDWR).unwrap();
        assert_eq!(fs.write(h1, 0, &[b'X'; 700]).unwrap(), 700);
        fs.close(h1).unwrap();

        let h2 = fs.open(b"/peer", FS_O_CREATE | FS_O_RDWR).unwrap();
        assert_eq!(fs.write(h2, 0, b"ANCHOR-TAIL").unwrap(), 11);
        fs.close(h2).unwrap();
        assert_eq!(fs.pool_used, 700 + 256);

        // Truncating `/log` must reclaim its excess capacity above 256 bytes and compact `/peer`
        // so subsequent files can allocate from the reclaimed 444 bytes without `NoSpace`.
        let h_trunc = fs.open(b"/log", FS_O_RDWR | FS_O_TRUNC).unwrap();
        assert_eq!(fs.write(h_trunc, 0, b"tiny").unwrap(), 4);
        fs.close(h_trunc).unwrap();
        assert_eq!(
            fs.pool_used,
            256 + 256,
            "FS_O_TRUNC must compact and reclaim excess capacity from pool_used"
        );

        let h_big = fs.open(b"/fresh", FS_O_CREATE | FS_O_RDWR).unwrap();
        assert_eq!(fs.write(h_big, 0, &[b'Z'; 500]).unwrap(), 500);
        fs.close(h_big).unwrap();

        let mut check = [0u8; 32];
        let hp = fs.open(b"/peer", FS_O_RDONLY).unwrap();
        let np = fs.read(hp, 0, &mut check).unwrap();
        assert_eq!(&check[..np], b"ANCHOR-TAIL");
        fs.close(hp).unwrap();
    }

    #[test]
    fn ramfs_rejects_rdonly_trunc_preserves_state_on_handle_exhaustion_and_avoids_mount_id_collision() {
        // 1. `FS_O_RDONLY | FS_O_TRUNC` must be rejected with `ReadOnly` without truncating existing file data!
        let mut fs: MemRamFs<2, 512> = MemRamFs::new();
        fs.seed_file(b"/keep", b"IMPORTANT", 32, 0).unwrap();
        assert_eq!(
            fs.open(b"/keep", FS_O_RDONLY | FS_O_TRUNC),
            Err(FsError::ReadOnly)
        );
        assert_eq!(fs.stat(b"/keep").unwrap().size, 9);

        // 2. When all open-handle slots (I = 2) are full, `open(..., FS_O_TRUNC)` and `open(..., FS_O_CREATE)`
        //    must fail with `TooManyHandles` BEFORE truncating `/keep` or leaking `/ghost` into `inodes`/`pool_used`!
        let h1 = fs.open(b"/keep", FS_O_RDONLY).unwrap();
        let h2 = fs.open(b"/keep", FS_O_RDONLY).unwrap();
        let used_before = fs.pool_used;
        let inodes_before = fs.inode_count();
        assert_eq!(
            fs.open(b"/keep", FS_O_RDWR | FS_O_TRUNC),
            Err(FsError::TooManyHandles)
        );
        assert_eq!(
            fs.open(b"/ghost", FS_O_RDWR | FS_O_CREATE),
            Err(FsError::TooManyHandles)
        );
        fs.close(h1).unwrap();
        fs.close(h2).unwrap();
        assert_eq!(fs.stat(b"/keep").unwrap().size, 9, "failed open(O_TRUNC) must not destroy file data");
        assert_eq!(fs.stat(b"/ghost"), Err(FsError::NotFound), "failed open(O_CREATE) must not leak an inode");
        assert_eq!(fs.inode_count(), inodes_before);
        assert_eq!(fs.pool_used, used_before);

        // 3. Mounting `/` (`mount_id = 1`), cycling 255 mounts on `/tmp` so `next_mount_id` wraps around to `1`,
        //    and then mounting `/boot` must NOT assign a colliding `mount_id = 1`!
        let mut vfs = VfsImpl::<4>::new();
        let root_fs = make_static_ramfs();
        root_fs.seed_file(b"/f", b"ROOT", 16, 0).unwrap();
        vfs.mount(b"/", root_fs as &mut dyn Filesystem).unwrap();
        for _ in 0..254 {
            let tmp_fs = make_static_ramfs();
            vfs.mount(b"/tmp", tmp_fs as &mut dyn Filesystem).unwrap();
            vfs.unmount(b"/tmp").unwrap();
        }
        let boot_fs = make_static_ramfs();
        boot_fs.seed_file(b"/f", b"BOOT", 16, 0).unwrap();
        vfs.mount(b"/boot", boot_fs as &mut dyn Filesystem).unwrap();

        let hb = vfs.open(b"/boot/f", FS_O_RDONLY).unwrap();
        let mut rbuf = [0u8; 8];
        let nb = vfs.read(hb, 0, &mut rbuf).unwrap();
        assert_eq!(&rbuf[..nb], b"BOOT", "wrapped mount_id must not alias active root mount");
        vfs.close(hb).unwrap();
    }

    #[test]
    fn ramfs_paged_mode_scales_to_96_inodes_256kib_pool_32kib_files_and_dirty_mask() {
        let mut fs: MemRamFs<24, 10240> = MemRamFs::new();
        assert!(!fs.is_paged_mode());
        assert_eq!(fs.max_inodes(), 24);
        assert_eq!(fs.pool_capacity(), 10240);

        fs.seed_file(b"/etc/hostname", b"cuttle\n", 64, 1).unwrap();
        fs.set_paged_mode(true);
        assert!(fs.is_paged_mode());
        assert_eq!(fs.max_inodes(), PAGED_VFS_MAX_INODES);
        assert_eq!(fs.pool_capacity(), PAGED_VFS_MAX_POOL);
        assert_eq!(fs.inode_data(0).unwrap().1, b"cuttle\n");
        fs.clear_paged_dirty();
        assert!(!fs.is_dir_dirty());
        assert!(!fs.is_inode_dirty(0));

        // Create a 32 KiB file (`PAGED_VFS_MAX_FILE_BYTES`) and verify >32 KiB is rejected cleanly.
        let h_big = fs.open(b"/data/blob.bin", FS_O_CREATE | FS_O_RDWR).unwrap();
        let pattern: alloc::vec::Vec<u8> = (0..PAGED_VFS_MAX_FILE_BYTES)
            .map(|i| ((i * 31 + 7) & 0xFF) as u8)
            .collect();
        assert_eq!(
            fs.write(h_big, 0, &pattern).unwrap(),
            PAGED_VFS_MAX_FILE_BYTES
        );
        assert_eq!(
            fs.write(h_big, PAGED_VFS_MAX_FILE_BYTES as u64, b"x"),
            Err(FsError::NoSpace),
            "writes beyond PAGED_VFS_MAX_FILE_BYTES (32 KiB) must fail closed with NoSpace"
        );
        assert!(!fs.can_replace(b"/data/blob.bin", PAGED_VFS_MAX_FILE_BYTES + 1));
        fs.close(h_big).unwrap();
        assert!(fs.is_dir_dirty());
        assert!(fs.is_inode_dirty(1));

        let mut verify = alloc::vec![0u8; PAGED_VFS_MAX_FILE_BYTES];
        let hr = fs.open(b"/data/blob.bin", FS_O_RDONLY).unwrap();
        assert_eq!(fs.read(hr, 0, &mut verify).unwrap(), PAGED_VFS_MAX_FILE_BYTES);
        assert_eq!(verify, pattern);
        fs.close(hr).unwrap();

        fs.clear_paged_dirty();

        // Fill all remaining 94 inodes (total = 96) and verify 97th fails with NoSpace.
        for idx in 2..PAGED_VFS_MAX_INODES {
            let path = alloc::format!("/var/f_{idx:02}.txt");
            let payload = alloc::format!("record-{idx:02}\n");
            let h = fs.open(path.as_bytes(), FS_O_CREATE | FS_O_RDWR).unwrap();
            assert_eq!(fs.write(h, 0, payload.as_bytes()).unwrap(), payload.len());
            fs.close(h).unwrap();
            assert!(fs.is_inode_dirty(idx));
        }
        assert_eq!(fs.inode_count(), PAGED_VFS_MAX_INODES);
        assert_eq!(
            fs.open(b"/var/overflow_97.txt", FS_O_CREATE | FS_O_RDWR),
            Err(FsError::NoSpace)
        );

        // Unlinking reclaims pool bytes and marks only that inode + dir dirty.
        fs.clear_paged_dirty();
        let used_before_rm = fs.pool_used();
        fs.unlink(b"/data/blob.bin").unwrap();
        assert_eq!(
            fs.pool_used(),
            used_before_rm - PAGED_VFS_MAX_FILE_BYTES as u32
        );
        assert!(fs.is_dir_dirty());
        assert!(fs.is_inode_dirty(1));
        assert!(!fs.is_inode_dirty(2));
    }

    #[test]
    fn set_paged_mode_false_repacks_inline_files_and_paged_path_cap_enforced() {
        let mut fs: MemRamFs<24, 10240> = MemRamFs::new();
        fs.seed_file(b"/etc/hostname", b"cuttle-te\n", 64, 1).unwrap();
        fs.seed_file(b"/var/note", b"important\n", 64, 7).unwrap();

        fs.set_paged_mode(true);
        // Paged mode must reject paths > 200 bytes so `MemRamFs` and `sync_vfs_to_paged_store` agree.
        let path_220 = b"/a".repeat(110);
        assert_eq!(
            fs.open(&path_220, FS_O_CREATE | FS_O_RDWR),
            Err(FsError::NameTooLong)
        );

        // Toggling back to inline mode must losslessly repack files back into `pool`.
        fs.set_paged_mode(false);
        assert!(!fs.is_paged_mode());
        let mut buf = [0u8; 32];
        let h1 = fs.open(b"/etc/hostname", FS_O_RDONLY).unwrap();
        let n1 = fs.read(h1, 0, &mut buf).unwrap();
        fs.close(h1).unwrap();
        assert_eq!(&buf[..n1], b"cuttle-te\n");

        // Writing a new file in inline mode must not alias or overwrite `/etc/hostname`.
        let h_new = fs.open(b"/var/second", FS_O_CREATE | FS_O_RDWR).unwrap();
        assert_eq!(fs.write(h_new, 0, b"abc").unwrap(), 3);
        fs.close(h_new).unwrap();

        let h1_re = fs.open(b"/etc/hostname", FS_O_RDONLY).unwrap();
        let n1_re = fs.read(h1_re, 0, &mut buf).unwrap();
        fs.close(h1_re).unwrap();
        assert_eq!(&buf[..n1_re], b"cuttle-te\n");

        let h2 = fs.open(b"/var/note", FS_O_RDONLY).unwrap();
        let n2 = fs.read(h2, 0, &mut buf).unwrap();
        fs.close(h2).unwrap();
        assert_eq!(&buf[..n2], b"important\n");
    }
}
