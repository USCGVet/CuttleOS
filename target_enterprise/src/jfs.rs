//! Journaled-FS (JFS2) on-disk image walker — TASK-064.
//!
//! Read-only wire codec for a minimal JFS2 image: superblock parser,
//! inode-table loader, fixed-size directory-entry walker, and direct-
//! extent file reader. No allocator, no WAL, no free-bitmap mutation
//! — those live in the full donor runtime (`RustOSa/src/jfs.rs`).
//! This port is the **walker** the kernel needs to prove a fixture
//! image round-trips: mount → lookup `/hello.txt` → read body.
//!
//! # On-disk layout (fixture-friendly)
//!
//! ```text
//!   LBA 0          superblock (first 32 bytes of the sector)
//!   LBA inode_tbl  inode table (16 × 32-byte inodes per sector)
//!   LBA data...    file / directory body sectors (direct extents)
//! ```
//!
//! # Inode (32 bytes)
//!
//! ```text
//!   0..4    magic "JINO"
//!   4..8    u32 LE size_bytes
//!   8..16   u64 LE mtime_unix
//!  16..20   u32 LE extent[0]  (0 = unused)
//!  20..24   u32 LE extent[1]
//!  24..28   u32 LE extent[2]
//!  28      u8  kind (0=file, 1=dir)
//!  29..32   reserved
//! ```
//!
//! # Directory entry (32 bytes, fixed)
//!
//! ```text
//!   0..4    u32 LE target inode
//!   4       u8  name_len (1..=27)
//!   5..32   name bytes, zero-padded
//! ```

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    JournalFs, JfsDirEntry, JfsError, JfsInode, JfsSuperblock, JFS_DE_OFF_INODE, JFS_DE_OFF_NAME,
    JFS_DE_OFF_NAME_LEN, JFS_DIRENT_LEN, JFS_DIRENT_MAX_NAME, JFS_INODE_LEN, JFS_INODE_MAGIC,
    JFS_INODES_PER_SECTOR, JFS_INO_OFF_EXTENT0, JFS_INO_OFF_EXTENT1, JFS_INO_OFF_EXTENT2,
    JFS_INO_OFF_KIND, JFS_INO_OFF_MAGIC, JFS_INO_OFF_MTIME, JFS_INO_OFF_SIZE, JFS_KIND_DIR,
    JFS_KIND_FILE, JFS_MAGIC, JFS_ROOT_INODE, JFS_SB_LEN, JFS_SB_OFF_BITMAP_LBA,
    JFS_SB_OFF_BLOCK_SIZE, JFS_SB_OFF_DATA_START_LBA, JFS_SB_OFF_INODE_COUNT,
    JFS_SB_OFF_INODE_TABLE_LBA, JFS_SB_OFF_MAGIC, JFS_SB_OFF_ROOT_INODE, JFS_SB_OFF_VERSION,
    JFS_SECTOR_SIZE, JFS_VERSION,
};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

#[inline]
fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    let mut b = [0u8; 4];
    b.copy_from_slice(&buf[off..off + 4]);
    u32::from_le_bytes(b)
}

#[inline]
fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&buf[off..off + 8]);
    u64::from_le_bytes(b)
}

#[inline]
fn write_u32_le(buf: &mut [u8], off: usize, v: u32) {
    let b = v.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}

#[inline]
fn write_u64_le(buf: &mut [u8], off: usize, v: u64) {
    let b = v.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        buf[off + i] = b[i];
        i += 1;
    }
}

/// Absolute byte offset of LBA `lba` inside an image.
#[inline]
pub fn lba_offset(lba: u32) -> usize {
    (lba as usize) * JFS_SECTOR_SIZE
}

/// Slice one sector out of `image`. Returns [`JfsError::Truncated`]
/// if the LBA falls off the end.
pub fn sector_slice(image: &[u8], lba: u32) -> Result<&[u8], JfsError> {
    let off = lba_offset(lba);
    if off + JFS_SECTOR_SIZE > image.len() {
        return Err(JfsError::Truncated);
    }
    Ok(&image[off..off + JFS_SECTOR_SIZE])
}

/// Mutable sector slice (fixture builders).
pub fn sector_slice_mut(image: &mut [u8], lba: u32) -> Result<&mut [u8], JfsError> {
    let off = lba_offset(lba);
    if off + JFS_SECTOR_SIZE > image.len() {
        return Err(JfsError::Truncated);
    }
    Ok(&mut image[off..off + JFS_SECTOR_SIZE])
}

// ---------------------------------------------------------------------------
// Pure parsers (also usable without a mounted handle)
// ---------------------------------------------------------------------------

/// Parse a superblock from the first [`JFS_SB_LEN`] bytes of `buf`.
pub fn parse_superblock(buf: &[u8]) -> Result<JfsSuperblock, JfsError> {
    if buf.len() < JFS_SB_LEN {
        return Err(JfsError::Truncated);
    }
    if buf[JFS_SB_OFF_MAGIC..JFS_SB_OFF_MAGIC + 4] != JFS_MAGIC {
        return Err(JfsError::BadMagic);
    }
    let version = read_u32_le(buf, JFS_SB_OFF_VERSION);
    if version != JFS_VERSION {
        return Err(JfsError::BadVersion);
    }
    let block_size = read_u32_le(buf, JFS_SB_OFF_BLOCK_SIZE);
    if block_size as usize != JFS_SECTOR_SIZE {
        return Err(JfsError::BadBlockSize);
    }
    let root_inode = read_u32_le(buf, JFS_SB_OFF_ROOT_INODE);
    if root_inode != JFS_ROOT_INODE {
        return Err(JfsError::BadSuperblock);
    }
    let inode_count = read_u32_le(buf, JFS_SB_OFF_INODE_COUNT);
    if inode_count == 0 || inode_count > 16 * 1024 {
        return Err(JfsError::BadSuperblock);
    }
    let inode_table_lba = read_u32_le(buf, JFS_SB_OFF_INODE_TABLE_LBA);
    let data_start_lba = read_u32_le(buf, JFS_SB_OFF_DATA_START_LBA);
    let free_bitmap_lba = read_u32_le(buf, JFS_SB_OFF_BITMAP_LBA);
    if inode_table_lba == 0 {
        return Err(JfsError::BadSuperblock);
    }
    Ok(JfsSuperblock {
        version,
        block_size,
        root_inode,
        inode_count,
        inode_table_lba,
        data_start_lba,
        free_bitmap_lba,
    })
}

/// Encode a superblock into the first [`JFS_SB_LEN`] bytes of `out`.
///
/// **TASK-164:** requires a [`CapProof`] minted under
/// [`proteus_contracts::caps::DURABLE_FS_WRITE`]. This is the first
/// JFS durable-write gate (superblock is the image root of trust).
/// Inode/dirent/body encodes remain open residual.
pub fn encode_superblock(
    sb: &JfsSuperblock,
    out: &mut [u8],
    _proof: proteus_contracts::CapProof,
) -> Result<(), JfsError> {
    let _ = _proof;
    if out.len() < JFS_SB_LEN {
        return Err(JfsError::Truncated);
    }
    out[JFS_SB_OFF_MAGIC..JFS_SB_OFF_MAGIC + 4].copy_from_slice(&JFS_MAGIC);
    write_u32_le(out, JFS_SB_OFF_VERSION, sb.version);
    write_u32_le(out, JFS_SB_OFF_BLOCK_SIZE, sb.block_size);
    write_u32_le(out, JFS_SB_OFF_ROOT_INODE, sb.root_inode);
    write_u32_le(out, JFS_SB_OFF_INODE_COUNT, sb.inode_count);
    write_u32_le(out, JFS_SB_OFF_INODE_TABLE_LBA, sb.inode_table_lba);
    write_u32_le(out, JFS_SB_OFF_DATA_START_LBA, sb.data_start_lba);
    write_u32_le(out, JFS_SB_OFF_BITMAP_LBA, sb.free_bitmap_lba);
    Ok(())
}

/// Mint a CapProof for [`proteus_contracts::caps::DURABLE_FS_WRITE`]
/// when `held` includes that bit (TASK-164).
#[inline]
pub fn durable_fs_proof(
    held: u64,
) -> Result<proteus_contracts::CapProof, proteus_contracts::CapError> {
    proteus_contracts::mint_cap_proof(held, proteus_contracts::caps::DURABLE_FS_WRITE)
}

/// Privileged self-grant for fixtures / banner / tests (TASK-164).
#[inline]
pub fn durable_fs_proof_init() -> proteus_contracts::CapProof {
    durable_fs_proof(proteus_contracts::caps::DURABLE_FS_WRITE)
        .expect("DURABLE_FS_WRITE self-grant must succeed")
}

/// Parse one 32-byte inode record at `buf`.
pub fn parse_inode(buf: &[u8], ino: u32) -> Result<JfsInode, JfsError> {
    if buf.len() < JFS_INODE_LEN {
        return Err(JfsError::Truncated);
    }
    // Free / empty slot: all zeros.
    let mut all_zero = true;
    let mut i = 0usize;
    while i < JFS_INODE_LEN {
        if buf[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    if all_zero {
        return Err(JfsError::BadInode);
    }
    if buf[JFS_INO_OFF_MAGIC..JFS_INO_OFF_MAGIC + 4] != JFS_INODE_MAGIC {
        return Err(JfsError::BadInode);
    }
    let kind = buf[JFS_INO_OFF_KIND];
    if kind != JFS_KIND_FILE && kind != JFS_KIND_DIR {
        return Err(JfsError::BadInode);
    }
    Ok(JfsInode {
        ino,
        size_bytes: read_u32_le(buf, JFS_INO_OFF_SIZE),
        mtime_unix: read_u64_le(buf, JFS_INO_OFF_MTIME),
        extents: [
            read_u32_le(buf, JFS_INO_OFF_EXTENT0),
            read_u32_le(buf, JFS_INO_OFF_EXTENT1),
            read_u32_le(buf, JFS_INO_OFF_EXTENT2),
        ],
        kind,
    })
}

/// Encode one inode into a 32-byte buffer.
///
/// **TASK-167:** requires [`CapProof`] under
/// [`proteus_contracts::caps::DURABLE_FS_WRITE`] (same bit as superblock).
pub fn encode_inode(
    inode: &JfsInode,
    out: &mut [u8],
    _proof: proteus_contracts::CapProof,
) -> Result<(), JfsError> {
    let _ = _proof;
    if out.len() < JFS_INODE_LEN {
        return Err(JfsError::Truncated);
    }
    let mut i = 0usize;
    while i < JFS_INODE_LEN {
        out[i] = 0;
        i += 1;
    }
    out[JFS_INO_OFF_MAGIC..JFS_INO_OFF_MAGIC + 4].copy_from_slice(&JFS_INODE_MAGIC);
    write_u32_le(out, JFS_INO_OFF_SIZE, inode.size_bytes);
    write_u64_le(out, JFS_INO_OFF_MTIME, inode.mtime_unix);
    write_u32_le(out, JFS_INO_OFF_EXTENT0, inode.extents[0]);
    write_u32_le(out, JFS_INO_OFF_EXTENT1, inode.extents[1]);
    write_u32_le(out, JFS_INO_OFF_EXTENT2, inode.extents[2]);
    out[JFS_INO_OFF_KIND] = inode.kind;
    Ok(())
}

/// Parse one fixed directory entry.
pub fn parse_dirent(buf: &[u8]) -> Result<Option<(u32, &[u8])>, JfsError> {
    if buf.len() < JFS_DIRENT_LEN {
        return Err(JfsError::Truncated);
    }
    let ino = read_u32_le(buf, JFS_DE_OFF_INODE);
    if ino == 0 {
        return Ok(None); // free / padding slot
    }
    let name_len = buf[JFS_DE_OFF_NAME_LEN] as usize;
    if name_len == 0 || name_len > JFS_DIRENT_MAX_NAME {
        return Err(JfsError::BadDirent);
    }
    let name = &buf[JFS_DE_OFF_NAME..JFS_DE_OFF_NAME + name_len];
    Ok(Some((ino, name)))
}

/// Encode one directory entry.
///
/// **TASK-168:** requires [`CapProof`] under
/// [`proteus_contracts::caps::DURABLE_FS_WRITE`] (namespace mutation is
/// durable when the image hits media). File *body* sector writes remain
/// open residual (no single encode helper for arbitrary payloads).
pub fn encode_dirent(
    ino: u32,
    name: &[u8],
    out: &mut [u8],
    _proof: proteus_contracts::CapProof,
) -> Result<(), JfsError> {
    let _ = _proof;
    if out.len() < JFS_DIRENT_LEN {
        return Err(JfsError::Truncated);
    }
    if name.is_empty() || name.len() > JFS_DIRENT_MAX_NAME {
        return Err(JfsError::BadDirent);
    }
    let mut i = 0usize;
    while i < JFS_DIRENT_LEN {
        out[i] = 0;
        i += 1;
    }
    write_u32_le(out, JFS_DE_OFF_INODE, ino);
    out[JFS_DE_OFF_NAME_LEN] = name.len() as u8;
    out[JFS_DE_OFF_NAME..JFS_DE_OFF_NAME + name.len()].copy_from_slice(name);
    Ok(())
}

// ---------------------------------------------------------------------------
// Mounted walker
// ---------------------------------------------------------------------------

/// Stateless-after-mount JFS walker. Holds only the parsed superblock;
/// every method re-borrows the image slice.
pub struct JfsImpl {
    sb: JfsSuperblock,
}

impl JfsImpl {
    /// Superblock accessor (same as trait method, for free use).
    pub fn sb(&self) -> &JfsSuperblock {
        &self.sb
    }
}

impl JournalFs for JfsImpl {
    fn mount(image: &[u8]) -> Result<Self, JfsError> {
        if image.len() < JFS_SECTOR_SIZE {
            return Err(JfsError::Truncated);
        }
        let sb = parse_superblock(&image[..JFS_SB_LEN])?;
        // Inode table must fit.
        let table_bytes = (sb.inode_count as usize) * JFS_INODE_LEN;
        let table_sectors =
            (table_bytes + JFS_SECTOR_SIZE - 1) / JFS_SECTOR_SIZE;
        let table_end = lba_offset(sb.inode_table_lba) + table_sectors * JFS_SECTOR_SIZE;
        if table_end > image.len() {
            return Err(JfsError::Truncated);
        }
        Ok(JfsImpl { sb })
    }

    fn superblock(&self) -> &JfsSuperblock {
        &self.sb
    }

    fn read_inode(&self, image: &[u8], ino: u32) -> Result<JfsInode, JfsError> {
        if ino == 0 || ino >= self.sb.inode_count {
            return Err(JfsError::BadInode);
        }
        // Slot `ino` sits at byte offset ino * JFS_INODE_LEN within the
        // inode table, which starts at inode_table_lba.
        let byte_off = lba_offset(self.sb.inode_table_lba) + (ino as usize) * JFS_INODE_LEN;
        if byte_off + JFS_INODE_LEN > image.len() {
            return Err(JfsError::Truncated);
        }
        parse_inode(&image[byte_off..byte_off + JFS_INODE_LEN], ino)
    }

    fn read_dir(
        &self,
        image: &[u8],
        dir_ino: u32,
        sink: &mut dyn FnMut(JfsDirEntry<'_>),
    ) -> Result<usize, JfsError> {
        let inode = self.read_inode(image, dir_ino)?;
        if !inode.is_dir() {
            return Err(JfsError::WrongKind);
        }
        // Read the directory body into a stack buffer (max 3 sectors).
        let mut body = [0u8; JFS_SECTOR_SIZE * 3];
        let n = self.read_file_body(image, &inode, &mut body)?;
        if n % JFS_DIRENT_LEN != 0 {
            return Err(JfsError::BadDirent);
        }
        let mut count = 0usize;
        let mut off = 0usize;
        while off + JFS_DIRENT_LEN <= n {
            match parse_dirent(&body[off..off + JFS_DIRENT_LEN])? {
                None => {}
                Some((ino, name)) => {
                    sink(JfsDirEntry { ino, name });
                    count += 1;
                }
            }
            off += JFS_DIRENT_LEN;
        }
        Ok(count)
    }

    fn lookup(&self, image: &[u8], dir_ino: u32, name: &[u8]) -> Result<u32, JfsError> {
        let mut found: Option<u32> = None;
        self.read_dir(image, dir_ino, &mut |e| {
            if found.is_none() && e.name == name {
                found = Some(e.ino);
            }
        })?;
        found.ok_or(JfsError::NotFound)
    }

    fn read_file(&self, image: &[u8], ino: u32, out: &mut [u8]) -> Result<usize, JfsError> {
        let inode = self.read_inode(image, ino)?;
        if !inode.is_file() {
            return Err(JfsError::WrongKind);
        }
        self.read_file_body(image, &inode, out)
    }
}

impl JfsImpl {
    /// Read the body of any inode (file or directory) via direct extents.
    fn read_file_body(
        &self,
        image: &[u8],
        inode: &JfsInode,
        out: &mut [u8],
    ) -> Result<usize, JfsError> {
        let size = inode.size_bytes as usize;
        if size > 3 * JFS_SECTOR_SIZE {
            return Err(JfsError::FileTooLarge);
        }
        if out.len() < size {
            return Err(JfsError::BufferTooSmall);
        }
        let mut written = 0usize;
        let mut ei = 0usize;
        while ei < 3 && written < size {
            let lba = inode.extents[ei];
            if lba == 0 {
                break;
            }
            let sec = sector_slice(image, lba)?;
            let take = core::cmp::min(JFS_SECTOR_SIZE, size - written);
            out[written..written + take].copy_from_slice(&sec[..take]);
            written += take;
            ei += 1;
        }
        if written < size {
            // Not enough extents to cover size_bytes — corrupt image.
            return Err(JfsError::Truncated);
        }
        Ok(size)
    }
}

// ---------------------------------------------------------------------------
// Fixture builder (hand-rolled banner + test image)
// ---------------------------------------------------------------------------

/// Canonical banner fixture: 4 sectors.
///
/// - LBA 0: superblock (root=1, inode_count=3, table@1, data@2)
/// - LBA 1: inode table — ino1=root dir, ino2=hello.txt
/// - LBA 2: root directory body (one dirent → hello.txt)
/// - LBA 3: hello.txt body
pub const FIXTURE_SECTORS: usize = 4;
/// Byte length of the canonical fixture.
pub const FIXTURE_BYTES: usize = FIXTURE_SECTORS * JFS_SECTOR_SIZE;

/// Body of `/hello.txt` in the banner fixture.
pub const HELLO_BODY: &[u8] = b"hello, proteus!\n";
/// Expected length of [`HELLO_BODY`].
pub const HELLO_BODY_LEN: usize = 16;

/// Build the locked banner fixture into `out` (must be ≥ [`FIXTURE_BYTES`]).
/// Returns the number of bytes written ([`FIXTURE_BYTES`]).
pub fn build_banner_fixture(out: &mut [u8]) -> Result<usize, JfsError> {
    if out.len() < FIXTURE_BYTES {
        return Err(JfsError::BufferTooSmall);
    }
    // Zero the whole image first.
    let mut i = 0usize;
    while i < FIXTURE_BYTES {
        out[i] = 0;
        i += 1;
    }

    // Superblock.
    let sb = JfsSuperblock {
        version: JFS_VERSION,
        block_size: JFS_SECTOR_SIZE as u32,
        root_inode: JFS_ROOT_INODE,
        inode_count: 3, // slots 0..2 (0 unused, 1 root, 2 hello)
        inode_table_lba: 1,
        data_start_lba: 2,
        free_bitmap_lba: 0,
    };
    encode_superblock(&sb, &mut out[..JFS_SB_LEN], durable_fs_proof_init())?;

    // Inode 1: root directory, body at LBA 2, size = one dirent.
    let root = JfsInode {
        ino: 1,
        size_bytes: JFS_DIRENT_LEN as u32,
        mtime_unix: 1_773_578_096, // matches RTC fixture epoch
        extents: [2, 0, 0],
        kind: JFS_KIND_DIR,
    };
    let root_off = lba_offset(1) + 1 * JFS_INODE_LEN;
    encode_inode(&root, &mut out[root_off..root_off + JFS_INODE_LEN], durable_fs_proof_init())?;

    // Inode 2: hello.txt, body at LBA 3.
    let hello = JfsInode {
        ino: 2,
        size_bytes: HELLO_BODY_LEN as u32,
        mtime_unix: 1_773_578_096,
        extents: [3, 0, 0],
        kind: JFS_KIND_FILE,
    };
    let hello_off = lba_offset(1) + 2 * JFS_INODE_LEN;
    encode_inode(&hello, &mut out[hello_off..hello_off + JFS_INODE_LEN], durable_fs_proof_init())?;

    // Root dir body at LBA 2: one dirent for "hello.txt" → ino 2.
    let dir_sec = sector_slice_mut(out, 2)?;
    encode_dirent(2, b"hello.txt", &mut dir_sec[..JFS_DIRENT_LEN], durable_fs_proof_init())?;

    // File body at LBA 3.
    let file_sec = sector_slice_mut(out, 3)?;
    file_sec[..HELLO_BODY_LEN].copy_from_slice(HELLO_BODY);

    Ok(FIXTURE_BYTES)
}

/// Fletcher-32 over `data` — used by the kernel banner to print a
/// short content fingerprint without pulling the full HashImpl path.
pub fn fletcher32_body(data: &[u8]) -> u32 {
    let mut sum1: u32 = 0;
    let mut sum2: u32 = 0;
    let mut i = 0usize;
    while i + 1 < data.len() {
        let word = ((data[i] as u32) << 8) | (data[i + 1] as u32);
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
        i += 2;
    }
    if i < data.len() {
        let word = (data[i] as u32) << 8;
        sum1 = (sum1 + word) % 0xFFFF;
        sum2 = (sum2 + sum1) % 0xFFFF;
    }
    (sum2 << 16) | sum1
}

/// Locked Fletcher-32 of [`HELLO_BODY`] — computed offline so the
/// banner can assert without recomputing a golden each morph.
///
/// Verified by `hello_body_fletcher_locked` unit test.
pub const HELLO_BODY_FLETCHER32: u32 = 0xaa3c_e1c0;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::JournalFs;

    fn fixture() -> [u8; FIXTURE_BYTES] {
        let mut img = [0u8; FIXTURE_BYTES];
        build_banner_fixture(&mut img).expect("fixture");
        img
    }

    #[test]
    fn constants_match_spec() {
        assert_eq!(&JFS_MAGIC, b"JFS2");
        assert_eq!(&JFS_INODE_MAGIC, b"JINO");
        assert_eq!(JFS_VERSION, 2);
        assert_eq!(JFS_SECTOR_SIZE, 512);
        assert_eq!(JFS_SB_LEN, 32);
        assert_eq!(JFS_INODE_LEN, 32);
        assert_eq!(JFS_DIRENT_LEN, 32);
        assert_eq!(JFS_DIRENT_MAX_NAME, 27);
        assert_eq!(JFS_INODES_PER_SECTOR, 16);
        assert_eq!(JFS_ROOT_INODE, 1);
        assert_eq!(JFS_KIND_FILE, 0);
        assert_eq!(JFS_KIND_DIR, 1);
        assert_eq!(HELLO_BODY_LEN, HELLO_BODY.len());
    }

    #[test]
    fn field_offsets_are_packed() {
        assert_eq!(JFS_SB_OFF_MAGIC, 0);
        assert_eq!(JFS_SB_OFF_VERSION, 4);
        assert_eq!(JFS_SB_OFF_BLOCK_SIZE, 8);
        assert_eq!(JFS_SB_OFF_ROOT_INODE, 12);
        assert_eq!(JFS_SB_OFF_INODE_COUNT, 16);
        assert_eq!(JFS_SB_OFF_INODE_TABLE_LBA, 20);
        assert_eq!(JFS_SB_OFF_DATA_START_LBA, 24);
        assert_eq!(JFS_SB_OFF_BITMAP_LBA, 28);
        assert_eq!(JFS_INO_OFF_MAGIC, 0);
        assert_eq!(JFS_INO_OFF_SIZE, 4);
        assert_eq!(JFS_INO_OFF_MTIME, 8);
        assert_eq!(JFS_INO_OFF_EXTENT0, 16);
        assert_eq!(JFS_INO_OFF_KIND, 28);
        assert_eq!(JFS_DE_OFF_INODE, 0);
        assert_eq!(JFS_DE_OFF_NAME_LEN, 4);
        assert_eq!(JFS_DE_OFF_NAME, 5);
    }

    #[test]
    fn mount_banner_fixture() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).expect("mount");
        let sb = fs.superblock();
        assert_eq!(sb.version, JFS_VERSION);
        assert_eq!(sb.block_size, 512);
        assert_eq!(sb.root_inode, 1);
        assert_eq!(sb.inode_count, 3);
        assert_eq!(sb.inode_table_lba, 1);
        assert_eq!(sb.data_start_lba, 2);
    }

    #[test]
    fn mount_rejects_short_image() {
        let img = [0u8; 100];
        assert!(matches!(JfsImpl::mount(&img), Err(JfsError::Truncated)));
    }

    #[test]
    fn mount_rejects_bad_magic() {
        let mut img = fixture();
        img[0] = b'X';
        assert!(matches!(JfsImpl::mount(&img), Err(JfsError::BadMagic)));
    }

    #[test]
    fn mount_rejects_bad_version() {
        let mut img = fixture();
        write_u32_le(&mut img, JFS_SB_OFF_VERSION, 99);
        assert!(matches!(JfsImpl::mount(&img), Err(JfsError::BadVersion)));
    }

    #[test]
    fn mount_rejects_bad_block_size() {
        let mut img = fixture();
        write_u32_le(&mut img, JFS_SB_OFF_BLOCK_SIZE, 1024);
        assert!(matches!(JfsImpl::mount(&img), Err(JfsError::BadBlockSize)));
    }

    #[test]
    fn mount_rejects_bad_root_inode() {
        let mut img = fixture();
        write_u32_le(&mut img, JFS_SB_OFF_ROOT_INODE, 7);
        assert!(matches!(
            JfsImpl::mount(&img),
            Err(JfsError::BadSuperblock)
        ));
    }

    #[test]
    fn encode_superblock_requires_durable_fs_cap() {
        // TASK-164: unprivileged held mask cannot mint FS durable proof.
        assert!(durable_fs_proof(0).is_err());
        assert!(durable_fs_proof(proteus_contracts::caps::BLOCK_WRITE).is_err());
        assert!(durable_fs_proof(proteus_contracts::caps::DURABLE_WAL_WRITE).is_err());
        let p = durable_fs_proof(proteus_contracts::caps::DURABLE_FS_WRITE).unwrap();
        let sb = JfsSuperblock {
            version: JFS_VERSION,
            block_size: JFS_SECTOR_SIZE as u32,
            root_inode: JFS_ROOT_INODE,
            inode_count: 2,
            inode_table_lba: 1,
            data_start_lba: 2,
            free_bitmap_lba: 0,
        };
        let mut buf = [0u8; 32];
        encode_superblock(&sb, &mut buf, p).unwrap();
        assert_eq!(&buf[0..4], &JFS_MAGIC);
    }

    #[test]
    fn encode_inode_and_dirent_require_durable_fs_cap() {
        // TASK-167/168: same bit as superblock; body writes still ungated.
        let ino = JfsInode {
            ino: 1,
            size_bytes: 0,
            mtime_unix: 0,
            extents: [0; 3],
            kind: JFS_KIND_FILE,
        };
        let mut ibuf = [0u8; 32];
        encode_inode(&ino, &mut ibuf, durable_fs_proof_init()).unwrap();
        assert_eq!(&ibuf[0..4], &JFS_INODE_MAGIC);

        let mut dbuf = [0u8; 32];
        encode_dirent(2, b"x.txt", &mut dbuf, durable_fs_proof_init()).unwrap();
        assert_eq!(parse_dirent(&dbuf).unwrap().unwrap().0, 2);
    }

    #[test]
    fn superblock_round_trip() {
        let sb = JfsSuperblock {
            version: 2,
            block_size: 512,
            root_inode: 1,
            inode_count: 16,
            inode_table_lba: 3,
            data_start_lba: 10,
            free_bitmap_lba: 2,
        };
        let mut buf = [0u8; 32];
        encode_superblock(&sb, &mut buf, durable_fs_proof_init()).unwrap();
        let back = parse_superblock(&buf).unwrap();
        assert_eq!(back, sb);
    }

    #[test]
    fn inode_round_trip() {
        let ino = JfsInode {
            ino: 5,
            size_bytes: 42,
            mtime_unix: 1_700_000_000,
            extents: [10, 11, 0],
            kind: JFS_KIND_FILE,
        };
        let mut buf = [0u8; 32];
        encode_inode(&ino, &mut buf, durable_fs_proof_init()).unwrap();
        let back = parse_inode(&buf, 5).unwrap();
        assert_eq!(back.size_bytes, 42);
        assert_eq!(back.mtime_unix, 1_700_000_000);
        assert_eq!(back.extents, [10, 11, 0]);
        assert!(back.is_file());
        assert!(!back.is_dir());
    }

    #[test]
    fn parse_inode_rejects_empty_slot() {
        let buf = [0u8; 32];
        assert_eq!(parse_inode(&buf, 1), Err(JfsError::BadInode));
    }

    #[test]
    fn parse_inode_rejects_bad_magic() {
        let mut buf = [0u8; 32];
        buf[0..4].copy_from_slice(b"XXXX");
        buf[JFS_INO_OFF_KIND] = JFS_KIND_FILE;
        assert_eq!(parse_inode(&buf, 1), Err(JfsError::BadInode));
    }

    #[test]
    fn dirent_round_trip() {
        let mut buf = [0u8; 32];
        encode_dirent(42, b"hello.txt", &mut buf, durable_fs_proof_init()).unwrap();
        let (ino, name) = parse_dirent(&buf).unwrap().unwrap();
        assert_eq!(ino, 42);
        assert_eq!(name, b"hello.txt");
    }

    #[test]
    fn dirent_rejects_empty_name() {
        let mut buf = [0u8; 32];
        assert_eq!(encode_dirent(1, b"", &mut buf, durable_fs_proof_init()), Err(JfsError::BadDirent));
    }

    #[test]
    fn dirent_rejects_overlong_name() {
        let mut buf = [0u8; 32];
        let long = [b'a'; 28];
        assert_eq!(
            encode_dirent(1, &long, &mut buf, durable_fs_proof_init()),
            Err(JfsError::BadDirent)
        );
    }

    #[test]
    fn dirent_zero_inode_is_free_slot() {
        let buf = [0u8; 32];
        assert_eq!(parse_dirent(&buf).unwrap(), None);
    }

    #[test]
    fn read_inode_root_is_dir() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let root = fs.read_inode(&img, 1).unwrap();
        assert!(root.is_dir());
        assert_eq!(root.size_bytes, JFS_DIRENT_LEN as u32);
        assert_eq!(root.extents[0], 2);
    }

    #[test]
    fn read_inode_hello_is_file() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let f = fs.read_inode(&img, 2).unwrap();
        assert!(f.is_file());
        assert_eq!(f.size_bytes, HELLO_BODY_LEN as u32);
        assert_eq!(f.extents[0], 3);
    }

    #[test]
    fn read_inode_zero_is_bad() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        assert_eq!(fs.read_inode(&img, 0), Err(JfsError::BadInode));
    }

    #[test]
    fn read_inode_out_of_range() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        assert_eq!(fs.read_inode(&img, 99), Err(JfsError::BadInode));
    }

    #[test]
    fn read_dir_lists_hello() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let mut inos = [0u32; 4];
        let mut name_ok = false;
        let mut n = 0usize;
        let count = fs
            .read_dir(&img, 1, &mut |e| {
                if n < 4 {
                    if e.name == b"hello.txt" {
                        name_ok = true;
                    }
                    inos[n] = e.ino;
                    n += 1;
                }
            })
            .unwrap();
        assert_eq!(count, 1);
        assert!(name_ok);
        assert_eq!(inos[0], 2);
    }

    #[test]
    fn lookup_hello_txt() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let ino = fs.lookup(&img, 1, b"hello.txt").unwrap();
        assert_eq!(ino, 2);
    }

    #[test]
    fn lookup_missing_is_not_found() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        assert_eq!(
            fs.lookup(&img, 1, b"missing"),
            Err(JfsError::NotFound)
        );
    }

    #[test]
    fn read_file_hello_body() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let mut out = [0u8; 64];
        let n = fs.read_file(&img, 2, &mut out).unwrap();
        assert_eq!(n, HELLO_BODY_LEN);
        assert_eq!(&out[..n], HELLO_BODY);
    }

    #[test]
    fn read_file_buffer_too_small() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            fs.read_file(&img, 2, &mut out),
            Err(JfsError::BufferTooSmall)
        );
    }

    #[test]
    fn read_file_on_dir_is_wrong_kind() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let mut out = [0u8; 64];
        assert_eq!(
            fs.read_file(&img, 1, &mut out),
            Err(JfsError::WrongKind)
        );
    }

    #[test]
    fn read_dir_on_file_is_wrong_kind() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        assert_eq!(
            fs.read_dir(&img, 2, &mut |_| {}),
            Err(JfsError::WrongKind)
        );
    }

    #[test]
    fn end_to_end_mount_lookup_read() {
        let img = fixture();
        let fs = JfsImpl::mount(&img).unwrap();
        let ino = fs.lookup(&img, fs.superblock().root_inode, b"hello.txt").unwrap();
        let mut out = [0u8; 64];
        let n = fs.read_file(&img, ino, &mut out).unwrap();
        assert_eq!(&out[..n], HELLO_BODY);
    }

    #[test]
    fn hello_body_fletcher_locked() {
        assert_eq!(fletcher32_body(HELLO_BODY), HELLO_BODY_FLETCHER32);
    }

    #[test]
    fn multi_extent_file() {
        // Build a custom image: file spanning two sectors.
        let mut img = [0u8; 5 * JFS_SECTOR_SIZE];
        let sb = JfsSuperblock {
            version: JFS_VERSION,
            block_size: 512,
            root_inode: 1,
            inode_count: 3,
            inode_table_lba: 1,
            data_start_lba: 2,
            free_bitmap_lba: 0,
        };
        encode_superblock(&sb, &mut img, durable_fs_proof_init()).unwrap();
        // Root dir empty (size 0, no extents) — still a dir.
        let root = JfsInode {
            ino: 1,
            size_bytes: 0,
            mtime_unix: 0,
            extents: [0, 0, 0],
            kind: JFS_KIND_DIR,
        };
        let root_off = lba_offset(1) + JFS_INODE_LEN;
        encode_inode(&root, &mut img[root_off..root_off + JFS_INODE_LEN], durable_fs_proof_init()).unwrap();
        // File of 600 bytes across LBA 2 + 3.
        let mut body = [0u8; 600];
        let mut i = 0usize;
        while i < 600 {
            body[i] = (i & 0xFF) as u8;
            i += 1;
        }
        let file = JfsInode {
            ino: 2,
            size_bytes: 600,
            mtime_unix: 0,
            extents: [2, 3, 0],
            kind: JFS_KIND_FILE,
        };
        let file_off = lba_offset(1) + 2 * JFS_INODE_LEN;
        encode_inode(&file, &mut img[file_off..file_off + JFS_INODE_LEN], durable_fs_proof_init()).unwrap();
        img[lba_offset(2)..lba_offset(2) + 512].copy_from_slice(&body[..512]);
        img[lba_offset(3)..lba_offset(3) + 88].copy_from_slice(&body[512..]);

        let fs = JfsImpl::mount(&img).unwrap();
        let mut out = [0u8; 600];
        let n = fs.read_file(&img, 2, &mut out).unwrap();
        assert_eq!(n, 600);
        assert_eq!(out, body);
    }

    #[test]
    fn multi_dirent_lookup() {
        let mut img = [0u8; 4 * JFS_SECTOR_SIZE];
        let sb = JfsSuperblock {
            version: JFS_VERSION,
            block_size: 512,
            root_inode: 1,
            inode_count: 4,
            inode_table_lba: 1,
            data_start_lba: 2,
            free_bitmap_lba: 0,
        };
        encode_superblock(&sb, &mut img, durable_fs_proof_init()).unwrap();
        // Root dir with 2 dirents.
        let root = JfsInode {
            ino: 1,
            size_bytes: (2 * JFS_DIRENT_LEN) as u32,
            mtime_unix: 0,
            extents: [2, 0, 0],
            kind: JFS_KIND_DIR,
        };
        encode_inode(
            &root,
            &mut img[lba_offset(1) + JFS_INODE_LEN..lba_offset(1) + 2 * JFS_INODE_LEN],
            durable_fs_proof_init(),
        )
        .unwrap();
        // Two empty files.
        for (ino, name_lba) in [(2u32, 3u32), (3u32, 3u32)] {
            let f = JfsInode {
                ino,
                size_bytes: 0,
                mtime_unix: 0,
                extents: [name_lba, 0, 0],
                kind: JFS_KIND_FILE,
            };
            let off = lba_offset(1) + (ino as usize) * JFS_INODE_LEN;
            encode_inode(&f, &mut img[off..off + JFS_INODE_LEN], durable_fs_proof_init()).unwrap();
        }
        let dir = sector_slice_mut(&mut img, 2).unwrap();
        encode_dirent(2, b"a.txt", &mut dir[0..32], durable_fs_proof_init()).unwrap();
        encode_dirent(3, b"b.txt", &mut dir[32..64], durable_fs_proof_init()).unwrap();

        let fs = JfsImpl::mount(&img).unwrap();
        assert_eq!(fs.lookup(&img, 1, b"a.txt").unwrap(), 2);
        assert_eq!(fs.lookup(&img, 1, b"b.txt").unwrap(), 3);
        assert_eq!(fs.lookup(&img, 1, b"c.txt"), Err(JfsError::NotFound));
        let mut count = 0usize;
        fs.read_dir(&img, 1, &mut |_| count += 1).unwrap();
        assert_eq!(count, 2);
    }

    #[test]
    fn inode_is_file_is_dir_helpers() {
        let f = JfsInode {
            ino: 1,
            size_bytes: 0,
            mtime_unix: 0,
            extents: [0; 3],
            kind: JFS_KIND_FILE,
        };
        let d = JfsInode {
            kind: JFS_KIND_DIR,
            ..f
        };
        assert!(f.is_file() && !f.is_dir());
        assert!(d.is_dir() && !d.is_file());
    }

    #[test]
    fn sector_slice_bounds() {
        let img = [0u8; 512];
        assert!(sector_slice(&img, 0).is_ok());
        assert_eq!(sector_slice(&img, 1), Err(JfsError::Truncated));
    }

    #[test]
    fn fixture_is_deterministic() {
        let a = fixture();
        let b = fixture();
        assert_eq!(a, b);
    }

    #[test]
    fn empty_file_reads_zero_bytes() {
        let mut img = [0u8; 3 * JFS_SECTOR_SIZE];
        let sb = JfsSuperblock {
            version: JFS_VERSION,
            block_size: 512,
            root_inode: 1,
            inode_count: 3,
            inode_table_lba: 1,
            data_start_lba: 2,
            free_bitmap_lba: 0,
        };
        encode_superblock(&sb, &mut img, durable_fs_proof_init()).unwrap();
        let root = JfsInode {
            ino: 1,
            size_bytes: 0,
            mtime_unix: 0,
            extents: [0; 3],
            kind: JFS_KIND_DIR,
        };
        encode_inode(
            &root,
            &mut img[lba_offset(1) + JFS_INODE_LEN..lba_offset(1) + 2 * JFS_INODE_LEN],
            durable_fs_proof_init(),
        )
        .unwrap();
        let empty = JfsInode {
            ino: 2,
            size_bytes: 0,
            mtime_unix: 0,
            extents: [0; 3],
            kind: JFS_KIND_FILE,
        };
        encode_inode(
            &empty,
            &mut img[lba_offset(1) + 2 * JFS_INODE_LEN..lba_offset(1) + 3 * JFS_INODE_LEN],
            durable_fs_proof_init(),
        )
        .unwrap();
        let fs = JfsImpl::mount(&img).unwrap();
        let mut out = [0u8; 16];
        assert_eq!(fs.read_file(&img, 2, &mut out).unwrap(), 0);
    }
}
