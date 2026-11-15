//! Page-Granular Encrypted 4 KiB Copy-on-Write + Physical `CWAL` Block Storage Engine (`CTTLPGS1`).
//!
//! Lifts Cuttle OS's durable relational SQL (`SqlDb`) and Virtual Filesystem (`MemRamFs`)
//! above the fixed 53-sector (`26.5 KiB`) `AB_FORMAT_V3` snapshot ceiling while keeping
//! `LBA 0..2047` (`AB_FORMAT_V3` primary/shadow/commit at `1040..=1149`, quarantine at
//! `1216..=1323`, emergency crash dump at `1536..=1567`, and `2048`-sector `1 MiB` smoke
//! disks) 100% intact.
//!
//! ## On-Disk Layout (`LBA 2048..`, active when `dev.capacity_sectors() >= 4096`)
//!
//! ```text
//!   LBA 2048         Superblock A (CTTLPGS1, 512 B, HMAC-SHA256 sealed)
//!   LBA 2049         Superblock B (CTTLPGS1, 512 B, HMAC-SHA256 sealed)
//!   LBA 2050..2058   Page Directory A (8 sectors = 4 KiB, 256 x 16-byte entries)
//!   LBA 2058..2066   Page Directory B (8 sectors = 4 KiB, 256 x 16-byte entries)
//!   LBA 2066..2194   Physical CWAL Redo Journal (128 sectors = 64 KiB:
//!                      LBA 2066 = CTTLCWL1 header, LBA 2067..2193 = up to 14 x 9-sector redo frames)
//!   LBA 2194..       Encrypted 4 KiB Physical Page Pool (8 sectors/page, up to 512 phys pages = 2 MiB)
//! ```
//!
//! ## Security & Crash-Atomicity Guarantees
//!
//! 1. **Per-Page Authenticated Encryption (`ChaCha20-Poly1305`, RFC 8439):**
//!    Every 4 KiB physical page carries a 64-byte `CTTLPGE1` header (`domain`, `flags`,
//!    `logical_id`, `phys_slot`, `payload_len`, `owner_id`, `page_lsn`, 96-bit nonce,
//!    128-bit Poly1305 tag) and `4,032` bytes of ciphertext with `AAD = header[0..28]`.
//!    Cross-page substitution, cross-domain replay, and bit-flips fail closed.
//!
//!    The nonce is derived from the header **and the plaintext** (see `page_nonce`), so
//!    two different page images are never sealed under one nonce, whatever happens to the
//!    LSN. That matters because an epoch can be written and then abandoned (a power cut
//!    between this store's commit and the `AB_FORMAT_V3` commit that anchors it, or a
//!    failed commit): the next commit writes different contents to the same physical slots.
//!    Independently of that, an LSN is never reused: see [`PagedBlockStore::lsn_floor`].
//! 2. **Binary SHA-256 Merkle Anti-Rollback Root (`page_lsn_merkle_root`):**
//!    An 8-level binary SHA-256 Merkle tree commits all `256` `(logical_id, domain, flags,
//!    phys_slot, owner_id, page_lsn)` directory leaves into a 32-byte root anchored both in
//!    the `CTTLPGS1` A/B Superblocks and in `OsShell`'s `AB_FORMAT_V3` state image (`CTTLPGA1`),
//!    defeating single-page LSN rollback and whole-region replay.
//! 3. **`O(dirty pages)` Dual-Epoch Copy-on-Write + `CWAL` Redo Commits:**
//!    Because `max_logical <= avail_phys / 2`, dirty logical pages are always staged into
//!    free physical slots disjoint from the previous committed epoch (`prev_dir`). Both the
//!    previous committed epoch and the newly staged epoch remain simultaneously intact on the
//!    platter across the `AB_FORMAT_V3` commit barrier, while `CWAL` physical redo records
//!    enable deterministic roll-forward and home-page self-healing after interrupted commits.

use alloc::boxed::Box;
use alloc::vec::Vec;
use sha2::{Digest, Sha256};

use crate::durable_seal::{
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place, constant_time_eq,
    is_seal_key_set, seal_bytes_keyed, seal_matches_keyed, zeroize_secret_bytes, AEAD_NONCE_LEN,
    AEAD_TAG_LEN, DURABLE_DIGEST_LEN,
};
use crate::state_store::{IoFault, SectorIo, SECTOR_BYTES};

/// First LBA of the paged block store (`1 MiB` offset, clear of `LBA 0..2047`).
pub const PAGED_STORE_BASE_LBA: u64 = 2048;
/// Minimum device capacity in 512-byte sectors required to activate [`PagedBlockStore`] (`2 MiB`).
pub const PAGED_STORE_MIN_DISK_SECTORS: u64 = 4096;
/// Recommended enterprise state disk size in 512-byte sectors (`4 MiB`, full 256 logical / 512 physical pages).
pub const PAGED_STORE_DEFAULT_DISK_SECTORS: u64 = 8192;

/// Sectors per 4 KiB page (`8` x `512` B).
pub const SECTORS_PER_PAGE: usize = 8;
/// Byte size of one encrypted storage page (`4096` B).
pub const PAGED_PAGE_BYTES: usize = SECTORS_PER_PAGE * SECTOR_BYTES;
/// Byte size of the cleartext authenticated header on every 4 KiB physical page (`64` B).
pub const PAGED_PAGE_HEADER_BYTES: usize = 64;
/// Usable encrypted payload bytes per 4 KiB page (`4032` B).
pub const PAGED_PAGE_PAYLOAD_BYTES: usize = PAGED_PAGE_BYTES - PAGED_PAGE_HEADER_BYTES;

/// Maximum logical 4 KiB pages addressable in the v1 page directory (`256` pages = `1,032,192` payload bytes).
pub const PAGED_MAX_LOGICAL_PAGES: usize = 256;
/// Maximum physical 4 KiB page slots managed in the v1 CoW pool (`512` pages = `2 MiB`).
pub const PAGED_MAX_PHYS_PAGES: usize = 512;
/// Binary Merkle tree height over [`PAGED_MAX_LOGICAL_PAGES`] (`2^8 = 256`).
pub const PAGED_MERKLE_DEPTH: usize = 8;

/// Minimum device capacity in 512-byte sectors that activates `CTTLPGS1` format v2 (`8 MiB` = `16,384` sectors).
pub const PAGED_V2_MIN_DISK_SECTORS: u64 = 16_384;
/// Recommended large-scale enterprise state disk size (`12 MiB` = `24,576` sectors, full `1,024` logical / `2,048` physical pages).
pub const PAGED_STORE_LARGE_DISK_SECTORS: u64 = 24_576;
/// Sectors per directory copy (`DIR_A` / `DIR_B`) in `CTTLPGS1` format v2 (`32` sectors = `16 KiB`).
pub const PAGED_V2_DIR_SECTORS: usize = 32;
/// Maximum logical 4 KiB pages addressable in `CTTLPGS1` format v2 (`1,024` pages = `4,128,768` payload bytes).
pub const PAGED_V2_MAX_LOGICAL_PAGES: usize = 1024;
/// Maximum physical 4 KiB page slots managed in the v2 CoW pool (`2,048` pages = `8 MiB`).
pub const PAGED_V2_MAX_PHYS_PAGES: usize = 2048;
/// Binary Merkle tree height over [`PAGED_V2_MAX_LOGICAL_PAGES`] (`2^10 = 1024`).
pub const PAGED_V2_MERKLE_DEPTH: usize = 10;

/// LBA of Superblock A (`2048`).
pub const SUPERBLOCK_A_LBA: u64 = PAGED_STORE_BASE_LBA;
/// LBA of Superblock B (`2049`).
pub const SUPERBLOCK_B_LBA: u64 = PAGED_STORE_BASE_LBA + 1;
/// First LBA of Page Directory A (`2050..2058`, `8` sectors).
pub const DIR_A_LBA: u64 = PAGED_STORE_BASE_LBA + 2;
/// First LBA of Page Directory B (`2058..2066`, `8` sectors).
pub const DIR_B_LBA: u64 = DIR_A_LBA + SECTORS_PER_PAGE as u64;
/// First LBA of the `CWAL` physical redo journal (`2066..2194`, `128` sectors = `64 KiB`).
pub const CWAL_BASE_LBA: u64 = DIR_B_LBA + SECTORS_PER_PAGE as u64;
/// Total sectors reserved for the `CWAL` physical redo journal (`128` sectors).
pub const CWAL_TOTAL_SECTORS: u64 = 128;
/// Maximum full 4 KiB page redo frames stored in one `CWAL` batch (`(128 - 1) / 9 = 14`).
pub const CWAL_MAX_REDO_PAGES: usize = 14;
/// Sectors per `CWAL` physical redo frame (`1` descriptor sector + `8` encrypted page sectors).
pub const CWAL_REDO_FRAME_SECTORS: u64 = 1 + SECTORS_PER_PAGE as u64;
/// First LBA of the physical 4 KiB CoW page pool (`2194`).
pub const PAGE_POOL_BASE_LBA: u64 = CWAL_BASE_LBA + CWAL_TOTAL_SECTORS;

/// Sentinel physical slot value indicating an unallocated logical page (`0xFFFF`).
pub const UNMAPPED_PHYS_SLOT: u16 = 0xFFFF;

/// Superblock magic (`CTTLPGS1`).
pub const PAGED_SUPER_MAGIC: [u8; 8] = *b"CTTLPGS1";
/// Physical page header magic (`CTTLPGE1`).
pub const PAGED_PAGE_MAGIC: [u8; 8] = *b"CTTLPGE1";
/// `CWAL` redo journal header magic (`CTTLCWL1`).
pub const PAGED_CWAL_MAGIC: [u8; 8] = *b"CTTLCWL1";
/// `CWAL` redo frame descriptor magic (`CTTLFRM1`).
pub const PAGED_FRAME_MAGIC: [u8; 8] = *b"CTTLFRM1";
/// Cross-partition anchor magic embedded in `CTTLSHL1` / `CTTLSQL1` (`CTTLPGA1`).
pub const PAGED_ANCHOR_MAGIC: [u8; 8] = *b"CTTLPGA1";
/// Byte length of the HMAC-authenticated [`PagedAnchor`] block embedded in `CTTLSHL1` `[184..264]`.
pub const WAL_PAGED_ANCHOR_BYTES: usize = 80;

/// Superblock transaction state: physical home pages may still need `CWAL` roll-forward.
pub const PAGED_STATE_IN_FLIGHT: u8 = 1;
/// Superblock transaction state: all home pages and directory entries are durable and verified.
pub const PAGED_STATE_QUIESCENT: u8 = 2;

/// Logical subsystem domain owning a 4 KiB page.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PageDomain {
    /// Unallocated logical page slot.
    Free = 0,
    /// `SqlDb` table schemas, `tx_seq`, and B+Tree/page root catalog.
    SqlCatalog = 1,
    /// `SqlDb` 32-row fixed-slot relational/B+Tree leaf page.
    SqlLeaf = 2,
    /// VFS extended inode directory / long-path table page.
    VfsDir = 3,
    /// VFS file data extent page.
    VfsData = 4,
}

impl PageDomain {
    /// Parse a raw domain byte, returning `None` on unknown values.
    pub const fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Self::Free),
            1 => Some(Self::SqlCatalog),
            2 => Some(Self::SqlLeaf),
            3 => Some(Self::VfsDir),
            4 => Some(Self::VfsData),
            _ => None,
        }
    }
}

/// Compact cryptographic anchor binding [`PagedBlockStore`] into `AB_FORMAT_V3`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PagedAnchor {
    /// Monotonic transaction LSN committed in [`PagedBlockStore`].
    pub tx_lsn: u64,
    /// Binary SHA-256 Merkle root over all 256 logical page directory entries.
    pub merkle_root: [u8; DURABLE_DIGEST_LEN],
    /// Total committed SQL rows stored across SQL pages.
    pub sql_rows: u32,
    /// Total committed user VFS files stored across VFS pages.
    pub vfs_files: u32,
    /// Total committed user VFS payload bytes.
    pub vfs_bytes: u32,
}

impl PagedAnchor {
    /// Empty zero anchor (`tx_lsn == 0` means no paged store anchor is active).
    pub const fn zero() -> Self {
        Self {
            tx_lsn: 0,
            merkle_root: [0u8; DURABLE_DIGEST_LEN],
            sql_rows: 0,
            vfs_files: 0,
            vfs_bytes: 0,
        }
    }

    /// `true` when this anchor references a committed [`PagedBlockStore`] epoch.
    pub const fn is_active(&self) -> bool {
        self.tx_lsn > 0
    }
}

/// 16-byte directory entry for one logical 4 KiB page (`0..256`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PageDirEntry {
    /// Physical 4 KiB slot in `PAGE_POOL_BASE_LBA..` (`UNMAPPED_PHYS_SLOT` when unallocated).
    pub phys_slot: u16,
    /// Owning subsystem domain (`PageDomain::Free` when unallocated).
    pub domain: PageDomain,
    /// Page-specific flags (`payload_len` high metadata or subtype).
    pub flags: u8,
    /// Subsystem owner tag (e.g., `(table_idx << 16) | chunk_idx` or `inode_idx`).
    pub owner_id: u32,
    /// Exact `tx_lsn` under which this physical page was encrypted and sealed.
    pub page_lsn: u64,
}

impl PageDirEntry {
    /// Unmapped free directory entry.
    pub const fn empty() -> Self {
        Self {
            phys_slot: UNMAPPED_PHYS_SLOT,
            domain: PageDomain::Free,
            flags: 0,
            owner_id: 0,
            page_lsn: 0,
        }
    }

    /// `true` when this logical slot is currently mapped to a live physical page.
    pub const fn is_mapped(&self) -> bool {
        !matches!(self.domain, PageDomain::Free) && self.phys_slot != UNMAPPED_PHYS_SLOT
    }

    fn encode(&self, out: &mut [u8; 16]) {
        out[0..2].copy_from_slice(&self.phys_slot.to_le_bytes());
        out[2] = self.domain as u8;
        out[3] = self.flags;
        out[4..8].copy_from_slice(&self.owner_id.to_le_bytes());
        out[8..16].copy_from_slice(&self.page_lsn.to_le_bytes());
    }

    fn decode(raw: &[u8]) -> Option<Self> {
        if raw.len() < 16 {
            return None;
        }
        let phys_slot = u16::from_le_bytes([raw[0], raw[1]]);
        let domain = PageDomain::from_u8(raw[2])?;
        let flags = raw[3];
        let owner_id = u32::from_le_bytes([raw[4], raw[5], raw[6], raw[7]]);
        let page_lsn = u64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        if matches!(domain, PageDomain::Free) {
            if phys_slot != UNMAPPED_PHYS_SLOT || flags != 0 || owner_id != 0 || page_lsn != 0 {
                return None;
            }
        } else if phys_slot == UNMAPPED_PHYS_SLOT || page_lsn == 0 {
            return None;
        }
        Some(Self {
            phys_slot,
            domain,
            flags,
            owner_id,
            page_lsn,
        })
    }
}

/// Binary SHA-256 Merkle inclusion proof for a single logical page entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PageMerkleProof {
    /// Logical page index (`0..256` on v1, `0..1024` on v2).
    pub logical_id: u16,
    /// Directory entry proven by this path.
    pub entry: PageDirEntry,
    /// Active Merkle tree height (`8` for v1 `256`-slot directories, `10` for v2 `1,024`-slot directories).
    pub depth: u8,
    /// Sibling hashes from level 0 (leaf sibling) up to `depth - 1`.
    pub siblings: [[u8; DURABLE_DIGEST_LEN]; PAGED_V2_MERKLE_DEPTH],
}

/// Error returned by [`PagedBlockStore`] operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PagedStoreError {
    /// Device seal key is all zeros.
    KeyUnset,
    /// Attached block device is smaller than [`PAGED_STORE_MIN_DISK_SECTORS`] (`4096` sectors).
    DiskTooSmall,
    /// Underlying block device returned an I/O fault.
    Io(IoFault),
    /// Logical page ID is out of bounds (`>= max_logical_pages`).
    InvalidPageId,
    /// Caller supplied a payload larger than [`PAGED_PAGE_PAYLOAD_BYTES`] (`4032` bytes).
    PayloadTooLarge,
    /// Logical or physical page pool capacity is exhausted.
    OutOfPages,
    /// On-disk superblock, directory, `CWAL`, Merkle root, or page AEAD tag failed verification.
    CorruptOrTampered,
    /// Requested `PagedAnchor` was not found or its LSN/Merkle root was rolled back.
    RollbackOrAnchorMismatch,
    /// A page, directory or superblock the device accepted read back differently
    /// (a dropped or misdirected write). The epoch being written is not committed.
    VerifyFailed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PagedSuperblock {
    state: u8,
    slot_idx: u8,
    boots: u64,
    tx_lsn: u64,
    prev_tx_lsn: u64,
    allocated_pages: u16,
    cwal_redo_count: u16,
    sql_rows: u32,
    vfs_files: u32,
    vfs_bytes: u32,
    dir_sha256: [u8; DURABLE_DIGEST_LEN],
    cwal_sha256: [u8; DURABLE_DIGEST_LEN],
    merkle_root: [u8; DURABLE_DIGEST_LEN],
}

#[derive(Clone)]
struct CachedLogicalPage {
    allocated: bool,
    dirty: bool,
    domain: PageDomain,
    flags: u8,
    owner_id: u32,
    payload_len: u16,
    payload: Vec<u8>,
}

impl CachedLogicalPage {
    const fn empty() -> Self {
        Self {
            allocated: false,
            dirty: false,
            domain: PageDomain::Free,
            flags: 0,
            owner_id: 0,
            payload_len: 0,
            payload: Vec::new(),
        }
    }
}

/// Derive the domain-separated 256-bit `HMAC-SHA256` authentication key for `CTTLPGS1` metadata.
pub fn derive_paged_mac_key(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> [u8; DURABLE_DIGEST_LEN] {
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(seal_key, b"CTTLPGS1-MAC-KEY-v1", &mut out);
    out
}

/// Derive the domain-separated 256-bit `ChaCha20-Poly1305` encryption key for 4 KiB pages.
pub fn derive_paged_aead_key(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> [u8; DURABLE_DIGEST_LEN] {
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(seal_key, b"CTTLPGS1-AEAD-KEY-v1", &mut out);
    out
}

/// Derive the domain-separated 256-bit `HMAC-SHA256` key for content-bound page nonces.
pub fn derive_paged_nonce_key(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> [u8; DURABLE_DIGEST_LEN] {
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(seal_key, b"CTTLPGS1-NONCE-KEY-v1", &mut out);
    out
}

/// The keys the page store derives from the seal key. Wiped when dropped, so
/// every early return in commit and recovery clears them.
struct PagedKeys {
    mac: [u8; DURABLE_DIGEST_LEN],
    aead: [u8; DURABLE_DIGEST_LEN],
    nonce: [u8; DURABLE_DIGEST_LEN],
}

impl PagedKeys {
    fn derive(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> Self {
        Self {
            mac: derive_paged_mac_key(seal_key),
            aead: derive_paged_aead_key(seal_key),
            nonce: derive_paged_nonce_key(seal_key),
        }
    }
}

impl Drop for PagedKeys {
    fn drop(&mut self) {
        zeroize_secret_bytes(&mut self.mac);
        zeroize_secret_bytes(&mut self.aead);
        zeroize_secret_bytes(&mut self.nonce);
    }
}

fn sha256_of(data: &[u8]) -> [u8; DURABLE_DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(data);
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    out.copy_from_slice(&h.finalize());
    out
}

fn merkle_leaf_hash(logical_id: u16, entry: &PageDirEntry) -> [u8; DURABLE_DIGEST_LEN] {
    let mut raw_entry = [0u8; 16];
    entry.encode(&mut raw_entry);
    let mut h = Sha256::new();
    h.update(b"CTTLPGS1-LEAF-v1");
    h.update(logical_id.to_le_bytes());
    h.update(raw_entry);
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    out.copy_from_slice(&h.finalize());
    out
}

fn merkle_parent_hash(
    left: &[u8; DURABLE_DIGEST_LEN],
    right: &[u8; DURABLE_DIGEST_LEN],
) -> [u8; DURABLE_DIGEST_LEN] {
    let mut h = Sha256::new();
    h.update(b"CTTLPGS1-NODE-v1");
    h.update(left);
    h.update(right);
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    out.copy_from_slice(&h.finalize());
    out
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct PagedLayoutSpec {
    ver: u16,
    dir_sectors: usize,
    dir_slots: usize,
    max_phys_cap: usize,
    merkle_depth: u8,
    dir_a_lba: u64,
    dir_b_lba: u64,
    cwal_base_lba: u64,
    page_pool_base_lba: u64,
}

impl PagedLayoutSpec {
    const fn for_sectors(capacity_sectors: u64) -> Self {
        if capacity_sectors >= PAGED_V2_MIN_DISK_SECTORS {
            let dir_b_lba = DIR_A_LBA + PAGED_V2_DIR_SECTORS as u64;
            let cwal_base_lba = dir_b_lba + PAGED_V2_DIR_SECTORS as u64;
            let page_pool_base_lba = cwal_base_lba + CWAL_TOTAL_SECTORS;
            Self {
                ver: 2,
                dir_sectors: PAGED_V2_DIR_SECTORS,
                dir_slots: PAGED_V2_MAX_LOGICAL_PAGES,
                max_phys_cap: PAGED_V2_MAX_PHYS_PAGES,
                merkle_depth: PAGED_V2_MERKLE_DEPTH as u8,
                dir_a_lba: DIR_A_LBA,
                dir_b_lba,
                cwal_base_lba,
                page_pool_base_lba,
            }
        } else {
            Self {
                ver: 1,
                dir_sectors: SECTORS_PER_PAGE,
                dir_slots: PAGED_MAX_LOGICAL_PAGES,
                max_phys_cap: PAGED_MAX_PHYS_PAGES,
                merkle_depth: PAGED_MERKLE_DEPTH as u8,
                dir_a_lba: DIR_A_LBA,
                dir_b_lba: DIR_B_LBA,
                cwal_base_lba: CWAL_BASE_LBA,
                page_pool_base_lba: PAGE_POOL_BASE_LBA,
            }
        }
    }
}

/// Compute the 32-byte binary SHA-256 Merkle root over a power-of-two [`PageDirEntry`] slice (`256` or `1,024` slots).
pub fn compute_dir_merkle_root(entries: &[PageDirEntry]) -> [u8; DURABLE_DIGEST_LEN] {
    let n = entries.len();
    if n == 0 || !n.is_power_of_two() {
        return [0u8; DURABLE_DIGEST_LEN];
    }
    let mut level: Vec<[u8; DURABLE_DIGEST_LEN]> = Vec::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        level.push(merkle_leaf_hash(i as u16, &entries[i]));
        i += 1;
    }
    let mut width = n;
    while width > 1 {
        let mut p = 0usize;
        while p < width / 2 {
            level[p] = merkle_parent_hash(&level[2 * p], &level[2 * p + 1]);
            p += 1;
        }
        width /= 2;
    }
    level[0]
}

/// Construct a cryptographic Merkle inclusion proof for `logical_id` across `entries` (`256` or `1,024` slots).
pub fn build_dir_merkle_proof(
    entries: &[PageDirEntry],
    logical_id: u16,
) -> Option<PageMerkleProof> {
    let n = entries.len();
    if (n != PAGED_MAX_LOGICAL_PAGES && n != PAGED_V2_MAX_LOGICAL_PAGES) || !n.is_power_of_two() {
        return None;
    }
    let idx0 = logical_id as usize;
    if idx0 >= n {
        return None;
    }
    let target_depth = n.trailing_zeros() as usize;
    let mut level: Vec<[u8; DURABLE_DIGEST_LEN]> = Vec::with_capacity(n);
    let mut i = 0usize;
    while i < n {
        level.push(merkle_leaf_hash(i as u16, &entries[i]));
        i += 1;
    }
    let mut siblings = [[0u8; DURABLE_DIGEST_LEN]; PAGED_V2_MERKLE_DEPTH];
    let mut cur = idx0;
    let mut width = n;
    let mut depth = 0usize;
    while width > 1 && depth < target_depth {
        siblings[depth] = level[cur ^ 1];
        let mut p = 0usize;
        while p < width / 2 {
            level[p] = merkle_parent_hash(&level[2 * p], &level[2 * p + 1]);
            p += 1;
        }
        cur /= 2;
        width /= 2;
        depth += 1;
    }
    Some(PageMerkleProof {
        logical_id,
        entry: entries[idx0],
        depth: target_depth as u8,
        siblings,
    })
}

/// Verify a [`PageMerkleProof`] against an authenticated `expected_root` in constant time.
pub fn verify_dir_merkle_proof(
    proof: &PageMerkleProof,
    expected_root: &[u8; DURABLE_DIGEST_LEN],
) -> bool {
    let pdepth = proof.depth as usize;
    if pdepth != PAGED_MERKLE_DEPTH && pdepth != PAGED_V2_MERKLE_DEPTH {
        return false;
    }
    let n = 1usize << pdepth;
    if (proof.logical_id as usize) >= n {
        return false;
    }
    let mut acc = merkle_leaf_hash(proof.logical_id, &proof.entry);
    let mut idx = proof.logical_id as usize;
    let mut depth = 0usize;
    while depth < pdepth {
        if (idx & 1) == 0 {
            acc = merkle_parent_hash(&acc, &proof.siblings[depth]);
        } else {
            acc = merkle_parent_hash(&proof.siblings[depth], &acc);
        }
        idx >>= 1;
        depth += 1;
    }
    constant_time_eq(&acc, expected_root)
}

fn pack_superblock(
    mac_key: &[u8; DURABLE_DIGEST_LEN],
    layout: &PagedLayoutSpec,
    sb: &PagedSuperblock,
    out: &mut [u8; SECTOR_BYTES],
) {
    *out = [0u8; SECTOR_BYTES];
    out[0..8].copy_from_slice(&PAGED_SUPER_MAGIC);
    out[8..10].copy_from_slice(&layout.ver.to_le_bytes());
    out[10] = sb.state;
    out[11] = sb.slot_idx;
    out[12..14].copy_from_slice(&sb.allocated_pages.to_le_bytes());
    out[14..16].copy_from_slice(&sb.cwal_redo_count.to_le_bytes());
    out[16..24].copy_from_slice(&sb.boots.to_le_bytes());
    out[24..32].copy_from_slice(&sb.tx_lsn.to_le_bytes());
    out[32..40].copy_from_slice(&sb.prev_tx_lsn.to_le_bytes());
    out[40..44].copy_from_slice(&sb.sql_rows.to_le_bytes());
    out[44..48].copy_from_slice(&sb.vfs_files.to_le_bytes());
    out[48..52].copy_from_slice(&sb.vfs_bytes.to_le_bytes());
    if layout.ver == 2 {
        out[52..54].copy_from_slice(&(layout.dir_sectors as u16).to_le_bytes());
        out[54] = layout.merkle_depth;
        out[55] = 0;
    }
    out[56..88].copy_from_slice(&sb.dir_sha256);
    out[88..120].copy_from_slice(&sb.cwal_sha256);
    out[120..152].copy_from_slice(&sb.merkle_root);
    let mut tag = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(mac_key, &out[0..152], &mut tag);
    out[152..184].copy_from_slice(&tag);
}

fn verify_superblock(
    mac_key: &[u8; DURABLE_DIGEST_LEN],
    layout: &PagedLayoutSpec,
    expected_slot_idx: u8,
    sec: &[u8; SECTOR_BYTES],
) -> Option<PagedSuperblock> {
    if sec[0..8] != PAGED_SUPER_MAGIC {
        return None;
    }
    let ver = u16::from_le_bytes([sec[8], sec[9]]);
    if ver != layout.ver {
        return None;
    }
    let state = sec[10];
    if state != PAGED_STATE_IN_FLIGHT && state != PAGED_STATE_QUIESCENT {
        return None;
    }
    let slot_idx = sec[11];
    if slot_idx != expected_slot_idx {
        return None;
    }
    let mut expected_tag = [0u8; DURABLE_DIGEST_LEN];
    expected_tag.copy_from_slice(&sec[152..184]);
    if !seal_matches_keyed(mac_key, &sec[0..152], &expected_tag) {
        return None;
    }
    if ver == 1 {
        if sec[52..56] != [0u8; 4] {
            return None;
        }
    } else {
        let ds = u16::from_le_bytes([sec[52], sec[53]]) as usize;
        if ds != layout.dir_sectors || sec[54] != layout.merkle_depth || sec[55] != 0 {
            return None;
        }
    }
    let allocated_pages = u16::from_le_bytes([sec[12], sec[13]]);
    let cwal_redo_count = u16::from_le_bytes([sec[14], sec[15]]);
    if (allocated_pages as usize) > layout.dir_slots
        || (cwal_redo_count as usize) > CWAL_MAX_REDO_PAGES
    {
        return None;
    }
    let boots = u64::from_le_bytes([
        sec[16], sec[17], sec[18], sec[19], sec[20], sec[21], sec[22], sec[23],
    ]);
    let tx_lsn = u64::from_le_bytes([
        sec[24], sec[25], sec[26], sec[27], sec[28], sec[29], sec[30], sec[31],
    ]);
    let prev_tx_lsn = u64::from_le_bytes([
        sec[32], sec[33], sec[34], sec[35], sec[36], sec[37], sec[38], sec[39],
    ]);
    if tx_lsn == 0 || prev_tx_lsn >= tx_lsn {
        return None;
    }
    let sql_rows = u32::from_le_bytes([sec[40], sec[41], sec[42], sec[43]]);
    let vfs_files = u32::from_le_bytes([sec[44], sec[45], sec[46], sec[47]]);
    let vfs_bytes = u32::from_le_bytes([sec[48], sec[49], sec[50], sec[51]]);
    let mut dir_sha256 = [0u8; DURABLE_DIGEST_LEN];
    let mut cwal_sha256 = [0u8; DURABLE_DIGEST_LEN];
    let mut merkle_root = [0u8; DURABLE_DIGEST_LEN];
    dir_sha256.copy_from_slice(&sec[56..88]);
    cwal_sha256.copy_from_slice(&sec[88..120]);
    merkle_root.copy_from_slice(&sec[120..152]);
    Some(PagedSuperblock {
        state,
        slot_idx,
        boots,
        tx_lsn,
        prev_tx_lsn,
        allocated_pages,
        cwal_redo_count,
        sql_rows,
        vfs_files,
        vfs_bytes,
        dir_sha256,
        cwal_sha256,
        merkle_root,
    })
}

/// The 96-bit nonce one page image is sealed under:
/// `HMAC-SHA256(nonce_key, "CTTLPGE1-NONCE-v2:" || header[0..28] || SHA-256(plaintext))[0..12]`.
///
/// `header[0..28]` is the page's authenticated header (domain, flags, logical id,
/// physical slot, payload length, owner, LSN) and `plaintext` is the whole
/// zero-padded 4,032-byte payload area. Because the nonce depends on every
/// byte that is encrypted, the same nonce means the same page image and so the
/// same ciphertext: writing different contents to a physical slot under an LSN
/// that was already used there cannot repeat a (key, nonce) pair. Encryption
/// stays deterministic, which commit and recovery rely on (the redo frame and
/// the home page of a commit are byte-identical).
///
/// Pages written before this derivation carry `(page_lsn, phys_slot, domain, 0xA5)`
/// in the same header field and are still read: decryption uses the stored nonce,
/// which the Poly1305 tag authenticates.
fn page_nonce(
    nonce_key: &[u8; DURABLE_DIGEST_LEN],
    header28: &[u8],
    plaintext: &[u8],
) -> [u8; AEAD_NONCE_LEN] {
    const LABEL: &[u8; 18] = b"CTTLPGE1-NONCE-v2:";
    let mut msg = [0u8; 18 + 28 + DURABLE_DIGEST_LEN];
    msg[0..18].copy_from_slice(LABEL);
    msg[18..46].copy_from_slice(&header28[0..28]);
    msg[46..78].copy_from_slice(&sha256_of(plaintext));
    let mut mac = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(nonce_key, &msg, &mut mac);
    let mut n = [0u8; AEAD_NONCE_LEN];
    n.copy_from_slice(&mac[0..AEAD_NONCE_LEN]);
    n
}

fn encrypt_page_sectors(
    keys: &PagedKeys,
    logical_id: u16,
    phys_slot: u16,
    domain: PageDomain,
    flags: u8,
    owner_id: u32,
    page_lsn: u64,
    payload: &[u8],
    out_sectors: &mut [[u8; SECTOR_BYTES]; SECTORS_PER_PAGE],
) -> Result<(), PagedStoreError> {
    if payload.len() > PAGED_PAGE_PAYLOAD_BYTES {
        return Err(PagedStoreError::PayloadTooLarge);
    }
    let flat = out_sectors.as_flattened_mut();
    flat.fill(0);
    flat[0..8].copy_from_slice(&PAGED_PAGE_MAGIC);
    flat[8] = domain as u8;
    flat[9] = flags;
    flat[10..12].copy_from_slice(&logical_id.to_le_bytes());
    flat[12..14].copy_from_slice(&phys_slot.to_le_bytes());
    flat[14..16].copy_from_slice(&(payload.len() as u16).to_le_bytes());
    flat[16..20].copy_from_slice(&owner_id.to_le_bytes());
    flat[20..28].copy_from_slice(&page_lsn.to_le_bytes());

    let mut aad = [0u8; 28];
    aad.copy_from_slice(&flat[0..28]);
    flat[PAGED_PAGE_HEADER_BYTES..PAGED_PAGE_HEADER_BYTES + payload.len()].copy_from_slice(payload);
    let nonce = page_nonce(&keys.nonce, &aad, &flat[PAGED_PAGE_HEADER_BYTES..]);
    flat[28..40].copy_from_slice(&nonce);
    let tag = chacha20_poly1305_encrypt_in_place(
        &keys.aead,
        &nonce,
        &aad,
        &mut flat[PAGED_PAGE_HEADER_BYTES..],
    );
    flat[40..56].copy_from_slice(&tag);
    Ok(())
}

fn decrypt_page_sectors(
    aead_key: &[u8; DURABLE_DIGEST_LEN],
    expected_logical_id: u16,
    expected_entry: &PageDirEntry,
    sectors: &mut [[u8; SECTOR_BYTES]; SECTORS_PER_PAGE],
) -> Option<usize> {
    let flat = sectors.as_flattened_mut();
    if flat[0..8] != PAGED_PAGE_MAGIC {
        return None;
    }
    let domain = PageDomain::from_u8(flat[8])?;
    let flags = flat[9];
    let logical_id = u16::from_le_bytes([flat[10], flat[11]]);
    let phys_slot = u16::from_le_bytes([flat[12], flat[13]]);
    let payload_len = u16::from_le_bytes([flat[14], flat[15]]) as usize;
    let owner_id = u32::from_le_bytes([flat[16], flat[17], flat[18], flat[19]]);
    let page_lsn = u64::from_le_bytes([
        flat[20], flat[21], flat[22], flat[23], flat[24], flat[25], flat[26], flat[27],
    ]);
    if logical_id != expected_logical_id
        || domain != expected_entry.domain
        || flags != expected_entry.flags
        || phys_slot != expected_entry.phys_slot
        || owner_id != expected_entry.owner_id
        || page_lsn != expected_entry.page_lsn
        || payload_len > PAGED_PAGE_PAYLOAD_BYTES
    {
        return None;
    }
    if !flat[56..64].iter().all(|&b| b == 0) {
        return None;
    }
    // The stored nonce is not trusted for anything but decryption: a page
    // sealed under any other nonce fails the Poly1305 check below.
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce.copy_from_slice(&flat[28..40]);
    let mut tag = [0u8; AEAD_TAG_LEN];
    tag.copy_from_slice(&flat[40..56]);
    let mut aad = [0u8; 28];
    aad.copy_from_slice(&flat[0..28]);
    if !chacha20_poly1305_decrypt_in_place(
        aead_key,
        &nonce,
        &aad,
        &mut flat[PAGED_PAGE_HEADER_BYTES..],
        &tag,
    ) {
        return None;
    }
    Some(payload_len)
}

fn encode_dir_sectors(
    entries: &[PageDirEntry],
    out: &mut [[u8; SECTOR_BYTES]],
) -> [u8; DURABLE_DIGEST_LEN] {
    let flat = out.as_flattened_mut();
    flat.fill(0);
    let mut i = 0usize;
    while i < entries.len() {
        let mut raw = [0u8; 16];
        entries[i].encode(&mut raw);
        flat[i * 16..(i + 1) * 16].copy_from_slice(&raw);
        i += 1;
    }
    let mut h = Sha256::new();
    h.update(&flat[..]);
    let mut dig = [0u8; DURABLE_DIGEST_LEN];
    dig.copy_from_slice(&h.finalize());
    dig
}

fn decode_dir_sectors(
    sectors: &[[u8; SECTOR_BYTES]],
    layout: &PagedLayoutSpec,
    expected_sha256: &[u8; DURABLE_DIGEST_LEN],
    expected_merkle: &[u8; DURABLE_DIGEST_LEN],
    avail_phys: usize,
) -> Option<Vec<PageDirEntry>> {
    if sectors.len() != layout.dir_sectors {
        return None;
    }
    let flat = sectors.as_flattened();
    let mut h = Sha256::new();
    h.update(flat);
    let mut actual_sha = [0u8; DURABLE_DIGEST_LEN];
    actual_sha.copy_from_slice(&h.finalize());
    if !constant_time_eq(&actual_sha, expected_sha256) {
        return None;
    }
    let mut entries = alloc::vec![PageDirEntry::empty(); layout.dir_slots];
    let mut seen_phys = [0u64; 32]; // 2,048 bits
    let mut i = 0usize;
    while i < layout.dir_slots {
        let e = PageDirEntry::decode(&flat[i * 16..(i + 1) * 16])?;
        if e.is_mapped() {
            let p = e.phys_slot as usize;
            if p >= avail_phys || p >= layout.max_phys_cap {
                return None;
            }
            let w = p / 64;
            let b = 1u64 << (p % 64);
            // Reject corrupted directories that alias two logical pages onto one physical slot.
            if (seen_phys[w] & b) != 0 {
                return None;
            }
            seen_phys[w] |= b;
        }
        entries[i] = e;
        i += 1;
    }
    let root = compute_dir_merkle_root(&entries);
    if !constant_time_eq(&root, expected_merkle) {
        return None;
    }
    Some(entries)
}

/// Encode an 80-byte authenticated [`PagedAnchor`] into `CTTLSHL1` header bytes `[184..264]`.
pub fn pack_wal_paged_anchor(
    seal_key: &[u8; DURABLE_DIGEST_LEN],
    hdr_prefix_84: &[u8],
    anchor: &PagedAnchor,
    out_80: &mut [u8; 80],
) {
    *out_80 = [0u8; 80];
    if !anchor.is_active() || hdr_prefix_84.len() < 84 {
        return;
    }
    out_80[0..8].copy_from_slice(&PAGED_ANCHOR_MAGIC);
    out_80[8..16].copy_from_slice(&anchor.tx_lsn.to_le_bytes());
    out_80[16..48].copy_from_slice(&anchor.merkle_root);
    let mut msg = [0u8; 16 + 84 + 48];
    msg[0..16].copy_from_slice(b"CTTLPGA1-HDR-v1:");
    msg[16..100].copy_from_slice(&hdr_prefix_84[0..84]);
    msg[100..148].copy_from_slice(&out_80[0..48]);
    let mut tag = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(seal_key, &msg, &mut tag);
    out_80[48..80].copy_from_slice(&tag);
}

/// Verify and decode an optional 80-byte [`PagedAnchor`] from `CTTLSHL1` header bytes `[184..264]`.
///
/// Returns `Ok(None)` when `[184..264]` is all zeros (unanchored legacy image), `Ok(Some(anchor))`
/// when valid, or `Err(())` if any byte is non-zero and fails authentication.
pub fn unpack_wal_paged_anchor(
    seal_key: &[u8; DURABLE_DIGEST_LEN],
    hdr_prefix_84: &[u8],
    raw_80: &[u8; 80],
) -> Result<Option<PagedAnchor>, ()> {
    if raw_80.iter().all(|&b| b == 0) {
        return Ok(None);
    }
    if !is_seal_key_set(seal_key) || hdr_prefix_84.len() < 84 || raw_80[0..8] != PAGED_ANCHOR_MAGIC {
        return Err(());
    }
    let tx_lsn = u64::from_le_bytes([
        raw_80[8], raw_80[9], raw_80[10], raw_80[11], raw_80[12], raw_80[13], raw_80[14],
        raw_80[15],
    ]);
    if tx_lsn == 0 {
        return Err(());
    }
    let mut msg = [0u8; 16 + 84 + 48];
    msg[0..16].copy_from_slice(b"CTTLPGA1-HDR-v1:");
    msg[16..100].copy_from_slice(&hdr_prefix_84[0..84]);
    msg[100..148].copy_from_slice(&raw_80[0..48]);
    let mut expected_tag = [0u8; DURABLE_DIGEST_LEN];
    expected_tag.copy_from_slice(&raw_80[48..80]);
    if !seal_matches_keyed(seal_key, &msg, &expected_tag) {
        return Err(());
    }
    let mut merkle_root = [0u8; DURABLE_DIGEST_LEN];
    merkle_root.copy_from_slice(&raw_80[16..48]);
    Ok(Some(PagedAnchor {
        tx_lsn,
        merkle_root,
        sql_rows: 0,
        vfs_files: 0,
        vfs_bytes: 0,
    }))
}

/// Page-granular encrypted Copy-on-Write + `CWAL` block storage engine.
pub struct PagedBlockStore {
    initialized: bool,
    active_slot: u8,
    tx_lsn: u64,
    boots: u64,
    sql_rows: u32,
    vfs_files: u32,
    vfs_bytes: u32,
    last_dirty_pages_written: usize,
    /// Highest LSN any page may already have been sealed under: by this
    /// instance (including commits that failed part-way) or, as far as the
    /// device shows, by an earlier one. See [`Self::lsn_floor`].
    lsn_floor: u64,
    /// Home pages the last recovery rewrote from the redo journal.
    last_recovery_healed: usize,
    /// Whether the last recovery completed an interrupted (`IN_FLIGHT`) commit.
    last_recovery_rolled_forward: bool,
    /// Whether a standalone `recover_latest` call fell back to an older superblock epoch.
    last_recovery_fell_back_epoch: bool,
    dir_slots: usize,
    merkle_root: [u8; DURABLE_DIGEST_LEN],
    dir: Vec<PageDirEntry>,
    pages: Vec<CachedLogicalPage>,
}

impl Default for PagedBlockStore {
    fn default() -> Self {
        Self::new()
    }
}

impl PagedBlockStore {
    /// Construct an empty unmounted [`PagedBlockStore`] (`const fn`, zero heap allocations).
    pub const fn new() -> Self {
        Self {
            initialized: false,
            active_slot: 0,
            tx_lsn: 0,
            boots: 0,
            sql_rows: 0,
            vfs_files: 0,
            vfs_bytes: 0,
            last_dirty_pages_written: 0,
            lsn_floor: 0,
            last_recovery_healed: 0,
            last_recovery_rolled_forward: false,
            last_recovery_fell_back_epoch: false,
            dir_slots: 0,
            merkle_root: [0u8; DURABLE_DIGEST_LEN],
            dir: Vec::new(),
            pages: Vec::new(),
        }
    }

    /// Clear all in-memory cached state.
    ///
    /// [`Self::lsn_floor`] is kept: forgetting which LSNs were used is the one
    /// thing a reset must not do.
    pub fn reset(&mut self) {
        self.last_recovery_healed = 0;
        self.last_recovery_rolled_forward = false;
        self.last_recovery_fell_back_epoch = false;
        self.initialized = false;
        self.active_slot = 0;
        self.tx_lsn = 0;
        self.boots = 0;
        self.sql_rows = 0;
        self.vfs_files = 0;
        self.vfs_bytes = 0;
        self.last_dirty_pages_written = 0;
        self.dir_slots = 0;
        self.merkle_root = [0u8; DURABLE_DIGEST_LEN];
        self.dir.clear();
        self.pages.clear();
    }

    /// `true` if `capacity_sectors` is large enough to host [`PagedBlockStore`].
    pub const fn supports_disk_capacity(capacity_sectors: u64) -> bool {
        capacity_sectors >= PAGED_STORE_MIN_DISK_SECTORS
    }

    /// Compute `(avail_phys_pages, max_logical_pages)` for `capacity_sectors`.
    pub const fn geometry_for_sectors(capacity_sectors: u64) -> (usize, usize) {
        if capacity_sectors < PAGED_STORE_MIN_DISK_SECTORS {
            return (0, 0);
        }
        let layout = PagedLayoutSpec::for_sectors(capacity_sectors);
        if capacity_sectors <= layout.page_pool_base_lba {
            return (0, 0);
        }
        let raw_phys =
            ((capacity_sectors - layout.page_pool_base_lba) / SECTORS_PER_PAGE as u64) as usize;
        let avail_phys = if raw_phys > layout.max_phys_cap {
            layout.max_phys_cap
        } else {
            raw_phys
        };
        let half = avail_phys / 2;
        let max_logical = if half > layout.dir_slots {
            layout.dir_slots
        } else {
            half
        };
        (avail_phys, max_logical)
    }

    fn ensure_tables_for(&mut self, min_slots: usize) {
        let target = min_slots.max(PAGED_MAX_LOGICAL_PAGES);
        if self.dir.len() < target {
            self.dir.resize(target, PageDirEntry::empty());
        }
        if self.pages.len() < target {
            self.pages.resize_with(target, CachedLogicalPage::empty);
        }
    }

    /// Latest committed transaction LSN (`0` before the first commit).
    pub const fn tx_lsn(&self) -> u64 {
        self.tx_lsn
    }

    /// Latest committed 32-byte Merkle root over the 256-slot page directory.
    pub const fn merkle_root(&self) -> [u8; DURABLE_DIGEST_LEN] {
        self.merkle_root
    }

    /// Number of dirty 4 KiB logical pages written during the most recent [`Self::commit_dirty`] call.
    pub const fn last_dirty_pages_written(&self) -> usize {
        self.last_dirty_pages_written
    }

    /// The highest LSN that may already have been used to seal a page.
    ///
    /// The next commit takes an LSN above both this and [`Self::tx_lsn`], so an
    /// LSN is used for at most one epoch. Without that, an epoch that was
    /// written and then abandoned (the anchoring `AB_FORMAT_V3` commit did not
    /// happen, or the commit failed part-way) would share its LSN with the
    /// epoch that replaces it, and a page of the abandoned epoch left behind
    /// by a lost write would pass every check of the new one: the directory
    /// binds a page by slot and LSN, not by content.
    ///
    /// The floor rises when a commit starts writing, and at recovery to the
    /// highest LSN in either authenticated superblock or in an authenticated
    /// redo-journal header (a bulk commit records its LSN there, durably,
    /// before its first page is written).
    pub const fn lsn_floor(&self) -> u64 {
        self.lsn_floor
    }

    /// Home pages the most recent recovery found damaged and rewrote from the
    /// redo journal. Non-zero means sectors changed outside a commit.
    pub const fn last_recovery_healed(&self) -> usize {
        self.last_recovery_healed
    }

    /// Whether the most recent recovery completed a commit that a power cut
    /// had interrupted after its redo journal was durable.
    pub const fn last_recovery_rolled_forward(&self) -> bool {
        self.last_recovery_rolled_forward
    }

    /// Whether a standalone [`Self::recover_latest`] call fell back to an older
    /// superblock epoch because a newer epoch recorded on the device was damaged.
    pub const fn last_recovery_fell_back_epoch(&self) -> bool {
        self.last_recovery_fell_back_epoch
    }

    /// Current [`PagedAnchor`] snapshot.
    pub const fn anchor(&self) -> PagedAnchor {
        PagedAnchor {
            tx_lsn: self.tx_lsn,
            merkle_root: self.merkle_root,
            sql_rows: self.sql_rows,
            vfs_files: self.vfs_files,
            vfs_bytes: self.vfs_bytes,
        }
    }

    /// Update summary counters stored in the superblock.
    pub fn set_summary_counts(&mut self, sql_rows: u32, vfs_files: u32, vfs_bytes: u32) {
        self.sql_rows = sql_rows;
        self.vfs_files = vfs_files;
        self.vfs_bytes = vfs_bytes;
    }

    /// Count currently allocated logical 4 KiB pages.
    pub fn allocated_page_count(&self) -> usize {
        self.pages.iter().filter(|p| p.allocated).count()
    }

    /// Count logical 4 KiB pages currently marked dirty (pending write on next [`Self::commit_dirty`]).
    pub fn dirty_page_count(&self) -> usize {
        self.pages.iter().filter(|p| p.dirty).count()
    }

    /// Configure this store's active directory slot ceiling (`256` for v1 `< 16,384` sectors,
    /// `1024` for v2 `>= 16,384` sectors) for a target block device of `capacity_sectors`.
    pub fn configure_for_sectors(&mut self, capacity_sectors: u64) {
        if capacity_sectors >= PAGED_STORE_MIN_DISK_SECTORS {
            self.dir_slots = PagedLayoutSpec::for_sectors(capacity_sectors).dir_slots;
        }
    }

    /// Ensure this store's active directory ceiling accommodates `max_logical` logical pages.
    pub fn configure_max_logical(&mut self, max_logical: usize) {
        if max_logical > PAGED_MAX_LOGICAL_PAGES && self.dir_slots < PAGED_V2_MAX_LOGICAL_PAGES {
            self.dir_slots = PAGED_V2_MAX_LOGICAL_PAGES;
        }
    }

    fn active_logical_slot_cap(&self) -> usize {
        if self.dir_slots > PAGED_MAX_LOGICAL_PAGES {
            PAGED_V2_MAX_LOGICAL_PAGES
        } else {
            PAGED_MAX_LOGICAL_PAGES
        }
    }

    /// Stage or update a logical 4 KiB page (`0..PAGED_MAX_LOGICAL_PAGES` in v1, `0..PAGED_V2_MAX_LOGICAL_PAGES` in v2) in memory.
    ///
    /// If the page is already allocated with byte-identical `(domain, flags, owner_id, payload)`,
    /// it is **not** marked dirty, avoiding redundant disk writes.
    pub fn put_page(
        &mut self,
        logical_id: u16,
        domain: PageDomain,
        flags: u8,
        owner_id: u32,
        payload: &[u8],
    ) -> Result<(), PagedStoreError> {
        let idx = logical_id as usize;
        let active_cap = self.active_logical_slot_cap();
        if idx >= active_cap || matches!(domain, PageDomain::Free) {
            return Err(PagedStoreError::InvalidPageId);
        }
        if payload.len() > PAGED_PAGE_PAYLOAD_BYTES {
            return Err(PagedStoreError::PayloadTooLarge);
        }
        self.ensure_tables_for(active_cap);
        let slot = &mut self.pages[idx];
        if slot.allocated
            && slot.domain == domain
            && slot.flags == flags
            && slot.owner_id == owner_id
            && slot.payload_len as usize == payload.len()
            && slot.payload.as_slice() == payload
        {
            return Ok(());
        }
        slot.allocated = true;
        slot.dirty = true;
        slot.domain = domain;
        slot.flags = flags;
        slot.owner_id = owner_id;
        slot.payload_len = payload.len() as u16;
        slot.payload.clear();
        slot.payload.extend_from_slice(payload);
        Ok(())
    }

    /// Free an allocated logical 4 KiB page so its physical slot is reclaimed on commit.
    pub fn free_page(&mut self, logical_id: u16) -> Result<(), PagedStoreError> {
        let idx = logical_id as usize;
        let active_cap = self.active_logical_slot_cap();
        if idx >= active_cap {
            return Err(PagedStoreError::InvalidPageId);
        }
        self.ensure_tables_for(active_cap);
        let slot = &mut self.pages[idx];
        if !slot.allocated {
            return Ok(());
        }
        zeroize_secret_bytes(&mut slot.payload);
        slot.payload.clear();
        slot.payload_len = 0;
        slot.allocated = false;
        slot.domain = PageDomain::Free;
        slot.flags = 0;
        slot.owner_id = 0;
        slot.dirty = true;
        Ok(())
    }

    /// Borrow a cached logical page's `(domain, flags, owner_id, payload)` slice.
    pub fn get_page(&self, logical_id: u16) -> Option<(PageDomain, u8, u32, &[u8])> {
        let slot = self.pages.get(logical_id as usize)?;
        if !slot.allocated {
            return None;
        }
        Some((
            slot.domain,
            slot.flags,
            slot.owner_id,
            &slot.payload[..slot.payload_len as usize],
        ))
    }

    /// Find the logical page ID matching `(domain, owner_id)`, if any.
    pub fn find_page(&self, domain: PageDomain, owner_id: u32) -> Option<u16> {
        let mut i = 0usize;
        while i < self.pages.len() {
            let p = &self.pages[i];
            if p.allocated && p.domain == domain && p.owner_id == owner_id {
                return Some(i as u16);
            }
            i += 1;
        }
        None
    }

    /// Maximum logical 4 KiB pages addressable on a device of `capacity_sectors`.
    pub const fn max_logical_pages_for_sectors(capacity_sectors: u64) -> usize {
        Self::geometry_for_sectors(capacity_sectors).1
    }

    /// Count currently allocated logical pages belonging to `domain`.
    pub fn count_domain_pages(&self, domain: PageDomain) -> usize {
        self.pages
            .iter()
            .filter(|p| p.allocated && p.domain == domain)
            .count()
    }

    /// Stage or update the unique logical page identified by `(domain, owner_id)`,
    /// allocating a fresh logical ID within `0..max_logical` when needed.
    pub fn upsert_owned_page(
        &mut self,
        domain: PageDomain,
        owner_id: u32,
        payload: &[u8],
        max_logical: usize,
    ) -> Result<u16, PagedStoreError> {
        if max_logical > PAGED_MAX_LOGICAL_PAGES && self.dir_slots < PAGED_V2_MAX_LOGICAL_PAGES {
            self.dir_slots = PAGED_V2_MAX_LOGICAL_PAGES;
        }
        let lid = match self.find_page(domain, owner_id) {
            Some(id) => id,
            None => self
                .alloc_logical_id(max_logical)
                .ok_or(PagedStoreError::OutOfPages)?,
        };
        self.put_page(lid, domain, 0, owner_id, payload)?;
        Ok(lid)
    }

    /// Remove and zeroize the logical page identified by `(domain, owner_id)`, if present.
    pub fn remove_owned_page(
        &mut self,
        domain: PageDomain,
        owner_id: u32,
    ) -> Result<bool, PagedStoreError> {
        let Some(lid) = self.find_page(domain, owner_id) else {
            return Ok(false);
        };
        self.free_page(lid)?;
        Ok(true)
    }

    /// Copy the cached payload of `(domain, owner_id)` into `out`, returning `Ok(Some(payload_len))`
    /// when present or `Ok(None)` when absent.
    pub fn read_owned_page(
        &self,
        domain: PageDomain,
        owner_id: u32,
        out: &mut [u8],
    ) -> Result<Option<usize>, PagedStoreError> {
        let Some(lid) = self.find_page(domain, owner_id) else {
            return Ok(None);
        };
        let Some((_, _, _, data)) = self.get_page(lid) else {
            return Ok(None);
        };
        if out.len() < data.len() {
            return Err(PagedStoreError::PayloadTooLarge);
        }
        out[..data.len()].copy_from_slice(data);
        Ok(Some(data.len()))
    }

    /// Allocate the lowest free logical page ID within `0..max_logical`.
    pub fn alloc_logical_id(&self, max_logical: usize) -> Option<u16> {
        let cap = max_logical.min(PAGED_V2_MAX_LOGICAL_PAGES);
        let mut i = 0usize;
        while i < cap {
            let used = self.pages.get(i).map(|p| p.allocated).unwrap_or(false);
            if !used {
                return Some(i as u16);
            }
            i += 1;
        }
        None
    }

    /// The committed directory entry of `logical_id`: where its page lives and
    /// under which LSN it was sealed. `None` before the first commit or
    /// recovery, or when `logical_id` is out of range.
    pub fn dir_entry(&self, logical_id: u16) -> Option<PageDirEntry> {
        let bound = if self.dir_slots > 0 {
            self.dir_slots
        } else {
            self.dir.len()
        };
        if (logical_id as usize) >= bound {
            return None;
        }
        self.dir.get(logical_id as usize).copied()
    }

    /// Construct a Merkle inclusion proof for `logical_id` from the current committed directory.
    pub fn merkle_proof(&self, logical_id: u16) -> Option<PageMerkleProof> {
        let slots = if self.dir_slots > 0 {
            self.dir_slots
        } else {
            return None;
        };
        if self.dir.len() < slots {
            return None;
        }
        build_dir_merkle_proof(&self.dir[..slots], logical_id)
    }

    /// Incrementally commit only dirty 4 KiB pages to `dev` using Dual-Epoch Copy-on-Write
    /// and physical `CWAL` redo logging.
    ///
    /// - Writes `0` sectors when no pages are dirty and the store is already initialized.
    /// - Writes `O(dirty pages)` sectors when a subset of pages changed.
    pub fn commit_dirty<D: SectorIo>(
        &mut self,
        dev: &mut D,
        seal_key: &[u8; DURABLE_DIGEST_LEN],
        boots: u64,
    ) -> Result<PagedAnchor, PagedStoreError> {
        if !is_seal_key_set(seal_key) {
            return Err(PagedStoreError::KeyUnset);
        }
        let cap_secs = dev.capacity_sectors();
        let (avail_phys, max_logical) = Self::geometry_for_sectors(cap_secs);
        if max_logical == 0 {
            return Err(PagedStoreError::DiskTooSmall);
        }
        let layout = PagedLayoutSpec::for_sectors(cap_secs);
        self.ensure_tables_for(layout.dir_slots);

        let mut dirty_allocated = Vec::new();
        let mut any_dirty = false;
        let mut allocated_total = 0u16;
        let scan_len = self.pages.len().max(layout.dir_slots);
        let mut i = 0usize;
        while i < scan_len {
            if let Some(p) = self.pages.get(i) {
                if p.allocated {
                    if i >= max_logical {
                        return Err(PagedStoreError::OutOfPages);
                    }
                    allocated_total += 1;
                }
                if p.dirty {
                    any_dirty = true;
                    if p.allocated {
                        dirty_allocated.push(i as u16);
                    }
                }
            }
            i += 1;
        }

        if !any_dirty && self.initialized && self.tx_lsn > 0 {
            self.last_dirty_pages_written = 0;
            return Ok(self.anchor());
        }

        let keys = PagedKeys::derive(seal_key);

        // An unmounted store is about to write its first epoch over whatever
        // the region holds. Learn which LSNs that region already used.
        if !self.initialized {
            self.observe_lsn_floor(dev, &layout, &keys);
        }
        let prev_lsn = self.tx_lsn;
        let next_lsn = prev_lsn
            .max(self.lsn_floor)
            .checked_add(1)
            .ok_or(PagedStoreError::OutOfPages)?;
        let target_slot: u8 = if !self.initialized {
            0
        } else {
            self.active_slot ^ 1
        };

        // Build physical-slot exclusion bitmap: reserve every physical slot held by `self.dir`
        // (previous committed epoch `S0`) AND every physical slot retained by clean pages in `S1`,
        // so staging `S1` NEVER overwrites any physical page of `S0`!
        let mut reserved_phys = [0u64; 32]; // 2,048 bits
        let mut new_dir = alloc::vec![PageDirEntry::empty(); layout.dir_slots];
        let mut l = 0usize;
        while l < layout.dir_slots {
            let old_e = self.dir[l];
            if old_e.is_mapped() {
                let ps = old_e.phys_slot as usize;
                if ps < layout.max_phys_cap {
                    reserved_phys[ps / 64] |= 1u64 << (ps % 64);
                }
            }
            if self.pages[l].allocated && !self.pages[l].dirty {
                new_dir[l] = old_e;
            }
            l += 1;
        }

        // Assign fresh CoW physical slots for all dirty allocated logical pages.
        let mut next_phys_scan = 0usize;
        for &lid in &dirty_allocated {
            let mut chosen: Option<u16> = None;
            while next_phys_scan < avail_phys {
                let w = next_phys_scan / 64;
                let b = 1u64 << (next_phys_scan % 64);
                if (reserved_phys[w] & b) == 0 {
                    reserved_phys[w] |= b;
                    chosen = Some(next_phys_scan as u16);
                    next_phys_scan += 1;
                    break;
                }
                next_phys_scan += 1;
            }
            let phys_slot = chosen.ok_or(PagedStoreError::OutOfPages)?;
            let p = &self.pages[lid as usize];
            new_dir[lid as usize] = PageDirEntry {
                phys_slot,
                domain: p.domain,
                flags: p.flags,
                owner_id: p.owner_id,
                page_lsn: next_lsn,
            };
        }

        let mut dir_secs = alloc::vec![[0u8; SECTOR_BYTES]; layout.dir_sectors];
        let dir_sha256 = encode_dir_sectors(&new_dir, &mut dir_secs);
        let merkle_root = compute_dir_merkle_root(&new_dir);

        let mut page_buf = Box::new([[0u8; SECTOR_BYTES]; SECTORS_PER_PAGE]);
        let mut sb_sec = [0u8; SECTOR_BYTES];
        // SHA-256 of each dirty page as written, for the read-back check below.
        let mut page_digests: Vec<[u8; DURABLE_DIGEST_LEN]> =
            Vec::with_capacity(dirty_allocated.len());

        let use_cwal_redo = dirty_allocated.len() <= CWAL_MAX_REDO_PAGES;
        let cwal_redo_count = if use_cwal_redo {
            dirty_allocated.len() as u16
        } else {
            0u16
        };

        let dir_lba = if target_slot == 0 {
            layout.dir_a_lba
        } else {
            layout.dir_b_lba
        };
        let sb_lba = if target_slot == 0 {
            SUPERBLOCK_A_LBA
        } else {
            SUPERBLOCK_B_LBA
        };
        let home_lba = |entry: &PageDirEntry| -> u64 {
            layout.page_pool_base_lba + (entry.phys_slot as u64) * (SECTORS_PER_PAGE as u64)
        };
        let io = PagedStoreError::Io;

        let mut cwal_hasher = Sha256::new();
        let mut cwal_hdr = [0u8; SECTOR_BYTES];
        cwal_hdr[0..8].copy_from_slice(&PAGED_CWAL_MAGIC);
        cwal_hdr[8..16].copy_from_slice(&next_lsn.to_le_bytes());
        cwal_hdr[16..18].copy_from_slice(&cwal_redo_count.to_le_bytes());
        cwal_hdr[18..20].copy_from_slice(&(dirty_allocated.len() as u16).to_le_bytes());
        cwal_hasher.update(&cwal_hdr[0..20]);

        // Pages sealed under `next_lsn` reach the device from here on. Whatever
        // happens next, that LSN is spent: a later attempt takes a higher one.
        self.lsn_floor = next_lsn;

        // 1. Small commit (<= 14 dirty pages): write the CWAL physical redo frames.
        if use_cwal_redo {
            for (r_idx, &lid) in dirty_allocated.iter().enumerate() {
                let entry = new_dir[lid as usize];
                let p = &self.pages[lid as usize];
                encrypt_page_sectors(
                    &keys,
                    lid,
                    entry.phys_slot,
                    entry.domain,
                    entry.flags,
                    entry.owner_id,
                    next_lsn,
                    &p.payload[..p.payload_len as usize],
                    &mut page_buf,
                )?;
                page_digests.push(sha256_of(page_buf.as_flattened()));

                let mut desc_sec = [0u8; SECTOR_BYTES];
                desc_sec[0..8].copy_from_slice(&PAGED_FRAME_MAGIC);
                desc_sec[8..16].copy_from_slice(&next_lsn.to_le_bytes());
                desc_sec[16..18].copy_from_slice(&lid.to_le_bytes());
                let mut raw_entry = [0u8; 16];
                entry.encode(&mut raw_entry);
                desc_sec[18..34].copy_from_slice(&raw_entry);

                cwal_hasher.update(&desc_sec[0..34]);
                cwal_hasher.update(page_buf.as_flattened());

                let frame_lba =
                    layout.cwal_base_lba + 1 + (r_idx as u64) * CWAL_REDO_FRAME_SECTORS;
                dev.write_sector(frame_lba, &desc_sec).map_err(io)?;
                dev.write_sectors(frame_lba + 1, &page_buf[..]).map_err(io)?;
            }
        }

        let mut cwal_sha256 = [0u8; DURABLE_DIGEST_LEN];
        cwal_sha256.copy_from_slice(&cwal_hasher.finalize());
        cwal_hdr[20..52].copy_from_slice(&cwal_sha256);
        let mut cwal_tag = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&keys.mac, &cwal_hdr[0..52], &mut cwal_tag);
        cwal_hdr[52..84].copy_from_slice(&cwal_tag);

        if use_cwal_redo {
            // Redo frames, their header and the inactive directory become durable together.
            dev.write_sector(layout.cwal_base_lba, &cwal_hdr)
                .map_err(io)?;
            dev.write_sectors(dir_lba, &dir_secs[..]).map_err(io)?;
            dev.flush().map_err(io)?;

            if !dirty_allocated.is_empty() {
                // 2. Publish the `IN_FLIGHT` superblock: recovery can now roll this
                //    epoch forward from the redo frames.
                let sb_inflight = PagedSuperblock {
                    state: PAGED_STATE_IN_FLIGHT,
                    slot_idx: target_slot,
                    boots,
                    tx_lsn: next_lsn,
                    prev_tx_lsn: prev_lsn,
                    allocated_pages: allocated_total,
                    cwal_redo_count,
                    sql_rows: self.sql_rows,
                    vfs_files: self.vfs_files,
                    vfs_bytes: self.vfs_bytes,
                    dir_sha256,
                    cwal_sha256,
                    merkle_root,
                };
                pack_superblock(&keys.mac, &layout, &sb_inflight, &mut sb_sec);
                dev.write_sector(sb_lba, &sb_sec).map_err(io)?;
                dev.flush().map_err(io)?;

                // 3. Install the dirty pages into their new CoW home slots.
                for &lid in &dirty_allocated {
                    let entry = new_dir[lid as usize];
                    let p = &self.pages[lid as usize];
                    encrypt_page_sectors(
                        &keys,
                        lid,
                        entry.phys_slot,
                        entry.domain,
                        entry.flags,
                        entry.owner_id,
                        next_lsn,
                        &p.payload[..p.payload_len as usize],
                        &mut page_buf,
                    )?;
                    dev.write_sectors(home_lba(&entry), &page_buf[..]).map_err(io)?;
                }
                dev.flush().map_err(io)?;
            }
        } else {
            // Bulk commit (> 14 dirty pages): no redo frames; the pages go straight to
            // free CoW slots, so `S0` stays untouched until the superblock is written.
            //
            // The journal header goes first, and is made durable before the first
            // page: it carries `next_lsn`, and it is the only record that this LSN
            // was used if power is cut before the superblock. Recovery raises
            // `lsn_floor` from it.
            dev.write_sector(layout.cwal_base_lba, &cwal_hdr)
                .map_err(io)?;
            dev.flush().map_err(io)?;
            for &lid in &dirty_allocated {
                let entry = new_dir[lid as usize];
                let p = &self.pages[lid as usize];
                encrypt_page_sectors(
                    &keys,
                    lid,
                    entry.phys_slot,
                    entry.domain,
                    entry.flags,
                    entry.owner_id,
                    next_lsn,
                    &p.payload[..p.payload_len as usize],
                    &mut page_buf,
                )?;
                page_digests.push(sha256_of(page_buf.as_flattened()));
                dev.write_sectors(home_lba(&entry), &page_buf[..]).map_err(io)?;
            }
            dev.write_sectors(dir_lba, &dir_secs[..]).map_err(io)?;
            dev.flush().map_err(io)?;
        }

        // Prove the epoch landed before a superblock calls it committed: read every
        // page of this commit and the directory back and compare. A device that
        // reported success for a write it dropped or misdirected is caught here,
        // while the previous epoch is still the committed one.
        for (i, &lid) in dirty_allocated.iter().enumerate() {
            dev.read_sectors(home_lba(&new_dir[lid as usize]), &mut page_buf[..])
                .map_err(io)?;
            if sha256_of(page_buf.as_flattened()) != page_digests[i] {
                return Err(PagedStoreError::VerifyFailed);
            }
        }
        for s in &mut dir_secs {
            *s = [0u8; SECTOR_BYTES];
        }
        dev.read_sectors(dir_lba, &mut dir_secs[..]).map_err(io)?;
        if sha256_of(dir_secs.as_flattened()) != dir_sha256 {
            return Err(PagedStoreError::VerifyFailed);
        }

        // 4. Finalize target Superblock as `QUIESCENT`, flush, and read it back.
        let sb_quiescent = PagedSuperblock {
            state: PAGED_STATE_QUIESCENT,
            slot_idx: target_slot,
            boots,
            tx_lsn: next_lsn,
            prev_tx_lsn: prev_lsn,
            allocated_pages: allocated_total,
            cwal_redo_count,
            sql_rows: self.sql_rows,
            vfs_files: self.vfs_files,
            vfs_bytes: self.vfs_bytes,
            dir_sha256,
            cwal_sha256,
            merkle_root,
        };
        pack_superblock(&keys.mac, &layout, &sb_quiescent, &mut sb_sec);
        dev.write_sector(sb_lba, &sb_sec).map_err(io)?;
        dev.flush().map_err(io)?;
        let mut sb_back = [0u8; SECTOR_BYTES];
        dev.read_sector(sb_lba, &mut sb_back).map_err(io)?;
        if sb_back != sb_sec {
            return Err(PagedStoreError::VerifyFailed);
        }

        // Commit succeeded: advance in-memory directory & clear dirty flags.
        self.dir[..layout.dir_slots].copy_from_slice(&new_dir[..]);
        self.dir_slots = layout.dir_slots;
        for slot in &mut self.pages {
            slot.dirty = false;
        }
        self.initialized = true;
        self.active_slot = target_slot;
        self.tx_lsn = next_lsn;
        self.boots = boots;
        self.merkle_root = merkle_root;
        self.last_dirty_pages_written = dirty_allocated.len();
        Ok(self.anchor())
    }

    /// Raise [`Self::lsn_floor`] to the highest LSN the device shows was used:
    /// in either authenticated superblock, or in an authenticated redo-journal
    /// header. Sectors that cannot be read or authenticated contribute nothing.
    fn observe_lsn_floor<D: SectorIo>(
        &mut self,
        dev: &mut D,
        layout: &PagedLayoutSpec,
        keys: &PagedKeys,
    ) {
        let mut seen = 0u64;
        let mut sec = [0u8; SECTOR_BYTES];
        if dev.read_sector(SUPERBLOCK_A_LBA, &mut sec).is_ok() {
            if let Some(sb) = verify_superblock(&keys.mac, layout, 0, &sec) {
                seen = seen.max(sb.tx_lsn);
            }
        }
        if dev.read_sector(SUPERBLOCK_B_LBA, &mut sec).is_ok() {
            if let Some(sb) = verify_superblock(&keys.mac, layout, 1, &sec) {
                seen = seen.max(sb.tx_lsn);
            }
        }
        if dev.read_sector(layout.cwal_base_lba, &mut sec).is_ok()
            && sec[0..8] == PAGED_CWAL_MAGIC
        {
            let mut tag = [0u8; DURABLE_DIGEST_LEN];
            tag.copy_from_slice(&sec[52..84]);
            if seal_matches_keyed(&keys.mac, &sec[0..52], &tag) {
                seen = seen.max(u64::from_le_bytes([
                    sec[8], sec[9], sec[10], sec[11], sec[12], sec[13], sec[14], sec[15],
                ]));
            }
        }
        if seen > self.lsn_floor {
            self.lsn_floor = seen;
        }
    }

    /// Recover the latest valid committed epoch directly from `dev` (standalone mode).
    ///
    /// Returns `Ok(None)` if the paged store region (`LBA 2048..2049`) is completely blank.
    pub fn recover_latest<D: SectorIo>(
        &mut self,
        dev: &mut D,
        seal_key: &[u8; DURABLE_DIGEST_LEN],
    ) -> Result<Option<PagedAnchor>, PagedStoreError> {
        self.recover_internal(dev, seal_key, None)
    }

    /// Recover and verify the exact epoch bound by `expected_anchor` (coupled `AB_FORMAT_V3` mode).
    pub fn recover_at_anchor<D: SectorIo>(
        &mut self,
        dev: &mut D,
        seal_key: &[u8; DURABLE_DIGEST_LEN],
        expected_anchor: &PagedAnchor,
    ) -> Result<PagedAnchor, PagedStoreError> {
        if !expected_anchor.is_active() {
            return Err(PagedStoreError::RollbackOrAnchorMismatch);
        }
        match self.recover_internal(dev, seal_key, Some(expected_anchor))? {
            Some(a) => Ok(a),
            None => Err(PagedStoreError::RollbackOrAnchorMismatch),
        }
    }

    fn recover_internal<D: SectorIo>(
        &mut self,
        dev: &mut D,
        seal_key: &[u8; DURABLE_DIGEST_LEN],
        expected_anchor: Option<&PagedAnchor>,
    ) -> Result<Option<PagedAnchor>, PagedStoreError> {
        self.last_recovery_fell_back_epoch = false;
        if !is_seal_key_set(seal_key) {
            return Err(PagedStoreError::KeyUnset);
        }
        let cap_secs = dev.capacity_sectors();
        let (avail_phys, max_logical) = Self::geometry_for_sectors(cap_secs);
        if max_logical == 0 {
            return Err(PagedStoreError::DiskTooSmall);
        }
        let layout = PagedLayoutSpec::for_sectors(cap_secs);

        let mut sec_a = [0u8; SECTOR_BYTES];
        let mut sec_b = [0u8; SECTOR_BYTES];
        let a_ok = dev.read_sector(SUPERBLOCK_A_LBA, &mut sec_a).is_ok();
        let b_ok = dev.read_sector(SUPERBLOCK_B_LBA, &mut sec_b).is_ok();
        if !a_ok && !b_ok {
            return Err(PagedStoreError::Io(IoFault::DeviceError));
        }
        let a_blank = a_ok && sec_a.iter().all(|&b| b == 0);
        let b_blank = b_ok && sec_b.iter().all(|&b| b == 0);
        if a_blank && b_blank {
            if expected_anchor.is_some() {
                return Err(PagedStoreError::RollbackOrAnchorMismatch);
            }
            self.reset();
            self.dir_slots = layout.dir_slots;
            return Ok(None);
        }

        let keys = PagedKeys::derive(seal_key);
        // Every LSN the region shows was used counts, including an epoch this
        // recovery is about to pass over because the anchor names another one.
        self.observe_lsn_floor(dev, &layout, &keys);

        let sb_a = if a_ok {
            verify_superblock(&keys.mac, &layout, 0, &sec_a)
        } else {
            None
        };
        let sb_b = if b_ok {
            verify_superblock(&keys.mac, &layout, 1, &sec_b)
        } else {
            None
        };

        // Order candidate superblocks: highest `tx_lsn` first, filtered by `expected_anchor` when provided.
        let mut candidates: [Option<PagedSuperblock>; 2] = match (sb_a, sb_b) {
            (Some(a), Some(b)) => {
                if b.tx_lsn >= a.tx_lsn {
                    [Some(b), Some(a)]
                } else {
                    [Some(a), Some(b)]
                }
            }
            (Some(a), None) => [Some(a), None],
            (None, Some(b)) => [Some(b), None],
            (None, None) => [None, None],
        };

        if let Some(exp) = expected_anchor {
            let mut c = 0usize;
            while c < 2 {
                if let Some(sb) = candidates[c] {
                    if sb.tx_lsn != exp.tx_lsn
                        || !constant_time_eq(&sb.merkle_root, &exp.merkle_root)
                    {
                        candidates[c] = None;
                    }
                }
                c += 1;
            }
        }

        let mut last_err = if expected_anchor.is_some() {
            PagedStoreError::RollbackOrAnchorMismatch
        } else {
            PagedStoreError::CorruptOrTampered
        };

        let mut c_idx = 0usize;
        while c_idx < 2 {
            let Some(sb) = candidates[c_idx] else {
                c_idx += 1;
                continue;
            };
            match self.try_load_superblock(dev, &layout, &keys, avail_phys, max_logical, &sb) {
                Ok(anchor) => {
                    if expected_anchor.is_none() {
                        self.last_recovery_fell_back_epoch =
                            (c_idx > 0 && candidates[0].is_some()) || sb.tx_lsn < self.lsn_floor;
                    }
                    return Ok(Some(anchor));
                }
                Err(e) => {
                    last_err = e;
                }
            }
            c_idx += 1;
        }
        Err(last_err)
    }

    fn try_load_superblock<D: SectorIo>(
        &mut self,
        dev: &mut D,
        layout: &PagedLayoutSpec,
        keys: &PagedKeys,
        avail_phys: usize,
        max_logical: usize,
        sb: &PagedSuperblock,
    ) -> Result<PagedAnchor, PagedStoreError> {
        let dir_lba = if sb.slot_idx == 0 {
            layout.dir_a_lba
        } else {
            layout.dir_b_lba
        };
        let mut dir_secs = alloc::vec![[0u8; SECTOR_BYTES]; layout.dir_sectors];
        dev.read_sectors(dir_lba, &mut dir_secs[..])
            .map_err(PagedStoreError::Io)?;
        let Some(entries) = decode_dir_sectors(
            &dir_secs,
            layout,
            &sb.dir_sha256,
            &sb.merkle_root,
            avail_phys,
        ) else {
            return Err(PagedStoreError::CorruptOrTampered);
        };

        // Load and verify optional CWAL physical redo frames matching `sb.tx_lsn`.
        let mut cwal_frames: Vec<(u16, PageDirEntry, Box<[[u8; SECTOR_BYTES]; SECTORS_PER_PAGE]>)> =
            Vec::new();
        if sb.cwal_redo_count > 0 {
            let mut cwal_hdr = [0u8; SECTOR_BYTES];
            if dev.read_sector(layout.cwal_base_lba, &mut cwal_hdr).is_ok()
                && cwal_hdr[0..8] == PAGED_CWAL_MAGIC
            {
                let cwal_lsn = u64::from_le_bytes([
                    cwal_hdr[8],
                    cwal_hdr[9],
                    cwal_hdr[10],
                    cwal_hdr[11],
                    cwal_hdr[12],
                    cwal_hdr[13],
                    cwal_hdr[14],
                    cwal_hdr[15],
                ]);
                let hdr_cnt = u16::from_le_bytes([cwal_hdr[16], cwal_hdr[17]]);
                let mut hdr_sha = [0u8; DURABLE_DIGEST_LEN];
                hdr_sha.copy_from_slice(&cwal_hdr[20..52]);
                let mut hdr_tag = [0u8; DURABLE_DIGEST_LEN];
                hdr_tag.copy_from_slice(&cwal_hdr[52..84]);
                if cwal_lsn == sb.tx_lsn
                    && hdr_cnt == sb.cwal_redo_count
                    && constant_time_eq(&hdr_sha, &sb.cwal_sha256)
                    && seal_matches_keyed(&keys.mac, &cwal_hdr[0..52], &hdr_tag)
                {
                    let mut hasher = Sha256::new();
                    hasher.update(&cwal_hdr[0..20]);
                    let mut frames_ok = true;
                    let mut temp_frames = Vec::with_capacity(sb.cwal_redo_count as usize);
                    let mut r = 0usize;
                    while r < sb.cwal_redo_count as usize {
                        let frame_lba =
                            layout.cwal_base_lba + 1 + (r as u64) * CWAL_REDO_FRAME_SECTORS;
                        let mut desc = [0u8; SECTOR_BYTES];
                        let mut pbuf = Box::new([[0u8; SECTOR_BYTES]; SECTORS_PER_PAGE]);
                        if dev.read_sector(frame_lba, &mut desc).is_err()
                            || dev.read_sectors(frame_lba + 1, &mut pbuf[..]).is_err()
                            || desc[0..8] != PAGED_FRAME_MAGIC
                        {
                            frames_ok = false;
                            break;
                        }
                        let flsn = u64::from_le_bytes([
                            desc[8], desc[9], desc[10], desc[11], desc[12], desc[13], desc[14],
                            desc[15],
                        ]);
                        let lid = u16::from_le_bytes([desc[16], desc[17]]);
                        let Some(fe) = PageDirEntry::decode(&desc[18..34]) else {
                            frames_ok = false;
                            break;
                        };
                        if flsn != sb.tx_lsn
                            || (lid as usize) >= layout.dir_slots
                            || entries[lid as usize] != fe
                        {
                            frames_ok = false;
                            break;
                        }
                        hasher.update(&desc[0..34]);
                        hasher.update(pbuf.as_flattened());
                        temp_frames.push((lid, fe, pbuf));
                        r += 1;
                    }
                    if frames_ok {
                        let mut actual_cwal_sha = [0u8; DURABLE_DIGEST_LEN];
                        actual_cwal_sha.copy_from_slice(&hasher.finalize());
                        if constant_time_eq(&actual_cwal_sha, &sb.cwal_sha256) {
                            cwal_frames = temp_frames;
                        }
                    }
                }
            }
        }

        if sb.state == PAGED_STATE_IN_FLIGHT && cwal_frames.len() != sb.cwal_redo_count as usize {
            return Err(PagedStoreError::CorruptOrTampered);
        }

        // Verify and decrypt every mapped logical page; if a home page fails verification
        // (always possible while `sb.state == IN_FLIGHT`), restore it from the authenticated
        // CWAL redo frame when there is one.
        let mut loaded_pages = Vec::with_capacity(layout.dir_slots);
        loaded_pages.resize_with(layout.dir_slots, CachedLogicalPage::empty);
        let mut page_buf = Box::new([[0u8; SECTOR_BYTES]; SECTORS_PER_PAGE]);
        // Home pages rewritten from the redo journal: where, and what they must read back as.
        let mut healed: Vec<(u64, [u8; DURABLE_DIGEST_LEN])> = Vec::new();

        let mut lid = 0usize;
        while lid < layout.dir_slots {
            let e = entries[lid];
            if e.is_mapped() {
                if lid >= max_logical {
                    return Err(PagedStoreError::CorruptOrTampered);
                }
                let phys_lba = layout.page_pool_base_lba
                    + (e.phys_slot as u64) * (SECTORS_PER_PAGE as u64);
                let home_read = dev.read_sectors(phys_lba, &mut page_buf[..]);
                let home_ok = if home_read.is_ok() {
                    decrypt_page_sectors(&keys.aead, lid as u16, &e, &mut page_buf)
                } else {
                    None
                };

                let payload_len = match home_ok {
                    Some(plen) => plen,
                    None => {
                        // Look up authenticated CWAL redo image for `lid`.
                        let Some((_, _, cwal_cipher)) =
                            cwal_frames.iter().find(|(id, _, _)| *id == lid as u16)
                        else {
                            if let Err(io_fault) = home_read {
                                return Err(PagedStoreError::Io(io_fault));
                            }
                            return Err(PagedStoreError::CorruptOrTampered);
                        };
                        let mut repair_copy = cwal_cipher.clone();
                        let Some(plen) =
                            decrypt_page_sectors(&keys.aead, lid as u16, &e, &mut repair_copy)
                        else {
                            return Err(PagedStoreError::CorruptOrTampered);
                        };
                        // Rewrite the home slot from the redo image. This must succeed:
                        // the next commit overwrites the redo journal, and a home page
                        // left damaged would then be this page's only copy, gone.
                        dev.write_sectors(phys_lba, &cwal_cipher[..])
                            .map_err(PagedStoreError::Io)?;
                        healed.push((phys_lba, sha256_of(cwal_cipher.as_flattened())));
                        page_buf = repair_copy;
                        plen
                    }
                };

                let flat = page_buf.as_flattened();
                let mut payload = Vec::with_capacity(payload_len);
                payload.extend_from_slice(
                    &flat[PAGED_PAGE_HEADER_BYTES..PAGED_PAGE_HEADER_BYTES + payload_len],
                );
                loaded_pages[lid] = CachedLogicalPage {
                    allocated: true,
                    dirty: false,
                    domain: e.domain,
                    flags: e.flags,
                    owner_id: e.owner_id,
                    payload_len: payload_len as u16,
                    payload,
                };
            }
            lid += 1;
        }

        // Make the repairs durable and prove they landed before anything relies on them.
        if !healed.is_empty() {
            dev.flush().map_err(PagedStoreError::Io)?;
            for (lba, digest) in &healed {
                dev.read_sectors(*lba, &mut page_buf[..])
                    .map_err(PagedStoreError::Io)?;
                if sha256_of(page_buf.as_flattened()) != *digest {
                    return Err(PagedStoreError::VerifyFailed);
                }
            }
        }

        // Close an interrupted commit. Until its superblock says `QUIESCENT` this epoch
        // depends on the redo journal, which the next commit overwrites; so a store
        // that cannot record the roll-forward is not handed back as recovered.
        let rolled_forward = sb.state == PAGED_STATE_IN_FLIGHT;
        if rolled_forward {
            let sb_lba = if sb.slot_idx == 0 {
                SUPERBLOCK_A_LBA
            } else {
                SUPERBLOCK_B_LBA
            };
            let sb_quiescent = PagedSuperblock {
                state: PAGED_STATE_QUIESCENT,
                ..*sb
            };
            let mut sb_sec = [0u8; SECTOR_BYTES];
            pack_superblock(&keys.mac, layout, &sb_quiescent, &mut sb_sec);
            dev.write_sector(sb_lba, &sb_sec)
                .map_err(PagedStoreError::Io)?;
            dev.flush().map_err(PagedStoreError::Io)?;
            let mut sb_back = [0u8; SECTOR_BYTES];
            dev.read_sector(sb_lba, &mut sb_back)
                .map_err(PagedStoreError::Io)?;
            if sb_back != sb_sec {
                return Err(PagedStoreError::VerifyFailed);
            }
        }

        self.dir = entries;
        self.dir_slots = layout.dir_slots;
        self.pages = loaded_pages;
        self.initialized = true;
        self.active_slot = sb.slot_idx;
        self.tx_lsn = sb.tx_lsn;
        self.boots = sb.boots;
        self.sql_rows = sb.sql_rows;
        self.vfs_files = sb.vfs_files;
        self.vfs_bytes = sb.vfs_bytes;
        self.last_dirty_pages_written = 0;
        self.last_recovery_healed = healed.len();
        self.last_recovery_rolled_forward = rolled_forward;
        self.merkle_root = sb.merkle_root;
        Ok(self.anchor())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::durable_seal::DEFAULT_DURABLE_SEAL_KEY;

    struct CountingDisk {
        sectors: Vec<[u8; SECTOR_BYTES]>,
        unflushed: Vec<(u64, [u8; SECTOR_BYTES])>,
        writes: usize,
        reads: usize,
        flushes: usize,
        op_budget: Option<usize>,
        ops_done: usize,
    }

    impl CountingDisk {
        fn new(num_sectors: usize) -> Self {
            Self {
                sectors: alloc::vec![[0u8; SECTOR_BYTES]; num_sectors],
                unflushed: Vec::new(),
                writes: 0,
                reads: 0,
                flushes: 0,
                op_budget: None,
                ops_done: 0,
            }
        }

        fn reset_counters(&mut self) {
            self.writes = 0;
            self.reads = 0;
            self.flushes = 0;
        }

        fn clone_platter_after_power_cut(&self) -> Self {
            // Simulates sudden power loss: all unflushed volatile write-cache sectors are lost!
            Self {
                sectors: self.sectors.clone(),
                unflushed: Vec::new(),
                writes: 0,
                reads: 0,
                flushes: 0,
                op_budget: None,
                ops_done: 0,
            }
        }
    }

    impl SectorIo for CountingDisk {
        fn capacity_sectors(&self) -> u64 {
            self.sectors.len() as u64
        }

        fn read_sector(&mut self, lba: u64, out: &mut [u8; SECTOR_BYTES]) -> Result<(), IoFault> {
            let idx = lba as usize;
            if idx >= self.sectors.len() {
                return Err(IoFault::OutOfRange);
            }
            self.reads += 1;
            if let Some((_, data)) = self.unflushed.iter().rev().find(|(l, _)| *l == lba) {
                *out = *data;
            } else {
                *out = self.sectors[idx];
            }
            Ok(())
        }

        fn write_sector(&mut self, lba: u64, data: &[u8; SECTOR_BYTES]) -> Result<(), IoFault> {
            let idx = lba as usize;
            if idx >= self.sectors.len() {
                return Err(IoFault::OutOfRange);
            }
            if let Some(budget) = self.op_budget {
                if self.ops_done >= budget {
                    return Err(IoFault::DeviceError);
                }
            }
            self.ops_done += 1;
            self.writes += 1;
            self.unflushed.push((lba, *data));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), IoFault> {
            if let Some(budget) = self.op_budget {
                if self.ops_done >= budget {
                    return Err(IoFault::DeviceError);
                }
            }
            self.ops_done += 1;
            self.flushes += 1;
            for (lba, data) in self.unflushed.drain(..) {
                self.sectors[lba as usize] = data;
            }
            Ok(())
        }
    }

    #[test]
    fn incremental_commit_writes_o_dirty_pages_not_full_database() {
        let mut disk = CountingDisk::new(PAGED_STORE_DEFAULT_DISK_SECTORS as usize);
        let mut store = PagedBlockStore::new();
        let key = DEFAULT_DURABLE_SEAL_KEY;

        // Populate 80 logical 4 KiB pages (`320 KiB` = `640` page sectors).
        for lid in 0..80u16 {
            let mut buf = [0u8; 512];
            buf[0..2].copy_from_slice(&lid.to_le_bytes());
            buf[2..10].copy_from_slice(b"INITPAGE");
            store
                .put_page(lid, PageDomain::SqlLeaf, 0, lid as u32, &buf)
                .expect("put initial page");
        }
        store.set_summary_counts(2560, 0, 0);
        let a1 = store
            .commit_dirty(&mut disk, &key, 1)
            .expect("initial bulk commit");
        assert_eq!(a1.tx_lsn, 1);
        assert_eq!(store.last_dirty_pages_written(), 80);

        // No-op commit when nothing changed must perform 0 writes!
        disk.reset_counters();
        let a_same = store.commit_dirty(&mut disk, &key, 1).expect("no-op commit");
        assert_eq!(a_same, a1);
        assert_eq!(disk.writes, 0, "clean commit must write 0 sectors");

        // Mutate a SINGLE page (`lid = 42`) out of 80 populated pages (`640` sectors).
        let mut updated = [0u8; 512];
        updated[0..2].copy_from_slice(&42u16.to_le_bytes());
        updated[2..10].copy_from_slice(b"UPDATED!");
        store
            .put_page(42, PageDomain::SqlLeaf, 0, 42, &updated)
            .expect("update single page");

        disk.reset_counters();
        let a2 = store
            .commit_dirty(&mut disk, &key, 1)
            .expect("1-page incremental commit");
        assert_eq!(a2.tx_lsn, 2);
        assert_eq!(store.last_dirty_pages_written(), 1);
        // 1 CWAL header + 9 CWAL redo sectors + 8 dir sectors + 1 IN_FLIGHT sb + 8 home sectors + 1 QUIESCENT sb = 28 sectors!
        assert!(
            disk.writes <= 32,
            "1-page update wrote {} sectors (expected <= 32 O(dirty pages), full DB is 640+ sectors)",
            disk.writes
        );

        // Recover into a fresh instance and verify all 80 pages + Merkle inclusion proof!
        let mut recovered = PagedBlockStore::new();
        let a_rec = recovered
            .recover_at_anchor(&mut disk, &key, &a2)
            .expect("recover at anchor a2");
        assert_eq!(a_rec, a2);
        for lid in 0..80u16 {
            let (dom, _, owner, data) = recovered.get_page(lid).expect("page present");
            assert_eq!(dom, PageDomain::SqlLeaf);
            assert_eq!(owner, lid as u32);
            if lid == 42 {
                assert_eq!(&data[2..10], b"UPDATED!");
            } else {
                assert_eq!(&data[2..10], b"INITPAGE");
            }
            let proof = recovered.merkle_proof(lid).expect("merkle proof");
            assert!(verify_dir_merkle_proof(&proof, &a2.merkle_root));
        }
    }

    #[test]
    fn power_cut_at_every_write_and_flush_boundary_recovers_atomically() {
        let key = DEFAULT_DURABLE_SEAL_KEY;
        let mut base_disk = CountingDisk::new(PAGED_STORE_MIN_DISK_SECTORS as usize);
        let mut s0 = PagedBlockStore::new();
        for lid in 0..6u16 {
            s0.put_page(lid, PageDomain::VfsData, 1, lid as u32, &[lid as u8 + 10; 200])
                .unwrap();
        }
        let anchor0 = s0.commit_dirty(&mut base_disk, &key, 1).unwrap();

        // Measure total ops in a 2-page update + 1-page delete + 1-page alloc transaction.
        let mut measure_disk = base_disk.clone_platter_after_power_cut();
        let mut s_meas = PagedBlockStore::new();
        s_meas.recover_at_anchor(&mut measure_disk, &key, &anchor0).unwrap();
        s_meas
            .put_page(1, PageDomain::VfsData, 2, 1, &[0xBB; 300])
            .unwrap();
        s_meas
            .put_page(4, PageDomain::VfsData, 2, 4, &[0xCC; 300])
            .unwrap();
        s_meas.free_page(2).unwrap();
        s_meas
            .put_page(6, PageDomain::SqlLeaf, 0, 99, &[0xDD; 128])
            .unwrap();
        measure_disk.ops_done = 0;
        let anchor1 = s_meas.commit_dirty(&mut measure_disk, &key, 2).unwrap();
        let total_ops = measure_disk.ops_done;
        assert!(total_ops > 10);

        for cut in 0..=total_ops {
            let mut fault_disk = base_disk.clone_platter_after_power_cut();
            let mut writer = PagedBlockStore::new();
            writer
                .recover_at_anchor(&mut fault_disk, &key, &anchor0)
                .unwrap();
            writer
                .put_page(1, PageDomain::VfsData, 2, 1, &[0xBB; 300])
                .unwrap();
            writer
                .put_page(4, PageDomain::VfsData, 2, 4, &[0xCC; 300])
                .unwrap();
            writer.free_page(2).unwrap();
            writer
                .put_page(6, PageDomain::SqlLeaf, 0, 99, &[0xDD; 128])
                .unwrap();

            fault_disk.ops_done = 0;
            fault_disk.op_budget = Some(cut);
            let res = writer.commit_dirty(&mut fault_disk, &key, 2);

            // Simulate sudden power loss (drop unflushed write cache).
            let mut reboot_disk = fault_disk.clone_platter_after_power_cut();

            // 1. Coupled `AB_FORMAT_V3` anchor recovery: `anchor0` MUST ALWAYS remain valid
            //    whenever `res.is_err()`, and `anchor1` MUST be valid when `res.is_ok()`!
            if res.is_ok() {
                let mut r1 = PagedBlockStore::new();
                r1.recover_at_anchor(&mut reboot_disk, &key, &anchor1)
                    .expect("committed anchor1 must recover");
                assert_eq!(r1.get_page(1).unwrap().3, &[0xBB; 300]);
                assert!(r1.get_page(2).is_none());
                assert_eq!(r1.get_page(6).unwrap().3, &[0xDD; 128]);
            } else {
                let mut r0 = PagedBlockStore::new();
                r0.recover_at_anchor(&mut reboot_disk, &key, &anchor0)
                    .expect("previous committed anchor0 must remain intact on aborted commit");
                assert_eq!(r0.get_page(1).unwrap().3, &[11u8; 200]);
                assert_eq!(r0.get_page(2).unwrap().3, &[12u8; 200]);
                assert!(r0.get_page(6).is_none());
            }

            // 2. Standalone `recover_latest`: must cleanly recover EITHER exact S0 OR exact S1, never a torn mix!
            let mut latest_disk = fault_disk.clone_platter_after_power_cut();
            let mut r_lat = PagedBlockStore::new();
            let lat_anchor = r_lat
                .recover_latest(&mut latest_disk, &key)
                .expect("standalone recover_latest must never fail on power cut")
                .expect("non-empty store");
            assert!(
                lat_anchor == anchor0 || lat_anchor == anchor1,
                "cut={cut}: unexpected anchor {:?}",
                lat_anchor
            );
        }
    }

    #[test]
    fn cwal_redo_heals_corrupted_home_page_and_detects_tamper_or_rollback() {
        let key = DEFAULT_DURABLE_SEAL_KEY;
        let mut disk = CountingDisk::new(PAGED_STORE_MIN_DISK_SECTORS as usize);
        let mut store = PagedBlockStore::new();
        store
            .put_page(0, PageDomain::SqlCatalog, 0, 0, b"catalog-v1")
            .unwrap();
        let a1 = store.commit_dirty(&mut disk, &key, 1).unwrap();

        store
            .put_page(0, PageDomain::SqlCatalog, 0, 0, b"catalog-v2-healed")
            .unwrap();
        let a2 = store.commit_dirty(&mut disk, &key, 2).unwrap();

        // Corrupt the home physical page of logical page 0 in epoch 2 — CWAL still holds the valid redo image!
        let phys_slot = store.dir[0].phys_slot;
        let home_lba = (PAGE_POOL_BASE_LBA + (phys_slot as u64) * 8) as usize;
        disk.sectors[home_lba + 2][10] ^= 0xFF;

        let mut healed = PagedBlockStore::new();
        healed
            .recover_at_anchor(&mut disk, &key, &a2)
            .expect("CWAL redo must heal damaged home page");
        assert_eq!(healed.get_page(0).unwrap().3, b"catalog-v2-healed");

        // Now corrupt BOTH CWAL and the home physical page: must fail closed!
        disk.sectors[(CWAL_BASE_LBA + 3) as usize][25] ^= 0x55;
        disk.sectors[home_lba + 2][10] ^= 0xFF;
        let mut rejected = PagedBlockStore::new();
        assert_eq!(
            rejected.recover_at_anchor(&mut disk, &key, &a2),
            Err(PagedStoreError::CorruptOrTampered)
        );

        // Whole-epoch rollback check: asking for `a2` when Superblock B (`a2`) is wiped back to zeros
        // while `a1` still sits in Superblock A must fail with `RollbackOrAnchorMismatch`!
        disk.sectors[SUPERBLOCK_B_LBA as usize] = [0u8; SECTOR_BYTES];
        let mut rb = PagedBlockStore::new();
        assert_eq!(
            rb.recover_at_anchor(&mut disk, &key, &a2),
            Err(PagedStoreError::RollbackOrAnchorMismatch)
        );
        // Meanwhile `a1` itself is rejected when `a2` is demanded, proving anti-rollback!
        assert_ne!(a1.tx_lsn, a2.tx_lsn);
    }

    #[test]
    fn parser_and_api_reject_unset_key_small_disk_oversized_payload_and_bad_headers() {
        let key = DEFAULT_DURABLE_SEAL_KEY;
        let mut small = CountingDisk::new(2048);
        let mut store = PagedBlockStore::new();
        assert_eq!(
            store.commit_dirty(&mut small, &[0u8; 32], 1),
            Err(PagedStoreError::KeyUnset)
        );
        assert_eq!(
            store.commit_dirty(&mut small, &key, 1),
            Err(PagedStoreError::DiskTooSmall)
        );
        assert_eq!(
            store.put_page(
                0,
                PageDomain::VfsData,
                0,
                0,
                &[0xAAu8; PAGED_PAGE_PAYLOAD_BYTES + 1]
            ),
            Err(PagedStoreError::PayloadTooLarge)
        );
        assert_eq!(
            store.put_page(256, PageDomain::VfsData, 0, 0, b"bad"),
            Err(PagedStoreError::InvalidPageId)
        );
        assert_eq!(
            store.put_page(0, PageDomain::Free, 0, 0, b"bad"),
            Err(PagedStoreError::InvalidPageId)
        );

        // Corrupt superblock magic / directory aliasing checks.
        let mut disk = CountingDisk::new(PAGED_STORE_MIN_DISK_SECTORS as usize);
        disk.sectors[SUPERBLOCK_A_LBA as usize][0..8].copy_from_slice(b"BADMAGIC");
        assert_eq!(
            store.recover_latest(&mut disk, &key),
            Err(PagedStoreError::CorruptOrTampered)
        );
    }
}

/// Tests against the fault-injecting disk model: abandoned epochs, dropped
/// writes, and recovery that is itself interrupted or refused.
#[cfg(test)]
mod fault_tests {
    use super::*;
    use crate::durable_seal::DEFAULT_DURABLE_SEAL_KEY;
    use crate::state_store::testdisk::{CacheLoss, MemDisk};
    extern crate std;
    use std::vec::Vec;

    // The smallest disk the store accepts: 237 physical pages, 118 logical.
    const SECTORS: usize = PAGED_STORE_MIN_DISK_SECTORS as usize;

    fn key() -> [u8; DURABLE_DIGEST_LEN] {
        DEFAULT_DURABLE_SEAL_KEY
    }

    /// A page body that depends on `tag` and `lid` in every byte.
    fn body(tag: u8, lid: u16) -> Vec<u8> {
        (0..3000usize)
            .map(|i| (i as u8).wrapping_mul(31) ^ tag ^ (lid as u8).wrapping_mul(7))
            .collect()
    }

    fn put(store: &mut PagedBlockStore, lids: core::ops::Range<u16>, tag: u8) {
        for lid in lids {
            store
                .put_page(lid, PageDomain::VfsData, 0, lid as u32, &body(tag, lid))
                .expect("put_page");
        }
    }

    fn page(store: &PagedBlockStore, lid: u16) -> Vec<u8> {
        store.get_page(lid).expect("page present").3.to_vec()
    }

    /// The disk as a power cycle would leave it: flushed contents only.
    fn clone_disk(d: &MemDisk) -> MemDisk {
        let mut c = MemDisk::new(SECTORS);
        for l in 0..SECTORS as u64 {
            let sec = d.peek(l);
            c.poke(l, |s| *s = sec);
        }
        c
    }

    fn recovered_at(disk: &mut MemDisk, anchor: &PagedAnchor) -> PagedBlockStore {
        let mut s = PagedBlockStore::new();
        s.recover_at_anchor(disk, &key(), anchor)
            .expect("recover_at_anchor");
        s
    }

    /// `(state, tx_lsn)` of the superblock in `slot`, read without authentication.
    fn raw_superblock(disk: &MemDisk, slot: u8) -> (u8, u64) {
        let sec = disk.peek(SUPERBLOCK_A_LBA + slot as u64);
        let mut lsn = [0u8; 8];
        lsn.copy_from_slice(&sec[24..32]);
        (sec[10], u64::from_le_bytes(lsn))
    }

    /// Every physical slot whose stored header carries `lsn`.
    fn slots_bearing_lsn(disk: &MemDisk, lsn: u64) -> Vec<u16> {
        let (avail, _) = PagedBlockStore::geometry_for_sectors(SECTORS as u64);
        (0..avail as u16)
            .filter(|p| {
                let sec = disk.peek(PAGE_POOL_BASE_LBA + (*p as u64) * SECTORS_PER_PAGE as u64);
                let mut l = [0u8; 8];
                l.copy_from_slice(&sec[20..28]);
                sec[0..8] == PAGED_PAGE_MAGIC && u64::from_le_bytes(l) == lsn
            })
            .collect()
    }

    /// Every physical slot the store's committed directory maps under `lsn`.
    fn slots_mapped_at_lsn(store: &PagedBlockStore, lsn: u64) -> Vec<u16> {
        (0..PAGED_MAX_LOGICAL_PAGES as u16)
            .filter_map(|lid| store.dir_entry(lid))
            .filter(|e| e.is_mapped() && e.page_lsn == lsn)
            .map(|e| e.phys_slot)
            .collect()
    }

    #[test]
    fn two_different_page_images_never_share_a_nonce_and_equal_images_encrypt_identically() {
        let keys = PagedKeys::derive(&key());
        let seal = |payload: &[u8]| {
            let mut secs = Box::new([[0u8; SECTOR_BYTES]; SECTORS_PER_PAGE]);
            // Same logical page, same physical slot, same LSN every time: only
            // the contents differ. This is what a commit that replaces an
            // abandoned epoch writes.
            encrypt_page_sectors(&keys, 5, 9, PageDomain::SqlLeaf, 0, 77, 41, payload, &mut secs)
                .expect("encrypt");
            secs
        };
        let a = seal(&body(1, 5));
        let a_again = seal(&body(1, 5));
        let b = seal(&body(2, 5));
        // One byte of difference, at the very end of the payload area.
        let mut near = body(1, 5);
        near.resize(PAGED_PAGE_PAYLOAD_BYTES, 0);
        near[PAGED_PAGE_PAYLOAD_BYTES - 1] ^= 1;
        let c = seal(&near);

        let nonce = |s: &[[u8; SECTOR_BYTES]; SECTORS_PER_PAGE]| s.as_flattened()[28..40].to_vec();
        assert_eq!(a.as_flattened(), a_again.as_flattened(), "encryption must be deterministic");
        assert_ne!(nonce(&a), nonce(&b), "different contents sealed under one nonce");
        assert_ne!(nonce(&a), nonce(&c), "a one-byte difference must change the nonce");

        // What nonce reuse would give away: the XOR of the two ciphertexts
        // equal to the XOR of the two plaintexts.
        let (fa, fb) = (a.as_flattened(), b.as_flattened());
        let (pa, pb) = (body(1, 5), body(2, 5));
        let leaks = (0..pa.len()).all(|i| {
            fa[PAGED_PAGE_HEADER_BYTES + i] ^ fb[PAGED_PAGE_HEADER_BYTES + i] == pa[i] ^ pb[i]
        });
        assert!(!leaks, "ciphertexts of two page images share a keystream");

        // Both still decrypt to what was sealed.
        let entry = PageDirEntry {
            phys_slot: 9,
            domain: PageDomain::SqlLeaf,
            flags: 0,
            owner_id: 77,
            page_lsn: 41,
        };
        let mut back = b.clone();
        let n = decrypt_page_sectors(&keys.aead, 5, &entry, &mut back).expect("decrypt");
        assert_eq!(&back.as_flattened()[PAGED_PAGE_HEADER_BYTES..][..n], &body(2, 5)[..]);
    }

    #[test]
    fn pages_sealed_under_the_previous_nonce_derivation_are_still_read() {
        let keys = PagedKeys::derive(&key());
        let entry = PageDirEntry {
            phys_slot: 3,
            domain: PageDomain::VfsData,
            flags: 0,
            owner_id: 12,
            page_lsn: 6,
        };
        let payload = body(9, 2);
        let mut secs = Box::new([[0u8; SECTOR_BYTES]; SECTORS_PER_PAGE]);
        {
            let flat = secs.as_flattened_mut();
            flat[0..8].copy_from_slice(&PAGED_PAGE_MAGIC);
            flat[8] = entry.domain as u8;
            flat[9] = entry.flags;
            flat[10..12].copy_from_slice(&2u16.to_le_bytes());
            flat[12..14].copy_from_slice(&entry.phys_slot.to_le_bytes());
            flat[14..16].copy_from_slice(&(payload.len() as u16).to_le_bytes());
            flat[16..20].copy_from_slice(&entry.owner_id.to_le_bytes());
            flat[20..28].copy_from_slice(&entry.page_lsn.to_le_bytes());
            // The derivation pages were written with before: (lsn, slot, domain, 0xA5).
            let mut nonce = [0u8; AEAD_NONCE_LEN];
            nonce[0..8].copy_from_slice(&entry.page_lsn.to_le_bytes());
            nonce[8..10].copy_from_slice(&entry.phys_slot.to_le_bytes());
            nonce[10] = entry.domain as u8;
            nonce[11] = 0xA5;
            flat[28..40].copy_from_slice(&nonce);
            let mut aad = [0u8; 28];
            aad.copy_from_slice(&flat[0..28]);
            flat[PAGED_PAGE_HEADER_BYTES..PAGED_PAGE_HEADER_BYTES + payload.len()]
                .copy_from_slice(&payload);
            let tag = chacha20_poly1305_encrypt_in_place(
                &keys.aead,
                &nonce,
                &aad,
                &mut flat[PAGED_PAGE_HEADER_BYTES..],
            );
            flat[40..56].copy_from_slice(&tag);
        }
        let n = decrypt_page_sectors(&keys.aead, 2, &entry, &mut secs).expect("legacy page");
        assert_eq!(&secs.as_flattened()[PAGED_PAGE_HEADER_BYTES..][..n], &payload[..]);

        // A nonce that was not the one used to seal is still rejected.
        let mut secs2 = Box::new([[0u8; SECTOR_BYTES]; SECTORS_PER_PAGE]);
        encrypt_page_sectors(&keys, 2, 3, PageDomain::VfsData, 0, 12, 6, &payload, &mut secs2)
            .unwrap();
        secs2.as_flattened_mut()[30] ^= 1;
        assert!(decrypt_page_sectors(&keys.aead, 2, &entry, &mut secs2).is_none());
    }

    /// The window this store is built around: its own commit is durable, and
    /// power is lost before the state image that anchors it is. The node
    /// comes back at the previous anchor and commits something else.
    #[test]
    fn an_abandoned_epoch_does_not_share_its_lsn_with_the_epoch_that_replaces_it() {
        let mut disk = MemDisk::new(SECTORS);
        let mut s = PagedBlockStore::new();
        put(&mut s, 0..6, 1);
        let a = s.commit_dirty(&mut disk, &key(), 1).expect("epoch A");

        put(&mut s, 2..4, 2);
        let b = s.commit_dirty(&mut disk, &key(), 1).expect("epoch B");
        assert!(b.tx_lsn > a.tx_lsn);
        let b_slots = slots_mapped_at_lsn(&s, b.tx_lsn);
        assert_eq!(b_slots.len(), 2);

        // Reboot. The anchor on disk still names A.
        disk.reboot();
        let mut r = recovered_at(&mut disk, &a);
        assert_eq!(page(&r, 2), body(1, 2));
        assert!(r.lsn_floor() >= b.tx_lsn, "the abandoned epoch's LSN must be remembered");

        put(&mut r, 2..4, 3);
        let c = r.commit_dirty(&mut disk, &key(), 2).expect("epoch C");
        assert!(
            c.tx_lsn > b.tx_lsn,
            "epoch C took LSN {} although abandoned epoch B already sealed pages under {}",
            c.tx_lsn,
            b.tx_lsn
        );
        // C went to the physical slots B had used, which is what makes a
        // shared LSN dangerous.
        assert_eq!(slots_mapped_at_lsn(&r, c.tx_lsn), b_slots);

        // The same holds when the store object survives (a failed state
        // commit in the same boot) instead of being rebuilt by recovery.
        let mut same_boot = recovered_at(&mut disk, &c);
        put(&mut same_boot, 0..1, 4);
        let d = same_boot.commit_dirty(&mut disk, &key(), 2).expect("epoch D");
        let mut back_at_c = PagedBlockStore::new();
        back_at_c.recover_at_anchor(&mut disk, &key(), &c).unwrap();
        put(&mut back_at_c, 0..1, 5);
        let e = back_at_c.commit_dirty(&mut disk, &key(), 2).expect("epoch E");
        assert!(e.tx_lsn > d.tx_lsn);
    }

    /// A lost write must not be able to pass off a page of an abandoned
    /// epoch as the page of the epoch that replaced it.
    #[test]
    fn a_page_left_over_from_an_abandoned_epoch_is_never_returned_as_current() {
        for bulk in [false, true] {
            let n: u16 = if bulk { 20 } else { 3 };
            let mut disk = MemDisk::new(SECTORS);
            let mut s = PagedBlockStore::new();
            put(&mut s, 0..n, 1);
            let a = s.commit_dirty(&mut disk, &key(), 1).unwrap();

            // Epoch B rewrites every page, is durable, and is then abandoned.
            put(&mut s, 0..n, 2);
            let b = s.commit_dirty(&mut disk, &key(), 1).unwrap();
            let b_slot_of_page0 = s.dir_entry(0).unwrap().phys_slot;
            let b_home = PAGE_POOL_BASE_LBA + b_slot_of_page0 as u64 * SECTORS_PER_PAGE as u64;
            let b_page0: Vec<[u8; SECTOR_BYTES]> =
                (0..SECTORS_PER_PAGE as u64).map(|i| disk.peek(b_home + i)).collect();

            disk.reboot();
            let mut r = recovered_at(&mut disk, &a);
            put(&mut r, 0..n, 3);
            let c = r.commit_dirty(&mut disk, &key(), 2).unwrap();
            assert_eq!(
                r.dir_entry(0).unwrap().phys_slot,
                b_slot_of_page0,
                "test premise: C reuses B's slot"
            );
            assert_ne!(c.tx_lsn, b.tx_lsn);

            // The device lost C's write of page 0: B's bytes are still there.
            for (i, sec) in b_page0.iter().enumerate() {
                disk.poke(b_home + i as u64, |s| *s = *sec);
            }
            disk.reboot();
            let mut after = PagedBlockStore::new();
            match after.recover_at_anchor(&mut disk, &key(), &c) {
                // A small commit still has its redo frame: the page is restored.
                Ok(_) => {
                    assert!(!bulk, "a bulk commit has no redo copy to restore from");
                    assert_eq!(page(&after, 0), body(3, 0), "stale page returned as current");
                    assert_eq!(after.last_recovery_healed(), 1);
                }
                // A bulk commit does not: the loss is reported, not papered over.
                Err(e) => {
                    assert!(bulk, "small commit should have healed: {e:?}");
                    assert_eq!(e, PagedStoreError::CorruptOrTampered);
                }
            }
        }
    }

    /// A bulk commit writes pages before any superblock names its LSN. Cut
    /// power anywhere in it, recover, commit again: no page on the disk may
    /// carry the new epoch's LSN unless the new epoch put it there.
    #[test]
    fn a_power_cut_anywhere_in_a_bulk_commit_never_leaves_pages_under_a_reused_lsn() {
        let mut base = MemDisk::new(SECTORS);
        // One page more than the redo journal holds: the smallest bulk commit.
        const N: u16 = CWAL_MAX_REDO_PAGES as u16 + 1;
        let mut s0 = PagedBlockStore::new();
        put(&mut s0, 0..N, 1);
        let a = s0.commit_dirty(&mut base, &key(), 1).unwrap();
        base.reboot();

        // Count the operations of the bulk commit that will be interrupted.
        let mut dry = clone_disk(&base);
        let mut sd = recovered_at(&mut dry, &a);
        put(&mut sd, 0..N, 2);
        dry.ops = 0;
        let b = sd.commit_dirty(&mut dry, &key(), 2).unwrap();
        let total = dry.ops;
        assert!(total > 200, "expected a bulk commit, got {total} ops");

        let mut leftovers_seen = 0usize;
        for cut in 0..total {
            // Every cut point, with the three cache-loss models in rotation.
            let loss = match cut % 3 {
                0 => CacheLoss::KeepAll,
                1 => CacheLoss::DropAll,
                _ => CacheLoss::Random(cut as u64 + 7),
            };
            {
                let mut disk = clone_disk(&base);
                let mut w = recovered_at(&mut disk, &a);
                put(&mut w, 0..N, 2);
                disk.ops = 0;
                disk.cache_loss = loss;
                disk.power_cut_at = Some(cut);
                assert!(w.commit_dirty(&mut disk, &key(), 2).is_err());
                disk.reboot();

                // Either epoch may be the survivor; A must always be reachable
                // until B's superblock is durable.
                let mut r = PagedBlockStore::new();
                let got = r
                    .recover_latest(&mut disk, &key())
                    .expect("recover_latest after a cut")
                    .expect("a committed epoch");
                assert!(got == a || got == b, "cut {cut}: recovered neither A nor B");
                let want = if got == a { 1 } else { 2 };
                for lid in 0..N {
                    assert_eq!(page(&r, lid), body(want, lid), "cut {cut}: torn epoch");
                }
                if !slots_bearing_lsn(&disk, b.tx_lsn).is_empty() && got == a {
                    leftovers_seen += 1;
                }

                // One page changes; the commit after the cut.
                put(&mut r, 5..6, 9);
                let c = r.commit_dirty(&mut disk, &key(), 3).expect("commit after recovery");
                let mut mapped = slots_mapped_at_lsn(&r, c.tx_lsn);
                let mut bearing = slots_bearing_lsn(&disk, c.tx_lsn);
                mapped.sort_unstable();
                bearing.sort_unstable();
                assert_eq!(
                    bearing, mapped,
                    "cut {cut} ({loss:?}): pages of the interrupted commit carry the LSN of the next one"
                );
            }
        }
        assert!(leftovers_seen > 0, "the sweep never produced the case under test");
    }

    #[test]
    fn a_write_the_device_dropped_fails_the_commit_instead_of_committing_a_hole() {
        for bulk in [false, true] {
            let n: u16 = if bulk { 18 } else { 4 };
            let mut base = MemDisk::new(SECTORS);
            let mut s0 = PagedBlockStore::new();
            put(&mut s0, 0..n, 1);
            let a = s0.commit_dirty(&mut base, &key(), 1).unwrap();
            base.reboot();

            let mut dry = clone_disk(&base);
            let mut sd = recovered_at(&mut dry, &a);
            put(&mut sd, 0..n, 2);
            dry.ops = 0;
            sd.commit_dirty(&mut dry, &key(), 2).unwrap();
            let total = dry.ops;

            let (mut failed, mut passed) = (0usize, 0usize);
            for drop_at in 0..total {
                let mut disk = clone_disk(&base);
                let mut w = recovered_at(&mut disk, &a);
                put(&mut w, 0..n, 2);
                disk.ops = 0;
                disk.drop_write_at = Some(drop_at);
                let res = w.commit_dirty(&mut disk, &key(), 2);
                disk.reboot();
                match res {
                    // A commit that reports success must be whole on the next boot,
                    // with nothing to repair.
                    Ok(anchor) => {
                        passed += 1;
                        let r = recovered_at(&mut disk, &anchor);
                        for lid in 0..n {
                            assert_eq!(page(&r, lid), body(2, lid), "drop at {drop_at}");
                        }
                        assert_eq!(
                            r.last_recovery_healed(),
                            0,
                            "drop at {drop_at}: commit reported success with a damaged home page"
                        );
                    }
                    // A commit that reports failure leaves the previous epoch committed.
                    Err(e) => {
                        failed += 1;
                        assert_eq!(e, PagedStoreError::VerifyFailed, "drop at {drop_at}");
                        let r = recovered_at(&mut disk, &a);
                        for lid in 0..n {
                            assert_eq!(page(&r, lid), body(1, lid), "drop at {drop_at}");
                        }
                    }
                }
            }
            // Every sector of every home page, the directory and the superblock
            // is covered by the read-back.
            let min_checked = n as usize * SECTORS_PER_PAGE + SECTORS_PER_PAGE + 1;
            assert!(
                failed >= min_checked,
                "bulk={bulk}: only {failed} dropped writes were caught, expected >= {min_checked}"
            );
            assert!(passed > 0, "bulk={bulk}: reads and flushes cannot be dropped");
        }
    }

    /// An interrupted small commit is rolled forward from its redo frames.
    /// Recovery must either finish that (pages home, superblock `QUIESCENT`,
    /// both durable) or report failure: the next commit overwrites the redo
    /// frames, so "recovered" with the superblock still `IN_FLIGHT` is one
    /// power cut away from an epoch that cannot be loaded at all.
    #[test]
    fn recovery_of_an_interrupted_commit_finishes_the_roll_forward_or_fails() {
        let mut base = MemDisk::new(SECTORS);
        let mut s0 = PagedBlockStore::new();
        put(&mut s0, 0..5, 1);
        let a = s0.commit_dirty(&mut base, &key(), 1).unwrap();
        base.reboot();

        let mut dry = clone_disk(&base);
        let mut sd = recovered_at(&mut dry, &a);
        put(&mut sd, 1..4, 2);
        dry.ops = 0;
        let b = sd.commit_dirty(&mut dry, &key(), 2).unwrap();
        let total = dry.ops;

        // Find the cuts that leave B's superblock durable and IN_FLIGHT.
        let mut in_flight_disks = Vec::new();
        for cut in 0..total {
            let mut disk = clone_disk(&base);
            let mut w = recovered_at(&mut disk, &a);
            put(&mut w, 1..4, 2);
            disk.ops = 0;
            disk.cache_loss = CacheLoss::DropAll;
            disk.power_cut_at = Some(cut);
            let _ = w.commit_dirty(&mut disk, &key(), 2);
            disk.reboot();
            let in_flight = (0..2u8).any(|slot| {
                raw_superblock(&disk, slot) == (PAGED_STATE_IN_FLIGHT, b.tx_lsn)
            });
            if in_flight {
                in_flight_disks.push(clone_disk(&disk));
            }
        }
        assert!(in_flight_disks.len() >= 3, "no IN_FLIGHT disks produced");

        let b_slot = |disk: &MemDisk| -> u8 {
            (0..2u8)
                .find(|s| raw_superblock(disk, *s).1 == b.tx_lsn)
                .expect("B's superblock")
        };

        let (mut refused, mut completed) = (0usize, 0usize);
        // The first, a middle and the last such disk: before any home page is
        // written, part-way through, and with only the closing superblock missing.
        let picks = [0, in_flight_disks.len() / 2, in_flight_disks.len() - 1];
        for start in picks.iter().map(|i| &in_flight_disks[*i]) {
            // Undisturbed: rolled forward, reported, and durable.
            let mut disk = clone_disk(start);
            let r = recovered_at(&mut disk, &b);
            assert!(r.last_recovery_rolled_forward());
            for lid in 1..4 {
                assert_eq!(page(&r, lid), body(2, lid));
            }
            let ops = disk.ops;
            disk.reboot();
            assert_eq!(raw_superblock(&disk, b_slot(&disk)).0, PAGED_STATE_QUIESCENT);
            let again = recovered_at(&mut disk, &b);
            assert!(!again.last_recovery_rolled_forward());
            assert_eq!(again.last_recovery_healed(), 0);

            // With the device refusing each operation of that recovery in turn.
            for fail_at in 0..ops {
                let mut disk = clone_disk(start);
                disk.io_error_at = Some(fail_at);
                let mut r = PagedBlockStore::new();
                let res = r.recover_at_anchor(&mut disk, &key(), &b);
                disk.reboot();
                let state = raw_superblock(&disk, b_slot(&disk)).0;
                match res {
                    Ok(_) => {
                        completed += 1;
                        assert_eq!(
                            state, PAGED_STATE_QUIESCENT,
                            "error at op {fail_at}: recovery reported success with the commit still open"
                        );
                        let healthy = recovered_at(&mut disk, &b);
                        assert_eq!(
                            healthy.last_recovery_healed(),
                            0,
                            "error at op {fail_at}: recovery reported success with a home page not restored"
                        );
                    }
                    Err(_) => refused += 1,
                }
            }
        }
        assert!(refused > 0 && completed > 0, "refused={refused} completed={completed}");
    }

    #[test]
    fn standalone_recover_latest_reports_epoch_fallback_when_newest_epoch_is_damaged() {
        let mut disk = MemDisk::new(SECTORS);
        let mut s = PagedBlockStore::new();
        s.put_page(1, PageDomain::VfsData, 10, 0, &body(1, 1)).unwrap();
        let a1 = s.commit_dirty(&mut disk, &key(), 1).unwrap();
        s.put_page(1, PageDomain::VfsData, 10, 0, &body(2, 1)).unwrap();
        let a2 = s.commit_dirty(&mut disk, &key(), 1).unwrap();
        assert!(a2.tx_lsn > a1.tx_lsn);
        disk.reboot();

        // 1. Healthy disk recovers newest epoch `a2` with `last_recovery_fell_back_epoch() == false`.
        let mut r_ok = PagedBlockStore::new();
        let got_ok = r_ok.recover_latest(&mut disk, &key()).unwrap().unwrap();
        assert_eq!(got_ok.tx_lsn, a2.tx_lsn);
        assert!(!r_ok.last_recovery_fell_back_epoch());

        // 2. Damaging the older superblock (`a1`) while `a2` is intact still recovers `a2`
        //    with `last_recovery_fell_back_epoch() == false`.
        let a2_slot = u8::from(raw_superblock(&disk, 1).1 == a2.tx_lsn);
        let a1_sb_lba = if a2_slot == 0 {
            SUPERBLOCK_B_LBA
        } else {
            SUPERBLOCK_A_LBA
        };
        let mut disk_old_bad = clone_disk(&disk);
        disk_old_bad.poke(a1_sb_lba, |sec| sec[20] ^= 0x55);
        let mut r_old_bad = PagedBlockStore::new();
        let got_old_bad = r_old_bad
            .recover_latest(&mut disk_old_bad, &key())
            .unwrap()
            .unwrap();
        assert_eq!(got_old_bad.tx_lsn, a2.tx_lsn);
        assert!(!r_old_bad.last_recovery_fell_back_epoch());

        // 3. Damaging `a2`'s directory (`DIR_A_LBA` or `DIR_B_LBA`) forces `recover_latest`
        //    to fall back to `a1` and report `last_recovery_fell_back_epoch() == true`.
        let a2_dir_lba = if a2_slot == 0 { DIR_A_LBA } else { DIR_B_LBA };
        let mut disk_dir_bad = clone_disk(&disk);
        disk_dir_bad.poke(a2_dir_lba, |sec| sec[0] ^= 0xFF);
        let mut r_dir_bad = PagedBlockStore::new();
        let got_dir_bad = r_dir_bad
            .recover_latest(&mut disk_dir_bad, &key())
            .unwrap()
            .unwrap();
        assert_eq!(got_dir_bad.tx_lsn, a1.tx_lsn);
        assert_eq!(page(&r_dir_bad, 1), body(1, 1));
        assert!(r_dir_bad.last_recovery_fell_back_epoch());

        // 4. Damaging `a2`'s superblock sector directly while `CWAL_BASE_LBA` still proves
        //    `a2.tx_lsn` existed ALSO reports `last_recovery_fell_back_epoch() == true`.
        let a2_sb_lba = if a2_slot == 0 {
            SUPERBLOCK_A_LBA
        } else {
            SUPERBLOCK_B_LBA
        };
        let mut disk_sb_bad = clone_disk(&disk);
        disk_sb_bad.poke(a2_sb_lba, |sec| sec[20] ^= 0xAA);
        let mut r_sb_bad = PagedBlockStore::new();
        let got_sb_bad = r_sb_bad
            .recover_latest(&mut disk_sb_bad, &key())
            .unwrap()
            .unwrap();
        assert_eq!(got_sb_bad.tx_lsn, a1.tx_lsn);
        assert!(r_sb_bad.last_recovery_fell_back_epoch());
    }

    #[test]
    fn paged_store_v2_scales_to_1024_pages_and_persists_all_16384_sql_rows_plus_vfs() {
        use crate::shell::OsShell;
        use crate::state_store::{
            BootOutcome, ShellKeys, ShellStore, AHCI_QUARANTINE_LBA, AHCI_STATE_LAYOUT,
        };
        use cuttle_contracts::{Filesystem, FS_O_CREATE, FS_O_RDWR};

        // v1 disks (< 8 MiB / 16,384 sectors) remain unchanged at 118 and 256 logical pages.
        assert_eq!(PagedBlockStore::max_logical_pages_for_sectors(4096), 118);
        assert_eq!(PagedBlockStore::max_logical_pages_for_sectors(8192), 256);

        // v2 disks (>= 8 MiB / 16,384 sectors) lift the directory ceiling to support >= 880..1,024 pages!
        assert!(PagedBlockStore::max_logical_pages_for_sectors(16_384) >= 880);
        assert_eq!(PagedBlockStore::max_logical_pages_for_sectors(24_576), 1024);

        // Verify v2 `configure_for_sectors` enforces `0..1024` and rejects `1024`.
        let mut raw_v2 = PagedBlockStore::new();
        assert_eq!(
            raw_v2.put_page(256, PageDomain::VfsData, 0, 0, b"v1-reject"),
            Err(PagedStoreError::InvalidPageId)
        );
        raw_v2.configure_for_sectors(24_576);
        assert!(raw_v2.put_page(1023, PageDomain::VfsData, 0, 0, b"v2-ok").is_ok());
        assert_eq!(
            raw_v2.put_page(1024, PageDomain::VfsData, 0, 0, b"v2-reject"),
            Err(PagedStoreError::InvalidPageId)
        );

        // Full scale proof on a 12 MiB (24,576-sector) disk: all 8 SQL tables x 2,048 rows
        // (16,384 rows = 513 SQL pages) + 8 x 32 KiB VFS files (256 KiB = 65 VFS pages) fit together!
        let mut disk = MemDisk::new(24_576);
        let keys = ShellKeys {
            seal: key(),
            legacy_seal: [0x22; 32],
            attest: [0x33; 32],
        };
        let mut store = ShellStore::new(AHCI_STATE_LAYOUT, AHCI_QUARANTINE_LBA);
        let mut sh = OsShell::empty();
        let boot = store.boot(&mut disk, &mut sh, &keys, 1).unwrap();
        assert_eq!(boot.outcome, BootOutcome::Fresh);
        assert_eq!(sh.paged_max_logical(), 1024);

        let mut out = [0u8; 256];
        // Create 6 more tables so all 8 SQL table slots (`services`, `kv`, `t2..t7`) exist.
        for t in 2..8 {
            let ddl = alloc::format!("sql CREATE TABLE t{t} (id INT, tag TEXT)");
            let act = sh.exec_line(ddl.as_bytes(), 1, 0, 0, &mut out);
            assert!(out[..act.bytes_written()].ends_with(b" OK\n"));
        }
        // Fill all 8 tables to their full 2,048-row maximum (16,384 total rows).
        let svc_existing = sh.db.table_at(0).row_count();
        for i in svc_existing..2048 {
            let ins = alloc::format!("INSERT INTO services VALUES ({i}, 'svc_{i}', 8000, 'TCP')");
            let n = sh.db.exec(ins.as_bytes(), &mut out);
            assert_eq!(&out[..n], b"INSERT 1\n");
        }
        let kv_existing = sh.db.table_at(1).row_count();
        for i in kv_existing..2048 {
            let ins = alloc::format!("INSERT INTO kv VALUES ('k_{i}', 'v_{i}', {i})");
            let n = sh.db.exec(ins.as_bytes(), &mut out);
            assert_eq!(&out[..n], b"INSERT 1\n");
        }
        for t in 2..8 {
            for i in 0..2048 {
                let ins = alloc::format!("INSERT INTO t{t} VALUES ({i}, 'row_{t}_{i}')");
                let n = sh.db.exec(ins.as_bytes(), &mut out);
                assert_eq!(&out[..n], b"INSERT 1\n");
            }
        }
        assert_eq!(sh.db.total_rows(), 16_384);
        sh.sync_paged_budgets();

        // Also write 255 KiB of user VFS files alongside the 16,384 SQL rows.
        let blob = alloc::vec![0x5Au8; 32 * 1024];
        for f in 0..7 {
            let p = alloc::format!("/data/vol_{f}.bin");
            let h = sh.fs.open(p.as_bytes(), FS_O_CREATE | FS_O_RDWR).unwrap();
            assert_eq!(sh.fs.write(h, 0, &blob).unwrap(), blob.len());
            sh.fs.close(h).unwrap();
        }
        sh.sync_paged_budgets();

        store.commit(&mut disk, &mut sh, 1).unwrap();
        let expected_hash = sh.db.state_hash();
        assert!(store.paged_store().allocated_page_count() > 550);

        // Verify Merkle proof at a logical page index >= 256 (`lid = 550`).
        let proof = store.paged_store().merkle_proof(550).expect("v2 merkle proof >= 256");
        assert!(verify_dir_merkle_proof(&proof, &store.paged_store().merkle_root()));

        // Reboot into a clean shell and verify every single row and VFS file survived!
        let mut store2 = ShellStore::new(AHCI_STATE_LAYOUT, AHCI_QUARANTINE_LBA);
        let mut sh2 = OsShell::empty();
        let boot2 = store2.boot(&mut disk, &mut sh2, &keys, 2).unwrap();
        assert!(matches!(boot2.outcome, BootOutcome::Restored { .. }));
        assert_eq!(sh2.db.total_rows(), 16_384);
        assert_eq!(sh2.db.state_hash(), expected_hash);
        assert_eq!(sh2.fs.stat(b"/data/vol_6.bin").unwrap().size, 32 * 1024);
    }
}
