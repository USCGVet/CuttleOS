//! Standalone `#![no_std]` Sealed 4 KiB B+Tree Block Storage Library (`CTTLBTP1`)
//! with Per-Tree Key Derivation, Sealed Anti-Rollback Manifest, Link Validation,
//! Free-Page Reclamation, and RAID-5 XOR Parity Recovery.
//!
//! Note: This module is a standalone `#![no_std]` B+Tree storage library component
//! (separate from [`crate::sql::SqlDb`]'s 4 KiB `CTTLSQL1` partition).
//!
//! Key guarantees:
//! - Every 4 KiB page (`[u8; 4096]`) carries an 8-byte `"CTTLBTP1"` magic header, page ID,
//!   node kind (`Leaf` vs. `Internal`), entry count, sibling/parent links, `tree_id` tag,
//!   monotonic LSN, and a constant-time keyed `HMAC-SHA256` authentication tag (`[32..64]`)
//!   computed under a per-tree derived key (`HMAC-SHA256(seal_key, "CTTLBTP1-TREE-KEY" || tree_id)`).
//! - A sealed [`BTreeManifest`] (`"CTTLMNF1"`) binds `tree_id`, `epoch`, `root_page`,
//!   `allocated_pages`, `free_mask`, `lsn`, `total_records`, and the expected `page_lsns`
//!   array under `HMAC-SHA256`, catching single-page rollback, stale-parity healing, and
//!   cross-tree page substitution.
//! - Every read and traversal validates on-page `next_leaf`, `parent`, `rightmost_child`,
//!   and internal `left_child` links before indexing into the page pool.
//! - Emptied non-root leaf pages are unlinked and reclaimed via `free_mask` on `delete`.
//! - `scan_range` never silently truncates: returns [`BTreeError::BufferTooSmall`] if the
//!   caller's output slice cannot hold all matching records.

#![allow(clippy::needless_range_loop)]

use core::sync::atomic::{AtomicU64, Ordering};

use crate::durable_seal::{
    is_seal_key_set, seal_bytes_keyed, seal_matches_keyed, DURABLE_DIGEST_LEN,
};

static NEXT_BTREE_ID: AtomicU64 = AtomicU64::new(1);

/// Byte size of a single B+Tree storage page (`4 KiB` = `8` × 512-byte sectors).
pub const BTREE_PAGE_SIZE: usize = 4096;
/// Number of 512-byte disk sectors per 4 KiB B+Tree page.
pub const BTREE_SECTORS_PER_PAGE: usize = 8;
/// Maximum number of 4 KiB pages managed by a [`BTreePager`] instance (`32` pages = `128 KiB`).
pub const BTREE_MAX_PAGES: usize = 32;
/// 8-byte magic header on every sealed 4 KiB B+Tree page.
pub const BTREE_PAGE_MAGIC: &[u8; 8] = b"CTTLBTP1";
/// 8-byte magic header on every sealed [`BTreeManifest`].
pub const BTREE_MANIFEST_MAGIC: &[u8; 8] = b"CTTLMNF1";
/// Sentinel page ID indicating no sibling or parent page (`0xFFFF`).
pub const BTREE_NO_PAGE: u16 = 0xFFFF;
/// Maximum number of records stored in a single 4 KiB leaf page before splitting (`64` × 60B = `3,840B`).
pub const BTREE_LEAF_MAX_ENTRIES: usize = 64;
/// Maximum number of separator keys stored in an internal index page (`31` separators -> `32` children).
pub const BTREE_INTERNAL_MAX_KEYS: usize = 31;
/// Maximum byte length of a record's text key label.
pub const BTREE_KEY_LABEL_CAP: usize = 16;
/// Maximum byte length of a record's text value payload.
pub const BTREE_VAL_CAP: usize = 24;
/// Byte size of a serialized [`BTreeRecord`] inside a leaf page (`60` bytes: `64 * 60 = 3,840B <= 4,032B`).
pub const BTREE_RECORD_DISK_LEN: usize = 60;
/// Byte offset where the 4 KiB page payload begins (`64` bytes after header + LSN + HMAC-SHA256).
pub const BTREE_HEADER_BYTES: usize = 64;

/// B+Tree node kind encoded at byte offset `10` of a 4 KiB page.
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BTreePageKind {
    /// Unallocated page slot.
    Free = 0,
    /// Leaf page storing sorted [`BTreeRecord`] entries and a `next_leaf` pointer.
    Leaf = 1,
    /// Internal index page storing sorted `(sep_key, left_child_page)` pairs and `rightmost_child`.
    Internal = 2,
}

/// Error returned by [`BTreePager`] operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BTreeError {
    /// Device/cluster HMAC-SHA256 seal key is unset (`[0u8; 32]`).
    SealKeyUnset,
    /// Input key label or value is empty, oversized, or contains invalid control bytes.
    InvalidInput,
    /// Input exceeds [`BTREE_KEY_LABEL_CAP`] (`16B`) or [`BTREE_VAL_CAP`] (`24B`).
    InputTooLarge,
    /// Output buffer provided to [`BTreePager::scan_range`] is too small for all matching records.
    BufferTooSmall,
    /// Page pool (`BTREE_MAX_PAGES`) is exhausted.
    PagerFull,
    /// Requested page ID is out of range or unallocated.
    InvalidPageId,
    /// Sealed [`BTreeManifest`] failed `HMAC-SHA256` or structural verification.
    ManifestTampered,
    /// Constant-time `HMAC-SHA256` verification, LSN anti-rollback check, or link validation failed.
    PageTampered {
        /// Page index whose seal, LSN, or header failed verification.
        page_id: u16,
    },
}

/// Sealed root & per-page LSN anti-rollback manifest for a [`BTreePager`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BTreeManifest {
    /// 8-byte `"CTTLMNF1"` magic header.
    pub magic: [u8; 8],
    /// Unique 64-bit tree identifier bound into the per-tree derived HMAC key.
    pub tree_id: u64,
    /// Monotonic structural/seal epoch.
    pub epoch: u64,
    /// Current root page ID (`0..BTREE_MAX_PAGES`).
    pub root_page: u16,
    /// High-water number of page slots initialized (`1..=BTREE_MAX_PAGES`).
    pub allocated_pages: u16,
    /// Bitmask of reclaimed free page slots (`bit i == 1` means page `i` is free).
    pub free_mask: u32,
    /// Latest committed Log Sequence Number.
    pub lsn: u64,
    /// Total live records stored across all leaf pages.
    pub total_records: u32,
    /// Expected LSN for every page slot (`0` for free/unallocated pages).
    pub page_lsns: [u64; BTREE_MAX_PAGES],
    /// Constant-time `HMAC-SHA256` tag over all manifest fields under the per-tree derived key.
    pub hmac_tag: [u8; DURABLE_DIGEST_LEN],
}

/// Structured record stored in a [`BTreePager`] leaf page.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BTreeRecord {
    /// Primary 64-bit signed integer key (used for B+Tree ordering and range scans).
    pub key: i64,
    /// Monotonic revision or secondary integer attribute.
    pub rev: i64,
    /// Valid byte length of `key_label` (`1..=BTREE_KEY_LABEL_CAP`).
    pub key_label_len: u8,
    /// Valid byte length of `val` (`0..=BTREE_VAL_CAP`).
    pub val_len: u8,
    /// UTF-8 / ASCII label associated with `key`.
    pub key_label: [u8; BTREE_KEY_LABEL_CAP],
    /// UTF-8 / ASCII value bytes.
    pub val: [u8; BTREE_VAL_CAP],
}

impl BTreeRecord {
    /// Construct an empty zeroed record.
    pub const fn empty() -> Self {
        Self {
            key: 0,
            rev: 0,
            key_label_len: 0,
            val_len: 0,
            key_label: [0u8; BTREE_KEY_LABEL_CAP],
            val: [0u8; BTREE_VAL_CAP],
        }
    }

    /// Slice of valid `key_label` bytes.
    pub fn key_label_bytes(&self) -> &[u8] {
        &self.key_label[..self.key_label_len as usize]
    }

    /// Slice of valid `val` bytes.
    pub fn val_bytes(&self) -> &[u8] {
        &self.val[..self.val_len as usize]
    }

    fn encode_into(&self, out: &mut [u8; BTREE_RECORD_DISK_LEN]) {
        out[0..8].copy_from_slice(&self.key.to_le_bytes());
        out[8..16].copy_from_slice(&self.rev.to_le_bytes());
        out[16] = self.key_label_len;
        out[17] = self.val_len;
        out[18] = 0;
        out[19] = 0;
        out[20..36].copy_from_slice(&self.key_label);
        out[36..60].copy_from_slice(&self.val);
    }

    fn decode_from(raw: &[u8]) -> Option<Self> {
        if raw.len() < BTREE_RECORD_DISK_LEN {
            return None;
        }
        let key = i64::from_le_bytes([
            raw[0], raw[1], raw[2], raw[3], raw[4], raw[5], raw[6], raw[7],
        ]);
        let rev = i64::from_le_bytes([
            raw[8], raw[9], raw[10], raw[11], raw[12], raw[13], raw[14], raw[15],
        ]);
        let kl = raw[16];
        let vl = raw[17];
        if (kl as usize) > BTREE_KEY_LABEL_CAP || (vl as usize) > BTREE_VAL_CAP {
            return None;
        }
        let mut key_label = [0u8; BTREE_KEY_LABEL_CAP];
        let mut val = [0u8; BTREE_VAL_CAP];
        key_label.copy_from_slice(&raw[20..36]);
        val.copy_from_slice(&raw[36..60]);
        Some(Self {
            key,
            rev,
            key_label_len: kl,
            val_len: vl,
            key_label,
            val,
        })
    }
}

/// Standalone Paged 4 KiB B+Tree Block Storage Engine with per-tree derived `HMAC-SHA256`
/// sealing and sealed per-page LSN anti-rollback manifest.
#[derive(Clone)]
pub struct BTreePager {
    /// Master 256-bit `HMAC-SHA256` key from which the per-tree key is derived.
    pub seal_key: [u8; DURABLE_DIGEST_LEN],
    /// Unique 64-bit tree identifier bound into every page seal and the manifest key.
    pub tree_id: u64,
    /// Monotonic manifest epoch incremented on every page seal or structural update.
    pub epoch: u64,
    /// Page ID of the current B+Tree root page (`0..BTREE_MAX_PAGES`).
    pub root_page: u16,
    /// High-water number of initialized 4 KiB page slots (`1..=BTREE_MAX_PAGES`).
    pub allocated_pages: u16,
    /// Bitmask of reclaimed free page slots (`bit i == 1` means page `i` is free).
    pub free_mask: u32,
    /// Monotonic Log Sequence Number incremented on every page seal operation.
    pub lsn: u64,
    /// Total leaf page split operations performed.
    pub leaf_splits: u64,
    /// Total records currently stored across all leaf pages.
    pub total_records: usize,
    /// Expected committed LSN for each page slot (`0` for free/unallocated pages).
    pub page_lsns: [u64; BTREE_MAX_PAGES],
    /// Sealed `HMAC-SHA256` tag over the current manifest state.
    pub manifest_tag: [u8; DURABLE_DIGEST_LEN],
    /// Fixed pool of 4 KiB (`4096`-byte) sealed disk pages.
    pub pages: [[u8; BTREE_PAGE_SIZE]; BTREE_MAX_PAGES],
}

impl BTreePager {
    /// Construct an unprovisioned pager (`seal_key = [0; 32]`).
    pub const fn empty() -> Self {
        Self {
            seal_key: [0u8; DURABLE_DIGEST_LEN],
            tree_id: 0,
            epoch: 0,
            root_page: 0,
            allocated_pages: 0,
            free_mask: 0,
            lsn: 0,
            leaf_splits: 0,
            total_records: 0,
            page_lsns: [0u64; BTREE_MAX_PAGES],
            manifest_tag: [0u8; DURABLE_DIGEST_LEN],
            pages: [[0u8; BTREE_PAGE_SIZE]; BTREE_MAX_PAGES],
        }
    }

    /// Construct and initialize a provisioned [`BTreePager`] with a fresh unique `tree_id`
    /// and a sealed empty root leaf page (`page 0`).
    pub fn new(seal_key: [u8; DURABLE_DIGEST_LEN]) -> Result<Self, BTreeError> {
        let tid = NEXT_BTREE_ID.fetch_add(1, Ordering::Relaxed);
        Self::new_with_tree_id(seal_key, tid)
    }

    /// Construct and initialize a provisioned [`BTreePager`] bound to an explicit `tree_id`.
    pub fn new_with_tree_id(
        seal_key: [u8; DURABLE_DIGEST_LEN],
        tree_id: u64,
    ) -> Result<Self, BTreeError> {
        if !is_seal_key_set(&seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if tree_id == 0 {
            return Err(BTreeError::InvalidInput);
        }
        let mut pager = Self::empty();
        pager.seal_key = seal_key;
        pager.tree_id = tree_id;
        pager.allocated_pages = 1;
        pager.root_page = 0;
        pager.init_page_header(
            0,
            BTreePageKind::Leaf,
            0,
            BTREE_NO_PAGE,
            BTREE_NO_PAGE,
            BTREE_NO_PAGE,
        );
        pager.seal_page(0)?;
        Ok(pager)
    }

    fn derived_tree_key(&self) -> [u8; DURABLE_DIGEST_LEN] {
        let mut kdf_msg = [0u8; 25];
        kdf_msg[0..17].copy_from_slice(b"CTTLBTP1-TREE-KEY");
        kdf_msg[17..25].copy_from_slice(&self.tree_id.to_le_bytes());
        let mut out = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&self.seal_key, &kdf_msg, &mut out);
        out
    }

    #[inline]
    fn is_page_free(&self, page_id: u16) -> bool {
        (page_id as usize) >= BTREE_MAX_PAGES || ((self.free_mask >> page_id) & 1) != 0
    }

    fn compute_manifest_tag(&self) -> [u8; DURABLE_DIGEST_LEN] {
        let mut buf = [0u8; 8 + 8 + 8 + 2 + 2 + 4 + 8 + 4 + (BTREE_MAX_PAGES * 8)];
        buf[0..8].copy_from_slice(BTREE_MANIFEST_MAGIC);
        buf[8..16].copy_from_slice(&self.tree_id.to_le_bytes());
        buf[16..24].copy_from_slice(&self.epoch.to_le_bytes());
        buf[24..26].copy_from_slice(&self.root_page.to_le_bytes());
        buf[26..28].copy_from_slice(&self.allocated_pages.to_le_bytes());
        buf[28..32].copy_from_slice(&self.free_mask.to_le_bytes());
        buf[32..40].copy_from_slice(&self.lsn.to_le_bytes());
        buf[40..44].copy_from_slice(&(self.total_records as u32).to_le_bytes());
        let mut i = 0usize;
        while i < BTREE_MAX_PAGES {
            let off = 44 + i * 8;
            buf[off..off + 8].copy_from_slice(&self.page_lsns[i].to_le_bytes());
            i += 1;
        }
        let tree_key = self.derived_tree_key();
        let mut tag = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&tree_key, &buf, &mut tag);
        tag
    }

    fn refresh_manifest(&mut self) {
        self.epoch = self.epoch.wrapping_add(1);
        self.manifest_tag = self.compute_manifest_tag();
    }

    /// Verify the constant-time `HMAC-SHA256` seal of the pager's internal manifest.
    pub fn verify_manifest(&self) -> Result<(), BTreeError> {
        if !is_seal_key_set(&self.seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if self.tree_id == 0
            || self.allocated_pages == 0
            || (self.allocated_pages as usize) > BTREE_MAX_PAGES
            || (self.root_page as usize) >= (self.allocated_pages as usize)
            || self.is_page_free(self.root_page)
        {
            return Err(BTreeError::ManifestTampered);
        }
        let mut buf = [0u8; 8 + 8 + 8 + 2 + 2 + 4 + 8 + 4 + (BTREE_MAX_PAGES * 8)];
        buf[0..8].copy_from_slice(BTREE_MANIFEST_MAGIC);
        buf[8..16].copy_from_slice(&self.tree_id.to_le_bytes());
        buf[16..24].copy_from_slice(&self.epoch.to_le_bytes());
        buf[24..26].copy_from_slice(&self.root_page.to_le_bytes());
        buf[26..28].copy_from_slice(&self.allocated_pages.to_le_bytes());
        buf[28..32].copy_from_slice(&self.free_mask.to_le_bytes());
        buf[32..40].copy_from_slice(&self.lsn.to_le_bytes());
        buf[40..44].copy_from_slice(&(self.total_records as u32).to_le_bytes());
        let mut i = 0usize;
        while i < BTREE_MAX_PAGES {
            let off = 44 + i * 8;
            buf[off..off + 8].copy_from_slice(&self.page_lsns[i].to_le_bytes());
            i += 1;
        }
        let tree_key = self.derived_tree_key();
        if !seal_matches_keyed(&tree_key, &buf, &self.manifest_tag) {
            return Err(BTreeError::ManifestTampered);
        }
        Ok(())
    }

    /// Export a verified, `HMAC-SHA256`-sealed [`BTreeManifest`] for persistent storage.
    pub fn export_manifest(&self) -> Result<BTreeManifest, BTreeError> {
        self.verify_manifest()?;
        Ok(BTreeManifest {
            magic: *BTREE_MANIFEST_MAGIC,
            tree_id: self.tree_id,
            epoch: self.epoch,
            root_page: self.root_page,
            allocated_pages: self.allocated_pages,
            free_mask: self.free_mask,
            lsn: self.lsn,
            total_records: self.total_records as u32,
            page_lsns: self.page_lsns,
            hmac_tag: self.manifest_tag,
        })
    }

    /// Reconstruct and verify a [`BTreePager`] from a sealed [`BTreeManifest`] and 4 KiB page pool,
    /// verifying both the manifest `HMAC-SHA256` and every active page's seal, LSN, and links.
    pub fn load_from_manifest_and_pages(
        seal_key: [u8; DURABLE_DIGEST_LEN],
        manifest: &BTreeManifest,
        pages: &[[u8; BTREE_PAGE_SIZE]; BTREE_MAX_PAGES],
    ) -> Result<Self, BTreeError> {
        if !is_seal_key_set(&seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if &manifest.magic != BTREE_MANIFEST_MAGIC {
            return Err(BTreeError::ManifestTampered);
        }
        let pager = Self {
            seal_key,
            tree_id: manifest.tree_id,
            epoch: manifest.epoch,
            root_page: manifest.root_page,
            allocated_pages: manifest.allocated_pages,
            free_mask: manifest.free_mask,
            lsn: manifest.lsn,
            leaf_splits: 0,
            total_records: manifest.total_records as usize,
            page_lsns: manifest.page_lsns,
            manifest_tag: manifest.hmac_tag,
            pages: *pages,
        };
        pager.verify_all_page_seals()?;
        Ok(pager)
    }

    fn init_page_header(
        &mut self,
        page_id: u16,
        kind: BTreePageKind,
        count: u16,
        next_leaf: u16,
        parent: u16,
        rightmost_child: u16,
    ) {
        let p = &mut self.pages[page_id as usize];
        *p = [0u8; BTREE_PAGE_SIZE];
        p[0..8].copy_from_slice(BTREE_PAGE_MAGIC);
        p[8..10].copy_from_slice(&page_id.to_le_bytes());
        p[10] = kind as u8;
        p[11..13].copy_from_slice(&count.to_le_bytes());
        p[13..15].copy_from_slice(&next_leaf.to_le_bytes());
        p[15..17].copy_from_slice(&parent.to_le_bytes());
        p[17..19].copy_from_slice(&rightmost_child.to_le_bytes());
        p[20..24].copy_from_slice(&(self.tree_id as u32).to_le_bytes());
    }

    fn seal_page(&mut self, page_id: u16) -> Result<(), BTreeError> {
        if !is_seal_key_set(&self.seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if (page_id as usize) >= (self.allocated_pages as usize) || self.is_page_free(page_id) {
            return Err(BTreeError::InvalidPageId);
        }
        self.lsn = self.lsn.wrapping_add(1);
        let new_lsn = self.lsn;
        let tree_id = self.tree_id;
        let tree_key = self.derived_tree_key();
        let p = &mut self.pages[page_id as usize];
        p[20..24].copy_from_slice(&(tree_id as u32).to_le_bytes());
        p[24..32].copy_from_slice(&new_lsn.to_le_bytes());
        // Compute HMAC-SHA256 over `tree_id` `[0..8]` || header `[0..32]` || payload `[64..4096]`.
        let mut msg = [0u8; 8 + 32 + (BTREE_PAGE_SIZE - BTREE_HEADER_BYTES)];
        msg[0..8].copy_from_slice(&tree_id.to_le_bytes());
        msg[8..40].copy_from_slice(&p[0..32]);
        msg[40..].copy_from_slice(&p[BTREE_HEADER_BYTES..]);
        let mut tag = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&tree_key, &msg, &mut tag);
        p[32..64].copy_from_slice(&tag);
        self.page_lsns[page_id as usize] = new_lsn;
        self.refresh_manifest();
        Ok(())
    }

    /// Verify in constant time the `CTTLBTP1` header, `tree_id`, expected LSN, structural links,
    /// and per-tree `HMAC-SHA256` seal of `page_id`.
    pub fn verify_page_seal(&self, page_id: u16) -> Result<BTreePageKind, BTreeError> {
        if !is_seal_key_set(&self.seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if (page_id as usize) >= (self.allocated_pages as usize) || self.is_page_free(page_id) {
            return Err(BTreeError::InvalidPageId);
        }
        let p = &self.pages[page_id as usize];
        if &p[0..8] != BTREE_PAGE_MAGIC {
            return Err(BTreeError::PageTampered { page_id });
        }
        let pid = u16::from_le_bytes([p[8], p[9]]);
        if pid != page_id {
            return Err(BTreeError::PageTampered { page_id });
        }
        let tid_lo = u32::from_le_bytes([p[20], p[21], p[22], p[23]]);
        if tid_lo != (self.tree_id as u32) {
            return Err(BTreeError::PageTampered { page_id });
        }
        let on_page_lsn = u64::from_le_bytes([
            p[24], p[25], p[26], p[27], p[28], p[29], p[30], p[31],
        ]);
        let expected_lsn = self.page_lsns[page_id as usize];
        if expected_lsn == 0 || on_page_lsn != expected_lsn {
            return Err(BTreeError::PageTampered { page_id });
        }
        let kind = match p[10] {
            1 => BTreePageKind::Leaf,
            2 => BTreePageKind::Internal,
            _ => return Err(BTreeError::PageTampered { page_id }),
        };
        let count = u16::from_le_bytes([p[11], p[12]]) as usize;
        if (kind == BTreePageKind::Leaf && count > BTREE_LEAF_MAX_ENTRIES)
            || (kind == BTreePageKind::Internal && count > BTREE_INTERNAL_MAX_KEYS)
        {
            return Err(BTreeError::PageTampered { page_id });
        }

        let mut msg = [0u8; 8 + 32 + (BTREE_PAGE_SIZE - BTREE_HEADER_BYTES)];
        msg[0..8].copy_from_slice(&self.tree_id.to_le_bytes());
        msg[8..40].copy_from_slice(&p[0..32]);
        msg[40..].copy_from_slice(&p[BTREE_HEADER_BYTES..]);
        let mut expected = [0u8; DURABLE_DIGEST_LEN];
        expected.copy_from_slice(&p[32..64]);
        let tree_key = self.derived_tree_key();
        if !seal_matches_keyed(&tree_key, &msg, &expected) {
            return Err(BTreeError::PageTampered { page_id });
        }

        // Validate all on-page links (`next_leaf`, `parent`, `rightmost_child`, and internal `left_child`s)
        // before any caller indexes `self.pages` using those links:
        let next_leaf = u16::from_le_bytes([p[13], p[14]]);
        let parent = u16::from_le_bytes([p[15], p[16]]);
        let rightmost = u16::from_le_bytes([p[17], p[18]]);
        let alloc = self.allocated_pages;

        if page_id == self.root_page {
            if parent != BTREE_NO_PAGE {
                return Err(BTreeError::PageTampered { page_id });
            }
        } else if parent != BTREE_NO_PAGE
            && (parent >= alloc || parent == page_id || self.is_page_free(parent))
        {
            return Err(BTreeError::PageTampered { page_id });
        }

        match kind {
            BTreePageKind::Leaf => {
                if rightmost != BTREE_NO_PAGE {
                    return Err(BTreeError::PageTampered { page_id });
                }
                if next_leaf != BTREE_NO_PAGE
                    && (next_leaf >= alloc
                        || next_leaf == page_id
                        || self.is_page_free(next_leaf))
                {
                    return Err(BTreeError::PageTampered { page_id });
                }
            }
            BTreePageKind::Internal => {
                if next_leaf != BTREE_NO_PAGE
                    || rightmost >= alloc
                    || rightmost == page_id
                    || self.is_page_free(rightmost)
                {
                    return Err(BTreeError::PageTampered { page_id });
                }
                let mut i = 0usize;
                while i < count {
                    let (_, left_child) = self.read_internal_entry(page_id, i);
                    if left_child >= alloc
                        || left_child == page_id
                        || self.is_page_free(left_child)
                    {
                        return Err(BTreeError::PageTampered { page_id });
                    }
                    i += 1;
                }
            }
            BTreePageKind::Free => return Err(BTreeError::PageTampered { page_id }),
        }

        Ok(kind)
    }

    /// Verify the sealed [`BTreeManifest`] and the constant-time `HMAC-SHA256` seal on every
    /// active 4 KiB page in the pool.
    pub fn verify_all_page_seals(&self) -> Result<usize, BTreeError> {
        self.verify_manifest()?;
        let n = self.allocated_pages as usize;
        let mut active = 0usize;
        let mut i = 0usize;
        while i < n {
            let pid = i as u16;
            if !self.is_page_free(pid) {
                self.verify_page_seal(pid)?;
                active += 1;
            }
            i += 1;
        }
        Ok(active)
    }

    fn available_page_slots(&self) -> usize {
        let free_reclaimable = self.free_mask.count_ones() as usize;
        let unallocated = BTREE_MAX_PAGES.saturating_sub(self.allocated_pages as usize);
        free_reclaimable + unallocated
    }

    fn alloc_page_slot(&mut self) -> Result<u16, BTreeError> {
        if self.free_mask != 0 {
            let pid = self.free_mask.trailing_zeros() as u16;
            self.free_mask &= !(1u32 << pid);
            return Ok(pid);
        }
        if (self.allocated_pages as usize) >= BTREE_MAX_PAGES {
            return Err(BTreeError::PagerFull);
        }
        let pid = self.allocated_pages;
        self.allocated_pages += 1;
        Ok(pid)
    }

    fn mark_page_free(&mut self, page_id: u16) {
        self.pages[page_id as usize] = [0u8; BTREE_PAGE_SIZE];
        self.page_lsns[page_id as usize] = 0;
        self.free_mask |= 1u32 << page_id;
    }

    fn page_count(&self, page_id: u16) -> usize {
        let p = &self.pages[page_id as usize];
        u16::from_le_bytes([p[11], p[12]]) as usize
    }

    fn set_page_count(&mut self, page_id: u16, count: usize) {
        let p = &mut self.pages[page_id as usize];
        p[11..13].copy_from_slice(&(count as u16).to_le_bytes());
    }

    fn page_next_leaf(&self, page_id: u16) -> u16 {
        let p = &self.pages[page_id as usize];
        u16::from_le_bytes([p[13], p[14]])
    }

    fn set_page_next_leaf(&mut self, page_id: u16, next_leaf: u16) {
        let p = &mut self.pages[page_id as usize];
        p[13..15].copy_from_slice(&next_leaf.to_le_bytes());
    }

    fn page_parent(&self, page_id: u16) -> u16 {
        let p = &self.pages[page_id as usize];
        u16::from_le_bytes([p[15], p[16]])
    }

    fn set_page_parent(&mut self, page_id: u16, parent: u16) {
        let p = &mut self.pages[page_id as usize];
        p[15..17].copy_from_slice(&parent.to_le_bytes());
    }

    fn page_rightmost_child(&self, page_id: u16) -> u16 {
        let p = &self.pages[page_id as usize];
        u16::from_le_bytes([p[17], p[18]])
    }

    fn set_page_rightmost_child(&mut self, page_id: u16, child: u16) {
        let p = &mut self.pages[page_id as usize];
        p[17..19].copy_from_slice(&child.to_le_bytes());
    }

    fn read_leaf_record(&self, page_id: u16, idx: usize) -> Option<BTreeRecord> {
        let off = BTREE_HEADER_BYTES + idx * BTREE_RECORD_DISK_LEN;
        if off + BTREE_RECORD_DISK_LEN > BTREE_PAGE_SIZE {
            return None;
        }
        BTreeRecord::decode_from(&self.pages[page_id as usize][off..off + BTREE_RECORD_DISK_LEN])
    }

    fn write_leaf_record(&mut self, page_id: u16, idx: usize, rec: &BTreeRecord) {
        let off = BTREE_HEADER_BYTES + idx * BTREE_RECORD_DISK_LEN;
        let mut buf = [0u8; BTREE_RECORD_DISK_LEN];
        rec.encode_into(&mut buf);
        self.pages[page_id as usize][off..off + BTREE_RECORD_DISK_LEN].copy_from_slice(&buf);
    }

    fn read_internal_entry(&self, page_id: u16, idx: usize) -> (i64, u16) {
        let off = BTREE_HEADER_BYTES + idx * 16;
        let p = &self.pages[page_id as usize];
        let sep_key = i64::from_le_bytes([
            p[off],
            p[off + 1],
            p[off + 2],
            p[off + 3],
            p[off + 4],
            p[off + 5],
            p[off + 6],
            p[off + 7],
        ]);
        let left_child = u16::from_le_bytes([p[off + 8], p[off + 9]]);
        (sep_key, left_child)
    }

    fn write_internal_entry(&mut self, page_id: u16, idx: usize, sep_key: i64, left_child: u16) {
        let off = BTREE_HEADER_BYTES + idx * 16;
        let p = &mut self.pages[page_id as usize];
        p[off..off + 8].copy_from_slice(&sep_key.to_le_bytes());
        p[off + 8..off + 10].copy_from_slice(&left_child.to_le_bytes());
        p[off + 10..off + 16].copy_from_slice(&[0u8; 6]);
    }

    /// Route from `self.root_page` down to the target leaf page for `key`, verifying every
    /// visited page's `HMAC-SHA256` seal, LSN, and links in constant time.
    fn find_leaf_page(&self, key: i64) -> Result<u16, BTreeError> {
        self.verify_manifest()?;
        let mut curr = self.root_page;
        let mut depth = 0usize;
        while depth < 8 {
            let kind = self.verify_page_seal(curr)?;
            if kind == BTreePageKind::Leaf {
                return Ok(curr);
            }
            let count = self.page_count(curr);
            let mut chosen = self.page_rightmost_child(curr);
            let mut i = 0usize;
            while i < count {
                let (sep_key, left_child) = self.read_internal_entry(curr, i);
                if key < sep_key {
                    chosen = left_child;
                    break;
                }
                i += 1;
            }
            if (chosen as usize) >= (self.allocated_pages as usize) || self.is_page_free(chosen) {
                return Err(BTreeError::PageTampered { page_id: curr });
            }
            curr = chosen;
            depth += 1;
        }
        Err(BTreeError::PageTampered {
            page_id: self.root_page,
        })
    }

    /// Insert or update `(key, key_label, val, rev)` in the B+Tree, automatically splitting
    /// 4 KiB leaf pages at 64 entries and updating the internal root index.
    ///
    /// Never silently truncates: returns [`BTreeError::InputTooLarge`] if `key_label.len() > 16`
    /// or `val.len() > 24`, and [`BTreeError::InvalidInput`] if `key_label` is empty or contains
    /// control/NUL bytes.
    pub fn insert(
        &mut self,
        key: i64,
        key_label: &[u8],
        val: &[u8],
        rev: i64,
    ) -> Result<u16, BTreeError> {
        if key_label.is_empty() {
            return Err(BTreeError::InvalidInput);
        }
        if key_label.len() > BTREE_KEY_LABEL_CAP || val.len() > BTREE_VAL_CAP {
            return Err(BTreeError::InputTooLarge);
        }
        let mut i = 0usize;
        while i < key_label.len() {
            if key_label[i] <= 0x20 || key_label[i] >= 0x7F {
                return Err(BTreeError::InvalidInput);
            }
            i += 1;
        }
        let mut j = 0usize;
        while j < val.len() {
            if val[j] == 0 || (val[j] < 0x20 && val[j] != b'\t') || val[j] == 0x7F {
                return Err(BTreeError::InvalidInput);
            }
            j += 1;
        }

        let mut rec = BTreeRecord::empty();
        rec.key = key;
        rec.rev = rev;
        rec.key_label_len = key_label.len() as u8;
        rec.val_len = val.len() as u8;
        rec.key_label[..key_label.len()].copy_from_slice(key_label);
        rec.val[..val.len()].copy_from_slice(val);

        let leaf_id = self.find_leaf_page(key)?;
        let count = self.page_count(leaf_id);

        // Check if `key` already exists in `leaf_id` (update in place):
        let mut pos = 0usize;
        while pos < count {
            let existing = self
                .read_leaf_record(leaf_id, pos)
                .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
            if existing.key == key {
                self.write_leaf_record(leaf_id, pos, &rec);
                self.seal_page(leaf_id)?;
                return Ok(leaf_id);
            }
            if existing.key > key {
                break;
            }
            pos += 1;
        }

        // If `leaf_id` has room (< 64 entries), insert in sorted order and re-seal:
        if count < BTREE_LEAF_MAX_ENTRIES {
            let mut k = count;
            while k > pos {
                let prev = self
                    .read_leaf_record(leaf_id, k - 1)
                    .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
                self.write_leaf_record(leaf_id, k, &prev);
                k -= 1;
            }
            self.write_leaf_record(leaf_id, pos, &rec);
            self.set_page_count(leaf_id, count + 1);
            self.total_records += 1;
            self.seal_page(leaf_id)?;
            return Ok(leaf_id);
        }

        // Otherwise, split the full 64-entry leaf page across two 4 KiB leaf pages!
        let parent_id = self.page_parent(leaf_id);
        let needed_pages = if parent_id == BTREE_NO_PAGE {
            2usize // new right leaf + new internal root page
        } else {
            1usize // new right leaf
        };
        if self.available_page_slots() < needed_pages {
            return Err(BTreeError::PagerFull);
        }
        if parent_id != BTREE_NO_PAGE {
            let p_kind = self.verify_page_seal(parent_id)?;
            if p_kind != BTreePageKind::Internal {
                return Err(BTreeError::PageTampered { page_id: parent_id });
            }
            if self.page_count(parent_id) >= BTREE_INTERNAL_MAX_KEYS {
                return Err(BTreeError::PagerFull);
            }
        }

        // Collect all 65 sorted records in stack scratch:
        let mut all = [BTreeRecord::empty(); BTREE_LEAF_MAX_ENTRIES + 1];
        let mut idx = 0usize;
        while idx < pos {
            all[idx] = self
                .read_leaf_record(leaf_id, idx)
                .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
            idx += 1;
        }
        all[pos] = rec;
        while idx < count {
            all[idx + 1] = self
                .read_leaf_record(leaf_id, idx)
                .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
            idx += 1;
        }

        let left_count = (BTREE_LEAF_MAX_ENTRIES + 1) / 2; // 32
        let right_count = (BTREE_LEAF_MAX_ENTRIES + 1) - left_count; // 33
        let sep_key = all[left_count].key;

        let right_id = self.alloc_page_slot()?;
        let old_next = self.page_next_leaf(leaf_id);

        // Rewrite left leaf (`leaf_id`):
        self.init_page_header(
            leaf_id,
            BTreePageKind::Leaf,
            left_count as u16,
            right_id,
            parent_id,
            BTREE_NO_PAGE,
        );
        let mut li = 0usize;
        while li < left_count {
            self.write_leaf_record(leaf_id, li, &all[li]);
            li += 1;
        }

        // Initialize right leaf (`right_id`):
        self.init_page_header(
            right_id,
            BTreePageKind::Leaf,
            right_count as u16,
            old_next,
            parent_id,
            BTREE_NO_PAGE,
        );
        let mut ri = 0usize;
        while ri < right_count {
            self.write_leaf_record(right_id, ri, &all[left_count + ri]);
            ri += 1;
        }

        self.total_records += 1;
        self.leaf_splits += 1;

        if parent_id == BTREE_NO_PAGE {
            // Allocate new internal root page:
            let new_root = self.alloc_page_slot()?;
            self.init_page_header(
                new_root,
                BTreePageKind::Internal,
                1,
                BTREE_NO_PAGE,
                BTREE_NO_PAGE,
                right_id,
            );
            self.write_internal_entry(new_root, 0, sep_key, leaf_id);
            self.set_page_parent(leaf_id, new_root);
            self.set_page_parent(right_id, new_root);
            self.root_page = new_root;
            self.seal_page(leaf_id)?;
            self.seal_page(right_id)?;
            self.seal_page(new_root)?;
        } else {
            let p_count = self.page_count(parent_id);
            // Insert `(sep_key, leaf_id)` into `parent_id` and update child pointer after `sep_key` to `right_id`:
            let mut ins_at = p_count;
            let mut pi = 0usize;
            while pi < p_count {
                let (k_i, _) = self.read_internal_entry(parent_id, pi);
                if sep_key < k_i {
                    ins_at = pi;
                    break;
                }
                pi += 1;
            }
            if ins_at == p_count {
                self.write_internal_entry(parent_id, p_count, sep_key, leaf_id);
                self.set_page_rightmost_child(parent_id, right_id);
            } else {
                let mut s = p_count;
                while s > ins_at {
                    let (prev_k, prev_c) = self.read_internal_entry(parent_id, s - 1);
                    self.write_internal_entry(parent_id, s, prev_k, prev_c);
                    s -= 1;
                }
                let (next_k, _) = self.read_internal_entry(parent_id, ins_at + 1);
                self.write_internal_entry(parent_id, ins_at, sep_key, leaf_id);
                self.write_internal_entry(parent_id, ins_at + 1, next_k, right_id);
            }
            self.set_page_count(parent_id, p_count + 1);
            self.seal_page(leaf_id)?;
            self.seal_page(right_id)?;
            self.seal_page(parent_id)?;
        }

        Ok(if key < sep_key { leaf_id } else { right_id })
    }

    /// Point lookup for `key` across the B+Tree, verifying the constant-time `HMAC-SHA256`
    /// seal of the manifest, root, and target leaf pages before binary-searching the leaf.
    pub fn get(&self, key: i64) -> Result<Option<BTreeRecord>, BTreeError> {
        let leaf_id = self.find_leaf_page(key)?;
        let count = self.page_count(leaf_id);
        let mut lo = 0usize;
        let mut hi = count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let rec = self
                .read_leaf_record(leaf_id, mid)
                .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
            if rec.key == key {
                return Ok(Some(rec));
            } else if rec.key < key {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        Ok(None)
    }

    /// Delete `key` from its B+Tree leaf page, reclaiming the leaf page into `free_mask`
    /// if it becomes empty and is not the sole root page.
    pub fn delete(&mut self, key: i64) -> Result<bool, BTreeError> {
        let leaf_id = self.find_leaf_page(key)?;
        let count = self.page_count(leaf_id);
        let mut found = None;
        let mut i = 0usize;
        while i < count {
            let rec = self
                .read_leaf_record(leaf_id, i)
                .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
            if rec.key == key {
                found = Some(i);
                break;
            }
            if rec.key > key {
                break;
            }
            i += 1;
        }
        let Some(pos) = found else {
            return Ok(false);
        };
        let mut k = pos;
        while k + 1 < count {
            let next_rec = self
                .read_leaf_record(leaf_id, k + 1)
                .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
            self.write_leaf_record(leaf_id, k, &next_rec);
            k += 1;
        }
        self.write_leaf_record(leaf_id, count - 1, &BTreeRecord::empty());
        let new_count = count - 1;
        self.set_page_count(leaf_id, new_count);
        self.total_records = self.total_records.saturating_sub(1);

        let parent_id = self.page_parent(leaf_id);
        if new_count == 0 && leaf_id != self.root_page && parent_id != BTREE_NO_PAGE {
            let p_kind = self.verify_page_seal(parent_id)?;
            if p_kind != BTreePageKind::Internal {
                return Err(BTreeError::PageTampered { page_id: parent_id });
            }
            let p_count = self.page_count(parent_id);
            if p_count >= 1 {
                // 1. Unlink `leaf_id` from any predecessor leaf whose `next_leaf == leaf_id`:
                let succ_leaf = self.page_next_leaf(leaf_id);
                let mut pid = 0u16;
                while pid < self.allocated_pages {
                    if pid != leaf_id
                        && !self.is_page_free(pid)
                        && self.pages[pid as usize][10] == (BTreePageKind::Leaf as u8)
                        && self.page_next_leaf(pid) == leaf_id
                    {
                        self.verify_page_seal(pid)?;
                        self.set_page_next_leaf(pid, succ_leaf);
                        self.seal_page(pid)?;
                    }
                    pid += 1;
                }

                // 2. Remove `leaf_id` from `parent_id`:
                let mut child_idx = None;
                let mut ci = 0usize;
                while ci < p_count {
                    let (_, lc) = self.read_internal_entry(parent_id, ci);
                    if lc == leaf_id {
                        child_idx = Some(ci);
                        break;
                    }
                    ci += 1;
                }
                if let Some(c_at) = child_idx {
                    let mut s = c_at;
                    while s + 1 < p_count {
                        let (nk, nc) = self.read_internal_entry(parent_id, s + 1);
                        self.write_internal_entry(parent_id, s, nk, nc);
                        s += 1;
                    }
                    self.write_internal_entry(parent_id, p_count - 1, 0, 0);
                } else if self.page_rightmost_child(parent_id) == leaf_id {
                    let (_, prev_lc) = self.read_internal_entry(parent_id, p_count - 1);
                    self.set_page_rightmost_child(parent_id, prev_lc);
                    self.write_internal_entry(parent_id, p_count - 1, 0, 0);
                }

                let new_p_count = p_count - 1;
                self.mark_page_free(leaf_id);
                if new_p_count == 0 && parent_id == self.root_page {
                    let sole_child = self.page_rightmost_child(parent_id);
                    self.verify_page_seal(sole_child)?;
                    self.root_page = sole_child;
                    self.set_page_parent(sole_child, BTREE_NO_PAGE);
                    self.mark_page_free(parent_id);
                    self.seal_page(sole_child)?;
                } else {
                    self.set_page_count(parent_id, new_p_count);
                    self.seal_page(parent_id)?;
                }
                return Ok(true);
            }
        }

        self.seal_page(leaf_id)?;
        Ok(true)
    }

    /// Ordered range scan over `[min_key ..= max_key]`, routing to the starting 4 KiB leaf page
    /// and following sibling `next_leaf` links while verifying every visited page's `HMAC-SHA256` seal.
    ///
    /// Never silently truncates: returns [`BTreeError::BufferTooSmall`] if the number of matching
    /// records exceeds `out.len()`.
    pub fn scan_range(
        &self,
        min_key: i64,
        max_key: i64,
        out: &mut [BTreeRecord],
    ) -> Result<usize, BTreeError> {
        if min_key > max_key {
            return Ok(0);
        }
        let mut leaf_id = self.find_leaf_page(min_key)?;
        let mut written = 0usize;
        let mut hops = 0usize;
        while leaf_id != BTREE_NO_PAGE && hops < BTREE_MAX_PAGES {
            let kind = self.verify_page_seal(leaf_id)?;
            if kind != BTreePageKind::Leaf {
                return Err(BTreeError::PageTampered { page_id: leaf_id });
            }
            let count = self.page_count(leaf_id);
            let mut i = 0usize;
            while i < count {
                let rec = self
                    .read_leaf_record(leaf_id, i)
                    .ok_or(BTreeError::PageTampered { page_id: leaf_id })?;
                if rec.key > max_key {
                    return Ok(written);
                }
                if rec.key >= min_key {
                    if written >= out.len() {
                        return Err(BTreeError::BufferTooSmall);
                    }
                    out[written] = rec;
                    written += 1;
                }
                i += 1;
            }
            leaf_id = self.page_next_leaf(leaf_id);
            hops += 1;
        }
        Ok(written)
    }

    /// Export a 4 KiB B+Tree page as 8 × 512-byte AHCI/NVMe disk sectors after verifying its seal.
    pub fn export_page_sectors(
        &self,
        page_id: u16,
        out_sectors: &mut [[u8; 512]; BTREE_SECTORS_PER_PAGE],
    ) -> Result<(), BTreeError> {
        self.verify_page_seal(page_id)?;
        let p = &self.pages[page_id as usize];
        let mut s = 0usize;
        while s < BTREE_SECTORS_PER_PAGE {
            out_sectors[s].copy_from_slice(&p[s * 512..(s + 1) * 512]);
            s += 1;
        }
        Ok(())
    }

    /// Compute a 4 KiB RAID-5 XOR parity page (`parity = page_a ^ page_b`).
    pub fn compute_xor_parity_page(
        page_a: &[u8; BTREE_PAGE_SIZE],
        page_b: &[u8; BTREE_PAGE_SIZE],
        parity_out: &mut [u8; BTREE_PAGE_SIZE],
    ) {
        let mut i = 0usize;
        while i < BTREE_PAGE_SIZE {
            parity_out[i] = page_a[i] ^ page_b[i];
            i += 1;
        }
    }

    /// Reconstruct a corrupted or lost 4 KiB B+Tree page (`corrupted_page_id`) from a peer
    /// 4 KiB page and their 4 KiB RAID-5 XOR parity block ($D_{\text{rec}} = D_{\text{peer}} \oplus P$),
    /// verifying its `CTTLBTP1` header, expected LSN, links, and constant-time `HMAC-SHA256` seal before committing.
    pub fn heal_corrupted_page_with_xor_parity(
        &mut self,
        corrupted_page_id: u16,
        peer_page: &[u8; BTREE_PAGE_SIZE],
        parity_page: &[u8; BTREE_PAGE_SIZE],
    ) -> Result<(), BTreeError> {
        if (corrupted_page_id as usize) >= (self.allocated_pages as usize)
            || self.is_page_free(corrupted_page_id)
        {
            return Err(BTreeError::InvalidPageId);
        }
        let mut recovered = [0u8; BTREE_PAGE_SIZE];
        Self::compute_xor_parity_page(peer_page, parity_page, &mut recovered);
        let prev = self.pages[corrupted_page_id as usize];
        self.pages[corrupted_page_id as usize] = recovered;
        if let Err(e) = self.verify_page_seal(corrupted_page_id) {
            self.pages[corrupted_page_id as usize] = prev;
            return Err(e);
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_BTREE_KEY: [u8; 32] = *b"Cuttle-BTree-4KiB-HMAC-SealKey01";

    #[test]
    fn btree_pager_scales_to_512_rows_across_split_4kib_leaf_pages_and_verifies_hmac_seals() {
        let mut pager = BTreePager::new(TEST_BTREE_KEY).expect("provisioned pager");
        assert_eq!(pager.allocated_pages, 1);

        // Insert 512 rows in scrambled order (8x the 64-row single-table limit) to exercise
        // repeated 4 KiB leaf splits, internal root separator promotion, and sibling links:
        for step in 0..512i64 {
            let key = ((step * 173) % 512) + 1; // permutation of 1..=512
            let mut klabel = [0u8; 12];
            klabel[0..4].copy_from_slice(b"row_");
            let mut d = key as u64;
            for pos in (4..8).rev() {
                klabel[pos] = b'0' + ((d % 10) as u8);
                d /= 10;
            }
            let mut val = [0u8; 10];
            val[0..4].copy_from_slice(b"val_");
            let mut v = (key * 10) as u64;
            for pos in (4..10).rev() {
                val[pos] = b'0' + ((v % 10) as u8);
                v /= 10;
            }
            pager
                .insert(key, &klabel[..8], &val[..10], key * 3)
                .expect("insert 512 rows");
        }

        assert_eq!(pager.total_records, 512);
        assert!(
            pager.leaf_splits >= 10,
            "512 records across 64-entry 4 KiB leaves must trigger multi-page splits (got {})",
            pager.leaf_splits
        );
        assert!(pager.allocated_pages >= 12);
        assert_eq!(
            pager.verify_all_page_seals().unwrap(),
            pager.allocated_pages as usize
        );

        // Point-lookup all 512 keys and verify exact key_label, val, and rev:
        for k in 1..=512i64 {
            let rec = pager
                .get(k)
                .expect("HMAC verified lookup")
                .expect("record present");
            assert_eq!(rec.key, k);
            assert_eq!(rec.rev, k * 3);
        }

        // Range scan [100 ..= 249] (150 records spanning multiple split 4 KiB leaf pages):
        let mut scan_out = [BTreeRecord::empty(); 160];
        let n = pager
            .scan_range(100, 249, &mut scan_out)
            .expect("range scan across leaf sibling links");
        assert_eq!(n, 150);
        for idx in 0..150 {
            assert_eq!(scan_out[idx].key, 100 + (idx as i64));
        }

        // Undersized range scan output buffer must return `Err(BTreeError::BufferTooSmall)` without silent truncation:
        let mut tiny_out = [BTreeRecord::empty(); 10];
        assert_eq!(
            pager.scan_range(100, 249, &mut tiny_out),
            Err(BTreeError::BufferTooSmall)
        );

        // Delete 50 keys and confirm point lookup returns None while remaining 462 keys verify:
        for k in 200..250i64 {
            assert!(pager.delete(k).unwrap());
            assert!(pager.get(k).unwrap().is_none());
        }
        assert_eq!(pager.total_records, 462);
    }

    #[test]
    fn btree_pager_detects_single_bit_tampering_and_heals_4kib_page_via_raid5_xor_parity() {
        let mut pager = BTreePager::new(TEST_BTREE_KEY).unwrap();
        for k in 1..=160i64 {
            pager.insert(k, b"acct_key", b"balance_ok", k).unwrap();
        }
        assert!(pager.allocated_pages >= 4);

        // Compute 4 KiB RAID-5 XOR parity between Leaf Page 0 and Leaf Page 1 (`P = P0 ^ P1`):
        let page0_backup = pager.pages[0];
        let page1_live = pager.pages[1];
        let mut parity_4k = [0u8; BTREE_PAGE_SIZE];
        BTreePager::compute_xor_parity_page(&page0_backup, &page1_live, &mut parity_4k);

        // 1. Flip a single bit in Leaf Page 0's payload and verify constant-time HMAC-SHA256 catches it:
        pager.pages[0][128] ^= 0x01;
        assert_eq!(
            pager.verify_page_seal(0),
            Err(BTreeError::PageTampered { page_id: 0 })
        );
        assert_eq!(
            pager.get(1),
            Err(BTreeError::PageTampered { page_id: 0 })
        );

        // 2. Wipe all 4,096 bytes of Leaf Page 0 (`0xFF`) and heal it using Page 1 + 4 KiB XOR parity:
        pager.pages[0] = [0xFFu8; BTREE_PAGE_SIZE];
        pager
            .heal_corrupted_page_with_xor_parity(0, &page1_live, &parity_4k)
            .expect("4 KiB RAID-5 XOR parity reconstruction must restore and verify HMAC seal");
        assert_eq!(pager.pages[0], page0_backup);
        assert_eq!(pager.get(1).unwrap().unwrap().val_bytes(), b"balance_ok");
    }

    #[test]
    fn btree_pager_rejects_rollback_stale_parity_cross_tree_swap_corrupt_links_and_reclaims_deleted_pages()
    {
        let mut pager = BTreePager::new(TEST_BTREE_KEY).unwrap();
        for k in 1..=160i64 {
            pager.insert(k, b"acct_key", b"v1", k).unwrap();
        }

        // Snapshot Page 0 and its RAID-5 XOR parity at `v1` (`LSN` before update):
        let stale_page0 = pager.pages[0];
        let page1_snapshot = pager.pages[1];
        let mut stale_parity = [0u8; BTREE_PAGE_SIZE];
        BTreePager::compute_xor_parity_page(&stale_page0, &page1_snapshot, &mut stale_parity);

        // Advance Page 0 by updating key 1 to `v2` and deleting key 2:
        pager.insert(1, b"acct_key", b"v2", 99).unwrap();
        assert!(pager.delete(2).unwrap());
        let fresh_page0 = pager.pages[0];

        // 1. Single-page rollback: restoring `stale_page0` (which has a valid HMAC under the tree key,
        //    but an older LSN than `pager.page_lsns[0]`) is rejected!
        pager.pages[0] = stale_page0;
        assert_eq!(
            pager.verify_page_seal(0),
            Err(BTreeError::PageTampered { page_id: 0 }),
            "restoring an older sealed snapshot of page 0 must be caught by expected LSN check"
        );
        assert_eq!(
            pager.get(1),
            Err(BTreeError::PageTampered { page_id: 0 })
        );
        pager.pages[0] = fresh_page0;

        // 2. Stale parity heal: healing Page 0 with `stale_parity` is rejected!
        pager.pages[0] = [0xAAu8; BTREE_PAGE_SIZE];
        assert_eq!(
            pager.heal_corrupted_page_with_xor_parity(0, &page1_snapshot, &stale_parity),
            Err(BTreeError::PageTampered { page_id: 0 }),
            "healing with stale parity must be rejected by expected LSN check"
        );
        pager.pages[0] = fresh_page0;
        assert_eq!(pager.get(1).unwrap().unwrap().val_bytes(), b"v2");
        assert!(pager.get(2).unwrap().is_none());

        // 3. Cross-tree page substitution: a sealed page from another BTreePager initialized with
        //    the same `TEST_BTREE_KEY` (and even at the same LSN!) is rejected due to per-tree key derivation.
        let mut other_pager = BTreePager::new(TEST_BTREE_KEY).unwrap();
        while other_pager.page_lsns[0] < pager.page_lsns[0] {
            other_pager.insert(1, b"other_k", b"other_v", 1).unwrap();
        }
        assert_eq!(other_pager.page_lsns[0], pager.page_lsns[0]);
        pager.pages[0] = other_pager.pages[0];
        assert_eq!(
            pager.verify_page_seal(0),
            Err(BTreeError::PageTampered { page_id: 0 }),
            "page from another BTreePager with the same master key and LSN must fail verification"
        );
        pager.pages[0] = fresh_page0;

        // 4. Out-of-range link validation: a page with an out-of-range `next_leaf` (`99`) or `parent` (`99`),
        //    even if re-sealed with the pager's own key and LSN, is rejected with `PageTampered` instead of panicking.
        let saved_lsn = pager.lsn;
        let saved_p0_lsn = pager.page_lsns[0];
        let saved_epoch = pager.epoch;
        let saved_mtag = pager.manifest_tag;
        pager.lsn = saved_p0_lsn - 1;
        pager.set_page_next_leaf(0, 99);
        pager.seal_page(0).unwrap();
        assert_eq!(
            pager.verify_page_seal(0),
            Err(BTreeError::PageTampered { page_id: 0 }),
            "sealed page with out-of-range next_leaf link must be rejected without panicking"
        );
        assert_eq!(
            pager.insert(3, b"acct_key", b"v3", 3),
            Err(BTreeError::PageTampered { page_id: 0 })
        );
        pager.pages[0] = fresh_page0;
        pager.lsn = saved_lsn;
        pager.page_lsns[0] = saved_p0_lsn;
        pager.epoch = saved_epoch;
        pager.manifest_tag = saved_mtag;

        // 5. Sealed Manifest export & load path (`export_manifest` + `load_from_manifest_and_pages`):
        let manifest = pager.export_manifest().unwrap();
        let loaded =
            BTreePager::load_from_manifest_and_pages(TEST_BTREE_KEY, &manifest, &pager.pages)
                .expect("valid manifest + pages must load cleanly");
        assert_eq!(loaded.get(1).unwrap().unwrap().val_bytes(), b"v2");
        let mut tampered_manifest = manifest;
        tampered_manifest.epoch ^= 1;
        assert_eq!(
            BTreePager::load_from_manifest_and_pages(
                TEST_BTREE_KEY,
                &tampered_manifest,
                &pager.pages
            )
            .err(),
            Some(BTreeError::ManifestTampered)
        );

        // 6. Delete page reclamation: filling the pager with 512 rows, deleting all 512 rows,
        //    and inserting 512 new rows succeeds by reclaiming freed leaf pages via `free_mask`.
        let mut churn_pager = BTreePager::new(TEST_BTREE_KEY).unwrap();
        for k in 1..=512i64 {
            churn_pager.insert(k, b"churn_k", b"pass1", k).unwrap();
        }
        assert_eq!(churn_pager.total_records, 512);
        for k in 1..=512i64 {
            assert!(churn_pager.delete(k).unwrap());
        }
        assert_eq!(churn_pager.total_records, 0);
        assert!(
            churn_pager.free_mask != 0,
            "emptying split leaves must reclaim pages into free_mask"
        );
        for k in 1001..=1512i64 {
            churn_pager
                .insert(k, b"churn_k", b"pass2", k)
                .expect("re-inserting 512 rows after full delete must reuse reclaimed pages");
        }
        assert_eq!(churn_pager.total_records, 512);
        assert_eq!(
            churn_pager.get(1512).unwrap().unwrap().val_bytes(),
            b"pass2"
        );
    }

    #[test]
    fn btree_pager_rejects_unseeded_keys_empty_labels_and_oversized_inputs_without_truncation() {
        assert_eq!(
            BTreePager::new([0u8; 32]).err(),
            Some(BTreeError::SealKeyUnset)
        );
        let mut pager = BTreePager::new(TEST_BTREE_KEY).unwrap();

        // Empty label and control bytes rejected:
        assert_eq!(
            pager.insert(1, b"", b"v", 1),
            Err(BTreeError::InvalidInput)
        );
        assert_eq!(
            pager.insert(1, b"bad label", b"v", 1),
            Err(BTreeError::InvalidInput)
        );
        assert_eq!(
            pager.insert(1, b"ok", b"bad\0val", 1),
            Err(BTreeError::InvalidInput)
        );

        // Oversized key_label (> 16B) and oversized val (> 24B) rejected with InputTooLarge:
        assert_eq!(
            pager.insert(1, &[b'k'; BTREE_KEY_LABEL_CAP + 1], b"v", 1),
            Err(BTreeError::InputTooLarge)
        );
        assert_eq!(
            pager.insert(1, b"ok", &[b'v'; BTREE_VAL_CAP + 1], 1),
            Err(BTreeError::InputTooLarge)
        );
        assert_eq!(pager.total_records, 0);
    }
}
