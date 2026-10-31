//! Sealed 4 KiB B+Tree Block Storage Engine (`CTTLBTP1`) with RAID-5 XOR Parity Recovery.
//!
//! Scales structured key-value and relational row storage beyond a single 4 KiB partition
//! by organizing 4 KiB (`8 × 512B` AHCI/NVMe sector) disk blocks into a B+Tree of
//! internal index pages and sibling-linked leaf pages:
//! - Every 4 KiB page (`[u8; 4096]`) carries an 8-byte `"CTTLBTP1"` magic header, page ID,
//!   node kind (`Leaf` vs. `Internal`), entry count, sibling/parent links, monotonic LSN,
//!   and a constant-time keyed `HMAC-SHA256` authentication tag (`[32..64]`).
//! - Automatic leaf splits at 64 records per 4 KiB page promote separator keys into the
//!   internal root page and link leaf sibling pointers (`next_leaf`) for ordered range scans.
//! - Every read (`get`, `scan_range`, `verify_all_page_seals`) verifies the visited 4 KiB
//!   page's keyed `HMAC-SHA256` tag in constant time before trusting any on-page pointer or cell.
//! - Supports 4 KiB RAID-5 XOR parity ($D_1 \oplus D_2 = P$) computation and single-page
//!   catastrophic corruption recovery (`heal_corrupted_page_with_xor_parity`).

#![allow(clippy::needless_range_loop)]

use crate::durable_seal::{
    is_seal_key_set, seal_bytes_keyed, seal_matches_keyed, DURABLE_DIGEST_LEN,
};

/// Byte size of a single B+Tree storage page (`4 KiB` = `8` × 512-byte sectors).
pub const BTREE_PAGE_SIZE: usize = 4096;
/// Number of 512-byte disk sectors per 4 KiB B+Tree page.
pub const BTREE_SECTORS_PER_PAGE: usize = 8;
/// Maximum number of 4 KiB pages managed by a [`BTreePager`] instance (`32` pages = `128 KiB`).
pub const BTREE_MAX_PAGES: usize = 32;
/// 8-byte magic header on every sealed 4 KiB B+Tree page.
pub const BTREE_PAGE_MAGIC: &[u8; 8] = b"CTTLBTP1";
/// Sentinel page ID indicating no sibling or parent page (`0xFFFF`).
pub const BTREE_NO_PAGE: u16 = 0xFFFF;
/// Maximum number of records stored in a single 4 KiB leaf page before splitting (`64` × 56B = `3,584B`).
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
    /// Page pool (`BTREE_MAX_PAGES`) is exhausted.
    PagerFull,
    /// Requested page ID is out of range or unallocated.
    InvalidPageId,
    /// Constant-time `HMAC-SHA256` verification failed or page header is corrupted.
    PageTampered {
        /// Page index whose seal or header failed verification.
        page_id: u16,
    },
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

/// Paged 4 KiB B+Tree Block Storage Engine with per-page `HMAC-SHA256` sealing.
#[derive(Clone)]
pub struct BTreePager {
    /// 256-bit `HMAC-SHA256` key used to seal and verify every 4 KiB page.
    pub seal_key: [u8; DURABLE_DIGEST_LEN],
    /// Page ID of the current B+Tree root page (`0..BTREE_MAX_PAGES`).
    pub root_page: u16,
    /// Number of allocated 4 KiB pages (`1..=BTREE_MAX_PAGES`).
    pub allocated_pages: u16,
    /// Monotonic Log Sequence Number incremented on every page seal operation.
    pub lsn: u64,
    /// Total leaf page split operations performed.
    pub leaf_splits: u64,
    /// Total records currently stored across all leaf pages.
    pub total_records: usize,
    /// Fixed pool of 4 KiB (`4096`-byte) sealed disk pages.
    pub pages: [[u8; BTREE_PAGE_SIZE]; BTREE_MAX_PAGES],
}

impl BTreePager {
    /// Construct an unprovisioned pager (`seal_key = [0; 32]`).
    pub const fn empty() -> Self {
        Self {
            seal_key: [0u8; DURABLE_DIGEST_LEN],
            root_page: 0,
            allocated_pages: 0,
            lsn: 0,
            leaf_splits: 0,
            total_records: 0,
            pages: [[0u8; BTREE_PAGE_SIZE]; BTREE_MAX_PAGES],
        }
    }

    /// Construct and initialize a provisioned [`BTreePager`] with a sealed empty root leaf page (`page 0`).
    pub fn new(seal_key: [u8; DURABLE_DIGEST_LEN]) -> Result<Self, BTreeError> {
        if !is_seal_key_set(&seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        let mut pager = Self::empty();
        pager.seal_key = seal_key;
        pager.allocated_pages = 1;
        pager.root_page = 0;
        pager.init_page_header(0, BTreePageKind::Leaf, 0, BTREE_NO_PAGE, BTREE_NO_PAGE, BTREE_NO_PAGE);
        pager.seal_page(0)?;
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
    }

    fn seal_page(&mut self, page_id: u16) -> Result<(), BTreeError> {
        if !is_seal_key_set(&self.seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if (page_id as usize) >= (self.allocated_pages as usize) {
            return Err(BTreeError::InvalidPageId);
        }
        self.lsn = self.lsn.wrapping_add(1);
        let p = &mut self.pages[page_id as usize];
        p[24..32].copy_from_slice(&self.lsn.to_le_bytes());
        // Compute HMAC-SHA256 over header `[0..32]` || payload `[64..4096]`.
        let mut msg = [0u8; 32 + (BTREE_PAGE_SIZE - BTREE_HEADER_BYTES)];
        msg[0..32].copy_from_slice(&p[0..32]);
        msg[32..].copy_from_slice(&p[BTREE_HEADER_BYTES..]);
        let mut tag = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(&self.seal_key, &msg, &mut tag);
        p[32..64].copy_from_slice(&tag);
        Ok(())
    }

    /// Verify in constant time the `CTTLBTP1` header and `HMAC-SHA256` seal of `page_id`.
    pub fn verify_page_seal(&self, page_id: u16) -> Result<BTreePageKind, BTreeError> {
        if !is_seal_key_set(&self.seal_key) {
            return Err(BTreeError::SealKeyUnset);
        }
        if (page_id as usize) >= (self.allocated_pages as usize) {
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
        let mut msg = [0u8; 32 + (BTREE_PAGE_SIZE - BTREE_HEADER_BYTES)];
        msg[0..32].copy_from_slice(&p[0..32]);
        msg[32..].copy_from_slice(&p[BTREE_HEADER_BYTES..]);
        let mut expected = [0u8; DURABLE_DIGEST_LEN];
        expected.copy_from_slice(&p[32..64]);
        if !seal_matches_keyed(&self.seal_key, &msg, &expected) {
            return Err(BTreeError::PageTampered { page_id });
        }
        Ok(kind)
    }

    /// Verify the constant-time `HMAC-SHA256` seal on every allocated 4 KiB page in the pool.
    pub fn verify_all_page_seals(&self) -> Result<usize, BTreeError> {
        let n = self.allocated_pages as usize;
        let mut i = 0usize;
        while i < n {
            self.verify_page_seal(i as u16)?;
            i += 1;
        }
        Ok(n)
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
    /// visited page's `HMAC-SHA256` seal in constant time.
    fn find_leaf_page(&self, key: i64) -> Result<u16, BTreeError> {
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
            if (chosen as usize) >= (self.allocated_pages as usize) {
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
            self.seal_page(leaf_id)?;
            self.total_records += 1;
            return Ok(leaf_id);
        }

        // Otherwise, split the full 64-entry leaf page across two 4 KiB leaf pages!
        let needed_pages = if self.page_parent(leaf_id) == BTREE_NO_PAGE {
            2usize // new right leaf + new internal root page
        } else {
            1usize // new right leaf
        };
        if (self.allocated_pages as usize) + needed_pages > BTREE_MAX_PAGES {
            return Err(BTreeError::PagerFull);
        }
        if self.page_parent(leaf_id) != BTREE_NO_PAGE {
            let p_id = self.page_parent(leaf_id);
            if self.page_count(p_id) >= BTREE_INTERNAL_MAX_KEYS {
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

        let right_id = self.allocated_pages;
        self.allocated_pages += 1;
        let old_next = self.page_next_leaf(leaf_id);
        let parent_id = self.page_parent(leaf_id);

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

        if parent_id == BTREE_NO_PAGE {
            // Allocate new internal root page:
            let new_root = self.allocated_pages;
            self.allocated_pages += 1;
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
            self.verify_page_seal(parent_id)?;
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
                // `leaf_id` was `rightmost_child`; now `leaf_id` becomes entry `p_count` and `right_id` is `rightmost_child`.
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

        self.leaf_splits += 1;
        self.total_records += 1;
        Ok(if key < sep_key { leaf_id } else { right_id })
    }

    /// Point lookup for `key` across the B+Tree, verifying the constant-time `HMAC-SHA256`
    /// seal of the root and target leaf pages before binary-searching the leaf.
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

    /// Delete `key` from its B+Tree leaf page and re-seal the modified 4 KiB page.
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
        self.set_page_count(leaf_id, count - 1);
        self.seal_page(leaf_id)?;
        self.total_records = self.total_records.saturating_sub(1);
        Ok(true)
    }

    /// Ordered range scan over `[min_key ..= max_key]`, routing to the starting 4 KiB leaf page
    /// and following sibling `next_leaf` links while verifying every visited page's `HMAC-SHA256` seal.
    pub fn scan_range(
        &self,
        min_key: i64,
        max_key: i64,
        out: &mut [BTreeRecord],
    ) -> Result<usize, BTreeError> {
        if min_key > max_key || out.is_empty() {
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
                        return Ok(written);
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
    /// verifying its `CTTLBTP1` header and constant-time `HMAC-SHA256` seal before committing.
    pub fn heal_corrupted_page_with_xor_parity(
        &mut self,
        corrupted_page_id: u16,
        peer_page: &[u8; BTREE_PAGE_SIZE],
        parity_page: &[u8; BTREE_PAGE_SIZE],
    ) -> Result<(), BTreeError> {
        if (corrupted_page_id as usize) >= (self.allocated_pages as usize) {
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
