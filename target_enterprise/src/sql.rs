//! Embedded zero-allocation relational SQL engine (`SqlDb`) with keyed HMAC-SHA256 block persistence.
//!
//! Provides a SQLite-compatible `#![no_std]` subset for structured operating-system
//! and application state:
//! - `CREATE TABLE <name> (<col> <INT|INTEGER|TEXT>, ...)`
//! - `DROP TABLE <name>`
//! - `INSERT INTO <name> VALUES (<v1>, <v2>, ...)`
//! - `SELECT * | COUNT(*) | <col>, ... FROM <name> [WHERE <col> <op> <val>] [ORDER BY <col> [ASC|DESC]] [LIMIT <n>]`
//! - `UPDATE <name> SET <col> = <val> [WHERE <col> <op> <val>]`
//! - `DELETE FROM <name> [WHERE <col> <op> <val>]`
//! - `.tables` / `SHOW TABLES` and `.schema` / `DESCRIBE <name>`
//! - Deterministic 16-sector (`8 KiB`) AHCI partition serialization (`CTTLSQL1`)
//!   protected by a keyed `HMAC-SHA256` tag (with automatic migration from legacy
//!   8-sector `4 KiB` v1 images).

use crate::durable_seal::{is_seal_key_set, zeroize_secret_bytes, DURABLE_DIGEST_LEN};
use crate::paged_store::{
    PageDomain, PagedBlockStore, PagedStoreError, PAGED_PAGE_PAYLOAD_BYTES,
};
use alloc::vec::Vec;

/// Maximum number of relational tables in a standalone/inline [`SqlDb`] instance.
pub const SQL_MAX_TABLES: usize = 4;
/// Maximum number of relational tables when [`SqlDb::is_paged_mode`] is active.
pub const SQL_PAGED_MAX_TABLES: usize = 8;
/// Maximum number of columns per table.
pub const SQL_MAX_COLS: usize = 4;
/// Maximum number of inline rows per table (`256` total rows across [`SQL_MAX_TABLES`]).
pub const SQL_MAX_ROWS: usize = 64;
/// Maximum number of rows per table when [`SqlDb::is_paged_mode`] is active (`2,048` rows/table).
pub const SQL_PAGED_MAX_ROWS: usize = 2048;
/// Number of row slots packed into each 4 KiB `PageDomain::SqlLeaf` page (`2048 / 32 = 64` leaf pages/table).
pub const SQL_ROWS_PER_LEAF_PAGE: usize = 32;
/// Maximum 4 KiB leaf pages per table (`64`, tracked in a single `u64` dirty bitmask).
pub const SQL_LEAF_PAGES_PER_TABLE: usize = SQL_PAGED_MAX_ROWS / SQL_ROWS_PER_LEAF_PAGE;
/// Header flag byte in `CTTLSQL1` (`sectors[0][18]`) indicating authoritative rows reside in [`PagedBlockStore`].
pub const SQL_PART_FLAG_PAGED: u8 = 1;
/// Maximum byte length of a table or column identifier.
pub const SQL_IDENT_LEN: usize = 16;
/// Maximum byte length of a `TEXT` cell value.
pub const SQL_TEXT_LEN: usize = 24;
/// Pre-upgrade v1 sector count for [`SqlDb`] (`4 KiB`).
pub const SQL_PART_SECTORS_V1: usize = 8;
/// Number of 512-byte disk sectors used to persist [`SqlDb`] (`8 KiB`).
pub const SQL_PART_SECTORS: usize = 16;
/// 8-byte superblock magic for the persistent SQL partition (`CTTLSQL1`).
pub const SQL_PART_MAGIC: &[u8; 8] = b"CTTLSQL1";
/// Sentinel value for [`SqlTable::indexed_col`] when no secondary index is defined.
pub const SQL_NO_INDEX: u8 = 0xFF;

/// SQL session owner ID for interactive serial/PS2 console commands.
pub const SQL_OWNER_CONSOLE: u64 = 0;
/// SQL session owner ID for the built-in `CuttleVault` (`vault`) application.
pub const SQL_OWNER_VAULT: u64 = 0xFFFF_0001;
/// SQL session owner ID for the built-in `CuttleChronos` (`cron`) scheduler.
pub const SQL_OWNER_CRON: u64 = 0xFFFF_0002;
/// SQL session owner ID for the 3-node Triad TMR replication and coordinator path.
pub const SQL_OWNER_TRIAD: u64 = 0xFFFF_0003;
/// SQL session owner ID for the UDP `:8080` control-plane service.
pub const SQL_OWNER_UDP: u64 = 0xFFFF_0004;
/// SQL session owner ID for unauthenticated HTTP gateway queries (`GET /sql`, `POST /sql`).
pub const SQL_OWNER_HTTP_ANON: u64 = 0xFFFF_0005;
/// Maximum number of simultaneous unacknowledged timed-out transaction owners tracked by [`SqlDb`].
pub const SQL_MAX_ABORTED_OWNERS: usize = 16;

/// Why [`SqlDb::try_save_partition`] produced no image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SqlSaveError {
    /// The seal key is all zero.
    KeyUnset,
    /// The committed tables and rows do not fit the partition.
    TooLarge,
}

/// Initial `tx_seq` value after `SqlDb::new()` seeds default system tables (`services`, `kv`).
pub const SQL_GENESIS_TX_SEQ: u64 = 7;

/// Column data type in [`SqlDb`].
#[repr(u8)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SqlType {
    /// 64-bit signed integer (`INT` / `INTEGER`).
    Int = 1,
    /// UTF-8 / ASCII text string up to [`SQL_TEXT_LEN`] bytes (`TEXT`).
    Text = 2,
}

/// Typed cell value stored in a [`SqlRow`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SqlVal {
    /// 64-bit signed integer value.
    Int(i64),
    /// Fixed-capacity byte string `(buf, len)`.
    Text([u8; SQL_TEXT_LEN], u8),
}

impl SqlVal {
    /// Construct an empty integer cell (`0`).
    pub const fn zero_int() -> Self {
        SqlVal::Int(0)
    }

    /// Construct a `TEXT` value from a byte slice up to [`SQL_TEXT_LEN`] bytes,
    /// returning `None` if `s.len() > SQL_TEXT_LEN` rather than silently truncating.
    pub fn try_from_text(s: &[u8]) -> Option<Self> {
        if s.len() > SQL_TEXT_LEN {
            return None;
        }
        let mut buf = [0u8; SQL_TEXT_LEN];
        let n = s.len();
        let mut i = 0usize;
        while i < n {
            buf[i] = s[i];
            i += 1;
        }
        Some(SqlVal::Text(buf, n as u8))
    }

    /// Construct a `TEXT` value from a validated byte slice (`s.len() <= SQL_TEXT_LEN`).
    pub fn from_text(s: &[u8]) -> Self {
        let mut buf = [0u8; SQL_TEXT_LEN];
        let n = s.len().min(SQL_TEXT_LEN);
        let mut i = 0usize;
        while i < n {
            buf[i] = s[i];
            i += 1;
        }
        SqlVal::Text(buf, n as u8)
    }

    /// Compare two [`SqlVal`] cells under `op`.
    pub fn compare(&self, op: CmpOp, rhs: &SqlVal) -> bool {
        match (self, rhs) {
            (SqlVal::Int(a), SqlVal::Int(b)) => match op {
                CmpOp::Eq => *a == *b,
                CmpOp::Ne => *a != *b,
                CmpOp::Lt => *a < *b,
                CmpOp::Gt => *a > *b,
                CmpOp::Le => *a <= *b,
                CmpOp::Ge => *a >= *b,
                CmpOp::Like => false,
            },
            (SqlVal::Text(ab, al), SqlVal::Text(bb, bl)) => {
                let a = &ab[..*al as usize];
                let b = &bb[..*bl as usize];
                if op == CmpOp::Like {
                    return sql_like_match(a, b);
                }
                let ord = cmp_bytes(a, b);
                match op {
                    CmpOp::Eq => ord == 0,
                    CmpOp::Ne => ord != 0,
                    CmpOp::Lt => ord < 0,
                    CmpOp::Gt => ord > 0,
                    CmpOp::Le => ord <= 0,
                    CmpOp::Ge => ord >= 0,
                    CmpOp::Like => false,
                }
            }
            _ => false,
        }
    }
}

/// Relational comparison operator for `WHERE` clauses.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CmpOp {
    /// `=`
    Eq,
    /// `!=` or `<>`
    Ne,
    /// `<`
    Lt,
    /// `>`
    Gt,
    /// `<=`
    Le,
    /// `>=`
    Ge,
    /// `LIKE` (`%` and `_` pattern matching)
    Like,
}

/// Aggregate function kind in `SELECT <agg>(<col>)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum AggKind {
    Sum,
    Min,
    Max,
    Avg,
}

/// Column definition inside a [`SqlTable`].
#[derive(Copy, Clone, Debug)]
pub struct SqlColumn {
    /// Column identifier bytes.
    pub name: [u8; SQL_IDENT_LEN],
    /// Valid length of `name`.
    pub name_len: u8,
    /// Column data type.
    pub col_type: SqlType,
}

impl SqlColumn {
    /// Construct an empty column slot.
    pub const fn empty() -> Self {
        Self {
            name: [0u8; SQL_IDENT_LEN],
            name_len: 0,
            col_type: SqlType::Int,
        }
    }

    /// Column name slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }
}

/// Single row inside a [`SqlTable`].
#[derive(Copy, Clone, Debug)]
pub struct SqlRow {
    /// Whether this row slot is occupied.
    pub used: bool,
    /// Optional 96-bit per-row AEAD nonce metadata (`[0u8; 12]` for ordinary SQL rows).
    pub meta96: [u8; 12],
    /// Cell values indexed by column position.
    pub cells: [SqlVal; SQL_MAX_COLS],
}

impl SqlRow {
    /// Construct an unoccupied row slot.
    pub const fn empty() -> Self {
        Self {
            used: false,
            meta96: [0u8; 12],
            cells: [SqlVal::zero_int(); SQL_MAX_COLS],
        }
    }
}

/// Compute a non-zero 64-bit FNV-1a hash fingerprint for a [`SqlVal`] cell.
pub fn hash_sql_val(val: &SqlVal) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    match val {
        SqlVal::Int(v) => {
            h ^= 1u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
            let b = v.to_le_bytes();
            let mut i = 0usize;
            while i < 8 {
                h ^= b[i] as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
                i += 1;
            }
        }
        SqlVal::Text(buf, len) => {
            h ^= 2u64;
            h = h.wrapping_mul(0x0100_0000_01b3);
            let l = (*len as usize).min(SQL_TEXT_LEN);
            let mut i = 0usize;
            while i < l {
                h ^= buf[i] as u64;
                h = h.wrapping_mul(0x0100_0000_01b3);
                i += 1;
            }
        }
    }
    if h == 0 {
        1
    } else {
        h
    }
}

static EMPTY_SQL_ROW: SqlRow = SqlRow::empty();

/// Relational table with inline rows (`0..64`), optional paged overflow rows (`64..2048`),
/// hash index, and sorted B+Tree index (`btree_keys`).
#[derive(Clone, Debug)]
pub struct SqlTable {
    /// Whether this table slot is occupied.
    pub used: bool,
    /// Table identifier bytes.
    pub name: [u8; SQL_IDENT_LEN],
    /// Valid length of `name`.
    pub name_len: u8,
    /// Number of defined columns (`1..=SQL_MAX_COLS`).
    pub col_count: u8,
    /// Column schemas.
    pub cols: [SqlColumn; SQL_MAX_COLS],
    /// Inline row storage (`64` rows per table).
    pub rows: [SqlRow; SQL_MAX_ROWS],
    /// Indexed column index (`0..col_count`), or [`SQL_NO_INDEX`] (`0xFF`) when unindexed.
    pub indexed_col: u8,
    /// Secondary index identifier bytes.
    pub index_name: [u8; SQL_IDENT_LEN],
    /// Valid length of `index_name`.
    pub index_name_len: u8,
    /// Per-row 64-bit FNV-1a hash fingerprint for `cells[indexed_col]` (inline slots `0..64`).
    pub index_hashes: [u64; SQL_MAX_ROWS],
    /// Overflow row slots (`64..SQL_PAGED_MAX_ROWS`) allocated lazily in paged mode.
    pub overflow_rows: Vec<SqlRow>,
    /// Overflow hash fingerprints matching `overflow_rows`.
    pub overflow_hashes: Vec<u64>,
    /// Sorted B+Tree `(int_key, row_slot)` index for `INT` `indexed_col` equality and range scans.
    pub btree_keys: Vec<(i64, u16)>,
    /// 64-bit dirty bitmask over 32-row leaf pages (`bit p` = rows `p*32..(p+1)*32` mutated).
    pub dirty_page_mask: u64,
    /// Whether this table's DDL / index metadata changed since last paged-store sync.
    pub schema_dirty: bool,
}

impl SqlTable {
    /// Construct an empty unused table slot (`const fn`, zero heap allocations).
    pub const fn empty() -> Self {
        Self {
            used: false,
            name: [0u8; SQL_IDENT_LEN],
            name_len: 0,
            col_count: 0,
            cols: [SqlColumn::empty(); SQL_MAX_COLS],
            rows: [SqlRow::empty(); SQL_MAX_ROWS],
            indexed_col: SQL_NO_INDEX,
            index_name: [0u8; SQL_IDENT_LEN],
            index_name_len: 0,
            index_hashes: [0u64; SQL_MAX_ROWS],
            overflow_rows: Vec::new(),
            overflow_hashes: Vec::new(),
            btree_keys: Vec::new(),
            dirty_page_mask: 0,
            schema_dirty: false,
        }
    }

    /// Reset a table slot in-place without materializing a multi-kilobyte [`SqlTable`] temporary on the stack.
    pub fn reset_in_place(&mut self) {
        self.used = false;
        self.name = [0u8; SQL_IDENT_LEN];
        self.name_len = 0;
        self.col_count = 0;
        let mut c = 0usize;
        while c < SQL_MAX_COLS {
            self.cols[c] = SqlColumn::empty();
            c += 1;
        }
        let mut r = 0usize;
        while r < SQL_MAX_ROWS {
            self.rows[r].used = false;
            self.rows[r].meta96 = [0u8; 12];
            let mut k = 0usize;
            while k < SQL_MAX_COLS {
                self.rows[r].cells[k] = SqlVal::zero_int();
                k += 1;
            }
            self.index_hashes[r] = 0;
            r += 1;
        }
        self.overflow_rows.clear();
        self.overflow_hashes.clear();
        self.btree_keys.clear();
        self.dirty_page_mask = 0;
        self.schema_dirty = true;
        self.indexed_col = SQL_NO_INDEX;
        self.index_name = [0u8; SQL_IDENT_LEN];
        self.index_name_len = 0;
    }

    /// Number of currently allocated row slots (`64 + overflow_rows.len()`).
    #[inline]
    pub fn row_slots_len(&self) -> usize {
        SQL_MAX_ROWS + self.overflow_rows.len()
    }

    /// Borrow row slot `r` (returns `&EMPTY_SQL_ROW` if `r >= self.row_slots_len()`).
    #[inline]
    pub fn row_at(&self, r: usize) -> &SqlRow {
        if r < SQL_MAX_ROWS {
            &self.rows[r]
        } else {
            self.overflow_rows
                .get(r - SQL_MAX_ROWS)
                .unwrap_or(&EMPTY_SQL_ROW)
        }
    }

    /// Mutably borrow row slot `r`, extending `overflow_rows` if `r >= SQL_MAX_ROWS`.
    #[inline]
    pub fn row_mut(&mut self, r: usize) -> &mut SqlRow {
        if r < SQL_MAX_ROWS {
            &mut self.rows[r]
        } else {
            let ext_idx = r - SQL_MAX_ROWS;
            if self.overflow_rows.len() <= ext_idx {
                self.overflow_rows.resize(ext_idx + 1, SqlRow::empty());
                self.overflow_hashes.resize(ext_idx + 1, 0);
            }
            &mut self.overflow_rows[ext_idx]
        }
    }

    /// Read the secondary-index hash fingerprint at slot `r`.
    #[inline]
    pub fn hash_at(&self, r: usize) -> u64 {
        if r < SQL_MAX_ROWS {
            self.index_hashes[r]
        } else {
            self.overflow_hashes
                .get(r - SQL_MAX_ROWS)
                .copied()
                .unwrap_or(0)
        }
    }

    /// Set the secondary-index hash fingerprint at slot `r`.
    #[inline]
    pub fn set_hash_at(&mut self, r: usize, h: u64) {
        if r < SQL_MAX_ROWS {
            self.index_hashes[r] = h;
        } else {
            let ext_idx = r - SQL_MAX_ROWS;
            if self.overflow_hashes.len() <= ext_idx {
                self.overflow_hashes.resize(ext_idx + 1, 0);
            }
            self.overflow_hashes[ext_idx] = h;
        }
    }

    /// Mark the 32-row leaf page containing row slot `r` dirty for incremental persistence.
    #[inline]
    pub fn mark_row_dirty(&mut self, r: usize) {
        let chunk = r / SQL_ROWS_PER_LEAF_PAGE;
        if chunk < SQL_LEAF_PAGES_PER_TABLE {
            self.dirty_page_mask |= 1u64 << chunk;
        }
    }

    /// Mark every 32-row leaf page that currently contains at least one occupied row dirty.
    pub fn mark_occupied_pages_dirty(&mut self) {
        let len = self.row_slots_len();
        let mut r = 0usize;
        while r < len {
            if self.row_at(r).used {
                self.mark_row_dirty(r);
            }
            r += 1;
        }
    }

    /// Table name slice.
    pub fn name_bytes(&self) -> &[u8] {
        &self.name[..self.name_len as usize]
    }

    /// Secondary index name slice (empty if unindexed).
    pub fn index_name_bytes(&self) -> &[u8] {
        &self.index_name[..self.index_name_len as usize]
    }

    /// Count of occupied rows in this table.
    pub fn row_count(&self) -> usize {
        let mut n = 0usize;
        let len = self.row_slots_len();
        let mut i = 0usize;
        while i < len {
            if self.row_at(i).used {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Find column index by case-insensitive name.
    pub fn find_col(&self, col_name: &[u8]) -> Option<usize> {
        let mut i = 0usize;
        while i < self.col_count as usize {
            if eq_ignore_ascii_case(self.cols[i].name_bytes(), col_name) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Rebuild `index_hashes`, `overflow_hashes`, and sorted `btree_keys` for all occupied rows.
    pub fn rebuild_index(&mut self) {
        let c = self.indexed_col as usize;
        self.btree_keys.clear();
        if c >= self.col_count as usize {
            self.index_hashes = [0u64; SQL_MAX_ROWS];
            self.overflow_hashes.fill(0);
            return;
        }
        let is_int_idx = self.cols[c].col_type == SqlType::Int;
        let len = self.row_slots_len();
        let mut r = 0usize;
        while r < len {
            let row = *self.row_at(r);
            if row.used {
                let h = hash_sql_val(&row.cells[c]);
                self.set_hash_at(r, h);
                if is_int_idx {
                    if let SqlVal::Int(k) = row.cells[c] {
                        self.btree_keys.push((k, r as u16));
                    }
                }
            } else {
                self.set_hash_at(r, 0);
            }
            r += 1;
        }
        if is_int_idx {
            self.btree_keys.sort_unstable();
        }
    }

    /// Maintain secondary hash and sorted B+Tree index incrementally on a single row mutation.
    fn sync_index_row(&mut self, r: usize, old_row: Option<&SqlRow>, new_row: Option<&SqlRow>) {
        let c = self.indexed_col as usize;
        if c >= self.col_count as usize {
            self.set_hash_at(r, 0);
            return;
        }
        let is_int_idx = self.cols[c].col_type == SqlType::Int;
        if is_int_idx {
            if let Some(prev) = old_row {
                if prev.used {
                    if let SqlVal::Int(old_k) = prev.cells[c] {
                        let pair = (old_k, r as u16);
                        if let Ok(pos) = self.btree_keys.binary_search(&pair) {
                            self.btree_keys.remove(pos);
                        }
                    }
                }
            }
        }
        if let Some(next) = new_row {
            if next.used {
                self.set_hash_at(r, hash_sql_val(&next.cells[c]));
                if is_int_idx {
                    if let SqlVal::Int(new_k) = next.cells[c] {
                        let pair = (new_k, r as u16);
                        let pos = self.btree_keys.partition_point(|x| *x < pair);
                        if self.btree_keys.get(pos) != Some(&pair) {
                            self.btree_keys.insert(pos, pair);
                        }
                    }
                }
                return;
            }
        }
        self.set_hash_at(r, 0);
    }

    /// Collect candidate row indices matching an indexed `INT` comparison (`=`, `<`, `<=`, `>`, `>=`)
    /// in `O(log N + K)` via binary search over `btree_keys`.
    fn btree_scan_int(&self, op: CmpOp, target: i64, out: &mut Vec<usize>) -> bool {
        let c = self.indexed_col as usize;
        if c >= self.col_count as usize || self.cols[c].col_type != SqlType::Int {
            return false;
        }
        let (lo, hi) = match op {
            CmpOp::Eq => {
                let l = self.btree_keys.partition_point(|(k, _)| *k < target);
                let h = self.btree_keys.partition_point(|(k, _)| *k <= target);
                (l, h)
            }
            CmpOp::Lt => (0, self.btree_keys.partition_point(|(k, _)| *k < target)),
            CmpOp::Le => (0, self.btree_keys.partition_point(|(k, _)| *k <= target)),
            CmpOp::Gt => (
                self.btree_keys.partition_point(|(k, _)| *k <= target),
                self.btree_keys.len(),
            ),
            CmpOp::Ge => (
                self.btree_keys.partition_point(|(k, _)| *k < target),
                self.btree_keys.len(),
            ),
            CmpOp::Ne | CmpOp::Like => return false,
        };
        let mut i = lo;
        while i < hi {
            out.push(self.btree_keys[i].1 as usize);
            i += 1;
        }
        // Sort by physical slot order so non-ORDER-BY SELECT output matches deterministic slot scan order!
        out.sort_unstable();
        true
    }
}

/// Maximum number of row mutations tracked in an active `BEGIN ... ROLLBACK` transaction.
pub const SQL_TX_UNDO_CAP: usize = 8;
/// Maximum number of idle timer ticks before an open transaction is automatically rolled back.
pub const SQL_TX_MAX_IDLE_TICKS: u8 = 16;

/// Embedded relational SQL database engine with inline (`8 KiB`) and paged (`PagedBlockStore`) persistence.
#[derive(Clone, Debug)]
pub struct SqlDb {
    /// Inline table slots (`0..4`).
    pub tables: [SqlTable; SQL_MAX_TABLES],
    /// Overflow table slots (`4..8`) allocated lazily when `paged_mode` is enabled.
    pub overflow_tables: Vec<SqlTable>,
    /// Monotonic counter of mutating SQL statements executed.
    pub tx_seq: u64,
    /// Monotonic counter of secondary-index-accelerated `WHERE` lookups.
    pub idx_hits: u64,
    /// Whether an explicit `BEGIN` transaction is currently open.
    pub tx_active: bool,
    /// Session/client owner identifier holding the active transaction (`0` = console/system, `>0` = session slot).
    pub tx_owner: u64,
    /// Idle timer ticks elapsed since the last statement inside the active transaction.
    pub tx_age_ticks: u8,
    /// Number of row-level undo records captured in the current transaction (`0..=SQL_TX_UNDO_CAP`).
    pub tx_undo_len: u8,
    /// Saved `tx_seq` prior to `BEGIN`, restored on `ROLLBACK`.
    pub tx_undo_seq: u64,
    /// Table index for each undo slot.
    pub tx_undo_table: [u8; SQL_TX_UNDO_CAP],
    /// Row index for each undo slot (`0..SQL_PAGED_MAX_ROWS`).
    pub tx_undo_row: [u16; SQL_TX_UNDO_CAP],
    /// Pre-transaction row snapshot for each undo slot.
    pub tx_undo_prev: [SqlRow; SQL_TX_UNDO_CAP],
    /// The last transaction was rolled back by the idle timeout and at least one
    /// owner has not yet acknowledged its rollback with `ROLLBACK`, `COMMIT` or `BEGIN`.
    pub tx_aborted: bool,
    /// Most recent owner whose transaction was rolled back by the idle timeout.
    pub tx_aborted_owner: u64,
    /// Bounded set of distinct owner IDs whose timed-out transactions remain unacknowledged.
    pub tx_aborted_set: [u64; SQL_MAX_ABORTED_OWNERS],
    /// Valid entry count in [`Self::tx_aborted_set`].
    pub tx_aborted_count: u8,
    /// Whether page-granular overflow storage (`<= 8` tables, `<= 2,048` rows/table) is enabled.
    paged_mode: bool,
    /// Whether `SqlCatalog` metadata (`tx_seq` or table schemas) changed since last paged-store sync.
    catalog_dirty: bool,
    /// Optional logical-page cap (`PageDomain::SqlCatalog` + `PageDomain::SqlLeaf`) enforced in `paged_mode`.
    paged_page_budget: Option<usize>,
}

impl Default for SqlDb {
    fn default() -> Self {
        Self::new()
    }
}

static EMPTY_SQL_TABLE: SqlTable = SqlTable::empty();

impl SqlDb {
    /// Construct an empty unseeded SQL database (`const fn`, zero heap allocations).
    pub const fn empty() -> Self {
        Self {
            tables: [
                SqlTable::empty(),
                SqlTable::empty(),
                SqlTable::empty(),
                SqlTable::empty(),
            ],
            overflow_tables: Vec::new(),
            tx_seq: 0,
            idx_hits: 0,
            tx_active: false,
            tx_owner: 0,
            tx_age_ticks: 0,
            tx_undo_len: 0,
            tx_undo_seq: 0,
            tx_undo_table: [0u8; SQL_TX_UNDO_CAP],
            tx_undo_row: [0u16; SQL_TX_UNDO_CAP],
            tx_undo_prev: [SqlRow::empty(); SQL_TX_UNDO_CAP],
            tx_aborted: false,
            tx_aborted_owner: 0,
            tx_aborted_set: [0u64; SQL_MAX_ABORTED_OWNERS],
            tx_aborted_count: 0,
            paged_mode: false,
            catalog_dirty: false,
            paged_page_budget: None,
        }
    }

    /// Set or clear the maximum logical 4 KiB pages (`SqlCatalog` + `SqlLeaf`) this database may occupy in `paged_mode`.
    pub fn set_paged_page_budget(&mut self, budget: Option<usize>) {
        self.paged_page_budget = budget;
    }

    /// Return the configured logical-page budget in `paged_mode`, if any.
    pub const fn paged_page_budget(&self) -> Option<usize> {
        self.paged_page_budget
    }

    /// Exact number of `PagedBlockStore` logical pages (`1` `SqlCatalog` + active 32-row `SqlLeaf` chunks)
    /// required by this database in `paged_mode`.
    pub fn paged_pages_needed(&self) -> usize {
        if !self.paged_mode {
            return 0;
        }
        self.paged_pages_with_planned_inserts(usize::MAX, &[])
    }

    fn paged_pages_with_planned_inserts(
        &self,
        planned_table: usize,
        planned_slots: &[usize],
    ) -> usize {
        let mut pages = 1usize; // `PageDomain::SqlCatalog` (`owner_id = 0`)
        let mut t = 0usize;
        while t < SQL_PAGED_MAX_TABLES {
            if !self.table_at(t).used {
                t += 1;
                continue;
            }
            let r_len = self.table_at(t).row_slots_len();
            let mut chunk = 0usize;
            while chunk < SQL_LEAF_PAGES_PER_TABLE {
                let base_r = chunk * SQL_ROWS_PER_LEAF_PAGE;
                let mut occupied = false;
                if t == planned_table {
                    let mut p = 0usize;
                    while p < planned_slots.len() {
                        let s = planned_slots[p];
                        if s >= base_r && s < base_r + SQL_ROWS_PER_LEAF_PAGE {
                            occupied = true;
                            break;
                        }
                        p += 1;
                    }
                }
                if !occupied && base_r < r_len {
                    let max_k = SQL_ROWS_PER_LEAF_PAGE.min(r_len - base_r);
                    let mut k = 0usize;
                    while k < max_k {
                        let r = base_r + k;
                        if self.table_at(t).row_at(r).used || self.committed_row(t, r).used {
                            occupied = true;
                            break;
                        }
                        k += 1;
                    }
                }
                if occupied {
                    pages += 1;
                }
                chunk += 1;
            }
            t += 1;
        }
        pages
    }

    /// `true` when page-granular overflow storage (`<= 8` tables, `<= 2,048` rows/table) is active.
    #[inline]
    pub const fn is_paged_mode(&self) -> bool {
        self.paged_mode
    }

    /// Enable or disable page-granular overflow storage (`PagedBlockStore` backing).
    pub fn set_paged_mode(&mut self, enabled: bool) {
        if enabled && !self.paged_mode {
            self.paged_mode = true;
            self.catalog_dirty = true;
            let len = self.table_slots_len();
            let mut t = 0usize;
            while t < len {
                if self.table_at(t).used {
                    let tbl = self.table_mut(t);
                    tbl.schema_dirty = true;
                    tbl.mark_occupied_pages_dirty();
                }
                t += 1;
            }
        } else if !enabled && self.paged_mode {
            if self.overflow_tables.iter().any(|t| t.used) {
                return;
            }
            let mut t = 0usize;
            while t < SQL_MAX_TABLES {
                if self.tables[t].used
                    && self.tables[t]
                        .overflow_rows
                        .iter()
                        .any(|r| r.used)
                {
                    return;
                }
                t += 1;
            }
            if self.serialized_partition_bytes() > SQL_PART_SECTORS * 512 - 8 {
                return;
            }
            self.overflow_tables.clear();
            let mut ti = 0usize;
            while ti < SQL_MAX_TABLES {
                self.tables[ti].overflow_rows.clear();
                self.tables[ti].overflow_hashes.clear();
                if self.tables[ti].used {
                    self.tables[ti].rebuild_index();
                }
                ti += 1;
            }
            self.paged_page_budget = None;
            self.paged_mode = false;
        }
    }

    /// Maximum table count permitted in the current mode (`4` inline, `8` paged).
    #[inline]
    pub const fn max_tables(&self) -> usize {
        if self.paged_mode {
            SQL_PAGED_MAX_TABLES
        } else {
            SQL_MAX_TABLES
        }
    }

    /// Maximum row count per table permitted in the current mode (`64` inline, `2,048` paged).
    #[inline]
    pub const fn max_rows_per_table(&self) -> usize {
        if self.paged_mode {
            SQL_PAGED_MAX_ROWS
        } else {
            SQL_MAX_ROWS
        }
    }

    /// Number of currently allocated table slots (`4 + overflow_tables.len()`).
    #[inline]
    pub fn table_slots_len(&self) -> usize {
        SQL_MAX_TABLES + self.overflow_tables.len()
    }

    /// Borrow table slot `t` (returns `&EMPTY_SQL_TABLE` if `t >= self.table_slots_len()`).
    #[inline]
    pub fn table_at(&self, t: usize) -> &SqlTable {
        if t < SQL_MAX_TABLES {
            &self.tables[t]
        } else {
            self.overflow_tables
                .get(t - SQL_MAX_TABLES)
                .unwrap_or(&EMPTY_SQL_TABLE)
        }
    }

    /// Mutably borrow table slot `t`, extending `overflow_tables` if `t >= SQL_MAX_TABLES`.
    #[inline]
    pub fn table_mut(&mut self, t: usize) -> &mut SqlTable {
        if t < SQL_MAX_TABLES {
            &mut self.tables[t]
        } else {
            let ext_idx = t - SQL_MAX_TABLES;
            if self.overflow_tables.len() <= ext_idx {
                self.overflow_tables.resize_with(ext_idx + 1, SqlTable::empty);
            }
            &mut self.overflow_tables[ext_idx]
        }
    }

    /// Return `true` if `owner` has an unacknowledged timed-out transaction rollback.
    pub fn is_owner_aborted(&self, owner: u64) -> bool {
        if self.tx_aborted && self.tx_aborted_owner == owner {
            return true;
        }
        let n = (self.tx_aborted_count as usize).min(SQL_MAX_ABORTED_OWNERS);
        let mut i = 0usize;
        while i < n {
            if self.tx_aborted_set[i] == owner {
                return true;
            }
            i += 1;
        }
        false
    }

    fn mark_owner_aborted(&mut self, owner: u64) {
        let mut n = (self.tx_aborted_count as usize).min(SQL_MAX_ABORTED_OWNERS);
        let mut i = 0usize;
        while i < n {
            if self.tx_aborted_set[i] == owner {
                self.tx_aborted = true;
                self.tx_aborted_owner = owner;
                return;
            }
            i += 1;
        }
        if n == SQL_MAX_ABORTED_OWNERS {
            let mut k = 1usize;
            while k < SQL_MAX_ABORTED_OWNERS {
                self.tx_aborted_set[k - 1] = self.tx_aborted_set[k];
                k += 1;
            }
            n = SQL_MAX_ABORTED_OWNERS - 1;
        }
        self.tx_aborted_set[n] = owner;
        self.tx_aborted_count = (n + 1) as u8;
        self.tx_aborted = true;
        self.tx_aborted_owner = owner;
    }

    fn clear_owner_aborted(&mut self, owner: u64) {
        let mut n = (self.tx_aborted_count as usize).min(SQL_MAX_ABORTED_OWNERS);
        let mut w = 0usize;
        let mut r = 0usize;
        while r < n {
            if self.tx_aborted_set[r] != owner {
                self.tx_aborted_set[w] = self.tx_aborted_set[r];
                w += 1;
            }
            r += 1;
        }
        let mut z = w;
        while z < SQL_MAX_ABORTED_OWNERS {
            self.tx_aborted_set[z] = 0;
            z += 1;
        }
        n = w;
        self.tx_aborted_count = n as u8;
        if n > 0 {
            self.tx_aborted = true;
            self.tx_aborted_owner = self.tx_aborted_set[n - 1];
        } else if self.tx_aborted && self.tx_aborted_owner == owner {
            self.tx_aborted = false;
            self.tx_aborted_owner = 0;
        }
    }

    fn has_undo_record(&self, t_idx: usize, r_idx: usize) -> bool {
        let len = self.tx_undo_len as usize;
        let mut i = 0usize;
        while i < len {
            if (self.tx_undo_table[i] as usize) == t_idx && (self.tx_undo_row[i] as usize) == r_idx
            {
                return true;
            }
            i += 1;
        }
        false
    }

    fn can_record_row_undo(&self, t_idx: usize, r_idx: usize) -> bool {
        if !self.tx_active {
            return true;
        }
        if self.has_undo_record(t_idx, r_idx) {
            return true;
        }
        (self.tx_undo_len as usize) < SQL_TX_UNDO_CAP
    }

    fn record_row_undo(&mut self, t_idx: usize, r_idx: usize) {
        if !self.tx_active || self.has_undo_record(t_idx, r_idx) {
            return;
        }
        let len = self.tx_undo_len as usize;
        if len < SQL_TX_UNDO_CAP {
            self.tx_undo_table[len] = t_idx as u8;
            self.tx_undo_row[len] = r_idx as u16;
            self.tx_undo_prev[len] = *self.table_at(t_idx).row_at(r_idx);
            self.tx_undo_len = (len + 1) as u8;
        }
    }

    /// Return the last committed snapshot of row `(t_idx, r_idx)` so [`SqlDb::save_partition`]
    /// and [`SqlDb::sync_to_paged_store`] never persist uncommitted rows from an in-flight `BEGIN` transaction.
    fn committed_row(&self, t_idx: usize, r_idx: usize) -> &SqlRow {
        if self.tx_active {
            let len = self.tx_undo_len as usize;
            let mut i = 0usize;
            while i < len {
                if (self.tx_undo_table[i] as usize) == t_idx
                    && (self.tx_undo_row[i] as usize) == r_idx
                {
                    return &self.tx_undo_prev[i];
                }
                i += 1;
            }
        }
        self.table_at(t_idx).row_at(r_idx)
    }

    /// Roll back the currently active transaction in-place and release its session lock.
    pub fn rollback_active_transaction(&mut self) {
        if !self.tx_active {
            return;
        }
        let mut k = self.tx_undo_len as usize;
        while k > 0 {
            k -= 1;
            let t = self.tx_undo_table[k] as usize;
            let r = self.tx_undo_row[k] as usize;
            let prev = self.tx_undo_prev[k];
            if t < self.table_slots_len() && r < SQL_PAGED_MAX_ROWS {
                let tbl = self.table_mut(t);
                *tbl.row_mut(r) = prev;
                tbl.mark_row_dirty(r);
            }
        }
        let t_len = self.table_slots_len();
        let mut t = 0usize;
        while t < t_len {
            if self.table_at(t).used {
                self.table_mut(t).rebuild_index();
            }
            t += 1;
        }
        self.tx_seq = self.tx_undo_seq;
        self.tx_active = false;
        self.tx_owner = 0;
        self.tx_age_ticks = 0;
        self.tx_undo_len = 0;
    }

    /// Advance the active transaction idle timer by one tick, automatically rolling back
    /// any abandoned transaction that has been idle for [`SQL_TX_MAX_IDLE_TICKS`] ticks.
    /// Returns `true` if a stale transaction was rolled back.
    pub fn tick_transaction_timeout(&mut self) -> bool {
        if !self.tx_active {
            return false;
        }
        self.tx_age_ticks = self.tx_age_ticks.saturating_add(1);
        if self.tx_age_ticks >= SQL_TX_MAX_IDLE_TICKS {
            let owner = self.tx_owner;
            self.rollback_active_transaction();
            self.mark_owner_aborted(owner);
            return true;
        }
        false
    }

    /// Construct and seed a default SQL database with system tables (`services`, `kv`).
    pub fn new() -> Self {
        let mut db = Self::empty();
        db.seed_defaults();
        db
    }

    /// Populate default system tables (`services` and `kv`) if no tables exist.
    pub fn seed_defaults(&mut self) {
        if self.table_count() > 0 {
            return;
        }
        let mut scratch = [0u8; 256];
        let _ = self.exec(
            b"CREATE TABLE services (id INT, name TEXT, port INT, proto TEXT)",
            &mut scratch,
        );
        let _ = self.exec(
            b"INSERT INTO services VALUES (1, 'http-web', 80, 'TCP')",
            &mut scratch,
        );
        let _ = self.exec(
            b"INSERT INTO services VALUES (2, 'https-tls13', 443, 'TCP')",
            &mut scratch,
        );
        let _ = self.exec(
            b"INSERT INTO services VALUES (3, 'ctrl-udp', 8080, 'UDP')",
            &mut scratch,
        );
        let _ = self.exec(
            b"CREATE TABLE kv (k TEXT, v TEXT, rev INT)",
            &mut scratch,
        );
        let _ = self.exec(
            b"INSERT INTO kv VALUES ('cluster.role', 'primary', 1)",
            &mut scratch,
        );
        let _ = self.exec(
            b"INSERT INTO kv VALUES ('mtd.policy', 'binmorph-7pass', 1)",
            &mut scratch,
        );
    }

    /// Number of active tables.
    pub fn table_count(&self) -> usize {
        let mut n = 0usize;
        let len = self.table_slots_len();
        let mut i = 0usize;
        while i < len {
            if self.table_at(i).used {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Total number of rows across all active tables.
    pub fn total_rows(&self) -> usize {
        let mut n = 0usize;
        let len = self.table_slots_len();
        let mut i = 0usize;
        while i < len {
            if self.table_at(i).used {
                n += self.table_at(i).row_count();
            }
            i += 1;
        }
        n
    }

    /// Total number of committed rows across all active tables.
    pub fn committed_total_rows(&self) -> u32 {
        let mut n = 0u32;
        let t_len = self.table_slots_len();
        let mut t = 0usize;
        while t < t_len {
            let tbl = self.table_at(t);
            if tbl.used {
                let r_len = tbl.row_slots_len();
                let mut r = 0usize;
                while r < r_len {
                    if self.committed_row(t, r).used {
                        n = n.saturating_add(1);
                    }
                    r += 1;
                }
            }
            t += 1;
        }
        n
    }

    /// Compute a deterministic 64-bit FNV-1a cryptographic state fingerprint across all
    /// active tables, columns, secondary indexes, and canonically sorted live rows for 2-of-3 Triad TMR voting.
    pub fn state_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mix_byte = |acc: u64, b: u8| -> u64 { (acc ^ (b as u64)).wrapping_mul(0x0100_0000_01b3) };

        // Canonically sort active table indices by ASCII-lowercased table name.
        let mut tbl_order = [0usize; SQL_PAGED_MAX_TABLES];
        let mut tcount = 0usize;
        let t_len = self.table_slots_len();
        let mut ti = 0usize;
        while ti < t_len {
            if self.table_at(ti).used && tcount < SQL_PAGED_MAX_TABLES {
                tbl_order[tcount] = ti;
                tcount += 1;
            }
            ti += 1;
        }
        let mut a = 0usize;
        while a < tcount {
            let mut b = a + 1;
            while b < tcount {
                let na = self.table_at(tbl_order[a]).name_bytes();
                let nb = self.table_at(tbl_order[b]).name_bytes();
                if cmp_ascii_case_insensitive(na, nb) > 0 {
                    tbl_order.swap(a, b);
                }
                b += 1;
            }
            a += 1;
        }

        let mut row_order: Vec<usize> = Vec::new();
        let mut ord_i = 0usize;
        while ord_i < tcount {
            let t_idx = tbl_order[ord_i];
            let tbl = self.table_at(t_idx);
            let col_count = tbl.col_count as usize;
            let is_kv = eq_ignore_ascii_case(tbl.name_bytes(), b"kv");
            h = mix_byte(h, 0xA5);
            let mut i = 0usize;
            while i < (tbl.name_len as usize) {
                h = mix_byte(h, tbl.name[i].to_ascii_lowercase());
                i += 1;
            }
            h = mix_byte(h, tbl.col_count);
            let mut col_i = 0usize;
            while col_i < col_count {
                let cname = tbl.cols[col_i].name_bytes();
                h = mix_byte(h, cname.len() as u8);
                let mut ci = 0usize;
                while ci < cname.len() {
                    h = mix_byte(h, cname[ci].to_ascii_lowercase());
                    ci += 1;
                }
                h = mix_byte(h, tbl.cols[col_i].col_type as u8);
                col_i += 1;
            }
            if (tbl.indexed_col as usize) < col_count && tbl.index_name_len > 0 {
                h = mix_byte(h, 1);
                h = mix_byte(h, tbl.indexed_col);
                let iname = tbl.index_name_bytes();
                h = mix_byte(h, iname.len() as u8);
                let mut ii = 0usize;
                while ii < iname.len() {
                    h = mix_byte(h, iname[ii].to_ascii_lowercase());
                    ii += 1;
                }
            } else {
                h = mix_byte(h, 0);
            }

            // Collect and canonically sort occupied rows on the heap so bare-metal stack frames stay tiny!
            row_order.clear();
            let r_len = tbl.row_slots_len();
            let mut r_idx = 0usize;
            while r_idx < r_len {
                if self.committed_row(t_idx, r_idx).used {
                    row_order.push(r_idx);
                }
                r_idx += 1;
            }
            row_order.sort_by(|&ri, &rj| {
                let ra = self.committed_row(t_idx, ri);
                let rb = self.committed_row(t_idx, rj);
                let ord = cmp_rows_canonical(ra, rb, col_count, is_kv);
                if ord < 0 {
                    core::cmp::Ordering::Less
                } else if ord > 0 {
                    core::cmp::Ordering::Greater
                } else {
                    core::cmp::Ordering::Equal
                }
            });

            let mut rk = 0usize;
            while rk < row_order.len() {
                let row = self.committed_row(t_idx, row_order[rk]);
                let vault_key = if is_kv && col_count > 0 {
                    match &row.cells[0] {
                        SqlVal::Text(tb, tl) if *tl >= 2 && tb[0] == b'v' && tb[1] == b':' => {
                            Some(&tb[..*tl as usize])
                        }
                        _ => None,
                    }
                } else {
                    None
                };
                if let Some(vk) = vault_key {
                    h = mix_byte(h, 0x5B);
                    h = mix_byte(h, vk.len() as u8);
                    let mut vi = 0usize;
                    while vi < vk.len() {
                        h = mix_byte(h, vk[vi]);
                        vi += 1;
                    }
                    let tag = b"<HW_SEALED>";
                    let mut si = 0usize;
                    while si < tag.len() {
                        h = mix_byte(h, tag[si]);
                        si += 1;
                    }
                    rk += 1;
                    continue;
                }
                h = mix_byte(h, 0x5A);
                if row.meta96 != [0u8; 12] {
                    h = mix_byte(h, 4);
                    let mut mi = 0usize;
                    while mi < 12 {
                        h = mix_byte(h, row.meta96[mi]);
                        mi += 1;
                    }
                }
                let mut c_idx = 0usize;
                while c_idx < col_count {
                    match &row.cells[c_idx] {
                        SqlVal::Int(iv) => {
                            h = mix_byte(h, 1);
                            let bytes = iv.to_le_bytes();
                            let mut bi = 0usize;
                            while bi < 8 {
                                h = mix_byte(h, bytes[bi]);
                                bi += 1;
                            }
                        }
                        SqlVal::Text(tb, tl) => {
                            h = mix_byte(h, 2);
                            h = mix_byte(h, *tl);
                            let mut ti2 = 0usize;
                            while ti2 < (*tl as usize) {
                                h = mix_byte(h, tb[ti2]);
                                ti2 += 1;
                            }
                        }
                    }
                    c_idx += 1;
                }
                rk += 1;
            }
            ord_i += 1;
        }
        h
    }

    /// Return the exact byte offset reached when serializing all live tables and rows
    /// into the 8 KiB `CTTLSQL1` partition layout (must remain `<= SQL_PART_SECTORS * 512 - 8` in inline mode).
    pub fn serialized_partition_bytes(&self) -> usize {
        let mut pos = 52usize;
        let t_len = self.table_slots_len().max(SQL_MAX_TABLES);
        let mut t = 0usize;
        while t < t_len {
            let tbl = self.table_at(t);
            if !tbl.used {
                pos += 1;
                t += 1;
                continue;
            }
            let col_count = (tbl.col_count as usize).min(SQL_MAX_COLS);
            let has_idx = tbl.index_name_len > 0 && (tbl.indexed_col as usize) < col_count;
            pos += 4 + SQL_IDENT_LEN + col_count * (2 + SQL_IDENT_LEN);
            if has_idx {
                pos += 2 + (tbl.index_name_len as usize).min(SQL_IDENT_LEN);
            }
            let r_len = tbl.row_slots_len();
            let mut r = 0usize;
            while r < r_len {
                let row = tbl.row_at(r);
                if row.used {
                    if row.meta96 != [0u8; 12] {
                        pos += 13;
                    }
                    let mut c = 0usize;
                    while c < col_count {
                        pos += match row.cells[c] {
                            SqlVal::Int(v) => {
                                if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                                    3
                                } else {
                                    9
                                }
                            }
                            SqlVal::Text(_, len) => 2 + (len as usize).min(SQL_TEXT_LEN),
                        };
                        c += 1;
                    }
                }
                r += 1;
            }
            t += 1;
        }
        pos
    }

    fn visible_row(&self, t_idx: usize, r_idx: usize, use_committed: bool) -> &SqlRow {
        if use_committed {
            self.committed_row(t_idx, r_idx)
        } else {
            self.table_at(t_idx).row_at(r_idx)
        }
    }

    /// Return `true` if `query` is strictly read-only (`SELECT`, `.tables`, `.schema`, `.dump`, `SHOW`, `DESCRIBE`).
    pub fn is_readonly_query(query: &[u8]) -> bool {
        let q = trim_sql(query);
        if q.starts_with(b"/*triad*/") || q.starts_with(b"/*t*/") {
            return false;
        }
        if q.is_empty() {
            return true;
        }
        let (kw, _) = next_token(q);
        eq_ignore_ascii_case(kw, b"SELECT")
            || eq_ignore_ascii_case(kw, b"SHOW")
            || eq_ignore_ascii_case(kw, b"DESCRIBE")
            || eq_ignore_ascii_case(kw, b".tables")
            || eq_ignore_ascii_case(kw, b".schema")
            || eq_ignore_ascii_case(kw, b".dump")
    }

    /// Execute a SQL statement or meta-command on behalf of the default interactive console (`owner = SQL_OWNER_CONSOLE`).
    /// Returns the number of bytes written to `out`.
    pub fn exec(&mut self, query: &[u8], out: &mut [u8]) -> usize {
        self.exec_as(SQL_OWNER_CONSOLE, query, out)
    }

    /// Execute a SQL statement or meta-command on behalf of `owner` (`SQL_OWNER_CONSOLE`, HTTP session slot `1..=4`,
    /// or subsystem owner `SQL_OWNER_VAULT` / `SQL_OWNER_CRON` / `SQL_OWNER_TRIAD` / `SQL_OWNER_UDP`)
    /// and format the output into `out`.
    ///
    /// Enforces session-bound transactions with **Read Committed** isolation:
    /// - While `self.tx_active` is `true`, mutating statements and `BEGIN`/`COMMIT`/`ROLLBACK` from any
    ///   `owner != self.tx_owner` are refused with `EBUSY`.
    /// - Read-only queries (`SELECT`, `SHOW TABLES`) from `owner != self.tx_owner` read the committed
    ///   pre-transaction snapshot (`committed_row`), preventing dirty reads.
    pub fn exec_as(&mut self, mut owner: u64, query: &[u8], out: &mut [u8]) -> usize {
        let mut q = trim_sql(query);
        if q.starts_with(b"/*triad*/") {
            if owner != SQL_OWNER_CONSOLE && owner != SQL_OWNER_TRIAD {
                return copy_str(
                    b"error: EACCES (/*triad*/ prefix reserved for Triad controller)\n",
                    out,
                );
            }
            owner = SQL_OWNER_TRIAD;
            q = trim_sql(&q[9..]);
        } else if q.starts_with(b"/*t*/") {
            if owner != SQL_OWNER_CONSOLE && owner != SQL_OWNER_TRIAD {
                return copy_str(
                    b"error: EACCES (/*triad*/ prefix reserved for Triad controller)\n",
                    out,
                );
            }
            owner = SQL_OWNER_TRIAD;
            q = trim_sql(&q[5..]);
        }
        if q.is_empty() {
            return copy_str(b"error: empty SQL query\n", out);
        }
        if eq_ignore_ascii_case(q, b".tables") || eq_ignore_ascii_case(q, b"SHOW TABLES") {
            return self.exec_show_tables(owner, out);
        }
        if starts_with_ignore_case(q, b".schema") || starts_with_ignore_case(q, b"DESCRIBE") {
            let (_, rest) = next_token(q);
            return self.exec_schema(trim_sql(rest), out);
        }
        if starts_with_ignore_case(q, b".dump") {
            let (_, rest) = next_token(q);
            return self.exec_dump(owner, trim_sql(rest), out);
        }
        let (kw, rest) = next_token(q);
        if eq_ignore_ascii_case(kw, b"SELECT") {
            return self.exec_select(owner, rest, out);
        }

        // Non-read-only statement: enforce active transaction ownership!
        if self.tx_active && self.tx_owner != owner {
            return copy_str(
                b"error: EBUSY (database locked by another session's transaction)\n",
                out,
            );
        }
        if self.tx_active {
            self.tx_age_ticks = 0;
        }

        // This owner's transaction was rolled back by the idle timeout. Until
        // it acknowledges that, nothing it sends may change the database.
        if self.is_owner_aborted(owner) {
            if eq_ignore_ascii_case(kw, b"ROLLBACK") {
                self.clear_owner_aborted(owner);
                return copy_str(b"ROLLBACK OK\n", out);
            }
            if eq_ignore_ascii_case(kw, b"COMMIT") {
                self.clear_owner_aborted(owner);
                return copy_str(
                    b"error: transaction timed out and was rolled back; nothing was committed\n",
                    out,
                );
            }
            if !eq_ignore_ascii_case(kw, b"BEGIN") {
                return copy_str(
                    b"error: transaction timed out and was rolled back; send ROLLBACK before further statements\n",
                    out,
                );
            }
            self.clear_owner_aborted(owner);
        }

        if eq_ignore_ascii_case(kw, b"BEGIN") {
            if self.tx_active {
                return copy_str(b"error: transaction already active\n", out);
            }
            self.tx_active = true;
            self.tx_owner = owner;
            self.tx_age_ticks = 0;
            self.tx_undo_len = 0;
            self.tx_undo_seq = self.tx_seq;
            copy_str(b"BEGIN OK\n", out)
        } else if eq_ignore_ascii_case(kw, b"COMMIT") {
            if !self.tx_active {
                return copy_str(b"error: no transaction active\n", out);
            }
            let ulen = self.tx_undo_len as usize;
            let mut ui = 0usize;
            while ui < ulen {
                let t = self.tx_undo_table[ui] as usize;
                let r = self.tx_undo_row[ui] as usize;
                if t < self.table_slots_len() && r < SQL_PAGED_MAX_ROWS {
                    self.table_mut(t).mark_row_dirty(r);
                }
                ui += 1;
            }
            if ulen > 0 {
                self.catalog_dirty = true;
            }
            self.tx_active = false;
            self.tx_owner = 0;
            self.tx_age_ticks = 0;
            self.tx_undo_len = 0;
            copy_str(b"COMMIT OK\n", out)
        } else if eq_ignore_ascii_case(kw, b"ROLLBACK") {
            if !self.tx_active {
                return copy_str(b"error: no transaction active\n", out);
            }
            self.rollback_active_transaction();
            copy_str(b"ROLLBACK OK\n", out)
        } else if eq_ignore_ascii_case(kw, b"CREATE") {
            if self.tx_active {
                return copy_str(
                    b"error: DDL (CREATE/DROP) not allowed inside active transaction; COMMIT or ROLLBACK first\n",
                    out,
                );
            }
            self.exec_create(rest, out)
        } else if eq_ignore_ascii_case(kw, b"DROP") {
            if self.tx_active {
                return copy_str(
                    b"error: DDL (CREATE/DROP) not allowed inside active transaction; COMMIT or ROLLBACK first\n",
                    out,
                );
            }
            self.exec_drop(rest, out)
        } else if eq_ignore_ascii_case(kw, b"INSERT") {
            self.exec_insert(rest, false, out)
        } else if eq_ignore_ascii_case(kw, b"REPLACE") {
            self.exec_insert(rest, true, out)
        } else if eq_ignore_ascii_case(kw, b"UPDATE") {
            self.exec_update(rest, out)
        } else if eq_ignore_ascii_case(kw, b"DELETE") {
            self.exec_delete(rest, out)
        } else {
            copy_str(b"error: unsupported SQL statement\n", out)
        }
    }

    fn find_table(&self, name: &[u8]) -> Option<usize> {
        let len = self.table_slots_len();
        let mut i = 0usize;
        while i < len {
            let t = self.table_at(i);
            if t.used && eq_ignore_ascii_case(t.name_bytes(), name) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn exec_show_tables(&self, owner: u64, out: &mut [u8]) -> usize {
        let use_committed = self.tx_active && self.tx_owner != owner;
        let mut pos = 0usize;
        let t_len = self.table_slots_len();
        let mut i = 0usize;
        let mut count = 0usize;
        while i < t_len {
            let tbl = self.table_at(i);
            if tbl.used {
                let mut rows = 0usize;
                let r_len = tbl.row_slots_len();
                let mut r = 0usize;
                while r < r_len {
                    if self.visible_row(i, r, use_committed).used {
                        rows += 1;
                    }
                    r += 1;
                }
                pos += append_bytes(out, pos, tbl.name_bytes());
                pos += append_bytes(out, pos, b" (rows=");
                pos += append_u64(out, pos, rows as u64);
                pos += append_bytes(out, pos, b", cols=");
                pos += append_u64(out, pos, tbl.col_count as u64);
                pos += append_bytes(out, pos, b")\n");
                count += 1;
            }
            i += 1;
        }
        if count == 0 {
            pos += append_bytes(out, pos, b"(no tables)\n");
        }
        pos
    }

    fn exec_schema(&self, filter_name: &[u8], out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        let t_len = self.table_slots_len();
        let mut i = 0usize;
        let mut found = false;
        while i < t_len {
            let t = self.table_at(i);
            if t.used && (filter_name.is_empty() || eq_ignore_ascii_case(t.name_bytes(), filter_name)) {
                found = true;
                pos += append_bytes(out, pos, b"CREATE TABLE ");
                pos += append_bytes(out, pos, t.name_bytes());
                pos += append_bytes(out, pos, b" (");
                let mut c = 0usize;
                while c < t.col_count as usize {
                    if c > 0 {
                        pos += append_bytes(out, pos, b", ");
                    }
                    pos += append_bytes(out, pos, t.cols[c].name_bytes());
                    match t.cols[c].col_type {
                        SqlType::Int => pos += append_bytes(out, pos, b" INT"),
                        SqlType::Text => pos += append_bytes(out, pos, b" TEXT"),
                    }
                    c += 1;
                }
                pos += append_bytes(out, pos, b");\n");
                if t.index_name_len > 0 && (t.indexed_col as usize) < (t.col_count as usize) {
                    pos += append_bytes(out, pos, b"CREATE INDEX ");
                    pos += append_bytes(out, pos, t.index_name_bytes());
                    pos += append_bytes(out, pos, b" ON ");
                    pos += append_bytes(out, pos, t.name_bytes());
                    pos += append_bytes(out, pos, b" (");
                    pos += append_bytes(out, pos, t.cols[t.indexed_col as usize].name_bytes());
                    pos += append_bytes(out, pos, b");\n");
                }
            }
            i += 1;
        }
        if !found {
            pos += append_bytes(out, pos, b"error: table not found\n");
        }
        pos
    }

    fn exec_dump(&self, owner: u64, rest: &[u8], out: &mut [u8]) -> usize {
        let (tname, after_tname) = next_token(rest);
        if tname.is_empty() {
            return copy_str(b"usage: .dump <table> [offset] [limit]\n", out);
        }
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let (off_tok, after_off) = next_token(after_tname);
        let (offset, limit) = if off_tok.is_empty() {
            (0usize, 3usize)
        } else if eq_ignore_ascii_case(off_tok, b"digest") {
            let (extra_tok, _) = next_token(after_off);
            if !extra_tok.is_empty() {
                return copy_str(b"usage: .dump <table> [offset] [limit]\n", out);
            }
            (0usize, 0usize)
        } else {
            let Some(v) = parse_i64(off_tok) else {
                return copy_str(b"usage: .dump <table> [offset] [limit]\n", out);
            };
            if v < 0 {
                return copy_str(b"usage: .dump <table> [offset] [limit]\n", out);
            }
            let (lim_tok, _) = next_token(after_off);
            let lim = if lim_tok.is_empty() {
                3usize
            } else {
                let Some(lv) = parse_i64(lim_tok) else {
                    return copy_str(b"usage: .dump <table> [offset] [limit]\n", out);
                };
                if lv < 0 {
                    return copy_str(b"usage: .dump <table> [offset] [limit]\n", out);
                }
                if lv == 0 {
                    0usize
                } else {
                    (lv as usize).clamp(1, 3)
                }
            };
            (v as usize, lim)
        };

        let use_committed = self.tx_active && self.tx_owner != owner;
        let t = self.table_at(t_idx);
        let col_count = t.col_count as usize;
        let is_kv = eq_ignore_ascii_case(t.name_bytes(), b"kv");
        let r_len = t.row_slots_len();
        let mut matched: Vec<usize> = Vec::new();
        let mut r = 0usize;
        while r < r_len {
            if self.visible_row(t_idx, r, use_committed).used {
                matched.push(r);
            }
            r += 1;
        }

        // Canonically sort rows by cell values so the table digest and dump order
        // are invariant to physical row-slot allocation order across nodes.
        matched.sort_by(|&ri, &rj| {
            let ra = self.visible_row(t_idx, ri, use_committed);
            let rb = self.visible_row(t_idx, rj, use_committed);
            let ord = cmp_rows_canonical(ra, rb, col_count, is_kv);
            if ord < 0 {
                core::cmp::Ordering::Less
            } else if ord > 0 {
                core::cmp::Ordering::Greater
            } else {
                core::cmp::Ordering::Equal
            }
        });
        let mcount = matched.len();

        // Compute 256-bit SHA-256 table digest over schema + canonically sorted rows
        // (normalizing `kv` rows where col 0 starts with `v:` as `<HW_SEALED>`).
        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(t.name_bytes());
        hasher.update([t.col_count]);
        let mut c = 0usize;
        while c < col_count {
            hasher.update(t.cols[c].name_bytes());
            hasher.update([match t.cols[c].col_type {
                SqlType::Int => 1,
                SqlType::Text => 2,
            }]);
            c += 1;
        }
        hasher.update([t.indexed_col]);
        hasher.update(t.index_name_bytes());
        hasher.update((mcount as u64).to_le_bytes());
        let mut k = 0usize;
        while k < mcount {
            let row = self.visible_row(t_idx, matched[k], use_committed);
            let is_vault_row = is_kv
                && col_count > 0
                && matches!(
                    &row.cells[0],
                    SqlVal::Text(tb, tl) if *tl >= 2 && tb[0] == b'v' && tb[1] == b':'
                );
            if is_vault_row {
                hasher.update([0x5B]);
                if let SqlVal::Text(tb, tl) = &row.cells[0] {
                    hasher.update([*tl]);
                    hasher.update(&tb[..*tl as usize]);
                }
                hasher.update(b"<HW_SEALED>");
            } else {
                hasher.update([0x5A]);
                let mut col = 0usize;
                while col < col_count {
                    match &row.cells[col] {
                        SqlVal::Int(iv) => {
                            hasher.update([1]);
                            hasher.update(iv.to_le_bytes());
                        }
                        SqlVal::Text(tb, tl) => {
                            hasher.update([2, *tl]);
                            hasher.update(&tb[..*tl as usize]);
                        }
                    }
                    col += 1;
                }
            }
            k += 1;
        }
        let digest_bytes: [u8; 32] = hasher.finalize().into();

        let max_rows = if offset >= mcount {
            0usize
        } else {
            (mcount - offset).min(limit)
        };
        // Reserve 8 bytes (`SHELL_PROMPT.len()`) so `OsShell::feed_byte` can append
        // `cuttle> ` into the shared 1,024-byte console reply buffer without truncation.
        let max_out_len = out.len().saturating_sub(8);

        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"sqldump table=");
        pos += append_bytes(out, pos, t.name_bytes());
        pos += append_bytes(out, pos, b" rows=");
        pos += append_u64(out, pos, mcount as u64);
        pos += append_bytes(out, pos, b" off=");
        pos += append_u64(out, pos, offset as u64);
        pos += append_bytes(out, pos, b" count=");
        let count_digit_pos = pos;
        pos += append_u64(out, pos, 0);
        pos += append_bytes(out, pos, b" digest=");
        pos += append_hex_bytes(out, pos, &digest_bytes);
        if offset == 0 {
            let mut ddl_buf = [0u8; 192];
            let mut dpos = 0usize;
            dpos += append_bytes(&mut ddl_buf, dpos, b"CREATE TABLE ");
            dpos += append_bytes(&mut ddl_buf, dpos, t.name_bytes());
            dpos += append_bytes(&mut ddl_buf, dpos, b" (");
            let mut col = 0usize;
            while col < col_count {
                if col > 0 {
                    dpos += append_bytes(&mut ddl_buf, dpos, b", ");
                }
                dpos += append_bytes(&mut ddl_buf, dpos, t.cols[col].name_bytes());
                match t.cols[col].col_type {
                    SqlType::Int => dpos += append_bytes(&mut ddl_buf, dpos, b" INT"),
                    SqlType::Text => dpos += append_bytes(&mut ddl_buf, dpos, b" TEXT"),
                }
                col += 1;
            }
            dpos += append_bytes(&mut ddl_buf, dpos, b")");
            pos += append_bytes(out, pos, b" ddl=");
            pos += append_hex_bytes(out, pos, &ddl_buf[..dpos]);

            if t.index_name_len > 0 && (t.indexed_col as usize) < col_count {
                let mut idx_buf = [0u8; 128];
                let mut ipos = 0usize;
                ipos += append_bytes(&mut idx_buf, ipos, b"CREATE INDEX ");
                ipos += append_bytes(&mut idx_buf, ipos, t.index_name_bytes());
                ipos += append_bytes(&mut idx_buf, ipos, b" ON ");
                ipos += append_bytes(&mut idx_buf, ipos, t.name_bytes());
                ipos += append_bytes(&mut idx_buf, ipos, b" (");
                ipos += append_bytes(&mut idx_buf, ipos, t.cols[t.indexed_col as usize].name_bytes());
                ipos += append_bytes(&mut idx_buf, ipos, b")");
                pos += append_bytes(out, pos, b" idx_ddl=");
                pos += append_hex_bytes(out, pos, &idx_buf[..ipos]);
            }
        }
        pos += append_bytes(out, pos, b"\n");

        let mut actual_count = 0usize;
        let mut ri = 0usize;
        while ri < max_rows {
            let row = self.visible_row(t_idx, matched[offset + ri], use_committed);
            let mut row_buf = [0u8; 256];
            let mut rpos = 0usize;
            rpos += append_bytes(&mut row_buf, rpos, b"row ");
            let mut col = 0usize;
            while col < col_count {
                if col > 0 {
                    rpos += append_bytes(&mut row_buf, rpos, b"|");
                }
                match &row.cells[col] {
                    SqlVal::Int(iv) => {
                        rpos += append_bytes(&mut row_buf, rpos, b"I:");
                        rpos += append_i64(&mut row_buf, rpos, *iv);
                    }
                    SqlVal::Text(tb, tl) => {
                        rpos += append_bytes(&mut row_buf, rpos, b"T:");
                        rpos += append_hex_bytes(&mut row_buf, rpos, &tb[..*tl as usize]);
                    }
                }
                col += 1;
            }
            rpos += append_bytes(&mut row_buf, rpos, b"\n");
            let next_pos = pos.saturating_add(rpos);
            if (next_pos > max_out_len && actual_count > 0) || next_pos > out.len() {
                break;
            }
            pos += append_bytes(out, pos, &row_buf[..rpos]);
            actual_count += 1;
            ri += 1;
        }
        if count_digit_pos < pos && actual_count <= 9 {
            out[count_digit_pos] = b'0' + (actual_count as u8);
        }
        pos
    }

    fn exec_create(&mut self, rest: &[u8], out: &mut [u8]) -> usize {
        let (kw_kind, after_kind) = next_token(rest);
        if eq_ignore_ascii_case(kw_kind, b"INDEX") {
            return self.exec_create_index(after_kind, out);
        }
        if !eq_ignore_ascii_case(kw_kind, b"TABLE") {
            return copy_str(b"error: expected CREATE TABLE <name> (...)\n", out);
        }
        let after_table = trim_sql(after_kind);
        let Some(lparen) = find_byte(after_table, b'(') else {
            return copy_str(b"error: missing '(' in CREATE TABLE\n", out);
        };
        let Some(rparen) = rfind_byte(after_table, b')') else {
            return copy_str(b"error: missing ')' in CREATE TABLE\n", out);
        };
        if rparen <= lparen || !trim_sql(&after_table[rparen + 1..]).is_empty() {
            return copy_str(b"error: malformed column list in CREATE TABLE\n", out);
        }
        let mut tname = trim_sql(&after_table[..lparen]);
        let mut if_not_exists = false;
        let (w1, r1) = next_token(tname);
        if eq_ignore_ascii_case(w1, b"IF") {
            let (w2, r2) = next_token(r1);
            let (w3, r3) = next_token(r2);
            if eq_ignore_ascii_case(w2, b"NOT") && eq_ignore_ascii_case(w3, b"EXISTS") {
                if_not_exists = true;
                tname = trim_sql(r3);
            }
        }
        if !is_valid_ident(tname) {
            return copy_str(b"error: invalid table name\n", out);
        }
        if self.find_table(tname).is_some() {
            if if_not_exists {
                let mut pos = 0usize;
                pos += append_bytes(out, pos, b"CREATE TABLE ");
                pos += append_bytes(out, pos, tname);
                pos += append_bytes(out, pos, b" OK\n");
                return pos;
            }
            return copy_str(b"error: table already exists\n", out);
        }
        let mut free_slot = None;
        let max_tbls = self.max_tables();
        let mut i = 0usize;
        while i < max_tbls {
            if !self.table_at(i).used {
                free_slot = Some(i);
                break;
            }
            i += 1;
        }
        let Some(t_idx) = free_slot else {
            return copy_str(b"error: maximum table limit reached\n", out);
        };

        let cols_raw = trim_sql(&after_table[lparen + 1..rparen]);
        if cols_raw.is_empty() {
            return copy_str(b"error: malformed column list in CREATE TABLE\n", out);
        }
        let mut parsed_cols = [SqlColumn::empty(); SQL_MAX_COLS];
        let mut col_count = 0u8;

        let mut cursor = cols_raw;
        while !cursor.is_empty() {
            let had_comma = find_byte(cursor, b',').is_some();
            let (col_def, next_cursor) = split_comma(cursor);
            cursor = next_cursor;
            let col_def = trim_sql(col_def);
            if col_def.is_empty() || (had_comma && trim_sql(cursor).is_empty()) {
                return copy_str(b"error: empty column definition in CREATE TABLE\n", out);
            }
            if col_count as usize >= SQL_MAX_COLS {
                return copy_str(b"error: too many columns (max 4)\n", out);
            }
            let (cname, ctype_raw) = next_token(col_def);
            let (ctype_tok, after_ctype) = next_token(ctype_raw);
            if !trim_sql(after_ctype).is_empty() {
                return copy_str(b"error: unexpected tokens in column definition\n", out);
            }
            if !is_valid_ident(cname) {
                return copy_str(b"error: invalid column name\n", out);
            }
            let mut dup = false;
            let mut j = 0usize;
            while j < col_count as usize {
                if eq_ignore_ascii_case(parsed_cols[j].name_bytes(), cname) {
                    dup = true;
                    break;
                }
                j += 1;
            }
            if dup {
                return copy_str(b"error: duplicate column name in CREATE TABLE\n", out);
            }
            let ctype = if eq_ignore_ascii_case(ctype_tok, b"INT")
                || eq_ignore_ascii_case(ctype_tok, b"INTEGER")
            {
                SqlType::Int
            } else if eq_ignore_ascii_case(ctype_tok, b"TEXT")
                || eq_ignore_ascii_case(ctype_tok, b"VARCHAR")
            {
                SqlType::Text
            } else {
                return copy_str(b"error: column type must be INT or TEXT\n", out);
            };
            let idx = col_count as usize;
            parsed_cols[idx].name[..cname.len()].copy_from_slice(cname);
            parsed_cols[idx].name_len = cname.len() as u8;
            parsed_cols[idx].col_type = ctype;
            col_count += 1;
        }
        if !trim_sql(&after_table[rparen + 1..]).is_empty() {
            return copy_str(b"error: unexpected trailing tokens after CREATE TABLE\n", out);
        }
        if col_count == 0 {
            return copy_str(b"error: CREATE TABLE requires at least 1 column\n", out);
        }
        {
            let tbl = self.table_mut(t_idx);
            tbl.reset_in_place();
            tbl.used = true;
            tbl.name[..tname.len()].copy_from_slice(tname);
            tbl.name_len = tname.len() as u8;
            tbl.col_count = col_count;
            tbl.cols = parsed_cols;
            tbl.schema_dirty = true;
        }
        if !self.paged_mode && self.serialized_partition_bytes() > SQL_PART_SECTORS * 512 - 8 {
            self.table_mut(t_idx).reset_in_place();
            return copy_str(
                b"error: SQL partition capacity full (8 KiB CTTLSQL1 limit)\n",
                out,
            );
        }
        self.catalog_dirty = true;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"CREATE TABLE ");
        pos += append_bytes(out, pos, tname);
        pos += append_bytes(out, pos, b" OK\n");
        pos
    }

    fn exec_create_index(&mut self, rest: &[u8], out: &mut [u8]) -> usize {
        let (idx_name, after_idx) = next_token(rest);
        if !is_valid_ident(idx_name) {
            return copy_str(b"error: invalid index name\n", out);
        }
        let (kw_on, after_on) = next_token(after_idx);
        if !eq_ignore_ascii_case(kw_on, b"ON") {
            return copy_str(b"error: expected CREATE INDEX <name> ON <table> (<col>)\n", out);
        }
        let after_on = trim_sql(after_on);
        let Some(lparen) = find_byte(after_on, b'(') else {
            return copy_str(b"error: missing '(' in CREATE INDEX\n", out);
        };
        let Some(rparen) = rfind_byte(after_on, b')') else {
            return copy_str(b"error: missing ')' in CREATE INDEX\n", out);
        };
        if rparen <= lparen || !trim_sql(&after_on[rparen + 1..]).is_empty() {
            return copy_str(b"error: malformed column in CREATE INDEX\n", out);
        }
        let tname = trim_sql(&after_on[..lparen]);
        let cname = trim_sql(&after_on[lparen + 1..rparen]);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let Some(c_idx) = self.table_at(t_idx).find_col(cname) else {
            return copy_str(b"error: column not found in CREATE INDEX\n", out);
        };
        // The index name is stored in the partition image. Admit it only if the
        // image still fits in inline mode; otherwise `save_partition` could not hold the table's rows.
        if !self.paged_mode {
            let tbl_ref = self.table_at(t_idx);
            let col_count = (tbl_ref.col_count as usize).min(SQL_MAX_COLS);
            let had_idx = tbl_ref.index_name_len > 0 && (tbl_ref.indexed_col as usize) < col_count;
            let old_idx_bytes = if had_idx {
                2 + (tbl_ref.index_name_len as usize).min(SQL_IDENT_LEN)
            } else {
                0
            };
            let new_idx_bytes = 2 + idx_name.len().min(SQL_IDENT_LEN);
            if self
                .serialized_partition_bytes()
                .saturating_sub(old_idx_bytes)
                .saturating_add(new_idx_bytes)
                > SQL_PART_SECTORS * 512 - 8
            {
                return copy_str(
                    b"error: SQL partition capacity full (8 KiB CTTLSQL1 limit)\n",
                    out,
                );
            }
        }
        {
            let tbl = self.table_mut(t_idx);
            tbl.indexed_col = c_idx as u8;
            tbl.index_name = [0u8; SQL_IDENT_LEN];
            tbl.index_name[..idx_name.len()].copy_from_slice(idx_name);
            tbl.index_name_len = idx_name.len() as u8;
            tbl.schema_dirty = true;
            tbl.rebuild_index();
        }
        self.catalog_dirty = true;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"CREATE INDEX ");
        pos += append_bytes(out, pos, idx_name);
        pos += append_bytes(out, pos, b" OK\n");
        pos
    }

    fn exec_drop(&mut self, rest: &[u8], out: &mut [u8]) -> usize {
        let (kw_kind, after_kind) = next_token(rest);
        if eq_ignore_ascii_case(kw_kind, b"INDEX") {
            let (idx_name, _) = next_token(after_kind);
            let t_len = self.table_slots_len();
            let mut i = 0usize;
            while i < t_len {
                let is_match = {
                    let t = self.table_at(i);
                    t.used && t.index_name_len > 0 && eq_ignore_ascii_case(t.index_name_bytes(), idx_name)
                };
                if is_match {
                    let tbl = self.table_mut(i);
                    tbl.indexed_col = SQL_NO_INDEX;
                    tbl.index_name = [0u8; SQL_IDENT_LEN];
                    tbl.index_name_len = 0;
                    tbl.schema_dirty = true;
                    tbl.rebuild_index();
                    self.catalog_dirty = true;
                    self.tx_seq = self.tx_seq.wrapping_add(1);
                    let mut pos = 0usize;
                    pos += append_bytes(out, pos, b"DROP INDEX ");
                    pos += append_bytes(out, pos, idx_name);
                    pos += append_bytes(out, pos, b" OK\n");
                    return pos;
                }
                i += 1;
            }
            return copy_str(b"error: index not found\n", out);
        }
        if !eq_ignore_ascii_case(kw_kind, b"TABLE") {
            return copy_str(b"error: expected DROP TABLE <name>\n", out);
        }
        let (mut tname, after_t1) = next_token(after_kind);
        let mut if_exists = false;
        if eq_ignore_ascii_case(tname, b"IF") {
            let (w2, r2) = next_token(after_t1);
            if eq_ignore_ascii_case(w2, b"EXISTS") {
                if_exists = true;
                let (real_tname, _) = next_token(r2);
                tname = real_tname;
            }
        }
        let Some(t_idx) = self.find_table(tname) else {
            if if_exists {
                let mut pos = 0usize;
                pos += append_bytes(out, pos, b"DROP TABLE ");
                pos += append_bytes(out, pos, tname);
                pos += append_bytes(out, pos, b" OK\n");
                return pos;
            }
            return copy_str(b"error: table not found\n", out);
        };
        self.table_mut(t_idx).reset_in_place();
        self.catalog_dirty = true;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"DROP TABLE ");
        pos += append_bytes(out, pos, tname);
        pos += append_bytes(out, pos, b" OK\n");
        pos
    }

    fn collect_matching_rows(
        &mut self,
        t_idx: usize,
        filter: &Option<WhereFilter>,
        use_committed: bool,
        matched: &mut Vec<usize>,
    ) {
        matched.clear();
        let idx_col = self.table_at(t_idx).indexed_col as usize;
        let col_count = self.table_at(t_idx).col_count as usize;
        if !use_committed
            && idx_col < col_count
            && self.table_at(t_idx).cols[idx_col].col_type == SqlType::Int
        {
            if let Some((op, target)) = filter.as_ref().and_then(|f| f.indexed_int_range(idx_col)) {
                let mut candidates = Vec::new();
                if self
                    .table_at(t_idx)
                    .btree_scan_int(op, target, &mut candidates)
                {
                    self.idx_hits = self.idx_hits.wrapping_add(1);
                    let mut ci = 0usize;
                    while ci < candidates.len() {
                        let r = candidates[ci];
                        let row = self.visible_row(t_idx, r, false);
                        if row.used {
                            let pass = match filter {
                                Some(f) => f.eval(row),
                                None => true,
                            };
                            if pass {
                                matched.push(r);
                            }
                        }
                        ci += 1;
                    }
                    return;
                }
            }
        }
        let indexed_eq_hash = if use_committed {
            None
        } else {
            filter.as_ref().and_then(|f| f.single_indexed_eq(idx_col))
        };
        if indexed_eq_hash.is_some() {
            self.idx_hits = self.idx_hits.wrapping_add(1);
        }
        let r_len = self.table_at(t_idx).row_slots_len();
        let mut r = 0usize;
        while r < r_len {
            let row = self.visible_row(t_idx, r, use_committed);
            if row.used {
                if let Some(h) = indexed_eq_hash {
                    if self.table_at(t_idx).hash_at(r) != h {
                        r += 1;
                        continue;
                    }
                }
                let pass = match filter {
                    Some(f) => f.eval(row),
                    None => true,
                };
                if pass {
                    matched.push(r);
                }
            }
            r += 1;
        }
    }

    fn exec_insert(&mut self, rest: &[u8], mut is_replace: bool, out: &mut [u8]) -> usize {
        let (kw1, after_kw1) = next_token(rest);
        let after_into = if eq_ignore_ascii_case(kw1, b"OR") {
            let (kw_rep, after_rep) = next_token(after_kw1);
            let (kw_into, after_i) = next_token(after_rep);
            if !eq_ignore_ascii_case(kw_rep, b"REPLACE") || !eq_ignore_ascii_case(kw_into, b"INTO")
            {
                return copy_str(
                    b"error: expected INSERT [OR REPLACE] INTO <table> VALUES (...)\n",
                    out,
                );
            }
            is_replace = true;
            after_i
        } else if eq_ignore_ascii_case(kw1, b"INTO") {
            after_kw1
        } else {
            return copy_str(b"error: expected INSERT INTO <table> VALUES (...)\n", out);
        };
        let (tname, after_tname) = next_token(after_into);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let after_tname = trim_sql(after_tname);
        let (kw_values, after_values) = if starts_with_ignore_case(after_tname, b"VALUES")
            && (after_tname.len() == 6
                || matches!(after_tname[6], b' ' | b'\t' | b'\r' | b'\n' | b'('))
        {
            (&after_tname[..6], trim_sql(&after_tname[6..]))
        } else {
            next_token(after_tname)
        };
        if !eq_ignore_ascii_case(kw_values, b"VALUES") {
            return copy_str(b"error: expected VALUES (...)\n", out);
        }
        let after_values = trim_sql(after_values);
        let tuple_slices = match parse_values_tuple_slices(after_values) {
            Ok(v) => v,
            Err(err_msg) => return copy_str(err_msg, out),
        };
        if tuple_slices.len() > SQL_PAGED_MAX_ROWS {
            return copy_str(b"error: too many tuples in VALUES batch\n", out);
        }

        let col_count = self.table_at(t_idx).col_count as usize;
        let cols = self.table_at(t_idx).cols;
        let mut parsed_rows: Vec<SqlRow> = Vec::with_capacity(tuple_slices.len());
        let mut ti = 0usize;
        while ti < tuple_slices.len() {
            let mut row = SqlRow::empty();
            row.used = true;
            let mut val_idx = 0usize;
            let mut cursor = trim_sql(tuple_slices[ti]);
            while !cursor.is_empty() {
                let (val_raw, next_cursor) = split_comma_respecting_quotes(cursor);
                let had_comma = val_raw.len() < cursor.len();
                cursor = next_cursor;
                let val_raw = trim_sql(val_raw);
                if val_raw.is_empty() || (had_comma && trim_sql(cursor).is_empty()) {
                    return copy_str(b"error: empty literal in VALUES list\n", out);
                }
                if val_idx >= col_count {
                    return copy_str(b"error: too many values for table schema\n", out);
                }
                let expected_type = cols[val_idx].col_type;
                let Some(parsed) = parse_literal(val_raw, expected_type) else {
                    return copy_str(b"error: type mismatch in VALUES literal\n", out);
                };
                row.cells[val_idx] = parsed;
                val_idx += 1;
            }
            if val_idx != col_count {
                return copy_str(b"error: column count mismatch in VALUES\n", out);
            }
            parsed_rows.push(row);
            ti += 1;
        }

        // Plan target slots across the entire batch before mutating any live state,
        // ensuring multi-tuple VALUES statements are 100% atomic on capacity/undo errors.
        let max_rows = self.max_rows_per_table();
        let mut planned_slots: Vec<usize> = Vec::with_capacity(parsed_rows.len());
        let mut next_free_scan = 0usize;
        let mut pi = 0usize;
        while pi < parsed_rows.len() {
            let cand = &parsed_rows[pi];
            let mut chosen_slot: Option<usize> = None;
            if is_replace && col_count > 0 {
                // Check earlier tuples in the same batch first so duplicate keys overwrite in-place.
                let mut prev_p = 0usize;
                while prev_p < pi {
                    if parsed_rows[prev_p].cells[0].compare(CmpOp::Eq, &cand.cells[0]) {
                        chosen_slot = Some(planned_slots[prev_p]);
                        break;
                    }
                    prev_p += 1;
                }
                if chosen_slot.is_none() {
                    let existing_len = self.table_at(t_idx).row_slots_len().min(max_rows);
                    let mut r = 0usize;
                    while r < existing_len {
                        let existing = self.table_at(t_idx).row_at(r);
                        if existing.used && existing.cells[0].compare(CmpOp::Eq, &cand.cells[0]) {
                            chosen_slot = Some(r);
                            break;
                        }
                        r += 1;
                    }
                }
            }
            if chosen_slot.is_none() {
                while next_free_scan < max_rows {
                    let already_claimed = planned_slots.contains(&next_free_scan);
                    if !already_claimed && !self.table_at(t_idx).row_at(next_free_scan).used {
                        chosen_slot = Some(next_free_scan);
                        next_free_scan += 1;
                        break;
                    }
                    next_free_scan += 1;
                }
            }
            let Some(slot) = chosen_slot else {
                return if self.paged_mode {
                    copy_str(b"error: table row capacity full (max 2048)\n", out)
                } else {
                    copy_str(b"error: table row capacity full (max 64)\n", out)
                };
            };
            planned_slots.push(slot);
            pi += 1;
        }

        if self.paged_mode {
            if let Some(budget) = self.paged_page_budget {
                if self.paged_pages_with_planned_inserts(t_idx, &planned_slots) > budget {
                    return copy_str(b"error: ENOSPC (page store full)\n", out);
                }
            }
        }

        if self.tx_active {
            let mut distinct_new_undo: Vec<usize> = Vec::new();
            let mut k = 0usize;
            while k < planned_slots.len() {
                let s = planned_slots[k];
                if !self.has_undo_record(t_idx, s) && !distinct_new_undo.contains(&s) {
                    distinct_new_undo.push(s);
                }
                k += 1;
            }
            if (self.tx_undo_len as usize) + distinct_new_undo.len() > SQL_TX_UNDO_CAP {
                return copy_str(
                    b"error: transaction undo log full (max 8 rows); COMMIT or ROLLBACK first\n",
                    out,
                );
            }
        }

        if !self.paged_mode {
            let mut saved_originals: Vec<(usize, SqlRow)> = Vec::new();
            let mut k = 0usize;
            while k < planned_slots.len() {
                let s = planned_slots[k];
                if !saved_originals.iter().any(|(idx, _)| *idx == s) {
                    saved_originals.push((s, *self.table_at(t_idx).row_at(s)));
                }
                *self.table_mut(t_idx).row_mut(s) = parsed_rows[k];
                k += 1;
            }
            let too_big = self.serialized_partition_bytes() > SQL_PART_SECTORS * 512 - 8;
            let mut ri = saved_originals.len();
            while ri > 0 {
                ri -= 1;
                let (s, orig) = saved_originals[ri];
                *self.table_mut(t_idx).row_mut(s) = orig;
            }
            if too_big {
                return copy_str(
                    b"error: SQL partition capacity full (8 KiB CTTLSQL1 limit)\n",
                    out,
                );
            }
        }

        let mut k = 0usize;
        while k < planned_slots.len() {
            let s = planned_slots[k];
            let new_row = parsed_rows[k];
            self.record_row_undo(t_idx, s);
            let prev_row = *self.table_at(t_idx).row_at(s);
            let tbl = self.table_mut(t_idx);
            *tbl.row_mut(s) = new_row;
            tbl.sync_index_row(s, Some(&prev_row), Some(&new_row));
            tbl.mark_row_dirty(s);
            k += 1;
        }
        self.catalog_dirty = true;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut pos = 0usize;
        if is_replace {
            pos += append_bytes(out, pos, b"REPLACE ");
        } else {
            pos += append_bytes(out, pos, b"INSERT ");
        }
        pos += append_u64(out, pos, parsed_rows.len() as u64);
        pos += append_bytes(out, pos, b"\n");
        pos
    }

    fn exec_select(&mut self, owner: u64, rest: &[u8], out: &mut [u8]) -> usize {
        let Some((proj_raw, after_from)) = split_keyword_ignore_case(rest, b"FROM") else {
            return copy_str(b"error: SELECT missing FROM clause\n", out);
        };
        let proj = trim_sql(proj_raw);
        let (tname, mut clauses) = next_token(after_from);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let use_committed = self.tx_active && self.tx_owner != owner;

        // Parse optional LIMIT <n> at tail.
        let max_rows = self.max_rows_per_table();
        let mut limit = max_rows;
        if let Some((before_lim, lim_str)) = split_keyword_ignore_case(clauses, b"LIMIT") {
            clauses = before_lim;
            let (lim_tok, lim_tail) = next_token(lim_str);
            if !trim_sql(lim_tail).is_empty() {
                return copy_str(b"error: unexpected tokens after LIMIT\n", out);
            }
            let Some(n) = parse_i64(lim_tok) else {
                return copy_str(b"error: invalid LIMIT value\n", out);
            };
            if n < 0 {
                return copy_str(b"error: LIMIT must be non-negative\n", out);
            }
            limit = (n as usize).min(max_rows);
        }

        // Parse optional ORDER BY <col> [ASC|DESC].
        let mut order_col: Option<(usize, bool)> = None;
        if let Some((before_ord, ord_str)) = split_keyword_ignore_case(clauses, b"ORDER") {
            clauses = before_ord;
            let (kw_by, after_by) = next_token(ord_str);
            if !eq_ignore_ascii_case(kw_by, b"BY") {
                return copy_str(b"error: expected ORDER BY <col> [ASC|DESC]\n", out);
            }
            let (ocol, dir_raw) = next_token(after_by);
            let (dir_tok, dir_tail) = next_token(dir_raw);
            if !trim_sql(dir_tail).is_empty() {
                return copy_str(b"error: unexpected tokens after ORDER BY\n", out);
            }
            let Some(c_idx) = self.table_at(t_idx).find_col(ocol) else {
                return copy_str(b"error: unknown column in ORDER BY\n", out);
            };
            let desc = if dir_tok.is_empty() || eq_ignore_ascii_case(dir_tok, b"ASC") {
                false
            } else if eq_ignore_ascii_case(dir_tok, b"DESC") {
                true
            } else {
                return copy_str(b"error: invalid ORDER BY direction\n", out);
            };
            order_col = Some((c_idx, desc));
        }

        // Parse optional WHERE <col> <op> <val> [AND|OR <col2> <op2> <val2>].
        let mut filter: Option<WhereFilter> = None;
        let clauses = trim_sql(clauses);
        if !clauses.is_empty() {
            let (kw_where, cond_raw) = next_token(clauses);
            if !eq_ignore_ascii_case(kw_where, b"WHERE") {
                return copy_str(b"error: unexpected clause after FROM\n", out);
            }
            let Some(parsed_cond) = parse_where_filter(self.table_at(t_idx), cond_raw) else {
                return copy_str(b"error: malformed WHERE condition\n", out);
            };
            filter = Some(parsed_cond);
        }

        let mut matched: Vec<usize> = Vec::new();
        self.collect_matching_rows(t_idx, &filter, use_committed, &mut matched);
        let mcount = matched.len();

        // Sort matched rows if ORDER BY is present.
        if let Some((c_idx, desc)) = order_col {
            matched.sort_by(|&ri, &rj| {
                let a = &self.visible_row(t_idx, ri, use_committed).cells[c_idx];
                let b = &self.visible_row(t_idx, rj, use_committed).cells[c_idx];
                if desc {
                    if a.compare(CmpOp::Gt, b) {
                        core::cmp::Ordering::Less
                    } else if a.compare(CmpOp::Lt, b) {
                        core::cmp::Ordering::Greater
                    } else {
                        core::cmp::Ordering::Equal
                    }
                } else if a.compare(CmpOp::Lt, b) {
                    core::cmp::Ordering::Less
                } else if a.compare(CmpOp::Gt, b) {
                    core::cmp::Ordering::Greater
                } else {
                    core::cmp::Ordering::Equal
                }
            });
        }

        // Handle COUNT(*) aggregate.
        if eq_ignore_ascii_case(proj, b"COUNT(*)") {
            let mut pos = 0usize;
            pos += append_bytes(out, pos, b"count\n");
            pos += append_u64(out, pos, mcount as u64);
            pos += append_bytes(out, pos, b"\n");
            return pos;
        }

        // Handle SUM(<col>), MIN(<col>), MAX(<col>), AVG(<col>) aggregates.
        if let Some((agg_kind, agg_col_name)) = parse_aggregate_proj(proj) {
            let Some(c_idx) = self.table_at(t_idx).find_col(agg_col_name) else {
                return copy_str(b"error: unknown column in aggregate\n", out);
            };
            if self.table_at(t_idx).cols[c_idx].col_type != SqlType::Int {
                return copy_str(b"error: numeric aggregate requires INT column\n", out);
            }
            let hdr: &[u8] = match agg_kind {
                AggKind::Sum => b"sum\n",
                AggKind::Min => b"min\n",
                AggKind::Max => b"max\n",
                AggKind::Avg => b"avg\n",
            };
            let mut pos = 0usize;
            pos += append_bytes(out, pos, hdr);
            if mcount == 0 {
                pos += append_bytes(out, pos, b"0\n");
                return pos;
            }
            let mut sum: i128 = 0;
            let mut min_v = i64::MAX;
            let mut max_v = i64::MIN;
            let mut k = 0usize;
            while k < mcount {
                if let SqlVal::Int(v) =
                    self.visible_row(t_idx, matched[k], use_committed).cells[c_idx]
                {
                    sum = sum.saturating_add(v as i128);
                    if v < min_v {
                        min_v = v;
                    }
                    if v > max_v {
                        max_v = v;
                    }
                }
                k += 1;
            }
            let res_i64 = match agg_kind {
                AggKind::Sum => sum.clamp(i64::MIN as i128, i64::MAX as i128) as i64,
                AggKind::Min => min_v,
                AggKind::Max => max_v,
                AggKind::Avg => {
                    let avg = sum / (mcount as i128);
                    avg.clamp(i64::MIN as i128, i64::MAX as i128) as i64
                }
            };
            pos += append_i64(out, pos, res_i64);
            pos += append_bytes(out, pos, b"\n");
            return pos;
        }

        // Resolve projected columns.
        let mut proj_cols = [0usize; SQL_MAX_COLS];
        let mut proj_count = 0usize;
        if proj == b"*" {
            while proj_count < self.table_at(t_idx).col_count as usize {
                proj_cols[proj_count] = proj_count;
                proj_count += 1;
            }
        } else {
            let proj_trimmed = trim_sql(proj);
            if proj_trimmed.is_empty() {
                return copy_str(b"error: empty column in SELECT projection\n", out);
            }
            let mut cursor = proj_trimmed;
            while !cursor.is_empty() {
                let had_comma = find_byte(cursor, b',').is_some();
                let (cname, next_cursor) = split_comma(cursor);
                cursor = next_cursor;
                let cname = trim_sql(cname);
                if cname.is_empty() || (had_comma && trim_sql(cursor).is_empty()) {
                    return copy_str(b"error: empty column in SELECT projection\n", out);
                }
                let Some(c_idx) = self.table_at(t_idx).find_col(cname) else {
                    return copy_str(b"error: unknown column in SELECT projection\n", out);
                };
                if proj_count >= SQL_MAX_COLS {
                    return copy_str(b"error: too many projected columns (max 4)\n", out);
                }
                proj_cols[proj_count] = c_idx;
                proj_count += 1;
            }
        }

        // Format header + rows.
        let mut pos = 0usize;
        let mut c = 0usize;
        while c < proj_count {
            if c > 0 {
                pos += append_bytes(out, pos, b"|");
            }
            pos += append_bytes(out, pos, self.table_at(t_idx).cols[proj_cols[c]].name_bytes());
            c += 1;
        }
        pos += append_bytes(out, pos, b"\n");

        let emit_rows = mcount.min(limit);
        let mut m = 0usize;
        while m < emit_rows {
            let row = self.visible_row(t_idx, matched[m], use_committed);
            let mut pc = 0usize;
            while pc < proj_count {
                if pc > 0 {
                    pos += append_bytes(out, pos, b"|");
                }
                match &row.cells[proj_cols[pc]] {
                    SqlVal::Int(v) => pos += append_i64(out, pos, *v),
                    SqlVal::Text(buf, len) => pos += append_bytes(out, pos, &buf[..*len as usize]),
                }
                pc += 1;
            }
            pos += append_bytes(out, pos, b"\n");
            m += 1;
        }
        pos
    }

    fn exec_update(&mut self, rest: &[u8], out: &mut [u8]) -> usize {
        let (tname, after_tname) = next_token(rest);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let (kw_set, after_set) = next_token(after_tname);
        if !eq_ignore_ascii_case(kw_set, b"SET") {
            return copy_str(b"error: expected UPDATE <table> SET <col> = <val>\n", out);
        }
        let (set_clause, where_clause) =
            if let Some((s, w)) = split_keyword_ignore_case(after_set, b"WHERE") {
                (trim_sql(s), Some(trim_sql(w)))
            } else {
                (trim_sql(after_set), None)
            };

        let Some(eq_pos) = find_byte(set_clause, b'=') else {
            return copy_str(b"error: missing '=' in SET clause\n", out);
        };
        let set_col_name = trim_sql(&set_clause[..eq_pos]);
        let set_val_raw = trim_sql(&set_clause[eq_pos + 1..]);
        let Some(set_col_idx) = self.table_at(t_idx).find_col(set_col_name) else {
            return copy_str(b"error: unknown column in SET clause\n", out);
        };
        let set_col_type = self.table_at(t_idx).cols[set_col_idx].col_type;
        let Some(new_val) = parse_literal(set_val_raw, set_col_type) else {
            return copy_str(b"error: invalid value in SET clause\n", out);
        };

        let filter = if let Some(w_raw) = where_clause {
            let Some(cond) = parse_where_filter(self.table_at(t_idx), w_raw) else {
                return copy_str(b"error: malformed WHERE condition\n", out);
            };
            Some(cond)
        } else {
            None
        };

        let mut matched: Vec<usize> = Vec::new();
        self.collect_matching_rows(t_idx, &filter, false, &mut matched);
        let mcount = matched.len();

        if self.tx_active {
            let mut new_undo = 0usize;
            let mut mi = 0usize;
            while mi < mcount {
                if !self.has_undo_record(t_idx, matched[mi]) {
                    new_undo += 1;
                }
                mi += 1;
            }
            if (self.tx_undo_len as usize) + new_undo > SQL_TX_UNDO_CAP {
                return copy_str(
                    b"error: transaction undo log full (max 8 rows); COMMIT or ROLLBACK first\n",
                    out,
                );
            }
        }

        // Pre-verify 8 KiB `CTTLSQL1` partition budget in inline mode before mutating rows or undo log:
        if !self.paged_mode && mcount > 0 {
            let mut delta: isize = 0;
            let new_cell_bytes: isize = match new_val {
                SqlVal::Int(v) => {
                    if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                        3
                    } else {
                        9
                    }
                }
                SqlVal::Text(_, len) => (2 + (len as usize).min(SQL_TEXT_LEN)) as isize,
            };
            let mut mi = 0usize;
            while mi < mcount {
                let old_cell = &self.table_at(t_idx).row_at(matched[mi]).cells[set_col_idx];
                let old_bytes: isize = match old_cell {
                    SqlVal::Int(v) => {
                        if *v >= (i16::MIN as i64) && *v <= (i16::MAX as i64) {
                            3
                        } else {
                            9
                        }
                    }
                    SqlVal::Text(_, len) => (2 + (*len as usize).min(SQL_TEXT_LEN)) as isize,
                };
                delta += new_cell_bytes - old_bytes;
                mi += 1;
            }
            if delta > 0
                && self.serialized_partition_bytes().saturating_add(delta as usize)
                    > SQL_PART_SECTORS * 512 - 8
            {
                return copy_str(
                    b"error: SQL partition capacity full (8 KiB CTTLSQL1 limit)\n",
                    out,
                );
            }
        }

        let mut updated = 0u64;
        let mut m = 0usize;
        while m < mcount {
            let row_idx = matched[m];
            self.record_row_undo(t_idx, row_idx);
            let prev_row = *self.table_at(t_idx).row_at(row_idx);
            let mut next_row = prev_row;
            next_row.cells[set_col_idx] = new_val;
            let tbl = self.table_mut(t_idx);
            *tbl.row_mut(row_idx) = next_row;
            tbl.sync_index_row(row_idx, Some(&prev_row), Some(&next_row));
            tbl.mark_row_dirty(row_idx);
            updated += 1;
            m += 1;
        }
        if updated > 0 {
            self.catalog_dirty = true;
            self.tx_seq = self.tx_seq.wrapping_add(1);
        }
        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"UPDATE ");
        pos += append_u64(out, pos, updated);
        pos += append_bytes(out, pos, b"\n");
        pos
    }

    fn exec_delete(&mut self, rest: &[u8], out: &mut [u8]) -> usize {
        let (kw_from, after_from) = next_token(rest);
        if !eq_ignore_ascii_case(kw_from, b"FROM") {
            return copy_str(b"error: expected DELETE FROM <table> [WHERE ...]\n", out);
        }
        let (tname, after_tname) = next_token(after_from);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let after_tname = trim_sql(after_tname);
        let filter = if !after_tname.is_empty() {
            let (kw_where, cond_raw) = next_token(after_tname);
            if !eq_ignore_ascii_case(kw_where, b"WHERE") {
                return copy_str(b"error: expected WHERE after table name\n", out);
            }
            let Some(cond) = parse_where_filter(self.table_at(t_idx), cond_raw) else {
                return copy_str(b"error: malformed WHERE condition\n", out);
            };
            Some(cond)
        } else {
            None
        };

        let mut matched: Vec<usize> = Vec::new();
        self.collect_matching_rows(t_idx, &filter, false, &mut matched);
        let mcount = matched.len();

        if self.tx_active {
            let mut new_undo = 0usize;
            let mut mi = 0usize;
            while mi < mcount {
                if !self.has_undo_record(t_idx, matched[mi]) {
                    new_undo += 1;
                }
                mi += 1;
            }
            if (self.tx_undo_len as usize) + new_undo > SQL_TX_UNDO_CAP {
                return copy_str(
                    b"error: transaction undo log full (max 8 rows); COMMIT or ROLLBACK first\n",
                    out,
                );
            }
        }

        let mut deleted = 0u64;
        let mut m = 0usize;
        while m < mcount {
            let row_idx = matched[m];
            self.record_row_undo(t_idx, row_idx);
            let prev_row = *self.table_at(t_idx).row_at(row_idx);
            let tbl = self.table_mut(t_idx);
            *tbl.row_mut(row_idx) = SqlRow::empty();
            tbl.sync_index_row(row_idx, Some(&prev_row), None);
            tbl.mark_row_dirty(row_idx);
            deleted += 1;
            m += 1;
        }
        if deleted > 0 {
            self.catalog_dirty = true;
            self.tx_seq = self.tx_seq.wrapping_add(1);
        }
        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"DELETE ");
        pos += append_u64(out, pos, deleted);
        pos += append_bytes(out, pos, b"\n");
        pos
    }

    /// Serialize the entire database into an 8-sector (`4 KiB`) partition image
    /// protected by `CTTLSQL1` magic and a keyed `HMAC-SHA256` authentication tag.
    ///
    /// If a `BEGIN` transaction is currently open, serializes the last **committed**
    /// pre-transaction state (`tx_undo_seq` and `committed_row`) so uncommitted rows
    /// are never persisted to disk before `COMMIT`.
    ///
    /// If the image cannot be produced (unset key, or a database too large for
    /// the partition) `sectors` is zero-filled, which no loader accepts. Use
    /// [`SqlDb::try_save_partition`] to learn why.
    pub fn save_partition(
        &self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &mut [[u8; 512]; SQL_PART_SECTORS],
    ) {
        let _ = self.try_save_partition(key, sectors);
    }

    /// The sequence number [`SqlDb::save_partition`] stores in the partition
    /// header: `tx_seq` of the last committed statement. While a transaction
    /// is open it stays at the pre-`BEGIN` value and jumps on `COMMIT`, so a
    /// change in this value means the persisted image changed.
    pub fn committed_seq(&self) -> u64 {
        if self.tx_active {
            self.tx_undo_seq
        } else {
            self.tx_seq
        }
    }

    /// Exact size in bytes of the image [`SqlDb::save_partition`] would
    /// produce for the committed state (the pre-transaction rows while a
    /// transaction is open).
    pub fn committed_partition_bytes(&self) -> usize {
        let mut pos = 52usize;
        let t_len = self.table_slots_len().max(SQL_MAX_TABLES);
        let mut t = 0usize;
        while t < t_len {
            let tbl = self.table_at(t);
            if !tbl.used {
                pos += 1;
                t += 1;
                continue;
            }
            let col_count = (tbl.col_count as usize).min(SQL_MAX_COLS);
            let has_idx = tbl.index_name_len > 0 && (tbl.indexed_col as usize) < col_count;
            pos += 4 + SQL_IDENT_LEN + col_count * (2 + SQL_IDENT_LEN);
            if has_idx {
                pos += 2 + (tbl.index_name_len as usize).min(SQL_IDENT_LEN);
            }
            let r_len = tbl.row_slots_len();
            let mut r = 0usize;
            while r < r_len {
                let row = self.committed_row(t, r);
                if row.used {
                    if row.meta96 != [0u8; 12] {
                        pos += 13;
                    }
                    let mut c = 0usize;
                    while c < col_count {
                        pos += match row.cells[c] {
                            SqlVal::Int(v) => {
                                if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                                    3
                                } else {
                                    9
                                }
                            }
                            SqlVal::Text(_, len) => 2 + (len as usize).min(SQL_TEXT_LEN),
                        };
                        c += 1;
                    }
                }
                r += 1;
            }
            t += 1;
        }
        pos
    }

    /// Return `true` when `self.paged_mode` is active and committed SQL state exceeds
    /// inline `CTTLSQL1` limits (`> 4` tables, row slots `>= 64`, or `> total_bytes - 8`),
    /// requiring an HMAC-authenticated `SQL_PART_FLAG_PAGED` stub in `AB_FORMAT_V3`.
    pub fn needs_paged_partition_stub_for(&self, total_bytes: usize) -> bool {
        if !self.paged_mode {
            return false;
        }
        let t_len = self.table_slots_len();
        let mut t = SQL_MAX_TABLES;
        while t < t_len {
            if self.table_at(t).used {
                return true;
            }
            t += 1;
        }
        let mut t0 = 0usize;
        while t0 < SQL_MAX_TABLES {
            let tbl = self.table_at(t0);
            if tbl.used {
                let r_len = tbl.row_slots_len();
                let mut r = SQL_MAX_ROWS;
                while r < r_len {
                    if self.committed_row(t0, r).used {
                        return true;
                    }
                    r += 1;
                }
            }
            t0 += 1;
        }
        self.committed_partition_bytes() > total_bytes.saturating_sub(8)
    }

    /// `true` if the SQL catalog or any table's schema or 32-row leaf page is dirty.
    pub fn has_dirty_pages(&self) -> bool {
        if self.catalog_dirty {
            return true;
        }
        let t_len = self.table_slots_len();
        let mut t = 0usize;
        while t < t_len {
            let tbl = self.table_at(t);
            if tbl.schema_dirty || tbl.dirty_page_mask != 0 {
                return true;
            }
            t += 1;
        }
        false
    }

    /// Re-mark all SQL schemas and 32-row leaf pages dirty so a subsequent
    /// [`Self::sync_to_paged_store`] re-stages or reclaims every slot after a device I/O fault.
    pub fn mark_all_paged_dirty(&mut self) {
        self.catalog_dirty = true;
        let mut t = 0usize;
        while t < SQL_PAGED_MAX_TABLES {
            let tbl = self.table_mut(t);
            tbl.schema_dirty = true;
            tbl.dirty_page_mask = u64::MAX;
            t += 1;
        }
    }

    /// As [`SqlDb::save_partition`], but reports failure instead of producing
    /// an unusable image.
    ///
    /// Every table and every committed row is written, or nothing is: a
    /// database that does not fit is refused with
    /// [`SqlSaveError::TooLarge`] rather than saved without its last rows.
    /// The statement-level capacity checks keep a database from growing past
    /// the partition, so `TooLarge` signals a missed check, and the caller
    /// must treat it as a failed save.
    pub fn try_save_partition(
        &self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &mut [[u8; 512]; SQL_PART_SECTORS],
    ) -> Result<(), SqlSaveError> {
        self.try_save_partition_slices(key, &mut sectors[..])
    }

    fn try_save_partition_slices(
        &self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &mut [[u8; 512]],
    ) -> Result<(), SqlSaveError> {
        let mut s = 0usize;
        while s < sectors.len() {
            sectors[s] = [0u8; 512];
            s += 1;
        }
        if !is_seal_key_set(key) {
            return Err(SqlSaveError::KeyUnset);
        }
        let total_bytes = sectors
            .len()
            .checked_mul(512)
            .ok_or(SqlSaveError::TooLarge)?;
        if total_bytes < 512 {
            return Err(SqlSaveError::TooLarge);
        }

        if self.needs_paged_partition_stub_for(total_bytes) {
            sec_write_slice(sectors, 0, SQL_PART_MAGIC);
            let committed_seq = self.committed_seq();
            sec_write_slice(sectors, 8, &committed_seq.to_le_bytes());
            sec_write_slice(sectors, 16, &4u16.to_le_bytes());
            sec_set(sectors, 18, SQL_PART_FLAG_PAGED);
            // Four empty inline table markers `[0, 0, 0, 0]` at `[52..56]`.
            let mut tag = [0u8; DURABLE_DIGEST_LEN];
            sql_part_hmac(key, sectors, &mut tag);
            sectors[0][20..52].copy_from_slice(&tag);
            return Ok(());
        }

        if self.committed_partition_bytes() > total_bytes {
            return Err(SqlSaveError::TooLarge);
        }
        sec_write_slice(sectors, 0, SQL_PART_MAGIC);
        let committed_seq = self.committed_seq();
        sec_write_slice(sectors, 8, &committed_seq.to_le_bytes());

        // Header layout:
        //   0..8   : SQL_PART_MAGIC ("CTTLSQL1")
        //   8..16  : tx_seq (u64 LE)
        //   16..18 : payload_len (u16 LE)
        //   18..20 : flags/reserved (`sectors[0][18] == SQL_PART_FLAG_PAGED` when paged stub)
        //   20..52 : 32-byte keyed HMAC-SHA256 tag over [0..20] || [52..total_bytes]
        let mut pos = 52usize;
        let mut t = 0usize;
        while t < SQL_MAX_TABLES {
            let tbl = &self.tables[t];
            if !tbl.used {
                sec_set(sectors, pos, 0);
                pos += 1;
                t += 1;
                continue;
            }
            let col_count = (tbl.col_count as usize).min(SQL_MAX_COLS);
            let has_idx = tbl.index_name_len > 0 && (tbl.indexed_col as usize) < col_count;
            let used_rows_hdr_pos = pos + 3;
            sec_set(sectors, pos, if has_idx { 2 } else { 1 });
            sec_set(sectors, pos + 1, tbl.name_len.min(SQL_IDENT_LEN as u8));
            sec_set(sectors, pos + 2, col_count as u8);
            sec_set(sectors, pos + 3, 0);
            pos += 4;
            sec_write_slice(sectors, pos, &tbl.name);
            pos += SQL_IDENT_LEN;

            let mut c = 0usize;
            while c < col_count {
                sec_set(sectors, pos, tbl.cols[c].name_len.min(SQL_IDENT_LEN as u8));
                sec_set(sectors, pos + 1, tbl.cols[c].col_type as u8);
                pos += 2;
                sec_write_slice(sectors, pos, &tbl.cols[c].name);
                pos += SQL_IDENT_LEN;
                c += 1;
            }

            if has_idx {
                let ilen = (tbl.index_name_len as usize).min(SQL_IDENT_LEN);
                sec_set(sectors, pos, tbl.indexed_col);
                sec_set(sectors, pos + 1, ilen as u8);
                sec_write_slice(sectors, pos + 2, &tbl.index_name[..ilen]);
                pos += 2 + ilen;
            }

            let mut written_rows = 0u8;
            let mut r2 = 0usize;
            while r2 < SQL_MAX_ROWS {
                let row = self.committed_row(t, r2);
                if row.used {
                    let has_meta = row.meta96 != [0u8; 12];
                    let mut row_bytes = if has_meta { 13usize } else { 0usize };
                    let mut rc0 = 0usize;
                    while rc0 < col_count {
                        row_bytes += match row.cells[rc0] {
                            SqlVal::Int(v) => {
                                if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                                    3
                                } else {
                                    9
                                }
                            }
                            SqlVal::Text(_, len) => 2 + (len as usize).min(SQL_TEXT_LEN),
                        };
                        rc0 += 1;
                    }
                    if pos + row_bytes > total_bytes {
                        let mut z = 0usize;
                        while z < sectors.len() {
                            sectors[z] = [0u8; 512];
                            z += 1;
                        }
                        return Err(SqlSaveError::TooLarge);
                    }
                    if has_meta {
                        sec_set(sectors, pos, 4);
                        sec_write_slice(sectors, pos + 1, &row.meta96);
                        pos += 13;
                    }
                    let mut rc = 0usize;
                    while rc < col_count {
                        match row.cells[rc] {
                            SqlVal::Int(v) => {
                                if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                                    sec_set(sectors, pos, 3);
                                    sec_write_slice(sectors, pos + 1, &(v as i16).to_le_bytes());
                                    pos += 3;
                                } else {
                                    sec_set(sectors, pos, SqlType::Int as u8);
                                    sec_write_slice(sectors, pos + 1, &v.to_le_bytes());
                                    pos += 9;
                                }
                            }
                            SqlVal::Text(buf, len) => {
                                let l = (len as usize).min(SQL_TEXT_LEN);
                                sec_set(sectors, pos, SqlType::Text as u8);
                                sec_set(sectors, pos + 1, l as u8);
                                sec_write_slice(sectors, pos + 2, &buf[..l]);
                                pos += 2 + l;
                            }
                        }
                        rc += 1;
                    }
                    written_rows = written_rows.saturating_add(1);
                }
                r2 += 1;
            }
            sec_set(sectors, used_rows_hdr_pos, written_rows);
            t += 1;
        }

        let payload_len = pos - 52;
        sec_write_slice(sectors, 16, &(payload_len as u16).to_le_bytes());

        let mut tag = [0u8; DURABLE_DIGEST_LEN];
        sql_part_hmac(key, sectors, &mut tag);
        sectors[0][20..52].copy_from_slice(&tag);
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn try_save_partition_v1(
        &self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &mut [[u8; 512]; SQL_PART_SECTORS_V1],
    ) -> Result<(), SqlSaveError> {
        self.try_save_partition_slices(key, &mut sectors[..])
    }

    /// Restore the database from a 16-sector (`8 KiB`) partition image after verifying
    /// the `CTTLSQL1` (or legacy `PRTSSQL1`) magic and constant-time keyed `HMAC-SHA256` tag.
    pub fn load_partition(
        &mut self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &[[u8; 512]; SQL_PART_SECTORS],
    ) -> bool {
        self.load_partition_with_legacy(key, &[0u8; DURABLE_DIGEST_LEN], sectors)
    }

    /// Restore the database from a 16-sector (`8 KiB`) partition image, verifying
    /// `CTTLSQL1` with `key` or legacy `PRTSSQL1` with device-derived `key` / `legacy_key`.
    pub fn load_partition_with_legacy(
        &mut self,
        key: &[u8; DURABLE_DIGEST_LEN],
        legacy_key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &[[u8; 512]; SQL_PART_SECTORS],
    ) -> bool {
        self.load_partition_slices(key, legacy_key, &sectors[..])
    }

    /// Restore the database from a pre-upgrade 8-sector (`4 KiB`) v1 partition image.
    pub fn load_partition_v1(
        &mut self,
        key: &[u8; DURABLE_DIGEST_LEN],
        legacy_key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &[[u8; 512]; SQL_PART_SECTORS_V1],
    ) -> bool {
        self.load_partition_slices(key, legacy_key, &sectors[..])
    }

    /// Verify the magic, HMAC-SHA256 seal, and complete table/row framing of a
    /// `CTTLSQL1` (or legacy `PRTSSQL1`) partition slice without mutating any [`SqlDb`].
    pub fn validate_partition_slices(
        key: &[u8; DURABLE_DIGEST_LEN],
        legacy_key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &[[u8; 512]],
    ) -> bool {
        if sectors.is_empty() {
            return false;
        }
        let Some(total_bytes) = sectors.len().checked_mul(512) else {
            return false;
        };
        let is_legacy = &sectors[0][0..8] == b"PRTSSQL1";
        if &sectors[0][0..8] != SQL_PART_MAGIC && !is_legacy {
            return false;
        }
        if !is_legacy && sectors[0][18] != 0 && sectors[0][18] != SQL_PART_FLAG_PAGED {
            return false;
        }
        let payload_len = u16::from_le_bytes([sectors[0][16], sectors[0][17]]) as usize;
        if 52 + payload_len > total_bytes {
            return false;
        }
        let total_pos = 52 + payload_len;

        let mut tag_in = [0u8; DURABLE_DIGEST_LEN];
        tag_in.copy_from_slice(&sectors[0][20..52]);
        let tag_ok = if is_legacy {
            (is_seal_key_set(key) && sql_part_hmac_matches(key, sectors, &tag_in))
                || (is_seal_key_set(legacy_key)
                    && sql_part_hmac_matches(legacy_key, sectors, &tag_in))
        } else {
            is_seal_key_set(key) && sql_part_hmac_matches(key, sectors, &tag_in)
        };
        if !tag_ok {
            return false;
        }

        // Validate the entire serialized payload structure without allocating
        // multi-kilobyte `SqlTable` or partition temporaries on the bare-metal kernel stack.
        let mut scan = 52usize;
        let mut st = 0usize;
        while st < SQL_MAX_TABLES {
            if scan >= total_pos {
                return false;
            }
            let marker = sec_get(sectors, scan);
            if marker == 0 {
                scan += 1;
                st += 1;
                continue;
            }
            if scan + 4 + SQL_IDENT_LEN > total_pos {
                return false;
            }
            let col_count = (sec_get(sectors, scan + 2).min(SQL_MAX_COLS as u8)) as usize;
            let used_rows = (sec_get(sectors, scan + 3) as usize).min(SQL_MAX_ROWS);
            scan += 4 + SQL_IDENT_LEN;

            if scan + col_count * (2 + SQL_IDENT_LEN) > total_pos {
                return false;
            }
            scan += col_count * (2 + SQL_IDENT_LEN);

            if marker == 2 {
                if scan + 2 > total_pos {
                    return false;
                }
                let idx_col = sec_get(sectors, scan);
                let ilen = (sec_get(sectors, scan + 1) as usize).min(SQL_IDENT_LEN);
                if scan + 2 + ilen > total_pos || (idx_col as usize) >= col_count {
                    return false;
                }
                scan += 2 + ilen;
            }

            let mut sr = 0usize;
            while sr < used_rows {
                if scan < total_pos && sec_get(sectors, scan) == 4 {
                    if scan + 13 > total_pos {
                        return false;
                    }
                    scan += 13;
                }
                let mut sc = 0usize;
                while sc < col_count {
                    if scan >= total_pos {
                        return false;
                    }
                    let tag_b = sec_get(sectors, scan);
                    if tag_b == SqlType::Text as u8 {
                        if scan + 2 > total_pos {
                            return false;
                        }
                        let len = (sec_get(sectors, scan + 1) as usize).min(SQL_TEXT_LEN);
                        if scan + 2 + len > total_pos {
                            return false;
                        }
                        scan += 2 + len;
                    } else if tag_b == 3 {
                        if scan + 3 > total_pos {
                            return false;
                        }
                        scan += 3;
                    } else if tag_b == SqlType::Int as u8 {
                        if scan + 9 > total_pos {
                            return false;
                        }
                        scan += 9;
                    } else {
                        return false;
                    }
                    sc += 1;
                }
                sr += 1;
            }
            st += 1;
        }
        scan == total_pos
    }

    fn load_partition_slices(
        &mut self,
        key: &[u8; DURABLE_DIGEST_LEN],
        legacy_key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &[[u8; 512]],
    ) -> bool {
        if !Self::validate_partition_slices(key, legacy_key, sectors) {
            return false;
        }
        let is_legacy = &sectors[0][0..8] == b"PRTSSQL1";
        if !is_legacy && sectors[0][18] == SQL_PART_FLAG_PAGED && !self.paged_mode {
            return false;
        }
        let payload_len = u16::from_le_bytes([sectors[0][16], sectors[0][17]]) as usize;
        let total_pos = 52 + payload_len;

        self.overflow_tables.clear();

        // Payload is verified valid; decode directly into `self.tables` in-place.
        let mut pos = 52usize;
        let mut t = 0usize;
        while t < SQL_MAX_TABLES {
            self.tables[t].reset_in_place();
            let marker = sec_get(sectors, pos);
            if marker == 0 {
                pos += 1;
                t += 1;
                continue;
            }
            let tbl = &mut self.tables[t];
            tbl.used = true;
            tbl.name_len = sec_get(sectors, pos + 1).min(SQL_IDENT_LEN as u8);
            tbl.col_count = sec_get(sectors, pos + 2).min(SQL_MAX_COLS as u8);
            let used_rows = (sec_get(sectors, pos + 3) as usize).min(SQL_MAX_ROWS);
            pos += 4;
            sec_copy_out(sectors, pos, &mut tbl.name);
            pos += SQL_IDENT_LEN;

            let col_count = tbl.col_count as usize;
            let mut c = 0usize;
            while c < col_count {
                tbl.cols[c].name_len = sec_get(sectors, pos).min(SQL_IDENT_LEN as u8);
                tbl.cols[c].col_type = if sec_get(sectors, pos + 1) == SqlType::Text as u8 {
                    SqlType::Text
                } else {
                    SqlType::Int
                };
                pos += 2;
                sec_copy_out(sectors, pos, &mut tbl.cols[c].name);
                pos += SQL_IDENT_LEN;
                c += 1;
            }

            if marker == 2 {
                let idx_col = sec_get(sectors, pos);
                let ilen = (sec_get(sectors, pos + 1) as usize).min(SQL_IDENT_LEN);
                tbl.indexed_col = idx_col;
                tbl.index_name_len = ilen as u8;
                sec_copy_out(sectors, pos + 2, &mut tbl.index_name[..ilen]);
                pos += 2 + ilen;
            }

            let mut r = 0usize;
            while r < used_rows {
                tbl.rows[r].used = true;
                if pos < total_pos && sec_get(sectors, pos) == 4 {
                    sec_copy_out(sectors, pos + 1, &mut tbl.rows[r].meta96);
                    pos += 13;
                } else {
                    tbl.rows[r].meta96 = [0u8; 12];
                }
                let mut rc = 0usize;
                while rc < col_count {
                    let tag_b = sec_get(sectors, pos);
                    if tag_b == SqlType::Text as u8 {
                        let len = (sec_get(sectors, pos + 1) as usize).min(SQL_TEXT_LEN);
                        let mut buf = [0u8; SQL_TEXT_LEN];
                        sec_copy_out(sectors, pos + 2, &mut buf[..len]);
                        tbl.rows[r].cells[rc] = SqlVal::Text(buf, len as u8);
                        pos += 2 + len;
                    } else if tag_b == 3 {
                        let v16 =
                            i16::from_le_bytes([sec_get(sectors, pos + 1), sec_get(sectors, pos + 2)]);
                        tbl.rows[r].cells[rc] = SqlVal::Int(v16 as i64);
                        pos += 3;
                    } else {
                        let mut vb = [0u8; 8];
                        sec_copy_out(sectors, pos + 1, &mut vb);
                        tbl.rows[r].cells[rc] = SqlVal::Int(i64::from_le_bytes(vb));
                        pos += 9;
                    }
                    rc += 1;
                }
                r += 1;
            }
            tbl.rebuild_index();
            if self.paged_mode {
                tbl.mark_occupied_pages_dirty();
            }
            t += 1;
        }

        let mut tx_bytes = [0u8; 8];
        tx_bytes.copy_from_slice(&sectors[0][8..16]);
        self.tx_seq = u64::from_le_bytes(tx_bytes);
        self.catalog_dirty = self.paged_mode;
        self.tx_active = false;
        self.tx_owner = 0;
        self.tx_age_ticks = 0;
        self.tx_undo_len = 0;
        self.tx_aborted = false;
        self.tx_aborted_owner = 0;
        self.tx_aborted_set = [0u64; SQL_MAX_ABORTED_OWNERS];
        self.tx_aborted_count = 0;
        true
    }

    /// Read the 96-bit AEAD nonce metadata attached to row `key` in `kv` under
    /// Read Committed visibility for `owner`.
    pub fn kv_row_meta96(&self, owner: u64, key: &[u8]) -> Option<[u8; 12]> {
        let t_idx = self.find_table(b"kv")?;
        if self.table_at(t_idx).col_count == 0 {
            return None;
        }
        let target = SqlVal::try_from_text(key)?;
        let use_committed = self.tx_active && self.tx_owner != owner;
        let r_len = self.table_at(t_idx).row_slots_len();
        let mut r = 0usize;
        while r < r_len {
            let row = self.visible_row(t_idx, r, use_committed);
            if row.used && row.cells[0].compare(CmpOp::Eq, &target) {
                return Some(row.meta96);
            }
            r += 1;
        }
        None
    }

    /// Attach 96-bit AEAD nonce metadata to row `key` in `kv` on behalf of `owner`,
    /// enforcing transaction ownership, undo logging, and (in inline mode) the 8 KiB `CTTLSQL1` budget.
    pub fn set_kv_row_meta96(&mut self, owner: u64, key: &[u8], meta96: [u8; 12]) -> bool {
        if self.tx_active && self.tx_owner != owner {
            return false;
        }
        if self.is_owner_aborted(owner) {
            return false;
        }
        let Some(t_idx) = self.find_table(b"kv") else {
            return false;
        };
        if self.table_at(t_idx).col_count == 0 {
            return false;
        }
        let Some(target) = SqlVal::try_from_text(key) else {
            return false;
        };
        let r_len = self.table_at(t_idx).row_slots_len();
        let mut r = 0usize;
        while r < r_len {
            if self.table_at(t_idx).row_at(r).used
                && self.table_at(t_idx).row_at(r).cells[0].compare(CmpOp::Eq, &target)
            {
                if !self.can_record_row_undo(t_idx, r) {
                    return false;
                }
                let prev_meta = self.table_at(t_idx).row_at(r).meta96;
                let extra = if prev_meta == [0u8; 12] && meta96 != [0u8; 12] {
                    13usize
                } else {
                    0usize
                };
                if !self.paged_mode
                    && extra > 0
                    && self.serialized_partition_bytes().saturating_add(extra)
                        > SQL_PART_SECTORS * 512 - 8
                {
                    return false;
                }
                self.record_row_undo(t_idx, r);
                let tbl = self.table_mut(t_idx);
                tbl.row_mut(r).meta96 = meta96;
                tbl.mark_row_dirty(r);
                self.catalog_dirty = true;
                return true;
            }
            r += 1;
        }
        false
    }

    /// Incrementally stage dirty `SqlCatalog` (`owner_id = 0`) and 32-row `SqlLeaf`
    /// (`owner_id = (table_idx << 16) | chunk_idx`) pages into `store`.
    ///
    /// Returns the total number of committed rows across all active tables.
    pub fn sync_to_paged_store(
        &mut self,
        store: &mut PagedBlockStore,
        max_logical: usize,
    ) -> Result<u32, PagedStoreError> {
        store.configure_max_logical(max_logical);
        let mut total_rows = 0u32;
        let mut leaf_masks = [0u64; SQL_PAGED_MAX_TABLES];
        let mut leaf_buf: Vec<u8> = Vec::with_capacity(3800);

        // Pass 1: reclaim logical IDs from dropped tables or newly-empty 32-row chunks across
        // all tables BEFORE allocating any new `SqlLeaf` logical IDs, so a transaction or batch
        // that deletes from one table and inserts into another at exact `max_logical` capacity
        // never transiently exceeds `max_logical`.
        let mut ft = 0usize;
        while ft < SQL_PAGED_MAX_TABLES {
            if !self.table_at(ft).used {
                if self.table_at(ft).schema_dirty {
                    let mut chunk = 0usize;
                    while chunk < SQL_LEAF_PAGES_PER_TABLE {
                        let owner_id = ((ft as u32) << 16) | (chunk as u32);
                        if let Some(lid) = store.find_page(PageDomain::SqlLeaf, owner_id) {
                            store.free_page(lid)?;
                        }
                        chunk += 1;
                    }
                }
            } else {
                let r_len = self.table_at(ft).row_slots_len();
                let dirty_mask = self.table_at(ft).dirty_page_mask;
                let schema_dirty = self.table_at(ft).schema_dirty;
                let mut chunk = 0usize;
                while chunk < SQL_LEAF_PAGES_PER_TABLE {
                    if (dirty_mask & (1u64 << chunk)) != 0 || schema_dirty {
                        let base_r = chunk * SQL_ROWS_PER_LEAF_PAGE;
                        let mut any_used = false;
                        if base_r < r_len {
                            let max_k = SQL_ROWS_PER_LEAF_PAGE.min(r_len - base_r);
                            let mut k = 0usize;
                            while k < max_k {
                                if self.committed_row(ft, base_r + k).used {
                                    any_used = true;
                                    break;
                                }
                                k += 1;
                            }
                        }
                        if !any_used {
                            let owner_id = ((ft as u32) << 16) | (chunk as u32);
                            if let Some(lid) = store.find_page(PageDomain::SqlLeaf, owner_id) {
                                store.free_page(lid)?;
                            }
                        }
                    }
                    chunk += 1;
                }
            }
            ft += 1;
        }

        let mut t = 0usize;
        while t < SQL_PAGED_MAX_TABLES {
            let tbl_used = self.table_at(t).used;
            if !tbl_used {
                if self.table_at(t).schema_dirty {
                    let mut chunk = 0usize;
                    while chunk < SQL_LEAF_PAGES_PER_TABLE {
                        let owner_id = ((t as u32) << 16) | (chunk as u32);
                        if let Some(lid) = store.find_page(PageDomain::SqlLeaf, owner_id) {
                            store.free_page(lid)?;
                        }
                        chunk += 1;
                    }
                }
                t += 1;
                continue;
            }

            let col_count = (self.table_at(t).col_count as usize).min(SQL_MAX_COLS);
            let r_len = self.table_at(t).row_slots_len();
            let dirty_mask = self.table_at(t).dirty_page_mask;
            let schema_dirty = self.table_at(t).schema_dirty;

            let mut mask = 0u64;
            let mut chunk = 0usize;
            while chunk < SQL_LEAF_PAGES_PER_TABLE {
                let base_r = chunk * SQL_ROWS_PER_LEAF_PAGE;
                let mut slot_bitmap = 0u32;
                let mut row_in_leaf = 0u8;
                if base_r < r_len {
                    let max_k = SQL_ROWS_PER_LEAF_PAGE.min(r_len - base_r);
                    let mut k = 0usize;
                    while k < max_k {
                        if self.committed_row(t, base_r + k).used {
                            slot_bitmap |= 1u32 << k;
                            row_in_leaf += 1;
                            total_rows = total_rows.saturating_add(1);
                        }
                        k += 1;
                    }
                }

                let owner_id = ((t as u32) << 16) | (chunk as u32);
                if slot_bitmap == 0 {
                    if (dirty_mask & (1u64 << chunk)) != 0 || schema_dirty {
                        if let Some(lid) = store.find_page(PageDomain::SqlLeaf, owner_id) {
                            store.free_page(lid)?;
                        }
                    }
                } else {
                    mask |= 1u64 << chunk;
                    let existing_lid = store.find_page(PageDomain::SqlLeaf, owner_id);
                    if (dirty_mask & (1u64 << chunk)) != 0 || schema_dirty || existing_lid.is_none()
                    {
                        let lid = match existing_lid {
                            Some(id) => id,
                            None => store
                                .alloc_logical_id(max_logical)
                                .ok_or(PagedStoreError::OutOfPages)?,
                        };
                        leaf_buf.clear();
                        leaf_buf.extend_from_slice(b"SQLLF001");
                        leaf_buf.push(t as u8);
                        leaf_buf.push(chunk as u8);
                        leaf_buf.push(col_count as u8);
                        leaf_buf.push(row_in_leaf);
                        leaf_buf.extend_from_slice(&slot_bitmap.to_le_bytes());

                        let mut k = 0usize;
                        while k < SQL_ROWS_PER_LEAF_PAGE {
                            if (slot_bitmap & (1u32 << k)) != 0 {
                                let row = self.committed_row(t, base_r + k);
                                let has_meta = row.meta96 != [0u8; 12];
                                leaf_buf.push(if has_meta { 1u8 } else { 0u8 });
                                if has_meta {
                                    leaf_buf.extend_from_slice(&row.meta96);
                                }
                                let mut c = 0usize;
                                while c < col_count {
                                    match row.cells[c] {
                                        SqlVal::Int(v) => {
                                            if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                                                leaf_buf.push(3);
                                                leaf_buf.extend_from_slice(&(v as i16).to_le_bytes());
                                            } else {
                                                leaf_buf.push(SqlType::Int as u8);
                                                leaf_buf.extend_from_slice(&v.to_le_bytes());
                                            }
                                        }
                                        SqlVal::Text(buf, len) => {
                                            let l = (len as usize).min(SQL_TEXT_LEN);
                                            leaf_buf.push(SqlType::Text as u8);
                                            leaf_buf.push(l as u8);
                                            leaf_buf.extend_from_slice(&buf[..l]);
                                        }
                                    }
                                    c += 1;
                                }
                            }
                            k += 1;
                        }
                        if leaf_buf.len() > PAGED_PAGE_PAYLOAD_BYTES {
                            return Err(PagedStoreError::PayloadTooLarge);
                        }
                        store.put_page(lid, PageDomain::SqlLeaf, 0, owner_id, &leaf_buf)?;
                    }
                }
                chunk += 1;
            }
            leaf_masks[t] = mask;
            t += 1;
        }

        let existing_cat = store.find_page(PageDomain::SqlCatalog, 0);
        if self.catalog_dirty || existing_cat.is_none() {
            let cat_lid = match existing_cat {
                Some(id) => id,
                None => store
                    .alloc_logical_id(max_logical)
                    .ok_or(PagedStoreError::OutOfPages)?,
            };
            let mut cat_buf: Vec<u8> = Vec::with_capacity(1024);
            cat_buf.extend_from_slice(b"SQLCAT01");
            cat_buf.extend_from_slice(&self.committed_seq().to_le_bytes());
            cat_buf.push(SQL_PAGED_MAX_TABLES as u8);
            cat_buf.extend_from_slice(&[0u8; 3]);

            let mut ct = 0usize;
            while ct < SQL_PAGED_MAX_TABLES {
                let tbl = self.table_at(ct);
                if !tbl.used {
                    cat_buf.push(0);
                } else {
                    let col_count = (tbl.col_count as usize).min(SQL_MAX_COLS);
                    let has_idx = tbl.index_name_len > 0 && (tbl.indexed_col as usize) < col_count;
                    cat_buf.push(if has_idx { 2 } else { 1 });
                    cat_buf.push(tbl.name_len.min(SQL_IDENT_LEN as u8));
                    cat_buf.push(col_count as u8);
                    cat_buf.extend_from_slice(&leaf_masks[ct].to_le_bytes());
                    cat_buf.extend_from_slice(&tbl.name);
                    let mut c = 0usize;
                    while c < col_count {
                        cat_buf.push(tbl.cols[c].name_len.min(SQL_IDENT_LEN as u8));
                        cat_buf.push(tbl.cols[c].col_type as u8);
                        cat_buf.extend_from_slice(&tbl.cols[c].name);
                        c += 1;
                    }
                    if has_idx {
                        let ilen = (tbl.index_name_len as usize).min(SQL_IDENT_LEN);
                        cat_buf.push(tbl.indexed_col);
                        cat_buf.push(ilen as u8);
                        cat_buf.extend_from_slice(&tbl.index_name[..ilen]);
                    }
                }
                ct += 1;
            }
            store.put_page(cat_lid, PageDomain::SqlCatalog, 0, 0, &cat_buf)?;
        }

        if !self.tx_active {
            let t_len = self.table_slots_len();
            let mut cl = 0usize;
            while cl < t_len {
                let tbl = self.table_mut(cl);
                tbl.dirty_page_mask = 0;
                tbl.schema_dirty = false;
                cl += 1;
            }
            self.catalog_dirty = false;
        }
        Ok(total_rows)
    }

    /// Reconstruct all `0..8` tables, up to `2,048` rows/table, and secondary hash + B+Tree
    /// indexes from a verified [`PagedBlockStore`], failing closed on any framing mismatch.
    pub fn load_from_paged_store(
        &mut self,
        store: &PagedBlockStore,
    ) -> Result<u32, PagedStoreError> {
        let Some(cat_lid) = store.find_page(PageDomain::SqlCatalog, 0) else {
            return Err(PagedStoreError::CorruptOrTampered);
        };
        let Some((_, _, _, cat)) = store.get_page(cat_lid) else {
            return Err(PagedStoreError::CorruptOrTampered);
        };
        if cat.len() < 20 || &cat[0..8] != b"SQLCAT01" {
            return Err(PagedStoreError::CorruptOrTampered);
        }
        let mut seq_b = [0u8; 8];
        seq_b.copy_from_slice(&cat[8..16]);
        let committed_seq = u64::from_le_bytes(seq_b);
        let tbl_slots = cat[16] as usize;
        if tbl_slots == 0 || tbl_slots > SQL_PAGED_MAX_TABLES {
            return Err(PagedStoreError::CorruptOrTampered);
        }

        let mut next_db = SqlDb::empty();
        next_db.paged_mode = true;
        next_db.paged_page_budget = self.paged_page_budget;
        next_db.tx_seq = committed_seq;

        let mut pos = 20usize;
        let mut expected_leaves: Vec<u32> = Vec::new();
        let mut loaded_rows = 0u32;

        let mut t = 0usize;
        while t < tbl_slots {
            if pos >= cat.len() {
                return Err(PagedStoreError::CorruptOrTampered);
            }
            let marker = cat[pos];
            pos += 1;
            if marker == 0 {
                t += 1;
                continue;
            }
            if (marker != 1 && marker != 2) || pos + 2 + 8 + SQL_IDENT_LEN > cat.len() {
                return Err(PagedStoreError::CorruptOrTampered);
            }
            let name_len = cat[pos];
            let col_count = cat[pos + 1] as usize;
            if name_len == 0
                || (name_len as usize) > SQL_IDENT_LEN
                || col_count == 0
                || col_count > SQL_MAX_COLS
            {
                return Err(PagedStoreError::CorruptOrTampered);
            }
            let mut mask_b = [0u8; 8];
            mask_b.copy_from_slice(&cat[pos + 2..pos + 10]);
            let leaf_mask = u64::from_le_bytes(mask_b);
            pos += 10;

            let mut tname = [0u8; SQL_IDENT_LEN];
            tname.copy_from_slice(&cat[pos..pos + SQL_IDENT_LEN]);
            pos += SQL_IDENT_LEN;

            if pos + col_count * (2 + SQL_IDENT_LEN) > cat.len() {
                return Err(PagedStoreError::CorruptOrTampered);
            }
            let mut cols = [SqlColumn::empty(); SQL_MAX_COLS];
            let mut c = 0usize;
            while c < col_count {
                let cname_len = cat[pos];
                let ctype_b = cat[pos + 1];
                if cname_len == 0 || (cname_len as usize) > SQL_IDENT_LEN {
                    return Err(PagedStoreError::CorruptOrTampered);
                }
                let ctype = if ctype_b == SqlType::Int as u8 {
                    SqlType::Int
                } else if ctype_b == SqlType::Text as u8 {
                    SqlType::Text
                } else {
                    return Err(PagedStoreError::CorruptOrTampered);
                };
                pos += 2;
                cols[c].name_len = cname_len;
                cols[c].col_type = ctype;
                cols[c].name.copy_from_slice(&cat[pos..pos + SQL_IDENT_LEN]);
                pos += SQL_IDENT_LEN;
                c += 1;
            }

            let mut indexed_col = SQL_NO_INDEX;
            let mut index_name = [0u8; SQL_IDENT_LEN];
            let mut index_name_len = 0u8;
            if marker == 2 {
                if pos + 2 > cat.len() {
                    return Err(PagedStoreError::CorruptOrTampered);
                }
                indexed_col = cat[pos];
                let ilen = cat[pos + 1] as usize;
                if (indexed_col as usize) >= col_count
                    || ilen == 0
                    || ilen > SQL_IDENT_LEN
                    || pos + 2 + ilen > cat.len()
                {
                    return Err(PagedStoreError::CorruptOrTampered);
                }
                index_name_len = ilen as u8;
                index_name[..ilen].copy_from_slice(&cat[pos + 2..pos + 2 + ilen]);
                pos += 2 + ilen;
            }

            {
                let tbl = next_db.table_mut(t);
                tbl.reset_in_place();
                tbl.used = true;
                tbl.name = tname;
                tbl.name_len = name_len;
                tbl.col_count = col_count as u8;
                tbl.cols = cols;
                tbl.indexed_col = indexed_col;
                tbl.index_name = index_name;
                tbl.index_name_len = index_name_len;
                tbl.schema_dirty = false;
            }

            let mut chunk = 0usize;
            while chunk < SQL_LEAF_PAGES_PER_TABLE {
                if (leaf_mask & (1u64 << chunk)) != 0 {
                    let owner_id = ((t as u32) << 16) | (chunk as u32);
                    expected_leaves.push(owner_id);
                    let Some(leaf_lid) = store.find_page(PageDomain::SqlLeaf, owner_id) else {
                        return Err(PagedStoreError::CorruptOrTampered);
                    };
                    let Some((_, _, _, lf)) = store.get_page(leaf_lid) else {
                        return Err(PagedStoreError::CorruptOrTampered);
                    };
                    if lf.len() < 16
                        || &lf[0..8] != b"SQLLF001"
                        || (lf[8] as usize) != t
                        || (lf[9] as usize) != chunk
                        || (lf[10] as usize) != col_count
                    {
                        return Err(PagedStoreError::CorruptOrTampered);
                    }
                    let expected_in_leaf = lf[11] as u32;
                    let slot_bitmap = u32::from_le_bytes([lf[12], lf[13], lf[14], lf[15]]);
                    if slot_bitmap == 0 || slot_bitmap.count_ones() != expected_in_leaf {
                        return Err(PagedStoreError::CorruptOrTampered);
                    }

                    let mut lpos = 16usize;
                    let base_r = chunk * SQL_ROWS_PER_LEAF_PAGE;
                    let mut k = 0usize;
                    while k < SQL_ROWS_PER_LEAF_PAGE {
                        if (slot_bitmap & (1u32 << k)) != 0 {
                            if lpos >= lf.len() {
                                return Err(PagedStoreError::CorruptOrTampered);
                            }
                            let rflags = lf[lpos];
                            lpos += 1;
                            if (rflags & !1u8) != 0 {
                                return Err(PagedStoreError::CorruptOrTampered);
                            }
                            let mut row = SqlRow::empty();
                            row.used = true;
                            if (rflags & 1) != 0 {
                                if lpos + 12 > lf.len() {
                                    return Err(PagedStoreError::CorruptOrTampered);
                                }
                                row.meta96.copy_from_slice(&lf[lpos..lpos + 12]);
                                lpos += 12;
                            }
                            let mut rc = 0usize;
                            while rc < col_count {
                                if lpos >= lf.len() {
                                    return Err(PagedStoreError::CorruptOrTampered);
                                }
                                let tag_b = lf[lpos];
                                lpos += 1;
                                if tag_b == SqlType::Text as u8 {
                                    if lpos >= lf.len() || cols[rc].col_type != SqlType::Text {
                                        return Err(PagedStoreError::CorruptOrTampered);
                                    }
                                    let tlen = lf[lpos] as usize;
                                    lpos += 1;
                                    if tlen > SQL_TEXT_LEN || lpos + tlen > lf.len() {
                                        return Err(PagedStoreError::CorruptOrTampered);
                                    }
                                    let mut tb = [0u8; SQL_TEXT_LEN];
                                    tb[..tlen].copy_from_slice(&lf[lpos..lpos + tlen]);
                                    row.cells[rc] = SqlVal::Text(tb, tlen as u8);
                                    lpos += tlen;
                                } else if tag_b == 3 {
                                    if lpos + 2 > lf.len() || cols[rc].col_type != SqlType::Int {
                                        return Err(PagedStoreError::CorruptOrTampered);
                                    }
                                    let v16 = i16::from_le_bytes([lf[lpos], lf[lpos + 1]]);
                                    row.cells[rc] = SqlVal::Int(v16 as i64);
                                    lpos += 2;
                                } else if tag_b == SqlType::Int as u8 {
                                    if lpos + 8 > lf.len() || cols[rc].col_type != SqlType::Int {
                                        return Err(PagedStoreError::CorruptOrTampered);
                                    }
                                    let mut vb = [0u8; 8];
                                    vb.copy_from_slice(&lf[lpos..lpos + 8]);
                                    row.cells[rc] = SqlVal::Int(i64::from_le_bytes(vb));
                                    lpos += 8;
                                } else {
                                    return Err(PagedStoreError::CorruptOrTampered);
                                }
                                rc += 1;
                            }
                            *next_db.table_mut(t).row_mut(base_r + k) = row;
                            loaded_rows = loaded_rows.saturating_add(1);
                        }
                        k += 1;
                    }
                    if lpos != lf.len() {
                        return Err(PagedStoreError::CorruptOrTampered);
                    }
                }
                chunk += 1;
            }
            let tbl = next_db.table_mut(t);
            tbl.rebuild_index();
            tbl.dirty_page_mask = 0;
            tbl.schema_dirty = false;
            t += 1;
        }
        if pos != cat.len() {
            return Err(PagedStoreError::CorruptOrTampered);
        }

        // Reject any unreferenced orphan `SqlLeaf` or duplicate `SqlCatalog` page in `store`.
        let mut lid = 0u16;
        while (lid as usize) < crate::paged_store::PAGED_V2_MAX_LOGICAL_PAGES {
            if let Some((dom, _, owner_id, _)) = store.get_page(lid) {
                match dom {
                    PageDomain::SqlCatalog if owner_id != 0 || lid != cat_lid => {
                        return Err(PagedStoreError::CorruptOrTampered);
                    }
                    PageDomain::SqlLeaf if !expected_leaves.contains(&owner_id) => {
                        return Err(PagedStoreError::CorruptOrTampered);
                    }
                    _ => {}
                }
            }
            lid += 1;
        }

        next_db.catalog_dirty = false;
        *self = next_db;
        Ok(loaded_rows)
    }
}

#[inline]
fn sec_get(sectors: &[[u8; 512]], pos: usize) -> u8 {
    sectors[pos / 512][pos % 512]
}

#[inline]
fn sec_set(sectors: &mut [[u8; 512]], pos: usize, val: u8) {
    sectors[pos / 512][pos % 512] = val;
}

#[inline]
fn sec_write_slice(sectors: &mut [[u8; 512]], pos: usize, src: &[u8]) {
    let mut i = 0usize;
    while i < src.len() {
        sectors[(pos + i) / 512][(pos + i) % 512] = src[i];
        i += 1;
    }
}

#[inline]
fn sec_copy_out(sectors: &[[u8; 512]], pos: usize, dst: &mut [u8]) {
    let mut i = 0usize;
    while i < dst.len() {
        dst[i] = sectors[(pos + i) / 512][(pos + i) % 512];
        i += 1;
    }
}

fn sql_part_hmac(
    key: &[u8; DURABLE_DIGEST_LEN],
    sectors: &[[u8; 512]],
    out: &mut [u8; DURABLE_DIGEST_LEN],
) {
    let Some((first, tail)) = sectors.split_first() else {
        *out = [0u8; DURABLE_DIGEST_LEN];
        return;
    };
    crate::tls::hmac_sha256_parts(
        key,
        &[&first[0..20], &first[52..512], tail.as_flattened()],
        out,
    );
}

fn sql_part_hmac_matches(
    key: &[u8; DURABLE_DIGEST_LEN],
    sectors: &[[u8; 512]],
    expected: &[u8; DURABLE_DIGEST_LEN],
) -> bool {
    let mut actual = [0u8; DURABLE_DIGEST_LEN];
    sql_part_hmac(key, sectors, &mut actual);
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < DURABLE_DIGEST_LEN {
        diff |= actual[i] ^ expected[i];
        i += 1;
    }
    zeroize_secret_bytes(&mut actual);
    diff == 0
}

// ---------------------------------------------------------------------------
// Lexer / Parser Helpers
// ---------------------------------------------------------------------------

/// Non-recursive iterative SQL `LIKE` pattern matcher supporting `%` (0+ bytes) and `_` (1 byte).
pub fn sql_like_match(text: &[u8], pat: &[u8]) -> bool {
    let mut ti = 0usize;
    let mut pi = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti: usize = 0;

    while ti < text.len() {
        if pi < pat.len() && (pat[pi] == b'_' || pat[pi] == text[ti]) {
            ti += 1;
            pi += 1;
        } else if pi < pat.len() && pat[pi] == b'%' {
            star_pi = Some(pi);
            pi += 1;
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'%' {
        pi += 1;
    }
    pi == pat.len()
}

fn parse_aggregate_proj(proj: &[u8]) -> Option<(AggKind, &[u8])> {
    let lparen = find_byte(proj, b'(')?;
    let rparen = rfind_byte(proj, b')')?;
    if rparen <= lparen + 1 || rparen + 1 != proj.len() {
        return None;
    }
    let fn_name = trim_sql(&proj[..lparen]);
    let col_name = trim_sql(&proj[lparen + 1..rparen]);
    if col_name.is_empty() {
        return None;
    }
    if eq_ignore_ascii_case(fn_name, b"SUM") {
        Some((AggKind::Sum, col_name))
    } else if eq_ignore_ascii_case(fn_name, b"MIN") {
        Some((AggKind::Min, col_name))
    } else if eq_ignore_ascii_case(fn_name, b"MAX") {
        Some((AggKind::Max, col_name))
    } else if eq_ignore_ascii_case(fn_name, b"AVG") {
        Some((AggKind::Avg, col_name))
    } else {
        None
    }
}

fn trim_sql(s: &[u8]) -> &[u8] {
    let mut a = 0usize;
    while a < s.len()
        && (s[a] == b' ' || s[a] == b'\t' || s[a] == b'\r' || s[a] == b'\n')
    {
        a += 1;
    }
    let mut b = s.len();
    while b > a
        && (s[b - 1] == b' '
            || s[b - 1] == b'\t'
            || s[b - 1] == b'\r'
            || s[b - 1] == b'\n'
            || s[b - 1] == b';')
    {
        b -= 1;
    }
    &s[a..b]
}

fn next_token(s: &[u8]) -> (&[u8], &[u8]) {
    let s = trim_sql(s);
    let mut i = 0usize;
    while i < s.len() && s[i] != b' ' && s[i] != b'\t' && s[i] != b'\r' && s[i] != b'\n' {
        i += 1;
    }
    (&s[..i], trim_sql(&s[i..]))
}

fn find_byte(s: &[u8], b: u8) -> Option<usize> {
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == b {
            return Some(i);
        }
        i += 1;
    }
    None
}

fn rfind_byte(s: &[u8], b: u8) -> Option<usize> {
    let mut i = s.len();
    while i > 0 {
        i -= 1;
        if s[i] == b {
            return Some(i);
        }
    }
    None
}

fn split_comma(s: &[u8]) -> (&[u8], &[u8]) {
    if let Some(idx) = find_byte(s, b',') {
        (&s[..idx], &s[idx + 1..])
    } else {
        (s, &[])
    }
}

fn split_comma_respecting_quotes(s: &[u8]) -> (&[u8], &[u8]) {
    let mut quote_char = 0u8;
    let mut i = 0usize;
    while i < s.len() {
        if quote_char == 0 {
            if s[i] == b'\'' || s[i] == b'"' {
                quote_char = s[i];
            } else if s[i] == b',' {
                return (&s[..i], &s[i + 1..]);
            }
        } else if s[i] == quote_char {
            if i + 1 < s.len() && s[i + 1] == quote_char {
                i += 2;
                continue;
            }
            quote_char = 0;
        }
        i += 1;
    }
    (s, &[])
}

fn cmp_ascii_case_insensitive(a: &[u8], b: &[u8]) -> i8 {
    let min_len = a.len().min(b.len());
    let mut i = 0usize;
    while i < min_len {
        let ca = a[i].to_ascii_lowercase();
        let cb = b[i].to_ascii_lowercase();
        if ca < cb {
            return -1;
        }
        if ca > cb {
            return 1;
        }
        i += 1;
    }
    if a.len() < b.len() {
        -1
    } else if a.len() > b.len() {
        1
    } else {
        0
    }
}

fn split_keyword_ignore_case<'a>(s: &'a [u8], kw: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let mut quote_char = 0u8;
    let mut i = 0usize;
    while i + kw.len() <= s.len() {
        if quote_char == 0 {
            if s[i] == b'\'' || s[i] == b'"' {
                quote_char = s[i];
                i += 1;
                continue;
            }
            let left_ok = i == 0 || matches!(s[i - 1], b' ' | b'\t' | b'\r' | b'\n');
            let right_ok = i + kw.len() == s.len()
                || matches!(s[i + kw.len()], b' ' | b'\t' | b'\r' | b'\n');
            if left_ok && right_ok && eq_ignore_ascii_case(&s[i..i + kw.len()], kw) {
                return Some((&s[..i], &s[i + kw.len()..]));
            }
        } else if s[i] == quote_char {
            if i + 1 < s.len() && s[i + 1] == quote_char {
                i += 2;
                continue;
            }
            quote_char = 0;
        }
        i += 1;
    }
    None
}

#[derive(Clone, Copy)]
enum WhereFilter {
    Single(usize, CmpOp, SqlVal),
    And((usize, CmpOp, SqlVal), (usize, CmpOp, SqlVal)),
    Or((usize, CmpOp, SqlVal), (usize, CmpOp, SqlVal)),
}

impl WhereFilter {
    fn eval(&self, row: &SqlRow) -> bool {
        match self {
            WhereFilter::Single(c, op, rhs) => row.cells[*c].compare(*op, rhs),
            WhereFilter::And((c1, op1, rhs1), (c2, op2, rhs2)) => {
                row.cells[*c1].compare(*op1, rhs1) && row.cells[*c2].compare(*op2, rhs2)
            }
            WhereFilter::Or((c1, op1, rhs1), (c2, op2, rhs2)) => {
                row.cells[*c1].compare(*op1, rhs1) || row.cells[*c2].compare(*op2, rhs2)
            }
        }
    }

    fn single_indexed_eq(&self, indexed_col: usize) -> Option<u64> {
        match self {
            WhereFilter::Single(c_idx, CmpOp::Eq, rhs) if *c_idx == indexed_col => {
                Some(hash_sql_val(rhs))
            }
            WhereFilter::And((c1, CmpOp::Eq, rhs1), _) if *c1 == indexed_col => {
                Some(hash_sql_val(rhs1))
            }
            WhereFilter::And(_, (c2, CmpOp::Eq, rhs2)) if *c2 == indexed_col => {
                Some(hash_sql_val(rhs2))
            }
            _ => None,
        }
    }

    fn indexed_int_range(&self, indexed_col: usize) -> Option<(CmpOp, i64)> {
        match self {
            WhereFilter::Single(c_idx, op, SqlVal::Int(v))
                if *c_idx == indexed_col && !matches!(op, CmpOp::Ne | CmpOp::Like) =>
            {
                Some((*op, *v))
            }
            WhereFilter::And((c1, op1, SqlVal::Int(v1)), _)
                if *c1 == indexed_col && !matches!(op1, CmpOp::Ne | CmpOp::Like) =>
            {
                Some((*op1, *v1))
            }
            WhereFilter::And(_, (c2, op2, SqlVal::Int(v2)))
                if *c2 == indexed_col && !matches!(op2, CmpOp::Ne | CmpOp::Like) =>
            {
                Some((*op2, *v2))
            }
            _ => None,
        }
    }
}

fn parse_values_tuple_slices(s: &[u8]) -> Result<Vec<&[u8]>, &'static [u8]> {
    if find_byte(s, b'(').is_none() {
        return Err(b"error: missing '(' after VALUES\n");
    }
    if rfind_byte(s, b')').is_none() {
        return Err(b"error: missing ')' after VALUES\n");
    }
    let mut out: Vec<&[u8]> = Vec::new();
    let mut pos = 0usize;
    loop {
        while pos < s.len()
            && (s[pos] == b' ' || s[pos] == b'\t' || s[pos] == b'\r' || s[pos] == b'\n')
        {
            pos += 1;
        }
        if pos >= s.len() || s[pos] != b'(' {
            return Err(b"error: malformed VALUES list\n");
        }
        let inner_start = pos + 1;
        let mut quote_char = 0u8;
        let mut inner_end: Option<usize> = None;
        let mut i = inner_start;
        while i < s.len() {
            if quote_char == 0 {
                if s[i] == b'\'' || s[i] == b'"' {
                    quote_char = s[i];
                } else if s[i] == b'(' {
                    return Err(b"error: malformed VALUES list\n");
                } else if s[i] == b')' {
                    inner_end = Some(i);
                    break;
                }
            } else if s[i] == quote_char {
                if i + 1 < s.len() && s[i + 1] == quote_char {
                    i += 2;
                    continue;
                }
                quote_char = 0;
            }
            i += 1;
        }
        let Some(end_idx) = inner_end else {
            if quote_char != 0 {
                if let Some(rp) = rfind_byte(&s[inner_start..], b')') {
                    if trim_sql(&s[inner_start + rp + 1..]).is_empty() {
                        out.push(&s[inner_start..inner_start + rp]);
                        return Ok(out);
                    }
                }
                return Err(b"error: malformed VALUES list\n");
            }
            return Err(b"error: missing ')' after VALUES\n");
        };
        out.push(&s[inner_start..end_idx]);
        pos = end_idx + 1;
        while pos < s.len()
            && (s[pos] == b' ' || s[pos] == b'\t' || s[pos] == b'\r' || s[pos] == b'\n')
        {
            pos += 1;
        }
        if pos == s.len() {
            break;
        }
        if s[pos] == b',' {
            pos += 1;
            while pos < s.len()
                && (s[pos] == b' ' || s[pos] == b'\t' || s[pos] == b'\r' || s[pos] == b'\n')
            {
                pos += 1;
            }
            if pos == s.len() {
                return Err(b"error: malformed VALUES list\n");
            }
            continue;
        }
        return Err(b"error: malformed VALUES list\n");
    }
    if out.is_empty() {
        return Err(b"error: malformed VALUES list\n");
    }
    Ok(out)
}

fn parse_where_filter(table: &SqlTable, raw: &[u8]) -> Option<WhereFilter> {
    let raw = trim_sql(raw);
    if let Some((lhs, rhs)) = split_keyword_ignore_case(raw, b"AND") {
        let p1 = parse_where_clause(table, lhs)?;
        let p2 = parse_where_clause(table, rhs)?;
        return Some(WhereFilter::And(p1, p2));
    }
    if let Some((lhs, rhs)) = split_keyword_ignore_case(raw, b"OR") {
        let p1 = parse_where_clause(table, lhs)?;
        let p2 = parse_where_clause(table, rhs)?;
        return Some(WhereFilter::Or(p1, p2));
    }
    let p = parse_where_clause(table, raw)?;
    Some(WhereFilter::Single(p.0, p.1, p.2))
}

fn parse_where_clause(table: &SqlTable, raw: &[u8]) -> Option<(usize, CmpOp, SqlVal)> {
    let raw = trim_sql(raw);
    if let Some((col_raw, pat_raw)) = split_keyword_ignore_case(raw, b"LIKE") {
        let col_name = trim_sql(col_raw);
        let c_idx = table.find_col(col_name)?;
        let val = parse_literal(trim_sql(pat_raw), SqlType::Text)?;
        return Some((c_idx, CmpOp::Like, val));
    }
    let ops: [(&[u8], CmpOp); 7] = [
        (b"!=", CmpOp::Ne),
        (b"<>", CmpOp::Ne),
        (b"<=", CmpOp::Le),
        (b">=", CmpOp::Ge),
        (b"=", CmpOp::Eq),
        (b"<", CmpOp::Lt),
        (b">", CmpOp::Gt),
    ];
    let mut quote_char = 0u8;
    let mut i = 0usize;
    while i < raw.len() {
        if quote_char == 0 {
            if raw[i] == b'\'' || raw[i] == b'"' {
                quote_char = raw[i];
                i += 1;
                continue;
            }
            let mut k = 0usize;
            while k < ops.len() {
                let (pat, op) = ops[k];
                if i + pat.len() <= raw.len() && &raw[i..i + pat.len()] == pat {
                    let col_name = trim_sql(&raw[..i]);
                    let val_raw = trim_sql(&raw[i + pat.len()..]);
                    let c_idx = table.find_col(col_name)?;
                    let val = parse_literal(val_raw, table.cols[c_idx].col_type)?;
                    return Some((c_idx, op, val));
                }
                k += 1;
            }
        } else if raw[i] == quote_char {
            if i + 1 < raw.len() && raw[i + 1] == quote_char {
                i += 2;
                continue;
            }
            quote_char = 0;
        }
        i += 1;
    }
    None
}

fn parse_hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn parse_literal(raw: &[u8], expected: SqlType) -> Option<SqlVal> {
    let raw = trim_sql(raw);
    match expected {
        SqlType::Int => parse_i64(raw).map(SqlVal::Int),
        SqlType::Text => {
            if raw.len() >= 3
                && (raw[0] == b'X' || raw[0] == b'x')
                && raw[1] == b'\''
                && raw[raw.len() - 1] == b'\''
            {
                let hex = &raw[2..raw.len() - 1];
                if hex.len() % 2 != 0 || hex.len() > SQL_TEXT_LEN * 2 {
                    return None;
                }
                let mut decoded = [0u8; SQL_TEXT_LEN];
                let mut out_len = 0usize;
                let mut i = 0usize;
                while i < hex.len() {
                    let hi = parse_hex_nibble(hex[i])?;
                    let lo = parse_hex_nibble(hex[i + 1])?;
                    if out_len >= SQL_TEXT_LEN {
                        return None;
                    }
                    decoded[out_len] = (hi << 4) | lo;
                    out_len += 1;
                    i += 2;
                }
                SqlVal::try_from_text(&decoded[..out_len])
            } else if raw.len() >= 2
                && ((raw[0] == b'\'' && raw[raw.len() - 1] == b'\'')
                    || (raw[0] == b'"' && raw[raw.len() - 1] == b'"'))
            {
                let q = raw[0];
                let inner = &raw[1..raw.len() - 1];
                let mut decoded = [0u8; SQL_TEXT_LEN];
                let mut out_len = 0usize;
                let mut i = 0usize;
                while i < inner.len() {
                    if inner[i] == q {
                        if i + 1 < inner.len() && inner[i + 1] == q {
                            if out_len >= SQL_TEXT_LEN {
                                return None;
                            }
                            decoded[out_len] = q;
                            out_len += 1;
                            i += 2;
                            continue;
                        }
                        return None;
                    }
                    if out_len >= SQL_TEXT_LEN {
                        return None;
                    }
                    decoded[out_len] = inner[i];
                    out_len += 1;
                    i += 1;
                }
                SqlVal::try_from_text(&decoded[..out_len])
            } else {
                None
            }
        }
    }
}

fn parse_i64(s: &[u8]) -> Option<i64> {
    let s = trim_sql(s);
    if s.is_empty() {
        return None;
    }
    let (neg, digits) = if s[0] == b'-' {
        (true, &s[1..])
    } else if s[0] == b'+' {
        (false, &s[1..])
    } else {
        (false, s)
    };
    if digits.is_empty() {
        return None;
    }
    let mut acc: u64 = 0;
    let max_mag: u64 = if neg {
        (i64::MAX as u64) + 1
    } else {
        i64::MAX as u64
    };
    let mut i = 0usize;
    while i < digits.len() {
        if !digits[i].is_ascii_digit() {
            return None;
        }
        acc = acc.checked_mul(10)?.checked_add((digits[i] - b'0') as u64)?;
        if acc > max_mag {
            return None;
        }
        i += 1;
    }
    if neg {
        if acc == (i64::MAX as u64) + 1 {
            Some(i64::MIN)
        } else {
            Some(-(acc as i64))
        }
    } else {
        Some(acc as i64)
    }
}

fn is_valid_ident(s: &[u8]) -> bool {
    if s.is_empty() || s.len() > SQL_IDENT_LEN {
        return false;
    }
    if !(s[0].is_ascii_alphabetic() || s[0] == b'_') {
        return false;
    }
    let mut i = 1usize;
    while i < s.len() {
        if !(s[i].is_ascii_alphanumeric() || s[i] == b'_') {
            return false;
        }
        i += 1;
    }
    true
}

fn eq_ignore_ascii_case(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut i = 0usize;
    while i < a.len() {
        let ca = if a[i].is_ascii_uppercase() { a[i] + 32 } else { a[i] };
        let cb = if b[i].is_ascii_uppercase() { b[i] + 32 } else { b[i] };
        if ca != cb {
            return false;
        }
        i += 1;
    }
    true
}

fn starts_with_ignore_case(s: &[u8], prefix: &[u8]) -> bool {
    s.len() >= prefix.len() && eq_ignore_ascii_case(&s[..prefix.len()], prefix)
}

fn cmp_bytes(a: &[u8], b: &[u8]) -> i32 {
    let min_len = a.len().min(b.len());
    let mut i = 0usize;
    while i < min_len {
        if a[i] < b[i] {
            return -1;
        }
        if a[i] > b[i] {
            return 1;
        }
        i += 1;
    }
    if a.len() < b.len() {
        -1
    } else if a.len() > b.len() {
        1
    } else {
        0
    }
}

fn copy_str(src: &[u8], dst: &mut [u8]) -> usize {
    let n = src.len().min(dst.len());
    dst[..n].copy_from_slice(&src[..n]);
    n
}

fn append_bytes(out: &mut [u8], pos: usize, src: &[u8]) -> usize {
    if pos >= out.len() {
        return 0;
    }
    let n = src.len().min(out.len() - pos);
    out[pos..pos + n].copy_from_slice(&src[..n]);
    n
}

fn append_u64(out: &mut [u8], pos: usize, mut val: u64) -> usize {
    if pos >= out.len() {
        return 0;
    }
    if val == 0 {
        out[pos] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut k = 0usize;
    while val > 0 {
        tmp[k] = b'0' + (val % 10) as u8;
        val /= 10;
        k += 1;
    }
    let n = k.min(out.len() - pos);
    let mut i = 0usize;
    while i < n {
        out[pos + i] = tmp[k - 1 - i];
        i += 1;
    }
    n
}

fn append_i64(out: &mut [u8], pos: usize, val: i64) -> usize {
    if val < 0 {
        let mut written = append_bytes(out, pos, b"-");
        written += append_u64(out, pos.saturating_add(written), val.unsigned_abs());
        written
    } else {
        append_u64(out, pos, val as u64)
    }
}

fn cmp_rows_canonical(a: &SqlRow, b: &SqlRow, col_count: usize, is_kv: bool) -> i32 {
    if is_kv
        && col_count > 0
        && matches!(&a.cells[0], SqlVal::Text(tb, tl) if *tl >= 2 && tb[0] == b'v' && tb[1] == b':')
        && matches!(&b.cells[0], SqlVal::Text(tb, tl) if *tl >= 2 && tb[0] == b'v' && tb[1] == b':')
    {
        if a.cells[0].compare(CmpOp::Lt, &b.cells[0]) {
            return -1;
        }
        if a.cells[0].compare(CmpOp::Gt, &b.cells[0]) {
            return 1;
        }
        return 0;
    }
    let mut c = 0usize;
    while c < col_count {
        if a.cells[c].compare(CmpOp::Lt, &b.cells[c]) {
            return -1;
        }
        if a.cells[c].compare(CmpOp::Gt, &b.cells[c]) {
            return 1;
        }
        c += 1;
    }
    0
}

fn append_hex_bytes(out: &mut [u8], pos: usize, src: &[u8]) -> usize {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut written = 0usize;
    let mut i = 0usize;
    while i < src.len() {
        let Some(base) = pos.checked_add(written) else {
            break;
        };
        let Some(end) = base.checked_add(2) else {
            break;
        };
        let Some(pair) = out.get_mut(base..end) else {
            break;
        };
        pair[0] = HEX[(src[i] >> 4) as usize];
        pair[1] = HEX[(src[i] & 0xF) as usize];
        written += 2;
        i += 1;
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sql_create_insert_select_where_order_limit() {
        let mut db = SqlDb::empty();
        let mut out = [0u8; 512];

        let n = db.exec(
            b"CREATE TABLE nodes (id INT, host TEXT, load INT)",
            &mut out,
        );
        assert_eq!(&out[..n], b"CREATE TABLE nodes OK\n");

        let n = db.exec(b"INSERT INTO nodes VALUES (1, 'alpha', 40)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        let n = db.exec(b"INSERT INTO nodes VALUES (2, 'bravo', 10)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        let n = db.exec(b"INSERT INTO nodes VALUES (3, 'charlie', 85)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");

        let n = db.exec(
            b"SELECT host, load FROM nodes WHERE load >= 40 ORDER BY load DESC",
            &mut out,
        );
        assert_eq!(
            &out[..n],
            b"host|load\ncharlie|85\nalpha|40\n"
        );

        let n = db.exec(b"SELECT COUNT(*) FROM nodes WHERE load > 20", &mut out);
        assert_eq!(&out[..n], b"count\n2\n");
    }

    #[test]
    fn sql_update_delete_and_schema() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 512];

        let n = db.exec(
            b"UPDATE services SET port = 8443 WHERE name = 'https-tls13'",
            &mut out,
        );
        assert_eq!(&out[..n], b"UPDATE 1\n");

        let n = db.exec(
            b"SELECT name, port FROM services WHERE id = 2",
            &mut out,
        );
        assert_eq!(&out[..n], b"name|port\nhttps-tls13|8443\n");

        let n = db.exec(b"DELETE FROM services WHERE id = 3", &mut out);
        assert_eq!(&out[..n], b"DELETE 1\n");

        let n = db.exec(b"SELECT COUNT(*) FROM services", &mut out);
        assert_eq!(&out[..n], b"count\n2\n");
    }

    #[test]
    fn sql_partition_persistence_and_tamper_rejection() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];
        let _ = db.exec(
            b"INSERT INTO kv VALUES ('app.mode', 'production', 7)",
            &mut out,
        );
        let key = [0x5Au8; 32];
        let mut sectors = [[0u8; 512]; SQL_PART_SECTORS];
        db.save_partition(&key, &mut sectors);

        let mut restored = SqlDb::empty();
        assert!(restored.load_partition(&key, &sectors));
        let n = restored.exec(
            b"SELECT v, rev FROM kv WHERE k = 'app.mode'",
            &mut out,
        );
        assert_eq!(&out[..n], b"v|rev\nproduction|7\n");

        // Wrong key or tampered byte must fail verification.
        let bad_key = [0x5Bu8; 32];
        let mut bad_db = SqlDb::empty();
        assert!(!bad_db.load_partition(&bad_key, &sectors));

        sectors[1][12] ^= 0x01;
        assert!(!bad_db.load_partition(&key, &sectors));
    }

    #[test]
    fn sql_64_rows_secondary_index_aggregates_like_and_redteam_hardening() {
        let mut db = SqlDb::empty();
        let mut out = [0u8; 512];

        let n = db.exec(
            b"CREATE TABLE telemetry (id INT, tag TEXT, val INT)",
            &mut out,
        );
        assert_eq!(&out[..n], b"CREATE TABLE telemetry OK\n");
        let n = db.exec(
            b"CREATE INDEX idx_telem_tag ON telemetry (tag)",
            &mut out,
        );
        assert_eq!(&out[..n], b"CREATE INDEX idx_telem_tag OK\n");
        let n_bad_idx = db.exec(
            b"CREATE INDEX idx_telemetry_tag_too_long ON telemetry (tag)",
            &mut out,
        );
        assert_eq!(&out[..n_bad_idx], b"error: invalid index name\n");

        // Insert 64 rows up to full table capacity (Blue Team scaling verification).
        for i in 0..64i64 {
            let prefix: &[u8] = if i % 2 == 0 { b"sensor.cpu." } else { b"net.eth." };
            let mut q = [0u8; 128];
            let mut pos = 0usize;
            pos += append_bytes(&mut q, pos, b"INSERT INTO telemetry VALUES (");
            pos += append_i64(&mut q, pos, i + 1);
            pos += append_bytes(&mut q, pos, b", '");
            pos += append_bytes(&mut q, pos, prefix);
            pos += append_i64(&mut q, pos, i);
            pos += append_bytes(&mut q, pos, b"', ");
            pos += append_i64(&mut q, pos, (i + 1) * 10);
            pos += append_bytes(&mut q, pos, b")");
            let n = db.exec(&q[..pos], &mut out);
            assert_eq!(&out[..n], b"INSERT 1\n");
        }
        // 65th insert must be cleanly rejected at the 64-row boundary.
        let n = db.exec(b"INSERT INTO telemetry VALUES (65, 'overflow', 650)", &mut out);
        assert_eq!(&out[..n], b"error: table row capacity full (max 64)\n");

        // Index-accelerated equality lookup increments `idx_hits`:
        let hits_before = db.idx_hits;
        let n = db.exec(
            b"SELECT id, val FROM telemetry WHERE tag = 'sensor.cpu.42'",
            &mut out,
        );
        assert_eq!(&out[..n], b"id|val\n43|430\n");
        assert_eq!(db.idx_hits, hits_before + 1);

        // Aggregates: SUM, MIN, MAX, AVG over all 64 rows (sum of 10..=640 = 20800, avg = 325).
        let n = db.exec(b"SELECT SUM(val) FROM telemetry", &mut out);
        assert_eq!(&out[..n], b"sum\n20800\n");
        let n = db.exec(b"SELECT MIN(val) FROM telemetry", &mut out);
        assert_eq!(&out[..n], b"min\n10\n");
        let n = db.exec(b"SELECT MAX(val) FROM telemetry", &mut out);
        assert_eq!(&out[..n], b"max\n640\n");
        let n = db.exec(b"SELECT AVG(val) FROM telemetry", &mut out);
        assert_eq!(&out[..n], b"avg\n325\n");

        // LIKE pattern matching (`WHERE tag LIKE 'sensor.cpu.%'` matches 32 even rows).
        let n = db.exec(
            b"SELECT COUNT(*) FROM telemetry WHERE tag LIKE 'sensor.cpu.%'",
            &mut out,
        );
        assert_eq!(&out[..n], b"count\n32\n");

        // Persist all 64 rows + secondary index metadata into the 8-sector CTTLSQL1 partition and restore.
        let key = [0x99u8; 32];
        let mut sectors = [[0u8; 512]; SQL_PART_SECTORS];
        db.save_partition(&key, &mut sectors);
        let mut restored = SqlDb::empty();
        assert!(restored.load_partition(&key, &sectors));
        assert_eq!(restored.total_rows(), 64);
        let n = restored.exec(
            b"SELECT id, val FROM telemetry WHERE tag = 'net.eth.63'",
            &mut out,
        );
        assert_eq!(&out[..n], b"id|val\n64|640\n");
        assert_eq!(restored.idx_hits, 1);

        // Red Team parser hardening: reject interior unescaped quotes, integer overflow beyond i64, and pathological LIKE patterns.
        let n = restored.exec(b"SELECT * FROM telemetry WHERE tag = 'a' OR '1'='1'", &mut out);
        assert_eq!(&out[..n], b"error: malformed WHERE condition\n");
        let n = restored.exec(b"SELECT * FROM telemetry WHERE id = 99999999999999999999999", &mut out);
        assert_eq!(&out[..n], b"error: malformed WHERE condition\n");
        assert!(sql_like_match(b"sensor.cpu.42", b"%%%%%sensor%_%42%%%%"));
        assert!(!sql_like_match(b"sensor.cpu.42", b"%%%%%sensor%_%99%%%%"));
    }

    #[test]
    fn sql_upsert_compound_where_and_transactions() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 512];

        // 1. INSERT OR REPLACE / REPLACE INTO upsert on primary key (col 0).
        let n = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('os.brand', 'CuttleOS-Pro', 9)",
            &mut out,
        );
        assert_eq!(&out[..n], b"REPLACE 1\n");
        let n = db.exec(b"SELECT v, rev FROM kv WHERE k = 'os.brand'", &mut out);
        assert_eq!(&out[..n], b"v|rev\nCuttleOS-Pro|9\n");

        // 2. Compound WHERE with AND / OR.
        let n = db.exec(
            b"SELECT name FROM services WHERE port >= 443 AND proto = 'TCP'",
            &mut out,
        );
        assert_eq!(&out[..n], b"name\nhttps-tls13\n");

        let n = db.exec(
            b"SELECT name FROM services WHERE id = 1 OR id = 3",
            &mut out,
        );
        assert_eq!(&out[..n], b"name\nhttp-web\nctrl-udp\n");

        // 3. Atomic Transactions: BEGIN, mutate, ROLLBACK restores exact prior rows and tx_seq.
        let seq_before = db.tx_seq;
        let n = db.exec(b"BEGIN", &mut out);
        assert_eq!(&out[..n], b"BEGIN OK\n");
        let _ = db.exec(
            b"UPDATE services SET proto = 'DOWN' WHERE id = 1 OR id = 2",
            &mut out,
        );
        let _ = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('os.brand', 'Tampered', 99)",
            &mut out,
        );
        let n = db.exec(b"ROLLBACK", &mut out);
        assert_eq!(&out[..n], b"ROLLBACK OK\n");
        assert_eq!(db.tx_seq, seq_before);

        let n = db.exec(b"SELECT v, rev FROM kv WHERE k = 'os.brand'", &mut out);
        assert_eq!(&out[..n], b"v|rev\nCuttleOS-Pro|9\n");
        let n = db.exec(
            b"SELECT COUNT(*) FROM services WHERE proto = 'TCP'",
            &mut out,
        );
        assert_eq!(&out[..n], b"count\n2\n");

        // 4. BEGIN + COMMIT persists changes.
        let _ = db.exec(b"BEGIN", &mut out);
        let _ = db.exec(
            b"REPLACE INTO kv VALUES ('vault.mode', 'sealed-aead', 1)",
            &mut out,
        );
        let n = db.exec(b"COMMIT", &mut out);
        assert_eq!(&out[..n], b"COMMIT OK\n");
        let n = db.exec(b"SELECT v FROM kv WHERE k = 'vault.mode'", &mut out);
        assert_eq!(&out[..n], b"v\nsealed-aead\n");

        // 5. Undo log capacity (> 8 rows) and DDL refusal inside an active transaction:
        for i in 1..=8i64 {
            let mut q = [0u8; 96];
            let mut p = 0usize;
            p += append_bytes(&mut q, p, b"INSERT INTO kv VALUES ('extra.");
            p += append_i64(&mut q, p, i);
            p += append_bytes(&mut q, p, b"', 'val', 1)");
            let _ = db.exec(&q[..p], &mut out);
        }
        let rows_before = db.tables[db.find_table(b"kv").unwrap()].row_count();
        assert!(rows_before > SQL_TX_UNDO_CAP);

        let _ = db.exec(b"BEGIN", &mut out);
        // DDL inside a transaction must be refused:
        let n_ddl = db.exec(b"CREATE TABLE tmp (x INT)", &mut out);
        assert!(out[..n_ddl].starts_with(b"error: DDL (CREATE/DROP) not allowed"));
        let n_drop = db.exec(b"DROP TABLE kv", &mut out);
        assert!(out[..n_drop].starts_with(b"error: DDL (CREATE/DROP) not allowed"));

        // Bulk DELETE or UPDATE affecting > 8 rows must be refused before modifying any row:
        let n_del = db.exec(b"DELETE FROM kv", &mut out);
        assert_eq!(
            &out[..n_del],
            b"error: transaction undo log full (max 8 rows); COMMIT or ROLLBACK first\n"
        );
        assert_eq!(
            db.tables[db.find_table(b"kv").unwrap()].row_count(),
            rows_before
        );
        let _ = db.exec(b"ROLLBACK", &mut out);
        assert_eq!(
            db.tables[db.find_table(b"kv").unwrap()].row_count(),
            rows_before
        );

        // 6. Session-bound transactions (`exec_as`), `save_partition` uncommitted row isolation, and timeout:
        let n_b1 = db.exec_as(10, b"BEGIN", &mut out);
        assert_eq!(&out[..n_b1], b"BEGIN OK\n");
        let _ = db.exec_as(
            10,
            b"REPLACE INTO kv VALUES ('vault.mode', 'uncommitted-secret', 99)",
            &mut out,
        );
        // Another session (owner = 20 or console owner = 0) cannot mutate or ROLLBACK session 10's transaction:
        let n_busy_w = db.exec_as(
            20,
            b"INSERT INTO kv VALUES ('intruder', '1', 1)",
            &mut out,
        );
        assert!(out[..n_busy_w].starts_with(b"error: EBUSY"));
        let n_busy_rb = db.exec_as(0, b"ROLLBACK", &mut out);
        assert!(out[..n_busy_rb].starts_with(b"error: EBUSY"));

        // `save_partition` while session 10's transaction is open must serialize ONLY the committed state:
        let key = [0x77u8; 32];
        let mut sectors = [[0u8; 512]; SQL_PART_SECTORS];
        db.save_partition(&key, &mut sectors);
        let mut snap = SqlDb::empty();
        assert!(snap.load_partition(&key, &sectors));
        let n_snap = snap.exec(b"SELECT v FROM kv WHERE k = 'vault.mode'", &mut out);
        assert_eq!(
            &out[..n_snap],
            b"v\nsealed-aead\n",
            "save_partition must not persist uncommitted transaction mutations"
        );

        // Idle timeout (`SQL_TX_MAX_IDLE_TICKS = 16`) automatically rolls back abandoned transactions:
        for _ in 0..15 {
            assert!(!db.tick_transaction_timeout());
        }
        assert!(db.tick_transaction_timeout());
        assert!(!db.tx_active);
        let n_after_to = db.exec(b"SELECT v FROM kv WHERE k = 'vault.mode'", &mut out);
        assert_eq!(&out[..n_after_to], b"v\nsealed-aead\n");
    }

    #[test]
    fn regression_item3_sql_read_committed_prevents_dirty_reads() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 512];
        let hash_committed = db.state_hash();

        // Owner 0 (console) opens BEGIN and mutates rows.
        let n = db.exec_as(SQL_OWNER_CONSOLE, b"BEGIN", &mut out);
        assert_eq!(&out[..n], b"BEGIN OK\n");
        let _ = db.exec_as(
            SQL_OWNER_CONSOLE,
            b"UPDATE kv SET v = 'DirtyRole' WHERE k = 'cluster.role'",
            &mut out,
        );
        let _ = db.exec_as(
            SQL_OWNER_CONSOLE,
            b"INSERT INTO kv VALUES ('dirty.key', 'uncommitted', 1)",
            &mut out,
        );

        // Owner 0 sees its own uncommitted changes.
        let n_own = db.exec_as(
            SQL_OWNER_CONSOLE,
            b"SELECT v FROM kv WHERE k = 'cluster.role'",
            &mut out,
        );
        assert_eq!(&out[..n_own], b"v\nDirtyRole\n");

        // Another owner (e.g., SQL_OWNER_VAULT, SQL_OWNER_CRON, SQL_OWNER_TRIAD, or HTTP session 42)
        // must see only the committed rows (Read Committed — no dirty reads).
        let n_other = db.exec_as(
            SQL_OWNER_VAULT,
            b"SELECT v FROM kv WHERE k = 'cluster.role'",
            &mut out,
        );
        assert_eq!(&out[..n_other], b"v\nprimary\n");
        let n_dirty = db.exec_as(
            42,
            b"SELECT v FROM kv WHERE k = 'dirty.key'",
            &mut out,
        );
        assert_eq!(&out[..n_dirty], b"v\n");

        // `state_hash()` must also reflect only committed rows while a transaction is active.
        assert_eq!(db.state_hash(), hash_committed);

        // A `/*triad*/` prefixed statement runs as `SQL_OWNER_TRIAD` even if invoked via `exec` (owner 0),
        // so it is refused with `EBUSY` on writes while console `BEGIN` is active.
        let n_triad = db.exec(
            b"/*triad*/ INSERT INTO kv VALUES ('triad.k', 'v', 1)",
            &mut out,
        );
        assert!(out[..n_triad].starts_with(b"error: EBUSY"));

        let _ = db.exec_as(SQL_OWNER_CONSOLE, b"ROLLBACK", &mut out);
        assert_eq!(db.state_hash(), hash_committed);
    }

    #[test]
    fn regression_prev_item3_rollback_undo_overflow_and_ddl_in_tx_refused() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 512];
        for i in 1..=8i64 {
            let mut q = [0u8; 96];
            let mut p = 0usize;
            p += append_bytes(&mut q, p, b"INSERT INTO kv VALUES ('k.");
            p += append_i64(&mut q, p, i);
            p += append_bytes(&mut q, p, b"', 'v', 1)");
            let _ = db.exec(&q[..p], &mut out);
        }
        let _ = db.exec(b"BEGIN", &mut out);
        let n_ddl = db.exec(b"CREATE TABLE t2 (id INT)", &mut out);
        assert!(out[..n_ddl].starts_with(b"error: DDL (CREATE/DROP) not allowed"));
        let n_upd = db.exec(b"UPDATE kv SET rev = 99", &mut out);
        assert_eq!(
            &out[..n_upd],
            b"error: transaction undo log full (max 8 rows); COMMIT or ROLLBACK first\n"
        );
        let _ = db.exec(b"ROLLBACK", &mut out);
    }

    #[test]
    fn sqldump_chunked_lossless_and_doubled_quotes_hex_literals() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 1024];

        // 1. Doubled single quotes ('it''s') and hex literals (X'...') round-trip losslessly,
        //    including values containing '|' and ','.
        let n1 = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('quote.k', 'it''s|a,test', 7)",
            &mut out,
        );
        assert_eq!(&out[..n1], b"REPLACE 1\n");
        let n2 = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('hex.k', X'617c622763', 8)",
            &mut out,
        );
        assert_eq!(&out[..n2], b"REPLACE 1\n");

        // Unescaped interior quote (SQL injection attempt) must still be rejected.
        let n_inj = db.exec(
            b"SELECT * FROM kv WHERE k = 'a' OR '1'='1'",
            &mut out,
        );
        assert!(out[..n_inj].starts_with(b"error:"));

        // 2. `.dump kv 0 3` and `.dump kv 3 3` emit chunked hex-encoded rows and DDL under 1024 bytes.
        let nd0 = db.exec(b".dump kv 0 3", &mut out);
        assert!(nd0 < 1024);
        let s0 = core::str::from_utf8(&out[..nd0]).unwrap();
        assert!(s0.starts_with("sqldump table=kv rows=4 off=0 count=3 digest="));
        assert!(s0.contains(" ddl="));

        let nd1 = db.exec(b".dump kv 3 3", &mut out);
        assert!(nd1 < 1024);
        let s1 = core::str::from_utf8(&out[..nd1]).unwrap();
        assert!(s1.starts_with("sqldump table=kv rows=4 off=3 count=1 digest="));

        // 3. Two databases with identical rows inserted in opposite order produce identical `.dump` output and digest.
        let mut db_a = SqlDb::empty();
        let mut db_b = SqlDb::empty();
        let _ = db_a.exec(b"CREATE TABLE t (k TEXT, v INT)", &mut out);
        let _ = db_b.exec(b"CREATE TABLE t (k TEXT, v INT)", &mut out);
        let _ = db_a.exec(b"INSERT INTO t VALUES ('alpha', 1)", &mut out);
        let _ = db_a.exec(b"INSERT INTO t VALUES ('bravo', 2)", &mut out);
        let _ = db_b.exec(b"INSERT INTO t VALUES ('bravo', 2)", &mut out);
        let _ = db_b.exec(b"INSERT INTO t VALUES ('alpha', 1)", &mut out);
        let mut out_a = [0u8; 1024];
        let mut out_b = [0u8; 1024];
        let na = db_a.exec(b".dump t 0 3", &mut out_a);
        let nb = db_b.exec(b".dump t 0 3", &mut out_b);
        assert_eq!(&out_a[..na], &out_b[..nb]);
    }

    #[test]
    fn sqldump_digest_only_mode_matches_full_dump_header_and_rejects_bad_args() {
        let mut db = SqlDb::new();
        let mut out_full = [0u8; 1024];
        let mut out_dig = [0u8; 1024];
        // Verify 256-bit SHA-256 table digest on fresh genesis `kv` matches golden SHA-256 vector:
        let mut out_gen = [0u8; 1024];
        let n_gen = db.exec(b".dump kv digest", &mut out_gen);
        let s_gen = core::str::from_utf8(&out_gen[..n_gen]).unwrap().trim_end_matches('\n');
        assert_eq!(
            s_gen,
            "sqldump table=kv rows=2 off=0 count=0 digest=9909bdf6933be5adf4c8f9dc94e9b4bc072d9e85d068d1b7ec603240be4bbc21 ddl=435245415445205441424c45206b7620286b20544558542c207620544558542c2072657620494e5429"
        );

        let _ = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('v:secret', 'cipher-a', 100)",
            &mut out_full,
        );
        let _ = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('app.k', 'val', 2)",
            &mut out_full,
        );

        let n_full = db.exec(b".dump kv 0 3", &mut out_full);
        let s_full = core::str::from_utf8(&out_full[..n_full]).unwrap();
        let full_hdr = s_full.lines().next().unwrap();

        let n_dig = db.exec(b".dump kv digest", &mut out_dig);
        let s_dig = core::str::from_utf8(&out_dig[..n_dig]).unwrap();
        let dig_lines: [&str; 1] = [s_dig.trim_end_matches('\n')];
        assert!(!s_dig.contains("\nrow "), "digest-only .dump must not emit row lines: {s_dig}");
        assert!(
            dig_lines[0].starts_with("sqldump table=kv rows=4 off=0 count=0 digest="),
            "unexpected digest header: {}",
            dig_lines[0]
        );
        let dig_tok = dig_lines[0]
            .split_whitespace()
            .find_map(|w| w.strip_prefix("digest="))
            .unwrap();
        assert_eq!(dig_tok.len(), 64, "expected 64-hex-char SHA-256 digest, got: {dig_tok}");
        assert!(dig_tok.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase()));
        // Header matches full dump header except count=0 instead of count=3
        let expected_dig_hdr = full_hdr.replace(" count=3 ", " count=0 ");
        assert_eq!(dig_lines[0], expected_dig_hdr);

        // `.dump kv 0 0` also returns the same digest-only header
        let mut out_z = [0u8; 1024];
        let n_z = db.exec(b".dump kv 0 0", &mut out_z);
        assert_eq!(&out_z[..n_z], &out_dig[..n_dig]);

        // Extra token after `digest` or negative limit is rejected with usage
        let n_bad1 = db.exec(b".dump kv digest extra", &mut out_z);
        assert!(out_z[..n_bad1].starts_with(b"usage: .dump"));
        let n_bad2 = db.exec(b".dump kv 0 -1", &mut out_z);
        assert!(out_z[..n_bad2].starts_with(b"usage: .dump"));
    }

    #[test]
    fn parse_literal_rejects_text_and_hex_literals_exceeding_24_bytes_without_truncating() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];

        // 1. Exactly 24-byte TEXT ('24 chars') and 24-byte hex (X'48 hex chars') succeed.
        let n_ok1 = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('ok.24.str', '0123456789abcdef01234567', 1)",
            &mut out,
        );
        assert_eq!(&out[..n_ok1], b"REPLACE 1\n");
        let n_ok2 = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('ok.24.hex', X'303132333435363738396162636465663031323334353637', 1)",
            &mut out,
        );
        assert_eq!(&out[..n_ok2], b"REPLACE 1\n");

        // 2. 25-byte TEXT ('25 chars') and 25-byte hex (X'50 hex chars') in INSERT and UPDATE
        //    are rejected with `error:` rather than silently truncated to 24 bytes.
        let n_bad_str = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('bad.25.str', '0123456789abcdef012345678', 1)",
            &mut out,
        );
        assert!(
            out[..n_bad_str].starts_with(b"error:"),
            "25-byte TEXT literal must be rejected: {:?}",
            core::str::from_utf8(&out[..n_bad_str])
        );
        let n_bad_hex = db.exec(
            b"INSERT OR REPLACE INTO kv VALUES ('bad.25.hex', X'30313233343536373839616263646566303132333435363738', 1)",
            &mut out,
        );
        assert!(
            out[..n_bad_hex].starts_with(b"error:"),
            "25-byte X'..' literal must be rejected: {:?}",
            core::str::from_utf8(&out[..n_bad_hex])
        );
        let n_bad_upd = db.exec(
            b"UPDATE kv SET v = '0123456789abcdef012345678' WHERE k = 'ok.24.str'",
            &mut out,
        );
        assert!(
            out[..n_bad_upd].starts_with(b"error:"),
            "25-byte UPDATE SET TEXT literal must be rejected: {:?}",
            core::str::from_utf8(&out[..n_bad_upd])
        );
        assert!(SqlVal::try_from_text(&[b'x'; 25]).is_none());
    }

    #[test]
    fn idle_timeout_aborts_the_transaction_until_its_owner_acknowledges_it() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];
        let owner = 2u64;
        let other = 3u64;
        let run = |db: &mut SqlDb, who: u64, q: &[u8], out: &mut [u8; 256]| -> alloc::string::String {
            let n = db.exec_as(who, q, out);
            alloc::string::String::from_utf8_lossy(&out[..n]).into_owned()
        };

        // A two-statement transfer: the first half is sent, then the client stalls.
        assert_eq!(run(&mut db, owner, b"BEGIN", &mut out), "BEGIN OK\n");
        assert_eq!(
            run(&mut db, owner, b"INSERT INTO kv VALUES ('debit', '100', 1)", &mut out),
            "INSERT 1\n"
        );
        let rows_before = db.total_rows();
        for _ in 0..SQL_TX_MAX_IDLE_TICKS - 1 {
            assert!(!db.tick_transaction_timeout());
        }
        assert!(db.tick_transaction_timeout(), "the idle transaction must be rolled back");
        assert_eq!(db.total_rows(), rows_before - 1, "the first half must be undone");
        let committed = db.committed_seq();

        // The second half arrives late. It must not be applied on its own.
        let late = run(&mut db, owner, b"INSERT INTO kv VALUES ('credit', '100', 1)", &mut out);
        assert!(late.starts_with("error: transaction timed out"), "{late}");
        let late = run(&mut db, owner, b"UPDATE kv SET v = 'x' WHERE k = 'boot.state'", &mut out);
        assert!(late.starts_with("error: transaction timed out"), "{late}");
        let late = run(&mut db, owner, b"DELETE FROM kv WHERE k = 'credit'", &mut out);
        assert!(late.starts_with("error: transaction timed out"), "{late}");
        assert_eq!(db.total_rows(), rows_before - 1);
        assert_eq!(db.committed_seq(), committed, "nothing may be committed while aborted");

        // Reads still work, and other sessions are not affected.
        assert!(run(&mut db, owner, b"SELECT k FROM kv", &mut out).starts_with("k\n"));
        assert_eq!(
            run(&mut db, other, b"INSERT INTO kv VALUES ('other', '1', 1)", &mut out),
            "INSERT 1\n"
        );

        // COMMIT reports the loss instead of claiming success, and clears the state.
        let c = run(&mut db, owner, b"COMMIT", &mut out);
        assert!(c.starts_with("error: transaction timed out"), "{c}");
        assert_eq!(
            run(&mut db, owner, b"INSERT INTO kv VALUES ('after', '1', 1)", &mut out),
            "INSERT 1\n"
        );

        // ROLLBACK and BEGIN also acknowledge it.
        for ack in [b"ROLLBACK".as_slice(), b"BEGIN".as_slice()] {
            assert_eq!(run(&mut db, owner, b"BEGIN", &mut out), "BEGIN OK\n");
            for _ in 0..SQL_TX_MAX_IDLE_TICKS {
                db.tick_transaction_timeout();
            }
            assert!(db.tx_aborted && !db.tx_active);
            let r = run(&mut db, owner, ack, &mut out);
            assert!(r.ends_with(" OK\n"), "{r}");
            assert!(!db.tx_aborted);
            if db.tx_active {
                assert_eq!(run(&mut db, owner, b"ROLLBACK", &mut out), "ROLLBACK OK\n");
            }
        }
    }

    #[test]
    fn create_index_respects_partition_capacity_and_a_full_database_saves_every_row() {
        let key = [0x5Cu8; DURABLE_DIGEST_LEN];
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];
        let n = db.exec(b"CREATE TABLE tiny (n INT)", &mut out);
        assert_eq!(&out[..n], b"CREATE TABLE tiny OK\n");

        // Fill the partition with wide rows, then top it up with 3-byte rows
        // so that less than one index header of headroom is left.
        let mut wide = 0u32;
        loop {
            let q = alloc::format!(
                "INSERT INTO kv VALUES ('key-{wide:04}-padpadpadpadpad', 'value-{wide:04}-padpadpadpad', {wide})"
            );
            let n = db.exec(q.as_bytes(), &mut out);
            if &out[..n] != b"INSERT 1\n" {
                break;
            }
            wide += 1;
            assert!(wide < 200, "kv never filled");
        }
        let n = db.exec(b"CREATE TABLE big (a TEXT, b TEXT, c TEXT, d TEXT)", &mut out);
        assert_eq!(&out[..n], b"CREATE TABLE big OK
");
        let mut bulk = 0u32;
        loop {
            let q = alloc::format!(
                "INSERT INTO big VALUES ('a-{bulk:04}-padpadpadpadpadpa', 'b-{bulk:04}-padpadpadpadpadpa', 'c-{bulk:04}-padpadpadpadpadpa', 'd-{bulk:04}-padpadpadpadpadpa')"
            );
            let n = db.exec(q.as_bytes(), &mut out);
            if &out[..n] != b"INSERT 1\n" {
                assert_eq!(
                    &out[..n],
                    b"error: SQL partition capacity full (8 KiB CTTLSQL1 limit)\n"
                );
                break;
            }
            bulk += 1;
            assert!(bulk < 200, "big never filled");
        }
        let mut small = 0u32;
        loop {
            let q = alloc::format!("INSERT INTO tiny VALUES ({small})");
            let n = db.exec(q.as_bytes(), &mut out);
            if &out[..n] != b"INSERT 1\n" {
                break;
            }
            small += 1;
            assert!(small < 200, "tiny never filled");
        }
        let cap = SQL_PART_SECTORS * 512 - 8;
        assert!(db.serialized_partition_bytes() <= cap);
        assert!(
            db.serialized_partition_bytes() + 18 > cap,
            "setup left {} bytes free; the index would fit and the test would prove nothing",
            cap - db.serialized_partition_bytes()
        );

        // An index name is stored in the partition; here it no longer fits.
        let seq = db.tx_seq;
        let n = db.exec(b"CREATE INDEX idx_kv_key_name0 ON kv (k)", &mut out);
        assert_eq!(
            &out[..n],
            b"error: SQL partition capacity full (8 KiB CTTLSQL1 limit)\n"
        );
        assert_eq!(db.tx_seq, seq, "a refused statement must not change the database");

        // The full database round-trips with every row.
        let mut secs = [[0u8; 512]; SQL_PART_SECTORS];
        assert_eq!(db.try_save_partition(&key, &mut secs), Ok(()));
        assert_eq!(db.committed_partition_bytes(), db.serialized_partition_bytes());
        let mut back = SqlDb::new();
        assert!(back.load_partition(&key, &secs));
        assert_eq!(back.total_rows(), db.total_rows());
        assert_eq!(back.state_hash(), db.state_hash());

        // A database that cannot fit is refused outright, never saved short.
        // (Reachable only by bypassing the statement-level checks, as here.)
        let mut over = db;
        let last = over.tables.iter().rposition(|t| t.used).expect("a table");
        over.tables[last].index_name_len = SQL_IDENT_LEN as u8;
        over.tables[last].indexed_col = 0;
        assert!(over.committed_partition_bytes() > SQL_PART_SECTORS * 512 - 8);
        let mut grown = over;
        let mut t = 0usize;
        while grown.committed_partition_bytes() <= SQL_PART_SECTORS * 512 && t < SQL_MAX_TABLES {
            if grown.tables[t].used && grown.tables[t].index_name_len == 0 {
                grown.tables[t].index_name_len = SQL_IDENT_LEN as u8;
                grown.tables[t].indexed_col = 0;
            }
            t += 1;
        }
        if grown.committed_partition_bytes() > SQL_PART_SECTORS * 512 {
            let mut secs2 = [[0xEEu8; 512]; SQL_PART_SECTORS];
            assert_eq!(
                grown.try_save_partition(&key, &mut secs2),
                Err(SqlSaveError::TooLarge)
            );
            assert!(
                secs2.iter().all(|s| s.iter().all(|&b| b == 0)),
                "a refused save must not leave a partial image"
            );
            assert!(!SqlDb::new().load_partition(&key, &secs2));
        }
        assert_eq!(
            SqlDb::new().try_save_partition(&[0u8; DURABLE_DIGEST_LEN], &mut secs),
            Err(SqlSaveError::KeyUnset)
        );
    }

    #[test]
    fn sql_owner_triad_prefix_refused_for_non_triad_and_non_console_owners() {
        let mut db = SqlDb::new();
        assert_eq!(db.tx_seq, SQL_GENESIS_TX_SEQ);
        let mut out = [0u8; 256];

        // 1. Non-Triad / non-console callers (HTTP anonymous, HTTP session slots 1..=4, UDP, cron, vault)
        //    must be refused when supplying `/*triad*/` or `/*t*/` owner override prefixes.
        for bad_owner in [
            1u64,
            2u64,
            4u64,
            SQL_OWNER_HTTP_ANON,
            SQL_OWNER_UDP,
            SQL_OWNER_CRON,
            SQL_OWNER_VAULT,
        ] {
            for q in [
                b"/*triad*/ INSERT INTO kv VALUES ('pwn', '1', 1)".as_slice(),
                b"/*t*/ INSERT INTO kv VALUES ('pwn', '1', 1)".as_slice(),
                b"/*triad*/ SELECT * FROM kv".as_slice(),
                b"/*t*/ .dump kv".as_slice(),
            ] {
                let n = db.exec_as(bad_owner, q, &mut out);
                assert_eq!(
                    &out[..n],
                    b"error: EACCES (/*triad*/ prefix reserved for Triad controller)\n",
                    "owner={bad_owner} must not be allowed to use Triad prefix in {q:?}"
                );
            }
        }

        // 2. Triad controller (`SQL_OWNER_TRIAD`) and local serial console (`SQL_OWNER_CONSOLE`) succeed.
        let n_triad = db.exec_as(
            SQL_OWNER_TRIAD,
            b"/*t*/ INSERT INTO kv VALUES ('triad.ok', '1', 1)",
            &mut out,
        );
        assert_eq!(&out[..n_triad], b"INSERT 1\n");
        let n_con = db.exec_as(
            SQL_OWNER_CONSOLE,
            b"/*triad*/ SELECT v FROM kv WHERE k = 'triad.ok'",
            &mut out,
        );
        assert_eq!(&out[..n_con], b"v\n1\n");
    }

    #[test]
    fn state_hash_is_slot_order_independent_and_parser_rejects_overflow_and_malformed_clauses() {
        let mut out = [0u8; 512];

        // 1. Two databases reaching identical logical rows via different DELETE/INSERT slot orderings
        //    must produce the exact same `state_hash()`.
        let mut db_a = SqlDb::new();
        let mut db_b = SqlDb::new();
        let n = db_a.exec(b"INSERT INTO kv VALUES ('alpha', '1', 10)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        let n = db_a.exec(b"INSERT INTO kv VALUES ('beta', '2', 20)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");

        // `db_b` inserts a dummy first, then `beta`, then deletes dummy, then inserts `alpha` into slot 0
        // so `beta` sits in a higher physical `rows[]` index than in `db_a` (or vice versa):
        let n = db_b.exec(b"INSERT INTO kv VALUES ('tmp', '0', 0)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        let n = db_b.exec(b"INSERT INTO kv VALUES ('beta', '2', 20)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        let n = db_b.exec(b"DELETE FROM kv WHERE k = 'tmp'", &mut out);
        assert_eq!(&out[..n], b"DELETE 1\n");
        let n = db_b.exec(b"INSERT INTO kv VALUES ('alpha', '1', 10)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        // Flip order in `db_b`: put `beta` in slot 0 and `alpha` in slot 1!
        let mut db_c = SqlDb::new();
        let _ = db_c.exec(b"INSERT INTO kv VALUES ('beta', '2', 20)", &mut out);
        let _ = db_c.exec(b"INSERT INTO kv VALUES ('alpha', '1', 10)", &mut out);
        assert_eq!(
            db_a.state_hash(),
            db_c.state_hash(),
            "state_hash() must be invariant to physical row-slot ordering across Triad nodes"
        );

        // 2. Duplicate column names in CREATE TABLE and malformed LIMIT / ORDER BY must be rejected.
        let n_dup = db_a.exec(b"CREATE TABLE bad_dup (id INT, id TEXT)", &mut out);
        assert!(
            out[..n_dup].starts_with(b"error:"),
            "duplicate column names must fail: {:?}",
            core::str::from_utf8(&out[..n_dup])
        );
        let n_lim = db_a.exec(b"SELECT * FROM kv LIMIT abc", &mut out);
        assert!(
            out[..n_lim].starts_with(b"error:"),
            "non-numeric LIMIT must fail: {:?}",
            core::str::from_utf8(&out[..n_lim])
        );
        let n_ord = db_a.exec(b"SELECT * FROM kv ORDER k", &mut out);
        assert!(
            out[..n_ord].starts_with(b"error:"),
            "ORDER without BY must fail: {:?}",
            core::str::from_utf8(&out[..n_ord])
        );
        let n_dir = db_a.exec(b"SELECT * FROM kv ORDER BY k SIDEWAYS", &mut out);
        assert!(
            out[..n_dir].starts_with(b"error:"),
            "invalid ORDER BY direction must fail: {:?}",
            core::str::from_utf8(&out[..n_dir])
        );

        // 3. Partition capacity enforcement: `SqlDb` must reject mutations that would exceed the
        //    4 KiB `CTTLSQL1` partition budget instead of silently dropping rows on `save_partition`.
        let mut db_full = SqlDb::new();
        for t in 0..2usize {
            let create = alloc::format!("CREATE TABLE wide{t} (a TEXT, b TEXT, c TEXT, d TEXT)");
            let n = db_full.exec(create.as_bytes(), &mut out);
            assert!(!out[..n].starts_with(b"error:"));
        }
        let mut rejected_overflow = false;
        for t in 0..2usize {
            for r in 0..40usize {
                let ins = alloc::format!(
                    "INSERT INTO wide{t} VALUES ('k{t}_{r:02}_xxxxxxxxxxxxxxxx', 'v1_{r:02}_xxxxxxxxxxxxxxxxxx', 'v2_{r:02}_xxxxxxxxxxxxxxxxxx', 'v3_{r:02}_xxxxxxxxxxxxxxxxxx')"
                );
                let ni = db_full.exec(ins.as_bytes(), &mut out);
                if out[..ni].starts_with(b"error:") {
                    rejected_overflow = true;
                    break;
                }
            }
        }
        assert!(
            rejected_overflow,
            "SqlDb must explicitly reject INSERT once 4 KiB CTTLSQL1 partition capacity is reached"
        );
        let key = [0x5Au8; 32];
        let mut secs = [[0u8; 512]; SQL_PART_SECTORS];
        db_full.save_partition(&key, &mut secs);
        let mut reloaded = SqlDb::empty();
        assert!(reloaded.load_partition(&key, &secs));
        assert_eq!(
            reloaded.state_hash(),
            db_full.state_hash(),
            "every accepted SQL row must survive save_partition + load_partition without silent truncation"
        );
    }

    #[test]
    fn sql_rejects_excess_projections_empty_commas_and_trailing_tokens() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];

        let n = db.exec(b"SELECT k, v, rev, k, v FROM kv", &mut out);
        assert!(
            out[..n].starts_with(b"error:"),
            "SELECT with >4 projected columns must reject instead of silently truncating: {:?}",
            core::str::from_utf8(&out[..n])
        );

        let n = db.exec(b"SELECT , FROM kv", &mut out);
        assert!(
            out[..n].starts_with(b"error:"),
            "SELECT with empty projection slot must reject: {:?}",
            core::str::from_utf8(&out[..n])
        );

        let n = db.exec(b"INSERT INTO kv VALUES ('bad', , 'v', 1)", &mut out);
        assert!(
            out[..n].starts_with(b"error:"),
            "INSERT with empty comma slot must reject: {:?}",
            core::str::from_utf8(&out[..n])
        );

        let n = db.exec(b"INSERT INTO kv VALUES ('bad', 'v', 1) WHERE 1 = 0", &mut out);
        assert!(
            out[..n].starts_with(b"error:"),
            "INSERT with trailing tokens after ')' must reject: {:?}",
            core::str::from_utf8(&out[..n])
        );

        let n = db.exec(b"CREATE INDEX idx_bad ON kv (k) GARBAGE", &mut out);
        assert!(
            out[..n].starts_with(b"error:"),
            "CREATE INDEX with trailing tokens after ')' must reject: {:?}",
            core::str::from_utf8(&out[..n])
        );

        let n = db.exec(b"CREATE TABLE bad_cols (a INT, , b TEXT)", &mut out);
        assert!(
            out[..n].starts_with(b"error:"),
            "CREATE TABLE with empty comma slot must reject: {:?}",
            core::str::from_utf8(&out[..n])
        );
    }

    #[test]
    fn multiple_aborted_transaction_owners_are_tracked_independently() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];
        let owner_a: u64 = 0x1_0000_0100;
        let owner_b: u64 = 0x1_0000_0201;
        let owner_c: u64 = 0x1_0000_0302;

        // Owner A opens a transaction and times out.
        let n_begin_a = db.exec_as(owner_a, b"BEGIN", &mut out);
        assert_eq!(&out[..n_begin_a], b"BEGIN OK\n");
        let n = db.exec_as(owner_a, b"INSERT INTO kv VALUES ('a', '1', 1)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        for _ in 0..SQL_TX_MAX_IDLE_TICKS {
            let _ = db.tick_transaction_timeout();
        }
        assert!(db.is_owner_aborted(owner_a));
        assert!(!db.is_owner_aborted(owner_b));

        // Before Owner A acknowledges, Owner B opens a transaction and ALSO times out.
        let n_begin_b = db.exec_as(owner_b, b"BEGIN", &mut out);
        assert_eq!(&out[..n_begin_b], b"BEGIN OK\n");
        let n = db.exec_as(owner_b, b"INSERT INTO kv VALUES ('b', '2', 2)", &mut out);
        assert_eq!(&out[..n], b"INSERT 1\n");
        for _ in 0..SQL_TX_MAX_IDLE_TICKS {
            let _ = db.tick_transaction_timeout();
        }

        // BOTH Owner A and Owner B remain aborted; Owner C is completely unaffected!
        assert!(db.is_owner_aborted(owner_a));
        assert!(db.is_owner_aborted(owner_b));
        assert!(!db.is_owner_aborted(owner_c));

        let n_c = db.exec_as(owner_c, b"INSERT INTO kv VALUES ('c', '3', 3)", &mut out);
        assert_eq!(&out[..n_c], b"INSERT 1\n", "unaffected owner C must not be blocked");

        let n_a = db.exec_as(owner_a, b"INSERT INTO kv VALUES ('a2', '9', 9)", &mut out);
        assert!(
            out[..n_a].starts_with(b"error: transaction timed out and was rolled back;"),
            "owner A must still be refused even after owner B also timed out"
        );

        // Owner B acknowledges with ROLLBACK; Owner A is STILL aborted until it acknowledges!
        let n_rb_b = db.exec_as(owner_b, b"ROLLBACK", &mut out);
        assert_eq!(&out[..n_rb_b], b"ROLLBACK OK\n");
        assert!(!db.is_owner_aborted(owner_b));
        assert!(db.is_owner_aborted(owner_a));

        let n_rb_a = db.exec_as(owner_a, b"ROLLBACK", &mut out);
        assert_eq!(&out[..n_rb_a], b"ROLLBACK OK\n");
        assert!(!db.is_owner_aborted(owner_a));
        assert!(!db.tx_aborted);
    }

    #[test]
    fn paged_sql_scales_to_1500_rows_8_tables_btree_ranges_and_o_dirty_leaf_sync() {
        use crate::paged_store::{PagedBlockStore, PAGED_STORE_DEFAULT_DISK_SECTORS};
        use crate::state_store::{testdisk::MemDisk, SectorIo};

        let mut db = SqlDb::new();
        db.set_paged_mode(true);
        let mut out = [0u8; 4096];

        // 1. Create up to 8 total tables (default `services` + `kv` + 6 user tables),
        //    and verify the 9th table is rejected.
        let mut t = 0usize;
        while t < 6 {
            let ddl = alloc::format!("CREATE TABLE ext_{t} (id INT, label TEXT, score INT)");
            let n = db.exec(ddl.as_bytes(), &mut out);
            assert!(
                out[..n].ends_with(b" OK\n"),
                "table ext_{t} failed: {:?}",
                core::str::from_utf8(&out[..n])
            );
            t += 1;
        }
        assert_eq!(db.table_count(), SQL_PAGED_MAX_TABLES);
        let n_ninth = db.exec(b"CREATE TABLE ext_overflow (id INT)", &mut out);
        assert_eq!(&out[..n_ninth], b"error: maximum table limit reached\n");

        // 2. Define a B+Tree INT index on `ext_0(id)` and bulk-insert 1,500 rows via multi-tuple VALUES!
        let n_idx = db.exec(b"CREATE INDEX idx_ext0_id ON ext_0 (id)", &mut out);
        assert_eq!(&out[..n_idx], b"CREATE INDEX idx_ext0_id OK\n");

        let mut batch = 0usize;
        while batch < 150 {
            let mut q = alloc::string::String::from("INSERT INTO ext_0 VALUES ");
            let mut k = 0usize;
            while k < 10 {
                let id = (batch * 10 + k) as i64;
                let score = (id * 7) % 1000;
                if k > 0 {
                    q.push_str(", ");
                }
                q.push_str(&alloc::format!("({id}, 'item-{id:04}', {score})"));
                k += 1;
            }
            let n = db.exec(q.as_bytes(), &mut out);
            assert_eq!(
                &out[..n],
                b"INSERT 10\n",
                "batch {batch} failed: {:?}",
                core::str::from_utf8(&out[..n])
            );
            batch += 1;
        }
        let n_cnt = db.exec(b"SELECT COUNT(*) FROM ext_0", &mut out);
        assert_eq!(&out[..n_cnt], b"count\n1500\n");

        // 3. B+Tree equality + range queries (`=`, `>=` AND `<=`, `<`, `>`) hit `btree_keys` (`idx_hits` advances).
        let hits0 = db.idx_hits;
        let n_eq = db.exec(b"SELECT label, score FROM ext_0 WHERE id = 1234", &mut out);
        assert_eq!(&out[..n_eq], b"label|score\nitem-1234|638\n");
        assert_eq!(db.idx_hits, hits0 + 1);

        let n_rng = db.exec(
            b"SELECT id FROM ext_0 WHERE id >= 1495 AND id <= 1498 ORDER BY id ASC",
            &mut out,
        );
        assert_eq!(&out[..n_rng], b"id\n1495\n1496\n1497\n1498\n");
        assert_eq!(db.idx_hits, hits0 + 2);

        let n_lt = db.exec(b"SELECT COUNT(*) FROM ext_0 WHERE id < 25", &mut out);
        assert_eq!(&out[..n_lt], b"count\n25\n");
        assert_eq!(db.idx_hits, hits0 + 3);

        // 4. Sync all 1,505 committed rows to `PagedBlockStore` on an 8192-sector (4 MiB) disk.
        let key = [0x42u8; DURABLE_DIGEST_LEN];
        let mut disk = MemDisk::new(PAGED_STORE_DEFAULT_DISK_SECTORS as usize);
        let (_, max_logical) = PagedBlockStore::geometry_for_sectors(disk.capacity_sectors());
        let mut store = PagedBlockStore::new();
        let synced_rows = db
            .sync_to_paged_store(&mut store, max_logical)
            .expect("initial paged sync");
        assert_eq!(synced_rows, 1505);
        let anchor1 = store.commit_dirty(&mut disk, &key, 1).expect("commit 1");
        let full_pages_written = store.last_dirty_pages_written();
        assert!(
            full_pages_written >= 48,
            "initial 1,500-row commit should stage ~48+ pages, wrote {full_pages_written}"
        );

        // 5. Mutate ONE row in the 1,500-row table and verify O(dirty pages) (`<= 2` pages: 1 SqlLeaf + 1 SqlCatalog)!
        let n_upd = db.exec(b"UPDATE ext_0 SET score = 9999 WHERE id = 777", &mut out);
        assert_eq!(&out[..n_upd], b"UPDATE 1\n");
        let synced_rows2 = db
            .sync_to_paged_store(&mut store, max_logical)
            .expect("incremental sync");
        assert_eq!(synced_rows2, 1505);
        let anchor2 = store.commit_dirty(&mut disk, &key, 1).expect("commit 2");
        assert_eq!(
            store.last_dirty_pages_written(),
            2,
            "single-row UPDATE in 1,500-row table must write ONLY 2 pages (1 SqlLeaf + 1 SqlCatalog)"
        );

        // 6. Verify inline `CTTLSQL1` produces an HMAC-authenticated `SQL_PART_FLAG_PAGED` stub,
        //    unpaged `SqlDb` refuses the stub, and `load_from_paged_store` restores exact state_hash!
        let mut sql_secs = [[0u8; 512]; SQL_PART_SECTORS];
        assert_eq!(db.try_save_partition(&key, &mut sql_secs), Ok(()));
        assert_eq!(sql_secs[0][18], SQL_PART_FLAG_PAGED);
        assert!(!SqlDb::new().load_partition(&key, &sql_secs));

        let mut recovered_store = PagedBlockStore::new();
        recovered_store
            .recover_at_anchor(&mut disk, &key, &anchor2)
            .expect("recover anchor2");
        let mut reloaded = SqlDb::empty();
        let loaded_rows = reloaded
            .load_from_paged_store(&recovered_store)
            .expect("load_from_paged_store");
        assert_eq!(loaded_rows, 1505);
        assert_eq!(reloaded.state_hash(), db.state_hash());
        let n_chk = reloaded.exec(b"SELECT score FROM ext_0 WHERE id = 777", &mut out);
        assert_eq!(&out[..n_chk], b"score\n9999\n");

        // Verify previous CoW epoch (`anchor1`) also remains recoverable before overwrite!
        let mut prev_store = PagedBlockStore::new();
        prev_store
            .recover_at_anchor(&mut disk, &key, &anchor1)
            .expect("recover anchor1");
        let mut prev_db = SqlDb::empty();
        prev_db
            .load_from_paged_store(&prev_store)
            .expect("load anchor1");
        let n_prev = prev_db.exec(b"SELECT score FROM ext_0 WHERE id = 777", &mut out);
        assert_eq!(&out[..n_prev], b"score\n439\n");
    }

    #[test]
    fn multi_tuple_values_parser_rejects_malformed_inputs_and_preserves_batch_atomicity() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 512];

        // Malformed multi-tuple syntax edge cases:
        for bad in [
            b"INSERT INTO kv VALUES ".as_slice(),
            b"INSERT INTO kv VALUES ()".as_slice(),
            b"INSERT INTO kv VALUES ('a', '1', 1),".as_slice(),
            b"INSERT INTO kv VALUES ('a', '1', 1), ()".as_slice(),
            b"INSERT INTO kv VALUES (('a', '1', 1))".as_slice(),
            b"INSERT INTO kv VALUES ('a', '1', 1) ('b', '2', 2)".as_slice(),
            b"INSERT INTO kv VALUES ('a', '1', 1), ('b', '2'".as_slice(),
            b"INSERT INTO kv VALUES ('a', '1', 1), ('b', 'too-many', 2, 99)".as_slice(),
        ] {
            let pre_hash = db.state_hash();
            let n = db.exec(bad, &mut out);
            assert!(
                out[..n].starts_with(b"error:"),
                "malformed batch {bad:?} must fail, got {:?}",
                core::str::from_utf8(&out[..n])
            );
            assert_eq!(db.state_hash(), pre_hash, "failed batch {bad:?} mutated db");
        }

        // Batch undo-log overflow inside BEGIN must reject atomically without partial insertion!
        let n_beg = db.exec(b"BEGIN", &mut out);
        assert_eq!(&out[..n_beg], b"BEGIN OK\n");
        let pre_rows = db.total_rows();
        let n_over = db.exec(
            b"INSERT INTO kv VALUES ('u1','1',1),('u2','1',1),('u3','1',1),('u4','1',1),('u5','1',1),('u6','1',1),('u7','1',1),('u8','1',1),('u9','1',1)",
            &mut out,
        );
        assert!(out[..n_over].starts_with(b"error: transaction undo log full"));
        assert_eq!(db.total_rows(), pre_rows, "atomic batch must not leave partial rows");
        let _ = db.exec(b"ROLLBACK", &mut out);
    }

    #[test]
    fn state_hash_commits_secondary_indexes_and_normalizes_vault_rows() {
        let db0 = SqlDb::new();
        let mut db1 = SqlDb::new();
        let mut out = [0u8; 256];
        let n = db1.exec(b"CREATE INDEX idx_kv_k ON kv (k)", &mut out);
        assert_eq!(&out[..n], b"CREATE INDEX idx_kv_k OK\n");
        assert_ne!(
            db0.state_hash(),
            db1.state_hash(),
            "secondary index DDL must change SqlDb::state_hash()"
        );

        let mut sh0 = crate::shell::OsShell::with_seal_key([0x11; 32]);
        let mut sh1 = crate::shell::OsShell::with_seal_key([0x22; 32]);
        let mut s_out0 = [0u8; 256];
        let mut s_out1 = [0u8; 256];
        sh0.exec_line(b"vault set api_key secret1", 1, 0, 0, &mut s_out0);
        sh1.exec_line(b"vault set api_key secret1", 1, 0, 0, &mut s_out1);
        assert_eq!(
            sh0.db.state_hash(),
            sh1.db.state_hash(),
            "per-node hardware-sealed vault rows must hash canonically across Triad nodes"
        );
    }

    #[test]
    fn load_from_paged_store_preserves_budget_and_set_paged_mode_false_guards_overflow() {
        let mut db = SqlDb::new();
        db.set_paged_mode(true);
        db.set_paged_page_budget(Some(5));
        let mut store = crate::paged_store::PagedBlockStore::new();
        db.sync_to_paged_store(&mut store, 10).unwrap();
        db.load_from_paged_store(&store).unwrap();
        assert_eq!(
            db.paged_page_budget(),
            Some(5),
            "load_from_paged_store must preserve configured paged_page_budget"
        );

        let mut out = [0u8; 128];
        for t in 0..3 {
            let ddl = alloc::format!("CREATE TABLE extra_{t} (id INT)");
            let n = db.exec(ddl.as_bytes(), &mut out);
            assert!(out[..n].ends_with(b" OK\n"));
        }
        // 5 active tables (> inline cap of 4): set_paged_mode(false) must refuse to drop overflow state.
        db.set_paged_mode(false);
        assert!(db.is_paged_mode());
    }

    #[test]
    fn multiline_sql_queries_and_insert_values_newline_succeed() {
        let mut db = SqlDb::new();
        let mut out = [0u8; 256];
        let n_ins = db.exec(
            b"INSERT INTO kv VALUES\n('nl_key', 'nl_val', 7)",
            &mut out,
        );
        assert_eq!(&out[..n_ins], b"INSERT 1\n");

        let n_upd = db.exec(
            b"UPDATE kv\nSET v = 'nl_val2'\r\nWHERE k = 'nl_key'",
            &mut out,
        );
        assert_eq!(&out[..n_upd], b"UPDATE 1\n");

        let n_sel = db.exec(
            b"SELECT v, rev\nFROM kv\nWHERE k = 'nl_key'\nLIMIT 1",
            &mut out,
        );
        assert_eq!(&out[..n_sel], b"v|rev\nnl_val2|7\n");
    }
}
