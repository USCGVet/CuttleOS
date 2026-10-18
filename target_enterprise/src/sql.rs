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
//! - Deterministic 8-sector (`4 KiB`) AHCI partition serialization (`CTTLSQL1`)
//!   protected by a chained keyed `HMAC-SHA256` tag.

#![allow(clippy::needless_range_loop)]

use crate::durable_seal::{seal_bytes_keyed, DURABLE_DIGEST_LEN};

/// Maximum number of relational tables in a [`SqlDb`] instance.
pub const SQL_MAX_TABLES: usize = 4;
/// Maximum number of columns per table.
pub const SQL_MAX_COLS: usize = 4;
/// Maximum number of rows per table (`256` total rows across [`SQL_MAX_TABLES`]).
pub const SQL_MAX_ROWS: usize = 64;
/// Maximum byte length of a table or column identifier.
pub const SQL_IDENT_LEN: usize = 16;
/// Maximum byte length of a `TEXT` cell value.
pub const SQL_TEXT_LEN: usize = 24;
/// Number of 512-byte disk sectors used to persist [`SqlDb`] (`4 KiB`).
pub const SQL_PART_SECTORS: usize = 8;
/// 8-byte superblock magic for the persistent SQL partition (`CTTLSQL1`).
pub const SQL_PART_MAGIC: &[u8; 8] = b"CTTLSQL1";
/// Sentinel value for [`SqlTable::indexed_col`] when no secondary index is defined.
pub const SQL_NO_INDEX: u8 = 0xFF;

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

    /// Construct a `TEXT` value from a byte slice (truncated to [`SQL_TEXT_LEN`]).
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
    /// Cell values indexed by column position.
    pub cells: [SqlVal; SQL_MAX_COLS],
}

impl SqlRow {
    /// Construct an unoccupied row slot.
    pub const fn empty() -> Self {
        Self {
            used: false,
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

/// Fixed-capacity relational table with optional secondary hash index.
#[derive(Copy, Clone, Debug)]
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
    /// Fixed-capacity row storage (`64` rows per table).
    pub rows: [SqlRow; SQL_MAX_ROWS],
    /// Indexed column index (`0..col_count`), or [`SQL_NO_INDEX`] (`0xFF`) when unindexed.
    pub indexed_col: u8,
    /// Secondary index identifier bytes.
    pub index_name: [u8; SQL_IDENT_LEN],
    /// Valid length of `index_name`.
    pub index_name_len: u8,
    /// Per-row 64-bit FNV-1a hash fingerprint for `cells[indexed_col]`.
    pub index_hashes: [u64; SQL_MAX_ROWS],
}

impl SqlTable {
    /// Construct an empty unused table slot.
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
        let mut i = 0usize;
        while i < SQL_MAX_ROWS {
            if self.rows[i].used {
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

    /// Rebuild `index_hashes` for all occupied rows when `indexed_col` is active.
    pub fn rebuild_index(&mut self) {
        let c = self.indexed_col as usize;
        if c >= self.col_count as usize {
            self.index_hashes = [0u64; SQL_MAX_ROWS];
            return;
        }
        let mut r = 0usize;
        while r < SQL_MAX_ROWS {
            if self.rows[r].used {
                self.index_hashes[r] = hash_sql_val(&self.rows[r].cells[c]);
            } else {
                self.index_hashes[r] = 0;
            }
            r += 1;
        }
    }
}

/// Maximum number of row mutations tracked in an active `BEGIN ... ROLLBACK` transaction.
pub const SQL_TX_UNDO_CAP: usize = 8;

/// Embedded zero-allocation SQL database engine.
#[derive(Copy, Clone, Debug)]
pub struct SqlDb {
    /// Table slots.
    pub tables: [SqlTable; SQL_MAX_TABLES],
    /// Monotonic counter of mutating SQL statements executed.
    pub tx_seq: u64,
    /// Monotonic counter of secondary-index-accelerated `WHERE <col> = <val>` lookups.
    pub idx_hits: u64,
    /// Whether an explicit `BEGIN` transaction is currently open.
    pub tx_active: bool,
    /// Number of row-level undo records captured in the current transaction (`0..=SQL_TX_UNDO_CAP`).
    pub tx_undo_len: u8,
    /// Saved `tx_seq` prior to `BEGIN`, restored on `ROLLBACK`.
    pub tx_undo_seq: u64,
    /// Table index for each undo slot.
    pub tx_undo_table: [u8; SQL_TX_UNDO_CAP],
    /// Row index for each undo slot.
    pub tx_undo_row: [u8; SQL_TX_UNDO_CAP],
    /// Pre-transaction row snapshot for each undo slot.
    pub tx_undo_prev: [SqlRow; SQL_TX_UNDO_CAP],
}

impl Default for SqlDb {
    fn default() -> Self {
        Self::new()
    }
}

impl SqlDb {
    /// Construct an empty unseeded SQL database.
    pub const fn empty() -> Self {
        Self {
            tables: [SqlTable::empty(); SQL_MAX_TABLES],
            tx_seq: 0,
            idx_hits: 0,
            tx_active: false,
            tx_undo_len: 0,
            tx_undo_seq: 0,
            tx_undo_table: [0u8; SQL_TX_UNDO_CAP],
            tx_undo_row: [0u8; SQL_TX_UNDO_CAP],
            tx_undo_prev: [SqlRow::empty(); SQL_TX_UNDO_CAP],
        }
    }

    fn record_row_undo(&mut self, t_idx: usize, r_idx: usize) {
        if !self.tx_active {
            return;
        }
        let len = self.tx_undo_len as usize;
        let mut i = 0usize;
        while i < len {
            if (self.tx_undo_table[i] as usize) == t_idx && (self.tx_undo_row[i] as usize) == r_idx
            {
                return;
            }
            i += 1;
        }
        if len < SQL_TX_UNDO_CAP {
            self.tx_undo_table[len] = t_idx as u8;
            self.tx_undo_row[len] = r_idx as u8;
            self.tx_undo_prev[len] = self.tables[t_idx].rows[r_idx];
            self.tx_undo_len = (len + 1) as u8;
        }
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
        let mut i = 0usize;
        while i < SQL_MAX_TABLES {
            if self.tables[i].used {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Total number of rows across all active tables.
    pub fn total_rows(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0usize;
        while i < SQL_MAX_TABLES {
            if self.tables[i].used {
                n += self.tables[i].row_count();
            }
            i += 1;
        }
        n
    }

    /// Compute a deterministic 64-bit FNV-1a cryptographic state fingerprint across all
    /// active tables, columns, secondary indexes, and live rows for 2-of-3 Triad TMR voting.
    pub fn state_hash(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mix_byte = |acc: u64, b: u8| -> u64 { (acc ^ (b as u64)).wrapping_mul(0x0100_0000_01b3) };
        let mut t_idx = 0usize;
        while t_idx < SQL_MAX_TABLES {
            let tbl = &self.tables[t_idx];
            if tbl.used {
                h = mix_byte(h, 0xA5);
                let mut i = 0usize;
                while i < (tbl.name_len as usize) {
                    h = mix_byte(h, tbl.name[i]);
                    i += 1;
                }
                h = mix_byte(h, tbl.col_count);
                let mut r_idx = 0usize;
                while r_idx < SQL_MAX_ROWS {
                    let row = &tbl.rows[r_idx];
                    if row.used {
                        h = mix_byte(h, 0x5A);
                        let mut c_idx = 0usize;
                        while c_idx < (tbl.col_count as usize) {
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
                                    let mut ti = 0usize;
                                    while ti < (*tl as usize) {
                                        h = mix_byte(h, tb[ti]);
                                        ti += 1;
                                    }
                                }
                            }
                            c_idx += 1;
                        }
                    }
                    r_idx += 1;
                }
            }
            t_idx += 1;
        }
        h
    }

    /// Return `true` if `query` is strictly read-only (`SELECT`, `.tables`, `.schema`, `SHOW`, `DESCRIBE`).
    pub fn is_readonly_query(query: &[u8]) -> bool {
        let q = trim_sql(query);
        if q.is_empty() {
            return true;
        }
        if q.starts_with(b".") {
            return true;
        }
        let (kw, _) = next_token(q);
        eq_ignore_ascii_case(kw, b"SELECT")
            || eq_ignore_ascii_case(kw, b"SHOW")
            || eq_ignore_ascii_case(kw, b"DESCRIBE")
    }

    /// Execute a SQL statement or meta-command and format the output into `out`.
    /// Returns the number of bytes written to `out`.
    pub fn exec(&mut self, query: &[u8], out: &mut [u8]) -> usize {
        let q = trim_sql(query);
        if q.is_empty() {
            return copy_str(b"error: empty SQL query\n", out);
        }
        if eq_ignore_ascii_case(q, b".tables") || eq_ignore_ascii_case(q, b"SHOW TABLES") {
            return self.exec_show_tables(out);
        }
        if q.starts_with(b".schema") || starts_with_ignore_case(q, b"DESCRIBE") {
            let (_, rest) = next_token(q);
            return self.exec_schema(trim_sql(rest), out);
        }
        let (kw, rest) = next_token(q);
        if eq_ignore_ascii_case(kw, b"BEGIN") {
            self.tx_active = true;
            self.tx_undo_len = 0;
            self.tx_undo_seq = self.tx_seq;
            copy_str(b"BEGIN OK\n", out)
        } else if eq_ignore_ascii_case(kw, b"COMMIT") {
            if !self.tx_active {
                return copy_str(b"error: no transaction active\n", out);
            }
            self.tx_active = false;
            self.tx_undo_len = 0;
            copy_str(b"COMMIT OK\n", out)
        } else if eq_ignore_ascii_case(kw, b"ROLLBACK") {
            if !self.tx_active {
                return copy_str(b"error: no transaction active\n", out);
            }
            let mut k = self.tx_undo_len as usize;
            while k > 0 {
                k -= 1;
                let t = self.tx_undo_table[k] as usize;
                let r = self.tx_undo_row[k] as usize;
                if t < SQL_MAX_TABLES && r < SQL_MAX_ROWS {
                    self.tables[t].rows[r] = self.tx_undo_prev[k];
                }
            }
            let mut t = 0usize;
            while t < SQL_MAX_TABLES {
                if self.tables[t].used {
                    self.tables[t].rebuild_index();
                }
                t += 1;
            }
            self.tx_seq = self.tx_undo_seq;
            self.tx_active = false;
            self.tx_undo_len = 0;
            copy_str(b"ROLLBACK OK\n", out)
        } else if eq_ignore_ascii_case(kw, b"CREATE") {
            self.exec_create(rest, out)
        } else if eq_ignore_ascii_case(kw, b"DROP") {
            self.exec_drop(rest, out)
        } else if eq_ignore_ascii_case(kw, b"INSERT") {
            self.exec_insert(rest, false, out)
        } else if eq_ignore_ascii_case(kw, b"REPLACE") {
            self.exec_insert(rest, true, out)
        } else if eq_ignore_ascii_case(kw, b"SELECT") {
            self.exec_select(rest, out)
        } else if eq_ignore_ascii_case(kw, b"UPDATE") {
            self.exec_update(rest, out)
        } else if eq_ignore_ascii_case(kw, b"DELETE") {
            self.exec_delete(rest, out)
        } else {
            copy_str(b"error: unsupported SQL statement\n", out)
        }
    }

    fn find_table(&self, name: &[u8]) -> Option<usize> {
        let mut i = 0usize;
        while i < SQL_MAX_TABLES {
            if self.tables[i].used && eq_ignore_ascii_case(self.tables[i].name_bytes(), name) {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    fn exec_show_tables(&self, out: &mut [u8]) -> usize {
        let mut pos = 0usize;
        let mut i = 0usize;
        let mut count = 0usize;
        while i < SQL_MAX_TABLES {
            if self.tables[i].used {
                pos += append_bytes(out, pos, self.tables[i].name_bytes());
                pos += append_bytes(out, pos, b" (rows=");
                pos += append_u64(out, pos, self.tables[i].row_count() as u64);
                pos += append_bytes(out, pos, b", cols=");
                pos += append_u64(out, pos, self.tables[i].col_count as u64);
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
        let mut i = 0usize;
        let mut found = false;
        while i < SQL_MAX_TABLES {
            let t = &self.tables[i];
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
        if rparen <= lparen {
            return copy_str(b"error: malformed column list in CREATE TABLE\n", out);
        }
        let tname = trim_sql(&after_table[..lparen]);
        if !is_valid_ident(tname) {
            return copy_str(b"error: invalid table name\n", out);
        }
        if self.find_table(tname).is_some() {
            return copy_str(b"error: table already exists\n", out);
        }
        let mut free_slot = None;
        let mut i = 0usize;
        while i < SQL_MAX_TABLES {
            if !self.tables[i].used {
                free_slot = Some(i);
                break;
            }
            i += 1;
        }
        let Some(t_idx) = free_slot else {
            return copy_str(b"error: maximum table limit reached\n", out);
        };

        let cols_raw = &after_table[lparen + 1..rparen];
        let mut table = SqlTable::empty();
        table.used = true;
        table.name[..tname.len()].copy_from_slice(tname);
        table.name_len = tname.len() as u8;

        let mut cursor = cols_raw;
        while !cursor.is_empty() {
            let (col_def, next_cursor) = split_comma(cursor);
            cursor = next_cursor;
            let col_def = trim_sql(col_def);
            if col_def.is_empty() {
                continue;
            }
            if table.col_count as usize >= SQL_MAX_COLS {
                return copy_str(b"error: too many columns (max 4)\n", out);
            }
            let (cname, ctype_raw) = next_token(col_def);
            let (ctype_tok, _) = next_token(ctype_raw);
            if !is_valid_ident(cname) {
                return copy_str(b"error: invalid column name\n", out);
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
            let idx = table.col_count as usize;
            table.cols[idx].name[..cname.len()].copy_from_slice(cname);
            table.cols[idx].name_len = cname.len() as u8;
            table.cols[idx].col_type = ctype;
            table.col_count += 1;
        }
        if table.col_count == 0 {
            return copy_str(b"error: CREATE TABLE requires at least 1 column\n", out);
        }
        self.tables[t_idx] = table;
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
        if rparen <= lparen {
            return copy_str(b"error: malformed column in CREATE INDEX\n", out);
        }
        let tname = trim_sql(&after_on[..lparen]);
        let cname = trim_sql(&after_on[lparen + 1..rparen]);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        let Some(c_idx) = self.tables[t_idx].find_col(cname) else {
            return copy_str(b"error: column not found in CREATE INDEX\n", out);
        };
        self.tables[t_idx].indexed_col = c_idx as u8;
        self.tables[t_idx].index_name = [0u8; SQL_IDENT_LEN];
        self.tables[t_idx].index_name[..idx_name.len()].copy_from_slice(idx_name);
        self.tables[t_idx].index_name_len = idx_name.len() as u8;
        self.tables[t_idx].rebuild_index();
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
            let mut i = 0usize;
            while i < SQL_MAX_TABLES {
                if self.tables[i].used
                    && self.tables[i].index_name_len > 0
                    && eq_ignore_ascii_case(self.tables[i].index_name_bytes(), idx_name)
                {
                    self.tables[i].indexed_col = SQL_NO_INDEX;
                    self.tables[i].index_name = [0u8; SQL_IDENT_LEN];
                    self.tables[i].index_name_len = 0;
                    self.tables[i].index_hashes = [0u64; SQL_MAX_ROWS];
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
        let (tname, _) = next_token(after_kind);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };
        self.tables[t_idx] = SqlTable::empty();
        self.tx_seq = self.tx_seq.wrapping_add(1);
        let mut pos = 0usize;
        pos += append_bytes(out, pos, b"DROP TABLE ");
        pos += append_bytes(out, pos, tname);
        pos += append_bytes(out, pos, b" OK\n");
        pos
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
        let (kw_values, after_values) = next_token(after_tname);
        if !eq_ignore_ascii_case(kw_values, b"VALUES") {
            return copy_str(b"error: expected VALUES (...)\n", out);
        }
        let after_values = trim_sql(after_values);
        let Some(lparen) = find_byte(after_values, b'(') else {
            return copy_str(b"error: missing '(' after VALUES\n", out);
        };
        let Some(rparen) = rfind_byte(after_values, b')') else {
            return copy_str(b"error: missing ')' after VALUES\n", out);
        };
        if rparen <= lparen {
            return copy_str(b"error: malformed VALUES list\n", out);
        }

        let col_count = self.tables[t_idx].col_count as usize;
        let mut row = SqlRow::empty();
        row.used = true;
        let mut val_idx = 0usize;
        let mut cursor = &after_values[lparen + 1..rparen];
        while !cursor.is_empty() {
            let (val_raw, next_cursor) = split_comma_respecting_quotes(cursor);
            cursor = next_cursor;
            let val_raw = trim_sql(val_raw);
            if val_raw.is_empty() {
                continue;
            }
            if val_idx >= col_count {
                return copy_str(b"error: too many values for table schema\n", out);
            }
            let expected_type = self.tables[t_idx].cols[val_idx].col_type;
            let Some(parsed) = parse_literal(val_raw, expected_type) else {
                return copy_str(b"error: type mismatch in VALUES literal\n", out);
            };
            row.cells[val_idx] = parsed;
            val_idx += 1;
        }
        if val_idx != col_count {
            return copy_str(b"error: column count mismatch in VALUES\n", out);
        }

        if is_replace && col_count > 0 {
            let mut r = 0usize;
            while r < SQL_MAX_ROWS {
                if self.tables[t_idx].rows[r].used
                    && self.tables[t_idx].rows[r].cells[0].compare(CmpOp::Eq, &row.cells[0])
                {
                    self.record_row_undo(t_idx, r);
                    let idx_col = self.tables[t_idx].indexed_col as usize;
                    if idx_col < col_count {
                        self.tables[t_idx].index_hashes[r] = hash_sql_val(&row.cells[idx_col]);
                    }
                    self.tables[t_idx].rows[r] = row;
                    self.tx_seq = self.tx_seq.wrapping_add(1);
                    return copy_str(b"REPLACE 1\n", out);
                }
                r += 1;
            }
        }

        let mut free_row = None;
        let mut r = 0usize;
        while r < SQL_MAX_ROWS {
            if !self.tables[t_idx].rows[r].used {
                free_row = Some(r);
                break;
            }
            r += 1;
        }
        let Some(r_idx) = free_row else {
            return copy_str(b"error: table row capacity full (max 64)\n", out);
        };
        self.record_row_undo(t_idx, r_idx);
        let idx_col = self.tables[t_idx].indexed_col as usize;
        if idx_col < col_count {
            self.tables[t_idx].index_hashes[r_idx] = hash_sql_val(&row.cells[idx_col]);
        }
        self.tables[t_idx].rows[r_idx] = row;
        self.tx_seq = self.tx_seq.wrapping_add(1);
        if is_replace {
            copy_str(b"REPLACE 1\n", out)
        } else {
            copy_str(b"INSERT 1\n", out)
        }
    }

    fn exec_select(&mut self, rest: &[u8], out: &mut [u8]) -> usize {
        let Some((proj_raw, after_from)) = split_keyword_ignore_case(rest, b"FROM") else {
            return copy_str(b"error: SELECT missing FROM clause\n", out);
        };
        let proj = trim_sql(proj_raw);
        let (tname, mut clauses) = next_token(after_from);
        let Some(t_idx) = self.find_table(tname) else {
            return copy_str(b"error: table not found\n", out);
        };

        // Parse optional LIMIT <n> at tail.
        let mut limit = SQL_MAX_ROWS;
        if let Some((before_lim, lim_str)) = split_keyword_ignore_case(clauses, b"LIMIT") {
            clauses = before_lim;
            let (lim_tok, _) = next_token(lim_str);
            if let Some(n) = parse_i64(lim_tok) {
                if n >= 0 {
                    limit = (n as usize).min(SQL_MAX_ROWS);
                }
            }
        }

        // Parse optional ORDER BY <col> [ASC|DESC].
        let mut order_col: Option<(usize, bool)> = None;
        if let Some((before_ord, ord_str)) = split_keyword_ignore_case(clauses, b"ORDER") {
            clauses = before_ord;
            let (kw_by, after_by) = next_token(ord_str);
            if eq_ignore_ascii_case(kw_by, b"BY") {
                let (ocol, dir_raw) = next_token(after_by);
                let (dir_tok, _) = next_token(dir_raw);
                let Some(c_idx) = self.tables[t_idx].find_col(ocol) else {
                    return copy_str(b"error: unknown column in ORDER BY\n", out);
                };
                let desc = eq_ignore_ascii_case(dir_tok, b"DESC");
                order_col = Some((c_idx, desc));
            }
        }

        // Parse optional WHERE <col> <op> <val> [AND|OR <col2> <op2> <val2>].
        let mut filter: Option<WhereFilter> = None;
        let clauses = trim_sql(clauses);
        if !clauses.is_empty() {
            let (kw_where, cond_raw) = next_token(clauses);
            if !eq_ignore_ascii_case(kw_where, b"WHERE") {
                return copy_str(b"error: unexpected clause after FROM\n", out);
            }
            let Some(parsed_cond) = parse_where_filter(&self.tables[t_idx], cond_raw) else {
                return copy_str(b"error: malformed WHERE condition\n", out);
            };
            filter = Some(parsed_cond);
        }

        // Check if secondary hash index can accelerate an equality WHERE clause.
        let indexed_eq_hash = filter
            .as_ref()
            .and_then(|f| f.single_indexed_eq(self.tables[t_idx].indexed_col as usize));
        if indexed_eq_hash.is_some() {
            self.idx_hits = self.idx_hits.wrapping_add(1);
        }

        let table = &self.tables[t_idx];

        // Collect matching row indices.
        let mut matched = [0usize; SQL_MAX_ROWS];
        let mut mcount = 0usize;
        let mut r = 0usize;
        while r < SQL_MAX_ROWS {
            if table.rows[r].used {
                if let Some(h) = indexed_eq_hash {
                    if table.index_hashes[r] != h {
                        r += 1;
                        continue;
                    }
                }
                let pass = match &filter {
                    Some(f) => f.eval(&table.rows[r]),
                    None => true,
                };
                if pass {
                    matched[mcount] = r;
                    mcount += 1;
                }
            }
            r += 1;
        }

        // Sort matched rows if ORDER BY is present.
        if let Some((c_idx, desc)) = order_col {
            let mut i = 0usize;
            while i < mcount {
                let mut j = i + 1;
                while j < mcount {
                    let a = &table.rows[matched[i]].cells[c_idx];
                    let b = &table.rows[matched[j]].cells[c_idx];
                    let swap = if desc {
                        a.compare(CmpOp::Lt, b)
                    } else {
                        a.compare(CmpOp::Gt, b)
                    };
                    if swap {
                        matched.swap(i, j);
                    }
                    j += 1;
                }
                i += 1;
            }
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
            let Some(c_idx) = table.find_col(agg_col_name) else {
                return copy_str(b"error: unknown column in aggregate\n", out);
            };
            if table.cols[c_idx].col_type != SqlType::Int {
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
                if let SqlVal::Int(v) = table.rows[matched[k]].cells[c_idx] {
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
            while proj_count < table.col_count as usize {
                proj_cols[proj_count] = proj_count;
                proj_count += 1;
            }
        } else {
            let mut cursor = proj;
            while !cursor.is_empty() {
                let (cname, next_cursor) = split_comma(cursor);
                cursor = next_cursor;
                let cname = trim_sql(cname);
                if cname.is_empty() {
                    continue;
                }
                let Some(c_idx) = table.find_col(cname) else {
                    return copy_str(b"error: unknown column in SELECT projection\n", out);
                };
                if proj_count < SQL_MAX_COLS {
                    proj_cols[proj_count] = c_idx;
                    proj_count += 1;
                }
            }
        }

        // Format header + rows.
        let mut pos = 0usize;
        let mut c = 0usize;
        while c < proj_count {
            if c > 0 {
                pos += append_bytes(out, pos, b"|");
            }
            pos += append_bytes(out, pos, table.cols[proj_cols[c]].name_bytes());
            c += 1;
        }
        pos += append_bytes(out, pos, b"\n");

        let emit_rows = mcount.min(limit);
        let mut m = 0usize;
        while m < emit_rows {
            let row = &table.rows[matched[m]];
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
        let Some(set_col_idx) = self.tables[t_idx].find_col(set_col_name) else {
            return copy_str(b"error: unknown column in SET clause\n", out);
        };
        let set_col_type = self.tables[t_idx].cols[set_col_idx].col_type;
        let Some(new_val) = parse_literal(set_val_raw, set_col_type) else {
            return copy_str(b"error: invalid value in SET clause\n", out);
        };

        let filter = if let Some(w_raw) = where_clause {
            let Some(cond) = parse_where_filter(&self.tables[t_idx], w_raw) else {
                return copy_str(b"error: malformed WHERE condition\n", out);
            };
            Some(cond)
        } else {
            None
        };

        let indexed_eq_hash = filter
            .as_ref()
            .and_then(|f| f.single_indexed_eq(self.tables[t_idx].indexed_col as usize));
        if indexed_eq_hash.is_some() {
            self.idx_hits = self.idx_hits.wrapping_add(1);
        }

        let mut updated = 0u64;
        let mut r = 0usize;
        while r < SQL_MAX_ROWS {
            if self.tables[t_idx].rows[r].used {
                if let Some(h) = indexed_eq_hash {
                    if self.tables[t_idx].index_hashes[r] != h {
                        r += 1;
                        continue;
                    }
                }
                let pass = match &filter {
                    Some(f) => f.eval(&self.tables[t_idx].rows[r]),
                    None => true,
                };
                if pass {
                    self.record_row_undo(t_idx, r);
                    self.tables[t_idx].rows[r].cells[set_col_idx] = new_val;
                    if self.tables[t_idx].indexed_col as usize == set_col_idx {
                        self.tables[t_idx].index_hashes[r] = hash_sql_val(&new_val);
                    }
                    updated += 1;
                }
            }
            r += 1;
        }
        if updated > 0 {
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
            let Some(cond) = parse_where_filter(&self.tables[t_idx], cond_raw) else {
                return copy_str(b"error: malformed WHERE condition\n", out);
            };
            Some(cond)
        } else {
            None
        };

        let indexed_eq_hash = filter
            .as_ref()
            .and_then(|f| f.single_indexed_eq(self.tables[t_idx].indexed_col as usize));
        if indexed_eq_hash.is_some() {
            self.idx_hits = self.idx_hits.wrapping_add(1);
        }

        let mut deleted = 0u64;
        let mut r = 0usize;
        while r < SQL_MAX_ROWS {
            if self.tables[t_idx].rows[r].used {
                if let Some(h) = indexed_eq_hash {
                    if self.tables[t_idx].index_hashes[r] != h {
                        r += 1;
                        continue;
                    }
                }
                let pass = match &filter {
                    Some(f) => f.eval(&self.tables[t_idx].rows[r]),
                    None => true,
                };
                if pass {
                    self.record_row_undo(t_idx, r);
                    self.tables[t_idx].rows[r] = SqlRow::empty();
                    self.tables[t_idx].index_hashes[r] = 0;
                    deleted += 1;
                }
            }
            r += 1;
        }
        if deleted > 0 {
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
    pub fn save_partition(
        &self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &mut [[u8; 512]; SQL_PART_SECTORS],
    ) {
        let mut flat = [0u8; SQL_PART_SECTORS * 512];
        flat[0..8].copy_from_slice(SQL_PART_MAGIC);
        flat[8..16].copy_from_slice(&self.tx_seq.to_le_bytes());

        // Header layout:
        //   0..8   : SQL_PART_MAGIC ("CTTLSQL1")
        //   8..16  : tx_seq (u64 LE)
        //   16..18 : payload_len (u16 LE)
        //   18..20 : reserved (0)
        //   20..52 : 32-byte keyed HMAC-SHA256 tag over flat[0..20] || flat[52..4096]
        let mut pos = 52usize;
        let mut t = 0usize;
        while t < SQL_MAX_TABLES {
            let tbl = &self.tables[t];
            if !tbl.used {
                flat[pos] = 0;
                pos += 1;
                t += 1;
                continue;
            }
            let col_count = (tbl.col_count as usize).min(SQL_MAX_COLS);
            let has_idx = tbl.index_name_len > 0 && (tbl.indexed_col as usize) < col_count;
            let used_rows_hdr_pos = pos + 3;
            flat[pos] = if has_idx { 2 } else { 1 };
            flat[pos + 1] = tbl.name_len.min(SQL_IDENT_LEN as u8);
            flat[pos + 2] = col_count as u8;
            flat[pos + 3] = 0;
            pos += 4;
            flat[pos..pos + SQL_IDENT_LEN].copy_from_slice(&tbl.name);
            pos += SQL_IDENT_LEN;

            let mut c = 0usize;
            while c < col_count {
                flat[pos] = tbl.cols[c].name_len.min(SQL_IDENT_LEN as u8);
                flat[pos + 1] = tbl.cols[c].col_type as u8;
                pos += 2;
                flat[pos..pos + SQL_IDENT_LEN].copy_from_slice(&tbl.cols[c].name);
                pos += SQL_IDENT_LEN;
                c += 1;
            }

            if has_idx {
                let ilen = (tbl.index_name_len as usize).min(SQL_IDENT_LEN);
                flat[pos] = tbl.indexed_col;
                flat[pos + 1] = ilen as u8;
                flat[pos + 2..pos + 2 + ilen].copy_from_slice(&tbl.index_name[..ilen]);
                pos += 2 + ilen;
            }

            let mut written_rows = 0u8;
            let mut r2 = 0usize;
            while r2 < SQL_MAX_ROWS {
                let row = &tbl.rows[r2];
                if row.used {
                    // Compute exact serialized byte length of this row first.
                    let mut row_bytes = 0usize;
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
                    // Reserve 8 bytes at the end of `flat` so remaining table headers always fit.
                    if pos + row_bytes + 8 > flat.len() {
                        break;
                    }
                    let mut rc = 0usize;
                    while rc < col_count {
                        match row.cells[rc] {
                            SqlVal::Int(v) => {
                                if v >= (i16::MIN as i64) && v <= (i16::MAX as i64) {
                                    flat[pos] = 3; // compact i16 cell tag
                                    flat[pos + 1..pos + 3]
                                        .copy_from_slice(&(v as i16).to_le_bytes());
                                    pos += 3;
                                } else {
                                    flat[pos] = SqlType::Int as u8;
                                    flat[pos + 1..pos + 9].copy_from_slice(&v.to_le_bytes());
                                    pos += 9;
                                }
                            }
                            SqlVal::Text(buf, len) => {
                                let l = (len as usize).min(SQL_TEXT_LEN);
                                flat[pos] = SqlType::Text as u8;
                                flat[pos + 1] = l as u8;
                                flat[pos + 2..pos + 2 + l].copy_from_slice(&buf[..l]);
                                pos += 2 + l;
                            }
                        }
                        rc += 1;
                    }
                    written_rows = written_rows.saturating_add(1);
                }
                r2 += 1;
            }
            flat[used_rows_hdr_pos] = written_rows;
            t += 1;
        }

        let payload_len = pos - 52;
        flat[16..18].copy_from_slice(&(payload_len as u16).to_le_bytes());

        // Compute keyed HMAC-SHA256 over header metadata (0..20) and the full remaining partition (52..4096).
        let rest_len = flat.len() - 52;
        let mut mac_input = [0u8; SQL_PART_SECTORS * 512];
        mac_input[0..20].copy_from_slice(&flat[0..20]);
        mac_input[20..20 + rest_len].copy_from_slice(&flat[52..]);
        let mut tag = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(key, &mac_input[..20 + rest_len], &mut tag);
        flat[20..52].copy_from_slice(&tag);

        let mut s = 0usize;
        while s < SQL_PART_SECTORS {
            sectors[s].copy_from_slice(&flat[s * 512..(s + 1) * 512]);
            s += 1;
        }
    }

    /// Restore the database from an 8-sector (`4 KiB`) partition image after verifying
    /// the `CTTLSQL1` magic and constant-time keyed `HMAC-SHA256` tag.
    pub fn load_partition(
        &mut self,
        key: &[u8; DURABLE_DIGEST_LEN],
        sectors: &[[u8; 512]; SQL_PART_SECTORS],
    ) -> bool {
        let mut flat = [0u8; SQL_PART_SECTORS * 512];
        let mut s = 0usize;
        while s < SQL_PART_SECTORS {
            flat[s * 512..(s + 1) * 512].copy_from_slice(&sectors[s]);
            s += 1;
        }
        if &flat[0..8] != SQL_PART_MAGIC {
            return false;
        }
        let payload_len = u16::from_le_bytes([flat[16], flat[17]]) as usize;
        if 52 + payload_len > flat.len() {
            return false;
        }
        let total_pos = 52 + payload_len;

        let rest_len = flat.len() - 52;
        let mut mac_input = [0u8; SQL_PART_SECTORS * 512];
        mac_input[0..20].copy_from_slice(&flat[0..20]);
        mac_input[20..20 + rest_len].copy_from_slice(&flat[52..]);
        let mut expected_tag = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes_keyed(key, &mac_input[..20 + rest_len], &mut expected_tag);
        let mut diff = 0u8;
        let mut i = 0usize;
        while i < DURABLE_DIGEST_LEN {
            diff |= flat[20 + i] ^ expected_tag[i];
            i += 1;
        }
        if diff != 0 {
            return false;
        }

        let mut pos = 52usize;
        let mut parsed_tables = [SqlTable::empty(); SQL_MAX_TABLES];
        let mut t = 0usize;
        while t < SQL_MAX_TABLES {
            if pos >= total_pos {
                return false;
            }
            let marker = flat[pos];
            if marker == 0 {
                pos += 1;
                t += 1;
                continue;
            }
            if pos + 4 + SQL_IDENT_LEN > total_pos {
                return false;
            }
            let mut tbl = SqlTable::empty();
            tbl.used = true;
            tbl.name_len = flat[pos + 1].min(SQL_IDENT_LEN as u8);
            tbl.col_count = flat[pos + 2].min(SQL_MAX_COLS as u8);
            let used_rows = (flat[pos + 3] as usize).min(SQL_MAX_ROWS);
            pos += 4;
            tbl.name.copy_from_slice(&flat[pos..pos + SQL_IDENT_LEN]);
            pos += SQL_IDENT_LEN;

            let col_count = tbl.col_count as usize;
            let mut c = 0usize;
            while c < col_count {
                if pos + 2 + SQL_IDENT_LEN > total_pos {
                    return false;
                }
                tbl.cols[c].name_len = flat[pos].min(SQL_IDENT_LEN as u8);
                tbl.cols[c].col_type = if flat[pos + 1] == SqlType::Text as u8 {
                    SqlType::Text
                } else {
                    SqlType::Int
                };
                pos += 2;
                tbl.cols[c].name.copy_from_slice(&flat[pos..pos + SQL_IDENT_LEN]);
                pos += SQL_IDENT_LEN;
                c += 1;
            }

            if marker == 2 {
                if pos + 2 > total_pos {
                    return false;
                }
                let idx_col = flat[pos];
                let ilen = (flat[pos + 1] as usize).min(SQL_IDENT_LEN);
                if pos + 2 + ilen > total_pos || (idx_col as usize) >= col_count {
                    return false;
                }
                tbl.indexed_col = idx_col;
                tbl.index_name_len = ilen as u8;
                tbl.index_name[..ilen].copy_from_slice(&flat[pos + 2..pos + 2 + ilen]);
                pos += 2 + ilen;
            }

            let mut r = 0usize;
            while r < used_rows {
                tbl.rows[r].used = true;
                let mut rc = 0usize;
                while rc < col_count {
                    if pos >= total_pos {
                        return false;
                    }
                    let tag_b = flat[pos];
                    if tag_b == SqlType::Text as u8 {
                        if pos + 2 > total_pos {
                            return false;
                        }
                        let len = (flat[pos + 1] as usize).min(SQL_TEXT_LEN);
                        if pos + 2 + len > total_pos {
                            return false;
                        }
                        let mut buf = [0u8; SQL_TEXT_LEN];
                        buf[..len].copy_from_slice(&flat[pos + 2..pos + 2 + len]);
                        tbl.rows[r].cells[rc] = SqlVal::Text(buf, len as u8);
                        pos += 2 + len;
                    } else if tag_b == 3 {
                        if pos + 3 > total_pos {
                            return false;
                        }
                        let v16 = i16::from_le_bytes([flat[pos + 1], flat[pos + 2]]);
                        tbl.rows[r].cells[rc] = SqlVal::Int(v16 as i64);
                        pos += 3;
                    } else {
                        if pos + 9 > total_pos {
                            return false;
                        }
                        let mut vb = [0u8; 8];
                        vb.copy_from_slice(&flat[pos + 1..pos + 9]);
                        tbl.rows[r].cells[rc] = SqlVal::Int(i64::from_le_bytes(vb));
                        pos += 9;
                    }
                    rc += 1;
                }
                r += 1;
            }
            tbl.rebuild_index();
            parsed_tables[t] = tbl;
            t += 1;
        }
        if pos != total_pos {
            return false;
        }

        let mut tx_bytes = [0u8; 8];
        tx_bytes.copy_from_slice(&flat[8..16]);
        self.tx_seq = u64::from_le_bytes(tx_bytes);
        self.tables = parsed_tables;
        true
    }
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
    let mut in_quote = false;
    let mut i = 0usize;
    while i < s.len() {
        if s[i] == b'\'' {
            in_quote = !in_quote;
        } else if s[i] == b',' && !in_quote {
            return (&s[..i], &s[i + 1..]);
        }
        i += 1;
    }
    (s, &[])
}

fn split_keyword_ignore_case<'a>(s: &'a [u8], kw: &[u8]) -> Option<(&'a [u8], &'a [u8])> {
    let mut in_quote = false;
    let mut i = 0usize;
    while i + kw.len() <= s.len() {
        if s[i] == b'\'' {
            in_quote = !in_quote;
        }
        if !in_quote {
            let left_ok = i == 0 || s[i - 1] == b' ' || s[i - 1] == b'\t';
            let right_ok =
                i + kw.len() == s.len() || s[i + kw.len()] == b' ' || s[i + kw.len()] == b'\t';
            if left_ok && right_ok && eq_ignore_ascii_case(&s[i..i + kw.len()], kw) {
                return Some((&s[..i], &s[i + kw.len()..]));
            }
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
    let mut in_quote = false;
    let mut i = 0usize;
    while i < raw.len() {
        if raw[i] == b'\'' {
            in_quote = !in_quote;
        } else if !in_quote {
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
        }
        i += 1;
    }
    None
}

fn parse_literal(raw: &[u8], expected: SqlType) -> Option<SqlVal> {
    let raw = trim_sql(raw);
    match expected {
        SqlType::Int => parse_i64(raw).map(SqlVal::Int),
        SqlType::Text => {
            if raw.len() >= 2 && raw[0] == b'\'' && raw[raw.len() - 1] == b'\'' {
                let inner = &raw[1..raw.len() - 1];
                if find_byte(inner, b'\'').is_some() {
                    return None;
                }
                Some(SqlVal::from_text(inner))
            } else if raw.len() >= 2 && raw[0] == b'"' && raw[raw.len() - 1] == b'"' {
                let inner = &raw[1..raw.len() - 1];
                if find_byte(inner, b'"').is_some() {
                    return None;
                }
                Some(SqlVal::from_text(inner))
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
        written += append_u64(out, pos + written, val.unsigned_abs());
        written
    } else {
        append_u64(out, pos, val as u64)
    }
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
    }
}
