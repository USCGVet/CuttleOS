//! Per-uid disk quota wire codec — TASK-066.
//!
//! Fixed 32-byte records + a scanner + a check-on-write predicate.
//! No allocator, no disk I/O: the caller supplies a quotafile byte
//! buffer (or an in-memory table the banner builds).
//!
//! # On-wire record (32 bytes, little-endian)
//!
//! ```text
//!   0..4    uid          u32
//!   4..12   block_used   u64
//!  12..20   block_limit  u64
//!  20..24   inode_used   u32
//!  24..28   inode_limit  u32
//!  28..32   grace        u32   // Unix seconds grace expiry; 0 = hard
//! ```
//!
//! # Banner fixture
//!
//! Three live uids:
//! - 1000: under both limits
//! - 1001: `block_used == block_limit` → next block write rejected
//! - 1002: inode soft-over with expired grace → inode reject

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    Quota, QuotaError, QuotaRecord, QuotaReject, QUOTA_MAX_RECORDS, QUOTA_OFF_BLOCK_LIMIT,
    QUOTA_OFF_BLOCK_USED, QUOTA_OFF_GRACE, QUOTA_OFF_INODE_LIMIT, QUOTA_OFF_INODE_USED,
    QUOTA_OFF_UID, QUOTA_RECORD_LEN, QUOTA_UNLIMITED,
};

// ---------------------------------------------------------------------------
// LE helpers
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

// ---------------------------------------------------------------------------
// Free functions
// ---------------------------------------------------------------------------

/// Decode one 32-byte record.
pub fn parse_record_impl(buf: &[u8]) -> Result<QuotaRecord, QuotaError> {
    if buf.len() < QUOTA_RECORD_LEN {
        return Err(QuotaError::Truncated);
    }
    Ok(QuotaRecord {
        uid: read_u32_le(buf, QUOTA_OFF_UID),
        block_used: read_u64_le(buf, QUOTA_OFF_BLOCK_USED),
        block_limit: read_u64_le(buf, QUOTA_OFF_BLOCK_LIMIT),
        inode_used: read_u32_le(buf, QUOTA_OFF_INODE_USED),
        inode_limit: read_u32_le(buf, QUOTA_OFF_INODE_LIMIT),
        grace: read_u32_le(buf, QUOTA_OFF_GRACE),
    })
}

/// Encode one record into a 32-byte buffer.
pub fn encode_record_impl(rec: &QuotaRecord, out: &mut [u8]) -> Result<(), QuotaError> {
    if out.len() < QUOTA_RECORD_LEN {
        return Err(QuotaError::Truncated);
    }
    write_u32_le(out, QUOTA_OFF_UID, rec.uid);
    write_u64_le(out, QUOTA_OFF_BLOCK_USED, rec.block_used);
    write_u64_le(out, QUOTA_OFF_BLOCK_LIMIT, rec.block_limit);
    write_u32_le(out, QUOTA_OFF_INODE_USED, rec.inode_used);
    write_u32_le(out, QUOTA_OFF_INODE_LIMIT, rec.inode_limit);
    write_u32_le(out, QUOTA_OFF_GRACE, rec.grace);
    Ok(())
}

/// Walk every live record in `buf`.
pub fn scan_impl(buf: &[u8], sink: &mut dyn FnMut(QuotaRecord)) -> Result<usize, QuotaError> {
    if buf.len() % QUOTA_RECORD_LEN != 0 {
        return Err(QuotaError::BadLength);
    }
    let slots = buf.len() / QUOTA_RECORD_LEN;
    if slots > QUOTA_MAX_RECORDS {
        return Err(QuotaError::TableFull);
    }
    let mut count = 0usize;
    let mut i = 0usize;
    while i < slots {
        let off = i * QUOTA_RECORD_LEN;
        let rec = parse_record_impl(&buf[off..off + QUOTA_RECORD_LEN])?;
        if rec.uid != 0 {
            sink(rec);
            count += 1;
        }
        i += 1;
    }
    Ok(count)
}

/// First record matching `uid`.
pub fn lookup_impl(buf: &[u8], uid: u32) -> Result<QuotaRecord, QuotaError> {
    if uid == 0 {
        return Err(QuotaError::BadUid);
    }
    let mut found: Option<QuotaRecord> = None;
    scan_impl(buf, &mut |rec| {
        if found.is_none() && rec.uid == uid {
            found = Some(rec);
        }
    })?;
    found.ok_or(QuotaError::NotFound)
}

/// Check whether charging `block_delta` / `inode_delta` would succeed.
///
/// Rules (locked):
/// - Unlimited limits (`QUOTA_UNLIMITED` / `u32::MAX`) never reject.
/// - If `used + delta <= limit` → `Ok`.
/// - If exceed and (`grace == 0` or `grace <= now_unix`) → reject
///   with [`QuotaReject::BlockLimit`] / [`QuotaReject::InodeLimit`]
///   (block checked first).
/// - If exceed and `grace > now_unix` → still `Ok` (soft window).
pub fn check_write_impl(
    rec: &QuotaRecord,
    block_delta: u64,
    inode_delta: u32,
    now_unix: u32,
) -> Result<(), QuotaReject> {
    // Block check.
    if rec.block_limit != QUOTA_UNLIMITED {
        let new_blocks = rec.block_used.saturating_add(block_delta);
        if new_blocks > rec.block_limit {
            if grace_open(rec.grace, now_unix) {
                // Soft window still open — allow.
            } else if rec.grace != 0 {
                // Non-zero grace has lapsed.
                return Err(QuotaReject::GraceExpired);
            } else {
                return Err(QuotaReject::BlockLimit);
            }
        }
    }
    // Inode check.
    if rec.inode_limit != u32::MAX {
        let new_inodes = rec.inode_used.saturating_add(inode_delta);
        if new_inodes > rec.inode_limit {
            if grace_open(rec.grace, now_unix) {
                // Soft window still open — allow.
            } else if rec.grace != 0 {
                return Err(QuotaReject::GraceExpired);
            } else {
                return Err(QuotaReject::InodeLimit);
            }
        }
    }
    Ok(())
}

/// Grace is open when `grace > now_unix`. `grace == 0` means hard.
#[inline]
fn grace_open(grace: u32, now_unix: u32) -> bool {
    grace != 0 && grace > now_unix
}

// ---------------------------------------------------------------------------
// Trait impl
// ---------------------------------------------------------------------------

/// Stateless quota wire-codec impl.
pub struct QuotaImpl;

impl Quota for QuotaImpl {
    fn parse_record(buf: &[u8]) -> Result<QuotaRecord, QuotaError> {
        parse_record_impl(buf)
    }

    fn encode_record(rec: &QuotaRecord, out: &mut [u8]) -> Result<(), QuotaError> {
        encode_record_impl(rec, out)
    }

    fn scan(buf: &[u8], sink: &mut dyn FnMut(QuotaRecord)) -> Result<usize, QuotaError> {
        scan_impl(buf, sink)
    }

    fn lookup(buf: &[u8], uid: u32) -> Result<QuotaRecord, QuotaError> {
        lookup_impl(buf, uid)
    }

    fn check_write(
        rec: &QuotaRecord,
        block_delta: u64,
        inode_delta: u32,
        now_unix: u32,
    ) -> Result<(), QuotaReject> {
        check_write_impl(rec, block_delta, inode_delta, now_unix)
    }
}

// ---------------------------------------------------------------------------
// Fixed-capacity in-memory table (banner + tests)
// ---------------------------------------------------------------------------

/// In-memory quota table with fixed capacity.
pub struct QuotaTable {
    slots: [QuotaRecord; QUOTA_MAX_RECORDS],
    len: usize,
}

impl Default for QuotaTable {
    fn default() -> Self {
        Self::new()
    }
}

impl QuotaTable {
    /// Empty table.
    pub const fn new() -> Self {
        Self {
            slots: [QuotaRecord {
                uid: 0,
                block_used: 0,
                block_limit: 0,
                inode_used: 0,
                inode_limit: 0,
                grace: 0,
            }; QUOTA_MAX_RECORDS],
            len: 0,
        }
    }

    /// Insert or replace by uid. Returns false if full.
    pub fn upsert(&mut self, rec: QuotaRecord) -> bool {
        if rec.uid == 0 {
            return false;
        }
        let mut i = 0usize;
        while i < self.len {
            if self.slots[i].uid == rec.uid {
                self.slots[i] = rec;
                return true;
            }
            i += 1;
        }
        if self.len >= QUOTA_MAX_RECORDS {
            return false;
        }
        self.slots[self.len] = rec;
        self.len += 1;
        true
    }

    /// Number of live records.
    pub fn len(&self) -> usize {
        self.len
    }

    /// True if empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Lookup by uid.
    pub fn get(&self, uid: u32) -> Option<QuotaRecord> {
        let mut i = 0usize;
        while i < self.len {
            if self.slots[i].uid == uid {
                return Some(self.slots[i]);
            }
            i += 1;
        }
        None
    }

    /// Serialize live records into `out`. Returns bytes written.
    pub fn encode_all(&self, out: &mut [u8]) -> Result<usize, QuotaError> {
        let need = self.len * QUOTA_RECORD_LEN;
        if out.len() < need {
            return Err(QuotaError::Truncated);
        }
        let mut i = 0usize;
        while i < self.len {
            encode_record_impl(&self.slots[i], &mut out[i * QUOTA_RECORD_LEN..])?;
            i += 1;
        }
        Ok(need)
    }
}

// ---------------------------------------------------------------------------
// Banner fixture
// ---------------------------------------------------------------------------

/// Banner wall-clock used for grace checks.
pub const BANNER_NOW_UNIX: u32 = 1_700_000_000;

/// Build the locked 3-uid fixture into `out` (≥ 96 bytes).
/// Returns bytes written (96).
pub fn build_banner_fixture(out: &mut [u8]) -> Result<usize, QuotaError> {
    if out.len() < 3 * QUOTA_RECORD_LEN {
        return Err(QuotaError::Truncated);
    }
    // uid 1000: healthy
    let r0 = QuotaRecord {
        uid: 1000,
        block_used: 10,
        block_limit: 100,
        inode_used: 1,
        inode_limit: 50,
        grace: 0,
    };
    // uid 1001: at block limit — next +1 block rejected (grace=0 hard)
    let r1 = QuotaRecord {
        uid: 1001,
        block_used: 100,
        block_limit: 100,
        inode_used: 5,
        inode_limit: 50,
        grace: 0,
    };
    // uid 1002: over inode with expired grace
    let r2 = QuotaRecord {
        uid: 1002,
        block_used: 0,
        block_limit: QUOTA_UNLIMITED,
        inode_used: 10,
        inode_limit: 10,
        grace: BANNER_NOW_UNIX - 1, // expired
    };
    encode_record_impl(&r0, &mut out[0..QUOTA_RECORD_LEN])?;
    encode_record_impl(&r1, &mut out[QUOTA_RECORD_LEN..2 * QUOTA_RECORD_LEN])?;
    encode_record_impl(&r2, &mut out[2 * QUOTA_RECORD_LEN..3 * QUOTA_RECORD_LEN])?;
    Ok(3 * QUOTA_RECORD_LEN)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Quota;

    #[test]
    fn constants_locked() {
        assert_eq!(QUOTA_RECORD_LEN, 32);
        assert_eq!(QUOTA_MAX_RECORDS, 256);
        assert_eq!(QUOTA_OFF_UID, 0);
        assert_eq!(QUOTA_OFF_BLOCK_USED, 4);
        assert_eq!(QUOTA_OFF_BLOCK_LIMIT, 12);
        assert_eq!(QUOTA_OFF_INODE_USED, 20);
        assert_eq!(QUOTA_OFF_INODE_LIMIT, 24);
        assert_eq!(QUOTA_OFF_GRACE, 28);
        assert_eq!(QUOTA_UNLIMITED, u64::MAX);
    }

    #[test]
    fn record_round_trip() {
        let rec = QuotaRecord {
            uid: 42,
            block_used: 1_000,
            block_limit: 10_000,
            inode_used: 3,
            inode_limit: 100,
            grace: 1_700_000_000,
        };
        let mut buf = [0u8; 32];
        QuotaImpl::encode_record(&rec, &mut buf).unwrap();
        let back = QuotaImpl::parse_record(&buf).unwrap();
        assert_eq!(back, rec);
    }

    #[test]
    fn parse_rejects_truncated() {
        let buf = [0u8; 16];
        assert_eq!(
            QuotaImpl::parse_record(&buf),
            Err(QuotaError::Truncated)
        );
    }

    #[test]
    fn encode_rejects_truncated() {
        let rec = QuotaRecord {
            uid: 1,
            block_used: 0,
            block_limit: 1,
            inode_used: 0,
            inode_limit: 1,
            grace: 0,
        };
        let mut buf = [0u8; 8];
        assert_eq!(
            QuotaImpl::encode_record(&rec, &mut buf),
            Err(QuotaError::Truncated)
        );
    }

    #[test]
    fn scan_banner_fixture_three_records() {
        let mut buf = [0u8; 96];
        build_banner_fixture(&mut buf).unwrap();
        let mut count = 0usize;
        let n = QuotaImpl::scan(&buf, &mut |_| count += 1).unwrap();
        assert_eq!(n, 3);
        assert_eq!(count, 3);
    }

    #[test]
    fn scan_skips_zero_uid_slots() {
        let mut buf = [0u8; 64];
        // first slot empty, second live
        let rec = QuotaRecord {
            uid: 7,
            block_used: 0,
            block_limit: 10,
            inode_used: 0,
            inode_limit: 10,
            grace: 0,
        };
        QuotaImpl::encode_record(&rec, &mut buf[32..]).unwrap();
        let mut seen = 0u32;
        let n = QuotaImpl::scan(&buf, &mut |r| seen = r.uid).unwrap();
        assert_eq!(n, 1);
        assert_eq!(seen, 7);
    }

    #[test]
    fn scan_rejects_bad_length() {
        let buf = [0u8; 33];
        assert_eq!(QuotaImpl::scan(&buf, &mut |_| {}), Err(QuotaError::BadLength));
    }

    #[test]
    fn lookup_banner_uids() {
        let mut buf = [0u8; 96];
        build_banner_fixture(&mut buf).unwrap();
        let r = QuotaImpl::lookup(&buf, 1001).unwrap();
        assert_eq!(r.uid, 1001);
        assert_eq!(r.block_used, 100);
        assert_eq!(r.block_limit, 100);
        assert_eq!(
            QuotaImpl::lookup(&buf, 9999),
            Err(QuotaError::NotFound)
        );
    }

    #[test]
    fn lookup_rejects_uid_zero() {
        let buf = [0u8; 32];
        assert_eq!(QuotaImpl::lookup(&buf, 0), Err(QuotaError::BadUid));
    }

    #[test]
    fn check_write_under_limit_ok() {
        let rec = QuotaRecord {
            uid: 1,
            block_used: 10,
            block_limit: 100,
            inode_used: 1,
            inode_limit: 10,
            grace: 0,
        };
        assert!(QuotaImpl::check_write(&rec, 5, 1, 0).is_ok());
    }

    #[test]
    fn check_write_block_limit_hard() {
        let rec = QuotaRecord {
            uid: 1001,
            block_used: 100,
            block_limit: 100,
            inode_used: 0,
            inode_limit: 50,
            grace: 0,
        };
        assert_eq!(
            QuotaImpl::check_write(&rec, 1, 0, BANNER_NOW_UNIX),
            Err(QuotaReject::BlockLimit)
        );
    }

    #[test]
    fn check_write_inode_limit_hard() {
        let rec = QuotaRecord {
            uid: 2,
            block_used: 0,
            block_limit: QUOTA_UNLIMITED,
            inode_used: 10,
            inode_limit: 10,
            grace: 0,
        };
        assert_eq!(
            QuotaImpl::check_write(&rec, 0, 1, 0),
            Err(QuotaReject::InodeLimit)
        );
    }

    #[test]
    fn check_write_unlimited_never_rejects() {
        let rec = QuotaRecord {
            uid: 3,
            block_used: u64::MAX - 1,
            block_limit: QUOTA_UNLIMITED,
            inode_used: u32::MAX - 1,
            inode_limit: u32::MAX,
            grace: 0,
        };
        assert!(QuotaImpl::check_write(&rec, 100, 100, 0).is_ok());
    }

    #[test]
    fn check_write_soft_grace_still_open() {
        let rec = QuotaRecord {
            uid: 4,
            block_used: 100,
            block_limit: 100,
            inode_used: 0,
            inode_limit: 50,
            grace: BANNER_NOW_UNIX + 3600, // still open
        };
        // Would exceed blocks but grace open → Ok
        assert!(QuotaImpl::check_write(&rec, 1, 0, BANNER_NOW_UNIX).is_ok());
    }

    #[test]
    fn check_write_grace_expired_blocks() {
        let rec = QuotaRecord {
            uid: 5,
            block_used: 100,
            block_limit: 100,
            inode_used: 0,
            inode_limit: 50,
            grace: BANNER_NOW_UNIX - 1,
        };
        assert_eq!(
            QuotaImpl::check_write(&rec, 1, 0, BANNER_NOW_UNIX),
            Err(QuotaReject::GraceExpired)
        );
    }

    #[test]
    fn check_write_exact_limit_zero_delta_ok() {
        let rec = QuotaRecord {
            uid: 6,
            block_used: 100,
            block_limit: 100,
            inode_used: 10,
            inode_limit: 10,
            grace: 0,
        };
        assert!(QuotaImpl::check_write(&rec, 0, 0, 0).is_ok());
    }

    #[test]
    fn banner_fixture_reject_uid_1001_block() {
        let mut buf = [0u8; 96];
        build_banner_fixture(&mut buf).unwrap();
        let rec = QuotaImpl::lookup(&buf, 1001).unwrap();
        assert_eq!(
            QuotaImpl::check_write(&rec, 1, 0, BANNER_NOW_UNIX),
            Err(QuotaReject::BlockLimit)
        );
    }

    #[test]
    fn banner_fixture_uid_1000_allows() {
        let mut buf = [0u8; 96];
        build_banner_fixture(&mut buf).unwrap();
        let rec = QuotaImpl::lookup(&buf, 1000).unwrap();
        assert!(QuotaImpl::check_write(&rec, 1, 1, BANNER_NOW_UNIX).is_ok());
    }

    #[test]
    fn table_upsert_and_get() {
        let mut t = QuotaTable::new();
        assert!(t.is_empty());
        assert!(t.upsert(QuotaRecord {
            uid: 1,
            block_used: 0,
            block_limit: 10,
            inode_used: 0,
            inode_limit: 5,
            grace: 0,
        }));
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(1).unwrap().block_limit, 10);
        // replace
        assert!(t.upsert(QuotaRecord {
            uid: 1,
            block_used: 3,
            block_limit: 20,
            inode_used: 1,
            inode_limit: 5,
            grace: 0,
        }));
        assert_eq!(t.len(), 1);
        assert_eq!(t.get(1).unwrap().block_used, 3);
        assert_eq!(t.get(1).unwrap().block_limit, 20);
    }

    #[test]
    fn table_encode_all_round_trips() {
        let mut t = QuotaTable::new();
        t.upsert(QuotaRecord {
            uid: 10,
            block_used: 1,
            block_limit: 2,
            inode_used: 0,
            inode_limit: 1,
            grace: 0,
        });
        t.upsert(QuotaRecord {
            uid: 20,
            block_used: 5,
            block_limit: 50,
            inode_used: 2,
            inode_limit: 10,
            grace: 99,
        });
        let mut buf = [0u8; 64];
        let n = t.encode_all(&mut buf).unwrap();
        assert_eq!(n, 64);
        assert_eq!(QuotaImpl::lookup(&buf, 10).unwrap().block_limit, 2);
        assert_eq!(QuotaImpl::lookup(&buf, 20).unwrap().grace, 99);
    }

    #[test]
    fn free_functions_match_trait() {
        let mut buf = [0u8; 32];
        let rec = QuotaRecord {
            uid: 9,
            block_used: 1,
            block_limit: 2,
            inode_used: 0,
            inode_limit: 1,
            grace: 0,
        };
        encode_record_impl(&rec, &mut buf).unwrap();
        assert_eq!(
            parse_record_impl(&buf).unwrap(),
            QuotaImpl::parse_record(&buf).unwrap()
        );
    }

    #[test]
    fn reject_discriminants_locked() {
        assert_eq!(QuotaReject::BlockLimit as u8, 1);
        assert_eq!(QuotaReject::InodeLimit as u8, 2);
        assert_eq!(QuotaReject::GraceExpired as u8, 3);
    }

    #[test]
    fn block_checked_before_inode() {
        // Both would fail; block wins.
        let rec = QuotaRecord {
            uid: 8,
            block_used: 10,
            block_limit: 10,
            inode_used: 10,
            inode_limit: 10,
            grace: 0,
        };
        assert_eq!(
            QuotaImpl::check_write(&rec, 1, 1, 0),
            Err(QuotaReject::BlockLimit)
        );
    }

    #[test]
    fn saturating_add_does_not_wrap() {
        let rec = QuotaRecord {
            uid: 11,
            block_used: u64::MAX - 5,
            block_limit: u64::MAX - 1,
            inode_used: 0,
            inode_limit: 10,
            grace: 0,
        };
        // saturating add to MAX > limit
        assert_eq!(
            QuotaImpl::check_write(&rec, 100, 0, 0),
            Err(QuotaReject::BlockLimit)
        );
    }

    #[test]
    fn empty_scan() {
        let buf: [u8; 0] = [];
        let n = QuotaImpl::scan(&buf, &mut |_| {}).unwrap();
        assert_eq!(n, 0);
    }

    #[test]
    fn fixture_deterministic() {
        let mut a = [0u8; 96];
        let mut b = [0u8; 96];
        build_banner_fixture(&mut a).unwrap();
        build_banner_fixture(&mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn scan_table_full_guard() {
        // 257 records → TableFull
        let big = [0u8; (QUOTA_MAX_RECORDS + 1) * QUOTA_RECORD_LEN];
        assert_eq!(
            QuotaImpl::scan(&big, &mut |_| {}),
            Err(QuotaError::TableFull)
        );
    }

    #[test]
    fn end_to_end_banner_scenario() {
        let mut buf = [0u8; 96];
        let n = build_banner_fixture(&mut buf).unwrap();
        assert_eq!(n, 96);
        let count = QuotaImpl::scan(&buf, &mut |_| {}).unwrap();
        assert_eq!(count, 3);
        let r = QuotaImpl::lookup(&buf, 1001).unwrap();
        assert_eq!(
            QuotaImpl::check_write(&r, 1, 0, BANNER_NOW_UNIX),
            Err(QuotaReject::BlockLimit)
        );
    }

    #[test]
    fn inode_grace_expired() {
        let rec = QuotaRecord {
            uid: 1002,
            block_used: 0,
            block_limit: QUOTA_UNLIMITED,
            inode_used: 10,
            inode_limit: 10,
            grace: BANNER_NOW_UNIX - 1,
        };
        assert_eq!(
            QuotaImpl::check_write(&rec, 0, 1, BANNER_NOW_UNIX),
            Err(QuotaReject::GraceExpired)
        );
    }

    #[test]
    fn table_rejects_uid_zero_upsert() {
        let mut t = QuotaTable::new();
        assert!(!t.upsert(QuotaRecord {
            uid: 0,
            block_used: 0,
            block_limit: 1,
            inode_used: 0,
            inode_limit: 1,
            grace: 0,
        }));
    }

    #[test]
    fn wire_bytes_uid_little_endian() {
        let rec = QuotaRecord {
            uid: 0x0102_0304,
            block_used: 0,
            block_limit: 0,
            inode_used: 0,
            inode_limit: 0,
            grace: 0,
        };
        let mut buf = [0u8; 32];
        QuotaImpl::encode_record(&rec, &mut buf).unwrap();
        assert_eq!(&buf[0..4], &[0x04, 0x03, 0x02, 0x01]);
    }

    #[test]
    fn zero_delta_on_over_soft_with_open_grace_ok() {
        let rec = QuotaRecord {
            uid: 12,
            block_used: 200,
            block_limit: 100,
            inode_used: 0,
            inode_limit: 50,
            grace: BANNER_NOW_UNIX + 10,
        };
        // already over but delta 0 and grace open
        assert!(QuotaImpl::check_write(&rec, 0, 0, BANNER_NOW_UNIX).is_ok());
    }
}
