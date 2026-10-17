//! Kernel audit-log subsystem — [`AuditLogImpl`].
//!
//! This module is the [`proteus_contracts::AuditLog`] contract impl. It
//! closes the observability gap left by the existing cap-table / IOMMU /
//! packet-filter denial paths (which today refuse silently): every
//! denial becomes an [`AuditEvent`] the offline parser can correlate to
//! a `task_id` + `syscall_nr`.
//!
//! # What this implements
//!
//! - [`AuditLogImpl`] `<const N>` — fixed-capacity ring with
//!   `append` / `iter` / `snapshot`. Append stamps a monotonic
//!   `event_id`, overwrites the oldest entry on full, and keeps the
//!   high-water-mark so the snapshot header records how many events
//!   were dropped.
//! - [`AUDIT_DEFAULT_CAPACITY`] — kernel-banner default. Operators
//!   with denser streams instantiate with a larger `N`.
//! - Byte-exact `snapshot` emission matching the layout documented
//!   on [`proteus_contracts::AuditLog::snapshot`]: a 20-byte big-
//!   endian header followed by N × 96-byte records.
//!
//! # What this does NOT implement
//!
//! - On-disk persistence. The snapshot stream is the boundary; the
//!   caller (a future `audit_disk` module) writes it to the NVMe
//!   block device.
//! - Rate limiting. The ring is intentionally lossy (overwrite-
//!   oldest) — an audit storm cannot stall the syscall path.
//! - Cryptographic chaining. A future task can extend the snapshot
//!   header with a Merkle-root field once the on-disk format is
//!   stabilised.
//!
//! The donor — `RustOSa/src/audit.rs` — is a similarly-shaped fixed-
//! capacity ring but couples the storage with a syscall-path printk
//! sink. This port keeps storage and emission orthogonal: the trait's
//! `snapshot` returns a byte stream that any sink (printk, NVMe, TCP
//! to a SIEM collector) can consume without re-implementing the
//! record layout.

#![allow(missing_docs)]

use proteus_contracts::{
    AuditError, AuditEvent, AuditIter, AuditLog, AuditVerdict, AUDIT_EVENT_WIRE_LEN,
    AUDIT_MESSAGE_LEN, AUDIT_SNAPSHOT_HEADER_LEN, AUDIT_SNAPSHOT_MAGIC,
};

// ----------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------

/// Default ring capacity used by the kernel banner. Operators with
/// denser streams instantiate [`AuditLogImpl`] with a larger `N`.
/// 256 events × 96 bytes = 24 KiB resident, which is small enough to
/// keep in BSS and large enough for ~1 s of typical denial bursts on
/// a single VM.
pub const AUDIT_DEFAULT_CAPACITY: usize = 256;

/// Zero-event placeholder used to initialise the slot array. The
/// surrounding ring's `len` tracks how many slots are live, so a
/// caller never sees an `EMPTY_EVENT`.
const EMPTY_EVENT: AuditEvent = AuditEvent {
    event_id: 0,
    wall_unix: 0,
    task_id: 0,
    syscall_nr: 0,
    verdict: AuditVerdict::Allowed,
    message: [0u8; AUDIT_MESSAGE_LEN],
};

// ----------------------------------------------------------------------
// Fixed-capacity ring
// ----------------------------------------------------------------------

/// Fixed-capacity audit-event ring with monotonic `event_id` and
/// overwrite-oldest semantics on full.
///
/// The ring stores up to `N` events. `append` always succeeds — when
/// the ring is full it overwrites the oldest entry. The
/// `high_watermark` field tracks the largest `event_id` ever appended
/// so the snapshot header records both "what fits" and "what existed".
///
/// The ring is single-writer: the kernel surfaces today serialise
/// audit appends behind the spin-locked syscall path. A future
/// per-CPU sharded variant would carry `N` independent rings and a
/// merge step at snapshot time.
pub struct AuditLogImpl<const N: usize> {
    /// Slot array. Capacity-fixed at compile time.
    slots: [AuditEvent; N],
    /// Index of the oldest still-resident slot. When `len < N`, this
    /// is always zero. When `len == N`, this slides forward by one
    /// every overwrite.
    head: usize,
    /// Number of resident events (≤ N).
    len: usize,
    /// Total number of `append` calls ever observed. This is also the
    /// `event_id` of the **next** event to be appended; the just-
    /// appended event carries `high_watermark - 1` after the append
    /// completes.
    high_watermark: u64,
}

impl<const N: usize> AuditLogImpl<N> {
    /// Construct an empty ring with `N` slots.
    pub const fn new() -> Self {
        AuditLogImpl {
            slots: [EMPTY_EVENT; N],
            head: 0,
            len: 0,
            high_watermark: 0,
        }
    }

    /// Number of events currently resident in the ring.
    pub const fn len(&self) -> usize {
        self.len
    }

    /// Whether the ring is empty.
    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Total ring capacity (`N`).
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Largest `event_id` ever appended + 1; equivalently, the count
    /// of `append` calls observed across the ring's lifetime. The
    /// difference `high_watermark() - len() as u64` is the number of
    /// events overwritten so far.
    pub const fn high_watermark(&self) -> u64 {
        self.high_watermark
    }

    /// Number of events dropped to overwrite. Always equals
    /// `high_watermark - len`.
    pub const fn dropped(&self) -> u64 {
        self.high_watermark - self.len as u64
    }

    /// Reset the ring to its empty state. Resets the high-watermark as
    /// well — used by the host-side tests to reuse the same ring
    /// across cases without instantiating a fresh one. The kernel
    /// itself never calls this.
    pub fn clear(&mut self) {
        self.head = 0;
        self.len = 0;
        self.high_watermark = 0;
        let mut i = 0usize;
        while i < N {
            self.slots[i] = EMPTY_EVENT;
            i += 1;
        }
    }
}

impl<const N: usize> Default for AuditLogImpl<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> AuditLog for AuditLogImpl<N> {
    fn append(&mut self, mut event: AuditEvent) -> u64 {
        // Stamp the monotonic event_id. The caller's `event_id` field
        // is intentionally overwritten so a buggy / malicious caller
        // cannot mint a duplicate or out-of-order id.
        let id = self.high_watermark;
        event.event_id = id;
        self.high_watermark = self.high_watermark.wrapping_add(1);

        if N == 0 {
            // Pathological zero-capacity variant: still bump the
            // high-watermark so the offline parser can see the drop
            // count, but there is nothing to store.
            return id;
        }

        if self.len < N {
            // Ring not yet full — store at slot (head + len) and
            // bump len.
            let slot = (self.head + self.len) % N;
            self.slots[slot] = event;
            self.len += 1;
        } else {
            // Ring full — overwrite the oldest slot (head) and slide
            // head forward by one.
            self.slots[self.head] = event;
            self.head = (self.head + 1) % N;
        }
        id
    }

    fn iter(&self) -> AuditIter<'_> {
        AuditIter::new(&self.slots, self.head, self.len)
    }

    fn snapshot(&self, out: &mut [u8]) -> Result<usize, AuditError> {
        let need = AUDIT_SNAPSHOT_HEADER_LEN + self.len * AUDIT_EVENT_WIRE_LEN;
        if out.len() < need {
            return Err(AuditError::BufferTooSmall);
        }

        // Header.
        let magic = AUDIT_SNAPSHOT_MAGIC.to_be_bytes();
        out[0..4].copy_from_slice(&magic);
        let count = (self.len as u32).to_be_bytes();
        out[4..8].copy_from_slice(&count);
        let rec_size = (AUDIT_EVENT_WIRE_LEN as u32).to_be_bytes();
        out[8..12].copy_from_slice(&rec_size);
        let hw = self.high_watermark.to_be_bytes();
        out[12..20].copy_from_slice(&hw);

        // Records, in iter order (oldest first).
        let mut cursor = AUDIT_SNAPSHOT_HEADER_LEN;
        let mut k = 0usize;
        while k < self.len {
            if N == 0 {
                break;
            }
            let slot = (self.head + k) % N;
            let ev = &self.slots[slot];
            write_record(ev, &mut out[cursor..cursor + AUDIT_EVENT_WIRE_LEN]);
            cursor += AUDIT_EVENT_WIRE_LEN;
            k += 1;
        }
        Ok(need)
    }
}

/// Serialise one event into the locked 96-byte big-endian record
/// layout. The caller guarantees `out.len() == AUDIT_EVENT_WIRE_LEN`.
fn write_record(ev: &AuditEvent, out: &mut [u8]) {
    out[0..8].copy_from_slice(&ev.event_id.to_be_bytes());
    out[8..16].copy_from_slice(&ev.wall_unix.to_be_bytes());
    out[16..24].copy_from_slice(&ev.task_id.to_be_bytes());
    out[24..28].copy_from_slice(&ev.syscall_nr.to_be_bytes());
    out[28] = ev.verdict.as_u8();
    out[29] = 0;
    out[30] = 0;
    out[31] = 0;
    out[32..32 + AUDIT_MESSAGE_LEN].copy_from_slice(&ev.message);
}

/// Parse a serialised record back into an [`AuditEvent`]. Pure inverse
/// of [`write_record`]; used by the offline-parser test in this
/// module's test block. Returns `None` if the verdict byte is unknown
/// — caller decides whether that counts as a corruption.
pub fn parse_record(rec: &[u8]) -> Option<AuditEvent> {
    if rec.len() != AUDIT_EVENT_WIRE_LEN {
        return None;
    }
    let mut eid = [0u8; 8];
    eid.copy_from_slice(&rec[0..8]);
    let mut wu = [0u8; 8];
    wu.copy_from_slice(&rec[8..16]);
    let mut tid = [0u8; 8];
    tid.copy_from_slice(&rec[16..24]);
    let mut sn = [0u8; 4];
    sn.copy_from_slice(&rec[24..28]);
    let verdict = AuditVerdict::from_u8(rec[28])?;
    let mut msg = [0u8; AUDIT_MESSAGE_LEN];
    msg.copy_from_slice(&rec[32..32 + AUDIT_MESSAGE_LEN]);
    Some(AuditEvent {
        event_id: u64::from_be_bytes(eid),
        wall_unix: u64::from_be_bytes(wu),
        task_id: u64::from_be_bytes(tid),
        syscall_nr: u32::from_be_bytes(sn),
        verdict,
        message: msg,
    })
}

/// Recover the snapshot header from the leading bytes of an emitted
/// stream. Returns `None` if the buffer is too short or the magic
/// does not match.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct SnapshotHeader {
    pub magic: u32,
    pub record_count: u32,
    pub record_size: u32,
    pub high_watermark: u64,
}

/// Parse the leading 20 bytes of a snapshot stream as a
/// [`SnapshotHeader`]. Returns `None` if the buffer is too short.
/// Note: this does NOT validate the magic — the caller decides whether
/// `magic != AUDIT_SNAPSHOT_MAGIC` is a corruption (it usually is, but
/// a future format extension may overload the magic).
pub fn parse_header(buf: &[u8]) -> Option<SnapshotHeader> {
    if buf.len() < AUDIT_SNAPSHOT_HEADER_LEN {
        return None;
    }
    let mut m = [0u8; 4];
    m.copy_from_slice(&buf[0..4]);
    let mut rc = [0u8; 4];
    rc.copy_from_slice(&buf[4..8]);
    let mut rs = [0u8; 4];
    rs.copy_from_slice(&buf[8..12]);
    let mut hw = [0u8; 8];
    hw.copy_from_slice(&buf[12..20]);
    Some(SnapshotHeader {
        magic: u32::from_be_bytes(m),
        record_count: u32::from_be_bytes(rc),
        record_size: u32::from_be_bytes(rs),
        high_watermark: u64::from_be_bytes(hw),
    })
}

// ----------------------------------------------------------------------
// Tests
// ----------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    extern crate alloc;
    use alloc::vec::Vec;

    fn ev(task: u64, sysnr: u32, verdict: AuditVerdict, msg: &[u8]) -> AuditEvent {
        AuditEvent::new(0, 1_700_000_000, task, sysnr, verdict, msg)
    }

    #[test]
    fn event_new_pads_short_message_with_nul() {
        let e = AuditEvent::new(7, 42, 5, 1, AuditVerdict::Allowed, b"hello");
        assert_eq!(&e.message[..5], b"hello");
        // Bytes after the message must be NUL.
        let mut k = 5;
        while k < AUDIT_MESSAGE_LEN {
            assert_eq!(e.message[k], 0, "msg[{}] not NUL", k);
            k += 1;
        }
        assert_eq!(e.message_bytes(), b"hello");
    }

    #[test]
    fn event_new_truncates_overflowing_message() {
        // 80 bytes is longer than AUDIT_MESSAGE_LEN (64).
        let long = [b'A'; 80];
        let e = AuditEvent::new(0, 0, 0, 0, AuditVerdict::Error, &long);
        // Every slot must be 'A' (since the 64-byte truncation lands
        // mid-buffer and there is no room for a NUL).
        for &b in &e.message {
            assert_eq!(b, b'A');
        }
        // message_bytes walks to the first NUL or the end of the
        // array — here, no NULs, so it returns the full 64 bytes.
        assert_eq!(e.message_bytes().len(), AUDIT_MESSAGE_LEN);
    }

    #[test]
    fn audit_verdict_round_trip_via_u8() {
        for v in [AuditVerdict::Allowed, AuditVerdict::Denied, AuditVerdict::Error] {
            assert_eq!(AuditVerdict::from_u8(v.as_u8()), Some(v));
        }
        // Out-of-range u8 must not mint.
        assert_eq!(AuditVerdict::from_u8(3), None);
        assert_eq!(AuditVerdict::from_u8(255), None);
    }

    #[test]
    fn audit_verdict_discriminants_locked() {
        // The discriminants are part of the wire surface. Lock them.
        assert_eq!(AuditVerdict::Allowed as u8, 0);
        assert_eq!(AuditVerdict::Denied as u8, 1);
        assert_eq!(AuditVerdict::Error as u8, 2);
    }

    #[test]
    fn wire_layout_constants_locked() {
        // 8 + 8 + 8 + 4 + 1 + 3 + 64 = 96
        assert_eq!(AUDIT_EVENT_WIRE_LEN, 96);
        // 4 + 4 + 4 + 8 = 20
        assert_eq!(AUDIT_SNAPSHOT_HEADER_LEN, 20);
        assert_eq!(AUDIT_MESSAGE_LEN, 64);
        // ASCII "AUDT"
        assert_eq!(AUDIT_SNAPSHOT_MAGIC, 0x4155_4454);
        assert_eq!(
            AUDIT_SNAPSHOT_MAGIC.to_be_bytes(),
            *b"AUDT"
        );
    }

    #[test]
    fn empty_log_invariants() {
        let log: AuditLogImpl<8> = AuditLogImpl::new();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        assert_eq!(log.capacity(), 8);
        assert_eq!(log.high_watermark(), 0);
        assert_eq!(log.dropped(), 0);
        assert_eq!(log.iter().count(), 0);
    }

    #[test]
    fn append_assigns_monotonic_ids() {
        let mut log: AuditLogImpl<8> = AuditLogImpl::new();
        // The caller's `event_id` field is overwritten.
        let mut e = ev(1, 10, AuditVerdict::Allowed, b"first");
        e.event_id = 999_999; // bogus — must be replaced.
        let id0 = log.append(e);
        assert_eq!(id0, 0);
        let id1 = log.append(ev(2, 11, AuditVerdict::Denied, b"second"));
        assert_eq!(id1, 1);
        let id2 = log.append(ev(3, 12, AuditVerdict::Error, b"third"));
        assert_eq!(id2, 2);
        assert_eq!(log.high_watermark(), 3);
        assert_eq!(log.len(), 3);
        assert_eq!(log.dropped(), 0);

        // iter sees the ids in ascending order.
        let ids: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        assert_eq!(ids.as_slice(), &[0, 1, 2]);
    }

    #[test]
    fn iter_yields_append_order_partial() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Allowed, b"a"));
        log.append(ev(2, 2, AuditVerdict::Allowed, b"b"));
        let msgs: Vec<Vec<u8>> = log
            .iter()
            .map(|e| e.message_bytes().to_vec())
            .collect();
        assert_eq!(msgs[0].as_slice(), b"a");
        assert_eq!(msgs[1].as_slice(), b"b");
    }

    #[test]
    fn iter_is_read_stable() {
        // Calling iter twice produces the same sequence.
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Denied, b"x"));
        log.append(ev(2, 2, AuditVerdict::Denied, b"y"));
        let first: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        let second: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        assert_eq!(first, second);
    }

    #[test]
    fn ring_overflow_overwrites_oldest() {
        let mut log: AuditLogImpl<3> = AuditLogImpl::new();
        // Append 5 events into a 3-slot ring. Events 0 + 1 must be
        // dropped; 2, 3, 4 are resident.
        for i in 0..5u64 {
            log.append(ev(i, i as u32, AuditVerdict::Error, b"x"));
        }
        assert_eq!(log.len(), 3);
        assert_eq!(log.high_watermark(), 5);
        assert_eq!(log.dropped(), 2);
        let ids: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        assert_eq!(ids.as_slice(), &[2, 3, 4]);
    }

    #[test]
    fn boundary_capacity_exact_full_does_not_drop() {
        // Append exactly N events into an N-slot ring. Nothing
        // dropped; ids 0..N resident in order.
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        for i in 0..4u64 {
            log.append(ev(i, i as u32, AuditVerdict::Allowed, b"z"));
        }
        assert_eq!(log.len(), 4);
        assert_eq!(log.high_watermark(), 4);
        assert_eq!(log.dropped(), 0);
        let ids: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        assert_eq!(ids.as_slice(), &[0, 1, 2, 3]);
    }

    #[test]
    fn boundary_capacity_one_more_drops_one() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        for i in 0..5u64 {
            log.append(ev(i, i as u32, AuditVerdict::Allowed, b"z"));
        }
        let ids: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        assert_eq!(ids.as_slice(), &[1, 2, 3, 4]);
        assert_eq!(log.dropped(), 1);
    }

    #[test]
    fn snapshot_header_byte_layout_locked() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Allowed, b"a"));
        log.append(ev(2, 2, AuditVerdict::Denied, b"b"));
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + 4 * AUDIT_EVENT_WIRE_LEN];
        let n = log.snapshot(&mut buf).expect("snapshot OK");
        assert_eq!(n, AUDIT_SNAPSHOT_HEADER_LEN + 2 * AUDIT_EVENT_WIRE_LEN);

        // Header magic
        assert_eq!(&buf[0..4], b"AUDT");
        // record_count = 2
        assert_eq!(&buf[4..8], &[0, 0, 0, 2]);
        // record_size = 96
        assert_eq!(&buf[8..12], &[0, 0, 0, 96]);
        // high_watermark = 2
        assert_eq!(&buf[12..20], &[0, 0, 0, 0, 0, 0, 0, 2]);
    }

    #[test]
    fn snapshot_records_byte_exact_for_first_event() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        // Hand-built event with deterministic bytes.
        let e = AuditEvent::new(
            0,
            0x1122_3344_5566_7788,
            0x0A0B_0C0D_0E0F_1011,
            0xDEAD_BEEF,
            AuditVerdict::Denied,
            b"deny",
        );
        log.append(e);

        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + AUDIT_EVENT_WIRE_LEN];
        let n = log.snapshot(&mut buf).unwrap();
        assert_eq!(n, AUDIT_SNAPSHOT_HEADER_LEN + AUDIT_EVENT_WIRE_LEN);

        let rec = &buf[AUDIT_SNAPSHOT_HEADER_LEN..];
        // event_id = 0 (stamped by append)
        assert_eq!(&rec[0..8], &[0; 8]);
        // wall_unix big-endian
        assert_eq!(&rec[8..16], &[0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88]);
        // task_id big-endian
        assert_eq!(&rec[16..24], &[0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11]);
        // syscall_nr big-endian
        assert_eq!(&rec[24..28], &[0xDE, 0xAD, 0xBE, 0xEF]);
        // verdict = Denied = 1
        assert_eq!(rec[28], 1);
        // padding bytes = 0
        assert_eq!(rec[29], 0);
        assert_eq!(rec[30], 0);
        assert_eq!(rec[31], 0);
        // message bytes (NUL-padded)
        assert_eq!(&rec[32..36], b"deny");
        for k in 36..32 + AUDIT_MESSAGE_LEN {
            assert_eq!(rec[k], 0);
        }
    }

    #[test]
    fn snapshot_round_trip_via_parse_record() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 10, AuditVerdict::Allowed, b"open"));
        log.append(ev(2, 20, AuditVerdict::Denied, b"deny-cap"));
        log.append(ev(3, 30, AuditVerdict::Error, b"iommu-fault"));

        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + 4 * AUDIT_EVENT_WIRE_LEN];
        let n = log.snapshot(&mut buf).unwrap();
        let header = parse_header(&buf[..n]).unwrap();
        assert_eq!(header.magic, AUDIT_SNAPSHOT_MAGIC);
        assert_eq!(header.record_count, 3);
        assert_eq!(header.record_size as usize, AUDIT_EVENT_WIRE_LEN);
        assert_eq!(header.high_watermark, 3);

        // Walk records and compare against iter() order.
        let live: Vec<AuditEvent> = log.iter().collect();
        let mut cursor = AUDIT_SNAPSHOT_HEADER_LEN;
        for expected in live.iter() {
            let rec = &buf[cursor..cursor + AUDIT_EVENT_WIRE_LEN];
            let parsed = parse_record(rec).unwrap();
            assert_eq!(parsed, *expected);
            cursor += AUDIT_EVENT_WIRE_LEN;
        }
        assert_eq!(cursor, n);
    }

    #[test]
    fn snapshot_buffer_too_small_returns_err() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Allowed, b"x"));
        log.append(ev(2, 2, AuditVerdict::Denied, b"y"));
        // Buffer just shy of header + 2 records.
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + AUDIT_EVENT_WIRE_LEN];
        // 1 record fits (96 + 20 = 116), but we have 2 records (192 +
        // 20 = 212 needed).
        let r = log.snapshot(&mut buf);
        assert_eq!(r, Err(AuditError::BufferTooSmall));
        // out is not modified on error.
        for &b in buf.iter() {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn snapshot_empty_log_writes_header_only() {
        let log: AuditLogImpl<4> = AuditLogImpl::new();
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN];
        let n = log.snapshot(&mut buf).unwrap();
        assert_eq!(n, AUDIT_SNAPSHOT_HEADER_LEN);
        assert_eq!(&buf[0..4], b"AUDT");
        assert_eq!(&buf[4..8], &[0, 0, 0, 0]); // record_count = 0
        assert_eq!(&buf[12..20], &[0; 8]); // high_watermark = 0
    }

    #[test]
    fn snapshot_records_in_iter_order_after_overwrite() {
        // Overflow the ring; snapshot must emit the resident events
        // in iter() order (which is oldest-resident → newest).
        let mut log: AuditLogImpl<3> = AuditLogImpl::new();
        for i in 0..6u64 {
            log.append(ev(i, i as u32, AuditVerdict::Allowed, b"k"));
        }
        // After 6 appends into 3 slots: ids 3, 4, 5 resident.
        let ids: Vec<u64> = log.iter().map(|e| e.event_id).collect();
        assert_eq!(ids.as_slice(), &[3u64, 4, 5]);
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN];
        let n = log.snapshot(&mut buf).unwrap();
        assert_eq!(n, AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN);
        let header = parse_header(&buf).unwrap();
        assert_eq!(header.record_count, 3);
        assert_eq!(header.high_watermark, 6);

        let mut expected = 3u64;
        let mut cursor = AUDIT_SNAPSHOT_HEADER_LEN;
        while cursor < n {
            let rec = parse_record(&buf[cursor..cursor + AUDIT_EVENT_WIRE_LEN]).unwrap();
            assert_eq!(rec.event_id, expected);
            expected += 1;
            cursor += AUDIT_EVENT_WIRE_LEN;
        }
        assert_eq!(expected, 6);
    }

    #[test]
    fn parse_record_rejects_unknown_verdict_byte() {
        // Hand-build a record with verdict = 3 (out of range).
        let mut rec = [0u8; AUDIT_EVENT_WIRE_LEN];
        rec[28] = 3;
        assert!(parse_record(&rec).is_none());
    }

    #[test]
    fn parse_record_rejects_short_buffer() {
        let rec = [0u8; AUDIT_EVENT_WIRE_LEN - 1];
        assert!(parse_record(&rec).is_none());
    }

    #[test]
    fn parse_header_rejects_short_buffer() {
        let buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN - 1];
        assert!(parse_header(&buf).is_none());
    }

    #[test]
    fn clear_resets_ring_state() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Allowed, b"a"));
        log.append(ev(2, 2, AuditVerdict::Denied, b"b"));
        assert_eq!(log.high_watermark(), 2);
        log.clear();
        assert_eq!(log.len(), 0);
        assert!(log.is_empty());
        assert_eq!(log.high_watermark(), 0);
        // After clear, append begins at id 0 again.
        let id = log.append(ev(7, 7, AuditVerdict::Error, b"after-clear"));
        assert_eq!(id, 0);
    }

    #[test]
    fn append_id_zero_for_first_event_even_with_message_caller_id() {
        // Caller supplies a non-zero event_id; append must overwrite
        // it to 0 (the first monotonic id).
        let mut e = ev(1, 1, AuditVerdict::Allowed, b"first");
        e.event_id = 12_345;
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        let id = log.append(e);
        assert_eq!(id, 0);
        // The stored event also has id = 0 (not 12_345).
        let stored = log.iter().next().unwrap();
        assert_eq!(stored.event_id, 0);
    }

    #[test]
    fn default_constructs_empty_log() {
        let log: AuditLogImpl<8> = AuditLogImpl::default();
        assert_eq!(log.len(), 0);
        assert_eq!(log.capacity(), 8);
    }

    #[test]
    fn iter_len_tracks_pos() {
        let mut log: AuditLogImpl<4> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Allowed, b"a"));
        log.append(ev(2, 2, AuditVerdict::Allowed, b"b"));
        let mut it = log.iter();
        assert_eq!(it.len(), 2);
        let _ = it.next();
        assert_eq!(it.len(), 1);
        let _ = it.next();
        assert_eq!(it.len(), 0);
        assert!(it.is_empty());
        assert!(it.next().is_none());
    }

    #[test]
    fn snapshot_exact_buffer_size_succeeds() {
        // Buffer is exactly header + N records — must succeed (the
        // ">=" check on capacity is the contract; equality is the
        // edge).
        let mut log: AuditLogImpl<2> = AuditLogImpl::new();
        log.append(ev(1, 1, AuditVerdict::Allowed, b"a"));
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + AUDIT_EVENT_WIRE_LEN];
        let n = log.snapshot(&mut buf).unwrap();
        assert_eq!(n, buf.len());
    }

    #[test]
    fn high_watermark_keeps_counting_past_capacity() {
        let mut log: AuditLogImpl<2> = AuditLogImpl::new();
        for i in 0..10u64 {
            log.append(ev(i, i as u32, AuditVerdict::Allowed, b"x"));
        }
        // 10 appends → high_watermark = 10, but only 2 resident.
        assert_eq!(log.high_watermark(), 10);
        assert_eq!(log.len(), 2);
        assert_eq!(log.dropped(), 8);
        // Snapshot header surfaces the high-watermark.
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + 2 * AUDIT_EVENT_WIRE_LEN];
        let _ = log.snapshot(&mut buf).unwrap();
        let h = parse_header(&buf).unwrap();
        assert_eq!(h.high_watermark, 10);
        assert_eq!(h.record_count, 2);
    }

    #[test]
    fn three_verdict_kinds_round_trip_via_snapshot() {
        // Mirrors the kernel banner's three-event composition (one of
        // each verdict). Confirms every variant survives snapshot →
        // parse without aliasing.
        let mut log: AuditLogImpl<3> = AuditLogImpl::new();
        log.append(ev(10, 1, AuditVerdict::Allowed, b"open OK"));
        log.append(ev(11, 2, AuditVerdict::Denied, b"cap_check EPERM"));
        log.append(ev(12, 3, AuditVerdict::Error, b"iommu_translate ENOENT"));
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN];
        let n = log.snapshot(&mut buf).unwrap();
        let verdicts: Vec<u8> = (0..3)
            .map(|i| {
                let start = AUDIT_SNAPSHOT_HEADER_LEN + i * AUDIT_EVENT_WIRE_LEN;
                buf[start + 28]
            })
            .collect();
        assert_eq!(verdicts.as_slice(), &[0u8, 1, 2]);

        // Parse round-trip every record.
        let mut k = 0usize;
        let mut cursor = AUDIT_SNAPSHOT_HEADER_LEN;
        while cursor < n {
            let p = parse_record(&buf[cursor..cursor + AUDIT_EVENT_WIRE_LEN]).unwrap();
            assert_eq!(p.event_id, k as u64);
            cursor += AUDIT_EVENT_WIRE_LEN;
            k += 1;
        }
        assert_eq!(k, 3);
    }

    #[test]
    fn message_bytes_walks_to_first_nul() {
        let e = AuditEvent::new(0, 0, 0, 0, AuditVerdict::Allowed, b"abc");
        assert_eq!(e.message_bytes(), b"abc");
        // Embedded NUL truncates the recovered slice.
        let mut msg = [0u8; AUDIT_MESSAGE_LEN];
        msg[0] = b'A';
        msg[1] = 0;
        msg[2] = b'B';
        let ev2 = AuditEvent {
            event_id: 0,
            wall_unix: 0,
            task_id: 0,
            syscall_nr: 0,
            verdict: AuditVerdict::Allowed,
            message: msg,
        };
        assert_eq!(ev2.message_bytes(), b"A");
    }
}

