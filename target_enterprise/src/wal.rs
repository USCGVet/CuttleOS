//! Write-Ahead Log primitive — `no_std`, in-memory backing store.
//!
//! Adapted from `RustOSa/src/wal.rs` (sector-based, virtio-blk
//! backed) into a fixed-capacity byte-buffer journal suitable for
//! the host-testable `target_enterprise` seed. The framing scheme
//! is a clear descendant of the donor's record format, simplified
//! for a contiguous byte log rather than a ring of 512-byte sectors:
//!
//! ```text
//!   record on disk:
//!       0..4   u32 LE  payload length
//!       4..8   u32 LE  CRC-32 over the payload bytes only
//!       8..    N bytes payload
//! ```
//!
//! The CRC excludes the length and crc fields themselves so a torn
//! write that clips the header is detected by short-read at replay
//! time rather than by an internally-consistent corrupt frame.
//!
//! ## Cursors
//!
//! - `write_cursor` — the byte offset in the backing store where the
//!   next `append` will land. Advances on every append. Records
//!   between the durable cursor and the write cursor are written
//!   into the buffer but are NOT visible to `replay`.
//! - `durable_cursor` — the byte offset up to which records have
//!   been declared durable by a successful `flush`. `replay` walks
//!   the buffer from byte 0 to `durable_cursor`, never past.
//!
//! A simulated crash is modeled by dropping the in-memory `WalImpl`
//! and reconstructing it from the underlying `[u8; CAPACITY]` buffer
//! plus the persisted durable cursor (callers persist this cursor
//! out-of-band; the test harness in `tests/wal_replay.rs` does so
//! via the `WalImpl::durable_cursor` accessor). Records written but
//! never flushed are simply not within `[0, durable_cursor)` and are
//! invisible to the post-crash replay.
//!
//! ## On the LSN
//!
//! `next_lsn` starts at 1 and advances on every successful `append`.
//! LSNs are returned to callers but are NOT stored in the record
//! frame itself — they are recovered at replay time by counting
//! records in append order. This keeps the per-record overhead at
//! 8 bytes (matching the donor's 24-byte header minus the magic and
//! kind fields the host harness doesn't need).
//!
//! ## Allocation discipline
//!
//! Zero. The backing store is a `[u8; CAPACITY]` owned by the impl
//! struct; the CRC scratch is a stack-local `u32`; the replay loop
//! borrows the payload slice directly out of the backing buffer and
//! hands it to the caller's callback. There is no `alloc`, no
//! `heapless::Vec`, no implicit allocation anywhere in this module.

use proteus_contracts::{CapProof, WriteAheadLog};

/// Mint a [`CapProof`] for [`proteus_contracts::caps::DURABLE_WAL_WRITE`]
/// when `held` includes that bit (TASK-161). Prefer this at call sites
/// that already know the caller's capability mask.
#[inline]
pub fn durable_wal_proof(held: u64) -> Result<CapProof, proteus_contracts::CapError> {
    proteus_contracts::mint_cap_proof(held, proteus_contracts::caps::DURABLE_WAL_WRITE)
}

/// Privileged self-grant for tests / banner / init (holds only the WAL
/// durable bit). Not a bypass for unprivileged tasks — those must
/// pass their real held mask through [`durable_wal_proof`].
#[inline]
pub fn durable_wal_proof_init() -> CapProof {
    durable_wal_proof(proteus_contracts::caps::DURABLE_WAL_WRITE)
        .expect("DURABLE_WAL_WRITE self-grant must succeed")
}

/// Fixed framing overhead per record in bytes: `len: u32 + crc: u32`.
pub const FRAME_HEADER_BYTES: usize = 8;

/// Errors returned by [`WalImpl`] fallible methods.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub enum WalError {
    /// The record's payload plus the 8-byte frame header would exceed
    /// the impl's `CAPACITY` const generic. The append is rejected
    /// and the write cursor is not advanced.
    OutOfCapacity,
    /// The payload length exceeds `MAX_PAYLOAD_LEN` and cannot be
    /// encoded in the 32-bit length field. The write cursor is not
    /// advanced.
    PayloadTooLarge,
}

/// Largest payload a single record may carry. `u32::MAX` would be
/// the theoretical ceiling; we cap at `1 << 20` (1 MiB) so the size
/// always fits within any sane `CAPACITY` and accidental overflow
/// arithmetic on `cursor + len` is structurally impossible on a
/// 32-bit usize host.
pub const MAX_PAYLOAD_LEN: usize = 1 << 20;

/// In-memory, fixed-capacity Write-Ahead Log.
///
/// The const generic `CAPACITY` is the byte capacity of the backing
/// store. Pick it to comfortably hold the journal high-water mark of
/// the workload before the upstream code can checkpoint. The impl
/// does NOT wrap around; once `CAPACITY` is full, `append` returns
/// `Err(WalError::OutOfCapacity)`. Wraparound semantics are a
/// follow-on task.
pub struct WalImpl<const CAPACITY: usize> {
    /// Contiguous byte buffer holding framed records.
    buf: [u8; CAPACITY],
    /// Offset within `buf` where the next `append` will land.
    write_cursor: usize,
    /// Offset within `buf` declared durable by the most recent
    /// `flush`. Replay walks `[0, durable_cursor)`.
    durable_cursor: usize,
    /// LSN that will be assigned to the next successful `append`.
    /// Monotonic; starts at 1 on a fresh init.
    next_lsn: u64,
}

impl<const CAPACITY: usize> WalImpl<CAPACITY> {
    /// Construct a fresh, empty WAL. The backing buffer is zeroed.
    /// `next_lsn` starts at 1; `write_cursor` and `durable_cursor`
    /// start at 0.
    pub const fn new() -> Self {
        Self {
            buf: [0u8; CAPACITY],
            write_cursor: 0,
            durable_cursor: 0,
            next_lsn: 1,
        }
    }

    /// Reconstruct a WAL from an existing backing buffer and a
    /// previously-persisted durable cursor. This is the canonical
    /// "boot from disk" path: a real impl would read `buf` and
    /// `durable_cursor` from stable storage; the in-memory harness
    /// hands them in directly to model a crash + restart.
    ///
    /// On reconstruction, `next_lsn` is recovered by counting the
    /// valid records in `[0, durable_cursor)`. This guarantees that
    /// a subsequent `append` after replay assigns an LSN strictly
    /// greater than any LSN already on disk.
    ///
    /// `durable_cursor` is clamped to `CAPACITY` defensively; a
    /// caller passing a stale cursor from a larger-buffer build
    /// can't escape the bounds of the new buffer.
    pub fn from_backing(buf: [u8; CAPACITY], durable_cursor: usize) -> Self {
        let dc = if durable_cursor > CAPACITY { CAPACITY } else { durable_cursor };
        // Count valid records in the durable prefix to recover the
        // next LSN. We tolerate a corrupt tail (truncate at the
        // first invalid frame) just like `replay` does — durable
        // cursor lies within the valid prefix by construction, but
        // belt-and-suspenders.
        let mut lsn_counter: u64 = 0;
        let mut off = 0usize;
        while off + FRAME_HEADER_BYTES <= dc {
            let len = read_u32_le(&buf[off..off + 4]) as usize;
            let want_crc = read_u32_le(&buf[off + 4..off + 8]);
            if len > MAX_PAYLOAD_LEN {
                break;
            }
            let payload_start = off + FRAME_HEADER_BYTES;
            let payload_end = payload_start.saturating_add(len);
            if payload_end > dc {
                break;
            }
            let got_crc = crc32_ieee(&buf[payload_start..payload_end]);
            if got_crc != want_crc {
                break;
            }
            lsn_counter += 1;
            off = payload_end;
        }
        Self {
            buf,
            write_cursor: dc,
            durable_cursor: dc,
            next_lsn: lsn_counter + 1,
        }
    }

    /// Borrow the underlying backing buffer. Used by the crash-
    /// recovery test to copy the bytes out, drop the WAL, and
    /// reconstruct from the copy.
    pub fn backing(&self) -> &[u8; CAPACITY] {
        &self.buf
    }

    /// Current write cursor (next-append offset).
    pub fn write_cursor(&self) -> usize {
        self.write_cursor
    }

    /// Current durable cursor (replay bound).
    pub fn durable_cursor(&self) -> usize {
        self.durable_cursor
    }

    /// LSN that will be assigned to the next successful `append`.
    pub fn next_lsn(&self) -> u64 {
        self.next_lsn
    }
}

impl<const CAPACITY: usize> Default for WalImpl<CAPACITY> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const CAPACITY: usize> WriteAheadLog for WalImpl<CAPACITY> {
    type Error = WalError;

    fn append(&mut self, record: &[u8]) -> Result<u64, Self::Error> {
        if record.len() > MAX_PAYLOAD_LEN {
            return Err(WalError::PayloadTooLarge);
        }
        // Capacity check uses checked arithmetic so a pathological
        // cursor value can't wrap around into accepting a write.
        let needed = match FRAME_HEADER_BYTES.checked_add(record.len()) {
            Some(n) => n,
            None => return Err(WalError::PayloadTooLarge),
        };
        let new_cursor = match self.write_cursor.checked_add(needed) {
            Some(c) => c,
            None => return Err(WalError::OutOfCapacity),
        };
        if new_cursor > CAPACITY {
            return Err(WalError::OutOfCapacity);
        }
        // Frame layout: [len: u32 LE][crc32: u32 LE][payload..]
        let off = self.write_cursor;
        let len_u32 = record.len() as u32;
        let crc = crc32_ieee(record);
        write_u32_le(&mut self.buf[off..off + 4], len_u32);
        write_u32_le(&mut self.buf[off + 4..off + 8], crc);
        let payload_start = off + FRAME_HEADER_BYTES;
        let payload_end = payload_start + record.len();
        self.buf[payload_start..payload_end].copy_from_slice(record);
        self.write_cursor = new_cursor;
        let lsn = self.next_lsn;
        self.next_lsn = lsn + 1;
        Ok(lsn)
    }

    fn flush(&mut self, _proof: CapProof) -> Result<(), Self::Error> {
        // TASK-161: CapProof required at the type level — unprivileged
        // callers cannot obtain one without holding DURABLE_WAL_WRITE.
        // In-memory backing: flush is the cursor advance.
        // A future disk-backed impl would issue the sync here and
        // only advance `durable_cursor` on Ok.
        let _ = _proof;
        self.durable_cursor = self.write_cursor;
        Ok(())
    }

    fn replay(&self, callback: &mut dyn FnMut(u64, &[u8])) {
        let bound = self.durable_cursor;
        let mut off = 0usize;
        let mut lsn: u64 = 1;
        while off + FRAME_HEADER_BYTES <= bound {
            let len = read_u32_le(&self.buf[off..off + 4]) as usize;
            let want_crc = read_u32_le(&self.buf[off + 4..off + 8]);
            if len > MAX_PAYLOAD_LEN {
                // Implausible length → torn frame. Stop without
                // delivering this record. This mirrors the donor's
                // "break at first invalid sector" behaviour.
                return;
            }
            let payload_start = off + FRAME_HEADER_BYTES;
            let payload_end = match payload_start.checked_add(len) {
                Some(e) => e,
                None => return,
            };
            if payload_end > bound {
                // Truncated tail: the record header parsed but the
                // payload runs past the durable cursor. Stop.
                return;
            }
            let payload = &self.buf[payload_start..payload_end];
            let got_crc = crc32_ieee(payload);
            if got_crc != want_crc {
                // CRC mismatch: data corruption / bit rot. Stop
                // without delivering this or any later record.
                return;
            }
            callback(lsn, payload);
            lsn += 1;
            off = payload_end;
        }
    }
}

// ---------- internal helpers ----------

/// CRC-32 / IEEE 802.3 polynomial `0xEDB88320`, computed byte-at-a-
/// time. Not cryptographically secure; fits the on-disk frame-
/// integrity role this WAL needs.
///
/// The algorithm is the canonical reflected variant: initial
/// register `0xFFFF_FFFF`, final XOR `0xFFFF_FFFF`, reflected input
/// and output. Matches `zlib::crc32` byte-for-byte on equal input.
pub fn crc32_ieee(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    let mut i = 0usize;
    while i < bytes.len() {
        crc ^= bytes[i] as u32;
        let mut bit = 0u32;
        while bit < 8 {
            let mask = !((crc & 1).wrapping_sub(1));
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
            bit += 1;
        }
        i += 1;
    }
    !crc
}

fn read_u32_le(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

fn write_u32_le(b: &mut [u8], v: u32) {
    let bytes = v.to_le_bytes();
    b[0] = bytes[0];
    b[1] = bytes[1];
    b[2] = bytes[2];
    b[3] = bytes[3];
}

// ============================================================
// In-source unit tests. Property tests live in
// `target_enterprise/tests/wal_replay.rs` and run against 100 random
// seeds × 1000 ops each; these are the small-deterministic smoke
// tests that catch off-by-one and framing bugs before the slow
// property test runs.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::WriteAheadLog as _;

    fn proof() -> CapProof {
        durable_wal_proof_init()
    }

    #[test]
    fn flush_requires_durable_wal_cap_proof() {
        // TASK-161: unprivileged held mask cannot mint proof.
        assert!(durable_wal_proof(0).is_err());
        assert!(durable_wal_proof(proteus_contracts::caps::BLOCK_WRITE).is_err());
        assert!(durable_wal_proof(proteus_contracts::caps::AUDIT_WRITE).is_err());
        let p = durable_wal_proof(proteus_contracts::caps::DURABLE_WAL_WRITE).unwrap();
        let mut wal: WalImpl<64> = WalImpl::new();
        wal.append(b"x").unwrap();
        wal.flush(p).unwrap();
        assert_eq!(wal.durable_cursor(), FRAME_HEADER_BYTES + 1);
    }

    #[test]
    fn crc32_known_vectors() {
        // Canonical zlib/IEEE 802.3 reference values.
        assert_eq!(crc32_ieee(b""), 0);
        assert_eq!(crc32_ieee(b"a"), 0xE8B7BE43);
        assert_eq!(crc32_ieee(b"123456789"), 0xCBF43926);
    }

    #[test]
    fn fresh_wal_has_empty_replay() {
        let wal: WalImpl<256> = WalImpl::new();
        let mut count = 0usize;
        wal.replay(&mut |_, _| {
            count += 1;
        });
        assert_eq!(count, 0);
        assert_eq!(wal.next_lsn(), 1);
        assert_eq!(wal.write_cursor(), 0);
        assert_eq!(wal.durable_cursor(), 0);
    }

    #[test]
    fn append_advances_write_but_not_durable_cursor() {
        let mut wal: WalImpl<256> = WalImpl::new();
        let lsn = wal.append(b"hello").unwrap();
        assert_eq!(lsn, 1);
        assert_eq!(wal.write_cursor(), FRAME_HEADER_BYTES + 5);
        // Durable cursor stays at 0 until flush.
        assert_eq!(wal.durable_cursor(), 0);
        // Replay before flush sees nothing.
        let mut seen: usize = 0;
        wal.replay(&mut |_, _| seen += 1);
        assert_eq!(seen, 0);
    }

    #[test]
    fn flush_makes_records_visible() {
        let mut wal: WalImpl<256> = WalImpl::new();
        wal.append(b"alpha").unwrap();
        wal.append(b"bravo").unwrap();
        wal.flush(proof()).unwrap();
        let mut seen_lsns: [u64; 4] = [0; 4];
        let mut seen_payloads: [[u8; 8]; 4] = [[0; 8]; 4];
        let mut seen_lens: [usize; 4] = [0; 4];
        let mut idx: usize = 0;
        wal.replay(&mut |lsn, payload| {
            seen_lsns[idx] = lsn;
            seen_lens[idx] = payload.len();
            let n = payload.len().min(8);
            seen_payloads[idx][..n].copy_from_slice(&payload[..n]);
            idx += 1;
        });
        assert_eq!(idx, 2);
        assert_eq!(seen_lsns[0], 1);
        assert_eq!(seen_lsns[1], 2);
        assert_eq!(&seen_payloads[0][..seen_lens[0]], b"alpha");
        assert_eq!(&seen_payloads[1][..seen_lens[1]], b"bravo");
    }

    #[test]
    fn out_of_capacity_rejects_append() {
        // 16-byte capacity holds exactly one 8-byte frame header
        // plus an 8-byte payload; the second append must reject.
        let mut wal: WalImpl<16> = WalImpl::new();
        assert!(wal.append(&[0u8; 8]).is_ok());
        let err = wal.append(b"x").unwrap_err();
        assert_eq!(err, WalError::OutOfCapacity);
        // Write cursor should not have advanced on the failed append.
        assert_eq!(wal.write_cursor(), 16);
    }

    #[test]
    fn crash_after_flush_recovers_all_committed_records() {
        let mut wal: WalImpl<1024> = WalImpl::new();
        wal.append(b"one").unwrap();
        wal.append(b"two").unwrap();
        wal.append(b"three").unwrap();
        wal.flush(proof()).unwrap();
        // Snapshot the durable cursor and backing buffer.
        let snapshot_cursor = wal.durable_cursor();
        let snapshot_buf = *wal.backing();
        // Drop and reconstruct.
        drop(wal);
        let restored: WalImpl<1024> = WalImpl::from_backing(snapshot_buf, snapshot_cursor);
        let mut seen: usize = 0;
        restored.replay(&mut |_, _| seen += 1);
        assert_eq!(seen, 3);
        // Next LSN must be strictly greater than any recovered LSN.
        assert_eq!(restored.next_lsn(), 4);
    }

    #[test]
    fn crash_before_flush_discards_uncommitted_records() {
        let mut wal: WalImpl<1024> = WalImpl::new();
        wal.append(b"committed-1").unwrap();
        wal.flush(proof()).unwrap();
        let snapshot_cursor = wal.durable_cursor();
        // These appends come after the only flush — they're in the
        // backing buffer but not durable.
        wal.append(b"uncommitted-1").unwrap();
        wal.append(b"uncommitted-2").unwrap();
        let snapshot_buf = *wal.backing();
        drop(wal);
        let restored: WalImpl<1024> = WalImpl::from_backing(snapshot_buf, snapshot_cursor);
        let mut seen_count: usize = 0;
        let mut last_payload: [u8; 32] = [0; 32];
        let mut last_len: usize = 0;
        restored.replay(&mut |_, payload| {
            seen_count += 1;
            last_len = payload.len();
            last_payload[..payload.len()].copy_from_slice(payload);
        });
        assert_eq!(seen_count, 1);
        assert_eq!(&last_payload[..last_len], b"committed-1");
    }

    #[test]
    fn replay_stops_at_first_corrupt_record() {
        let mut wal: WalImpl<256> = WalImpl::new();
        wal.append(b"good-1").unwrap();
        wal.append(b"good-2").unwrap();
        wal.append(b"good-3").unwrap();
        wal.flush(proof()).unwrap();
        // Corrupt the payload of the middle record. We need to
        // locate it: first record is at offset 0, header 8 bytes,
        // payload 6 bytes → second record starts at 14.
        let mid_off = FRAME_HEADER_BYTES + b"good-1".len() + FRAME_HEADER_BYTES;
        let backing_cursor = wal.durable_cursor();
        let mut backing = *wal.backing();
        backing[mid_off] ^= 0xFF;
        let restored: WalImpl<256> = WalImpl::from_backing(backing, backing_cursor);
        let mut seen: usize = 0;
        restored.replay(&mut |_, _| seen += 1);
        // First record valid, second record corrupt → stop. The
        // third record never makes it to the callback even though
        // its bytes are physically intact.
        assert_eq!(seen, 1);
    }
}
