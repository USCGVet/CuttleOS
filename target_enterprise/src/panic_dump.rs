//! Post-mortem crash dump — TASK-019.
//!
//! When the kernel's `panic_handler` decides to halt, this module's
//! [`PanicDumpImpl`] serialises the panic context into a 16 KiB,
//! fixed-layout byte buffer. A caller-supplied [`SectorSink`] then
//! ships the buffer to a reserved LBA range on the boot device. A
//! follow-on boot (or a host-side reader after exporting the disk)
//! pulls the same 16 KiB back, recovers every field via
//! [`PanicDumpImpl::parse_header`] + the `extract_*` helpers, and
//! resolves backtrace addresses against the kernel symbol table via
//! [`crate::symbols::StaticSymbolResolver`].
//!
//! ## On-disk layout (locked)
//!
//! Total size: **16 384 bytes** (32 × 512-byte sectors). All byte
//! offsets are defined in [`cuttle_contracts::crash_offsets`]:
//!
//! - Sector 0 (header, 512 bytes):
//!   - 0..8     magic                = `"CTTLPAN1"` ([`CRASH_DUMP_MAGIC`])
//!   - 8..12    schema       (u32 LE) = [`CRASH_DUMP_SCHEMA`]
//!   - 12..16   reserved
//!   - 16..24   wall_unix    (u64 LE)
//!   - 24..32   tsc          (u64 LE)
//!   - 32..48   reserved (16 bytes)
//!   - 48..176  panic_loc    (utf-8, NUL-padded, 128 bytes — `CRASH_LOC_MAX`)
//!   - 176..432 message      (utf-8, NUL-padded, 256 bytes — `CRASH_MSG_MAX`)
//!   - 432..436 kmsg_len           (u32 LE)
//!   - 436..440 backtrace_count    (u32 LE)
//!   - 440..444 register_count     (u32 LE) — always `CRASH_REG_COUNT`
//!   - 444..448 body_crc32c        (u32 LE) — Castagnoli over sectors 1..32
//!   - 448..512 reserved (zero)
//! - Sector 1 (registers, 512 bytes): 24 × u64 LE = 192 bytes + 320
//!   bytes of zero padding.
//! - Sector 2 (backtrace, 512 bytes): up to 64 × u64 LE (one frame
//!   address per slot); unused slots are zero. `backtrace_count` in
//!   the header is the only authority on how many slots are valid.
//! - Sectors 3..32 (kmsg, 14 848 bytes): raw kernel-message ring tail
//!   bytes, NUL-padded to the end.
//!
//! ## CRC32-C body checksum
//!
//! The header carries a 32-bit Castagnoli CRC computed over the body
//! bytes (range `512..16384`). [`PanicDumpImpl::verify_crc`] recomputes
//! and rejects mismatches. The polynomial is `0x1EDC6F41` (RFC 3309),
//! implemented as a portable bit-by-bit loop — algorithmically locked,
//! the implementation morphs (table-driven, slice-by-N, etc.) without
//! changing the emitted value.
//!
//! ## Why fixed-capacity, allocation-free
//!
//! Panic dumps run after the heap may already be corrupt. Every scratch
//! buffer in this module is either:
//! - a caller-supplied `&mut [u8]` (the dump buffer itself); or
//! - a stack array sized at compile time from a `cuttle_contracts`
//!   constant.
//!
//! No `extern crate alloc`; no global state mutated by `build_dump`.
//! The [`SectorSink`] trait is the sole I/O interface and is invoked
//! after the dump has been fully assembled in memory, so a fault
//! while writing to disk produces at most a partial dump — never a
//! re-entrant panic.
//!
//! ## Re-entry safety
//!
//! [`PANIC_DUMP_LATCH`] is a one-shot `AtomicBool`. The first call to
//! [`set_dumped`] swaps it `true` and returns `false` (meaning the
//! caller MAY proceed with dumping); subsequent calls return `true`
//! and the caller should fall back to serial-only diagnostics. The
//! latch is process-wide and survives until reboot — exactly the
//! lifetime of a panic-handler invocation.

#![allow(clippy::too_many_arguments)]

use core::sync::atomic::{AtomicBool, Ordering};

use cuttle_contracts::{
    crash_offsets, CrashContext, CrashDump, CrashDumpError, CrashDumpHeader,
    CRASH_BACKTRACE_MAX, CRASH_DUMP_BYTES, CRASH_DUMP_MAGIC, CRASH_DUMP_SCHEMA, CRASH_KMSG_MAX,
    CRASH_LOC_MAX, CRASH_MSG_MAX, CRASH_REG_COUNT,
};

/// The reserved LBA where dumps land on the boot device. Matches the
/// RustOSa donor convention so the same `pdumpread` reader works
/// against both. 1024 × 512 = 512 KiB into the image; the default
/// `mkdisk` FAT32 layout reserves this region.
pub const DUMP_START_LBA: u64 = 1024;

/// Sector size in bytes. Locked at 512 across all morph cycles
/// (matches [`cuttle_contracts::BlockDevice::BLOCK_SIZE`]).
pub const SECTOR_BYTES: usize = 512;

/// One-shot re-entry latch. A panic handler that calls
/// [`PanicDumpImpl::build_dump`] twice in the same boot has hit
/// re-entry — likely a fault during disk write — and must not loop
/// forever. The latch is set on the first invocation; the caller
/// inspects [`set_dumped`] and falls back to serial-only diagnostics
/// when it returns `true`.
static PANIC_DUMP_LATCH: AtomicBool = AtomicBool::new(false);

/// Idempotently mark "a panic dump has been attempted in this boot".
/// Returns the prior value (i.e. `true` means re-entry — caller must
/// not proceed).
pub fn set_dumped() -> bool {
    PANIC_DUMP_LATCH.swap(true, Ordering::AcqRel)
}

/// Test-only — reset the re-entry latch. Production panic flow MUST
/// NOT call this; the latch is a load-bearing safety net.
#[doc(hidden)]
pub fn reset_for_selftest() {
    PANIC_DUMP_LATCH.store(false, Ordering::Release);
}

/// Caller-supplied sink that ships dump sectors to the boot device.
///
/// The implementation is whatever raw block-device interface the kernel
/// has access to mid-panic (in the live target: virtio-blk with the
/// global mutex force-unlocked; in tests: an in-memory `[u8; 16384]`
/// stand-in). The trait is invoked AFTER the dump buffer is fully
/// assembled in memory — so a write failure produces a partial dump,
/// never a re-entrant panic in `build_dump` itself.
pub trait SectorSink {
    /// Error type the sink reports back.
    type Error;
    /// Write `buf` (always exactly [`SECTOR_BYTES`] bytes) to `lba`.
    fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR_BYTES]) -> Result<(), Self::Error>;
}

/// In-memory [`SectorSink`] used by tests + the kernel banner. Owns a
/// 16 KiB buffer and stamps each sector at the recorded LBA into the
/// matching offset.
pub struct MemorySectorSink {
    /// Backing store. `disk[ (lba - DUMP_START_LBA) * 512 ..  + 512 ]`
    /// contains the bytes the sink received for `lba`.
    pub disk: [u8; CRASH_DUMP_BYTES],
    /// Sectors observed in arrival order. Lets tests assert the writer
    /// emits sectors in ascending LBA without back-and-forth seeks.
    pub recorded_lbas: [u64; CRASH_DUMP_SECTORS_USIZE],
    /// Number of valid entries in `recorded_lbas`.
    pub recorded: usize,
}

/// `usize` form of `cuttle_contracts::CRASH_DUMP_SECTORS`. Module-level
/// because the contract const is `u64`.
pub const CRASH_DUMP_SECTORS_USIZE: usize = 32;

impl MemorySectorSink {
    /// Construct an empty in-memory sink.
    pub fn new() -> Self {
        Self {
            disk: [0u8; CRASH_DUMP_BYTES],
            recorded_lbas: [0u64; CRASH_DUMP_SECTORS_USIZE],
            recorded: 0,
        }
    }
}

impl Default for MemorySectorSink {
    fn default() -> Self {
        Self::new()
    }
}

impl SectorSink for MemorySectorSink {
    type Error = CrashDumpError;
    fn write_sector(&mut self, lba: u64, buf: &[u8; SECTOR_BYTES]) -> Result<(), CrashDumpError> {
        if lba < DUMP_START_LBA {
            return Err(CrashDumpError::LayoutOverflow);
        }
        let rel = (lba - DUMP_START_LBA) as usize;
        if rel >= CRASH_DUMP_SECTORS_USIZE {
            return Err(CrashDumpError::LayoutOverflow);
        }
        let off = rel * SECTOR_BYTES;
        self.disk[off..off + SECTOR_BYTES].copy_from_slice(buf);
        if self.recorded < CRASH_DUMP_SECTORS_USIZE {
            self.recorded_lbas[self.recorded] = lba;
            self.recorded += 1;
        }
        Ok(())
    }
}

/// The locked [`CrashDump`] implementation. Stateless — the trait
/// methods don't read or write any module-level state. Re-entry
/// protection is the caller's responsibility via [`set_dumped`].
pub struct PanicDumpImpl;

impl PanicDumpImpl {
    /// Assemble a dump from `ctx` into `buf` (which must be at least
    /// [`CRASH_DUMP_BYTES`] long), then write it sector-by-sector
    /// starting at [`DUMP_START_LBA`] via the supplied `sink`. Returns
    /// the LBA range that was actually written (always
    /// `DUMP_START_LBA .. DUMP_START_LBA + CRASH_DUMP_SECTORS`).
    ///
    /// Errors:
    /// - The contract layer's errors propagate from
    ///   [`Self::build_dump`].
    /// - Any sink error is mapped to
    ///   [`CrashDumpError::LayoutOverflow`].
    pub fn dump_to_sink<S: SectorSink>(
        ctx: &CrashContext<'_>,
        buf: &mut [u8],
        sink: &mut S,
    ) -> Result<(u64, u64), CrashDumpError> {
        <Self as CrashDump>::build_dump(ctx, buf)?;
        let mut sec_buf = [0u8; SECTOR_BYTES];
        let mut sec = 0u64;
        while sec < cuttle_contracts::CRASH_DUMP_SECTORS {
            let off = (sec as usize) * SECTOR_BYTES;
            sec_buf.copy_from_slice(&buf[off..off + SECTOR_BYTES]);
            sink.write_sector(DUMP_START_LBA + sec, &sec_buf)
                .map_err(|_| CrashDumpError::LayoutOverflow)?;
            sec += 1;
        }
        Ok((DUMP_START_LBA, DUMP_START_LBA + cuttle_contracts::CRASH_DUMP_SECTORS))
    }
}

impl CrashDump for PanicDumpImpl {
    const DUMP_START_LBA: u64 = DUMP_START_LBA;
    type Error = CrashDumpError;

    fn build_dump(ctx: &CrashContext<'_>, buf: &mut [u8]) -> Result<usize, CrashDumpError> {
        if buf.len() < CRASH_DUMP_BYTES {
            return Err(CrashDumpError::BufferTooSmall);
        }
        if ctx.backtrace.len() > CRASH_BACKTRACE_MAX {
            return Err(CrashDumpError::InputTooLarge);
        }
        if ctx.kmsg.len() > CRASH_KMSG_MAX {
            return Err(CrashDumpError::InputTooLarge);
        }

        // Zero the buffer up front. The serial-proof of "no stale
        // bytes" is byte-for-byte determinism: a dump for the same
        // ctx always emits identical 16 384 bytes.
        for b in &mut buf[..CRASH_DUMP_BYTES] {
            *b = 0;
        }

        // ---- header sector ----
        buf[crash_offsets::MAGIC..crash_offsets::MAGIC + 8].copy_from_slice(&CRASH_DUMP_MAGIC);
        write_u32_le(buf, crash_offsets::SCHEMA, CRASH_DUMP_SCHEMA);
        write_u64_le(buf, crash_offsets::WALL_UNIX, ctx.wall_unix);
        write_u64_le(buf, crash_offsets::TSC, ctx.tsc);
        copy_string_nul_padded(buf, crash_offsets::PANIC_LOC, CRASH_LOC_MAX, ctx.panic_loc);
        copy_string_nul_padded(buf, crash_offsets::MESSAGE, CRASH_MSG_MAX, ctx.message);
        write_u32_le(buf, crash_offsets::KMSG_LEN, ctx.kmsg.len() as u32);
        write_u32_le(
            buf,
            crash_offsets::BACKTRACE_COUNT,
            ctx.backtrace.len() as u32,
        );
        write_u32_le(buf, crash_offsets::REGISTER_COUNT, CRASH_REG_COUNT as u32);
        // CRC slot left zero until we compute it below.

        // ---- registers sector ----
        let mut i = 0usize;
        while i < CRASH_REG_COUNT {
            write_u64_le(buf, crash_offsets::REGISTERS + i * 8, ctx.registers[i]);
            i += 1;
        }

        // ---- backtrace sector ----
        let mut j = 0usize;
        while j < ctx.backtrace.len() {
            write_u64_le(buf, crash_offsets::BACKTRACE + j * 8, ctx.backtrace[j]);
            j += 1;
        }

        // ---- kmsg sectors ----
        if !ctx.kmsg.is_empty() {
            buf[crash_offsets::KMSG..crash_offsets::KMSG + ctx.kmsg.len()]
                .copy_from_slice(ctx.kmsg);
        }

        // ---- body CRC32-C ----
        let crc = crc32c(&buf[SECTOR_BYTES..CRASH_DUMP_BYTES]);
        write_u32_le(buf, crash_offsets::BODY_CRC32C, crc);

        Ok(CRASH_DUMP_BYTES)
    }

    fn parse_header(buf: &[u8]) -> Result<CrashDumpHeader<'_>, CrashDumpError> {
        if buf.len() < SECTOR_BYTES {
            return Err(CrashDumpError::BufferTooSmall);
        }
        if buf[crash_offsets::MAGIC..crash_offsets::MAGIC + 8] != CRASH_DUMP_MAGIC {
            return Err(CrashDumpError::MagicMismatch);
        }
        let schema = read_u32_le(buf, crash_offsets::SCHEMA);
        if schema != CRASH_DUMP_SCHEMA {
            return Err(CrashDumpError::SchemaMismatch);
        }
        let wall_unix = read_u64_le(buf, crash_offsets::WALL_UNIX);
        let tsc = read_u64_le(buf, crash_offsets::TSC);
        let panic_loc =
            read_nul_terminated_str(buf, crash_offsets::PANIC_LOC, CRASH_LOC_MAX)?;
        let message = read_nul_terminated_str(buf, crash_offsets::MESSAGE, CRASH_MSG_MAX)?;
        let kmsg_len = read_u32_le(buf, crash_offsets::KMSG_LEN);
        let backtrace_count = read_u32_le(buf, crash_offsets::BACKTRACE_COUNT);
        let register_count = read_u32_le(buf, crash_offsets::REGISTER_COUNT);
        let body_crc32c = read_u32_le(buf, crash_offsets::BODY_CRC32C);

        // Sanity-bound the count fields before the caller acts on
        // them — a header that claims `backtrace_count = u32::MAX`
        // would cause `extract_backtrace` to walk past the buffer.
        if (kmsg_len as usize) > CRASH_KMSG_MAX
            || (backtrace_count as usize) > CRASH_BACKTRACE_MAX
            || (register_count as usize) > CRASH_REG_COUNT
        {
            return Err(CrashDumpError::LayoutOverflow);
        }

        Ok(CrashDumpHeader {
            schema,
            wall_unix,
            tsc,
            panic_loc,
            message,
            kmsg_len,
            backtrace_count,
            register_count,
            body_crc32c,
        })
    }

    fn verify_crc(buf: &[u8]) -> Result<(), CrashDumpError> {
        if buf.len() < CRASH_DUMP_BYTES {
            return Err(CrashDumpError::BufferTooSmall);
        }
        // Magic must be right before we trust any header field.
        if buf[crash_offsets::MAGIC..crash_offsets::MAGIC + 8] != CRASH_DUMP_MAGIC {
            return Err(CrashDumpError::MagicMismatch);
        }
        let want = read_u32_le(buf, crash_offsets::BODY_CRC32C);
        let got = crc32c(&buf[SECTOR_BYTES..CRASH_DUMP_BYTES]);
        if want == got {
            Ok(())
        } else {
            Err(CrashDumpError::CrcMismatch)
        }
    }

    fn extract_registers(buf: &[u8], out: &mut [u64]) -> Result<usize, CrashDumpError> {
        if buf.len() < crash_offsets::BACKTRACE {
            return Err(CrashDumpError::BufferTooSmall);
        }
        let header = Self::parse_header(buf)?;
        let count = header.register_count as usize;
        if out.len() < count {
            return Err(CrashDumpError::BufferTooSmall);
        }
        let mut i = 0usize;
        while i < count {
            out[i] = read_u64_le(buf, crash_offsets::REGISTERS + i * 8);
            i += 1;
        }
        Ok(count)
    }

    fn extract_backtrace(buf: &[u8], out: &mut [u64]) -> Result<usize, CrashDumpError> {
        if buf.len() < crash_offsets::KMSG {
            return Err(CrashDumpError::BufferTooSmall);
        }
        let header = Self::parse_header(buf)?;
        let count = header.backtrace_count as usize;
        if out.len() < count {
            return Err(CrashDumpError::BufferTooSmall);
        }
        let mut i = 0usize;
        while i < count {
            out[i] = read_u64_le(buf, crash_offsets::BACKTRACE + i * 8);
            i += 1;
        }
        Ok(count)
    }

    fn extract_kmsg(buf: &[u8]) -> Result<&[u8], CrashDumpError> {
        if buf.len() < CRASH_DUMP_BYTES {
            return Err(CrashDumpError::BufferTooSmall);
        }
        let header = Self::parse_header(buf)?;
        let len = header.kmsg_len as usize;
        Ok(&buf[crash_offsets::KMSG..crash_offsets::KMSG + len])
    }
}

// ============================================================
// CRC32-C (Castagnoli) — polynomial 0x1EDC6F41 reversed = 0x82F63B78.
// Bit-by-bit reference implementation. Slow (~30 cycles/byte) but
// allocation-free and small. The contract is locked on the emitted
// value; future morph cycles may rewrite this as a table or
// slice-by-8 without affecting the wire surface.
// ============================================================

const CRC32C_POLY_REV: u32 = 0x82F6_3B78;

/// Compute CRC32-C (Castagnoli) over `bytes`. Returns the standard
/// `final_xor = !`-applied checksum.
pub fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    let mut i = 0usize;
    while i < bytes.len() {
        crc ^= bytes[i] as u32;
        let mut k = 0u32;
        while k < 8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (CRC32C_POLY_REV & mask);
            k += 1;
        }
        i += 1;
    }
    !crc
}

// ============================================================
// Byte helpers (allocation-free)
// ============================================================

fn write_u32_le(buf: &mut [u8], off: usize, val: u32) {
    let b = val.to_le_bytes();
    buf[off] = b[0];
    buf[off + 1] = b[1];
    buf[off + 2] = b[2];
    buf[off + 3] = b[3];
}

fn write_u64_le(buf: &mut [u8], off: usize, val: u64) {
    let b = val.to_le_bytes();
    let mut i = 0usize;
    while i < 8 {
        buf[off + i] = b[i];
        i += 1;
    }
}

fn read_u32_le(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

fn read_u64_le(buf: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        buf[off],
        buf[off + 1],
        buf[off + 2],
        buf[off + 3],
        buf[off + 4],
        buf[off + 5],
        buf[off + 6],
        buf[off + 7],
    ])
}

fn copy_string_nul_padded(buf: &mut [u8], off: usize, capacity: usize, src: &str) {
    let bytes = src.as_bytes();
    let take = if bytes.len() > capacity - 1 {
        capacity - 1
    } else {
        bytes.len()
    };
    let mut i = 0usize;
    while i < take {
        buf[off + i] = bytes[i];
        i += 1;
    }
    // Remainder already zero from the upfront fill in build_dump, but
    // belt-and-braces in case a caller reuses the buffer without
    // zeroing first.
    while i < capacity {
        buf[off + i] = 0;
        i += 1;
    }
}

fn read_nul_terminated_str(
    buf: &[u8],
    off: usize,
    capacity: usize,
) -> Result<&str, CrashDumpError> {
    if off + capacity > buf.len() {
        return Err(CrashDumpError::LayoutOverflow);
    }
    let slab = &buf[off..off + capacity];
    let mut end = 0usize;
    while end < slab.len() && slab[end] != 0 {
        end += 1;
    }
    // Lossy isn't an option in no_std without alloc; require valid
    // UTF-8 — the writer only stores `&str`, so this should always
    // succeed unless the buffer was tampered with.
    core::str::from_utf8(&slab[..end]).map_err(|_| CrashDumpError::LayoutOverflow)
}

// ============================================================
// Tests
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::CrashRegisters;

    fn sample_registers() -> CrashRegisters {
        let mut r = [0u64; CRASH_REG_COUNT];
        let mut i = 0usize;
        while i < CRASH_REG_COUNT {
            // Distinct, non-zero, non-monotonic values so a swap or
            // off-by-one in extract_registers would be visible.
            r[i] = 0xDEAD_BEEF_0000_0000 ^ ((i as u64) * 0x101_010_101);
            i += 1;
        }
        r
    }

    fn sample_backtrace() -> [u64; 5] {
        [
            0xFFFF_FFFF_8000_1234,
            0xFFFF_FFFF_8000_2345,
            0xFFFF_FFFF_8000_3456,
            0xFFFF_FFFF_8000_4567,
            0xFFFF_FFFF_8000_5678,
        ]
    }

    fn sample_kmsg() -> [u8; 128] {
        let mut k = [0u8; 128];
        let mut i = 0usize;
        while i < k.len() {
            k[i] = (i as u8).wrapping_mul(7);
            i += 1;
        }
        k
    }

    #[test]
    fn roundtrip_header_fields() {
        let regs = sample_registers();
        let bt = sample_backtrace();
        let kmsg = sample_kmsg();
        let ctx = CrashContext {
            wall_unix: 1_700_000_000,
            tsc: 0x0123_4567_89AB_CDEF,
            panic_loc: "kernel/main.rs:1234:5",
            message: "assertion failed: tcb.state == Established",
            registers: &regs,
            backtrace: &bt,
            kmsg: &kmsg,
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        let n = PanicDumpImpl::build_dump(&ctx, &mut buf).expect("build");
        assert_eq!(n, CRASH_DUMP_BYTES);

        let h = PanicDumpImpl::parse_header(&buf).expect("parse_header");
        assert_eq!(h.schema, CRASH_DUMP_SCHEMA);
        assert_eq!(h.wall_unix, 1_700_000_000);
        assert_eq!(h.tsc, 0x0123_4567_89AB_CDEF);
        assert_eq!(h.panic_loc, "kernel/main.rs:1234:5");
        assert_eq!(h.message, "assertion failed: tcb.state == Established");
        assert_eq!(h.kmsg_len as usize, kmsg.len());
        assert_eq!(h.backtrace_count as usize, bt.len());
        assert_eq!(h.register_count as usize, CRASH_REG_COUNT);
    }

    #[test]
    fn roundtrip_register_payload() {
        let regs = sample_registers();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x.rs:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();

        let mut out = [0u64; CRASH_REG_COUNT];
        let n = PanicDumpImpl::extract_registers(&buf, &mut out).unwrap();
        assert_eq!(n, CRASH_REG_COUNT);
        assert_eq!(out, regs);
    }

    #[test]
    fn roundtrip_backtrace_payload() {
        let regs = sample_registers();
        let bt = sample_backtrace();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x.rs:1:1",
            message: "m",
            registers: &regs,
            backtrace: &bt,
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();

        let mut out = [0u64; CRASH_BACKTRACE_MAX];
        let n = PanicDumpImpl::extract_backtrace(&buf, &mut out).unwrap();
        assert_eq!(n, bt.len());
        assert_eq!(&out[..n], &bt[..]);
        // Slots past the recorded count must be zero.
        let mut k = n;
        while k < CRASH_BACKTRACE_MAX {
            assert_eq!(out[k], 0, "trailing slot {} not zero", k);
            k += 1;
        }
    }

    #[test]
    fn roundtrip_kmsg_payload() {
        let regs = sample_registers();
        let kmsg = sample_kmsg();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x.rs:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &kmsg,
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        let recovered = PanicDumpImpl::extract_kmsg(&buf).unwrap();
        assert_eq!(recovered.len(), kmsg.len());
        assert_eq!(recovered, &kmsg[..]);
    }

    #[test]
    fn build_dump_is_deterministic() {
        let regs = sample_registers();
        let bt = sample_backtrace();
        let kmsg = sample_kmsg();
        let ctx = CrashContext {
            wall_unix: 42,
            tsc: 99,
            panic_loc: "a:1:1",
            message: "boom",
            registers: &regs,
            backtrace: &bt,
            kmsg: &kmsg,
        };
        let mut a = [0u8; CRASH_DUMP_BYTES];
        let mut b = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut a).unwrap();
        PanicDumpImpl::build_dump(&ctx, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn crc_verifies_clean_dump() {
        let regs = sample_registers();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &[1, 2, 3, 4, 5],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        PanicDumpImpl::verify_crc(&buf).expect("verify_crc clean");
    }

    #[test]
    fn crc_rejects_single_bit_flip_in_body() {
        let regs = sample_registers();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &[1, 2, 3, 4, 5],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        // Flip a byte in the kmsg payload region (sector 3+).
        buf[crash_offsets::KMSG + 2] ^= 1;
        assert_eq!(
            PanicDumpImpl::verify_crc(&buf),
            Err(CrashDumpError::CrcMismatch)
        );
    }

    #[test]
    fn crc_rejects_single_bit_flip_in_register_sector() {
        let regs = sample_registers();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        buf[crash_offsets::REGISTERS] ^= 0x80;
        assert_eq!(
            PanicDumpImpl::verify_crc(&buf),
            Err(CrashDumpError::CrcMismatch)
        );
    }

    #[test]
    fn parse_header_rejects_bad_magic() {
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        buf[0] = b'X';
        assert_eq!(
            PanicDumpImpl::parse_header(&buf),
            Err(CrashDumpError::MagicMismatch)
        );
    }

    #[test]
    fn parse_header_rejects_bad_schema() {
        let regs = sample_registers();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        // Corrupt schema → SchemaMismatch.
        write_u32_le(&mut buf, crash_offsets::SCHEMA, 99);
        assert_eq!(
            PanicDumpImpl::parse_header(&buf),
            Err(CrashDumpError::SchemaMismatch)
        );
    }

    #[test]
    fn build_dump_rejects_short_buffer() {
        let regs = sample_registers();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &[],
        };
        let mut small = [0u8; CRASH_DUMP_BYTES - 1];
        assert_eq!(
            PanicDumpImpl::build_dump(&ctx, &mut small),
            Err(CrashDumpError::BufferTooSmall)
        );
    }

    #[test]
    fn build_dump_rejects_oversized_backtrace() {
        let regs = sample_registers();
        let big_bt = [0u64; CRASH_BACKTRACE_MAX + 1];
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &big_bt,
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        assert_eq!(
            PanicDumpImpl::build_dump(&ctx, &mut buf),
            Err(CrashDumpError::InputTooLarge)
        );
    }

    #[test]
    fn build_dump_rejects_oversized_kmsg() {
        let regs = sample_registers();
        // Use a Box-free way: a const-sized array won't fit on the
        // stack here, so we test the boundary via slicing of a smaller
        // allocation extended past CRASH_KMSG_MAX with a fake length.
        // To keep no_std-clean, build a slice from a static array sized
        // exactly to MAX+1 — must live on the stack OR be heap'd. Use a
        // static const ZERO array.
        static OVERSIZED: [u8; CRASH_KMSG_MAX + 1] = [0u8; CRASH_KMSG_MAX + 1];
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &[],
            kmsg: &OVERSIZED[..],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        assert_eq!(
            PanicDumpImpl::build_dump(&ctx, &mut buf),
            Err(CrashDumpError::InputTooLarge)
        );
    }

    #[test]
    fn truncates_overlong_panic_loc() {
        let regs = sample_registers();
        // A panic_loc longer than CRASH_LOC_MAX should be truncated to
        // CRASH_LOC_MAX - 1 bytes (leaving room for the NUL).
        static LONG: [u8; CRASH_LOC_MAX * 2] = [b'A'; CRASH_LOC_MAX * 2];
        let s = core::str::from_utf8(&LONG[..]).unwrap();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: s,
            message: "ok",
            registers: &regs,
            backtrace: &[],
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        let h = PanicDumpImpl::parse_header(&buf).unwrap();
        assert_eq!(h.panic_loc.len(), CRASH_LOC_MAX - 1);
        // Every recovered byte is 'A'.
        for &b in h.panic_loc.as_bytes() {
            assert_eq!(b, b'A');
        }
    }

    #[test]
    fn truncates_overlong_message() {
        let regs = sample_registers();
        static LONG: [u8; CRASH_MSG_MAX * 2] = [b'M'; CRASH_MSG_MAX * 2];
        let s = core::str::from_utf8(&LONG[..]).unwrap();
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: s,
            registers: &regs,
            backtrace: &[],
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        let h = PanicDumpImpl::parse_header(&buf).unwrap();
        assert_eq!(h.message.len(), CRASH_MSG_MAX - 1);
    }

    #[test]
    fn sink_writes_every_sector_in_order() {
        let regs = sample_registers();
        let kmsg = sample_kmsg();
        let ctx = CrashContext {
            wall_unix: 7,
            tsc: 8,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &sample_backtrace(),
            kmsg: &kmsg,
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        let mut sink = MemorySectorSink::new();
        let (start, end) = PanicDumpImpl::dump_to_sink(&ctx, &mut buf, &mut sink).unwrap();
        assert_eq!(start, DUMP_START_LBA);
        assert_eq!(end, DUMP_START_LBA + cuttle_contracts::CRASH_DUMP_SECTORS);
        assert_eq!(sink.recorded, CRASH_DUMP_SECTORS_USIZE);
        // LBAs must be strictly increasing.
        let mut prev = sink.recorded_lbas[0];
        let mut i = 1usize;
        while i < sink.recorded {
            assert!(sink.recorded_lbas[i] > prev);
            prev = sink.recorded_lbas[i];
            i += 1;
        }
        // The bytes the sink received must equal the bytes the builder
        // emitted.
        assert_eq!(sink.disk, buf);
    }

    #[test]
    fn reentry_latch_one_shot() {
        // Note: latch is process-wide; we reset before/after to keep
        // this test independent of any other.
        reset_for_selftest();
        assert_eq!(set_dumped(), false, "first call sees latch=false");
        assert_eq!(set_dumped(), true, "second call sees latch=true");
        reset_for_selftest();
        assert_eq!(set_dumped(), false, "after reset, latch is fresh");
        reset_for_selftest();
    }

    #[test]
    fn crc32c_known_castagnoli_vectors() {
        // Castagnoli test vectors (rfc3309 appendix B / iSCSI):
        //   empty input  → 0
        //   "123456789"  → 0xE3069283
        //   32 × 0x00    → 0x8A9136AA
        //   32 × 0xFF    → 0x62A8AB43
        assert_eq!(crc32c(b""), 0);
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xFFu8; 32]), 0x62A8_AB43);
    }

    #[test]
    fn unused_backtrace_slots_are_zero() {
        let regs = sample_registers();
        let bt = [0xAAAA_AAAA_AAAA_AAAAu64; 2]; // only 2 frames
        let ctx = CrashContext {
            wall_unix: 1,
            tsc: 2,
            panic_loc: "x:1:1",
            message: "m",
            registers: &regs,
            backtrace: &bt,
            kmsg: &[],
        };
        let mut buf = [0u8; CRASH_DUMP_BYTES];
        PanicDumpImpl::build_dump(&ctx, &mut buf).unwrap();
        // Slot 0 + 1 should be 0xAAAA_AAAA_AAAA_AAAA; 2..64 zero.
        let mut i = 2usize;
        while i < CRASH_BACKTRACE_MAX {
            let v = read_u64_le(&buf, crash_offsets::BACKTRACE + i * 8);
            assert_eq!(v, 0, "slot {} not zero", i);
            i += 1;
        }
    }

    #[test]
    fn header_offsets_are_locked() {
        // Compile-time assertion via const evaluation that the locked
        // offsets in cuttle_contracts::crash_offsets land exactly
        // where this module's layout expects them.
        const _: () = assert!(crash_offsets::MAGIC == 0);
        const _: () = assert!(crash_offsets::SCHEMA == 8);
        const _: () = assert!(crash_offsets::WALL_UNIX == 16);
        const _: () = assert!(crash_offsets::TSC == 24);
        const _: () = assert!(crash_offsets::PANIC_LOC == 48);
        const _: () = assert!(crash_offsets::MESSAGE == 176);
        const _: () = assert!(crash_offsets::KMSG_LEN == 432);
        const _: () = assert!(crash_offsets::BACKTRACE_COUNT == 436);
        const _: () = assert!(crash_offsets::REGISTER_COUNT == 440);
        const _: () = assert!(crash_offsets::BODY_CRC32C == 444);
        const _: () = assert!(crash_offsets::REGISTERS == 512);
        const _: () = assert!(crash_offsets::BACKTRACE == 1024);
        const _: () = assert!(crash_offsets::KMSG == 1536);
    }
}
