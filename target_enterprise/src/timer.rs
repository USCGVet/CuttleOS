//! PIT (8253/8254) + CMOS RTC wire codec — TASK-062.
//!
//! Stateless I/O-port codecs for the IBM-PC Programmable Interval
//! Timer channel 0 and the MC146818 Real-Time Clock. Both traits
//! are exercised exclusively through a caller-supplied [`IoPort`]
//! surface so the same code path runs against:
//!
//! * a recording in-RAM harness (unit tests + kernel banners), and
//! * real `in`/`out` opcodes at bare-metal runtime (future kernel
//!   wiring — not in this iteration).
//!
//! # What this port covers
//!
//! * PIT command-byte builder + divisor encoding for channel 0
//!   mode-3 square-wave at a requested Hz.
//! * RTC UIP wait + consistency dance + BCD/binary + 12/24-hour
//!   decode + Gregorian → Unix epoch conversion.
//!
//! # What this port deliberately does NOT cover
//!
//! * IRQ 0 unmask / PIC programming.
//! * Tick counter / `on_tick` / `sleep_ms` (scheduler layer).
//! * HPET composition / boot-snapshot atomics.
//! * Century CMOS register (ACPI FADT) — classic 1980..=2079 window.
//! * NMI-disable bit on port 0x70 (left clear, matching every other
//!   modern OS).

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    IoPort, PicTimer, Rtc, RtcTimeView, TimerError, CMOS_DATA_PORT, CMOS_INDEX_PORT,
    PIT_BASE_HZ, PIT_CH0_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN, PIT_CMD_PORT, RTC_CONSISTENCY_PASSES,
    RTC_HOUR_PM, RTC_REG_DAY, RTC_REG_HOURS, RTC_REG_MINUTES, RTC_REG_MONTH, RTC_REG_SECONDS,
    RTC_REG_STATUS_A, RTC_REG_STATUS_B, RTC_REG_YEAR, RTC_STATUS_A_UIP, RTC_STATUS_B_24H,
    RTC_STATUS_B_BINARY, RTC_UIP_SPIN_BUDGET,
};

// ---------------------------------------------------------------------------
// Pure helpers (diversifiable internals; locked by trait invariants)
// ---------------------------------------------------------------------------

/// Compute the 16-bit PIT divisor for a requested tick rate.
///
/// `hz == 0` is rejected by the trait method; this free function
/// returns 0 for that case so pure arithmetic tests can exercise
/// the edge without port I/O.
#[inline]
pub fn pit_divisor(hz: u32) -> u16 {
    if hz == 0 {
        return 0;
    }
    (PIT_BASE_HZ / hz).clamp(1, u16::MAX as u32) as u16
}

/// Convert a packed BCD nibble-pair to binary.
/// `0x47` → `47`. No range check — caller owns the register content.
#[inline]
pub fn bcd_to_bin(b: u8) -> u8 {
    ((b >> 4) * 10) + (b & 0x0F)
}

/// Convert a binary value 0..=99 to packed BCD.
#[inline]
pub fn bin_to_bcd(b: u8) -> u8 {
    ((b / 10) << 4) | (b % 10)
}

/// Days in each month (non-leap). Index 1..=12; index 0 unused.
const DAYS_IN_MONTH: [u32; 13] = [0, 31, 28, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31];

/// Gregorian leap-year test.
#[inline]
pub fn is_leap(year: u32) -> bool {
    (year % 4 == 0 && year % 100 != 0) || (year % 400 == 0)
}

/// Convert Gregorian Y/M/D/H/Mi/S to Unix epoch seconds (UTC).
/// No timezone handling — the BIOS RTC is by convention UTC on a
/// server-grade host.
pub fn ymdhms_to_unix(y: u32, m: u32, d: u32, h: u32, mi: u32, s: u32) -> u64 {
    let mut days: u64 = 0;
    let mut year = 1970u32;
    while year < y {
        days += if is_leap(year) { 366 } else { 365 };
        year += 1;
    }
    let mut month = 1u32;
    while month < m {
        days += DAYS_IN_MONTH[month as usize] as u64;
        if month == 2 && is_leap(y) {
            days += 1;
        }
        month += 1;
    }
    days += (d.saturating_sub(1)) as u64;
    days * 86_400 + (h as u64) * 3600 + (mi as u64) * 60 + (s as u64)
}

/// Inverse of [`ymdhms_to_unix`]: split Unix epoch seconds into
/// Gregorian parts. Used by tests and the kernel banner for
/// round-trip proof.
pub fn split_unix(unix: u64) -> RtcTimeView {
    let secs_per_day: u64 = 86_400;
    let mut days = unix / secs_per_day;
    let rem = unix % secs_per_day;
    let hour = (rem / 3600) as u8;
    let minute = ((rem % 3600) / 60) as u8;
    let second = (rem % 60) as u8;

    let mut year: u32 = 1970;
    loop {
        let dy: u64 = if is_leap(year) { 366 } else { 365 };
        if days < dy {
            break;
        }
        days -= dy;
        year += 1;
    }
    let mut month: u8 = 1;
    loop {
        let mut dm: u64 = DAYS_IN_MONTH[month as usize] as u64;
        if month == 2 && is_leap(year) {
            dm += 1;
        }
        if days < dm {
            break;
        }
        days -= dm;
        month += 1;
    }
    RtcTimeView {
        year,
        month,
        day: (days + 1) as u8,
        hour,
        minute,
        second,
        unix,
    }
}

/// Decode a raw calendar register snapshot + status-B into an
/// [`RtcTimeView`]. Pure — no port I/O.
pub fn decode_raw(
    sec: u8,
    min: u8,
    hour_raw: u8,
    day: u8,
    mon: u8,
    year: u8,
    status_b: u8,
) -> RtcTimeView {
    let bcd = status_b & RTC_STATUS_B_BINARY == 0;
    let is_24h = status_b & RTC_STATUS_B_24H != 0;
    let conv = |b: u8| if bcd { bcd_to_bin(b) } else { b };

    let sec_v = conv(sec & 0x7F);
    let min_v = conv(min & 0x7F);
    let hour: u8 = {
        let pm = hour_raw & RTC_HOUR_PM != 0;
        let hr = conv(hour_raw & 0x7F);
        if is_24h {
            hr
        } else {
            // 12-hour: 12 AM == 0; otherwise add 12 for PM.
            let mut h = if hr == 12 { 0 } else { hr };
            if pm {
                h = h.wrapping_add(12);
            }
            h
        }
    };
    let day_v = conv(day);
    let mon_v = conv(mon);
    let year2 = conv(year);

    let year_full: u32 = if (year2 as u32) < 80 {
        2000 + year2 as u32
    } else {
        1900 + year2 as u32
    };

    let unix = ymdhms_to_unix(
        year_full,
        mon_v as u32,
        day_v as u32,
        hour as u32,
        min_v as u32,
        sec_v as u32,
    );
    RtcTimeView {
        year: year_full,
        month: mon_v,
        day: day_v,
        hour,
        minute: min_v,
        second: sec_v,
        unix,
    }
}

// ---------------------------------------------------------------------------
// Trait impls
// ---------------------------------------------------------------------------

/// Stateless PIT wire-codec impl.
pub struct PicTimerImpl;

/// Stateless RTC wire-codec impl.
pub struct RtcImpl;

impl PicTimer for PicTimerImpl {
    fn program_hz(port: &mut dyn IoPort, hz: u32) -> Result<u16, TimerError> {
        program_hz_impl(port, hz)
    }
}

impl Rtc for RtcImpl {
    fn read_time(port: &mut dyn IoPort) -> Result<RtcTimeView, TimerError> {
        read_time_impl(port)
    }
}

/// Program channel 0. Free function so the kernel banner can call it
/// by a fixed name (diversifier alias-safe).
pub fn program_hz_impl(port: &mut dyn IoPort, hz: u32) -> Result<u16, TimerError> {
    if hz == 0 {
        return Err(TimerError::ZeroHz);
    }
    let divisor = pit_divisor(hz);
    port.write_u8(PIT_CMD_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN);
    port.write_u8(PIT_CH0_PORT, (divisor & 0xFF) as u8);
    port.write_u8(PIT_CH0_PORT, (divisor >> 8) as u8);
    Ok(divisor)
}

/// Read CMOS register `reg` via the index/data port pair.
#[inline]
fn cmos_read(port: &mut dyn IoPort, reg: u8) -> u8 {
    // Leave bit 7 clear so the NMI-disable latch is preserved.
    port.write_u8(CMOS_INDEX_PORT, reg & 0x7F);
    port.read_u8(CMOS_DATA_PORT)
}

/// True while the RTC is mid-update.
#[inline]
fn update_in_progress(port: &mut dyn IoPort) -> bool {
    cmos_read(port, RTC_REG_STATUS_A) & RTC_STATUS_A_UIP != 0
}

/// One raw calendar snapshot (pre-decode).
#[derive(Clone, Copy, Default, PartialEq, Eq)]
struct RawTime {
    sec: u8,
    min: u8,
    hour: u8,
    day: u8,
    mon: u8,
    year: u8,
}

fn read_raw(port: &mut dyn IoPort) -> RawTime {
    RawTime {
        sec: cmos_read(port, RTC_REG_SECONDS),
        min: cmos_read(port, RTC_REG_MINUTES),
        hour: cmos_read(port, RTC_REG_HOURS),
        day: cmos_read(port, RTC_REG_DAY),
        mon: cmos_read(port, RTC_REG_MONTH),
        year: cmos_read(port, RTC_REG_YEAR),
    }
}

/// RTC read with UIP + consistency dance. Free function for the
/// kernel banner.
pub fn read_time_impl(port: &mut dyn IoPort) -> Result<RtcTimeView, TimerError> {
    // Wait out an in-progress update before sampling.
    let mut spin = 0u32;
    while update_in_progress(port) {
        spin += 1;
        if spin > RTC_UIP_SPIN_BUDGET {
            return Err(TimerError::UipTimeout);
        }
        core::hint::spin_loop();
    }

    // Read twice in a row; if anything changed mid-read the RTC
    // ticked and we re-read. In practice one extra pass is enough —
    // the RTC updates once a second.
    let mut prev = read_raw(port);
    let mut pass = 0u32;
    while pass < RTC_CONSISTENCY_PASSES {
        // Wait for UIP again in case it raised between raw reads.
        let mut spin2 = 0u32;
        while update_in_progress(port) {
            spin2 += 1;
            if spin2 > RTC_UIP_SPIN_BUDGET {
                return Err(TimerError::UipTimeout);
            }
            core::hint::spin_loop();
        }
        let cur = read_raw(port);
        if cur == prev {
            let status_b = cmos_read(port, RTC_REG_STATUS_B);
            return Ok(decode_raw(
                cur.sec, cur.min, cur.hour, cur.day, cur.mon, cur.year, status_b,
            ));
        }
        prev = cur;
        pass += 1;
    }
    Err(TimerError::InconsistentRead)
}

// ---------------------------------------------------------------------------
// Recording IoPort harness
// ---------------------------------------------------------------------------

/// One recorded write the driver issued via `write_u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortWrite {
    /// I/O port address.
    pub port: u16,
    /// Byte written.
    pub value: u8,
}

/// One recorded read the driver issued via `read_u8`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortRead {
    /// I/O port address.
    pub port: u16,
    /// Byte returned.
    pub value: u8,
}

/// Maximum number of scripted (port → value) entries a
/// [`RecordingIoPort`] can hold.
pub const RECORDING_PORT_CAPACITY: usize = 64;
/// Maximum number of write / read log entries.
pub const RECORDING_LOG_CAPACITY: usize = 256;

/// One scripted port value. On a `read_u8` of a matching port the
/// harness returns `value`. Writes update the script in place so
/// a test can observe RMW paths.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PortScript {
    /// Port address.
    pub port: u16,
    /// Value returned on read (and updated on write when
    /// `script_writes` is true).
    pub value: u8,
}

/// In-RAM [`IoPort`] impl backed by a fixed-capacity script table
/// + write/read logs. Used by unit tests and the kernel banner.
///
/// * **Read path**: linear scan of the script table. Misses return
///   `0xFF` (open-bus style) so an unscripted port is visible.
/// * **Write path**: appends to the write log; if a script entry
///   matches the port, its value is updated in place.
pub struct RecordingIoPort {
    scripts: [Option<PortScript>; RECORDING_PORT_CAPACITY],
    script_count: usize,
    writes: [Option<PortWrite>; RECORDING_LOG_CAPACITY],
    write_count: usize,
    reads: [Option<PortRead>; RECORDING_LOG_CAPACITY],
    read_count: usize,
}

impl Default for RecordingIoPort {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingIoPort {
    /// Construct an empty bus. Every read returns `0xFF` until
    /// scripted via [`set`](Self::set).
    pub const fn new() -> Self {
        Self {
            scripts: [None; RECORDING_PORT_CAPACITY],
            script_count: 0,
            writes: [None; RECORDING_LOG_CAPACITY],
            write_count: 0,
            reads: [None; RECORDING_LOG_CAPACITY],
            read_count: 0,
        }
    }

    /// Script `port` to return `value` on the next `read_u8`.
    /// Overwrites an existing entry. Returns `false` if full.
    pub fn set(&mut self, port: u16, value: u8) -> bool {
        let mut i = 0usize;
        while i < self.script_count {
            if let Some(s) = self.scripts[i] {
                if s.port == port {
                    self.scripts[i] = Some(PortScript { port, value });
                    return true;
                }
            }
            i += 1;
        }
        if self.script_count >= RECORDING_PORT_CAPACITY {
            return false;
        }
        self.scripts[self.script_count] = Some(PortScript { port, value });
        self.script_count += 1;
        true
    }

    /// Number of writes since construction.
    pub fn write_count(&self) -> usize {
        self.write_count
    }

    /// Look up the `idx`'th recorded write.
    pub fn write_at(&self, idx: usize) -> Option<PortWrite> {
        if idx >= self.write_count {
            return None;
        }
        self.writes[idx]
    }

    /// Number of reads since construction.
    pub fn read_count(&self) -> usize {
        self.read_count
    }

    /// Look up the `idx`'th recorded read.
    pub fn read_at(&self, idx: usize) -> Option<PortRead> {
        if idx >= self.read_count {
            return None;
        }
        self.reads[idx]
    }

    /// Clear write + read logs without touching the script table.
    pub fn clear_logs(&mut self) {
        self.write_count = 0;
        self.read_count = 0;
        let mut i = 0usize;
        while i < RECORDING_LOG_CAPACITY {
            self.writes[i] = None;
            self.reads[i] = None;
            i += 1;
        }
    }
}

impl IoPort for RecordingIoPort {
    fn write_u8(&mut self, port: u16, value: u8) {
        // Update script in place if present.
        let mut i = 0usize;
        let mut found = false;
        while i < self.script_count {
            if let Some(s) = self.scripts[i] {
                if s.port == port {
                    self.scripts[i] = Some(PortScript { port, value });
                    found = true;
                    break;
                }
            }
            i += 1;
        }
        // CMOS index port is a selector, not a data store — when the
        // driver writes an index we remember it under a private
        // "last index" script key so the next data-port read can
        // be demuxed. Handled via a special internal port below.
        let _ = found;

        if self.write_count < RECORDING_LOG_CAPACITY {
            self.writes[self.write_count] = Some(PortWrite { port, value });
            self.write_count += 1;
        }

        // Track the most recent CMOS index write so data-port reads
        // can be demuxed against per-register scripts. We store the
        // index under a synthetic key at port 0xFFFF.
        if port == CMOS_INDEX_PORT {
            let mut j = 0usize;
            let mut hit = false;
            while j < self.script_count {
                if let Some(s) = self.scripts[j] {
                    if s.port == 0xFFFF {
                        self.scripts[j] = Some(PortScript {
                            port: 0xFFFF,
                            value,
                        });
                        hit = true;
                        break;
                    }
                }
                j += 1;
            }
            if !hit && self.script_count < RECORDING_PORT_CAPACITY {
                self.scripts[self.script_count] = Some(PortScript {
                    port: 0xFFFF,
                    value,
                });
                self.script_count += 1;
            }
        }
    }

    fn read_u8(&mut self, port: u16) -> u8 {
        let value = if port == CMOS_DATA_PORT {
            // Demux: look up the last CMOS index, then look up the
            // scripted value for that register under a synthetic
            // port key `0x7000 | reg`.
            let mut last_idx: u8 = 0xFF;
            let mut j = 0usize;
            while j < self.script_count {
                if let Some(s) = self.scripts[j] {
                    if s.port == 0xFFFF {
                        last_idx = s.value;
                        break;
                    }
                }
                j += 1;
            }
            let key: u16 = 0x7000 | (last_idx as u16);
            let mut val = 0xFFu8;
            let mut k = 0usize;
            while k < self.script_count {
                if let Some(s) = self.scripts[k] {
                    if s.port == key {
                        val = s.value;
                        break;
                    }
                }
                k += 1;
            }
            val
        } else {
            let mut val = 0xFFu8;
            let mut i = 0usize;
            while i < self.script_count {
                if let Some(s) = self.scripts[i] {
                    if s.port == port {
                        val = s.value;
                        break;
                    }
                }
                i += 1;
            }
            val
        };

        if self.read_count < RECORDING_LOG_CAPACITY {
            self.reads[self.read_count] = Some(PortRead { port, value });
            self.read_count += 1;
        }
        value
    }
}

impl RecordingIoPort {
    /// Script a CMOS register value. On a subsequent index-select
    /// of `reg` + data-port read, returns `value`.
    pub fn set_cmos(&mut self, reg: u8, value: u8) -> bool {
        let key: u16 = 0x7000 | (reg as u16);
        self.set(key, value)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::{PicTimer, Rtc};

    // ---- constant locks ---------------------------------------------------

    #[test]
    fn pit_constants_match_ibm_pc() {
        assert_eq!(PIT_CMD_PORT, 0x43);
        assert_eq!(PIT_CH0_PORT, 0x40);
        assert_eq!(PIT_BASE_HZ, 1_193_182);
        assert_eq!(PIT_CMD_CH0_LOHI_MODE3_BIN, 0x36);
    }

    #[test]
    fn rtc_constants_match_mc146818() {
        assert_eq!(CMOS_INDEX_PORT, 0x70);
        assert_eq!(CMOS_DATA_PORT, 0x71);
        assert_eq!(RTC_REG_SECONDS, 0x00);
        assert_eq!(RTC_REG_MINUTES, 0x02);
        assert_eq!(RTC_REG_HOURS, 0x04);
        assert_eq!(RTC_REG_DAY, 0x07);
        assert_eq!(RTC_REG_MONTH, 0x08);
        assert_eq!(RTC_REG_YEAR, 0x09);
        assert_eq!(RTC_REG_STATUS_A, 0x0A);
        assert_eq!(RTC_REG_STATUS_B, 0x0B);
        assert_eq!(RTC_STATUS_A_UIP, 0x80);
        assert_eq!(RTC_STATUS_B_24H, 0x02);
        assert_eq!(RTC_STATUS_B_BINARY, 0x04);
        assert_eq!(RTC_HOUR_PM, 0x80);
    }

    // ---- PIT divisor arithmetic -------------------------------------------

    #[test]
    fn pit_divisor_1khz() {
        // 1_193_182 / 1000 = 1193
        assert_eq!(pit_divisor(1000), 1193);
    }

    #[test]
    fn pit_divisor_100hz() {
        // 1_193_182 / 100 = 11931
        assert_eq!(pit_divisor(100), 11_931);
    }

    #[test]
    fn pit_divisor_zero_returns_zero() {
        assert_eq!(pit_divisor(0), 0);
    }

    #[test]
    fn pit_divisor_clamps_to_u16_max_on_hz_1() {
        // 1_193_182 / 1 = 1_193_182 > u16::MAX → clamp to 65535
        assert_eq!(pit_divisor(1), u16::MAX);
    }

    #[test]
    fn pit_divisor_clamps_to_one_on_huge_hz() {
        // hz larger than base → floor division = 0 → clamp to 1
        assert_eq!(pit_divisor(PIT_BASE_HZ * 2), 1);
    }

    // ---- PIT program_hz byte sequence -------------------------------------

    #[test]
    fn program_hz_zero_is_error_no_writes() {
        let mut port = RecordingIoPort::new();
        let r = PicTimerImpl::program_hz(&mut port, 0);
        assert_eq!(r, Err(TimerError::ZeroHz));
        assert_eq!(port.write_count(), 0);
    }

    #[test]
    fn program_hz_1khz_byte_sequence() {
        let mut port = RecordingIoPort::new();
        let div = PicTimerImpl::program_hz(&mut port, 1000).unwrap();
        assert_eq!(div, 1193);
        assert_eq!(port.write_count(), 3);
        let w0 = port.write_at(0).unwrap();
        assert_eq!(w0.port, PIT_CMD_PORT);
        assert_eq!(w0.value, PIT_CMD_CH0_LOHI_MODE3_BIN);
        let w1 = port.write_at(1).unwrap();
        assert_eq!(w1.port, PIT_CH0_PORT);
        assert_eq!(w1.value, (1193u16 & 0xFF) as u8); // 0xA9
        let w2 = port.write_at(2).unwrap();
        assert_eq!(w2.port, PIT_CH0_PORT);
        assert_eq!(w2.value, (1193u16 >> 8) as u8); // 0x04
    }

    #[test]
    fn program_hz_100hz_byte_sequence() {
        let mut port = RecordingIoPort::new();
        let div = PicTimerImpl::program_hz(&mut port, 100).unwrap();
        assert_eq!(div, 11_931);
        assert_eq!(port.write_count(), 3);
        assert_eq!(port.write_at(0).unwrap().value, 0x36);
        assert_eq!(port.write_at(1).unwrap().value, (11_931u16 & 0xFF) as u8);
        assert_eq!(port.write_at(2).unwrap().value, (11_931u16 >> 8) as u8);
    }

    // ---- BCD helpers ------------------------------------------------------

    #[test]
    fn bcd_to_bin_round_trip() {
        assert_eq!(bcd_to_bin(0x00), 0);
        assert_eq!(bcd_to_bin(0x09), 9);
        assert_eq!(bcd_to_bin(0x10), 10);
        assert_eq!(bcd_to_bin(0x47), 47);
        assert_eq!(bcd_to_bin(0x59), 59);
        assert_eq!(bcd_to_bin(0x23), 23);
        assert_eq!(bin_to_bcd(47), 0x47);
        assert_eq!(bin_to_bcd(0), 0x00);
        assert_eq!(bin_to_bcd(59), 0x59);
    }

    // ---- Gregorian / Unix -------------------------------------------------

    #[test]
    fn ymdhms_to_unix_epoch() {
        assert_eq!(ymdhms_to_unix(1970, 1, 1, 0, 0, 0), 0);
    }

    #[test]
    fn ymdhms_to_unix_known_dates() {
        // 2020-01-01 00:00:00 UTC
        assert_eq!(ymdhms_to_unix(2020, 1, 1, 0, 0, 0), 1_577_836_800);
        // 2026-03-15 12:34:56 UTC
        // Verified offline: 1773578096
        assert_eq!(ymdhms_to_unix(2026, 3, 15, 12, 34, 56), 1_773_578_096);
    }

    #[test]
    fn leap_year_feb29_counts() {
        // 2020 is leap; 2020-03-01 00:00:00 = 2020-01-01 + 31 + 29 days
        let mar1 = ymdhms_to_unix(2020, 3, 1, 0, 0, 0);
        let jan1 = ymdhms_to_unix(2020, 1, 1, 0, 0, 0);
        assert_eq!(mar1 - jan1, (31 + 29) * 86_400);
    }

    #[test]
    fn split_unix_round_trips() {
        let cases = [
            0u64,
            1_577_836_800, // 2020-01-01
            1_773_578_096, // 2026-03-15 12:34:56
            1_000_000_000, // 2001-09-09 01:46:40
        ];
        for &u in &cases {
            let parts = split_unix(u);
            let back = ymdhms_to_unix(
                parts.year,
                parts.month as u32,
                parts.day as u32,
                parts.hour as u32,
                parts.minute as u32,
                parts.second as u32,
            );
            assert_eq!(back, u, "round-trip failed for unix={}", u);
            assert_eq!(parts.unix, u);
        }
    }

    #[test]
    fn is_leap_gregorian_rules() {
        assert!(is_leap(2000)); // divisible by 400
        assert!(!is_leap(1900)); // divisible by 100 not 400
        assert!(is_leap(2020));
        assert!(!is_leap(2021));
        assert!(is_leap(2024));
    }

    // ---- decode_raw (pure, no ports) --------------------------------------

    #[test]
    fn decode_raw_bcd_24h_fixture() {
        // 2026-03-15 12:34:56, BCD, 24-hour
        // status_B: 24h set, binary clear → 0x02
        let t = decode_raw(
            0x56, // sec
            0x34, // min
            0x12, // hour
            0x15, // day
            0x03, // mon
            0x26, // year
            RTC_STATUS_B_24H,
        );
        assert_eq!(t.year, 2026);
        assert_eq!(t.month, 3);
        assert_eq!(t.day, 15);
        assert_eq!(t.hour, 12);
        assert_eq!(t.minute, 34);
        assert_eq!(t.second, 56);
        assert_eq!(t.unix, 1_773_578_096);
    }

    #[test]
    fn decode_raw_binary_24h() {
        let t = decode_raw(
            56, 34, 12, 15, 3, 26,
            RTC_STATUS_B_24H | RTC_STATUS_B_BINARY,
        );
        assert_eq!(t.year, 2026);
        assert_eq!(t.hour, 12);
        assert_eq!(t.second, 56);
        assert_eq!(t.unix, 1_773_578_096);
    }

    #[test]
    fn decode_raw_bcd_12h_pm() {
        // 3:00:00 PM in 12-hour BCD with PM bit → hour = 15
        let t = decode_raw(
            0x00,
            0x00,
            0x03 | RTC_HOUR_PM, // 3 PM
            0x01,
            0x01,
            0x20, // 2020-01-01
            0x00, // 12-hour, BCD
        );
        assert_eq!(t.year, 2020);
        assert_eq!(t.hour, 15);
        assert_eq!(t.unix, ymdhms_to_unix(2020, 1, 1, 15, 0, 0));
    }

    #[test]
    fn decode_raw_bcd_12h_midnight() {
        // 12:00:00 AM → hour = 0
        let t = decode_raw(
            0x00,
            0x00,
            0x12, // 12 AM (no PM bit)
            0x01,
            0x01,
            0x20,
            0x00,
        );
        assert_eq!(t.hour, 0);
    }

    #[test]
    fn decode_raw_bcd_12h_noon() {
        // 12:00:00 PM → hour = 12
        let t = decode_raw(
            0x00,
            0x00,
            0x12 | RTC_HOUR_PM,
            0x01,
            0x01,
            0x20,
            0x00,
        );
        assert_eq!(t.hour, 12);
    }

    #[test]
    fn decode_raw_year_window_pre_80_is_20xx() {
        // Binary mode: year byte is the literal two-digit year.
        let t2 = decode_raw(0, 0, 0, 1, 1, 79, RTC_STATUS_B_BINARY | RTC_STATUS_B_24H);
        assert_eq!(t2.year, 2079);
        let t3 = decode_raw(0, 0, 0, 1, 1, 80, RTC_STATUS_B_BINARY | RTC_STATUS_B_24H);
        assert_eq!(t3.year, 1980);
        // BCD mode: 0x26 → 26 → 2026
        let t4 = decode_raw(0, 0, 0, 1, 1, 0x26, RTC_STATUS_B_24H);
        assert_eq!(t4.year, 2026);
    }

    // ---- RTC read_time via recording harness ------------------------------

    /// Script a complete, consistent BCD 24-hour RTC fixture for
    /// 2026-03-15 12:34:56 with UIP clear.
    fn script_banner_fixture(port: &mut RecordingIoPort) {
        port.set_cmos(RTC_REG_STATUS_A, 0x00); // UIP clear
        port.set_cmos(RTC_REG_STATUS_B, RTC_STATUS_B_24H); // BCD + 24h
        port.set_cmos(RTC_REG_SECONDS, 0x56);
        port.set_cmos(RTC_REG_MINUTES, 0x34);
        port.set_cmos(RTC_REG_HOURS, 0x12);
        port.set_cmos(RTC_REG_DAY, 0x15);
        port.set_cmos(RTC_REG_MONTH, 0x03);
        port.set_cmos(RTC_REG_YEAR, 0x26);
    }

    #[test]
    fn read_time_banner_fixture() {
        let mut port = RecordingIoPort::new();
        script_banner_fixture(&mut port);
        let t = RtcImpl::read_time(&mut port).unwrap();
        assert_eq!(t.year, 2026);
        assert_eq!(t.month, 3);
        assert_eq!(t.day, 15);
        assert_eq!(t.hour, 12);
        assert_eq!(t.minute, 34);
        assert_eq!(t.second, 56);
        assert_eq!(t.unix, 1_773_578_096);
    }

    #[test]
    fn read_time_uip_timeout() {
        let mut port = RecordingIoPort::new();
        // Status A always has UIP set; never clears.
        port.set_cmos(RTC_REG_STATUS_A, RTC_STATUS_A_UIP);
        let r = RtcImpl::read_time(&mut port);
        assert_eq!(r, Err(TimerError::UipTimeout));
    }

    #[test]
    fn read_time_binary_mode_fixture() {
        let mut port = RecordingIoPort::new();
        port.set_cmos(RTC_REG_STATUS_A, 0x00);
        port.set_cmos(RTC_REG_STATUS_B, RTC_STATUS_B_24H | RTC_STATUS_B_BINARY);
        port.set_cmos(RTC_REG_SECONDS, 56);
        port.set_cmos(RTC_REG_MINUTES, 34);
        port.set_cmos(RTC_REG_HOURS, 12);
        port.set_cmos(RTC_REG_DAY, 15);
        port.set_cmos(RTC_REG_MONTH, 3);
        port.set_cmos(RTC_REG_YEAR, 26);
        let t = RtcImpl::read_time(&mut port).unwrap();
        assert_eq!(t.unix, 1_773_578_096);
    }

    #[test]
    fn read_time_issues_index_then_data_pairs() {
        let mut port = RecordingIoPort::new();
        script_banner_fixture(&mut port);
        let _ = RtcImpl::read_time(&mut port).unwrap();
        // At least one write to the index port must have happened.
        let mut saw_index = false;
        let mut i = 0usize;
        while i < port.write_count() {
            if let Some(w) = port.write_at(i) {
                if w.port == CMOS_INDEX_PORT {
                    saw_index = true;
                    break;
                }
            }
            i += 1;
        }
        assert!(saw_index, "expected CMOS index port writes");
        assert!(port.read_count() > 0, "expected CMOS data port reads");
    }

    #[test]
    fn trait_surface_pic_timer_and_rtc_object_safe_via_dyn() {
        // Compile-time: methods take &mut dyn IoPort.
        let mut port = RecordingIoPort::new();
        let _ = PicTimerImpl::program_hz(&mut port, 1000);
        script_banner_fixture(&mut port);
        let _ = RtcImpl::read_time(&mut port);
    }

    #[test]
    fn recording_port_open_bus_returns_ff() {
        let mut port = RecordingIoPort::new();
        assert_eq!(port.read_u8(0x1234), 0xFF);
    }

    #[test]
    fn program_hz_via_free_function_matches_trait() {
        let mut a = RecordingIoPort::new();
        let mut b = RecordingIoPort::new();
        let da = program_hz_impl(&mut a, 1000).unwrap();
        let db = PicTimerImpl::program_hz(&mut b, 1000).unwrap();
        assert_eq!(da, db);
        assert_eq!(a.write_count(), b.write_count());
        assert_eq!(a.write_at(0), b.write_at(0));
        assert_eq!(a.write_at(1), b.write_at(1));
        assert_eq!(a.write_at(2), b.write_at(2));
    }
}
