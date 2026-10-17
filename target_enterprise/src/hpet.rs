//! HPET MMIO wire codec — TASK-067.
//!
//! Capability decode, enable/disable, main-counter read, timer-0
//! periodic program over [`MmioRegBus`]. Recording harness for tests.

#![allow(missing_docs)]
#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    Hpet, HpetCaps, HpetError, MmioRegBus, HPET_CAP_COUNT_SIZE_64, HPET_CFG_ENABLE,
    HPET_REG_CAP, HPET_REG_CONFIG, HPET_REG_MAIN_COUNTER, HPET_REG_TIMER0_COMPARATOR,
    HPET_REG_TIMER0_CONFIG, HPET_TN_INT_ENB, HPET_TN_TYPE_PERIODIC, HPET_TN_VAL_SET,
};

/// Stateless HPET codec.
pub struct HpetImpl;

impl Hpet for HpetImpl {
    fn read_caps(bus: &mut dyn MmioRegBus) -> Result<HpetCaps, HpetError> {
        read_caps_impl(bus)
    }
    fn enable(bus: &mut dyn MmioRegBus) {
        enable_impl(bus)
    }
    fn disable(bus: &mut dyn MmioRegBus) {
        disable_impl(bus)
    }
    fn read_counter(bus: &mut dyn MmioRegBus) -> u64 {
        read_counter_impl(bus)
    }
    fn program_timer0_periodic(
        bus: &mut dyn MmioRegBus,
        comparator: u64,
    ) -> Result<u32, HpetError> {
        program_timer0_periodic_impl(bus, comparator)
    }
    fn ms_to_ticks(period_fs: u32, period_ms: u32) -> Result<u64, HpetError> {
        ms_to_ticks_impl(period_fs, period_ms)
    }
}

pub fn read_caps_impl(bus: &mut dyn MmioRegBus) -> Result<HpetCaps, HpetError> {
    let lo = bus.read_u32(HPET_REG_CAP);
    let hi = bus.read_u32(HPET_REG_CAP + 4);
    let count_size_64 = (lo & HPET_CAP_COUNT_SIZE_64) != 0;
    if !count_size_64 {
        return Err(HpetError::Not64Bit);
    }
    let period_fs = hi; // bits 32..63 of CAP = high dword
    if period_fs == 0 {
        return Err(HpetError::BadPeriod);
    }
    let vendor_id = ((lo >> 16) & 0xFFFF) as u16;
    let num_timers = (((lo >> 8) & 0x1F) as u8).wrapping_add(1);
    Ok(HpetCaps {
        period_fs,
        count_size_64,
        vendor_id,
        num_timers,
    })
}

pub fn enable_impl(bus: &mut dyn MmioRegBus) {
    let cur = bus.read_u32(HPET_REG_CONFIG);
    bus.write_u32(HPET_REG_CONFIG, cur | HPET_CFG_ENABLE);
}

pub fn disable_impl(bus: &mut dyn MmioRegBus) {
    let cur = bus.read_u32(HPET_REG_CONFIG);
    bus.write_u32(HPET_REG_CONFIG, cur & !HPET_CFG_ENABLE);
}

pub fn read_counter_impl(bus: &mut dyn MmioRegBus) -> u64 {
    let lo = bus.read_u32(HPET_REG_MAIN_COUNTER) as u64;
    let hi = bus.read_u32(HPET_REG_MAIN_COUNTER + 4) as u64;
    (hi << 32) | lo
}

pub fn program_timer0_periodic_impl(
    bus: &mut dyn MmioRegBus,
    comparator: u64,
) -> Result<u32, HpetError> {
    if comparator == 0 {
        return Err(HpetError::BadInterval);
    }
    let cfg = HPET_TN_INT_ENB | HPET_TN_TYPE_PERIODIC | HPET_TN_VAL_SET;
    bus.write_u32(HPET_REG_TIMER0_CONFIG, cfg);
    bus.write_u32(HPET_REG_TIMER0_COMPARATOR, comparator as u32);
    bus.write_u32(HPET_REG_TIMER0_COMPARATOR + 4, (comparator >> 32) as u32);
    // Re-clear VAL_SET so subsequent writes don't re-set accumulator.
    let cfg_run = HPET_TN_INT_ENB | HPET_TN_TYPE_PERIODIC;
    bus.write_u32(HPET_REG_TIMER0_CONFIG, cfg_run);
    Ok(cfg_run)
}

/// `ticks = (period_ms * 10^12) / period_fs`  because 1 ms = 10^12 fs.
pub fn ms_to_ticks_impl(period_fs: u32, period_ms: u32) -> Result<u64, HpetError> {
    if period_fs == 0 || period_ms == 0 {
        return Err(HpetError::BadPeriod);
    }
    let num = (period_ms as u128) * 1_000_000_000_000u128;
    let ticks = num / (period_fs as u128);
    if ticks == 0 || ticks > u64::MAX as u128 {
        return Err(HpetError::BadInterval);
    }
    Ok(ticks as u64)
}

// ---------- Recording MMIO harness ----------

/// Max scripted dword slots.
pub const HPET_BUS_CAP: usize = 64;

/// In-RAM [`MmioRegBus`] with write log.
pub struct RecordingHpetBus {
    regs: [u32; HPET_BUS_CAP],
    writes: [(usize, u32); HPET_BUS_CAP],
    write_count: usize,
}

impl Default for RecordingHpetBus {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingHpetBus {
    pub const fn new() -> Self {
        Self {
            regs: [0; HPET_BUS_CAP],
            writes: [(0, 0); HPET_BUS_CAP],
            write_count: 0,
        }
    }
    /// Script a 32-bit register value at byte offset.
    pub fn set_u32(&mut self, off: usize, val: u32) {
        let idx = off / 4;
        if idx < HPET_BUS_CAP {
            self.regs[idx] = val;
        }
    }
    pub fn write_count(&self) -> usize {
        self.write_count
    }
    pub fn write_at(&self, i: usize) -> Option<(usize, u32)> {
        if i < self.write_count {
            Some(self.writes[i])
        } else {
            None
        }
    }
    /// Install a canonical CAP: 64-bit counter, period_fs, vendor.
    pub fn script_canonical_cap(&mut self, period_fs: u32, vendor: u16, timers_m1: u8) {
        let lo = HPET_CAP_COUNT_SIZE_64
            | ((vendor as u32) << 16)
            | (((timers_m1 as u32) & 0x1F) << 8);
        self.set_u32(HPET_REG_CAP, lo);
        self.set_u32(HPET_REG_CAP + 4, period_fs);
    }
}

impl MmioRegBus for RecordingHpetBus {
    fn read_u32(&mut self, offset: usize) -> u32 {
        let idx = offset / 4;
        if idx < HPET_BUS_CAP {
            self.regs[idx]
        } else {
            0
        }
    }
    fn write_u32(&mut self, offset: usize, value: u32) {
        let idx = offset / 4;
        if idx < HPET_BUS_CAP {
            self.regs[idx] = value;
        }
        if self.write_count < HPET_BUS_CAP {
            self.writes[self.write_count] = (offset, value);
            self.write_count += 1;
        }
    }
}

/// Banner fixture period: 69_841_279 fs ≈ 14.31818 MHz (classic).
pub const BANNER_PERIOD_FS: u32 = 69_841_279;
/// Banner programs 1 ms periodic.
pub const BANNER_PERIOD_MS: u32 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Hpet;

    #[test]
    fn constants() {
        assert_eq!(HPET_REG_CAP, 0x000);
        assert_eq!(HPET_REG_CONFIG, 0x010);
        assert_eq!(HPET_REG_MAIN_COUNTER, 0x0F0);
        assert_eq!(HPET_REG_TIMER0_CONFIG, 0x100);
        assert_eq!(HPET_REG_TIMER0_COMPARATOR, 0x108);
    }

    #[test]
    fn read_caps_canonical() {
        let mut bus = RecordingHpetBus::new();
        bus.script_canonical_cap(BANNER_PERIOD_FS, 0x8086, 2);
        let c = HpetImpl::read_caps(&mut bus).unwrap();
        assert!(c.count_size_64);
        assert_eq!(c.period_fs, BANNER_PERIOD_FS);
        assert_eq!(c.vendor_id, 0x8086);
        assert_eq!(c.num_timers, 3);
    }

    #[test]
    fn read_caps_rejects_32bit() {
        let mut bus = RecordingHpetBus::new();
        bus.set_u32(HPET_REG_CAP, 0); // no 64-bit bit
        bus.set_u32(HPET_REG_CAP + 4, 1000);
        assert_eq!(HpetImpl::read_caps(&mut bus), Err(HpetError::Not64Bit));
    }

    #[test]
    fn read_caps_rejects_zero_period() {
        let mut bus = RecordingHpetBus::new();
        bus.set_u32(HPET_REG_CAP, HPET_CAP_COUNT_SIZE_64);
        bus.set_u32(HPET_REG_CAP + 4, 0);
        assert_eq!(HpetImpl::read_caps(&mut bus), Err(HpetError::BadPeriod));
    }

    #[test]
    fn enable_sets_bit0() {
        let mut bus = RecordingHpetBus::new();
        HpetImpl::enable(&mut bus);
        assert_eq!(bus.read_u32(HPET_REG_CONFIG) & HPET_CFG_ENABLE, HPET_CFG_ENABLE);
    }

    #[test]
    fn disable_clears_bit0() {
        let mut bus = RecordingHpetBus::new();
        bus.set_u32(HPET_REG_CONFIG, HPET_CFG_ENABLE | 0x10);
        HpetImpl::disable(&mut bus);
        assert_eq!(bus.read_u32(HPET_REG_CONFIG) & HPET_CFG_ENABLE, 0);
        assert_eq!(bus.read_u32(HPET_REG_CONFIG) & 0x10, 0x10);
    }

    #[test]
    fn read_counter_64() {
        let mut bus = RecordingHpetBus::new();
        bus.set_u32(HPET_REG_MAIN_COUNTER, 0x11223344);
        bus.set_u32(HPET_REG_MAIN_COUNTER + 4, 0xAABBCCDD);
        assert_eq!(
            HpetImpl::read_counter(&mut bus),
            0xAABBCCDD_11223344
        );
    }

    #[test]
    fn ms_to_ticks_1ms() {
        let t = HpetImpl::ms_to_ticks(BANNER_PERIOD_FS, 1).unwrap();
        assert!(t > 0);
        // 10^12 / 69841279 ≈ 14318
        assert_eq!(t, 1_000_000_000_000u64 / BANNER_PERIOD_FS as u64);
    }

    #[test]
    fn ms_to_ticks_rejects_zero() {
        assert!(HpetImpl::ms_to_ticks(0, 1).is_err());
        assert!(HpetImpl::ms_to_ticks(100, 0).is_err());
    }

    #[test]
    fn program_timer0_write_sequence() {
        let mut bus = RecordingHpetBus::new();
        let cmp = HpetImpl::ms_to_ticks(BANNER_PERIOD_FS, 1).unwrap();
        let cfg = HpetImpl::program_timer0_periodic(&mut bus, cmp).unwrap();
        assert_eq!(cfg, HPET_TN_INT_ENB | HPET_TN_TYPE_PERIODIC);
        // First write: config with VAL_SET
        let w0 = bus.write_at(0).unwrap();
        assert_eq!(w0.0, HPET_REG_TIMER0_CONFIG);
        assert_eq!(
            w0.1,
            HPET_TN_INT_ENB | HPET_TN_TYPE_PERIODIC | HPET_TN_VAL_SET
        );
        // Comparator lo/hi
        let w1 = bus.write_at(1).unwrap();
        assert_eq!(w1.0, HPET_REG_TIMER0_COMPARATOR);
        assert_eq!(w1.1, cmp as u32);
        let w2 = bus.write_at(2).unwrap();
        assert_eq!(w2.0, HPET_REG_TIMER0_COMPARATOR + 4);
        assert_eq!(w2.1, (cmp >> 32) as u32);
        // Clear VAL_SET
        let w3 = bus.write_at(3).unwrap();
        assert_eq!(w3.1, cfg);
    }

    #[test]
    fn program_rejects_zero_cmp() {
        let mut bus = RecordingHpetBus::new();
        assert_eq!(
            HpetImpl::program_timer0_periodic(&mut bus, 0),
            Err(HpetError::BadInterval)
        );
    }

    #[test]
    fn banner_scenario() {
        let mut bus = RecordingHpetBus::new();
        bus.script_canonical_cap(BANNER_PERIOD_FS, 0x8086, 2);
        let caps = HpetImpl::read_caps(&mut bus).unwrap();
        assert_eq!(caps.period_fs, BANNER_PERIOD_FS);
        HpetImpl::enable(&mut bus);
        let cmp = HpetImpl::ms_to_ticks(caps.period_fs, BANNER_PERIOD_MS).unwrap();
        let _ = HpetImpl::program_timer0_periodic(&mut bus, cmp).unwrap();
        assert!(bus.write_count() >= 4);
    }

    #[test]
    fn free_matches_trait() {
        let mut a = RecordingHpetBus::new();
        let mut b = RecordingHpetBus::new();
        a.script_canonical_cap(1000, 1, 0);
        b.script_canonical_cap(1000, 1, 0);
        assert_eq!(
            read_caps_impl(&mut a).unwrap(),
            HpetImpl::read_caps(&mut b).unwrap()
        );
    }

    #[test]
    fn enable_preserves_other_bits() {
        let mut bus = RecordingHpetBus::new();
        bus.set_u32(HPET_REG_CONFIG, 0x20);
        HpetImpl::enable(&mut bus);
        assert_eq!(bus.read_u32(HPET_REG_CONFIG), 0x20 | HPET_CFG_ENABLE);
    }

    #[test]
    fn ms_to_ticks_10ms() {
        let t10 = HpetImpl::ms_to_ticks(BANNER_PERIOD_FS, 10).unwrap();
        // Independent of 1ms rounding: 10 * 1e12 / period_fs
        assert_eq!(t10, 10_000_000_000_000u64 / BANNER_PERIOD_FS as u64);
        assert!(t10 > 100_000);
    }

    #[test]
    fn counter_zero_default() {
        let mut bus = RecordingHpetBus::new();
        assert_eq!(HpetImpl::read_counter(&mut bus), 0);
    }

    #[test]
    fn num_timers_zero_field_means_one() {
        let mut bus = RecordingHpetBus::new();
        bus.set_u32(HPET_REG_CAP, HPET_CAP_COUNT_SIZE_64); // timers_m1=0
        bus.set_u32(HPET_REG_CAP + 4, 50);
        assert_eq!(HpetImpl::read_caps(&mut bus).unwrap().num_timers, 1);
    }

    #[test]
    fn write_log_capacity() {
        let mut bus = RecordingHpetBus::new();
        for _ in 0..10 {
            HpetImpl::enable(&mut bus);
        }
        assert_eq!(bus.write_count(), 10);
    }

    #[test]
    fn period_fs_in_caps() {
        let mut bus = RecordingHpetBus::new();
        bus.script_canonical_cap(12345, 0, 0);
        assert_eq!(HpetImpl::read_caps(&mut bus).unwrap().period_fs, 12345);
    }

    #[test]
    fn program_cmp_hi_nonzero() {
        let mut bus = RecordingHpetBus::new();
        let cmp = 0x1_0000_0001u64;
        HpetImpl::program_timer0_periodic(&mut bus, cmp).unwrap();
        assert_eq!(bus.write_at(1).unwrap().1, 1);
        assert_eq!(bus.write_at(2).unwrap().1, 1);
    }

    #[test]
    fn constants_tn_bits() {
        assert_eq!(HPET_TN_INT_ENB, 4);
        assert_eq!(HPET_TN_TYPE_PERIODIC, 8);
        assert_eq!(HPET_TN_VAL_SET, 64);
    }

    #[test]
    fn ms_to_ticks_large_period_fs() {
        // very slow timer
        let t = HpetImpl::ms_to_ticks(500_000_000, 1).unwrap();
        assert_eq!(t, 2000);
    }

    #[test]
    fn disable_when_already_off() {
        let mut bus = RecordingHpetBus::new();
        HpetImpl::disable(&mut bus);
        assert_eq!(bus.read_u32(HPET_REG_CONFIG) & HPET_CFG_ENABLE, 0);
    }

    #[test]
    fn banner_cmp_locked_value() {
        let cmp = ms_to_ticks_impl(BANNER_PERIOD_FS, 1).unwrap();
        assert_eq!(cmp, 14318); // floor(1e12 / 69841279)
    }
}
