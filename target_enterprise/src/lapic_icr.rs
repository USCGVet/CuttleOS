//! LAPIC ICR INIT/SIPI command builder — TASK-084.

#![allow(missing_docs)]

use proteus_contracts::{
    IcrCommand, LapicIcr, ICR_DELIVERY_FIXED, ICR_DELIVERY_INIT, ICR_DELIVERY_SIPI,
    ICR_DEST_NONE, ICR_HIGH_DEST_SHIFT, ICR_LEVEL_ASSERT, ICR_LEVEL_DEASSERT, ICR_TRIGGER_LEVEL,
};

pub struct LapicIcrImpl;

impl LapicIcr for LapicIcrImpl {
    fn init(apic_id: u8) -> IcrCommand {
        init_impl(apic_id)
    }
    fn sipi(apic_id: u8, startup_vec: u8) -> IcrCommand {
        sipi_impl(apic_id, startup_vec)
    }
    fn delivery_of(low: u32) -> u32 {
        low & (0x7 << 8)
    }
}

pub fn init_impl(apic_id: u8) -> IcrCommand {
    // INIT assert, level trigger, no vector
    let low = ICR_DELIVERY_INIT | ICR_LEVEL_ASSERT | ICR_TRIGGER_LEVEL | ICR_DEST_NONE;
    let high = (apic_id as u32) << ICR_HIGH_DEST_SHIFT;
    IcrCommand { low, high }
}

pub fn sipi_impl(apic_id: u8, startup_vec: u8) -> IcrCommand {
    let low = ICR_DELIVERY_SIPI | ICR_DEST_NONE | (startup_vec as u32);
    let high = (apic_id as u32) << ICR_HIGH_DEST_SHIFT;
    IcrCommand { low, high }
}

/// Deassert INIT (level deassert).
pub fn init_deassert(apic_id: u8) -> IcrCommand {
    let low = ICR_DELIVERY_INIT | ICR_LEVEL_DEASSERT | ICR_TRIGGER_LEVEL | ICR_DEST_NONE;
    let high = (apic_id as u32) << ICR_HIGH_DEST_SHIFT;
    IcrCommand { low, high }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::LapicIcr;

    #[test]
    fn init_delivery() {
        let c = LapicIcrImpl::init(1);
        assert_eq!(LapicIcrImpl::delivery_of(c.low), ICR_DELIVERY_INIT);
    }

    #[test]
    fn sipi_delivery() {
        let c = LapicIcrImpl::sipi(2, 0x08);
        assert_eq!(LapicIcrImpl::delivery_of(c.low), ICR_DELIVERY_SIPI);
        assert_eq!(c.low & 0xFF, 0x08);
    }

    #[test]
    fn dest_in_high() {
        let c = LapicIcrImpl::init(7);
        assert_eq!(c.high, 7 << 24);
    }

    #[test]
    fn init_assert_bits() {
        let c = LapicIcrImpl::init(0);
        assert_ne!(c.low & ICR_LEVEL_ASSERT, 0);
        assert_ne!(c.low & ICR_TRIGGER_LEVEL, 0);
    }

    #[test]
    fn deassert() {
        let c = init_deassert(1);
        assert_eq!(c.low & ICR_LEVEL_ASSERT, 0);
        assert_eq!(LapicIcrImpl::delivery_of(c.low), ICR_DELIVERY_INIT);
    }

    #[test]
    fn free_match() {
        assert_eq!(init_impl(3), LapicIcrImpl::init(3));
        assert_eq!(sipi_impl(3, 9), LapicIcrImpl::sipi(3, 9));
    }

    #[test]
    fn constants() {
        assert_eq!(ICR_DELIVERY_INIT, 5 << 8);
        assert_eq!(ICR_DELIVERY_SIPI, 6 << 8);
        assert_eq!(ICR_HIGH_DEST_SHIFT, 24);
    }

    #[test]
    fn banner_init() {
        let c = LapicIcrImpl::init(0);
        assert_eq!(LapicIcrImpl::delivery_of(c.low), ICR_DELIVERY_INIT);
    }

    #[test]
    fn sipi_vec_mask() {
        let c = LapicIcrImpl::sipi(0, 0xFF);
        assert_eq!(c.low & 0xFF, 0xFF);
    }

    #[test]
    fn fixed_const() {
        assert_eq!(ICR_DELIVERY_FIXED, 0);
    }

    #[test]
    fn dest_none() {
        assert_eq!(ICR_DEST_NONE, 0);
    }

    #[test]
    fn level_assert() {
        assert_eq!(ICR_LEVEL_ASSERT, 1 << 14);
    }

    #[test]
    fn trigger_level() {
        assert_eq!(ICR_TRIGGER_LEVEL, 1 << 15);
    }

    #[test]
    fn different_apic_ids() {
        assert_ne!(LapicIcrImpl::init(1).high, LapicIcrImpl::init(2).high);
    }

    #[test]
    fn sipi_not_init() {
        assert_ne!(
            LapicIcrImpl::delivery_of(LapicIcrImpl::sipi(0, 1).low),
            ICR_DELIVERY_INIT
        );
    }

    #[test]
    fn end_to_end() {
        let i = LapicIcrImpl::init(0);
        let s = LapicIcrImpl::sipi(0, 0x08);
        assert_eq!(LapicIcrImpl::delivery_of(i.low), ICR_DELIVERY_INIT);
        assert_eq!(LapicIcrImpl::delivery_of(s.low), ICR_DELIVERY_SIPI);
    }

    #[test]
    fn det() {
        assert_eq!(LapicIcrImpl::init(5), LapicIcrImpl::init(5));
    }

    #[test]
    fn deassert_dest() {
        assert_eq!(init_deassert(4).high, 4 << 24);
    }

    #[test]
    fn sipi_startup_8() {
        // trampoline 0x8000 → vec 0x08
        let c = LapicIcrImpl::sipi(1, 0x08);
        assert_eq!(c.low & 0xFF, 0x08);
        assert_eq!(c.high, 1 << 24);
    }

    #[test]
    fn delivery_mask() {
        let c = LapicIcrImpl::init(0);
        assert_eq!(c.low & (0x7 << 8), 5 << 8);
    }

    #[test]
    fn banner_str() {
        // LAPIC icr OK delivery=init
        assert_eq!(ICR_DELIVERY_INIT >> 8, 5);
    }

    #[test]
    fn zero_apic() {
        let c = LapicIcrImpl::init(0);
        assert_eq!(c.high, 0);
    }

    #[test]
    fn sipi_no_level_assert_required() {
        let c = LapicIcrImpl::sipi(0, 0);
        // SIPI typically edge; we don't set level assert
        assert_eq!(c.low & ICR_LEVEL_ASSERT, 0);
    }

    #[test]
    fn eq_cmd() {
        let a = IcrCommand { low: 1, high: 2 };
        assert_eq!(a, IcrCommand { low: 1, high: 2 });
    }

    #[test]
    fn deassert_trigger() {
        let c = init_deassert(0);
        assert_ne!(c.low & ICR_TRIGGER_LEVEL, 0);
    }
}
