//! ACPI PM1a S5 soft-off encode — TASK-073.
//!
//! Wire codec only: build/decode PM1_CNT sleep bits. No port I/O.

#![allow(missing_docs)]

#[cfg(test)]
use proteus_contracts::SLP_TYP_S5;
use proteus_contracts::{
    Pm1Control, Power, PM1A_CNT_PORT, PM1_SLP_EN, PM1_SLP_TYP_MASK, PM1_SLP_TYP_SHIFT,
};

/// Stateless power codec.
pub struct PowerImpl;

impl Power for PowerImpl {
    fn encode_s5(slp_typ: u8) -> Pm1Control {
        encode_s5_impl(slp_typ)
    }
    fn decode_slp_typ(pm1: Pm1Control) -> u8 {
        decode_slp_typ_impl(pm1)
    }
    fn is_slp_en(pm1: Pm1Control) -> bool {
        is_slp_en_impl(pm1)
    }
}

pub fn encode_s5_impl(slp_typ: u8) -> Pm1Control {
    let typ = (slp_typ as u16) & PM1_SLP_TYP_MASK;
    let raw = (typ << PM1_SLP_TYP_SHIFT) | PM1_SLP_EN;
    Pm1Control { raw }
}

pub fn decode_slp_typ_impl(pm1: Pm1Control) -> u8 {
    ((pm1.raw >> PM1_SLP_TYP_SHIFT) & PM1_SLP_TYP_MASK) as u8
}

pub fn is_slp_en_impl(pm1: Pm1Control) -> bool {
    pm1.raw & PM1_SLP_EN != 0
}

/// Recording write for port-level harnesses.
#[derive(Clone, Copy)]
pub struct PowerPortWrite {
    pub port: u16,
    pub value: u16,
}

/// Simulated PM1a port writer.
pub struct RecordingPm1 {
    pub writes: [Option<PowerPortWrite>; 8],
    pub count: usize,
}

impl Default for RecordingPm1 {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingPm1 {
    pub const fn new() -> Self {
        Self {
            writes: [None; 8],
            count: 0,
        }
    }
    pub fn write_pm1a(&mut self, value: u16) {
        if self.count < 8 {
            self.writes[self.count] = Some(PowerPortWrite {
                port: PM1A_CNT_PORT,
                value,
            });
            self.count += 1;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Power;

    #[test]
    fn constants() {
        assert_eq!(PM1_SLP_EN, 1 << 13);
        assert_eq!(PM1_SLP_TYP_SHIFT, 10);
        assert_eq!(SLP_TYP_S5, 5);
        assert_eq!(PM1A_CNT_PORT, 0x604);
    }

    #[test]
    fn encode_s5_sets_en_and_typ() {
        let p = PowerImpl::encode_s5(SLP_TYP_S5);
        assert!(PowerImpl::is_slp_en(p));
        assert_eq!(PowerImpl::decode_slp_typ(p), 5);
        // raw = (5 << 10) | (1 << 13) = 0x2000 | 0x1400 = 0x3400
        assert_eq!(p.raw, 0x3400);
    }

    #[test]
    fn encode_masks_typ_to_3_bits() {
        let p = PowerImpl::encode_s5(0xFF);
        assert_eq!(PowerImpl::decode_slp_typ(p), 7);
    }

    #[test]
    fn decode_round_trip() {
        for t in 0u8..8 {
            let p = PowerImpl::encode_s5(t);
            assert_eq!(PowerImpl::decode_slp_typ(p), t);
            assert!(PowerImpl::is_slp_en(p));
        }
    }

    #[test]
    fn is_slp_en_false_without_bit() {
        let p = Pm1Control { raw: 5 << 10 };
        assert!(!PowerImpl::is_slp_en(p));
    }

    #[test]
    fn recording_port() {
        let mut bus = RecordingPm1::new();
        let p = PowerImpl::encode_s5(SLP_TYP_S5);
        bus.write_pm1a(p.raw);
        assert_eq!(bus.count, 1);
        let w = bus.writes[0].as_ref().unwrap();
        assert_eq!(w.port, PM1A_CNT_PORT);
        assert_eq!(w.value, 0x3400);
    }

    #[test]
    fn free_match_trait() {
        assert_eq!(
            encode_s5_impl(5).raw,
            PowerImpl::encode_s5(5).raw
        );
    }

    #[test]
    fn banner_s5() {
        let p = PowerImpl::encode_s5(SLP_TYP_S5);
        assert_eq!(PowerImpl::decode_slp_typ(p), 5);
        assert!(PowerImpl::is_slp_en(p));
    }

    #[test]
    fn typ_zero() {
        let p = PowerImpl::encode_s5(0);
        assert_eq!(p.raw, PM1_SLP_EN);
    }

    #[test]
    fn typ_seven() {
        let p = PowerImpl::encode_s5(7);
        assert_eq!(p.raw, (7 << 10) | PM1_SLP_EN);
    }

    #[test]
    fn multiple_writes() {
        let mut bus = RecordingPm1::new();
        bus.write_pm1a(1);
        bus.write_pm1a(2);
        assert_eq!(bus.count, 2);
    }

    #[test]
    fn default_bus() {
        assert_eq!(RecordingPm1::default().count, 0);
    }

    #[test]
    fn pm1_control_eq() {
        assert_eq!(
            PowerImpl::encode_s5(5),
            Pm1Control { raw: 0x3400 }
        );
    }

    #[test]
    fn shift_matches_mask() {
        assert_eq!(PM1_SLP_TYP_MASK << PM1_SLP_TYP_SHIFT, 0x1C00);
    }

    #[test]
    fn encode_does_not_set_other_bits() {
        let p = PowerImpl::encode_s5(1);
        assert_eq!(p.raw & !(PM1_SLP_EN | (PM1_SLP_TYP_MASK << PM1_SLP_TYP_SHIFT)), 0);
    }

    #[test]
    fn s5_value_locked() {
        assert_eq!(PowerImpl::encode_s5(5).raw, (5u16 << 10) | (1 << 13));
    }

    #[test]
    fn decode_ignores_other_bits() {
        let p = Pm1Control {
            raw: 0x3400 | 0x00FF,
        };
        assert_eq!(PowerImpl::decode_slp_typ(p), 5);
        assert!(PowerImpl::is_slp_en(p));
    }

    #[test]
    fn port_constant_qemu() {
        assert_eq!(PM1A_CNT_PORT, 0x604);
    }

    #[test]
    fn end_to_end() {
        let p = PowerImpl::encode_s5(SLP_TYP_S5);
        let mut bus = RecordingPm1::new();
        bus.write_pm1a(p.raw);
        assert_eq!(bus.writes[0].as_ref().unwrap().value, 0x3400);
    }

    #[test]
    fn typ_one() {
        assert_eq!(PowerImpl::decode_slp_typ(PowerImpl::encode_s5(1)), 1);
    }
}
