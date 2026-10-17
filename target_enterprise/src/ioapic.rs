//! IOAPIC redirection table entry encode/decode — TASK-083.

#![allow(missing_docs)]

use proteus_contracts::{
    IoApic, IoApicRedir, IOAPIC_DELIVERY_FIXED, IOAPIC_DEST_PHYSICAL, IOAPIC_POLARITY_HIGH,
    IOAPIC_TRIGGER_EDGE,
};
#[cfg(test)]
use proteus_contracts::{
    IOAPIC_DELIVERY_EXTINT, IOAPIC_DELIVERY_INIT, IOAPIC_DELIVERY_LOWEST, IOAPIC_DELIVERY_NMI,
    IOAPIC_DELIVERY_SMI, IOAPIC_DEST_LOGICAL, IOAPIC_MASKED, IOAPIC_POLARITY_LOW,
    IOAPIC_TRIGGER_LEVEL,
};

pub struct IoApicImpl;

impl IoApic for IoApicImpl {
    fn encode(e: &IoApicRedir) -> (u32, u32) {
        encode_impl(e)
    }
    fn decode(low: u32, high: u32) -> IoApicRedir {
        decode_impl(low, high)
    }
}

/// Low dword layout (Intel SDM):
/// bits 0..7 vector, 8..10 delivery, 11 dest_mode, 13 polarity,
/// 15 trigger, 16 mask. High: bits 24..31 dest.
pub fn encode_impl(e: &IoApicRedir) -> (u32, u32) {
    let mut low = e.vector as u32;
    low |= ((e.delivery as u32) & 7) << 8;
    low |= ((e.dest_mode as u32) & 1) << 11;
    low |= ((e.polarity as u32) & 1) << 13;
    low |= ((e.trigger as u32) & 1) << 15;
    low |= ((e.mask as u32) & 1) << 16;
    let high = (e.dest as u32) << 24;
    (low, high)
}

pub fn decode_impl(low: u32, high: u32) -> IoApicRedir {
    IoApicRedir {
        vector: (low & 0xFF) as u8,
        delivery: ((low >> 8) & 7) as u8,
        dest_mode: ((low >> 11) & 1) as u8,
        polarity: ((low >> 13) & 1) as u8,
        trigger: ((low >> 15) & 1) as u8,
        mask: ((low >> 16) & 1) as u8,
        dest: ((high >> 24) & 0xFF) as u8,
    }
}

/// Banner fixture entry: vec=0x30, fixed, physical, edge, high, unmasked, dest=0.
pub fn banner_entry() -> IoApicRedir {
    IoApicRedir {
        vector: 0x30,
        delivery: IOAPIC_DELIVERY_FIXED,
        dest_mode: IOAPIC_DEST_PHYSICAL,
        polarity: IOAPIC_POLARITY_HIGH,
        trigger: IOAPIC_TRIGGER_EDGE,
        mask: 0,
        dest: 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::IoApic;

    #[test]
    fn round_trip_banner() {
        let e = banner_entry();
        let (lo, hi) = IoApicImpl::encode(&e);
        let d = IoApicImpl::decode(lo, hi);
        assert_eq!(d, e);
    }

    #[test]
    fn vector_0x30() {
        let (lo, _) = IoApicImpl::encode(&banner_entry());
        assert_eq!(lo & 0xFF, 0x30);
    }

    #[test]
    fn mask_bit() {
        let mut e = banner_entry();
        e.mask = IOAPIC_MASKED;
        let (lo, _) = IoApicImpl::encode(&e);
        assert_ne!(lo & (1 << 16), 0);
    }

    #[test]
    fn dest_in_high() {
        let mut e = banner_entry();
        e.dest = 3;
        let (_, hi) = IoApicImpl::encode(&e);
        assert_eq!(hi, 3 << 24);
    }

    #[test]
    fn delivery_nmi() {
        let mut e = banner_entry();
        e.delivery = IOAPIC_DELIVERY_NMI;
        let (lo, _) = IoApicImpl::encode(&e);
        assert_eq!((lo >> 8) & 7, 4);
    }

    #[test]
    fn level_low() {
        let mut e = banner_entry();
        e.trigger = IOAPIC_TRIGGER_LEVEL;
        e.polarity = IOAPIC_POLARITY_LOW;
        let d = IoApicImpl::decode(IoApicImpl::encode(&e).0, 0);
        assert_eq!(d.trigger, IOAPIC_TRIGGER_LEVEL);
        assert_eq!(d.polarity, IOAPIC_POLARITY_LOW);
    }

    #[test]
    fn logical_dest() {
        let mut e = banner_entry();
        e.dest_mode = IOAPIC_DEST_LOGICAL;
        let (lo, _) = IoApicImpl::encode(&e);
        assert_ne!(lo & (1 << 11), 0);
    }

    #[test]
    fn free_match() {
        let e = banner_entry();
        assert_eq!(encode_impl(&e), IoApicImpl::encode(&e));
    }

    #[test]
    fn constants() {
        assert_eq!(IOAPIC_DELIVERY_FIXED, 0);
        assert_eq!(IOAPIC_DELIVERY_INIT, 5);
        assert_eq!(IOAPIC_DELIVERY_EXTINT, 7);
        assert_eq!(IOAPIC_DELIVERY_SMI, 2);
        assert_eq!(IOAPIC_DELIVERY_LOWEST, 1);
    }

    #[test]
    fn decode_zero() {
        let d = IoApicImpl::decode(0, 0);
        assert_eq!(d.vector, 0);
        assert_eq!(d.dest, 0);
    }

    #[test]
    fn banner_unmasked() {
        assert_eq!(banner_entry().mask, 0);
    }

    #[test]
    fn end_to_end() {
        let e = banner_entry();
        assert_eq!(e.vector, 0x30);
        let (lo, hi) = IoApicImpl::encode(&e);
        assert_eq!(IoApicImpl::decode(lo, hi).vector, 0x30);
    }

    #[test]
    fn all_fields_roundtrip() {
        let e = IoApicRedir {
            vector: 0x41,
            delivery: 5,
            dest_mode: 1,
            polarity: 1,
            trigger: 1,
            mask: 1,
            dest: 0xFE,
        };
        let (lo, hi) = IoApicImpl::encode(&e);
        assert_eq!(IoApicImpl::decode(lo, hi), e);
    }

    #[test]
    fn dest_physical() {
        assert_eq!(IOAPIC_DEST_PHYSICAL, 0);
    }

    #[test]
    fn edge() {
        assert_eq!(IOAPIC_TRIGGER_EDGE, 0);
    }

    #[test]
    fn high_pol() {
        assert_eq!(IOAPIC_POLARITY_HIGH, 0);
    }

    #[test]
    fn masked_const() {
        assert_eq!(IOAPIC_MASKED, 1);
    }

    #[test]
    fn logical_const() {
        assert_eq!(IOAPIC_DEST_LOGICAL, 1);
    }

    #[test]
    fn level_const() {
        assert_eq!(IOAPIC_TRIGGER_LEVEL, 1);
    }

    #[test]
    fn low_pol() {
        assert_eq!(IOAPIC_POLARITY_LOW, 1);
    }

    #[test]
    fn vec_ff() {
        let mut e = banner_entry();
        e.vector = 0xFE;
        assert_eq!(IoApicImpl::encode(&e).0 & 0xFF, 0xFE);
    }

    #[test]
    fn delivery_bits_only_3() {
        let mut e = banner_entry();
        e.delivery = 0xFF;
        let (lo, _) = IoApicImpl::encode(&e);
        assert_eq!((lo >> 8) & 7, 7);
    }

    #[test]
    fn hi_only_dest() {
        let (_, hi) = IoApicImpl::encode(&banner_entry());
        assert_eq!(hi & 0x00FF_FFFF, 0);
    }

    #[test]
    fn det() {
        assert_eq!(
            IoApicImpl::encode(&banner_entry()),
            IoApicImpl::encode(&banner_entry())
        );
    }

    #[test]
    fn banner_str() {
        // IOAPIC entry OK vec=0x30
        assert_eq!(banner_entry().vector, 0x30);
    }
}
