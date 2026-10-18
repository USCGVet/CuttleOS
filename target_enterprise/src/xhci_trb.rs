//! xHCI Transfer Request Block No-Op + Link encode — TASK-089.

#![allow(missing_docs)]

use cuttle_contracts::{
    XhciTrb, XhciTrbError, XhciTrbWords, XHCI_TRB_CYCLE, XHCI_TRB_LEN, XHCI_TRB_TOGGLE_CYCLE,
    XHCI_TRB_TYPE_LINK, XHCI_TRB_TYPE_NOOP, XHCI_TRB_TYPE_SHIFT,
};

pub struct XhciTrbImpl;

impl XhciTrb for XhciTrbImpl {
    fn encode_noop(cycle: bool) -> XhciTrbWords {
        encode_noop_impl(cycle)
    }
    fn encode_link(
        ring_ptr: u64,
        cycle: bool,
        toggle_cycle: bool,
    ) -> Result<XhciTrbWords, XhciTrbError> {
        encode_link_impl(ring_ptr, cycle, toggle_cycle)
    }
    fn trb_type(d3: u32) -> u8 {
        trb_type_impl(d3)
    }
    fn to_bytes(w: &XhciTrbWords, out: &mut [u8]) -> Result<usize, XhciTrbError> {
        to_bytes_impl(w, out)
    }
    fn from_bytes(buf: &[u8]) -> Result<XhciTrbWords, XhciTrbError> {
        from_bytes_impl(buf)
    }
}

pub fn encode_noop_impl(cycle: bool) -> XhciTrbWords {
    let mut d3 = (XHCI_TRB_TYPE_NOOP as u32) << XHCI_TRB_TYPE_SHIFT;
    if cycle {
        d3 |= XHCI_TRB_CYCLE;
    }
    XhciTrbWords {
        d0: 0,
        d1: 0,
        d2: 0,
        d3,
    }
}

pub fn encode_link_impl(
    ring_ptr: u64,
    cycle: bool,
    toggle_cycle: bool,
) -> Result<XhciTrbWords, XhciTrbError> {
    if ring_ptr & 0xF != 0 {
        return Err(XhciTrbError::BadAlign);
    }
    let mut d3 = (XHCI_TRB_TYPE_LINK as u32) << XHCI_TRB_TYPE_SHIFT;
    if cycle {
        d3 |= XHCI_TRB_CYCLE;
    }
    if toggle_cycle {
        d3 |= XHCI_TRB_TOGGLE_CYCLE;
    }
    Ok(XhciTrbWords {
        d0: ring_ptr as u32,
        d1: (ring_ptr >> 32) as u32,
        d2: 0,
        d3,
    })
}

pub fn trb_type_impl(d3: u32) -> u8 {
    ((d3 >> XHCI_TRB_TYPE_SHIFT) & 0x3F) as u8
}

pub fn to_bytes_impl(w: &XhciTrbWords, out: &mut [u8]) -> Result<usize, XhciTrbError> {
    if out.len() < XHCI_TRB_LEN {
        return Err(XhciTrbError::Truncated);
    }
    out[0..4].copy_from_slice(&w.d0.to_le_bytes());
    out[4..8].copy_from_slice(&w.d1.to_le_bytes());
    out[8..12].copy_from_slice(&w.d2.to_le_bytes());
    out[12..16].copy_from_slice(&w.d3.to_le_bytes());
    Ok(XHCI_TRB_LEN)
}

pub fn from_bytes_impl(buf: &[u8]) -> Result<XhciTrbWords, XhciTrbError> {
    if buf.len() < XHCI_TRB_LEN {
        return Err(XhciTrbError::Truncated);
    }
    Ok(XhciTrbWords {
        d0: u32::from_le_bytes([buf[0], buf[1], buf[2], buf[3]]),
        d1: u32::from_le_bytes([buf[4], buf[5], buf[6], buf[7]]),
        d2: u32::from_le_bytes([buf[8], buf[9], buf[10], buf[11]]),
        d3: u32::from_le_bytes([buf[12], buf[13], buf[14], buf[15]]),
    })
}

/// Banner: encode no-op, confirm type field.
pub fn banner_noop_type() -> u8 {
    let w = XhciTrbImpl::encode_noop(true);
    XhciTrbImpl::trb_type(w.d3)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::XhciTrb;

    #[test]
    fn constants() {
        assert_eq!(XHCI_TRB_LEN, 16);
        assert_eq!(XHCI_TRB_TYPE_NOOP, 8);
        assert_eq!(XHCI_TRB_TYPE_LINK, 6);
    }

    #[test]
    fn noop_type() {
        let w = XhciTrbImpl::encode_noop(true);
        assert_eq!(XhciTrbImpl::trb_type(w.d3), XHCI_TRB_TYPE_NOOP);
        assert_ne!(w.d3 & XHCI_TRB_CYCLE, 0);
        assert_eq!(w.d0 | w.d1 | w.d2, 0);
    }

    #[test]
    fn noop_cycle_off() {
        let w = XhciTrbImpl::encode_noop(false);
        assert_eq!(w.d3 & XHCI_TRB_CYCLE, 0);
        assert_eq!(XhciTrbImpl::trb_type(w.d3), XHCI_TRB_TYPE_NOOP);
    }

    #[test]
    fn link_ptr() {
        let w = XhciTrbImpl::encode_link(0x1000, true, true).unwrap();
        assert_eq!(w.d0, 0x1000);
        assert_eq!(w.d1, 0);
        assert_eq!(XhciTrbImpl::trb_type(w.d3), XHCI_TRB_TYPE_LINK);
        assert_ne!(w.d3 & XHCI_TRB_TOGGLE_CYCLE, 0);
    }

    #[test]
    fn link_hi() {
        let ptr = 0x0000_0002_0000_1000u64;
        let w = XhciTrbImpl::encode_link(ptr, false, false).unwrap();
        assert_eq!(w.d0, 0x1000);
        assert_eq!(w.d1, 2);
        assert_eq!(w.d3 & XHCI_TRB_CYCLE, 0);
    }

    #[test]
    fn bad_align() {
        assert_eq!(
            XhciTrbImpl::encode_link(0x1001, true, false),
            Err(XhciTrbError::BadAlign)
        );
    }

    #[test]
    fn roundtrip_bytes() {
        let w = XhciTrbImpl::encode_noop(true);
        let mut b = [0u8; 16];
        XhciTrbImpl::to_bytes(&w, &mut b).unwrap();
        assert_eq!(XhciTrbImpl::from_bytes(&b).unwrap(), w);
    }

    #[test]
    fn link_roundtrip() {
        let w = XhciTrbImpl::encode_link(0x2000, true, true).unwrap();
        let mut b = [0u8; 16];
        XhciTrbImpl::to_bytes(&w, &mut b).unwrap();
        let d = XhciTrbImpl::from_bytes(&b).unwrap();
        assert_eq!(d, w);
        assert_eq!(XhciTrbImpl::trb_type(d.d3), XHCI_TRB_TYPE_LINK);
    }

    #[test]
    fn truncated() {
        let w = XhciTrbImpl::encode_noop(true);
        let mut s = [0u8; 8];
        assert_eq!(XhciTrbImpl::to_bytes(&w, &mut s), Err(XhciTrbError::Truncated));
        assert_eq!(XhciTrbImpl::from_bytes(&[0u8; 4]), Err(XhciTrbError::Truncated));
    }

    #[test]
    fn free_match() {
        assert_eq!(encode_noop_impl(true), XhciTrbImpl::encode_noop(true));
    }

    #[test]
    fn banner() {
        assert_eq!(banner_noop_type(), XHCI_TRB_TYPE_NOOP);
    }

    #[test]
    fn det() {
        assert_eq!(
            XhciTrbImpl::encode_noop(true),
            XhciTrbImpl::encode_noop(true)
        );
    }

    #[test]
    fn type_mask() {
        let w = XhciTrbImpl::encode_noop(true);
        assert_eq!((w.d3 >> 10) & 0x3F, 8);
    }

    #[test]
    fn link_not_noop() {
        let n = XhciTrbImpl::encode_noop(true);
        let l = XhciTrbImpl::encode_link(0x1000, true, false).unwrap();
        assert_ne!(XhciTrbImpl::trb_type(n.d3), XhciTrbImpl::trb_type(l.d3));
    }

    #[test]
    fn end_to_end() {
        assert_eq!(banner_noop_type(), 8);
    }

    #[test]
    fn le_layout() {
        let w = XhciTrbWords {
            d0: 0x04030201,
            d1: 0,
            d2: 0,
            d3: 0,
        };
        let mut b = [0u8; 16];
        XhciTrbImpl::to_bytes(&w, &mut b).unwrap();
        assert_eq!(&b[0..4], &[1, 2, 3, 4]);
    }

    #[test]
    fn banner_str() {
        // XHCI trb OK type=noop
        assert_eq!(XHCI_TRB_TYPE_NOOP, 8);
    }
}
