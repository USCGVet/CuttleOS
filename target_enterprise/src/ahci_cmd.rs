//! AHCI command list header + PRDT entry — TASK-093.

#![allow(missing_docs)]

use cuttle_contracts::{
    AhciCmd, AhciCmdError, AhciCmdHeader, AhciPrdt, AHCI_CFL_H2D, AHCI_CMD_HDR_LEN, AHCI_PRDT_IOC,
    AHCI_PRDT_LEN,
};

pub struct AhciCmdImpl;

impl AhciCmd for AhciCmdImpl {
    fn encode_header(h: &AhciCmdHeader, out: &mut [u8]) -> Result<usize, AhciCmdError> {
        encode_header_impl(h, out)
    }
    fn decode_header(buf: &[u8]) -> Result<AhciCmdHeader, AhciCmdError> {
        decode_header_impl(buf)
    }
    fn encode_prdt(p: &AhciPrdt, out: &mut [u8]) -> Result<usize, AhciCmdError> {
        encode_prdt_impl(p, out)
    }
    fn decode_prdt(buf: &[u8]) -> Result<AhciPrdt, AhciCmdError> {
        decode_prdt_impl(buf)
    }
    fn identify_slot(ctba: u64, data_buf: u64) -> Result<(AhciCmdHeader, AhciPrdt), AhciCmdError> {
        identify_slot_impl(ctba, data_buf)
    }
}

fn put_u32(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn encode_header_impl(h: &AhciCmdHeader, out: &mut [u8]) -> Result<usize, AhciCmdError> {
    if out.len() < AHCI_CMD_HDR_LEN {
        return Err(AhciCmdError::Truncated);
    }
    if h.cfl > 0x1F || h.cfl == 0 {
        return Err(AhciCmdError::BadField);
    }
    if h.pmp > 0x0F {
        return Err(AhciCmdError::BadPort);
    }
    for b in out.iter_mut().take(AHCI_CMD_HDR_LEN) {
        *b = 0;
    }
    // DW0: PRDTL[31:16] | PMP[12:8] | W[6] | CFL[4:0]
    let mut dw0 = (h.cfl as u32) & 0x1F;
    if h.write {
        dw0 |= 1 << 6;
    }
    dw0 |= ((h.pmp as u32) & 0x0F) << 8;
    dw0 |= (h.prdtl as u32) << 16;
    put_u32(out, 0, dw0);
    put_u32(out, 4, h.prdbc);
    put_u32(out, 8, h.ctba as u32);
    put_u32(out, 12, (h.ctba >> 32) as u32);
    Ok(AHCI_CMD_HDR_LEN)
}

pub fn decode_header_impl(buf: &[u8]) -> Result<AhciCmdHeader, AhciCmdError> {
    if buf.len() < AHCI_CMD_HDR_LEN {
        return Err(AhciCmdError::Truncated);
    }
    let dw0 = get_u32(buf, 0);
    let cfl = (dw0 & 0x1F) as u8;
    if cfl == 0 {
        return Err(AhciCmdError::BadField);
    }
    Ok(AhciCmdHeader {
        cfl,
        write: (dw0 & (1 << 6)) != 0,
        pmp: ((dw0 >> 8) & 0x0F) as u8,
        prdtl: ((dw0 >> 16) & 0xFFFF) as u16,
        prdbc: get_u32(buf, 4),
        ctba: (get_u32(buf, 8) as u64) | ((get_u32(buf, 12) as u64) << 32),
    })
}

pub fn encode_prdt_impl(p: &AhciPrdt, out: &mut [u8]) -> Result<usize, AhciCmdError> {
    if out.len() < AHCI_PRDT_LEN {
        return Err(AhciCmdError::Truncated);
    }
    // AHCI: DBC is byte count minus 1; zero means 1 byte; max 4MiB-1 → count 4MiB
    if p.byte_count == 0 || p.byte_count > 4 * 1024 * 1024 {
        return Err(AhciCmdError::BadField);
    }
    for b in out.iter_mut().take(AHCI_PRDT_LEN) {
        *b = 0;
    }
    put_u32(out, 0, p.dba as u32);
    put_u32(out, 4, (p.dba >> 32) as u32);
    // DW2 reserved
    let mut dw3 = (p.byte_count - 1) & 0x003F_FFFF;
    if p.ioc {
        dw3 |= AHCI_PRDT_IOC;
    }
    put_u32(out, 12, dw3);
    Ok(AHCI_PRDT_LEN)
}

pub fn decode_prdt_impl(buf: &[u8]) -> Result<AhciPrdt, AhciCmdError> {
    if buf.len() < AHCI_PRDT_LEN {
        return Err(AhciCmdError::Truncated);
    }
    let dw3 = get_u32(buf, 12);
    let byte_count = (dw3 & 0x003F_FFFF) + 1;
    Ok(AhciPrdt {
        dba: (get_u32(buf, 0) as u64) | ((get_u32(buf, 4) as u64) << 32),
        byte_count,
        ioc: (dw3 & AHCI_PRDT_IOC) != 0,
    })
}

/// IDENTIFY DEVICE: read 512 bytes, CFL=5, PRDTL=1, W=0.
pub fn identify_slot_impl(
    ctba: u64,
    data_buf: u64,
) -> Result<(AhciCmdHeader, AhciPrdt), AhciCmdError> {
    let h = AhciCmdHeader {
        cfl: AHCI_CFL_H2D,
        write: false,
        pmp: 0,
        prdtl: 1,
        prdbc: 0,
        ctba,
    };
    let p = AhciPrdt {
        dba: data_buf,
        byte_count: 512,
        ioc: true,
    };
    Ok((h, p))
}

pub fn banner_prdtl() -> u16 {
    let (h, _) = AhciCmdImpl::identify_slot(0x1000, 0x2000).expect("slot");
    h.prdtl
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::AhciCmd;

    #[test]
    fn constants() {
        assert_eq!(AHCI_CMD_HDR_LEN, 32);
        assert_eq!(AHCI_PRDT_LEN, 16);
        assert_eq!(AHCI_CFL_H2D, 5);
    }

    #[test]
    fn identify_slot() {
        let (h, p) = AhciCmdImpl::identify_slot(0x1000, 0x2000).unwrap();
        assert_eq!(h.cfl, 5);
        assert_eq!(h.prdtl, 1);
        assert!(!h.write);
        assert_eq!(p.byte_count, 512);
        assert!(p.ioc);
        assert_eq!(p.dba, 0x2000);
    }

    #[test]
    fn header_roundtrip() {
        let (h, _) = AhciCmdImpl::identify_slot(0xABCD_0000_1000, 0).unwrap();
        let mut b = [0u8; 32];
        AhciCmdImpl::encode_header(&h, &mut b).unwrap();
        assert_eq!(AhciCmdImpl::decode_header(&b).unwrap(), h);
    }

    #[test]
    fn prdt_roundtrip() {
        let (_, p) = AhciCmdImpl::identify_slot(0, 0x9000).unwrap();
        let mut b = [0u8; 16];
        AhciCmdImpl::encode_prdt(&p, &mut b).unwrap();
        assert_eq!(AhciCmdImpl::decode_prdt(&b).unwrap(), p);
    }

    #[test]
    fn prdt_dbc_encoding() {
        let p = AhciPrdt {
            dba: 0,
            byte_count: 512,
            ioc: false,
        };
        let mut b = [0u8; 16];
        AhciCmdImpl::encode_prdt(&p, &mut b).unwrap();
        let dw3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        assert_eq!(dw3 & 0x003F_FFFF, 511);
    }

    #[test]
    fn write_bit() {
        let h = AhciCmdHeader {
            cfl: 5,
            write: true,
            pmp: 2,
            prdtl: 3,
            prdbc: 0,
            ctba: 0,
        };
        let mut b = [0u8; 32];
        AhciCmdImpl::encode_header(&h, &mut b).unwrap();
        let d = AhciCmdImpl::decode_header(&b).unwrap();
        assert!(d.write);
        assert_eq!(d.pmp, 2);
        assert_eq!(d.prdtl, 3);
    }

    #[test]
    fn truncated() {
        let (h, p) = AhciCmdImpl::identify_slot(0, 0).unwrap();
        let mut s = [0u8; 8];
        assert_eq!(
            AhciCmdImpl::encode_header(&h, &mut s),
            Err(AhciCmdError::Truncated)
        );
        assert_eq!(
            AhciCmdImpl::encode_prdt(&p, &mut s),
            Err(AhciCmdError::Truncated)
        );
    }

    #[test]
    fn bad_cfl() {
        let h = AhciCmdHeader {
            cfl: 0,
            write: false,
            pmp: 0,
            prdtl: 0,
            prdbc: 0,
            ctba: 0,
        };
        let mut b = [0u8; 32];
        assert_eq!(
            AhciCmdImpl::encode_header(&h, &mut b),
            Err(AhciCmdError::BadField)
        );
    }

    #[test]
    fn bad_port() {
        let h = AhciCmdHeader {
            cfl: 5,
            write: false,
            pmp: 16,
            prdtl: 1,
            prdbc: 0,
            ctba: 0,
        };
        let mut b = [0u8; 32];
        assert_eq!(
            AhciCmdImpl::encode_header(&h, &mut b),
            Err(AhciCmdError::BadPort)
        );
    }

    #[test]
    fn bad_byte_count() {
        let p = AhciPrdt {
            dba: 0,
            byte_count: 0,
            ioc: false,
        };
        let mut b = [0u8; 16];
        assert_eq!(
            AhciCmdImpl::encode_prdt(&p, &mut b),
            Err(AhciCmdError::BadField)
        );
    }

    #[test]
    fn free_match() {
        let a = identify_slot_impl(1, 2).unwrap();
        let b = AhciCmdImpl::identify_slot(1, 2).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn banner() {
        assert_eq!(banner_prdtl(), 1);
    }

    #[test]
    fn banner_str() {
        // AHCI cmd OK prdtl=1
        assert_eq!(banner_prdtl(), 1);
    }

    #[test]
    fn ioc_bit() {
        let p = AhciPrdt {
            dba: 0,
            byte_count: 1,
            ioc: true,
        };
        let mut b = [0u8; 16];
        AhciCmdImpl::encode_prdt(&p, &mut b).unwrap();
        let dw3 = u32::from_le_bytes([b[12], b[13], b[14], b[15]]);
        assert_ne!(dw3 & AHCI_PRDT_IOC, 0);
    }

    #[test]
    fn det() {
        assert_eq!(
            AhciCmdImpl::identify_slot(9, 8).unwrap(),
            AhciCmdImpl::identify_slot(9, 8).unwrap()
        );
    }

    #[test]
    fn end_to_end() {
        let (h, p) = AhciCmdImpl::identify_slot(0x1000, 0x2000).unwrap();
        let mut hb = [0u8; 32];
        let mut pb = [0u8; 16];
        AhciCmdImpl::encode_header(&h, &mut hb).unwrap();
        AhciCmdImpl::encode_prdt(&p, &mut pb).unwrap();
        assert_eq!(AhciCmdImpl::decode_header(&hb).unwrap().prdtl, 1);
        assert_eq!(AhciCmdImpl::decode_prdt(&pb).unwrap().byte_count, 512);
    }

    #[test]
    fn ctba_hi() {
        let (h, _) = AhciCmdImpl::identify_slot(0x0000_0003_0000_0000, 0).unwrap();
        let mut b = [0u8; 32];
        AhciCmdImpl::encode_header(&h, &mut b).unwrap();
        assert_eq!(AhciCmdImpl::decode_header(&b).unwrap().ctba, 0x3_0000_0000);
    }
}
