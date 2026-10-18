//! AHCI Register Host-to-Device FIS encode — TASK-088.
//!
//! Locks the SATA 20-byte H2D layout used for ATA IDENTIFY DEVICE and
//! READ DMA so AHCI command framing is diversifiable only in
//! implementation detail, not wire shape.

#![allow(missing_docs)]

use cuttle_contracts::{
    AhciFis, AhciFisError, H2dFisParams, AHCI_FIS_C_BIT, AHCI_FIS_H2D_LEN, AHCI_FIS_PMP_MASK,
    AHCI_FIS_TYPE_H2D, ATA_CMD_IDENTIFY, ATA_CMD_READ_DMA, ATA_DEV_LBA,
};

/// Concrete [`AhciFis`] implementation.
pub struct AhciFisImpl;

impl AhciFis for AhciFisImpl {
    fn encode_h2d(p: &H2dFisParams, out: &mut [u8]) -> Result<usize, AhciFisError> {
        encode_h2d_impl(p, out)
    }
    fn decode_h2d(fis: &[u8]) -> Result<H2dFisParams, AhciFisError> {
        decode_h2d_impl(fis)
    }
    fn identify(pm_port: u8) -> Result<H2dFisParams, AhciFisError> {
        identify_impl(pm_port)
    }
    fn read_dma(lba: u64, count: u16, pm_port: u8) -> Result<H2dFisParams, AhciFisError> {
        read_dma_impl(lba, count, pm_port)
    }
}

fn check_port(pm_port: u8) -> Result<(), AhciFisError> {
    if pm_port > AHCI_FIS_PMP_MASK {
        return Err(AhciFisError::BadPort);
    }
    Ok(())
}

/// Encode Register H2D FIS (type 0x27, 20 bytes).
pub fn encode_h2d_impl(p: &H2dFisParams, out: &mut [u8]) -> Result<usize, AhciFisError> {
    check_port(p.pm_port)?;
    if out.len() < AHCI_FIS_H2D_LEN {
        return Err(AhciFisError::Truncated);
    }
    for b in out.iter_mut().take(AHCI_FIS_H2D_LEN) {
        *b = 0;
    }
    out[0] = AHCI_FIS_TYPE_H2D;
    let mut b1 = p.pm_port & AHCI_FIS_PMP_MASK;
    if p.is_command {
        b1 |= AHCI_FIS_C_BIT;
    }
    out[1] = b1;
    out[2] = p.command;
    out[3] = (p.features & 0xFF) as u8;
    // LBA 47:0 little-endian across FIS bytes 4-6 and 8-10.
    out[4] = (p.lba & 0xFF) as u8;
    out[5] = ((p.lba >> 8) & 0xFF) as u8;
    out[6] = ((p.lba >> 16) & 0xFF) as u8;
    out[7] = p.device;
    out[8] = ((p.lba >> 24) & 0xFF) as u8;
    out[9] = ((p.lba >> 32) & 0xFF) as u8;
    out[10] = ((p.lba >> 40) & 0xFF) as u8;
    out[11] = ((p.features >> 8) & 0xFF) as u8;
    out[12] = (p.count & 0xFF) as u8;
    out[13] = ((p.count >> 8) & 0xFF) as u8;
    // out[14] ICC, out[15] Control, out[16..20] reserved — zeroed above.
    Ok(AHCI_FIS_H2D_LEN)
}

/// Decode Register H2D FIS.
pub fn decode_h2d_impl(fis: &[u8]) -> Result<H2dFisParams, AhciFisError> {
    if fis.len() < AHCI_FIS_H2D_LEN {
        return Err(AhciFisError::Truncated);
    }
    if fis[0] != AHCI_FIS_TYPE_H2D {
        return Err(AhciFisError::BadType);
    }
    let pm_port = fis[1] & AHCI_FIS_PMP_MASK;
    let is_command = (fis[1] & AHCI_FIS_C_BIT) != 0;
    let features = (fis[3] as u16) | ((fis[11] as u16) << 8);
    let lba = (fis[4] as u64)
        | ((fis[5] as u64) << 8)
        | ((fis[6] as u64) << 16)
        | ((fis[8] as u64) << 24)
        | ((fis[9] as u64) << 32)
        | ((fis[10] as u64) << 40);
    let count = (fis[12] as u16) | ((fis[13] as u16) << 8);
    Ok(H2dFisParams {
        command: fis[2],
        features,
        lba,
        count,
        device: fis[7],
        pm_port,
        is_command,
    })
}

/// ATA IDENTIFY DEVICE — C=1, command 0xEC, LBA mode, zero LBA/count.
pub fn identify_impl(pm_port: u8) -> Result<H2dFisParams, AhciFisError> {
    check_port(pm_port)?;
    Ok(H2dFisParams {
        command: ATA_CMD_IDENTIFY,
        features: 0,
        lba: 0,
        count: 0,
        device: ATA_DEV_LBA,
        pm_port,
        is_command: true,
    })
}

/// ATA READ DMA (28-bit) — C=1, command 0xC8, LBA + sector count.
///
/// Only the low 28 bits of `lba` are meaningful for classic READ DMA;
/// upper bits still land in the 48-bit FIS slots for round-trip fidelity.
pub fn read_dma_impl(lba: u64, count: u16, pm_port: u8) -> Result<H2dFisParams, AhciFisError> {
    check_port(pm_port)?;
    Ok(H2dFisParams {
        command: ATA_CMD_READ_DMA,
        features: 0,
        lba,
        count,
        device: ATA_DEV_LBA,
        pm_port,
        is_command: true,
    })
}

/// Banner helper: encode IDENTIFY and return the command byte from the FIS.
pub fn banner_identify_cmd() -> u8 {
    let p = AhciFisImpl::identify(0).expect("identify params");
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    AhciFisImpl::encode_h2d(&p, &mut fis).expect("encode");
    fis[2]
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::{AhciFis, ATA_CMD_READ_DMA_EXT};

    #[test]
    fn constants() {
        assert_eq!(AHCI_FIS_TYPE_H2D, 0x27);
        assert_eq!(AHCI_FIS_H2D_LEN, 20);
        assert_eq!(ATA_CMD_IDENTIFY, 0xEC);
        assert_eq!(ATA_CMD_READ_DMA, 0xC8);
        assert_eq!(ATA_CMD_READ_DMA_EXT, 0x25);
        assert_eq!(ATA_DEV_LBA, 0x40);
        assert_eq!(AHCI_FIS_C_BIT, 0x80);
    }

    #[test]
    fn identify_params() {
        let p = AhciFisImpl::identify(0).unwrap();
        assert_eq!(p.command, ATA_CMD_IDENTIFY);
        assert!(p.is_command);
        assert_eq!(p.device, ATA_DEV_LBA);
        assert_eq!(p.lba, 0);
        assert_eq!(p.count, 0);
    }

    #[test]
    fn identify_encode_layout() {
        let p = AhciFisImpl::identify(0).unwrap();
        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        let n = AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        assert_eq!(n, 20);
        assert_eq!(fis[0], 0x27);
        assert_eq!(fis[1], AHCI_FIS_C_BIT); // C=1, PMP=0
        assert_eq!(fis[2], ATA_CMD_IDENTIFY);
        assert_eq!(fis[7], ATA_DEV_LBA);
        // reserved tail zero
        assert_eq!(&fis[14..20], &[0u8; 6]);
    }

    #[test]
    fn identify_roundtrip() {
        let p = AhciFisImpl::identify(3).unwrap();
        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        let d = AhciFisImpl::decode_h2d(&fis).unwrap();
        assert_eq!(d, p);
    }

    #[test]
    fn read_dma_roundtrip() {
        let p = AhciFisImpl::read_dma(0x1A2B_3C4D, 16, 1).unwrap();
        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        let d = AhciFisImpl::decode_h2d(&fis).unwrap();
        assert_eq!(d.command, ATA_CMD_READ_DMA);
        assert_eq!(d.lba, 0x1A2B_3C4D);
        assert_eq!(d.count, 16);
        assert_eq!(d.pm_port, 1);
        assert_eq!(d, p);
    }

    #[test]
    fn read_dma_lba_bytes() {
        let p = AhciFisImpl::read_dma(0x00_11_22_33_44_55, 0x0201, 0).unwrap();
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        assert_eq!(fis[4], 0x55);
        assert_eq!(fis[5], 0x44);
        assert_eq!(fis[6], 0x33);
        assert_eq!(fis[8], 0x22);
        assert_eq!(fis[9], 0x11);
        assert_eq!(fis[10], 0x00);
        assert_eq!(fis[12], 0x01);
        assert_eq!(fis[13], 0x02);
    }

    #[test]
    fn features_split() {
        let mut p = AhciFisImpl::identify(0).unwrap();
        p.features = 0xABCD;
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        assert_eq!(fis[3], 0xCD);
        assert_eq!(fis[11], 0xAB);
        let d = AhciFisImpl::decode_h2d(&fis).unwrap();
        assert_eq!(d.features, 0xABCD);
    }

    #[test]
    fn truncated_encode() {
        let p = AhciFisImpl::identify(0).unwrap();
        let mut short = [0u8; 10];
        assert_eq!(
            AhciFisImpl::encode_h2d(&p, &mut short),
            Err(AhciFisError::Truncated)
        );
    }

    #[test]
    fn truncated_decode() {
        assert_eq!(
            AhciFisImpl::decode_h2d(&[0x27u8; 5]),
            Err(AhciFisError::Truncated)
        );
    }

    #[test]
    fn bad_type() {
        let mut fis = [0u8; 20];
        fis[0] = 0x34; // D2H
        assert_eq!(AhciFisImpl::decode_h2d(&fis), Err(AhciFisError::BadType));
    }

    #[test]
    fn bad_port_identify() {
        assert_eq!(AhciFisImpl::identify(16), Err(AhciFisError::BadPort));
    }

    #[test]
    fn bad_port_encode() {
        let p = H2dFisParams {
            command: ATA_CMD_IDENTIFY,
            features: 0,
            lba: 0,
            count: 0,
            device: ATA_DEV_LBA,
            pm_port: 0x20,
            is_command: true,
        };
        let mut fis = [0u8; 20];
        assert_eq!(
            AhciFisImpl::encode_h2d(&p, &mut fis),
            Err(AhciFisError::BadPort)
        );
    }

    #[test]
    fn free_match() {
        let p = identify_impl(2).unwrap();
        assert_eq!(p, AhciFisImpl::identify(2).unwrap());
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        encode_h2d_impl(&p, &mut a).unwrap();
        AhciFisImpl::encode_h2d(&p, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn control_update_no_c() {
        let p = H2dFisParams {
            command: 0,
            features: 0,
            lba: 0,
            count: 0,
            device: ATA_DEV_LBA,
            pm_port: 0,
            is_command: false,
        };
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        assert_eq!(fis[1] & AHCI_FIS_C_BIT, 0);
        let d = AhciFisImpl::decode_h2d(&fis).unwrap();
        assert!(!d.is_command);
    }

    #[test]
    fn pm_port_in_byte1() {
        let p = AhciFisImpl::identify(0x0A).unwrap();
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        assert_eq!(fis[1] & AHCI_FIS_PMP_MASK, 0x0A);
        assert_eq!(fis[1] & AHCI_FIS_C_BIT, AHCI_FIS_C_BIT);
    }

    #[test]
    fn banner_cmd() {
        assert_eq!(banner_identify_cmd(), ATA_CMD_IDENTIFY);
    }

    #[test]
    fn banner_str_shape() {
        // AHCI fis OK cmd=identify
        assert_eq!(banner_identify_cmd(), 0xEC);
    }

    #[test]
    fn read_dma_zero_count() {
        let p = AhciFisImpl::read_dma(0, 0, 0).unwrap();
        assert_eq!(p.count, 0);
        assert_eq!(p.command, ATA_CMD_READ_DMA);
    }

    #[test]
    fn read_dma_max_lba48() {
        let lba = 0xFFFF_FFFF_FFFF;
        let p = AhciFisImpl::read_dma(lba, 1, 0).unwrap();
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        let d = AhciFisImpl::decode_h2d(&fis).unwrap();
        assert_eq!(d.lba, lba);
    }

    #[test]
    fn det() {
        let mut a = [0u8; 20];
        let mut b = [0u8; 20];
        let p = AhciFisImpl::identify(0).unwrap();
        AhciFisImpl::encode_h2d(&p, &mut a).unwrap();
        AhciFisImpl::encode_h2d(&p, &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn identify_not_read_dma() {
        let i = AhciFisImpl::identify(0).unwrap();
        let r = AhciFisImpl::read_dma(0, 1, 0).unwrap();
        assert_ne!(i.command, r.command);
    }

    #[test]
    fn end_to_end_banner_path() {
        let p = AhciFisImpl::identify(0).unwrap();
        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        let d = AhciFisImpl::decode_h2d(&fis).unwrap();
        assert_eq!(d.command, ATA_CMD_IDENTIFY);
        assert_eq!(fis[2], ATA_CMD_IDENTIFY);
    }

    #[test]
    fn read_dma_ext_const_available() {
        // EXT opcode locked for future 48-bit path; H2D builder uses classic.
        assert_ne!(ATA_CMD_READ_DMA_EXT, ATA_CMD_READ_DMA);
        assert_eq!(ATA_CMD_READ_DMA_EXT, 0x25);
    }

    #[test]
    fn decode_ignores_extra_bytes() {
        let p = AhciFisImpl::identify(0).unwrap();
        let mut buf = [0u8; 32];
        AhciFisImpl::encode_h2d(&p, &mut buf).unwrap();
        buf[20] = 0xFF;
        let d = AhciFisImpl::decode_h2d(&buf).unwrap();
        assert_eq!(d.command, ATA_CMD_IDENTIFY);
    }

    #[test]
    fn bad_port_read_dma() {
        assert_eq!(
            AhciFisImpl::read_dma(0, 1, 0xFF),
            Err(AhciFisError::BadPort)
        );
    }

    #[test]
    fn device_preserved() {
        let mut p = AhciFisImpl::identify(0).unwrap();
        p.device = 0xE0;
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&p, &mut fis).unwrap();
        assert_eq!(fis[7], 0xE0);
        assert_eq!(AhciFisImpl::decode_h2d(&fis).unwrap().device, 0xE0);
    }
}
