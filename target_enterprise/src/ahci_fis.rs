//! AHCI Register Host-to-Device FIS encode — TASK-088.
//!
//! Locks the SATA 20-byte H2D layout used for ATA IDENTIFY DEVICE and
//! READ DMA so AHCI command framing is diversifiable only in
//! implementation detail, not wire shape.

#![allow(missing_docs)]

use cuttle_contracts::{
    AhciFis, AhciFisError, H2dFisParams, AHCI_FIS_C_BIT, AHCI_FIS_H2D_LEN, AHCI_FIS_PMP_MASK,
    AHCI_FIS_TYPE_H2D, ATA_CMD_IDENTIFY, ATA_CMD_READ_DMA, ATA_CMD_READ_DMA_EXT, ATA_DEV_LBA,
};

/// ATA command: WRITE DMA (28-bit LBA).
pub const ATA_CMD_WRITE_DMA: u8 = 0xCA;
/// ATA command: WRITE DMA EXT (48-bit LBA).
pub const ATA_CMD_WRITE_DMA_EXT: u8 = 0x35;
/// ATA command: FLUSH CACHE (28-bit non-data).
pub const ATA_CMD_FLUSH_CACHE: u8 = 0xE7;
/// ATA command: FLUSH CACHE EXT (48-bit non-data).
pub const ATA_CMD_FLUSH_CACHE_EXT: u8 = 0xEA;

/// Exclusive sector ceiling for 28-bit LBA commands (`2^28` sectors = 128 GiB).
pub const AHCI_LBA28_MAX_SECTORS: u64 = 1u64 << 28;
/// Exclusive sector ceiling for 48-bit LBA EXT commands (`2^48` sectors = 128 PiB).
pub const AHCI_LBA48_MAX_SECTORS: u64 = 1u64 << 48;

/// Errors returned when constructing bounded 28-bit or 48-bit DMA FIS parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaFisError {
    /// Underlying port/FIS validation error.
    Fis(AhciFisError),
    /// Transfer count of zero sectors is rejected.
    ZeroCount,
    /// Sector count exceeds the command mode's per-command limit (`256` for LBA28, `65535` here for u16 LBA48).
    CountTooLarge,
    /// Starting LBA or `lba + count` exceeds the addressing mode's range (`2^28` or `2^48`).
    LbaOutOfRange,
}

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

/// Build validated Register H2D FIS parameters for multi-sector DMA read or write.
///
/// - When `lba48` is `true`, emits `READ DMA EXT` (`0x25`) or `WRITE DMA EXT` (`0x35`),
///   checking `1 <= count` and `lba + count <= 2^48`.
/// - When `lba48` is `false`, emits 28-bit `READ DMA` (`0xC8`) or `WRITE DMA` (`0xCA`),
///   packing `LBA[27:24]` into `device[3:0]` (`ATA_DEV_LBA | ((lba >> 24) & 0x0F)`) per
///   ATA/SATA specification and checking `1 <= count <= 256` and `lba + count <= 2^28`.
pub fn build_rw_dma_fis(
    lba: u64,
    count: u16,
    write: bool,
    lba48: bool,
    pm_port: u8,
) -> Result<H2dFisParams, DmaFisError> {
    check_port(pm_port).map_err(DmaFisError::Fis)?;
    if count == 0 {
        return Err(DmaFisError::ZeroCount);
    }
    if lba48 {
        let end = lba
            .checked_add(count as u64)
            .ok_or(DmaFisError::LbaOutOfRange)?;
        if lba >= AHCI_LBA48_MAX_SECTORS || end > AHCI_LBA48_MAX_SECTORS {
            return Err(DmaFisError::LbaOutOfRange);
        }
        Ok(H2dFisParams {
            command: if write {
                ATA_CMD_WRITE_DMA_EXT
            } else {
                ATA_CMD_READ_DMA_EXT
            },
            features: 0,
            lba,
            count,
            device: ATA_DEV_LBA,
            pm_port,
            is_command: true,
        })
    } else {
        if count > 256 {
            return Err(DmaFisError::CountTooLarge);
        }
        let end = lba
            .checked_add(count as u64)
            .ok_or(DmaFisError::LbaOutOfRange)?;
        if lba >= AHCI_LBA28_MAX_SECTORS || end > AHCI_LBA28_MAX_SECTORS {
            return Err(DmaFisError::LbaOutOfRange);
        }
        let dev_hi = ((lba >> 24) & 0x0F) as u8;
        // Classic 28-bit ATA encodes 256 sectors as 0 in the 8-bit sector count register.
        let fis_count = if count == 256 { 0 } else { count & 0xFF };
        Ok(H2dFisParams {
            command: if write {
                ATA_CMD_WRITE_DMA
            } else {
                ATA_CMD_READ_DMA
            },
            features: 0,
            lba: lba & 0x00FF_FFFF,
            count: fis_count,
            device: ATA_DEV_LBA | dev_hi,
            pm_port,
            is_command: true,
        })
    }
}

/// Build Register H2D FIS parameters for `FLUSH CACHE EXT` (`0xEA`) or `FLUSH CACHE` (`0xE7`).
pub fn build_flush_fis(lba48: bool, pm_port: u8) -> Result<H2dFisParams, AhciFisError> {
    check_port(pm_port)?;
    Ok(H2dFisParams {
        command: if lba48 {
            ATA_CMD_FLUSH_CACHE_EXT
        } else {
            ATA_CMD_FLUSH_CACHE
        },
        features: 0,
        lba: 0,
        count: 0,
        device: ATA_DEV_LBA,
        pm_port,
        is_command: true,
    })
}

/// Parse addressable sector capacity and 48-bit LBA capability `(sectors, supports_lba48)`
/// from a 512-byte ATA `IDENTIFY DEVICE` payload.
///
/// Inspects Word 83 bit 10 (`48-bit Address feature set supported`), Words `100..=103`
/// (48-bit max user LBA count), and Words `60..=61` (28-bit user addressable sectors).
pub fn parse_identify_geometry(identify_data: &[u8; 512]) -> Option<(u64, bool)> {
    if identify_data.iter().all(|&b| b == 0) {
        return None;
    }
    let word = |w: usize| u16::from_le_bytes([identify_data[2 * w], identify_data[2 * w + 1]]) as u64;
    let lba28 = word(60) | (word(61) << 16);
    let lba48_raw = word(100) | (word(101) << 16) | (word(102) << 32) | (word(103) << 48);
    let lba48 = lba48_raw & (AHCI_LBA48_MAX_SECTORS - 1);
    let cmd_set_lba48 = (word(83) & (1 << 10)) != 0;
    if cmd_set_lba48 && lba48 != 0 {
        Some((lba48, true))
    } else if lba28 != 0 {
        Some((lba28.min(AHCI_LBA28_MAX_SECTORS), false))
    } else if lba48 != 0 {
        Some((lba48.min(AHCI_LBA28_MAX_SECTORS), false))
    } else {
        None
    }
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

    #[test]
    fn rw_dma_ext_48bit_and_28bit_boundary_encoding() {
        // 48-bit READ DMA EXT / WRITE DMA EXT above 2^28 sectors.
        let high_lba = (1u64 << 34) | 0x0504_0302;
        let rd = build_rw_dma_fis(high_lba, 26, false, true, 0).unwrap();
        assert_eq!(rd.command, ATA_CMD_READ_DMA_EXT);
        assert_eq!(rd.lba, high_lba);
        assert_eq!(rd.count, 26);
        assert_eq!(rd.device, ATA_DEV_LBA);
        let mut fis = [0u8; 20];
        AhciFisImpl::encode_h2d(&rd, &mut fis).unwrap();
        assert_eq!(AhciFisImpl::decode_h2d(&fis).unwrap(), rd);

        let wr = build_rw_dma_fis(high_lba, 64, true, true, 0).unwrap();
        assert_eq!(wr.command, ATA_CMD_WRITE_DMA_EXT);
        assert_eq!(wr.count, 64);

        // Bounds checks on 48-bit and 28-bit modes.
        assert_eq!(
            build_rw_dma_fis(0, 0, false, true, 0),
            Err(DmaFisError::ZeroCount)
        );
        assert_eq!(
            build_rw_dma_fis(AHCI_LBA48_MAX_SECTORS - 4, 5, true, true, 0),
            Err(DmaFisError::LbaOutOfRange)
        );
        assert!(build_rw_dma_fis(AHCI_LBA48_MAX_SECTORS - 5, 5, true, true, 0).is_ok());

        // 28-bit mode packs bits 27:24 into device[3:0] and rejects >= 2^28.
        let lba28_hi = 0x0ABC_DEF0u64;
        let rd28 = build_rw_dma_fis(lba28_hi, 256, false, false, 0).unwrap();
        assert_eq!(rd28.command, ATA_CMD_READ_DMA);
        assert_eq!(rd28.device, ATA_DEV_LBA | 0x0A);
        assert_eq!(rd28.lba, 0x00BC_DEF0);
        assert_eq!(rd28.count, 0);
        assert_eq!(
            build_rw_dma_fis(AHCI_LBA28_MAX_SECTORS, 1, false, false, 0),
            Err(DmaFisError::LbaOutOfRange)
        );
        assert_eq!(
            build_rw_dma_fis(0, 257, true, false, 0),
            Err(DmaFisError::CountTooLarge)
        );

        assert_eq!(
            build_flush_fis(true, 0).unwrap().command,
            ATA_CMD_FLUSH_CACHE_EXT
        );
        assert_eq!(
            build_flush_fis(false, 0).unwrap().command,
            ATA_CMD_FLUSH_CACHE
        );
    }

    #[test]
    fn parse_identify_geometry_lba48_and_lba28_fallback() {
        let mut id = [0u8; 512];
        assert_eq!(parse_identify_geometry(&id), None);

        // QEMU-style LBA48 drive > 128 GiB: word 83 bit 10 set, words 100..103 = 0x2_0000_0000.
        let big_sectors: u64 = 0x2_0000_0000;
        id[2 * 60..2 * 62].copy_from_slice(&0x0FFF_FFFFu32.to_le_bytes());
        id[2 * 83..2 * 84].copy_from_slice(&(1u16 << 10).to_le_bytes());
        id[2 * 100..2 * 104].copy_from_slice(&big_sectors.to_le_bytes());
        assert_eq!(parse_identify_geometry(&id), Some((big_sectors, true)));

        // Legacy LBA28-only drive: word 83 bit 10 clear.
        id[2 * 83..2 * 84].copy_from_slice(&0u16.to_le_bytes());
        id[2 * 100..2 * 104].copy_from_slice(&0u64.to_le_bytes());
        id[2 * 60..2 * 62].copy_from_slice(&2048u32.to_le_bytes());
        assert_eq!(parse_identify_geometry(&id), Some((2048, false)));
    }
}
