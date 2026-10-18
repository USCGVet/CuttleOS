//! ACPI RSDP v1 signature + checksum — TASK-081.

#![allow(missing_docs)]

use cuttle_contracts::{AcpiRsdp, RsdpError, RsdpV1, RSDP_SIG, RSDP_V1_LEN};

pub struct AcpiRsdpImpl;

impl AcpiRsdp for AcpiRsdpImpl {
    fn parse_v1(bytes: &[u8]) -> Result<RsdpV1, RsdpError> {
        parse_v1_impl(bytes)
    }
    fn checksum(bytes: &[u8]) -> u8 {
        checksum_impl(bytes)
    }
}

pub fn checksum_impl(bytes: &[u8]) -> u8 {
    let mut s: u8 = 0;
    for &b in bytes {
        s = s.wrapping_add(b);
    }
    s
}

pub fn parse_v1_impl(bytes: &[u8]) -> Result<RsdpV1, RsdpError> {
    if bytes.len() < RSDP_V1_LEN {
        return Err(RsdpError::Truncated);
    }
    if bytes[0..8] != RSDP_SIG {
        return Err(RsdpError::BadSig);
    }
    if checksum_impl(&bytes[..RSDP_V1_LEN]) != 0 {
        return Err(RsdpError::BadChecksum);
    }
    let mut oem = [0u8; 6];
    oem.copy_from_slice(&bytes[9..15]);
    let revision = bytes[15];
    let rsdt = u32::from_le_bytes([bytes[16], bytes[17], bytes[18], bytes[19]]);
    Ok(RsdpV1 {
        oem_id: oem,
        revision,
        rsdt_addr: rsdt,
    })
}

/// Build a valid v1 RSDP fixture into `out` (20 bytes).
pub fn build_banner_fixture(out: &mut [u8]) -> Result<(), RsdpError> {
    if out.len() < RSDP_V1_LEN {
        return Err(RsdpError::Truncated);
    }
    for b in out.iter_mut().take(RSDP_V1_LEN) {
        *b = 0;
    }
    out[0..8].copy_from_slice(&RSDP_SIG);
    out[9..15].copy_from_slice(b"BOCHS ");
    out[15] = 0; // rev 0
    // rsdt @ 0x000E_0000
    out[16..20].copy_from_slice(&0x000E_0000u32.to_le_bytes());
    // checksum byte at offset 8
    let sum = checksum_impl(&out[..RSDP_V1_LEN]);
    // we need total sum 0; currently sum includes checksum 0, so set checksum = -sum
    out[8] = 0u8.wrapping_sub(sum);
    debug_assert_eq!(checksum_impl(&out[..RSDP_V1_LEN]), 0);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::AcpiRsdp;

    fn fix() -> [u8; 20] {
        let mut b = [0u8; 20];
        build_banner_fixture(&mut b).unwrap();
        b
    }

    #[test]
    fn sig() {
        assert_eq!(&RSDP_SIG, b"RSD PTR ");
    }

    #[test]
    fn parse_ok() {
        let b = fix();
        let r = AcpiRsdpImpl::parse_v1(&b).unwrap();
        assert_eq!(&r.oem_id, b"BOCHS ");
        assert_eq!(r.rsdt_addr, 0xE0000);
    }

    #[test]
    fn checksum_zero() {
        let b = fix();
        assert_eq!(AcpiRsdpImpl::checksum(&b), 0);
    }

    #[test]
    fn bad_sig() {
        let mut b = fix();
        b[0] = b'X';
        assert_eq!(AcpiRsdpImpl::parse_v1(&b), Err(RsdpError::BadSig));
    }

    #[test]
    fn bad_cksum() {
        let mut b = fix();
        b[8] ^= 1;
        assert_eq!(AcpiRsdpImpl::parse_v1(&b), Err(RsdpError::BadChecksum));
    }

    #[test]
    fn truncated() {
        assert_eq!(
            AcpiRsdpImpl::parse_v1(&[0u8; 10]),
            Err(RsdpError::Truncated)
        );
    }

    #[test]
    fn banner() {
        let b = fix();
        assert!(AcpiRsdpImpl::parse_v1(&b).is_ok());
    }

    #[test]
    fn free_match() {
        let b = fix();
        assert_eq!(
            parse_v1_impl(&b).unwrap(),
            AcpiRsdpImpl::parse_v1(&b).unwrap()
        );
    }

    #[test]
    fn det() {
        assert_eq!(fix(), fix());
    }

    #[test]
    fn rev0() {
        assert_eq!(fix()[15], 0);
    }

    #[test]
    fn len() {
        assert_eq!(RSDP_V1_LEN, 20);
    }

    #[test]
    fn sum_empty() {
        assert_eq!(checksum_impl(&[]), 0);
    }

    #[test]
    fn sum_ones() {
        assert_eq!(checksum_impl(&[1, 2, 3]), 6);
    }

    #[test]
    fn wrap_sum() {
        assert_eq!(checksum_impl(&[0xFF, 0x02]), 1);
    }

    #[test]
    fn oem() {
        let r = AcpiRsdpImpl::parse_v1(&fix()).unwrap();
        assert_eq!(r.oem_id[0], b'B');
    }

    #[test]
    fn rsdt() {
        assert_eq!(
            AcpiRsdpImpl::parse_v1(&fix()).unwrap().rsdt_addr,
            0xE0000
        );
    }

    #[test]
    fn end_to_end() {
        let mut b = [0u8; 20];
        build_banner_fixture(&mut b).unwrap();
        assert!(AcpiRsdpImpl::parse_v1(&b).is_ok());
    }

    #[test]
    fn short_build() {
        let mut b = [0u8; 8];
        assert!(build_banner_fixture(&mut b).is_err());
    }

    #[test]
    fn errors() {
        assert_ne!(RsdpError::BadSig, RsdpError::BadChecksum);
    }

    #[test]
    fn sig_space() {
        assert_eq!(RSDP_SIG[7], b' ');
    }

    #[test]
    fn banner_str() {
        // RSDP parse OK oem=BOCHS
        assert_eq!(&fix()[9..15], b"BOCHS ");
    }

    #[test]
    fn cksum_byte_nonzero_usually() {
        // often non-zero checksum field
        let b = fix();
        let _ = b[8];
    }

    #[test]
    fn reparse() {
        let b = fix();
        let a = AcpiRsdpImpl::parse_v1(&b).unwrap();
        let c = AcpiRsdpImpl::parse_v1(&b).unwrap();
        assert_eq!(a, c);
    }

    #[test]
    fn v1_only_20() {
        let mut b = [0u8; 36];
        build_banner_fixture(&mut b).unwrap();
        // still parses first 20
        assert!(AcpiRsdpImpl::parse_v1(&b[..20]).is_ok());
    }

    #[test]
    fn corrupt_oem_still_cksum_fail_if_flip_sig() {
        let mut b = fix();
        b[1] ^= 1;
        assert!(AcpiRsdpImpl::parse_v1(&b).is_err());
    }
}
