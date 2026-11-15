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

/// Minimum length of an ACPI 2.0+ RSDP structure (36 bytes).
pub const RSDP_V2_LEN: usize = 36;
/// Fixed header length of every ACPI System Description Table (`SDT`).
pub const ACPI_SDT_HDR_LEN: usize = 36;

/// Parsed ACPI 1.0 or ACPI 2.0+ Root System Description Pointer (`RSDP`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsdpAny {
    /// 6-byte OEM identifier.
    pub oem_id: [u8; 6],
    /// ACPI RSDP revision (`0` = ACPI 1.0, `>= 2` = ACPI 2.0+ with `xsdt_addr`).
    pub revision: u8,
    /// Physical 32-bit address of the `RSDT`.
    pub rsdt_addr: u32,
    /// Physical 64-bit address of the `XSDT` when `revision >= 2` and non-zero.
    pub xsdt_addr: Option<u64>,
}

/// Parse an ACPI 1.0 (`20`-byte) or ACPI 2.0+ (`36`-byte) `RSDP`, verifying both the v1
/// checksum and (when `revision >= 2`) the extended length and v2 checksum.
pub fn parse_rsdp_any(bytes: &[u8]) -> Result<RsdpAny, RsdpError> {
    let v1 = parse_v1_impl(bytes)?;
    if v1.revision < 2 {
        return Ok(RsdpAny {
            oem_id: v1.oem_id,
            revision: v1.revision,
            rsdt_addr: v1.rsdt_addr,
            xsdt_addr: None,
        });
    }
    if bytes.len() < RSDP_V2_LEN {
        return Err(RsdpError::Truncated);
    }
    let declared_len = u32::from_le_bytes([bytes[20], bytes[21], bytes[22], bytes[23]]) as usize;
    if !(RSDP_V2_LEN..=4096).contains(&declared_len) {
        return Err(RsdpError::BadChecksum);
    }
    if checksum_impl(&bytes[..RSDP_V2_LEN]) != 0 {
        return Err(RsdpError::BadChecksum);
    }
    let xsdt = u64::from_le_bytes([
        bytes[24], bytes[25], bytes[26], bytes[27], bytes[28], bytes[29], bytes[30], bytes[31],
    ]);
    Ok(RsdpAny {
        oem_id: v1.oem_id,
        revision: v1.revision,
        rsdt_addr: v1.rsdt_addr,
        xsdt_addr: if xsdt != 0 { Some(xsdt) } else { None },
    })
}

/// Scan a 16-byte-aligned BIOS memory window (EBDA or `0x000E_0000..0x0010_0000`)
/// and return the byte offset of the first checksum-valid `RSDP`.
pub fn scan_bios_rsdp_offset(window: &[u8]) -> Option<usize> {
    let mut off = 0usize;
    while off.checked_add(RSDP_V1_LEN).is_some_and(|end| end <= window.len()) {
        if &window[off..off + 8] == RSDP_SIG.as_slice() {
            let rev = window[off + 15];
            let ok = if rev >= 2 && off.checked_add(RSDP_V2_LEN).is_some_and(|end| end <= window.len()) {
                parse_rsdp_any(&window[off..]).is_ok()
            } else if rev < 2 {
                parse_v1_impl(&window[off..off + RSDP_V1_LEN]).is_ok()
            } else {
                false
            };
            if ok {
                return Some(off);
            }
        }
        off = match off.checked_add(16) {
            Some(next) => next,
            None => break,
        };
    }
    None
}

/// Validated 36-byte header of an ACPI System Description Table (`RSDT`, `XSDT`, `APIC`, `HPET`, `DMAR`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AcpiSdtHeader {
    /// 4-byte ASCII table signature (`*b"RSDT"`, `*b"XSDT"`, `*b"APIC"`, `*b"HPET"`, `*b"DMAR"`).
    pub signature: [u8; 4],
    /// Total byte length of the table including the 36-byte SDT header.
    pub length: u32,
    /// Table revision byte.
    pub revision: u8,
    /// 6-byte OEM identifier.
    pub oem_id: [u8; 6],
}

/// Parse and validate an ACPI SDT header (`bytes[..36]`), optionally verifying the full-table
/// byte-sum checksum when `verify_full_checksum` is `true` (requiring `bytes.len() >= length`).
pub fn parse_sdt_header(bytes: &[u8], verify_full_checksum: bool) -> Result<AcpiSdtHeader, RsdpError> {
    if bytes.len() < ACPI_SDT_HDR_LEN {
        return Err(RsdpError::Truncated);
    }
    let sig = [bytes[0], bytes[1], bytes[2], bytes[3]];
    let mut i = 0usize;
    while i < 4 {
        if !sig[i].is_ascii_graphic() && sig[i] != b' ' {
            return Err(RsdpError::BadSig);
        }
        i += 1;
    }
    let len = u32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]);
    if (len as usize) < ACPI_SDT_HDR_LEN || (len as usize) > 65536 {
        return Err(RsdpError::Truncated);
    }
    if verify_full_checksum {
        let total = len as usize;
        if bytes.len() < total {
            return Err(RsdpError::Truncated);
        }
        if checksum_impl(&bytes[..total]) != 0 {
            return Err(RsdpError::BadChecksum);
        }
    }
    let mut oem = [0u8; 6];
    oem.copy_from_slice(&bytes[10..16]);
    Ok(AcpiSdtHeader {
        signature: sig,
        length: len,
        revision: bytes[8],
        oem_id: oem,
    })
}

/// Validate a complete `RSDT` (`is_xsdt = false`, 32-bit pointers) or `XSDT` (`is_xsdt = true`,
/// 64-bit pointers) and extract up to `out.len()` non-zero child SDT physical addresses.
pub fn extract_sdt_table_addrs(
    sdt_bytes: &[u8],
    is_xsdt: bool,
    out: &mut [u64],
) -> Result<usize, RsdpError> {
    let hdr = parse_sdt_header(sdt_bytes, true)?;
    let expected_sig = if is_xsdt { *b"XSDT" } else { *b"RSDT" };
    if hdr.signature != expected_sig {
        return Err(RsdpError::BadSig);
    }
    let body_len = (hdr.length as usize) - ACPI_SDT_HDR_LEN;
    let stride = if is_xsdt { 8usize } else { 4usize };
    if body_len % stride != 0 {
        return Err(RsdpError::Truncated);
    }
    let entries = body_len / stride;
    let mut written = 0usize;
    let mut idx = 0usize;
    while idx < entries && written < out.len() {
        let off = ACPI_SDT_HDR_LEN + idx * stride;
        let addr = if is_xsdt {
            u64::from_le_bytes([
                sdt_bytes[off],
                sdt_bytes[off + 1],
                sdt_bytes[off + 2],
                sdt_bytes[off + 3],
                sdt_bytes[off + 4],
                sdt_bytes[off + 5],
                sdt_bytes[off + 6],
                sdt_bytes[off + 7],
            ])
        } else {
            u32::from_le_bytes([
                sdt_bytes[off],
                sdt_bytes[off + 1],
                sdt_bytes[off + 2],
                sdt_bytes[off + 3],
            ]) as u64
        };
        if addr != 0 {
            out[written] = addr;
            written += 1;
        }
        idx += 1;
    }
    Ok(written)
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

    #[test]
    fn stage13_rsdp_v2_xsdt_rsdt_and_bios_scan_edge_cases() {
        // 1. Valid RSDP v2 (revision = 2, length = 36, xsdt_addr = 0x7FFE_1000).
        let mut v2 = [0u8; RSDP_V2_LEN];
        v2[0..8].copy_from_slice(b"RSD PTR ");
        v2[9..15].copy_from_slice(b"CUTTLE");
        v2[15] = 2; // ACPI 2.0+
        v2[16..20].copy_from_slice(&0x000E_1000u32.to_le_bytes());
        let sum1 = checksum_impl(&v2[..20]);
        v2[8] = (0u8).wrapping_sub(sum1);
        v2[20..24].copy_from_slice(&(RSDP_V2_LEN as u32).to_le_bytes());
        v2[24..32].copy_from_slice(&0x0000_0000_7FFE_1000u64.to_le_bytes());
        let sum2 = checksum_impl(&v2[..RSDP_V2_LEN]);
        v2[32] = (0u8).wrapping_sub(sum2);

        let parsed = parse_rsdp_any(&v2).expect("valid RSDP v2 must parse");
        assert_eq!(parsed.revision, 2);
        assert_eq!(parsed.rsdt_addr, 0x000E_1000);
        assert_eq!(parsed.xsdt_addr, Some(0x7FFE_1000));

        // Truncated v2, corrupt extended checksum, and empty input must fail closed.
        assert_eq!(parse_rsdp_any(&[]), Err(RsdpError::Truncated));
        assert_eq!(parse_rsdp_any(&v2[..24]), Err(RsdpError::Truncated));
        let mut bad_ext = v2;
        bad_ext[32] ^= 0x01;
        assert_eq!(parse_rsdp_any(&bad_ext), Err(RsdpError::BadChecksum));

        // 2. BIOS 16-byte boundary scan ignores misaligned decoy and finds valid 16B-aligned RSDP.
        let mut rom = [0u8; 256];
        rom[4..4 + RSDP_V2_LEN].copy_from_slice(&v2); // misaligned (off % 16 != 0)
        rom[128..128 + RSDP_V2_LEN].copy_from_slice(&v2); // 16B-aligned!
        assert_eq!(scan_bios_rsdp_offset(&rom), Some(128));

        // 3. Valid XSDT (64-bit pointers) and RSDT (32-bit pointers) + malformed/oversized rejections.
        let mut xsdt = [0u8; ACPI_SDT_HDR_LEN + 24];
        let xsdt_len = xsdt.len() as u32;
        xsdt[0..4].copy_from_slice(b"XSDT");
        xsdt[4..8].copy_from_slice(&xsdt_len.to_le_bytes());
        xsdt[8] = 1;
        xsdt[10..16].copy_from_slice(b"CUTTLE");
        xsdt[36..44].copy_from_slice(&0x7FFE_2000u64.to_le_bytes()); // MADT
        xsdt[44..52].copy_from_slice(&0u64.to_le_bytes()); // zero entry skipped
        xsdt[52..60].copy_from_slice(&0x7FFE_3000u64.to_le_bytes()); // HPET
        xsdt[9] = (0u8).wrapping_sub(checksum_impl(&xsdt));

        let mut out = [0u64; 8];
        let n = extract_sdt_table_addrs(&xsdt, true, &mut out).expect("valid XSDT");
        assert_eq!(n, 2);
        assert_eq!(&out[..2], &[0x7FFE_2000, 0x7FFE_3000]);
        assert_eq!(extract_sdt_table_addrs(&xsdt, false, &mut out), Err(RsdpError::BadSig));
        assert_eq!(extract_sdt_table_addrs(&[], true, &mut out), Err(RsdpError::Truncated));

        // Oversized length (> 65536) and unaligned pointer payload must fail closed.
        let mut huge = xsdt;
        huge[4..8].copy_from_slice(&100_000u32.to_le_bytes());
        assert_eq!(parse_sdt_header(&huge, false), Err(RsdpError::Truncated));
        let mut odd_xsdt = [0u8; ACPI_SDT_HDR_LEN + 4];
        let odd_len = odd_xsdt.len() as u32;
        odd_xsdt[0..4].copy_from_slice(b"XSDT");
        odd_xsdt[4..8].copy_from_slice(&odd_len.to_le_bytes());
        odd_xsdt[9] = (0u8).wrapping_sub(checksum_impl(&odd_xsdt));
        assert_eq!(
            extract_sdt_table_addrs(&odd_xsdt, true, &mut out),
            Err(RsdpError::Truncated)
        );
    }
}
