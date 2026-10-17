//! GPT protective MBR + header + partition entry walker — TASK-085.

#![allow(missing_docs)]

use proteus_contracts::{
    Gpt, GptError, GptHeader, GptPart, GPT_ENTRY_LEN, GPT_MBR_TYPE, GPT_SECTOR, GPT_SIG,
};

pub struct GptImpl;

impl Gpt for GptImpl {
    fn parse_header(image: &[u8]) -> Result<GptHeader, GptError> {
        parse_header_impl(image)
    }
    fn read_part(image: &[u8], hdr: &GptHeader, idx: u32) -> Result<GptPart, GptError> {
        read_part_impl(image, hdr, idx)
    }
}

#[cfg(test)]
fn le16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}
fn le32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}
fn le64(b: &[u8], o: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[o..o + 8]);
    u64::from_le_bytes(a)
}
#[cfg(test)]
fn put16(b: &mut [u8], o: usize, v: u16) {
    b[o..o + 2].copy_from_slice(&v.to_le_bytes());
}
fn put32(b: &mut [u8], o: usize, v: u32) {
    b[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn put64(b: &mut [u8], o: usize, v: u64) {
    b[o..o + 8].copy_from_slice(&v.to_le_bytes());
}

pub fn parse_header_impl(image: &[u8]) -> Result<GptHeader, GptError> {
    // Need LBA 0 + LBA 1 at minimum
    if image.len() < 2 * GPT_SECTOR {
        return Err(GptError::Truncated);
    }
    // Protective MBR: partition 0 type 0xEE at offset 446+4
    let mbr = &image[0..GPT_SECTOR];
    if mbr[510] != 0x55 || mbr[511] != 0xAA {
        return Err(GptError::BadMagic);
    }
    if mbr[446 + 4] != GPT_MBR_TYPE {
        return Err(GptError::BadMagic);
    }
    let hdr = &image[GPT_SECTOR..2 * GPT_SECTOR];
    if hdr[0..8] != GPT_SIG {
        return Err(GptError::BadMagic);
    }
    let my_lba = le64(hdr, 24);
    let first_usable = le64(hdr, 40);
    let last_usable = le64(hdr, 48);
    let part_lba = le64(hdr, 72);
    let num_parts = le32(hdr, 80);
    let entry_size = le32(hdr, 84);
    if entry_size as usize != GPT_ENTRY_LEN || num_parts == 0 {
        return Err(GptError::BadGeometry);
    }
    if my_lba != 1 {
        return Err(GptError::BadGeometry);
    }
    Ok(GptHeader {
        my_lba,
        first_usable,
        last_usable,
        part_lba,
        num_parts,
        entry_size,
    })
}

pub fn read_part_impl(image: &[u8], hdr: &GptHeader, idx: u32) -> Result<GptPart, GptError> {
    if idx >= hdr.num_parts {
        return Err(GptError::BadGeometry);
    }
    let off = (hdr.part_lba as usize) * GPT_SECTOR + (idx as usize) * GPT_ENTRY_LEN;
    if off + GPT_ENTRY_LEN > image.len() {
        return Err(GptError::Truncated);
    }
    let e = &image[off..off + GPT_ENTRY_LEN];
    let mut present = false;
    for i in 0..16 {
        if e[i] != 0 {
            present = true;
            break;
        }
    }
    Ok(GptPart {
        start_lba: le64(e, 32),
        end_lba: le64(e, 40),
        present,
    })
}

/// Fixture: MBR + GPT hdr LBA1 + 1 part at LBA2. 3 sectors.
pub const GPT_FIXTURE_SECTORS: usize = 3;
pub const GPT_FIXTURE_BYTES: usize = GPT_FIXTURE_SECTORS * GPT_SECTOR;

pub fn build_banner_fixture(out: &mut [u8]) -> Result<usize, GptError> {
    if out.len() < GPT_FIXTURE_BYTES {
        return Err(GptError::Truncated);
    }
    for b in out.iter_mut().take(GPT_FIXTURE_BYTES) {
        *b = 0;
    }
    // MBR signature + type EE partition
    out[510] = 0x55;
    out[511] = 0xAA;
    out[446 + 4] = GPT_MBR_TYPE;
    // GPT header LBA 1
    let h = &mut out[GPT_SECTOR..2 * GPT_SECTOR];
    h[0..8].copy_from_slice(&GPT_SIG);
    put32(h, 8, 0x0001_0000); // revision 1.0
    put32(h, 12, 92); // header size
    put64(h, 24, 1); // my_lba
    put64(h, 32, 3 * 1024 * 1024 / 512); // alternate (dummy)
    put64(h, 40, 34); // first usable
    put64(h, 48, 1000); // last usable
    put64(h, 72, 2); // part entries LBA
    put32(h, 80, 1); // num parts
    put32(h, 84, GPT_ENTRY_LEN as u32);
    // Partition entry LBA 2: type GUID non-zero, start 34 end 100
    let p = &mut out[2 * GPT_SECTOR..3 * GPT_SECTOR];
    p[0] = 0x28; // first byte of EFI system type-ish
    p[15] = 0x01;
    put64(p, 32, 34);
    put64(p, 40, 100);
    Ok(GPT_FIXTURE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Gpt;

    fn fix() -> [u8; GPT_FIXTURE_BYTES] {
        let mut b = [0u8; GPT_FIXTURE_BYTES];
        build_banner_fixture(&mut b).unwrap();
        b
    }

    #[test]
    fn parse_ok() {
        let img = fix();
        let h = GptImpl::parse_header(&img).unwrap();
        assert_eq!(h.my_lba, 1);
        assert_eq!(h.num_parts, 1);
        assert_eq!(h.part_lba, 2);
    }

    #[test]
    fn read_part0() {
        let img = fix();
        let h = GptImpl::parse_header(&img).unwrap();
        let p = GptImpl::read_part(&img, &h, 0).unwrap();
        assert!(p.present);
        assert_eq!(p.start_lba, 34);
        assert_eq!(p.end_lba, 100);
    }

    #[test]
    fn bad_sig() {
        let mut img = fix();
        img[GPT_SECTOR] = b'X';
        assert_eq!(GptImpl::parse_header(&img), Err(GptError::BadMagic));
    }

    #[test]
    fn truncated() {
        assert_eq!(GptImpl::parse_header(&[0u8; 100]), Err(GptError::Truncated));
    }

    #[test]
    fn banner() {
        let img = fix();
        let h = GptImpl::parse_header(&img).unwrap();
        assert_eq!(h.num_parts, 1);
    }

    #[test]
    fn constants() {
        assert_eq!(&GPT_SIG, b"EFI PART");
        assert_eq!(GPT_MBR_TYPE, 0xEE);
        assert_eq!(GPT_ENTRY_LEN, 128);
    }

    #[test]
    fn free_match() {
        let img = fix();
        assert_eq!(
            parse_header_impl(&img).unwrap(),
            GptImpl::parse_header(&img).unwrap()
        );
    }

    #[test]
    fn bad_mbr_type() {
        let mut img = fix();
        img[446 + 4] = 0x83;
        assert!(GptImpl::parse_header(&img).is_err());
    }

    #[test]
    fn part_oob() {
        let img = fix();
        let h = GptImpl::parse_header(&img).unwrap();
        assert!(GptImpl::read_part(&img, &h, 5).is_err());
    }

    #[test]
    fn empty_part_not_present() {
        let mut img = fix();
        // zero type guid
        for i in 0..16 {
            img[2 * GPT_SECTOR + i] = 0;
        }
        let h = GptImpl::parse_header(&img).unwrap();
        assert!(!GptImpl::read_part(&img, &h, 0).unwrap().present);
    }

    #[test]
    fn det() {
        assert_eq!(fix(), fix());
    }

    #[test]
    fn first_usable() {
        assert_eq!(GptImpl::parse_header(&fix()).unwrap().first_usable, 34);
    }

    #[test]
    fn entry_size() {
        assert_eq!(
            GptImpl::parse_header(&fix()).unwrap().entry_size,
            128
        );
    }

    #[test]
    fn mbr_sig() {
        let img = fix();
        assert_eq!(img[510], 0x55);
        assert_eq!(img[511], 0xAA);
    }

    #[test]
    fn end_to_end() {
        let img = fix();
        let h = GptImpl::parse_header(&img).unwrap();
        let p = GptImpl::read_part(&img, &h, 0).unwrap();
        assert!(p.present && p.start_lba < p.end_lba);
    }

    #[test]
    fn banner_str() {
        // GPT parse OK parts=1
        assert_eq!(GptImpl::parse_header(&fix()).unwrap().num_parts, 1);
    }

    #[test]
    fn short_build() {
        let mut b = [0u8; 10];
        assert!(build_banner_fixture(&mut b).is_err());
    }

    #[test]
    fn geometry_my_lba() {
        assert_eq!(GptImpl::parse_header(&fix()).unwrap().my_lba, 1);
    }

    #[test]
    fn last_usable() {
        assert_eq!(GptImpl::parse_header(&fix()).unwrap().last_usable, 1000);
    }

    #[test]
    fn errors_distinct() {
        assert_ne!(GptError::BadMagic, GptError::Truncated);
    }

    #[test]
    fn le_helpers() {
        let mut b = [0u8; 8];
        put64(&mut b, 0, 0x1122334455667788);
        assert_eq!(le64(&b, 0), 0x1122334455667788);
        let _ = le16(&b, 0);
        let _ = le32(&b, 0);
        put16(&mut b, 0, 1);
        put32(&mut b, 0, 2);
    }

    #[test]
    fn fixture_len() {
        assert_eq!(GPT_FIXTURE_BYTES, 1536);
    }

    #[test]
    fn sig_efi() {
        assert_eq!(&fix()[512..520], b"EFI PART");
    }

    #[test]
    fn det2() {
        assert_eq!(fix(), fix());
    }

    #[test]
    fn part_start_end() {
        let img = fix();
        let h = GptImpl::parse_header(&img).unwrap();
        let p = GptImpl::read_part(&img, &h, 0).unwrap();
        assert_eq!((p.start_lba, p.end_lba), (34, 100));
    }
}
