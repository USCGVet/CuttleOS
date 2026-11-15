//! ELF64 Ehdr + PT_LOAD walker — TASK-074.
//!
//! Minimal no_std parser for factory proof. Hand-built mini ELF fixture.

#![allow(missing_docs)]

use cuttle_contracts::{
    Elf64, ElfError, ElfHeader, ElfPhdr, ELF_CLASS64, ELF_DATA_LE, ELF_EHDR_LEN, ELF_EM_X86_64,
    ELF_ET_DYN, ELF_ET_EXEC, ELF_MAGIC, ELF_MAX_PHDRS, ELF_PHDR_LEN, ELF_PT_LOAD,
};

/// Stateless ELF64 walker.
pub struct Elf64Impl;

impl Elf64 for Elf64Impl {
    fn parse_header(image: &[u8]) -> Result<ElfHeader, ElfError> {
        parse_header_impl(image)
    }
    fn load_phdrs(
        image: &[u8],
        hdr: &ElfHeader,
        out: &mut [ElfPhdr; ELF_MAX_PHDRS],
    ) -> Result<usize, ElfError> {
        load_phdrs_impl(image, hdr, out)
    }
}

#[inline]
fn le16(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}
#[inline]
fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
#[inline]
fn le64(b: &[u8], off: usize) -> u64 {
    let mut a = [0u8; 8];
    a.copy_from_slice(&b[off..off + 8]);
    u64::from_le_bytes(a)
}
#[inline]
fn put16(b: &mut [u8], off: usize, v: u16) {
    let x = v.to_le_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
}
#[inline]
fn put32(b: &mut [u8], off: usize, v: u32) {
    let x = v.to_le_bytes();
    b[off..off + 4].copy_from_slice(&x);
}
#[inline]
fn put64(b: &mut [u8], off: usize, v: u64) {
    let x = v.to_le_bytes();
    b[off..off + 8].copy_from_slice(&x);
}

pub fn parse_header_impl(image: &[u8]) -> Result<ElfHeader, ElfError> {
    if image.len() < ELF_EHDR_LEN {
        return Err(ElfError::Truncated);
    }
    if image[0..4] != ELF_MAGIC {
        return Err(ElfError::BadHeader);
    }
    if image[4] != ELF_CLASS64 || image[5] != ELF_DATA_LE || image[6] != 1 {
        return Err(ElfError::BadHeader);
    }
    let etype = le16(image, 16);
    let machine = le16(image, 18);
    if machine != ELF_EM_X86_64 {
        return Err(ElfError::BadHeader);
    }
    if etype != ELF_ET_EXEC && etype != ELF_ET_DYN {
        return Err(ElfError::BadHeader);
    }
    let entry = le64(image, 24);
    let phoff = le64(image, 32);
    let phentsize = le16(image, 54);
    let phnum = le16(image, 56);
    if phentsize as usize != ELF_PHDR_LEN {
        return Err(ElfError::BadPhdrs);
    }
    if phnum as usize > ELF_MAX_PHDRS {
        return Err(ElfError::TooManyLoads);
    }
    Ok(ElfHeader {
        entry,
        phoff,
        phnum,
        phentsize,
        etype,
        machine,
    })
}

pub fn load_phdrs_impl(
    image: &[u8],
    hdr: &ElfHeader,
    out: &mut [ElfPhdr; ELF_MAX_PHDRS],
) -> Result<usize, ElfError> {
    const EMPTY_PHDR: ElfPhdr = ElfPhdr {
        ptype: 0,
        flags: 0,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        align: 0,
    };
    let phoff = usize::try_from(hdr.phoff).map_err(|_| ElfError::Truncated)?;
    let mut staged = [EMPTY_PHDR; ELF_MAX_PHDRS];
    let mut count = 0usize;
    let mut i = 0u16;
    while i < hdr.phnum {
        let step = (i as usize)
            .checked_mul(ELF_PHDR_LEN)
            .ok_or(ElfError::Truncated)?;
        let off = phoff.checked_add(step).ok_or(ElfError::Truncated)?;
        let end = off.checked_add(ELF_PHDR_LEN).ok_or(ElfError::Truncated)?;
        if end > image.len() {
            return Err(ElfError::Truncated);
        }
        let raw = &image[off..end];
        let ptype = le32(raw, 0);
        if ptype == ELF_PT_LOAD {
            if count >= ELF_MAX_PHDRS {
                return Err(ElfError::TooManyLoads);
            }
            let flags = le32(raw, 4);
            let seg_off = le64(raw, 8);
            let vaddr = le64(raw, 16);
            let filesz = le64(raw, 32);
            let memsz = le64(raw, 40);
            let align = le64(raw, 48);
            // Enforce W^X (`PF_X = 1`, `PF_W = 2`), `filesz <= memsz`, and non-wrapping ranges.
            if (flags & 0x3) == 0x3
                || filesz > memsz
                || seg_off.checked_add(filesz).is_none()
                || vaddr.checked_add(memsz).is_none()
            {
                return Err(ElfError::BadPhdrs);
            }
            let new_end = vaddr + memsz;
            let mut prev = 0usize;
            while prev < count {
                let p_start = staged[prev].vaddr;
                let p_end = p_start + staged[prev].memsz;
                if memsz > 0 && staged[prev].memsz > 0 && vaddr < p_end && p_start < new_end {
                    return Err(ElfError::BadPhdrs);
                }
                prev += 1;
            }
            staged[count] = ElfPhdr {
                ptype,
                flags,
                offset: seg_off,
                vaddr,
                filesz,
                memsz,
                align,
            };
            count += 1;
        }
        i += 1;
    }
    out[..count].copy_from_slice(&staged[..count]);
    Ok(count)
}

// ---------- Mini ELF fixture ----------

/// Banner fixture: Ehdr + 1 PT_LOAD phdr. entry = 0x401000, phnum = 1.
pub const ELF_FIXTURE_LEN: usize = ELF_EHDR_LEN + ELF_PHDR_LEN;
pub const ELF_BANNER_ENTRY: u64 = 0x401000;
pub const ELF_BANNER_PHNUM: u16 = 1;

pub fn build_banner_fixture(out: &mut [u8]) -> Result<usize, ElfError> {
    if out.len() < ELF_FIXTURE_LEN {
        return Err(ElfError::Truncated);
    }
    let mut i = 0usize;
    while i < ELF_FIXTURE_LEN {
        out[i] = 0;
        i += 1;
    }
    // e_ident
    out[0..4].copy_from_slice(&ELF_MAGIC);
    out[4] = ELF_CLASS64;
    out[5] = ELF_DATA_LE;
    out[6] = 1; // EV_CURRENT
    put16(out, 16, ELF_ET_EXEC);
    put16(out, 18, ELF_EM_X86_64);
    put32(out, 20, 1); // e_version
    put64(out, 24, ELF_BANNER_ENTRY);
    put64(out, 32, ELF_EHDR_LEN as u64); // e_phoff
    put64(out, 40, 0); // e_shoff
    put32(out, 48, 0); // e_flags
    put16(out, 52, ELF_EHDR_LEN as u16); // e_ehsize
    put16(out, 54, ELF_PHDR_LEN as u16);
    put16(out, 56, ELF_BANNER_PHNUM);
    put16(out, 58, 0); // e_shentsize
    put16(out, 60, 0); // e_shnum
    put16(out, 62, 0); // e_shstrndx

    // Phdr PT_LOAD
    let p = &mut out[ELF_EHDR_LEN..ELF_FIXTURE_LEN];
    put32(p, 0, ELF_PT_LOAD);
    put32(p, 4, 5); // PF_R|PF_X
    put64(p, 8, 0); // offset
    put64(p, 16, ELF_BANNER_ENTRY); // vaddr
    put64(p, 24, ELF_BANNER_ENTRY); // paddr
    put64(p, 32, 0x100); // filesz
    put64(p, 40, 0x100); // memsz
    put64(p, 48, 0x1000); // align
    Ok(ELF_FIXTURE_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::Elf64;

    fn fixture() -> [u8; ELF_FIXTURE_LEN] {
        let mut b = [0u8; ELF_FIXTURE_LEN];
        build_banner_fixture(&mut b).unwrap();
        b
    }

    #[test]
    fn constants() {
        assert_eq!(&ELF_MAGIC, b"\x7fELF");
        assert_eq!(ELF_EHDR_LEN, 64);
        assert_eq!(ELF_PHDR_LEN, 56);
        assert_eq!(ELF_EM_X86_64, 62);
        assert_eq!(ELF_PT_LOAD, 1);
    }

    #[test]
    fn parse_banner_header() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        assert_eq!(h.entry, ELF_BANNER_ENTRY);
        assert_eq!(h.phnum, 1);
        assert_eq!(h.machine, ELF_EM_X86_64);
        assert_eq!(h.etype, ELF_ET_EXEC);
        assert_eq!(h.phentsize, ELF_PHDR_LEN as u16);
    }

    #[test]
    fn load_one_phdr() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        let n = Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].ptype, ELF_PT_LOAD);
        assert_eq!(out[0].vaddr, ELF_BANNER_ENTRY);
        assert_eq!(out[0].filesz, 0x100);
        assert_eq!(out[0].flags, 5);
    }

    #[test]
    fn rejects_short() {
        assert_eq!(
            Elf64Impl::parse_header(&[0u8; 10]),
            Err(ElfError::Truncated)
        );
    }

    #[test]
    fn rejects_bad_magic() {
        let mut img = fixture();
        img[0] = 0;
        assert_eq!(Elf64Impl::parse_header(&img), Err(ElfError::BadHeader));
    }

    #[test]
    fn rejects_bad_machine() {
        let mut img = fixture();
        put16(&mut img, 18, 3); // EM_386
        assert_eq!(Elf64Impl::parse_header(&img), Err(ElfError::BadHeader));
    }

    #[test]
    fn accepts_dyn() {
        let mut img = fixture();
        put16(&mut img, 16, ELF_ET_DYN);
        let h = Elf64Impl::parse_header(&img).unwrap();
        assert_eq!(h.etype, ELF_ET_DYN);
    }

    #[test]
    fn rejects_wrong_phentsize() {
        let mut img = fixture();
        put16(&mut img, 54, 32);
        assert_eq!(Elf64Impl::parse_header(&img), Err(ElfError::BadPhdrs));
    }

    #[test]
    fn rejects_too_many_phdrs() {
        let mut img = fixture();
        put16(&mut img, 56, (ELF_MAX_PHDRS as u16) + 1);
        assert_eq!(
            Elf64Impl::parse_header(&img),
            Err(ElfError::TooManyLoads)
        );
    }

    #[test]
    fn fixture_deterministic() {
        assert_eq!(fixture(), fixture());
    }

    #[test]
    fn skips_non_load() {
        // Add a second phdr that is PT_NOTE — need larger image
        let mut img = [0u8; ELF_EHDR_LEN + 2 * ELF_PHDR_LEN];
        build_banner_fixture(&mut img).unwrap();
        put16(&mut img, 56, 2); // phnum=2
        // second phdr PT_NOTE = 4
        let p2 = &mut img[ELF_EHDR_LEN + ELF_PHDR_LEN..];
        put32(p2, 0, 4);
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        let n = Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap();
        assert_eq!(n, 1); // only PT_LOAD
    }

    #[test]
    fn truncated_phdr_table() {
        let mut img = fixture();
        // claim phnum=2 but image only has 1 phdr
        put16(&mut img, 56, 2);
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        assert_eq!(
            Elf64Impl::load_phdrs(&img, &h, &mut out),
            Err(ElfError::Truncated)
        );
    }

    #[test]
    fn banner_entry_phnum() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        assert_eq!(h.entry, 0x401000);
        assert_eq!(h.phnum, 1);
    }

    #[test]
    fn free_match() {
        let img = fixture();
        assert_eq!(
            parse_header_impl(&img).unwrap(),
            Elf64Impl::parse_header(&img).unwrap()
        );
    }

    #[test]
    fn class_data_checks() {
        let mut img = fixture();
        img[4] = 1; // ELFCLASS32
        assert!(Elf64Impl::parse_header(&img).is_err());
    }

    #[test]
    fn endian_check() {
        let mut img = fixture();
        img[5] = 2; // big endian
        assert!(Elf64Impl::parse_header(&img).is_err());
    }

    #[test]
    fn version_check() {
        let mut img = fixture();
        img[6] = 0;
        assert!(Elf64Impl::parse_header(&img).is_err());
    }

    #[test]
    fn et_none_rejected() {
        let mut img = fixture();
        put16(&mut img, 16, 0);
        assert!(Elf64Impl::parse_header(&img).is_err());
    }

    #[test]
    fn phoff_in_header() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        assert_eq!(h.phoff, 64);
    }

    #[test]
    fn load_flags_rx() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap();
        assert_eq!(out[0].flags & 1, 1); // PF_X
        assert_eq!(out[0].flags & 4, 4); // PF_R
    }

    #[test]
    fn align_4k() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap();
        assert_eq!(out[0].align, 0x1000);
    }

    #[test]
    fn memsz_eq_filesz_fixture() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap();
        assert_eq!(out[0].filesz, out[0].memsz);
    }

    #[test]
    fn build_len() {
        let mut b = [0u8; ELF_FIXTURE_LEN];
        assert_eq!(build_banner_fixture(&mut b).unwrap(), ELF_FIXTURE_LEN);
    }

    #[test]
    fn zero_phnum() {
        let mut img = fixture();
        put16(&mut img, 56, 0);
        let h = Elf64Impl::parse_header(&img).unwrap();
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        assert_eq!(Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap(), 0);
    }

    #[test]
    fn max_phdrs_ok() {
        let mut img = fixture();
        put16(&mut img, 56, ELF_MAX_PHDRS as u16);
        // header alone accepts; load will truncate on image size
        assert!(Elf64Impl::parse_header(&img).is_ok());
    }

    #[test]
    fn end_to_end_banner() {
        let img = fixture();
        let h = Elf64Impl::parse_header(&img).unwrap();
        assert_eq!(h.phnum, ELF_BANNER_PHNUM);
        assert_eq!(h.entry, ELF_BANNER_ENTRY);
        let mut out = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        assert_eq!(Elf64Impl::load_phdrs(&img, &h, &mut out).unwrap(), 1);
    }

    #[test]
    fn errors_distinct() {
        assert_ne!(ElfError::BadHeader, ElfError::Truncated);
    }

    #[test]
    fn le_helpers() {
        let mut b = [0u8; 16];
        put64(&mut b, 0, 0x0102030405060708);
        assert_eq!(le64(&b, 0), 0x0102030405060708);
    }

    #[test]
    fn entry_nonzero() {
        assert_ne!(ELF_BANNER_ENTRY, 0);
    }

    #[test]
    fn magic_bytes() {
        assert_eq!(ELF_MAGIC[0], 0x7F);
        assert_eq!(ELF_MAGIC[1], b'E');
    }

    #[test]
    fn load_phdrs_rejects_wx_segments_filesz_gt_memsz_phoff_overflow_and_vaddr_overlap() {
        let empty = ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        };

        // 1. `phoff` near `usize::MAX` must return `Err(ElfError::Truncated)` without overflowing `off + ELF_PHDR_LEN`.
        let mut ovf = fixture();
        put64(&mut ovf, 32, u64::MAX - 16);
        let h_ovf = Elf64Impl::parse_header(&ovf).unwrap();
        let mut out = [empty; ELF_MAX_PHDRS];
        assert_eq!(Elf64Impl::load_phdrs(&ovf, &h_ovf, &mut out), Err(ElfError::Truncated));

        // 2. W+X `PT_LOAD` (`PF_R | PF_W | PF_X = 7`) must be rejected with `Err(ElfError::BadPhdrs)`!
        let mut wx = fixture();
        put32(&mut wx[ELF_EHDR_LEN..], 4, 7);
        let h_wx = Elf64Impl::parse_header(&wx).unwrap();
        assert_eq!(Elf64Impl::load_phdrs(&wx, &h_wx, &mut out), Err(ElfError::BadPhdrs));

        // 3. `filesz > memsz` must be rejected with `Err(ElfError::BadPhdrs)`!
        let mut bad_sz = fixture();
        put64(&mut bad_sz[ELF_EHDR_LEN..], 32, 0x200); // filesz
        put64(&mut bad_sz[ELF_EHDR_LEN..], 40, 0x100); // memsz < filesz
        let h_sz = Elf64Impl::parse_header(&bad_sz).unwrap();
        assert_eq!(Elf64Impl::load_phdrs(&bad_sz, &h_sz, &mut out), Err(ElfError::BadPhdrs));

        // 4. Two overlapping `PT_LOAD` virtual ranges must be rejected with `Err(ElfError::BadPhdrs)`!
        let mut overlap = [0u8; ELF_EHDR_LEN + 2 * ELF_PHDR_LEN];
        overlap[..ELF_FIXTURE_LEN].copy_from_slice(&fixture());
        put16(&mut overlap, 56, 2); // phnum = 2
        let p2_off = ELF_EHDR_LEN + ELF_PHDR_LEN;
        let p1_copy = overlap[ELF_EHDR_LEN..p2_off].to_vec();
        overlap[p2_off..p2_off + ELF_PHDR_LEN].copy_from_slice(&p1_copy);
        put32(&mut overlap[p2_off..], 4, 6); // PF_R | PF_W
        put64(&mut overlap[p2_off..], 16, ELF_BANNER_ENTRY + 0x80); // overlaps [0x401000, 0x401100)!
        let h_ovl = Elf64Impl::parse_header(&overlap).unwrap();
        let sentinel = ElfPhdr {
            ptype: 0xDEAD_BEEF,
            flags: 0xAA,
            offset: 0x11,
            vaddr: 0x22,
            filesz: 0x33,
            memsz: 0x44,
            align: 0x55,
        };
        let mut out_all_or_nothing = [sentinel; ELF_MAX_PHDRS];
        assert_eq!(
            Elf64Impl::load_phdrs(&overlap, &h_ovl, &mut out_all_or_nothing),
            Err(ElfError::BadPhdrs)
        );
        assert_eq!(
            out_all_or_nothing[0], sentinel,
            "load_phdrs wrote partial phdr[0] before rejecting overlapping phdr[1]"
        );
    }
}

#[cfg(test)]
extern crate alloc;
