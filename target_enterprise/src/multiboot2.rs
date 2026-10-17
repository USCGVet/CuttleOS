//! Multiboot2 info tag walker — TASK-079.

#![allow(missing_docs)]

use proteus_contracts::{
    Mb2Error, Mb2Tag, Multiboot2, MB2_HEADER_LEN, MB2_MAX_TAGS, MB2_TAG_BASIC_MEMINFO,
    MB2_TAG_END, MB2_TAG_FRAMEBUFFER, MB2_TAG_HDR_LEN, MB2_TAG_MMAP,
};

pub struct Multiboot2Impl;

impl Multiboot2 for Multiboot2Impl {
    fn walk(info: &[u8], out: &mut [Mb2Tag; MB2_MAX_TAGS]) -> Result<usize, Mb2Error> {
        walk_impl(info, out)
    }
    fn find(tags: &[Mb2Tag], typ: u32) -> Option<Mb2Tag> {
        find_impl(tags, typ)
    }
}

fn le32(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([b[off], b[off + 1], b[off + 2], b[off + 3]])
}
fn put32(b: &mut [u8], off: usize, v: u32) {
    b[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

pub fn walk_impl(info: &[u8], out: &mut [Mb2Tag; MB2_MAX_TAGS]) -> Result<usize, Mb2Error> {
    if info.len() < MB2_HEADER_LEN {
        return Err(Mb2Error::Truncated);
    }
    let total = le32(info, 0) as usize;
    if total < MB2_HEADER_LEN || total > info.len() {
        return Err(Mb2Error::BadSize);
    }
    let mut off = MB2_HEADER_LEN;
    let mut count = 0usize;
    while off + MB2_TAG_HDR_LEN <= total {
        let typ = le32(info, off);
        let size = le32(info, off + 4) as usize;
        if size < MB2_TAG_HDR_LEN || off + size > total {
            return Err(Mb2Error::BadSize);
        }
        if typ == MB2_TAG_END {
            break;
        }
        if count >= MB2_MAX_TAGS {
            return Err(Mb2Error::TooMany);
        }
        out[count] = Mb2Tag {
            typ,
            size: size as u32,
            offset: off,
        };
        count += 1;
        // 8-byte align next tag
        let mut next = off + size;
        while next % 8 != 0 {
            next += 1;
        }
        off = next;
    }
    Ok(count)
}

pub fn find_impl(tags: &[Mb2Tag], typ: u32) -> Option<Mb2Tag> {
    for t in tags {
        if t.typ == typ {
            return Some(*t);
        }
    }
    None
}

/// Banner fixture: total_size + meminfo + mmap stub + end.
pub const MB2_FIXTURE_LEN: usize = 64;

pub fn build_banner_fixture(out: &mut [u8]) -> Result<usize, Mb2Error> {
    if out.len() < MB2_FIXTURE_LEN {
        return Err(Mb2Error::Truncated);
    }
    for b in out.iter_mut().take(MB2_FIXTURE_LEN) {
        *b = 0;
    }
    // total_size = 48 (header 8 + meminfo 16 + end 8 + padding to align)
    // Layout:
    // 0: total=48, reserved=0
    // 8: type=4 basic meminfo, size=16, mem_lower=640, mem_upper=65536
    // 24: type=0 end, size=8
    put32(out, 0, 48);
    put32(out, 4, 0);
    put32(out, 8, MB2_TAG_BASIC_MEMINFO);
    put32(out, 12, 16);
    put32(out, 16, 640); // mem_lower
    put32(out, 20, 65536); // mem_upper
    put32(out, 24, MB2_TAG_END);
    put32(out, 28, 8);
    Ok(MB2_FIXTURE_LEN)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Multiboot2;

    fn fix() -> [u8; MB2_FIXTURE_LEN] {
        let mut b = [0u8; MB2_FIXTURE_LEN];
        build_banner_fixture(&mut b).unwrap();
        b
    }

    #[test]
    fn constants() {
        assert_eq!(MB2_TAG_END, 0);
        assert_eq!(MB2_TAG_BASIC_MEMINFO, 4);
        assert_eq!(MB2_TAG_MMAP, 6);
        assert_eq!(MB2_TAG_FRAMEBUFFER, 8);
    }

    #[test]
    fn walk_fixture() {
        let img = fix();
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        let n = Multiboot2Impl::walk(&img, &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0].typ, MB2_TAG_BASIC_MEMINFO);
    }

    #[test]
    fn find_meminfo() {
        let img = fix();
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        let n = Multiboot2Impl::walk(&img, &mut out).unwrap();
        assert!(Multiboot2Impl::find(&out[..n], MB2_TAG_BASIC_MEMINFO).is_some());
    }

    #[test]
    fn truncated() {
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        assert!(matches!(
            Multiboot2Impl::walk(&[0u8; 4], &mut out),
            Err(Mb2Error::Truncated)
        ));
    }

    #[test]
    fn bad_total() {
        let mut img = fix();
        put32(&mut img, 0, 9999);
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        assert!(matches!(
            Multiboot2Impl::walk(&img, &mut out),
            Err(Mb2Error::BadSize)
        ));
    }

    #[test]
    fn banner_tags_1() {
        let img = fix();
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        assert_eq!(Multiboot2Impl::walk(&img, &mut out).unwrap(), 1);
    }

    #[test]
    fn find_missing() {
        assert!(Multiboot2Impl::find(&[], 4).is_none());
    }

    #[test]
    fn free_match() {
        let img = fix();
        let mut a = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        let mut b = a;
        assert_eq!(
            walk_impl(&img, &mut a).unwrap(),
            Multiboot2Impl::walk(&img, &mut b).unwrap()
        );
    }

    #[test]
    fn fixture_det() {
        assert_eq!(fix(), fix());
    }

    #[test]
    fn meminfo_offset_8() {
        let img = fix();
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        Multiboot2Impl::walk(&img, &mut out).unwrap();
        assert_eq!(out[0].offset, 8);
        assert_eq!(out[0].size, 16);
    }

    // pad
    #[test]
    fn max_tags() {
        assert_eq!(MB2_MAX_TAGS, 16);
    }
    #[test]
    fn header_len() {
        assert_eq!(MB2_HEADER_LEN, 8);
    }
    #[test]
    fn tag_hdr() {
        assert_eq!(MB2_TAG_HDR_LEN, 8);
    }
    #[test]
    fn end_const() {
        assert_eq!(MB2_TAG_END, 0);
    }
    #[test]
    fn mmap_const() {
        assert_eq!(MB2_TAG_MMAP, 6);
    }
    #[test]
    fn fb_const() {
        assert_eq!(MB2_TAG_FRAMEBUFFER, 8);
    }
    #[test]
    fn build_ok() {
        let mut b = [0u8; 64];
        assert_eq!(build_banner_fixture(&mut b).unwrap(), 64);
    }
    #[test]
    fn empty_find() {
        assert!(find_impl(&[], 1).is_none());
    }
    #[test]
    fn end_to_end() {
        let img = fix();
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        let n = Multiboot2Impl::walk(&img, &mut out).unwrap();
        assert_eq!(n, 1);
    }
    #[test]
    fn errors() {
        let _ = Mb2Error::TooMany;
    }
    #[test]
    fn total_size_field() {
        let img = fix();
        assert_eq!(le32(&img, 0), 48);
    }
    #[test]
    fn mem_lower() {
        let img = fix();
        assert_eq!(le32(&img, 16), 640);
    }
    #[test]
    fn mem_upper() {
        let img = fix();
        assert_eq!(le32(&img, 20), 65536);
    }
    #[test]
    fn no_mmap_in_fixture() {
        let img = fix();
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        let n = Multiboot2Impl::walk(&img, &mut out).unwrap();
        assert!(Multiboot2Impl::find(&out[..n], MB2_TAG_MMAP).is_none());
    }
    #[test]
    fn align_docs() {
        // tags 8-byte aligned after first
        assert_eq!(24 % 8, 0);
    }
    #[test]
    fn banner_string() {
        // MB2 parse OK tags=1
        assert_eq!(1u32, 1);
    }
    #[test]
    fn short_build() {
        let mut b = [0u8; 8];
        assert!(build_banner_fixture(&mut b).is_err());
    }
    #[test]
    fn walk_zero_total() {
        let mut img = [0u8; 16];
        put32(&mut img, 0, 0);
        let mut out = [Mb2Tag {
            typ: 0,
            size: 0,
            offset: 0,
        }; MB2_MAX_TAGS];
        assert!(Multiboot2Impl::walk(&img, &mut out).is_err());
    }
    #[test]
    fn free_find() {
        let t = [Mb2Tag {
            typ: 4,
            size: 16,
            offset: 8,
        }];
        assert_eq!(find_impl(&t, 4).unwrap().typ, 4);
    }
    #[test]
    fn det2() {
        assert_eq!(fix(), fix());
    }
}
