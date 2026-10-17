//! FAT32 BPB + root-directory walker — TASK-070.
//!
//! Read-only codec over a caller-supplied image. Mini fixture embeds
//! HELLO.TXT for the kernel banner.

#![allow(missing_docs)]
#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    Fat32, FatBpb, FatDirent, FatError, FAT_ATTR_DIR, FAT_ATTR_LFN, FAT_ATTR_VOLUME,
    FAT_BPB_BYTES_PER_SECTOR, FAT_BPB_FAT_SIZE_32, FAT_BPB_FS_TYPE, FAT_BPB_NUM_FATS,
    FAT_BPB_RESERVED, FAT_BPB_ROOT_CLUSTER, FAT_BPB_SEC_PER_CLUS, FAT_CLUS_MASK, FAT_DIR_ATTR,
    FAT_DIR_CLUS_HI, FAT_DIR_CLUS_LO, FAT_DIR_ENTRY_LEN, FAT_DIR_SIZE, FAT_EOC, FAT_SECTOR_SIZE,
};

/// Mounted FAT32 layout.
pub struct Fat32Impl {
    bpb: FatBpb,
}

impl Fat32 for Fat32Impl {
    fn mount(image: &[u8]) -> Result<Self, FatError> {
        let bpb = parse_bpb(image)?;
        Ok(Fat32Impl { bpb })
    }
    fn bpb(&self) -> &FatBpb {
        &self.bpb
    }
    fn lookup_root(&self, image: &[u8], name_83: &[u8; 11]) -> Result<FatDirent, FatError> {
        lookup_root_impl(&self.bpb, image, name_83)
    }
    fn read_file(
        &self,
        image: &[u8],
        ent: &FatDirent,
        out: &mut [u8],
    ) -> Result<usize, FatError> {
        read_file_impl(&self.bpb, image, ent, out)
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
fn put_le16(b: &mut [u8], off: usize, v: u16) {
    let x = v.to_le_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
}
#[inline]
fn put_le32(b: &mut [u8], off: usize, v: u32) {
    let x = v.to_le_bytes();
    b[off] = x[0];
    b[off + 1] = x[1];
    b[off + 2] = x[2];
    b[off + 3] = x[3];
}

/// Parse BPB from sector 0.
pub fn parse_bpb(image: &[u8]) -> Result<FatBpb, FatError> {
    if image.len() < FAT_SECTOR_SIZE {
        return Err(FatError::Truncated);
    }
    // Boot signature 0x55AA at 510.
    if image[510] != 0x55 || image[511] != 0xAA {
        return Err(FatError::BadBpb);
    }
    let bytes_per_sector = le16(image, FAT_BPB_BYTES_PER_SECTOR);
    if bytes_per_sector as usize != FAT_SECTOR_SIZE {
        return Err(FatError::BadBpb);
    }
    let sectors_per_cluster = image[FAT_BPB_SEC_PER_CLUS];
    if sectors_per_cluster == 0 {
        return Err(FatError::BadBpb);
    }
    let reserved_sectors = le16(image, FAT_BPB_RESERVED);
    let num_fats = image[FAT_BPB_NUM_FATS];
    if num_fats == 0 {
        return Err(FatError::BadBpb);
    }
    let fat_size_sectors = le32(image, FAT_BPB_FAT_SIZE_32);
    if fat_size_sectors == 0 {
        return Err(FatError::BadBpb);
    }
    let root_cluster = le32(image, FAT_BPB_ROOT_CLUSTER);
    if root_cluster < 2 {
        return Err(FatError::BadBpb);
    }
    // FS type string at 82 should start with "FAT"
    if image.len() > FAT_BPB_FS_TYPE + 3 {
        if &image[FAT_BPB_FS_TYPE..FAT_BPB_FS_TYPE + 3] != b"FAT" {
            return Err(FatError::BadBpb);
        }
    }
    let fat_start = reserved_sectors as u32;
    let first_data_sector =
        fat_start + (num_fats as u32) * fat_size_sectors;
    Ok(FatBpb {
        bytes_per_sector,
        sectors_per_cluster,
        reserved_sectors,
        num_fats,
        fat_size_sectors,
        root_cluster,
        fat_start,
        first_data_sector,
    })
}

fn cluster_to_lba(bpb: &FatBpb, cluster: u32) -> u32 {
    bpb.first_data_sector + (cluster - 2) * (bpb.sectors_per_cluster as u32)
}

fn sector_slice(image: &[u8], lba: u32) -> Result<&[u8], FatError> {
    let off = (lba as usize) * FAT_SECTOR_SIZE;
    if off + FAT_SECTOR_SIZE > image.len() {
        return Err(FatError::Truncated);
    }
    Ok(&image[off..off + FAT_SECTOR_SIZE])
}

fn fat_next(bpb: &FatBpb, image: &[u8], cluster: u32) -> Result<Option<u32>, FatError> {
    let fat_offset = (cluster as usize) * 4;
    let sec = bpb.fat_start + (fat_offset as u32) / (bpb.bytes_per_sector as u32);
    let in_sec = fat_offset % (bpb.bytes_per_sector as usize);
    let s = sector_slice(image, sec)?;
    let entry = le32(s, in_sec) & FAT_CLUS_MASK;
    if entry >= FAT_EOC {
        return Ok(None);
    }
    if entry < 2 {
        return Err(FatError::BadChain);
    }
    Ok(Some(entry))
}

fn parse_dirent(raw: &[u8]) -> Option<FatDirent> {
    if raw.len() < FAT_DIR_ENTRY_LEN {
        return None;
    }
    if raw[0] == 0x00 {
        return None; // end of dir
    }
    if raw[0] == 0xE5 {
        return None; // deleted
    }
    let attr = raw[FAT_DIR_ATTR];
    if attr == FAT_ATTR_LFN {
        return None;
    }
    if attr & FAT_ATTR_VOLUME != 0 {
        return None;
    }
    let mut name_83 = [0u8; 11];
    name_83.copy_from_slice(&raw[0..11]);
    let clus_hi = le16(raw, FAT_DIR_CLUS_HI) as u32;
    let clus_lo = le16(raw, FAT_DIR_CLUS_LO) as u32;
    let cluster = (clus_hi << 16) | clus_lo;
    let size = le32(raw, FAT_DIR_SIZE);
    Some(FatDirent {
        name_83,
        attr,
        cluster,
        size,
    })
}

fn name_eq_ci(a: &[u8; 11], b: &[u8; 11]) -> bool {
    let mut i = 0usize;
    while i < 11 {
        let x = if a[i] >= b'a' && a[i] <= b'z' {
            a[i] - 32
        } else {
            a[i]
        };
        let y = if b[i] >= b'a' && b[i] <= b'z' {
            b[i] - 32
        } else {
            b[i]
        };
        if x != y {
            return false;
        }
        i += 1;
    }
    true
}

pub fn lookup_root_impl(
    bpb: &FatBpb,
    image: &[u8],
    name_83: &[u8; 11],
) -> Result<FatDirent, FatError> {
    let mut cluster = bpb.root_cluster;
    loop {
        let lba = cluster_to_lba(bpb, cluster);
        let mut s = 0u8;
        while s < bpb.sectors_per_cluster {
            let sec = sector_slice(image, lba + s as u32)?;
            let mut off = 0usize;
            while off + FAT_DIR_ENTRY_LEN <= FAT_SECTOR_SIZE {
                if sec[off] == 0x00 {
                    return Err(FatError::NotFound);
                }
                if let Some(ent) = parse_dirent(&sec[off..off + FAT_DIR_ENTRY_LEN]) {
                    if name_eq_ci(&ent.name_83, name_83) {
                        if ent.attr & FAT_ATTR_DIR != 0 {
                            return Err(FatError::NotFile);
                        }
                        return Ok(ent);
                    }
                }
                off += FAT_DIR_ENTRY_LEN;
            }
            s += 1;
        }
        match fat_next(bpb, image, cluster)? {
            Some(n) => cluster = n,
            None => return Err(FatError::NotFound),
        }
    }
}

pub fn read_file_impl(
    bpb: &FatBpb,
    image: &[u8],
    ent: &FatDirent,
    out: &mut [u8],
) -> Result<usize, FatError> {
    if ent.size as usize > out.len() {
        return Err(FatError::BufferTooSmall);
    }
    if ent.size == 0 {
        return Ok(0);
    }
    let mut cluster = ent.cluster;
    if cluster < 2 {
        return Err(FatError::BadChain);
    }
    let mut written = 0usize;
    let need = ent.size as usize;
    while written < need {
        let lba = cluster_to_lba(bpb, cluster);
        let mut s = 0u8;
        while s < bpb.sectors_per_cluster && written < need {
            let sec = sector_slice(image, lba + s as u32)?;
            let take = core::cmp::min(FAT_SECTOR_SIZE, need - written);
            out[written..written + take].copy_from_slice(&sec[..take]);
            written += take;
            s += 1;
        }
        if written >= need {
            break;
        }
        match fat_next(bpb, image, cluster)? {
            Some(n) => cluster = n,
            None => return Err(FatError::BadChain),
        }
    }
    Ok(need)
}

// ---------- Banner fixture (compact FAT32) ----------

/// Fixture layout:
/// - LBA 0: BPB (512 B/sec, 1 sec/clus, reserved=1, fats=2, fat_size=1, root=2)
/// - LBA 1: FAT #0 (cluster 2 → EOC)
/// - LBA 2: FAT #1 (mirror)
/// - LBA 3: cluster 2 = root dir (HELLO.TXT → cluster 3)
/// - LBA 4: cluster 3 = file body
pub const FAT_FIXTURE_SECTORS: usize = 5;
pub const FAT_FIXTURE_BYTES: usize = FAT_FIXTURE_SECTORS * FAT_SECTOR_SIZE;
/// HELLO.TXT body.
pub const FAT_HELLO_BODY: &[u8] = b"hello fat32!\n";
pub const FAT_HELLO_LEN: usize = 13;
/// 8.3 name HELLO   TXT
pub const FAT_HELLO_83: [u8; 11] = *b"HELLO   TXT";

/// Build the locked banner FAT image into `out`.
pub fn build_banner_fixture(out: &mut [u8]) -> Result<usize, FatError> {
    if out.len() < FAT_FIXTURE_BYTES {
        return Err(FatError::BufferTooSmall);
    }
    let mut i = 0usize;
    while i < FAT_FIXTURE_BYTES {
        out[i] = 0;
        i += 1;
    }
    // BPB
    out[0] = 0xEB;
    out[1] = 0x58;
    out[2] = 0x90; // jmp
    put_le16(out, FAT_BPB_BYTES_PER_SECTOR, 512);
    out[FAT_BPB_SEC_PER_CLUS] = 1;
    put_le16(out, FAT_BPB_RESERVED, 1);
    out[FAT_BPB_NUM_FATS] = 2;
    put_le32(out, FAT_BPB_FAT_SIZE_32, 1);
    put_le32(out, FAT_BPB_ROOT_CLUSTER, 2);
    out[FAT_BPB_FS_TYPE..FAT_BPB_FS_TYPE + 8].copy_from_slice(b"FAT32   ");
    out[510] = 0x55;
    out[511] = 0xAA;

    // FAT #0 at LBA 1: entries for clusters 0,1 reserved; 2=EOC; 3=EOC
    {
        let fat0 = &mut out[FAT_SECTOR_SIZE..2 * FAT_SECTOR_SIZE];
        put_le32(fat0, 0, 0x0FFF_FFF8); // media
        put_le32(fat0, 4, 0x0FFF_FFFF);
        put_le32(fat0, 8, 0x0FFF_FFFF); // root cluster 2 EOC
        put_le32(fat0, 12, 0x0FFF_FFFF); // file cluster 3 EOC
    }
    // FAT #1 mirror LBA 2 — copy bytes without overlapping borrows
    let mut i = 0usize;
    while i < FAT_SECTOR_SIZE {
        out[2 * FAT_SECTOR_SIZE + i] = out[FAT_SECTOR_SIZE + i];
        i += 1;
    }

    // Root dir at LBA 3 (cluster 2): one 8.3 entry HELLO.TXT → cluster 3
    let dir = &mut out[3 * FAT_SECTOR_SIZE..4 * FAT_SECTOR_SIZE];
    dir[0..11].copy_from_slice(&FAT_HELLO_83);
    dir[FAT_DIR_ATTR] = 0x20; // archive file
    put_le16(dir, FAT_DIR_CLUS_HI, 0);
    put_le16(dir, FAT_DIR_CLUS_LO, 3);
    put_le32(dir, FAT_DIR_SIZE, FAT_HELLO_LEN as u32);

    // File body LBA 4 (cluster 3)
    let body = &mut out[4 * FAT_SECTOR_SIZE..5 * FAT_SECTOR_SIZE];
    body[..FAT_HELLO_LEN].copy_from_slice(FAT_HELLO_BODY);

    Ok(FAT_FIXTURE_BYTES)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Fat32;

    fn fixture() -> [u8; FAT_FIXTURE_BYTES] {
        let mut img = [0u8; FAT_FIXTURE_BYTES];
        build_banner_fixture(&mut img).unwrap();
        img
    }

    #[test]
    fn constants() {
        assert_eq!(FAT_SECTOR_SIZE, 512);
        assert_eq!(FAT_DIR_ENTRY_LEN, 32);
        assert_eq!(FAT_HELLO_LEN, FAT_HELLO_BODY.len());
    }

    #[test]
    fn mount_fixture() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let b = fs.bpb();
        assert_eq!(b.bytes_per_sector, 512);
        assert_eq!(b.sectors_per_cluster, 1);
        assert_eq!(b.num_fats, 2);
        assert_eq!(b.root_cluster, 2);
        assert_eq!(b.fat_start, 1);
        assert_eq!(b.first_data_sector, 3); // 1 + 2*1
    }

    #[test]
    fn mount_rejects_short() {
        assert!(matches!(Fat32Impl::mount(&[0u8; 100]), Err(FatError::Truncated)));
    }

    #[test]
    fn mount_rejects_bad_sig() {
        let mut img = fixture();
        img[510] = 0;
        assert!(matches!(Fat32Impl::mount(&img), Err(FatError::BadBpb)));
    }

    #[test]
    fn lookup_hello() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let e = fs.lookup_root(&img, &FAT_HELLO_83).unwrap();
        assert_eq!(e.cluster, 3);
        assert_eq!(e.size, FAT_HELLO_LEN as u32);
    }

    #[test]
    fn lookup_case_insensitive() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let name = *b"hello   txt";
        assert!(fs.lookup_root(&img, &name).is_ok());
    }

    #[test]
    fn lookup_missing() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        assert_eq!(
            fs.lookup_root(&img, b"MISSING TXT"),
            Err(FatError::NotFound)
        );
    }

    #[test]
    fn read_hello_body() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let e = fs.lookup_root(&img, &FAT_HELLO_83).unwrap();
        let mut out = [0u8; 64];
        let n = fs.read_file(&img, &e, &mut out).unwrap();
        assert_eq!(&out[..n], FAT_HELLO_BODY);
    }

    #[test]
    fn read_buffer_too_small() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let e = fs.lookup_root(&img, &FAT_HELLO_83).unwrap();
        let mut out = [0u8; 4];
        assert_eq!(
            fs.read_file(&img, &e, &mut out),
            Err(FatError::BufferTooSmall)
        );
    }

    #[test]
    fn bpb_round_geometry() {
        let img = fixture();
        let bpb = parse_bpb(&img).unwrap();
        assert_eq!(bpb.reserved_sectors, 1);
        assert_eq!(bpb.fat_size_sectors, 1);
    }

    #[test]
    fn fixture_deterministic() {
        assert_eq!(fixture(), fixture());
    }

    #[test]
    fn empty_file_size_zero() {
        // craft dirent with size 0
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let mut e = fs.lookup_root(&img, &FAT_HELLO_83).unwrap();
        e.size = 0;
        let mut out = [0u8; 8];
        assert_eq!(fs.read_file(&img, &e, &mut out).unwrap(), 0);
    }

    #[test]
    fn bad_cluster_zero() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        let e = FatDirent {
            name_83: *b"X       TXT",
            attr: 0x20,
            cluster: 0,
            size: 1,
        };
        let mut out = [0u8; 8];
        assert_eq!(
            fs.read_file(&img, &e, &mut out),
            Err(FatError::BadChain)
        );
    }

    #[test]
    fn cluster_to_lba_root() {
        let img = fixture();
        let b = parse_bpb(&img).unwrap();
        assert_eq!(cluster_to_lba(&b, 2), 3);
        assert_eq!(cluster_to_lba(&b, 3), 4);
    }

    #[test]
    fn name_eq_ci_spaces() {
        assert!(name_eq_ci(b"HELLO   TXT", b"hello   txt"));
        assert!(!name_eq_ci(b"HELLO   TXT", b"HELLO   TXU"));
    }

    #[test]
    fn parse_dirent_deleted() {
        let mut raw = [0u8; 32];
        raw[0] = 0xE5;
        assert!(parse_dirent(&raw).is_none());
    }

    #[test]
    fn parse_dirent_lfn() {
        let mut raw = [0u8; 32];
        raw[0] = 0x41;
        raw[FAT_DIR_ATTR] = FAT_ATTR_LFN;
        assert!(parse_dirent(&raw).is_none());
    }

    #[test]
    fn parse_dirent_volume() {
        let mut raw = [0u8; 32];
        raw[0] = b'V';
        raw[FAT_DIR_ATTR] = FAT_ATTR_VOLUME;
        assert!(parse_dirent(&raw).is_none());
    }

    #[test]
    fn fat_next_eoc() {
        let img = fixture();
        let b = parse_bpb(&img).unwrap();
        assert_eq!(fat_next(&b, &img, 2).unwrap(), None);
    }

    #[test]
    fn mount_rejects_zero_spc() {
        let mut img = fixture();
        img[FAT_BPB_SEC_PER_CLUS] = 0;
        assert!(matches!(Fat32Impl::mount(&img), Err(FatError::BadBpb)));
    }

    #[test]
    fn mount_rejects_bad_fstype() {
        let mut img = fixture();
        img[FAT_BPB_FS_TYPE] = b'X';
        assert!(matches!(Fat32Impl::mount(&img), Err(FatError::BadBpb)));
    }

    #[test]
    fn end_to_end_banner() {
        let img = fixture();
        let fs = Fat32Impl::mount(&img).unwrap();
        assert_eq!(fs.bpb().num_fats, 2);
        assert_eq!(fs.bpb().root_cluster, 2);
        let e = fs.lookup_root(&img, &FAT_HELLO_83).unwrap();
        let mut out = [0u8; 32];
        let n = fs.read_file(&img, &e, &mut out).unwrap();
        assert_eq!(n, FAT_HELLO_LEN);
        assert_eq!(&out[..n], FAT_HELLO_BODY);
    }

    #[test]
    fn dir_flag_rejects() {
        let img = fixture();
        // Patch HELLO entry attr to directory
        let mut img = img;
        img[3 * FAT_SECTOR_SIZE + FAT_DIR_ATTR] = FAT_ATTR_DIR;
        let fs = Fat32Impl::mount(&img).unwrap();
        assert_eq!(
            fs.lookup_root(&img, &FAT_HELLO_83),
            Err(FatError::NotFile)
        );
    }

    #[test]
    fn le_helpers() {
        let mut b = [0u8; 8];
        put_le32(&mut b, 0, 0x01020304);
        assert_eq!(le32(&b, 0), 0x01020304);
        put_le16(&mut b, 4, 0xAABB);
        assert_eq!(le16(&b, 4), 0xAABB);
    }

    #[test]
    fn first_data_sector_formula() {
        let img = fixture();
        let b = parse_bpb(&img).unwrap();
        assert_eq!(
            b.first_data_sector,
            b.fat_start + (b.num_fats as u32) * b.fat_size_sectors
        );
    }

    #[test]
    fn attr_constants() {
        assert_eq!(FAT_ATTR_LFN, 0x0F);
        assert_eq!(FAT_ATTR_DIR, 0x10);
        assert_eq!(FAT_ATTR_VOLUME, 0x08);
    }

    #[test]
    fn hello_83_layout() {
        assert_eq!(&FAT_HELLO_83[0..5], b"HELLO");
        assert_eq!(&FAT_HELLO_83[8..11], b"TXT");
    }

    #[test]
    fn truncated_sector_read() {
        let img = fixture();
        let b = parse_bpb(&img).unwrap();
        // image cut before cluster 3
        let short = &img[..4 * FAT_SECTOR_SIZE];
        let fs = Fat32Impl {
            bpb: b,
        };
        let e = FatDirent {
            name_83: FAT_HELLO_83,
            attr: 0x20,
            cluster: 3,
            size: 5,
        };
        let mut out = [0u8; 8];
        assert_eq!(
            fs.read_file(short, &e, &mut out),
            Err(FatError::Truncated)
        );
    }

    #[test]
    fn zero_fats_bad() {
        let mut img = fixture();
        img[FAT_BPB_NUM_FATS] = 0;
        assert!(matches!(Fat32Impl::mount(&img), Err(FatError::BadBpb)));
    }

    #[test]
    fn root_cluster_one_bad() {
        let mut img = fixture();
        put_le32(&mut img, FAT_BPB_ROOT_CLUSTER, 1);
        assert!(matches!(Fat32Impl::mount(&img), Err(FatError::BadBpb)));
    }

    #[test]
    fn fat_size_zero_bad() {
        let mut img = fixture();
        put_le32(&mut img, FAT_BPB_FAT_SIZE_32, 0);
        assert!(matches!(Fat32Impl::mount(&img), Err(FatError::BadBpb)));
    }

    #[test]
    fn build_returns_size() {
        let mut img = [0u8; FAT_FIXTURE_BYTES];
        assert_eq!(build_banner_fixture(&mut img).unwrap(), FAT_FIXTURE_BYTES);
    }

    #[test]
    fn eoc_threshold() {
        assert!(FAT_EOC > 0x0FFF_FFF7);
    }
}
