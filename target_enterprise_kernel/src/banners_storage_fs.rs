//! Storage, block device, and filesystem boot self-proof banners.

pub(crate) use crate::*;


/// WAL: instantiate a 4 KiB WalImpl, append 16 fixture frames, flush,/// replay, assert the frame count and final LSN match the fixture
/// constants, emit `WAL replay OK frames=16 lsn=<N>\n`.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_wal_replay() {
    let mut wal: WalImpl<{ kf::WAL_CAPACITY }> = WalImpl::new();
    let mut i = 0usize;
    while i < kf::WAL_FRAMES {
        let payload = [i as u8; kf::WAL_PAYLOAD_LEN];
        if wal.append(&payload).is_err() {
            panic!("WAL append failed");
        }
        i += 1;
    }
    // TASK-161: durable flush requires CapProof (DURABLE_WAL_WRITE).
    // Banner path is privileged init — self-grant the WAL durable bit.
    if wal
        .flush(target_enterprise::wal::durable_wal_proof_init())
        .is_err()
    {
        panic!("WAL flush failed");
    }
    if wal.next_lsn() != kf::WAL_EXPECTED_NEXT_LSN {
        panic!("WAL next_lsn drift");
    }
    // Walk the durable prefix; assert frame count and order.
    let mut seen: u64 = 0;
    let mut last_lsn: u64 = 0;
    wal.replay(&mut |lsn, payload| {
        seen += 1;
        if lsn != last_lsn + 1 {
            panic!("WAL replay LSN out of order");
        }
        last_lsn = lsn;
        if payload.len() != kf::WAL_PAYLOAD_LEN {
            panic!("WAL replay payload length drift");
        }
        let expected_byte = (lsn - 1) as u8;
        let mut j = 0usize;
        while j < payload.len() {
            if payload[j] != expected_byte {
                panic!("WAL replay payload content drift");
            }
            j += 1;
        }
    });
    if seen != kf::WAL_FRAMES as u64 {
        panic!("WAL replay frame count drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"WAL replay OK frames=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(seen, &mut line[pos..]);
    let mid = b" lsn=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(last_lsn, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// TASK-018: NVMe driver round-trip. Construct an in-kernel
// `MemNvmeController` emulator, drive an `NvmeImpl` through the
// spec-mandated bring-up + IO-queue creation + Identify Controller
// + write+read round-trip, emit:
//   `NVMe init OK ctrl=PROTEUS-NVME-EMU\n`
//   `NVMe read_lba(7) OK first_byte=A5\n`
//
// The emulator runs in-kernel because the QEMU smoke test boots
// without an actual NVMe device attached (factory_builder doesn't
// pass `-device nvme,drive=...`). Running the emulator in-kernel is
// the same pattern banner_iommu_translate / banner_kpti use — the
// algorithmic core is exercised against synthetic state, proving the
// driver pipeline is functionally correct without requiring real
// hardware.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_nvme() {
    use target_enterprise::nvme::{
        MemNvmeController, NvmeImpl, IDENTIFY_BUF_SIZE, NVME_BLOCK_SIZE,
    };

    // Construct the emulator + driver. Emulator's disk is 32 KiB (64
    // blocks) — small enough to live on the kernel stack.
    let mut drv = NvmeImpl::new(MemNvmeController::new());

    // Bring up the controller, create I/O queues.
    if drv.bring_up(0x1000, 0x2000).is_err() {
        panic!("NVMe bring_up failed");
    }
    if drv.create_io_queues(0x3000, 0x4000).is_err() {
        panic!("NVMe create_io_queues failed");
    }

    // Identify Controller — emulator stamps "PROTEUS-NVME-EMU" into
    // bytes [4..24] of the response. Confirm.
    let mut ident = [0u8; IDENTIFY_BUF_SIZE];
    if drv.identify_controller(0x5000, &mut ident).is_err() {
        panic!("NVMe identify_controller failed");
    }
    if &ident[4..20] != b"PROTEUS-NVME-EMU" {
        panic!("NVMe identify_controller SN mismatch");
    }

    // Emit init banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVMe init OK ctrl=PROTEUS-NVME-EMU";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Identify Namespace — populates disk_blocks (=64).
    let nsze = match drv.identify_namespace(0x5000) {
        Ok(n) => n,
        Err(_) => panic!("NVMe identify_namespace failed"),
    };
    if nsze != 64 {
        panic!("NVMe namespace block count drift");
    }

    // Write a fixture pattern to LBA 7, read it back, confirm.
    let mut write_buf = [0u8; NVME_BLOCK_SIZE];
    write_buf[0] = 0xA5; // First byte we'll surface in the banner.
    for i in 1..NVME_BLOCK_SIZE {
        write_buf[i] = ((i * 13) & 0xFF) as u8;
    }
    if drv.try_write_block(7, &write_buf, 0x6000).is_err() {
        panic!("NVMe try_write_block failed");
    }
    let mut read_buf = [0u8; NVME_BLOCK_SIZE];
    if drv.try_read_block(7, &mut read_buf, 0x6000).is_err() {
        panic!("NVMe try_read_block failed");
    }
    // Byte-equality check — load-bearing: if any byte differs, the
    // banner is suppressed and the QEMU smoke test fails.
    let mut i = 0usize;
    while i < NVME_BLOCK_SIZE {
        if read_buf[i] != write_buf[i] {
            panic!("NVMe read_back byte mismatch");
        }
        i += 1;
    }

    // Emit read_lba banner with the first byte (0xA5).
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVMe read_lba(7) OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&read_buf[..1], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}
// ============================================================
// TASK-061: VirtIO-blk driver bring-up + sector round-trip.
//
// Constructs a MemVirtioBlkBus + VirtioBlk in static storage,
// drives the VirtIO 1.0 RESET → ACK → DRIVER → FEATURES_OK →
// DRIVER_OK handshake against a virtio-blk device, reads the
// disk capacity from device-cfg (32 sectors — the bus default),
// writes a locked 512-byte pattern to sector 3, then reads it
// back and asserts byte-equality.
//
// Emits (in order):
//   `VIRTIO_BLK init OK capacity=32 blk_size=512\n`
//   `VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5\n`
//
// A kernel that perturbs the descriptor wire layout, the bring-up
// status sequence, the feature-bit constants, the request-header
// byte order, or the 3-descriptor chain shape panics here and
// these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_blk() {
    use proteus_contracts::{BlockDeviceVirtio, VIRTIO_BLK_SECTOR_SIZE};
    use target_enterprise::virtio_blk::{MemVirtioBlkBus, VirtioBlk};

    // Same static-storage pattern as banner_virtio_net — the bus
    // carries a 64 KiB shadow + a 16 KiB backing disk + a handful
    // of observation buffers. Too large for the kernel-main stack
    // (the bootloader allocates a modest stack and the banner
    // sequence is already deep into it).
    static BUS_STORAGE: spin::Mutex<MemVirtioBlkBus> = spin::Mutex::new(MemVirtioBlkBus::new());
    let mut bus_guard = BUS_STORAGE.lock();
    let bus: &mut MemVirtioBlkBus = &mut *bus_guard;
    let mut drv = VirtioBlk::new();

    if drv.init(bus).is_err() {
        panic!("virtio-blk init failed");
    }
    if drv.capacity_sectors() != MemVirtioBlkBus::DISK_SECTORS {
        panic!("virtio-blk capacity drift");
    }
    if drv.preferred_block_size() != VIRTIO_BLK_SECTOR_SIZE as u32 {
        panic!("virtio-blk preferred_block_size drift");
    }
    if drv.read_only() {
        panic!("virtio-blk unexpected read-only flag");
    }

    // Emit init banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_BLK init OK capacity=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.capacity_sectors(), &mut line[pos..]);
        let mid = b" blk_size=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(drv.preferred_block_size() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Build a locked 512-byte pattern. byte[i] = 0xA5 XOR i. The
    // first byte is therefore 0xA5 — the banner asserts that
    // specific value to make any byte-order drift obvious.
    let mut pattern = [0u8; VIRTIO_BLK_SECTOR_SIZE];
    let mut i = 0usize;
    while i < VIRTIO_BLK_SECTOR_SIZE {
        pattern[i] = 0xA5 ^ (i as u8);
        i += 1;
    }

    if drv.write_block(bus, 3, &pattern).is_err() {
        panic!("virtio-blk write_block failed");
    }

    let mut readback = [0u8; VIRTIO_BLK_SECTOR_SIZE];
    if drv.read_block(bus, 3, &mut readback).is_err() {
        panic!("virtio-blk read_block failed");
    }

    // Byte-equality check.
    let mut j = 0usize;
    while j < VIRTIO_BLK_SECTOR_SIZE {
        if readback[j] != pattern[j] {
            panic!("virtio-blk readback byte drift");
        }
        j += 1;
    }

    if drv.request_count() != 2 {
        panic!("virtio-blk request_count drift");
    }
    if drv.completion_count() != 2 {
        panic!("virtio-blk completion_count drift");
    }

    // Emit roundtrip banner with the first byte in hex so the log
    // line carries a non-trivial value derived from the actual
    // disk read (not just a counter).
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_BLK roundtrip OK reqs=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.request_count() as u64, &mut line[pos..]);
        let mid = b" sector=3 first_byte=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 2];
        hex_encode(&[readback[0]], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// VFS banner — TASK-054.
///
/// Exercises the locked [`Vfs`] + [`Filesystem`] surfaces: instantiates a
/// `MemRamFs` in a static-mut arena, seeds `/etc/hostname` with the
/// locked byte fixture `b"proteus-te\n"`, mounts it at `/`, opens the
/// path through `VfsImpl`, reads the bytes back, and asserts the
/// recovered contents byte-for-byte against the locked expectation.
/// A morph that perturbs the mount-table dispatch, the path
/// normalisation, the handle packing, or the open-file table panics
/// inside `banner_vfs` and the two banners never appear.
///
/// Emits two banners:
/// - `VFS mount OK fs=ramfs root=/`
/// - `VFS read OK path=/etc/hostname bytes=11`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_vfs() {
    // Locked fixture matching the kernel-banner expectation.
    const HOSTNAME_BYTES: &[u8] = b"proteus-te\n";
    const HOSTNAME_LEN: usize = 11;

    // Storage backing the ramfs lives in a static-mut arena. The
    // VFS holds a `'static mut` borrow for the lifetime of the
    // banner, so a heap allocator is not required.
    static RAMFS: spin::Mutex<VfsRamFsArena> = spin::Mutex::new(VfsRamFsArena::new());
    let fs_ref: &'static mut MemRamFs<8, 4096> = &mut spin::MutexGuard::leak(RAMFS.lock()).fs;

    // Seed `/etc/hostname` with the fixture.
    match fs_ref.seed_file(b"/etc/hostname", HOSTNAME_BYTES, HOSTNAME_LEN, 0) {
        Ok(_) => {}
        Err(_) => panic!("vfs: seed_file returned Err"),
    }

    // Build a fresh dispatcher and mount the ramfs at root.
    let mut vfs: VfsImpl<8> = VfsImpl::new();
    match vfs.mount(b"/", fs_ref as &mut dyn Filesystem) {
        Ok(()) => {}
        Err(_) => panic!("vfs: mount returned Err"),
    }
    if vfs.mount_count() != 1 {
        panic!("vfs: mount_count drift");
    }
    match vfs.mount_at(0) {
        Some(mp) if mp == b"/" => {}
        _ => panic!("vfs: mount_at(0) wire drift"),
    }

    // First banner.
    {
        let prefix = b"VFS mount OK fs=ramfs root=/\n";
        serial_write_bytes(prefix);
    }

    // Open + read + close round-trip.
    let h = match <VfsImpl<8> as Vfs>::open(&mut vfs, b"/etc/hostname", FS_O_RDONLY) {
        Ok(h) => h,
        Err(_) => panic!("vfs: open returned Err"),
    };
    let mut buf = [0u8; 32];
    let n = match <VfsImpl<8> as Vfs>::read(&mut vfs, h, 0, &mut buf) {
        Ok(n) => n,
        Err(_) => panic!("vfs: read returned Err"),
    };
    if n != HOSTNAME_LEN {
        panic!("vfs: read length drift");
    }
    // Byte-for-byte assertion against the locked fixture.
    let mut k = 0usize;
    while k < HOSTNAME_LEN {
        if buf[k] != HOSTNAME_BYTES[k] {
            panic!("vfs: read byte drift");
        }
        k += 1;
    }
    match <VfsImpl<8> as Vfs>::close(&mut vfs, h) {
        Ok(()) => {}
        Err(_) => panic!("vfs: close returned Err"),
    }

    // Second banner — bytes=11 is the locked length.
    {
        let mut line = [0u8; 64];
        let prefix = b"VFS read OK path=/etc/hostname bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Static-mut arena holding the kernel-banner ramfs. Sized at compile
/// time so the BSS slot is fixed; the morph engine can diversify the
/// pool / inode internal layout without changing the binary's symbol
/// table.
pub(crate) struct VfsRamFsArena {
    pub(crate) fs: MemRamFs<8, 4096>,
}

impl VfsRamFsArena {
    pub(crate) const fn new() -> Self {
        VfsRamFsArena {
            fs: MemRamFs::new(),
        }
    }
}

// TASK-085 GPT
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_gpt() {
    use proteus_contracts::Gpt;
    use target_enterprise::gpt::{build_banner_fixture, GPT_FIXTURE_BYTES, GptImpl};

    let mut img = [0u8; GPT_FIXTURE_BYTES];
    build_banner_fixture(&mut img).unwrap();
    let h = GptImpl::parse_header(&img).unwrap();
    if h.num_parts != 1 {
        panic!("GPT banner: parts");
    }
    serial_write_bytes(b"GPT parse OK parts=1\n");
}

// TASK-088 AHCI Register H2D FIS
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_fis() {
    use proteus_contracts::{AhciFis, ATA_CMD_IDENTIFY, AHCI_FIS_H2D_LEN};
    use target_enterprise::ahci_fis::AhciFisImpl;

    let p = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI banner: identify params"),
    };
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    if AhciFisImpl::encode_h2d(&p, &mut fis).is_err() {
        panic!("AHCI banner: encode");
    }
    let d = match AhciFisImpl::decode_h2d(&fis) {
        Ok(d) => d,
        Err(_) => panic!("AHCI banner: decode"),
    };
    if d.command != ATA_CMD_IDENTIFY || fis[2] != ATA_CMD_IDENTIFY {
        panic!("AHCI banner: cmd drift");
    }
    serial_write_bytes(b"AHCI fis OK cmd=identify\n");
}

// TASK-093 AHCI command header + PRDT
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_cmd() {
    use proteus_contracts::AhciCmd;
    use target_enterprise::ahci_cmd::AhciCmdImpl;

    let (h, p) = match AhciCmdImpl::identify_slot(0x1000, 0x2000) {
        Ok(v) => v,
        Err(_) => panic!("AHCI cmd banner: slot"),
    };
    if h.prdtl != 1 || p.byte_count != 512 {
        panic!("AHCI cmd banner: fields");
    }
    let mut hb = [0u8; 32];
    let mut pb = [0u8; 16];
    if AhciCmdImpl::encode_header(&h, &mut hb).is_err()
        || AhciCmdImpl::encode_prdt(&p, &mut pb).is_err()
    {
        panic!("AHCI cmd banner: encode");
    }
    serial_write_bytes(b"AHCI cmd OK prdtl=1\n");
}


// TASK-070: FAT32 mount + HELLO.TXT read.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_fat32() {
    use proteus_contracts::Fat32;
    use target_enterprise::fat32::{
        build_banner_fixture, FAT_FIXTURE_BYTES, FAT_HELLO_83, FAT_HELLO_BODY, FAT_HELLO_LEN,
        Fat32Impl,
    };

    let mut img = [0u8; FAT_FIXTURE_BYTES];
    if build_banner_fixture(&mut img).is_err() {
        panic!("FAT banner: fixture failed");
    }
    let fs = match Fat32Impl::mount(&img) {
        Ok(f) => f,
        Err(_) => panic!("FAT banner: mount failed"),
    };
    if fs.bpb().num_fats != 2 || fs.bpb().root_cluster != 2 {
        panic!("FAT banner: bpb drift");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"FAT mount OK fats=2 root_clus=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(fs.bpb().root_cluster as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let ent = match fs.lookup_root(&img, &FAT_HELLO_83) {
        Ok(e) => e,
        Err(_) => panic!("FAT banner: lookup failed"),
    };
    let mut body = [0u8; 32];
    let n = match fs.read_file(&img, &ent, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("FAT banner: read failed"),
    };
    if n != FAT_HELLO_LEN {
        panic!("FAT banner: len drift");
    }
    let mut j = 0usize;
    while j < n {
        if body[j] != FAT_HELLO_BODY[j] {
            panic!("FAT banner: body drift");
        }
        j += 1;
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"FAT read OK name=HELLO.TXT bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-066: Disk quota wire codec. Builds a 3-uid fixture, scans
// it, looks up uid 1001 (at block limit), and asserts a +1 block
// write is rejected with BlockLimit.
// Banners: `QUOTA scan OK records=3` +
// `QUOTA reject OK uid=1001 reason=block_limit`.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_quota() {
    use proteus_contracts::{Quota, QuotaReject};
    use target_enterprise::quota::{build_banner_fixture, BANNER_NOW_UNIX, QuotaImpl};

    let mut buf = [0u8; 96];
    match build_banner_fixture(&mut buf) {
        Ok(n) if n == 96 => {}
        _ => panic!("QUOTA banner: fixture build failed"),
    }
    let mut count = 0usize;
    match QuotaImpl::scan(&buf, &mut |_| count += 1) {
        Ok(n) if n == 3 && count == 3 => {}
        _ => panic!("QUOTA banner: scan drift"),
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"QUOTA scan OK records=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(count as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let rec = match QuotaImpl::lookup(&buf, 1001) {
        Ok(r) => r,
        Err(_) => panic!("QUOTA banner: lookup 1001 failed"),
    };
    match QuotaImpl::check_write(&rec, 1, 0, BANNER_NOW_UNIX) {
        Err(QuotaReject::BlockLimit) => {}
        _ => panic!("QUOTA banner: expected BlockLimit reject"),
    }

    {
        let msg = b"QUOTA reject OK uid=1001 reason=block_limit\n";
        serial_write_bytes(msg);
    }
}

// TASK-064: JFS image walker. Builds the locked 4-sector fixture
// (root dir + hello.txt), mounts it, looks up `/hello.txt`, reads
// the body, and asserts byte-equality + Fletcher-32 fingerprint.
// Banners: `JFS mount OK root_ino=1 inodes=3` and
// `JFS read OK path=/hello.txt bytes=16 sha=aa3ce1c0`.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_jfs() {
    use proteus_contracts::{JournalFs, JFS_ROOT_INODE};
    use target_enterprise::jfs::{
        build_banner_fixture, fletcher32_body, FIXTURE_BYTES, HELLO_BODY, HELLO_BODY_FLETCHER32,
        HELLO_BODY_LEN, JfsImpl,
    };

    let mut img = [0u8; FIXTURE_BYTES];
    match build_banner_fixture(&mut img) {
        Ok(n) if n == FIXTURE_BYTES => {}
        _ => panic!("JFS banner: fixture build failed"),
    }
    let fs = match JfsImpl::mount(&img) {
        Ok(f) => f,
        Err(_) => panic!("JFS banner: mount failed"),
    };
    let sb = fs.superblock();
    if sb.root_inode != JFS_ROOT_INODE {
        panic!("JFS banner: root_inode drift");
    }
    if sb.inode_count != 3 {
        panic!("JFS banner: inode_count drift");
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"JFS mount OK root_ino=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(sb.root_inode as u64, &mut line[pos..]);
        let mid = b" inodes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(sb.inode_count as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let ino = match fs.lookup(&img, sb.root_inode, b"hello.txt") {
        Ok(i) => i,
        Err(_) => panic!("JFS banner: lookup hello.txt failed"),
    };
    let mut body = [0u8; 64];
    let n = match fs.read_file(&img, ino, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("JFS banner: read_file failed"),
    };
    if n != HELLO_BODY_LEN {
        panic!("JFS banner: body length drift");
    }
    let mut i = 0usize;
    while i < n {
        if body[i] != HELLO_BODY[i] {
            panic!("JFS banner: body byte drift");
        }
        i += 1;
    }
    let fp = fletcher32_body(&body[..n]);
    if fp != HELLO_BODY_FLETCHER32 {
        panic!("JFS banner: fletcher drift");
    }

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"JFS read OK path=/hello.txt bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        let mid = b" sha=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // 8 lowercase hex digits of the fletcher fingerprint.
        let mut shift = 28i32;
        while shift >= 0 {
            let nibble = ((fp >> shift) & 0xF) as u8;
            line[pos] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            pos += 1;
            shift -= 4;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}
