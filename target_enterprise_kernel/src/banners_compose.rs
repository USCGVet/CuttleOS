//! Cross-subsystem composition proofs and OsShell AHCI persistence.

pub(crate) use crate::*;

/// BLOCK path compose: same 512-byte pattern written and read on both
/// NVMe (MemNvmeController) and virtio-blk (MemVirtioBlkBus). Proves
/// the two block backends still agree on sector size and data path
/// after independent morph of `nvme` + `virtio_blk`.
///
/// Banner: `BLOCK path compose OK sector=512 nvme=a5 virtio=a5`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_block_path_compose() {
    use proteus_contracts::{BlockDeviceVirtio, VIRTIO_BLK_SECTOR_SIZE};
    use target_enterprise::nvme::{
        MemNvmeController, NvmeImpl, NVME_BLOCK_SIZE,
    };
    use target_enterprise::virtio_blk::{MemVirtioBlkBus, VirtioBlk};

    if NVME_BLOCK_SIZE != VIRTIO_BLK_SECTOR_SIZE {
        panic!("BLOCK path compose: sector size mismatch constants");
    }
    const SECTOR: usize = 512;
    if NVME_BLOCK_SIZE != SECTOR {
        panic!("BLOCK path compose: expected 512 B sectors");
    }

    // Locked pattern: byte[i] = 0xA5 ^ (i as u8) — same family as
    // virtio-blk isolated banner; first byte is 0xA5.
    let mut pattern = [0u8; SECTOR];
    let mut i = 0usize;
    while i < SECTOR {
        pattern[i] = 0xA5 ^ (i as u8);
        i += 1;
    }

    // ---- NVMe path ----
    let mut nvme = NvmeImpl::new(MemNvmeController::new());
    if nvme.bring_up(0x1000, 0x2000).is_err() {
        panic!("BLOCK path compose: NVMe bring_up");
    }
    if nvme.create_io_queues(0x3000, 0x4000).is_err() {
        panic!("BLOCK path compose: NVMe queues");
    }
    // identify so namespace capacity is live
    if nvme.identify_namespace(0x5000).is_err() {
        panic!("BLOCK path compose: NVMe identify_ns");
    }
    if nvme.try_write_block(5, &pattern, 0x6000).is_err() {
        panic!("BLOCK path compose: NVMe write");
    }
    let mut nvme_rb = [0u8; SECTOR];
    if nvme.try_read_block(5, &mut nvme_rb, 0x6000).is_err() {
        panic!("BLOCK path compose: NVMe read");
    }
    i = 0;
    while i < SECTOR {
        if nvme_rb[i] != pattern[i] {
            panic!("BLOCK path compose: NVMe byte drift");
        }
        i += 1;
    }

    // ---- virtio-blk path ----
    static BLK_BUS: spin::Mutex<MemVirtioBlkBus> = spin::Mutex::new(MemVirtioBlkBus::new());
    let mut bus_guard = BLK_BUS.lock();
    let bus: &mut MemVirtioBlkBus = &mut *bus_guard;
    let mut vblk = VirtioBlk::new();
    if vblk.init(bus).is_err() {
        panic!("BLOCK path compose: virtio init");
    }
    if vblk.preferred_block_size() as usize != SECTOR {
        panic!("BLOCK path compose: virtio blk_size");
    }
    if vblk.write_block(bus, 5, &pattern).is_err() {
        panic!("BLOCK path compose: virtio write");
    }
    let mut v_rb = [0u8; SECTOR];
    if vblk.read_block(bus, 5, &mut v_rb).is_err() {
        panic!("BLOCK path compose: virtio read");
    }
    i = 0;
    while i < SECTOR {
        if v_rb[i] != pattern[i] {
            panic!("BLOCK path compose: virtio byte drift");
        }
        i += 1;
    }

    // Cross-backend: both recovered first byte must match pattern.
    if nvme_rb[0] != 0xA5 || v_rb[0] != 0xA5 || nvme_rb[0] != v_rb[0] {
        panic!("BLOCK path compose: first_byte cross mismatch");
    }

    serial_write_bytes(b"BLOCK path compose OK sector=512 nvme=a5 virtio=a5\n");
}

/// NET path compose: TCP 3-way handshake → ESTABLISHED, then HTTP GET
/// as a real TCP data payload, then HTTP 200 response built and
/// re-framed as a TCP segment. Proves tcp + http glue (not two
/// isolated demos): morph damage to either side drops this banner.
///
/// Banner: `NET path compose OK method=GET status=200`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_net_path_compose() {
    use proteus_contracts::{tcp_flags, Http, HttpMethod, Tcp};
    use target_enterprise::http::HttpImpl;
    use target_enterprise::tcp::{process_segment, Tcb, TcpImpl, TcpState};

    let server_ip: [u8; 4] = [10, 0, 0, 2];
    let client_ip: [u8; 4] = [10, 0, 0, 1];
    let server_port: u16 = 80;
    let client_port: u16 = 40000;
    let client_isn: u32 = 0x2000_0000;

    // ---- handshake (same shape as banner_tcp, tighter asserts) ----
    let mut tcb = Tcb::listen(server_ip, server_port, 65535);
    let mut buf = [0u8; 256];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn,
        0,
        tcp_flags::SYN,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: SYN build"),
    };
    let syn = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: SYN parse"),
    };
    let (next, syn_ack) = match process_segment(tcb, &syn, 0xBEEF) {
        Ok(t) => t,
        Err(_) => panic!("NET path compose: process SYN"),
    };
    tcb = next;
    if tcb.state != TcpState::SynReceived || !syn_ack.present {
        panic!("NET path compose: SynReceived/hint");
    }
    let server_isn = syn_ack.seq;

    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: ACK build"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: ACK parse"),
    };
    let (next, _) = match process_segment(tcb, &ack, 0xBEEF) {
        Ok(t) => t,
        Err(_) => panic!("NET path compose: process ACK"),
    };
    tcb = next;
    if tcb.state != TcpState::Established {
        panic!("NET path compose: not Established");
    }

    // ---- HTTP request as TCP data on the established stream ----
    let http_req: &[u8] =
        b"GET /healthz HTTP/1.1\r\nHost: proteus.local\r\n\r\n";
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::PSH | tcp_flags::ACK,
        65535,
        http_req,
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: HTTP data segment build"),
    };
    let data_seg = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: HTTP data segment parse"),
    };
    if data_seg.payload != http_req {
        panic!("NET path compose: payload drift after TCP round-trip");
    }
    let rcv_before = tcb.rcv_nxt;
    let (next, data_ack) = match process_segment(tcb, &data_seg, 0xBEEF) {
        Ok(t) => t,
        Err(_) => panic!("NET path compose: process HTTP data"),
    };
    tcb = next;
    if tcb.state != TcpState::Established {
        panic!("NET path compose: left Established on data");
    }
    if tcb.rcv_nxt != rcv_before.wrapping_add(http_req.len() as u32) {
        panic!("NET path compose: rcv_nxt not advanced by HTTP len");
    }
    if !data_ack.present {
        panic!("NET path compose: missing ACK for HTTP data");
    }

    // Application layer: parse the *TCP payload*, not a side fixture.
    let view = match HttpImpl::parse_request(data_seg.payload) {
        Ok(v) => v,
        Err(_) => panic!("NET path compose: HTTP parse of TCP payload"),
    };
    if view.method != HttpMethod::Get || view.path != b"/healthz" {
        panic!("NET path compose: method/path drift");
    }

    let mut http_out = [0u8; 96];
    let http_n = match HttpImpl::build_response(200, b"text/plain", b"OK", &mut http_out) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: HTTP build_response"),
    };
    let expected_prefix = b"HTTP/1.1 200 OK\r\n";
    if http_n < expected_prefix.len()
        || &http_out[..expected_prefix.len()] != expected_prefix
    {
        panic!("NET path compose: response status line drift");
    }

    // Server frames the HTTP response as a TCP segment back to client.
    let n = match TcpImpl::build_segment(
        server_port,
        client_port,
        tcb.snd_nxt,
        tcb.rcv_nxt,
        tcp_flags::PSH | tcp_flags::ACK,
        tcb.rcv_wnd,
        &http_out[..http_n],
        server_ip,
        client_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: response segment build"),
    };
    let resp_seg = match TcpImpl::parse_segment(&buf[..n], server_ip, client_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: response segment parse"),
    };
    if resp_seg.payload != &http_out[..http_n] {
        panic!("NET path compose: response payload drift");
    }

    serial_write_bytes(b"NET path compose OK method=GET status=200\n");
}

/// AHCI storage compose: Register H2D IDENTIFY FIS + command header +
/// single PRDT for a 512-byte IDENTIFY buffer. Proves the three
/// storage-command surfaces agree on one slot layout (CFL=5, PRDTL=1,
/// FIS cmd=0xEC, PRDT IOC 512 B) so diversifying one module cannot
/// silently desync the others.
///
/// Banner: `AHCI storage compose OK fis=ec prdtl=1 bytes=512`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_storage_compose() {
    use proteus_contracts::{
        AhciCmd, AhciFis, AHCI_CFL_H2D, AHCI_FIS_H2D_LEN, ATA_CMD_IDENTIFY,
    };
    use target_enterprise::ahci_cmd::AhciCmdImpl;
    use target_enterprise::ahci_fis::AhciFisImpl;

    // Command table base + IDENTIFY data buffer (fixture addresses).
    const CTBA: u64 = 0x0000_0000_0010_0000;
    const DATA: u64 = 0x0000_0000_0020_0000;

    let fis_params = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI storage compose: identify params"),
    };
    if fis_params.command != ATA_CMD_IDENTIFY || !fis_params.is_command {
        panic!("AHCI storage compose: FIS command drift");
    }
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    if AhciFisImpl::encode_h2d(&fis_params, &mut fis).is_err() {
        panic!("AHCI storage compose: FIS encode");
    }
    let fis_back = match AhciFisImpl::decode_h2d(&fis) {
        Ok(p) => p,
        Err(_) => panic!("AHCI storage compose: FIS decode"),
    };
    if fis_back.command != ATA_CMD_IDENTIFY || fis[2] != ATA_CMD_IDENTIFY {
        panic!("AHCI storage compose: FIS round-trip drift");
    }

    let (hdr, prd) = match AhciCmdImpl::identify_slot(CTBA, DATA) {
        Ok(v) => v,
        Err(_) => panic!("AHCI storage compose: slot"),
    };
    if hdr.cfl != AHCI_CFL_H2D || hdr.prdtl != 1 || hdr.write {
        panic!("AHCI storage compose: header fields");
    }
    if hdr.ctba != CTBA || prd.dba != DATA || prd.byte_count != 512 || !prd.ioc {
        panic!("AHCI storage compose: address/PRDT drift");
    }

    let mut hb = [0u8; 32];
    let mut pb = [0u8; 16];
    if AhciCmdImpl::encode_header(&hdr, &mut hb).is_err()
        || AhciCmdImpl::encode_prdt(&prd, &mut pb).is_err()
    {
        panic!("AHCI storage compose: header/PRDT encode");
    }
    let hdr2 = match AhciCmdImpl::decode_header(&hb) {
        Ok(h) => h,
        Err(_) => panic!("AHCI storage compose: header decode"),
    };
    let prd2 = match AhciCmdImpl::decode_prdt(&pb) {
        Ok(p) => p,
        Err(_) => panic!("AHCI storage compose: PRDT decode"),
    };
    if hdr2.prdtl != 1 || hdr2.cfl != AHCI_CFL_H2D || prd2.byte_count != 512 {
        panic!("AHCI storage compose: cmd round-trip drift");
    }
    // Cross-surface lock: H2D FIS length in dwords must match CFL.
    if (AHCI_FIS_H2D_LEN / 4) as u8 != hdr2.cfl {
        panic!("AHCI storage compose: CFL vs FIS len mismatch");
    }

    serial_write_bytes(b"AHCI storage compose OK fis=ec prdtl=1 bytes=512\n");
}

// ============================================================
// Anti-sprawl live composition banners
// ============================================================
//
// Isolated per-module banners prove each codec alone. These prove
// the *integration* risk: PIT program → tick mux → watchdog pet/fire,
// and quota check-on-write gating a real VFS create/write. A morph
// that diversifies one side of the pair but breaks the glue panics
// here and suppresses PROTEUS-TE HALT.

/// TIMEBASE compose: PIT 1 kHz program + TickSource (PIT then HPET)
/// drives Watchdog arm → tick → pet → fire.
///
/// Banner: `TIMEBASE compose OK pit_div=1193 pet_rem=5 fire=timeout`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_timebase_compose() {
    use proteus_contracts::{
        PicTimer, TickKind, TickSource, Watchdog, WatchdogError, PIT_CH0_PORT,
        PIT_CMD_CH0_LOHI_MODE3_BIN, PIT_CMD_PORT,
    };
    use target_enterprise::tick_source::TickSourceImpl;
    use target_enterprise::timer::{PicTimerImpl, RecordingIoPort};
    use target_enterprise::watchdog::WatchdogImpl;

    // ---- PIT program (same locked 1 kHz path as banner_timer) ----
    let mut port = RecordingIoPort::new();
    let div = match PicTimerImpl::program_hz(&mut port, 1000) {
        Ok(d) => d,
        Err(_) => panic!("TIMEBASE compose: program_hz failed"),
    };
    if div != 1193 {
        panic!("TIMEBASE compose: divisor drift");
    }
    if port.write_count() != 3 {
        panic!("TIMEBASE compose: PIT write count drift");
    }
    let w0 = port.write_at(0).expect("TIMEBASE compose: missing PIT cmd");
    if w0.port != PIT_CMD_PORT || w0.value != PIT_CMD_CH0_LOHI_MODE3_BIN {
        panic!("TIMEBASE compose: PIT cmd byte drift");
    }
    let w1 = port.write_at(1).expect("TIMEBASE compose: missing lo");
    let w2 = port.write_at(2).expect("TIMEBASE compose: missing hi");
    if w1.port != PIT_CH0_PORT || w1.value != 0xA9 || w2.port != PIT_CH0_PORT || w2.value != 0x04 {
        panic!("TIMEBASE compose: PIT divisor bytes drift");
    }

    // ---- Tick mux: arm watchdog from PIT ticks, pet, then fire ----
    let mut ticks = TickSourceImpl::new();
    ticks.select(TickKind::Pit);
    let mut wd = WatchdogImpl::new();
    // deadline = 5 ticks (locked composition constant)
    if wd.arm(5).is_err() {
        panic!("TIMEBASE compose: arm failed");
    }
    // Advance 2 PIT ticks → 2 watchdog ticks
    ticks.advance(2);
    if ticks.now_ticks() != 2 {
        panic!("TIMEBASE compose: PIT ticks drift");
    }
    if wd.tick().is_err() || wd.tick().is_err() {
        panic!("TIMEBASE compose: early tick failed");
    }
    if wd.remaining() != 3 {
        panic!("TIMEBASE compose: remaining after 2 ticks drift");
    }
    // Pet resets remaining to deadline
    if wd.pet().is_err() {
        panic!("TIMEBASE compose: pet failed");
    }
    if wd.remaining() != 5 {
        panic!("TIMEBASE compose: pet remaining drift");
    }
    let pet_rem = wd.remaining();

    // Switch to HPET counter (independent) and fire watchdog via ticks
    ticks.select(TickKind::Hpet);
    ticks.advance(1);
    if ticks.kind() != TickKind::Hpet || ticks.now_ticks() != 1 {
        panic!("TIMEBASE compose: HPET switch drift");
    }
    // Fire: 5 ticks exhaust remaining
    let mut i = 0u32;
    while i < 4 {
        if wd.tick().is_err() {
            panic!("TIMEBASE compose: fire path early error");
        }
        i += 1;
    }
    match wd.tick() {
        Err(WatchdogError::Fired) => {}
        _ => panic!("TIMEBASE compose: expected Fired"),
    }

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"TIMEBASE compose OK pit_div=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(div as u64, &mut line[pos..]);
        let mid = b" pet_rem=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(pet_rem as u64, &mut line[pos..]);
        let tail = b" fire=timeout\n";
        line[pos..pos + tail.len()].copy_from_slice(tail);
        pos += tail.len();
        serial_write_bytes(&line[..pos]);
    }
}

/// VFS + QUOTA compose: check_write gates a real VFS create/write.
///
/// uid 1000 (healthy) is allowed → write 8 bytes to `/var/ok`.
/// uid 1001 (at block limit) is rejected → no write attempted.
///
/// Banner: `VFS+QUOTA compose OK allow=1000 reject=1001 bytes=8`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_vfs_quota_compose() {
    use proteus_contracts::{
        Filesystem, Quota, QuotaReject, Vfs, FS_O_CREATE, FS_O_RDWR, FS_O_RDONLY,
    };
    use target_enterprise::quota::{build_banner_fixture, BANNER_NOW_UNIX, QuotaImpl};
    use target_enterprise::vfs::{MemRamFs, VfsImpl};

    // ---- Quota fixture (same locked 3-uid table) ----
    let mut qbuf = [0u8; 96];
    match build_banner_fixture(&mut qbuf) {
        Ok(n) if n == 96 => {}
        _ => panic!("VFS+QUOTA compose: fixture failed"),
    }

    // Allow path: uid 1000 can take +1 block +1 inode
    let rec_ok = match QuotaImpl::lookup(&qbuf, 1000) {
        Ok(r) => r,
        Err(_) => panic!("VFS+QUOTA compose: lookup 1000 failed"),
    };
    if QuotaImpl::check_write(&rec_ok, 1, 1, BANNER_NOW_UNIX).is_err() {
        panic!("VFS+QUOTA compose: uid 1000 should allow");
    }

    // Reject path: uid 1001 at hard block limit
    let rec_bad = match QuotaImpl::lookup(&qbuf, 1001) {
        Ok(r) => r,
        Err(_) => panic!("VFS+QUOTA compose: lookup 1001 failed"),
    };
    match QuotaImpl::check_write(&rec_bad, 1, 0, BANNER_NOW_UNIX) {
        Err(QuotaReject::BlockLimit) => {}
        _ => panic!("VFS+QUOTA compose: uid 1001 should BlockLimit"),
    }

    // ---- Only the allowed write hits VFS ----
    static COMPOSE_RAMFS: spin::Mutex<ComposeVfsArena> = spin::Mutex::new(ComposeVfsArena::new());
    let fs_ref: &'static mut MemRamFs<8, 4096> =
        &mut spin::MutexGuard::leak(COMPOSE_RAMFS.lock()).fs;

    let mut vfs: VfsImpl<8> = VfsImpl::new();
    if vfs.mount(b"/", fs_ref as &mut dyn Filesystem).is_err() {
        panic!("VFS+QUOTA compose: mount failed");
    }

    // After the allow gate, create + write. Ramfs CREATE reserves a
    // 256-byte pool slot — enough for the locked 8-byte payload.
    let h = match <VfsImpl<8> as Vfs>::open(
        &mut vfs,
        b"/var/ok",
        FS_O_RDWR | FS_O_CREATE,
    ) {
        Ok(h) => h,
        Err(_) => panic!("VFS+QUOTA compose: open failed"),
    };
    const PAYLOAD: &[u8] = b"proteus\n";
    let n = match <VfsImpl<8> as Vfs>::write(&mut vfs, h, 0, PAYLOAD) {
        Ok(n) => n,
        Err(_) => panic!("VFS+QUOTA compose: write failed"),
    };
    if n != PAYLOAD.len() {
        panic!("VFS+QUOTA compose: write length drift");
    }
    if <VfsImpl<8> as Vfs>::close(&mut vfs, h).is_err() {
        panic!("VFS+QUOTA compose: close failed");
    }

    // Read-back proves the write stuck (quota gate + VFS path linked)
    let h2 = match <VfsImpl<8> as Vfs>::open(&mut vfs, b"/var/ok", FS_O_RDONLY) {
        Ok(h) => h,
        Err(_) => panic!("VFS+QUOTA compose: reopen failed"),
    };
    let mut rbuf = [0u8; 16];
    let rn = match <VfsImpl<8> as Vfs>::read(&mut vfs, h2, 0, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("VFS+QUOTA compose: read failed"),
    };
    if rn != PAYLOAD.len() {
        panic!("VFS+QUOTA compose: read length drift");
    }
    let mut k = 0usize;
    while k < PAYLOAD.len() {
        if rbuf[k] != PAYLOAD[k] {
            panic!("VFS+QUOTA compose: read byte drift");
        }
        k += 1;
    }
    let _ = <VfsImpl<8> as Vfs>::close(&mut vfs, h2);

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"VFS+QUOTA compose OK allow=1000 reject=1001 bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Separate BSS arena so compose banner does not share state with
/// `banner_vfs`'s `RAMFS`.
pub(crate) struct ComposeVfsArena {
    pub(crate) fs: MemRamFs<8, 4096>,
}

impl ComposeVfsArena {
    pub(crate) const fn new() -> Self {
        ComposeVfsArena {
            fs: MemRamFs::new(),
        }
    }
}


pub(crate) static KERNEL_SHELL: spin::Mutex<target_enterprise::OsShell> =
    spin::Mutex::new(target_enterprise::OsShell::empty());

/// First LBA of the 2-sector (`PRTSSHL1` header + 512-byte WAL) sealed
/// `OsShell` persistence region on the AHCI disk (`LBA 1040..=1041`).
pub(crate) const SHELL_DISK_LBA: u64 = 1040;
/// First LBA of the 16-sector (`8 KiB`, `PRTSFS01` superblock + inode table +
/// data pool) block-backed filesystem partition on the AHCI disk (`LBA 1042..=1057`).
pub(crate) const SHELL_FS_DISK_LBA: u64 = 1042;

static FS_PART_SECTORS: spin::Mutex<[[u8; 512]; target_enterprise::shell::SHELL_FS_PART_SECTORS]> =
    spin::Mutex::new([[0u8; 512]; target_enterprise::shell::SHELL_FS_PART_SECTORS]);

pub(crate) fn persist_shell_to_ahci(sh: &mut target_enterprise::OsShell, boots: u64) -> Option<usize> {
    let mut hdr_sec = [0u8; 512];
    let mut wal_sec = [0u8; 512];
    let count = sh.pack_disk_image(boots, &mut hdr_sec, &mut wal_sec).ok()?;
    let mut fs_secs = FS_PART_SECTORS.lock();
    sh.pack_fs_partition(boots, &mut *fs_secs).ok()?;
    let port = AhciHwPort::probe_start();
    // Write directory + data sectors first, then superblock sector last (crash-atomic).
    let mut s = 1usize;
    while s < target_enterprise::shell::SHELL_FS_PART_SECTORS {
        port.write_sector(SHELL_FS_DISK_LBA + (s as u64), &fs_secs[s]);
        s += 1;
    }
    port.write_sector(SHELL_FS_DISK_LBA, &fs_secs[0]);
    // Write WAL payload sector first, then header sector last (crash-atomic).
    port.write_sector(SHELL_DISK_LBA + 1, &wal_sec);
    port.write_sector(SHELL_DISK_LBA, &hdr_sec);
    Some(count)
}

pub(crate) fn restore_shell_from_ahci(sh: &mut target_enterprise::OsShell) -> Option<(u64, usize)> {
    let port = AhciHwPort::probe_start();
    let hdr_sec = port.read_sector(SHELL_DISK_LBA);
    let wal_sec = port.read_sector(SHELL_DISK_LBA + 1);
    let mut all_zero = true;
    let mut i = 0usize;
    while i < 512 {
        if hdr_sec[i] != 0 || wal_sec[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    if all_zero {
        return None;
    }
    let res = match sh.unpack_disk_image(&hdr_sec, &wal_sec) {
        Ok(res) => res,
        Err(_) => {
            serial_write_str(
                "SHELL resume REJECTED: HMAC-SHA256 seal verification failed (tampered disk)\n",
            );
            return None;
        }
    };
    let sb_sec = port.read_sector(SHELL_FS_DISK_LBA);
    let mut fs_present = false;
    let mut j = 0usize;
    while j < 512 {
        if sb_sec[j] != 0 {
            fs_present = true;
            break;
        }
        j += 1;
    }
    if fs_present {
        let mut fs_secs = FS_PART_SECTORS.lock();
        fs_secs[0] = sb_sec;
        let mut s = 1usize;
        while s < target_enterprise::shell::SHELL_FS_PART_SECTORS {
            fs_secs[s] = port.read_sector(SHELL_FS_DISK_LBA + (s as u64));
            s += 1;
        }
        match sh.unpack_fs_partition(&*fs_secs) {
            Ok((generation, _, _)) if generation == res.0 => {}
            _ => {
                serial_write_str(
                    "SHELL resume REJECTED: HMAC-SHA256 seal verification failed (tampered disk)\n",
                );
                return None;
            }
        }
    }
    Some(res)
}

/// Decode the 32-byte MAC from the `hmac=<hex64>` field of an `attest:` quote line.
fn quote_hmac(quote: &[u8]) -> Option<[u8; 32]> {
    const KEY: &[u8] = b" hmac=";
    let start = quote.windows(KEY.len()).position(|w| w == KEY)? + KEY.len();
    let hex = quote.get(start..start + 64)?;
    let nibble = |c: u8| (c as char).to_digit(16).map(|d| d as u8);
    let mut mac = [0u8; 32];
    for (i, byte) in mac.iter_mut().enumerate() {
        *byte = (nibble(hex[2 * i])? << 4) | nibble(hex[2 * i + 1])?;
    }
    Some(mac)
}

/// Live composition proof for `OsShell`: seeds the BSS shell, writes and
/// reads back `/var/boot.ok`, spawns PID 5, verifies capability-gated
/// `SYS_OPEN` (`EPERM` before `grant 5 fs`, `ret=0` after), executes user
/// ELF64 `/bin/fib 10`, persists the keyed HMAC-SHA256-sealed WAL to physical AHCI
/// sectors `1040..=1041`, and verifies round-trip restoration from AHCI.
#[inline(never)]
pub(crate) fn banner_shell_compose() {
    use target_enterprise::ShellAction;

    let seal_key = derive_runtime_seal_key();
    let attest_key = derive_runtime_attest_key();
    let mut sh_guard = KERNEL_SHELL.lock();
    let sh: &mut target_enterprise::OsShell = &mut *sh_guard;
    *sh = target_enterprise::OsShell::empty();
    sh.seal_key = seal_key;
    sh.attest_key = attest_key;
    sh.seed_defaults();

    let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let mut out = [0u8; 256];
    let mut seal_rejected = false;

    if boots > 1 {
        if let Some((prev_boots, applied)) = restore_shell_from_ahci(sh) {
            if prev_boots + 1 != boots || applied < 2 {
                panic!("SHELL resume: cross-boot AHCI state drift");
            }
            let ar = sh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
            if &out[..ar.bytes_written()] != b"ready\n" {
                panic!("SHELL resume: cross-boot /var/boot.ok drift");
            }
            serial_write_str("SHELL resume OK\n");
        } else if sh.audit.len() > 0 {
            seal_rejected = true;
        }
        *sh = target_enterprise::OsShell::empty();
        sh.seal_key = seal_key;
        sh.attest_key = attest_key;
        sh.seed_defaults();
    }

    let a1 = sh.exec_line(b"write /var/boot.ok ready", boots, 0, 0, &mut out);
    if &out[..a1.bytes_written()] != b"wrote 6 bytes to /var/boot.ok\n" {
        panic!("SHELL compose: write /var/boot.ok drift");
    }
    let a2 = sh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a2.bytes_written()] != b"ready\n" {
        panic!("SHELL compose: cat /var/boot.ok drift");
    }
    let a3 = sh.exec_line(b"spawn", boots, 0, 0, &mut out);
    if &out[..a3.bytes_written()] != b"spawned pid=5\n" {
        panic!("SHELL compose: spawn pid=5 drift");
    }
    let a4 = sh.exec_line(b"kill 1", boots, 0, 0, &mut out);
    if &out[..a4.bytes_written()] != b"error: permission denied (protected system task)\n" {
        panic!("SHELL compose: protected kill 1 should deny");
    }
    let a5 = sh.exec_line(b"status", boots, 0, 0, &mut out);
    if !matches!(a5, ShellAction::Continue(_)) || sh.fs.inode_count() != 5 || sh.audit.len() != 5 {
        panic!("SHELL compose: status/audit state drift");
    }

    // Verify capability-gated syscall enforcement + ELF64/KPTI/eBPF exec:
    let a6 = sh.exec_line(b"syscall 5 open /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a6.bytes_written()] != b"syscall denied: EPERM (missing fs capability)\n" {
        panic!("SHELL compose: unprivileged syscall open should deny");
    }
    let a7 = sh.exec_line(b"grant 5 fs", boots, 0, 0, &mut out);
    if &out[..a7.bytes_written()] != b"granted fs on pid=5\n" {
        panic!("SHELL compose: grant 5 fs drift");
    }
    let a8 = sh.exec_line(b"syscall 5 open /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a8.bytes_written()] != b"syscall ok: ret=0\n" {
        panic!("SHELL compose: granted syscall open should succeed");
    }
    let a_sc_deny = sh.exec_line(b"seccomp deny 5 open", boots, 0, 0, &mut out);
    if &out[..a_sc_deny.bytes_written()] != b"seccomp: denied open on pid=5 (mask=8)\n" {
        panic!("SHELL compose: seccomp deny 5 open drift");
    }
    let a_sc_blk = sh.exec_line(b"syscall 5 open /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a_sc_blk.bytes_written()]
        != b"syscall denied: EACCES (blocked by eBPF seccomp filter)\n"
    {
        panic!("SHELL compose: seccomp filter failed to block open");
    }
    let a_sc_ok = sh.exec_line(b"syscall 5 getpid", boots, 0, 0, &mut out);
    if &out[..a_sc_ok.bytes_written()] != b"syscall ok: ret=1\n" {
        panic!("SHELL compose: seccomp filter blocked permitted getpid");
    }
    let a9 = sh.exec_line(b"exec /bin/fib 10", boots, 0, 0, &mut out);
    if &out[..a9.bytes_written()]
        != b"exec: path=/bin/fib entry=4198400 kpti=isolated insns=11 ret=55\n"
    {
        panic!("SHELL compose: exec /bin/fib 10 drift");
    }
    if sh.ima_measurements != 1 || sh.ima_pcr10 == [0u8; 32] {
        panic!("SHELL compose: IMA/TPM PCR-10 measurement not extended");
    }
    let a10 = sh.exec_line(b"exec /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a10.bytes_written()] != b"error: EPERM (IMA signature verification failed)\n" {
        panic!("SHELL compose: unsigned binary must be rejected by IMA");
    }
    let a11 = sh.exec_line(b"fw block 192.168.66.0/24", boots, 0, 0, &mut out);
    if &out[..a11.bytes_written()] != b"fw: blocked src=192.168.66.0/24\n" || sh.fw.len() != 1 {
        panic!("SHELL compose: fw block CIDR failed");
    }
    sh.auth_seq = 7;

    // Persist sealed WAL (F + T + W + Q = 4 records) to physical AHCI disk sectors 1040..=1041 and verify round-trip restore:
    if persist_shell_to_ahci(sh, boots) != Some(4) {
        panic!("SHELL compose: AHCI persist expected 4 records");
    }
    static VERIFY_SHELL: spin::Mutex<target_enterprise::OsShell> =
        spin::Mutex::new(target_enterprise::OsShell::empty());
    let mut vsh_guard = VERIFY_SHELL.lock();
    let vsh: &mut target_enterprise::OsShell = &mut *vsh_guard;
    *vsh = target_enterprise::OsShell::empty();
    vsh.seal_key = seal_key;
    vsh.attest_key = attest_key;
    vsh.seed_defaults();
    if restore_shell_from_ahci(vsh) != Some((boots, 4)) {
        panic!("SHELL compose: AHCI sealed restore failed");
    }
    if vsh.fw.len() != 1 || vsh.auth_seq != 7 || vsh.seccomp_mask[5] != 8 {
        panic!("SHELL compose: AHCI restored fw/auth_seq/seccomp drift");
    }
    let av_sc = vsh.exec_line(b"syscall 5 open /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..av_sc.bytes_written()]
        != b"syscall denied: EACCES (blocked by eBPF seccomp filter)\n"
    {
        panic!("SHELL compose: AHCI restored seccomp filter did not enforce");
    }
    let av = vsh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..av.bytes_written()] != b"ready\n" {
        panic!("SHELL compose: AHCI restored /var/boot.ok drift");
    }
    serial_write_str("SECCOMP: OK engine=ebpf filter=enforced\n");
    let mut attest_out = [0u8; 320];
    let aq = vsh.exec_line(b"attest boot-quote", boots, 0, 0, &mut attest_out);
    let quote = &attest_out[..aq.bytes_written()];
    if !quote.starts_with(b"attest: v=1 boots=") {
        panic!("SHELL compose: remote attestation quote drift");
    }
    // Verify the MAC the shell actually printed, as a remote verifier would,
    // rather than one recomputed here (which would always match).
    let Some(mac) = quote_hmac(quote) else {
        panic!("SHELL compose: remote attestation quote has no hmac field");
    };
    if !vsh.verify_attestation_mac(boots, b"boot-quote", &mac) {
        panic!("SHELL compose: remote attestation MAC verification failed");
    }
    // A quote for a different nonce must not verify.
    if vsh.verify_attestation_mac(boots, b"other-quote", &mac) {
        panic!("SHELL compose: remote attestation MAC accepted the wrong nonce");
    }
    serial_write_str("ATTEST: OK seed=");
    serial_write_str(option_env!("PROTEUS_VARIANT_SEED").unwrap_or("default-variant"));
    serial_write_str(" quote=verified\n");
    let av_df = vsh.exec_line(b"df", boots, 0, 0, &mut out);
    if &out[..av_df.bytes_written()]
        != b"fs: magic=PRTSFS01 inodes=5/16 pool_bytes=704/4096 part_sectors=16\n"
    {
        panic!("SHELL compose: df output drift");
    }
    let av_sync = vsh.exec_line(b"sync", boots, 0, 0, &mut out);
    if !out[..av_sync.bytes_written()].starts_with(b"sync: ok files=1 bytes=6 seal=") {
        panic!("SHELL compose: sync output drift");
    }
    serial_write_str("FS partition OK lba=1042..1057 sectors=16 files=1 magic=PRTSFS01\n");
    verify_https_and_concurrent_tcp_compose(boots, seal_key);
    let _ = sh.exec_line(b"seccomp clear 5", boots, 0, 0, &mut out);
    let _ = sh.exec_line(b"fw clear", boots, 0, 0, &mut out);
    sh.auth_seq = 0;

    serial_write_str("SHELL compose OK tasks=5 files=5 audit=5\n");
    if seal_rejected {
        sh.record_net_audit(proteus_contracts::AuditVerdict::Denied, b"shell:wal:seal-mismatch");
    }
}

#[inline(never)]
fn verify_https_and_concurrent_tcp_compose(boots: u64, auth_key: [u8; 32]) {
    use proteus_contracts::{tcp_flags, Aead, Tcp, IP_PROTO_TCP};
    use target_enterprise::lived_net::{
        GUEST_IP, HTTPS_PORT, HTTP_PORT, TCP_MAX_SLOTS, TLS_CONTENT_APPLICATION_DATA,
        TLS_SERVER_PUBKEY,
    };
    use target_enterprise::tcp::TcpImpl;
    use target_enterprise::tls::{
        build_client_hello, decode_record_header, encode_record_header, parse_server_hello,
        CONTENT_TYPE_HANDSHAKE, LEGACY_VERSION, RECORD_HEADER_LEN,
    };

    const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
    const PEER_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
    const PEER_IP: [u8; 4] = [10, 0, 2, 2];

    static COMPOSE_REPLIES: spin::Mutex<target_enterprise::ReplySet> =
        spin::Mutex::new(target_enterprise::ReplySet::new());

    let mut net = target_enterprise::LivedNet::with_auth_key(MAC, auth_key);
    let mut tls_server_isn = 0u32;

    let wrap_eth_ip = |tcp_seg: &[u8], frame_out: &mut [u8; 384]| -> usize {
        let ip_len = 20 + tcp_seg.len();
        let eth_len = 14 + ip_len;
        frame_out[..6].copy_from_slice(&MAC);
        frame_out[6..12].copy_from_slice(&PEER_MAC);
        frame_out[12] = 0x08;
        frame_out[13] = 0x00;
        frame_out[14] = 0x45;
        frame_out[15] = 0;
        frame_out[16..18].copy_from_slice(&(ip_len as u16).to_be_bytes());
        frame_out[18..22].copy_from_slice(&[0, 0, 0x40, 0]);
        frame_out[22] = 64;
        frame_out[23] = IP_PROTO_TCP;
        frame_out[24..26].copy_from_slice(&[0, 0]);
        frame_out[26..30].copy_from_slice(&PEER_IP);
        frame_out[30..34].copy_from_slice(&GUEST_IP);
        let ck = target_enterprise::net::ipv4_header_checksum(&frame_out[14..34]);
        frame_out[24..26].copy_from_slice(&ck.to_be_bytes());
        frame_out[34..eth_len].copy_from_slice(tcp_seg);
        eth_len
    };

    let mut slot = 0usize;
    while slot < TCP_MAX_SLOTS {
        let dst_port = if slot + 1 == TCP_MAX_SLOTS {
            HTTPS_PORT
        } else {
            HTTP_PORT
        };
        let cport = 52000 + (slot as u16);
        let cisn = 0x5000_0000 + ((slot as u32) << 16);
        let mut syn = [0u8; 40];
        let n = TcpImpl::build_segment(
            cport,
            dst_port,
            cisn,
            0,
            tcp_flags::SYN,
            65535,
            b"",
            PEER_IP,
            GUEST_IP,
            &mut syn,
        )
        .unwrap();
        let mut frame = [0u8; 384];
        let flen = wrap_eth_ip(&syn[..n], &mut frame);
        let mut rep = COMPOSE_REPLIES.lock();
        *rep = target_enterprise::ReplySet::new();
        net.handle_frame(&frame[..flen], boots, &mut *rep);
        if rep.len() != 1 {
            panic!("HTTPS+TCP4 compose: expected SYN-ACK");
        }
        let sa = TcpImpl::parse_segment(&rep.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
        if sa.flags != (tcp_flags::SYN | tcp_flags::ACK) {
            panic!("HTTPS+TCP4 compose: unexpected SYN-ACK flags");
        }
        if dst_port == HTTPS_PORT {
            tls_server_isn = sa.seq;
        }
        slot += 1;
    }

    if net.active_tcp_slots() != 4 {
        panic!("HTTPS+TCP4 compose: expected 4 active concurrent TCP slots");
    }

    let client_random = [0x33u8; 32];
    let client_pubkey = [0x77u8; 32];
    let mut ch_msg = [0u8; 256];
    let ch_len = build_client_hello(&client_random, &client_pubkey, &mut ch_msg).unwrap();
    let mut tls_rec = [0u8; 264];
    let _ = encode_record_header(
        CONTENT_TYPE_HANDSHAKE,
        LEGACY_VERSION,
        ch_len as u16,
        &mut tls_rec,
    );
    tls_rec[RECORD_HEADER_LEN..RECORD_HEADER_LEN + ch_len].copy_from_slice(&ch_msg[..ch_len]);
    let rec_total = RECORD_HEADER_LEN + ch_len;

    let tls_cport = 52000 + ((TCP_MAX_SLOTS - 1) as u16);
    let tls_cisn = 0x5000_0000 + (((TCP_MAX_SLOTS - 1) as u32) << 16);
    let mut ch_seg = [0u8; 320];
    let n = TcpImpl::build_segment(
        tls_cport,
        HTTPS_PORT,
        tls_cisn.wrapping_add(1),
        tls_server_isn.wrapping_add(1),
        tcp_flags::ACK | tcp_flags::PSH,
        65535,
        &tls_rec[..rec_total],
        PEER_IP,
        GUEST_IP,
        &mut ch_seg,
    )
    .unwrap();
    let mut frame = [0u8; 384];
    let flen = wrap_eth_ip(&ch_seg[..n], &mut frame);
    let mut rep = COMPOSE_REPLIES.lock();
    *rep = target_enterprise::ReplySet::new();
    net.handle_frame(&frame[..flen], boots, &mut *rep);
    if rep.len() != 1 {
        panic!("HTTPS+TCP4 compose: expected TLS 1.3 ServerHello + ApplicationData segment");
    }
    let resp_seg = TcpImpl::parse_segment(&rep.get(0).unwrap()[34..], GUEST_IP, PEER_IP).unwrap();
    let payload = resp_seg.payload;
    let (r1_type, _, r1_len_u16) = decode_record_header(payload).unwrap();
    if r1_type != CONTENT_TYPE_HANDSHAKE {
        panic!("HTTPS+TCP4 compose: expected Handshake record");
    }
    let r1_len = r1_len_u16 as usize;
    let sh_slice = &payload[RECORD_HEADER_LEN..RECORD_HEADER_LEN + r1_len];
    let parsed_sh = parse_server_hello(sh_slice).unwrap();
    if parsed_sh.server_pubkey != TLS_SERVER_PUBKEY {
        panic!("HTTPS+TCP4 compose: ServerHello pubkey mismatch");
    }
    let mut record_key = [0u8; 16];
    let _ = target_enterprise::LivedNet::derive_tls13_record_key(
        &client_pubkey,
        &ch_msg[..ch_len],
        sh_slice,
        &mut record_key,
    );
    let r2_slice = &payload[RECORD_HEADER_LEN + r1_len..];
    let (r2_type, _, r2_len_u16) = decode_record_header(r2_slice).unwrap();
    if r2_type != TLS_CONTENT_APPLICATION_DATA {
        panic!("HTTPS+TCP4 compose: expected ApplicationData record");
    }
    let r2_len = r2_len_u16 as usize;
    let mut plain_status = [0u8; 64];
    let plen = target_enterprise::AeadImpl::decrypt(
        &record_key,
        &[0u8; 8],
        &r2_slice[RECORD_HEADER_LEN..RECORD_HEADER_LEN + r2_len],
        &r2_slice[..RECORD_HEADER_LEN],
        &mut plain_status,
    )
    .unwrap();
    if !plain_status[..plen].starts_with(b"PROTEUS-STATUS boots=") {
        panic!("HTTPS+TCP4 compose: decrypted TLS 1.3 status payload drift");
    }

    serial_write_str("HTTPS+TCP4 compose OK slots=4 port=443 tls13=ok\n");
}

