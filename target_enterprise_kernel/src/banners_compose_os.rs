//! Kernel submodule.

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

// TASK-083 IOAPIC
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ioapic() {
    use proteus_contracts::IoApic;
    use target_enterprise::ioapic::{banner_entry, IoApicImpl};

    let e = banner_entry();
    let (lo, hi) = IoApicImpl::encode(&e);
    let d = IoApicImpl::decode(lo, hi);
    if d.vector != 0x30 {
        panic!("IOAPIC banner: vector drift");
    }
    serial_write_bytes(b"IOAPIC entry OK vec=0x30\n");
}

// TASK-084 LAPIC ICR
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_lapic() {
    use proteus_contracts::{LapicIcr, ICR_DELIVERY_INIT};
    use target_enterprise::lapic_icr::LapicIcrImpl;

    let c = LapicIcrImpl::init(0);
    if LapicIcrImpl::delivery_of(c.low) != ICR_DELIVERY_INIT {
        panic!("LAPIC banner: delivery drift");
    }
    serial_write_bytes(b"LAPIC icr OK delivery=init\n");
}

// TASK-079 Multiboot2
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_mb2() {
    use proteus_contracts::{Mb2Tag, Multiboot2, MB2_MAX_TAGS};
    use target_enterprise::multiboot2::{build_banner_fixture, MB2_FIXTURE_LEN, Multiboot2Impl};

    let mut img = [0u8; MB2_FIXTURE_LEN];
    build_banner_fixture(&mut img).unwrap();
    let mut out = [Mb2Tag {
        typ: 0,
        size: 0,
        offset: 0,
    }; MB2_MAX_TAGS];
    let n = Multiboot2Impl::walk(&img, &mut out).unwrap();
    if n != 1 {
        panic!("MB2 banner: tag count");
    }
    serial_write_bytes(b"MB2 parse OK tags=1\n");
}

// TASK-080 CRC32C
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_crc32c() {
    use proteus_contracts::Crc32c;
    use target_enterprise::crc32c::Crc32cImpl;

    if Crc32cImpl::hash(b"123456789") != 0xE306_9283 {
        panic!("CRC32C banner: kat fail");
    }
    serial_write_bytes(b"CRC32C kat OK\n");
}

// TASK-081 RSDP
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_rsdp() {
    use proteus_contracts::AcpiRsdp;
    use target_enterprise::acpi_rsdp::{build_banner_fixture, AcpiRsdpImpl};

    let mut b = [0u8; 20];
    build_banner_fixture(&mut b).unwrap();
    let r = AcpiRsdpImpl::parse_v1(&b).unwrap();
    if &r.oem_id != b"BOCHS " {
        panic!("RSDP banner: oem");
    }
    serial_write_bytes(b"RSDP parse OK oem=BOCHS\n");
}

// TASK-082 frame bitmap
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_frame() {
    use proteus_contracts::FrameBitmap;
    use target_enterprise::frame_bitmap::FrameBitmapImpl;

    let mut b = FrameBitmapImpl::new();
    b.alloc().unwrap();
    b.alloc().unwrap();
    if b.free_count() != 4094 {
        panic!("FRAME banner: free count");
    }
    serial_write_bytes(b"FRAME alloc OK free=4094\n");
}

// TASK-075: 16550 init sequence
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_serial() {
    use proteus_contracts::{Serial16550, SERIAL_COM1, SERIAL_INIT_WRITES};
    use target_enterprise::serial16550::{expected_com1_init, RecordingSerialPort, Serial16550Impl};

    let mut p = RecordingSerialPort::new();
    let n = Serial16550Impl::init(&mut p, SERIAL_COM1);
    if n != SERIAL_INIT_WRITES || p.write_n() != 7 {
        panic!("SERIAL banner: write count");
    }
    let exp = expected_com1_init();
    let mut i = 0usize;
    while i < 7 {
        if p.write_at(i) != Some(exp[i]) {
            panic!("SERIAL banner: sequence drift");
        }
        i += 1;
    }
    serial_write_bytes(b"SERIAL init OK port=0x3f8\n");
}

// TASK-076: tick source mux
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_tick() {
    use proteus_contracts::{TickKind, TickSource};
    use target_enterprise::tick_source::TickSourceImpl;

    let mut t = TickSourceImpl::new();
    t.select(TickKind::Hpet);
    if t.kind() != TickKind::Hpet {
        panic!("TICK banner: kind drift");
    }
    t.advance(1);
    if t.now_ticks() != 1 {
        panic!("TICK banner: ticks drift");
    }
    serial_write_bytes(b"TICK source OK kind=hpet\n");
}

// TASK-077: virtio pci caps
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_caps() {
    use proteus_contracts::{
        VirtioPciCap, VirtioPciCaps, VIRTIO_PCI_CAP_COMMON_CFG, VIRTIO_PCI_CAP_MAX,
    };
    use target_enterprise::virtio_pci_caps::{banner_read_dword, VirtioPciCapsImpl};

    let mut out = [VirtioPciCap {
        offset: 0,
        cfg_type: 0,
        bar: 0,
        bar_offset: 0,
        length: 0,
    }; VIRTIO_PCI_CAP_MAX];
    let n = match VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out) {
        Ok(n) => n,
        Err(_) => panic!("VIRTIO caps banner: walk failed"),
    };
    if VirtioPciCapsImpl::find(&out[..n], VIRTIO_PCI_CAP_COMMON_CFG).is_none() {
        panic!("VIRTIO caps banner: common missing");
    }
    serial_write_bytes(b"VIRTIO caps OK common=found\n");
}

// TASK-078: sig kat
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_sigkat() {
    use proteus_contracts::{SigKat, SIGKAT_VECTOR_COUNT};
    use target_enterprise::sigkat::SigKatImpl;

    let s = SigKatImpl::run_all();
    if !s.all_ok() || s.total != SIGKAT_VECTOR_COUNT {
        panic!("SIGKAT banner: suite failed");
    }
    {
        let mut line = [0u8; 40];
        let mut pos = 0usize;
        let prefix = b"SIGKAT all OK vectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(s.passed as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-071: Watchdog arm/pet/fire.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_watchdog() {
    use proteus_contracts::{Watchdog, WatchdogError};
    use target_enterprise::watchdog::{BANNER_DEADLINE, WatchdogImpl};

    let mut w = WatchdogImpl::new();
    if w.arm(BANNER_DEADLINE).is_err() {
        panic!("WATCHDOG banner: arm failed");
    }
    if w.pet().is_err() {
        panic!("WATCHDOG banner: pet failed");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"WATCHDOG pet OK deadline=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(w.deadline() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    // Fire: re-arm with 2 and tick out
    let mut w2 = WatchdogImpl::new();
    w2.arm(2).unwrap();
    w2.tick().unwrap();
    match w2.tick() {
        Err(WatchdogError::Fired) => {}
        _ => panic!("WATCHDOG banner: fire expected"),
    }
    serial_write_bytes(b"WATCHDOG fire OK reason=timeout\n");
}

// TASK-072: RNG KAT
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_rng() {
    use proteus_contracts::Random;
    use target_enterprise::random::{banner_expected_prefix8, BANNER_SEED, RandomImpl};

    let mut r = RandomImpl::new();
    if r.seed(&BANNER_SEED).is_err() {
        panic!("RNG banner: seed failed");
    }
    let mut out = [0u8; 8];
    if r.fill(&mut out).is_err() {
        panic!("RNG banner: fill failed");
    }
    let exp = banner_expected_prefix8();
    let mut i = 0usize;
    while i < 8 {
        if out[i] != exp[i] {
            panic!("RNG banner: KAT drift");
        }
        i += 1;
    }
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"RNG kat OK seed=0102 out=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        i = 0;
        while i < 4 {
            let b = out[i];
            let hi = b >> 4;
            let lo = b & 0x0F;
            line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
            pos += 1;
            line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
            pos += 1;
            i += 1;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-073: Power S5
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_power() {
    use proteus_contracts::{Power, SLP_TYP_S5};
    use target_enterprise::power::PowerImpl;

    let p = PowerImpl::encode_s5(SLP_TYP_S5);
    if PowerImpl::decode_slp_typ(p) != 5 || !PowerImpl::is_slp_en(p) {
        panic!("POWER banner: encode drift");
    }
    serial_write_bytes(b"POWER s5 OK slp_typ=5\n");
}

// TASK-074: ELF64
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_elf() {
    use proteus_contracts::{Elf64, ELF_MAX_PHDRS, ElfPhdr};
    use target_enterprise::elf64::{
        build_banner_fixture, ELF_BANNER_ENTRY, ELF_BANNER_PHNUM, ELF_FIXTURE_LEN, Elf64Impl,
    };

    let mut img = [0u8; ELF_FIXTURE_LEN];
    if build_banner_fixture(&mut img).is_err() {
        panic!("ELF banner: fixture failed");
    }
    let h = match Elf64Impl::parse_header(&img) {
        Ok(h) => h,
        Err(_) => panic!("ELF banner: parse failed"),
    };
    if h.phnum != ELF_BANNER_PHNUM || h.entry != ELF_BANNER_ENTRY {
        panic!("ELF banner: header drift");
    }
    let mut ph = [ElfPhdr {
        ptype: 0,
        flags: 0,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        align: 0,
    }; ELF_MAX_PHDRS];
    let n = match Elf64Impl::load_phdrs(&img, &h, &mut ph) {
        Ok(n) => n,
        Err(_) => panic!("ELF banner: phdrs failed"),
    };
    if n != 1 {
        panic!("ELF banner: phdr count drift");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"ELF parse OK phnum=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(h.phnum as u64, &mut line[pos..]);
        let mid = b" entry=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(h.entry, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-067: HPET — program 1 ms periodic timer0 against recording bus.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_hpet() {
    use proteus_contracts::Hpet;
    use target_enterprise::hpet::{
        BANNER_PERIOD_FS, BANNER_PERIOD_MS, HpetImpl, RecordingHpetBus,
    };

    let mut bus = RecordingHpetBus::new();
    bus.script_canonical_cap(BANNER_PERIOD_FS, 0x8086, 2);
    let caps = match HpetImpl::read_caps(&mut bus) {
        Ok(c) => c,
        Err(_) => panic!("HPET banner: caps failed"),
    };
    if caps.period_fs != BANNER_PERIOD_FS {
        panic!("HPET banner: period drift");
    }
    HpetImpl::enable(&mut bus);
    let cmp = match HpetImpl::ms_to_ticks(caps.period_fs, BANNER_PERIOD_MS) {
        Ok(t) => t,
        Err(_) => panic!("HPET banner: ms_to_ticks failed"),
    };
    if cmp != 14318 {
        panic!("HPET banner: cmp drift");
    }
    if HpetImpl::program_timer0_periodic(&mut bus, cmp).is_err() {
        panic!("HPET banner: program failed");
    }
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"HPET program OK period_fs=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(caps.period_fs as u64, &mut line[pos..]);
        let mid = b" cmp=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(cmp, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-068: Stack canary mint + mismatch fingerprint.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_canary() {
    use proteus_contracts::StackCanary;
    use target_enterprise::stack_canary::{BANNER_SEED, StackCanaryImpl};

    let tok = match StackCanaryImpl::mint(&BANNER_SEED) {
        Ok(t) => t,
        Err(_) => panic!("CANARY banner: mint failed"),
    };
    if StackCanaryImpl::verify(&tok, &tok).is_err() {
        panic!("CANARY banner: self-verify failed");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"CANARY mint OK tok=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // first 4 bytes as hex
        let mut i = 0usize;
        while i < 4 {
            let b = tok.bytes[i];
            let hi = b >> 4;
            let lo = b & 0x0F;
            line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
            pos += 1;
            line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
            pos += 1;
            i += 1;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let mut bad = tok;
    bad.bytes[0] ^= 0x01;
    if StackCanaryImpl::verify(&tok, &bad).is_ok() {
        panic!("CANARY banner: mismatch not detected");
    }
    let fp = StackCanaryImpl::fail_fingerprint(&tok, &bad);
    if (fp & 0xFF) != 1 {
        panic!("CANARY banner: fingerprint drift");
    }
    serial_write_bytes(b"CANARY fail OK reason=mismatch\n");
}

// TASK-069: Keyboard set-1 stream a/b.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_keyboard() {
    use proteus_contracts::{KeyCode, Keyboard, KBD_BREAK_A, KBD_BREAK_B, KBD_MAKE_A, KBD_MAKE_B};
    use target_enterprise::keyboard::KeyboardImpl;

    let mut kbd = KeyboardImpl::new();
    let stream = [KBD_MAKE_A, KBD_BREAK_A, KBD_MAKE_B, KBD_BREAK_B];
    let mut keys = 0u32;
    let mut last = b'\0';
    let mut i = 0usize;
    while i < stream.len() {
        if let Some(ev) = kbd.feed(stream[i]) {
            if ev.pressed && ev.ascii != 0 {
                keys += 1;
                last = ev.ascii;
                let _ = KeyCode::Letter(b'A'); // keep import used
            }
        }
        i += 1;
    }
    if keys != 2 || last != b'b' {
        panic!("KBD banner: decode drift");
    }
    serial_write_bytes(b"KBD decode OK keys=2 last=b\n");
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

// TASK-065: GDB RSP wire codec. Parses the locked `$g#67` frame
// (read-registers), classifies it, builds the 256-zero register
// reply, re-frames it, and asserts the checksum digits are `00`.
// Banner: `GDBSTUB parse OK cmd=g cksum=67`.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_gdbstub() {
    use proteus_contracts::{GdbCommand, GdbStub};
    use target_enterprise::gdbstub::GdbStubImpl;

    let frame = b"$g#67";
    let pkt = match GdbStubImpl::parse_frame(frame) {
        Ok(p) => p,
        Err(_) => panic!("GDBSTUB banner: parse failed"),
    };
    if pkt.body != b"g" {
        panic!("GDBSTUB banner: body drift");
    }
    if pkt.checksum != 0x67 {
        panic!("GDBSTUB banner: checksum drift");
    }
    let cmd = GdbStubImpl::classify(pkt.body);
    if cmd != GdbCommand::ReadRegisters {
        panic!("GDBSTUB banner: classify drift");
    }
    let mut body = [0u8; 256];
    let n = match GdbStubImpl::reply_body(&cmd, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("GDBSTUB banner: reply failed"),
    };
    if n != 256 {
        panic!("GDBSTUB banner: reply length drift");
    }
    // Re-frame and verify checksum digits of the all-zero reply.
    let mut out_frame = [0u8; 512];
    let flen = match GdbStubImpl::build_frame(&body[..n], &mut out_frame) {
        Ok(n) => n,
        Err(_) => panic!("GDBSTUB banner: build_frame failed"),
    };
    // Last two bytes must be hex of checksum(256 × '0') = 0x00.
    if out_frame[flen - 2] != b'0' || out_frame[flen - 1] != b'0' {
        panic!("GDBSTUB banner: reply frame cksum drift");
    }
    // Round-trip parse.
    match GdbStubImpl::parse_frame(&out_frame[..flen]) {
        Ok(p) if p.body.len() == 256 && p.checksum == 0 => {}
        _ => panic!("GDBSTUB banner: reply reparse failed"),
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"GDBSTUB parse OK cmd=g cksum=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Two hex digits of 0x67.
        let cs: u8 = 0x67;
        let hi = cs >> 4;
        let lo = cs & 0x0F;
        line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
        pos += 1;
        line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
        pos += 1;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
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

// TASK-063: Crypto KAT harness. Runs the locked 9-vector suite
// (SHA-256 empty/abc/million-a, HMAC RFC 4231 cases 1-4, HKDF RFC
// 5869 cases 1-2) against the real TLS crypto primitives. Any
// digest drift panics; on full pass emits
// `KAT all OK vectors=9`. A morph that perturbs SHA-256, HMAC, or
// HKDF arithmetic panics inside `banner_kat` and the banner never
// appears.
// ============================================================
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_kat() {
    use proteus_contracts::{KatRunner, KAT_VECTOR_COUNT};
    use target_enterprise::kat::KatImpl;

    let suite = KatImpl::run_all();
    if suite.total != KAT_VECTOR_COUNT {
        panic!("KAT banner: suite cardinality drift");
    }
    if !suite.all_ok() {
        panic!("KAT banner: vector failure");
    }
    if suite.passed != KAT_VECTOR_COUNT {
        panic!("KAT banner: passed count drift");
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"KAT all OK vectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(suite.passed as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-060: X.509 v3 DER parser. The kernel parses the locked
// 257-byte Ed25519 self-signed fixture in
// `kernel_fixtures::X509_FIXTURE_DER`, asserts the recovered
// version / serial / validity window / pubkey / subject CN match
// the locked goldens byte-for-byte, then emits two banners. A
// morph that perturbs any byte position in the TLV walker, the
// SPKI BIT STRING decode, or the UTCTime arithmetic panics inside
// `banner_x509` and the banners never appear.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_x509() {
    use proteus_contracts::{X509PubKey, X509PubKeyAlg, X509Time, X509};
    use target_enterprise::x509::X509Impl;

    let cert = match X509Impl::parse(kf::X509_FIXTURE_DER) {
        Ok(c) => c,
        Err(_) => panic!("X509 banner: parse failed"),
    };
    if cert.version != 2 {
        panic!("X509 banner: version drift");
    }
    if cert.pubkey_alg != X509PubKeyAlg::Ed25519 {
        panic!("X509 banner: pubkey_alg drift");
    }
    if cert.serial.len() != 1 || cert.serial[0] != kf::X509_FIXTURE_SERIAL {
        panic!("X509 banner: serial drift");
    }
    if cert.not_before.unix != kf::X509_FIXTURE_NOT_BEFORE_UNIX {
        panic!("X509 banner: not_before drift");
    }
    if cert.not_after.unix != kf::X509_FIXTURE_NOT_AFTER_UNIX {
        panic!("X509 banner: not_after drift");
    }
    match cert.pubkey {
        X509PubKey::Ed25519 { key } => {
            if key != kf::X509_FIXTURE_PUBKEY {
                panic!("X509 banner: pubkey bytes drift");
            }
        }
        _ => panic!("X509 banner: pubkey variant drift"),
    }
    if !X509Impl::validity_contains(&cert, X509Time { unix: 1_700_000_000 }) {
        panic!("X509 banner: validity window drift");
    }
    if cert.issuer != cert.subject {
        panic!("X509 banner: self-signed DN drift");
    }
    if X509Impl::issuer_matches_subject(&cert, &cert).is_err() {
        panic!("X509 banner: issuer/subject match drift");
    }

    // Emit parse banner: byte length + serial.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"X509 parse OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(kf::X509_FIXTURE_DER.len() as u64, &mut line[pos..]);
        let mid = b" serial=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(cert.serial[0] as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Recover the CN from the subject DN and assert byte-equality.
    let cn = match X509Impl::find_cn(cert.subject) {
        Some(c) => c,
        None => panic!("X509 banner: subject CN missing"),
    };
    if cn != kf::X509_FIXTURE_SUBJECT_CN {
        panic!("X509 banner: CN drift");
    }

    // Emit CN banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"X509 cn OK cn=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos..pos + cn.len()].copy_from_slice(cn);
        pos += cn.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TASK-145: live guest durable seal of a fixed empty audit snapshot
/// header (magic-only / zero events). Proves `durable_seal` is linked
/// into the boot image. Does **not** claim implant immunity.
#[inline(never)]
pub(crate) fn banner_durable_seal() {
    use proteus_contracts::{AUDIT_SNAPSHOT_HEADER_LEN, AUDIT_SNAPSHOT_MAGIC};
    use target_enterprise::durable_seal::{
        seal_bytes, seal_bytes_keyed, seal_matches_keyed, DURABLE_DIGEST_LEN,
    };

    // Empty log snapshot = 20-byte header only (count=0).
    let mut snap = [0u8; AUDIT_SNAPSHOT_HEADER_LEN];
    let magic = AUDIT_SNAPSHOT_MAGIC.to_be_bytes();
    snap[0..4].copy_from_slice(&magic);
    // record_count = 0 already
    let rec_size = (96u32).to_be_bytes(); // AUDIT_EVENT_WIRE_LEN
    snap[8..12].copy_from_slice(&rec_size);
    // high_watermark = 0

    let mut dig = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes(&snap, &mut dig);

    // Also verify keyed HMAC-SHA256 tamper-proof sealing and confirm an unkeyed SHA-256 hash is rejected.
    let seal_key = derive_runtime_seal_key();
    let mut keyed_mac = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(&seal_key, &snap, &mut keyed_mac);
    if !seal_matches_keyed(&seal_key, &snap, &keyed_mac)
        || seal_matches_keyed(&seal_key, &snap, &dig)
    {
        panic!("DURABLE seal: keyed HMAC-SHA256 verification failed");
    }

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"DURABLE seal OK dig=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 16]; // first 8 bytes of digest
    hex_encode(&dig, 8, &mut hex);
    line[pos..pos + 16].copy_from_slice(&hex);
    pos += 16;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_panic_dump() {
    // Build the canonical CrashContext.
    let ctx = CrashContext {
        wall_unix: kf::CRASH_WALL_UNIX,
        tsc: kf::CRASH_TSC,
        panic_loc: kf::CRASH_PANIC_LOC,
        message: kf::CRASH_MESSAGE,
        registers: &kf::CRASH_REGISTERS,
        backtrace: &kf::CRASH_BACKTRACE,
        kmsg: kf::CRASH_KMSG,
    };

    let mut buf = [0u8; proteus_contracts::CRASH_DUMP_BYTES];
    let mut sink = MemorySectorSink::new();
    let (lba_start, lba_end) = match PanicDumpImpl::dump_to_sink(&ctx, &mut buf, &mut sink) {
        Ok(t) => t,
        Err(_) => panic!("PanicDumpImpl::dump_to_sink failed"),
    };
    if lba_start != DUMP_START_LBA {
        panic!("panic_dump: lba_start drift");
    }
    if lba_end - lba_start != proteus_contracts::CRASH_DUMP_SECTORS {
        panic!("panic_dump: lba range size drift");
    }

    // Body CRC must verify, AND the recorded CRC must equal the
    // locked expected fixture so a morph that perturbs the layout
    // panics here.
    if PanicDumpImpl::verify_crc(&buf).is_err() {
        panic!("panic_dump: verify_crc returned Err for own dump");
    }
    let header = match PanicDumpImpl::parse_header(&buf) {
        Ok(h) => h,
        Err(_) => panic!("panic_dump: parse_header rejected own dump"),
    };
    if header.body_crc32c != kf::CRASH_EXPECTED_CRC32C {
        panic!("panic_dump: CRC32-C drift");
    }
    if header.kmsg_len as usize != kf::CRASH_KMSG.len() {
        panic!("panic_dump: kmsg_len drift");
    }
    if header.backtrace_count as usize != kf::CRASH_BACKTRACE.len() {
        panic!("panic_dump: backtrace_count drift");
    }
    if header.register_count as usize != proteus_contracts::CRASH_REG_COUNT {
        panic!("panic_dump: register_count drift");
    }
    // Header strings must round-trip.
    if header.panic_loc.as_bytes() != kf::CRASH_PANIC_LOC.as_bytes() {
        panic!("panic_dump: panic_loc drift");
    }
    if header.message.as_bytes() != kf::CRASH_MESSAGE.as_bytes() {
        panic!("panic_dump: message drift");
    }

    // Sink must have received every sector in ascending LBA order.
    if sink.recorded != 32 {
        panic!("panic_dump: sink missed a sector");
    }
    let mut k = 1usize;
    while k < sink.recorded {
        if sink.recorded_lbas[k] <= sink.recorded_lbas[k - 1] {
            panic!("panic_dump: sector LBAs not strictly ascending");
        }
        k += 1;
    }

    // Disk bytes received by the sink must equal the build_dump output.
    let mut i = 0usize;
    while i < proteus_contracts::CRASH_DUMP_BYTES {
        if sink.disk[i] != buf[i] {
            panic!("panic_dump: sink/buf byte drift");
        }
        i += 1;
    }

    // Backtrace recovery must round-trip.
    let mut extracted_bt = [0u64; proteus_contracts::CRASH_BACKTRACE_MAX];
    let bt_n = match PanicDumpImpl::extract_backtrace(&buf, &mut extracted_bt) {
        Ok(n) => n,
        Err(_) => panic!("panic_dump: extract_backtrace failed"),
    };
    if bt_n != kf::CRASH_BACKTRACE.len() {
        panic!("panic_dump: extracted backtrace length drift");
    }
    let mut j = 0usize;
    while j < bt_n {
        if extracted_bt[j] != kf::CRASH_BACKTRACE[j] {
            panic!("panic_dump: backtrace frame drift");
        }
        j += 1;
    }

    // Emit the dump banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"CRASH_DUMP wrote 16384 bytes to lba=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(DUMP_START_LBA, &mut line[pos..]);
        let mid = b" crc=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let crc_be = header.body_crc32c.to_be_bytes();
        let mut crc_hex = [0u8; 8];
        hex_encode(&crc_be, 4, &mut crc_hex);
        line[pos..pos + 8].copy_from_slice(&crc_hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Hand-built kernel-symbol fixture matching CRASH_BACKTRACE.
    const SYMBOLS: &[SymbolEntry] = &[
        SymbolEntry::new(0xFFFF_FFFF_8010_0000, 0x100, "kernel_main"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0500, 0x200, "schedule_next_task"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0800, 0x100, "handle_irq_timer"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0A00, 0x080, "halt_forever"),
    ];
    if !StaticSymbolResolver::is_sorted_by_addr(SYMBOLS) {
        panic!("panic_dump: kernel-symbol fixture is unsorted");
    }
    let resolver = StaticSymbolResolver::new(SYMBOLS);
    if resolver.symbol_count() != 4 {
        panic!("panic_dump: symbol_count drift");
    }

    // Resolve every recovered frame; assert the first matches the
    // locked expected name/offset.
    let (first_name, first_off) = match resolver.resolve(extracted_bt[0]) {
        Some(t) => t,
        None => panic!("panic_dump: first frame did not resolve"),
    };
    if first_name.as_bytes() != kf::CRASH_EXPECTED_RESOLVE_NAME.as_bytes() {
        panic!("panic_dump: resolved name drift");
    }
    if first_off != kf::CRASH_EXPECTED_RESOLVE_OFFSET {
        panic!("panic_dump: resolved offset drift");
    }
    let mut m = 0usize;
    while m < bt_n {
        if resolver.resolve(extracted_bt[m]).is_none() {
            panic!("panic_dump: a backtrace frame did not resolve");
        }
        m += 1;
    }

    // Emit the resolver banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"SYMBOL resolve OK ";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let nb = first_name.as_bytes();
        line[pos..pos + nb.len()].copy_from_slice(nb);
        pos += nb.len();
        let mid = b"+0x";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // Lowercase hex of first_off, MSB-first, no leading zeros.
        let mut nyb = 16i32; // count leading non-zero nybbles
        while nyb > 0 {
            let shift = (nyb - 1) * 4;
            if ((first_off >> shift) & 0xF) != 0 {
                break;
            }
            nyb -= 1;
        }
        if nyb == 0 {
            line[pos] = b'0';
            pos += 1;
        } else {
            let mut nn = nyb;
            while nn > 0 {
                nn -= 1;
                let n = ((first_off >> (nn * 4)) & 0xF) as u8;
                line[pos] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }
        }
        let mid2 = b" (";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(bt_n as u64, &mut line[pos..]);
        let mid3 = b" frames)";
        line[pos..pos + mid3.len()].copy_from_slice(mid3);
        pos += mid3.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
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

pub(crate) fn persist_shell_to_ahci(sh: &mut target_enterprise::OsShell, boots: u64) -> Option<usize> {
    let mut hdr_sec = [0u8; 512];
    let mut wal_sec = [0u8; 512];
    let count = sh.pack_disk_image(boots, &mut hdr_sec, &mut wal_sec).ok()?;
    let port = AhciHwPort::probe_start();
    // Write WAL payload sector first, then header sector last (crash-atomic).
    port.write_sector(SHELL_DISK_LBA + 1, &wal_sec);
    port.write_sector(SHELL_DISK_LBA, &hdr_sec);
    Some(count)
}

pub(crate) fn restore_shell_from_ahci(sh: &mut target_enterprise::OsShell) -> Option<(u64, usize)> {
    let port = AhciHwPort::probe_start();
    let hdr_sec = port.read_sector(SHELL_DISK_LBA);
    if &hdr_sec[0..8] != b"PRTSSHL1" {
        return None;
    }
    let wal_sec = port.read_sector(SHELL_DISK_LBA + 1);
    sh.unpack_disk_image(&hdr_sec, &wal_sec).ok()
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
    let mut sh_guard = KERNEL_SHELL.lock();
    let sh: &mut target_enterprise::OsShell = &mut *sh_guard;
    *sh = target_enterprise::OsShell::empty();
    sh.seal_key = seal_key;
    sh.seed_defaults();

    let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let mut out = [0u8; 256];

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
        }
        *sh = target_enterprise::OsShell::empty();
        sh.seal_key = seal_key;
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
    vsh.seed_defaults();
    if restore_shell_from_ahci(vsh) != Some((boots, 4)) {
        panic!("SHELL compose: AHCI sealed restore failed");
    }
    if vsh.fw.len() != 1 || vsh.auth_seq != 7 {
        panic!("SHELL compose: AHCI restored fw/auth_seq drift");
    }
    let av = vsh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..av.bytes_written()] != b"ready\n" {
        panic!("SHELL compose: AHCI restored /var/boot.ok drift");
    }
    let _ = sh.exec_line(b"fw clear", boots, 0, 0, &mut out);
    sh.auth_seq = 0;

    serial_write_str("SHELL compose OK tasks=5 files=5 audit=5\n");
}

