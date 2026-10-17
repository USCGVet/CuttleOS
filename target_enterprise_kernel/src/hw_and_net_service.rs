//! Kernel submodule.

pub(crate) use crate::*;

/// TASK-104/105 — hardware-truth virtio-blk via real PCI + BAR I/O.
///
/// Unlike `banner_virtio_blk` (MemVirtioBlkBus emulator), this:
/// 1. Issues real `out`/`in` against 0xCF8/0xCFC to find VirtIO blk
/// 2. Enables I/O space in the PCI command register
/// 3. Reads **capacity** from the legacy virtio-pci device config
///    window at BAR0+0x14/0x18 (after the 20-byte common header) —
///    a real I/O-port access into QEMU's virtio-blk model, not MemBus
///
/// Banners:
///   `VIRTIO_HW probe OK blk=found slot=N bar0=0x…`
///   `VIRTIO_HW io OK capacity=2048`   (1 MiB image / 512 B sectors)
///
/// TASK-107: after capacity, runs a real legacy virtqueue write+read
/// of sector 0 (pattern 0xA5^i) against QEMU — not MemBus.
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_BLK_TRANSITIONAL: u16 = 0x1001;
    const VIRTIO_BLK_MODERN: u16 = 0x1042;
    /// PCI command bit 0: I/O Space enable.
    const PCI_COMMAND_IO: u32 = 1;
    /// Legacy virtio-pci: device-specific config starts at BAR0+20.
    const VIRTIO_PCI_CONFIG: u16 = 20;
    /// Legacy device_status register offset in I/O BAR.
    const VIRTIO_PCI_STATUS: u16 = 18;
    /// Expected sectors for tools' 1 MiB `virtio_hw.img` (512 B/sec).
    const EXPECTED_CAPACITY: u64 = (1024 * 1024) / 512;

    let mut bus = RealPciBus;
    let mut found_slot: Option<u8> = None;
    let mut found_dev: u16 = 0;
    let mut found_bar0: u32 = 0;
    let mut found_addr: Option<PciAddress> = None;
    let mut bar_is_io = false;

    // Bus 0 only — QEMU default root bus places virtio-blk-pci here.
    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == VIRTIO_VENDOR
            && (dev_id == VIRTIO_BLK_TRANSITIONAL || dev_id == VIRTIO_BLK_MODERN)
        {
            found_slot = Some(device);
            found_dev = dev_id;
            found_addr = Some(addr);
            match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Io(p)) => {
                    found_bar0 = p;
                    bar_is_io = true;
                }
                Ok(PciBar::Mmio32(p)) => {
                    found_bar0 = p;
                    bar_is_io = false;
                }
                Ok(PciBar::Mmio64(p)) => {
                    found_bar0 = p as u32;
                    bar_is_io = false;
                }
                Err(_) => found_bar0 = 0,
            }
            break;
        }
        device = device.wrapping_add(1);
    }

    let slot = match found_slot {
        Some(s) => s,
        None => panic!("VIRTIO_HW: no virtio-blk on bus 0 (attach -device virtio-blk-pci)"),
    };
    let addr = match found_addr {
        Some(a) => a,
        None => panic!("VIRTIO_HW: missing addr"),
    };
    if found_dev == 0 || found_bar0 == 0 {
        panic!("VIRTIO_HW: device id or BAR0 zero");
    }

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_HW probe OK blk=found slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(slot as u64, &mut line[pos..]);
        let mid = b" bar0=0x";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let be = found_bar0.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&be, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ---- TASK-105: real device-config capacity read ----
    // Enable I/O (+ bus master) so the legacy BAR is live.
    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    let new_cmd = cmd | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER;
    PciConfigBus::write_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS, new_cmd);

    let capacity = if bar_is_io {
        let base = found_bar0 as u16;
        // Reset + ACK|DRIVER so config space is active (legacy path).
        // SAFETY: Writing legacy virtio-pci status register at BAR0 + 18 over I/O port space.
        unsafe {
            outb(base + VIRTIO_PCI_STATUS, 0);
            outb(base + VIRTIO_PCI_STATUS, 1); // ACKNOWLEDGE
            outb(base + VIRTIO_PCI_STATUS, 3); // ACK | DRIVER
        }
        // capacity is u64 LE at device-config offset 0 → BAR+20.
        // SAFETY: Reading legacy virtio-blk capacity dwords from BAR0 + 20 and BAR0 + 24.
        let lo = unsafe { inl(base + VIRTIO_PCI_CONFIG) };
        // SAFETY: Reading upper 32 bits of capacity from BAR0 + 24.
        let hi = unsafe { inl(base + VIRTIO_PCI_CONFIG + 4) };
        ((hi as u64) << 32) | (lo as u64)
    } else {
        // MMIO BAR (modern layout residual): try volatile capacity at
        // device-cfg via common offset only if identity-mapped; if not,
        // fail loud — we attach legacy-capable virtio-blk-pci.
        panic!("VIRTIO_HW: BAR0 is MMIO; expect legacy I/O BAR for capacity gate");
    };

    if capacity == 0 {
        panic!("VIRTIO_HW: capacity read returned 0");
    }
    if capacity != EXPECTED_CAPACITY {
        panic!("VIRTIO_HW: capacity drift vs 1MiB virtio_hw.img");
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_HW io OK capacity=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(capacity, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ---- TASK-107: real virtqueue sector write + read ----
    if !bar_is_io {
        panic!("VIRTIO_HW sector: need legacy I/O BAR");
    }
    if phys_map_offset() == 0 {
        panic!("VIRTIO_HW sector: physical_memory_offset missing");
    }
    if dma_phys_base() == 0 {
        panic!("VIRTIO_HW sector: no usable DMA region");
    }
    let first = virtio_legacy_sector_roundtrip(found_bar0 as u16);
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_HW sector OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&[first], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TASK-109/111 — hardware-truth virtio-net: PCI probe + MAC + real
/// TX/RX virtqueues (legacy QUEUE_PFN). Not MemVirtioBus.
///
/// QEMU attaches **two** legacy virtio-net-pci devices on the same
/// hub (`hubport`) so a TX on peer B is delivered as RX on peer A —
/// pure in-guest loopback, no host inject race.
///
/// Banners:
///   `VIRTIO_NET_HW probe OK slot=N mac=…`  (RX peer)
///   `VIRTIO_NET_HW tx OK bytes=76`         (12-byte hdr + 64-byte eth)
///   `VIRTIO_NET_HW rx OK bytes=N`          (used.len from RX virtqueue)
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_net_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000;
    const VIRTIO_NET_MODERN: u16 = 0x1041;
    const PCI_COMMAND_IO: u32 = 1;
    const VIRTIO_PCI_STATUS: u16 = 18;
    const VIRTIO_PCI_CONFIG: u16 = 20;

    struct NetDev {
        slot: u8,
        bar0: u16,
        mac: [u8; 6],
    }

    let mut bus = RealPciBus;
    let mut peers: [Option<NetDev>; 2] = [None, None];
    let mut nfound = 0usize;

    let mut device: u8 = 0;
    while device < 32 && nfound < 2 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == VIRTIO_VENDOR
            && (dev_id == VIRTIO_NET_TRANSITIONAL || dev_id == VIRTIO_NET_MODERN)
        {
            let (bar0, bar_is_io) = match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Io(p)) => (p, true),
                Ok(PciBar::Mmio32(p)) => (p, false),
                Ok(PciBar::Mmio64(p)) => (p as u32, false),
                Err(_) => (0, false),
            };
            if bar0 == 0 || !bar_is_io {
                panic!("VIRTIO_NET_HW: need legacy I/O BAR");
            }
            let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
            PciConfigBus::write_dword(
                &mut bus,
                addr,
                PCI_CFG_OFFSET_COMMAND_STATUS,
                cmd | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER,
            );
            let base = bar0 as u16;
            let mut mac = [0u8; 6];
            // SAFETY: Resetting legacy virtio-net status port and reading the 6-byte MAC from BAR0 + 20..26.
            unsafe {
                outb(base + VIRTIO_PCI_STATUS, 0);
                outb(base + VIRTIO_PCI_STATUS, 1);
                outb(base + VIRTIO_PCI_STATUS, 3);
                let mut i = 0usize;
                while i < 6 {
                    mac[i] = inb(base + VIRTIO_PCI_CONFIG + i as u16);
                    i += 1;
                }
            }
            if mac[0] == 0 && mac[1] == 0 && mac[2] == 0 {
                panic!("VIRTIO_NET_HW: MAC all zeros");
            }
            peers[nfound] = Some(NetDev {
                slot: device,
                bar0: base,
                mac,
            });
            nfound += 1;
            let _ = addr;
        }
        device = device.wrapping_add(1);
    }

    if nfound < 2 {
        panic!("VIRTIO_NET_HW: need two hubport virtio-net devices");
    }
    if phys_map_offset() == 0 || dma_phys_base() == 0 {
        panic!("VIRTIO_NET_HW: DMA map missing");
    }

    let rx = peers[0].as_ref().unwrap();
    let tx = peers[1].as_ref().unwrap();

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET_HW probe OK slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rx.slot as u64, &mut line[pos..]);
        let mid = b" mac=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 12];
        hex_encode(&rx.mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let (tx_bytes, rx_bytes) = virtio_legacy_net_hub_roundtrip(rx.bar0, tx.bar0, &tx.mac);

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET_HW tx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(tx_bytes as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET_HW rx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rx_bytes as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// DMA layout for hub TX→RX (qsz=256 → used ring @ +0x2000, region 0x3000):
///   [0x0000) RX peer queue 0 (live RX)
///   [0x3000) RX peer queue 1 (empty TX placeholder)
///   [0x6000) TX peer queue 0 (empty RX placeholder)
///   [0x9000) TX peer queue 1 (live TX)
///   [0xC000) RX buffer (2 KiB)
///   [0xC800) TX frame (hdr+eth)
///
/// Returns (tx_bytes, rx_used_len).
pub(crate) fn virtio_legacy_net_hub_roundtrip(rx_io: u16, tx_io: u16, tx_mac: &[u8; 6]) -> (usize, usize) {
    use core::sync::atomic::{fence, Ordering};

    const Q_RX: u16 = 0;
    const Q_TX: u16 = 1;
    const HDR: usize = 12;
    const FRAME: usize = 64;
    const TOTAL: usize = HDR + FRAME;
    const RX_BUF_LEN: u32 = 2048;
    /// Payload magic at eth offset 14 (after dst/src/etype) — proves real delivery.
    const MAGIC: &[u8; 8] = b"PNETRX01";

    let dma = dma_phys_base();
    let rx_q_pa = dma; // RX peer RX queue
    let rx_dummy_tx_q_pa = dma + 0x3000;
    let tx_dummy_rx_q_pa = dma + 0x6000;
    let tx_q_pa = dma + 0x9000;
    let rx_buf_pa = dma + 0xC000;
    let tx_frame_pa = dma + 0xC800;

    // Zero DMA window (queues + buffers); needs full 64 KiB map.
    // SAFETY: `dma..dma+0xD000` lies within the reserved DMA RAM region mapped via `pa_to_va`.
    unsafe {
        let base = pa_to_va(dma);
        let mut i = 0usize;
        while i < 0xD000 {
            core::ptr::write_volatile(base.add(i), 0);
            i += 1;
        }
        // Poison RX buffer so overwrite is visible.
        let rb = pa_to_va(rx_buf_pa);
        i = 0;
        while i < RX_BUF_LEN as usize {
            core::ptr::write_volatile(rb.add(i), 0xEE);
            i += 1;
        }
        // Build TX frame: virtio_net_hdr + eth broadcast + magic payload.
        let f = pa_to_va(tx_frame_pa);
        i = 0;
        while i < HDR {
            core::ptr::write_volatile(f.add(i), 0);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(f.add(HDR + i), 0xff);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(f.add(HDR + 6 + i), tx_mac[i]);
            i += 1;
        }
        core::ptr::write_volatile(f.add(HDR + 12), 0x88);
        core::ptr::write_volatile(f.add(HDR + 13), 0xB5);
        i = 0;
        while i < MAGIC.len() {
            core::ptr::write_volatile(f.add(HDR + 14 + i), MAGIC[i]);
            i += 1;
        }
    }

    let avail_off = (VQ_SIZE as u64) * 16;
    let used_off = {
        let raw = avail_off + 4 + 2 * (VQ_SIZE as u64);
        (raw + VQ_ALIGN - 1) & !(VQ_ALIGN - 1)
    };

    // ---- RX peer: post one device-writable buffer on queue 0 ----
    // SAFETY: Programming legacy virtio-net RX peer I/O ports (`rx_io`) in ring 0.
    unsafe {
        outb(rx_io + 18, 0);
        outb(rx_io + 18, 1);
        outb(rx_io + 18, 3);
        outl(rx_io + 4, 0);
        // Queue 0 = RX
        outw(rx_io + 14, Q_RX);
        let qsz = inw(rx_io + 12);
        if qsz != VQ_SIZE {
            panic!("VIRTIO_NET_HW: RX peer qsz");
        }
        outl(rx_io + 8, (rx_q_pa >> 12) as u32);
        // Queue 1 = TX (empty avail — not used on RX peer)
        outw(rx_io + 14, Q_TX);
        let qsz_tx = inw(rx_io + 12);
        if qsz_tx != VQ_SIZE {
            panic!("VIRTIO_NET_HW: RX peer TX qsz");
        }
        // Valid empty queue region; leave avail.idx=0.
        outl(rx_io + 8, (rx_dummy_tx_q_pa >> 12) as u32);
    }
    let rx_q = pa_to_va(rx_q_pa);
    // VRING_DESC_F_WRITE = 2
    write_desc_phys(rx_q, 0, rx_buf_pa, RX_BUF_LEN, 2, 0);
    // SAFETY: Writing avail ring slot 0 and avail.idx = 1 inside the mapped `rx_q` virtqueue page.
    unsafe {
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 4), 0);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 5), 0);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 2), 1);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 3), 0);
    }
    fence(Ordering::SeqCst);
    // SAFETY: Setting DRIVER_OK and kicking RX queue 0 on `rx_io`.
    unsafe {
        outb(rx_io + 18, 1 | 2 | 4); // DRIVER_OK
        outw(rx_io + 16, Q_RX); // kick RX with buffer available
    }

    // ---- TX peer: send one frame on queue 1 ----
    // SAFETY: Programming legacy virtio-net TX peer I/O ports (`tx_io`) in ring 0.
    unsafe {
        outb(tx_io + 18, 0);
        outb(tx_io + 18, 1);
        outb(tx_io + 18, 3);
        outl(tx_io + 4, 0);
        outw(tx_io + 14, Q_RX);
        let qsz = inw(tx_io + 12);
        if qsz != VQ_SIZE {
            panic!("VIRTIO_NET_HW: TX peer RX qsz");
        }
        outl(tx_io + 8, (tx_dummy_rx_q_pa >> 12) as u32);
        outw(tx_io + 14, Q_TX);
        let qsz2 = inw(tx_io + 12);
        if qsz2 != VQ_SIZE {
            panic!("VIRTIO_NET_HW: TX peer TX qsz");
        }
        outl(tx_io + 8, (tx_q_pa >> 12) as u32);
        outb(tx_io + 18, 1 | 2 | 4);
    }
    let tx_q = pa_to_va(tx_q_pa);
    write_desc_phys(tx_q, 0, tx_frame_pa, TOTAL as u32, 0, 0);
    // SAFETY: Writing avail ring slot 0 and avail.idx = 1 inside the mapped `tx_q` virtqueue page.
    unsafe {
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 4), 0);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 5), 0);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 2), 1);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 3), 0);
    }
    fence(Ordering::SeqCst);
    // SAFETY: Kicking TX queue 1 on `tx_io` notify port (`tx_io + 16`).
    unsafe {
        outw(tx_io + 16, Q_TX);
    }

    // Wait TX completion.
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        // SAFETY: Reading volatile 16-bit used.idx from the mapped `tx_q` virtqueue page.
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(tx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(tx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == 1 {
            break;
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            panic!("VIRTIO_NET_HW: TX completion timeout");
        }
        core::hint::spin_loop();
    }

    // Wait RX completion (hub delivers TX frame to peer).
    spins = 0;
    let rx_len = loop {
        fence(Ordering::SeqCst);
        // SAFETY: Reading volatile 16-bit used.idx from the mapped `rx_q` virtqueue page.
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == 1 {
            // used.ring[0].len at used_off + 4 + 4 (id u32, len u32)
            // SAFETY: Reading volatile 32-bit used.ring[0].len from the mapped `rx_q` virtqueue page.
            break unsafe {
                let p = rx_q.add(used_off as usize + 8);
                let b0 = core::ptr::read_volatile(p);
                let b1 = core::ptr::read_volatile(p.add(1));
                let b2 = core::ptr::read_volatile(p.add(2));
                let b3 = core::ptr::read_volatile(p.add(3));
                u32::from_le_bytes([b0, b1, b2, b3])
            };
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            panic!("VIRTIO_NET_HW: RX completion timeout");
        }
        core::hint::spin_loop();
    };

    if rx_len < (10 + 14 + MAGIC.len()) as u32 {
        panic!("VIRTIO_NET_HW: RX frame too short");
    }

    // Search for magic in received buffer (after virtio_net_hdr 10 or 12).
    // SAFETY: `rx_buf_pa` is a 2048-byte buffer in the mapped DMA region and `max <= RX_BUF_LEN`.
    let found = unsafe {
        let rb = pa_to_va(rx_buf_pa);
        let max = (rx_len as usize).min(RX_BUF_LEN as usize);
        let mut ok = false;
        let mut off = 0usize;
        while off + MAGIC.len() <= max {
            let mut m = 0usize;
            let mut match_ok = true;
            while m < MAGIC.len() {
                if core::ptr::read_volatile(rb.add(off + m)) != MAGIC[m] {
                    match_ok = false;
                    break;
                }
                m += 1;
            }
            if match_ok {
                ok = true;
                break;
            }
            off += 1;
        }
        ok
    };
    if !found {
        panic!("VIRTIO_NET_HW: RX magic missing (hub deliver failed)");
    }

    (TOTAL, rx_len as usize)
}

// ---------------------------------------------------------------------------
// TASK-113: real AHCI HBA under QEMU (PCI + MMIO + ATA IDENTIFY)
// Not MemBus — PCI class 01:06:01, ABAR MMIO, port command engine.
// ---------------------------------------------------------------------------

// Banners:
//   `AHCI_HW probe OK slot=N abar=0x… pi=0x…`
//   `AHCI_HW identify OK sectors=2048`
//   `AHCI_HW sector OK first_byte=5a`  (TASK-117 WRITE+READ DMA)
// ---------------------------------------------------------------------------
// Shared AHCI hardware port — probe, engine start, and single-slot sector I/O
// against the QEMU `ahci` device + ide-hd. Factored out of banner_ahci_hw so
// the continuity banner can persist the WAL to real disk across morph boots
// without duplicating 400 lines of MMIO setup.
// ---------------------------------------------------------------------------
#[allow(dead_code)]
pub(crate) struct AhciHwPort {
    pub(crate) abar: u64,
    pub(crate) pbase: u64,
    pub(crate) clb_pa: u64,
    pub(crate) ctba_pa: u64,
    pub(crate) data_pa: u64,
    pub(crate) slot: u8,
}

impl AhciHwPort {
    /// PCI scan for the AHCI HBA, enable MMIO + bus mastering, start the
    /// port command engine on the first port with a device present.
    pub(crate) fn probe_start() -> Self {
        use proteus_contracts::{
            pci_class, Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_CLASS_REVISION,
            PCI_CFG_OFFSET_COMMAND_STATUS, PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
        };
        use target_enterprise::pci::PciImpl;

        const PCI_COMMAND_MEMORY: u32 = 1 << 1;
        const PROG_IF_AHCI: u8 = 0x01;
        const REG_CAP: u64 = 0x00;
        const REG_GHC: u64 = 0x04;
        const REG_PI: u64 = 0x0C;
        const REG_VS: u64 = 0x10;
        const PORT_CLB: u64 = 0x00;
        const PORT_CLBU: u64 = 0x04;
        const PORT_FB: u64 = 0x08;
        const PORT_FBU: u64 = 0x0C;
        const PORT_IS: u64 = 0x10;
        const PORT_CMD: u64 = 0x18;
        const PORT_SSTS: u64 = 0x28;
        const PORT_SERR: u64 = 0x30;
        const PX_CMD_ST: u32 = 1;
        const PX_CMD_FRE: u32 = 1 << 4;
        const PX_CMD_FR: u32 = 1 << 14;
        const PX_CMD_CR: u32 = 1 << 15;
        const GHC_AE: u32 = 1 << 31;

        if phys_map_offset() == 0 || dma_phys_base() == 0 {
            panic!("AHCI_HW: DMA / phys map missing");
        }
        let mut bus = RealPciBus;
        let mut found_slot: Option<u8> = None;
        let mut found_addr: Option<PciAddress> = None;
        let mut abar: u64 = 0;
        let mut device: u8 = 0;
        while device < 32 {
            let addr = PciAddress { bus: 0, device, function: 0 };
            let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
            if (id & 0xFFFF) == 0xFFFF {
                device = device.wrapping_add(1);
                continue;
            }
            let class_dw = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_CLASS_REVISION);
            let class_code = (class_dw >> 24) as u8;
            let subclass = (class_dw >> 16) as u8;
            let prog_if = (class_dw >> 8) as u8;
            if class_code == pci_class::CLASS_MASS_STORAGE
                && subclass == pci_class::SUBCLASS_SATA
                && prog_if == PROG_IF_AHCI
            {
                let bar = match PciImpl::read_bar(&mut bus, addr, 5) {
                    Ok(PciBar::Mmio32(p)) => p as u64,
                    Ok(PciBar::Mmio64(p)) => p,
                    Ok(PciBar::Io(_)) | Err(_) => 0,
                };
                let bar = if bar == 0 {
                    match PciImpl::read_bar(&mut bus, addr, 0) {
                        Ok(PciBar::Mmio32(p)) => p as u64,
                        Ok(PciBar::Mmio64(p)) => p,
                        _ => 0,
                    }
                } else {
                    bar
                };
                if bar != 0 {
                    found_slot = Some(device);
                    found_addr = Some(addr);
                    abar = bar;
                    break;
                }
            }
            device = device.wrapping_add(1);
        }
        let slot = match found_slot {
            Some(s) => s,
            None => panic!("AHCI_HW: no AHCI HBA on bus 0 (attach -device ahci)"),
        };
        let addr = match found_addr {
            Some(a) => a,
            None => panic!("AHCI_HW: missing addr"),
        };
        let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
        PciConfigBus::write_dword(
            &mut bus,
            addr,
            PCI_CFG_OFFSET_COMMAND_STATUS,
            cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
        );
        // SAFETY: Enabling AHCI mode (GHC.AE) in the HBA's ABAR MMIO register space.
        unsafe {
            let ghc = mmio_read32(abar + REG_GHC);
            mmio_write32(abar + REG_GHC, ghc | GHC_AE);
        }
        // SAFETY: Reading HBA capabilities (CAP) from ABAR + 0x00.
        let cap = unsafe { mmio_read32(abar + REG_CAP) };
        // SAFETY: Reading ports-implemented bitmask (PI) from ABAR + 0x0C.
        let pi = unsafe { mmio_read32(abar + REG_PI) };
        // SAFETY: Reading AHCI version register (VS) from ABAR + 0x10.
        let vs = unsafe { mmio_read32(abar + REG_VS) };
        if cap == 0 || cap == 0xFFFF_FFFF {
            panic!("AHCI_HW: CAP read failed (MMIO map?)");
        }
        if pi == 0 {
            panic!("AHCI_HW: no ports implemented");
        }
        if vs == 0 {
            panic!("AHCI_HW: version register zero");
        }
        {
            let mut line = [0u8; 80];
            let mut pos = 0usize;
            let prefix = b"AHCI_HW probe OK slot=";
            line[..prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            pos += dec_u64(slot as u64, &mut line[pos..]);
            let mid = b" abar=0x";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            let be = (abar as u32).to_be_bytes();
            let mut hex = [0u8; 8];
            hex_encode(&be, 4, &mut hex);
            line[pos..pos + 8].copy_from_slice(&hex);
            pos += 8;
            let mid2 = b" pi=0x";
            line[pos..pos + mid2.len()].copy_from_slice(mid2);
            pos += mid2.len();
            let pibe = pi.to_be_bytes();
            hex_encode(&pibe, 4, &mut hex);
            line[pos..pos + 8].copy_from_slice(&hex);
            pos += 8;
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }

        // First implemented port with device present (SSTS.DET == 3).
        let mut port: Option<u32> = None;
        let mut p = 0u32;
        while p < 32 {
            if (pi & (1u32 << p)) != 0 {
                let pbase = abar + 0x100 + (p as u64) * 0x80;
                // SAFETY: Reading port SATA status register (PxSSTS) from valid port MMIO base `pbase`.
                let ssts = unsafe { mmio_read32(pbase + PORT_SSTS) };
                if (ssts & 0xF) == 3 {
                    port = Some(p);
                    break;
                }
            }
            p += 1;
        }
        let port = match port {
            Some(p) => p,
            None => panic!("AHCI_HW: no port with device present"),
        };
        let pbase = abar + 0x100 + (port as u64) * 0x80;

        let dma = dma_phys_base();
        let clb_pa = dma; // 1 KiB aligned
        let fb_pa = dma + 0x0400; // 256 B aligned
        let ctba_pa = dma + 0x0800; // 128 B aligned
        let data_pa = dma + 0x1000;

        // SAFETY: Zeroing the reserved AHCI DMA window (`dma..dma+0x1400`) and programming port CLB/FB/CMD MMIO registers.
        unsafe {
            let base = pa_to_va(dma);
            let mut i = 0usize;
            while i < 0x1400 {
                core::ptr::write_volatile(base.add(i), 0);
                i += 1;
            }
            let mut c = mmio_read32(pbase + PORT_CMD);
            c &= !(PX_CMD_ST | PX_CMD_FRE);
            mmio_write32(pbase + PORT_CMD, c);
            let mut spins = 0u32;
            loop {
                let c2 = mmio_read32(pbase + PORT_CMD);
                if c2 & (PX_CMD_CR | PX_CMD_FR) == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: port stop timeout");
                }
                core::hint::spin_loop();
            }
            mmio_write32(pbase + PORT_CLB, clb_pa as u32);
            mmio_write32(pbase + PORT_CLBU, (clb_pa >> 32) as u32);
            mmio_write32(pbase + PORT_FB, fb_pa as u32);
            mmio_write32(pbase + PORT_FBU, (fb_pa >> 32) as u32);
            mmio_write32(pbase + PORT_SERR, 0xFFFF_FFFF);
            mmio_write32(pbase + PORT_IS, 0xFFFF_FFFF);
            let mut c = mmio_read32(pbase + PORT_CMD);
            c |= PX_CMD_FRE;
            mmio_write32(pbase + PORT_CMD, c);
            spins = 0;
            loop {
                if mmio_read32(pbase + PORT_CMD) & PX_CMD_FR != 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: FRE start timeout");
                }
                core::hint::spin_loop();
            }
            c = mmio_read32(pbase + PORT_CMD);
            c |= PX_CMD_ST;
            mmio_write32(pbase + PORT_CMD, c);
        }

        AhciHwPort {
            abar,
            pbase,
            clb_pa,
            ctba_pa,
            data_pa,
            slot,
        }
    }

    /// Issue one H2D command in slot 0 against the running port.
    pub(crate) fn issue(&self, fis_params: &proteus_contracts::H2dFisParams, write: bool, tag: &[u8]) {
        use proteus_contracts::{
            AhciCmd, AhciCmdHeader, AhciFis, AhciPrdt, AHCI_CFL_H2D, AHCI_CMD_HDR_LEN,
            AHCI_FIS_H2D_LEN, AHCI_PRDT_LEN,
        };
        use target_enterprise::ahci_cmd::AhciCmdImpl;
        use target_enterprise::ahci_fis::AhciFisImpl;

        const PORT_IS: u64 = 0x10;
        const PORT_TFD: u64 = 0x20;
        const PORT_CI: u64 = 0x38;

        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        if AhciFisImpl::encode_h2d(fis_params, &mut fis).is_err() {
            panic!("AHCI_HW: FIS encode");
        }
        let hdr = AhciCmdHeader {
            cfl: AHCI_CFL_H2D,
            write,
            pmp: 0,
            prdtl: 1,
            prdbc: 0,
            ctba: self.ctba_pa,
        };
        let prdt = AhciPrdt {
            dba: self.data_pa,
            byte_count: 512,
            ioc: true,
        };
        let mut hbuf = [0u8; AHCI_CMD_HDR_LEN];
        let mut pbuf = [0u8; AHCI_PRDT_LEN];
        if AhciCmdImpl::encode_header(&hdr, &mut hbuf).is_err()
            || AhciCmdImpl::encode_prdt(&prdt, &mut pbuf).is_err()
        {
            panic!("AHCI_HW: header/PRDT encode");
        }
        // SAFETY: Writing FIS, PRDT, and command header into mapped DMA buffers (`ctba_pa`, `clb_pa`) and ringing PxCI slot 0.
        unsafe {
            let ct = pa_to_va(self.ctba_pa);
            let mut i = 0usize;
            while i < 0x100 {
                core::ptr::write_volatile(ct.add(i), 0);
                i += 1;
            }
            i = 0;
            while i < AHCI_FIS_H2D_LEN {
                core::ptr::write_volatile(ct.add(i), fis[i]);
                i += 1;
            }
            i = 0;
            while i < AHCI_PRDT_LEN {
                core::ptr::write_volatile(ct.add(0x80 + i), pbuf[i]);
                i += 1;
            }
            let cl = pa_to_va(self.clb_pa);
            i = 0;
            while i < AHCI_CMD_HDR_LEN {
                core::ptr::write_volatile(cl.add(i), hbuf[i]);
                i += 1;
            }
            let mut spins = 0u32;
            loop {
                let tfd = mmio_read32(self.pbase + PORT_TFD);
                if tfd & 0x80 == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: TFD BSY timeout");
                }
                core::hint::spin_loop();
            }
            mmio_write32(self.pbase + PORT_IS, 0xFFFF_FFFF);
            mmio_write32(self.pbase + PORT_CI, 1);
            spins = 0;
            loop {
                if mmio_read32(self.pbase + PORT_CI) & 1 == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 40_000_000 {
                    let _ = tag;
                    panic!("AHCI_HW: command CI timeout");
                }
                core::hint::spin_loop();
            }
            let tfd = mmio_read32(self.pbase + PORT_TFD);
            if tfd & 0x01 != 0 {
                let _ = tag;
                panic!("AHCI_HW: command TFD ERR");
            }
        }
    }

    /// Read the DMA data buffer back into a 512-byte array.
    pub(crate) fn drain_data(&self) -> [u8; 512] {
        let mut out = [0u8; 512];
        // SAFETY: `self.data_pa` points to a 512-byte sector buffer in the reserved DMA window.
        unsafe {
            let d = pa_to_va(self.data_pa);
            let mut i = 0usize;
            while i < 512 {
                out[i] = core::ptr::read_volatile(d.add(i));
                i += 1;
            }
        }
        out
    }

    /// Fill the DMA data buffer from a 512-byte array.
    pub(crate) fn fill_data(&self, src: &[u8; 512]) {
        // SAFETY: `self.data_pa` points to a 512-byte sector buffer in the reserved DMA window.
        unsafe {
            let d = pa_to_va(self.data_pa);
            let mut i = 0usize;
            while i < 512 {
                core::ptr::write_volatile(d.add(i), src[i]);
                i += 1;
            }
        }
    }

    /// ATA WRITE DMA one 512-byte sector at `lba`.
    pub(crate) fn write_sector(&self, lba: u64, data: &[u8; 512]) {
        use proteus_contracts::{H2dFisParams, ATA_DEV_LBA};
        const ATA_CMD_WRITE_DMA: u8 = 0xCA;
        self.fill_data(data);
        let wr = H2dFisParams {
            command: ATA_CMD_WRITE_DMA,
            features: 0,
            lba,
            count: 1,
            device: ATA_DEV_LBA,
            pm_port: 0,
            is_command: true,
        };
        self.issue(&wr, true, b"write");
    }

    /// ATA READ DMA one 512-byte sector at `lba`.
    pub(crate) fn read_sector(&self, lba: u64) -> [u8; 512] {
        use proteus_contracts::{AhciFis, ATA_CMD_READ_DMA};
        use target_enterprise::ahci_fis::AhciFisImpl;
        let rd = match AhciFisImpl::read_dma(lba, 1, 0) {
            Ok(p) => p,
            Err(_) => panic!("AHCI_HW: read_dma params"),
        };
        if rd.command != ATA_CMD_READ_DMA {
            panic!("AHCI_HW: read_dma opcode drift");
        }
        self.issue(&rd, false, b"read");
        self.drain_data()
    }
}

/// Banner: `AHCI_HW probe OK slot=N abar=… pi=…`, `AHCI_HW identify OK
/// sectors=2048`, `AHCI_HW sector OK first_byte=5a` (real PCI + MMIO +
/// IDENTIFY + sector DMA — TASK-113/117).
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_hw() {
    use proteus_contracts::{AhciFis, ATA_CMD_READ_DMA};
    use target_enterprise::ahci_fis::AhciFisImpl;

    /// 1 MiB `ahci_hw.img` → 2048 × 512 B sectors.
    const EXPECTED_SECTORS: u64 = (1024 * 1024) / 512;

    let port = AhciHwPort::probe_start();

    // IDENTIFY via contract helper.
    let fis_params = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI_HW: identify params"),
    };
    port.issue(&fis_params, false, b"identify");
    let data = port.drain_data();
    let mut all_zero = true;
    let mut i = 0usize;
    while i < 512 {
        if data[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    if all_zero {
        panic!("AHCI_HW: IDENTIFY buffer empty");
    }
    let w60 = u16::from_le_bytes([data[120], data[121]]) as u64;
    let w61 = u16::from_le_bytes([data[122], data[123]]) as u64;
    let lba28 = w60 | (w61 << 16);
    let w100 = u16::from_le_bytes([data[200], data[201]]) as u64;
    let w101 = u16::from_le_bytes([data[202], data[203]]) as u64;
    let w102 = u16::from_le_bytes([data[204], data[205]]) as u64;
    let w103 = u16::from_le_bytes([data[206], data[207]]) as u64;
    let lba48 = w100 | (w101 << 16) | (w102 << 32) | (w103 << 48);
    let sectors = if lba48 != 0 { lba48 } else { lba28 };
    if sectors != EXPECTED_SECTORS {
        panic!("AHCI_HW: sector count drift vs 1MiB ahci_hw.img");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"AHCI_HW identify OK sectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(sectors, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // WRITE DMA + READ DMA sector 0 (pattern 0x5A ^ i).
    let mut pattern = [0u8; 512];
    i = 0;
    while i < 512 {
        pattern[i] = 0x5Au8 ^ (i as u8);
        i += 1;
    }
    port.write_sector(0, &pattern);
    let rd = match AhciFisImpl::read_dma(0, 1, 0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI_HW: read_dma params"),
    };
    if rd.command != ATA_CMD_READ_DMA {
        panic!("AHCI_HW: read_dma opcode drift");
    }
    port.fill_data(&[0xEEu8; 512]);
    port.issue(&rd, false, b"read");
    let back = port.drain_data();
    let mut i2 = 0usize;
    while i2 < 512 {
        let want = 0x5Au8 ^ (i2 as u8);
        if back[i2] != want {
            panic!("AHCI_HW: sector data drift");
        }
        i2 += 1;
    }
    let first = back[0];

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"AHCI_HW sector OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hx = [0u8; 2];
        hex_encode(&[first], 1, &mut hx);
        line[pos] = hx[0];
        line[pos + 1] = hx[1];
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ---------------------------------------------------------------------------
// Cross-morph durable-state continuity (Class A of the cadence program).
//
// The theory: a morph cycle is a fast reboot. Durable state survives iff
// the on-disk format is part of the locked contract surface and the next
// kernel replays it. This banner proves it with the REAL WAL and REAL
// disk: a 9-sector region at LBA 1024 on the AHCI disk holds one header
// sector (magic, boot counter, durable cursor, region CRC) plus 8 sectors
// of WalImpl backing. Each boot:
//   1. reads the header; if magic + region CRC verify, reconstructs the
//      WAL via `WalImpl::from_backing` and replays it — this is the
//      "morphed kernel resumes prior durable state" moment;
//   2. appends one boot-marker frame (payload: boot counter + resumed
//      frame count), flushes (CapProof-gated like every durable write),
//      and writes the region + updated header back.
// Genesis (blank/corrupt region) starts a fresh WAL. A second boot —
// especially of a LAYOUT-MORPHED image — printing `CONTINUITY resume OK`
// with a strictly larger frame count is the cross-morph proof.
// ---------------------------------------------------------------------------

/// First LBA of the continuity region (header + 8 WAL sectors). Chosen
/// above the sectors exercised by other banners (sector 0) and below
/// the 2048-sector disk size.
pub(crate) const CONTINUITY_LBA: u64 = 1024;
pub(crate) const CONTINUITY_MAGIC: &[u8; 8] = b"PRTSWAL1";
pub(crate) const CONTINUITY_WAL_SECTORS: u64 = (kf::WAL_CAPACITY / 512) as u64;

#[inline(never)]
pub(crate) fn banner_continuity() {
    use target_enterprise::wal::crc32_ieee;

    let port = AhciHwPort::probe_start();

    // Read header sector.
    let hdr = port.read_sector(CONTINUITY_LBA);
    let mut wal_buf = [0u8; kf::WAL_CAPACITY];
    let mut resumed_boots: u64 = 0;
    let mut resumed_cursor: usize = 0;
    let mut is_resume = false;
    if hdr[..8] == CONTINUITY_MAGIC[..] {
        resumed_boots = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        resumed_cursor =
            u32::from_le_bytes(hdr[16..20].try_into().unwrap()) as usize;
        let want_crc = u32::from_le_bytes(hdr[20..24].try_into().unwrap());
        let mut s = 0u64;
        while s < CONTINUITY_WAL_SECTORS {
            let sec = port.read_sector(CONTINUITY_LBA + 1 + s);
            let off = (s as usize) * 512;
            wal_buf[off..off + 512].copy_from_slice(&sec);
            s += 1;
        }
        if crc32_ieee(&wal_buf) == want_crc && resumed_cursor <= kf::WAL_CAPACITY {
            is_resume = true;
        }
    }

    let mut wal: WalImpl<{ kf::WAL_CAPACITY }> = if is_resume {
        WalImpl::from_backing(wal_buf, resumed_cursor)
    } else {
        WalImpl::new()
    };

    // Replay the durable prefix: count frames and last LSN.
    let mut frames: u64 = 0;
    let mut last_lsn: u64 = 0;
    wal.replay(&mut |lsn, _payload| {
        frames += 1;
        if lsn <= last_lsn {
            panic!("CONTINUITY: replay LSN not monotonic");
        }
        last_lsn = lsn;
    });

    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        if is_resume {
            let prefix = b"CONTINUITY resume OK boots=";
            line[..prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            pos += dec_u64(resumed_boots, &mut line[pos..]);
        } else {
            let prefix = b"CONTINUITY genesis boots=";
            line[..prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            pos += dec_u64(0, &mut line[pos..]);
        }
        let mid = b" frames=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(frames, &mut line[pos..]);
        let mid2 = b" lsn=";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(last_lsn, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Append the boot-marker frame: payload = [boot counter, resumed
    // frame count] — each morph boot leaves an auditable trace.
    let this_boot = resumed_boots + 1;
    // Publish for the UDP status payload ("PROTEUS-STATUS boots=N").
    CONTINUITY_BOOT_COUNT.store(this_boot, core::sync::atomic::Ordering::Relaxed);
    let mut marker = [0u8; 16];
    marker[..8].copy_from_slice(&this_boot.to_le_bytes());
    marker[8..].copy_from_slice(&frames.to_le_bytes());
    if wal.append(&marker).is_err() {
        // WAL region full → CHECKPOINT: the header's boot counter is the
        // cross-morph continuity truth; the WAL region rotates. Start a
        // fresh WAL with a checkpoint marker carrying the boot count and
        // the pre-rotation frame count, so the on-disk journal always
        // opens with a boundary record. This is what lets cadence run
        // indefinitely (soak-tested at 1000+ cycles).
        let mut fresh: WalImpl<{ kf::WAL_CAPACITY }> = WalImpl::new();
        if fresh.append(&marker).is_err() {
            panic!("CONTINUITY: checkpoint marker append failed");
        }
        wal = fresh;
    }
    if wal
        .flush(target_enterprise::wal::durable_wal_proof_init())
        .is_err()
    {
        panic!("CONTINUITY: flush failed");
    }

    // Persist: WAL region sectors then header (header LAST so a crash
    // mid-write never presents a valid header over a stale region).
    let backing = wal.backing();
    let mut s = 0u64;
    while s < CONTINUITY_WAL_SECTORS {
        let off = (s as usize) * 512;
        let mut sec = [0u8; 512];
        sec.copy_from_slice(&backing[off..off + 512]);
        port.write_sector(CONTINUITY_LBA + 1 + s, &sec);
        s += 1;
    }
    let new_crc = crc32_ieee(backing);
    let mut hdr_out = [0u8; 512];
    hdr_out[..8].copy_from_slice(CONTINUITY_MAGIC);
    hdr_out[8..16].copy_from_slice(&this_boot.to_le_bytes());
    hdr_out[16..20].copy_from_slice(&(wal.durable_cursor() as u32).to_le_bytes());
    hdr_out[20..24].copy_from_slice(&new_crc.to_le_bytes());
    port.write_sector(CONTINUITY_LBA, &hdr_out);

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"CONTINUITY persist OK cursor=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(wal.durable_cursor() as u64, &mut line[pos..]);
        let mid = b" crc=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let be = new_crc.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&be, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ---------------------------------------------------------------------------
// Modern virtio-net driver (virtio 1.x, MMIO common-config) — ported
// from RustOSa's proven slirp-facing driver (src/virtio_net.rs). The
// legacy I/O-port path receives hub frames but is deaf on QEMU
// user-mode networking (slirp); the modern path is what RustOSa runs
// real DHCP/DNS/UDP over, so the service speaks modern when a
// 0x1041 device is present.
// ---------------------------------------------------------------------------

pub(crate) const VN_CC_FEATURE_SEL: usize = 0x00;
pub(crate) const VN_CC_FEATURE: usize = 0x04;
pub(crate) const VN_CC_DRV_FEATURE_SEL: usize = 0x08;
pub(crate) const VN_CC_DRV_FEATURE: usize = 0x0C;
pub(crate) const VN_CC_STATUS: usize = 0x14;
pub(crate) const VN_CC_QUEUE_SELECT: usize = 0x16;
pub(crate) const VN_CC_QUEUE_SIZE: usize = 0x18;
pub(crate) const VN_CC_QUEUE_ENABLE: usize = 0x1C;
pub(crate) const VN_CC_QUEUE_NOTIFY_OFF: usize = 0x1E;
pub(crate) const VN_CC_QUEUE_DESC: usize = 0x20;
pub(crate) const VN_CC_QUEUE_DRIVER: usize = 0x28;
pub(crate) const VN_CC_QUEUE_DEVICE: usize = 0x30;
pub(crate) const VN_QSIZE: u16 = 64;
pub(crate) const VN_RX_BUFFERS: usize = 8;
pub(crate) const VN_HDR: usize = 12;
pub(crate) const VN_RX_BUF: usize = 2048;
pub(crate) const VN_DESC_OFF: u64 = 0x000;
pub(crate) const VN_AVAIL_OFF: u64 = 0x400;
pub(crate) const VN_USED_OFF: u64 = 0x800;

#[allow(dead_code)]
pub(crate) struct VnetModern {
    pub(crate) common: u64,
    pub(crate) notify: u64,
    pub(crate) notify_mult: u32,
    pub(crate) rx_q_phys: u64,
    pub(crate) rx_q_virt: u64,
    pub(crate) tx_q_phys: u64,
    pub(crate) tx_q_virt: u64,
    pub(crate) rx_notify_off: u16,
    pub(crate) tx_notify_off: u16,
    pub(crate) rx_avail_next: u16,
    pub(crate) rx_used_seen: u16,
    pub(crate) tx_avail_next: u16,
    pub(crate) tx_used_seen: u16,
    pub(crate) mac: [u8; 6],
}

pub(crate) fn vn_rd8(v: u64, off: usize) -> u8 {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to a mapped virtio-net MMIO register or virtqueue byte.
    let val = unsafe { core::ptr::read_volatile((v + off as u64) as *const u8) };
    fence(Ordering::SeqCst);
    val
}
pub(crate) fn vn_rd16(v: u64, off: usize) -> u16 {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to a 2-byte aligned mapped virtio-net MMIO or virtqueue field.
    let val = unsafe { core::ptr::read_volatile((v + off as u64) as *const u16) };
    fence(Ordering::SeqCst);
    val
}
pub(crate) fn vn_rd32(v: u64, off: usize) -> u32 {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to a 4-byte aligned mapped virtio-net MMIO or virtqueue field.
    let val = unsafe { core::ptr::read_volatile((v + off as u64) as *const u32) };
    fence(Ordering::SeqCst);
    val
}
pub(crate) fn vn_wr8(v: u64, off: usize, x: u8) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to a mapped virtio-net MMIO register or virtqueue byte.
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u8, x) };
    fence(Ordering::SeqCst);
}
pub(crate) fn vn_wr16(v: u64, off: usize, x: u16) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to a 2-byte aligned mapped virtio-net MMIO or virtqueue field.
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u16, x) };
    fence(Ordering::SeqCst);
}
pub(crate) fn vn_wr32(v: u64, off: usize, x: u32) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to a 4-byte aligned mapped virtio-net MMIO or virtqueue field.
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u32, x) };
    fence(Ordering::SeqCst);
}
pub(crate) fn vn_wr64(v: u64, off: usize, x: u64) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    // SAFETY: `v + off` points to an 8-byte aligned mapped virtio-net MMIO or virtqueue field.
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u64, x) };
    fence(Ordering::SeqCst);
}

/// Find + init the first modern virtio-net (PCI device id 0x1041).
/// Returns None if absent or init fails (caller falls back / reports).
pub(crate) fn vnet_modern_init(dma: u64) -> Option<VnetModern> {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const PCI_COMMAND_MEMORY: u32 = 1 << 1;
    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_NET_MODERN: u16 = 0x1041;

    let mut bus = RealPciBus;
    let mut found: Option<(PciAddress, u64)> = None;
    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress { bus: 0, device, function: 0 };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        if (id & 0xFFFF) as u16 == VIRTIO_VENDOR && (id >> 16) as u16 == VIRTIO_NET_MODERN {
            let bar = match PciImpl::read_bar(&mut bus, addr, 4) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                _ => 0,
            };
            if bar == 0 {
                if let Ok(PciBar::Mmio32(p)) = PciImpl::read_bar(&mut bus, addr, 0) {
                    found = Some((addr, p as u64));
                    break;
                }
                if let Ok(PciBar::Mmio64(p)) = PciImpl::read_bar(&mut bus, addr, 0) {
                    found = Some((addr, p));
                    break;
                }
            } else {
                found = Some((addr, bar));
                break;
            }
        }
        device = device.wrapping_add(1);
    }
    let (addr, _bar_phys) = found?;

    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );

    // Walk the PCI capability list for virtio vendor caps (0x09):
    // cfg_type@3, bar@4, offset@8, length@12.
    let status = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    if (status >> 16) & 0x10 == 0 {
        return None; // no cap list
    }
    let mut cap_ptr =
        (PciConfigBus::read_dword(&mut bus, addr, 0x34) & 0xFF) as u8;
    let mut common: Option<(u64, u64)> = None; // (bar, offset)
    let mut notify: Option<(u64, u64)> = None;
    let mut notify_mult: u32 = 0;
    let mut device_cfg: Option<(u64, u64)> = None;
    let mut guard = 0;
    while cap_ptr != 0 && guard < 48 {
        let dw0 = PciConfigBus::read_dword(&mut bus, addr, cap_ptr);
        let cap_id = (dw0 & 0xFF) as u8;
        let next = ((dw0 >> 8) & 0xFF) as u8;
        if cap_id == 0x09 {
            let dw1 = PciConfigBus::read_dword(&mut bus, addr, cap_ptr + 4);
            let cfg_type = ((dw0 >> 24) & 0xFF) as u8;
            let bar_idx = (dw1 & 0xFF) as u8;
            let off = PciConfigBus::read_dword(&mut bus, addr, cap_ptr + 8) as u64;
            let cap_bar = match PciImpl::read_bar(&mut bus, addr, bar_idx) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                _ => 0,
            };
            if cap_bar != 0 {
                match cfg_type {
                    1 => common = Some((cap_bar, off)),
                    2 => {
                        notify = Some((cap_bar, off));
                        notify_mult =
                            PciConfigBus::read_dword(&mut bus, addr, cap_ptr + 16);
                    }
                    4 => device_cfg = Some((cap_bar, off)),
                    _ => {}
                }
            }
        }
        cap_ptr = next;
        guard += 1;
    }
    let (common_bar, common_off) = common?;
    let (notify_bar, notify_off) = notify?;
    let (devcfg_bar, devcfg_off) = device_cfg?;

    let phys_off = phys_map_offset();
    if phys_off == 0 {
        return None;
    }
    // SAFETY: Mapping the modern virtio-net common, notify, and device-cfg MMIO pages uncached in ring 0.
    unsafe {
        ensure_mmio_page(common_bar + common_off);
        ensure_mmio_page(notify_bar + notify_off);
        ensure_mmio_page(devcfg_bar + devcfg_off);
    }
    let common_virt = phys_off + common_bar + common_off;
    let notify_virt = phys_off + notify_bar + notify_off;
    let devcfg_virt = phys_off + devcfg_bar + devcfg_off;

    // Handshake: RESET → ACK → DRIVER → negotiate VERSION_1 → FEATURES_OK.
    vn_wr8(common_virt, VN_CC_STATUS, 0);
    let mut spins = 0u32;
    while vn_rd8(common_virt, VN_CC_STATUS) != 0 {
        spins += 1;
        if spins > 1_000_000 {
            return None;
        }
        core::hint::spin_loop();
    }
    vn_wr8(common_virt, VN_CC_STATUS, 1);
    vn_wr8(common_virt, VN_CC_STATUS, 3);
    vn_wr32(common_virt, VN_CC_FEATURE_SEL, 1);
    let feat_hi = vn_rd32(common_virt, VN_CC_FEATURE);
    if feat_hi & 0x1 == 0 {
        return None; // no VERSION_1
    }
    vn_wr32(common_virt, VN_CC_FEATURE_SEL, 0);
    let feat_lo = vn_rd32(common_virt, VN_CC_FEATURE);
    // Accept VERSION_1 always, plus MAC (bit 5) and STATUS (bit 16)
    // when offered — matching RustOSa. Without F_MAC the device may
    // drop unicast frames destined for the guest MAC (RX silence).
    let mut acc_lo: u32 = 0;
    if feat_lo & (1 << 5) != 0 {
        acc_lo |= 1 << 5;
    }
    if feat_lo & (1 << 16) != 0 {
        acc_lo |= 1 << 16;
    }
    vn_wr32(common_virt, VN_CC_DRV_FEATURE_SEL, 0);
    vn_wr32(common_virt, VN_CC_DRV_FEATURE, acc_lo);
    vn_wr32(common_virt, VN_CC_DRV_FEATURE_SEL, 1);
    vn_wr32(common_virt, VN_CC_DRV_FEATURE, 1); // VERSION_1
    vn_wr8(common_virt, VN_CC_STATUS, 1 | 2 | 8);
    if vn_rd8(common_virt, VN_CC_STATUS) & 8 == 0 {
        return None;
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = vn_rd8(devcfg_virt, i);
    }

    // Queue pages from the DMA window.
    let rx_q_phys = dma;
    let tx_q_phys = dma + 0x1000;
    let rx_bufs_phys = dma + 0x2000;
    let _tx_buf_phys = dma + 0xA000;
    // SAFETY: Zeroing the 48 KiB virtio-net modern queue/buffer window (`dma..dma+0xC000`) in mapped DMA RAM.
    unsafe {
        let b = pa_to_va(dma);
        let mut i = 0usize;
        while i < 0xC000 {
            core::ptr::write_volatile(b.add(i), 0);
            i += 1;
        }
    }

    // Program queues.
    vn_wr16(common_virt, VN_CC_QUEUE_SELECT, 0);
    if vn_rd16(common_virt, VN_CC_QUEUE_SIZE) < VN_QSIZE {
        return None;
    }
    vn_wr16(common_virt, VN_CC_QUEUE_SIZE, VN_QSIZE);
    vn_wr64(common_virt, VN_CC_QUEUE_DESC, rx_q_phys + VN_DESC_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DRIVER, rx_q_phys + VN_AVAIL_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DEVICE, rx_q_phys + VN_USED_OFF);
    let rx_notify_off = vn_rd16(common_virt, VN_CC_QUEUE_NOTIFY_OFF);
    vn_wr16(common_virt, VN_CC_QUEUE_ENABLE, 1);

    vn_wr16(common_virt, VN_CC_QUEUE_SELECT, 1);
    if vn_rd16(common_virt, VN_CC_QUEUE_SIZE) < VN_QSIZE {
        return None;
    }
    vn_wr16(common_virt, VN_CC_QUEUE_SIZE, VN_QSIZE);
    vn_wr64(common_virt, VN_CC_QUEUE_DESC, tx_q_phys + VN_DESC_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DRIVER, tx_q_phys + VN_AVAIL_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DEVICE, tx_q_phys + VN_USED_OFF);
    let tx_notify_off = vn_rd16(common_virt, VN_CC_QUEUE_NOTIFY_OFF);
    vn_wr16(common_virt, VN_CC_QUEUE_ENABLE, 1);

    // DRIVER_OK.
    vn_wr8(common_virt, VN_CC_STATUS, 1 | 2 | 8 | 4);
    if vn_rd8(common_virt, VN_CC_STATUS) & 128 != 0 {
        return None;
    }

    let rx_q_virt = pa_to_va(rx_q_phys) as u64;
    let tx_q_virt = pa_to_va(tx_q_phys) as u64;
    let rx_bufs_virt = pa_to_va(rx_bufs_phys) as u64;

    // Post VN_RX_BUFFERS RX buffers as 2-desc chains (hdr + payload).
    // SAFETY: Populating RX descriptor chains and avail ring slots in the mapped `rx_q_virt` virtqueue page.
    unsafe {
        core::ptr::write_volatile(
            (rx_q_virt + VN_AVAIL_OFF) as *mut u16,
            0u16, // avail flags
        );
        let mut i = 0usize;
        while i < VN_RX_BUFFERS {
            let hdr_p = rx_bufs_phys + (i as u64) * (VN_RX_BUF as u64);
            let data_p = hdr_p + 0x40;
            let head = (2 * i) as u16;
            // hdr desc (WRITE|NEXT)
            let d0 = rx_q_virt + VN_DESC_OFF + (2 * i as u64) * 16;
            vn_wr64(d0, 0, hdr_p);
            vn_wr32(d0, 8, VN_HDR as u32);
            vn_wr16(d0, 12, 1 | 2);
            vn_wr16(d0, 14, head + 1);
            // payload desc (WRITE)
            let d1 = rx_q_virt + VN_DESC_OFF + ((2 * i + 1) as u64) * 16;
            vn_wr64(d1, 0, data_p);
            vn_wr32(d1, 8, (VN_RX_BUF - 0x40) as u32);
            vn_wr16(d1, 12, 2);
            vn_wr16(d1, 14, 0);
            // avail ring slot i = head
            core::ptr::write_volatile(
                (rx_q_virt + VN_AVAIL_OFF + 4 + (i as u64) * 2) as *mut u16,
                head,
            );
            i += 1;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            (rx_q_virt + VN_AVAIL_OFF + 2) as *mut u16,
            VN_RX_BUFFERS as u16,
        );
    }
    let _ = rx_bufs_virt;

    let n = VnetModern {
        common: common_virt,
        notify: notify_virt,
        notify_mult,
        rx_q_phys,
        rx_q_virt,
        tx_q_phys,
        tx_q_virt,
        rx_notify_off,
        tx_notify_off,
        rx_avail_next: VN_RX_BUFFERS as u16,
        rx_used_seen: 0,
        tx_avail_next: 0,
        tx_used_seen: 0,
        mac,
    };
    // Kick RX so the device picks up the posted buffers (RustOSa does
    // this right after pre-posting; without it the device never starts
    // delivering and used stays 0 forever).
    vnet_notify(&n, 0);
    Some(n)
}

pub(crate) fn vnet_notify(n: &VnetModern, queue: u16) {
    let off = (if queue == 0 { n.rx_notify_off } else { n.tx_notify_off } as u64)
        .wrapping_mul(n.notify_mult as u64);
    // SAFETY: Writing queue index to the mapped modern virtio-net notify MMIO doorbell (`n.notify + off`).
    unsafe {
        core::ptr::write_volatile((n.notify + off) as *mut u16, queue);
    }
}

/// TX one Ethernet frame (2-desc chain, no wait — completion is
/// reaped lazily). Returns false if the ring bookkeeping misbehaves.
pub(crate) fn vnet_tx(n: &mut VnetModern, frame: &[u8]) -> bool {
    use core::sync::atomic::{fence, Ordering};
    let tx_buf_phys = n.tx_q_phys + 0x8000; // tx scratch: dma+0xA000
    let tx_buf_virt = pa_to_va(tx_buf_phys) as u64;
    // SAFETY: Copying frame into the mapped TX scratch buffer (`tx_buf_virt`) and updating TX descriptors/avail ring.
    unsafe {
        // hdr (12 zero bytes) + frame
        let mut i = 0usize;
        while i < VN_HDR {
            core::ptr::write_volatile((tx_buf_virt + i as u64) as *mut u8, 0);
            i += 1;
        }
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            (tx_buf_virt + VN_HDR as u64) as *mut u8,
            frame.len(),
        );
        let d0 = n.tx_q_virt + VN_DESC_OFF;
        vn_wr64(d0, 0, tx_buf_phys);
        vn_wr32(d0, 8, VN_HDR as u32);
        vn_wr16(d0, 12, 1); // NEXT
        vn_wr16(d0, 14, 1);
        let d1 = n.tx_q_virt + VN_DESC_OFF + 16;
        vn_wr64(d1, 0, tx_buf_phys + VN_HDR as u64);
        vn_wr32(d1, 8, frame.len() as u32);
        vn_wr16(d1, 12, 0);
        vn_wr16(d1, 14, 0);
        let slot = (n.tx_avail_next as u64) & (VN_QSIZE as u64 - 1);
        core::ptr::write_volatile(
            (n.tx_q_virt + VN_AVAIL_OFF + 4 + slot * 2) as *mut u16,
            0u16, // head desc 0
        );
        fence(Ordering::SeqCst);
        let next = n.tx_avail_next.wrapping_add(1);
        core::ptr::write_volatile((n.tx_q_virt + VN_AVAIL_OFF + 2) as *mut u16, next);
        n.tx_avail_next = next;
    }
    vnet_notify(n, 1);
    true
}

/// Poll one RX frame into `out`; returns (frame_len, hdr_buf_index) —
/// the caller recycles by calling vnet_rx_recycle(idx).
pub(crate) fn vnet_rx(n: &mut VnetModern, out: &mut [u8]) -> Option<(usize, u16)> {
    // SAFETY: Reading volatile 16-bit RX used.idx from the mapped `n.rx_q_virt` virtqueue page.
    let cur = unsafe { core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16) };
    if cur == n.rx_used_seen {
        return None;
    }
    let slot = (n.rx_used_seen as u64) & (VN_QSIZE as u64 - 1);
    // SAFETY: Reading volatile used.ring[slot].id from the mapped RX used ring.
    let id = unsafe {
        core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 4 + slot * 8) as *const u32)
    } as u16;
    // SAFETY: Reading volatile used.ring[slot].len from the mapped RX used ring.
    let len = unsafe {
        core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 4 + slot * 8 + 4) as *const u32)
    } as usize;
    n.rx_used_seen = n.rx_used_seen.wrapping_add(1);
    // head desc id → buffer index = id/2. Used len = virtio hdr (12)
    // + payload bytes; the frame lives at buf + 0x40 (hdr region is
    // the first 0x40 bytes of the buffer, payload follows).
    let bi = (id / 2) as u64;
    let data_virt = pa_to_va(n.rx_q_phys + 0x2000 + bi * (VN_RX_BUF as u64) + 0x40);
    let flen = len.saturating_sub(VN_HDR).min(out.len());
    // SAFETY: `data_virt` points to the mapped RX payload buffer in DMA RAM and `flen <= out.len()`.
    unsafe {
        core::ptr::copy_nonoverlapping(data_virt as *const u8, out.as_mut_ptr(), flen);
    }
    Some((flen, id))
}

/// Repost an RX buffer after consumption.
pub(crate) fn vnet_rx_recycle(n: &mut VnetModern, head_id: u16) {
    use core::sync::atomic::{fence, Ordering};
    // SAFETY: Returning `head_id` to the RX avail ring and advancing avail.idx in the mapped RX virtqueue page.
    unsafe {
        let slot = (n.rx_avail_next as u64) & (VN_QSIZE as u64 - 1);
        core::ptr::write_volatile(
            (n.rx_q_virt + VN_AVAIL_OFF + 4 + slot * 2) as *mut u16,
            head_id,
        );
        fence(Ordering::SeqCst);
        let next = n.rx_avail_next.wrapping_add(1);
        core::ptr::write_volatile((n.rx_q_virt + VN_AVAIL_OFF + 2) as *mut u16, next);
        n.rx_avail_next = next;
    }
    vnet_notify(n, 0);
}


//
// Design: static guest IP 10.0.2.15 on QEMU user-mode networking
// (-netdev user,hostfwd=udp::8080-:8080,hostfwd=tcp::80-:80).
// Polled virtqueue driver on the FIRST virtio-net device found.
// `LivedNet` answers ARP, ICMP echo, UDP/8080 status, and TCP/80
// HTTP GET /status|/healthz|/ with "PROTEUS-STATUS boots=N\n".
// Bounded loop: the service window is a boot-phase activity, then
// the kernel proceeds to HALT as usual.
// ---------------------------------------------------------------------------

/// Boot counter published by banner_continuity for the status payload.
pub(crate) static CONTINUITY_BOOT_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub(crate) const UDP_SVC_IP: [u8; 4] = [10, 0, 2, 15];
pub(crate) const UDP_SVC_PORT: u16 = 8080;
pub(crate) const UDP_SVC_VIRTIO_HDR: usize = 12;

pub(crate) fn derive_runtime_net_auth_key(mac: [u8; 6]) -> [u8; 32] {
    let variant_tag = option_env!("PROTEUS_VARIANT_SEED").unwrap_or("default-variant");
    let mut root = target_enterprise::lived_net::DEFAULT_NET_AUTH_KEY;
    let vb = variant_tag.as_bytes();
    let mut i = 0usize;
    while i < vb.len() {
        root[i & 31] ^= vb[i].wrapping_mul(0x9E).wrapping_add(i as u8);
        i += 1;
    }
    target_enterprise::lived_net::LivedNet::derive_node_key(&root, mac)
}

pub(crate) fn derive_runtime_seal_key() -> [u8; 32] {
    let variant_tag = option_env!("PROTEUS_VARIANT_SEED").unwrap_or("default-variant");
    target_enterprise::durable_seal::derive_seal_key(
        &target_enterprise::durable_seal::DEFAULT_DURABLE_SEAL_KEY,
        variant_tag.as_bytes(),
    )
}

pub(crate) fn service_udp_status() {
    // Modern driver first (slirp-proven); legacy I/O-port path as
    // fallback (works on hub topology, deaf on user-mode networking).
    let dma = dma_phys_base();
    if dma != 0 {
        if let Some(mut n) = vnet_modern_init(dma) {
            service_udp_status_modern(&mut n);
            return;
        }
    }
    service_udp_status_legacy();
}

/// Service loop over the modern virtio-net driver.
pub(crate) fn service_udp_status_modern(n: &mut VnetModern) {
    let mac = n.mac;
    let mut svc = target_enterprise::LivedNet::with_auth_key(mac, derive_runtime_net_auth_key(mac));
    serial_write_str("UDP SVC UP modern ip=10.0.2.15 port=8080\n");
    serial_write_str("NET SVC UP ip=10.0.2.15 udp=8080 tcp=80 icmp=echo\n");
    {
        // Debug: DMA window base + queue sanity.
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg dma=0x";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        let dma = dma_phys_base();
        let be = dma.to_be_bytes();
        let mut hx = [0u8; 16];
        hex_encode(&be, 8, &mut hx);
        line[pos..pos + 16].copy_from_slice(&hx);
        pos += 16;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Gratuitous ARP + gateway ARP: register with slirp's bridge.
    let mut garp = [0u8; 42];
    garp[..6].copy_from_slice(&[0xffu8; 6]);
    garp[6..12].copy_from_slice(&mac);
    garp[12] = 0x08;
    garp[13] = 0x06;
    garp[14] = 0;
    garp[15] = 1;
    garp[16] = 0x08;
    garp[17] = 0;
    garp[18] = 6;
    garp[19] = 4;
    garp[20] = 0;
    garp[21] = 1;
    garp[22..28].copy_from_slice(&mac);
    garp[28..32].copy_from_slice(&UDP_SVC_IP);
    garp[32..38].copy_from_slice(&[0u8; 6]);
    garp[38..42].copy_from_slice(&UDP_SVC_IP);
    vnet_tx(n, &garp);
    let mut gw = garp;
    gw[38..42].copy_from_slice(&[10, 0, 2, 2]);
    vnet_tx(n, &gw);
    {
        // Did TX complete? Read TX used idx after a spin.
        let mut spins = 0u32;
        let mut u = 0u16;
        while spins < 20_000_000 {
            // SAFETY: Reading volatile 16-bit TX used.idx from the mapped `n.tx_q_virt` virtqueue page.
            u = unsafe {
                core::ptr::read_volatile((n.tx_q_virt + VN_USED_OFF + 2) as *const u16)
            };
            if u != 0 {
                break;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg tx-used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(u as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // RX probe: DNS query to slirp's embedded resolver (10.0.2.3:53).
    // slirp always answers; the answer proves RX delivery independent
    // of hostfwd mapping.
    {
        const DNS_IP: [u8; 4] = [10, 0, 2, 3];
        let mut dns = [0u8; 29];
        dns[0] = 0xc0;
        dns[1] = 0xde;
        dns[2] = 0x01;
        dns[3] = 0x00;
        dns[5] = 0x01;
        dns[12] = 7;
        dns[13..20].copy_from_slice(b"example");
        dns[20] = 3;
        dns[21..24].copy_from_slice(b"com");
        dns[24] = 0;
        dns[26] = 0x01;
        dns[28] = 0x01;
        let dlen = dns.len();
        let udp_len = (8 + dlen) as u16;
        let mut uf = [0u8; 2048];
        uf[0..2].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        uf[2..4].copy_from_slice(&53u16.to_be_bytes());
        uf[4..6].copy_from_slice(&udp_len.to_be_bytes());
        uf[8..8 + dlen].copy_from_slice(&dns);
        let uc = target_enterprise::net::udp_checksum(UDP_SVC_IP, DNS_IP, &uf[..udp_len as usize]);
        uf[6..8].copy_from_slice(&uc.to_be_bytes());
        let ip_len = (20 + udp_len) as u16;
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&UDP_SVC_IP);
        ip[16..20].copy_from_slice(&DNS_IP);
        let ic = target_enterprise::net::ipv4_header_checksum(&ip);
        ip[10..12].copy_from_slice(&ic.to_be_bytes());
        let el = 14 + ip_len as usize;
        let mut eth = [0u8; 2048];
        eth[..6].copy_from_slice(&[0x52, 0x55, 0x0a, 0x00, 0x02, 0x03]);
        eth[6..12].copy_from_slice(&mac);
        eth[12] = 0x08;
        eth[13] = 0x00;
        eth[14..34].copy_from_slice(&ip);
        eth[34..el].copy_from_slice(&uf[..udp_len as usize]);
        vnet_tx(n, &eth[..el]);
    }

    // Watch RX used for the DNS answer (bounded).
    {
        let mut spins = 0u32;
        let mut rxu = 0u16;
        while spins < 40_000_000 {
            // SAFETY: Reading volatile 16-bit RX used.idx from the mapped `n.rx_q_virt` virtqueue page.
            rxu = unsafe {
                core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16)
            };
            if rxu != 0 {
                break;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg dns-rx-used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(rxu as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 2;
    let mut idle: u64 = 0;
    let mut frame = [0u8; 2048];

    {
        // One-shot: state at loop entry.
        // SAFETY: Reading volatile 16-bit RX used.idx from the mapped `n.rx_q_virt` virtqueue page.
        let cur0 = unsafe {
            core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16)
        };
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg loop-enter used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(cur0 as u64, &mut line[pos..]);
        let mid = b" seen=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64_to_buf(n.rx_used_seen as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    loop {
        let Some((flen, head_id)) = vnet_rx(n, &mut frame) else {
            idle += 1;
            let max_idle: u64 = if rx_count == 0 { 2_000_000 } else { 200_000_000 };
            if idle > max_idle {
                break;
            }
            core::hint::spin_loop();
            continue;
        };
        idle = 0;
        rx_count += 1;
        {
            // Debug every consumed frame: len + etype + dst port.
            let mut line = [0u8; 80];
            let mut pos = 0usize;
            let pre = b"UDP SVC got flen=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(flen as u64, &mut line[pos..]);
            if flen >= 14 {
                let et = u16::from_be_bytes([frame[12], frame[13]]);
                let mid = b" etype=0x";
                line[pos..pos + mid.len()].copy_from_slice(mid);
                pos += mid.len();
                let be = et.to_be_bytes();
                let mut hx = [0u8; 4];
                hex_encode(&be, 2, &mut hx);
                line[pos..pos + 4].copy_from_slice(&hx);
                pos += 4;
            }
            if flen >= 36 && u16::from_be_bytes([frame[12], frame[13]]) == 0x0800 {
                let ihl2 = ((frame[14] & 0x0F) as usize) * 4;
                let dport = u16::from_be_bytes([frame[14 + ihl2 + 2], frame[14 + ihl2 + 3]]);
                let mid2 = b" dport=";
                line[pos..pos + mid2.len()].copy_from_slice(mid2);
                pos += mid2.len();
                pos += dec_u64_to_buf(dport as u64, &mut line[pos..]);
                let sport = u16::from_be_bytes([frame[14 + ihl2], frame[14 + ihl2 + 1]]);
                let mid3 = b" sport=";
                line[pos..pos + mid3.len()].copy_from_slice(mid3);
                pos += mid3.len();
                pos += dec_u64_to_buf(sport as u64, &mut line[pos..]);
            }
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
        if flen < 14 {
            vnet_rx_recycle(n, head_id);
            continue;
        }

        let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        let mut replies = target_enterprise::ReplySet::new();
        {
            let mut sh_guard = KERNEL_SHELL.lock();
            let sh: &mut target_enterprise::OsShell = &mut *sh_guard;
            if sh.fs.inode_count() == 0 {
                sh.seal_key = derive_runtime_seal_key();
                sh.seed_defaults();
                let _ = restore_shell_from_ahci(sh);
            }
            svc.handle_frame_with_shell(&frame[..flen], boots, sh, &mut replies);
        }
        let mut ri = 0usize;
        while ri < replies.len() {
            if let Some(r) = replies.get(ri) {
                vnet_tx(n, r);
                tx_count += 1;
            }
            ri += 1;
        }
        if replies.len() != 0 {
            let mut line = [0u8; 64];
            let mut pos = 0usize;
            let pre = b"NET SVC rx=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(rx_count, &mut line[pos..]);
            let mid = b" tx=";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            pos += dec_u64_to_buf(tx_count, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
        vnet_rx_recycle(n, head_id);
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let pre = b"UDP SVC DOWN window-closed rx=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(rx_count, &mut line[pos..]);
        let mid = b" tx=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64_to_buf(tx_count, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Legacy I/O-port path (hub topology only — kept as fallback).
pub(crate) fn service_udp_status_legacy() {
    use core::sync::atomic::{fence, Ordering};
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000;
    const VIRTIO_NET_MODERN: u16 = 0x1041;
    const PCI_COMMAND_IO: u32 = 1;
    const VIRTIO_PCI_STATUS: u16 = 18;
    const VIRTIO_PCI_CONFIG: u16 = 20;
    const Q_RX: u16 = 0;
    const Q_TX: u16 = 1;
    const N_RX_BUFS: u16 = 8;
    const RX_BUF_LEN: u32 = 2048;

    // --- PCI: first virtio-net device ---
    let mut bus = RealPciBus;
    let mut io: Option<(u16, [u8; 6])> = None;
    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress { bus: 0, device, function: 0 };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == VIRTIO_VENDOR
            && (dev_id == VIRTIO_NET_TRANSITIONAL || dev_id == VIRTIO_NET_MODERN)
        {
            if let Ok(PciBar::Io(p)) = PciImpl::read_bar(&mut bus, addr, 0) {
                let base = p as u16;
                let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
                PciConfigBus::write_dword(
                    &mut bus,
                    addr,
                    PCI_CFG_OFFSET_COMMAND_STATUS,
                    cmd | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER,
                );
                let mut mac = [0u8; 6];
                // SAFETY: Resetting legacy virtio-net status register and reading 6-byte MAC from BAR0 + 20..26.
                unsafe {
                    outb(base + VIRTIO_PCI_STATUS, 0);
                    outb(base + VIRTIO_PCI_STATUS, 1);
                    outb(base + VIRTIO_PCI_STATUS, 3);
                    let mut i = 0;
                    while i < 6 {
                        mac[i] = inb(base + VIRTIO_PCI_CONFIG + i as u16);
                        i += 1;
                    }
                }
                io = Some((base, mac));
                break;
            }
        }
        device = device.wrapping_add(1);
    }
    let Some((base, mac)) = io else {
        serial_write_str("UDP SVC DOWN no-virtio-net\n");
        return;
    };

    if phys_map_offset() == 0 || dma_phys_base() == 0 {
        serial_write_str("UDP SVC DOWN dma-missing\n");
        return;
    }
    let dma = dma_phys_base();
    let rx_q_pa = dma;
    let tx_q_pa = dma + 0x3000;
    let rx_bufs_pa = dma + 0x6000;
    let tx_buf_pa = dma + 0xA000;

    let avail_off = (VQ_SIZE as u64) * 16;
    let used_off = {
        let raw = avail_off + 4 + 2 * (VQ_SIZE as u64);
        (raw + VQ_ALIGN - 1) & !(VQ_ALIGN - 1)
    };

    // Zero queue window.
    // SAFETY: Zeroing the 48 KiB legacy virtio-net DMA window and programming queue PFNs over I/O ports (`base`).
    unsafe {
        let b = pa_to_va(dma);
        let mut i = 0usize;
        while i < 0xC000 {
            core::ptr::write_volatile(b.add(i), 0);
            i += 1;
        }
        // Device setup: reset, ack, driver, features-none.
        outb(base + VIRTIO_PCI_STATUS, 0);
        outb(base + VIRTIO_PCI_STATUS, 1);
        outb(base + VIRTIO_PCI_STATUS, 3);
        outl(base + 4, 0);
        // RX queue with buffers posted.
        outw(base + 14, Q_RX);
        if inw(base + 12) != VQ_SIZE {
            serial_write_str("UDP SVC DOWN rx-qsz\n");
            return;
        }
        outl(base + 8, (rx_q_pa >> 12) as u32);
        outw(base + 14, Q_TX);
        if inw(base + 12) != VQ_SIZE {
            serial_write_str("UDP SVC DOWN tx-qsz\n");
            return;
        }
        outl(base + 8, (tx_q_pa >> 12) as u32);
    }

    let rx_q = pa_to_va(rx_q_pa);
    let tx_q = pa_to_va(tx_q_pa);
    // Post N_RX_BUFS device-writable RX descriptors.
    let mut i: u16 = 0;
    while i < N_RX_BUFS {
        write_desc_phys(rx_q, i as u64, rx_bufs_pa + (i as u64) * (RX_BUF_LEN as u64), RX_BUF_LEN, 2, 0);
        // SAFETY: Writing descriptor index `i` into RX avail.ring[i] in the mapped `rx_q` virtqueue page.
        unsafe {
            core::ptr::write_volatile(rx_q.add(avail_off as usize + 4 + (i as usize) * 2), i as u8);
            core::ptr::write_volatile(
                rx_q.add(avail_off as usize + 4 + (i as usize) * 2 + 1),
                (i >> 8) as u8,
            );
        }
        i += 1;
    }
    // SAFETY: Publishing avail.idx = N_RX_BUFS in the mapped `rx_q` virtqueue page.
    unsafe {
        // avail.idx = N_RX_BUFS
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 2), N_RX_BUFS as u8);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 3), (N_RX_BUFS >> 8) as u8);
    }
    fence(Ordering::SeqCst);
    // SAFETY: Setting DRIVER_OK and kicking RX queue 0 on legacy virtio-net I/O ports (`base`).
    unsafe {
        outb(base + VIRTIO_PCI_STATUS, 1 | 2 | 4); // DRIVER_OK
        outw(base + 16, Q_RX);
    }

    // Gratuitous ARP FIRST: QEMU user-mode networking (slirp) is a
    // learning bridge — until the guest transmits, slirp does not know
    // its MAC and drops inbound frames. Announce ourselves so hostfwd
    // traffic can flow (learned from RustOSa's bring-up).
    let mut rx_used_last: u16 = 0;
    let mut tx_avail_idx: u16 = 0;
    let mut tx_used_last: u16 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    let mut idle: u64 = 0;
    {
        let mut garp = [0u8; 42];
        let bcast = [0xffu8; 6];
        garp[..6].copy_from_slice(&bcast);
        garp[6..12].copy_from_slice(&mac);
        garp[12] = 0x08;
        garp[13] = 0x06;
        garp[14] = 0;
        garp[15] = 1; // htype eth
        garp[16] = 0x08;
        garp[17] = 0; // ptype ipv4
        garp[18] = 6;
        garp[19] = 4; // hlen/plen
        garp[20] = 0;
        garp[21] = 1; // request
        garp[22..28].copy_from_slice(&mac);
        garp[28..32].copy_from_slice(&UDP_SVC_IP);
        garp[32..38].copy_from_slice(&[0u8; 6]);
        garp[38..42].copy_from_slice(&UDP_SVC_IP);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &garp);
        tx_count += 1;
        // Did the gratuitous ARP actually complete on the device?
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC garp-tx-used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(tx_used_last as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);

        // Direction probe: TX a UDP datagram to the slirp gateway
        // (10.0.2.2:8080 = the host). If the host receives this, the
        // guest→host path is proven; RX silence then isolates to
        // slirp→guest delivery.
        const GW_IP: [u8; 4] = [10, 0, 2, 2];
        const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let payload = b"PROTEUS-HELLO\n";
        let plen = payload.len();
        let udp_len = (8 + plen) as u16;
        let mut udp_full = [0u8; 2048];
        udp_full[0..2].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        udp_full[2..4].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        udp_full[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp_full[8..8 + plen].copy_from_slice(payload);
        let uc = target_enterprise::net::udp_checksum(
            UDP_SVC_IP,
            GW_IP,
            &udp_full[..udp_len as usize],
        );
        udp_full[6..8].copy_from_slice(&uc.to_be_bytes());
        let ip_len = (20 + udp_len) as u16;
        let mut out_ip = [0u8; 20];
        out_ip[0] = 0x45;
        out_ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
        out_ip[8] = 64;
        out_ip[9] = 17;
        out_ip[12..16].copy_from_slice(&UDP_SVC_IP);
        out_ip[16..20].copy_from_slice(&GW_IP);
        let ic = target_enterprise::net::ipv4_header_checksum(&out_ip);
        out_ip[10..12].copy_from_slice(&ic.to_be_bytes());
        let eth_len = 14 + ip_len as usize;
        let mut eth = [0u8; 2048];
        eth[..6].copy_from_slice(&GW_MAC);
        eth[6..12].copy_from_slice(&mac);
        eth[12] = 0x08;
        eth[13] = 0x00;
        eth[14..34].copy_from_slice(&out_ip);
        eth[34..eth_len].copy_from_slice(&udp_full[..udp_len as usize]);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &eth[..eth_len]);
        tx_count += 1;

        // ARP request for the GATEWAY (10.0.2.2): slirp's neighbor
        // table is populated by ARP *replies* — the gratuitous announce
        // may not be enough. Asking forces slirp to answer and to mark
        // us reachable, which is what hostfwd delivery keys on.
        let mut gw_arp = [0u8; 42];
        let bcast2 = [0xffu8; 6];
        gw_arp[..6].copy_from_slice(&bcast2);
        gw_arp[6..12].copy_from_slice(&mac);
        gw_arp[12] = 0x08;
        gw_arp[13] = 0x06;
        gw_arp[14] = 0;
        gw_arp[15] = 1;
        gw_arp[16] = 0x08;
        gw_arp[17] = 0;
        gw_arp[18] = 6;
        gw_arp[19] = 4;
        gw_arp[20] = 0;
        gw_arp[21] = 1; // request
        gw_arp[22..28].copy_from_slice(&mac);
        gw_arp[28..32].copy_from_slice(&UDP_SVC_IP);
        gw_arp[32..38].copy_from_slice(&[0u8; 6]);
        gw_arp[38..42].copy_from_slice(&GW_IP);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &gw_arp);
        tx_count += 1;

        // RX probe: real DNS query to slirp's embedded resolver
        // (10.0.2.3:53). slirp MUST answer — and the answer is a unicast
        // frame back to us. If `used` advances, virtio RX works and the
        // problem is hostfwd mapping; if not, RX is dead at QEMU level.
        const DNS_IP: [u8; 4] = [10, 0, 2, 3];
        let mut dns = [0u8; 29];
        dns[0] = 0xc0;
        dns[1] = 0xde; // id
        dns[2] = 0x01;
        dns[3] = 0x00; // RD
        dns[5] = 0x01; // qdcount=1
        // qname: 7 example 3 com 0
        dns[12] = 7;
        dns[13..20].copy_from_slice(b"example");
        dns[20] = 3;
        dns[21..24].copy_from_slice(b"com");
        dns[24] = 0;
        dns[26] = 0x01; // qtype A (bytes 25-26 BE: 0x0001)
        dns[28] = 0x01; // qclass IN (bytes 27-28 BE: 0x0001)
        let dlen = dns.len();
        let udp_len2 = (8 + dlen) as u16;
        let mut uf2 = [0u8; 2048];
        uf2[0..2].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        uf2[2..4].copy_from_slice(&53u16.to_be_bytes());
        uf2[4..6].copy_from_slice(&udp_len2.to_be_bytes());
        uf2[8..8 + dlen].copy_from_slice(&dns);
        let uc2 = target_enterprise::net::udp_checksum(UDP_SVC_IP, DNS_IP, &uf2[..udp_len2 as usize]);
        uf2[6..8].copy_from_slice(&uc2.to_be_bytes());
        let ip_len2 = (20 + udp_len2) as u16;
        let mut ip2 = [0u8; 20];
        ip2[0] = 0x45;
        ip2[2..4].copy_from_slice(&ip_len2.to_be_bytes());
        ip2[8] = 64;
        ip2[9] = 17;
        ip2[12..16].copy_from_slice(&UDP_SVC_IP);
        ip2[16..20].copy_from_slice(&DNS_IP);
        let ic2 = target_enterprise::net::ipv4_header_checksum(&ip2);
        ip2[10..12].copy_from_slice(&ic2.to_be_bytes());
        let el2 = 14 + ip_len2 as usize;
        let mut eth2 = [0u8; 2048];
        eth2[..6].copy_from_slice(&GW_MAC);
        eth2[6..12].copy_from_slice(&mac);
        eth2[12] = 0x08;
        eth2[13] = 0x00;
        eth2[14..34].copy_from_slice(&ip2);
        eth2[34..el2].copy_from_slice(&uf2[..udp_len2 as usize]);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &eth2[..el2]);
        tx_count += 1;
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"UDP SVC UP ip=10.0.2.15 port=8080\n";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let _ = line;
        let _ = pos;
        serial_write_str("UDP SVC UP ip=10.0.2.15 port=8080\n");
        serial_write_str("NET SVC UP ip=10.0.2.15 udp=8080 tcp=80 icmp=echo\n");
    }

    let mut svc = target_enterprise::LivedNet::with_auth_key(mac, derive_runtime_net_auth_key(mac));

    // Bounded service window.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC loop-enter used0=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        // SAFETY: rx_q points to the mapped legacy virtqueue page; used_off + 2..4 is the used ring index.
        let u0 = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        pos += dec_u64_to_buf(u0 as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    loop {
        fence(Ordering::SeqCst);
        // SAFETY: rx_q is mapped and valid; reading the volatile 16-bit used ring idx.
        let rx_used = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if rx_used == rx_used_last {
            idle += 1;
            if idle % 500_000_000 == 0 {
                // Heartbeat debug: prove the poll loop is alive and
                // report the raw used index (frame-arrival signal).
                let mut line = [0u8; 48];
                let mut pos = 0usize;
                let pre = b"UDP SVC poll used=";
                line[..pre.len()].copy_from_slice(pre);
                pos += pre.len();
                pos += dec_u64_to_buf(rx_used as u64, &mut line[pos..]);
                line[pos] = b'\n';
                pos += 1;
                serial_write_bytes(&line[..pos]);
            }
            let max_idle: u64 = if rx_count == 0 { 2_000_000 } else { 200_000_000 };
            if idle > max_idle {
                break;
            }
            core::hint::spin_loop();
            continue;
        }
        idle = 0;
        // Consume one used RX element (ring slot = idx % VQ_SIZE; id
        // field at used_off+4+8*slot).
        let slot = (rx_used_last % VQ_SIZE) as usize;
        // SAFETY: slot < VQ_SIZE lies within the mapped used ring table.
        let desc_id = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 4 + slot * 8));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 5 + slot * 8));
            u16::from_le_bytes([b0, b1])
        };
        rx_used_last = rx_used_last.wrapping_add(1);

        // Read the frame.
        let buf_pa = rx_bufs_pa + (desc_id as u64) * (RX_BUF_LEN as u64);
        let mut frame = [0u8; 2048];
        // SAFETY: buf_pa lies in the reserved DMA window and frame has 2048 bytes (>= 1536).
        unsafe {
            let p = pa_to_va(buf_pa + UDP_SVC_VIRTIO_HDR as u64);
            core::ptr::copy_nonoverlapping(p, frame.as_mut_ptr(), 1536);
        }

        // Repost the buffer immediately.
        write_desc_phys(rx_q, desc_id as u64, buf_pa, RX_BUF_LEN, 2, 0);
        fence(Ordering::SeqCst);
        // SAFETY: Updating the avail ring slot and notifying legacy virtio-net queue port (base + 16).
        unsafe {
            let idx_pos = avail_off as usize + 2;
            let cur = u16::from_le_bytes([
                core::ptr::read_volatile(rx_q.add(idx_pos)),
                core::ptr::read_volatile(rx_q.add(idx_pos + 1)),
            ]);
            let apos = avail_off as usize + 4 + (cur as usize % VQ_SIZE as usize) * 2;
            core::ptr::write_volatile(rx_q.add(apos), desc_id as u8);
            core::ptr::write_volatile(rx_q.add(apos + 1), (desc_id >> 8) as u8);
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(rx_q.add(idx_pos), cur.wrapping_add(1) as u8);
            core::ptr::write_volatile(rx_q.add(idx_pos + 1), (cur.wrapping_add(1) >> 8) as u8);
            outw(base + 16, Q_RX);
        }

        rx_count += 1;

        // Debug: every consumed frame gets a line (first bytes + etype).
        {
            let mut line = [0u8; 64];
            let mut pos = 0usize;
            let pre = b"UDP SVC frame id=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(desc_id as u64, &mut line[pos..]);
            let mid = b" etype=";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            let mut hx = [0u8; 4];
            hex_encode(&[frame[12], frame[13]], 2, &mut hx);
            line[pos..pos + 4].copy_from_slice(&hx);
            pos += 4;
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }

        let boots = CONTINUITY_BOOT_COUNT.load(Ordering::Relaxed);
        let mut replies = target_enterprise::ReplySet::new();
        {
            let mut sh_guard = KERNEL_SHELL.lock();
            let sh: &mut target_enterprise::OsShell = &mut *sh_guard;
            if sh.fs.inode_count() == 0 {
                sh.seal_key = derive_runtime_seal_key();
                sh.seed_defaults();
                let _ = restore_shell_from_ahci(sh);
            }
            // Legacy RX copies 1536 bytes; LivedNet uses IPv4 total_length.
            svc.handle_frame_with_shell(&frame[..1536.min(frame.len())], boots, sh, &mut replies);
        }
        let mut ri = 0usize;
        while ri < replies.len() {
            if let Some(r) = replies.get(ri) {
                udp_svc_tx(
                    base,
                    tx_q,
                    tx_buf_pa,
                    avail_off,
                    used_off,
                    &mut tx_avail_idx,
                    &mut tx_used_last,
                    r,
                );
                tx_count += 1;
            }
            ri += 1;
        }
        if replies.len() != 0 {
            let mut line = [0u8; 64];
            let mut pos = 0usize;
            let pre = b"NET SVC rx=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(rx_count, &mut line[pos..]);
            let mid = b" tx=";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            pos += dec_u64_to_buf(tx_count, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
    }

    serial_write_str("UDP SVC DOWN window-closed\n");
}

/// Transmit one Ethernet frame via the TX virtqueue (virtio_net_hdr
/// prepended). Waits for TX completion before returning (bounded).
pub(crate) fn udp_svc_tx(
    base: u16,
    tx_q: *mut u8,
    tx_buf_pa: u64,
    avail_off: u64,
    used_off: u64,
    avail_idx: &mut u16,
    used_last: &mut u16,
    frame: &[u8],
) {
    use core::sync::atomic::{fence, Ordering};
    let total = (UDP_SVC_VIRTIO_HDR + frame.len()) as u32;
    // SAFETY: Writing 12-byte virtio_net_hdr and copying `frame` into the mapped TX DMA buffer (`tx_buf_pa`).
    unsafe {
        // virtio_net_hdr (12 zero bytes) + frame.
        let p = pa_to_va(tx_buf_pa);
        let mut i = 0usize;
        while i < UDP_SVC_VIRTIO_HDR {
            core::ptr::write_volatile(p.add(i), 0);
            i += 1;
        }
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            p.add(UDP_SVC_VIRTIO_HDR),
            frame.len(),
        );
    }
    let slot = *avail_idx % VQ_SIZE;
    write_desc_phys(tx_q, slot as u64, tx_buf_pa, total, 0, 0);
    fence(Ordering::SeqCst);
    // SAFETY: Publishing `slot` into TX avail ring and notifying legacy virtio-net queue port (`base + 16`).
    unsafe {
        let apos = avail_off as usize + 4 + (slot as usize) * 2;
        core::ptr::write_volatile(tx_q.add(apos), slot as u8);
        core::ptr::write_volatile(tx_q.add(apos + 1), (slot >> 8) as u8);
        fence(Ordering::SeqCst);
        let next = avail_idx.wrapping_add(1);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 2), next as u8);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 3), (next >> 8) as u8);
        outw(base + 16, Q_TX_KICK);
    }
    *avail_idx = avail_idx.wrapping_add(1);
    // Wait completion (bounded).
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        // SAFETY: Reading volatile 16-bit TX used.idx from the mapped `tx_q` virtqueue page.
        let u = unsafe {
            let b0 = core::ptr::read_volatile(tx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(tx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if u != *used_last {
            *used_last = u;
            break;
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            return; // drop; service loop stays alive
        }
        core::hint::spin_loop();
    }
}

pub(crate) const Q_TX_KICK: u16 = 1;

/// Decimal u64 into buf, returns bytes written (service-local variant
/// of dec_u64 for the payload builder).
pub(crate) fn dec_u64_to_buf(mut v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut i = 0usize;
    while i < n {
        out[i] = tmp[n - 1 - i];
        i += 1;
    }
    n
}


// Not MemMmioBus — 0xCF8/0xCFC + ABAR-style uncached MMIO map.
// ---------------------------------------------------------------------------

/// Banner: `E1000_HW probe OK slot=N mac=…` then `E1000_HW tx OK bytes=64`
/// (TASK-116 probe + TASK-120 real TX descriptor ring + DD completion).
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_e1000_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER, E1000_CTRL_RST,
        E1000_CTRL_SLU, E1000_DESC_STA_DD, E1000_EEPROM_MAC_WORD0,
        E1000_EEPROM_MAC_WORD1, E1000_EEPROM_MAC_WORD2, E1000_EERD_ADDR_MASK,
        E1000_EERD_ADDR_SHIFT, E1000_EERD_DATA_MASK, E1000_EERD_DATA_SHIFT,
        E1000_EERD_DONE, E1000_EERD_START, E1000_REG_CTRL, E1000_REG_EERD,
        E1000_REG_IMC, E1000_REG_STATUS, E1000_REG_TCTL, E1000_REG_TDBAH,
        E1000_REG_TDBAL, E1000_REG_TDH, E1000_REG_TDLEN, E1000_REG_TDT,
        E1000_REG_TIPG, E1000_TCTL_EN, E1000_TCTL_PSP, E1000_TX_DESC_LEN,
        E1000_TXD_CMD_EOP, E1000_TXD_CMD_IFCS, E1000_TXD_CMD_RS,
    };
    use target_enterprise::e1000::TxDesc;
    use target_enterprise::pci::PciImpl;

    const PCI_COMMAND_MEMORY: u32 = 1 << 1;
    const INTEL_VENDOR: u16 = 0x8086;
    // QEMU default e1000 = 82540EM; also accept common variants.
    const DEV_82540EM: u16 = 0x100E;
    const DEV_82545EM: u16 = 0x100F;
    const DEV_82574L: u16 = 0x10D3;

    if phys_map_offset() == 0 || dma_phys_base() == 0 {
        panic!("E1000_HW: phys map missing");
    }

    let mut bus = RealPciBus;
    let mut found_slot: Option<u8> = None;
    let mut found_addr: Option<PciAddress> = None;
    let mut bar0: u64 = 0;

    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == INTEL_VENDOR
            && (dev_id == DEV_82540EM || dev_id == DEV_82545EM || dev_id == DEV_82574L)
        {
            let bar = match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                Ok(PciBar::Io(_)) | Err(_) => 0,
            };
            if bar != 0 {
                found_slot = Some(device);
                found_addr = Some(addr);
                bar0 = bar;
                break;
            }
        }
        device = device.wrapping_add(1);
    }

    let slot = match found_slot {
        Some(s) => s,
        None => panic!("E1000_HW: no e1000 on bus 0 (attach -device e1000)"),
    };
    let addr = match found_addr {
        Some(a) => a,
        None => panic!("E1000_HW: missing addr"),
    };

    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );

    // Soft reset + mask IRQs (same sequence as E1000Impl::reset).
    // SAFETY: Performing soft reset and masking IRQs in the e1000 controller's BAR0 MMIO space.
    unsafe {
        mmio_write32(bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        let ctrl = mmio_read32(bar0 + E1000_REG_CTRL as u64);
        if ctrl == 0xFFFF_FFFF {
            panic!("E1000_HW: CTRL MMIO fault");
        }
        mmio_write32(bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_RST);
        let mut spins = 0u32;
        loop {
            let c = mmio_read32(bar0 + E1000_REG_CTRL as u64);
            if c & E1000_CTRL_RST == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 20_000_000 {
                panic!("E1000_HW: reset timeout");
            }
            core::hint::spin_loop();
        }
        mmio_write32(bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        // STATUS must be readable (non-fault).
        let st = mmio_read32(bar0 + E1000_REG_STATUS as u64);
        if st == 0xFFFF_FFFF {
            panic!("E1000_HW: STATUS MMIO fault");
        }
    }

    // EEPROM MAC words 0..2 via EERD (82540EM layout; QEMU default).
    let read_eerd = |word: u8| -> u16 {
        let cmd = E1000_EERD_START | ((word as u32 & E1000_EERD_ADDR_MASK) << E1000_EERD_ADDR_SHIFT);
        // SAFETY: Writing and polling the EERD MMIO register at `bar0 + E1000_REG_EERD`.
        unsafe {
            mmio_write32(bar0 + E1000_REG_EERD as u64, cmd);
            let mut spins = 0u32;
            loop {
                let v = mmio_read32(bar0 + E1000_REG_EERD as u64);
                if v & E1000_EERD_DONE != 0 {
                    return ((v >> E1000_EERD_DATA_SHIFT) & E1000_EERD_DATA_MASK) as u16;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("E1000_HW: EEPROM poll timeout");
                }
                core::hint::spin_loop();
            }
        }
    };
    let w0 = read_eerd(E1000_EEPROM_MAC_WORD0);
    let w1 = read_eerd(E1000_EEPROM_MAC_WORD1);
    let w2 = read_eerd(E1000_EEPROM_MAC_WORD2);
    let mac = [
        (w0 & 0xFF) as u8,
        ((w0 >> 8) & 0xFF) as u8,
        (w1 & 0xFF) as u8,
        ((w1 >> 8) & 0xFF) as u8,
        (w2 & 0xFF) as u8,
        ((w2 >> 8) & 0xFF) as u8,
    ];
    if mac == [0u8; 6] || mac == [0xFFu8; 6] {
        panic!("E1000_HW: invalid EEPROM MAC");
    }
    // Multicast bit must be clear on burned-in unicast MAC.
    if mac[0] & 1 != 0 {
        panic!("E1000_HW: MAC multicast bit set");
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"E1000_HW probe OK slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(slot as u64, &mut line[pos..]);
        let mid = b" mac=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // TASK-120: real TX ring in DMA window (not stack identity phys).
    // Layout: [0] 16-byte legacy desc, [0x40] 64-byte eth frame.
    const E1000_TX_RING_PHYS_OFF: u64 = 0x2_0000;
    const E1000_TX_BUF_PHYS_OFF: u64 = 0x2_0040;
    const TX_FRAME_LEN: u16 = 64;
    let tx_ring_phys = dma_phys_base() + E1000_TX_RING_PHYS_OFF;
    let tx_buf_phys = dma_phys_base() + E1000_TX_BUF_PHYS_OFF;
    let ring_va = pa_to_va(tx_ring_phys);
    let buf_va = pa_to_va(tx_buf_phys);

    // Minimal Ethernet: dst ff:ff:ff:ff:ff:ff, src = EEPROM MAC, ethertype 0x0800, zeros.
    // SAFETY: `buf_va` points to a 64-byte TX buffer in the reserved DMA window.
    unsafe {
        let mut i = 0usize;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(i), 0xFF);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(6 + i), mac[i]);
            i += 1;
        }
        core::ptr::write_volatile(buf_va.add(12), 0x08);
        core::ptr::write_volatile(buf_va.add(13), 0x00);
        i = 14;
        while i < TX_FRAME_LEN as usize {
            core::ptr::write_volatile(buf_va.add(i), (i as u8).wrapping_mul(0x11));
            i += 1;
        }
    }

    let desc = TxDesc {
        addr: tx_buf_phys,
        length: TX_FRAME_LEN,
        cso: 0,
        cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
        sta: 0, // device sets DD
        css: 0,
        special: 0,
    };
    let enc = desc.encode();
    // SAFETY: `ring_va` points to the 16-slot TX descriptor ring in the reserved DMA window.
    unsafe {
        let mut i = 0usize;
        while i < E1000_TX_DESC_LEN {
            core::ptr::write_volatile(ring_va.add(i), enc[i]);
            i += 1;
        }
        // Zero remaining ring slots not used.
        i = E1000_TX_DESC_LEN;
        while i < 16 * E1000_TX_DESC_LEN {
            core::ptr::write_volatile(ring_va.add(i), 0);
            i += 1;
        }
    }

    // SAFETY: Programming e1000 TX ring MMIO registers (`TDBAL`/`TDBAH`/`TDLEN`/`TDH`/`TDT`/`TCTL`) and polling DD bit.
    unsafe {
        // Link up + TX ring program (Intel 82540EM / QEMU).
        let ctrl = mmio_read32(bar0 + E1000_REG_CTRL as u64);
        mmio_write32(bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_SLU);
        mmio_write32(bar0 + E1000_REG_TDBAL as u64, tx_ring_phys as u32);
        mmio_write32(bar0 + E1000_REG_TDBAH as u64, (tx_ring_phys >> 32) as u32);
        mmio_write32(
            bar0 + E1000_REG_TDLEN as u64,
            (16 * E1000_TX_DESC_LEN) as u32,
        );
        mmio_write32(bar0 + E1000_REG_TDH as u64, 0);
        mmio_write32(bar0 + E1000_REG_TDT as u64, 0);
        // TIPG default IPG for copper (QEMU accepts common 0x0060200A).
        mmio_write32(bar0 + E1000_REG_TIPG as u64, 0x0060_200A);
        mmio_write32(
            bar0 + E1000_REG_TCTL as u64,
            E1000_TCTL_EN | E1000_TCTL_PSP | (0x0F << 4) | (0x40 << 12),
        );
        // Hand one descriptor to the device.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        mmio_write32(bar0 + E1000_REG_TDT as u64, 1);

        let mut spins = 0u32;
        loop {
            let sta = core::ptr::read_volatile(ring_va.add(12));
            if sta & E1000_DESC_STA_DD != 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("E1000_HW: TX DD timeout");
            }
            core::hint::spin_loop();
        }
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"E1000_HW tx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(TX_FRAME_LEN as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // TASK-132: dual e1000 on hubid=2 — TX peer → RX peer magic frame.
    // Find a second e1000 (different slot) for RX.
    let mut rx_slot: Option<u8> = None;
    let mut rx_addr: Option<PciAddress> = None;
    let mut rx_bar0: u64 = 0;
    let mut device: u8 = 0;
    while device < 32 {
        if device == slot {
            device = device.wrapping_add(1);
            continue;
        }
        let a = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, a, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == INTEL_VENDOR
            && (dev_id == DEV_82540EM || dev_id == DEV_82545EM || dev_id == DEV_82574L)
        {
            let bar = match PciImpl::read_bar(&mut bus, a, 0) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                Ok(PciBar::Io(_)) | Err(_) => 0,
            };
            if bar != 0 {
                rx_slot = Some(device);
                rx_addr = Some(a);
                rx_bar0 = bar;
                break;
            }
        }
        device = device.wrapping_add(1);
    }
    let rx_slot = match rx_slot {
        Some(s) => s,
        None => panic!("E1000_HW: need 2nd e1000 for RX (dual hubport)"),
    };
    let rx_addr = match rx_addr {
        Some(a) => a,
        None => panic!("E1000_HW: rx addr missing"),
    };
    let cmd = PciConfigBus::read_dword(&mut bus, rx_addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        rx_addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );
    // SAFETY: Performing soft reset and setting link-up (SLU) on the second e1000 peer's BAR0 MMIO space (`rx_bar0`).
    unsafe {
        mmio_write32(rx_bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        let ctrl = mmio_read32(rx_bar0 + E1000_REG_CTRL as u64);
        mmio_write32(rx_bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_RST);
        let mut spins = 0u32;
        loop {
            let c = mmio_read32(rx_bar0 + E1000_REG_CTRL as u64);
            if c & E1000_CTRL_RST == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 20_000_000 {
                panic!("E1000_HW: RX reset timeout");
            }
            core::hint::spin_loop();
        }
        mmio_write32(rx_bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        let ctrl = mmio_read32(rx_bar0 + E1000_REG_CTRL as u64);
        mmio_write32(rx_bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_SLU);
    }

    use proteus_contracts::{
        E1000_RCTL_BAM, E1000_RCTL_EN, E1000_RCTL_SECRC, E1000_REG_RDBAH, E1000_REG_RDBAL,
        E1000_REG_RDH, E1000_REG_RDLEN, E1000_REG_RDT, E1000_REG_RCTL, E1000_RX_DESC_LEN,
    };
    use target_enterprise::e1000::RxDesc;

    const RX_RING_OFF: u64 = 0x2_1000;
    const RX_BUF_OFF: u64 = 0x2_2000;
    let rx_ring_phys = dma_phys_base() + RX_RING_OFF;
    let rx_buf_phys = dma_phys_base() + RX_BUF_OFF;
    let rx_ring_va = pa_to_va(rx_ring_phys);
    let rx_buf_va = pa_to_va(rx_buf_phys);
    // Clear RX buffer; magic "PE1000RX" will be searched after TX.
    // SAFETY: Initializing RX descriptor 0 and buffer in the mapped DMA window and programming RX ring MMIO registers on `rx_bar0`.
    unsafe {
        let mut i = 0usize;
        while i < 256 {
            core::ptr::write_volatile(rx_buf_va.add(i), 0);
            i += 1;
        }
        let rxd = RxDesc {
            addr: rx_buf_phys,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        let enc = rxd.encode();
        let mut i = 0usize;
        while i < E1000_RX_DESC_LEN {
            core::ptr::write_volatile(rx_ring_va.add(i), enc[i]);
            i += 1;
        }
        // Zero remaining ring entries.
        while i < 16 * E1000_RX_DESC_LEN {
            core::ptr::write_volatile(rx_ring_va.add(i), 0);
            i += 1;
        }
        mmio_write32(rx_bar0 + E1000_REG_RDBAL as u64, rx_ring_phys as u32);
        mmio_write32(rx_bar0 + E1000_REG_RDBAH as u64, (rx_ring_phys >> 32) as u32);
        mmio_write32(
            rx_bar0 + E1000_REG_RDLEN as u64,
            (16 * E1000_RX_DESC_LEN) as u32,
        );
        mmio_write32(rx_bar0 + E1000_REG_RDH as u64, 0);
        mmio_write32(rx_bar0 + E1000_REG_RDT as u64, 15);
        mmio_write32(
            rx_bar0 + E1000_REG_RCTL as u64,
            E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC,
        );
    }

    // Re-send frame with magic at eth payload offset 14.
    const MAGIC: &[u8; 8] = b"PE1000RX";
    // SAFETY: Writing `PE1000RX` frame into mapped `buf_va`, arming TX descriptor 1, ringing `TDT`, and polling RX DD + magic.
    unsafe {
        let mut i = 0usize;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(i), 0xFF);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(6 + i), mac[i]);
            i += 1;
        }
        core::ptr::write_volatile(buf_va.add(12), 0x08);
        core::ptr::write_volatile(buf_va.add(13), 0x00);
        i = 0;
        while i < 8 {
            core::ptr::write_volatile(buf_va.add(14 + i), MAGIC[i]);
            i += 1;
        }
        i = 22;
        while i < TX_FRAME_LEN as usize {
            core::ptr::write_volatile(buf_va.add(i), 0xAA);
            i += 1;
        }
        // Re-arm TX desc (sta cleared).
        let desc = TxDesc {
            addr: tx_buf_phys,
            length: TX_FRAME_LEN,
            cso: 0,
            cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
            sta: 0,
            css: 0,
            special: 0,
        };
        let enc = desc.encode();
        let mut i = 0usize;
        while i < E1000_TX_DESC_LEN {
            core::ptr::write_volatile(ring_va.add(i), enc[i]);
            i += 1;
        }
        // Advance TDT past previous completion: use descriptor index 1.
        let desc2 = TxDesc {
            addr: tx_buf_phys,
            length: TX_FRAME_LEN,
            cso: 0,
            cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
            sta: 0,
            css: 0,
            special: 0,
        };
        let enc2 = desc2.encode();
        let d1 = ring_va.add(E1000_TX_DESC_LEN);
        let mut i = 0usize;
        while i < E1000_TX_DESC_LEN {
            core::ptr::write_volatile(d1.add(i), enc2[i]);
            i += 1;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        mmio_write32(bar0 + E1000_REG_TDT as u64, 2);

        let mut spins = 0u32;
        let mut found = false;
        loop {
            // Poll RX DD + scan buffer for magic.
            let sta = core::ptr::read_volatile(rx_ring_va.add(12));
            if sta & E1000_DESC_STA_DD != 0 {
                let mut j = 0usize;
                while j + 8 <= 256 {
                    let mut match_ok = true;
                    let mut k = 0usize;
                    while k < 8 {
                        if core::ptr::read_volatile(rx_buf_va.add(j + k)) != MAGIC[k] {
                            match_ok = false;
                            break;
                        }
                        k += 1;
                    }
                    if match_ok {
                        found = true;
                        break;
                    }
                    j += 1;
                }
                if found {
                    break;
                }
            }
            spins = spins.wrapping_add(1);
            if spins > 80_000_000 {
                panic!("E1000_HW: RX magic timeout");
            }
            core::hint::spin_loop();
        }
        let _ = found;
    }

    {
        let mut line = [0u8; 40];
        let mut pos = 0usize;
        let prefix = b"E1000_HW rx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Report descriptor length if set, else frame size.
        // SAFETY: Reading volatile 16-bit length field at offset 8..10 of RX descriptor 0 in `rx_ring_va`.
        let rlen = unsafe {
            let lo = core::ptr::read_volatile(rx_ring_va.add(8));
            let hi = core::ptr::read_volatile(rx_ring_va.add(9));
            (lo as u16) | ((hi as u16) << 8)
        };
        let report = if rlen > 0 { rlen as u64 } else { TX_FRAME_LEN as u64 };
        pos += dec_u64(report, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let _ = rx_slot;
}

// ---------------------------------------------------------------------------
// TASK-119: real QEMU NVMe (PCI + BAR0 MMIO + admin identify)
// ---------------------------------------------------------------------------

/// Banner: `NVME_HW probe OK slot=N` then `NVME_HW identify OK sn=…`
#[cfg(not(proteus_prod))]
#[inline(never)]
pub(crate) fn banner_nvme_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_CLASS_REVISION,
        PCI_CFG_OFFSET_COMMAND_STATUS, PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::nvme::{
        CompletionQueueEntry, SubmissionQueueEntry, ADMIN_QUEUE_ENTRIES, CC_EN, CSTS_CFS,
        CSTS_RDY, IO_QUEUE_ENTRIES, NVME_BLOCK_SIZE, REG_ACQ, REG_AQA, REG_ASQ, REG_CAP,
        REG_CC, REG_CSTS, REG_VS,
    };
    use target_enterprise::pci::PciImpl;

    const PCI_COMMAND_MEMORY: u32 = 1 << 1;
    // Mass storage / NVM Express (PCI class 01:08:02).
    const CLASS_MASS: u8 = 0x01;
    const SUBCLASS_NVME: u8 = 0x08;
    const PROG_NVME: u8 = 0x02;
    // QEMU also exposes 8086:5845.
    const INTEL_VENDOR: u16 = 0x8086;
    const QEMU_NVME_DEV: u16 = 0x5845;

    if phys_map_offset() == 0 || dma_phys_base() == 0 {
        panic!("NVME_HW: phys map missing");
    }

    let mut bus = RealPciBus;
    let mut found_slot: Option<u8> = None;
    let mut found_addr: Option<PciAddress> = None;
    let mut bar0: u64 = 0;

    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == 0xFFFF {
            device = device.wrapping_add(1);
            continue;
        }
        let class_dw = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_CLASS_REVISION);
        let prog_if = ((class_dw >> 8) & 0xFF) as u8;
        let subclass = ((class_dw >> 16) & 0xFF) as u8;
        let class_code = ((class_dw >> 24) & 0xFF) as u8;
        let is_nvme = (class_code == CLASS_MASS
            && subclass == SUBCLASS_NVME
            && prog_if == PROG_NVME)
            || (vendor == INTEL_VENDOR && dev_id == QEMU_NVME_DEV);
        if is_nvme {
            let bar = match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                Ok(PciBar::Io(_)) | Err(_) => 0,
            };
            if bar != 0 {
                found_slot = Some(device);
                found_addr = Some(addr);
                bar0 = bar;
                break;
            }
        }
        device = device.wrapping_add(1);
    }

    let slot = match found_slot {
        Some(s) => s,
        None => panic!("NVME_HW: no NVMe on bus 0 (attach -device nvme)"),
    };
    let addr = match found_addr {
        Some(a) => a,
        None => panic!("NVME_HW: missing addr"),
    };

    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );

    // Map register page + doorbell page (0x1000).
    // SAFETY: Mapping the NVMe controller's BAR0 register page and doorbell page uncached in ring 0.
    unsafe {
        let _ = ensure_mmio_page(bar0);
        let _ = ensure_mmio_page(bar0 + 0x1000);
    }

    // SAFETY: Reading 64-bit NVMe CAP register at `bar0 + REG_CAP`.
    let cap = unsafe { mmio_read64(bar0 + REG_CAP as u64) };
    if cap == 0 || cap == u64::MAX {
        panic!("NVME_HW: CAP MMIO fault");
    }
    // SAFETY: Reading 32-bit NVMe VS register at `bar0 + REG_VS`.
    let vs = unsafe { mmio_read32(bar0 + REG_VS as u64) };
    if vs == 0 || vs == 0xFFFF_FFFF {
        panic!("NVME_HW: VS MMIO fault");
    }
    let dstrd = ((cap >> 32) & 0xF) as u32;
    let doorbell_stride = 4u64 << dstrd;

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"NVME_HW probe OK slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(slot as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Admin queues + identify buffer in DMA window.
    const NVME_ASQ_OFF: u64 = 0x3_0000;
    const NVME_ACQ_OFF: u64 = 0x3_1000;
    const NVME_ID_OFF: u64 = 0x3_2000;
    let asq_phys = dma_phys_base() + NVME_ASQ_OFF;
    let acq_phys = dma_phys_base() + NVME_ACQ_OFF;
    let id_phys = dma_phys_base() + NVME_ID_OFF;
    // SAFETY: Zeroing the 12 KiB NVMe admin queue and Identify buffer pages in the reserved DMA window.
    unsafe {
        let mut p = 0u64;
        while p < 0x3000 {
            let va = pa_to_va(asq_phys + p);
            core::ptr::write_volatile(va, 0);
            p += 1;
        }
    }

    // Disable controller, wait !RDY.
    // SAFETY: Programming NVMe controller configuration (`CC`, `AQA`, `ASQ`, `ACQ`) and polling `CSTS.RDY` over BAR0 MMIO.
    unsafe {
        let cc = mmio_read32(bar0 + REG_CC as u64);
        mmio_write32(bar0 + REG_CC as u64, cc & !CC_EN);
        let mut spins = 0u32;
        loop {
            let csts = mmio_read32(bar0 + REG_CSTS as u64);
            if csts & CSTS_CFS != 0 {
                panic!("NVME_HW: CFS on disable");
            }
            if csts & CSTS_RDY == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("NVME_HW: disable RDY timeout");
            }
            core::hint::spin_loop();
        }

        let aqa = ((ADMIN_QUEUE_ENTRIES as u32 - 1) << 16) | (ADMIN_QUEUE_ENTRIES as u32 - 1);
        mmio_write32(bar0 + REG_AQA as u64, aqa);
        mmio_write64(bar0 + REG_ASQ as u64, asq_phys);
        mmio_write64(bar0 + REG_ACQ as u64, acq_phys);
        // IOSQES=6 (64B), IOCQES=4 (16B), EN=1
        let cc_new = (4u32 << 20) | (6u32 << 16) | CC_EN;
        mmio_write32(bar0 + REG_CC as u64, cc_new);
        spins = 0;
        loop {
            let csts = mmio_read32(bar0 + REG_CSTS as u64);
            if csts & CSTS_CFS != 0 {
                panic!("NVME_HW: CFS on enable");
            }
            if csts & CSTS_RDY != 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("NVME_HW: enable RDY timeout");
            }
            core::hint::spin_loop();
        }
    }

    // Identify Controller (opcode 0x06, CNS=1) → id buffer.
    let cid: u16 = 1;
    let mut sqe = SubmissionQueueEntry::EMPTY;
    sqe.cdw0 = SubmissionQueueEntry::cdw0(0x06, cid);
    sqe.nsid = 0;
    sqe.prp1 = id_phys;
    sqe.cdw10 = 0x01; // CNS=Identify Controller
    // SAFETY: Writing Identify Controller SQE into mapped `asq_phys`, ringing SQ0 doorbell, and polling `acq_phys` completion.
    unsafe {
        let asq_va = pa_to_va(asq_phys);
        // Write SQE as raw LE bytes (repr C on LE host).
        let sqe_ptr = asq_va as *mut SubmissionQueueEntry;
        core::ptr::write_volatile(sqe_ptr, sqe);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SQ0 tail doorbell = 0x1000 + 0 * stride
        let sq_dbl = bar0 + 0x1000;
        mmio_write32(sq_dbl, 1);

        let acq_va = pa_to_va(acq_phys);
        let mut spins = 0u32;
        let phase_expect = true; // first completion uses phase=1
        loop {
            let status_and_cid =
                core::ptr::read_volatile(acq_va.add(12) as *const u32);
            let phase = (status_and_cid >> 16) & 1 != 0;
            let got_cid = (status_and_cid & 0xFFFF) as u16;
            if phase == phase_expect && got_cid == cid {
                let cqe = CompletionQueueEntry {
                    dw0: core::ptr::read_volatile(acq_va as *const u32),
                    dw1: core::ptr::read_volatile(acq_va.add(4) as *const u32),
                    sq_head_and_id: core::ptr::read_volatile(acq_va.add(8) as *const u32),
                    status_and_cid,
                };
                if !cqe.is_success() {
                    panic!("NVME_HW: identify status nonzero");
                }
                // CQ head doorbell
                let cq_dbl = bar0 + 0x1000 + doorbell_stride;
                mmio_write32(cq_dbl, 1);
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("NVME_HW: identify CQ timeout");
            }
            core::hint::spin_loop();
        }
    }

    // SN is 20 ASCII bytes at offset 4 of Identify Controller data.
    let mut sn = [0u8; 20];
    // SAFETY: Reading the 20-byte serial number at offset 4..24 of the mapped 4 KiB Identify Controller buffer (`id_phys`).
    unsafe {
        let id_va = pa_to_va(id_phys);
        let mut i = 0usize;
        while i < 20 {
            sn[i] = core::ptr::read_volatile(id_va.add(4 + i));
            i += 1;
        }
    }
    // Trim spaces; require at least one non-space (QEMU serial=).
    let mut sn_len = 20usize;
    while sn_len > 0 && (sn[sn_len - 1] == b' ' || sn[sn_len - 1] == 0) {
        sn_len -= 1;
    }
    if sn_len == 0 {
        panic!("NVME_HW: empty Identify SN");
    }
    // Must not be the in-kernel emu stamp.
    if sn_len >= 15 {
        let emu = b"PROTEUS-NVME-EMU";
        let mut same = true;
        let mut i = 0usize;
        while i < 15 {
            if sn[i] != emu[i] {
                same = false;
                break;
            }
            i += 1;
        }
        if same {
            panic!("NVME_HW: got emulator SN — wrong path");
        }
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVME_HW identify OK sn=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let n = if sn_len > 20 { 20 } else { sn_len };
        line[pos..pos + n].copy_from_slice(&sn[..n]);
        pos += n;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // TASK-131: Create I/O CQ+SQ, WRITE then READ LBA 0 with pattern 0x5A^i.
    const NVME_IOSQ_OFF: u64 = 0x3_4000;
    const NVME_IOCQ_OFF: u64 = 0x3_5000;
    const NVME_SEC_OFF: u64 = 0x3_6000;
    let iosq_phys = dma_phys_base() + NVME_IOSQ_OFF;
    let iocq_phys = dma_phys_base() + NVME_IOCQ_OFF;
    let sec_phys = dma_phys_base() + NVME_SEC_OFF;
    // SAFETY: Zeroing the 12 KiB NVMe I/O queue and sector buffer pages (`iosq_phys..iosq_phys+0x3000`) in mapped DMA RAM.
    unsafe {
        let mut p = 0u64;
        while p < 0x3000 {
            core::ptr::write_volatile(pa_to_va(iosq_phys + p), 0);
            p += 1;
        }
    }

    // Admin SQ tail = 1 after identify; CQ head = 1; phase still 1 until wrap.
    let mut admin_sq_tail: u16 = 1;
    let mut admin_cq_head: u16 = 1;
    let mut admin_phase = true;
    let mut next_cid: u16 = 2;

    let sq0_dbl = bar0 + 0x1000;
    let cq0_dbl = bar0 + 0x1000 + doorbell_stride;

    let admin_submit = |sqe: &SubmissionQueueEntry,
                        admin_sq_tail: &mut u16,
                        admin_cq_head: &mut u16,
                        admin_phase: &mut bool,
                        _bar0: u64,
                        asq_phys: u64,
                        acq_phys: u64,
                        sq0_dbl: u64,
                        cq0_dbl: u64| {
        // SAFETY: Writing admin SQE into mapped `asq_phys` ring, ringing `sq0_dbl`, and polling `acq_phys` completion.
        unsafe {
            let slot = (*admin_sq_tail as usize) % (ADMIN_QUEUE_ENTRIES as usize);
            let asq_va = pa_to_va(asq_phys).add(slot * 64) as *mut SubmissionQueueEntry;
            core::ptr::write_volatile(asq_va, *sqe);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            *admin_sq_tail = admin_sq_tail.wrapping_add(1);
            if *admin_sq_tail >= ADMIN_QUEUE_ENTRIES {
                *admin_sq_tail = 0;
            }
            // Spec: doorbell is new tail value (index of next free slot).
            mmio_write32(sq0_dbl, *admin_sq_tail as u32);

            let mut spins = 0u32;
            loop {
                let cq_slot = (*admin_cq_head as usize) % (ADMIN_QUEUE_ENTRIES as usize);
                let cqe_va = pa_to_va(acq_phys).add(cq_slot * 16);
                let status_and_cid =
                    core::ptr::read_volatile(cqe_va.add(12) as *const u32);
                let phase = (status_and_cid >> 16) & 1 != 0;
                let got_cid = (status_and_cid & 0xFFFF) as u16;
                if phase == *admin_phase && got_cid == sqe.cid() {
                    let status = ((status_and_cid >> 17) & 0x7FFF) as u16;
                    if status != 0 {
                        panic!("NVME_HW: admin cmd status nonzero");
                    }
                    *admin_cq_head = admin_cq_head.wrapping_add(1);
                    if *admin_cq_head >= ADMIN_QUEUE_ENTRIES {
                        *admin_cq_head = 0;
                        *admin_phase = !*admin_phase;
                    }
                    mmio_write32(cq0_dbl, *admin_cq_head as u32);
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 50_000_000 {
                    panic!("NVME_HW: admin CQ timeout");
                }
                core::hint::spin_loop();
            }
        }
    };

    // Create I/O CQ (qid=1).
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x05, next_cid);
        sqe.prp1 = iocq_phys;
        sqe.cdw10 = ((IO_QUEUE_ENTRIES as u32 - 1) << 16) | 1;
        sqe.cdw11 = 0x01; // PC
        admin_submit(
            &sqe,
            &mut admin_sq_tail,
            &mut admin_cq_head,
            &mut admin_phase,
            bar0,
            asq_phys,
            acq_phys,
            sq0_dbl,
            cq0_dbl,
        );
        next_cid = next_cid.wrapping_add(1);
    }
    // Create I/O SQ (qid=1).
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x01, next_cid);
        sqe.prp1 = iosq_phys;
        sqe.cdw10 = ((IO_QUEUE_ENTRIES as u32 - 1) << 16) | 1;
        sqe.cdw11 = (1 << 16) | 0x01; // CQID=1 | PC
        admin_submit(
            &sqe,
            &mut admin_sq_tail,
            &mut admin_cq_head,
            &mut admin_phase,
            bar0,
            asq_phys,
            acq_phys,
            sq0_dbl,
            cq0_dbl,
        );
        next_cid = next_cid.wrapping_add(1);
    }

    let sq1_dbl = bar0 + 0x1000 + 2 * doorbell_stride;
    let cq1_dbl = bar0 + 0x1000 + 3 * doorbell_stride;
    let mut io_sq_tail: u16 = 0;
    let mut io_cq_head: u16 = 0;
    let mut io_phase = true;

    let mut io_submit = |sqe: &SubmissionQueueEntry| {
        // SAFETY: Writing I/O SQE into mapped `iosq_phys` ring, ringing `sq1_dbl`, and polling `iocq_phys` completion.
        unsafe {
            let slot = (io_sq_tail as usize) % (IO_QUEUE_ENTRIES as usize);
            let va = pa_to_va(iosq_phys).add(slot * 64) as *mut SubmissionQueueEntry;
            core::ptr::write_volatile(va, *sqe);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            io_sq_tail = io_sq_tail.wrapping_add(1);
            if io_sq_tail >= IO_QUEUE_ENTRIES {
                io_sq_tail = 0;
            }
            mmio_write32(sq1_dbl, io_sq_tail as u32);

            let mut spins = 0u32;
            loop {
                let cq_slot = (io_cq_head as usize) % (IO_QUEUE_ENTRIES as usize);
                let cqe_va = pa_to_va(iocq_phys).add(cq_slot * 16);
                let status_and_cid =
                    core::ptr::read_volatile(cqe_va.add(12) as *const u32);
                let phase = (status_and_cid >> 16) & 1 != 0;
                let got_cid = (status_and_cid & 0xFFFF) as u16;
                if phase == io_phase && got_cid == sqe.cid() {
                    let status = ((status_and_cid >> 17) & 0x7FFF) as u16;
                    if status != 0 {
                        panic!("NVME_HW: io cmd status nonzero");
                    }
                    io_cq_head = io_cq_head.wrapping_add(1);
                    if io_cq_head >= IO_QUEUE_ENTRIES {
                        io_cq_head = 0;
                        io_phase = !io_phase;
                    }
                    mmio_write32(cq1_dbl, io_cq_head as u32);
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 50_000_000 {
                    panic!("NVME_HW: io CQ timeout");
                }
                core::hint::spin_loop();
            }
        }
    };

    // Pattern 0x5A ^ i over 512 B at LBA 0.
    // SAFETY: Writing 512-byte test pattern into the mapped NVMe sector buffer (`sec_phys`).
    unsafe {
        let sec_va = pa_to_va(sec_phys);
        let mut i = 0usize;
        while i < NVME_BLOCK_SIZE {
            core::ptr::write_volatile(sec_va.add(i), 0x5Au8 ^ (i as u8));
            i += 1;
        }
    }
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x01, next_cid); // Write
        sqe.nsid = 1;
        sqe.prp1 = sec_phys;
        sqe.cdw10 = 0; // LBA low
        sqe.cdw11 = 0;
        sqe.cdw12 = 0; // 1 block
        io_submit(&sqe);
        next_cid = next_cid.wrapping_add(1);
    }
    // Clear buffer, then Read LBA 0.
    // SAFETY: Clearing the 512-byte NVMe sector buffer (`sec_phys`) prior to DMA READ.
    unsafe {
        let sec_va = pa_to_va(sec_phys);
        let mut i = 0usize;
        while i < NVME_BLOCK_SIZE {
            core::ptr::write_volatile(sec_va.add(i), 0);
            i += 1;
        }
    }
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x02, next_cid); // Read
        sqe.nsid = 1;
        sqe.prp1 = sec_phys;
        sqe.cdw10 = 0;
        sqe.cdw11 = 0;
        sqe.cdw12 = 0;
        io_submit(&sqe);
    }
    // SAFETY: Reading the first byte of the mapped 512-byte NVMe sector buffer (`sec_phys`).
    let first = unsafe { core::ptr::read_volatile(pa_to_va(sec_phys)) };
    if first != 0x5A {
        panic!("NVME_HW: sector first_byte drift");
    }
    // SAFETY: Verifying all 512 bytes in the mapped NVMe sector buffer (`sec_phys`).
    unsafe {
        let sec_va = pa_to_va(sec_phys);
        let mut i = 1usize;
        while i < NVME_BLOCK_SIZE {
            let got = core::ptr::read_volatile(sec_va.add(i));
            let want = 0x5Au8 ^ (i as u8);
            if got != want {
                panic!("NVME_HW: sector data drift");
            }
            i += 1;
        }
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"NVME_HW sector OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&[first], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let _ = found_addr;
    let _ = bar0;
    let _ = next_cid;
}

// ---------------------------------------------------------------------------
// TASK-107: legacy virtio-pci virtqueue sector round-trip (real DMA)
// DMA lives in a usable physical RAM window (BootInfo), accessed via
// physical_memory_offset — not kernel .bss (which has a separate map).
// Layout in DMA window for QEMU legacy default qsz=256:
//   desc: 256*16 = 4096
//   avail: 4+512 = 516  → used = align(4612) = 8192
//   used ring fits in next 4K → queue ends ~12K
//   [0x4000) header, [0x4010) data 512B, [0x4210] status
// ---------------------------------------------------------------------------

pub(crate) const VQ_SIZE: u16 = 256;
pub(crate) const VQ_ALIGN: u64 = 4096;
pub(crate) const DMA_Q_OFF: u64 = 0;
pub(crate) const DMA_HDR_OFF: u64 = 0x4000;
pub(crate) const DMA_DATA_OFF: u64 = 0x4010;
pub(crate) const DMA_ST_OFF: u64 = 0x4210;
pub(crate) const DMA_ZERO_LEN: usize = 0x5000;

/// Write then read sector 0 via legacy virtqueue; return data[0].
pub(crate) fn virtio_legacy_sector_roundtrip(io_base: u16) -> u8 {
    use core::sync::atomic::{fence, Ordering};
    use proteus_contracts::virtio_blk_req_type;
    use proteus_contracts::virtio_blk_status_byte;

    let dma_phys = dma_phys_base();
    let q_pa = dma_phys + DMA_Q_OFF;
    let hdr_pa = dma_phys + DMA_HDR_OFF;
    let data_pa = dma_phys + DMA_DATA_OFF;
    let st_pa = dma_phys + DMA_ST_OFF;

    // Zero DMA window via physical map.
    // SAFETY: Zeroing the 20 KiB legacy virtio-blk DMA window (`dma_phys..dma_phys+0x5000`) and poisoning status byte.
    unsafe {
        let base = pa_to_va(dma_phys);
        let mut i = 0usize;
        while i < DMA_ZERO_LEN {
            core::ptr::write_volatile(base.add(i), 0);
            i += 1;
        }
        core::ptr::write_volatile(pa_to_va(st_pa), 0xff);
    }

    // DMA self-test via physical map.
    // SAFETY: Probing writability of the mapped DMA data buffer (`data_pa`).
    unsafe {
        let p = pa_to_va(data_pa);
        core::ptr::write_volatile(p, 0x5A);
        if core::ptr::read_volatile(p) != 0x5A {
            panic!("VIRTIO_HW sector: DMA window not writable");
        }
        core::ptr::write_volatile(p, 0);
    }

    // Legacy bring-up: features + queue PFN + DRIVER_OK.
    // Accept host feature low 24 bits (device-type + transport).
    // SAFETY: Programming legacy virtio-blk status, features, and queue PFN over I/O ports (`io_base`).
    unsafe {
        outb(io_base + 18, 0);
        outb(io_base + 18, 1);
        outb(io_base + 18, 3);
        let host_feat = inl(io_base + 0);
        // Negotiate no optional features (basic IN/OUT always work).
        let _ = host_feat;
        outl(io_base + 4, 0);
        outw(io_base + 14, 0); // queue_sel
        // QEMU legacy: QueueNum is the fixed queue size (typically 256),
        // not a programmable field. Layout MUST use this size.
        let qsz = inw(io_base + 12);
        if qsz != VQ_SIZE {
            let mut line = [0u8; 40];
            let mut pos = 0usize;
            let pfx = b"VIRTIO_HW fail qsz=";
            line[..pfx.len()].copy_from_slice(pfx);
            pos += pfx.len();
            pos += dec_u64(qsz as u64, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
            panic!("VIRTIO_HW sector: unexpected device queue size");
        }
        let pfn = (q_pa >> 12) as u32;
        if pfn == 0 {
            panic!("VIRTIO_HW sector: zero PFN");
        }
        outl(io_base + 8, pfn);
        outb(io_base + 18, 1 | 2 | 4);
    }

    let desc_off = 0u64;
    let avail_off = (VQ_SIZE as u64) * 16; // 4096
    // used = align_up(avail + 4 + 2*qsz, 4096) = align_up(4612)=8192
    let used_off = {
        let raw = avail_off + 4 + 2 * (VQ_SIZE as u64);
        (raw + VQ_ALIGN - 1) & !(VQ_ALIGN - 1)
    };

    // Pattern for write.
    // SAFETY: Writing 512-byte test pattern into the mapped virtio-blk data buffer (`data_pa`).
    unsafe {
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            core::ptr::write_volatile(d.add(i), 0xA5 ^ (i as u8));
            i += 1;
        }
    }

    virtio_legacy_submit(
        io_base,
        q_pa,
        desc_off,
        avail_off,
        used_off,
        hdr_pa,
        data_pa,
        st_pa,
        virtio_blk_req_type::OUT,
        0,
        false,
        0, // first submit: avail starts 0, expect used 1
    );
    // SAFETY: Reading the 1-byte completion status written by virtio-blk at `st_pa`.
    let st = unsafe { core::ptr::read_volatile(pa_to_va(st_pa)) };
    if st != virtio_blk_status_byte::OK {
        panic!("VIRTIO_HW sector: write status not OK");
    }

    // Clear data, READ sector 0.
    // SAFETY: Clearing the 512-byte data buffer (`data_pa`) and resetting status byte (`st_pa`) before DMA READ.
    unsafe {
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            core::ptr::write_volatile(d.add(i), 0);
            i += 1;
        }
        core::ptr::write_volatile(pa_to_va(st_pa), 0xff);
    }
    virtio_legacy_submit(
        io_base,
        q_pa,
        desc_off,
        avail_off,
        used_off,
        hdr_pa,
        data_pa,
        st_pa,
        virtio_blk_req_type::IN,
        0,
        true,
        1, // second submit: avail was 1, expect used 2
    );
    // SAFETY: Reading the 1-byte completion status written by virtio-blk at `st_pa`.
    let st = unsafe { core::ptr::read_volatile(pa_to_va(st_pa)) };
    if st != virtio_blk_status_byte::OK {
        panic!("VIRTIO_HW sector: read status not OK");
    }

    // SAFETY: Verifying all 512 bytes in the mapped virtio-blk data buffer (`data_pa`) and returning byte 0.
    unsafe {
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            let got = core::ptr::read_volatile(d.add(i));
            let expect = 0xA5u8 ^ (i as u8);
            if got != expect {
                panic!("VIRTIO_HW sector: data byte drift");
            }
            i += 1;
        }
        fence(Ordering::SeqCst);
        core::ptr::read_volatile(d)
    }
}

pub(crate) fn virtio_legacy_submit(
    io_base: u16,
    q_pa: u64,
    desc_off: u64,
    avail_off: u64,
    used_off: u64,
    hdr_pa: u64,
    data_pa: u64,
    st_pa: u64,
    req_type: u32,
    sector: u64,
    data_device_write: bool,
    prev_avail_idx: u16,
) {
    use core::sync::atomic::{fence, Ordering};

    // Header in DMA.
    // SAFETY: Writing the 16-byte virtio_blk_outhdr into the mapped DMA header buffer (`hdr_pa`).
    unsafe {
        let h = pa_to_va(hdr_pa);
        let t = req_type.to_le_bytes();
        let mut i = 0;
        while i < 4 {
            core::ptr::write_volatile(h.add(i), t[i]);
            i += 1;
        }
        i = 0;
        while i < 4 {
            core::ptr::write_volatile(h.add(4 + i), 0);
            i += 1;
        }
        let s = sector.to_le_bytes();
        i = 0;
        while i < 8 {
            core::ptr::write_volatile(h.add(8 + i), s[i]);
            i += 1;
        }
    }

    let q = pa_to_va(q_pa);
    // desc 0 header
    write_desc_phys(q, desc_off, hdr_pa, 16, 1, 1);
    let dflags: u16 = if data_device_write { 1 | 2 } else { 1 };
    write_desc_phys(q, desc_off + 16, data_pa, 512, dflags, 2);
    write_desc_phys(q, desc_off + 32, st_pa, 1, 2, 0);

    // avail
    let old_idx = prev_avail_idx;
    let slot = (old_idx as usize) & (VQ_SIZE as usize - 1);
    // SAFETY: Publishing head descriptor 0 into `avail.ring[slot]` and advancing `avail.idx` in the mapped virtqueue (`q`).
    unsafe {
        let ring = q.add(avail_off as usize + 4 + slot * 2);
        core::ptr::write_volatile(ring, 0);
        core::ptr::write_volatile(ring.add(1), 0);
        let new_idx = old_idx.wrapping_add(1);
        let ib = new_idx.to_le_bytes();
        core::ptr::write_volatile(q.add(avail_off as usize + 2), ib[0]);
        core::ptr::write_volatile(q.add(avail_off as usize + 3), ib[1]);
    }

    fence(Ordering::SeqCst);
    // SAFETY: Kicking queue 0 on legacy virtio-blk notify I/O port (`io_base + 16`).
    unsafe {
        outw(io_base + 16, 0);
    }

    let target = prev_avail_idx.wrapping_add(1);
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        // SAFETY: Reading volatile 16-bit `used.idx` from the mapped virtqueue (`q`).
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == target {
            break;
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            // Dump used.idx so the serial log diagnoses the hang.
            let mut line = [0u8; 40];
            let mut pos = 0usize;
            let pfx = b"VIRTIO_HW fail used=";
            line[..pfx.len()].copy_from_slice(pfx);
            pos += pfx.len();
            pos += dec_u64(uidx as u64, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
            panic!("VIRTIO_HW sector: completion timeout");
        }
        core::hint::spin_loop();
    }
}

pub(crate) fn write_desc_phys(q: *mut u8, off: u64, addr: u64, len: u32, flags: u16, next: u16) {
    // SAFETY: Writing a 16-byte virtqueue descriptor at offset `off` inside the mapped virtqueue page `q`.
    unsafe {
        let p = q.add(off as usize);
        let a = addr.to_le_bytes();
        let mut i = 0;
        while i < 8 {
            core::ptr::write_volatile(p.add(i), a[i]);
            i += 1;
        }
        let l = len.to_le_bytes();
        i = 0;
        while i < 4 {
            core::ptr::write_volatile(p.add(8 + i), l[i]);
            i += 1;
        }
        let f = flags.to_le_bytes();
        core::ptr::write_volatile(p.add(12), f[0]);
        core::ptr::write_volatile(p.add(13), f[1]);
        let n = next.to_le_bytes();
        core::ptr::write_volatile(p.add(14), n[0]);
        core::ptr::write_volatile(p.add(15), n[1]);
    }
}

