//! Hardware-truth PCI/MMIO/DMA network drivers (VirtIO-net and Intel e1000 hub round-trips).

pub(crate) use crate::*;


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
            // SAFETY: Running at CPL=0; `rx_io` is a PCI-enumerated VirtIO-net BAR0 I/O base and offsets +18 and +20..26 are valid 8-bit device registers.
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
    // SAFETY: Running at CPL=0; `rx_io` is a validated VirtIO-net BAR0 I/O port base and `rx_q_pa >> 12` points to a 4 KiB-aligned page inside the reserved DMA window.
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
    // SAFETY: `rx_q` is derived via `pa_to_va` from the 16 KiB-reserved `rx_q_pa` DMA region; `avail_off + 2` and `avail_off + 4` are 2-byte aligned and in bounds.
    unsafe {
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 4), 0);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 5), 0);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 2), 1);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 3), 0);
    }
    fence(Ordering::SeqCst);
    // SAFETY: Running at CPL=0; `rx_io + 18` (status) and `rx_io + 16` (queue notify) are valid I/O ports on the initialized RX VirtIO-net PCI function.
    unsafe {
        outb(rx_io + 18, 1 | 2 | 4); // DRIVER_OK
        outw(rx_io + 16, Q_RX); // kick RX with buffer available
    }

    // ---- TX peer: send one frame on queue 1 ----
    // SAFETY: Running at CPL=0; `tx_io` is a validated VirtIO-net BAR0 I/O port base and `tx_q_pa >> 12` points to a 4 KiB-aligned page inside the reserved DMA window.
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
    // SAFETY: `tx_q` is derived via `pa_to_va` from the 16 KiB-reserved `tx_q_pa` DMA region; `avail_off + 2` and `avail_off + 4` are 2-byte aligned and in bounds.
    unsafe {
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 4), 0);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 5), 0);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 2), 1);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 3), 0);
    }
    fence(Ordering::SeqCst);
    // SAFETY: Running at CPL=0; `tx_io + 16` is the 16-bit Queue Notify port for the initialized TX VirtIO-net PCI function after descriptors are published.
    unsafe {
        outw(tx_io + 16, Q_TX);
    }

    // Wait TX completion.
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        // SAFETY: `tx_q + used_off + 2` is 2-byte aligned and lies within the 16 KiB `tx_q_pa` DMA allocation mapped via `pa_to_va`; volatile read observes device DMA completion.
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
        // SAFETY: `rx_q + used_off + 2` is 2-byte aligned and lies within the 16 KiB `rx_q_pa` DMA allocation mapped via `pa_to_va`; volatile read observes device DMA completion.
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == 1 {
            // used.ring[0].len at used_off + 4 + 4 (id u32, len u32)
            // SAFETY: `rx_q + used_off + 8` is 4-byte aligned and lies within the mapped `rx_q_pa` used ring table after `used.idx != 0` confirmed a completed entry.
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
    // SAFETY: `bar0` is the PCI-discovered e1000 MMIO BAR0 base mapped uncached via `ensure_mmio_page`, and `CTRL`/`IMC`/`ICR` offsets are 4-byte aligned within the 128 KiB BAR.
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
        // SAFETY: `bar0 + E1000_REG_EERD` (+0x0014) is a 4-byte-aligned 32-bit register in the uncached-mapped e1000 BAR0 MMIO page.
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

    // SAFETY: `bar0` is uncached-mapped via `ensure_mmio_page`, `ring_pa` and `buf_va` lie in the reserved DMA window, and TX descriptor 0 status byte (+12) is read volatile to observe hardware DMA completion.
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
    // SAFETY: `rx_bar0` is the second e1000 PCI function's MMIO BAR0 base, mapped uncached via `ensure_mmio_page`, with 4-byte-aligned register offsets.
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
    // SAFETY: `rx_ring_va` and `rx_buf_va` are disjoint subregions of the 128 KiB reserved DMA window mapped via `pa_to_va`, and `rx_bar0` is uncached-mapped.
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
    // SAFETY: `buf_va`, `ring_va` (slot 1 at +16), `rx_ring_va`, and `rx_buf_va` all reside within the reserved DMA window mapped via `pa_to_va`, and `bar0`/`rx_bar0` are uncached-mapped MMIO.
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
        // SAFETY: `rx_ring_va + 8..10` lies within the 16-byte RX descriptor 0 in mapped DMA RAM after the DD bit confirmed hardware completion.
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
