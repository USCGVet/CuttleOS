//! Live guest network control plane (modern and legacy VirtIO-net UDP/TCP/ICMP service loops).

pub(crate) use crate::*;


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
    use cuttle_contracts::{
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
    // SAFETY: Running at CPL=0 with initialized page-table pool; `common_bar`, `notify_bar`, and `devcfg_bar` are PCI-validated MMIO BAR addresses.
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
    // SAFETY: `dma..dma+0xC000` (48 KiB) fits within the 128 KiB physical DMA pool mapped via `pa_to_va` and is zeroed before enabling the device queues.
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
    // SAFETY: `rx_q_virt` points to the 4 KiB-aligned RX virtqueue page in the reserved DMA window and all `i < VN_RX_BUFFERS` indices are within the 64-entry ring bounds.
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
    // SAFETY: `n.notify + off` lies within the uncached-mapped VirtIO notify BAR page and is 2-byte aligned per the PCI capability multiplier.
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
    // SAFETY: `tx_buf_virt` and `n.tx_q_virt` lie within the reserved 48 KiB DMA window (`VN_HDR + frame.len() <= 2048`), and single-threaded access prevents ring races.
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
    // SAFETY: `n.rx_q_virt + VN_USED_OFF + 2` is 2-byte aligned inside the mapped RX virtqueue page; volatile load prevents compiler caching across poll iterations.
    let cur = unsafe { core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16) };
    if cur == n.rx_used_seen {
        return None;
    }
    let slot = (n.rx_used_seen as u64) & (VN_QSIZE as u64 - 1);
    // SAFETY: `slot = (rx_used_seen % VN_QSIZE) < 64`, so `VN_USED_OFF + 4 + slot * 8` is 4-byte aligned and in bounds of the mapped RX virtqueue page.
    let id = unsafe {
        core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 4 + slot * 8) as *const u32)
    } as u16;
    // SAFETY: `slot < 64`, so `VN_USED_OFF + 4 + slot * 8 + 4` is 4-byte aligned and in bounds of the mapped RX virtqueue page.
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
    // SAFETY: `slot = (rx_avail_next % VN_QSIZE) < 64` and `n.rx_q_virt + VN_AVAIL_OFF` is 2-byte aligned inside the mapped RX virtqueue DMA page.
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
// HTTP GET /status|/healthz|/ with "CUTTLE-STATUS boots=N\n".
// Bounded loop: the service window is a boot-phase activity, then
// the kernel proceeds to HALT as usual.
// ---------------------------------------------------------------------------

/// Boot counter published by banner_continuity for the status payload.
pub(crate) static CONTINUITY_BOOT_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

pub(crate) const UDP_SVC_IP: [u8; 4] = [10, 0, 2, 15];
pub(crate) const UDP_SVC_PORT: u16 = 8080;
pub(crate) const UDP_SVC_VIRTIO_HDR: usize = 12;

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

/// Serve HTTPS on port 443 from `svc`: seed the TLS CSPRNG from hardware
/// entropy, derive this node's TLS identity, build the rustls server
/// configuration and hand it to the service. Emits
/// `HTTPS UP port=443 tls13=rustls cert_sha256=<hex64>`; clients pin that
/// certificate (fetch it once, compare this fingerprint out of band).
pub(crate) fn enable_https(svc: &mut target_enterprise::LivedNet, mac: [u8; 6]) {
    use target_enterprise::https::{server_config, ServerIdentity};
    use target_enterprise::tls_provider::{seed_system_rng, system_provider};

    seed_system_rng(tls_rng_seed());
    let identity = ServerIdentity::derive(&derive_runtime_tls_identity_secret(mac), mac);
    match server_config(&identity, system_provider()) {
        Ok(config) => {
            svc.enable_tls(config);
            let mut line = [0u8; 128];
            let prefix = b"HTTPS UP port=443 tls13=rustls cert_sha256=";
            line[..prefix.len()].copy_from_slice(prefix);
            let mut pos = prefix.len();
            pos += hex_encode(&identity.fingerprint(), 32, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
        Err(_) => serial_write_str("HTTPS DISABLED: TLS configuration rejected\n"),
    }
}

/// Service loop over the modern virtio-net driver.
#[inline(never)]
pub(crate) fn service_udp_status_modern(n: &mut VnetModern) {
    let mac = n.mac;
    let mut svc = match derive_runtime_net_auth_key(mac) {
        Some(k) => target_enterprise::LivedNet::with_auth_key(mac, k),
        None => target_enterprise::LivedNet::new_unprovisioned(mac),
    };
    enable_https(&mut svc, mac);
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
            // SAFETY: `n.tx_q_virt + VN_USED_OFF + 2` is 2-byte aligned inside the mapped TX virtqueue page; volatile load observes device completion.
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
        let mut uf = [0u8; 128];
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
        let mut eth = [0u8; 128];
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
            // SAFETY: `n.rx_q_virt + VN_USED_OFF + 2` is 2-byte aligned inside the mapped RX virtqueue page; volatile load prevents compiler caching across poll iterations.
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
        // SAFETY: `n.rx_q_virt + VN_USED_OFF + 2` is 2-byte aligned inside the mapped RX virtqueue page; volatile load prevents compiler caching across poll iterations.
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
            let max_idle: u64 = 2_000_000;
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
                sh.legacy_seal_key = derive_runtime_legacy_seal_key();
                sh.attest_key = derive_runtime_attest_key();
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
#[inline(never)]
pub(crate) fn service_udp_status_legacy() {
    use core::sync::atomic::{fence, Ordering};
    use cuttle_contracts::{
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
                // SAFETY: Running at CPL=0; `base` is a PCI-validated legacy VirtIO-net I/O BAR0 base and offsets +18 and +20..26 are valid 8-bit device registers.
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
    // SAFETY: Running at CPL=0; `dma..dma+0xC000` lies within the 128 KiB reserved DMA window mapped via `pa_to_va`, and `base` is the validated PCI I/O BAR0.
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
        write_desc_phys(
            rx_q,
            (i as u64) * 16,
            rx_bufs_pa + (i as u64) * (RX_BUF_LEN as u64),
            RX_BUF_LEN,
            2,
            0,
        );
        // SAFETY: `rx_q` is mapped via `pa_to_va` from the 16 KiB RX queue DMA allocation and `i < N_RX_BUFS (8) < VQ_SIZE (256)` is in bounds and 2-byte aligned.
        unsafe {
            core::ptr::write_volatile(rx_q.add(avail_off as usize + 4 + (i as usize) * 2), i as u8);
            core::ptr::write_volatile(
                rx_q.add(avail_off as usize + 4 + (i as usize) * 2 + 1),
                (i >> 8) as u8,
            );
        }
        i += 1;
    }
    // SAFETY: `rx_q + avail_off + 2` is 2-byte aligned and lies within the mapped 16 KiB RX virtqueue DMA allocation.
    unsafe {
        // avail.idx = N_RX_BUFS
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 2), N_RX_BUFS as u8);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 3), (N_RX_BUFS >> 8) as u8);
    }
    fence(Ordering::SeqCst);
    // SAFETY: Running at CPL=0; `base + 18` (status) and `base + 16` (queue notify) are valid I/O ports on the initialized legacy VirtIO-net device.
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
        let payload = b"CUTTLE-HELLO\n";
        let plen = payload.len();
        let udp_len = (8 + plen) as u16;
        let mut udp_full = [0u8; 128];
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
        let mut eth = [0u8; 128];
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
        let mut uf2 = [0u8; 128];
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
        let mut eth2 = [0u8; 128];
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

    let mut svc = match derive_runtime_net_auth_key(mac) {
        Some(k) => target_enterprise::LivedNet::with_auth_key(mac, k),
        None => target_enterprise::LivedNet::new_unprovisioned(mac),
    };
    enable_https(&mut svc, mac);

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
        write_desc_phys(rx_q, (desc_id as u64) * 16, buf_pa, RX_BUF_LEN, 2, 0);
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
                sh.legacy_seal_key = derive_runtime_legacy_seal_key();
                sh.attest_key = derive_runtime_attest_key();
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
    // SAFETY: `tx_buf_pa` is a 2048-byte buffer inside the reserved DMA window mapped via `pa_to_va`, and `12 + frame.len() <= 1526 < 2048` guarantees all writes are in bounds.
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
    write_desc_phys(tx_q, (slot as u64) * 16, tx_buf_pa, total, 0, 0);
    fence(Ordering::SeqCst);
    // SAFETY: `tx_q` lies in the mapped DMA window (`slot < VQ_SIZE`), and `base + 16` is the valid CPL=0 Queue Notify I/O port.
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
        if spins > 200_000 {
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
