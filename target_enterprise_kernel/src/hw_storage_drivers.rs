//! Hardware-truth PCI/MMIO/DMA block drivers (VirtIO-blk, AHCI, NVMe) and WAL continuity.

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
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_hw() {
    use cuttle_contracts::{
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
        // SAFETY: Running at CPL=0; `io_base` is a validated PCI BAR0 I/O port base and offset +18 is the 8-bit VirtIO device status port (no memory aliasing).
        unsafe {
            outb(base + VIRTIO_PCI_STATUS, 0);
            outb(base + VIRTIO_PCI_STATUS, 1); // ACKNOWLEDGE
            outb(base + VIRTIO_PCI_STATUS, 3); // ACK | DRIVER
        }
        // capacity is u64 LE at device-config offset 0 → BAR+20.
        // SAFETY: Running at CPL=0; `io_base + 20` is a 4-byte-aligned legacy VirtIO-blk config port in PCI I/O space (no memory aliasing).
        let lo = unsafe { inl(base + VIRTIO_PCI_CONFIG) };
        // SAFETY: Running at CPL=0; `io_base + 24` is the 4-byte-aligned upper capacity dword port in the validated PCI BAR0 I/O window.
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
#[derive(Clone, Copy)]
pub(crate) struct AhciHwPort {
    pub(crate) abar: u64,
    pub(crate) pbase: u64,
    pub(crate) pbase_va: u64,
    pub(crate) clb_pa: u64,
    pub(crate) ctba_pa: u64,
    pub(crate) data_pa: u64,
    pub(crate) slot: u8,
}

static AHCI_CACHED_PBASE_VA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static AHCI_CACHED_CLB_PA: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static AHCI_CACHED_EMERG_CTBA_PA: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static AHCI_CACHED_EMERG_DATA_PA: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);
static AHCI_CACHED_EMERG_SLOT: core::sync::atomic::AtomicU8 = core::sync::atomic::AtomicU8::new(0);
static AHCI_CACHED_LBA48: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

// SAFETY: Caller must supply a pre-mapped uncached MMIO virtual base (`pbase_va`) and 4-byte-aligned register offset.
#[inline]
unsafe fn port_mmio_read32(pbase_va: u64, reg_off: u64) -> u32 {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `pbase_va` was mapped uncached via `ensure_mmio_page` during `probe_start_inner`, and `reg_off` is 4-byte aligned within the 0x80-byte AHCI port window.
    let val = unsafe { core::ptr::read_volatile((pbase_va + reg_off) as *const u32) };
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    val
}

// SAFETY: Caller must supply a pre-mapped uncached MMIO virtual base (`pbase_va`) and 4-byte-aligned register offset.
#[inline]
unsafe fn port_mmio_write32(pbase_va: u64, reg_off: u64, val: u32) {
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `pbase_va` was mapped uncached via `ensure_mmio_page` during `probe_start_inner`, and `reg_off` is 4-byte aligned within the 0x80-byte AHCI port window.
    unsafe {
        core::ptr::write_volatile((pbase_va + reg_off) as *mut u32, val);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

/// Non-panicking best-effort emergency 512-byte sector write for `#[panic_handler]`.
///
/// Uses a dedicated command slot (`slot 1` when `CAP.NCS >= 2`), dedicated DMA command table
/// (`AHCI_CTBA_EMERG_OFF`) and sector buffer (`AHCI_DATA_EMERG_OFF`), and the pre-mapped port
/// MMIO virtual address (`AHCI_CACHED_PBASE_VA`) so a panic raised mid-commit or while holding
/// `PT_MOD_LOCK` never deadlocks on page-table locking or overwrites Slot 0's buffers.
pub(crate) fn try_write_ahci_sector_emergency(lba: u64, data: &[u8; 512]) -> bool {
    use core::sync::atomic::Ordering;
    use cuttle_contracts::{
        AhciCmd, AhciCmdHeader, AhciFis, AhciPrdt, AHCI_CFL_H2D, AHCI_CMD_HDR_LEN,
        AHCI_FIS_H2D_LEN, AHCI_PRDT_LEN,
    };
    use target_enterprise::ahci_cmd::AhciCmdImpl;
    use target_enterprise::ahci_fis::{build_rw_dma_fis, AhciFisImpl};

    const PORT_IS: u64 = 0x10;
    const PORT_TFD: u64 = 0x20;
    const PORT_CI: u64 = 0x38;

    let pbase_va = AHCI_CACHED_PBASE_VA.load(Ordering::Acquire);
    let clb_pa = AHCI_CACHED_CLB_PA.load(Ordering::Acquire);
    let ctba_pa = AHCI_CACHED_EMERG_CTBA_PA.load(Ordering::Acquire);
    let data_pa = AHCI_CACHED_EMERG_DATA_PA.load(Ordering::Acquire);
    let slot_idx = AHCI_CACHED_EMERG_SLOT.load(Ordering::Acquire);
    let lba48 = AHCI_CACHED_LBA48.load(Ordering::Acquire);
    if pbase_va == 0
        || clb_pa == 0
        || ctba_pa == 0
        || data_pa == 0
        || slot_idx >= 32
        || phys_map_offset() == 0
    {
        return false;
    }

    let Ok(fis_params) = build_rw_dma_fis(lba, 1, true, lba48, 0) else {
        return false;
    };
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    if AhciFisImpl::encode_h2d(&fis_params, &mut fis).is_err() {
        return false;
    }
    let hdr = AhciCmdHeader {
        cfl: AHCI_CFL_H2D,
        write: true,
        pmp: 0,
        prdtl: 1,
        prdbc: 0,
        ctba: ctba_pa,
    };
    let mut hbuf = [0u8; AHCI_CMD_HDR_LEN];
    if AhciCmdImpl::encode_header(&hdr, &mut hbuf).is_err() {
        return false;
    }
    let prdt = AhciPrdt {
        dba: data_pa,
        byte_count: 512,
        ioc: true,
    };
    let mut pbuf = [0u8; AHCI_PRDT_LEN];
    if AhciCmdImpl::encode_prdt(&prdt, &mut pbuf).is_err() {
        return false;
    }

    let slot_bit = 1u32 << (slot_idx as u32);
    let cl_slot_off = (slot_idx as usize) * AHCI_CMD_HDR_LEN;

    // SAFETY: `pbase_va` was pre-mapped uncached and `clb_pa`, `ctba_pa`, `data_pa` are disjoint regions in mapped DMA RAM.
    unsafe {
        let mut spins = 0u32;
        while port_mmio_read32(pbase_va, PORT_CI) != 0
            || (port_mmio_read32(pbase_va, PORT_TFD) & 0x88) != 0
        {
            spins = spins.wrapping_add(1);
            if spins > 2_000_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            core::ptr::write_volatile(d.add(i), data[i]);
            i += 1;
        }
        let ct = pa_to_va(ctba_pa);
        i = 0;
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
        let cl = pa_to_va(clb_pa).add(cl_slot_off);
        i = 0;
        while i < AHCI_CMD_HDR_LEN {
            core::ptr::write_volatile(cl.add(i), hbuf[i]);
            i += 1;
        }
        port_mmio_write32(pbase_va, PORT_IS, 0xFFFF_FFFF);
        port_mmio_write32(pbase_va, PORT_CI, slot_bit);
        spins = 0;
        while (port_mmio_read32(pbase_va, PORT_CI) & slot_bit) != 0 {
            spins = spins.wrapping_add(1);
            if spins > 4_000_000 {
                return false;
            }
            core::hint::spin_loop();
        }
        (port_mmio_read32(pbase_va, PORT_TFD) & 0x21) == 0
    }
}

impl AhciHwPort {
    /// PCI scan for the AHCI HBA, enable MMIO + bus mastering, start the
    /// port command engine on the first port with a device present, and emit
    /// the boot-time `AHCI_HW probe OK` serial banner.
    pub(crate) fn probe_start() -> Self {
        Self::probe_start_inner(true)
    }

    /// Quiet variant of [`Self::probe_start`] for runtime persistence (`persist_shell_to_ahci`
    /// and `restore_shell_from_ahci`) so every SQL/VFS disk commit does not spam `COM1`.
    pub(crate) fn probe_start_quiet() -> Self {
        Self::probe_start_inner(false)
    }

    fn probe_start_inner(emit_banner: bool) -> Self {
        use cuttle_contracts::{
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
        // SAFETY: `abar` is a PCI-discovered AHCI BAR5 MMIO base mapped uncached via `ensure_mmio_page`, and `REG_GHC` (+0x04) is a 4-byte-aligned 32-bit HBA register.
        unsafe {
            let ghc = mmio_read32(abar + REG_GHC);
            mmio_write32(abar + REG_GHC, ghc | GHC_AE);
        }
        // SAFETY: `abar + REG_CAP` (+0x00) is a 4-byte-aligned 32-bit HBA capability register in the uncached-mapped AHCI ABAR MMIO page.
        let cap = unsafe { mmio_read32(abar + REG_CAP) };
        // SAFETY: `abar + REG_PI` (+0x0C) is a 4-byte-aligned 32-bit register in the uncached-mapped AHCI ABAR MMIO page.
        let pi = unsafe { mmio_read32(abar + REG_PI) };
        // SAFETY: `abar + REG_VS` (+0x10) is a 4-byte-aligned 32-bit register in the uncached-mapped AHCI ABAR MMIO page.
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
        if emit_banner {
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
                // SAFETY: `pbase` (`abar + 0x100 + p * 0x80` for `p < 32`) lies within the 4 KiB AHCI ABAR MMIO space and `PORT_SSTS` (+0x28) is 4-byte aligned.
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
        // Pre-map both edge pages of the 0x80-byte port register block once so neither
        // normal DMA polling nor the emergency panic-dump writer ever needs `PT_MOD_LOCK`.
        // SAFETY: Running at CPL=0 with active 4-level paging; `pbase..pbase+0x7C` is the PCI-discovered AHCI port MMIO block.
        let pbase_va = unsafe {
            let page_va = ensure_mmio_page(pbase) as u64;
            let _ = ensure_mmio_page(pbase + 0x7C);
            page_va + (pbase & 0xFFF)
        };

        use target_enterprise::memory::dma_layout::{
            AHCI_CLB_OFF, AHCI_CTBA_EMERG_OFF, AHCI_CTBA_SLOT0_OFF, AHCI_CTRL_ZERO_BYTES,
            AHCI_DATA_EMERG_OFF, AHCI_DATA_SLOT0_OFF, AHCI_FB_OFF,
        };
        let dma_root = dma_phys_base();
        let clb_pa = dma_root + AHCI_CLB_OFF;
        let fb_pa = dma_root + AHCI_FB_OFF;
        let ctba_pa = dma_root + AHCI_CTBA_SLOT0_OFF;
        let emerg_ctba_pa = dma_root + AHCI_CTBA_EMERG_OFF;
        let emerg_data_pa = dma_root + AHCI_DATA_EMERG_OFF;
        let data_pa = dma_root + AHCI_DATA_SLOT0_OFF;
        let emerg_slot: u8 = if ((cap >> 8) & 0x1F) >= 1 { 1 } else { 0 };

        // SAFETY: `clb_pa..clb_pa+AHCI_CTRL_ZERO_BYTES` lies within the audited 48 KiB `AHCI_REGION` mapped via `pa_to_va`, and the port engine is stopped (`ST=0, CR=0`) before reprogramming `CLB`/`FB`.
        unsafe {
            let base = pa_to_va(clb_pa);
            let mut i = 0usize;
            while i < AHCI_CTRL_ZERO_BYTES {
                core::ptr::write_volatile(base.add(i), 0);
                i += 1;
            }
            let mut c = port_mmio_read32(pbase_va, PORT_CMD);
            c &= !(PX_CMD_ST | PX_CMD_FRE);
            port_mmio_write32(pbase_va, PORT_CMD, c);
            let mut spins = 0u32;
            loop {
                let c2 = port_mmio_read32(pbase_va, PORT_CMD);
                if c2 & (PX_CMD_CR | PX_CMD_FR) == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: port stop timeout");
                }
                core::hint::spin_loop();
            }
            port_mmio_write32(pbase_va, PORT_CLB, clb_pa as u32);
            port_mmio_write32(pbase_va, PORT_CLBU, (clb_pa >> 32) as u32);
            port_mmio_write32(pbase_va, PORT_FB, fb_pa as u32);
            port_mmio_write32(pbase_va, PORT_FBU, (fb_pa >> 32) as u32);
            port_mmio_write32(pbase_va, PORT_SERR, 0xFFFF_FFFF);
            port_mmio_write32(pbase_va, PORT_IS, 0xFFFF_FFFF);
            let mut c = port_mmio_read32(pbase_va, PORT_CMD);
            c |= PX_CMD_FRE;
            port_mmio_write32(pbase_va, PORT_CMD, c);
            spins = 0;
            loop {
                if port_mmio_read32(pbase_va, PORT_CMD) & PX_CMD_FR != 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: FRE start timeout");
                }
                core::hint::spin_loop();
            }
            c = port_mmio_read32(pbase_va, PORT_CMD);
            c |= PX_CMD_ST;
            port_mmio_write32(pbase_va, PORT_CMD, c);
        }

        AHCI_CACHED_PBASE_VA.store(pbase_va, core::sync::atomic::Ordering::Release);
        AHCI_CACHED_CLB_PA.store(clb_pa, core::sync::atomic::Ordering::Release);
        AHCI_CACHED_EMERG_CTBA_PA.store(emerg_ctba_pa, core::sync::atomic::Ordering::Release);
        AHCI_CACHED_EMERG_DATA_PA.store(emerg_data_pa, core::sync::atomic::Ordering::Release);
        AHCI_CACHED_EMERG_SLOT.store(emerg_slot, core::sync::atomic::Ordering::Release);

        AhciHwPort {
            abar,
            pbase,
            pbase_va,
            clb_pa,
            ctba_pa,
            data_pa,
            slot,
        }
    }

    /// Issue one H2D command in slot 0 against the running port with `prdtl` PRDT entries
    /// (`0` or `1`) transferring `prdt_bytes` bytes (`1..=32768`) and report how it ended.
    ///
    /// Completion is checked against everything the HBA reports: the port
    /// interrupt status error bits, the task-file error and device-fault bits,
    /// and, when `expect_bytes` is given, the byte count the device says it
    /// transferred. Nothing here panics, so a caller can fall back to another
    /// copy or refuse a commit.
    pub(crate) fn try_issue_slot0_bytes(
        &self,
        fis_params: &cuttle_contracts::H2dFisParams,
        write: bool,
        prdtl: u16,
        prdt_bytes: u32,
        expect_bytes: Option<u32>,
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use cuttle_contracts::{
            AhciCmd, AhciCmdHeader, AhciFis, AhciPrdt, AHCI_CFL_H2D, AHCI_CMD_HDR_LEN,
            AHCI_FIS_H2D_LEN, AHCI_PRDT_LEN,
        };
        use target_enterprise::ahci_cmd::AhciCmdImpl;
        use target_enterprise::ahci_fis::AhciFisImpl;
        use target_enterprise::memory::dma_layout::AHCI_MAX_BATCH_SECTORS;
        use target_enterprise::state_store::IoFault;

        const PORT_IS: u64 = 0x10;
        const PORT_TFD: u64 = 0x20;
        const PORT_CI: u64 = 0x38;
        /// PxIS: task-file error, host bus fatal, host bus data, interface fatal.
        const PORT_IS_ERRORS: u32 = (1 << 30) | (1 << 29) | (1 << 28) | (1 << 27);
        /// PxTFD status: ERR and DF.
        const TFD_ERR_OR_FAULT: u32 = 0x01 | 0x20;
        const MAX_DMA_BYTES: u32 = (AHCI_MAX_BATCH_SECTORS as u32) * 512;

        if prdtl > 1 || (prdtl == 1 && (prdt_bytes == 0 || prdt_bytes > MAX_DMA_BYTES)) {
            return Err(IoFault::OutOfRange);
        }

        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        if AhciFisImpl::encode_h2d(fis_params, &mut fis).is_err() {
            return Err(IoFault::OutOfRange);
        }
        let hdr = AhciCmdHeader {
            cfl: AHCI_CFL_H2D,
            write,
            pmp: 0,
            prdtl,
            prdbc: 0,
            ctba: self.ctba_pa,
        };
        let mut hbuf = [0u8; AHCI_CMD_HDR_LEN];
        if AhciCmdImpl::encode_header(&hdr, &mut hbuf).is_err() {
            return Err(IoFault::OutOfRange);
        }
        let mut pbuf = [0u8; AHCI_PRDT_LEN];
        if prdtl > 0 {
            let prdt = AhciPrdt {
                dba: self.data_pa,
                byte_count: prdt_bytes,
                ioc: true,
            };
            if AhciCmdImpl::encode_prdt(&prdt, &mut pbuf).is_err() {
                return Err(IoFault::OutOfRange);
            }
        }
        // Keep console input flowing while the disk is busy (see `SerialRxRing`).
        crate::serial_rx_pump();
        // SAFETY: `pbase_va` is pre-mapped uncached, `ctba_pa` and `clb_pa` are disjoint aligned subregions of the reserved DMA window mapped via `pa_to_va`, and slot 0 is idle (`PxCI & 1 == 0`) while we populate descriptors.
        unsafe {
            let mut spins = 0u32;
            loop {
                let busy = port_mmio_read32(self.pbase_va, PORT_TFD) & 0x88 != 0;
                let in_flight = port_mmio_read32(self.pbase_va, PORT_CI) & 1 != 0;
                if !busy && !in_flight {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    return Err(IoFault::Timeout);
                }
                core::hint::spin_loop();
            }
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
            if prdtl > 0 {
                i = 0;
                while i < AHCI_PRDT_LEN {
                    core::ptr::write_volatile(ct.add(0x80 + i), pbuf[i]);
                    i += 1;
                }
            }
            let cl = pa_to_va(self.clb_pa);
            i = 0;
            while i < AHCI_CMD_HDR_LEN {
                core::ptr::write_volatile(cl.add(i), hbuf[i]);
                i += 1;
            }
            port_mmio_write32(self.pbase_va, PORT_IS, 0xFFFF_FFFF);
            port_mmio_write32(self.pbase_va, PORT_CI, 1);
            spins = 0;
            loop {
                // On a task-file error the HBA leaves PxCI set, so the error
                // bits are the only prompt signal that the command is over.
                if port_mmio_read32(self.pbase_va, PORT_IS) & PORT_IS_ERRORS != 0 {
                    return Err(IoFault::DeviceError);
                }
                if port_mmio_read32(self.pbase_va, PORT_CI) & 1 == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 40_000_000 {
                    return Err(IoFault::Timeout);
                }
                if spins % 256 == 0 {
                    crate::serial_rx_pump();
                }
                core::hint::spin_loop();
            }
            if port_mmio_read32(self.pbase_va, PORT_TFD) & TFD_ERR_OR_FAULT != 0
                || port_mmio_read32(self.pbase_va, PORT_IS) & PORT_IS_ERRORS != 0
            {
                return Err(IoFault::DeviceError);
            }
            if let Some(want) = expect_bytes {
                // PRDBC: bytes the device transferred, DW1 of the command header.
                let prdbc = core::ptr::read_volatile(cl.add(4).cast::<u32>());
                if u32::from_le(prdbc) != want {
                    return Err(IoFault::DeviceError);
                }
            }
        }
        Ok(())
    }

    /// Single-sector wrapper around [`Self::try_issue_slot0_bytes`].
    pub(crate) fn try_issue_with_prdtl(
        &self,
        fis_params: &cuttle_contracts::H2dFisParams,
        write: bool,
        prdtl: u16,
        expect_bytes: Option<u32>,
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        let prdt_bytes = if prdtl > 0 { 512 } else { 0 };
        self.try_issue_slot0_bytes(fis_params, write, prdtl, prdt_bytes, expect_bytes)
    }

    /// Panicking form of [`Self::try_issue_with_prdtl`] for the boot self-tests,
    /// where a failed command means the banner cannot be proved.
    pub(crate) fn issue_with_prdtl(
        &self,
        fis_params: &cuttle_contracts::H2dFisParams,
        write: bool,
        prdtl: u16,
        tag: &[u8],
    ) {
        use target_enterprise::state_store::IoFault;
        let _ = tag;
        match self.try_issue_with_prdtl(fis_params, write, prdtl, None) {
            Ok(()) => {}
            Err(IoFault::Timeout) => panic!("AHCI_HW: command timeout"),
            Err(IoFault::OutOfRange) => panic!("AHCI_HW: command encode"),
            Err(_) => panic!("AHCI_HW: command TFD ERR"),
        }
    }

    /// Issue one 1-PRDT H2D DMA command in slot 0 against the running port.
    pub(crate) fn issue(&self, fis_params: &cuttle_contracts::H2dFisParams, write: bool, tag: &[u8]) {
        self.issue_with_prdtl(fis_params, write, 1, tag);
    }

    /// Issue non-data ATA `FLUSH CACHE` (`0xE7`, `PRDTL = 0`) as a write-order durability barrier.
    pub(crate) fn flush_cache(&self) {
        use target_enterprise::ahci_fis::build_flush_fis;
        let fl = build_flush_fis(false, 0).expect("flush fis");
        self.issue_with_prdtl(&fl, false, 0, b"flush");
    }

    /// Read the DMA data buffer back into a 512-byte array.
    pub(crate) fn drain_data(&self) -> [u8; 512] {
        let mut out = [0u8; 512];
        // SAFETY: `self.data_pa` points to the 32 KiB sector buffer in the reserved DMA window.
        unsafe {
            let d = pa_to_va(self.data_pa);
            core::ptr::copy_nonoverlapping(d, out.as_mut_ptr(), 512);
        }
        out
    }

    /// Fill the DMA data buffer from a 512-byte array.
    pub(crate) fn fill_data(&self, src: &[u8; 512]) {
        // SAFETY: `self.data_pa` points to the 32 KiB sector buffer in the reserved DMA window.
        unsafe {
            let d = pa_to_va(self.data_pa);
            core::ptr::copy_nonoverlapping(src.as_ptr(), d, 512);
        }
    }

    /// ATA WRITE DMA one 512-byte sector at `lba`.
    pub(crate) fn write_sector(&self, lba: u64, data: &[u8; 512]) {
        use target_enterprise::ahci_fis::build_rw_dma_fis;
        self.fill_data(data);
        let wr = build_rw_dma_fis(lba, 1, true, false, 0).expect("write_dma params");
        self.issue(&wr, true, b"write");
    }

    /// ATA `FLUSH CACHE` / `FLUSH CACHE EXT`, reporting failure.
    pub(crate) fn try_flush_cache(
        &self,
        lba48: bool,
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use target_enterprise::ahci_fis::build_flush_fis;
        use target_enterprise::state_store::IoFault;
        let fl = build_flush_fis(lba48, 0).map_err(|_| IoFault::OutOfRange)?;
        self.try_issue_slot0_bytes(&fl, false, 0, 0, None)
    }

    /// Multi-sector DMA write across one or more slices using `WRITE DMA EXT` (`lba48 = true`)
    /// or `WRITE DMA` (`lba48 = false`) in chunks of up to `AHCI_MAX_BATCH_SECTORS` (`64` sectors = `32 KiB`).
    pub(crate) fn try_write_sector_slices(
        &self,
        lba: u64,
        lba48: bool,
        slices: &[&[[u8; 512]]],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use target_enterprise::ahci_fis::build_rw_dma_fis;
        use target_enterprise::memory::dma_layout::AHCI_MAX_BATCH_SECTORS;
        use target_enterprise::state_store::IoFault;

        let mut cur_lba = lba;
        let mut s_idx = 0usize;
        let mut s_off = 0usize;
        while s_idx < slices.len() {
            if s_off >= slices[s_idx].len() {
                s_idx += 1;
                s_off = 0;
                continue;
            }
            let mut batch_secs = 0usize;
            // SAFETY: `self.data_pa..self.data_pa + 32 KiB` is the dedicated Slot 0 DMA buffer in mapped physical RAM, idle while Slot 0 is not in flight.
            unsafe {
                let d = pa_to_va(self.data_pa);
                while batch_secs < AHCI_MAX_BATCH_SECTORS && s_idx < slices.len() {
                    let rem_in_slice = slices[s_idx].len() - s_off;
                    if rem_in_slice == 0 {
                        s_idx += 1;
                        s_off = 0;
                        continue;
                    }
                    let take = rem_in_slice.min(AHCI_MAX_BATCH_SECTORS - batch_secs);
                    core::ptr::copy_nonoverlapping(
                        slices[s_idx][s_off].as_ptr(),
                        d.add(batch_secs * 512),
                        take * 512,
                    );
                    batch_secs += take;
                    s_off += take;
                }
            }
            if batch_secs == 0 {
                break;
            }
            let byte_count = (batch_secs as u32) * 512;
            let wr = build_rw_dma_fis(cur_lba, batch_secs as u16, true, lba48, 0)
                .map_err(|_| IoFault::OutOfRange)?;
            self.try_issue_slot0_bytes(&wr, true, 1, byte_count, Some(byte_count))?;
            cur_lba = cur_lba
                .checked_add(batch_secs as u64)
                .ok_or(IoFault::OutOfRange)?;
        }
        Ok(())
    }

    /// Multi-sector DMA read into one or more destination slices using `READ DMA EXT` (`lba48 = true`)
    /// or `READ DMA` (`lba48 = false`) in chunks of up to `AHCI_MAX_BATCH_SECTORS` (`64` sectors = `32 KiB`).
    pub(crate) fn try_read_sector_slices(
        &self,
        lba: u64,
        lba48: bool,
        slices: &mut [&mut [[u8; 512]]],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use target_enterprise::ahci_fis::build_rw_dma_fis;
        use target_enterprise::memory::dma_layout::AHCI_MAX_BATCH_SECTORS;
        use target_enterprise::state_store::IoFault;

        let mut total_rem = 0usize;
        let mut k = 0usize;
        while k < slices.len() {
            total_rem = total_rem
                .checked_add(slices[k].len())
                .ok_or(IoFault::OutOfRange)?;
            k += 1;
        }
        let mut cur_lba = lba;
        let mut s_idx = 0usize;
        let mut s_off = 0usize;
        while total_rem > 0 {
            let batch_secs = total_rem.min(AHCI_MAX_BATCH_SECTORS);
            let byte_count = (batch_secs as u32) * 512;
            let rd = build_rw_dma_fis(cur_lba, batch_secs as u16, false, lba48, 0)
                .map_err(|_| IoFault::OutOfRange)?;
            self.try_issue_slot0_bytes(&rd, false, 1, byte_count, Some(byte_count))?;
            let mut copied = 0usize;
            // SAFETY: `self.data_pa..self.data_pa + byte_count` holds the freshly transferred DMA payload in mapped physical RAM after Slot 0 completed cleanly.
            unsafe {
                let d = pa_to_va(self.data_pa);
                while copied < batch_secs && s_idx < slices.len() {
                    let rem_in_slice = slices[s_idx].len() - s_off;
                    if rem_in_slice == 0 {
                        s_idx += 1;
                        s_off = 0;
                        continue;
                    }
                    let take = rem_in_slice.min(batch_secs - copied);
                    core::ptr::copy_nonoverlapping(
                        d.add(copied * 512),
                        slices[s_idx][s_off].as_mut_ptr(),
                        take * 512,
                    );
                    copied += take;
                    s_off += take;
                }
            }
            cur_lba = cur_lba
                .checked_add(batch_secs as u64)
                .ok_or(IoFault::OutOfRange)?;
            total_rem -= batch_secs;
        }
        Ok(())
    }

    /// ATA WRITE DMA / WRITE DMA EXT one 512-byte sector at `lba`, reporting failure.
    pub(crate) fn try_write_sector(
        &self,
        lba: u64,
        lba48: bool,
        data: &[u8; 512],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        self.try_write_sector_slices(lba, lba48, &[core::slice::from_ref(data)])
    }

    /// ATA READ DMA / READ DMA EXT one 512-byte sector at `lba` into `out`, reporting failure.
    pub(crate) fn try_read_sector(
        &self,
        lba: u64,
        lba48: bool,
        out: &mut [u8; 512],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        self.try_read_sector_slices(lba, lba48, &mut [core::slice::from_mut(out)])
    }

    /// ATA IDENTIFY DEVICE: addressable sector count and 48-bit LBA capability.
    pub(crate) fn try_identify_geometry(
        &self,
    ) -> Result<(u64, bool), target_enterprise::state_store::IoFault> {
        use cuttle_contracts::AhciFis;
        use target_enterprise::ahci_fis::{parse_identify_geometry, AhciFisImpl};
        use target_enterprise::state_store::IoFault;
        let params = AhciFisImpl::identify(0).map_err(|_| IoFault::OutOfRange)?;
        self.fill_data(&[0u8; 512]);
        self.try_issue_slot0_bytes(&params, false, 1, 512, None)?;
        let data = self.drain_data();
        let (sectors, lba48) = parse_identify_geometry(&data).ok_or(IoFault::DeviceError)?;
        AHCI_CACHED_LBA48.store(lba48, core::sync::atomic::Ordering::Release);
        Ok((sectors, lba48))
    }

    /// ATA READ DMA one 512-byte sector at `lba`.
    pub(crate) fn read_sector(&self, lba: u64) -> [u8; 512] {
        use cuttle_contracts::{AhciFis, ATA_CMD_READ_DMA};
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

/// The AHCI port, sector capacity, and LBA48 capability the durable state store runs on, probed once.
static AHCI_STATE_DISK: spin::Mutex<Option<(AhciHwPort, u64, bool)>> = spin::Mutex::new(None);

/// The AHCI disk as a fallible multi-sector DMA block device for
/// [`target_enterprise::state_store`].
pub(crate) struct AhciDisk {
    port: AhciHwPort,
    sectors: u64,
    lba48: bool,
}

impl AhciDisk {
    /// The state disk. The first call probes the HBA and reads the device
    /// geometry; later calls reuse it, so commits never re-probe the port.
    pub(crate) fn state_disk() -> Result<Self, target_enterprise::state_store::IoFault> {
        let mut cached = AHCI_STATE_DISK.lock();
        if let Some((port, sectors, lba48)) = *cached {
            return Ok(AhciDisk {
                port,
                sectors,
                lba48,
            });
        }
        let port = AhciHwPort::probe_start_quiet();
        let (sectors, lba48) = port.try_identify_geometry()?;
        *cached = Some((port, sectors, lba48));
        Ok(AhciDisk {
            port,
            sectors,
            lba48,
        })
    }

    /// After a failed command the port holds error state and will not run
    /// another. Restart it so the caller's fallback (the other slot, a
    /// repair write) has a working device.
    fn restart_port_after_fault(&mut self) {
        self.port = AhciHwPort::probe_start_quiet();
        *AHCI_STATE_DISK.lock() = Some((self.port, self.sectors, self.lba48));
    }

    fn checked<T>(
        &mut self,
        r: Result<T, target_enterprise::state_store::IoFault>,
    ) -> Result<T, target_enterprise::state_store::IoFault> {
        if r.is_err() {
            self.restart_port_after_fault();
        }
        r
    }

    fn check_range(
        &self,
        lba: u64,
        count: usize,
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use target_enterprise::state_store::IoFault;
        let end = lba.checked_add(count as u64).ok_or(IoFault::OutOfRange)?;
        if end > target_enterprise::state_store::SectorIo::capacity_sectors(self) {
            return Err(IoFault::OutOfRange);
        }
        Ok(())
    }
}

impl target_enterprise::state_store::SectorIo for AhciDisk {
    fn capacity_sectors(&self) -> u64 {
        use target_enterprise::ahci_fis::{AHCI_LBA28_MAX_SECTORS, AHCI_LBA48_MAX_SECTORS};
        let cap_max = if self.lba48 {
            AHCI_LBA48_MAX_SECTORS
        } else {
            AHCI_LBA28_MAX_SECTORS
        };
        self.sectors.min(cap_max)
    }

    fn read_sector(
        &mut self,
        lba: u64,
        out: &mut [u8; 512],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        self.check_range(lba, 1)?;
        let r = self.port.try_read_sector(lba, self.lba48, out);
        self.checked(r)
    }

    fn write_sector(
        &mut self,
        lba: u64,
        data: &[u8; 512],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        self.check_range(lba, 1)?;
        let r = self.port.try_write_sector(lba, self.lba48, data);
        self.checked(r)
    }

    fn read_sectors(
        &mut self,
        lba: u64,
        out: &mut [[u8; 512]],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        self.check_range(lba, out.len())?;
        let r = self.port.try_read_sector_slices(lba, self.lba48, &mut [out]);
        self.checked(r)
    }

    fn write_sectors(
        &mut self,
        lba: u64,
        data: &[[u8; 512]],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        self.check_range(lba, data.len())?;
        let r = self.port.try_write_sector_slices(lba, self.lba48, &[data]);
        self.checked(r)
    }

    fn read_sector_slices(
        &mut self,
        lba: u64,
        slices: &mut [&mut [[u8; 512]]],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use target_enterprise::state_store::IoFault;
        let mut total = 0usize;
        let mut i = 0usize;
        while i < slices.len() {
            total = total.checked_add(slices[i].len()).ok_or(IoFault::OutOfRange)?;
            i += 1;
        }
        self.check_range(lba, total)?;
        let r = self.port.try_read_sector_slices(lba, self.lba48, slices);
        self.checked(r)
    }

    fn write_sector_slices(
        &mut self,
        lba: u64,
        slices: &[&[[u8; 512]]],
    ) -> Result<(), target_enterprise::state_store::IoFault> {
        use target_enterprise::state_store::IoFault;
        let mut total = 0usize;
        let mut i = 0usize;
        while i < slices.len() {
            total = total.checked_add(slices[i].len()).ok_or(IoFault::OutOfRange)?;
            i += 1;
        }
        self.check_range(lba, total)?;
        let r = self.port.try_write_sector_slices(lba, self.lba48, slices);
        self.checked(r)
    }

    fn flush(&mut self) -> Result<(), target_enterprise::state_store::IoFault> {
        let r = self.port.try_flush_cache(self.lba48);
        self.checked(r)
    }
}

/// Banner: `AHCI_HW probe OK slot=N abar=… pi=…`, `AHCI_HW identify OK
/// sectors=2048`, `AHCI_HW sector OK first_byte=5a` (real PCI + MMIO +
/// IDENTIFY + sector DMA — TASK-113/117).
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_ahci_hw() {
    use cuttle_contracts::{AhciFis, ATA_CMD_READ_DMA};
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
pub(crate) const CONTINUITY_MAGIC: &[u8; 8] = b"CTTLWAL1";
pub(crate) const CONTINUITY_LEGACY_MAGIC: &[u8; 8] = b"PRTSWAL1";
pub(crate) const CONTINUITY_WAL_SECTORS: u64 = (kf::WAL_CAPACITY / 512) as u64;

/// Durable cursor and region CRC written by [`banner_continuity`] this boot,
/// kept so [`continuity_set_boots`] can rewrite the header.
static CONTINUITY_CURSOR: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
static CONTINUITY_CRC: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn continuity_header(boots: u64, cursor: u32, crc: u32) -> [u8; 512] {
    let mut hdr = [0u8; 512];
    hdr[..8].copy_from_slice(CONTINUITY_MAGIC);
    hdr[8..16].copy_from_slice(&boots.to_le_bytes());
    hdr[16..20].copy_from_slice(&cursor.to_le_bytes());
    hdr[20..24].copy_from_slice(&crc.to_le_bytes());
    hdr
}

/// Move the boot counter forward to `boots` in memory and in the continuity
/// header.
///
/// The counter is only a hint: the sealed shell state carries the
/// authoritative boot generation. When the two disagree (the continuity
/// region was lost and restarted at 1, say) the shell store reports the
/// generation to use and this brings the counter back in line, so the next
/// boot counts on from the right place. A failed rewrite is not fatal: the
/// next boot simply reconciles again.
pub(crate) fn continuity_set_boots(boots: u64) {
    use target_enterprise::state_store::SectorIo;
    CONTINUITY_BOOT_COUNT.store(boots, core::sync::atomic::Ordering::Relaxed);
    let cursor = CONTINUITY_CURSOR.load(core::sync::atomic::Ordering::Relaxed) as u32;
    let crc = CONTINUITY_CRC.load(core::sync::atomic::Ordering::Relaxed) as u32;
    let hdr = continuity_header(boots, cursor, crc);
    let wrote = match AhciDisk::state_disk() {
        Ok(mut disk) => disk
            .write_sector(CONTINUITY_LBA, &hdr)
            .and_then(|()| disk.flush())
            .is_ok(),
        Err(_) => false,
    };
    if !wrote {
        serial_write_str("CONTINUITY NOTICE: boot counter rewrite failed; next boot will reconcile\n");
    }
}

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
    if hdr[..8] == CONTINUITY_MAGIC[..] || hdr[..8] == CONTINUITY_LEGACY_MAGIC[..] {
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
    } else if &hdr[..4] == b"PRTS" {
        serial_write_str("CONTINUITY resume NOTICE: legacy format, state not migrated\n");
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
    let this_boot = resumed_boots.saturating_add(1);
    // Publish for the UDP status payload ("CUTTLE-STATUS boots=N").
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
    // Barrier: the region must be on the platter before a header that
    // vouches for it, or a power cut could leave a valid header over a
    // half-written region.
    port.flush_cache();
    let new_crc = crc32_ieee(backing);
    CONTINUITY_CURSOR.store(wal.durable_cursor() as u64, core::sync::atomic::Ordering::Relaxed);
    CONTINUITY_CRC.store(new_crc as u64, core::sync::atomic::Ordering::Relaxed);
    port.write_sector(CONTINUITY_LBA, &continuity_header(this_boot, wal.durable_cursor() as u32, new_crc));
    port.flush_cache();

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
// TASK-119: real QEMU NVMe (PCI + BAR0 MMIO + admin identify)
// ---------------------------------------------------------------------------

/// Banner: `NVME_HW probe OK slot=N` then `NVME_HW identify OK sn=…`
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_nvme_hw() {
    use cuttle_contracts::{
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
    // SAFETY: Running at CPL=0 with initialized page-table pool; `bar0` and `bar0 + 0x1000` are the PCI-discovered NVMe MMIO register and doorbell pages.
    unsafe {
        let _ = ensure_mmio_page(bar0);
        let _ = ensure_mmio_page(bar0 + 0x1000);
    }

    // SAFETY: `bar0 + REG_CAP` (+0x00) is an 8-byte-aligned 64-bit capability register in the uncached-mapped NVMe BAR0 MMIO page.
    let cap = unsafe { mmio_read64(bar0 + REG_CAP as u64) };
    if cap == 0 || cap == u64::MAX {
        panic!("NVME_HW: CAP MMIO fault");
    }
    // SAFETY: `bar0 + REG_VS` (+0x08) is a 4-byte-aligned 32-bit version register in the uncached-mapped NVMe BAR0 MMIO page.
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
    // SAFETY: `asq_phys..asq_phys+0x3000` (12 KiB) lies within the 128 KiB reserved DMA window mapped via `pa_to_va` and is zeroed while `CC.EN == 0`.
    unsafe {
        let mut p = 0u64;
        while p < 0x3000 {
            let va = pa_to_va(asq_phys + p);
            core::ptr::write_volatile(va, 0);
            p += 1;
        }
    }

    // Disable controller, wait !RDY.
    // SAFETY: `bar0` is mapped uncached via `ensure_mmio_page`, and `asq_phys`/`acq_phys` are 4 KiB-aligned physical pages inside the reserved DMA window.
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
    // SAFETY: `asq_phys` (64 B SQE0) and `acq_phys` (16 B CQE0) are mapped via `pa_to_va` in the reserved DMA window, and `sq0_dbl`/`cq0_dbl` are 4-byte-aligned registers in the mapped NVMe doorbell page.
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
    // SAFETY: `id_phys` is a 4 KiB page in the reserved DMA window mapped via `pa_to_va`, and Identify Controller completion was confirmed on ACQ0 before reading bytes 4..24.
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
        let emu = b"CUTTLE-NVME-EMU";
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
    // SAFETY: `iosq_phys..iosq_phys+0x3000` (`dma + 0x3000..0x6000`) lies within the 128 KiB reserved DMA window mapped via `pa_to_va` before I/O queues are created.
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
        // SAFETY: `slot < ADMIN_QUEUE_ENTRIES (16)` and `cq_slot < 16` bound all accesses within the 4 KiB `asq_phys` and `acq_phys` DMA pages mapped via `pa_to_va`.
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
        // SAFETY: `slot < IO_QUEUE_ENTRIES (16)` and `cq_slot < 16` bound all accesses within the 4 KiB `iosq_phys` and `iocq_phys` DMA pages mapped via `pa_to_va`, and `sq1_dbl`/`cq1_dbl` lie in the mapped doorbell page.
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
    // SAFETY: `sec_phys` (`dma + 0x5000`) is a 4 KiB page in the reserved DMA window mapped via `pa_to_va`, and `i < 512` is in bounds while no I/O command is in flight.
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
    // SAFETY: `sec_phys` (`dma + 0x5000`) is a 4 KiB page in the reserved DMA window mapped via `pa_to_va`, and the preceding WRITE command completed before clearing.
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
    // SAFETY: `sec_phys` is mapped via `pa_to_va` in the reserved DMA window and the NVMe READ command completed on IOCQ1 before reading.
    let first = unsafe { core::ptr::read_volatile(pa_to_va(sec_phys)) };
    if first != 0x5A {
        panic!("NVME_HW: sector first_byte drift");
    }
    // SAFETY: `sec_phys` is a 4 KiB mapped DMA page (`512 <= 4096`) and the NVMe READ CQE confirmed DMA transfer completion.
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

    // Quench NVMe controller (`CC.EN = 0` + wait `!CSTS.RDY`) before leaving `banner_nvme_hw`
    // so admin/IO DMA queues do not stay live across subsequent boot stages.
    // SAFETY: `bar0` is the uncached-mapped NVMe MMIO register page (`REG_CC`, `REG_CSTS`).
    unsafe {
        let cc = mmio_read32(bar0 + REG_CC as u64);
        mmio_write32(bar0 + REG_CC as u64, cc & !CC_EN);
        let mut spins = 0u32;
        while (mmio_read32(bar0 + REG_CSTS as u64) & CSTS_RDY) != 0 && spins < 5_000_000 {
            spins = spins.wrapping_add(1);
            core::hint::spin_loop();
        }
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
    use cuttle_contracts::virtio_blk_req_type;
    use cuttle_contracts::virtio_blk_status_byte;

    let dma_phys = dma_phys_base();
    let q_pa = dma_phys + DMA_Q_OFF;
    let hdr_pa = dma_phys + DMA_HDR_OFF;
    let data_pa = dma_phys + DMA_DATA_OFF;
    let st_pa = dma_phys + DMA_ST_OFF;

    // Zero DMA window via physical map.
    // SAFETY: `dma_phys..dma_phys+0x5000` (20 KiB) fits inside the 128 KiB reserved DMA window mapped via `pa_to_va` and is initialized while the device is reset.
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
    // SAFETY: `data_pa` (`dma_phys + 0x4010`) lies within the 20 KiB mapped DMA window and no hardware DMA is active yet.
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
    // SAFETY: Running at CPL=0; `io_base` is the PCI-validated VirtIO-blk BAR0 I/O base and `q_pa >> 12` is a 4 KiB-aligned PFN in the reserved DMA window.
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
    // SAFETY: `data_pa` (`dma_phys + 0x4010..0x4210`) lies in the reserved DMA window mapped via `pa_to_va` and no virtqueue request is in flight.
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
    // SAFETY: `st_pa` (`dma_phys + 0x4210`) is mapped via `pa_to_va` in the reserved DMA window and `used.idx` advancement confirmed the device completed the request.
    let st = unsafe { core::ptr::read_volatile(pa_to_va(st_pa)) };
    if st != virtio_blk_status_byte::OK {
        panic!("VIRTIO_HW sector: write status not OK");
    }

    // Clear data, READ sector 0.
    // SAFETY: `data_pa` and `st_pa` lie in the reserved DMA window mapped via `pa_to_va` and the prior request completed before re-initializing.
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
    // SAFETY: `st_pa` (`dma_phys + 0x4210`) is mapped via `pa_to_va` in the reserved DMA window and `used.idx` advancement confirmed the device completed the request.
    let st = unsafe { core::ptr::read_volatile(pa_to_va(st_pa)) };
    if st != virtio_blk_status_byte::OK {
        panic!("VIRTIO_HW sector: read status not OK");
    }

    // SAFETY: `data_pa` (`dma_phys + 0x4010..0x4210`) lies in the mapped DMA window and the READ request completed with status == 0.
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
    // SAFETY: `hdr_pa` (`dma_phys + 0x4000..0x4010`) lies in the reserved DMA window mapped via `pa_to_va` and no request is currently active.
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
    // SAFETY: `q` points to the 16 KiB mapped virtqueue region (`slot < VQ_SIZE (256)`), and `avail_off + 2` / `avail_off + 4 + slot * 2` are 2-byte aligned.
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
    // SAFETY: Running at CPL=0; `io_base + 16` is the 16-bit Queue Notify port on the initialized VirtIO-blk PCI function after the `SeqCst` fence.
    unsafe {
        outw(io_base + 16, 0);
    }

    let target = prev_avail_idx.wrapping_add(1);
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        // SAFETY: `q + used_off + 2` is 2-byte aligned inside the 16 KiB mapped virtqueue DMA allocation; volatile read observes device completion.
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
    // SAFETY: `q` points to the 16 KiB mapped virtqueue DMA region and callers pass `off = slot * 16` with `slot < 256` (`off + 16 <= 4096`).
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

