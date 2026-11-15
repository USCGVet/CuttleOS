//! Interrupt-driven asynchronous DMA completion ring and PCI MSI / MSI-X codecs.
//!
//! Provides two host-verifiable `no_std` building blocks shared by the kernel's
//! AHCI, NVMe, VirtIO-blk, and VirtIO-net hardware drivers:
//!
//! 1. [`IoCompletionRing`] — fixed-capacity (`N`-slot) pipelined I/O submission
//!    and completion tracker supporting out-of-order DMA completions, monotonic
//!    request tags, interrupt wakeup accounting, hardware `HLT` sleep counts,
//!    and bounded timeout reclamation.
//! 2. PCI MSI (`cap_id = 0x05`, PCI Local Bus Spec §6.8.1) and MSI-X
//!    (`cap_id = 0x11`, §6.8.2) capability discovery, x86-64 Local APIC message
//!    address/data encoders (`0xFEE0_0000 | (apic_id << 12)`), per-vector mask
//!    handling, and legacy `INTx` disable (`PCI_CMD_INTX_DISABLE`).

use cuttle_contracts::{
    Pci, PciAddress, PciBar, PciConfigBus, PciError, PCI_CFG_OFFSET_COMMAND_STATUS,
    PCI_MSIX_ENABLE_BIT, PCI_MSIX_FUNCMASK_BIT,
};

use crate::pci::PciImpl;

/// PCI Capability ID for Message Signaled Interrupts (MSI, PCI Spec §6.8.1).
pub const PCI_CAP_ID_MSI: u8 = 0x05;

/// PCI Command register bit 10: Interrupt Disable (`INTx#` assertion disabled).
pub const PCI_CMD_INTX_DISABLE: u32 = 1 << 10;

/// PCI Command register bit 1: Memory Space enable (required for MSI-X MMIO table).
pub const PCI_CMD_MEM_SPACE: u32 = 1 << 1;

/// PCI Command register bit 2: Bus Master enable (required for MSI/MSI-X DMA writes).
pub const PCI_CMD_BUS_MASTER: u32 = 1 << 2;

/// MSI Message Control bit 0: MSI Enable.
pub const MSI_CTRL_ENABLE: u16 = 1 << 0;

/// MSI Message Control bit 7: 64-bit Address Capable.
pub const MSI_CTRL_64BIT: u16 = 1 << 7;

/// MSI Message Control bit 8: Per-Vector Masking Capable.
pub const MSI_CTRL_PVM: u16 = 1 << 8;

/// MSI Message Control bits `6:4`: Multiple Message Enable mask (clear -> 1 vector).
pub const MSI_CTRL_MME_MASK: u16 = 0b111 << 4;

/// Architectural x86-64 Local APIC MSI physical base address (`0xFEE0_0000`).
pub const LAPIC_MSI_BASE_ADDR: u32 = 0xFEE0_0000;

/// IDT vector reserved for PCI MSI / MSI-X block-storage DMA completions.
pub const MSI_VECTOR_BLOCK: u8 = 0x45;

/// IDT vector reserved for PCI MSI / MSI-X network TX/RX DMA completions.
pub const MSI_VECTOR_NET: u8 = 0x46;

/// Category of an asynchronous hardware DMA operation tracked in [`IoCompletionRing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncIoKind {
    /// Block-device sector read DMA (`AHCI`, `NVMe`, or `VirtIO-blk`).
    BlockRead,
    /// Block-device sector write DMA (`AHCI`, `NVMe`, or `VirtIO-blk`).
    BlockWrite,
    /// Block-device volatile write-cache flush (`SATA FLUSH CACHE EXT` / `NVMe FLUSH`).
    BlockFlush,
    /// Network packet transmit DMA (`VirtIO-net` pipelined TX ring).
    NetTx,
    /// Network packet receive DMA (`VirtIO-net` RX ring).
    NetRx,
}

/// Lifecycle state of one slot inside [`IoCompletionRing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IoSlotState {
    /// Slot is unused and available for [`IoCompletionRing::submit`].
    Empty,
    /// DMA descriptor has been posted to hardware and awaits completion.
    InFlight,
    /// Hardware signaled completion; ready to be reaped by the caller.
    Completed,
}

/// Metadata for a single slot inside [`IoCompletionRing`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoSlotEntry {
    /// Monotonic non-zero request tag assigned on submission.
    pub tag: u64,
    /// Operation class (`BlockRead`, `BlockWrite`, `BlockFlush`, `NetTx`, `NetRx`).
    pub kind: AsyncIoKind,
    /// Caller-supplied hardware queue/descriptor index (`u16`).
    pub hw_slot: u16,
    /// Current lifecycle state of this slot.
    pub state: IoSlotState,
    /// Device status code recorded on completion (`0` = OK).
    pub status: u32,
    /// True if completion coincided with at least one hardware MSI/MSI-X IRQ edge.
    pub irq_delivered: bool,
}

impl IoSlotEntry {
    /// Construct an empty slot entry.
    pub const fn empty() -> Self {
        Self {
            tag: 0,
            kind: AsyncIoKind::BlockRead,
            hw_slot: 0,
            state: IoSlotState::Empty,
            status: 0,
            irq_delivered: false,
        }
    }
}

/// Errors returned by [`IoCompletionRing`] operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AsyncIoError {
    /// All `N` slots in the completion ring are currently occupied.
    RingFull,
    /// No in-flight or completed slot matched the requested tag.
    UnknownTag,
    /// The slot exists, but hardware has not marked it completed yet.
    NotReady,
}

/// Fixed-capacity (`N`-slot) asynchronous DMA submission and completion ring.
#[derive(Debug)]
pub struct IoCompletionRing<const N: usize> {
    slots: [IoSlotEntry; N],
    next_tag: u64,
    inflight: usize,
    /// Peak concurrent in-flight DMA requests observed since initialization.
    pub max_inflight_seen: usize,
    /// Total DMA requests submitted through this ring.
    pub total_submitted: u64,
    /// Total DMA requests completed and reaped without timeout.
    pub total_completed: u64,
    /// Total completions accompanied by a hardware MSI/MSI-X interrupt edge.
    pub irq_woken: u64,
    /// Total hardware `HLT` sleep cycles entered while awaiting DMA completion.
    pub hlt_sleeps: u64,
    /// Total in-flight requests cancelled due to timeout expiry.
    pub timeouts: u64,
}

impl<const N: usize> IoCompletionRing<N> {
    /// Create an empty `N`-slot completion ring suitable for `static` initialization.
    pub const fn new() -> Self {
        Self {
            slots: [IoSlotEntry::empty(); N],
            next_tag: 1,
            inflight: 0,
            max_inflight_seen: 0,
            total_submitted: 0,
            total_completed: 0,
            irq_woken: 0,
            hlt_sleeps: 0,
            timeouts: 0,
        }
    }

    /// Current number of occupied (`InFlight` or un-reaped `Completed`) slots.
    #[inline]
    pub const fn inflight_count(&self) -> usize {
        self.inflight
    }

    /// Ring capacity `N`.
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Record one hardware `HLT` sleep wakeup cycle while awaiting DMA completion.
    #[inline]
    pub fn record_hlt_sleep(&mut self) {
        self.hlt_sleeps = self.hlt_sleeps.saturating_add(1);
    }

    /// Register a newly posted hardware DMA descriptor and return its unique monotonic tag.
    pub fn submit(&mut self, kind: AsyncIoKind, hw_slot: u16) -> Result<u64, AsyncIoError> {
        let mut idx = 0usize;
        while idx < N {
            if self.slots[idx].state == IoSlotState::Empty {
                let tag = self.next_tag;
                self.next_tag = self.next_tag.wrapping_add(1).max(1);
                self.slots[idx] = IoSlotEntry {
                    tag,
                    kind,
                    hw_slot,
                    state: IoSlotState::InFlight,
                    status: 0,
                    irq_delivered: false,
                };
                self.inflight += 1;
                if self.inflight > self.max_inflight_seen {
                    self.max_inflight_seen = self.inflight;
                }
                self.total_submitted = self.total_submitted.saturating_add(1);
                return Ok(tag);
            }
            idx += 1;
        }
        Err(AsyncIoError::RingFull)
    }

    /// Mark an in-flight DMA request identified by `tag` as completed with `status`.
    pub fn complete(
        &mut self,
        tag: u64,
        status: u32,
        irq_delivered: bool,
    ) -> Result<(), AsyncIoError> {
        if tag == 0 {
            return Err(AsyncIoError::UnknownTag);
        }
        let mut idx = 0usize;
        while idx < N {
            if self.slots[idx].state == IoSlotState::InFlight && self.slots[idx].tag == tag {
                self.slots[idx].state = IoSlotState::Completed;
                self.slots[idx].status = status;
                self.slots[idx].irq_delivered = irq_delivered;
                if irq_delivered {
                    self.irq_woken = self.irq_woken.saturating_add(1);
                }
                return Ok(());
            }
            idx += 1;
        }
        Err(AsyncIoError::UnknownTag)
    }

    /// Reap a completed DMA slot identified by `tag`, freeing the slot and returning its entry.
    pub fn reap(&mut self, tag: u64) -> Result<IoSlotEntry, AsyncIoError> {
        if tag == 0 {
            return Err(AsyncIoError::UnknownTag);
        }
        let mut idx = 0usize;
        while idx < N {
            if self.slots[idx].state != IoSlotState::Empty && self.slots[idx].tag == tag {
                if self.slots[idx].state != IoSlotState::Completed {
                    return Err(AsyncIoError::NotReady);
                }
                let out = self.slots[idx];
                self.slots[idx] = IoSlotEntry::empty();
                self.inflight = self.inflight.saturating_sub(1);
                self.total_completed = self.total_completed.saturating_add(1);
                return Ok(out);
            }
            idx += 1;
        }
        Err(AsyncIoError::UnknownTag)
    }

    /// Cancel a timed-out request identified by `tag`, freeing its slot and incrementing `timeouts`.
    pub fn cancel_timed_out(&mut self, tag: u64) -> Result<(), AsyncIoError> {
        if tag == 0 {
            return Err(AsyncIoError::UnknownTag);
        }
        let mut idx = 0usize;
        while idx < N {
            if self.slots[idx].state != IoSlotState::Empty && self.slots[idx].tag == tag {
                self.slots[idx] = IoSlotEntry::empty();
                self.inflight = self.inflight.saturating_sub(1);
                self.timeouts = self.timeouts.saturating_add(1);
                return Ok(());
            }
            idx += 1;
        }
        Err(AsyncIoError::UnknownTag)
    }
}

/// Encode the x86-64 Local APIC physical MSI address (`0xFEE0_0000 | (apic_id << 12)`),
/// physical destination mode (`DM = 0`), redirection hint off (`RH = 0`).
#[inline]
pub const fn encode_lapic_msi_address(apic_id: u8) -> u32 {
    LAPIC_MSI_BASE_ADDR | ((apic_id as u32) << 12)
}

/// Encode the x86-64 Local APIC edge-triggered Fixed delivery (`000b`) MSI data word for `vector`.
#[inline]
pub const fn encode_lapic_msi_data(vector: u8) -> u32 {
    vector as u32
}

/// Encode a 16-byte PCI MSI-X Table Entry (`[msg_addr_lo, msg_addr_hi, msg_data, vector_ctrl]`)
/// for `apic_id` and `vector` (`masked = false` -> `vector_ctrl = 0`, `masked = true` -> `1`).
#[inline]
pub const fn encode_msix_entry(apic_id: u8, vector: u8, masked: bool) -> [u32; 4] {
    [
        encode_lapic_msi_address(apic_id),
        0,
        encode_lapic_msi_data(vector),
        if masked { 1 } else { 0 },
    ]
}

/// Resolved MMIO location and vector count of a PCI device's MSI-X Table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MsixTableLoc {
    /// Config-space byte offset of the MSI-X capability header (`0x11`).
    pub cap_offset: u8,
    /// Number of MSI-X table entries (`1..=2048`).
    pub table_size: u16,
    /// Resolved physical MMIO base address of MSI-X Table entry `0` (`BAR[bir] + table_offset`).
    pub table_phys_base: u64,
}

/// Program and enable a standard PCI MSI (`cap_id = 0x05`) capability on `addr`
/// targeting `apic_id` and IDT `vector` (must be `>= 0x20`), unmasking per-vector
/// mask bits if present and setting `PCI_CMD_INTX_DISABLE | PCI_CMD_BUS_MASTER`.
pub fn enable_pci_msi(
    bus: &mut dyn PciConfigBus,
    addr: PciAddress,
    apic_id: u8,
    vector: u8,
) -> Result<u8, PciError> {
    if vector < 0x20 {
        return Err(PciError::CapabilityNotFound);
    }
    let cap = PciImpl::find_capability(bus, addr, PCI_CAP_ID_MSI)?;
    let dw0 = bus.read_dword(addr, cap);
    let ctrl = (dw0 >> 16) as u16;
    let is_64 = (ctrl & MSI_CTRL_64BIT) != 0;
    let has_pvm = (ctrl & MSI_CTRL_PVM) != 0;
    let needed_bytes: usize = match (is_64, has_pvm) {
        (true, true) => 20,
        (true, false) | (false, true) => 16,
        (false, false) => 12,
    };
    if (cap as usize) + needed_bytes > 256 {
        return Err(PciError::BadCapPointer);
    }

    // Disable MSI while updating Message Address / Data registers.
    let disabled_ctrl = (ctrl & !MSI_CTRL_MME_MASK) & !MSI_CTRL_ENABLE;
    bus.write_dword(addr, cap, (dw0 & 0x0000_FFFF) | ((disabled_ctrl as u32) << 16));

    let msg_addr = encode_lapic_msi_address(apic_id);
    let msg_data = encode_lapic_msi_data(vector);
    bus.write_dword(addr, cap.wrapping_add(4), msg_addr);
    if is_64 {
        bus.write_dword(addr, cap.wrapping_add(8), 0);
        let data_dw = bus.read_dword(addr, cap.wrapping_add(12));
        bus.write_dword(addr, cap.wrapping_add(12), (data_dw & 0xFFFF_0000) | msg_data);
        if has_pvm {
            bus.write_dword(addr, cap.wrapping_add(16), 0);
        }
    } else {
        let data_dw = bus.read_dword(addr, cap.wrapping_add(8));
        bus.write_dword(addr, cap.wrapping_add(8), (data_dw & 0xFFFF_0000) | msg_data);
        if has_pvm {
            bus.write_dword(addr, cap.wrapping_add(12), 0);
        }
    }

    // Enable Bus Master + disable legacy INTx assertion in PCI Command register
    // while preserving read-only PCI Status bits (e.g. Capabilities List `0x0010`)
    // and writing `0` to RW1C PCI Status error bits (`0xF900_0000`).
    let cmd_sts = bus.read_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    let new_cmd = (cmd_sts & 0x06FF_FFFF) | PCI_CMD_BUS_MASTER | PCI_CMD_INTX_DISABLE;
    bus.write_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS, new_cmd);

    // Enable single-message MSI (`MME = 0`, `Enable = 1`).
    let enabled_ctrl = disabled_ctrl | MSI_CTRL_ENABLE;
    bus.write_dword(addr, cap, (dw0 & 0x0000_FFFF) | ((enabled_ctrl as u32) << 16));
    Ok(cap)
}

/// Discover a PCI device's MSI-X (`cap_id = 0x11`) capability and resolve the physical
/// MMIO address of its MSI-X Vector Table via its BIR BAR (`Mmio32` or `Mmio64`).
pub fn discover_pci_msix(
    bus: &mut dyn PciConfigBus,
    addr: PciAddress,
) -> Result<MsixTableLoc, PciError> {
    let info = PciImpl::msix_info(bus, addr)?;
    let bar_phys = match PciImpl::read_bar(bus, addr, info.table_bar)? {
        PciBar::Mmio32(p) => p as u64,
        PciBar::Mmio64(p) => p,
        PciBar::Io(_) => return Err(PciError::EmptyBar),
    };
    if bar_phys == 0 {
        return Err(PciError::EmptyBar);
    }
    let table_phys_base = bar_phys
        .checked_add(info.table_offset as u64)
        .ok_or(PciError::BadCapPointer)?;
    Ok(MsixTableLoc {
        cap_offset: info.cap_offset,
        table_size: info.table_size,
        table_phys_base,
    })
}

/// Set or update the PCI MSI-X Message Control register at `cap_offset`:
/// enables Memory Space, Bus Master, and `PCI_CMD_INTX_DISABLE` in PCI Command,
/// sets `MSI-X Enable` (`bit 15`), and sets `Function Mask` (`bit 14`) according to `func_masked`.
pub fn set_pci_msix_ctrl(
    bus: &mut dyn PciConfigBus,
    addr: PciAddress,
    cap_offset: u8,
    enable: bool,
    func_masked: bool,
) {
    let cmd_sts = bus.read_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    let new_cmd =
        (cmd_sts & 0x06FF_FFFF) | PCI_CMD_MEM_SPACE | PCI_CMD_BUS_MASTER | PCI_CMD_INTX_DISABLE;
    bus.write_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS, new_cmd);

    let dw0 = bus.read_dword(addr, cap_offset);
    let mut mc = (dw0 >> 16) as u16;
    if enable {
        mc |= PCI_MSIX_ENABLE_BIT;
    } else {
        mc &= !PCI_MSIX_ENABLE_BIT;
    }
    if func_masked {
        mc |= PCI_MSIX_FUNCMASK_BIT;
    } else {
        mc &= !PCI_MSIX_FUNCMASK_BIT;
    }
    bus.write_dword(addr, cap_offset, (dw0 & 0x0000_FFFF) | ((mc as u32) << 16));
}

/// Return `true` when the PCI function at `addr` exposes an MSI-X capability (`0x11`)
/// whose Message Control `MSI-X Enable` bit (`bit 15`) is currently set.
pub fn is_pci_msix_enabled(bus: &mut dyn PciConfigBus, addr: PciAddress) -> bool {
    let Ok(info) = PciImpl::msix_info(bus, addr) else {
        return false;
    };
    let dw0 = bus.read_dword(addr, info.cap_offset);
    let mc = (dw0 >> 16) as u16;
    (mc & PCI_MSIX_ENABLE_BIT) != 0
}

/// Return the legacy VirtIO-PCI device-specific configuration byte offset within BAR0 I/O space:
/// `24` when PCI MSI-X is enabled on `addr` (accounting for the 4-byte MSI-X vector fields at
/// `20..24`), or `20` when MSI-X is absent or disabled.
pub fn virtio_legacy_devcfg_offset(bus: &mut dyn PciConfigBus, addr: PciAddress) -> u16 {
    if is_pci_msix_enabled(bus, addr) {
        24
    } else {
        20
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::{PCI_CAP_ID_MSIX, PCI_STATUS_CAPABILITIES_LIST};

    struct MockPciConfig {
        regs: [u32; 64],
    }

    impl MockPciConfig {
        fn new() -> Self {
            Self { regs: [0; 64] }
        }

        fn set_dw(&mut self, offset: u8, val: u32) {
            self.regs[(offset as usize) >> 2] = val;
        }

        fn get_dw(&self, offset: u8) -> u32 {
            self.regs[(offset as usize) >> 2]
        }
    }

    impl PciConfigBus for MockPciConfig {
        fn read_dword(&mut self, _addr: PciAddress, offset: u8) -> u32 {
            self.get_dw(offset)
        }

        fn write_dword(&mut self, _addr: PciAddress, offset: u8, value: u32) {
            if (offset & 0xFC) == PCI_CFG_OFFSET_COMMAND_STATUS {
                let prev = self.get_dw(PCI_CFG_OFFSET_COMMAND_STATUS);
                let sts_ro = prev & 0x06FF_0000;
                let sts_rw1c = (prev & 0xF900_0000) & !(value & 0xF900_0000);
                self.set_dw(
                    PCI_CFG_OFFSET_COMMAND_STATUS,
                    sts_ro | sts_rw1c | (value & 0x0000_FFFF),
                );
            } else {
                self.set_dw(offset, value);
            }
        }
    }

    const DEV: PciAddress = PciAddress {
        bus: 0,
        device: 4,
        function: 0,
    };

    #[test]
    fn pci_msi_64bit_pvm_known_answer_encoding() {
        let mut bus = MockPciConfig::new();
        bus.set_dw(0x00, 0x2922_8086); // ICH9 AHCI
        bus.set_dw(0x04, (PCI_STATUS_CAPABILITIES_LIST as u32) << 16);
        bus.set_dw(0x34, 0x80);
        // Capability at 0x80: cap_id=0x05, next=0x00, ctrl = 64-bit | PVM | MMC=3 (8 vectors)
        let ctrl: u16 = MSI_CTRL_64BIT | MSI_CTRL_PVM | (0b011 << 1);
        bus.set_dw(0x80, (PCI_CAP_ID_MSI as u32) | ((ctrl as u32) << 16));
        bus.set_dw(0x8C, 0xABCD_0000); // upper 16 bits beside data must be preserved
        bus.set_dw(0x90, 0xFFFF_FFFF); // all vectors initially masked

        let cap = enable_pci_msi(&mut bus, DEV, 2, MSI_VECTOR_BLOCK).expect("enable 64-bit MSI");
        assert_eq!(cap, 0x80);
        assert_eq!(bus.get_dw(0x84), 0xFEE0_2000);
        assert_eq!(bus.get_dw(0x88), 0x0000_0000);
        assert_eq!(bus.get_dw(0x8C), 0xABCD_0000 | (MSI_VECTOR_BLOCK as u32));
        assert_eq!(bus.get_dw(0x90), 0x0000_0000); // PVM unmasked
        let final_ctrl = (bus.get_dw(0x80) >> 16) as u16;
        assert_ne!(final_ctrl & MSI_CTRL_ENABLE, 0);
        assert_eq!(final_ctrl & MSI_CTRL_MME_MASK, 0);
        let cmd = bus.get_dw(0x04) & 0xFFFF;
        assert_ne!(cmd & PCI_CMD_INTX_DISABLE, 0);
        assert_ne!(cmd & PCI_CMD_BUS_MASTER, 0);
    }

    #[test]
    fn pci_msi_32bit_known_answer_encoding_and_low_vector_refusal() {
        let mut bus = MockPciConfig::new();
        bus.set_dw(0x00, 0x2922_8086);
        bus.set_dw(0x04, (PCI_STATUS_CAPABILITIES_LIST as u32) << 16);
        bus.set_dw(0x34, 0x50);
        bus.set_dw(0x50, PCI_CAP_ID_MSI as u32);

        // Exception vectors `< 0x20` must be refused.
        assert!(enable_pci_msi(&mut bus, DEV, 0, 0x0E).is_err());

        let cap = enable_pci_msi(&mut bus, DEV, 0, MSI_VECTOR_BLOCK).expect("enable 32-bit MSI");
        assert_eq!(cap, 0x50);
        assert_eq!(bus.get_dw(0x54), 0xFEE0_0000);
        assert_eq!(bus.get_dw(0x58) & 0xFFFF, MSI_VECTOR_BLOCK as u32);
    }

    #[test]
    fn pci_msix_discovery_and_table_entry_known_answer() {
        let mut bus = MockPciConfig::new();
        bus.set_dw(0x00, 0x0010_1B36); // QEMU NVMe
        bus.set_dw(0x04, (PCI_STATUS_CAPABILITIES_LIST as u32) << 16);
        // 64-bit BAR0 at 0xFEBF_0000 (`type = 0b10` -> bit 2 set).
        bus.set_dw(0x10, 0xFEBF_0004);
        bus.set_dw(0x14, 0x0000_0000);
        bus.set_dw(0x34, 0x90);
        // MSI-X cap at 0x90: table_size - 1 = 63 (64 entries), BIR = 0, table_offset = 0x2000
        bus.set_dw(0x90, (PCI_CAP_ID_MSIX as u32) | (63u32 << 16));
        bus.set_dw(0x94, 0x0000_2000);
        bus.set_dw(0x98, 0x0000_3000);

        let loc = discover_pci_msix(&mut bus, DEV).expect("discover MSI-X");
        assert_eq!(loc.cap_offset, 0x90);
        assert_eq!(loc.table_size, 64);
        assert_eq!(loc.table_phys_base, 0xFEBF_2000);

        set_pci_msix_ctrl(&mut bus, DEV, loc.cap_offset, true, false);
        let mc = (bus.get_dw(0x90) >> 16) as u16;
        assert_ne!(mc & PCI_MSIX_ENABLE_BIT, 0);
        assert_eq!(mc & PCI_MSIX_FUNCMASK_BIT, 0);
        assert!(is_pci_msix_enabled(&mut bus, DEV));
        assert_eq!(virtio_legacy_devcfg_offset(&mut bus, DEV), 24);

        set_pci_msix_ctrl(&mut bus, DEV, loc.cap_offset, false, false);
        assert!(!is_pci_msix_enabled(&mut bus, DEV));
        assert_eq!(virtio_legacy_devcfg_offset(&mut bus, DEV), 20);

        let ent = encode_msix_entry(3, MSI_VECTOR_NET, false);
        assert_eq!(ent, [0xFEE0_3000, 0, MSI_VECTOR_NET as u32, 0]);
    }

    #[test]
    fn cyclic_pci_capability_pointer_terminates_cleanly() {
        let mut bus = MockPciConfig::new();
        bus.set_dw(0x00, 0x1041_1AF4);
        bus.set_dw(0x04, (PCI_STATUS_CAPABILITIES_LIST as u32) << 16);
        bus.set_dw(0x34, 0x60);
        // Malformed self-cycle at 0x60 (`cap_id = 0x09`, `next = 0x60`).
        bus.set_dw(0x60, 0x0000_6009);

        assert_eq!(
            enable_pci_msi(&mut bus, DEV, 0, MSI_VECTOR_NET),
            Err(PciError::CapWalkOverflow)
        );
    }

    #[test]
    fn completion_ring_supports_8way_pipelining_and_out_of_order_reap() {
        let mut ring = IoCompletionRing::<8>::new();
        let mut tags = [0u64; 8];
        let mut i = 0usize;
        while i < 8 {
            tags[i] = ring
                .submit(AsyncIoKind::NetTx, i as u16)
                .expect("submit within 8-slot capacity");
            i += 1;
        }
        assert_eq!(ring.inflight_count(), 8);
        assert_eq!(ring.max_inflight_seen, 8);
        assert_eq!(
            ring.submit(AsyncIoKind::NetTx, 8),
            Err(AsyncIoError::RingFull)
        );

        // Out-of-order completion: slot 5 finishes before slot 0.
        assert_eq!(ring.reap(tags[5]), Err(AsyncIoError::NotReady));
        ring.record_hlt_sleep();
        ring.complete(tags[5], 0, true).expect("complete tag 5");
        ring.complete(tags[0], 0, true).expect("complete tag 0");
        assert_eq!(
            ring.complete(tags[5], 0, false),
            Err(AsyncIoError::UnknownTag)
        );

        let e5 = ring.reap(tags[5]).expect("reap tag 5");
        assert_eq!(e5.hw_slot, 5);
        assert!(e5.irq_delivered);
        let e0 = ring.reap(tags[0]).expect("reap tag 0");
        assert_eq!(e0.hw_slot, 0);
        assert_eq!(ring.inflight_count(), 6);
        assert_eq!(ring.irq_woken, 2);
        assert_eq!(ring.hlt_sleeps, 1);

        // Cancel remaining 6 slots on simulated timeout.
        ring.cancel_timed_out(tags[1]).expect("cancel tag 1");
        assert_eq!(ring.timeouts, 1);
        assert_eq!(ring.inflight_count(), 5);
    }

    #[test]
    fn enable_pci_msi_rejects_truncated_cap_without_writing_config_space() {
        let mut bus = MockPciConfig::new();
        bus.set_dw(0x00, 0x2922_8086);
        bus.set_dw(0x04, (PCI_STATUS_CAPABILITIES_LIST as u32) << 16);
        // 64-bit + PVM MSI requires 20 bytes; at 0xF0, 0xF0 + 20 = 260 > 256!
        bus.set_dw(0x34, 0xF0);
        let ctrl: u16 = MSI_CTRL_64BIT | MSI_CTRL_PVM;
        bus.set_dw(0xF0, (PCI_CAP_ID_MSI as u32) | ((ctrl as u32) << 16));
        let before = bus.regs;

        assert_eq!(
            enable_pci_msi(&mut bus, DEV, 2, MSI_VECTOR_BLOCK),
            Err(PciError::BadCapPointer)
        );
        assert_eq!(
            bus.regs, before,
            "enable_pci_msi must not wrap or mutate PCI config space on truncated MSI capability"
        );
    }
}
