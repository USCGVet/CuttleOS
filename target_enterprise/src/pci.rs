#![doc = " PCI bus enumeration — legacy 0xCF8/0xCFC configuration-space wire"]
#![doc = " codec."]
#![doc = ""]
#![doc = " `no_std`, no `alloc`, fixed-capacity scratch in the impl. The"]
#![doc = " kernel-side surface stops short of programming MMIO; this iteration"]
#![doc = " ships the *configuration-space cycles* against a caller-supplied"]
#![doc = " [`PciConfigBus`], validated through a recording test harness. The"]
#![doc = " real kernel-side `PciConfigBus` impl (the one that issues `out`/`in`"]
#![doc = " against ports 0xCF8/0xCFC) is plugged in at the"]
#![doc = " `target_enterprise_kernel` integration layer."]
#![doc = ""]
#![doc = " # Why this is wire-codec-shaped, not driver-state-shaped"]
#![doc = ""]
#![doc = " The verifier and the QEMU smoke test both assume deterministic"]
#![doc = " single-thread execution: each banner emits a byte sequence that"]
#![doc = " must round-trip identically across morph cycles. Real driver state"]
#![doc = " (enabled BAR ranges, programmed MSI-X vectors, registered IRQ"]
#![doc = " handlers) is per-boot and per-machine. The TASK-059 design dodges"]
#![doc = " that by making the *config-space walker* the locked surface: we"]
#![doc = " exercise `probe` / `enumerate` / `read_bar` / `find_capability` /"]
#![doc = " `msix_info` against a recording harness, and assert the captured"]
#![doc = " configuration-space access pattern matches a locked golden."]
#![doc = ""]
#![doc = " # PCI configuration-space layout (PCI Local Bus Spec §6.1)"]
#![doc = ""]
#![doc = " ```text"]
#![doc = "  Offset  Dword  Field"]
#![doc = "  ------  -----  ----------------------------------------"]
#![doc = "  0x00    0      vendor_id (LSB 16) | device_id (MSB 16)"]
#![doc = "  0x04    1      command (LSB 16)   | status (MSB 16)"]
#![doc = "  0x08    2      revision | prog_if | subclass | class"]
#![doc = "  0x0C    3      cacheline | latency | header_type | BIST"]
#![doc = "  0x10    4      BAR0"]
#![doc = "  0x14    5      BAR1"]
#![doc = "  ..."]
#![doc = "  0x24    9      BAR5"]
#![doc = "  0x34    13     capabilities_ptr (LSB byte)"]
#![doc = "  0x3C    15     int_line | int_pin | min_gnt | max_lat"]
#![doc = " ```"]
#![doc = ""]
#![doc = " # Mechanism #1 address encoding (PCI §3.2.2.3.4)"]
#![doc = ""]
#![doc = " Writing a dword to port 0xCF8 with this layout selects a specific"]
#![doc = " (bus, device, function, offset) tuple for the next 0xCFC access:"]
#![doc = ""]
#![doc = " ```text"]
#![doc = "  bit 31     : enable (must be 1 for the cycle to trigger)"]
#![doc = "  bits 23:16 : bus"]
#![doc = "  bits 15:11 : device (5 bits, 0..=31)"]
#![doc = "  bits 10:8  : function (3 bits, 0..=7)"]
#![doc = "  bits  7:0  : register (offset & 0xFC)"]
#![doc = " ```"]
#![allow(clippy::needless_range_loop)]
use proteus_contracts::{
    pci_class, Pci, PciAddress, PciBar, PciConfigBus, PciDevice, PciError, PciMsixInfo,
    PCI_BAR_INT_LINE_NONE, PCI_BAR_IO_ADDR_MASK, PCI_BAR_MMIO_ADDR_MASK, PCI_BAR_MMIO_TYPE_64BIT,
    PCI_BAR_MMIO_TYPE_MASK, PCI_BAR_TYPE_IO_BIT, PCI_CAP_ID_MSIX, PCI_CFG_OFFSET_CAP_PTR,
    PCI_CFG_OFFSET_CLASS_REVISION, PCI_CFG_OFFSET_COMMAND_STATUS, PCI_CFG_OFFSET_HEADER_LATENCY,
    PCI_CFG_OFFSET_INT_LINE, PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    PCI_HEADER_MULTIFUNC_BIT, PCI_MAX_BAR_INDEX, PCI_MAX_CAP_HOPS, PCI_MAX_DEVICE,
    PCI_MAX_FUNCTION, PCI_MSIX_BIR_MASK, PCI_MSIX_ENABLE_BIT, PCI_MSIX_FUNCMASK_BIT,
    PCI_MSIX_TABLE_SIZE_MASK, PCI_STATUS_CAPABILITIES_LIST, PCI_VENDOR_NONE,
};
#[doc = " One recorded write the driver issued via `write_dword`."]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciWriteRecord {
    #[doc = " The function the driver wrote to."]
    pub addr: PciAddress,
    #[doc = " The config-space byte offset (masked with 0xFC on access)."]
    pub offset: u8,
    #[doc = " The dword the driver wrote."]
    pub value: u32,
}
impl Pci for PciImpl {
    fn probe(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Option<PciDevice> {
        let __proteus_stack_pad_76cfccf1: [u8; 89usize] = ::core::hint::black_box([0u8; 89usize]);
        let id_vd3b15b95_0 = bus.read_dword(addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor_id_vd3b15b95_1 = (id_vd3b15b95_0 & 0xFFFF) as u16;
        if vendor_id_vd3b15b95_1 == PCI_VENDOR_NONE {
            return None;
        }
        let device_id_vd3b15b95_2 = (id_vd3b15b95_0 >> 16) as u16;
        let class_dword_vd3b15b95_3 = bus.read_dword(addr, PCI_CFG_OFFSET_CLASS_REVISION);
        let prog_if_vd3b15b95_5 = ((class_dword_vd3b15b95_3 >> 8) & 0xFF) as u8;
        let revision_vd3b15b95_4 = (class_dword_vd3b15b95_3 & 0xFF) as u8;
        let subclass_vd3b15b95_6 = ((class_dword_vd3b15b95_3 >> 16) & 0xFF) as u8;
        let class_vd3b15b95_7 = ((class_dword_vd3b15b95_3 >> 24) & 0xFF) as u8;
        let hdr_dword_vd3b15b95_8 = bus.read_dword(addr, PCI_CFG_OFFSET_HEADER_LATENCY);
        let header_type_vd3b15b95_9 = ((hdr_dword_vd3b15b95_8 >> 16) & 0xFF) as u8;
        Some(PciDevice {
            addr: addr,
            vendor_id: vendor_id_vd3b15b95_1,
            device_id: device_id_vd3b15b95_2,
            class: class_vd3b15b95_7,
            subclass: subclass_vd3b15b95_6,
            prog_if: prog_if_vd3b15b95_5,
            revision: revision_vd3b15b95_4,
            header_type: header_type_vd3b15b95_9,
        })
    }
    fn enumerate(bus: &mut dyn PciConfigBus, sink: &mut dyn FnMut(PciDevice)) {
        let __proteus_stack_pad_dd538ab9: [u8; 67usize] = ::core::hint::black_box([0u8; 67usize]);
        let mut bus_no_vd3b15b95_0: u16 = 0;
        while bus_no_vd3b15b95_0 < proteus_contracts::PCI_MAX_BUS {
            let mut device_vd3b15b95_1: u8 = 0;
            while device_vd3b15b95_1 < PCI_MAX_DEVICE {
                let f0_vd3b15b95_2 = PciAddress {
                    bus: bus_no_vd3b15b95_0 as u8,
                    device: device_vd3b15b95_1,
                    function: 0,
                };
                match Self::probe(bus, f0_vd3b15b95_2) {
                    None => {}
                    Some(dev0) => {
                        sink(dev0);
                        if dev0.header_type & PCI_HEADER_MULTIFUNC_BIT != 0 {
                            let mut function_vd3b15b95_3: u8 = 1;
                            while function_vd3b15b95_3 < PCI_MAX_FUNCTION {
                                let addr_vd3b15b95_4 = PciAddress {
                                    bus: bus_no_vd3b15b95_0 as u8,
                                    device: device_vd3b15b95_1,
                                    function: function_vd3b15b95_3,
                                };
                                if let Some(dev) = Self::probe(bus, addr_vd3b15b95_4) {
                                    sink(dev);
                                }
                                function_vd3b15b95_3 += 1;
                            }
                        }
                    }
                }
                device_vd3b15b95_1 += 1;
            }
            bus_no_vd3b15b95_0 += 1;
        }
    }
    fn class_name(class: u8, subclass: u8) -> &'static str {
        let __proteus_stack_pad_0459547d: [u8; 40usize] = ::core::hint::black_box([0u8; 40usize]);
        use pci_class::*;
        match (class, subclass) {
            (CLASS_MASS_STORAGE, SUBCLASS_IDE) => "Mass Storage: IDE",
            (CLASS_MASS_STORAGE, SUBCLASS_SATA) => "Mass Storage: SATA",
            (CLASS_MASS_STORAGE, SUBCLASS_NVME) => "Mass Storage: NVMe",
            (CLASS_MASS_STORAGE, _) => "Mass Storage: Other",
            (CLASS_NETWORK, SUBCLASS_ETHERNET) => "Network: Ethernet",
            (CLASS_NETWORK, _) => "Network: Other",
            (CLASS_DISPLAY, SUBCLASS_VGA) => "Display: VGA-compatible",
            (CLASS_DISPLAY, _) => "Display: Other",
            (CLASS_BRIDGE, SUBCLASS_HOST_BRIDGE) => "Bridge: Host",
            (CLASS_BRIDGE, SUBCLASS_ISA_BRIDGE) => "Bridge: ISA",
            (CLASS_BRIDGE, SUBCLASS_PCI_BRIDGE) => "Bridge: PCI-to-PCI",
            (CLASS_BRIDGE, _) => "Bridge: Other",
            (CLASS_SERIAL_BUS, SUBCLASS_USB) => "Serial Bus: USB",
            (CLASS_SERIAL_BUS, _) => "Serial Bus: Other",
            _ => "Other / Unknown",
        }
    }
    fn int_line(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Option<u8> {
        let __proteus_stack_pad_182942bd: [u8; 70usize] = ::core::hint::black_box([0u8; 70usize]);
        let dw_vd3b15b95_0 = bus.read_dword(addr, PCI_CFG_OFFSET_INT_LINE);
        let line_vd3b15b95_1 = (dw_vd3b15b95_0 & 0xFF) as u8;
        if line_vd3b15b95_1 == PCI_BAR_INT_LINE_NONE {
            None
        } else {
            Some(line_vd3b15b95_1)
        }
    }
    fn read_bar(bus: &mut dyn PciConfigBus, addr: PciAddress, idx: u8) -> Result<PciBar, PciError> {
        let __proteus_stack_pad_380a36f3: [u8; 198usize] = ::core::hint::black_box([0u8; 198usize]);
        if idx > PCI_MAX_BAR_INDEX {
            return Err(PciError::BadBarIndex);
        }
        let offset_vd3b15b95_0 = proteus_contracts::PCI_CFG_OFFSET_BAR0 + idx * 4;
        let lo_vd3b15b95_1 = bus.read_dword(addr, offset_vd3b15b95_0);
        if lo_vd3b15b95_1 == 0 {
            return Err(PciError::EmptyBar);
        }
        if lo_vd3b15b95_1 & PCI_BAR_TYPE_IO_BIT != 0 {
            return Ok(PciBar::Io(lo_vd3b15b95_1 & PCI_BAR_IO_ADDR_MASK));
        }
        let mtype_vd3b15b95_2 = lo_vd3b15b95_1 & PCI_BAR_MMIO_TYPE_MASK;
        if mtype_vd3b15b95_2 == PCI_BAR_MMIO_TYPE_64BIT {
            if idx >= PCI_MAX_BAR_INDEX {
                return Err(PciError::BadBarIndex);
            }
            let hi_vd3b15b95_3 = bus.read_dword(addr, offset_vd3b15b95_0 + 4);
            let high_addr_vd3b15b95_5 = (hi_vd3b15b95_3 as u64) << 32;
            let low_addr_vd3b15b95_4 = (lo_vd3b15b95_1 & PCI_BAR_MMIO_ADDR_MASK) as u64;
            Ok(PciBar::Mmio64(high_addr_vd3b15b95_5 | low_addr_vd3b15b95_4))
        } else {
            Ok(PciBar::Mmio32(lo_vd3b15b95_1 & PCI_BAR_MMIO_ADDR_MASK))
        }
    }
    fn enable_bus_master(bus: &mut dyn PciConfigBus, addr: PciAddress) {
        let __proteus_stack_pad_985f0f7c: [u8; 79usize] = ::core::hint::black_box([0u8; 79usize]);
        let cur_vd3b15b95_0 = bus.read_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS);
        let new_vd3b15b95_1 = cur_vd3b15b95_0 | PCI_COMMAND_BUS_MASTER;
        bus.write_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS, new_vd3b15b95_1);
    }
    fn find_capability(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        cap_id: u8,
    ) -> Result<u8, PciError> {
        let __proteus_stack_pad_09e27238: [u8; 211usize] = ::core::hint::black_box([0u8; 211usize]);
        let status_cmd_vd3b15b95_0 = bus.read_dword(addr, PCI_CFG_OFFSET_COMMAND_STATUS);
        let status_vd3b15b95_1 = (status_cmd_vd3b15b95_0 >> 16) as u16;
        if status_vd3b15b95_1 & PCI_STATUS_CAPABILITIES_LIST == 0 {
            return Err(PciError::NoCapabilities);
        }
        let cap_ptr_dw_vd3b15b95_2 = bus.read_dword(addr, PCI_CFG_OFFSET_CAP_PTR);
        let mut hops_vd3b15b95_4: u8 = 0;
        let mut ptr_vd3b15b95_3 = (cap_ptr_dw_vd3b15b95_2 & 0xFC) as u8;
        while hops_vd3b15b95_4 < PCI_MAX_CAP_HOPS {
            if ptr_vd3b15b95_3 == 0 {
                return Err(PciError::CapabilityNotFound);
            }
            if ptr_vd3b15b95_3 < 0x34 || ptr_vd3b15b95_3 > 0xFC {
                return Err(PciError::BadCapPointer);
            }
            let cap_dw_vd3b15b95_5 = bus.read_dword(addr, ptr_vd3b15b95_3);
            let next_vd3b15b95_7 = ((cap_dw_vd3b15b95_5 >> 8) & 0xFC) as u8;
            let id_vd3b15b95_6 = (cap_dw_vd3b15b95_5 & 0xFF) as u8;
            if id_vd3b15b95_6 == cap_id {
                return Ok(ptr_vd3b15b95_3);
            }
            hops_vd3b15b95_4 += 1;
            ptr_vd3b15b95_3 = next_vd3b15b95_7;
        }
        Err(PciError::CapWalkOverflow)
    }
    fn msix_info(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Result<PciMsixInfo, PciError> {
        let __proteus_stack_pad_7bb04dac: [u8; 37usize] = ::core::hint::black_box([0u8; 37usize]);
        let cap_offset_vd3b15b95_0 = Self::find_capability(bus, addr, PCI_CAP_ID_MSIX)?;
        let dw0_vd3b15b95_1 = bus.read_dword(addr, cap_offset_vd3b15b95_0);
        let table_dw_vd3b15b95_2 = bus.read_dword(addr, cap_offset_vd3b15b95_0 + 4);
        let pba_dw_vd3b15b95_3 = bus.read_dword(addr, cap_offset_vd3b15b95_0 + 8);
        let mc_vd3b15b95_4 = (dw0_vd3b15b95_1 >> 16) as u16;
        let table_bar_vd3b15b95_6 = (table_dw_vd3b15b95_2 & PCI_MSIX_BIR_MASK) as u8;
        let table_offset_vd3b15b95_7 = table_dw_vd3b15b95_2 & !PCI_MSIX_BIR_MASK;
        let table_size_vd3b15b95_5 = (mc_vd3b15b95_4 & PCI_MSIX_TABLE_SIZE_MASK) + 1;
        let pba_offset_vd3b15b95_9 = pba_dw_vd3b15b95_3 & !PCI_MSIX_BIR_MASK;
        let pba_bar_vd3b15b95_8 = (pba_dw_vd3b15b95_3 & PCI_MSIX_BIR_MASK) as u8;
        Ok(PciMsixInfo {
            cap_offset: cap_offset_vd3b15b95_0,
            table_size: table_size_vd3b15b95_5,
            table_bar: table_bar_vd3b15b95_6,
            table_offset: table_offset_vd3b15b95_7,
            pba_bar: pba_bar_vd3b15b95_8,
            pba_offset: pba_offset_vd3b15b95_9,
        })
    }
    fn msix_set_enable(bus: &mut dyn PciConfigBus, addr: PciAddress, info: &PciMsixInfo, on: bool) {
        let __proteus_stack_pad_6c7c78ef: [u8; 111usize] = ::core::hint::black_box([0u8; 111usize]);
        let cur_vd3b15b95_0 = bus.read_dword(addr, info.cap_offset);
        let mut mc_vd3b15b95_1 = (cur_vd3b15b95_0 >> 16) as u16;
        match on {
            true => {
                mc_vd3b15b95_1 |= PCI_MSIX_ENABLE_BIT;
                mc_vd3b15b95_1 &= !PCI_MSIX_FUNCMASK_BIT;
            }
            false => {
                mc_vd3b15b95_1 &= !PCI_MSIX_ENABLE_BIT;
            }
        }
        let new_vd3b15b95_2 = (cur_vd3b15b95_0 & 0x0000_FFFF) | ((mc_vd3b15b95_1 as u32) << 16);
        bus.write_dword(addr, info.cap_offset, new_vd3b15b95_2);
    }
}
#[doc = " Maximum number of scripted dwords a [`RecordingBus`] can hold."]
#[doc = " Sized large enough to script every BAR + capability dword a"]
#[doc = " banner-side fixture needs (each fixture device burns at most"]
#[doc = " ~20 entries; capacity = 256 keeps us comfortable for the entire"]
#[doc = " kernel proof sequence)."]
pub const RECORDING_BUS_CAPACITY: usize = 256;
#[doc = " Wire codec impl. Stateless."]
pub struct PciImpl;
#[doc = " One scripted (address, offset, dword) tuple inside a"]
#[doc = " [`RecordingBus`]."]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciScript {
    #[doc = " The function the entry applies to."]
    pub addr: PciAddress,
    #[doc = " The config-space byte offset (masked with 0xFC on access)."]
    pub offset: u8,
    #[doc = " The dword the bus reports on a `read_dword` of this tuple."]
    pub value: u32,
}
#[doc = " In-RAM `PciConfigBus` impl backed by a fixed-capacity script table."]
#[doc = ""]
#[doc = " Read path: linear scan of the script table for a matching"]
#[doc = " `(addr, offset & 0xFC)`. Misses return `PCI_VENDOR_NONE`-shaped"]
#[doc = " dwords (0xFFFF_FFFF) so the enumerator sees an empty slot — this"]
#[doc = " is the documented sentinel value for an unresponsive function."]
#[doc = ""]
#[doc = " Write path: appends to the write log AND mutates the matching"]
#[doc = " script entry in place (or appends a new entry if no match exists)."]
#[doc = " That lets a test exercise read-modify-write paths like"]
#[doc = " `enable_bus_master`: write the modified dword, then re-read and"]
#[doc = " observe the new value."]
pub struct RecordingBus {
    scripts: [Option<PciScript>; RECORDING_BUS_CAPACITY],
    script_count: usize,
    writes: [Option<PciWriteRecord>; RECORDING_BUS_CAPACITY],
    write_count: usize,
}
impl Default for RecordingBus {
    fn default() -> Self {
        let __proteus_stack_pad_d221c244: [u8; 34usize] = ::core::hint::black_box([0u8; 34usize]);
        Self::new()
    }
}
impl RecordingBus {
    #[doc = " Construct an empty bus. Every config-space read returns the"]
    #[doc = " \"empty slot\" sentinel (0xFFFF_FFFF) until the caller scripts"]
    #[doc = " values via [`set`](Self::set)."]
    pub const fn new() -> Self {
        Self {
            scripts: [None; RECORDING_BUS_CAPACITY],
            script_count: 0,
            writes: [None; RECORDING_BUS_CAPACITY],
            write_count: 0,
        }
    }
    #[doc = " Script a `(addr, offset)` tuple to return `value` on the next"]
    #[doc = " `read_dword`. Overwrites an existing entry if one matches."]
    #[doc = " Returns `false` if the script table is full."]
    pub fn set(&mut self, addr: PciAddress, offset: u8, value: u32) -> bool {
        let __proteus_stack_pad_47bf8601: [u8; 171usize] = ::core::hint::black_box([0u8; 171usize]);
        let mut i_vd3b15b95_1 = 0usize;
        let off_vd3b15b95_0 = offset & 0xFC;
        while i_vd3b15b95_1 < self.script_count {
            if let Some(s) = self.scripts[i_vd3b15b95_1] {
                if s.addr == addr && s.offset == off_vd3b15b95_0 {
                    self.scripts[i_vd3b15b95_1] = Some(PciScript {
                        addr: addr,
                        offset: off_vd3b15b95_0,
                        value: value,
                    });
                    return true;
                }
            }
            i_vd3b15b95_1 += 1;
        }
        if self.script_count >= RECORDING_BUS_CAPACITY {
            return false;
        }
        self.scripts[self.script_count] = Some(PciScript {
            addr: addr,
            offset: off_vd3b15b95_0,
            value: value,
        });
        self.script_count += 1;
        true
    }
    #[doc = " Number of writes the driver has issued through this bus since"]
    #[doc = " construction."]
    pub fn write_count(&self) -> usize {
        let __proteus_stack_pad_a763ac5e: [u8; 123usize] = ::core::hint::black_box([0u8; 123usize]);
        self.write_count
    }
    #[doc = " Look up the `idx`'th recorded write. Returns `None` past the"]
    #[doc = " end of the log."]
    pub fn write_at(&self, idx: usize) -> Option<PciWriteRecord> {
        let __proteus_stack_pad_74cb48f2: [u8; 196usize] = ::core::hint::black_box([0u8; 196usize]);
        if idx >= self.write_count {
            return None;
        }
        self.writes[idx]
    }
    #[doc = " Total number of scripted entries."]
    pub fn script_count(&self) -> usize {
        let __proteus_stack_pad_7ff218c1: [u8; 54usize] = ::core::hint::black_box([0u8; 54usize]);
        self.script_count
    }
}
impl PciConfigBus for RecordingBus {
    fn read_dword(&mut self, addr: PciAddress, offset: u8) -> u32 {
        let __proteus_stack_pad_76fc4025: [u8; 41usize] = ::core::hint::black_box([0u8; 41usize]);
        let off_vd3b15b95_0 = offset & 0xFC;
        let mut i_vd3b15b95_1 = 0usize;
        while i_vd3b15b95_1 < self.script_count {
            if let Some(s) = self.scripts[i_vd3b15b95_1] {
                if s.addr == addr && s.offset == off_vd3b15b95_0 {
                    return s.value;
                }
            }
            i_vd3b15b95_1 += 1;
        }
        0xFFFF_FFFF
    }
    fn write_dword(&mut self, addr: PciAddress, offset: u8, value: u32) {
        let __proteus_stack_pad_3471647d: [u8; 127usize] = ::core::hint::black_box([0u8; 127usize]);
        let mut i_vd3b15b95_1 = 0usize;
        let off_vd3b15b95_0 = offset & 0xFC;
        let mut found_vd3b15b95_2 = false;
        while i_vd3b15b95_1 < self.script_count {
            if let Some(s) = self.scripts[i_vd3b15b95_1] {
                if s.addr == addr && s.offset == off_vd3b15b95_0 {
                    self.scripts[i_vd3b15b95_1] = Some(PciScript {
                        addr: addr,
                        offset: off_vd3b15b95_0,
                        value: value,
                    });
                    found_vd3b15b95_2 = true;
                    break;
                }
            }
            i_vd3b15b95_1 += 1;
        }
        if !found_vd3b15b95_2 && self.script_count < RECORDING_BUS_CAPACITY {
            self.scripts[self.script_count] = Some(PciScript {
                addr: addr,
                offset: off_vd3b15b95_0,
                value: value,
            });
            self.script_count += 1;
        }
        if self.write_count < RECORDING_BUS_CAPACITY {
            self.writes[self.write_count] = Some(PciWriteRecord {
                addr: addr,
                offset: off_vd3b15b95_0,
                value: value,
            });
            self.write_count += 1;
        }
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::pci_class::*;
    use proteus_contracts::{
        PCI_CAP_ID_MSI, PCI_CAP_ID_MSIX, PCI_CONFIG_ADDRESS_PORT, PCI_CONFIG_DATA_PORT,
        PCI_MAX_BUS, PCI_MAX_DEVICE, PCI_MAX_FUNCTION,
    };
    fn addr(bus: u8, device: u8, function: u8) -> PciAddress {
        PciAddress {
            bus,
            device,
            function,
        }
    }
    #[doc = " Pack a (class, subclass, prog_if, revision) tuple into the"]
    #[doc = " class/revision dword layout: revision in the LSB, class in the"]
    #[doc = " MSB."]
    fn class_dword(class: u8, subclass: u8, prog_if: u8, revision: u8) -> u32 {
        ((class as u32) << 24)
            | ((subclass as u32) << 16)
            | ((prog_if as u32) << 8)
            | (revision as u32)
    }
    #[doc = " Pack a (vendor_id, device_id) into the identification dword."]
    fn id_dword(vendor: u16, device: u16) -> u32 {
        ((device as u32) << 16) | (vendor as u32)
    }
    #[doc = " Pack header_type into the dword at offset 0x0C (byte 2)."]
    fn header_dword(header_type: u8) -> u32 {
        (header_type as u32) << 16
    }
    #[doc = " Script a fully-formed PCI function (vendor, device, class,"]
    #[doc = " subclass, prog_if, revision, header_type) into the bus."]
    fn script_device(
        bus: &mut RecordingBus,
        a: PciAddress,
        vendor: u16,
        device: u16,
        class: u8,
        subclass: u8,
        prog_if: u8,
        revision: u8,
        header_type: u8,
    ) {
        bus.set(a, 0x00, id_dword(vendor, device));
        bus.set(a, 0x08, class_dword(class, subclass, prog_if, revision));
        bus.set(a, 0x0C, header_dword(header_type));
    }
    #[test]
    fn constants_match_pci_local_bus_spec() {
        assert_eq!(PCI_CONFIG_ADDRESS_PORT, 0xCF8);
        assert_eq!(PCI_CONFIG_DATA_PORT, 0xCFC);
        assert_eq!(PCI_VENDOR_NONE, 0xFFFF);
        assert_eq!(PCI_MAX_BUS, 256);
        assert_eq!(PCI_MAX_DEVICE, 32);
        assert_eq!(PCI_MAX_FUNCTION, 8);
        assert_eq!(PCI_HEADER_MULTIFUNC_BIT, 0x80);
        assert_eq!(PCI_CAP_ID_MSI, 0x05);
        assert_eq!(PCI_CAP_ID_MSIX, 0x11);
        assert_eq!(PCI_STATUS_CAPABILITIES_LIST, 0x10);
        assert_eq!(PCI_MAX_CAP_HOPS, 48);
        assert_eq!(PCI_COMMAND_BUS_MASTER, 0b100);
        assert_eq!(PCI_MAX_BAR_INDEX, 5);
        assert_eq!(PCI_MSIX_TABLE_SIZE_MASK, 0x07FF);
        assert_eq!(PCI_MSIX_BIR_MASK, 0x07);
        assert_eq!(PCI_MSIX_ENABLE_BIT, 0x8000);
        assert_eq!(PCI_MSIX_FUNCMASK_BIT, 0x4000);
    }
    #[test]
    fn probe_returns_none_for_empty_slot() {
        let mut bus = RecordingBus::new();
        assert_eq!(PciImpl::probe(&mut bus, addr(0, 0, 0)), None);
    }
    #[test]
    fn probe_decodes_intel_e1000() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        script_device(&mut bus, a, 0x8086, 0x100E, 0x02, 0x00, 0x00, 0x03, 0x00);
        let dev = PciImpl::probe(&mut bus, a).expect("e1000 should respond");
        assert_eq!(dev.vendor_id, 0x8086);
        assert_eq!(dev.device_id, 0x100E);
        assert_eq!(dev.class, 0x02);
        assert_eq!(dev.subclass, 0x00);
        assert_eq!(dev.prog_if, 0x00);
        assert_eq!(dev.revision, 0x03);
        assert_eq!(dev.header_type, 0x00);
        assert_eq!(dev.addr, a);
    }
    #[test]
    fn probe_decodes_intel_nvme() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 5, 0);
        script_device(&mut bus, a, 0x8086, 0x5845, 0x01, 0x08, 0x02, 0x00, 0x00);
        let dev = PciImpl::probe(&mut bus, a).expect("nvme should respond");
        assert_eq!(dev.vendor_id, 0x8086);
        assert_eq!(dev.device_id, 0x5845);
        assert_eq!(dev.class, CLASS_MASS_STORAGE);
        assert_eq!(dev.subclass, SUBCLASS_NVME);
        assert_eq!(dev.prog_if, 0x02);
    }
    #[test]
    fn enumerate_finds_two_canonical_qemu_devices() {
        let mut bus = RecordingBus::new();
        let e1000 = addr(0, 3, 0);
        let nvme = addr(0, 5, 0);
        script_device(
            &mut bus, e1000, 0x8086, 0x100E, 0x02, 0x00, 0x00, 0x03, 0x00,
        );
        script_device(&mut bus, nvme, 0x8086, 0x5845, 0x01, 0x08, 0x02, 0x00, 0x00);
        let mut seen = [None::<PciDevice>; 4];
        let mut count = 0usize;
        PciImpl::enumerate(&mut bus, &mut |d| {
            if count < seen.len() {
                seen[count] = Some(d);
            }
            count += 1;
        });
        assert_eq!(count, 2, "exactly two responding functions");
        assert_eq!(seen[0].unwrap().addr, e1000);
        assert_eq!(seen[0].unwrap().vendor_id, 0x8086);
        assert_eq!(seen[0].unwrap().device_id, 0x100E);
        assert_eq!(seen[1].unwrap().addr, nvme);
        assert_eq!(seen[1].unwrap().vendor_id, 0x8086);
        assert_eq!(seen[1].unwrap().device_id, 0x5845);
    }
    #[test]
    fn enumerate_does_not_probe_f1_through_f7_on_single_function_device() {
        let mut bus = RecordingBus::new();
        let a0 = addr(0, 7, 0);
        script_device(&mut bus, a0, 0x10EC, 0x8139, 0x02, 0x00, 0x00, 0x00, 0x00);
        let ghost = addr(0, 7, 1);
        script_device(
            &mut bus, ghost, 0xDEAD, 0xBEEF, 0x00, 0x00, 0x00, 0x00, 0x00,
        );
        let mut found: u32 = 0;
        PciImpl::enumerate(&mut bus, &mut |d| {
            if d.vendor_id == 0xDEAD && d.device_id == 0xBEEF {
                found |= 1;
            }
            if d.vendor_id == 0x10EC && d.device_id == 0x8139 {
                found |= 2;
            }
        });
        assert_eq!(found & 1, 0, "ghost f1 must NOT be probed");
        assert_eq!(found & 2, 2, "f0 must be surfaced");
    }
    #[test]
    fn enumerate_probes_f1_through_f7_on_multi_function_device() {
        let mut bus = RecordingBus::new();
        let a0 = addr(0, 1, 0);
        let a1 = addr(0, 1, 1);
        let a2 = addr(0, 1, 2);
        script_device(&mut bus, a0, 0x8086, 0x2929, 0x06, 0x01, 0x00, 0x00, 0x80);
        script_device(&mut bus, a1, 0x8086, 0x2930, 0x06, 0x01, 0x00, 0x00, 0x80);
        script_device(&mut bus, a2, 0x8086, 0x2931, 0x06, 0x01, 0x00, 0x00, 0x80);
        let mut count = 0u32;
        PciImpl::enumerate(&mut bus, &mut |_| count += 1);
        assert_eq!(count, 3, "f0 + f1 + f2 all probed");
    }
    #[test]
    fn class_name_covers_documented_pairs() {
        assert_eq!(
            PciImpl::class_name(CLASS_MASS_STORAGE, SUBCLASS_IDE),
            "Mass Storage: IDE"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_MASS_STORAGE, SUBCLASS_SATA),
            "Mass Storage: SATA"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_MASS_STORAGE, SUBCLASS_NVME),
            "Mass Storage: NVMe"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_MASS_STORAGE, 0xEE),
            "Mass Storage: Other"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_NETWORK, SUBCLASS_ETHERNET),
            "Network: Ethernet"
        );
        assert_eq!(PciImpl::class_name(CLASS_NETWORK, 0xEE), "Network: Other");
        assert_eq!(
            PciImpl::class_name(CLASS_DISPLAY, SUBCLASS_VGA),
            "Display: VGA-compatible"
        );
        assert_eq!(PciImpl::class_name(CLASS_DISPLAY, 0xEE), "Display: Other");
        assert_eq!(
            PciImpl::class_name(CLASS_BRIDGE, SUBCLASS_HOST_BRIDGE),
            "Bridge: Host"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_BRIDGE, SUBCLASS_ISA_BRIDGE),
            "Bridge: ISA"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_BRIDGE, SUBCLASS_PCI_BRIDGE),
            "Bridge: PCI-to-PCI"
        );
        assert_eq!(PciImpl::class_name(CLASS_BRIDGE, 0xEE), "Bridge: Other");
        assert_eq!(
            PciImpl::class_name(CLASS_SERIAL_BUS, SUBCLASS_USB),
            "Serial Bus: USB"
        );
        assert_eq!(
            PciImpl::class_name(CLASS_SERIAL_BUS, 0xEE),
            "Serial Bus: Other"
        );
        assert_eq!(PciImpl::class_name(0xFF, 0xFF), "Other / Unknown");
    }
    #[test]
    fn int_line_normal_path() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x3C, 0x0000_010B);
        assert_eq!(PciImpl::int_line(&mut bus, a), Some(11));
    }
    #[test]
    fn int_line_sentinel_returns_none() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x3C, 0x0000_00FF);
        assert_eq!(PciImpl::int_line(&mut bus, a), None);
    }
    #[test]
    fn read_bar_rejects_out_of_range_index() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        let r = PciImpl::read_bar(&mut bus, a, 6);
        assert_eq!(r, Err(PciError::BadBarIndex));
    }
    #[test]
    fn read_bar_rejects_empty_slot() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x10, 0);
        assert_eq!(PciImpl::read_bar(&mut bus, a, 0), Err(PciError::EmptyBar));
    }
    #[test]
    fn read_bar_decodes_io_space() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x10, 0xC021);
        let bar = PciImpl::read_bar(&mut bus, a, 0).unwrap();
        assert_eq!(bar, PciBar::Io(0xC020));
    }
    #[test]
    fn read_bar_decodes_32bit_mmio() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x10, 0xFEBC_0000);
        let bar = PciImpl::read_bar(&mut bus, a, 0).unwrap();
        assert_eq!(bar, PciBar::Mmio32(0xFEBC_0000));
    }
    #[test]
    fn read_bar_decodes_32bit_mmio_masks_low_flag_bits() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x10, 0xFEBC_0008);
        let bar = PciImpl::read_bar(&mut bus, a, 0).unwrap();
        assert_eq!(bar, PciBar::Mmio32(0xFEBC_0000));
    }
    #[test]
    fn read_bar_decodes_64bit_mmio() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x10, 0x0000_8004);
        bus.set(a, 0x14, 0x0000_0001);
        let bar = PciImpl::read_bar(&mut bus, a, 0).unwrap();
        assert_eq!(bar, PciBar::Mmio64(0x1_0000_8000));
    }
    #[test]
    fn read_bar_rejects_64bit_at_index_5() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x10 + 5 * 4, 0x0000_8004);
        let r = PciImpl::read_bar(&mut bus, a, 5);
        assert_eq!(r, Err(PciError::BadBarIndex));
    }
    #[test]
    fn enable_bus_master_sets_bit_2_preserves_other_bits() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0003);
        PciImpl::enable_bus_master(&mut bus, a);
        let expected = 0x0010_0007u32;
        assert_eq!(bus.write_count(), 1);
        let w = bus.write_at(0).unwrap();
        assert_eq!(w.addr, a);
        assert_eq!(w.offset, 0x04);
        assert_eq!(w.value, expected);
        let cur = bus.read_dword(a, 0x04);
        assert_eq!(cur, expected);
    }
    #[test]
    fn enable_bus_master_is_idempotent() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0007);
        PciImpl::enable_bus_master(&mut bus, a);
        let cur = bus.read_dword(a, 0x04);
        assert_eq!(cur, 0x0010_0007);
    }
    #[test]
    fn find_capability_rejects_when_status_bit_clear() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0000_0000);
        let r = PciImpl::find_capability(&mut bus, a, PCI_CAP_ID_MSIX);
        assert_eq!(r, Err(PciError::NoCapabilities));
    }
    #[test]
    fn find_capability_walks_one_entry_chain() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0050);
        bus.set(a, 0x50, 0x0000_0011);
        let off = PciImpl::find_capability(&mut bus, a, PCI_CAP_ID_MSIX).unwrap();
        assert_eq!(off, 0x50);
    }
    #[test]
    fn find_capability_walks_three_entry_chain_to_msix() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0040);
        bus.set(a, 0x40, 0x0000_5005);
        bus.set(a, 0x50, 0x0000_6001);
        bus.set(a, 0x60, 0x0000_0011);
        let off = PciImpl::find_capability(&mut bus, a, PCI_CAP_ID_MSIX).unwrap();
        assert_eq!(off, 0x60);
    }
    #[test]
    fn find_capability_returns_not_found_when_chain_lacks_id() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0050);
        bus.set(a, 0x50, 0x0000_0001);
        let r = PciImpl::find_capability(&mut bus, a, PCI_CAP_ID_MSIX);
        assert_eq!(r, Err(PciError::CapabilityNotFound));
    }
    #[test]
    fn find_capability_rejects_circular_chain() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0040);
        bus.set(a, 0x40, 0x0000_5001);
        bus.set(a, 0x50, 0x0000_4001);
        let r = PciImpl::find_capability(&mut bus, a, PCI_CAP_ID_MSIX);
        assert_eq!(r, Err(PciError::CapWalkOverflow));
    }
    #[test]
    fn find_capability_rejects_pointer_below_0x34() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0020);
        let r = PciImpl::find_capability(&mut bus, a, PCI_CAP_ID_MSIX);
        assert_eq!(r, Err(PciError::BadCapPointer));
    }
    #[test]
    fn msix_info_decodes_canonical_header() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0070);
        bus.set(a, 0x70, 0x0007_0011);
        bus.set(a, 0x74, 0x0000_2004);
        bus.set(a, 0x78, 0x0000_3004);
        let info = PciImpl::msix_info(&mut bus, a).unwrap();
        assert_eq!(info.cap_offset, 0x70);
        assert_eq!(info.table_size, 8);
        assert_eq!(info.table_bar, 4);
        assert_eq!(info.table_offset, 0x2000);
        assert_eq!(info.pba_bar, 4);
        assert_eq!(info.pba_offset, 0x3000);
    }
    #[test]
    fn msix_info_table_size_is_off_by_one_corrected() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0070);
        bus.set(a, 0x70, 0x0000_0011);
        bus.set(a, 0x74, 0x0000_0000);
        bus.set(a, 0x78, 0x0000_0000);
        let info = PciImpl::msix_info(&mut bus, a).unwrap();
        assert_eq!(info.table_size, 1);
    }
    #[test]
    fn msix_info_caps_table_size_at_2048() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0010_0000);
        bus.set(a, 0x34, 0x0000_0070);
        bus.set(a, 0x70, 0x07FF_0011);
        bus.set(a, 0x74, 0x0000_0000);
        bus.set(a, 0x78, 0x0000_0000);
        let info = PciImpl::msix_info(&mut bus, a).unwrap();
        assert_eq!(info.table_size, 2048);
    }
    #[test]
    fn msix_info_rejects_function_without_capabilities() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0000_0000);
        let r = PciImpl::msix_info(&mut bus, a);
        assert_eq!(r, Err(PciError::NoCapabilities));
    }
    #[test]
    fn msix_set_enable_on_sets_enable_clears_funcmask() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x70, 0x4000_0011);
        let info = PciMsixInfo {
            cap_offset: 0x70,
            table_size: 8,
            table_bar: 4,
            table_offset: 0x2000,
            pba_bar: 4,
            pba_offset: 0x3000,
        };
        PciImpl::msix_set_enable(&mut bus, a, &info, true);
        let w = bus.write_at(0).unwrap();
        assert_eq!(w.value & 0x0000_FFFF, 0x0000_0011);
        assert_eq!(
            (w.value >> 16) as u16 & PCI_MSIX_ENABLE_BIT,
            PCI_MSIX_ENABLE_BIT
        );
        assert_eq!((w.value >> 16) as u16 & PCI_MSIX_FUNCMASK_BIT, 0);
    }
    #[test]
    fn msix_set_enable_off_clears_enable_only() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x70, 0xC000_0011);
        let info = PciMsixInfo {
            cap_offset: 0x70,
            table_size: 8,
            table_bar: 4,
            table_offset: 0x2000,
            pba_bar: 4,
            pba_offset: 0x3000,
        };
        PciImpl::msix_set_enable(&mut bus, a, &info, false);
        let w = bus.write_at(0).unwrap();
        assert_eq!((w.value >> 16) as u16 & PCI_MSIX_ENABLE_BIT, 0);
        assert_eq!(
            (w.value >> 16) as u16 & PCI_MSIX_FUNCMASK_BIT,
            PCI_MSIX_FUNCMASK_BIT
        );
    }
    #[test]
    fn recording_bus_missing_script_returns_empty_sentinel() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 0, 0);
        assert_eq!(bus.read_dword(a, 0x00), 0xFFFF_FFFF);
    }
    #[test]
    fn recording_bus_write_then_read_observes_value() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0x0000_0001);
        bus.write_dword(a, 0x04, 0x0000_0007);
        assert_eq!(bus.read_dword(a, 0x04), 0x0000_0007);
        assert_eq!(bus.write_count(), 1);
        assert_eq!(bus.write_at(0).unwrap().value, 0x0000_0007);
    }
    #[test]
    fn recording_bus_masks_offset_bottom_two_bits() {
        let mut bus = RecordingBus::new();
        let a = addr(0, 3, 0);
        bus.set(a, 0x04, 0xDEAD_BEEF);
        assert_eq!(bus.read_dword(a, 0x05), 0xDEAD_BEEF);
        assert_eq!(bus.read_dword(a, 0x07), 0xDEAD_BEEF);
    }
    #[test]
    fn enumerate_qemu_typical_topology_three_devices() {
        let mut bus = RecordingBus::new();
        script_device(
            &mut bus,
            addr(0, 0, 0),
            0x8086,
            0x1237,
            CLASS_BRIDGE,
            SUBCLASS_HOST_BRIDGE,
            0,
            0,
            0,
        );
        script_device(
            &mut bus,
            addr(0, 3, 0),
            0x8086,
            0x100E,
            CLASS_NETWORK,
            SUBCLASS_ETHERNET,
            0,
            3,
            0,
        );
        script_device(
            &mut bus,
            addr(0, 5, 0),
            0x8086,
            0x5845,
            CLASS_MASS_STORAGE,
            SUBCLASS_NVME,
            2,
            0,
            0,
        );
        let mut names: [&'static str; 4] = [""; 4];
        let mut n = 0usize;
        PciImpl::enumerate(&mut bus, &mut |d| {
            if n < names.len() {
                names[n] = PciImpl::class_name(d.class, d.subclass);
                n += 1;
            }
        });
        assert_eq!(n, 3);
        assert_eq!(names[0], "Bridge: Host");
        assert_eq!(names[1], "Network: Ethernet");
        assert_eq!(names[2], "Mass Storage: NVMe");
    }
}
