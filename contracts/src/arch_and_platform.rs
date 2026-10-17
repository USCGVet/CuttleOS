//! x86_64 architecture and platform contracts: SMP, PCI, xHCI, UEFI GOP, IOAPIC, LAPIC, Multiboot2, ACPI RSDP, Serial 16550, TickSource, Watchdog, Power, ELF64, HPET, Keyboard, PIT, and RTC.

use super::*;

// ---------------------------------------------------------------------------
// Smp — multi-core bring-up + per-CPU storage (TASK-057)
// ---------------------------------------------------------------------------

/// Maximum number of CPUs the seed's `PerCpu` storage supports. Larger
/// systems (>64 cores) are out of scope for the seed; a future
/// schema-compatible extension can bump this.
pub const MAX_CPUS: usize = 64;

/// Local APIC ID — the 8-bit identifier each x86_64 logical CPU
/// presents in its `CPUID 0xB` leaf and the ACPI MADT.
pub type ApicId = u8;

/// Intel SDM Vol 3A §10.6 — Interrupt Command Register (ICR) field
/// constants. Locked: the diversifier cannot morph these values
/// without breaking real-hardware AP bring-up. Used both by the
/// seed's `wake_aps` driver and (in the future) by the real-APIC
/// kernel-side implementation.
pub mod smp_consts {
    /// ICR `Delivery Mode` field = INIT (0b101 << 8).
    pub const ICR_DELIVERY_INIT: u32 = 5 << 8;
    /// ICR `Delivery Mode` field = Start-Up (0b110 << 8).
    pub const ICR_DELIVERY_STARTUP: u32 = 6 << 8;
    /// ICR `Level` field = Assert (1 << 14).
    pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
    /// ICR `Level` field = De-assert (0 << 14).
    pub const ICR_LEVEL_DEASSERT: u32 = 0;
    /// ICR `Trigger Mode` field = Level (1 << 15).
    pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;
    /// ICR `Destination Shorthand` = All-Excluding-Self (0b11 << 18).
    pub const ICR_DEST_SHORTHAND_ALL_EXCL_SELF: u32 = 3 << 18;
    /// ICR `Delivery Status` (RO, bit 12). When set after an ICR_low
    /// write, the previous IPI is still in flight.
    pub const ICR_DELIVERY_STATUS_PENDING: u32 = 1 << 12;
    /// Vector-field mask for SIPI: low 8 bits of ICR_low encode the
    /// real-mode page number to start the AP from.
    pub const ICR_VECTOR_MASK: u32 = 0xFF;
    /// Bit-shift to place an `ApicId` into the upper 8 bits of
    /// ICR-high (target CPU identifier).
    pub const ICR_HIGH_DEST_SHIFT: u32 = 24;
    /// SDM §10.4.7.1: spec-mandated 10 ms between INIT and first SIPI.
    pub const SMP_INIT_TO_SIPI_US: u32 = 10_000;
    /// SDM §10.4.7.1: spec-mandated 200 µs between successive SIPIs.
    pub const SMP_SIPI_TO_SIPI_US: u32 = 200;
    /// Bounded retry budget for `wait_for_idle` to observe the
    /// previous IPI's delivery-status clearing.
    pub const SMP_DELIVERY_RETRY_BUDGET: u32 = 1_000;
}

/// ACPI 6.4 §5.2.12 — Multiple APIC Description Table layout constants.
pub mod madt {
    /// MADT table signature (first 4 bytes of the table header).
    pub const SIG_APIC: [u8; 4] = *b"APIC";
    /// Subtable type code for Processor Local APIC (ACPI 6.4 §5.2.12.2).
    pub const ENTRY_LOCAL_APIC: u8 = 0;
    /// Subtable type code for I/O APIC (ACPI 6.4 §5.2.12.3). Parser
    /// skips these for now — the seed only needs the Local APIC entries.
    pub const ENTRY_IO_APIC: u8 = 1;
    /// Flag bit 0 of a Processor Local APIC entry: the CPU is
    /// **enabled** (and therefore ready to be bootstrapped).
    pub const LOCAL_APIC_FLAG_ENABLED: u32 = 1 << 0;
    /// Flag bit 1 of a Processor Local APIC entry: the CPU is
    /// **online-capable** but not currently enabled (firmware
    /// might enable it later — out of scope for the seed).
    pub const LOCAL_APIC_FLAG_ONLINE_CAPABLE: u32 = 1 << 1;
    /// Length in bytes of the MADT header before the first subtable.
    pub const HEADER_LEN: usize = 44;
    /// Length in bytes of a Processor Local APIC subtable entry.
    pub const LOCAL_APIC_ENTRY_LEN: usize = 8;
}

/// SMP-discovered topology: which CPU is the bootstrap processor and
/// which application processors must be woken. Storage-only — no
/// behaviour. Returned by [`Smp::discover`].
#[derive(Debug, Clone, Copy)]
pub struct CpuTopology {
    /// Bootstrap processor's APIC ID (the CPU the firmware boots).
    /// Selected as the first **enabled** Processor Local APIC entry
    /// in the MADT.
    pub bsp: ApicId,
    /// Application processor APIC IDs, in MADT discovery order.
    /// Only the first `ap_count` slots are valid.
    pub aps: [ApicId; MAX_CPUS],
    /// Number of AP IDs in `aps`. Always strictly less than `MAX_CPUS`.
    pub ap_count: usize,
}

impl CpuTopology {
    /// Total CPU count (BSP + APs).
    #[inline]
    pub fn cpu_count(&self) -> usize {
        1 + self.ap_count
    }

    /// View into the populated portion of `aps`.
    #[inline]
    pub fn ap_ids(&self) -> &[ApicId] {
        &self.aps[..self.ap_count]
    }
}

/// Errors from the SMP bring-up wire codec. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SmpError {
    /// MADT signature byte sequence isn't `b"APIC"`.
    BadMadtSignature,
    /// MADT header is truncated, an entry's length-byte is invalid,
    /// or an entry runs past the table's `Length` field.
    BadMadtEntry,
    /// MADT contains more enabled Processor Local APIC entries than
    /// the seed's `MAX_CPUS` slot table can hold.
    TooManyCpus,
    /// MADT walked clean but contained zero enabled Processor Local
    /// APIC entries — there is no BSP to designate.
    NoEnabledCpu,
    /// `wait_for_idle` exhausted its retry budget without observing
    /// the previous IPI's delivery-status bit clearing. In a real
    /// kernel: hardware fault. In tests: harness misconfigured.
    ApicTimeout,
    /// `trampoline_pa` doesn't satisfy the SIPI vector encoding
    /// constraints (not page-aligned, or page-number is 0 or 0xFF).
    BadIpiVector,
    /// [`PerCpu`] table has no free slot for a new APIC ID.
    PerCpuOverflow,
    /// [`PerCpu::get`] / `try_get` invoked with an APIC ID that was
    /// never registered.
    UnknownApicId,
}

/// MMIO surface for the Local APIC ICR (Interrupt Command Register).
/// Caller-supplied so the seed's [`Smp::wake_aps`] can be exercised
/// against a recording test harness AND against the real APIC at
/// kernel runtime through the same trait surface.
///
/// On real x86_64 hardware the Local APIC is MMIO-mapped at
/// `MSR_IA32_APIC_BASE`; ICR_low lives at offset 0x300, ICR_high at
/// offset 0x310. The kernel-side implementation wraps those reads
/// + writes; the test harness records every call into a Vec for
/// later assertion against a locked golden.
pub trait ApicWriter {
    /// Write the low 32 bits of the ICR. Writing ICR-low is what
    /// triggers IPI delivery — ICR-high must already hold the target.
    fn write_icr_low(&mut self, val: u32);
    /// Write the high 32 bits of the ICR. The upper 8 bits are the
    /// destination APIC ID (see `smp_consts::ICR_HIGH_DEST_SHIFT`).
    fn write_icr_high(&mut self, val: u32);
    /// Read the low 32 bits of the ICR. Used by `wait_for_idle` to
    /// poll the `Delivery Status` bit.
    fn read_icr_low(&mut self) -> u32;
}

/// SMP bring-up byte-locked surface.
///
/// # Locked invariants the verifier checks
///
/// 1. [`discover`](Smp::discover) on a well-formed MADT recovers
///    every enabled Processor Local APIC entry, designates the
///    first as BSP, and packs the remainder into `CpuTopology::aps`
///    in MADT-discovery order.
/// 2. `discover` rejects malformed input via the locked `SmpError`
///    variant set; no panics, no silent truncation.
/// 3. [`wake_aps`](Smp::wake_aps) emits exactly 3 IPIs per AP
///    (INIT, SIPI, SIPI), in that order. The 9-write sequence for
///    a 3-AP topology against a recording `ApicWriter` is locked.
/// 4. The SIPI vector encoded in ICR-low equals
///    `(trampoline_pa >> 12) & ICR_VECTOR_MASK`.
/// 5. `wake_aps` waits `SMP_INIT_TO_SIPI_US` after INIT and
///    `SMP_SIPI_TO_SIPI_US` after each SIPI before the next write,
///    via the caller-supplied `delay_us` closure (so the timing
///    contract is auditable in tests).
///
/// # Not in this contract (intentional)
///
/// - The AP-side trampoline blob itself. The seed exercises the
///   BSP-side ICR sequence only; the trampoline page contents (real-
///   mode → protected → long-mode dance) are a future surface.
/// - Real APIC MMIO reads/writes — the kernel-side implementation
///   wraps those behind `ApicWriter`. Tests use a recording harness.
/// - Actual concurrent execution on AP cores. `discover` + `wake_aps`
///   are wire-codec-shaped; no AP code runs in the seed's QEMU smoke.
/// - ACPI MADT checksum validation (sum-mod-256 = 0). The seed treats
///   the MADT as caller-pre-validated; adding the checksum check is
///   a schema-compatible extension.
pub trait Smp {
    /// Parse an ACPI MADT byte slice, returning the discovered
    /// [`CpuTopology`].
    fn discover(madt: &[u8]) -> Result<CpuTopology, SmpError>;

    /// Drive the INIT-SIPI-SIPI AP wake sequence through the
    /// caller-supplied [`ApicWriter`]. Returns the number of IPIs
    /// issued (= 3 × `topology.ap_count` on success).
    ///
    /// `trampoline_pa` is the physical address of the real-mode AP
    /// trampoline page; the SIPI vector is `(trampoline_pa >> 12)`,
    /// constrained to the inclusive range `[0x01, 0xFE]`.
    ///
    /// `delay_us` is invoked between each IPI with the SDM-mandated
    /// wait (10 ms after INIT, 200 µs after each SIPI). The caller
    /// supplies the actual timing primitive (kernel: APIC timer or
    /// TSC-deadline; tests: no-op).
    fn wake_aps(
        topology: &CpuTopology,
        trampoline_pa: u64,
        apic: &mut dyn ApicWriter,
        delay_us: &mut dyn FnMut(u32),
    ) -> Result<usize, SmpError>;
}

/// Fixed-capacity per-CPU storage indexed by APIC ID. Allocation-free.
///
/// APIC IDs aren't guaranteed dense (a hyperthreaded system might
/// present 0, 1, 4, 5), so the slot table stores `(apic_id, value)`
/// pairs and `get` / `try_get` does a linear scan over the registered
/// prefix. For `MAX_CPUS = 64` the scan is bounded at 64 comparisons
/// — within budget for any per-syscall lookup.
///
/// Locked surface: the slot-table layout + the
/// `register`/`get`/`try_get` semantics are part of the contract.
/// Internal representation (the scan loop, the field order) is
/// fully diversifiable.
pub struct PerCpu<T, const N: usize> {
    /// `Some(apic_id)` for registered slots, `None` for free slots.
    /// Indices `[0, count)` are registered; `[count, N)` are free.
    pub(crate) apic_ids: [Option<ApicId>; N],
    /// Per-CPU values. Slot `i` corresponds to `apic_ids[i]`.
    pub(crate) slots: [T; N],
    /// Count of registered entries. Always `<= N`.
    pub(crate) count: usize,
}

impl<T: Default + Copy, const N: usize> Default for PerCpu<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Default + Copy, const N: usize> PerCpu<T, N> {
    /// Construct an empty `PerCpu` with all slots free. Not `const fn`
    /// because `T::default()` is not const-stable; if a caller needs
    /// a `const`-context constructor for a specific `T` whose default
    /// IS const, they can wrap their own.
    pub fn new() -> Self {
        Self {
            apic_ids: [None; N],
            slots: [T::default(); N],
            count: 0,
        }
    }

    /// Register an APIC ID with an initial value. Returns
    /// [`SmpError::PerCpuOverflow`] when the table is full.
    pub fn register(&mut self, apic_id: ApicId, value: T) -> Result<(), SmpError> {
        if self.count >= N {
            return Err(SmpError::PerCpuOverflow);
        }
        self.apic_ids[self.count] = Some(apic_id);
        self.slots[self.count] = value;
        self.count += 1;
        Ok(())
    }

    /// Look up the slot for a registered APIC ID. Panics on
    /// unknown — kernel-internal invariant violation. Use
    /// [`try_get`](PerCpu::try_get) when the caller can recover.
    pub fn get(&mut self, apic_id: ApicId) -> &mut T {
        match self.try_get(apic_id) {
            Some(slot) => slot,
            None => panic!("PerCpu::get on unregistered APIC ID"),
        }
    }

    /// Try-form of [`get`](PerCpu::get) — returns `None` for an
    /// unregistered APIC ID instead of panicking.
    pub fn try_get(&mut self, apic_id: ApicId) -> Option<&mut T> {
        let mut i = 0usize;
        while i < self.count {
            if self.apic_ids[i] == Some(apic_id) {
                return Some(&mut self.slots[i]);
            }
            i += 1;
        }
        None
    }

    /// Number of registered slots.
    #[inline]
    pub fn count(&self) -> usize {
        self.count
    }

    /// Capacity (compile-time `N`).
    #[inline]
    pub const fn capacity() -> usize {
        N
    }
}

// ============================================================
// TASK-059: PCI bus enumeration (legacy 0xCF8/0xCFC config
// mechanism #1)
// ============================================================
//
// Wire-codec-shaped surface that lets the seed discover every
// PCI function on the bus, decode BARs and the MSI-X capability
// block, and toggle bus-master enable. The kernel-side
// implementation wraps the actual `out`/`in` opcodes; tests
// substitute a recording bus harness that returns scripted
// dwords for `(bus, device, function, offset)` tuples.

/// I/O port for the PCI configuration-address register.
pub const PCI_CONFIG_ADDRESS_PORT: u16 = 0xCF8;
/// I/O port for the PCI configuration-data register.
pub const PCI_CONFIG_DATA_PORT: u16 = 0xCFC;
/// "No device responded" sentinel returned by the vendor-id field of an
/// empty configuration-space slot.
pub const PCI_VENDOR_NONE: u16 = 0xFFFF;
/// PCI buses to scan during a full enumeration. The legacy mechanism
/// #1 addressing space covers 256 buses × 32 devices × 8 functions =
/// 65,536 configuration cycles per scan.
pub const PCI_MAX_BUS: u16 = 256;
/// Devices per PCI bus.
pub const PCI_MAX_DEVICE: u8 = 32;
/// Functions per PCI device. Only multi-function devices (header_type
/// bit 7 set) populate functions 1..7.
pub const PCI_MAX_FUNCTION: u8 = 8;
/// Bit 7 of the header_type byte at config offset 0x0E. Set means the
/// function is part of a multi-function device — probe the remaining
/// functions; clear means functions 1..7 are reserved and the enumerator
/// must NOT issue a config cycle for them (skips ghost echoes on some
/// chipsets).
pub const PCI_HEADER_MULTIFUNC_BIT: u8 = 0x80;
/// PCI capability ID for legacy MSI (per PCI Local Bus Spec §6.8).
pub const PCI_CAP_ID_MSI: u8 = 0x05;
/// PCI capability ID for MSI-X (per PCI Local Bus Spec §6.8.2).
pub const PCI_CAP_ID_MSIX: u8 = 0x11;
/// Bit 4 of the status register at config offset 0x06. Set means the
/// function exposes a capabilities list at offset 0x34.
pub const PCI_STATUS_CAPABILITIES_LIST: u16 = 1 << 4;
/// Hard cap on capability-list hops during a `find_capability` walk.
/// Real firmware lists rarely exceed 8 entries; the bound exists to
/// guard against a buggy chipset that builds a circular list.
pub const PCI_MAX_CAP_HOPS: u8 = 48;
/// Config offset of the vendor-id (LSB) + device-id (MSB) dword.
pub const PCI_CFG_OFFSET_VENDOR_DEVICE: u8 = 0x00;
/// Config offset of the command (LSB 16) + status (MSB 16) dword.
pub const PCI_CFG_OFFSET_COMMAND_STATUS: u8 = 0x04;
/// Config offset of the class + subclass + prog-if + revision dword.
pub const PCI_CFG_OFFSET_CLASS_REVISION: u8 = 0x08;
/// Config offset of the cache-line size + latency + header_type + BIST
/// dword. `header_type` is the third byte (bits 16..23).
pub const PCI_CFG_OFFSET_HEADER_LATENCY: u8 = 0x0C;
/// Config offset of BAR0. BARs are 4 bytes apart; BAR_idx lives at
/// `PCI_CFG_OFFSET_BAR0 + idx * 4`.
pub const PCI_CFG_OFFSET_BAR0: u8 = 0x10;
/// Config offset of the interrupt-line (LSB) + interrupt-pin (next) +
/// min-grant + max-latency dword. Interrupt-line is the firmware-
/// programmed legacy IRQ for the device's INTx pin.
pub const PCI_CFG_OFFSET_INT_LINE: u8 = 0x3C;
/// Config offset of the capabilities pointer (LSB byte; bits 0..7 of
/// the dword). Only valid when the capabilities-list status bit is set.
pub const PCI_CFG_OFFSET_CAP_PTR: u8 = 0x34;
/// Bit 2 of the command register: Bus Master Enable. Required for
/// any DMA-capable device.
pub const PCI_COMMAND_BUS_MASTER: u32 = 1 << 2;
/// Bit 0 of a BAR's low dword: 1 = port-I/O space, 0 = MMIO.
pub const PCI_BAR_TYPE_IO_BIT: u32 = 0x1;
/// Bits 1..2 of an MMIO BAR's low dword carry the memory-type encoding.
pub const PCI_BAR_MMIO_TYPE_MASK: u32 = 0x6;
/// Bits 1..2 encoded value = 0b10: this BAR is the low half of a
/// 64-bit address; the adjacent (idx+1) BAR is the high half.
pub const PCI_BAR_MMIO_TYPE_64BIT: u32 = 0x2 << 1;
/// Address bits of an MMIO BAR — the low 4 bits carry flags
/// (type, prefetchable) which the caller must mask off.
pub const PCI_BAR_MMIO_ADDR_MASK: u32 = !0xF;
/// Address bits of an I/O-space BAR — the low 2 bits are reserved
/// (low bit carries the type discriminator).
pub const PCI_BAR_IO_ADDR_MASK: u32 = !0x3;
/// Sentinel value of the interrupt-line byte meaning "no legacy
/// IRQ wired" — caller should fall back to MSI / MSI-X.
pub const PCI_BAR_INT_LINE_NONE: u8 = 0xFF;
/// Maximum valid BAR index. BARs 0..=5 — a 64-bit BAR consumes two
/// slots so the caller may not request `idx=5` for a 64-bit pair.
pub const PCI_MAX_BAR_INDEX: u8 = 5;
/// Bits 0..10 of an MSI-X capability's message-control word encode
/// `table_size - 1`. The decoded `table_size` is in 1..=2048.
pub const PCI_MSIX_TABLE_SIZE_MASK: u16 = 0x07FF;
/// Low 3 bits of the MSI-X table_offset / pba_offset dwords are the
/// BAR Indicator Register — they name which BAR (0..=5) holds the
/// table or PBA.
pub const PCI_MSIX_BIR_MASK: u32 = 0x07;
/// Bit 15 of the MSI-X message-control word: function-level enable.
pub const PCI_MSIX_ENABLE_BIT: u16 = 1 << 15;
/// Bit 14 of the MSI-X message-control word: function mask.
pub const PCI_MSIX_FUNCMASK_BIT: u16 = 1 << 14;

/// PCI class / subclass discriminator constants. Names match the
/// "PCI Code and ID Assignment Specification" §1.4. Only the classes
/// the seed has any reason to mention are enumerated; everything
/// else falls through to "Other / Unknown".
pub mod pci_class {
    /// Mass-storage class (NVMe, SATA, IDE, etc.).
    pub const CLASS_MASS_STORAGE: u8 = 0x01;
    /// IDE subclass.
    pub const SUBCLASS_IDE: u8 = 0x01;
    /// SATA subclass.
    pub const SUBCLASS_SATA: u8 = 0x06;
    /// NVMe subclass.
    pub const SUBCLASS_NVME: u8 = 0x08;
    /// Network controller class.
    pub const CLASS_NETWORK: u8 = 0x02;
    /// Ethernet subclass.
    pub const SUBCLASS_ETHERNET: u8 = 0x00;
    /// Display controller class.
    pub const CLASS_DISPLAY: u8 = 0x03;
    /// VGA-compatible display subclass.
    pub const SUBCLASS_VGA: u8 = 0x00;
    /// Bridge device class.
    pub const CLASS_BRIDGE: u8 = 0x06;
    /// Host bridge subclass.
    pub const SUBCLASS_HOST_BRIDGE: u8 = 0x00;
    /// ISA bridge subclass.
    pub const SUBCLASS_ISA_BRIDGE: u8 = 0x01;
    /// PCI-to-PCI bridge subclass.
    pub const SUBCLASS_PCI_BRIDGE: u8 = 0x04;
    /// Serial-bus controller class.
    pub const CLASS_SERIAL_BUS: u8 = 0x0C;
    /// USB subclass.
    pub const SUBCLASS_USB: u8 = 0x03;
}

/// Identifies a PCI function by its (bus, device, function) triple.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciAddress {
    /// Bus number, 0..=255.
    pub bus: u8,
    /// Device slot on the bus, 0..=31.
    pub device: u8,
    /// Function number within the device, 0..=7.
    pub function: u8,
}

/// Decoded per-function identification block (vendor + device + class).
/// Storage-only; emitted by [`Pci::probe`] / [`Pci::enumerate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciDevice {
    /// Location of the function on the bus.
    pub addr: PciAddress,
    /// Vendor identifier (low 16 bits of the identification dword).
    pub vendor_id: u16,
    /// Device identifier (high 16 bits of the identification dword).
    pub device_id: u16,
    /// Class code (byte 3 of the class/revision dword).
    pub class: u8,
    /// Subclass code (byte 2 of the class/revision dword).
    pub subclass: u8,
    /// Programming interface (byte 1 of the class/revision dword).
    pub prog_if: u8,
    /// Revision identifier (byte 0 of the class/revision dword).
    pub revision: u8,
    /// Header-type byte (byte 2 of the header/latency dword). Bit 7
    /// distinguishes single-function (0) from multi-function (1).
    pub header_type: u8,
}

/// Decoded BAR (Base Address Register) entry. 64-bit MMIO BARs span
/// two adjacent config-space dwords; this enum collapses that into
/// a single decoded value the caller can match on.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciBar {
    /// 32-bit memory-mapped I/O at this physical address.
    Mmio32(u32),
    /// 64-bit memory-mapped I/O at this physical address.
    Mmio64(u64),
    /// Port-I/O at this base port (lower 32 bits only — PCI never
    /// exposes 64-bit I/O space).
    Io(u32),
}

/// Decoded MSI-X capability header. Storage-only; emitted by
/// [`Pci::msix_info`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PciMsixInfo {
    /// Config-space byte offset of this device's MSI-X capability
    /// block (the first byte is the capability-id, equal to
    /// [`PCI_CAP_ID_MSIX`]).
    pub cap_offset: u8,
    /// Number of MSI-X table entries the device supports (1..=2048).
    /// Decoded as `(message_control & PCI_MSIX_TABLE_SIZE_MASK) + 1`.
    pub table_size: u16,
    /// BAR index (0..=5) that holds the MSI-X table.
    pub table_bar: u8,
    /// Byte offset of the table within that BAR.
    pub table_offset: u32,
    /// BAR index (0..=5) that holds the Pending Bit Array.
    pub pba_bar: u8,
    /// Byte offset of the PBA within that BAR.
    pub pba_offset: u32,
}

/// Errors emitted by [`Pci::read_bar`], [`Pci::find_capability`], and
/// [`Pci::msix_info`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PciError {
    /// `idx > PCI_MAX_BAR_INDEX`, or a 64-bit MMIO BAR was requested
    /// at index 5 (the high half would fall off the BAR table).
    BadBarIndex,
    /// The requested BAR's low dword reads as zero — the firmware
    /// hasn't programmed an address for this slot.
    EmptyBar,
    /// The status register's capabilities-list bit
    /// ([`PCI_STATUS_CAPABILITIES_LIST`]) was clear, so no capability
    /// chain exists to walk.
    NoCapabilities,
    /// Walked the capability chain to its null terminator without
    /// finding the requested `cap_id`.
    CapabilityNotFound,
    /// Walked [`PCI_MAX_CAP_HOPS`] entries without reaching the chain
    /// terminator — assumed to be a circular list (firmware bug).
    CapWalkOverflow,
    /// Capability pointer below the configuration-space header
    /// boundary at 0x34, or beyond 0xFC (the last aligned 4-byte
    /// slot in the standard 256-byte config window).
    BadCapPointer,
}

/// MMIO / port-I/O surface for PCI configuration-space access. Caller-
/// supplied so the seed's [`Pci`] driver can be exercised against a
/// recording test harness AND against the real 0xCF8/0xCFC port pair
/// at kernel runtime through the same trait surface.
///
/// On real x86_64 hardware the implementation writes the (1 << 31 |
/// bus << 16 | device << 11 | function << 8 | offset & 0xFC)
/// address into port 0xCF8, then issues a 32-bit `in`/`out` against
/// port 0xCFC. The test harness records every call into a fixture
/// table indexed by the address tuple and returns the scripted dword.
pub trait PciConfigBus {
    /// Read a 32-bit dword from the function's configuration space at
    /// the given byte offset. `offset` is masked with `0xFC` on the
    /// wire — the bottom two bits must be zero in the address register
    /// per PCI Local Bus Spec §3.2.2.3.4.
    fn read_dword(&mut self, addr: PciAddress, offset: u8) -> u32;
    /// Write a 32-bit dword into the function's configuration space at
    /// the given byte offset. Same alignment rule as `read_dword`.
    fn write_dword(&mut self, addr: PciAddress, offset: u8, value: u32);
}

/// PCI configuration-space byte-locked surface.
///
/// # Locked invariants the verifier checks
///
/// 1. [`probe`](Pci::probe) on a slot whose vendor-id reads as
///    [`PCI_VENDOR_NONE`] returns `None`; otherwise it returns
///    `Some(PciDevice)` with every field decoded from the three
///    standard config-space dwords (0x00 / 0x08 / 0x0C).
/// 2. [`enumerate`](Pci::enumerate) walks the full (bus 0..=255,
///    device 0..32, function 0..=7) address space, calling the sink
///    once per responding function. Functions 1..7 are probed only
///    when function 0's `header_type` has [`PCI_HEADER_MULTIFUNC_BIT`]
///    set (the single-function fast path that avoids ghost echoes).
/// 3. [`read_bar`](Pci::read_bar) decodes the per-BAR low dword into
///    [`PciBar::Mmio32`] / [`PciBar::Mmio64`] / [`PciBar::Io`] per
///    the PCI Local Bus Spec §6.2.5.1 encoding, masking off the type
///    and prefetch flags. 64-bit BARs read the high half from
///    `idx + 1` and reject `idx == 5`.
/// 4. [`find_capability`](Pci::find_capability) walks the linked list
///    rooted at [`PCI_CFG_OFFSET_CAP_PTR`] with hop bound
///    [`PCI_MAX_CAP_HOPS`], returning the offset of the first
///    capability whose ID matches.
/// 5. [`msix_info`](Pci::msix_info) decodes the standard MSI-X
///    capability header per PCI 3.0 §6.8.2 — message-control word
///    yields `table_size`; the next two dwords yield (BIR, offset)
///    for the table and PBA respectively.
/// 6. [`enable_bus_master`](Pci::enable_bus_master) does a 32-bit
///    read-modify-write of the command/status dword that sets exactly
///    [`PCI_COMMAND_BUS_MASTER`] and preserves every other bit.
///
/// # Not in this contract (intentional)
///
/// - PCIe extended configuration space (offset > 0xFC). The seed uses
///   mechanism #1 which exposes only the legacy 256-byte window.
/// - PCI-to-PCI bridge secondary-bus recursion. QEMU's chipsets expose
///   every secondary bus in the same flat address space we already
///   iterate; real hardware sometimes hides one — schema-compatible
///   future extension.
/// - BAR sizing (write all-ones, read-back, decode size). The seed
///   reads BAR addresses, not their sizes; adding `bar_size` is a
///   schema-compatible extension.
/// - MSI (non-X) capability decode. The legacy MSI block is documented
///   via [`PCI_CAP_ID_MSI`] but no decoder ships in the seed.
pub trait Pci {
    /// Read the per-function identification block. Returns `None` if
    /// the slot is empty (vendor == [`PCI_VENDOR_NONE`]).
    fn probe(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Option<PciDevice>;

    /// Walk every `(bus, device, function)` and invoke `sink` for each
    /// responding function. Allocation-free.
    fn enumerate(bus: &mut dyn PciConfigBus, sink: &mut dyn FnMut(PciDevice));

    /// Human-readable name for a (class, subclass) pair. Only covers
    /// the classes the seed has any reason to mention; everything else
    /// falls through to "Other / Unknown".
    fn class_name(class: u8, subclass: u8) -> &'static str;

    /// Read the firmware-programmed interrupt line byte at config
    /// offset 0x3C. Returns `None` for the legacy "no connection"
    /// sentinel [`PCI_BAR_INT_LINE_NONE`].
    fn int_line(bus: &mut dyn PciConfigBus, addr: PciAddress) -> Option<u8>;

    /// Read BAR `idx` (0..=5) for the function at `addr` and decode it
    /// into a [`PciBar`]. 64-bit MMIO BARs are read as a pair and
    /// collapsed into [`PciBar::Mmio64`].
    fn read_bar(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        idx: u8,
    ) -> Result<PciBar, PciError>;

    /// Set the bus-master-enable bit (bit 2) of the command register
    /// at config offset 0x04. Preserves the rest of the command word
    /// and the read-only status word in the upper half of the dword.
    fn enable_bus_master(bus: &mut dyn PciConfigBus, addr: PciAddress);

    /// Walk the per-function capability list and return the offset of
    /// the first capability whose ID matches `cap_id`. Bounded at
    /// [`PCI_MAX_CAP_HOPS`] hops to defend against a circular list.
    fn find_capability(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        cap_id: u8,
    ) -> Result<u8, PciError>;

    /// Probe the function for an MSI-X capability and return its
    /// decoded header. Composes `find_capability(cap_id =
    /// PCI_CAP_ID_MSIX)` with the message-control / table-pointer /
    /// PBA-pointer dword reads.
    fn msix_info(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
    ) -> Result<PciMsixInfo, PciError>;

    /// Set the MSI-X capability's enable bit (bit 15 of
    /// message-control) to `on`. When `on=true` the function-mask
    /// bit is also cleared so the per-entry mask bits become the
    /// only gate.
    fn msix_set_enable(
        bus: &mut dyn PciConfigBus,
        addr: PciAddress,
        info: &PciMsixInfo,
        on: bool,
    );
}

// ============================================================
// XhciTrb — USB3 Transfer Request Block No-Op + Link (TASK-089)
// ============================================================

/// TRB size in bytes (4 dwords).
pub const XHCI_TRB_LEN: usize = 16;
/// TRB Type: Link.
pub const XHCI_TRB_TYPE_LINK: u8 = 6;
/// TRB Type: No-Op Transfer TRB.
pub const XHCI_TRB_TYPE_NOOP: u8 = 8;
/// Cycle bit in TRB dword 3 bit 0.
pub const XHCI_TRB_CYCLE: u32 = 1 << 0;
/// Toggle Cycle bit in Link TRB dword 3 bit 1.
pub const XHCI_TRB_TOGGLE_CYCLE: u32 = 1 << 1;
/// TRB Type field shift in dword 3 (bits 15:10).
pub const XHCI_TRB_TYPE_SHIFT: u32 = 10;

/// Four little-endian dwords of one TRB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciTrbWords {
    /// Parameter low / ring segment pointer low.
    pub d0: u32,
    /// Parameter high / ring segment pointer high.
    pub d1: u32,
    /// Status dword.
    pub d2: u32,
    /// Control dword (Cycle + Type + flags).
    pub d3: u32,
}

/// XHCI TRB codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciTrbError {
    /// Buffer shorter than [`XHCI_TRB_LEN`].
    Truncated,
    /// Link ring pointer not 16-byte aligned.
    BadAlign,
}

/// xHCI Transfer Request Block encoder for No-Op and Link TRBs.
pub trait XhciTrb {
    /// Encode a No-Op Transfer TRB (`type = 8`) with the given cycle bit.
    fn encode_noop(cycle: bool) -> XhciTrbWords;
    /// Encode a Link TRB pointing at `ring_ptr` (must be 16-byte aligned).
    fn encode_link(
        ring_ptr: u64,
        cycle: bool,
        toggle_cycle: bool,
    ) -> Result<XhciTrbWords, XhciTrbError>;
    /// Extract TRB Type field from dword 3.
    fn trb_type(d3: u32) -> u8;
    /// Serialize words to 16 little-endian bytes.
    fn to_bytes(w: &XhciTrbWords, out: &mut [u8]) -> Result<usize, XhciTrbError>;
    /// Parse 16 little-endian bytes into words.
    fn from_bytes(buf: &[u8]) -> Result<XhciTrbWords, XhciTrbError>;
}

// ============================================================
// UefiGop — Graphics Output Protocol mode info view (TASK-090)
// ============================================================

/// Packed GOP mode info length (version, H, V, format, 4×mask, ppsl).
pub const GOP_MODE_INFO_LEN: usize = 40;
/// Pixel format: RGB reserved 8-bit per color.
pub const GOP_PIXEL_RGB: u32 = 0;
/// Pixel format: BGR reserved 8-bit per color.
pub const GOP_PIXEL_BGR: u32 = 1;
/// Pixel format: bit mask.
pub const GOP_PIXEL_BITMASK: u32 = 2;
/// Pixel format: Blt-only.
pub const GOP_PIXEL_BLT_ONLY: u32 = 3;

/// UEFI GOP mode information (subset of EFI_GRAPHICS_OUTPUT_MODE_INFORMATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GopModeInfo {
    /// Structure version (0 for current UEFI).
    pub version: u32,
    /// Horizontal resolution in pixels.
    pub horizontal: u32,
    /// Vertical resolution in pixels.
    pub vertical: u32,
    /// Pixel format enum ([`GOP_PIXEL_RGB`], …).
    pub pixel_format: u32,
    /// Red mask (bitmask format only; else 0).
    pub red_mask: u32,
    /// Green mask.
    pub green_mask: u32,
    /// Blue mask.
    pub blue_mask: u32,
    /// Reserved mask.
    pub reserved_mask: u32,
    /// Pixels per scan line (≥ horizontal).
    pub pixels_per_scan_line: u32,
}

/// GOP codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GopError {
    /// Buffer shorter than [`GOP_MODE_INFO_LEN`].
    Truncated,
    /// Geometry inconsistent (e.g. zero resolution).
    BadGeometry,
}

/// UEFI Graphics Output Protocol mode-info pack/unpack.
pub trait UefiGop {
    /// Pack mode info into little-endian bytes (40 bytes).
    fn encode(info: &GopModeInfo, out: &mut [u8]) -> Result<usize, GopError>;
    /// Unpack mode info from little-endian bytes.
    fn decode(buf: &[u8]) -> Result<GopModeInfo, GopError>;
    /// Canonical 1280×720 RGB mode used by the kernel banner.
    fn mode_1280x720() -> GopModeInfo;
}

// ============================================================
// IoApic — redirection table entry encode (TASK-083)
// ============================================================

/// Delivery mode: fixed.
pub const IOAPIC_DELIVERY_FIXED: u8 = 0;
/// Delivery mode: lowest priority.
pub const IOAPIC_DELIVERY_LOWEST: u8 = 1;
/// Delivery mode: SMI.
pub const IOAPIC_DELIVERY_SMI: u8 = 2;
/// Delivery mode: NMI.
pub const IOAPIC_DELIVERY_NMI: u8 = 4;
/// Delivery mode: INIT.
pub const IOAPIC_DELIVERY_INIT: u8 = 5;
/// Delivery mode: ExtINT.
pub const IOAPIC_DELIVERY_EXTINT: u8 = 7;
/// Destination mode: physical.
pub const IOAPIC_DEST_PHYSICAL: u8 = 0;
/// Destination mode: logical.
pub const IOAPIC_DEST_LOGICAL: u8 = 1;
/// Trigger: edge.
pub const IOAPIC_TRIGGER_EDGE: u8 = 0;
/// Trigger: level.
pub const IOAPIC_TRIGGER_LEVEL: u8 = 1;
/// Pin polarity: active high.
pub const IOAPIC_POLARITY_HIGH: u8 = 0;
/// Pin polarity: active low.
pub const IOAPIC_POLARITY_LOW: u8 = 1;
/// Mask bit set = masked.
pub const IOAPIC_MASKED: u8 = 1;

/// Decoded IOAPIC redirection table entry (low + high dwords).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicRedir {
    /// Interrupt vector 0x10..=0xFE.
    pub vector: u8,
    /// Delivery mode (3 bits).
    pub delivery: u8,
    /// Destination mode (1 bit).
    pub dest_mode: u8,
    /// Polarity.
    pub polarity: u8,
    /// Trigger mode.
    pub trigger: u8,
    /// Mask bit.
    pub mask: u8,
    /// Destination APIC id (bits 56..63 of high dword).
    pub dest: u8,
}

/// IOAPIC redtable codec.
pub trait IoApic {
    /// Pack entry into (low, high) dwords.
    fn encode(e: &IoApicRedir) -> (u32, u32);
    /// Unpack (low, high) dwords.
    fn decode(low: u32, high: u32) -> IoApicRedir;
}

// ============================================================
// LapicIcr — ICR INIT/SIPI command builder (TASK-084)
// ============================================================

/// ICR delivery: Fixed.
pub const ICR_DELIVERY_FIXED: u32 = 0 << 8;
/// ICR delivery: INIT.
pub const ICR_DELIVERY_INIT: u32 = 5 << 8;
/// ICR delivery: Start-Up (SIPI).
pub const ICR_DELIVERY_SIPI: u32 = 6 << 8;
/// ICR level assert.
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// ICR level deassert.
pub const ICR_LEVEL_DEASSERT: u32 = 0 << 14;
/// ICR trigger level.
pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;
/// ICR dest shorthand: no shorthand.
pub const ICR_DEST_NONE: u32 = 0 << 18;
/// ICR high dword dest shift (APIC id in bits 24..31 of ICR_HIGH).
pub const ICR_HIGH_DEST_SHIFT: u32 = 24;

/// Built ICR pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcrCommand {
    /// ICR low dword (0x300).
    pub low: u32,
    /// ICR high dword (0x310).
    pub high: u32,
}

/// LAPIC ICR builder.
pub trait LapicIcr {
    /// Build INIT IPI to `apic_id` (assert then software sequences deassert).
    fn init(apic_id: u8) -> IcrCommand;
    /// Build SIPI with startup vector page (`vec` = pa >> 12, low 8 bits).
    fn sipi(apic_id: u8, startup_vec: u8) -> IcrCommand;
    /// Extract delivery mode field from low dword.
    fn delivery_of(low: u32) -> u32;
}

// ============================================================
// Multiboot2 info tag walker (TASK-079)
// ============================================================

/// Multiboot2 info total_size field is first u32.
pub const MB2_HEADER_LEN: usize = 8;
/// Tag header length (type + size).
pub const MB2_TAG_HDR_LEN: usize = 8;
/// End tag type.
pub const MB2_TAG_END: u32 = 0;
/// Basic memory info tag.
pub const MB2_TAG_BASIC_MEMINFO: u32 = 4;
/// Memory map tag.
pub const MB2_TAG_MMAP: u32 = 6;
/// Framebuffer tag.
pub const MB2_TAG_FRAMEBUFFER: u32 = 8;
/// Max tags walked.
pub const MB2_MAX_TAGS: usize = 16;

/// One Multiboot2 tag header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mb2Tag {
    /// Tag type.
    pub typ: u32,
    /// Total tag size including header.
    pub size: u32,
    /// Byte offset of tag in the info block.
    pub offset: usize,
}

/// Multiboot2 errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mb2Error {
    /// Buffer too short.
    Truncated,
    /// total_size inconsistent / tag overflow.
    BadSize,
    /// Too many tags.
    TooMany,
}

/// Multiboot2 info-block tag walker.
pub trait Multiboot2 {
    /// Walk tags in `info` (starts with total_size + reserved).
    /// Fills `out`, returns count (excluding END tag).
    fn walk(
        info: &[u8],
        out: &mut [Mb2Tag; MB2_MAX_TAGS],
    ) -> Result<usize, Mb2Error>;
    /// Find first tag of `typ`.
    fn find(tags: &[Mb2Tag], typ: u32) -> Option<Mb2Tag>;
}

// ============================================================
// AcpiRsdp — RSDP signature + checksum (TASK-081)
// ============================================================

/// RSDP signature "RSD PTR ".
pub const RSDP_SIG: [u8; 8] = *b"RSD PTR ";
/// RSDP v1 length (checksum coverage).
pub const RSDP_V1_LEN: usize = 20;
/// RSDP v2 extended length field offset.
pub const RSDP_LEN_OFF: usize = 20;

/// Parsed RSDP view (v1 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsdpV1 {
    /// OEM id 6 bytes.
    pub oem_id: [u8; 6],
    /// Revision (0 = v1, 2 = v2).
    pub revision: u8,
    /// RSDT physical address.
    pub rsdt_addr: u32,
}

/// RSDP errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsdpError {
    /// Too short.
    Truncated,
    /// Bad signature.
    BadSig,
    /// Checksum failed.
    BadChecksum,
}

/// ACPI RSDP parser.
pub trait AcpiRsdp {
    /// Parse and validate v1 fields (first 20 bytes checksum).
    fn parse_v1(bytes: &[u8]) -> Result<RsdpV1, RsdpError>;
    /// Compute 8-bit sum checksum over `bytes` (must be 0 for valid).
    fn checksum(bytes: &[u8]) -> u8;
}

// ============================================================
// Serial16550 — UART init / TX wire codec (TASK-075)
// ============================================================

/// COM1 base port.
pub const SERIAL_COM1: u16 = 0x3F8;
/// COM2 base port.
pub const SERIAL_COM2: u16 = 0x2F8;
/// Line Status Register offset from base.
pub const SERIAL_LSR_OFF: u16 = 5;
/// Line Control Register offset.
pub const SERIAL_LCR_OFF: u16 = 3;
/// FIFO Control Register offset.
pub const SERIAL_FCR_OFF: u16 = 2;
/// Modem Control Register offset.
pub const SERIAL_MCR_OFF: u16 = 4;
/// Interrupt Enable Register offset.
pub const SERIAL_IER_OFF: u16 = 1;
/// LSR bit 5: THR empty.
pub const SERIAL_LSR_THRE: u8 = 1 << 5;
/// LSR bit 0: data ready.
pub const SERIAL_LSR_DR: u8 = 1 << 0;
/// LCR DLAB bit.
pub const SERIAL_LCR_DLAB: u8 = 0x80;
/// LCR 8N1 value (DLAB off).
pub const SERIAL_LCR_8N1: u8 = 0x03;
/// Divisor latch low for 38400 baud (with 1.8432 MHz clock).
pub const SERIAL_DIVISOR_LO_38400: u8 = 0x03;
/// Divisor latch high for 38400.
pub const SERIAL_DIVISOR_HI_38400: u8 = 0x00;
/// FCR enable + clear + 14-byte trigger.
pub const SERIAL_FCR_INIT: u8 = 0xC7;
/// MCR DTR|RTS|OUT2.
pub const SERIAL_MCR_INIT: u8 = 0x0B;
/// Number of port writes in the locked init sequence.
pub const SERIAL_INIT_WRITES: usize = 7;

/// One recorded `out` in the init sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialPortWrite {
    /// Absolute I/O port.
    pub port: u16,
    /// Byte written.
    pub value: u8,
}

/// 16550 UART wire codec over [`IoPort`].
pub trait Serial16550 {
    /// Emit the locked 38400 8N1 init sequence for `base` (COM1/COM2).
    /// Returns the number of writes (always [`SERIAL_INIT_WRITES`]).
    fn init(port: &mut dyn IoPort, base: u16) -> usize;
    /// Wait for THRE then write `byte` to THR (`base + 0`).
    fn write_byte(port: &mut dyn IoPort, base: u16, byte: u8);
}

// ============================================================
// TickSource — PIT / HPET mux (TASK-076)
// ============================================================

/// Which hardware counter backs the tick view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TickKind {
    /// 8253/8254 PIT.
    Pit = 0,
    /// High Precision Event Timer.
    Hpet = 1,
}

/// Unified monotonic tick source.
pub trait TickSource {
    /// Select the active kind.
    fn select(&mut self, kind: TickKind);
    /// Currently selected kind.
    fn kind(&self) -> TickKind;
    /// Advance the synthetic counter by `delta` (test harness / IRQ).
    fn advance(&mut self, delta: u64);
    /// Current tick count for the selected source.
    fn now_ticks(&self) -> u64;
    /// Pet-friendly remaining helper: saturating sub of deadline.
    fn until(&self, deadline: u64) -> u64;
}

// ============================================================
// Watchdog — software deadline arm/pet/check (TASK-071)
// ============================================================

/// Default deadline in ticks (300 = 3 s at 100 Hz; banner-friendly).
pub const WATCHDOG_DEFAULT_DEADLINE_TICKS: u32 = 300;

/// Watchdog errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// Not armed / disabled.
    NotArmed,
    /// Deadline already fired.
    Fired,
    /// Zero deadline rejected.
    ZeroDeadline,
}

/// Software watchdog against an injected tick counter.
pub trait Watchdog {
    /// Arm with `deadline_ticks` remaining. Rejects zero.
    fn arm(&mut self, deadline_ticks: u32) -> Result<(), WatchdogError>;
    /// Reset remaining to the armed deadline.
    fn pet(&mut self) -> Result<(), WatchdogError>;
    /// Advance one tick. Returns `Err(Fired)` when remaining hits 0.
    fn tick(&mut self) -> Result<(), WatchdogError>;
    /// Cooperative check — `Err(Fired)` if previously fired.
    fn check(&self) -> Result<(), WatchdogError>;
    /// Current remaining ticks (0 if fired or not armed).
    fn remaining(&self) -> u32;
    /// Armed deadline value.
    fn deadline(&self) -> u32;
    /// True if currently armed and not fired.
    fn is_armed(&self) -> bool;
}

// ============================================================
// Power — ACPI PM1a S5 soft-off encode (TASK-073)
// ============================================================

/// PM1 control SLP_EN bit (bit 13).
pub const PM1_SLP_EN: u16 = 1 << 13;
/// SLP_TYP field shift (bits 10..12).
pub const PM1_SLP_TYP_SHIFT: u16 = 10;
/// SLP_TYP field mask (3 bits).
pub const PM1_SLP_TYP_MASK: u16 = 0b111;
/// Classic S5 sleep type value used by many firmwares.
pub const SLP_TYP_S5: u8 = 5;
/// QEMU/Bochs ACPI PM1a_CNT default I/O port.
pub const PM1A_CNT_PORT: u16 = 0x604;

/// Encoded PM1 control register view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pm1Control {
    /// Raw 16-bit PM1_CNT value.
    pub raw: u16,
}

/// Power management wire codec.
pub trait Power {
    /// Build PM1_CNT value for sleep type `slp_typ` with SLP_EN set.
    fn encode_s5(slp_typ: u8) -> Pm1Control;
    /// Extract SLP_TYP from a PM1_CNT value.
    fn decode_slp_typ(pm1: Pm1Control) -> u8;
    /// True if SLP_EN is set.
    fn is_slp_en(pm1: Pm1Control) -> bool;
}

// ============================================================
// Elf64 — ELF64 Ehdr + PT_LOAD walker (TASK-074)
// ============================================================

/// ELF magic.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// ELFCLASS64.
pub const ELF_CLASS64: u8 = 2;
/// ELFDATA2LSB.
pub const ELF_DATA_LE: u8 = 1;
/// EM_X86_64.
pub const ELF_EM_X86_64: u16 = 62;
/// ET_EXEC.
pub const ELF_ET_EXEC: u16 = 2;
/// ET_DYN.
pub const ELF_ET_DYN: u16 = 3;
/// PT_LOAD.
pub const ELF_PT_LOAD: u32 = 1;
/// Size of ELF64 Ehdr.
pub const ELF_EHDR_LEN: usize = 64;
/// Size of ELF64 Phdr.
pub const ELF_PHDR_LEN: usize = 56;
/// Max PT_LOAD segments the seed walker accepts.
pub const ELF_MAX_PHDRS: usize = 8;

/// Parsed ELF64 file header (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeader {
    /// e_entry
    pub entry: u64,
    /// e_phoff
    pub phoff: u64,
    /// e_phnum
    pub phnum: u16,
    /// e_phentsize
    pub phentsize: u16,
    /// e_type
    pub etype: u16,
    /// e_machine
    pub machine: u16,
}

/// One PT_LOAD program header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfPhdr {
    /// p_type (must be PT_LOAD for returned entries)
    pub ptype: u32,
    /// p_flags
    pub flags: u32,
    /// p_offset
    pub offset: u64,
    /// p_vaddr
    pub vaddr: u64,
    /// p_filesz
    pub filesz: u64,
    /// p_memsz
    pub memsz: u64,
    /// p_align
    pub align: u64,
}

/// ELF parse errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Buffer too short.
    Truncated,
    /// Bad magic / class / endian / machine.
    BadHeader,
    /// phentsize/phnum out of range.
    BadPhdrs,
    /// Too many PT_LOAD segments.
    TooManyLoads,
}

/// ELF64 header + PT_LOAD walker.
pub trait Elf64 {
    /// Parse Ehdr from `image`.
    fn parse_header(image: &[u8]) -> Result<ElfHeader, ElfError>;
    /// Collect PT_LOAD phdrs into `out` (capacity [`ELF_MAX_PHDRS`]).
    /// Returns count written.
    fn load_phdrs(
        image: &[u8],
        hdr: &ElfHeader,
        out: &mut [ElfPhdr; ELF_MAX_PHDRS],
    ) -> Result<usize, ElfError>;
}

// ============================================================
// Hpet — High Precision Event Timer MMIO codec (TASK-067)
// ============================================================

/// General Capabilities & ID register (64-bit, low dword at this off).
pub const HPET_REG_CAP: usize = 0x000;
/// General Configuration register.
pub const HPET_REG_CONFIG: usize = 0x010;
/// Main counter value (64-bit, low dword).
pub const HPET_REG_MAIN_COUNTER: usize = 0x0F0;
/// Timer 0 configuration / capability register.
pub const HPET_REG_TIMER0_CONFIG: usize = 0x100;
/// Timer 0 comparator value (64-bit low dword).
pub const HPET_REG_TIMER0_COMPARATOR: usize = 0x108;

/// CONFIG bit 0: ENABLE_CNF — main counter runs when set.
pub const HPET_CFG_ENABLE: u32 = 1 << 0;
/// CAP bit 13: COUNT_SIZE_CAP — 64-bit main counter when set.
pub const HPET_CAP_COUNT_SIZE_64: u32 = 1 << 13;
/// Timer-N config bit 2: interrupt enable.
pub const HPET_TN_INT_ENB: u32 = 1 << 2;
/// Timer-N config bit 3: periodic mode (1) vs one-shot (0).
pub const HPET_TN_TYPE_PERIODIC: u32 = 1 << 3;
/// Timer-N config bit 6: allow software to set accumulator.
pub const HPET_TN_VAL_SET: u32 = 1 << 6;

/// Parsed HPET capability view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpetCaps {
    /// Counter period in femtoseconds (from CAP bits 32..63).
    pub period_fs: u32,
    /// True if 64-bit main counter is supported.
    pub count_size_64: bool,
    /// Vendor ID from CAP bits 16..31.
    pub vendor_id: u16,
    /// Number of timers minus one (CAP bits 8..12) + 1 = timer count.
    pub num_timers: u8,
}

/// Errors from [`Hpet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpetError {
    /// CAP.COUNT_SIZE_CAP clear — seed requires 64-bit counter.
    Not64Bit,
    /// Period field was zero (illegal per HPET spec).
    BadPeriod,
    /// Comparator ticks computed as zero for the requested interval.
    BadInterval,
}

/// HPET MMIO wire codec over [`MmioRegBus`].
pub trait Hpet {
    /// Read and decode the CAP register pair into [`HpetCaps`].
    fn read_caps(bus: &mut dyn MmioRegBus) -> Result<HpetCaps, HpetError>;
    /// Enable the main counter (`CONFIG.ENABLE_CNF = 1`).
    fn enable(bus: &mut dyn MmioRegBus);
    /// Disable the main counter.
    fn disable(bus: &mut dyn MmioRegBus);
    /// Read the 64-bit main counter (low then high dword).
    fn read_counter(bus: &mut dyn MmioRegBus) -> u64;
    /// Program timer 0 as periodic with `comparator` ticks and enable.
    /// Returns the config dword written.
    fn program_timer0_periodic(
        bus: &mut dyn MmioRegBus,
        comparator: u64,
    ) -> Result<u32, HpetError>;
    /// Convert `period_ms` to comparator ticks given `period_fs`.
    /// `ticks = (period_ms * 1_000_000_000_000) / period_fs`  (ms→fs).
    fn ms_to_ticks(period_fs: u32, period_ms: u32) -> Result<u64, HpetError>;
}

// ============================================================
// Keyboard — PS/2 set-1 scancode decoder (TASK-069)
// ============================================================

/// Set-1 make code for `A`.
pub const KBD_MAKE_A: u8 = 0x1E;
/// Set-1 break code for `A` (`make | 0x80`).
pub const KBD_BREAK_A: u8 = 0x9E;
/// Set-1 make code for `B`.
pub const KBD_MAKE_B: u8 = 0x30;
/// Set-1 break code for `B`.
pub const KBD_BREAK_B: u8 = 0xB0;
/// Extended prefix byte.
pub const KBD_PREFIX_E0: u8 = 0xE0;
/// Pause-sequence prefix.
pub const KBD_PREFIX_E1: u8 = 0xE1;
/// Left shift make.
pub const KBD_MAKE_LSHIFT: u8 = 0x2A;
/// Left shift break.
pub const KBD_BREAK_LSHIFT: u8 = 0xAA;
/// Enter make.
pub const KBD_MAKE_ENTER: u8 = 0x1C;
/// Escape make.
pub const KBD_MAKE_ESC: u8 = 0x01;
/// Backspace make.
pub const KBD_MAKE_BACKSPACE: u8 = 0x0E;

/// Logical key identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    /// Letter A..=Z (stored as uppercase ASCII).
    Letter(u8),
    /// Digit '0'..='9'.
    Digit(u8),
    /// Enter / return.
    Enter,
    /// Escape.
    Escape,
    /// Backspace.
    Backspace,
    /// Space.
    Space,
    /// Left or right shift (indistinguished in set-1 bare).
    Shift,
    /// Left or right ctrl.
    Ctrl,
    /// Left or right alt.
    Alt,
    /// Arrow up (E0 48).
    ArrowUp,
    /// Arrow down (E0 50).
    ArrowDown,
    /// Arrow left (E0 4B).
    ArrowLeft,
    /// Arrow right (E0 4D).
    ArrowRight,
    /// Unrecognised / non-printable.
    Other(u8),
}

/// One decoded key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Key identity.
    pub code: KeyCode,
    /// True = make (press), false = break (release).
    pub pressed: bool,
    /// ASCII byte if printable and pressed; else 0.
    pub ascii: u8,
}

/// Keyboard decoder errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbError {
    /// Need more scancode bytes (prefix in flight).
    NeedMore,
    /// Byte stream produced no event (swallowed prefix/modifier).
    Consumed,
}

/// PS/2 set-1 scancode decoder.
pub trait Keyboard {
    /// Feed one scancode byte. Returns `Some(event)` when a complete
    /// make/break is decoded; `None` if the byte was a prefix or
    /// part of a multi-byte sequence still in flight.
    fn feed(&mut self, scancode: u8) -> Option<KeyEvent>;
    /// Reset prefix / modifier state.
    fn reset(&mut self);
}

// ============================================================
// PicTimer + Rtc — PIT 8253/8254 + MC146818 CMOS RTC (TASK-062)
// ============================================================

/// PIT command port (IBM PC architecture). Writes the channel /
/// access / mode / BCD command byte.
pub const PIT_CMD_PORT: u16 = 0x43;
/// PIT channel-0 data port. Divisor low then high after a command.
pub const PIT_CH0_PORT: u16 = 0x40;
/// PIT input clock frequency in Hz — fixed by IBM PC architecture
/// at ~1.193182 MHz (derived from the 14.31818 MHz crystal / 12).
pub const PIT_BASE_HZ: u32 = 1_193_182;
/// Command byte: channel 0, lobyte/hibyte access, mode 3 (square
/// wave generator), binary counting. Bit layout
/// `SC1 SC0 RW1 RW0 M2 M1 M0 BCD` = `00 11 011 0` = `0x36`.
pub const PIT_CMD_CH0_LOHI_MODE3_BIN: u8 = 0x36;

/// CMOS RTC index port. Writing selects the register; bit 7 is the
/// NMI-disable latch (legacy — leave clear so NMI policy is preserved).
pub const CMOS_INDEX_PORT: u16 = 0x70;
/// CMOS RTC data port. Read/write the register selected via
/// [`CMOS_INDEX_PORT`].
pub const CMOS_DATA_PORT: u16 = 0x71;

/// RTC register: seconds (0..=59).
pub const RTC_REG_SECONDS: u8 = 0x00;
/// RTC register: minutes (0..=59).
pub const RTC_REG_MINUTES: u8 = 0x02;
/// RTC register: hours (0..=23 or 1..=12 + PM bit).
pub const RTC_REG_HOURS: u8 = 0x04;
/// RTC register: day of month (1..=31).
pub const RTC_REG_DAY: u8 = 0x07;
/// RTC register: month (1..=12).
pub const RTC_REG_MONTH: u8 = 0x08;
/// RTC register: year within century (0..=99).
pub const RTC_REG_YEAR: u8 = 0x09;
/// RTC register: status A (bit 7 = Update In Progress).
pub const RTC_REG_STATUS_A: u8 = 0x0A;
/// RTC register: status B (bit 1 = 24-hour, bit 2 = binary mode).
pub const RTC_REG_STATUS_B: u8 = 0x0B;

/// Status-A bit 7: Update In Progress. Registers may be incoherent
/// while this bit is set.
pub const RTC_STATUS_A_UIP: u8 = 0x80;
/// Status-B bit 1: 24-hour clock when set; 12-hour when clear.
pub const RTC_STATUS_B_24H: u8 = 0x02;
/// Status-B bit 2: binary (binary=1) vs BCD (binary=0) encoding.
pub const RTC_STATUS_B_BINARY: u8 = 0x04;
/// Hours-register bit 7: PM indicator in 12-hour mode.
pub const RTC_HOUR_PM: u8 = 0x80;

/// Maximum spin iterations while waiting for UIP to clear. At the
/// RTC's 32.768 kHz crystal UIP self-clears in <2.4 µs; this budget
/// is generous for a slow emulator and bounded so a broken RTC
/// cannot hang the kernel forever.
pub const RTC_UIP_SPIN_BUDGET: u32 = 1_000_000;
/// Maximum consecutive raw-read pairs attempted for the RTC
/// consistency dance (two consecutive identical snapshots).
pub const RTC_CONSISTENCY_PASSES: u32 = 16;

/// Abstract 8-bit I/O-port surface. Caller-supplied so the seed's
/// [`PicTimer`] / [`Rtc`] codecs can be exercised against a
/// recording test harness AND against real `in`/`out` at kernel
/// runtime through the same trait surface.
pub trait IoPort {
    /// Write an 8-bit value to the given I/O port.
    fn write_u8(&mut self, port: u16, value: u8);
    /// Read an 8-bit value from the given I/O port.
    fn read_u8(&mut self, port: u16) -> u8;
}

/// Decomposed Gregorian wall-clock time recovered from the RTC,
/// plus the derived Unix epoch seconds. Year is full (e.g. 2026);
/// month + day are 1-based; hour / minute / second are 0-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTimeView {
    /// Full Gregorian year (e.g. 2026).
    pub year: u32,
    /// Month 1..=12.
    pub month: u8,
    /// Day of month 1..=31.
    pub day: u8,
    /// Hour 0..=23 (always converted to 24-hour form).
    pub hour: u8,
    /// Minute 0..=59.
    pub minute: u8,
    /// Second 0..=59.
    pub second: u8,
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
    pub unix: u64,
}

/// Errors emitted by [`PicTimer::program_hz`] and [`Rtc::read_time`].
/// Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    /// Caller requested `hz == 0` — a no-op that would hang any
    /// subsequent tick-based sleep, so it is rejected explicitly.
    ZeroHz,
    /// UIP bit stayed set for more than [`RTC_UIP_SPIN_BUDGET`]
    /// spins — RTC is absent or broken.
    UipTimeout,
    /// Two consecutive raw register snapshots never agreed across
    /// [`RTC_CONSISTENCY_PASSES`] attempts.
    InconsistentRead,
}

/// Programmable Interval Timer (8253/8254) channel-0 wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`program_hz`](PicTimer::program_hz) with `hz == 0` returns
///    [`TimerError::ZeroHz`] and issues **zero** port writes.
/// 2. For every non-zero `hz`, the method writes exactly three
///    bytes in order:
///    - `write_u8(PIT_CMD_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN)`
///    - `write_u8(PIT_CH0_PORT, (divisor & 0xFF) as u8)`
///    - `write_u8(PIT_CH0_PORT, (divisor >> 8) as u8)`
///    where `divisor = (PIT_BASE_HZ / hz).clamp(1, u16::MAX)`.
/// 3. The returned `u16` equals that divisor.
///
/// No IRQ unmask, no tick counter, no sleep primitive — those are
/// scheduler / interrupt-handler surfaces layered on top of this
/// codec.
pub trait PicTimer {
    /// Program channel 0 to fire IRQ 0 at approximately `hz` Hz.
    /// Returns the 16-bit divisor written to the data port.
    fn program_hz(port: &mut dyn IoPort, hz: u32) -> Result<u16, TimerError>;
}

/// MC146818 CMOS Real-Time Clock wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`read_time`](Rtc::read_time) polls status-A until UIP clears
///    (or returns [`TimerError::UipTimeout`]), then reads the six
///    calendar registers + status-B, re-reading until two
///    consecutive snapshots match (or returns
///    [`TimerError::InconsistentRead`]).
/// 2. BCD vs binary is decided by status-B bit 2
///    ([`RTC_STATUS_B_BINARY`]); 12-hour vs 24-hour by bit 1
///    ([`RTC_STATUS_B_24H`]); the PM bit is bit 7 of the hours
///    register ([`RTC_HOUR_PM`]).
/// 3. Two-digit years map to 2000..=2079 for `year2 < 80`, else
///    1900..=1979 — covering the classic CMOS century window.
/// 4. [`RtcTimeView::unix`] equals the pure Gregorian conversion
///    of the decoded Y/M/D/H/Mi/S tuple (no timezone offset).
///
/// No HPET composition, no boot-snapshot atomics — those are
/// higher-level kernel services layered on top of this codec.
pub trait Rtc {
    /// Read the current wall-clock time as a decoded
    /// [`RtcTimeView`]. Performs the UIP + consistency dance.
    fn read_time(port: &mut dyn IoPort) -> Result<RtcTimeView, TimerError>;
}

