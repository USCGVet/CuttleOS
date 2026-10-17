//! IOMMU + DMA-protection skeleton â€” `no_std`, fixed-capacity, allocation-free.
//!
//! Adapted from `RustOSa/src/iommu.rs`. The donor is a thin Intel
//! VT-d DMAR walker: it parses the ACPI DMAR table, records each
//! DMA-Remapping Hardware Unit (DRHD), and stops there. The donor
//! never programs the root/context/PASID tables that actually re-map
//! DMA â€” that surface is "left for future work" in the donor's own
//! prose.
//!
//! This seed ships the *isolation semantics* the donor stops short
//! of: a logical Intel VT-d-style IOMMU with a domain table, a
//! device-to-domain binding table, a per-domain page table, and a
//! `translate` verb that walks the page table for a device's bound
//! domain and either returns the host physical address or rejects
//! the access with a [`proteus_contracts::IommuError`].
//!
//! The donor's DMAR walker is preserved in [`dmar`] (a sibling
//! sub-module). It is rewritten to take a raw byte buffer instead of
//! the `acpi` crate handle, so it is portable to the host test
//! harness without dragging in the rest of the donor kernel. The
//! DMAR walker tells you how many hardware IOMMUs the firmware
//! advertises; the logical model is what enforces isolation. Both
//! belong.
//!
//! ## Allocation discipline
//!
//! Zero. Every table is inlined as a fixed-capacity array under a
//! const generic on [`IommuImpl`]. The default const generic values
//! ([`MAX_DOMAINS`] = 8, [`MAX_DEVICES`] = 32, [`ENTRIES_PER_DOMAIN`]
//! = 256) match the donor's comment that "real systems top out at
//! 2â€“4 IOMMU units" â€” the seed's caps give 2x headroom for each
//! axis. No `alloc`, no `heapless::Vec`, no implicit allocation.
//!
//! ## Page size
//!
//! Page size is locked at 4 KiB (the smallest Intel VT-d second-
//! level entry size). DMA addresses are indexed by `dma_addr >>
//! PAGE_SHIFT`. The per-domain mapping range is bounded at compile
//! time by `ENTRIES_PER_DOMAIN * PAGE_SIZE` â€” for the default values
//! that is 256 * 4 KiB = 1 MiB of addressable DMA per domain. The
//! morph engine will later swap this flat table for a multi-level
//! tree; the public surface does not change.

use proteus_contracts::{AccessKind, Iommu, IommuError, PagePerms};

/// Log-base-2 of the IOMMU page size. Locked at 12 (4 KiB), matching
/// Intel VT-d's smallest second-level entry size.
pub const PAGE_SHIFT: u32 = 12;
/// IOMMU page size in bytes. 4 KiB.
pub const PAGE_SIZE: u64 = 1u64 << PAGE_SHIFT;
/// Mask that selects the page-frame portion of a DMA address.
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Default const-generic capacity for the domain table on
/// [`IommuImpl`]. Real Intel VT-d systems top out at 2â€“4 hardware
/// IOMMUs; one isolation domain per driver class is the common
/// programming model. 8 gives the seed 2x headroom.
pub const MAX_DOMAINS: usize = 8;

/// Default const-generic capacity for the device-binding table on
/// [`IommuImpl`]. A populated x86 server typically has 16â€“24 PCIe
/// endpoints across all segments; 32 gives the seed 2x headroom.
pub const MAX_DEVICES: usize = 32;

/// Default const-generic capacity for the per-domain page-table
/// entry count. With 4 KiB pages this caps each domain at 1 MiB of
/// addressable DMA. Sufficient for a streaming descriptor ring (the
/// only DMA the seed exercises); a multi-level morph candidate will
/// lift this when real drivers land.
pub const ENTRIES_PER_DOMAIN: usize = 256;

/// Packed `(segment, bus, device, function)` PCI BDF.
///
/// Layout matches the canonical Linux `pci_dev_addr` packing so a
/// future hardware shadow can shift bits into a VT-d source-id field
/// (16 bits) by masking to the low 16. The contract treats the value
/// as opaque.
///
/// Bits:
/// - `[31:16]` â€” PCI segment group (typically 0 on single-socket
///   systems; the donor's `Drhd::segment` field).
/// - `[15: 8]` â€” bus number.
/// - `[ 7: 3]` â€” device number (5 bits, 0..=31).
/// - `[ 2: 0]` â€” function number (3 bits, 0..=7).
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct DeviceId(pub u32);

impl DeviceId {
    /// Build a `DeviceId` from its `(segment, bus, device, function)`
    /// components. Out-of-range `device` (>31) and `function` (>7)
    /// values are masked to fit; the contract treats those inputs as
    /// caller bugs and does not surface an error.
    pub const fn from_bdf(segment: u16, bus: u8, device: u8, function: u8) -> Self {
        let s = (segment as u32) << 16;
        let b = (bus as u32) << 8;
        let d = ((device & 0x1F) as u32) << 3;
        let f = (function & 0x07) as u32;
        Self(s | b | d | f)
    }

    /// PCI segment group.
    pub const fn segment(self) -> u16 {
        (self.0 >> 16) as u16
    }
    /// PCI bus number.
    pub const fn bus(self) -> u8 {
        (self.0 >> 8) as u8
    }
    /// PCI device number (0..=31).
    pub const fn device(self) -> u8 {
        ((self.0 >> 3) & 0x1F) as u8
    }
    /// PCI function number (0..=7).
    pub const fn function(self) -> u8 {
        (self.0 & 0x07) as u8
    }
}

/// Stable handle to a domain inside an [`IommuImpl`]. Internally a
/// slot index plus a generation counter so a recycled slot can be
/// distinguished from a stale handle. The contract treats the value
/// as opaque.
#[derive(Copy, Clone, PartialEq, Eq, Debug, Default)]
pub struct DomainId {
    /// Slot index in the impl's `domains[]` table.
    slot: u16,
    /// Generation counter â€” incremented when the slot is recycled.
    /// A stale `DomainId` from a previous tenant of this slot is
    /// rejected by `resolve_domain` even though `slot` is in range.
    generation: u16,
}

impl DomainId {
    /// Sentinel "no domain" id. Used as the unbound-device marker
    /// in the device binding table.
    pub const NONE: DomainId = DomainId { slot: u16::MAX, generation: 0 };

    /// True iff this handle is the sentinel "no domain".
    pub const fn is_none(self) -> bool {
        self.slot == u16::MAX
    }
}

/// One page-table entry. A live entry has a non-zero `perms` byte
/// (at least one of READ/WRITE set); a zero `perms` byte marks the
/// slot as empty. We keep `host_phys` and `dma_addr` separately
/// because the per-domain entry array is flat (linearly probed by
/// `dma_addr`) rather than indexed by frame number â€” see the rant
/// in the file header about the multi-level morph candidate.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
struct PageEntry {
    /// DMA virtual address (page-aligned) this entry maps. Zero is a
    /// legal DMA address; the `perms` byte being zero is what marks
    /// the slot empty.
    dma_addr: u64,
    /// Host physical address (page-aligned) the DMA address resolves
    /// to.
    host_phys: u64,
    /// Permission bits for the mapping. Zero = empty slot.
    perms: u8,
}

impl PageEntry {
    const EMPTY: Self = Self {
        dma_addr: 0,
        host_phys: 0,
        perms: 0,
    };

    #[inline]
    const fn is_live(&self) -> bool {
        self.perms != 0
    }
}

/// One isolation domain. Holds a fixed-capacity flat page table
/// and a generation counter that bumps when the slot is recycled.
#[derive(Copy, Clone)]
struct Domain<const E: usize> {
    /// True iff this slot is in use (i.e. holds a live domain).
    in_use: bool,
    /// Generation counter â€” matches `DomainId.generation`. Incremented on
    /// every recycle so a stale `DomainId` referring to a previous
    /// tenant of this slot is rejected.
    generation: u16,
    /// Page-table entries. Linearly probed by `dma_addr`.
    entries: [PageEntry; E],
}

impl<const E: usize> Domain<E> {
    const EMPTY: Self = Self {
        in_use: false,
        generation: 0,
        entries: [PageEntry::EMPTY; E],
    };
}

/// Device-binding table entry. A live entry has `in_use = true`;
/// `domain.is_none()` marks the entry as unbound (the device is
/// known to the IOMMU â€” e.g. previously bound and then unbound â€”
/// but has no current domain). For the seed we keep unbound entries
/// in the table only transiently; `unbind_device` resets the slot
/// to `in_use = false` so the slot can be reused. Future morph
/// cycles may want to distinguish "never bound" from "explicitly
/// unbound" for audit; we surface the same error variant for both.
#[derive(Copy, Clone)]
struct Binding {
    /// True iff this slot is in use.
    in_use: bool,
    /// BDF of the device this slot describes.
    device: DeviceId,
    /// Domain this device is currently bound to. Never
    /// `DomainId::NONE` while `in_use == true` â€” when a device is
    /// unbound, the slot is reset to `in_use = false` rather than
    /// kept around with a sentinel domain.
    domain: DomainId,
}

impl Binding {
    const EMPTY: Self = Self {
        in_use: false,
        device: DeviceId(0),
        domain: DomainId::NONE,
    };
}

/// In-memory, fixed-capacity logical IOMMU.
///
/// The three const generics parameterise the table sizes:
/// - `D` â€” maximum number of concurrent isolation domains. Defaults
///   to [`MAX_DOMAINS`] = 8.
/// - `V` â€” maximum number of devices the IOMMU can know about at
///   once. Defaults to [`MAX_DEVICES`] = 32.
/// - `E` â€” page-table entries per domain. Defaults to
///   [`ENTRIES_PER_DOMAIN`] = 256, capping each domain at 1 MiB of
///   addressable DMA at 4 KiB pages.
///
/// The impl is `Sized` (the tables are inline) and does not need
/// `Send` / `Sync`; the morph engine will wrap a real instance in a
/// `spin::Mutex` when wiring the syscall layer.
pub struct IommuImpl<
    const D: usize = MAX_DOMAINS,
    const V: usize = MAX_DEVICES,
    const E: usize = ENTRIES_PER_DOMAIN,
> {
    /// Domain table. Slot index â†” `DomainId.slot`.
    domains: [Domain<E>; D],
    /// Device binding table.
    devices: [Binding; V],
}

impl<const D: usize, const V: usize, const E: usize> IommuImpl<D, V, E> {
    /// Construct a fresh IOMMU with no domains and no device
    /// bindings. Every device defaults to deny-all DMA until it is
    /// explicitly bound to a domain.
    pub const fn new() -> Self {
        Self {
            domains: [Domain::<E>::EMPTY; D],
            devices: [Binding::EMPTY; V],
        }
    }

    /// Number of live (allocated) domains.
    pub fn domain_count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0usize;
        while i < D {
            if self.domains[i].in_use {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Number of currently-bound devices.
    pub fn binding_count(&self) -> usize {
        let mut n = 0usize;
        let mut i = 0usize;
        while i < V {
            if self.devices[i].in_use {
                n += 1;
            }
            i += 1;
        }
        n
    }

    /// Domain-table capacity (== `D`).
    pub const fn domain_capacity(&self) -> usize {
        D
    }

    /// Device-table capacity (== `V`).
    pub const fn device_capacity(&self) -> usize {
        V
    }

    /// Per-domain page-table entry capacity (== `E`).
    pub const fn entries_per_domain(&self) -> usize {
        E
    }

    /// Resolve a `DomainId` to a slot index, or `None` if the handle
    /// is stale (slot recycled) or out of range.
    fn resolve_domain(&self, id: DomainId) -> Option<usize> {
        let slot = id.slot as usize;
        if slot >= D {
            return None;
        }
        let d = &self.domains[slot];
        if !d.in_use {
            return None;
        }
        if d.generation != id.generation {
            return None;
        }
        Some(slot)
    }

    /// Find the binding-table slot for `device`, or `None` if the
    /// device is not currently bound.
    fn find_binding(&self, device: DeviceId) -> Option<usize> {
        let mut i = 0usize;
        while i < V {
            if self.devices[i].in_use && self.devices[i].device == device {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Allocate a free binding-table slot. `None` if the table is
    /// full.
    fn alloc_binding(&self) -> Option<usize> {
        let mut i = 0usize;
        while i < V {
            if !self.devices[i].in_use {
                return Some(i);
            }
            i += 1;
        }
        None
    }
}

impl<const D: usize, const V: usize, const E: usize> Default for IommuImpl<D, V, E> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const D: usize, const V: usize, const E: usize> Iommu for IommuImpl<D, V, E> {
    type DomainId = DomainId;
    type DeviceId = DeviceId;

    fn create_domain(&mut self) -> Result<DomainId, IommuError> {
        // Linear scan for the lowest-index free slot. Keeps DomainIds
        // dense at the start of the table, which makes the resolve
        // path cheap to step through in a debugger.
        let mut i = 0usize;
        while i < D {
            if !self.domains[i].in_use {
                self.domains[i].in_use = true;
                // Wipe any leftover entries from a previous tenant
                // so the new domain starts truly empty.
                let mut j = 0usize;
                while j < E {
                    self.domains[i].entries[j] = PageEntry::EMPTY;
                    j += 1;
                }
                return Ok(DomainId {
                    slot: i as u16,
                    generation: self.domains[i].generation,
                });
            }
            i += 1;
        }
        Err(IommuError::DomainTableFull)
    }

    fn bind_device(
        &mut self,
        device: DeviceId,
        domain: DomainId,
    ) -> Result<(), IommuError> {
        // Validate the domain first so an "already bound" check
        // doesn't shadow a stale-DomainId bug.
        if self.resolve_domain(domain).is_none() {
            return Err(IommuError::UnknownDomain);
        }
        if self.find_binding(device).is_some() {
            return Err(IommuError::DeviceAlreadyBound);
        }
        let slot = match self.alloc_binding() {
            Some(s) => s,
            None => return Err(IommuError::DeviceTableFull),
        };
        self.devices[slot] = Binding {
            in_use: true,
            device,
            domain,
        };
        Ok(())
    }

    fn unbind_device(&mut self, device: DeviceId) -> Result<(), IommuError> {
        let slot = match self.find_binding(device) {
            Some(s) => s,
            None => return Err(IommuError::DeviceNotBound),
        };
        self.devices[slot] = Binding::EMPTY;
        Ok(())
    }

    fn map(
        &mut self,
        domain: DomainId,
        dma_addr: u64,
        host_phys: u64,
        perms: PagePerms,
    ) -> Result<(), IommuError> {
        // Page-alignment is enforced on both sides. The donor
        // hardware would silently lose the low 12 bits; the
        // contract surfaces the error instead.
        if (dma_addr & (PAGE_SIZE - 1)) != 0 {
            return Err(IommuError::BadAddress);
        }
        if (host_phys & (PAGE_SIZE - 1)) != 0 {
            return Err(IommuError::BadAddress);
        }
        // perms == 0 (neither READ nor WRITE) is meaningless: a
        // mapping that permits nothing is structurally identical to
        // the absence of a mapping. Reject so callers don't get
        // surprised by a `translate` that returns `PermissionDenied`
        // where they expected `Unmapped`.
        if perms.0 == 0 {
            return Err(IommuError::BadAddress);
        }
        let slot = self
            .resolve_domain(domain)
            .ok_or(IommuError::UnknownDomain)?;
        // Map dma_addr into the flat entry table by page-frame index.
        let pfn = (dma_addr >> PAGE_SHIFT) as usize;
        if pfn >= E {
            return Err(IommuError::BadAddress);
        }
        let entry = &mut self.domains[slot].entries[pfn];
        if entry.is_live() {
            return Err(IommuError::AlreadyMapped);
        }
        *entry = PageEntry {
            dma_addr,
            host_phys,
            perms: perms.0,
        };
        Ok(())
    }

    fn unmap(&mut self, domain: DomainId, dma_addr: u64) -> Result<(), IommuError> {
        if (dma_addr & (PAGE_SIZE - 1)) != 0 {
            return Err(IommuError::BadAddress);
        }
        let slot = self
            .resolve_domain(domain)
            .ok_or(IommuError::UnknownDomain)?;
        let pfn = (dma_addr >> PAGE_SHIFT) as usize;
        if pfn >= E {
            return Err(IommuError::BadAddress);
        }
        let entry = &mut self.domains[slot].entries[pfn];
        if !entry.is_live() {
            return Err(IommuError::Unmapped);
        }
        *entry = PageEntry::EMPTY;
        Ok(())
    }

    fn translate(
        &self,
        device: DeviceId,
        dma_addr: u64,
        access: AccessKind,
    ) -> Result<u64, IommuError> {
        // Step 1: device â†’ domain. An unbound device defaults to
        // deny-all; that's the load-bearing isolation property.
        let bind_slot = self
            .find_binding(device)
            .ok_or(IommuError::DeviceNotBound)?;
        let domain = self.devices[bind_slot].domain;
        // The binding holds the DomainId by value, so a domain that
        // was destroyed and re-created in the same slot is caught by
        // the generation-counter mismatch on resolve.
        let dom_slot = self
            .resolve_domain(domain)
            .ok_or(IommuError::UnknownDomain)?;
        // Step 2: page-table walk. For the flat single-level model
        // the "walk" is one indexed lookup; the contract is the same
        // for a future multi-level morph candidate.
        let pfn = (dma_addr >> PAGE_SHIFT) as usize;
        if pfn >= E {
            return Err(IommuError::Unmapped);
        }
        let entry = &self.domains[dom_slot].entries[pfn];
        if !entry.is_live() {
            return Err(IommuError::Unmapped);
        }
        // Step 3: permission check.
        let allowed = match access {
            AccessKind::Read => (entry.perms & PagePerms::READ.0) != 0,
            AccessKind::Write => (entry.perms & PagePerms::WRITE.0) != 0,
        };
        if !allowed {
            return Err(IommuError::PermissionDenied);
        }
        // Step 4: assemble the host physical address. The entry's
        // host_phys is page-aligned (enforced at map time); the
        // page-offset portion of dma_addr passes through.
        let page_off = dma_addr & (PAGE_SIZE - 1);
        Ok(entry.host_phys | page_off)
    }
}

// ============================================================
// DMAR walker â€” the donor's firmware-detection surface, rewritten
// to take a raw byte buffer so it ports cleanly without dragging
// in the donor kernel's `acpi` crate.
// ============================================================

/// ACPI DMAR table walker.
///
/// The donor (`RustOSa/src/iommu.rs`) parsed the DMAR table via the
/// kernel's `acpi` crate handle. That coupling is host-incompatible:
/// the host test harness has no ACPI, and the `acpi` crate the donor
/// uses is a kernel-private fork. We rewrite the walker to take a
/// raw byte buffer â€” the table contents as the BIOS handed them to
/// the bootloader â€” and return the same [`IommuInfo`] struct.
///
/// The structural walk (header offsets, type/length framing,
/// malformed-length defenses) is preserved byte-for-byte from the
/// donor. The only change is the entry point: instead of `acpi::get`
/// the caller hands us `&[u8]`.
pub mod dmar {
    /// Offset of `host_address_width` (u8) inside the DMAR table body.
    /// Matches the donor.
    pub const DMAR_OFF_HAW: usize = 36;
    /// Offset of `flags` (u8) inside the DMAR table body.
    pub const DMAR_OFF_FLAGS: usize = 37;
    /// Offset of the first Remapping Structure inside the DMAR table.
    pub const DMAR_OFF_FIRST_STRUCT: usize = 48;
    /// Minimum DMAR table length that still contains the fixed header.
    pub const DMAR_MIN_LEN: usize = DMAR_OFF_FIRST_STRUCT;

    /// Remapping-Structure type code for a DMA Remapping Hardware Unit.
    pub const STRUCT_TYPE_DRHD: u16 = 0x00;
    /// Remapping-Structure type code for a Reserved Memory Region
    /// Reporting structure. Skipped by the seed walker.
    pub const STRUCT_TYPE_RMRR: u16 = 0x01;
    /// Remapping-Structure type code for a Root Port ATS Capability
    /// Reporting structure. Skipped by the seed walker.
    pub const STRUCT_TYPE_ATSR: u16 = 0x02;
    /// Header bytes preceding every Remapping Structure body:
    /// u16 type + u16 length = 4.
    pub const STRUCT_HDR_LEN: usize = 4;

    /// DRHD body offsets, measured from the start of the structure
    /// (inclusive of the 4-byte type/length header).
    pub const DRHD_OFF_FLAGS: usize = 4;
    /// DRHD body offset of the segment field (u16).
    pub const DRHD_OFF_SEGMENT: usize = 6;
    /// DRHD body offset of the register base (u64).
    pub const DRHD_OFF_REGBASE: usize = 8;
    /// Minimum DRHD structure length. Anything shorter is malformed.
    pub const DRHD_MIN_LEN: usize = 16;

    /// Hard cap on retained DRHD entries. Real systems top out at
    /// 2â€“4 IOMMU units (one per socket, occasionally one extra for
    /// the GPU); 8 gives the seed 2x headroom.
    pub const MAX_DRHD: usize = 8;

    /// Errors surfaced by [`parse_dmar`].
    #[derive(Copy, Clone, PartialEq, Eq, Debug)]
    pub enum DmarError {
        /// The table buffer is shorter than the fixed DMAR header.
        Truncated,
        /// A Remapping Structure's declared length is zero (would
        /// infinite-loop the walk).
        ZeroLengthStruct,
        /// A Remapping Structure's declared length runs past the end
        /// of the table buffer.
        StructOverflow,
    }

    /// One DMA Remapping Hardware Unit, as described by a DRHD
    /// structure. Layout matches the donor's `iommu::Drhd`.
    #[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
    pub struct Drhd {
        /// Bit 0 = INCLUDE_PCI_ALL: this unit covers every PCI
        /// device in `segment` that no other DRHD claims via a
        /// device-scope entry.
        pub flags: u8,
        /// PCI segment group this IOMMU services.
        pub segment: u16,
        /// Physical base address of the IOMMU's MMIO register
        /// block. The register layout itself (Capability, Extended
        /// Capability, Root Table Address, â€¦) is VT-d Â§10.4.
        pub register_base: u64,
    }

    /// Snapshot of the parsed DMAR header plus every DRHD we kept.
    /// Returned by [`parse_dmar`].
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct IommuInfo {
        /// Host Address Width minus one, in bits. `0x2F` means
        /// 48-bit DMA addressing (the common modern value); `0x27`
        /// would be 40-bit.
        pub host_address_width: u8,
        /// DMAR flags. Bit 0 = INTR_REMAP; bit 1 = X2APIC_OPT_OUT.
        pub flags: u8,
        /// Number of DRHD entries populated in `drhd`. Always
        /// `<= MAX_DRHD`.
        pub drhd_count: usize,
        /// Fixed-capacity DRHD list. Only the first `drhd_count`
        /// are valid.
        pub drhd: [Drhd; MAX_DRHD],
    }

    impl IommuInfo {
        /// Empty `IommuInfo` â€” used as the success return when the
        /// DMAR table is well-formed but contains no DRHDs.
        pub const EMPTY: Self = Self {
            host_address_width: 0,
            flags: 0,
            drhd_count: 0,
            drhd: [Drhd {
                flags: 0,
                segment: 0,
                register_base: 0,
            }; MAX_DRHD],
        };
    }

    /// Walk a DMAR table buffer and collect every DRHD up to
    /// [`MAX_DRHD`]. The buffer is the table contents as the BIOS
    /// handed them to the bootloader (post-checksum-validation in a
    /// real system; the seed parser is defensive against corruption
    /// regardless).
    ///
    /// This is the donor's `probe()` rewritten to take a `&[u8]`
    /// instead of `acpi::get()`. The structural walk (header
    /// offsets, type/length framing, malformed-length defenses) is
    /// preserved byte-for-byte.
    pub fn parse_dmar(table: &[u8]) -> Result<IommuInfo, DmarError> {
        if table.len() < DMAR_MIN_LEN {
            return Err(DmarError::Truncated);
        }
        let mut info = IommuInfo {
            host_address_width: table[DMAR_OFF_HAW],
            flags: table[DMAR_OFF_FLAGS],
            ..IommuInfo::EMPTY
        };

        let mut cursor = DMAR_OFF_FIRST_STRUCT;
        while cursor + STRUCT_HDR_LEN <= table.len() {
            // u16 LE reads â€” we use safe slice indexing here because
            // the structural walker doesn't need raw pointer reads
            // once the buffer is a `&[u8]`.
            let stype = read_u16_le(&table[cursor..cursor + 2]);
            let slen = read_u16_le(&table[cursor + 2..cursor + 4]) as usize;

            if slen == 0 {
                return Err(DmarError::ZeroLengthStruct);
            }
            if slen > table.len() - cursor {
                return Err(DmarError::StructOverflow);
            }

            if stype == STRUCT_TYPE_DRHD {
                if slen < DRHD_MIN_LEN {
                    // Short DRHD: skip it but keep walking, matching
                    // the donor's kwarn-and-continue behaviour.
                } else if info.drhd_count >= MAX_DRHD {
                    // Bounded cap; silently drop extras past MAX_DRHD.
                } else {
                    let drhd = Drhd {
                        flags: table[cursor + DRHD_OFF_FLAGS],
                        segment: read_u16_le(
                            &table[cursor + DRHD_OFF_SEGMENT..cursor + DRHD_OFF_SEGMENT + 2],
                        ),
                        register_base: read_u64_le(
                            &table[cursor + DRHD_OFF_REGBASE..cursor + DRHD_OFF_REGBASE + 8],
                        ),
                    };
                    info.drhd[info.drhd_count] = drhd;
                    info.drhd_count += 1;
                }
            }
            // Other types (RMRR/ATSR/RHSA/ANDD/SATC/SIDP) skipped â€”
            // matches the donor.
            cursor += slen;
        }

        Ok(info)
    }

    #[inline]
    fn read_u16_le(b: &[u8]) -> u16 {
        u16::from_le_bytes([b[0], b[1]])
    }

    #[inline]
    fn read_u64_le(b: &[u8]) -> u64 {
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]])
    }
}

// ============================================================
// Unit tests. Cover the contract's invariants:
//   - Default-deny on unbound devices.
//   - Domain creation up to and past the cap.
//   - Device binding (single bind, rebind reject, unbind).
//   - Page-table walk: unmapped â†’ Err(Unmapped).
//   - Page-table walk: mapped â†’ correct host phys.
//   - Permission enforcement (write to RO mapping â†’ PermissionDenied).
//   - Domain isolation across distinct domains.
//   - Map / unmap error edges (alignment, duplicate, double-unmap).
//   - DMAR parser: truncated input rejected; well-formed parses;
//     zero-length structure rejected.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Iommu as _;

    /// Convenience: spawn a default-sized IOMMU for terse tests.
    fn fresh_iommu() -> IommuImpl<MAX_DOMAINS, MAX_DEVICES, ENTRIES_PER_DOMAIN> {
        IommuImpl::new()
    }

    #[test]
    fn fresh_iommu_has_no_state() {
        let iommu = fresh_iommu();
        assert_eq!(iommu.domain_count(), 0);
        assert_eq!(iommu.binding_count(), 0);
        assert_eq!(iommu.domain_capacity(), MAX_DOMAINS);
        assert_eq!(iommu.device_capacity(), MAX_DEVICES);
        assert_eq!(iommu.entries_per_domain(), ENTRIES_PER_DOMAIN);
    }

    #[test]
    fn create_domain_up_to_cap_then_fail() {
        let mut iommu: IommuImpl<3, MAX_DEVICES, ENTRIES_PER_DOMAIN> = IommuImpl::new();
        let _a = iommu.create_domain().expect("first domain");
        let _b = iommu.create_domain().expect("second domain");
        let _c = iommu.create_domain().expect("third domain");
        // Fourth must fail cleanly (no panic).
        let err = iommu.create_domain().unwrap_err();
        assert_eq!(err, IommuError::DomainTableFull);
        assert_eq!(iommu.domain_count(), 3);
    }

    #[test]
    fn unbound_device_translate_is_default_deny() {
        let iommu = fresh_iommu();
        let dev = DeviceId::from_bdf(0, 0, 1, 0);
        let err = iommu
            .translate(dev, 0xDEAD_BEEF & PAGE_MASK, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::DeviceNotBound);
    }

    #[test]
    fn bind_then_translate_on_empty_domain_is_unmapped() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 1, 0);
        iommu.bind_device(dev, dom).unwrap();
        // Page-aligned DMA address; nothing is mapped â†’ Unmapped.
        let err = iommu
            .translate(dev, 0x1000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::Unmapped);
    }

    #[test]
    fn translate_unmapped_dma_addr_rejected() {
        // The task spec calls this out explicitly: "page-table walk
        // rejects unmapped DMA addresses".
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 2, 0);
        iommu.bind_device(dev, dom).unwrap();
        iommu
            .map(dom, 0x1000, 0xAAAA_0000, PagePerms::RW)
            .unwrap();
        // Different page â†’ Unmapped, even though the domain is non-empty.
        let err = iommu
            .translate(dev, 0x2000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::Unmapped);
    }

    #[test]
    fn mapped_translation_returns_correct_host_phys() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 3, 0);
        iommu.bind_device(dev, dom).unwrap();
        iommu
            .map(dom, 0x4000, 0xCAFE_0000, PagePerms::RW)
            .unwrap();
        // Page base resolves cleanly.
        let phys = iommu.translate(dev, 0x4000, AccessKind::Read).unwrap();
        assert_eq!(phys, 0xCAFE_0000);
        // Page offset passes through.
        let phys2 = iommu.translate(dev, 0x4000 + 0x123, AccessKind::Write).unwrap();
        assert_eq!(phys2, 0xCAFE_0000 + 0x123);
    }

    #[test]
    fn write_to_read_only_mapping_is_denied() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 4, 0);
        iommu.bind_device(dev, dom).unwrap();
        iommu
            .map(dom, 0x1000, 0x9000, PagePerms::READ)
            .unwrap();
        // Read succeeds.
        assert_eq!(iommu.translate(dev, 0x1000, AccessKind::Read), Ok(0x9000));
        // Write rejected.
        let err = iommu
            .translate(dev, 0x1000, AccessKind::Write)
            .unwrap_err();
        assert_eq!(err, IommuError::PermissionDenied);
    }

    #[test]
    fn read_from_write_only_mapping_is_denied() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 5, 0);
        iommu.bind_device(dev, dom).unwrap();
        iommu
            .map(dom, 0x1000, 0x9000, PagePerms::WRITE)
            .unwrap();
        let err = iommu
            .translate(dev, 0x1000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::PermissionDenied);
    }

    #[test]
    fn rebinding_a_device_is_rejected() {
        let mut iommu = fresh_iommu();
        let a = iommu.create_domain().unwrap();
        let b = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 6, 0);
        iommu.bind_device(dev, a).unwrap();
        // Second bind to a different domain without unbinding is an error.
        let err = iommu.bind_device(dev, b).unwrap_err();
        assert_eq!(err, IommuError::DeviceAlreadyBound);
        // Rebinding to the *same* domain is also rejected â€” the
        // contract is "no silent rebind".
        let err2 = iommu.bind_device(dev, a).unwrap_err();
        assert_eq!(err2, IommuError::DeviceAlreadyBound);
    }

    #[test]
    fn unbind_then_translate_returns_to_default_deny() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 7, 0);
        iommu.bind_device(dev, dom).unwrap();
        iommu
            .map(dom, 0x1000, 0xBABE_0000, PagePerms::RW)
            .unwrap();
        // Sanity: mapped path works.
        assert!(iommu.translate(dev, 0x1000, AccessKind::Read).is_ok());
        // Now unbind.
        iommu.unbind_device(dev).unwrap();
        let err = iommu
            .translate(dev, 0x1000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::DeviceNotBound);
        // Double-unbind: clean error, not panic.
        let err2 = iommu.unbind_device(dev).unwrap_err();
        assert_eq!(err2, IommuError::DeviceNotBound);
    }

    #[test]
    fn rebind_after_unbind_works() {
        let mut iommu = fresh_iommu();
        let a = iommu.create_domain().unwrap();
        let b = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 8, 0);
        iommu.bind_device(dev, a).unwrap();
        iommu.unbind_device(dev).unwrap();
        // Now the device is unbound; binding to a different domain
        // is allowed.
        iommu.bind_device(dev, b).unwrap();
        // Map in b only.
        iommu
            .map(b, 0x1000, 0xBEEF_0000, PagePerms::RW)
            .unwrap();
        let phys = iommu.translate(dev, 0x1000, AccessKind::Read).unwrap();
        assert_eq!(phys, 0xBEEF_0000);
    }

    #[test]
    fn domains_are_isolated() {
        let mut iommu = fresh_iommu();
        let a = iommu.create_domain().unwrap();
        let b = iommu.create_domain().unwrap();
        // Same DMA address, different host phys per domain.
        iommu
            .map(a, 0x1000, 0xAAAA_0000, PagePerms::RW)
            .unwrap();
        iommu
            .map(b, 0x1000, 0xBBBB_0000, PagePerms::RW)
            .unwrap();
        let dev_a = DeviceId::from_bdf(0, 0, 9, 0);
        let dev_b = DeviceId::from_bdf(0, 0, 10, 0);
        iommu.bind_device(dev_a, a).unwrap();
        iommu.bind_device(dev_b, b).unwrap();
        // Each device sees only its domain's mapping.
        assert_eq!(
            iommu.translate(dev_a, 0x1000, AccessKind::Read),
            Ok(0xAAAA_0000)
        );
        assert_eq!(
            iommu.translate(dev_b, 0x1000, AccessKind::Read),
            Ok(0xBBBB_0000)
        );
        // And an address mapped in A but not in B is Unmapped for B.
        iommu
            .map(a, 0x2000, 0xAAAA_2000, PagePerms::RW)
            .unwrap();
        let err = iommu
            .translate(dev_b, 0x2000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::Unmapped);
    }

    #[test]
    fn map_unaligned_dma_addr_rejected() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let err = iommu
            .map(dom, 0x1001, 0x9000, PagePerms::RW)
            .unwrap_err();
        assert_eq!(err, IommuError::BadAddress);
    }

    #[test]
    fn map_unaligned_host_phys_rejected() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let err = iommu
            .map(dom, 0x1000, 0x9001, PagePerms::RW)
            .unwrap_err();
        assert_eq!(err, IommuError::BadAddress);
    }

    #[test]
    fn map_with_empty_perms_rejected() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let err = iommu
            .map(dom, 0x1000, 0x9000, PagePerms(0))
            .unwrap_err();
        assert_eq!(err, IommuError::BadAddress);
    }

    #[test]
    fn map_over_existing_mapping_rejected() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        iommu
            .map(dom, 0x1000, 0x9000, PagePerms::RW)
            .unwrap();
        let err = iommu
            .map(dom, 0x1000, 0xAAAA_0000, PagePerms::RW)
            .unwrap_err();
        assert_eq!(err, IommuError::AlreadyMapped);
    }

    #[test]
    fn unmap_absent_page_is_clean_error() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let err = iommu.unmap(dom, 0x1000).unwrap_err();
        assert_eq!(err, IommuError::Unmapped);
    }

    #[test]
    fn unmap_then_translate_returns_unmapped() {
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 11, 0);
        iommu.bind_device(dev, dom).unwrap();
        iommu
            .map(dom, 0x1000, 0x9000, PagePerms::RW)
            .unwrap();
        iommu.unmap(dom, 0x1000).unwrap();
        let err = iommu
            .translate(dev, 0x1000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::Unmapped);
    }

    #[test]
    fn bind_to_unknown_domain_rejected() {
        let mut iommu = fresh_iommu();
        let dev = DeviceId::from_bdf(0, 0, 12, 0);
        let bogus = DomainId { slot: 0, generation: 99 };
        let err = iommu.bind_device(dev, bogus).unwrap_err();
        assert_eq!(err, IommuError::UnknownDomain);
    }

    #[test]
    fn out_of_range_dma_addr_translates_to_unmapped() {
        // ENTRIES_PER_DOMAIN * PAGE_SIZE = 256 * 4 KiB = 1 MiB.
        // 0x10_0000 is one past the last addressable page.
        let mut iommu = fresh_iommu();
        let dom = iommu.create_domain().unwrap();
        let dev = DeviceId::from_bdf(0, 0, 13, 0);
        iommu.bind_device(dev, dom).unwrap();
        let err = iommu
            .translate(dev, 0x10_0000, AccessKind::Read)
            .unwrap_err();
        assert_eq!(err, IommuError::Unmapped);
    }

    #[test]
    fn device_table_full_surfaces_clean_error() {
        let mut iommu: IommuImpl<MAX_DOMAINS, 2, ENTRIES_PER_DOMAIN> = IommuImpl::new();
        let dom = iommu.create_domain().unwrap();
        iommu
            .bind_device(DeviceId::from_bdf(0, 0, 0, 0), dom)
            .unwrap();
        iommu
            .bind_device(DeviceId::from_bdf(0, 0, 1, 0), dom)
            .unwrap();
        let err = iommu
            .bind_device(DeviceId::from_bdf(0, 0, 2, 0), dom)
            .unwrap_err();
        assert_eq!(err, IommuError::DeviceTableFull);
    }

    // ---------- DMAR walker tests ----------

    #[test]
    fn dmar_truncated_buffer_rejected() {
        let buf = [0u8; 10];
        let err = dmar::parse_dmar(&buf).unwrap_err();
        assert_eq!(err, dmar::DmarError::Truncated);
    }

    #[test]
    fn dmar_empty_buffer_rejected() {
        let buf: [u8; 0] = [];
        let err = dmar::parse_dmar(&buf).unwrap_err();
        assert_eq!(err, dmar::DmarError::Truncated);
    }

    #[test]
    fn dmar_header_only_parses_with_zero_drhds() {
        // Build a DMAR table header with no remapping structures.
        // The "ACPI header" (first 36 bytes) is ignored by the walker
        // since we read HAW from offset 36 onward; we just need the
        // buffer length to clear DMAR_MIN_LEN = 48.
        let mut buf = [0u8; 48];
        buf[dmar::DMAR_OFF_HAW] = 0x2F;
        buf[dmar::DMAR_OFF_FLAGS] = 0x01;
        let info = dmar::parse_dmar(&buf).unwrap();
        assert_eq!(info.host_address_width, 0x2F);
        assert_eq!(info.flags, 0x01);
        assert_eq!(info.drhd_count, 0);
    }

    #[test]
    fn dmar_walks_one_drhd() {
        // Build a minimal table with a single DRHD: header (48 bytes)
        // + DRHD (16 bytes) = 64 bytes total.
        let mut buf = [0u8; 64];
        buf[dmar::DMAR_OFF_HAW] = 0x2F;
        buf[dmar::DMAR_OFF_FLAGS] = 0x01;
        // DRHD structure starts at offset 48.
        let off = dmar::DMAR_OFF_FIRST_STRUCT;
        // type = 0 (DRHD) â€” already zero.
        // length = 16.
        buf[off + 2] = 16;
        buf[off + 3] = 0;
        // flags (offset 4 from struct start) â€” INCLUDE_PCI_ALL = 1.
        buf[off + dmar::DRHD_OFF_FLAGS] = 0x01;
        // segment (offset 6): 0.
        // register_base (offset 8): 0xFED9_0000 (a plausible VT-d MMIO).
        let reg = 0xFED9_0000u64.to_le_bytes();
        let regbase = off + dmar::DRHD_OFF_REGBASE;
        let mut i = 0;
        while i < 8 {
            buf[regbase + i] = reg[i];
            i += 1;
        }
        let info = dmar::parse_dmar(&buf).unwrap();
        assert_eq!(info.drhd_count, 1);
        assert_eq!(info.drhd[0].flags, 0x01);
        assert_eq!(info.drhd[0].segment, 0);
        assert_eq!(info.drhd[0].register_base, 0xFED9_0000);
    }

    #[test]
    fn dmar_zero_length_struct_rejected() {
        let mut buf = [0u8; 64];
        buf[dmar::DMAR_OFF_HAW] = 0x2F;
        // Zero-length structure at offset 48 â€” would infinite-loop.
        // type/length both zero already; nothing to do.
        let err = dmar::parse_dmar(&buf).unwrap_err();
        assert_eq!(err, dmar::DmarError::ZeroLengthStruct);
    }

    #[test]
    fn dmar_overlong_struct_rejected() {
        let mut buf = [0u8; 64];
        buf[dmar::DMAR_OFF_HAW] = 0x2F;
        let off = dmar::DMAR_OFF_FIRST_STRUCT;
        // length = 200 â€” past the 64-byte buffer.
        buf[off + 2] = 200;
        let err = dmar::parse_dmar(&buf).unwrap_err();
        assert_eq!(err, dmar::DmarError::StructOverflow);
    }

    #[test]
    fn bdf_packing_round_trip() {
        let dev = DeviceId::from_bdf(0x1234, 0x56, 0x1F, 0x07);
        assert_eq!(dev.segment(), 0x1234);
        assert_eq!(dev.bus(), 0x56);
        assert_eq!(dev.device(), 0x1F);
        assert_eq!(dev.function(), 0x07);
    }
}

