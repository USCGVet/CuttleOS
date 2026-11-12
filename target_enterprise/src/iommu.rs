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
//! the access with a [`cuttle_contracts::IommuError`].
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

use cuttle_contracts::{AccessKind, Iommu, IommuError, PagePerms};

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
        if perms.0 == 0 || (perms.0 & !(PagePerms::READ.0 | PagePerms::WRITE.0)) != 0 {
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

/// Intel VT-d (`DMAR` Spec §9.1–§9.3, §10.4) hardware Root Table, Context Table, and
/// 4-level Second-Level Page Table (`SLPT`) builders and software-verified walker.
pub mod vtd_hw {
    use cuttle_contracts::{AccessKind, IommuError, PagePerms};

    use super::{DeviceId, PAGE_MASK, PAGE_SHIFT, PAGE_SIZE};

    /// VT-d Version Register (`VER_REG`) MMIO offset.
    pub const VTD_REG_VER: u64 = 0x00;
    /// VT-d Capability Register (`CAP_REG`) MMIO offset.
    pub const VTD_REG_CAP: u64 = 0x08;
    /// VT-d Extended Capability Register (`ECAP_REG`) MMIO offset.
    pub const VTD_REG_ECAP: u64 = 0x10;
    /// VT-d Global Command Register (`GCMD_REG`) MMIO offset.
    pub const VTD_REG_GCMD: u64 = 0x18;
    /// VT-d Global Status Register (`GSTS_REG`) MMIO offset.
    pub const VTD_REG_GSTS: u64 = 0x1C;
    /// VT-d Root Table Address Register (`RTADDR_REG`) MMIO offset.
    pub const VTD_REG_RTADDR: u64 = 0x20;
    /// VT-d Context Command Register (`CCMD_REG`) MMIO offset.
    pub const VTD_REG_CCMD: u64 = 0x28;
    /// `CAP.SAGAW` bit (`bit 10`, i.e., `SAGAW[2]`) indicating 48-bit 4-level SLPT support.
    pub const CAP_SAGAW_48BIT_4LVL: u64 = 1u64 << 10;
    /// `GCMD.TE` (`bit 31`): Translation Enable.
    pub const GCMD_TE: u32 = 1 << 31;
    /// `GCMD.SRTP` (`bit 30`): Set Root Table Pointer.
    pub const GCMD_SRTP: u32 = 1 << 30;
    /// `GSTS.TES` (`bit 31`): Translation Enable Status.
    pub const GSTS_TES: u32 = 1 << 31;
    /// `GSTS.RTPS` (`bit 30`): Root Table Pointer Status.
    pub const GSTS_RTPS: u32 = 1 << 30;
    /// Mask preserving persistent `GSTS` state bits without re-triggering one-shot `GCMD` actions (§10.4.4).
    pub const GSTS_PERSISTENT_MASK: u32 = 0x96FF_FFFF;
    /// `CCMD.ICC` (`bit 63`): Invalidate Context-Cache trigger/busy bit.
    pub const CCMD_ICC: u64 = 1u64 << 63;
    /// `CCMD.ICC` (`bit 63`) | Global Context Invalidation (`01b << 61`).
    pub const CCMD_GLOBAL_INVAL: u64 = CCMD_ICC | (1u64 << 61);
    /// `IOTLB.IVT` (`bit 63`): Invalidate IOTLB trigger/busy bit.
    pub const IOTLB_IVT: u64 = 1u64 << 63;
    /// `IOTLB.IVT` (`bit 63`) | Global IOTLB Invalidation (`01b << 60`).
    pub const IOTLB_GLOBAL_INVAL: u64 = IOTLB_IVT | (1u64 << 60);

    /// VT-d Second-Level PTE Read permission (`bit 0`).
    pub const SLPT_READ: u64 = 1 << 0;
    /// VT-d Second-Level PTE Write permission (`bit 1`).
    pub const SLPT_WRITE: u64 = 1 << 1;
    /// VT-d 4 KiB physical address mask (`bits 51:12`).
    pub const VTD_PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;
    /// VT-d Context Entry Address Width `010b` = 48-bit AGAW (4-level SLPT).
    pub const CTX_AW_48BIT_4LVL: u64 = 0b010;

    /// Encode a 128-bit Intel VT-d Root Entry pointing PCI bus `bus` at 4 KiB-aligned `ctx_table_phys`.
    pub const fn encode_root_entry(ctx_table_phys: u64) -> Result<[u8; 16], IommuError> {
        if ctx_table_phys == 0
            || (ctx_table_phys & !PAGE_MASK) != 0
            || (ctx_table_phys & !VTD_PHYS_MASK) != 0
        {
            return Err(IommuError::BadAddress);
        }
        let lo = (ctx_table_phys & VTD_PHYS_MASK) | 1u64;
        let lb = lo.to_le_bytes();
        let mut out = [0u8; 16];
        let mut i = 0usize;
        while i < 8 {
            out[i] = lb[i];
            i += 1;
        }
        Ok(out)
    }

    /// Encode a 128-bit Intel VT-d Legacy Context Entry binding `(dev, func)` to `slpt_pml4_phys`
    /// under 48-bit 4-level translation (`AW = 0b010`) and non-zero `domain_id`.
    pub const fn encode_context_entry(
        slpt_pml4_phys: u64,
        domain_id: u16,
    ) -> Result<[u8; 16], IommuError> {
        if domain_id == 0
            || slpt_pml4_phys == 0
            || (slpt_pml4_phys & !PAGE_MASK) != 0
            || (slpt_pml4_phys & !VTD_PHYS_MASK) != 0
        {
            return Err(IommuError::BadAddress);
        }
        let lo = (slpt_pml4_phys & VTD_PHYS_MASK) | 1u64;
        let hi = CTX_AW_48BIT_4LVL | ((domain_id as u64) << 8);
        let lb = lo.to_le_bytes();
        let hb = hi.to_le_bytes();
        let mut out = [0u8; 16];
        let mut i = 0usize;
        while i < 8 {
            out[i] = lb[i];
            out[8 + i] = hb[i];
            i += 1;
        }
        Ok(out)
    }

    /// Populate a 4-level VT-d Second-Level Page Table (`SLPT`) confining a device strictly
    /// to `[region_base_phys, region_base_phys + region_len)` within a single 2 MiB L1 window.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub fn build_confined_slpt_4level(
        pml4: &mut [u64; 512],
        pdpt: &mut [u64; 512],
        pd: &mut [u64; 512],
        pt: &mut [u64; 512],
        pdpt_phys: u64,
        pd_phys: u64,
        pt_phys: u64,
        region_base_phys: u64,
        region_len: u64,
        perms: PagePerms,
    ) -> Result<usize, IommuError> {
        if region_len == 0
            || (region_base_phys & !PAGE_MASK) != 0
            || (region_len & !PAGE_MASK) != 0
            || (pdpt_phys & !PAGE_MASK) != 0
            || (pd_phys & !PAGE_MASK) != 0
            || (pt_phys & !PAGE_MASK) != 0
            || pdpt_phys == 0
            || pd_phys == 0
            || pt_phys == 0
            || (perms.0 & !(PagePerms::READ.0 | PagePerms::WRITE.0)) != 0
            || perms.0 == 0
        {
            return Err(IommuError::BadAddress);
        }
        let end_phys = region_base_phys
            .checked_add(region_len)
            .ok_or(IommuError::BadAddress)?;
        if (region_base_phys >> 21) != ((end_phys - 1) >> 21) {
            return Err(IommuError::BadAddress);
        }

        let mut i = 0usize;
        while i < 512 {
            pml4[i] = 0;
            pdpt[i] = 0;
            pd[i] = 0;
            pt[i] = 0;
            i += 1;
        }

        let l4_idx = ((region_base_phys >> 39) & 0x1FF) as usize;
        let l3_idx = ((region_base_phys >> 30) & 0x1FF) as usize;
        let l2_idx = ((region_base_phys >> 21) & 0x1FF) as usize;

        let non_leaf_rw = SLPT_READ | SLPT_WRITE;
        pml4[l4_idx] = (pdpt_phys & VTD_PHYS_MASK) | non_leaf_rw;
        pdpt[l3_idx] = (pd_phys & VTD_PHYS_MASK) | non_leaf_rw;
        pd[l2_idx] = (pt_phys & VTD_PHYS_MASK) | non_leaf_rw;

        let mut leaf_flags = 0u64;
        if (perms.0 & PagePerms::READ.0) != 0 {
            leaf_flags |= SLPT_READ;
        }
        if (perms.0 & PagePerms::WRITE.0) != 0 {
            leaf_flags |= SLPT_WRITE;
        }

        let pages = (region_len >> PAGE_SHIFT) as usize;
        let mut p = 0usize;
        while p < pages {
            let pa = region_base_phys + (p as u64) * PAGE_SIZE;
            let l1_idx = ((pa >> 12) & 0x1FF) as usize;
            pt[l1_idx] = (pa & VTD_PHYS_MASK) | leaf_flags;
            p += 1;
        }
        Ok(pages)
    }

    /// Software-verify an Intel VT-d hardware Root -> Context -> 4-level SLPT translation for `dev`.
    #[inline(never)]
    #[allow(clippy::too_many_arguments)]
    pub fn verify_vtd_dma_access(
        root_table_4k: &[u8; 4096],
        bus0_ctx_table_4k: &[u8; 4096],
        expected_ctx_phys: u64,
        expected_pml4_phys: u64,
        pml4: &[u64; 512],
        pdpt: &[u64; 512],
        pd: &[u64; 512],
        pt: &[u64; 512],
        expected_pdpt_phys: u64,
        expected_pd_phys: u64,
        expected_pt_phys: u64,
        dev: DeviceId,
        iova: u64,
        access: AccessKind,
    ) -> Result<u64, IommuError> {
        if dev.segment() != 0 || dev.bus() != 0 {
            return Err(IommuError::DeviceNotBound);
        }
        let root_lo = u64::from_le_bytes([
            root_table_4k[0],
            root_table_4k[1],
            root_table_4k[2],
            root_table_4k[3],
            root_table_4k[4],
            root_table_4k[5],
            root_table_4k[6],
            root_table_4k[7],
        ]);
        if (root_lo & 1) == 0 || (root_lo & VTD_PHYS_MASK) != expected_ctx_phys {
            return Err(IommuError::DeviceNotBound);
        }

        let devfn = (((dev.device() & 0x1F) << 3) | (dev.function() & 0x07)) as usize;
        let ctx_off = devfn * 16;
        let ctx_lo = u64::from_le_bytes([
            bus0_ctx_table_4k[ctx_off],
            bus0_ctx_table_4k[ctx_off + 1],
            bus0_ctx_table_4k[ctx_off + 2],
            bus0_ctx_table_4k[ctx_off + 3],
            bus0_ctx_table_4k[ctx_off + 4],
            bus0_ctx_table_4k[ctx_off + 5],
            bus0_ctx_table_4k[ctx_off + 6],
            bus0_ctx_table_4k[ctx_off + 7],
        ]);
        let ctx_hi = u64::from_le_bytes([
            bus0_ctx_table_4k[ctx_off + 8],
            bus0_ctx_table_4k[ctx_off + 9],
            bus0_ctx_table_4k[ctx_off + 10],
            bus0_ctx_table_4k[ctx_off + 11],
            bus0_ctx_table_4k[ctx_off + 12],
            bus0_ctx_table_4k[ctx_off + 13],
            bus0_ctx_table_4k[ctx_off + 14],
            bus0_ctx_table_4k[ctx_off + 15],
        ]);
        if (ctx_lo & 1) == 0
            || (ctx_lo & VTD_PHYS_MASK) != expected_pml4_phys
            || (ctx_hi & 0x7) != CTX_AW_48BIT_4LVL
            || ((ctx_hi >> 8) & 0xFFFF) == 0
        {
            return Err(IommuError::DeviceNotBound);
        }

        let req_bit = match access {
            AccessKind::Read => SLPT_READ,
            AccessKind::Write => SLPT_WRITE,
        };
        let l4 = pml4[((iova >> 39) & 0x1FF) as usize];
        if (l4 & req_bit) == 0 || (l4 & VTD_PHYS_MASK) != expected_pdpt_phys {
            return Err(if (l4 & (SLPT_READ | SLPT_WRITE)) == 0 {
                IommuError::Unmapped
            } else {
                IommuError::PermissionDenied
            });
        }
        let l3 = pdpt[((iova >> 30) & 0x1FF) as usize];
        if (l3 & req_bit) == 0 || (l3 & VTD_PHYS_MASK) != expected_pd_phys {
            return Err(if (l3 & (SLPT_READ | SLPT_WRITE)) == 0 {
                IommuError::Unmapped
            } else {
                IommuError::PermissionDenied
            });
        }
        let l2 = pd[((iova >> 21) & 0x1FF) as usize];
        if (l2 & req_bit) == 0 || (l2 & VTD_PHYS_MASK) != expected_pt_phys {
            return Err(if (l2 & (SLPT_READ | SLPT_WRITE)) == 0 {
                IommuError::Unmapped
            } else {
                IommuError::PermissionDenied
            });
        }
        let l1 = pt[((iova >> 12) & 0x1FF) as usize];
        if (l1 & (SLPT_READ | SLPT_WRITE)) == 0 {
            return Err(IommuError::Unmapped);
        }
        if (l1 & req_bit) == 0 {
            return Err(IommuError::PermissionDenied);
        }
        Ok((l1 & VTD_PHYS_MASK) | (iova & (PAGE_SIZE - 1)))
    }

    /// Abstract MMIO register bus for an Intel VT-d `DRHD` remapping hardware unit (`4 KiB` register bank).
    pub trait VtdMmioBus {
        /// Read a 32-bit little-endian VT-d register at `offset`.
        fn read_u32(&mut self, offset: u64) -> u32;
        /// Write a 32-bit little-endian VT-d register at `offset`.
        fn write_u32(&mut self, offset: u64, val: u32);
        /// Read a 64-bit little-endian VT-d register at `offset`.
        fn read_u64(&mut self, offset: u64) -> u64;
        /// Write a 64-bit little-endian VT-d register at `offset`.
        fn write_u64(&mut self, offset: u64, val: u64);
    }

    /// Hardware initialization failures surfaced by [`enable_drhd_translation_hw`].
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum VtdDrhdError {
        /// `root_table_phys` is zero, unaligned, or exceeds 52-bit VT-d physical width, or `max_spins == 0`.
        BadRootTableAddress,
        /// Hardware `CAP_REG` is all-zeros/all-ones or lacks 48-bit 4-level SLPT (`SAGAW[2]`).
        UnsupportedSagaw48,
        /// `GSTS.RTPS` did not assert within `max_spins` after `GCMD.SRTP`.
        SrtpTimeout,
        /// `CCMD.ICC` did not clear within `max_spins` after global context-cache invalidation.
        ContextInvalTimeout,
        /// `IOTLB.IVT` did not clear within `max_spins` after global IOTLB invalidation.
        IotlbInvalTimeout,
        /// `GSTS.TES` did not assert within `max_spins` after `GCMD.TE`.
        TranslationEnableTimeout,
    }

    /// Compute the MMIO offset of `IOTLB_REG` (`IRO * 16 + 0x08`) from `ECAP_REG` (VT-d §10.4.3, §10.4.8).
    #[inline]
    pub const fn extract_ecap_iro_offset(ecap: u64) -> u64 {
        ((ecap >> 8) & 0x3FF) * 16 + 0x08
    }

    /// Program an Intel VT-d `DRHD` unit to enforce `root_table_phys` via the specification's
    /// mandatory sequence (`CAP.SAGAW` check -> `RTADDR` -> `GCMD.SRTP` + `GSTS.RTPS` ->
    /// global `CCMD` invalidation -> global `IOTLB` invalidation -> `GCMD.TE` + `GSTS.TES`).
    pub fn enable_drhd_translation_hw(
        bus: &mut dyn VtdMmioBus,
        root_table_phys: u64,
        max_spins: u32,
    ) -> Result<(), VtdDrhdError> {
        if max_spins == 0
            || root_table_phys == 0
            || (root_table_phys & !PAGE_MASK) != 0
            || (root_table_phys & !VTD_PHYS_MASK) != 0
        {
            return Err(VtdDrhdError::BadRootTableAddress);
        }

        let cap = bus.read_u64(VTD_REG_CAP);
        if cap == 0 || cap == u64::MAX || (cap & CAP_SAGAW_48BIT_4LVL) == 0 {
            return Err(VtdDrhdError::UnsupportedSagaw48);
        }
        let ecap = bus.read_u64(VTD_REG_ECAP);

        // 1. Latch 4 KiB Root Table physical address (`RTADDR_REG`) and trigger `GCMD.SRTP`.
        bus.write_u64(VTD_REG_RTADDR, root_table_phys & VTD_PHYS_MASK);
        let gsts_pre_srtp = bus.read_u32(VTD_REG_GSTS) & GSTS_PERSISTENT_MASK;
        bus.write_u32(VTD_REG_GCMD, gsts_pre_srtp | GCMD_SRTP);

        let mut spins = 0u32;
        let mut rtps_ok = false;
        while spins < max_spins {
            if (bus.read_u32(VTD_REG_GSTS) & GSTS_RTPS) != 0 {
                rtps_ok = true;
                break;
            }
            spins += 1;
        }
        if !rtps_ok {
            return Err(VtdDrhdError::SrtpTimeout);
        }

        // 2. Global Context-Cache Invalidation (`CCMD_REG`).
        bus.write_u64(VTD_REG_CCMD, CCMD_GLOBAL_INVAL);
        spins = 0;
        let mut ccmd_ok = false;
        while spins < max_spins {
            if (bus.read_u64(VTD_REG_CCMD) & CCMD_ICC) == 0 {
                ccmd_ok = true;
                break;
            }
            spins += 1;
        }
        if !ccmd_ok {
            return Err(VtdDrhdError::ContextInvalTimeout);
        }

        // 3. Global IOTLB Invalidation (`ECAP.IRO * 16 + 0x08`).
        let iotlb_off = extract_ecap_iro_offset(ecap);
        bus.write_u64(iotlb_off, IOTLB_GLOBAL_INVAL);
        spins = 0;
        let mut iotlb_ok = false;
        while spins < max_spins {
            if (bus.read_u64(iotlb_off) & IOTLB_IVT) == 0 {
                iotlb_ok = true;
                break;
            }
            spins += 1;
        }
        if !iotlb_ok {
            return Err(VtdDrhdError::IotlbInvalTimeout);
        }

        // 4. Enable DMA Remapping Translation (`GCMD.TE`) preserving persistent `GSTS` bits.
        let gsts_pre_te = bus.read_u32(VTD_REG_GSTS) & GSTS_PERSISTENT_MASK;
        bus.write_u32(VTD_REG_GCMD, gsts_pre_te | GCMD_TE);
        spins = 0;
        let mut tes_ok = false;
        while spins < max_spins {
            if (bus.read_u32(VTD_REG_GSTS) & GSTS_TES) != 0 {
                tes_ok = true;
                break;
            }
            spins += 1;
        }
        if !tes_ok {
            return Err(VtdDrhdError::TranslationEnableTimeout);
        }

        Ok(())
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

    #[test]
    fn iommu_map_rejects_undefined_page_perms_bits() {
        let mut iommu: IommuImpl<2, 2, 8> = IommuImpl::new();
        let dom = iommu.create_domain().unwrap();
        assert_eq!(
            iommu.map(dom, 0x1000, 0x2000, PagePerms(0x04)),
            Err(IommuError::BadAddress)
        );
        assert_eq!(
            iommu.map(dom, 0x1000, 0x2000, PagePerms(0x83)),
            Err(IommuError::BadAddress)
        );
    }

    #[test]
    fn stage15_vtd_hw_root_context_slpt_confines_pci_bdf_dma() {
        use super::vtd_hw::{
            build_confined_slpt_4level, encode_context_entry, encode_root_entry,
            verify_vtd_dma_access,
        };
        use crate::memory::dma_layout::{AHCI_REGION, VIRTIO_REGION};

        assert_eq!(encode_root_entry(0), Err(IommuError::BadAddress));
        assert_eq!(encode_root_entry(0x1234), Err(IommuError::BadAddress));
        assert_eq!(encode_context_entry(0x2000, 0), Err(IommuError::BadAddress)); // domain 0 reserved!

        let mut root_4k = [0u8; 4096];
        let mut ctx_4k = [0u8; 4096];
        let ctx_pa = 0x50_1000u64;
        let v_pml4_pa = 0x50_2000u64;
        let v_pdpt_pa = 0x50_3000u64;
        let v_pd_pa = 0x50_4000u64;
        let v_pt_pa = 0x50_5000u64;
        let a_pml4_pa = 0x50_6000u64;
        let a_pdpt_pa = 0x50_7000u64;
        let a_pd_pa = 0x50_8000u64;
        let a_pt_pa = 0x50_9000u64;

        root_4k[0..16].copy_from_slice(&encode_root_entry(ctx_pa).unwrap());
        let dev_virtio = DeviceId::from_bdf(0, 0, 1, 0);
        let dev_ahci = DeviceId::from_bdf(0, 0, 2, 0);
        let dev_unbound = DeviceId::from_bdf(0, 0, 3, 0);
        ctx_4k[8 * 16..8 * 16 + 16]
            .copy_from_slice(&encode_context_entry(v_pml4_pa, 1).unwrap());
        ctx_4k[16 * 16..16 * 16 + 16]
            .copy_from_slice(&encode_context_entry(a_pml4_pa, 2).unwrap());

        let dma_base = 0x20_0000u64;
        let (v_start, v_end) = VIRTIO_REGION;
        let (a_start, a_end) = AHCI_REGION;
        let v_len = v_end - v_start;
        let a_len = a_end - a_start;
        let virtio_pa = dma_base + v_start;
        let ahci_pa = dma_base + a_start;

        let mut v_pml4 = [0u64; 512];
        let mut v_pdpt = [0u64; 512];
        let mut v_pd = [0u64; 512];
        let mut v_pt = [0u64; 512];
        let rw = PagePerms(PagePerms::READ.0 | PagePerms::WRITE.0);
        let pages = build_confined_slpt_4level(
            &mut v_pml4,
            &mut v_pdpt,
            &mut v_pd,
            &mut v_pt,
            v_pdpt_pa,
            v_pd_pa,
            v_pt_pa,
            virtio_pa,
            v_len,
            rw,
        )
        .unwrap();
        assert_eq!(pages, (v_len / 4096) as usize);

        let mut a_pml4 = [0u64; 512];
        let mut a_pdpt = [0u64; 512];
        let mut a_pd = [0u64; 512];
        let mut a_pt = [0u64; 512];
        build_confined_slpt_4level(
            &mut a_pml4,
            &mut a_pdpt,
            &mut a_pd,
            &mut a_pt,
            a_pdpt_pa,
            a_pd_pa,
            a_pt_pa,
            ahci_pa,
            a_len,
            PagePerms::READ,
        )
        .unwrap();

        // VirtIO R/W inside VIRTIO_REGION translates 1:1; cross-device DMA into AHCI_REGION is blocked!
        assert_eq!(
            verify_vtd_dma_access(
                &root_4k,
                &ctx_4k,
                ctx_pa,
                v_pml4_pa,
                &v_pml4,
                &v_pdpt,
                &v_pd,
                &v_pt,
                v_pdpt_pa,
                v_pd_pa,
                v_pt_pa,
                dev_virtio,
                virtio_pa + 0x248,
                AccessKind::Write,
            ),
            Ok(virtio_pa + 0x248)
        );
        assert_eq!(
            verify_vtd_dma_access(
                &root_4k,
                &ctx_4k,
                ctx_pa,
                v_pml4_pa,
                &v_pml4,
                &v_pdpt,
                &v_pd,
                &v_pt,
                v_pdpt_pa,
                v_pd_pa,
                v_pt_pa,
                dev_virtio,
                ahci_pa,
                AccessKind::Write,
            ),
            Err(IommuError::Unmapped)
        );
        // Read-only SLPT blocks DMA writes with PermissionDenied, and unbound BDF fails DeviceNotBound.
        assert_eq!(
            verify_vtd_dma_access(
                &root_4k,
                &ctx_4k,
                ctx_pa,
                a_pml4_pa,
                &a_pml4,
                &a_pdpt,
                &a_pd,
                &a_pt,
                a_pdpt_pa,
                a_pd_pa,
                a_pt_pa,
                dev_ahci,
                ahci_pa + 0x40,
                AccessKind::Write,
            ),
            Err(IommuError::PermissionDenied)
        );
        assert_eq!(
            verify_vtd_dma_access(
                &root_4k,
                &ctx_4k,
                ctx_pa,
                v_pml4_pa,
                &v_pml4,
                &v_pdpt,
                &v_pd,
                &v_pt,
                v_pdpt_pa,
                v_pd_pa,
                v_pt_pa,
                dev_unbound,
                virtio_pa,
                AccessKind::Read,
            ),
            Err(IommuError::DeviceNotBound)
        );
    }

    #[test]
    fn stage20_vtd_drhd_mmio_driver_srtp_ccmd_iotlb_te_and_timeout_guards() {
        use super::vtd_hw::*;

        struct MockDrhd {
            cap: u64,
            ecap: u64,
            gsts: u32,
            rtaddr: u64,
            ccmd: u64,
            iotlb: u64,
            stall_srtp: bool,
            stall_ccmd: bool,
            stall_iotlb: bool,
            stall_te: bool,
            ccmd_count: u32,
            iotlb_count: u32,
        }
        impl MockDrhd {
            fn new() -> Self {
                Self {
                    cap: CAP_SAGAW_48BIT_4LVL,
                    ecap: 0x24u64 << 8, // IRO = 0x24 -> IOTLB at 0x248
                    gsts: 1 << 25,      // persistent IRES status bit (VT-d §10.4.4) that must be preserved!
                    rtaddr: 0,
                    ccmd: 0,
                    iotlb: 0,
                    stall_srtp: false,
                    stall_ccmd: false,
                    stall_iotlb: false,
                    stall_te: false,
                    ccmd_count: 0,
                    iotlb_count: 0,
                }
            }
        }
        impl VtdMmioBus for MockDrhd {
            fn read_u32(&mut self, offset: u64) -> u32 {
                if offset == VTD_REG_GSTS {
                    self.gsts
                } else {
                    0x10
                }
            }
            fn write_u32(&mut self, offset: u64, val: u32) {
                if offset == VTD_REG_GCMD {
                    let preserved = val & (1 << 25);
                    self.gsts = (self.gsts & !(1 << 25)) | preserved;
                    if (val & GCMD_SRTP) != 0 && !self.stall_srtp {
                        self.gsts |= GSTS_RTPS;
                    }
                    if (val & GCMD_TE) != 0 && !self.stall_te {
                        self.gsts |= GSTS_TES;
                    }
                }
            }
            fn read_u64(&mut self, offset: u64) -> u64 {
                let iro_off = extract_ecap_iro_offset(self.ecap);
                if offset == VTD_REG_CAP {
                    self.cap
                } else if offset == VTD_REG_ECAP {
                    self.ecap
                } else if offset == VTD_REG_RTADDR {
                    self.rtaddr
                } else if offset == VTD_REG_CCMD {
                    self.ccmd
                } else if offset == iro_off {
                    self.iotlb
                } else {
                    0
                }
            }
            fn write_u64(&mut self, offset: u64, val: u64) {
                let iro_off = extract_ecap_iro_offset(self.ecap);
                if offset == VTD_REG_RTADDR {
                    self.rtaddr = val;
                } else if offset == VTD_REG_CCMD {
                    self.ccmd_count += 1;
                    self.ccmd = if self.stall_ccmd {
                        val
                    } else {
                        val & !CCMD_ICC
                    };
                } else if offset == iro_off {
                    self.iotlb_count += 1;
                    self.iotlb = if self.stall_iotlb {
                        val
                    } else {
                        val & !IOTLB_IVT
                    };
                }
            }
        }

        assert_eq!(extract_ecap_iro_offset(0x24u64 << 8), 0x248);

        // 1. Happy path: programs RTADDR, preserves persistent GSTS bits, flushes CCMD + IOTLB, enables TE.
        let mut ok_bus = MockDrhd::new();
        assert_eq!(enable_drhd_translation_hw(&mut ok_bus, 0x0080_4000, 16), Ok(()));
        assert_eq!(ok_bus.rtaddr, 0x0080_4000);
        assert_eq!(ok_bus.ccmd_count, 1);
        assert_eq!(ok_bus.iotlb_count, 1);
        assert_ne!(ok_bus.gsts & GSTS_RTPS, 0);
        assert_ne!(ok_bus.gsts & GSTS_TES, 0);
        assert_ne!(ok_bus.gsts & (1 << 25), 0, "persistent GSTS state bits must be preserved");

        // 2. Bad root-table alignment / zero / zero max_spins.
        assert_eq!(
            enable_drhd_translation_hw(&mut ok_bus, 0, 16),
            Err(VtdDrhdError::BadRootTableAddress)
        );
        assert_eq!(
            enable_drhd_translation_hw(&mut ok_bus, 0x4001, 16),
            Err(VtdDrhdError::BadRootTableAddress)
        );
        assert_eq!(
            enable_drhd_translation_hw(&mut ok_bus, 0x4000, 0),
            Err(VtdDrhdError::BadRootTableAddress)
        );

        // 3. Missing 48-bit 4-level SLPT capability or disconnected MMIO (`u64::MAX`).
        let mut bad_cap = MockDrhd::new();
        bad_cap.cap = 0;
        assert_eq!(
            enable_drhd_translation_hw(&mut bad_cap, 0x4000, 8),
            Err(VtdDrhdError::UnsupportedSagaw48)
        );
        bad_cap.cap = u64::MAX;
        assert_eq!(
            enable_drhd_translation_hw(&mut bad_cap, 0x4000, 8),
            Err(VtdDrhdError::UnsupportedSagaw48)
        );

        // 4. Deterministic bounded spin timeouts on every hardware handshake stage.
        let mut s_srtp = MockDrhd::new();
        s_srtp.stall_srtp = true;
        assert_eq!(
            enable_drhd_translation_hw(&mut s_srtp, 0x4000, 8),
            Err(VtdDrhdError::SrtpTimeout)
        );
        let mut s_ccmd = MockDrhd::new();
        s_ccmd.stall_ccmd = true;
        assert_eq!(
            enable_drhd_translation_hw(&mut s_ccmd, 0x4000, 8),
            Err(VtdDrhdError::ContextInvalTimeout)
        );
        let mut s_iotlb = MockDrhd::new();
        s_iotlb.stall_iotlb = true;
        assert_eq!(
            enable_drhd_translation_hw(&mut s_iotlb, 0x4000, 8),
            Err(VtdDrhdError::IotlbInvalTimeout)
        );
        let mut s_te = MockDrhd::new();
        s_te.stall_te = true;
        assert_eq!(
            enable_drhd_translation_hw(&mut s_te, 0x4000, 8),
            Err(VtdDrhdError::TranslationEnableTimeout)
        );
    }
}

