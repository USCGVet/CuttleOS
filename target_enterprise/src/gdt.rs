//! Global Descriptor Table — x86_64 long-mode layout.
//!
//! Skeleton port of `RustOSa/src/gdt.rs`. The donor module installs a
//! GDT with kernel/user code/data + TSS, all backed by static mutable
//! IST/RSP0 stacks. Here we lift the *descriptor encoding* (the byte
//! layout each `GdtEntry` produces) into a host-testable form. The
//! actual `lgdt` instruction and the IST stack pointers are left
//! abstract — IST values default to `0`, which the morph engine will
//! eventually replace with real per-CPU stack tops.
//!
//! GDT entry encoding (8 bytes, packed little-endian):
//!
//! ```text
//!   bits  0..16   limit[0..16]
//!   bits 16..40   base[0..24]
//!   bits 40..48   access byte
//!   bits 48..52   limit[16..20]
//!   bits 52..56   flags (G, D/B, L, AVL)
//!   bits 56..64   base[24..32]
//! ```
//!
//! The Long Mode TSS descriptor is 16 bytes (two slots). The seed
//! exposes both 8-byte and 16-byte builders so the morph engine has
//! a real surface to optimise.

/// Logical index of each GDT slot in the layout the enterprise target
/// installs. Order matters: the SYSCALL/SYSRET MSR contract requires
/// `kernel_data = kernel_code + 8`, `user_ss = user_base + 8`,
/// `user_cs = user_base + 16`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum GdtSlot {
    /// Implicit NULL descriptor at index 0.
    Null = 0,
    /// Ring-0 code segment.
    KernelCode = 1,
    /// Ring-0 data segment.
    KernelData = 2,
    /// Ring-3 data segment (placed before user code to satisfy SYSRET).
    UserData = 3,
    /// Ring-3 code segment.
    UserCode = 4,
    /// Low half of the 16-byte TSS descriptor.
    TssLow = 5,
    /// High half of the 16-byte TSS descriptor.
    TssHigh = 6,
}

/// Access-byte fields for a code/data segment descriptor.
pub mod access {
    /// Present bit. MUST be 1 for any usable entry.
    pub const PRESENT: u8 = 1 << 7;
    /// DPL ring-0 (bits 5..7 = 00).
    pub const DPL_RING0: u8 = 0;
    /// DPL ring-3 (bits 5..7 = 11).
    pub const DPL_RING3: u8 = 3 << 5;
    /// "Descriptor type" — 1 for code/data, 0 for system (TSS).
    pub const TYPE_CODE_DATA: u8 = 1 << 4;
    /// Executable bit — 1 for code, 0 for data.
    pub const EXECUTABLE: u8 = 1 << 3;
    /// Readable bit (code) / writable bit (data).
    pub const RW: u8 = 1 << 1;
    /// "Accessed" — must be writable by CPU. Leave 0; CPU sets it.
    pub const ACCESSED: u8 = 1 << 0;
    /// 64-bit TSS available type code (4 LSBs of access byte for TSS).
    pub const TSS_AVAIL_64: u8 = 0x9;
}

/// Flags nibble fields for a code/data segment descriptor.
pub mod flags {
    /// 4 KiB granularity.
    pub const GRANULARITY_4K: u8 = 1 << 3;
    /// Long mode (64-bit code segment).
    pub const LONG_MODE: u8 = 1 << 1;
    /// 32-bit data segment (mutually exclusive with LONG_MODE).
    pub const SIZE_32: u8 = 1 << 2;
}

/// One 8-byte GDT descriptor in its raw form. Bit-packed exactly per
/// the Intel SDM Vol. 3, §3.4.5.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct GdtEntry {
    /// Limit bits 0..16.
    pub limit_low: u16,
    /// Base bits 0..16.
    pub base_low: u16,
    /// Base bits 16..24.
    pub base_mid: u8,
    /// Access byte.
    pub access: u8,
    /// Limit bits 16..20 (low nibble) + flags (high nibble).
    pub limit_high_and_flags: u8,
    /// Base bits 24..32.
    pub base_high: u8,
}

impl GdtEntry {
    /// The implicit NULL descriptor — all zero.
    pub const NULL: Self = Self {
        limit_low: 0,
        base_low: 0,
        base_mid: 0,
        access: 0,
        limit_high_and_flags: 0,
        base_high: 0,
    };

    /// Build a code/data segment descriptor for the given access byte
    /// and flags nibble. Base is 0 and limit is 0xF_FFFF (max) since
    /// 64-bit code/data segments ignore base/limit for normal access.
    pub fn new_code_data(access_byte: u8, flags_nibble: u8) -> Self {
        let limit: u32 = 0xF_FFFF;
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: 0,
            base_mid: 0,
            access: access_byte,
            limit_high_and_flags: ((limit >> 16) as u8 & 0x0F) | ((flags_nibble & 0x0F) << 4),
            base_high: 0,
        }
    }

    /// Ring-0 64-bit code segment.
    pub fn kernel_code() -> Self {
        Self::new_code_data(
            access::PRESENT
                | access::DPL_RING0
                | access::TYPE_CODE_DATA
                | access::EXECUTABLE
                | access::RW,
            flags::GRANULARITY_4K | flags::LONG_MODE,
        )
    }

    /// Ring-0 data segment.
    pub fn kernel_data() -> Self {
        Self::new_code_data(
            access::PRESENT | access::DPL_RING0 | access::TYPE_CODE_DATA | access::RW,
            flags::GRANULARITY_4K | flags::SIZE_32,
        )
    }

    /// Ring-3 64-bit code segment.
    pub fn user_code() -> Self {
        Self::new_code_data(
            access::PRESENT
                | access::DPL_RING3
                | access::TYPE_CODE_DATA
                | access::EXECUTABLE
                | access::RW,
            flags::GRANULARITY_4K | flags::LONG_MODE,
        )
    }

    /// Ring-3 data segment.
    pub fn user_data() -> Self {
        Self::new_code_data(
            access::PRESENT | access::DPL_RING3 | access::TYPE_CODE_DATA | access::RW,
            flags::GRANULARITY_4K | flags::SIZE_32,
        )
    }
}

/// 16-byte Long-Mode TSS descriptor. Encoded as TWO consecutive GDT
/// slots — the low half is a normal-looking GdtEntry with a system
/// type code in the access byte and the base extended into bits 32..64
/// of the high half.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TssDescriptor {
    /// Low half — the part that looks like a normal GdtEntry.
    pub low: GdtEntry,
    /// Base bits 32..64.
    pub base_upper: u32,
    /// Reserved — must be zero.
    pub reserved: u32,
}

impl TssDescriptor {
    /// Build a 16-byte TSS descriptor for a TSS structure at `base`
    /// with size `limit` (typically `sizeof::<Tss>() - 1`).
    pub fn new(base: u64, limit: u32) -> Self {
        let mut low = GdtEntry::default();
        low.limit_low = (limit & 0xFFFF) as u16;
        low.base_low = (base & 0xFFFF) as u16;
        low.base_mid = ((base >> 16) & 0xFF) as u8;
        // Access byte: P=1, DPL=0, S=0 (system), Type=0x9 (64-bit TSS Avail).
        low.access = access::PRESENT | access::TSS_AVAIL_64;
        low.limit_high_and_flags = ((limit >> 16) as u8 & 0x0F) | (flags::GRANULARITY_4K << 4);
        low.base_high = ((base >> 24) & 0xFF) as u8;
        Self {
            low,
            base_upper: ((base >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }
}

/// Number of GDT slots in the enterprise target layout. 7 = NULL +
/// Number of GDT slots in the enterprise target layout. 7 = NULL +
/// (kernel code/data) + (user data/code) + 2-slot TSS.
pub const GDT_LEN: usize = 7;

/// Ring-0 kernel code segment selector (`slot 1 << 3 = 0x08`).
pub const KERNEL_CODE_SEL: u16 = (GdtSlot::KernelCode as u16) << 3;
/// Ring-0 kernel data segment selector (`slot 2 << 3 = 0x10`).
pub const KERNEL_DATA_SEL: u16 = (GdtSlot::KernelData as u16) << 3;
/// Ring-3 user data segment selector with `RPL = 3` (`(slot 3 << 3) | 3 = 0x1B`).
pub const USER_DATA_SEL: u16 = ((GdtSlot::UserData as u16) << 3) | 3;
/// Ring-3 user code segment selector with `RPL = 3` (`(slot 4 << 3) | 3 = 0x23`).
pub const USER_CODE_SEL: u16 = ((GdtSlot::UserCode as u16) << 3) | 3;
/// 64-bit Task State Segment selector (`slot 5 << 3 = 0x28`).
pub const TSS_SEL: u16 = (GdtSlot::TssLow as u16) << 3;

/// Size in bytes of the architectural 64-bit Task State Segment (`Tss64`).
pub const TSS64_LEN: usize = 104;

/// Architectural 64-bit Task State Segment (Intel SDM Vol. 3A §7.7).
///
/// Holds the privilege-level stack pointers (`rsp[0..3]`) used on `CPL=3 -> CPL=0`
/// transitions and the 7 Interrupt Stack Table pointers (`ist[0..7]`) used by
/// IDT gates with a non-zero IST index.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Tss64 {
    /// Reserved at offset 0x00.
    pub reserved0: u32,
    /// Stack pointers for privilege levels 0, 1, and 2 (offsets 0x04..0x1C).
    pub rsp: [u64; 3],
    /// Reserved at offset 0x1C.
    pub reserved1: u64,
    /// Interrupt Stack Table pointers `IST1..=IST7` (offsets 0x24..0x5C).
    pub ist: [u64; 7],
    /// Reserved at offset 0x5C.
    pub reserved2: u64,
    /// Reserved at offset 0x64.
    pub reserved3: u16,
    /// I/O map base address at offset 0x66 (`>= TSS64_LEN` disables I/O bitmap).
    pub iomap_base: u16,
}

impl Default for Tss64 {
    fn default() -> Self {
        Self::new()
    }
}

impl Tss64 {
    /// Construct an empty 64-bit TSS with `iomap_base = TSS64_LEN` (no I/O bitmap).
    pub const fn new() -> Self {
        Self {
            reserved0: 0,
            rsp: [0; 3],
            reserved1: 0,
            ist: [0; 7],
            reserved2: 0,
            reserved3: 0,
            iomap_base: TSS64_LEN as u16,
        }
    }

    /// Construct a 64-bit TSS populated with `RSP0` (Ring-0 privilege-transition
    /// stack top) and `IST1` (exception stack top).
    pub const fn with_stacks(rsp0: u64, ist1: u64) -> Self {
        let mut tss = Self::new();
        tss.rsp[0] = rsp0;
        tss.ist[0] = ist1;
        tss
    }

    /// Encode this `Tss64` into its canonical 104-byte little-endian layout.
    pub fn to_bytes(&self) -> [u8; TSS64_LEN] {
        let mut out = [0u8; TSS64_LEN];
        let rsp0 = self.rsp[0];
        let rsp1 = self.rsp[1];
        let rsp2 = self.rsp[2];
        out[4..12].copy_from_slice(&rsp0.to_le_bytes());
        out[12..20].copy_from_slice(&rsp1.to_le_bytes());
        out[20..28].copy_from_slice(&rsp2.to_le_bytes());
        let mut i = 0usize;
        while i < 7 {
            let v = self.ist[i];
            let off = 36 + i * 8;
            out[off..off + 8].copy_from_slice(&v.to_le_bytes());
            i += 1;
        }
        let iomap = self.iomap_base;
        out[102..104].copy_from_slice(&iomap.to_le_bytes());
        out
    }
}

/// Global Descriptor Table with 7 8-byte slots (`NULL`, `KernelCode`,
/// `KernelData`, `UserData`, `UserCode`, `TssLow`, `TssHigh`).
pub struct Gdt {
    /// The 7 8-byte slots. Slot 5+6 together form the 16-byte TSS
    /// descriptor.
    pub entries: [GdtEntry; GDT_LEN],
    /// IST stack pointers. Slot 0 is the double-fault stack top; slot
    /// 1 is the fault stack top.
    pub ist_stacks: [u64; 7],
    /// Ring-0 entry stack (TSS rsp0).
    pub rsp0: u64,
}

impl Gdt {
    /// Build a kernel-only GDT (no user segments installed, no TSS).
    pub fn new_kernel_only() -> Self {
        let mut entries = [GdtEntry::NULL; GDT_LEN];
        entries[GdtSlot::KernelCode as usize] = GdtEntry::kernel_code();
        entries[GdtSlot::KernelData as usize] = GdtEntry::kernel_data();
        Self {
            entries,
            ist_stacks: [0; 7],
            rsp0: 0,
        }
    }

    /// Build a full GDT with kernel + user segments. TSS descriptor
    /// occupies slots 5+6, with `tss_base` and `tss_limit` driving its
    /// encoding.
    pub fn new_full(tss_base: u64, tss_limit: u32) -> Self {
        let mut entries = [GdtEntry::NULL; GDT_LEN];
        entries[GdtSlot::KernelCode as usize] = GdtEntry::kernel_code();
        entries[GdtSlot::KernelData as usize] = GdtEntry::kernel_data();
        entries[GdtSlot::UserData as usize] = GdtEntry::user_data();
        entries[GdtSlot::UserCode as usize] = GdtEntry::user_code();
        let tss = TssDescriptor::new(tss_base, tss_limit);
        entries[GdtSlot::TssLow as usize] = tss.low;
        // Pack base_upper into the next slot's first 4 bytes. The remaining
        // 4 bytes of that slot are reserved (must be zero).
        let high = GdtEntry {
            limit_low: (tss.base_upper & 0xFFFF) as u16,
            base_low: ((tss.base_upper >> 16) & 0xFFFF) as u16,
            base_mid: 0,
            access: 0,
            limit_high_and_flags: 0,
            base_high: 0,
        };
        entries[GdtSlot::TssHigh as usize] = high;
        Self {
            entries,
            ist_stacks: [0; 7],
            rsp0: 0,
        }
    }

    /// Return the raw 8-byte little-endian encoding of slot `i`.
    pub fn raw_bytes(&self, i: usize) -> [u8; 8] {
        let e = self.entries[i];
        let limit_low = e.limit_low;
        let base_low = e.base_low;
        [
            (limit_low & 0xFF) as u8,
            (limit_low >> 8) as u8,
            (base_low & 0xFF) as u8,
            (base_low >> 8) as u8,
            e.base_mid,
            e.access,
            e.limit_high_and_flags,
            e.base_high,
        ]
    }

    /// Encode the entire 56-byte GDT (`7 * 8` bytes) into a contiguous buffer.
    pub fn to_table_bytes(&self) -> [u8; GDT_LEN * 8] {
        let mut out = [0u8; GDT_LEN * 8];
        let mut i = 0usize;
        while i < GDT_LEN {
            let slot = self.raw_bytes(i);
            out[i * 8..i * 8 + 8].copy_from_slice(&slot);
            i += 1;
        }
        out
    }

    /// Total byte size of the table.
    #[inline]
    pub const fn byte_size() -> usize {
        GDT_LEN * 8
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selectors_match_syscall_and_ring3_layout() {
        assert_eq!(KERNEL_CODE_SEL, 0x08);
        assert_eq!(KERNEL_DATA_SEL, 0x10);
        assert_eq!(USER_DATA_SEL, 0x1B);
        assert_eq!(USER_CODE_SEL, 0x23);
        assert_eq!(TSS_SEL, 0x28);
    }

    #[test]
    fn tss64_layout_is_104_bytes_with_expected_offsets() {
        assert_eq!(core::mem::size_of::<Tss64>(), TSS64_LEN);
        let tss = Tss64::with_stacks(0xFFFF_8000_0010_0000, 0xFFFF_8000_0020_0000);
        let bytes = tss.to_bytes();
        assert_eq!(
            u64::from_le_bytes(bytes[4..12].try_into().unwrap()),
            0xFFFF_8000_0010_0000
        );
        assert_eq!(
            u64::from_le_bytes(bytes[36..44].try_into().unwrap()),
            0xFFFF_8000_0020_0000
        );
        assert_eq!(
            u16::from_le_bytes(bytes[102..104].try_into().unwrap()),
            TSS64_LEN as u16
        );
    }

    #[test]
    fn gdt_full_encodes_segments_and_64bit_tss_base() {
        let tss_base: u64 = 0xFFFF_8000_1234_5678;
        let gdt = Gdt::new_full(tss_base, (TSS64_LEN - 1) as u32);
        let table = gdt.to_table_bytes();
        assert_eq!(&table[0..8], &[0u8; 8]);
        // KernelCode access byte: P=1, DPL=0, S=1, E=1, RW=1 -> 0x9A
        assert_eq!(table[8 + 5], 0x9A);
        // UserCode access byte: P=1, DPL=3, S=1, E=1, RW=1 -> 0xFA
        assert_eq!(table[32 + 5], 0xFA);
        // TSS upper 32 bits in slot 6 bytes 0..4
        assert_eq!(
            u32::from_le_bytes(table[48..52].try_into().unwrap()),
            0xFFFF_8000
        );
    }
}

