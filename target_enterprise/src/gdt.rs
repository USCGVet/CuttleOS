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
/// (kernel code/data) + (user data/code) + 2-slot TSS.
pub const GDT_LEN: usize = 7;

/// A built-but-not-loaded GDT. The `lgdt` instruction is left out of
/// this seed crate — it requires inline asm that is host-incompatible.
/// The morph engine will eventually swap `Gdt::load()` in.
pub struct Gdt {
    /// The 7 8-byte slots. Slot 5+6 together form the 16-byte TSS
    /// descriptor.
    pub entries: [GdtEntry; GDT_LEN],
    /// IST stack pointers. Slot 0 is the double-fault stack top; slot
    /// 1 is the fault stack top. Real per-CPU values are wired in by
    /// the morph engine; the seed leaves them at 0.
    pub ist_stacks: [u64; 7],
    /// Ring-0 entry stack (TSS rsp0). 0 in the seed.
    pub rsp0: u64,
}

impl Gdt {
    /// Build a kernel-only GDT (no user segments installed, no TSS).
    /// Useful for the verifier's early-boot smoke tests where the
    /// system never runs user code.
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

    /// Total byte size of the table.
    #[inline]
    pub const fn byte_size() -> usize {
        GDT_LEN * 8
    }
}
