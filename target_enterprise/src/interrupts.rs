//! Interrupt Descriptor Table — 16-byte 64-bit gate descriptors.
//!
//! Algorithmic core lifted from `RustOSa/src/interrupts.rs`. The donor
//! uses the `x86_64` crate's `InterruptDescriptorTable` builder, which
//! abstracts the per-vector packing. Here we expose the packing itself
//! as a real, host-testable surface — every byte of every 16-byte IDT
//! entry is bit-packed by hand per Intel SDM Vol. 3, §6.14.1.
//!
//! IDT entry layout (16 bytes, little-endian):
//!
//! ```text
//!   bytes  0..2    handler offset bits 0..16
//!   bytes  2..4    segment selector (kernel code)
//!   byte   4       IST index (bits 0..3); reserved (bits 3..8)
//!   byte   5       type/attr (P=1, DPL, type=0xE for interrupt gate)
//!   bytes  6..8    handler offset bits 16..32
//!   bytes  8..12   handler offset bits 32..64
//!   bytes 12..16   reserved (must be zero)
//! ```
//!
//! All 256 vectors are kept in a fixed-size table; the morph engine can
//! re-order the build order but the on-wire encoding is locked.

/// Number of vectors in the IDT (CPU exception vectors 0..32 + ISA IRQs
/// remapped to 32..48 + the remaining 256 - 48 software vectors).
pub const IDT_LEN: usize = 256;

/// PIC remap base for the master 8259. The legacy 0..16 range collides
/// with CPU exception vectors so the BIOS / OS remaps to 32..40 (master)
/// and 40..48 (slave). Locked here so userspace can construct vector
/// numbers without consulting the runtime.
pub const PIC_1_OFFSET: u8 = 32;
/// PIC remap base for the slave 8259.
pub const PIC_2_OFFSET: u8 = PIC_1_OFFSET + 8;

/// Type byte for a 64-bit interrupt gate, present, DPL=0.
pub const TYPE_INTERRUPT_GATE_DPL0: u8 = 0x8E;
/// Type byte for a 64-bit interrupt gate, present, DPL=3 (callable
/// from user mode).
pub const TYPE_INTERRUPT_GATE_DPL3: u8 = 0xEE;

/// Type byte for a 64-bit trap gate (does NOT clear IF on entry), DPL=0.
pub const TYPE_TRAP_GATE_DPL0: u8 = 0x8F;

/// One 16-byte IDT entry, packed exactly per the Intel SDM.
#[repr(C, packed)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct IdtEntry {
    /// Handler offset bits 0..16.
    pub offset_low: u16,
    /// Segment selector for the kernel code segment.
    pub selector: u16,
    /// IST index (bits 0..3) and reserved (bits 3..8). Bit 7..3 are
    /// reserved and must be zero.
    pub ist: u8,
    /// Type/attr byte (Present, DPL, type code).
    pub type_attr: u8,
    /// Handler offset bits 16..32.
    pub offset_mid: u16,
    /// Handler offset bits 32..64.
    pub offset_high: u32,
    /// Reserved — must be zero.
    pub reserved: u32,
}

impl IdtEntry {
    /// The default zero-initialised entry. P=0 so the CPU treats it as
    /// an "absent" gate.
    pub const NULL: Self = Self {
        offset_low: 0,
        selector: 0,
        ist: 0,
        type_attr: 0,
        offset_mid: 0,
        offset_high: 0,
        reserved: 0,
    };

    /// Build a new entry pointing at `handler_addr`. `selector` is the
    /// kernel code-segment selector (typically `GdtSlot::KernelCode << 3`,
    /// i.e. 0x08). `type_attr` is one of the `TYPE_*` constants. `ist`
    /// is 0 for "no IST" or 1..=7 for an explicit per-stack switch.
    pub fn new(handler_addr: u64, selector: u16, type_attr: u8, ist: u8) -> Self {
        Self {
            offset_low: (handler_addr & 0xFFFF) as u16,
            selector,
            ist: ist & 0x07,
            type_attr,
            offset_mid: ((handler_addr >> 16) & 0xFFFF) as u16,
            offset_high: ((handler_addr >> 32) & 0xFFFF_FFFF) as u32,
            reserved: 0,
        }
    }

    /// Re-extract the handler address. Mostly useful in tests.
    pub fn handler_addr(&self) -> u64 {
        (self.offset_low as u64)
            | ((self.offset_mid as u64) << 16)
            | ((self.offset_high as u64) << 32)
    }

    /// Whether the Present bit is set.
    #[inline]
    pub fn is_present(&self) -> bool {
        (self.type_attr & 0x80) != 0
    }
}

/// The 256-vector Interrupt Descriptor Table. Backed by a fixed-size
/// array so it lives in BSS (no allocation).
pub struct Idt {
    /// All 256 vectors. `[0..32]` are CPU exception vectors, `[32..48]`
    /// are ISA IRQs (remapped PIC), `[48..256]` are software vectors.
    pub entries: [IdtEntry; IDT_LEN],
    /// Kernel code-segment selector. Used by `set_handler` so callers
    /// don't have to repeat it for every vector.
    pub kernel_cs: u16,
}

impl Idt {
    /// Build an empty (all-NULL) IDT with `kernel_cs = 0x08` (GdtSlot::KernelCode * 8).
    pub fn new_empty() -> Self {
        Self {
            entries: [IdtEntry::NULL; IDT_LEN],
            kernel_cs: 0x08,
        }
    }

    /// Build an empty IDT with an explicit kernel code-segment selector.
    pub fn new_empty_with_cs(kernel_cs: u16) -> Self {
        Self {
            entries: [IdtEntry::NULL; IDT_LEN],
            kernel_cs,
        }
    }

    /// Install a handler at vector `vec`. The handler is registered as a
    /// 64-bit interrupt gate (DPL=0, no IST). The morph engine can later
    /// swap the type/attr byte for trap gates or DPL=3 entries by calling
    /// `set_handler_with_attr` instead.
    pub fn set_handler(&mut self, vec: u8, addr: u64) {
        self.entries[vec as usize] =
            IdtEntry::new(addr, self.kernel_cs, TYPE_INTERRUPT_GATE_DPL0, 0);
    }

    /// Install a handler with an explicit type/attr byte and IST index.
    pub fn set_handler_with_attr(&mut self, vec: u8, addr: u64, type_attr: u8, ist: u8) {
        self.entries[vec as usize] = IdtEntry::new(addr, self.kernel_cs, type_attr, ist);
    }

    /// Return the raw 16-byte encoding of vector `vec`. Useful for the
    /// verifier's byte-layout property checks.
    pub fn raw_bytes(&self, vec: u8) -> [u8; 16] {
        let e = self.entries[vec as usize];
        let off_lo = e.offset_low;
        let sel = e.selector;
        let off_mid = e.offset_mid;
        let off_hi = e.offset_high;
        let resv = e.reserved;
        [
            (off_lo & 0xFF) as u8,
            (off_lo >> 8) as u8,
            (sel & 0xFF) as u8,
            (sel >> 8) as u8,
            e.ist,
            e.type_attr,
            (off_mid & 0xFF) as u8,
            (off_mid >> 8) as u8,
            (off_hi & 0xFF) as u8,
            ((off_hi >> 8) & 0xFF) as u8,
            ((off_hi >> 16) & 0xFF) as u8,
            ((off_hi >> 24) & 0xFF) as u8,
            (resv & 0xFF) as u8,
            ((resv >> 8) & 0xFF) as u8,
            ((resv >> 16) & 0xFF) as u8,
            ((resv >> 24) & 0xFF) as u8,
        ]
    }

    /// Total byte size of the table (always 4096 bytes for a full IDT).
    #[inline]
    pub const fn byte_size() -> usize {
        IDT_LEN * 16
    }
}

/// Canonical x86_64 CPU exception vectors.
pub mod vectors {
    /// Divide-by-zero error.
    pub const DIVIDE_ERROR: u8 = 0;
    /// Debug exception.
    pub const DEBUG: u8 = 1;
    /// Non-maskable interrupt.
    pub const NMI: u8 = 2;
    /// Breakpoint (INT3).
    pub const BREAKPOINT: u8 = 3;
    /// Overflow (INTO).
    pub const OVERFLOW: u8 = 4;
    /// BOUND range exceeded.
    pub const BOUND_RANGE: u8 = 5;
    /// Invalid opcode.
    pub const INVALID_OPCODE: u8 = 6;
    /// Device not available (no FPU).
    pub const DEVICE_NOT_AVAIL: u8 = 7;
    /// Double fault.
    pub const DOUBLE_FAULT: u8 = 8;
    /// Invalid TSS.
    pub const INVALID_TSS: u8 = 10;
    /// Segment not present.
    pub const SEGMENT_NOT_PRESENT: u8 = 11;
    /// Stack-segment fault.
    pub const STACK_SEGMENT_FAULT: u8 = 12;
    /// General protection fault.
    pub const GENERAL_PROTECTION: u8 = 13;
    /// Page fault.
    pub const PAGE_FAULT: u8 = 14;
    /// x87 FPU floating-point error.
    pub const X87_FPU: u8 = 16;
    /// Alignment check.
    pub const ALIGNMENT_CHECK: u8 = 17;
    /// Machine check.
    pub const MACHINE_CHECK: u8 = 18;
    /// SIMD floating-point exception.
    pub const SIMD_FP: u8 = 19;
}
