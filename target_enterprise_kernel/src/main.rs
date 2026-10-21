//! Bare-metal `x86_64-unknown-none` unikernel entry point (`target_enterprise_kernel`).
//!
//! Links the verified `target_enterprise` subsystems to physical x86-64
//! hardware (16550 UART on `COM1`, PCI, AHCI, NVMe, VirtIO-net/blk, Intel
//! e1000, APIC/IOAPIC, HPET/PIT/RTC, and QEMU `fw_cfg` provisioning).
//!
//! Build via `factory_builder`:
//! `cargo run -p factory_builder -- build-kernel --kernel-crate <path-to-target_enterprise_kernel>`
//!
//! In default builds, the kernel executes the deterministic subsystem proof
//! sequence against `kernel_fixtures` on `COM1`, restores sealed `OsShell`
//! state from AHCI `LBA 1040..=1041`, services the network control plane, and
//! enters the interactive console shell. In production builds (`--prod` /
//! `--cfg cuttle_prod`), self-test banners and the red-team harness are
//! compiled out.

#![no_std]
#![no_main]
// Production builds (`--cfg cuttle_prod` in RUSTFLAGS, injected by
// `factory_builder build-kernel --prod`) exclude the banner self-proof
// suite and the red-team attack harness: every `banner_*` definition and
// call site is cfg-gated except `banner_continuity` / `banner_durable_seal`
// (real cross-morph durable-state work, not self-tests), and the planted
// attack surface is compiled out entirely. Prod boots are externally
// distinguishable by the `CUTTLE-TE PROD` serial line. Helpers left
// unused once banners are stripped are silenced, not deleted, so the
// banner build stays byte-for-byte identical in structure.
#![cfg_attr(cuttle_prod, allow(dead_code, unused_imports, unused_mut, unused_variables))]

// rustls (HTTPS on :443) allocates; `heap.rs` provides the global allocator.
extern crate alloc;

use core::arch::asm;
use core::panic::PanicInfo;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use cuttle_contracts::{
    AccessKind, AuditEvent, AuditLog, AuditVerdict, BpfContext, CrashContext, CrashDump, EBpf,
    FilterAction, FilterRule, Filesystem, Hash, Iommu, Ipv4PacketView, NtpReply, NtpTimestamp,
    PacketFilter, PagePerms, Sntp, SymbolResolve, Tpm, TpmResponseView, Verdict, Vfs, WriteAheadLog, AUDIT_EVENT_WIRE_LEN, AUDIT_SNAPSHOT_HEADER_LEN,
    AUDIT_SNAPSHOT_MAGIC, BPF_STACK_SIZE, FS_O_RDONLY, FW_PORT_ANY, IP_PROTO_ICMP, IP_PROTO_TCP,
    IP_PROTO_UDP, SNTP_MODE_CLIENT, SNTP_MODE_SERVER, SNTP_PACKET_LEN, SNTP_VERSION,
    TPM_ALG_SHA256, TPM_CC_GET_RANDOM, TPM_RC_SUCCESS, TPM_SHA256_DIGEST_LEN, TPM_ST_NO_SESSIONS,
    TPM_ST_SESSIONS, TPM_SU_CLEAR,
};
use target_enterprise::iommu::{DeviceId, IommuImpl};
use target_enterprise::kernel_fixtures as kf;
use target_enterprise::kpti::{
    KptiImpl, PageTable, KPTI_IRETQ_VIRT, KPTI_IRQ_TIMER_VIRT, KPTI_TRAMPOLINE_VIRT, PTE_NX,
    PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
use target_enterprise::audit::{parse_header as parse_audit_header, parse_record as parse_audit_record, AuditLogImpl};
use target_enterprise::e1000::BANNER_MAC;
use target_enterprise::ebpf::{run_reference_program, EBpfImpl, REFERENCE_PROGRAM_INSNS};
use target_enterprise::firewall::{FilterRuleExt, FirewallImpl, FirewallTable};
use target_enterprise::tpm::{
    extract_get_random_bytes, MaxTpmCommandBuf, TpmImpl, TPM_GET_RANDOM_CMD_LEN,
    TPM_PCR_EXTEND_SHA256_CMD_LEN, TPM_PCR_READ_CMD_LEN, TPM_STARTUP_CMD_LEN,
};
use target_enterprise::net::{build_udp_datagram, parse_ipv4_header, parse_udp_datagram};
use target_enterprise::panic_dump::{MemorySectorSink, PanicDumpImpl, DUMP_START_LBA};
use target_enterprise::sntp::SntpImpl;
use target_enterprise::vfs::{MemRamFs, VfsImpl};
use target_enterprise::symbols::{StaticSymbolResolver, SymbolEntry};
use target_enterprise::tls::{hkdf_expand_label, hkdf_extract};
use target_enterprise::wal::WalImpl;
use target_enterprise::HashImpl;
use cuttle_contracts::Kpti;

/// Map all physical memory so virtio DMA buffers (kernel statics)
/// have known guest-physical addresses for QEMU virtio-blk.
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut c = BootloaderConfig::new_default();
    c.mappings.physical_memory = Some(Mapping::Dynamic);
    c.kernel_stack_size = 512 * 1024;
    c
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Physical→virtual offset for the full physical memory map
/// (`virt = phys + PHYS_MAP_OFFSET`). Required for virtio DMA.
pub(crate) static PHYS_MAP_OFFSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Guest-physical base of a usable DMA scratch region (≥ 128 KiB for
/// virtqueues + AHCI command structures + temporary page-table frames
/// for MMIO BAR mapping).
pub(crate) static DMA_PHYS_BASE: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Bump cursor for page-table frames carved from the top of the DMA window.
pub(crate) static PT_ALLOC_NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

#[inline(always)]
pub(crate) fn phys_map_offset() -> u64 {
    PHYS_MAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed)
}

#[inline(always)]
pub(crate) fn dma_phys_base() -> u64 {
    DMA_PHYS_BASE.load(core::sync::atomic::Ordering::Relaxed)
}

pub(crate) fn set_phys_offset(boot: &BootInfo) {
    let map_off = match boot.physical_memory_offset.into_option() {
        Some(o) => o,
        None => 0,
    };
    // Prefer conventional RAM in the low 4 GiB for legacy QUEUE_PFN
    // (32-bit PFN field). Skip the first 1 MiB (IVT/EBDA/bootloader).
    let mut dma = 0u64;
    for r in boot.memory_regions.iter() {
        use bootloader_api::info::MemoryRegionKind;
        if r.kind != MemoryRegionKind::Usable {
            continue;
        }
        let start = r.start;
        let end = r.end.min(0x1_0000_0000); // stay below 4 GiB
        if end <= start {
            continue;
        }
        let aligned = (start + 0xFFF) & !0xFFF;
        // 256 KiB: virtio queues + AHCI CLB/FB/CTBA + PT scratch + Ring-3 trampoline frames + SMP PT frames.
        if aligned >= 0x10_0000 && end.saturating_sub(aligned) >= 0x4_0000 {
            dma = aligned;
            break;
        }
    }
    PHYS_MAP_OFFSET.store(map_off, core::sync::atomic::Ordering::Relaxed);
    DMA_PHYS_BASE.store(dma, core::sync::atomic::Ordering::Relaxed);
    // Page-table frame pool (`0x1_C000 .. 0x2_4000` and `0x2_C000 .. 0x4_0000`);
    // `0x2_4000 .. 0x2_C000` is reserved for the Ring-3 GDT/TSS/IDT/page-table transition frames.
    let pt_next = if dma != 0 { dma + 0x1_C000 } else { 0 };
    PT_ALLOC_NEXT.store(pt_next, core::sync::atomic::Ordering::Relaxed);
}

/// Virtual address for a guest-physical address in the physical memory map.
pub(crate) fn pa_to_va(phys: u64) -> *mut u8 {
    let off = phys_map_offset();
    (phys.wrapping_add(off)) as *mut u8
}

// ---- Page-table helpers for PCI MMIO BARs (outside RAM E820) ----

pub(crate) const PTE_P: u64 = 1;
pub(crate) const PTE_W: u64 = 2;
pub(crate) const PTE_PWT: u64 = 1 << 3;
pub(crate) const PTE_PCD: u64 = 1 << 4;
pub(crate) const PTE_PS: u64 = 1 << 7;
pub(crate) const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

// SAFETY: Caller must execute in ring 0 (kernel mode) where reading CR3 is privileged-safe.
#[inline(always)]
pub(crate) unsafe fn read_cr3() -> u64 {
    let v: u64;
    // SAFETY: Reading CR3 in ring 0 has no side effects and preserves registers/flags.
    unsafe {
        asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

// SAFETY: Caller must ensure DMA_PHYS_BASE and PHYS_MAP_OFFSET are initialized from BootInfo.
pub(crate) unsafe fn alloc_pt_frame() -> u64 {
    let base = dma_phys_base();
    let mut next = PT_ALLOC_NEXT.load(core::sync::atomic::Ordering::Relaxed);
    if base != 0 && next == base + 0x2_4000 {
        next = base + 0x2_C000;
    }
    if base == 0 || next == 0 || next + 0x1000 > base + 0x4_0000 {
        panic!("AHCI_HW: PT frame pool exhausted");
    }
    let frame = next;
    PT_ALLOC_NEXT.store(next + 0x1000, core::sync::atomic::Ordering::Relaxed);
    // SAFETY: `frame` is a newly allocated 4 KiB page inside the reserved DMA/PT pool mapped via `pa_to_va`.
    unsafe {
        let p = pa_to_va(frame);
        let mut i = 0usize;
        while i < 0x1000 {
            core::ptr::write_volatile(p.add(i), 0);
            i += 1;
        }
    }
    frame
}

/// Ensure guest-physical `phys` (any offset in page) is reachable via
/// `PHYS_MAP_OFFSET`. Installs a 4 KiB uncached PTE when the bootloader
/// did not map the page (typical for PCI MMIO BARs).
// SAFETY: Caller must pass a valid guest-physical MMIO or RAM address in ring 0 with active 4-level paging.
pub(crate) unsafe fn ensure_mmio_page(phys: u64) -> *mut u8 {
    let phys_page = phys & !0xFFFu64;
    let off = PHYS_MAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    if off == 0 {
        panic!("AHCI_HW: no physical_memory_offset for MMIO");
    }
    let va = phys_page.wrapping_add(off);
    let indices = [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ];
    // SAFETY: Running in ring 0; CR3 holds the active PML4 physical address.
    let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let mut level = 0usize;
    while level < 3 {
        // SAFETY: `table` is a physical page-table frame mapped via `pa_to_va`, and `indices[level] < 512`.
        let ent_ptr = unsafe { pa_to_va(table).cast::<u64>().add(indices[level]) };
        // SAFETY: `ent_ptr` is 8-byte aligned and points to a valid page-table entry in mapped physical memory.
        let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
        if ent & PTE_P == 0 {
            // SAFETY: Running at CPL=0 with initialized `PT_ALLOC_NEXT`; returns a 4 KiB-aligned physical address within the reserved DMA/PT pool.
            let new_t = unsafe { alloc_pt_frame() };
            // SAFETY: `ent_ptr` is an 8-byte-aligned PTE slot in the mapped parent page table and `new_ent` points to a zeroed 4 KiB frame.
            unsafe {
                core::ptr::write_volatile(ent_ptr, new_t | PTE_P | PTE_W);
            }
            table = new_t;
        } else if ent & PTE_PS != 0 {
            // Huge page already present — only valid if it covers this
            // phys (bootloader RAM maps). MMIO VAs should not hit this.
            return va as *mut u8;
        } else {
            table = ent & PTE_ADDR_MASK;
        }
        level += 1;
    }
    // SAFETY: `table` is the L1 page-table frame and `indices[3] < 512`.
    let leaf = unsafe { pa_to_va(table).cast::<u64>().add(indices[3]) };
    // SAFETY: `leaf` is a valid L1 PTE pointer in mapped physical memory.
    let ent = unsafe { core::ptr::read_volatile(leaf) };
    if ent & PTE_P == 0 || (ent & (PTE_PWT | PTE_PCD)) != (PTE_PWT | PTE_PCD) {
        // Present | Writable | PWT | PCD (uncached MMIO).
        let pte = phys_page | PTE_P | PTE_W | PTE_PWT | PTE_PCD;
        // SAFETY: `leaf` is an 8-byte-aligned L1 PTE pointer in mapped physical memory and `invlpg` is valid at CPL=0 for any canonical virtual address `va`.
        unsafe {
            core::ptr::write_volatile(leaf, pte);
            asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
        }
    }
    va as *mut u8
}

// SAFETY: Caller must pass a valid guest-physical MMIO register address in ring 0.
pub(crate) unsafe fn mmio_read8(phys: u64) -> u8 {
    // SAFETY: Running at CPL=0; `phys & !0xFFF` is a page-aligned guest-physical MMIO address mapped with `PTE_P | PTE_W | PTE_PWT | PTE_PCD`.
    let page = unsafe { ensure_mmio_page(phys) };
    let off = (phys & 0xFFF) as usize;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `off = (phys & 0xFFF) <= 0xFFF`, so `page.add(off)` is a mapped 8-bit MMIO register within the 4 KiB page.
    let val = unsafe { core::ptr::read_volatile(page.add(off)) };
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    val
}

// SAFETY: Caller must pass a valid guest-physical MMIO register address in ring 0.
pub(crate) unsafe fn mmio_write8(phys: u64, val: u8) {
    // SAFETY: Running at CPL=0; `phys & !0xFFF` is a page-aligned guest-physical MMIO address mapped with `PTE_P | PTE_W | PTE_PWT | PTE_PCD`.
    let page = unsafe { ensure_mmio_page(phys) };
    let off = (phys & 0xFFF) as usize;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `off = (phys & 0xFFF) <= 0xFFF`, so `page.add(off)` is a mapped 8-bit MMIO register within the 4 KiB page.
    unsafe {
        core::ptr::write_volatile(page.add(off), val);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

// SAFETY: Caller must pass a 4-byte aligned guest-physical MMIO register address.
pub(crate) unsafe fn mmio_read32(phys: u64) -> u32 {
    // SAFETY: Running at CPL=0; `phys & !0xFFF` is a page-aligned guest-physical MMIO address mapped with `PTE_P | PTE_W | PTE_PWT | PTE_PCD`.
    let page = unsafe { ensure_mmio_page(phys) };
    let off = (phys & 0xFFF) as usize;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `off = (phys & 0xFFF) <= 0xFFC` and caller guarantees 4-byte alignment, so `page.add(off)` is an aligned, mapped 32-bit MMIO register.
    let val = unsafe { core::ptr::read_volatile(page.add(off) as *const u32) };
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    val
}

// SAFETY: Caller must pass a 4-byte aligned guest-physical MMIO register address.
pub(crate) unsafe fn mmio_write32(phys: u64, val: u32) {
    // SAFETY: Running at CPL=0; `phys & !0xFFF` is a page-aligned guest-physical MMIO address mapped with `PTE_P | PTE_W | PTE_PWT | PTE_PCD`.
    let page = unsafe { ensure_mmio_page(phys) };
    let off = (phys & 0xFFF) as usize;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: `off = (phys & 0xFFF) <= 0xFFC` and caller guarantees 4-byte alignment, so `page.add(off)` is an aligned, mapped 32-bit MMIO register.
    unsafe {
        core::ptr::write_volatile(page.add(off) as *mut u32, val);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

// SAFETY: Caller must pass a valid 64-bit MMIO register address supporting two 32-bit reads.
pub(crate) unsafe fn mmio_read64(phys: u64) -> u64 {
    // SAFETY: Caller guarantees `phys` is an 8-byte-aligned 64-bit MMIO register; reading low dword at `phys` via `mmio_read32` is aligned and mapped.
    let lo = unsafe { mmio_read32(phys) } as u64;
    // SAFETY: Caller guarantees `phys` is an 8-byte-aligned 64-bit MMIO register, so `phys + 4` is 4-byte aligned within the same 4 KiB MMIO page.
    let hi = unsafe { mmio_read32(phys + 4) } as u64;
    lo | (hi << 32)
}

// SAFETY: Caller must pass a valid 64-bit MMIO register address supporting two 32-bit writes.
pub(crate) unsafe fn mmio_write64(phys: u64, val: u64) {
    // SAFETY: Caller guarantees `phys` is an 8-byte-aligned 64-bit MMIO register, so both `phys` and `phys + 4` are 4-byte aligned within the same page.
    unsafe {
        mmio_write32(phys, val as u32);
        mmio_write32(phys + 4, (val >> 32) as u32);
    }
}

// ============================================================
// 16550 UART driver (COM1)
// ============================================================

/// QEMU 16550 UART base I/O port. THR/RBR at +0, LSR at +5.
pub(crate) const COM1: u16 = 0x3F8;
/// LSR bit 5: transmitter holding register empty.
pub(crate) const LSR_THRE: u8 = 1 << 5;

// SAFETY: Caller must pass a valid x86 I/O port in ring 0.
#[inline(always)]
pub(crate) unsafe fn outb(port: u16, val: u8) {
    // SAFETY: Executing 8-bit port I/O write in ring 0; does not touch memory or stack.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

// SAFETY: Caller must pass a valid x86 I/O port in ring 0.
#[inline(always)]
pub(crate) unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    // SAFETY: Executing 8-bit port I/O read in ring 0; does not touch memory or stack.
    unsafe {
        asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

// SAFETY: Caller must pass a valid 32-bit x86 I/O port in ring 0.
#[inline(always)]
pub(crate) unsafe fn outl(port: u16, val: u32) {
    // SAFETY: Executing 32-bit port I/O write in ring 0; does not touch memory or stack.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
    }
}

// SAFETY: Caller must pass a valid 32-bit x86 I/O port in ring 0.
#[inline(always)]
pub(crate) unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    // SAFETY: Executing 32-bit port I/O read in ring 0; does not touch memory or stack.
    unsafe {
        asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

// SAFETY: Caller must pass a valid 16-bit x86 I/O port in ring 0.
#[inline(always)]
pub(crate) unsafe fn outw(port: u16, val: u16) {
    // SAFETY: Executing 16-bit port I/O write in ring 0; does not touch memory or stack.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
    }
}

// SAFETY: Caller must pass a valid 16-bit x86 I/O port in ring 0.
#[inline(always)]
pub(crate) unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    // SAFETY: Executing 16-bit port I/O read in ring 0; does not touch memory or stack.
    unsafe {
        asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// PCI configuration-space address / data ports (mechanism #1).
pub(crate) const PCI_CONFIG_ADDR: u16 = 0xCF8;
pub(crate) const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Real PCI config-space bus: issues `out`/`in` against 0xCF8/0xCFC.
/// This is the hardware-truth counterpart to `RecordingBus` — every
/// read is a real I/O cycle observed by QEMU's PCI host bridge.
pub(crate) struct RealPciBus;

impl cuttle_contracts::PciConfigBus for RealPciBus {
    fn read_dword(&mut self, addr: cuttle_contracts::PciAddress, offset: u8) -> u32 {
        let o = (offset as u32) & 0xFC;
        let conf = 0x8000_0000u32
            | ((addr.bus as u32) << 16)
            | ((addr.device as u32) << 11)
            | ((addr.function as u32) << 8)
            | o;
        // SAFETY: Running at CPL=0; ports 0xCF8 and 0xCFC are the architectural x86 PCI Mechanism #1 config registers and do not alias memory.
        unsafe {
            outl(PCI_CONFIG_ADDR, conf);
            inl(PCI_CONFIG_DATA)
        }
    }
    fn write_dword(
        &mut self,
        addr: cuttle_contracts::PciAddress,
        offset: u8,
        value: u32,
    ) {
        let o = (offset as u32) & 0xFC;
        let conf = 0x8000_0000u32
            | ((addr.bus as u32) << 16)
            | ((addr.device as u32) << 11)
            | ((addr.function as u32) << 8)
            | o;
        // SAFETY: Running at CPL=0; ports 0xCF8 and 0xCFC are the architectural x86 PCI Mechanism #1 config registers and do not alias memory.
        unsafe {
            outl(PCI_CONFIG_ADDR, conf);
            outl(PCI_CONFIG_DATA, value);
        }
    }
}

pub(crate) fn serial_init() {
    // 16550 init: 38400 baud, 8N1, FIFO enabled.
    // SAFETY: Running at CPL=0; I/O ports `0x3F8..=0x3FC` decode to the architectural COM1 16550 UART registers and do not touch memory.
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // enable DLAB
        outb(COM1 + 0, 0x03); // divisor lo = 3 (38400 baud)
        outb(COM1 + 1, 0x00); // divisor hi
        outb(COM1 + 3, 0x03); // 8N1, DLAB off
        outb(COM1 + 2, 0xC7); // FIFO enable, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }
}

pub(crate) fn serial_write_byte(b: u8) {
    // SAFETY: Running at CPL=0 after `serial_init`; port 0x3FD is COM1 LSR and port 0x3F8 is COM1 THR once LSR.THRE confirms FIFO space.
    unsafe {
        while inb(COM1 + 5) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, b);
    }
    fb_write_byte(b);
}

pub(crate) fn serial_write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(b);
    }
}

pub(crate) fn serial_write_bytes(buf: &[u8]) {
    for &b in buf {
        if b == b'\n' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(b);
    }
}

// ============================================================
// Tiny no_std hex / decimal formatters (no `core::fmt`)
// ============================================================

pub(crate) const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Write the first `n` bytes of `bytes` as lowercase hex into `out`.
/// Caller-supplied `out` must be at least `n * 2` bytes long.
pub(crate) fn hex_encode(bytes: &[u8], n: usize, out: &mut [u8]) -> usize {
    let take = if n > bytes.len() { bytes.len() } else { n };
    let mut i = 0usize;
    while i < take {
        let b = bytes[i];
        out[i * 2] = HEX_DIGITS[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_DIGITS[(b & 0x0F) as usize];
        i += 1;
    }
    take * 2
}

/// Format `val` as zero-padded 8-character lowercase hex (the low 32
/// bits). Writes 8 bytes into `out`.
pub(crate) fn hex_u32(val: u32, out: &mut [u8; 8]) {
    let mut i = 0usize;
    while i < 8 {
        let shift = 28 - i * 4;
        let nyb = ((val >> shift) & 0xF) as usize;
        out[i] = HEX_DIGITS[nyb];
        i += 1;
    }
}

/// Format `val` as decimal into `out`, returning the number of bytes
/// written. `out` must be at least 20 bytes long (max u64 decimal).
pub(crate) fn dec_u64(mut val: u64, out: &mut [u8]) -> usize {
    if val == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut k = 0usize;
    while val > 0 {
        tmp[k] = b'0' + ((val % 10) as u8);
        val /= 10;
        k += 1;
    }
    // tmp is little-endian decimal; reverse into out.
    let mut i = 0usize;
    while i < k {
        out[i] = tmp[k - 1 - i];
        i += 1;
    }
    k
}

// ============================================================
// Banner emitters — one per morphed surface
// ============================================================

/// Assert `actual == expected` byte-for-byte. On mismatch, panic with
/// a message naming the surface; the panic handler emits the panic
/// banner over serial, the QEMU smoke test then fails because the
/// trailing per-feature banner does not appear.
pub(crate) fn assert_eq_bytes(actual: &[u8], expected: &[u8], surface: &'static str) {
    if actual.len() != expected.len() {
        panic!("{} length mismatch", surface);
    }
    let mut i = 0usize;
    while i < actual.len() {
        if actual[i] != expected[i] {
            panic!("{} byte mismatch", surface);
        }
        i += 1;
    }
}


mod banners_arch_platform;
mod banners_compose;
mod banners_security_crypto;
mod banners_storage_fs;
mod banners_tls_net;
mod fb_console;
mod heap;
mod hw_net_drivers;
mod hw_storage_drivers;
mod net_service;
mod provisioning;
mod smp_hw;

pub(crate) use banners_arch_platform::*;
pub(crate) use banners_compose::*;
pub(crate) use banners_security_crypto::*;
pub(crate) use banners_storage_fs::*;
pub(crate) use banners_tls_net::*;
pub(crate) use fb_console::*;
pub(crate) use hw_net_drivers::*;
pub(crate) use hw_storage_drivers::*;
pub(crate) use net_service::*;
pub(crate) use provisioning::*;
pub(crate) use smp_hw::*;

// ============================================================
// Entry + panic handler + halt
// ============================================================

pub(crate) fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    heap::init(); // before anything allocates (rustls on port 443)
    set_phys_offset(boot_info);
    fb_register(boot_info);
    serial_init();
    serial_write_str("CUTTLE-TE OK\n");
    // Distinguishes production boots externally; absent in banner builds.
    #[cfg(cuttle_prod)]
    serial_write_str("CUTTLE-TE PROD\n");

    // Per-feature proof sequence. Each helper asserts against the
    // locked fixtures (panic on mismatch → handler emits PANIC banner,
    // QEMU smoke fails) and emits one line on success.
    #[cfg(not(cuttle_prod))]
    banner_tls_hkdf();
    // HTTPS building blocks: the RustCrypto provider's known-answer
    // vectors, then a generated certificate parsed and verified.
    #[cfg(not(cuttle_prod))]
    banner_tls_kat();
    #[cfg(not(cuttle_prod))]
    banner_tls_cert();
    #[cfg(not(cuttle_prod))]
    banner_wal_replay();
    #[cfg(not(cuttle_prod))]
    banner_iommu_translate();
    #[cfg(not(cuttle_prod))]
    banner_hash_digest();
    #[cfg(not(cuttle_prod))]
    banner_net_build();
    #[cfg(not(cuttle_prod))]
    banner_kpti();
    #[cfg(not(cuttle_prod))]
    banner_dma();
    #[cfg(not(cuttle_prod))]
    banner_ring3_transition();
    #[cfg(not(cuttle_prod))]
    banner_nvme();
    #[cfg(not(cuttle_prod))]
    banner_tcp();
    #[cfg(not(cuttle_prod))]
    banner_http();
    #[cfg(not(cuttle_prod))]
    banner_dns();
    #[cfg(not(cuttle_prod))]
    banner_icmp();
    #[cfg(not(cuttle_prod))]
    banner_eth();
    #[cfg(not(cuttle_prod))]
    banner_arp();
    #[cfg(not(cuttle_prod))]
    banner_dhcp();
    #[cfg(not(cuttle_prod))]
    banner_virtio_net();
    #[cfg(not(cuttle_prod))]
    banner_virtio_blk();
    #[cfg(not(cuttle_prod))]
    banner_e1000();
    #[cfg(not(cuttle_prod))]
    banner_firewall();
    #[cfg(not(cuttle_prod))]
    banner_tpm();
    #[cfg(not(cuttle_prod))]
    banner_audit();
    #[cfg(not(cuttle_prod))]
    banner_sntp();
    #[cfg(not(cuttle_prod))]
    banner_vfs();
    #[cfg(not(cuttle_prod))]
    banner_ebpf();
    #[cfg(not(cuttle_prod))]
    banner_smp();
    #[cfg(not(cuttle_prod))]
    banner_tftp();
    #[cfg(not(cuttle_prod))]
    banner_pci();
    #[cfg(not(cuttle_prod))]
    banner_x509();
    #[cfg(not(cuttle_prod))]
    banner_timer();
    #[cfg(not(cuttle_prod))]
    banner_kat();
    #[cfg(not(cuttle_prod))]
    banner_jfs();
    #[cfg(not(cuttle_prod))]
    banner_gdbstub();
    #[cfg(not(cuttle_prod))]
    banner_quota();
    #[cfg(not(cuttle_prod))]
    banner_hpet();
    #[cfg(not(cuttle_prod))]
    banner_canary();
    #[cfg(not(cuttle_prod))]
    banner_keyboard();
    #[cfg(not(cuttle_prod))]
    banner_fat32();
    #[cfg(not(cuttle_prod))]
    banner_watchdog();
    #[cfg(not(cuttle_prod))]
    banner_rng();
    #[cfg(not(cuttle_prod))]
    banner_power();
    #[cfg(not(cuttle_prod))]
    banner_elf();
    #[cfg(not(cuttle_prod))]
    banner_serial();
    #[cfg(not(cuttle_prod))]
    banner_tick();
    #[cfg(not(cuttle_prod))]
    banner_virtio_caps();
    #[cfg(not(cuttle_prod))]
    banner_sigkat();
    #[cfg(not(cuttle_prod))]
    banner_mb2();
    #[cfg(not(cuttle_prod))]
    banner_crc32c();
    #[cfg(not(cuttle_prod))]
    banner_rsdp();
    #[cfg(not(cuttle_prod))]
    banner_frame();
    #[cfg(not(cuttle_prod))]
    banner_ioapic();
    #[cfg(not(cuttle_prod))]
    banner_lapic();
    #[cfg(not(cuttle_prod))]
    banner_gpt();
    #[cfg(not(cuttle_prod))]
    banner_dns_name();
    #[cfg(not(cuttle_prod))]
    banner_drbg();
    #[cfg(not(cuttle_prod))]
    banner_ahci_fis();
    #[cfg(not(cuttle_prod))]
    banner_xhci_trb();
    #[cfg(not(cuttle_prod))]
    banner_uefi_gop();
    #[cfg(not(cuttle_prod))]
    banner_attest_tlv();
    #[cfg(not(cuttle_prod))]
    banner_base64();
    #[cfg(not(cuttle_prod))]
    banner_ahci_cmd();
    // Anti-sprawl live composition: codecs wired *together*, not only
    // isolated per-module banners. Proves timer/tick/watchdog,
    // VFS/quota, and AHCI FIS+cmd table call chains survive into the
    // boot image — and (via morphed_qemu_proof) after diversification.
    #[cfg(not(cuttle_prod))]
    banner_timebase_compose();
    #[cfg(not(cuttle_prod))]
    banner_vfs_quota_compose();
    #[cfg(not(cuttle_prod))]
    banner_ahci_storage_compose();
    #[cfg(not(cuttle_prod))]
    banner_net_path_compose();
    #[cfg(not(cuttle_prod))]
    banner_block_path_compose();
    // TASK-104/107: real PCI + virtqueue I/O for virtio-blk-pci.
    #[cfg(not(cuttle_prod))]
    banner_virtio_hw();
    // TASK-109/111: real PCI + TX/RX virtqueues for virtio-net-pci.
    #[cfg(not(cuttle_prod))]
    banner_virtio_net_hw();
    // TASK-113/117: real AHCI HBA MMIO + IDENTIFY + sector DMA.
    #[cfg(not(cuttle_prod))]
    banner_ahci_hw();
    // Cross-morph durable-state continuity: real WAL replay + persist
    // on the AHCI disk; a morphed successor boot resumes it.
    banner_continuity();
    // REAL WORKLOAD: lived net on the first virtio-net — UDP/8080
    // status, TCP/80 HTTP /status, ICMP echo. Bounded poll loop;
    // exits to HALT when the window closes.
    service_udp_status();
    // TASK-116/120: real e1000 PCI + MMIO + EEPROM MAC + TX DD.
    #[cfg(not(cuttle_prod))]
    banner_e1000_hw();
    // TASK-119: real QEMU NVMe admin identify (not MemNvmeController).
    #[cfg(not(cuttle_prod))]
    banner_nvme_hw();
    // TASK-145: guest durable seal of empty audit snapshot header.
    banner_durable_seal();
    #[cfg(not(cuttle_prod))]
    banner_panic_dump();
    // Interactive OS shell + unified VFS/Scheduler/Audit runtime proof.
    banner_shell_compose();
    // True hardware multi-core SMP AP bringup + multi-stack thread context switching.
    banner_smp_hw();

    // ============================================================
    // RED-TEAM ATTACK HARNESS (deliberate, instrumented vulnerability)
    // ============================================================
    // A serial-port attack surface with a REAL stack buffer overflow,
    // planted so the core-theory experiment can fire a genuine ROP
    // chain at this kernel instead of simulating one. If COM1 delivers
    // the magic bytes "ATK!" followed by exactly ATTACK_READ_LEN bytes,
    // `attack_vulnerable_service` copies all of them into a 64-byte
    // stack buffer with no bounds check. An attacker payload that
    // overwrites the return address with a gadget chain gains control
    // when the function returns. Reachable only via physical/serial
    // access to the boot console — never via the network stack — and
    // the window closes after a short poll, so normal boots are
    // unaffected.
    #[cfg(not(cuttle_prod))]
    attack_iface_pilot();

    serial_write_str("CUTTLE-TE HALT\n");
    live_os_console_loop();
}


static CONSOLE_NET_REPLIES: spin::Mutex<target_enterprise::ReplySet> =
    spin::Mutex::new(target_enterprise::ReplySet::new());
static CONSOLE_NET_FRAME: spin::Mutex<[u8; 2048]> = spin::Mutex::new([0u8; 2048]);
static CONSOLE_NET_SVC: spin::Mutex<target_enterprise::LivedNet> =
    spin::Mutex::new(target_enterprise::LivedNet::empty());

/// Unified continuous OS event loop multiplexing:
/// - VirtIO-Net (`VnetModern`) + [`target_enterprise::LivedNet`] (`HTTP :80`, `HTTPS :443` (rustls TLS 1.3), `UDP :8080`, `UDP :8081`, `ICMP`, `ARP`)
/// - Serial console (`COM1` `0x3F8`) and PS/2 keyboard (`0x60`/`0x64`)
/// - Live AHCI disk persistence (`LBA 1040..=1065`) on `sync`, SQL mutations, `halt`, and `reboot`
pub(crate) fn live_os_console_loop() -> ! {
    use cuttle_contracts::{KeyCode, Keyboard};
    use target_enterprise::keyboard::KeyboardImpl;
    use target_enterprise::{ShellAction, SHELL_PROMPT};

    let mut sh_guard = KERNEL_SHELL.lock();
    let sh: &mut target_enterprise::OsShell = &mut *sh_guard;
    let mut kbd = KeyboardImpl::new();

    let dma = dma_phys_base();
    let mut vnet_opt = if dma != 0 { vnet_modern_init(dma) } else { None };
    if let Some(vn) = vnet_opt.as_mut() {
        let mut garp = [0u8; 42];
        garp[..6].copy_from_slice(&[0xffu8; 6]);
        garp[6..12].copy_from_slice(&vn.mac);
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
        garp[22..28].copy_from_slice(&vn.mac);
        garp[28..32].copy_from_slice(&UDP_SVC_IP);
        garp[32..38].copy_from_slice(&[0u8; 6]);
        garp[38..42].copy_from_slice(&UDP_SVC_IP);
        vnet_tx(vn, &garp);
        let mut gw = garp;
        gw[38..42].copy_from_slice(&[10, 0, 2, 2]);
        vnet_tx(vn, &gw);
    }
    let mut svc_guard = CONSOLE_NET_SVC.lock();
    let svc: &mut target_enterprise::LivedNet = &mut *svc_guard;
    if let Some(vn) = vnet_opt.as_ref() {
        *svc = match derive_runtime_net_auth_key(vn.mac) {
            Some(k) => target_enterprise::LivedNet::with_auth_key(vn.mac, k),
            None => target_enterprise::LivedNet::new_unprovisioned(vn.mac),
        };
        enable_https(svc, vn.mac);
    }
    let mut net_rx: u64 = 0;
    let mut net_tx: u64 = 0;
    let mut last_sql_tx: u64 = sh.db.tx_seq;

    smp_hw_tick_and_sync(sh);
    smp_hw_enable_bsp_timer();
    fb_console_start();
    serial_write_str("Cuttle Enterprise OS interactive shell ready.\n");
    serial_write_str("Web UI: http://127.0.0.1:18080/app | SQL: http://127.0.0.1:18080/sql\n");
    serial_write_bytes(SHELL_PROMPT);

    let mut echo = [0u8; 32];
    let mut reply = [0u8; 1024];

    loop {
        let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        let mut did_io = false;

        // 0. Drain live VirtIO-Net interface for HTTP (:80), TLS 1.3 (:443), UDP (:8080/:8081), ICMP, and ARP.
        if let Some(vn) = vnet_opt.as_mut() {
            let _ = svc.tick_tcp_rto();
            let mut f_guard = CONSOLE_NET_FRAME.lock();
            while let Some((flen, head_id)) = vnet_rx(vn, &mut *f_guard) {
                did_io = true;
                net_rx = net_rx.wrapping_add(1);
                if flen >= 14 {
                    smp_hw_tick_and_sync(sh);
                    let mut rep_guard = CONSOLE_NET_REPLIES.lock();
                    *rep_guard = target_enterprise::ReplySet::new();
                    svc.handle_frame_with_shell(&f_guard[..flen], boots, sh, &mut *rep_guard);
                    let mut ri = 0usize;
                    while ri < rep_guard.len() {
                        if let Some(r) = rep_guard.get(ri) {
                            vnet_tx(vn, r);
                            net_tx = net_tx.wrapping_add(1);
                        }
                        ri += 1;
                    }
                }
                vnet_rx_recycle(vn, head_id);
                if sh.db.tx_seq != last_sql_tx {
                    last_sql_tx = sh.db.tx_seq;
                    let _ = persist_shell_to_ahci(sh, boots);
                }
            }
        }

        let mut maybe_byte: Option<u8> = None;

        // 1. Poll COM1 (16550 UART LSR bit 0 = data ready).
        // SAFETY: Running at CPL=0; port 0x3FD is the read-only COM1 Line Status Register and reading it has no memory side effects.
        if unsafe { inb(COM1 + 5) & 0x01 != 0 } {
            // SAFETY: COM1 LSR bit 0 confirmed a received byte is ready in RBR (0x3F8).
            maybe_byte = Some(unsafe { inb(COM1) });
        } else {
            // 2. Poll PS/2 8042 status port (bit 0 = output buffer full).
            // SAFETY: Running at CPL=0; port 0x64 is the read-only i8042 PS/2 controller status register and reading it has no memory side effects.
            let kbd_ready = unsafe { inb(0x64) & 0x01 != 0 };
            if kbd_ready {
                // SAFETY: 8042 status bit 0 confirmed a scancode byte is ready at port 0x60.
                let sc = unsafe { inb(0x60) };
                if let Some(ev) = kbd.feed(sc) {
                    if ev.pressed {
                        if ev.ascii != 0 {
                            maybe_byte = Some(ev.ascii);
                        } else if ev.code == KeyCode::Enter {
                            maybe_byte = Some(b'\n');
                        } else if ev.code == KeyCode::Backspace {
                            maybe_byte = Some(0x08);
                        }
                    }
                }
            }
        }

        if let Some(b) = maybe_byte {
            if b == b'\n' || b == b'\r' {
                smp_hw_tick_and_sync(sh);
            }
            let (elen, act) = sh.feed_byte(b, boots, net_rx, net_tx, &mut echo, &mut reply);
            if elen > 0 {
                serial_write_bytes(&echo[..elen]);
            }
            let rlen = act.bytes_written();
            if rlen > 0 {
                smp_hw_tick_and_sync(sh);
                if reply[..rlen].starts_with(b"sync: ok ") || sh.db.tx_seq != last_sql_tx {
                    last_sql_tx = sh.db.tx_seq;
                    let _ = persist_shell_to_ahci(sh, boots);
                }
                serial_write_bytes(&reply[..rlen]);
            }
            match act {
                ShellAction::Continue(_) => {}
                ShellAction::Halt(_) => {
                    let _ = persist_shell_to_ahci(sh, boots);
                    // QEMU/Bochs ACPI PM1a_CNT S5 poweroff (0x604 <- 0x2000).
                    // SAFETY: Running at CPL=0 during shutdown; port 0x604 is the QEMU/Bochs ACPI PM1a_CNT register where writing 0x2000 asserts SLP_TYP=S5 | SLP_EN.
                    unsafe { outw(0x604, 0x2000) };
                    halt_forever();
                }
                ShellAction::Reboot(_) => {
                    let _ = persist_shell_to_ahci(sh, boots);
                    // 8042 keyboard controller CPU reset pulse (0x64 <- 0xFE).
                    // SAFETY: Running at CPL=0 during reboot; port 0x64 is the i8042 command register where 0xFE pulses the x86 CPU INIT/reset line.
                    unsafe { outb(0x64, 0xFE) };
                    halt_forever();
                }
            }
        } else if !did_io {
            // No network frames and no console input on this pass: put CPU 0 into
            // low-power HLT state until the Local APIC timer (0x40) or IPI (0x41) wakes it.
            smp_hw_idle_wait();
        }
    }
}

#[panic_handler]
pub(crate) fn panic(info: &PanicInfo) -> ! {
    serial_write_str("CUTTLE-TE PANIC: ");
    // Prefer the panic payload so hardware-path failures are diagnosable
    // from the QEMU serial log without a debugger.
    {
        use core::fmt::Write;
        struct Sw;
        impl Write for Sw {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                serial_write_str(s);
                Ok(())
            }
        }
        let _ = write!(Sw, "{}", info.message());
    }
    serial_write_str(" @ ");
    if let Some(loc) = info.location() {
        serial_write_str(loc.file());
    }
    serial_write_str("\n");
    halt_forever();
}

pub(crate) fn halt_forever() -> ! {
    loop {
        // SAFETY: `hlt` in ring 0 halts the CPU until the next interrupt without touching memory or flags.
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

// ============================================================
// RED-TEAM ATTACK HARNESS — see the call site above kernel_main's HALT
// ============================================================

/// Payload length the vulnerable service reads. Sized by disassembly +
/// fault forensics: saved return address is ~0x88 above buf, but the
/// kernel stack page ends ~0xD0 above the frame — writes past that
/// guard boundary fault mid-copy. 176 bytes covers the chain zone
/// (ret slot + ret-sled + win) while staying mapped.
#[cfg(not(cuttle_prod))]
pub(crate) const ATTACK_READ_LEN: usize = 176;

/// Blocking read of one byte from COM1 (16550 RBR, polled).
#[cfg(not(cuttle_prod))]
pub(crate) fn serial_read_byte() -> u8 {
    // SAFETY: Running at CPL=0; polling 0x3FD until bit 0 (DR) is set guarantees a received byte is latched in RBR (0x3F8).
    unsafe {
        while inb(COM1 + 5) & 0x01 == 0 {
            core::hint::spin_loop();
        }
        inb(COM1)
    }
}

/// Non-blocking check: is a byte waiting on COM1?
#[cfg(not(cuttle_prod))]
pub(crate) fn serial_data_ready() -> bool {
    // SAFETY: Running at CPL=0; port 0x3FD is the read-only COM1 Line Status Register and does not alias memory.
    unsafe { inb(COM1 + 5) & 0x01 != 0 }
}

/// Attack entry point: wait (bounded) for the "ATK!" magic on COM1, then
/// run the vulnerable service. The bound keeps normal boots fast — if
/// no attacker shows up, the kernel proceeds to HALT as usual.
#[cfg(not(cuttle_prod))]
pub(crate) fn attack_iface_pilot() {
    // Keep `attack_win` linked: nothing calls it legitimately (that is
    // the point — only a hijacked return address lands there), so
    // without a live reference the linker GCs it and the exploit driver
    // loses its symbol. An atomic store of its address defeats GC without `static mut`.
    static WIN_SINK: core::sync::atomic::AtomicUsize = core::sync::atomic::AtomicUsize::new(0);
    WIN_SINK.store(attack_win as *const () as usize, core::sync::atomic::Ordering::SeqCst);
    serial_write_str("ATK IFACE UP\n");
    let max_spins: u32 = if fw_cfg_select("opt/attack.bin").is_some() {
        20_000_000
    } else {
        50_000
    };
    let magic = *b"ATK!";
    let mut matched = 0usize;
    let mut spins = 0u32;
    while matched < magic.len() && spins < max_spins {
        if serial_data_ready() {
            let b = serial_read_byte();
            if b == magic[matched] {
                matched += 1;
            } else {
                matched = if b == magic[0] { 1 } else { 0 };
            }
        } else {
            spins += 1;
            core::hint::spin_loop();
        }
    }
    if matched < magic.len() {
        return; // no attacker this boot
    }
    serial_write_str("ATK ACCEPT\n");
    attack_vulnerable_service();
    // If the overflow did NOT hijack control (defended kernel, or the
    // chain missed), execution survives to here.
    serial_write_str("ATK SVC SURVIVED\n");
}

// --- fw_cfg payload channel (QEMU I/O ports 0x510/0x511) -------------
// The exploit bytes arrive via `-fw_cfg name=opt/attack.bin,file=...`:
// a real, attacker-controlled input channel that (unlike 16550 RX under
// TCG) cannot drop bytes. Serial remains the output/verdict channel.
pub(crate) const FW_CFG_CTL: u16 = 0x510;
pub(crate) const FW_CFG_DATA: u16 = 0x511;

/// Locate the fw_cfg file named `want` and return its selector. The
/// fw_cfg file directory (key 0x0019) is a BE u32 count followed by
/// entries {u32 size, u16 select, u16 reserved, char name[56]}.
pub(crate) fn fw_cfg_select(want: &str) -> Option<u16> {
    // SAFETY: Running at CPL=0; port 0x510 is the QEMU `fw_cfg` selector register and writing 0x0019 selects the read-only directory stream.
    unsafe { outw(FW_CFG_CTL, 0x0019) };
    // SAFETY: Running at CPL=0 after selecting key 0x0019 on port 0x510; reading port 0x511 streams the 4-byte big-endian directory entry count.
    let count = unsafe {
        u32::from_be_bytes([
            inb(FW_CFG_DATA),
            inb(FW_CFG_DATA),
            inb(FW_CFG_DATA),
            inb(FW_CFG_DATA),
        ])
    };
    let mut found: Option<u16> = None;
    for _ in 0..count.min(256) {
        // Entry: u32 size (BE), u16 select (BE), u16 reserved, name[56].
        let mut hdr = [0u8; 8];
        for b in hdr.iter_mut() {
            // SAFETY: Running at CPL=0 with key 0x0019 active; reading port 0x511 streams the 8-byte `(size, select, reserved)` header of the current entry.
            *b = unsafe { inb(FW_CFG_DATA) };
        }
        let select = u16::from_be_bytes([hdr[4], hdr[5]]);
        let mut name = [0u8; 56];
        for b in name.iter_mut() {
            // SAFETY: Running at CPL=0 with key 0x0019 active; reading port 0x511 streams the 56-byte NUL-padded filename of the current directory entry.
            *b = unsafe { inb(FW_CFG_DATA) };
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(56);
        if let Ok(n) = core::str::from_utf8(&name[..end]) {
            if n == want {
                found = Some(select);
            }
        }
    }
    found
}

/// The planted vulnerability: an unbounded fw_cfg read into a fixed
/// 64-byte stack buffer, with NO staging buffer — bytes flow from the
/// I/O port straight into the overflowing frame. (A first version
/// staged the payload in a second stack buffer; the compiler placed
/// that buffer above `buf` and it absorbed the overflow, leaving the
/// saved return address untouched. Learned from "ATK SVC SURVIVED".)
/// THIS FUNCTION IS INTENTIONALLY INSECURE — it exists to give the red
/// team a deterministic memory-corruption primitive.
#[inline(never)]
#[cfg(not(cuttle_prod))]
pub(crate) fn attack_vulnerable_service() {
    let Some(sel) = fw_cfg_select("opt/attack.bin") else {
        serial_write_str("ATK NO PAYLOAD FILE\n");
        return;
    };
    // Re-selecting rewinds the data cursor to offset 0.
    // SAFETY: Running at CPL=0; writing `sel` to port 0x510 latches the `opt/attack.bin` `fw_cfg` blob at stream offset 0.
    unsafe { outw(FW_CFG_CTL, sel) };
    let mut buf = [0u8; 64];
    let dst = buf.as_mut_ptr();
    for i in 0..ATTACK_READ_LEN {
        // SAFETY: Running at CPL=0 with `sel` latched on port 0x510; reading port 0x511 streams the next byte of the `fw_cfg` payload.
        let b = unsafe { inb(FW_CFG_DATA) };
        // SAFETY: INTENTIONAL RED-TEAM VULNERABILITY — writes `ATTACK_READ_LEN` (176) bytes into a
        // 64-byte stack buffer (`dst`) while remaining within the mapped kernel stack page to test
        // cross-variant ROP chain survival. Excluded from production (`#[cfg(not(cuttle_prod))]`).
        unsafe { dst.add(i).write_volatile(b) };
    }
    serial_write_str("ATK RD DONE\n");
    // Consume the (possibly overflowed) buffer so the write is not
    // optimized out; a correct kernel prints this and returns safely.
    let mut acc = 0u8;
    for &b in buf.iter() {
        acc = acc.wrapping_add(b);
    }
    if acc == 0xFF {
        serial_write_str("ATK SVC CK\n");
    }
}

/// The attacker's target: proof-of-control function. A successful ROP
/// chain lands here and prints the red-team verdict. `#[no_mangle]` so
/// the exploit driver can resolve its address from the ELF symbol
/// table — exactly what a real attacker does with a leaked symbol.
#[no_mangle]
#[inline(never)]
#[cfg(not(cuttle_prod))]
pub extern "C" fn attack_win() -> ! {
    serial_write_str("PWNED\n");
    halt_forever();
}
