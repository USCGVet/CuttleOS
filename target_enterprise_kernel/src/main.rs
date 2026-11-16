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
#![cfg_attr(
    not(test),
    deny(
        clippy::unwrap_used,
        clippy::expect_used,
        clippy::todo,
        clippy::unimplemented,
        clippy::unreachable,
        clippy::fallible_impl_from,
    )
)]
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
/// Firmware RSDP physical address reported by `bootloader_api::BootInfo`, if any.
pub(crate) static BOOT_RSDP_PHYS: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// IRQ-safe lock serializing shared kernel page-table frame allocation and PTE updates.
static PT_MOD_LOCK: spin::Mutex<()> = spin::Mutex::new(());
/// Global physical 4 KiB page-frame manager seeded from `BootInfo.memory_regions` (`E820` / `UEFI`).
static KERNEL_PHYS_MM: spin::Mutex<target_enterprise::phys_mm::KernelPhysFrameManager> =
    spin::Mutex::new(target_enterprise::phys_mm::KernelPhysFrameManager::empty());
/// Atomic flag indicating `KERNEL_PHYS_MM` has finished `BootInfo` memory-map ingestion.
static PHYS_MM_READY: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Execute `f` with local interrupts masked (`cli`) while holding `KERNEL_PHYS_MM`, restoring
/// the caller's `RFLAGS.IF` state upon return.
#[inline]
pub(crate) fn with_phys_mm_lock<R>(
    f: impl FnOnce(&mut target_enterprise::phys_mm::KernelPhysFrameManager) -> R,
) -> R {
    let saved_rflags: u64;
    // SAFETY: Reading RFLAGS and executing `cli` in Ring-0 prevents IRQ re-entrancy on `KERNEL_PHYS_MM`.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) saved_rflags,
            options(nomem, preserves_flags),
        );
    }
    let mut guard = KERNEL_PHYS_MM.lock();
    let res = f(&mut *guard);
    drop(guard);
    if (saved_rflags & (1 << 9)) != 0 {
        // SAFETY: Restoring `IF = 1` only when interrupts were previously enabled.
        unsafe {
            asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
    res
}

#[inline]
pub(crate) fn phys_mm_is_initialized() -> bool {
    PHYS_MM_READY.load(core::sync::atomic::Ordering::Acquire)
}

pub(crate) fn phys_mm_stats() -> target_enterprise::phys_mm::PhysMmStats {
    if !phys_mm_is_initialized() {
        return target_enterprise::phys_mm::PhysMmStats {
            total_usable_frames: 0,
            allocated_frames: 0,
            free_frames: 0,
            peak_allocated_frames: 0,
            total_alloc_ops: 0,
            total_free_ops: 0,
            high_mem_usable_frames: 0,
        };
    }
    with_phys_mm_lock(|pmm| pmm.stats())
}

/// Refresh `sh`'s live Ring-0 heap, slab, and physical-frame telemetry snapshot.
pub(crate) fn refresh_shell_mem_telemetry(sh: &mut target_enterprise::OsShell) {
    let hs = heap::stats();
    let ss = heap::slab_stats();
    let ps = phys_mm_stats();
    sh.set_mem_telemetry(target_enterprise::shell::MemTelemetry {
        heap_used_bytes: hs.used as u64,
        heap_free_bytes: hs.free as u64,
        heap_peak_bytes: heap::peak_used_bytes().max(ss.peak_used_bytes) as u64,
        slab_active: ss.active_slabs.min(u32::MAX as usize) as u32,
        slab_cached_empty: ss.empty_cached_slabs.min(u32::MAX as usize) as u32,
        large_spans: ss.active_large_spans.min(u32::MAX as usize) as u32,
        phys_free_frames: ps.free_frames as u64,
        phys_total_frames: ps.total_usable_frames as u64,
        alloc_failures: heap::alloc_failures(),
    });
}

/// Allocate one zero-scrubbed 4 KiB physical frame from `KERNEL_PHYS_MM`.
pub(crate) fn alloc_phys_frame_zeroed() -> Option<u64> {
    if !phys_mm_is_initialized() {
        return None;
    }
    let pa = with_phys_mm_lock(|pmm| pmm.alloc_frame())?;
    // SAFETY: `pa` is a freshly allocated usable 4 KiB RAM frame mapped at `pa_to_va(pa)`.
    let slice = unsafe { core::slice::from_raw_parts_mut(pa_to_va(pa), 4096) };
    target_enterprise::phys_mm::scrub_frame_bytes(slice);
    Some(pa)
}

/// Allocate `N` individual zero-scrubbed 4 KiB physical frames from `KERNEL_PHYS_MM`
/// all-or-nothing, rolling back any partial batch on out-of-memory.
pub(crate) fn alloc_phys_frames_zeroed_atomic<const N: usize>() -> Option<[u64; N]> {
    if !phys_mm_is_initialized() {
        return None;
    }
    let frames = with_phys_mm_lock(|pmm| pmm.alloc_frames_atomic::<N>().ok())?;
    let mut k = 0usize;
    while k < N {
        // SAFETY: `frames[k]` is a freshly allocated usable 4 KiB RAM frame mapped at `pa_to_va`.
        let slice = unsafe { core::slice::from_raw_parts_mut(pa_to_va(frames[k]), 4096) };
        target_enterprise::phys_mm::scrub_frame_bytes(slice);
        k += 1;
    }
    Some(frames)
}

/// Allocate `count` contiguous zero-scrubbed 4 KiB physical frames aligned to `align_frames`.
pub(crate) fn alloc_phys_contiguous_zeroed(count: usize, align_frames: usize) -> Option<u64> {
    if !phys_mm_is_initialized() {
        return None;
    }
    let pa = with_phys_mm_lock(|pmm| pmm.alloc_contiguous(count, align_frames).ok())?;
    let total_bytes = count.checked_mul(4096)?;
    // SAFETY: `[pa .. pa + count * 4096)` is a freshly allocated contiguous usable RAM span mapped at `pa_to_va(pa)`.
    let slice = unsafe { core::slice::from_raw_parts_mut(pa_to_va(pa), total_bytes) };
    target_enterprise::phys_mm::scrub_frame_bytes(slice);
    Some(pa)
}

/// Zero-scrub and release one 4 KiB physical frame previously obtained from `KERNEL_PHYS_MM`.
// SAFETY: Caller must guarantee `pa` is no longer referenced by any active page table, DMA ring, or slice.
pub(crate) unsafe fn free_phys_frame_scrubbed(
    pa: u64,
) -> Result<(), target_enterprise::phys_mm::PhysMmError> {
    with_phys_mm_lock(|pmm| {
        if !pmm.is_usable(pa) {
            return Err(target_enterprise::phys_mm::PhysMmError::ReservedOrInvalidFrame);
        }
        if !pmm.is_allocated(pa) {
            return Err(target_enterprise::phys_mm::PhysMmError::DoubleFree);
        }
        // SAFETY: `pa` was verified usable + allocated under `KERNEL_PHYS_MM` and caller ended all references.
        let slice = unsafe { core::slice::from_raw_parts_mut(pa_to_va(pa), 4096) };
        target_enterprise::phys_mm::scrub_frame_bytes(slice);
        pmm.free_frame(pa)
    })
}

/// Zero-scrub and release `count` contiguous 4 KiB physical frames starting at `base_pa`.
// SAFETY: Caller must guarantee none of the `count` frames are referenced by any active page table, DMA ring, or slice.
pub(crate) unsafe fn free_phys_contiguous_scrubbed(
    base_pa: u64,
    count: usize,
) -> Result<(), target_enterprise::phys_mm::PhysMmError> {
    if count == 0 {
        return Err(target_enterprise::phys_mm::PhysMmError::ZeroFrameCount);
    }
    let total_bytes = count
        .checked_mul(4096)
        .ok_or(target_enterprise::phys_mm::PhysMmError::ReservedOrInvalidFrame)?;
    with_phys_mm_lock(|pmm| {
        let mut k = 0usize;
        while k < count {
            let pa = base_pa
                .checked_add((k as u64) * 4096)
                .ok_or(target_enterprise::phys_mm::PhysMmError::ReservedOrInvalidFrame)?;
            if !pmm.is_usable(pa) {
                return Err(target_enterprise::phys_mm::PhysMmError::ReservedOrInvalidFrame);
            }
            if !pmm.is_allocated(pa) {
                return Err(target_enterprise::phys_mm::PhysMmError::DoubleFree);
            }
            k += 1;
        }
        // SAFETY: Every frame in `[base_pa .. base_pa + total_bytes)` is usable + allocated and unreferenced.
        let slice = unsafe { core::slice::from_raw_parts_mut(pa_to_va(base_pa), total_bytes) };
        target_enterprise::phys_mm::scrub_frame_bytes(slice);
        pmm.free_contiguous(base_pa, count)
    })
}

/// Execute `f` with local interrupts masked (`cli`) while holding `PT_MOD_LOCK`, restoring
/// the caller's `RFLAGS.IF` state upon return.
#[inline]
pub(crate) fn with_pt_lock<R>(f: impl FnOnce() -> R) -> R {
    let saved_rflags: u64;
    // SAFETY: Reading RFLAGS and executing `cli` in Ring-0 is privileged-safe and prevents IRQ re-entrancy.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) saved_rflags,
            options(nomem, preserves_flags),
        );
    }
    let guard = PT_MOD_LOCK.lock();
    let res = f();
    drop(guard);
    if (saved_rflags & (1 << 9)) != 0 {
        // SAFETY: Restoring `IF = 1` only when interrupts were previously enabled before acquiring `PT_MOD_LOCK`.
        unsafe {
            asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
    res
}

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
        let start = r.start.max(0x10_0000);
        let end = r.end.min(0x1_0000_0000); // stay below 4 GiB
        if end <= start {
            continue;
        }
        let Some(aligned) = start.checked_add(0xFFF).map(|v| v & !0xFFF) else {
            continue;
        };
        // 384 KiB (`DMA_WINDOW_BYTES = 0x6_0000`): disjoint device DMA apertures (`0x0_0000..0x3_7000`)
        // + dedicated 40-frame Page-Table pool (`0x3_8000..0x6_0000`).
        if aligned >= 0x10_0000
            && end.saturating_sub(aligned)
                >= target_enterprise::memory::dma_layout::DMA_WINDOW_BYTES
        {
            dma = aligned;
            break;
        }
    }
    PHYS_MAP_OFFSET.store(map_off, core::sync::atomic::Ordering::Relaxed);
    DMA_PHYS_BASE.store(dma, core::sync::atomic::Ordering::Relaxed);
    // Dedicated Page-Table frame pool (`0x3_8000 .. 0x6_0000`, 40 frames = 160 KiB),
    // strictly disjoint from VirtIO, AHCI, e1000, KPTI CR3, and NVMe DMA rings.
    let pt_next = if dma != 0 {
        dma + target_enterprise::memory::dma_layout::PT_POOL_START_OFF
    } else {
        0
    };
    PT_ALLOC_NEXT.store(pt_next, core::sync::atomic::Ordering::Relaxed);
    if let Some(rsdp) = boot.rsdp_addr.into_option() {
        BOOT_RSDP_PHYS.store(rsdp, core::sync::atomic::Ordering::Relaxed);
    }

    // Seed `KERNEL_PHYS_MM` dynamically from `boot.memory_regions` (BIOS E820 or UEFI GetMemoryMap),
    // excluding `< 1 MiB`, all non-usable firmware regions, and the `384 KiB` `DMA_WINDOW_BYTES` aperture.
    with_phys_mm_lock(|pmm| {
        use bootloader_api::info::MemoryRegionKind;
        pmm.begin_init();
        for r in boot.memory_regions.iter() {
            if r.kind == MemoryRegionKind::Usable && r.end > r.start {
                pmm.mark_usable_region(r.start, r.end);
            }
        }
        for r in boot.memory_regions.iter() {
            if r.kind != MemoryRegionKind::Usable && r.end > r.start {
                pmm.exclude_region(r.start, r.end);
            }
        }
        if dma != 0 {
            pmm.exclude_region(
                dma,
                dma.saturating_add(target_enterprise::memory::dma_layout::DMA_WINDOW_BYTES),
            );
        }
        pmm.finish_init();
    });
    if map_off != 0 {
        PHYS_MM_READY.store(true, core::sync::atomic::Ordering::Release);
    }
}

/// Virtual address for a guest-physical address in the physical memory map.
pub(crate) fn pa_to_va(phys: u64) -> *mut u8 {
    let off = phys_map_offset();
    (phys.wrapping_add(off)) as *mut u8
}

// ---- Page-table helpers for PCI MMIO BARs and dynamic Ring-3 / kernel mappings ----

pub(crate) const PTE_P: u64 = 1;
pub(crate) const PTE_W: u64 = 2;
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
pub(crate) unsafe fn alloc_pt_frame_locked() -> u64 {
    if let Some(pa) = alloc_phys_frame_zeroed() {
        return pa;
    }
    let base = dma_phys_base();
    let next = PT_ALLOC_NEXT.load(core::sync::atomic::Ordering::Acquire);
    let pool_start = base.checked_add(target_enterprise::memory::dma_layout::PT_POOL_START_OFF);
    let pool_end = base.checked_add(target_enterprise::memory::dma_layout::PT_POOL_END_OFF);
    let next_after = next.checked_add(0x1000);
    if base == 0
        || pool_start.is_none_or(|ps| next < ps)
        || match (next_after, pool_end) {
            (Some(na), Some(pe)) => na > pe,
            _ => true,
        }
    {
        panic!("AHCI_HW: PT frame pool exhausted");
    }
    let frame = next;
    if let Some(na) = next_after {
        PT_ALLOC_NEXT.store(na, core::sync::atomic::Ordering::Release);
    }
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

// SAFETY: Caller must ensure `frame` is an unreferenced 4 KiB page-table frame previously returned by `alloc_pt_frame*`.
#[allow(dead_code)]
pub(crate) unsafe fn free_pt_frame_locked(frame: u64) {
    let base = dma_phys_base();
    if base != 0
        && frame >= base + target_enterprise::memory::dma_layout::PT_POOL_START_OFF
        && frame < base + target_enterprise::memory::dma_layout::PT_POOL_END_OFF
    {
        // SAFETY: Static bootstrap PT pool frame mapped via `pa_to_va`; zero-scrub in place.
        let slice = unsafe { core::slice::from_raw_parts_mut(pa_to_va(frame), 4096) };
        target_enterprise::phys_mm::scrub_frame_bytes(slice);
        return;
    }
    // SAFETY: Caller verified `frame` is unreferenced and came from `KERNEL_PHYS_MM`.
    let _ = unsafe { free_phys_frame_scrubbed(frame) };
}

// SAFETY: Caller must ensure DMA_PHYS_BASE and PHYS_MAP_OFFSET are initialized from BootInfo.
pub(crate) unsafe fn alloc_pt_frame() -> u64 {
    with_pt_lock(|| unsafe { alloc_pt_frame_locked() })
}

// SAFETY: Caller must ensure `frame` is an unreferenced 4 KiB page-table frame previously returned by `alloc_pt_frame*`.
#[allow(dead_code)]
pub(crate) unsafe fn free_pt_frame(frame: u64) {
    with_pt_lock(|| unsafe { free_pt_frame_locked(frame) })
}

/// Walk the active 4-level `CR3` page table to resolve the guest-physical address backing
/// a mapped kernel virtual address (`4 KiB` page or `2 MiB` huge page).
// SAFETY: Caller must execute in Ring-0 after `set_phys_offset` initialized `PHYS_MAP_OFFSET`.
pub(crate) unsafe fn translate_kernel_va_to_pa(va: u64) -> Option<u64> {
    let indices = [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ];
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active PML4 physical address.
    let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let mut level = 0usize;
    while level < 3 {
        // SAFETY: `table` is a physical page-table frame mapped via `pa_to_va` and `indices[level] < 512`.
        let ent = unsafe { core::ptr::read_volatile(pa_to_va(table).cast::<u64>().add(indices[level])) };
        if (ent & PTE_P) == 0 {
            return None;
        }
        if (ent & PTE_PS) != 0 {
            return if level == 2 {
                Some((ent & 0x000F_FFFF_FFE0_0000) | (va & 0x001F_FFFF))
            } else if level == 1 {
                Some((ent & 0x000F_FFFF_C000_0000) | (va & 0x3FFF_FFFF))
            } else {
                None
            };
        }
        table = ent & PTE_ADDR_MASK;
        level += 1;
    }
    // SAFETY: `table` is the L1 page table mapped via `pa_to_va` and `indices[3] < 512`.
    let leaf = unsafe { core::ptr::read_volatile(pa_to_va(table).cast::<u64>().add(indices[3])) };
    if (leaf & PTE_P) == 0 {
        return None;
    }
    Some((leaf & PTE_ADDR_MASK) | (va & 0xFFF))
}

/// Ensure guest-physical firmware/ROM page `phys` is readable via `PHYS_MAP_OFFSET`
/// without altering existing RAM cacheability; maps unmapped pages as `Read-Only + NX`.
// SAFETY: Caller must execute in Ring-0 with active 4-level paging and initialized `PHYS_MAP_OFFSET`.
pub(crate) unsafe fn ensure_phys_ro_page(phys: u64) -> *const u8 {
    use target_enterprise::memory::kernel_guards::PTE_NX_BIT;
    let phys_page = phys & !0xFFFu64;
    let off = PHYS_MAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    if off == 0 {
        return core::ptr::null();
    }
    let va = phys_page.wrapping_add(off);
    let mut shootdown = false;
    with_pt_lock(|| {
        let indices = [
            ((va >> 39) & 0x1FF) as usize,
            ((va >> 30) & 0x1FF) as usize,
            ((va >> 21) & 0x1FF) as usize,
            ((va >> 12) & 0x1FF) as usize,
        ];
        // SAFETY: Running at CPL=0 under `PT_MOD_LOCK`.
        let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
        let mut level = 0usize;
        while level < 3 {
            // SAFETY: `table` is mapped via `pa_to_va` and `indices[level] < 512`.
            let ent_ptr = unsafe { pa_to_va(table).cast::<u64>().add(indices[level]) };
            // SAFETY: `ent_ptr` is an 8-byte-aligned PTE slot in mapped RAM.
            let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
            if ent & PTE_P == 0 {
                // SAFETY: Under `PT_MOD_LOCK` with initialized PT frame pool.
                let new_t = unsafe { alloc_pt_frame_locked() };
                // SAFETY: Writing intermediate PTE into mapped parent page table.
                unsafe {
                    core::ptr::write_volatile(ent_ptr, new_t | PTE_P | PTE_W);
                }
                table = new_t;
            } else if ent & PTE_PS != 0 {
                return;
            } else {
                table = ent & PTE_ADDR_MASK;
            }
            level += 1;
        }
        // SAFETY: `table` is the L1 page table and `indices[3] < 512`.
        let leaf = unsafe { pa_to_va(table).cast::<u64>().add(indices[3]) };
        // SAFETY: Reading L1 PTE in mapped RAM.
        let ent = unsafe { core::ptr::read_volatile(leaf) };
        if ent & PTE_P == 0 {
            let pte = phys_page | PTE_P | PTE_NX_BIT;
            // SAFETY: Installing Read-Only + NX leaf PTE and invalidating local TLB.
            unsafe {
                core::ptr::write_volatile(leaf, pte);
                asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
            }
            shootdown = true;
        }
    });
    if shootdown {
        smp_broadcast_tlb_shootdown();
    }
    va as *const u8
}

/// Ensure guest-physical `phys` (any offset in page) is reachable via
/// `PHYS_MAP_OFFSET`. Installs a 4 KiB uncached `RW + NX` PTE (`mmio_leaf_pte`)
/// when the bootloader did not map the page (typical for PCI MMIO BARs).
// SAFETY: Caller must pass a valid guest-physical MMIO or RAM address in ring 0 with active 4-level paging.
pub(crate) unsafe fn ensure_mmio_page(phys: u64) -> *mut u8 {
    use target_enterprise::memory::kernel_guards::{is_mmio_pte_compliant, mmio_leaf_pte};
    let phys_page = phys & !0xFFFu64;
    let off = PHYS_MAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    if off == 0 {
        panic!("AHCI_HW: no physical_memory_offset for MMIO");
    }
    let va = phys_page.wrapping_add(off);
    let mut shootdown = false;
    with_pt_lock(|| {
        let indices = [
            ((va >> 39) & 0x1FF) as usize,
            ((va >> 30) & 0x1FF) as usize,
            ((va >> 21) & 0x1FF) as usize,
            ((va >> 12) & 0x1FF) as usize,
        ];
        // SAFETY: Running in ring 0 under `PT_MOD_LOCK`; CR3 holds the active PML4 physical address.
        let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
        let mut level = 0usize;
        while level < 3 {
            // SAFETY: `table` is a physical page-table frame mapped via `pa_to_va`, and `indices[level] < 512`.
            let ent_ptr = unsafe { pa_to_va(table).cast::<u64>().add(indices[level]) };
            // SAFETY: `ent_ptr` is 8-byte aligned and points to a valid page-table entry in mapped physical memory.
            let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
            if ent & PTE_P == 0 {
                // SAFETY: Running at CPL=0 under `PT_MOD_LOCK` with initialized `PT_ALLOC_NEXT`.
                let new_t = unsafe { alloc_pt_frame_locked() };
                // SAFETY: `ent_ptr` is an 8-byte-aligned PTE slot in the mapped parent page table.
                unsafe {
                    core::ptr::write_volatile(ent_ptr, new_t | PTE_P | PTE_W);
                }
                table = new_t;
            } else if ent & PTE_PS != 0 {
                return;
            } else {
                table = ent & PTE_ADDR_MASK;
            }
            level += 1;
        }
        // SAFETY: `table` is the L1 page-table frame and `indices[3] < 512`.
        let leaf = unsafe { pa_to_va(table).cast::<u64>().add(indices[3]) };
        // SAFETY: `leaf` is a valid L1 PTE pointer in mapped physical memory.
        let ent = unsafe { core::ptr::read_volatile(leaf) };
        if !is_mmio_pte_compliant(ent) {
            let pte = mmio_leaf_pte(phys_page);
            // SAFETY: `leaf` is an 8-byte-aligned L1 PTE pointer in mapped physical memory and `invlpg` is valid at CPL=0.
            unsafe {
                core::ptr::write_volatile(leaf, pte);
                asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
            }
            shootdown = true;
        }
    });
    if shootdown {
        smp_broadcast_tlb_shootdown();
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
    if CONSOLE_LOOP_ACTIVE.load(core::sync::atomic::Ordering::Relaxed) {
        serial_rx_pump();
    }
    // SAFETY: Running at CPL=0 after `serial_init`; port 0x3FD is COM1 LSR and port 0x3F8 is COM1 THR once LSR.THRE confirms FIFO space (bounded so a wedged UART never hangs Ring-0).
    unsafe {
        let mut spins = 0u32;
        while inb(COM1 + 5) & LSR_THRE == 0 && spins < 1_000_000 {
            if (spins & 0x3F) == 0
                && CONSOLE_LOOP_ACTIVE.load(core::sync::atomic::Ordering::Relaxed)
            {
                serial_rx_pump();
            }
            core::hint::spin_loop();
            spins += 1;
        }
        outb(COM1, b);
    }
    fb_write_byte(b);
}

/// Console bytes received while the kernel was busy and could not get
/// back to its input poll.
///
/// The UART is polled, and its own FIFO holds 16 bytes. A state commit keeps
/// the kernel in disk waits for far longer than 16 characters take to
/// arrive, so without this buffer everything typed or pasted during a commit
/// was dropped.
pub(crate) struct SerialRxRing {
    buf: [u8; 2048],
    head: usize,
    len: usize,
    /// Bytes discarded because the ring was full.
    pub(crate) overruns: u64,
}

impl SerialRxRing {
    const fn new() -> Self {
        Self {
            buf: [0u8; 2048],
            head: 0,
            len: 0,
            overruns: 0,
        }
    }

    fn push(&mut self, b: u8) {
        if self.len == self.buf.len() {
            self.overruns = self.overruns.wrapping_add(1);
            return;
        }
        let tail = (self.head + self.len) % self.buf.len();
        self.buf[tail] = b;
        self.len += 1;
    }

    fn pop(&mut self) -> Option<u8> {
        if self.len == 0 {
            return None;
        }
        let b = self.buf[self.head];
        self.head = (self.head + 1) % self.buf.len();
        self.len -= 1;
        Some(b)
    }
}

static SERIAL_RX_RING: spin::Mutex<SerialRxRing> = spin::Mutex::new(SerialRxRing::new());
/// Set to `true` once `live_os_console_loop` begins servicing the interactive console.
pub(crate) static CONSOLE_LOOP_ACTIVE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Move every byte waiting in the COM1 receive FIFO into [`SERIAL_RX_RING`].
/// Cheap when nothing is waiting; called from the main loop and from inside
/// long device waits. Only the boot CPU reads the console.
pub(crate) fn serial_rx_pump() {
    if !CONSOLE_LOOP_ACTIVE.load(core::sync::atomic::Ordering::Relaxed) {
        return;
    }
    let Some(mut ring) = SERIAL_RX_RING.try_lock() else {
        return;
    };
    // SAFETY: Running at CPL=0; port 0x3FD is the COM1 Line Status Register and 0x3F8 the
    // receive buffer, read only while LSR bit 0 reports a byte ready.
    unsafe {
        let mut budget = 64u32;
        while budget > 0 && inb(COM1 + 5) & 0x01 != 0 {
            ring.push(inb(COM1));
            budget -= 1;
        }
    }
}

/// True if [`SERIAL_RX_RING`] or the hardware `COM1` receive buffer holds unread bytes.
pub(crate) fn serial_rx_has_pending() -> bool {
    serial_rx_pump();
    SERIAL_RX_RING.try_lock().is_some_and(|r| r.len > 0)
}

/// Next console byte, if one has arrived.
pub(crate) fn serial_rx_take() -> Option<u8> {
    serial_rx_pump();
    SERIAL_RX_RING.lock().pop()
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

/// Write the first `n` bytes of `bytes` as lowercase hex into `out`,
/// bounded by `out.len() / 2` so short buffers never panic.
pub(crate) fn hex_encode(bytes: &[u8], n: usize, out: &mut [u8]) -> usize {
    target_enterprise::memory::kernel_guards::hex_encode_bounded(bytes, n, out)
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
/// written (`0` if `out` cannot hold the digits).
pub(crate) fn dec_u64(val: u64, out: &mut [u8]) -> usize {
    target_enterprise::memory::kernel_guards::dec_u64_bounded(val, out)
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
mod proc_hw;
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
pub(crate) use proc_hw::*;
pub(crate) use provisioning::*;
pub(crate) use smp_hw::*;

// ============================================================
// Entry + panic handler + halt
// ============================================================

pub(crate) fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    set_phys_offset(boot_info); // seed PHYS_MAP_OFFSET + KERNEL_PHYS_MM from BootInfo first
    heap::init(); // initialize slab + fallback heap before anything allocates (rustls on port 443)
    // Enforce hardware NXE + WP + SMEP + SMAP + UMIP + FSGSBASE and install the early BSP
    // GDT/TSS (`IST1` for `#DF`, `IST2` for `#MC`/`NMI`) + 256-vector `RUNTIME_IDT` BEFORE
    // touching device MMIO, serial I/O, or boot banners so no early CPU fault can triple-fault.
    // SAFETY: Running at CPL=0 in 64-bit Long Mode before any Ring-3 or untrusted code runs.
    unsafe {
        enable_cpu_memory_protections();
    }
    init_early_bsp_gdt_idt_tss();
    fb_register(boot_info);
    serial_init();
    if !verify_early_bsp_idt_active() {
        panic!("EARLY_IDT: BSP GDT/TSS/IDT failed early boot verification");
    }
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
    banner_tcp_ipv6_triad();
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
    banner_tpm_nv_rollback();
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
    // Restore the node's durable state (or seed defaults) before anything
    // below can serve a request against it.
    shell_store_boot();
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
    // Live physical frame manager (>128 PT frames exceeding legacy 40-frame limit) + size-class slab proof.
    #[cfg(not(cuttle_prod))]
    banner_phys_mm_slab();
    // Live multi-segment Ring-3 ELF64 process runtime, SYSCALL/int 0x80, 0x50 preemption, SMP, IPC & fault isolation proof.
    #[cfg(not(cuttle_prod))]
    banner_ring3_elf_multiprocess();
    // Live PCI MSI/MSI-X (0x45 block, 0x46 net) + IoCompletionRing + 8-slot pipelined TX proof.
    #[cfg(not(cuttle_prod))]
    banner_async_dma_irq();
    // Live encrypted Copy-on-Write + CWAL PagedBlockStore incremental commit + Merkle inclusion proof.
    #[cfg(not(cuttle_prod))]
    banner_paged_store();

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
/// - Live AHCI disk persistence (`LBA 1040..=1149`) on `sync`, SQL mutations, `halt`, and `reboot`
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
        svc.last_auth_seq = sh.auth_seq;
        svc.last_http_login_seq = sh.http_login_seq;
        svc.last_triad_rpc_seq = sh.triad_rpc_seq;
        svc.triad_min_epoch = sh.triad_min_epoch;
        enable_https(svc, vn.mac);
    }
    // Scrub the root 32-byte device master key from `.bss` before serving live untrusted traffic.
    scrub_cached_master_key();
    let mut net_rx: u64 = 0;
    let mut net_tx: u64 = 0;

    smp_hw_tick_and_sync(sh);
    smp_hw_enable_bsp_timer();
    let mut last_rto_irq: u64 = read_monotonic_timer_ticks();
    svc.set_timer_hz(read_calibrated_irqs_per_sec());
    // Switch COM1 to 115,200 baud (`divisor = 1`) before activating interactive console polling
    // (after all boot banners and `attack_iface_pilot` have completed) so 16550A THR/RBR shift
    // 3x faster without disturbing any boot-banner timing or FIFO state.
    // SAFETY: Running at CPL=0; ports `0x3F8..=0x3FD` are the architectural COM1 16550A registers.
    unsafe {
        let mut spins = 0u32;
        while (inb(COM1 + 5) & 0x40) == 0 && spins < 500_000 {
            core::hint::spin_loop();
            spins += 1;
        }
        outb(COM1 + 3, 0x80);
        outb(COM1 + 0, 0x01);
        outb(COM1 + 1, 0x00);
        outb(COM1 + 3, 0x03);
    }
    CONSOLE_LOOP_ACTIVE.store(true, core::sync::atomic::Ordering::Release);
    fb_console_start();
    serial_write_str("Cuttle Enterprise OS interactive shell ready.\n");
    serial_write_str("Web UI: http://127.0.0.1:18080/app | SQL: http://127.0.0.1:18080/sql\n");
    serial_write_bytes(SHELL_PROMPT);

    let mut echo = [0u8; 32];
    let mut reply = [0u8; 1024];
    let mut console_grace_tsc: u64 = crate::smp_hw::tsc_deadline_ms(2_000);
    #[cfg(not(cuttle_prod))]
    let mut selftest_line = [0u8; 32];
    #[cfg(not(cuttle_prod))]
    let mut selftest_len = 0usize;

    loop {
        let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        let mut did_io = false;

        // 0. Drain live VirtIO-Net interface for HTTP (:80), TLS 1.3 (:443), UDP (:8080/:8081), ICMP, and ARP.
        //    Bounded to 16 frames per pass so continuous inbound traffic cannot starve serial/PS2 console or RTO ticks.
        if let Some(vn) = vnet_opt.as_mut() {
            let now_irq = read_monotonic_timer_ticks();
            if now_irq > last_rto_irq {
                let elapsed_irqs = (now_irq - last_rto_irq).min(64);
                last_rto_irq = now_irq;
                let mut step = 0u64;
                while step < elapsed_irqs {
                    serial_rx_pump();
                    let mut rto_rep = CONSOLE_NET_REPLIES.lock();
                    rto_rep.clear();
                    let _ = svc.tick_tcp_rto_with_replies(&mut *rto_rep);
                    let mut ri = 0usize;
                    while ri < rto_rep.len() {
                        if let Some(r) = rto_rep.get(ri) {
                            if vnet_tx(vn, r) {
                                net_tx = net_tx.wrapping_add(1);
                            }
                        }
                        ri += 1;
                    }
                    step += 1;
                }
            }
            const MAX_RX_FRAMES_PER_PASS: usize = 16;
            let mut rx_pass = 0usize;
            let mut f_guard = CONSOLE_NET_FRAME.lock();
            while rx_pass < MAX_RX_FRAMES_PER_PASS {
                serial_rx_pump();
                let Some((flen, head_id)) = vnet_rx(vn, &mut *f_guard) else {
                    break;
                };
                rx_pass += 1;
                did_io = true;
                net_rx = net_rx.wrapping_add(1);
                if flen >= 14 {
                    smp_hw_tick_and_sync(sh);
                    let mut rep_guard = CONSOLE_NET_REPLIES.lock();
                    rep_guard.clear();
                    svc.handle_frame_with_shell(&f_guard[..flen], boots, sh, &mut *rep_guard);
                    // Durable first, then acknowledged: whatever this frame
                    // changed is on disk before any reply leaves the node.
                    persist_shell_if_changed(sh, false);
                    let mut ri = 0usize;
                    while ri < rep_guard.len() {
                        if let Some(r) = rep_guard.get(ri) {
                            if vnet_tx(vn, r) {
                                net_tx = net_tx.wrapping_add(1);
                            }
                        }
                        ri += 1;
                    }
                }
                vnet_rx_recycle(vn, head_id);
            }
        }

        // Drain up to 64 ready console bytes per outer pass so multi-character
        // commands on COM1 or PS/2 are never starved or dropped by a 16-byte
        // 16550A UART FIFO overflow during continuous inbound network floods.
        const MAX_CONSOLE_BYTES_PER_PASS: usize = 64;
        let mut con_pass = 0usize;
        while con_pass < MAX_CONSOLE_BYTES_PER_PASS {
            let mut maybe_byte: Option<u8> = None;

            // 1. COM1: bytes buffered during a commit or network RX pass first,
            //    then whatever the UART holds now.
            if let Some(b) = serial_rx_take() {
                maybe_byte = Some(b);
            } else {
                // 2. Poll PS/2 8042 status port (bit 0 = output buffer full; bit 5 = AUXB mouse; bits 6..7 = error).
                // SAFETY: Running at CPL=0; port 0x64 is the read-only i8042 PS/2 controller status register and reading it has no memory side effects.
                let status = unsafe { inb(0x64) };
                if (status & 0x01) != 0 {
                    // SAFETY: 8042 status bit 0 confirmed an output byte is waiting at port 0x60 (drain even if AUXB/error).
                    let sc = unsafe { inb(0x60) };
                    if target_enterprise::memory::kernel_guards::ps2_kbd_byte_ready(status) {
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
            }

            let Some(b) = maybe_byte else {
                break;
            };
            did_io = true;
            con_pass += 1;
            console_grace_tsc = crate::smp_hw::tsc_deadline_ms(2_000);

            #[cfg(not(cuttle_prod))]
            {
                if b == b'\n' || b == b'\r' {
                    if &selftest_line[..selftest_len] == b"__selftest_ud2_fault" {
                        // Deliberate Ring-0 `#UD` (`vec=6`) trap for `qemu_smoke` verification of
                        // `ISR_CPU_EXC_STUBS` + `kernel_cpu_exception_handler` + `CTTLPENC` crash dump.
                        // Strictly absent from `--prod` (`#[cfg(not(cuttle_prod))]`).
                        // SAFETY: Intentional Ring-0 `#UD` exception during non-prod QEMU test.
                        unsafe {
                            asm!("ud2", options(noreturn));
                        }
                    }
                    selftest_len = 0;
                } else if b == 0x08 || b == 0x7F {
                    selftest_len = selftest_len.saturating_sub(1);
                } else if selftest_len < selftest_line.len() {
                    selftest_line[selftest_len] = b;
                    selftest_len += 1;
                }
            }
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
                // Durable first, then acknowledged. `sync` forces a commit
                // (a no-op on disk if nothing changed), so its "ok" is only
                // printed once the state is known to be saved.
                persist_shell_if_changed(sh, reply[..rlen].starts_with(b"sync: ok "));
                serial_write_bytes(&reply[..rlen]);
                console_grace_tsc = crate::smp_hw::tsc_deadline_ms(2_000);
            }
            match act {
                ShellAction::Continue(_) => {}
                ShellAction::Halt(_) => {
                    persist_shell_if_changed(sh, true);
                    // QEMU/Bochs ACPI PM1a_CNT S5 poweroff (0x604 <- 0x2000).
                    // SAFETY: Running at CPL=0 during shutdown; port 0x604 is the QEMU/Bochs ACPI PM1a_CNT register where writing 0x2000 asserts SLP_TYP=S5 | SLP_EN.
                    unsafe { outw(0x604, 0x2000) };
                    halt_forever();
                }
                ShellAction::Reboot(_) => {
                    persist_shell_if_changed(sh, true);
                    // 8042 keyboard controller CPU reset pulse (0x64 <- 0xFE).
                    // SAFETY: Running at CPL=0 during reboot; port 0x64 is the i8042 command register where 0xFE pulses the x86 CPU INIT/reset line.
                    unsafe { outb(0x64, 0xFE) };
                    halt_forever();
                }
            }
        }

        if !did_io {
            if has_ready_processes() {
                let _ = run_next_ready_process_quantum(0, 50_000);
            } else if console_grace_tsc != 0 && !crate::smp_hw::tsc_past_deadline(console_grace_tsc) {
                // Keep polling COM1 at sub-microsecond latency while an interactive/pasted
                // command stream is actively arriving so 16550A's 16-byte RX FIFO never overruns.
                serial_rx_pump();
                core::hint::spin_loop();
            } else {
                console_grace_tsc = 0;
                // No network frames, no console input, and no runnable Ring-3 processes:
                // put CPU 0 into low-power HLT state until Local APIC timer (0x40), MSI/MSI-X (0x45/0x46), or IPI wakes it.
                smp_hw_idle_wait();
            }
        }
    }
}

/// Disjoint AHCI LBA partition (`1536..1568`, 16 KiB) reserved for forensic `CTTLPAN1`
/// crash dumps so emergency dumps never overlap continuity/shell/SQL (`LBA 0..1100`).
pub(crate) const AHCI_PANIC_DUMP_LBA: u64 = 1536;

struct PanicDumpScratch(core::cell::UnsafeCell<[u8; cuttle_contracts::CRASH_DUMP_BYTES]>);
// SAFETY: Accessed exclusively inside `write_emergency_crash_dump_with_scratch` after winning the one-shot
// `!target_enterprise::panic_dump::set_dumped()` atomic latch and halting peer APs.
unsafe impl Sync for PanicDumpScratch {}

static PANIC_DUMP_SCRATCH: PanicDumpScratch =
    PanicDumpScratch(core::cell::UnsafeCell::new([0u8; cuttle_contracts::CRASH_DUMP_BYTES]));

struct EmergencyAhciCrashSink;

impl target_enterprise::panic_dump::SectorSink for EmergencyAhciCrashSink {
    type Error = cuttle_contracts::CrashDumpError;

    fn write_sector(
        &mut self,
        lba: u64,
        data: &[u8; 512],
    ) -> Result<(), cuttle_contracts::CrashDumpError> {
        let rel = lba.saturating_sub(DUMP_START_LBA);
        if rel >= 32 {
            return Err(cuttle_contracts::CrashDumpError::LayoutOverflow);
        }
        if try_write_ahci_sector_emergency(AHCI_PANIC_DUMP_LBA + rel, data)
            || try_write_nvme_sector_emergency(AHCI_PANIC_DUMP_LBA + rel, data)
        {
            Ok(())
        } else {
            Err(cuttle_contracts::CrashDumpError::LayoutOverflow)
        }
    }
}

/// Shared emergency crash-dump writer used by both `#[panic_handler]` and
/// `smp_hw::kernel_cpu_exception_handler` once `!target_enterprise::panic_dump::set_dumped()`
/// has been won by the faulting CPU.
pub(crate) fn write_emergency_crash_dump_with_scratch(
    loc_str: &str,
    msg_str: &str,
    regs: &[u64; cuttle_contracts::CRASH_REG_COUNT],
    rip_val: u64,
    tsc_val: u64,
    dump_aead_key: Option<&[u8; 32]>,
) {
    let bt = [rip_val];
    let ctx = CrashContext {
        wall_unix: 0,
        tsc: tsc_val,
        panic_loc: loc_str,
        message: msg_str,
        registers: regs,
        backtrace: &bt,
        kmsg: &[],
    };
    let mut sink = EmergencyAhciCrashSink;
    // SAFETY: Caller won the one-shot `target_enterprise::panic_dump::set_dumped()` latch after halting peer APs.
    let dump_buf = unsafe { &mut *PANIC_DUMP_SCRATCH.0.get() };
    let mut nonce = [0u8; 12];
    nonce[0..8].copy_from_slice(&tsc_val.to_le_bytes());
    nonce[8..12].copy_from_slice(&(regs[0] as u32).to_le_bytes());
    let _ = PanicDumpImpl::dump_encrypted_to_sink(&ctx, dump_aead_key, &nonce, dump_buf, &mut sink);
}

#[panic_handler]
pub(crate) fn panic(info: &PanicInfo) -> ! {
    // 1. Mask interrupts immediately on the faulting CPU.
    // SAFETY: `cli` in Ring-0 masks maskable external interrupts during crash containment.
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }

    // 2. One-shot atomic re-entry guard (`set_dumped()` returns `false` on first entry).
    //    On first entry stop the other CPUs and wipe runtime secrets in `.bss` before
    //    anything that can block, keeping only a transient stack copy of the crash-dump
    //    AEAD subkey (zeroized immediately after `dump_encrypted_to_sink`).
    let first_entry = !target_enterprise::panic_dump::set_dumped();
    let mut dump_aead_key = if first_entry {
        smp_broadcast_panic_halt();
        take_emergency_dump_aead_key_and_scrub()
    } else {
        None
    };

    // 3. Report. The dump below needs MMIO and the disk, either of which may
    //    be the reason for the panic; the message must not depend on them.
    serial_write_str("CUTTLE-TE PANIC: ");
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
    serial_write_str("
");

    // 4. Commit a forensic CRC32-C-sealed `CTTLPAN1` dump to AHCI `LBA 1536..1568`
    //    using `.bss` scratch (`PANIC_DUMP_SCRATCH`).
    if first_entry {
        let rip_val: u64;
        let rsp_val: u64;
        let tsc_lo: u32;
        let tsc_hi: u32;
        // SAFETY: Reading RIP/RSP/RDTSC in Ring-0 has no memory side effects.
        unsafe {
            asm!(
                "lea {rip}, [rip + 0]",
                "mov {rsp}, rsp",
                "rdtsc",
                rip = out(reg) rip_val,
                rsp = out(reg) rsp_val,
                out("eax") tsc_lo,
                out("edx") tsc_hi,
                options(nomem, nostack, preserves_flags),
            );
        }
        let mut msg_buf = [0u8; 96];
        let mut msg_len = 0usize;
        {
            use core::fmt::Write;
            struct BufWriter<'a> {
                buf: &'a mut [u8],
                pos: &'a mut usize,
            }
            impl<'a> Write for BufWriter<'a> {
                fn write_str(&mut self, s: &str) -> core::fmt::Result {
                    let bytes = s.as_bytes();
                    let rem = self.buf.len().saturating_sub(*self.pos);
                    let n = bytes.len().min(rem);
                    self.buf[*self.pos..*self.pos + n].copy_from_slice(&bytes[..n]);
                    *self.pos += n;
                    Ok(())
                }
            }
            let _ = write!(
                BufWriter {
                    buf: &mut msg_buf,
                    pos: &mut msg_len,
                },
                "{}",
                info.message()
            );
        }
        let loc_str = info.location().map(|l| l.file()).unwrap_or("kernel");
        let msg_str = core::str::from_utf8(&msg_buf[..msg_len]).unwrap_or("panic");
        let mut regs = [0u64; cuttle_contracts::CRASH_REG_COUNT];
        regs[0] = read_current_lapic_id_safe() as u64;
        regs[7] = rsp_val;
        regs[16] = rip_val;
        write_emergency_crash_dump_with_scratch(
            loc_str,
            msg_str,
            &regs,
            rip_val,
            ((tsc_hi as u64) << 32) | (tsc_lo as u64),
            dump_aead_key.as_ref(),
        );
        if let Some(ref mut key) = dump_aead_key {
            target_enterprise::durable_seal::zeroize_secret_bytes(key);
        }
    }

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

/// Locate the fw_cfg file named `want` and return its `(selector, size)`.
/// The fw_cfg file directory (key 0x0019) is a BE u32 count followed by
/// entries {u32 size, u16 select, u16 reserved, char name[56]}.
pub(crate) fn fw_cfg_select(want: &str) -> Option<(u16, u32)> {
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
    let mut found: Option<(u16, u32)> = None;
    for _ in 0..count.min(256) {
        // Entry: u32 size (BE), u16 select (BE), u16 reserved, name[56].
        let mut hdr = [0u8; 8];
        for b in hdr.iter_mut() {
            // SAFETY: Running at CPL=0 with key 0x0019 active; reading port 0x511 streams the 8-byte `(size, select, reserved)` header of the current entry.
            *b = unsafe { inb(FW_CFG_DATA) };
        }
        let size = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
        let select = u16::from_be_bytes([hdr[4], hdr[5]]);
        let mut name = [0u8; 56];
        for b in name.iter_mut() {
            // SAFETY: Running at CPL=0 with key 0x0019 active; reading port 0x511 streams the 56-byte NUL-padded filename of the current directory entry.
            *b = unsafe { inb(FW_CFG_DATA) };
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(56);
        if let Ok(n) = core::str::from_utf8(&name[..end]) {
            if n == want {
                found = Some((select, size));
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
    let Some((sel, _)) = fw_cfg_select("opt/attack.bin") else {
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
