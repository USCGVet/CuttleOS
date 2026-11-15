//! Enterprise kernel allocator: segregated size-class slab + dynamic physical-page spans
//! with an IRQ-safe spinlock and an `8 MiB` static `.bss` emergency fallback arena.
//!
//! - **Primary path**: [`target_enterprise::slab_alloc::KernelSlabAllocator`] (`32 B ..= 4096 B`
//!   out-of-line bitmap slabs + multi-page contiguous spans `> 4096 B`) backed directly by
//!   [`crate::alloc_phys_contiguous_zeroed`] / [`crate::free_phys_contiguous_scrubbed`] over
//!   all usable physical RAM discovered in `BootInfo.memory_regions`.
//! - **Zero-scrub on free**: every freed slab slot and reclaimed physical page is scrubbed
//!   with `0x00` + compiler fence before reuse so TLS/session/user secrets never linger in free memory.
//! - **Overflow / early-boot fallback**: an `8 MiB` `.bss` `linked_list_allocator::Heap` absorbs
//!   any early pre-`BootInfo` allocation or descriptor-table overflow, identified in `O(1)`
//!   by pointer range check `[fallback_start .. fallback_end)`.
//! - **IRQ-safe locking**: `with_heap_lock` masks local interrupts (`cli`) before acquiring
//!   `HEAP_LOCK`, maintaining the strict lock hierarchy `HEAP_LOCK -> PHYS_MM_LOCK`.

use core::alloc::{GlobalAlloc, Layout};
use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use linked_list_allocator::Heap as FallbackHeap;
use target_enterprise::phys_mm::scrub_frame_bytes;
use target_enterprise::slab_alloc::{KernelSlabAllocator, PageBackend, SlabStats};

/// `8 MiB` static `.bss` fallback arena (adds zero bytes to the on-disk kernel ELF).
pub const HEAP_SIZE: usize = 8 * 1024 * 1024;

/// `512 KiB` emergency Ring-0 reserve withheld from untrusted network/TLS connection floods.
pub const KERNEL_HEAP_RESERVE_BYTES: usize = 512 * 1024;

#[repr(C, align(4096))]
struct HeapRegion([u8; HEAP_SIZE]);

struct SyncHeapRegion(UnsafeCell<HeapRegion>);
// SAFETY: Handed once to `HEAP_STATE` inside `init()` gated by `HEAP_INITIALIZED` under `HEAP_LOCK`.
unsafe impl Sync for SyncHeapRegion {}

static FALLBACK_REGION: SyncHeapRegion = SyncHeapRegion(UnsafeCell::new(HeapRegion([0; HEAP_SIZE])));
static FALLBACK_START: AtomicUsize = AtomicUsize::new(0);
static FALLBACK_END: AtomicUsize = AtomicUsize::new(0);
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);
static PEAK_USED_BYTES: AtomicUsize = AtomicUsize::new(0);
static ALLOC_FAILURES: AtomicU64 = AtomicU64::new(0);

struct HeapInner {
    slab: KernelSlabAllocator,
    fallback: FallbackHeap,
}

impl HeapInner {
    const fn new() -> Self {
        Self {
            slab: KernelSlabAllocator::empty(),
            fallback: FallbackHeap::empty(),
        }
    }
}

static HEAP_LOCK: spin::Mutex<HeapInner> = spin::Mutex::new(HeapInner::new());

/// Execute `f` under `HEAP_LOCK` with local maskable interrupts disabled (`cli`),
/// restoring the caller's `RFLAGS.IF` bit upon return.
#[inline]
fn with_heap_lock<R>(f: impl FnOnce(&mut HeapInner) -> R) -> R {
    let saved_rflags: u64;
    // SAFETY: Reading RFLAGS and executing `cli` in Ring-0 prevents IRQ re-entrancy on `HEAP_LOCK`.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) saved_rflags,
            options(nomem, preserves_flags),
        );
    }
    let mut guard = HEAP_LOCK.lock();
    let res = f(&mut *guard);
    drop(guard);
    if (saved_rflags & (1 << 9)) != 0 {
        // SAFETY: Restoring `IF = 1` only when interrupts were enabled prior to `with_heap_lock`.
        unsafe {
            asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
    res
}

/// Physical-frame [`PageBackend`] bridging `KernelSlabAllocator` to `KERNEL_PHYS_MM`.
struct KernelPhysBackend;

impl PageBackend for KernelPhysBackend {
    fn alloc_pages(&mut self, count: usize, align_pages: usize) -> Option<usize> {
        let pa = crate::alloc_phys_contiguous_zeroed(count, align_pages)?;
        Some(crate::pa_to_va(pa) as usize)
    }

    fn free_pages(&mut self, base_va: usize, count: usize) {
        let off = crate::phys_map_offset() as usize;
        if off == 0 || base_va < off {
            return;
        }
        let base_pa = (base_va - off) as u64;
        // SAFETY: `base_va` was allocated exclusively by `alloc_pages` for `KernelSlabAllocator`
        // and all slots within the span have been freed prior to `free_pages`.
        let _ = unsafe { crate::free_phys_contiguous_scrubbed(base_pa, count) };
    }

    fn free_page_count(&self) -> usize {
        crate::phys_mm_stats().free_frames
    }
}

struct EnterpriseGlobalAlloc;

// SAFETY: `EnterpriseGlobalAlloc` serializes all mutations through IRQ-safe `with_heap_lock`,
// hands out naturally aligned non-overlapping regions from `KernelSlabAllocator` (backed by
// zeroed 4 KiB physical frames) or `FallbackHeap`, and zero-scrubs freed slots before reuse.
unsafe impl GlobalAlloc for EnterpriseGlobalAlloc {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !HEAP_INITIALIZED.load(Ordering::Acquire) {
            ALLOC_FAILURES.fetch_add(1, Ordering::Relaxed);
            return ptr::null_mut();
        }
        with_heap_lock(|inner| {
            let mut backend = KernelPhysBackend;
            if crate::phys_mm_is_initialized() {
                if let Some(va) = inner.slab.alloc(layout.size(), layout.align(), &mut backend) {
                    let cur = inner
                        .slab
                        .stats()
                        .used_bytes
                        .saturating_add(inner.fallback.used());
                    PEAK_USED_BYTES.fetch_max(cur, Ordering::Relaxed);
                    return va as *mut u8;
                }
            }
            match inner.fallback.allocate_first_fit(layout) {
                Ok(nn) => {
                    let cur = inner
                        .slab
                        .stats()
                        .used_bytes
                        .saturating_add(inner.fallback.used());
                    PEAK_USED_BYTES.fetch_max(cur, Ordering::Relaxed);
                    nn.as_ptr()
                }
                Err(()) => {
                    ALLOC_FAILURES.fetch_add(1, Ordering::Relaxed);
                    ptr::null_mut()
                }
            }
        })
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() {
            return;
        }
        let addr = ptr as usize;
        let fb_start = FALLBACK_START.load(Ordering::Relaxed);
        let fb_end = FALLBACK_END.load(Ordering::Relaxed);

        with_heap_lock(|inner| {
            if addr >= fb_start && addr < fb_end {
                // Scrub fallback allocation payload before returning to `linked_list_allocator`.
                if layout.size() > 0 {
                    // SAFETY: Caller guarantees `(ptr, layout)` is a live allocation inside `FALLBACK_REGION`.
                    let slice = unsafe { core::slice::from_raw_parts_mut(ptr, layout.size()) };
                    scrub_frame_bytes(slice);
                }
                if let Some(nn) = ptr::NonNull::new(ptr) {
                    // SAFETY: `addr` lies in `[fb_start, fb_end)` and was allocated from `inner.fallback`.
                    unsafe {
                        inner.fallback.deallocate(nn, layout);
                    }
                }
                return;
            }

            // Scrub the ENTIRE owning slab slot or multi-page span (including trailing padding bytes
            // beyond `layout.size()`) BEFORE releasing the slot bit!
            let scrub_len = inner
                .slab
                .slot_or_span_bytes(addr)
                .unwrap_or(layout.size());
            if scrub_len > 0 {
                // SAFETY: `addr` is a live allocation base owned by `inner.slab` with backing capacity `scrub_len`.
                let slice = unsafe { core::slice::from_raw_parts_mut(ptr, scrub_len) };
                scrub_frame_bytes(slice);
            }
            let mut backend = KernelPhysBackend;
            let _ = inner
                .slab
                .dealloc(addr, layout.size(), layout.align(), &mut backend);
        });
    }
}

#[global_allocator]
static ALLOCATOR: EnterpriseGlobalAlloc = EnterpriseGlobalAlloc;

/// Snapshot of kernel heap + dynamic physical pool utilization (`used`, `free`, `total` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct HeapStats {
    pub used: usize,
    pub free: usize,
    pub total: usize,
}

/// Initialize the kernel slab + fallback heap. Must run once on the BSP before allocations.
pub fn init() {
    if HEAP_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    let start = FALLBACK_REGION.0.get().cast::<u8>();
    let start_addr = start as usize;
    FALLBACK_START.store(start_addr, Ordering::Release);
    FALLBACK_END.store(start_addr + HEAP_SIZE, Ordering::Release);
    with_heap_lock(|inner| {
        // SAFETY: `compare_exchange` ensures single initialization on the BSP; `FALLBACK_REGION`
        // is a 4 KiB-aligned `HEAP_SIZE` `.bss` block owned exclusively by `inner.fallback`.
        unsafe {
            inner.fallback.init(start, HEAP_SIZE);
        }
    });
}

/// Read combined slab + dynamic physical pool + fallback heap utilization.
pub fn stats() -> HeapStats {
    let pmm_free_bytes = crate::phys_mm_stats()
        .free_frames
        .saturating_mul(target_enterprise::slab_alloc::SLAB_PAGE_BYTES);
    with_heap_lock(|inner| {
        let st = inner.slab.stats();
        let used = st.used_bytes.saturating_add(inner.fallback.used());
        let free = pmm_free_bytes.saturating_add(inner.fallback.free());
        HeapStats {
            used,
            free,
            total: used.saturating_add(free),
        }
    })
}

/// Snapshot detailed segregated size-class slab metrics.
pub fn slab_stats() -> SlabStats {
    with_heap_lock(|inner| inner.slab.stats())
}

/// Reclaim warm cached empty 4 KiB slab pages back to `KERNEL_PHYS_MM`.
pub fn reclaim_empty_slabs() -> usize {
    with_heap_lock(|inner| {
        let mut backend = KernelPhysBackend;
        inner.slab.reclaim_empty_slabs(&mut backend)
    })
}

/// Return the high-water mark of simultaneously allocated heap bytes since boot.
pub fn peak_used_bytes() -> usize {
    PEAK_USED_BYTES.load(Ordering::Relaxed)
}

/// Return the cumulative count of failed global allocator requests since boot.
pub fn alloc_failures() -> u64 {
    ALLOC_FAILURES.load(Ordering::Relaxed)
}

/// Return `true` iff allocating `requested` bytes preserves at least
/// [`KERNEL_HEAP_RESERVE_BYTES`] of free Ring-0 emergency headroom.
pub fn has_headroom(requested: usize) -> bool {
    if !HEAP_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }
    let st = stats();
    requested <= st.free.saturating_sub(KERNEL_HEAP_RESERVE_BYTES)
        && target_enterprise::memory::kernel_guards::heap_has_headroom(
            st.used,
            st.total,
            requested,
            KERNEL_HEAP_RESERVE_BYTES,
        )
}
