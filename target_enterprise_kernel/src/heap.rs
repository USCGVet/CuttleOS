//! Kernel heap.
//!
//! rustls (TLS 1.3 on port 443) needs `alloc`; nothing else in the kernel
//! allocates. The heap is a fixed, zero-initialized region in `.bss` (so it adds
//! nothing to the kernel ELF) managed by `linked_list_allocator` behind a spin
//! lock, which is safe across SMP cores. Interrupt handlers never allocate, so the
//! lock cannot be re-entered from an interrupt.

use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, Ordering};
use linked_list_allocator::LockedHeap;

/// 8 MiB. One TLS 1.3 connection needs tens of KiB, so this covers all 16 TCP
/// slots with ample headroom inside a 128 MiB VM.
pub const HEAP_SIZE: usize = 8 * 1024 * 1024;

/// 512 KiB emergency Ring-0 heap reserve withheld from untrusted network/TLS
/// connection floods so core kernel paths never panic on heap exhaustion.
pub const KERNEL_HEAP_RESERVE_BYTES: usize = 512 * 1024;

#[repr(C, align(4096))]
struct HeapRegion([u8; HEAP_SIZE]);

struct SyncHeapRegion(UnsafeCell<HeapRegion>);

// SAFETY: Access to the backing `.bss` region is handed once to `ALLOCATOR` (a spinlock-Synchronized
// `LockedHeap`) inside `init()` gated by `HEAP_INITIALIZED`.
unsafe impl Sync for SyncHeapRegion {}

static HEAP: SyncHeapRegion = SyncHeapRegion(UnsafeCell::new(HeapRegion([0; HEAP_SIZE])));
static HEAP_INITIALIZED: AtomicBool = AtomicBool::new(false);

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Snapshot of kernel heap utilization (`used`, `free`, `total` bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[allow(dead_code)]
pub struct HeapStats {
    pub used: usize,
    pub free: usize,
    pub total: usize,
}

/// Hand the heap region to the allocator. Must run once, on the BSP, before
/// anything allocates and before the application processors start.
pub fn init() {
    if HEAP_INITIALIZED
        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
        .is_err()
    {
        return;
    }
    // SAFETY: `compare_exchange` guarantees this runs at most once on the BSP before any APs start;
    // `HEAP.0.get()` points to a 4 KiB-aligned `HEAP_SIZE` `.bss` block owned solely by `ALLOCATOR`.
    unsafe {
        let start = HEAP.0.get().cast::<u8>();
        ALLOCATOR.lock().init(start, HEAP_SIZE);
    }
}

/// Read current kernel heap utilization under the allocator spinlock.
#[allow(dead_code)]
pub fn stats() -> HeapStats {
    let guard = ALLOCATOR.lock();
    HeapStats {
        used: guard.used(),
        free: guard.free(),
        total: HEAP_SIZE,
    }
}

/// Return `true` iff allocating `requested` bytes preserves at least
/// [`KERNEL_HEAP_RESERVE_BYTES`] of free Ring-0 emergency heap headroom.
pub fn has_headroom(requested: usize) -> bool {
    if !HEAP_INITIALIZED.load(Ordering::Acquire) {
        return false;
    }
    let st = stats();
    target_enterprise::memory::kernel_guards::heap_has_headroom(
        st.used,
        st.total,
        requested,
        KERNEL_HEAP_RESERVE_BYTES,
    )
}
