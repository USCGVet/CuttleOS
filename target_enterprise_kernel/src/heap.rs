//! Kernel heap.
//!
//! rustls (TLS 1.3 on port 443) needs `alloc`; nothing else in the kernel
//! allocates. The heap is a fixed, zero-initialized region in `.bss` (so it adds
//! nothing to the kernel ELF) managed by `linked_list_allocator` behind a spin
//! lock, which is safe across SMP cores. Interrupt handlers never allocate, so the
//! lock cannot be re-entered from an interrupt.

use linked_list_allocator::LockedHeap;

/// 8 MiB. One TLS 1.3 connection needs tens of KiB, so this covers all 16 TCP
/// slots with ample headroom inside a 128 MiB VM.
pub const HEAP_SIZE: usize = 8 * 1024 * 1024;

#[repr(C, align(4096))]
struct HeapRegion([u8; HEAP_SIZE]);

static mut HEAP: HeapRegion = HeapRegion([0; HEAP_SIZE]);

#[global_allocator]
static ALLOCATOR: LockedHeap = LockedHeap::empty();

/// Hand the heap region to the allocator. Must run once, on the BSP, before
/// anything allocates and before the application processors start.
pub fn init() {
    // SAFETY: called exactly once at the top of `kernel_main`, before any other
    // core runs; `HEAP` is referenced nowhere else, so this is its only borrow.
    unsafe {
        let start = core::ptr::addr_of_mut!(HEAP) as *mut u8;
        ALLOCATOR.lock().init(start, HEAP_SIZE);
    }
}
