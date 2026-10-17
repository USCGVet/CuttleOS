//! Physical-frame bitmap allocator — caller-provided backing buffer.
//!
//! Algorithmic core lifted from `RustOSa/src/memory.rs` (one bit per
//! 4 KiB frame, bitmap-backed, O(1) free, bounded-scan alloc with a
//! "lowest known free" hint) but stripped of the bootloader-specific
//! mutable statics and `MemoryRegions` walk. The donor module locks
//! the bitmap inside a `static mut` array; this seed version exposes
//! the algorithm as a plain `BitmapAllocator` parameterised by a
//! caller-supplied `&mut [u8]`. That makes it host-testable while
//! preserving the exact bit-packing semantics — every bit is `1`
//! when the frame is in use, `0` when free; frame index N occupies
//! bit `N % 8` of byte `N / 8`. The morph engine will eventually
//! port the bootloader-backed init path on top of this surface.
//!
//! Frame size is locked at 4 KiB to match the donor and the x86_64
//! page size; this is the granularity at which the OS-facing allocator
//! hands out physical memory.

use core::sync::atomic::{AtomicUsize, Ordering};

/// Frame size in bytes. Locked at 4 KiB across all morph cycles.
pub const FRAME_SIZE: u64 = 4096;

/// Bitmap-backed frame allocator with caller-provided storage.
///
/// `buf` holds one bit per frame. The allocator covers `buf.len() * 8`
/// frames total — frame indices `0 .. buf.len() * 8`. A `1` bit means
/// the frame is in use; a `0` bit means it is free.
///
/// Invariants (locked across morph cycles):
/// - `alloc_frame` returns a physical address (frame_idx * FRAME_SIZE);
///   the same address is never returned to two different callers without
///   an intervening `free_frame`.
/// - `free_frame(pa)` is idempotent — freeing a frame that is already
///   free is a no-op.
/// - The `next_hint` field is a *hint* — it is allowed to point at an
///   in-use frame; the scan will skip over it.
pub struct BitmapAllocator<'a> {
    /// Backing bitmap. One bit per frame, byte index = frame / 8,
    /// bit index = frame % 8.
    bits: &'a mut [u8],
    /// Lowest frame index that *might* be free. Monotonically increases
    /// during a scan; reset downward by `free_frame` if a lower index
    /// is freed.
    next_hint: usize,
    /// Total number of free frames currently in the bitmap. Maintained
    /// in sync with the bits by every mutation.
    free_count: usize,
    /// Frame count capacity = `bits.len() * 8`. Cached at construction.
    capacity: usize,
}

impl<'a> BitmapAllocator<'a> {
    /// Build a new allocator over `buf`. All frames start FREE — i.e.
    /// every bit is cleared to `0`. Note: the donor module starts with
    /// every bit SET (in use) and clears bits for usable regions; this
    /// seed flips the default to match the host-testable surface where
    /// the caller hasn't yet declared any unusable regions. Switch by
    /// calling `mark_used(idx)` for any frame that should not be handed
    /// out (e.g. the kernel image, MMIO holes).
    pub fn new(buf: &'a mut [u8]) -> Self {
        let capacity = buf.len() * 8;
        // Zero every byte. We do this deliberately instead of trusting the
        // caller's buffer to already be zeroed — a fresh stack buffer is
        // commonly initialised with garbage in debug builds.
        let mut i = 0;
        while i < buf.len() {
            buf[i] = 0;
            i += 1;
        }
        Self {
            bits: buf,
            next_hint: 0,
            free_count: capacity,
            capacity,
        }
    }

    /// Total number of frames this allocator can ever hand out.
    #[inline]
    pub fn capacity(&self) -> usize {
        self.capacity
    }

    /// Number of frames currently free.
    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count
    }

    /// Mark frame `idx` as used. Safe to call on an already-used frame
    /// (idempotent). Returns `true` if the frame was free before this
    /// call (i.e. this call transitioned it to in-use).
    pub fn mark_used(&mut self, idx: usize) -> bool {
        if idx >= self.capacity {
            return false;
        }
        let byte = idx / 8;
        let bit = 1u8 << (idx % 8);
        let was_free = (self.bits[byte] & bit) == 0;
        self.bits[byte] |= bit;
        if was_free {
            self.free_count -= 1;
        }
        was_free
    }

    /// Allocate one frame. Returns the physical address (`frame_idx *
    /// FRAME_SIZE`) on success, or `None` if no frames remain.
    pub fn alloc_frame(&mut self) -> Option<u64> {
        if self.free_count == 0 {
            return None;
        }
        // Bounded scan from the hint. We walk byte-at-a-time and
        // short-circuit on bytes that are fully in-use (0xFF).
        let mut idx = self.next_hint;
        while idx < self.capacity {
            let byte_idx = idx / 8;
            let bit_idx = idx % 8;
            let byte = self.bits[byte_idx];
            // Fast skip: if the whole byte is full and we are at a byte
            // boundary, jump 8 bits forward.
            if byte == 0xFF && bit_idx == 0 {
                idx += 8;
                continue;
            }
            if (byte & (1 << bit_idx)) == 0 {
                // Free — claim it.
                self.bits[byte_idx] = byte | (1 << bit_idx);
                self.free_count -= 1;
                self.next_hint = idx + 1;
                return Some((idx as u64) * FRAME_SIZE);
            }
            idx += 1;
        }
        // Hint was stale. Restart from 0 if the hint was non-zero — this
        // handles the case where every frame after the hint is in use but
        // some frame before it has been freed.
        if self.next_hint > 0 {
            let saved = self.next_hint;
            self.next_hint = 0;
            let r = self.alloc_frame();
            // If still nothing, restore the hint so subsequent allocs
            // don't keep restarting.
            if r.is_none() {
                self.next_hint = saved;
            }
            return r;
        }
        None
    }

    /// Free a frame previously returned by `alloc_frame`. `pa` must be
    /// 4 KiB-aligned and within the bitmap's capacity; otherwise this is
    /// a no-op.
    pub fn free_frame(&mut self, pa: u64) {
        if pa % FRAME_SIZE != 0 {
            return;
        }
        let idx = (pa / FRAME_SIZE) as usize;
        if idx >= self.capacity {
            return;
        }
        let byte_idx = idx / 8;
        let bit = 1u8 << (idx % 8);
        if (self.bits[byte_idx] & bit) != 0 {
            self.bits[byte_idx] &= !bit;
            self.free_count += 1;
            if idx < self.next_hint {
                self.next_hint = idx;
            }
        }
    }

    /// Query whether frame `idx` is currently in use.
    #[inline]
    pub fn is_used(&self, idx: usize) -> bool {
        if idx >= self.capacity {
            return false;
        }
        (self.bits[idx / 8] & (1 << (idx % 8))) != 0
    }
}

/// Number of `with_mm` calls made so far. Exposed for diagnostics and so
/// the host-side tests can observe that the closure ran without leaking
/// the allocator through the public API.
pub static WITH_MM_CALLS: AtomicUsize = AtomicUsize::new(0);

/// Borrow the global allocator under a closure. In the seed crate this
/// is host-testable: the caller supplies the allocator directly. The
/// morph engine will eventually re-wire this to talk to a real
/// `spin::Mutex<BitmapAllocator>` static, matching the donor module's
/// `Mutex<BitmapFrameAllocator>` shape.
pub fn with_mm<R, F: FnOnce(&mut BitmapAllocator<'_>) -> R>(
    allocator: &mut BitmapAllocator<'_>,
    f: F,
) -> R {
    WITH_MM_CALLS.fetch_add(1, Ordering::Relaxed);
    f(allocator)
}

/// Convenience: convert a frame index to its physical base address.
#[inline]
pub const fn frame_idx_to_pa(idx: usize) -> u64 {
    (idx as u64) * FRAME_SIZE
}

/// Convenience: convert a physical address to its frame index (truncates).
#[inline]
pub const fn pa_to_frame_idx(pa: u64) -> usize {
    (pa / FRAME_SIZE) as usize
}
