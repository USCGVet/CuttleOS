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

/// Bare-metal kernel physical DMA window layout and VirtIO ring-entry validators.
pub mod dma_layout {
    /// Total reserved DMA + page-table window size in bytes (`384 KiB`).
    pub const DMA_WINDOW_BYTES: u64 = 0x6_0000;
    /// VirtIO-Net / VirtIO-Blk legacy & modern virtqueue/buffer region `[0x0_0000 .. 0x0_C000)`.
    pub const VIRTIO_REGION: (u64, u64) = (0x0_0000, 0x0_C000);
    /// AHCI CLB/FB/CTBA/sector DMA region `[0x1_0000 .. 0x1_C000)`.
    pub const AHCI_REGION: (u64, u64) = (0x1_0000, 0x1_C000);
    /// Intel e1000 TX/RX descriptor rings and frame buffers `[0x2_0000 .. 0x2_3000)`.
    pub const E1000_REGION: (u64, u64) = (0x2_0000, 0x2_3000);
    /// Dedicated 9-frame isolated `CR3` KPTI Ring-3 sandbox `[0x2_4000 .. 0x2_D000)`.
    pub const RING3_KPTI_REGION: (u64, u64) = (0x2_4000, 0x2_D000);
    /// NVMe Admin/I/O SQ+CQ + Identify/sector DMA buffers `[0x3_0000 .. 0x3_7000)`.
    pub const NVME_REGION: (u64, u64) = (0x3_0000, 0x3_7000);
    /// Dynamic 4 KiB page-table frame pool `[PT_POOL_START_OFF .. PT_POOL_END_OFF)` (`40` dedicated frames).
    pub const PT_POOL_START_OFF: u64 = 0x3_8000;
    /// Exclusive upper bound of the dynamic 4 KiB page-table frame pool.
    pub const PT_POOL_END_OFF: u64 = 0x6_0000;

    /// Validate that every region in `regions` is 4 KiB-aligned, non-empty, within `window_bytes`,
    /// and pairwise non-overlapping. Returns `Err((idx_a, idx_b))` on overlap or bounds violation.
    pub const fn validate_regions(
        window_bytes: u64,
        regions: &[(u64, u64)],
    ) -> Result<(), (usize, usize)> {
        let mut i = 0usize;
        while i < regions.len() {
            let (s_i, e_i) = regions[i];
            if s_i >= e_i || (s_i & 0xFFF) != 0 || (e_i & 0xFFF) != 0 || e_i > window_bytes {
                return Err((i, i));
            }
            let mut j = i + 1;
            while j < regions.len() {
                let (s_j, e_j) = regions[j];
                if s_i < e_j && s_j < e_i {
                    return Err((i, j));
                }
                j += 1;
            }
            i += 1;
        }
        Ok(())
    }

    /// Validate the active kernel DMA + page-table pool layout for pairwise disjointness.
    pub const fn validate_default_layout() -> Result<(), (usize, usize)> {
        let regions = [
            VIRTIO_REGION,
            AHCI_REGION,
            E1000_REGION,
            RING3_KPTI_REGION,
            NVME_REGION,
            (PT_POOL_START_OFF, PT_POOL_END_OFF),
        ];
        validate_regions(DMA_WINDOW_BYTES, &regions)
    }

    const _: () = {
        assert!(validate_default_layout().is_ok());
    };

    /// Validate a modern VirtIO-Net RX used-ring completion `(id, used_len)` before indexing DMA buffers.
    pub const fn validate_modern_vnet_rx_used(
        id: u16,
        used_len: usize,
        rx_buffers: usize,
        hdr_len: usize,
        max_payload: usize,
        out_len: usize,
    ) -> Option<usize> {
        if (id as usize) >= 2 * rx_buffers || (id & 1) != 0 {
            return None;
        }
        if used_len < hdr_len {
            return None;
        }
        let flen = used_len - hdr_len;
        if flen > max_payload || flen > out_len {
            return None;
        }
        Some(flen)
    }

    /// Validate a legacy VirtIO-Net RX used-ring descriptor index before indexing `rx_bufs_pa`.
    pub const fn validate_legacy_vnet_rx_desc(desc_id: u16, rx_buffers: usize) -> bool {
        (desc_id as usize) < rx_buffers
    }
}

#[cfg(test)]
mod tests {
    use super::dma_layout::*;

    #[test]
    fn kernel_dma_regions_are_disjoint_and_virtio_ring_bounds_reject_corrupt_used_entries() {
        assert_eq!(
            validate_default_layout(),
            Ok(()),
            "kernel PT_POOL must never overlap VirtIO, AHCI, e1000, Ring-3 KPTI, or NVMe DMA rings"
        );
        // Odd head descriptor, out-of-range id (>= 16), short (< 12B hdr), or oversize (> 1984B) must fail!
        assert_eq!(validate_modern_vnet_rx_used(1, 64, 8, 12, 1984, 2048), None);
        assert_eq!(validate_modern_vnet_rx_used(16, 64, 8, 12, 1984, 2048), None);
        assert_eq!(validate_modern_vnet_rx_used(0, 11, 8, 12, 1984, 2048), None);
        assert_eq!(validate_modern_vnet_rx_used(0, 12 + 1985, 8, 12, 1984, 2048), None);
        assert_eq!(validate_modern_vnet_rx_used(0, 12 + 1500, 8, 12, 1984, 1024), None);
        assert_eq!(validate_modern_vnet_rx_used(14, 12 + 60, 8, 12, 1984, 2048), Some(60));

        assert!(!validate_legacy_vnet_rx_desc(8, 8));
        assert!(!validate_legacy_vnet_rx_desc(u16::MAX, 8));
        assert!(validate_legacy_vnet_rx_desc(7, 8));
    }
}
