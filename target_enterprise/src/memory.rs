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

/// Pure host-testable bounds, protocol, and hardware-framing guards shared by
/// `target_enterprise_kernel` (`fb_console`, `smp_hw`, `net_service`, `main`).
pub mod kernel_guards {
    /// Compute the byte offset of pixel `(x, y)` inside a linear framebuffer.
    pub const fn fb_checked_pixel_offset(
        x: usize,
        y: usize,
        w: usize,
        h: usize,
        stride: usize,
        bpp: usize,
        len: usize,
    ) -> Option<usize> {
        if bpp < 3 || x >= w || y >= h || stride < w {
            return None;
        }
        let row_px = match y.checked_mul(stride) {
            Some(v) => v,
            None => return None,
        };
        let px_idx = match row_px.checked_add(x) {
            Some(v) => v,
            None => return None,
        };
        let off = match px_idx.checked_mul(bpp) {
            Some(v) => v,
            None => return None,
        };
        match off.checked_add(2) {
            Some(last_byte) if last_byte < len => Some(off),
            _ => None,
        }
    }

    /// Pack `(r, g, b)` into hardware byte order (`is_bgr = true` for BGR, `false` for RGB).
    pub const fn fb_pack_rgb(rgb: (u8, u8, u8), is_bgr: bool) -> [u8; 3] {
        if is_bgr {
            [rgb.2, rgb.1, rgb.0]
        } else {
            [rgb.0, rgb.1, rgb.2]
        }
    }

    /// Translate physical address `phys` in `[0x8000, 0x9000)` into the SMP RX trampoline VA.
    pub const fn smp_checked_rx_va(base_va: u64, phys: u64) -> Option<u64> {
        if base_va == 0 || phys < 0x8000 || phys >= 0x9000 {
            return None;
        }
        base_va.checked_add(phys - 0x8000)
    }

    /// Map AP slot `cpu_slot` (`1..max_cpus`) to a target Local APIC ID without self-targeting `bsp_apic_id`.
    pub const fn smp_apic_for_ap_slot(cpu_slot: usize, bsp_apic_id: u32) -> Option<u32> {
        if cpu_slot == 0 {
            None
        } else {
            let cand = (cpu_slot - 1) as u32;
            if cand < bsp_apic_id {
                Some(cand)
            } else {
                Some(cpu_slot as u32)
            }
        }
    }

    /// Validate a PCI capability list offset (`0x40..=0xFC`, 4-byte aligned, with room for `min_bytes`).
    pub const fn vnet_valid_pci_cap_ptr(cap_ptr: u8, min_bytes: u8) -> bool {
        if cap_ptr < 0x40 || (cap_ptr & 3) != 0 || min_bytes < 4 {
            return false;
        }
        (cap_ptr as u16) + (min_bytes as u16) <= 0x100
    }

    /// Compute the physical MMIO address of a VirtIO modern queue notify doorbell.
    pub const fn vnet_notify_mmio_pa(
        notify_bar: u64,
        notify_off: u64,
        queue_notify_off: u16,
        notify_mult: u32,
    ) -> Option<u64> {
        let base = match notify_bar.checked_add(notify_off) {
            Some(b) => b,
            None => return None,
        };
        let qoff = match (queue_notify_off as u64).checked_mul(notify_mult as u64) {
            Some(q) => q,
            None => return None,
        };
        match base.checked_add(qoff) {
            Some(pa) if (pa & 1) == 0 => Some(pa),
            _ => None,
        }
    }

    /// Validate an outbound Ethernet frame length against the VirtIO header and DMA buffer size.
    pub const fn vnet_valid_tx_frame_len(
        frame_len: usize,
        hdr_len: usize,
        dma_buf_len: usize,
    ) -> bool {
        if frame_len == 0 {
            return false;
        }
        match hdr_len.checked_add(frame_len) {
            Some(total) => total <= dma_buf_len,
            None => false,
        }
    }

    /// Extract `(sport, dport)` from an Ethernet + IPv4 + TCP/UDP frame of valid length `flen`.
    pub fn ipv4_l4_ports_in_frame(frame: &[u8], flen: usize) -> Option<(u16, u16)> {
        if flen < 36 || flen > frame.len() {
            return None;
        }
        if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
            return None;
        }
        if (frame[14] >> 4) != 4 {
            return None;
        }
        let ihl = ((frame[14] & 0x0F) as usize) * 4;
        if ihl < 20 {
            return None;
        }
        let proto = frame[23];
        if proto != 6 && proto != 17 {
            return None;
        }
        let l4_end = 14usize.checked_add(ihl)?.checked_add(4)?;
        if l4_end > flen {
            return None;
        }
        let sport = u16::from_be_bytes([frame[14 + ihl], frame[14 + ihl + 1]]);
        let dport = u16::from_be_bytes([frame[14 + ihl + 2], frame[14 + ihl + 3]]);
        Some((sport, dport))
    }

    /// Return `true` iff an i8042 status byte (`port 0x64`) indicates a clean PS/2 keyboard scancode
    /// (bit 0 OBF set, bit 5 AUXB mouse cleared, bits 6..7 timeout/parity error cleared).
    pub const fn ps2_kbd_byte_ready(status: u8) -> bool {
        (status & 0x01) != 0 && (status & 0xE0) == 0
    }

    /// Format up to `n` bytes of `bytes` as lowercase hex into `out`, bounded by `out.len() / 2`.
    pub fn hex_encode_bounded(bytes: &[u8], n: usize, out: &mut [u8]) -> usize {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let max_in = out.len() / 2;
        let take_req = if n > bytes.len() { bytes.len() } else { n };
        let take = if take_req > max_in { max_in } else { take_req };
        let mut i = 0usize;
        while i < take {
            let b = bytes[i];
            out[i * 2] = HEX[(b >> 4) as usize];
            out[i * 2 + 1] = HEX[(b & 0x0F) as usize];
            i += 1;
        }
        take * 2
    }

    /// Format `val` as decimal ASCII into `out`, returning `0` if `out` cannot hold the digits.
    pub fn dec_u64_bounded(mut val: u64, out: &mut [u8]) -> usize {
        if val == 0 {
            if out.is_empty() {
                return 0;
            }
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
        if k > out.len() {
            return 0;
        }
        let mut i = 0usize;
        while i < k {
            out[i] = tmp[k - 1 - i];
            i += 1;
        }
        k
    }

    /// x86-64 PTE Present (`P`) flag.
    pub const PTE_P_BIT: u64 = 1;
    /// x86-64 PTE Writable (`R/W`) flag.
    pub const PTE_W_BIT: u64 = 1 << 1;
    /// x86-64 PTE Page-Level Write-Through (`PWT`) flag.
    pub const PTE_PWT_BIT: u64 = 1 << 3;
    /// x86-64 PTE Page-Level Cache Disable (`PCD`) flag.
    pub const PTE_PCD_BIT: u64 = 1 << 4;
    /// x86-64 PTE Execute-Disable (`NX`) flag.
    pub const PTE_NX_BIT: u64 = 1u64 << 63;
    /// x86-64 4 KiB physical frame address mask (`bits 51:12`).
    pub const PTE_PHYS_MASK: u64 = 0x000F_FFFF_FFFF_F000;

    /// Virtual page stride for one guarded 16 KiB hardware stack (`1` unmapped guard + `4` `RW+NX` pages).
    pub const STACK16K_STRIDE_PAGES: usize = 5;
    /// Virtual page stride for one guarded 4 KiB IST stack (`1` unmapped guard + `1` `RW+NX` page).
    pub const IST4K_STRIDE_PAGES: usize = 2;

    /// Build a strict `W^X`-compliant uncached MMIO leaf PTE (`Present | Writable | PWT | PCD | NX`).
    pub const fn mmio_leaf_pte(phys_page: u64) -> u64 {
        (phys_page & PTE_PHYS_MASK)
            | PTE_P_BIT
            | PTE_W_BIT
            | PTE_PWT_BIT
            | PTE_PCD_BIT
            | PTE_NX_BIT
    }

    /// Return `true` iff `pte` maps an uncached MMIO page with `PTE_NX_BIT` enforced (`never executable`).
    pub const fn is_mmio_pte_compliant(pte: u64) -> bool {
        let req = PTE_P_BIT | PTE_W_BIT | PTE_PWT_BIT | PTE_PCD_BIT | PTE_NX_BIT;
        (pte & req) == req
    }

    /// Compute `(bottom_guard_va, stack_base_va, stack_top_va)` for guarded 16 KiB stack `slot_idx`.
    ///
    /// Note that `stack_top_va` coincides with the unmapped 4 KiB guard page immediately above the stack.
    pub const fn guarded_stack16k_bounds_va(
        region_base_va: u64,
        slot_idx: usize,
    ) -> Option<(u64, u64, u64)> {
        if region_base_va == 0 || (region_base_va & 0x1F_FFFF) != 0 {
            return None;
        }
        let first_page = match slot_idx.checked_mul(STACK16K_STRIDE_PAGES) {
            Some(p) if p + STACK16K_STRIDE_PAGES < 512 => p,
            _ => return None,
        };
        let guard_lo = region_base_va + (first_page as u64) * 4096;
        let base = guard_lo + 4096;
        let top = base + 16 * 1024;
        Some((guard_lo, base, top))
    }

    /// Compute `(bottom_guard_va, ist_base_va, ist_top_va)` for guarded 4 KiB IST stack `ist_idx`
    /// placed after `num_16k_slots` guarded 16 KiB stacks inside the same 2 MiB L1 page table.
    pub const fn guarded_ist4k_bounds_va(
        region_base_va: u64,
        num_16k_slots: usize,
        ist_idx: usize,
    ) -> Option<(u64, u64, u64)> {
        if region_base_va == 0 || (region_base_va & 0x1F_FFFF) != 0 {
            return None;
        }
        let base_pt = match num_16k_slots.checked_mul(STACK16K_STRIDE_PAGES) {
            Some(v) => v,
            None => return None,
        };
        let off_pt = match ist_idx.checked_mul(IST4K_STRIDE_PAGES) {
            Some(v) => v,
            None => return None,
        };
        let first_page = match base_pt.checked_add(off_pt) {
            Some(p) if p + IST4K_STRIDE_PAGES < 512 => p,
            _ => return None,
        };
        let guard_lo = region_base_va + (first_page as u64) * 4096;
        let base = guard_lo + 4096;
        let top = base + 4096;
        Some((guard_lo, base, top))
    }

    /// Populate a 512-entry L1 Page Table (`pt_out`) with guarded 16 KiB stacks (`stacks_16k`)
    /// and guarded 4 KiB IST stacks (`ists_4k`), placing an unmapped (`PTE_P = 0`) 4 KiB guard
    /// page below and above every stack and enforcing `Supervisor RW + NX` on all interior pages.
    #[inline(never)]
    pub fn build_guarded_stacks_pt(
        stacks_16k: &[[u64; 4]],
        ists_4k: &[u64],
        pt_out: &mut [u64; 512],
    ) -> Result<usize, &'static str> {
        let s_entries = stacks_16k
            .len()
            .checked_mul(STACK16K_STRIDE_PAGES)
            .ok_or("stack count overflow")?;
        let i_entries = ists_4k
            .len()
            .checked_mul(IST4K_STRIDE_PAGES)
            .ok_or("ist count overflow")?;
        let total_entries = s_entries
            .checked_add(i_entries)
            .and_then(|v| v.checked_add(1))
            .ok_or("pt entry count overflow")?;
        if total_entries > 512 {
            return Err("guarded stacks exceed single L1 page table");
        }

        let mut i = 0usize;
        while i < 512 {
            pt_out[i] = 0;
            i += 1;
        }

        let mut cursor = 0usize;
        let mut s = 0usize;
        while s < stacks_16k.len() {
            pt_out[cursor] = 0; // Unmapped 4 KiB bottom guard page
            cursor += 1;
            let mut p = 0usize;
            while p < 4 {
                let pa = stacks_16k[s][p];
                if pa == 0 || (pa & 0xFFF) != 0 || (pa & !PTE_PHYS_MASK) != 0 {
                    return Err("unaligned or invalid 16k stack physical frame");
                }
                pt_out[cursor] = pa | PTE_P_BIT | PTE_W_BIT | PTE_NX_BIT;
                cursor += 1;
                p += 1;
            }
            s += 1;
        }

        let mut k = 0usize;
        while k < ists_4k.len() {
            pt_out[cursor] = 0; // Unmapped 4 KiB bottom guard page
            cursor += 1;
            let pa = ists_4k[k];
            if pa == 0 || (pa & 0xFFF) != 0 || (pa & !PTE_PHYS_MASK) != 0 {
                return Err("unaligned or invalid 4k IST physical frame");
            }
            pt_out[cursor] = pa | PTE_P_BIT | PTE_W_BIT | PTE_NX_BIT;
            cursor += 1;
            k += 1;
        }

        pt_out[cursor] = 0; // Trailing unmapped 4 KiB top guard page

        // Verify pairwise disjointness of all mapped physical frames and zero RWX.
        let mut a = 0usize;
        while a < cursor {
            let ea = pt_out[a];
            if (ea & PTE_P_BIT) != 0 {
                if (ea & PTE_NX_BIT) == 0 {
                    return Err("executable stack PTE forbidden");
                }
                let pa_a = ea & PTE_PHYS_MASK;
                let mut b = a + 1;
                while b < cursor {
                    let eb = pt_out[b];
                    if (eb & PTE_P_BIT) != 0 && (eb & PTE_PHYS_MASK) == pa_a {
                        return Err("duplicate physical frame in guarded stack table");
                    }
                    b += 1;
                }
            }
            a += 1;
        }

        Ok(total_entries)
    }

    /// Return `true` iff allocating `requested` bytes from a heap with `used` of `total` bytes
    /// preserves at least `min_reserve` bytes of emergency Ring-0 headroom.
    pub const fn heap_has_headroom(
        used: usize,
        total: usize,
        requested: usize,
        min_reserve: usize,
    ) -> bool {
        if used > total {
            return false;
        }
        let avail = total - used;
        match requested.checked_add(min_reserve) {
            Some(need) => avail >= need,
            None => false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::dma_layout::*;
    use super::kernel_guards::*;

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

    #[test]
    fn stage10_kernel_fb_smp_vnet_ps2_and_fmt_guards() {
        // 1. Framebuffer bounds + RGB/BGR channel order.
        assert_eq!(
            fb_checked_pixel_offset(105, 10, 100, 80, 128, 4, 128 * 80 * 4),
            None,
            "pixel x >= viewport width must be clipped even when stride > width"
        );
        assert_eq!(
            fb_checked_pixel_offset(10, 80, 100, 80, 128, 4, 128 * 80 * 4),
            None,
            "pixel y >= viewport height must be clipped"
        );
        assert_eq!(
            fb_checked_pixel_offset(0, usize::MAX / 2, usize::MAX, usize::MAX, 4, 4, 4096),
            None,
            "usize multiplication wraparound must not pass bounds check"
        );
        assert_eq!(fb_pack_rgb((0x11, 0x22, 0x33), true), [0x33, 0x22, 0x11]);
        assert_eq!(fb_pack_rgb((0x11, 0x22, 0x33), false), [0x11, 0x22, 0x33]);

        // 2. SMP RX trampoline VA bounds & non-zero BSP APIC ID avoidance.
        assert_eq!(smp_checked_rx_va(0xFFFF_8000_0008_0000, 0x7FFF), None);
        assert_eq!(smp_checked_rx_va(0xFFFF_8000_0008_0000, 0x9000), None);
        assert_eq!(
            smp_checked_rx_va(0xFFFF_8000_0008_0000, 0x8120),
            Some(0xFFFF_8000_0008_0120)
        );
        assert_eq!(smp_apic_for_ap_slot(1, 0), Some(1));
        assert_eq!(smp_apic_for_ap_slot(2, 0), Some(2));
        assert_eq!(smp_apic_for_ap_slot(3, 0), Some(3));
        for slot in 1..=3 {
            assert_ne!(
                smp_apic_for_ap_slot(slot, 1),
                Some(1),
                "AP wake target must never send INIT/SIPI to BSP APIC ID"
            );
            assert_ne!(smp_apic_for_ap_slot(slot, 2), Some(2));
        }

        // 3. VirtIO PCI cap pointer alignment/wraparound, TX DMA frame bounds, and RX IPv4 IHL bounds.
        assert!(!vnet_valid_pci_cap_ptr(0x00, 4));
        assert!(!vnet_valid_pci_cap_ptr(0x3C, 4));
        assert!(!vnet_valid_pci_cap_ptr(0x42, 4));
        assert!(!vnet_valid_pci_cap_ptr(0xF4, 20), "0xF4 + 16 would wrap u8 PCI config offset");
        assert!(vnet_valid_pci_cap_ptr(0x40, 20));
        assert!(!vnet_valid_tx_frame_len(0, 12, 2048));
        assert!(!vnet_valid_tx_frame_len(2040, 12, 2048));
        assert!(vnet_valid_tx_frame_len(1514, 12, 2048));

        let mut frame = [0xAAu8; 128];
        frame[12] = 0x08;
        frame[13] = 0x00;
        frame[14] = 0x4F; // IHL = 60 bytes, while flen = 38 -> out of received frame bounds!
        frame[23] = 17; // UDP
        assert_eq!(
            ipv4_l4_ports_in_frame(&frame, 38),
            None,
            "oversized IPv4 IHL must not read stale L4 bytes past flen"
        );
        frame[14] = 0x45; // IHL = 20 bytes
        frame[23] = 1; // ICMP (not TCP/UDP)
        assert_eq!(ipv4_l4_ports_in_frame(&frame, 42), None);
        frame[23] = 6; // TCP
        frame[34..38].copy_from_slice(&[0x1F, 0x90, 0x00, 0x50]); // 8080 -> 80
        assert_eq!(ipv4_l4_ports_in_frame(&frame, 38), Some((8080, 80)));

        // 4. PS/2 i8042 status AUXB/error filtering and bounded formatters.
        assert!(ps2_kbd_byte_ready(0x01));
        assert!(!ps2_kbd_byte_ready(0x21), "AUXB mouse byte must not feed root shell");
        assert!(!ps2_kbd_byte_ready(0x81), "parity error byte must be dropped");
        assert!(!ps2_kbd_byte_ready(0x41), "timeout error byte must be dropped");

        let mut tiny = [0u8; 3];
        assert_eq!(hex_encode_bounded(&[0xAB, 0xCD], 2, &mut tiny), 2);
        assert_eq!(&tiny[..2], b"ab");
        assert_eq!(dec_u64_bounded(12345, &mut tiny), 0);
        assert_eq!(dec_u64_bounded(0, &mut []), 0);
    }

    #[test]
    fn stage12_mmio_nx_guarded_stacks_and_heap_headroom_guards() {
        use super::kernel_guards::{
            build_guarded_stacks_pt, guarded_ist4k_bounds_va, guarded_stack16k_bounds_va,
            heap_has_headroom, is_mmio_pte_compliant, mmio_leaf_pte, IST4K_STRIDE_PAGES,
            PTE_NX_BIT, PTE_P_BIT, PTE_W_BIT, STACK16K_STRIDE_PAGES,
        };

        // 1. MMIO leaf PTE MUST always enforce `PTE_NX_BIT` (never executable).
        let lapic_pte = mmio_leaf_pte(0xFEE0_0000);
        assert!(is_mmio_pte_compliant(lapic_pte));
        assert_ne!(lapic_pte & PTE_NX_BIT, 0, "MMIO BAR PTE must enforce NX");
        assert!(
            !is_mmio_pte_compliant(lapic_pte & !PTE_NX_BIT),
            "executable MMIO PTE must be rejected as non-compliant"
        );

        // 2. Build 16 guarded hardware stacks (8 x 16 KiB + 8 x 4 KiB IST) in a 512-entry L1 PT.
        let mut stacks_16k = [[0u64; 4]; 8];
        let mut next_pa = 0x20_0000u64;
        for slot in &mut stacks_16k {
            for frame in slot.iter_mut() {
                *frame = next_pa;
                next_pa += 4096;
            }
        }
        let mut ists_4k = [0u64; 8];
        for frame in &mut ists_4k {
            *frame = next_pa;
            next_pa += 4096;
        }
        let mut pt = [0xFFFF_FFFF_FFFF_FFFFu64; 512];
        let used = build_guarded_stacks_pt(&stacks_16k, &ists_4k, &mut pt)
            .expect("valid guarded stack table must succeed");
        assert_eq!(used, 8 * STACK16K_STRIDE_PAGES + 8 * IST4K_STRIDE_PAGES + 1);

        let region_va = 0xFFFF_8800_0020_0000u64;
        for s in 0..8 {
            let (glo, base, top) = guarded_stack16k_bounds_va(region_va, s).unwrap();
            let glo_idx = ((glo - region_va) / 4096) as usize;
            let top_idx = ((top - region_va) / 4096) as usize;
            assert_eq!(pt[glo_idx], 0, "bottom 4 KiB guard page must be unmapped");
            assert_eq!(pt[top_idx], 0, "top 4 KiB guard page must be unmapped");
            for p in 0..4 {
                let idx = ((base - region_va) / 4096) as usize + p;
                assert_eq!(
                    pt[idx] & (PTE_P_BIT | PTE_W_BIT | PTE_NX_BIT),
                    PTE_P_BIT | PTE_W_BIT | PTE_NX_BIT,
                    "stack interior page must be Supervisor RW + NX"
                );
            }
        }
        for i in 0..8 {
            let (glo, base, top) = guarded_ist4k_bounds_va(region_va, 8, i).unwrap();
            let glo_idx = ((glo - region_va) / 4096) as usize;
            let in_idx = ((base - region_va) / 4096) as usize;
            let top_idx = ((top - region_va) / 4096) as usize;
            assert_eq!(pt[glo_idx], 0, "IST bottom guard page must be unmapped");
            assert_eq!(pt[top_idx], 0, "IST top guard page must be unmapped");
            assert_eq!(
                pt[in_idx] & (PTE_P_BIT | PTE_W_BIT | PTE_NX_BIT),
                PTE_P_BIT | PTE_W_BIT | PTE_NX_BIT,
                "IST page must be Supervisor RW + NX"
            );
        }

        // Duplicate physical frame, unaligned PA, and zero PA must all fail closed.
        let mut dup = stacks_16k;
        dup[3][1] = dup[0][2];
        assert!(build_guarded_stacks_pt(&dup, &ists_4k, &mut pt).is_err());
        let mut unaligned = ists_4k;
        unaligned[2] |= 0x100;
        assert!(build_guarded_stacks_pt(&stacks_16k, &unaligned, &mut pt).is_err());
        let mut zero_pa = ists_4k;
        zero_pa[0] = 0;
        assert!(build_guarded_stacks_pt(&stacks_16k, &zero_pa, &mut pt).is_err());
        assert_eq!(guarded_stack16k_bounds_va(0xFFFF_8800_0010_0000, 0), None);

        // 3. Emergency heap reserve guard prevents connection floods from exhausting Ring-0 heap.
        let total = 2 * 1024 * 1024;
        let reserve = 512 * 1024;
        assert!(heap_has_headroom(1024 * 1024, total, 64 * 1024, reserve));
        assert!(!heap_has_headroom(
            total - reserve + 1,
            total,
            64 * 1024,
            reserve
        ));
        assert!(!heap_has_headroom(0, total, usize::MAX, reserve));
        assert!(!heap_has_headroom(total + 1, total, 0, reserve));
    }
}
