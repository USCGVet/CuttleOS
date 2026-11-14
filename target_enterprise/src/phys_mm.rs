//! Multi-region physical 4 KiB page-frame manager (`phys_mm`).
//!
//! Ingests firmware physical memory maps (`BootInfo.memory_regions`, BIOS E820,
//! or UEFI `GetMemoryMap`) together with explicit kernel/DMA exclusion ranges
//! and tracks both **usability** (`usable_bits`) and **ownership** (`alloc_bits`)
//! across low-4 GiB physical RAM (`[0 .. 4 GiB)`) and up to [`MAX_HIGH_EXTENTS`]
//! high-memory arenas above `4 GiB` (`>= 0x1_0000_0000`).
//!
//! # Enterprise invariants
//! - **Fail-closed usable set**: frames below `1 MiB` (`0x10_0000`), frames not
//!   marked `usable`, frames overlapped by any non-usable region, and frames
//!   overlapped (even partially) by an explicit exclusion interval can **never**
//!   be handed out.
//! - **Deterministic double-free & invalid-free detection**: freeing an
//!   unaligned address, a reserved/MMIO address, or an already-free frame
//!   returns an explicit [`PhysMmError`] without mutating allocator state.
//! - **Contiguous aligned spans**: [`PhysFrameManager::alloc_contiguous`]
//!   allocates `count` contiguous 4 KiB physical frames aligned to `align_frames`
//!   for multi-page DMA queues, kernel stacks, and large heap spans.
//! - **Zero-scrubbing**: [`scrub_frame_bytes`] zeroes 4 KiB frame slices with a
//!   compiler fence so reclaimed Ring-3 user pages and page tables never leak
//!   residual bytes across processes.

use core::sync::atomic::{compiler_fence, Ordering};

/// Hardware page / frame size (`4 KiB`).
pub const PHYS_FRAME_BYTES: u64 = 4096;

/// Low conventional memory boundary (`1 MiB`): `[0 .. 0x10_0000)` is always
/// excluded to protect IVT, BDA/EBDA, VGA aperture, and the `0x8000` SMP real-mode trampoline.
pub const LOW_CONVENTIONAL_EXCLUDE_END: u64 = 0x0010_0000;

/// 4 GiB boundary (`0x1_0000_0000`) separating 32-bit-addressable low physical frames
/// from 64-bit high physical memory extents.
pub const LOW_4GIB_END: u64 = 0x1_0000_0000;

/// Number of `u64` bitmap words needed to cover `[0 .. 4 GiB)` (`1,048,576` frames = `16,384` words).
pub const KERNEL_LOW_BITMAP_WORDS: usize = 16_384;

/// Maximum number of high-memory (`>= 4 GiB`) extents tracked above `LOW_4GIB_END`.
pub const MAX_HIGH_EXTENTS: usize = 8;

/// Number of `u64` bitmap words per high-memory extent (`2,048` words = `131,072` frames = `512 MiB` per extent,
/// `4 GiB` total high-RAM capacity across 8 extents -> `8 GiB` total tracked RAM).
pub const HIGH_EXTENT_WORDS: usize = 2_048;

/// Firmware memory region descriptor normalized from `BootInfo`, E820, or UEFI `MemoryDescriptor`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhysRegionDesc {
    /// Inclusive start guest-physical byte address.
    pub start: u64,
    /// Exclusive end guest-physical byte address.
    pub end: u64,
    /// `true` iff firmware reports the range as conventional usable RAM.
    pub usable: bool,
}

/// Errors returned by [`PhysFrameManager`] operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PhysMmError {
    /// Physical address is not aligned to [`PHYS_FRAME_BYTES`] (`4 KiB`).
    UnalignedAddress,
    /// Physical frame lies outside usable RAM (reserved, MMIO, `< 1 MiB`, or excluded).
    ReservedOrInvalidFrame,
    /// Physical frame was freed while already in the free state.
    DoubleFree,
    /// Requested `0` frames in a contiguous allocation or free.
    ZeroFrameCount,
    /// Alignment parameter is `0` or not a power of two.
    InvalidAlignment,
    /// Insufficient free (or contiguous free) physical frames to satisfy the request.
    OutOfMemory,
}

/// Telemetry snapshot of physical frame utilization.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct PhysMmStats {
    /// Total 4 KiB usable frames discovered after applying all exclusions.
    pub total_usable_frames: usize,
    /// Frames currently allocated.
    pub allocated_frames: usize,
    /// Frames currently free and available for allocation.
    pub free_frames: usize,
    /// High-water mark of simultaneously allocated frames since initialization.
    pub peak_allocated_frames: usize,
    /// Cumulative single-frame + multi-frame allocation count (in frames).
    pub total_alloc_ops: u64,
    /// Cumulative freed frame count.
    pub total_free_ops: u64,
    /// Usable frames located at or above `4 GiB` (`0x1_0000_0000`).
    pub high_mem_usable_frames: usize,
}

/// High-memory (`>= 4 GiB`) bitmap arena covering up to `HIGH_EXTENT_WORDS * 64` frames (`512 MiB`).
#[derive(Copy, Clone)]
struct HighExtent {
    /// 4 KiB-aligned base physical address (`>= LOW_4GIB_END`), or `0` when unused.
    base_pa: u64,
    /// Number of valid frame slots tracked by this extent (`<= HIGH_EXTENT_WORDS * 64`).
    frame_cap: usize,
    /// Hint word index for next allocation scan.
    next_word_hint: usize,
    /// Bit `b` of word `w` is `1` iff frame `w * 64 + b` is usable RAM.
    usable_bits: [u64; HIGH_EXTENT_WORDS],
    /// Bit `b` of word `w` is `1` iff frame `w * 64 + b` is currently allocated.
    alloc_bits: [u64; HIGH_EXTENT_WORDS],
}

impl HighExtent {
    const fn empty() -> Self {
        Self {
            base_pa: 0,
            frame_cap: 0,
            next_word_hint: 0,
            usable_bits: [0u64; HIGH_EXTENT_WORDS],
            alloc_bits: [0u64; HIGH_EXTENT_WORDS],
        }
    }

    #[inline]
    fn contains_pa(&self, pa: u64) -> Option<usize> {
        if self.frame_cap == 0 || pa < self.base_pa {
            return None;
        }
        let rel = pa - self.base_pa;
        let idx = (rel / PHYS_FRAME_BYTES) as usize;
        if idx < self.frame_cap {
            Some(idx)
        } else {
            None
        }
    }
}

/// Multi-region physical 4 KiB frame allocator parameterized by low-memory word count `WORDS`.
///
/// Use [`KernelPhysFrameManager`] (`WORDS = 16_384`) in the kernel to cover the full
/// `[0 .. 4 GiB)` low address space plus `4 GiB` of high-memory extents (`8 GiB` total).
pub struct PhysFrameManager<const WORDS: usize> {
    usable_bits: [u64; WORDS],
    alloc_bits: [u64; WORDS],
    next_word_hint: usize,
    high_extents: [HighExtent; MAX_HIGH_EXTENTS],
    total_usable_frames: usize,
    allocated_frames: usize,
    peak_allocated_frames: usize,
    total_alloc_ops: u64,
    total_free_ops: u64,
    high_mem_usable_frames: usize,
    initialized: bool,
}

/// Default kernel-wide physical frame manager type (`4 GiB` low bitmap + `8 x 512 MiB` high extents).
pub type KernelPhysFrameManager = PhysFrameManager<KERNEL_LOW_BITMAP_WORDS>;

impl<const WORDS: usize> PhysFrameManager<WORDS> {
    /// Construct an uninitialized zeroed manager suitable for `.bss` static placement.
    pub const fn empty() -> Self {
        Self {
            usable_bits: [0u64; WORDS],
            alloc_bits: [0u64; WORDS],
            next_word_hint: 0,
            high_extents: [HighExtent::empty(); MAX_HIGH_EXTENTS],
            total_usable_frames: 0,
            allocated_frames: 0,
            peak_allocated_frames: 0,
            total_alloc_ops: 0,
            total_free_ops: 0,
            high_mem_usable_frames: 0,
            initialized: false,
        }
    }

    /// Return `true` once [`Self::init_from_regions`] has completed.
    #[inline]
    pub const fn is_initialized(&self) -> bool {
        self.initialized
    }

    /// Maximum low-memory frame capacity (`WORDS * 64` frames).
    #[inline]
    pub const fn low_frame_capacity(&self) -> usize {
        WORDS * 64
    }

    /// Snapshot current utilization and lifetime counters.
    #[inline]
    pub const fn stats(&self) -> PhysMmStats {
        PhysMmStats {
            total_usable_frames: self.total_usable_frames,
            allocated_frames: self.allocated_frames,
            free_frames: self.total_usable_frames.saturating_sub(self.allocated_frames),
            peak_allocated_frames: self.peak_allocated_frames,
            total_alloc_ops: self.total_alloc_ops,
            total_free_ops: self.total_free_ops,
            high_mem_usable_frames: self.high_mem_usable_frames,
        }
    }

    /// Reset bitmaps and counters prior to streaming region registration (`mark_usable_region` /
    /// `exclude_region` / `finish_init`).
    pub fn begin_init(&mut self) {
        let mut w = 0usize;
        while w < WORDS {
            self.usable_bits[w] = 0;
            self.alloc_bits[w] = 0;
            w += 1;
        }
        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            self.high_extents[h] = HighExtent::empty();
            h += 1;
        }
        self.next_word_hint = 0;
        self.total_usable_frames = 0;
        self.allocated_frames = 0;
        self.peak_allocated_frames = 0;
        self.total_alloc_ops = 0;
        self.total_free_ops = 0;
        self.high_mem_usable_frames = 0;
        self.initialized = false;
    }

    /// Mark an inward-4 KiB-aligned usable RAM interval `[start, end)` during initialization.
    pub fn mark_usable_region(&mut self, start: u64, end: u64) {
        if end <= start {
            return;
        }
        let Some(aligned_start) = align_up_4k(start) else {
            return;
        };
        let aligned_end = end & !(PHYS_FRAME_BYTES - 1);
        if aligned_end <= aligned_start {
            return;
        }
        let low_limit_pa = (WORDS as u64) * 64 * PHYS_FRAME_BYTES;
        if aligned_start < low_limit_pa {
            let lo_end = if aligned_end < low_limit_pa {
                aligned_end
            } else {
                low_limit_pa
            };
            self.set_low_usable_range(aligned_start, lo_end, true);
        }
        if aligned_end > LOW_4GIB_END {
            let hi_start = if aligned_start > LOW_4GIB_END {
                aligned_start
            } else {
                LOW_4GIB_END
            };
            self.add_high_usable_range(hi_start, aligned_end);
        }
    }

    /// Exclude an outward-4 KiB-aligned reserved/DMA/kernel interval `[start, end)` during initialization.
    pub fn exclude_region(&mut self, start: u64, end: u64) {
        if end > start {
            self.exclude_range_outward(start, end);
        }
    }

    /// Finalize streaming initialization: enforce `[0 .. 1 MiB)` exclusion, recount usable frames,
    /// and prime scan hints.
    pub fn finish_init(&mut self) {
        self.exclude_range_outward(0, LOW_CONVENTIONAL_EXCLUDE_END);
        let mut low_usable = 0usize;
        let mut first_hint: Option<usize> = None;
        let mut wi = 0usize;
        while wi < WORDS {
            let bits = self.usable_bits[wi];
            if bits != 0 {
                low_usable += bits.count_ones() as usize;
                if first_hint.is_none() {
                    first_hint = Some(wi);
                }
            }
            wi += 1;
        }
        self.next_word_hint = first_hint.unwrap_or(0);

        let mut hi_usable = 0usize;
        let mut hi = 0usize;
        while hi < MAX_HIGH_EXTENTS {
            let ext = &mut self.high_extents[hi];
            if ext.frame_cap > 0 {
                let mut ext_first: Option<usize> = None;
                let mut ew = 0usize;
                while ew < HIGH_EXTENT_WORDS {
                    let b = ext.usable_bits[ew];
                    if b != 0 {
                        hi_usable += b.count_ones() as usize;
                        if ext_first.is_none() {
                            ext_first = Some(ew);
                        }
                    }
                    ew += 1;
                }
                ext.next_word_hint = ext_first.unwrap_or(0);
            }
            hi += 1;
        }

        self.high_mem_usable_frames = hi_usable;
        self.total_usable_frames = low_usable + hi_usable;
        self.initialized = true;
    }

    /// Initialize usable physical frames from firmware `regions` and explicit `(start, end)` byte `exclusions`.
    ///
    /// - Usable regions are rounded **inward** to 4 KiB page boundaries so partial edge pages are never claimed.
    /// - Non-usable regions, `[0 .. 1 MiB)`, and `exclusions` are rounded **outward** to 4 KiB boundaries so any
    ///   page touched by a reserved range fails closed.
    pub fn init_from_regions(&mut self, regions: &[PhysRegionDesc], exclusions: &[(u64, u64)]) {
        self.begin_init();
        let mut r_idx = 0usize;
        while r_idx < regions.len() {
            let reg = regions[r_idx];
            if reg.usable && reg.end > reg.start {
                self.mark_usable_region(reg.start, reg.end);
            }
            r_idx += 1;
        }
        let mut nr_idx = 0usize;
        while nr_idx < regions.len() {
            let reg = regions[nr_idx];
            if !reg.usable && reg.end > reg.start {
                self.exclude_region(reg.start, reg.end);
            }
            nr_idx += 1;
        }
        let mut ex_idx = 0usize;
        while ex_idx < exclusions.len() {
            let (s, e) = exclusions[ex_idx];
            self.exclude_region(s, e);
            ex_idx += 1;
        }
        self.finish_init();
    }

    fn set_low_usable_range(&mut self, start_pa: u64, end_pa: u64, usable: bool) {
        let max_frames = WORDS * 64;
        let start_idx = (start_pa / PHYS_FRAME_BYTES) as usize;
        let end_idx_raw = (end_pa / PHYS_FRAME_BYTES) as usize;
        let end_idx = if end_idx_raw > max_frames {
            max_frames
        } else {
            end_idx_raw
        };
        if start_idx >= end_idx {
            return;
        }
        let mut idx = start_idx;
        while idx < end_idx {
            let w = idx / 64;
            let bit = idx % 64;
            if bit == 0 && idx + 64 <= end_idx {
                self.usable_bits[w] = if usable { u64::MAX } else { 0 };
                idx += 64;
            } else {
                let mask = 1u64 << bit;
                if usable {
                    self.usable_bits[w] |= mask;
                } else {
                    self.usable_bits[w] &= !mask;
                }
                idx += 1;
            }
        }
    }

    fn add_high_usable_range(&mut self, mut cur_pa: u64, end_pa: u64) {
        let extent_span_bytes = (HIGH_EXTENT_WORDS as u64) * 64 * PHYS_FRAME_BYTES;
        while cur_pa < end_pa {
            let chunk_end = match cur_pa.checked_add(extent_span_bytes) {
                Some(v) if v < end_pa => v,
                _ => end_pa,
            };
            // Try merging into an existing extent if `[cur_pa, chunk_end)` falls inside its 512 MiB window.
            let mut target_slot: Option<usize> = None;
            let mut s = 0usize;
            while s < MAX_HIGH_EXTENTS {
                let ext = &self.high_extents[s];
                if ext.frame_cap > 0 && cur_pa >= ext.base_pa {
                    let max_end = ext.base_pa.saturating_add(extent_span_bytes);
                    if cur_pa < max_end {
                        target_slot = Some(s);
                        break;
                    }
                }
                s += 1;
            }
            if target_slot.is_none() {
                let mut e_slot = 0usize;
                while e_slot < MAX_HIGH_EXTENTS {
                    if self.high_extents[e_slot].frame_cap == 0 {
                        self.high_extents[e_slot].base_pa = cur_pa;
                        target_slot = Some(e_slot);
                        break;
                    }
                    e_slot += 1;
                }
            }
            let Some(slot) = target_slot else {
                // High-extent descriptor slots full; stop cleanly without panicking.
                break;
            };
            let ext = &mut self.high_extents[slot];
            let max_end = ext.base_pa.saturating_add(extent_span_bytes);
            let sub_end = if chunk_end < max_end {
                chunk_end
            } else {
                max_end
            };
            let start_off = ((cur_pa - ext.base_pa) / PHYS_FRAME_BYTES) as usize;
            let end_off = ((sub_end - ext.base_pa) / PHYS_FRAME_BYTES) as usize;
            if end_off > ext.frame_cap {
                ext.frame_cap = end_off;
            }
            let mut f = start_off;
            while f < end_off {
                let w = f / 64;
                let b = f % 64;
                if b == 0 && f + 64 <= end_off {
                    ext.usable_bits[w] = u64::MAX;
                    f += 64;
                } else {
                    ext.usable_bits[w] |= 1u64 << b;
                    f += 1;
                }
            }
            cur_pa = sub_end;
        }
    }

    fn exclude_range_outward(&mut self, raw_start: u64, raw_end: u64) {
        let start = raw_start & !(PHYS_FRAME_BYTES - 1);
        let end = match align_up_4k(raw_end) {
            Some(v) => v,
            None => u64::MAX & !(PHYS_FRAME_BYTES - 1),
        };
        if end <= start {
            return;
        }
        let low_limit_pa = (WORDS as u64) * 64 * PHYS_FRAME_BYTES;
        if start < low_limit_pa {
            let lo_end = if end < low_limit_pa { end } else { low_limit_pa };
            self.set_low_usable_range(start, lo_end, false);
        }
        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            let ext = &mut self.high_extents[h];
            if ext.frame_cap > 0 {
                let ext_end = ext.base_pa.saturating_add((ext.frame_cap as u64) * PHYS_FRAME_BYTES);
                let ov_start = if start > ext.base_pa { start } else { ext.base_pa };
                let ov_end = if end < ext_end { end } else { ext_end };
                if ov_end > ov_start {
                    let s_idx = ((ov_start - ext.base_pa) / PHYS_FRAME_BYTES) as usize;
                    let e_idx = ((ov_end - ext.base_pa) / PHYS_FRAME_BYTES) as usize;
                    let mut i = s_idx;
                    while i < e_idx {
                        ext.usable_bits[i / 64] &= !(1u64 << (i % 64));
                        i += 1;
                    }
                }
            }
            h += 1;
        }
    }

    #[inline]
    fn record_alloc(&mut self, n_frames: usize) {
        self.allocated_frames += n_frames;
        if self.allocated_frames > self.peak_allocated_frames {
            self.peak_allocated_frames = self.allocated_frames;
        }
        self.total_alloc_ops = self.total_alloc_ops.wrapping_add(n_frames as u64);
    }

    /// Allocate one 4 KiB physical frame strictly below `4 GiB` (`0x1_0000_0000`),
    /// suitable for 32-bit DMA descriptors and general low-memory use.
    pub fn alloc_frame_low32(&mut self) -> Option<u64> {
        if self.allocated_frames >= self.total_usable_frames || WORDS == 0 {
            return None;
        }
        let hint = if self.next_word_hint < WORDS {
            self.next_word_hint
        } else {
            0
        };
        let mut pass = 0usize;
        while pass < 2 {
            let (start_w, end_w) = if pass == 0 { (hint, WORDS) } else { (0, hint) };
            let mut w = start_w;
            while w < end_w {
                let avail = self.usable_bits[w] & !self.alloc_bits[w];
                if avail != 0 {
                    let bit = avail.trailing_zeros() as usize;
                    self.alloc_bits[w] |= 1u64 << bit;
                    self.next_word_hint = w;
                    self.record_alloc(1);
                    let frame_idx = w * 64 + bit;
                    return Some((frame_idx as u64) * PHYS_FRAME_BYTES);
                }
                w += 1;
            }
            pass += 1;
        }
        None
    }

    /// Allocate one 4 KiB physical frame from any usable RAM region (preferring low-4 GiB first,
    /// then high-memory extents `>= 4 GiB`).
    pub fn alloc_frame(&mut self) -> Option<u64> {
        if let Some(pa) = self.alloc_frame_low32() {
            return Some(pa);
        }
        if self.allocated_frames >= self.total_usable_frames {
            return None;
        }
        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            let ext = &mut self.high_extents[h];
            if ext.frame_cap > 0 {
                let words = (ext.frame_cap + 63) / 64;
                let hint = if ext.next_word_hint < words {
                    ext.next_word_hint
                } else {
                    0
                };
                let mut pass = 0usize;
                while pass < 2 {
                    let (sw, ew) = if pass == 0 { (hint, words) } else { (0, hint) };
                    let mut w = sw;
                    while w < ew {
                        let avail = ext.usable_bits[w] & !ext.alloc_bits[w];
                        if avail != 0 {
                            let bit = avail.trailing_zeros() as usize;
                            let idx = w * 64 + bit;
                            if idx < ext.frame_cap {
                                ext.alloc_bits[w] |= 1u64 << bit;
                                ext.next_word_hint = w;
                                let pa = ext.base_pa + (idx as u64) * PHYS_FRAME_BYTES;
                                self.record_alloc(1);
                                return Some(pa);
                            }
                        }
                        w += 1;
                    }
                    pass += 1;
                }
            }
            h += 1;
        }
        None
    }

    /// Allocate `count` contiguous 4 KiB physical frames whose base frame index is aligned
    /// to `align_frames` (must be a non-zero power of two).
    pub fn alloc_contiguous(
        &mut self,
        count: usize,
        align_frames: usize,
    ) -> Result<u64, PhysMmError> {
        if count == 0 {
            return Err(PhysMmError::ZeroFrameCount);
        }
        if align_frames == 0 || !align_frames.is_power_of_two() {
            return Err(PhysMmError::InvalidAlignment);
        }
        let free = self.total_usable_frames.saturating_sub(self.allocated_frames);
        if count > free {
            return Err(PhysMmError::OutOfMemory);
        }
        if count == 1 && align_frames == 1 {
            return self.alloc_frame().ok_or(PhysMmError::OutOfMemory);
        }

        // 1. Scan low-4 GiB bitmap.
        let total_low_frames = WORDS * 64;
        let mut base = align_up_usize(self.next_word_hint * 64, align_frames);
        let mut pass = 0usize;
        while pass < 2 {
            let limit = if pass == 0 {
                total_low_frames
            } else {
                (self.next_word_hint * 64).saturating_add(count)
            };
            if pass == 1 {
                base = 0;
            }
            while base.checked_add(count).map_or(false, |end| end <= total_low_frames && base < limit)
            {
                let mut ok = true;
                let mut fail_idx = base;
                let mut k = 0usize;
                while k < count {
                    let f = base + k;
                    let w = f / 64;
                    let mask = 1u64 << (f % 64);
                    if (self.usable_bits[w] & mask) == 0 || (self.alloc_bits[w] & mask) != 0 {
                        ok = false;
                        fail_idx = f;
                        break;
                    }
                    k += 1;
                }
                if ok {
                    let mut m = 0usize;
                    while m < count {
                        let f = base + m;
                        self.alloc_bits[f / 64] |= 1u64 << (f % 64);
                        m += 1;
                    }
                    self.record_alloc(count);
                    return Ok((base as u64) * PHYS_FRAME_BYTES);
                }
                base = align_up_usize(fail_idx + 1, align_frames);
            }
            pass += 1;
        }

        // 2. Scan high-memory extents `>= 4 GiB`.
        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            if self.high_extents[h].frame_cap >= count {
                let ext_base_frame = (self.high_extents[h].base_pa / PHYS_FRAME_BYTES) as usize;
                let cap = self.high_extents[h].frame_cap;
                let mut rel = 0usize;
                while rel + count <= cap {
                    let abs_frame = ext_base_frame + rel;
                    if (abs_frame & (align_frames - 1)) != 0 {
                        let next_abs = align_up_usize(abs_frame, align_frames);
                        rel = next_abs - ext_base_frame;
                        continue;
                    }
                    let mut ok = true;
                    let mut fail_rel = rel;
                    let mut k = 0usize;
                    while k < count {
                        let idx = rel + k;
                        let mask = 1u64 << (idx % 64);
                        let ext = &self.high_extents[h];
                        if (ext.usable_bits[idx / 64] & mask) == 0
                            || (ext.alloc_bits[idx / 64] & mask) != 0
                        {
                            ok = false;
                            fail_rel = idx;
                            break;
                        }
                        k += 1;
                    }
                    if ok {
                        let base_pa =
                            self.high_extents[h].base_pa + (rel as u64) * PHYS_FRAME_BYTES;
                        let mut m = 0usize;
                        while m < count {
                            let idx = rel + m;
                            self.high_extents[h].alloc_bits[idx / 64] |= 1u64 << (idx % 64);
                            m += 1;
                        }
                        self.record_alloc(count);
                        return Ok(base_pa);
                    }
                    rel = fail_rel + 1;
                }
            }
            h += 1;
        }

        Err(PhysMmError::OutOfMemory)
    }

    /// Free one previously allocated 4 KiB physical frame, rejecting unaligned,
    /// reserved, or already-free addresses.
    pub fn free_frame(&mut self, pa: u64) -> Result<(), PhysMmError> {
        if (pa & (PHYS_FRAME_BYTES - 1)) != 0 {
            return Err(PhysMmError::UnalignedAddress);
        }
        let low_limit_pa = (WORDS as u64) * 64 * PHYS_FRAME_BYTES;
        if pa < low_limit_pa {
            let idx = (pa / PHYS_FRAME_BYTES) as usize;
            let w = idx / 64;
            let mask = 1u64 << (idx % 64);
            if (self.usable_bits[w] & mask) == 0 {
                return Err(PhysMmError::ReservedOrInvalidFrame);
            }
            if (self.alloc_bits[w] & mask) == 0 {
                return Err(PhysMmError::DoubleFree);
            }
            self.alloc_bits[w] &= !mask;
            if w < self.next_word_hint {
                self.next_word_hint = w;
            }
            self.allocated_frames -= 1;
            self.total_free_ops = self.total_free_ops.wrapping_add(1);
            return Ok(());
        }

        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            if let Some(idx) = self.high_extents[h].contains_pa(pa) {
                let w = idx / 64;
                let mask = 1u64 << (idx % 64);
                let ext = &mut self.high_extents[h];
                if (ext.usable_bits[w] & mask) == 0 {
                    return Err(PhysMmError::ReservedOrInvalidFrame);
                }
                if (ext.alloc_bits[w] & mask) == 0 {
                    return Err(PhysMmError::DoubleFree);
                }
                ext.alloc_bits[w] &= !mask;
                if w < ext.next_word_hint {
                    ext.next_word_hint = w;
                }
                self.allocated_frames -= 1;
                self.total_free_ops = self.total_free_ops.wrapping_add(1);
                return Ok(());
            }
            h += 1;
        }
        Err(PhysMmError::ReservedOrInvalidFrame)
    }

    /// Free `count` contiguous 4 KiB physical frames starting at `base_pa` atomically:
    /// validates every frame before mutating any allocation bit.
    pub fn free_contiguous(&mut self, base_pa: u64, count: usize) -> Result<(), PhysMmError> {
        if count == 0 {
            return Err(PhysMmError::ZeroFrameCount);
        }
        if (base_pa & (PHYS_FRAME_BYTES - 1)) != 0 {
            return Err(PhysMmError::UnalignedAddress);
        }
        // Pre-validate all `count` frames so an invalid span never leaves a half-freed state.
        let mut k = 0usize;
        while k < count {
            let pa = base_pa
                .checked_add((k as u64) * PHYS_FRAME_BYTES)
                .ok_or(PhysMmError::ReservedOrInvalidFrame)?;
            if !self.is_usable(pa) {
                return Err(PhysMmError::ReservedOrInvalidFrame);
            }
            if !self.is_allocated(pa) {
                return Err(PhysMmError::DoubleFree);
            }
            k += 1;
        }
        let mut m = 0usize;
        while m < count {
            let pa = base_pa + (m as u64) * PHYS_FRAME_BYTES;
            let _ = self.free_frame(pa);
            m += 1;
        }
        Ok(())
    }

    /// Return `true` iff `pa` is 4 KiB-aligned and belongs to usable physical RAM.
    pub fn is_usable(&self, pa: u64) -> bool {
        if (pa & (PHYS_FRAME_BYTES - 1)) != 0 {
            return false;
        }
        let low_limit_pa = (WORDS as u64) * 64 * PHYS_FRAME_BYTES;
        if pa < low_limit_pa {
            let idx = (pa / PHYS_FRAME_BYTES) as usize;
            return (self.usable_bits[idx / 64] & (1u64 << (idx % 64))) != 0;
        }
        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            if let Some(idx) = self.high_extents[h].contains_pa(pa) {
                return (self.high_extents[h].usable_bits[idx / 64] & (1u64 << (idx % 64))) != 0;
            }
            h += 1;
        }
        false
    }

    /// Return `true` iff `pa` is 4 KiB-aligned and currently allocated.
    pub fn is_allocated(&self, pa: u64) -> bool {
        if (pa & (PHYS_FRAME_BYTES - 1)) != 0 {
            return false;
        }
        let low_limit_pa = (WORDS as u64) * 64 * PHYS_FRAME_BYTES;
        if pa < low_limit_pa {
            let idx = (pa / PHYS_FRAME_BYTES) as usize;
            return (self.alloc_bits[idx / 64] & (1u64 << (idx % 64))) != 0;
        }
        let mut h = 0usize;
        while h < MAX_HIGH_EXTENTS {
            if let Some(idx) = self.high_extents[h].contains_pa(pa) {
                return (self.high_extents[h].alloc_bits[idx / 64] & (1u64 << (idx % 64))) != 0;
            }
            h += 1;
        }
        false
    }
}

/// Zero-scrub a physical frame or slab slice and emit a SeqCst compiler fence
/// so the compiler cannot dead-store-eliminate the scrub when memory is freed.
#[inline]
pub fn scrub_frame_bytes(buf: &mut [u8]) {
    buf.fill(0);
    compiler_fence(Ordering::SeqCst);
}

/// Abstract 4 KiB physical frame allocator and byte/word accessor used by
/// [`crate::proc_vm::ProcessTable`] so multi-page ELF64 loading, KPTI page-table
/// synthesis, `PROC_SYS_BRK` demand paging, and 100% fault frame reclamation are
/// verified deterministically on the host as well as over `KERNEL_PHYS_MM` in Ring-0.
pub trait PageFrameSource {
    /// Allocate a zero-scrubbed 4 KiB physical frame (`>= 0x1000`, 4 KiB-aligned).
    fn alloc_zeroed_frame(&mut self) -> Option<u64>;

    /// Zero-scrub and release a previously allocated 4 KiB physical frame.
    fn free_zeroed_frame(&mut self, pa: u64);

    /// Read `out.len()` bytes starting at `offset` (`offset + out.len() <= 4096`) within `pa`.
    fn read_frame_bytes(&self, pa: u64, offset: usize, out: &mut [u8]);

    /// Write `data.len()` bytes starting at `offset` (`offset + data.len() <= 4096`) within `pa`.
    fn write_frame_bytes(&mut self, pa: u64, offset: usize, data: &[u8]);

    /// Populate all 512 little-endian `u64` entries (`4096` bytes) of a page-table frame `pa`.
    fn write_frame_u64s(&mut self, pa: u64, words: &[u64; 512]) {
        let mut i = 0usize;
        while i < 512 {
            self.write_frame_bytes(pa, i * 8, &words[i].to_le_bytes());
            i += 1;
        }
    }

    /// Write a single 64-bit page-table entry at `index` (`0..512`) inside frame `pa`.
    fn write_frame_u64_at(&mut self, pa: u64, index: usize, word: u64) {
        self.write_frame_bytes(pa, index * 8, &word.to_le_bytes());
    }

    /// Read a single 64-bit page-table entry at `index` (`0..512`) inside frame `pa`.
    fn read_frame_u64_at(&self, pa: u64, index: usize) -> u64 {
        let mut b = [0u8; 8];
        self.read_frame_bytes(pa, index * 8, &mut b);
        u64::from_le_bytes(b)
    }
}

#[inline]
const fn align_up_4k(addr: u64) -> Option<u64> {
    match addr.checked_add(PHYS_FRAME_BYTES - 1) {
        Some(v) => Some(v & !(PHYS_FRAME_BYTES - 1)),
        None => None,
    }
}

#[inline]
const fn align_up_usize(val: usize, align: usize) -> usize {
    let mask = align - 1;
    (val + mask) & !mask
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn e820_and_uefi_regions_exclude_low_1mib_dma_overlaps_and_support_high_4gib_ram() {
        let mut pmm: PhysFrameManager<256> = PhysFrameManager::empty();
        // 256 words = 16,384 frames = 64 MiB low bitmap + high extents >= 4 GiB.
        let regions = [
            // Conventional low RAM `< 1 MiB` must be completely excluded even if marked usable.
            PhysRegionDesc {
                start: 0x0,
                end: 0x0009_FC00,
                usable: true,
            },
            // Main low usable RAM `[1 MiB + 128 B .. 32 MiB - 77 B)` (unaligned edges must round inward!).
            PhysRegionDesc {
                start: 0x0010_0080,
                end: 0x0200_0000 - 77,
                usable: true,
            },
            // Dirty BIOS/ACPI NVS hole overlapping the middle of usable RAM `[0x0080_0100 .. 0x0080_1F00)`
            // -> outward rounding must exclude TWO full frames (`0x0080_0000` and `0x0080_1000`).
            PhysRegionDesc {
                start: 0x0080_0100,
                end: 0x0080_1F00,
                usable: false,
            },
            // High UEFI RAM above 4 GiB: `[4 GiB .. 4 GiB + 8 MiB)` = 2,048 frames.
            PhysRegionDesc {
                start: LOW_4GIB_END,
                end: LOW_4GIB_END + 8 * 1024 * 1024,
                usable: true,
            },
        ];
        // Kernel DMA window `[0x0010_1000 .. 0x0016_1000)` (`384 KiB` = `96` frames).
        let exclusions = [(0x0010_1000u64, 0x0016_1000u64)];
        pmm.init_from_regions(&regions, &exclusions);

        assert!(pmm.is_initialized());
        // Check edge rounding and exclusions:
        assert!(!pmm.is_usable(0x0000_8000), "SMP trampoline < 1 MiB must never be usable");
        assert!(!pmm.is_usable(0x0010_0000), "unaligned start 0x100080 must round inward to 0x101000");
        assert!(!pmm.is_usable(0x0010_1000), "DMA window start must be excluded");
        assert!(!pmm.is_usable(0x0016_0000), "DMA window last frame must be excluded");
        assert!(pmm.is_usable(0x0016_1000), "first frame above DMA window must be usable");
        assert!(!pmm.is_usable(0x0080_0000), "overlapping ACPI NVS frame 0 must fail closed");
        assert!(!pmm.is_usable(0x0080_1000), "overlapping ACPI NVS frame 1 must fail closed");
        assert!(!pmm.is_usable(0x01FF_F000), "unaligned end must round inward");
        assert!(pmm.is_usable(0x01FF_E000));
        assert!(pmm.is_usable(LOW_4GIB_END), "high RAM >= 4 GiB must be usable");

        let st = pmm.stats();
        assert_eq!(st.high_mem_usable_frames, 2048);
        // Low frames: `[0x101000 .. 0x1FFF000)` = 8191 - 257 = 7934 frames minus 96 DMA minus 2 NVS = 7836.
        assert_eq!(st.total_usable_frames, 7836 + 2048);
    }

    #[test]
    fn allocate_beyond_40_frame_legacy_limit_double_free_and_contiguous_aligned_spans() {
        let mut pmm: PhysFrameManager<64> = PhysFrameManager::empty();
        pmm.init_from_regions(
            &[
                PhysRegionDesc {
                    start: 0x0020_0000,
                    end: 0x0060_0000, // 4 MiB = 1024 frames
                    usable: true,
                },
                PhysRegionDesc {
                    start: LOW_4GIB_END + 0x10_0000,
                    end: LOW_4GIB_END + 0x30_0000, // 2 MiB = 512 high frames
                    usable: true,
                },
            ],
            &[],
        );

        let initial_free = pmm.stats().free_frames;
        assert_eq!(initial_free, 1024 + 512);

        // 1. Allocate 256 single frames (6.4x the old 40-frame kernel PT_ALLOC_NEXT panic limit).
        let mut frames = [0u64; 256];
        for slot in &mut frames {
            *slot = pmm.alloc_frame().expect("must allocate > 40 frames cleanly");
        }
        // Pairwise distinct check.
        for i in 0..frames.len() {
            for j in (i + 1)..frames.len() {
                assert_ne!(frames[i], frames[j], "duplicate physical frame handed out");
            }
        }

        // 2. Contiguous 16-frame (`64 KiB`) allocation aligned to 16 frames (`64 KiB`).
        let contig = pmm
            .alloc_contiguous(16, 16)
            .expect("16-frame 64 KiB-aligned DMA span must succeed");
        assert_eq!(contig % (16 * 4096), 0);
        for k in 0..16 {
            assert!(pmm.is_allocated(contig + (k as u64) * 4096));
        }

        // 3. Error discipline: unaligned, reserved, and double-free must be rejected without corrupting counts.
        assert_eq!(pmm.free_frame(contig + 123), Err(PhysMmError::UnalignedAddress));
        assert_eq!(pmm.free_frame(0xFEE0_0000), Err(PhysMmError::ReservedOrInvalidFrame));
        pmm.free_frame(frames[10]).expect("valid free must succeed");
        assert_eq!(pmm.free_frame(frames[10]), Err(PhysMmError::DoubleFree));

        // Partial invalid `free_contiguous` must reject atomically without freeing the valid prefix!
        assert_eq!(
            pmm.free_contiguous(frames[10], 4),
            Err(PhysMmError::DoubleFree),
            "span starting on already-freed frame must fail closed"
        );
        assert!(
            pmm.is_allocated(frames[11]),
            "failed free_contiguous must not partially free later frames"
        );

        // 4. Drain remaining low frames and verify seamless spillover into >= 4 GiB high memory!
        let mut high_seen = false;
        let mut extra = alloc::vec::Vec::new();
        while let Some(pa) = pmm.alloc_frame() {
            if pa >= LOW_4GIB_END {
                high_seen = true;
            }
            extra.push(pa);
        }
        assert!(high_seen, "allocator must spill into >= 4 GiB high extents when low RAM fills");
        assert_eq!(pmm.stats().free_frames, 0);
        assert_eq!(pmm.alloc_frame_low32(), None);

        // 5. Reclaim 100% of allocated frames and verify exact conservation.
        for (idx, &pa) in frames.iter().enumerate() {
            if idx != 10 {
                pmm.free_frame(pa).unwrap();
            }
        }
        pmm.free_contiguous(contig, 16).unwrap();
        for pa in extra {
            pmm.free_frame(pa).unwrap();
        }
        assert_eq!(pmm.stats().allocated_frames, 0);
        assert_eq!(pmm.stats().free_frames, initial_free);

        // 6. Zero-scrub helper check.
        let mut dirty = [0xA5u8; 4096];
        scrub_frame_bytes(&mut dirty);
        assert!(dirty.iter().all(|&b| b == 0));
    }
}
