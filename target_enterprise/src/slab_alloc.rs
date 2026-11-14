//! Segregated size-class slab & multi-page kernel allocator (`slab_alloc`).
//!
//! Eliminates external heap fragmentation under sustained TCP/TLS/process churn
//! and scales dynamically across arbitrary physical RAM via [`PageBackend`]:
//!
//! - **8 segregated power-of-two size classes** (`32, 64, 128, 256, 512, 1024, 2048, 4096` B).
//! - **Out-of-line slab metadata**: zero allocator headers or free-list pointers are
//!   stored inside data pages, preventing heap buffer overflows from corrupting
//!   allocator control structures and guaranteeing natural alignment up to `4096 B`.
//! - **Tombstone-free `O(1)` page hash tables** (Knuth Algorithm R backshift deletion)
//!   for constant-time `dealloc` without linear descriptor scans or tombstone buildup.
//! - **Warm cache hysteresis + physical reclamation**: retains up to
//!   [`WARM_EMPTY_SLABS_PER_CLASS`] empty 4 KiB slabs per class for zero-lock-contention
//!   reuse and returns excess empty pages directly to [`PageBackend`].

/// Hardware page size backing every slab (`4 KiB`).
pub const SLAB_PAGE_BYTES: usize = 4096;

/// Number of segregated small/page size classes (`32 B ..= 4096 B`).
pub const NUM_SIZE_CLASSES: usize = 8;

/// Byte sizes of the 8 segregated slab classes.
pub const CLASS_SIZES: [usize; NUM_SIZE_CLASSES] = [32, 64, 128, 256, 512, 1024, 2048, 4096];

/// Number of objects packed into a single 4 KiB slab page for each class.
pub const CLASS_SLOTS: [usize; NUM_SIZE_CLASSES] = [128, 64, 32, 16, 8, 4, 2, 1];

/// Maximum empty 4 KiB slab pages retained warm per size class before returning
/// frames to the underlying physical [`PageBackend`].
pub const WARM_EMPTY_SLABS_PER_CLASS: usize = 2;

/// Default kernel slab descriptor table capacity (`2,048` slabs = up to `8 MiB` of small objects,
/// or up to `262,144` concurrent `32 B` allocations).
pub const KERNEL_MAX_SLABS: usize = 2048;

/// Open-addressed hash table bucket count for `KERNEL_MAX_SLABS` (power of two, load factor `<= 0.5`).
pub const KERNEL_SLAB_HASH_BUCKETS: usize = 4096;

/// Default kernel large multi-page span table capacity (`512` concurrent `> 4 KiB` spans).
pub const KERNEL_MAX_LARGE_SPANS: usize = 512;

/// Open-addressed hash table bucket count for `KERNEL_MAX_LARGE_SPANS` (power of two, load factor `<= 0.5`).
pub const KERNEL_LARGE_HASH_BUCKETS: usize = 1024;

const EMPTY_BUCKET: u16 = u16::MAX;

/// Backing page provider supplying zeroed 4 KiB-aligned virtual pages (e.g. `pa_to_va(pa)`
/// over [`crate::phys_mm::PhysFrameManager`]).
pub trait PageBackend {
    /// Allocate `count` contiguous 4 KiB pages aligned to `align_pages` (power of two),
    /// returning the 4 KiB-aligned virtual base address, or `None` if out of memory.
    fn alloc_pages(&mut self, count: usize, align_pages: usize) -> Option<usize>;

    /// Reclaim `count` contiguous 4 KiB pages starting at `base_va`.
    fn free_pages(&mut self, base_va: usize, count: usize);

    /// Total free 4 KiB pages currently available in the underlying physical pool.
    fn free_page_count(&self) -> usize;
}

/// Errors returned by [`SlabAllocator::dealloc`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SlabError {
    /// Pointer does not belong to any active slab or large multi-page span.
    UnknownAddress,
    /// Pointer is misaligned for its slab class or page boundary.
    MisalignedSlot,
    /// Deallocation size/alignment class does not match the owning slab or span.
    LayoutMismatch,
    /// Slot in the owning slab was already free.
    DoubleFree,
}

/// Utilization snapshot of a [`SlabAllocator`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct SlabStats {
    /// Total bytes currently handed out across all active slab slots and large spans.
    pub used_bytes: usize,
    /// Total bytes backed by currently claimed 4 KiB slab + large pages.
    pub mapped_bytes: usize,
    /// Number of active 4 KiB slab pages (including warm empty slabs).
    pub active_slabs: usize,
    /// Number of warm empty 4 KiB slab pages currently cached.
    pub empty_cached_slabs: usize,
    /// Number of active multi-page (`> 4 KiB`) spans.
    pub active_large_spans: usize,
    /// Cumulative allocation count.
    pub total_allocs: u64,
    /// Cumulative deallocation count.
    pub total_deallocs: u64,
}

#[derive(Copy, Clone)]
struct SlabMeta {
    /// 4 KiB-aligned base virtual address (`0` when descriptor is unused).
    page_va: usize,
    /// Size class index (`0..NUM_SIZE_CLASSES`).
    class_idx: u8,
    /// Number of currently allocated slots (`0..=128`).
    in_use: u16,
    /// Allocation bitmap for slots `0..64`.
    used_lo: u64,
    /// Allocation bitmap for slots `64..128` (used by 32-byte class 0).
    used_hi: u64,
}

impl SlabMeta {
    const fn empty() -> Self {
        Self {
            page_va: 0,
            class_idx: 0,
            in_use: 0,
            used_lo: 0,
            used_hi: 0,
        }
    }

    #[inline]
    fn alloc_slot(&mut self) -> Option<usize> {
        let cap = CLASS_SLOTS[self.class_idx as usize];
        if (self.in_use as usize) >= cap {
            return None;
        }
        let lo_cap = if cap > 64 { 64 } else { cap };
        let lo_mask = if lo_cap == 64 {
            u64::MAX
        } else {
            (1u64 << lo_cap) - 1
        };
        let free_lo = (!self.used_lo) & lo_mask;
        if free_lo != 0 {
            let bit = free_lo.trailing_zeros() as usize;
            self.used_lo |= 1u64 << bit;
            self.in_use += 1;
            return Some(bit);
        }
        if cap > 64 {
            let hi_cap = cap - 64;
            let hi_mask = if hi_cap == 64 {
                u64::MAX
            } else {
                (1u64 << hi_cap) - 1
            };
            let free_hi = (!self.used_hi) & hi_mask;
            if free_hi != 0 {
                let bit = free_hi.trailing_zeros() as usize;
                self.used_hi |= 1u64 << bit;
                self.in_use += 1;
                return Some(64 + bit);
            }
        }
        None
    }

    #[inline]
    fn free_slot(&mut self, slot: usize) -> Result<(), SlabError> {
        let cap = CLASS_SLOTS[self.class_idx as usize];
        if slot >= cap {
            return Err(SlabError::MisalignedSlot);
        }
        if slot < 64 {
            let mask = 1u64 << slot;
            if (self.used_lo & mask) == 0 {
                return Err(SlabError::DoubleFree);
            }
            self.used_lo &= !mask;
        } else {
            let mask = 1u64 << (slot - 64);
            if (self.used_hi & mask) == 0 {
                return Err(SlabError::DoubleFree);
            }
            self.used_hi &= !mask;
        }
        self.in_use -= 1;
        Ok(())
    }
}

#[derive(Copy, Clone)]
struct LargeSpanMeta {
    base_va: usize,
    page_count: usize,
}

impl LargeSpanMeta {
    const fn empty() -> Self {
        Self {
            base_va: 0,
            page_count: 0,
        }
    }
}

/// Map `(size, align)` to one of the 8 segregated size classes (`0..8`), or `None`
/// if `max(size, align) > 4096`.
#[inline]
pub const fn size_class_for(size: usize, align: usize) -> Option<usize> {
    let req_size = if size == 0 { 1 } else { size };
    let effective = if req_size > align { req_size } else { align };
    if effective > SLAB_PAGE_BYTES {
        return None;
    }
    let mut c = 0usize;
    while c < NUM_SIZE_CLASSES {
        if CLASS_SIZES[c] >= effective {
            return Some(c);
        }
        c += 1;
    }
    None
}

#[inline]
const fn hash_page_va(page_va: usize, buckets_mask: usize) -> usize {
    let pfn = (page_va >> 12) as u64;
    let mixed = pfn.wrapping_mul(0x9E37_79B9_7F4A_7C15);
    ((mixed >> 32) as usize ^ (mixed as usize)) & buckets_mask
}

/// Out-of-line segregated size-class slab and multi-page span allocator.
pub struct SlabAllocator<
    const MAX_SLABS: usize,
    const SLAB_BUCKETS: usize,
    const MAX_LARGE: usize,
    const LARGE_BUCKETS: usize,
> {
    slabs: [SlabMeta; MAX_SLABS],
    slab_hash: [u16; SLAB_BUCKETS],
    slab_free_cursor: usize,
    class_hint: [u16; NUM_SIZE_CLASSES],
    class_empty_count: [usize; NUM_SIZE_CLASSES],
    large_spans: [LargeSpanMeta; MAX_LARGE],
    large_hash: [u16; LARGE_BUCKETS],
    large_free_cursor: usize,
    used_bytes: usize,
    mapped_pages: usize,
    active_slabs: usize,
    active_large_spans: usize,
    total_allocs: u64,
    total_deallocs: u64,
}

/// Default kernel slab allocator configuration (`2,048` slabs + `512` large spans).
pub type KernelSlabAllocator = SlabAllocator<
    KERNEL_MAX_SLABS,
    KERNEL_SLAB_HASH_BUCKETS,
    KERNEL_MAX_LARGE_SPANS,
    KERNEL_LARGE_HASH_BUCKETS,
>;

impl<
        const MAX_SLABS: usize,
        const SLAB_BUCKETS: usize,
        const MAX_LARGE: usize,
        const LARGE_BUCKETS: usize,
    > SlabAllocator<MAX_SLABS, SLAB_BUCKETS, MAX_LARGE, LARGE_BUCKETS>
{
    /// Construct an empty `.bss`-friendly slab allocator.
    ///
    /// `SLAB_BUCKETS` and `LARGE_BUCKETS` must be powers of two strictly greater
    /// than `MAX_SLABS` and `MAX_LARGE` respectively.
    pub const fn empty() -> Self {
        assert!(SLAB_BUCKETS.is_power_of_two() && SLAB_BUCKETS > MAX_SLABS);
        assert!(LARGE_BUCKETS.is_power_of_two() && LARGE_BUCKETS > MAX_LARGE);
        assert!(MAX_SLABS < (EMPTY_BUCKET as usize));
        assert!(MAX_LARGE < (EMPTY_BUCKET as usize));
        Self {
            slabs: [SlabMeta::empty(); MAX_SLABS],
            slab_hash: [EMPTY_BUCKET; SLAB_BUCKETS],
            slab_free_cursor: 0,
            class_hint: [EMPTY_BUCKET; NUM_SIZE_CLASSES],
            class_empty_count: [0usize; NUM_SIZE_CLASSES],
            large_spans: [LargeSpanMeta::empty(); MAX_LARGE],
            large_hash: [EMPTY_BUCKET; LARGE_BUCKETS],
            large_free_cursor: 0,
            used_bytes: 0,
            mapped_pages: 0,
            active_slabs: 0,
            active_large_spans: 0,
            total_allocs: 0,
            total_deallocs: 0,
        }
    }

    /// Snapshot current slab and multi-page span utilization.
    pub fn stats(&self) -> SlabStats {
        let mut empty_cached = 0usize;
        let mut c = 0usize;
        while c < NUM_SIZE_CLASSES {
            empty_cached += self.class_empty_count[c];
            c += 1;
        }
        SlabStats {
            used_bytes: self.used_bytes,
            mapped_bytes: self.mapped_pages * SLAB_PAGE_BYTES,
            active_slabs: self.active_slabs,
            empty_cached_slabs: empty_cached,
            active_large_spans: self.active_large_spans,
            total_allocs: self.total_allocs,
            total_deallocs: self.total_deallocs,
        }
    }

    /// Return `true` iff `ptr_va` belongs to a slab page or large span managed by `self`.
    pub fn owns_address(&self, ptr_va: usize) -> bool {
        if ptr_va == 0 {
            return false;
        }
        let page_va = ptr_va & !(SLAB_PAGE_BYTES - 1);
        if self.find_slab_by_page(page_va).is_some() {
            return true;
        }
        self.find_large_by_base(page_va).is_some()
    }

    /// Allocate a block satisfying `(size, align)` using `backend` for new physical pages.
    pub fn alloc<B: PageBackend>(
        &mut self,
        size: usize,
        align: usize,
        backend: &mut B,
    ) -> Option<usize> {
        if align == 0 || !align.is_power_of_two() {
            return None;
        }
        if let Some(c) = size_class_for(size, align) {
            return self.alloc_small(c, backend);
        }
        self.alloc_large(size, align, backend)
    }

    fn alloc_small<B: PageBackend>(&mut self, c: usize, backend: &mut B) -> Option<usize> {
        let class_bytes = CLASS_SIZES[c];
        let slots_per_page = CLASS_SLOTS[c];

        // 1. Fast path: try the hinted slab for class `c`.
        let hint = self.class_hint[c];
        if hint != EMPTY_BUCKET {
            let idx = hint as usize;
            if idx < MAX_SLABS
                && self.slabs[idx].page_va != 0
                && (self.slabs[idx].class_idx as usize) == c
                && (self.slabs[idx].in_use as usize) < slots_per_page
            {
                let was_empty = self.slabs[idx].in_use == 0;
                if let Some(slot) = self.slabs[idx].alloc_slot() {
                    if was_empty && self.class_empty_count[c] > 0 {
                        self.class_empty_count[c] -= 1;
                    }
                    self.used_bytes += class_bytes;
                    self.total_allocs = self.total_allocs.wrapping_add(1);
                    return Some(self.slabs[idx].page_va + slot * class_bytes);
                }
            }
        }

        // 2. Scan existing slabs for a non-full slab in class `c` (preferring non-empty partial slabs first).
        let mut empty_candidate: Option<usize> = None;
        let mut s = 0usize;
        while s < MAX_SLABS {
            let meta = &self.slabs[s];
            if meta.page_va != 0 && (meta.class_idx as usize) == c {
                let used = meta.in_use as usize;
                if used > 0 && used < slots_per_page {
                    let slot = self.slabs[s].alloc_slot()?;
                    self.class_hint[c] = s as u16;
                    self.used_bytes += class_bytes;
                    self.total_allocs = self.total_allocs.wrapping_add(1);
                    return Some(self.slabs[s].page_va + slot * class_bytes);
                } else if used == 0 && empty_candidate.is_none() {
                    empty_candidate = Some(s);
                }
            }
            s += 1;
        }

        if let Some(s_idx) = empty_candidate {
            let slot = self.slabs[s_idx].alloc_slot()?;
            if self.class_empty_count[c] > 0 {
                self.class_empty_count[c] -= 1;
            }
            self.class_hint[c] = s_idx as u16;
            self.used_bytes += class_bytes;
            self.total_allocs = self.total_allocs.wrapping_add(1);
            return Some(self.slabs[s_idx].page_va + slot * class_bytes);
        }

        // 3. Allocate a fresh 4 KiB slab page from `backend`.
        let desc_idx = self.find_free_slab_slot()?;
        let page_va = backend.alloc_pages(1, 1)?;
        if page_va == 0 || (page_va & (SLAB_PAGE_BYTES - 1)) != 0 {
            backend.free_pages(page_va, 1);
            return None;
        }
        self.slabs[desc_idx] = SlabMeta {
            page_va,
            class_idx: c as u8,
            in_use: 1,
            used_lo: 1,
            used_hi: 0,
        };
        self.insert_slab_hash(page_va, desc_idx as u16);
        self.active_slabs += 1;
        self.mapped_pages += 1;
        self.class_hint[c] = desc_idx as u16;
        self.used_bytes += class_bytes;
        self.total_allocs = self.total_allocs.wrapping_add(1);
        Some(page_va)
    }

    fn alloc_large<B: PageBackend>(
        &mut self,
        size: usize,
        align: usize,
        backend: &mut B,
    ) -> Option<usize> {
        let req_bytes = if size == 0 { 1 } else { size };
        let pages = req_bytes.checked_add(SLAB_PAGE_BYTES - 1)? / SLAB_PAGE_BYTES;
        let align_pages = if align <= SLAB_PAGE_BYTES {
            1
        } else {
            align / SLAB_PAGE_BYTES
        };
        let slot_idx = self.find_free_large_slot()?;
        let base_va = backend.alloc_pages(pages, align_pages)?;
        if base_va == 0 || (base_va & (SLAB_PAGE_BYTES - 1)) != 0 {
            backend.free_pages(base_va, pages);
            return None;
        }
        self.large_spans[slot_idx] = LargeSpanMeta {
            base_va,
            page_count: pages,
        };
        self.insert_large_hash(base_va, slot_idx as u16);
        self.active_large_spans += 1;
        self.mapped_pages += pages;
        self.used_bytes += pages * SLAB_PAGE_BYTES;
        self.total_allocs = self.total_allocs.wrapping_add(1);
        Some(base_va)
    }

    /// Deallocate `(ptr_va, size, align)`, returning the byte count of the freed slot/span
    /// so the caller can scrub raw memory if desired before or during reclamation.
    ///
    /// Note: when an empty slab exceeds [`WARM_EMPTY_SLABS_PER_CLASS`] or when a large
    /// span is freed, `backend.free_pages(...)` is invoked immediately.
    pub fn dealloc<B: PageBackend>(
        &mut self,
        ptr_va: usize,
        size: usize,
        align: usize,
        backend: &mut B,
    ) -> Result<usize, SlabError> {
        if ptr_va == 0 {
            return Err(SlabError::UnknownAddress);
        }
        if let Some(expected_class) = size_class_for(size, align) {
            let page_va = ptr_va & !(SLAB_PAGE_BYTES - 1);
            let Some(desc_idx) = self.find_slab_by_page(page_va) else {
                return Err(SlabError::UnknownAddress);
            };
            let actual_class = self.slabs[desc_idx].class_idx as usize;
            if actual_class != expected_class {
                return Err(SlabError::LayoutMismatch);
            }
            let class_bytes = CLASS_SIZES[actual_class];
            let offset = ptr_va - page_va;
            if (offset % class_bytes) != 0 {
                return Err(SlabError::MisalignedSlot);
            }
            let slot = offset / class_bytes;
            self.slabs[desc_idx].free_slot(slot)?;
            self.used_bytes = self.used_bytes.saturating_sub(class_bytes);
            self.total_deallocs = self.total_deallocs.wrapping_add(1);

            if self.slabs[desc_idx].in_use == 0 {
                if self.class_empty_count[actual_class] >= WARM_EMPTY_SLABS_PER_CLASS {
                    // Reclaim physical frame back to `backend`.
                    self.remove_slab_hash(page_va);
                    self.slabs[desc_idx] = SlabMeta::empty();
                    self.active_slabs -= 1;
                    self.mapped_pages -= 1;
                    if self.class_hint[actual_class] == desc_idx as u16 {
                        self.class_hint[actual_class] = EMPTY_BUCKET;
                    }
                    if desc_idx < self.slab_free_cursor {
                        self.slab_free_cursor = desc_idx;
                    }
                    backend.free_pages(page_va, 1);
                } else {
                    self.class_empty_count[actual_class] += 1;
                    self.class_hint[actual_class] = desc_idx as u16;
                }
            } else {
                self.class_hint[actual_class] = desc_idx as u16;
            }
            return Ok(class_bytes);
        }

        // Large multi-page span deallocation.
        if (ptr_va & (SLAB_PAGE_BYTES - 1)) != 0 {
            return Err(SlabError::MisalignedSlot);
        }
        let req_bytes = if size == 0 { 1 } else { size };
        let expected_pages = (req_bytes + SLAB_PAGE_BYTES - 1) / SLAB_PAGE_BYTES;
        let Some(slot_idx) = self.find_large_by_base(ptr_va) else {
            return Err(SlabError::UnknownAddress);
        };
        let pages = self.large_spans[slot_idx].page_count;
        if pages != expected_pages {
            return Err(SlabError::LayoutMismatch);
        }
        self.remove_large_hash(ptr_va);
        self.large_spans[slot_idx] = LargeSpanMeta::empty();
        if slot_idx < self.large_free_cursor {
            self.large_free_cursor = slot_idx;
        }
        self.active_large_spans -= 1;
        self.mapped_pages = self.mapped_pages.saturating_sub(pages);
        let span_bytes = pages * SLAB_PAGE_BYTES;
        self.used_bytes = self.used_bytes.saturating_sub(span_bytes);
        self.total_deallocs = self.total_deallocs.wrapping_add(1);
        backend.free_pages(ptr_va, pages);
        Ok(span_bytes)
    }

    /// Release all warm cached empty 4 KiB slab pages back to `backend`, returning the
    /// number of physical pages reclaimed.
    pub fn reclaim_empty_slabs<B: PageBackend>(&mut self, backend: &mut B) -> usize {
        let mut reclaimed = 0usize;
        let mut s = 0usize;
        while s < MAX_SLABS {
            if self.slabs[s].page_va != 0 && self.slabs[s].in_use == 0 {
                let page_va = self.slabs[s].page_va;
                let c = self.slabs[s].class_idx as usize;
                self.remove_slab_hash(page_va);
                self.slabs[s] = SlabMeta::empty();
                self.active_slabs -= 1;
                self.mapped_pages -= 1;
                if self.class_empty_count[c] > 0 {
                    self.class_empty_count[c] -= 1;
                }
                if self.class_hint[c] == s as u16 {
                    self.class_hint[c] = EMPTY_BUCKET;
                }
                if s < self.slab_free_cursor {
                    self.slab_free_cursor = s;
                }
                backend.free_pages(page_va, 1);
                reclaimed += 1;
            }
            s += 1;
        }
        reclaimed
    }

    fn find_free_slab_slot(&mut self) -> Option<usize> {
        let start = if self.slab_free_cursor < MAX_SLABS {
            self.slab_free_cursor
        } else {
            0
        };
        let mut pass = 0usize;
        while pass < 2 {
            let (lo, hi) = if pass == 0 {
                (start, MAX_SLABS)
            } else {
                (0, start)
            };
            let mut i = lo;
            while i < hi {
                if self.slabs[i].page_va == 0 {
                    self.slab_free_cursor = i + 1;
                    return Some(i);
                }
                i += 1;
            }
            pass += 1;
        }
        None
    }

    fn find_free_large_slot(&mut self) -> Option<usize> {
        let start = if self.large_free_cursor < MAX_LARGE {
            self.large_free_cursor
        } else {
            0
        };
        let mut pass = 0usize;
        while pass < 2 {
            let (lo, hi) = if pass == 0 {
                (start, MAX_LARGE)
            } else {
                (0, start)
            };
            let mut i = lo;
            while i < hi {
                if self.large_spans[i].base_va == 0 {
                    self.large_free_cursor = i + 1;
                    return Some(i);
                }
                i += 1;
            }
            pass += 1;
        }
        None
    }

    fn insert_slab_hash(&mut self, page_va: usize, desc_idx: u16) {
        let mask = SLAB_BUCKETS - 1;
        let mut b = hash_page_va(page_va, mask);
        loop {
            if self.slab_hash[b] == EMPTY_BUCKET {
                self.slab_hash[b] = desc_idx;
                return;
            }
            b = (b + 1) & mask;
        }
    }

    fn find_slab_by_page(&self, page_va: usize) -> Option<usize> {
        let mask = SLAB_BUCKETS - 1;
        let mut b = hash_page_va(page_va, mask);
        let mut probes = 0usize;
        while probes < SLAB_BUCKETS {
            let entry = self.slab_hash[b];
            if entry == EMPTY_BUCKET {
                return None;
            }
            let idx = entry as usize;
            if self.slabs[idx].page_va == page_va {
                return Some(idx);
            }
            b = (b + 1) & mask;
            probes += 1;
        }
        None
    }

    /// Tombstone-free Knuth Algorithm R deletion on `slab_hash`.
    fn remove_slab_hash(&mut self, page_va: usize) {
        let mask = SLAB_BUCKETS - 1;
        let mut i = hash_page_va(page_va, mask);
        let mut probes = 0usize;
        while probes < SLAB_BUCKETS {
            let entry = self.slab_hash[i];
            if entry == EMPTY_BUCKET {
                return;
            }
            if self.slabs[entry as usize].page_va == page_va {
                break;
            }
            i = (i + 1) & mask;
            probes += 1;
        }
        if probes >= SLAB_BUCKETS {
            return;
        }
        let mut j = i;
        loop {
            self.slab_hash[i] = EMPTY_BUCKET;
            loop {
                j = (j + 1) & mask;
                let cand = self.slab_hash[j];
                if cand == EMPTY_BUCKET {
                    return;
                }
                let r = hash_page_va(self.slabs[cand as usize].page_va, mask);
                // Check if `r` is cyclically in `(i, j]` — if so, `cand` must NOT move to `i`.
                let in_window = if i <= j {
                    i < r && r <= j
                } else {
                    i < r || r <= j
                };
                if !in_window {
                    break;
                }
            }
            self.slab_hash[i] = self.slab_hash[j];
            i = j;
        }
    }

    fn insert_large_hash(&mut self, base_va: usize, slot_idx: u16) {
        let mask = LARGE_BUCKETS - 1;
        let mut b = hash_page_va(base_va, mask);
        loop {
            if self.large_hash[b] == EMPTY_BUCKET {
                self.large_hash[b] = slot_idx;
                return;
            }
            b = (b + 1) & mask;
        }
    }

    fn find_large_by_base(&self, base_va: usize) -> Option<usize> {
        let mask = LARGE_BUCKETS - 1;
        let mut b = hash_page_va(base_va, mask);
        let mut probes = 0usize;
        while probes < LARGE_BUCKETS {
            let entry = self.large_hash[b];
            if entry == EMPTY_BUCKET {
                return None;
            }
            let idx = entry as usize;
            if self.large_spans[idx].base_va == base_va {
                return Some(idx);
            }
            b = (b + 1) & mask;
            probes += 1;
        }
        None
    }

    fn remove_large_hash(&mut self, base_va: usize) {
        let mask = LARGE_BUCKETS - 1;
        let mut i = hash_page_va(base_va, mask);
        let mut probes = 0usize;
        while probes < LARGE_BUCKETS {
            let entry = self.large_hash[i];
            if entry == EMPTY_BUCKET {
                return;
            }
            if self.large_spans[entry as usize].base_va == base_va {
                break;
            }
            i = (i + 1) & mask;
            probes += 1;
        }
        if probes >= LARGE_BUCKETS {
            return;
        }
        let mut j = i;
        loop {
            self.large_hash[i] = EMPTY_BUCKET;
            loop {
                j = (j + 1) & mask;
                let cand = self.large_hash[j];
                if cand == EMPTY_BUCKET {
                    return;
                }
                let r = hash_page_va(self.large_spans[cand as usize].base_va, mask);
                let in_window = if i <= j {
                    i < r && r <= j
                } else {
                    i < r || r <= j
                };
                if !in_window {
                    break;
                }
            }
            self.large_hash[i] = self.large_hash[j];
            i = j;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phys_mm::{PhysFrameManager, PhysRegionDesc};

    struct SimPhysPageBackend {
        pmm: PhysFrameManager<128>, // 8,192 frames = 32 MiB
        va_offset: usize,
    }

    impl SimPhysPageBackend {
        fn new_16mib() -> Self {
            let mut pmm = PhysFrameManager::empty();
            pmm.init_from_regions(
                &[PhysRegionDesc {
                    start: 0x0020_0000,
                    end: 0x0120_0000, // 16 MiB = 4,096 frames
                    usable: true,
                }],
                &[],
            );
            Self {
                pmm,
                va_offset: 0xFFFF_8000_0000_0000,
            }
        }
    }

    impl PageBackend for SimPhysPageBackend {
        fn alloc_pages(&mut self, count: usize, align_pages: usize) -> Option<usize> {
            let pa = self.pmm.alloc_contiguous(count, align_pages).ok()?;
            Some(self.va_offset.wrapping_add(pa as usize))
        }

        fn free_pages(&mut self, base_va: usize, count: usize) {
            let pa = base_va.wrapping_sub(self.va_offset) as u64;
            self.pmm
                .free_contiguous(pa, count)
                .expect("SimPhysPageBackend free_pages must succeed without double-free");
        }

        fn free_page_count(&self) -> usize {
            self.pmm.stats().free_frames
        }
    }

    #[test]
    fn slab_allocator_100k_adversarial_churn_alignment_and_full_reclaim() {
        let mut backend = SimPhysPageBackend::new_16mib();
        let initial_frames = backend.free_page_count();
        assert_eq!(initial_frames, 4096);

        let mut slab: SlabAllocator<512, 1024, 128, 256> = SlabAllocator::empty();
        let mut live: alloc::vec::Vec<(usize, usize, usize)> = alloc::vec::Vec::with_capacity(512);

        // Deterministic PRNG (`xorshift64*`) driving 100,000 mixed small + large allocations/frees.
        let mut rng: u64 = 0xC077_1E05_2026_B1A1;
        let sizes = [
            1usize, 17, 32, 48, 64, 96, 128, 200, 256, 400, 512, 900, 1024, 1500, 2048, 3500,
            4096, 6000, 12_288, 32_768,
        ];
        let aligns = [8usize, 16, 32, 64, 256, 4096, 8192];

        for step in 0..100_000usize {
            rng ^= rng >> 12;
            rng ^= rng << 25;
            rng ^= rng >> 27;
            let r = rng.wrapping_mul(0x2545_F491_4F6C_DD1D);

            let should_alloc = live.len() < 128 || (live.len() < 384 && (r & 1) == 0);
            if should_alloc {
                let sz = sizes[(r as usize) % sizes.len()];
                let al = aligns[((r >> 8) as usize) % aligns.len()];
                let va = slab
                    .alloc(sz, al, &mut backend)
                    .unwrap_or_else(|| panic!("alloc failed at step {step} (sz={sz}, al={al})"));
                assert_eq!(va % al, 0, "returned VA must satisfy requested alignment {al}");
                assert!(slab.owns_address(va));
                live.push((va, sz, al));
            } else {
                let idx = ((r >> 16) as usize) % live.len();
                let (va, sz, al) = live.swap_remove(idx);
                slab.dealloc(va, sz, al, &mut backend)
                    .expect("dealloc of live slot must succeed");
            }
        }

        // Verify double-free and misaligned-slot rejection on a fresh allocation.
        let probe_va = slab.alloc(64, 64, &mut backend).unwrap();
        assert_eq!(
            slab.dealloc(probe_va + 8, 64, 64, &mut backend),
            Err(SlabError::MisalignedSlot)
        );
        assert_eq!(
            slab.dealloc(probe_va, 256, 64, &mut backend),
            Err(SlabError::LayoutMismatch)
        );
        slab.dealloc(probe_va, 64, 64, &mut backend).unwrap();
        // Either the page stayed warm (DoubleFree) or was reclaimed (UnknownAddress) — both reject!
        assert!(slab.dealloc(probe_va, 64, 64, &mut backend).is_err());

        // Drain all remaining live allocations + warm caches and prove 100% physical frame conservation!
        for (va, sz, al) in live {
            slab.dealloc(va, sz, al, &mut backend).unwrap();
        }
        let _reclaimed = slab.reclaim_empty_slabs(&mut backend);
        let st = slab.stats();
        assert_eq!(st.used_bytes, 0);
        assert_eq!(st.mapped_bytes, 0);
        assert_eq!(st.active_slabs, 0);
        assert_eq!(st.active_large_spans, 0);
        assert_eq!(
            backend.free_page_count(),
            initial_frames,
            "100,000-cycle slab + multi-page churn must leak zero physical frames"
        );
    }
}
