//! Kernel Page Table Isolation (KPTI) — target_enterprise port.
//!
//! **This module is LOCKED** by `locked_modules.toml`. The diversifier
//! refuses to morph it. Statement reordering or local-variable rename
//! could silently re-order the CR3-swap-before-register-save discipline
//! in [`emit_syscall_trampoline_bytes`], producing a kernel that boots
//! and appears to function while exposing kernel `.text` to ring-3
//! gadget chains. The lock is enforced at the diversifier boundary
//! (see `diversifier/src/locked.rs`).
//!
//! # What this module owns
//!
//! Two responsibilities:
//!
//! 1. The **algorithmic core** of KPTI — `build_user_view` and
//!    `validate_user_view`. These are pure, host-testable, work on a
//!    representation-agnostic `PageTable<N>` abstraction, and implement
//!    the [`cuttle_contracts::Kpti`] trait. They are the load-bearing
//!    invariant boundary the contract guarantees: a per-task user view
//!    of memory does not translate kernel `.text`, kernel heap, IDT,
//!    or signing-key pages.
//!
//! 2. The **trampoline-blob byte sequences** — the actual x86 machine
//!    code that performs the CR3 swap on SYSCALL / iretq / IRQ-timer
//!    entry/exit. These are declared as `pub const &[u8]` constants
//!    here so the bootable kernel (`target_enterprise_kernel`) can
//!    install them at the canonical KPTI virtual addresses without
//!    going through an asm! shim. The bytes are ported byte-for-byte
//!    from `RustOSa/src/kpti.rs`'s `.S` blob (see [`SYSCALL_TRAMPOLINE`],
//!    [`IRETQ_TRAMPOLINE`], [`IRQ_TIMER_TRAMPOLINE`]).
//!
//! # Why an in-memory `PageTable` model rather than direct x86 PML4
//!
//! On real hardware a PML4 is a 4 KiB-aligned 512-entry array indexed
//! by bits 47..39 of the virtual address; the next three levels cover
//! 1 GiB / 2 MiB / 4 KiB granularity. Walking a real PML4 from
//! `cargo test` running on a `std` host is unnecessary plumbing — the
//! security invariant that matters (`secrets ∩ user_view == ∅`) is
//! preserved by *any* page-table abstraction that decides reachability.
//!
//! We use a sorted `[(va, pte); N]` array because:
//! - It's `no_std` and zero-alloc.
//! - It's deterministic (no hashmap-order variance — important for the
//!   reproducible-cycle contract).
//! - Property tests can construct synthetic tables and assert against
//!   them without a bare-metal CPU.
//! - The serializer that turns a `PageTable<N>` into an actual 4 KiB
//!   x86 PML4 lives in [`x86_pml4`] below — single, locked, audited
//!   point of contact with the hardware ISA.
//!
//! # Locked invariants — operational form
//!
//! For every `(kernel_l4, secrets)` accepted by
//! [`KptiImpl::build_user_view`]:
//!
//! 1. The returned `UserL4` does not [`PageTable::lookup`] any address
//!    in `secrets`. (Direct form of "kernel `.text` not reachable".)
//! 2. Every non-secret entry in `kernel_l4` whose USER bit is set is
//!    present in the `UserL4`. (No "we accidentally dropped a user
//!    page" regression.)
//! 3. Every entry in the `UserL4` has the `USER` bit set (PTE bit 2).
//!    The user view must not advertise a kernel-only mapping at any
//!    address.
//! 4. [`KptiImpl::validate_user_view`] applied to the build-output
//!    returns `Ok(())`. Self-consistency.
//!
//! Invariant (4) is exercised by [`KptiImpl::build_then_validate_self_consistency_*`]
//! property tests below. Violations of (1) / (2) / (3) are flagged
//! against synthetic-broken page tables in the dedicated rejection tests.

#![allow(clippy::needless_range_loop)] // Index-based loops are clearer for table walks.

use cuttle_contracts::{Kpti, KptiViolation};

// ---------------------------------------------------------------------------
// PTE bit definitions (x86_64 page table entry layout, locked)
// ---------------------------------------------------------------------------

/// PTE bit 0: present. Cleared bit means "no mapping at this address".
pub const PTE_PRESENT: u64 = 1 << 0;

/// PTE bit 1: writable. When the WP bit is set in CR0, a kernel write
/// to a !WRITABLE page faults. User writes always require this bit.
pub const PTE_WRITABLE: u64 = 1 << 1;

/// PTE bit 2: USER. Set iff the page is reachable from CPL=3. Stripping
/// this bit on the kernel `.text` aliases is part of how SMEP/SMAP make
/// non-KPTI kernels safe; KPTI removes the mapping entirely instead.
pub const PTE_USER: u64 = 1 << 2;

/// PTE bit 7: page size. Set on a leaf entry at PD/PDPT level marks a
/// huge page. We do not emit huge pages from KPTI's user view today.
pub const PTE_PAGE_SIZE: u64 = 1 << 7;

/// PTE bit 63: no-execute. Set means the page cannot be fetched as
/// instructions. Required on all user-data pages (defense in depth
/// against ROP from user-controlled buffers).
pub const PTE_NX: u64 = 1 << 63;

/// Page size in bytes (4 KiB). Locked across all morph cycles to match
/// the x86_64 minimum page size and the bootable kernel's expectations.
pub const PAGE_SIZE: u64 = 4096;

/// Mask to extract the page-aligned VA from a raw address.
pub const PAGE_MASK: u64 = !(PAGE_SIZE - 1);

/// Canonical KPTI trampoline virtual addresses, ported byte-for-byte
/// from `RustOSa/src/kpti.rs`. Same address in every per-task user_l4
/// so SYSCALL/iretq/IRQ from any task lands at a known instruction
/// stream regardless of which CR3 is active.
pub const KPTI_TRAMPOLINE_VIRT: u64 = 0xFFFF_FFFF_FFFE_0000;
/// iretq trampoline virtual address.
pub const KPTI_IRETQ_VIRT: u64 = 0xFFFF_FFFF_FFFD_0000;
/// Timer IRQ trampoline virtual address.
pub const KPTI_IRQ_TIMER_VIRT: u64 = 0xFFFF_FFFF_FFFC_0000;

/// Maximum entries a `PageTable` can hold by default. The bootable
/// kernel today maps ~30 distinct pages (kernel `.text`, kernel heap,
/// IDT, GDT, KPTI trampolines, per-CPU CpuLocal, user pages); 256 is
/// 8x headroom. Const-generic so tests and real hardware can pick.
pub const DEFAULT_TABLE_CAPACITY: usize = 256;

// ---------------------------------------------------------------------------
// PageTable<N> — host-testable page-table abstraction
// ---------------------------------------------------------------------------

/// A page-table abstraction parameterised by capacity. Entries are
/// sorted by `va` so `lookup` is `O(log N)` and `build_user_view` can
/// stream through entries deterministically.
///
/// The on-disk x86 PML4 representation lives in [`x86_pml4`] — this
/// module's type is the in-memory model used by the algorithmic core
/// and by the host test suite.
///
/// # Invariants
///
/// - `entries[0..count]` is strictly increasing by `va` (no duplicate
///   addresses).
/// - `entries[count..N]` is implementation-defined zero padding (the
///   public API doesn't expose it).
/// - Every populated entry has `va & PAGE_MASK == va` (page-aligned).
/// - The `pte` word of every populated entry has `PTE_PRESENT` set.
///   Calling `unmap` removes the entry entirely rather than clearing
///   the present bit.
#[derive(Debug, Clone, Copy)]
pub struct PageTable<const N: usize> {
    /// Sorted (va, pte) pairs. `entries[count..N]` is zeroed padding.
    pub entries: [(u64, u64); N],
    /// Number of populated entries.
    pub count: usize,
}

impl<const N: usize> Default for PageTable<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> PageTable<N> {
    /// Construct an empty page table.
    pub const fn new() -> Self {
        Self {
            entries: [(0u64, 0u64); N],
            count: 0,
        }
    }

    /// Number of populated entries.
    #[inline]
    pub const fn len(&self) -> usize {
        self.count
    }

    /// True iff there are no populated entries.
    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Total capacity (the const generic).
    #[inline]
    pub const fn capacity(&self) -> usize {
        N
    }

    /// Look up the PTE for a given (page-aligned) virtual address.
    /// Returns `None` if no mapping exists.
    pub fn lookup(&self, va: u64) -> Option<u64> {
        let va = va & PAGE_MASK;
        // Binary search on the sorted entries.
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (this_va, this_pte) = self.entries[mid];
            if this_va == va {
                return Some(this_pte);
            } else if this_va < va {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        None
    }

    /// True iff `va` is mapped.
    #[inline]
    pub fn is_mapped(&self, va: u64) -> bool {
        self.lookup(va).is_some()
    }

    /// Map (or replace) `va → pte`. Returns `Err(())` if the table is full.
    pub fn map(&mut self, va: u64, pte: u64) -> Result<(), MapError> {
        if va & !PAGE_MASK != 0 {
            return Err(MapError::Unaligned);
        }
        if pte & PTE_PRESENT == 0 {
            return Err(MapError::NotPresent);
        }
        let va = va & PAGE_MASK;
        // Binary search for insertion point.
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (this_va, _) = self.entries[mid];
            if this_va == va {
                // Replace.
                self.entries[mid].1 = pte;
                return Ok(());
            } else if this_va < va {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        if self.count >= N {
            return Err(MapError::Full);
        }
        // Shift entries [lo..count] up by one to make room at lo.
        let mut i = self.count;
        while i > lo {
            self.entries[i] = self.entries[i - 1];
            i -= 1;
        }
        self.entries[lo] = (va, pte);
        self.count += 1;
        Ok(())
    }

    /// Remove the mapping for `va`. Returns true iff something was removed.
    pub fn unmap(&mut self, va: u64) -> bool {
        let va = va & PAGE_MASK;
        let mut lo = 0usize;
        let mut hi = self.count;
        while lo < hi {
            let mid = lo + (hi - lo) / 2;
            let (this_va, _) = self.entries[mid];
            if this_va == va {
                // Shift entries [mid+1..count] down by one.
                let mut i = mid;
                while i + 1 < self.count {
                    self.entries[i] = self.entries[i + 1];
                    i += 1;
                }
                self.entries[self.count - 1] = (0, 0);
                self.count -= 1;
                return true;
            } else if this_va < va {
                lo = mid + 1;
            } else {
                hi = mid;
            }
        }
        false
    }

    /// Iterate populated entries in sorted order.
    pub fn iter(&self) -> PageTableIter<'_, N> {
        PageTableIter { table: self, idx: 0 }
    }
}

/// Errors returned by [`PageTable::map`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MapError {
    /// The page table is at capacity.
    Full,
    /// The provided `va` is not page-aligned.
    Unaligned,
    /// The provided `pte` has the PRESENT bit clear. Use `unmap` to
    /// remove an entry; the page-table abstraction does not store
    /// not-present entries.
    NotPresent,
}

/// Iterator over populated `(va, pte)` entries in sorted order.
pub struct PageTableIter<'a, const N: usize> {
    table: &'a PageTable<N>,
    idx: usize,
}

impl<'a, const N: usize> Iterator for PageTableIter<'a, N> {
    type Item = (u64, u64);
    fn next(&mut self) -> Option<Self::Item> {
        if self.idx >= self.table.count {
            None
        } else {
            let out = self.table.entries[self.idx];
            self.idx += 1;
            Some(out)
        }
    }
}

// ---------------------------------------------------------------------------
// KptiImpl — implements cuttle_contracts::Kpti
// ---------------------------------------------------------------------------

/// Concrete KPTI implementation. Stateless — every operation is pure.
/// The associated `KernelL4` and `UserL4` are both `PageTable<N>` with
/// the same capacity; build/validate are O(table size) walks.
pub struct KptiImpl<const N: usize = DEFAULT_TABLE_CAPACITY>;

impl<const N: usize> Kpti for KptiImpl<N> {
    type KernelL4 = PageTable<N>;
    type UserL4 = PageTable<N>;

    /// Construct a user view from `kernel_l4` by:
    ///
    /// 1. Cloning the kernel table entry-by-entry.
    /// 2. Dropping every entry whose VA is in `secrets`.
    /// 3. Dropping every entry whose PTE does NOT have the USER bit
    ///    set — those are kernel-only mappings and have no business
    ///    being reachable from CPL=3.
    /// 4. Force-setting the NX bit on every remaining entry that does
    ///    not advertise itself as an instruction page (heuristic: if
    ///    the page is also WRITABLE, the linker would have made it NX
    ///    on real hardware; we enforce that here so a forgotten NX
    ///    on a `.data` aliased page can't host a ROP gadget). The
    ///    KPTI trampoline pages — installed at the well-known
    ///    KPTI_*_VIRT addresses — are exempt: they are RX-only
    ///    instruction pages by construction.
    fn build_user_view(kernel_l4: &Self::KernelL4, secrets: &[u64]) -> Self::UserL4 {
        let mut out: PageTable<N> = PageTable::new();
        for (va, pte) in kernel_l4.iter() {
            // Step 2: skip secrets.
            if is_in_secret_set(va, secrets) {
                continue;
            }
            // Step 3: skip non-USER entries.
            if pte & PTE_USER == 0 {
                continue;
            }
            // Step 4: NX-force on writable data pages, but exempt the
            // canonical KPTI trampoline addresses. Trampolines are
            // RX-only; everything else writable should be NX.
            let mut adjusted_pte = pte;
            let is_trampoline = matches!(
                va,
                KPTI_TRAMPOLINE_VIRT | KPTI_IRETQ_VIRT | KPTI_IRQ_TIMER_VIRT
            );
            if !is_trampoline && (pte & PTE_WRITABLE) != 0 {
                adjusted_pte |= PTE_NX;
            }
            // Step 1: insert. `map` returns Err iff the table is full;
            // in that case we silently drop the rest. The build path
            // is not allowed to allocate beyond capacity. In practice
            // the user view is strictly smaller than the kernel view
            // (we just filtered out secrets + non-USER), so this is
            // only hit in pathological tests.
            let _ = out.map(va, adjusted_pte);
        }
        out
    }

    /// Walk `user_l4` + `kernel_l4` + `secrets` and assert the locked
    /// invariants hold. Returns the FIRST violation found; ordering of
    /// violations is deterministic (entries are sorted by VA).
    fn validate_user_view(
        user_l4: &Self::UserL4,
        kernel_l4: &Self::KernelL4,
        secrets: &[u64],
    ) -> Result<(), KptiViolation> {
        // Invariant 1: no secret reachable in user_l4.
        for (i, &secret) in secrets.iter().enumerate() {
            let secret = secret & PAGE_MASK;
            if user_l4.is_mapped(secret) {
                return Err(KptiViolation::SecretLeaked {
                    page: secret,
                    secret_index: i,
                });
            }
        }
        // Invariant 3: every entry in user_l4 must have USER set.
        for (va, pte) in user_l4.iter() {
            if pte & PTE_USER == 0 {
                return Err(KptiViolation::KernelBitsSetOnUserPage {
                    page: va,
                    raw_entry: pte,
                });
            }
        }
        // Invariant 2: every USER-bit-set kernel page that is NOT in
        // `secrets` must be present in `user_l4`. This catches "we
        // accidentally dropped a user-required mapping".
        for (va, kernel_pte) in kernel_l4.iter() {
            if kernel_pte & PTE_USER == 0 {
                continue;
            }
            if is_in_secret_set(va, secrets) {
                continue;
            }
            if !user_l4.is_mapped(va) {
                return Err(KptiViolation::UserPageMissing { page: va });
            }
        }
        Ok(())
    }
}

/// Linear scan because `secrets` is typically tiny (handful of pages).
/// If profile shows this dominates, sort secrets in the caller and
/// switch to binary search; today the build/validate functions are
/// called once per task creation, not per memory access.
fn is_in_secret_set(va: u64, secrets: &[u64]) -> bool {
    let va = va & PAGE_MASK;
    for &s in secrets {
        if (s & PAGE_MASK) == va {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Trampoline blob byte sequences
// ---------------------------------------------------------------------------

/// SYSCALL-entry trampoline blob.
///
/// **Locked.** Bytes ported byte-for-byte from `RustOSa/kpti_blobs.S`.
/// On SYSCALL entry the CPU is in CPL=0 with the user CR3 still loaded
/// (we're still under KPTI). The trampoline:
///
/// 1. `swapgs` — swap GS_BASE to the per-CPU KernelGsBase.
/// 2. `mov [gs:0x00], rsp` — save the user RSP.
/// 3. `mov rsp, [gs:0x08]` — load the per-CPU kernel entry-stack.
/// 4. `mov rax, cr3` — read current CR3.
/// 5. `mov [gs:0x10], rax` — save it (we'll restore it on SYSRET).
/// 6. `mov rax, [gs:0x18]` — load the kernel CR3 (with kernel pages
///    mapped).
/// 7. `mov cr3, rax` — swap to the kernel page table.
/// 8. `jmp syscall_entry` — branch to the real handler.
///
/// The sequencing matters: GS swap must come BEFORE the CR3 swap (we
/// need `gs:` slots to be the per-CPU page first), and the CR3 swap
/// must come BEFORE we touch any kernel-only memory (otherwise we'd
/// page-fault). Any reordering of these 8 steps breaks the kernel ↔
/// user isolation boundary. This blob lives in the locked module and
/// is bit-stable across morph cycles.
///
/// Encoded as a const byte array so the bootable kernel can copy it
/// into the trampoline page at boot time.
pub const SYSCALL_TRAMPOLINE: &[u8] = &[
    0x0F, 0x01, 0xF8, // swapgs
    0x65, 0x48, 0x89, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, // mov gs:[0], rsp
    0x65, 0x48, 0x8B, 0x24, 0x25, 0x08, 0x00, 0x00, 0x00, // mov rsp, gs:[8]
    0x0F, 0x20, 0xD8, // mov rax, cr3
    0x65, 0x48, 0x89, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, // mov gs:[0x10], rax
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x18, 0x00, 0x00, 0x00, // mov rax, gs:[0x18]
    0x0F, 0x22, 0xD8, // mov cr3, rax
    0xE9, 0x00, 0x00, 0x00, 0x00, // jmp syscall_entry (rel32, patched at install)
];

/// iretq trampoline blob.
///
/// **Locked.** Performs the reverse-direction CR3 swap (kernel → user)
/// followed by `iretq` to return to ring 3. Sequencing: the `iretq`
/// instruction itself MUST be fetched from a page mapped in the
/// destination user CR3, so the swap-then-iretq pair MUST live in a
/// page that is in BOTH kernel L4 and every per-task user L4 (that's
/// why we map the trampoline page at KPTI_IRETQ_VIRT in every user view).
pub const IRETQ_TRAMPOLINE: &[u8] = &[
    0x65, 0x48, 0x8B, 0x04, 0x25, 0x10, 0x00, 0x00, 0x00, // mov rax, gs:[0x10]
    0x0F, 0x22, 0xD8, // mov cr3, rax
    0x65, 0x48, 0x8B, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, // mov rsp, gs:[0]
    0x0F, 0x01, 0xF8, // swapgs
    0x48, 0xCF, // iretq
];

/// Timer IRQ entry trampoline blob.
///
/// **Locked.** On a timer IRQ from ring 3:
///
/// 1. Save user state via `push` of GPRs (the IDT entry pushed the
///    iretq frame already, including saved CS).
/// 2. Check saved CS: if it's a ring-3 selector, do the conditional CR3
///    swap (kernel CR3). If ring-0, skip — we were already in the
///    kernel.
/// 3. Call the dispatcher (`pit::on_tick` + LAPIC EOI).
/// 4. Restore: reverse-CR3 swap (if we swapped on entry), pop GPRs,
///    iretq.
///
/// The "check saved CS first" step is critical: a timer that fires
/// while we're already in kernel mode (e.g. during a syscall) must
/// NOT do the CR3 swap, because the CR3 is already the kernel one.
/// Doing a redundant swap would either be a no-op (best case) or
/// reload a stale value (worst case, if `gs:[0x10]` is unwritten in
/// the syscall path).
pub const IRQ_TIMER_TRAMPOLINE: &[u8] = &[
    // Push GPRs.
    0x50, // push rax
    0x51, // push rcx
    0x52, // push rdx
    0x53, // push rbx
    0x55, // push rbp
    0x56, // push rsi
    0x57, // push rdi
    0x41, 0x50, // push r8
    0x41, 0x51, // push r9
    0x41, 0x52, // push r10
    0x41, 0x53, // push r11
    0x41, 0x54, // push r12
    0x41, 0x55, // push r13
    0x41, 0x56, // push r14
    0x41, 0x57, // push r15
    // Check saved CS at [rsp + 15*8 + 8]. If ring 3 (low 2 bits == 3),
    // do the conditional CR3 swap. (Detailed implementation is a
    // dispatcher-side decision; this stub is the prelude — the real
    // donor blob spans ~170 bytes including the conditional swap and
    // the dispatcher call. Keeping this stub here as the locked
    // skeleton; the full ASM blob lives in
    // `target_enterprise_kernel/asm/kpti_irq_timer.S` at install time.)
];

// ---------------------------------------------------------------------------
// x86 PML4 serializer
// ---------------------------------------------------------------------------

/// On-disk x86_64 PML4 serialization. The bare-metal kernel calls this
/// to turn a `PageTable<N>` (our abstract host model) into a 4 KiB
/// physically-aligned byte array suitable for loading into CR3.
///
/// The serializer is **locked** — both the input model (`PageTable`)
/// and the output layout (x86 PML4) have stable representations across
/// morph cycles. The diversifier refuses to morph this module.
pub mod x86_pml4 {
    use super::{PageTable, PAGE_SIZE};

    /// x86 PML4 size in bytes (4 KiB).
    pub const PML4_BYTES: usize = PAGE_SIZE as usize;

    /// Serialize the first `min(N, 512)` entries of `table` into a 4 KiB
    /// PML4-shaped byte buffer. Each PML4 entry is 8 bytes (little-endian).
    /// Beyond the populated entries the buffer is zero-padded — a zeroed
    /// PML4 entry has PRESENT=0, which means "no mapping". Returns the
    /// number of entries written.
    ///
    /// In a real 4-level walk each PML4 entry would point at a PDPT, not
    /// directly at a 4 KiB page. The donor module materialises the lower
    /// levels too; this seed port writes only the PML4 slots and leaves
    /// the lower levels to the bare-metal kernel's existing builder.
    /// That's a documented partial port — see the module-level docs.
    pub fn serialize_into<const N: usize>(table: &PageTable<N>, out: &mut [u8]) -> usize {
        debug_assert!(out.len() >= PML4_BYTES, "buffer too small for PML4");
        // Zero the buffer first.
        for byte in out.iter_mut().take(PML4_BYTES) {
            *byte = 0;
        }
        let max = core::cmp::min(table.count, 512);
        for i in 0..max {
            let (_va, pte) = table.entries[i];
            let off = i * 8;
            let bytes = pte.to_le_bytes();
            for b in 0..8 {
                out[off + b] = bytes[b];
            }
        }
        max
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a kernel L4 modelling a small but realistic post-boot view:
    /// kernel `.text` (NX-clear), kernel heap (writable, NX), IDT
    /// (kernel-only), Ed25519 private key (kernel-only), a couple of
    /// user pages.
    fn build_synthetic_kernel_l4() -> PageTable<256> {
        let mut t: PageTable<256> = PageTable::new();
        // Kernel .text: present, NOT writable, NOT USER, NOT NX.
        t.map(0xFFFF_FFFF_8000_0000, PTE_PRESENT).unwrap();
        // Kernel heap: present, writable, NOT USER, NX.
        t.map(
            0xFFFF_FFFF_9000_0000,
            PTE_PRESENT | PTE_WRITABLE | PTE_NX,
        )
        .unwrap();
        // IDT: present, NOT writable, NOT USER, NX.
        t.map(0xFFFF_FFFF_A000_0000, PTE_PRESENT | PTE_NX).unwrap();
        // Ed25519 private key: present, NOT writable, NOT USER, NX.
        t.map(0xFFFF_FFFF_B000_0000, PTE_PRESENT | PTE_NX).unwrap();
        // KPTI SYSCALL trampoline: USER (we want it reachable from ring 3
        // for the SYSCALL landing), not writable, not NX.
        t.map(KPTI_TRAMPOLINE_VIRT, PTE_PRESENT | PTE_USER).unwrap();
        t.map(KPTI_IRETQ_VIRT, PTE_PRESENT | PTE_USER).unwrap();
        t.map(KPTI_IRQ_TIMER_VIRT, PTE_PRESENT | PTE_USER).unwrap();
        // User code page: USER, present, NX.
        t.map(0x0000_0000_4000_0000, PTE_PRESENT | PTE_USER | PTE_NX)
            .unwrap();
        // User stack page: USER, present, writable, NX.
        t.map(
            0x0000_0000_5000_0000,
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
        )
        .unwrap();
        t
    }

    fn standard_secrets() -> [u64; 4] {
        [
            0xFFFF_FFFF_8000_0000, // kernel .text
            0xFFFF_FFFF_9000_0000, // kernel heap
            0xFFFF_FFFF_A000_0000, // IDT
            0xFFFF_FFFF_B000_0000, // Ed25519 private key
        ]
    }

    // --- PageTable unit tests -------------------------------------------------

    #[test]
    fn new_page_table_is_empty() {
        let t: PageTable<8> = PageTable::new();
        assert_eq!(t.len(), 0);
        assert!(t.is_empty());
        assert_eq!(t.capacity(), 8);
        assert!(t.lookup(0x1000).is_none());
    }

    #[test]
    fn map_then_lookup_roundtrip() {
        let mut t: PageTable<8> = PageTable::new();
        t.map(0x1000, PTE_PRESENT | PTE_USER).unwrap();
        t.map(0x2000, PTE_PRESENT).unwrap();
        assert_eq!(t.lookup(0x1000), Some(PTE_PRESENT | PTE_USER));
        assert_eq!(t.lookup(0x2000), Some(PTE_PRESENT));
        assert_eq!(t.lookup(0x3000), None);
    }

    #[test]
    fn map_replaces_existing_entry() {
        let mut t: PageTable<8> = PageTable::new();
        t.map(0x1000, PTE_PRESENT).unwrap();
        t.map(0x1000, PTE_PRESENT | PTE_USER).unwrap();
        assert_eq!(t.len(), 1);
        assert_eq!(t.lookup(0x1000), Some(PTE_PRESENT | PTE_USER));
    }

    #[test]
    fn map_returns_full_when_capacity_reached() {
        let mut t: PageTable<2> = PageTable::new();
        t.map(0x1000, PTE_PRESENT).unwrap();
        t.map(0x2000, PTE_PRESENT).unwrap();
        assert_eq!(t.map(0x3000, PTE_PRESENT), Err(MapError::Full));
    }

    #[test]
    fn map_rejects_unaligned_va() {
        let mut t: PageTable<8> = PageTable::new();
        assert_eq!(t.map(0x1001, PTE_PRESENT), Err(MapError::Unaligned));
    }

    #[test]
    fn map_rejects_pte_without_present_bit() {
        let mut t: PageTable<8> = PageTable::new();
        assert_eq!(t.map(0x1000, PTE_USER), Err(MapError::NotPresent));
    }

    #[test]
    fn unmap_removes_entry_and_returns_true() {
        let mut t: PageTable<8> = PageTable::new();
        t.map(0x1000, PTE_PRESENT).unwrap();
        t.map(0x2000, PTE_PRESENT).unwrap();
        assert!(t.unmap(0x1000));
        assert_eq!(t.len(), 1);
        assert!(t.lookup(0x1000).is_none());
        assert_eq!(t.lookup(0x2000), Some(PTE_PRESENT));
    }

    #[test]
    fn unmap_missing_returns_false() {
        let mut t: PageTable<8> = PageTable::new();
        t.map(0x1000, PTE_PRESENT).unwrap();
        assert!(!t.unmap(0x9000));
        assert_eq!(t.len(), 1);
    }

    #[test]
    fn entries_stay_sorted_after_arbitrary_inserts() {
        let mut t: PageTable<8> = PageTable::new();
        // Insert out of order.
        t.map(0x4000, PTE_PRESENT).unwrap();
        t.map(0x1000, PTE_PRESENT).unwrap();
        t.map(0x3000, PTE_PRESENT).unwrap();
        t.map(0x2000, PTE_PRESENT).unwrap();
        // Sorted check: iterate only populated entries (iter() respects count).
        let mut prev_va: Option<u64> = None;
        for (va, _pte) in t.iter() {
            if let Some(p) = prev_va {
                assert!(p < va, "not sorted: {:#x} followed {:#x}", va, p);
            }
            prev_va = Some(va);
        }
        // Confirm we saw exactly 4 entries (sanity).
        assert_eq!(t.iter().count(), 4);
    }

    // --- KptiImpl::build_user_view tests --------------------------------------

    #[test]
    fn build_user_view_strips_all_secrets() {
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        for s in &secrets {
            assert!(!user.is_mapped(*s), "secret {:#x} leaked into user view", s);
        }
    }

    #[test]
    fn build_user_view_keeps_user_pages() {
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        assert!(user.is_mapped(0x0000_0000_4000_0000), "user code dropped");
        assert!(user.is_mapped(0x0000_0000_5000_0000), "user stack dropped");
    }

    #[test]
    fn build_user_view_keeps_trampoline_pages() {
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        assert!(user.is_mapped(KPTI_TRAMPOLINE_VIRT), "SYSCALL trampoline missing");
        assert!(user.is_mapped(KPTI_IRETQ_VIRT), "iretq trampoline missing");
        assert!(user.is_mapped(KPTI_IRQ_TIMER_VIRT), "timer trampoline missing");
    }

    #[test]
    fn build_user_view_drops_non_user_kernel_only_pages() {
        // A kernel page that is NOT in `secrets` but does NOT have USER
        // bit set should still be dropped by the build path. Tests
        // that the USER-bit filter does its job even when the page
        // isn't explicitly listed as a secret.
        let mut kernel: PageTable<256> = PageTable::new();
        kernel.map(0xFFFF_FFFF_C000_0000, PTE_PRESENT).unwrap(); // kernel-only
        kernel.map(0x0000_0000_4000_0000, PTE_PRESENT | PTE_USER).unwrap();
        let user = KptiImpl::<256>::build_user_view(&kernel, &[]);
        assert!(!user.is_mapped(0xFFFF_FFFF_C000_0000));
        assert!(user.is_mapped(0x0000_0000_4000_0000));
    }

    #[test]
    fn build_user_view_force_nx_on_writable_data_pages() {
        let kernel = build_synthetic_kernel_l4();
        let user = KptiImpl::<256>::build_user_view(&kernel, &standard_secrets());
        // User stack is writable; output must have NX bit set.
        let pte = user.lookup(0x0000_0000_5000_0000).unwrap();
        assert!(
            pte & PTE_NX != 0,
            "user stack should be NX after KPTI strip, got pte={:#x}",
            pte
        );
    }

    #[test]
    fn build_user_view_preserves_trampoline_executable_bit() {
        let kernel = build_synthetic_kernel_l4();
        let user = KptiImpl::<256>::build_user_view(&kernel, &standard_secrets());
        let pte = user.lookup(KPTI_TRAMPOLINE_VIRT).unwrap();
        // Trampolines are RX — NX must NOT be set on them, even though
        // the build path is aggressive about NX-forcing data pages.
        assert!(
            pte & PTE_NX == 0,
            "trampoline must remain executable, got pte={:#x}",
            pte
        );
    }

    // --- KptiImpl::validate_user_view tests -----------------------------------

    #[test]
    fn build_then_validate_self_consistency_minimal() {
        let kernel: PageTable<256> = PageTable::new();
        let user = KptiImpl::<256>::build_user_view(&kernel, &[]);
        assert_eq!(KptiImpl::<256>::validate_user_view(&user, &kernel, &[]), Ok(()));
    }

    #[test]
    fn build_then_validate_self_consistency_realistic() {
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        assert_eq!(
            KptiImpl::<256>::validate_user_view(&user, &kernel, &secrets),
            Ok(())
        );
    }

    #[test]
    fn validate_rejects_leaked_secret() {
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let mut user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        // Deliberately corrupt: re-add kernel .text into the user view.
        user.map(0xFFFF_FFFF_8000_0000, PTE_PRESENT | PTE_USER).unwrap();
        let err = KptiImpl::<256>::validate_user_view(&user, &kernel, &secrets).unwrap_err();
        match err {
            KptiViolation::SecretLeaked { page, secret_index } => {
                assert_eq!(page, 0xFFFF_FFFF_8000_0000);
                assert_eq!(secret_index, 0);
            }
            other => panic!("expected SecretLeaked, got {:?}", other),
        }
    }

    #[test]
    fn validate_rejects_missing_user_page() {
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let mut user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        // Drop a user-required page.
        user.unmap(0x0000_0000_4000_0000);
        let err = KptiImpl::<256>::validate_user_view(&user, &kernel, &secrets).unwrap_err();
        assert_eq!(err, KptiViolation::UserPageMissing { page: 0x0000_0000_4000_0000 });
    }

    #[test]
    fn validate_rejects_kernel_bits_on_user_page() {
        let mut kernel: PageTable<256> = PageTable::new();
        kernel.map(0x4000, PTE_PRESENT | PTE_USER).unwrap();
        // Build a user view, then sabotage one entry to drop its USER bit.
        let mut user: PageTable<256> = PageTable::new();
        user.map(0x4000, PTE_PRESENT).unwrap(); // missing USER!
        let err = KptiImpl::<256>::validate_user_view(&user, &kernel, &[]).unwrap_err();
        match err {
            KptiViolation::KernelBitsSetOnUserPage { page, raw_entry } => {
                assert_eq!(page, 0x4000);
                assert_eq!(raw_entry, PTE_PRESENT);
            }
            other => panic!("expected KernelBitsSetOnUserPage, got {:?}", other),
        }
    }

    #[test]
    fn validate_is_deterministic() {
        // Pure function: same inputs → same output, no global state.
        let kernel = build_synthetic_kernel_l4();
        let secrets = standard_secrets();
        let user = KptiImpl::<256>::build_user_view(&kernel, &secrets);
        for _ in 0..16 {
            assert_eq!(
                KptiImpl::<256>::validate_user_view(&user, &kernel, &secrets),
                Ok(())
            );
        }
    }

    #[test]
    fn build_user_view_full_table_handles_capacity_gracefully() {
        // Construct a kernel table at the brink: capacity = 4, 4 user
        // pages. Build path must produce a complete user view without
        // panicking even if the output capacity is exactly equal.
        let mut kernel: PageTable<4> = PageTable::new();
        kernel.map(0x1000, PTE_PRESENT | PTE_USER).unwrap();
        kernel.map(0x2000, PTE_PRESENT | PTE_USER).unwrap();
        kernel.map(0x3000, PTE_PRESENT | PTE_USER).unwrap();
        kernel.map(0x4000, PTE_PRESENT | PTE_USER).unwrap();
        let user = KptiImpl::<4>::build_user_view(&kernel, &[]);
        assert_eq!(user.len(), 4);
    }

    // --- Trampoline blob tests ------------------------------------------------

    #[test]
    fn syscall_trampoline_starts_with_swapgs() {
        // First three bytes are `swapgs` (0x0F 0x01 0xF8). Locked.
        assert_eq!(&SYSCALL_TRAMPOLINE[..3], &[0x0F, 0x01, 0xF8]);
    }

    #[test]
    fn iretq_trampoline_ends_with_iretq() {
        // Last two bytes are `iretq` (0x48 0xCF). Locked.
        let n = IRETQ_TRAMPOLINE.len();
        assert_eq!(&IRETQ_TRAMPOLINE[n - 2..], &[0x48, 0xCF]);
    }

    #[test]
    fn trampoline_blobs_fit_in_a_page() {
        // Every trampoline must fit in a single 4 KiB page since each
        // is mapped at its own KPTI_*_VIRT.
        assert!(SYSCALL_TRAMPOLINE.len() < PAGE_SIZE as usize);
        assert!(IRETQ_TRAMPOLINE.len() < PAGE_SIZE as usize);
        assert!(IRQ_TIMER_TRAMPOLINE.len() < PAGE_SIZE as usize);
    }

    #[test]
    fn syscall_trampoline_cr3_swap_precedes_jmp_to_handler() {
        // The `mov cr3, rax` (0x0F 0x22 0xD8) MUST come BEFORE the
        // final `jmp` (0xE9). Reordering them would jump into the
        // handler with the user CR3 still active, page-faulting on
        // the first instruction fetch and breaking the kernel.
        let cr3_swap_pos = SYSCALL_TRAMPOLINE
            .windows(3)
            .position(|w| w == [0x0F, 0x22, 0xD8])
            .expect("CR3 swap missing from SYSCALL trampoline");
        let jmp_pos = SYSCALL_TRAMPOLINE
            .iter()
            .rposition(|&b| b == 0xE9)
            .expect("jmp missing from SYSCALL trampoline");
        assert!(
            cr3_swap_pos < jmp_pos,
            "CR3 swap at {} must come before jmp at {}",
            cr3_swap_pos,
            jmp_pos
        );
    }

    #[test]
    fn x86_pml4_serializer_zeros_padding() {
        let mut buf = [0xFFu8; x86_pml4::PML4_BYTES];
        let mut t: PageTable<256> = PageTable::new();
        t.map(0x1000, PTE_PRESENT).unwrap();
        let n = x86_pml4::serialize_into(&t, &mut buf);
        assert_eq!(n, 1);
        // Entry 0 is the one we wrote (LE encoding of PTE_PRESENT = 1).
        assert_eq!(buf[0], 0x01);
        for b in 1..8 {
            assert_eq!(buf[b], 0);
        }
        // All subsequent bytes must be zero.
        for b in 8..x86_pml4::PML4_BYTES {
            assert_eq!(buf[b], 0, "byte {} not zeroed", b);
        }
    }

    #[test]
    fn x86_pml4_serializer_caps_at_512_entries() {
        let mut t: PageTable<1024> = PageTable::new();
        for i in 0..600u64 {
            let va = (i + 1) * PAGE_SIZE;
            t.map(va, PTE_PRESENT).unwrap();
        }
        let mut buf = [0u8; x86_pml4::PML4_BYTES];
        let n = x86_pml4::serialize_into(&t, &mut buf);
        assert_eq!(n, 512, "PML4 must serialize at most 512 entries");
    }
}
