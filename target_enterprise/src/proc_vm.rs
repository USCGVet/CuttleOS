//! Multi-process Ring-3 (`CPL=3`) ELF64 virtual memory layout, `UserTrapFrame` context,
//! capability-gated extended syscall dispatch, IPC mailboxes, and preemptive SMP process table (`proc_vm`).
//!
//! # Per-process 2 MiB `PD[0]` virtual layout (`proc_base_va = ((64 + slot) as u64) << 39`)
//! Every active process owns a dedicated lower-half 512 GiB PML4 slot (`64 .. 64 + MAX_PROCS`)
//! whose isolated `user_pml4` maps **zero** higher-half kernel PML4 entries (`256..512`) and
//! **zero** peer-process slots:
//!
//! - `PT[0 .. 64)` (`256 KiB`): Multi-page ELF64 `PT_LOAD` segments enforcing strict `W^X`
//!   (`PF_X -> User RX`, `PF_W -> User RW+NX`, `PF_R -> User RO+NX`).
//! - `PT[64]`: Unmapped (`PTE_P = 0`) guard page isolating `.bss` from the user heap.
//! - `PT[65 .. 97)` (`128 KiB`): Dynamic `PROC_SYS_BRK` user heap (`User RW+NX`), demand-allocated
//!   and reclaimed page-by-page.
//! - `PT[97]`: Unmapped (`PTE_P = 0`) bottom stack guard page (catches Ring-3 stack overflow via `#PF`).
//! - `PT[98 .. 102)` (`16 KiB` = 4 pages): User stack (`User RW+NX`, initial `RSP = base + 0x6_5FF0`).
//! - `PT[102]`: Unmapped (`PTE_P = 0`) top stack guard page.
//! - `PT[103]` (`4 KiB`): Per-process structured Ring-3 IPC / service mailbox page (`User RW+NX`).
//! - `PT[104 .. 508)`: Unmapped (`PTE_P = 0`) isolation moat.
//! - `PT[508]`: KPTI Supervisor `RX` trampoline (`PTE_USER = 0`, `entry_to_ring3`, `int 0x80`,
//!   `SYSCALL` `LSTAR`, `0x50` preemption timer, `0..31` fault stubs).
//! - `PT[509]`: KPTI Supervisor `RW+NX` (`PTE_USER = 0`) GDT, TSS, `ProcBridgeState`, `RSP0`, `IST1`.
//! - `PT[510]`: KPTI Supervisor `RO+NX` (`PTE_USER = 0`) 256-entry IDT.
//! - `PT[511]`: Unmapped (`PTE_P = 0`) trailing guard page.

use cuttle_contracts::{
    Elf64, ElfError, ElfPhdr, ELF_CLASS64, ELF_DATA_LE, ELF_EHDR_LEN, ELF_EM_X86_64, ELF_ET_DYN,
    ELF_MAGIC, ELF_MAX_PHDRS, ELF_PHDR_LEN, ELF_PT_LOAD,
};

use crate::elf64::Elf64Impl;
use crate::kpti::{PTE_NX, PTE_PRESENT, PTE_USER, PTE_WRITABLE};
use crate::phys_mm::PageFrameSource;
use crate::svc_runtime::{ServiceId, SVC_CAP_IPC};
use crate::syscall::{dispatch_syscall, Errno, SYS_EXIT, SYS_GETPID, SYS_MAX, SYS_READ, SYS_SLEEP_MS, SYS_WRITE, SYS_YIELD};

/// Maximum concurrent Ring-3 processes tracked in [`ProcessTable`].
pub const MAX_PROCS: usize = 16;

/// First lower-half PML4 index reserved for per-process isolated address spaces (`96..112`),
/// strictly disjoint from transient `exec_service_ring3_core` slot `64` and higher-half kernel `256..512`.
pub const PROC_PML4_BASE_SLOT: usize = 96;

/// Maximum 4 KiB pages mapped by ELF64 `PT_LOAD` segments (`PT[0..64)` = `256 KiB`).
pub const PROC_MAX_ELF_PAGES: usize = 64;

/// First L1 PT index of the dynamic `PROC_SYS_BRK` heap (`PT[65]`, above `PT[64]` guard).
pub const PROC_HEAP_FIRST_PT: usize = 65;

/// Maximum 4 KiB pages in the dynamic `PROC_SYS_BRK` heap (`32` pages = `128 KiB`, `PT[65..97)`).
pub const PROC_MAX_HEAP_PAGES: usize = 32;

/// Unmapped bottom stack guard PT index (`PT[97]`).
pub const PROC_STACK_GUARD_LO_PT: usize = 97;

/// First L1 PT index of the 4-page (`16 KiB`) Ring-3 stack (`PT[98..102)`).
pub const PROC_STACK_FIRST_PT: usize = 98;

/// Number of 4 KiB pages in each process's Ring-3 stack (`4` pages = `16 KiB`).
pub const PROC_STACK_PAGES: usize = 4;

/// Unmapped top stack guard PT index (`PT[102]`).
pub const PROC_STACK_GUARD_HI_PT: usize = 102;

/// L1 PT index of the 4 KiB structured IPC / service mailbox page (`PT[103]`).
pub const PROC_IPC_PAGE_PT: usize = 103;

/// L1 PT index of the KPTI Supervisor `RX` trampoline page (`PT[508]`).
pub const PROC_TRAMP_PT: usize = 508;

/// L1 PT index of the KPTI Supervisor `RW+NX` GDT/TSS/bridge/stacks page (`PT[509]`).
pub const PROC_SUP_RW_PT: usize = 509;

/// L1 PT index of the KPTI Supervisor `RO+NX` 256-entry IDT page (`PT[510]`).
pub const PROC_SUP_IDT_PT: usize = 510;

/// Extended Ring-3 syscall: query (`a0 == 0`) or set (`a0 = new_brk`) dynamic user heap break.
pub const PROC_SYS_BRK: u64 = 64;

/// Extended Ring-3 syscall: send bounded IPC message `(dst_pid, tag, user_va, len)`.
pub const PROC_SYS_IPC_SEND: u64 = 65;

/// Extended Ring-3 syscall: non-blocking receive IPC message `(user_va, max_len, tag_out_va)`.
pub const PROC_SYS_IPC_RECV: u64 = 66;

/// Extended Ring-3 syscall: return hardware SMP CPU core index (`0..3`) executing this quantum.
pub const PROC_SYS_GETCPU: u64 = 67;

/// POSIX `ENOMEM` (`12`) returned negatively (`-12`) when `PROC_SYS_BRK` exceeds the heap window or physical RAM.
pub const PROC_ENOMEM: i64 = 12;

/// Maximum bytes retained in a process's captured `stdout`/`stderr` ring.
pub const PROC_STDOUT_CAP: usize = 256;

/// Maximum queued IPC messages per process inbox.
pub const PROC_IPC_INBOX_CAP: usize = 4;

/// Maximum payload bytes per IPC message.
pub const PROC_IPC_MSG_MAX: usize = 128;

/// Full 18-register x86-64 architectural Ring-3 execution state (`144` bytes).
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct UserTrapFrame {
    /// General-purpose register `rax` (syscall number on entry, return value on resume).
    pub rax: u64,
    /// General-purpose register `rbx`.
    pub rbx: u64,
    /// General-purpose register `rcx` (clobbered with next `RIP` by hardware `SYSCALL`).
    pub rcx: u64,
    /// General-purpose register `rdx` (syscall `arg2`).
    pub rdx: u64,
    /// General-purpose register `rsi` (syscall `arg1`).
    pub rsi: u64,
    /// General-purpose register `rdi` (syscall `arg0`).
    pub rdi: u64,
    /// Frame pointer `rbp`.
    pub rbp: u64,
    /// General-purpose register `r8` (syscall `arg4`).
    pub r8: u64,
    /// General-purpose register `r9` (syscall `arg5`).
    pub r9: u64,
    /// General-purpose register `r10` (syscall `arg3`).
    pub r10: u64,
    /// General-purpose register `r11` (clobbered with `RFLAGS` by hardware `SYSCALL`).
    pub r11: u64,
    /// General-purpose register `r12`.
    pub r12: u64,
    /// General-purpose register `r13`.
    pub r13: u64,
    /// General-purpose register `r14`.
    pub r14: u64,
    /// General-purpose register `r15`.
    pub r15: u64,
    /// User instruction pointer `rip`.
    pub rip: u64,
    /// User stack pointer `rsp`.
    pub rsp: u64,
    /// User flags register `rflags` (`0x202` with `IF = 1` for preemptible execution).
    pub rflags: u64,
}

/// The `RFLAGS` bits a ring-3 process owns: the arithmetic status flags
/// (`CF`, `PF`, `AF`, `ZF`, `SF`, `OF`) and `DF`.
pub const USER_RFLAGS_OWNED: u64 = 0x0000_0CD5;

/// The `RFLAGS` value to resume a ring-3 process with, given the value saved
/// when it left ring 3.
///
/// A saved value comes from user mode and can carry bits user code is able to
/// set but must not bring back through the kernel: `NT` (a kernel `iretq`
/// executed with it set faults), `TF`, `AC`, `ID`. `IOPL`, `RF`, `VM`, `VIF`
/// and `VIP` are never the process's to choose. So everything outside
/// [`USER_RFLAGS_OWNED`] is dropped, and `IF` (with the always-one bit 1) is
/// forced on so the preemption timer keeps firing.
pub const fn sanitize_user_rflags(saved: u64) -> u64 {
    (saved & USER_RFLAGS_OWNED) | 0x202
}

/// Lifecycle state of an entry in [`ProcessTable`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcState {
    /// Slot is free.
    Unused,
    /// Runnable and eligible to be claimed by any SMP core (`CPU 0..3`).
    Ready,
    /// Currently executing a hardware Ring-3 quantum on `running_cpu`.
    Running,
    /// Cleanly terminated via `SYS_EXIT(exit_code)`; frames reclaimed.
    Exited,
    /// Terminated due to an isolated `CPL=3` hardware CPU fault (`#UD`, `#PF`, `#GP`, etc.); frames reclaimed.
    Faulted,
}

/// Hardware CPU fault details recorded when a `CPL=3` process faults without affecting Ring-0.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcFaultInfo {
    /// x86 exception vector (`6 = #UD`, `13 = #GP`, `14 = #PF`, etc.).
    pub vector: u8,
    /// Hardware error code pushed by CPU (or `0` for error-code-free vectors).
    pub error_code: u64,
    /// Faulting linear address from `CR2` (for `#PF`).
    pub cr2: u64,
    /// Faulting user `RIP`.
    pub rip: u64,
    /// Code selector (`0x23` confirming `CPL=3` origin).
    pub cs: u16,
}

/// Bounded inter-process message stored in a recipient PID's inbox.
#[derive(Copy, Clone, Debug)]
pub struct ProcIpcMsg {
    /// Sender PID.
    pub sender_pid: u32,
    /// Application-defined 32-bit message tag.
    pub tag: u32,
    /// Valid byte count in `data` (`0..=PROC_IPC_MSG_MAX`).
    pub len: usize,
    /// Message payload bytes.
    pub data: [u8; PROC_IPC_MSG_MAX],
}

impl ProcIpcMsg {
    const fn empty() -> Self {
        Self {
            sender_pid: 0,
            tag: 0,
            len: 0,
            data: [0u8; PROC_IPC_MSG_MAX],
        }
    }
}

/// Errors returned by ELF64 process loading, memory mapping, or IPC operations.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ProcError {
    /// Process table has no free slots.
    ProcessTableFull,
    /// Invalid or `W^X`-violating ELF64 binary.
    ElfInvalid(ElfError),
    /// ELF64 segment virtual range exceeds the per-process `PT[0..64)` window or overlaps a guard page.
    SegmentOutOfBounds,
    /// Entry point does not fall inside an executable (`PF_X`) `PT_LOAD` page.
    EntryNotExecutable,
    /// Physical frame allocator ran out of 4 KiB frames.
    OutOfPhysicalMemory,
    /// Invalid or non-existent PID.
    InvalidPid,
    /// User pointer `[va .. va + len)` crosses an unmapped, supervisor-only, or non-writable page.
    BadUserPointer,
    /// Target IPC inbox is full (`EAGAIN`).
    IpcQueueFull,
    /// Caller lacks required capability bit (`EPERM`).
    CapabilityDenied,
}

/// Per-page permission class in `PT[0..64)`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum UserPagePerm {
    /// Unmapped guard / unused slot (`0`).
    Unmapped,
    /// User Read + Execute (`PTE_PRESENT | PTE_USER`).
    ReadExec,
    /// User Read-Only + No-Execute (`PTE_PRESENT | PTE_USER | PTE_NX`).
    ReadOnly,
    /// User Read-Write + No-Execute (`PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX`).
    ReadWrite,
}

impl UserPagePerm {
    /// Convert to architectural x86-64 leaf PTE flags (excluding physical address).
    pub const fn pte_flags(self) -> u64 {
        match self {
            UserPagePerm::Unmapped => 0,
            UserPagePerm::ReadExec => PTE_PRESENT | PTE_USER,
            UserPagePerm::ReadOnly => PTE_PRESENT | PTE_USER | PTE_NX,
            UserPagePerm::ReadWrite => PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX,
        }
    }
}

/// Complete physical-frame ownership record for one isolated Ring-3 process.
#[derive(Copy, Clone)]
pub struct ProcAddressSpace {
    /// Slot index `0..MAX_PROCS` (`pml4_slot = PROC_PML4_BASE_SLOT + slot`).
    pub slot_idx: usize,
    /// Base user virtual address (`((64 + slot_idx) as u64) << 39`).
    pub base_va: u64,
    /// Isolated user `CR3` PML4 physical frame (`0` when reclaimed).
    pub user_pml4_pa: u64,
    /// L3 PDPT physical frame.
    pub pdpt_pa: u64,
    /// L2 PD physical frame.
    pub pd_pa: u64,
    /// L1 PT physical frame.
    pub pt_pa: u64,
    /// Physical frames backing `PT[0..64)` ELF64 `PT_LOAD` pages (`0` if unmapped).
    pub elf_page_pa: [u64; PROC_MAX_ELF_PAGES],
    /// Permissions for `PT[0..64)` ELF64 `PT_LOAD` pages.
    pub elf_page_perm: [UserPagePerm; PROC_MAX_ELF_PAGES],
    /// Physical frames backing `PT[65..97)` `PROC_SYS_BRK` heap pages (`0` if unmapped).
    pub heap_page_pa: [u64; PROC_MAX_HEAP_PAGES],
    /// Number of currently mapped heap pages (`0..=PROC_MAX_HEAP_PAGES`).
    pub heap_pages_mapped: usize,
    /// Current user heap break virtual address (`[heap_base_va .. heap_max_va]`).
    pub brk_va: u64,
    /// Physical frames backing `PT[98..102)` 16 KiB user stack.
    pub stack_page_pa: [u64; PROC_STACK_PAGES],
    /// Physical frame backing `PT[103]` 4 KiB IPC mailbox page.
    pub ipc_page_pa: u64,
    /// Physical frame backing `PT[508]` KPTI Supervisor `RX` trampoline page.
    pub tramp_pa: u64,
    /// Physical frame backing `PT[509]` KPTI Supervisor `RW+NX` GDT/TSS/state/stacks page.
    pub sup_rw_pa: u64,
    /// Physical frame backing `PT[510]` KPTI Supervisor `RO+NX` IDT page.
    pub sup_idt_pa: u64,
}

impl ProcAddressSpace {
    /// Construct an empty unallocated address-space record.
    pub const fn empty() -> Self {
        Self {
            slot_idx: 0,
            base_va: 0,
            user_pml4_pa: 0,
            pdpt_pa: 0,
            pd_pa: 0,
            pt_pa: 0,
            elf_page_pa: [0u64; PROC_MAX_ELF_PAGES],
            elf_page_perm: [UserPagePerm::Unmapped; PROC_MAX_ELF_PAGES],
            heap_page_pa: [0u64; PROC_MAX_HEAP_PAGES],
            heap_pages_mapped: 0,
            brk_va: 0,
            stack_page_pa: [0u64; PROC_STACK_PAGES],
            ipc_page_pa: 0,
            tramp_pa: 0,
            sup_rw_pa: 0,
            sup_idt_pa: 0,
        }
    }

    /// Lower-half PML4 index (`64 + slot_idx`).
    #[inline]
    pub const fn pml4_slot(&self) -> usize {
        PROC_PML4_BASE_SLOT + self.slot_idx
    }

    /// Start virtual address of the `PROC_SYS_BRK` heap (`PT[65]`).
    #[inline]
    pub const fn heap_base_va(&self) -> u64 {
        self.base_va + (PROC_HEAP_FIRST_PT as u64) * 4096
    }

    /// Maximum virtual address of the `PROC_SYS_BRK` heap (`PT[97]` guard boundary).
    #[inline]
    pub const fn heap_max_va(&self) -> u64 {
        self.base_va + ((PROC_HEAP_FIRST_PT + PROC_MAX_HEAP_PAGES) as u64) * 4096
    }

    /// Initial 16-byte-aligned top-of-stack virtual address inside `PT[101]`.
    #[inline]
    pub const fn initial_stack_rsp(&self) -> u64 {
        self.base_va + ((PROC_STACK_FIRST_PT + PROC_STACK_PAGES) as u64) * 4096 - 16
    }

    /// Virtual address of the 4 KiB user IPC mailbox page (`PT[103]`).
    #[inline]
    pub const fn ipc_page_va(&self) -> u64 {
        self.base_va + (PROC_IPC_PAGE_PT as u64) * 4096
    }

    /// Virtual address of KPTI Supervisor `RX` trampoline page (`PT[508]`).
    #[inline]
    pub const fn tramp_va(&self) -> u64 {
        self.base_va + (PROC_TRAMP_PT as u64) * 4096
    }

    /// Virtual address of KPTI Supervisor `RW+NX` GDT/TSS/state/stacks page (`PT[509]`).
    #[inline]
    pub const fn sup_rw_va(&self) -> u64 {
        self.base_va + (PROC_SUP_RW_PT as u64) * 4096
    }

    /// Virtual address of KPTI Supervisor `RO+NX` IDT page (`PT[510]`).
    #[inline]
    pub const fn sup_idt_va(&self) -> u64 {
        self.base_va + (PROC_SUP_IDT_PT as u64) * 4096
    }

    /// Count all non-zero physical 4 KiB frames currently owned by this process.
    pub fn owned_frame_count(&self) -> usize {
        let mut n = 0usize;
        for pa in [
            self.user_pml4_pa,
            self.pdpt_pa,
            self.pd_pa,
            self.pt_pa,
            self.ipc_page_pa,
            self.tramp_pa,
            self.sup_rw_pa,
            self.sup_idt_pa,
        ] {
            if pa != 0 {
                n += 1;
            }
        }
        let mut i = 0usize;
        while i < PROC_MAX_ELF_PAGES {
            if self.elf_page_pa[i] != 0 {
                n += 1;
            }
            i += 1;
        }
        let mut h = 0usize;
        while h < PROC_MAX_HEAP_PAGES {
            if self.heap_page_pa[h] != 0 {
                n += 1;
            }
            h += 1;
        }
        let mut s = 0usize;
        while s < PROC_STACK_PAGES {
            if self.stack_page_pa[s] != 0 {
                n += 1;
            }
            s += 1;
        }
        n
    }

    /// Translate a user virtual address `va` within `self` to `(phys_addr, page_offset, writable)`,
    /// rejecting unmapped pages, guard pages, and supervisor KPTI pages (`PT[508..510]`).
    pub fn translate_user_va(&self, va: u64) -> Option<(u64, usize, bool)> {
        if self.user_pml4_pa == 0 || va < self.base_va {
            return None;
        }
        let rel = va - self.base_va;
        let pt_idx = (rel / 4096) as usize;
        let page_off = (rel & 0xFFF) as usize;
        if pt_idx < PROC_MAX_ELF_PAGES {
            let pa = self.elf_page_pa[pt_idx];
            if pa == 0 {
                return None;
            }
            let writable = self.elf_page_perm[pt_idx] == UserPagePerm::ReadWrite;
            return Some((pa, page_off, writable));
        }
        if pt_idx >= PROC_HEAP_FIRST_PT && pt_idx < PROC_HEAP_FIRST_PT + self.heap_pages_mapped {
            let h_idx = pt_idx - PROC_HEAP_FIRST_PT;
            let pa = self.heap_page_pa[h_idx];
            if pa != 0 {
                return Some((pa, page_off, true));
            }
        }
        if pt_idx >= PROC_STACK_FIRST_PT && pt_idx < PROC_STACK_FIRST_PT + PROC_STACK_PAGES {
            let s_idx = pt_idx - PROC_STACK_FIRST_PT;
            let pa = self.stack_page_pa[s_idx];
            if pa != 0 {
                return Some((pa, page_off, true));
            }
        }
        if pt_idx == PROC_IPC_PAGE_PT && self.ipc_page_pa != 0 {
            return Some((self.ipc_page_pa, page_off, true));
        }
        None
    }

    /// Serialize the 512-entry `user_pml4`, `pdpt`, `pd`, and `pt` tables for this process,
    /// enforcing KPTI higher-half exclusion (`PML4[256..512] == 0`), unmapped stack/heap guard
    /// pages, and strict `W^X` across all 512 L1 PTEs.
    pub fn serialize_4level_tables(
        &self,
        pml4_out: &mut [u64; 512],
        pdpt_out: &mut [u64; 512],
        pd_out: &mut [u64; 512],
        pt_out: &mut [u64; 512],
    ) {
        pml4_out.fill(0);
        pdpt_out.fill(0);
        pd_out.fill(0);
        pt_out.fill(0);

        let pml4_idx = self.pml4_slot();
        pml4_out[pml4_idx] = self.pdpt_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        pdpt_out[0] = self.pd_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER;
        pd_out[0] = self.pt_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER;

        let mut i = 0usize;
        while i < PROC_MAX_ELF_PAGES {
            if self.elf_page_pa[i] != 0 {
                pt_out[i] = self.elf_page_pa[i] | self.elf_page_perm[i].pte_flags();
            }
            i += 1;
        }
        // PT[64] = 0 (heap bottom guard)
        let mut h = 0usize;
        while h < self.heap_pages_mapped && h < PROC_MAX_HEAP_PAGES {
            if self.heap_page_pa[h] != 0 {
                pt_out[PROC_HEAP_FIRST_PT + h] =
                    self.heap_page_pa[h] | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX;
            }
            h += 1;
        }
        // PT[97] = 0 (stack bottom guard)
        let mut s = 0usize;
        while s < PROC_STACK_PAGES {
            pt_out[PROC_STACK_FIRST_PT + s] =
                self.stack_page_pa[s] | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX;
            s += 1;
        }
        // PT[102] = 0 (stack top guard)
        pt_out[PROC_IPC_PAGE_PT] =
            self.ipc_page_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX;

        // KPTI Supervisor-only entry/exit trampolines (`PTE_USER = 0`!).
        pt_out[PROC_TRAMP_PT] = self.tramp_pa | PTE_PRESENT;
        pt_out[PROC_SUP_RW_PT] = self.sup_rw_pa | PTE_PRESENT | PTE_WRITABLE | PTE_NX;
        pt_out[PROC_SUP_IDT_PT] = self.sup_idt_pa | PTE_PRESENT | PTE_NX;
    }

    /// Write the 4-level KPTI isolated page tables directly into `user_pml4_pa..pt_pa` via `source`
    /// without allocating `[u64; 512]` (`4 KiB`) arrays on the kernel stack.
    pub fn write_4level_tables_to_source<S: PageFrameSource>(&self, source: &mut S) {
        let zero64 = [0u8; 64];
        for pa in [self.user_pml4_pa, self.pdpt_pa, self.pd_pa, self.pt_pa] {
            let mut off = 0usize;
            while off < 4096 {
                source.write_frame_bytes(pa, off, &zero64);
                off += 64;
            }
        }

        let pml4_idx = self.pml4_slot();
        source.write_frame_u64_at(
            self.user_pml4_pa,
            pml4_idx,
            self.pdpt_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER,
        );
        source.write_frame_u64_at(
            self.pdpt_pa,
            0,
            self.pd_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER,
        );
        source.write_frame_u64_at(
            self.pd_pa,
            0,
            self.pt_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER,
        );

        let mut i = 0usize;
        while i < PROC_MAX_ELF_PAGES {
            if self.elf_page_pa[i] != 0 {
                source.write_frame_u64_at(
                    self.pt_pa,
                    i,
                    self.elf_page_pa[i] | self.elf_page_perm[i].pte_flags(),
                );
            }
            i += 1;
        }
        let mut h = 0usize;
        while h < self.heap_pages_mapped && h < PROC_MAX_HEAP_PAGES {
            if self.heap_page_pa[h] != 0 {
                source.write_frame_u64_at(
                    self.pt_pa,
                    PROC_HEAP_FIRST_PT + h,
                    self.heap_page_pa[h] | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX,
                );
            }
            h += 1;
        }
        let mut s = 0usize;
        while s < PROC_STACK_PAGES {
            source.write_frame_u64_at(
                self.pt_pa,
                PROC_STACK_FIRST_PT + s,
                self.stack_page_pa[s] | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX,
            );
            s += 1;
        }
        source.write_frame_u64_at(
            self.pt_pa,
            PROC_IPC_PAGE_PT,
            self.ipc_page_pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX,
        );
        source.write_frame_u64_at(self.pt_pa, PROC_TRAMP_PT, self.tramp_pa | PTE_PRESENT);
        source.write_frame_u64_at(
            self.pt_pa,
            PROC_SUP_RW_PT,
            self.sup_rw_pa | PTE_PRESENT | PTE_WRITABLE | PTE_NX,
        );
        source.write_frame_u64_at(
            self.pt_pa,
            PROC_SUP_IDT_PT,
            self.sup_idt_pa | PTE_PRESENT | PTE_NX,
        );
    }

    /// Reset all fields of `self` in place without constructing a stack temporary.
    pub fn reset_in_place(&mut self, slot_idx: usize) {
        self.slot_idx = slot_idx;
        self.base_va = ((PROC_PML4_BASE_SLOT + slot_idx) as u64) << 39;
        self.user_pml4_pa = 0;
        self.pdpt_pa = 0;
        self.pd_pa = 0;
        self.pt_pa = 0;
        self.elf_page_pa.fill(0);
        self.elf_page_perm.fill(UserPagePerm::Unmapped);
        self.heap_page_pa.fill(0);
        self.heap_pages_mapped = 0;
        self.brk_va = 0;
        self.stack_page_pa.fill(0);
        self.ipc_page_pa = 0;
        self.tramp_pa = 0;
        self.sup_rw_pa = 0;
        self.sup_idt_pa = 0;
    }

    /// Release every owned physical frame via `source` and reset `self` to empty.
    pub fn release_all_frames<S: PageFrameSource>(&mut self, source: &mut S) -> usize {
        let mut freed = 0usize;
        let mut i = 0usize;
        while i < PROC_MAX_ELF_PAGES {
            if self.elf_page_pa[i] != 0 {
                source.free_zeroed_frame(self.elf_page_pa[i]);
                self.elf_page_pa[i] = 0;
                self.elf_page_perm[i] = UserPagePerm::Unmapped;
                freed += 1;
            }
            i += 1;
        }
        let mut h = 0usize;
        while h < PROC_MAX_HEAP_PAGES {
            if self.heap_page_pa[h] != 0 {
                source.free_zeroed_frame(self.heap_page_pa[h]);
                self.heap_page_pa[h] = 0;
                freed += 1;
            }
            h += 1;
        }
        self.heap_pages_mapped = 0;
        let mut s = 0usize;
        while s < PROC_STACK_PAGES {
            if self.stack_page_pa[s] != 0 {
                source.free_zeroed_frame(self.stack_page_pa[s]);
                self.stack_page_pa[s] = 0;
                freed += 1;
            }
            s += 1;
        }
        for pa_slot in [
            &mut self.ipc_page_pa,
            &mut self.tramp_pa,
            &mut self.sup_rw_pa,
            &mut self.sup_idt_pa,
            &mut self.pt_pa,
            &mut self.pd_pa,
            &mut self.pdpt_pa,
            &mut self.user_pml4_pa,
        ] {
            if *pa_slot != 0 {
                source.free_zeroed_frame(*pa_slot);
                *pa_slot = 0;
                freed += 1;
            }
        }
        freed
    }
}

/// Process Control Block (`PCB`) stored inside [`ProcessTable`].
#[derive(Copy, Clone)]
pub struct ProcessEntry {
    /// Monotonically assigned non-zero process ID (`>= 100`).
    pub pid: u32,
    /// Lifecycle state.
    pub state: ProcState,
    /// Optional supervised appliance service role (`svc-http`, `svc-sql`, `svc-sh`).
    pub service_id: Option<ServiceId>,
    /// Binary diversification seed active for this process instance.
    pub variant_seed: u64,
    /// Per-process capability bitmask enforced on every syscall.
    pub cap_mask: u64,
    /// Saved 18-register Ring-3 context.
    pub trap_frame: UserTrapFrame,
    /// Per-process isolated KPTI 4-level address space and owned physical frames.
    pub vm: ProcAddressSpace,
    /// Exit status passed to `SYS_EXIT` (when `state == ProcState::Exited`).
    pub exit_code: i32,
    /// Recorded CPU exception telemetry (when `state == ProcState::Faulted`).
    pub last_fault: ProcFaultInfo,
    /// Hardware SMP core (`0..3`) currently or most recently executing this PID.
    pub last_cpu: u8,
    /// Allowed SMP core bitmask (`0xFF` = any core; `1 << cpu` = pinned to `cpu`).
    pub cpu_affinity_mask: u8,
    /// Bitmask of SMP cores (`1 << cpu`) that have executed at least one quantum of this PID.
    pub cpu_mask_seen: u8,
    /// Number of hardware timer (`0x50`) or `SYS_YIELD` preemptions survived by this PID.
    pub preemptions: u64,
    /// Number of Ring-3 syscalls (`int 0x80` + `SYSCALL`) executed by this PID.
    pub syscalls: u64,
    /// Captured `SYS_WRITE(1/2, ...)` output bytes.
    pub stdout_buf: [u8; PROC_STDOUT_CAP],
    /// Valid byte count in `stdout_buf`.
    pub stdout_len: usize,
    /// Bounded IPC message inbox.
    pub inbox: [ProcIpcMsg; PROC_IPC_INBOX_CAP],
    /// Number of messages waiting in `inbox`.
    pub inbox_len: usize,
    /// Snapshot of `PT[103] + 0x270` (`verdict_out`) captured immediately before `SYS_EXIT` scrubs `ipc_page_pa`.
    pub last_ipc_status: u32,
    /// Snapshot of `PT[103] + 0x268` (`fnv_out`) captured immediately before `SYS_EXIT` scrubs `ipc_page_pa`.
    pub last_ipc_fnv: u64,
}

impl ProcessEntry {
    const fn empty(slot_idx: usize) -> Self {
        let mut vm = ProcAddressSpace::empty();
        vm.slot_idx = slot_idx;
        vm.base_va = ((PROC_PML4_BASE_SLOT + slot_idx) as u64) << 39;
        Self {
            pid: 0,
            state: ProcState::Unused,
            service_id: None,
            variant_seed: 0,
            cap_mask: 0,
            trap_frame: UserTrapFrame {
                rax: 0,
                rbx: 0,
                rcx: 0,
                rdx: 0,
                rsi: 0,
                rdi: 0,
                rbp: 0,
                r8: 0,
                r9: 0,
                r10: 0,
                r11: 0,
                r12: 0,
                r13: 0,
                r14: 0,
                r15: 0,
                rip: 0,
                rsp: 0,
                rflags: 0x202,
            },
            vm,
            exit_code: 0,
            last_fault: ProcFaultInfo {
                vector: 0,
                error_code: 0,
                cr2: 0,
                rip: 0,
                cs: 0,
            },
            last_cpu: 0,
            cpu_affinity_mask: 0xFF,
            cpu_mask_seen: 0,
            preemptions: 0,
            syscalls: 0,
            stdout_buf: [0u8; PROC_STDOUT_CAP],
            stdout_len: 0,
            inbox: [ProcIpcMsg::empty(); PROC_IPC_INBOX_CAP],
            inbox_len: 0,
            last_ipc_status: 0,
            last_ipc_fnv: 0,
        }
    }

    /// Reset all PCB fields in place so kernel callers on 16 KiB guarded stacks never materialize
    /// a multi-kilobyte `ProcessEntry` by value on the stack.
    pub fn reset_in_place(&mut self, slot_idx: usize) {
        self.pid = 0;
        self.state = ProcState::Unused;
        self.service_id = None;
        self.variant_seed = 0;
        self.cap_mask = 0;
        self.trap_frame = UserTrapFrame {
            rax: 0,
            rbx: 0,
            rcx: 0,
            rdx: 0,
            rsi: 0,
            rdi: 0,
            rbp: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r11: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            rip: 0,
            rsp: 0,
            rflags: 0x202,
        };
        self.vm.reset_in_place(slot_idx);
        self.exit_code = 0;
        self.last_fault = ProcFaultInfo {
            vector: 0,
            error_code: 0,
            cr2: 0,
            rip: 0,
            cs: 0,
        };
        self.last_cpu = 0;
        self.cpu_affinity_mask = 0xFF;
        self.cpu_mask_seen = 0;
        self.preemptions = 0;
        self.syscalls = 0;
        self.stdout_buf.fill(0);
        self.stdout_len = 0;
        let mut m = 0usize;
        while m < PROC_IPC_INBOX_CAP {
            self.inbox[m].sender_pid = 0;
            self.inbox[m].tag = 0;
            self.inbox[m].len = 0;
            self.inbox[m].data.fill(0);
            m += 1;
        }
        self.inbox_len = 0;
        self.last_ipc_status = 0;
        self.last_ipc_fnv = 0;
    }
}

/// Outcome of handling a single Ring-3 syscall in [`ProcessTable::handle_syscall`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum SyscallStepOutcome {
    /// Syscall completed; resume Ring-3 process (with `tf.rax` updated).
    Continue,
    /// Process voluntarily yielded (`SYS_YIELD` / `SYS_SLEEP_MS`); marked `Ready` for round-robin switch.
    Yielded,
    /// Process called `SYS_EXIT(code)`; frames freed and state moved to `Exited`.
    Exited(i32),
}

/// Multi-core SMP-safe Ring-3 process table and round-robin run-queue.
pub struct ProcessTable {
    /// Fixed process slot array (`0..MAX_PROCS`).
    pub procs: [ProcessEntry; MAX_PROCS],
    next_pid: u32,
    rr_cursor: usize,
    /// Lifetime count of spawned ELF64 processes.
    pub total_spawned: u64,
    /// Lifetime count of cleanly exited ELF64 processes.
    pub total_exited: u64,
    /// Lifetime count of isolated `CPL=3` faulting processes reaped without Ring-0 panic.
    pub total_faulted_reaped: u64,
    /// Lifetime count of supervised service auto-respawns with fresh `variant_seed`s.
    pub total_service_respawns: u64,
}

impl ProcessTable {
    /// Construct an empty `.bss`-friendly process table.
    pub const fn new() -> Self {
        let mut procs = [ProcessEntry::empty(0); MAX_PROCS];
        let mut i = 0usize;
        while i < MAX_PROCS {
            procs[i] = ProcessEntry::empty(i);
            i += 1;
        }
        Self {
            procs,
            next_pid: 100,
            rr_cursor: 0,
            total_spawned: 0,
            total_exited: 0,
            total_faulted_reaped: 0,
            total_service_respawns: 0,
        }
    }

    /// Look up process slot index by `pid`.
    pub fn slot_by_pid(&self, pid: u32) -> Option<usize> {
        if pid == 0 {
            return None;
        }
        let mut i = 0usize;
        while i < MAX_PROCS {
            if self.procs[i].state != ProcState::Unused && self.procs[i].pid == pid {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Look up active supervised service process slot (`Ready` or `Running`) for `svc`.
    pub fn active_service_slot(&self, svc: ServiceId) -> Option<usize> {
        let mut i = 0usize;
        while i < MAX_PROCS {
            if self.procs[i].service_id == Some(svc)
                && matches!(self.procs[i].state, ProcState::Ready | ProcState::Running)
            {
                return Some(i);
            }
            i += 1;
        }
        None
    }

    /// Reclaim a finished (`Exited` or `Faulted`) slot so `MAX_PROCS` slots recycle cleanly.
    pub fn free_reaped_slot(&mut self, slot: usize) {
        if slot < MAX_PROCS && matches!(self.procs[slot].state, ProcState::Exited | ProcState::Faulted)
        {
            self.procs[slot].reset_in_place(slot);
        }
    }

    /// Spawn a new isolated Ring-3 ELF64 process from `elf_image`, allocating its KPTI 4-level
    /// page tables, multi-page `W^X` `PT_LOAD` segments, 16 KiB guarded user stack, and 4 KiB IPC page.
    pub fn spawn_elf64<S: PageFrameSource>(
        &mut self,
        elf_image: &[u8],
        cap_mask: u64,
        variant_seed: u64,
        service_id: Option<ServiceId>,
        source: &mut S,
    ) -> Result<(u32, usize), ProcError> {
        // Find an `Unused` slot (or recycle the oldest `Exited`/`Faulted` slot if all 16 are occupied).
        let mut target_slot: Option<usize> = None;
        let mut i = 0usize;
        while i < MAX_PROCS {
            if self.procs[i].state == ProcState::Unused {
                target_slot = Some(i);
                break;
            }
            i += 1;
        }
        if target_slot.is_none() {
            let mut j = 0usize;
            while j < MAX_PROCS {
                if matches!(self.procs[j].state, ProcState::Exited | ProcState::Faulted) {
                    self.procs[j].vm.release_all_frames(source);
                    self.procs[j].reset_in_place(j);
                    target_slot = Some(j);
                    break;
                }
                j += 1;
            }
        }
        let slot = target_slot.ok_or(ProcError::ProcessTableFull)?;

        // Parse ELF64 header and `PT_LOAD` program headers (`Elf64Impl` already rejects `PF_W | PF_X`).
        let hdr = Elf64Impl::parse_header(elf_image).map_err(ProcError::ElfInvalid)?;
        let mut phdrs = [ElfPhdr {
            ptype: 0,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 0,
        }; ELF_MAX_PHDRS];
        let n_loads =
            Elf64Impl::load_phdrs(elf_image, &hdr, &mut phdrs).map_err(ProcError::ElfInvalid)?;
        if n_loads == 0 {
            return Err(ProcError::ElfInvalid(ElfError::BadPhdrs));
        }

        let slot_base_va = ((PROC_PML4_BASE_SLOT + slot) as u64) << 39;

        // Determine canonical rebase offset:
        // - `ET_DYN` (PIE, `vaddr < 0x4_0000`) rebases directly onto `vm.base_va`.
        // - `ET_EXEC` linked at `[0x40_0000 .. 0x44_0000)` or `[vm.base_va .. vm.base_va + 0x4_0000)`
        //   maps relative to its lowest `PT_LOAD` page aligned to `0x40_0000` or `vm.base_va`.
        let load_bias: u64 = if hdr.etype == ELF_ET_DYN {
            0
        } else if hdr.entry >= slot_base_va
            && hdr.entry < slot_base_va + (PROC_MAX_ELF_PAGES as u64) * 4096
        {
            slot_base_va
        } else if hdr.entry >= 0x0040_0000
            && hdr.entry < 0x0040_0000 + (PROC_MAX_ELF_PAGES as u64) * 4096
        {
            0x0040_0000
        } else {
            return Err(ProcError::SegmentOutOfBounds);
        };

        // Initialize the PCB and `ProcAddressSpace` directly in place (`self.procs[slot]`) so
        // 16 KiB guarded kernel stacks never allocate multi-KiB temporaries!
        self.procs[slot].reset_in_place(slot);
        self.procs[slot].vm.brk_va = self.procs[slot].vm.heap_base_va();

        // Allocate core page tables + stack + IPC + KPTI trampoline frames; on any OOM, roll back cleanly.
        let alloc_core = |vm_ref: &mut ProcAddressSpace, src: &mut S| -> Result<(), ProcError> {
            vm_ref.user_pml4_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            vm_ref.pdpt_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            vm_ref.pd_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            vm_ref.pt_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            let mut s = 0usize;
            while s < PROC_STACK_PAGES {
                vm_ref.stack_page_pa[s] =
                    src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
                s += 1;
            }
            vm_ref.ipc_page_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            vm_ref.tramp_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            vm_ref.sup_rw_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            vm_ref.sup_idt_pa = src.alloc_zeroed_frame().ok_or(ProcError::OutOfPhysicalMemory)?;
            Ok(())
        };
        if let Err(e) = alloc_core(&mut self.procs[slot].vm, source) {
            self.procs[slot].vm.release_all_frames(source);
            self.procs[slot].reset_in_place(slot);
            return Err(e);
        }

        // Map and copy every `PT_LOAD` segment enforcing page-level `W^X` (no two segments with
        // conflicting permissions may share a 4 KiB page!).
        let mut p_idx = 0usize;
        while p_idx < n_loads {
            let ph = phdrs[p_idx];
            if ph.memsz == 0 {
                p_idx += 1;
                continue;
            }
            if ph.vaddr < load_bias {
                self.procs[slot].vm.release_all_frames(source);
                self.procs[slot].reset_in_place(slot);
                return Err(ProcError::SegmentOutOfBounds);
            }
            let rel_start = ph.vaddr - load_bias;
            let rel_end = match rel_start.checked_add(ph.memsz) {
                Some(v) if v <= (PROC_MAX_ELF_PAGES as u64) * 4096 => v,
                _ => {
                    self.procs[slot].vm.release_all_frames(source);
                    self.procs[slot].reset_in_place(slot);
                    return Err(ProcError::SegmentOutOfBounds);
                }
            };
            let file_off = ph.offset as usize;
            let file_len = ph.filesz as usize;
            if file_off.checked_add(file_len).map_or(true, |end| end > elf_image.len()) {
                self.procs[slot].vm.release_all_frames(source);
                self.procs[slot].reset_in_place(slot);
                return Err(ProcError::ElfInvalid(ElfError::Truncated));
            }

            let perm = if (ph.flags & 0x1) != 0 {
                UserPagePerm::ReadExec
            } else if (ph.flags & 0x2) != 0 {
                UserPagePerm::ReadWrite
            } else {
                UserPagePerm::ReadOnly
            };

            let first_pt = (rel_start / 4096) as usize;
            let last_pt = ((rel_end + 4095) / 4096) as usize;
            let mut pt_i = first_pt;
            while pt_i < last_pt {
                if self.procs[slot].vm.elf_page_pa[pt_i] == 0 {
                    let Some(pa) = source.alloc_zeroed_frame() else {
                        self.procs[slot].vm.release_all_frames(source);
                        self.procs[slot].reset_in_place(slot);
                        return Err(ProcError::OutOfPhysicalMemory);
                    };
                    self.procs[slot].vm.elf_page_pa[pt_i] = pa;
                    self.procs[slot].vm.elf_page_perm[pt_i] = perm;
                } else if self.procs[slot].vm.elf_page_perm[pt_i] != perm {
                    // Refuse mixing e.g. `RX` and `RW` on the same 4 KiB page (`W^X`).
                    self.procs[slot].vm.release_all_frames(source);
                    self.procs[slot].reset_in_place(slot);
                    return Err(ProcError::ElfInvalid(ElfError::BadPhdrs));
                }
                pt_i += 1;
            }

            // Copy `filesz` initialized bytes into the allocated physical frames (remaining `memsz - filesz`
            // `.bss` bytes are already zeroed by `alloc_zeroed_frame`!).
            let mut copied = 0usize;
            while copied < file_len {
                let cur_rel = (rel_start as usize) + copied;
                let pt_slot = cur_rel / 4096;
                let page_off = cur_rel & 0xFFF;
                let chunk = (4096 - page_off).min(file_len - copied);
                let dst_pa = self.procs[slot].vm.elf_page_pa[pt_slot];
                source.write_frame_bytes(
                    dst_pa,
                    page_off,
                    &elf_image[file_off + copied..file_off + copied + chunk],
                );
                copied += chunk;
            }
            p_idx += 1;
        }

        // Validate that `hdr.entry` lands inside a mapped `ReadExec` page!
        if hdr.entry < load_bias {
            self.procs[slot].vm.release_all_frames(source);
            self.procs[slot].reset_in_place(slot);
            return Err(ProcError::EntryNotExecutable);
        }
        let entry_rel = hdr.entry - load_bias;
        let entry_pt = (entry_rel / 4096) as usize;
        if entry_pt >= PROC_MAX_ELF_PAGES
            || self.procs[slot].vm.elf_page_perm[entry_pt] != UserPagePerm::ReadExec
        {
            self.procs[slot].vm.release_all_frames(source);
            self.procs[slot].reset_in_place(slot);
            return Err(ProcError::EntryNotExecutable);
        }
        let user_entry_va = slot_base_va + entry_rel;

        // Materialize the 4-level KPTI isolated page tables directly into `user_pml4_pa..pt_pa`
        // without allocating `[u64; 512]` arrays on the stack.
        self.procs[slot].vm.write_4level_tables_to_source(source);

        let pid = self.next_pid;
        self.next_pid = self.next_pid.wrapping_add(1).max(100);
        self.total_spawned = self.total_spawned.wrapping_add(1);

        let init_rsp = self.procs[slot].vm.initial_stack_rsp();
        let ipc_va = self.procs[slot].vm.ipc_page_va();
        let entry = &mut self.procs[slot];
        entry.pid = pid;
        entry.state = ProcState::Ready;
        entry.service_id = service_id;
        entry.variant_seed = variant_seed;
        entry.cap_mask = cap_mask;
        entry.trap_frame.rip = user_entry_va;
        entry.trap_frame.rsp = init_rsp;
        entry.trap_frame.rflags = 0x202; // Interrupts enabled (`IF = 1`) for hardware preemption!
        entry.trap_frame.rdi = ipc_va; // Pass IPC mailbox VA in `rdi` (`argc/aux` convention)!
        entry.trap_frame.rsi = variant_seed;

        Ok((pid, slot))
    }

    /// Claim the next `Ready` process eligible for `cpu_id` (`cpu_affinity_mask`) in round-robin
    /// order, transitioning it to `Running`.
    pub fn claim_next_ready(&mut self, cpu_id: u8) -> Option<usize> {
        let cpu_bit = 1u8 << (cpu_id & 7);
        let mut scanned = 0usize;
        while scanned < MAX_PROCS {
            let idx = (self.rr_cursor + scanned) % MAX_PROCS;
            if self.procs[idx].state == ProcState::Ready
                && (self.procs[idx].cpu_affinity_mask & cpu_bit) != 0
            {
                self.procs[idx].state = ProcState::Running;
                self.procs[idx].last_cpu = cpu_id;
                self.procs[idx].cpu_mask_seen |= cpu_bit;
                self.rr_cursor = (idx + 1) % MAX_PROCS;
                return Some(idx);
            }
            scanned += 1;
        }
        None
    }

    /// Record a hardware timer preemption (`0x50`) for `slot`, saving `tf` and returning
    /// the process to `Ready` so other runnable processes get fair CPU quanta.
    pub fn on_timer_preempt(&mut self, slot: usize, tf: UserTrapFrame) {
        if slot < MAX_PROCS && self.procs[slot].state == ProcState::Running {
            self.procs[slot].trap_frame = tf;
            self.procs[slot].trap_frame.rflags = sanitize_user_rflags(tf.rflags);
            self.procs[slot].preemptions = self.procs[slot].preemptions.wrapping_add(1);
            self.procs[slot].state = ProcState::Ready;
        }
    }

    /// Isolate and reap a faulting `CPL=3` process: records `fault`, releases **100%** of its
    /// physical 4 KiB frames via `source`, transitions ONLY this process to `Faulted`, and returns
    /// the number of reclaimed physical frames (plus `Some(svc)` if a supervised service needs morphed respawn).
    pub fn on_user_fault<S: PageFrameSource>(
        &mut self,
        slot: usize,
        fault: ProcFaultInfo,
        source: &mut S,
    ) -> (usize, Option<(ServiceId, u64, u64, u8)>) {
        if slot >= MAX_PROCS || self.procs[slot].state == ProcState::Unused {
            return (0, None);
        }
        let svc_respawn = self.procs[slot].service_id.map(|svc| {
            let next_seed = self.procs[slot]
                .variant_seed
                .wrapping_add(0x9E37_79B9_7F4A_7C15)
                ^ (fault.vector as u64);
            (
                svc,
                self.procs[slot].cap_mask,
                next_seed,
                self.procs[slot].cpu_affinity_mask,
            )
        });
        let freed = self.procs[slot].vm.release_all_frames(source);
        self.procs[slot].last_fault = fault;
        self.procs[slot].state = ProcState::Faulted;
        self.total_faulted_reaped = self.total_faulted_reaped.wrapping_add(1);
        (freed, svc_respawn)
    }

    /// Read validated user memory `[user_va .. user_va + out.len())` across page boundaries.
    pub fn read_user_bytes<S: PageFrameSource>(
        &self,
        slot: usize,
        user_va: u64,
        out: &mut [u8],
        source: &S,
    ) -> Result<(), ProcError> {
        if slot >= MAX_PROCS {
            return Err(ProcError::InvalidPid);
        }
        let vm = &self.procs[slot].vm;
        let mut done = 0usize;
        while done < out.len() {
            let cur_va = user_va
                .checked_add(done as u64)
                .ok_or(ProcError::BadUserPointer)?;
            let (pa, page_off, _writable) =
                vm.translate_user_va(cur_va).ok_or(ProcError::BadUserPointer)?;
            let chunk = (4096 - page_off).min(out.len() - done);
            source.read_frame_bytes(pa, page_off, &mut out[done..done + chunk]);
            done += chunk;
        }
        Ok(())
    }

    /// Write validated writable user memory `[user_va .. user_va + data.len())` across page boundaries.
    pub fn write_user_bytes<S: PageFrameSource>(
        &self,
        slot: usize,
        user_va: u64,
        data: &[u8],
        source: &mut S,
    ) -> Result<(), ProcError> {
        if slot >= MAX_PROCS {
            return Err(ProcError::InvalidPid);
        }
        let vm = &self.procs[slot].vm;
        // Pre-validate every touched page is mapped `PTE_USER | PTE_WRITABLE` before writing!
        let mut chk = 0usize;
        while chk < data.len() {
            let cur_va = user_va
                .checked_add(chk as u64)
                .ok_or(ProcError::BadUserPointer)?;
            let (_pa, page_off, writable) =
                vm.translate_user_va(cur_va).ok_or(ProcError::BadUserPointer)?;
            if !writable {
                return Err(ProcError::BadUserPointer);
            }
            chk += (4096 - page_off).min(data.len() - chk);
        }
        let mut done = 0usize;
        while done < data.len() {
            let cur_va = user_va + (done as u64);
            let (pa, page_off, _) = vm.translate_user_va(cur_va).unwrap();
            let chunk = (4096 - page_off).min(data.len() - done);
            source.write_frame_bytes(pa, page_off, &data[done..done + chunk]);
            done += chunk;
        }
        Ok(())
    }

    /// Dispatch a Ring-3 syscall (`int 0x80` or `SYSCALL` `0F 05`) for `slot` with full capability
    /// checking, `SYS_WRITE`/`SYS_READ` user-pointer validation, `PROC_SYS_BRK` demand paging,
    /// and `PROC_SYS_IPC_SEND`/`RECV` message passing.
    pub fn handle_syscall<S: PageFrameSource>(
        &mut self,
        slot: usize,
        mut tf: UserTrapFrame,
        cpu_id: u8,
        monotonic_ns: u64,
        source: &mut S,
    ) -> SyscallStepOutcome {
        let nr = tf.rax;
        let a0 = tf.rdi;
        let a1 = tf.rsi;
        let a2 = tf.rdx;
        let a3 = tf.r10;
        let a4 = tf.r8;
        let a5 = tf.r9;

        self.procs[slot].syscalls = self.procs[slot].syscalls.wrapping_add(1);
        let pid = self.procs[slot].pid;
        let cap_mask = self.procs[slot].cap_mask;
        let cap_task_slot = (slot % crate::syscall::CAP_TABLE_TASKS) as u64;

        // 1. Standard Cuttle contract syscalls (`0..SYS_MAX`), gated via `CapProof` in `dispatch_syscall`.
        if nr < SYS_MAX {
            let _ = crate::syscall::set_task_cap_mask(cap_task_slot, cap_mask);
            if nr == SYS_EXIT {
                let code = a0 as i32;
                let ipc_pa = self.procs[slot].vm.ipc_page_pa;
                if ipc_pa != 0 {
                    let mut ipc_snap = [0u8; 16];
                    source.read_frame_bytes(ipc_pa, 0x268, &mut ipc_snap);
                    self.procs[slot].last_ipc_fnv = u64::from_le_bytes([
                        ipc_snap[0],
                        ipc_snap[1],
                        ipc_snap[2],
                        ipc_snap[3],
                        ipc_snap[4],
                        ipc_snap[5],
                        ipc_snap[6],
                        ipc_snap[7],
                    ]);
                    self.procs[slot].last_ipc_status =
                        u32::from_le_bytes([ipc_snap[8], ipc_snap[9], ipc_snap[10], ipc_snap[11]]);
                }
                self.procs[slot].vm.release_all_frames(source);
                self.procs[slot].exit_code = code;
                self.procs[slot].state = ProcState::Exited;
                self.total_exited = self.total_exited.wrapping_add(1);
                return SyscallStepOutcome::Exited(code);
            }
            if nr == SYS_GETPID {
                tf.rax = pid as u64;
                self.procs[slot].trap_frame = tf;
                return SyscallStepOutcome::Continue;
            }
            if nr == crate::syscall::SYS_GETTIME_NS {
                tf.rax = monotonic_ns;
                self.procs[slot].trap_frame = tf;
                return SyscallStepOutcome::Continue;
            }
            if nr == SYS_YIELD || nr == SYS_SLEEP_MS {
                tf.rax = 0;
                self.procs[slot].trap_frame = tf;
                self.procs[slot].preemptions = self.procs[slot].preemptions.wrapping_add(1);
                self.procs[slot].state = ProcState::Ready;
                return SyscallStepOutcome::Yielded;
            }
            if nr == SYS_WRITE {
                // Validate capability via `dispatch_syscall` first, then copy validated user slice.
                match dispatch_syscall(cap_task_slot, cap_mask, SYS_WRITE, a0, 0, 0, a3, a4, a5) {
                    Ok(_) => {
                        let fd = a0;
                        let len = (a2 as usize).min(PROC_STDOUT_CAP);
                        if (fd == 1 || fd == 2) && a2 <= 4096 {
                            let mut tmp = [0u8; PROC_STDOUT_CAP];
                            if self.read_user_bytes(slot, a1, &mut tmp[..len], source).is_ok() {
                                let avail = PROC_STDOUT_CAP.saturating_sub(self.procs[slot].stdout_len);
                                let copy_n = len.min(avail);
                                let cur = self.procs[slot].stdout_len;
                                self.procs[slot].stdout_buf[cur..cur + copy_n]
                                    .copy_from_slice(&tmp[..copy_n]);
                                self.procs[slot].stdout_len += copy_n;
                                tf.rax = len as u64;
                            } else {
                                tf.rax = (-14i64) as u64; // -EFAULT
                            }
                        } else {
                            tf.rax = (-(Errno::EINVAL as i64)) as u64;
                        }
                    }
                    Err(e) => {
                        tf.rax = (-(e as i64)) as u64;
                    }
                }
                self.procs[slot].trap_frame = tf;
                return SyscallStepOutcome::Continue;
            }
            if nr == SYS_READ {
                match dispatch_syscall(cap_task_slot, cap_mask, SYS_READ, a0, 0, 0, a3, a4, a5) {
                    Ok(_) => {
                        if a0 == 0 && self.procs[slot].inbox_len > 0 {
                            let msg = self.procs[slot].inbox[0];
                            let take = msg.len.min(a2 as usize);
                            if self.write_user_bytes(slot, a1, &msg.data[..take], source).is_ok() {
                                let rem = self.procs[slot].inbox_len - 1;
                                let mut m = 0usize;
                                while m < rem {
                                    self.procs[slot].inbox[m] = self.procs[slot].inbox[m + 1];
                                    m += 1;
                                }
                                self.procs[slot].inbox[rem] = ProcIpcMsg::empty();
                                self.procs[slot].inbox_len = rem;
                                tf.rax = take as u64;
                            } else {
                                tf.rax = (-14i64) as u64; // -EFAULT
                            }
                        } else {
                            tf.rax = 0;
                        }
                    }
                    Err(e) => {
                        tf.rax = (-(e as i64)) as u64;
                    }
                }
                self.procs[slot].trap_frame = tf;
                return SyscallStepOutcome::Continue;
            }

            match dispatch_syscall(cap_task_slot, cap_mask, nr, a0, a1, a2, a3, a4, a5) {
                Ok(v) => tf.rax = v,
                Err(e) => tf.rax = (-(e as i64)) as u64,
            }
            self.procs[slot].trap_frame = tf;
            return SyscallStepOutcome::Continue;
        }

        // 2. Process-runtime extended syscalls (`64..=67`).
        match nr {
            PROC_SYS_BRK => {
                let heap_base = self.procs[slot].vm.heap_base_va();
                let heap_max = self.procs[slot].vm.heap_max_va();
                if a0 == 0 {
                    tf.rax = self.procs[slot].vm.brk_va;
                } else if a0 < heap_base || a0 > heap_max {
                    tf.rax = (-PROC_ENOMEM) as u64;
                } else {
                    let needed_pages = ((a0 - heap_base + 4095) / 4096) as usize;
                    let cur_pages = self.procs[slot].vm.heap_pages_mapped;
                    let mut oom = false;
                    if needed_pages > cur_pages {
                        let mut p = cur_pages;
                        while p < needed_pages {
                            if let Some(pa) = source.alloc_zeroed_frame() {
                                self.procs[slot].vm.heap_page_pa[p] = pa;
                                let pte = pa | PTE_PRESENT | PTE_WRITABLE | PTE_USER | PTE_NX;
                                source.write_frame_u64_at(
                                    self.procs[slot].vm.pt_pa,
                                    PROC_HEAP_FIRST_PT + p,
                                    pte,
                                );
                                self.procs[slot].vm.heap_pages_mapped = p + 1;
                            } else {
                                oom = true;
                                break;
                            }
                            p += 1;
                        }
                    } else if needed_pages < cur_pages {
                        let mut p = needed_pages;
                        while p < cur_pages {
                            let old_pa = self.procs[slot].vm.heap_page_pa[p];
                            self.procs[slot].vm.heap_page_pa[p] = 0;
                            source.write_frame_u64_at(
                                self.procs[slot].vm.pt_pa,
                                PROC_HEAP_FIRST_PT + p,
                                0,
                            );
                            if old_pa != 0 {
                                source.free_zeroed_frame(old_pa);
                            }
                            p += 1;
                        }
                        self.procs[slot].vm.heap_pages_mapped = needed_pages;
                    }
                    if oom {
                        tf.rax = (-PROC_ENOMEM) as u64;
                    } else {
                        self.procs[slot].vm.brk_va = a0;
                        tf.rax = a0;
                    }
                }
            }
            PROC_SYS_IPC_SEND => {
                if (cap_mask & SVC_CAP_IPC) == 0 {
                    tf.rax = (-(Errno::EPERM as i64)) as u64;
                } else {
                    let dst_pid = a0 as u32;
                    let tag = a1 as u32;
                    let ptr_va = a2;
                    let len = a3 as usize;
                    if len > PROC_IPC_MSG_MAX {
                        tf.rax = (-(Errno::EINVAL as i64)) as u64;
                    } else if let Some(dst_slot) = self.slot_by_pid(dst_pid) {
                        if self.procs[dst_slot].inbox_len >= PROC_IPC_INBOX_CAP {
                            tf.rax = (-11i64) as u64; // -EAGAIN
                        } else {
                            let mut payload = [0u8; PROC_IPC_MSG_MAX];
                            if self.read_user_bytes(slot, ptr_va, &mut payload[..len], source).is_ok() {
                                let q_idx = self.procs[dst_slot].inbox_len;
                                self.procs[dst_slot].inbox[q_idx] = ProcIpcMsg {
                                    sender_pid: pid,
                                    tag,
                                    len,
                                    data: payload,
                                };
                                self.procs[dst_slot].inbox_len += 1;
                                tf.rax = len as u64;
                            } else {
                                tf.rax = (-14i64) as u64; // -EFAULT
                            }
                        }
                    } else {
                        tf.rax = (-(Errno::ENOENT as i64)) as u64;
                    }
                }
            }
            PROC_SYS_IPC_RECV => {
                if (cap_mask & SVC_CAP_IPC) == 0 {
                    tf.rax = (-(Errno::EPERM as i64)) as u64;
                } else if self.procs[slot].inbox_len == 0 {
                    tf.rax = (-11i64) as u64; // -EAGAIN
                } else {
                    let ptr_va = a0;
                    let max_len = a1 as usize;
                    let tag_out_va = a2;
                    let msg = self.procs[slot].inbox[0];
                    let copy_n = msg.len.min(max_len);
                    let body_ok = self
                        .write_user_bytes(slot, ptr_va, &msg.data[..copy_n], source)
                        .is_ok();
                    let tag_meta =
                        ((msg.sender_pid as u64) << 32) | (msg.tag as u64);
                    let tag_ok = if tag_out_va == 0 {
                        true
                    } else {
                        self.write_user_bytes(slot, tag_out_va, &tag_meta.to_le_bytes(), source)
                            .is_ok()
                    };
                    if body_ok && tag_ok {
                        let rem = self.procs[slot].inbox_len - 1;
                        let mut m = 0usize;
                        while m < rem {
                            self.procs[slot].inbox[m] = self.procs[slot].inbox[m + 1];
                            m += 1;
                        }
                        self.procs[slot].inbox[rem] = ProcIpcMsg::empty();
                        self.procs[slot].inbox_len = rem;
                        tf.rax = copy_n as u64;
                    } else {
                        tf.rax = (-14i64) as u64; // -EFAULT
                    }
                }
            }
            PROC_SYS_GETCPU => {
                tf.rax = cpu_id as u64;
            }
            _ => {
                tf.rax = (-(Errno::ENOSYS as i64)) as u64;
            }
        }
        self.procs[slot].trap_frame = tf;
        SyscallStepOutcome::Continue
    }
}

/// Built-in Ring-3 x86-64 ELF64 multi-segment program templates (`ET_DYN` with `.text` `RX`,
/// `.rodata` `RO+NX`, and `.data`/`.bss` `RW+NX`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ElfProgramKind {
    /// CPU-bound checksum + `PROC_SYS_BRK` heap + `SYSCALL`/`int 0x80` worker running `iterations` loops
    /// without yielding (exercises hardware `0x50` timer preemption and multi-core SMP execution!).
    CpuBoundWorker {
        /// Loop iterations executed in Ring-3 before `SYS_EXIT`.
        iterations: u32,
    },
    /// IPC ping-pong sender/receiver exchanging messages with `peer_pid` via `PROC_SYS_IPC_SEND`/`RECV`.
    IpcPeer {
        /// Target peer PID (`0` = wait to receive first, then reply to sender!).
        target_pid: u32,
    },
    /// Real multi-segment Ring-3 service worker (`svc-http`, `svc-sql`, `svc-sh`) validating its
    /// `PT[103]` IPC mailbox request against `.rodata` rules, updating `.bss` counters, and signing FNV-1a.
    ServiceSanitizer(ServiceId),
    /// Deliberate Ring-3 `ud2` (`#UD`, vector `6`) fault test.
    FaultUd2,
    /// Deliberate Ring-3 higher-half kernel address read (`0xFFFF_8000_0000_0000`, `#PF` KPTI test).
    FaultKernelRead,
    /// Deliberate Ring-3 bottom stack guard page touch (`#PF` stack-overflow guard test).
    FaultStackGuard,
    /// Deliberate Ring-3 privileged `cli` (`0xFA`, `#GP` vector `13` test).
    FaultPrivCli,
}

/// Synthesize a valid 64-bit x86-64 multi-segment `ET_DYN` ELF64 image (`<= 2048` file bytes,
/// mapping 3 `PT_LOAD` segments across `vaddr 0x1000`, `0x2000`, and `0x3000` with `.bss` expansion)
/// diversified deterministically by `variant_seed`.
pub fn build_elf64_program(
    kind: ElfProgramKind,
    variant_seed: u64,
    out: &mut [u8; 2048],
) -> usize {
    init_elf64_three_segment_skeleton(variant_seed, out);
    let text = &mut out[0x200..0x500];
    let mut c = emit_seed_nop_sled(variant_seed, text);

    match kind {
        ElfProgramKind::CpuBoundWorker { iterations } => {
            // 1. Query `PROC_SYS_BRK(0)` via hardware `syscall` (`0F 05`), then expand heap by `4096` bytes!
            //    `mov eax, 64; xor edi, edi; syscall` -> `rax = brk_base`
            text[c..c + 9].copy_from_slice(&[
                0xB8, 0x40, 0x00, 0x00, 0x00, // mov eax, 64 (PROC_SYS_BRK)
                0x31, 0xFF,                   // xor edi, edi
                0x0F, 0x05,                   // syscall (LSTAR!)
            ]);
            c += 9;
            // `mov r12, rax; lea rdi, [rax + 0x1000]; mov eax, 64; syscall`
            text[c..c + 17].copy_from_slice(&[
                0x49, 0x89, 0xC4,                               // mov r12, rax
                0x48, 0x8D, 0xB8, 0x00, 0x10, 0x00, 0x00,       // lea rdi, [rax + 0x1000]
                0xB8, 0x40, 0x00, 0x00, 0x00,                   // mov eax, 64
                0x0F, 0x05,                                     // syscall
            ]);
            c += 17;
            // Write `.rodata` magic (`[rip + disp -> 0x2000]`) into newly demand-allocated heap `[r12]`
            // AND into `.bss` second page (`0x4000`, proving `.bss` `memsz > filesz` zero-fill + RW!).
            let disp_ro = (0x1000i32 - ((c + 7) as i32)).to_le_bytes();
            text[c..c + 7].copy_from_slice(&[0x48, 0x8B, 0x1D, disp_ro[0], disp_ro[1], disp_ro[2], disp_ro[3]]); // mov rbx, [rip -> 0x2000]
            c += 7;
            text[c..c + 4].copy_from_slice(&[0x49, 0x89, 0x1C, 0x24]); // mov [r12], rbx
            c += 4;
            let disp_bss = (0x3000i32 - ((c + 7) as i32)).to_le_bytes();
            text[c..c + 7].copy_from_slice(&[0x48, 0x89, 0x1D, disp_bss[0], disp_bss[1], disp_bss[2], disp_bss[3]]); // mov [rip -> 0x4000], rbx
            c += 7;

            // 2. Write `"R3-OK\n"` (`0x2010`, 6 bytes) to `stdout` (`SYS_WRITE`, `fd = 1`) via `syscall`!
            let disp_msg = (0x1010i32 - ((c + 7) as i32)).to_le_bytes();
            text[c..c + 7].copy_from_slice(&[0x48, 0x8D, 0x35, disp_msg[0], disp_msg[1], disp_msg[2], disp_msg[3]]); // lea rsi, [rip -> 0x2010]
            c += 7;
            let wr_nr = (SYS_WRITE as u32).to_le_bytes();
            let ex_nr = (SYS_EXIT as u32).to_le_bytes();
            text[c..c + 17].copy_from_slice(&[
                0xBF, 0x01, 0x00, 0x00, 0x00,                   // mov edi, 1
                0xBA, 0x06, 0x00, 0x00, 0x00,                   // mov edx, 6
                0xB8, wr_nr[0], wr_nr[1], wr_nr[2], wr_nr[3],   // mov eax, SYS_WRITE
                0x0F, 0x05,                                     // syscall
            ]);
            c += 17;

            // 3. Query `PROC_SYS_GETCPU (67)` via `int 0x80` (`r13 = cpu_id`)!
            text[c..c + 10].copy_from_slice(&[
                0xB8, 0x43, 0x00, 0x00, 0x00, // mov eax, 67 (PROC_SYS_GETCPU)
                0xCD, 0x80,                   // int 0x80
                0x49, 0x89, 0xC5,             // mov r13, rax
            ]);
            c += 10;

            // 4. CPU-bound arithmetic loop (`iterations` rounds, preemptible by Local APIC `0x50`!):
            //    `mov ecx, iterations; xor edx, edx`
            //    `loop_top: imul rdx, rdx, 1103545157; add rdx, rcx; dec ecx; jnz loop_top`
            let it_b = iterations.max(1).to_le_bytes();
            text[c..c + 7].copy_from_slice(&[0xB9, it_b[0], it_b[1], it_b[2], it_b[3], 0x31, 0xD2]);
            c += 7;
            let loop_top = c;
            text[c..c + 14].copy_from_slice(&[
                0x48, 0x69, 0xD2, 0x45, 0xC3, 0xC6, 0x41, // imul rdx, rdx, 0x41C6C345
                0x48, 0x01, 0xCA,                         // add rdx, rcx
                0xFF, 0xC9,                               // dec ecx
                0x75, 0xF2,                               // jnz loop_top (-14)
            ]);
            debug_assert_eq!((c + 14) as isize - 14, loop_top as isize);
            c += 14;

            // 5. Combine `rdx` checksum (`low 16 bits`, non-zero) with `[r12]` verification and `SYS_EXIT(code)`!
            text[c..c + 19].copy_from_slice(&[
                0x49, 0x3B, 0x1C, 0x24,       // cmp rbx, [r12]
                0x75, 0x0D,                   // jne fail_exit (+13)
                0x89, 0xD7,                   // mov edi, edx
                0x81, 0xE7, 0xFF, 0x7F, 0x00, 0x00, // and edi, 0x7FFF
                0x83, 0xCF, 0x40,             // or edi, 0x40 (guaranteed positive non-zero exit code!)
                0xEB, 0x05,                   // jmp do_exit (+5)
            ]);
            c += 19;
            // fail_exit: mov edi, 99
            text[c..c + 5].copy_from_slice(&[0xBF, 0x63, 0x00, 0x00, 0x00]);
            c += 5;
            // do_exit: mov eax, SYS_EXIT; int 0x80
            text[c..c + 7].copy_from_slice(&[0xB8, ex_nr[0], ex_nr[1], ex_nr[2], ex_nr[3], 0xCD, 0x80]);
        }
        ElfProgramKind::IpcPeer { target_pid } => {
            let ex_nr = (SYS_EXIT as u32).to_le_bytes();
            let yld_nr = (SYS_YIELD as u32).to_le_bytes();
            if target_pid != 0 {
                // Sender: `PROC_SYS_IPC_SEND(target_pid, tag=0x42, ptr=0x2010 "R3-OK\n", len=6)` -> `SYS_EXIT(rax)`
                let disp_msg = (0x1010i32 - ((c + 7) as i32)).to_le_bytes();
                text[c..c + 7].copy_from_slice(&[0x48, 0x8D, 0x15, disp_msg[0], disp_msg[1], disp_msg[2], disp_msg[3]]); // lea rdx, [rip -> 0x2010]
                c += 7;
                let pid_b = target_pid.to_le_bytes();
                text[c..c + 26].copy_from_slice(&[
                    0xBF, pid_b[0], pid_b[1], pid_b[2], pid_b[3], // mov edi, target_pid
                    0xBE, 0x42, 0x00, 0x00, 0x00,                 // mov esi, 0x42
                    0x41, 0xBA, 0x06, 0x00, 0x00, 0x00,           // mov r10d, 6
                    0xB8, 0x41, 0x00, 0x00, 0x00,                 // mov eax, 65 (PROC_SYS_IPC_SEND)
                    0x0F, 0x05,                                   // syscall
                    0x89, 0xC7,                                   // mov edi, eax
                    0x90,
                ]);
                c += 26;
                text[c..c + 7].copy_from_slice(&[0xB8, ex_nr[0], ex_nr[1], ex_nr[2], ex_nr[3], 0xCD, 0x80]);
            } else {
                // Receiver: spin-yield until `PROC_SYS_IPC_RECV(buf=0x3020, max_len=16, tag_out=0)` >= 0,
                // verify first 4 bytes == `"R3-O"`, and `SYS_EXIT(77)`!
                let poll_top = c;
                let disp_buf = (0x2020i32 - ((c + 7) as i32)).to_le_bytes();
                text[c..c + 7].copy_from_slice(&[0x48, 0x8D, 0x3D, disp_buf[0], disp_buf[1], disp_buf[2], disp_buf[3]]); // lea rdi, [rip -> 0x3020]
                c += 7;
                text[c..c + 19].copy_from_slice(&[
                    0xBE, 0x10, 0x00, 0x00, 0x00, // mov esi, 16
                    0x31, 0xD2,                   // xor edx, edx
                    0xB8, 0x42, 0x00, 0x00, 0x00, // mov eax, 66 (PROC_SYS_IPC_RECV)
                    0x0F, 0x05,                   // syscall
                    0x48, 0x85, 0xC0,             // test rax, rax
                    0x79, 0x09,                   // jns got_msg (+9)
                ]);
                c += 19;
                // Yield (`SYS_YIELD`) and retry!
                let rel_back = (poll_top as isize - (c + 9) as isize) as i8;
                text[c..c + 9].copy_from_slice(&[
                    0xB8, yld_nr[0], yld_nr[1], yld_nr[2], yld_nr[3], // mov eax, SYS_YIELD
                    0x0F, 0x05,                                       // syscall
                    0xEB, rel_back as u8,                             // jmp poll_top
                ]);
                c += 9;
                // got_msg: verify `[0x3020]` starts with `"R3-O"` (`0x4F2D3352`), exit `77` if match else `98`!
                let disp_chk = (0x2020i32 - ((c + 6) as i32)).to_le_bytes();
                text[c..c + 6].copy_from_slice(&[0x8B, 0x05, disp_chk[0], disp_chk[1], disp_chk[2], disp_chk[3]]); // mov eax, [rip -> 0x3020]
                c += 6;
                text[c..c + 18].copy_from_slice(&[
                    0x3D, 0x52, 0x33, 0x2D, 0x4F, // cmp eax, 0x4F2D3352 ("R3-O")
                    0xB8, 0x62, 0x00, 0x00, 0x00, // mov eax, 98
                    0xBF, 0x4D, 0x00, 0x00, 0x00, // mov edi, 77
                    0x0F, 0x45, 0xF8,             // cmovne edi, eax
                ]);
                c += 18;
                text[c..c + 7].copy_from_slice(&[0xB8, ex_nr[0], ex_nr[1], ex_nr[2], ex_nr[3], 0xCD, 0x80]);
            }
        }
        ElfProgramKind::ServiceSanitizer(svc) => {
            let mut raw = [0u8; crate::svc_runtime::SVC_RING3_WORKER_CAP];
            let raw_len =
                crate::svc_runtime::build_ring3_mailbox_worker_code(svc, variant_seed, &mut raw);
            let disp_bss_cnt = (0x2800i32 - ((c + 7) as i32)).to_le_bytes();
            text[c..c + 7].copy_from_slice(&[
                0x48, 0xFF, 0x05, disp_bss_cnt[0], disp_bss_cnt[1], disp_bss_cnt[2], disp_bss_cnt[3],
            ]); // inc qword ptr [rip -> 0x3800]
            c += 7;
            adapt_mailbox_worker_for_elf64(&raw[..raw_len], &mut text[c..]);
        }
        ElfProgramKind::FaultUd2 => {
            text[c..c + 2].copy_from_slice(&[0x0F, 0x0B]); // ud2 -> #UD (vec 6)
        }
        ElfProgramKind::FaultKernelRead => {
            // `mov rax, 0xFFFF800000000000; mov rax, [rax]` -> #PF (vec 14) on KPTI unmapped kernel VA!
            text[c..c + 13].copy_from_slice(&[
                0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0xFF, 0xFF,
                0x48, 0x8B, 0x00,
            ]);
        }
        ElfProgramKind::FaultStackGuard => {
            // Touch bottom stack guard page `rsp - 0x4000` (`PT[97]`, `PTE_P = 0`) -> #PF (vec 14)!
            text[c..c + 8].copy_from_slice(&[
                0x48, 0x8B, 0x84, 0x24, 0x00, 0xC0, 0xFF, 0xFF, // mov rax, [rsp - 0x4000]
            ]);
        }
        ElfProgramKind::FaultPrivCli => {
            text[c] = 0xFA; // cli at CPL=3 -> #GP (vec 13)
        }
    }

    0x680
}

/// Package a polymorphic x86-64 `worker_code` slice synthesized by
/// [`crate::svc_runtime::build_ring3_mailbox_worker_code`] directly into a 3-segment `ET_DYN`
/// ELF64 process image (`.text` `RX`, `.rodata` `RO+NX`, `.data+.bss` `RW+NX`) executing over
/// the process's `PT[103]` IPC mailbox (`rdi = ipc_page_va`) and exiting via `SYSCALL` (`0F 05`).
pub fn build_elf64_from_mailbox_worker(
    worker_code: &[u8],
    variant_seed: u64,
    out: &mut [u8; 2048],
) -> usize {
    init_elf64_three_segment_skeleton(variant_seed, out);
    let text = &mut out[0x200..0x500];
    let mut c = emit_seed_nop_sled(variant_seed, text);
    if worker_code.len() >= 2 && worker_code[0] == 0x0F && worker_code[1] == 0x0B {
        // Preserve intentional `ud2` (`0F 0B`) fault-injection trap immediately after prologue sled.
        text[c..c + 2].copy_from_slice(&[0x0F, 0x0B]);
    } else {
        let disp_bss_cnt = (0x2800i32 - ((c + 7) as i32)).to_le_bytes();
        text[c..c + 7].copy_from_slice(&[
            0x48, 0xFF, 0x05, disp_bss_cnt[0], disp_bss_cnt[1], disp_bss_cnt[2], disp_bss_cnt[3],
        ]); // inc qword ptr [rip -> 0x3800]
        c += 7;
        adapt_mailbox_worker_for_elf64(worker_code, &mut text[c..]);
    }
    0x680
}

fn init_elf64_three_segment_skeleton(variant_seed: u64, out: &mut [u8; 2048]) {
    out.fill(0);
    // File layout (`0x680 = 1,664` bytes):
    //   `0x000 .. 0x040`: 64-byte ELF64 Header (`e_type = ET_DYN`, `e_phnum = 3`, `e_entry = 0x1000`)
    //   `0x040 .. 0x0E8`: 3 x 56-byte `PT_LOAD` Program Headers:
    //      - `PT_LOAD[0]`: `.text`   file `[0x200..0x500)` -> vaddr `0x1000`, `filesz = 0x300`, `memsz = 0x300`, `PF_R | PF_X` (`5`)
    //      - `PT_LOAD[1]`: `.rodata` file `[0x500..0x600)` -> vaddr `0x2000`, `filesz = 0x100`, `memsz = 0x100`, `PF_R` (`4`)
    //      - `PT_LOAD[2]`: `.data`   file `[0x600..0x680)` -> vaddr `0x3000`, `filesz = 0x080`, `memsz = 0x1800` (2 pages `.bss`!), `PF_R | PF_W` (`6`)
    out[0..4].copy_from_slice(&ELF_MAGIC);
    out[4] = ELF_CLASS64;
    out[5] = ELF_DATA_LE;
    out[6] = 1;
    out[16..18].copy_from_slice(&ELF_ET_DYN.to_le_bytes());
    out[18..20].copy_from_slice(&ELF_EM_X86_64.to_le_bytes());
    out[20..24].copy_from_slice(&1u32.to_le_bytes());
    out[24..32].copy_from_slice(&0x1000u64.to_le_bytes());
    out[32..40].copy_from_slice(&(ELF_EHDR_LEN as u64).to_le_bytes());
    out[52..54].copy_from_slice(&(ELF_EHDR_LEN as u16).to_le_bytes());
    out[54..56].copy_from_slice(&(ELF_PHDR_LEN as u16).to_le_bytes());
    out[56..58].copy_from_slice(&3u16.to_le_bytes());

    let write_phdr =
        |buf: &mut [u8], idx: usize, flags: u32, off: u64, va: u64, fsz: u64, msz: u64| {
            let p = &mut buf[ELF_EHDR_LEN + idx * ELF_PHDR_LEN..ELF_EHDR_LEN + (idx + 1) * ELF_PHDR_LEN];
            p[0..4].copy_from_slice(&ELF_PT_LOAD.to_le_bytes());
            p[4..8].copy_from_slice(&flags.to_le_bytes());
            p[8..16].copy_from_slice(&off.to_le_bytes());
            p[16..24].copy_from_slice(&va.to_le_bytes());
            p[24..32].copy_from_slice(&va.to_le_bytes());
            p[32..40].copy_from_slice(&fsz.to_le_bytes());
            p[40..48].copy_from_slice(&msz.to_le_bytes());
            p[48..56].copy_from_slice(&0x1000u64.to_le_bytes());
        };
    write_phdr(out, 0, 5, 0x200, 0x1000, 0x300, 0x300);
    write_phdr(out, 1, 4, 0x500, 0x2000, 0x100, 0x100);
    write_phdr(out, 2, 6, 0x600, 0x3000, 0x080, 0x1800);

    out[0x500..0x508].copy_from_slice(&0x4354_544C_5233_4F4Bu64.to_le_bytes()); // "CTTLR3OK"
    out[0x508..0x510].copy_from_slice(&variant_seed.to_le_bytes());
    out[0x510..0x516].copy_from_slice(b"R3-OK\n");
    out[0x600..0x608].copy_from_slice(&0x1234_5678_9ABC_DEF0u64.to_le_bytes());
}

fn emit_seed_nop_sled(variant_seed: u64, text: &mut [u8]) -> usize {
    let mut c = 0usize;
    let pad_n = (variant_seed as usize) & 3;
    let mut p = 0usize;
    while p < pad_n {
        text[c..c + 4].copy_from_slice(&[0x0F, 0x1F, 0x40, 0x00]);
        c += 4;
        p += 1;
    }
    c
}

/// Adapt `build_ring3_mailbox_worker_code` in-place (preserving 100% of internal relative branch
/// displacements!) so `rsi` loads `PT[103]` (`ipc_page_va` passed in `rdi`) instead of `rsp & -4096`
/// and exits via hardware `SYSCALL` (`0F 05`, `SYS_EXIT = 0`).
fn adapt_mailbox_worker_for_elf64(worker_code: &[u8], out: &mut [u8]) -> usize {
    let len = worker_code.len().min(out.len());
    out[..len].copy_from_slice(&worker_code[..len]);
    const OLD_PROLOGUE: [u8; 10] = [0x48, 0x89, 0xE6, 0x48, 0x81, 0xE6, 0x00, 0xF0, 0xFF, 0xFF];
    const NEW_PROLOGUE: [u8; 10] = [0x48, 0x89, 0xFE, 0x0F, 0x1F, 0x80, 0x00, 0x00, 0x00, 0x00];
    if len >= 10 {
        let max_scan = (len - 10).min(8);
        let mut s = 0usize;
        while s <= max_scan {
            if out[s..s + 10] == OLD_PROLOGUE {
                out[s..s + 10].copy_from_slice(&NEW_PROLOGUE);
                break;
            }
            s += 1;
        }
    }
    const OLD_EPILOGUE: [u8; 7] = [0xBF, 0x52, 0x00, 0x00, 0x00, 0xCD, 0x80];
    if len >= 7 && out[len - 7..len] == OLD_EPILOGUE {
        let ex_nr = (SYS_EXIT as u32).to_le_bytes();
        if SYS_EXIT == 0 {
            // `xor edi, edi` (2B) + `xor eax, eax` (2B) + `syscall` (2B) + `nop` (1B) = 7B
            out[len - 7..len].copy_from_slice(&[0x31, 0xFF, 0x31, 0xC0, 0x0F, 0x05, 0x90]);
        } else {
            out[len - 7..len]
                .copy_from_slice(&[0xB8, ex_nr[0], ex_nr[1], ex_nr[2], ex_nr[3], 0x0F, 0x05]);
        }
    }
    len
}

/// Compute the deterministic Ring-3 `SYS_EXIT` checksum emitted by [`ElfProgramKind::CpuBoundWorker`].
pub const fn expected_cpu_worker_exit_code(iterations: u32) -> i32 {
    let mut rcx = if iterations == 0 { 1u64 } else { iterations as u64 };
    let mut rdx = 0u64;
    while rcx > 0 {
        rdx = rdx.wrapping_mul(0x41C6_C345).wrapping_add(rcx);
        rcx -= 1;
    }
    (((rdx as u32) & 0x7FFF) | 0x40) as i32
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phys_mm::{scrub_frame_bytes, PhysFrameManager, PhysRegionDesc};
    use alloc::collections::BTreeMap;

    const CAP_ALL: u64 = u64::MAX;
    const CAP_NO_IPC: u64 = !SVC_CAP_IPC;

    /// Host-backed `PageFrameSource` wrapping `PhysFrameManager` + 4 KiB frame byte map.
    struct HostFrameArena {
        pmm: PhysFrameManager<64>,
        mem: BTreeMap<u64, [u8; 4096]>,
    }

    impl HostFrameArena {
        fn new(frames: usize) -> Self {
            let mut pmm = PhysFrameManager::empty();
            let base = 0x0020_0000u64;
            pmm.init_from_regions(
                &[PhysRegionDesc {
                    start: base,
                    end: base + (frames as u64) * 4096,
                    usable: true,
                }],
                &[],
            );
            Self {
                pmm,
                mem: BTreeMap::new(),
            }
        }

        fn allocated_count(&self) -> usize {
            self.pmm.stats().allocated_frames
        }
    }

    impl PageFrameSource for HostFrameArena {
        fn alloc_zeroed_frame(&mut self) -> Option<u64> {
            let pa = self.pmm.alloc_frame()?;
            self.mem.insert(pa, [0u8; 4096]);
            Some(pa)
        }

        fn free_zeroed_frame(&mut self, pa: u64) {
            if let Some(buf) = self.mem.get_mut(&pa) {
                scrub_frame_bytes(buf);
            }
            self.mem.remove(&pa);
            self.pmm
                .free_frame(pa)
                .expect("process frame release must never double-free or invalid-free");
        }

        fn read_frame_bytes(&self, pa: u64, offset: usize, out: &mut [u8]) {
            let page = self.mem.get(&pa).expect("read from unallocated frame");
            out.copy_from_slice(&page[offset..offset + out.len()]);
        }

        fn write_frame_bytes(&mut self, pa: u64, offset: usize, data: &[u8]) {
            let page = self.mem.get_mut(&pa).expect("write to unallocated frame");
            page[offset..offset + data.len()].copy_from_slice(data);
        }
    }

    #[test]
    fn multi_segment_elf64_loader_enforces_wx_kpti_guards_and_bss_zero_fill() {
        let mut arena = HostFrameArena::new(256);
        let mut table = ProcessTable::new();
        let mut elf = [0u8; 2048];
        let elf_len = build_elf64_program(
            ElfProgramKind::CpuBoundWorker { iterations: 100 },
            0xCAFE_BABE_1234_5678,
            &mut elf,
        );

        let (pid, slot) = table
            .spawn_elf64(&elf[..elf_len], CAP_ALL, 0xCAFE_BABE_1234_5678, None, &mut arena)
            .expect("valid multi-segment ELF64 must spawn");
        assert!(pid >= 100);
        assert_eq!(slot, 0);

        let vm = &table.procs[slot].vm;
        // 4 PT + 4 stack + 1 IPC + 3 KPTI + 1 (.text) + 1 (.rodata) + 2 (.data+.bss) = 16 frames.
        assert_eq!(vm.owned_frame_count(), 16);
        assert_eq!(arena.allocated_count(), 16);

        // Verify KPTI higher-half PML4[256..512] == 0 and disjoint per-process PML4[64] mapping.
        for idx in 0..512 {
            let pml4e = arena.read_frame_u64_at(vm.user_pml4_pa, idx);
            if idx == PROC_PML4_BASE_SLOT {
                assert_ne!(pml4e & PTE_PRESENT, 0);
                assert_ne!(pml4e & PTE_USER, 0);
            } else {
                assert_eq!(pml4e, 0, "user PML4[{idx}] must be unmapped under KPTI");
            }
        }

        // Verify L1 PT W^X permissions and guard pages.
        let pte_text = arena.read_frame_u64_at(vm.pt_pa, 1); // vaddr 0x1000 (.text)
        assert_eq!(pte_text & (PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX), PTE_PRESENT | PTE_USER);
        let pte_ro = arena.read_frame_u64_at(vm.pt_pa, 2); // vaddr 0x2000 (.rodata)
        assert_eq!(pte_ro & (PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX), PTE_PRESENT | PTE_USER | PTE_NX);
        let pte_data = arena.read_frame_u64_at(vm.pt_pa, 3); // vaddr 0x3000 (.data)
        let pte_bss = arena.read_frame_u64_at(vm.pt_pa, 4); // vaddr 0x4000 (.bss second page)
        assert_eq!(
            pte_data & (PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX),
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX
        );
        assert_eq!(
            pte_bss & (PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX),
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX
        );
        // Guard pages must have PTE_PRESENT == 0.
        for guard_pt in [64usize, PROC_STACK_GUARD_LO_PT, PROC_STACK_GUARD_HI_PT, 511] {
            assert_eq!(arena.read_frame_u64_at(vm.pt_pa, guard_pt), 0);
        }
        // KPTI supervisor pages must have PTE_USER == 0.
        for sup_pt in [PROC_TRAMP_PT, PROC_SUP_RW_PT, PROC_SUP_IDT_PT] {
            let pte = arena.read_frame_u64_at(vm.pt_pa, sup_pt);
            assert_ne!(pte & PTE_PRESENT, 0);
            assert_eq!(pte & PTE_USER, 0, "KPTI supervisor page PT[{sup_pt}] leaked PTE_USER");
        }

        // Verify `.bss` beyond `filesz` is zero-filled while `.data` carries initialized seed.
        let mut init_qword = [0u8; 8];
        table
            .read_user_bytes(slot, vm.base_va + 0x3000, &mut init_qword, &arena)
            .unwrap();
        assert_eq!(u64::from_le_bytes(init_qword), 0x1234_5678_9ABC_DEF0);
        let mut bss_check = [0xFFu8; 64];
        table
            .read_user_bytes(slot, vm.base_va + 0x4000, &mut bss_check, &arena)
            .unwrap();
        assert!(bss_check.iter().all(|&b| b == 0));

        // Reject kernel writes to `.rodata` (`RO+NX`), `.text` (`RX`), guard pages, and KPTI pages.
        assert_eq!(
            table.write_user_bytes(slot, vm.base_va + 0x2000, b"nope", &mut arena),
            Err(ProcError::BadUserPointer)
        );
        assert_eq!(
            table.write_user_bytes(slot, vm.base_va + 0x1000, b"nope", &mut arena),
            Err(ProcError::BadUserPointer)
        );
        assert_eq!(
            table.write_user_bytes(slot, vm.sup_rw_va(), b"nope", &mut arena),
            Err(ProcError::BadUserPointer)
        );
    }

    #[test]
    fn elf64_loader_rejects_empty_malformed_oversized_and_wx_conflicting_inputs_without_leaking_frames() {
        let mut arena = HostFrameArena::new(128);
        let mut table = ProcessTable::new();

        // 1. Empty input.
        assert!(matches!(
            table.spawn_elf64(&[], CAP_ALL, 1, None, &mut arena),
            Err(ProcError::ElfInvalid(_))
        ));
        assert_eq!(arena.allocated_count(), 0);

        // 2. Malformed magic.
        assert!(matches!(
            table.spawn_elf64(&[0xDE, 0xAD, 0xBE, 0xEF], CAP_ALL, 1, None, &mut arena),
            Err(ProcError::ElfInvalid(_))
        ));
        assert_eq!(arena.allocated_count(), 0);

        // 3. Oversized segment (`memsz > 256 KiB` per-process ELF window).
        let mut oversized = [0u8; 2048];
        let n = build_elf64_program(ElfProgramKind::FaultUd2, 0, &mut oversized);
        let big_memsz = ((PROC_MAX_ELF_PAGES as u64) * 4096 + 4096).to_le_bytes();
        let ph2_memsz_off = ELF_EHDR_LEN + 2 * ELF_PHDR_LEN + 40;
        oversized[ph2_memsz_off..ph2_memsz_off + 8].copy_from_slice(&big_memsz);
        assert_eq!(
            table.spawn_elf64(&oversized[..n], CAP_ALL, 1, None, &mut arena),
            Err(ProcError::SegmentOutOfBounds)
        );
        assert_eq!(arena.allocated_count(), 0, "rejected oversized ELF must leak 0 frames");

        // 4. Two segments sharing page `0x1000` with conflicting permissions (`RX` + `RW`).
        let mut wx_conflict = [0u8; 2048];
        let n2 = build_elf64_program(ElfProgramKind::FaultUd2, 0, &mut wx_conflict);
        let ph2_vaddr_off = ELF_EHDR_LEN + 2 * ELF_PHDR_LEN + 16;
        wx_conflict[ph2_vaddr_off..ph2_vaddr_off + 8].copy_from_slice(&0x1800u64.to_le_bytes());
        assert_eq!(
            table.spawn_elf64(&wx_conflict[..n2], CAP_ALL, 1, None, &mut arena),
            Err(ProcError::ElfInvalid(ElfError::BadPhdrs))
        );
        assert_eq!(arena.allocated_count(), 0, "W^X page conflict must leak 0 frames");

        // 5. Entry point targeting `.rodata` (`PF_X == 0`) must be rejected.
        let mut nx_entry = [0u8; 2048];
        let n3 = build_elf64_program(ElfProgramKind::FaultUd2, 0, &mut nx_entry);
        nx_entry[24..32].copy_from_slice(&0x2000u64.to_le_bytes());
        assert_eq!(
            table.spawn_elf64(&nx_entry[..n3], CAP_ALL, 1, None, &mut arena),
            Err(ProcError::EntryNotExecutable)
        );
        assert_eq!(arena.allocated_count(), 0);
    }

    #[test]
    fn brk_heap_ipc_capabilities_preemption_and_fault_reclamation_preserve_frame_accounting() {
        let mut arena = HostFrameArena::new(256);
        let mut table = ProcessTable::new();
        let mut elf = [0u8; 2048];
        let n = build_elf64_program(ElfProgramKind::CpuBoundWorker { iterations: 16 }, 7, &mut elf);

        // Spawn process A (full caps + IPC) and process B (no IPC cap).
        let (pid_a, slot_a) = table
            .spawn_elf64(
                &elf[..n],
                CAP_ALL | SVC_CAP_IPC,
                0x1111,
                Some(ServiceId::Http),
                &mut arena,
            )
            .unwrap();
        let (pid_b, slot_b) = table
            .spawn_elf64(&elf[..n], CAP_NO_IPC, 0x2222, None, &mut arena)
            .unwrap();
        let base_frames = arena.allocated_count();
        assert_eq!(base_frames, 32);

        // 1. Claim A on CPU 0, grow heap via `PROC_SYS_BRK` by 3 pages (`12 KiB`), then shrink to 1 page.
        assert_eq!(table.claim_next_ready(0), Some(slot_a));
        let heap_base = table.procs[slot_a].vm.heap_base_va();
        let mut tf = table.procs[slot_a].trap_frame;
        tf.rax = PROC_SYS_BRK;
        tf.rdi = heap_base + 3 * 4096;
        assert_eq!(
            table.handle_syscall(slot_a, tf, 0, 1_000, &mut arena),
            SyscallStepOutcome::Continue
        );
        assert_eq!(table.procs[slot_a].trap_frame.rax, heap_base + 3 * 4096);
        assert_eq!(arena.allocated_count(), base_frames + 3);

        tf = table.procs[slot_a].trap_frame;
        tf.rax = PROC_SYS_BRK;
        tf.rdi = heap_base + 4096;
        table.handle_syscall(slot_a, tf, 0, 2_000, &mut arena);
        assert_eq!(arena.allocated_count(), base_frames + 1);

        // 2. IPC send from A -> B succeeds; IPC send from B (missing `SVC_CAP_IPC`) fails with `-EPERM`!
        let msg_va = heap_base;
        table
            .write_user_bytes(slot_a, msg_va, b"PING-IPC", &mut arena)
            .unwrap();
        tf = table.procs[slot_a].trap_frame;
        tf.rax = PROC_SYS_IPC_SEND;
        tf.rdi = pid_b as u64;
        tf.rsi = 0x99;
        tf.rdx = msg_va;
        tf.r10 = 8;
        table.handle_syscall(slot_a, tf, 0, 3_000, &mut arena);
        assert_eq!(table.procs[slot_a].trap_frame.rax, 8);
        assert_eq!(table.procs[slot_b].inbox_len, 1);

        assert_eq!(table.claim_next_ready(2), Some(slot_b));
        let mut tf_b = table.procs[slot_b].trap_frame;
        tf_b.rax = PROC_SYS_IPC_SEND;
        tf_b.rdi = pid_a as u64;
        tf_b.rsi = 1;
        tf_b.rdx = table.procs[slot_b].vm.base_va + 0x2000;
        tf_b.r10 = 4;
        table.handle_syscall(slot_b, tf_b, 2, 3_500, &mut arena);
        assert_eq!(
            table.procs[slot_b].trap_frame.rax,
            (-(Errno::EPERM as i64)) as u64,
            "missing SVC_CAP_IPC must be refused with -EPERM"
        );

        // 3. Timer preemption (`0x50`) saves 18-register context and rotates across SMP cores.
        tf.r15 = 0xDEAD_BEEF_CAFE_0001;
        table.on_timer_preempt(slot_a, tf);
        assert_eq!(table.procs[slot_a].state, ProcState::Ready);
        assert_eq!(table.procs[slot_a].preemptions, 1);
        assert_eq!(table.claim_next_ready(3), Some(slot_a));
        assert_eq!(table.procs[slot_a].cpu_mask_seen, (1 << 0) | (1 << 3));
        assert_eq!(table.procs[slot_a].trap_frame.r15, 0xDEAD_BEEF_CAFE_0001);

        // 4. Fault process A (`#PF` vector 14): must free 100% of A's frames (including dynamic heap!)
        //    and return morphed respawn metadata for `ServiceId::Http`.
        let (freed_a, respawn) = table.on_user_fault(
            slot_a,
            ProcFaultInfo {
                vector: 14,
                error_code: 0x4,
                cr2: 0xFFFF_8000_0000_0000,
                rip: table.procs[slot_a].trap_frame.rip,
                cs: 0x23,
            },
            &mut arena,
        );
        assert_eq!(freed_a, 17);
        assert_eq!(arena.allocated_count(), 16, "only process B's 16 frames may remain");
        let (svc, caps, next_seed, aff) =
            respawn.expect("supervised Http service must trigger respawn");
        assert_eq!(svc, ServiceId::Http);
        assert_eq!(caps, CAP_ALL | SVC_CAP_IPC);
        assert_ne!(next_seed, 0x1111);
        assert_eq!(aff, 0xFF);

        // 5. Clean `SYS_EXIT(42)` on process B reclaims remaining 16 frames -> 0 leaked frames!
        tf_b = table.procs[slot_b].trap_frame;
        tf_b.rax = SYS_EXIT;
        tf_b.rdi = 42;
        assert_eq!(
            table.handle_syscall(slot_b, tf_b, 2, 5_000, &mut arena),
            SyscallStepOutcome::Exited(42)
        );
        assert_eq!(arena.allocated_count(), 0);
    }

    #[test]
    fn mailbox_worker_elf64_adapter_cpu_affinity_and_ipc_snapshot_roundtrip() {
        let mut arena = HostFrameArena::new(128);
        let mut table = ProcessTable::new();
        let mut raw_worker = [0u8; crate::svc_runtime::SVC_RING3_WORKER_CAP];
        let raw_len = crate::svc_runtime::build_ring3_mailbox_worker_code(
            ServiceId::Sql,
            0xABCD_EF01_2345_6789,
            &mut raw_worker,
        );
        let mut elf = [0u8; 2048];
        let elf_len = build_elf64_from_mailbox_worker(
            &raw_worker[..raw_len],
            0xABCD_EF01_2345_6789,
            &mut elf,
        );

        let (_pid, slot) = table
            .spawn_elf64(&elf[..elf_len], CAP_ALL, 1, Some(ServiceId::Sql), &mut arena)
            .unwrap();
        table.procs[slot].cpu_affinity_mask = 0x01; // Pin to CPU 0
        assert_eq!(table.claim_next_ready(1), None, "CPU 1 must respect cpu_affinity_mask");
        assert_eq!(table.claim_next_ready(0), Some(slot));

        // Write simulated verdict + FNV-1a at `[ipc_va + 0x268..0x274]` and verify `SYS_EXIT` snapshots both!
        let ipc_va = table.procs[slot].vm.ipc_page_va();
        let expected_fnv = 0x9988_7766_5544_3322u64;
        table
            .write_user_bytes(slot, ipc_va + 0x268, &expected_fnv.to_le_bytes(), &mut arena)
            .unwrap();
        table
            .write_user_bytes(slot, ipc_va + 0x270, &1u32.to_le_bytes(), &mut arena)
            .unwrap();
        let mut tf = table.procs[slot].trap_frame;
        tf.rax = SYS_EXIT;
        tf.rdi = 0;
        assert_eq!(
            table.handle_syscall(slot, tf, 0, 9_000, &mut arena),
            SyscallStepOutcome::Exited(0)
        );
        assert_eq!(table.procs[slot].last_ipc_fnv, expected_fnv);
        assert_eq!(table.procs[slot].last_ipc_status, 1);
        assert_eq!(arena.allocated_count(), 0);
    }
}

#[cfg(test)]
mod rflags_tests {
    use super::{sanitize_user_rflags, USER_RFLAGS_OWNED};

    #[test]
    fn a_resumed_process_keeps_its_status_flags_and_nothing_else() {
        const NT: u64 = 1 << 14;
        const IOPL: u64 = 3 << 12;
        const TF: u64 = 1 << 8;
        const IF: u64 = 1 << 9;
        const AC: u64 = 1 << 18;
        const RF: u64 = 1 << 16;
        const VM: u64 = 1 << 17;
        const ID: u64 = 1 << 21;

        // A fresh frame is unchanged.
        assert_eq!(sanitize_user_rflags(0x202), 0x202);
        // Interrupts cannot be left off, and bit 1 is always set.
        assert_eq!(sanitize_user_rflags(0), 0x202);
        // Every status flag and DF survive.
        assert_eq!(sanitize_user_rflags(USER_RFLAGS_OWNED), USER_RFLAGS_OWNED | 0x202);
        // Nothing a process could use against the kernel or its neighbours does.
        for hostile in [NT, IOPL, TF, AC, RF, VM, ID, u64::MAX] {
            let out = sanitize_user_rflags(hostile | 0x0C5);
            assert_eq!(
                out & (NT | IOPL | TF | AC | RF | VM | ID),
                0,
                "flag bits {hostile:#x} reached ring 3 as {out:#x}"
            );
            assert_eq!(out & IF, IF);
            assert_eq!(out & 0x0C5, 0x0C5);
            assert_eq!(out >> 22, 0);
        }
    }
}
