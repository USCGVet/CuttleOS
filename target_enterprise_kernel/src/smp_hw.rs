//! Hardware Multi-Core SMP (`INIT`/`SIPI` AP bringup via Local APIC MMIO) and
//! Hardware Multi-Stack Kernel Thread Context Switching (`proteus_switch_context`).
//!
//! - Wakes secondary x86-64 hardware cores (`AP 1..=3`) from `Wait-for-SIPI` at
//!   physical page `0x8000` (16-bit Real Mode -> 32-bit Protected Mode -> 64-bit
//!   Long Mode) onto dedicated 16 KiB per-CPU stacks (`AP_STACKS`).
//! - Secondary cores execute `proteus_ap_entry` concurrently in 64-bit Long Mode,
//!   pulling parallel work items from a lock-free atomic ring buffer (`SMP_WORK_RING`).
//! - Implements true hardware `%rsp` context switching (`0x8200`) across 4 dedicated
//!   16 KiB kernel thread stacks (`KTHREAD_STACKS`) for `init`, `kthreadd-net`,
//!   `kthreadd-wal`, and `proteus-sh`/`worker`.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use crate::{
    alloc_pt_frame, dec_u64, mmio_read32, mmio_write32, pa_to_va, read_cr3, serial_write_bytes,
    KERNEL_SHELL, PTE_ADDR_MASK, PTE_P, PTE_PS, PTE_W,
};

/// Maximum number of hardware SMP cores supported (`BSP + 3 APs`).
pub(crate) const MAX_SMP_CPUS: usize = 4;
/// Number of dedicated hardware-context-switched kernel worker threads.
pub(crate) const NUM_KTHREADS: usize = 4;
/// Number of `u64` words per 16 KiB hardware stack (`2048 * 8 = 16384` bytes).
const STACK_WORDS: usize = 2048;
/// Lock-free SMP work ring capacity (power of two).
const WORK_RING_CAP: usize = 64;

/// Local APIC MMIO physical base address.
const LAPIC_PHYS_BASE: u64 = 0xFEE0_0000;
/// Local APIC Spurious Interrupt Vector Register offset.
const LAPIC_SVR: u64 = 0x00F0;
/// Local APIC Error Status Register offset.
const LAPIC_ESR: u64 = 0x0280;
/// Local APIC Interrupt Command Register Low offset.
const LAPIC_ICR_LO: u64 = 0x0300;
/// Local APIC Interrupt Command Register High offset.
const LAPIC_ICR_HI: u64 = 0x0310;

/// Physical and identity-mapped virtual address of the AP startup trampoline page.
const TRAMPOLINE_PAGE_PHYS: u64 = 0x8000;
/// Virtual/physical address of the 27-byte `proteus_switch_context` routine.
const SWITCH_CONTEXT_VA: u64 = 0x8200;

/// 16-byte-aligned 16 KiB hardware stack backed by atomic words (zero `static mut`).
#[repr(C, align(16))]
pub(crate) struct HardwareStack([AtomicU64; STACK_WORDS]);

impl HardwareStack {
    const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self([ZERO; STACK_WORDS])
    }

    #[inline(always)]
    fn base_va(&self) -> u64 {
        self.0.as_ptr() as usize as u64
    }

    #[inline(always)]
    fn top_va(&self) -> u64 {
        self.base_va() + ((STACK_WORDS * 8) as u64)
    }
}

/// Dedicated 16 KiB hardware stacks for secondary CPU cores (`CPU 0..4`).
static AP_STACKS: [HardwareStack; MAX_SMP_CPUS] = [
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
];

/// Dedicated 16 KiB hardware stacks for context-switched kernel threads (`0..4`).
static KTHREAD_STACKS: [HardwareStack; NUM_KTHREADS] = [
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
];

/// Per-AP boot completion flags set by `proteus_ap_entry` once in 64-bit Long Mode.
static AP_BOOT_READY: [AtomicBool; MAX_SMP_CPUS] = [
    AtomicBool::new( true),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// Count of online hardware CPUs (`1` = BSP only, `4` = BSP + 3 APs).
pub(crate) static HW_ONLINE_CPUS: AtomicUsize = AtomicUsize::new(1);

/// Live hardware tick counters incremented directly by each CPU core (`0..4`).
pub(crate) static HW_CPU_TICKS: [AtomicU64; MAX_SMP_CPUS] = [
    AtomicU64::new(1),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Live parallel job completion counters incremented by each CPU core (`0..4`).
pub(crate) static HW_CPU_JOBS: [AtomicU64; MAX_SMP_CPUS] = [
    AtomicU64::new(1),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Last parallel integrity digest computed by each CPU core (`0..4`).
pub(crate) static HW_CPU_DIGEST: [AtomicU64; MAX_SMP_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];

/// Lock-free MPMC work queue feeding parallel jobs to the secondary AP cores.
static SMP_WORK_RING: [AtomicU64; WORK_RING_CAP] = {
    #[allow(clippy::declare_interior_mutable_const)]
    const ZERO: AtomicU64 = AtomicU64::new(0);
    [ZERO; WORK_RING_CAP]
};
static SMP_WORK_HEAD: AtomicUsize = AtomicUsize::new(0);
static SMP_WORK_TAIL: AtomicUsize = AtomicUsize::new(0);

/// Saved scheduler `%rsp` when switching from the BSP into a worker thread stack.
static BSP_SCHED_RSP: AtomicU64 = AtomicU64::new(0);
/// Saved `%rsp` per hardware-context-switched kernel thread (`0..4`).
static KTHREAD_RSP: [AtomicU64; NUM_KTHREADS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Hardware `%rsp` observed inside each kernel thread during its execution quantum.
pub(crate) static KTHREAD_OBSERVED_RSP: [AtomicU64; NUM_KTHREADS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Per-thread hardware stack context-switch counter (`0..4`).
pub(crate) static HW_THREAD_SWITCHES: [AtomicU64; NUM_KTHREADS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Index (`0..4`) of the currently executing hardware kernel thread.
static CURRENT_KTHREAD_ID: AtomicUsize = AtomicUsize::new(0);
/// Round-robin cursor for hardware thread context switching.
static NEXT_KTHREAD_CURSOR: AtomicUsize = AtomicUsize::new(0);
/// True once `smp_hw_init` has mapped `0x8000` and initialized the thread stacks.
static SMP_HW_INITIALIZED: AtomicBool = AtomicBool::new(false);

/// Push a parallel work seed onto the lock-free SMP work queue for AP execution.
#[inline]
pub(crate) fn push_smp_work(seed: u64) {
    let head = SMP_WORK_HEAD.fetch_add(1, Ordering::AcqRel);
    SMP_WORK_RING[head & (WORK_RING_CAP - 1)].store(seed | 1, Ordering::Release);
}

/// Pop a parallel work seed from the lock-free SMP work queue on an AP core.
#[inline]
fn pop_smp_work() -> Option<u64> {
    let mut tail = SMP_WORK_TAIL.load(Ordering::Acquire);
    loop {
        let head = SMP_WORK_HEAD.load(Ordering::Acquire);
        if tail >= head {
            return None;
        }
        match SMP_WORK_TAIL.compare_exchange_weak(
            tail,
            tail.wrapping_add(1),
            Ordering::AcqRel,
            Ordering::Acquire,
        ) {
            Ok(claimed) => {
                let slot = &SMP_WORK_RING[claimed & (WORK_RING_CAP - 1)];
                let val = slot.swap(0, Ordering::AcqRel);
                if val != 0 {
                    return Some(val);
                }
                return Some((claimed as u64).wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
            }
            Err(actual) => tail = actual,
        }
    }
}

/// Deterministic 64-bit integrity/hash work executed in parallel on AP cores.
#[inline]
fn execute_parallel_work_unit(seed: u64, cpu_id: u64) -> u64 {
    let mut acc = seed ^ cpu_id.wrapping_mul(0x517C_C1B7_2722_0A95);
    let mut round = 0u32;
    while round < 32 {
        acc ^= acc >> 30;
        acc = acc.wrapping_mul(0xBF58_476D_1CE4_E5B9);
        acc ^= acc >> 27;
        acc = acc.wrapping_mul(0x94D0_49BB_1331_11EB);
        acc ^= (round as u64).wrapping_add(cpu_id);
        round += 1;
    }
    acc ^ (acc >> 31)
}

/// Entry point invoked in 64-bit Long Mode by each secondary hardware processor
/// (`AP 1..=3`) after completing the 16-bit -> 32-bit -> 64-bit trampoline at `0x8000`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn proteus_ap_entry(cpu_id: u64) -> ! {
    let idx = (cpu_id as usize) & (MAX_SMP_CPUS - 1);
    AP_BOOT_READY[idx].store(true, Ordering::SeqCst);
    HW_ONLINE_CPUS.fetch_add(1, Ordering::SeqCst);
    HW_CPU_TICKS[idx].store(1, Ordering::Relaxed);
    HW_CPU_JOBS[idx].store(1, Ordering::Relaxed);

    loop {
        let ticks = HW_CPU_TICKS[idx].fetch_add(1, Ordering::Relaxed);
        if let Some(seed) = pop_smp_work() {
            let digest = execute_parallel_work_unit(seed, cpu_id);
            HW_CPU_DIGEST[idx].store(digest, Ordering::Relaxed);
            HW_CPU_JOBS[idx].fetch_add(1, Ordering::Release);
        } else if (ticks & 0x3FFF) == 0 {
            let digest = execute_parallel_work_unit(ticks, cpu_id);
            HW_CPU_DIGEST[idx].store(digest, Ordering::Relaxed);
            HW_CPU_JOBS[idx].fetch_add(1, Ordering::Release);
        }
        core::hint::spin_loop();
    }
}

/// Invoke the 27-byte hardware stack context switcher installed at `pa_to_va(0x8200)`.
///
/// Saves `rbp, rbx, r12, r13, r14, r15` and `%rsp` into `*old_rsp_ptr`, loads
/// `%rsp` from `*new_rsp_ptr`, pops `r15..rbp`, and `ret`s onto the new stack.
#[inline(never)]
// SAFETY: Caller must ensure `pa_to_va(0x8200)` contains the initialized `proteus_switch_context`
// machine code with `PTE_NX` cleared and that `old_rsp_ptr` and `new_rsp_ptr` point to valid
// 8-byte stack-pointer slots whose target stacks follow `[r15, r14, r13, r12, rbx, rbp, rip]`.
unsafe fn invoke_switch_context(old_rsp_ptr: *mut u64, new_rsp_ptr: *const u64) {
    let code_va = pa_to_va(SWITCH_CONTEXT_VA) as usize;
    let fn_ptr: unsafe extern "C" fn(*mut u64, *const u64) =
        // SAFETY: `pa_to_va(0x8200)` is mapped executable by `make_va_executable` and populated
        // with the 27-byte System V AMD64 `proteus_switch_context` routine before any call.
        unsafe { core::mem::transmute(code_va) };
    // SAFETY: Caller guarantees both stack pointer slots and target hardware stacks are valid.
    unsafe { fn_ptr(old_rsp_ptr, new_rsp_ptr) };
}

/// Main loop executed by each hardware-context-switched kernel thread (`0..4`)
/// on its own dedicated 16 KiB stack (`KTHREAD_STACKS[tid]`).
#[no_mangle]
#[inline(never)]
pub extern "C" fn kthread_worker_entry() -> ! {
    loop {
        let tid = CURRENT_KTHREAD_ID.load(Ordering::Acquire) & (NUM_KTHREADS - 1);
        let cur_rsp: u64;
        // SAFETY: Reading `%rsp` in ring 0 has no side effects and observes this thread's active hardware stack pointer.
        unsafe {
            asm!("mov {}, rsp", out(reg) cur_rsp, options(nomem, nostack, preserves_flags));
        }
        KTHREAD_OBSERVED_RSP[tid].store(cur_rsp, Ordering::Release);
        let sw = HW_THREAD_SWITCHES[tid].fetch_add(1, Ordering::AcqRel) + 1;

        // Enqueue a parallel work unit for the secondary AP cores from this thread's context.
        push_smp_work(sw.wrapping_mul(0x9E37_79B9).wrapping_add(tid as u64));

        // Yield hardware `%rsp` back to the scheduler context on the BSP stack.
        // SAFETY: `KTHREAD_RSP[tid]` holds this thread's saved stack slot and `BSP_SCHED_RSP`
        // holds the active BSP scheduler stack frame saved by `kthread_switch_next`.
        unsafe {
            invoke_switch_context(
                KTHREAD_RSP[tid].as_ptr(),
                BSP_SCHED_RSP.as_ptr() as *const u64,
            );
        }
    }
}

/// Clear `PTE_NX` (`bit 63`) along all active page-table levels covering `va`
/// so code placed at `va` (`pa_to_va(0x8200)`) can be executed at CPL=0.
// SAFETY: Caller must pass a mapped canonical kernel virtual address at CPL=0.
unsafe fn make_va_executable(va: u64) {
    let indices = [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ];
    let pte_nx: u64 = 1u64 << 63;
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active 4-level PML4 physical address.
    let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let mut level = 0usize;
    while level < 4 {
        // SAFETY: `table` is a valid page-table physical frame mapped via `pa_to_va` and `indices[level] < 512`.
        let ent_ptr = unsafe { pa_to_va(table).cast::<u64>().add(indices[level]) };
        // SAFETY: `ent_ptr` is an 8-byte-aligned page-table entry in mapped physical RAM.
        let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
        if ent & PTE_P == 0 {
            return;
        }
        if (ent & pte_nx) != 0 || (ent & PTE_W) == 0 {
            // SAFETY: `ent_ptr` is a valid PTE in mapped physical RAM.
            unsafe {
                core::ptr::write_volatile(ent_ptr, (ent & !pte_nx) | PTE_P | PTE_W);
            }
        }
        if ent & PTE_PS != 0 || level == 3 {
            break;
        }
        table = ent & PTE_ADDR_MASK;
        level += 1;
    }
    // SAFETY: `invlpg` is privileged-safe at CPL=0 for any canonical address `va`.
    unsafe {
        asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
}

/// Temporarily identity-map virtual page `0x8000` -> physical page `0x8000`
/// (`PTE_P | PTE_W`, `PTE_NX = 0`) for AP startup, returning `(pte_ptr, orig_pte)`
/// so the caller can restore any prior mapping at `0x8000` once APs are in 64-bit mode.
// SAFETY: Caller must execute at CPL=0 after `set_phys_offset` has initialized `PHYS_MAP_OFFSET` and `DMA_PHYS_BASE`.
unsafe fn map_temp_identity_trampoline(phys_page: u64) -> (*mut u64, u64) {
    let va = phys_page & !0xFFFu64;
    let indices = [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ];
    let pte_nx: u64 = 1u64 << 63;
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active 4-level PML4 physical address.
    let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let mut level = 0usize;
    while level < 3 {
        // SAFETY: `table` is a valid page-table physical frame mapped via `pa_to_va` and `indices[level] < 512`.
        let ent_ptr = unsafe { pa_to_va(table).cast::<u64>().add(indices[level]) };
        // SAFETY: `ent_ptr` is an 8-byte-aligned page-table entry in mapped physical RAM.
        let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
        if ent & PTE_P == 0 {
            // SAFETY: Running at CPL=0 with initialized page-table frame pool.
            let new_t = unsafe { alloc_pt_frame() };
            // SAFETY: `ent_ptr` is a valid PTE slot in mapped physical memory.
            unsafe {
                core::ptr::write_volatile(ent_ptr, new_t | PTE_P | PTE_W);
            }
            table = new_t;
        } else if ent & PTE_PS != 0 {
            // Temporarily replace the huge-page mapping at `va = 0` with an identity-mapped
            // executable huge page (`phys = 0`) and return `(ent_ptr, ent)` for restoration.
            // SAFETY: `ent_ptr` is a valid huge-page PTE in mapped physical memory.
            unsafe {
                core::ptr::write_volatile(ent_ptr, PTE_P | PTE_W | PTE_PS);
                asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
            }
            return (ent_ptr, ent);
        } else {
            if (ent & pte_nx) != 0 {
                // SAFETY: `ent_ptr` is a valid intermediate PTE in mapped physical memory.
                unsafe {
                    core::ptr::write_volatile(ent_ptr, (ent & !pte_nx) | PTE_P | PTE_W);
                }
            }
            table = ent & PTE_ADDR_MASK;
        }
        level += 1;
    }
    // SAFETY: `table` is the L1 page table and `indices[3] < 512`.
    let leaf = unsafe { pa_to_va(table).cast::<u64>().add(indices[3]) };
    // SAFETY: `leaf` is a valid L1 PTE in mapped physical memory.
    let orig_pte = unsafe { core::ptr::read_volatile(leaf) };
    let pte = va | PTE_P | PTE_W;
    // SAFETY: `leaf` is a valid L1 PTE in mapped physical memory and `invlpg` is privileged-safe at CPL=0.
    unsafe {
        core::ptr::write_volatile(leaf, pte);
        asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
    (leaf, orig_pte)
}

/// Read `(cr0, cr3, cr4, efer)` on the Bootstrap Processor so secondary APs
/// configure identical control and MSR registers before entering 64-bit Rust.
// SAFETY: Caller must execute at CPL=0 where reading CR0/CR3/CR4 and IA32_EFER (`0xC000_0080`) is valid.
unsafe fn read_bsp_control_regs() -> (u32, u32, u32, u32) {
    let cr0: u64;
    let cr3: u64;
    let cr4: u64;
    let efer_lo: u32;
    let _efer_hi: u32;
    // SAFETY: Reading CR0, CR3, CR4, and MSR 0xC000_0080 (IA32_EFER) at CPL=0 has no side effects.
    unsafe {
        asm!(
            "mov {cr0}, cr0",
            "mov {cr3}, cr3",
            "mov {cr4}, cr4",
            "mov ecx, 0xC0000080",
            "rdmsr",
            cr0 = out(reg) cr0,
            cr3 = out(reg) cr3,
            cr4 = out(reg) cr4,
            out("ecx") _,
            out("eax") efer_lo,
            out("edx") _efer_hi,
            options(nomem, nostack, preserves_flags)
        );
    }
    (cr0 as u32, cr3 as u32, cr4 as u32, efer_lo)
}

/// Initialize the 4 hardware kernel thread stacks (`KTHREAD_STACKS[0..4]`) and
/// install the 27-byte `proteus_switch_context` routine at `pa_to_va(0x8200)`.
// SAFETY: Caller must execute at CPL=0 after `make_va_executable(pa_to_va(0x8200))` has cleared `PTE_NX`.
unsafe fn init_kthread_stacks() {
    // 27-byte System V AMD64 context switcher at 0x8200:
    //   push rbp; push rbx; push r12; push r13; push r14; push r15
    //   mov [rdi], rsp
    //   mov rsp, [rsi]
    //   pop r15; pop r14; pop r13; pop r12; pop rbx; pop rbp
    //   ret
    const SWITCH_CODE: [u8; 27] = [
        0x55, 0x53, 0x41, 0x54, 0x41, 0x55, 0x41, 0x56, 0x41, 0x57, 0x48, 0x89, 0x27, 0x48, 0x8B,
        0x26, 0x41, 0x5F, 0x41, 0x5E, 0x41, 0x5D, 0x41, 0x5C, 0x5B, 0x5D, 0xC3,
    ];
    let dst = pa_to_va(SWITCH_CONTEXT_VA);
    let mut i = 0usize;
    while i < SWITCH_CODE.len() {
        // SAFETY: `dst` points to `pa_to_va(0x8200)` inside the mapped physical memory window.
        unsafe {
            core::ptr::write_volatile(dst.add(i), SWITCH_CODE[i]);
        }
        i += 1;
    }

    let entry_va = kthread_worker_entry as *const () as usize as u64;
    let mut tid = 0usize;
    while tid < NUM_KTHREADS {
        let base = KTHREAD_STACKS[tid].base_va();
        // Top of stack:
        //   [2047] (`top - 8`):  0 (alignment pad so `%rsp % 16 == 8` at `kthread_worker_entry`)
        //   [2046] (`top - 16`): `kthread_worker_entry` return RIP
        //   [2040..2046] (`top - 64 .. top - 16`): initial `[r15, r14, r13, r12, rbx, rbp]` = 0
        KTHREAD_STACKS[tid].0[STACK_WORDS - 1].store(0, Ordering::SeqCst);
        KTHREAD_STACKS[tid].0[STACK_WORDS - 2].store(entry_va, Ordering::SeqCst);
        let mut reg_slot = STACK_WORDS - 8;
        while reg_slot < STACK_WORDS - 2 {
            KTHREAD_STACKS[tid].0[reg_slot].store(0, Ordering::SeqCst);
            reg_slot += 1;
        }
        let initial_rsp = base + ((STACK_WORDS - 8) * 8) as u64;
        KTHREAD_RSP[tid].store(initial_rsp, Ordering::SeqCst);
        tid += 1;
    }
}

/// Perform one hardware stack context switch from the BSP into the next
/// runnable kernel thread (`0..4`) and back.
pub(crate) fn kthread_switch_next() -> usize {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        return 0;
    }
    let tid = NEXT_KTHREAD_CURSOR.fetch_add(1, Ordering::Relaxed) & (NUM_KTHREADS - 1);
    CURRENT_KTHREAD_ID.store(tid, Ordering::Release);
    // SAFETY: `init_kthread_stacks` populated `pa_to_va(0x8200)` and initialized `KTHREAD_RSP[tid]`
    // with a valid 16 KiB stack frame in `KTHREAD_STACKS[tid]`.
    unsafe {
        invoke_switch_context(
            BSP_SCHED_RSP.as_ptr(),
            KTHREAD_RSP[tid].as_ptr() as *const u64,
        );
    }
    HW_CPU_TICKS[0].fetch_add(1, Ordering::Relaxed);
    HW_CPU_JOBS[0].fetch_add(1, Ordering::Relaxed);
    tid
}

/// Install the x86-64 AP startup trampoline at `0x8000`, wake secondary
/// hardware cores (`AP 1..=3`) via Local APIC `INIT` + `SIPI`, and initialize
/// the 4 hardware kernel thread stacks.
pub(crate) fn smp_hw_init() -> usize {
    if SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        return HW_ONLINE_CPUS.load(Ordering::Acquire);
    }

    // 1. Make `pa_to_va(0x8200)` executable (`PTE_NX = 0`) and initialize kernel thread stacks.
    // SAFETY: Running at CPL=0 after `set_phys_offset` initialized the physical memory map.
    unsafe {
        make_va_executable(pa_to_va(SWITCH_CONTEXT_VA) as u64);
        init_kthread_stacks();
    }

    // 2. Write the 16-bit Real Mode -> 32-bit Protected Mode -> 64-bit Long Mode
    //    trampoline and GDT to `0x8000..0x80B8`.
    const AP_TRAMPOLINE: [u8; 184] = [
        // 0x00: 16-bit Real Mode (CS=0x0800, IP=0x0000 -> linear 0x8000)
        0xFA, // cli
        0xFC, // cld
        0x31, 0xC0, // xor ax, ax
        0x8E, 0xD8, // mov ds, ax
        0x8E, 0xC0, // mov es, ax
        0x8E, 0xD0, // mov ss, ax
        0x2E, 0x0F, 0x01, 0x16, 0x80, 0x00, // lgdt cs:[0x0080]
        0x0F, 0x20, 0xC0, // mov eax, cr0
        0x0C, 0x01, // or al, 1
        0x0F, 0x22, 0xC0, // mov cr0, eax
        0x66, 0xEA, 0x20, 0x80, 0x00, 0x00, 0x08, 0x00, // jmp dword 0x0008:0x00008020
        // 0x20: 32-bit Protected Mode (CS=0x0008, EIP=0x00008020)
        0x66, 0xB8, 0x10, 0x00, // mov ax, 0x0010
        0x8E, 0xD8, // mov ds, ax
        0x8E, 0xC0, // mov es, ax
        0x8E, 0xD0, // mov ss, ax
        0xA1, 0x04, 0x81, 0x00, 0x00, // mov eax, [0x00008104] (BSP CR4)
        0x0F, 0x22, 0xE0, // mov cr4, eax
        0xA1, 0x00, 0x81, 0x00, 0x00, // mov eax, [0x00008100] (BSP CR3)
        0x0F, 0x22, 0xD8, // mov cr3, eax
        0xB9, 0x80, 0x00, 0x00, 0xC0, // mov ecx, 0xC0000080 (IA32_EFER)
        0xA1, 0x28, 0x81, 0x00, 0x00, // mov eax, [0x00008128] (BSP EFER)
        0x31, 0xD2, // xor edx, edx
        0x0F, 0x30, // wrmsr
        0xA1, 0x2C, 0x81, 0x00, 0x00, // mov eax, [0x0000812C] (BSP CR0)
        0x0F, 0x22, 0xC0, // mov cr0, eax
        0xEA, 0x58, 0x80, 0x00, 0x00, 0x18, 0x00, // jmp 0x0018:0x00008058
        0x90, // nop
        // 0x58: 64-bit Long Mode (CS=0x0018, RIP=0x0000000000008058)
        0x66, 0xB8, 0x20, 0x00, // mov ax, 0x0020
        0x8E, 0xD8, // mov ds, ax
        0x8E, 0xC0, // mov es, ax
        0x8E, 0xD0, // mov ss, ax
        0x48, 0x8B, 0x24, 0x25, 0x10, 0x81, 0x00, 0x00, // mov rsp, [0x8110]
        0x48, 0x8B, 0x3C, 0x25, 0x18, 0x81, 0x00, 0x00, // mov rdi, [0x8118]
        0x48, 0x8B, 0x04, 0x25, 0x08, 0x81, 0x00, 0x00, // mov rax, [0x8108]
        0xFF, 0xD0, // call rax
        0xF4, // hlt
        0xEB, 0xFD, // jmp $-3
        0x90, // nop
        // 0x80: GDTR (limit=0x0027, base=0x00008090) + padding to 0x90
        0x27, 0x00, 0x90, 0x80, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        // 0x90: GDT (0x00 null, 0x08 code32, 0x10 data32, 0x18 code64, 0x20 data64)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xCF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9A, 0xAF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x92, 0xCF, 0x00,
    ];

    let tramp_va = pa_to_va(TRAMPOLINE_PAGE_PHYS);
    let mut i = 0usize;
    while i < AP_TRAMPOLINE.len() {
        // SAFETY: `tramp_va` points to physical page `0x8000` mapped via `pa_to_va`.
        unsafe {
            core::ptr::write_volatile(tramp_va.add(i), AP_TRAMPOLINE[i]);
        }
        i += 1;
    }

    // 3. Populate shared BSP control registers and `proteus_ap_entry` address in mailbox `0x8100..0x8130`.
    // SAFETY: Running at CPL=0; `read_bsp_control_regs` reads CR0/CR3/CR4/EFER without side effects.
    let (cr0, cr3, cr4, efer) = unsafe { read_bsp_control_regs() };
    let ap_entry_va = proteus_ap_entry as *const () as usize as u64;
    // SAFETY: Offsets `0x100..0x130` lie within the mapped 4 KiB trampoline page at `0x8000`.
    unsafe {
        core::ptr::write_volatile(tramp_va.add(0x100).cast::<u32>(), cr3);
        core::ptr::write_volatile(tramp_va.add(0x104).cast::<u32>(), cr4);
        core::ptr::write_volatile(tramp_va.add(0x108).cast::<u64>(), ap_entry_va);
        core::ptr::write_volatile(tramp_va.add(0x128).cast::<u32>(), efer);
        core::ptr::write_volatile(tramp_va.add(0x12C).cast::<u32>(), cr0);
    }

    // 4. Temporarily identity-map virtual `0x8000` -> physical `0x8000`, enable the BSP Local APIC,
    //    and wake APs `1..=3` via `INIT` + `SIPI`.
    // SAFETY: Running at CPL=0 with initialized page-table pool.
    let (saved_pte_ptr, orig_pte) = unsafe { map_temp_identity_trampoline(TRAMPOLINE_PAGE_PHYS) };

    // SAFETY: `LAPIC_PHYS_BASE` (`0xFEE0_0000`) is the architectural x86-64 Local APIC MMIO page.
    unsafe {
        let svr = mmio_read32(LAPIC_PHYS_BASE + LAPIC_SVR);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_SVR, svr | 0x1FF);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_ESR, 0);
    }

    let mut cpu_id = 1usize;
    while cpu_id < MAX_SMP_CPUS {
        let stack_top = AP_STACKS[cpu_id].top_va() - 16;
        // SAFETY: Offsets `0x110` and `0x118` are 8-byte-aligned mailbox slots inside `0x8000..0x9000`.
        unsafe {
            core::ptr::write_volatile(tramp_va.add(0x110).cast::<u64>(), stack_top);
            core::ptr::write_volatile(tramp_va.add(0x118).cast::<u64>(), cpu_id as u64);
        }
        core::sync::atomic::fence(Ordering::SeqCst);

        // Send INIT IPI (`0x0000_4500`) to `apic_id = cpu_id`.
        // SAFETY: Writing `ICR_HI` (`0xFEE0_0310`) followed by `ICR_LO` (`0xFEE0_0300`) dispatches an IPI to `cpu_id`.
        unsafe {
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, (cpu_id as u32) << 24);
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4500);
        }
        let mut d = 0u32;
        while d < 10_000 {
            core::hint::spin_loop();
            d += 1;
        }

        // Send SIPI IPI (`0x0000_4608`, vector `0x08` -> physical `0x8000`).
        // SAFETY: Writing `ICR_HI` and `ICR_LO` sends a Startup IPI with vector `0x08` (`0x8000`) to `cpu_id`.
        unsafe {
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, (cpu_id as u32) << 24);
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4608);
        }

        let mut spins = 0u32;
        while !AP_BOOT_READY[cpu_id].load(Ordering::Acquire) && spins < 400_000 {
            if spins == 80_000 {
                // Second SIPI per Intel MP specification if first did not latch yet.
                // SAFETY: Re-sending Startup IPI with vector `0x08` to `cpu_id` before AP ready flag is set.
                unsafe {
                    mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, (cpu_id as u32) << 24);
                    mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4608);
                }
            }
            core::hint::spin_loop();
            spins += 1;
        }

        // If `cpu_id == 1` did not respond within the timeout, the VM was booted
        // with `-smp 1`; skip probing higher APIC IDs to keep single-vCPU boots fast.
        if !AP_BOOT_READY[cpu_id].load(Ordering::Acquire) {
            break;
        }
        cpu_id += 1;
    }

    // 5. Restore the original page-table entry at `0x8000` now that all online APs are executing
    //    `proteus_ap_entry` in higher-half `.text`.
    // SAFETY: `saved_pte_ptr` is the PTE slot modified by `map_temp_identity_trampoline`.
    unsafe {
        core::ptr::write_volatile(saved_pte_ptr, orig_pte);
        asm!("invlpg [{}]", in(reg) TRAMPOLINE_PAGE_PHYS, options(nostack, preserves_flags));
    }

    SMP_HW_INITIALIZED.store(true, Ordering::Release);
    HW_ONLINE_CPUS.load(Ordering::Acquire)
}

/// Synchronize live hardware SMP and multi-stack thread telemetry into `OsShell`,
/// performing one hardware thread stack context switch and feeding the AP work ring.
pub(crate) fn smp_hw_tick_and_sync(sh: &mut target_enterprise::OsShell) {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        let _ = smp_hw_init();
    }
    let _ = kthread_switch_next();

    let online = HW_ONLINE_CPUS.load(Ordering::Relaxed).clamp(1, MAX_SMP_CPUS);
    sh.smp_cpus_online = online as u8;
    let mut c = 0usize;
    while c < MAX_SMP_CPUS {
        let hw_t = HW_CPU_TICKS[c].load(Ordering::Relaxed);
        let hw_j = HW_CPU_JOBS[c].load(Ordering::Relaxed);
        if hw_t > sh.smp_cpu_ticks[c] {
            sh.smp_cpu_ticks[c] = hw_t;
        }
        if hw_j > sh.smp_cpu_jobs[c] {
            sh.smp_cpu_jobs[c] = hw_j;
        } else if sh.smp_cpu_jobs[c] > hw_j {
            let delta = (sh.smp_cpu_jobs[c] - hw_j).min(16);
            let mut k = 0u64;
            while k < delta {
                push_smp_work(hw_j.wrapping_add(k).wrapping_add(1) ^ ((c as u64) << 16));
                k += 1;
            }
        }
        c += 1;
    }
    let mut t = 0usize;
    while t < NUM_KTHREADS {
        let sw = HW_THREAD_SWITCHES[t].load(Ordering::Relaxed);
        let pid = t + 1;
        if pid < sh.kthread_switches.len() && sw > sh.kthread_switches[pid] {
            sh.kthread_switches[pid] = sw;
        }
        t += 1;
    }
}

/// Boot self-proof banner for hardware SMP AP bringup and multi-stack context switching.
///
/// Boots all available secondary hardware cores, switches across all 4 dedicated
/// 16 KiB kernel thread stacks (`KTHREAD_STACKS`), verifies each thread executed
/// with `%rsp` inside its own stack allocation, and emits:
/// `SMP_HW init OK cpus=<N> threads=4 ctx_sw=4`
#[inline(never)]
pub(crate) fn banner_smp_hw() {
    let online = smp_hw_init();

    // Execute one full round of hardware stack context switches across all 4 threads.
    let mut i = 0usize;
    while i < NUM_KTHREADS {
        let tid = kthread_switch_next();
        let obs_rsp = KTHREAD_OBSERVED_RSP[tid].load(Ordering::Acquire);
        let base = KTHREAD_STACKS[tid].base_va();
        let top = KTHREAD_STACKS[tid].top_va();
        if obs_rsp <= base || obs_rsp > top {
            panic!("SMP_HW: thread RSP outside dedicated hardware stack");
        }
        i += 1;
    }

    // Wait briefly for online APs to drain initial work items dispatched by the 4 threads.
    if online > 1 {
        let mut wait = 0u32;
        while wait < 50_000 {
            let mut all_ran = true;
            let mut c = 1usize;
            while c < online {
                if HW_CPU_JOBS[c].load(Ordering::Acquire) < 2 {
                    all_ran = false;
                }
                c += 1;
            }
            if all_ran {
                break;
            }
            core::hint::spin_loop();
            wait += 1;
        }
    }

    let mut total_sw = 0u64;
    let mut t = 0usize;
    while t < NUM_KTHREADS {
        total_sw += HW_THREAD_SWITCHES[t].load(Ordering::Acquire);
        t += 1;
    }

    {
        let mut sh = KERNEL_SHELL.lock();
        smp_hw_tick_and_sync(&mut sh);
    }

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let p0 = b"SMP_HW init OK cpus=";
    line[pos..pos + p0.len()].copy_from_slice(p0);
    pos += p0.len();
    pos += dec_u64(online as u64, &mut line[pos..]);
    let p1 = b" threads=4 ctx_sw=";
    line[pos..pos + p1.len()].copy_from_slice(p1);
    pos += p1.len();
    pos += dec_u64(total_sw, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}
