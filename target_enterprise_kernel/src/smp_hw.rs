//! Hardware Multi-Core SMP (`INIT`/`SIPI` AP bringup via Local APIC MMIO) and
//! Hardware Multi-Stack Kernel Thread Context Switching (`cuttle_switch_context`).
//!
//! - Wakes secondary x86-64 hardware cores (`AP 1..=3`) from `Wait-for-SIPI` at
//!   physical page `0x8000` (16-bit Real Mode -> 32-bit Protected Mode -> 64-bit
//!   Long Mode) onto dedicated 16 KiB per-CPU stacks (`AP_STACKS`).
//! - Secondary cores execute `cuttle_ap_entry` concurrently in 64-bit Long Mode,
//!   pulling parallel work items from a lock-free atomic ring buffer (`SMP_WORK_RING`).
//! - Implements true hardware `%rsp` context switching (`0x8200`) across 4 dedicated
//!   16 KiB kernel thread stacks (`KTHREAD_STACKS`) for `init`, `kthreadd-net`,
//!   `kthreadd-wal`, and `cuttle-sh`/`worker`.

use core::arch::asm;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::{
    alloc_pt_frame, dec_u64, ensure_mmio_page, inb, mmio_read32, mmio_write32, outb, pa_to_va,
    read_cr3, serial_write_bytes, KERNEL_SHELL, PTE_ADDR_MASK, PTE_P, PTE_PS, PTE_W,
};

/// Maximum number of hardware SMP cores supported (`BSP + 3 APs`).
pub(crate) const MAX_SMP_CPUS: usize = 4;
/// Number of dedicated hardware-context-switched kernel worker threads.
pub(crate) const NUM_KTHREADS: usize = 4;
/// Number of `u64` words per 16 KiB hardware stack (`2048 * 8 = 16384` bytes).
const STACK_WORDS: usize = 2048;

/// Local APIC MMIO physical base address.
const LAPIC_PHYS_BASE: u64 = 0xFEE0_0000;
/// Local APIC ID Register offset.
const LAPIC_ID: u64 = 0x0020;
/// Local APIC Task Priority Register offset.
const LAPIC_TPR: u64 = 0x0080;
/// Local APIC End-Of-Interrupt Register offset.
const LAPIC_EOI: u64 = 0x00B0;
/// Local APIC Spurious Interrupt Vector Register offset.
const LAPIC_SVR: u64 = 0x00F0;
/// Local APIC Error Status Register offset.
const LAPIC_ESR: u64 = 0x0280;
/// Local APIC Interrupt Command Register Low offset.
const LAPIC_ICR_LO: u64 = 0x0300;
/// Local APIC Interrupt Command Register High offset.
const LAPIC_ICR_HI: u64 = 0x0310;
/// Local APIC LVT Timer Register offset.
const LAPIC_LVT_TIMER: u64 = 0x0320;
/// Local APIC Timer Initial Count Register offset.
const LAPIC_TIMER_INIT: u64 = 0x0380;
/// Local APIC Timer Current Count Register offset.
const LAPIC_TIMER_CCR: u64 = 0x0390;
/// Local APIC Timer Divide Configuration Register offset.
const LAPIC_TIMER_DIV: u64 = 0x03E0;

/// Interrupt vector for the BSP Local APIC periodic wakeup timer (`0x40`).
const LAPIC_TIMER_VECTOR: u32 = 0x40;
/// Interrupt vector for the SMP Doorbell Wakeup IPI (`0x41`).
const SMP_DOORBELL_VECTOR: u32 = 0x41;

/// Physical and identity-mapped virtual address of the AP startup trampoline page.
const TRAMPOLINE_PAGE_PHYS: u64 = 0x8000;
/// Physical address of the 27-byte `cuttle_switch_context` routine.
const SWITCH_CONTEXT_VA: u64 = 0x8200;
/// Physical address of the 5-entry Runtime 64-bit GDT.
const RUNTIME_GDT_PHYS: u64 = 0x8240;
/// Physical address of the 10-byte Runtime `GDTR` descriptor.
const RUNTIME_GDTR_PHYS: u64 = 0x8280;
/// Physical address of the 10-byte Runtime `IDTR` descriptor.
const RUNTIME_IDTR_PHYS: u64 = 0x8290;
/// Physical address of `ISR_LAPIC_EOI` (28 bytes, handles Local APIC Timer vector `0x40`).
const ISR_LAPIC_EOI_PHYS: u64 = 0x8300;
/// Physical address of `ISR_PIC_EOI` (10 bytes, handles legacy vectors `0x20..0x2F`).
const ISR_PIC_EOI_PHYS: u64 = 0x8320;
/// Physical address of `ISR_SPURIOUS` (2 bytes, `iretq`).
const ISR_SPURIOUS_PHYS: u64 = 0x8340;
/// Physical address of `LOAD_GDT_IDT_CODE` (30 bytes).
const LOAD_GDT_IDT_PHYS: u64 = 0x8350;
/// Physical address of `SLEEP_HLT_CODE` (4 bytes: `sti; hlt; cli; ret`).
const SLEEP_HLT_PHYS: u64 = 0x8370;
/// Physical address storing `&HW_IRQ_WAKEUP_COUNTER` (`.bss` `RW+NX` atomic pointer).
const IRQ_WAKEUPS_PTR_PHYS: u64 = 0x8380;
/// Physical address storing `pa_to_va(LAPIC_PHYS_BASE + LAPIC_EOI) as u64`.
const LAPIC_EOI_PTR_PHYS: u64 = 0x8388;
/// Physical address of `ISR_LAPIC_DOORBELL` (17 bytes, handles Doorbell IPI `0x41` and non-timer LAPIC vectors without touching `0x8380`).
const ISR_LAPIC_DOORBELL_PHYS: u64 = 0x8390;
/// Physical address of `ISR_CPU_FAULT_DIAG` (23 bytes, diagnostic `COM1` + halt for unexpected Ring-0 CPU faults).
const ISR_CPU_FAULT_DIAG_PHYS: u64 = 0x83B0;
/// Physical page holding the 256-entry Runtime 64-bit IDT (`4096` bytes).
const RUNTIME_IDT_PHYS: u64 = 0x9000;

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

/// Per-AP boot completion flags set by `cuttle_ap_entry` once in 64-bit Long Mode.
static AP_BOOT_READY: [AtomicBool; MAX_SMP_CPUS] = [
    AtomicBool::new(true),
    AtomicBool::new(false),
    AtomicBool::new(false),
    AtomicBool::new(false),
];

/// Hardware Local APIC IDs observed on each core (`CPU 0..4`) via `0xFEE0_0020`.
static HW_APIC_IDS: [AtomicU32; MAX_SMP_CPUS] = [
    AtomicU32::new(0),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
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

/// Per-CPU pending job counts (`CPU 0..4`) drained by sleeping AP cores upon Doorbell IPI wakeup.
static CPU_PENDING_JOBS: [AtomicU64; MAX_SMP_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Latest work seed assigned to each CPU (`CPU 0..4`).
static CPU_WORK_SEED: [AtomicU64; MAX_SMP_CPUS] = [
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
    AtomicU64::new(0),
];
/// Round-robin dispatch cursor for assigning parallel work across online APs.
static SMP_WORK_HEAD: AtomicUsize = AtomicUsize::new(0);
/// Total Doorbell IPIs (`vector 0x41`) transmitted via Local APIC `ICR_LO`.
pub(crate) static HW_IPI_DOORBELLS: AtomicU64 = AtomicU64::new(0);
/// Hardware Local APIC Timer (`vector 0x40`) wakeup counter in `.bss` (`RW+NX`, strict `W^X`).
static HW_IRQ_WAKEUP_COUNTER: AtomicU64 = AtomicU64::new(0);
/// Dedicated 4 KiB Supervisor `RX`-only higher-half virtual address mapping physical page `0x8000`.
static SMP_RX_TRAMPOLINE_VA: AtomicU64 = AtomicU64::new(0);

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

/// Translate a physical address inside `0x8000..0x9000` into its dedicated
/// Supervisor Read+Execute (`W^X`, `PTE_W = 0`, `PTE_NX = 0`) higher-half virtual address.
#[inline(always)]
fn smp_rx_va(phys: u64) -> u64 {
    let base = SMP_RX_TRAMPOLINE_VA.load(Ordering::Acquire);
    if base == 0 {
        panic!("SMP_HW: RX trampoline VA not initialized");
    }
    base + (phys - TRAMPOLINE_PAGE_PHYS)
}

/// Poll the Local APIC `ICR_LO` Delivery Status bit (`bit 12`) until Idle (`0`) or bounded timeout.
#[inline]
// SAFETY: Caller must execute at CPL=0 after `ensure_mmio_page(LAPIC_PHYS_BASE)` mapped `0xFEE0_0000`.
unsafe fn wait_lapic_icr_idle() {
    let icr_lo_va = pa_to_va(LAPIC_PHYS_BASE + LAPIC_ICR_LO).cast::<u32>();
    let mut spins = 0u32;
    while (unsafe { core::ptr::read_volatile(icr_lo_va) } & (1 << 12)) != 0 && spins < 50_000 {
        core::hint::spin_loop();
        spins += 1;
    }
}

/// Send a broadcast Doorbell IPI (`vector 0x41`, All-Excluding-Self `0x000C_4041`)
/// via the BSP Local APIC `ICR_LO` (`0xFEE0_0300`) to wake sleeping AP cores from `HLT`.
#[inline]
pub(crate) fn ring_smp_doorbell() {
    let online = HW_ONLINE_CPUS.load(Ordering::Relaxed);
    if online <= 1 {
        return;
    }
    HW_IPI_DOORBELLS.fetch_add(1, Ordering::Relaxed);
    // SAFETY: `LAPIC_PHYS_BASE` (`0xFEE0_0000`) is mapped by `smp_hw_init` and writing `0x000C_4041`
    // to `ICR_LO` (`0xFEE0_0300`) after `wait_lapic_icr_idle` sends a Fixed broadcast-excluding-self IPI.
    unsafe {
        wait_lapic_icr_idle();
        let icr_lo_va = pa_to_va(LAPIC_PHYS_BASE + LAPIC_ICR_LO).cast::<u32>();
        core::ptr::write_volatile(icr_lo_va, 0x000C_4000 | SMP_DOORBELL_VECTOR);
    }
}

/// Read the total hardware Local APIC Timer (`vector 0x40`) wakeup count recorded in `.bss` (`HW_IRQ_WAKEUP_COUNTER`).
#[inline]
pub(crate) fn read_hw_irq_wakeups() -> u64 {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        return 0;
    }
    HW_IRQ_WAKEUP_COUNTER.load(Ordering::Acquire)
}

/// Push a parallel work seed onto a secondary AP core's queue and ring the Doorbell IPI (`0x41`).
#[inline]
pub(crate) fn push_smp_work(seed: u64) {
    let online = HW_ONLINE_CPUS.load(Ordering::Acquire);
    let head = SMP_WORK_HEAD.fetch_add(1, Ordering::AcqRel);
    let target = if online > 1 {
        1 + (head % (online - 1))
    } else {
        0
    };
    CPU_WORK_SEED[target].store(seed | 1, Ordering::Relaxed);
    CPU_PENDING_JOBS[target].fetch_add(1, Ordering::SeqCst);
    if online > 1 && SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        ring_smp_doorbell();
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

/// Invoke the 30-byte `load_runtime_gdt_idt` stub via its Supervisor `RX` alias (`smp_rx_va(0x8350)`).
#[inline(never)]
// SAFETY: Caller must execute at CPL=0 after `init_runtime_idt_and_isrs` has populated `0x8240..0x83C7` and `0x9000`.
unsafe fn invoke_load_runtime_gdt_idt() {
    let code_va = smp_rx_va(LOAD_GDT_IDT_PHYS) as usize;
    let gdtr_va = pa_to_va(RUNTIME_GDTR_PHYS) as u64;
    let idtr_va = pa_to_va(RUNTIME_IDTR_PHYS) as u64;
    let fn_ptr: unsafe extern "C" fn(u64, u64) =
        // SAFETY: `smp_rx_va(0x8350)` is mapped Supervisor Read+Execute (`W^X`) and contains `LOAD_GDT_IDT_CODE`.
        unsafe { core::mem::transmute(code_va) };
    // SAFETY: `gdtr_va` and `idtr_va` point to valid 10-byte descriptors for `RUNTIME_GDT` and `RUNTIME_IDT`.
    unsafe { fn_ptr(gdtr_va, idtr_va) };
}

/// Invoke the 4-byte `sti; hlt; cli; ret` hardware sleep stub via `smp_rx_va(0x8370)`.
///
/// Atomically unmasks interrupts and halts the CPU core (`C1` state, 0% host CPU)
/// until the next hardware interrupt (Local APIC Timer `0x40` on BSP or Doorbell IPI
/// `0x41` on APs) wakes the core.
#[inline(never)]
// SAFETY: Caller must execute at CPL=0 after `invoke_load_runtime_gdt_idt` and Local APIC initialization.
unsafe fn invoke_cpu_sleep_hlt() {
    let code_va = smp_rx_va(SLEEP_HLT_PHYS) as usize;
    let fn_ptr: unsafe extern "C" fn() =
        // SAFETY: `smp_rx_va(0x8370)` is mapped Supervisor Read+Execute (`W^X`) and contains `[0xFB, 0xF4, 0xFA, 0xC3]`.
        unsafe { core::mem::transmute(code_va) };
    // SAFETY: Wakes via `ISR_LAPIC_EOI` / `ISR_LAPIC_DOORBELL` (`iretq`) and returns with interrupts masked (`cli`).
    unsafe { fn_ptr() };
}

/// Entry point invoked in 64-bit Long Mode by each secondary hardware processor
/// (`AP 1..=3`) after completing the 16-bit -> 32-bit -> 64-bit trampoline at `0x8000`.
#[no_mangle]
#[inline(never)]
pub extern "C" fn cuttle_ap_entry(cpu_id: u64) -> ! {
    let idx = (cpu_id as usize) & (MAX_SMP_CPUS - 1);

    // 1. Load the shared higher-half 64-bit Runtime GDT (`CS=0x08, SS=0x10`) and 256-entry Runtime IDT,
    //    record this core's hardware Local APIC ID (`0xFEE0_0020`), and enable its Local APIC (`SVR = 0x1FF`).
    // SAFETY: Running at CPL=0 in 64-bit Long Mode after `init_runtime_idt_and_isrs` mapped `0x8000`, `0x9000`, and `0xFEE0_0000`.
    unsafe {
        invoke_load_runtime_gdt_idt();
        let id_ptr = pa_to_va(LAPIC_PHYS_BASE + LAPIC_ID).cast::<u32>();
        let hw_apic_id = core::ptr::read_volatile(id_ptr) >> 24;
        HW_APIC_IDS[idx].store(hw_apic_id, Ordering::Release);
        let svr_ptr = pa_to_va(LAPIC_PHYS_BASE + LAPIC_SVR).cast::<u32>();
        let tpr_ptr = pa_to_va(LAPIC_PHYS_BASE + LAPIC_TPR).cast::<u32>();
        let esr_ptr = pa_to_va(LAPIC_PHYS_BASE + LAPIC_ESR).cast::<u32>();
        let svr = core::ptr::read_volatile(svr_ptr);
        core::ptr::write_volatile(svr_ptr, svr | 0x1FF);
        core::ptr::write_volatile(tpr_ptr, 0);
        core::ptr::write_volatile(esr_ptr, 0);
    }

    let init_digest = execute_parallel_work_unit(0xA5A5_5A5A ^ cpu_id, cpu_id);
    HW_CPU_DIGEST[idx].store(init_digest, Ordering::Relaxed);
    HW_CPU_TICKS[idx].store(1, Ordering::Relaxed);
    HW_CPU_JOBS[idx].store(1, Ordering::Release);
    HW_ONLINE_CPUS.fetch_add(1, Ordering::SeqCst);
    AP_BOOT_READY[idx].store(true, Ordering::SeqCst);

    loop {
        while CPU_PENDING_JOBS[idx].load(Ordering::SeqCst) > 0 {
            CPU_PENDING_JOBS[idx].fetch_sub(1, Ordering::SeqCst);
            let seed = CPU_WORK_SEED[idx].load(Ordering::Relaxed);
            let ticks = HW_CPU_TICKS[idx].fetch_add(1, Ordering::Relaxed) + 1;
            let digest = execute_parallel_work_unit(seed ^ ticks, cpu_id);
            HW_CPU_DIGEST[idx].store(digest, Ordering::Relaxed);
            HW_CPU_JOBS[idx].fetch_add(1, Ordering::Release);
        }
        // Go silent in hardware HLT (0% host CPU) until woken by Doorbell IPI (vector 0x41).
        // SAFETY: Runtime GDT, Runtime IDT, and Local APIC are active on this AP.
        unsafe {
            invoke_cpu_sleep_hlt();
        }
        HW_CPU_TICKS[idx].fetch_add(1, Ordering::Relaxed);
    }
}

/// Invoke the 27-byte hardware stack context switcher via `smp_rx_va(0x8200)` (`W^X`).
///
/// Saves `rbp, rbx, r12, r13, r14, r15` and `%rsp` into `*old_rsp_ptr`, loads
/// `%rsp` from `*new_rsp_ptr`, pops `r15..rbp`, and `ret`s onto the new stack.
#[inline(never)]
// SAFETY: Caller must ensure `smp_rx_va(0x8200)` is mapped Supervisor `RX` and populated with
// `cuttle_switch_context`, and that `old_rsp_ptr` and `new_rsp_ptr` point to valid 8-byte
// stack-pointer slots whose target stacks follow `[r15, r14, r13, r12, rbx, rbp, rip]`.
unsafe fn invoke_switch_context(old_rsp_ptr: *mut u64, new_rsp_ptr: *const u64) {
    let code_va = smp_rx_va(SWITCH_CONTEXT_VA) as usize;
    let fn_ptr: unsafe extern "C" fn(*mut u64, *const u64) =
        // SAFETY: `smp_rx_va(0x8200)` is mapped Supervisor Read+Execute (`PTE_W = 0`, `PTE_NX = 0`)
        // and populated with the 27-byte System V AMD64 `cuttle_switch_context` routine before any call.
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

/// Map physical page `0x8000` into an unused higher-half PML4 slot (`256..512`) as a
/// dedicated 4 KiB Supervisor Read+Execute (`PTE_P` only: `PTE_W = 0`, `PTE_U = 0`, `PTE_NX = 0`)
/// page so `PHYS_MAP_OFFSET` stays strictly `RW+NX` (zero `RWX` pages anywhere in kernel space).
// SAFETY: Caller must execute at CPL=0 after `set_phys_offset` initialized `PHYS_MAP_OFFSET` and `PT_ALLOC_NEXT`.
unsafe fn map_smp_rx_trampoline_page() -> u64 {
    let existing = SMP_RX_TRAMPOLINE_VA.load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active 4-level kernel PML4 physical address.
    let pml4_phys = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let pml4_ptr = pa_to_va(pml4_phys).cast::<u64>();
    let mut chosen_slot: Option<usize> = None;
    let mut s = 256usize;
    while s < 512 {
        // SAFETY: `s < 512` inside the mapped 4 KiB kernel PML4 frame.
        let ent = unsafe { core::ptr::read_volatile(pml4_ptr.add(s)) };
        if ent & PTE_P == 0 {
            chosen_slot = Some(s);
            break;
        }
        s += 1;
    }
    let slot = match chosen_slot {
        Some(idx) => idx,
        None => panic!("SMP_HW: no free higher-half PML4 slot for RX trampoline"),
    };
    // SAFETY: Running at CPL=0 with initialized page-table frame pool.
    let pdpt_phys = unsafe { alloc_pt_frame() };
    // SAFETY: Running at CPL=0 with initialized page-table frame pool.
    let pd_phys = unsafe { alloc_pt_frame() };
    // SAFETY: Running at CPL=0 with initialized page-table frame pool.
    let pt_phys = unsafe { alloc_pt_frame() };

    let va = 0xFFFF_0000_0000_0000u64 | ((slot as u64) << 39);
    // Strict `W^X`: `PTE_P` only (`PTE_W = 0`, `PTE_U = 0`, `PTE_NX = 0`) at all 4 levels.
    // SAFETY: `pdpt_phys`, `pd_phys`, `pt_phys`, and `pml4_ptr.add(slot)` are valid 8-byte-aligned PTEs in mapped RAM.
    unsafe {
        core::ptr::write_volatile(pa_to_va(pt_phys).cast::<u64>(), TRAMPOLINE_PAGE_PHYS | PTE_P);
        core::ptr::write_volatile(pa_to_va(pd_phys).cast::<u64>(), pt_phys | PTE_P);
        core::ptr::write_volatile(pa_to_va(pdpt_phys).cast::<u64>(), pd_phys | PTE_P);
        core::ptr::write_volatile(pml4_ptr.add(slot), pdpt_phys | PTE_P);
        asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
    }
    SMP_RX_TRAMPOLINE_VA.store(va, Ordering::Release);
    va
}

/// Temporarily identity-map virtual page `0x8000` -> physical page `0x8000`
/// as Supervisor Read+Execute (`PTE_P`, `PTE_W = 0`, `PTE_U = 0`, `PTE_NX = 0`) for AP startup,
/// returning `(pte_ptr, orig_pte)` so the caller restores any prior mapping once APs enter Long Mode.
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
            // Supervisor Read+Execute (`PTE_P | PTE_PS`, `PTE_W = 0`) huge page and return `(ent_ptr, ent)`.
            // SAFETY: `ent_ptr` is a valid huge-page PTE in mapped physical memory.
            unsafe {
                core::ptr::write_volatile(ent_ptr, PTE_P | PTE_PS);
                asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
            }
            return (ent_ptr, ent);
        } else {
            if (ent & pte_nx) != 0 {
                // SAFETY: `ent_ptr` is a valid intermediate PTE in mapped physical memory.
                unsafe {
                    core::ptr::write_volatile(ent_ptr, (ent & !pte_nx) | PTE_P);
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
    // Strict `W^X`: Supervisor Read+Execute (`PTE_P` only, `PTE_W = 0`, `PTE_U = 0`, `PTE_NX = 0`).
    let pte = va | PTE_P;
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

/// Write a 16-byte 64-bit Interrupt Gate (`selector = 0x08`, `IST = 0`, `type_attr = 0x8E`)
/// into `idt_base` at `vec_idx`.
// SAFETY: `idt_base` must point to a mapped 4096-byte IDT page and `vec_idx < 256`.
unsafe fn write_idt_gate(idt_base: *mut u8, vec_idx: usize, handler_va: u64) {
    let off = vec_idx * 16;
    let lo16 = (handler_va & 0xFFFF) as u16;
    let mid16 = ((handler_va >> 16) & 0xFFFF) as u16;
    let hi32 = (handler_va >> 32) as u32;
    let mut entry = [0u8; 16];
    entry[0..2].copy_from_slice(&lo16.to_le_bytes());
    entry[2..4].copy_from_slice(&0x0008u16.to_le_bytes());
    entry[4] = 0;
    entry[5] = 0x8E;
    entry[6..8].copy_from_slice(&mid16.to_le_bytes());
    entry[8..12].copy_from_slice(&hi32.to_le_bytes());
    let mut k = 0usize;
    while k < 16 {
        // SAFETY: `off + k < 4096` inside the mapped IDT frame.
        unsafe {
            core::ptr::write_volatile(idt_base.add(off + k), entry[k]);
        }
        k += 1;
    }
}

/// Initialize the shared 64-bit Runtime GDT (`0x8240`), 256-entry Runtime IDT (`0x9000`),
/// hardware ISR stubs (`0x8300..0x83C7`), legacy 8259 PIC remap/mask, and load `GDTR`/`IDTR` on `CPU 0`.
// SAFETY: Caller must execute at CPL=0 after `map_smp_rx_trampoline_page()` mapped `SMP_RX_TRAMPOLINE_VA`.
unsafe fn init_runtime_idt_and_isrs() {
    // 1. Map the Local APIC MMIO page (`0xFEE0_0000`) into the shared higher-half page tables
    //    so both the BSP and all secondary APs can access `LAPIC_EOI` (`0xFEE0_00B0`) directly.
    // SAFETY: `LAPIC_PHYS_BASE` is the architectural x86-64 Local APIC MMIO frame.
    let lapic_page_va = unsafe { ensure_mmio_page(LAPIC_PHYS_BASE) as u64 };
    let lapic_eoi_va = lapic_page_va + LAPIC_EOI;
    let wakeup_counter_va = HW_IRQ_WAKEUP_COUNTER.as_ptr() as usize as u64;

    // 2. Store `&HW_IRQ_WAKEUP_COUNTER` (`.bss` `RW+NX`) at `0x8380` and `LAPIC_EOI` pointer at `0x8388`.
    // SAFETY: `0x8380` and `0x8388` are 8-byte-aligned slots inside the mapped `0x8000` frame (`PHYS_MAP_OFFSET`, `RW+NX`).
    unsafe {
        HW_IRQ_WAKEUP_COUNTER.store(0, Ordering::Release);
        core::ptr::write_volatile(
            pa_to_va(IRQ_WAKEUPS_PTR_PHYS).cast::<u64>(),
            wakeup_counter_va,
        );
        core::ptr::write_volatile(pa_to_va(LAPIC_EOI_PTR_PHYS).cast::<u64>(), lapic_eoi_va);
    }

    // 3. Install `ISR_LAPIC_EOI` at `0x8300` (handles Local APIC Timer `0x40` under strict `W^X`):
    //      push rax
    //      mov  rax, [rip + 0x78]       -> reads &HW_IRQ_WAKEUP_COUNTER from 0x8380
    //      lock inc qword ptr [rax]     -> increments .bss RW+NX counter (zero writes to RX page!)
    //      mov  rax, [rip + 0x75]       -> reads lapic_eoi_va from 0x8388
    //      mov  dword ptr [rax], 0      -> writes 0 to LAPIC_EOI MMIO
    //      pop  rax
    //      iretq
    const ISR_LAPIC_EOI: [u8; 28] = [
        0x50,
        0x48, 0x8B, 0x05, 0x78, 0x00, 0x00, 0x00,
        0xF0, 0x48, 0xFF, 0x00,
        0x48, 0x8B, 0x05, 0x75, 0x00, 0x00, 0x00,
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x58,
        0x48, 0xCF,
    ];
    // 4. Install `ISR_PIC_EOI` at `0x8320` (handles legacy 8259 PIC vectors `0x20..0x2F`):
    const ISR_PIC_EOI: [u8; 10] = [
        0x50,
        0xB0, 0x20,
        0xE6, 0xA0,
        0xE6, 0x20,
        0x58,
        0x48, 0xCF,
    ];
    // 5. Install `ISR_SPURIOUS` at `0x8340` (`iretq`):
    const ISR_SPURIOUS: [u8; 2] = [0x48, 0xCF];
    // 6. Install `LOAD_GDT_IDT_CODE` at `0x8350`:
    const LOAD_GDT_IDT_CODE: [u8; 30] = [
        0x0F, 0x01, 0x17,                         // lgdt [rdi]
        0x0F, 0x01, 0x1E,                         // lidt [rsi]
        0x6A, 0x08,                               // push 0x08
        0x48, 0x8D, 0x05, 0x03, 0x00, 0x00, 0x00, // lea rax, [rip + 3] -> +0x362
        0x50,                                     // push rax
        0x48, 0xCB,                               // retfq
        0xB8, 0x10, 0x00, 0x00, 0x00,             // mov eax, 0x10
        0x8E, 0xD8,                               // mov ds, ax
        0x8E, 0xC0,                               // mov es, ax
        0x8E, 0xD0,                               // mov ss, ax
        0xC3,                                     // ret
    ];
    // 7. Install `SLEEP_HLT_CODE` at `0x8370` (`sti; hlt; cli; ret`):
    const SLEEP_HLT_CODE: [u8; 4] = [0xFB, 0xF4, 0xFA, 0xC3];
    // 7b. Install `ISR_LAPIC_DOORBELL` at `0x8390` (handles Doorbell IPI `0x41` and non-timer
    //     LAPIC vectors `0x30..0xFE` except `0x40`, writing 0 to `LAPIC_EOI` without touching `0x8380`):
    const ISR_LAPIC_DOORBELL: [u8; 17] = [
        0x50,
        0x48, 0x8B, 0x05, 0xF0, 0xFF, 0xFF, 0xFF,
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x58,
        0x48, 0xCF,
    ];
    // 7c. Install `ISR_CPU_FAULT_DIAG` at `0x83B0` (emits `!EXC\n` on `COM1` `0x3F8` and halts
    //     so unexpected Ring-0 CPU faults never silently `iretq` with an unpopped error code):
    const ISR_CPU_FAULT_DIAG: [u8; 23] = [
        0xFA,                   // cli
        0x66, 0xBA, 0xF8, 0x03, // mov dx, 0x03F8
        0xB0, b'!', 0xEE,       // out dx, '!'
        0xB0, b'E', 0xEE,       // out dx, 'E'
        0xB0, b'X', 0xEE,       // out dx, 'X'
        0xB0, b'C', 0xEE,       // out dx, 'C'
        0xB0, b'\n', 0xEE,      // out dx, '\n'
        0xF4,                   // hlt
        0xEB, 0xFD,             // jmp -3
    ];

    // SAFETY: All destination offsets (`0x8300..0x83C7`) lie within the mapped `0x8000` page (`PHYS_MAP_OFFSET`, `RW+NX`).
    unsafe {
        let mut i = 0usize;
        while i < ISR_LAPIC_EOI.len() {
            core::ptr::write_volatile(pa_to_va(ISR_LAPIC_EOI_PHYS).add(i), ISR_LAPIC_EOI[i]);
            i += 1;
        }
        let mut d = 0usize;
        while d < ISR_LAPIC_DOORBELL.len() {
            core::ptr::write_volatile(
                pa_to_va(ISR_LAPIC_DOORBELL_PHYS).add(d),
                ISR_LAPIC_DOORBELL[d],
            );
            d += 1;
        }
        let mut f = 0usize;
        while f < ISR_CPU_FAULT_DIAG.len() {
            core::ptr::write_volatile(
                pa_to_va(ISR_CPU_FAULT_DIAG_PHYS).add(f),
                ISR_CPU_FAULT_DIAG[f],
            );
            f += 1;
        }
        let mut j = 0usize;
        while j < ISR_PIC_EOI.len() {
            core::ptr::write_volatile(pa_to_va(ISR_PIC_EOI_PHYS).add(j), ISR_PIC_EOI[j]);
            j += 1;
        }
        core::ptr::write_volatile(pa_to_va(ISR_SPURIOUS_PHYS).add(0), ISR_SPURIOUS[0]);
        core::ptr::write_volatile(pa_to_va(ISR_SPURIOUS_PHYS).add(1), ISR_SPURIOUS[1]);
        let mut m = 0usize;
        while m < LOAD_GDT_IDT_CODE.len() {
            core::ptr::write_volatile(pa_to_va(LOAD_GDT_IDT_PHYS).add(m), LOAD_GDT_IDT_CODE[m]);
            m += 1;
        }
        let mut s = 0usize;
        while s < SLEEP_HLT_CODE.len() {
            core::ptr::write_volatile(pa_to_va(SLEEP_HLT_PHYS).add(s), SLEEP_HLT_CODE[s]);
            s += 1;
        }
    }

    // 8. Build the 5-entry 64-bit Runtime GDT at `pa_to_va(0x8240)` (`RW+NX`) and 256-entry Runtime IDT at `pa_to_va(0x9000)` (`RW+NX`),
    //    pointing every IDT gate to the dedicated Supervisor `RX` alias (`smp_rx_va(...)`).
    const RUNTIME_GDT_ENTRIES: [u64; 5] = [
        0x0000_0000_0000_0000, // 0x00: Null
        0x00AF_9B00_0000_FFFF, // 0x08: 64-bit Code (DPL=0, L=1, Accessed=1)
        0x00CF_9300_0000_FFFF, // 0x10: 64-bit Data (DPL=0, W=1, Accessed=1)
        0x00AF_9B00_0000_FFFF, // 0x18: 64-bit Code alias
        0x00CF_9300_0000_FFFF, // 0x20: 64-bit Data alias
    ];
    let gdt_va = pa_to_va(RUNTIME_GDT_PHYS) as u64;
    let idt_va = pa_to_va(RUNTIME_IDT_PHYS) as u64;
    let isr_lapic_va = smp_rx_va(ISR_LAPIC_EOI_PHYS);
    let isr_doorbell_va = smp_rx_va(ISR_LAPIC_DOORBELL_PHYS);
    let isr_pic_va = smp_rx_va(ISR_PIC_EOI_PHYS);
    let isr_spurious_va = smp_rx_va(ISR_SPURIOUS_PHYS);
    let isr_fault_diag_va = smp_rx_va(ISR_CPU_FAULT_DIAG_PHYS);

    // SAFETY: `RUNTIME_GDT_PHYS` (`0x8240`) and `RUNTIME_IDT_PHYS` (`0x9000`) are mapped physical RAM frames.
    unsafe {
        let gdt_ptr = pa_to_va(RUNTIME_GDT_PHYS).cast::<u64>();
        let mut g = 0usize;
        while g < RUNTIME_GDT_ENTRIES.len() {
            core::ptr::write_volatile(gdt_ptr.add(g), RUNTIME_GDT_ENTRIES[g]);
            g += 1;
        }

        let idt_ptr = pa_to_va(RUNTIME_IDT_PHYS);
        let mut v = 0usize;
        while v < 256 {
            let handler = if v < 0x20 {
                if v == 2 || v == 3 {
                    isr_spurious_va
                } else {
                    isr_fault_diag_va
                }
            } else if v == 0xFF {
                isr_spurious_va
            } else if v < 0x30 {
                isr_pic_va
            } else if v == (LAPIC_TIMER_VECTOR as usize) {
                isr_lapic_va
            } else {
                isr_doorbell_va
            };
            write_idt_gate(idt_ptr, v, handler);
            v += 1;
        }

        // Write 10-byte `GDTR` (`0x8280`) and `IDTR` (`0x8290`).
        let gdtr_ptr = pa_to_va(RUNTIME_GDTR_PHYS);
        let gdt_lim = 39u16.to_le_bytes();
        let gdt_base = gdt_va.to_le_bytes();
        core::ptr::write_volatile(gdtr_ptr.add(0), gdt_lim[0]);
        core::ptr::write_volatile(gdtr_ptr.add(1), gdt_lim[1]);
        let mut b = 0usize;
        while b < 8 {
            core::ptr::write_volatile(gdtr_ptr.add(2 + b), gdt_base[b]);
            b += 1;
        }

        let idtr_ptr = pa_to_va(RUNTIME_IDTR_PHYS);
        let idt_lim = 4095u16.to_le_bytes();
        let idt_base = idt_va.to_le_bytes();
        core::ptr::write_volatile(idtr_ptr.add(0), idt_lim[0]);
        core::ptr::write_volatile(idtr_ptr.add(1), idt_lim[1]);
        let mut b2 = 0usize;
        while b2 < 8 {
            core::ptr::write_volatile(idtr_ptr.add(2 + b2), idt_base[b2]);
            b2 += 1;
        }

        // Remap legacy 8259 PIC (`0x20`/`0xA0`) to vectors `0x20..0x2F` and mask all lines (`0xFF`)
        // so legacy ISA IRQ0 never collides with CPU exception vector `0x08` (`#DF`) during `sti; hlt`.
        outb(0x20, 0x11);
        outb(0xA0, 0x11);
        outb(0x21, 0x20);
        outb(0xA1, 0x28);
        outb(0x21, 0x04);
        outb(0xA1, 0x02);
        outb(0x21, 0x01);
        outb(0xA1, 0x01);
        outb(0x21, 0xFF);
        outb(0xA1, 0xFF);

        // Load `RUNTIME_GDTR` (`CS=0x08, SS=0x10`) and `RUNTIME_IDTR` on the BSP.
        invoke_load_runtime_gdt_idt();
    }
}

/// Initialize the 4 hardware kernel thread stacks (`KTHREAD_STACKS[0..4]`) and
/// install the 27-byte `cuttle_switch_context` routine at `pa_to_va(0x8200)` (`executed via smp_rx_va(0x8200)`).
// SAFETY: Caller must execute at CPL=0 after `set_phys_offset` mapped `PHYS_MAP_OFFSET`.
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
        // SAFETY: `dst` points to `pa_to_va(0x8200)` inside the mapped physical memory window (`RW+NX`).
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

/// Calibrated number of Local APIC timer interrupts (`vector 0x40`) corresponding to 1 second (`1 Hz` cooldown tick),
/// measured against the 8254 PIT (`1,193,182 Hz`) during `smp_hw_enable_bsp_timer`.
static CALIBRATED_IRQS_PER_COOLDOWN_TICK: AtomicU64 = AtomicU64::new(250);

/// Return the hardware-calibrated Local APIC timer interrupt frequency (`vector 0x40` IRQs per second).
#[inline]
pub(crate) fn read_calibrated_irqs_per_sec() -> u64 {
    CALIBRATED_IRQS_PER_COOLDOWN_TICK.load(Ordering::Relaxed).max(16)
}

/// Calibrate the BSP (`CPU 0`) Local APIC Timer against the 8254 PIT (`1,193,182 Hz`, Channel 2)
/// over a `10 ms` window (`11,932` PIT ticks) and arm the Periodic Timer on vector `0x40` so
/// `CPU 0` can sleep in hardware `HLT` (`0%` idle host CPU) while login cooldown and cron ticks
/// advance at a hardware-calibrated `1 Hz` rate across hypervisors and bare metal.
pub(crate) fn smp_hw_enable_bsp_timer() {
    use target_enterprise::timer::{
        calibrate_apic_irqs_per_sec, LAPIC_TIMER_PERIOD_COUNT, PIT_CALIBRATION_TICKS_10MS,
    };

    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        let _ = smp_hw_init();
    }
    // SAFETY: `LAPIC_PHYS_BASE` is mapped, `RUNTIME_IDT` has `ISR_LAPIC_EOI` installed at vector `0x40`,
    // and I/O ports `0x61`, `0x43`, `0x42` are the standard IBM-PC 8254 PIT Channel 2 registers at CPL=0.
    unsafe {
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TPR, 0);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TIMER_DIV, 0x03); // Divide by 16

        // 1. Gate PIT Channel 2 (`port 0x61` bit 0 = 1, bit 1 = 0) in Mode 0 (one-shot terminal count, `0xB0`)
        //    for `PIT_CALIBRATION_TICKS_10MS` (`11,932` ticks = ~10 ms).
        let gate = inb(0x61);
        outb(0x61, (gate & 0xFC) | 0x01);
        outb(0x43, 0xB0);
        outb(0x42, (PIT_CALIBRATION_TICKS_10MS & 0xFF) as u8);
        outb(0x42, (PIT_CALIBRATION_TICKS_10MS >> 8) as u8);

        // 2. Start Local APIC timer in masked one-shot mode from `0xFFFF_FFFF` while PIT Channel 2 counts down.
        mmio_write32(
            LAPIC_PHYS_BASE + LAPIC_LVT_TIMER,
            0x0001_0000 | LAPIC_TIMER_VECTOR, // Masked one-shot during calibration
        );
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TIMER_INIT, 0xFFFF_FFFF);

        let mut spins = 0u32;
        while (inb(0x61) & 0x20) == 0 && spins < 200_000 {
            core::hint::spin_loop();
            spins += 1;
        }
        let ccr = mmio_read32(LAPIC_PHYS_BASE + LAPIC_TIMER_CCR);
        let lapic_elapsed = 0xFFFF_FFFFu32.saturating_sub(ccr);
        let irqs_per_sec = calibrate_apic_irqs_per_sec(
            lapic_elapsed,
            PIT_CALIBRATION_TICKS_10MS as u32,
            LAPIC_TIMER_PERIOD_COUNT,
        );
        CALIBRATED_IRQS_PER_COOLDOWN_TICK.store(irqs_per_sec, Ordering::Relaxed);

        // 3. Arm Periodic Local APIC Timer on vector `0x40` with `LAPIC_TIMER_PERIOD_COUNT` (`250,000`).
        mmio_write32(
            LAPIC_PHYS_BASE + LAPIC_LVT_TIMER,
            0x0002_0000 | LAPIC_TIMER_VECTOR, // Periodic mode (bit 17) | vector 0x40
        );
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TIMER_INIT, LAPIC_TIMER_PERIOD_COUNT);
    }
}

/// Put `CPU 0` (the BSP) into hardware `HLT` sleep until the next interrupt
/// (`vector 0x40` Local APIC Timer wakeup).
#[inline]
pub(crate) fn smp_hw_idle_wait() {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        core::hint::spin_loop();
        return;
    }
    // SAFETY: `smp_hw_enable_bsp_timer` armed the periodic Local APIC timer on vector `0x40`.
    unsafe {
        invoke_cpu_sleep_hlt();
    }
    HW_CPU_TICKS[0].fetch_add(1, Ordering::Relaxed);
}

/// Install the x86-64 AP startup trampoline at `0x8000` (mapped `RX` via `SMP_RX_TRAMPOLINE_VA`
/// without clearing `PTE_NX` on `PHYS_MAP_OFFSET`), enforce `WP + NXE + SMEP` across BSP + APs,
/// wake secondary hardware cores (`AP 1..=3`) via Local APIC `INIT` + `SIPI`, and initialize
/// the 4 hardware kernel thread stacks and Runtime IDT/ISRs.
pub(crate) fn smp_hw_init() -> usize {
    if SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        return HW_ONLINE_CPUS.load(Ordering::Acquire);
    }

    // 1. Enable hardware `NXE + WP + SMEP` on the BSP (so APs inherit identical protections via
    //    `read_bsp_control_regs()`), map the dedicated 4 KiB Supervisor `RX` trampoline alias,
    //    initialize Runtime GDT/IDT/ISRs, and initialize the 4 hardware kernel thread stacks.
    // SAFETY: Running at CPL=0 after `set_phys_offset` initialized the physical memory map.
    unsafe {
        crate::banners_arch_platform::enable_cpu_memory_protections();
        let _ = map_smp_rx_trampoline_page();
        init_runtime_idt_and_isrs();
        init_kthread_stacks();
    }

    // 2. Write the 16-bit Real Mode -> 32-bit Protected Mode -> 64-bit Long Mode
    //    trampoline and GDT (with Accessed bits pre-set so `RX` mapping at `0x8000` never faults
    //    under `CR0.WP = 1`) to `0x8000..0x80B8`.
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
        // 0x90: GDT (0x00 null, 0x08 code32, 0x10 data32, 0x18 code64, 0x20 data64; Accessed=1)
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xCF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x9B, 0xAF, 0x00,
        0xFF, 0xFF, 0x00, 0x00, 0x00, 0x93, 0xCF, 0x00,
    ];

    let tramp_va = pa_to_va(TRAMPOLINE_PAGE_PHYS);
    let mut i = 0usize;
    while i < AP_TRAMPOLINE.len() {
        // SAFETY: `tramp_va` points to physical page `0x8000` mapped via `pa_to_va` (`RW+NX`).
        unsafe {
            core::ptr::write_volatile(tramp_va.add(i), AP_TRAMPOLINE[i]);
        }
        i += 1;
    }

    // 3. Populate shared BSP control registers and `cuttle_ap_entry` address in mailbox `0x8100..0x8130`.
    // SAFETY: Running at CPL=0; `read_bsp_control_regs` reads CR0/CR3/CR4/EFER without side effects.
    let (cr0, cr3, cr4, efer) = unsafe { read_bsp_control_regs() };
    let ap_entry_va = cuttle_ap_entry as *const () as usize as u64;
    // SAFETY: Offsets `0x100..0x130` lie within the mapped 4 KiB trampoline page at `0x8000`.
    unsafe {
        core::ptr::write_volatile(tramp_va.add(0x100).cast::<u32>(), cr3);
        core::ptr::write_volatile(tramp_va.add(0x104).cast::<u32>(), cr4);
        core::ptr::write_volatile(tramp_va.add(0x108).cast::<u64>(), ap_entry_va);
        core::ptr::write_volatile(tramp_va.add(0x128).cast::<u32>(), efer);
        core::ptr::write_volatile(tramp_va.add(0x12C).cast::<u32>(), cr0);
    }

    // 4. Temporarily identity-map virtual `0x8000` -> physical `0x8000` (`Supervisor RX`), enable the
    //    BSP Local APIC, and wake APs `1..=3` via `INIT` + `SIPI`.
    // SAFETY: Running at CPL=0 with initialized page-table pool.
    let (saved_pte_ptr, orig_pte) = unsafe { map_temp_identity_trampoline(TRAMPOLINE_PAGE_PHYS) };

    // SAFETY: `LAPIC_PHYS_BASE` (`0xFEE0_0000`) is the architectural x86-64 Local APIC MMIO page.
    unsafe {
        let bsp_apic_id = mmio_read32(LAPIC_PHYS_BASE + LAPIC_ID) >> 24;
        HW_APIC_IDS[0].store(bsp_apic_id, Ordering::Release);
        let svr = mmio_read32(LAPIC_PHYS_BASE + LAPIC_SVR);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_SVR, svr | 0x1FF);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TPR, 0);
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
        // SAFETY: Polling `ICR_LO` idle then writing `ICR_HI` + `ICR_LO` dispatches an IPI to `cpu_id`.
        unsafe {
            wait_lapic_icr_idle();
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, (cpu_id as u32) << 24);
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4500);
            wait_lapic_icr_idle();
        }
        let mut d = 0u32;
        while d < 10_000 {
            core::hint::spin_loop();
            d += 1;
        }

        // Send SIPI IPI (`0x0000_4608`, vector `0x08` -> physical `0x8000`).
        // SAFETY: Polling `ICR_LO` idle then writing `ICR_HI` + `ICR_LO` sends a Startup IPI to `cpu_id`.
        unsafe {
            wait_lapic_icr_idle();
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, (cpu_id as u32) << 24);
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4608);
            wait_lapic_icr_idle();
        }

        let mut spins = 0u32;
        while !AP_BOOT_READY[cpu_id].load(Ordering::Acquire) && spins < 400_000 {
            if spins == 80_000 {
                // Second SIPI per Intel MP specification if first did not latch yet.
                // SAFETY: Re-sending Startup IPI with vector `0x08` to `cpu_id` before AP ready flag is set.
                unsafe {
                    wait_lapic_icr_idle();
                    mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, (cpu_id as u32) << 24);
                    mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4608);
                    wait_lapic_icr_idle();
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
    //    `cuttle_ap_entry` in higher-half `.text`.
    // SAFETY: `saved_pte_ptr` is the PTE slot modified by `map_temp_identity_trampoline`.
    unsafe {
        core::ptr::write_volatile(saved_pte_ptr, orig_pte);
        asm!("invlpg [{}]", in(reg) TRAMPOLINE_PAGE_PHYS, options(nostack, preserves_flags));
    }

    SMP_HW_INITIALIZED.store(true, Ordering::Release);
    HW_ONLINE_CPUS.load(Ordering::Acquire)
}

/// Walk the active 4-level kernel page table for `va` and return `(present, eff_writable, eff_executable)`.
// SAFETY: Caller must execute at CPL=0 with active 4-level paging and initialized `PHYS_MAP_OFFSET`.
unsafe fn walk_va_effective_wx(va: u64) -> (bool, bool, bool) {
    let indices = [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ];
    let pte_nx: u64 = 1u64 << 63;
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active PML4 physical address.
    let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let mut all_writable = true;
    let mut any_nx = false;
    let mut level = 0usize;
    while level < 4 {
        // SAFETY: `table` is a valid page-table frame mapped via `pa_to_va` and `indices[level] < 512`.
        let ent_ptr = unsafe { pa_to_va(table).cast::<u64>().add(indices[level]) };
        // SAFETY: `ent_ptr` is an 8-byte-aligned PTE slot in mapped physical memory.
        let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
        if ent & PTE_P == 0 {
            return (false, false, false);
        }
        if ent & PTE_W == 0 {
            all_writable = false;
        }
        if (ent & pte_nx) != 0 {
            any_nx = true;
        }
        if ent & PTE_PS != 0 || level == 3 {
            return (true, all_writable, !any_nx);
        }
        table = ent & PTE_ADDR_MASK;
        level += 1;
    }
    (false, false, false)
}

/// Synchronize live hardware SMP and multi-stack thread telemetry into `OsShell`,
/// performing one hardware thread stack context switch and waking sleeping AP cores via Doorbell IPI.
pub(crate) fn smp_hw_tick_and_sync(sh: &mut target_enterprise::OsShell) {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        let _ = smp_hw_init();
    }
    let _ = kthread_switch_next();

    let online = HW_ONLINE_CPUS.load(Ordering::Relaxed).clamp(1, MAX_SMP_CPUS);
    sh.smp_cpus_online = online as u8;
    let mut need_doorbell = false;
    let mut c = 0usize;
    while c < MAX_SMP_CPUS {
        let hw_t = HW_CPU_TICKS[c].load(Ordering::Relaxed);
        let hw_j = HW_CPU_JOBS[c].load(Ordering::Relaxed);
        if hw_t > sh.smp_cpu_ticks[c] {
            sh.smp_cpu_ticks[c] = hw_t;
        }
        if hw_j > sh.smp_cpu_jobs[c] {
            sh.smp_cpu_jobs[c] = hw_j;
        } else if sh.smp_cpu_jobs[c] > hw_j && c > 0 && c < online {
            let delta = (sh.smp_cpu_jobs[c] - hw_j).min(16);
            CPU_WORK_SEED[c].store(hw_j.wrapping_add(delta) ^ ((c as u64) << 16), Ordering::Relaxed);
            CPU_PENDING_JOBS[c].fetch_add(delta, Ordering::SeqCst);
            need_doorbell = true;
        }
        c += 1;
    }
    if need_doorbell {
        ring_smp_doorbell();
    }

    let irqs_per_cooldown_tick = CALIBRATED_IRQS_PER_COOLDOWN_TICK.load(Ordering::Relaxed).max(16);
    let hw_irqs = read_hw_irq_wakeups();
    let hw_ipis = HW_IPI_DOORBELLS.load(Ordering::Relaxed);
    if hw_irqs > sh.smp_irq_wakeups {
        let prev_epochs = sh.smp_irq_wakeups / irqs_per_cooldown_tick;
        let cur_epochs = hw_irqs / irqs_per_cooldown_tick;
        sh.smp_irq_wakeups = hw_irqs;
        if cur_epochs > prev_epochs {
            let delta = (cur_epochs - prev_epochs).min(8);
            let mut d = 0u64;
            while d < delta {
                sh.tick_login_cooldown();
                d += 1;
            }
        }
    }
    if hw_ipis > sh.smp_ipi_doorbells {
        sh.smp_ipi_doorbells = hw_ipis;
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
    let _ = sh.tick_cron_jobs(1);
}

/// Boot self-proof banner for hardware SMP AP bringup, strict `W^X` RX trampoline,
/// Doorbell IPI (`0x41`) wakeup from `HLT`, and multi-stack kernel thread context switching.
///
/// Boots all available secondary hardware cores, verifies `SMP_RX_TRAMPOLINE_VA` is
/// Supervisor `RX` (`!writable && executable`) and `PHYS_MAP_OFFSET` (`pa_to_va(0x8200)`)
/// is never simultaneously writable and executable, switches across all 4 dedicated
/// 16 KiB kernel thread stacks (`KTHREAD_STACKS`), wakes sleeping AP cores from `HLT`
/// via Doorbell IPI (`vector 0x41`), and emits:
/// `SMP_HW init OK cpus=<N> threads=4 ctx_sw=4`
#[inline(never)]
pub(crate) fn banner_smp_hw() {
    let online = smp_hw_init();

    // Verify strict `W^X` across both the Supervisor RX trampoline alias and `PHYS_MAP_OFFSET`.
    // SAFETY: Running at CPL=0 after `smp_hw_init` mapped `SMP_RX_TRAMPOLINE_VA`.
    unsafe {
        let (rx_p, rx_w, rx_x) = walk_va_effective_wx(smp_rx_va(SWITCH_CONTEXT_VA));
        if !rx_p || rx_w || !rx_x {
            panic!("SMP_HW: RX trampoline violated W^X (expected RX, non-writable)");
        }
        let (dm_p, dm_w, dm_x) = walk_va_effective_wx(pa_to_va(SWITCH_CONTEXT_VA) as u64);
        if !dm_p || (dm_w && dm_x) {
            panic!("SMP_HW: PHYS_MAP_OFFSET violated W^X (unexpected RWX mapping)");
        }
    }

    // Verify online APs observed distinct hardware Local APIC IDs (`0xFEE0_0020`).
    let mut ap_idx = 1usize;
    while ap_idx < online {
        let obs_apic = HW_APIC_IDS[ap_idx].load(Ordering::Acquire);
        if obs_apic != ap_idx as u32 {
            panic!("SMP_HW: AP hardware Local APIC ID mismatch");
        }
        ap_idx += 1;
    }

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

    // Ensure every online AP has at least 1 queued job and ring the Doorbell IPI (`vector 0x41`)
    // to wake them from `HLT`.
    if online > 1 {
        let mut ap = 1usize;
        while ap < online {
            CPU_WORK_SEED[ap].store(0xCAFE_0000 | (ap as u64), Ordering::Relaxed);
            CPU_PENDING_JOBS[ap].fetch_add(1, Ordering::SeqCst);
            ap += 1;
        }
        ring_smp_doorbell();

        let mut wait = 0u32;
        while wait < 100_000 {
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
            if wait == 10_000 || wait == 30_000 {
                ring_smp_doorbell();
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
    // Verify Doorbell IPIs (`vector 0x41`) fired during AP wakeup and kthread scheduling
    // did NOT increment the Local APIC Timer (`vector 0x40`) counter in `.bss`.
    if read_hw_irq_wakeups() != 0 {
        panic!("SMP_HW: Doorbell IPI 0x41 incremented timer IRQ counter");
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
