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
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use crate::{
    alloc_pt_frame, dec_u64, dma_phys_base, ensure_mmio_page, ensure_phys_ro_page, hex_u32, inb,
    mmio_read32, mmio_read64, mmio_write32, mmio_write64, outb, pa_to_va, read_cr3,
    serial_write_bytes, translate_kernel_va_to_pa, with_pt_lock, BOOT_RSDP_PHYS, KERNEL_SHELL,
    PTE_ADDR_MASK, PTE_P, PTE_PS, PTE_W,
};

/// Maximum number of hardware SMP cores supported (`BSP + 3 APs`).
pub(crate) const MAX_SMP_CPUS: usize = 4;
/// Number of dedicated hardware-context-switched kernel worker threads.
pub(crate) const NUM_KTHREADS: usize = 4;
/// Number of `u64` words per 16 KiB hardware stack (`2048 * 8 = 16384` bytes).
const STACK_WORDS: usize = 2048;
/// Number of `u64` words per 4 KiB hardware IST stack (`512 * 8 = 4096` bytes).
const IST_WORDS: usize = 512;

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
/// Interrupt vector for Cross-CPU TLB Shootdown IPI (`0x42`).
const SMP_TLB_SHOOTDOWN_VECTOR: u32 = 0x42;
/// Interrupt vector for Emergency Panic Halt IPI (`0x43`).
const SMP_PANIC_HALT_VECTOR: u32 = 0x43;

/// Physical and identity-mapped virtual address of the AP startup trampoline page.
const TRAMPOLINE_PAGE_PHYS: u64 = 0x8000;
/// Physical address of the 27-byte `cuttle_switch_context` routine.
const SWITCH_CONTEXT_VA: u64 = 0x8200;
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
/// Physical address of `SLEEP_HLT_CODE` (4 bytes: `sti; hlt; cli; ret`).
const SLEEP_HLT_PHYS: u64 = 0x8370;
/// Physical address storing `&HW_IRQ_WAKEUP_COUNTER` (`.bss` `RW+NX` atomic pointer).
const IRQ_WAKEUPS_PTR_PHYS: u64 = 0x8380;
/// Physical address storing `pa_to_va(LAPIC_PHYS_BASE + LAPIC_EOI) as u64`.
const LAPIC_EOI_PTR_PHYS: u64 = 0x8388;
/// Physical address of `ISR_LAPIC_DOORBELL` (17 bytes, handles Doorbell IPI `0x41`).
const ISR_LAPIC_DOORBELL_PHYS: u64 = 0x8390;
/// Physical address of `ISR_CPU_FAULT_DIAG` (23 bytes, diagnostic `COM1` + halt for Ring-0 CPU faults).
const ISR_CPU_FAULT_DIAG_PHYS: u64 = 0x83B0;
/// Physical address storing `&HW_TLB_SHOOTDOWN_ACKS` (`.bss` `RW+NX` atomic pointer).
const TLB_ACKS_PTR_PHYS: u64 = 0x83D0;
/// Physical address storing `&HW_NMI_COUNT` (`.bss` `RW+NX` atomic pointer).
const NMI_COUNT_PTR_PHYS: u64 = 0x83D8;
/// Physical address of the Runtime 64-bit GDT (`5 * 8 + 4 * 16 = 104` bytes: `0x08..0x20` + 4 per-CPU TSS).
const RUNTIME_GDT_PHYS: u64 = 0x8400;
/// Physical base of the 4 per-CPU 104-byte `Tss64` structures (`0x80` byte stride -> `0x8500..0x8700`).
const RUNTIME_TSS_BASE_PHYS: u64 = 0x8500;
/// Physical address of `ISR_TLB_SHOOTDOWN` (34 bytes, vector `0x42`).
const ISR_TLB_SHOOTDOWN_PHYS: u64 = 0x8700;
/// Physical address of `ISR_PANIC_HALT` (4 bytes, vector `0x43`).
const ISR_PANIC_HALT_PHYS: u64 = 0x8740;
/// Physical address of `ISR_NMI_WATCHDOG` (15 bytes, vector `2` on `IST2`).
const ISR_NMI_WATCHDOG_PHYS: u64 = 0x8760;
/// Physical address of `LOAD_GDT_IDT_TSS_CODE` (33 bytes: `lgdt`, `lidt`, segment reload, `ltr dx`).
const LOAD_GDT_IDT_TSS_PHYS: u64 = 0x8780;
/// Physical page holding the 256-entry Runtime 64-bit IDT (`4096` bytes).
const RUNTIME_IDT_PHYS: u64 = 0x9000;

/// 4 KiB-aligned 16 KiB hardware stack backed by atomic words (zero `static mut`).
#[repr(C, align(4096))]
pub(crate) struct HardwareStack([AtomicU64; STACK_WORDS]);

impl HardwareStack {
    const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self([ZERO; STACK_WORDS])
    }

    #[inline(always)]
    fn bss_base_va(&self) -> u64 {
        self.0.as_ptr() as usize as u64
    }
}

/// 4 KiB-aligned dedicated per-CPU Interrupt Stack Table (`IST`) frame (`4 KiB`).
#[repr(C, align(4096))]
struct HardwareIstPage([AtomicU64; IST_WORDS]);

impl HardwareIstPage {
    const fn new() -> Self {
        #[allow(clippy::declare_interior_mutable_const)]
        const ZERO: AtomicU64 = AtomicU64::new(0);
        Self([ZERO; IST_WORDS])
    }

    #[inline(always)]
    fn bss_base_va(&self) -> u64 {
        self.0.as_ptr() as usize as u64
    }
}

/// Physical backing frames for per-CPU runtime stacks (`CPU 0..4`, mapped with unmapped guard pages).
static AP_STACKS: [HardwareStack; MAX_SMP_CPUS] = [
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
];

/// Physical backing frames for context-switched kernel thread stacks (`0..4`, mapped with guard pages).
static KTHREAD_STACKS: [HardwareStack; NUM_KTHREADS] = [
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
    HardwareStack::new(),
];

/// Per-CPU dedicated `IST1` (`#DF` Double Fault) 4 KiB physical backing pages (`CPU 0..4`).
static CPU_IST1_PAGES: [HardwareIstPage; MAX_SMP_CPUS] = [
    HardwareIstPage::new(),
    HardwareIstPage::new(),
    HardwareIstPage::new(),
    HardwareIstPage::new(),
];

/// Per-CPU dedicated `IST2` (`#NMI` / `#MC`) 4 KiB physical backing pages (`CPU 0..4`).
static CPU_IST2_PAGES: [HardwareIstPage; MAX_SMP_CPUS] = [
    HardwareIstPage::new(),
    HardwareIstPage::new(),
    HardwareIstPage::new(),
    HardwareIstPage::new(),
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
/// Base virtual address (`PD[1]`, 2 MiB-aligned) of the guarded hardware stack & IST L1 page table.
static SMP_GUARDED_STACKS_VA: AtomicU64 = AtomicU64::new(0);
/// Cross-CPU TLB shootdown IPI (`vector 0x42`) acknowledgement counter in `.bss` (`RW+NX`).
static HW_TLB_SHOOTDOWN_ACKS: AtomicU64 = AtomicU64::new(0);
/// Non-Maskable Interrupt (`vector 2` on `IST2`) counter in `.bss` (`RW+NX`).
static HW_NMI_COUNT: AtomicU64 = AtomicU64::new(0);
/// Hardware `STR` Task Register selector observed on each online CPU (`0x28 + cpu * 0x10`).
static HW_CPU_TR_SEL: [AtomicU16; MAX_SMP_CPUS] = [
    AtomicU16::new(0),
    AtomicU16::new(0),
    AtomicU16::new(0),
    AtomicU16::new(0),
];
/// Hardware CPU security feature bitmask (`NXE | WP | SMEP | SMAP | UMIP | FSGSBASE`) observed per CPU.
static HW_AP_SEC_BITS: [AtomicU32; MAX_SMP_CPUS] = [
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
    AtomicU32::new(0),
];
/// Expected Local APIC IDs resolved from firmware ACPI `MADT` (or architectural fallback) per slot.
static EXPECTED_APIC_IDS: [AtomicU32; MAX_SMP_CPUS] = [
    AtomicU32::new(0),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
    AtomicU32::new(u32::MAX),
];
/// True once `LAPIC_PHYS_BASE` (`0xFEE0_0000`) has been mapped into `PHYS_MAP_OFFSET`.
static LAPIC_MMIO_READY: AtomicBool = AtomicBool::new(false);
/// True if a valid firmware ACPI `MADT` (`"APIC"`) table was discovered via `RSDP -> XSDT/RSDT`.
static ACPI_MADT_FOUND: AtomicBool = AtomicBool::new(false);
/// Firmware HPET MMIO base physical address discovered via ACPI `"HPET"` table (`0` if absent).
static ACPI_HPET_PHYS: AtomicU64 = AtomicU64::new(0);
/// True if a firmware Intel VT-d `"DMAR"` table was discovered via `RSDP -> XSDT/RSDT`.
static ACPI_DMAR_FOUND: AtomicBool = AtomicBool::new(false);
/// Multi-core hard-lockup watchdog tracking per-CPU tick progress across scheduling epochs.
static SMP_WATCHDOG: spin::Mutex<target_enterprise::smp::SmpLockupWatchdog<MAX_SMP_CPUS>> =
    spin::Mutex::new(target_enterprise::smp::SmpLockupWatchdog::new(8));

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
    match target_enterprise::memory::kernel_guards::smp_checked_rx_va(base, phys) {
        Some(va) => va,
        None => panic!("SMP_HW: invalid or uninitialized RX trampoline phys/VA"),
    }
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

/// Return `(bottom_guard_va, base_va, top_va)` for per-CPU guarded 16 KiB stack `cpu_idx` (`0..4`).
#[inline]
fn guarded_ap_stack_bounds_va(cpu_idx: usize) -> (u64, u64, u64) {
    let region = SMP_GUARDED_STACKS_VA.load(Ordering::Acquire);
    match target_enterprise::memory::kernel_guards::guarded_stack16k_bounds_va(
        region,
        cpu_idx & (MAX_SMP_CPUS - 1),
    ) {
        Some(v) => v,
        None => panic!("SMP_HW: uninitialized guarded AP stack VA"),
    }
}

/// Return `(bottom_guard_va, base_va, top_va)` for guarded 16 KiB kernel thread stack `tid` (`0..4`).
#[inline]
fn guarded_kthread_stack_bounds_va(tid: usize) -> (u64, u64, u64) {
    let region = SMP_GUARDED_STACKS_VA.load(Ordering::Acquire);
    match target_enterprise::memory::kernel_guards::guarded_stack16k_bounds_va(
        region,
        MAX_SMP_CPUS + (tid & (NUM_KTHREADS - 1)),
    ) {
        Some(v) => v,
        None => panic!("SMP_HW: uninitialized guarded kthread stack VA"),
    }
}

/// Return `(bottom_guard_va, base_va, top_va)` for per-CPU guarded 4 KiB `IST1` (`#DF`) stack `cpu_idx`.
#[inline]
fn guarded_ist1_bounds_va(cpu_idx: usize) -> (u64, u64, u64) {
    let region = SMP_GUARDED_STACKS_VA.load(Ordering::Acquire);
    match target_enterprise::memory::kernel_guards::guarded_ist4k_bounds_va(
        region,
        MAX_SMP_CPUS + NUM_KTHREADS,
        cpu_idx & (MAX_SMP_CPUS - 1),
    ) {
        Some(v) => v,
        None => panic!("SMP_HW: uninitialized guarded IST1 stack VA"),
    }
}

/// Return `(bottom_guard_va, base_va, top_va)` for per-CPU guarded 4 KiB `IST2` (`#NMI`/`#MC`) stack `cpu_idx`.
#[inline]
fn guarded_ist2_bounds_va(cpu_idx: usize) -> (u64, u64, u64) {
    let region = SMP_GUARDED_STACKS_VA.load(Ordering::Acquire);
    match target_enterprise::memory::kernel_guards::guarded_ist4k_bounds_va(
        region,
        MAX_SMP_CPUS + NUM_KTHREADS,
        MAX_SMP_CPUS + (cpu_idx & (MAX_SMP_CPUS - 1)),
    ) {
        Some(v) => v,
        None => panic!("SMP_HW: uninitialized guarded IST2 stack VA"),
    }
}

/// Return the 16-byte 64-bit TSS selector in `RUNTIME_GDT` (`0x28 + cpu_idx * 0x10`).
#[inline(always)]
const fn cpu_tss_selector(cpu_idx: usize) -> u16 {
    (0x28 + (cpu_idx & (MAX_SMP_CPUS - 1)) * 0x10) as u16
}

/// Broadcast a Cross-CPU TLB Shootdown IPI (`vector 0x42`, All-Excluding-Self) and wait
/// (bounded) for all online peer APs to reload `CR3` and acknowledge via `HW_TLB_SHOOTDOWN_ACKS`.
pub(crate) fn smp_broadcast_tlb_shootdown() {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    let online = HW_ONLINE_CPUS.load(Ordering::Acquire);
    if online <= 1 {
        return;
    }
    let peers = (online - 1) as u64;
    let before = HW_TLB_SHOOTDOWN_ACKS.load(Ordering::Acquire);
    // SAFETY: `LAPIC_PHYS_BASE` is mapped and `ISR_TLB_SHOOTDOWN` is installed on vector `0x42`.
    unsafe {
        wait_lapic_icr_idle();
        let icr_lo_va = pa_to_va(LAPIC_PHYS_BASE + LAPIC_ICR_LO).cast::<u32>();
        core::ptr::write_volatile(icr_lo_va, 0x000C_4000 | SMP_TLB_SHOOTDOWN_VECTOR);
    }
    let mut spins = 0u32;
    while HW_TLB_SHOOTDOWN_ACKS.load(Ordering::Acquire) < before.saturating_add(peers)
        && spins < 100_000
    {
        core::hint::spin_loop();
        spins += 1;
    }
}

/// Best-effort broadcast of the Emergency Panic Halt IPI (`vector 0x43`, All-Excluding-Self)
/// so peer APs immediately execute `cli; hlt; jmp -3` during crash containment.
pub(crate) fn smp_broadcast_panic_halt() {
    if !LAPIC_MMIO_READY.load(Ordering::Relaxed) {
        return;
    }
    // SAFETY: `LAPIC_PHYS_BASE` was mapped; bounded wait + Fixed broadcast-excluding-self IPI.
    unsafe {
        wait_lapic_icr_idle();
        let icr_lo_va = pa_to_va(LAPIC_PHYS_BASE + LAPIC_ICR_LO).cast::<u32>();
        core::ptr::write_volatile(icr_lo_va, 0x000C_4000 | SMP_PANIC_HALT_VECTOR);
    }
}

/// Non-panicking read of the executing CPU's hardware Local APIC ID (`0xFEE0_0020 >> 24`) for crash forensics.
pub(crate) fn read_current_lapic_id_safe() -> u32 {
    if LAPIC_MMIO_READY.load(Ordering::Relaxed) {
        // SAFETY: `LAPIC_PHYS_BASE` was mapped via `ensure_mmio_page`.
        unsafe { core::ptr::read_volatile(pa_to_va(LAPIC_PHYS_BASE + LAPIC_ID).cast::<u32>()) >> 24 }
    } else {
        HW_APIC_IDS[0].load(Ordering::Relaxed)
    }
}

/// Restore `CPU 0`'s permanent guarded `RUNTIME_TSS` (`selector 0x28`) after a Ring-3 sandbox exit
/// temporarily loaded a sandbox-local TSS into `TR`.
pub(crate) fn restore_cpu0_runtime_tss_if_active() {
    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        return;
    }
    let sel = cpu_tss_selector(0);
    // Clear the Busy bit (`0x02` in Type `0x8B -> 0x89`) in `RUNTIME_GDT` before `ltr`.
    // SAFETY: `RUNTIME_GDT_PHYS + 0x28` is CPU 0's 16-byte 64-bit TSS descriptor in mapped RAM.
    unsafe {
        let access_ptr = pa_to_va(RUNTIME_GDT_PHYS + (sel as u64) + 5);
        let acc = core::ptr::read_volatile(access_ptr);
        core::ptr::write_volatile(access_ptr, acc & !0x02);
        let obs_tr: u16;
        asm!(
            "ltr {sel:x}",
            "str {obs:x}",
            sel = in(reg) sel,
            obs = out(reg) obs_tr,
            options(nomem, nostack, preserves_flags),
        );
        HW_CPU_TR_SEL[0].store(obs_tr, Ordering::Release);
    }
}

/// Invoke the 33-byte `load_runtime_gdt_idt_tss` stub via its Supervisor `RX` alias (`smp_rx_va(0x8780)`),
/// loading `RUNTIME_GDTR`, `RUNTIME_IDTR`, `CS=0x08`/`SS=0x10`, and per-CPU 64-bit TSS (`0x28 + cpu_idx * 0x10`).
#[inline(never)]
// SAFETY: Caller must execute at CPL=0 after `init_runtime_idt_and_isrs` populated `RUNTIME_GDT`, `RUNTIME_TSS`, and `RUNTIME_IDT`.
unsafe fn invoke_load_runtime_gdt_idt_tss(cpu_idx: usize) {
    let sel = cpu_tss_selector(cpu_idx);
    // Clear TSS Busy bit (`0x8B -> 0x89`) in case this CPU reloads its runtime TSS.
    // SAFETY: `RUNTIME_GDT_PHYS + sel` is a valid 16-byte TSS descriptor in mapped RAM.
    unsafe {
        let access_ptr = pa_to_va(RUNTIME_GDT_PHYS + (sel as u64) + 5);
        let acc = core::ptr::read_volatile(access_ptr);
        core::ptr::write_volatile(access_ptr, acc & !0x02);
    }
    let code_va = smp_rx_va(LOAD_GDT_IDT_TSS_PHYS) as usize;
    let gdtr_va = pa_to_va(RUNTIME_GDTR_PHYS) as u64;
    let idtr_va = pa_to_va(RUNTIME_IDTR_PHYS) as u64;
    let fn_ptr: unsafe extern "C" fn(u64, u64, u16) =
        // SAFETY: `smp_rx_va(0x8780)` is mapped Supervisor Read+Execute (`W^X`) and holds `LOAD_GDT_IDT_TSS_CODE`.
        unsafe { core::mem::transmute(code_va) };
    // SAFETY: `gdtr_va`, `idtr_va`, and `sel` reference valid `RUNTIME_GDT`, `RUNTIME_IDT`, and per-CPU `Tss64`.
    unsafe {
        fn_ptr(gdtr_va, idtr_va, sel);
        let obs_tr: u16;
        asm!("str {:x}", out(reg) obs_tr, options(nomem, nostack, preserves_flags));
        HW_CPU_TR_SEL[cpu_idx & (MAX_SMP_CPUS - 1)].store(obs_tr, Ordering::Release);
    }
}

/// Invoke the 4-byte `sti; hlt; cli; ret` hardware sleep stub via `smp_rx_va(0x8370)`.
///
/// Atomically unmasks interrupts and halts the CPU core (`C1` state, 0% host CPU)
/// until the next hardware interrupt (Local APIC Timer `0x40` on BSP or Doorbell IPI
/// `0x41` on APs) wakes the core.
#[inline(never)]
// SAFETY: Caller must execute at CPL=0 after `invoke_load_runtime_gdt_idt_tss` and Local APIC initialization.
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

    // 1. Enforce `NXE + WP + SMEP + SMAP + UMIP + FSGSBASE` on this AP, load the shared Runtime GDT/IDT
    //    plus this AP's dedicated 64-bit TSS (`0x28 + idx * 0x10`, with guarded `RSP0`, `IST1`, `IST2`),
    //    record this core's hardware Local APIC ID (`0xFEE0_0020`), and enable its Local APIC (`SVR = 0x1FF`).
    // SAFETY: Running at CPL=0 in 64-bit Long Mode after `init_runtime_idt_and_isrs` mapped `0x8000`, `0x9000`, and `0xFEE0_0000`.
    unsafe {
        let sec = crate::banners_arch_platform::enable_cpu_memory_protections();
        HW_AP_SEC_BITS[idx].store(sec, Ordering::Release);
        invoke_load_runtime_gdt_idt_tss(idx);
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
        // SAFETY: Runtime GDT, per-CPU TSS, Runtime IDT, and Local APIC are active on this AP.
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
/// dedicated 4 KiB Supervisor Read+Execute (`PD[0]`, `PTE_W = 0`, `PTE_U = 0`, `PTE_NX = 0`)
/// page, and map all 16 hardware stacks (`AP_STACKS[0..4]`, `KTHREAD_STACKS[0..4]`,
/// `CPU_IST1_PAGES[0..4]`, `CPU_IST2_PAGES[0..4]`) into `PD[1]` (`va + 0x20_0000`) with
/// unmapped (`PTE_P = 0`) 4 KiB guard pages below and above every stack and `RW+NX` interior pages.
// SAFETY: Caller must execute at CPL=0 after `set_phys_offset` initialized `PHYS_MAP_OFFSET` and `PT_ALLOC_NEXT`.
unsafe fn map_smp_rx_trampoline_page() -> u64 {
    use target_enterprise::memory::kernel_guards::{build_guarded_stacks_pt, PTE_NX_BIT};

    let existing = SMP_RX_TRAMPOLINE_VA.load(Ordering::Acquire);
    if existing != 0 {
        return existing;
    }

    // Resolve physical frames backing `AP_STACKS`, `KTHREAD_STACKS`, `CPU_IST1_PAGES`, and `CPU_IST2_PAGES`.
    let mut stacks_16k_pa = [[0u64; 4]; MAX_SMP_CPUS + NUM_KTHREADS];
    let mut c = 0usize;
    while c < MAX_SMP_CPUS {
        let base_va = AP_STACKS[c].bss_base_va();
        let mut p = 0usize;
        while p < 4 {
            // SAFETY: Running at CPL=0 with active 4-level kernel page tables.
            let pa = match unsafe { translate_kernel_va_to_pa(base_va + (p as u64) * 4096) } {
                Some(addr) => addr & !0xFFFu64,
                None => panic!("SMP_HW: failed to resolve AP_STACKS physical frame"),
            };
            stacks_16k_pa[c][p] = pa;
            p += 1;
        }
        c += 1;
    }
    let mut t = 0usize;
    while t < NUM_KTHREADS {
        let base_va = KTHREAD_STACKS[t].bss_base_va();
        let mut p = 0usize;
        while p < 4 {
            // SAFETY: Running at CPL=0 with active 4-level kernel page tables.
            let pa = match unsafe { translate_kernel_va_to_pa(base_va + (p as u64) * 4096) } {
                Some(addr) => addr & !0xFFFu64,
                None => panic!("SMP_HW: failed to resolve KTHREAD_STACKS physical frame"),
            };
            stacks_16k_pa[MAX_SMP_CPUS + t][p] = pa;
            p += 1;
        }
        t += 1;
    }
    let mut ists_4k_pa = [0u64; MAX_SMP_CPUS * 2];
    let mut ic = 0usize;
    while ic < MAX_SMP_CPUS {
        // SAFETY: Running at CPL=0 with active 4-level kernel page tables.
        let pa1 = match unsafe { translate_kernel_va_to_pa(CPU_IST1_PAGES[ic].bss_base_va()) } {
            Some(addr) => addr & !0xFFFu64,
            None => panic!("SMP_HW: failed to resolve CPU_IST1_PAGES physical frame"),
        };
        // SAFETY: Running at CPL=0 with active 4-level kernel page tables.
        let pa2 = match unsafe { translate_kernel_va_to_pa(CPU_IST2_PAGES[ic].bss_base_va()) } {
            Some(addr) => addr & !0xFFFu64,
            None => panic!("SMP_HW: failed to resolve CPU_IST2_PAGES physical frame"),
        };
        ists_4k_pa[ic] = pa1;
        ists_4k_pa[MAX_SMP_CPUS + ic] = pa2;
        ic += 1;
    }

    let (va, stacks_va) = with_pt_lock(|| {
        // SAFETY: Running at CPL=0 under `PT_MOD_LOCK`.
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
        // SAFETY: Under `PT_MOD_LOCK` with initialized PT frame pool.
        let pdpt_phys = unsafe { crate::alloc_pt_frame_locked() };
        // SAFETY: Under `PT_MOD_LOCK` with initialized PT frame pool.
        let pd_phys = unsafe { crate::alloc_pt_frame_locked() };
        // SAFETY: Under `PT_MOD_LOCK` with initialized PT frame pool.
        let pt_phys = unsafe { crate::alloc_pt_frame_locked() };
        // SAFETY: Under `PT_MOD_LOCK` with initialized PT frame pool.
        let stack_pt_phys = unsafe { crate::alloc_pt_frame_locked() };

        // Populate `stack_pt_phys` via verified `build_guarded_stacks_pt`.
        // SAFETY: `stack_pt_phys` is a freshly zeroed 4 KiB page-table frame mapped via `pa_to_va`.
        unsafe {
            let stack_pt_slice = &mut *(pa_to_va(stack_pt_phys) as *mut [u64; 512]);
            if build_guarded_stacks_pt(&stacks_16k_pa, &ists_4k_pa, stack_pt_slice).is_err() {
                panic!("SMP_HW: build_guarded_stacks_pt failed validation");
            }
        }

        let rx_va = 0xFFFF_0000_0000_0000u64 | ((slot as u64) << 39);
        let guarded_va = rx_va + 0x20_0000;
        // Strict `W^X`:
        //   - `PML4[slot]` & `PDPT[0]` carry `PTE_P | PTE_W` (`PTE_NX = 0`) so children narrow permissions:
        //   - `PD[0]` (`rx_va`) omits `PTE_W` (`PTE_P` only) -> strictly Supervisor Read+Execute (`RX`)!
        //   - `PD[1]` (`guarded_va`) sets `PTE_P | PTE_W | PTE_NX_BIT` -> strictly Supervisor `RW+NX` + guard holes!
        // SAFETY: All four page-table frames are valid 8-byte-aligned tables in mapped RAM.
        unsafe {
            core::ptr::write_volatile(pa_to_va(pt_phys).cast::<u64>(), TRAMPOLINE_PAGE_PHYS | PTE_P);
            let pd_ptr = pa_to_va(pd_phys).cast::<u64>();
            core::ptr::write_volatile(pd_ptr.add(0), pt_phys | PTE_P);
            core::ptr::write_volatile(pd_ptr.add(1), stack_pt_phys | PTE_P | PTE_W | PTE_NX_BIT);
            core::ptr::write_volatile(pa_to_va(pdpt_phys).cast::<u64>(), pd_phys | PTE_P | PTE_W);
            core::ptr::write_volatile(pml4_ptr.add(slot), pdpt_phys | PTE_P | PTE_W);
            asm!("invlpg [{}]", in(reg) rx_va, options(nostack, preserves_flags));
        }
        (rx_va, guarded_va)
    });

    SMP_GUARDED_STACKS_VA.store(stacks_va, Ordering::Release);
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

/// Write a 16-byte 64-bit Interrupt Gate (`selector = 0x08`, `IST = ist & 7`, `type_attr = 0x8E`)
/// into `idt_base` at `vec_idx`.
// SAFETY: `idt_base` must point to a mapped 4096-byte IDT page and `vec_idx < 256`.
unsafe fn write_idt_gate_ist(idt_base: *mut u8, vec_idx: usize, handler_va: u64, ist: u8) {
    let off = vec_idx * 16;
    let lo16 = (handler_va & 0xFFFF) as u16;
    let mid16 = ((handler_va >> 16) & 0xFFFF) as u16;
    let hi32 = (handler_va >> 32) as u32;
    let mut entry = [0u8; 16];
    entry[0..2].copy_from_slice(&lo16.to_le_bytes());
    entry[2..4].copy_from_slice(&0x0008u16.to_le_bytes());
    entry[4] = ist & 0x07;
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

/// Encode a 16-byte 64-bit Available TSS descriptor (`P=1, DPL=0, S=0, Type=0x9` -> `0x89`)
/// for a 104-byte `Tss64` at `tss_va`.
#[inline]
fn encode_tss64_descriptor(tss_va: u64) -> [u8; 16] {
    let limit: u32 = (target_enterprise::gdt::TSS64_LEN - 1) as u32;
    let mut d = [0u8; 16];
    d[0..2].copy_from_slice(&(limit as u16).to_le_bytes());
    d[2..4].copy_from_slice(&((tss_va & 0xFFFF) as u16).to_le_bytes());
    d[4] = ((tss_va >> 16) & 0xFF) as u8;
    d[5] = 0x89; // Present | 64-bit TSS Available
    d[6] = ((limit >> 16) & 0x0F) as u8;
    d[7] = ((tss_va >> 24) & 0xFF) as u8;
    d[8..12].copy_from_slice(&((tss_va >> 32) as u32).to_le_bytes());
    d
}

/// Initialize the shared 64-bit Runtime GDT (`0x8400`, with 4 per-CPU 16-byte TSS descriptors),
/// 4 per-CPU `Tss64` structures (`0x8500..0x8700`, with guarded `RSP0`, `IST1`, `IST2`),
/// 256-entry Runtime IDT (`0x9000`), hardware ISR stubs (`0x8300..0x87A1`), legacy 8259 PIC
/// remap/mask, and load `GDTR`/`IDTR`/`TR` (`0x28`) on `CPU 0`.
// SAFETY: Caller must execute at CPL=0 after `map_smp_rx_trampoline_page()` mapped `SMP_RX_TRAMPOLINE_VA` and `SMP_GUARDED_STACKS_VA`.
unsafe fn init_runtime_idt_and_isrs() {
    use target_enterprise::gdt::Tss64;

    // 1. Map the Local APIC MMIO page (`0xFEE0_0000`) into the shared higher-half page tables
    //    (with strict `PTE_NX` via `mmio_leaf_pte`) so both BSP and APs access `LAPIC_EOI` directly.
    // SAFETY: `LAPIC_PHYS_BASE` is the architectural x86-64 Local APIC MMIO frame.
    let lapic_page_va = unsafe { ensure_mmio_page(LAPIC_PHYS_BASE) as u64 };
    LAPIC_MMIO_READY.store(true, Ordering::Release);
    let lapic_eoi_va = lapic_page_va + LAPIC_EOI;
    let wakeup_counter_va = HW_IRQ_WAKEUP_COUNTER.as_ptr() as usize as u64;
    let tlb_acks_va = HW_TLB_SHOOTDOWN_ACKS.as_ptr() as usize as u64;
    let nmi_count_va = HW_NMI_COUNT.as_ptr() as usize as u64;

    // 2. Store `.bss` (`RW+NX`) atomic pointers at `0x8380`, `0x8388`, `0x83D0`, `0x83D8`.
    // SAFETY: All pointer slots are 8-byte-aligned inside the mapped `0x8000` frame (`PHYS_MAP_OFFSET`, `RW+NX`).
    unsafe {
        HW_IRQ_WAKEUP_COUNTER.store(0, Ordering::Release);
        HW_TLB_SHOOTDOWN_ACKS.store(0, Ordering::Release);
        HW_NMI_COUNT.store(0, Ordering::Release);
        core::ptr::write_volatile(
            pa_to_va(IRQ_WAKEUPS_PTR_PHYS).cast::<u64>(),
            wakeup_counter_va,
        );
        core::ptr::write_volatile(pa_to_va(LAPIC_EOI_PTR_PHYS).cast::<u64>(), lapic_eoi_va);
        core::ptr::write_volatile(pa_to_va(TLB_ACKS_PTR_PHYS).cast::<u64>(), tlb_acks_va);
        core::ptr::write_volatile(pa_to_va(NMI_COUNT_PTR_PHYS).cast::<u64>(), nmi_count_va);
    }

    // 3. Install `ISR_LAPIC_EOI` at `0x8300` (Local APIC Timer `0x40`):
    const ISR_LAPIC_EOI: [u8; 28] = [
        0x50,
        0x48, 0x8B, 0x05, 0x78, 0x00, 0x00, 0x00,
        0xF0, 0x48, 0xFF, 0x00,
        0x48, 0x8B, 0x05, 0x75, 0x00, 0x00, 0x00,
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x58,
        0x48, 0xCF,
    ];
    // 4. Install `ISR_PIC_EOI` at `0x8320` (`0x20..0x2F`):
    const ISR_PIC_EOI: [u8; 10] = [
        0x50, 0xB0, 0x20, 0xE6, 0xA0, 0xE6, 0x20, 0x58, 0x48, 0xCF,
    ];
    // 5. Install `ISR_SPURIOUS` at `0x8340` (`iretq`):
    const ISR_SPURIOUS: [u8; 2] = [0x48, 0xCF];
    // 6. Install `SLEEP_HLT_CODE` at `0x8370` (`sti; hlt; cli; ret`):
    const SLEEP_HLT_CODE: [u8; 4] = [0xFB, 0xF4, 0xFA, 0xC3];
    // 7. Install `ISR_LAPIC_DOORBELL` at `0x8390` (Doorbell IPI `0x41`):
    const ISR_LAPIC_DOORBELL: [u8; 17] = [
        0x50,
        0x48, 0x8B, 0x05, 0xF0, 0xFF, 0xFF, 0xFF,
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x58,
        0x48, 0xCF,
    ];
    // 8. Install `ISR_CPU_FAULT_DIAG` at `0x83B0` (`#DF` on `IST1`, `#MC` on `IST2`, etc.):
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
    // 9. Install `ISR_TLB_SHOOTDOWN` at `0x8700` (Vector `0x42`: reloads `CR3`, `lock inc` `0x83D0`, `LAPIC_EOI`):
    const ISR_TLB_SHOOTDOWN: [u8; 34] = [
        0x50,                                     // push rax
        0x0F, 0x20, 0xD8,                         // mov rax, cr3
        0x0F, 0x22, 0xD8,                         // mov cr3, rax (flush local TLB)
        0x48, 0x8B, 0x05, 0xC2, 0xFC, 0xFF, 0xFF, // mov rax, [rip - 0x33E] -> 0x83D0
        0xF0, 0x48, 0xFF, 0x00,                   // lock inc qword ptr [rax]
        0x48, 0x8B, 0x05, 0x6F, 0xFC, 0xFF, 0xFF, // mov rax, [rip - 0x391] -> 0x8388
        0xC7, 0x00, 0x00, 0x00, 0x00, 0x00,       // mov dword ptr [rax], 0 (LAPIC_EOI)
        0x58,                                     // pop rax
        0x48, 0xCF,                               // iretq
    ];
    // 10. Install `ISR_PANIC_HALT` at `0x8740` (Vector `0x43`: immediate `cli; hlt; jmp -3`):
    const ISR_PANIC_HALT: [u8; 4] = [0xFA, 0xF4, 0xEB, 0xFD];
    // 11. Install `ISR_NMI_WATCHDOG` at `0x8760` (Vector `2` on dedicated `IST2` stack):
    const ISR_NMI_WATCHDOG: [u8; 15] = [
        0x50,                                     // push rax
        0x48, 0x8B, 0x05, 0x70, 0xFC, 0xFF, 0xFF, // mov rax, [rip - 0x390] -> 0x83D8
        0xF0, 0x48, 0xFF, 0x00,                   // lock inc qword ptr [rax]
        0x58,                                     // pop rax
        0x48, 0xCF,                               // iretq
    ];
    // 12. Install `LOAD_GDT_IDT_TSS_CODE` at `0x8780` (`lgdt [rdi]; lidt [rsi]; far retfq CS=0x08; SS=0x10; ltr dx; ret`):
    const LOAD_GDT_IDT_TSS_CODE: [u8; 33] = [
        0x0F, 0x01, 0x17,                         // lgdt [rdi]
        0x0F, 0x01, 0x1E,                         // lidt [rsi]
        0x6A, 0x08,                               // push 0x08
        0x48, 0x8D, 0x05, 0x03, 0x00, 0x00, 0x00, // lea rax, [rip + 3] -> +0x12
        0x50,                                     // push rax
        0x48, 0xCB,                               // retfq
        0xB8, 0x10, 0x00, 0x00, 0x00,             // mov eax, 0x10
        0x8E, 0xD8,                               // mov ds, ax
        0x8E, 0xC0,                               // mov es, ax
        0x8E, 0xD0,                               // mov ss, ax
        0x0F, 0x00, 0xDA,                         // ltr dx
        0xC3,                                     // ret
    ];

    // SAFETY: All destination offsets (`0x8300..0x87A1`) lie within the mapped `0x8000` page (`PHYS_MAP_OFFSET`, `RW+NX`).
    unsafe {
        let copy_stub = |phys: u64, bytes: &[u8]| {
            let dst = pa_to_va(phys);
            let mut k = 0usize;
            while k < bytes.len() {
                core::ptr::write_volatile(dst.add(k), bytes[k]);
                k += 1;
            }
        };
        copy_stub(ISR_LAPIC_EOI_PHYS, &ISR_LAPIC_EOI);
        copy_stub(ISR_LAPIC_DOORBELL_PHYS, &ISR_LAPIC_DOORBELL);
        copy_stub(ISR_CPU_FAULT_DIAG_PHYS, &ISR_CPU_FAULT_DIAG);
        copy_stub(ISR_PIC_EOI_PHYS, &ISR_PIC_EOI);
        copy_stub(ISR_SPURIOUS_PHYS, &ISR_SPURIOUS);
        copy_stub(SLEEP_HLT_PHYS, &SLEEP_HLT_CODE);
        copy_stub(ISR_TLB_SHOOTDOWN_PHYS, &ISR_TLB_SHOOTDOWN);
        copy_stub(ISR_PANIC_HALT_PHYS, &ISR_PANIC_HALT);
        copy_stub(ISR_NMI_WATCHDOG_PHYS, &ISR_NMI_WATCHDOG);
        copy_stub(LOAD_GDT_IDT_TSS_PHYS, &LOAD_GDT_IDT_TSS_CODE);
    }

    // 13. Build the 104-byte Runtime GDT at `pa_to_va(0x8400)` (`5` code/data slots + `4` per-CPU 16B TSS slots)
    //     and 4 per-CPU `Tss64` structures at `pa_to_va(0x8500 + c * 0x80)` backed by guarded `RSP0`, `IST1`, `IST2`.
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
    let isr_tlb_va = smp_rx_va(ISR_TLB_SHOOTDOWN_PHYS);
    let isr_panic_va = smp_rx_va(ISR_PANIC_HALT_PHYS);
    let isr_nmi_va = smp_rx_va(ISR_NMI_WATCHDOG_PHYS);

    // SAFETY: `RUNTIME_GDT_PHYS` (`0x8400`), `RUNTIME_TSS_BASE_PHYS` (`0x8500`), and `RUNTIME_IDT_PHYS` (`0x9000`) are mapped RAM.
    unsafe {
        let gdt_ptr = pa_to_va(RUNTIME_GDT_PHYS).cast::<u64>();
        let mut g = 0usize;
        while g < RUNTIME_GDT_ENTRIES.len() {
            core::ptr::write_volatile(gdt_ptr.add(g), RUNTIME_GDT_ENTRIES[g]);
            g += 1;
        }

        let mut cpu = 0usize;
        while cpu < MAX_SMP_CPUS {
            let (_, _, rsp0_top) = guarded_ap_stack_bounds_va(cpu);
            let (_, _, ist1_top) = guarded_ist1_bounds_va(cpu);
            let (_, _, ist2_top) = guarded_ist2_bounds_va(cpu);
            let mut tss = Tss64::with_stacks(rsp0_top - 16, ist1_top - 16);
            tss.ist[1] = ist2_top - 16;
            let tss_bytes = tss.to_bytes();
            let tss_phys = RUNTIME_TSS_BASE_PHYS + (cpu as u64) * 0x80;
            let tss_dst = pa_to_va(tss_phys);
            let mut tb = 0usize;
            while tb < tss_bytes.len() {
                core::ptr::write_volatile(tss_dst.add(tb), tss_bytes[tb]);
                tb += 1;
            }
            let desc = encode_tss64_descriptor(tss_dst as u64);
            let desc_dst = pa_to_va(RUNTIME_GDT_PHYS + 0x28 + (cpu as u64) * 0x10);
            let mut db = 0usize;
            while db < 16 {
                core::ptr::write_volatile(desc_dst.add(db), desc[db]);
                db += 1;
            }
            cpu += 1;
        }

        let idt_ptr = pa_to_va(RUNTIME_IDT_PHYS);
        let mut v = 0usize;
        while v < 256 {
            let (handler, ist) = if v == 2 {
                (isr_nmi_va, 2u8)
            } else if v == 3 {
                (isr_spurious_va, 0u8)
            } else if v == 8 {
                (isr_fault_diag_va, 1u8)
            } else if v == 18 {
                (isr_fault_diag_va, 2u8)
            } else if v < 0x20 {
                (isr_fault_diag_va, 0u8)
            } else if v == 0xFF {
                (isr_spurious_va, 0u8)
            } else if v < 0x30 {
                (isr_pic_va, 0u8)
            } else if v == (LAPIC_TIMER_VECTOR as usize) {
                (isr_lapic_va, 0u8)
            } else if v == (SMP_TLB_SHOOTDOWN_VECTOR as usize) {
                (isr_tlb_va, 0u8)
            } else if v == (SMP_PANIC_HALT_VECTOR as usize) {
                (isr_panic_va, 0u8)
            } else {
                (isr_doorbell_va, 0u8)
            };
            write_idt_gate_ist(idt_ptr, v, handler, ist);
            v += 1;
        }

        // Write 10-byte `GDTR` (`0x8280`, limit = `104 - 1 = 103`) and `IDTR` (`0x8290`).
        let gdtr_ptr = pa_to_va(RUNTIME_GDTR_PHYS);
        let gdt_lim = 103u16.to_le_bytes();
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

        // Load `RUNTIME_GDTR` (`CS=0x08, SS=0x10`), `RUNTIME_IDTR`, and CPU 0 TSS (`0x28`) on the BSP.
        invoke_load_runtime_gdt_idt_tss(0);
    }
}

/// Initialize the 4 guarded hardware kernel thread stacks (`guarded_kthread_stack_bounds_va(0..4)`)
/// and install the 27-byte `cuttle_switch_context` routine at `pa_to_va(0x8200)`.
// SAFETY: Caller must execute at CPL=0 after `map_smp_rx_trampoline_page` mapped `SMP_GUARDED_STACKS_VA`.
unsafe fn init_kthread_stacks() {
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
        let (_, base, _) = guarded_kthread_stack_bounds_va(tid);
        let words_ptr = base as *mut u64;
        // Write initial context frame directly through the guarded `RW+NX` stack virtual mapping:
        //   [2047] (`top - 8`):  0 (alignment pad so `%rsp % 16 == 8` at `kthread_worker_entry`)
        //   [2046] (`top - 16`): `kthread_worker_entry` return RIP
        //   [2040..2046] (`top - 64 .. top - 16`): initial `[r15, r14, r13, r12, rbx, rbp]` = 0
        // SAFETY: `base .. base + 16384` is mapped `Supervisor RW + NX` with 4 KiB guard pages on both sides.
        unsafe {
            core::ptr::write_volatile(words_ptr.add(STACK_WORDS - 1), 0);
            core::ptr::write_volatile(words_ptr.add(STACK_WORDS - 2), entry_va);
            let mut reg_slot = STACK_WORDS - 8;
            while reg_slot < STACK_WORDS - 2 {
                core::ptr::write_volatile(words_ptr.add(reg_slot), 0);
                reg_slot += 1;
            }
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

/// Read `len` bytes from guest-physical firmware memory (`phys .. phys + len`) into `out[..len]`
/// across 4 KiB page boundaries via `ensure_phys_ro_page`.
// SAFETY: Caller must pass a firmware/ROM physical range in Ring-0 after `set_phys_offset`.
unsafe fn read_firmware_phys_bytes(phys: u64, out: &mut [u8]) -> bool {
    let mut i = 0usize;
    let mut cur_page = u64::MAX;
    let mut page_ptr: *const u8 = core::ptr::null();
    while i < out.len() {
        let p = phys.wrapping_add(i as u64);
        let pg = p & !0xFFFu64;
        if pg != cur_page {
            // SAFETY: Mapping firmware page as `Read-Only + NX` if not already in `PHYS_MAP_OFFSET`.
            page_ptr = unsafe { ensure_phys_ro_page(pg) };
            if page_ptr.is_null() {
                return false;
            }
            cur_page = pg;
        }
        // SAFETY: `page_ptr` points to mapped 4 KiB page `pg` and `(p & 0xFFF) < 4096`.
        out[i] = unsafe { core::ptr::read_volatile(page_ptr.add((p & 0xFFF) as usize)) };
        i += 1;
    }
    true
}

/// Discover firmware ACPI `RSDP` (`BOOT_RSDP_PHYS` or BIOS EBDA/`0xE0000..0x100000`), walk
/// `XSDT`/`RSDT` with full checksum verification, and populate `EXPECTED_APIC_IDS` (`MADT`),
/// `ACPI_HPET_PHYS` (`HPET`), and `ACPI_DMAR_FOUND` (`DMAR`).
#[inline(never)]
// SAFETY: Caller must execute in Ring-0 after `set_phys_offset` initialized `PHYS_MAP_OFFSET`.
unsafe fn discover_firmware_acpi_tables(bsp_apic_id: u32) {
    use target_enterprise::acpi_rsdp::{
        extract_sdt_table_addrs, parse_rsdp_any, parse_sdt_header, scan_bios_rsdp_offset,
        ACPI_SDT_HDR_LEN, RSDP_V2_LEN,
    };
    use target_enterprise::smp::resolve_ap_apic_targets;

    let mut found_rsdp = None;
    let boot_rsdp = BOOT_RSDP_PHYS.load(Ordering::Relaxed);
    if boot_rsdp != 0 {
        let mut buf = [0u8; RSDP_V2_LEN];
        // SAFETY: Probing bootloader-supplied RSDP physical address.
        if unsafe { read_firmware_phys_bytes(boot_rsdp, &mut buf) } {
            found_rsdp = parse_rsdp_any(&buf).ok();
        }
    }
    if found_rsdp.is_none() {
        // 1. Scan 1 KiB BIOS EBDA (`*(0x040E) << 4`) if inside conventional low RAM.
        let mut bda = [0u8; 2];
        // SAFETY: `0x040E` is the standard IBM-PC BIOS Data Area EBDA segment word in low RAM.
        if unsafe { read_firmware_phys_bytes(0x040E, &mut bda) } {
            let ebda_phys = (u16::from_le_bytes(bda) as u64) << 4;
            if (0x80000..0xA0000).contains(&ebda_phys) {
                let mut ebda_buf = [0u8; 1024];
                // SAFETY: Reading 1 KiB BIOS EBDA window in low RAM.
                if unsafe { read_firmware_phys_bytes(ebda_phys, &mut ebda_buf) } {
                    if let Some(off) = scan_bios_rsdp_offset(&ebda_buf) {
                        found_rsdp = parse_rsdp_any(&ebda_buf[off..]).ok();
                    }
                }
            }
        }
    }
    if found_rsdp.is_none() {
        // 2. Scan BIOS ROM `0xE0000..0x100000` in 4 KiB chunks on 16-byte boundaries.
        let mut rom_page = 0xE0000u64;
        let mut page_buf = [0u8; 4096];
        while rom_page < 0x100000 {
            // SAFETY: Reading 4 KiB BIOS ROM frame via `ensure_phys_ro_page`.
            if unsafe { read_firmware_phys_bytes(rom_page, &mut page_buf) } {
                if let Some(off) = scan_bios_rsdp_offset(&page_buf) {
                    found_rsdp = parse_rsdp_any(&page_buf[off..]).ok();
                    if found_rsdp.is_some() {
                        break;
                    }
                }
            }
            rom_page += 4096;
        }
    }

    let mut madt_parsed = false;
    if let Some(rsdp) = found_rsdp {
        let (root_phys, is_xsdt) = match rsdp.xsdt_addr {
            Some(xa) => (xa, true),
            None => (rsdp.rsdt_addr as u64, false),
        };
        if root_phys != 0 {
            let mut hdr_bytes = [0u8; ACPI_SDT_HDR_LEN];
            // SAFETY: Reading 36-byte RSDT/XSDT header from firmware physical address.
            if unsafe { read_firmware_phys_bytes(root_phys, &mut hdr_bytes) } {
                if let Ok(hdr) = parse_sdt_header(&hdr_bytes, false) {
                    let len = hdr.length as usize;
                    if (ACPI_SDT_HDR_LEN..=4096).contains(&len) {
                        let mut root_buf = [0u8; 4096];
                        // SAFETY: Reading bounded RSDT/XSDT body (`<= 4096` bytes).
                        if unsafe { read_firmware_phys_bytes(root_phys, &mut root_buf[..len]) } {
                            let mut addrs = [0u64; 32];
                            if let Ok(cnt) =
                                extract_sdt_table_addrs(&root_buf[..len], is_xsdt, &mut addrs)
                            {
                                let mut ti = 0usize;
                                while ti < cnt {
                                    let t_phys = addrs[ti];
                                    let mut th_b = [0u8; ACPI_SDT_HDR_LEN];
                                    // SAFETY: Reading 36-byte child SDT header.
                                    if t_phys != 0
                                        && unsafe { read_firmware_phys_bytes(t_phys, &mut th_b) }
                                    {
                                        if let Ok(th) = parse_sdt_header(&th_b, false) {
                                            let t_len = th.length as usize;
                                            if (ACPI_SDT_HDR_LEN..=4096).contains(&t_len) {
                                                let mut t_buf = [0u8; 4096];
                                                // SAFETY: Reading bounded child ACPI table (`<= 4096` bytes).
                                                if unsafe {
                                                    read_firmware_phys_bytes(
                                                        t_phys,
                                                        &mut t_buf[..t_len],
                                                    )
                                                } && parse_sdt_header(&t_buf[..t_len], true)
                                                    .is_ok()
                                                {
                                                    if &th.signature == b"APIC" {
                                                        let (targets, _count) =
                                                            resolve_ap_apic_targets::<MAX_SMP_CPUS>(
                                                                Some(&t_buf[..t_len]),
                                                                bsp_apic_id,
                                                            );
                                                        let mut s = 0usize;
                                                        while s < MAX_SMP_CPUS {
                                                            EXPECTED_APIC_IDS[s]
                                                                .store(targets[s], Ordering::Release);
                                                            s += 1;
                                                        }
                                                        ACPI_MADT_FOUND
                                                            .store(true, Ordering::Release);
                                                        madt_parsed = true;
                                                    } else if &th.signature == b"HPET"
                                                        && t_len >= 52
                                                    {
                                                        let hpet_pa = u64::from_le_bytes([
                                                            t_buf[44], t_buf[45], t_buf[46],
                                                            t_buf[47], t_buf[48], t_buf[49],
                                                            t_buf[50], t_buf[51],
                                                        ]);
                                                        if hpet_pa != 0
                                                            && hpet_pa < 0x0001_0000_0000_0000
                                                        {
                                                            ACPI_HPET_PHYS
                                                                .store(hpet_pa, Ordering::Release);
                                                        }
                                                    } else if &th.signature == b"DMAR" {
                                                        ACPI_DMAR_FOUND
                                                            .store(true, Ordering::Release);
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    ti += 1;
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    if !madt_parsed {
        let (targets, _) = resolve_ap_apic_targets::<MAX_SMP_CPUS>(None, bsp_apic_id);
        let mut s = 0usize;
        while s < MAX_SMP_CPUS {
            EXPECTED_APIC_IDS[s].store(targets[s], Ordering::Release);
            s += 1;
        }
    }
}

/// Calibrate the BSP (`CPU 0`) Local APIC Timer against firmware HPET (`ACPI_HPET_PHYS`, when
/// present and ticking) with automatic fallback to the 8254 PIT (`1,193,182 Hz`, Channel 2)
/// over a `10 ms` window, then arm the Periodic Timer on vector `0x40`.
pub(crate) fn smp_hw_enable_bsp_timer() {
    use cuttle_contracts::{
        HPET_CFG_ENABLE, HPET_REG_CAP, HPET_REG_CONFIG, HPET_REG_MAIN_COUNTER,
    };
    use target_enterprise::timer::{
        calibrate_apic_irqs_per_sec, LAPIC_TIMER_PERIOD_COUNT, PIT_CALIBRATION_TICKS_10MS,
    };

    if !SMP_HW_INITIALIZED.load(Ordering::Acquire) {
        let _ = smp_hw_init();
    }
    // SAFETY: `LAPIC_PHYS_BASE` is mapped, `RUNTIME_IDT` has `ISR_LAPIC_EOI` installed at vector `0x40`,
    // and HPET MMIO / PIT Channel 2 registers are accessed at CPL=0.
    unsafe {
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TPR, 0);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TIMER_DIV, 0x03); // Divide by 16

        let mut calibrated_hz: Option<u64> = None;
        let hpet_pa = ACPI_HPET_PHYS.load(Ordering::Acquire);
        if hpet_pa != 0 {
            let _ = ensure_mmio_page(hpet_pa);
            let gcap = mmio_read64(hpet_pa + (HPET_REG_CAP as u64));
            let period_fs = gcap >> 32;
            // IA-PC HPET Spec §2.3.4: `COUNTER_CLK_PERIOD` must be non-zero and `<= 0x05F5_E100` (`100_000_000 fs`).
            if period_fs > 0 && period_fs <= 100_000_000 {
                let target_ticks = (10_000_000_000_000u64 / period_fs).max(64);
                let conf = mmio_read64(hpet_pa + (HPET_REG_CONFIG as u64));
                mmio_write64(hpet_pa + (HPET_REG_CONFIG as u64), conf | (HPET_CFG_ENABLE as u64));
                let start_cnt = mmio_read64(hpet_pa + (HPET_REG_MAIN_COUNTER as u64));
                mmio_write32(
                    LAPIC_PHYS_BASE + LAPIC_LVT_TIMER,
                    0x0001_0000 | LAPIC_TIMER_VECTOR,
                );
                mmio_write32(LAPIC_PHYS_BASE + LAPIC_TIMER_INIT, 0xFFFF_FFFF);
                let mut spins = 0u32;
                while mmio_read64(hpet_pa + (HPET_REG_MAIN_COUNTER as u64))
                    .wrapping_sub(start_cnt)
                    < target_ticks
                    && spins < 500_000
                {
                    core::hint::spin_loop();
                    spins += 1;
                }
                let elapsed_hpet = mmio_read64(hpet_pa + (HPET_REG_MAIN_COUNTER as u64))
                    .wrapping_sub(start_cnt);
                if elapsed_hpet >= target_ticks / 2 {
                    let ccr = mmio_read32(LAPIC_PHYS_BASE + LAPIC_TIMER_CCR);
                    let lapic_elapsed = 0xFFFF_FFFFu32.saturating_sub(ccr) as u64;
                    if lapic_elapsed > 0 {
                        let hz = ((lapic_elapsed.saturating_mul(100))
                            / (LAPIC_TIMER_PERIOD_COUNT as u64))
                            .clamp(16, 100_000);
                        calibrated_hz = Some(hz);
                    }
                }
            }
        }

        let irqs_per_sec = match calibrated_hz {
            Some(hz) => hz,
            None => {
                // Fallback: 8254 PIT Channel 2 (`1,193,182 Hz`) `10 ms` terminal count.
                let gate = inb(0x61);
                outb(0x61, (gate & 0xFC) | 0x01);
                outb(0x43, 0xB0);
                outb(0x42, (PIT_CALIBRATION_TICKS_10MS & 0xFF) as u8);
                outb(0x42, (PIT_CALIBRATION_TICKS_10MS >> 8) as u8);
                mmio_write32(
                    LAPIC_PHYS_BASE + LAPIC_LVT_TIMER,
                    0x0001_0000 | LAPIC_TIMER_VECTOR,
                );
                mmio_write32(LAPIC_PHYS_BASE + LAPIC_TIMER_INIT, 0xFFFF_FFFF);
                let mut spins = 0u32;
                while (inb(0x61) & 0x20) == 0 && spins < 200_000 {
                    core::hint::spin_loop();
                    spins += 1;
                }
                let ccr = mmio_read32(LAPIC_PHYS_BASE + LAPIC_TIMER_CCR);
                let lapic_elapsed = 0xFFFF_FFFFu32.saturating_sub(ccr);
                calibrate_apic_irqs_per_sec(
                    lapic_elapsed,
                    PIT_CALIBRATION_TICKS_10MS as u32,
                    LAPIC_TIMER_PERIOD_COUNT,
                )
            }
        };
        CALIBRATED_IRQS_PER_COOLDOWN_TICK.store(irqs_per_sec, Ordering::Relaxed);

        // Arm Periodic Local APIC Timer on vector `0x40` with `LAPIC_TIMER_PERIOD_COUNT` (`250,000`).
        mmio_write32(
            LAPIC_PHYS_BASE + LAPIC_LVT_TIMER,
            0x0002_0000 | LAPIC_TIMER_VECTOR,
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

    // 1. Enable hardware `NXE + WP + SMEP + SMAP + UMIP + FSGSBASE` on the BSP (so APs inherit
    //    identical protections via `read_bsp_control_regs()`), map the dedicated 4 KiB Supervisor `RX`
    //    trampoline alias + `PD[1]` guarded stacks, initialize Runtime GDT/TSS/IDT/ISRs, and initialize
    //    the 4 guarded hardware kernel thread stacks.
    // SAFETY: Running at CPL=0 after `set_phys_offset` initialized the physical memory map.
    unsafe {
        let bsp_sec = crate::banners_arch_platform::enable_cpu_memory_protections();
        HW_AP_SEC_BITS[0].store(bsp_sec, Ordering::Release);
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
    let bsp_apic_id = unsafe {
        let id = mmio_read32(LAPIC_PHYS_BASE + LAPIC_ID) >> 24;
        HW_APIC_IDS[0].store(id, Ordering::Release);
        let svr = mmio_read32(LAPIC_PHYS_BASE + LAPIC_SVR);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_SVR, svr | 0x1FF);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_TPR, 0);
        mmio_write32(LAPIC_PHYS_BASE + LAPIC_ESR, 0);
        discover_firmware_acpi_tables(id);
        id
    };

    let mut cpu_id = 1usize;
    while cpu_id < MAX_SMP_CPUS {
        let exp_apic = EXPECTED_APIC_IDS[cpu_id].load(Ordering::Acquire);
        let target_apic_id = if exp_apic != u32::MAX && exp_apic <= 0xFF && exp_apic != bsp_apic_id {
            exp_apic
        } else {
            break;
        };
        let (_, _, ap_top_va) = guarded_ap_stack_bounds_va(cpu_id);
        let stack_top = ap_top_va - 16;
        // SAFETY: Offsets `0x110` and `0x118` are 8-byte-aligned mailbox slots inside `0x8000..0x9000`.
        unsafe {
            core::ptr::write_volatile(tramp_va.add(0x110).cast::<u64>(), stack_top);
            core::ptr::write_volatile(tramp_va.add(0x118).cast::<u64>(), cpu_id as u64);
        }
        core::sync::atomic::fence(Ordering::SeqCst);

        // Send INIT IPI (`0x0000_4500`) to `target_apic_id` (never self-targeting `bsp_apic_id`).
        // SAFETY: Polling `ICR_LO` idle then writing `ICR_HI` + `ICR_LO` dispatches an IPI to `target_apic_id`.
        unsafe {
            wait_lapic_icr_idle();
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, target_apic_id << 24);
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4500);
            wait_lapic_icr_idle();
        }
        let mut d = 0u32;
        while d < 10_000 {
            core::hint::spin_loop();
            d += 1;
        }

        // Send SIPI IPI (`0x0000_4608`, vector `0x08` -> physical `0x8000`).
        // SAFETY: Polling `ICR_LO` idle then writing `ICR_HI` + `ICR_LO` sends a Startup IPI to `target_apic_id`.
        unsafe {
            wait_lapic_icr_idle();
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, target_apic_id << 24);
            mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_LO, 0x0000_4608);
            wait_lapic_icr_idle();
        }

        let mut spins = 0u32;
        while !AP_BOOT_READY[cpu_id].load(Ordering::Acquire) && spins < 400_000 {
            if spins == 80_000 {
                // Second SIPI per Intel MP specification if first did not latch yet.
                // SAFETY: Re-sending Startup IPI with vector `0x08` to `target_apic_id` before AP ready flag is set.
                unsafe {
                    wait_lapic_icr_idle();
                    mmio_write32(LAPIC_PHYS_BASE + LAPIC_ICR_HI, target_apic_id << 24);
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
            let mut live_ticks = [0u64; MAX_SMP_CPUS];
            let mut wc = 0usize;
            while wc < MAX_SMP_CPUS {
                live_ticks[wc] = HW_CPU_TICKS[wc].load(Ordering::Relaxed);
                wc += 1;
            }
            if let Some(mut wd) = SMP_WATCHDOG.try_lock() {
                let stalled = wd.check_stalled_mask(online, &live_ticks);
                if stalled != 0 {
                    ring_smp_doorbell();
                }
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

/// Self-verify Intel VT-d (`vtd_hw`) Root Table -> Bus-0 Context Table -> 4-level SLPT
/// hardware DMA confinement for PCI `00:01.0` (`VirtIO`) and `00:02.0` (`AHCI`).
#[cfg(not(cuttle_prod))]
#[inline(never)]
fn verify_vtd_slpt_confinement_live() {
    use alloc::boxed::Box;
    use cuttle_contracts::{AccessKind, IommuError, PagePerms};
    use target_enterprise::iommu::vtd_hw::{
        build_confined_slpt_4level, encode_context_entry, encode_root_entry, verify_vtd_dma_access,
    };
    use target_enterprise::iommu::DeviceId;
    use target_enterprise::memory::dma_layout::{AHCI_REGION, VIRTIO_REGION};

    struct VtdScratch {
        root: [u8; 4096],
        ctx: [u8; 4096],
        v_pml4: [u64; 512],
        v_pdpt: [u64; 512],
        v_pd: [u64; 512],
        v_pt: [u64; 512],
        a_pml4: [u64; 512],
        a_pdpt: [u64; 512],
        a_pd: [u64; 512],
        a_pt: [u64; 512],
    }

    let mut s = Box::new(VtdScratch {
        root: [0u8; 4096],
        ctx: [0u8; 4096],
        v_pml4: [0u64; 512],
        v_pdpt: [0u64; 512],
        v_pd: [0u64; 512],
        v_pt: [0u64; 512],
        a_pml4: [0u64; 512],
        a_pdpt: [0u64; 512],
        a_pd: [0u64; 512],
        a_pt: [0u64; 512],
    });

    let raw_dma = dma_phys_base();
    let (v_start, v_end) = VIRTIO_REGION;
    let (a_start, a_end) = AHCI_REGION;
    let v_len = v_end - v_start;
    let a_len = a_end - a_start;
    let base_2m = if ((raw_dma + v_start) >> 21) == ((raw_dma + a_end - 1) >> 21) {
        raw_dma
    } else {
        0x20_0000
    };
    let virtio_pa = base_2m + v_start;
    let ahci_pa = base_2m + a_start;

    let ctx_pa: u64 = 0x40_1000;
    let v_pml4_pa: u64 = 0x40_2000;
    let v_pdpt_pa: u64 = 0x40_3000;
    let v_pd_pa: u64 = 0x40_4000;
    let v_pt_pa: u64 = 0x40_5000;
    let a_pml4_pa: u64 = 0x40_6000;
    let a_pdpt_pa: u64 = 0x40_7000;
    let a_pd_pa: u64 = 0x40_8000;
    let a_pt_pa: u64 = 0x40_9000;

    let root_ent = encode_root_entry(ctx_pa).expect("VTD: root entry");
    s.root[0..16].copy_from_slice(&root_ent);

    let dev_virtio = DeviceId::from_bdf(0, 0, 1, 0);
    let dev_ahci = DeviceId::from_bdf(0, 0, 2, 0);
    let _ = dev_ahci;
    let v_ctx = encode_context_entry(v_pml4_pa, 1).expect("VTD: virtio ctx");
    let a_ctx = encode_context_entry(a_pml4_pa, 2).expect("VTD: ahci ctx");
    s.ctx[8 * 16..8 * 16 + 16].copy_from_slice(&v_ctx);
    s.ctx[16 * 16..16 * 16 + 16].copy_from_slice(&a_ctx);

    let rw = PagePerms(PagePerms::READ.0 | PagePerms::WRITE.0);
    build_confined_slpt_4level(
        &mut s.v_pml4,
        &mut s.v_pdpt,
        &mut s.v_pd,
        &mut s.v_pt,
        v_pdpt_pa,
        v_pd_pa,
        v_pt_pa,
        virtio_pa,
        v_len,
        rw,
    )
    .expect("VTD: virtio slpt");
    build_confined_slpt_4level(
        &mut s.a_pml4,
        &mut s.a_pdpt,
        &mut s.a_pd,
        &mut s.a_pt,
        a_pdpt_pa,
        a_pd_pa,
        a_pt_pa,
        ahci_pa,
        a_len,
        rw,
    )
    .expect("VTD: ahci slpt");

    // 1. In-aperture DMA succeeds for each PCI BDF.
    let ok_v = verify_vtd_dma_access(
        &s.root,
        &s.ctx,
        ctx_pa,
        v_pml4_pa,
        &s.v_pml4,
        &s.v_pdpt,
        &s.v_pd,
        &s.v_pt,
        v_pdpt_pa,
        v_pd_pa,
        v_pt_pa,
        dev_virtio,
        virtio_pa + 0x180,
        AccessKind::Write,
    );
    if ok_v != Ok(virtio_pa + 0x180) {
        panic!("OS_ARMOR: VT-d VirtIO in-window DMA failed");
    }
    // 2. Cross-device DMA (`VirtIO` attempting to write into `AHCI_REGION`) MUST fail closed!
    let cross = verify_vtd_dma_access(
        &s.root,
        &s.ctx,
        ctx_pa,
        v_pml4_pa,
        &s.v_pml4,
        &s.v_pdpt,
        &s.v_pd,
        &s.v_pt,
        v_pdpt_pa,
        v_pd_pa,
        v_pt_pa,
        dev_virtio,
        ahci_pa,
        AccessKind::Write,
    );
    if cross != Err(IommuError::Unmapped) {
        panic!("OS_ARMOR: VT-d failed to block cross-device DMA into AHCI window");
    }
}

/// Boot self-proof banner for hardware SMP AP bringup, strict `W^X` RX trampoline,
/// hardware guard pages on all 16 stacks, per-CPU `Tss64` (`ltr`), cross-CPU TLB shootdown,
/// firmware ACPI MADT topology, and Intel VT-d SLPT confinement.
#[inline(never)]
pub(crate) fn banner_smp_hw() {
    use crate::banners_arch_platform::{CPU_SEC_NXE, CPU_SEC_WP};

    let online = smp_hw_init();

    // 1. Verify strict `W^X` across RX trampoline, `PHYS_MAP_OFFSET`, and `LAPIC` MMIO leaf (`PTE_NX` enforced!).
    // SAFETY: Running at CPL=0 after `smp_hw_init` mapped `SMP_RX_TRAMPOLINE_VA`, `SMP_GUARDED_STACKS_VA`, and `LAPIC_PHYS_BASE`.
    unsafe {
        let (rx_p, rx_w, rx_x) = walk_va_effective_wx(smp_rx_va(SWITCH_CONTEXT_VA));
        if !rx_p || rx_w || !rx_x {
            panic!("SMP_HW: RX trampoline violated W^X (expected RX, non-writable)");
        }
        let (dm_p, dm_w, dm_x) = walk_va_effective_wx(pa_to_va(SWITCH_CONTEXT_VA) as u64);
        if !dm_p || (dm_w && dm_x) {
            panic!("SMP_HW: PHYS_MAP_OFFSET violated W^X (unexpected RWX mapping)");
        }
        let (mmio_p, mmio_w, mmio_x) = walk_va_effective_wx(pa_to_va(LAPIC_PHYS_BASE) as u64);
        if !mmio_p || !mmio_w || mmio_x {
            panic!("OS_ARMOR: LAPIC MMIO leaf violated PTE_NX (executable MMIO forbidden)");
        }

        // 2. Verify all 16 hardware stacks (`4 AP + 4 KTHREAD + 4 IST1 + 4 IST2`) have unmapped (`!present`)
        //    bottom & top 4 KiB guard pages and `RW+NX` interior pages in live `CR3`.
        let mut s = 0usize;
        while s < MAX_SMP_CPUS {
            let (glo, base, top) = guarded_ap_stack_bounds_va(s);
            let (gp_lo, _, _) = walk_va_effective_wx(glo);
            let (gp_hi, _, _) = walk_va_effective_wx(top);
            let (sp, sw, sx) = walk_va_effective_wx(base);
            if gp_lo || gp_hi || !sp || !sw || sx {
                panic!("OS_ARMOR: AP guarded stack page-table invariant violated");
            }
            let (ig1_lo, ib1, it1) = guarded_ist1_bounds_va(s);
            let (ig2_lo, ib2, it2) = guarded_ist2_bounds_va(s);
            let (p1_lo, _, _) = walk_va_effective_wx(ig1_lo);
            let (p1_hi, _, _) = walk_va_effective_wx(it1);
            let (p1_in, w1_in, x1_in) = walk_va_effective_wx(ib1);
            let (p2_lo, _, _) = walk_va_effective_wx(ig2_lo);
            let (p2_hi, _, _) = walk_va_effective_wx(it2);
            let (p2_in, w2_in, x2_in) = walk_va_effective_wx(ib2);
            if p1_lo || p1_hi || !p1_in || !w1_in || x1_in || p2_lo || p2_hi || !p2_in || !w2_in || x2_in {
                panic!("OS_ARMOR: IST1/IST2 guarded stack page-table invariant violated");
            }
            s += 1;
        }
        let mut kt = 0usize;
        while kt < NUM_KTHREADS {
            let (glo, base, top) = guarded_kthread_stack_bounds_va(kt);
            let (gp_lo, _, _) = walk_va_effective_wx(glo);
            let (gp_hi, _, _) = walk_va_effective_wx(top);
            let (sp, sw, sx) = walk_va_effective_wx(base);
            if gp_lo || gp_hi || !sp || !sw || sx {
                panic!("OS_ARMOR: KTHREAD guarded stack page-table invariant violated");
            }
            kt += 1;
        }
    }

    // 3. Verify online CPUs observed expected distinct hardware Local APIC IDs, distinct per-CPU `TR` (`ltr`),
    //    and active hardware security controls (`NXE | WP`, matching BSP feature mask).
    let bsp_sec = HW_AP_SEC_BITS[0].load(Ordering::Acquire);
    if (bsp_sec & (CPU_SEC_NXE | CPU_SEC_WP)) != (CPU_SEC_NXE | CPU_SEC_WP)
        || crate::banners_arch_platform::read_active_cpu_sec_bits() != bsp_sec
    {
        panic!("OS_ARMOR: BSP missing NXE or WP protection");
    }
    let mut cpu_i = 0usize;
    while cpu_i < online {
        let obs_apic = HW_APIC_IDS[cpu_i].load(Ordering::Acquire);
        let exp_apic = EXPECTED_APIC_IDS[cpu_i].load(Ordering::Acquire);
        if cpu_i > 0 && obs_apic != exp_apic {
            panic!("SMP_HW: AP hardware Local APIC ID mismatch against MADT/target");
        }
        let mut prev = 0usize;
        while prev < cpu_i {
            if HW_APIC_IDS[prev].load(Ordering::Acquire) == obs_apic {
                panic!("SMP_HW: duplicate Local APIC ID across online cores");
            }
            prev += 1;
        }
        let obs_tr = HW_CPU_TR_SEL[cpu_i].load(Ordering::Acquire);
        if obs_tr != cpu_tss_selector(cpu_i) {
            panic!("OS_ARMOR: CPU failed to load dedicated per-CPU 64-bit TSS selector");
        }
        let ap_sec = HW_AP_SEC_BITS[cpu_i].load(Ordering::Acquire);
        if ap_sec != bsp_sec {
            panic!("OS_ARMOR: AP CPU security bits diverged from BSP");
        }
        cpu_i += 1;
    }

    // 4. Execute one full round of hardware stack context switches across all 4 guarded kernel threads.
    let mut i = 0usize;
    while i < NUM_KTHREADS {
        let tid = kthread_switch_next();
        let obs_rsp = KTHREAD_OBSERVED_RSP[tid].load(Ordering::Acquire);
        let (_, base, top) = guarded_kthread_stack_bounds_va(tid);
        if obs_rsp <= base || obs_rsp > top {
            panic!("SMP_HW: thread RSP outside dedicated guarded hardware stack");
        }
        i += 1;
    }

    // 5. Wake sleeping AP cores via Doorbell IPI (`vector 0x41`) and verify parallel job execution.
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

    // 6. Exercise Cross-CPU TLB Shootdown IPI (`vector 0x42`) and verify peer AP acknowledgements.
    let acks_before = HW_TLB_SHOOTDOWN_ACKS.load(Ordering::Acquire);
    smp_broadcast_tlb_shootdown();
    let acks_delta = HW_TLB_SHOOTDOWN_ACKS
        .load(Ordering::Acquire)
        .saturating_sub(acks_before);
    if online > 1 && acks_delta < (online - 1) as u64 {
        panic!("OS_ARMOR: cross-CPU TLB shootdown IPI did not receive all peer ACKs");
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
    if read_hw_irq_wakeups() != 0 {
        panic!("SMP_HW: Doorbell/TLB IPI incremented timer IRQ counter");
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

    #[cfg(not(cuttle_prod))]
    {
        verify_vtd_slpt_confinement_live();
        let madt_flag: u64 = if ACPI_MADT_FOUND.load(Ordering::Acquire) {
            1
        } else {
            0
        };
        let total_acks = HW_TLB_SHOOTDOWN_ACKS.load(Ordering::Acquire);
        let mut armor = [0u8; 128];
        let mut apos = 0usize;
        let a0 = b"OS_ARMOR OK mmio_nx=1 guarded_stacks=16 tss_ltr=";
        armor[apos..apos + a0.len()].copy_from_slice(a0);
        apos += a0.len();
        apos += dec_u64(online as u64, &mut armor[apos..]);
        let a1 = b" cpu_sec=0x";
        armor[apos..apos + a1.len()].copy_from_slice(a1);
        apos += a1.len();
        let mut sec_hex = [0u8; 8];
        hex_u32(bsp_sec, &mut sec_hex);
        armor[apos..apos + 8].copy_from_slice(&sec_hex);
        apos += 8;
        let a2 = b" acpi_madt=";
        armor[apos..apos + a2.len()].copy_from_slice(a2);
        apos += a2.len();
        apos += dec_u64(madt_flag, &mut armor[apos..]);
        let a3 = b" tlb_ipi=";
        armor[apos..apos + a3.len()].copy_from_slice(a3);
        apos += a3.len();
        apos += dec_u64(total_acks, &mut armor[apos..]);
        let a4 = b" vtd_slpt=ok\n";
        armor[apos..apos + a4.len()].copy_from_slice(a4);
        apos += a4.len();
        serial_write_bytes(&armor[..apos]);
    }
}
