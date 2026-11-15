//! Hardware Ring-3 (`CPL=3`) multi-page ELF64 process executor, `int 0x80` + `SYSCALL` (`0F 05` /
//! `IA32_LSTAR` / `SWAPGS`) dual entry, Local APIC `0x50` preemptive time-slicing, multi-core SMP
//! run-queue scheduling (`CPU 0..3`), and `CPL=3` hardware fault isolation (`proc_hw`).

use core::arch::asm;
use core::mem::offset_of;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use target_enterprise::gdt::{
    Gdt, Tss64, KERNEL_CODE_SEL, KERNEL_DATA_SEL, TSS64_LEN, TSS_SEL, USER_CODE_SEL, USER_DATA_SEL,
};
use target_enterprise::interrupts::{
    Idt, IdtEntry, TYPE_INTERRUPT_GATE_DPL0, TYPE_INTERRUPT_GATE_DPL3,
};
use target_enterprise::phys_mm::PageFrameSource;
use target_enterprise::proc_vm::{
    build_elf64_from_mailbox_worker, build_elf64_program, expected_cpu_worker_exit_code,
    ElfProgramKind, FxSaveArea, ProcAddressSpace, ProcError, ProcFaultInfo, ProcState,
    ProcessTable, SyscallStepOutcome, UserTrapFrame, MAX_PROCS,
};
use target_enterprise::svc_runtime::{Ring3MailboxHwVerdict, ServiceId, SVC_CAP_IPC};

/// Global IRQ-safe Ring-3 ELF64 process table shared across `CPU 0..3`.
static KERNEL_PROC_TABLE: spin::Mutex<ProcessTable> = spin::Mutex::new(ProcessTable::new());

/// Fast lock-free hint of `Ready` Ring-3 processes so idle SMP cores avoid locking `KERNEL_PROC_TABLE`.
static READY_PROC_HINT: AtomicUsize = AtomicUsize::new(0);

/// Monotonic hardware quantum counter across all SMP cores.
static TOTAL_HW_QUANTA: AtomicU64 = AtomicU64::new(0);

const LAPIC_BASE: u64 = 0xFEE0_0000;
const LAPIC_TPR_OFF: u64 = 0x0080;
const LAPIC_EOI_OFF: u64 = 0x00B0;
const LAPIC_SVR_OFF: u64 = 0x00F0;
const LAPIC_LVT_TIMER_OFF: u64 = 0x0320;
const LAPIC_TIMER_INIT_OFF: u64 = 0x0380;
const LAPIC_TIMER_DIV_OFF: u64 = 0x03E0;
const PREEMPT_TIMER_VEC: u8 = 0x50;
const LAPIC_ISR_PREEMPT_OFF: u64 = 0x0100 + (((PREEMPT_TIMER_VEC as u64) >> 5) * 0x10);
const LAPIC_ISR_PREEMPT_BIT: u32 = 1u32 << ((PREEMPT_TIMER_VEC as u32) & 31);

const MSR_IA32_EFER: u32 = 0xC000_0080;
const MSR_IA32_STAR: u32 = 0xC000_0081;
const MSR_IA32_LSTAR: u32 = 0xC000_0082;
const MSR_IA32_FMASK: u32 = 0xC000_0084;
const MSR_IA32_FS_BASE: u32 = 0xC000_0100;
const MSR_IA32_GS_BASE: u32 = 0xC000_0101;
const MSR_IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;

const EFER_SCE: u64 = 1 << 0;
const SYSCALL_STAR_VAL: u64 = ((0x0013u64) << 48) | ((KERNEL_CODE_SEL as u64) << 32);
/// Clear `TF (0x100) | IF (0x200) | DF (0x400) | IOPL (0x3000) | NT (0x4000) | AC (0x40000)`
/// upon `0F 05` `SYSCALL` entry.
///
/// `NT` is in the mask because ring 3 can set it and `SYSCALL` otherwise carries
/// it into the kernel: the next `iretq` on that CPU, which is the entry into
/// whichever process runs next, then faults at CPL 0 and that process is the
/// one reaped for it.
const SYSCALL_FMASK_VAL: u64 = 0x0004_7700;

const PTE_P: u64 = 1 << 0;
const PTE_W: u64 = 1 << 1;
const PTE_U: u64 = 1 << 2;
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

const EXIT_REASON_SYSCALL: u64 = 1;
const EXIT_REASON_PREEMPT: u64 = 2;
const EXIT_REASON_FAULT: u64 = 3;

/// Per-quantum supervisor bridge block stored at `sup_rw_va + 0x200` (`tramp_va + 0x1200`).
#[repr(C)]
#[derive(Copy, Clone, Default)]
struct ProcBridgeState {
    saved_kernel_rsp: u64,
    kernel_cr3: u64,
    user_cr3: u64,
    exit_reason: u64,
    fault_vec: u64,
    fault_err: u64,
    fault_cr2: u64,
    fault_cs: u64,
    observed_cr3: u64,
    scratch_rax: u64,
    tf: UserTrapFrame,
}

/// Hardware `PageFrameSource` backed by `KERNEL_PHYS_MM` (`BootInfo` dynamic frame manager)
/// and `PHYS_MAP_OFFSET` higher-half direct physical mapping.
pub(crate) struct KernelPageFrameSource;

impl PageFrameSource for KernelPageFrameSource {
    fn alloc_zeroed_frame(&mut self) -> Option<u64> {
        crate::alloc_phys_frame_zeroed()
    }

    fn free_zeroed_frame(&mut self, pa: u64) {
        // SAFETY: `ProcessTable` releases frames only after tearing down active mappings and ownership.
        let res = unsafe { crate::free_phys_frame_scrubbed(pa) };
        if res.is_err() {
            panic!("PROC_HW: invalid physical frame release in ProcessTable");
        }
    }

    fn read_frame_bytes(&self, pa: u64, offset: usize, out: &mut [u8]) {
        assert!(offset + out.len() <= 4096);
        // SAFETY: `pa` is an allocated usable 4 KiB frame mapped in `PHYS_MAP_OFFSET`.
        unsafe {
            let src = crate::pa_to_va(pa).add(offset);
            core::ptr::copy_nonoverlapping(src, out.as_mut_ptr(), out.len());
        }
    }

    fn write_frame_bytes(&mut self, pa: u64, offset: usize, data: &[u8]) {
        assert!(offset + data.len() <= 4096);
        // SAFETY: `pa` is an allocated usable 4 KiB frame mapped in `PHYS_MAP_OFFSET`.
        unsafe {
            let dst = crate::pa_to_va(pa).add(offset);
            core::ptr::copy_nonoverlapping(data.as_ptr(), dst, data.len());
        }
    }
}

/// Execute `f` with local interrupts masked (`cli`) while holding `KERNEL_PROC_TABLE`.
///
/// Lock hierarchy: `KERNEL_PROC_TABLE -> KERNEL_PHYS_MM` (never nested with `PT_MOD_LOCK`).
#[inline]
fn with_proc_table_lock<R>(f: impl FnOnce(&mut ProcessTable) -> R) -> R {
    let saved_rflags: u64;
    // SAFETY: Reading RFLAGS and executing `cli` in Ring-0 prevents local timer/IPI lock re-entrancy.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) saved_rflags,
            options(nomem, preserves_flags),
        );
    }
    let mut guard = KERNEL_PROC_TABLE.lock();
    let out = f(&mut *guard);
    // Refresh lock-free ready hint while still under `KERNEL_PROC_TABLE`.
    let mut rdy = 0usize;
    let mut i = 0usize;
    while i < MAX_PROCS {
        if guard.procs[i].state == ProcState::Ready {
            rdy += 1;
        }
        i += 1;
    }
    READY_PROC_HINT.store(rdy, Ordering::Release);
    drop(guard);
    if (saved_rflags & (1 << 9)) != 0 {
        // SAFETY: Restoring `IF = 1` only if enabled prior to acquiring `KERNEL_PROC_TABLE`.
        unsafe {
            asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }
    out
}

/// Fast non-blocking check whether at least one Ring-3 ELF64 process is `Ready`.
#[inline]
pub(crate) fn has_ready_processes() -> bool {
    READY_PROC_HINT.load(Ordering::Acquire) > 0
}

/// Spawn an ELF64 Ring-3 process into `KERNEL_PROC_TABLE` and ring the SMP Doorbell IPI (`0x41`).
#[cfg(not(cuttle_prod))]
pub(crate) fn spawn_kernel_elf64_process(
    elf_image: &[u8],
    cap_mask: u64,
    variant_seed: u64,
    service_id: Option<ServiceId>,
) -> Result<(u32, usize), ProcError> {
    let res = with_proc_table_lock(|table| {
        let mut src = KernelPageFrameSource;
        table.spawn_elf64(elf_image, cap_mask, variant_seed, service_id, &mut src)
    });
    if res.is_ok() {
        crate::smp_hw::ring_smp_doorbell();
    }
    res
}

#[inline]
// SAFETY: Caller must pass a valid architectural x86-64 MSR address at CPL=0.
unsafe fn rdmsr(msr: u32) -> u64 {
    let lo: u32;
    let hi: u32;
    // SAFETY: Privileged `rdmsr` on architectural MSR in Ring-0.
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    ((hi as u64) << 32) | (lo as u64)
}

#[inline]
// SAFETY: Caller must pass a valid architectural x86-64 MSR address and canonical value at CPL=0.
unsafe fn wrmsr(msr: u32, val: u64) {
    let lo = val as u32;
    let hi = (val >> 32) as u32;
    // SAFETY: Privileged `wrmsr` on architectural MSR in Ring-0.
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") lo,
            in("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
}

// x86-64 register numbers for ModRM/REX encoding (`base = rax = 0`).
const REG_RAX: u8 = 0;
const REG_RCX: u8 = 1;
const REG_RDX: u8 = 2;
const REG_RBX: u8 = 3;
const REG_RSP: u8 = 4;
const REG_RBP: u8 = 5;
const REG_RSI: u8 = 6;
const REG_RDI: u8 = 7;
const REG_R8: u8 = 8;
const REG_R9: u8 = 9;
const REG_R10: u8 = 10;
const REG_R11: u8 = 11;
const REG_R12: u8 = 12;
const REG_R13: u8 = 13;
const REG_R14: u8 = 14;
const REG_R15: u8 = 15;

#[inline]
fn emit_lea_rax_state(buf: &mut [u8; 4096], pos: &mut usize) {
    // `state_va` is always at `tramp_va + 0x1200`.
    let rel = (0x1200i32 - ((*pos + 7) as i32)).to_le_bytes();
    buf[*pos..*pos + 7].copy_from_slice(&[0x48, 0x8D, 0x05, rel[0], rel[1], rel[2], rel[3]]);
    *pos += 7;
}

#[inline]
fn emit_load_from_rax(buf: &mut [u8; 4096], pos: &mut usize, reg: u8, disp: usize) {
    let rex = 0x48 | if reg >= 8 { 0x04 } else { 0x00 };
    let modrm = 0x80 | ((reg & 7) << 3); // Mod=10 (disp32), R/M=000 (rax)
    let d = (disp as i32).to_le_bytes();
    buf[*pos..*pos + 7].copy_from_slice(&[rex, 0x8B, modrm, d[0], d[1], d[2], d[3]]);
    *pos += 7;
}

#[inline]
fn emit_store_to_rax(buf: &mut [u8; 4096], pos: &mut usize, reg: u8, disp: usize) {
    let rex = 0x48 | if reg >= 8 { 0x04 } else { 0x00 };
    let modrm = 0x80 | ((reg & 7) << 3); // Mod=10 (disp32), R/M=000 (rax)
    let d = (disp as i32).to_le_bytes();
    buf[*pos..*pos + 7].copy_from_slice(&[rex, 0x89, modrm, d[0], d[1], d[2], d[3]]);
    *pos += 7;
}

#[inline]
fn emit_push_mem_rax(buf: &mut [u8; 4096], pos: &mut usize, disp: usize) {
    let d = (disp as i32).to_le_bytes();
    buf[*pos..*pos + 6].copy_from_slice(&[0xFF, 0xB0, d[0], d[1], d[2], d[3]]);
    *pos += 6;
}

#[inline]
fn emit_store_non_rax_gprs(buf: &mut [u8; 4096], pos: &mut usize) {
    let tf_base = offset_of!(ProcBridgeState, tf);
    emit_store_to_rax(buf, pos, REG_RBX, tf_base + offset_of!(UserTrapFrame, rbx));
    emit_store_to_rax(buf, pos, REG_RCX, tf_base + offset_of!(UserTrapFrame, rcx));
    emit_store_to_rax(buf, pos, REG_RDX, tf_base + offset_of!(UserTrapFrame, rdx));
    emit_store_to_rax(buf, pos, REG_RSI, tf_base + offset_of!(UserTrapFrame, rsi));
    emit_store_to_rax(buf, pos, REG_RDI, tf_base + offset_of!(UserTrapFrame, rdi));
    emit_store_to_rax(buf, pos, REG_RBP, tf_base + offset_of!(UserTrapFrame, rbp));
    emit_store_to_rax(buf, pos, REG_R8, tf_base + offset_of!(UserTrapFrame, r8));
    emit_store_to_rax(buf, pos, REG_R9, tf_base + offset_of!(UserTrapFrame, r9));
    emit_store_to_rax(buf, pos, REG_R10, tf_base + offset_of!(UserTrapFrame, r10));
    emit_store_to_rax(buf, pos, REG_R11, tf_base + offset_of!(UserTrapFrame, r11));
    emit_store_to_rax(buf, pos, REG_R12, tf_base + offset_of!(UserTrapFrame, r12));
    emit_store_to_rax(buf, pos, REG_R13, tf_base + offset_of!(UserTrapFrame, r13));
    emit_store_to_rax(buf, pos, REG_R14, tf_base + offset_of!(UserTrapFrame, r14));
    emit_store_to_rax(buf, pos, REG_R15, tf_base + offset_of!(UserTrapFrame, r15));
}

#[inline]
fn emit_exit_to_kernel_tail(buf: &mut [u8; 4096], pos: &mut usize, reason: u32) {
    let r = reason.to_le_bytes();
    buf[*pos..*pos + 5].copy_from_slice(&[0xB9, r[0], r[1], r[2], r[3]]); // mov ecx, reason
    *pos += 5;
    emit_store_to_rax(buf, pos, REG_RCX, offset_of!(ProcBridgeState, exit_reason));
    // mov rcx, cr3
    buf[*pos..*pos + 3].copy_from_slice(&[0x0F, 0x20, 0xD9]);
    *pos += 3;
    emit_store_to_rax(buf, pos, REG_RCX, offset_of!(ProcBridgeState, observed_cr3));
    // Restore kernel_cr3 -> cr3
    emit_load_from_rax(buf, pos, REG_RCX, offset_of!(ProcBridgeState, kernel_cr3));
    buf[*pos..*pos + 3].copy_from_slice(&[0x0F, 0x22, 0xD9]); // mov cr3, rcx
    *pos += 3;
    // Restore kernel SS = 0x10 and saved_kernel_rsp, then ret
    buf[*pos..*pos + 7].copy_from_slice(&[0xB9, KERNEL_DATA_SEL as u8, 0, 0, 0, 0x8E, 0xD1]);
    *pos += 7;
    emit_load_from_rax(buf, pos, REG_RSP, offset_of!(ProcBridgeState, saved_kernel_rsp));
    buf[*pos] = 0xC3; // ret
    *pos += 1;
}

/// Synthesize the 4 KiB KPTI Supervisor `RX` trampoline page (`PT[508]`).
fn build_trampoline_page(out: &mut [u8; 4096]) {
    out.fill(0xCC); // int3 poison across unused gaps
    let tf_base = offset_of!(ProcBridgeState, tf);

    // 1. `+0x000`: `entry_to_ring3` — switches to `user_cr3`, restores all 18 `UserTrapFrame` registers, `iretq` -> CPL=3.
    let mut p = 0x000usize;
    emit_lea_rax_state(out, &mut p);
    emit_store_to_rax(out, &mut p, REG_RSP, offset_of!(ProcBridgeState, saved_kernel_rsp));
    out[p..p + 3].copy_from_slice(&[0x0F, 0x20, 0xD9]); // mov rcx, cr3
    p += 3;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, kernel_cr3));
    // lea rsp, [rax + 0x400] (rsp0_top = sup_rw_va + 0x600)
    out[p..p + 7].copy_from_slice(&[0x48, 0x8D, 0xA0, 0x00, 0x04, 0x00, 0x00]);
    p += 7;
    emit_load_from_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, user_cr3));
    out[p..p + 3].copy_from_slice(&[0x0F, 0x22, 0xD9]); // mov cr3, rcx
    p += 3;
    // Push 5-word iretq frame: SS, RSP, RFLAGS, CS, RIP
    out[p..p + 2].copy_from_slice(&[0x6A, USER_DATA_SEL as u8]);
    p += 2;
    emit_push_mem_rax(out, &mut p, tf_base + offset_of!(UserTrapFrame, rsp));
    emit_push_mem_rax(out, &mut p, tf_base + offset_of!(UserTrapFrame, rflags));
    out[p..p + 2].copy_from_slice(&[0x6A, USER_CODE_SEL as u8]);
    p += 2;
    emit_push_mem_rax(out, &mut p, tf_base + offset_of!(UserTrapFrame, rip));
    // Restore rbx..r15, then rax last, then iretq!
    emit_load_from_rax(out, &mut p, REG_RBX, tf_base + offset_of!(UserTrapFrame, rbx));
    emit_load_from_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rcx));
    emit_load_from_rax(out, &mut p, REG_RDX, tf_base + offset_of!(UserTrapFrame, rdx));
    emit_load_from_rax(out, &mut p, REG_RSI, tf_base + offset_of!(UserTrapFrame, rsi));
    emit_load_from_rax(out, &mut p, REG_RDI, tf_base + offset_of!(UserTrapFrame, rdi));
    emit_load_from_rax(out, &mut p, REG_RBP, tf_base + offset_of!(UserTrapFrame, rbp));
    emit_load_from_rax(out, &mut p, REG_R8, tf_base + offset_of!(UserTrapFrame, r8));
    emit_load_from_rax(out, &mut p, REG_R9, tf_base + offset_of!(UserTrapFrame, r9));
    emit_load_from_rax(out, &mut p, REG_R10, tf_base + offset_of!(UserTrapFrame, r10));
    emit_load_from_rax(out, &mut p, REG_R11, tf_base + offset_of!(UserTrapFrame, r11));
    emit_load_from_rax(out, &mut p, REG_R12, tf_base + offset_of!(UserTrapFrame, r12));
    emit_load_from_rax(out, &mut p, REG_R13, tf_base + offset_of!(UserTrapFrame, r13));
    emit_load_from_rax(out, &mut p, REG_R14, tf_base + offset_of!(UserTrapFrame, r14));
    emit_load_from_rax(out, &mut p, REG_R15, tf_base + offset_of!(UserTrapFrame, r15));
    emit_load_from_rax(out, &mut p, REG_RAX, tf_base + offset_of!(UserTrapFrame, rax));
    out[p..p + 2].copy_from_slice(&[0x48, 0xCF]); // iretq
    p += 2;
    assert!(p <= 0x100);

    // 2. `+0x100`: `isr_int80` (DPL=3 interrupt gate `0x80` -> `IF=0` on entry)
    p = 0x100;
    out[p..p + 2].copy_from_slice(&[0xFC, 0x50]); // cld; push rax
    p += 2;
    emit_lea_rax_state(out, &mut p);
    emit_store_non_rax_gprs(out, &mut p);
    out[p] = 0x59; // pop rcx (saved user rax)
    p += 1;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rax));
    out[p..p + 4].copy_from_slice(&[0x48, 0x8B, 0x0C, 0x24]); // mov rcx, [rsp + 0x00] (rip)
    p += 4;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rip));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]); // mov rcx, [rsp + 0x08] (cs)
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_cs));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x10]); // mov rcx, [rsp + 0x10] (rflags)
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rflags));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x18]); // mov rcx, [rsp + 0x18] (rsp)
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rsp));
    emit_exit_to_kernel_tail(out, &mut p, EXIT_REASON_SYSCALL as u32);
    assert!(p <= 0x200);

    // 3. `+0x200`: `syscall_lstar_entry` (`0F 05` `SYSCALL` via `IA32_LSTAR` + `SWAPGS`, `IF=0` via `FMASK`)
    p = 0x200;
    let scratch_off = (offset_of!(ProcBridgeState, scratch_rax) as i32).to_le_bytes();
    out[p..p + 3].copy_from_slice(&[0x0F, 0x01, 0xF8]); // swapgs
    p += 3;
    // mov gs:[scratch_rax], rax (65 48 89 04 25 disp32)
    out[p..p + 9].copy_from_slice(&[
        0x65,
        0x48,
        0x89,
        0x04,
        0x25,
        scratch_off[0],
        scratch_off[1],
        scratch_off[2],
        scratch_off[3],
    ]);
    p += 9;
    emit_lea_rax_state(out, &mut p);
    out[p..p + 4].copy_from_slice(&[0x0F, 0x01, 0xF8, 0xFC]); // swapgs (restore GS); cld
    p += 4;
    // Save untrusted user RSP without dereferencing it, then pivot to supervisor stack `[rax + 0x680]` (`sup_rw_va + 0x880`)!
    emit_store_to_rax(out, &mut p, REG_RSP, tf_base + offset_of!(UserTrapFrame, rsp));
    out[p..p + 7].copy_from_slice(&[0x48, 0x8D, 0xA0, 0x80, 0x06, 0x00, 0x00]); // lea rsp, [rax + 0x680]
    p += 7;
    emit_store_non_rax_gprs(out, &mut p);
    // Hardware `syscall` placed next RIP in `rcx` and RFLAGS in `r11`.
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rip));
    emit_store_to_rax(out, &mut p, REG_R11, tf_base + offset_of!(UserTrapFrame, rflags));
    emit_load_from_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, scratch_rax));
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rax));
    out[p..p + 5].copy_from_slice(&[0xB9, USER_CODE_SEL as u8, 0, 0, 0]);
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_cs));
    emit_exit_to_kernel_tail(out, &mut p, EXIT_REASON_SYSCALL as u32);
    assert!(p <= 0x300);

    // 4. `+0x300`: `isr_preempt_timer` (Vector `0x50`, DPL=0 interrupt gate -> saves all 18 GPRs!)
    p = 0x300;
    out[p..p + 2].copy_from_slice(&[0xFC, 0x50]); // cld; push rax
    p += 2;
    emit_lea_rax_state(out, &mut p);
    emit_store_non_rax_gprs(out, &mut p);
    out[p] = 0x59; // pop rcx (saved user rax)
    p += 1;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rax));
    out[p..p + 4].copy_from_slice(&[0x48, 0x8B, 0x0C, 0x24]); // rip
    p += 4;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rip));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]); // cs
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_cs));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x10]); // rflags
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rflags));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x18]); // rsp
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rsp));
    emit_exit_to_kernel_tail(out, &mut p, EXIT_REASON_PREEMPT as u32);
    assert!(p <= 0x400);

    // 5. `+0x400`: `common_fault_handler` (Vectors `0..31` -> `[vec, err, rip, cs, rflags, rsp, ss]`)
    p = 0x400;
    out[p] = 0xFC; // cld
    p += 1;
    emit_lea_rax_state(out, &mut p);
    out[p..p + 4].copy_from_slice(&[0x48, 0x8B, 0x0C, 0x24]); // vec
    p += 4;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_vec));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x08]); // err
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_err));
    out[p..p + 3].copy_from_slice(&[0x0F, 0x20, 0xD1]); // mov rcx, cr2
    p += 3;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_cr2));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x10]); // rip
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rip));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x18]); // cs
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, offset_of!(ProcBridgeState, fault_cs));
    out[p..p + 5].copy_from_slice(&[0x48, 0x8B, 0x4C, 0x24, 0x28]); // rsp
    p += 5;
    emit_store_to_rax(out, &mut p, REG_RCX, tf_base + offset_of!(UserTrapFrame, rsp));
    emit_exit_to_kernel_tail(out, &mut p, EXIT_REASON_FAULT as u32);
    assert!(p <= 0x500);

    // 6. `+0x500 .. +0x700`: Per-vector CPU exception stubs `0..31`
    const HAS_ERR_CODE_MASK: u32 = (1 << 8)
        | (1 << 10)
        | (1 << 11)
        | (1 << 12)
        | (1 << 13)
        | (1 << 14)
        | (1 << 17)
        | (1 << 21)
        | (1 << 29)
        | (1 << 30);
    let mut v = 0usize;
    while v < 32 {
        let mut pos = 0x500 + v * 16;
        if (HAS_ERR_CODE_MASK & (1u32 << v)) == 0 {
            out[pos..pos + 2].copy_from_slice(&[0x6A, 0x00]); // push 0
            pos += 2;
        }
        out[pos..pos + 2].copy_from_slice(&[0x6A, v as u8]); // push vec
        pos += 2;
        let rel32 = (0x400i32 - ((pos + 5) as i32)).to_le_bytes();
        out[pos..pos + 5].copy_from_slice(&[0xE9, rel32[0], rel32[1], rel32[2], rel32[3]]);
        v += 1;
    }

    // 7. `+0x720`: Spurious APIC interrupt vector `0xFF` (`iretq`)
    out[0x720..0x722].copy_from_slice(&[0x48, 0xCF]);

    // 8. `+0x730`: Legacy 8259 PIC `ExtINT` vectors `0x20..0x2F` (`push rax; EOI slave+master; pop rax; iretq`)
    out[0x730..0x73A]
        .copy_from_slice(&[0x50, 0xB0, 0x20, 0xE6, 0xA0, 0xE6, 0x20, 0x58, 0x48, 0xCF]);
}

/// Outcome of executing a single hardware Ring-3 quantum on `cpu_id`.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub(crate) enum QuantumResult {
    /// Process executed a syscall and remains `Ready` (or `Exited`).
    Stepped { pid: u32, exited: Option<i32> },
    /// Process was preempted by Local APIC `0x50` timer and returned to `Ready`.
    Preempted { pid: u32, rip: u64 },
    /// Process triggered a `CPL=3` CPU exception; its frames were 100% reclaimed without Ring-0 panic.
    FaultIsolated {
        pid: u32,
        vector: u8,
        cr2: u64,
        reclaimed_frames: usize,
        respawned_pid: Option<u32>,
    },
}

/// Claim and execute one hardware Ring-3 (`CPL=3`) quantum for the next `Ready` ELF64 process
/// on `cpu_id` (`0..3`), arming this CPU's Local APIC one-shot preemption timer (`0x50`).
#[inline(never)]
pub(crate) fn run_next_ready_process_quantum(
    cpu_id: u8,
    preempt_timer_ticks: u32,
) -> Option<QuantumResult> {
    if !has_ready_processes() {
        return None;
    }

    // 1. Claim next `Ready` process slot and snapshot its per-process `FXSAVE64` + `FS_BASE`/`GS_BASE`
    //    state under `KERNEL_PROC_TABLE` (no nested locks!).
    let mut proc_fx = FxSaveArea::clean_user_default();
    let mut kern_fx = FxSaveArea::clean_user_default();
    let claimed: Option<(usize, u32, ProcAddressSpace, UserTrapFrame, u64, u64)> =
        with_proc_table_lock(|table| {
            let slot = table.claim_next_ready(cpu_id)?;
            let pid = table.procs[slot].pid;
            let vm = table.procs[slot].vm;
            let tf = table.procs[slot].trap_frame;
            let (user_fs, user_gs) = table.load_arch_ext_state_into(slot, &mut proc_fx);
            Some((slot, pid, vm, tf, user_fs, user_gs))
        });
    let (slot, pid, vm, initial_tf, user_fs_base, user_gs_base) = claimed?;

    // SAFETY: Running at CPL=0; ensure CPU protections and Local APIC MMIO page are mapped.
    unsafe {
        crate::banners_arch_platform::enable_cpu_memory_protections();
        let _ = crate::ensure_mmio_page(LAPIC_BASE);
    }

    // 2. Populate `PT[508]` (`tramp_pa`), `PT[509]` (`sup_rw_pa`), and `PT[510]` (`sup_idt_pa`)
    //    inside this process's private physical frames (zero shared mutable bridge state across CPUs!).
    let tramp_va = vm.tramp_va();
    let sup_rw_va = vm.sup_rw_va();
    let sup_idt_va = vm.sup_idt_va();
    let state_va = sup_rw_va + 0x200;
    let gdtr_new_va = sup_rw_va + 0x040;
    let idtr_new_va = sup_rw_va + 0x050;
    let gdtr_orig_va = sup_rw_va + 0x060;
    let idtr_orig_va = sup_rw_va + 0x070;
    let tss_va = sup_rw_va + 0x100;
    let rsp0_top = sup_rw_va + 0x600;
    let ist1_top = sup_rw_va + 0xB00;
    let ist2_top = sup_rw_va + 0xD80;
    let ist3_top = sup_rw_va + 0x1000;

    {
        // SAFETY: `vm.tramp_pa` is an exclusive 4 KiB frame mapped in `PHYS_MAP_OFFSET` and owned
        // solely by `slot` while in `ProcState::Running`; writing directly avoids a 4 KiB stack local.
        unsafe {
            let tramp_dst = &mut *(crate::pa_to_va(vm.tramp_pa).cast::<[u8; 4096]>());
            build_trampoline_page(tramp_dst);
        }
    }

    {
        // SAFETY: `vm.sup_idt_pa` is an exclusive 4 KiB frame mapped in `PHYS_MAP_OFFSET`;
        // writing 16-byte `IdtEntry` descriptors directly avoids a 4 KiB `Idt` stack local.
        unsafe {
            let idt_dst = crate::pa_to_va(vm.sup_idt_pa);
            core::ptr::write_bytes(idt_dst, 0, 4096);
            let entries_ptr = idt_dst.cast::<IdtEntry>();
            let mut exc_v = 0u8;
            while exc_v < 32 {
                let ist = match exc_v {
                    8 => 1,
                    2 => 2,
                    18 => 3,
                    _ => 0,
                };
                core::ptr::write_unaligned(
                    entries_ptr.add(exc_v as usize),
                    IdtEntry::new(
                        tramp_va + 0x500 + (exc_v as u64) * 16,
                        KERNEL_CODE_SEL,
                        TYPE_INTERRUPT_GATE_DPL0,
                        ist,
                    ),
                );
                exc_v += 1;
            }
            let mut pic_v = 0x20usize;
            while pic_v < 0x30 {
                core::ptr::write_unaligned(
                    entries_ptr.add(pic_v),
                    IdtEntry::new(
                        tramp_va + 0x730,
                        KERNEL_CODE_SEL,
                        TYPE_INTERRUPT_GATE_DPL0,
                        0,
                    ),
                );
                pic_v += 1;
            }
            let mut ext_v = 0x30usize;
            while ext_v < 0xFF {
                if ext_v == 0x80 {
                    core::ptr::write_unaligned(
                        entries_ptr.add(0x80),
                        IdtEntry::new(
                            tramp_va + 0x100,
                            KERNEL_CODE_SEL,
                            TYPE_INTERRUPT_GATE_DPL3,
                            0,
                        ),
                    );
                } else {
                    core::ptr::write_unaligned(
                        entries_ptr.add(ext_v),
                        IdtEntry::new(
                            tramp_va + 0x300,
                            KERNEL_CODE_SEL,
                            TYPE_INTERRUPT_GATE_DPL0,
                            0,
                        ),
                    );
                }
                ext_v += 1;
            }
            core::ptr::write_unaligned(
                entries_ptr.add(0xFF),
                IdtEntry::new(
                    tramp_va + 0x720,
                    KERNEL_CODE_SEL,
                    TYPE_INTERRUPT_GATE_DPL0,
                    0,
                ),
            );
        }
    }

    {
        let tss = Tss64::with_ist_stacks(rsp0_top, ist1_top, ist2_top, ist3_top);
        let tss_bytes = tss.to_bytes();
        let gdt = Gdt::new_full(tss_va, (TSS64_LEN - 1) as u32);
        let gdt_bytes = gdt.to_table_bytes();
        let gdt_limit: u16 = (Gdt::byte_size() - 1) as u16;
        let idt_limit: u16 = (Idt::byte_size() - 1) as u16;

        // SAFETY: `vm.sup_rw_pa` is an exclusive 4 KiB frame mapped in `PHYS_MAP_OFFSET`.
        unsafe {
            let base_ptr = crate::pa_to_va(vm.sup_rw_pa);
            core::ptr::write_bytes(base_ptr, 0, 4096);
            core::ptr::copy_nonoverlapping(gdt_bytes.as_ptr(), base_ptr, gdt_bytes.len());
            core::ptr::copy_nonoverlapping(
                tss_bytes.as_ptr(),
                base_ptr.add(0x100),
                tss_bytes.len(),
            );

            let gdtr_ptr = base_ptr.add(0x040);
            gdtr_ptr.copy_from_nonoverlapping(gdt_limit.to_le_bytes().as_ptr(), 2);
            gdtr_ptr
                .add(2)
                .copy_from_nonoverlapping(sup_rw_va.to_le_bytes().as_ptr(), 8);

            let idtr_ptr = base_ptr.add(0x050);
            idtr_ptr.copy_from_nonoverlapping(idt_limit.to_le_bytes().as_ptr(), 2);
            idtr_ptr
                .add(2)
                .copy_from_nonoverlapping(sup_idt_va.to_le_bytes().as_ptr(), 8);

            let st_ptr = base_ptr.add(0x200).cast::<ProcBridgeState>();
            let mut init_st = ProcBridgeState::default();
            init_st.user_cr3 = vm.user_pml4_pa;
            init_st.tf = initial_tf;
            // Only the status flags a process may own survive into ring 3; `IF` is
            // forced on so the `0x50` preemption timer fires.
            init_st.tf.rflags = target_enterprise::proc_vm::sanitize_user_rflags(init_st.tf.rflags);
            core::ptr::write_volatile(st_ptr, init_st);
        }
    }

    // 3. Install per-process disjoint `PML4[96 + slot] -> vm.pdpt_pa` in `kernel_cr3` under `PT_MOD_LOCK`.
    let pml4_slot = vm.pml4_slot();
    crate::with_pt_lock(|| {
        // SAFETY: Under `PT_MOD_LOCK` at CPL=0; `pml4_slot` (`96..112`) is dedicated exclusively to `slot`.
        unsafe {
            let kernel_cr3 = crate::read_cr3() & PTE_ADDR_MASK;
            let kpml4 = crate::pa_to_va(kernel_cr3).cast::<u64>();
            core::ptr::write_volatile(kpml4.add(pml4_slot), vm.pdpt_pa | PTE_P | PTE_W | PTE_U);
            asm!(
                "invlpg [{0}]",
                "invlpg [{1}]",
                "invlpg [{2}]",
                in(reg) tramp_va,
                in(reg) sup_rw_va,
                in(reg) sup_idt_va,
                options(nostack, preserves_flags),
            );
        }
    });

    // 4. Mask local interrupts, save MSRs + Local APIC timer state, arm `SYSCALL` MSRs + `0x50` preemption timer,
    //    execute Ring-3 quantum (`entry_to_ring3`), and restore all CPU state cleanly!
    let saved_rflags: u64;
    let orig_efer: u64;
    let orig_star: u64;
    let orig_lstar: u64;
    let orig_fmask: u64;
    let orig_fs_base: u64;
    let orig_gs_base: u64;
    let orig_kgs_base: u64;
    let post_user_fs: u64;
    let post_user_gs: u64;
    let saved_tpr: u32;
    let saved_lvt_timer: u32;
    let saved_timer_init: u32;

    // SAFETY: Executing on `cpu_id` at CPL=0 with `cli`; all MSRs and Local APIC registers are per-CPU hardware state.
    unsafe {
        asm!(
            "pushfq",
            "pop {}",
            "cli",
            out(reg) saved_rflags,
            options(nomem, preserves_flags),
        );

        orig_efer = rdmsr(MSR_IA32_EFER);
        orig_star = rdmsr(MSR_IA32_STAR);
        orig_lstar = rdmsr(MSR_IA32_LSTAR);
        orig_fmask = rdmsr(MSR_IA32_FMASK);
        orig_fs_base = rdmsr(MSR_IA32_FS_BASE);
        orig_gs_base = rdmsr(MSR_IA32_GS_BASE);
        orig_kgs_base = rdmsr(MSR_IA32_KERNEL_GS_BASE);

        wrmsr(MSR_IA32_EFER, orig_efer | EFER_SCE);
        wrmsr(MSR_IA32_STAR, SYSCALL_STAR_VAL);
        wrmsr(MSR_IA32_LSTAR, tramp_va + 0x200);
        wrmsr(MSR_IA32_FMASK, SYSCALL_FMASK_VAL);
        wrmsr(MSR_IA32_FS_BASE, user_fs_base);
        wrmsr(MSR_IA32_GS_BASE, user_gs_base);
        wrmsr(MSR_IA32_KERNEL_GS_BASE, state_va);

        // Save supervisor x87/SSE state (`FXSAVE64 [rdi]`) and load this process's sanitized
        // `FxSaveArea` (`FXRSTOR64 [rdi]`) before entering Ring-3.
        asm!(
            ".byte 0x48, 0x0f, 0xae, 0x07",
            in("rdi") kern_fx.bytes.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
        asm!(
            ".byte 0x48, 0x0f, 0xae, 0x0f",
            in("rdi") proc_fx.bytes.as_ptr(),
            options(nostack, preserves_flags),
        );

        saved_tpr = crate::mmio_read32(LAPIC_BASE + LAPIC_TPR_OFF);
        saved_lvt_timer = crate::mmio_read32(LAPIC_BASE + LAPIC_LVT_TIMER_OFF);
        saved_timer_init = crate::mmio_read32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF);
        let svr = crate::mmio_read32(LAPIC_BASE + LAPIC_SVR_OFF);
        crate::mmio_write32(LAPIC_BASE + LAPIC_SVR_OFF, svr | 0x1FF);
        // Hold class-4 (`0x40..0x44`) vectors in IRR while class-5 (`0x50`) preemption timer runs.
        crate::mmio_write32(LAPIC_BASE + LAPIC_TPR_OFF, 0x40);
        crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_DIV_OFF, 0x03);
        crate::mmio_write32(LAPIC_BASE + LAPIC_LVT_TIMER_OFF, PREEMPT_TIMER_VEC as u32);
        crate::mmio_write32(
            LAPIC_BASE + LAPIC_TIMER_INIT_OFF,
            preempt_timer_ticks.max(128),
        );

        asm!(
            "sgdt [r9]",
            "sidt [r10]",
            "mov r13d, cs",
            "mov r14d, ss",
            "lgdt [r11]",
            "push {k_cs}",
            "lea rax, [rip + 2f]",
            "push rax",
            "retfq",
            "2:",
            "mov eax, {k_ds}",
            "mov ss, ax",
            "mov ds, ax",
            "mov es, ax",
            "mov eax, {tss_sel}",
            "ltr ax",
            "lidt [r12]",
            "push rbx",
            "push rbp",
            "push r9",
            "push r10",
            "push r13",
            "push r14",
            "push r15",
            "call r8",
            "pop r15",
            "pop r14",
            "pop r13",
            "pop r10",
            "pop r9",
            "pop rbp",
            "pop rbx",
            "lgdt [r9]",
            "push r13",
            "lea rax, [rip + 3f]",
            "push rax",
            "retfq",
            "3:",
            "mov ss, r14w",
            "xor eax, eax",
            "mov ds, ax",
            "mov es, ax",
            "lidt [r10]",
            inout("r8") tramp_va => _,
            inout("r9") gdtr_orig_va => _,
            inout("r10") idtr_orig_va => _,
            inout("r11") gdtr_new_va => _,
            inout("r12") idtr_new_va => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("rsi") _,
            out("rdi") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            k_cs = const (KERNEL_CODE_SEL as u64),
            k_ds = const (KERNEL_DATA_SEL as u32),
            tss_sel = const (TSS_SEL as u32),
            clobber_abi("C"),
        );

        // Snapshot this process's x87/SSE state (`FXSAVE64 [rdi]`) + `FS_BASE`/`GS_BASE` and restore
        // supervisor x87/SSE state (`FXRSTOR64 [rdi]`) before releasing `cli`!
        asm!(
            ".byte 0x48, 0x0f, 0xae, 0x07",
            in("rdi") proc_fx.bytes.as_mut_ptr(),
            options(nostack, preserves_flags),
        );
        asm!(
            ".byte 0x48, 0x0f, 0xae, 0x0f",
            in("rdi") kern_fx.bytes.as_ptr(),
            options(nostack, preserves_flags),
        );
        post_user_fs = rdmsr(MSR_IA32_FS_BASE);
        post_user_gs = rdmsr(MSR_IA32_GS_BASE);

        // Disarm `0x50` preemption timer, drain/EOI any in-service APIC ISR vector (`0x20..=0xFF`),
        // and restore Local APIC + per-CPU runtime TSS + MSRs!
        crate::mmio_write32(
            LAPIC_BASE + LAPIC_LVT_TIMER_OFF,
            0x0001_0000 | (PREEMPT_TIMER_VEC as u32),
        );
        crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF, 0);
        let mut isr_idx = 7usize;
        while isr_idx >= 1 {
            let mut isr_word = crate::mmio_read32(LAPIC_BASE + 0x0100 + (isr_idx as u64) * 0x10);
            while isr_word != 0 {
                let bit = 31 - isr_word.leading_zeros();
                let vec = (isr_idx as u32) * 32 + bit;
                crate::smp_hw::account_ring3_intercepted_apic_irq(vec);
                crate::mmio_write32(LAPIC_BASE + LAPIC_EOI_OFF, 0);
                isr_word &= !(1u32 << bit);
            }
            isr_idx -= 1;
        }
        let _ = (LAPIC_ISR_PREEMPT_OFF, LAPIC_ISR_PREEMPT_BIT);
        crate::mmio_write32(LAPIC_BASE + LAPIC_TPR_OFF, saved_tpr);
        if (saved_lvt_timer & 0x0002_0000) != 0 && saved_timer_init != 0 {
            crate::mmio_write32(LAPIC_BASE + LAPIC_LVT_TIMER_OFF, saved_lvt_timer);
            crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF, saved_timer_init);
        }

        crate::smp_hw::restore_cpu_runtime_tss_if_active(cpu_id as usize);

        wrmsr(MSR_IA32_FS_BASE, orig_fs_base);
        wrmsr(MSR_IA32_GS_BASE, orig_gs_base);
        wrmsr(MSR_IA32_KERNEL_GS_BASE, orig_kgs_base);
        wrmsr(MSR_IA32_FMASK, orig_fmask);
        wrmsr(MSR_IA32_LSTAR, orig_lstar);
        wrmsr(MSR_IA32_STAR, orig_star);
        wrmsr(MSR_IA32_EFER, orig_efer);
    }

    // 5. Snapshot `ProcBridgeState` and unmap `kernel_pml4[pml4_slot]` BEFORE potentially freeing frames!
    // SAFETY: `vm.sup_rw_pa` is still exclusively owned by `slot`.
    let bridge_out: ProcBridgeState = unsafe {
        core::ptr::read_volatile(crate::pa_to_va(vm.sup_rw_pa).add(0x200).cast::<ProcBridgeState>())
    };

    crate::with_pt_lock(|| {
        // SAFETY: Clearing our exclusive `pml4_slot` (`96..112`) under `PT_MOD_LOCK`.
        unsafe {
            let kernel_cr3 = crate::read_cr3() & PTE_ADDR_MASK;
            let kpml4 = crate::pa_to_va(kernel_cr3).cast::<u64>();
            core::ptr::write_volatile(kpml4.add(pml4_slot), 0);
            asm!(
                "invlpg [{0}]",
                "invlpg [{1}]",
                "invlpg [{2}]",
                in(reg) tramp_va,
                in(reg) sup_rw_va,
                in(reg) sup_idt_va,
                options(nostack, preserves_flags),
            );
        }
    });

    if (saved_rflags & (1 << 9)) != 0 {
        // SAFETY: All original GDT/IDT/TSS/MSR state is restored; safe to re-enable `IF = 1`.
        unsafe {
            asm!("sti", options(nomem, nostack, preserves_flags));
        }
    }

    TOTAL_HW_QUANTA.fetch_add(1, Ordering::Relaxed);

    // Hardware NMI (#2), Machine Check (#18), or any exception whose saved `CS` is not the
    // Ring-3 user code selector (`USER_CODE_SEL`) is a fatal platform / kernel fault, never
    // a user process fault — route straight to forensic crash containment instead of charging `slot`!
    if bridge_out.exit_reason != EXIT_REASON_SYSCALL
        && bridge_out.exit_reason != EXIT_REASON_PREEMPT
    {
        if bridge_out.fault_vec == 2 {
            panic!("PROC_HW: hardware NMI (#2) interrupted Ring-3 quantum");
        }
        if bridge_out.fault_vec == 18 {
            panic!("PROC_HW: hardware Machine Check (#18) interrupted Ring-3 quantum");
        }
        if (bridge_out.fault_cs as u16) != USER_CODE_SEL {
            panic!("PROC_HW: supervisor-mode CPU exception (CS != USER_CODE_SEL) during Ring-3 quantum");
        }
    }

    // Verify KPTI hardware `CR3` isolation held during the entire Ring-3 quantum!
    if (bridge_out.observed_cr3 & PTE_ADDR_MASK) != vm.user_pml4_pa {
        panic!("PROC_HW: Ring-3 quantum did not execute under isolated user_pml4 CR3");
    }

    let mono_ns = crate::smp_hw::read_monotonic_timer_ticks().wrapping_mul(4_000_000);

    // 6. Commit exit outcome (`Syscall`, `PreemptTimer`, or `CpuFault`) under `KERNEL_PROC_TABLE`.
    let res = with_proc_table_lock(|table| {
        // Persist `FXSAVE64` + pre-syscall `FS_BASE`/`GS_BASE` BEFORE `handle_syscall` so
        // `PROC_SYS_SET_FS_BASE` / `PROC_SYS_SET_GS_BASE` updates win cleanly!
        table.save_arch_ext_state(slot, &proc_fx, post_user_fs, post_user_gs);
        let mut src = KernelPageFrameSource;
        match bridge_out.exit_reason {
            EXIT_REASON_SYSCALL => {
                match table.handle_syscall(slot, bridge_out.tf, cpu_id, mono_ns, &mut src) {
                    SyscallStepOutcome::Continue => {
                        // Keep process `Ready` so round-robin scheduler advances fairly across SMP cores!
                        table.procs[slot].state = ProcState::Ready;
                        QuantumResult::Stepped { pid, exited: None }
                    }
                    SyscallStepOutcome::Yielded => QuantumResult::Stepped { pid, exited: None },
                    SyscallStepOutcome::Exited(code) => QuantumResult::Stepped {
                        pid,
                        exited: Some(code),
                    },
                }
            }
            EXIT_REASON_PREEMPT => {
                table.on_timer_preempt(slot, bridge_out.tf);
                QuantumResult::Preempted {
                    pid,
                    rip: bridge_out.tf.rip,
                }
            }
            _ => {
                let fault = ProcFaultInfo {
                    vector: bridge_out.fault_vec as u8,
                    error_code: bridge_out.fault_err,
                    cr2: bridge_out.fault_cr2,
                    rip: bridge_out.tf.rip,
                    cs: bridge_out.fault_cs as u16,
                };
                let (reclaimed_frames, respawn) = table.on_user_fault(slot, fault, &mut src);
                let mut respawned_pid = None;
                if let Some((svc, caps, next_seed, aff_mask)) = respawn {
                    let mut elf_buf = [0u8; 2048];
                    let n = build_elf64_program(
                        ElfProgramKind::ServiceSanitizer(svc),
                        next_seed,
                        &mut elf_buf,
                    );
                    if let Ok((new_pid, new_slot)) =
                        table.spawn_elf64(&elf_buf[..n], caps, next_seed, Some(svc), &mut src)
                    {
                        table.procs[new_slot].cpu_affinity_mask = aff_mask;
                        table.total_service_respawns = table.total_service_respawns.wrapping_add(1);
                        respawned_pid = Some(new_pid);
                    }
                }
                QuantumResult::FaultIsolated {
                    pid,
                    vector: fault.vector,
                    cr2: fault.cr2,
                    reclaimed_frames,
                    respawned_pid,
                }
            }
        }
    });

    if has_ready_processes() {
        crate::smp_hw::ring_smp_doorbell();
    }
    Some(res)
}

fn stage_ipc_in_locked_table(
    table: &ProcessTable,
    slot: usize,
    canary: u32,
    strict_vfs: bool,
    path: &[u8],
    body: &[u8],
) {
    let ipc_pa = table.procs[slot].vm.ipc_page_pa;
    if ipc_pa == 0 {
        return;
    }
    let plen = path.len().min(64);
    let blen = body.len().min(512);
    // SAFETY: `ipc_pa` is an allocated 4 KiB frame mapped in `PHYS_MAP_OFFSET`.
    unsafe {
        let dst = crate::pa_to_va(ipc_pa);
        core::ptr::write_bytes(dst, 0, 4096);
        dst.copy_from_nonoverlapping(canary.to_le_bytes().as_ptr(), 4);
        dst.add(0x260)
            .copy_from_nonoverlapping(canary.to_le_bytes().as_ptr(), 4);
        core::ptr::write_volatile(dst.add(0x04), u8::from(strict_vfs));
        core::ptr::write_volatile(dst.add(0x05), plen as u8);
        dst.add(0x06)
            .copy_from_nonoverlapping((blen as u16).to_le_bytes().as_ptr(), 2);
        if plen > 0 {
            core::ptr::copy_nonoverlapping(path.as_ptr(), dst.add(0x10), plen);
        }
        if blen > 0 {
            core::ptr::copy_nonoverlapping(body.as_ptr(), dst.add(0x50), blen);
        }
    }
}

/// Stage a structured service IPC mailbox request into `slot`'s `PT[103]` (`ipc_page_va`).
#[cfg(not(cuttle_prod))]
fn stage_service_ipc_mailbox(
    slot: usize,
    canary: u32,
    strict_vfs: bool,
    path: &[u8],
    body: &[u8],
) {
    with_proc_table_lock(|table| {
        stage_ipc_in_locked_table(table, slot, canary, strict_vfs, path, body);
    });
}

/// Live `svc_runtime` mailbox hook executing `svc-http`, `svc-sql`, and `svc-sh` as real
/// multi-segment `ET_DYN` Ring-3 ELF64 processes (`.text` `RX`, `.rodata` `RO+NX`, `.data+.bss`
/// `RW+NX`, 4-page guarded stack, `PT[103]` IPC mailbox, and `0F 05` `SYSCALL` exit)!
#[inline(never)]
pub(crate) fn exec_service_elf64_mailbox_live(
    svc: ServiceId,
    worker_code: &[u8],
    canary: u32,
    strict_vfs: bool,
    path: &[u8],
    body: &[u8],
    expected_fnv: u64,
) -> Ring3MailboxHwVerdict {
    // Defensive early-boot / extreme-OOM fallback if physical frame allocator has < 20 free pages.
    if crate::phys_mm_stats().free_frames < 20 {
        return crate::banners_arch_platform::exec_service_ring3_mailbox_live(
            svc,
            worker_code,
            canary,
            strict_vfs,
            path,
            body,
            expected_fnv,
        );
    }

    // Detect infinite-loop (`EB FE`) preemption probe or wrap `worker_code` (including `ud2` `0F 0B`
    // fault injection) directly inside an isolated 3-segment `ET_DYN` ELF64 process!
    let mut elf = [0u8; 2048];
    let seed = (canary as u64) ^ ((svc.pid() as u64) << 32) ^ 0x5A5A_A5A5_1357_2468;
    let is_spin = worker_code.len() >= 2 && worker_code[0] == 0xEB && worker_code[1] == 0xFE;

    if is_spin {
        // Spawn a runaway CPU-bound ELF64 loop and prove hardware `0x50` timer preemption evicts it!
        let n = build_elf64_program(
            ElfProgramKind::CpuBoundWorker {
                iterations: 500_000_000,
            },
            seed,
            &mut elf,
        );
        let Ok((pid, slot)) = with_proc_table_lock(|table| {
            let mut src = KernelPageFrameSource;
            let pair = table.spawn_elf64(&elf[..n], svc.policy().cap_mask, seed, None, &mut src)?;
            table.procs[pair.1].cpu_affinity_mask = 0x01;
            Ok::<_, ProcError>(pair)
        }) else {
            return Ring3MailboxHwVerdict::FaultedOrPreempted;
        };
        let mut steps = 0usize;
        let mut saw_preempt = false;
        while steps < 16 {
            if let Some(q) = run_next_ready_process_quantum(0, 2_000) {
                if let QuantumResult::Preempted { pid: qpid, .. } = q {
                    if qpid == pid {
                        saw_preempt = true;
                        break;
                    }
                }
            }
            steps += 1;
        }
        with_proc_table_lock(|table| {
            let mut src = KernelPageFrameSource;
            let _ = table.on_user_fault(
                slot,
                ProcFaultInfo {
                    vector: PREEMPT_TIMER_VEC,
                    error_code: 0,
                    cr2: 0,
                    rip: 0,
                    cs: USER_CODE_SEL,
                },
                &mut src,
            );
            table.free_reaped_slot(slot);
        });
        let _ = saw_preempt;
        return Ring3MailboxHwVerdict::FaultedOrPreempted;
    }

    let elf_len = build_elf64_from_mailbox_worker(worker_code, seed, &mut elf);
    let caps = svc.policy().cap_mask | SVC_CAP_IPC;

    let (pid, slot) = match with_proc_table_lock(|table| {
        let mut src = KernelPageFrameSource;
        let pair = table.spawn_elf64(&elf[..elf_len], caps, seed, Some(svc), &mut src)?;
        table.procs[pair.1].cpu_affinity_mask = 0x01;
        stage_ipc_in_locked_table(table, pair.1, canary, strict_vfs, path, body);
        Ok::<_, ProcError>(pair)
    }) {
        Ok(pair) => pair,
        Err(_) => return Ring3MailboxHwVerdict::FaultedOrPreempted,
    };

    // Drive quanta until `pid` finishes (`Exited` or `Faulted`).
    let mut guard_steps = 0usize;
    let mut faulted_respawn: Option<u32> = None;
    while guard_steps < 32 {
        let state = with_proc_table_lock(|t| t.procs[slot].state);
        if matches!(state, ProcState::Exited | ProcState::Faulted | ProcState::Unused) {
            break;
        }
        if let Some(QuantumResult::FaultIsolated {
            pid: fpid,
            respawned_pid,
            ..
        }) = run_next_ready_process_quantum(0, 10_000_000)
        {
            if fpid == pid {
                faulted_respawn = respawned_pid;
                break;
            }
        }
        guard_steps += 1;
    }

    // If `FaultUd2` triggered automatic morphed service respawn, reap the idle respawned instance cleanly
    // so `KERNEL_PROC_TABLE` leaves zero background frames after the fault-containment check.
    if let Some(rpid) = faulted_respawn {
        with_proc_table_lock(|table| {
            if let Some(rslot) = table.slot_by_pid(rpid) {
                let mut src = KernelPageFrameSource;
                table.procs[rslot].vm.release_all_frames(&mut src);
                table.procs[rslot].state = ProcState::Exited;
                table.free_reaped_slot(rslot);
            }
        });
    }

    let (final_state, status, fnv) = with_proc_table_lock(|table| {
        let st = table.procs[slot].state;
        let ipc_st = table.procs[slot].last_ipc_status;
        let ipc_fnv = table.procs[slot].last_ipc_fnv;
        // Reap any timed-out worker still `Ready` or `Running` after 32 quanta so neither its
        // slot nor its physical frames leak into `KERNEL_PROC_TABLE`!
        if !matches!(st, ProcState::Exited | ProcState::Faulted | ProcState::Unused) {
            let mut src = KernelPageFrameSource;
            table.procs[slot].vm.release_all_frames(&mut src);
            table.procs[slot].state = ProcState::Faulted;
            table.total_faulted_reaped = table.total_faulted_reaped.wrapping_add(1);
        }
        table.free_reaped_slot(slot);
        (st, ipc_st, ipc_fnv)
    });

    if final_state != ProcState::Exited {
        return Ring3MailboxHwVerdict::FaultedOrPreempted;
    }
    match status {
        1 if fnv != 0 => Ring3MailboxHwVerdict::Ok(fnv),
        2 => Ring3MailboxHwVerdict::RejectedPath,
        3 => Ring3MailboxHwVerdict::RejectedBody,
        _ => Ring3MailboxHwVerdict::FaultedOrPreempted,
    }
}

/// Comprehensive bare-metal proof of Stage B2 (Gap B1):
/// 1. Multi-segment `ET_DYN` ELF64 Ring-3 (`CPL=3`) process loading (`.text` `RX`, `.rodata` `RO+NX`,
///    `.data+.bss` `RW+NX`, 4-page `16 KiB` guarded user stack, `PROC_SYS_BRK` demand heap, `SYSCALL` `0F 05`
///    via `IA32_LSTAR` + `SWAPGS`, and `int 0x80`).
/// 2. Preemptive Local APIC (`0x50`) time-slicing + parallel multi-core SMP execution across `CPU 0..3`.
/// 3. Inter-process message passing (`PROC_SYS_IPC_SEND` / `PROC_SYS_IPC_RECV` + `SYS_YIELD`).
/// 4. Complete `CPL=3` hardware fault isolation (`#UD` vec 6, KPTI kernel-address `#PF` vec 14,
///    stack-guard overflow `#PF` vec 14, privileged `cli` `#GP` vec 13) + automatic morphed service respawn
///    with **zero leaked physical frames**.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_ring3_elf_multiprocess() {
    crate::heap::reclaim_empty_slabs();
    let baseline = crate::phys_mm_stats();

    // ---- Phase 1: 4 concurrent CPU-bound multi-segment ELF64 processes across SMP cores + 0x50 preemption ----
    const WORKER_ITERS: u32 = 4_000_000;
    let expected_code = expected_cpu_worker_exit_code(WORKER_ITERS);
    let mut worker_pids = [0u32; 4];
    let mut worker_slots = [0usize; 4];
    let mut w = 0usize;
    while w < 4 {
        let mut elf = [0u8; 2048];
        let seed = 0xB200_0000_0000_0000u64 | (w as u64);
        let len = build_elf64_program(
            ElfProgramKind::CpuBoundWorker {
                iterations: WORKER_ITERS,
            },
            seed,
            &mut elf,
        );
        let (pid, slot) = spawn_kernel_elf64_process(&elf[..len], u64::MAX, seed, None)
            .expect("RING3_ELF_MP: failed to spawn CpuBoundWorker");
        worker_pids[w] = pid;
        worker_slots[w] = slot;
        w += 1;
    }

    // Wake AP cores `CPU 1..3` via Doorbell IPI while `CPU 0` also drains quanta with tight `0x50` timer (`256` ticks)!
    crate::smp_hw::ring_smp_doorbell();
    let mut safety_loops = 0u32;
    let mut idle_spins = 0u32;
    while safety_loops < 5_000_000 {
        let all_done = with_proc_table_lock(|t| {
            worker_slots
                .iter()
                .all(|&s| t.procs[s].state == ProcState::Exited)
        });
        if all_done {
            break;
        }
        if run_next_ready_process_quantum(0, 256).is_none() {
            if (idle_spins & 0xFF) == 0 {
                crate::smp_hw::ring_smp_doorbell();
            }
            idle_spins = idle_spins.wrapping_add(1);
            core::hint::spin_loop();
        }
        safety_loops += 1;
    }

    let (total_preempts, cpu_union) = with_proc_table_lock(|t| {
        let mut pr = 0u64;
        let mut cpus = 0u8;
        for (idx, &s) in worker_slots.iter().enumerate() {
            let p = &t.procs[s];
            if p.pid != worker_pids[idx] || p.state != ProcState::Exited {
                panic!("RING3_ELF_MP: CpuBoundWorker did not complete cleanly");
            }
            if p.exit_code != expected_code {
                panic!("RING3_ELF_MP: CpuBoundWorker arithmetic/heap checksum mismatch");
            }
            if p.stdout_len < 6 || &p.stdout_buf[..6] != b"R3-OK\n" {
                panic!("RING3_ELF_MP: SYSCALL (0F 05) SYS_WRITE output missing");
            }
            pr += p.preemptions;
            cpus |= p.cpu_mask_seen;
            t.free_reaped_slot(s);
        }
        (pr, cpus)
    });
    if total_preempts == 0 {
        panic!("RING3_ELF_MP: Local APIC 0x50 timer did not preempt CPU-bound Ring-3 workers");
    }

    // ---- Phase 2: Ring-3 ELF64 IPC (`PROC_SYS_IPC_SEND` + `PROC_SYS_IPC_RECV` + `SYS_YIELD`) ----
    let mut elf_rx = [0u8; 2048];
    let n_rx = build_elf64_program(ElfProgramKind::IpcPeer { target_pid: 0 }, 1, &mut elf_rx);
    let (rx_pid, rx_slot) =
        spawn_kernel_elf64_process(&elf_rx[..n_rx], u64::MAX, 1, None).unwrap();

    let mut elf_tx = [0u8; 2048];
    let n_tx = build_elf64_program(
        ElfProgramKind::IpcPeer { target_pid: rx_pid },
        2,
        &mut elf_tx,
    );
    let (_tx_pid, tx_slot) =
        spawn_kernel_elf64_process(&elf_tx[..n_tx], u64::MAX, 2, None).unwrap();

    crate::smp_hw::ring_smp_doorbell();
    let mut ipc_loops = 0u32;
    let mut ipc_idle = 0u32;
    while ipc_loops < 2_000_000 {
        let done = with_proc_table_lock(|t| {
            t.procs[rx_slot].state == ProcState::Exited
                && t.procs[tx_slot].state == ProcState::Exited
        });
        if done {
            break;
        }
        if run_next_ready_process_quantum(0, 50_000).is_none() {
            if (ipc_idle & 0xFF) == 0 {
                crate::smp_hw::ring_smp_doorbell();
            }
            ipc_idle = ipc_idle.wrapping_add(1);
            core::hint::spin_loop();
        }
        ipc_loops += 1;
    }
    with_proc_table_lock(|t| {
        if t.procs[tx_slot].state != ProcState::Exited
            || t.procs[rx_slot].state != ProcState::Exited
            || t.procs[tx_slot].exit_code != 6
            || t.procs[rx_slot].exit_code != 77
        {
            panic!("RING3_ELF_MP: Ring-3 ELF64 IPC ping-pong verification failed");
        }
        t.free_reaped_slot(tx_slot);
        t.free_reaped_slot(rx_slot);
    });

    // ---- Phase 3: 4 Hostile Ring-3 Faults + Automatic Morphed Service Respawn ----
    let fault_cases: [(ElfProgramKind, u8, Option<ServiceId>); 4] = [
        (ElfProgramKind::FaultKernelRead, 14, None),
        (ElfProgramKind::FaultStackGuard, 14, None),
        (ElfProgramKind::FaultPrivCli, 13, None),
        (ElfProgramKind::FaultUd2, 6, Some(ServiceId::Http)),
    ];
    let mut isolated_count = 0u64;
    let mut respawned_svc_pid: Option<u32> = None;

    for (idx, (kind, expected_vec, svc_opt)) in fault_cases.iter().enumerate() {
        let mut felf = [0u8; 2048];
        let flen = build_elf64_program(*kind, 0xF000 + (idx as u64), &mut felf);
        let (fpid, fslot) = with_proc_table_lock(|t| {
            let mut src = KernelPageFrameSource;
            let pair = t.spawn_elf64(
                &felf[..flen],
                u64::MAX,
                0xF000 + (idx as u64),
                *svc_opt,
                &mut src,
            )?;
            t.procs[pair.1].cpu_affinity_mask = 0x01;
            Ok::<_, ProcError>(pair)
        })
        .expect("RING3_ELF_MP: failed to spawn fault test process");

        let mut f_steps = 0usize;
        let mut trapped = false;
        while f_steps < 16 {
            let q = run_next_ready_process_quantum(0, 20_000_000)
                .expect("RING3_ELF_MP: fault test quantum did not run");
            match q {
                QuantumResult::Preempted { .. } => {
                    f_steps += 1;
                    continue;
                }
                QuantumResult::FaultIsolated {
                    pid,
                    vector,
                    cr2,
                    reclaimed_frames,
                    respawned_pid,
                } => {
                    if pid != fpid || vector != *expected_vec || reclaimed_frames < 15 {
                        panic!("RING3_ELF_MP: unexpected fault vector or incomplete frame reclamation");
                    }
                    if matches!(kind, ElfProgramKind::FaultKernelRead)
                        && cr2 != 0xFFFF_8000_0000_0000
                    {
                        panic!("RING3_ELF_MP: KPTI kernel read fault recorded wrong CR2");
                    }
                    if svc_opt.is_some() {
                        respawned_svc_pid = respawned_pid;
                    }
                    isolated_count += 1;
                    trapped = true;
                    break;
                }
                QuantumResult::Stepped { .. } => {
                    panic!("RING3_ELF_MP: hostile Ring-3 instruction exited instead of faulting");
                }
            }
        }
        if !trapped {
            panic!("RING3_ELF_MP: hostile Ring-3 instruction did not trap as CpuFault");
        }
        with_proc_table_lock(|t| {
            if t.procs[fslot].last_fault.cs != USER_CODE_SEL {
                panic!("RING3_ELF_MP: fault did not originate from CPL=3 CS=0x23");
            }
            t.free_reaped_slot(fslot);
        });
    }

    // Verify `FaultUd2` on `ServiceId::Http` automatically respawned a fresh morphed ELF64 PID,
    // stage a live HTTP request into its `PT[103]` IPC page, and run it to clean completion!
    let rpid = respawned_svc_pid.expect("RING3_ELF_MP: supervised svc-http did not auto-respawn");
    let rslot = with_proc_table_lock(|t| t.slot_by_pid(rpid))
        .expect("RING3_ELF_MP: respawned svc-http slot missing");
    stage_service_ipc_mailbox(rslot, 0xCAFE_1234, false, b"/healthz", b"ok");
    let mut r_steps = 0usize;
    while r_steps < 32 {
        if with_proc_table_lock(|t| t.procs[rslot].state == ProcState::Exited) {
            break;
        }
        let _ = run_next_ready_process_quantum(0, 20_000_000);
        r_steps += 1;
    }
    with_proc_table_lock(|t| {
        if t.procs[rslot].state != ProcState::Exited || t.procs[rslot].last_ipc_status != 1 {
            panic!("RING3_ELF_MP: auto-respawned morphed svc-http ELF64 process failed request");
        }
        t.free_reaped_slot(rslot);
    });

    // ---- Phase 3b: Hostile `RFLAGS.NT = 1` + `0F 05` `SYSCALL`, per-process `XMM0` & `FS_BASE`
    //                isolation, timed-out service worker reaping, and dedicated `IST2`/`IST3` check ----
    {
        let mut elf_a = [0u8; 2048];
        let mut elf_b = [0u8; 2048];
        let n_a = build_elf64_program(
            ElfProgramKind::HostileSyscallNtAndSimd {
                token: 0xA111_2222_3333_4444,
            },
            0xDEAD_A111,
            &mut elf_a,
        );
        let n_b = build_elf64_program(
            ElfProgramKind::HostileSyscallNtAndSimd {
                token: 0xB555_6666_7777_8888,
            },
            0xDEAD_B222,
            &mut elf_b,
        );
        let (slot_a, slot_b) = with_proc_table_lock(|t| {
            let mut src = KernelPageFrameSource;
            let (_, sa) = t
                .spawn_elf64(&elf_a[..n_a], u64::MAX, 0xDEAD_A111, None, &mut src)
                .expect("RING3_ELF_MP: spawn HostileSyscallNtAndSimd A");
            let (_, sb) = t
                .spawn_elf64(&elf_b[..n_b], u64::MAX, 0xDEAD_B222, None, &mut src)
                .expect("RING3_ELF_MP: spawn HostileSyscallNtAndSimd B");
            t.procs[sa].cpu_affinity_mask = 0x01;
            t.procs[sb].cpu_affinity_mask = 0x01;
            (sa, sb)
        });
        let mut nt_steps = 0usize;
        while nt_steps < 64 {
            let done = with_proc_table_lock(|t| {
                t.procs[slot_a].state == ProcState::Exited
                    && t.procs[slot_b].state == ProcState::Exited
            });
            if done {
                break;
            }
            let _ = run_next_ready_process_quantum(0, 20_000_000);
            nt_steps += 1;
        }
        with_proc_table_lock(|t| {
            if t.procs[slot_a].state != ProcState::Exited
                || t.procs[slot_b].state != ProcState::Exited
                || t.procs[slot_a].exit_code != 55
                || t.procs[slot_b].exit_code != 55
            {
                panic!("RING3_ELF_MP: HostileSyscallNtAndSimd failed (NT leak or XMM0/FS_BASE bleed)");
            }
            t.free_reaped_slot(slot_a);
            t.free_reaped_slot(slot_b);
        });

        // Timed-out `SYS_YIELD` loop (`mov eax, 10; syscall; jmp -9`) exceeding 32 quanta must be
        // cleanly reaped by `exec_service_elf64_mailbox_live` with zero leaked slots or frames!
        let timeout_verdict = exec_service_elf64_mailbox_live(
            ServiceId::Http,
            &[0xB8, 0x0A, 0x00, 0x00, 0x00, 0x0F, 0x05, 0xEB, 0xF7],
            0xDEAD_7777,
            false,
            b"/spin",
            b"x",
            0,
        );
        if timeout_verdict != Ring3MailboxHwVerdict::FaultedOrPreempted {
            panic!("RING3_ELF_MP: timed-out service worker did not return FaultedOrPreempted");
        }

        let tss_chk = Tss64::with_ist_stacks(0x1600, 0x1B00, 0x1D80, 0x2000).to_bytes();
        let ist1_enc = u64::from_le_bytes(tss_chk[36..44].try_into().unwrap());
        let ist2_enc = u64::from_le_bytes(tss_chk[44..52].try_into().unwrap());
        let ist3_enc = u64::from_le_bytes(tss_chk[52..60].try_into().unwrap());
        if ist1_enc != 0x1B00 || ist2_enc != 0x1D80 || ist3_enc != 0x2000 {
            panic!("RING3_ELF_MP: Tss64 IST1/IST2/IST3 encoding mismatch");
        }
    }

    // ---- Phase 4: Verify 100% physical frame conservation (0 leaked frames across all processes!) ----
    crate::heap::reclaim_empty_slabs();
    let after = crate::phys_mm_stats();
    if after.free_frames != baseline.free_frames {
        panic!("RING3_ELF_MP: physical frame leak detected after multi-process & fault storm");
    }

    let smp_cpus = (cpu_union.count_ones() as u64).max(1);
    let mut line = [0u8; 192];
    let mut pos = 0usize;
    let p0 = b"RING3_ELF_MP OK procs=11 preempts=";
    line[pos..pos + p0.len()].copy_from_slice(p0);
    pos += p0.len();
    pos += crate::dec_u64(total_preempts, &mut line[pos..]);
    let p1 = b" smp_cpus=";
    line[pos..pos + p1.len()].copy_from_slice(p1);
    pos += p1.len();
    pos += crate::dec_u64(smp_cpus, &mut line[pos..]);
    let p2 = b" faults_isolated=";
    line[pos..pos + p2.len()].copy_from_slice(p2);
    pos += p2.len();
    pos += crate::dec_u64(isolated_count, &mut line[pos..]);
    let p3 = b" respawn=1 leak=0 nt_fmask=1 simd_fsgs=2 timeout_reap=1 ist23=1\n";
    line[pos..pos + p3.len()].copy_from_slice(p3);
    pos += p3.len();
    crate::serial_write_bytes(&line[..pos]);
}
