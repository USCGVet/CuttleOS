//! x86_64 architecture, IOMMU, DMA, SMP, PCI, APIC, ACPI, and timer boot banners.

pub(crate) use crate::*;


/// IOMMU: instantiate `IommuImpl<4, 8, 16>`, create a domain, bind one
/// device, map one page, translate, assert the host PA matches the
/// locked fixture, emit `IOMMU translate OK pa=<hex8>\n`.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_iommu_translate() {
    let mut iommu: IommuImpl<
        { kf::IOMMU_DOMAINS },
        { kf::IOMMU_DEVICES },
        { kf::IOMMU_ENTRIES_PER_DOMAIN },
    > = IommuImpl::new();

    let domain = match iommu.create_domain() {
        Ok(d) => d,
        Err(_) => panic!("IOMMU create_domain failed"),
    };
    let device = DeviceId::from_bdf(
        kf::IOMMU_DEVICE_SEGMENT,
        kf::IOMMU_DEVICE_BUS,
        kf::IOMMU_DEVICE_DEVICE,
        kf::IOMMU_DEVICE_FUNCTION,
    );
    if iommu.bind_device(device, domain).is_err() {
        panic!("IOMMU bind_device failed");
    }
    if iommu
        .map(domain, kf::IOMMU_DMA_ADDR, kf::IOMMU_HOST_PHYS, PagePerms::RW)
        .is_err()
    {
        panic!("IOMMU map failed");
    }
    let probe = kf::IOMMU_DMA_ADDR + kf::IOMMU_PAGE_OFFSET;
    let pa = match iommu.translate(device, probe, AccessKind::Read) {
        Ok(pa) => pa,
        Err(_) => panic!("IOMMU translate returned Err for mapped page"),
    };
    if pa != kf::IOMMU_EXPECTED_PA {
        panic!("IOMMU translate PA drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"IOMMU translate OK pa=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex8 = [0u8; 8];
    hex_u32((pa & 0xFFFF_FFFF) as u32, &mut hex8);
    line[pos..pos + 8].copy_from_slice(&hex8);
    pos += 8;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// TASK-014: DMA syscall path. Construct an `IommuImpl<4, 8, 16>`, bind
// a synthetic privileged device, build a `Task` pre-bound to that
// IOMMU domain, then call `dispatch_dma` twice: SYS_DMA_MAP +
// SYS_DMA_UNMAP. The dispatcher routes through `check_cap` (which
// mints a `CapProof`) and the handler consumes the proof by value
// before delegating to the IOMMU. Emits:
//   `DMA_MAP test OK\n`
//   `DMA_UNMAP test OK\n`
//
// A kernel that boots with the type-state cap check + the IOMMU +
// the per-task `iommu_domain` field is exercising every load-bearing
// piece TASK-014 wired together. If any of them is broken (proof not
// minted, domain not threaded, IOMMU state lost), one of the two
// banners is missing from the serial log and the QEMU smoke test
// surfaces it.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_dma() {
    use cuttle_contracts::Iommu;
    use cuttle_contracts::caps::NET_RAW;
    use target_enterprise::iommu::{DeviceId as IommuDeviceId, IommuImpl as DmaIommuImpl};
    use target_enterprise::scheduler::{Task, TaskId};
    use target_enterprise::syscall::{dispatch_dma, SYS_DMA_MAP, SYS_DMA_UNMAP};

    let mut iommu: DmaIommuImpl<4, 8, 16> = DmaIommuImpl::new();
    let domain = iommu.create_domain().expect("kpti-dma: create_domain");
    let device = IommuDeviceId::from_bdf(0, 0, 1, 0);
    iommu
        .bind_device(device, domain)
        .expect("kpti-dma: bind_device");
    let task = Task::new_ready_with_domain(7 as TaskId, 1, domain);

    // ---- SYS_DMA_MAP ----
    let dma_addr = 0x4000u64;
    let host_phys = 0xC000_0000u64;
    match dispatch_dma(
        &mut iommu,
        &task,
        NET_RAW,
        SYS_DMA_MAP,
        dma_addr,
        host_phys,
        0b11, // RW
    ) {
        Ok(0) => {}
        Ok(other) => panic!("DMA_MAP returned unexpected Ok({})", other),
        Err(_) => panic!("DMA_MAP failed unexpectedly"),
    }
    serial_write_str("DMA_MAP test OK\n");

    // ---- SYS_DMA_UNMAP ----
    match dispatch_dma(
        &mut iommu,
        &task,
        NET_RAW,
        SYS_DMA_UNMAP,
        dma_addr,
        0,
        0,
    ) {
        Ok(0) => {}
        Ok(other) => panic!("DMA_UNMAP returned unexpected Ok({})", other),
        Err(_) => panic!("DMA_UNMAP failed unexpectedly"),
    }
    serial_write_str("DMA_UNMAP test OK\n");
}

/// Live hardware GDT + 64-bit TSS (`lgdt`/`ltr`), 256-entry IDT (`lidt`),
/// `IST1` breakpoint exception (`int3`), and Ring-0 -> Ring-3 (`iretq`) ->
/// Ring-0 (`int 0x80` on `RSP0` + `dispatch_with_cap`) privilege transition proof.
/// Execute a 32-byte x86-64 Ring-3 (`CPL=3`) machine-code stub at hardware `CPL=3` via
/// `iretq` -> `int 0x80` on `TSS.RSP0`, verifying the `IST1` breakpoint stack switch,
/// `CPL=3` `USER_CODE_SEL`/`USER_DATA_SEL` selectors, user-mapped IPC mailbox request/canary
/// read (`[rsp - 0x20]`) and signed response write (`[rsp - 0x18]`), `SYS_GETPID` trap, and `expected_arg0`.
/// Bitmask of hardware CPU security controls verified active on the BSP (`NXE`, `WP`, `SMEP`, `SMAP`, `FSGSBASE`, `UMIP`).
pub(crate) static ACTIVE_CPU_SEC_BITS: core::sync::atomic::AtomicU32 =
    core::sync::atomic::AtomicU32::new(0);

pub(crate) const CPU_SEC_NXE: u32 = 1 << 0;
pub(crate) const CPU_SEC_WP: u32 = 1 << 1;
pub(crate) const CPU_SEC_SMEP: u32 = 1 << 2;
pub(crate) const CPU_SEC_SMAP: u32 = 1 << 3;
pub(crate) const CPU_SEC_FSGSBASE: u32 = 1 << 4;
pub(crate) const CPU_SEC_UMIP: u32 = 1 << 5;

#[inline]
pub(crate) fn read_active_cpu_sec_bits() -> u32 {
    ACTIVE_CPU_SEC_BITS.load(core::sync::atomic::Ordering::Acquire)
}

/// Enable hardware `IA32_EFER.NXE` (`bit 11`), `CR0.WP` (`bit 16`), and all CPUID-advertised
/// Ring-0/Ring-3 architectural protections (`CR4.SMEP` bit 20, `CR4.SMAP` bit 21 + `CLAC`,
/// `CR4.UMIP` bit 11, and `CR4.FSGSBASE` bit 16) on the calling logical processor, returning
/// the hardware read-back bitmask (`CPU_SEC_*`).
// SAFETY: Caller must execute at CPL=0 in 64-bit Long Mode where all supervisor pages have `PTE_U = 0`.
pub(crate) unsafe fn enable_cpu_memory_protections() -> u32 {
    let max_leaf: u32;
    // SAFETY: CPUID leaf 0 is supported on all x86-64 CPUs; `rbx` is preserved across `cpuid`.
    unsafe {
        asm!(
            "push rbx",
            "xor eax, eax",
            "cpuid",
            "pop rbx",
            out("eax") max_leaf,
            out("ecx") _,
            out("edx") _,
            options(nomem, preserves_flags),
        );
    }
    let (has_fsgsbase, has_smep, has_smap, has_umip) = if max_leaf >= 7 {
        let ebx_7: u32;
        let ecx_7: u32;
        // SAFETY: `max_leaf >= 7` verified leaf 7 support; `rbx` is saved in `r9` and restored.
        unsafe {
            asm!(
                "mov r9, rbx",
                "mov eax, 7",
                "xor ecx, ecx",
                "cpuid",
                "mov {out_ebx:e}, ebx",
                "mov rbx, r9",
                out_ebx = out(reg) ebx_7,
                out("eax") _,
                out("ecx") ecx_7,
                out("edx") _,
                out("r9") _,
                options(nomem, preserves_flags),
            );
        }
        (
            (ebx_7 & (1 << 0)) != 0,
            (ebx_7 & (1 << 7)) != 0,
            (ebx_7 & (1 << 20)) != 0,
            (ecx_7 & (1 << 2)) != 0,
        )
    } else {
        (false, false, false, false)
    };

    let mut active_mask: u32 = 0;

    // SAFETY: Setting IA32_EFER.NXE, CR0.WP, and CPUID-verified CR4 security controls at CPL=0.
    unsafe {
        let mut efer_lo: u32;
        let efer_hi: u32;
        asm!(
            "mov ecx, 0xC0000080",
            "rdmsr",
            out("ecx") _,
            out("eax") efer_lo,
            out("edx") efer_hi,
            options(nomem, nostack, preserves_flags),
        );
        if (efer_lo & (1 << 11)) == 0 {
            let new_lo = efer_lo | (1 << 11);
            asm!(
                "mov ecx, 0xC0000080",
                "wrmsr",
                in("eax") new_lo,
                in("edx") efer_hi,
                out("ecx") _,
                options(nomem, nostack, preserves_flags),
            );
            asm!(
                "mov ecx, 0xC0000080",
                "rdmsr",
                out("ecx") _,
                out("eax") efer_lo,
                out("edx") _,
                options(nomem, nostack, preserves_flags),
            );
        }
        if (efer_lo & (1 << 11)) != 0 {
            active_mask |= CPU_SEC_NXE;
        }

        let mut cr0_val: u64;
        asm!("mov {}, cr0", out(reg) cr0_val, options(nomem, nostack, preserves_flags));
        if (cr0_val & (1 << 16)) == 0 {
            cr0_val |= 1 << 16;
            asm!("mov cr0, {}", in(reg) cr0_val, options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr0", out(reg) cr0_val, options(nomem, nostack, preserves_flags));
        }
        if (cr0_val & (1 << 16)) != 0 {
            active_mask |= CPU_SEC_WP;
        }

        let mut cr4_want: u64 = 0;
        if has_umip {
            cr4_want |= 1 << 11;
        }
        if has_fsgsbase {
            cr4_want |= 1 << 16;
        }
        if has_smep {
            cr4_want |= 1 << 20;
        }
        if has_smap {
            cr4_want |= 1 << 21;
            // Clear RFLAGS.AC (`clac` = 0F 01 CA) BEFORE enabling CR4.SMAP so supervisor mode
            // immediately blocks any accidental user-page (`PTE_U = 1`) dereference!
            asm!(".byte 0x0f, 0x01, 0xca", options(nomem, nostack));
        }
        let mut cr4_val: u64;
        asm!("mov {}, cr4", out(reg) cr4_val, options(nomem, nostack, preserves_flags));
        if (cr4_val & cr4_want) != cr4_want {
            cr4_val |= cr4_want;
            asm!("mov cr4, {}", in(reg) cr4_val, options(nomem, nostack, preserves_flags));
            asm!("mov {}, cr4", out(reg) cr4_val, options(nomem, nostack, preserves_flags));
        }
        if (cr4_val & (1 << 20)) != 0 {
            active_mask |= CPU_SEC_SMEP;
        }
        if (cr4_val & (1 << 21)) != 0 {
            active_mask |= CPU_SEC_SMAP;
        }
        if (cr4_val & (1 << 16)) != 0 {
            active_mask |= CPU_SEC_FSGSBASE;
        }
        if (cr4_val & (1 << 11)) != 0 {
            active_mask |= CPU_SEC_UMIP;
        }
    }

    ACTIVE_CPU_SEC_BITS.fetch_or(active_mask, core::sync::atomic::Ordering::Release);
    active_mask
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct Ring3ExecOutcome {
    pub(crate) user_va: u64,
    pub(crate) kernel_cr3: u64,
    pub(crate) user_cr3: u64,
    pub(crate) observed_cr3: u64,
    pub(crate) pid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Ring3FaultOutcome {
    SetupFailed,
    CpuException {
        vec: u8,
        err_code: u64,
        cr2: u64,
        frame_cs: u16,
        user_va: u64,
        user_cr3: u64,
        observed_cr3: u64,
    },
    Preempted {
        rip: u64,
        frame_cs: u16,
        observed_cr3: u64,
    },
    MailboxOrTrapMismatch,
    SyscallDenied(target_enterprise::syscall::Errno),
}

/// Execute a 32-byte x86-64 Ring-3 (`CPL=3`) machine-code stub inside a dedicated hardware
/// `CR3`-isolated 4-level user page-table hierarchy (`user_pml4_phys`, zero higher-half kernel
/// PML4 entries) enforcing strict `W^X` (`PT[0]` User RX, `PT[1]` unmapped guard page,
/// `PT[2]` User RW+NX stack/mailbox, `PT[3]` Supervisor RX trampoline, `PT[4]` Supervisor RW+NX
/// GDT/TSS/state/stacks, `PT[5]` Supervisor RO+NX IDT), full IDT `0..31` Ring-3 fault recovery,
/// and per-task capability-gated syscall dispatch (`dispatch_syscall(task_id, cap_mask, ...)`).
#[inline(never)]
pub(crate) fn exec_service_ring3_stub_isolated(
    task_id: u64,
    cap_mask: u64,
    ring3_code: &[u8; 32],
    mailbox_req_word: u64,
    expected_arg0: u64,
    corrupt_canary: bool,
) -> Result<Ring3ExecOutcome, Ring3FaultOutcome> {
    exec_service_ring3_stub_with_opts(
        task_id,
        cap_mask,
        ring3_code,
        mailbox_req_word,
        expected_arg0,
        corrupt_canary,
        None,
    )
}

struct MailboxWorkerStaging<'a> {
    canary: u32,
    strict_vfs: bool,
    path: &'a [u8],
    body: &'a [u8],
}

#[inline(never)]
pub(crate) fn exec_service_ring3_stub_with_opts(
    task_id: u64,
    cap_mask: u64,
    ring3_code: &[u8; 32],
    mailbox_req_word: u64,
    expected_arg0: u64,
    corrupt_canary: bool,
    preempt_timer_ticks: Option<u32>,
) -> Result<Ring3ExecOutcome, Ring3FaultOutcome> {
    exec_service_ring3_core(
        task_id,
        cap_mask,
        ring3_code,
        mailbox_req_word,
        expected_arg0,
        corrupt_canary,
        preempt_timer_ticks,
        None,
    )
}

#[inline(never)]
#[allow(clippy::too_many_arguments)]
fn exec_service_ring3_core(
    task_id: u64,
    cap_mask: u64,
    ring3_code: &[u8],
    mailbox_req_word: u64,
    expected_arg0: u64,
    corrupt_canary: bool,
    preempt_timer_ticks: Option<u32>,
    mut worker_staging: Option<(MailboxWorkerStaging<'_>, &mut (u64, u32))>,
) -> Result<Ring3ExecOutcome, Ring3FaultOutcome> {
    use target_enterprise::gdt::{
        Gdt, Tss64, KERNEL_CODE_SEL, KERNEL_DATA_SEL, TSS64_LEN, TSS_SEL, USER_CODE_SEL,
        USER_DATA_SEL,
    };
    use target_enterprise::interrupts::{
        vectors, Idt, IDT_LEN, TYPE_INTERRUPT_GATE_DPL0, TYPE_INTERRUPT_GATE_DPL3,
        TYPE_TRAP_GATE_DPL0,
    };
    use target_enterprise::kpti::x86_pml4::{
        serialize_isolated_user_4level, IsolatedUserSandboxSpec, PML4_BYTES,
    };
    use target_enterprise::syscall::{dispatch_syscall, set_task_cap_mask};

    const LAPIC_BASE: u64 = 0xFEE0_0000;
    const LAPIC_TPR_OFF: u64 = 0x0080;
    const LAPIC_EOI_OFF: u64 = 0x00B0;
    const LAPIC_SVR_OFF: u64 = 0x00F0;
    const LAPIC_LVT_TIMER_OFF: u64 = 0x0320;
    const LAPIC_TIMER_INIT_OFF: u64 = 0x0380;
    const LAPIC_TIMER_DIV_OFF: u64 = 0x03E0;
    const PREEMPT_TIMER_VEC: u8 = 0x40;

    let dma = dma_phys_base();
    if dma == 0 || phys_map_offset() == 0 {
        return Err(Ring3FaultOutcome::SetupFailed);
    }

    // SAFETY: Running at CPL=0 in 64-bit Long Mode.
    unsafe {
        enable_cpu_memory_protections();
        if preempt_timer_ticks.is_some() {
            let _ = crate::ensure_mmio_page(LAPIC_BASE);
        }
    }

    // 9 dedicated 4 KiB physical frames in `dma + 0x2_4000 .. dma + 0x2_D000`:
    //   +0x2_4000: `user_pml4_phys` — Dedicated isolated user `CR3` PML4 (higher-half slots 256..512 all 0!)
    //   +0x2_5000: `pdpt_phys`
    //   +0x2_6000: `pd_phys`
    //   +0x2_7000: `pt_phys`
    //   +0x2_8000: `user_code_phys` (`PT[0]`: User RX only)
    //   +0x2_9000: `user_data_phys` (`PT[2]`: User RW+NX stack + IPC mailbox; `PT[1]` = unmapped guard page)
    //   +0x2_A000: `tramp_phys`     (`PT[3]`: Supervisor RX entry/exit/fault trampolines)
    //   +0x2_B000: `idt_phys`       (`PT[5]`: Supervisor RO+NX 256-entry IDT)
    //   +0x2_C000: `gdt_phys`       (`PT[4]`: Supervisor RW+NX GDT/TSS/state/`RSP0`/`IST1`)
    let user_pml4_phys = dma + 0x2_4000;
    let pdpt_phys = dma + 0x2_5000;
    let pd_phys = dma + 0x2_6000;
    let pt_phys = dma + 0x2_7000;
    let user_code_phys = dma + 0x2_8000;
    let user_data_phys = dma + 0x2_9000;
    let tramp_phys = dma + 0x2_A000;
    let idt_phys = dma + 0x2_B000;
    let gdt_phys = dma + 0x2_C000;

    // Zero all 9 frames (`9 * 4096 = 0x9000` bytes).
    // SAFETY: `user_pml4_phys .. user_pml4_phys + 0x9000` is reserved exclusively in the 256 KiB DMA window.
    unsafe {
        let base_ptr = pa_to_va(user_pml4_phys);
        let mut i = 0usize;
        while i < 0x9000 {
            core::ptr::write_volatile(base_ptr.add(i), 0);
            i += 1;
        }
    }

    // Find an unused lower-half PML4 slot (`64..256`) in the active kernel PML4 so `PT[3..5]`
    // share identical supervisor virtual addresses across `kernel_cr3` and `user_pml4_phys`
    // during the `mov cr3` transition, while higher-half `256..512` remain 100% absent from `user_pml4_phys`.
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active 4-level kernel PML4 physical address.
    let kernel_cr3 = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let kernel_pml4_va = pa_to_va(kernel_cr3) as *mut u64;
    let mut pml4_idx: Option<usize> = None;
    let mut idx = 64usize;
    while idx < 256 {
        // SAFETY: `kernel_pml4_va` points to the 512-entry active kernel PML4 mapped via `pa_to_va`.
        let entry = unsafe { core::ptr::read_volatile(kernel_pml4_va.add(idx)) };
        if entry == 0 {
            pml4_idx = Some(idx);
            break;
        }
        idx += 1;
    }
    let Some(pml4_slot) = pml4_idx else {
        return Err(Ring3FaultOutcome::SetupFailed);
    };

    let user_va: u64 = (pml4_slot as u64) << 39;
    let user_rsp: u64 = user_va + 0x2FF0; // Top of PT[2] (above unmapped PT[1] guard page!)
    let kernel_trampoline_va: u64 = user_va + 0x3000; // PT[3] Supervisor RX
    let shared_sup_rw_va: u64 = user_va + 0x4000; // PT[4] Supervisor RW+NX
    let shared_idt_va: u64 = user_va + 0x5000; // PT[5] Supervisor RO+NX

    let spec = IsolatedUserSandboxSpec {
        user_va,
        pdpt_phys,
        pd_phys,
        pt_phys,
        user_code_phys,
        user_data_phys,
        tramp_phys,
        gdt_phys,
        idt_phys,
    };

    // Materialize and `W^X`-validate the 4-level isolated user CR3 tables directly in the physical frames.
    // SAFETY: Each of the 4 physical frames is a distinct 4 KiB page in the reserved DMA window.
    let ser_res = unsafe {
        let pml4_buf = &mut *(pa_to_va(user_pml4_phys) as *mut [u8; PML4_BYTES]);
        let pdpt_buf = &mut *(pa_to_va(pdpt_phys) as *mut [u8; PML4_BYTES]);
        let pd_buf = &mut *(pa_to_va(pd_phys) as *mut [u8; PML4_BYTES]);
        let pt_buf = &mut *(pa_to_va(pt_phys) as *mut [u8; PML4_BYTES]);
        serialize_isolated_user_4level(&spec, None, pml4_buf, pdpt_buf, pd_buf, pt_buf)
    };
    if ser_res != Ok(pml4_slot) {
        return Err(Ring3FaultOutcome::SetupFailed);
    }

    // Temporarily alias `PML4[pml4_slot] -> pdpt_phys` into `kernel_cr3` so `PT[3..5]` are
    // reachable at identical virtual addresses across `mov cr3, user_pml4_phys` and back.
    const PTE_U: u64 = 1 << 2;
    // SAFETY: `pml4_slot` in `kernel_pml4_va` was verified empty and `pdpt_phys` is initialized.
    unsafe {
        core::ptr::write_volatile(
            kernel_pml4_va.add(pml4_slot),
            pdpt_phys | PTE_P | PTE_W | PTE_U,
        );
        let mut p = 0u64;
        while p < 6 {
            let flush_va = user_va + p * 0x1000;
            asm!("invlpg [{}]", in(reg) flush_va, options(nostack, preserves_flags));
            p += 1;
        }
    }

    // Populate `user_code_phys` (`PT[0]`) with `ring3_code`, and `user_data_phys` (`PT[2]`)
    // with either the structured mailbox sanitizer page or `[user_rsp - 0x20]` request word.
    let planted_req = if corrupt_canary {
        mailbox_req_word ^ 0xDEAD_BEEF_0000_0000
    } else {
        mailbox_req_word
    };
    let code_len = ring3_code.len().min(4096);
    // SAFETY: `user_code_phys` and `user_data_phys` are dedicated 4 KiB frames mapped RW in `PHYS_MAP_OFFSET`.
    unsafe {
        let code_dst = pa_to_va(user_code_phys);
        let mut i = 0usize;
        while i < code_len {
            core::ptr::write_volatile(code_dst.add(i), ring3_code[i]);
            i += 1;
        }
        let data_dst = pa_to_va(user_data_phys);
        if let Some((ref stg, _)) = worker_staging {
            let can_b = stg.canary.to_le_bytes();
            let plen = stg.path.len().min(64);
            let blen = stg.body.len().min(512);
            let blen_b = (blen as u16).to_le_bytes();
            let mut c = 0usize;
            while c < 4 {
                core::ptr::write_volatile(data_dst.add(c), can_b[c]);
                core::ptr::write_volatile(data_dst.add(0x260 + c), can_b[c]);
                c += 1;
            }
            core::ptr::write_volatile(data_dst.add(0x04), u8::from(stg.strict_vfs));
            core::ptr::write_volatile(data_dst.add(0x05), plen as u8);
            core::ptr::write_volatile(data_dst.add(0x06), blen_b[0]);
            core::ptr::write_volatile(data_dst.add(0x07), blen_b[1]);
            let mut pi = 0usize;
            while pi < plen {
                core::ptr::write_volatile(data_dst.add(0x10 + pi), stg.path[pi]);
                pi += 1;
            }
            let mut bi = 0usize;
            while bi < blen {
                core::ptr::write_volatile(data_dst.add(0x50 + bi), stg.body[bi]);
                bi += 1;
            }
        } else {
            let req_bytes = planted_req.to_le_bytes();
            let mut k = 0usize;
            while k < 8 {
                core::ptr::write_volatile(data_dst.add(0xFD0 + k), req_bytes[k]);
                k += 1;
            }
        }
    }

    // Populate Ring-0 Supervisor RX trampolines in `tramp_phys` (`user_va + 0x3000`; `state_va = user_va + 0x4200`):
    // 1) `+0x000`: `isr_breakpoint_ist1` (Vector 3 `#BP`, `DPL=0`, `IST=1`)
    let isr_bp_code: [u8; 18] = [
        0x50,                                     // push rax
        0x48, 0x8D, 0x05, 0xF8, 0x11, 0x00, 0x00, // lea rax, [rip + 0x11F8] -> user_va + 0x4200
        0x48, 0xFF, 0x00,                         // inc qword ptr [rax]
        0x48, 0x89, 0x60, 0x08,                   // mov [rax + 0x08], rsp
        0x58,                                     // pop rax
        0x48, 0xCF,                               // iretq
    ];
    // 2) `+0x040`: `entry_to_ring3` (saves `saved_kernel_rsp` & `kernel_cr3`, pivots `RSP` to `rsp0_top`,
    //    switches hardware `CR3` to `user_pml4_phys`, pushes `user_rflags` from `[rax + 0x90]`, scrubs GPRs, and `iretq`s)
    let entry_to_ring3_code: [u8; 56] = [
        0x48, 0x8D, 0x05, 0xB9, 0x11, 0x00, 0x00, // lea rax, [rip + 0x11B9] -> user_va + 0x4200
        0x48, 0x89, 0x60, 0x10,                   // mov [rax + 0x10], rsp (saved_kernel_rsp)
        0x0F, 0x20, 0xD9,                         // mov rcx, cr3
        0x48, 0x89, 0x48, 0x18,                   // mov [rax + 0x18], rcx (kernel_cr3)
        0x48, 0x8D, 0xA0, 0x00, 0x06, 0x00, 0x00, // lea rsp, [rax + 0x600] (rsp0_top = user_va + 0x4800)
        0x48, 0x8B, 0x48, 0x50,                   // mov rcx, [rax + 0x50] (user_cr3)
        0x0F, 0x22, 0xD9,                         // mov cr3, rcx (SWITCH TO ISOLATED USER CR3!)
        0x6A, USER_DATA_SEL as u8,                // push USER_DATA_SEL (0x1B)
        0x56,                                     // push rsi (user_rsp)
        0xFF, 0xB0, 0x90, 0x00, 0x00, 0x00,       // push qword ptr [rax + 0x90] (0x02 or 0x202 IF=1)
        0x6A, USER_CODE_SEL as u8,                // push USER_CODE_SEL (0x23)
        0x57,                                     // push rdi (user_va)
        0x31, 0xC0,                               // xor eax, eax
        0x31, 0xC9,                               // xor ecx, ecx
        0x31, 0xD2,                               // xor edx, edx
        0x31, 0xF6,                               // xor esi, esi
        0x31, 0xFF,                               // xor edi, edi
        0x48, 0xCF,                               // iretq -> CPL=3!
    ];
    // 3) `+0x080`: `isr_syscall_int80` (Vector `0x80`, `DPL=3`, `IST=0`: records Ring-3 state + active `CR3`,
    //    switches hardware `CR3` back to `kernel_cr3`, restores `SS` + `saved_kernel_rsp`, `ret`)
    let isr_int80_code: [u8; 67] = [
        0x48, 0x8D, 0x05, 0x79, 0x11, 0x00, 0x00, // lea rax, [rip + 0x1179] -> user_va + 0x4200
        0x48, 0x89, 0x70, 0x20,                   // mov [rax + 0x20], rsi (r3_cs)
        0x48, 0x8B, 0x4C, 0x24, 0x08,             // mov rcx, [rsp + 0x08] (frame_cs)
        0x48, 0x89, 0x48, 0x28,                   // mov [rax + 0x28], rcx
        0x48, 0x8B, 0x4C, 0x24, 0x20,             // mov rcx, [rsp + 0x20] (frame_ss)
        0x48, 0x89, 0x48, 0x30,                   // mov [rax + 0x30], rcx
        0x48, 0x89, 0x78, 0x38,                   // mov [rax + 0x38], rdi (sys_nr)
        0x48, 0x89, 0x50, 0x40,                   // mov [rax + 0x40], rdx (sys_arg0)
        0x48, 0x89, 0x60, 0x48,                   // mov [rax + 0x48], rsp (trap_rsp)
        0x0F, 0x20, 0xD9,                         // mov rcx, cr3
        0x48, 0x89, 0x48, 0x58,                   // mov [rax + 0x58], rcx (observed_active_cr3)
        0x48, 0x8B, 0x48, 0x18,                   // mov rcx, [rax + 0x18] (kernel_cr3)
        0x0F, 0x22, 0xD9,                         // mov cr3, rcx (RESTORE KERNEL CR3!)
        0xB9, 0x10, 0x00, 0x00, 0x00,             // mov ecx, 0x10
        0x8E, 0xD1,                               // mov ss, cx
        0x48, 0x8B, 0x60, 0x10,                   // mov rsp, [rax + 0x10] (saved_kernel_rsp)
        0xC3,                                     // ret
    ];
    // 4) `+0x300`: `common_fault_handler` for CPU exceptions `0..31` triggered in Ring-3
    let common_fault_code: [u8; 74] = [
        0x48, 0x8D, 0x05, 0xF9, 0x0E, 0x00, 0x00,             // lea rax, [rip + 0x0EF9] -> user_va + 0x4200
        0x48, 0xC7, 0x40, 0x60, 0x01, 0x00, 0x00, 0x00,       // mov qword ptr [rax + 0x60], 1 (fault_flag)
        0x48, 0x8B, 0x0C, 0x24,                               // mov rcx, [rsp] (vec)
        0x48, 0x89, 0x48, 0x68,                               // mov [rax + 0x68], rcx (fault_vec)
        0x48, 0x8B, 0x4C, 0x24, 0x08,                         // mov rcx, [rsp + 0x08] (err_code)
        0x48, 0x89, 0x48, 0x78,                               // mov [rax + 0x78], rcx (fault_err_code)
        0x0F, 0x20, 0xD1,                                     // mov rcx, cr2
        0x48, 0x89, 0x48, 0x70,                               // mov [rax + 0x70], rcx (fault_cr2)
        0x48, 0x8B, 0x4C, 0x24, 0x18,                         // mov rcx, [rsp + 0x18] (frame_cs)
        0x48, 0x89, 0x48, 0x28,                               // mov [rax + 0x28], rcx
        0x0F, 0x20, 0xD9,                                     // mov rcx, cr3
        0x48, 0x89, 0x48, 0x58,                               // mov [rax + 0x58], rcx (observed_active_cr3)
        0x48, 0x8B, 0x48, 0x18,                               // mov rcx, [rax + 0x18] (kernel_cr3)
        0x0F, 0x22, 0xD9,                                     // mov cr3, rcx (RESTORE KERNEL CR3!)
        0xB9, 0x10, 0x00, 0x00, 0x00,                         // mov ecx, 0x10
        0x8E, 0xD1,                                           // mov ss, cx
        0x48, 0x8B, 0x60, 0x10,                               // mov rsp, [rax + 0x10] (saved_kernel_rsp)
        0xC3,                                                 // ret
    ];

    // 5) `+0x360`: `isr_preempt_timer` (Vector `0x40`, `DPL=0`, `IST=0`: evicts runaway Ring-3 code
    //    upon Local APIC timer expiry while `user_pml4_phys` is loaded in `CR3`, restores `kernel_cr3` + `RSP`)
    let isr_preempt_timer: [u8; 64] = [
        0x48, 0x8D, 0x05, 0x99, 0x0E, 0x00, 0x00,                   // lea rax, [rip + 0x0E99] -> user_va + 0x4200
        0x48, 0xC7, 0x80, 0x80, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, // mov qword ptr [rax + 0x80], 1
        0x48, 0x8B, 0x0C, 0x24,                                     // mov rcx, [rsp] (interrupted RIP)
        0x48, 0x89, 0x88, 0x88, 0x00, 0x00, 0x00,                   // mov [rax + 0x88], rcx
        0x48, 0x8B, 0x4C, 0x24, 0x08,                               // mov rcx, [rsp + 0x08] (frame_cs)
        0x48, 0x89, 0x48, 0x28,                                     // mov [rax + 0x28], rcx
        0x0F, 0x20, 0xD9,                                           // mov rcx, cr3
        0x48, 0x89, 0x48, 0x58,                                     // mov [rax + 0x58], rcx (observed_active_cr3)
        0x48, 0x8B, 0x48, 0x18,                                     // mov rcx, [rax + 0x18] (kernel_cr3)
        0x0F, 0x22, 0xD9,                                           // mov cr3, rcx (RESTORE KERNEL CR3!)
        0xB9, 0x10, 0x00, 0x00, 0x00,                               // mov ecx, 0x10
        0x8E, 0xD1,                                                 // mov ss, cx
        0x48, 0x8B, 0x60, 0x10,                                     // mov rsp, [rax + 0x10] (saved_kernel_rsp)
        0xC3,                                                       // ret
    ];
    // 6) `+0x3B0`: benign `iretq` for spurious vector `0xFF`
    let isr_spurious_code: [u8; 2] = [0x48, 0xCF];

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

    // SAFETY: `tramp_phys` is a dedicated 4 KiB frame mapped RW in `PHYS_MAP_OFFSET`.
    unsafe {
        let dst = pa_to_va(tramp_phys);
        let mut i = 0usize;
        while i < isr_bp_code.len() {
            core::ptr::write_volatile(dst.add(i), isr_bp_code[i]);
            i += 1;
        }
        let mut e = 0usize;
        while e < entry_to_ring3_code.len() {
            core::ptr::write_volatile(dst.add(0x40 + e), entry_to_ring3_code[e]);
            e += 1;
        }
        let mut j = 0usize;
        while j < isr_int80_code.len() {
            core::ptr::write_volatile(dst.add(0x80 + j), isr_int80_code[j]);
            j += 1;
        }
        let mut c = 0usize;
        while c < common_fault_code.len() {
            core::ptr::write_volatile(dst.add(0x300 + c), common_fault_code[c]);
            c += 1;
        }
        let mut pt = 0usize;
        while pt < isr_preempt_timer.len() {
            core::ptr::write_volatile(dst.add(0x360 + pt), isr_preempt_timer[pt]);
            pt += 1;
        }
        core::ptr::write_volatile(dst.add(0x3B0), isr_spurious_code[0]);
        core::ptr::write_volatile(dst.add(0x3B1), isr_spurious_code[1]);
        let mut v = 0usize;
        while v < 32 {
            if v != (vectors::BREAKPOINT as usize) {
                let stub_off = 0x100 + v * 16;
                let mut pos = stub_off;
                if (HAS_ERR_CODE_MASK & (1u32 << v)) == 0 {
                    core::ptr::write_volatile(dst.add(pos), 0x6A); // push 0
                    core::ptr::write_volatile(dst.add(pos + 1), 0x00);
                    pos += 2;
                }
                core::ptr::write_volatile(dst.add(pos), 0x6A); // push vec
                core::ptr::write_volatile(dst.add(pos + 1), v as u8);
                pos += 2;
                let rel32 = (0x300i32 - ((pos + 5) as i32)).to_le_bytes();
                core::ptr::write_volatile(dst.add(pos), 0xE9); // jmp common_fault_handler
                core::ptr::write_volatile(dst.add(pos + 1), rel32[0]);
                core::ptr::write_volatile(dst.add(pos + 2), rel32[1]);
                core::ptr::write_volatile(dst.add(pos + 3), rel32[2]);
                core::ptr::write_volatile(dst.add(pos + 4), rel32[3]);
            }
            v += 1;
        }
    }

    // Build GDT, 64-bit TSS, state block, and 256-entry IDT using the shared lower-half supervisor VAs
    // (`shared_sup_rw_va = user_va + 0x4000`, `shared_idt_va = user_va + 0x5000`) so `GDTR`, `TSS`,
    // `RSP0`, `IST1`, and `IDTR` remain valid while `user_pml4_phys` is loaded in `CR3`!
    let gdt_va = shared_sup_rw_va;
    let gdtr_new_va = shared_sup_rw_va + 0x040;
    let idtr_new_va = shared_sup_rw_va + 0x050;
    let gdtr_orig_va = shared_sup_rw_va + 0x060;
    let idtr_orig_va = shared_sup_rw_va + 0x070;
    let tss_va = shared_sup_rw_va + 0x100;
    let rsp0_top = shared_sup_rw_va + 0x800;
    let ist1_top = shared_sup_rw_va + 0x1000;

    let tss = Tss64::with_stacks(rsp0_top, ist1_top);
    let tss_bytes = tss.to_bytes();
    let gdt = Gdt::new_full(tss_va, (TSS64_LEN - 1) as u32);
    let gdt_bytes = gdt.to_table_bytes();

    let mut idt = Idt::new_empty();
    let mut exc_v = 0u8;
    while exc_v < 32 {
        if exc_v == vectors::BREAKPOINT {
            idt.set_handler_with_attr(exc_v, kernel_trampoline_va, TYPE_TRAP_GATE_DPL0, 1);
        } else {
            let ist = if exc_v == 8 { 1 } else { 0 };
            idt.set_handler_with_attr(
                exc_v,
                kernel_trampoline_va + 0x100 + ((exc_v as u64) * 16),
                TYPE_INTERRUPT_GATE_DPL0,
                ist,
            );
        }
        exc_v += 1;
    }
    idt.set_handler_with_attr(
        PREEMPT_TIMER_VEC,
        kernel_trampoline_va + 0x360,
        TYPE_INTERRUPT_GATE_DPL0,
        0,
    );
    idt.set_handler_with_attr(
        0xFF,
        kernel_trampoline_va + 0x3B0,
        TYPE_INTERRUPT_GATE_DPL0,
        0,
    );
    idt.set_handler_with_attr(
        vectors::SYSCALL_INT,
        kernel_trampoline_va + 0x80,
        TYPE_INTERRUPT_GATE_DPL3,
        0,
    );

    let user_rflags: u64 = if preempt_timer_ticks.is_some() {
        0x202
    } else {
        0x02
    };

    // SAFETY: `gdt_phys` and `idt_phys` are dedicated 4 KiB frames mapped RW in `PHYS_MAP_OFFSET`.
    unsafe {
        let gdt_phys_ptr = pa_to_va(gdt_phys);
        let mut i = 0usize;
        while i < gdt_bytes.len() {
            core::ptr::write_volatile(gdt_phys_ptr.add(i), gdt_bytes[i]);
            i += 1;
        }
        let tss_ptr = gdt_phys_ptr.add(0x100);
        let mut j = 0usize;
        while j < tss_bytes.len() {
            core::ptr::write_volatile(tss_ptr.add(j), tss_bytes[j]);
            j += 1;
        }
        // Seed `state[10]` (`+0x250`) with `user_pml4_phys` and `state[18]` (`+0x290`) with `user_rflags`.
        core::ptr::write_volatile(
            gdt_phys_ptr.add(0x250).cast::<u64>(),
            user_pml4_phys,
        );
        core::ptr::write_volatile(gdt_phys_ptr.add(0x290).cast::<u64>(), user_rflags);

        let idt_phys_ptr = pa_to_va(idt_phys);
        let mut v = 0usize;
        while v < IDT_LEN {
            let entry_bytes = idt.raw_bytes(v as u8);
            let mut k = 0usize;
            while k < 16 {
                core::ptr::write_volatile(idt_phys_ptr.add(v * 16 + k), entry_bytes[k]);
                k += 1;
            }
            v += 1;
        }

        let gdt_limit: u16 = (Gdt::byte_size() - 1) as u16;
        let idt_limit: u16 = (Idt::byte_size() - 1) as u16;
        let gdtr_ptr = gdt_phys_ptr.add(0x040);
        let gdt_lim_b = gdt_limit.to_le_bytes();
        let gdt_base_b = gdt_va.to_le_bytes();
        core::ptr::write_volatile(gdtr_ptr.add(0), gdt_lim_b[0]);
        core::ptr::write_volatile(gdtr_ptr.add(1), gdt_lim_b[1]);
        let mut b = 0usize;
        while b < 8 {
            core::ptr::write_volatile(gdtr_ptr.add(2 + b), gdt_base_b[b]);
            b += 1;
        }

        let idtr_ptr = gdt_phys_ptr.add(0x050);
        let idt_lim_b = idt_limit.to_le_bytes();
        let idt_base_b = shared_idt_va.to_le_bytes();
        core::ptr::write_volatile(idtr_ptr.add(0), idt_lim_b[0]);
        core::ptr::write_volatile(idtr_ptr.add(1), idt_lim_b[1]);
        let mut b2 = 0usize;
        while b2 < 8 {
            core::ptr::write_volatile(idtr_ptr.add(2 + b2), idt_base_b[b2]);
            b2 += 1;
        }
    }

    let entry_stub_va = kernel_trampoline_va + 0x040;

    // Save/arm Local APIC one-shot preemption timer when requested (with legacy 8259 PIC masked).
    let mut saved_lvt_timer: u32 = 0;
    let mut saved_timer_init: u32 = 0;
    // SAFETY: Running at CPL=0; `LAPIC_BASE` was mapped above when `preempt_timer_ticks.is_some()`.
    unsafe {
        if let Some(ticks) = preempt_timer_ticks {
            asm!("cli", options(nomem, nostack, preserves_flags));
            crate::outb(0x20, 0x11);
            crate::outb(0xA0, 0x11);
            crate::outb(0x21, 0x20);
            crate::outb(0xA1, 0x28);
            crate::outb(0x21, 0x04);
            crate::outb(0xA1, 0x02);
            crate::outb(0x21, 0x01);
            crate::outb(0xA1, 0x01);
            crate::outb(0x21, 0xFF);
            crate::outb(0xA1, 0xFF);
            crate::outb(0x3F9, 0x00);

            saved_lvt_timer = crate::mmio_read32(LAPIC_BASE + LAPIC_LVT_TIMER_OFF);
            saved_timer_init = crate::mmio_read32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF);
            let svr = crate::mmio_read32(LAPIC_BASE + LAPIC_SVR_OFF);
            crate::mmio_write32(LAPIC_BASE + LAPIC_SVR_OFF, svr | 0x1FF);
            crate::mmio_write32(LAPIC_BASE + LAPIC_TPR_OFF, 0);
            crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_DIV_OFF, 0x03);
            crate::mmio_write32(
                LAPIC_BASE + LAPIC_LVT_TIMER_OFF,
                PREEMPT_TIMER_VEC as u32,
            );
            crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF, ticks.max(64));
        }
    }

    // Execute live GDT/TSS/IDT load, `int3` on `IST1`, and hardware `CR3`-isolated Ring-3 round-trip.
    // Preserve all live kernel & callee-saved GPRs on the kernel stack across `call r8` and scrub
    // upper GPRs before entering Ring-3 so untrusted `CPL=3` code sees zero kernel register state
    // and cannot corrupt kernel recovery even if it clobbers every GPR (`rax..r15`, `rbx`, `rbp`).
    // SAFETY: Interrupts are masked (`cli`); `entry_stub_va` switches `CR3` to `user_pml4_phys` and
    // `isr_syscall_int80` / `common_fault_handler` / `isr_preempt_timer` restores `kernel_cr3` before returning here.
    unsafe {
        asm!(
            "pushfq",
            "pop r15",
            "cli",
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
            "int3",
            "push rbx",
            "push rbp",
            "push r9",
            "push r10",
            "push r13",
            "push r14",
            "push r15",
            "xor ebx, ebx",
            "xor ebp, ebp",
            "xor r9d, r9d",
            "xor r10d, r10d",
            "xor r11d, r11d",
            "xor r12d, r12d",
            "xor r13d, r13d",
            "xor r14d, r14d",
            "xor r15d, r15d",
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
            "lea rax, [rip + 5f]",
            "push rax",
            "retfq",
            "5:",
            "mov ss, r14w",
            "xor eax, eax",
            "mov ds, ax",
            "mov es, ax",
            "lidt [r10]",
            "push r15",
            "popfq",
            inout("r8") entry_stub_va => _,
            inout("r9") gdtr_orig_va => _,
            inout("r10") idtr_orig_va => _,
            inout("r11") gdtr_new_va => _,
            inout("r12") idtr_new_va => _,
            inout("rsi") user_rsp => _,
            inout("rdi") user_va => _,
            out("rax") _,
            out("rcx") _,
            out("rdx") _,
            out("r13") _,
            out("r14") _,
            out("r15") _,
            k_cs = const (KERNEL_CODE_SEL as u64),
            k_ds = const (KERNEL_DATA_SEL as u32),
            tss_sel = const (TSS_SEL as u32),
            clobber_abi("C"),
        );
    }

    // Disarm/EOI one-shot preemption timer and restore CPU 0's permanent guarded runtime TSS (`TR`).
    // SAFETY: Running at CPL=0 with `kernel_cr3` active.
    unsafe {
        if preempt_timer_ticks.is_some() {
            crate::mmio_write32(
                LAPIC_BASE + LAPIC_LVT_TIMER_OFF,
                0x0001_0000 | (PREEMPT_TIMER_VEC as u32),
            );
            crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF, 0);
            crate::mmio_write32(LAPIC_BASE + LAPIC_EOI_OFF, 0);
            if (saved_lvt_timer & 0x0002_0000) != 0 && saved_timer_init != 0 {
                crate::mmio_write32(LAPIC_BASE + LAPIC_LVT_TIMER_OFF, saved_lvt_timer);
                crate::mmio_write32(LAPIC_BASE + LAPIC_TIMER_INIT_OFF, saved_timer_init);
            }
        }
        crate::smp_hw::restore_cpu0_runtime_tss_if_active();
    }

    // Read back captured hardware state and tear down the temporary `kernel_pml4_va[pml4_slot]` alias.
    // SAFETY: `gdt_phys` and `user_data_phys` are mapped via `pa_to_va`, and `kernel_cr3` is active.
    let (
        bp_count,
        bp_rsp,
        r3_cs,
        frame_cs,
        frame_ss,
        sys_nr,
        sys_arg0,
        trap_rsp,
        observed_cr3,
        fault_flag,
        fault_vec,
        fault_cr2,
        fault_err,
        preempt_flag,
        preempt_rip,
        mb_resp,
        mb_fnv,
        mb_verdict,
    ) = unsafe {
        let st = pa_to_va(gdt_phys + 0x200) as *const u64;
        let user_ptr = pa_to_va(user_data_phys);
        let mut mb_bytes = [0u8; 8];
        let mut fnv_bytes = [0u8; 8];
        let mut m = 0usize;
        while m < 8 {
            mb_bytes[m] = core::ptr::read_volatile(user_ptr.add(0xFD8 + m));
            fnv_bytes[m] = core::ptr::read_volatile(user_ptr.add(0x268 + m));
            m += 1;
        }
        let mut verd_bytes = [0u8; 4];
        let mut v = 0usize;
        while v < 4 {
            verd_bytes[v] = core::ptr::read_volatile(user_ptr.add(0x270 + v));
            v += 1;
        }
        let vals = (
            core::ptr::read_volatile(st.add(0)),
            core::ptr::read_volatile(st.add(1)),
            core::ptr::read_volatile(st.add(4)),
            core::ptr::read_volatile(st.add(5)),
            core::ptr::read_volatile(st.add(6)),
            core::ptr::read_volatile(st.add(7)),
            core::ptr::read_volatile(st.add(8)),
            core::ptr::read_volatile(st.add(9)),
            core::ptr::read_volatile(st.add(11)) & PTE_ADDR_MASK,
            core::ptr::read_volatile(st.add(12)),
            core::ptr::read_volatile(st.add(13)),
            core::ptr::read_volatile(st.add(14)),
            core::ptr::read_volatile(st.add(15)),
            core::ptr::read_volatile(st.add(16)),
            core::ptr::read_volatile(st.add(17)),
            u64::from_le_bytes(mb_bytes),
            u64::from_le_bytes(fnv_bytes),
            u32::from_le_bytes(verd_bytes),
        );
        core::ptr::write_volatile(kernel_pml4_va.add(pml4_slot), 0);
        let mut p = 0u64;
        while p < 6 {
            let flush_va = user_va + p * 0x1000;
            asm!("invlpg [{}]", in(reg) flush_va, options(nostack, preserves_flags));
            p += 1;
        }
        vals
    };

    if bp_count != 1 || bp_rsp != ist1_top - 48 {
        return Err(Ring3FaultOutcome::SetupFailed);
    }
    if preempt_flag != 0 {
        return Err(Ring3FaultOutcome::Preempted {
            rip: preempt_rip,
            frame_cs: frame_cs as u16,
            observed_cr3,
        });
    }
    if fault_flag != 0 {
        return Err(Ring3FaultOutcome::CpuException {
            vec: fault_vec as u8,
            err_code: fault_err,
            cr2: fault_cr2,
            frame_cs: frame_cs as u16,
            user_va,
            user_cr3: user_pml4_phys,
            observed_cr3,
        });
    }
    if observed_cr3 != user_pml4_phys || observed_cr3 == kernel_cr3 {
        return Err(Ring3FaultOutcome::MailboxOrTrapMismatch);
    }
    if (frame_cs as u16) != USER_CODE_SEL
        || (frame_ss as u16) != USER_DATA_SEL
        || trap_rsp != rsp0_top - 40
    {
        return Err(Ring3FaultOutcome::MailboxOrTrapMismatch);
    }
    if let Some((_, ref mut out_pair)) = worker_staging {
        if sys_nr != 0x52 {
            return Err(Ring3FaultOutcome::MailboxOrTrapMismatch);
        }
        let verified_fnv = if mb_verdict == 1 && sys_arg0 == mb_fnv {
            mb_fnv
        } else {
            0
        };
        **out_pair = (verified_fnv, mb_verdict);
        return Ok(Ring3ExecOutcome {
            user_va,
            kernel_cr3,
            user_cr3: user_pml4_phys,
            observed_cr3,
            pid: task_id,
        });
    }
    if (r3_cs as u16) != USER_CODE_SEL {
        return Err(Ring3FaultOutcome::MailboxOrTrapMismatch);
    }
    let expected_resp = mailbox_req_word ^ expected_arg0;
    if sys_arg0 != expected_resp || mb_resp != expected_resp {
        return Err(Ring3FaultOutcome::MailboxOrTrapMismatch);
    }

    if set_task_cap_mask(task_id, cap_mask).is_err() {
        return Err(Ring3FaultOutcome::SyscallDenied(
            target_enterprise::syscall::Errno::EPERM,
        ));
    }
    let pid = match dispatch_syscall(task_id, cap_mask, sys_nr, sys_arg0, 0, 0, 0, 0, 0) {
        Ok(v) => v,
        Err(errno) => return Err(Ring3FaultOutcome::SyscallDenied(errno)),
    };
    if pid != 1 || pid.wrapping_add(sys_arg0) != 1u64.wrapping_add(expected_resp) {
        return Err(Ring3FaultOutcome::MailboxOrTrapMismatch);
    }
    Ok(Ring3ExecOutcome {
        user_va,
        kernel_cr3,
        user_cr3: user_pml4_phys,
        observed_cr3,
        pid,
    })
}

#[inline(never)]
pub(crate) fn exec_service_ring3_stub(
    ring3_code: &[u8; 32],
    mailbox_req_word: u64,
    expected_arg0: u64,
    corrupt_canary: bool,
) -> bool {
    exec_service_ring3_stub_isolated(
        1,
        0,
        ring3_code,
        mailbox_req_word,
        expected_arg0,
        corrupt_canary,
    )
    .is_ok()
}

/// Capability-aware hardware `CPL=3` execution callback registered on
/// [`target_enterprise::svc_runtime::ServiceSupervisor`] so every live mediated request executes
/// the target service's diversified x86-64 stub under an isolated `CR3` PML4 and bounded `cap_mask`.
pub(crate) fn exec_service_ring3_cap_live(
    svc: target_enterprise::svc_runtime::ServiceId,
    ring3_code: &[u8; 32],
    mailbox_req_word: u64,
    expected_arg0: u64,
    cap_mask: u64,
) -> bool {
    exec_service_ring3_stub_isolated(
        svc.pid() as u64,
        cap_mask,
        ring3_code,
        mailbox_req_word,
        expected_arg0,
        false,
    )
    .is_ok()
}

/// Bare-metal `CPL=3` (`CS=0x23`, isolated KPTI `user_pml4_phys`, `W^X` `User RX` + `User RW+NX`,
/// Local APIC `0x40` preemption armed) mailbox sanitizer & FNV-1a worker callback.
#[inline(never)]
pub(crate) fn exec_service_ring3_mailbox_live(
    svc: target_enterprise::svc_runtime::ServiceId,
    worker_code: &[u8],
    canary: u32,
    strict_vfs: bool,
    path: &[u8],
    body: &[u8],
    _expected_fnv: u64,
) -> target_enterprise::svc_runtime::Ring3MailboxHwVerdict {
    use target_enterprise::svc_runtime::Ring3MailboxHwVerdict;

    let mut out_pair: (u64, u32) = (0, 0);
    let stg = MailboxWorkerStaging {
        canary,
        strict_vfs,
        path,
        body,
    };
    let res = exec_service_ring3_core(
        svc.pid() as u64,
        svc.policy().cap_mask,
        worker_code,
        0,
        0,
        false,
        Some(20_000_000),
        Some((stg, &mut out_pair)),
    );
    match res {
        Ok(_) => match out_pair.1 {
            1 if out_pair.0 != 0 => Ring3MailboxHwVerdict::Ok(out_pair.0),
            2 => Ring3MailboxHwVerdict::RejectedPath,
            3 => Ring3MailboxHwVerdict::RejectedBody,
            _ => Ring3MailboxHwVerdict::FaultedOrPreempted,
        },
        Err(_) => Ring3MailboxHwVerdict::FaultedOrPreempted,
    }
}

#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_ring3_transition() {
    use target_enterprise::gdt::USER_CODE_SEL;
    use target_enterprise::svc_runtime::ServiceId;
    use target_enterprise::syscall::Errno;

    let ring3_code: [u8; 32] = [
        0x8C, 0xC8, // mov eax, cs
        0x48, 0x89, 0xC6, // mov rsi, rax
        0x48, 0x8B, 0x44, 0x24, 0xE0, // mov rax, [rsp - 0x20]
        0x48, 0x89, 0xC2, // mov rdx, rax
        0x48, 0x81, 0xF2, 0x2A, 0x00, 0x00, 0x00, // xor rdx, 42
        0x48, 0x89, 0x54, 0x24, 0xE8, // mov [rsp - 0x18], rdx
        0xBF, 0x02, 0x00, 0x00, 0x00, // mov edi, 2 (SYS_GETPID)
        0xCD, 0x80, // int 0x80
    ];
    let ok = match exec_service_ring3_stub_isolated(1, 0, &ring3_code, 0, 42, false) {
        Ok(o) => o,
        Err(_) => panic!("RING3: isolated CR3 hardware CPL=3 transition failed"),
    };
    if ok.observed_cr3 != ok.user_cr3 || ok.observed_cr3 == ok.kernel_cr3 || ok.pid != 1 {
        panic!("RING3: hardware CR3 switch to isolated user PML4 did not occur");
    }

    // Red Team Check 1: Corrupted user-space mailbox canary must be rejected.
    if exec_service_ring3_stub(&ring3_code, 0xA55A_3C3C_0000_0001, 42, true) {
        panic!("RING3: corrupted user-space mailbox canary was not rejected");
    }

    // Red Team Check 2: Illegal instruction (`ud2`) in Ring-3 traps to IDT vector 6 (`#UD`)
    // under isolated `user_cr3` and recovers cleanly without crashing the kernel.
    let mut ud2_code = [0x90u8; 32];
    ud2_code[0] = 0x0F;
    ud2_code[1] = 0x0B; // ud2
    match exec_service_ring3_stub_isolated(1, 0, &ud2_code, 0, 0, false) {
        Err(Ring3FaultOutcome::CpuException {
            vec: 6,
            frame_cs,
            user_cr3,
            observed_cr3,
            ..
        }) if frame_cs == USER_CODE_SEL && observed_cr3 == user_cr3 => {}
        other => panic!("RING3: #UD fault recovery drift: {:?}", other),
    }

    // Red Team Check 3: Stack underflow/overflow into unmapped guard page `PT[1]` (`[rsp - 0x1000]`)
    // triggers a non-present user `#PF` (`vec = 14`, `err_code & 0x05 == 0x04`) and recovers cleanly.
    let mut guard_pf_code = [0x90u8; 32];
    let guard_probe: [u8; 10] = [
        0x48, 0x8B, 0x84, 0x24, 0x00, 0xF0, 0xFF, 0xFF, // mov rax, [rsp - 0x1000]
        0xCD, 0x80,
    ];
    guard_pf_code[..guard_probe.len()].copy_from_slice(&guard_probe);
    match exec_service_ring3_stub_isolated(1, 0, &guard_pf_code, 0, 0, false) {
        Err(Ring3FaultOutcome::CpuException {
            vec: 14,
            err_code,
            cr2,
            user_va,
            ..
        }) if cr2 == user_va + 0x1FF0 && (err_code & 0x05) == 0x04 => {}
        other => panic!("RING3: guard page #PF recovery drift: {:?}", other),
    }

    // Red Team Check 4: Reading higher-half kernel `PHYS_MAP_OFFSET` memory from Ring-3 triggers a
    // non-present `#PF` (`P = 0`), proving hardware KPTI `user_cr3` unmaps kernel memory!
    let kernel_probe_va = pa_to_va(dma_phys_base()) as u64;
    let kb = kernel_probe_va.to_le_bytes();
    let mut kpti_pf_code = [0x90u8; 32];
    let kpti_probe: [u8; 15] = [
        0x48, 0xB8, kb[0], kb[1], kb[2], kb[3], kb[4], kb[5], kb[6], kb[7], // movabs rax, kernel_probe_va
        0x48, 0x8B, 0x00, // mov rax, [rax]
        0xCD, 0x80,
    ];
    kpti_pf_code[..kpti_probe.len()].copy_from_slice(&kpti_probe);
    match exec_service_ring3_stub_isolated(1, 0, &kpti_pf_code, 0, 0, false) {
        Err(Ring3FaultOutcome::CpuException {
            vec: 14,
            err_code,
            cr2,
            ..
        }) if cr2 == kernel_probe_va && (err_code & 0x05) == 0x04 => {}
        other => panic!("RING3: KPTI higher-half kernel read was not #PF(P=0): {:?}", other),
    }

    // Red Team Check 5: Writing to `PT[0]` user code page from Ring-3 triggers a `W^X` protection
    // `#PF` (`P=1, W=1, U=1` -> `0x07`) and recovers cleanly.
    let mut wx_pf_code = [0x90u8; 32];
    let wx_probe: [u8; 9] = [
        0xC6, 0x05, 0x00, 0x00, 0x00, 0x00, 0x90, // mov byte ptr [rip + 0], 0x90
        0xCD, 0x80,
    ];
    wx_pf_code[..wx_probe.len()].copy_from_slice(&wx_probe);
    match exec_service_ring3_stub_isolated(1, 0, &wx_pf_code, 0, 0, false) {
        Err(Ring3FaultOutcome::CpuException {
            vec: 14,
            err_code,
            cr2,
            user_va,
            ..
        }) if cr2 == user_va + 7 && (err_code & 0x07) == 0x07 => {}
        other => panic!("RING3: W^X user code write was not #PF(P|W|U): {:?}", other),
    }

    // Red Team Check 6: `svc-http` Ring-3 stub attempting `SYS_OPEN` (`edi = 5`, requires `FS_BYPASS`)
    // under its bounded capability mask is denied with `Errno::EPERM`.
    let mut unpriv_open_code = ring3_code;
    unpriv_open_code[25..30].copy_from_slice(&[0xBF, 0x05, 0x00, 0x00, 0x00]); // mov edi, 5 (SYS_OPEN)
    match exec_service_ring3_stub_isolated(
        ServiceId::Http.pid() as u64,
        ServiceId::Http.policy().cap_mask,
        &unpriv_open_code,
        0,
        42,
        false,
    ) {
        Err(Ring3FaultOutcome::SyscallDenied(Errno::EPERM)) => {}
        other => panic!("RING3: unprivileged SYS_OPEN was not denied with EPERM: {:?}", other),
    }

    // Red Team Check 7: Privileged instruction (`hlt` `0xF4`) in Ring-3 traps to `#GP` (`vec = 13`)
    // under isolated `user_cr3` and recovers cleanly without halting the CPU.
    let mut hlt_code = [0x90u8; 32];
    hlt_code[0] = 0xF4; // hlt (privileged CPL=0 instruction)
    match exec_service_ring3_stub_isolated(1, 0, &hlt_code, 0, 0, false) {
        Err(Ring3FaultOutcome::CpuException {
            vec: 13,
            frame_cs,
            user_cr3,
            observed_cr3,
            ..
        }) if frame_cs == USER_CODE_SEL && observed_cr3 == user_cr3 => {}
        other => panic!("RING3: privileged HLT #GP recovery drift: {:?}", other),
    }

    // Red Team Check 8: Preemptive Ring-3 eviction — an infinite Ring-3 CPU loop (`jmp $` `[0xEB, 0xFE]`)
    // is forcibly preempted by the Local APIC one-shot timer (`vector 0x40`) and evicted back to Ring-0!
    let mut inf_loop_code = [0x90u8; 32];
    inf_loop_code[0] = 0xEB;
    inf_loop_code[1] = 0xFE; // jmp $
    match exec_service_ring3_stub_with_opts(1, 0, &inf_loop_code, 0, 0, false, Some(2048)) {
        Err(Ring3FaultOutcome::Preempted {
            rip,
            frame_cs,
            observed_cr3,
        }) if rip == ok.user_va && frame_cs == USER_CODE_SEL && observed_cr3 == ok.user_cr3 => {}
        other => panic!("RING3: runaway infinite loop preemption failed: {:?}", other),
    }

    serial_write_str("RING3 transition OK cpl=3->0 vec=0x80 ist1=ok rsp0=ok syscall=43\n");
}

// ============================================================
// SMP / TASK-057: ACPI MADT parsing + INIT-SIPI-SIPI AP wake
// sequence. The kernel constructs a 4-CPU fixture MADT
// (BSP=0, APs=1/2/3, all ENABLED), runs `SmpImpl::discover`
// to recover the topology, asserts the 9-write ICR sequence
// emitted by `wake_aps` against a recording harness matches
// the locked golden (per Intel SDM Vol 3A §10.4.7.1):
// INIT, SIPI, SIPI per AP × 3 APs = 9 IPIs. Emits:
//   `SMP discover OK bsp=0 aps=3\n`
//   `SMP wake OK ipis=9 vec=0x08\n`
//
// This is wire-codec-shaped: no AP actually executes. The
// real-APIC kernel-side ApicWriter + AP-side real-mode
// trampoline + concurrent AP execution are TASK-057b. A
// morph that perturbs the ICR field encodings, the SIPI
// vector arithmetic, or the MADT entry-type walk panics
// inside `banner_smp` and the trailing banners are
// suppressed.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_smp() {
    use cuttle_contracts::{smp_consts, ApicWriter, Smp};
    use target_enterprise::smp::{build_madt_fixture, SmpImpl};

    // 1. Build a 4-CPU MADT in a stack buffer + parse it.
    let mut madt_buf = [0u8; 128];
    let madt_len = match build_madt_fixture(4, &mut madt_buf) {
        Ok(n) => n,
        Err(_) => panic!("SMP banner: build_madt_fixture failed"),
    };
    let topo = match SmpImpl::discover(&madt_buf[..madt_len]) {
        Ok(t) => t,
        Err(_) => panic!("SMP banner: discover rejected fixture"),
    };
    if topo.bsp != 0 || topo.ap_count != 3 {
        panic!("SMP banner: topology drift");
    }
    if topo.ap_ids() != &[1u8, 2, 3] {
        panic!("SMP banner: AP order drift");
    }

    // Emit discover banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"SMP discover OK bsp=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(topo.bsp as u64, &mut line[pos..]);
        let mid = b" aps=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(topo.ap_count as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // 2. Wake APs through a recording harness — assert the 9-write
    //    golden + the vector arithmetic.
    struct RecordingApic {
        icr_low: [u32; 16],
        low_count: usize,
        icr_high: [u32; 16],
        high_count: usize,
    }
    impl ApicWriter for RecordingApic {
        fn write_icr_low(&mut self, val: u32) {
            if self.low_count < self.icr_low.len() {
                self.icr_low[self.low_count] = val;
                self.low_count += 1;
            }
        }
        fn write_icr_high(&mut self, val: u32) {
            if self.high_count < self.icr_high.len() {
                self.icr_high[self.high_count] = val;
                self.high_count += 1;
            }
        }
        fn read_icr_low(&mut self) -> u32 {
            0
        }
    }
    let mut apic = RecordingApic {
        icr_low: [0; 16],
        low_count: 0,
        icr_high: [0; 16],
        high_count: 0,
    };
    let mut delay_us_noop = |_us: u32| {};
    let ipi_count = match SmpImpl::wake_aps(
        &topo,
        0x8000,
        &mut apic,
        &mut delay_us_noop,
    ) {
        Ok(n) => n,
        Err(_) => panic!("SMP banner: wake_aps failed"),
    };
    if ipi_count != 9 {
        panic!("SMP banner: ipi count drift");
    }
    if apic.low_count != 9 || apic.high_count != 9 {
        panic!("SMP banner: ICR write count drift");
    }
    // Assert the SIPI vector encoded in the 2nd and 3rd ICR-low
    // writes (the SIPIs for AP 1) is 0x08.
    if apic.icr_low[1] & smp_consts::ICR_VECTOR_MASK != 0x08 {
        panic!("SMP banner: SIPI vector arithmetic drift");
    }
    if apic.icr_low[2] & smp_consts::ICR_VECTOR_MASK != 0x08 {
        panic!("SMP banner: SIPI redundancy vector drift");
    }
    // Assert the INIT IPI delivery-mode bits are set (first ICR-low
    // of each AP triple).
    let init_low = smp_consts::ICR_DELIVERY_INIT
        | smp_consts::ICR_LEVEL_ASSERT
        | smp_consts::ICR_TRIGGER_LEVEL;
    if apic.icr_low[0] != init_low
        || apic.icr_low[3] != init_low
        || apic.icr_low[6] != init_low
    {
        panic!("SMP banner: INIT encoding drift");
    }
    // Assert the target APIC IDs in ICR-high progress 1, 2, 3 (with
    // each one written 3 times for the 3-IPI sequence per AP).
    if apic.icr_high[0] != 1 << 24
        || apic.icr_high[3] != 2 << 24
        || apic.icr_high[6] != 3 << 24
    {
        panic!("SMP banner: ICR-high target drift");
    }

    // Emit wake banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"SMP wake OK ipis=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(ipi_count as u64, &mut line[pos..]);
        let mid = b" vec=0x08";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// PCI / TASK-059: legacy 0xCF8/0xCFC configuration-space wire codec.
// The kernel constructs an in-RAM `RecordingBus` populated with two
// QEMU-canonical devices (Intel 8086:100E e1000 at 00:03.0 + Intel
// 8086:5845 NVMe at 00:05.0). It runs `PciImpl::enumerate` and
// asserts both functions are surfaced with byte-exact
// (vendor, device, class, subclass). It then reads BAR0 on the e1000
// (port-I/O space at 0xC020) and asserts the decoded
// `PciBar::Io(0xC020)`. Emits:
//   `PCI scan OK devices=2 e1000=found nvme=found\n`
//   `PCI bar OK e1000_io=0xc020\n`
//
// Wire-codec-shaped: no real PCI cycle is issued — the recording bus
// scripts every dword. The real kernel-side 0xCF8/0xCFC port writer
// is plugged in at the `PciConfigBus` impl boundary, separately. A
// morph that perturbs the (bus, device, function, offset) encoding,
// the multi-function bit gating, the BAR low-bit decode, or the
// vendor-none sentinel panics inside `banner_pci` and these banners
// never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_pci() {
    use cuttle_contracts::{pci_class, Pci, PciAddress, PciBar};
    use target_enterprise::pci::{PciImpl, RecordingBus};

    // 1. Build the in-RAM bus with two QEMU-canonical devices +
    //    the e1000's BAR0 (port-I/O at 0xC020).
    let mut bus = RecordingBus::new();
    let e1000 = PciAddress {
        bus: 0,
        device: 3,
        function: 0,
    };
    let nvme = PciAddress {
        bus: 0,
        device: 5,
        function: 0,
    };
    // e1000: vendor=0x8086, device=0x100E, class=0x02 (Network),
    //        subclass=0x00 (Ethernet), prog_if=0, revision=0x03,
    //        header_type=0 (single-function).
    // Identification dword at 0x00: device_id<<16 | vendor_id.
    bus.set(e1000, 0x00, (0x100Eu32 << 16) | 0x8086);
    // Class dword at 0x08: class<<24 | subclass<<16 | prog_if<<8 | rev.
    bus.set(e1000, 0x08, (0x02u32 << 24) | (0x00 << 16) | (0x00 << 8) | 0x03);
    // Header dword at 0x0C: header_type in byte 2.
    bus.set(e1000, 0x0C, 0x0000_0000);
    // BAR0 at 0x10: port-I/O space at 0xC020 (low bit set).
    bus.set(e1000, 0x10, 0xC021);

    // nvme: vendor=0x8086, device=0x5845, class=0x01 (Mass Storage),
    //       subclass=0x08 (NVMe), prog_if=0x02, revision=0,
    //       header_type=0 (single-function).
    bus.set(nvme, 0x00, (0x5845u32 << 16) | 0x8086);
    bus.set(nvme, 0x08, (0x01u32 << 24) | (0x08 << 16) | (0x02 << 8));
    bus.set(nvme, 0x0C, 0x0000_0000);

    // 2. Enumerate and verify both devices are surfaced byte-exact.
    let mut e1000_found = false;
    let mut nvme_found = false;
    let mut count = 0usize;
    PciImpl::enumerate(&mut bus, &mut |d| {
        count += 1;
        if d.vendor_id == 0x8086
            && d.device_id == 0x100E
            && d.class == pci_class::CLASS_NETWORK
            && d.subclass == pci_class::SUBCLASS_ETHERNET
        {
            e1000_found = true;
        }
        if d.vendor_id == 0x8086
            && d.device_id == 0x5845
            && d.class == pci_class::CLASS_MASS_STORAGE
            && d.subclass == pci_class::SUBCLASS_NVME
        {
            nvme_found = true;
        }
    });
    if count != 2 {
        panic!("PCI banner: enumerate device count drift");
    }
    if !e1000_found {
        panic!("PCI banner: e1000 not surfaced");
    }
    if !nvme_found {
        panic!("PCI banner: NVMe not surfaced");
    }

    // 3. Emit the scan banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"PCI scan OK devices=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(count as u64, &mut line[pos..]);
        let mid = b" e1000=found nvme=found";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // 4. Read e1000 BAR0 and assert decoded value byte-exact.
    let bar = match PciImpl::read_bar(&mut bus, e1000, 0) {
        Ok(b) => b,
        Err(_) => panic!("PCI banner: BAR0 read failed"),
    };
    let io_port = match bar {
        PciBar::Io(p) => p,
        _ => panic!("PCI banner: BAR0 decoded as wrong variant"),
    };
    if io_port != 0xC020 {
        panic!("PCI banner: BAR0 address drift");
    }

    // 5. Emit the BAR banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"PCI bar OK e1000_io=0x";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Lowercase hex of io_port (u32), MSB-first, no leading zeros.
        let mut nyb = 8i32;
        while nyb > 0 {
            let shift = (nyb - 1) * 4;
            if ((io_port >> shift) & 0xF) != 0 {
                break;
            }
            nyb -= 1;
        }
        if nyb == 0 {
            line[pos] = b'0';
            pos += 1;
        } else {
            let mut nn = nyb;
            while nn > 0 {
                nn -= 1;
                let n = ((io_port >> (nn * 4)) & 0xF) as u8;
                line[pos] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-062: PIT + CMOS RTC wire codec. The kernel programs the
// PIT for 1 kHz against a recording IoPort and asserts the exact
// three-byte sequence (cmd=0x36, divisor lo/hi for 1193), then
// reads a hardcoded BCD 24-hour RTC fixture (2026-03-15 12:34:56)
// and recovers the locked Unix epoch. A morph that perturbs the
// command byte, the divisor arithmetic, the CMOS index/data
// dance, BCD decode, or Gregorian conversion panics inside
// `banner_timer` and these banners never appear.
// ============================================================
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_timer() {
    use cuttle_contracts::{
        PicTimer, Rtc, PIT_CH0_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN, PIT_CMD_PORT, RTC_REG_DAY,
        RTC_REG_HOURS, RTC_REG_MINUTES, RTC_REG_MONTH, RTC_REG_SECONDS, RTC_REG_STATUS_A,
        RTC_REG_STATUS_B, RTC_REG_YEAR, RTC_STATUS_B_24H,
    };
    use target_enterprise::timer::{PicTimerImpl, RecordingIoPort, RtcImpl};

    // ---- PIT 1 kHz program sequence ----
    let mut port = RecordingIoPort::new();
    let div = match PicTimerImpl::program_hz(&mut port, 1000) {
        Ok(d) => d,
        Err(_) => panic!("TIMER banner: program_hz failed"),
    };
    // 1_193_182 / 1000 = 1193 = 0x04A9
    if div != 1193 {
        panic!("TIMER banner: divisor drift");
    }
    if port.write_count() != 3 {
        panic!("TIMER banner: write count drift");
    }
    let w0 = match port.write_at(0) {
        Some(w) => w,
        None => panic!("TIMER banner: missing write 0"),
    };
    let w1 = match port.write_at(1) {
        Some(w) => w,
        None => panic!("TIMER banner: missing write 1"),
    };
    let w2 = match port.write_at(2) {
        Some(w) => w,
        None => panic!("TIMER banner: missing write 2"),
    };
    if w0.port != PIT_CMD_PORT || w0.value != PIT_CMD_CH0_LOHI_MODE3_BIN {
        panic!("TIMER banner: PIT cmd byte drift");
    }
    if w1.port != PIT_CH0_PORT || w1.value != 0xA9 {
        panic!("TIMER banner: PIT divisor lo drift");
    }
    if w2.port != PIT_CH0_PORT || w2.value != 0x04 {
        panic!("TIMER banner: PIT divisor hi drift");
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"PIT program OK hz=1000 div=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(div as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ---- RTC fixture read ----
    let mut rtc_port = RecordingIoPort::new();
    rtc_port.set_cmos(RTC_REG_STATUS_A, 0x00);
    rtc_port.set_cmos(RTC_REG_STATUS_B, RTC_STATUS_B_24H);
    rtc_port.set_cmos(RTC_REG_SECONDS, 0x56);
    rtc_port.set_cmos(RTC_REG_MINUTES, 0x34);
    rtc_port.set_cmos(RTC_REG_HOURS, 0x12);
    rtc_port.set_cmos(RTC_REG_DAY, 0x15);
    rtc_port.set_cmos(RTC_REG_MONTH, 0x03);
    rtc_port.set_cmos(RTC_REG_YEAR, 0x26);

    let t = match RtcImpl::read_time(&mut rtc_port) {
        Ok(v) => v,
        Err(_) => panic!("TIMER banner: RTC read failed"),
    };
    if t.year != 2026 || t.month != 3 || t.day != 15 {
        panic!("TIMER banner: RTC date drift");
    }
    if t.hour != 12 || t.minute != 34 || t.second != 56 {
        panic!("TIMER banner: RTC time drift");
    }
    // 2026-03-15 12:34:56 UTC
    if t.unix != 1_773_578_096 {
        panic!("TIMER banner: RTC unix drift");
    }

    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"RTC read OK unix=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(t.unix, &mut line[pos..]);
        let mid = b" date=2026-03-15";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-089 xHCI No-Op TRB
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_xhci_trb() {
    use cuttle_contracts::{XhciTrb, XHCI_TRB_TYPE_NOOP};
    use target_enterprise::xhci_trb::XhciTrbImpl;

    let w = XhciTrbImpl::encode_noop(true);
    if XhciTrbImpl::trb_type(w.d3) != XHCI_TRB_TYPE_NOOP {
        panic!("XHCI banner: type drift");
    }
    serial_write_bytes(b"XHCI trb OK type=noop\n");
}

// TASK-090 UEFI GOP mode
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_uefi_gop() {
    use cuttle_contracts::UefiGop;
    use target_enterprise::uefi_gop::UefiGopImpl;

    let m = UefiGopImpl::mode_1280x720();
    let mut b = [0u8; 40];
    if UefiGopImpl::encode(&m, &mut b).is_err() {
        panic!("GOP banner: encode");
    }
    let d = match UefiGopImpl::decode(&b) {
        Ok(d) => d,
        Err(_) => panic!("GOP banner: decode"),
    };
    if d.horizontal != 1280 || d.vertical != 720 {
        panic!("GOP banner: res drift");
    }
    serial_write_bytes(b"GOP mode OK 1280x720\n");
}

// TASK-083 IOAPIC
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_ioapic() {
    use cuttle_contracts::IoApic;
    use target_enterprise::ioapic::{banner_entry, IoApicImpl};

    let e = banner_entry();
    let (lo, hi) = IoApicImpl::encode(&e);
    let d = IoApicImpl::decode(lo, hi);
    if d.vector != 0x30 {
        panic!("IOAPIC banner: vector drift");
    }
    serial_write_bytes(b"IOAPIC entry OK vec=0x30\n");
}

// TASK-084 LAPIC ICR
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_lapic() {
    use cuttle_contracts::{LapicIcr, ICR_DELIVERY_INIT};
    use target_enterprise::lapic_icr::LapicIcrImpl;

    let c = LapicIcrImpl::init(0);
    if LapicIcrImpl::delivery_of(c.low) != ICR_DELIVERY_INIT {
        panic!("LAPIC banner: delivery drift");
    }
    serial_write_bytes(b"LAPIC icr OK delivery=init\n");
}

// TASK-079 Multiboot2
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_mb2() {
    use cuttle_contracts::{Mb2Tag, Multiboot2, MB2_MAX_TAGS};
    use target_enterprise::multiboot2::{build_banner_fixture, MB2_FIXTURE_LEN, Multiboot2Impl};

    let mut img = [0u8; MB2_FIXTURE_LEN];
    build_banner_fixture(&mut img).unwrap();
    let mut out = [Mb2Tag {
        typ: 0,
        size: 0,
        offset: 0,
    }; MB2_MAX_TAGS];
    let n = Multiboot2Impl::walk(&img, &mut out).unwrap();
    if n != 1 {
        panic!("MB2 banner: tag count");
    }
    serial_write_bytes(b"MB2 parse OK tags=1\n");
}

// TASK-081 RSDP
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_rsdp() {
    use cuttle_contracts::AcpiRsdp;
    use target_enterprise::acpi_rsdp::{build_banner_fixture, AcpiRsdpImpl};

    let mut b = [0u8; 20];
    build_banner_fixture(&mut b).unwrap();
    let r = AcpiRsdpImpl::parse_v1(&b).unwrap();
    if &r.oem_id != b"BOCHS " {
        panic!("RSDP banner: oem");
    }
    serial_write_bytes(b"RSDP parse OK oem=BOCHS\n");
}

// TASK-082 frame bitmap
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_frame() {
    use cuttle_contracts::FrameBitmap;
    use target_enterprise::frame_bitmap::FrameBitmapImpl;

    let mut b = FrameBitmapImpl::new();
    b.alloc().unwrap();
    b.alloc().unwrap();
    if b.free_count() != 4094 {
        panic!("FRAME banner: free count");
    }
    serial_write_bytes(b"FRAME alloc OK free=4094\n");
}

// TASK-075: 16550 init sequence
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_serial() {
    use cuttle_contracts::{Serial16550, SERIAL_COM1, SERIAL_INIT_WRITES};
    use target_enterprise::serial16550::{expected_com1_init, RecordingSerialPort, Serial16550Impl};

    let mut p = RecordingSerialPort::new();
    let n = Serial16550Impl::init(&mut p, SERIAL_COM1);
    if n != SERIAL_INIT_WRITES || p.write_n() != 7 {
        panic!("SERIAL banner: write count");
    }
    let exp = expected_com1_init();
    let mut i = 0usize;
    while i < 7 {
        if p.write_at(i) != Some(exp[i]) {
            panic!("SERIAL banner: sequence drift");
        }
        i += 1;
    }
    serial_write_bytes(b"SERIAL init OK port=0x3f8\n");
}

// TASK-076: tick source mux
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_tick() {
    use cuttle_contracts::{TickKind, TickSource};
    use target_enterprise::tick_source::TickSourceImpl;

    let mut t = TickSourceImpl::new();
    t.select(TickKind::Hpet);
    if t.kind() != TickKind::Hpet {
        panic!("TICK banner: kind drift");
    }
    t.advance(1);
    if t.now_ticks() != 1 {
        panic!("TICK banner: ticks drift");
    }
    serial_write_bytes(b"TICK source OK kind=hpet\n");
}

// TASK-077: virtio pci caps
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_virtio_caps() {
    use cuttle_contracts::{
        VirtioPciCap, VirtioPciCaps, VIRTIO_PCI_CAP_COMMON_CFG, VIRTIO_PCI_CAP_MAX,
    };
    use target_enterprise::virtio_pci_caps::{banner_read_dword, VirtioPciCapsImpl};

    let mut out = [VirtioPciCap {
        offset: 0,
        cfg_type: 0,
        bar: 0,
        bar_offset: 0,
        length: 0,
    }; VIRTIO_PCI_CAP_MAX];
    let n = match VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out) {
        Ok(n) => n,
        Err(_) => panic!("VIRTIO caps banner: walk failed"),
    };
    if VirtioPciCapsImpl::find(&out[..n], VIRTIO_PCI_CAP_COMMON_CFG).is_none() {
        panic!("VIRTIO caps banner: common missing");
    }
    serial_write_bytes(b"VIRTIO caps OK common=found\n");
}

// TASK-071: Watchdog arm/pet/fire.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_watchdog() {
    use cuttle_contracts::{Watchdog, WatchdogError};
    use target_enterprise::watchdog::{BANNER_DEADLINE, WatchdogImpl};

    let mut w = WatchdogImpl::new();
    if w.arm(BANNER_DEADLINE).is_err() {
        panic!("WATCHDOG banner: arm failed");
    }
    if w.pet().is_err() {
        panic!("WATCHDOG banner: pet failed");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"WATCHDOG pet OK deadline=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(w.deadline() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    // Fire: re-arm with 2 and tick out
    let mut w2 = WatchdogImpl::new();
    w2.arm(2).unwrap();
    w2.tick().unwrap();
    match w2.tick() {
        Err(WatchdogError::Fired) => {}
        _ => panic!("WATCHDOG banner: fire expected"),
    }
    serial_write_bytes(b"WATCHDOG fire OK reason=timeout\n");
}

// TASK-073: Power S5
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_power() {
    use cuttle_contracts::{Power, SLP_TYP_S5};
    use target_enterprise::power::PowerImpl;

    let p = PowerImpl::encode_s5(SLP_TYP_S5);
    if PowerImpl::decode_slp_typ(p) != 5 || !PowerImpl::is_slp_en(p) {
        panic!("POWER banner: encode drift");
    }
    serial_write_bytes(b"POWER s5 OK slp_typ=5\n");
}

// TASK-074: ELF64
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_elf() {
    use cuttle_contracts::{Elf64, ELF_MAX_PHDRS, ElfPhdr};
    use target_enterprise::elf64::{
        build_banner_fixture, ELF_BANNER_ENTRY, ELF_BANNER_PHNUM, ELF_FIXTURE_LEN, Elf64Impl,
    };

    let mut img = [0u8; ELF_FIXTURE_LEN];
    if build_banner_fixture(&mut img).is_err() {
        panic!("ELF banner: fixture failed");
    }
    let h = match Elf64Impl::parse_header(&img) {
        Ok(h) => h,
        Err(_) => panic!("ELF banner: parse failed"),
    };
    if h.phnum != ELF_BANNER_PHNUM || h.entry != ELF_BANNER_ENTRY {
        panic!("ELF banner: header drift");
    }
    let mut ph = [ElfPhdr {
        ptype: 0,
        flags: 0,
        offset: 0,
        vaddr: 0,
        filesz: 0,
        memsz: 0,
        align: 0,
    }; ELF_MAX_PHDRS];
    let n = match Elf64Impl::load_phdrs(&img, &h, &mut ph) {
        Ok(n) => n,
        Err(_) => panic!("ELF banner: phdrs failed"),
    };
    if n != 1 {
        panic!("ELF banner: phdr count drift");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"ELF parse OK phnum=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(h.phnum as u64, &mut line[pos..]);
        let mid = b" entry=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(h.entry, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-067: HPET — program 1 ms periodic timer0 against recording bus.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_hpet() {
    use cuttle_contracts::Hpet;
    use target_enterprise::hpet::{
        BANNER_PERIOD_FS, BANNER_PERIOD_MS, HpetImpl, RecordingHpetBus,
    };

    let mut bus = RecordingHpetBus::new();
    bus.script_canonical_cap(BANNER_PERIOD_FS, 0x8086, 2);
    let caps = match HpetImpl::read_caps(&mut bus) {
        Ok(c) => c,
        Err(_) => panic!("HPET banner: caps failed"),
    };
    if caps.period_fs != BANNER_PERIOD_FS {
        panic!("HPET banner: period drift");
    }
    HpetImpl::enable(&mut bus);
    let cmp = match HpetImpl::ms_to_ticks(caps.period_fs, BANNER_PERIOD_MS) {
        Ok(t) => t,
        Err(_) => panic!("HPET banner: ms_to_ticks failed"),
    };
    if cmp != 14318 {
        panic!("HPET banner: cmp drift");
    }
    if HpetImpl::program_timer0_periodic(&mut bus, cmp).is_err() {
        panic!("HPET banner: program failed");
    }
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"HPET program OK period_fs=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(caps.period_fs as u64, &mut line[pos..]);
        let mid = b" cmp=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(cmp, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-069: Keyboard set-1 stream a/b.
#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_keyboard() {
    use cuttle_contracts::{KeyCode, Keyboard, KBD_BREAK_A, KBD_BREAK_B, KBD_MAKE_A, KBD_MAKE_B};
    use target_enterprise::keyboard::KeyboardImpl;

    let mut kbd = KeyboardImpl::new();
    let stream = [KBD_MAKE_A, KBD_BREAK_A, KBD_MAKE_B, KBD_BREAK_B];
    let mut keys = 0u32;
    let mut last = b'\0';
    let mut i = 0usize;
    while i < stream.len() {
        if let Some(ev) = kbd.feed(stream[i]) {
            if ev.pressed && ev.ascii != 0 {
                keys += 1;
                last = ev.ascii;
                let _ = KeyCode::Letter(b'A'); // keep import used
            }
        }
        i += 1;
    }
    if keys != 2 || last != b'b' {
        panic!("KBD banner: decode drift");
    }
    serial_write_bytes(b"KBD decode OK keys=2 last=b\n");
}
