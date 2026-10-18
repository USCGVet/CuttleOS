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
#[inline(never)]
pub(crate) fn exec_service_ring3_stub(
    ring3_code: &[u8; 32],
    mailbox_req_word: u64,
    expected_arg0: u64,
    corrupt_canary: bool,
) -> bool {
    use target_enterprise::gdt::{
        Gdt, Tss64, KERNEL_CODE_SEL, KERNEL_DATA_SEL, TSS64_LEN, TSS_SEL, USER_CODE_SEL,
        USER_DATA_SEL,
    };
    use target_enterprise::interrupts::{
        vectors, Idt, IDT_LEN, TYPE_INTERRUPT_GATE_DPL3, TYPE_TRAP_GATE_DPL0,
    };
    use target_enterprise::syscall::{dispatch_with_cap, SYS_GETPID};

    let dma = dma_phys_base();
    if dma == 0 || phys_map_offset() == 0 {
        return false;
    }

    // Dedicated physical frames in `dma + 0x2_4000 .. dma + 0x2_B000`:
    //   +0x2_4000: PDPT for temporary lower-half user mapping
    //   +0x2_5000: PD
    //   +0x2_6000: PT (`PT[0]` = Ring-3 code/stack/mailbox page, `PT[1]` = Ring-0 ISR trampoline page)
    //   +0x2_7000: Ring-3 user code + stack + IPC mailbox frame (`+0xFD0` request/canary, `+0xFD8` response)
    //   +0x2_8000: Ring-0 ISR trampoline + state frame
    //   +0x2_9000: Live 256-entry IDT (4096 bytes)
    //   +0x2_A000: Live GDT (`+0x000`), descriptor pointers (`+0x040..+0x080`),
    //              64-bit TSS (`+0x100`), `RSP0` stack (`+0x200..+0x800`), `IST1` stack (`+0x800..+0x1000`)
    let pdpt_phys = dma + 0x2_4000;
    let pd_phys = dma + 0x2_5000;
    let pt_phys = dma + 0x2_6000;
    let user_phys = dma + 0x2_7000;
    let tramp_phys = dma + 0x2_8000;
    let idt_phys = dma + 0x2_9000;
    let gdt_phys = dma + 0x2_A000;

    // Zero all 7 scratch frames (`7 * 4096 = 0x7000` bytes).
    // SAFETY: `pdpt_phys .. pdpt_phys + 0x7000` lies within the reserved 192 KiB DMA window mapped via `pa_to_va`.
    unsafe {
        let base_ptr = pa_to_va(pdpt_phys);
        let mut i = 0usize;
        while i < 0x7000 {
            core::ptr::write_volatile(base_ptr.add(i), 0);
            i += 1;
        }
    }

    // Find an unused lower-half PML4 slot (`64..256`).
    // SAFETY: Running at CPL=0; `read_cr3()` returns the active 4-level PML4 physical address.
    let pml4_phys = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let pml4_va = pa_to_va(pml4_phys) as *mut u64;
    let mut pml4_idx: Option<usize> = None;
    let mut idx = 64usize;
    while idx < 256 {
        // SAFETY: `pml4_va` points to the 512-entry active PML4 table mapped via `pa_to_va`.
        let entry = unsafe { core::ptr::read_volatile(pml4_va.add(idx)) };
        if entry == 0 {
            pml4_idx = Some(idx);
            break;
        }
        idx += 1;
    }
    let Some(pml4_slot) = pml4_idx else {
        return false;
    };

    let user_va: u64 = (pml4_slot as u64) << 39;
    let kernel_trampoline_va: u64 = user_va + 0x1000;
    let tramp_state_va: u64 = kernel_trampoline_va + 0x200;
    let user_rsp: u64 = user_va + 0xFF0;

    // Install 4-level mapping (`PTE_P | PTE_W | PTE_USER` on `PT[0]`, `PTE_P | PTE_W` on `PT[1]`).
    const PTE_U: u64 = 1 << 2;
    // SAFETY: `pdpt_phys`, `pd_phys`, and `pt_phys` are freshly zeroed 4 KiB frames in the reserved DMA pool, and `pml4_slot` was verified empty.
    unsafe {
        let pdpt_va = pa_to_va(pdpt_phys) as *mut u64;
        let pd_va = pa_to_va(pd_phys) as *mut u64;
        let pt_va = pa_to_va(pt_phys) as *mut u64;
        core::ptr::write_volatile(pt_va.add(0), user_phys | PTE_P | PTE_W | PTE_U);
        core::ptr::write_volatile(pt_va.add(1), tramp_phys | PTE_P | PTE_W);
        core::ptr::write_volatile(pd_va.add(0), pt_phys | PTE_P | PTE_W | PTE_U);
        core::ptr::write_volatile(pdpt_va.add(0), pd_phys | PTE_P | PTE_W | PTE_U);
        core::ptr::write_volatile(pml4_va.add(pml4_slot), pdpt_phys | PTE_P | PTE_W | PTE_U);
        asm!(
            "invlpg [{}]",
            "invlpg [{}]",
            in(reg) user_va,
            in(reg) kernel_trampoline_va,
            options(nostack, preserves_flags)
        );
    }

    // Write Ring-3 payload into `user_phys` and populate the user-mapped IPC mailbox request + canary
    // word at `user_phys + 0xFD0` (`[rsp - 0x20]`).
    let planted_req = if corrupt_canary {
        mailbox_req_word ^ 0xDEAD_BEEF_0000_0000
    } else {
        mailbox_req_word
    };
    // SAFETY: `user_phys` is a dedicated 4 KiB frame in the reserved DMA window mapped via `pa_to_va`.
    unsafe {
        let dst = pa_to_va(user_phys);
        let mut i = 0usize;
        while i < ring3_code.len() {
            core::ptr::write_volatile(dst.add(i), ring3_code[i]);
            i += 1;
        }
        let req_bytes = planted_req.to_le_bytes();
        let mut k = 0usize;
        while k < 8 {
            core::ptr::write_volatile(dst.add(0xFD0 + k), req_bytes[k]);
            k += 1;
        }
    }

    // Write Ring-0 ISR trampolines into `tramp_phys`:
    // 1) `isr_breakpoint_ist1` at `+0x000` (Vector 3 `#BP`, `IST = 1`)
    let isr_bp_code: [u8; 18] = [
        0x50,                                     // push rax
        0x48, 0x8D, 0x05, 0xF8, 0x01, 0x00, 0x00, // lea rax, [rip + 0x1F8] -> +0x200
        0x48, 0xFF, 0x00,                         // inc qword ptr [rax]
        0x48, 0x89, 0x60, 0x08,                   // mov [rax + 0x08], rsp
        0x58,                                     // pop rax
        0x48, 0xCF,                               // iretq
    ];
    // 2) `isr_syscall_int80` at `+0x080` (Vector 0x80 `SYSCALL_INT`, `DPL = 3`, `IST = 0`)
    let isr_int80_code: [u8; 53] = [
        0x48, 0x8D, 0x05, 0x79, 0x01, 0x00, 0x00, // lea rax, [rip + 0x179] -> +0x200
        0x48, 0x89, 0x70, 0x20,                   // mov [rax + 0x20], rsi
        0x48, 0x8B, 0x4C, 0x24, 0x08,             // mov rcx, [rsp + 0x08]
        0x48, 0x89, 0x48, 0x28,                   // mov [rax + 0x28], rcx
        0x48, 0x8B, 0x4C, 0x24, 0x20,             // mov rcx, [rsp + 0x20]
        0x48, 0x89, 0x48, 0x30,                   // mov [rax + 0x30], rcx
        0x48, 0x89, 0x78, 0x38,                   // mov [rax + 0x38], rdi
        0x48, 0x89, 0x50, 0x40,                   // mov [rax + 0x40], rdx
        0x48, 0x89, 0x60, 0x48,                   // mov [rax + 0x48], rsp
        0xB9, 0x10, 0x00, 0x00, 0x00,             // mov ecx, 0x10
        0x8E, 0xD1,                               // mov ss, cx
        0x48, 0x8B, 0x60, 0x10,                   // mov rsp, [rax + 0x10]
        0xC3,                                     // ret
    ];
    // SAFETY: `tramp_phys` is a dedicated 4 KiB frame in the reserved DMA window mapped via `pa_to_va`.
    unsafe {
        let dst = pa_to_va(tramp_phys);
        let mut i = 0usize;
        while i < isr_bp_code.len() {
            core::ptr::write_volatile(dst.add(i), isr_bp_code[i]);
            i += 1;
        }
        let mut j = 0usize;
        while j < isr_int80_code.len() {
            core::ptr::write_volatile(dst.add(0x80 + j), isr_int80_code[j]);
            j += 1;
        }
    }

    // Build GDT, 64-bit TSS, and 256-entry IDT in `gdt_phys` and `idt_phys`.
    let gdt_frame_va = pa_to_va(gdt_phys) as u64;
    let gdt_va = gdt_frame_va;
    let gdtr_new_va = gdt_frame_va + 0x040;
    let idtr_new_va = gdt_frame_va + 0x050;
    let gdtr_orig_va = gdt_frame_va + 0x060;
    let idtr_orig_va = gdt_frame_va + 0x070;
    let tss_va = gdt_frame_va + 0x100;
    let rsp0_top = gdt_frame_va + 0x800;
    let ist1_top = gdt_frame_va + 0x1000;
    let idt_va = pa_to_va(idt_phys) as u64;

    let tss = Tss64::with_stacks(rsp0_top, ist1_top);
    let tss_bytes = tss.to_bytes();
    let gdt = Gdt::new_full(tss_va, (TSS64_LEN - 1) as u32);
    let gdt_bytes = gdt.to_table_bytes();

    let mut idt = Idt::new_empty();
    idt.set_handler_with_attr(
        vectors::BREAKPOINT,
        kernel_trampoline_va,
        TYPE_TRAP_GATE_DPL0,
        1,
    );
    idt.set_handler_with_attr(
        vectors::SYSCALL_INT,
        kernel_trampoline_va + 0x80,
        TYPE_INTERRUPT_GATE_DPL3,
        0,
    );

    // SAFETY: `gdt_frame_va` and `idt_va` point into dedicated 4 KiB frames in the reserved DMA window.
    unsafe {
        let gdt_ptr = gdt_va as *mut u8;
        let mut i = 0usize;
        while i < gdt_bytes.len() {
            core::ptr::write_volatile(gdt_ptr.add(i), gdt_bytes[i]);
            i += 1;
        }
        let tss_ptr = tss_va as *mut u8;
        let mut j = 0usize;
        while j < tss_bytes.len() {
            core::ptr::write_volatile(tss_ptr.add(j), tss_bytes[j]);
            j += 1;
        }
        let idt_ptr = idt_va as *mut u8;
        let mut v = 0usize;
        while v < IDT_LEN {
            let entry_bytes = idt.raw_bytes(v as u8);
            let mut k = 0usize;
            while k < 16 {
                core::ptr::write_volatile(idt_ptr.add(v * 16 + k), entry_bytes[k]);
                k += 1;
            }
            v += 1;
        }

        // Write 10-byte `[limit: u16, base: u64]` descriptors for `lgdt` and `lidt`.
        let gdt_limit: u16 = (Gdt::byte_size() - 1) as u16;
        let idt_limit: u16 = (Idt::byte_size() - 1) as u16;
        let gdtr_ptr = gdtr_new_va as *mut u8;
        let gdt_lim_b = gdt_limit.to_le_bytes();
        let gdt_base_b = gdt_va.to_le_bytes();
        core::ptr::write_volatile(gdtr_ptr.add(0), gdt_lim_b[0]);
        core::ptr::write_volatile(gdtr_ptr.add(1), gdt_lim_b[1]);
        let mut b = 0usize;
        while b < 8 {
            core::ptr::write_volatile(gdtr_ptr.add(2 + b), gdt_base_b[b]);
            b += 1;
        }

        let idtr_ptr = idtr_new_va as *mut u8;
        let idt_lim_b = idt_limit.to_le_bytes();
        let idt_base_b = idt_va.to_le_bytes();
        core::ptr::write_volatile(idtr_ptr.add(0), idt_lim_b[0]);
        core::ptr::write_volatile(idtr_ptr.add(1), idt_lim_b[1]);
        let mut b2 = 0usize;
        while b2 < 8 {
            core::ptr::write_volatile(idtr_ptr.add(2 + b2), idt_base_b[b2]);
            b2 += 1;
        }
    }

    // Execute live GDT/TSS/IDT load, `int3` on `IST1`, and Ring-0 -> Ring-3 (`iretq`) -> Ring-0 (`int 0x80`) round-trip.
    // SAFETY: Running at CPL=0 with interrupts masked (`cli`); `gdtr_new_va`, `idtr_new_va`, `tss_va`,
    // `user_va`, and `kernel_trampoline_va` are mapped and initialized, and original `GDTR`/`IDTR`/`CS`/`SS`/`RFLAGS`
    // are saved and restored before returning.
    unsafe {
        asm!(
            "pushfq",
            "pop r15",
            "cli",
            "sgdt [r9]",
            "sidt [r10]",
            "mov r13d, cs",
            "mov r14d, ss",
            // Load Cuttle GDT, reload CS=0x08 and SS/DS/ES=0x10, load TR=0x28, load IDT.
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
            // 1. Trigger #BP (vector 3) to verify live IDT + TSS IST1 stack switch.
            "int3",
            // 2. Drop to Ring-3 (`CPL=3`) via `iretq` and return via `int 0x80` on `RSP0`.
            "call 3f",
            "jmp 4f",
            "3:",
            "mov [r8 + 0x10], rsp",
            "push {u_ss}",
            "push rsi",
            "push 0x2",
            "push {u_cs}",
            "push rdi",
            "iretq",
            "4:",
            // Restore bootloader GDTR, CS, SS, IDTR, and RFLAGS.
            "lgdt [r9]",
            "push r13",
            "lea rax, [rip + 5f]",
            "push rax",
            "retfq",
            "5:",
            "mov ss, r14w",
            "lidt [r10]",
            "push r15",
            "popfq",
            in("r8") tramp_state_va,
            in("r9") gdtr_orig_va,
            in("r10") idtr_orig_va,
            in("r11") gdtr_new_va,
            in("r12") idtr_new_va,
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
            u_ss = const (USER_DATA_SEL as u64),
            u_cs = const (USER_CODE_SEL as u64),
            clobber_abi("C"),
        );
    }

    // Read back the hardware state captured by `isr_breakpoint_ist1` and `isr_syscall_int80`,
    // plus the signed IPC response word written by `CPL=3` into `user_phys + 0xFD8` (`[rsp - 0x18]`).
    // SAFETY: `tramp_state_va` points to the 64-bit state slots at `tramp_phys + 0x200`, `user_phys` is mapped via `pa_to_va`, and `pml4_va` points to the active PML4.
    let (bp_count, bp_rsp, r3_cs, frame_cs, frame_ss, sys_nr, sys_arg0, trap_rsp, mb_resp) = unsafe {
        let st = pa_to_va(tramp_phys + 0x200) as *const u64;
        let user_ptr = pa_to_va(user_phys);
        let mut mb_bytes = [0u8; 8];
        let mut m = 0usize;
        while m < 8 {
            mb_bytes[m] = core::ptr::read_volatile(user_ptr.add(0xFD8 + m));
            m += 1;
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
            u64::from_le_bytes(mb_bytes),
        );
        // Tear down temporary PML4 entry and flush TLB.
        core::ptr::write_volatile(pml4_va.add(pml4_slot), 0);
        asm!(
            "invlpg [{}]",
            "invlpg [{}]",
            in(reg) user_va,
            in(reg) kernel_trampoline_va,
            options(nostack, preserves_flags)
        );
        vals
    };

    if bp_count != 1 || bp_rsp != ist1_top - 48 {
        return false;
    }
    if (r3_cs as u16) != USER_CODE_SEL
        || (frame_cs as u16) != USER_CODE_SEL
        || (frame_ss as u16) != USER_DATA_SEL
    {
        return false;
    }
    if trap_rsp != rsp0_top - 40 {
        return false;
    }
    let expected_resp = mailbox_req_word ^ expected_arg0;
    if sys_nr != SYS_GETPID || sys_arg0 != expected_resp || mb_resp != expected_resp {
        return false;
    }

    let pid = match dispatch_with_cap(sys_nr, u64::MAX, sys_arg0, 0, 0, 0, 0, 0) {
        Ok(v) => v,
        Err(_) => return false,
    };
    pid == 1 && pid.wrapping_add(sys_arg0) == 1u64.wrapping_add(expected_resp)
}

#[cfg(not(cuttle_prod))]
#[inline(never)]
pub(crate) fn banner_ring3_transition() {
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
    if !exec_service_ring3_stub(&ring3_code, 0, 42, false) {
        panic!("RING3: hardware CPL=3 transition verification failed");
    }
    // Red Team negative verification: corrupted user-space mailbox canary must be rejected.
    if exec_service_ring3_stub(&ring3_code, 0xA55A_3C3C_0000_0001, 42, true) {
        panic!("RING3: corrupted user-space mailbox canary was not rejected");
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
