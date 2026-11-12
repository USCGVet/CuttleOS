#![doc = " SMP bring-up wire codec — ACPI MADT parsing + INIT-SIPI-SIPI AP"]
#![doc = " wake sequence per Intel SDM Vol 3A §10.4.7.1."]
#![doc = ""]
#![doc = " `no_std`, no `alloc`, fixed-capacity scratch in the impl. The"]
#![doc = " kernel-side surface stops short of actually scheduling on AP cores"]
#![doc = " — this iteration ships the *bring-up wire sequence* against a"]
#![doc = " caller-supplied `ApicWriter`, validated through a recording test"]
#![doc = " harness. The real-APIC kernel-side `ApicWriter` impl + the"]
#![doc = " AP-side real-mode trampoline + concurrent execution semantics"]
#![doc = " are explicit future surfaces (TASK-057b)."]
#![doc = ""]
#![doc = " # Why this is wire-codec-shaped, not concurrency-shaped"]
#![doc = ""]
#![doc = " The verifier and the QEMU smoke test both assume deterministic"]
#![doc = " single-thread execution: each banner emits a byte sequence that"]
#![doc = " must round-trip identically across morph cycles. Real concurrent"]
#![doc = " AP execution would break that assumption (banners would race on"]
#![doc = " COM1). The TASK-057 design dodges the contract change by making"]
#![doc = " the *driver code path* the locked surface: we exercise"]
#![doc = " `discover` + `wake_aps` end-to-end, capture every ICR write into"]
#![doc = " a recording harness, and assert the captured sequence matches a"]
#![doc = " locked 9-write golden. Real AP execution requires the"]
#![doc = " per-CPU banner buffer contract change — TASK-057b lands that."]
#![doc = ""]
#![doc = " # ACPI MADT layout (ACPI 6.4 §5.2.12)"]
#![doc = ""]
#![doc = " ```text"]
#![doc = "  0    4    8        12       16          24                  44"]
#![doc = "  +----+----+--------+--------+-----------+-------------------+"]
#![doc = "  |Sig |Len |Rev|Chk |OEMID(6)|OEMTabID(8)|...meta(20 bytes)..|"]
#![doc = "  +----+----+--------+--------+-----------+-------------------+"]
#![doc = "  ^ \"APIC\"   ^ table length (LE u32, includes the header)"]
#![doc = ""]
#![doc = "  44   45   46                52                              ..."]
#![doc = "  +----+----+-------+---------+------+----+----+----+----+"]
#![doc = "  |T=0 |L=8 |ACPI_ID|APIC_ID  | Flags (LE u32)            |"]
#![doc = "  +----+----+-------+---------+----------------------------+"]
#![doc = "  ^ Processor Local APIC subtable. Flags bit 0 = ENABLED."]
#![doc = " ```"]
#![doc = ""]
#![doc = " Other subtable types (IO_APIC, NMI source, etc.) are skipped by"]
#![doc = " length — the seed only consumes Type 0."]
#![doc = ""]
#![doc = " # INIT-SIPI-SIPI wake sequence (Intel SDM Vol 3A §10.4.7.1)"]
#![doc = ""]
#![doc = " Per AP, 3 IPIs:"]
#![doc = ""]
#![doc = " 1. **INIT IPI** — assert, level-triggered. Resets the AP."]
#![doc = " 2. (Wait 10 ms.)"]
#![doc = " 3. **SIPI #1** — vector = `(trampoline_pa >> 12)`. AP starts"]
#![doc = "    executing real-mode code at `trampoline_pa`."]
#![doc = " 4. (Wait 200 µs.)"]
#![doc = " 5. **SIPI #2** — same vector. Per SDM recommendation: redundancy"]
#![doc = "    for slow APs that missed the first SIPI."]
#![doc = " 6. (Wait 200 µs, then check delivery status.)"]
#![doc = ""]
#![doc = " Each IPI is two ICR writes: ICR-high (target APIC ID in the upper"]
#![doc = " 8 bits) then ICR-low (delivery mode + vector + flags — and writing"]
#![doc = " ICR-low triggers the actual IPI send)."]
#![allow(clippy::needless_range_loop)]
use cuttle_contracts::{
    madt, smp_consts, ApicId, ApicWriter, CpuTopology, Smp, SmpError, MAX_CPUS,
};
#[doc = " Poll the APIC's ICR-low `Delivery Status` bit until it reads"]
#[doc = " idle (== 0) OR the retry budget is exhausted. The recording"]
#[doc = " harness returns 0 immediately; on real hardware the kernel"]
#[doc = " supplies an APIC whose `read_icr_low` actually probes the MMIO"]
#[doc = " register."]
#[inline(never)]
fn wait_for_idle_mbc56b67e(apic: &mut dyn ApicWriter) -> Result<(), SmpError> {
    let __cuttle_stack_pad_b752143a: [u8; 212usize] = ::core::hint::black_box([0u8; 212usize]);
    let mut retries_v73aa22a7_0 = 0u32;
    while retries_v73aa22a7_0 < smp_consts::SMP_DELIVERY_RETRY_BUDGET {
        let v_v73aa22a7_1 = apic.read_icr_low();
        if v_v73aa22a7_1 & smp_consts::ICR_DELIVERY_STATUS_PENDING == 0 {
            return Ok(());
        }
        retries_v73aa22a7_0 += 1;
    }
    Err(SmpError::ApicTimeout)
}
impl Smp for SmpImpl {
    fn discover(madt_bytes: &[u8]) -> Result<CpuTopology, SmpError> {
        let __cuttle_stack_pad_96665ef8: [u8; 104usize] = ::core::hint::black_box([0u8; 104usize]);
        if madt_bytes.len() < madt::HEADER_LEN {
            return Err(SmpError::BadMadtEntry);
        }
        if &madt_bytes[0..4] != madt::SIG_APIC.as_slice() {
            return Err(SmpError::BadMadtSignature);
        }
        let table_len_v73aa22a7_0 =
            u32::from_le_bytes([madt_bytes[4], madt_bytes[5], madt_bytes[6], madt_bytes[7]])
                as usize;
        if table_len_v73aa22a7_0 < madt::HEADER_LEN || table_len_v73aa22a7_0 > madt_bytes.len() {
            return Err(SmpError::BadMadtEntry);
        }
        let mut bsp_v73aa22a7_2: Option<ApicId> = None;
        let mut aps_v73aa22a7_3 = [0u8; MAX_CPUS];
        let mut ap_count_v73aa22a7_4 = 0usize;
        let mut cursor_v73aa22a7_1 = madt::HEADER_LEN;
        while cursor_v73aa22a7_1 + 2 <= table_len_v73aa22a7_0 {
            let entry_len_v73aa22a7_6 = madt_bytes[cursor_v73aa22a7_1 + 1] as usize;
            let entry_type_v73aa22a7_5 = madt_bytes[cursor_v73aa22a7_1];
            if entry_len_v73aa22a7_6 < 2
                || cursor_v73aa22a7_1 + entry_len_v73aa22a7_6 > table_len_v73aa22a7_0
            {
                return Err(SmpError::BadMadtEntry);
            }
            if entry_type_v73aa22a7_5 == madt::ENTRY_LOCAL_APIC {
                if entry_len_v73aa22a7_6 != madt::LOCAL_APIC_ENTRY_LEN {
                    return Err(SmpError::BadMadtEntry);
                }
                let apic_id_v73aa22a7_7 = madt_bytes[cursor_v73aa22a7_1 + 3];
                let flags_v73aa22a7_8 = u32::from_le_bytes([
                    madt_bytes[cursor_v73aa22a7_1 + 4],
                    madt_bytes[cursor_v73aa22a7_1 + 5],
                    madt_bytes[cursor_v73aa22a7_1 + 6],
                    madt_bytes[cursor_v73aa22a7_1 + 7],
                ]);
                if flags_v73aa22a7_8 & madt::LOCAL_APIC_FLAG_ENABLED != 0 {
                    match bsp_v73aa22a7_2.is_none() {
                        true => {
                            bsp_v73aa22a7_2 = Some(apic_id_v73aa22a7_7);
                        }
                        false => {
                            if ap_count_v73aa22a7_4 >= MAX_CPUS {
                                return Err(SmpError::TooManyCpus);
                            }
                            aps_v73aa22a7_3[ap_count_v73aa22a7_4] = apic_id_v73aa22a7_7;
                            ap_count_v73aa22a7_4 += 1;
                        }
                    }
                }
            }
            cursor_v73aa22a7_1 += entry_len_v73aa22a7_6;
        }
        let bsp_v73aa22a7_9 = bsp_v73aa22a7_2.ok_or(SmpError::NoEnabledCpu)?;
        Ok(CpuTopology {
            bsp: bsp_v73aa22a7_9,
            aps: aps_v73aa22a7_3,
            ap_count: ap_count_v73aa22a7_4,
        })
    }
    fn wake_aps(
        topology: &CpuTopology,
        trampoline_pa: u64,
        apic: &mut dyn ApicWriter,
        delay_us: &mut dyn FnMut(u32),
    ) -> Result<usize, SmpError> {
        let __cuttle_stack_pad_a818e611: [u8; 171usize] = ::core::hint::black_box([0u8; 171usize]);
        if trampoline_pa & 0xFFF != 0 {
            return Err(SmpError::BadIpiVector);
        }
        let vector_v73aa22a7_0 = (trampoline_pa >> 12) as u32 & smp_consts::ICR_VECTOR_MASK;
        if vector_v73aa22a7_0 == 0 || vector_v73aa22a7_0 == 0xFF {
            return Err(SmpError::BadIpiVector);
        }
        let init_low_v73aa22a7_2 = smp_consts::ICR_DELIVERY_INIT
            | smp_consts::ICR_LEVEL_ASSERT
            | smp_consts::ICR_TRIGGER_LEVEL;
        let sipi_low_v73aa22a7_3 =
            smp_consts::ICR_DELIVERY_STARTUP | smp_consts::ICR_LEVEL_ASSERT | vector_v73aa22a7_0;
        let mut i_v73aa22a7_4 = 0usize;
        let mut ipi_count_v73aa22a7_1 = 0usize;
        while i_v73aa22a7_4 < topology.ap_count {
            let ap_id_v73aa22a7_5 = topology.aps[i_v73aa22a7_4];
            let target_v73aa22a7_6 = (ap_id_v73aa22a7_5 as u32) << smp_consts::ICR_HIGH_DEST_SHIFT;
            apic.write_icr_high(target_v73aa22a7_6);
            apic.write_icr_low(init_low_v73aa22a7_2);
            ipi_count_v73aa22a7_1 += 1;
            delay_us(smp_consts::SMP_INIT_TO_SIPI_US);
            wait_for_idle_mbc56b67e(apic)?;
            apic.write_icr_high(target_v73aa22a7_6);
            apic.write_icr_low(sipi_low_v73aa22a7_3);
            ipi_count_v73aa22a7_1 += 1;
            delay_us(smp_consts::SMP_SIPI_TO_SIPI_US);
            wait_for_idle_mbc56b67e(apic)?;
            apic.write_icr_high(target_v73aa22a7_6);
            apic.write_icr_low(sipi_low_v73aa22a7_3);
            ipi_count_v73aa22a7_1 += 1;
            delay_us(smp_consts::SMP_SIPI_TO_SIPI_US);
            wait_for_idle_mbc56b67e(apic)?;
            i_v73aa22a7_4 += 1;
        }
        Ok(ipi_count_v73aa22a7_1)
    }
}
#[doc = " Wire codec impl. Stateless."]
pub struct SmpImpl;
#[doc = " Construct a canonical MADT for `cpu_count` enabled CPUs (BSP = 0,"]
#[doc = " APs = 1..cpu_count). Used both by the unit tests and by the"]
#[doc = " kernel banner_smp. Locked layout: 44-byte header + N × 8-byte"]
#[doc = " Local APIC subtables."]
#[doc = ""]
#[doc = " `out` must hold at least `madt::HEADER_LEN + cpu_count * madt::LOCAL_APIC_ENTRY_LEN`"]
#[doc = " bytes; the function returns the number written."]
#[inline(always)]
pub fn build_madt_fixture(cpu_count: usize, out: &mut [u8]) -> Result<usize, SmpError> {
    let __cuttle_stack_pad_2daf2d32: [u8; 140usize] = ::core::hint::black_box([0u8; 140usize]);
    let total_v73aa22a7_0 = madt::HEADER_LEN + cpu_count * madt::LOCAL_APIC_ENTRY_LEN;
    if out.len() < total_v73aa22a7_0 || cpu_count == 0 || cpu_count > MAX_CPUS {
        return Err(SmpError::BadMadtEntry);
    }
    for i_v73aa22a7_1 in 0..total_v73aa22a7_0 {
        out[i_v73aa22a7_1] = 0;
    }
    out[0..4].copy_from_slice(&madt::SIG_APIC);
    let len_bytes_v73aa22a7_2 = (total_v73aa22a7_0 as u32).to_le_bytes();
    out[4..8].copy_from_slice(&len_bytes_v73aa22a7_2);
    let mut cpu_idx_v73aa22a7_4 = 0u8;
    let mut cursor_v73aa22a7_3 = madt::HEADER_LEN;
    while (cpu_idx_v73aa22a7_4 as usize) < cpu_count {
        out[cursor_v73aa22a7_3] = madt::ENTRY_LOCAL_APIC;
        out[cursor_v73aa22a7_3 + 1] = madt::LOCAL_APIC_ENTRY_LEN as u8;
        out[cursor_v73aa22a7_3 + 2] = cpu_idx_v73aa22a7_4;
        out[cursor_v73aa22a7_3 + 3] = cpu_idx_v73aa22a7_4;
        let flags_v73aa22a7_5 = madt::LOCAL_APIC_FLAG_ENABLED.to_le_bytes();
        out[cursor_v73aa22a7_3 + 4..cursor_v73aa22a7_3 + 8].copy_from_slice(&flags_v73aa22a7_5);
        cpu_idx_v73aa22a7_4 += 1;
        cursor_v73aa22a7_3 += madt::LOCAL_APIC_ENTRY_LEN;
    }
    Ok(total_v73aa22a7_0)
}

/// MADT entry type `9` (`Processor Local x2APIC`, 16 bytes, ACPI 6.4 §5.2.12.12).
pub const MADT_ENTRY_LOCAL_X2APIC: u8 = 9;
/// Fixed byte length of a MADT Processor Local x2APIC subtable.
pub const MADT_LOCAL_X2APIC_LEN: usize = 16;
/// MADT Processor Local APIC `Online Capable` flag (`bit 1`, ACPI 6.3+).
pub const MADT_FLAG_ONLINE_CAPABLE: u32 = 1 << 1;

/// Resolve up to `N` distinct hardware Local APIC IDs (`out[0] = bsp_apic_id`, `out[1..count]` = APs)
/// from an optional firmware `MADT` (`"APIC"`) table, supporting sparse/non-contiguous Xeon/EPYC
/// APIC topologies (both Type-0 xAPIC and Type-9 x2APIC entries) and falling back cleanly to
/// [`crate::memory::kernel_guards::smp_apic_for_ap_slot`] when `madt_opt` is absent or malformed.
#[inline(never)]
pub fn resolve_ap_apic_targets<const N: usize>(
    madt_opt: Option<&[u8]>,
    bsp_apic_id: u32,
) -> ([u32; N], usize) {
    let mut out = [u32::MAX; N];
    if N == 0 {
        return (out, 0);
    }
    out[0] = bsp_apic_id;
    let mut count = 1usize;

    if let Some(madt_bytes) = madt_opt {
        if madt_bytes.len() >= madt::HEADER_LEN && &madt_bytes[0..4] == madt::SIG_APIC.as_slice() {
            let tlen = u32::from_le_bytes([
                madt_bytes[4],
                madt_bytes[5],
                madt_bytes[6],
                madt_bytes[7],
            ]) as usize;
            if tlen >= madt::HEADER_LEN && tlen <= madt_bytes.len() {
                let mut cur = madt::HEADER_LEN;
                let mut malformed = false;
                while cur + 2 <= tlen {
                    let etype = madt_bytes[cur];
                    let elen = madt_bytes[cur + 1] as usize;
                    if elen < 2 || cur + elen > tlen {
                        malformed = true;
                        break;
                    }
                    let mut cand_id: Option<u32> = None;
                    if etype == madt::ENTRY_LOCAL_APIC && elen == madt::LOCAL_APIC_ENTRY_LEN {
                        let flags = u32::from_le_bytes([
                            madt_bytes[cur + 4],
                            madt_bytes[cur + 5],
                            madt_bytes[cur + 6],
                            madt_bytes[cur + 7],
                        ]);
                        if (flags & (madt::LOCAL_APIC_FLAG_ENABLED | MADT_FLAG_ONLINE_CAPABLE)) != 0
                        {
                            cand_id = Some(madt_bytes[cur + 3] as u32);
                        }
                    } else if etype == MADT_ENTRY_LOCAL_X2APIC && elen >= MADT_LOCAL_X2APIC_LEN {
                        let x2_id = u32::from_le_bytes([
                            madt_bytes[cur + 4],
                            madt_bytes[cur + 5],
                            madt_bytes[cur + 6],
                            madt_bytes[cur + 7],
                        ]);
                        let flags = u32::from_le_bytes([
                            madt_bytes[cur + 8],
                            madt_bytes[cur + 9],
                            madt_bytes[cur + 10],
                            madt_bytes[cur + 11],
                        ]);
                        if (flags & (madt::LOCAL_APIC_FLAG_ENABLED | MADT_FLAG_ONLINE_CAPABLE)) != 0
                            && x2_id <= 0xFE
                        {
                            cand_id = Some(x2_id);
                        }
                    }
                    if let Some(apic_id) = cand_id {
                        let mut dup = false;
                        let mut j = 0usize;
                        while j < count {
                            if out[j] == apic_id {
                                dup = true;
                                break;
                            }
                            j += 1;
                        }
                        if !dup && count < N {
                            out[count] = apic_id;
                            count += 1;
                        }
                    }
                    cur += elen;
                }
                if !malformed && count >= 1 {
                    return (out, count);
                }
            }
        }
    }

    // Firmware MADT unavailable or malformed: populate deterministic non-BSP fallback targets.
    count = 1;
    while count < N {
        if let Some(apic_id) =
            crate::memory::kernel_guards::smp_apic_for_ap_slot(count, bsp_apic_id)
        {
            out[count] = apic_id;
            count += 1;
        } else {
            break;
        }
    }
    (out, count)
}

/// Hardware SMP lockup detector tracking per-CPU progress ticks across periodic epochs.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SmpLockupWatchdog<const N: usize> {
    last_ticks: [u64; N],
    stalled_epochs: [u32; N],
    threshold_epochs: u32,
}

impl<const N: usize> SmpLockupWatchdog<N> {
    /// Construct a lockup watchdog flagging any online AP that fails to advance ticks
    /// across `threshold_epochs` consecutive checks.
    pub const fn new(threshold_epochs: u32) -> Self {
        let thresh = if threshold_epochs == 0 { 1 } else { threshold_epochs };
        Self {
            last_ticks: [0u64; N],
            stalled_epochs: [0u32; N],
            threshold_epochs: thresh,
        }
    }

    /// Compare `observed_ticks` for `0..online_cpus` against the previous check and return
    /// a bitmask (`bit c = 1`) of secondary AP cores (`1 <= c < online_cpus`) stalled past threshold.
    pub fn check_stalled_mask(&mut self, online_cpus: usize, observed_ticks: &[u64; N]) -> u32 {
        let limit = if online_cpus > N { N } else { online_cpus };
        let mut mask = 0u32;
        let mut c = 0usize;
        while c < limit && c < 32 {
            let cur = observed_ticks[c];
            if cur != self.last_ticks[c] {
                self.last_ticks[c] = cur;
                self.stalled_epochs[c] = 0;
            } else if c > 0 {
                self.stalled_epochs[c] = self.stalled_epochs[c].saturating_add(1);
                if self.stalled_epochs[c] >= self.threshold_epochs {
                    mask |= 1u32 << c;
                }
            }
            c += 1;
        }
        mask
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::PerCpu;
    #[doc = " Recording `ApicWriter` test harness. Captures every write"]
    #[doc = " into a fixed-capacity buffer; `wait_for_idle` reads return"]
    #[doc = " idle (delivery_status bit clear) immediately."]
    struct RecordingApic {
        writes: [(WriteKind, u32); 64],
        count: usize,
    }
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum WriteKind {
        IcrLow,
        IcrHigh,
    }
    impl RecordingApic {
        fn new() -> Self {
            Self {
                writes: [(WriteKind::IcrLow, 0); 64],
                count: 0,
            }
        }
        fn record(&mut self, kind: WriteKind, val: u32) {
            if self.count < self.writes.len() {
                self.writes[self.count] = (kind, val);
                self.count += 1;
            }
        }
        fn icr_low_writes(&self) -> impl Iterator<Item = u32> + '_ {
            self.writes[..self.count]
                .iter()
                .filter(|(k, _)| *k == WriteKind::IcrLow)
                .map(|(_, v)| *v)
        }
        fn icr_high_writes(&self) -> impl Iterator<Item = u32> + '_ {
            self.writes[..self.count]
                .iter()
                .filter(|(k, _)| *k == WriteKind::IcrHigh)
                .map(|(_, v)| *v)
        }
    }
    impl ApicWriter for RecordingApic {
        fn write_icr_low(&mut self, val: u32) {
            self.record(WriteKind::IcrLow, val);
        }
        fn write_icr_high(&mut self, val: u32) {
            self.record(WriteKind::IcrHigh, val);
        }
        fn read_icr_low(&mut self) -> u32 {
            0
        }
    }
    #[test]
    fn discover_recovers_bsp_and_aps_in_order() {
        let mut buf = [0u8; 256];
        let n = build_madt_fixture(4, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        assert_eq!(topo.bsp, 0);
        assert_eq!(topo.ap_count, 3);
        assert_eq!(topo.aps[0], 1);
        assert_eq!(topo.aps[1], 2);
        assert_eq!(topo.aps[2], 3);
        assert_eq!(topo.cpu_count(), 4);
        assert_eq!(topo.ap_ids(), &[1u8, 2, 3]);
    }
    #[test]
    fn discover_rejects_bad_signature() {
        let mut buf = [0u8; 128];
        build_madt_fixture(2, &mut buf).unwrap();
        buf[0] = b'X';
        let r = SmpImpl::discover(&buf);
        assert_eq!(r.unwrap_err(), SmpError::BadMadtSignature);
    }
    #[test]
    fn discover_rejects_truncated_header() {
        let buf = [0u8; 16];
        let r = SmpImpl::discover(&buf);
        assert_eq!(r.unwrap_err(), SmpError::BadMadtEntry);
    }
    #[test]
    fn discover_rejects_length_past_input() {
        let mut buf = [0u8; 128];
        build_madt_fixture(2, &mut buf).unwrap();
        let lie = 1000u32.to_le_bytes();
        buf[4..8].copy_from_slice(&lie);
        let r = SmpImpl::discover(&buf);
        assert_eq!(r.unwrap_err(), SmpError::BadMadtEntry);
    }
    #[test]
    fn discover_rejects_subtable_overrun() {
        let mut buf = [0u8; 128];
        build_madt_fixture(2, &mut buf).unwrap();
        buf[45] = 100;
        let r = SmpImpl::discover(&buf);
        assert_eq!(r.unwrap_err(), SmpError::BadMadtEntry);
    }
    #[test]
    fn discover_rejects_zero_length_subtable() {
        let mut buf = [0u8; 128];
        build_madt_fixture(2, &mut buf).unwrap();
        buf[45] = 0;
        let r = SmpImpl::discover(&buf);
        assert_eq!(r.unwrap_err(), SmpError::BadMadtEntry);
    }
    #[test]
    fn discover_skips_disabled_local_apic() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(2, &mut buf).unwrap();
        buf[56] = 0;
        buf[57] = 0;
        buf[58] = 0;
        buf[59] = 0;
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        assert_eq!(topo.bsp, 0);
        assert_eq!(topo.ap_count, 0, "disabled APIC should not be an AP");
    }
    #[test]
    fn discover_rejects_no_enabled_cpu() {
        let mut buf = [0u8; 128];
        build_madt_fixture(1, &mut buf).unwrap();
        buf[48] = 0;
        buf[49] = 0;
        buf[50] = 0;
        buf[51] = 0;
        let r = SmpImpl::discover(&buf);
        assert_eq!(r.unwrap_err(), SmpError::NoEnabledCpu);
    }
    #[test]
    fn discover_skips_io_apic_subtable() {
        let mut buf = [0u8; 128];
        let total = madt::HEADER_LEN + 8 + 12 + 8;
        for i in 0..total {
            buf[i] = 0;
        }
        buf[0..4].copy_from_slice(&madt::SIG_APIC);
        let len_bytes = (total as u32).to_le_bytes();
        buf[4..8].copy_from_slice(&len_bytes);
        let bsp_off = madt::HEADER_LEN;
        buf[bsp_off] = madt::ENTRY_LOCAL_APIC;
        buf[bsp_off + 1] = 8;
        buf[bsp_off + 3] = 0;
        buf[bsp_off + 4..bsp_off + 8].copy_from_slice(&madt::LOCAL_APIC_FLAG_ENABLED.to_le_bytes());
        let io_off = bsp_off + 8;
        buf[io_off] = madt::ENTRY_IO_APIC;
        buf[io_off + 1] = 12;
        let ap_off = io_off + 12;
        buf[ap_off] = madt::ENTRY_LOCAL_APIC;
        buf[ap_off + 1] = 8;
        buf[ap_off + 3] = 5;
        buf[ap_off + 4..ap_off + 8].copy_from_slice(&madt::LOCAL_APIC_FLAG_ENABLED.to_le_bytes());
        let topo = SmpImpl::discover(&buf[..total]).unwrap();
        assert_eq!(topo.bsp, 0);
        assert_eq!(topo.ap_ids(), &[5u8]);
    }
    #[test]
    fn wake_aps_emits_nine_ipis_for_three_aps() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(4, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_log = [0u32; 64];
        let mut delay_count = 0usize;
        let mut delay_us = |us: u32| {
            if delay_count < delay_log.len() {
                delay_log[delay_count] = us;
                delay_count += 1;
            }
        };
        let count = SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us).unwrap();
        assert_eq!(count, 9);
        assert_eq!(apic.count, 18);
        assert_eq!(apic.icr_low_writes().count(), 9);
        assert_eq!(apic.icr_high_writes().count(), 9);
        assert_eq!(delay_count, 9);
    }
    #[test]
    fn wake_aps_icr_low_sequence_is_locked_golden() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(4, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us).unwrap();
        let init_low = smp_consts::ICR_DELIVERY_INIT
            | smp_consts::ICR_LEVEL_ASSERT
            | smp_consts::ICR_TRIGGER_LEVEL;
        let vector = 0x8000u32 >> 12;
        let sipi_low = smp_consts::ICR_DELIVERY_STARTUP | smp_consts::ICR_LEVEL_ASSERT | vector;
        let expected: [u32; 9] = [
            init_low, sipi_low, sipi_low, init_low, sipi_low, sipi_low, init_low, sipi_low,
            sipi_low,
        ];
        let actual: [u32; 9] = {
            let mut a = [0u32; 9];
            for (i, v) in apic.icr_low_writes().enumerate() {
                a[i] = v;
            }
            a
        };
        assert_eq!(actual, expected);
    }
    #[test]
    fn wake_aps_icr_high_targets_each_ap_in_order() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(4, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us).unwrap();
        let expected_targets: [u32; 9] = [
            1 << 24,
            1 << 24,
            1 << 24,
            2 << 24,
            2 << 24,
            2 << 24,
            3 << 24,
            3 << 24,
            3 << 24,
        ];
        let actual: [u32; 9] = {
            let mut a = [0u32; 9];
            for (i, v) in apic.icr_high_writes().enumerate() {
                a[i] = v;
            }
            a
        };
        assert_eq!(actual, expected_targets);
    }
    #[test]
    fn wake_aps_delay_pattern_is_locked() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(4, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_log = [0u32; 16];
        let mut delay_count = 0usize;
        let mut delay_us = |us: u32| {
            if delay_count < delay_log.len() {
                delay_log[delay_count] = us;
                delay_count += 1;
            }
        };
        SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us).unwrap();
        assert_eq!(delay_count, 9);
        let expected = [10_000u32, 200, 200, 10_000, 200, 200, 10_000, 200, 200];
        assert_eq!(&delay_log[..9], &expected[..]);
    }
    #[test]
    fn wake_aps_vector_arithmetic_for_0x8000_is_0x08() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(2, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us).unwrap();
        let icr_low_writes: [u32; 3] = {
            let mut a = [0u32; 3];
            for (i, v) in apic.icr_low_writes().enumerate() {
                a[i] = v;
            }
            a
        };
        assert_eq!(icr_low_writes[1] & 0xFF, 0x08);
        assert_eq!(icr_low_writes[2] & 0xFF, 0x08);
    }
    #[test]
    fn wake_aps_rejects_unaligned_trampoline() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(2, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        let r = SmpImpl::wake_aps(&topo, 0x8123, &mut apic, &mut delay_us);
        assert_eq!(r.unwrap_err(), SmpError::BadIpiVector);
    }
    #[test]
    fn wake_aps_rejects_vector_zero() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(2, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        let r = SmpImpl::wake_aps(&topo, 0x0000, &mut apic, &mut delay_us);
        assert_eq!(r.unwrap_err(), SmpError::BadIpiVector);
    }
    #[test]
    fn wake_aps_rejects_vector_0xff() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(2, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        let r = SmpImpl::wake_aps(&topo, 0xFF000, &mut apic, &mut delay_us);
        assert_eq!(r.unwrap_err(), SmpError::BadIpiVector);
    }
    #[test]
    fn wake_aps_with_zero_aps_emits_no_ipis() {
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(1, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        assert_eq!(topo.ap_count, 0);
        let mut apic = RecordingApic::new();
        let mut delay_us = |_us: u32| {};
        let count = SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us).unwrap();
        assert_eq!(count, 0);
        assert_eq!(apic.count, 0);
    }
    #[test]
    fn wake_aps_apic_timeout_surfaces() {
        struct StuckApic;
        impl ApicWriter for StuckApic {
            fn write_icr_low(&mut self, _: u32) {}
            fn write_icr_high(&mut self, _: u32) {}
            fn read_icr_low(&mut self) -> u32 {
                smp_consts::ICR_DELIVERY_STATUS_PENDING
            }
        }
        let mut buf = [0u8; 128];
        let n = build_madt_fixture(2, &mut buf).unwrap();
        let topo = SmpImpl::discover(&buf[..n]).unwrap();
        let mut apic = StuckApic;
        let mut delay_us = |_us: u32| {};
        let r = SmpImpl::wake_aps(&topo, 0x8000, &mut apic, &mut delay_us);
        assert_eq!(r.unwrap_err(), SmpError::ApicTimeout);
    }
    #[test]
    fn per_cpu_register_and_get_round_trip() {
        let mut pc: PerCpu<u32, 4> = PerCpu::new();
        pc.register(0, 100).unwrap();
        pc.register(1, 200).unwrap();
        pc.register(2, 300).unwrap();
        assert_eq!(pc.count(), 3);
        assert_eq!(*pc.get(0), 100);
        assert_eq!(*pc.get(1), 200);
        assert_eq!(*pc.get(2), 300);
        *pc.get(1) = 999;
        assert_eq!(*pc.get(1), 999);
    }
    #[test]
    fn per_cpu_register_overflow() {
        let mut pc: PerCpu<u32, 2> = PerCpu::new();
        pc.register(0, 1).unwrap();
        pc.register(1, 2).unwrap();
        let r = pc.register(2, 3);
        assert_eq!(r.unwrap_err(), SmpError::PerCpuOverflow);
    }
    #[test]
    fn per_cpu_try_get_returns_none_for_unknown() {
        let mut pc: PerCpu<u32, 4> = PerCpu::new();
        pc.register(0, 1).unwrap();
        pc.register(2, 3).unwrap();
        assert!(pc.try_get(1).is_none());
        assert!(pc.try_get(5).is_none());
        assert!(pc.try_get(0).is_some());
        assert!(pc.try_get(2).is_some());
    }
    #[test]
    fn per_cpu_handles_non_dense_apic_ids() {
        let mut pc: PerCpu<u64, 16> = PerCpu::new();
        pc.register(0, 1000).unwrap();
        pc.register(1, 1001).unwrap();
        pc.register(4, 1004).unwrap();
        pc.register(5, 1005).unwrap();
        assert_eq!(pc.count(), 4);
        assert_eq!(*pc.get(4), 1004);
        assert_eq!(*pc.get(5), 1005);
        assert!(pc.try_get(2).is_none());
        assert!(pc.try_get(3).is_none());
    }
    #[test]
    fn build_madt_fixture_is_round_trip_safe() {
        for cpus in 1..=8 {
            let mut buf = [0u8; 256];
            let n = build_madt_fixture(cpus, &mut buf).unwrap();
            let topo = SmpImpl::discover(&buf[..n]).unwrap();
            assert_eq!(topo.cpu_count(), cpus);
            assert_eq!(topo.bsp, 0);
            for i in 0..topo.ap_count {
                assert_eq!(topo.aps[i] as usize, i + 1);
            }
        }
    }

    #[test]
    fn stage14_sparse_madt_x2apic_topology_and_lockup_watchdog() {
        // 1. Sparse non-contiguous MADT with non-zero BSP (`bsp_apic_id = 4`), Type-0 xAPIC (`0, 2`),
        //    disabled entry (`8`, flags = 0), and Type-9 x2APIC (`6`, Online-Capable).
        let mut madt_buf = [0u8; madt::HEADER_LEN + 3 * 8 + MADT_LOCAL_X2APIC_LEN];
        let madt_len = madt_buf.len() as u32;
        madt_buf[0..4].copy_from_slice(&madt::SIG_APIC);
        madt_buf[4..8].copy_from_slice(&madt_len.to_le_bytes());

        let mut off = madt::HEADER_LEN;
        for &(apic_id, flags) in &[
            (0u8, madt::LOCAL_APIC_FLAG_ENABLED),
            (2u8, madt::LOCAL_APIC_FLAG_ENABLED),
            (8u8, 0u32), // disabled -> must be ignored!
        ] {
            madt_buf[off] = madt::ENTRY_LOCAL_APIC;
            madt_buf[off + 1] = 8;
            madt_buf[off + 3] = apic_id;
            madt_buf[off + 4..off + 8].copy_from_slice(&flags.to_le_bytes());
            off += 8;
        }
        // Type-9 Local x2APIC entry (`apic_id = 6`, Online-Capable)
        madt_buf[off] = MADT_ENTRY_LOCAL_X2APIC;
        madt_buf[off + 1] = MADT_LOCAL_X2APIC_LEN as u8;
        madt_buf[off + 4..off + 8].copy_from_slice(&6u32.to_le_bytes());
        madt_buf[off + 8..off + 12].copy_from_slice(&MADT_FLAG_ONLINE_CAPABLE.to_le_bytes());

        let (targets, count) = resolve_ap_apic_targets::<4>(Some(&madt_buf), 4);
        assert_eq!(count, 4);
        assert_eq!(targets, [4, 0, 2, 6], "BSP=4 must stay slot 0, followed by sparse APs 0, 2, 6");

        // Malformed MADT (entry length = 0) falls back cleanly without panicking or targeting BSP.
        let mut bad = madt_buf;
        bad[madt::HEADER_LEN + 1] = 0;
        let (fb, fb_cnt) = resolve_ap_apic_targets::<4>(Some(&bad), 2);
        assert_eq!(fb_cnt, 4);
        assert_eq!(fb[0], 2);
        assert!(!fb[1..].contains(&2), "fallback must never target BSP");

        // 2. Multi-core lockup watchdog detects stalled secondary APs and clears once ticks advance.
        let mut wd = SmpLockupWatchdog::<4>::new(2);
        assert_eq!(wd.check_stalled_mask(4, &[10, 5, 5, 5]), 0);
        assert_eq!(wd.check_stalled_mask(4, &[11, 6, 5, 6]), 0); // AP 2 stalled 1st epoch (< 2)
        assert_eq!(
            wd.check_stalled_mask(4, &[12, 7, 5, 7]),
            1 << 2,
            "AP 2 stalled across 2 epochs must raise bit 2"
        );
        assert_eq!(
            wd.check_stalled_mask(4, &[13, 8, 6, 8]),
            0,
            "AP 2 advancing tick must clear stall mask"
        );
    }
}
