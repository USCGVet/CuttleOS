//! Bootable kernel ELF for `target_enterprise`.
//!
//! This kernel is the load-bearing artefact for the project's
//! diversity-empirical claim. TASK-023 rewrote it because the prior
//! banner-only kernel never referenced the morphed surfaces in
//! `target_enterprise`: the linker dead-code-eliminated `tls.rs`,
//! `wal.rs`, `iommu.rs`, and the `HashImpl` chain construction. As a
//! result, source-level diversification did not reach the binary
//! (iteration 12: 1/19 distinct kernel ELF `.text` SHA-256s across 19
//! accepted morph cycles).
//!
//! Build:  `cargo build --release` from inside this crate
//!         (nightly + rust-src; see `rust-toolchain.toml`).
//!
//! Per-feature proof sequence emitted to COM1 16550 UART (I/O 0x3F8):
//!
//!   PROTEUS-TE OK\n                              boot banner
//!   TLS hkdf OK prk_sha=<hex16>\n                HKDF-Extract RFC 5869 §A.1
//!                                                + HKDF-Expand-Label proof
//!   TLS server_hello OK len=<N>\n                build_server_hello golden bytes
//!   WAL replay OK frames=16 lsn=<N>\n            WAL append+flush+replay
//!   IOMMU translate OK pa=<hex8>\n               IOMMU map + translate walk
//!   HASH OK digest_sha=<hex16>\n                 HashImpl over a locked fixture
//!   PROTEUS-TE HALT\n                            clean exit
//!
//! Each banner is preceded by the kernel asserting the operation's
//! output against the locked `kernel_fixtures::EXPECTED_*` constants.
//! On mismatch the kernel panics, the `panic_handler` emits
//! `PROTEUS-TE PANIC: <file>\n`, and the QEMU smoke test fails because
//! the trailing banner is absent. The host-side
//! `target_enterprise/tests/kernel_fixtures_check.rs` runs the same
//! sequence on every `cargo test` to catch drift between the algorithm
//! and the embedded expected bytes before the kernel even boots.
//!
//! No allocator. No `extern crate alloc`. Every scratch buffer is a
//! stack array sized at compile time from a `kernel_fixtures` constant.

#![no_std]
#![no_main]
// Production builds (`--cfg proteus_prod` in RUSTFLAGS, injected by
// `factory_builder build-kernel --prod`) exclude the banner self-proof
// suite and the red-team attack harness: every `banner_*` definition and
// call site is cfg-gated except `banner_continuity` / `banner_durable_seal`
// (real cross-morph durable-state work, not self-tests), and the planted
// attack surface is compiled out entirely. Prod boots are externally
// distinguishable by the `PROTEUS-TE PROD` serial line. Helpers left
// unused once banners are stripped are silenced, not deleted, so the
// banner build stays byte-for-byte identical in structure.
#![cfg_attr(proteus_prod, allow(dead_code, unused_imports, unused_mut, unused_variables))]

use core::arch::asm;
use core::panic::PanicInfo;

use bootloader_api::config::{BootloaderConfig, Mapping};
use bootloader_api::{entry_point, BootInfo};
use proteus_contracts::{
    AccessKind, AuditEvent, AuditLog, AuditVerdict, BpfContext, CrashContext, CrashDump, EBpf,
    FilterAction, FilterRule, Filesystem, HandshakeKeys, Hash, Iommu, Ipv4PacketView, NtpReply,
    NtpTimestamp, PacketFilter, PagePerms, Sntp, SymbolResolve, Tls13Client, Tls13Server, Tpm,
    TpmResponseView, Verdict, Vfs, WriteAheadLog, AUDIT_EVENT_WIRE_LEN, AUDIT_SNAPSHOT_HEADER_LEN,
    AUDIT_SNAPSHOT_MAGIC, BPF_STACK_SIZE, FS_O_RDONLY, FW_PORT_ANY, IP_PROTO_ICMP, IP_PROTO_TCP,
    IP_PROTO_UDP, SNTP_MODE_CLIENT, SNTP_MODE_SERVER, SNTP_PACKET_LEN, SNTP_VERSION,
    TPM_ALG_SHA256, TPM_CC_GET_RANDOM, TPM_RC_SUCCESS, TPM_SHA256_DIGEST_LEN, TPM_ST_NO_SESSIONS,
    TPM_ST_SESSIONS, TPM_SU_CLEAR,
};
use target_enterprise::iommu::{DeviceId, IommuImpl};
use target_enterprise::kernel_fixtures as kf;
use target_enterprise::kpti::{
    KptiImpl, PageTable, KPTI_IRETQ_VIRT, KPTI_IRQ_TIMER_VIRT, KPTI_TRAMPOLINE_VIRT, PTE_NX,
    PTE_PRESENT, PTE_USER, PTE_WRITABLE,
};
use target_enterprise::audit::{parse_header as parse_audit_header, parse_record as parse_audit_record, AuditLogImpl};
use target_enterprise::e1000::BANNER_MAC;
use target_enterprise::ebpf::{run_reference_program, EBpfImpl, REFERENCE_PROGRAM_INSNS};
use target_enterprise::firewall::{FilterRuleExt, FirewallImpl, FirewallTable};
use target_enterprise::tpm::{
    extract_get_random_bytes, MaxTpmCommandBuf, TpmImpl, TPM_GET_RANDOM_CMD_LEN,
    TPM_PCR_EXTEND_SHA256_CMD_LEN, TPM_PCR_READ_CMD_LEN, TPM_STARTUP_CMD_LEN,
};
use target_enterprise::net::{build_udp_datagram, parse_ipv4_header, parse_udp_datagram};
use target_enterprise::panic_dump::{MemorySectorSink, PanicDumpImpl, DUMP_START_LBA};
use target_enterprise::sntp::SntpImpl;
use target_enterprise::vfs::{MemRamFs, VfsImpl};
use target_enterprise::symbols::{StaticSymbolResolver, SymbolEntry};
use target_enterprise::tls::{
    build_client_finished, build_client_hello, build_server_hello, derive_handshake_keys,
    hkdf_expand_label, hkdf_extract, parse_server_hello, Tls13ClientImpl, Tls13ServerImpl,
};
use target_enterprise::wal::WalImpl;
use target_enterprise::HashImpl;
use proteus_contracts::Kpti;

/// Map all physical memory so virtio DMA buffers (kernel statics)
/// have known guest-physical addresses for QEMU virtio-blk.
pub static BOOTLOADER_CONFIG: BootloaderConfig = {
    let mut c = BootloaderConfig::new_default();
    c.mappings.physical_memory = Some(Mapping::Dynamic);
    c
};

entry_point!(kernel_main, config = &BOOTLOADER_CONFIG);

/// Physical→virtual offset for the full physical memory map
/// (`virt = phys + PHYS_MAP_OFFSET`). Required for virtio DMA.
static PHYS_MAP_OFFSET: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);
/// Guest-physical base of a usable DMA scratch region (≥ 128 KiB for
/// virtqueues + AHCI command structures + temporary page-table frames
/// for MMIO BAR mapping).
static mut DMA_PHYS_BASE: u64 = 0;
/// Bump cursor for page-table frames carved from the top of the DMA window.
static PT_ALLOC_NEXT: core::sync::atomic::AtomicU64 = core::sync::atomic::AtomicU64::new(0);

fn set_phys_offset(boot: &BootInfo) {
    let map_off = match boot.physical_memory_offset.into_option() {
        Some(o) => o,
        None => 0,
    };
    // Prefer conventional RAM in the low 4 GiB for legacy QUEUE_PFN
    // (32-bit PFN field). Skip the first 1 MiB (IVT/EBDA/bootloader).
    let mut dma = 0u64;
    for r in boot.memory_regions.iter() {
        use bootloader_api::info::MemoryRegionKind;
        if r.kind != MemoryRegionKind::Usable {
            continue;
        }
        let start = r.start;
        let end = r.end.min(0x1_0000_0000); // stay below 4 GiB
        if end <= start {
            continue;
        }
        let aligned = (start + 0xFFF) & !0xFFF;
        // 128 KiB: virtio queues + AHCI CLB/FB/CTBA + PT scratch.
        if aligned >= 0x10_0000 && end.saturating_sub(aligned) >= 0x2_0000 {
            dma = aligned;
            break;
        }
    }
    PHYS_MAP_OFFSET.store(map_off, core::sync::atomic::Ordering::Relaxed);
    // Top 16 KiB of the 128 KiB window = page-table frame pool.
    let pt_next = if dma != 0 { dma + 0x1_C000 } else { 0 };
    PT_ALLOC_NEXT.store(pt_next, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        DMA_PHYS_BASE = dma;
    }
}

/// Virtual address for a guest-physical address in the physical memory map.
fn pa_to_va(phys: u64) -> *mut u8 {
    let off = PHYS_MAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    (phys.wrapping_add(off)) as *mut u8
}

// ---- Page-table helpers for PCI MMIO BARs (outside RAM E820) ----

const PTE_P: u64 = 1;
const PTE_W: u64 = 2;
const PTE_PWT: u64 = 1 << 3;
const PTE_PCD: u64 = 1 << 4;
const PTE_PS: u64 = 1 << 7;
const PTE_ADDR_MASK: u64 = 0x000F_FFFF_FFFF_F000;

#[inline(always)]
unsafe fn read_cr3() -> u64 {
    let v: u64;
    unsafe {
        asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags));
    }
    v
}

unsafe fn alloc_pt_frame() -> u64 {
    let base = unsafe { DMA_PHYS_BASE };
    let next = PT_ALLOC_NEXT.load(core::sync::atomic::Ordering::Relaxed);
    if base == 0 || next == 0 || next + 0x1000 > base + 0x2_0000 {
        panic!("AHCI_HW: PT frame pool exhausted");
    }
    let frame = next;
    PT_ALLOC_NEXT.store(next + 0x1000, core::sync::atomic::Ordering::Relaxed);
    unsafe {
        let p = pa_to_va(frame);
        let mut i = 0usize;
        while i < 0x1000 {
            core::ptr::write_volatile(p.add(i), 0);
            i += 1;
        }
    }
    frame
}

/// Ensure guest-physical `phys` (any offset in page) is reachable via
/// `PHYS_MAP_OFFSET`. Installs a 4 KiB uncached PTE when the bootloader
/// did not map the page (typical for PCI MMIO BARs).
unsafe fn ensure_mmio_page(phys: u64) -> *mut u8 {
    let phys_page = phys & !0xFFFu64;
    let off = PHYS_MAP_OFFSET.load(core::sync::atomic::Ordering::Relaxed);
    if off == 0 {
        panic!("AHCI_HW: no physical_memory_offset for MMIO");
    }
    let va = phys_page.wrapping_add(off);
    let indices = [
        ((va >> 39) & 0x1FF) as usize,
        ((va >> 30) & 0x1FF) as usize,
        ((va >> 21) & 0x1FF) as usize,
        ((va >> 12) & 0x1FF) as usize,
    ];
    let mut table = unsafe { read_cr3() } & PTE_ADDR_MASK;
    let mut level = 0usize;
    while level < 3 {
        let ent_ptr = pa_to_va(table).cast::<u64>().add(indices[level]);
        let ent = unsafe { core::ptr::read_volatile(ent_ptr) };
        if ent & PTE_P == 0 {
            let new_t = unsafe { alloc_pt_frame() };
            unsafe {
                core::ptr::write_volatile(ent_ptr, new_t | PTE_P | PTE_W);
            }
            table = new_t;
        } else if ent & PTE_PS != 0 {
            // Huge page already present — only valid if it covers this
            // phys (bootloader RAM maps). MMIO VAs should not hit this.
            return va as *mut u8;
        } else {
            table = ent & PTE_ADDR_MASK;
        }
        level += 1;
    }
    let leaf = pa_to_va(table).cast::<u64>().add(indices[3]);
    let ent = unsafe { core::ptr::read_volatile(leaf) };
    if ent & PTE_P == 0 || (ent & (PTE_PWT | PTE_PCD)) != (PTE_PWT | PTE_PCD) {
        // Present | Writable | PWT | PCD (uncached MMIO).
        let pte = phys_page | PTE_P | PTE_W | PTE_PWT | PTE_PCD;
        unsafe {
            core::ptr::write_volatile(leaf, pte);
            asm!("invlpg [{}]", in(reg) va, options(nostack, preserves_flags));
        }
    }
    va as *mut u8
}

unsafe fn mmio_read32(phys: u64) -> u32 {
    let page = unsafe { ensure_mmio_page(phys) };
    let off = (phys & 0xFFF) as usize;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    let val = unsafe { core::ptr::read_volatile(page.add(off) as *const u32) };
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    val
}

unsafe fn mmio_write32(phys: u64, val: u32) {
    let page = unsafe { ensure_mmio_page(phys) };
    let off = (phys & 0xFFF) as usize;
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
    unsafe {
        core::ptr::write_volatile(page.add(off) as *mut u32, val);
    }
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

unsafe fn mmio_read64(phys: u64) -> u64 {
    let lo = unsafe { mmio_read32(phys) } as u64;
    let hi = unsafe { mmio_read32(phys + 4) } as u64;
    lo | (hi << 32)
}

unsafe fn mmio_write64(phys: u64, val: u64) {
    unsafe {
        mmio_write32(phys, val as u32);
        mmio_write32(phys + 4, (val >> 32) as u32);
    }
}

// ============================================================
// 16550 UART driver (COM1)
// ============================================================

/// QEMU 16550 UART base I/O port. THR/RBR at +0, LSR at +5.
const COM1: u16 = 0x3F8;
/// LSR bit 5: transmitter holding register empty.
const LSR_THRE: u8 = 1 << 5;

#[inline(always)]
unsafe fn outb(port: u16, val: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") val, options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
unsafe fn inb(port: u16) -> u8 {
    let val: u8;
    unsafe {
        asm!("in al, dx", out("al") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

#[inline(always)]
unsafe fn outl(port: u16, val: u32) {
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") val, options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
unsafe fn inl(port: u16) -> u32 {
    let val: u32;
    unsafe {
        asm!("in eax, dx", out("eax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

#[inline(always)]
unsafe fn outw(port: u16, val: u16) {
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") val, options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
unsafe fn inw(port: u16) -> u16 {
    let val: u16;
    unsafe {
        asm!("in ax, dx", out("ax") val, in("dx") port, options(nomem, nostack, preserves_flags));
    }
    val
}

/// PCI configuration-space address / data ports (mechanism #1).
const PCI_CONFIG_ADDR: u16 = 0xCF8;
const PCI_CONFIG_DATA: u16 = 0xCFC;

/// Real PCI config-space bus: issues `out`/`in` against 0xCF8/0xCFC.
/// This is the hardware-truth counterpart to `RecordingBus` — every
/// read is a real I/O cycle observed by QEMU's PCI host bridge.
struct RealPciBus;

impl proteus_contracts::PciConfigBus for RealPciBus {
    fn read_dword(&mut self, addr: proteus_contracts::PciAddress, offset: u8) -> u32 {
        let o = (offset as u32) & 0xFC;
        let conf = 0x8000_0000u32
            | ((addr.bus as u32) << 16)
            | ((addr.device as u32) << 11)
            | ((addr.function as u32) << 8)
            | o;
        unsafe {
            outl(PCI_CONFIG_ADDR, conf);
            inl(PCI_CONFIG_DATA)
        }
    }
    fn write_dword(
        &mut self,
        addr: proteus_contracts::PciAddress,
        offset: u8,
        value: u32,
    ) {
        let o = (offset as u32) & 0xFC;
        let conf = 0x8000_0000u32
            | ((addr.bus as u32) << 16)
            | ((addr.device as u32) << 11)
            | ((addr.function as u32) << 8)
            | o;
        unsafe {
            outl(PCI_CONFIG_ADDR, conf);
            outl(PCI_CONFIG_DATA, value);
        }
    }
}

fn serial_init() {
    // 16550 init: 38400 baud, 8N1, FIFO enabled.
    unsafe {
        outb(COM1 + 1, 0x00); // disable interrupts
        outb(COM1 + 3, 0x80); // enable DLAB
        outb(COM1 + 0, 0x03); // divisor lo = 3 (38400 baud)
        outb(COM1 + 1, 0x00); // divisor hi
        outb(COM1 + 3, 0x03); // 8N1, DLAB off
        outb(COM1 + 2, 0xC7); // FIFO enable, clear, 14-byte threshold
        outb(COM1 + 4, 0x0B); // IRQs enabled, RTS/DSR set
    }
}

fn serial_write_byte(b: u8) {
    unsafe {
        while inb(COM1 + 5) & LSR_THRE == 0 {
            core::hint::spin_loop();
        }
        outb(COM1, b);
    }
}

fn serial_write_str(s: &str) {
    for b in s.bytes() {
        if b == b'\n' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(b);
    }
}

fn serial_write_bytes(buf: &[u8]) {
    for &b in buf {
        if b == b'\n' {
            serial_write_byte(b'\r');
        }
        serial_write_byte(b);
    }
}

// ============================================================
// Tiny no_std hex / decimal formatters (no `core::fmt`)
// ============================================================

const HEX_DIGITS: &[u8; 16] = b"0123456789abcdef";

/// Write the first `n` bytes of `bytes` as lowercase hex into `out`.
/// Caller-supplied `out` must be at least `n * 2` bytes long.
fn hex_encode(bytes: &[u8], n: usize, out: &mut [u8]) -> usize {
    let take = if n > bytes.len() { bytes.len() } else { n };
    let mut i = 0usize;
    while i < take {
        let b = bytes[i];
        out[i * 2] = HEX_DIGITS[(b >> 4) as usize];
        out[i * 2 + 1] = HEX_DIGITS[(b & 0x0F) as usize];
        i += 1;
    }
    take * 2
}

/// Format `val` as zero-padded 8-character lowercase hex (the low 32
/// bits). Writes 8 bytes into `out`.
fn hex_u32(val: u32, out: &mut [u8; 8]) {
    let mut i = 0usize;
    while i < 8 {
        let shift = 28 - i * 4;
        let nyb = ((val >> shift) & 0xF) as usize;
        out[i] = HEX_DIGITS[nyb];
        i += 1;
    }
}

/// Format `val` as decimal into `out`, returning the number of bytes
/// written. `out` must be at least 20 bytes long (max u64 decimal).
fn dec_u64(mut val: u64, out: &mut [u8]) -> usize {
    if val == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut k = 0usize;
    while val > 0 {
        tmp[k] = b'0' + ((val % 10) as u8);
        val /= 10;
        k += 1;
    }
    // tmp is little-endian decimal; reverse into out.
    let mut i = 0usize;
    while i < k {
        out[i] = tmp[k - 1 - i];
        i += 1;
    }
    k
}

// ============================================================
// Banner emitters — one per morphed surface
// ============================================================

/// Assert `actual == expected` byte-for-byte. On mismatch, panic with
/// a message naming the surface; the panic handler emits the panic
/// banner over serial, the QEMU smoke test then fails because the
/// trailing per-feature banner does not appear.
fn assert_eq_bytes(actual: &[u8], expected: &[u8], surface: &'static str) {
    if actual.len() != expected.len() {
        panic!("{} length mismatch", surface);
    }
    let mut i = 0usize;
    while i < actual.len() {
        if actual[i] != expected[i] {
            panic!("{} byte mismatch", surface);
        }
        i += 1;
    }
}

/// TLS: run HKDF-Extract + HKDF-Expand-Label against the locked
/// fixtures, assert byte-equality, emit
/// `TLS hkdf OK prk_sha=<hex16>\n`.
///
/// Returns the PRK so a follow-on banner could chain off it; the kernel
/// does not need it again here.
#[cfg(not(proteus_prod))]
fn banner_tls_hkdf() {
    let mut prk = [0u8; 32];
    <Tls13ServerImpl as Tls13Server>::hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk);
    assert_eq_bytes(&prk, &kf::HKDF_EXPECTED_PRK, "TLS HKDF-Extract");

    // Also exercise the freestanding fn so the diversifier-renamed
    // local bindings in hkdf_extract (`total_label_len`, `sid_len`,
    // etc., per iteration 12) all show in the live call graph.
    let mut prk2 = [0u8; 32];
    hkdf_extract(&kf::HKDF_SALT, &kf::HKDF_IKM, &mut prk2);
    assert_eq_bytes(&prk2, &kf::HKDF_EXPECTED_PRK, "TLS HKDF-Extract(2)");

    let mut expanded = [0u8; kf::HKDF_EXPAND_OUT_LEN];
    hkdf_expand_label(&prk, kf::HKDF_EXPAND_LABEL, &kf::HKDF_INFO, &mut expanded);
    assert_eq_bytes(
        &expanded[..8],
        &kf::HKDF_EXPECTED_EXPAND_PREFIX8,
        "TLS HKDF-Expand-Label",
    );

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"TLS hkdf OK prk_sha=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += hex_encode(&prk, 8, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// TLS: build a ServerHello against the locked ClientHello fixture,
/// assert byte length and prefix, emit `TLS server_hello OK len=<N>\n`.
#[cfg(not(proteus_prod))]
fn banner_tls_server_hello() {
    let mut out = [0u8; 256];
    let n = match build_server_hello(
        &kf::CLIENT_HELLO,
        &kf::SERVER_RANDOM,
        &kf::SERVER_PUBKEY,
        None,
        &mut out,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TLS build_server_hello returned Err"),
    };
    if n != kf::SERVER_HELLO_EXPECTED_LEN {
        panic!("TLS ServerHello length drift");
    }
    assert_eq_bytes(
        &out[..8],
        &kf::SERVER_HELLO_EXPECTED_PREFIX8,
        "TLS ServerHello prefix",
    );

    let mut line = [0u8; 48];
    let mut pos = 0usize;
    let prefix = b"TLS server_hello OK len=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// TLS 1.3 client (TASK-049): build a ClientHello against the locked
/// fixtures, assert byte length + prefix; parse the locked
/// ServerHello fixture, assert the recovered server_pubkey matches;
/// run the RFC 8446 §7.1 key schedule against the locked shared
/// secret, assert all three secrets match the locked goldens; build
/// the client Finished verify_data against a synthetic transcript
/// hash, assert byte-equality.
///
/// Emits:
///   `TLS client_hello OK len=<dec>\n`
///   `TLS client handshake_keys OK prk=<hex16>\n`
///
/// A kernel that perturbs the ClientHello layout, the ServerHello
/// parser, the key-schedule label or chaining order, or the Finished
/// MAC construction panics here and the banners never appear.
#[cfg(not(proteus_prod))]
fn banner_tls_client() {
    // 1) ClientHello build — length + prefix lock.
    let mut ch = [0u8; 256];
    let ch_len = match build_client_hello(
        &kf::TLS_CLIENT_RANDOM,
        &kf::TLS_CLIENT_PUBKEY,
        &mut ch,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TLS build_client_hello returned Err"),
    };
    if ch_len != kf::TLS_CLIENT_HELLO_EXPECTED_LEN {
        panic!("TLS ClientHello length drift");
    }
    assert_eq_bytes(
        &ch[..8],
        &kf::TLS_CLIENT_HELLO_EXPECTED_PREFIX8,
        "TLS ClientHello prefix",
    );

    // Also exercise the trait surface so the diversifier-renamed
    // helpers inside the impl all show in the live call graph.
    let mut ch2 = [0u8; 256];
    let ch2_len = match <Tls13ClientImpl as Tls13Client>::build_client_hello(
        &kf::TLS_CLIENT_RANDOM,
        &kf::TLS_CLIENT_PUBKEY,
        &mut ch2,
    ) {
        Ok(n) => n,
        Err(_) => panic!("Tls13Client::build_client_hello returned Err"),
    };
    if ch2_len != ch_len {
        panic!("TLS ClientHello length differs between free fn + trait");
    }
    assert_eq_bytes(&ch2[..ch2_len], &ch[..ch_len], "TLS ClientHello bytes");

    // Emit the first banner now that the ClientHello is locked.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"TLS client_hello OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(ch_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // 2) ServerHello parse — recover server_pubkey + assert.
    let parsed = match parse_server_hello(&kf::TLS_SERVER_HELLO_FIXTURE) {
        Ok(p) => p,
        Err(_) => panic!("TLS parse_server_hello returned Err"),
    };
    // Expect server_pubkey = 32 × 0x09.
    let mut i = 0usize;
    while i < 32 {
        if parsed.server_pubkey[i] != 0x09 {
            panic!("TLS parsed server_pubkey drift");
        }
        i += 1;
    }
    if parsed.cipher_suite != 0x1301 {
        panic!("TLS parsed cipher_suite drift");
    }

    // 3) Key schedule — derive + lock the three secrets.
    let mut keys = HandshakeKeys {
        handshake_secret: [0u8; 32],
        client_handshake_traffic_secret: [0u8; 32],
        server_handshake_traffic_secret: [0u8; 32],
    };
    derive_handshake_keys(
        &kf::TLS_SHARED_SECRET,
        &ch[..ch_len],
        &kf::TLS_SERVER_HELLO_FIXTURE,
        &mut keys,
    );
    assert_eq_bytes(
        &keys.handshake_secret,
        &kf::TLS_HANDSHAKE_SECRET_EXPECTED,
        "TLS handshake_secret",
    );
    assert_eq_bytes(
        &keys.client_handshake_traffic_secret,
        &kf::TLS_CLIENT_HS_TRAFFIC_EXPECTED,
        "TLS c_hs_traffic",
    );
    assert_eq_bytes(
        &keys.server_handshake_traffic_secret,
        &kf::TLS_SERVER_HS_TRAFFIC_EXPECTED,
        "TLS s_hs_traffic",
    );

    // 4) Client Finished MAC — lock verify_data bytes.
    let mut vd = [0u8; 32];
    build_client_finished(
        &keys.client_handshake_traffic_secret,
        &kf::TLS_FINISHED_TRANSCRIPT_HASH,
        &mut vd,
    );
    assert_eq_bytes(&vd, &kf::TLS_CLIENT_FINISHED_EXPECTED, "TLS client Finished");

    // Emit the second banner: `TLS client handshake_keys OK prk=<hex16>`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TLS client handshake_keys OK prk=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += hex_encode(&keys.handshake_secret, 8, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TLS 1.3 session resumption (RFC 8446 §4.6.1) — cross-morph session
/// continuity (Class B). Full chain: master secret → resumption master
/// secret → resumption PSK → sealed blob → [morph boundary] → open blob
/// → early secret from the RELOADED PSK. The banner proves the reloaded
/// early secret is byte-identical to the continuous-process one, and
/// that a corrupted durable PSK is rejected rather than silently
/// producing a wrong early secret. Emits
/// `TLS RESUME OK psk=<hex8>\n`.
#[cfg(not(proteus_prod))]
fn banner_tls_resumption() {
    use target_enterprise::tls::{
        derive_resumption_master_secret, derive_resumption_psk, early_secret_from_psk,
        open_resumption_psk, seal_resumption_psk, RESUMPTION_BLOB_LEN,
    };

    // Fixture handshake output (a real deployment takes these from the
    // completed handshake; the banner exercises the derivation path).
    let master_secret = [0x42u8; 32];
    let transcript = b"proteus kernel resumption banner transcript";
    let ticket_nonce = [0xA5u8; 32];

    let mut rms = [0u8; 32];
    derive_resumption_master_secret(&master_secret, transcript, &mut rms);
    let mut psk = [0u8; 32];
    derive_resumption_psk(&rms, &ticket_nonce, &mut psk);
    let mut early_direct = [0u8; 32];
    early_secret_from_psk(&psk, &mut early_direct);

    // Sealed blob = the durable artifact that crosses a morph cycle.
    let mut blob = [0u8; RESUMPTION_BLOB_LEN];
    seal_resumption_psk(&psk, &ticket_nonce, &mut blob);

    // --- simulated morph boundary: parse back as the successor kernel ---
    let (nonce2, psk2) = match open_resumption_psk(&blob) {
        Ok(t) => t,
        Err(_) => panic!("TLS RESUME: sealed blob rejected own PSK"),
    };
    if nonce2 != ticket_nonce || psk2 != psk {
        panic!("TLS RESUME: blob round-trip drift");
    }
    let mut early_reloaded = [0u8; 32];
    early_secret_from_psk(&psk2, &mut early_reloaded);
    if early_reloaded != early_direct {
        panic!("TLS RESUME: early secret drift across boundary");
    }

    // Corrupt durable PSK must fail closed, not yield a wrong secret.
    let mut bad = blob;
    bad[50] ^= 0x80;
    if open_resumption_psk(&bad).is_ok() {
        panic!("TLS RESUME: corrupted blob accepted");
    }

    let mut line = [0u8; 48];
    let mut pos = 0usize;
    let prefix = b"TLS RESUME OK psk=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let be: [u8; 4] = [psk[0], psk[1], psk[2], psk[3]];
    let mut hx = [0u8; 8];
    hex_encode(&be, 4, &mut hx);
    line[pos..pos + 8].copy_from_slice(&hx);
    pos += 8;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// WAL: instantiate a 4 KiB WalImpl, append 16 fixture frames, flush,/// replay, assert the frame count and final LSN match the fixture
/// constants, emit `WAL replay OK frames=16 lsn=<N>\n`.
#[cfg(not(proteus_prod))]
fn banner_wal_replay() {
    let mut wal: WalImpl<{ kf::WAL_CAPACITY }> = WalImpl::new();
    let mut i = 0usize;
    while i < kf::WAL_FRAMES {
        let payload = [i as u8; kf::WAL_PAYLOAD_LEN];
        if wal.append(&payload).is_err() {
            panic!("WAL append failed");
        }
        i += 1;
    }
    // TASK-161: durable flush requires CapProof (DURABLE_WAL_WRITE).
    // Banner path is privileged init — self-grant the WAL durable bit.
    if wal
        .flush(target_enterprise::wal::durable_wal_proof_init())
        .is_err()
    {
        panic!("WAL flush failed");
    }
    if wal.next_lsn() != kf::WAL_EXPECTED_NEXT_LSN {
        panic!("WAL next_lsn drift");
    }
    // Walk the durable prefix; assert frame count and order.
    let mut seen: u64 = 0;
    let mut last_lsn: u64 = 0;
    wal.replay(&mut |lsn, payload| {
        seen += 1;
        if lsn != last_lsn + 1 {
            panic!("WAL replay LSN out of order");
        }
        last_lsn = lsn;
        if payload.len() != kf::WAL_PAYLOAD_LEN {
            panic!("WAL replay payload length drift");
        }
        let expected_byte = (lsn - 1) as u8;
        let mut j = 0usize;
        while j < payload.len() {
            if payload[j] != expected_byte {
                panic!("WAL replay payload content drift");
            }
            j += 1;
        }
    });
    if seen != kf::WAL_FRAMES as u64 {
        panic!("WAL replay frame count drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"WAL replay OK frames=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(seen, &mut line[pos..]);
    let mid = b" lsn=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(last_lsn, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// IOMMU: instantiate `IommuImpl<4, 8, 16>`, create a domain, bind one
/// device, map one page, translate, assert the host PA matches the
/// locked fixture, emit `IOMMU translate OK pa=<hex8>\n`.
#[cfg(not(proteus_prod))]
fn banner_iommu_translate() {
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

/// HASH: hash the locked fixture input through `HashImpl`, assert the
/// 32-byte digest matches the locked expected bytes, emit
/// `HASH OK digest_sha=<hex16>\n`.
#[cfg(not(proteus_prod))]
fn banner_hash_digest() {
    let mut got = [0u8; 32];
    HashImpl::hash(kf::HASH_INPUT, &mut got);
    assert_eq_bytes(&got, &kf::HASH_EXPECTED, "HashImpl digest");

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"HASH OK digest_sha=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += hex_encode(&got, 8, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

/// NET: build the canonical UDP/IPv4 datagram through
/// [`target_enterprise::net::build_udp_datagram`], assert the 38 emitted
/// bytes match the locked golden fixture in `kernel_fixtures`, parse
/// the datagram back through `parse_ipv4_header` + `parse_udp_datagram`
/// and assert the recovered src_ip / dst_ip / ttl / ident / port
/// fields, then emit
/// `NET build OK len=<dec> ip_cksum=<hex4> udp_cksum=<hex4>\n`.
///
/// The byte-equality check against `NET_EXPECTED_DATAGRAM` is the
/// load-bearing wire-equivalence proof inside the kernel: a morph
/// candidate that produces different bytes panics here rather than
/// reaching the trailing PROTEUS-TE HALT banner — the QEMU smoke test
/// then surfaces the missing banner as a failure.
#[cfg(not(proteus_prod))]
fn banner_net_build() {
    let mut buf = [0u8; kf::NET_EXPECTED_LEN];
    let n = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut buf,
    )
    .unwrap_or_else(|_| panic!("NET build_udp_datagram failed"));
    if n != kf::NET_EXPECTED_LEN {
        panic!("NET emitted length drift");
    }
    assert_eq_bytes(&buf[..n], &kf::NET_EXPECTED_DATAGRAM, "NET datagram");

    let ip = parse_ipv4_header(&buf[..n])
        .unwrap_or_else(|_| panic!("NET parse_ipv4_header rejected own output"));
    if ip.src_ip != kf::NET_SRC_IP
        || ip.dst_ip != kf::NET_DST_IP
        || ip.ttl != kf::NET_TTL
        || ip.identification != kf::NET_IDENT
        || ip.header_checksum != kf::NET_EXPECTED_IP_CHECKSUM
    {
        panic!("NET IPv4 parse drift");
    }

    let udp = parse_udp_datagram(kf::NET_SRC_IP, kf::NET_DST_IP, &buf[20..n])
        .unwrap_or_else(|_| panic!("NET parse_udp_datagram rejected own output"));
    if udp.src_port != kf::NET_SRC_PORT
        || udp.dst_port != kf::NET_DST_PORT
        || udp.checksum != kf::NET_EXPECTED_UDP_CHECKSUM
        || udp.payload_len != kf::NET_PAYLOAD.len()
    {
        panic!("NET UDP parse drift");
    }

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"NET build OK len=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    let mid = b" ip_cksum=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    let mut hex_ip = [0u8; 8];
    hex_u32(kf::NET_EXPECTED_IP_CHECKSUM as u32, &mut hex_ip);
    // Take the low 4 chars (16-bit value).
    line[pos..pos + 4].copy_from_slice(&hex_ip[4..]);
    pos += 4;
    let mid2 = b" udp_cksum=";
    line[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    let mut hex_udp = [0u8; 8];
    hex_u32(kf::NET_EXPECTED_UDP_CHECKSUM as u32, &mut hex_udp);
    line[pos..pos + 4].copy_from_slice(&hex_udp[4..]);
    pos += 4;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// KPTI: build a synthetic kernel L4 (kernel .text, heap, IDT, signing
// key, three KPTI trampoline pages, two user pages), call
// `KptiImpl::build_user_view` to produce a per-task user view that
// strips the four secret regions, then `validate_user_view` to assert
// the locked invariants hold. On success emit:
//   `KPTI build_user_view OK secrets=4\n`
//   `KPTI validate_user_view OK violations=0\n`
//
// The synthetic fixture mirrors the post-boot kernel L4 shape (kernel
// `.text` at canonical-high addresses, KPTI trampolines at the locked
// KPTI_*_VIRT slots, user code/stack at canonical-low addresses) so
// the validate path exercises a realistic separation, not a contrived
// minimum.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_kpti() {
    let mut kernel: PageTable<32> = PageTable::new();
    // Kernel secrets — these MUST be stripped from the user view.
    let secrets: [u64; 4] = [
        0xFFFF_FFFF_8000_0000, // kernel .text
        0xFFFF_FFFF_9000_0000, // kernel heap
        0xFFFF_FFFF_A000_0000, // IDT
        0xFFFF_FFFF_B000_0000, // Ed25519 private key page
    ];
    kernel.map(secrets[0], PTE_PRESENT).expect("kpti map .text");
    kernel
        .map(secrets[1], PTE_PRESENT | PTE_WRITABLE | PTE_NX)
        .expect("kpti map heap");
    kernel
        .map(secrets[2], PTE_PRESENT | PTE_NX)
        .expect("kpti map IDT");
    kernel
        .map(secrets[3], PTE_PRESENT | PTE_NX)
        .expect("kpti map signing-key");

    // KPTI trampolines — USER bit set so the build path retains them.
    kernel
        .map(KPTI_TRAMPOLINE_VIRT, PTE_PRESENT | PTE_USER)
        .expect("kpti map SYSCALL trampoline");
    kernel
        .map(KPTI_IRETQ_VIRT, PTE_PRESENT | PTE_USER)
        .expect("kpti map iretq trampoline");
    kernel
        .map(KPTI_IRQ_TIMER_VIRT, PTE_PRESENT | PTE_USER)
        .expect("kpti map timer trampoline");

    // User pages — USER bit set; build path keeps these.
    kernel
        .map(0x0000_0000_4000_0000, PTE_PRESENT | PTE_USER | PTE_NX)
        .expect("kpti map user code");
    kernel
        .map(
            0x0000_0000_5000_0000,
            PTE_PRESENT | PTE_USER | PTE_WRITABLE | PTE_NX,
        )
        .expect("kpti map user stack");

    let user = KptiImpl::<32>::build_user_view(&kernel, &secrets);

    // Emit build banner: `KPTI build_user_view OK secrets=4\n`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"KPTI build_user_view OK secrets=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(secrets.len() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Validate. Panic on any violation — the QEMU smoke test then
    // surfaces the missing banner as a failure.
    if let Err(violation) = KptiImpl::<32>::validate_user_view(&user, &kernel, &secrets) {
        // Touch `violation` to avoid `unused_variables`; emit a tag
        // before panicking so even a panic-handler-eaten message at
        // least surfaces the violation kind.
        serial_write_str("KPTI VALIDATE FAIL: ");
        match violation {
            proteus_contracts::KptiViolation::SecretLeaked { .. } => {
                serial_write_str("SecretLeaked\n")
            }
            proteus_contracts::KptiViolation::UserPageMissing { .. } => {
                serial_write_str("UserPageMissing\n")
            }
            proteus_contracts::KptiViolation::KernelBitsSetOnUserPage { .. } => {
                serial_write_str("KernelBitsSetOnUserPage\n")
            }
        }
        panic!("KPTI validate_user_view returned an invariant violation");
    }

    // Emit validate banner: `KPTI validate_user_view OK violations=0\n`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"KPTI validate_user_view OK violations=0";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
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
#[cfg(not(proteus_prod))]
fn banner_dma() {
    use proteus_contracts::Iommu;
    use proteus_contracts::caps::NET_RAW;
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

// ============================================================
// TASK-018: NVMe driver round-trip. Construct an in-kernel
// `MemNvmeController` emulator, drive an `NvmeImpl` through the
// spec-mandated bring-up + IO-queue creation + Identify Controller
// + write+read round-trip, emit:
//   `NVMe init OK ctrl=PROTEUS-NVME-EMU\n`
//   `NVMe read_lba(7) OK first_byte=A5\n`
//
// The emulator runs in-kernel because the QEMU smoke test boots
// without an actual NVMe device attached (factory_builder doesn't
// pass `-device nvme,drive=...`). Running the emulator in-kernel is
// the same pattern banner_iommu_translate / banner_kpti use — the
// algorithmic core is exercised against synthetic state, proving the
// driver pipeline is functionally correct without requiring real
// hardware.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_nvme() {
    use target_enterprise::nvme::{
        MemNvmeController, NvmeImpl, IDENTIFY_BUF_SIZE, NVME_BLOCK_SIZE,
    };

    // Construct the emulator + driver. Emulator's disk is 32 KiB (64
    // blocks) — small enough to live on the kernel stack.
    let mut drv = NvmeImpl::new(MemNvmeController::new());

    // Bring up the controller, create I/O queues.
    if drv.bring_up(0x1000, 0x2000).is_err() {
        panic!("NVMe bring_up failed");
    }
    if drv.create_io_queues(0x3000, 0x4000).is_err() {
        panic!("NVMe create_io_queues failed");
    }

    // Identify Controller — emulator stamps "PROTEUS-NVME-EMU" into
    // bytes [4..24] of the response. Confirm.
    let mut ident = [0u8; IDENTIFY_BUF_SIZE];
    if drv.identify_controller(0x5000, &mut ident).is_err() {
        panic!("NVMe identify_controller failed");
    }
    if &ident[4..20] != b"PROTEUS-NVME-EMU" {
        panic!("NVMe identify_controller SN mismatch");
    }

    // Emit init banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVMe init OK ctrl=PROTEUS-NVME-EMU";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Identify Namespace — populates disk_blocks (=64).
    let nsze = match drv.identify_namespace(0x5000) {
        Ok(n) => n,
        Err(_) => panic!("NVMe identify_namespace failed"),
    };
    if nsze != 64 {
        panic!("NVMe namespace block count drift");
    }

    // Write a fixture pattern to LBA 7, read it back, confirm.
    let mut write_buf = [0u8; NVME_BLOCK_SIZE];
    write_buf[0] = 0xA5; // First byte we'll surface in the banner.
    for i in 1..NVME_BLOCK_SIZE {
        write_buf[i] = ((i * 13) & 0xFF) as u8;
    }
    if drv.try_write_block(7, &write_buf, 0x6000).is_err() {
        panic!("NVMe try_write_block failed");
    }
    let mut read_buf = [0u8; NVME_BLOCK_SIZE];
    if drv.try_read_block(7, &mut read_buf, 0x6000).is_err() {
        panic!("NVMe try_read_block failed");
    }
    // Byte-equality check — load-bearing: if any byte differs, the
    // banner is suppressed and the QEMU smoke test fails.
    let mut i = 0usize;
    while i < NVME_BLOCK_SIZE {
        if read_buf[i] != write_buf[i] {
            panic!("NVMe read_back byte mismatch");
        }
        i += 1;
    }

    // Emit read_lba banner with the first byte (0xA5).
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVMe read_lba(7) OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&read_buf[..1], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TCP: drive a full 3-way handshake (LISTEN → SYN_RCVD → ESTABLISHED)
// then a clean teardown (FIN-from-peer → CLOSE_WAIT → close() → LAST_ACK
// → ACK → CLOSED). Every transition exercises real TCB state arithmetic
// AND a real wire-byte round-trip through `TcpImpl::build_segment` +
// `TcpImpl::parse_segment` (checksum-verified). Emits:
//   `TCP handshake OK state=ESTABLISHED seq=<hex8>\n`
//   `TCP teardown OK state=CLOSED snd_nxt=<hex8>\n`
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_tcp() {
    use proteus_contracts::{tcp_flags, Tcp};
    use target_enterprise::tcp::{close, process_segment, Tcb, TcpImpl, TcpState};

    let server_ip: [u8; 4] = [10, 0, 0, 2];
    let client_ip: [u8; 4] = [10, 0, 0, 1];
    let server_port: u16 = 8443;
    let client_port: u16 = 54321;
    let client_isn: u32 = 0x1000_0000;

    // Step 1: passive open.
    let mut tcb = Tcb::listen(server_ip, server_port, 65535);
    if tcb.state != TcpState::Listen {
        panic!("TCP listen did not produce Listen state");
    }

    // Step 2: client → server SYN.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn,
        0,
        tcp_flags::SYN,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build SYN failed"),
    };
    let syn = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse SYN failed (checksum?)"),
    };
    let (next_tcb, syn_ack_hint) = match process_segment(tcb, &syn, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process SYN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::SynReceived {
        panic!("TCP SYN did not move TCB to SynReceived");
    }
    if !syn_ack_hint.present {
        panic!("TCP process SYN must produce a SYN+ACK reply hint");
    }
    let server_isn = syn_ack_hint.seq;

    // Step 3: client → server ACK of SYN+ACK.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build ACK-of-SYN failed"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse ACK-of-SYN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &ack, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process ACK-of-SYN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::Established {
        panic!("TCP 3-way handshake did not reach Established");
    }
    let established_seq = tcb.snd_nxt;

    // Emit handshake banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TCP handshake OK state=ESTABLISHED seq=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let bytes = established_seq.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&bytes, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Step 4: client → server FIN (peer initiating close).
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::FIN | tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build FIN failed"),
    };
    let fin = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse FIN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &fin, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process FIN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::CloseWait {
        panic!("TCP FIN did not move TCB to CloseWait");
    }

    // Step 5: local close() → LastAck.
    let (next_tcb, fin_hint) = match close(tcb) {
        Ok(t) => t,
        Err(_) => panic!("TCP close() failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::LastAck {
        panic!("TCP close() did not produce LastAck");
    }
    if !fin_hint.present {
        panic!("TCP close() must produce FIN reply hint");
    }

    // Step 6: client → server ACK of our FIN.
    let mut buf = [0u8; 64];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(2),
        tcb.snd_nxt,
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("TCP build ACK-of-our-FIN failed"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("TCP parse ACK-of-our-FIN failed"),
    };
    let (next_tcb, _reply) = match process_segment(tcb, &ack, 0xCAFE) {
        Ok(t) => t,
        Err(_) => panic!("TCP process ACK-of-our-FIN failed"),
    };
    tcb = next_tcb;
    if tcb.state != TcpState::Closed {
        panic!("TCP teardown did not reach Closed");
    }

    // Emit teardown banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TCP teardown OK state=CLOSED snd_nxt=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let bytes = tcb.snd_nxt.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&bytes, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// HTTP/1.1: parse a fixture `GET /healthz HTTP/1.1` request through
// `HttpImpl::parse_request`, then build a 200 OK response with
// `Content-Type: text/plain` and body "OK" through
// `HttpImpl::build_response`. Asserts the parsed method/path AND the
// byte-exact response prefix. Emits:
//   `HTTP parse OK method=GET path=/healthz\n`
//   `HTTP build OK status=200 bytes=<N>\n`
//
// A morph that perturbs the request-line tokenizer, the header-block
// scanner, or the response status-line emitter panics inside this
// banner and the trailing `PROTEUS-TE HALT` is suppressed.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_http() {
    use proteus_contracts::{Http, HttpMethod};
    use target_enterprise::http::HttpImpl;

    // --- parse ---
    let req: &[u8] = b"GET /healthz HTTP/1.1\r\nHost: localhost\r\nUser-Agent: probe\r\n\r\n";
    let view = match HttpImpl::parse_request(req) {
        Ok(v) => v,
        Err(_) => panic!("HTTP parse_request returned Err for healthz fixture"),
    };
    if view.method != HttpMethod::Get {
        panic!("HTTP parse: method drift");
    }
    if view.path != b"/healthz" {
        panic!("HTTP parse: path drift");
    }
    if view.version_minor != 1 {
        panic!("HTTP parse: version drift");
    }
    // Header lookup must find Host case-insensitively.
    match HttpImpl::find_header(view.headers_raw, b"host") {
        Some(v) if v == b"localhost" => {}
        Some(_) => panic!("HTTP find_header: host value drift"),
        None => panic!("HTTP find_header: missing Host"),
    }
    serial_write_str("HTTP parse OK method=GET path=/healthz\n");

    // --- build ---
    let mut out = [0u8; 96];
    let n = match HttpImpl::build_response(200, b"text/plain", b"OK", &mut out) {
        Ok(n) => n,
        Err(_) => panic!("HTTP build_response returned Err"),
    };
    // Byte-exact assert on the full response we expect from the locked
    // wire surface.
    let expected: &[u8] =
        b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 2\r\n\r\nOK";
    if n != expected.len() {
        panic!("HTTP build: length drift");
    }
    assert_eq_bytes(&out[..n], expected, "HTTP response");

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"HTTP build OK status=200 bytes=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    pos += dec_u64(n as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// DNS/RFC 1035: build an A-record query for `proteus.local`, parse it
// to recover the question name byte-for-byte, then build a response
// pointing to 10.0.0.42 and assert the resulting bytes match the
// locked golden encoding. Emits:
//   `DNS query OK id=<hex4> qname=proteus.local\n`
//   `DNS response OK id=<hex4> ans=10.0.0.42 bytes=<N>\n`
//
// A morph that perturbs name encoding, header byte order, or the
// answer-section assembly panics here and the trailing banners are
// suppressed.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_dns() {
    use proteus_contracts::{dns_class, dns_flags, Dns, DnsRecordType};
    use target_enterprise::dns::DnsImpl;

    let qid: u16 = 0xC0DE;

    // --- query build ---
    let mut qbuf = [0u8; 64];
    let qn = match DnsImpl::build_a_query(qid, b"proteus.local", &mut qbuf) {
        Ok(n) => n,
        Err(_) => panic!("DNS build_a_query returned Err"),
    };
    // Byte-exact assertion: known canonical encoding of "proteus.local"
    // as an A query with RD set.
    let qexpected: &[u8] = &[
        0xC0, 0xDE, // id
        0x01, 0x00, // flags (RD)
        0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // qd=1, an/ns/ar=0
        7, b'p', b'r', b'o', b't', b'e', b'u', b's',
        5, b'l', b'o', b'c', b'a', b'l', 0, // QNAME
        0x00, 0x01, 0x00, 0x01, // QTYPE=A, QCLASS=IN
    ];
    if qn != qexpected.len() {
        panic!("DNS query length drift");
    }
    assert_eq_bytes(&qbuf[..qn], qexpected, "DNS A query");

    // --- parse round-trip ---
    let qview = match DnsImpl::parse_message(&qbuf[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("DNS parse_message rejected own query"),
    };
    if qview.header.id != qid {
        panic!("DNS parse: id drift");
    }
    if qview.header.qdcount != 1 {
        panic!("DNS parse: qdcount drift");
    }
    if qview.first_question_type != DnsRecordType::A as u16 {
        panic!("DNS parse: qtype drift");
    }
    if qview.first_question_class != dns_class::IN {
        panic!("DNS parse: qclass drift");
    }
    let qname_wire = match qview.first_question_name {
        Some(n) => n,
        None => panic!("DNS parse: missing first question name"),
    };

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"DNS query OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let id_be = qid.to_be_bytes();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" qname=proteus.local";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);

    // --- response build (echo of the parsed qname + 10.0.0.42 / TTL 60) ---
    let mut rbuf = [0u8; 96];
    let rn = match DnsImpl::build_a_response(qid, qname_wire, [10, 0, 0, 42], 60, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("DNS build_a_response returned Err"),
    };
    // Parse the response and verify the recovered fields.
    let rview = match DnsImpl::parse_message(&rbuf[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("DNS parse_message rejected own response"),
    };
    if rview.header.id != qid {
        panic!("DNS response: id drift");
    }
    if rview.header.flags & dns_flags::QR_RESPONSE == 0 {
        panic!("DNS response: QR bit clear");
    }
    if rview.header.qdcount != 1 || rview.header.ancount != 1 {
        panic!("DNS response: section count drift");
    }
    // Confirm the rdata bytes 10.0.0.42 land at the locked offset.
    // header(12) + qname + 4 (qtype/qclass) + qname + 2 + 2 + 4 + 2
    let qn_len = qname_wire.len();
    let rdata_off = 12 + qn_len + 4 + qn_len + 2 + 2 + 4 + 2;
    if rbuf[rdata_off] != 10
        || rbuf[rdata_off + 1] != 0
        || rbuf[rdata_off + 2] != 0
        || rbuf[rdata_off + 3] != 42
    {
        panic!("DNS response: rdata drift");
    }

    let mut line = [0u8; 96];
    let mut pos = 0usize;
    let prefix = b"DNS response OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" ans=10.0.0.42 bytes=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(rn as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// ICMP/RFC 792: build an echo request (ping) with id=0x4242, seq=7,
// payload "proteus-ping", parse it (which verifies the RFC 1071
// checksum), then build the matching echo reply and confirm the
// reply parses with type=ECHO_REPLY and identical id/seq. Emits:
//   `ICMP echo_req OK id=4242 seq=7 cksum=<hex4>\n`
//   `ICMP echo_rep OK id=4242 seq=7\n`
//
// A morph that perturbs the checksum routine, the type-code byte, or
// the identifier/sequence byte order panics inside `banner_icmp` and
// these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_icmp() {
    use proteus_contracts::{icmp_type, Icmp};
    use target_enterprise::icmp::IcmpImpl;

    let id: u16 = 0x4242;
    let seq: u16 = 7;
    let payload: &[u8] = b"proteus-ping";

    // --- build + parse echo request ---
    let mut qbuf = [0u8; 32];
    let qn = match IcmpImpl::build_echo_request(id, seq, payload, &mut qbuf) {
        Ok(n) => n,
        Err(_) => panic!("ICMP build_echo_request returned Err"),
    };
    let qview = match IcmpImpl::parse_echo(&qbuf[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("ICMP parse_echo rejected own request (checksum?)"),
    };
    if qview.icmp_type != icmp_type::ECHO_REQUEST {
        panic!("ICMP echo request: type drift");
    }
    if qview.identifier != id || qview.sequence_number != seq {
        panic!("ICMP echo request: id/seq drift");
    }
    if qview.payload != payload {
        panic!("ICMP echo request: payload drift");
    }

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"ICMP echo_req OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let id_be = id.to_be_bytes();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" seq=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(seq as u64, &mut line[pos..]);
    let mid2 = b" cksum=";
    line[pos..pos + mid2.len()].copy_from_slice(mid2);
    pos += mid2.len();
    let cksum_be = qview.checksum.to_be_bytes();
    let mut cks_hex = [0u8; 4];
    hex_encode(&cksum_be, 2, &mut cks_hex);
    line[pos..pos + 4].copy_from_slice(&cks_hex);
    pos += 4;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);

    // --- build + parse echo reply ---
    let mut rbuf = [0u8; 32];
    let rn = match IcmpImpl::build_echo_reply(id, seq, payload, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("ICMP build_echo_reply returned Err"),
    };
    let rview = match IcmpImpl::parse_echo(&rbuf[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("ICMP parse_echo rejected own reply"),
    };
    if rview.icmp_type != icmp_type::ECHO_REPLY {
        panic!("ICMP echo reply: type drift");
    }
    if rview.identifier != id || rview.sequence_number != seq {
        panic!("ICMP echo reply: id/seq drift");
    }

    let mut line = [0u8; 64];
    let mut pos = 0usize;
    let prefix = b"ICMP echo_rep OK id=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 4];
    hex_encode(&id_be, 2, &mut hex);
    line[pos..pos + 4].copy_from_slice(&hex);
    pos += 4;
    let mid = b" seq=";
    line[pos..pos + mid.len()].copy_from_slice(mid);
    pos += mid.len();
    pos += dec_u64(seq as u64, &mut line[pos..]);
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

// ============================================================
// Ethernet/IEEE 802.3: wrap the locked NET fixture (the
// 38-byte UDP/IPv4 datagram from kernel_fixtures) inside an Ethernet
// II frame, byte-exact assert against the locked golden bytes
// (header + payload), parse it back through `EthImpl::parse_frame`,
// confirm dst/src/EtherType/payload are recovered. Then build a
// VLAN-tagged version with PCP=3/VID=100 and round-trip it. Emits:
//   `ETH build OK len=52 ethertype=0800`
//   `ETH parse OK src=00aabbccddee dst=1234567890bc`
//   `ETH vlan OK tci=6064 vid=100 pcp=3`
//
// A morph that perturbs MAC byte order, EtherType big-endian
// encoding, VLAN TCI field packing, or the header byte layout
// panics in `banner_eth` and the banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_eth() {
    use proteus_contracts::{ether_type, Eth};
    use target_enterprise::ethernet::{
        is_broadcast, pack_vlan_tci, vlan_pcp, vlan_vid, EthImpl, ETH_HEADER_LEN,
    };
    use target_enterprise::net::build_udp_datagram;

    let dst: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];
    let src: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];

    // Rebuild the canonical UDP/IPv4 datagram so we have a real wire
    // payload to wrap — not just synthetic bytes.
    let mut ipv4 = [0u8; kf::NET_EXPECTED_LEN];
    let ipv4_len = build_udp_datagram(
        kf::NET_SRC_IP,
        kf::NET_DST_IP,
        kf::NET_SRC_PORT,
        kf::NET_DST_PORT,
        kf::NET_PAYLOAD,
        kf::NET_TTL,
        kf::NET_IDENT,
        &mut ipv4,
    )
    .unwrap_or_else(|_| panic!("ETH banner: net build failed"));
    if ipv4_len != kf::NET_EXPECTED_LEN {
        panic!("ETH banner: net length drift");
    }

    // --- build untagged frame ---
    let mut frame = [0u8; 64];
    let n = match EthImpl::build_frame(dst, src, ether_type::IPV4, &ipv4[..ipv4_len], &mut frame)
    {
        Ok(n) => n,
        Err(_) => panic!("ETH build_frame returned Err"),
    };
    if n != ETH_HEADER_LEN + ipv4_len {
        panic!("ETH build_frame length drift");
    }
    // Header bytes byte-exact.
    let mut header_expected = [0u8; 14];
    header_expected[..6].copy_from_slice(&dst);
    header_expected[6..12].copy_from_slice(&src);
    header_expected[12] = 0x08;
    header_expected[13] = 0x00;
    assert_eq_bytes(&frame[..14], &header_expected, "ETH header");
    // Payload bytes byte-exact (against the locked NET fixture).
    assert_eq_bytes(&frame[14..n], &kf::NET_EXPECTED_DATAGRAM, "ETH payload");

    // Broadcast detection sanity — used by the eventual NIC driver to
    // short-circuit the unicast-filter path.
    let bcast = proteus_contracts::ETH_BROADCAST_MAC;
    if !is_broadcast(&bcast) {
        panic!("ETH is_broadcast(ETH_BROADCAST_MAC) returned false");
    }

    // Emit build banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"ETH build OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        let mid = b" ethertype=0800";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- parse + recover ---
    let view = match EthImpl::parse_frame(&frame[..n]) {
        Ok(v) => v,
        Err(_) => panic!("ETH parse_frame rejected own output"),
    };
    if view.dst != dst {
        panic!("ETH parse: dst MAC drift");
    }
    if view.src != src {
        panic!("ETH parse: src MAC drift");
    }
    if view.ether_type != ether_type::IPV4 {
        panic!("ETH parse: ethertype drift");
    }
    if view.vlan_tci.is_some() {
        panic!("ETH parse: untagged frame claimed VLAN");
    }
    if view.payload.len() != ipv4_len {
        panic!("ETH parse: payload length drift");
    }
    if &view.payload[..] != &kf::NET_EXPECTED_DATAGRAM[..] {
        panic!("ETH parse: payload byte drift");
    }

    // Emit parse banner with src/dst MACs as hex12.
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"ETH parse OK src=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&src, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        let mid = b" dst=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        hex_encode(&dst, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- 802.1Q VLAN tagged round-trip ---
    let tci = pack_vlan_tci(3, false, 100); // PCP=3, DEI=0, VID=100
    if tci != 0x6064 {
        panic!("ETH pack_vlan_tci drift");
    }
    let mut vbuf = [0u8; 64];
    let vn = match EthImpl::build_frame_vlan(dst, src, tci, ether_type::IPV4, &[], &mut vbuf) {
        Ok(n) => n,
        Err(_) => panic!("ETH build_frame_vlan returned Err"),
    };
    let vview = match EthImpl::parse_frame(&vbuf[..vn]) {
        Ok(v) => v,
        Err(_) => panic!("ETH parse rejected own VLAN frame"),
    };
    match vview.vlan_tci {
        Some(t) if t == tci => {}
        Some(_) => panic!("ETH VLAN tci drift"),
        None => panic!("ETH parse missed VLAN tag"),
    }
    if vlan_pcp(tci) != 3 || vlan_vid(tci) != 100 {
        panic!("ETH VLAN field decode drift");
    }

    // Emit VLAN banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"ETH vlan OK tci=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let tci_be = tci.to_be_bytes();
        let mut hex = [0u8; 4];
        hex_encode(&tci_be, 2, &mut hex);
        line[pos..pos + 4].copy_from_slice(&hex);
        pos += 4;
        let mid = b" vid=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(vlan_vid(tci) as u64, &mut line[pos..]);
        let mid2 = b" pcp=";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(vlan_pcp(tci) as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-046: ARP / RFC 826 over Ethernet. Build a REQUEST asking
// "who has 10.0.0.42? tell 10.0.0.1 / 00:AA:BB:CC:DD:EE", assert
// the wire bytes are byte-exact against the locked 28-byte
// expectation, parse them back through `ArpImpl::parse_packet`,
// confirm the round-trip recovers OPER/sender/target. Then build
// the matching REPLY (target_mac = 12:34:56:78:9A:BC) and add it
// to a 4-slot ArpCache; confirm lookup hits. Emits:
//   `ARP request OK target_ip=10.0.0.42 op=1`
//   `ARP cache OK entries=1`
//
// A morph that perturbs HTYPE/PTYPE big-endian encoding, the
// HLEN/PLEN constants, the 28-byte field layout, or the cache LRU /
// poison-defence routine panics inside `banner_arp` and the
// banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_arp() {
    use proteus_contracts::{arp_op, Arp};
    use target_enterprise::arp::{ArpCache, ArpImpl, PACKET_LEN};

    let sender_mac: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let sender_ip: [u8; 4] = [10, 0, 0, 1];
    let target_ip: [u8; 4] = [10, 0, 0, 42];
    let target_mac: [u8; 6] = [0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC];

    // --- build REQUEST ---
    let mut req = [0u8; 32];
    let qn = match ArpImpl::build_request(sender_mac, sender_ip, target_ip, &mut req) {
        Ok(n) => n,
        Err(_) => panic!("ARP build_request returned Err"),
    };
    if qn != PACKET_LEN {
        panic!("ARP build_request length drift");
    }
    let expected_req: [u8; 28] = [
        0x00, 0x01, // HTYPE = 1
        0x08, 0x00, // PTYPE = 0x0800
        0x06, 0x04, // HLEN=6, PLEN=4
        0x00, 0x01, // OPER = REQUEST
        0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, // sender MAC
        10, 0, 0, 1, // sender IP
        0, 0, 0, 0, 0, 0, // target MAC zeros
        10, 0, 0, 42, // target IP
    ];
    assert_eq_bytes(&req[..qn], &expected_req, "ARP REQUEST bytes");

    // Parse + recover.
    let qview = match ArpImpl::parse_packet(&req[..qn]) {
        Ok(v) => v,
        Err(_) => panic!("ARP parse_packet rejected own REQUEST"),
    };
    if qview.oper != arp_op::REQUEST {
        panic!("ARP REQUEST: oper drift");
    }
    if qview.sender_mac != sender_mac {
        panic!("ARP REQUEST: sender_mac drift");
    }
    if qview.sender_ip != sender_ip {
        panic!("ARP REQUEST: sender_ip drift");
    }
    if qview.target_ip != target_ip {
        panic!("ARP REQUEST: target_ip drift");
    }
    if qview.target_mac != [0u8; 6] {
        panic!("ARP REQUEST: target_mac not all-zeros");
    }

    // Emit request banner.
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"ARP request OK target_ip=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Format the dotted-decimal IP in-line — keeps the banner
        // grep-friendly for the qemu_smoke required-banner check.
        let octets = [target_ip[0], target_ip[1], target_ip[2], target_ip[3]];
        for (i, oct) in octets.iter().enumerate() {
            pos += dec_u64(*oct as u64, &mut line[pos..]);
            if i < 3 {
                line[pos] = b'.';
                pos += 1;
            }
        }
        let mid = b" op=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(qview.oper as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- build matching REPLY + populate cache ---
    let mut rep = [0u8; 32];
    let rn = match ArpImpl::build_reply(target_mac, target_ip, sender_mac, sender_ip, &mut rep) {
        Ok(n) => n,
        Err(_) => panic!("ARP build_reply returned Err"),
    };
    let rview = match ArpImpl::parse_packet(&rep[..rn]) {
        Ok(v) => v,
        Err(_) => panic!("ARP parse_packet rejected own REPLY"),
    };
    if rview.oper != arp_op::REPLY {
        panic!("ARP REPLY: oper drift");
    }
    if rview.sender_mac != target_mac {
        panic!("ARP REPLY: sender_mac drift");
    }
    if rview.sender_ip != target_ip {
        panic!("ARP REPLY: sender_ip drift");
    }
    if rview.target_mac != sender_mac {
        panic!("ARP REPLY: target_mac drift");
    }

    let mut cache: ArpCache<4> = ArpCache::new();
    // Use the parsed REPLY's (sender_ip, sender_mac) — that's the
    // canonical "we now know IP X is at MAC Y" pattern.
    if cache
        .insert(rview.sender_ip, rview.sender_mac, 100)
        .is_err()
    {
        panic!("ARP cache insert failed");
    }
    if cache.len() != 1 {
        panic!("ARP cache: post-insert len drift");
    }
    match cache.lookup(&target_ip, 200) {
        Some(m) if m == target_mac => {}
        Some(_) => panic!("ARP cache: lookup returned wrong MAC"),
        None => panic!("ARP cache: lookup missed inserted entry"),
    }

    // Emit cache banner.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"ARP cache OK entries=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(cache.len() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-047: DHCPv4 client (RFC 2131/2132). Drive a synthetic
// INIT → DISCOVER → (parse OFFER fixture) → REQUEST → (parse ACK
// fixture) → BOUND sequence. Asserts:
//   - DISCOVER bytes round-trip through parse_message (xid +
//     msg_type recovered).
//   - OFFER fixture is accepted: state -> Requesting, yiaddr +
//     server_id captured.
//   - ACK fixture binds the lease with the expected yiaddr.
//
// Emits:
//   `DHCP discover OK xid=<hex8>\n`
//   `DHCP bound OK yiaddr=10.0.0.42 lease=86400\n`
//
// A kernel that perturbs the BOOTP byte order, mishandles the
// magic-cookie offset, or breaks the option TLV scan panics here
// and the trailing banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_dhcp() {
    use proteus_contracts::{dhcp_msg_type, Dhcp, DhcpClientState, DHCP_FIXED_HEADER_LEN};
    use target_enterprise::dhcp::{DhcpClient, DhcpImpl, DHCP_MAX_MESSAGE_LEN};

    let mac: [u8; 6] = [0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE];
    let xid: u32 = 0xDEAD_BEEF;
    let offered_ip: [u8; 4] = [10, 0, 0, 42];
    let server_id: [u8; 4] = [10, 0, 0, 1];
    let subnet: [u8; 4] = [255, 255, 255, 0];
    let router: [u8; 4] = [10, 0, 0, 1];
    let dns: [u8; 4] = [10, 0, 0, 53];
    let lease_secs: u32 = 86_400;

    // --- Step 1: build a DISCOVER, parse it back, assert msg_type. ---
    let mut cli = DhcpClient::new(mac);
    let mut disc = [0u8; DHCP_MAX_MESSAGE_LEN];
    let n_disc = match cli.start_discover(xid, &mut disc) {
        Ok(n) => n,
        Err(_) => panic!("DHCP start_discover returned Err"),
    };
    if n_disc < DHCP_FIXED_HEADER_LEN {
        panic!("DHCP DISCOVER undersized");
    }
    let dview = match DhcpImpl::parse_message(&disc[..n_disc]) {
        Ok(v) => v,
        Err(_) => panic!("DHCP parse_message rejected own DISCOVER"),
    };
    if dview.msg_type != dhcp_msg_type::DISCOVER {
        panic!("DHCP DISCOVER msg_type drift");
    }
    if dview.xid != xid {
        panic!("DHCP DISCOVER xid drift");
    }
    if dview.chaddr != mac {
        panic!("DHCP DISCOVER chaddr drift");
    }
    if cli.state() != DhcpClientState::Selecting {
        panic!("DHCP client state != Selecting after DISCOVER");
    }

    // Emit discover banner with the xid in hex.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"DHCP discover OK xid=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 8];
        hex_u32(xid, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- Step 2: build an OFFER fixture by hand, feed it into the client. ---
    let mut offer = [0u8; DHCP_MAX_MESSAGE_LEN];
    let offer_len = build_dhcp_reply_fixture(
        &mut offer,
        dhcp_msg_type::OFFER,
        xid,
        mac,
        offered_ip,
        Some(server_id),
        Some(subnet),
        Some(router),
        Some(dns),
        Some(lease_secs),
    );
    let mut req = [0u8; DHCP_MAX_MESSAGE_LEN];
    let _n_req = match cli.on_offer(&offer[..offer_len], &mut req) {
        Ok(n) => n,
        Err(_) => panic!("DHCP on_offer rejected fixture"),
    };
    if cli.state() != DhcpClientState::Requesting {
        panic!("DHCP client state != Requesting after OFFER");
    }
    if cli.offered_ip() != offered_ip {
        panic!("DHCP captured offered_ip drift");
    }
    if cli.server_id() != server_id {
        panic!("DHCP captured server_id drift");
    }

    // --- Step 3: build an ACK fixture, bind. ---
    let mut ack = [0u8; DHCP_MAX_MESSAGE_LEN];
    let ack_len = build_dhcp_reply_fixture(
        &mut ack,
        dhcp_msg_type::ACK,
        xid,
        mac,
        offered_ip,
        Some(server_id),
        Some(subnet),
        Some(router),
        Some(dns),
        Some(lease_secs),
    );
    let lease = match cli.on_ack(&ack[..ack_len], 1_700_000_000) {
        Ok(l) => l,
        Err(_) => panic!("DHCP on_ack rejected fixture"),
    };
    if cli.state() != DhcpClientState::Bound {
        panic!("DHCP client state != Bound after ACK");
    }
    if lease.assigned_ip != offered_ip {
        panic!("DHCP lease.assigned_ip drift");
    }
    if lease.lease_secs != lease_secs {
        panic!("DHCP lease.lease_secs drift");
    }
    if lease.server_id != server_id {
        panic!("DHCP lease.server_id drift");
    }
    if lease.gateway != router {
        panic!("DHCP lease.gateway drift");
    }
    if lease.dns != dns {
        panic!("DHCP lease.dns drift");
    }

    // Emit bound banner: `DHCP bound OK yiaddr=10.0.0.42 lease=86400`
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"DHCP bound OK yiaddr=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let octs = [
            lease.assigned_ip[0],
            lease.assigned_ip[1],
            lease.assigned_ip[2],
            lease.assigned_ip[3],
        ];
        for (i, o) in octs.iter().enumerate() {
            pos += dec_u64(*o as u64, &mut line[pos..]);
            if i < 3 {
                line[pos] = b'.';
                pos += 1;
            }
        }
        let mid = b" lease=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(lease.lease_secs as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Build a DHCP reply fixture in `buf`. Returns the byte length
/// written. Helper exists only for `banner_dhcp` — the per-option
/// matrix is hand-built so the banner doesn't depend on the impl's
/// reply-builder (the impl only emits client→server messages).
#[allow(clippy::too_many_arguments)]
fn build_dhcp_reply_fixture(
    buf: &mut [u8],
    msg_type: u8,
    xid: u32,
    mac: [u8; 6],
    yiaddr: [u8; 4],
    server_id: Option<[u8; 4]>,
    subnet_mask: Option<[u8; 4]>,
    router: Option<[u8; 4]>,
    dns: Option<[u8; 4]>,
    lease_secs: Option<u32>,
) -> usize {
    use proteus_contracts::{
        dhcp_option, DHCP_FIXED_HEADER_LEN, DHCP_HLEN_ETHERNET, DHCP_HTYPE_ETHERNET,
        DHCP_MAGIC_COOKIE, DHCP_OP_BOOTREPLY,
    };
    // Zero the fixed header span.
    for b in &mut buf[..DHCP_FIXED_HEADER_LEN] {
        *b = 0;
    }
    buf[0] = DHCP_OP_BOOTREPLY;
    buf[1] = DHCP_HTYPE_ETHERNET;
    buf[2] = DHCP_HLEN_ETHERNET;
    buf[4..8].copy_from_slice(&xid.to_be_bytes());
    buf[16..20].copy_from_slice(&yiaddr);
    buf[28..34].copy_from_slice(&mac);
    buf[236..240].copy_from_slice(&DHCP_MAGIC_COOKIE);
    let mut pos = DHCP_FIXED_HEADER_LEN;
    // opt53 msg_type
    buf[pos] = dhcp_option::MSG_TYPE;
    buf[pos + 1] = 1;
    buf[pos + 2] = msg_type;
    pos += 3;
    if let Some(sm) = subnet_mask {
        buf[pos] = dhcp_option::SUBNET_MASK;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&sm);
        pos += 6;
    }
    if let Some(rt) = router {
        buf[pos] = dhcp_option::ROUTER;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&rt);
        pos += 6;
    }
    if let Some(d) = dns {
        buf[pos] = dhcp_option::DNS;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&d);
        pos += 6;
    }
    if let Some(lt) = lease_secs {
        buf[pos] = dhcp_option::LEASE_TIME;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&lt.to_be_bytes());
        pos += 6;
    }
    if let Some(sid) = server_id {
        buf[pos] = dhcp_option::SERVER_ID;
        buf[pos + 1] = 4;
        buf[pos + 2..pos + 6].copy_from_slice(&sid);
        pos += 6;
    }
    buf[pos] = dhcp_option::END;
    pos + 1
}

// ============================================================
// TASK-019: Panic-dump capture + symbol resolution. Build a
// deterministic CrashContext from the locked fixtures, package it
// via `PanicDumpImpl::dump_to_sink` into an in-kernel
// `MemorySectorSink`, verify the body CRC32-C matches
// `kf::CRASH_EXPECTED_CRC32C`, parse the header back, then resolve
// the first backtrace frame through a `StaticSymbolResolver` over a
// hand-built kernel-symbol fixture and assert (name, offset) match
// the locked expectations.
//
// Emits:
//   `CRASH_DUMP wrote 16384 bytes to lba=1024 crc=<hex8>\n`
//   `SYMBOL resolve OK kernel_main+0x42 (5 frames)\n`
//
// A kernel that perturbs the dump layout (sector offsets, CRC poly,
// header byte order) or the symbol-resolver binary search panics in
// this banner and the trailing `PROTEUS-TE HALT` is suppressed.
// ============================================================
// ============================================================
// TASK-048: VirtIO-net driver (VirtIO 1.0 §5.1). Drive a complete
// bring-up + roundtrip exercise against the in-process MemVirtioBus
// emulator:
//   - construct bus + driver, run init: asserts status sequence,
//     feature negotiation, MAC read, queue setup, RX pre-post.
//   - transmit a locked 60-byte fixture frame: asserts the captured
//     TX observation is byte-identical to the input.
//   - inject a synthetic incoming frame, deliver into the RX ring,
//     receive: asserts the returned bytes equal the injected frame
//     byte-for-byte and that the virtio_net header was stripped.
//
// Emits:
//   `VIRTIO_NET init OK mac=525400123456\n`
//   `VIRTIO_NET roundtrip OK tx=1 rx=1\n`
//
// A kernel that perturbs the descriptor wire layout, the bring-up
// status sequence, the feature-bit constants, or the TX/RX ring
// arithmetic panics here and these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_virtio_net() {
    use proteus_contracts::NetDevice;
    use target_enterprise::virtio_net::{MemVirtioBus, VirtioNet, MAX_FRAME_LEN};

    // The MemVirtioBus carries a 64 KiB shadow + observation/pending
    // FIFOs (~85 KiB total). That's too large for the kernel-main
    // stack (the bootloader allocates a modest stack and we're
    // already deep into the banner sequence). Park it in static
    // storage instead; the banner is single-threaded so the unsafe
    // &mut access is sound — banner_virtio_net is the sole writer.
    static mut BUS_STORAGE: MemVirtioBus = MemVirtioBus::new();
    // SAFETY: kernel_main is single-threaded; this banner is called
    // exactly once before halt. No other code path observes the
    // static. The reference does not escape the function.
    let bus: &mut MemVirtioBus = unsafe {
        let ptr = core::ptr::addr_of_mut!(BUS_STORAGE);
        &mut *ptr
    };
    let mut drv = VirtioNet::new();

    if drv.init(bus).is_err() {
        panic!("virtio-net init failed");
    }
    let mac = drv.mac_address();
    if mac != [0x52, 0x54, 0x00, 0x12, 0x34, 0x56] {
        panic!("virtio-net MAC drift");
    }
    if !drv.link_up() {
        panic!("virtio-net link_up drift (expected true after init on default bus)");
    }

    // Emit init banner: `VIRTIO_NET init OK mac=525400123456`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET init OK mac=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Build a locked 60-byte TX fixture: dst=broadcast, src=our MAC,
    // EtherType=0x0800, then a recognisable payload.
    let mut tx_frame = [0u8; 60];
    tx_frame[0] = 0xFF;
    tx_frame[1] = 0xFF;
    tx_frame[2] = 0xFF;
    tx_frame[3] = 0xFF;
    tx_frame[4] = 0xFF;
    tx_frame[5] = 0xFF;
    tx_frame[6] = mac[0];
    tx_frame[7] = mac[1];
    tx_frame[8] = mac[2];
    tx_frame[9] = mac[3];
    tx_frame[10] = mac[4];
    tx_frame[11] = mac[5];
    tx_frame[12] = 0x08; // EtherType high
    tx_frame[13] = 0x00; // EtherType low
    let mut i = 14;
    while i < 60 {
        tx_frame[i] = (i as u8).wrapping_mul(7).wrapping_add(11);
        i += 1;
    }

    if drv.transmit(bus, &tx_frame).is_err() {
        panic!("virtio-net transmit failed");
    }

    // Confirm the bus captured the TX frame byte-for-byte.
    let obs = bus.tx_observations();
    if obs.len() != 1 {
        panic!("virtio-net TX observation count drift");
    }
    if obs[0].len != 60 {
        panic!("virtio-net TX observation len drift");
    }
    let mut j = 0usize;
    while j < 60 {
        if obs[0].bytes[j] != tx_frame[j] {
            panic!("virtio-net TX byte drift");
        }
        j += 1;
    }

    // Inject an incoming frame. Use a different recognisable
    // payload so it cannot be confused with the TX bytes.
    let mut rx_inject = [0u8; 80];
    rx_inject[0] = mac[0];
    rx_inject[1] = mac[1];
    rx_inject[2] = mac[2];
    rx_inject[3] = mac[3];
    rx_inject[4] = mac[4];
    rx_inject[5] = mac[5];
    rx_inject[6] = 0xDE;
    rx_inject[7] = 0xAD;
    rx_inject[8] = 0xBE;
    rx_inject[9] = 0xEF;
    rx_inject[10] = 0xCA;
    rx_inject[11] = 0xFE;
    rx_inject[12] = 0x08;
    rx_inject[13] = 0x06; // EtherType = ARP — irrelevant to RX path.
    let mut k = 14usize;
    while k < 80 {
        rx_inject[k] = (k as u8) ^ 0x5A;
        k += 1;
    }

    if !bus.enqueue_rx(&rx_inject) {
        panic!("virtio-net RX enqueue refused");
    }
    if !bus.deliver_pending_rx() {
        panic!("virtio-net RX delivery refused");
    }

    let mut rx_out = [0u8; MAX_FRAME_LEN];
    let n = match drv.receive(bus, &mut rx_out) {
        Ok(n) => n,
        Err(_) => panic!("virtio-net receive failed"),
    };
    if n != 80 {
        panic!("virtio-net RX length drift");
    }
    let mut m = 0usize;
    while m < 80 {
        if rx_out[m] != rx_inject[m] {
            panic!("virtio-net RX byte drift");
        }
        m += 1;
    }

    // Emit roundtrip banner: `VIRTIO_NET roundtrip OK tx=1 rx=1`.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET roundtrip OK tx=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.tx_count() as u64, &mut line[pos..]);
        let mid = b" rx=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(drv.rx_count() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TASK-061: VirtIO-blk driver bring-up + sector round-trip.
//
// Constructs a MemVirtioBlkBus + VirtioBlk in static storage,
// drives the VirtIO 1.0 RESET → ACK → DRIVER → FEATURES_OK →
// DRIVER_OK handshake against a virtio-blk device, reads the
// disk capacity from device-cfg (32 sectors — the bus default),
// writes a locked 512-byte pattern to sector 3, then reads it
// back and asserts byte-equality.
//
// Emits (in order):
//   `VIRTIO_BLK init OK capacity=32 blk_size=512\n`
//   `VIRTIO_BLK roundtrip OK reqs=2 sector=3 first_byte=a5\n`
//
// A kernel that perturbs the descriptor wire layout, the bring-up
// status sequence, the feature-bit constants, the request-header
// byte order, or the 3-descriptor chain shape panics here and
// these banners never appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_virtio_blk() {
    use proteus_contracts::{BlockDeviceVirtio, VIRTIO_BLK_SECTOR_SIZE};
    use target_enterprise::virtio_blk::{MemVirtioBlkBus, VirtioBlk};

    // Same static-storage pattern as banner_virtio_net — the bus
    // carries a 64 KiB shadow + a 16 KiB backing disk + a handful
    // of observation buffers. Too large for the kernel-main stack
    // (the bootloader allocates a modest stack and the banner
    // sequence is already deep into it).
    static mut BUS_STORAGE: MemVirtioBlkBus = MemVirtioBlkBus::new();
    // SAFETY: kernel_main is single-threaded; this banner is called
    // exactly once before halt. No other code path observes the
    // static. The reference does not escape the function.
    let bus: &mut MemVirtioBlkBus = unsafe {
        let ptr = core::ptr::addr_of_mut!(BUS_STORAGE);
        &mut *ptr
    };
    let mut drv = VirtioBlk::new();

    if drv.init(bus).is_err() {
        panic!("virtio-blk init failed");
    }
    if drv.capacity_sectors() != MemVirtioBlkBus::DISK_SECTORS {
        panic!("virtio-blk capacity drift");
    }
    if drv.preferred_block_size() != VIRTIO_BLK_SECTOR_SIZE as u32 {
        panic!("virtio-blk preferred_block_size drift");
    }
    if drv.read_only() {
        panic!("virtio-blk unexpected read-only flag");
    }

    // Emit init banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_BLK init OK capacity=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.capacity_sectors(), &mut line[pos..]);
        let mid = b" blk_size=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(drv.preferred_block_size() as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Build a locked 512-byte pattern. byte[i] = 0xA5 XOR i. The
    // first byte is therefore 0xA5 — the banner asserts that
    // specific value to make any byte-order drift obvious.
    let mut pattern = [0u8; VIRTIO_BLK_SECTOR_SIZE];
    let mut i = 0usize;
    while i < VIRTIO_BLK_SECTOR_SIZE {
        pattern[i] = 0xA5 ^ (i as u8);
        i += 1;
    }

    if drv.write_block(bus, 3, &pattern).is_err() {
        panic!("virtio-blk write_block failed");
    }

    let mut readback = [0u8; VIRTIO_BLK_SECTOR_SIZE];
    if drv.read_block(bus, 3, &mut readback).is_err() {
        panic!("virtio-blk read_block failed");
    }

    // Byte-equality check.
    let mut j = 0usize;
    while j < VIRTIO_BLK_SECTOR_SIZE {
        if readback[j] != pattern[j] {
            panic!("virtio-blk readback byte drift");
        }
        j += 1;
    }

    if drv.request_count() != 2 {
        panic!("virtio-blk request_count drift");
    }
    if drv.completion_count() != 2 {
        panic!("virtio-blk completion_count drift");
    }

    // Emit roundtrip banner with the first byte in hex so the log
    // line carries a non-trivial value derived from the actual
    // disk read (not just a counter).
    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_BLK roundtrip OK reqs=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(drv.request_count() as u64, &mut line[pos..]);
        let mid = b" sector=3 first_byte=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 2];
        hex_encode(&[readback[0]], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Stateless IPv4 packet-filter exercise.
///
/// Builds a four-entry [`FirewallTable`] mirroring the TASK-050 spec:
///
/// 1. Accept TCP/22 from `10/8`
/// 2. Accept UDP/53 from anywhere
/// 3. Reject ICMP from `192.168/16`
/// 4. (table empty otherwise → default Drop)
///
/// Evaluates three synthetic IPv4 packets through
/// [`FirewallImpl::evaluate`] AND through [`FirewallTable::evaluate`]
/// (which folds in the default-action), asserting both paths return
/// the locked verdict — Accept, Accept, Drop (the ICMP rule is
/// `Reject`, which the operator-facing banner reports as `drop` per
/// the task spec's verdict label, but the underlying `Verdict` is
/// `Reject`; we assert the underlying byte too).
///
/// After the per-packet checks, the function feeds a packet that no
/// rule matches (TCP/443 from a public IP) and asserts the default
/// fall-through is `Drop`.
///
/// A morph that perturbs the CIDR-mask arithmetic, the descending-
/// mask-score ordering invariant, the first-match-wins semantics, or
/// the proto-byte equality check panics inside `banner_firewall` and
/// the two banners never appear.
#[cfg(not(proteus_prod))]
fn banner_firewall() {
    // ------------------------------------------------------------------
    // 1. Build the canonical 4-rule table (3 rules + default fallthrough).
    // ------------------------------------------------------------------
    let mut table: FirewallTable<8> = FirewallTable::new();

    // Rule 1: Accept TCP/22 from 10/8 (any source port, dst port 22).
    let r1 = FilterRule {
        src_ip: [10, 0, 0, 0],
        src_mask: 8,
        dst_ip: [0, 0, 0, 0],
        dst_mask: 0,
        proto: IP_PROTO_TCP,
        src_port_start: FW_PORT_ANY,
        src_port_end: FW_PORT_ANY,
        dst_port_start: 22,
        dst_port_end: 22,
        action: FilterAction::Accept,
    };
    // Rule 2: Accept UDP/53 from 0/0 (everywhere, any source port, dst 53).
    let r2 = FilterRule {
        src_ip: [0, 0, 0, 0],
        src_mask: 0,
        dst_ip: [0, 0, 0, 0],
        dst_mask: 0,
        proto: IP_PROTO_UDP,
        src_port_start: FW_PORT_ANY,
        src_port_end: FW_PORT_ANY,
        dst_port_start: 53,
        dst_port_end: 53,
        action: FilterAction::Accept,
    };
    // Rule 3: Reject ICMP from 192.168/16.
    let r3 = FilterRule {
        src_ip: [192, 168, 0, 0],
        src_mask: 16,
        dst_ip: [0, 0, 0, 0],
        dst_mask: 0,
        proto: IP_PROTO_ICMP,
        src_port_start: FW_PORT_ANY,
        src_port_end: FW_PORT_ANY,
        dst_port_start: FW_PORT_ANY,
        dst_port_end: FW_PORT_ANY,
        action: FilterAction::Reject,
    };

    if r1.validate().is_err() {
        panic!("firewall: r1 failed validate");
    }
    if r2.validate().is_err() {
        panic!("firewall: r2 failed validate");
    }
    if r3.validate().is_err() {
        panic!("firewall: r3 failed validate");
    }

    // Insert in operator-natural order; the table re-orders by
    // descending mask score so r3 (/16) winds up at slot 0, r1 (/8)
    // at slot 1, r2 (/0) at slot 2.
    if table.insert(r1).is_err() {
        panic!("firewall: insert r1 failed");
    }
    if table.insert(r2).is_err() {
        panic!("firewall: insert r2 failed");
    }
    if table.insert(r3).is_err() {
        panic!("firewall: insert r3 failed");
    }
    if table.len() != 3 {
        panic!("firewall: table len drift");
    }

    // Locked ordering: r3 (/16) > r1 (/8) > r2 (/0).
    let s = table.as_slice();
    if s[0].proto != IP_PROTO_ICMP {
        panic!("firewall: slot 0 not r3");
    }
    if s[1].proto != IP_PROTO_TCP {
        panic!("firewall: slot 1 not r1");
    }
    if s[2].proto != IP_PROTO_UDP {
        panic!("firewall: slot 2 not r2");
    }

    // ------------------------------------------------------------------
    // 2. Evaluate the three synthetic packets.
    // ------------------------------------------------------------------
    // Packet A: 10.0.0.5:40000 → 192.168.1.10:22 TCP → Accept.
    let pa = Ipv4PacketView {
        src_ip: [10, 0, 0, 5],
        dst_ip: [192, 168, 1, 10],
        protocol: IP_PROTO_TCP,
        src_port: 40000,
        dst_port: 22,
    };
    // Packet B: 8.8.8.8:12345 → 10.0.0.5:53 UDP → Accept.
    let pb = Ipv4PacketView {
        src_ip: [8, 8, 8, 8],
        dst_ip: [10, 0, 0, 5],
        protocol: IP_PROTO_UDP,
        src_port: 12345,
        dst_port: 53,
    };
    // Packet C: 192.168.1.42 → 10.0.0.5 ICMP → Reject (banner labels "drop").
    let pc = Ipv4PacketView {
        src_ip: [192, 168, 1, 42],
        dst_ip: [10, 0, 0, 5],
        protocol: IP_PROTO_ICMP,
        src_port: 0,
        dst_port: 0,
    };

    let va = FirewallImpl::evaluate(s, &pa);
    let vb = FirewallImpl::evaluate(s, &pb);
    let vc = FirewallImpl::evaluate(s, &pc);
    if va != Verdict::Accept {
        panic!("firewall: packet A verdict drift");
    }
    if vb != Verdict::Accept {
        panic!("firewall: packet B verdict drift");
    }
    if vc != Verdict::Reject {
        panic!("firewall: packet C verdict drift");
    }

    // Same packets through the table-with-default path: should match
    // the trait-level verdict because every packet has a matching
    // rule.
    if table.evaluate(&pa, FilterAction::Drop) != Verdict::Accept {
        panic!("firewall: pa via table drift");
    }
    if table.evaluate(&pb, FilterAction::Drop) != Verdict::Accept {
        panic!("firewall: pb via table drift");
    }
    if table.evaluate(&pc, FilterAction::Drop) != Verdict::Reject {
        panic!("firewall: pc via table drift");
    }

    // Emit the first banner.
    serial_write_str("FW eval OK rules=3 verdicts=accept,accept,drop\n");

    // ------------------------------------------------------------------
    // 3. Default-deny fall-through. A packet that matches no rule
    //    should surface as the supplied default action (Drop).
    // ------------------------------------------------------------------
    // Packet D: 1.1.1.1:50000 → 9.9.9.9:443 TCP. No rule matches
    // (10/8 source missing, dst port != 22, dst port != 53,
    // 192.168/16 source missing, ICMP missing).
    let pd = Ipv4PacketView {
        src_ip: [1, 1, 1, 1],
        dst_ip: [9, 9, 9, 9],
        protocol: IP_PROTO_TCP,
        src_port: 50000,
        dst_port: 443,
    };
    let raw = FirewallImpl::evaluate(s, &pd);
    if raw != Verdict::NoMatch {
        panic!("firewall: default-deny: raw verdict not NoMatch");
    }
    let folded = table.evaluate(&pd, FilterAction::Drop);
    if folded != Verdict::Drop {
        panic!("firewall: default-deny: folded verdict not Drop");
    }

    // Also assert that flipping the default to Accept changes the
    // folded verdict — proves the table doesn't ignore the default
    // policy parameter under a NoMatch.
    if table.evaluate(&pd, FilterAction::Accept) != Verdict::Accept {
        panic!("firewall: default policy parameter not honoured");
    }

    // Emit the second banner.
    serial_write_str("FW default OK action=Drop\n");
}

/// TPM 2.0 client-side wire codec banner (TASK-051).
///
/// Exercises every command builder in [`TpmImpl`] plus the response
/// parser against locked TCG-spec wire fixtures. The kernel asserts
/// byte-equality on:
///
/// * `TPM2_Startup(SU_CLEAR)` — 12-byte request golden,
/// * `TPM2_GetRandom(16)` — 12-byte request golden,
/// * `TPM2_PCR_Read(pcr=10)` — 20-byte request golden, bitmap byte 1
///    bit 2 set (PCR 10 = 8 + 2),
/// * `TPM2_PCR_Extend(pcr=8, SHA-256, [0x42; 32])` — 65-byte request
///   golden, sessions tag, PWAP session block.
///
/// It then hand-builds the canonical 28-byte `TPM2_GetRandom(16)`
/// success response and walks the parsed view: tag = 0x8001, size =
/// 28, response_code = TPM_RC_SUCCESS, body length = 18 (TPM2B_DIGEST
/// = 2 + 16), the inline 16 random bytes recover byte-for-byte. A
/// morph that perturbs any byte of the locked wire layout or any
/// constant (header endianness, command codes, the auth-session
/// constants, the PCR bitmap arithmetic, the response size-field
/// check) panics here and the two banners never appear.
#[cfg(not(proteus_prod))]
fn banner_tpm() {
    // ------------------------------------------------------------------
    // 1. TPM2_Startup(SU_CLEAR) request — locked 12-byte frame.
    // ------------------------------------------------------------------
    let expected_startup: [u8; TPM_STARTUP_CMD_LEN] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x00,
    ];
    let mut startup_buf = [0u8; TPM_STARTUP_CMD_LEN];
    let startup_len = match TpmImpl::build_startup(&mut startup_buf, TPM_SU_CLEAR) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_startup failed"),
    };
    if startup_len != TPM_STARTUP_CMD_LEN {
        panic!("tpm: startup length drift");
    }
    assert_eq_bytes(&startup_buf, &expected_startup, "TPM startup wire");

    // ------------------------------------------------------------------
    // 2. TPM2_GetRandom(16) request — locked 12-byte frame.
    // ------------------------------------------------------------------
    let expected_get_random: [u8; TPM_GET_RANDOM_CMD_LEN] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x7B, 0x00, 0x10,
    ];
    let mut get_random_buf = [0u8; TPM_GET_RANDOM_CMD_LEN];
    let get_random_len = match TpmImpl::build_get_random(&mut get_random_buf, 16) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_get_random failed"),
    };
    if get_random_len != TPM_GET_RANDOM_CMD_LEN {
        panic!("tpm: get_random length drift");
    }
    assert_eq_bytes(&get_random_buf, &expected_get_random, "TPM getrandom wire");

    // ------------------------------------------------------------------
    // 3. TPM2_PCR_Read(pcr=10) request — locked 20-byte frame.
    // ------------------------------------------------------------------
    let expected_pcr_read: [u8; TPM_PCR_READ_CMD_LEN] = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x14, // commandSize = 20
        0x00, 0x00, 0x01, 0x7E, // commandCode = PCR_Read
        0x00, 0x00, 0x00, 0x01, // count = 1
        0x00, 0x0B, // SHA-256
        0x03, // sizeOfSelect
        0x00, 0x04, 0x00, // bitmap: bit 2 of byte 1 = PCR 10
    ];
    let mut pcr_read_buf = [0u8; TPM_PCR_READ_CMD_LEN];
    let pcr_read_len = match TpmImpl::build_pcr_read(&mut pcr_read_buf, 10) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_pcr_read failed"),
    };
    if pcr_read_len != TPM_PCR_READ_CMD_LEN {
        panic!("tpm: pcr_read length drift");
    }
    assert_eq_bytes(&pcr_read_buf, &expected_pcr_read, "TPM pcr_read wire");

    // ------------------------------------------------------------------
    // 4. TPM2_PCR_Extend(pcr=8, SHA-256, [0x42; 32]) — locked 65-byte
    //    frame. Use the MaxTpmCommandBuf scratch wrapper so we exercise
    //    that surface too.
    // ------------------------------------------------------------------
    let extend_digest = [0x42u8; TPM_SHA256_DIGEST_LEN];
    let expected_pcr_extend: [u8; TPM_PCR_EXTEND_SHA256_CMD_LEN] = [
        0x80, 0x02, // sessions tag
        0x00, 0x00, 0x00, 0x41, // commandSize = 65
        0x00, 0x00, 0x01, 0x82, // commandCode = PCR_Extend
        0x00, 0x00, 0x00, 0x08, // pcrHandle = 8
        0x00, 0x00, 0x00, 0x09, // authorizationSize = 9
        0x40, 0x00, 0x00, 0x09, // session: handle = TPM_RS_PW
        0x00, 0x00, // nonceSize = 0
        0x00, // sessionAttributes = 0
        0x00, 0x00, // hmacSize = 0
        0x00, 0x00, 0x00, 0x01, // digests.count = 1
        0x00, 0x0B, // hashAlg = SHA-256
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];
    let mut scratch = MaxTpmCommandBuf::new();
    let pcr_extend_len = match TpmImpl::build_pcr_extend(
        scratch.as_mut(),
        8,
        TPM_ALG_SHA256,
        &extend_digest,
    ) {
        Ok(n) => n,
        Err(_) => panic!("tpm: build_pcr_extend failed"),
    };
    if pcr_extend_len != TPM_PCR_EXTEND_SHA256_CMD_LEN {
        panic!("tpm: pcr_extend length drift");
    }
    assert_eq_bytes(
        scratch.prefix(pcr_extend_len),
        &expected_pcr_extend,
        "TPM pcr_extend wire",
    );

    // First banner: byte-exact request encoding for the two task-spec
    // fixtures (startup + getrandom). The format echoes the locked
    // header fields so a serial-log grep can confirm both at once.
    serial_write_str("TPM startup OK len=12 tag=8001\n");
    serial_write_str("TPM getrandom OK len=12 cc=0000017b\n");

    // ------------------------------------------------------------------
    // 5. Parse a hand-built TPM2_GetRandom(16) success response. Walk
    //    every field of the view and recover the random bytes.
    // ------------------------------------------------------------------
    // Wire layout: tag(2) + size(4) + rc(4) + TPM2B_DIGEST { size(2) + 16 bytes }.
    // Total: 10 + 2 + 16 = 28 bytes.
    let mut resp = [0u8; 28];
    resp[0] = 0x80;
    resp[1] = 0x01;
    resp[2] = 0x00;
    resp[3] = 0x00;
    resp[4] = 0x00;
    resp[5] = 28; // size
    resp[6] = 0x00;
    resp[7] = 0x00;
    resp[8] = 0x00;
    resp[9] = 0x00; // rc = success
    // body: TPM2B_DIGEST size = 16
    resp[10] = 0x00;
    resp[11] = 0x10;
    let mut i = 0usize;
    while i < 16 {
        resp[12 + i] = (0xC0 ^ i as u8).wrapping_add(1);
        i += 1;
    }

    let view: TpmResponseView<'_> = match TpmImpl::parse_response(&resp) {
        Ok(v) => v,
        Err(_) => panic!("tpm: parse_response failed"),
    };
    if view.tag != TPM_ST_NO_SESSIONS {
        panic!("tpm: response tag drift");
    }
    if view.size != 28 {
        panic!("tpm: response size drift");
    }
    if view.response_code != TPM_RC_SUCCESS {
        panic!("tpm: response rc not success");
    }
    if view.body.len() != 18 {
        panic!("tpm: response body length drift");
    }

    let random = match extract_get_random_bytes(view.body) {
        Ok(r) => r,
        Err(_) => panic!("tpm: extract_get_random_bytes failed"),
    };
    if random.len() != 16 {
        panic!("tpm: random buffer length drift");
    }
    // Verify a couple of recovered bytes byte-for-byte.
    if random[0] != ((0xC0u8) ^ 0).wrapping_add(1) {
        panic!("tpm: random[0] drift");
    }
    if random[15] != ((0xC0u8) ^ 15).wrapping_add(1) {
        panic!("tpm: random[15] drift");
    }

    // Negative path #1: malformed tag. Hand-build a 10-byte response
    // with tag = 0x8003 (unassigned) and verify parse rejects it.
    let mut bad_tag = [0u8; 10];
    bad_tag[0] = 0x80;
    bad_tag[1] = 0x03;
    bad_tag[5] = 10;
    if TpmImpl::parse_response(&bad_tag).is_ok() {
        panic!("tpm: parse_response accepted bad tag");
    }

    // Negative path #2: size-field mismatch. tag valid, size says 12
    // but buffer is 10. parse must reject.
    let mut bad_size = [0u8; 10];
    bad_size[0] = 0x80;
    bad_size[1] = 0x01;
    bad_size[5] = 12;
    if TpmImpl::parse_response(&bad_size).is_ok() {
        panic!("tpm: parse_response accepted size mismatch");
    }

    // Cover the sessions tag too — also build a PCR_Extend response.
    let mut extend_resp = [0u8; 19];
    extend_resp[0] = 0x80;
    extend_resp[1] = 0x02;
    extend_resp[5] = 19;
    let extend_view = match TpmImpl::parse_response(&extend_resp) {
        Ok(v) => v,
        Err(_) => panic!("tpm: parse_response rejected sessions tag"),
    };
    if extend_view.tag != TPM_ST_SESSIONS {
        panic!("tpm: sessions tag round-trip drift");
    }

    // Second banner: response parser proved healthy on both tags and
    // recovered the 16 random bytes. Includes the parsed RC for
    // operator visibility.
    serial_write_str("TPM parse OK rc=00000000 random_len=16\n");
    let _ = (TPM_CC_GET_RANDOM,); // suppress unused-import warning if any
}

/// Kernel audit-log subsystem banner (TASK-052).
///
/// Exercises the locked [`AuditLog`] surface: appends three events of
/// distinct verdicts (Allowed / Denied / Error), confirms the
/// monotonic-event-id contract, takes a `snapshot`, parses the header
/// + every record back via the offline-parser helpers, and asserts
/// byte-equality against the expected layout. A morph that perturbs
/// the ring head/len bookkeeping, the snapshot byte layout, the
/// verdict discriminants, or the high-watermark accounting panics
/// inside `banner_audit` and the two banners never appear.
///
/// Emits two banners:
/// - `AUDIT append OK events=3` — three appends, three monotonic ids
///   recovered from `iter()` byte-for-byte.
/// - `AUDIT snapshot OK bytes=<N>` — snapshot returns the locked
///   `AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN = 308`
///   bytes; offline-parser round-trips every record's verdict +
///   message; the recorded magic == 'AUDT' and high_watermark == 3.
#[cfg(not(proteus_prod))]
fn banner_audit() {
    // Three locked events — one per verdict variant. The kernel uses
    // the audit log to record cap-table denials and IOMMU faults, so
    // the fixture covers every verdict the future syscall/IOMMU
    // surfaces will emit.
    let mut log: AuditLogImpl<16> = AuditLogImpl::new();

    let e0 = AuditEvent::new(
        0,
        0x1111_2222_3333_4444,
        0x0000_0000_0000_0001, // task_id 1 (init)
        0x0000_0001,           // sys_exit
        AuditVerdict::Allowed,
        b"sys_exit OK",
    );
    let e1 = AuditEvent::new(
        0,
        0x1111_2222_3333_4445,
        0x0000_0000_0000_0002, // task_id 2 (worker)
        0x0000_000A,           // sys_open
        AuditVerdict::Denied,
        b"cap_check EPERM",
    );
    let e2 = AuditEvent::new(
        0,
        0x1111_2222_3333_4446,
        0x0000_0000_0000_0003, // task_id 3 (driver)
        0x0000_0014,           // hypothetical IOMMU syscall
        AuditVerdict::Error,
        b"iommu_translate ENOENT",
    );

    let id0 = log.append(e0);
    let id1 = log.append(e1);
    let id2 = log.append(e2);
    if id0 != 0 || id1 != 1 || id2 != 2 {
        panic!("audit: append id drift");
    }
    if log.len() != 3 {
        panic!("audit: len drift after 3 appends");
    }
    if log.high_watermark() != 3 {
        panic!("audit: high_watermark drift");
    }
    if log.dropped() != 0 {
        panic!("audit: dropped drift");
    }

    // iter() must yield ids 0, 1, 2 in order, each preserving its
    // caller-supplied verdict + message + task_id.
    let expected_verdicts = [AuditVerdict::Allowed, AuditVerdict::Denied, AuditVerdict::Error];
    let expected_tasks = [1u64, 2, 3];
    let expected_msgs: [&[u8]; 3] = [b"sys_exit OK", b"cap_check EPERM", b"iommu_translate ENOENT"];
    let mut idx = 0usize;
    for ev in log.iter() {
        if ev.event_id != idx as u64 {
            panic!("audit: iter event_id drift");
        }
        if ev.verdict != expected_verdicts[idx] {
            panic!("audit: iter verdict drift");
        }
        if ev.task_id != expected_tasks[idx] {
            panic!("audit: iter task_id drift");
        }
        if ev.message_bytes() != expected_msgs[idx] {
            panic!("audit: iter message drift");
        }
        idx += 1;
    }
    if idx != 3 {
        panic!("audit: iter yielded wrong count");
    }

    // First banner — three appends survived the monotonic-id contract.
    serial_write_str("AUDIT append OK events=3\n");

    // ------------------------------------------------------------------
    // Snapshot: header + 3 records = 20 + 3*96 = 308 bytes locked.
    // ------------------------------------------------------------------
    const SNAP_LEN: usize = AUDIT_SNAPSHOT_HEADER_LEN + 3 * AUDIT_EVENT_WIRE_LEN;
    let mut snap_buf = [0u8; SNAP_LEN];
    let n = match log.snapshot(&mut snap_buf) {
        Ok(n) => n,
        Err(_) => panic!("audit: snapshot returned Err"),
    };
    if n != SNAP_LEN {
        panic!("audit: snapshot length drift");
    }

    // Header round-trip via offline parser.
    let header = match parse_audit_header(&snap_buf) {
        Some(h) => h,
        None => panic!("audit: parse_header returned None"),
    };
    if header.magic != AUDIT_SNAPSHOT_MAGIC {
        panic!("audit: snapshot magic drift");
    }
    if header.record_count != 3 {
        panic!("audit: snapshot record_count drift");
    }
    if header.record_size as usize != AUDIT_EVENT_WIRE_LEN {
        panic!("audit: snapshot record_size drift");
    }
    if header.high_watermark != 3 {
        panic!("audit: snapshot high_watermark drift");
    }

    // First three bytes of the magic must literally spell 'A', 'U',
    // 'D' so an operator browsing the snapshot file with a hex viewer
    // recognises it instantly.
    if snap_buf[0] != b'A' || snap_buf[1] != b'U' || snap_buf[2] != b'D' || snap_buf[3] != b'T' {
        panic!("audit: snapshot magic bytes drift");
    }

    // Each record round-trips byte-for-byte.
    let mut cursor = AUDIT_SNAPSHOT_HEADER_LEN;
    let mut rec_idx = 0usize;
    while rec_idx < 3 {
        let rec = match parse_audit_record(&snap_buf[cursor..cursor + AUDIT_EVENT_WIRE_LEN]) {
            Some(r) => r,
            None => panic!("audit: parse_record returned None"),
        };
        if rec.event_id != rec_idx as u64 {
            panic!("audit: record event_id drift");
        }
        if rec.verdict != expected_verdicts[rec_idx] {
            panic!("audit: record verdict drift");
        }
        if rec.task_id != expected_tasks[rec_idx] {
            panic!("audit: record task_id drift");
        }
        if rec.message_bytes() != expected_msgs[rec_idx] {
            panic!("audit: record message drift");
        }
        cursor += AUDIT_EVENT_WIRE_LEN;
        rec_idx += 1;
    }
    if cursor != n {
        panic!("audit: cursor did not reach n");
    }

    // Second banner — snapshot length is the locked invariant.
    {
        let mut line = [0u8; 64];
        let prefix = b"AUDIT snapshot OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Kernel SNTPv4 client banner (TASK-053).
///
/// Exercises the locked [`Sntp`] surface: builds a mode-3 client
/// request with `client_now = NTP_EPOCH + 100s`, asserts the wire
/// byte-0 carries (LI=0, VN=4, Mode=3) = 0x23, and asserts the
/// transmit-timestamp tail equals `100 << 32` in big-endian; then
/// parses a hand-built mode-4 reply with locked timestamps that yield
/// `offset_ns = 0`, `delay_ns = 1_000_000_000`, and asserts both
/// values byte-for-byte against the SNTP algorithm in RFC 4330 §5.
/// A morph that perturbs the bit-packing, the field offsets, or the
/// offset/delay arithmetic panics inside `banner_sntp` and the two
/// banners never appear.
///
/// Emits two banners:
/// - `SNTP request OK mode=3 vn=4 xmt=429496729600` — the transmit
///   timestamp raw value (decimal) recovered from the planted u64.
/// - `SNTP reply OK offset_ns=0 delay_ns=1000000000` — the locked
///   skew computed from the symmetric reply timestamps.
#[cfg(not(proteus_prod))]
fn banner_sntp() {
    // ------------------------------------------------------------------
    // build_request — t1 = NTP_EPOCH + 100s -> raw = 100 << 32.
    // ------------------------------------------------------------------
    let t1 = NtpTimestamp::from_secs_frac(100, 0);
    let mut req = [0u8; SNTP_PACKET_LEN];
    let n = match <SntpImpl as Sntp>::build_request(t1, &mut req) {
        Ok(n) => n,
        Err(_) => panic!("sntp: build_request returned Err"),
    };
    if n != SNTP_PACKET_LEN {
        panic!("sntp: build_request length drift");
    }
    // Byte 0: LI=0, VN=4, Mode=3 -> 0x23.
    if req[0] != 0x23 {
        panic!("sntp: byte0 LI/VN/Mode drift");
    }
    // Bytes 1..40 must be zero in a stock client request.
    let mut k = 1usize;
    while k < 40 {
        if req[k] != 0 {
            panic!("sntp: non-zero filler byte");
        }
        k += 1;
    }
    // Bytes 40..48: big-endian of 100 << 32 = 0x0000_0064_0000_0000.
    let expected_xmt = [0x00, 0x00, 0x00, 0x64, 0x00, 0x00, 0x00, 0x00];
    let mut j = 0usize;
    while j < 8 {
        if req[40 + j] != expected_xmt[j] {
            panic!("sntp: transmit timestamp wire drift");
        }
        j += 1;
    }

    // First banner: xmt raw is t1.raw = 100 << 32 = 429_496_729_600.
    {
        let mut line = [0u8; 96];
        let prefix = b"SNTP request OK mode=3 vn=4 xmt=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(t1.raw, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ------------------------------------------------------------------
    // parse_reply + compute_offset_delay — symmetric goldens.
    //   t1 = 100s, t2 = 100.5s, t3 = 100.5s, t4 = 101s.
    //   offset = ((t2-t1) + (t3-t4)) / 2 = (500e6 + -500e6)/2 = 0.
    //   delay  = (t4-t1) - (t3-t2)       = 1e9 - 0 = 1_000_000_000.
    // ------------------------------------------------------------------
    let t2 = NtpTimestamp::from_secs_frac(100, 0x8000_0000); // 100.5s
    let t3 = NtpTimestamp::from_secs_frac(100, 0x8000_0000); // 100.5s
    let t4 = NtpTimestamp::from_secs_frac(101, 0);

    // Hand-build a mode-4 reply: byte 0 = LI=0, VN=4, Mode=4 = 0x24.
    let mut reply_buf = [0u8; SNTP_PACKET_LEN];
    reply_buf[0] = (0u8 << 6) | ((SNTP_VERSION & 0x7) << 3) | (SNTP_MODE_SERVER & 0x7);
    reply_buf[1] = 3; // stratum
    reply_buf[2] = 6; // poll
    reply_buf[3] = 0xEC; // precision = -20
    // Reference identifier "GPS\0" — stratum 1 primary-reference style.
    reply_buf[12] = b'G';
    reply_buf[13] = b'P';
    reply_buf[14] = b'S';
    reply_buf[15] = 0;
    // Reference + origin + receive + transmit timestamps (big-endian).
    let plant = |buf: &mut [u8; SNTP_PACKET_LEN], at: usize, v: u64| {
        buf[at] = (v >> 56) as u8;
        buf[at + 1] = (v >> 48) as u8;
        buf[at + 2] = (v >> 40) as u8;
        buf[at + 3] = (v >> 32) as u8;
        buf[at + 4] = (v >> 24) as u8;
        buf[at + 5] = (v >> 16) as u8;
        buf[at + 6] = (v >> 8) as u8;
        buf[at + 7] = v as u8;
    };
    plant(&mut reply_buf, 16, NtpTimestamp::from_secs_frac(99, 0).raw); // ref
    plant(&mut reply_buf, 24, t1.raw); // origin
    plant(&mut reply_buf, 32, t2.raw); // receive
    plant(&mut reply_buf, 40, t3.raw); // transmit

    let reply: NtpReply = match <SntpImpl as Sntp>::parse_reply(&reply_buf) {
        Ok(r) => r,
        Err(_) => panic!("sntp: parse_reply returned Err"),
    };
    if reply.stratum != 3 {
        panic!("sntp: reply stratum drift");
    }
    if reply.version != SNTP_VERSION {
        panic!("sntp: reply version drift");
    }
    if reply.leap_indicator != 0 {
        panic!("sntp: reply LI drift");
    }
    if reply.origin_timestamp != t1 {
        panic!("sntp: reply origin drift");
    }
    if reply.receive_timestamp != t2 {
        panic!("sntp: reply receive drift");
    }
    if reply.transmit_timestamp != t3 {
        panic!("sntp: reply transmit drift");
    }
    if reply.ref_id != [b'G', b'P', b'S', 0] {
        panic!("sntp: reply ref_id drift");
    }

    let skew = <SntpImpl as Sntp>::compute_offset_delay(&reply, t4);
    if skew.offset_ns != 0 {
        panic!("sntp: offset_ns drift");
    }
    if skew.delay_ns != 1_000_000_000 {
        panic!("sntp: delay_ns drift");
    }

    // Second banner — offset_ns is exactly zero, delay_ns is exactly
    // 1_000_000_000. dec_u64 handles the unsigned case; the offset is
    // nonneg here so no sign handling is needed.
    {
        let mut line = [0u8; 96];
        let prefix = b"SNTP reply OK offset_ns=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        let off = skew.offset_ns;
        if off < 0 {
            line[pos] = b'-';
            pos += 1;
            pos += dec_u64((-(off as i128)) as u64, &mut line[pos..]);
        } else {
            pos += dec_u64(off as u64, &mut line[pos..]);
        }
        let mid = b" delay_ns=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(skew.delay_ns as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Silence the import-unused warning in case the morph rewrites the
    // call site to avoid the constant.
    let _ = SNTP_MODE_CLIENT;
}

/// VFS banner — TASK-054.
///
/// Exercises the locked [`Vfs`] + [`Filesystem`] surfaces: instantiates a
/// `MemRamFs` in a static-mut arena, seeds `/etc/hostname` with the
/// locked byte fixture `b"proteus-te\n"`, mounts it at `/`, opens the
/// path through `VfsImpl`, reads the bytes back, and asserts the
/// recovered contents byte-for-byte against the locked expectation.
/// A morph that perturbs the mount-table dispatch, the path
/// normalisation, the handle packing, or the open-file table panics
/// inside `banner_vfs` and the two banners never appear.
///
/// Emits two banners:
/// - `VFS mount OK fs=ramfs root=/`
/// - `VFS read OK path=/etc/hostname bytes=11`
#[cfg(not(proteus_prod))]
fn banner_vfs() {
    // Locked fixture matching the kernel-banner expectation.
    const HOSTNAME_BYTES: &[u8] = b"proteus-te\n";
    const HOSTNAME_LEN: usize = 11;

    // Storage backing the ramfs lives in a static-mut arena. The
    // VFS holds a `'static mut` borrow for the lifetime of the
    // banner, so a heap allocator is not required.
    static mut RAMFS: VfsRamFsArena = VfsRamFsArena::new();
    let fs_ref: &'static mut MemRamFs<8, 4096> = unsafe {
        // Safety: we are single-threaded in the kernel banner. The
        // static-mut access is protected by the synchronous call
        // sequence in `kernel_main`; no other code path can touch
        // RAMFS while this banner runs.
        &mut *core::ptr::addr_of_mut!(RAMFS.fs)
    };

    // Seed `/etc/hostname` with the fixture.
    match fs_ref.seed_file(b"/etc/hostname", HOSTNAME_BYTES, HOSTNAME_LEN, 0) {
        Ok(_) => {}
        Err(_) => panic!("vfs: seed_file returned Err"),
    }

    // Build a fresh dispatcher and mount the ramfs at root.
    let mut vfs: VfsImpl<8> = VfsImpl::new();
    match vfs.mount(b"/", fs_ref as &mut dyn Filesystem) {
        Ok(()) => {}
        Err(_) => panic!("vfs: mount returned Err"),
    }
    if vfs.mount_count() != 1 {
        panic!("vfs: mount_count drift");
    }
    match vfs.mount_at(0) {
        Some(mp) if mp == b"/" => {}
        _ => panic!("vfs: mount_at(0) wire drift"),
    }

    // First banner.
    {
        let prefix = b"VFS mount OK fs=ramfs root=/\n";
        serial_write_bytes(prefix);
    }

    // Open + read + close round-trip.
    let h = match <VfsImpl<8> as Vfs>::open(&mut vfs, b"/etc/hostname", FS_O_RDONLY) {
        Ok(h) => h,
        Err(_) => panic!("vfs: open returned Err"),
    };
    let mut buf = [0u8; 32];
    let n = match <VfsImpl<8> as Vfs>::read(&mut vfs, h, 0, &mut buf) {
        Ok(n) => n,
        Err(_) => panic!("vfs: read returned Err"),
    };
    if n != HOSTNAME_LEN {
        panic!("vfs: read length drift");
    }
    // Byte-for-byte assertion against the locked fixture.
    let mut k = 0usize;
    while k < HOSTNAME_LEN {
        if buf[k] != HOSTNAME_BYTES[k] {
            panic!("vfs: read byte drift");
        }
        k += 1;
    }
    match <VfsImpl<8> as Vfs>::close(&mut vfs, h) {
        Ok(()) => {}
        Err(_) => panic!("vfs: close returned Err"),
    }

    // Second banner — bytes=11 is the locked length.
    {
        let mut line = [0u8; 64];
        let prefix = b"VFS read OK path=/etc/hostname bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Static-mut arena holding the kernel-banner ramfs. Sized at compile
/// time so the BSS slot is fixed; the morph engine can diversify the
/// pool / inode internal layout without changing the binary's symbol
/// table.
struct VfsRamFsArena {
    fs: MemRamFs<8, 4096>,
}

impl VfsRamFsArena {
    const fn new() -> Self {
        VfsRamFsArena {
            fs: MemRamFs::new(),
        }
    }
}

/// eBPF interpreter banner — TASK-055.
///
/// Builds the 6-instruction reference program (which computes
/// `1 - (ctx[0] & 1)`), runs it against three input bytes
/// `[0, 1, 2]`, asserts the verdicts equal the locked pattern
/// `[1, 0, 1]`, and emits two banners:
///
/// - `EBPF program OK insns=6 verdicts=1,0,1`
/// - `EBPF stack OK bytes=512`
///
/// A morph that perturbs the ALU64 sub-op dispatch, the MOV/SUB/AND
/// wire-encoding, the LDX byte-size routing, the ST imm planting,
/// or the EXIT terminator path panics inside `banner_ebpf` and the
/// banners never appear. The stack-size banner also fails if the
/// contract's [`BPF_STACK_SIZE`] constant drifts — surfacing a
/// schema-incompatible change before the trailing `PROTEUS-TE
/// HALT` line.
#[cfg(not(proteus_prod))]
fn banner_ebpf() {
    // Run the reference program three times. The context is
    // re-used; the interpreter resets registers + stack on every
    // call by contract, so cross-run leakage is impossible.
    let mut ctx = BpfContext::new();
    const EXPECTED_VERDICTS: [u64; 3] = [1, 0, 1];
    let inputs: [u8; 3] = [0, 1, 2];

    let mut i = 0usize;
    while i < 3 {
        let verdict = match run_reference_program(inputs[i], &mut ctx) {
            Ok(v) => v,
            Err(_) => panic!("ebpf: run returned Err"),
        };
        if verdict != EXPECTED_VERDICTS[i] {
            panic!("ebpf: verdict drift");
        }
        i += 1;
    }

    // Also validate the trait-direct path against a 1-instruction
    // EXIT program — exercises `EBpfImpl::run` directly so a morph
    // that breaks the trait dispatch is caught here.
    let exit_only = [proteus_contracts::BpfInstr::new(
        proteus_contracts::bpf_op::BPF_OP_EXIT,
        0,
        0,
        0,
        0,
    )];
    match EBpfImpl::run(&exit_only, &mut ctx) {
        Ok(0) => {}
        _ => panic!("ebpf: trait-direct exit drift"),
    }

    // Emit banner 1: program OK with the locked verdict tuple.
    {
        let mut line = [0u8; 64];
        let prefix = b"EBPF program OK insns=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(REFERENCE_PROGRAM_INSNS as u64, &mut line[pos..]);
        let mid = b" verdicts=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // Verdicts are 0/1 — fixed-width single decimal digit each.
        line[pos] = b'0' + (EXPECTED_VERDICTS[0] as u8);
        line[pos + 1] = b',';
        line[pos + 2] = b'0' + (EXPECTED_VERDICTS[1] as u8);
        line[pos + 3] = b',';
        line[pos + 4] = b'0' + (EXPECTED_VERDICTS[2] as u8);
        line[pos + 5] = b'\n';
        pos += 6;
        serial_write_bytes(&line[..pos]);
    }

    // Emit banner 2: stack-size invariant from the contract.
    {
        let mut line = [0u8; 64];
        let prefix = b"EBPF stack OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(BPF_STACK_SIZE as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Intel e1000 NIC driver banner — TASK-056.
///
/// Runs the locked round-trip:
///
/// 1. Construct a `MemMmioBus` pre-seeded with the locked
///    `BANNER_MAC` in EEPROM words 0/1/2 and STATUS bits encoding
///    `LU + FD + Up @ 1 Gbit`.
/// 2. Drive `E1000Impl::init` through the bring-up sequence (reset
///    → poll(!RST) → EEPROM MAC read → CTRL.SLU → program RX/TX
///    rings → RCTL.EN + TCTL.EN).
/// 3. Transmit a locked 64-byte Ethernet frame (broadcast dest,
///    `BANNER_MAC` source, EtherType=0x0800, deterministic payload).
///    The bus captures the frame from the TX descriptor on TDT
///    advance — byte-for-byte equality is asserted before continuing.
/// 4. Inject the same frame on the RX side and consume it via
///    `E1000Impl::receive`. Bytes recovered must equal the frame
///    bytes.
///
/// On any drift — descriptor byte packing, EEPROM word index order,
/// MAC read endianness, CTRL.RST poll path, link-state decode,
/// ring wrap modulus, RDT/TDT lag arithmetic — one of the asserts
/// inside `run_banner_round_trip` panics and the QEMU log emits a
/// PANIC line instead of the expected two `E1000 ...` banners.
///
/// A morph that perturbs these internals while leaving the
/// `EthernetController` contract methods, the `MmioRegBus` trait,
/// the descriptor STATUS/CMD constants, or the register-offset
/// constants intact will preserve the banner; a morph that perturbs
/// the wire surface will fail the in-order sweep on this banner.
#[cfg(not(proteus_prod))]
fn banner_e1000() {
    // The driver embeds two 16-slot ring arrays of 1518-byte buffers
    // (~48 KiB) plus the `MemMmioBus` (128 KiB shadow + capture log
    // — ~180 KiB total) — well over the kernel-main stack budget.
    // Park BOTH in static storage initialised through `const fn`
    // constructors so no large value ever lives on the stack. The
    // banner is single-threaded so the unsafe `&mut` against the
    // statics is sound.
    use target_enterprise::e1000::{build_banner_frame, E1000Impl, MemMmioBus};
    use proteus_contracts::{EthernetController, LinkState};

    static mut DRIVER_STORAGE: E1000Impl = E1000Impl::new();
    static mut BUS_STORAGE: MemMmioBus = MemMmioBus::zeroed();

    // SAFETY: kernel_main is single-threaded; this banner runs once
    // before halt. References do not escape.
    let driver: &mut E1000Impl = unsafe {
        let ptr = core::ptr::addr_of_mut!(DRIVER_STORAGE);
        &mut *ptr
    };
    let bus: &mut MemMmioBus = unsafe {
        let ptr = core::ptr::addr_of_mut!(BUS_STORAGE);
        &mut *ptr
    };

    // Seed the EEPROM with the locked banner MAC. STATUS was set by
    // `MemMmioBus::zeroed` to LU + FD + Up @ 1G.
    bus.set_eeprom_mac(BANNER_MAC);

    let mut mac = [0u8; 6];
    if driver.init(bus, &mut mac).is_err() {
        panic!("e1000: init failed");
    }
    if mac != BANNER_MAC {
        panic!("e1000: MAC drift");
    }
    if driver.link_state() != LinkState::Up1000 {
        panic!("e1000: link state drift (expected Up1000)");
    }

    // Transmit a 64-byte fixture frame; the bus drains the TX
    // descriptor on TDT advance and captures the bytes.
    let frame = build_banner_frame();
    if driver.transmit(bus, &frame).is_err() {
        panic!("e1000: transmit failed");
    }
    let caps = bus.tx_captures();
    if caps.len() != 1 || caps[0].len != 64 {
        panic!("e1000: TX capture count or length drift");
    }
    {
        let mut i = 0usize;
        while i < 64 {
            if caps[0].bytes[i] != frame[i] {
                panic!("e1000: TX capture byte drift");
            }
            i += 1;
        }
    }

    // Inject the same frame back on the RX side and round-trip it
    // through `receive`.
    if bus.inject_rx_frame(&frame).is_err() {
        panic!("e1000: RX inject failed");
    }
    let mut rx_buf = [0u8; 64];
    let rx_len = match driver.receive(bus, &mut rx_buf) {
        Ok(Some(n)) => n,
        _ => panic!("e1000: receive failed"),
    };
    if rx_len != 64 {
        panic!("e1000: RX length drift");
    }
    {
        let mut i = 0usize;
        while i < rx_len {
            if rx_buf[i] != frame[i] {
                panic!("e1000: RX byte drift");
            }
            i += 1;
        }
    }

    // Emit banner 1: init OK with the recovered MAC + link speed.
    {
        let mut line = [0u8; 80];
        let prefix = b"E1000 init OK mac=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        let mid = b" link=up_1000";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Emit banner 2: frame round-trip OK with byte counts.
    {
        let mut line = [0u8; 80];
        let prefix = b"E1000 frame OK tx_bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        let mut pos = prefix.len();
        pos += dec_u64(64, &mut line[pos..]);
        let mid = b" rx_bytes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(rx_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// TFTP / TASK-058: RFC 1350 client-side wire codec. The kernel
// builds an RRQ for `/proteus-boot.img` in octet mode, asserts
// the byte-exact request; parses a locked ACK(1) reply, recovers
// block=1; parses a locked DATA(2, "0123456789") packet, recovers
// block=2 + 10-byte payload byte-for-byte. Emits:
//   `TFTP rrq OK len=33 mode=octet\n`
//   `TFTP data OK block=2 bytes=10\n`
//
// A morph that perturbs the opcode big-endian encoding, the
// NUL-terminated string discipline, or the block-number byte
// order panics inside `banner_tftp` and these banners never
// appear.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_tftp() {
    use proteus_contracts::{Tftp, TftpMode, TftpPacket};
    use target_enterprise::tftp::TftpImpl;

    // --- build RRQ ---
    let mut rrq_buf = [0u8; 64];
    let rrq_n =
        match TftpImpl::build_rrq(b"/proteus-boot.img", TftpMode::Octet, &mut rrq_buf) {
            Ok(n) => n,
            Err(_) => panic!("TFTP banner: build_rrq failed"),
        };
    // Expected: opcode(0x0001) + "/proteus-boot.img"(17) + NUL +
    // "octet"(5) + NUL = 2 + 17 + 1 + 5 + 1 = 26.
    // Wait, /proteus-boot.img is 17 chars. So 2+17+1+5+1 = 26.
    // The banner text uses dec_u64 so we just need consistency.
    // Locked expected bytes:
    let expected_rrq: &[u8] = &[
        0x00, 0x01, // opcode = RRQ
        b'/', b'p', b'r', b'o', b't', b'e', b'u', b's', b'-', b'b', b'o', b'o', b't', b'.',
        b'i', b'm', b'g', // filename (17 bytes)
        0x00, // NUL
        b'o', b'c', b't', b'e', b't', // mode
        0x00, // NUL
    ];
    if rrq_n != expected_rrq.len() {
        panic!("TFTP banner: RRQ length drift");
    }
    assert_eq_bytes(&rrq_buf[..rrq_n], expected_rrq, "TFTP RRQ");

    // Emit RRQ banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TFTP rrq OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rrq_n as u64, &mut line[pos..]);
        let mid = b" mode=octet";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // --- parse locked ACK(1) reply ---
    let ack_bytes: &[u8] = &[0x00, 0x04, 0x00, 0x01];
    match TftpImpl::parse_packet(ack_bytes) {
        Ok(TftpPacket::Ack { block }) => {
            if block != 1 {
                panic!("TFTP banner: ACK block drift");
            }
        }
        Ok(_) => panic!("TFTP banner: ACK parsed as wrong variant"),
        Err(_) => panic!("TFTP banner: ACK parse failed"),
    }

    // --- parse locked DATA(2, "0123456789") packet ---
    let data_bytes: &[u8] = &[
        0x00, 0x03, // opcode = DATA
        0x00, 0x02, // block = 2
        b'0', b'1', b'2', b'3', b'4', b'5', b'6', b'7', b'8', b'9',
    ];
    let (rec_block, rec_payload_len) = match TftpImpl::parse_packet(data_bytes) {
        Ok(TftpPacket::Data { block, payload }) => {
            // Byte-equality on the payload.
            if payload.len() != 10 {
                panic!("TFTP banner: DATA payload length drift");
            }
            let expected_payload = b"0123456789";
            let mut i = 0usize;
            while i < payload.len() {
                if payload[i] != expected_payload[i] {
                    panic!("TFTP banner: DATA payload byte drift");
                }
                i += 1;
            }
            (block, payload.len())
        }
        _ => panic!("TFTP banner: DATA parse failed"),
    };
    if rec_block != 2 {
        panic!("TFTP banner: DATA block drift");
    }

    // Emit DATA banner.
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"TFTP data OK block=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rec_block as u64, &mut line[pos..]);
        let mid = b" bytes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(rec_payload_len as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
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
#[cfg(not(proteus_prod))]
fn banner_smp() {
    use proteus_contracts::{smp_consts, ApicWriter, Smp};
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
#[cfg(not(proteus_prod))]
fn banner_pci() {
    use proteus_contracts::{pci_class, Pci, PciAddress, PciBar};
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
#[cfg(not(proteus_prod))]
fn banner_timer() {
    use proteus_contracts::{
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

// TASK-085 GPT
#[cfg(not(proteus_prod))]
fn banner_gpt() {
    use proteus_contracts::Gpt;
    use target_enterprise::gpt::{build_banner_fixture, GPT_FIXTURE_BYTES, GptImpl};

    let mut img = [0u8; GPT_FIXTURE_BYTES];
    build_banner_fixture(&mut img).unwrap();
    let h = GptImpl::parse_header(&img).unwrap();
    if h.num_parts != 1 {
        panic!("GPT banner: parts");
    }
    serial_write_bytes(b"GPT parse OK parts=1\n");
}

// TASK-086 DNS name
#[cfg(not(proteus_prod))]
fn banner_dns_name() {
    use proteus_contracts::{DnsName, DNS_MAX_LABELS};
    use target_enterprise::dns_name::DnsNameImpl;

    let mut wire = [0u8; 32];
    let n = DnsNameImpl::encode(&[b"a", b"b"], &mut wire).unwrap();
    let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
    let mut lens = [0usize; DNS_MAX_LABELS];
    let (c, _) = DnsNameImpl::decode(&wire[..n], 0, &mut labs, &mut lens).unwrap();
    if c != 2 {
        panic!("DNS name banner: labels");
    }
    serial_write_bytes(b"DNS name OK labels=2\n");
}

// TASK-087 DRBG
#[cfg(not(proteus_prod))]
fn banner_drbg() {
    use proteus_contracts::HmacDrbg;
    use target_enterprise::hmac_drbg::{banner_out16, BANNER_LABEL, BANNER_SEED, HmacDrbgImpl};

    let mut o = [0u8; 16];
    HmacDrbgImpl::expand(&BANNER_SEED, BANNER_LABEL, &mut o);
    if o != banner_out16() {
        panic!("DRBG banner: kat");
    }
    serial_write_bytes(b"DRBG kat OK\n");
}

// TASK-088 AHCI Register H2D FIS
#[cfg(not(proteus_prod))]
fn banner_ahci_fis() {
    use proteus_contracts::{AhciFis, ATA_CMD_IDENTIFY, AHCI_FIS_H2D_LEN};
    use target_enterprise::ahci_fis::AhciFisImpl;

    let p = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI banner: identify params"),
    };
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    if AhciFisImpl::encode_h2d(&p, &mut fis).is_err() {
        panic!("AHCI banner: encode");
    }
    let d = match AhciFisImpl::decode_h2d(&fis) {
        Ok(d) => d,
        Err(_) => panic!("AHCI banner: decode"),
    };
    if d.command != ATA_CMD_IDENTIFY || fis[2] != ATA_CMD_IDENTIFY {
        panic!("AHCI banner: cmd drift");
    }
    serial_write_bytes(b"AHCI fis OK cmd=identify\n");
}

// TASK-089 xHCI No-Op TRB
#[cfg(not(proteus_prod))]
fn banner_xhci_trb() {
    use proteus_contracts::{XhciTrb, XHCI_TRB_TYPE_NOOP};
    use target_enterprise::xhci_trb::XhciTrbImpl;

    let w = XhciTrbImpl::encode_noop(true);
    if XhciTrbImpl::trb_type(w.d3) != XHCI_TRB_TYPE_NOOP {
        panic!("XHCI banner: type drift");
    }
    serial_write_bytes(b"XHCI trb OK type=noop\n");
}

// TASK-090 UEFI GOP mode
#[cfg(not(proteus_prod))]
fn banner_uefi_gop() {
    use proteus_contracts::UefiGop;
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

// TASK-091 Attest TLV
#[cfg(not(proteus_prod))]
fn banner_attest_tlv() {
    use proteus_contracts::AttestTlv;
    use target_enterprise::attest_tlv::{banner_three_tags, AttestTlvImpl};

    let mut b = [0u8; 64];
    let n = match banner_three_tags(&mut b) {
        Ok(n) => n,
        Err(_) => panic!("TLV banner: encode"),
    };
    match AttestTlvImpl::count_sequence(&b[..n]) {
        Ok(3) => {}
        _ => panic!("TLV banner: tags"),
    }
    serial_write_bytes(b"TLV parse OK tags=3\n");
}

// TASK-092 Base64
#[cfg(not(proteus_prod))]
fn banner_base64() {
    use target_enterprise::base64::banner_roundtrip;

    if !banner_roundtrip() {
        panic!("B64 banner: roundtrip");
    }
    serial_write_bytes(b"B64 roundtrip OK\n");
}

// TASK-093 AHCI command header + PRDT
#[cfg(not(proteus_prod))]
fn banner_ahci_cmd() {
    use proteus_contracts::AhciCmd;
    use target_enterprise::ahci_cmd::AhciCmdImpl;

    let (h, p) = match AhciCmdImpl::identify_slot(0x1000, 0x2000) {
        Ok(v) => v,
        Err(_) => panic!("AHCI cmd banner: slot"),
    };
    if h.prdtl != 1 || p.byte_count != 512 {
        panic!("AHCI cmd banner: fields");
    }
    let mut hb = [0u8; 32];
    let mut pb = [0u8; 16];
    if AhciCmdImpl::encode_header(&h, &mut hb).is_err()
        || AhciCmdImpl::encode_prdt(&p, &mut pb).is_err()
    {
        panic!("AHCI cmd banner: encode");
    }
    serial_write_bytes(b"AHCI cmd OK prdtl=1\n");
}

/// TASK-104/105 — hardware-truth virtio-blk via real PCI + BAR I/O.
///
/// Unlike `banner_virtio_blk` (MemVirtioBlkBus emulator), this:
/// 1. Issues real `out`/`in` against 0xCF8/0xCFC to find VirtIO blk
/// 2. Enables I/O space in the PCI command register
/// 3. Reads **capacity** from the legacy virtio-pci device config
///    window at BAR0+0x14/0x18 (after the 20-byte common header) —
///    a real I/O-port access into QEMU's virtio-blk model, not MemBus
///
/// Banners:
///   `VIRTIO_HW probe OK blk=found slot=N bar0=0x…`
///   `VIRTIO_HW io OK capacity=2048`   (1 MiB image / 512 B sectors)
///
/// TASK-107: after capacity, runs a real legacy virtqueue write+read
/// of sector 0 (pattern 0xA5^i) against QEMU — not MemBus.
#[cfg(not(proteus_prod))]
fn banner_virtio_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_BLK_TRANSITIONAL: u16 = 0x1001;
    const VIRTIO_BLK_MODERN: u16 = 0x1042;
    /// PCI command bit 0: I/O Space enable.
    const PCI_COMMAND_IO: u32 = 1;
    /// Legacy virtio-pci: device-specific config starts at BAR0+20.
    const VIRTIO_PCI_CONFIG: u16 = 20;
    /// Legacy device_status register offset in I/O BAR.
    const VIRTIO_PCI_STATUS: u16 = 18;
    /// Expected sectors for tools' 1 MiB `virtio_hw.img` (512 B/sec).
    const EXPECTED_CAPACITY: u64 = (1024 * 1024) / 512;

    let mut bus = RealPciBus;
    let mut found_slot: Option<u8> = None;
    let mut found_dev: u16 = 0;
    let mut found_bar0: u32 = 0;
    let mut found_addr: Option<PciAddress> = None;
    let mut bar_is_io = false;

    // Bus 0 only — QEMU default root bus places virtio-blk-pci here.
    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == VIRTIO_VENDOR
            && (dev_id == VIRTIO_BLK_TRANSITIONAL || dev_id == VIRTIO_BLK_MODERN)
        {
            found_slot = Some(device);
            found_dev = dev_id;
            found_addr = Some(addr);
            match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Io(p)) => {
                    found_bar0 = p;
                    bar_is_io = true;
                }
                Ok(PciBar::Mmio32(p)) => {
                    found_bar0 = p;
                    bar_is_io = false;
                }
                Ok(PciBar::Mmio64(p)) => {
                    found_bar0 = p as u32;
                    bar_is_io = false;
                }
                Err(_) => found_bar0 = 0,
            }
            break;
        }
        device = device.wrapping_add(1);
    }

    let slot = match found_slot {
        Some(s) => s,
        None => panic!("VIRTIO_HW: no virtio-blk on bus 0 (attach -device virtio-blk-pci)"),
    };
    let addr = match found_addr {
        Some(a) => a,
        None => panic!("VIRTIO_HW: missing addr"),
    };
    if found_dev == 0 || found_bar0 == 0 {
        panic!("VIRTIO_HW: device id or BAR0 zero");
    }

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_HW probe OK blk=found slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(slot as u64, &mut line[pos..]);
        let mid = b" bar0=0x";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let be = found_bar0.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&be, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ---- TASK-105: real device-config capacity read ----
    // Enable I/O (+ bus master) so the legacy BAR is live.
    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    let new_cmd = cmd | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER;
    PciConfigBus::write_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS, new_cmd);

    let capacity = if bar_is_io {
        let base = found_bar0 as u16;
        // Reset + ACK|DRIVER so config space is active (legacy path).
        unsafe {
            outb(base + VIRTIO_PCI_STATUS, 0);
            outb(base + VIRTIO_PCI_STATUS, 1); // ACKNOWLEDGE
            outb(base + VIRTIO_PCI_STATUS, 3); // ACK | DRIVER
        }
        // capacity is u64 LE at device-config offset 0 → BAR+20.
        let lo = unsafe { inl(base + VIRTIO_PCI_CONFIG) };
        let hi = unsafe { inl(base + VIRTIO_PCI_CONFIG + 4) };
        ((hi as u64) << 32) | (lo as u64)
    } else {
        // MMIO BAR (modern layout residual): try volatile capacity at
        // device-cfg via common offset only if identity-mapped; if not,
        // fail loud — we attach legacy-capable virtio-blk-pci.
        panic!("VIRTIO_HW: BAR0 is MMIO; expect legacy I/O BAR for capacity gate");
    };

    if capacity == 0 {
        panic!("VIRTIO_HW: capacity read returned 0");
    }
    if capacity != EXPECTED_CAPACITY {
        panic!("VIRTIO_HW: capacity drift vs 1MiB virtio_hw.img");
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_HW io OK capacity=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(capacity, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // ---- TASK-107: real virtqueue sector write + read ----
    if !bar_is_io {
        panic!("VIRTIO_HW sector: need legacy I/O BAR");
    }
    if unsafe { PHYS_MAP_OFFSET } == 0 {
        panic!("VIRTIO_HW sector: physical_memory_offset missing");
    }
    if unsafe { DMA_PHYS_BASE } == 0 {
        panic!("VIRTIO_HW sector: no usable DMA region");
    }
    let first = virtio_legacy_sector_roundtrip(found_bar0 as u16);
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_HW sector OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&[first], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TASK-109/111 — hardware-truth virtio-net: PCI probe + MAC + real
/// TX/RX virtqueues (legacy QUEUE_PFN). Not MemVirtioBus.
///
/// QEMU attaches **two** legacy virtio-net-pci devices on the same
/// hub (`hubport`) so a TX on peer B is delivered as RX on peer A —
/// pure in-guest loopback, no host inject race.
///
/// Banners:
///   `VIRTIO_NET_HW probe OK slot=N mac=…`  (RX peer)
///   `VIRTIO_NET_HW tx OK bytes=76`         (12-byte hdr + 64-byte eth)
///   `VIRTIO_NET_HW rx OK bytes=N`          (used.len from RX virtqueue)
#[cfg(not(proteus_prod))]
fn banner_virtio_net_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000;
    const VIRTIO_NET_MODERN: u16 = 0x1041;
    const PCI_COMMAND_IO: u32 = 1;
    const VIRTIO_PCI_STATUS: u16 = 18;
    const VIRTIO_PCI_CONFIG: u16 = 20;

    struct NetDev {
        slot: u8,
        bar0: u16,
        mac: [u8; 6],
    }

    let mut bus = RealPciBus;
    let mut peers: [Option<NetDev>; 2] = [None, None];
    let mut nfound = 0usize;

    let mut device: u8 = 0;
    while device < 32 && nfound < 2 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == VIRTIO_VENDOR
            && (dev_id == VIRTIO_NET_TRANSITIONAL || dev_id == VIRTIO_NET_MODERN)
        {
            let (bar0, bar_is_io) = match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Io(p)) => (p, true),
                Ok(PciBar::Mmio32(p)) => (p, false),
                Ok(PciBar::Mmio64(p)) => (p as u32, false),
                Err(_) => (0, false),
            };
            if bar0 == 0 || !bar_is_io {
                panic!("VIRTIO_NET_HW: need legacy I/O BAR");
            }
            let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
            PciConfigBus::write_dword(
                &mut bus,
                addr,
                PCI_CFG_OFFSET_COMMAND_STATUS,
                cmd | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER,
            );
            let base = bar0 as u16;
            let mut mac = [0u8; 6];
            unsafe {
                outb(base + VIRTIO_PCI_STATUS, 0);
                outb(base + VIRTIO_PCI_STATUS, 1);
                outb(base + VIRTIO_PCI_STATUS, 3);
                let mut i = 0usize;
                while i < 6 {
                    mac[i] = inb(base + VIRTIO_PCI_CONFIG + i as u16);
                    i += 1;
                }
            }
            if mac[0] == 0 && mac[1] == 0 && mac[2] == 0 {
                panic!("VIRTIO_NET_HW: MAC all zeros");
            }
            peers[nfound] = Some(NetDev {
                slot: device,
                bar0: base,
                mac,
            });
            nfound += 1;
            let _ = addr;
        }
        device = device.wrapping_add(1);
    }

    if nfound < 2 {
        panic!("VIRTIO_NET_HW: need two hubport virtio-net devices");
    }
    if unsafe { PHYS_MAP_OFFSET } == 0 || unsafe { DMA_PHYS_BASE } == 0 {
        panic!("VIRTIO_NET_HW: DMA map missing");
    }

    let rx = peers[0].as_ref().unwrap();
    let tx = peers[1].as_ref().unwrap();

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET_HW probe OK slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rx.slot as u64, &mut line[pos..]);
        let mid = b" mac=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 12];
        hex_encode(&rx.mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let (tx_bytes, rx_bytes) = virtio_legacy_net_hub_roundtrip(rx.bar0, tx.bar0, &tx.mac);

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET_HW tx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(tx_bytes as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"VIRTIO_NET_HW rx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(rx_bytes as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// DMA layout for hub TX→RX (qsz=256 → used ring @ +0x2000, region 0x3000):
///   [0x0000) RX peer queue 0 (live RX)
///   [0x3000) RX peer queue 1 (empty TX placeholder)
///   [0x6000) TX peer queue 0 (empty RX placeholder)
///   [0x9000) TX peer queue 1 (live TX)
///   [0xC000) RX buffer (2 KiB)
///   [0xC800) TX frame (hdr+eth)
///
/// Returns (tx_bytes, rx_used_len).
fn virtio_legacy_net_hub_roundtrip(rx_io: u16, tx_io: u16, tx_mac: &[u8; 6]) -> (usize, usize) {
    use core::sync::atomic::{fence, Ordering};

    const Q_RX: u16 = 0;
    const Q_TX: u16 = 1;
    const HDR: usize = 12;
    const FRAME: usize = 64;
    const TOTAL: usize = HDR + FRAME;
    const RX_BUF_LEN: u32 = 2048;
    /// Payload magic at eth offset 14 (after dst/src/etype) — proves real delivery.
    const MAGIC: &[u8; 8] = b"PNETRX01";

    let dma = unsafe { DMA_PHYS_BASE };
    let rx_q_pa = dma; // RX peer RX queue
    let rx_dummy_tx_q_pa = dma + 0x3000;
    let tx_dummy_rx_q_pa = dma + 0x6000;
    let tx_q_pa = dma + 0x9000;
    let rx_buf_pa = dma + 0xC000;
    let tx_frame_pa = dma + 0xC800;

    // Zero DMA window (queues + buffers); needs full 64 KiB map.
    unsafe {
        let base = pa_to_va(dma);
        let mut i = 0usize;
        while i < 0xD000 {
            core::ptr::write_volatile(base.add(i), 0);
            i += 1;
        }
        // Poison RX buffer so overwrite is visible.
        let rb = pa_to_va(rx_buf_pa);
        i = 0;
        while i < RX_BUF_LEN as usize {
            core::ptr::write_volatile(rb.add(i), 0xEE);
            i += 1;
        }
        // Build TX frame: virtio_net_hdr + eth broadcast + magic payload.
        let f = pa_to_va(tx_frame_pa);
        i = 0;
        while i < HDR {
            core::ptr::write_volatile(f.add(i), 0);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(f.add(HDR + i), 0xff);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(f.add(HDR + 6 + i), tx_mac[i]);
            i += 1;
        }
        core::ptr::write_volatile(f.add(HDR + 12), 0x88);
        core::ptr::write_volatile(f.add(HDR + 13), 0xB5);
        i = 0;
        while i < MAGIC.len() {
            core::ptr::write_volatile(f.add(HDR + 14 + i), MAGIC[i]);
            i += 1;
        }
    }

    let avail_off = (VQ_SIZE as u64) * 16;
    let used_off = {
        let raw = avail_off + 4 + 2 * (VQ_SIZE as u64);
        (raw + VQ_ALIGN - 1) & !(VQ_ALIGN - 1)
    };

    // ---- RX peer: post one device-writable buffer on queue 0 ----
    unsafe {
        outb(rx_io + 18, 0);
        outb(rx_io + 18, 1);
        outb(rx_io + 18, 3);
        outl(rx_io + 4, 0);
        // Queue 0 = RX
        outw(rx_io + 14, Q_RX);
        let qsz = inw(rx_io + 12);
        if qsz != VQ_SIZE {
            panic!("VIRTIO_NET_HW: RX peer qsz");
        }
        outl(rx_io + 8, (rx_q_pa >> 12) as u32);
        // Queue 1 = TX (empty avail — not used on RX peer)
        outw(rx_io + 14, Q_TX);
        let qsz_tx = inw(rx_io + 12);
        if qsz_tx != VQ_SIZE {
            panic!("VIRTIO_NET_HW: RX peer TX qsz");
        }
        // Valid empty queue region; leave avail.idx=0.
        outl(rx_io + 8, (rx_dummy_tx_q_pa >> 12) as u32);
    }
    let rx_q = pa_to_va(rx_q_pa);
    // VRING_DESC_F_WRITE = 2
    write_desc_phys(rx_q, 0, rx_buf_pa, RX_BUF_LEN, 2, 0);
    unsafe {
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 4), 0);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 5), 0);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 2), 1);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 3), 0);
    }
    fence(Ordering::SeqCst);
    unsafe {
        outb(rx_io + 18, 1 | 2 | 4); // DRIVER_OK
        outw(rx_io + 16, Q_RX); // kick RX with buffer available
    }

    // ---- TX peer: send one frame on queue 1 ----
    unsafe {
        outb(tx_io + 18, 0);
        outb(tx_io + 18, 1);
        outb(tx_io + 18, 3);
        outl(tx_io + 4, 0);
        outw(tx_io + 14, Q_RX);
        let qsz = inw(tx_io + 12);
        if qsz != VQ_SIZE {
            panic!("VIRTIO_NET_HW: TX peer RX qsz");
        }
        outl(tx_io + 8, (tx_dummy_rx_q_pa >> 12) as u32);
        outw(tx_io + 14, Q_TX);
        let qsz2 = inw(tx_io + 12);
        if qsz2 != VQ_SIZE {
            panic!("VIRTIO_NET_HW: TX peer TX qsz");
        }
        outl(tx_io + 8, (tx_q_pa >> 12) as u32);
        outb(tx_io + 18, 1 | 2 | 4);
    }
    let tx_q = pa_to_va(tx_q_pa);
    write_desc_phys(tx_q, 0, tx_frame_pa, TOTAL as u32, 0, 0);
    unsafe {
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 4), 0);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 5), 0);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 2), 1);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 3), 0);
    }
    fence(Ordering::SeqCst);
    unsafe {
        outw(tx_io + 16, Q_TX);
    }

    // Wait TX completion.
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(tx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(tx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == 1 {
            break;
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            panic!("VIRTIO_NET_HW: TX completion timeout");
        }
        core::hint::spin_loop();
    }

    // Wait RX completion (hub delivers TX frame to peer).
    spins = 0;
    let rx_len = loop {
        fence(Ordering::SeqCst);
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == 1 {
            // used.ring[0].len at used_off + 4 + 4 (id u32, len u32)
            break unsafe {
                let p = rx_q.add(used_off as usize + 8);
                let b0 = core::ptr::read_volatile(p);
                let b1 = core::ptr::read_volatile(p.add(1));
                let b2 = core::ptr::read_volatile(p.add(2));
                let b3 = core::ptr::read_volatile(p.add(3));
                u32::from_le_bytes([b0, b1, b2, b3])
            };
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            panic!("VIRTIO_NET_HW: RX completion timeout");
        }
        core::hint::spin_loop();
    };

    if rx_len < (10 + 14 + MAGIC.len()) as u32 {
        panic!("VIRTIO_NET_HW: RX frame too short");
    }

    // Search for magic in received buffer (after virtio_net_hdr 10 or 12).
    let found = unsafe {
        let rb = pa_to_va(rx_buf_pa);
        let max = (rx_len as usize).min(RX_BUF_LEN as usize);
        let mut ok = false;
        let mut off = 0usize;
        while off + MAGIC.len() <= max {
            let mut m = 0usize;
            let mut match_ok = true;
            while m < MAGIC.len() {
                if core::ptr::read_volatile(rb.add(off + m)) != MAGIC[m] {
                    match_ok = false;
                    break;
                }
                m += 1;
            }
            if match_ok {
                ok = true;
                break;
            }
            off += 1;
        }
        ok
    };
    if !found {
        panic!("VIRTIO_NET_HW: RX magic missing (hub deliver failed)");
    }

    (TOTAL, rx_len as usize)
}

// ---------------------------------------------------------------------------
// TASK-113: real AHCI HBA under QEMU (PCI + MMIO + ATA IDENTIFY)
// Not MemBus — PCI class 01:06:01, ABAR MMIO, port command engine.
// ---------------------------------------------------------------------------

// Banners:
//   `AHCI_HW probe OK slot=N abar=0x… pi=0x…`
//   `AHCI_HW identify OK sectors=2048`
//   `AHCI_HW sector OK first_byte=5a`  (TASK-117 WRITE+READ DMA)
// ---------------------------------------------------------------------------
// Shared AHCI hardware port — probe, engine start, and single-slot sector I/O
// against the QEMU `ahci` device + ide-hd. Factored out of banner_ahci_hw so
// the continuity banner can persist the WAL to real disk across morph boots
// without duplicating 400 lines of MMIO setup.
// ---------------------------------------------------------------------------
struct AhciHwPort {
    abar: u64,
    pbase: u64,
    clb_pa: u64,
    ctba_pa: u64,
    data_pa: u64,
    slot: u8,
}

impl AhciHwPort {
    /// PCI scan for the AHCI HBA, enable MMIO + bus mastering, start the
    /// port command engine on the first port with a device present.
    fn probe_start() -> Self {
        use proteus_contracts::{
            pci_class, Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_CLASS_REVISION,
            PCI_CFG_OFFSET_COMMAND_STATUS, PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
        };
        use target_enterprise::pci::PciImpl;

        const PCI_COMMAND_MEMORY: u32 = 1 << 1;
        const PROG_IF_AHCI: u8 = 0x01;
        const REG_CAP: u64 = 0x00;
        const REG_GHC: u64 = 0x04;
        const REG_PI: u64 = 0x0C;
        const REG_VS: u64 = 0x10;
        const PORT_CLB: u64 = 0x00;
        const PORT_CLBU: u64 = 0x04;
        const PORT_FB: u64 = 0x08;
        const PORT_FBU: u64 = 0x0C;
        const PORT_IS: u64 = 0x10;
        const PORT_CMD: u64 = 0x18;
        const PORT_SSTS: u64 = 0x28;
        const PORT_SERR: u64 = 0x30;
        const PX_CMD_ST: u32 = 1;
        const PX_CMD_FRE: u32 = 1 << 4;
        const PX_CMD_FR: u32 = 1 << 14;
        const PX_CMD_CR: u32 = 1 << 15;
        const GHC_AE: u32 = 1 << 31;

        if unsafe { PHYS_MAP_OFFSET } == 0 || unsafe { DMA_PHYS_BASE } == 0 {
            panic!("AHCI_HW: DMA / phys map missing");
        }
        let mut bus = RealPciBus;
        let mut found_slot: Option<u8> = None;
        let mut found_addr: Option<PciAddress> = None;
        let mut abar: u64 = 0;
        let mut device: u8 = 0;
        while device < 32 {
            let addr = PciAddress { bus: 0, device, function: 0 };
            let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
            if (id & 0xFFFF) == 0xFFFF {
                device = device.wrapping_add(1);
                continue;
            }
            let class_dw = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_CLASS_REVISION);
            let class_code = (class_dw >> 24) as u8;
            let subclass = (class_dw >> 16) as u8;
            let prog_if = (class_dw >> 8) as u8;
            if class_code == pci_class::CLASS_MASS_STORAGE
                && subclass == pci_class::SUBCLASS_SATA
                && prog_if == PROG_IF_AHCI
            {
                let bar = match PciImpl::read_bar(&mut bus, addr, 5) {
                    Ok(PciBar::Mmio32(p)) => p as u64,
                    Ok(PciBar::Mmio64(p)) => p,
                    Ok(PciBar::Io(_)) | Err(_) => 0,
                };
                let bar = if bar == 0 {
                    match PciImpl::read_bar(&mut bus, addr, 0) {
                        Ok(PciBar::Mmio32(p)) => p as u64,
                        Ok(PciBar::Mmio64(p)) => p,
                        _ => 0,
                    }
                } else {
                    bar
                };
                if bar != 0 {
                    found_slot = Some(device);
                    found_addr = Some(addr);
                    abar = bar;
                    break;
                }
            }
            device = device.wrapping_add(1);
        }
        let slot = match found_slot {
            Some(s) => s,
            None => panic!("AHCI_HW: no AHCI HBA on bus 0 (attach -device ahci)"),
        };
        let addr = match found_addr {
            Some(a) => a,
            None => panic!("AHCI_HW: missing addr"),
        };
        let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
        PciConfigBus::write_dword(
            &mut bus,
            addr,
            PCI_CFG_OFFSET_COMMAND_STATUS,
            cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
        );
        unsafe {
            let ghc = mmio_read32(abar + REG_GHC);
            mmio_write32(abar + REG_GHC, ghc | GHC_AE);
        }
        let cap = unsafe { mmio_read32(abar + REG_CAP) };
        let pi = unsafe { mmio_read32(abar + REG_PI) };
        let vs = unsafe { mmio_read32(abar + REG_VS) };
        if cap == 0 || cap == 0xFFFF_FFFF {
            panic!("AHCI_HW: CAP read failed (MMIO map?)");
        }
        if pi == 0 {
            panic!("AHCI_HW: no ports implemented");
        }
        if vs == 0 {
            panic!("AHCI_HW: version register zero");
        }
        {
            let mut line = [0u8; 80];
            let mut pos = 0usize;
            let prefix = b"AHCI_HW probe OK slot=";
            line[..prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            pos += dec_u64(slot as u64, &mut line[pos..]);
            let mid = b" abar=0x";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            let be = (abar as u32).to_be_bytes();
            let mut hex = [0u8; 8];
            hex_encode(&be, 4, &mut hex);
            line[pos..pos + 8].copy_from_slice(&hex);
            pos += 8;
            let mid2 = b" pi=0x";
            line[pos..pos + mid2.len()].copy_from_slice(mid2);
            pos += mid2.len();
            let pibe = pi.to_be_bytes();
            hex_encode(&pibe, 4, &mut hex);
            line[pos..pos + 8].copy_from_slice(&hex);
            pos += 8;
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }

        // First implemented port with device present (SSTS.DET == 3).
        let mut port: Option<u32> = None;
        let mut p = 0u32;
        while p < 32 {
            if (pi & (1u32 << p)) != 0 {
                let pbase = abar + 0x100 + (p as u64) * 0x80;
                let ssts = unsafe { mmio_read32(pbase + PORT_SSTS) };
                if (ssts & 0xF) == 3 {
                    port = Some(p);
                    break;
                }
            }
            p += 1;
        }
        let port = match port {
            Some(p) => p,
            None => panic!("AHCI_HW: no port with device present"),
        };
        let pbase = abar + 0x100 + (port as u64) * 0x80;

        let dma = unsafe { DMA_PHYS_BASE };
        let clb_pa = dma; // 1 KiB aligned
        let fb_pa = dma + 0x0400; // 256 B aligned
        let ctba_pa = dma + 0x0800; // 128 B aligned
        let data_pa = dma + 0x1000;

        unsafe {
            let base = pa_to_va(dma);
            let mut i = 0usize;
            while i < 0x1400 {
                core::ptr::write_volatile(base.add(i), 0);
                i += 1;
            }
            let mut c = mmio_read32(pbase + PORT_CMD);
            c &= !(PX_CMD_ST | PX_CMD_FRE);
            mmio_write32(pbase + PORT_CMD, c);
            let mut spins = 0u32;
            loop {
                let c2 = mmio_read32(pbase + PORT_CMD);
                if c2 & (PX_CMD_CR | PX_CMD_FR) == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: port stop timeout");
                }
                core::hint::spin_loop();
            }
            mmio_write32(pbase + PORT_CLB, clb_pa as u32);
            mmio_write32(pbase + PORT_CLBU, (clb_pa >> 32) as u32);
            mmio_write32(pbase + PORT_FB, fb_pa as u32);
            mmio_write32(pbase + PORT_FBU, (fb_pa >> 32) as u32);
            mmio_write32(pbase + PORT_SERR, 0xFFFF_FFFF);
            mmio_write32(pbase + PORT_IS, 0xFFFF_FFFF);
            let mut c = mmio_read32(pbase + PORT_CMD);
            c |= PX_CMD_FRE;
            mmio_write32(pbase + PORT_CMD, c);
            spins = 0;
            loop {
                if mmio_read32(pbase + PORT_CMD) & PX_CMD_FR != 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: FRE start timeout");
                }
                core::hint::spin_loop();
            }
            c = mmio_read32(pbase + PORT_CMD);
            c |= PX_CMD_ST;
            mmio_write32(pbase + PORT_CMD, c);
        }

        AhciHwPort {
            abar,
            pbase,
            clb_pa,
            ctba_pa,
            data_pa,
            slot,
        }
    }

    /// Issue one H2D command in slot 0 against the running port.
    fn issue(&self, fis_params: &proteus_contracts::H2dFisParams, write: bool, tag: &[u8]) {
        use proteus_contracts::{
            AhciCmd, AhciCmdHeader, AhciFis, AhciPrdt, AHCI_CFL_H2D, AHCI_CMD_HDR_LEN,
            AHCI_FIS_H2D_LEN, AHCI_PRDT_LEN,
        };
        use target_enterprise::ahci_cmd::AhciCmdImpl;
        use target_enterprise::ahci_fis::AhciFisImpl;

        const PORT_IS: u64 = 0x10;
        const PORT_TFD: u64 = 0x20;
        const PORT_CI: u64 = 0x38;

        let mut fis = [0u8; AHCI_FIS_H2D_LEN];
        if AhciFisImpl::encode_h2d(fis_params, &mut fis).is_err() {
            panic!("AHCI_HW: FIS encode");
        }
        let hdr = AhciCmdHeader {
            cfl: AHCI_CFL_H2D,
            write,
            pmp: 0,
            prdtl: 1,
            prdbc: 0,
            ctba: self.ctba_pa,
        };
        let prdt = AhciPrdt {
            dba: self.data_pa,
            byte_count: 512,
            ioc: true,
        };
        let mut hbuf = [0u8; AHCI_CMD_HDR_LEN];
        let mut pbuf = [0u8; AHCI_PRDT_LEN];
        if AhciCmdImpl::encode_header(&hdr, &mut hbuf).is_err()
            || AhciCmdImpl::encode_prdt(&prdt, &mut pbuf).is_err()
        {
            panic!("AHCI_HW: header/PRDT encode");
        }
        unsafe {
            let ct = pa_to_va(self.ctba_pa);
            let mut i = 0usize;
            while i < 0x100 {
                core::ptr::write_volatile(ct.add(i), 0);
                i += 1;
            }
            i = 0;
            while i < AHCI_FIS_H2D_LEN {
                core::ptr::write_volatile(ct.add(i), fis[i]);
                i += 1;
            }
            i = 0;
            while i < AHCI_PRDT_LEN {
                core::ptr::write_volatile(ct.add(0x80 + i), pbuf[i]);
                i += 1;
            }
            let cl = pa_to_va(self.clb_pa);
            i = 0;
            while i < AHCI_CMD_HDR_LEN {
                core::ptr::write_volatile(cl.add(i), hbuf[i]);
                i += 1;
            }
            let mut spins = 0u32;
            loop {
                let tfd = mmio_read32(self.pbase + PORT_TFD);
                if tfd & 0x80 == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("AHCI_HW: TFD BSY timeout");
                }
                core::hint::spin_loop();
            }
            mmio_write32(self.pbase + PORT_IS, 0xFFFF_FFFF);
            mmio_write32(self.pbase + PORT_CI, 1);
            spins = 0;
            loop {
                if mmio_read32(self.pbase + PORT_CI) & 1 == 0 {
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 40_000_000 {
                    let _ = tag;
                    panic!("AHCI_HW: command CI timeout");
                }
                core::hint::spin_loop();
            }
            let tfd = mmio_read32(self.pbase + PORT_TFD);
            if tfd & 0x01 != 0 {
                let _ = tag;
                panic!("AHCI_HW: command TFD ERR");
            }
        }
    }

    /// Read the DMA data buffer back into a 512-byte array.
    fn drain_data(&self) -> [u8; 512] {
        let mut out = [0u8; 512];
        unsafe {
            let d = pa_to_va(self.data_pa);
            let mut i = 0usize;
            while i < 512 {
                out[i] = core::ptr::read_volatile(d.add(i));
                i += 1;
            }
        }
        out
    }

    /// Fill the DMA data buffer from a 512-byte array.
    fn fill_data(&self, src: &[u8; 512]) {
        unsafe {
            let d = pa_to_va(self.data_pa);
            let mut i = 0usize;
            while i < 512 {
                core::ptr::write_volatile(d.add(i), src[i]);
                i += 1;
            }
        }
    }

    /// ATA WRITE DMA one 512-byte sector at `lba`.
    fn write_sector(&self, lba: u64, data: &[u8; 512]) {
        use proteus_contracts::{H2dFisParams, ATA_DEV_LBA};
        const ATA_CMD_WRITE_DMA: u8 = 0xCA;
        self.fill_data(data);
        let wr = H2dFisParams {
            command: ATA_CMD_WRITE_DMA,
            features: 0,
            lba,
            count: 1,
            device: ATA_DEV_LBA,
            pm_port: 0,
            is_command: true,
        };
        self.issue(&wr, true, b"write");
    }

    /// ATA READ DMA one 512-byte sector at `lba`.
    fn read_sector(&self, lba: u64) -> [u8; 512] {
        use proteus_contracts::{AhciFis, ATA_CMD_READ_DMA};
        use target_enterprise::ahci_fis::AhciFisImpl;
        let rd = match AhciFisImpl::read_dma(lba, 1, 0) {
            Ok(p) => p,
            Err(_) => panic!("AHCI_HW: read_dma params"),
        };
        if rd.command != ATA_CMD_READ_DMA {
            panic!("AHCI_HW: read_dma opcode drift");
        }
        self.issue(&rd, false, b"read");
        self.drain_data()
    }
}

/// Banner: `AHCI_HW probe OK slot=N abar=… pi=…`, `AHCI_HW identify OK
/// sectors=2048`, `AHCI_HW sector OK first_byte=5a` (real PCI + MMIO +
/// IDENTIFY + sector DMA — TASK-113/117).
#[cfg(not(proteus_prod))]
fn banner_ahci_hw() {
    use proteus_contracts::{AhciFis, ATA_CMD_READ_DMA};
    use target_enterprise::ahci_fis::AhciFisImpl;

    /// 1 MiB `ahci_hw.img` → 2048 × 512 B sectors.
    const EXPECTED_SECTORS: u64 = (1024 * 1024) / 512;

    let port = AhciHwPort::probe_start();

    // IDENTIFY via contract helper.
    let fis_params = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI_HW: identify params"),
    };
    port.issue(&fis_params, false, b"identify");
    let data = port.drain_data();
    let mut all_zero = true;
    let mut i = 0usize;
    while i < 512 {
        if data[i] != 0 {
            all_zero = false;
            break;
        }
        i += 1;
    }
    if all_zero {
        panic!("AHCI_HW: IDENTIFY buffer empty");
    }
    let w60 = u16::from_le_bytes([data[120], data[121]]) as u64;
    let w61 = u16::from_le_bytes([data[122], data[123]]) as u64;
    let lba28 = w60 | (w61 << 16);
    let w100 = u16::from_le_bytes([data[200], data[201]]) as u64;
    let w101 = u16::from_le_bytes([data[202], data[203]]) as u64;
    let w102 = u16::from_le_bytes([data[204], data[205]]) as u64;
    let w103 = u16::from_le_bytes([data[206], data[207]]) as u64;
    let lba48 = w100 | (w101 << 16) | (w102 << 32) | (w103 << 48);
    let sectors = if lba48 != 0 { lba48 } else { lba28 };
    if sectors != EXPECTED_SECTORS {
        panic!("AHCI_HW: sector count drift vs 1MiB ahci_hw.img");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"AHCI_HW identify OK sectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(sectors, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // WRITE DMA + READ DMA sector 0 (pattern 0x5A ^ i).
    let mut pattern = [0u8; 512];
    i = 0;
    while i < 512 {
        pattern[i] = 0x5Au8 ^ (i as u8);
        i += 1;
    }
    port.write_sector(0, &pattern);
    let rd = match AhciFisImpl::read_dma(0, 1, 0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI_HW: read_dma params"),
    };
    if rd.command != ATA_CMD_READ_DMA {
        panic!("AHCI_HW: read_dma opcode drift");
    }
    port.fill_data(&[0xEEu8; 512]);
    port.issue(&rd, false, b"read");
    let back = port.drain_data();
    let mut i2 = 0usize;
    while i2 < 512 {
        let want = 0x5Au8 ^ (i2 as u8);
        if back[i2] != want {
            panic!("AHCI_HW: sector data drift");
        }
        i2 += 1;
    }
    let first = back[0];

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"AHCI_HW sector OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hx = [0u8; 2];
        hex_encode(&[first], 1, &mut hx);
        line[pos] = hx[0];
        line[pos + 1] = hx[1];
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ---------------------------------------------------------------------------
// Cross-morph durable-state continuity (Class A of the cadence program).
//
// The theory: a morph cycle is a fast reboot. Durable state survives iff
// the on-disk format is part of the locked contract surface and the next
// kernel replays it. This banner proves it with the REAL WAL and REAL
// disk: a 9-sector region at LBA 1024 on the AHCI disk holds one header
// sector (magic, boot counter, durable cursor, region CRC) plus 8 sectors
// of WalImpl backing. Each boot:
//   1. reads the header; if magic + region CRC verify, reconstructs the
//      WAL via `WalImpl::from_backing` and replays it — this is the
//      "morphed kernel resumes prior durable state" moment;
//   2. appends one boot-marker frame (payload: boot counter + resumed
//      frame count), flushes (CapProof-gated like every durable write),
//      and writes the region + updated header back.
// Genesis (blank/corrupt region) starts a fresh WAL. A second boot —
// especially of a LAYOUT-MORPHED image — printing `CONTINUITY resume OK`
// with a strictly larger frame count is the cross-morph proof.
// ---------------------------------------------------------------------------

/// First LBA of the continuity region (header + 8 WAL sectors). Chosen
/// above the sectors exercised by other banners (sector 0) and below
/// the 2048-sector disk size.
const CONTINUITY_LBA: u64 = 1024;
const CONTINUITY_MAGIC: &[u8; 8] = b"PRTSWAL1";
const CONTINUITY_WAL_SECTORS: u64 = (kf::WAL_CAPACITY / 512) as u64;

fn banner_continuity() {
    use target_enterprise::wal::crc32_ieee;

    let port = AhciHwPort::probe_start();

    // Read header sector.
    let hdr = port.read_sector(CONTINUITY_LBA);
    let mut wal_buf = [0u8; kf::WAL_CAPACITY];
    let mut resumed_boots: u64 = 0;
    let mut resumed_cursor: usize = 0;
    let mut is_resume = false;
    if hdr[..8] == CONTINUITY_MAGIC[..] {
        resumed_boots = u64::from_le_bytes(hdr[8..16].try_into().unwrap());
        resumed_cursor =
            u32::from_le_bytes(hdr[16..20].try_into().unwrap()) as usize;
        let want_crc = u32::from_le_bytes(hdr[20..24].try_into().unwrap());
        let mut s = 0u64;
        while s < CONTINUITY_WAL_SECTORS {
            let sec = port.read_sector(CONTINUITY_LBA + 1 + s);
            let off = (s as usize) * 512;
            wal_buf[off..off + 512].copy_from_slice(&sec);
            s += 1;
        }
        if crc32_ieee(&wal_buf) == want_crc && resumed_cursor <= kf::WAL_CAPACITY {
            is_resume = true;
        }
    }

    let mut wal: WalImpl<{ kf::WAL_CAPACITY }> = if is_resume {
        WalImpl::from_backing(wal_buf, resumed_cursor)
    } else {
        WalImpl::new()
    };

    // Replay the durable prefix: count frames and last LSN.
    let mut frames: u64 = 0;
    let mut last_lsn: u64 = 0;
    wal.replay(&mut |lsn, _payload| {
        frames += 1;
        if lsn <= last_lsn {
            panic!("CONTINUITY: replay LSN not monotonic");
        }
        last_lsn = lsn;
    });

    {
        let mut line = [0u8; 80];
        let mut pos = 0usize;
        if is_resume {
            let prefix = b"CONTINUITY resume OK boots=";
            line[..prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            pos += dec_u64(resumed_boots, &mut line[pos..]);
        } else {
            let prefix = b"CONTINUITY genesis boots=";
            line[..prefix.len()].copy_from_slice(prefix);
            pos += prefix.len();
            pos += dec_u64(0, &mut line[pos..]);
        }
        let mid = b" frames=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(frames, &mut line[pos..]);
        let mid2 = b" lsn=";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(last_lsn, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Append the boot-marker frame: payload = [boot counter, resumed
    // frame count] — each morph boot leaves an auditable trace.
    let this_boot = resumed_boots + 1;
    // Publish for the UDP status payload ("PROTEUS-STATUS boots=N").
    CONTINUITY_BOOT_COUNT.store(this_boot, core::sync::atomic::Ordering::Relaxed);
    let mut marker = [0u8; 16];
    marker[..8].copy_from_slice(&this_boot.to_le_bytes());
    marker[8..].copy_from_slice(&frames.to_le_bytes());
    if wal.append(&marker).is_err() {
        // WAL region full → CHECKPOINT: the header's boot counter is the
        // cross-morph continuity truth; the WAL region rotates. Start a
        // fresh WAL with a checkpoint marker carrying the boot count and
        // the pre-rotation frame count, so the on-disk journal always
        // opens with a boundary record. This is what lets cadence run
        // indefinitely (soak-tested at 1000+ cycles).
        let mut fresh: WalImpl<{ kf::WAL_CAPACITY }> = WalImpl::new();
        if fresh.append(&marker).is_err() {
            panic!("CONTINUITY: checkpoint marker append failed");
        }
        wal = fresh;
    }
    if wal
        .flush(target_enterprise::wal::durable_wal_proof_init())
        .is_err()
    {
        panic!("CONTINUITY: flush failed");
    }

    // Persist: WAL region sectors then header (header LAST so a crash
    // mid-write never presents a valid header over a stale region).
    let backing = wal.backing();
    let mut s = 0u64;
    while s < CONTINUITY_WAL_SECTORS {
        let off = (s as usize) * 512;
        let mut sec = [0u8; 512];
        sec.copy_from_slice(&backing[off..off + 512]);
        port.write_sector(CONTINUITY_LBA + 1 + s, &sec);
        s += 1;
    }
    let new_crc = crc32_ieee(backing);
    let mut hdr_out = [0u8; 512];
    hdr_out[..8].copy_from_slice(CONTINUITY_MAGIC);
    hdr_out[8..16].copy_from_slice(&this_boot.to_le_bytes());
    hdr_out[16..20].copy_from_slice(&(wal.durable_cursor() as u32).to_le_bytes());
    hdr_out[20..24].copy_from_slice(&new_crc.to_le_bytes());
    port.write_sector(CONTINUITY_LBA, &hdr_out);

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"CONTINUITY persist OK cursor=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(wal.durable_cursor() as u64, &mut line[pos..]);
        let mid = b" crc=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let be = new_crc.to_be_bytes();
        let mut hex = [0u8; 8];
        hex_encode(&be, 4, &mut hex);
        line[pos..pos + 8].copy_from_slice(&hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ---------------------------------------------------------------------------
// Modern virtio-net driver (virtio 1.x, MMIO common-config) — ported
// from RustOSa's proven slirp-facing driver (src/virtio_net.rs). The
// legacy I/O-port path receives hub frames but is deaf on QEMU
// user-mode networking (slirp); the modern path is what RustOSa runs
// real DHCP/DNS/UDP over, so the service speaks modern when a
// 0x1041 device is present.
// ---------------------------------------------------------------------------

const VN_CC_FEATURE_SEL: usize = 0x00;
const VN_CC_FEATURE: usize = 0x04;
const VN_CC_DRV_FEATURE_SEL: usize = 0x08;
const VN_CC_DRV_FEATURE: usize = 0x0C;
const VN_CC_STATUS: usize = 0x14;
const VN_CC_QUEUE_SELECT: usize = 0x16;
const VN_CC_QUEUE_SIZE: usize = 0x18;
const VN_CC_QUEUE_ENABLE: usize = 0x1C;
const VN_CC_QUEUE_NOTIFY_OFF: usize = 0x1E;
const VN_CC_QUEUE_DESC: usize = 0x20;
const VN_CC_QUEUE_DRIVER: usize = 0x28;
const VN_CC_QUEUE_DEVICE: usize = 0x30;
const VN_QSIZE: u16 = 64;
const VN_RX_BUFFERS: usize = 8;
const VN_HDR: usize = 12;
const VN_RX_BUF: usize = 2048;
const VN_DESC_OFF: u64 = 0x000;
const VN_AVAIL_OFF: u64 = 0x400;
const VN_USED_OFF: u64 = 0x800;

struct VnetModern {
    common: u64,
    notify: u64,
    notify_mult: u32,
    rx_q_phys: u64,
    rx_q_virt: u64,
    tx_q_phys: u64,
    tx_q_virt: u64,
    rx_notify_off: u16,
    tx_notify_off: u16,
    rx_avail_next: u16,
    rx_used_seen: u16,
    tx_avail_next: u16,
    tx_used_seen: u16,
    mac: [u8; 6],
}

fn vn_rd8(v: u64, off: usize) -> u8 {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    let val = unsafe { core::ptr::read_volatile((v + off as u64) as *const u8) };
    fence(Ordering::SeqCst);
    val
}
fn vn_rd16(v: u64, off: usize) -> u16 {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    let val = unsafe { core::ptr::read_volatile((v + off as u64) as *const u16) };
    fence(Ordering::SeqCst);
    val
}
fn vn_rd32(v: u64, off: usize) -> u32 {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    let val = unsafe { core::ptr::read_volatile((v + off as u64) as *const u32) };
    fence(Ordering::SeqCst);
    val
}
fn vn_wr8(v: u64, off: usize, x: u8) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u8, x) };
    fence(Ordering::SeqCst);
}
fn vn_wr16(v: u64, off: usize, x: u16) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u16, x) };
    fence(Ordering::SeqCst);
}
fn vn_wr32(v: u64, off: usize, x: u32) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u32, x) };
    fence(Ordering::SeqCst);
}
fn vn_wr64(v: u64, off: usize, x: u64) {
    use core::sync::atomic::{fence, Ordering};
    fence(Ordering::SeqCst);
    unsafe { core::ptr::write_volatile((v + off as u64) as *mut u64, x) };
    fence(Ordering::SeqCst);
}

/// Find + init the first modern virtio-net (PCI device id 0x1041).
/// Returns None if absent or init fails (caller falls back / reports).
fn vnet_modern_init(dma: u64) -> Option<VnetModern> {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const PCI_COMMAND_MEMORY: u32 = 1 << 1;
    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_NET_MODERN: u16 = 0x1041;

    let mut bus = RealPciBus;
    let mut found: Option<(PciAddress, u64)> = None;
    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress { bus: 0, device, function: 0 };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        if (id & 0xFFFF) as u16 == VIRTIO_VENDOR && (id >> 16) as u16 == VIRTIO_NET_MODERN {
            let bar = match PciImpl::read_bar(&mut bus, addr, 4) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                _ => 0,
            };
            if bar == 0 {
                if let Ok(PciBar::Mmio32(p)) = PciImpl::read_bar(&mut bus, addr, 0) {
                    found = Some((addr, p as u64));
                    break;
                }
                if let Ok(PciBar::Mmio64(p)) = PciImpl::read_bar(&mut bus, addr, 0) {
                    found = Some((addr, p));
                    break;
                }
            } else {
                found = Some((addr, bar));
                break;
            }
        }
        device = device.wrapping_add(1);
    }
    let (addr, bar_phys) = found?;

    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );

    // Walk the PCI capability list for virtio vendor caps (0x09):
    // cfg_type@3, bar@4, offset@8, length@12.
    let status = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    if (status >> 16) & 0x10 == 0 {
        return None; // no cap list
    }
    let mut cap_ptr =
        (PciConfigBus::read_dword(&mut bus, addr, 0x34) & 0xFF) as u8;
    let mut common: Option<(u64, u64)> = None; // (bar, offset)
    let mut notify: Option<(u64, u64)> = None;
    let mut notify_mult: u32 = 0;
    let mut device_cfg: Option<(u64, u64)> = None;
    let mut guard = 0;
    while cap_ptr != 0 && guard < 48 {
        let dw0 = PciConfigBus::read_dword(&mut bus, addr, cap_ptr);
        let cap_id = (dw0 & 0xFF) as u8;
        let next = ((dw0 >> 8) & 0xFF) as u8;
        if cap_id == 0x09 {
            let dw1 = PciConfigBus::read_dword(&mut bus, addr, cap_ptr + 4);
            let cfg_type = ((dw0 >> 24) & 0xFF) as u8;
            let bar_idx = (dw1 & 0xFF) as u8;
            let off = PciConfigBus::read_dword(&mut bus, addr, cap_ptr + 8) as u64;
            let cap_bar = match PciImpl::read_bar(&mut bus, addr, bar_idx) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                _ => 0,
            };
            if cap_bar != 0 {
                match cfg_type {
                    1 => common = Some((cap_bar, off)),
                    2 => {
                        notify = Some((cap_bar, off));
                        notify_mult =
                            PciConfigBus::read_dword(&mut bus, addr, cap_ptr + 16);
                    }
                    4 => device_cfg = Some((cap_bar, off)),
                    _ => {}
                }
            }
        }
        cap_ptr = next;
        guard += 1;
    }
    let (common_bar, common_off) = common?;
    let (notify_bar, notify_off) = notify?;
    let (devcfg_bar, devcfg_off) = device_cfg?;

    let phys_off = unsafe { PHYS_MAP_OFFSET };
    if phys_off == 0 {
        return None;
    }
    unsafe {
        ensure_mmio_page(common_bar + common_off);
        ensure_mmio_page(notify_bar + notify_off);
        ensure_mmio_page(devcfg_bar + devcfg_off);
    }
    let common_virt = phys_off + common_bar + common_off;
    let notify_virt = phys_off + notify_bar + notify_off;
    let devcfg_virt = phys_off + devcfg_bar + devcfg_off;

    // Handshake: RESET → ACK → DRIVER → negotiate VERSION_1 → FEATURES_OK.
    vn_wr8(common_virt, VN_CC_STATUS, 0);
    let mut spins = 0u32;
    while vn_rd8(common_virt, VN_CC_STATUS) != 0 {
        spins += 1;
        if spins > 1_000_000 {
            return None;
        }
        core::hint::spin_loop();
    }
    vn_wr8(common_virt, VN_CC_STATUS, 1);
    vn_wr8(common_virt, VN_CC_STATUS, 3);
    vn_wr32(common_virt, VN_CC_FEATURE_SEL, 1);
    let feat_hi = vn_rd32(common_virt, VN_CC_FEATURE);
    if feat_hi & 0x1 == 0 {
        return None; // no VERSION_1
    }
    vn_wr32(common_virt, VN_CC_FEATURE_SEL, 0);
    let feat_lo = vn_rd32(common_virt, VN_CC_FEATURE);
    // Accept VERSION_1 always, plus MAC (bit 5) and STATUS (bit 16)
    // when offered — matching RustOSa. Without F_MAC the device may
    // drop unicast frames destined for the guest MAC (RX silence).
    let mut acc_lo: u32 = 0;
    if feat_lo & (1 << 5) != 0 {
        acc_lo |= 1 << 5;
    }
    if feat_lo & (1 << 16) != 0 {
        acc_lo |= 1 << 16;
    }
    vn_wr32(common_virt, VN_CC_DRV_FEATURE_SEL, 0);
    vn_wr32(common_virt, VN_CC_DRV_FEATURE, acc_lo);
    vn_wr32(common_virt, VN_CC_DRV_FEATURE_SEL, 1);
    vn_wr32(common_virt, VN_CC_DRV_FEATURE, 1); // VERSION_1
    vn_wr8(common_virt, VN_CC_STATUS, 1 | 2 | 8);
    if vn_rd8(common_virt, VN_CC_STATUS) & 8 == 0 {
        return None;
    }

    let mut mac = [0u8; 6];
    for i in 0..6 {
        mac[i] = vn_rd8(devcfg_virt, i);
    }

    // Queue pages from the DMA window.
    let rx_q_phys = dma;
    let tx_q_phys = dma + 0x1000;
    let rx_bufs_phys = dma + 0x2000;
    let tx_buf_phys = dma + 0xA000;
    unsafe {
        let b = pa_to_va(dma);
        let mut i = 0usize;
        while i < 0xC000 {
            core::ptr::write_volatile(b.add(i), 0);
            i += 1;
        }
    }

    // Program queues.
    vn_wr16(common_virt, VN_CC_QUEUE_SELECT, 0);
    if vn_rd16(common_virt, VN_CC_QUEUE_SIZE) < VN_QSIZE {
        return None;
    }
    vn_wr16(common_virt, VN_CC_QUEUE_SIZE, VN_QSIZE);
    vn_wr64(common_virt, VN_CC_QUEUE_DESC, rx_q_phys + VN_DESC_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DRIVER, rx_q_phys + VN_AVAIL_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DEVICE, rx_q_phys + VN_USED_OFF);
    let rx_notify_off = vn_rd16(common_virt, VN_CC_QUEUE_NOTIFY_OFF);
    vn_wr16(common_virt, VN_CC_QUEUE_ENABLE, 1);

    vn_wr16(common_virt, VN_CC_QUEUE_SELECT, 1);
    if vn_rd16(common_virt, VN_CC_QUEUE_SIZE) < VN_QSIZE {
        return None;
    }
    vn_wr16(common_virt, VN_CC_QUEUE_SIZE, VN_QSIZE);
    vn_wr64(common_virt, VN_CC_QUEUE_DESC, tx_q_phys + VN_DESC_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DRIVER, tx_q_phys + VN_AVAIL_OFF);
    vn_wr64(common_virt, VN_CC_QUEUE_DEVICE, tx_q_phys + VN_USED_OFF);
    let tx_notify_off = vn_rd16(common_virt, VN_CC_QUEUE_NOTIFY_OFF);
    vn_wr16(common_virt, VN_CC_QUEUE_ENABLE, 1);

    // DRIVER_OK.
    vn_wr8(common_virt, VN_CC_STATUS, 1 | 2 | 8 | 4);
    if vn_rd8(common_virt, VN_CC_STATUS) & 128 != 0 {
        return None;
    }

    let rx_q_virt = pa_to_va(rx_q_phys) as u64;
    let tx_q_virt = pa_to_va(tx_q_phys) as u64;
    let rx_bufs_virt = pa_to_va(rx_bufs_phys) as u64;

    // Post VN_RX_BUFFERS RX buffers as 2-desc chains (hdr + payload).
    unsafe {
        core::ptr::write_volatile(
            (rx_q_virt + VN_AVAIL_OFF) as *mut u16,
            0u16, // avail flags
        );
        let mut i = 0usize;
        while i < VN_RX_BUFFERS {
            let hdr_p = rx_bufs_phys + (i as u64) * (VN_RX_BUF as u64);
            let data_p = hdr_p + 0x40;
            let head = (2 * i) as u16;
            // hdr desc (WRITE|NEXT)
            let d0 = rx_q_virt + VN_DESC_OFF + (2 * i as u64) * 16;
            vn_wr64(d0, 0, hdr_p);
            vn_wr32(d0, 8, VN_HDR as u32);
            vn_wr16(d0, 12, 1 | 2);
            vn_wr16(d0, 14, head + 1);
            // payload desc (WRITE)
            let d1 = rx_q_virt + VN_DESC_OFF + ((2 * i + 1) as u64) * 16;
            vn_wr64(d1, 0, data_p);
            vn_wr32(d1, 8, (VN_RX_BUF - 0x40) as u32);
            vn_wr16(d1, 12, 2);
            vn_wr16(d1, 14, 0);
            // avail ring slot i = head
            core::ptr::write_volatile(
                (rx_q_virt + VN_AVAIL_OFF + 4 + (i as u64) * 2) as *mut u16,
                head,
            );
            i += 1;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        core::ptr::write_volatile(
            (rx_q_virt + VN_AVAIL_OFF + 2) as *mut u16,
            VN_RX_BUFFERS as u16,
        );
    }
    let _ = rx_bufs_virt;

    let n = VnetModern {
        common: common_virt,
        notify: notify_virt,
        notify_mult,
        rx_q_phys,
        rx_q_virt,
        tx_q_phys,
        tx_q_virt,
        rx_notify_off,
        tx_notify_off,
        rx_avail_next: VN_RX_BUFFERS as u16,
        rx_used_seen: 0,
        tx_avail_next: 0,
        tx_used_seen: 0,
        mac,
    };
    // Kick RX so the device picks up the posted buffers (RustOSa does
    // this right after pre-posting; without it the device never starts
    // delivering and used stays 0 forever).
    vnet_notify(&n, 0);
    Some(n)
}

fn vnet_notify(n: &VnetModern, queue: u16) {
    let off = (if queue == 0 { n.rx_notify_off } else { n.tx_notify_off } as u64)
        .wrapping_mul(n.notify_mult as u64);
    unsafe {
        core::ptr::write_volatile((n.notify + off) as *mut u16, queue);
    }
}

/// TX one Ethernet frame (2-desc chain, no wait — completion is
/// reaped lazily). Returns false if the ring bookkeeping misbehaves.
fn vnet_tx(n: &mut VnetModern, frame: &[u8]) -> bool {
    use core::sync::atomic::{fence, Ordering};
    let tx_buf_phys = n.tx_q_phys + 0x8000; // tx scratch: dma+0xA000
    let tx_buf_virt = pa_to_va(tx_buf_phys) as u64;
    unsafe {
        // hdr (12 zero bytes) + frame
        let mut i = 0usize;
        while i < VN_HDR {
            core::ptr::write_volatile((tx_buf_virt + i as u64) as *mut u8, 0);
            i += 1;
        }
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            (tx_buf_virt + VN_HDR as u64) as *mut u8,
            frame.len(),
        );
        let d0 = n.tx_q_virt + VN_DESC_OFF;
        vn_wr64(d0, 0, tx_buf_phys);
        vn_wr32(d0, 8, VN_HDR as u32);
        vn_wr16(d0, 12, 1); // NEXT
        vn_wr16(d0, 14, 1);
        let d1 = n.tx_q_virt + VN_DESC_OFF + 16;
        vn_wr64(d1, 0, tx_buf_phys + VN_HDR as u64);
        vn_wr32(d1, 8, frame.len() as u32);
        vn_wr16(d1, 12, 0);
        vn_wr16(d1, 14, 0);
        let slot = (n.tx_avail_next as u64) & (VN_QSIZE as u64 - 1);
        core::ptr::write_volatile(
            (n.tx_q_virt + VN_AVAIL_OFF + 4 + slot * 2) as *mut u16,
            0u16, // head desc 0
        );
        fence(Ordering::SeqCst);
        let next = n.tx_avail_next.wrapping_add(1);
        core::ptr::write_volatile((n.tx_q_virt + VN_AVAIL_OFF + 2) as *mut u16, next);
        n.tx_avail_next = next;
    }
    vnet_notify(n, 1);
    true
}

/// Poll one RX frame into `out`; returns (frame_len, hdr_buf_index) —
/// the caller recycles by calling vnet_rx_recycle(idx).
fn vnet_rx(n: &mut VnetModern, out: &mut [u8]) -> Option<(usize, u16)> {
    let cur = unsafe { core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16) };
    if cur == n.rx_used_seen {
        return None;
    }
    let slot = (n.rx_used_seen as u64) & (VN_QSIZE as u64 - 1);
    let id = unsafe {
        core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 4 + slot * 8) as *const u32)
    } as u16;
    let len = unsafe {
        core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 4 + slot * 8 + 4) as *const u32)
    } as usize;
    n.rx_used_seen = n.rx_used_seen.wrapping_add(1);
    // head desc id → buffer index = id/2. Used len = virtio hdr (12)
    // + payload bytes; the frame lives at buf + 0x40 (hdr region is
    // the first 0x40 bytes of the buffer, payload follows).
    let bi = (id / 2) as u64;
    let data_virt = pa_to_va(n.rx_q_phys + 0x2000 + bi * (VN_RX_BUF as u64) + 0x40);
    let flen = len.saturating_sub(VN_HDR).min(out.len());
    unsafe {
        core::ptr::copy_nonoverlapping(data_virt as *const u8, out.as_mut_ptr(), flen);
    }
    Some((flen, id))
}

/// Repost an RX buffer after consumption.
fn vnet_rx_recycle(n: &mut VnetModern, head_id: u16) {
    use core::sync::atomic::{fence, Ordering};
    unsafe {
        let slot = (n.rx_avail_next as u64) & (VN_QSIZE as u64 - 1);
        core::ptr::write_volatile(
            (n.rx_q_virt + VN_AVAIL_OFF + 4 + slot * 2) as *mut u16,
            head_id,
        );
        fence(Ordering::SeqCst);
        let next = n.rx_avail_next.wrapping_add(1);
        core::ptr::write_volatile((n.rx_q_virt + VN_AVAIL_OFF + 2) as *mut u16, next);
        n.rx_avail_next = next;
    }
    vnet_notify(n, 0);
}


//
// Design: static guest IP 10.0.2.15 on QEMU user-mode networking
// (-netdev user,hostfwd=udp::8080-:8080,hostfwd=tcp::80-:80).
// Polled virtqueue driver on the FIRST virtio-net device found.
// `LivedNet` answers ARP, ICMP echo, UDP/8080 status, and TCP/80
// HTTP GET /status|/healthz|/ with "PROTEUS-STATUS boots=N\n".
// Bounded loop: the service window is a boot-phase activity, then
// the kernel proceeds to HALT as usual.
// ---------------------------------------------------------------------------

/// Boot counter published by banner_continuity for the status payload.
static CONTINUITY_BOOT_COUNT: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

const UDP_SVC_IP: [u8; 4] = [10, 0, 2, 15];
const UDP_SVC_PORT: u16 = 8080;
const UDP_SVC_VIRTIO_HDR: usize = 12;

fn service_udp_status() {
    // Modern driver first (slirp-proven); legacy I/O-port path as
    // fallback (works on hub topology, deaf on user-mode networking).
    let dma = unsafe { DMA_PHYS_BASE };
    if dma != 0 {
        if let Some(mut n) = vnet_modern_init(dma) {
            service_udp_status_modern(&mut n);
            return;
        }
    }
    service_udp_status_legacy();
}

/// Service loop over the modern virtio-net driver.
fn service_udp_status_modern(n: &mut VnetModern) {
    let mac = n.mac;
    let mut svc = target_enterprise::LivedNet::new(mac);
    serial_write_str("UDP SVC UP modern ip=10.0.2.15 port=8080\n");
    serial_write_str("NET SVC UP ip=10.0.2.15 udp=8080 tcp=80 icmp=echo\n");
    {
        // Debug: DMA window base + queue sanity.
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg dma=0x";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        let dma = unsafe { DMA_PHYS_BASE };
        let be = dma.to_be_bytes();
        let mut hx = [0u8; 16];
        hex_encode(&be, 8, &mut hx);
        line[pos..pos + 16].copy_from_slice(&hx);
        pos += 16;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Gratuitous ARP + gateway ARP: register with slirp's bridge.
    let mut garp = [0u8; 42];
    garp[..6].copy_from_slice(&[0xffu8; 6]);
    garp[6..12].copy_from_slice(&mac);
    garp[12] = 0x08;
    garp[13] = 0x06;
    garp[14] = 0;
    garp[15] = 1;
    garp[16] = 0x08;
    garp[17] = 0;
    garp[18] = 6;
    garp[19] = 4;
    garp[20] = 0;
    garp[21] = 1;
    garp[22..28].copy_from_slice(&mac);
    garp[28..32].copy_from_slice(&UDP_SVC_IP);
    garp[32..38].copy_from_slice(&[0u8; 6]);
    garp[38..42].copy_from_slice(&UDP_SVC_IP);
    vnet_tx(n, &garp);
    let mut gw = garp;
    gw[38..42].copy_from_slice(&[10, 0, 2, 2]);
    vnet_tx(n, &gw);
    {
        // Did TX complete? Read TX used idx after a spin.
        let mut spins = 0u32;
        let mut u = 0u16;
        while spins < 20_000_000 {
            u = unsafe {
                core::ptr::read_volatile((n.tx_q_virt + VN_USED_OFF + 2) as *const u16)
            };
            if u != 0 {
                break;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg tx-used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(u as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // RX probe: DNS query to slirp's embedded resolver (10.0.2.3:53).
    // slirp always answers; the answer proves RX delivery independent
    // of hostfwd mapping.
    {
        const DNS_IP: [u8; 4] = [10, 0, 2, 3];
        let mut dns = [0u8; 29];
        dns[0] = 0xc0;
        dns[1] = 0xde;
        dns[2] = 0x01;
        dns[3] = 0x00;
        dns[5] = 0x01;
        dns[12] = 7;
        dns[13..20].copy_from_slice(b"example");
        dns[20] = 3;
        dns[21..24].copy_from_slice(b"com");
        dns[24] = 0;
        dns[26] = 0x01;
        dns[28] = 0x01;
        let dlen = dns.len();
        let udp_len = (8 + dlen) as u16;
        let mut uf = [0u8; 2048];
        uf[0..2].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        uf[2..4].copy_from_slice(&53u16.to_be_bytes());
        uf[4..6].copy_from_slice(&udp_len.to_be_bytes());
        uf[8..8 + dlen].copy_from_slice(&dns);
        let uc = target_enterprise::net::udp_checksum(UDP_SVC_IP, DNS_IP, &uf[..udp_len as usize]);
        uf[6..8].copy_from_slice(&uc.to_be_bytes());
        let ip_len = (20 + udp_len) as u16;
        let mut ip = [0u8; 20];
        ip[0] = 0x45;
        ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
        ip[8] = 64;
        ip[9] = 17;
        ip[12..16].copy_from_slice(&UDP_SVC_IP);
        ip[16..20].copy_from_slice(&DNS_IP);
        let ic = target_enterprise::net::ipv4_header_checksum(&ip);
        ip[10..12].copy_from_slice(&ic.to_be_bytes());
        let el = 14 + ip_len as usize;
        let mut eth = [0u8; 2048];
        eth[..6].copy_from_slice(&[0x52, 0x55, 0x0a, 0x00, 0x02, 0x03]);
        eth[6..12].copy_from_slice(&mac);
        eth[12] = 0x08;
        eth[13] = 0x00;
        eth[14..34].copy_from_slice(&ip);
        eth[34..el].copy_from_slice(&uf[..udp_len as usize]);
        vnet_tx(n, &eth[..el]);
    }

    // Watch RX used for the DNS answer (bounded).
    {
        let mut spins = 0u32;
        let mut rxu = 0u16;
        while spins < 40_000_000 {
            rxu = unsafe {
                core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16)
            };
            if rxu != 0 {
                break;
            }
            spins += 1;
            core::hint::spin_loop();
        }
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg dns-rx-used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(rxu as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 2;
    let mut idle: u64 = 0;
    let mut frame = [0u8; 2048];

    {
        // One-shot: state at loop entry.
        let cur0 = unsafe {
            core::ptr::read_volatile((n.rx_q_virt + VN_USED_OFF + 2) as *const u16)
        };
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let pre = b"UDP SVC dbg loop-enter used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(cur0 as u64, &mut line[pos..]);
        let mid = b" seen=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64_to_buf(n.rx_used_seen as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    loop {
        let Some((flen, head_id)) = vnet_rx(n, &mut frame) else {
            idle += 1;
            let max_idle: u64 = if rx_count == 0 { 2_000_000 } else { 200_000_000 };
            if idle > max_idle {
                break;
            }
            core::hint::spin_loop();
            continue;
        };
        idle = 0;
        rx_count += 1;
        {
            // Debug every consumed frame: len + etype + dst port.
            let mut line = [0u8; 80];
            let mut pos = 0usize;
            let pre = b"UDP SVC got flen=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(flen as u64, &mut line[pos..]);
            if flen >= 14 {
                let et = u16::from_be_bytes([frame[12], frame[13]]);
                let mid = b" etype=0x";
                line[pos..pos + mid.len()].copy_from_slice(mid);
                pos += mid.len();
                let be = et.to_be_bytes();
                let mut hx = [0u8; 4];
                hex_encode(&be, 2, &mut hx);
                line[pos..pos + 4].copy_from_slice(&hx);
                pos += 4;
            }
            if flen >= 36 && u16::from_be_bytes([frame[12], frame[13]]) == 0x0800 {
                let ihl2 = ((frame[14] & 0x0F) as usize) * 4;
                let dport = u16::from_be_bytes([frame[14 + ihl2 + 2], frame[14 + ihl2 + 3]]);
                let mid2 = b" dport=";
                line[pos..pos + mid2.len()].copy_from_slice(mid2);
                pos += mid2.len();
                pos += dec_u64_to_buf(dport as u64, &mut line[pos..]);
                let sport = u16::from_be_bytes([frame[14 + ihl2], frame[14 + ihl2 + 1]]);
                let mid3 = b" sport=";
                line[pos..pos + mid3.len()].copy_from_slice(mid3);
                pos += mid3.len();
                pos += dec_u64_to_buf(sport as u64, &mut line[pos..]);
            }
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
        if flen < 14 {
            vnet_rx_recycle(n, head_id);
            continue;
        }

        let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
        let mut replies = target_enterprise::ReplySet::new();
        let sh: &'static mut target_enterprise::OsShell =
            unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_SHELL) };
        if sh.fs.inode_count() == 0 {
            sh.seed_defaults();
            let _ = restore_shell_from_ahci(sh);
        }
        svc.handle_frame_with_shell(&frame[..flen], boots, sh, &mut replies);
        let mut ri = 0usize;
        while ri < replies.len() {
            if let Some(r) = replies.get(ri) {
                vnet_tx(n, r);
                tx_count += 1;
            }
            ri += 1;
        }
        if replies.len() != 0 {
            let mut line = [0u8; 64];
            let mut pos = 0usize;
            let pre = b"NET SVC rx=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(rx_count, &mut line[pos..]);
            let mid = b" tx=";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            pos += dec_u64_to_buf(tx_count, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
        vnet_rx_recycle(n, head_id);
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let pre = b"UDP SVC DOWN window-closed rx=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(rx_count, &mut line[pos..]);
        let mid = b" tx=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64_to_buf(tx_count, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Legacy I/O-port path (hub topology only — kept as fallback).
fn service_udp_status_legacy() {
    use core::sync::atomic::{fence, Ordering};
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::pci::PciImpl;

    const VIRTIO_VENDOR: u16 = 0x1AF4;
    const VIRTIO_NET_TRANSITIONAL: u16 = 0x1000;
    const VIRTIO_NET_MODERN: u16 = 0x1041;
    const PCI_COMMAND_IO: u32 = 1;
    const VIRTIO_PCI_STATUS: u16 = 18;
    const VIRTIO_PCI_CONFIG: u16 = 20;
    const Q_RX: u16 = 0;
    const Q_TX: u16 = 1;
    const N_RX_BUFS: u16 = 8;
    const RX_BUF_LEN: u32 = 2048;

    // --- PCI: first virtio-net device ---
    let mut bus = RealPciBus;
    let mut io: Option<(u16, [u8; 6])> = None;
    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress { bus: 0, device, function: 0 };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == VIRTIO_VENDOR
            && (dev_id == VIRTIO_NET_TRANSITIONAL || dev_id == VIRTIO_NET_MODERN)
        {
            if let Ok(PciBar::Io(p)) = PciImpl::read_bar(&mut bus, addr, 0) {
                let base = p as u16;
                let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
                PciConfigBus::write_dword(
                    &mut bus,
                    addr,
                    PCI_CFG_OFFSET_COMMAND_STATUS,
                    cmd | PCI_COMMAND_IO | PCI_COMMAND_BUS_MASTER,
                );
                let mut mac = [0u8; 6];
                unsafe {
                    outb(base + VIRTIO_PCI_STATUS, 0);
                    outb(base + VIRTIO_PCI_STATUS, 1);
                    outb(base + VIRTIO_PCI_STATUS, 3);
                    let mut i = 0;
                    while i < 6 {
                        mac[i] = inb(base + VIRTIO_PCI_CONFIG + i as u16);
                        i += 1;
                    }
                }
                io = Some((base, mac));
                break;
            }
        }
        device = device.wrapping_add(1);
    }
    let Some((base, mac)) = io else {
        serial_write_str("UDP SVC DOWN no-virtio-net\n");
        return;
    };

    if unsafe { PHYS_MAP_OFFSET } == 0 || unsafe { DMA_PHYS_BASE } == 0 {
        serial_write_str("UDP SVC DOWN dma-missing\n");
        return;
    }
    let dma = unsafe { DMA_PHYS_BASE };
    let rx_q_pa = dma;
    let tx_q_pa = dma + 0x3000;
    let rx_bufs_pa = dma + 0x6000;
    let tx_buf_pa = dma + 0xA000;

    let avail_off = (VQ_SIZE as u64) * 16;
    let used_off = {
        let raw = avail_off + 4 + 2 * (VQ_SIZE as u64);
        (raw + VQ_ALIGN - 1) & !(VQ_ALIGN - 1)
    };

    // Zero queue window.
    unsafe {
        let b = pa_to_va(dma);
        let mut i = 0usize;
        while i < 0xC000 {
            core::ptr::write_volatile(b.add(i), 0);
            i += 1;
        }
        // Device setup: reset, ack, driver, features-none.
        outb(base + VIRTIO_PCI_STATUS, 0);
        outb(base + VIRTIO_PCI_STATUS, 1);
        outb(base + VIRTIO_PCI_STATUS, 3);
        outl(base + 4, 0);
        // RX queue with buffers posted.
        outw(base + 14, Q_RX);
        if inw(base + 12) != VQ_SIZE {
            serial_write_str("UDP SVC DOWN rx-qsz\n");
            return;
        }
        outl(base + 8, (rx_q_pa >> 12) as u32);
        outw(base + 14, Q_TX);
        if inw(base + 12) != VQ_SIZE {
            serial_write_str("UDP SVC DOWN tx-qsz\n");
            return;
        }
        outl(base + 8, (tx_q_pa >> 12) as u32);
    }

    let rx_q = pa_to_va(rx_q_pa);
    let tx_q = pa_to_va(tx_q_pa);
    // Post N_RX_BUFS device-writable RX descriptors.
    let mut i: u16 = 0;
    while i < N_RX_BUFS {
        write_desc_phys(rx_q, i as u64, rx_bufs_pa + (i as u64) * (RX_BUF_LEN as u64), RX_BUF_LEN, 2, 0);
        unsafe {
            core::ptr::write_volatile(rx_q.add(avail_off as usize + 4 + (i as usize) * 2), i as u8);
            core::ptr::write_volatile(
                rx_q.add(avail_off as usize + 4 + (i as usize) * 2 + 1),
                (i >> 8) as u8,
            );
        }
        i += 1;
    }
    unsafe {
        // avail.idx = N_RX_BUFS
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 2), N_RX_BUFS as u8);
        core::ptr::write_volatile(rx_q.add(avail_off as usize + 3), (N_RX_BUFS >> 8) as u8);
    }
    fence(Ordering::SeqCst);
    unsafe {
        outb(base + VIRTIO_PCI_STATUS, 1 | 2 | 4); // DRIVER_OK
        outw(base + 16, Q_RX);
    }

    // Gratuitous ARP FIRST: QEMU user-mode networking (slirp) is a
    // learning bridge — until the guest transmits, slirp does not know
    // its MAC and drops inbound frames. Announce ourselves so hostfwd
    // traffic can flow (learned from RustOSa's bring-up).
    let mut rx_used_last: u16 = 0;
    let mut tx_avail_idx: u16 = 0;
    let mut tx_used_last: u16 = 0;
    let mut rx_count: u64 = 0;
    let mut tx_count: u64 = 0;
    let mut idle: u64 = 0;
    {
        let mut garp = [0u8; 42];
        let bcast = [0xffu8; 6];
        garp[..6].copy_from_slice(&bcast);
        garp[6..12].copy_from_slice(&mac);
        garp[12] = 0x08;
        garp[13] = 0x06;
        garp[14] = 0;
        garp[15] = 1; // htype eth
        garp[16] = 0x08;
        garp[17] = 0; // ptype ipv4
        garp[18] = 6;
        garp[19] = 4; // hlen/plen
        garp[20] = 0;
        garp[21] = 1; // request
        garp[22..28].copy_from_slice(&mac);
        garp[28..32].copy_from_slice(&UDP_SVC_IP);
        garp[32..38].copy_from_slice(&[0u8; 6]);
        garp[38..42].copy_from_slice(&UDP_SVC_IP);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &garp);
        tx_count += 1;
        // Did the gratuitous ARP actually complete on the device?
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC garp-tx-used=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        pos += dec_u64_to_buf(tx_used_last as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);

        // Direction probe: TX a UDP datagram to the slirp gateway
        // (10.0.2.2:8080 = the host). If the host receives this, the
        // guest→host path is proven; RX silence then isolates to
        // slirp→guest delivery.
        const GW_IP: [u8; 4] = [10, 0, 2, 2];
        const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
        let payload = b"PROTEUS-HELLO\n";
        let plen = payload.len();
        let udp_len = (8 + plen) as u16;
        let mut udp_full = [0u8; 2048];
        udp_full[0..2].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        udp_full[2..4].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        udp_full[4..6].copy_from_slice(&udp_len.to_be_bytes());
        udp_full[8..8 + plen].copy_from_slice(payload);
        let uc = target_enterprise::net::udp_checksum(
            UDP_SVC_IP,
            GW_IP,
            &udp_full[..udp_len as usize],
        );
        udp_full[6..8].copy_from_slice(&uc.to_be_bytes());
        let ip_len = (20 + udp_len) as u16;
        let mut out_ip = [0u8; 20];
        out_ip[0] = 0x45;
        out_ip[2..4].copy_from_slice(&ip_len.to_be_bytes());
        out_ip[8] = 64;
        out_ip[9] = 17;
        out_ip[12..16].copy_from_slice(&UDP_SVC_IP);
        out_ip[16..20].copy_from_slice(&GW_IP);
        let ic = target_enterprise::net::ipv4_header_checksum(&out_ip);
        out_ip[10..12].copy_from_slice(&ic.to_be_bytes());
        let eth_len = 14 + ip_len as usize;
        let mut eth = [0u8; 2048];
        eth[..6].copy_from_slice(&GW_MAC);
        eth[6..12].copy_from_slice(&mac);
        eth[12] = 0x08;
        eth[13] = 0x00;
        eth[14..34].copy_from_slice(&out_ip);
        eth[34..eth_len].copy_from_slice(&udp_full[..udp_len as usize]);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &eth[..eth_len]);
        tx_count += 1;

        // ARP request for the GATEWAY (10.0.2.2): slirp's neighbor
        // table is populated by ARP *replies* — the gratuitous announce
        // may not be enough. Asking forces slirp to answer and to mark
        // us reachable, which is what hostfwd delivery keys on.
        let mut gw_arp = [0u8; 42];
        let bcast2 = [0xffu8; 6];
        gw_arp[..6].copy_from_slice(&bcast2);
        gw_arp[6..12].copy_from_slice(&mac);
        gw_arp[12] = 0x08;
        gw_arp[13] = 0x06;
        gw_arp[14] = 0;
        gw_arp[15] = 1;
        gw_arp[16] = 0x08;
        gw_arp[17] = 0;
        gw_arp[18] = 6;
        gw_arp[19] = 4;
        gw_arp[20] = 0;
        gw_arp[21] = 1; // request
        gw_arp[22..28].copy_from_slice(&mac);
        gw_arp[28..32].copy_from_slice(&UDP_SVC_IP);
        gw_arp[32..38].copy_from_slice(&[0u8; 6]);
        gw_arp[38..42].copy_from_slice(&GW_IP);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &gw_arp);
        tx_count += 1;

        // RX probe: real DNS query to slirp's embedded resolver
        // (10.0.2.3:53). slirp MUST answer — and the answer is a unicast
        // frame back to us. If `used` advances, virtio RX works and the
        // problem is hostfwd mapping; if not, RX is dead at QEMU level.
        const DNS_IP: [u8; 4] = [10, 0, 2, 3];
        let mut dns = [0u8; 29];
        dns[0] = 0xc0;
        dns[1] = 0xde; // id
        dns[2] = 0x01;
        dns[3] = 0x00; // RD
        dns[5] = 0x01; // qdcount=1
        // qname: 7 example 3 com 0
        dns[12] = 7;
        dns[13..20].copy_from_slice(b"example");
        dns[20] = 3;
        dns[21..24].copy_from_slice(b"com");
        dns[24] = 0;
        dns[26] = 0x01; // qtype A (bytes 25-26 BE: 0x0001)
        dns[28] = 0x01; // qclass IN (bytes 27-28 BE: 0x0001)
        let dlen = dns.len();
        let udp_len2 = (8 + dlen) as u16;
        let mut uf2 = [0u8; 2048];
        uf2[0..2].copy_from_slice(&UDP_SVC_PORT.to_be_bytes());
        uf2[2..4].copy_from_slice(&53u16.to_be_bytes());
        uf2[4..6].copy_from_slice(&udp_len2.to_be_bytes());
        uf2[8..8 + dlen].copy_from_slice(&dns);
        let uc2 = target_enterprise::net::udp_checksum(UDP_SVC_IP, DNS_IP, &uf2[..udp_len2 as usize]);
        uf2[6..8].copy_from_slice(&uc2.to_be_bytes());
        let ip_len2 = (20 + udp_len2) as u16;
        let mut ip2 = [0u8; 20];
        ip2[0] = 0x45;
        ip2[2..4].copy_from_slice(&ip_len2.to_be_bytes());
        ip2[8] = 64;
        ip2[9] = 17;
        ip2[12..16].copy_from_slice(&UDP_SVC_IP);
        ip2[16..20].copy_from_slice(&DNS_IP);
        let ic2 = target_enterprise::net::ipv4_header_checksum(&ip2);
        ip2[10..12].copy_from_slice(&ic2.to_be_bytes());
        let el2 = 14 + ip_len2 as usize;
        let mut eth2 = [0u8; 2048];
        eth2[..6].copy_from_slice(&GW_MAC);
        eth2[6..12].copy_from_slice(&mac);
        eth2[12] = 0x08;
        eth2[13] = 0x00;
        eth2[14..34].copy_from_slice(&ip2);
        eth2[34..el2].copy_from_slice(&uf2[..udp_len2 as usize]);
        udp_svc_tx(base, tx_q, tx_buf_pa, avail_off, used_off, &mut tx_avail_idx, &mut tx_used_last, &eth2[..el2]);
        tx_count += 1;
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"UDP SVC UP ip=10.0.2.15 port=8080\n";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let _ = line;
        let _ = pos;
        serial_write_str("UDP SVC UP ip=10.0.2.15 port=8080\n");
        serial_write_str("NET SVC UP ip=10.0.2.15 udp=8080 tcp=80 icmp=echo\n");
    }

    let mut svc = target_enterprise::LivedNet::new(mac);

    // Bounded service window.
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let pre = b"UDP SVC loop-enter used0=";
        line[..pre.len()].copy_from_slice(pre);
        pos += pre.len();
        let u0 = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        pos += dec_u64_to_buf(u0 as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    loop {
        fence(Ordering::SeqCst);
        let rx_used = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if rx_used == rx_used_last {
            idle += 1;
            if idle % 500_000_000 == 0 {
                // Heartbeat debug: prove the poll loop is alive and
                // report the raw used index (frame-arrival signal).
                let mut line = [0u8; 48];
                let mut pos = 0usize;
                let pre = b"UDP SVC poll used=";
                line[..pre.len()].copy_from_slice(pre);
                pos += pre.len();
                pos += dec_u64_to_buf(rx_used as u64, &mut line[pos..]);
                line[pos] = b'\n';
                pos += 1;
                serial_write_bytes(&line[..pos]);
            }
            let max_idle: u64 = if rx_count == 0 { 2_000_000 } else { 200_000_000 };
            if idle > max_idle {
                break;
            }
            core::hint::spin_loop();
            continue;
        }
        idle = 0;
        // Consume one used RX element (ring slot = idx % VQ_SIZE; id
        // field at used_off+4+8*slot).
        let slot = (rx_used_last % VQ_SIZE) as usize;
        let desc_id = unsafe {
            let b0 = core::ptr::read_volatile(rx_q.add(used_off as usize + 4 + slot * 8));
            let b1 = core::ptr::read_volatile(rx_q.add(used_off as usize + 5 + slot * 8));
            u16::from_le_bytes([b0, b1])
        };
        rx_used_last = rx_used_last.wrapping_add(1);

        // Read the frame.
        let buf_pa = rx_bufs_pa + (desc_id as u64) * (RX_BUF_LEN as u64);
        let mut frame = [0u8; 2048];
        unsafe {
            let p = pa_to_va(buf_pa + UDP_SVC_VIRTIO_HDR as u64);
            core::ptr::copy_nonoverlapping(p, frame.as_mut_ptr(), 1536);
        }

        // Repost the buffer immediately.
        write_desc_phys(rx_q, desc_id as u64, buf_pa, RX_BUF_LEN, 2, 0);
        fence(Ordering::SeqCst);
        unsafe {
            let idx_pos = avail_off as usize + 2;
            let cur = u16::from_le_bytes([
                core::ptr::read_volatile(rx_q.add(idx_pos)),
                core::ptr::read_volatile(rx_q.add(idx_pos + 1)),
            ]);
            let apos = avail_off as usize + 4 + (cur as usize % VQ_SIZE as usize) * 2;
            core::ptr::write_volatile(rx_q.add(apos), desc_id as u8);
            core::ptr::write_volatile(rx_q.add(apos + 1), (desc_id >> 8) as u8);
            fence(Ordering::SeqCst);
            core::ptr::write_volatile(rx_q.add(idx_pos), cur.wrapping_add(1) as u8);
            core::ptr::write_volatile(rx_q.add(idx_pos + 1), (cur.wrapping_add(1) >> 8) as u8);
            outw(base + 16, Q_RX);
        }

        rx_count += 1;

        // Debug: every consumed frame gets a line (first bytes + etype).
        {
            let mut line = [0u8; 64];
            let mut pos = 0usize;
            let pre = b"UDP SVC frame id=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(desc_id as u64, &mut line[pos..]);
            let mid = b" etype=";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            let mut hx = [0u8; 4];
            hex_encode(&[frame[12], frame[13]], 2, &mut hx);
            line[pos..pos + 4].copy_from_slice(&hx);
            pos += 4;
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }

        let boots = CONTINUITY_BOOT_COUNT.load(Ordering::Relaxed);
        let mut replies = target_enterprise::ReplySet::new();
        let sh: &'static mut target_enterprise::OsShell =
            unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_SHELL) };
        if sh.fs.inode_count() == 0 {
            sh.seed_defaults();
            let _ = restore_shell_from_ahci(sh);
        }
        // Legacy RX copies 1536 bytes; LivedNet uses IPv4 total_length.
        svc.handle_frame_with_shell(&frame[..1536.min(frame.len())], boots, sh, &mut replies);
        let mut ri = 0usize;
        while ri < replies.len() {
            if let Some(r) = replies.get(ri) {
                udp_svc_tx(
                    base,
                    tx_q,
                    tx_buf_pa,
                    avail_off,
                    used_off,
                    &mut tx_avail_idx,
                    &mut tx_used_last,
                    r,
                );
                tx_count += 1;
            }
            ri += 1;
        }
        if replies.len() != 0 {
            let mut line = [0u8; 64];
            let mut pos = 0usize;
            let pre = b"NET SVC rx=";
            line[..pre.len()].copy_from_slice(pre);
            pos += pre.len();
            pos += dec_u64_to_buf(rx_count, &mut line[pos..]);
            let mid = b" tx=";
            line[pos..pos + mid.len()].copy_from_slice(mid);
            pos += mid.len();
            pos += dec_u64_to_buf(tx_count, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
        }
    }

    serial_write_str("UDP SVC DOWN window-closed\n");
}

/// Transmit one Ethernet frame via the TX virtqueue (virtio_net_hdr
/// prepended). Waits for TX completion before returning (bounded).
fn udp_svc_tx(
    base: u16,
    tx_q: *mut u8,
    tx_buf_pa: u64,
    avail_off: u64,
    used_off: u64,
    avail_idx: &mut u16,
    used_last: &mut u16,
    frame: &[u8],
) {
    use core::sync::atomic::{fence, Ordering};
    let total = (UDP_SVC_VIRTIO_HDR + frame.len()) as u32;
    unsafe {
        // virtio_net_hdr (12 zero bytes) + frame.
        let p = pa_to_va(tx_buf_pa);
        let mut i = 0usize;
        while i < UDP_SVC_VIRTIO_HDR {
            core::ptr::write_volatile(p.add(i), 0);
            i += 1;
        }
        core::ptr::copy_nonoverlapping(
            frame.as_ptr(),
            p.add(UDP_SVC_VIRTIO_HDR),
            frame.len(),
        );
    }
    let slot = *avail_idx % VQ_SIZE;
    write_desc_phys(tx_q, slot as u64, tx_buf_pa, total, 0, 0);
    fence(Ordering::SeqCst);
    unsafe {
        let apos = avail_off as usize + 4 + (slot as usize) * 2;
        core::ptr::write_volatile(tx_q.add(apos), slot as u8);
        core::ptr::write_volatile(tx_q.add(apos + 1), (slot >> 8) as u8);
        fence(Ordering::SeqCst);
        let next = avail_idx.wrapping_add(1);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 2), next as u8);
        core::ptr::write_volatile(tx_q.add(avail_off as usize + 3), (next >> 8) as u8);
        outw(base + 16, Q_TX_KICK);
    }
    *avail_idx = avail_idx.wrapping_add(1);
    // Wait completion (bounded).
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        let u = unsafe {
            let b0 = core::ptr::read_volatile(tx_q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(tx_q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if u != *used_last {
            *used_last = u;
            break;
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            return; // drop; service loop stays alive
        }
        core::hint::spin_loop();
    }
}

const Q_TX_KICK: u16 = 1;

/// Decimal u64 into buf, returns bytes written (service-local variant
/// of dec_u64 for the payload builder).
fn dec_u64_to_buf(mut v: u64, out: &mut [u8]) -> usize {
    if v == 0 {
        out[0] = b'0';
        return 1;
    }
    let mut tmp = [0u8; 20];
    let mut n = 0usize;
    while v > 0 {
        tmp[n] = b'0' + (v % 10) as u8;
        v /= 10;
        n += 1;
    }
    let mut i = 0usize;
    while i < n {
        out[i] = tmp[n - 1 - i];
        i += 1;
    }
    n
}


// Not MemMmioBus — 0xCF8/0xCFC + ABAR-style uncached MMIO map.
// ---------------------------------------------------------------------------

/// Banner: `E1000_HW probe OK slot=N mac=…` then `E1000_HW tx OK bytes=64`
/// (TASK-116 probe + TASK-120 real TX descriptor ring + DD completion).
#[cfg(not(proteus_prod))]
fn banner_e1000_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_COMMAND_STATUS,
        PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER, E1000_CTRL_RST,
        E1000_CTRL_SLU, E1000_DESC_STA_DD, E1000_EEPROM_MAC_WORD0,
        E1000_EEPROM_MAC_WORD1, E1000_EEPROM_MAC_WORD2, E1000_EERD_ADDR_MASK,
        E1000_EERD_ADDR_SHIFT, E1000_EERD_DATA_MASK, E1000_EERD_DATA_SHIFT,
        E1000_EERD_DONE, E1000_EERD_START, E1000_REG_CTRL, E1000_REG_EERD,
        E1000_REG_IMC, E1000_REG_STATUS, E1000_REG_TCTL, E1000_REG_TDBAH,
        E1000_REG_TDBAL, E1000_REG_TDH, E1000_REG_TDLEN, E1000_REG_TDT,
        E1000_REG_TIPG, E1000_TCTL_EN, E1000_TCTL_PSP, E1000_TX_DESC_LEN,
        E1000_TXD_CMD_EOP, E1000_TXD_CMD_IFCS, E1000_TXD_CMD_RS,
    };
    use target_enterprise::e1000::TxDesc;
    use target_enterprise::pci::PciImpl;

    const PCI_COMMAND_MEMORY: u32 = 1 << 1;
    const INTEL_VENDOR: u16 = 0x8086;
    // QEMU default e1000 = 82540EM; also accept common variants.
    const DEV_82540EM: u16 = 0x100E;
    const DEV_82545EM: u16 = 0x100F;
    const DEV_82574L: u16 = 0x10D3;

    if unsafe { PHYS_MAP_OFFSET } == 0 || unsafe { DMA_PHYS_BASE } == 0 {
        panic!("E1000_HW: phys map missing");
    }

    let mut bus = RealPciBus;
    let mut found_slot: Option<u8> = None;
    let mut found_addr: Option<PciAddress> = None;
    let mut bar0: u64 = 0;

    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == INTEL_VENDOR
            && (dev_id == DEV_82540EM || dev_id == DEV_82545EM || dev_id == DEV_82574L)
        {
            let bar = match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                Ok(PciBar::Io(_)) | Err(_) => 0,
            };
            if bar != 0 {
                found_slot = Some(device);
                found_addr = Some(addr);
                bar0 = bar;
                break;
            }
        }
        device = device.wrapping_add(1);
    }

    let slot = match found_slot {
        Some(s) => s,
        None => panic!("E1000_HW: no e1000 on bus 0 (attach -device e1000)"),
    };
    let addr = match found_addr {
        Some(a) => a,
        None => panic!("E1000_HW: missing addr"),
    };

    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );

    // Soft reset + mask IRQs (same sequence as E1000Impl::reset).
    unsafe {
        mmio_write32(bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        let ctrl = mmio_read32(bar0 + E1000_REG_CTRL as u64);
        if ctrl == 0xFFFF_FFFF {
            panic!("E1000_HW: CTRL MMIO fault");
        }
        mmio_write32(bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_RST);
        let mut spins = 0u32;
        loop {
            let c = mmio_read32(bar0 + E1000_REG_CTRL as u64);
            if c & E1000_CTRL_RST == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 20_000_000 {
                panic!("E1000_HW: reset timeout");
            }
            core::hint::spin_loop();
        }
        mmio_write32(bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        // STATUS must be readable (non-fault).
        let st = mmio_read32(bar0 + E1000_REG_STATUS as u64);
        if st == 0xFFFF_FFFF {
            panic!("E1000_HW: STATUS MMIO fault");
        }
    }

    // EEPROM MAC words 0..2 via EERD (82540EM layout; QEMU default).
    let read_eerd = |word: u8| -> u16 {
        let cmd = E1000_EERD_START | ((word as u32 & E1000_EERD_ADDR_MASK) << E1000_EERD_ADDR_SHIFT);
        unsafe {
            mmio_write32(bar0 + E1000_REG_EERD as u64, cmd);
            let mut spins = 0u32;
            loop {
                let v = mmio_read32(bar0 + E1000_REG_EERD as u64);
                if v & E1000_EERD_DONE != 0 {
                    return ((v >> E1000_EERD_DATA_SHIFT) & E1000_EERD_DATA_MASK) as u16;
                }
                spins = spins.wrapping_add(1);
                if spins > 20_000_000 {
                    panic!("E1000_HW: EEPROM poll timeout");
                }
                core::hint::spin_loop();
            }
        }
    };
    let w0 = read_eerd(E1000_EEPROM_MAC_WORD0);
    let w1 = read_eerd(E1000_EEPROM_MAC_WORD1);
    let w2 = read_eerd(E1000_EEPROM_MAC_WORD2);
    let mac = [
        (w0 & 0xFF) as u8,
        ((w0 >> 8) & 0xFF) as u8,
        (w1 & 0xFF) as u8,
        ((w1 >> 8) & 0xFF) as u8,
        (w2 & 0xFF) as u8,
        ((w2 >> 8) & 0xFF) as u8,
    ];
    if mac == [0u8; 6] || mac == [0xFFu8; 6] {
        panic!("E1000_HW: invalid EEPROM MAC");
    }
    // Multicast bit must be clear on burned-in unicast MAC.
    if mac[0] & 1 != 0 {
        panic!("E1000_HW: MAC multicast bit set");
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"E1000_HW probe OK slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(slot as u64, &mut line[pos..]);
        let mid = b" mac=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let mut hex = [0u8; 12];
        hex_encode(&mac, 6, &mut hex);
        line[pos..pos + 12].copy_from_slice(&hex);
        pos += 12;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // TASK-120: real TX ring in DMA window (not stack identity phys).
    // Layout: [0] 16-byte legacy desc, [0x40] 64-byte eth frame.
    const E1000_TX_RING_PHYS_OFF: u64 = 0x2_0000;
    const E1000_TX_BUF_PHYS_OFF: u64 = 0x2_0040;
    const TX_FRAME_LEN: u16 = 64;
    let tx_ring_phys = unsafe { DMA_PHYS_BASE } + E1000_TX_RING_PHYS_OFF;
    let tx_buf_phys = unsafe { DMA_PHYS_BASE } + E1000_TX_BUF_PHYS_OFF;
    let ring_va = unsafe { pa_to_va(tx_ring_phys) };
    let buf_va = unsafe { pa_to_va(tx_buf_phys) };

    // Minimal Ethernet: dst ff:ff:ff:ff:ff:ff, src = EEPROM MAC, ethertype 0x0800, zeros.
    unsafe {
        let mut i = 0usize;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(i), 0xFF);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(6 + i), mac[i]);
            i += 1;
        }
        core::ptr::write_volatile(buf_va.add(12), 0x08);
        core::ptr::write_volatile(buf_va.add(13), 0x00);
        i = 14;
        while i < TX_FRAME_LEN as usize {
            core::ptr::write_volatile(buf_va.add(i), (i as u8).wrapping_mul(0x11));
            i += 1;
        }
    }

    let desc = TxDesc {
        addr: tx_buf_phys,
        length: TX_FRAME_LEN,
        cso: 0,
        cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
        sta: 0, // device sets DD
        css: 0,
        special: 0,
    };
    let enc = desc.encode();
    unsafe {
        let mut i = 0usize;
        while i < E1000_TX_DESC_LEN {
            core::ptr::write_volatile(ring_va.add(i), enc[i]);
            i += 1;
        }
        // Zero remaining ring slots not used.
        i = E1000_TX_DESC_LEN;
        while i < 16 * E1000_TX_DESC_LEN {
            core::ptr::write_volatile(ring_va.add(i), 0);
            i += 1;
        }
    }

    unsafe {
        // Link up + TX ring program (Intel 82540EM / QEMU).
        let ctrl = mmio_read32(bar0 + E1000_REG_CTRL as u64);
        mmio_write32(bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_SLU);
        mmio_write32(bar0 + E1000_REG_TDBAL as u64, tx_ring_phys as u32);
        mmio_write32(bar0 + E1000_REG_TDBAH as u64, (tx_ring_phys >> 32) as u32);
        mmio_write32(
            bar0 + E1000_REG_TDLEN as u64,
            (16 * E1000_TX_DESC_LEN) as u32,
        );
        mmio_write32(bar0 + E1000_REG_TDH as u64, 0);
        mmio_write32(bar0 + E1000_REG_TDT as u64, 0);
        // TIPG default IPG for copper (QEMU accepts common 0x0060200A).
        mmio_write32(bar0 + E1000_REG_TIPG as u64, 0x0060_200A);
        mmio_write32(
            bar0 + E1000_REG_TCTL as u64,
            E1000_TCTL_EN | E1000_TCTL_PSP | (0x0F << 4) | (0x40 << 12),
        );
        // Hand one descriptor to the device.
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        mmio_write32(bar0 + E1000_REG_TDT as u64, 1);

        let mut spins = 0u32;
        loop {
            let sta = core::ptr::read_volatile(ring_va.add(12));
            if sta & E1000_DESC_STA_DD != 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("E1000_HW: TX DD timeout");
            }
            core::hint::spin_loop();
        }
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"E1000_HW tx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(TX_FRAME_LEN as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // TASK-132: dual e1000 on hubid=2 — TX peer → RX peer magic frame.
    // Find a second e1000 (different slot) for RX.
    let mut rx_slot: Option<u8> = None;
    let mut rx_addr: Option<PciAddress> = None;
    let mut rx_bar0: u64 = 0;
    let mut device: u8 = 0;
    while device < 32 {
        if device == slot {
            device = device.wrapping_add(1);
            continue;
        }
        let a = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, a, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == INTEL_VENDOR
            && (dev_id == DEV_82540EM || dev_id == DEV_82545EM || dev_id == DEV_82574L)
        {
            let bar = match PciImpl::read_bar(&mut bus, a, 0) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                Ok(PciBar::Io(_)) | Err(_) => 0,
            };
            if bar != 0 {
                rx_slot = Some(device);
                rx_addr = Some(a);
                rx_bar0 = bar;
                break;
            }
        }
        device = device.wrapping_add(1);
    }
    let rx_slot = match rx_slot {
        Some(s) => s,
        None => panic!("E1000_HW: need 2nd e1000 for RX (dual hubport)"),
    };
    let rx_addr = match rx_addr {
        Some(a) => a,
        None => panic!("E1000_HW: rx addr missing"),
    };
    let cmd = PciConfigBus::read_dword(&mut bus, rx_addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        rx_addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );
    unsafe {
        mmio_write32(rx_bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        let ctrl = mmio_read32(rx_bar0 + E1000_REG_CTRL as u64);
        mmio_write32(rx_bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_RST);
        let mut spins = 0u32;
        loop {
            let c = mmio_read32(rx_bar0 + E1000_REG_CTRL as u64);
            if c & E1000_CTRL_RST == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 20_000_000 {
                panic!("E1000_HW: RX reset timeout");
            }
            core::hint::spin_loop();
        }
        mmio_write32(rx_bar0 + E1000_REG_IMC as u64, 0xFFFF_FFFF);
        let ctrl = mmio_read32(rx_bar0 + E1000_REG_CTRL as u64);
        mmio_write32(rx_bar0 + E1000_REG_CTRL as u64, ctrl | E1000_CTRL_SLU);
    }

    use proteus_contracts::{
        E1000_RCTL_BAM, E1000_RCTL_EN, E1000_RCTL_SECRC, E1000_REG_RDBAH, E1000_REG_RDBAL,
        E1000_REG_RDH, E1000_REG_RDLEN, E1000_REG_RDT, E1000_REG_RCTL, E1000_RX_DESC_LEN,
    };
    use target_enterprise::e1000::RxDesc;

    const RX_RING_OFF: u64 = 0x2_1000;
    const RX_BUF_OFF: u64 = 0x2_2000;
    let rx_ring_phys = unsafe { DMA_PHYS_BASE } + RX_RING_OFF;
    let rx_buf_phys = unsafe { DMA_PHYS_BASE } + RX_BUF_OFF;
    let rx_ring_va = unsafe { pa_to_va(rx_ring_phys) };
    let rx_buf_va = unsafe { pa_to_va(rx_buf_phys) };
    // Clear RX buffer; magic "PE1000RX" will be searched after TX.
    unsafe {
        let mut i = 0usize;
        while i < 256 {
            core::ptr::write_volatile(rx_buf_va.add(i), 0);
            i += 1;
        }
        let rxd = RxDesc {
            addr: rx_buf_phys,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        let enc = rxd.encode();
        let mut i = 0usize;
        while i < E1000_RX_DESC_LEN {
            core::ptr::write_volatile(rx_ring_va.add(i), enc[i]);
            i += 1;
        }
        // Zero remaining ring entries.
        while i < 16 * E1000_RX_DESC_LEN {
            core::ptr::write_volatile(rx_ring_va.add(i), 0);
            i += 1;
        }
        mmio_write32(rx_bar0 + E1000_REG_RDBAL as u64, rx_ring_phys as u32);
        mmio_write32(rx_bar0 + E1000_REG_RDBAH as u64, (rx_ring_phys >> 32) as u32);
        mmio_write32(
            rx_bar0 + E1000_REG_RDLEN as u64,
            (16 * E1000_RX_DESC_LEN) as u32,
        );
        mmio_write32(rx_bar0 + E1000_REG_RDH as u64, 0);
        mmio_write32(rx_bar0 + E1000_REG_RDT as u64, 15);
        mmio_write32(
            rx_bar0 + E1000_REG_RCTL as u64,
            E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC,
        );
    }

    // Re-send frame with magic at eth payload offset 14.
    const MAGIC: &[u8; 8] = b"PE1000RX";
    unsafe {
        let mut i = 0usize;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(i), 0xFF);
            i += 1;
        }
        i = 0;
        while i < 6 {
            core::ptr::write_volatile(buf_va.add(6 + i), mac[i]);
            i += 1;
        }
        core::ptr::write_volatile(buf_va.add(12), 0x08);
        core::ptr::write_volatile(buf_va.add(13), 0x00);
        i = 0;
        while i < 8 {
            core::ptr::write_volatile(buf_va.add(14 + i), MAGIC[i]);
            i += 1;
        }
        i = 22;
        while i < TX_FRAME_LEN as usize {
            core::ptr::write_volatile(buf_va.add(i), 0xAA);
            i += 1;
        }
        // Re-arm TX desc (sta cleared).
        let desc = TxDesc {
            addr: tx_buf_phys,
            length: TX_FRAME_LEN,
            cso: 0,
            cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
            sta: 0,
            css: 0,
            special: 0,
        };
        let enc = desc.encode();
        let mut i = 0usize;
        while i < E1000_TX_DESC_LEN {
            core::ptr::write_volatile(ring_va.add(i), enc[i]);
            i += 1;
        }
        // Advance TDT past previous completion: use descriptor index 1.
        let desc2 = TxDesc {
            addr: tx_buf_phys,
            length: TX_FRAME_LEN,
            cso: 0,
            cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
            sta: 0,
            css: 0,
            special: 0,
        };
        let enc2 = desc2.encode();
        let d1 = ring_va.add(E1000_TX_DESC_LEN);
        let mut i = 0usize;
        while i < E1000_TX_DESC_LEN {
            core::ptr::write_volatile(d1.add(i), enc2[i]);
            i += 1;
        }
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        mmio_write32(bar0 + E1000_REG_TDT as u64, 2);

        let mut spins = 0u32;
        let mut found = false;
        loop {
            // Poll RX DD + scan buffer for magic.
            let sta = core::ptr::read_volatile(rx_ring_va.add(12));
            if sta & E1000_DESC_STA_DD != 0 {
                let mut j = 0usize;
                while j + 8 <= 256 {
                    let mut match_ok = true;
                    let mut k = 0usize;
                    while k < 8 {
                        if core::ptr::read_volatile(rx_buf_va.add(j + k)) != MAGIC[k] {
                            match_ok = false;
                            break;
                        }
                        k += 1;
                    }
                    if match_ok {
                        found = true;
                        break;
                    }
                    j += 1;
                }
                if found {
                    break;
                }
            }
            spins = spins.wrapping_add(1);
            if spins > 80_000_000 {
                panic!("E1000_HW: RX magic timeout");
            }
            core::hint::spin_loop();
        }
        let _ = found;
    }

    {
        let mut line = [0u8; 40];
        let mut pos = 0usize;
        let prefix = b"E1000_HW rx OK bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Report descriptor length if set, else frame size.
        let rlen = unsafe {
            let lo = core::ptr::read_volatile(rx_ring_va.add(8));
            let hi = core::ptr::read_volatile(rx_ring_va.add(9));
            (lo as u16) | ((hi as u16) << 8)
        };
        let report = if rlen > 0 { rlen as u64 } else { TX_FRAME_LEN as u64 };
        pos += dec_u64(report, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let _ = rx_slot;
}

// ---------------------------------------------------------------------------
// TASK-119: real QEMU NVMe (PCI + BAR0 MMIO + admin identify)
// ---------------------------------------------------------------------------

/// Banner: `NVME_HW probe OK slot=N` then `NVME_HW identify OK sn=…`
#[cfg(not(proteus_prod))]
fn banner_nvme_hw() {
    use proteus_contracts::{
        Pci, PciAddress, PciBar, PciConfigBus, PCI_CFG_OFFSET_CLASS_REVISION,
        PCI_CFG_OFFSET_COMMAND_STATUS, PCI_CFG_OFFSET_VENDOR_DEVICE, PCI_COMMAND_BUS_MASTER,
    };
    use target_enterprise::nvme::{
        CompletionQueueEntry, SubmissionQueueEntry, ADMIN_QUEUE_ENTRIES, CC_EN, CSTS_CFS,
        CSTS_RDY, IO_QUEUE_ENTRIES, NVME_BLOCK_SIZE, REG_ACQ, REG_AQA, REG_ASQ, REG_CAP,
        REG_CC, REG_CSTS, REG_VS,
    };
    use target_enterprise::pci::PciImpl;

    const PCI_COMMAND_MEMORY: u32 = 1 << 1;
    // Mass storage / NVM Express (PCI class 01:08:02).
    const CLASS_MASS: u8 = 0x01;
    const SUBCLASS_NVME: u8 = 0x08;
    const PROG_NVME: u8 = 0x02;
    // QEMU also exposes 8086:5845.
    const INTEL_VENDOR: u16 = 0x8086;
    const QEMU_NVME_DEV: u16 = 0x5845;

    if unsafe { PHYS_MAP_OFFSET } == 0 || unsafe { DMA_PHYS_BASE } == 0 {
        panic!("NVME_HW: phys map missing");
    }

    let mut bus = RealPciBus;
    let mut found_slot: Option<u8> = None;
    let mut found_addr: Option<PciAddress> = None;
    let mut bar0: u64 = 0;

    let mut device: u8 = 0;
    while device < 32 {
        let addr = PciAddress {
            bus: 0,
            device,
            function: 0,
        };
        let id = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_VENDOR_DEVICE);
        let vendor = (id & 0xFFFF) as u16;
        let dev_id = (id >> 16) as u16;
        if vendor == 0xFFFF {
            device = device.wrapping_add(1);
            continue;
        }
        let class_dw = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_CLASS_REVISION);
        let prog_if = ((class_dw >> 8) & 0xFF) as u8;
        let subclass = ((class_dw >> 16) & 0xFF) as u8;
        let class_code = ((class_dw >> 24) & 0xFF) as u8;
        let is_nvme = (class_code == CLASS_MASS
            && subclass == SUBCLASS_NVME
            && prog_if == PROG_NVME)
            || (vendor == INTEL_VENDOR && dev_id == QEMU_NVME_DEV);
        if is_nvme {
            let bar = match PciImpl::read_bar(&mut bus, addr, 0) {
                Ok(PciBar::Mmio32(p)) => p as u64,
                Ok(PciBar::Mmio64(p)) => p,
                Ok(PciBar::Io(_)) | Err(_) => 0,
            };
            if bar != 0 {
                found_slot = Some(device);
                found_addr = Some(addr);
                bar0 = bar;
                break;
            }
        }
        device = device.wrapping_add(1);
    }

    let slot = match found_slot {
        Some(s) => s,
        None => panic!("NVME_HW: no NVMe on bus 0 (attach -device nvme)"),
    };
    let addr = match found_addr {
        Some(a) => a,
        None => panic!("NVME_HW: missing addr"),
    };

    let cmd = PciConfigBus::read_dword(&mut bus, addr, PCI_CFG_OFFSET_COMMAND_STATUS);
    PciConfigBus::write_dword(
        &mut bus,
        addr,
        PCI_CFG_OFFSET_COMMAND_STATUS,
        cmd | PCI_COMMAND_MEMORY | PCI_COMMAND_BUS_MASTER,
    );

    // Map register page + doorbell page (0x1000).
    unsafe {
        let _ = ensure_mmio_page(bar0);
        let _ = ensure_mmio_page(bar0 + 0x1000);
    }

    let cap = unsafe { mmio_read64(bar0 + REG_CAP as u64) };
    if cap == 0 || cap == u64::MAX {
        panic!("NVME_HW: CAP MMIO fault");
    }
    let vs = unsafe { mmio_read32(bar0 + REG_VS as u64) };
    if vs == 0 || vs == 0xFFFF_FFFF {
        panic!("NVME_HW: VS MMIO fault");
    }
    let dstrd = ((cap >> 32) & 0xF) as u32;
    let doorbell_stride = 4u64 << dstrd;

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"NVME_HW probe OK slot=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(slot as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Admin queues + identify buffer in DMA window.
    const NVME_ASQ_OFF: u64 = 0x3_0000;
    const NVME_ACQ_OFF: u64 = 0x3_1000;
    const NVME_ID_OFF: u64 = 0x3_2000;
    let asq_phys = unsafe { DMA_PHYS_BASE } + NVME_ASQ_OFF;
    let acq_phys = unsafe { DMA_PHYS_BASE } + NVME_ACQ_OFF;
    let id_phys = unsafe { DMA_PHYS_BASE } + NVME_ID_OFF;
    unsafe {
        let mut p = 0u64;
        while p < 0x3000 {
            let va = pa_to_va(asq_phys + p);
            core::ptr::write_volatile(va, 0);
            p += 1;
        }
    }

    // Disable controller, wait !RDY.
    unsafe {
        let cc = mmio_read32(bar0 + REG_CC as u64);
        mmio_write32(bar0 + REG_CC as u64, cc & !CC_EN);
        let mut spins = 0u32;
        loop {
            let csts = mmio_read32(bar0 + REG_CSTS as u64);
            if csts & CSTS_CFS != 0 {
                panic!("NVME_HW: CFS on disable");
            }
            if csts & CSTS_RDY == 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("NVME_HW: disable RDY timeout");
            }
            core::hint::spin_loop();
        }

        let aqa = ((ADMIN_QUEUE_ENTRIES as u32 - 1) << 16) | (ADMIN_QUEUE_ENTRIES as u32 - 1);
        mmio_write32(bar0 + REG_AQA as u64, aqa);
        mmio_write64(bar0 + REG_ASQ as u64, asq_phys);
        mmio_write64(bar0 + REG_ACQ as u64, acq_phys);
        // IOSQES=6 (64B), IOCQES=4 (16B), EN=1
        let cc_new = (4u32 << 20) | (6u32 << 16) | CC_EN;
        mmio_write32(bar0 + REG_CC as u64, cc_new);
        spins = 0;
        loop {
            let csts = mmio_read32(bar0 + REG_CSTS as u64);
            if csts & CSTS_CFS != 0 {
                panic!("NVME_HW: CFS on enable");
            }
            if csts & CSTS_RDY != 0 {
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("NVME_HW: enable RDY timeout");
            }
            core::hint::spin_loop();
        }
    }

    // Identify Controller (opcode 0x06, CNS=1) → id buffer.
    let cid: u16 = 1;
    let mut sqe = SubmissionQueueEntry::EMPTY;
    sqe.cdw0 = SubmissionQueueEntry::cdw0(0x06, cid);
    sqe.nsid = 0;
    sqe.prp1 = id_phys;
    sqe.cdw10 = 0x01; // CNS=Identify Controller
    unsafe {
        let asq_va = pa_to_va(asq_phys);
        // Write SQE as raw LE bytes (repr C on LE host).
        let sqe_ptr = asq_va as *mut SubmissionQueueEntry;
        core::ptr::write_volatile(sqe_ptr, sqe);
        core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
        // SQ0 tail doorbell = 0x1000 + 0 * stride
        let sq_dbl = bar0 + 0x1000;
        mmio_write32(sq_dbl, 1);

        let acq_va = pa_to_va(acq_phys);
        let mut spins = 0u32;
        let phase_expect = true; // first completion uses phase=1
        loop {
            let status_and_cid =
                core::ptr::read_volatile(acq_va.add(12) as *const u32);
            let phase = (status_and_cid >> 16) & 1 != 0;
            let got_cid = (status_and_cid & 0xFFFF) as u16;
            if phase == phase_expect && got_cid == cid {
                let cqe = CompletionQueueEntry {
                    dw0: core::ptr::read_volatile(acq_va as *const u32),
                    dw1: core::ptr::read_volatile(acq_va.add(4) as *const u32),
                    sq_head_and_id: core::ptr::read_volatile(acq_va.add(8) as *const u32),
                    status_and_cid,
                };
                if !cqe.is_success() {
                    panic!("NVME_HW: identify status nonzero");
                }
                // CQ head doorbell
                let cq_dbl = bar0 + 0x1000 + doorbell_stride;
                mmio_write32(cq_dbl, 1);
                break;
            }
            spins = spins.wrapping_add(1);
            if spins > 50_000_000 {
                panic!("NVME_HW: identify CQ timeout");
            }
            core::hint::spin_loop();
        }
    }

    // SN is 20 ASCII bytes at offset 4 of Identify Controller data.
    let mut sn = [0u8; 20];
    unsafe {
        let id_va = pa_to_va(id_phys);
        let mut i = 0usize;
        while i < 20 {
            sn[i] = core::ptr::read_volatile(id_va.add(4 + i));
            i += 1;
        }
    }
    // Trim spaces; require at least one non-space (QEMU serial=).
    let mut sn_len = 20usize;
    while sn_len > 0 && (sn[sn_len - 1] == b' ' || sn[sn_len - 1] == 0) {
        sn_len -= 1;
    }
    if sn_len == 0 {
        panic!("NVME_HW: empty Identify SN");
    }
    // Must not be the in-kernel emu stamp.
    if sn_len >= 15 {
        let emu = b"PROTEUS-NVME-EMU";
        let mut same = true;
        let mut i = 0usize;
        while i < 15 {
            if sn[i] != emu[i] {
                same = false;
                break;
            }
            i += 1;
        }
        if same {
            panic!("NVME_HW: got emulator SN — wrong path");
        }
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"NVME_HW identify OK sn=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let n = if sn_len > 20 { 20 } else { sn_len };
        line[pos..pos + n].copy_from_slice(&sn[..n]);
        pos += n;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // TASK-131: Create I/O CQ+SQ, WRITE then READ LBA 0 with pattern 0x5A^i.
    const NVME_IOSQ_OFF: u64 = 0x3_4000;
    const NVME_IOCQ_OFF: u64 = 0x3_5000;
    const NVME_SEC_OFF: u64 = 0x3_6000;
    let iosq_phys = unsafe { DMA_PHYS_BASE } + NVME_IOSQ_OFF;
    let iocq_phys = unsafe { DMA_PHYS_BASE } + NVME_IOCQ_OFF;
    let sec_phys = unsafe { DMA_PHYS_BASE } + NVME_SEC_OFF;
    unsafe {
        let mut p = 0u64;
        while p < 0x3000 {
            core::ptr::write_volatile(pa_to_va(iosq_phys + p), 0);
            p += 1;
        }
    }

    // Admin SQ tail = 1 after identify; CQ head = 1; phase still 1 until wrap.
    let mut admin_sq_tail: u16 = 1;
    let mut admin_cq_head: u16 = 1;
    let mut admin_phase = true;
    let mut next_cid: u16 = 2;

    let sq0_dbl = bar0 + 0x1000;
    let cq0_dbl = bar0 + 0x1000 + doorbell_stride;

    let mut admin_submit = |sqe: &SubmissionQueueEntry,
                            admin_sq_tail: &mut u16,
                            admin_cq_head: &mut u16,
                            admin_phase: &mut bool,
                            bar0: u64,
                            asq_phys: u64,
                            acq_phys: u64,
                            sq0_dbl: u64,
                            cq0_dbl: u64| {
        unsafe {
            let slot = (*admin_sq_tail as usize) % (ADMIN_QUEUE_ENTRIES as usize);
            let asq_va = pa_to_va(asq_phys).add(slot * 64) as *mut SubmissionQueueEntry;
            core::ptr::write_volatile(asq_va, *sqe);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            *admin_sq_tail = admin_sq_tail.wrapping_add(1);
            if *admin_sq_tail >= ADMIN_QUEUE_ENTRIES {
                *admin_sq_tail = 0;
            }
            // Spec: doorbell is new tail value (index of next free slot).
            mmio_write32(sq0_dbl, *admin_sq_tail as u32);

            let mut spins = 0u32;
            loop {
                let cq_slot = (*admin_cq_head as usize) % (ADMIN_QUEUE_ENTRIES as usize);
                let cqe_va = pa_to_va(acq_phys).add(cq_slot * 16);
                let status_and_cid =
                    core::ptr::read_volatile(cqe_va.add(12) as *const u32);
                let phase = (status_and_cid >> 16) & 1 != 0;
                let got_cid = (status_and_cid & 0xFFFF) as u16;
                if phase == *admin_phase && got_cid == sqe.cid() {
                    let status = ((status_and_cid >> 17) & 0x7FFF) as u16;
                    if status != 0 {
                        panic!("NVME_HW: admin cmd status nonzero");
                    }
                    *admin_cq_head = admin_cq_head.wrapping_add(1);
                    if *admin_cq_head >= ADMIN_QUEUE_ENTRIES {
                        *admin_cq_head = 0;
                        *admin_phase = !*admin_phase;
                    }
                    mmio_write32(cq0_dbl, *admin_cq_head as u32);
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 50_000_000 {
                    panic!("NVME_HW: admin CQ timeout");
                }
                core::hint::spin_loop();
            }
        }
    };

    // Create I/O CQ (qid=1).
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x05, next_cid);
        sqe.prp1 = iocq_phys;
        sqe.cdw10 = ((IO_QUEUE_ENTRIES as u32 - 1) << 16) | 1;
        sqe.cdw11 = 0x01; // PC
        admin_submit(
            &sqe,
            &mut admin_sq_tail,
            &mut admin_cq_head,
            &mut admin_phase,
            bar0,
            asq_phys,
            acq_phys,
            sq0_dbl,
            cq0_dbl,
        );
        next_cid = next_cid.wrapping_add(1);
    }
    // Create I/O SQ (qid=1).
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x01, next_cid);
        sqe.prp1 = iosq_phys;
        sqe.cdw10 = ((IO_QUEUE_ENTRIES as u32 - 1) << 16) | 1;
        sqe.cdw11 = (1 << 16) | 0x01; // CQID=1 | PC
        admin_submit(
            &sqe,
            &mut admin_sq_tail,
            &mut admin_cq_head,
            &mut admin_phase,
            bar0,
            asq_phys,
            acq_phys,
            sq0_dbl,
            cq0_dbl,
        );
        next_cid = next_cid.wrapping_add(1);
    }

    let sq1_dbl = bar0 + 0x1000 + 2 * doorbell_stride;
    let cq1_dbl = bar0 + 0x1000 + 3 * doorbell_stride;
    let mut io_sq_tail: u16 = 0;
    let mut io_cq_head: u16 = 0;
    let mut io_phase = true;

    let mut io_submit = |sqe: &SubmissionQueueEntry| {
        unsafe {
            let slot = (io_sq_tail as usize) % (IO_QUEUE_ENTRIES as usize);
            let va = pa_to_va(iosq_phys).add(slot * 64) as *mut SubmissionQueueEntry;
            core::ptr::write_volatile(va, *sqe);
            core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
            io_sq_tail = io_sq_tail.wrapping_add(1);
            if io_sq_tail >= IO_QUEUE_ENTRIES {
                io_sq_tail = 0;
            }
            mmio_write32(sq1_dbl, io_sq_tail as u32);

            let mut spins = 0u32;
            loop {
                let cq_slot = (io_cq_head as usize) % (IO_QUEUE_ENTRIES as usize);
                let cqe_va = pa_to_va(iocq_phys).add(cq_slot * 16);
                let status_and_cid =
                    core::ptr::read_volatile(cqe_va.add(12) as *const u32);
                let phase = (status_and_cid >> 16) & 1 != 0;
                let got_cid = (status_and_cid & 0xFFFF) as u16;
                if phase == io_phase && got_cid == sqe.cid() {
                    let status = ((status_and_cid >> 17) & 0x7FFF) as u16;
                    if status != 0 {
                        panic!("NVME_HW: io cmd status nonzero");
                    }
                    io_cq_head = io_cq_head.wrapping_add(1);
                    if io_cq_head >= IO_QUEUE_ENTRIES {
                        io_cq_head = 0;
                        io_phase = !io_phase;
                    }
                    mmio_write32(cq1_dbl, io_cq_head as u32);
                    break;
                }
                spins = spins.wrapping_add(1);
                if spins > 50_000_000 {
                    panic!("NVME_HW: io CQ timeout");
                }
                core::hint::spin_loop();
            }
        }
    };

    // Pattern 0x5A ^ i over 512 B at LBA 0.
    unsafe {
        let sec_va = pa_to_va(sec_phys);
        let mut i = 0usize;
        while i < NVME_BLOCK_SIZE {
            core::ptr::write_volatile(sec_va.add(i), 0x5Au8 ^ (i as u8));
            i += 1;
        }
    }
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x01, next_cid); // Write
        sqe.nsid = 1;
        sqe.prp1 = sec_phys;
        sqe.cdw10 = 0; // LBA low
        sqe.cdw11 = 0;
        sqe.cdw12 = 0; // 1 block
        io_submit(&sqe);
        next_cid = next_cid.wrapping_add(1);
    }
    // Clear buffer, then Read LBA 0.
    unsafe {
        let sec_va = pa_to_va(sec_phys);
        let mut i = 0usize;
        while i < NVME_BLOCK_SIZE {
            core::ptr::write_volatile(sec_va.add(i), 0);
            i += 1;
        }
    }
    {
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x02, next_cid); // Read
        sqe.nsid = 1;
        sqe.prp1 = sec_phys;
        sqe.cdw10 = 0;
        sqe.cdw11 = 0;
        sqe.cdw12 = 0;
        io_submit(&sqe);
    }
    let first = unsafe { core::ptr::read_volatile(pa_to_va(sec_phys)) };
    if first != 0x5A {
        panic!("NVME_HW: sector first_byte drift");
    }
    unsafe {
        let sec_va = pa_to_va(sec_phys);
        let mut i = 1usize;
        while i < NVME_BLOCK_SIZE {
            let got = core::ptr::read_volatile(sec_va.add(i));
            let want = 0x5Au8 ^ (i as u8);
            if got != want {
                panic!("NVME_HW: sector data drift");
            }
            i += 1;
        }
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"NVME_HW sector OK first_byte=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let mut hex = [0u8; 2];
        hex_encode(&[first], 1, &mut hex);
        line[pos..pos + 2].copy_from_slice(&hex);
        pos += 2;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let _ = found_addr;
    let _ = bar0;
    let _ = next_cid;
}

// ---------------------------------------------------------------------------
// TASK-107: legacy virtio-pci virtqueue sector round-trip (real DMA)
// DMA lives in a usable physical RAM window (BootInfo), accessed via
// physical_memory_offset — not kernel .bss (which has a separate map).
// Layout in DMA window for QEMU legacy default qsz=256:
//   desc: 256*16 = 4096
//   avail: 4+512 = 516  → used = align(4612) = 8192
//   used ring fits in next 4K → queue ends ~12K
//   [0x4000) header, [0x4010) data 512B, [0x4210] status
// ---------------------------------------------------------------------------

const VQ_SIZE: u16 = 256;
const VQ_ALIGN: u64 = 4096;
const DMA_Q_OFF: u64 = 0;
const DMA_HDR_OFF: u64 = 0x4000;
const DMA_DATA_OFF: u64 = 0x4010;
const DMA_ST_OFF: u64 = 0x4210;
const DMA_ZERO_LEN: usize = 0x5000;

/// Write then read sector 0 via legacy virtqueue; return data[0].
fn virtio_legacy_sector_roundtrip(io_base: u16) -> u8 {
    use core::sync::atomic::{fence, Ordering};
    use proteus_contracts::virtio_blk_req_type;
    use proteus_contracts::virtio_blk_status_byte;

    let dma_phys = unsafe { DMA_PHYS_BASE };
    let q_pa = dma_phys + DMA_Q_OFF;
    let hdr_pa = dma_phys + DMA_HDR_OFF;
    let data_pa = dma_phys + DMA_DATA_OFF;
    let st_pa = dma_phys + DMA_ST_OFF;

    // Zero DMA window via physical map.
    unsafe {
        let base = pa_to_va(dma_phys);
        let mut i = 0usize;
        while i < DMA_ZERO_LEN {
            core::ptr::write_volatile(base.add(i), 0);
            i += 1;
        }
        core::ptr::write_volatile(pa_to_va(st_pa), 0xff);
    }

    // DMA self-test via physical map.
    unsafe {
        let p = pa_to_va(data_pa);
        core::ptr::write_volatile(p, 0x5A);
        if core::ptr::read_volatile(p) != 0x5A {
            panic!("VIRTIO_HW sector: DMA window not writable");
        }
        core::ptr::write_volatile(p, 0);
    }

    // Legacy bring-up: features + queue PFN + DRIVER_OK.
    // Accept host feature low 24 bits (device-type + transport).
    unsafe {
        outb(io_base + 18, 0);
        outb(io_base + 18, 1);
        outb(io_base + 18, 3);
        let host_feat = inl(io_base + 0);
        // Negotiate no optional features (basic IN/OUT always work).
        let _ = host_feat;
        outl(io_base + 4, 0);
        outw(io_base + 14, 0); // queue_sel
        // QEMU legacy: QueueNum is the fixed queue size (typically 256),
        // not a programmable field. Layout MUST use this size.
        let qsz = inw(io_base + 12);
        if qsz != VQ_SIZE {
            let mut line = [0u8; 40];
            let mut pos = 0usize;
            let pfx = b"VIRTIO_HW fail qsz=";
            line[..pfx.len()].copy_from_slice(pfx);
            pos += pfx.len();
            pos += dec_u64(qsz as u64, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
            panic!("VIRTIO_HW sector: unexpected device queue size");
        }
        let pfn = (q_pa >> 12) as u32;
        if pfn == 0 {
            panic!("VIRTIO_HW sector: zero PFN");
        }
        outl(io_base + 8, pfn);
        outb(io_base + 18, 1 | 2 | 4);
    }

    let desc_off = 0u64;
    let avail_off = (VQ_SIZE as u64) * 16; // 4096
    // used = align_up(avail + 4 + 2*qsz, 4096) = align_up(4612)=8192
    let used_off = {
        let raw = avail_off + 4 + 2 * (VQ_SIZE as u64);
        (raw + VQ_ALIGN - 1) & !(VQ_ALIGN - 1)
    };

    // Pattern for write.
    unsafe {
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            core::ptr::write_volatile(d.add(i), 0xA5 ^ (i as u8));
            i += 1;
        }
    }

    virtio_legacy_submit(
        io_base,
        q_pa,
        desc_off,
        avail_off,
        used_off,
        hdr_pa,
        data_pa,
        st_pa,
        virtio_blk_req_type::OUT,
        0,
        false,
        0, // first submit: avail starts 0, expect used 1
    );
    let st = unsafe { core::ptr::read_volatile(pa_to_va(st_pa)) };
    if st != virtio_blk_status_byte::OK {
        panic!("VIRTIO_HW sector: write status not OK");
    }

    // Clear data, READ sector 0.
    unsafe {
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            core::ptr::write_volatile(d.add(i), 0);
            i += 1;
        }
        core::ptr::write_volatile(pa_to_va(st_pa), 0xff);
    }
    virtio_legacy_submit(
        io_base,
        q_pa,
        desc_off,
        avail_off,
        used_off,
        hdr_pa,
        data_pa,
        st_pa,
        virtio_blk_req_type::IN,
        0,
        true,
        1, // second submit: avail was 1, expect used 2
    );
    let st = unsafe { core::ptr::read_volatile(pa_to_va(st_pa)) };
    if st != virtio_blk_status_byte::OK {
        panic!("VIRTIO_HW sector: read status not OK");
    }

    unsafe {
        let d = pa_to_va(data_pa);
        let mut i = 0usize;
        while i < 512 {
            let got = core::ptr::read_volatile(d.add(i));
            let expect = 0xA5u8 ^ (i as u8);
            if got != expect {
                panic!("VIRTIO_HW sector: data byte drift");
            }
            i += 1;
        }
        fence(Ordering::SeqCst);
        core::ptr::read_volatile(d)
    }
}

fn virtio_legacy_submit(
    io_base: u16,
    q_pa: u64,
    desc_off: u64,
    avail_off: u64,
    used_off: u64,
    hdr_pa: u64,
    data_pa: u64,
    st_pa: u64,
    req_type: u32,
    sector: u64,
    data_device_write: bool,
    prev_avail_idx: u16,
) {
    use core::sync::atomic::{fence, Ordering};

    // Header in DMA.
    unsafe {
        let h = pa_to_va(hdr_pa);
        let t = req_type.to_le_bytes();
        let mut i = 0;
        while i < 4 {
            core::ptr::write_volatile(h.add(i), t[i]);
            i += 1;
        }
        i = 0;
        while i < 4 {
            core::ptr::write_volatile(h.add(4 + i), 0);
            i += 1;
        }
        let s = sector.to_le_bytes();
        i = 0;
        while i < 8 {
            core::ptr::write_volatile(h.add(8 + i), s[i]);
            i += 1;
        }
    }

    let q = pa_to_va(q_pa);
    // desc 0 header
    write_desc_phys(q, desc_off, hdr_pa, 16, 1, 1);
    let dflags: u16 = if data_device_write { 1 | 2 } else { 1 };
    write_desc_phys(q, desc_off + 16, data_pa, 512, dflags, 2);
    write_desc_phys(q, desc_off + 32, st_pa, 1, 2, 0);

    // avail
    let old_idx = prev_avail_idx;
    let slot = (old_idx as usize) & (VQ_SIZE as usize - 1);
    unsafe {
        let ring = q.add(avail_off as usize + 4 + slot * 2);
        core::ptr::write_volatile(ring, 0);
        core::ptr::write_volatile(ring.add(1), 0);
        let new_idx = old_idx.wrapping_add(1);
        let ib = new_idx.to_le_bytes();
        core::ptr::write_volatile(q.add(avail_off as usize + 2), ib[0]);
        core::ptr::write_volatile(q.add(avail_off as usize + 3), ib[1]);
    }

    fence(Ordering::SeqCst);
    unsafe {
        outw(io_base + 16, 0);
    }

    let target = prev_avail_idx.wrapping_add(1);
    let mut spins = 0u32;
    loop {
        fence(Ordering::SeqCst);
        let uidx = unsafe {
            let b0 = core::ptr::read_volatile(q.add(used_off as usize + 2));
            let b1 = core::ptr::read_volatile(q.add(used_off as usize + 3));
            u16::from_le_bytes([b0, b1])
        };
        if uidx == target {
            break;
        }
        spins = spins.wrapping_add(1);
        if spins > 20_000_000 {
            // Dump used.idx so the serial log diagnoses the hang.
            let mut line = [0u8; 40];
            let mut pos = 0usize;
            let pfx = b"VIRTIO_HW fail used=";
            line[..pfx.len()].copy_from_slice(pfx);
            pos += pfx.len();
            pos += dec_u64(uidx as u64, &mut line[pos..]);
            line[pos] = b'\n';
            pos += 1;
            serial_write_bytes(&line[..pos]);
            panic!("VIRTIO_HW sector: completion timeout");
        }
        core::hint::spin_loop();
    }
}

fn write_desc_phys(q: *mut u8, off: u64, addr: u64, len: u32, flags: u16, next: u16) {
    unsafe {
        let p = q.add(off as usize);
        let a = addr.to_le_bytes();
        let mut i = 0;
        while i < 8 {
            core::ptr::write_volatile(p.add(i), a[i]);
            i += 1;
        }
        let l = len.to_le_bytes();
        i = 0;
        while i < 4 {
            core::ptr::write_volatile(p.add(8 + i), l[i]);
            i += 1;
        }
        let f = flags.to_le_bytes();
        core::ptr::write_volatile(p.add(12), f[0]);
        core::ptr::write_volatile(p.add(13), f[1]);
        let n = next.to_le_bytes();
        core::ptr::write_volatile(p.add(14), n[0]);
        core::ptr::write_volatile(p.add(15), n[1]);
    }
}

/// BLOCK path compose: same 512-byte pattern written and read on both
/// NVMe (MemNvmeController) and virtio-blk (MemVirtioBlkBus). Proves
/// the two block backends still agree on sector size and data path
/// after independent morph of `nvme` + `virtio_blk`.
///
/// Banner: `BLOCK path compose OK sector=512 nvme=a5 virtio=a5`
#[cfg(not(proteus_prod))]
fn banner_block_path_compose() {
    use proteus_contracts::{BlockDeviceVirtio, VIRTIO_BLK_SECTOR_SIZE};
    use target_enterprise::nvme::{
        MemNvmeController, NvmeImpl, NVME_BLOCK_SIZE,
    };
    use target_enterprise::virtio_blk::{MemVirtioBlkBus, VirtioBlk};

    if NVME_BLOCK_SIZE != VIRTIO_BLK_SECTOR_SIZE {
        panic!("BLOCK path compose: sector size mismatch constants");
    }
    const SECTOR: usize = 512;
    if NVME_BLOCK_SIZE != SECTOR {
        panic!("BLOCK path compose: expected 512 B sectors");
    }

    // Locked pattern: byte[i] = 0xA5 ^ (i as u8) — same family as
    // virtio-blk isolated banner; first byte is 0xA5.
    let mut pattern = [0u8; SECTOR];
    let mut i = 0usize;
    while i < SECTOR {
        pattern[i] = 0xA5 ^ (i as u8);
        i += 1;
    }

    // ---- NVMe path ----
    let mut nvme = NvmeImpl::new(MemNvmeController::new());
    if nvme.bring_up(0x1000, 0x2000).is_err() {
        panic!("BLOCK path compose: NVMe bring_up");
    }
    if nvme.create_io_queues(0x3000, 0x4000).is_err() {
        panic!("BLOCK path compose: NVMe queues");
    }
    // identify so namespace capacity is live
    if nvme.identify_namespace(0x5000).is_err() {
        panic!("BLOCK path compose: NVMe identify_ns");
    }
    if nvme.try_write_block(5, &pattern, 0x6000).is_err() {
        panic!("BLOCK path compose: NVMe write");
    }
    let mut nvme_rb = [0u8; SECTOR];
    if nvme.try_read_block(5, &mut nvme_rb, 0x6000).is_err() {
        panic!("BLOCK path compose: NVMe read");
    }
    i = 0;
    while i < SECTOR {
        if nvme_rb[i] != pattern[i] {
            panic!("BLOCK path compose: NVMe byte drift");
        }
        i += 1;
    }

    // ---- virtio-blk path ----
    static mut BLK_BUS: MemVirtioBlkBus = MemVirtioBlkBus::new();
    let bus: &mut MemVirtioBlkBus = unsafe {
        // Safety: single-threaded banner; exclusive use of BLK_BUS.
        &mut *core::ptr::addr_of_mut!(BLK_BUS)
    };
    let mut vblk = VirtioBlk::new();
    if vblk.init(bus).is_err() {
        panic!("BLOCK path compose: virtio init");
    }
    if vblk.preferred_block_size() as usize != SECTOR {
        panic!("BLOCK path compose: virtio blk_size");
    }
    if vblk.write_block(bus, 5, &pattern).is_err() {
        panic!("BLOCK path compose: virtio write");
    }
    let mut v_rb = [0u8; SECTOR];
    if vblk.read_block(bus, 5, &mut v_rb).is_err() {
        panic!("BLOCK path compose: virtio read");
    }
    i = 0;
    while i < SECTOR {
        if v_rb[i] != pattern[i] {
            panic!("BLOCK path compose: virtio byte drift");
        }
        i += 1;
    }

    // Cross-backend: both recovered first byte must match pattern.
    if nvme_rb[0] != 0xA5 || v_rb[0] != 0xA5 || nvme_rb[0] != v_rb[0] {
        panic!("BLOCK path compose: first_byte cross mismatch");
    }

    serial_write_bytes(b"BLOCK path compose OK sector=512 nvme=a5 virtio=a5\n");
}

/// NET path compose: TCP 3-way handshake → ESTABLISHED, then HTTP GET
/// as a real TCP data payload, then HTTP 200 response built and
/// re-framed as a TCP segment. Proves tcp + http glue (not two
/// isolated demos): morph damage to either side drops this banner.
///
/// Banner: `NET path compose OK method=GET status=200`
#[cfg(not(proteus_prod))]
fn banner_net_path_compose() {
    use proteus_contracts::{tcp_flags, Http, HttpMethod, Tcp};
    use target_enterprise::http::HttpImpl;
    use target_enterprise::tcp::{process_segment, Tcb, TcpImpl, TcpState};

    let server_ip: [u8; 4] = [10, 0, 0, 2];
    let client_ip: [u8; 4] = [10, 0, 0, 1];
    let server_port: u16 = 80;
    let client_port: u16 = 40000;
    let client_isn: u32 = 0x2000_0000;

    // ---- handshake (same shape as banner_tcp, tighter asserts) ----
    let mut tcb = Tcb::listen(server_ip, server_port, 65535);
    let mut buf = [0u8; 256];
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn,
        0,
        tcp_flags::SYN,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: SYN build"),
    };
    let syn = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: SYN parse"),
    };
    let (next, syn_ack) = match process_segment(tcb, &syn, 0xBEEF) {
        Ok(t) => t,
        Err(_) => panic!("NET path compose: process SYN"),
    };
    tcb = next;
    if tcb.state != TcpState::SynReceived || !syn_ack.present {
        panic!("NET path compose: SynReceived/hint");
    }
    let server_isn = syn_ack.seq;

    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::ACK,
        65535,
        b"",
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: ACK build"),
    };
    let ack = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: ACK parse"),
    };
    let (next, _) = match process_segment(tcb, &ack, 0xBEEF) {
        Ok(t) => t,
        Err(_) => panic!("NET path compose: process ACK"),
    };
    tcb = next;
    if tcb.state != TcpState::Established {
        panic!("NET path compose: not Established");
    }

    // ---- HTTP request as TCP data on the established stream ----
    let http_req: &[u8] =
        b"GET /healthz HTTP/1.1\r\nHost: proteus.local\r\n\r\n";
    let n = match TcpImpl::build_segment(
        client_port,
        server_port,
        client_isn.wrapping_add(1),
        server_isn.wrapping_add(1),
        tcp_flags::PSH | tcp_flags::ACK,
        65535,
        http_req,
        client_ip,
        server_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: HTTP data segment build"),
    };
    let data_seg = match TcpImpl::parse_segment(&buf[..n], client_ip, server_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: HTTP data segment parse"),
    };
    if data_seg.payload != http_req {
        panic!("NET path compose: payload drift after TCP round-trip");
    }
    let rcv_before = tcb.rcv_nxt;
    let (next, data_ack) = match process_segment(tcb, &data_seg, 0xBEEF) {
        Ok(t) => t,
        Err(_) => panic!("NET path compose: process HTTP data"),
    };
    tcb = next;
    if tcb.state != TcpState::Established {
        panic!("NET path compose: left Established on data");
    }
    if tcb.rcv_nxt != rcv_before.wrapping_add(http_req.len() as u32) {
        panic!("NET path compose: rcv_nxt not advanced by HTTP len");
    }
    if !data_ack.present {
        panic!("NET path compose: missing ACK for HTTP data");
    }

    // Application layer: parse the *TCP payload*, not a side fixture.
    let view = match HttpImpl::parse_request(data_seg.payload) {
        Ok(v) => v,
        Err(_) => panic!("NET path compose: HTTP parse of TCP payload"),
    };
    if view.method != HttpMethod::Get || view.path != b"/healthz" {
        panic!("NET path compose: method/path drift");
    }

    let mut http_out = [0u8; 96];
    let http_n = match HttpImpl::build_response(200, b"text/plain", b"OK", &mut http_out) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: HTTP build_response"),
    };
    let expected_prefix = b"HTTP/1.1 200 OK\r\n";
    if http_n < expected_prefix.len()
        || &http_out[..expected_prefix.len()] != expected_prefix
    {
        panic!("NET path compose: response status line drift");
    }

    // Server frames the HTTP response as a TCP segment back to client.
    let n = match TcpImpl::build_segment(
        server_port,
        client_port,
        tcb.snd_nxt,
        tcb.rcv_nxt,
        tcp_flags::PSH | tcp_flags::ACK,
        tcb.rcv_wnd,
        &http_out[..http_n],
        server_ip,
        client_ip,
        &mut buf,
    ) {
        Ok(n) => n,
        Err(_) => panic!("NET path compose: response segment build"),
    };
    let resp_seg = match TcpImpl::parse_segment(&buf[..n], server_ip, client_ip) {
        Ok(s) => s,
        Err(_) => panic!("NET path compose: response segment parse"),
    };
    if resp_seg.payload != &http_out[..http_n] {
        panic!("NET path compose: response payload drift");
    }

    serial_write_bytes(b"NET path compose OK method=GET status=200\n");
}

/// AHCI storage compose: Register H2D IDENTIFY FIS + command header +
/// single PRDT for a 512-byte IDENTIFY buffer. Proves the three
/// storage-command surfaces agree on one slot layout (CFL=5, PRDTL=1,
/// FIS cmd=0xEC, PRDT IOC 512 B) so diversifying one module cannot
/// silently desync the others.
///
/// Banner: `AHCI storage compose OK fis=ec prdtl=1 bytes=512`
#[cfg(not(proteus_prod))]
fn banner_ahci_storage_compose() {
    use proteus_contracts::{
        AhciCmd, AhciFis, AHCI_CFL_H2D, AHCI_FIS_H2D_LEN, ATA_CMD_IDENTIFY,
    };
    use target_enterprise::ahci_cmd::AhciCmdImpl;
    use target_enterprise::ahci_fis::AhciFisImpl;

    // Command table base + IDENTIFY data buffer (fixture addresses).
    const CTBA: u64 = 0x0000_0000_0010_0000;
    const DATA: u64 = 0x0000_0000_0020_0000;

    let fis_params = match AhciFisImpl::identify(0) {
        Ok(p) => p,
        Err(_) => panic!("AHCI storage compose: identify params"),
    };
    if fis_params.command != ATA_CMD_IDENTIFY || !fis_params.is_command {
        panic!("AHCI storage compose: FIS command drift");
    }
    let mut fis = [0u8; AHCI_FIS_H2D_LEN];
    if AhciFisImpl::encode_h2d(&fis_params, &mut fis).is_err() {
        panic!("AHCI storage compose: FIS encode");
    }
    let fis_back = match AhciFisImpl::decode_h2d(&fis) {
        Ok(p) => p,
        Err(_) => panic!("AHCI storage compose: FIS decode"),
    };
    if fis_back.command != ATA_CMD_IDENTIFY || fis[2] != ATA_CMD_IDENTIFY {
        panic!("AHCI storage compose: FIS round-trip drift");
    }

    let (hdr, prd) = match AhciCmdImpl::identify_slot(CTBA, DATA) {
        Ok(v) => v,
        Err(_) => panic!("AHCI storage compose: slot"),
    };
    if hdr.cfl != AHCI_CFL_H2D || hdr.prdtl != 1 || hdr.write {
        panic!("AHCI storage compose: header fields");
    }
    if hdr.ctba != CTBA || prd.dba != DATA || prd.byte_count != 512 || !prd.ioc {
        panic!("AHCI storage compose: address/PRDT drift");
    }

    let mut hb = [0u8; 32];
    let mut pb = [0u8; 16];
    if AhciCmdImpl::encode_header(&hdr, &mut hb).is_err()
        || AhciCmdImpl::encode_prdt(&prd, &mut pb).is_err()
    {
        panic!("AHCI storage compose: header/PRDT encode");
    }
    let hdr2 = match AhciCmdImpl::decode_header(&hb) {
        Ok(h) => h,
        Err(_) => panic!("AHCI storage compose: header decode"),
    };
    let prd2 = match AhciCmdImpl::decode_prdt(&pb) {
        Ok(p) => p,
        Err(_) => panic!("AHCI storage compose: PRDT decode"),
    };
    if hdr2.prdtl != 1 || hdr2.cfl != AHCI_CFL_H2D || prd2.byte_count != 512 {
        panic!("AHCI storage compose: cmd round-trip drift");
    }
    // Cross-surface lock: H2D FIS length in dwords must match CFL.
    if (AHCI_FIS_H2D_LEN / 4) as u8 != hdr2.cfl {
        panic!("AHCI storage compose: CFL vs FIS len mismatch");
    }

    serial_write_bytes(b"AHCI storage compose OK fis=ec prdtl=1 bytes=512\n");
}

// TASK-083 IOAPIC
#[cfg(not(proteus_prod))]
fn banner_ioapic() {
    use proteus_contracts::IoApic;
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
#[cfg(not(proteus_prod))]
fn banner_lapic() {
    use proteus_contracts::{LapicIcr, ICR_DELIVERY_INIT};
    use target_enterprise::lapic_icr::LapicIcrImpl;

    let c = LapicIcrImpl::init(0);
    if LapicIcrImpl::delivery_of(c.low) != ICR_DELIVERY_INIT {
        panic!("LAPIC banner: delivery drift");
    }
    serial_write_bytes(b"LAPIC icr OK delivery=init\n");
}

// TASK-079 Multiboot2
#[cfg(not(proteus_prod))]
fn banner_mb2() {
    use proteus_contracts::{Mb2Tag, Multiboot2, MB2_MAX_TAGS};
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

// TASK-080 CRC32C
#[cfg(not(proteus_prod))]
fn banner_crc32c() {
    use proteus_contracts::Crc32c;
    use target_enterprise::crc32c::Crc32cImpl;

    if Crc32cImpl::hash(b"123456789") != 0xE306_9283 {
        panic!("CRC32C banner: kat fail");
    }
    serial_write_bytes(b"CRC32C kat OK\n");
}

// TASK-081 RSDP
#[cfg(not(proteus_prod))]
fn banner_rsdp() {
    use proteus_contracts::AcpiRsdp;
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
#[cfg(not(proteus_prod))]
fn banner_frame() {
    use proteus_contracts::FrameBitmap;
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
#[cfg(not(proteus_prod))]
fn banner_serial() {
    use proteus_contracts::{Serial16550, SERIAL_COM1, SERIAL_INIT_WRITES};
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
#[cfg(not(proteus_prod))]
fn banner_tick() {
    use proteus_contracts::{TickKind, TickSource};
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
#[cfg(not(proteus_prod))]
fn banner_virtio_caps() {
    use proteus_contracts::{
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

// TASK-078: sig kat
#[cfg(not(proteus_prod))]
fn banner_sigkat() {
    use proteus_contracts::{SigKat, SIGKAT_VECTOR_COUNT};
    use target_enterprise::sigkat::SigKatImpl;

    let s = SigKatImpl::run_all();
    if !s.all_ok() || s.total != SIGKAT_VECTOR_COUNT {
        panic!("SIGKAT banner: suite failed");
    }
    {
        let mut line = [0u8; 40];
        let mut pos = 0usize;
        let prefix = b"SIGKAT all OK vectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(s.passed as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-071: Watchdog arm/pet/fire.
#[cfg(not(proteus_prod))]
fn banner_watchdog() {
    use proteus_contracts::{Watchdog, WatchdogError};
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

// TASK-072: RNG KAT
#[cfg(not(proteus_prod))]
fn banner_rng() {
    use proteus_contracts::Random;
    use target_enterprise::random::{banner_expected_prefix8, BANNER_SEED, RandomImpl};

    let mut r = RandomImpl::new();
    if r.seed(&BANNER_SEED).is_err() {
        panic!("RNG banner: seed failed");
    }
    let mut out = [0u8; 8];
    if r.fill(&mut out).is_err() {
        panic!("RNG banner: fill failed");
    }
    let exp = banner_expected_prefix8();
    let mut i = 0usize;
    while i < 8 {
        if out[i] != exp[i] {
            panic!("RNG banner: KAT drift");
        }
        i += 1;
    }
    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"RNG kat OK seed=0102 out=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        i = 0;
        while i < 4 {
            let b = out[i];
            let hi = b >> 4;
            let lo = b & 0x0F;
            line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
            pos += 1;
            line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
            pos += 1;
            i += 1;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-073: Power S5
#[cfg(not(proteus_prod))]
fn banner_power() {
    use proteus_contracts::{Power, SLP_TYP_S5};
    use target_enterprise::power::PowerImpl;

    let p = PowerImpl::encode_s5(SLP_TYP_S5);
    if PowerImpl::decode_slp_typ(p) != 5 || !PowerImpl::is_slp_en(p) {
        panic!("POWER banner: encode drift");
    }
    serial_write_bytes(b"POWER s5 OK slp_typ=5\n");
}

// TASK-074: ELF64
#[cfg(not(proteus_prod))]
fn banner_elf() {
    use proteus_contracts::{Elf64, ELF_MAX_PHDRS, ElfPhdr};
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
#[cfg(not(proteus_prod))]
fn banner_hpet() {
    use proteus_contracts::Hpet;
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

// TASK-068: Stack canary mint + mismatch fingerprint.
#[cfg(not(proteus_prod))]
fn banner_canary() {
    use proteus_contracts::StackCanary;
    use target_enterprise::stack_canary::{BANNER_SEED, StackCanaryImpl};

    let tok = match StackCanaryImpl::mint(&BANNER_SEED) {
        Ok(t) => t,
        Err(_) => panic!("CANARY banner: mint failed"),
    };
    if StackCanaryImpl::verify(&tok, &tok).is_err() {
        panic!("CANARY banner: self-verify failed");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"CANARY mint OK tok=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // first 4 bytes as hex
        let mut i = 0usize;
        while i < 4 {
            let b = tok.bytes[i];
            let hi = b >> 4;
            let lo = b & 0x0F;
            line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
            pos += 1;
            line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
            pos += 1;
            i += 1;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let mut bad = tok;
    bad.bytes[0] ^= 0x01;
    if StackCanaryImpl::verify(&tok, &bad).is_ok() {
        panic!("CANARY banner: mismatch not detected");
    }
    let fp = StackCanaryImpl::fail_fingerprint(&tok, &bad);
    if (fp & 0xFF) != 1 {
        panic!("CANARY banner: fingerprint drift");
    }
    serial_write_bytes(b"CANARY fail OK reason=mismatch\n");
}

// TASK-069: Keyboard set-1 stream a/b.
#[cfg(not(proteus_prod))]
fn banner_keyboard() {
    use proteus_contracts::{KeyCode, Keyboard, KBD_BREAK_A, KBD_BREAK_B, KBD_MAKE_A, KBD_MAKE_B};
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

// TASK-070: FAT32 mount + HELLO.TXT read.
#[cfg(not(proteus_prod))]
fn banner_fat32() {
    use proteus_contracts::Fat32;
    use target_enterprise::fat32::{
        build_banner_fixture, FAT_FIXTURE_BYTES, FAT_HELLO_83, FAT_HELLO_BODY, FAT_HELLO_LEN,
        Fat32Impl,
    };

    let mut img = [0u8; FAT_FIXTURE_BYTES];
    if build_banner_fixture(&mut img).is_err() {
        panic!("FAT banner: fixture failed");
    }
    let fs = match Fat32Impl::mount(&img) {
        Ok(f) => f,
        Err(_) => panic!("FAT banner: mount failed"),
    };
    if fs.bpb().num_fats != 2 || fs.bpb().root_cluster != 2 {
        panic!("FAT banner: bpb drift");
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"FAT mount OK fats=2 root_clus=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(fs.bpb().root_cluster as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
    let ent = match fs.lookup_root(&img, &FAT_HELLO_83) {
        Ok(e) => e,
        Err(_) => panic!("FAT banner: lookup failed"),
    };
    let mut body = [0u8; 32];
    let n = match fs.read_file(&img, &ent, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("FAT banner: read failed"),
    };
    if n != FAT_HELLO_LEN {
        panic!("FAT banner: len drift");
    }
    let mut j = 0usize;
    while j < n {
        if body[j] != FAT_HELLO_BODY[j] {
            panic!("FAT banner: body drift");
        }
        j += 1;
    }
    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"FAT read OK name=HELLO.TXT bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-066: Disk quota wire codec. Builds a 3-uid fixture, scans
// it, looks up uid 1001 (at block limit), and asserts a +1 block
// write is rejected with BlockLimit.
// Banners: `QUOTA scan OK records=3` +
// `QUOTA reject OK uid=1001 reason=block_limit`.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_quota() {
    use proteus_contracts::{Quota, QuotaReject};
    use target_enterprise::quota::{build_banner_fixture, BANNER_NOW_UNIX, QuotaImpl};

    let mut buf = [0u8; 96];
    match build_banner_fixture(&mut buf) {
        Ok(n) if n == 96 => {}
        _ => panic!("QUOTA banner: fixture build failed"),
    }
    let mut count = 0usize;
    match QuotaImpl::scan(&buf, &mut |_| count += 1) {
        Ok(n) if n == 3 && count == 3 => {}
        _ => panic!("QUOTA banner: scan drift"),
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"QUOTA scan OK records=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(count as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let rec = match QuotaImpl::lookup(&buf, 1001) {
        Ok(r) => r,
        Err(_) => panic!("QUOTA banner: lookup 1001 failed"),
    };
    match QuotaImpl::check_write(&rec, 1, 0, BANNER_NOW_UNIX) {
        Err(QuotaReject::BlockLimit) => {}
        _ => panic!("QUOTA banner: expected BlockLimit reject"),
    }

    {
        let msg = b"QUOTA reject OK uid=1001 reason=block_limit\n";
        serial_write_bytes(msg);
    }
}

// TASK-065: GDB RSP wire codec. Parses the locked `$g#67` frame
// (read-registers), classifies it, builds the 256-zero register
// reply, re-frames it, and asserts the checksum digits are `00`.
// Banner: `GDBSTUB parse OK cmd=g cksum=67`.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_gdbstub() {
    use proteus_contracts::{GdbCommand, GdbStub};
    use target_enterprise::gdbstub::GdbStubImpl;

    let frame = b"$g#67";
    let pkt = match GdbStubImpl::parse_frame(frame) {
        Ok(p) => p,
        Err(_) => panic!("GDBSTUB banner: parse failed"),
    };
    if pkt.body != b"g" {
        panic!("GDBSTUB banner: body drift");
    }
    if pkt.checksum != 0x67 {
        panic!("GDBSTUB banner: checksum drift");
    }
    let cmd = GdbStubImpl::classify(pkt.body);
    if cmd != GdbCommand::ReadRegisters {
        panic!("GDBSTUB banner: classify drift");
    }
    let mut body = [0u8; 256];
    let n = match GdbStubImpl::reply_body(&cmd, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("GDBSTUB banner: reply failed"),
    };
    if n != 256 {
        panic!("GDBSTUB banner: reply length drift");
    }
    // Re-frame and verify checksum digits of the all-zero reply.
    let mut out_frame = [0u8; 512];
    let flen = match GdbStubImpl::build_frame(&body[..n], &mut out_frame) {
        Ok(n) => n,
        Err(_) => panic!("GDBSTUB banner: build_frame failed"),
    };
    // Last two bytes must be hex of checksum(256 × '0') = 0x00.
    if out_frame[flen - 2] != b'0' || out_frame[flen - 1] != b'0' {
        panic!("GDBSTUB banner: reply frame cksum drift");
    }
    // Round-trip parse.
    match GdbStubImpl::parse_frame(&out_frame[..flen]) {
        Ok(p) if p.body.len() == 256 && p.checksum == 0 => {}
        _ => panic!("GDBSTUB banner: reply reparse failed"),
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"GDBSTUB parse OK cmd=g cksum=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        // Two hex digits of 0x67.
        let cs: u8 = 0x67;
        let hi = cs >> 4;
        let lo = cs & 0x0F;
        line[pos] = if hi < 10 { b'0' + hi } else { b'a' + (hi - 10) };
        pos += 1;
        line[pos] = if lo < 10 { b'0' + lo } else { b'a' + (lo - 10) };
        pos += 1;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-064: JFS image walker. Builds the locked 4-sector fixture
// (root dir + hello.txt), mounts it, looks up `/hello.txt`, reads
// the body, and asserts byte-equality + Fletcher-32 fingerprint.
// Banners: `JFS mount OK root_ino=1 inodes=3` and
// `JFS read OK path=/hello.txt bytes=16 sha=aa3ce1c0`.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_jfs() {
    use proteus_contracts::{JournalFs, JFS_ROOT_INODE};
    use target_enterprise::jfs::{
        build_banner_fixture, fletcher32_body, FIXTURE_BYTES, HELLO_BODY, HELLO_BODY_FLETCHER32,
        HELLO_BODY_LEN, JfsImpl,
    };

    let mut img = [0u8; FIXTURE_BYTES];
    match build_banner_fixture(&mut img) {
        Ok(n) if n == FIXTURE_BYTES => {}
        _ => panic!("JFS banner: fixture build failed"),
    }
    let fs = match JfsImpl::mount(&img) {
        Ok(f) => f,
        Err(_) => panic!("JFS banner: mount failed"),
    };
    let sb = fs.superblock();
    if sb.root_inode != JFS_ROOT_INODE {
        panic!("JFS banner: root_inode drift");
    }
    if sb.inode_count != 3 {
        panic!("JFS banner: inode_count drift");
    }

    {
        let mut line = [0u8; 64];
        let mut pos = 0usize;
        let prefix = b"JFS mount OK root_ino=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(sb.root_inode as u64, &mut line[pos..]);
        let mid = b" inodes=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(sb.inode_count as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    let ino = match fs.lookup(&img, sb.root_inode, b"hello.txt") {
        Ok(i) => i,
        Err(_) => panic!("JFS banner: lookup hello.txt failed"),
    };
    let mut body = [0u8; 64];
    let n = match fs.read_file(&img, ino, &mut body) {
        Ok(n) => n,
        Err(_) => panic!("JFS banner: read_file failed"),
    };
    if n != HELLO_BODY_LEN {
        panic!("JFS banner: body length drift");
    }
    let mut i = 0usize;
    while i < n {
        if body[i] != HELLO_BODY[i] {
            panic!("JFS banner: body byte drift");
        }
        i += 1;
    }
    let fp = fletcher32_body(&body[..n]);
    if fp != HELLO_BODY_FLETCHER32 {
        panic!("JFS banner: fletcher drift");
    }

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"JFS read OK path=/hello.txt bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        let mid = b" sha=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // 8 lowercase hex digits of the fletcher fingerprint.
        let mut shift = 28i32;
        while shift >= 0 {
            let nibble = ((fp >> shift) & 0xF) as u8;
            line[pos] = if nibble < 10 {
                b'0' + nibble
            } else {
                b'a' + (nibble - 10)
            };
            pos += 1;
            shift -= 4;
        }
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-063: Crypto KAT harness. Runs the locked 9-vector suite
// (SHA-256 empty/abc/million-a, HMAC RFC 4231 cases 1-4, HKDF RFC
// 5869 cases 1-2) against the real TLS crypto primitives. Any
// digest drift panics; on full pass emits
// `KAT all OK vectors=9`. A morph that perturbs SHA-256, HMAC, or
// HKDF arithmetic panics inside `banner_kat` and the banner never
// appears.
// ============================================================
#[cfg(not(proteus_prod))]
fn banner_kat() {
    use proteus_contracts::{KatRunner, KAT_VECTOR_COUNT};
    use target_enterprise::kat::KatImpl;

    let suite = KatImpl::run_all();
    if suite.total != KAT_VECTOR_COUNT {
        panic!("KAT banner: suite cardinality drift");
    }
    if !suite.all_ok() {
        panic!("KAT banner: vector failure");
    }
    if suite.passed != KAT_VECTOR_COUNT {
        panic!("KAT banner: passed count drift");
    }

    {
        let mut line = [0u8; 48];
        let mut pos = 0usize;
        let prefix = b"KAT all OK vectors=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(suite.passed as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// TASK-060: X.509 v3 DER parser. The kernel parses the locked
// 257-byte Ed25519 self-signed fixture in
// `kernel_fixtures::X509_FIXTURE_DER`, asserts the recovered
// version / serial / validity window / pubkey / subject CN match
// the locked goldens byte-for-byte, then emits two banners. A
// morph that perturbs any byte position in the TLV walker, the
// SPKI BIT STRING decode, or the UTCTime arithmetic panics inside
// `banner_x509` and the banners never appear.
#[cfg(not(proteus_prod))]
fn banner_x509() {
    use proteus_contracts::{X509PubKey, X509PubKeyAlg, X509Time, X509};
    use target_enterprise::x509::X509Impl;

    let cert = match X509Impl::parse(kf::X509_FIXTURE_DER) {
        Ok(c) => c,
        Err(_) => panic!("X509 banner: parse failed"),
    };
    if cert.version != 2 {
        panic!("X509 banner: version drift");
    }
    if cert.pubkey_alg != X509PubKeyAlg::Ed25519 {
        panic!("X509 banner: pubkey_alg drift");
    }
    if cert.serial.len() != 1 || cert.serial[0] != kf::X509_FIXTURE_SERIAL {
        panic!("X509 banner: serial drift");
    }
    if cert.not_before.unix != kf::X509_FIXTURE_NOT_BEFORE_UNIX {
        panic!("X509 banner: not_before drift");
    }
    if cert.not_after.unix != kf::X509_FIXTURE_NOT_AFTER_UNIX {
        panic!("X509 banner: not_after drift");
    }
    match cert.pubkey {
        X509PubKey::Ed25519 { key } => {
            if key != kf::X509_FIXTURE_PUBKEY {
                panic!("X509 banner: pubkey bytes drift");
            }
        }
        _ => panic!("X509 banner: pubkey variant drift"),
    }
    if !X509Impl::validity_contains(&cert, X509Time { unix: 1_700_000_000 }) {
        panic!("X509 banner: validity window drift");
    }
    if cert.issuer != cert.subject {
        panic!("X509 banner: self-signed DN drift");
    }
    if X509Impl::issuer_matches_subject(&cert, &cert).is_err() {
        panic!("X509 banner: issuer/subject match drift");
    }

    // Emit parse banner: byte length + serial.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"X509 parse OK len=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(kf::X509_FIXTURE_DER.len() as u64, &mut line[pos..]);
        let mid = b" serial=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(cert.serial[0] as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Recover the CN from the subject DN and assert byte-equality.
    let cn = match X509Impl::find_cn(cert.subject) {
        Some(c) => c,
        None => panic!("X509 banner: subject CN missing"),
    };
    if cn != kf::X509_FIXTURE_SUBJECT_CN {
        panic!("X509 banner: CN drift");
    }

    // Emit CN banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"X509 cn OK cn=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        line[pos..pos + cn.len()].copy_from_slice(cn);
        pos += cn.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// TASK-145: live guest durable seal of a fixed empty audit snapshot
/// header (magic-only / zero events). Proves `durable_seal` is linked
/// into the boot image. Does **not** claim implant immunity.
fn banner_durable_seal() {
    use proteus_contracts::{AUDIT_SNAPSHOT_HEADER_LEN, AUDIT_SNAPSHOT_MAGIC};
    use target_enterprise::durable_seal::{seal_bytes, DURABLE_DIGEST_LEN};

    // Empty log snapshot = 20-byte header only (count=0).
    let mut snap = [0u8; AUDIT_SNAPSHOT_HEADER_LEN];
    let magic = AUDIT_SNAPSHOT_MAGIC.to_be_bytes();
    snap[0..4].copy_from_slice(&magic);
    // record_count = 0 already
    let rec_size = (96u32).to_be_bytes(); // AUDIT_EVENT_WIRE_LEN
    snap[8..12].copy_from_slice(&rec_size);
    // high_watermark = 0

    let mut dig = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes(&snap, &mut dig);

    let mut line = [0u8; 80];
    let mut pos = 0usize;
    let prefix = b"DURABLE seal OK dig=";
    line[..prefix.len()].copy_from_slice(prefix);
    pos += prefix.len();
    let mut hex = [0u8; 16]; // first 8 bytes of digest
    hex_encode(&dig, 8, &mut hex);
    line[pos..pos + 16].copy_from_slice(&hex);
    pos += 16;
    line[pos] = b'\n';
    pos += 1;
    serial_write_bytes(&line[..pos]);
}

#[cfg(not(proteus_prod))]
fn banner_panic_dump() {
    // Build the canonical CrashContext.
    let ctx = CrashContext {
        wall_unix: kf::CRASH_WALL_UNIX,
        tsc: kf::CRASH_TSC,
        panic_loc: kf::CRASH_PANIC_LOC,
        message: kf::CRASH_MESSAGE,
        registers: &kf::CRASH_REGISTERS,
        backtrace: &kf::CRASH_BACKTRACE,
        kmsg: kf::CRASH_KMSG,
    };

    let mut buf = [0u8; proteus_contracts::CRASH_DUMP_BYTES];
    let mut sink = MemorySectorSink::new();
    let (lba_start, lba_end) = match PanicDumpImpl::dump_to_sink(&ctx, &mut buf, &mut sink) {
        Ok(t) => t,
        Err(_) => panic!("PanicDumpImpl::dump_to_sink failed"),
    };
    if lba_start != DUMP_START_LBA {
        panic!("panic_dump: lba_start drift");
    }
    if lba_end - lba_start != proteus_contracts::CRASH_DUMP_SECTORS {
        panic!("panic_dump: lba range size drift");
    }

    // Body CRC must verify, AND the recorded CRC must equal the
    // locked expected fixture so a morph that perturbs the layout
    // panics here.
    if PanicDumpImpl::verify_crc(&buf).is_err() {
        panic!("panic_dump: verify_crc returned Err for own dump");
    }
    let header = match PanicDumpImpl::parse_header(&buf) {
        Ok(h) => h,
        Err(_) => panic!("panic_dump: parse_header rejected own dump"),
    };
    if header.body_crc32c != kf::CRASH_EXPECTED_CRC32C {
        panic!("panic_dump: CRC32-C drift");
    }
    if header.kmsg_len as usize != kf::CRASH_KMSG.len() {
        panic!("panic_dump: kmsg_len drift");
    }
    if header.backtrace_count as usize != kf::CRASH_BACKTRACE.len() {
        panic!("panic_dump: backtrace_count drift");
    }
    if header.register_count as usize != proteus_contracts::CRASH_REG_COUNT {
        panic!("panic_dump: register_count drift");
    }
    // Header strings must round-trip.
    if header.panic_loc.as_bytes() != kf::CRASH_PANIC_LOC.as_bytes() {
        panic!("panic_dump: panic_loc drift");
    }
    if header.message.as_bytes() != kf::CRASH_MESSAGE.as_bytes() {
        panic!("panic_dump: message drift");
    }

    // Sink must have received every sector in ascending LBA order.
    if sink.recorded != 32 {
        panic!("panic_dump: sink missed a sector");
    }
    let mut k = 1usize;
    while k < sink.recorded {
        if sink.recorded_lbas[k] <= sink.recorded_lbas[k - 1] {
            panic!("panic_dump: sector LBAs not strictly ascending");
        }
        k += 1;
    }

    // Disk bytes received by the sink must equal the build_dump output.
    let mut i = 0usize;
    while i < proteus_contracts::CRASH_DUMP_BYTES {
        if sink.disk[i] != buf[i] {
            panic!("panic_dump: sink/buf byte drift");
        }
        i += 1;
    }

    // Backtrace recovery must round-trip.
    let mut extracted_bt = [0u64; proteus_contracts::CRASH_BACKTRACE_MAX];
    let bt_n = match PanicDumpImpl::extract_backtrace(&buf, &mut extracted_bt) {
        Ok(n) => n,
        Err(_) => panic!("panic_dump: extract_backtrace failed"),
    };
    if bt_n != kf::CRASH_BACKTRACE.len() {
        panic!("panic_dump: extracted backtrace length drift");
    }
    let mut j = 0usize;
    while j < bt_n {
        if extracted_bt[j] != kf::CRASH_BACKTRACE[j] {
            panic!("panic_dump: backtrace frame drift");
        }
        j += 1;
    }

    // Emit the dump banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"CRASH_DUMP wrote 16384 bytes to lba=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(DUMP_START_LBA, &mut line[pos..]);
        let mid = b" crc=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        let crc_be = header.body_crc32c.to_be_bytes();
        let mut crc_hex = [0u8; 8];
        hex_encode(&crc_be, 4, &mut crc_hex);
        line[pos..pos + 8].copy_from_slice(&crc_hex);
        pos += 8;
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }

    // Hand-built kernel-symbol fixture matching CRASH_BACKTRACE.
    const SYMBOLS: &[SymbolEntry] = &[
        SymbolEntry::new(0xFFFF_FFFF_8010_0000, 0x100, "kernel_main"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0500, 0x200, "schedule_next_task"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0800, 0x100, "handle_irq_timer"),
        SymbolEntry::new(0xFFFF_FFFF_8010_0A00, 0x080, "halt_forever"),
    ];
    if !StaticSymbolResolver::is_sorted_by_addr(SYMBOLS) {
        panic!("panic_dump: kernel-symbol fixture is unsorted");
    }
    let resolver = StaticSymbolResolver::new(SYMBOLS);
    if resolver.symbol_count() != 4 {
        panic!("panic_dump: symbol_count drift");
    }

    // Resolve every recovered frame; assert the first matches the
    // locked expected name/offset.
    let (first_name, first_off) = match resolver.resolve(extracted_bt[0]) {
        Some(t) => t,
        None => panic!("panic_dump: first frame did not resolve"),
    };
    if first_name.as_bytes() != kf::CRASH_EXPECTED_RESOLVE_NAME.as_bytes() {
        panic!("panic_dump: resolved name drift");
    }
    if first_off != kf::CRASH_EXPECTED_RESOLVE_OFFSET {
        panic!("panic_dump: resolved offset drift");
    }
    let mut m = 0usize;
    while m < bt_n {
        if resolver.resolve(extracted_bt[m]).is_none() {
            panic!("panic_dump: a backtrace frame did not resolve");
        }
        m += 1;
    }

    // Emit the resolver banner.
    {
        let mut line = [0u8; 96];
        let mut pos = 0usize;
        let prefix = b"SYMBOL resolve OK ";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        let nb = first_name.as_bytes();
        line[pos..pos + nb.len()].copy_from_slice(nb);
        pos += nb.len();
        let mid = b"+0x";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        // Lowercase hex of first_off, MSB-first, no leading zeros.
        let mut nyb = 16i32; // count leading non-zero nybbles
        while nyb > 0 {
            let shift = (nyb - 1) * 4;
            if ((first_off >> shift) & 0xF) != 0 {
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
                let n = ((first_off >> (nn * 4)) & 0xF) as u8;
                line[pos] = if n < 10 { b'0' + n } else { b'a' + (n - 10) };
                pos += 1;
            }
        }
        let mid2 = b" (";
        line[pos..pos + mid2.len()].copy_from_slice(mid2);
        pos += mid2.len();
        pos += dec_u64(bt_n as u64, &mut line[pos..]);
        let mid3 = b" frames)";
        line[pos..pos + mid3.len()].copy_from_slice(mid3);
        pos += mid3.len();
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

// ============================================================
// Anti-sprawl live composition banners
// ============================================================
//
// Isolated per-module banners prove each codec alone. These prove
// the *integration* risk: PIT program → tick mux → watchdog pet/fire,
// and quota check-on-write gating a real VFS create/write. A morph
// that diversifies one side of the pair but breaks the glue panics
// here and suppresses PROTEUS-TE HALT.

/// TIMEBASE compose: PIT 1 kHz program + TickSource (PIT then HPET)
/// drives Watchdog arm → tick → pet → fire.
///
/// Banner: `TIMEBASE compose OK pit_div=1193 pet_rem=5 fire=timeout`
#[cfg(not(proteus_prod))]
fn banner_timebase_compose() {
    use proteus_contracts::{
        PicTimer, TickKind, TickSource, Watchdog, WatchdogError, PIT_CH0_PORT,
        PIT_CMD_CH0_LOHI_MODE3_BIN, PIT_CMD_PORT,
    };
    use target_enterprise::tick_source::TickSourceImpl;
    use target_enterprise::timer::{PicTimerImpl, RecordingIoPort};
    use target_enterprise::watchdog::WatchdogImpl;

    // ---- PIT program (same locked 1 kHz path as banner_timer) ----
    let mut port = RecordingIoPort::new();
    let div = match PicTimerImpl::program_hz(&mut port, 1000) {
        Ok(d) => d,
        Err(_) => panic!("TIMEBASE compose: program_hz failed"),
    };
    if div != 1193 {
        panic!("TIMEBASE compose: divisor drift");
    }
    if port.write_count() != 3 {
        panic!("TIMEBASE compose: PIT write count drift");
    }
    let w0 = port.write_at(0).expect("TIMEBASE compose: missing PIT cmd");
    if w0.port != PIT_CMD_PORT || w0.value != PIT_CMD_CH0_LOHI_MODE3_BIN {
        panic!("TIMEBASE compose: PIT cmd byte drift");
    }
    let w1 = port.write_at(1).expect("TIMEBASE compose: missing lo");
    let w2 = port.write_at(2).expect("TIMEBASE compose: missing hi");
    if w1.port != PIT_CH0_PORT || w1.value != 0xA9 || w2.port != PIT_CH0_PORT || w2.value != 0x04 {
        panic!("TIMEBASE compose: PIT divisor bytes drift");
    }

    // ---- Tick mux: arm watchdog from PIT ticks, pet, then fire ----
    let mut ticks = TickSourceImpl::new();
    ticks.select(TickKind::Pit);
    let mut wd = WatchdogImpl::new();
    // deadline = 5 ticks (locked composition constant)
    if wd.arm(5).is_err() {
        panic!("TIMEBASE compose: arm failed");
    }
    // Advance 2 PIT ticks → 2 watchdog ticks
    ticks.advance(2);
    if ticks.now_ticks() != 2 {
        panic!("TIMEBASE compose: PIT ticks drift");
    }
    if wd.tick().is_err() || wd.tick().is_err() {
        panic!("TIMEBASE compose: early tick failed");
    }
    if wd.remaining() != 3 {
        panic!("TIMEBASE compose: remaining after 2 ticks drift");
    }
    // Pet resets remaining to deadline
    if wd.pet().is_err() {
        panic!("TIMEBASE compose: pet failed");
    }
    if wd.remaining() != 5 {
        panic!("TIMEBASE compose: pet remaining drift");
    }
    let pet_rem = wd.remaining();

    // Switch to HPET counter (independent) and fire watchdog via ticks
    ticks.select(TickKind::Hpet);
    ticks.advance(1);
    if ticks.kind() != TickKind::Hpet || ticks.now_ticks() != 1 {
        panic!("TIMEBASE compose: HPET switch drift");
    }
    // Fire: 5 ticks exhaust remaining
    let mut i = 0u32;
    while i < 4 {
        if wd.tick().is_err() {
            panic!("TIMEBASE compose: fire path early error");
        }
        i += 1;
    }
    match wd.tick() {
        Err(WatchdogError::Fired) => {}
        _ => panic!("TIMEBASE compose: expected Fired"),
    }

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"TIMEBASE compose OK pit_div=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(div as u64, &mut line[pos..]);
        let mid = b" pet_rem=";
        line[pos..pos + mid.len()].copy_from_slice(mid);
        pos += mid.len();
        pos += dec_u64(pet_rem as u64, &mut line[pos..]);
        let tail = b" fire=timeout\n";
        line[pos..pos + tail.len()].copy_from_slice(tail);
        pos += tail.len();
        serial_write_bytes(&line[..pos]);
    }
}

/// VFS + QUOTA compose: check_write gates a real VFS create/write.
///
/// uid 1000 (healthy) is allowed → write 8 bytes to `/var/ok`.
/// uid 1001 (at block limit) is rejected → no write attempted.
///
/// Banner: `VFS+QUOTA compose OK allow=1000 reject=1001 bytes=8`
#[cfg(not(proteus_prod))]
fn banner_vfs_quota_compose() {
    use proteus_contracts::{
        Filesystem, Quota, QuotaReject, Vfs, FS_O_CREATE, FS_O_RDWR, FS_O_RDONLY,
    };
    use target_enterprise::quota::{build_banner_fixture, BANNER_NOW_UNIX, QuotaImpl};
    use target_enterprise::vfs::{MemRamFs, VfsImpl};

    // ---- Quota fixture (same locked 3-uid table) ----
    let mut qbuf = [0u8; 96];
    match build_banner_fixture(&mut qbuf) {
        Ok(n) if n == 96 => {}
        _ => panic!("VFS+QUOTA compose: fixture failed"),
    }

    // Allow path: uid 1000 can take +1 block +1 inode
    let rec_ok = match QuotaImpl::lookup(&qbuf, 1000) {
        Ok(r) => r,
        Err(_) => panic!("VFS+QUOTA compose: lookup 1000 failed"),
    };
    if QuotaImpl::check_write(&rec_ok, 1, 1, BANNER_NOW_UNIX).is_err() {
        panic!("VFS+QUOTA compose: uid 1000 should allow");
    }

    // Reject path: uid 1001 at hard block limit
    let rec_bad = match QuotaImpl::lookup(&qbuf, 1001) {
        Ok(r) => r,
        Err(_) => panic!("VFS+QUOTA compose: lookup 1001 failed"),
    };
    match QuotaImpl::check_write(&rec_bad, 1, 0, BANNER_NOW_UNIX) {
        Err(QuotaReject::BlockLimit) => {}
        _ => panic!("VFS+QUOTA compose: uid 1001 should BlockLimit"),
    }

    // ---- Only the allowed write hits VFS ----
    static mut COMPOSE_RAMFS: ComposeVfsArena = ComposeVfsArena::new();
    let fs_ref: &'static mut MemRamFs<8, 4096> = unsafe {
        // Safety: single-threaded kernel banner; exclusive use of
        // COMPOSE_RAMFS for this function only.
        &mut *core::ptr::addr_of_mut!(COMPOSE_RAMFS.fs)
    };

    let mut vfs: VfsImpl<8> = VfsImpl::new();
    if vfs.mount(b"/", fs_ref as &mut dyn Filesystem).is_err() {
        panic!("VFS+QUOTA compose: mount failed");
    }

    // After the allow gate, create + write. Ramfs CREATE reserves a
    // 256-byte pool slot — enough for the locked 8-byte payload.
    let h = match <VfsImpl<8> as Vfs>::open(
        &mut vfs,
        b"/var/ok",
        FS_O_RDWR | FS_O_CREATE,
    ) {
        Ok(h) => h,
        Err(_) => panic!("VFS+QUOTA compose: open failed"),
    };
    const PAYLOAD: &[u8] = b"proteus\n";
    let n = match <VfsImpl<8> as Vfs>::write(&mut vfs, h, 0, PAYLOAD) {
        Ok(n) => n,
        Err(_) => panic!("VFS+QUOTA compose: write failed"),
    };
    if n != PAYLOAD.len() {
        panic!("VFS+QUOTA compose: write length drift");
    }
    if <VfsImpl<8> as Vfs>::close(&mut vfs, h).is_err() {
        panic!("VFS+QUOTA compose: close failed");
    }

    // Read-back proves the write stuck (quota gate + VFS path linked)
    let h2 = match <VfsImpl<8> as Vfs>::open(&mut vfs, b"/var/ok", FS_O_RDONLY) {
        Ok(h) => h,
        Err(_) => panic!("VFS+QUOTA compose: reopen failed"),
    };
    let mut rbuf = [0u8; 16];
    let rn = match <VfsImpl<8> as Vfs>::read(&mut vfs, h2, 0, &mut rbuf) {
        Ok(n) => n,
        Err(_) => panic!("VFS+QUOTA compose: read failed"),
    };
    if rn != PAYLOAD.len() {
        panic!("VFS+QUOTA compose: read length drift");
    }
    let mut k = 0usize;
    while k < PAYLOAD.len() {
        if rbuf[k] != PAYLOAD[k] {
            panic!("VFS+QUOTA compose: read byte drift");
        }
        k += 1;
    }
    let _ = <VfsImpl<8> as Vfs>::close(&mut vfs, h2);

    {
        let mut line = [0u8; 72];
        let mut pos = 0usize;
        let prefix = b"VFS+QUOTA compose OK allow=1000 reject=1001 bytes=";
        line[..prefix.len()].copy_from_slice(prefix);
        pos += prefix.len();
        pos += dec_u64(n as u64, &mut line[pos..]);
        line[pos] = b'\n';
        pos += 1;
        serial_write_bytes(&line[..pos]);
    }
}

/// Separate BSS arena so compose banner does not share state with
/// `banner_vfs`'s `RAMFS`.
struct ComposeVfsArena {
    fs: MemRamFs<8, 4096>,
}

impl ComposeVfsArena {
    const fn new() -> Self {
        ComposeVfsArena {
            fs: MemRamFs::new(),
        }
    }
}

// ============================================================
// Entry + panic handler + halt
// ============================================================

fn kernel_main(boot_info: &'static mut BootInfo) -> ! {
    set_phys_offset(boot_info);
    serial_init();
    serial_write_str("PROTEUS-TE OK\n");
    // Distinguishes production boots externally; absent in banner builds.
    #[cfg(proteus_prod)]
    serial_write_str("PROTEUS-TE PROD\n");

    // Per-feature proof sequence. Each helper asserts against the
    // locked fixtures (panic on mismatch → handler emits PANIC banner,
    // QEMU smoke fails) and emits one line on success.
    #[cfg(not(proteus_prod))]
    banner_tls_hkdf();
    #[cfg(not(proteus_prod))]
    banner_tls_server_hello();
    #[cfg(not(proteus_prod))]
    banner_tls_client();
    // Cross-morph session continuity (Class B): RFC 8446 resumption PSK
    // survives a sealed-blob round trip; successor derives the same
    // early secret.
    #[cfg(not(proteus_prod))]
    banner_tls_resumption();
    #[cfg(not(proteus_prod))]
    banner_wal_replay();
    #[cfg(not(proteus_prod))]
    banner_iommu_translate();
    #[cfg(not(proteus_prod))]
    banner_hash_digest();
    #[cfg(not(proteus_prod))]
    banner_net_build();
    #[cfg(not(proteus_prod))]
    banner_kpti();
    #[cfg(not(proteus_prod))]
    banner_dma();
    #[cfg(not(proteus_prod))]
    banner_nvme();
    #[cfg(not(proteus_prod))]
    banner_tcp();
    #[cfg(not(proteus_prod))]
    banner_http();
    #[cfg(not(proteus_prod))]
    banner_dns();
    #[cfg(not(proteus_prod))]
    banner_icmp();
    #[cfg(not(proteus_prod))]
    banner_eth();
    #[cfg(not(proteus_prod))]
    banner_arp();
    #[cfg(not(proteus_prod))]
    banner_dhcp();
    #[cfg(not(proteus_prod))]
    banner_virtio_net();
    #[cfg(not(proteus_prod))]
    banner_virtio_blk();
    #[cfg(not(proteus_prod))]
    banner_e1000();
    #[cfg(not(proteus_prod))]
    banner_firewall();
    #[cfg(not(proteus_prod))]
    banner_tpm();
    #[cfg(not(proteus_prod))]
    banner_audit();
    #[cfg(not(proteus_prod))]
    banner_sntp();
    #[cfg(not(proteus_prod))]
    banner_vfs();
    #[cfg(not(proteus_prod))]
    banner_ebpf();
    #[cfg(not(proteus_prod))]
    banner_smp();
    #[cfg(not(proteus_prod))]
    banner_tftp();
    #[cfg(not(proteus_prod))]
    banner_pci();
    #[cfg(not(proteus_prod))]
    banner_x509();
    #[cfg(not(proteus_prod))]
    banner_timer();
    #[cfg(not(proteus_prod))]
    banner_kat();
    #[cfg(not(proteus_prod))]
    banner_jfs();
    #[cfg(not(proteus_prod))]
    banner_gdbstub();
    #[cfg(not(proteus_prod))]
    banner_quota();
    #[cfg(not(proteus_prod))]
    banner_hpet();
    #[cfg(not(proteus_prod))]
    banner_canary();
    #[cfg(not(proteus_prod))]
    banner_keyboard();
    #[cfg(not(proteus_prod))]
    banner_fat32();
    #[cfg(not(proteus_prod))]
    banner_watchdog();
    #[cfg(not(proteus_prod))]
    banner_rng();
    #[cfg(not(proteus_prod))]
    banner_power();
    #[cfg(not(proteus_prod))]
    banner_elf();
    #[cfg(not(proteus_prod))]
    banner_serial();
    #[cfg(not(proteus_prod))]
    banner_tick();
    #[cfg(not(proteus_prod))]
    banner_virtio_caps();
    #[cfg(not(proteus_prod))]
    banner_sigkat();
    #[cfg(not(proteus_prod))]
    banner_mb2();
    #[cfg(not(proteus_prod))]
    banner_crc32c();
    #[cfg(not(proteus_prod))]
    banner_rsdp();
    #[cfg(not(proteus_prod))]
    banner_frame();
    #[cfg(not(proteus_prod))]
    banner_ioapic();
    #[cfg(not(proteus_prod))]
    banner_lapic();
    #[cfg(not(proteus_prod))]
    banner_gpt();
    #[cfg(not(proteus_prod))]
    banner_dns_name();
    #[cfg(not(proteus_prod))]
    banner_drbg();
    #[cfg(not(proteus_prod))]
    banner_ahci_fis();
    #[cfg(not(proteus_prod))]
    banner_xhci_trb();
    #[cfg(not(proteus_prod))]
    banner_uefi_gop();
    #[cfg(not(proteus_prod))]
    banner_attest_tlv();
    #[cfg(not(proteus_prod))]
    banner_base64();
    #[cfg(not(proteus_prod))]
    banner_ahci_cmd();
    // Anti-sprawl live composition: codecs wired *together*, not only
    // isolated per-module banners. Proves timer/tick/watchdog,
    // VFS/quota, and AHCI FIS+cmd table call chains survive into the
    // boot image — and (via morphed_qemu_proof) after diversification.
    #[cfg(not(proteus_prod))]
    banner_timebase_compose();
    #[cfg(not(proteus_prod))]
    banner_vfs_quota_compose();
    #[cfg(not(proteus_prod))]
    banner_ahci_storage_compose();
    #[cfg(not(proteus_prod))]
    banner_net_path_compose();
    #[cfg(not(proteus_prod))]
    banner_block_path_compose();
    // TASK-104/107: real PCI + virtqueue I/O for virtio-blk-pci.
    #[cfg(not(proteus_prod))]
    banner_virtio_hw();
    // TASK-109/111: real PCI + TX/RX virtqueues for virtio-net-pci.
    #[cfg(not(proteus_prod))]
    banner_virtio_net_hw();
    // TASK-113/117: real AHCI HBA MMIO + IDENTIFY + sector DMA.
    #[cfg(not(proteus_prod))]
    banner_ahci_hw();
    // Cross-morph durable-state continuity: real WAL replay + persist
    // on the AHCI disk; a morphed successor boot resumes it.
    banner_continuity();
    // REAL WORKLOAD: lived net on the first virtio-net — UDP/8080
    // status, TCP/80 HTTP /status, ICMP echo. Bounded poll loop;
    // exits to HALT when the window closes.
    service_udp_status();
    // TASK-116/120: real e1000 PCI + MMIO + EEPROM MAC + TX DD.
    #[cfg(not(proteus_prod))]
    banner_e1000_hw();
    // TASK-119: real QEMU NVMe admin identify (not MemNvmeController).
    #[cfg(not(proteus_prod))]
    banner_nvme_hw();
    // TASK-145: guest durable seal of empty audit snapshot header.
    banner_durable_seal();
    #[cfg(not(proteus_prod))]
    banner_panic_dump();
    // Interactive OS shell + unified VFS/Scheduler/Audit runtime proof.
    banner_shell_compose();

    // ============================================================
    // RED-TEAM ATTACK HARNESS (deliberate, instrumented vulnerability)
    // ============================================================
    // A serial-port attack surface with a REAL stack buffer overflow,
    // planted so the core-theory experiment can fire a genuine ROP
    // chain at this kernel instead of simulating one. If COM1 delivers
    // the magic bytes "ATK!" followed by exactly ATTACK_READ_LEN bytes,
    // `attack_vulnerable_service` copies all of them into a 64-byte
    // stack buffer with no bounds check. An attacker payload that
    // overwrites the return address with a gadget chain gains control
    // when the function returns. Reachable only via physical/serial
    // access to the boot console — never via the network stack — and
    // the window closes after a short poll, so normal boots are
    // unaffected.
    #[cfg(not(proteus_prod))]
    attack_iface_pilot();

    serial_write_str("PROTEUS-TE HALT\n");
    live_os_console_loop();
}

static mut KERNEL_SHELL: target_enterprise::OsShell = target_enterprise::OsShell::empty();

/// First LBA of the 2-sector (`PRTSSHL1` header + 512-byte WAL) sealed
/// `OsShell` persistence region on the AHCI disk (`LBA 1040..=1041`).
const SHELL_DISK_LBA: u64 = 1040;

fn persist_shell_to_ahci(sh: &mut target_enterprise::OsShell, boots: u64) -> Option<usize> {
    let mut hdr_sec = [0u8; 512];
    let mut wal_sec = [0u8; 512];
    let count = sh.pack_disk_image(boots, &mut hdr_sec, &mut wal_sec).ok()?;
    let port = AhciHwPort::probe_start();
    // Write WAL payload sector first, then header sector last (crash-atomic).
    port.write_sector(SHELL_DISK_LBA + 1, &wal_sec);
    port.write_sector(SHELL_DISK_LBA, &hdr_sec);
    Some(count)
}

fn restore_shell_from_ahci(sh: &mut target_enterprise::OsShell) -> Option<(u64, usize)> {
    let port = AhciHwPort::probe_start();
    let hdr_sec = port.read_sector(SHELL_DISK_LBA);
    if &hdr_sec[0..8] != b"PRTSSHL1" {
        return None;
    }
    let wal_sec = port.read_sector(SHELL_DISK_LBA + 1);
    sh.unpack_disk_image(&hdr_sec, &wal_sec).ok()
}

/// Live composition proof for `OsShell`: seeds the BSS shell, writes and
/// reads back `/var/boot.ok`, spawns PID 5, verifies capability-gated
/// `SYS_OPEN` (`EPERM` before `grant 5 fs`, `ret=0` after), executes user
/// ELF64 `/bin/fib 10`, persists the SHA-256-sealed WAL to physical AHCI
/// sectors `1040..=1041`, and verifies round-trip restoration from AHCI.
fn banner_shell_compose() {
    use target_enterprise::ShellAction;

    let sh: &'static mut target_enterprise::OsShell =
        unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_SHELL) };
    *sh = target_enterprise::OsShell::empty();
    sh.seed_defaults();

    let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
    let mut out = [0u8; 256];

    if boots > 1 {
        if let Some((prev_boots, applied)) = restore_shell_from_ahci(sh) {
            if prev_boots + 1 != boots || applied < 2 {
                panic!("SHELL resume: cross-boot AHCI state drift");
            }
            let ar = sh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
            if &out[..ar.bytes_written()] != b"ready\n" {
                panic!("SHELL resume: cross-boot /var/boot.ok drift");
            }
            serial_write_str("SHELL resume OK\n");
            *sh = target_enterprise::OsShell::empty();
            sh.seed_defaults();
        }
    }

    let a1 = sh.exec_line(b"write /var/boot.ok ready", boots, 0, 0, &mut out);
    if &out[..a1.bytes_written()] != b"wrote 6 bytes to /var/boot.ok\n" {
        panic!("SHELL compose: write /var/boot.ok drift");
    }
    let a2 = sh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a2.bytes_written()] != b"ready\n" {
        panic!("SHELL compose: cat /var/boot.ok drift");
    }
    let a3 = sh.exec_line(b"spawn", boots, 0, 0, &mut out);
    if &out[..a3.bytes_written()] != b"spawned pid=5\n" {
        panic!("SHELL compose: spawn pid=5 drift");
    }
    let a4 = sh.exec_line(b"kill 1", boots, 0, 0, &mut out);
    if &out[..a4.bytes_written()] != b"error: permission denied (protected system task)\n" {
        panic!("SHELL compose: protected kill 1 should deny");
    }
    let a5 = sh.exec_line(b"status", boots, 0, 0, &mut out);
    if !matches!(a5, ShellAction::Continue(_)) || sh.fs.inode_count() != 5 || sh.audit.len() != 5 {
        panic!("SHELL compose: status/audit state drift");
    }

    // Verify capability-gated syscall enforcement + ELF64/KPTI/eBPF exec:
    let a6 = sh.exec_line(b"syscall 5 open /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a6.bytes_written()] != b"syscall denied: EPERM (missing fs capability)\n" {
        panic!("SHELL compose: unprivileged syscall open should deny");
    }
    let a7 = sh.exec_line(b"grant 5 fs", boots, 0, 0, &mut out);
    if &out[..a7.bytes_written()] != b"granted fs on pid=5\n" {
        panic!("SHELL compose: grant 5 fs drift");
    }
    let a8 = sh.exec_line(b"syscall 5 open /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a8.bytes_written()] != b"syscall ok: ret=0\n" {
        panic!("SHELL compose: granted syscall open should succeed");
    }
    let a9 = sh.exec_line(b"exec /bin/fib 10", boots, 0, 0, &mut out);
    if &out[..a9.bytes_written()]
        != b"exec: path=/bin/fib entry=4198400 kpti=isolated insns=11 ret=55\n"
    {
        panic!("SHELL compose: exec /bin/fib 10 drift");
    }
    if sh.ima_measurements != 1 || sh.ima_pcr10 == [0u8; 32] {
        panic!("SHELL compose: IMA/TPM PCR-10 measurement not extended");
    }
    let a10 = sh.exec_line(b"exec /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..a10.bytes_written()] != b"error: EPERM (IMA signature verification failed)\n" {
        panic!("SHELL compose: unsigned binary must be rejected by IMA");
    }
    let a11 = sh.exec_line(b"fw block 192.168.66.0/24", boots, 0, 0, &mut out);
    if &out[..a11.bytes_written()] != b"fw: blocked src=192.168.66.0/24\n" || sh.fw.len() != 1 {
        panic!("SHELL compose: fw block CIDR failed");
    }
    sh.auth_seq = 7;

    // Persist sealed WAL (F + T + W + Q = 4 records) to physical AHCI disk sectors 1040..=1041 and verify round-trip restore:
    if persist_shell_to_ahci(sh, boots) != Some(4) {
        panic!("SHELL compose: AHCI persist expected 4 records");
    }
    static mut VERIFY_SHELL: target_enterprise::OsShell = target_enterprise::OsShell::empty();
    let vsh = unsafe { &mut *core::ptr::addr_of_mut!(VERIFY_SHELL) };
    *vsh = target_enterprise::OsShell::empty();
    vsh.seed_defaults();
    if restore_shell_from_ahci(vsh) != Some((boots, 4)) {
        panic!("SHELL compose: AHCI sealed restore failed");
    }
    if vsh.fw.len() != 1 || vsh.auth_seq != 7 {
        panic!("SHELL compose: AHCI restored fw/auth_seq drift");
    }
    let av = vsh.exec_line(b"cat /var/boot.ok", boots, 0, 0, &mut out);
    if &out[..av.bytes_written()] != b"ready\n" {
        panic!("SHELL compose: AHCI restored /var/boot.ok drift");
    }
    let _ = sh.exec_line(b"fw clear", boots, 0, 0, &mut out);
    sh.auth_seq = 0;

    serial_write_str("SHELL compose OK tasks=5 files=5 audit=5\n");
}

/// Interactive OS console loop over COM1 (0x3F8) and PS/2 keyboard (0x60/0x64).
///
/// Runs after `PROTEUS-TE HALT` so automated smoke/soak harnesses see the
/// completion banner immediately, while interactive sessions (`-serial stdio`
/// or `proteus_prod` builds) stay alive and respond to shell commands.
fn live_os_console_loop() -> ! {
    use proteus_contracts::{KeyCode, Keyboard};
    use target_enterprise::keyboard::KeyboardImpl;
    use target_enterprise::{ShellAction, SHELL_PROMPT};

    let sh: &'static mut target_enterprise::OsShell =
        unsafe { &mut *core::ptr::addr_of_mut!(KERNEL_SHELL) };
    let mut kbd = KeyboardImpl::new();

    #[cfg(proteus_prod)]
    {
        serial_write_str("Proteus Enterprise OS interactive shell ready.\n");
        serial_write_bytes(SHELL_PROMPT);
    }

    let mut echo = [0u8; 32];
    let mut reply = [0u8; 512];

    loop {
        let mut maybe_byte: Option<u8> = None;

        // 1. Poll COM1 (16550 UART LSR bit 0 = data ready).
        if unsafe { inb(COM1 + 5) & 0x01 != 0 } {
            maybe_byte = Some(unsafe { inb(COM1) });
        } else if unsafe { inb(0x64) & 0x01 != 0 } {
            // 2. Poll PS/2 8042 status port (bit 0 = output buffer full).
            let sc = unsafe { inb(0x60) };
            if let Some(ev) = kbd.feed(sc) {
                if ev.pressed {
                    if ev.ascii != 0 {
                        maybe_byte = Some(ev.ascii);
                    } else if ev.code == KeyCode::Enter {
                        maybe_byte = Some(b'\n');
                    } else if ev.code == KeyCode::Backspace {
                        maybe_byte = Some(0x08);
                    }
                }
            }
        }

        if let Some(b) = maybe_byte {
            let boots = CONTINUITY_BOOT_COUNT.load(core::sync::atomic::Ordering::Relaxed);
            let (elen, act) = sh.feed_byte(b, boots, 0, 0, &mut echo, &mut reply);
            if elen > 0 {
                serial_write_bytes(&echo[..elen]);
            }
            let rlen = act.bytes_written();
            if rlen > 0 {
                serial_write_bytes(&reply[..rlen]);
            }
            match act {
                ShellAction::Continue(_) => {}
                ShellAction::Halt(_) => {
                    let _ = persist_shell_to_ahci(sh, boots);
                    // QEMU/Bochs ACPI PM1a_CNT S5 poweroff (0x604 <- 0x2000).
                    unsafe { outw(0x604, 0x2000) };
                    halt_forever();
                }
                ShellAction::Reboot(_) => {
                    let _ = persist_shell_to_ahci(sh, boots);
                    // 8042 keyboard controller CPU reset pulse (0x64 <- 0xFE).
                    unsafe { outb(0x64, 0xFE) };
                    halt_forever();
                }
            }
        } else {
            core::hint::spin_loop();
        }
    }
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    serial_write_str("PROTEUS-TE PANIC: ");
    // Prefer the panic payload so hardware-path failures are diagnosable
    // from the QEMU serial log without a debugger.
    {
        use core::fmt::Write;
        struct Sw;
        impl Write for Sw {
            fn write_str(&mut self, s: &str) -> core::fmt::Result {
                serial_write_str(s);
                Ok(())
            }
        }
        let _ = write!(Sw, "{}", info.message());
    }
    serial_write_str(" @ ");
    if let Some(loc) = info.location() {
        serial_write_str(loc.file());
    }
    serial_write_str("\n");
    halt_forever();
}

fn halt_forever() -> ! {
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

// ============================================================
// RED-TEAM ATTACK HARNESS — see the call site above kernel_main's HALT
// ============================================================

/// Payload length the vulnerable service reads. Sized by disassembly +
/// fault forensics: saved return address is ~0x88 above buf, but the
/// kernel stack page ends ~0xD0 above the frame — writes past that
/// guard boundary fault mid-copy. 176 bytes covers the chain zone
/// (ret slot + ret-sled + win) while staying mapped.
#[cfg(not(proteus_prod))]
const ATTACK_READ_LEN: usize = 176;

/// Blocking read of one byte from COM1 (16550 RBR, polled).
#[cfg(not(proteus_prod))]
fn serial_read_byte() -> u8 {
    unsafe {
        while inb(COM1 + 5) & 0x01 == 0 {
            core::hint::spin_loop();
        }
        inb(COM1)
    }
}

/// Non-blocking check: is a byte waiting on COM1?
#[cfg(not(proteus_prod))]
fn serial_data_ready() -> bool {
    unsafe { inb(COM1 + 5) & 0x01 != 0 }
}

/// Attack entry point: wait (bounded) for the "ATK!" magic on COM1, then
/// run the vulnerable service. The bound keeps normal boots fast — if
/// no attacker shows up, the kernel proceeds to HALT as usual.
#[cfg(not(proteus_prod))]
fn attack_iface_pilot() {
    // Keep `attack_win` linked: nothing calls it legitimately (that is
    // the point — only a hijacked return address lands there), so
    // without a live reference the linker GCs it and the exploit driver
    // loses its symbol. A volatile store of its address defeats GC.
    static mut WIN_SINK: usize = 0;
    unsafe { core::ptr::write_volatile(&raw mut WIN_SINK, attack_win as usize) };
    serial_write_str("ATK IFACE UP\n");
    let max_spins: u32 = if fw_cfg_select("opt/attack.bin").is_some() {
        20_000_000
    } else {
        50_000
    };
    let magic = *b"ATK!";
    let mut matched = 0usize;
    let mut spins = 0u32;
    while matched < magic.len() && spins < max_spins {
        if serial_data_ready() {
            let b = serial_read_byte();
            if b == magic[matched] {
                matched += 1;
            } else {
                matched = if b == magic[0] { 1 } else { 0 };
            }
        } else {
            spins += 1;
            core::hint::spin_loop();
        }
    }
    if matched < magic.len() {
        return; // no attacker this boot
    }
    serial_write_str("ATK ACCEPT\n");
    attack_vulnerable_service();
    // If the overflow did NOT hijack control (defended kernel, or the
    // chain missed), execution survives to here.
    serial_write_str("ATK SVC SURVIVED\n");
}

// --- fw_cfg payload channel (QEMU I/O ports 0x510/0x511) -------------
// The exploit bytes arrive via `-fw_cfg name=opt/attack.bin,file=...`:
// a real, attacker-controlled input channel that (unlike 16550 RX under
// TCG) cannot drop bytes. Serial remains the output/verdict channel.
#[cfg(not(proteus_prod))]
const FW_CFG_CTL: u16 = 0x510;
#[cfg(not(proteus_prod))]
const FW_CFG_DATA: u16 = 0x511;

/// Locate the fw_cfg file named `want` and return its selector. The
/// fw_cfg file directory (key 0x0019) is a BE u32 count followed by
/// entries {u32 size, u16 select, u16 reserved, char name[56]}.
#[cfg(not(proteus_prod))]
fn fw_cfg_select(want: &str) -> Option<u16> {
    unsafe { outw(FW_CFG_CTL, 0x0019) };
    let count = u32::from_be_bytes([
        unsafe { inb(FW_CFG_DATA) },
        unsafe { inb(FW_CFG_DATA) },
        unsafe { inb(FW_CFG_DATA) },
        unsafe { inb(FW_CFG_DATA) },
    ]);
    let mut found: Option<u16> = None;
    for _ in 0..count.min(256) {
        // Entry: u32 size (BE), u16 select (BE), u16 reserved, name[56].
        let mut hdr = [0u8; 8];
        for b in hdr.iter_mut() {
            *b = unsafe { inb(FW_CFG_DATA) };
        }
        let select = u16::from_be_bytes([hdr[4], hdr[5]]);
        let mut name = [0u8; 56];
        for b in name.iter_mut() {
            *b = unsafe { inb(FW_CFG_DATA) };
        }
        let end = name.iter().position(|&c| c == 0).unwrap_or(56);
        if let Ok(n) = core::str::from_utf8(&name[..end]) {
            if n == want {
                found = Some(select);
            }
        }
    }
    found
}

/// The planted vulnerability: an unbounded fw_cfg read into a fixed
/// 64-byte stack buffer, with NO staging buffer — bytes flow from the
/// I/O port straight into the overflowing frame. (A first version
/// staged the payload in a second stack buffer; the compiler placed
/// that buffer above `buf` and it absorbed the overflow, leaving the
/// saved return address untouched. Learned from "ATK SVC SURVIVED".)
/// THIS FUNCTION IS INTENTIONALLY INSECURE — it exists to give the red
/// team a deterministic memory-corruption primitive.
#[inline(never)]
#[cfg(not(proteus_prod))]
fn attack_vulnerable_service() {
    let Some(sel) = fw_cfg_select("opt/attack.bin") else {
        serial_write_str("ATK NO PAYLOAD FILE\n");
        return;
    };
    // Re-selecting rewinds the data cursor to offset 0.
    unsafe { outw(FW_CFG_CTL, sel) };
    let mut buf = [0u8; 64];
    let dst = buf.as_mut_ptr();
    for i in 0..ATTACK_READ_LEN {
        let b = unsafe { inb(FW_CFG_DATA) };
        unsafe { dst.add(i).write_volatile(b) };
    }
    serial_write_str("ATK RD DONE\n");
    // Consume the (possibly overflowed) buffer so the write is not
    // optimized out; a correct kernel prints this and returns safely.
    let mut acc = 0u8;
    for &b in buf.iter() {
        acc = acc.wrapping_add(b);
    }
    if acc == 0xFF {
        serial_write_str("ATK SVC CK\n");
    }
}

/// The attacker's target: proof-of-control function. A successful ROP
/// chain lands here and prints the red-team verdict. `#[no_mangle]` so
/// the exploit driver can resolve its address from the ELF symbol
/// table — exactly what a real attacker does with a leaked symbol.
#[no_mangle]
#[inline(never)]
#[cfg(not(proteus_prod))]
pub extern "C" fn attack_win() -> ! {
    serial_write_str("PWNED\n");
    halt_forever();
}
