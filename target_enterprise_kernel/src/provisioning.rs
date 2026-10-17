//! Out-of-band device secret provisioning and per-device key derivation.
//!
//! Security model:
//! - Neither the network control-plane `HMAC-SHA256` key nor the durable WAL
//!   `HMAC-SHA256` seal key may be derived from public constants in the
//!   source tree or from build seeds embedded in the kernel binary.
//! - On provisioned guests, the host/hypervisor supplies a 32-byte OS-CSPRNG
//!   secret (`device_secret_key.bin`, ignored by `.gitignore`) via the QEMU
//!   `fw_cfg` channel (`opt/proteus_device_key`). This secret resides outside
//!   both the kernel ELF image and the guest AHCI disk image.
//! - On unprovisioned boots (where `opt/proteus_device_key` is absent from
//!   `fw_cfg`), the kernel harvests 256 bits of hardware entropy directly
//!   from the CPU (`RDRAND` when supported by CPUID.01H:ECX[30], mixed with
//!   `RDTSC` jitter and CMOS RTC counter bytes through `HMAC-SHA256`) and
//!   caches that ephemeral master key in `PROVISIONED_MASTER_KEY` for the
//!   lifetime of the boot.

pub(crate) use crate::*;

/// QEMU `fw_cfg` selector path carrying the 32-byte CSPRNG device master key.
pub(crate) const FW_CFG_DEVICE_KEY_PATH: &str = "opt/proteus_device_key";

/// Cached `(master_key, is_fw_cfg_provisioned)` resolved once on first use during boot.
static PROVISIONED_MASTER_KEY: spin::Mutex<Option<([u8; 32], bool)>> = spin::Mutex::new(None);

/// Attempt to read a 32-byte out-of-band device secret key from QEMU `fw_cfg`
/// (`opt/proteus_device_key`). Returns `None` if the entry is absent, shorter
/// than 32 bytes, or all zeros.
fn read_fw_cfg_device_key() -> Option<[u8; 32]> {
    let sel = fw_cfg_select(FW_CFG_DEVICE_KEY_PATH)?;
    // SAFETY: Running at CPL=0 (ring 0); `FW_CFG_CTL` (0x510) is the standard
    // QEMU `fw_cfg` selector register and writing `sel` only latches the
    // active directory stream offset without touching memory or CPU flags.
    unsafe { outw(FW_CFG_CTL, sel) };

    let mut key = [0u8; 32];
    let mut non_zero = false;
    let mut i = 0usize;
    while i < 32 {
        // SAFETY: Running at CPL=0 after latching `sel` on port 0x510; reading
        // `FW_CFG_DATA` (0x511) sequentially streams the next byte of the
        // selected `fw_cfg` blob without aliasing any Rust memory.
        let b = unsafe { inb(FW_CFG_DATA) };
        if b != 0 {
            non_zero = true;
        }
        key[i] = b;
        i += 1;
    }
    if non_zero {
        Some(key)
    } else {
        None
    }
}

/// Read CMOS RTC registers (seconds, minutes, hours, day, month, year) via
/// ports `0x70`/`0x71` and the 8254 PIT channel-0 counter via ports `0x43`/`0x40`.
fn read_cmos_and_pit_word(round: u64) -> u64 {
    const CMOS_REGS: [u8; 6] = [0x00, 0x02, 0x04, 0x07, 0x08, 0x09];
    let mut acc: u64 = 0;
    let mut i = 0usize;
    while i < CMOS_REGS.len() {
        let reg = CMOS_REGS[(i + (round as usize)) % CMOS_REGS.len()];
        // SAFETY: Running at CPL=0; port 0x70 is the standard MC146818 CMOS
        // index register (bit 7 = 0 keeps NMIs enabled, which is safe because
        // the kernel IDT is already installed) and port 0x71 is the read-only
        // RTC data port. Neither aliases memory.
        let val = unsafe {
            outb(0x70, reg & 0x7F);
            inb(0x71)
        };
        acc = (acc << 8) | (val as u64);
        i += 1;
    }
    // SAFETY: Running at CPL=0; writing 0x00 to PIT command port 0x43 latches
    // channel 0's current 16-bit down-counter without altering its mode, and
    // two sequential reads from port 0x40 read low/high counter bytes.
    let pit: u16 = unsafe {
        outb(0x43, 0x00);
        let lo = inb(0x40) as u16;
        let hi = inb(0x40) as u16;
        (hi << 8) | lo
    };
    (acc << 16) ^ (pit as u64)
}

/// Read a 64-bit hardware random word via `rdrand` if CPUID.01H:ECX[30]
/// advertises `RDRAND` support, falling back to `rdtsc` mixed with CMOS RTC
/// registers and the 8254 PIT counter if the CPU/emulator does not implement `rdrand`.
fn read_hw_entropy_u64(round: u64) -> u64 {
    let has_rdrand: bool = {
        let ecx: u32;
        // SAFETY: `cpuid` with leaf EAX=1 is unconditionally supported on all
        // x86_64 processors; `rbx` is preserved by push/pop inside the block,
        // and `nomem` holds because only general-purpose registers are mutated.
        unsafe {
            core::arch::asm!(
                "push rbx",
                "mov eax, 1",
                "cpuid",
                "pop rbx",
                out("eax") _,
                out("ecx") ecx,
                out("edx") _,
                options(nomem, preserves_flags),
            );
        }
        (ecx & (1 << 30)) != 0
    };

    if has_rdrand {
        let mut tries = 0u32;
        while tries < 16 {
            let val: u64;
            let ok: u8;
            // SAFETY: CPUID.01H:ECX[30] confirmed `rdrand` instruction support;
            // `rdrand` writes a hardware-generated 64-bit random value into
            // `val` and sets CF=1 on success without touching memory or stack.
            unsafe {
                core::arch::asm!(
                    "rdrand {val}",
                    "setc {ok}",
                    val = out(reg) val,
                    ok = out(reg_byte) ok,
                    options(nomem, nostack),
                );
            }
            if ok != 0 && val != 0 && val != u64::MAX {
                return val;
            }
            tries += 1;
        }
    }

    let cmos_pit = read_cmos_and_pit_word(round);
    let tsc_lo: u32;
    let tsc_hi: u32;
    // SAFETY: `rdtsc` is always permitted in ring 0 (CR4.TSD is irrelevant at
    // CPL=0) and reads the 64-bit time-stamp counter into EDX:EAX without
    // touching memory or stack.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") tsc_lo,
            out("edx") tsc_hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    let tsc = ((tsc_hi as u64) << 32) | (tsc_lo as u64);
    tsc.wrapping_mul(0x9E37_79B9_7F4A_7C15)
        ^ cmos_pit.wrapping_mul(0xD6E8_FEB8_6659_FD93)
        ^ round.wrapping_mul(0xBF58_476D_1CE4_E5B9)
}

/// Generate a 256-bit boot-ephemeral master key from hardware entropy when no
/// out-of-band `fw_cfg` key was provisioned by the host.
fn generate_hw_entropy_master_key() -> [u8; 32] {
    let mut raw = [0u8; 64];
    let mut r = 0usize;
    while r < 8 {
        let w = read_hw_entropy_u64(r as u64);
        let bytes = w.to_le_bytes();
        let mut j = 0usize;
        while j < 8 {
            raw[r * 8 + j] = bytes[j];
            j += 1;
        }
        r += 1;
    }
    let mut salt = [0u8; 32];
    salt.copy_from_slice(&raw[0..32]);
    let mut out = [0u8; 32];
    target_enterprise::tls::hmac_sha256(&salt, &raw[32..64], &mut out);
    out
}

/// Resolve and return `(master_key, is_fw_cfg_provisioned)`.
fn device_master_key_state() -> ([u8; 32], bool) {
    let mut guard = PROVISIONED_MASTER_KEY.lock();
    if let Some(state) = *guard {
        return state;
    }
    let state = match read_fw_cfg_device_key() {
        Some(provisioned) => (provisioned, true),
        None => (generate_hw_entropy_master_key(), false),
    };
    *guard = Some(state);
    state
}

/// Derive the 256-bit `HMAC-SHA256` network control-plane key for `mac` from
/// the out-of-band provisioned `fw_cfg` device master key. Returns `None` when
/// no key was provisioned via `fw_cfg` so the network service refuses
/// authenticated commands entirely on unprovisioned boots.
pub(crate) fn derive_runtime_net_auth_key(mac: [u8; 6]) -> Option<[u8; 32]> {
    let (master, provisioned) = device_master_key_state();
    if provisioned {
        Some(target_enterprise::lived_net::LivedNet::derive_node_key(&master, mac))
    } else {
        None
    }
}

/// Derive the 256-bit `HMAC-SHA256` durable-state seal key from the
/// out-of-band provisioned device master key (or the boot-ephemeral hardware
/// key on unprovisioned boots).
pub(crate) fn derive_runtime_seal_key() -> [u8; 32] {
    let (master, _) = device_master_key_state();
    target_enterprise::durable_seal::derive_seal_key(&master, b"proteus-ahci-wal-seal-v1")
}

/// Derive the 256-bit `HMAC-SHA256` remote attestation quote key from the
/// out-of-band provisioned device master key (or boot-ephemeral hardware key).
pub(crate) fn derive_runtime_attest_key() -> [u8; 32] {
    let (master, _) = device_master_key_state();
    target_enterprise::durable_seal::derive_attest_key(&master, b"proteus-quote-v1")
}
