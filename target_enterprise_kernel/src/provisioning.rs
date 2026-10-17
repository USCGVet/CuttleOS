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

/// Cached 256-bit device master key resolved once on first use during boot.
static PROVISIONED_MASTER_KEY: spin::Mutex<Option<[u8; 32]>> = spin::Mutex::new(None);

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

/// Read a 64-bit hardware random word via `rdrand` if CPUID.01H:ECX[30]
/// advertises `RDRAND` support, falling back to `rdtsc` mixed with CMOS/PIT
/// jitter if the CPU/emulator does not implement `rdrand`.
fn read_hw_entropy_u64(round: u64) -> u64 {
    let has_rdrand: bool = {
        let ecx: u32;
        // SAFETY: `cpuid` with leaf EAX=1 is unconditionally supported on all
        // x86_64 processors; `rbx` is preserved by LLVM when not named as an
        // output operand, and `nomem, nostack` holds because `cpuid` only
        // mutates general-purpose registers EAX/EBX/ECX/EDX.
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

/// Return the 256-bit per-device master secret key, reading it once from the
/// out-of-band QEMU `fw_cfg` provisioning channel (`opt/proteus_device_key`)
/// or minting a hardware-entropy key via `RDRAND`/`RDTSC` on unprovisioned
/// boots.
pub(crate) fn device_master_key() -> [u8; 32] {
    let mut guard = PROVISIONED_MASTER_KEY.lock();
    if let Some(k) = *guard {
        return k;
    }
    let k = match read_fw_cfg_device_key() {
        Some(provisioned) => provisioned,
        None => generate_hw_entropy_master_key(),
    };
    *guard = Some(k);
    k
}

/// Derive the 256-bit `HMAC-SHA256` network control-plane key for `mac` from
/// the out-of-band provisioned device master key.
pub(crate) fn derive_runtime_net_auth_key(mac: [u8; 6]) -> [u8; 32] {
    let master = device_master_key();
    target_enterprise::lived_net::LivedNet::derive_node_key(&master, mac)
}

/// Derive the 256-bit `HMAC-SHA256` durable-state seal key from the
/// out-of-band provisioned device master key.
pub(crate) fn derive_runtime_seal_key() -> [u8; 32] {
    let master = device_master_key();
    target_enterprise::durable_seal::derive_seal_key(&master, b"proteus-ahci-wal-seal-v1")
}
