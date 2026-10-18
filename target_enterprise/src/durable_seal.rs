//! Guest-side durable-blob hash and keyed HMAC-SHA256 sealing (TASK-142).
//!
//! Pure `no_std` SHA-256 and keyed `HMAC-SHA256` over an opaque byte slice —
//! intended for sealing audit snapshots and WAL/disk state **inside** the
//! enterprise target. Host-side JSON seals live in
//! `cuttle_morph_engine::durable_seal`; this module is the guest twin.
//!
//! - Unkeyed [`seal_bytes`] / [`seal_matches`] compute plain SHA-256 digests
//!   for drift detection and IMA binary hashing.
//! - Keyed [`seal_bytes_keyed`] / [`seal_matches_keyed`] compute a 256-bit
//!   `HMAC-SHA256` MAC with constant-time verification so an attacker with raw
//!   disk write access cannot forge a valid WAL/disk seal without the device
//!   key.

use crate::tls::{hmac_sha256, sha256_into};

/// Digest / MAC length (SHA-256 / HMAC-SHA256 = 32 bytes).
pub const DURABLE_DIGEST_LEN: usize = 32;

/// Deterministic 256-bit seal key fixture used only by in-memory unit tests
/// (`OsShell::new`). Limited to `#[cfg(test)]` so production and kernel code
/// can never fall back to a public constant.
#[cfg(test)]
pub const DEFAULT_DURABLE_SEAL_KEY: [u8; DURABLE_DIGEST_LEN] =
    *b"Cuttle-Enterprise-DiskSeal-K0001";

/// Pre-rebrand (`Proteus`) deterministic 256-bit seal key fixture used only by
/// in-memory unit tests (`OsShell::new`). Limited to `#[cfg(test)]`.
#[cfg(test)]
pub const DEFAULT_LEGACY_DURABLE_SEAL_KEY: [u8; DURABLE_DIGEST_LEN] =
    *b"Proteus-Enterprise-DiskSeal-K001";

/// Deterministic 256-bit remote attestation key fixture used only by in-memory
/// unit tests (`OsShell::new`). Limited to `#[cfg(test)]`.
#[cfg(test)]
pub const DEFAULT_ATTEST_KEY: [u8; DURABLE_DIGEST_LEN] =
    *b"Cuttle-Enterprise-Attest-Key0001";

/// Derive a per-device 256-bit seal key from a root secret and device/node identifier
/// via `HMAC-SHA256(root_secret, "cuttle-durable-seal-v1:" || node_id)`.
pub fn derive_seal_key(
    root_secret: &[u8; DURABLE_DIGEST_LEN],
    node_id: &[u8],
) -> [u8; DURABLE_DIGEST_LEN] {
    const LABEL: &[u8] = b"cuttle-durable-seal-v1:";
    let mut msg = [0u8; 64];
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < LABEL.len() && pos < msg.len() {
        msg[pos] = LABEL[i];
        pos += 1;
        i += 1;
    }
    let mut j = 0usize;
    while j < node_id.len() && pos < msg.len() {
        msg[pos] = node_id[j];
        pos += 1;
        j += 1;
    }
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    hmac_sha256(root_secret, &msg[..pos], &mut out);
    out
}

/// Derive a pre-rebrand (`Proteus`) 256-bit seal key from a root secret and
/// device/node identifier via `HMAC-SHA256(root_secret, "proteus-durable-seal-v1:" || node_id)`
/// so `PRTS*` disk images can be cryptographically verified and migrated to `CTTL*`.
pub fn derive_legacy_seal_key(
    root_secret: &[u8; DURABLE_DIGEST_LEN],
    node_id: &[u8],
) -> [u8; DURABLE_DIGEST_LEN] {
    const LABEL: &[u8] = b"proteus-durable-seal-v1:";
    let mut msg = [0u8; 64];
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < LABEL.len() && pos < msg.len() {
        msg[pos] = LABEL[i];
        pos += 1;
        i += 1;
    }
    let mut j = 0usize;
    while j < node_id.len() && pos < msg.len() {
        msg[pos] = node_id[j];
        pos += 1;
        j += 1;
    }
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    hmac_sha256(root_secret, &msg[..pos], &mut out);
    out
}

/// Derive a per-device 256-bit remote attestation quote signing key from a root
/// secret and context label via `HMAC-SHA256(root_secret, "cuttle-remote-attest-v1:" || context)`.
pub fn derive_attest_key(
    root_secret: &[u8; DURABLE_DIGEST_LEN],
    context: &[u8],
) -> [u8; DURABLE_DIGEST_LEN] {
    const LABEL: &[u8] = b"cuttle-remote-attest-v1:";
    let mut msg = [0u8; 64];
    let mut pos = 0usize;
    let mut i = 0usize;
    while i < LABEL.len() && pos < msg.len() {
        msg[pos] = LABEL[i];
        pos += 1;
        i += 1;
    }
    let mut j = 0usize;
    while j < context.len() && pos < msg.len() {
        msg[pos] = context[j];
        pos += 1;
        j += 1;
    }
    let mut out = [0u8; DURABLE_DIGEST_LEN];
    hmac_sha256(root_secret, &msg[..pos], &mut out);
    out
}

/// Hash `data` into `out` (32 bytes). Uses the same SHA-256 primitive
/// as the TLS stack so morph cannot diverge the two paths.
pub fn seal_bytes(data: &[u8], out: &mut [u8; DURABLE_DIGEST_LEN]) {
    sha256_into(data, out);
}

/// `true` iff `data` hashes to `expected`.
pub fn seal_matches(data: &[u8], expected: &[u8; DURABLE_DIGEST_LEN]) -> bool {
    let mut got = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes(data, &mut got);
    constant_time_eq(&got, expected)
}

/// Compute a keyed 256-bit `HMAC-SHA256(key, data)` authentication tag into `out`.
pub fn seal_bytes_keyed(
    key: &[u8; DURABLE_DIGEST_LEN],
    data: &[u8],
    out: &mut [u8; DURABLE_DIGEST_LEN],
) {
    hmac_sha256(key, data, out);
}

/// `true` iff `HMAC-SHA256(key, data)` equals `expected` in constant time.
pub fn seal_matches_keyed(
    key: &[u8; DURABLE_DIGEST_LEN],
    data: &[u8],
    expected: &[u8; DURABLE_DIGEST_LEN],
) -> bool {
    let mut got = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(key, data, &mut got);
    constant_time_eq(&got, expected)
}

/// Returns `true` iff `key` is non-zero (i.e. has been explicitly provisioned
/// rather than left at the zeroed `OsShell::empty()` BSS state).
pub fn is_seal_key_set(key: &[u8; DURABLE_DIGEST_LEN]) -> bool {
    !constant_time_eq(key, &[0u8; DURABLE_DIGEST_LEN])
}

/// Constant-time compare of two digests (avoid short-circuit on first
/// mismatch for use with keyed MACs; cheap for 32 bytes).
fn constant_time_eq(a: &[u8; DURABLE_DIGEST_LEN], b: &[u8; DURABLE_DIGEST_LEN]) -> bool {
    let mut diff = 0u8;
    let mut i = 0usize;
    while i < DURABLE_DIGEST_LEN {
        diff |= a[i] ^ b[i];
        i += 1;
    }
    diff == 0
}

/// Overwrite sensitive key or secret material in `buf` using volatile byte writes
/// followed by a `SeqCst` compiler fence so the optimizer cannot elide the wipe
/// as a dead store.
pub fn zeroize_secret_bytes(buf: &mut [u8]) {
    let mut i = 0usize;
    while i < buf.len() {
        // SAFETY: `buf[i]` is a valid, aligned mutable `u8` within the slice bounds.
        unsafe {
            core::ptr::write_volatile(&mut buf[i], 0u8);
        }
        i += 1;
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::AuditLogImpl;
    use cuttle_contracts::{
        AuditEvent, AuditLog, AuditVerdict, AUDIT_MESSAGE_LEN, AUDIT_SNAPSHOT_HEADER_LEN,
    };

    #[test]
    fn seal_empty_is_sha256_empty() {
        // SHA-256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
        let mut out = [0u8; 32];
        seal_bytes(b"", &mut out);
        let expect: [u8; 32] = [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ];
        assert_eq!(out, expect);
        assert!(seal_matches(b"", &expect));
    }

    #[test]
    fn seal_detects_change() {
        let mut a = [0u8; 32];
        seal_bytes(b"audit-v1", &mut a);
        assert!(!seal_matches(b"audit-v2", &a));
        assert!(seal_matches(b"audit-v1", &a));
    }

    #[test]
    fn keyed_hmac_seal_rejects_wrong_key_and_unkeyed_hash() {
        let key1 = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"node-alpha");
        let key2 = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"node-beta");
        assert_ne!(key1, key2);

        let payload = b"wal-record-stream-v1";
        let mut mac = [0u8; 32];
        seal_bytes_keyed(&key1, payload, &mut mac);
        assert!(seal_matches_keyed(&key1, payload, &mac));
        // Wrong key cannot verify or forge the seal.
        assert!(!seal_matches_keyed(&key2, payload, &mac));
        // Plain SHA-256 recomputation by an unkeyed disk attacker is rejected.
        let mut plain_sha = [0u8; 32];
        seal_bytes(payload, &mut plain_sha);
        assert!(!seal_matches_keyed(&key1, payload, &plain_sha));
    }

    #[test]
    fn seal_audit_snapshot_stable() {
        let mut log = AuditLogImpl::<4>::new();
        let mut msg = [0u8; AUDIT_MESSAGE_LEN];
        msg[0] = b'x';
        let _ = log.append(AuditEvent {
            event_id: 0,
            wall_unix: 1_700_000_000,
            task_id: 1,
            syscall_nr: 42,
            verdict: AuditVerdict::Allowed,
            message: msg,
        });
        let mut buf = [0u8; AUDIT_SNAPSHOT_HEADER_LEN + 4 * 96];
        let n = log.snapshot(&mut buf).expect("snapshot");
        let mut dig1 = [0u8; 32];
        let mut dig2 = [0u8; 32];
        seal_bytes(&buf[..n], &mut dig1);
        seal_bytes(&buf[..n], &mut dig2);
        assert_eq!(dig1, dig2);
        assert!(seal_matches(&buf[..n], &dig1));
        // Mutate snapshot → mismatch.
        buf[4] ^= 1;
        assert!(!seal_matches(&buf[..n], &dig1));
    }

    #[test]
    fn regression_prev_item9_zeroize_secret_bytes_wipes_buffer() {
        let mut secret = [0xAAu8; 32];
        zeroize_secret_bytes(&mut secret);
        for i in 0..secret.len() {
            // SAFETY: `secret[i]` is a valid aligned `u8` in the local array.
            let b = unsafe { core::ptr::read_volatile(&secret[i]) };
            assert_eq!(b, 0, "zeroize_secret_bytes must wipe every byte to 0");
        }
        let legacy = derive_legacy_seal_key(&DEFAULT_LEGACY_DURABLE_SEAL_KEY, b"proteus-ahci-wal-seal-v1");
        let modern = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"cuttle-ahci-wal-seal-v1");
        assert_ne!(legacy, modern);
    }
}

