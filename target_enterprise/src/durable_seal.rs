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

use crate::tls::{hkdf_expand, hkdf_extract, hmac_sha256, hmac_sha256_parts, sha256_into};
use chacha20poly1305::aead::AeadInPlace;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce, Tag};

/// Digest / MAC length (SHA-256 / HMAC-SHA256 = 32 bytes).
pub const DURABLE_DIGEST_LEN: usize = 32;
/// Symmetric AEAD key length (`ChaCha20-Poly1305` = 32 bytes / 256 bits).
pub const AEAD_KEY_LEN: usize = 32;
/// Symmetric AEAD nonce length (`ChaCha20-Poly1305` = 12 bytes / 96 bits).
pub const AEAD_NONCE_LEN: usize = 12;
/// Symmetric AEAD authentication tag length (`Poly1305` = 16 bytes / 128 bits).
pub const AEAD_TAG_LEN: usize = 16;

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

/// Magic tag at `hdr[24..32]` marking an `HMAC-SHA256`-authenticated continuity header sector.
pub const CONTINUITY_HMAC_TAG_MAGIC: [u8; 8] = *b"CTTLWL2H";

/// Pack the 512-byte cross-morph continuity header (`CTTLWAL1`) authenticated under `seal_key`
/// (`HMAC-SHA256(seal_key, "cuttle-continuity-hdr-v1:" || hdr[0..32])` at `hdr[32..64]`).
pub fn pack_continuity_header(
    boots: u64,
    cursor: u32,
    crc: u32,
    seal_key: &[u8; DURABLE_DIGEST_LEN],
) -> [u8; 512] {
    let mut hdr = [0u8; 512];
    hdr[0..8].copy_from_slice(b"CTTLWAL1");
    hdr[8..16].copy_from_slice(&boots.to_le_bytes());
    hdr[16..20].copy_from_slice(&cursor.to_le_bytes());
    hdr[20..24].copy_from_slice(&crc.to_le_bytes());
    if is_seal_key_set(seal_key) {
        hdr[24..32].copy_from_slice(&CONTINUITY_HMAC_TAG_MAGIC);
        let mut mac = [0u8; DURABLE_DIGEST_LEN];
        hmac_sha256_parts(
            seal_key,
            &[b"cuttle-continuity-hdr-v1:", &hdr[0..32]],
            &mut mac,
        );
        hdr[32..64].copy_from_slice(&mac);
    }
    hdr
}

/// Verify an `HMAC-SHA256`-authenticated continuity header sector (`CTTLWAL1` + `CTTLWL2H`)
/// in constant time under `seal_key`, returning `Some((boots, cursor, crc))` iff authentic.
pub fn verify_continuity_header(
    hdr: &[u8; 512],
    seal_key: &[u8; DURABLE_DIGEST_LEN],
) -> Option<(u64, usize, u32)> {
    if !is_seal_key_set(seal_key) {
        return None;
    }
    if hdr[0..8] != *b"CTTLWAL1" || hdr[24..32] != CONTINUITY_HMAC_TAG_MAGIC {
        return None;
    }
    let mut expected_mac = [0u8; DURABLE_DIGEST_LEN];
    expected_mac.copy_from_slice(&hdr[32..64]);
    let mut actual_mac = [0u8; DURABLE_DIGEST_LEN];
    hmac_sha256_parts(
        seal_key,
        &[b"cuttle-continuity-hdr-v1:", &hdr[0..32]],
        &mut actual_mac,
    );
    if !constant_time_eq(&actual_mac, &expected_mac) {
        return None;
    }
    let mut boots_b = [0u8; 8];
    let mut cur_b = [0u8; 4];
    let mut crc_b = [0u8; 4];
    boots_b.copy_from_slice(&hdr[8..16]);
    cur_b.copy_from_slice(&hdr[16..20]);
    crc_b.copy_from_slice(&hdr[20..24]);
    Some((
        u64::from_le_bytes(boots_b),
        u32::from_le_bytes(cur_b) as usize,
        u32::from_le_bytes(crc_b),
    ))
}

/// Constant-time compare of two digests (avoid short-circuit on first
/// mismatch for use with keyed MACs; cheap for 32 bytes).
pub fn constant_time_eq(a: &[u8; DURABLE_DIGEST_LEN], b: &[u8; DURABLE_DIGEST_LEN]) -> bool {
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

/// Derive a domain-separated 256-bit `ChaCha20-Poly1305` at-rest state-disk
/// encryption key from `seal_key` via RFC 5869 `HKDF-SHA256`.
pub fn derive_disk_aead_key(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> [u8; AEAD_KEY_LEN] {
    let mut prk = [0u8; DURABLE_DIGEST_LEN];
    hkdf_extract(b"cuttle-disk-aead-salt-v3", seal_key, &mut prk);
    let mut out = [0u8; AEAD_KEY_LEN];
    hkdf_expand(&prk, b"cuttle-disk-aead-key-v3", &mut out);
    zeroize_secret_bytes(&mut prk);
    out
}

/// Derive a domain-separated 256-bit `ChaCha20-Poly1305` crash-dump encryption
/// key from `seal_key` via RFC 5869 `HKDF-SHA256`.
pub fn derive_crash_dump_aead_key(seal_key: &[u8; DURABLE_DIGEST_LEN]) -> [u8; AEAD_KEY_LEN] {
    let mut prk = [0u8; DURABLE_DIGEST_LEN];
    hkdf_extract(b"cuttle-crash-dump-salt-v1", seal_key, &mut prk);
    let mut out = [0u8; AEAD_KEY_LEN];
    hkdf_expand(&prk, b"cuttle-crash-dump-aead-v1", &mut out);
    zeroize_secret_bytes(&mut prk);
    out
}

/// Encrypt `buf` in place under RFC 8439 `ChaCha20-Poly1305` (`key`, `nonce`, `aad`)
/// and return the 128-bit detached `Poly1305` authentication tag.
pub fn chacha20_poly1305_encrypt_in_place(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
) -> [u8; AEAD_TAG_LEN] {
    let cipher = ChaCha20Poly1305::new(key.into());
    let tag = cipher
        .encrypt_in_place_detached(Nonce::from_slice(nonce), aad, buf)
        .expect("ChaCha20-Poly1305 detached encryption cannot fail on bounded slice");
    let mut out = [0u8; AEAD_TAG_LEN];
    out.copy_from_slice(&tag);
    out
}

/// Verify `tag` in constant time and decrypt `buf` in place under RFC 8439
/// `ChaCha20-Poly1305` (`key`, `nonce`, `aad`). On authentication failure,
/// `buf` is zeroized and `false` is returned.
pub fn chacha20_poly1305_decrypt_in_place(
    key: &[u8; AEAD_KEY_LEN],
    nonce: &[u8; AEAD_NONCE_LEN],
    aad: &[u8],
    buf: &mut [u8],
    tag: &[u8; AEAD_TAG_LEN],
) -> bool {
    let cipher = ChaCha20Poly1305::new(key.into());
    match cipher.decrypt_in_place_detached(Nonce::from_slice(nonce), aad, buf, Tag::from_slice(tag))
    {
        Ok(()) => true,
        Err(_) => {
            zeroize_secret_bytes(buf);
            false
        }
    }
}

/// Two-phase write-ahead `Slot B -> Slot A` atomic commit journal (`CTTLAB01`)
/// protecting multi-sector AHCI persistence (`WAL + FS + SQL`) against mid-write
/// power loss while preserving strict at-rest tamper rejection.
pub mod ab_journal {
    use super::{
        constant_time_eq, hmac_sha256_parts, is_seal_key_set, seal_bytes, seal_bytes_keyed,
        seal_matches_keyed, AEAD_NONCE_LEN, AEAD_TAG_LEN, DURABLE_DIGEST_LEN,
    };

    /// 8-byte magic header for the atomic shadow-journal commit sector (`LBA 1149` in v2/v3, `LBA 1098` in v1).
    pub const AB_JOURNAL_MAGIC: [u8; 8] = *b"CTTLAB01";
    /// Pre-upgrade v1 state-store layout (`26` sectors per slot: `2` WAL + `16` FS + `8` SQL).
    pub const AB_FORMAT_V1: u8 = 1;
    /// Expanded v2 state-store layout (`53` sectors per slot: `5` WAL + `32` FS + `16` SQL, plaintext).
    pub const AB_FORMAT_V2: u8 = 2;
    /// Encrypted v3 state-store layout (`53` sectors per slot encrypted at rest with `ChaCha20-Poly1305`).
    pub const AB_FORMAT_V3: u8 = 3;
    /// Journal state `0x01`: `Slot B` is fully staged and sealed;
    /// `Slot A` installation is currently in flight.
    pub const AB_STATE_IN_FLIGHT: u8 = 0x01;
    /// Journal state `0x02`: `Slot A` installation completed and flushed;
    /// any subsequent seal mismatch in `Slot A` indicates at-rest tampering.
    pub const AB_STATE_QUIESCENT: u8 = 0x02;

    /// Authenticated metadata stored in the 512-byte journal commit sector.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub struct AbCommitHeader {
        /// Transaction phase (`AB_STATE_IN_FLIGHT` or `AB_STATE_QUIESCENT`).
        pub state: u8,
        /// On-disk slot layout format version (`AB_FORMAT_V1`, `AB_FORMAT_V2`, or `AB_FORMAT_V3`).
        pub format_version: u8,
        /// Boot generation counter committed in this transaction.
        pub boots: u64,
        /// Monotonic journal commit sequence number.
        pub commit_seq: u64,
        /// SHA-256 over the journal partition (`5` sectors in v2/v3, `2` sectors in v1).
        pub wal_sha: [u8; DURABLE_DIGEST_LEN],
        /// SHA-256 over the FS partition (`32` sectors in v2/v3, `16` sectors in v1).
        pub fs_sha: [u8; DURABLE_DIGEST_LEN],
        /// SHA-256 over the SQL partition (`16` sectors in v2/v3, `8` sectors in v1).
        pub sql_sha: [u8; DURABLE_DIGEST_LEN],
        /// 96-bit base nonce for `AB_FORMAT_V3` `ChaCha20-Poly1305` slot encryption (`[0; 12]` in v1/v2).
        pub aead_nonce: [u8; AEAD_NONCE_LEN],
        /// 128-bit `Poly1305` authentication tag over the encrypted WAL partition (`[0; 16]` in v1/v2).
        pub wal_tag: [u8; AEAD_TAG_LEN],
        /// 128-bit `Poly1305` authentication tag over the encrypted FS partition (`[0; 16]` in v1/v2).
        pub fs_tag: [u8; AEAD_TAG_LEN],
        /// 128-bit `Poly1305` authentication tag over the encrypted SQL partition (`[0; 16]` in v1/v2).
        pub sql_tag: [u8; AEAD_TAG_LEN],
    }

    impl AbCommitHeader {
        /// Construct a commit header without AEAD envelope metadata (`v1`/`v2` or unencrypted test fixtures).
        pub const fn unencrypted(
            state: u8,
            format_version: u8,
            boots: u64,
            commit_seq: u64,
            wal_sha: [u8; DURABLE_DIGEST_LEN],
            fs_sha: [u8; DURABLE_DIGEST_LEN],
            sql_sha: [u8; DURABLE_DIGEST_LEN],
        ) -> Self {
            Self {
                state,
                format_version,
                boots,
                commit_seq,
                wal_sha,
                fs_sha,
                sql_sha,
                aead_nonce: [0u8; AEAD_NONCE_LEN],
                wal_tag: [0u8; AEAD_TAG_LEN],
                fs_tag: [0u8; AEAD_TAG_LEN],
                sql_tag: [0u8; AEAD_TAG_LEN],
            }
        }
    }

    /// Outcome of evaluating `Slot A` (`Primary`) and `Slot B` (`Journal`) at boot.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub enum AbRecoveryDecision {
        /// Freshly formatted / zeroed disk (`Slot A` empty and no `IN_FLIGHT` journal).
        Empty,
        /// `Slot A` verified cleanly (normal boot or power cut occurred during `Slot B` staging before `IN_FLIGHT`).
        UsePrimary,
        /// Power cut interrupted `Slot A` installation while `Slot B` was `IN_FLIGHT` and verified intact;
        /// caller must replay `Slot B -> Slot A`, flush, and mark `AB_STATE_QUIESCENT`.
        ReplayJournalToPrimary(AbCommitHeader),
        /// Journal is `QUIESCENT` (or absent/invalid) while `Slot A` is non-zero and fails HMAC verification.
        TamperedPrimary,
    }

    /// Compute the SHA-256 digest over a contiguous slice of 512-byte sectors.
    pub fn hash_sector_slice(sectors: &[[u8; 512]]) -> [u8; DURABLE_DIGEST_LEN] {
        // SAFETY: `[[u8; 512]]` has identical layout and alignment (`1`) to `[u8]` of length `sectors.len() * 512`.
        let flat = unsafe {
            core::slice::from_raw_parts(sectors.as_ptr().cast::<u8>(), sectors.len() * 512)
        };
        let mut out = [0u8; DURABLE_DIGEST_LEN];
        seal_bytes(flat, &mut out);
        out
    }

    /// Pack and HMAC-SHA256-authenticate a 512-byte journal commit sector.
    pub fn pack_ab_commit_sector(
        key: &[u8; DURABLE_DIGEST_LEN],
        hdr: &AbCommitHeader,
        out: &mut [u8; 512],
    ) -> bool {
        if !is_seal_key_set(key)
            || (hdr.state != AB_STATE_IN_FLIGHT && hdr.state != AB_STATE_QUIESCENT)
            || (hdr.format_version != AB_FORMAT_V1
                && hdr.format_version != AB_FORMAT_V2
                && hdr.format_version != AB_FORMAT_V3)
        {
            return false;
        }
        *out = [0u8; 512];
        out[0..8].copy_from_slice(&AB_JOURNAL_MAGIC);
        out[8] = hdr.state;
        // Pre-upgrade v1 commit sectors stored `0` at byte `9`; encoding `AB_FORMAT_V1`
        // as `0` reproduces the exact legacy wire image while `AB_FORMAT_V2`/`V3` write `2`/`3`.
        out[9] = if hdr.format_version == AB_FORMAT_V1 {
            0
        } else {
            hdr.format_version
        };
        out[16..24].copy_from_slice(&hdr.boots.to_le_bytes());
        out[24..32].copy_from_slice(&hdr.commit_seq.to_le_bytes());
        out[32..64].copy_from_slice(&hdr.wal_sha);
        out[64..96].copy_from_slice(&hdr.fs_sha);
        out[96..128].copy_from_slice(&hdr.sql_sha);
        let mut mac = [0u8; DURABLE_DIGEST_LEN];
        if hdr.format_version == AB_FORMAT_V3 {
            out[160..172].copy_from_slice(&hdr.aead_nonce);
            out[172..188].copy_from_slice(&hdr.wal_tag);
            out[188..204].copy_from_slice(&hdr.fs_tag);
            out[204..220].copy_from_slice(&hdr.sql_tag);
            hmac_sha256_parts(key, &[&out[0..128], &out[160..220]], &mut mac);
        } else {
            seal_bytes_keyed(key, &out[0..128], &mut mac);
        }
        out[128..160].copy_from_slice(&mac);
        true
    }

    /// Verify a 512-byte journal commit sector in constant time and decode [`AbCommitHeader`].
    pub fn verify_ab_commit_sector(
        key: &[u8; DURABLE_DIGEST_LEN],
        sec: &[u8; 512],
    ) -> Option<AbCommitHeader> {
        if !is_seal_key_set(key) || sec[0..8] != AB_JOURNAL_MAGIC {
            return None;
        }
        let state = sec[8];
        if state != AB_STATE_IN_FLIGHT && state != AB_STATE_QUIESCENT {
            return None;
        }
        let format_version = match sec[9] {
            0 | AB_FORMAT_V1 => AB_FORMAT_V1,
            AB_FORMAT_V2 => AB_FORMAT_V2,
            AB_FORMAT_V3 => AB_FORMAT_V3,
            _ => return None,
        };
        let mut expected_mac = [0u8; DURABLE_DIGEST_LEN];
        expected_mac.copy_from_slice(&sec[128..160]);
        if format_version == AB_FORMAT_V3 {
            if !sec[220..512].iter().all(|&b| b == 0) {
                return None;
            }
            let mut actual_mac = [0u8; DURABLE_DIGEST_LEN];
            hmac_sha256_parts(key, &[&sec[0..128], &sec[160..220]], &mut actual_mac);
            if !constant_time_eq(&actual_mac, &expected_mac) {
                return None;
            }
        } else if !seal_matches_keyed(key, &sec[0..128], &expected_mac) {
            return None;
        }
        let mut boots_b = [0u8; 8];
        let mut seq_b = [0u8; 8];
        let mut wal_sha = [0u8; DURABLE_DIGEST_LEN];
        let mut fs_sha = [0u8; DURABLE_DIGEST_LEN];
        let mut sql_sha = [0u8; DURABLE_DIGEST_LEN];
        let mut aead_nonce = [0u8; AEAD_NONCE_LEN];
        let mut wal_tag = [0u8; AEAD_TAG_LEN];
        let mut fs_tag = [0u8; AEAD_TAG_LEN];
        let mut sql_tag = [0u8; AEAD_TAG_LEN];
        boots_b.copy_from_slice(&sec[16..24]);
        seq_b.copy_from_slice(&sec[24..32]);
        wal_sha.copy_from_slice(&sec[32..64]);
        fs_sha.copy_from_slice(&sec[64..96]);
        sql_sha.copy_from_slice(&sec[96..128]);
        if format_version == AB_FORMAT_V3 {
            aead_nonce.copy_from_slice(&sec[160..172]);
            wal_tag.copy_from_slice(&sec[172..188]);
            fs_tag.copy_from_slice(&sec[188..204]);
            sql_tag.copy_from_slice(&sec[204..220]);
        }
        Some(AbCommitHeader {
            state,
            format_version,
            boots: u64::from_le_bytes(boots_b),
            commit_seq: u64::from_le_bytes(seq_b),
            wal_sha,
            fs_sha,
            sql_sha,
            aead_nonce,
            wal_tag,
            fs_tag,
            sql_tag,
        })
    }

    /// Decide whether to use `Slot A`, forward-replay an `IN_FLIGHT` `Slot B` redo journal,
    /// treat the disk as fresh (`Empty`), or reject an at-rest tampered `Slot A`.
    ///
    /// The kernel no longer uses this table. Boot recovery is
    /// [`crate::state_store::recover`], which makes the same roll-forward
    /// decision but differs in two cases this table gets wrong for a single
    /// node: a `QUIESCENT` record with a damaged primary slot and an intact
    /// shadow slot is restored from the shadow slot (and reported) instead of
    /// rejected, and an all-zero primary slot under a valid record is damage,
    /// not a fresh disk. This function is kept for callers that only need the
    /// roll-forward decision.
    pub const fn decide_ab_recovery(
        primary_all_zero: bool,
        primary_valid: bool,
        commit_hdr: Option<AbCommitHeader>,
        journal_digests_match: bool,
    ) -> AbRecoveryDecision {
        if let Some(hdr) = commit_hdr {
            if hdr.state == AB_STATE_IN_FLIGHT && journal_digests_match {
                return AbRecoveryDecision::ReplayJournalToPrimary(hdr);
            }
        }
        if primary_all_zero {
            AbRecoveryDecision::Empty
        } else if primary_valid {
            AbRecoveryDecision::UsePrimary
        } else {
            AbRecoveryDecision::TamperedPrimary
        }
    }
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

    #[test]
    fn stage17_ab_journal_survives_power_cut_at_every_sector_and_rejects_at_rest_tamper() {
        use super::ab_journal::*;

        let key = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"stage17-ab-journal");
        let wrong_key = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"stage17-wrong-key");

        // Fresh zeroed disk must classify as Empty.
        assert_eq!(
            decide_ab_recovery(true, false, None, false),
            AbRecoveryDecision::Empty
        );

        let make_gen = |gen_tag: u8| -> ([[u8; 512]; 2], [[u8; 512]; 16], [[u8; 512]; 8]) {
            let mut w = [[0u8; 512]; 2];
            let mut f = [[0u8; 512]; 16];
            let mut q = [[0u8; 512]; 8];
            for (i, sec) in w.iter_mut().enumerate() {
                sec.fill(gen_tag.wrapping_add(i as u8));
            }
            for (i, sec) in f.iter_mut().enumerate() {
                sec.fill(gen_tag.wrapping_add(0x20).wrapping_add(i as u8));
            }
            for (i, sec) in q.iter_mut().enumerate() {
                sec.fill(gen_tag.wrapping_add(0x60).wrapping_add(i as u8));
            }
            (w, f, q)
        };

        let (w1, f1, q1) = make_gen(0x11);
        let (w2, f2, q2) = make_gen(0x77);
        let w1_sha = hash_sector_slice(&w1);
        let f1_sha = hash_sector_slice(&f1);
        let q1_sha = hash_sector_slice(&q1);
        let w2_sha = hash_sector_slice(&w2);
        let f2_sha = hash_sector_slice(&f2);
        let q2_sha = hash_sector_slice(&q2);

        let mut base_commit = [0u8; 512];
        assert!(pack_ab_commit_sector(
            &key,
            &AbCommitHeader::unencrypted(AB_STATE_QUIESCENT, AB_FORMAT_V2, 1, 1, w1_sha, f1_sha, q1_sha),
            &mut base_commit,
        ));
        assert!(verify_ab_commit_sector(&wrong_key, &base_commit).is_none());

        // Test power cut at EVERY single sector write step `0..=54` across:
        //   steps 1..=26:  Shadow Slot B writes (2 WAL + 16 FS + 8 SQL)
        //   step  27:      LBA 1098 `AB_STATE_IN_FLIGHT` commit write
        //   steps 28..=53: Primary Slot A writes (26 sectors)
        //   step  54:      LBA 1098 `AB_STATE_QUIESCENT` commit write
        for cutoff in 0..=54usize {
            let mut slot_a_w = w1;
            let mut slot_a_f = f1;
            let mut slot_a_q = q1;
            let mut slot_b_w = [[0u8; 512]; 2];
            let mut slot_b_f = [[0u8; 512]; 16];
            let mut slot_b_q = [[0u8; 512]; 8];
            let mut commit_sec = base_commit;

            let mut step = 0usize;
            'tx: {
                for i in 0..2 {
                    if step == cutoff {
                        break 'tx;
                    }
                    slot_b_w[i] = w2[i];
                    step += 1;
                }
                for i in 0..16 {
                    if step == cutoff {
                        break 'tx;
                    }
                    slot_b_f[i] = f2[i];
                    step += 1;
                }
                for i in 0..8 {
                    if step == cutoff {
                        break 'tx;
                    }
                    slot_b_q[i] = q2[i];
                    step += 1;
                }
                if step == cutoff {
                    break 'tx;
                }
                let in_flight = AbCommitHeader::unencrypted(
                    AB_STATE_IN_FLIGHT,
                    AB_FORMAT_V2,
                    2,
                    2,
                    w2_sha,
                    f2_sha,
                    q2_sha,
                );
                assert!(pack_ab_commit_sector(&key, &in_flight, &mut commit_sec));
                step += 1;

                for i in 0..8 {
                    if step == cutoff {
                        break 'tx;
                    }
                    slot_a_q[i] = q2[i];
                    step += 1;
                }
                for i in 0..16 {
                    if step == cutoff {
                        break 'tx;
                    }
                    slot_a_f[i] = f2[i];
                    step += 1;
                }
                for i in 0..2 {
                    if step == cutoff {
                        break 'tx;
                    }
                    slot_a_w[i] = w2[i];
                    step += 1;
                }
                if step == cutoff {
                    break 'tx;
                }
                let quiescent = AbCommitHeader::unencrypted(
                    AB_STATE_QUIESCENT,
                    AB_FORMAT_V2,
                    2,
                    2,
                    w2_sha,
                    f2_sha,
                    q2_sha,
                );
                assert!(pack_ab_commit_sector(&key, &quiescent, &mut commit_sec));
            }

            let a_matches_gen1 = hash_sector_slice(&slot_a_w) == w1_sha
                && hash_sector_slice(&slot_a_f) == f1_sha
                && hash_sector_slice(&slot_a_q) == q1_sha;
            let a_matches_gen2 = hash_sector_slice(&slot_a_w) == w2_sha
                && hash_sector_slice(&slot_a_f) == f2_sha
                && hash_sector_slice(&slot_a_q) == q2_sha;
            let primary_valid = a_matches_gen1 || a_matches_gen2;

            let hdr_opt = verify_ab_commit_sector(&key, &commit_sec);
            let journal_ok = match hdr_opt {
                Some(h) => {
                    hash_sector_slice(&slot_b_w) == h.wal_sha
                        && hash_sector_slice(&slot_b_f) == h.fs_sha
                        && hash_sector_slice(&slot_b_q) == h.sql_sha
                }
                None => false,
            };
            let decision = decide_ab_recovery(false, primary_valid, hdr_opt, journal_ok);
            if cutoff < 27 {
                assert_eq!(decision, AbRecoveryDecision::UsePrimary);
                assert!(a_matches_gen1, "cutoff={cutoff} corrupted Generation 1");
            } else if cutoff < 54 {
                assert!(
                    matches!(decision, AbRecoveryDecision::ReplayJournalToPrimary(h) if h.boots == 2),
                    "cutoff={cutoff} failed to replay IN_FLIGHT journal"
                );
                slot_a_w = slot_b_w;
                slot_a_f = slot_b_f;
                slot_a_q = slot_b_q;
                assert_eq!(hash_sector_slice(&slot_a_w), w2_sha);
                assert_eq!(hash_sector_slice(&slot_a_f), f2_sha);
                assert_eq!(hash_sector_slice(&slot_a_q), q2_sha);
            } else {
                assert_eq!(decision, AbRecoveryDecision::UsePrimary);
                assert!(a_matches_gen2, "cutoff=54 did not finalize Generation 2");
            }
        }

        // At-rest tamper check: when journal is `AB_STATE_QUIESCENT`, a single flipped bit in
        // `Slot A` MUST return `AbRecoveryDecision::TamperedPrimary` (never masked by `Slot B`!).
        let hdr_q = verify_ab_commit_sector(&key, &base_commit);
        assert_eq!(hdr_q.map(|h| h.state), Some(AB_STATE_QUIESCENT));
        assert_eq!(
            decide_ab_recovery(false, false, hdr_q, true),
            AbRecoveryDecision::TamperedPrimary
        );

        // Format version authentication: v1 (`sec[9] == 0`) decodes as `AB_FORMAT_V1`,
        // v2 (`sec[9] == 2`) decodes as `AB_FORMAT_V2`, and downgrading `sec[9]` fails HMAC.
        let mut v1_sec = [0u8; 512];
        assert!(pack_ab_commit_sector(
            &key,
            &AbCommitHeader::unencrypted(AB_STATE_QUIESCENT, AB_FORMAT_V1, 1, 9, w1_sha, f1_sha, q1_sha),
            &mut v1_sec,
        ));
        assert_eq!(v1_sec[9], 0);
        assert_eq!(
            verify_ab_commit_sector(&key, &v1_sec).map(|h| h.format_version),
            Some(AB_FORMAT_V1)
        );
        let mut downgraded = base_commit;
        downgraded[9] = 0;
        assert!(
            verify_ab_commit_sector(&key, &downgraded).is_none(),
            "tampering format_version byte must invalidate commit HMAC"
        );
    }

    #[test]
    fn rfc8439_section_2_8_2_chacha20_poly1305_kat_and_tamper_rejection() {
        let mut key = [0u8; 32];
        for (i, b) in key.iter_mut().enumerate() {
            *b = 0x80u8 + (i as u8);
        }
        let nonce: [u8; 12] = [
            0x07, 0x00, 0x00, 0x00, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        ];
        let aad: [u8; 12] = [
            0x50, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_ciphertext: [u8; 114] = [
            0xd3, 0x1a, 0x8d, 0x34, 0x64, 0x8e, 0x60, 0xdb, 0x7b, 0x86, 0xaf, 0xbc, 0x53, 0xef,
            0x7e, 0xc2, 0xa4, 0xad, 0xed, 0x51, 0x29, 0x6e, 0x08, 0xfe, 0xa9, 0xe2, 0xb5, 0xa7,
            0x36, 0xee, 0x62, 0xd6, 0x3d, 0xbe, 0xa4, 0x5e, 0x8c, 0xa9, 0x67, 0x12, 0x82, 0xfa,
            0xfb, 0x69, 0xda, 0x92, 0x72, 0x8b, 0x1a, 0x71, 0xde, 0x0a, 0x9e, 0x06, 0x0b, 0x29,
            0x05, 0xd6, 0xa5, 0xb6, 0x7e, 0xcd, 0x3b, 0x36, 0x92, 0xdd, 0xbd, 0x7f, 0x2d, 0x77,
            0x8b, 0x8c, 0x98, 0x03, 0xae, 0xe3, 0x28, 0x09, 0x1b, 0x58, 0xfa, 0xb3, 0x24, 0xe4,
            0xfa, 0xd6, 0x75, 0x94, 0x55, 0x85, 0x80, 0x8b, 0x48, 0x31, 0xd7, 0xbc, 0x3f, 0xf4,
            0xde, 0xf0, 0x8e, 0x4b, 0x7a, 0x9d, 0xe5, 0x76, 0xd2, 0x65, 0x86, 0xce, 0xc6, 0x4b,
            0x61, 0x16,
        ];
        let expected_tag: [u8; 16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a, 0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60,
            0x06, 0x91,
        ];

        let mut buf = *plaintext;
        let tag = chacha20_poly1305_encrypt_in_place(&key, &nonce, &aad, &mut buf);
        assert_eq!(buf, expected_ciphertext);
        assert_eq!(tag, expected_tag);

        // Tamper checks: flipping ciphertext, AAD, nonce, or tag fails and zeroizes `buf`.
        let mut bad_ct = buf;
        bad_ct[17] ^= 0x01;
        assert!(!chacha20_poly1305_decrypt_in_place(
            &key, &nonce, &aad, &mut bad_ct, &tag
        ));
        assert!(bad_ct.iter().all(|&b| b == 0));

        let mut bad_aad_buf = buf;
        let mut bad_aad = aad;
        bad_aad[0] ^= 0x80;
        assert!(!chacha20_poly1305_decrypt_in_place(
            &key,
            &nonce,
            &bad_aad,
            &mut bad_aad_buf,
            &tag
        ));
        assert!(bad_aad_buf.iter().all(|&b| b == 0));

        let mut bad_tag_buf = buf;
        let mut bad_tag = tag;
        bad_tag[15] ^= 0x01;
        assert!(!chacha20_poly1305_decrypt_in_place(
            &key,
            &nonce,
            &aad,
            &mut bad_tag_buf,
            &bad_tag
        ));
        assert!(bad_tag_buf.iter().all(|&b| b == 0));

        // Exact recovery with valid key/nonce/AAD/tag:
        assert!(chacha20_poly1305_decrypt_in_place(
            &key, &nonce, &aad, &mut buf, &tag
        ));
        assert_eq!(&buf[..], &plaintext[..]);

        // Domain separation between disk AEAD key and crash-dump AEAD key:
        let disk_k = derive_disk_aead_key(&DEFAULT_DURABLE_SEAL_KEY);
        let dump_k = derive_crash_dump_aead_key(&DEFAULT_DURABLE_SEAL_KEY);
        assert_ne!(disk_k, dump_k);
        assert_ne!(disk_k, DEFAULT_DURABLE_SEAL_KEY);
        assert_ne!(dump_k, DEFAULT_DURABLE_SEAL_KEY);
    }

    #[test]
    fn ab_format_v3_commit_sector_binds_aead_nonce_and_tags() {
        use super::ab_journal::*;
        let key = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"v3-commit-sector");
        let hdr = AbCommitHeader {
            state: AB_STATE_QUIESCENT,
            format_version: AB_FORMAT_V3,
            boots: 4,
            commit_seq: 11,
            wal_sha: [0x11; 32],
            fs_sha: [0x22; 32],
            sql_sha: [0x33; 32],
            aead_nonce: [0xA5; 12],
            wal_tag: [0xB1; 16],
            fs_tag: [0xB2; 16],
            sql_tag: [0xB3; 16],
        };
        let mut sec = [0u8; 512];
        assert!(pack_ab_commit_sector(&key, &hdr, &mut sec));
        assert_eq!(sec[9], AB_FORMAT_V3);
        assert_eq!(verify_ab_commit_sector(&key, &sec), Some(hdr));

        for tamper_off in [9usize, 160, 171, 172, 188, 204, 219, 220] {
            let mut bad = sec;
            bad[tamper_off] ^= 0x01;
            assert!(
                verify_ab_commit_sector(&key, &bad).is_none(),
                "tampering byte {tamper_off} must invalidate AB_FORMAT_V3 commit sector"
            );
        }
    }

    #[test]
    fn continuity_header_hmac_rejects_forged_boot_counter_and_unauthenticated_v1() {
        let key = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"continuity-hdr");
        let hdr = pack_continuity_header(7, 144, 0xCAFE_BABE, &key);
        assert_eq!(verify_continuity_header(&hdr, &key), Some((7, 144, 0xCAFE_BABE)));

        // Forging `boots` (e.g. to spoof attestation quotes) invalidates HMAC.
        let mut forged_boots = hdr;
        forged_boots[8..16].copy_from_slice(&99_999u64.to_le_bytes());
        assert_eq!(verify_continuity_header(&forged_boots, &key), None);

        // Unauthenticated legacy header (`hdr[24..64] == 0`) is rejected.
        let mut unauth = [0u8; 512];
        unauth[0..8].copy_from_slice(b"CTTLWAL1");
        unauth[8..16].copy_from_slice(&7u64.to_le_bytes());
        unauth[16..20].copy_from_slice(&144u32.to_le_bytes());
        unauth[20..24].copy_from_slice(&0xCAFE_BABEu32.to_le_bytes());
        assert_eq!(verify_continuity_header(&unauth, &key), None);
    }
}

