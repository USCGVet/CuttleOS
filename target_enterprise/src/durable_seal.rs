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

/// Two-phase write-ahead `Slot B -> Slot A` atomic commit journal (`CTTLAB01`)
/// protecting multi-sector AHCI persistence (`WAL + FS + SQL`) against mid-write
/// power loss while preserving strict at-rest tamper rejection.
pub mod ab_journal {
    use super::{is_seal_key_set, seal_bytes, seal_bytes_keyed, seal_matches_keyed, DURABLE_DIGEST_LEN};

    /// 8-byte magic header for the atomic shadow-journal commit sector (`LBA 1149` in v2, `LBA 1098` in v1).
    pub const AB_JOURNAL_MAGIC: [u8; 8] = *b"CTTLAB01";
    /// Pre-upgrade v1 state-store layout (`26` sectors per slot: `2` WAL + `16` FS + `8` SQL).
    pub const AB_FORMAT_V1: u8 = 1;
    /// Expanded v2 state-store layout (`53` sectors per slot: `5` WAL + `32` FS + `16` SQL).
    pub const AB_FORMAT_V2: u8 = 2;
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
        /// On-disk slot layout format version (`AB_FORMAT_V1` or `AB_FORMAT_V2`).
        pub format_version: u8,
        /// Boot generation counter committed in this transaction.
        pub boots: u64,
        /// Monotonic journal commit sequence number.
        pub commit_seq: u64,
        /// SHA-256 over the journal partition (`5` sectors in v2, `2` sectors in v1).
        pub wal_sha: [u8; DURABLE_DIGEST_LEN],
        /// SHA-256 over the FS partition (`32` sectors in v2, `16` sectors in v1).
        pub fs_sha: [u8; DURABLE_DIGEST_LEN],
        /// SHA-256 over the SQL partition (`16` sectors in v2, `8` sectors in v1).
        pub sql_sha: [u8; DURABLE_DIGEST_LEN],
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
            || (hdr.format_version != AB_FORMAT_V1 && hdr.format_version != AB_FORMAT_V2)
        {
            return false;
        }
        *out = [0u8; 512];
        out[0..8].copy_from_slice(&AB_JOURNAL_MAGIC);
        out[8] = hdr.state;
        // Pre-upgrade v1 commit sectors stored `0` at byte `9`; encoding `AB_FORMAT_V1`
        // as `0` reproduces the exact legacy wire image while `AB_FORMAT_V2` writes `2`.
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
        seal_bytes_keyed(key, &out[0..128], &mut mac);
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
            _ => return None,
        };
        let mut expected_mac = [0u8; DURABLE_DIGEST_LEN];
        expected_mac.copy_from_slice(&sec[128..160]);
        if !seal_matches_keyed(key, &sec[0..128], &expected_mac) {
            return None;
        }
        let mut boots_b = [0u8; 8];
        let mut seq_b = [0u8; 8];
        let mut wal_sha = [0u8; DURABLE_DIGEST_LEN];
        let mut fs_sha = [0u8; DURABLE_DIGEST_LEN];
        let mut sql_sha = [0u8; DURABLE_DIGEST_LEN];
        boots_b.copy_from_slice(&sec[16..24]);
        seq_b.copy_from_slice(&sec[24..32]);
        wal_sha.copy_from_slice(&sec[32..64]);
        fs_sha.copy_from_slice(&sec[64..96]);
        sql_sha.copy_from_slice(&sec[96..128]);
        Some(AbCommitHeader {
            state,
            format_version,
            boots: u64::from_le_bytes(boots_b),
            commit_seq: u64::from_le_bytes(seq_b),
            wal_sha,
            fs_sha,
            sql_sha,
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
            &AbCommitHeader {
                state: AB_STATE_QUIESCENT,
                format_version: AB_FORMAT_V2,
                boots: 1,
                commit_seq: 1,
                wal_sha: w1_sha,
                fs_sha: f1_sha,
                sql_sha: q1_sha,
            },
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
                let in_flight = AbCommitHeader {
                    state: AB_STATE_IN_FLIGHT,
                    format_version: AB_FORMAT_V2,
                    boots: 2,
                    commit_seq: 2,
                    wal_sha: w2_sha,
                    fs_sha: f2_sha,
                    sql_sha: q2_sha,
                };
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
                let quiescent = AbCommitHeader {
                    state: AB_STATE_QUIESCENT,
                    format_version: AB_FORMAT_V2,
                    boots: 2,
                    commit_seq: 2,
                    wal_sha: w2_sha,
                    fs_sha: f2_sha,
                    sql_sha: q2_sha,
                };
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
            &AbCommitHeader {
                state: AB_STATE_QUIESCENT,
                format_version: AB_FORMAT_V1,
                boots: 1,
                commit_seq: 9,
                wal_sha: w1_sha,
                fs_sha: f1_sha,
                sql_sha: q1_sha,
            },
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
}

