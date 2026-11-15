//! Crash-atomic, self-healing durable state store.
//!
//! This module owns every decision about whether persisted node state
//! survives: the order in which sectors are written, where the flush
//! barriers go, what is read back and checked, and which copy boot
//! recovery trusts. It is generic over a fallible [`SectorIo`] device, so
//! the same code that runs on the kernel's AHCI disk is exercised on the
//! host against a fault-injecting in-memory disk (power cut at every device
//! operation, torn sectors, lost unflushed writes, bit rot, I/O errors and
//! silently dropped writes).
//!
//! ## On-disk layout
//!
//! A [`StateImage`] is 53 sectors (`26.5 KiB`): the 5-sector shell header +
//! `2 KiB` journal, the 32-sector (`16 KiB`, `10 KiB` pool) filesystem partition
//! and the 16-sector (`8 KiB`) SQL partition. Each partition carries its own
//! keyed seal. Pre-upgrade v1 disks (`26` sectors per slot: `2` WAL + `16` FS +
//! `8` SQL at `LBA 1040..=1098`) are authenticated and migrated crash-atomically
//! to v2 on boot. The store keeps two copies plus one commit sector:
//!
//! ```text
//!   primary slot   layout.primary_lba .. +53   the copy boot normally reads
//!   shadow slot    layout.shadow_lba  .. +53   a full second copy
//!   commit sector  layout.commit_lba           HMAC-sealed CTTLAB01 record:
//!                                              state, format_version, boots,
//!                                              commit_seq and partition SHA-256s
//! ```
//!
//! ## Commit ([`commit`])
//!
//! 1. Write the new image to the shadow slot, flush, read it back and check
//!    its digests. The primary slot and commit record are untouched, so a
//!    failure here leaves the previous state fully intact.
//! 2. Write the commit record as `IN_FLIGHT` with the new digests, flush and
//!    read it back. From this point the new state is durable: recovery rolls
//!    forward from the shadow slot.
//! 3. Install the image into the primary slot, flush, read it back and
//!    check its digests.
//! 4. Rewrite the commit record as `QUIESCENT`, flush and read it back.
//!
//! [`commit`] returns `Ok` only after step 4, so a caller that acknowledges a
//! request only after `Ok` never acknowledges state that a later power cut
//! can lose.
//!
//! There are four flush barriers: after the shadow slot (so the `IN_FLIGHT`
//! record never vouches for sectors that are not on the platter), after the
//! `IN_FLIGHT` record (the durability point), after the primary slot (so the
//! next commit cannot start overwriting the shadow slot while the primary is
//! still in a volatile cache), and after the `QUIESCENT` record. The last one
//! is not needed for atomicity: without it recovery would find the
//! `IN_FLIGHT` record beside a matching primary slot, which is the same
//! state. It is kept so that damage to the primary slot after a completed
//! commit is always reported as damage at rest and never mistaken for an
//! interrupted commit. The tests cut power at every device operation under
//! several models of what a volatile write cache keeps, including across
//! two consecutive commits.
//!
//! ## Recovery ([`recover`])
//!
//! The commit record is authenticated first. Then:
//!
//! - primary matches the record: use it (and re-create the shadow copy if
//!   that one no longer matches);
//! - primary does not match but shadow does: use the shadow copy and repair
//!   the primary from it. With an `IN_FLIGHT` record this is ordinary
//!   roll-forward of an interrupted commit; with a `QUIESCENT` record the
//!   primary was damaged at rest and the caller must report it;
//! - neither copy matches the record: [`RecoverError::Unrecoverable`]. The
//!   disk is left exactly as found;
//! - no valid record: [`RecoverySource::Unjournaled`]. The primary slot is
//!   returned as read and the caller must authenticate it with the
//!   per-partition seals (this is also the path for disks written before the
//!   commit record existed).
//!
//! A copy is only ever trusted when its digests equal those in an
//! HMAC-authenticated commit record, or when the caller verifies the
//! per-partition keyed seals. Damaged data is never returned as valid.
//!
//! ## Node state ([`ShellStore`])
//!
//! [`ShellStore`] applies the store to a live [`OsShell`]: it packs the
//! shell into an image and commits it, and at boot it decides what the shell
//! starts from. Two rules there go beyond the slot logic above:
//!
//! - The boot generation comes from the sealed state itself. A separately
//!   stored boot counter may be ahead of it (an earlier boot died before its
//!   first commit) or behind it (the counter was lost); neither stops the
//!   restore.
//! - State that cannot be authenticated is never simply overwritten. Before
//!   the node starts over, both slots and the commit sector are copied to a
//!   quarantine area, and a later boot that *can* authenticate that copy (the
//!   usual cause is one boot without the device key) restores it.

use crate::durable_seal::ab_journal::{
    hash_sector_slice, pack_ab_commit_sector, verify_ab_commit_sector, AbCommitHeader,
    AB_FORMAT_V1, AB_FORMAT_V2, AB_FORMAT_V3, AB_STATE_IN_FLIGHT, AB_STATE_QUIESCENT,
};
use crate::durable_seal::{
    chacha20_poly1305_decrypt_in_place, chacha20_poly1305_encrypt_in_place, constant_time_eq,
    derive_disk_aead_key, is_seal_key_set, seal_bytes_keyed, zeroize_secret_bytes, AEAD_NONCE_LEN,
    AEAD_TAG_LEN, DURABLE_DIGEST_LEN,
};
use crate::shell::{OsShell, StatePackError, StateRestore};
use crate::wal::crc32_ieee;
use sha2::{Digest, Sha256};

/// Size of one device sector in bytes.
pub const SECTOR_BYTES: usize = 512;
/// Sectors holding the sealed shell header (`CTTLSHL1`) and its `2 KiB` journal.
pub const STATE_WAL_SECTORS: usize = crate::shell::SHELL_JOURNAL_PART_SECTORS;
/// Sectors holding the sealed filesystem partition (`CTTLFS01`).
pub const STATE_FS_SECTORS: usize = crate::shell::SHELL_FS_PART_SECTORS;
/// Sectors holding the sealed SQL partition (`CTTLSQL1`).
pub const STATE_SQL_SECTORS: usize = crate::sql::SQL_PART_SECTORS;
/// Total sectors in one v2 [`StateImage`] (and therefore in each slot: `53` sectors).
pub const STATE_IMAGE_SECTORS: usize = STATE_WAL_SECTORS + STATE_FS_SECTORS + STATE_SQL_SECTORS;

/// Pre-upgrade v1 shell header + journal sector count (`2` sectors).
pub const STATE_WAL_SECTORS_V1: usize = 2;
/// Pre-upgrade v1 filesystem partition sector count (`16` sectors).
pub const STATE_FS_SECTORS_V1: usize = crate::shell::SHELL_FS_PART_SECTORS_V1;
/// Pre-upgrade v1 SQL partition sector count (`8` sectors).
pub const STATE_SQL_SECTORS_V1: usize = crate::sql::SQL_PART_SECTORS_V1;
/// Total sectors in a pre-upgrade v1 slot (`26` sectors).
pub const STATE_IMAGE_SECTORS_V1: usize =
    STATE_WAL_SECTORS_V1 + STATE_FS_SECTORS_V1 + STATE_SQL_SECTORS_V1;

/// Image-relative index of the filesystem superblock sector.
const IDX_FS_SUPER: usize = STATE_WAL_SECTORS;
/// Image-relative index of the SQL superblock sector.
const IDX_SQL_SUPER: usize = STATE_WAL_SECTORS + STATE_FS_SECTORS;

/// Why a device operation failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum IoFault {
    /// The device is absent or was never initialised.
    NotReady,
    /// The device did not complete the command in time.
    Timeout,
    /// The device completed the command and reported an error.
    DeviceError,
    /// The sector lies outside the device.
    OutOfRange,
}

/// A fallible 512-byte-sector block device.
///
/// Implementations must report failure instead of panicking: the store turns
/// a reported fault into a refused commit, which is recoverable, whereas a
/// panic in the middle of a commit is only as good as a power cut.
pub trait SectorIo {
    /// Number of addressable sectors.
    fn capacity_sectors(&self) -> u64;
    /// Read the sector at `lba` into `out`.
    fn read_sector(&mut self, lba: u64, out: &mut [u8; SECTOR_BYTES]) -> Result<(), IoFault>;
    /// Write `data` to the sector at `lba`.
    fn write_sector(&mut self, lba: u64, data: &[u8; SECTOR_BYTES]) -> Result<(), IoFault>;
    /// Make every preceding successful write durable against power loss.
    fn flush(&mut self) -> Result<(), IoFault>;

    /// Read a contiguous slice of sectors starting at `lba` into `out`.
    ///
    /// Default implementation loops sector-by-sector so fault-injecting test
    /// devices keep single-sector operation granularity; hardware DMA drivers
    /// override this to transfer multiple sectors per command.
    fn read_sectors(
        &mut self,
        lba: u64,
        out: &mut [[u8; SECTOR_BYTES]],
    ) -> Result<(), IoFault> {
        let mut i = 0usize;
        while i < out.len() {
            let cur = lba.checked_add(i as u64).ok_or(IoFault::OutOfRange)?;
            self.read_sector(cur, &mut out[i])?;
            i += 1;
        }
        Ok(())
    }

    /// Write a contiguous slice of sectors starting at `lba`.
    ///
    /// Default implementation loops sector-by-sector so fault-injecting test
    /// devices keep single-sector torn-write and power-cut granularity;
    /// hardware DMA drivers override this to transfer multiple sectors per command.
    fn write_sectors(
        &mut self,
        lba: u64,
        data: &[[u8; SECTOR_BYTES]],
    ) -> Result<(), IoFault> {
        let mut i = 0usize;
        while i < data.len() {
            let cur = lba.checked_add(i as u64).ok_or(IoFault::OutOfRange)?;
            self.write_sector(cur, &data[i])?;
            i += 1;
        }
        Ok(())
    }

    /// Read contiguous disk sectors starting at `lba` across multiple destination slices.
    fn read_sector_slices(
        &mut self,
        lba: u64,
        slices: &mut [&mut [[u8; SECTOR_BYTES]]],
    ) -> Result<(), IoFault> {
        let mut cur = lba;
        let mut s = 0usize;
        while s < slices.len() {
            self.read_sectors(cur, slices[s])?;
            cur = cur
                .checked_add(slices[s].len() as u64)
                .ok_or(IoFault::OutOfRange)?;
            s += 1;
        }
        Ok(())
    }

    /// Write contiguous disk sectors starting at `lba` from multiple source slices.
    fn write_sector_slices(
        &mut self,
        lba: u64,
        slices: &[&[[u8; SECTOR_BYTES]]],
    ) -> Result<(), IoFault> {
        let mut cur = lba;
        let mut s = 0usize;
        while s < slices.len() {
            self.write_sectors(cur, slices[s])?;
            cur = cur
                .checked_add(slices[s].len() as u64)
                .ok_or(IoFault::OutOfRange)?;
            s += 1;
        }
        Ok(())
    }
}

/// Where the two slots and the commit sector live on the device.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct StoreLayout {
    /// First sector of the primary slot.
    pub primary_lba: u64,
    /// First sector of the shadow slot.
    pub shadow_lba: u64,
    /// The commit sector.
    pub commit_lba: u64,
}

/// The v2 layout Cuttle OS uses on its AHCI state disk: primary `1040..=1092`
/// (`53` sectors: `5` WAL + `32` FS + `16` SQL), shadow `1096..=1148`,
/// commit record at `1149`.
pub const AHCI_STATE_LAYOUT: StoreLayout = StoreLayout {
    primary_lba: 1040,
    shadow_lba: 1096,
    commit_lba: 1149,
};

/// Pre-upgrade v1 layout on the AHCI state disk: primary `1040..=1065`
/// (`26` sectors: `2` WAL + `16` FS + `8` SQL), shadow `1072..=1097`,
/// commit record at `1098`.
pub const AHCI_STATE_LAYOUT_V1: StoreLayout = StoreLayout {
    primary_lba: 1040,
    shadow_lba: 1072,
    commit_lba: 1098,
};

impl StoreLayout {
    /// `true` iff both `slot_sectors`-sized slots and the commit sector are
    /// pairwise disjoint and lie inside a device of `capacity_sectors` sectors.
    pub const fn is_valid_for_sectors(&self, capacity_sectors: u64, slot_sectors: usize) -> bool {
        let n = slot_sectors as u64;
        let Some(p_end) = self.primary_lba.checked_add(n) else {
            return false;
        };
        let Some(s_end) = self.shadow_lba.checked_add(n) else {
            return false;
        };
        if p_end > capacity_sectors || s_end > capacity_sectors || self.commit_lba >= capacity_sectors
        {
            return false;
        }
        let slots_overlap = self.primary_lba < s_end && self.shadow_lba < p_end;
        let commit_in_primary = self.commit_lba >= self.primary_lba && self.commit_lba < p_end;
        let commit_in_shadow = self.commit_lba >= self.shadow_lba && self.commit_lba < s_end;
        !slots_overlap && !commit_in_primary && !commit_in_shadow
    }

    /// `true` iff both v2 slots (`STATE_IMAGE_SECTORS`) and the commit sector
    /// are pairwise disjoint and lie inside `capacity_sectors`.
    pub const fn is_valid_for(&self, capacity_sectors: u64) -> bool {
        self.is_valid_for_sectors(capacity_sectors, STATE_IMAGE_SECTORS)
    }
}

/// SHA-256 of each partition of a [`StateImage`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct ImageDigests {
    /// Digest of the shell header + journal sectors.
    pub wal: [u8; DURABLE_DIGEST_LEN],
    /// Digest of the filesystem partition.
    pub fs: [u8; DURABLE_DIGEST_LEN],
    /// Digest of the SQL partition.
    pub sql: [u8; DURABLE_DIGEST_LEN],
}

impl ImageDigests {
    /// `true` iff these digests equal the ones recorded in `hdr`.
    pub fn matches(&self, hdr: &AbCommitHeader) -> bool {
        // Evaluate all three so the comparison does not stop at the first
        // differing partition.
        let w = constant_time_eq(&self.wal, &hdr.wal_sha);
        let f = constant_time_eq(&self.fs, &hdr.fs_sha);
        let q = constant_time_eq(&self.sql, &hdr.sql_sha);
        w & f & q
    }
}

/// One complete persisted node state: shell header + journal, filesystem
/// partition and SQL partition.
///
/// The struct is 26.5 KiB (`53` sectors). Kernel code keeps it in a `static`;
/// do not pass it by value on a small stack.
pub struct StateImage {
    /// Shell header sector followed by the 4-sector (`2 KiB`) shell journal.
    pub wal: [[u8; SECTOR_BYTES]; STATE_WAL_SECTORS],
    /// Filesystem partition.
    pub fs: [[u8; SECTOR_BYTES]; STATE_FS_SECTORS],
    /// SQL partition.
    pub sql: [[u8; SECTOR_BYTES]; STATE_SQL_SECTORS],
}

impl StateImage {
    /// An all-zero image.
    pub const fn zeroed() -> Self {
        Self {
            wal: [[0u8; SECTOR_BYTES]; STATE_WAL_SECTORS],
            fs: [[0u8; SECTOR_BYTES]; STATE_FS_SECTORS],
            sql: [[0u8; SECTOR_BYTES]; STATE_SQL_SECTORS],
        }
    }

    /// Reset every sector to zero in place.
    pub fn clear(&mut self) {
        let mut i = 0usize;
        while i < STATE_IMAGE_SECTORS {
            *self.sector_mut(i) = [0u8; SECTOR_BYTES];
            i += 1;
        }
    }

    /// Borrow sector `idx` (`0..STATE_IMAGE_SECTORS`) in slot order:
    /// shell sectors, then filesystem sectors, then SQL sectors.
    ///
    /// # Panics
    /// Panics if `idx >= STATE_IMAGE_SECTORS`.
    pub fn sector(&self, idx: usize) -> &[u8; SECTOR_BYTES] {
        if idx < IDX_FS_SUPER {
            &self.wal[idx]
        } else if idx < IDX_SQL_SUPER {
            &self.fs[idx - IDX_FS_SUPER]
        } else {
            &self.sql[idx - IDX_SQL_SUPER]
        }
    }

    /// Mutably borrow sector `idx` (`0..STATE_IMAGE_SECTORS`) in slot order.
    ///
    /// # Panics
    /// Panics if `idx >= STATE_IMAGE_SECTORS`.
    pub fn sector_mut(&mut self, idx: usize) -> &mut [u8; SECTOR_BYTES] {
        if idx < IDX_FS_SUPER {
            &mut self.wal[idx]
        } else if idx < IDX_SQL_SUPER {
            &mut self.fs[idx - IDX_FS_SUPER]
        } else {
            &mut self.sql[idx - IDX_SQL_SUPER]
        }
    }

    /// SHA-256 of each partition.
    pub fn digests(&self) -> ImageDigests {
        ImageDigests {
            wal: hash_sector_slice(&self.wal),
            fs: hash_sector_slice(&self.fs),
            sql: hash_sector_slice(&self.sql),
        }
    }

    /// `true` iff every byte of the image is zero.
    pub fn is_all_zero(&self) -> bool {
        let mut acc = 0u8;
        let mut i = 0usize;
        while i < STATE_IMAGE_SECTORS {
            let sec = self.sector(i);
            let mut b = 0usize;
            while b < SECTOR_BYTES {
                acc |= sec[b];
                b += 1;
            }
            i += 1;
        }
        acc == 0
    }

    /// Boot generation recorded in the shell header sector (`CTTLSHL1`
    /// bytes `8..16`). Only meaningful once the image has been authenticated
    /// (and decrypted if it carried a [`STATE_AEAD_MAGIC`] envelope).
    pub fn saved_boots(&self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.wal[0][8..16]);
        u64::from_le_bytes(b)
    }

    /// Extract `(aead_nonce, wal_tag, fs_tag, sql_tag)` if `self.wal[0][0..68]`
    /// begins with [`STATE_AEAD_MAGIC`] (`*b"CTTLAE03"`) and canonical top-2-bit zero
    /// domain bits on `aead_nonce[11]`.
    pub fn aead_envelope(
        &self,
    ) -> Option<(
        [u8; AEAD_NONCE_LEN],
        [u8; AEAD_TAG_LEN],
        [u8; AEAD_TAG_LEN],
        [u8; AEAD_TAG_LEN],
    )> {
        if self.wal[0][0..8] != STATE_AEAD_MAGIC {
            return None;
        }
        let mut nonce = [0u8; AEAD_NONCE_LEN];
        nonce.copy_from_slice(&self.wal[0][8..20]);
        if (nonce[11] & 0xC0) != 0 {
            return None;
        }
        let mut wal_tag = [0u8; AEAD_TAG_LEN];
        let mut fs_tag = [0u8; AEAD_TAG_LEN];
        let mut sql_tag = [0u8; AEAD_TAG_LEN];
        wal_tag.copy_from_slice(&self.wal[0][20..36]);
        fs_tag.copy_from_slice(&self.wal[0][36..52]);
        sql_tag.copy_from_slice(&self.wal[0][52..68]);
        Some((nonce, wal_tag, fs_tag, sql_tag))
    }

    /// Encrypt all three partitions (`wal`, `fs`, `sql`) in place under
    /// `ChaCha20-Poly1305` (RFC 8439) using `derive_disk_aead_key(seal_key)` and
    /// domain-separated per-partition 96-bit nonces (`top 2 bits of byte 11` = `0..=2`),
    /// storing the 68-byte [`STATE_AEAD_MAGIC`] envelope in `self.wal[0][0..68]`.
    pub fn encrypt_in_place(
        &mut self,
        seal_key: &[u8; DURABLE_DIGEST_LEN],
        nonce_base: &[u8; AEAD_NONCE_LEN],
    ) -> bool {
        if !is_seal_key_set(seal_key) || self.wal[0][0..8] == STATE_AEAD_MAGIC {
            return false;
        }
        // `CTTLSHL1` header occupies bytes `0..116`; bytes `116..184` must be unused zeros
        // so shifting `0..116` to `68..184` is lossless.
        if !self.wal[0][116..184].iter().all(|&b| b == 0) {
            return false;
        }
        let mut canon = *nonce_base;
        canon[11] &= 0x3F;
        let mut aead_key = derive_disk_aead_key(seal_key);

        let wal_flat = self.wal.as_flattened_mut();
        wal_flat.copy_within(0..116, 68);
        let (n_wal, aad_wal) = state_aead_nonce_and_aad(&canon, 0);
        let wal_tag = chacha20_poly1305_encrypt_in_place(&aead_key, &n_wal, &aad_wal, &mut wal_flat[68..]);

        let fs_flat = self.fs.as_flattened_mut();
        let (n_fs, aad_fs) = state_aead_nonce_and_aad(&canon, 1);
        let fs_tag = chacha20_poly1305_encrypt_in_place(&aead_key, &n_fs, &aad_fs, fs_flat);

        let sql_flat = self.sql.as_flattened_mut();
        let (n_sql, aad_sql) = state_aead_nonce_and_aad(&canon, 2);
        let sql_tag = chacha20_poly1305_encrypt_in_place(&aead_key, &n_sql, &aad_sql, sql_flat);

        zeroize_secret_bytes(&mut aead_key);

        let wal_hdr = &mut self.wal[0];
        wal_hdr[0..8].copy_from_slice(&STATE_AEAD_MAGIC);
        wal_hdr[8..20].copy_from_slice(&canon);
        wal_hdr[20..36].copy_from_slice(&wal_tag);
        wal_hdr[36..52].copy_from_slice(&fs_tag);
        wal_hdr[52..68].copy_from_slice(&sql_tag);
        true
    }

    /// Authenticate and decrypt a [`STATE_AEAD_MAGIC`] (`CTTLAE03`) encrypted slot image
    /// in place, zeroizing the entire [`StateImage`] and returning `false` on any tag or
    /// format mismatch.
    pub fn decrypt_in_place(&mut self, seal_key: &[u8; DURABLE_DIGEST_LEN]) -> bool {
        let Some((canon, wal_tag, fs_tag, sql_tag)) = self.aead_envelope() else {
            return false;
        };
        if !is_seal_key_set(seal_key) {
            self.clear();
            return false;
        }
        let mut aead_key = derive_disk_aead_key(seal_key);

        let (n_wal, aad_wal) = state_aead_nonce_and_aad(&canon, 0);
        let wal_ok = chacha20_poly1305_decrypt_in_place(
            &aead_key,
            &n_wal,
            &aad_wal,
            &mut self.wal.as_flattened_mut()[68..],
            &wal_tag,
        );

        let (n_fs, aad_fs) = state_aead_nonce_and_aad(&canon, 1);
        let fs_ok = chacha20_poly1305_decrypt_in_place(
            &aead_key,
            &n_fs,
            &aad_fs,
            self.fs.as_flattened_mut(),
            &fs_tag,
        );

        let (n_sql, aad_sql) = state_aead_nonce_and_aad(&canon, 2);
        let sql_ok = chacha20_poly1305_decrypt_in_place(
            &aead_key,
            &n_sql,
            &aad_sql,
            self.sql.as_flattened_mut(),
            &sql_tag,
        );

        zeroize_secret_bytes(&mut aead_key);

        if !(wal_ok & fs_ok & sql_ok) {
            self.clear();
            return false;
        }
        let wal_flat = self.wal.as_flattened_mut();
        wal_flat.copy_within(68..184, 0);
        wal_flat[116..184].fill(0);
        true
    }
}

/// 8-byte magic prefix of an `AB_FORMAT_V3` `ChaCha20-Poly1305` encrypted [`StateImage`] slot.
pub const STATE_AEAD_MAGIC: [u8; 8] = *b"CTTLAE03";

fn state_aead_nonce_and_aad(
    canon_nonce: &[u8; AEAD_NONCE_LEN],
    part_id: u8,
) -> ([u8; AEAD_NONCE_LEN], [u8; 25]) {
    let mut nonce = *canon_nonce;
    nonce[11] = (nonce[11] & 0x3F) | ((part_id & 0x03) << 6);
    let mut aad = [0u8; 25];
    aad[0..12].copy_from_slice(b"CTTLAE03-AAD");
    aad[12] = part_id;
    aad[13..25].copy_from_slice(canon_nonce);
    (nonce, aad)
}

/// The step of [`commit`] that failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CommitStage {
    /// Writing or checking the shadow slot. The previous state is intact and
    /// the new state is not durable.
    Stage,
    /// Writing or checking the `IN_FLIGHT` commit record. The previous state
    /// is intact; the new state may or may not be durable.
    Journal,
    /// Installing or checking the primary slot. The new state is durable in
    /// the shadow slot and recovery will roll forward to it.
    Install,
    /// Writing or checking the `QUIESCENT` commit record. The new state is
    /// durable in both slots.
    Finalize,
}

/// Why [`commit`] refused or failed.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum CommitError {
    /// The seal key is all zero; nothing was written.
    KeyUnset,
    /// The layout does not fit the device or overlaps itself; nothing was written.
    BadLayout,
    /// A device operation reported a fault.
    Io {
        /// Step that was running.
        stage: CommitStage,
        /// Fault the device reported.
        fault: IoFault,
    },
    /// The device accepted a write but returned different bytes on read-back.
    Verify {
        /// Step that was running.
        stage: CommitStage,
    },
}

/// Which copy [`recover`] returned.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoverySource {
    /// No commit record and an all-zero primary slot: a freshly provisioned
    /// disk. The returned image is all zero.
    Empty,
    /// The primary slot matched the authenticated commit record.
    Primary,
    /// An interrupted commit was rolled forward from the shadow slot.
    JournalReplay,
    /// The primary slot was damaged at rest and the shadow slot was used.
    /// Callers must report this; it means sectors changed outside a commit.
    ShadowHeal,
    /// There is no valid commit record. The primary slot is returned as read
    /// and has **not** been authenticated; the caller must verify the
    /// per-partition seals before using it.
    Unjournaled,
}

/// Outcome of a successful [`recover`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Recovery {
    /// Which copy the returned image came from.
    pub source: RecoverySource,
    /// The authenticated commit record, when one exists.
    pub commit: Option<AbCommitHeader>,
    /// The primary slot was rewritten from the shadow slot and verified.
    pub repaired_primary: bool,
    /// The shadow slot was rewritten from the primary slot and verified.
    pub repaired_shadow: bool,
    /// A repair or record update was attempted and the device refused it.
    /// The returned image is still valid; the device is losing redundancy.
    pub repair_fault: Option<IoFault>,
}

/// Why [`recover`] could not return a state image.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum RecoverError {
    /// The seal key is all zero.
    KeyUnset,
    /// The layout does not fit the device or overlaps itself.
    BadLayout,
    /// A read needed to decide recovery failed.
    Io(IoFault),
    /// A valid commit record exists and neither slot matches it. Nothing was
    /// written; both slots are left as found for inspection.
    Unrecoverable(AbCommitHeader),
}

/// Which slot [`read_slot`] should load.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Slot {
    /// The copy boot normally reads.
    Primary,
    /// The second full copy.
    Shadow,
}

fn slot_base(layout: &StoreLayout, slot: Slot) -> u64 {
    match slot {
        Slot::Primary => layout.primary_lba,
        Slot::Shadow => layout.shadow_lba,
    }
}

/// Write `image` into the slot at `base` and flush.
fn write_slot<D: SectorIo>(dev: &mut D, base: u64, image: &StateImage) -> Result<(), IoFault> {
    dev.write_sector_slices(base, &[&image.wal, &image.fs, &image.sql])?;
    dev.flush()
}

/// Read the slot at `base` back from the device and hash each partition
/// without keeping more than an 8-sector (`4 KiB`) stack chunk at a time.
fn slot_digests<D: SectorIo>(dev: &mut D, base: u64) -> Result<ImageDigests, IoFault> {
    const CHUNK: usize = 8;
    let mut chunk = [[0u8; SECTOR_BYTES]; CHUNK];
    let mut out = ImageDigests {
        wal: [0u8; DURABLE_DIGEST_LEN],
        fs: [0u8; DURABLE_DIGEST_LEN],
        sql: [0u8; DURABLE_DIGEST_LEN],
    };
    let mut idx = 0usize;
    let parts = [
        (STATE_WAL_SECTORS, 0u8),
        (STATE_FS_SECTORS, 1u8),
        (STATE_SQL_SECTORS, 2u8),
    ];
    let mut p = 0usize;
    while p < parts.len() {
        let (count, which) = parts[p];
        let mut hasher = Sha256::new();
        let mut rem = count;
        while rem > 0 {
            let take = rem.min(CHUNK);
            dev.read_sectors(base + idx as u64, &mut chunk[..take])?;
            let mut s = 0usize;
            while s < take {
                hasher.update(chunk[s]);
                s += 1;
            }
            idx += take;
            rem -= take;
        }
        let digest = hasher.finalize();
        match which {
            0 => out.wal.copy_from_slice(&digest),
            1 => out.fs.copy_from_slice(&digest),
            _ => out.sql.copy_from_slice(&digest),
        }
        p += 1;
    }
    Ok(out)
}

/// Write the commit sector, flush, and confirm the device returns it intact.
fn write_commit_record<D: SectorIo>(
    dev: &mut D,
    key: &[u8; DURABLE_DIGEST_LEN],
    layout: &StoreLayout,
    hdr: &AbCommitHeader,
) -> Result<bool, IoFault> {
    let mut sec = [0u8; SECTOR_BYTES];
    if !pack_ab_commit_sector(key, hdr, &mut sec) {
        return Ok(false);
    }
    dev.write_sector(layout.commit_lba, &sec)?;
    dev.flush()?;
    let mut back = [0u8; SECTOR_BYTES];
    dev.read_sector(layout.commit_lba, &mut back)?;
    Ok(back == sec)
}

/// Durably replace the stored state with `image`.
///
/// `boots` and `commit_seq` are recorded in the commit record. `commit_seq`
/// should be one more than the sequence of the state being replaced (see
/// [`Recovery::commit`]).
///
/// Returns the `QUIESCENT` commit record on success. See the module docs for
/// the write order, and [`CommitStage`] for what each failure leaves behind.
/// After any `Err`, the caller must not acknowledge the state change, and
/// should treat the device as faulted: [`recover`] on the next boot returns
/// either the previous state or this one, never a mixture.
pub fn commit<D: SectorIo>(
    dev: &mut D,
    key: &[u8; DURABLE_DIGEST_LEN],
    layout: &StoreLayout,
    boots: u64,
    commit_seq: u64,
    image: &StateImage,
) -> Result<AbCommitHeader, CommitError> {
    if !is_seal_key_set(key) {
        return Err(CommitError::KeyUnset);
    }
    if !layout.is_valid_for(dev.capacity_sectors()) {
        return Err(CommitError::BadLayout);
    }
    let digests = image.digests();
    let io = |stage: CommitStage| move |fault: IoFault| CommitError::Io { stage, fault };

    // 1. Stage the complete image in the shadow slot and prove it landed.
    write_slot(dev, layout.shadow_lba, image).map_err(io(CommitStage::Stage))?;
    let staged = slot_digests(dev, layout.shadow_lba).map_err(io(CommitStage::Stage))?;
    if staged != digests {
        return Err(CommitError::Verify {
            stage: CommitStage::Stage,
        });
    }

    // 2. Point of no return: record that the shadow slot holds the new state.
    let in_flight = if let Some((aead_nonce, wal_tag, fs_tag, sql_tag)) = image.aead_envelope() {
        AbCommitHeader {
            state: AB_STATE_IN_FLIGHT,
            format_version: AB_FORMAT_V3,
            boots,
            commit_seq,
            wal_sha: digests.wal,
            fs_sha: digests.fs,
            sql_sha: digests.sql,
            aead_nonce,
            wal_tag,
            fs_tag,
            sql_tag,
        }
    } else {
        AbCommitHeader::unencrypted(
            AB_STATE_IN_FLIGHT,
            AB_FORMAT_V2,
            boots,
            commit_seq,
            digests.wal,
            digests.fs,
            digests.sql,
        )
    };
    match write_commit_record(dev, key, layout, &in_flight).map_err(io(CommitStage::Journal))? {
        true => {}
        false => {
            return Err(CommitError::Verify {
                stage: CommitStage::Journal,
            })
        }
    }

    // 3. Install into the primary slot and prove it landed.
    write_slot(dev, layout.primary_lba, image).map_err(io(CommitStage::Install))?;
    let installed = slot_digests(dev, layout.primary_lba).map_err(io(CommitStage::Install))?;
    if installed != digests {
        return Err(CommitError::Verify {
            stage: CommitStage::Install,
        });
    }

    // 4. Both copies agree and are durable: close the transaction.
    let quiescent = AbCommitHeader {
        state: AB_STATE_QUIESCENT,
        ..in_flight
    };
    match write_commit_record(dev, key, layout, &quiescent).map_err(io(CommitStage::Finalize))? {
        true => Ok(quiescent),
        false => Err(CommitError::Verify {
            stage: CommitStage::Finalize,
        }),
    }
}

/// Load one slot into `out` exactly as stored, without authenticating it.
///
/// For the [`RecoverySource::Unjournaled`] fallback, where the caller checks
/// the per-partition seals of the primary slot and, if those fail, of the
/// shadow slot.
pub fn read_slot<D: SectorIo>(
    dev: &mut D,
    layout: &StoreLayout,
    slot: Slot,
    out: &mut StateImage,
) -> Result<(), IoFault> {
    if !layout.is_valid_for(dev.capacity_sectors()) {
        return Err(IoFault::OutOfRange);
    }
    let base = slot_base(layout, slot);
    dev.read_sector_slices(base, &mut [&mut out.wal, &mut out.fs, &mut out.sql])
}

/// Rewrite one slot from `image` and confirm the device returns it intact.
fn repair_slot<D: SectorIo>(
    dev: &mut D,
    base: u64,
    image: &StateImage,
    expect: &ImageDigests,
) -> Result<bool, IoFault> {
    write_slot(dev, base, image)?;
    Ok(slot_digests(dev, base)? == *expect)
}

/// Find the state to boot from and load it into `out`.
///
/// See the module docs for the decision table. On `Ok`, `out` holds the
/// selected image; for every source except [`RecoverySource::Unjournaled`] it
/// has been matched against an HMAC-authenticated commit record. On `Err`,
/// the contents of `out` are unspecified and must not be used.
///
/// Recovery writes to the device only to repair a slot from a copy it has
/// already authenticated, or to close an interrupted commit. A refused repair
/// is reported in [`Recovery::repair_fault`] rather than failing recovery,
/// because the returned image is valid either way.
pub fn recover<D: SectorIo>(
    dev: &mut D,
    key: &[u8; DURABLE_DIGEST_LEN],
    layout: &StoreLayout,
    out: &mut StateImage,
) -> Result<Recovery, RecoverError> {
    if !is_seal_key_set(key) {
        return Err(RecoverError::KeyUnset);
    }
    if !layout.is_valid_for(dev.capacity_sectors()) {
        return Err(RecoverError::BadLayout);
    }

    // A sector the device cannot read is damage like any other: treat an
    // unreadable commit sector as "no record" and an unreadable primary slot
    // as "does not match", and let the other copy decide.
    let mut commit_sec = [0u8; SECTOR_BYTES];
    let commit_readable = dev.read_sector(layout.commit_lba, &mut commit_sec).is_ok();
    let commit = if commit_readable {
        verify_ab_commit_sector(key, &commit_sec)
            .filter(|h| h.format_version == AB_FORMAT_V2 || h.format_version == AB_FORMAT_V3)
    } else {
        None
    };

    let primary_read = read_slot(dev, layout, Slot::Primary, out);

    let Some(hdr) = commit else {
        // Without a record only the caller's seal checks can vouch for a
        // slot, so the primary must at least be readable to be offered.
        if let Err(fault) = primary_read {
            if read_slot(dev, layout, Slot::Shadow, out).is_err() {
                return Err(RecoverError::Io(fault));
            }
        }
        let commit_blank = commit_readable && commit_sec.iter().all(|&b| b == 0);
        let source = if commit_blank && primary_read.is_ok() && out.is_all_zero() {
            RecoverySource::Empty
        } else {
            RecoverySource::Unjournaled
        };
        return Ok(Recovery {
            source,
            commit: None,
            repaired_primary: false,
            repaired_shadow: false,
            repair_fault: None,
        });
    };

    let mut result = Recovery {
        source: RecoverySource::Primary,
        commit: Some(hdr),
        repaired_primary: false,
        repaired_shadow: false,
        repair_fault: None,
    };
    let want = ImageDigests {
        wal: hdr.wal_sha,
        fs: hdr.fs_sha,
        sql: hdr.sql_sha,
    };
    let quiescent = AbCommitHeader {
        state: AB_STATE_QUIESCENT,
        ..hdr
    };
    let slot_matches = |img: &StateImage| -> bool {
        img.digests().matches(&hdr)
            && (hdr.format_version != AB_FORMAT_V3
                || img.aead_envelope()
                    == Some((hdr.aead_nonce, hdr.wal_tag, hdr.fs_tag, hdr.sql_tag)))
    };

    if primary_read.is_ok() && slot_matches(out) {
        // The primary slot is the committed state. Restore redundancy if the
        // shadow copy no longer matches (an interrupted later commit, or
        // damage at rest), then close the record if it was left IN_FLIGHT.
        match slot_digests(dev, layout.shadow_lba) {
            Ok(d) if d == want => {}
            Ok(_) => match repair_slot(dev, layout.shadow_lba, out, &want) {
                Ok(true) => result.repaired_shadow = true,
                Ok(false) => result.repair_fault = Some(IoFault::DeviceError),
                Err(f) => result.repair_fault = Some(f),
            },
            Err(f) => result.repair_fault = Some(f),
        }
        if hdr.state == AB_STATE_IN_FLIGHT && result.repair_fault.is_none() {
            match write_commit_record(dev, key, layout, &quiescent) {
                Ok(true) => result.commit = Some(quiescent),
                Ok(false) => result.repair_fault = Some(IoFault::DeviceError),
                Err(f) => result.repair_fault = Some(f),
            }
        }
        return Ok(result);
    }

    // The primary slot is not the committed state. Only the shadow slot can
    // still hold it.
    read_slot(dev, layout, Slot::Shadow, out).map_err(RecoverError::Io)?;
    if !slot_matches(out) {
        return Err(RecoverError::Unrecoverable(hdr));
    }
    result.source = if hdr.state == AB_STATE_IN_FLIGHT {
        RecoverySource::JournalReplay
    } else {
        RecoverySource::ShadowHeal
    };
    match repair_slot(dev, layout.primary_lba, out, &want) {
        Ok(true) => {
            result.repaired_primary = true;
            match write_commit_record(dev, key, layout, &quiescent) {
                Ok(true) => result.commit = Some(quiescent),
                Ok(false) => result.repair_fault = Some(IoFault::DeviceError),
                Err(f) => result.repair_fault = Some(f),
            }
        }
        // Leave the record as it is: it still points at the intact shadow
        // slot, so the next boot makes the same decision.
        Ok(false) => result.repair_fault = Some(IoFault::DeviceError),
        Err(f) => result.repair_fault = Some(f),
    }
    Ok(result)
}

/// Sectors a quarantine area occupies: a copy of both slots, a copy of the
/// commit sector, and one marker sector.
pub const QUARANTINE_SECTORS: u64 = 2 * STATE_IMAGE_SECTORS as u64 + 2;

/// First sector of the quarantine area on the Cuttle OS AHCI state disk
/// (`1216..=1323`, `108` sectors), clear of the v2 store (`1040..=1149`),
/// pre-upgrade v1 store (`1040..=1098`) and the panic dump (`1536..=1567`).
pub const AHCI_QUARANTINE_LBA: u64 = 1216;

/// Magic of a quarantine marker sector.
const QUARANTINE_MAGIC: [u8; 8] = *b"CTTLQUA1";

/// The layout of the slot and commit copies inside a quarantine area that
/// starts at `base`. The marker sector follows at `base + 107`.
pub const fn quarantine_layout(base: u64) -> StoreLayout {
    StoreLayout {
        primary_lba: base,
        shadow_lba: base + STATE_IMAGE_SECTORS as u64,
        commit_lba: base + 2 * STATE_IMAGE_SECTORS as u64,
    }
}

const fn quarantine_marker_lba(base: u64) -> u64 {
    base + 2 * STATE_IMAGE_SECTORS as u64 + 1
}

/// `true` iff the quarantine area at `base` fits the device and overlaps
/// neither slot nor the commit sector of `layout`.
fn quarantine_fits(layout: &StoreLayout, base: u64, capacity_sectors: u64) -> bool {
    let Some(end) = base.checked_add(QUARANTINE_SECTORS) else {
        return false;
    };
    if end > capacity_sectors || !layout.is_valid_for(capacity_sectors) {
        return false;
    }
    let n = STATE_IMAGE_SECTORS as u64;
    let clear_of = |start: u64, len: u64| end <= start || base >= start + len;
    clear_of(layout.primary_lba, n) && clear_of(layout.shadow_lba, n) && clear_of(layout.commit_lba, 1)
}

fn quarantine_marker(sec: &[u8; SECTOR_BYTES]) -> bool {
    let mut crc = [0u8; 4];
    crc.copy_from_slice(&sec[8..12]);
    sec[0..8] == QUARANTINE_MAGIC && u32::from_le_bytes(crc) == crc32_ieee(&sec[0..8])
}

/// `true` iff the quarantine area at `base` holds a preserved copy.
pub fn quarantine_present<D: SectorIo>(dev: &mut D, base: u64) -> Result<bool, IoFault> {
    let mut sec = [0u8; SECTOR_BYTES];
    dev.read_sector(quarantine_marker_lba(base), &mut sec)?;
    Ok(quarantine_marker(&sec))
}

/// Copy both slots and the commit sector of `layout`, exactly as stored,
/// into the quarantine area at `base`, then mark the area as occupied.
///
/// Returns `Ok(false)` without writing if the area already holds a copy: the
/// first unverifiable state seen is the one worth keeping, and later ones
/// are usually what a keyless boot wrote over it.
pub fn quarantine<D: SectorIo>(
    dev: &mut D,
    layout: &StoreLayout,
    base: u64,
) -> Result<bool, IoFault> {
    if !quarantine_fits(layout, base, dev.capacity_sectors()) {
        return Err(IoFault::OutOfRange);
    }
    if quarantine_present(dev, base)? {
        return Ok(false);
    }
    let dst = quarantine_layout(base);
    // An unreadable source sector is preserved as zeros: the copy exists to
    // keep whatever can still be read, so one bad sector must not stop it.
    // Copy in 8-sector batches on healthy media, falling back to per-sector
    // reads only when a chunk encounters a bad sector.
    fn copy_range<D: SectorIo>(dev: &mut D, from: u64, to: u64, total: usize) -> Result<(), IoFault> {
        const CHUNK: usize = 8;
        let mut chunk = [[0u8; SECTOR_BYTES]; CHUNK];
        let mut off = 0usize;
        while off < total {
            let take = (total - off).min(CHUNK);
            if dev
                .read_sectors(from + off as u64, &mut chunk[..take])
                .is_err()
            {
                let mut s = 0usize;
                while s < take {
                    if dev
                        .read_sector(from + (off + s) as u64, &mut chunk[s])
                        .is_err()
                    {
                        chunk[s] = [0u8; SECTOR_BYTES];
                    }
                    s += 1;
                }
            }
            dev.write_sectors(to + off as u64, &chunk[..take])?;
            off += take;
        }
        Ok(())
    }
    copy_range(dev, layout.primary_lba, dst.primary_lba, STATE_IMAGE_SECTORS)?;
    copy_range(dev, layout.shadow_lba, dst.shadow_lba, STATE_IMAGE_SECTORS)?;
    copy_range(dev, layout.commit_lba, dst.commit_lba, 1)?;
    dev.flush()?;
    // The marker goes last, behind a flush, so a marked area is always complete.
    let mut marker = [0u8; SECTOR_BYTES];
    marker[0..8].copy_from_slice(&QUARANTINE_MAGIC);
    let crc = crc32_ieee(&marker[0..8]);
    marker[8..12].copy_from_slice(&crc.to_le_bytes());
    dev.write_sector(quarantine_marker_lba(base), &marker)?;
    dev.flush()?;
    Ok(true)
}

/// Release the quarantine area at `base` so a later unverifiable state can
/// be preserved in it.
pub fn clear_quarantine<D: SectorIo>(dev: &mut D, base: u64) -> Result<(), IoFault> {
    dev.write_sector(quarantine_marker_lba(base), &[0u8; SECTOR_BYTES])?;
    dev.flush()
}

/// The keys a shell needs before it can verify or seal anything.
#[derive(Copy, Clone)]
pub struct ShellKeys {
    /// Seals and verifies the persisted state.
    pub seal: [u8; DURABLE_DIGEST_LEN],
    /// Verifies state written under the pre-rebrand key derivation.
    pub legacy_seal: [u8; DURABLE_DIGEST_LEN],
    /// Signs attestation quotes.
    pub attest: [u8; DURABLE_DIGEST_LEN],
}

/// Replace `sh` with a freshly seeded shell for boot generation `boots`.
pub fn reset_shell(sh: &mut OsShell, keys: &ShellKeys, boots: u64) {
    *sh = OsShell::empty();
    sh.seal_key = keys.seal;
    sh.legacy_seal_key = keys.legacy_seal;
    sh.attest_key = keys.attest;
    sh.seed_defaults_for_boot(boots);
}

/// What [`ShellStore::boot`] started the shell from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootOutcome {
    /// The disk has never held state. The shell holds seeded defaults.
    Fresh,
    /// Persisted state was verified and loaded.
    Restored {
        /// What was loaded.
        restore: StateRestore,
        /// Which copy it came from.
        source: RecoverySource,
        /// It came from the quarantine area, not the store itself.
        from_quarantine: bool,
        /// The primary slot was rewritten from the shadow slot.
        repaired_primary: bool,
        /// The shadow slot was rewritten from the primary slot.
        repaired_shadow: bool,
        /// A repair was refused by the device (redundancy is reduced).
        repair_fault: Option<IoFault>,
        /// The state was committed again during boot (no journal record,
        /// legacy format, or recovered from quarantine).
        recommitted: bool,
    },
    /// The disk holds state that could not be authenticated. The shell holds
    /// seeded defaults.
    Rejected {
        /// A copy of the unverifiable state is held in the quarantine area
        /// (taken now, or kept from an earlier rejected boot).
        preserved: bool,
    },
}

/// Result of [`ShellStore::boot`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct BootReport {
    /// What the shell was started from.
    pub outcome: BootOutcome,
    /// Boot generation to use for this boot: never lower than the caller's
    /// counter, and always above the generation of restored state.
    pub boots: u64,
}

/// Why [`ShellStore::commit`] did not make the state durable.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PersistError {
    /// The shell state could not be serialised.
    Pack(StatePackError),
    /// The store refused or failed the commit.
    Commit(CommitError),
    /// An earlier commit on this store failed at the device, so what the disk
    /// holds is undecided until recovery runs. The store refuses to write
    /// again before the next [`ShellStore::boot`]; this call wrote nothing.
    ///
    /// Writing again without recovering first is how a failed commit becomes
    /// lost data: the retry stages over the one slot that still holds a
    /// complete image, and re-uses page-store slots the interrupted commit
    /// may already have made the committed ones.
    StoreFaulted,
}

/// Why the page store (`LBA 2048..`) stopped a boot. See [`BootError::PagedStore`].
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PagedBootFault {
    /// The state was authenticated, and the page store does not hold the
    /// epoch that state anchors (a damaged page with no redo copy, a missing
    /// or replayed superblock, or a device too small for it).
    AnchorMismatch,
    /// The state could not be authenticated, and the page store holds data.
    Unanchored,
}

/// Why [`ShellStore::boot`] could not decide what to start from.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum BootError {
    /// The seal key is all zero.
    KeyUnset,
    /// The layout or quarantine area does not fit the device.
    BadLayout,
    /// A read needed to decide recovery, or a quarantine write, failed.
    Io(IoFault),
    /// Restored state could not be committed back to the store.
    Persist(PersistError),
    /// Whole-disk rollback detected: the recovered `commit_seq` (`found`) is strictly below
    /// the externally anchored `min_commit_seq` floor (`min_expected`).
    Rollback {
        /// `commit_seq` found on the disk (`0` when wiped/unjournaled).
        found: u64,
        /// Minimum `commit_seq` required by the external high-water mark.
        min_expected: u64,
    },
    /// The page store holds data this boot cannot use, and the node did not
    /// start over on top of it. (Recovery may already have repaired a slot or
    /// a page from its own authenticated copy; nothing else was written.)
    ///
    /// The small state slots are copied to the quarantine area before a
    /// rejected boot starts over, so nothing is lost by starting over. The
    /// page store (SQL rows and file contents) is far larger than any spare
    /// area, and a node that started over would overwrite it with its first
    /// commit. So this is an error, not a [`BootOutcome::Rejected`]: the
    /// operator repairs the cause (the wrong device key is the common one) or
    /// replaces the disk, and until then every byte is still there.
    PagedStore(PagedBootFault),
}

/// What a successful [`ShellStore::commit`] did.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Committed {
    /// The image differed from the stored one and was committed.
    Written {
        /// The `QUIESCENT` commit record.
        commit: AbCommitHeader,
        /// Journal records in the image.
        records: usize,
    },
    /// The image is byte-identical to the stored one; nothing was written.
    Unchanged,
}

/// The durable state of one node: the store layout, the commit sequence,
/// external anti-rollback floor, page-granular CoW + CWAL engine, and a scratch image.
///
/// Kernel code keeps it in a `static`.
pub struct ShellStore {
    layout: StoreLayout,
    quarantine_lba: u64,
    commit_seq: u64,
    min_commit_seq: u64,
    /// Digests of the plaintext image known to be encrypted in both slots, if any.
    stored_plain: Option<ImageDigests>,
    /// Durable `PagedBlockStore` anchor committed inside `AB_FORMAT_V3`.
    durable_anchor: crate::paged_store::PagedAnchor,
    /// Page-granular encrypted CoW + CWAL block engine (`LBA 2048..` when disk `>= 4096` sectors).
    paged: crate::paged_store::PagedBlockStore,
    /// A commit failed at the device since the last [`ShellStore::boot`].
    /// See [`PersistError::StoreFaulted`].
    faulted: bool,
    image: StateImage,
}

impl ShellStore {
    /// A store over `layout` with its quarantine area at `quarantine_lba`.
    pub const fn new(layout: StoreLayout, quarantine_lba: u64) -> Self {
        Self {
            layout,
            quarantine_lba,
            commit_seq: 0,
            min_commit_seq: 0,
            stored_plain: None,
            durable_anchor: crate::paged_store::PagedAnchor::zero(),
            paged: crate::paged_store::PagedBlockStore::new(),
            faulted: false,
            image: StateImage::zeroed(),
        }
    }

    /// Whether a commit has failed at the device since the last
    /// [`ShellStore::boot`]. While it has, [`ShellStore::commit`] returns
    /// [`PersistError::StoreFaulted`] without writing.
    pub const fn is_faulted(&self) -> bool {
        self.faulted
    }

    /// Borrow the underlying page-granular CoW + CWAL block storage engine.
    pub const fn paged_store(&self) -> &crate::paged_store::PagedBlockStore {
        &self.paged
    }

    /// Whether `dev` and `self.layout` activate enterprise page-granular persistence (`LBA 2048..`).
    pub fn supports_paged_for<D: SectorIo>(&self, dev: &D) -> bool {
        self.layout == AHCI_STATE_LAYOUT
            && crate::paged_store::PagedBlockStore::supports_disk_capacity(dev.capacity_sectors())
    }

    /// Sequence number of the last commit this store wrote or recovered.
    pub fn commit_seq(&self) -> u64 {
        self.commit_seq
    }

    /// High-water `commit_seq` anti-rollback floor enforced on [`ShellStore::boot`].
    pub const fn min_commit_seq(&self) -> u64 {
        self.min_commit_seq
    }

    /// Anchor a minimum required `commit_seq` (from TPM NV or Triad coordinator).
    /// [`ShellStore::boot`] refuses any disk state whose `commit_seq` is below `min_seq`
    /// with [`BootError::Rollback`].
    pub fn set_min_commit_seq(&mut self, min_seq: u64) {
        self.min_commit_seq = min_seq;
    }

    fn map_paged_commit_err(err: crate::paged_store::PagedStoreError) -> PersistError {
        use crate::paged_store::PagedStoreError;
        match err {
            PagedStoreError::KeyUnset => PersistError::Commit(CommitError::KeyUnset),
            PagedStoreError::DiskTooSmall => PersistError::Commit(CommitError::BadLayout),
            PagedStoreError::Io(fault) => PersistError::Commit(CommitError::Io {
                stage: CommitStage::Stage,
                fault,
            }),
            PagedStoreError::InvalidPageId
            | PagedStoreError::PayloadTooLarge
            | PagedStoreError::OutOfPages => {
                PersistError::Pack(StatePackError::Filesystem(crate::WalError::OutOfCapacity))
            }
            PagedStoreError::CorruptOrTampered | PagedStoreError::RollbackOrAnchorMismatch => {
                PersistError::Commit(CommitError::Io {
                    stage: CommitStage::Stage,
                    fault: IoFault::DeviceError,
                })
            }
            PagedStoreError::VerifyFailed => PersistError::Commit(CommitError::Verify {
                stage: CommitStage::Stage,
            }),
        }
    }

    /// Whether a page-store error can have left the device part-written.
    /// The others are refused before the first write.
    fn paged_err_touched_device(err: &crate::paged_store::PagedStoreError) -> bool {
        use crate::paged_store::PagedStoreError;
        matches!(
            err,
            PagedStoreError::Io(_)
                | PagedStoreError::VerifyFailed
                | PagedStoreError::CorruptOrTampered
                | PagedStoreError::RollbackOrAnchorMismatch
        )
    }

    fn hydrate_paged_into<D: SectorIo>(
        &mut self,
        dev: &mut D,
        sh: &mut OsShell,
        key: &[u8; DURABLE_DIGEST_LEN],
        paged_cap: bool,
        restore: &mut StateRestore,
    ) -> Result<bool, IoFault> {
        if sh.paged_anchor().is_active() {
            if !paged_cap {
                return Ok(false);
            }
            match self.paged.recover_at_anchor(dev, key, &sh.paged_anchor()) {
                Ok(_) => {}
                Err(crate::paged_store::PagedStoreError::Io(f)) => return Err(f),
                Err(_) => return Ok(false),
            }
            if sh.db.load_from_paged_store(&self.paged).is_err() {
                return Ok(false);
            }
            let Ok((pfiles, _)) = sh.load_vfs_from_paged_store(&self.paged) else {
                return Ok(false);
            };
            restore.files = pfiles;
            self.durable_anchor = sh.paged_anchor();
            Ok(true)
        } else {
            self.paged.reset();
            self.durable_anchor = crate::paged_store::PagedAnchor::zero();
            if paged_cap {
                sh.mark_all_paged_dirty();
            }
            Ok(true)
        }
    }

    /// Make the current state of `sh` durable, stamped with generation `boots`,
    /// encrypted at rest under `ChaCha20-Poly1305` (`AB_FORMAT_V3` / [`STATE_AEAD_MAGIC`]).
    ///
    /// Returns [`Committed::Unchanged`] without touching the device when the
    /// packed plaintext image equals the stored one. After `Err`, the state is **not**
    /// known to be durable: the caller must not acknowledge the request that
    /// changed it, and must not carry on as if it were saved.
    pub fn commit<D: SectorIo>(
        &mut self,
        dev: &mut D,
        sh: &mut OsShell,
        boots: u64,
    ) -> Result<Committed, PersistError> {
        if self.faulted {
            return Err(PersistError::StoreFaulted);
        }
        let key = sh.seal_key;
        if !is_seal_key_set(&key) {
            self.stored_plain = None;
            return Err(PersistError::Commit(CommitError::KeyUnset));
        }
        if !self.layout.is_valid_for(dev.capacity_sectors()) {
            self.stored_plain = None;
            return Err(PersistError::Commit(CommitError::BadLayout));
        }

        let paged_cap = self.supports_paged_for(dev);
        if paged_cap {
            if !sh.is_paged_mode() {
                sh.set_paged_mode(true);
                sh.mark_all_paged_dirty();
            }
            if !self.durable_anchor.is_active() {
                if self.paged.tx_lsn() != 0 {
                    self.paged.reset();
                }
                sh.mark_all_paged_dirty();
            } else if self.paged.tx_lsn() != self.durable_anchor.tx_lsn
                || self.paged.merkle_root() != self.durable_anchor.merkle_root
            {
                match self
                    .paged
                    .recover_at_anchor(dev, &key, &self.durable_anchor)
                {
                    Ok(_) => sh.mark_all_paged_dirty(),
                    Err(e) => {
                        self.faulted |= Self::paged_err_touched_device(&e);
                        return Err(Self::map_paged_commit_err(e));
                    }
                }
            } else if sh.paged_anchor() != self.durable_anchor {
                sh.mark_all_paged_dirty();
            }

            let need_paged_commit = !self.durable_anchor.is_active()
                || sh.db.has_dirty_pages()
                || sh.fs.is_dir_dirty();
            if need_paged_commit {
                let max_logical =
                    crate::paged_store::PagedBlockStore::max_logical_pages_for_sectors(
                        dev.capacity_sectors(),
                    );
                let sql_rows = match sh.db.sync_to_paged_store(&mut self.paged, max_logical) {
                    Ok(r) => r,
                    Err(e) => {
                        sh.set_paged_anchor(self.durable_anchor);
                        sh.mark_all_paged_dirty();
                        return Err(Self::map_paged_commit_err(e));
                    }
                };
                if let Err(e) = sh.sync_vfs_to_paged_store(&mut self.paged, max_logical) {
                    sh.set_paged_anchor(self.durable_anchor);
                    sh.mark_all_paged_dirty();
                    return Err(Self::map_paged_commit_err(e));
                }
                let (uf, ub) = sh.user_file_summary();
                self.paged.set_summary_counts(sql_rows, uf, ub);
                match self.paged.commit_dirty(dev, &key, boots) {
                    Ok(anchor) => sh.set_paged_anchor(anchor),
                    Err(e) => {
                        self.faulted |= Self::paged_err_touched_device(&e);
                        sh.set_paged_anchor(self.durable_anchor);
                        sh.mark_all_paged_dirty();
                        return Err(Self::map_paged_commit_err(e));
                    }
                }
            } else {
                sh.set_paged_anchor(self.durable_anchor);
            }
        }

        let records = match sh.pack_state_image(boots, &mut self.image) {
            Ok(r) => r,
            Err(pe) => {
                if paged_cap {
                    sh.set_paged_anchor(self.durable_anchor);
                    sh.mark_all_paged_dirty();
                }
                return Err(PersistError::Pack(pe));
            }
        };
        let plain_digests = self.image.digests();
        if self.stored_plain == Some(plain_digests) {
            return Ok(Committed::Unchanged);
        }
        let seq = self.commit_seq.wrapping_add(1);
        let nonce_base =
            derive_commit_nonce(&key, boots, seq, &plain_digests, sh.vault_entropy_snapshot());
        if !self.image.encrypt_in_place(&key, &nonce_base) {
            self.stored_plain = None;
            if paged_cap {
                sh.set_paged_anchor(self.durable_anchor);
                sh.mark_all_paged_dirty();
            }
            return Err(PersistError::Commit(CommitError::KeyUnset));
        }
        match commit(dev, &key, &self.layout, boots, seq, &self.image) {
            Ok(hdr) => {
                self.commit_seq = seq;
                if seq > self.min_commit_seq {
                    self.min_commit_seq = seq;
                }
                sh.commit_seq = seq;
                if paged_cap {
                    self.durable_anchor = sh.paged_anchor();
                }
                self.stored_plain = Some(plain_digests);
                Ok(Committed::Written {
                    commit: hdr,
                    records,
                })
            }
            Err(e) => {
                // The slots are in an unknown intermediate state until the
                // next recovery; forget what we believed was stored, and do
                // not write over them again before that recovery has run.
                self.stored_plain = None;
                self.faulted |= matches!(e, CommitError::Io { .. } | CommitError::Verify { .. });
                if paged_cap {
                    sh.set_paged_anchor(self.durable_anchor);
                    sh.mark_all_paged_dirty();
                }
                Err(PersistError::Commit(e))
            }
        }
    }

    /// Decrypt `self.image` in place when it carries a `CTTLAE03` AEAD envelope,
    /// returning `Ok(true)` if the slot was pre-v3 legacy plaintext (needs upgrade).
    fn decrypt_slot_if_needed(
        &mut self,
        seal_key: &[u8; DURABLE_DIGEST_LEN],
        commit_hdr: Option<&AbCommitHeader>,
    ) -> Result<bool, ()> {
        match commit_hdr {
            Some(hdr) if hdr.format_version == AB_FORMAT_V3 => {
                if self.image.aead_envelope()
                    != Some((hdr.aead_nonce, hdr.wal_tag, hdr.fs_tag, hdr.sql_tag))
                {
                    self.image.clear();
                    return Err(());
                }
                if !self.image.decrypt_in_place(seal_key) {
                    return Err(());
                }
                Ok(false)
            }
            Some(hdr) if hdr.format_version == AB_FORMAT_V2 => {
                if self.image.aead_envelope().is_some() {
                    self.image.clear();
                    return Err(());
                }
                Ok(true)
            }
            Some(_) => {
                self.image.clear();
                Err(())
            }
            None => {
                if self.image.aead_envelope().is_some() {
                    if !self.image.decrypt_in_place(seal_key) {
                        return Err(());
                    }
                    Ok(false)
                } else {
                    Ok(true)
                }
            }
        }
    }

    /// Verify the stored state and load it into `sh`, which must be freshly
    /// seeded. Unlike [`ShellStore::boot`] this never falls back, quarantines
    /// or recommits; it answers "does the disk hold exactly this state?".
    pub fn load_into<D: SectorIo>(
        &mut self,
        dev: &mut D,
        sh: &mut OsShell,
    ) -> Result<StateRestore, BootError> {
        let key = sh.seal_key;
        let paged_cap = self.supports_paged_for(dev);
        if paged_cap && !sh.is_paged_mode() {
            sh.set_paged_mode(true);
        }
        match recover(dev, &key, &self.layout, &mut self.image) {
            Ok(r) if r.source != RecoverySource::Empty => {
                let legacy_plain = self
                    .decrypt_slot_if_needed(&key, r.commit.as_ref())
                    .map_err(|()| BootError::Io(IoFault::DeviceError))?;
                let mut restore = sh
                    .unpack_state_image(&self.image)
                    .map_err(|_| BootError::Io(IoFault::DeviceError))?;
                match self.hydrate_paged_into(dev, sh, &key, paged_cap, &mut restore) {
                    Ok(true) => {}
                    Ok(false) => return Err(BootError::Io(IoFault::DeviceError)),
                    Err(f) => return Err(BootError::Io(f)),
                }
                restore.migrated_legacy |= legacy_plain;
                sh.commit_seq = r.commit.map(|h| h.commit_seq).unwrap_or(0);
                Ok(restore)
            }
            Ok(_) => Err(BootError::Io(IoFault::NotReady)),
            Err(RecoverError::KeyUnset) => Err(BootError::KeyUnset),
            Err(RecoverError::BadLayout) => Err(BootError::BadLayout),
            Err(RecoverError::Io(f)) => Err(BootError::Io(f)),
            Err(RecoverError::Unrecoverable(_)) => Err(BootError::Io(IoFault::DeviceError)),
        }
    }

    /// Seed `sh` for the generation after the one recorded in the scratch
    /// image and try to load that image into it.
    fn try_load(
        &self,
        sh: &mut OsShell,
        keys: &ShellKeys,
        counter_boots: u64,
        paged_cap: bool,
    ) -> Option<(StateRestore, u64)> {
        let boots = counter_boots.max(self.image.saved_boots().saturating_add(1));
        reset_shell(sh, keys, boots);
        if paged_cap {
            sh.set_paged_mode(true);
        }
        sh.unpack_state_image(&self.image).ok().map(|r| (r, boots))
    }

    /// Run slot recovery over `layout` and load the result into `sh`.
    /// `Ok(None)` means nothing in `layout` could be authenticated.
    fn recover_and_load<D: SectorIo>(
        &mut self,
        dev: &mut D,
        layout: &StoreLayout,
        sh: &mut OsShell,
        keys: &ShellKeys,
        counter_boots: u64,
    ) -> Result<Option<(Recovery, StateRestore, u64)>, BootError> {
        let paged_cap = self.supports_paged_for(dev);
        let recovery = match recover(dev, &keys.seal, layout, &mut self.image) {
            Ok(r) => r,
            Err(RecoverError::Unrecoverable(_)) => return Ok(None),
            Err(RecoverError::KeyUnset) => return Err(BootError::KeyUnset),
            Err(RecoverError::BadLayout) => return Err(BootError::BadLayout),
            Err(RecoverError::Io(f)) => return Err(BootError::Io(f)),
        };
        if recovery.source == RecoverySource::Empty {
            return Ok(None);
        }
        // Set when a slot authenticated and unpacked, but the page store does
        // not hold the epoch it anchors.
        let mut pages_missing = false;
        if let Ok(legacy_plain) =
            self.decrypt_slot_if_needed(&keys.seal, recovery.commit.as_ref())
        {
            if let Some((mut restore, boots)) = self.try_load(sh, keys, counter_boots, paged_cap) {
                match self.hydrate_paged_into(dev, sh, &keys.seal, paged_cap, &mut restore) {
                    Ok(true) => {
                        restore.migrated_legacy |= legacy_plain;
                        return Ok(Some((recovery, restore, boots)));
                    }
                    Ok(false) => pages_missing = true,
                    Err(f) => return Err(BootError::Io(f)),
                }
            }
        }
        if recovery.source == RecoverySource::Unjournaled {
            // No commit record vouches for either slot, so the AEAD tags and
            // per-partition seals decide. The primary failed them; give the shadow its turn.
            read_slot(dev, layout, Slot::Shadow, &mut self.image).map_err(BootError::Io)?;
            if let Ok(legacy_plain) = self.decrypt_slot_if_needed(&keys.seal, None) {
                if let Some((mut restore, boots)) =
                    self.try_load(sh, keys, counter_boots, paged_cap)
                {
                    match self.hydrate_paged_into(dev, sh, &keys.seal, paged_cap, &mut restore) {
                        Ok(true) => {
                            restore.migrated_legacy |= legacy_plain;
                            return Ok(Some((recovery, restore, boots)));
                        }
                        Ok(false) => pages_missing = true,
                        Err(f) => return Err(BootError::Io(f)),
                    }
                }
            }
        }
        if pages_missing {
            // The state is genuine; part of what it refers to is not there.
            // That is not "a disk this boot cannot authenticate": report it,
            // and let nothing start over on top of the pages that remain.
            return Err(BootError::PagedStore(PagedBootFault::AnchorMismatch));
        }
        Ok(None)
    }

    /// Authenticate and migrate a pre-upgrade v1 state store (`AHCI_STATE_LAYOUT_V1`:
    /// `26` sectors per slot at `1040..=1065` / `1072..=1097`, commit at `1098`)
    /// into the current v2 layout, using `self.image` slices in place so zero
    /// large buffers are allocated on the kernel stack.
    ///
    /// Crash-atomic across power cuts at any sector operation:
    /// - v1 primary (`1040..=1065`) is disjoint from v2 shadow (`1096..=1148`)
    ///   and v2 commit (`1149`), so Stage 1 of `self.commit` never overwrites
    ///   v1 primary before the v2 `IN_FLIGHT` commit sector is durable.
    /// - When v1 recovery comes from v1 shadow (`1072..=1097`, which overlaps
    ///   `1096..=1097`), the verified 26-sector v1 image is first written to
    ///   v1 primary (`1040..=1065`) and flushed before `self.commit` touches
    ///   `1096..=1148`.
    fn try_migrate_v1<D: SectorIo>(
        &mut self,
        dev: &mut D,
        sh: &mut OsShell,
        keys: &ShellKeys,
        counter_boots: u64,
    ) -> Result<Option<(Recovery, StateRestore, u64)>, BootError> {
        let v1 = AHCI_STATE_LAYOUT_V1;
        if self.layout != AHCI_STATE_LAYOUT
            || !v1.is_valid_for_sectors(dev.capacity_sectors(), STATE_IMAGE_SECTORS_V1)
        {
            return Ok(None);
        }

        let mut commit_sec = [0u8; SECTOR_BYTES];
        let v1_commit = if dev.read_sector(v1.commit_lba, &mut commit_sec).is_ok() {
            verify_ab_commit_sector(&keys.seal, &commit_sec)
                .filter(|h| h.format_version == AB_FORMAT_V1)
        } else {
            None
        };

        let read_v1_slot = |dev: &mut D, base: u64, img: &mut StateImage| -> Result<(), IoFault> {
            let (wal_s, _) = img.wal.split_at_mut(STATE_WAL_SECTORS_V1);
            let (fs_s, _) = img.fs.split_at_mut(STATE_FS_SECTORS_V1);
            let (sql_s, _) = img.sql.split_at_mut(STATE_SQL_SECTORS_V1);
            dev.read_sector_slices(base, &mut [wal_s, fs_s, sql_s])
        };

        let v1_digests = |img: &StateImage| -> ImageDigests {
            ImageDigests {
                wal: hash_sector_slice(&img.wal[..STATE_WAL_SECTORS_V1]),
                fs: hash_sector_slice(&img.fs[..STATE_FS_SECTORS_V1]),
                sql: hash_sector_slice(&img.sql[..STATE_SQL_SECTORS_V1]),
            }
        };

        let try_unpack_v1 =
            |img: &StateImage, sh: &mut OsShell| -> Option<(StateRestore, u64)> {
                let wal_v1: &[[u8; SECTOR_BYTES]; STATE_WAL_SECTORS_V1] =
                    (&img.wal[..STATE_WAL_SECTORS_V1]).try_into().ok()?;
                let fs_v1: &[[u8; SECTOR_BYTES]; STATE_FS_SECTORS_V1] =
                    (&img.fs[..STATE_FS_SECTORS_V1]).try_into().ok()?;
                let sql_v1: &[[u8; SECTOR_BYTES]; STATE_SQL_SECTORS_V1] =
                    (&img.sql[..STATE_SQL_SECTORS_V1]).try_into().ok()?;
                let saved = u64::from_le_bytes(wal_v1[0][8..16].try_into().ok()?);
                let boots = counter_boots.max(saved.saturating_add(1));
                reset_shell(sh, keys, boots);
                sh.unpack_state_image_v1(wal_v1, fs_v1, sql_v1)
                    .ok()
                    .map(|mut r| {
                        r.migrated_legacy = true;
                        (r, boots)
                    })
            };

        let anchor_v1_primary = |dev: &mut D, img: &StateImage| -> Result<(), BootError> {
            dev.write_sector_slices(
                v1.primary_lba,
                &[
                    &img.wal[..STATE_WAL_SECTORS_V1],
                    &img.fs[..STATE_FS_SECTORS_V1],
                    &img.sql[..STATE_SQL_SECTORS_V1],
                ],
            )
            .map_err(BootError::Io)?;
            dev.flush().map_err(BootError::Io)
        };

        if let Some(hdr) = v1_commit {
            if read_v1_slot(dev, v1.primary_lba, &mut self.image).is_ok()
                && v1_digests(&self.image).matches(&hdr)
            {
                if let Some((restore, boots)) = try_unpack_v1(&self.image, sh) {
                    let rec = Recovery {
                        source: RecoverySource::Primary,
                        commit: Some(hdr),
                        repaired_primary: false,
                        repaired_shadow: false,
                        repair_fault: None,
                    };
                    return Ok(Some((rec, restore, boots)));
                }
            }
            if read_v1_slot(dev, v1.shadow_lba, &mut self.image).is_ok()
                && v1_digests(&self.image).matches(&hdr)
            {
                if let Some((restore, boots)) = try_unpack_v1(&self.image, sh) {
                    anchor_v1_primary(dev, &self.image)?;
                    let source = if hdr.state == AB_STATE_IN_FLIGHT {
                        RecoverySource::JournalReplay
                    } else {
                        RecoverySource::ShadowHeal
                    };
                    let rec = Recovery {
                        source,
                        commit: Some(hdr),
                        repaired_primary: true,
                        repaired_shadow: false,
                        repair_fault: None,
                    };
                    return Ok(Some((rec, restore, boots)));
                }
            }
            return Ok(None);
        }

        if read_v1_slot(dev, v1.primary_lba, &mut self.image).is_ok() {
            if let Some((restore, boots)) = try_unpack_v1(&self.image, sh) {
                let rec = Recovery {
                    source: RecoverySource::Unjournaled,
                    commit: None,
                    repaired_primary: false,
                    repaired_shadow: false,
                    repair_fault: None,
                };
                return Ok(Some((rec, restore, boots)));
            }
        }
        if read_v1_slot(dev, v1.shadow_lba, &mut self.image).is_ok() {
            if let Some((restore, boots)) = try_unpack_v1(&self.image, sh) {
                anchor_v1_primary(dev, &self.image)?;
                let rec = Recovery {
                    source: RecoverySource::Unjournaled,
                    commit: None,
                    repaired_primary: true,
                    repaired_shadow: false,
                    repair_fault: None,
                };
                return Ok(Some((rec, restore, boots)));
            }
        }
        Ok(None)
    }

    /// Decide what this boot starts from and bring `sh` to that state.
    ///
    /// `counter_boots` is the caller's own boot counter for this boot. `sh`
    /// is always replaced: with the restored state, or with seeded defaults.
    ///
    /// The order of preference is: the store's own slots; then a quarantined
    /// copy left by an earlier boot that could not authenticate the disk;
    /// then seeded defaults, after preserving the unverifiable slots in the
    /// quarantine area if it is free. See [`BootOutcome`].
    pub fn boot<D: SectorIo>(
        &mut self,
        dev: &mut D,
        sh: &mut OsShell,
        keys: &ShellKeys,
        counter_boots: u64,
    ) -> Result<BootReport, BootError> {
        self.commit_seq = 0;
        self.stored_plain = None;
        self.durable_anchor = crate::paged_store::PagedAnchor::zero();
        self.paged.reset();
        // Recovery below settles whatever a failed commit left behind.
        self.faulted = false;
        if !is_seal_key_set(&keys.seal) {
            return Err(BootError::KeyUnset);
        }
        if !quarantine_fits(&self.layout, self.quarantine_lba, dev.capacity_sectors()) {
            return Err(BootError::BadLayout);
        }
        let layout = self.layout;
        let paged_cap = self.supports_paged_for(dev);

        // A blank disk is the one case with nothing to restore or preserve
        // (unless an external high-water `min_commit_seq` proves the disk was wiped).
        // An unreadable sector is not blank.
        let mut commit_sec = [0u8; SECTOR_BYTES];
        let commit_blank = dev.read_sector(layout.commit_lba, &mut commit_sec).is_ok()
            && commit_sec.iter().all(|&b| b == 0);
        let primary_blank = read_slot(dev, &layout, Slot::Primary, &mut self.image).is_ok()
            && self.image.is_all_zero();
        let shadow_blank = read_slot(dev, &layout, Slot::Shadow, &mut self.image).is_ok()
            && self.image.is_all_zero();
        let paged_blank = if paged_cap {
            let mut sb_a = [0u8; SECTOR_BYTES];
            let mut sb_b = [0u8; SECTOR_BYTES];
            dev.read_sector(crate::paged_store::SUPERBLOCK_A_LBA, &mut sb_a)
                .is_ok()
                && sb_a.iter().all(|&b| b == 0)
                && dev
                    .read_sector(crate::paged_store::SUPERBLOCK_B_LBA, &mut sb_b)
                    .is_ok()
                && sb_b.iter().all(|&b| b == 0)
        } else {
            true
        };
        if primary_blank && shadow_blank && commit_blank && paged_blank {
            reset_shell(sh, keys, counter_boots);
            if paged_cap {
                sh.set_paged_mode(true);
                sh.mark_all_paged_dirty();
            }
            if self.min_commit_seq > 0 {
                return Err(BootError::Rollback {
                    found: 0,
                    min_expected: self.min_commit_seq,
                });
            }
            return Ok(BootReport {
                outcome: BootOutcome::Fresh,
                boots: counter_boots,
            });
        }

        let found = match self.recover_and_load(dev, &layout, sh, keys, counter_boots) {
            Ok(Some(v)) => Some(v),
            Ok(None) => self.try_migrate_v1(dev, sh, keys, counter_boots)?,
            Err(e) => {
                if matches!(e, BootError::PagedStore(_)) {
                    self.paged.reset();
                    self.durable_anchor = crate::paged_store::PagedAnchor::zero();
                    reset_shell(sh, keys, counter_boots);
                }
                return Err(e);
            }
        };
        if let Some((recovery, restore, boots)) = found {
            let found_seq = recovery.commit.map(|h| h.commit_seq).unwrap_or(0);
            if found_seq < self.min_commit_seq {
                self.paged.reset();
                self.durable_anchor = crate::paged_store::PagedAnchor::zero();
                reset_shell(sh, keys, counter_boots);
                if paged_cap {
                    sh.set_paged_mode(true);
                    sh.mark_all_paged_dirty();
                }
                return Err(BootError::Rollback {
                    found: found_seq,
                    min_expected: self.min_commit_seq,
                });
            }
            // The state came from the shadow slot and the device refused to
            // let the primary slot be rewritten from it. The shadow slot is
            // then the only complete copy, and it is exactly where the next
            // commit stages its image: one power cut during that write would
            // leave no copy at all. A node in this condition must not commit,
            // so it must not serve.
            if !recovery.repaired_primary
                && matches!(
                    recovery.source,
                    RecoverySource::ShadowHeal | RecoverySource::JournalReplay
                )
            {
                if let Some(fault) = recovery.repair_fault {
                    return Err(BootError::Io(fault));
                }
            }
            self.commit_seq = found_seq;
            sh.commit_seq = found_seq;
            let mut recommitted = false;
            if recovery.source == RecoverySource::Unjournaled || restore.migrated_legacy {
                // Re-establish the commit record and both slots in the
                // current encrypted v3 format before anything else depends on them.
                self.commit(dev, sh, boots).map_err(BootError::Persist)?;
                recommitted = true;
            } else {
                self.stored_plain = Some(self.image.digests());
            }
            if self.commit_seq > self.min_commit_seq {
                self.min_commit_seq = self.commit_seq;
            }
            // Verified state is running again: an old quarantined copy is
            // superseded, so free the area for the next incident.
            if quarantine_present(dev, self.quarantine_lba).map_err(BootError::Io)? {
                clear_quarantine(dev, self.quarantine_lba).map_err(BootError::Io)?;
            }
            return Ok(BootReport {
                outcome: BootOutcome::Restored {
                    restore,
                    source: recovery.source,
                    from_quarantine: false,
                    repaired_primary: recovery.repaired_primary,
                    repaired_shadow: recovery.repaired_shadow,
                    repair_fault: recovery.repair_fault,
                    recommitted,
                },
                boots,
            });
        }

        // The store holds something this boot cannot authenticate.
        if quarantine_present(dev, self.quarantine_lba).map_err(BootError::Io)? {
            let q_layout = quarantine_layout(self.quarantine_lba);
            let from_quarantine =
                match self.recover_and_load(dev, &q_layout, sh, keys, counter_boots) {
                    Ok(v) => v,
                    // The quarantined copy is genuine but the pages it anchors
                    // are no longer on this disk: it cannot be restored.
                    Err(BootError::PagedStore(_)) => None,
                    Err(e) => return Err(e),
                };
            if let Some((recovery, restore, boots)) = from_quarantine {
                let found_seq = recovery.commit.map(|h| h.commit_seq).unwrap_or(0);
                if found_seq < self.min_commit_seq {
                    self.paged.reset();
                    self.durable_anchor = crate::paged_store::PagedAnchor::zero();
                    reset_shell(sh, keys, counter_boots);
                    if paged_cap {
                        sh.set_paged_mode(true);
                        sh.mark_all_paged_dirty();
                    }
                    return Err(BootError::Rollback {
                        found: found_seq,
                        min_expected: self.min_commit_seq,
                    });
                }
                // An earlier boot set this state aside and this boot can
                // verify it: put it back and release the quarantine area.
                self.commit_seq = found_seq;
                self.commit(dev, sh, boots).map_err(BootError::Persist)?;
                clear_quarantine(dev, self.quarantine_lba).map_err(BootError::Io)?;
                return Ok(BootReport {
                    outcome: BootOutcome::Restored {
                        restore,
                        source: recovery.source,
                        from_quarantine: true,
                        repaired_primary: recovery.repaired_primary,
                        repaired_shadow: recovery.repaired_shadow,
                        repair_fault: recovery.repair_fault,
                        recommitted: true,
                    },
                    boots,
                });
            }
        }
        // An external high-water mark says this node has committed state. A
        // disk that cannot be authenticated is then no reason to start again
        // from sequence zero: the node would serve defaults in place of state
        // the mark proves existed, and its own next boot would find a
        // sequence below the mark and refuse. Same answer as for a wiped disk.
        if self.min_commit_seq > 0 {
            self.paged.reset();
            self.durable_anchor = crate::paged_store::PagedAnchor::zero();
            reset_shell(sh, keys, counter_boots);
            return Err(BootError::Rollback {
                found: 0,
                min_expected: self.min_commit_seq,
            });
        }
        // Starting over is only acceptable when nothing is lost by it. The
        // slots are small enough to copy aside; the page store is not, and
        // the first commit of a fresh node would write over it.
        if paged_cap && !paged_blank {
            self.paged.reset();
            self.durable_anchor = crate::paged_store::PagedAnchor::zero();
            reset_shell(sh, keys, counter_boots);
            return Err(BootError::PagedStore(PagedBootFault::Unanchored));
        }
        // Keep a copy before this boot's first commit overwrites the slots.
        // `quarantine` leaves an existing copy alone.
        quarantine(dev, &layout, self.quarantine_lba).map_err(BootError::Io)?;
        self.paged.reset();
        self.durable_anchor = crate::paged_store::PagedAnchor::zero();
        reset_shell(sh, keys, counter_boots);
        if paged_cap {
            sh.set_paged_mode(true);
            sh.mark_all_paged_dirty();
        }
        Ok(BootReport {
            outcome: BootOutcome::Rejected { preserved: true },
            boots: counter_boots,
        })
    }
}

fn derive_commit_nonce(
    seal_key: &[u8; DURABLE_DIGEST_LEN],
    boots: u64,
    seq: u64,
    plain: &ImageDigests,
    entropy_sample: u64,
) -> [u8; AEAD_NONCE_LEN] {
    let mut msg = [0u8; 18 + 8 + 8 + 96 + 8];
    msg[0..18].copy_from_slice(b"CTTLAE03-NONCE-v1:");
    msg[18..26].copy_from_slice(&boots.to_le_bytes());
    msg[26..34].copy_from_slice(&seq.to_le_bytes());
    msg[34..66].copy_from_slice(&plain.wal);
    msg[66..98].copy_from_slice(&plain.fs);
    msg[98..130].copy_from_slice(&plain.sql);
    msg[130..138].copy_from_slice(&entropy_sample.to_le_bytes());
    let mut mac = [0u8; DURABLE_DIGEST_LEN];
    seal_bytes_keyed(seal_key, &msg, &mut mac);
    let mut nonce = [0u8; AEAD_NONCE_LEN];
    nonce[0..8].copy_from_slice(&seq.to_le_bytes());
    nonce[8..12].copy_from_slice(&mac[0..4]);
    nonce[11] &= 0x3F;
    nonce
}

/// In-memory [`SectorIo`] with a volatile write cache and fault injection.
///
/// Models the failures a real disk exhibits so the store can be tested
/// against them: a power cut that tears the sector being written and drops
/// some or all writes issued since the last flush, reported I/O errors, and
/// writes that report success but are never stored.
#[cfg(test)]
pub(crate) mod testdisk {
    use super::{IoFault, SectorIo, SECTOR_BYTES};
    extern crate std;
    use std::vec::Vec;

    /// What happens to writes that were not yet flushed when power is cut.
    #[derive(Copy, Clone, Debug, PartialEq, Eq)]
    pub(crate) enum CacheLoss {
        /// Every unflushed write reached the platter.
        KeepAll,
        /// No unflushed write reached the platter.
        DropAll,
        /// Each unflushed write independently survives or not (seeded).
        Random(u64),
    }

    pub(crate) struct MemDisk {
        /// Contents that survive a power cut.
        durable: Vec<[u8; SECTOR_BYTES]>,
        /// Writes accepted since the last flush, in order.
        cache: Vec<(u64, [u8; SECTOR_BYTES])>,
        /// Device operations performed so far (reads, writes and flushes).
        pub(crate) ops: usize,
        /// Flush commands accepted so far.
        pub(crate) flushes: usize,
        /// Cut power when `ops` reaches this value.
        pub(crate) power_cut_at: Option<usize>,
        /// Report `DeviceError` for the operation at this index, once.
        pub(crate) io_error_at: Option<usize>,
        /// Acknowledge but discard the write at this operation index, once.
        pub(crate) drop_write_at: Option<usize>,
        /// Unflushed-write behaviour on a power cut.
        pub(crate) cache_loss: CacheLoss,
        /// Set once power has been cut; every later operation fails.
        pub(crate) dead: bool,
        /// Sectors that fail every read until they are rewritten (a latent
        /// media error; a successful write remaps the sector).
        pub(crate) unreadable: Vec<u64>,
    }

    impl MemDisk {
        pub(crate) fn new(sectors: usize) -> Self {
            Self {
                durable: std::vec![[0u8; SECTOR_BYTES]; sectors],
                cache: Vec::new(),
                ops: 0,
                flushes: 0,
                power_cut_at: None,
                io_error_at: None,
                drop_write_at: None,
                cache_loss: CacheLoss::DropAll,
                dead: false,
                unreadable: Vec::new(),
            }
        }

        /// Sector contents as a reader sees them now (cache over durable).
        pub(crate) fn peek(&self, lba: u64) -> [u8; SECTOR_BYTES] {
            let mut out = self.durable[lba as usize];
            for (l, data) in &self.cache {
                if *l == lba {
                    out = *data;
                }
            }
            out
        }

        /// Overwrite stored bytes directly, bypassing the device interface
        /// (models bit rot or an offline edit).
        pub(crate) fn poke(&mut self, lba: u64, f: impl FnOnce(&mut [u8; SECTOR_BYTES])) {
            let mut cur = self.peek(lba);
            f(&mut cur);
            self.cache.retain(|(l, _)| *l != lba);
            self.durable[lba as usize] = cur;
        }

        /// Cut power now: apply the cache-loss policy, tear `torn` if given.
        fn cut_power(&mut self, torn: Option<(u64, [u8; SECTOR_BYTES])>) {
            let mut rng = match self.cache_loss {
                CacheLoss::Random(seed) => seed | 1,
                _ => 0,
            };
            let pending = core::mem::take(&mut self.cache);
            for (lba, data) in pending {
                let keep = match self.cache_loss {
                    CacheLoss::KeepAll => true,
                    CacheLoss::DropAll => false,
                    CacheLoss::Random(_) => {
                        rng ^= rng << 13;
                        rng ^= rng >> 7;
                        rng ^= rng << 17;
                        rng & 1 == 1
                    }
                };
                if keep {
                    self.durable[lba as usize] = data;
                }
            }
            if let Some((lba, data)) = torn {
                // The interrupted write lands half-way: the first half of the
                // sector is new, the second half is whatever was there.
                let half = SECTOR_BYTES / 2;
                self.durable[lba as usize][..half].copy_from_slice(&data[..half]);
            }
            self.dead = true;
        }

        /// Power the device back on with whatever survived.
        pub(crate) fn reboot(&mut self) {
            self.cache.clear();
            self.dead = false;
            self.power_cut_at = None;
            self.io_error_at = None;
            self.drop_write_at = None;
            self.ops = 0;
        }

        /// Returns `Err` if this operation must fail, after applying a power cut.
        fn gate(&mut self, torn: Option<(u64, [u8; SECTOR_BYTES])>) -> Result<(), IoFault> {
            if self.dead {
                return Err(IoFault::NotReady);
            }
            let op = self.ops;
            self.ops += 1;
            if self.power_cut_at == Some(op) {
                self.cut_power(torn);
                return Err(IoFault::NotReady);
            }
            if self.io_error_at == Some(op) {
                self.io_error_at = None;
                return Err(IoFault::DeviceError);
            }
            Ok(())
        }
    }

    impl SectorIo for MemDisk {
        fn capacity_sectors(&self) -> u64 {
            self.durable.len() as u64
        }

        fn read_sector(&mut self, lba: u64, out: &mut [u8; SECTOR_BYTES]) -> Result<(), IoFault> {
            if lba >= self.capacity_sectors() {
                return Err(IoFault::OutOfRange);
            }
            self.gate(None)?;
            if self.unreadable.contains(&lba) {
                return Err(IoFault::DeviceError);
            }
            *out = self.peek(lba);
            Ok(())
        }

        fn write_sector(&mut self, lba: u64, data: &[u8; SECTOR_BYTES]) -> Result<(), IoFault> {
            if lba >= self.capacity_sectors() {
                return Err(IoFault::OutOfRange);
            }
            let op = self.ops;
            self.gate(Some((lba, *data)))?;
            if self.drop_write_at == Some(op) {
                self.drop_write_at = None;
                return Ok(());
            }
            self.unreadable.retain(|l| *l != lba);
            self.cache.push((lba, *data));
            Ok(())
        }

        fn flush(&mut self) -> Result<(), IoFault> {
            self.gate(None)?;
            self.flushes += 1;
            let pending = core::mem::take(&mut self.cache);
            for (lba, data) in pending {
                self.durable[lba as usize] = data;
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::testdisk::{CacheLoss, MemDisk};
    use super::*;
    use crate::durable_seal::{derive_seal_key, DEFAULT_DURABLE_SEAL_KEY};
    extern crate std;
    use std::boxed::Box;

    const DISK_SECTORS: usize = 2048;
    const LAYOUT: StoreLayout = AHCI_STATE_LAYOUT;

    fn key() -> [u8; DURABLE_DIGEST_LEN] {
        derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"state-store-tests")
    }

    /// A recognisable image: every sector is filled from `tag` and its index.
    fn image(tag: u8) -> Box<StateImage> {
        let mut img = Box::new(StateImage::zeroed());
        for i in 0..STATE_IMAGE_SECTORS {
            let fill = tag.wrapping_mul(31).wrapping_add(i as u8).wrapping_add(1);
            *img.sector_mut(i) = [fill; SECTOR_BYTES];
            img.sector_mut(i)[0] = tag;
        }
        img
    }

    fn same(a: &StateImage, b: &StateImage) -> bool {
        (0..STATE_IMAGE_SECTORS).all(|i| a.sector(i) == b.sector(i))
    }

    fn recover_image(disk: &mut MemDisk) -> (Result<Recovery, RecoverError>, Box<StateImage>) {
        let mut out = Box::new(StateImage::zeroed());
        let r = recover(disk, &key(), &LAYOUT, &mut out);
        (r, out)
    }

    /// A disk holding `image(1)` committed cleanly at sequence 1.
    fn disk_with_gen1() -> MemDisk {
        let mut disk = MemDisk::new(DISK_SECTORS);
        commit(&mut disk, &key(), &LAYOUT, 1, 1, &image(1)).expect("genesis commit");
        disk.reboot();
        disk
    }

    #[test]
    fn layout_rejects_overlap_and_out_of_range() {
        assert!(LAYOUT.is_valid_for(2048));
        // Commit sector is the last sector the layout touches (`1149`).
        assert!(LAYOUT.is_valid_for(1150));
        assert!(!LAYOUT.is_valid_for(1149));
        let overlapping_slots = StoreLayout {
            primary_lba: 100,
            shadow_lba: 110,
            commit_lba: 200,
        };
        assert!(!overlapping_slots.is_valid_for(2048));
        let commit_inside_primary = StoreLayout {
            primary_lba: 100,
            shadow_lba: 200,
            commit_lba: 110,
        };
        assert!(!commit_inside_primary.is_valid_for(2048));
        let commit_inside_shadow = StoreLayout {
            primary_lba: 100,
            shadow_lba: 200,
            commit_lba: 225,
        };
        assert!(!commit_inside_shadow.is_valid_for(2048));
        let wraps = StoreLayout {
            primary_lba: u64::MAX - 3,
            shadow_lba: 0,
            commit_lba: 500,
        };
        assert!(!wraps.is_valid_for(u64::MAX));
    }

    #[test]
    fn commit_refuses_unset_key_and_bad_layout_without_writing() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let zero_key = [0u8; DURABLE_DIGEST_LEN];
        assert_eq!(
            commit(&mut disk, &zero_key, &LAYOUT, 1, 1, &image(1)),
            Err(CommitError::KeyUnset)
        );
        let mut small = MemDisk::new(1090);
        assert_eq!(
            commit(&mut small, &key(), &LAYOUT, 1, 1, &image(1)),
            Err(CommitError::BadLayout)
        );
        assert_eq!(disk.ops, 0);
        assert_eq!(small.ops, 0);
        let mut out = Box::new(StateImage::zeroed());
        assert_eq!(
            recover(&mut disk, &zero_key, &LAYOUT, &mut out),
            Err(RecoverError::KeyUnset)
        );
        assert_eq!(
            recover(&mut small, &key(), &LAYOUT, &mut out),
            Err(RecoverError::BadLayout)
        );
    }

    #[test]
    fn blank_disk_recovers_as_empty() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("blank disk");
        assert_eq!(r.source, RecoverySource::Empty);
        assert_eq!(r.commit, None);
        assert!(out.is_all_zero());
    }

    #[test]
    fn clean_commit_round_trips_and_leaves_both_slots_identical() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let hdr = commit(&mut disk, &key(), &LAYOUT, 7, 3, &image(5)).expect("commit");
        assert_eq!(hdr.state, AB_STATE_QUIESCENT);
        assert_eq!((hdr.boots, hdr.commit_seq), (7, 3));
        disk.reboot();
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("recover");
        assert_eq!(r.source, RecoverySource::Primary);
        assert_eq!(r.commit, Some(hdr));
        assert!(!r.repaired_primary && !r.repaired_shadow);
        assert_eq!(r.repair_fault, None);
        assert!(same(&out, &image(5)));
        for i in 0..STATE_IMAGE_SECTORS as u64 {
            assert_eq!(
                disk.peek(LAYOUT.primary_lba + i),
                disk.peek(LAYOUT.shadow_lba + i)
            );
        }
    }

    /// The central guarantee. For a power cut at every device operation of a
    /// commit, under three models of what happens to unflushed writes:
    /// recovery returns exactly the old image or exactly the new one, a
    /// commit that returned `Ok` is never lost, and the store accepts a
    /// further commit afterwards.
    #[test]
    fn power_cut_at_every_operation_recovers_old_or_new_never_a_mixture() {
        let gen1 = image(1);
        let gen2 = image(2);
        let gen3 = image(3);

        // Count the operations of one uninterrupted commit.
        let total_ops = {
            let mut probe = disk_with_gen1();
            commit(&mut probe, &key(), &LAYOUT, 2, 2, &gen2).expect("probe commit");
            probe.ops
        };
        assert!(total_ops > 2 * STATE_IMAGE_SECTORS, "probe saw {total_ops} ops");

        let policies = [
            CacheLoss::DropAll,
            CacheLoss::KeepAll,
            CacheLoss::Random(0x9E37_79B9_7F4A_7C15),
            CacheLoss::Random(0xD1B5_4A32_D192_ED03),
        ];
        let mut saw_old = 0usize;
        let mut saw_new = 0usize;
        for policy in policies {
            for cut in 0..=total_ops {
                let mut disk = disk_with_gen1();
                disk.cache_loss = policy;
                disk.power_cut_at = Some(cut);
                let committed = commit(&mut disk, &key(), &LAYOUT, 2, 2, &gen2);
                assert_eq!(
                    committed.is_ok(),
                    cut == total_ops,
                    "policy={policy:?} cut={cut}: commit must fail iff power was cut"
                );

                disk.reboot();
                let (r, out) = recover_image(&mut disk);
                let r = r.unwrap_or_else(|e| {
                    panic!("policy={policy:?} cut={cut}: recovery failed with {e:?}")
                });
                let is_old = same(&out, &gen1);
                let is_new = same(&out, &gen2);
                assert!(
                    is_old || is_new,
                    "policy={policy:?} cut={cut}: recovered a mixture ({:?})",
                    r.source
                );
                assert_ne!(
                    r.source,
                    RecoverySource::ShadowHeal,
                    "policy={policy:?} cut={cut}: a power cut must never look like at-rest damage"
                );
                assert_ne!(r.source, RecoverySource::Empty);
                if committed.is_ok() {
                    assert!(is_new, "an acknowledged commit was lost");
                }
                if r.source == RecoverySource::Unjournaled {
                    // Only a torn commit sector produces this; the primary
                    // slot it returns must still be one whole generation.
                    assert_eq!(r.commit, None);
                }
                saw_old += is_old as usize;
                saw_new += is_new as usize;

                // Recovery is idempotent, and leaves the store able to commit.
                let (r2, out2) = recover_image(&mut disk);
                let r2 = r2.expect("second recovery");
                assert!(same(&out, &out2), "policy={policy:?} cut={cut}: recovery not stable");
                assert_eq!(r2.repair_fault, None);
                commit(&mut disk, &key(), &LAYOUT, 3, 3, &gen3)
                    .unwrap_or_else(|e| panic!("policy={policy:?} cut={cut}: follow-up {e:?}"));
                disk.reboot();
                let (r3, out3) = recover_image(&mut disk);
                assert_eq!(r3.expect("third recovery").source, RecoverySource::Primary);
                assert!(same(&out3, &gen3));
            }
        }
        assert!(saw_old > 0 && saw_new > 0, "old={saw_old} new={saw_new}");
    }

    /// Two commits back to back with no reboot between them, power cut
    /// during the second: the outcome must be the first commit's image or
    /// the second's, never the one before, and never a mixture.
    #[test]
    fn power_cut_during_a_second_consecutive_commit_never_loses_the_first() {
        let gen2 = image(2);
        let gen3 = image(3);
        let ops_per_commit = {
            let mut probe = disk_with_gen1();
            commit(&mut probe, &key(), &LAYOUT, 2, 2, &gen2).expect("probe commit");
            probe.ops
        };
        for policy in [
            CacheLoss::DropAll,
            CacheLoss::KeepAll,
            CacheLoss::Random(0x2545_F491_4F6C_DD1D),
            CacheLoss::Random(0x9FB2_1C65_1E98_DF25),
        ] {
            for cut in 0..=ops_per_commit {
                let mut disk = disk_with_gen1();
                disk.cache_loss = policy;
                commit(&mut disk, &key(), &LAYOUT, 2, 2, &gen2).expect("first commit");
                disk.power_cut_at = Some(disk.ops + cut);
                let second = commit(&mut disk, &key(), &LAYOUT, 2, 3, &gen3);
                assert_eq!(second.is_ok(), cut == ops_per_commit, "policy={policy:?} cut={cut}");
                disk.reboot();
                let (r, out) = recover_image(&mut disk);
                let r = r.unwrap_or_else(|e| {
                    panic!("policy={policy:?} cut={cut}: recovery failed with {e:?}")
                });
                assert!(
                    same(&out, &gen2) || same(&out, &gen3),
                    "policy={policy:?} cut={cut}: an acknowledged commit was lost or mixed ({:?})",
                    r.source
                );
                if second.is_ok() {
                    assert!(same(&out, &gen3));
                }
            }
        }
    }

    #[test]
    fn interrupted_install_rolls_forward_from_the_shadow_slot() {
        let gen2 = image(2);
        // Find the first operation after the IN_FLIGHT record is durable by
        // scanning for the first cut that recovers the new generation.
        let mut first_new = None;
        for cut in 0..400 {
            let mut disk = disk_with_gen1();
            disk.power_cut_at = Some(cut);
            if commit(&mut disk, &key(), &LAYOUT, 2, 2, &gen2).is_ok() {
                break;
            }
            disk.reboot();
            let (r, out) = recover_image(&mut disk);
            let r = r.expect("recover");
            if same(&out, &gen2) {
                assert_eq!(r.source, RecoverySource::JournalReplay, "cut={cut}");
                assert!(r.repaired_primary);
                assert_eq!(r.commit.map(|h| h.state), Some(AB_STATE_QUIESCENT));
                first_new.get_or_insert(cut);
                // After roll-forward the primary slot is whole again.
                let (again, _) = recover_image(&mut disk);
                assert_eq!(again.expect("again").source, RecoverySource::Primary);
                break;
            }
        }
        assert!(first_new.is_some(), "no cut point exercised journal replay");
    }

    #[test]
    fn damage_to_any_primary_sector_is_healed_from_shadow_and_reported() {
        let gen1 = image(1);
        for idx in 0..STATE_IMAGE_SECTORS as u64 {
            let mut disk = disk_with_gen1();
            disk.poke(LAYOUT.primary_lba + idx, |s| s[idx as usize * 7 % SECTOR_BYTES] ^= 0x40);
            let (r, out) = recover_image(&mut disk);
            let r = r.expect("recover");
            assert_eq!(r.source, RecoverySource::ShadowHeal, "sector {idx}");
            assert!(r.repaired_primary, "sector {idx}");
            assert_eq!(r.repair_fault, None);
            assert!(same(&out, &gen1), "sector {idx}: wrong data returned");
            // The repair is on disk: the next boot is clean.
            let (r2, out2) = recover_image(&mut disk);
            let r2 = r2.expect("recover after heal");
            assert_eq!(r2.source, RecoverySource::Primary, "sector {idx}");
            assert!(!r2.repaired_primary && !r2.repaired_shadow);
            assert!(same(&out2, &gen1));
        }
    }

    #[test]
    fn damage_to_any_shadow_sector_is_repaired_from_primary() {
        let gen1 = image(1);
        for idx in 0..STATE_IMAGE_SECTORS as u64 {
            let mut disk = disk_with_gen1();
            disk.poke(LAYOUT.shadow_lba + idx, |s| s[3] ^= 0x01);
            let (r, out) = recover_image(&mut disk);
            let r = r.expect("recover");
            assert_eq!(r.source, RecoverySource::Primary, "sector {idx}");
            assert!(r.repaired_shadow, "sector {idx}");
            assert!(same(&out, &gen1));
            for i in 0..STATE_IMAGE_SECTORS as u64 {
                assert_eq!(
                    disk.peek(LAYOUT.primary_lba + i),
                    disk.peek(LAYOUT.shadow_lba + i)
                );
            }
        }
    }

    #[test]
    fn damage_to_both_slots_is_unrecoverable_and_leaves_the_disk_untouched() {
        let mut disk = disk_with_gen1();
        disk.poke(LAYOUT.primary_lba + 4, |s| s[9] ^= 0xFF);
        disk.poke(LAYOUT.shadow_lba + 20, |s| s[200] ^= 0xFF);
        let before: std::vec::Vec<_> = (0..DISK_SECTORS as u64).map(|l| disk.peek(l)).collect();
        let (r, _) = recover_image(&mut disk);
        match r {
            Err(RecoverError::Unrecoverable(hdr)) => assert_eq!(hdr.commit_seq, 1),
            other => panic!("expected Unrecoverable, got {other:?}"),
        }
        let after: std::vec::Vec<_> = (0..DISK_SECTORS as u64).map(|l| disk.peek(l)).collect();
        assert!(before == after, "recovery wrote to an unrecoverable disk");
    }

    #[test]
    fn damaged_commit_record_falls_back_to_unjournaled_primary() {
        let mut disk = disk_with_gen1();
        disk.poke(LAYOUT.commit_lba, |s| s[40] ^= 0x10);
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("recover");
        assert_eq!(r.source, RecoverySource::Unjournaled);
        assert_eq!(r.commit, None);
        // The primary slot is handed back for the caller to authenticate.
        assert!(same(&out, &image(1)));
        // And the shadow slot is reachable for the caller's fallback.
        let mut shadow = Box::new(StateImage::zeroed());
        read_slot(&mut disk, &LAYOUT, Slot::Shadow, &mut shadow).expect("read shadow");
        assert!(same(&shadow, &image(1)));
    }

    #[test]
    fn commit_record_from_another_key_is_not_trusted() {
        let mut disk = disk_with_gen1();
        let other = derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"some-other-node");
        let mut out = Box::new(StateImage::zeroed());
        let r = recover(&mut disk, &other, &LAYOUT, &mut out).expect("recover");
        assert_eq!(r.source, RecoverySource::Unjournaled);
    }

    #[test]
    fn io_error_at_every_operation_fails_the_commit_and_recovers_cleanly() {
        let gen1 = image(1);
        let gen2 = image(2);
        let total_ops = {
            let mut probe = disk_with_gen1();
            commit(&mut probe, &key(), &LAYOUT, 2, 2, &gen2).expect("probe commit");
            probe.ops
        };
        for at in 0..total_ops {
            let mut disk = disk_with_gen1();
            disk.io_error_at = Some(at);
            let err = commit(&mut disk, &key(), &LAYOUT, 2, 2, &gen2)
                .expect_err("an I/O error must fail the commit");
            assert!(
                matches!(
                    err,
                    CommitError::Io {
                        fault: IoFault::DeviceError,
                        ..
                    }
                ),
                "op {at}: {err:?}"
            );
            // The device keeps running (no power cut), so cached writes land.
            disk.flush().expect("flush");
            disk.reboot();
            let (r, out) = recover_image(&mut disk);
            r.unwrap_or_else(|e| panic!("op {at}: recovery failed with {e:?}"));
            assert!(
                same(&out, &gen1) || same(&out, &gen2),
                "op {at}: recovered a mixture"
            );
        }
    }

    #[test]
    fn silently_dropped_write_is_caught_by_read_back() {
        let gen1 = image(1);
        let gen2 = image(2);
        let total_ops = {
            let mut probe = disk_with_gen1();
            commit(&mut probe, &key(), &LAYOUT, 2, 2, &gen2).expect("probe commit");
            probe.ops
        };
        let mut caught = 0usize;
        for at in 0..total_ops {
            let mut disk = disk_with_gen1();
            disk.drop_write_at = Some(at);
            let res = commit(&mut disk, &key(), &LAYOUT, 2, 2, &gen2);
            if disk.drop_write_at.is_some() {
                // `at` was a read or a flush, so nothing was dropped.
                assert!(res.is_ok(), "op {at}: {res:?}");
                continue;
            }
            caught += 1;
            assert!(
                matches!(res, Err(CommitError::Verify { .. })),
                "op {at}: a dropped write went unnoticed ({res:?})"
            );
            disk.flush().expect("flush");
            disk.reboot();
            let (r, out) = recover_image(&mut disk);
            r.unwrap_or_else(|e| panic!("op {at}: recovery failed with {e:?}"));
            assert!(
                same(&out, &gen1) || same(&out, &gen2),
                "op {at}: recovered a mixture"
            );
        }
        // Every sector of both slots plus both commit-record writes.
        assert_eq!(caught, 2 * STATE_IMAGE_SECTORS + 2);
        // And the commit uses exactly the four documented flush barriers.
        let mut counting = disk_with_gen1();
        let before = counting.flushes;
        commit(&mut counting, &key(), &LAYOUT, 2, 2, &gen2).expect("commit");
        assert_eq!(counting.flushes - before, 4);
    }

    #[test]
    fn dropped_shadow_write_leaves_the_previous_state_committed() {
        let mut disk = disk_with_gen1();
        // The first operations of a commit are the shadow-slot writes.
        disk.drop_write_at = Some(5);
        assert_eq!(
            commit(&mut disk, &key(), &LAYOUT, 2, 2, &image(2)),
            Err(CommitError::Verify {
                stage: CommitStage::Stage
            })
        );
        disk.flush().expect("flush");
        disk.reboot();
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("recover");
        assert_eq!(r.source, RecoverySource::Primary);
        assert_eq!(r.commit.map(|h| h.commit_seq), Some(1));
        assert!(r.repaired_shadow, "the half-staged shadow slot must be re-synced");
        assert!(same(&out, &image(1)));
    }

    #[test]
    fn refused_repair_is_reported_but_the_recovered_image_is_still_valid() {
        let mut disk = disk_with_gen1();
        disk.poke(LAYOUT.primary_lba + 1, |s| s[0] ^= 0x80);
        // 1 commit read + 26 primary reads + 26 shadow reads, then the first
        // repair write.
        disk.io_error_at = Some(1 + 2 * STATE_IMAGE_SECTORS);
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("recover");
        assert_eq!(r.source, RecoverySource::ShadowHeal);
        assert!(!r.repaired_primary);
        assert_eq!(r.repair_fault, Some(IoFault::DeviceError));
        assert!(same(&out, &image(1)));
    }

    #[test]
    fn unreadable_sector_in_either_slot_or_the_commit_record_does_not_stop_recovery() {
        let gen1 = image(1);
        // Primary: served from the shadow slot, and rewriting repairs it.
        for idx in [0u64, 7, 25] {
            let mut disk = disk_with_gen1();
            disk.unreadable.push(LAYOUT.primary_lba + idx);
            let (r, out) = recover_image(&mut disk);
            let r = r.unwrap_or_else(|e| panic!("primary sector {idx} unreadable: {e:?}"));
            assert_eq!(r.source, RecoverySource::ShadowHeal);
            assert!(r.repaired_primary);
            assert!(same(&out, &gen1));
            assert!(disk.unreadable.is_empty(), "the repair must rewrite the bad sector");
        }
        // Shadow: primary is used, shadow rewritten.
        let mut disk = disk_with_gen1();
        disk.unreadable.push(LAYOUT.shadow_lba + 9);
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("shadow sector unreadable");
        assert_eq!(r.source, RecoverySource::Primary);
        assert!(same(&out, &gen1));
        // Commit sector: falls back to the caller's seal checks.
        let mut disk = disk_with_gen1();
        disk.unreadable.push(LAYOUT.commit_lba);
        let (r, out) = recover_image(&mut disk);
        let r = r.expect("commit sector unreadable");
        assert_eq!(r.source, RecoverySource::Unjournaled);
        assert!(same(&out, &gen1));
        // Both slots unreadable with a valid record: nothing to return.
        let mut disk = disk_with_gen1();
        disk.unreadable.push(LAYOUT.primary_lba + 2);
        disk.unreadable.push(LAYOUT.shadow_lba + 2);
        let (r, _) = recover_image(&mut disk);
        assert!(matches!(r, Err(RecoverError::Io(IoFault::DeviceError))), "{r:?}");
    }

    #[test]
    fn saved_boots_reads_the_shell_header_generation() {
        let mut img = StateImage::zeroed();
        img.wal[0][8..16].copy_from_slice(&0x0102_0304_0506_0708u64.to_le_bytes());
        assert_eq!(img.saved_boots(), 0x0102_0304_0506_0708);
        img.clear();
        assert!(img.is_all_zero());
    }

    #[test]
    fn batched_commit_and_recovery_uses_multisector_transfers_and_supports_lba48() {
        use std::collections::BTreeMap;

        struct BatchSparseDisk {
            capacity: u64,
            max_batch: usize,
            sectors: BTreeMap<u64, [u8; SECTOR_BYTES]>,
            read_cmds: usize,
            write_cmds: usize,
            flush_cmds: usize,
            fail_cmd_at: Option<usize>,
        }

        impl BatchSparseDisk {
            fn new(capacity: u64, max_batch: usize) -> Self {
                Self {
                    capacity,
                    max_batch,
                    sectors: BTreeMap::new(),
                    read_cmds: 0,
                    write_cmds: 0,
                    flush_cmds: 0,
                    fail_cmd_at: None,
                }
            }

            fn total_cmds(&self) -> usize {
                self.read_cmds + self.write_cmds + self.flush_cmds
            }

            fn check_cmd(&mut self) -> Result<(), IoFault> {
                if self.fail_cmd_at == Some(self.total_cmds()) {
                    self.fail_cmd_at = None;
                    return Err(IoFault::DeviceError);
                }
                Ok(())
            }
        }

        impl SectorIo for BatchSparseDisk {
            fn capacity_sectors(&self) -> u64 {
                self.capacity
            }

            fn read_sector(&mut self, lba: u64, out: &mut [u8; SECTOR_BYTES]) -> Result<(), IoFault> {
                self.read_sectors(lba, core::slice::from_mut(out))
            }

            fn write_sector(&mut self, lba: u64, data: &[u8; SECTOR_BYTES]) -> Result<(), IoFault> {
                self.write_sectors(lba, core::slice::from_ref(data))
            }

            fn flush(&mut self) -> Result<(), IoFault> {
                self.check_cmd()?;
                self.flush_cmds += 1;
                Ok(())
            }

            fn read_sectors(
                &mut self,
                lba: u64,
                out: &mut [[u8; SECTOR_BYTES]],
            ) -> Result<(), IoFault> {
                let end = lba.checked_add(out.len() as u64).ok_or(IoFault::OutOfRange)?;
                if end > self.capacity {
                    return Err(IoFault::OutOfRange);
                }
                let mut off = 0usize;
                while off < out.len() {
                    let take = (out.len() - off).min(self.max_batch);
                    self.check_cmd()?;
                    self.read_cmds += 1;
                    for i in 0..take {
                        let cur = lba + (off + i) as u64;
                        out[off + i] = self.sectors.get(&cur).copied().unwrap_or([0u8; SECTOR_BYTES]);
                    }
                    off += take;
                }
                Ok(())
            }

            fn write_sectors(
                &mut self,
                lba: u64,
                data: &[[u8; SECTOR_BYTES]],
            ) -> Result<(), IoFault> {
                let end = lba.checked_add(data.len() as u64).ok_or(IoFault::OutOfRange)?;
                if end > self.capacity {
                    return Err(IoFault::OutOfRange);
                }
                let mut off = 0usize;
                while off < data.len() {
                    let take = (data.len() - off).min(self.max_batch);
                    self.check_cmd()?;
                    self.write_cmds += 1;
                    for i in 0..take {
                        let cur = lba + (off + i) as u64;
                        self.sectors.insert(cur, data[off + i]);
                    }
                    off += take;
                }
                Ok(())
            }

            fn read_sector_slices(
                &mut self,
                lba: u64,
                slices: &mut [&mut [[u8; SECTOR_BYTES]]],
            ) -> Result<(), IoFault> {
                let total: usize = slices.iter().map(|s| s.len()).sum();
                let end = lba.checked_add(total as u64).ok_or(IoFault::OutOfRange)?;
                if end > self.capacity {
                    return Err(IoFault::OutOfRange);
                }
                let mut flat = std::vec![[0u8; SECTOR_BYTES]; total];
                self.read_sectors(lba, &mut flat)?;
                let mut pos = 0usize;
                for s in slices.iter_mut() {
                    let n = s.len();
                    s.copy_from_slice(&flat[pos..pos + n]);
                    pos += n;
                }
                Ok(())
            }

            fn write_sector_slices(
                &mut self,
                lba: u64,
                slices: &[&[[u8; SECTOR_BYTES]]],
            ) -> Result<(), IoFault> {
                let total: usize = slices.iter().map(|s| s.len()).sum();
                let end = lba.checked_add(total as u64).ok_or(IoFault::OutOfRange)?;
                if end > self.capacity {
                    return Err(IoFault::OutOfRange);
                }
                let mut flat = std::vec::Vec::with_capacity(total);
                for s in slices {
                    flat.extend_from_slice(s);
                }
                self.write_sectors(lba, &flat)
            }
        }

        // 1. Place layout past the 28-bit LBA limit (`1 << 28` = 268,435,456 sectors).
        let high_base = (1u64 << 28) + 4096;
        let high_layout = StoreLayout {
            primary_lba: high_base,
            shadow_lba: high_base + 64,
            commit_lba: high_base + 128,
        };
        let mut batch_disk = BatchSparseDisk::new(1u64 << 32, 64);
        let img1 = image(7);
        commit(&mut batch_disk, &key(), &high_layout, 3, 1, &img1).expect("LBA48 batched commit");

        // Unbatched single-sector commit needed 220 device commands (4*53 + 8).
        // With batched slot writes and chunked read-back, a full 4-barrier commit
        // must take at most 24 device commands (2 slot writes + 14 read-back chunks
        // + 2 commit writes + 2 commit reads + 4 flushes).
        assert!(
            batch_disk.total_cmds() <= 24,
            "expected batched commit <= 24 device commands, got {} (reads={} writes={} flushes={})",
            batch_disk.total_cmds(),
            batch_disk.read_cmds,
            batch_disk.write_cmds,
            batch_disk.flush_cmds,
        );
        assert_eq!(batch_disk.flush_cmds, 4);

        // 2. Equivalence against single-sector MemDisk at standard layout.
        let mut mem_disk = MemDisk::new(DISK_SECTORS);
        commit(&mut mem_disk, &key(), &LAYOUT, 3, 1, &img1).expect("mem commit");
        for i in 0..STATE_IMAGE_SECTORS as u64 {
            assert_eq!(
                batch_disk.sectors.get(&(high_layout.primary_lba + i)).copied().unwrap(),
                mem_disk.peek(LAYOUT.primary_lba + i)
            );
            assert_eq!(
                batch_disk.sectors.get(&(high_layout.shadow_lba + i)).copied().unwrap(),
                mem_disk.peek(LAYOUT.shadow_lba + i)
            );
        }
        assert_eq!(
            batch_disk.sectors.get(&high_layout.commit_lba).copied().unwrap(),
            mem_disk.peek(LAYOUT.commit_lba)
        );

        // 3. Recovery and shadow self-heal at 48-bit LBA with batched reads/writes.
        batch_disk.sectors.get_mut(&(high_layout.primary_lba + 19)).unwrap()[0] ^= 0xFF;
        let mut recovered = Box::new(StateImage::zeroed());
        let rep = recover(&mut batch_disk, &key(), &high_layout, &mut recovered)
            .expect("LBA48 shadow heal");
        assert_eq!(rep.source, RecoverySource::ShadowHeal);
        assert!(rep.repaired_primary);
        assert!(same(&recovered, &img1));
    }
}

/// End-to-end tests: a real [`OsShell`] committed through [`ShellStore`] to
/// the fault-injecting disk, then booted again.
#[cfg(test)]
mod node_tests {
    use super::testdisk::{CacheLoss, MemDisk};
    use super::*;
    use crate::durable_seal::{
        derive_seal_key, DEFAULT_ATTEST_KEY, DEFAULT_DURABLE_SEAL_KEY,
        DEFAULT_LEGACY_DURABLE_SEAL_KEY,
    };
    use cuttle_contracts::Filesystem;
    extern crate std;
    use std::boxed::Box;
    use std::string::String;
    use std::vec::Vec;

    const DISK_SECTORS: usize = 2048;

    fn keys() -> ShellKeys {
        ShellKeys {
            seal: DEFAULT_DURABLE_SEAL_KEY,
            legacy_seal: DEFAULT_LEGACY_DURABLE_SEAL_KEY,
            attest: DEFAULT_ATTEST_KEY,
        }
    }

    fn other_keys() -> ShellKeys {
        ShellKeys {
            seal: derive_seal_key(&DEFAULT_DURABLE_SEAL_KEY, b"a-boot-without-the-device-key"),
            ..keys()
        }
    }

    fn store() -> Box<ShellStore> {
        Box::new(ShellStore::new(AHCI_STATE_LAYOUT, AHCI_QUARANTINE_LBA))
    }

    fn fresh_shell(boots: u64) -> Box<OsShell> {
        let mut sh = Box::new(OsShell::empty());
        reset_shell(&mut sh, &keys(), boots);
        sh
    }

    fn run(sh: &mut OsShell, line: &str) -> String {
        let mut out = [0u8; 1024];
        let act = sh.exec_line(line.as_bytes(), 1, 0, 0, &mut out);
        String::from_utf8_lossy(&out[..act.bytes_written()]).into_owned()
    }

    fn sql(sh: &mut OsShell, q: &str) -> String {
        let mut out = [0u8; 1024];
        let n = sh.db.exec(q.as_bytes(), &mut out);
        String::from_utf8_lossy(&out[..n]).into_owned()
    }

    /// Put the shell into a recognisable generation: one file, one SQL row,
    /// one firewall rule, all derived from `tag`.
    fn apply_generation(sh: &mut OsShell, tag: &str) {
        assert!(run(sh, &std::format!("write /var/gen {tag}")).starts_with("wrote "));
        let _ = sql(sh, "DELETE FROM kv WHERE k = 'gen'");
        assert_eq!(
            sql(sh, &std::format!("INSERT INTO kv VALUES ('gen', '{tag}', 1)")),
            "INSERT 1\n"
        );
    }

    /// The generation a shell is in, or a description of the mixture.
    fn generation(sh: &mut OsShell) -> String {
        let file = run(sh, "cat /var/gen");
        let row = sql(sh, "SELECT v FROM kv WHERE k = 'gen'");
        let file = String::from(file.trim_end());
        let row = String::from(row.lines().nth(1).unwrap_or("<no row>"));
        if file == row {
            file
        } else {
            std::format!("MIXED file={file:?} row={row:?}")
        }
    }

    /// A disk holding generation "one" committed at boot generation 1.
    fn disk_with_one() -> MemDisk {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);
        apply_generation(&mut sh, "one");
        let mut st = store();
        assert!(matches!(
            st.commit(&mut disk, &mut sh, 1).expect("genesis commit"),
            Committed::Written { .. }
        ));
        disk.reboot();
        disk
    }

    fn boot(disk: &mut MemDisk, k: &ShellKeys, counter: u64) -> (BootReport, Box<OsShell>, Box<ShellStore>) {
        let mut sh = Box::new(OsShell::empty());
        let mut st = store();
        let report = st.boot(disk, &mut sh, k, counter).expect("boot");
        (report, sh, st)
    }

    #[test]
    fn blank_disk_boots_fresh_and_first_commit_round_trips() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let (report, mut sh, mut st) = boot(&mut disk, &keys(), 1);
        assert_eq!(report.outcome, BootOutcome::Fresh);
        assert_eq!(report.boots, 1);
        assert!(!quarantine_present(&mut disk, AHCI_QUARANTINE_LBA).unwrap());

        apply_generation(&mut sh, "one");
        assert!(run(&mut sh, "fw block 10.9.0.0/16").starts_with("fw: blocked"));
        st.commit(&mut disk, &mut sh, 1).expect("commit");
        disk.reboot();

        let (report, mut sh2, _) = boot(&mut disk, &keys(), 2);
        match report.outcome {
            BootOutcome::Restored {
                restore,
                source,
                from_quarantine,
                recommitted,
                ..
            } => {
                assert_eq!(restore.saved_boots, 1);
                assert_eq!(source, RecoverySource::Primary);
                assert!(!from_quarantine && !recommitted);
            }
            other => panic!("expected Restored, got {other:?}"),
        }
        assert_eq!(report.boots, 2);
        assert_eq!(generation(&mut sh2), "one");
        assert_eq!(sh2.fw.as_slice().len(), 1);
    }

    #[test]
    fn unchanged_state_is_not_rewritten() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);
        apply_generation(&mut sh, "one");
        let mut st = store();
        st.commit(&mut disk, &mut sh, 1).expect("commit");
        let ops = disk.ops;
        assert_eq!(st.commit(&mut disk, &mut sh, 1), Ok(Committed::Unchanged));
        assert_eq!(disk.ops, ops, "an unchanged image must not touch the device");
        // A read-only command changes nothing durable.
        let fp = sh.durable_fingerprint();
        let _ = run(&mut sh, "cat /var/gen");
        let _ = run(&mut sh, "status");
        assert_eq!(sh.durable_fingerprint(), fp);
        assert_eq!(st.commit(&mut disk, &mut sh, 1), Ok(Committed::Unchanged));
    }

    /// Every kind of durable change must move the fingerprint the kernel
    /// watches, or the change would sit in memory until something else
    /// happened to trigger a commit.
    #[test]
    fn every_durable_change_moves_the_fingerprint() {
        let mut sh = fresh_shell(1);
        let mut last = sh.durable_fingerprint();
        let mut step = |sh: &mut OsShell, what: &str, f: &mut dyn FnMut(&mut OsShell)| {
            f(sh);
            let now = sh.durable_fingerprint();
            assert_ne!(now, last, "{what} did not change the durable fingerprint");
            last = now;
        };
        step(&mut sh, "file write", &mut |sh| {
            assert!(run(sh, "write /var/a hello").starts_with("wrote "));
        });
        step(&mut sh, "file overwrite", &mut |sh| {
            assert!(run(sh, "write /var/a world").starts_with("wrote "));
        });
        step(&mut sh, "file removal", &mut |sh| {
            assert!(run(sh, "rm /var/a").starts_with("removed "));
        });
        step(&mut sh, "spawn", &mut |sh| {
            assert!(run(sh, "spawn").starts_with("spawned pid="));
        });
        step(&mut sh, "grant", &mut |sh| {
            assert!(run(sh, "grant 5 fs").starts_with("granted "));
        });
        step(&mut sh, "firewall rule", &mut |sh| {
            assert!(run(sh, "fw block 10.1.0.0/16").starts_with("fw: blocked"));
        });
        step(&mut sh, "cron job", &mut |sh| {
            assert!(run(sh, "cron add 5 status").starts_with("cron: scheduled"));
        });
        step(&mut sh, "SQL insert", &mut |sh| {
            assert_eq!(sql(sh, "INSERT INTO kv VALUES ('a', 'b', 1)"), "INSERT 1\n");
        });
        step(&mut sh, "anti-replay watermark", &mut |sh| sh.auth_seq = 9);
        step(&mut sh, "lockdown", &mut |sh| sh.guard_lockdown = true);

        // Inside a transaction the committed image does not change, so the
        // fingerprint must hold still; COMMIT is the moment it moves.
        assert_eq!(sql(&mut sh, "BEGIN"), "BEGIN OK\n");
        let before = sh.durable_fingerprint();
        assert_eq!(sql(&mut sh, "INSERT INTO kv VALUES ('t', 'x', 1)"), "INSERT 1\n");
        assert_eq!(
            sh.durable_fingerprint(),
            before,
            "an uncommitted statement must not look like a durable change"
        );
        assert_eq!(sql(&mut sh, "COMMIT"), "COMMIT OK\n");
        assert_ne!(
            sh.durable_fingerprint(),
            before,
            "COMMIT must be seen as a durable change"
        );
    }

    #[test]
    fn committed_transaction_is_on_disk_and_uncommitted_one_is_not() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);
        let mut st = store();
        assert_eq!(sql(&mut sh, "BEGIN"), "BEGIN OK\n");
        assert_eq!(sql(&mut sh, "INSERT INTO kv VALUES ('paid', 'yes', 1)"), "INSERT 1\n");
        st.commit(&mut disk, &mut sh, 1).expect("commit while a transaction is open");
        disk.reboot();
        let (_, mut mid, _) = boot(&mut disk, &keys(), 2);
        assert_eq!(sql(&mut mid, "SELECT v FROM kv WHERE k = 'paid'"), "v\n");

        assert_eq!(sql(&mut sh, "COMMIT"), "COMMIT OK\n");
        assert!(matches!(
            st.commit(&mut disk, &mut sh, 1).expect("commit after COMMIT"),
            Committed::Written { .. }
        ));
        disk.reboot();
        let (_, mut after, _) = boot(&mut disk, &keys(), 2);
        assert_eq!(sql(&mut after, "SELECT v FROM kv WHERE k = 'paid'"), "v\nyes\n");
    }

    /// The node-level version of the store's central guarantee, on a real
    /// shell: a power cut at any device operation of a commit leaves a node
    /// that boots into exactly the old state or exactly the new one, and a
    /// commit that returned `Ok` is never lost.
    #[test]
    fn power_cut_during_commit_boots_into_old_or_new_state_never_a_mixture() {
        let total_ops = {
            let mut disk = disk_with_one();
            let (_, mut sh, mut st) = boot(&mut disk, &keys(), 2);
            apply_generation(&mut sh, "two");
            let before = disk.ops;
            st.commit(&mut disk, &mut sh, 2).expect("probe commit");
            disk.ops - before
        };
        let mut seen = std::collections::BTreeMap::<String, usize>::new();
        for policy in [CacheLoss::DropAll, CacheLoss::Random(0xA076_1D64_78BD_642F)] {
            for cut in 0..=total_ops {
                let mut disk = disk_with_one();
                let (_, mut sh, mut st) = boot(&mut disk, &keys(), 2);
                apply_generation(&mut sh, "two");
                disk.cache_loss = policy;
                disk.power_cut_at = Some(disk.ops + cut);
                let committed = st.commit(&mut disk, &mut sh, 2);
                assert_eq!(committed.is_ok(), cut == total_ops, "policy={policy:?} cut={cut}");

                disk.reboot();
                let (report, mut sh2, _) = boot(&mut disk, &keys(), 3);
                assert!(
                    matches!(report.outcome, BootOutcome::Restored { .. }),
                    "policy={policy:?} cut={cut}: {:?}",
                    report.outcome
                );
                let state = generation(&mut sh2);
                assert!(
                    state == "one" || state == "two",
                    "policy={policy:?} cut={cut}: booted into {state}"
                );
                if committed.is_ok() {
                    assert_eq!(state, "two", "an acknowledged commit was lost");
                }
                *seen.entry(state).or_default() += 1;
            }
        }
        assert!(seen["one"] > 0 && seen["two"] > 0, "{seen:?}");
    }

    #[test]
    fn boot_counter_ahead_of_or_behind_the_saved_generation_still_restores() {
        // Ahead: earlier boots died before their first commit.
        let mut disk = disk_with_one();
        let (report, mut sh, _) = boot(&mut disk, &keys(), 10);
        assert!(matches!(report.outcome, BootOutcome::Restored { .. }));
        assert_eq!(report.boots, 10);
        assert_eq!(generation(&mut sh), "one");

        // Behind: the separate counter was lost and restarted at 1, while
        // the sealed state says generation 7.
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(7);
        apply_generation(&mut sh, "seven");
        store().commit(&mut disk, &mut sh, 7).expect("commit");
        disk.reboot();
        let (report, mut sh2, _) = boot(&mut disk, &keys(), 1);
        match report.outcome {
            BootOutcome::Restored { restore, .. } => assert_eq!(restore.saved_boots, 7),
            other => panic!("a lost boot counter must not discard state: {other:?}"),
        }
        assert_eq!(report.boots, 8, "the generation must move past the saved one");
        assert_eq!(generation(&mut sh2), "seven");
    }

    #[test]
    fn damaged_or_zeroed_primary_slot_is_healed_not_treated_as_a_blank_disk() {
        // One flipped byte in the primary journal sector (what the QEMU
        // tamper test does at LBA 1041).
        let mut disk = disk_with_one();
        disk.poke(AHCI_STATE_LAYOUT.primary_lba + 1, |s| s[8] ^= 0xFF);
        let (report, mut sh, _) = boot(&mut disk, &keys(), 2);
        match report.outcome {
            BootOutcome::Restored {
                source,
                repaired_primary,
                ..
            } => {
                assert_eq!(source, RecoverySource::ShadowHeal);
                assert!(repaired_primary);
            }
            other => panic!("expected a healed restore, got {other:?}"),
        }
        assert_eq!(generation(&mut sh), "one");

        // The whole primary slot zeroed.
        let mut disk = disk_with_one();
        for i in 0..STATE_IMAGE_SECTORS as u64 {
            disk.poke(AHCI_STATE_LAYOUT.primary_lba + i, |s| *s = [0u8; SECTOR_BYTES]);
        }
        let (report, mut sh, _) = boot(&mut disk, &keys(), 2);
        assert!(
            matches!(
                report.outcome,
                BootOutcome::Restored {
                    source: RecoverySource::ShadowHeal,
                    ..
                }
            ),
            "{:?}",
            report.outcome
        );
        assert_eq!(generation(&mut sh), "one");
    }

    #[test]
    fn node_boots_through_an_unreadable_sector() {
        for lba in [
            AHCI_STATE_LAYOUT.primary_lba,
            AHCI_STATE_LAYOUT.primary_lba + 20,
            AHCI_STATE_LAYOUT.shadow_lba + 4,
            AHCI_STATE_LAYOUT.commit_lba,
        ] {
            let mut disk = disk_with_one();
            disk.unreadable.push(lba);
            let (report, mut sh, _) = boot(&mut disk, &keys(), 2);
            assert!(
                matches!(report.outcome, BootOutcome::Restored { .. }),
                "lba {lba}: {:?}",
                report.outcome
            );
            assert_eq!(generation(&mut sh), "one", "lba {lba}");
        }
    }

    #[test]
    fn a_partition_zeroed_in_both_slots_is_rejected_not_silently_reset() {
        for (name, first, count) in [
            ("filesystem", STATE_WAL_SECTORS, STATE_FS_SECTORS),
            ("sql", STATE_WAL_SECTORS + STATE_FS_SECTORS, STATE_SQL_SECTORS),
        ] {
            let mut disk = disk_with_one();
            for base in [AHCI_STATE_LAYOUT.primary_lba, AHCI_STATE_LAYOUT.shadow_lba] {
                for i in first..first + count {
                    disk.poke(base + i as u64, |s| *s = [0u8; SECTOR_BYTES]);
                }
            }
            // Without a commit record the per-partition seals must decide too.
            for wipe_commit in [false, true] {
                let mut d = MemDisk::new(DISK_SECTORS);
                for l in 0..DISK_SECTORS as u64 {
                    let sec = disk.peek(l);
                    d.poke(l, |s| *s = sec);
                }
                if wipe_commit {
                    d.poke(AHCI_STATE_LAYOUT.commit_lba, |s| *s = [0u8; SECTOR_BYTES]);
                }
                let (report, _, _) = boot(&mut d, &keys(), 2);
                assert_eq!(
                    report.outcome,
                    BootOutcome::Rejected { preserved: true },
                    "{name} partition zeroed, wipe_commit={wipe_commit}"
                );
            }
        }
    }

    #[test]
    fn lost_commit_record_restores_from_the_sealed_partitions_and_rejournals() {
        let mut disk = disk_with_one();
        disk.poke(AHCI_STATE_LAYOUT.commit_lba, |s| *s = [0u8; SECTOR_BYTES]);
        let (report, mut sh, _) = boot(&mut disk, &keys(), 2);
        match report.outcome {
            BootOutcome::Restored {
                source, recommitted, ..
            } => {
                assert_eq!(source, RecoverySource::Unjournaled);
                assert!(recommitted, "the commit record must be re-established");
            }
            other => panic!("{other:?}"),
        }
        assert_eq!(generation(&mut sh), "one");
        disk.reboot();
        let (again, _, _) = boot(&mut disk, &keys(), 3);
        assert!(matches!(
            again.outcome,
            BootOutcome::Restored {
                source: RecoverySource::Primary,
                recommitted: false,
                ..
            }
        ));

        // Same, with the primary slot also damaged: the shadow slot's own
        // seals are enough.
        let mut disk = disk_with_one();
        disk.poke(AHCI_STATE_LAYOUT.commit_lba, |s| *s = [0u8; SECTOR_BYTES]);
        disk.poke(AHCI_STATE_LAYOUT.primary_lba + 5, |s| s[17] ^= 1);
        let (report, mut sh, _) = boot(&mut disk, &keys(), 2);
        assert!(matches!(report.outcome, BootOutcome::Restored { .. }), "{:?}", report.outcome);
        assert_eq!(generation(&mut sh), "one");
    }

    #[test]
    fn unverifiable_state_is_preserved_before_the_node_starts_over() {
        let mut disk = disk_with_one();
        disk.poke(AHCI_STATE_LAYOUT.primary_lba + 3, |s| s[1] ^= 0xFF);
        disk.poke(AHCI_STATE_LAYOUT.shadow_lba + 3, |s| s[1] ^= 0xFF);
        let slots_before: Vec<_> = (0..STATE_IMAGE_SECTORS as u64)
            .flat_map(|i| {
                [
                    disk.peek(AHCI_STATE_LAYOUT.primary_lba + i),
                    disk.peek(AHCI_STATE_LAYOUT.shadow_lba + i),
                ]
            })
            .collect();

        let (report, mut sh, mut st) = boot(&mut disk, &keys(), 2);
        assert_eq!(report.outcome, BootOutcome::Rejected { preserved: true });
        assert!(generation(&mut sh).starts_with("MIXED"), "a rejected boot must start from defaults");
        assert!(quarantine_present(&mut disk, AHCI_QUARANTINE_LBA).unwrap());

        // The node starts over and commits; the rejected bytes are still
        // there, sector for sector, in the quarantine area.
        apply_generation(&mut sh, "restart");
        st.commit(&mut disk, &mut sh, 2).expect("commit after rejection");
        let q = quarantine_layout(AHCI_QUARANTINE_LBA);
        let kept: Vec<_> = (0..STATE_IMAGE_SECTORS as u64)
            .flat_map(|i| [disk.peek(q.primary_lba + i), disk.peek(q.shadow_lba + i)])
            .collect();
        assert!(slots_before == kept, "quarantine does not hold the rejected slots");

        // Once verified state boots again, the area is released.
        disk.reboot();
        let (report, mut sh2, _) = boot(&mut disk, &keys(), 3);
        assert!(matches!(report.outcome, BootOutcome::Restored { .. }));
        assert_eq!(generation(&mut sh2), "restart");
        assert!(!quarantine_present(&mut disk, AHCI_QUARANTINE_LBA).unwrap());
    }

    /// The accident this guards against: the node is booted once without its
    /// device key (so it runs on a throwaway key), cannot authenticate the
    /// disk, starts over and overwrites both slots. When the key is back,
    /// the original state must come back with it.
    #[test]
    fn state_survives_boots_without_the_device_key() {
        let mut disk = disk_with_one();

        // Two boots on throwaway keys, each committing its own fresh state.
        for (n, k) in [other_keys(), ShellKeys { seal: [0x5A; 32], ..keys() }]
            .iter()
            .enumerate()
        {
            let (report, mut sh, mut st) = boot(&mut disk, k, 2 + n as u64);
            assert_eq!(report.outcome, BootOutcome::Rejected { preserved: true }, "keyless boot {n}");
            assert!(run(&mut sh, "write /var/gen keyless").starts_with("wrote "));
            st.commit(&mut disk, &mut sh, 2 + n as u64).expect("keyless commit");
            disk.reboot();
        }

        // The device key is back.
        let (report, mut sh, _) = boot(&mut disk, &keys(), 4);
        match report.outcome {
            BootOutcome::Restored {
                restore,
                from_quarantine,
                recommitted,
                ..
            } => {
                assert!(from_quarantine && recommitted);
                assert_eq!(restore.saved_boots, 1);
            }
            other => panic!("the original state was not recovered: {other:?}"),
        }
        assert_eq!(generation(&mut sh), "one");
        assert!(!quarantine_present(&mut disk, AHCI_QUARANTINE_LBA).unwrap());

        // And it is back in the store proper.
        disk.reboot();
        let (report, mut sh, _) = boot(&mut disk, &keys(), 5);
        assert!(matches!(
            report.outcome,
            BootOutcome::Restored {
                from_quarantine: false,
                source: RecoverySource::Primary,
                ..
            }
        ));
        assert_eq!(generation(&mut sh), "one");
    }

    #[test]
    fn failed_commit_is_reported_and_the_next_boot_is_consistent() {
        // Count the operations of the commit that will be made to fail.
        let mut dry = disk_with_one();
        let (_, mut sh, mut st) = boot(&mut dry, &keys(), 2);
        apply_generation(&mut sh, "two");
        dry.ops = 0;
        st.commit(&mut dry, &mut sh, 2).expect("dry run");
        let total = dry.ops;

        let (mut old, mut new) = (0usize, 0usize);
        for fail_at in 0..total {
            let mut disk = disk_with_one();
            let (_, mut sh, mut st) = boot(&mut disk, &keys(), 2);
            apply_generation(&mut sh, "two");
            disk.ops = 0;
            disk.io_error_at = Some(fail_at);
            let err = st.commit(&mut disk, &mut sh, 2).expect_err("device error");
            assert!(
                matches!(err, PersistError::Commit(CommitError::Io { .. })),
                "op {fail_at}: {err:?}"
            );
            assert!(st.is_faulted(), "op {fail_at}");

            // What the disk holds is undecided until recovery runs. The store
            // neither reports "unchanged" nor writes over the slots again: a
            // second attempt would stage over the one slot that may be the
            // only complete copy.
            let ops_before = disk.ops;
            assert_eq!(
                st.commit(&mut disk, &mut sh, 2),
                Err(PersistError::StoreFaulted),
                "op {fail_at}"
            );
            assert_eq!(disk.ops, ops_before, "op {fail_at}: a refused commit touched the device");

            // The next boot settles it: the old state or the new one, whole.
            disk.reboot();
            let (report, mut sh2, mut st2) = boot(&mut disk, &keys(), 3);
            assert!(
                matches!(report.outcome, BootOutcome::Restored { .. }),
                "op {fail_at}: {:?}",
                report.outcome
            );
            match generation(&mut sh2).as_str() {
                "one" => old += 1,
                "two" => new += 1,
                other => panic!("op {fail_at}: {other}"),
            }

            // And the store takes commits again.
            assert!(!st2.is_faulted());
            apply_generation(&mut sh2, "three");
            assert!(matches!(
                st2.commit(&mut disk, &mut sh2, 3).expect("commit after recovery"),
                Committed::Written { .. }
            ));
            disk.reboot();
            let (_, mut sh3, _) = boot(&mut disk, &keys(), 4);
            assert_eq!(generation(&mut sh3), "three", "op {fail_at}");
        }
        assert!(old > 0 && new > 0, "old={old} new={new}");
    }

    /// The state is in the shadow slot only, and the device will not let the
    /// primary slot be rewritten from it. The next commit would stage its
    /// image over that shadow slot, so a node in this condition must not
    /// come up as if it were healthy.
    #[test]
    fn a_primary_slot_the_device_will_not_let_be_repaired_stops_the_boot() {
        let damaged = || {
            let mut d = disk_with_one();
            d.poke(AHCI_STATE_LAYOUT.primary_lba + 1, |s| s[8] ^= 0xFF);
            d
        };
        let mut dry = damaged();
        let (report, _, _) = boot(&mut dry, &keys(), 2);
        assert!(matches!(
            report.outcome,
            BootOutcome::Restored {
                source: RecoverySource::ShadowHeal,
                repaired_primary: true,
                ..
            }
        ));
        let total = dry.ops;

        let (mut stopped, mut served) = (0usize, 0usize);
        for fail_at in 0..total {
            let mut disk = damaged();
            disk.io_error_at = Some(fail_at);
            let mut sh = Box::new(OsShell::empty());
            let mut st = store();
            match st.boot(&mut disk, &mut sh, &keys(), 2) {
                Ok(report) => {
                    served += 1;
                    if let BootOutcome::Restored {
                        source,
                        repaired_primary,
                        ..
                    } = report.outcome
                    {
                        let from_shadow = matches!(
                            source,
                            RecoverySource::ShadowHeal | RecoverySource::JournalReplay
                        );
                        assert!(
                            !from_shadow || repaired_primary,
                            "error at op {fail_at}: serving from the shadow slot with the primary slot still damaged"
                        );
                    }
                    assert_eq!(generation(&mut sh), "one", "error at op {fail_at}");
                }
                Err(e) => {
                    stopped += 1;
                    assert!(matches!(e, BootError::Io(_)), "error at op {fail_at}: {e:?}");
                }
            }
            // Whatever this boot did, the state is still there for the next one.
            disk.reboot();
            let (_, mut sh2, _) = boot(&mut disk, &keys(), 3);
            assert_eq!(generation(&mut sh2), "one", "error at op {fail_at}");
        }
        assert!(stopped > 0 && served > 0, "stopped={stopped} served={served}");
    }

    #[test]
    fn an_unverifiable_disk_is_not_restarted_from_zero_under_a_rollback_floor() {
        let mut disk = disk_with_one();
        disk.poke(AHCI_STATE_LAYOUT.primary_lba + 3, |s| s[1] ^= 0xFF);
        disk.poke(AHCI_STATE_LAYOUT.shadow_lba + 3, |s| s[1] ^= 0xFF);
        let before: Vec<_> = (0..DISK_SECTORS as u64).map(|l| disk.peek(l)).collect();

        let mut sh = Box::new(OsShell::empty());
        let mut st = store();
        st.set_min_commit_seq(1);
        assert_eq!(
            st.boot(&mut disk, &mut sh, &keys(), 2),
            Err(BootError::Rollback {
                found: 0,
                min_expected: 1,
            })
        );
        assert!(sh.fs.stat(b"/var/gen").is_err());
        disk.reboot();
        assert!(
            (0..DISK_SECTORS as u64).all(|l| disk.peek(l) == before[l as usize]),
            "a refused boot wrote to the disk"
        );

        // Without a floor the same disk is set aside and the node starts over.
        let (report, _, _) = boot(&mut disk, &keys(), 2);
        assert_eq!(report.outcome, BootOutcome::Rejected { preserved: true });
    }

    /// What happens today when the page store runs out of logical pages: the
    /// shell has no admission check for it, so the command is accepted and
    /// the commit that follows fails. That failure is safe (nothing reaches
    /// the device, and the last committed state comes back whole), which is
    /// what this test pins. It is not graceful: the kernel treats a failed
    /// commit as a storage fault and halts. See Claude-Recommendations.md;
    /// when the shell learns to refuse the command with `ENOSPC` instead,
    /// this test should change to expect that.
    #[test]
    fn a_full_page_store_fails_the_commit_without_writing_and_loses_nothing_committed() {
        use crate::paged_store::{PagedBlockStore, PAGED_STORE_MIN_DISK_SECTORS};
        let cap = PAGED_STORE_MIN_DISK_SECTORS as usize;
        let max_logical = PagedBlockStore::max_logical_pages_for_sectors(cap as u64);
        let mut disk = MemDisk::new(cap);
        let (_, mut sh, mut st) = boot(&mut disk, &keys(), 1);
        apply_generation(&mut sh, "one");
        st.commit(&mut disk, &mut sh, 1).expect("first commit");

        // Files of two pages each, committed one at a time, until one does not fit.
        let body: Vec<u8> = (0..4001usize).map(|i| (i % 251) as u8).collect();
        let mut committed_files = 0usize;
        let mut refused = None;
        for f in 0..90usize {
            let path = std::format!("/var/fill_{f:02}.bin");
            sh.fs
                .seed_file(path.as_bytes(), &body, body.len(), 500 + f as u64)
                .expect("the filesystem itself has room");
            let ops_before = disk.ops;
            match st.commit(&mut disk, &mut sh, 1) {
                Ok(_) => committed_files += 1,
                Err(e) => {
                    assert_eq!(disk.ops, ops_before, "a commit that cannot fit wrote to the device");
                    refused = Some(e);
                    break;
                }
            }
        }
        let err = refused.expect("the page store never filled");
        assert!(
            matches!(err, PersistError::Pack(StatePackError::Filesystem(_))),
            "{err:?}"
        );
        assert!(!st.is_faulted(), "nothing was written, so there is nothing to recover");
        assert!(
            committed_files * 2 > max_logical / 2 && committed_files * 2 < max_logical,
            "filled {committed_files} two-page files into {max_logical} logical pages"
        );

        // Everything that was committed is still there, byte for byte.
        disk.reboot();
        let (report, mut sh2, _) = boot(&mut disk, &keys(), 2);
        assert!(matches!(report.outcome, BootOutcome::Restored { .. }), "{:?}", report.outcome);
        assert_eq!(generation(&mut sh2), "one");
        for f in 0..committed_files {
            let path = std::format!("/var/fill_{f:02}.bin");
            let h = sh2
                .fs
                .open(path.as_bytes(), cuttle_contracts::FS_O_RDONLY)
                .unwrap_or_else(|_| panic!("{path} lost"));
            let mut back = std::vec![0u8; body.len()];
            assert_eq!(sh2.fs.read(h, 0, &mut back).unwrap(), body.len(), "{path}");
            sh2.fs.close(h).unwrap();
            assert!(back == body, "{path} changed");
        }
        let not_committed = std::format!("/var/fill_{committed_files:02}.bin");
        assert!(sh2.fs.stat(not_committed.as_bytes()).is_err());
    }

    /// The page store is too large to copy aside, so a boot that cannot use
    /// it must leave it alone. The accident this guards against is the same
    /// one as `state_survives_boots_without_the_device_key`: one boot with
    /// the wrong key.
    #[test]
    fn a_paged_disk_this_boot_cannot_authenticate_is_left_untouched_until_it_can() {
        use crate::paged_store::PAGED_STORE_MIN_DISK_SECTORS;
        let cap = PAGED_STORE_MIN_DISK_SECTORS as usize;
        let mut disk = MemDisk::new(cap);
        let (report, mut sh, mut st) = boot(&mut disk, &keys(), 1);
        assert_eq!(report.outcome, BootOutcome::Fresh);
        assert!(sh.is_paged_mode());
        apply_generation(&mut sh, "one");
        assert!(sql(&mut sh, "CREATE TABLE big (id INT, v TEXT)").ends_with("OK\n"));
        for r in 0..200 {
            assert_eq!(
                sql(&mut sh, &std::format!("INSERT INTO big VALUES ({r}, 'row-{r}')")),
                "INSERT 1\n"
            );
        }
        st.commit(&mut disk, &mut sh, 1).expect("commit");
        assert!(st.paged_store().allocated_page_count() >= 8);
        disk.reboot();
        let snapshot = |d: &MemDisk| -> Vec<[u8; SECTOR_BYTES]> {
            (0..cap as u64).map(|l| d.peek(l)).collect()
        };
        let before = snapshot(&disk);

        // A boot with the wrong device key, twice.
        for (n, k) in [other_keys(), ShellKeys { seal: [0x5A; 32], ..keys() }]
            .iter()
            .enumerate()
        {
            let mut sh_w = Box::new(OsShell::empty());
            let mut st_w = store();
            assert_eq!(
                st_w.boot(&mut disk, &mut sh_w, k, 2 + n as u64),
                Err(BootError::PagedStore(PagedBootFault::Unanchored)),
                "wrong-key boot {n}"
            );
            assert!(sh_w.fs.stat(b"/var/gen").is_err());
            disk.reboot();
            assert!(snapshot(&disk) == before, "wrong-key boot {n} wrote to the disk");
        }

        // The device key is back, and so is everything else.
        let (report, mut sh2, _) = boot(&mut disk, &keys(), 4);
        assert!(
            matches!(
                report.outcome,
                BootOutcome::Restored {
                    from_quarantine: false,
                    ..
                }
            ),
            "{:?}",
            report.outcome
        );
        assert_eq!(generation(&mut sh2), "one");
        assert_eq!(sql(&mut sh2, "SELECT COUNT(*) FROM big"), "count\n200\n");

        // The state slots wiped, the page store intact: also not a blank disk.
        let mut wiped = MemDisk::new(cap);
        for (l, sec) in before.iter().enumerate() {
            wiped.poke(l as u64, |s| *s = *sec);
        }
        for l in AHCI_STATE_LAYOUT.primary_lba..=AHCI_STATE_LAYOUT.commit_lba {
            wiped.poke(l, |s| *s = [0u8; SECTOR_BYTES]);
        }
        let wiped_before = snapshot(&wiped);
        let mut sh_z = Box::new(OsShell::empty());
        let mut st_z = store();
        assert_eq!(
            st_z.boot(&mut wiped, &mut sh_z, &keys(), 5),
            Err(BootError::PagedStore(PagedBootFault::Unanchored))
        );
        wiped.reboot();
        assert!(snapshot(&wiped) == wiped_before);
    }

    #[test]
    fn boot_refuses_an_unset_key_and_a_layout_that_does_not_fit() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = Box::new(OsShell::empty());
        let unset = ShellKeys {
            seal: [0u8; 32],
            ..keys()
        };
        assert_eq!(store().boot(&mut disk, &mut sh, &unset, 1), Err(BootError::KeyUnset));
        // Quarantine area (`1216..=1323`) past the end of the device.
        let mut small = MemDisk::new(1300);
        assert_eq!(store().boot(&mut small, &mut sh, &keys(), 1), Err(BootError::BadLayout));
        // Quarantine area overlapping the shadow slot (`1096..=1148`).
        let mut overlapping = Box::new(ShellStore::new(AHCI_STATE_LAYOUT, 1110));
        assert_eq!(
            overlapping.boot(&mut disk, &mut sh, &keys(), 1),
            Err(BootError::BadLayout)
        );
        assert_eq!(disk.ops, 0);
    }

    /// Whatever the shell accepts, it can persist. Before the journal budget
    /// existed, a few firewall rules, IMA digests and cron jobs (or two
    /// 200-byte files) overflowed the 512-byte journal sector, after which
    /// every commit failed and nothing reached the disk again.
    #[test]
    fn every_state_the_shell_accepts_can_be_packed_and_restored() {
        let mut sh = fresh_shell(1);
        let mut image = Box::new(StateImage::zeroed());
        let mut refused = 0usize;
        let mut accepted = 0usize;
        let mut note = |reply: String, sh: &mut OsShell, image: &mut StateImage, what: &str| {
            if reply.contains("ENOSPC") {
                refused += 1;
            } else if !reply.starts_with("error:") {
                accepted += 1;
            }
            sh.pack_state_image(1, image)
                .unwrap_or_else(|e| panic!("state became unpersistable after `{what}`: {e:?}"));
        };
        // Records the kernel raises on its own must always fit as well.
        sh.auth_seq = 77;
        sh.http_login_seq = 3;
        for i in 0..20u32 {
            let r = run(&mut sh, "spawn");
            note(r, &mut sh, &mut image, "spawn");
            let line = std::format!("fw block 10.{i}.0.0/16");
            let r = run(&mut sh, &line);
            note(r, &mut sh, &mut image, &line);
            let line = std::format!("cron add {} echo-periodic-health-sweep-{i:02}", 5 + i);
            let r = run(&mut sh, &line);
            note(r, &mut sh, &mut image, &line);
            // A fresh file each round across the 20 user inode slots (`4` system + `20` user = `24`).
            let line = std::format!("write /var/custom-service-plugin-{i:02} payload-{i}");
            let r = run(&mut sh, &line);
            note(r, &mut sh, &mut image, &line);
            let line = std::format!("ima enroll /var/custom-service-plugin-{i:02}");
            let r = run(&mut sh, &line);
            note(r, &mut sh, &mut image, &line);
        }
        assert!(refused > 0, "the journal budget was never reached; the test proves nothing");
        assert!(accepted > 10, "accepted={accepted}");
        // Lockdown adds a firewall rule and a watermark record; both are reserved for.
        let r = run(&mut sh, "guard lockdown");
        assert!(r.starts_with("guard: posture=LOCKDOWN"), "{r}");
        sh.pack_state_image(1, &mut image).expect("state after lockdown");

        // And what was packed comes back.
        let mut back = fresh_shell(2);
        let restored = back.unpack_state_image(&image).expect("restore");
        assert_eq!(restored.saved_boots, 1);
        assert_eq!(back.fw.as_slice().len(), sh.fw.as_slice().len());
        assert_eq!(back.auth_seq, 77);
        assert!(back.guard_lockdown);
        assert_eq!(back.state_journal_bytes(), sh.state_journal_bytes());
    }

    #[test]
    fn many_and_large_files_persist_and_restore_byte_for_byte() {
        let mut sh = fresh_shell(1);
        // Eight 200-byte files: two of these alone used to overflow the journal.
        let mut expect = Vec::new();
        for i in 0..8u8 {
            let body: String = (0..200).map(|j| (b'a' + ((i as usize + j) % 26) as u8) as char).collect();
            let reply = run(&mut sh, &std::format!("write /var/f{i} {body}"));
            // `write` stores the text followed by a newline.
            assert!(reply.starts_with("wrote 201 bytes"), "{reply}");
            expect.push((std::format!("/var/f{i}"), std::format!("{body}
").into_bytes()));
        }
        // One file larger than a journal record can carry, written in pieces.
        let big: Vec<u8> = (0..1400u32).map(|i| (i % 251) as u8).collect();
        let h = sh
            .fs
            .open(b"/var/big", cuttle_contracts::FS_O_RDWR | cuttle_contracts::FS_O_CREATE)
            .expect("create big");
        for (n, chunk) in big.chunks(250).enumerate() {
            assert_eq!(sh.fs.write(h, (n * 250) as u64, chunk), Ok(chunk.len()));
        }
        sh.fs.close(h).expect("close");
        expect.push(("/var/big".into(), big));

        let mut image = Box::new(StateImage::zeroed());
        sh.pack_state_image(1, &mut image).expect("pack");
        let mut back = fresh_shell(2);
        let restored = back.unpack_state_image(&image).expect("restore");
        assert_eq!(restored.files, expect.len());
        for (path, body) in &expect {
            let h = back
                .fs
                .open(path.as_bytes(), cuttle_contracts::FS_O_RDONLY)
                .unwrap_or_else(|e| panic!("{path} missing after restore: {e:?}"));
            let mut got = std::vec![0u8; body.len() + 16];
            let n = back.fs.read(h, 0, &mut got).expect("read");
            back.fs.close(h).expect("close");
            assert_eq!(&got[..n], &body[..], "{path} differs after restore");
        }
        // Restored again from its own image: stable.
        let mut image2 = Box::new(StateImage::zeroed());
        back.pack_state_image(1, &mut image2).expect("repack");
        assert!(image.fs == image2.fs, "filesystem partition changed across a restore");
    }

    #[test]
    fn an_image_missing_a_partition_is_refused() {
        let mut sh = fresh_shell(1);
        apply_generation(&mut sh, "one");
        let mut image = Box::new(StateImage::zeroed());
        sh.pack_state_image(1, &mut image).expect("pack");

        let mut no_fs = Box::new(StateImage::zeroed());
        no_fs.wal = image.wal;
        no_fs.sql = image.sql;
        assert_eq!(
            fresh_shell(2).unpack_state_image(&no_fs),
            Err(crate::shell::StateRestoreError::Filesystem)
        );

        let mut no_sql = Box::new(StateImage::zeroed());
        no_sql.wal = image.wal;
        no_sql.fs = image.fs;
        assert_eq!(
            fresh_shell(2).unpack_state_image(&no_sql),
            Err(crate::shell::StateRestoreError::Sql)
        );

        // Partitions from two different generations must not be combined.
        let mut later = Box::new(StateImage::zeroed());
        sh.pack_state_image(2, &mut later).expect("pack gen 2");
        let mut mixed = Box::new(StateImage::zeroed());
        mixed.wal = later.wal;
        mixed.fs = image.fs;
        mixed.sql = later.sql;
        assert_eq!(
            fresh_shell(3).unpack_state_image(&mixed),
            Err(crate::shell::StateRestoreError::GenerationMismatch)
        );
    }

    #[test]
    fn ordinary_full_tables_fit_in_v2_journal_without_enospc() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);
        sh.auth_seq = 12345;
        sh.http_login_seq = 99;

        // Fill all 12 worker tasks (`PID 5..=16`), 7 user firewall rules (+1 reserved for lockdown),
        // 8 IMA digests, 8 cron jobs, and a vault secret: all must succeed with zero `ENOSPC`.
        for i in 0..12u32 {
            let r = run(&mut sh, "spawn");
            assert!(r.starts_with("spawned pid="), "worker {i}: {r}");
        }
        for i in 0..7u32 {
            let r = run(&mut sh, &std::format!("fw block 172.16.{i}.0/24"));
            assert!(r.starts_with("fw: blocked"), "fw {i}: {r}");
        }
        for i in 0..8u32 {
            let w = run(&mut sh, &std::format!("write /var/tool{i} binary-image-{i}"));
            assert!(w.starts_with("wrote "), "write {i}: {w}");
            let e = run(&mut sh, &std::format!("ima enroll /var/tool{i}"));
            assert!(e.starts_with("ima enrolled "), "ima {i}: {e}");
        }
        for i in 0..8u32 {
            let c = run(&mut sh, &std::format!("cron add {} status", 10 + i));
            assert!(c.starts_with("cron: scheduled"), "cron {i}: {c}");
        }
        let v = run(&mut sh, "vault put cluster.token SecretTok99!");
        assert!(v.starts_with("vault: sealed "), "{v}");
        let g = run(&mut sh, "guard lockdown");
        assert!(g.starts_with("guard: posture=LOCKDOWN"), "{g}");

        let mut st = store();
        assert!(matches!(
            st.commit(&mut disk, &mut sh, 1).expect("commit full ordinary tables"),
            Committed::Written { .. }
        ));
        disk.reboot();

        let (report, mut sh2, _) = boot(&mut disk, &keys(), 2);
        assert!(matches!(
            report.outcome,
            BootOutcome::Restored {
                source: RecoverySource::Primary,
                ..
            }
        ));
        assert_eq!(sh2.fw.as_slice().len(), 8);
        assert!(sh2.guard_lockdown);
        assert_eq!(sh2.auth_seq, 12345);
        assert_eq!(sh2.http_login_seq, 99);
        assert_eq!(
            run(&mut sh2, "vault get cluster.token"),
            "error: EACCES (vault sealed by CuttleGuard lockdown)\n"
        );
        assert_eq!(
            run(&mut sh2, "guard unlock"),
            "guard: posture=NORMAL vault=ready lockdown=cleared\n"
        );
        assert_eq!(
            run(&mut sh2, "vault get cluster.token"),
            "vault: key=cluster.token value=SecretTok99! verified=true\n"
        );
    }

    #[test]
    fn v1_disk_migrates_cleanly_to_v2_and_survives_mid_migration_power_cut() {
        let build_v1_disk = |journaled: bool, corrupt_v1_primary: bool| -> MemDisk {
            let mut disk = MemDisk::new(DISK_SECTORS);
            let mut sh = fresh_shell(3);
            apply_generation(&mut sh, "v1-migrated");
            assert!(run(&mut sh, "fw block 192.0.2.0/24").starts_with("fw: blocked"));
            assert!(run(&mut sh, "cron add 15 status").starts_with("cron: scheduled"));
            sh.auth_seq = 42;

            let mut hdr_sec = [0u8; SECTOR_BYTES];
            let mut wal_sec = [0u8; SECTOR_BYTES];
            sh.pack_disk_image(3, &mut hdr_sec, &mut wal_sec)
                .expect("pack v1 wal");
            let mut fs_secs = [[0u8; SECTOR_BYTES]; STATE_FS_SECTORS_V1];
            sh.pack_fs_partition_v1(3, &mut fs_secs)
                .expect("pack v1 fs");
            let mut sql_secs = [[0u8; SECTOR_BYTES]; STATE_SQL_SECTORS_V1];
            sh.db
                .try_save_partition_v1(&sh.seal_key, &mut sql_secs)
                .expect("pack v1 sql");
            let wal_secs = [hdr_sec, wal_sec];

            for base in [AHCI_STATE_LAYOUT_V1.primary_lba, AHCI_STATE_LAYOUT_V1.shadow_lba] {
                disk.write_sector_slices(base, &[&wal_secs, &fs_secs, &sql_secs])
                    .expect("write v1 slot");
            }
            if journaled {
                let hdr = AbCommitHeader::unencrypted(
                    AB_STATE_QUIESCENT,
                    AB_FORMAT_V1,
                    3,
                    5,
                    hash_sector_slice(&wal_secs),
                    hash_sector_slice(&fs_secs),
                    hash_sector_slice(&sql_secs),
                );
                let mut csec = [0u8; SECTOR_BYTES];
                assert!(pack_ab_commit_sector(&sh.seal_key, &hdr, &mut csec));
                // Verify pre-upgrade wire format (`out[9] == 0`).
                assert_eq!(csec[9], 0);
                disk.write_sector(AHCI_STATE_LAYOUT_V1.commit_lba, &csec)
                    .expect("write v1 commit");
            }
            disk.flush().expect("flush v1 disk");
            if corrupt_v1_primary {
                disk.poke(AHCI_STATE_LAYOUT_V1.primary_lba + 1, |s| s[12] ^= 0xFF);
            }
            disk.reboot();
            disk
        };

        // 1. Clean migration of journaled v1 primary, journaled v1 shadow-heal, and unjournaled v1.
        for (journaled, corrupt_primary, expect_seq) in [
            (true, false, 6u64),
            (true, true, 6u64),
            (false, false, 1u64),
        ] {
            let mut disk = build_v1_disk(journaled, corrupt_primary);
            let (report, mut sh, st) = boot(&mut disk, &keys(), 4);
            match report.outcome {
                BootOutcome::Restored {
                    restore,
                    from_quarantine,
                    recommitted,
                    repaired_primary,
                    ..
                } => {
                    assert!(!from_quarantine && recommitted);
                    assert_eq!(repaired_primary, corrupt_primary);
                    assert_eq!(restore.saved_boots, 3);
                }
                other => panic!("v1 migration failed ({journaled}, {corrupt_primary}): {other:?}"),
            }
            assert_eq!(report.boots, 4);
            assert_eq!(st.commit_seq(), expect_seq);
            assert_eq!(sh.commit_seq, expect_seq);
            assert_eq!(generation(&mut sh), "v1-migrated");
            assert_eq!(sh.fw.as_slice().len(), 1);
            assert_eq!(sh.auth_seq, 42);
            let csec = disk.peek(AHCI_STATE_LAYOUT.commit_lba);
            let hdr = verify_ab_commit_sector(&keys().seal, &csec).expect("v3 commit sector");
            assert_eq!(hdr.format_version, AB_FORMAT_V3);
            assert_eq!(hdr.commit_seq, expect_seq);
        }

        // 2. Power cut at EVERY device operation of v1 -> v2 migration (including v1 shadow-heal)
        //    never loses state: the subsequent boot always completes migration cleanly.
        for corrupt_primary in [false, true] {
            let total_ops = {
                let mut probe = build_v1_disk(true, corrupt_primary);
                let _ = boot(&mut probe, &keys(), 4);
                probe.ops
            };
            for policy in [CacheLoss::DropAll, CacheLoss::Random(0x517C_C1B7_2722_0A95)] {
                for cut in 0..=total_ops {
                    let mut disk = build_v1_disk(true, corrupt_primary);
                    disk.cache_loss = policy;
                    disk.power_cut_at = Some(cut);
                    let mut sh_try = Box::new(OsShell::empty());
                    let mut st_try = store();
                    let _ = st_try.boot(&mut disk, &mut sh_try, &keys(), 4);

                    disk.reboot();
                    let (report, mut sh_ok, _) = boot(&mut disk, &keys(), 5);
                    assert!(
                        matches!(report.outcome, BootOutcome::Restored { .. }),
                        "corrupt_primary={corrupt_primary} policy={policy:?} cut={cut}: {:?}",
                        report.outcome
                    );
                    assert_eq!(
                        generation(&mut sh_ok),
                        "v1-migrated",
                        "corrupt_primary={corrupt_primary} policy={policy:?} cut={cut}"
                    );
                    assert_eq!(sh_ok.auth_seq, 42);
                }
            }
        }
    }

    #[test]
    fn large_files_up_to_10kib_and_sql_up_to_8kib_persist_in_v2() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);

        // Write an 8,500-byte file (exceeds the old 4 KiB v1 pool more than 2x).
        let big: Vec<u8> = (0..8500u32).map(|i| ((i * 37 + 11) % 251) as u8).collect();
        let h = sh
            .fs
            .open(
                b"/var/archive.bin",
                cuttle_contracts::FS_O_RDWR | cuttle_contracts::FS_O_CREATE,
            )
            .expect("open /var/archive.bin");
        for (idx, chunk) in big.chunks(500).enumerate() {
            assert_eq!(sh.fs.write(h, (idx * 500) as u64, chunk), Ok(chunk.len()));
        }
        sh.fs.close(h).expect("close /var/archive.bin");

        // Populate two SQL tables past the old 4,088-byte v1 SQL partition ceiling (~5.6 KiB).
        assert_eq!(
            sql(&mut sh, "CREATE TABLE extra (k TEXT, v TEXT, rev INT)"),
            "CREATE TABLE extra OK\n"
        );
        for i in 0..58u32 {
            assert_eq!(
                sql(
                    &mut sh,
                    &std::format!("INSERT INTO kv VALUES ('key_{i:03}_alpha', 'val_{i:03}_bravo_charlie', {i})")
                ),
                "INSERT 1\n"
            );
            assert_eq!(
                sql(
                    &mut sh,
                    &std::format!("INSERT INTO extra VALUES ('ext_{i:03}_delta', 'payload_{i:03}_echo_foxtrot', {i})")
                ),
                "INSERT 1\n"
            );
        }
        assert!(
            sh.db.committed_partition_bytes() > STATE_SQL_SECTORS_V1 * SECTOR_BYTES,
            "expected SQL bytes > 4096, got {}",
            sh.db.committed_partition_bytes()
        );

        let mut st = store();
        st.commit(&mut disk, &mut sh, 1).expect("v2 large commit");
        disk.reboot();

        let (report, mut sh2, _) = boot(&mut disk, &keys(), 2);
        assert!(matches!(report.outcome, BootOutcome::Restored { .. }));

        let h2 = sh2
            .fs
            .open(b"/var/archive.bin", cuttle_contracts::FS_O_RDONLY)
            .expect("reopen /var/archive.bin");
        let mut got = std::vec![0u8; big.len() + 16];
        let n = sh2.fs.read(h2, 0, &mut got).expect("read /var/archive.bin");
        sh2.fs.close(h2).expect("close");
        assert_eq!(&got[..n], &big[..]);
        assert_eq!(
            sql(&mut sh2, "SELECT v FROM extra WHERE k = 'ext_057_delta'"),
            "v\npayload_057_echo_foxtrot\n"
        );
    }

    #[test]
    fn v3_encrypted_store_leaves_zero_plaintext_on_disk_and_migrates_v2() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);
        assert!(run(
            &mut sh,
            "write /var/topsecret_customer_ssn.txt SSN-987-65-4321-CONFIDENTIAL"
        )
        .starts_with("wrote "));
        assert_eq!(
            sql(
                &mut sh,
                "INSERT INTO kv VALUES ('customer_pii', 'ACME-PAYROLL-TOKEN-9999', 7)"
            ),
            "INSERT 1\n"
        );
        assert!(run(&mut sh, "cron add 15 echo-secret-cron-token").starts_with("cron: scheduled"));

        let mut st = store();
        st.commit(&mut disk, &mut sh, 1).expect("commit v3");
        disk.reboot();

        // 1. Inspect raw primary & shadow slots (`1040..=1148`): starts with `CTTLAE03`,
        //    and ZERO plaintext partition magics, filenames, file contents, SQL strings,
        //    or cron strings appear anywhere on disk!
        let mut raw_slots = Vec::with_capacity(2 * STATE_IMAGE_SECTORS * SECTOR_BYTES);
        for lba in AHCI_STATE_LAYOUT.primary_lba..AHCI_STATE_LAYOUT.primary_lba + STATE_IMAGE_SECTORS as u64 {
            raw_slots.extend_from_slice(&disk.peek(lba));
        }
        for lba in AHCI_STATE_LAYOUT.shadow_lba..AHCI_STATE_LAYOUT.shadow_lba + STATE_IMAGE_SECTORS as u64 {
            raw_slots.extend_from_slice(&disk.peek(lba));
        }
        assert_eq!(&disk.peek(AHCI_STATE_LAYOUT.primary_lba)[0..8], &STATE_AEAD_MAGIC);
        assert_eq!(&disk.peek(AHCI_STATE_LAYOUT.shadow_lba)[0..8], &STATE_AEAD_MAGIC);
        for needle in [
            &b"CTTLSHL1"[..],
            &b"CTTLFS01"[..],
            &b"CTTLSQL1"[..],
            &b"topsecret_customer_ssn"[..],
            &b"SSN-987-65-4321"[..],
            &b"customer_pii"[..],
            &b"ACME-PAYROLL-TOKEN"[..],
            &b"echo-secret-cron-token"[..],
        ] {
            assert!(
                !raw_slots.windows(needle.len()).any(|w| w == needle),
                "plaintext {:?} leaked onto raw disk sectors!",
                core::str::from_utf8(needle)
            );
        }
        let csec = disk.peek(AHCI_STATE_LAYOUT.commit_lba);
        let chdr = verify_ab_commit_sector(&keys().seal, &csec).expect("v3 commit");
        assert_eq!(chdr.format_version, AB_FORMAT_V3);

        // 2. Clean reboot decrypts and restores every byte.
        let (report, mut sh2, _) = boot(&mut disk, &keys(), 2);
        assert!(matches!(report.outcome, BootOutcome::Restored { recommitted: false, .. }));
        assert_eq!(
            run(&mut sh2, "cat /var/topsecret_customer_ssn.txt"),
            "SSN-987-65-4321-CONFIDENTIAL\n"
        );
        assert_eq!(
            sql(&mut sh2, "SELECT v FROM kv WHERE k = 'customer_pii'"),
            "v\nACME-PAYROLL-TOKEN-9999\n"
        );

        // 3. Pre-upgrade unencrypted `AB_FORMAT_V2` disk migrates cleanly to encrypted `AB_FORMAT_V3`.
        let mut v2_disk = MemDisk::new(DISK_SECTORS);
        let mut plain_img = Box::new(StateImage::zeroed());
        sh2.pack_state_image(2, &mut plain_img).expect("pack plain v2");
        assert_eq!(&plain_img.wal[0][0..8], b"CTTLSHL1");
        commit(&mut v2_disk, &keys().seal, &AHCI_STATE_LAYOUT, 2, 9, &plain_img)
            .expect("write unencrypted v2 store");
        v2_disk.reboot();
        assert_eq!(
            verify_ab_commit_sector(&keys().seal, &v2_disk.peek(AHCI_STATE_LAYOUT.commit_lba))
                .unwrap()
                .format_version,
            AB_FORMAT_V2
        );

        let (mig_rep, mut sh_mig, st_mig) = boot(&mut v2_disk, &keys(), 3);
        assert!(matches!(mig_rep.outcome, BootOutcome::Restored { recommitted: true, .. }));
        assert_eq!(st_mig.commit_seq(), 10);
        assert_eq!(
            &v2_disk.peek(AHCI_STATE_LAYOUT.primary_lba)[0..8],
            &STATE_AEAD_MAGIC
        );
        assert_eq!(
            verify_ab_commit_sector(&keys().seal, &v2_disk.peek(AHCI_STATE_LAYOUT.commit_lba))
                .unwrap()
                .format_version,
            AB_FORMAT_V3
        );
        assert_eq!(
            run(&mut sh_mig, "cat /var/topsecret_customer_ssn.txt"),
            "SSN-987-65-4321-CONFIDENTIAL\n"
        );
    }

    #[test]
    fn anti_rollback_min_commit_seq_rejects_stale_disk_snapshot() {
        let mut disk = MemDisk::new(DISK_SECTORS);
        let mut sh = fresh_shell(1);
        apply_generation(&mut sh, "gen-1");
        let mut st = store();
        st.commit(&mut disk, &mut sh, 1).expect("commit 1");
        assert_eq!(st.commit_seq(), 1);

        // Snapshot the entire validly-sealed disk at `commit_seq == 1`.
        let mut stale_snapshot: Vec<[u8; SECTOR_BYTES]> =
            (0..DISK_SECTORS).map(|lba| disk.peek(lba as u64)).collect();

        // Advance live disk to `commit_seq == 3`.
        apply_generation(&mut sh, "gen-2");
        st.commit(&mut disk, &mut sh, 1).expect("commit 2");
        apply_generation(&mut sh, "gen-3");
        st.commit(&mut disk, &mut sh, 1).expect("commit 3");
        assert_eq!(st.commit_seq(), 3);
        assert_eq!(sh.commit_seq, 3);

        // Replace every sector on disk with the older validly-sealed `seq == 1` snapshot.
        for (lba, sec) in stale_snapshot.drain(..).enumerate() {
            disk.write_sector(lba as u64, &sec).unwrap();
        }
        disk.flush().unwrap();
        disk.reboot();

        // With `min_commit_seq == 3` anchored from TPM/coordinator, booting the `seq == 1`
        // snapshot fails closed with `BootError::Rollback { found: 1, min_expected: 3 }`
        // and never leaves `gen-1` live in `sh_boot`.
        let mut sh_boot = Box::new(OsShell::empty());
        let mut st_boot = store();
        st_boot.set_min_commit_seq(3);
        assert_eq!(
            st_boot.boot(&mut disk, &mut sh_boot, &keys(), 2),
            Err(BootError::Rollback {
                found: 1,
                min_expected: 3,
            })
        );
        assert!(sh_boot.fs.stat(b"/var/gen").is_err());

        // Wiping the disk to all-zero when `min_commit_seq == 3` is also caught as rollback (`found: 0`).
        let mut wiped = MemDisk::new(DISK_SECTORS);
        let mut st_wiped = store();
        st_wiped.set_min_commit_seq(3);
        assert_eq!(
            st_wiped.boot(&mut wiped, &mut sh_boot, &keys(), 2),
            Err(BootError::Rollback {
                found: 0,
                min_expected: 3,
            })
        );
    }

    #[test]
    fn stage_b4_enterprise_paged_store_scale_incremental_writes_crash_and_tamper_proof() {
        use crate::paged_store::{
            PAGED_STORE_DEFAULT_DISK_SECTORS, PAGE_POOL_BASE_LBA, SUPERBLOCK_A_LBA,
            SUPERBLOCK_B_LBA,
        };
        let cap_sectors = PAGED_STORE_DEFAULT_DISK_SECTORS as usize; // 8,192 sectors = 4 MiB
        let mut disk = MemDisk::new(cap_sectors);
        let (rep0, mut sh, mut st) = boot(&mut disk, &keys(), 1);
        assert_eq!(rep0.outcome, BootOutcome::Fresh);
        assert!(sh.is_paged_mode());
        assert!(sh.db.is_paged_mode());
        assert!(sh.fs.is_paged_mode());

        // 1. Scale SQL to 6 active tables (`services`, `kv` + 4 enterprise tables) and > 1,200 rows,
        //    including an indexed INT table (`events` with `1,080` rows, exceeding legacy 64-row cap by 16x!).
        assert_eq!(
            sql(&mut sh, "CREATE TABLE events (id INT, msg TEXT)"),
            "CREATE TABLE events OK\n"
        );
        assert_eq!(
            sql(&mut sh, "CREATE INDEX idx_events_id ON events (id)"),
            "CREATE INDEX idx_events_id OK\n"
        );
        for t in 1..=3 {
            let ddl = std::format!("CREATE TABLE tenant_{t} (k INT, label TEXT)");
            assert!(sql(&mut sh, &ddl).ends_with("OK\n"));
            for r in 0..40 {
                let ins = std::format!("INSERT INTO tenant_{t} VALUES ({r}, 't{t}-row-{r}')");
                assert_eq!(sql(&mut sh, &ins), "INSERT 1\n");
            }
        }
        // Insert 1,080 rows into `events` in multi-tuple batches of 6.
        for batch in 0..180 {
            let b0 = batch * 6;
            let ins = std::format!(
                "INSERT INTO events VALUES ({}, 'ev-{}'), ({}, 'ev-{}'), ({}, 'ev-{}'), ({}, 'ev-{}'), ({}, 'ev-{}'), ({}, 'ev-{}')",
                b0, b0,
                b0 + 1, b0 + 1,
                b0 + 2, b0 + 2,
                b0 + 3, b0 + 3,
                b0 + 4, b0 + 4,
                b0 + 5, b0 + 5
            );
            assert_eq!(sql(&mut sh, &ins), "INSERT 6\n");
        }
        assert_eq!(sh.db.table_count(), 6);
        assert!(sh.db.total_rows() >= 1_205);

        // 2. Scale VFS to 69 live user files (> 140 KiB total, exceeding legacy 24-inode / 10 KiB pool caps),
        //    including a 20 KiB multi-chunk file AND an `unlink` hole at `/var/u_05.txt`.
        let mut blob20k = Vec::with_capacity(20_480);
        for i in 0..20_480usize {
            blob20k.push(((i.wrapping_mul(37).wrapping_add(11)) & 0xFF) as u8);
        }
        sh.fs
            .seed_file(b"/var/blob20k.bin", &blob20k, blob20k.len(), 100)
            .expect("seed 20 KiB multi-chunk file");

        let chunk_2k = std::vec![b'M'; 1800];
        for f in 0..69usize {
            let p = std::format!("/var/u_{f:02}.txt");
            if f < 65 {
                let mut content = chunk_2k.clone();
                content.extend_from_slice(std::format!("-file-{f:02}\n").as_bytes());
                sh.fs
                    .seed_file(p.as_bytes(), &content, content.len(), 200 + f as u64)
                    .expect("seed paged file");
            } else {
                let out_w = run(&mut sh, &std::format!("write {p} init-{f:02}"));
                assert!(out_w.starts_with("wrote "), "write failed: {out_w}");
            }
        }
        // Create an inode-table hole at `u_05` and copy `u_65` -> `u_copy.txt` to reach 70 user files (`blob20k` + 68 `u_*` + `u_copy`).
        assert!(run(&mut sh, "rm /var/u_05.txt").starts_with("removed "));
        assert!(run(&mut sh, "cp /var/u_65.txt /var/u_copy.txt").starts_with("copied "));
        let (uf1, ub1) = sh.user_file_summary();
        assert_eq!(uf1, 70);
        assert!(ub1 > 135_000, "expected >135 KiB VFS user bytes, got {ub1}");

        // 3. Initial full commit `C1`.
        disk.ops = 0;
        let c1 = st.commit(&mut disk, &mut sh, 1).expect("commit C1");
        assert!(matches!(c1, Committed::Written { .. }));
        let ops_c1 = disk.ops;
        let initial_pages = st.paged_store().allocated_page_count();
        assert!(
            initial_pages >= 70,
            "expected >=70 allocated 4KiB pages, got {initial_pages}"
        );
        assert_eq!(st.paged_store().tx_lsn(), 1);
        let df_out = run(&mut sh, "df");
        assert!(
            df_out.starts_with("fs: magic=CTTLPGS1 inodes=74/96 ")
                && df_out.contains("/262144 tx_lsn=1\n"),
            "unexpected paged df output: {df_out:?}"
        );

        // Immediate no-op commit writes ZERO sectors.
        let ops_before_noop = disk.ops;
        assert_eq!(
            st.commit(&mut disk, &mut sh, 1).expect("noop commit"),
            Committed::Unchanged
        );
        assert_eq!(disk.ops, ops_before_noop);

        // 4. Incremental commit `C2`: mutate ONLY 1 SQL row and ONLY 1 VFS file -> `O(dirty pages)`!
        assert_eq!(
            sql(&mut sh, "UPDATE events SET msg = 'patched-777' WHERE id = 777"),
            "UPDATE 1\n"
        );
        assert!(run(&mut sh, "append /var/u_66.txt delta-tail").starts_with("appended "));
        disk.ops = 0;
        let c2 = st.commit(&mut disk, &mut sh, 1).expect("incremental commit C2");
        assert!(matches!(c2, Committed::Written { .. }));
        let ops_c2 = disk.ops;
        let dirty_written = st.paged_store().last_dirty_pages_written();
        assert!(
            dirty_written <= 4,
            "incremental commit must write <= 4 dirty 4KiB pages (SqlLeaf+SqlCatalog+VfsData+VfsDir), wrote {dirty_written}"
        );
        assert!(
            ops_c2 * 3 < ops_c1,
            "incremental commit ops ({ops_c2}) must be < 1/3 of full commit ops ({ops_c1})"
        );
        let snap_sb_a_c2 = disk.peek(SUPERBLOCK_A_LBA);
        let snap_sb_b_c2 = disk.peek(SUPERBLOCK_B_LBA);

        // 5. Reboot on the 4 MiB disk and verify 100% fidelity + slot-hole stability on `C3`.
        disk.reboot();
        let (rep_boot, mut sh2, mut st2) = boot(&mut disk, &keys(), 2);
        assert!(matches!(
            rep_boot.outcome,
            BootOutcome::Restored {
                recommitted: false,
                ..
            }
        ));
        assert_eq!(sh2.db.table_count(), 6);
        assert_eq!(
            sql(&mut sh2, "SELECT COUNT(*) FROM events"),
            "count\n1080\n"
        );
        let hits_before = sh2.db.idx_hits;
        assert_eq!(
            sql(
                &mut sh2,
                "SELECT msg FROM events WHERE id >= 777 AND id <= 777"
            ),
            "msg\npatched-777\n"
        );
        assert!(
            sh2.db.idx_hits > hits_before,
            "B+Tree INT range index must accelerate >= / <= query after paged reboot"
        );
        assert!(sh2.fs.stat(b"/var/u_05.txt").is_err());
        assert_eq!(
            run(&mut sh2, "cat /var/u_66.txt"),
            "init-66\ndelta-tail\n"
        );
        assert_eq!(run(&mut sh2, "cat /var/u_copy.txt"), "init-65\n");
        let h_blob = sh2.fs.open(b"/var/blob20k.bin", cuttle_contracts::FS_O_RDONLY).unwrap();
        let mut read_blob = std::vec![0u8; 20_480];
        assert_eq!(sh2.fs.read(h_blob, 0, &mut read_blob).unwrap(), 20_480);
        sh2.fs.close(h_blob).unwrap();
        assert_eq!(read_blob, blob20k);

        // Prove `seed_file_at_slot` preserved exact slot indices across the `u_05` hole:
        // modifying 1 file after reboot still writes only 2 VFS pages (1 VfsData + 1 VfsDir)!
        assert!(run(&mut sh2, "append /var/u_67.txt post-reboot").starts_with("appended "));
        st2.commit(&mut disk, &mut sh2, 2).expect("commit C3");
        assert_eq!(st2.paged_store().last_dirty_pages_written(), 2);
        let snap_c3: Vec<[u8; SECTOR_BYTES]> =
            (0..cap_sectors).map(|l| disk.peek(l as u64)).collect();
        let clone_from_sectors = |secs: &[[u8; SECTOR_BYTES]]| -> MemDisk {
            let mut d = MemDisk::new(secs.len());
            for (i, s) in secs.iter().enumerate() {
                d.poke(i as u64, |dst| *dst = *s);
            }
            d
        };

        // 6. Power-cut crash-atomicity sweep across incremental commit `C3 -> C4`.
        let mut dry = clone_from_sectors(&snap_c3);
        let (_, mut sh_dry, mut st_dry) = boot(&mut dry, &keys(), 3);
        assert_eq!(
            sql(&mut sh_dry, "UPDATE events SET msg = 'atomic-c4' WHERE id = 42"),
            "UPDATE 1\n"
        );
        assert!(run(&mut sh_dry, "append /var/u_68.txt atomic-c4").starts_with("appended "));
        dry.ops = 0;
        st_dry.commit(&mut dry, &mut sh_dry, 3).expect("dry C4");
        let total_c4_ops = dry.ops;
        assert!(total_c4_ops > 4);

        for cut in (1..=total_c4_ops).step_by(3) {
            let mut crash_disk = clone_from_sectors(&snap_c3);
            let (_, mut sh_c, mut st_c) = boot(&mut crash_disk, &keys(), 3);
            let _ = sql(&mut sh_c, "UPDATE events SET msg = 'atomic-c4' WHERE id = 42");
            let _ = run(&mut sh_c, "append /var/u_68.txt atomic-c4");
            crash_disk.ops = 0;
            crash_disk.cache_loss = CacheLoss::Random(0xC0FFEE00u64 ^ (cut as u64));
            crash_disk.power_cut_at = Some(cut);
            let _ = st_c.commit(&mut crash_disk, &mut sh_c, 3);
            crash_disk.reboot();

            let (rep_rec, mut sh_rec, _) = boot(&mut crash_disk, &keys(), 4);
            assert!(
                matches!(rep_rec.outcome, BootOutcome::Restored { .. }),
                "cut at op {cut}/{total_c4_ops} failed to recover: {:?}",
                rep_rec.outcome
            );
            let ev42 = sql(&mut sh_rec, "SELECT msg FROM events WHERE id = 42");
            let u68 = run(&mut sh_rec, "cat /var/u_68.txt");
            let is_c3 = ev42 == "msg\nev-42\n" && u68 == "init-68\n";
            let is_c4 = ev42 == "msg\natomic-c4\n" && u68 == "init-68\natomic-c4\n";
            assert!(
                is_c3 || is_c4,
                "cut at op {cut}/{total_c4_ops} produced torn transaction state: ev42={ev42:?} u68={u68:?}"
            );
        }

        // 7a. Corrupt 1 byte in a committed home page (`SqlCatalog` or `VfsData` not in `C3`'s 2-page CWAL):
        //     the boot is refused, not restarted from defaults.
        let mut corrupt_disk = clone_from_sectors(&snap_c3);
        let cat_lid = st2
            .paged_store()
            .find_page(crate::paged_store::PageDomain::SqlCatalog, 0)
            .unwrap();
        let cat_phys = st2.paged_store().merkle_proof(cat_lid).unwrap().entry.phys_slot;
        let cat_lba = PAGE_POOL_BASE_LBA + (cat_phys as u64) * 8;
        corrupt_disk.poke(cat_lba + 1, |sec| sec[100] ^= 0x80);
        let all_sectors = |d: &MemDisk| -> Vec<[u8; SECTOR_BYTES]> {
            (0..cap_sectors).map(|l| d.peek(l as u64)).collect()
        };
        // The state is genuine and one of its pages is not: the boot stops, and
        // the disk is left exactly as found. (Starting over here would put a
        // fresh, empty page store on top of every other page.)
        let corrupt_before = all_sectors(&corrupt_disk);
        let mut sh_corrupt = Box::new(OsShell::empty());
        let mut st_corrupt = store();
        assert_eq!(
            st_corrupt.boot(&mut corrupt_disk, &mut sh_corrupt, &keys(), 4),
            Err(BootError::PagedStore(PagedBootFault::AnchorMismatch))
        );
        assert_eq!(sh_corrupt.db.table_count(), fresh_shell(4).db.table_count());
        corrupt_disk.reboot();
        assert!(
            all_sectors(&corrupt_disk) == corrupt_before,
            "a boot refused for a damaged page wrote to the disk"
        );
        // Because nothing was overwritten, undoing the damage brings it all back.
        corrupt_disk.poke(cat_lba + 1, |sec| sec[100] ^= 0x80);
        let (rep_fixed, mut sh_fixed, _) = boot(&mut corrupt_disk, &keys(), 5);
        assert!(matches!(rep_fixed.outcome, BootOutcome::Restored { .. }));
        assert_eq!(
            sql(&mut sh_fixed, "SELECT COUNT(*) FROM events"),
            "count\n1080\n"
        );

        // 7b. Replay older valid `C2` superblocks (`tx_lsn=2`) while `AB_FORMAT_V3` demands `C3` (`tx_lsn=3`):
        //     refused the same way.
        let mut replay_disk = clone_from_sectors(&snap_c3);
        replay_disk.poke(SUPERBLOCK_A_LBA, |sec| *sec = snap_sb_a_c2);
        replay_disk.poke(SUPERBLOCK_B_LBA, |sec| *sec = snap_sb_b_c2);
        let replay_before = all_sectors(&replay_disk);
        let mut sh_replay = Box::new(OsShell::empty());
        let mut st_replay = store();
        assert_eq!(
            st_replay.boot(&mut replay_disk, &mut sh_replay, &keys(), 4),
            Err(BootError::PagedStore(PagedBootFault::AnchorMismatch))
        );
        replay_disk.reboot();
        assert!(all_sectors(&replay_disk) == replay_before);
    }
}
