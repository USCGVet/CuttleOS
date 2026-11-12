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
//! A [`StateImage`] is 26 sectors: the 2-sector shell header + journal, the
//! 16-sector filesystem partition and the 8-sector SQL partition. Each
//! partition carries its own keyed seal. The store keeps two copies plus one
//! commit sector:
//!
//! ```text
//!   primary slot   layout.primary_lba .. +26   the copy boot normally reads
//!   shadow slot    layout.shadow_lba  .. +26   a full second copy
//!   commit sector  layout.commit_lba           HMAC-sealed CTTLAB01 record:
//!                                              state, boots, commit_seq and
//!                                              the SHA-256 of each partition
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
    AB_STATE_IN_FLIGHT, AB_STATE_QUIESCENT,
};
use crate::durable_seal::{constant_time_eq, is_seal_key_set, DURABLE_DIGEST_LEN};
use crate::shell::{OsShell, StatePackError, StateRestore};
use crate::wal::crc32_ieee;
use sha2::{Digest, Sha256};

/// Size of one device sector in bytes.
pub const SECTOR_BYTES: usize = 512;
/// Sectors holding the sealed shell header (`CTTLSHL1`) and its journal.
pub const STATE_WAL_SECTORS: usize = 2;
/// Sectors holding the sealed filesystem partition (`CTTLFS01`).
pub const STATE_FS_SECTORS: usize = crate::shell::SHELL_FS_PART_SECTORS;
/// Sectors holding the sealed SQL partition (`CTTLSQL1`).
pub const STATE_SQL_SECTORS: usize = crate::sql::SQL_PART_SECTORS;
/// Total sectors in one [`StateImage`] (and therefore in each slot).
pub const STATE_IMAGE_SECTORS: usize = STATE_WAL_SECTORS + STATE_FS_SECTORS + STATE_SQL_SECTORS;

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

/// The layout Cuttle OS uses on its AHCI state disk: primary `1040..=1065`,
/// shadow `1072..=1097`, commit record at `1098`.
pub const AHCI_STATE_LAYOUT: StoreLayout = StoreLayout {
    primary_lba: 1040,
    shadow_lba: 1072,
    commit_lba: 1098,
};

impl StoreLayout {
    /// `true` iff both slots and the commit sector are pairwise disjoint and
    /// lie inside a device of `capacity_sectors` sectors.
    pub const fn is_valid_for(&self, capacity_sectors: u64) -> bool {
        let n = STATE_IMAGE_SECTORS as u64;
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
/// The struct is 13 KiB. Kernel code keeps it in a `static`; do not pass it
/// by value on a small stack.
pub struct StateImage {
    /// Shell header sector followed by the shell journal sector.
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
    /// bytes `8..16`). Only meaningful once the image has been authenticated.
    pub fn saved_boots(&self) -> u64 {
        let mut b = [0u8; 8];
        b.copy_from_slice(&self.wal[0][8..16]);
        u64::from_le_bytes(b)
    }
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
    let mut i = 0usize;
    while i < STATE_IMAGE_SECTORS {
        dev.write_sector(base + i as u64, image.sector(i))?;
        i += 1;
    }
    dev.flush()
}

/// Read the slot at `base` back from the device and hash each partition
/// without keeping the sectors.
fn slot_digests<D: SectorIo>(dev: &mut D, base: u64) -> Result<ImageDigests, IoFault> {
    let mut buf = [0u8; SECTOR_BYTES];
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
        let mut s = 0usize;
        while s < count {
            dev.read_sector(base + idx as u64, &mut buf)?;
            hasher.update(buf);
            idx += 1;
            s += 1;
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
    let in_flight = AbCommitHeader {
        state: AB_STATE_IN_FLIGHT,
        boots,
        commit_seq,
        wal_sha: digests.wal,
        fs_sha: digests.fs,
        sql_sha: digests.sql,
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
    let mut i = 0usize;
    while i < STATE_IMAGE_SECTORS {
        dev.read_sector(base + i as u64, out.sector_mut(i))?;
        i += 1;
    }
    Ok(())
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

    if primary_read.is_ok() && out.digests().matches(&hdr) {
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
    if !out.digests().matches(&hdr) {
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
/// (`1152..=1205`), clear of the store (`1040..=1098`) and the panic dump
/// (`1536..=1567`).
pub const AHCI_QUARANTINE_LBA: u64 = 1152;

/// Magic of a quarantine marker sector.
const QUARANTINE_MAGIC: [u8; 8] = *b"CTTLQUA1";

/// The layout of the slot and commit copies inside a quarantine area that
/// starts at `base`. The marker sector follows at `base + 53`.
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
    let mut buf = [0u8; SECTOR_BYTES];
    // An unreadable source sector is preserved as zeros: the copy exists to
    // keep whatever can still be read, so one bad sector must not stop it.
    let mut copy = |dev: &mut D, from: u64, to: u64| -> Result<(), IoFault> {
        if dev.read_sector(from, &mut buf).is_err() {
            buf = [0u8; SECTOR_BYTES];
        }
        dev.write_sector(to, &buf)
    };
    let mut i = 0u64;
    while i < STATE_IMAGE_SECTORS as u64 {
        copy(dev, layout.primary_lba + i, dst.primary_lba + i)?;
        copy(dev, layout.shadow_lba + i, dst.shadow_lba + i)?;
        i += 1;
    }
    copy(dev, layout.commit_lba, dst.commit_lba)?;
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
/// and a scratch image.
///
/// 13 KiB. Kernel code keeps it in a `static`.
pub struct ShellStore {
    layout: StoreLayout,
    quarantine_lba: u64,
    commit_seq: u64,
    /// Digests of the image known to be in both slots, if any.
    stored: Option<ImageDigests>,
    image: StateImage,
}

impl ShellStore {
    /// A store over `layout` with its quarantine area at `quarantine_lba`.
    pub const fn new(layout: StoreLayout, quarantine_lba: u64) -> Self {
        Self {
            layout,
            quarantine_lba,
            commit_seq: 0,
            stored: None,
            image: StateImage::zeroed(),
        }
    }

    /// Sequence number of the last commit this store wrote or recovered.
    pub fn commit_seq(&self) -> u64 {
        self.commit_seq
    }

    /// Make the current state of `sh` durable, stamped with generation `boots`.
    ///
    /// Returns [`Committed::Unchanged`] without touching the device when the
    /// packed image equals the stored one. After `Err`, the state is **not**
    /// known to be durable: the caller must not acknowledge the request that
    /// changed it, and must not carry on as if it were saved.
    pub fn commit<D: SectorIo>(
        &mut self,
        dev: &mut D,
        sh: &mut OsShell,
        boots: u64,
    ) -> Result<Committed, PersistError> {
        let records = sh
            .pack_state_image(boots, &mut self.image)
            .map_err(PersistError::Pack)?;
        let digests = self.image.digests();
        if self.stored == Some(digests) {
            return Ok(Committed::Unchanged);
        }
        let seq = self.commit_seq.wrapping_add(1);
        let key = sh.seal_key;
        match commit(dev, &key, &self.layout, boots, seq, &self.image) {
            Ok(hdr) => {
                self.commit_seq = seq;
                self.stored = Some(digests);
                Ok(Committed::Written {
                    commit: hdr,
                    records,
                })
            }
            Err(e) => {
                // The slots are in an unknown intermediate state until the
                // next recovery; forget what we believed was stored.
                self.stored = None;
                Err(PersistError::Commit(e))
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
        match recover(dev, &key, &self.layout, &mut self.image) {
            Ok(r) if r.source != RecoverySource::Empty => sh
                .unpack_state_image(&self.image)
                .map_err(|_| BootError::Io(IoFault::DeviceError)),
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
    ) -> Option<(StateRestore, u64)> {
        let boots = counter_boots.max(self.image.saved_boots().saturating_add(1));
        reset_shell(sh, keys, boots);
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
        if let Some((restore, boots)) = self.try_load(sh, keys, counter_boots) {
            return Ok(Some((recovery, restore, boots)));
        }
        if recovery.source == RecoverySource::Unjournaled {
            // No commit record vouches for either slot, so the per-partition
            // seals decide. The primary failed them; give the shadow its turn.
            read_slot(dev, layout, Slot::Shadow, &mut self.image).map_err(BootError::Io)?;
            if let Some((restore, boots)) = self.try_load(sh, keys, counter_boots) {
                return Ok(Some((recovery, restore, boots)));
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
        self.stored = None;
        if !is_seal_key_set(&keys.seal) {
            return Err(BootError::KeyUnset);
        }
        if !quarantine_fits(&self.layout, self.quarantine_lba, dev.capacity_sectors()) {
            return Err(BootError::BadLayout);
        }
        let layout = self.layout;

        // A blank disk is the one case with nothing to restore or preserve.
        // An unreadable sector is not blank.
        let mut commit_sec = [0u8; SECTOR_BYTES];
        let commit_blank = dev.read_sector(layout.commit_lba, &mut commit_sec).is_ok()
            && commit_sec.iter().all(|&b| b == 0);
        let primary_blank = read_slot(dev, &layout, Slot::Primary, &mut self.image).is_ok()
            && self.image.is_all_zero();
        let shadow_blank = read_slot(dev, &layout, Slot::Shadow, &mut self.image).is_ok()
            && self.image.is_all_zero();
        if primary_blank && shadow_blank && commit_blank {
            reset_shell(sh, keys, counter_boots);
            return Ok(BootReport {
                outcome: BootOutcome::Fresh,
                boots: counter_boots,
            });
        }

        if let Some((recovery, restore, boots)) =
            self.recover_and_load(dev, &layout, sh, keys, counter_boots)?
        {
            self.commit_seq = recovery.commit.map(|h| h.commit_seq).unwrap_or(0);
            let mut recommitted = false;
            if recovery.source == RecoverySource::Unjournaled || restore.migrated_legacy {
                // Re-establish the commit record and both slots in the
                // current format before anything else depends on them.
                self.commit(dev, sh, boots).map_err(BootError::Persist)?;
                recommitted = true;
            } else {
                self.stored = Some(self.image.digests());
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
            if let Some((recovery, restore, boots)) =
                self.recover_and_load(dev, &q_layout, sh, keys, counter_boots)?
            {
                // An earlier boot set this state aside and this boot can
                // verify it: put it back and release the quarantine area.
                self.commit_seq = recovery.commit.map(|h| h.commit_seq).unwrap_or(0);
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
        // Keep a copy before this boot's first commit overwrites the slots.
        // `quarantine` leaves an existing copy alone.
        quarantine(dev, &layout, self.quarantine_lba).map_err(BootError::Io)?;
        reset_shell(sh, keys, counter_boots);
        Ok(BootReport {
            outcome: BootOutcome::Rejected { preserved: true },
            boots: counter_boots,
        })
    }
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
        // Commit sector is the last sector the layout touches.
        assert!(LAYOUT.is_valid_for(1099));
        assert!(!LAYOUT.is_valid_for(1098));
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
        let mut disk = disk_with_one();
        let (_, mut sh, mut st) = boot(&mut disk, &keys(), 2);
        apply_generation(&mut sh, "two");
        disk.io_error_at = Some(disk.ops + 40);
        let err = st.commit(&mut disk, &mut sh, 2).expect_err("device error");
        assert!(matches!(err, PersistError::Commit(CommitError::Io { .. })), "{err:?}");
        // The store no longer claims to know what is on disk, so a retry
        // really writes instead of reporting "unchanged".
        assert!(matches!(
            st.commit(&mut disk, &mut sh, 2).expect("retry"),
            Committed::Written { .. }
        ));
        disk.reboot();
        let (_, mut sh2, _) = boot(&mut disk, &keys(), 3);
        assert_eq!(generation(&mut sh2), "two");
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
        // Quarantine area past the end of the device.
        let mut small = MemDisk::new(1180);
        assert_eq!(store().boot(&mut small, &mut sh, &keys(), 1), Err(BootError::BadLayout));
        // Quarantine area overlapping the shadow slot.
        let mut overlapping = Box::new(ShellStore::new(AHCI_STATE_LAYOUT, 1090));
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
        for i in 0..12u32 {
            let r = run(&mut sh, "spawn");
            note(r, &mut sh, &mut image, "spawn");
            let line = std::format!("fw block 10.{i}.0.0/16");
            let r = run(&mut sh, &line);
            note(r, &mut sh, &mut image, &line);
            let line = std::format!("cron add {} status", 5 + i);
            let r = run(&mut sh, &line);
            note(r, &mut sh, &mut image, &line);
            // A fresh file each round, small enough for the 16-inode table.
            if i < 6 {
                let line = std::format!("write /var/bin{i} payload-{i}");
                let r = run(&mut sh, &line);
                note(r, &mut sh, &mut image, &line);
                let line = std::format!("ima enroll /var/bin{i}");
                let r = run(&mut sh, &line);
                note(r, &mut sh, &mut image, &line);
            }
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
}
