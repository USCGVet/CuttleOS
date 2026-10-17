//! NVMe driver — `target_enterprise` port (TASK-018).
//!
//! Minimal NVMe 1.4 controller driver targeting **host-testable**
//! semantics. Real bare-metal MMIO access lives behind the [`NvmeRegs`]
//! trait; the algorithmic core (queue ring management, command
//! encoding, completion processing, bring-up state machine) is pure
//! data manipulation that the host emulator [`MemNvmeController`] can
//! drive under `cargo test`.
//!
//! # What this port covers (today)
//!
//! - Controller bring-up sequence per NVMe 1.4 §7.6: `CC.EN=0`, wait
//!   `CSTS.RDY=0`, install admin SQ + CQ frames, write `AQA`/`ASQ`/
//!   `ACQ`, set `CC.EN=1`, wait `CSTS.RDY=1`.
//! - Admin commands: **Identify Controller** (CNS=0x01),
//!   **Identify Namespace** (CNS=0x00), **Create I/O Submission Queue**
//!   (opcode 0x01), **Create I/O Completion Queue** (opcode 0x05).
//! - I/O commands: **Read** (opcode 0x02), **Write** (opcode 0x01),
//!   **Flush** (opcode 0x00).
//! - Single submission queue + single completion queue per role
//!   (admin + io). Fixed 64-entry depth.
//! - Synchronous polled completion. No interrupts, no MSI-X.
//!
//! # What this port deliberately does NOT cover
//!
//! - Real PCI bus enumeration. The kernel's PCI walker (future port)
//!   will produce an `NvmeRegs` for a discovered controller and hand
//!   it to `NvmeImpl::new`.
//! - PRP-list assembly. Single-PRP transfers up to 4 KiB only; multi-
//!   page I/O requires `PRP2`-list traversal that isn't here yet.
//! - Namespace management beyond a single NS=1.
//! - Multi-queue / per-CPU IO queues. Real production deploy needs
//!   per-CPU SQs; this is the seed.
//!
//! # Locked surface
//!
//! The byte layout of [`SubmissionQueueEntry`] and
//! [`CompletionQueueEntry`] is locked by the NVMe specification; we
//! match it exactly. The `NvmeError` variants are locked across morph
//! cycles so attestation logs of error patterns stay comparable.

#![allow(clippy::needless_range_loop)]

use proteus_contracts::BlockDevice;

// ---------------------------------------------------------------------------
// NVMe register offsets (BAR0)
// ---------------------------------------------------------------------------

/// `CAP` — Controller Capabilities (64-bit, RO).
pub const REG_CAP: usize = 0x00;
/// `VS` — Version (32-bit, RO).
pub const REG_VS: usize = 0x08;
/// `CC` — Controller Configuration (32-bit, RW).
pub const REG_CC: usize = 0x14;
/// `CSTS` — Controller Status (32-bit, RO).
pub const REG_CSTS: usize = 0x1C;
/// `AQA` — Admin Queue Attributes (32-bit, RW).
pub const REG_AQA: usize = 0x24;
/// `ASQ` — Admin Submission Queue Base Address (64-bit, RW).
pub const REG_ASQ: usize = 0x28;
/// `ACQ` — Admin Completion Queue Base Address (64-bit, RW).
pub const REG_ACQ: usize = 0x30;

/// CC.EN bit (enable controller).
pub const CC_EN: u32 = 1 << 0;
/// CSTS.RDY bit (controller ready).
pub const CSTS_RDY: u32 = 1 << 0;
/// CSTS.CFS bit (controller fatal status).
pub const CSTS_CFS: u32 = 1 << 1;

/// Admin queue depth. 64 entries fit in a 4 KiB page for the SQ (64×64
/// = 4096 bytes) and use the first 1 KiB for the CQ (64×16 = 1024).
pub const ADMIN_QUEUE_ENTRIES: u16 = 64;

/// I/O queue depth. Same 64-entry geometry as admin for the seed.
pub const IO_QUEUE_ENTRIES: u16 = 64;

/// Identify Controller / Identify Namespace data buffer size (4 KiB).
pub const IDENTIFY_BUF_SIZE: usize = 4096;

/// NVMe block size, locked at 512 across morph cycles.
pub const NVME_BLOCK_SIZE: usize = 512;

// ---------------------------------------------------------------------------
// Submission Queue Entry — 64 bytes, NVMe 1.4 §4.2
// ---------------------------------------------------------------------------

/// A 64-byte NVMe submission queue entry. Layout per spec §4.2 Figure 11.
///
/// Most fields are command-specific; we expose the load-bearing ones
/// the driver writes (opcode, NSID, PRP1, command parameters CDW10..15)
/// and zero everything else.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
#[repr(C)]
pub struct SubmissionQueueEntry {
    /// Command Dword 0 (opcode | fuse | psdt | cid).
    pub cdw0: u32,
    /// Namespace identifier (0 = all NSes for admin commands; 1+ for IO).
    pub nsid: u32,
    /// Reserved.
    pub rsvd2: u64,
    /// Metadata pointer (we don't use metadata).
    pub mptr: u64,
    /// PRP entry 1 — physical address of first data buffer.
    pub prp1: u64,
    /// PRP entry 2 — second physical address or PRP list pointer.
    pub prp2: u64,
    /// Command Dword 10.
    pub cdw10: u32,
    /// Command Dword 11.
    pub cdw11: u32,
    /// Command Dword 12.
    pub cdw12: u32,
    /// Command Dword 13.
    pub cdw13: u32,
    /// Command Dword 14.
    pub cdw14: u32,
    /// Command Dword 15.
    pub cdw15: u32,
}

impl SubmissionQueueEntry {
    /// Empty / cleared entry.
    pub const EMPTY: Self = Self {
        cdw0: 0,
        nsid: 0,
        rsvd2: 0,
        mptr: 0,
        prp1: 0,
        prp2: 0,
        cdw10: 0,
        cdw11: 0,
        cdw12: 0,
        cdw13: 0,
        cdw14: 0,
        cdw15: 0,
    };

    /// Build CDW0: low byte = opcode, upper 16 bits = command identifier.
    pub const fn cdw0(opcode: u8, cid: u16) -> u32 {
        (opcode as u32) | ((cid as u32) << 16)
    }

    /// Extract the opcode from CDW0.
    pub const fn opcode(&self) -> u8 {
        (self.cdw0 & 0xFF) as u8
    }

    /// Extract the command identifier from CDW0.
    pub const fn cid(&self) -> u16 {
        (self.cdw0 >> 16) as u16
    }
}

// ---------------------------------------------------------------------------
// Completion Queue Entry — 16 bytes, NVMe 1.4 §4.3
// ---------------------------------------------------------------------------

/// A 16-byte NVMe completion queue entry.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Default)]
#[repr(C)]
pub struct CompletionQueueEntry {
    /// Command-specific (often 0 for the simple commands we issue).
    pub dw0: u32,
    /// Command-specific (often 0).
    pub dw1: u32,
    /// `[31:16]`: SQ identifier; `[15:0]`: SQ head pointer.
    pub sq_head_and_id: u32,
    /// `[31:17]`: Status field (SCT << 8 | SC); `[16]`: Phase tag;
    /// `[15:0]`: Command identifier.
    pub status_and_cid: u32,
}

impl CompletionQueueEntry {
    /// Extract the command identifier.
    pub const fn cid(&self) -> u16 {
        (self.status_and_cid & 0xFFFF) as u16
    }

    /// Extract the phase tag (used to detect new completions in the
    /// ring without consulting a head pointer).
    pub const fn phase(&self) -> bool {
        (self.status_and_cid >> 16) & 1 != 0
    }

    /// Extract the 15-bit status field (SCT<<8 | SC).
    pub const fn status(&self) -> u16 {
        ((self.status_and_cid >> 17) & 0x7FFF) as u16
    }

    /// True iff `status() == 0` (Successful Completion).
    pub const fn is_success(&self) -> bool {
        self.status() == 0
    }
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Errors returned by the driver's `try_*` surfaces. Locked variant
/// set across morph cycles.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum NvmeError {
    /// CSTS never transitioned to the expected RDY value within budget.
    BringUpTimeout,
    /// CSTS.CFS asserted (controller fatal status).
    FatalControllerStatus,
    /// An admin or I/O command completed with non-zero status.
    CommandFailed {
        /// NVMe opcode of the command that failed.
        opcode: u8,
        /// Status field (SCT<<8 | SC) from the CQE.
        status: u16,
    },
    /// LBA is out of range for the active namespace.
    BadLba,
    /// The buffer size doesn't match `NVME_BLOCK_SIZE`.
    BadBufferLen,
    /// A test asked for a feature we don't support yet (multi-block,
    /// metadata, fused ops).
    Unsupported,
}

// ---------------------------------------------------------------------------
// NvmeRegs — host abstraction over the controller's MMIO surface
// ---------------------------------------------------------------------------

/// Abstract MMIO surface. Real hardware implements this with `volatile`
/// reads/writes against the controller's BAR0; the in-memory emulator
/// implements it against a `[u8; ...]` byte buffer.
///
/// The driver is generic over `R: NvmeRegs` so the same code paths
/// run under `cargo test` (against the emulator) and on real hardware
/// (against an MMIO shim).
pub trait NvmeRegs {
    /// Read a 32-bit register at byte offset `off`.
    fn read32(&self, off: usize) -> u32;
    /// Write a 32-bit register at byte offset `off`.
    fn write32(&mut self, off: usize, val: u32);
    /// Read a 64-bit register at byte offset `off`.
    fn read64(&self, off: usize) -> u64;
    /// Write a 64-bit register at byte offset `off`.
    fn write64(&mut self, off: usize, val: u64);
    /// Ring the doorbell at `queue_index` with the new tail value.
    /// Real hardware writes the SQ tail or CQ head to MMIO; the
    /// emulator updates an internal counter.
    fn ring_sq_doorbell(&mut self, queue_index: u16, value: u16);
    /// Ring the CQ head doorbell.
    fn ring_cq_doorbell(&mut self, queue_index: u16, value: u16);
    /// Submit a Submission Queue Entry to the given queue. Real
    /// hardware writes it into the SQ memory at the tail offset; the
    /// emulator dequeues it inline.
    fn submit_entry(&mut self, queue_index: u16, entry: &SubmissionQueueEntry);
    /// Fetch the next CQE from the given completion queue. Returns
    /// `None` if no new completion is available (driver should poll).
    fn fetch_completion(&mut self, queue_index: u16) -> Option<CompletionQueueEntry>;
    /// Read a buffer of bytes back from the host phys address (where
    /// the controller wrote DMA data). For real hardware this is a
    /// no-op (the buffer lives in our linear-mapped frame already);
    /// for the emulator it copies from the emulator's internal
    /// "shadow phys" map.
    fn dma_read(&self, phys: u64, out: &mut [u8]);
    /// Symmetric: write `data` into the emulator's "shadow phys" map.
    /// Real hardware no-op.
    fn dma_write(&mut self, phys: u64, data: &[u8]);
}

// ---------------------------------------------------------------------------
// NvmeImpl — the driver
// ---------------------------------------------------------------------------

/// NVMe driver instance. Generic over the MMIO-shim trait so the same
/// code runs in tests (emulator) and on real hardware (MMIO).
pub struct NvmeImpl<R: NvmeRegs> {
    regs: R,
    next_cid: u16,
    /// Phase tag we expect on the next admin CQ completion. NVMe uses
    /// this to disambiguate new vs stale completions without a head
    /// pointer; we mirror that.
    admin_cq_phase: bool,
    /// Phase tag for the IO CQ.
    io_cq_phase: bool,
    /// SQ tail counters (we increment locally; the emulator follows).
    admin_sq_tail: u16,
    io_sq_tail: u16,
    /// Whether `bring_up()` has completed.
    enabled: bool,
    /// Whether `create_io_queues()` has completed.
    io_queues_ready: bool,
    /// Disk capacity in blocks, populated by `identify_namespace`.
    disk_blocks: u64,
}

impl<R: NvmeRegs> NvmeImpl<R> {
    /// Construct a fresh driver around an MMIO shim. Does NOT touch the
    /// controller; call `bring_up()` next.
    pub fn new(regs: R) -> Self {
        Self {
            regs,
            next_cid: 1,
            admin_cq_phase: true,
            io_cq_phase: true,
            admin_sq_tail: 0,
            io_sq_tail: 0,
            enabled: false,
            io_queues_ready: false,
            disk_blocks: 0,
        }
    }

    /// Acquire / mint a fresh command identifier. CIDs cycle through
    /// 1..u16::MAX; CID=0 is reserved as a sentinel.
    fn next_cid(&mut self) -> u16 {
        let cid = self.next_cid;
        self.next_cid = if self.next_cid == u16::MAX { 1 } else { self.next_cid + 1 };
        cid
    }

    /// True iff `bring_up()` has run to completion.
    pub fn is_enabled(&self) -> bool {
        self.enabled
    }

    /// True iff `create_io_queues()` has run to completion.
    pub fn io_ready(&self) -> bool {
        self.io_queues_ready
    }

    /// Capacity in 512-byte blocks (populated by `identify_namespace`).
    pub fn disk_blocks(&self) -> u64 {
        self.disk_blocks
    }

    /// Run the spec-mandated bring-up: CC.EN=0, wait CSTS.RDY=0, write
    /// AQA/ASQ/ACQ, set CC.EN=1, wait CSTS.RDY=1.
    pub fn bring_up(&mut self, asq_phys: u64, acq_phys: u64) -> Result<(), NvmeError> {
        // 1. Disable the controller. CC.EN := 0.
        let cc = self.regs.read32(REG_CC);
        self.regs.write32(REG_CC, cc & !CC_EN);
        // 2. Wait CSTS.RDY := 0. Budget: 64 polls — the emulator
        //    transitions immediately so this is a single-iteration loop
        //    in tests; real hardware may take ms.
        let mut polls = 64u32;
        while polls > 0 {
            let csts = self.regs.read32(REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return Err(NvmeError::FatalControllerStatus);
            }
            if csts & CSTS_RDY == 0 {
                break;
            }
            polls -= 1;
        }
        if polls == 0 {
            return Err(NvmeError::BringUpTimeout);
        }
        // 3. AQA: SQ tail and CQ tail attributes. Lower 12 bits = CQ
        //    size (entries-1); bits 16..28 = SQ size (entries-1).
        let aqa = ((ADMIN_QUEUE_ENTRIES as u32 - 1) << 16) | (ADMIN_QUEUE_ENTRIES as u32 - 1);
        self.regs.write32(REG_AQA, aqa);
        // 4. ASQ + ACQ base addresses (64-bit).
        self.regs.write64(REG_ASQ, asq_phys);
        self.regs.write64(REG_ACQ, acq_phys);
        // 5. CC: enable, IOSQES=6 (64-byte SQE), IOCQES=4 (16-byte CQE).
        //    `(IOCQES << 20) | (IOSQES << 16) | EN`. Other fields zeroed.
        let cc_new = (4 << 20) | (6 << 16) | CC_EN;
        self.regs.write32(REG_CC, cc_new);
        // 6. Wait CSTS.RDY := 1.
        polls = 64;
        while polls > 0 {
            let csts = self.regs.read32(REG_CSTS);
            if csts & CSTS_CFS != 0 {
                return Err(NvmeError::FatalControllerStatus);
            }
            if csts & CSTS_RDY != 0 {
                self.enabled = true;
                return Ok(());
            }
            polls -= 1;
        }
        Err(NvmeError::BringUpTimeout)
    }

    /// Build the SQE for an admin Identify Controller (CNS=0x01) and
    /// submit it. Returns the CID — caller polls the admin CQ to
    /// collect the completion.
    fn build_identify_controller(&mut self, prp1: u64) -> SubmissionQueueEntry {
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x06, cid); // 0x06 = Identify
        sqe.nsid = 0;
        sqe.prp1 = prp1;
        sqe.cdw10 = 0x01; // CNS=01 -> Identify Controller
        sqe
    }

    fn build_identify_namespace(&mut self, prp1: u64, nsid: u32) -> SubmissionQueueEntry {
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x06, cid);
        sqe.nsid = nsid;
        sqe.prp1 = prp1;
        sqe.cdw10 = 0x00; // CNS=00 -> Identify Namespace
        sqe
    }

    /// Submit the SQE on the admin SQ, advance the tail, poll the CQ
    /// for completion of THIS cid. Returns the CQE on success.
    fn admin_command(&mut self, sqe: &SubmissionQueueEntry) -> Result<CompletionQueueEntry, NvmeError> {
        let cid = sqe.cid();
        self.regs.submit_entry(0, sqe);
        self.admin_sq_tail = (self.admin_sq_tail + 1) % ADMIN_QUEUE_ENTRIES;
        self.regs.ring_sq_doorbell(0, self.admin_sq_tail);
        // Poll. Budget 1024 iterations to keep tests bounded.
        for _ in 0..1024 {
            if let Some(cqe) = self.regs.fetch_completion(0) {
                if cqe.cid() != cid {
                    // Unexpected CID — emulator misbehaviour; treat as
                    // fatal so tests catch it.
                    return Err(NvmeError::CommandFailed { opcode: sqe.opcode(), status: 0xFFFF });
                }
                if !cqe.is_success() {
                    return Err(NvmeError::CommandFailed { opcode: sqe.opcode(), status: cqe.status() });
                }
                self.admin_cq_phase = !self.admin_cq_phase;
                return Ok(cqe);
            }
        }
        Err(NvmeError::BringUpTimeout)
    }

    fn io_command(&mut self, sqe: &SubmissionQueueEntry) -> Result<CompletionQueueEntry, NvmeError> {
        if !self.io_queues_ready {
            return Err(NvmeError::Unsupported);
        }
        let cid = sqe.cid();
        self.regs.submit_entry(1, sqe);
        self.io_sq_tail = (self.io_sq_tail + 1) % IO_QUEUE_ENTRIES;
        self.regs.ring_sq_doorbell(1, self.io_sq_tail);
        for _ in 0..1024 {
            if let Some(cqe) = self.regs.fetch_completion(1) {
                if cqe.cid() != cid {
                    return Err(NvmeError::CommandFailed { opcode: sqe.opcode(), status: 0xFFFF });
                }
                if !cqe.is_success() {
                    return Err(NvmeError::CommandFailed { opcode: sqe.opcode(), status: cqe.status() });
                }
                self.io_cq_phase = !self.io_cq_phase;
                return Ok(cqe);
            }
        }
        Err(NvmeError::BringUpTimeout)
    }

    /// Issue Identify Controller and copy the result into `out` (must
    /// be ≥ 4 KiB). Returns the offset into `out` where SN ends.
    pub fn identify_controller(&mut self, prp1: u64, out: &mut [u8]) -> Result<(), NvmeError> {
        if out.len() < IDENTIFY_BUF_SIZE {
            return Err(NvmeError::BadBufferLen);
        }
        let sqe = self.build_identify_controller(prp1);
        self.admin_command(&sqe)?;
        // Read the controller's Identify response out of the shadow-phys
        // page at `prp1`.
        self.regs.dma_read(prp1, &mut out[..IDENTIFY_BUF_SIZE]);
        Ok(())
    }

    /// Issue Identify Namespace=1, parse the on-block count (NSZE,
    /// bytes 0..8 of the response). Updates `disk_blocks`.
    pub fn identify_namespace(&mut self, prp1: u64) -> Result<u64, NvmeError> {
        let sqe = self.build_identify_namespace(prp1, 1);
        self.admin_command(&sqe)?;
        let mut buf = [0u8; IDENTIFY_BUF_SIZE];
        self.regs.dma_read(prp1, &mut buf);
        let mut nsze_bytes = [0u8; 8];
        nsze_bytes.copy_from_slice(&buf[0..8]);
        let nsze = u64::from_le_bytes(nsze_bytes);
        self.disk_blocks = nsze;
        Ok(nsze)
    }

    /// Create the I/O Completion Queue (qid=1) at `cq_phys`, then the
    /// matching Submission Queue at `sq_phys`. Both 64-deep.
    pub fn create_io_queues(&mut self, sq_phys: u64, cq_phys: u64) -> Result<(), NvmeError> {
        // Create I/O CQ first (the spec requires CQ exist before SQ
        // references it).
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x05, cid); // 0x05 = Create I/O CQ
        sqe.prp1 = cq_phys;
        // CDW10: [31:16]=QSIZE-1, [15:0]=QID
        sqe.cdw10 = ((IO_QUEUE_ENTRIES as u32 - 1) << 16) | 1;
        // CDW11: [0]=PC (physically contiguous), [1]=IEN (intr enable)
        sqe.cdw11 = 0x01;
        self.admin_command(&sqe)?;

        // Create I/O SQ.
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x01, cid); // 0x01 = Create I/O SQ
        sqe.prp1 = sq_phys;
        sqe.cdw10 = ((IO_QUEUE_ENTRIES as u32 - 1) << 16) | 1;
        // CDW11: [31:16]=CQID, [0]=PC
        sqe.cdw11 = (1 << 16) | 0x01;
        self.admin_command(&sqe)?;

        self.io_queues_ready = true;
        Ok(())
    }

    /// Read a single 512-byte block at `lba` into `buf`. Returns
    /// `BadBufferLen` if `buf.len() != 512`. The controller DMAs the
    /// block to `prp1` which must be a valid physical address the
    /// emulator/hardware can reach.
    pub fn try_read_block(
        &mut self,
        lba: u64,
        buf: &mut [u8],
        prp1: u64,
    ) -> Result<(), NvmeError> {
        if buf.len() != NVME_BLOCK_SIZE {
            return Err(NvmeError::BadBufferLen);
        }
        if self.disk_blocks != 0 && lba >= self.disk_blocks {
            return Err(NvmeError::BadLba);
        }
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x02, cid); // Read
        sqe.nsid = 1;
        sqe.prp1 = prp1;
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        sqe.cdw12 = 0; // NLB-1 = 0 → 1 block
        self.io_command(&sqe)?;
        self.regs.dma_read(prp1, buf);
        Ok(())
    }

    /// Write a single 512-byte block at `lba` from `buf`. The driver
    /// stages the data into the host-phys page at `prp1` first, then
    /// issues the Write command.
    pub fn try_write_block(
        &mut self,
        lba: u64,
        buf: &[u8],
        prp1: u64,
    ) -> Result<(), NvmeError> {
        if buf.len() != NVME_BLOCK_SIZE {
            return Err(NvmeError::BadBufferLen);
        }
        if self.disk_blocks != 0 && lba >= self.disk_blocks {
            return Err(NvmeError::BadLba);
        }
        self.regs.dma_write(prp1, buf);
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x01, cid); // Write
        sqe.nsid = 1;
        sqe.prp1 = prp1;
        sqe.cdw10 = (lba & 0xFFFF_FFFF) as u32;
        sqe.cdw11 = ((lba >> 32) & 0xFFFF_FFFF) as u32;
        sqe.cdw12 = 0;
        self.io_command(&sqe)?;
        Ok(())
    }

    /// Issue Flush.
    pub fn try_flush(&mut self) -> Result<(), NvmeError> {
        let cid = self.next_cid();
        let mut sqe = SubmissionQueueEntry::EMPTY;
        sqe.cdw0 = SubmissionQueueEntry::cdw0(0x00, cid); // Flush
        sqe.nsid = 1;
        self.io_command(&sqe)?;
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// In-memory NVMe controller emulator (test fixture)
// ---------------------------------------------------------------------------

/// A `MemNvmeController` is a host-side NVMe emulator: it implements
/// [`NvmeRegs`] over an internal byte-state struct, responds to admin
/// + I/O commands against a backing disk array, and tracks the
/// bring-up state machine. Used by the test suite below AND by the
/// kernel `banner_nvme` exercise (the kernel runs the same emulator
/// in-process to demonstrate the driver pipeline works end-to-end).
pub struct MemNvmeController {
    /// Backing disk in 512-byte blocks.
    pub disk: [u8; MEM_DISK_BYTES],
    /// Block count exposed via Identify Namespace.
    pub block_count: u64,
    /// CC register.
    cc: u32,
    /// CSTS register. Emulator updates this synchronously on CC writes.
    csts: u32,
    /// AQA register.
    aqa: u32,
    /// ASQ / ACQ base phys (we record them for future DMA emulation
    /// but don't actually read SQ entries from there — `submit_entry`
    /// inlines them straight to the SQE queue below).
    asq_phys: u64,
    acq_phys: u64,
    /// In-flight admin SQ entries the driver has submitted but the
    /// emulator hasn't processed yet.
    admin_sq: [SubmissionQueueEntry; 64],
    admin_sq_head: usize,
    admin_sq_tail: usize,
    /// Completions ready for the driver to fetch.
    admin_cq: [CompletionQueueEntry; 64],
    admin_cq_head: usize,
    admin_cq_tail: usize,
    /// IO equivalents.
    io_sq: [SubmissionQueueEntry; 64],
    io_sq_head: usize,
    io_sq_tail: usize,
    io_cq: [CompletionQueueEntry; 64],
    io_cq_head: usize,
    io_cq_tail: usize,
    /// Shadow phys-buffer map. We model exactly one phys address; the
    /// driver should reuse the same PRP1 across commands (the seed
    /// driver never does parallel commands so this works).
    shadow_phys_addr: u64,
    shadow_phys_buf: [u8; IDENTIFY_BUF_SIZE],
    /// Sticky controller-fatal flag. Tests inject errors via this.
    pub force_cfs: bool,
}

/// Emulator backing-disk size in bytes. 32 KiB → 64 blocks. Sized
/// to fit comfortably on a test-thread stack AND on the bare-metal
/// kernel stack (the banner exercise constructs a `MemNvmeController`
/// inline). For larger disks in future tests, allocate the controller
/// on the heap via `Box::new(MemNvmeController::default())` from the
/// `std`-side test harness.
pub const MEM_DISK_BYTES: usize = 32 * 1024;

impl Default for MemNvmeController {
    fn default() -> Self {
        Self::new()
    }
}

impl MemNvmeController {
    /// Construct a fresh emulator. Disk is zero-filled, controller is
    /// powered-off (CC.EN=0, CSTS.RDY=0).
    pub fn new() -> Self {
        Self {
            disk: [0u8; MEM_DISK_BYTES],
            block_count: (MEM_DISK_BYTES / NVME_BLOCK_SIZE) as u64,
            cc: 0,
            csts: 0,
            aqa: 0,
            asq_phys: 0,
            acq_phys: 0,
            admin_sq: [SubmissionQueueEntry::EMPTY; 64],
            admin_sq_head: 0,
            admin_sq_tail: 0,
            admin_cq: [CompletionQueueEntry::default(); 64],
            admin_cq_head: 0,
            admin_cq_tail: 0,
            io_sq: [SubmissionQueueEntry::EMPTY; 64],
            io_sq_head: 0,
            io_sq_tail: 0,
            io_cq: [CompletionQueueEntry::default(); 64],
            io_cq_head: 0,
            io_cq_tail: 0,
            shadow_phys_addr: 0,
            shadow_phys_buf: [0u8; IDENTIFY_BUF_SIZE],
            force_cfs: false,
        }
    }

    fn process_admin_sq(&mut self) {
        while self.admin_sq_head != self.admin_sq_tail {
            let sqe = self.admin_sq[self.admin_sq_head];
            self.admin_sq_head = (self.admin_sq_head + 1) % 64;
            let mut cqe = CompletionQueueEntry::default();
            cqe.status_and_cid = (sqe.cid() as u32) | (1u32 << 16); // phase=1
            match sqe.opcode() {
                0x06 => {
                    // Identify
                    let cns = sqe.cdw10 & 0xFF;
                    let mut buf = [0u8; IDENTIFY_BUF_SIZE];
                    if cns == 0x01 {
                        // Identify Controller: stamp a recognisable SN.
                        let sn = b"PROTEUS-NVME-EMU\0\0\0\0\0";
                        let n = core::cmp::min(sn.len(), 20);
                        buf[4..4 + n].copy_from_slice(&sn[..n]);
                    } else if cns == 0x00 {
                        // Identify Namespace: NSZE in bytes 0..8 = block count.
                        let nsze = self.block_count.to_le_bytes();
                        buf[..8].copy_from_slice(&nsze);
                    }
                    self.shadow_phys_addr = sqe.prp1;
                    self.shadow_phys_buf = buf;
                }
                0x01 | 0x05 => {
                    // Create I/O SQ / CQ — emulator-side no-op; success.
                }
                _ => {
                    // Unsupported admin opcode → set status = 0x01 (Invalid Command Opcode).
                    cqe.status_and_cid |= 0x01 << 17;
                }
            }
            self.admin_cq[self.admin_cq_tail] = cqe;
            self.admin_cq_tail = (self.admin_cq_tail + 1) % 64;
        }
    }

    fn process_io_sq(&mut self) {
        while self.io_sq_head != self.io_sq_tail {
            let sqe = self.io_sq[self.io_sq_head];
            self.io_sq_head = (self.io_sq_head + 1) % 64;
            let mut cqe = CompletionQueueEntry::default();
            cqe.status_and_cid = (sqe.cid() as u32) | (1u32 << 16); // phase=1
            match sqe.opcode() {
                0x02 => {
                    // Read.
                    let lba = (sqe.cdw10 as u64) | ((sqe.cdw11 as u64) << 32);
                    let off = (lba as usize) * NVME_BLOCK_SIZE;
                    if off + NVME_BLOCK_SIZE > self.disk.len() {
                        cqe.status_and_cid |= 0x80 << 17; // LBA out of range
                    } else {
                        let mut buf = [0u8; IDENTIFY_BUF_SIZE];
                        buf[..NVME_BLOCK_SIZE]
                            .copy_from_slice(&self.disk[off..off + NVME_BLOCK_SIZE]);
                        self.shadow_phys_addr = sqe.prp1;
                        self.shadow_phys_buf = buf;
                    }
                }
                0x01 => {
                    // Write.
                    let lba = (sqe.cdw10 as u64) | ((sqe.cdw11 as u64) << 32);
                    let off = (lba as usize) * NVME_BLOCK_SIZE;
                    if off + NVME_BLOCK_SIZE > self.disk.len() {
                        cqe.status_and_cid |= 0x80 << 17;
                    } else if self.shadow_phys_addr == sqe.prp1 {
                        self.disk[off..off + NVME_BLOCK_SIZE]
                            .copy_from_slice(&self.shadow_phys_buf[..NVME_BLOCK_SIZE]);
                    } else {
                        cqe.status_and_cid |= 0x02 << 17; // Invalid Field
                    }
                }
                0x00 => {
                    // Flush — emulator persistent in RAM; no-op success.
                }
                _ => {
                    cqe.status_and_cid |= 0x01 << 17;
                }
            }
            self.io_cq[self.io_cq_tail] = cqe;
            self.io_cq_tail = (self.io_cq_tail + 1) % 64;
        }
    }
}

// Silly placeholder for the trailing `pub_unused: ()`. Keeps the
// MemNvmeController struct's `Self::new` literal clean and lets us
// add private internals later without touching the constructor body.
#[allow(dead_code)]
impl MemNvmeController {
    fn _padding() {}
}

impl NvmeRegs for MemNvmeController {
    fn read32(&self, off: usize) -> u32 {
        if self.force_cfs && off == REG_CSTS {
            return CSTS_CFS;
        }
        match off {
            REG_CC => self.cc,
            REG_CSTS => self.csts,
            REG_AQA => self.aqa,
            REG_VS => 0x0001_0400, // NVMe 1.4
            _ => 0,
        }
    }
    fn write32(&mut self, off: usize, val: u32) {
        match off {
            REG_CC => {
                self.cc = val;
                // Emulator updates CSTS synchronously.
                if val & CC_EN != 0 {
                    self.csts |= CSTS_RDY;
                } else {
                    self.csts &= !CSTS_RDY;
                }
            }
            REG_AQA => self.aqa = val,
            _ => {}
        }
    }
    fn read64(&self, off: usize) -> u64 {
        match off {
            REG_CAP => 0x000F_003F_0001_0000, // MQES=63 (64-entry), DSTRD=0
            REG_ASQ => self.asq_phys,
            REG_ACQ => self.acq_phys,
            _ => 0,
        }
    }
    fn write64(&mut self, off: usize, val: u64) {
        match off {
            REG_ASQ => self.asq_phys = val,
            REG_ACQ => self.acq_phys = val,
            _ => {}
        }
    }
    fn ring_sq_doorbell(&mut self, _qi: u16, _value: u16) {
        // No-op for the emulator: command processing is driven by
        // `submit_entry` directly.
    }
    fn ring_cq_doorbell(&mut self, _qi: u16, _value: u16) {}
    fn submit_entry(&mut self, queue_index: u16, entry: &SubmissionQueueEntry) {
        match queue_index {
            0 => {
                self.admin_sq[self.admin_sq_tail] = *entry;
                self.admin_sq_tail = (self.admin_sq_tail + 1) % 64;
                self.process_admin_sq();
            }
            1 => {
                self.io_sq[self.io_sq_tail] = *entry;
                self.io_sq_tail = (self.io_sq_tail + 1) % 64;
                self.process_io_sq();
            }
            _ => {} // Unknown queue — silently drop. Test would catch.
        }
    }
    fn fetch_completion(&mut self, queue_index: u16) -> Option<CompletionQueueEntry> {
        match queue_index {
            0 => {
                if self.admin_cq_head == self.admin_cq_tail {
                    None
                } else {
                    let cqe = self.admin_cq[self.admin_cq_head];
                    self.admin_cq_head = (self.admin_cq_head + 1) % 64;
                    Some(cqe)
                }
            }
            1 => {
                if self.io_cq_head == self.io_cq_tail {
                    None
                } else {
                    let cqe = self.io_cq[self.io_cq_head];
                    self.io_cq_head = (self.io_cq_head + 1) % 64;
                    Some(cqe)
                }
            }
            _ => None,
        }
    }
    fn dma_read(&self, phys: u64, out: &mut [u8]) {
        if phys == self.shadow_phys_addr {
            let n = core::cmp::min(out.len(), self.shadow_phys_buf.len());
            out[..n].copy_from_slice(&self.shadow_phys_buf[..n]);
        } else {
            // Unknown phys — fill with zeros. Tests catch this.
            for b in out.iter_mut() {
                *b = 0;
            }
        }
    }
    fn dma_write(&mut self, phys: u64, data: &[u8]) {
        self.shadow_phys_addr = phys;
        let n = core::cmp::min(data.len(), self.shadow_phys_buf.len());
        self.shadow_phys_buf[..n].copy_from_slice(&data[..n]);
    }
}

// ---------------------------------------------------------------------------
// BlockDevice trait impl
// ---------------------------------------------------------------------------

/// Type-erased wrapper that pins a `(driver, prp1)` pair into a static
/// for the synchronous `BlockDevice` trait surface. Real production
/// uses a per-CPU `with_nvme` pattern; the seed exposes `set_global`
/// for the kernel banner to install its emulator instance.
///
/// The `BlockDevice` trait is `()` -> () in shape; errors panic. The
/// `NvmeImpl::try_*` methods return Result for the test surface.
pub struct GlobalNvme;

impl BlockDevice for GlobalNvme {
    // BLOCK_SIZE inherited from the trait default (512).

    fn read_block(_lba: u64, _buf: &mut [u8]) {
        // Stateful BlockDevice surface; the seed routes per-call by
        // panicking. Production wiring threads a global mutex / per-CPU
        // pointer; that wiring is a future task.
        panic!("GlobalNvme::read_block requires runtime wiring not present in the seed");
    }
    fn write_block(_lba: u64, _buf: &[u8]) {
        panic!("GlobalNvme::write_block requires runtime wiring not present in the seed");
    }
    fn flush() {
        panic!("GlobalNvme::flush requires runtime wiring not present in the seed");
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a driver against a freshly-constructed emulator, run the
    /// full bring-up, return ready-to-use driver. Helper for the
    /// common test prelude.
    fn ready_driver() -> NvmeImpl<MemNvmeController> {
        let mut drv = NvmeImpl::new(MemNvmeController::new());
        drv.bring_up(0x1000, 0x2000).expect("bring_up");
        drv.create_io_queues(0x3000, 0x4000).expect("create_io_queues");
        drv
    }

    #[test]
    fn bring_up_transitions_to_ready() {
        let mut drv = NvmeImpl::new(MemNvmeController::new());
        assert!(!drv.is_enabled());
        drv.bring_up(0x1000, 0x2000).unwrap();
        assert!(drv.is_enabled());
    }

    #[test]
    fn bring_up_fails_on_forced_cfs() {
        let mut emu = MemNvmeController::new();
        emu.force_cfs = true;
        let mut drv = NvmeImpl::new(emu);
        let err = drv.bring_up(0x1000, 0x2000).unwrap_err();
        assert_eq!(err, NvmeError::FatalControllerStatus);
        assert!(!drv.is_enabled());
    }

    #[test]
    fn identify_controller_round_trip() {
        let mut drv = ready_driver();
        let mut buf = [0u8; IDENTIFY_BUF_SIZE];
        drv.identify_controller(0x5000, &mut buf).unwrap();
        // The emulator stamps "PROTEUS-NVME-EMU" into bytes [4..24].
        let needle = b"PROTEUS-NVME-EMU";
        assert!(
            buf[4..4 + needle.len()] == *needle,
            "expected emulator SN signature, got {:?}",
            &buf[..32]
        );
    }

    #[test]
    fn identify_namespace_returns_block_count() {
        let mut drv = ready_driver();
        let nsze = drv.identify_namespace(0x5000).unwrap();
        // 32 KiB disk / 512-byte blocks = 64 blocks.
        assert_eq!(nsze, 64);
        assert_eq!(drv.disk_blocks(), 64);
    }

    #[test]
    fn single_block_write_then_read_roundtrip() {
        let mut drv = ready_driver();
        let mut write_buf = [0u8; NVME_BLOCK_SIZE];
        for i in 0..NVME_BLOCK_SIZE {
            write_buf[i] = ((i * 7) & 0xFF) as u8;
        }
        drv.try_write_block(42, &write_buf, 0x6000).unwrap();
        let mut read_buf = [0u8; NVME_BLOCK_SIZE];
        drv.try_read_block(42, &mut read_buf, 0x6000).unwrap();
        assert_eq!(write_buf, read_buf, "block did not round-trip");
    }

    #[test]
    fn write_to_different_lbas_does_not_alias() {
        let mut drv = ready_driver();
        let a = [0xAAu8; NVME_BLOCK_SIZE];
        let b = [0xBBu8; NVME_BLOCK_SIZE];
        drv.try_write_block(10, &a, 0x6000).unwrap();
        drv.try_write_block(20, &b, 0x6000).unwrap();
        let mut got = [0u8; NVME_BLOCK_SIZE];
        drv.try_read_block(10, &mut got, 0x6000).unwrap();
        assert_eq!(got, a);
        drv.try_read_block(20, &mut got, 0x6000).unwrap();
        assert_eq!(got, b);
    }

    #[test]
    fn read_block_rejects_bad_buffer_len() {
        let mut drv = ready_driver();
        drv.identify_namespace(0x5000).unwrap();
        let mut buf = [0u8; 16]; // wrong size
        let err = drv.try_read_block(0, &mut buf, 0x6000).unwrap_err();
        assert_eq!(err, NvmeError::BadBufferLen);
    }

    #[test]
    fn out_of_range_lba_rejected_after_identify_ns() {
        let mut drv = ready_driver();
        drv.identify_namespace(0x5000).unwrap();
        let mut buf = [0u8; NVME_BLOCK_SIZE];
        // 64-block disk → LBA 999 is way out of range.
        let err = drv.try_read_block(999, &mut buf, 0x6000).unwrap_err();
        assert_eq!(err, NvmeError::BadLba);
    }

    #[test]
    fn flush_succeeds() {
        let mut drv = ready_driver();
        drv.try_flush().unwrap();
    }

    #[test]
    fn write_before_io_queues_returns_unsupported() {
        let mut drv = NvmeImpl::new(MemNvmeController::new());
        drv.bring_up(0x1000, 0x2000).unwrap();
        // Skipping create_io_queues.
        let buf = [0u8; NVME_BLOCK_SIZE];
        let err = drv.try_write_block(0, &buf, 0x6000).unwrap_err();
        assert_eq!(err, NvmeError::Unsupported);
    }

    #[test]
    fn submission_queue_entry_layout_locked() {
        // Lock the SQE size at 64 bytes — that's the NVMe spec.
        // A morph that introduces padding fails this assertion.
        assert_eq!(core::mem::size_of::<SubmissionQueueEntry>(), 64);
    }

    #[test]
    fn completion_queue_entry_layout_locked() {
        assert_eq!(core::mem::size_of::<CompletionQueueEntry>(), 16);
    }

    #[test]
    fn cdw0_packs_opcode_and_cid() {
        let cdw0 = SubmissionQueueEntry::cdw0(0x02, 0xBEEF);
        assert_eq!(cdw0 & 0xFF, 0x02);
        assert_eq!((cdw0 >> 16) as u16, 0xBEEF);
    }

    #[test]
    fn completion_phase_and_status_decode() {
        let mut cqe = CompletionQueueEntry::default();
        // CID=0x42, phase=1, status=0x80.
        cqe.status_and_cid = 0x42 | (1 << 16) | (0x80 << 17);
        assert_eq!(cqe.cid(), 0x42);
        assert!(cqe.phase());
        assert_eq!(cqe.status(), 0x80);
        assert!(!cqe.is_success());
    }

    #[test]
    fn multi_block_workflow_simulates_short_log() {
        // Write 8 distinct blocks, read them all back, assert no
        // cross-contamination. Stress-tests the SQ/CQ ring index
        // arithmetic across multiple commands.
        let mut drv = ready_driver();
        let mut blocks = [[0u8; NVME_BLOCK_SIZE]; 8];
        for i in 0..8 {
            for j in 0..NVME_BLOCK_SIZE {
                blocks[i][j] = ((i * 31 + j * 17) & 0xFF) as u8;
            }
            drv.try_write_block(i as u64, &blocks[i], 0x6000).unwrap();
        }
        let mut got = [0u8; NVME_BLOCK_SIZE];
        for i in 0..8 {
            drv.try_read_block(i as u64, &mut got, 0x6000).unwrap();
            assert_eq!(got, blocks[i], "block {} mismatch", i);
        }
    }
}
