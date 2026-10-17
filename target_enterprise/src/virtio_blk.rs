//! VirtIO-blk driver — `target_enterprise` port (TASK-061).
//!
//! Minimal VirtIO 1.0 block-device driver. Drives the spec-mandated
//! bring-up handshake, negotiates a small feature set, sets up the
//! single request virtqueue, exposes [`read_block`](BlockDeviceVirtio::read_block)
//! / [`write_block`](BlockDeviceVirtio::write_block) /
//! [`capacity_sectors`](BlockDeviceVirtio::capacity_sectors) against
//! an abstract [`MmioBus`].
//!
//! # Locked surface
//!
//! - [`proteus_contracts::VirtqDesc`] — 16-byte descriptor entry
//!   (spec §2.6.5). Reused from the TASK-048 VirtIO-net port.
//! - [`proteus_contracts::VirtBlkRequest`] — 16-byte request header
//!   (spec §5.2.6).
//! - [`proteus_contracts::virtio_blk_feature`] — feature bit constants.
//! - [`proteus_contracts::virtio_blk_req_type`] — request-type byte
//!   values.
//! - [`proteus_contracts::virtio_blk_status_byte`] — status-byte
//!   values written by the device.
//! - [`proteus_contracts::virtio_blk_device_cfg`] — device-cfg field
//!   offsets.
//! - [`proteus_contracts::virtio_status`] — `device_status` bit
//!   constants. Reused.
//! - [`proteus_contracts::virtio_common_cfg`] — common-cfg field
//!   offsets. Reused.
//! - [`proteus_contracts::BlockDeviceVirtio`] — the trait surface.
//!
//! # What this port covers
//!
//! - Reset → ACK → DRIVER → FEATURES_OK → DRIVER_OK handshake.
//! - Feature negotiation: `VERSION_1 | FLUSH | BLK_SIZE` offered;
//!   `VERSION_1` required.
//! - Single request virtqueue (queue 0), 64 entries deep.
//! - 3-descriptor chains per request (header + data + status).
//! - Synchronous polled completion. No interrupts.
//! - Read + write of 512-byte sectors.
//! - Capacity read from device-cfg.
//!
//! # What this port deliberately does NOT cover
//!
//! - PCI bus enumeration (BAR walking + cap discovery).
//! - VIRTIO_BLK_F_MQ — single queue only.
//! - DISCARD / WRITE_ZEROES / GET_ID. Future ports.
//! - FLUSH command (negotiated but not yet exposed on the trait).
//! - IRQ-driven completion. Polled only.
//! - INDIRECT descriptors. 3 explicit descriptors per request.

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    virtio_blk_device_cfg as dcfg, virtio_blk_feature as feat, virtio_blk_req_type as req_type,
    virtio_blk_status_byte as st, virtio_common_cfg as ccfg, virtio_status, virtq_desc_flags,
    BlockDeviceVirtio, MmioBus, VirtBlkError, VirtBlkRequest, VirtqDesc, VIRTIO_BLK_HDR_LEN,
    VIRTIO_BLK_QUEUE_REQUESTQ, VIRTIO_BLK_SECTOR_SIZE, VIRTIO_BLK_STATUS_LEN,
};

// ---------------------------------------------------------------------------
// Geometry constants
// ---------------------------------------------------------------------------

/// Depth of the request virtqueue. Power of two; matches the
/// VirtIO-net seed. The device's advertised max must be ≥ this.
pub const QUEUE_SIZE: u16 = 64;

/// `usize` form of [`QUEUE_SIZE`].
pub const QUEUE_SIZE_USIZE: usize = QUEUE_SIZE as usize;

/// Maximum number of poll iterations the bring-up handshake will
/// spin through while waiting for `device_status` to clear / accept.
/// Mirrors the VirtIO-net seed.
pub const HANDSHAKE_POLL_BUDGET: u32 = 100_000;

/// Maximum number of poll iterations a single read/write request
/// will spin through while waiting for completion. Generous so a
/// slow emulator can't trip the timeout, bounded so a misbehaving
/// device can't hang the kernel forever.
pub const COMPLETION_POLL_BUDGET: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Pseudo-phys address allocation
// ---------------------------------------------------------------------------
//
// Same approach as virtio_net: sentinel phys addresses laid out at
// distinct page-aligned bases inside the bus's shadow memory. The
// values are part of the locked contract — every byte the driver
// writes to common-cfg (which includes these phys addresses) must
// be byte-identical across morph cycles.

/// Base phys-addr for the request virtqueue's descriptor table.
pub const PHYS_REQ_DESC: u64 = 0x0000_1000;
/// Base phys-addr for the request virtqueue's avail ring.
pub const PHYS_REQ_AVAIL: u64 = 0x0000_2000;
/// Base phys-addr for the request virtqueue's used ring.
pub const PHYS_REQ_USED: u64 = 0x0000_3000;
/// Base phys-addr for the persistent request-header scratch (16 B).
pub const PHYS_REQ_HEADER: u64 = 0x0000_4000;
/// Base phys-addr for the persistent data buffer (512 B).
pub const PHYS_REQ_DATA: u64 = 0x0000_5000;
/// Base phys-addr for the persistent status byte (1 B).
pub const PHYS_REQ_STATUS: u64 = 0x0000_6000;

// ---------------------------------------------------------------------------
// Wire encoding helpers
// ---------------------------------------------------------------------------

/// Encode a [`VirtBlkRequest`] into its 16-byte little-endian wire form.
/// The contracts crate's `#[repr(C)]` already matches on every little-
/// endian host, but we emit explicit bytes so the bus's `dma_write`
/// shadow records the exact byte sequence the verifier asserts
/// against.
#[inline]
pub fn encode_req_header(h: &VirtBlkRequest, out: &mut [u8; VIRTIO_BLK_HDR_LEN]) {
    out[0..4].copy_from_slice(&h.req_type.to_le_bytes());
    out[4..8].copy_from_slice(&h.reserved.to_le_bytes());
    out[8..16].copy_from_slice(&h.sector.to_le_bytes());
}

/// Decode a 16-byte little-endian request header.
#[inline]
pub fn decode_req_header(bytes: &[u8; VIRTIO_BLK_HDR_LEN]) -> VirtBlkRequest {
    let mut req_type = [0u8; 4];
    req_type.copy_from_slice(&bytes[0..4]);
    let mut reserved = [0u8; 4];
    reserved.copy_from_slice(&bytes[4..8]);
    let mut sector = [0u8; 8];
    sector.copy_from_slice(&bytes[8..16]);
    VirtBlkRequest {
        req_type: u32::from_le_bytes(req_type),
        reserved: u32::from_le_bytes(reserved),
        sector: u64::from_le_bytes(sector),
    }
}

/// Encode a [`VirtqDesc`] into its 16-byte little-endian wire form.
/// Mirrors [`crate::virtio_net::encode_desc`] — kept local so the
/// virtio_blk module can stand alone if a morph cycle ever splits
/// the two drivers apart.
#[inline]
pub fn encode_desc(d: &VirtqDesc, out: &mut [u8; 16]) {
    out[0..8].copy_from_slice(&d.addr.to_le_bytes());
    out[8..12].copy_from_slice(&d.len.to_le_bytes());
    out[12..14].copy_from_slice(&d.flags.to_le_bytes());
    out[14..16].copy_from_slice(&d.next.to_le_bytes());
}

/// Decode a 16-byte little-endian descriptor entry.
#[inline]
pub fn decode_desc(bytes: &[u8; 16]) -> VirtqDesc {
    let mut addr = [0u8; 8];
    addr.copy_from_slice(&bytes[0..8]);
    let mut len = [0u8; 4];
    len.copy_from_slice(&bytes[8..12]);
    let mut flags = [0u8; 2];
    flags.copy_from_slice(&bytes[12..14]);
    let mut next = [0u8; 2];
    next.copy_from_slice(&bytes[14..16]);
    VirtqDesc {
        addr: u64::from_le_bytes(addr),
        len: u32::from_le_bytes(len),
        flags: u16::from_le_bytes(flags),
        next: u16::from_le_bytes(next),
    }
}

// ---------------------------------------------------------------------------
// VirtioBlk driver state
// ---------------------------------------------------------------------------

/// VirtIO-blk driver instance. The bus is passed per call — same
/// shape as the VirtIO-net seed.
pub struct VirtioBlk {
    /// Whether `init` has completed successfully.
    initialised: bool,
    /// Capacity read from device-cfg, in 512-byte sectors. 0 until
    /// `init` succeeds.
    capacity_sectors: u64,
    /// Feature set agreed with the device. 0 until `init` succeeds.
    negotiated_features: u64,
    /// True if `VIRTIO_BLK_F_RO` was advertised by the device. The
    /// seed driver still negotiates VERSION_1 + FLUSH + BLK_SIZE but
    /// remembers the read-only bit so `write_block` can reject.
    read_only: bool,
    /// `blk_size` from device-cfg if `VIRTIO_BLK_F_BLK_SIZE` was
    /// negotiated; 0 otherwise. The driver never serves bytes
    /// through `blk_size`-shaped chunks — it only feeds the value
    /// back through [`Self::preferred_block_size`] so a host-side
    /// partition manager can size its arithmetic correctly.
    preferred_block_size: u32,
    /// Next avail-ring slot the driver will publish into.
    avail_idx: u16,
    /// Number of completions reaped via the used ring.
    used_seen: u16,
    /// Notify-region offset for the request queue (read once at
    /// init).
    notify_off: u16,
}

impl Default for VirtioBlk {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioBlk {
    /// Construct a fresh driver. Does NOT touch any bus; call
    /// [`BlockDeviceVirtio::init`] next.
    pub const fn new() -> Self {
        Self {
            initialised: false,
            capacity_sectors: 0,
            negotiated_features: 0,
            read_only: false,
            preferred_block_size: 0,
            avail_idx: 0,
            used_seen: 0,
            notify_off: 0,
        }
    }

    /// True iff [`BlockDeviceVirtio::init`] has completed successfully.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Feature set agreed with the device on the most recent
    /// successful `init`. 0 if `init` has not been called.
    pub fn negotiated_features(&self) -> u64 {
        self.negotiated_features
    }

    /// True iff the device advertised `VIRTIO_BLK_F_RO`. Independent
    /// of the negotiated feature set — the seed driver reads the
    /// offered bit regardless of whether it accepts the feature
    /// (the read-only property is a device fact, not a driver
    /// choice).
    pub fn read_only(&self) -> bool {
        self.read_only
    }

    /// Preferred logical block size if `VIRTIO_BLK_F_BLK_SIZE` was
    /// negotiated; 0 otherwise. NOT the on-wire sector size — see
    /// [`VIRTIO_BLK_SECTOR_SIZE`].
    pub fn preferred_block_size(&self) -> u32 {
        self.preferred_block_size
    }

    /// Number of requests published since init. Wraps at u16.
    pub fn request_count(&self) -> u16 {
        self.avail_idx
    }

    /// Number of completions consumed since init. Wraps at u16.
    pub fn completion_count(&self) -> u16 {
        self.used_seen
    }

    /// Read the 64-bit device feature set from common-cfg through
    /// two 32-bit windows. Exposed for tests; production uses it
    /// inline during `init`.
    pub fn read_device_features(bus: &mut dyn MmioBus) -> u64 {
        bus.write_common_u32(ccfg::DEVICE_FEATURE_SELECT, 0);
        let lo = bus.read_common_u32(ccfg::DEVICE_FEATURE) as u64;
        bus.write_common_u32(ccfg::DEVICE_FEATURE_SELECT, 1);
        let hi = bus.read_common_u32(ccfg::DEVICE_FEATURE) as u64;
        lo | (hi << 32)
    }

    /// Write the 64-bit accepted feature set back through two
    /// 32-bit windows.
    pub fn write_driver_features(bus: &mut dyn MmioBus, value: u64) {
        bus.write_common_u32(ccfg::DRIVER_FEATURE_SELECT, 0);
        bus.write_common_u32(ccfg::DRIVER_FEATURE, value as u32);
        bus.write_common_u32(ccfg::DRIVER_FEATURE_SELECT, 1);
        bus.write_common_u32(ccfg::DRIVER_FEATURE, (value >> 32) as u32);
    }

    /// Set up the request virtqueue: writes `queue_size`, the three
    /// phys-addr triple, reads `queue_notify_off`, writes 1 to
    /// `queue_enable`. Returns the notify offset.
    pub fn configure_queue(
        bus: &mut dyn MmioBus,
        queue: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<u16, VirtBlkError> {
        bus.write_common_u16(ccfg::QUEUE_SELECT, queue);
        let device_size = bus.read_common_u16(ccfg::QUEUE_SIZE);
        if device_size < QUEUE_SIZE {
            return Err(VirtBlkError::QueueTooSmall);
        }
        bus.write_common_u16(ccfg::QUEUE_SIZE, QUEUE_SIZE);
        bus.write_common_u64(ccfg::QUEUE_DESC, desc_phys);
        bus.write_common_u64(ccfg::QUEUE_DRIVER, avail_phys);
        bus.write_common_u64(ccfg::QUEUE_DEVICE, used_phys);
        let notify_off = bus.read_common_u16(ccfg::QUEUE_NOTIFY_OFF);
        bus.write_common_u16(ccfg::QUEUE_ENABLE, 1);
        Ok(notify_off)
    }

    /// Build the 3-descriptor chain for a READ request at slots 0..3.
    /// Head (header, dev-readable) → data (dev-writable) → status
    /// (dev-writable). Mirrors the donor's chain shape from
    /// `RustOSa/src/virtio_blk.rs` line ~530.
    pub fn read_descriptor_chain() -> (VirtqDesc, VirtqDesc, VirtqDesc) {
        let head = VirtqDesc {
            addr: PHYS_REQ_HEADER,
            len: VIRTIO_BLK_HDR_LEN as u32,
            flags: virtq_desc_flags::NEXT,
            next: 1,
        };
        let data = VirtqDesc {
            addr: PHYS_REQ_DATA,
            len: VIRTIO_BLK_SECTOR_SIZE as u32,
            flags: virtq_desc_flags::NEXT | virtq_desc_flags::WRITE,
            next: 2,
        };
        let status = VirtqDesc {
            addr: PHYS_REQ_STATUS,
            len: VIRTIO_BLK_STATUS_LEN as u32,
            flags: virtq_desc_flags::WRITE,
            next: 0,
        };
        (head, data, status)
    }

    /// Build the 3-descriptor chain for a WRITE request at slots 0..3.
    /// Head (header, dev-readable) → data (dev-readable — driver
    /// sources the bytes) → status (dev-writable).
    pub fn write_descriptor_chain() -> (VirtqDesc, VirtqDesc, VirtqDesc) {
        let head = VirtqDesc {
            addr: PHYS_REQ_HEADER,
            len: VIRTIO_BLK_HDR_LEN as u32,
            flags: virtq_desc_flags::NEXT,
            next: 1,
        };
        let data = VirtqDesc {
            addr: PHYS_REQ_DATA,
            len: VIRTIO_BLK_SECTOR_SIZE as u32,
            // No WRITE flag — data is driver→device on a WRITE.
            flags: virtq_desc_flags::NEXT,
            next: 2,
        };
        let status = VirtqDesc {
            addr: PHYS_REQ_STATUS,
            len: VIRTIO_BLK_STATUS_LEN as u32,
            flags: virtq_desc_flags::WRITE,
            next: 0,
        };
        (head, data, status)
    }

    /// Read the current `used.idx` from the device-written used ring.
    fn read_used_idx(bus: &dyn MmioBus, used_base: u64) -> u16 {
        let mut buf = [0u8; 2];
        bus.dma_read(used_base + 2, &mut buf);
        u16::from_le_bytes(buf)
    }

    /// Read the used-ring entry at `slot`; returns `(head_idx,
    /// total_written)`. Mirrors [`crate::virtio_net`]'s helper.
    fn read_used_ring_entry(bus: &dyn MmioBus, used_base: u64, slot: u16) -> (u16, u32) {
        let entry_off = used_base + 4 + (slot as u64) * 8;
        let mut id_bytes = [0u8; 4];
        bus.dma_read(entry_off, &mut id_bytes);
        let mut len_bytes = [0u8; 4];
        bus.dma_read(entry_off + 4, &mut len_bytes);
        (
            u32::from_le_bytes(id_bytes) as u16,
            u32::from_le_bytes(len_bytes),
        )
    }

    /// Read the 64-bit `capacity` field from device-cfg by stitching
    /// 8 individual `read_device_u8` calls (LSB first). The MmioBus
    /// trait does not expose a `read_device_u64` method, but byte
    /// reads of consecutive offsets are sufficient because the
    /// device-cfg region is byte-addressable.
    pub fn read_device_capacity(bus: &dyn MmioBus) -> u64 {
        let mut value: u64 = 0;
        let mut i = 0usize;
        while i < 8 {
            let b = bus.read_device_u8(dcfg::CAPACITY + i) as u64;
            value |= b << (i * 8);
            i += 1;
        }
        value
    }

    /// Read the 32-bit `blk_size` field from device-cfg (only valid
    /// when `VIRTIO_BLK_F_BLK_SIZE` is negotiated).
    pub fn read_device_blk_size(bus: &dyn MmioBus) -> u32 {
        let mut value: u32 = 0;
        let mut i = 0usize;
        while i < 4 {
            let b = bus.read_device_u8(dcfg::BLK_SIZE + i) as u32;
            value |= b << (i * 8);
            i += 1;
        }
        value
    }

    /// Common request path: publishes a 3-descriptor chain, notifies
    /// the queue, polls for completion, validates the device's
    /// response. Shared between [`read_block`](Self::read_block) and
    /// [`write_block`](Self::write_block) so the bring-up sequence
    /// invariants are exercised once.
    fn submit_request(
        &mut self,
        bus: &mut dyn MmioBus,
        chain: (VirtqDesc, VirtqDesc, VirtqDesc),
    ) -> Result<(), VirtBlkError> {
        // 1. Write the 3 descriptors at slots 0/1/2.
        let mut desc_bytes = [0u8; 16];
        encode_desc(&chain.0, &mut desc_bytes);
        bus.dma_write(PHYS_REQ_DESC, &desc_bytes);
        encode_desc(&chain.1, &mut desc_bytes);
        bus.dma_write(PHYS_REQ_DESC + 16, &desc_bytes);
        encode_desc(&chain.2, &mut desc_bytes);
        bus.dma_write(PHYS_REQ_DESC + 32, &desc_bytes);

        // 2. Write avail-ring slot + bump avail.idx.
        let slot = (self.avail_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let head_idx_le = 0u16.to_le_bytes();
        bus.dma_write(PHYS_REQ_AVAIL + 4 + (slot as u64) * 2, &head_idx_le);
        let new_idx = self.avail_idx.wrapping_add(1);
        let new_idx_le = new_idx.to_le_bytes();
        bus.dma_write(PHYS_REQ_AVAIL + 2, &new_idx_le);
        self.avail_idx = new_idx;

        // 3. Notify the queue.
        bus.notify_queue(VIRTIO_BLK_QUEUE_REQUESTQ);

        // 4. Poll for completion. The expected used.idx is
        // `used_seen + 1` (one new completion). Bound the spin.
        let target = self.used_seen.wrapping_add(1);
        let mut polls = COMPLETION_POLL_BUDGET;
        loop {
            let cur = Self::read_used_idx(bus, PHYS_REQ_USED);
            if cur == target {
                break;
            }
            if polls == 0 {
                return Err(VirtBlkError::CompletionTimeout);
            }
            polls -= 1;
        }

        // 5. Validate the used-ring entry's chain-head reference.
        let used_slot = (target.wrapping_sub(1) as usize) & (QUEUE_SIZE_USIZE - 1);
        let (used_head_idx, _used_len) =
            Self::read_used_ring_entry(bus, PHYS_REQ_USED, used_slot as u16);
        if used_head_idx != 0 {
            return Err(VirtBlkError::DescriptorIndexOutOfRange);
        }
        self.used_seen = target;

        // 6. Read the device-written status byte.
        let mut status_buf = [0u8; 1];
        bus.dma_read(PHYS_REQ_STATUS, &mut status_buf);
        match status_buf[0] {
            st::OK => Ok(()),
            st::IOERR => Err(VirtBlkError::DeviceIoError),
            st::UNSUPP => Err(VirtBlkError::RequestUnsupported),
            st::SENTINEL => Err(VirtBlkError::StatusByteUntouched),
            _ => Err(VirtBlkError::DeviceIoError),
        }
    }
}

// ---------------------------------------------------------------------------
// BlockDeviceVirtio impl
// ---------------------------------------------------------------------------

impl BlockDeviceVirtio for VirtioBlk {
    fn init(&mut self, bus: &mut dyn MmioBus) -> Result<(), VirtBlkError> {
        if self.initialised {
            return Err(VirtBlkError::AlreadyInitialised);
        }

        // Step 1: RESET — write 0 to device_status, poll until it
        // reads back 0.
        bus.write_common_u8(ccfg::DEVICE_STATUS, 0);
        let mut polls = HANDSHAKE_POLL_BUDGET;
        loop {
            if bus.read_common_u8(ccfg::DEVICE_STATUS) == 0 {
                break;
            }
            if polls == 0 {
                return Err(VirtBlkError::ResetTimeout);
            }
            polls -= 1;
        }

        // Step 2: ACK.
        bus.write_common_u8(ccfg::DEVICE_STATUS, virtio_status::ACK);
        // Step 3: ACK | DRIVER.
        bus.write_common_u8(
            ccfg::DEVICE_STATUS,
            virtio_status::ACK | virtio_status::DRIVER,
        );

        // Step 4: feature negotiation.
        let offered = Self::read_device_features(bus);
        if offered & feat::VERSION_1 == 0 {
            return Err(VirtBlkError::LegacyDeviceUnsupported);
        }
        // Remember the read-only bit even though it's not in the
        // seed mask — write_block needs to reject preemptively.
        self.read_only = offered & feat::RO != 0;

        // Accept the intersection of what we want + what's offered,
        // plus the required bits.
        let accepted = (offered & feat::SEED_FEATURE_MASK) | feat::SEED_REQUIRED_MASK;
        Self::write_driver_features(bus, accepted);
        self.negotiated_features = accepted;

        // Step 5: write FEATURES_OK, read back to confirm.
        let with_features_ok =
            virtio_status::ACK | virtio_status::DRIVER | virtio_status::FEATURES_OK;
        bus.write_common_u8(ccfg::DEVICE_STATUS, with_features_ok);
        let after = bus.read_common_u8(ccfg::DEVICE_STATUS);
        if after & virtio_status::FAILED != 0 {
            return Err(VirtBlkError::DeviceFailed);
        }
        if after & virtio_status::FEATURES_OK == 0 {
            return Err(VirtBlkError::FeaturesOkRejected);
        }

        // Step 6: read capacity (always present) and blk_size if
        // negotiated.
        self.capacity_sectors = Self::read_device_capacity(bus);
        if accepted & feat::BLK_SIZE != 0 {
            self.preferred_block_size = Self::read_device_blk_size(bus);
        }

        // Step 7: configure the single request queue.
        self.notify_off = Self::configure_queue(
            bus,
            VIRTIO_BLK_QUEUE_REQUESTQ,
            PHYS_REQ_DESC,
            PHYS_REQ_AVAIL,
            PHYS_REQ_USED,
        )?;

        // Step 8: DRIVER_OK.
        bus.write_common_u8(
            ccfg::DEVICE_STATUS,
            with_features_ok | virtio_status::DRIVER_OK,
        );
        let final_status = bus.read_common_u8(ccfg::DEVICE_STATUS);
        if final_status & virtio_status::FAILED != 0 {
            return Err(VirtBlkError::DeviceFailed);
        }

        // Step 9: zero the avail-ring header so the device doesn't
        // read garbage on first notify.
        let flags = [0u8; 2];
        bus.dma_write(PHYS_REQ_AVAIL, &flags);
        let idx = 0u16.to_le_bytes();
        bus.dma_write(PHYS_REQ_AVAIL + 2, &idx);

        self.initialised = true;
        Ok(())
    }

    fn read_block(
        &mut self,
        bus: &mut dyn MmioBus,
        sector: u64,
        out: &mut [u8],
    ) -> Result<(), VirtBlkError> {
        if !self.initialised {
            return Err(VirtBlkError::NotInitialised);
        }
        if out.len() != VIRTIO_BLK_SECTOR_SIZE {
            return Err(VirtBlkError::BufferSizeMismatch);
        }
        if sector >= self.capacity_sectors {
            return Err(VirtBlkError::SectorOutOfRange);
        }

        // 1. Stage the request header.
        let hdr = VirtBlkRequest {
            req_type: req_type::IN,
            reserved: 0,
            sector,
        };
        let mut hdr_bytes = [0u8; VIRTIO_BLK_HDR_LEN];
        encode_req_header(&hdr, &mut hdr_bytes);
        bus.dma_write(PHYS_REQ_HEADER, &hdr_bytes);

        // 2. Stage the sentinel status byte so we can detect a
        // device that ignores the chain.
        bus.dma_write(PHYS_REQ_STATUS, &[st::SENTINEL]);

        // 3. Publish + poll.
        self.submit_request(bus, Self::read_descriptor_chain())?;

        // 4. Copy the device-written data into the caller's buffer.
        bus.dma_read(PHYS_REQ_DATA, out);
        Ok(())
    }

    fn write_block(
        &mut self,
        bus: &mut dyn MmioBus,
        sector: u64,
        data: &[u8],
    ) -> Result<(), VirtBlkError> {
        if !self.initialised {
            return Err(VirtBlkError::NotInitialised);
        }
        if data.len() != VIRTIO_BLK_SECTOR_SIZE {
            return Err(VirtBlkError::BufferSizeMismatch);
        }
        if sector >= self.capacity_sectors {
            return Err(VirtBlkError::SectorOutOfRange);
        }
        if self.read_only {
            return Err(VirtBlkError::DeviceReadOnly);
        }

        // 1. Stage the request header.
        let hdr = VirtBlkRequest {
            req_type: req_type::OUT,
            reserved: 0,
            sector,
        };
        let mut hdr_bytes = [0u8; VIRTIO_BLK_HDR_LEN];
        encode_req_header(&hdr, &mut hdr_bytes);
        bus.dma_write(PHYS_REQ_HEADER, &hdr_bytes);

        // 2. Stage caller's data + sentinel status.
        bus.dma_write(PHYS_REQ_DATA, data);
        bus.dma_write(PHYS_REQ_STATUS, &[st::SENTINEL]);

        // 3. Publish + poll.
        self.submit_request(bus, Self::write_descriptor_chain())
    }

    fn capacity_sectors(&self) -> u64 {
        self.capacity_sectors
    }
}

// ---------------------------------------------------------------------------
// In-memory MMIO bus (test fixture)
// ---------------------------------------------------------------------------

/// Backing-store size for the bus's "phys memory". 64 KiB — fits
/// the queue tables (3 × 4 KiB) + the request scratch slabs at
/// 0x4000/0x5000/0x6000 with slack. Sized to fit on a host test
/// stack AND the kernel's banner stack.
pub const MEM_BUS_BYTES: usize = 64 * 1024;

/// Cap on the number of "submitted-request observations" the bus
/// records. One slot per banner-style assertion.
pub const REQ_OBSERVATION_CAP: usize = 8;

/// One observed request the bus captured on a [`MmioBus::notify_queue`]
/// call. Records the header bytes + (for writes) the payload bytes
/// so the verifier can assert byte-equality.
#[derive(Clone, Copy)]
pub struct ReqObservation {
    /// Captured 16-byte header bytes (little-endian on the wire).
    pub header_bytes: [u8; VIRTIO_BLK_HDR_LEN],
    /// Captured 512-byte payload (only meaningful for OUT
    /// requests; zero-filled for IN).
    pub payload: [u8; VIRTIO_BLK_SECTOR_SIZE],
    /// Length of meaningful payload bytes (0 for IN, 512 for OUT).
    pub payload_len: usize,
    /// Decoded request-type byte (one of [`virtio_blk_req_type`]).
    pub req_type: u32,
    /// Decoded starting sector.
    pub sector: u64,
}

impl Default for ReqObservation {
    fn default() -> Self {
        Self {
            header_bytes: [0u8; VIRTIO_BLK_HDR_LEN],
            payload: [0u8; VIRTIO_BLK_SECTOR_SIZE],
            payload_len: 0,
            req_type: 0,
            sector: 0,
        }
    }
}

/// Status-byte write recorded by [`MemVirtioBlkBus::status_log`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusWrite {
    /// The byte value the driver wrote to `device_status` (common-cfg
    /// offset 0x14).
    pub value: u8,
}

/// Cap on `status_log` length.
pub const STATUS_LOG_CAP: usize = 8;

/// Host-side VirtIO-MMIO emulator with a virtio-blk-shaped backing
/// disk. Tracks the same common-cfg state as the VirtIO-net seed plus
/// a 512-byte-sector-addressable in-memory disk.
pub struct MemVirtioBlkBus {
    shadow: [u8; MEM_BUS_BYTES],
    // Common-cfg registers.
    device_status: u8,
    device_feature_select: u32,
    driver_feature_select: u32,
    device_features: u64,
    driver_features_lo: u32,
    driver_features_hi: u32,
    queue_select: u16,
    queue_size: u16,
    queue_desc: u64,
    queue_driver: u64,
    queue_device: u64,
    queue_enable: u16,
    // Device-cfg.
    capacity_sectors: u64,
    blk_size: u32,
    // Backing disk: fixed 32 sectors (16 KiB) at 512 B each. Sized
    // small so the bus structure fits on test + kernel stacks.
    disk: [u8; Self::DISK_BYTES],
    // Logs / fixtures.
    status_log: [StatusWrite; STATUS_LOG_CAP],
    status_log_len: usize,
    observations: [ReqObservation; REQ_OBSERVATION_CAP],
    observations_len: usize,
    /// Number of doorbell notifications received on the request
    /// queue.
    notify_count: u32,
    /// Force the next request to fail with the given status byte.
    /// 0 means "let it succeed". Test-only knob.
    force_status: u8,
}

impl Default for MemVirtioBlkBus {
    fn default() -> Self {
        Self::new()
    }
}

impl MemVirtioBlkBus {
    /// Number of sectors in the bus's backing disk.
    pub const DISK_SECTORS: u64 = 32;
    /// Total backing-disk size in bytes.
    pub const DISK_BYTES: usize = Self::DISK_SECTORS as usize * VIRTIO_BLK_SECTOR_SIZE;

    /// Construct a fresh emulator with a 32-sector zero-filled disk
    /// and the seed feature set advertised.
    pub const fn new() -> Self {
        Self {
            shadow: [0u8; MEM_BUS_BYTES],
            device_status: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            device_features: feat::VERSION_1 | feat::FLUSH | feat::BLK_SIZE,
            driver_features_lo: 0,
            driver_features_hi: 0,
            queue_select: 0,
            queue_size: QUEUE_SIZE,
            queue_desc: 0,
            queue_driver: 0,
            queue_device: 0,
            queue_enable: 0,
            capacity_sectors: Self::DISK_SECTORS,
            blk_size: VIRTIO_BLK_SECTOR_SIZE as u32,
            disk: [0u8; Self::DISK_BYTES],
            status_log: [StatusWrite { value: 0 }; STATUS_LOG_CAP],
            status_log_len: 0,
            observations: [ReqObservation {
                header_bytes: [0u8; VIRTIO_BLK_HDR_LEN],
                payload: [0u8; VIRTIO_BLK_SECTOR_SIZE],
                payload_len: 0,
                req_type: 0,
                sector: 0,
            }; REQ_OBSERVATION_CAP],
            observations_len: 0,
            notify_count: 0,
            force_status: 0,
        }
    }

    /// Override the device-cfg `capacity` field. Useful for testing
    /// sector-out-of-range rejection paths. Does NOT change the
    /// backing-disk size — calls that target sectors > `DISK_SECTORS`
    /// will be silently clamped to the in-bounds region.
    pub fn set_capacity(&mut self, sectors: u64) {
        self.capacity_sectors = sectors;
    }

    /// Override the device-cfg `blk_size` field.
    pub fn set_blk_size(&mut self, blk_size: u32) {
        self.blk_size = blk_size;
    }

    /// Override the device feature set advertised through
    /// `device_feature` reads.
    pub fn set_device_features(&mut self, features: u64) {
        self.device_features = features;
    }

    /// Make `queue_size` reads return `size` instead of [`QUEUE_SIZE`].
    pub fn set_queue_size(&mut self, size: u16) {
        self.queue_size = size;
    }

    /// Force the next completion's status byte to a specific value.
    /// Test-only knob to drive [`VirtBlkError::DeviceIoError`] /
    /// `RequestUnsupported` / `StatusByteUntouched` paths.
    pub fn force_next_status(&mut self, status: u8) {
        self.force_status = status;
    }

    /// Recorded sequence of `device_status` writes.
    pub fn status_log(&self) -> &[StatusWrite] {
        &self.status_log[..self.status_log_len]
    }

    /// The (lo, hi) pair of `driver_feature` halves the driver wrote.
    /// Combined u64 is `(hi << 32) | lo`.
    pub fn driver_features(&self) -> u64 {
        (self.driver_features_lo as u64) | ((self.driver_features_hi as u64) << 32)
    }

    /// Number of request-queue doorbell writes.
    pub fn notify_count(&self) -> u32 {
        self.notify_count
    }

    /// Captured request observations (one per submitted chain).
    pub fn observations(&self) -> &[ReqObservation] {
        &self.observations[..self.observations_len]
    }

    /// Borrow the backing-disk bytes for sector `sector`.
    pub fn disk_sector(&self, sector: u64) -> &[u8] {
        let off = (sector as usize) * VIRTIO_BLK_SECTOR_SIZE;
        let end = off + VIRTIO_BLK_SECTOR_SIZE;
        if end > Self::DISK_BYTES {
            return &self.disk[0..0];
        }
        &self.disk[off..end]
    }

    /// Plant `data` (must be 512 bytes) at sector `sector` of the
    /// backing disk. Useful for staging a read fixture.
    pub fn plant_sector(&mut self, sector: u64, data: &[u8]) -> bool {
        if data.len() != VIRTIO_BLK_SECTOR_SIZE {
            return false;
        }
        let off = (sector as usize) * VIRTIO_BLK_SECTOR_SIZE;
        let end = off + VIRTIO_BLK_SECTOR_SIZE;
        if end > Self::DISK_BYTES {
            return false;
        }
        self.disk[off..end].copy_from_slice(data);
        true
    }

    /// Process a single submitted request. Walks the descriptor
    /// chain at slots 0/1/2, decodes the header, executes the
    /// request against the backing disk, writes the device-written
    /// data (for reads) and the status byte. Mirrors what a real
    /// VirtIO-blk device does on doorbell.
    fn process_request(&mut self) {
        let driver_avail_idx = self.read_avail_idx(self.queue_driver);
        let device_used_idx = self.read_used_idx_internal(self.queue_device);
        if driver_avail_idx == device_used_idx {
            return;
        }

        // Read the head index from the avail ring slot.
        let avail_slot = (device_used_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let head_off = self.queue_driver + 4 + (avail_slot as u64) * 2;
        let mut head_le = [0u8; 2];
        self.read_shadow(head_off, &mut head_le);
        let head_idx = u16::from_le_bytes(head_le);

        // Decode the three descriptors.
        let mut bytes = [0u8; 16];
        self.read_shadow(self.queue_desc + (head_idx as u64) * 16, &mut bytes);
        let head_desc = decode_desc(&bytes);
        let next1 = head_desc.next;
        self.read_shadow(self.queue_desc + (next1 as u64) * 16, &mut bytes);
        let data_desc = decode_desc(&bytes);
        let next2 = data_desc.next;
        self.read_shadow(self.queue_desc + (next2 as u64) * 16, &mut bytes);
        let status_desc = decode_desc(&bytes);

        // Read the header bytes from shadow at head_desc.addr.
        let mut hdr_bytes = [0u8; VIRTIO_BLK_HDR_LEN];
        self.read_shadow(head_desc.addr, &mut hdr_bytes);
        let header = decode_req_header(&hdr_bytes);

        // Capture the observation BEFORE executing so a forced
        // failure still records the request. Compute the payload
        // first (immutable borrows of self.shadow) then write into
        // the observation slot.
        if self.observations_len < REQ_OBSERVATION_CAP {
            let (payload, payload_len) = if header.req_type == req_type::OUT
                && (data_desc.flags & virtq_desc_flags::WRITE) == 0
            {
                let mut payload = [0u8; VIRTIO_BLK_SECTOR_SIZE];
                let take = core::cmp::min(data_desc.len as usize, VIRTIO_BLK_SECTOR_SIZE);
                self.read_shadow(data_desc.addr, &mut payload[..take]);
                (payload, take)
            } else {
                ([0u8; VIRTIO_BLK_SECTOR_SIZE], 0usize)
            };
            let obs = &mut self.observations[self.observations_len];
            obs.header_bytes = hdr_bytes;
            obs.req_type = header.req_type;
            obs.sector = header.sector;
            obs.payload = payload;
            obs.payload_len = payload_len;
            self.observations_len += 1;
        }

        // Determine the status byte. force_status takes priority.
        let status_byte = if self.force_status != 0 {
            let s = self.force_status;
            self.force_status = 0;
            s
        } else {
            match header.req_type {
                req_type::IN => {
                    // Bounds-check the sector against the disk.
                    let off = (header.sector as usize) * VIRTIO_BLK_SECTOR_SIZE;
                    let end = off + VIRTIO_BLK_SECTOR_SIZE;
                    if end > Self::DISK_BYTES {
                        st::IOERR
                    } else {
                        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
                        buf.copy_from_slice(&self.disk[off..end]);
                        // Honour data descriptor's len cap (clamped at 512).
                        let take = core::cmp::min(data_desc.len as usize, VIRTIO_BLK_SECTOR_SIZE);
                        self.write_shadow(data_desc.addr, &buf[..take]);
                        st::OK
                    }
                }
                req_type::OUT => {
                    let off = (header.sector as usize) * VIRTIO_BLK_SECTOR_SIZE;
                    let end = off + VIRTIO_BLK_SECTOR_SIZE;
                    if end > Self::DISK_BYTES {
                        st::IOERR
                    } else {
                        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
                        let take = core::cmp::min(data_desc.len as usize, VIRTIO_BLK_SECTOR_SIZE);
                        self.read_shadow(data_desc.addr, &mut buf[..take]);
                        self.disk[off..end].copy_from_slice(&buf);
                        st::OK
                    }
                }
                req_type::FLUSH => st::OK,
                _ => st::UNSUPP,
            }
        };

        // Write the status byte to the status descriptor's buffer.
        self.write_shadow(status_desc.addr, &[status_byte]);

        // Publish to the used ring: id (u32) = head_idx, len = total
        // bytes the device wrote (for reads: 512; for writes: 0; the
        // status byte is universal but spec implementations vary —
        // we use sector-size + 1 to match QEMU's behaviour).
        let used_slot = (device_used_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let entry_off = self.queue_device + 4 + (used_slot as u64) * 8;
        let id_le = (head_idx as u32).to_le_bytes();
        self.write_shadow(entry_off, &id_le);
        let total = match header.req_type {
            req_type::IN => (VIRTIO_BLK_SECTOR_SIZE + 1) as u32,
            _ => 1u32,
        };
        let len_le = total.to_le_bytes();
        self.write_shadow(entry_off + 4, &len_le);

        // Bump used.idx.
        let new_used_idx = device_used_idx.wrapping_add(1);
        let new_idx_le = new_used_idx.to_le_bytes();
        self.write_shadow(self.queue_device + 2, &new_idx_le);
    }

    fn read_avail_idx(&self, base: u64) -> u16 {
        let mut out = [0u8; 2];
        self.read_shadow(base + 2, &mut out);
        u16::from_le_bytes(out)
    }

    fn read_used_idx_internal(&self, base: u64) -> u16 {
        let mut out = [0u8; 2];
        self.read_shadow(base + 2, &mut out);
        u16::from_le_bytes(out)
    }

    fn read_shadow(&self, phys: u64, out: &mut [u8]) {
        let start = phys as usize;
        let end = start.saturating_add(out.len());
        if end > MEM_BUS_BYTES {
            for b in out.iter_mut() {
                *b = 0;
            }
            return;
        }
        out.copy_from_slice(&self.shadow[start..end]);
    }

    fn write_shadow(&mut self, phys: u64, data: &[u8]) {
        let start = phys as usize;
        let end = start.saturating_add(data.len());
        if end > MEM_BUS_BYTES {
            return;
        }
        self.shadow[start..end].copy_from_slice(data);
    }
}

impl MmioBus for MemVirtioBlkBus {
    fn read_common_u8(&self, off: usize) -> u8 {
        match off {
            ccfg::DEVICE_STATUS => self.device_status,
            _ => 0,
        }
    }

    fn write_common_u8(&mut self, off: usize, val: u8) {
        if off == ccfg::DEVICE_STATUS {
            self.device_status = val;
            if self.status_log_len < STATUS_LOG_CAP {
                self.status_log[self.status_log_len] = StatusWrite { value: val };
                self.status_log_len += 1;
            }
        }
    }

    fn read_common_u16(&self, off: usize) -> u16 {
        match off {
            ccfg::QUEUE_SIZE => self.queue_size,
            ccfg::QUEUE_NOTIFY_OFF => self.queue_select,
            _ => 0,
        }
    }

    fn write_common_u16(&mut self, off: usize, val: u16) {
        match off {
            ccfg::QUEUE_SELECT => self.queue_select = val,
            ccfg::QUEUE_SIZE => self.queue_size = val,
            ccfg::QUEUE_ENABLE => self.queue_enable = val,
            _ => {}
        }
    }

    fn read_common_u32(&self, off: usize) -> u32 {
        match off {
            ccfg::DEVICE_FEATURE => match self.device_feature_select {
                0 => self.device_features as u32,
                1 => (self.device_features >> 32) as u32,
                _ => 0,
            },
            _ => 0,
        }
    }

    fn write_common_u32(&mut self, off: usize, val: u32) {
        match off {
            ccfg::DEVICE_FEATURE_SELECT => self.device_feature_select = val,
            ccfg::DRIVER_FEATURE_SELECT => self.driver_feature_select = val,
            ccfg::DRIVER_FEATURE => match self.driver_feature_select {
                0 => self.driver_features_lo = val,
                1 => self.driver_features_hi = val,
                _ => {}
            },
            _ => {}
        }
    }

    fn write_common_u64(&mut self, off: usize, val: u64) {
        match off {
            ccfg::QUEUE_DESC => self.queue_desc = val,
            ccfg::QUEUE_DRIVER => self.queue_driver = val,
            ccfg::QUEUE_DEVICE => self.queue_device = val,
            _ => {}
        }
    }

    fn read_device_u8(&self, off: usize) -> u8 {
        // capacity is at 0..8 (u64 LE).
        if off < 8 {
            return (self.capacity_sectors >> (off * 8)) as u8;
        }
        // blk_size is at 0x14..0x18 (u32 LE).
        if (0x14..0x18).contains(&off) {
            let shift = (off - 0x14) * 8;
            return (self.blk_size >> shift) as u8;
        }
        0
    }

    fn read_device_u16(&self, off: usize) -> u16 {
        // Geometry cylinders sit at 0x10..0x12; the seed driver
        // never reads them, but the trait requires us to answer.
        let lo = self.read_device_u8(off) as u16;
        let hi = self.read_device_u8(off + 1) as u16;
        lo | (hi << 8)
    }

    fn notify_queue(&mut self, _queue: u16) {
        self.notify_count += 1;
        // A real device walks the avail ring synchronously after
        // notify; the emulator does the same.
        self.process_request();
    }

    fn dma_write(&mut self, phys: u64, data: &[u8]) {
        self.write_shadow(phys, data);
    }

    fn dma_read(&self, phys: u64, out: &mut [u8]) {
        self.read_shadow(phys, out);
    }
}

// ---------------------------------------------------------------------------
// Unit tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::virtio_blk_feature as f;

    fn fresh() -> (VirtioBlk, MemVirtioBlkBus) {
        (VirtioBlk::new(), MemVirtioBlkBus::new())
    }

    #[test]
    fn new_driver_is_uninitialised() {
        let drv = VirtioBlk::new();
        assert!(!drv.is_initialised());
        assert_eq!(drv.capacity_sectors(), 0);
        assert_eq!(drv.negotiated_features(), 0);
        assert_eq!(drv.request_count(), 0);
        assert_eq!(drv.completion_count(), 0);
        assert_eq!(drv.preferred_block_size(), 0);
        assert!(!drv.read_only());
    }

    #[test]
    fn init_succeeds_against_default_bus() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        assert!(drv.is_initialised());
        assert_eq!(drv.capacity_sectors(), MemVirtioBlkBus::DISK_SECTORS);
        assert_eq!(drv.preferred_block_size(), VIRTIO_BLK_SECTOR_SIZE as u32);
        assert_eq!(
            drv.negotiated_features(),
            f::VERSION_1 | f::FLUSH | f::BLK_SIZE
        );
        assert!(!drv.read_only());
    }

    #[test]
    fn init_status_sequence_is_locked() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let log: alloc::vec::Vec<u8> = bus.status_log().iter().map(|s| s.value).collect();
        // Expected exact sequence per VirtIO 1.0 §3.1.1: RESET (0),
        // ACK (1), ACK|DRIVER (3), ACK|DRIVER|FEATURES_OK (11),
        // ACK|DRIVER|FEATURES_OK|DRIVER_OK (15).
        assert_eq!(log, alloc::vec![0u8, 1, 3, 11, 15]);
    }

    #[test]
    fn init_writes_driver_features_matching_seed_mask() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        assert_eq!(bus.driver_features(), f::VERSION_1 | f::FLUSH | f::BLK_SIZE);
    }

    #[test]
    fn init_is_idempotent() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("first init");
        let err = drv.init(&mut bus).unwrap_err();
        assert_eq!(err, VirtBlkError::AlreadyInitialised);
    }

    #[test]
    fn init_rejects_legacy_device() {
        let (mut drv, mut bus) = fresh();
        bus.set_device_features(0); // no VERSION_1
        let err = drv.init(&mut bus).unwrap_err();
        assert_eq!(err, VirtBlkError::LegacyDeviceUnsupported);
    }

    #[test]
    fn init_rejects_small_queue() {
        let (mut drv, mut bus) = fresh();
        bus.set_queue_size(QUEUE_SIZE - 1);
        let err = drv.init(&mut bus).unwrap_err();
        assert_eq!(err, VirtBlkError::QueueTooSmall);
    }

    #[test]
    fn init_captures_read_only_flag() {
        let (mut drv, mut bus) = fresh();
        bus.set_device_features(f::VERSION_1 | f::RO);
        drv.init(&mut bus).expect("init");
        assert!(drv.read_only());
        // RO is not in SEED_FEATURE_MASK so it's not accepted —
        // negotiated_features should NOT include RO.
        assert_eq!(drv.negotiated_features() & f::RO, 0);
    }

    #[test]
    fn init_records_capacity_from_device_cfg() {
        let (mut drv, mut bus) = fresh();
        bus.set_capacity(1234);
        drv.init(&mut bus).expect("init");
        assert_eq!(drv.capacity_sectors(), 1234);
    }

    #[test]
    fn init_records_blk_size_when_feature_negotiated() {
        let (mut drv, mut bus) = fresh();
        bus.set_blk_size(4096);
        drv.init(&mut bus).expect("init");
        assert_eq!(drv.preferred_block_size(), 4096);
    }

    #[test]
    fn init_does_not_record_blk_size_when_feature_missing() {
        let (mut drv, mut bus) = fresh();
        bus.set_device_features(f::VERSION_1); // no BLK_SIZE
        bus.set_blk_size(8192);
        drv.init(&mut bus).expect("init");
        assert_eq!(drv.preferred_block_size(), 0);
    }

    #[test]
    fn read_block_fails_before_init() {
        let (mut drv, mut bus) = fresh();
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        let err = drv.read_block(&mut bus, 0, &mut buf).unwrap_err();
        assert_eq!(err, VirtBlkError::NotInitialised);
    }

    #[test]
    fn read_block_rejects_wrong_buffer_size() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut short = [0u8; 256];
        assert_eq!(
            drv.read_block(&mut bus, 0, &mut short),
            Err(VirtBlkError::BufferSizeMismatch)
        );
        let mut long = [0u8; 1024];
        assert_eq!(
            drv.read_block(&mut bus, 0, &mut long),
            Err(VirtBlkError::BufferSizeMismatch)
        );
    }

    #[test]
    fn read_block_rejects_out_of_range_sector() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        let err = drv
            .read_block(&mut bus, MemVirtioBlkBus::DISK_SECTORS, &mut buf)
            .unwrap_err();
        assert_eq!(err, VirtBlkError::SectorOutOfRange);
    }

    #[test]
    fn read_block_round_trips_planted_data() {
        let (mut drv, mut bus) = fresh();
        let mut planted = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        for i in 0..VIRTIO_BLK_SECTOR_SIZE {
            planted[i] = (i & 0xFF) as u8;
        }
        bus.plant_sector(7, &planted);
        drv.init(&mut bus).expect("init");
        let mut out = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        drv.read_block(&mut bus, 7, &mut out).expect("read");
        assert_eq!(out, planted);
        assert_eq!(drv.request_count(), 1);
        assert_eq!(drv.completion_count(), 1);
    }

    #[test]
    fn read_block_observed_header_is_byte_exact() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut out = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        drv.read_block(&mut bus, 5, &mut out).expect("read");
        let obs = bus.observations();
        assert_eq!(obs.len(), 1);
        // Expected bytes: req_type=0 (IN), reserved=0, sector=5 LE.
        let expected = [
            0u8, 0, 0, 0, // req_type=IN
            0, 0, 0, 0, // reserved
            5, 0, 0, 0, 0, 0, 0, 0, // sector=5 LE
        ];
        assert_eq!(obs[0].header_bytes, expected);
        assert_eq!(obs[0].req_type, req_type::IN);
        assert_eq!(obs[0].sector, 5);
    }

    #[test]
    fn write_block_persists_to_backing_disk() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut data = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        for i in 0..VIRTIO_BLK_SECTOR_SIZE {
            data[i] = (i as u8).wrapping_mul(3);
        }
        drv.write_block(&mut bus, 9, &data).expect("write");
        let on_disk = bus.disk_sector(9);
        assert_eq!(on_disk, &data[..]);
    }

    #[test]
    fn write_block_observed_payload_is_byte_exact() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut data = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        for i in 0..VIRTIO_BLK_SECTOR_SIZE {
            data[i] = (i & 0x7F) as u8;
        }
        drv.write_block(&mut bus, 2, &data).expect("write");
        let obs = bus.observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].req_type, req_type::OUT);
        assert_eq!(obs[0].sector, 2);
        assert_eq!(obs[0].payload_len, VIRTIO_BLK_SECTOR_SIZE);
        assert_eq!(&obs[0].payload[..], &data[..]);
    }

    #[test]
    fn write_block_rejects_read_only_device() {
        let (mut drv, mut bus) = fresh();
        bus.set_device_features(f::VERSION_1 | f::RO);
        drv.init(&mut bus).expect("init");
        let data = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        let err = drv.write_block(&mut bus, 0, &data).unwrap_err();
        assert_eq!(err, VirtBlkError::DeviceReadOnly);
    }

    #[test]
    fn write_block_rejects_out_of_range_sector() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let data = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        let err = drv
            .write_block(&mut bus, MemVirtioBlkBus::DISK_SECTORS, &data)
            .unwrap_err();
        assert_eq!(err, VirtBlkError::SectorOutOfRange);
    }

    #[test]
    fn write_block_rejects_wrong_buffer_size() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let short = [0u8; 100];
        assert_eq!(
            drv.write_block(&mut bus, 0, &short),
            Err(VirtBlkError::BufferSizeMismatch)
        );
    }

    #[test]
    fn write_then_read_round_trip() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut data = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        for i in 0..VIRTIO_BLK_SECTOR_SIZE {
            data[i] = 0xA5 ^ (i as u8);
        }
        drv.write_block(&mut bus, 4, &data).expect("write");
        let mut readback = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        drv.read_block(&mut bus, 4, &mut readback).expect("read");
        assert_eq!(readback, data);
    }

    #[test]
    fn read_returns_ioerr_when_device_forces_it() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        bus.force_next_status(st::IOERR);
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        let err = drv.read_block(&mut bus, 0, &mut buf).unwrap_err();
        assert_eq!(err, VirtBlkError::DeviceIoError);
    }

    #[test]
    fn read_returns_unsupp_when_device_forces_it() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        bus.force_next_status(st::UNSUPP);
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        let err = drv.read_block(&mut bus, 0, &mut buf).unwrap_err();
        assert_eq!(err, VirtBlkError::RequestUnsupported);
    }

    #[test]
    fn many_sequential_reads_each_count_a_completion() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        for s in 0..16u64 {
            drv.read_block(&mut bus, s, &mut buf).expect("read");
        }
        assert_eq!(drv.request_count(), 16);
        assert_eq!(drv.completion_count(), 16);
    }

    #[test]
    fn descriptor_chain_read_shape_is_locked() {
        let (head, data, status) = VirtioBlk::read_descriptor_chain();
        assert_eq!(head.addr, PHYS_REQ_HEADER);
        assert_eq!(head.len, VIRTIO_BLK_HDR_LEN as u32);
        assert_eq!(head.flags, virtq_desc_flags::NEXT);
        assert_eq!(head.next, 1);
        assert_eq!(data.addr, PHYS_REQ_DATA);
        assert_eq!(data.len, VIRTIO_BLK_SECTOR_SIZE as u32);
        // READ: data descriptor is device-WRITABLE.
        assert_eq!(data.flags, virtq_desc_flags::NEXT | virtq_desc_flags::WRITE);
        assert_eq!(data.next, 2);
        assert_eq!(status.addr, PHYS_REQ_STATUS);
        assert_eq!(status.len, VIRTIO_BLK_STATUS_LEN as u32);
        assert_eq!(status.flags, virtq_desc_flags::WRITE);
        assert_eq!(status.next, 0);
    }

    #[test]
    fn descriptor_chain_write_shape_is_locked() {
        let (head, data, status) = VirtioBlk::write_descriptor_chain();
        assert_eq!(head.addr, PHYS_REQ_HEADER);
        assert_eq!(head.flags, virtq_desc_flags::NEXT);
        // WRITE: data descriptor is device-READABLE (no WRITE flag).
        assert_eq!(data.flags, virtq_desc_flags::NEXT);
        assert_eq!(status.flags, virtq_desc_flags::WRITE);
    }

    #[test]
    fn encode_req_header_layout_is_locked() {
        // VirtIO 1.0 §5.2.6: type (u32 LE) || reserved (u32 LE) ||
        // sector (u64 LE). Spot-check a non-trivial value.
        let req = VirtBlkRequest {
            req_type: req_type::OUT,
            reserved: 0,
            sector: 0x0123_4567_89AB_CDEF,
        };
        let mut bytes = [0u8; VIRTIO_BLK_HDR_LEN];
        encode_req_header(&req, &mut bytes);
        let expected = [
            1u8, 0, 0, 0, // OUT=1
            0, 0, 0, 0, // reserved
            0xEF, 0xCD, 0xAB, 0x89, 0x67, 0x45, 0x23, 0x01,
        ];
        assert_eq!(bytes, expected);
    }

    #[test]
    fn decode_req_header_round_trips_through_encode() {
        let original = VirtBlkRequest {
            req_type: req_type::IN,
            reserved: 0,
            sector: 0xDEAD_BEEF,
        };
        let mut bytes = [0u8; VIRTIO_BLK_HDR_LEN];
        encode_req_header(&original, &mut bytes);
        let decoded = decode_req_header(&bytes);
        assert_eq!(decoded, original);
    }

    #[test]
    fn decode_desc_round_trips_through_encode() {
        let original = VirtqDesc {
            addr: 0xCAFE_BABE_DEAD_BEEF,
            len: 0x1234_5678,
            flags: virtq_desc_flags::NEXT | virtq_desc_flags::WRITE,
            next: 0xABCD,
        };
        let mut bytes = [0u8; 16];
        encode_desc(&original, &mut bytes);
        let decoded = decode_desc(&bytes);
        assert_eq!(decoded, original);
    }

    #[test]
    fn read_device_capacity_helper_round_trips() {
        let (mut _drv, mut bus) = fresh();
        bus.set_capacity(0xCAFE_F00D_DEAD_BEEF);
        assert_eq!(VirtioBlk::read_device_capacity(&bus), 0xCAFE_F00D_DEAD_BEEF);
    }

    #[test]
    fn read_device_blk_size_helper_round_trips() {
        let (mut _drv, mut bus) = fresh();
        bus.set_blk_size(0x1234_5678);
        assert_eq!(VirtioBlk::read_device_blk_size(&bus), 0x1234_5678);
    }

    #[test]
    fn notify_count_advances_per_request() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        // Init does not notify (it only zeros the avail ring).
        let pre = bus.notify_count();
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        drv.read_block(&mut bus, 0, &mut buf).expect("read");
        assert_eq!(bus.notify_count(), pre + 1);
        drv.read_block(&mut bus, 1, &mut buf).expect("read");
        assert_eq!(bus.notify_count(), pre + 2);
    }

    #[test]
    fn write_block_observed_with_correct_descriptor_flags() {
        // Drive a write, then walk the bus's descriptor table to
        // confirm the data descriptor is device-readable (no WRITE
        // flag). This is the property the verifier checks.
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let data = [0x42u8; VIRTIO_BLK_SECTOR_SIZE];
        drv.write_block(&mut bus, 1, &data).expect("write");
        // Read the data descriptor (slot 1) directly from shadow.
        let mut bytes = [0u8; 16];
        bus.read_shadow(PHYS_REQ_DESC + 16, &mut bytes);
        let data_desc = decode_desc(&bytes);
        assert_eq!(data_desc.flags & virtq_desc_flags::WRITE, 0);
        assert_eq!(data_desc.flags & virtq_desc_flags::NEXT, virtq_desc_flags::NEXT);
    }

    #[test]
    fn read_block_observed_with_correct_descriptor_flags() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        drv.read_block(&mut bus, 0, &mut buf).expect("read");
        let mut bytes = [0u8; 16];
        bus.read_shadow(PHYS_REQ_DESC + 16, &mut bytes);
        let data_desc = decode_desc(&bytes);
        // READ: data descriptor MUST be device-WRITABLE.
        assert_eq!(
            data_desc.flags & virtq_desc_flags::WRITE,
            virtq_desc_flags::WRITE
        );
    }

    #[test]
    fn read_zero_filled_default_sectors() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut buf = [0xFFu8; VIRTIO_BLK_SECTOR_SIZE];
        drv.read_block(&mut bus, 0, &mut buf).expect("read");
        // Default disk is zero-filled.
        for &b in buf.iter() {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn boundary_sector_is_readable() {
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        // Last valid sector index = DISK_SECTORS - 1.
        let last = MemVirtioBlkBus::DISK_SECTORS - 1;
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        assert!(drv.read_block(&mut bus, last, &mut buf).is_ok());
    }

    #[test]
    fn observation_capacity_is_bounded() {
        // Submit one more request than the observation cap can hold;
        // assert the bus does not overflow.
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        for s in 0..(REQ_OBSERVATION_CAP as u64 + 4) {
            drv.read_block(&mut bus, s % MemVirtioBlkBus::DISK_SECTORS, &mut buf)
                .expect("read");
        }
        assert!(bus.observations().len() <= REQ_OBSERVATION_CAP);
    }

    #[test]
    fn feature_constants_are_locked() {
        // Spot-check that the feature bit positions match the spec.
        assert_eq!(f::SIZE_MAX, 1 << 1);
        assert_eq!(f::SEG_MAX, 1 << 2);
        assert_eq!(f::GEOMETRY, 1 << 4);
        assert_eq!(f::RO, 1 << 5);
        assert_eq!(f::BLK_SIZE, 1 << 6);
        assert_eq!(f::FLUSH, 1 << 9);
        assert_eq!(f::TOPOLOGY, 1 << 10);
        assert_eq!(f::CONFIG_WCE, 1 << 11);
        assert_eq!(f::MQ, 1 << 12);
        assert_eq!(f::DISCARD, 1 << 13);
        assert_eq!(f::WRITE_ZEROES, 1 << 14);
        assert_eq!(f::VERSION_1, 1 << 32);
    }

    #[test]
    fn req_type_constants_are_locked() {
        assert_eq!(req_type::IN, 0);
        assert_eq!(req_type::OUT, 1);
        assert_eq!(req_type::FLUSH, 4);
        assert_eq!(req_type::GET_ID, 8);
        assert_eq!(req_type::DISCARD, 11);
        assert_eq!(req_type::WRITE_ZEROES, 13);
    }

    #[test]
    fn status_byte_constants_are_locked() {
        assert_eq!(st::OK, 0);
        assert_eq!(st::IOERR, 1);
        assert_eq!(st::UNSUPP, 2);
        assert_eq!(st::SENTINEL, 0xFF);
    }

    #[test]
    fn device_cfg_offsets_match_spec() {
        assert_eq!(dcfg::CAPACITY, 0x00);
        assert_eq!(dcfg::SIZE_MAX, 0x08);
        assert_eq!(dcfg::SEG_MAX, 0x0C);
        assert_eq!(dcfg::GEOMETRY_CYLINDERS, 0x10);
        assert_eq!(dcfg::GEOMETRY_HEADS, 0x12);
        assert_eq!(dcfg::GEOMETRY_SECTORS, 0x13);
        assert_eq!(dcfg::BLK_SIZE, 0x14);
    }

    #[test]
    fn queue_and_size_constants_are_locked() {
        assert_eq!(VIRTIO_BLK_QUEUE_REQUESTQ, 0);
        assert_eq!(VIRTIO_BLK_HDR_LEN, 16);
        assert_eq!(VIRTIO_BLK_SECTOR_SIZE, 512);
        assert_eq!(VIRTIO_BLK_STATUS_LEN, 1);
        assert_eq!(QUEUE_SIZE, 64);
    }

    #[test]
    fn capacity_sectors_zero_before_init() {
        let drv = VirtioBlk::new();
        assert_eq!(drv.capacity_sectors(), 0);
    }

    #[test]
    fn write_then_read_back_alternating_sectors() {
        // Stress: write 8 different patterns to 8 sectors, then
        // read them back interleaved. Confirms the avail/used ring
        // arithmetic survives multiple in-flight cycles.
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        for s in 0..8u64 {
            let mut data = [0u8; VIRTIO_BLK_SECTOR_SIZE];
            for i in 0..VIRTIO_BLK_SECTOR_SIZE {
                data[i] = ((s as u8).wrapping_mul(7)).wrapping_add(i as u8);
            }
            drv.write_block(&mut bus, s, &data).expect("write");
        }
        for s in (0..8u64).rev() {
            let mut readback = [0u8; VIRTIO_BLK_SECTOR_SIZE];
            drv.read_block(&mut bus, s, &mut readback).expect("read");
            for i in 0..VIRTIO_BLK_SECTOR_SIZE {
                let expected = ((s as u8).wrapping_mul(7)).wrapping_add(i as u8);
                assert_eq!(
                    readback[i], expected,
                    "sector {s} byte {i} mismatch"
                );
            }
        }
        assert_eq!(drv.request_count(), 16);
        assert_eq!(drv.completion_count(), 16);
    }

    #[test]
    fn forced_status_consumes_only_one_completion() {
        // Force one IOERR, then the next request should succeed.
        let (mut drv, mut bus) = fresh();
        drv.init(&mut bus).expect("init");
        bus.force_next_status(st::IOERR);
        let mut buf = [0u8; VIRTIO_BLK_SECTOR_SIZE];
        assert!(drv.read_block(&mut bus, 0, &mut buf).is_err());
        // Second read: clean.
        drv.read_block(&mut bus, 0, &mut buf).expect("recover");
    }
}

// Pull `alloc::vec` into scope ONLY for the unit tests above. The
// production module is strictly no_std + no alloc; the `cfg(test)`
// gate keeps that property intact.
#[cfg(test)]
extern crate alloc;
