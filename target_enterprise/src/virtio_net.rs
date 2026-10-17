//! VirtIO-net driver — `target_enterprise` port (TASK-048).
//!
//! Minimal VirtIO 1.0 network-device driver. Drives the spec-mandated
//! bring-up handshake, negotiates a small feature set, sets up the
//! receive + transmit virtqueues, and exposes [`transmit`](NetDevice::transmit) /
//! [`receive`](NetDevice::receive) per-frame APIs against an abstract
//! [`MmioBus`].
//!
//! # Locked surface
//!
//! - [`proteus_contracts::VirtqDesc`] — 16-byte descriptor entry (spec §2.6.5)
//! - [`proteus_contracts::VirtioNetHdr`] — 12-byte packet header (spec §5.1.6)
//! - [`proteus_contracts::virtio_net_feature`] — feature bit constants
//! - [`proteus_contracts::virtio_status`] — `device_status` bit constants
//! - [`proteus_contracts::virtio_common_cfg`] — common-cfg field offsets
//! - [`proteus_contracts::NetDevice`] — the trait surface
//!
//! # What this port covers
//!
//! - Reset → ACK → DRIVER → FEATURES_OK → DRIVER_OK handshake.
//! - Feature negotiation: `VERSION_1 | MAC | STATUS | CSUM` offered;
//!   `VERSION_1 | MAC` required.
//! - Single RX queue (queue 0) + single TX queue (queue 1), each
//!   64 entries deep.
//! - Pre-posts 16 RX buffers at init.
//! - Synchronous polled completion. No interrupts, no MSI-X.
//! - 2-descriptor chain per TX (header + payload), 2-descriptor chain
//!   per RX (header + payload).
//!
//! # What this port deliberately does NOT cover
//!
//! - PCI bus enumeration (BAR walking + cap discovery). A future port
//!   wraps real PCI into an [`MmioBus`] implementor.
//! - VIRTIO_NET_F_MRG_RXBUF — single-buffer RX only.
//! - GSO / TSO / UFO offload paths.
//! - Multi-queue (RSS, virtio-net mq feature).
//! - IRQ-driven completion. Polled only.

#![allow(clippy::needless_range_loop)]

use proteus_contracts::{
    virtio_common_cfg as ccfg, virtio_net_feature as feat, virtio_net_status, virtio_status,
    virtq_desc_flags, MmioBus, NetDevice, NetDeviceError, VirtioNetHdr, VirtqDesc,
    VIRTIO_NET_HDR_LEN, VIRTIO_NET_QUEUE_RX, VIRTIO_NET_QUEUE_TX,
};

// ---------------------------------------------------------------------------
// Geometry constants
// ---------------------------------------------------------------------------

/// Depth of each virtqueue. Must be a power of two, matches the spec
/// constraint that queue_size ≤ device-advertised max.
pub const QUEUE_SIZE: u16 = 64;

/// Convenience `usize` form of [`QUEUE_SIZE`].
pub const QUEUE_SIZE_USIZE: usize = QUEUE_SIZE as usize;

/// Number of RX buffers we pre-post at init. Less than [`QUEUE_SIZE`]
/// so we always have spare descriptor slots when recycling.
pub const RX_BUFFERS: usize = 16;

/// Maximum Ethernet frame length we accept (1514 = 14-byte L2 header
/// + 1500 MTU). Buffers are 2048 bytes to give slack for tagged
/// frames + the prepended virtio-net header.
pub const MAX_FRAME_LEN: usize = 1514;

/// Per-buffer RX scratch size, large enough for an MTU-1500 frame +
/// the 12-byte virtio-net header + slack.
pub const RX_BUF_SIZE: usize = 2048;

/// Per-buffer TX scratch size. Same shape as the RX buffer for
/// symmetry; the driver only ever writes ≤ [`MAX_FRAME_LEN`] + 12 bytes.
pub const TX_BUF_SIZE: usize = 2048;

/// Maximum number of poll iterations the bring-up handshake will
/// spin through while waiting for `device_status` to clear / accept.
/// The emulator transitions synchronously so the actual count is 1;
/// real hardware may take a few microseconds.
pub const HANDSHAKE_POLL_BUDGET: u32 = 100_000;

// ---------------------------------------------------------------------------
// Pseudo-phys address allocation
// ---------------------------------------------------------------------------
//
// Real hardware: the driver pulls phys-addrs from the frame allocator.
// Host tests: we hand out monotone sentinel addresses; the bus tracks
// them in its shadow map. The exact numeric values are locked
// constants — the verifier asserts that every byte the driver writes
// to common-cfg matches the locked sequence, so the phys-addr layout
// is observable.

/// Base phys-addr for the RX descriptor table.
pub const PHYS_RX_DESC: u64 = 0x0000_1000;
/// Base phys-addr for the RX avail ring.
pub const PHYS_RX_AVAIL: u64 = 0x0000_2000;
/// Base phys-addr for the RX used ring.
pub const PHYS_RX_USED: u64 = 0x0000_3000;
/// Base phys-addr for the TX descriptor table.
pub const PHYS_TX_DESC: u64 = 0x0000_4000;
/// Base phys-addr for the TX avail ring.
pub const PHYS_TX_AVAIL: u64 = 0x0000_5000;
/// Base phys-addr for the TX used ring.
pub const PHYS_TX_USED: u64 = 0x0000_6000;
/// Base phys-addr for the RX buffer pool. Each buffer occupies
/// [`RX_BUF_SIZE`] bytes; buffer `i` lives at
/// `PHYS_RX_BUFFERS + i * RX_BUF_SIZE`. With RX_BUFFERS = 16 and
/// RX_BUF_SIZE = 2048, the pool spans 0x7000..0xF000.
pub const PHYS_RX_BUFFERS: u64 = 0x0000_7000;
/// Base phys-addr for the TX scratch buffer (single, reused per call).
pub const PHYS_TX_BUFFER: u64 = 0x0000_F000;

// ---------------------------------------------------------------------------
// Wire encoding helpers
// ---------------------------------------------------------------------------

/// Encode a [`VirtqDesc`] into its 16-byte little-endian wire form.
/// Lives in the contracts crate as a `#[repr(C)]` struct so the in-
/// memory layout already matches the wire layout on every little-
/// endian host. We still emit explicit bytes here so the bus's
/// `dma_write` shadow records the exact byte sequence the verifier
/// asserts against.
#[inline]
pub fn encode_desc(d: &VirtqDesc, out: &mut [u8; 16]) {
    out[0..8].copy_from_slice(&d.addr.to_le_bytes());
    out[8..12].copy_from_slice(&d.len.to_le_bytes());
    out[12..14].copy_from_slice(&d.flags.to_le_bytes());
    out[14..16].copy_from_slice(&d.next.to_le_bytes());
}

/// Decode a 16-byte little-endian descriptor entry into a [`VirtqDesc`].
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

/// Encode a [`VirtioNetHdr`] into its 12-byte little-endian wire form.
#[inline]
pub fn encode_net_hdr(h: &VirtioNetHdr, out: &mut [u8; VIRTIO_NET_HDR_LEN]) {
    out[0] = h.flags;
    out[1] = h.gso_type;
    out[2..4].copy_from_slice(&h.hdr_len.to_le_bytes());
    out[4..6].copy_from_slice(&h.gso_size.to_le_bytes());
    out[6..8].copy_from_slice(&h.csum_start.to_le_bytes());
    out[8..10].copy_from_slice(&h.csum_offset.to_le_bytes());
    out[10..12].copy_from_slice(&h.num_buffers.to_le_bytes());
}

/// Decode a 12-byte little-endian virtio-net header from `bytes`.
#[inline]
pub fn decode_net_hdr(bytes: &[u8; VIRTIO_NET_HDR_LEN]) -> VirtioNetHdr {
    let mut hdr_len = [0u8; 2];
    hdr_len.copy_from_slice(&bytes[2..4]);
    let mut gso_size = [0u8; 2];
    gso_size.copy_from_slice(&bytes[4..6]);
    let mut csum_start = [0u8; 2];
    csum_start.copy_from_slice(&bytes[6..8]);
    let mut csum_offset = [0u8; 2];
    csum_offset.copy_from_slice(&bytes[8..10]);
    let mut num_buffers = [0u8; 2];
    num_buffers.copy_from_slice(&bytes[10..12]);
    VirtioNetHdr {
        flags: bytes[0],
        gso_type: bytes[1],
        hdr_len: u16::from_le_bytes(hdr_len),
        gso_size: u16::from_le_bytes(gso_size),
        csum_start: u16::from_le_bytes(csum_start),
        csum_offset: u16::from_le_bytes(csum_offset),
        num_buffers: u16::from_le_bytes(num_buffers),
    }
}

// ---------------------------------------------------------------------------
// VirtioNet driver state
// ---------------------------------------------------------------------------

/// VirtIO-net driver instance. The bus is passed per call (so a single
/// driver can drive devices behind different buses across morph
/// cycles, and so the trait surface matches the locked contract). All
/// driver-side state (queue indices, MAC, negotiated feature set,
/// pre-posted RX buffer accounting) lives here.
pub struct VirtioNet {
    /// Whether `init` has completed successfully.
    initialised: bool,
    /// MAC read from device-cfg after feature negotiation. `[0; 6]`
    /// until `init` succeeds.
    mac: [u8; 6],
    /// Feature set agreed with the device. 0 until `init` succeeds.
    negotiated_features: u64,
    /// True if VIRTIO_NET_F_STATUS was negotiated AND the device
    /// reports LINK_UP at init time.
    link_up: bool,
    /// Next TX avail-ring slot the driver will publish into.
    tx_avail_idx: u16,
    /// Number of TX completions reaped via the used ring.
    tx_used_seen: u16,
    /// Next RX avail-ring slot the driver will write when recycling.
    rx_avail_idx: u16,
    /// Number of RX completions reaped via the used ring.
    rx_used_seen: u16,
    /// Notify-region offset for the RX queue (read once at init).
    rx_notify_off: u16,
    /// Notify-region offset for the TX queue.
    tx_notify_off: u16,
}

impl Default for VirtioNet {
    fn default() -> Self {
        Self::new()
    }
}

impl VirtioNet {
    /// Construct a fresh driver. Does NOT touch any bus; call
    /// [`NetDevice::init`] next.
    pub const fn new() -> Self {
        Self {
            initialised: false,
            mac: [0u8; 6],
            negotiated_features: 0,
            link_up: false,
            tx_avail_idx: 0,
            tx_used_seen: 0,
            rx_avail_idx: 0,
            rx_used_seen: 0,
            rx_notify_off: 0,
            tx_notify_off: 0,
        }
    }

    /// True iff [`NetDevice::init`] has completed successfully.
    pub fn is_initialised(&self) -> bool {
        self.initialised
    }

    /// Feature set agreed with the device on the most recent successful
    /// `init`. 0 if `init` has not been called.
    pub fn negotiated_features(&self) -> u64 {
        self.negotiated_features
    }

    /// True iff `VIRTIO_NET_F_STATUS` was negotiated AND the device's
    /// `status` word at init had `LINK_UP` set.
    pub fn link_up(&self) -> bool {
        self.link_up
    }

    /// Number of TX descriptors published since init. Wraps at u16.
    pub fn tx_count(&self) -> u16 {
        self.tx_avail_idx
    }

    /// Number of RX completions consumed since init.
    pub fn rx_count(&self) -> u16 {
        self.rx_used_seen
    }

    /// Read the 64-bit device feature set from common-cfg through two
    /// 32-bit windows. Exposed for tests + the harness; the production
    /// path uses it inline during `init`.
    pub fn read_device_features(bus: &mut dyn MmioBus) -> u64 {
        bus.write_common_u32(ccfg::DEVICE_FEATURE_SELECT, 0);
        let lo = bus.read_common_u32(ccfg::DEVICE_FEATURE) as u64;
        bus.write_common_u32(ccfg::DEVICE_FEATURE_SELECT, 1);
        let hi = bus.read_common_u32(ccfg::DEVICE_FEATURE) as u64;
        lo | (hi << 32)
    }

    /// Write the 64-bit accepted feature set back through two 32-bit
    /// windows.
    pub fn write_driver_features(bus: &mut dyn MmioBus, value: u64) {
        bus.write_common_u32(ccfg::DRIVER_FEATURE_SELECT, 0);
        bus.write_common_u32(ccfg::DRIVER_FEATURE, value as u32);
        bus.write_common_u32(ccfg::DRIVER_FEATURE_SELECT, 1);
        bus.write_common_u32(ccfg::DRIVER_FEATURE, (value >> 32) as u32);
    }

    /// Set up one virtqueue: writes `queue_size`, the three phys-addr
    /// triple (`queue_desc` / `queue_driver` / `queue_device`), reads
    /// `queue_notify_off`, and finally writes 1 to `queue_enable`.
    /// Returns the notify offset. Inlined into `init` in production;
    /// exposed for tests.
    pub fn configure_queue(
        bus: &mut dyn MmioBus,
        queue: u16,
        desc_phys: u64,
        avail_phys: u64,
        used_phys: u64,
    ) -> Result<u16, NetDeviceError> {
        bus.write_common_u16(ccfg::QUEUE_SELECT, queue);
        let device_size = bus.read_common_u16(ccfg::QUEUE_SIZE);
        if device_size < QUEUE_SIZE {
            return Err(NetDeviceError::QueueTooSmall);
        }
        bus.write_common_u16(ccfg::QUEUE_SIZE, QUEUE_SIZE);
        bus.write_common_u64(ccfg::QUEUE_DESC, desc_phys);
        bus.write_common_u64(ccfg::QUEUE_DRIVER, avail_phys);
        bus.write_common_u64(ccfg::QUEUE_DEVICE, used_phys);
        let notify_off = bus.read_common_u16(ccfg::QUEUE_NOTIFY_OFF);
        bus.write_common_u16(ccfg::QUEUE_ENABLE, 1);
        Ok(notify_off)
    }

    /// Build the descriptor entry for one RX slot. RX descriptors are
    /// 2-deep chains (header + data, both device-writable). The
    /// `head_index` is `2 * buffer_index`; the chain's `next` lands
    /// at `head_index + 1`. Buffer `i` lives at
    /// `PHYS_RX_BUFFERS + i * RX_BUF_SIZE`; the header occupies the
    /// first 12 bytes, the payload starts at offset 64 (cache-line
    /// aligned) — same shape as the donor.
    pub fn rx_descriptor_pair(buffer_index: usize) -> (VirtqDesc, VirtqDesc) {
        let buf_phys = PHYS_RX_BUFFERS + (buffer_index as u64) * (RX_BUF_SIZE as u64);
        let head_index = (2 * buffer_index) as u16;
        let head = VirtqDesc {
            addr: buf_phys,
            len: VIRTIO_NET_HDR_LEN as u32,
            flags: virtq_desc_flags::NEXT | virtq_desc_flags::WRITE,
            next: head_index + 1,
        };
        let tail = VirtqDesc {
            addr: buf_phys + 64,
            len: (RX_BUF_SIZE as u32) - 64,
            flags: virtq_desc_flags::WRITE,
            next: 0,
        };
        (head, tail)
    }

    /// Build the descriptor entry pair for one TX submission. The
    /// driver always reuses the head pair at indices 0 + 1; the
    /// avail ring's slot wraps. TX descriptors are device-READABLE
    /// (no `WRITE` flag).
    pub fn tx_descriptor_pair(payload_len: usize) -> (VirtqDesc, VirtqDesc) {
        let head = VirtqDesc {
            addr: PHYS_TX_BUFFER,
            len: VIRTIO_NET_HDR_LEN as u32,
            flags: virtq_desc_flags::NEXT,
            next: 1,
        };
        let tail = VirtqDesc {
            addr: PHYS_TX_BUFFER + 64,
            len: payload_len as u32,
            flags: 0,
            next: 0,
        };
        (head, tail)
    }

    /// Publish RX descriptor pairs + avail-ring entries for all
    /// pre-posted buffers, write the avail.idx, ring the doorbell.
    fn populate_rx_ring(&mut self, bus: &mut dyn MmioBus) {
        // Avail-ring flags word at the start of the avail ring (offset 0).
        let zero_flags = [0u8; 2];
        bus.dma_write(PHYS_RX_AVAIL, &zero_flags);

        let mut desc_bytes = [0u8; 16];
        for i in 0..RX_BUFFERS {
            let (head, tail) = Self::rx_descriptor_pair(i);
            let head_index = (2 * i) as u16;
            encode_desc(&head, &mut desc_bytes);
            bus.dma_write(
                PHYS_RX_DESC + (head_index as u64) * 16,
                &desc_bytes,
            );
            encode_desc(&tail, &mut desc_bytes);
            bus.dma_write(
                PHYS_RX_DESC + ((head_index + 1) as u64) * 16,
                &desc_bytes,
            );
            // Avail-ring entry at offset 4 + i * 2.
            let entry = head_index.to_le_bytes();
            bus.dma_write(PHYS_RX_AVAIL + 4 + (i as u64) * 2, &entry);
        }

        // Avail.idx at offset 2 of the avail ring.
        let idx = (RX_BUFFERS as u16).to_le_bytes();
        bus.dma_write(PHYS_RX_AVAIL + 2, &idx);
        self.rx_avail_idx = RX_BUFFERS as u16;

        bus.notify_queue(VIRTIO_NET_QUEUE_RX);
    }

    /// Read the next-RX descriptor's index out of the used ring at
    /// position `slot`. Returns `(head_idx, total_written)`.
    fn read_used_ring_entry(
        bus: &dyn MmioBus,
        used_base: u64,
        slot: u16,
    ) -> (u16, u32) {
        // Used-ring layout: flags (u16) | idx (u16) | UsedElem[]
        // Each UsedElem is { id: u32, len: u32 } = 8 bytes.
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

    /// Read the current used.idx from the device-written used ring.
    fn read_used_idx(bus: &dyn MmioBus, used_base: u64) -> u16 {
        let mut buf = [0u8; 2];
        bus.dma_read(used_base + 2, &mut buf);
        u16::from_le_bytes(buf)
    }
}

// ---------------------------------------------------------------------------
// NetDevice impl
// ---------------------------------------------------------------------------

impl NetDevice for VirtioNet {
    fn init(&mut self, bus: &mut dyn MmioBus) -> Result<(), NetDeviceError> {
        if self.initialised {
            return Err(NetDeviceError::AlreadyInitialised);
        }

        // Step 1: RESET — write 0 to device_status, poll until
        // it reads back 0.
        bus.write_common_u8(ccfg::DEVICE_STATUS, 0);
        let mut polls = HANDSHAKE_POLL_BUDGET;
        loop {
            if bus.read_common_u8(ccfg::DEVICE_STATUS) == 0 {
                break;
            }
            if polls == 0 {
                return Err(NetDeviceError::ResetTimeout);
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
            return Err(NetDeviceError::LegacyDeviceUnsupported);
        }
        if offered & feat::MAC == 0 {
            return Err(NetDeviceError::MacNotAdvertised);
        }

        // Accept the intersection of what we want + what's offered,
        // plus the required bits.
        let accepted = (offered & feat::SEED_FEATURE_MASK) | feat::SEED_REQUIRED_MASK;
        Self::write_driver_features(bus, accepted);
        self.negotiated_features = accepted;

        // Step 5: write FEATURES_OK, read back to confirm.
        let with_features_ok = virtio_status::ACK | virtio_status::DRIVER | virtio_status::FEATURES_OK;
        bus.write_common_u8(ccfg::DEVICE_STATUS, with_features_ok);
        let after = bus.read_common_u8(ccfg::DEVICE_STATUS);
        if after & virtio_status::FAILED != 0 {
            return Err(NetDeviceError::DeviceFailed);
        }
        if after & virtio_status::FEATURES_OK == 0 {
            return Err(NetDeviceError::FeaturesOkRejected);
        }

        // Step 6: read MAC + link status from device-cfg.
        let mut mac = [0u8; 6];
        for i in 0..6 {
            mac[i] = bus.read_device_u8(i);
        }
        self.mac = mac;
        if accepted & feat::STATUS != 0 {
            let status_word = bus.read_device_u16(6);
            self.link_up = status_word & virtio_net_status::LINK_UP != 0;
        }

        // Step 7: configure queues. RX = 0, TX = 1.
        self.rx_notify_off = Self::configure_queue(
            bus,
            VIRTIO_NET_QUEUE_RX,
            PHYS_RX_DESC,
            PHYS_RX_AVAIL,
            PHYS_RX_USED,
        )?;
        self.tx_notify_off = Self::configure_queue(
            bus,
            VIRTIO_NET_QUEUE_TX,
            PHYS_TX_DESC,
            PHYS_TX_AVAIL,
            PHYS_TX_USED,
        )?;

        // Step 8: DRIVER_OK.
        bus.write_common_u8(
            ccfg::DEVICE_STATUS,
            with_features_ok | virtio_status::DRIVER_OK,
        );
        let final_status = bus.read_common_u8(ccfg::DEVICE_STATUS);
        if final_status & virtio_status::FAILED != 0 {
            return Err(NetDeviceError::DeviceFailed);
        }

        // Step 9: pre-post the RX ring.
        self.populate_rx_ring(bus);

        // Step 10: also zero the TX avail-ring flags word, so the
        // device doesn't read garbage on first TX notify.
        let tx_flags = [0u8; 2];
        bus.dma_write(PHYS_TX_AVAIL, &tx_flags);
        let tx_idx = 0u16.to_le_bytes();
        bus.dma_write(PHYS_TX_AVAIL + 2, &tx_idx);

        self.initialised = true;
        Ok(())
    }

    fn transmit(
        &mut self,
        bus: &mut dyn MmioBus,
        frame: &[u8],
    ) -> Result<(), NetDeviceError> {
        if !self.initialised {
            return Err(NetDeviceError::NotInitialised);
        }
        if frame.is_empty() {
            return Err(NetDeviceError::FrameEmpty);
        }
        if frame.len() > MAX_FRAME_LEN {
            return Err(NetDeviceError::FrameTooLarge);
        }

        // Reap any completed TX descriptors so accounting stays current.
        let cur_used = Self::read_used_idx(bus, PHYS_TX_USED);
        self.tx_used_seen = cur_used;

        // 1. Write the 12-byte VirtIO-net header at PHYS_TX_BUFFER.
        let hdr = VirtioNetHdr {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        };
        let mut hdr_bytes = [0u8; VIRTIO_NET_HDR_LEN];
        encode_net_hdr(&hdr, &mut hdr_bytes);
        bus.dma_write(PHYS_TX_BUFFER, &hdr_bytes);

        // 2. Write the frame payload at PHYS_TX_BUFFER + 64.
        bus.dma_write(PHYS_TX_BUFFER + 64, frame);

        // 3. Publish a 2-descriptor chain at TX desc indices 0 + 1.
        let (head, tail) = Self::tx_descriptor_pair(frame.len());
        let mut desc_bytes = [0u8; 16];
        encode_desc(&head, &mut desc_bytes);
        bus.dma_write(PHYS_TX_DESC, &desc_bytes);
        encode_desc(&tail, &mut desc_bytes);
        bus.dma_write(PHYS_TX_DESC + 16, &desc_bytes);

        // 4. Write avail-ring slot + bump avail.idx.
        let slot = (self.tx_avail_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let head_idx_le = 0u16.to_le_bytes();
        bus.dma_write(PHYS_TX_AVAIL + 4 + (slot as u64) * 2, &head_idx_le);
        let new_idx = self.tx_avail_idx.wrapping_add(1);
        let new_idx_le = new_idx.to_le_bytes();
        bus.dma_write(PHYS_TX_AVAIL + 2, &new_idx_le);
        self.tx_avail_idx = new_idx;

        // 5. Notify the TX queue.
        bus.notify_queue(VIRTIO_NET_QUEUE_TX);
        Ok(())
    }

    fn receive(
        &mut self,
        bus: &mut dyn MmioBus,
        out: &mut [u8],
    ) -> Result<usize, NetDeviceError> {
        if !self.initialised {
            return Err(NetDeviceError::NotInitialised);
        }
        if out.len() < MAX_FRAME_LEN {
            return Err(NetDeviceError::OutputBufferTooSmall);
        }

        let used_idx = Self::read_used_idx(bus, PHYS_RX_USED);
        if used_idx == self.rx_used_seen {
            return Err(NetDeviceError::RxQueueEmpty);
        }

        let slot = (self.rx_used_seen as usize) & (QUEUE_SIZE_USIZE - 1);
        let (head_idx, total_written) =
            Self::read_used_ring_entry(bus, PHYS_RX_USED, slot as u16);

        // Validate descriptor index.
        if head_idx as usize >= 2 * RX_BUFFERS {
            return Err(NetDeviceError::DescriptorIndexOutOfRange);
        }
        if head_idx & 1 != 0 {
            // Chains always start on even indices.
            return Err(NetDeviceError::DescriptorIndexOutOfRange);
        }

        // The frame total is `total_written`. The first 12 bytes are
        // the VirtIO-net header (read from the head descriptor's
        // buffer); the remainder is the Ethernet payload (read from
        // the tail descriptor's buffer at offset 64).
        if (total_written as usize) < VIRTIO_NET_HDR_LEN {
            return Err(NetDeviceError::RxFrameTruncated);
        }
        let buffer_index = (head_idx / 2) as usize;
        let buf_phys = PHYS_RX_BUFFERS + (buffer_index as u64) * (RX_BUF_SIZE as u64);
        let mut hdr_bytes = [0u8; VIRTIO_NET_HDR_LEN];
        bus.dma_read(buf_phys, &mut hdr_bytes);
        let hdr = decode_net_hdr(&hdr_bytes);
        if hdr.num_buffers != 1 {
            return Err(NetDeviceError::UnsupportedRxBuffersMerged);
        }

        let payload_len = (total_written as usize) - VIRTIO_NET_HDR_LEN;
        let payload_len = core::cmp::min(payload_len, RX_BUF_SIZE - 64);
        let payload_len = core::cmp::min(payload_len, out.len());
        bus.dma_read(buf_phys + 64, &mut out[..payload_len]);

        // Advance rx_used_seen.
        self.rx_used_seen = self.rx_used_seen.wrapping_add(1);

        // Recycle the descriptor pair back into the avail ring.
        let recycle_slot = (self.rx_avail_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let head_le = head_idx.to_le_bytes();
        bus.dma_write(
            PHYS_RX_AVAIL + 4 + (recycle_slot as u64) * 2,
            &head_le,
        );
        let new_idx = self.rx_avail_idx.wrapping_add(1);
        let new_idx_le = new_idx.to_le_bytes();
        bus.dma_write(PHYS_RX_AVAIL + 2, &new_idx_le);
        self.rx_avail_idx = new_idx;
        bus.notify_queue(VIRTIO_NET_QUEUE_RX);

        Ok(payload_len)
    }

    fn mac_address(&self) -> [u8; 6] {
        self.mac
    }
}

// ---------------------------------------------------------------------------
// In-memory MMIO bus (test fixture)
// ---------------------------------------------------------------------------

/// Backing-store size for the test bus's "phys memory". 64 KiB — fits
/// the queue tables (6 × 4 KiB), the 16 × 2 KiB RX buffers, and the
/// single 2 KiB TX scratch buffer with a small head-padding region.
/// Sized to fit on a host test stack AND the kernel's banner stack.
pub const MEM_BUS_BYTES: usize = 64 * 1024;

/// Cap on the number of "transmit observations" the bus records.
/// Exposes one slot per banner-style assertion. Sized small to keep
/// the static stack lean.
pub const TX_OBSERVATION_CAP: usize = 8;

/// One observed TX frame in the [`MemVirtioBus`] device-side log.
/// Stored as a fixed-size array + length so the bus needs no
/// heap.
#[derive(Clone, Copy)]
pub struct TxObservation {
    /// Captured payload bytes.
    pub bytes: [u8; MAX_FRAME_LEN],
    /// Number of bytes actually used in `bytes`.
    pub len: usize,
}

impl Default for TxObservation {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FRAME_LEN],
            len: 0,
        }
    }
}

/// Status-byte write event recorded by [`MemVirtioBus::status_log`].
/// The verifier asserts the locked bring-up sequence by comparing the
/// observed writes against the spec-mandated values.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct StatusWrite {
    /// The byte value the driver wrote to `device_status` (common-cfg
    /// offset 0x14).
    pub value: u8,
}

/// Cap on `status_log` length.
pub const STATUS_LOG_CAP: usize = 8;

/// Cap on the number of "pending RX frames" the bus can queue up
/// before they overflow.
pub const PENDING_RX_CAP: usize = 4;

/// One pending RX frame the harness has injected for delivery to the
/// driver on the next [`MemVirtioBus::deliver_pending_rx`] call.
#[derive(Clone, Copy)]
pub struct PendingRxFrame {
    /// Captured payload bytes.
    pub bytes: [u8; MAX_FRAME_LEN],
    /// Number of bytes used.
    pub len: usize,
}

impl Default for PendingRxFrame {
    fn default() -> Self {
        Self {
            bytes: [0u8; MAX_FRAME_LEN],
            len: 0,
        }
    }
}

/// Host-side VirtIO-MMIO emulator. Tracks:
/// - A 1 MiB byte-addressable shadow phys memory.
/// - The 21 common-cfg fields the driver writes.
/// - Per-queue selection state + per-queue base addresses.
/// - A 6-byte MAC + 2-byte status word in device-cfg.
/// - A log of every `device_status` write (for the bring-up sequence
///   assertion).
/// - A log of every observed TX frame.
/// - A pending-RX FIFO for harness-injected receive frames.
pub struct MemVirtioBus {
    shadow: [u8; MEM_BUS_BYTES],
    // Common-cfg registers.
    device_status: u8,
    device_feature_select: u32,
    driver_feature_select: u32,
    device_features: u64,
    driver_features_lo: u32,
    driver_features_hi: u32,
    queue_select: u16,
    rx_queue_size: u16,
    tx_queue_size: u16,
    rx_queue_desc: u64,
    tx_queue_desc: u64,
    rx_queue_driver: u64,
    tx_queue_driver: u64,
    rx_queue_device: u64,
    tx_queue_device: u64,
    rx_queue_enable: u16,
    tx_queue_enable: u16,
    // Device-cfg.
    mac: [u8; 6],
    status_word: u16,
    // Logs / fixtures.
    status_log: [StatusWrite; STATUS_LOG_CAP],
    status_log_len: usize,
    tx_observations: [TxObservation; TX_OBSERVATION_CAP],
    tx_observations_len: usize,
    pending_rx: [PendingRxFrame; PENDING_RX_CAP],
    pending_rx_len: usize,
    /// How many TX queue notifications have been received.
    tx_notify_count: u32,
    /// How many RX queue notifications have been received.
    rx_notify_count: u32,
}

impl Default for MemVirtioBus {
    fn default() -> Self {
        Self::new()
    }
}

impl MemVirtioBus {
    /// Construct a fresh emulator with a sensible default MAC + the
    /// seed feature mask. The MAC is `52:54:00:12:34:56` — the QEMU
    /// default user-mode MAC, useful for the kernel banner so the
    /// log line has a recognisable value.
    pub const fn new() -> Self {
        Self {
            shadow: [0u8; MEM_BUS_BYTES],
            device_status: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            device_features: feat::VERSION_1 | feat::MAC | feat::STATUS | feat::CSUM,
            driver_features_lo: 0,
            driver_features_hi: 0,
            queue_select: 0,
            rx_queue_size: QUEUE_SIZE,
            tx_queue_size: QUEUE_SIZE,
            rx_queue_desc: 0,
            tx_queue_desc: 0,
            rx_queue_driver: 0,
            tx_queue_driver: 0,
            rx_queue_device: 0,
            tx_queue_device: 0,
            rx_queue_enable: 0,
            tx_queue_enable: 0,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            status_word: virtio_net_status::LINK_UP,
            status_log: [StatusWrite { value: 0 }; STATUS_LOG_CAP],
            status_log_len: 0,
            tx_observations: [TxObservation {
                bytes: [0u8; MAX_FRAME_LEN],
                len: 0,
            }; TX_OBSERVATION_CAP],
            tx_observations_len: 0,
            pending_rx: [PendingRxFrame {
                bytes: [0u8; MAX_FRAME_LEN],
                len: 0,
            }; PENDING_RX_CAP],
            pending_rx_len: 0,
            tx_notify_count: 0,
            rx_notify_count: 0,
        }
    }

    /// Override the MAC the device exposes. Used by tests + the
    /// banner exercise.
    pub fn set_mac(&mut self, mac: [u8; 6]) {
        self.mac = mac;
    }

    /// Set the device-cfg status word. The driver only reads it when
    /// `VIRTIO_NET_F_STATUS` is negotiated.
    pub fn set_status_word(&mut self, w: u16) {
        self.status_word = w;
    }

    /// Override the device feature set advertised through
    /// `device_feature` reads. Used by tests that exercise the
    /// "device offers less than required" rejection path.
    pub fn set_device_features(&mut self, features: u64) {
        self.device_features = features;
    }

    /// Make `read_queue_size` return `size` instead of [`QUEUE_SIZE`].
    /// Used by tests that exercise the "device too small" rejection.
    pub fn set_queue_size(&mut self, size: u16) {
        self.rx_queue_size = size;
        self.tx_queue_size = size;
    }

    /// Return the recorded sequence of `device_status` writes.
    pub fn status_log(&self) -> &[StatusWrite] {
        &self.status_log[..self.status_log_len]
    }

    /// Return the (lo, hi) pair of `driver_feature` halves the driver
    /// wrote. The combined u64 is `(hi << 32) | lo`.
    pub fn driver_features(&self) -> u64 {
        (self.driver_features_lo as u64) | ((self.driver_features_hi as u64) << 32)
    }

    /// Number of TX queue notifications recorded.
    pub fn tx_notify_count(&self) -> u32 {
        self.tx_notify_count
    }

    /// Number of RX queue notifications recorded.
    pub fn rx_notify_count(&self) -> u32 {
        self.rx_notify_count
    }

    /// Return a view of all observed TX frames.
    pub fn tx_observations(&self) -> &[TxObservation] {
        &self.tx_observations[..self.tx_observations_len]
    }

    /// Inject an RX frame for the next [`deliver_pending_rx`] call.
    /// Returns `false` if the pending queue is full.
    pub fn enqueue_rx(&mut self, frame: &[u8]) -> bool {
        if self.pending_rx_len >= PENDING_RX_CAP {
            return false;
        }
        if frame.len() > MAX_FRAME_LEN {
            return false;
        }
        let slot = &mut self.pending_rx[self.pending_rx_len];
        slot.bytes[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        self.pending_rx_len += 1;
        true
    }

    /// Drain one pending RX frame into the driver's published RX ring.
    /// Mirrors what a real VirtIO-net device does on receive: it
    /// picks the next free RX descriptor chain from the avail ring,
    /// writes the virtio_net_hdr + frame payload into the chain's
    /// buffers, then publishes an entry in the used ring.
    ///
    /// Returns `true` if a frame was delivered, `false` if either no
    /// pending frame existed or no RX buffer was published.
    pub fn deliver_pending_rx(&mut self) -> bool {
        if self.pending_rx_len == 0 {
            return false;
        }
        // Read avail.idx (driver's pointer); if the driver hasn't
        // published any buffers, we can't deliver.
        let driver_avail_idx = self.read_avail_idx(self.rx_queue_driver);
        let device_used_idx = self.read_used_idx(self.rx_queue_device);
        let pending_slots = driver_avail_idx.wrapping_sub(device_used_idx);
        if pending_slots == 0 {
            return false;
        }

        // Take next pending frame.
        let frame = self.pending_rx[0];
        // Shift the queue.
        for i in 1..self.pending_rx_len {
            self.pending_rx[i - 1] = self.pending_rx[i];
        }
        self.pending_rx_len -= 1;

        // Pull the next published avail-ring slot.
        let avail_slot = (device_used_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let head_idx_off = self.rx_queue_driver + 4 + (avail_slot as u64) * 2;
        let mut head_le = [0u8; 2];
        self.read_shadow(head_idx_off, &mut head_le);
        let head_idx = u16::from_le_bytes(head_le);

        // Decode the head + tail descriptor entries to find buffer phys
        // addresses.
        let head_off = self.rx_queue_desc + (head_idx as u64) * 16;
        let tail_off = self.rx_queue_desc + ((head_idx + 1) as u64) * 16;
        let mut head_bytes = [0u8; 16];
        self.read_shadow(head_off, &mut head_bytes);
        let head_desc = decode_desc(&head_bytes);
        let mut tail_bytes = [0u8; 16];
        self.read_shadow(tail_off, &mut tail_bytes);
        let tail_desc = decode_desc(&tail_bytes);

        // Write the 12-byte virtio_net_hdr into the head buffer.
        let hdr = VirtioNetHdr {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
            num_buffers: 1,
        };
        let mut hdr_bytes = [0u8; VIRTIO_NET_HDR_LEN];
        encode_net_hdr(&hdr, &mut hdr_bytes);
        self.write_shadow(head_desc.addr, &hdr_bytes);

        // Write payload into the tail buffer.
        let payload_len = core::cmp::min(frame.len, tail_desc.len as usize);
        self.write_shadow(tail_desc.addr, &frame.bytes[..payload_len]);

        // Publish to the used ring. Entry at offset 4 + slot * 8:
        //   id (u32) = head_idx; len (u32) = HDR_LEN + payload_len.
        let used_slot = (device_used_idx as usize) & (QUEUE_SIZE_USIZE - 1);
        let entry_off = self.rx_queue_device + 4 + (used_slot as u64) * 8;
        let id_le = (head_idx as u32).to_le_bytes();
        self.write_shadow(entry_off, &id_le);
        let total = (VIRTIO_NET_HDR_LEN + payload_len) as u32;
        let len_le = total.to_le_bytes();
        self.write_shadow(entry_off + 4, &len_le);

        // Bump used.idx.
        let new_used_idx = device_used_idx.wrapping_add(1);
        let new_used_idx_le = new_used_idx.to_le_bytes();
        self.write_shadow(self.rx_queue_device + 2, &new_used_idx_le);
        true
    }

    /// Read the TX avail ring and capture any newly-published frames
    /// into the [`tx_observations`] log. Mirrors what a real device's
    /// TX path does post-notify: it walks new avail-ring slots and
    /// reads the descriptor chains' payloads. Returns the number of
    /// frames captured this call.
    pub fn capture_pending_tx(&mut self) -> usize {
        let driver_avail_idx = self.read_avail_idx(self.tx_queue_driver);
        let device_used_idx = self.read_used_idx(self.tx_queue_device);
        let pending = driver_avail_idx.wrapping_sub(device_used_idx);
        let mut captured = 0usize;
        for i in 0..pending {
            let avail_slot = (device_used_idx.wrapping_add(i) as usize) & (QUEUE_SIZE_USIZE - 1);
            let head_off = self.tx_queue_driver + 4 + (avail_slot as u64) * 2;
            let mut head_le = [0u8; 2];
            self.read_shadow(head_off, &mut head_le);
            let head_idx = u16::from_le_bytes(head_le);

            let h_off = self.tx_queue_desc + (head_idx as u64) * 16;
            let t_off = self.tx_queue_desc + ((head_idx + 1) as u64) * 16;
            let mut h_bytes = [0u8; 16];
            self.read_shadow(h_off, &mut h_bytes);
            let h_desc = decode_desc(&h_bytes);
            let mut t_bytes = [0u8; 16];
            self.read_shadow(t_off, &mut t_bytes);
            let t_desc = decode_desc(&t_bytes);

            // Read header (validate fields).
            let mut hdr_bytes = [0u8; VIRTIO_NET_HDR_LEN];
            self.read_shadow(h_desc.addr, &mut hdr_bytes);
            let hdr = decode_net_hdr(&hdr_bytes);
            if hdr.num_buffers != 1 {
                // Spec violation; skip.
                continue;
            }

            // Capture payload.
            let payload_len = core::cmp::min(t_desc.len as usize, MAX_FRAME_LEN);
            if self.tx_observations_len < TX_OBSERVATION_CAP {
                let mut scratch = [0u8; MAX_FRAME_LEN];
                self.read_shadow(t_desc.addr, &mut scratch[..payload_len]);
                let slot = &mut self.tx_observations[self.tx_observations_len];
                slot.bytes[..payload_len].copy_from_slice(&scratch[..payload_len]);
                slot.len = payload_len;
                self.tx_observations_len += 1;
            }

            // Publish to used ring: id (u32) = head_idx, len = HDR_LEN.
            let used_slot = (device_used_idx.wrapping_add(i) as usize) & (QUEUE_SIZE_USIZE - 1);
            let entry_off = self.tx_queue_device + 4 + (used_slot as u64) * 8;
            let id_le = (head_idx as u32).to_le_bytes();
            self.write_shadow(entry_off, &id_le);
            let len_le = ((VIRTIO_NET_HDR_LEN + payload_len) as u32).to_le_bytes();
            self.write_shadow(entry_off + 4, &len_le);
            captured += 1;
        }
        if captured > 0 {
            let new_used = device_used_idx.wrapping_add(captured as u16);
            let new_le = new_used.to_le_bytes();
            self.write_shadow(self.tx_queue_device + 2, &new_le);
        }
        captured
    }

    // ---- internal helpers ----

    fn read_avail_idx(&self, base: u64) -> u16 {
        let mut out = [0u8; 2];
        self.read_shadow(base + 2, &mut out);
        u16::from_le_bytes(out)
    }

    fn read_used_idx(&self, base: u64) -> u16 {
        let mut out = [0u8; 2];
        self.read_shadow(base + 2, &mut out);
        u16::from_le_bytes(out)
    }

    fn read_shadow(&self, phys: u64, out: &mut [u8]) {
        let start = phys as usize;
        let end = start.saturating_add(out.len());
        if end > MEM_BUS_BYTES {
            // Out-of-range read — fill with zeros. Tests will catch.
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

impl MmioBus for MemVirtioBus {
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
            ccfg::QUEUE_SIZE => match self.queue_select {
                VIRTIO_NET_QUEUE_RX => self.rx_queue_size,
                VIRTIO_NET_QUEUE_TX => self.tx_queue_size,
                _ => 0,
            },
            ccfg::QUEUE_NOTIFY_OFF => self.queue_select,
            _ => 0,
        }
    }

    fn write_common_u16(&mut self, off: usize, val: u16) {
        match off {
            ccfg::QUEUE_SELECT => self.queue_select = val,
            ccfg::QUEUE_SIZE => match self.queue_select {
                VIRTIO_NET_QUEUE_RX => self.rx_queue_size = val,
                VIRTIO_NET_QUEUE_TX => self.tx_queue_size = val,
                _ => {}
            },
            ccfg::QUEUE_ENABLE => match self.queue_select {
                VIRTIO_NET_QUEUE_RX => self.rx_queue_enable = val,
                VIRTIO_NET_QUEUE_TX => self.tx_queue_enable = val,
                _ => {}
            },
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
        match (off, self.queue_select) {
            (ccfg::QUEUE_DESC, VIRTIO_NET_QUEUE_RX) => self.rx_queue_desc = val,
            (ccfg::QUEUE_DESC, VIRTIO_NET_QUEUE_TX) => self.tx_queue_desc = val,
            (ccfg::QUEUE_DRIVER, VIRTIO_NET_QUEUE_RX) => self.rx_queue_driver = val,
            (ccfg::QUEUE_DRIVER, VIRTIO_NET_QUEUE_TX) => self.tx_queue_driver = val,
            (ccfg::QUEUE_DEVICE, VIRTIO_NET_QUEUE_RX) => self.rx_queue_device = val,
            (ccfg::QUEUE_DEVICE, VIRTIO_NET_QUEUE_TX) => self.tx_queue_device = val,
            _ => {}
        }
    }

    fn read_device_u8(&self, off: usize) -> u8 {
        if off < 6 {
            self.mac[off]
        } else {
            0
        }
    }

    fn read_device_u16(&self, off: usize) -> u16 {
        if off == 6 {
            self.status_word
        } else {
            0
        }
    }

    fn notify_queue(&mut self, queue: u16) {
        match queue {
            VIRTIO_NET_QUEUE_RX => {
                self.rx_notify_count += 1;
            }
            VIRTIO_NET_QUEUE_TX => {
                self.tx_notify_count += 1;
                // Mirror what the device does: drain published frames
                // from the avail ring into observations.
                self.capture_pending_tx();
            }
            _ => {}
        }
    }

    fn dma_write(&mut self, phys: u64, data: &[u8]) {
        self.write_shadow(phys, data);
    }

    fn dma_read(&self, phys: u64, out: &mut [u8]) {
        self.read_shadow(phys, out);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::{virtio_net_feature, virtio_status};

    /// Compile-time guarantee: the locked structs are exactly the
    /// spec-mandated sizes. Re-asserted in the contracts crate; we
    /// also assert here so a deletion of the contracts assertion
    /// surfaces immediately in driver tests.
    #[test]
    fn virtq_desc_is_16_bytes() {
        assert_eq!(core::mem::size_of::<VirtqDesc>(), 16);
    }

    #[test]
    fn virtio_net_hdr_is_12_bytes() {
        assert_eq!(core::mem::size_of::<VirtioNetHdr>(), VIRTIO_NET_HDR_LEN);
    }

    #[test]
    fn desc_roundtrip_preserves_bytes() {
        let d = VirtqDesc {
            addr: 0xDEAD_BEEF_CAFE_F00D,
            len: 0x1234_5678,
            flags: virtq_desc_flags::NEXT | virtq_desc_flags::WRITE,
            next: 0x4242,
        };
        let mut bytes = [0u8; 16];
        encode_desc(&d, &mut bytes);
        let back = decode_desc(&bytes);
        assert_eq!(back, d);
    }

    #[test]
    fn net_hdr_roundtrip_preserves_bytes() {
        let h = VirtioNetHdr {
            flags: 0x11,
            gso_type: 0x22,
            hdr_len: 0x3344,
            gso_size: 0x5566,
            csum_start: 0x7788,
            csum_offset: 0x99AA,
            num_buffers: 0xBBCC,
        };
        let mut bytes = [0u8; VIRTIO_NET_HDR_LEN];
        encode_net_hdr(&h, &mut bytes);
        let back = decode_net_hdr(&bytes);
        assert_eq!(back, h);
    }

    /// The encoded descriptor must place `addr` as the first 8 bytes
    /// in little-endian byte order. A morph that swaps fields breaks
    /// this.
    #[test]
    fn desc_wire_layout_locks_field_offsets() {
        let d = VirtqDesc {
            addr: 0x0102_0304_0506_0708,
            len: 0xAABB_CCDD,
            flags: 0xEEFF,
            next: 0x1122,
        };
        let mut bytes = [0u8; 16];
        encode_desc(&d, &mut bytes);
        // addr bytes (little-endian).
        assert_eq!(&bytes[0..8], &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);
        // len bytes.
        assert_eq!(&bytes[8..12], &[0xDD, 0xCC, 0xBB, 0xAA]);
        // flags bytes.
        assert_eq!(&bytes[12..14], &[0xFF, 0xEE]);
        // next bytes.
        assert_eq!(&bytes[14..16], &[0x22, 0x11]);
    }

    /// The net header's byte layout. Identical structural lock.
    #[test]
    fn net_hdr_wire_layout_locks_field_offsets() {
        let h = VirtioNetHdr {
            flags: 0x01,
            gso_type: 0x02,
            hdr_len: 0x0403,
            gso_size: 0x0605,
            csum_start: 0x0807,
            csum_offset: 0x0A09,
            num_buffers: 0x0C0B,
        };
        let mut bytes = [0u8; VIRTIO_NET_HDR_LEN];
        encode_net_hdr(&h, &mut bytes);
        assert_eq!(
            &bytes,
            &[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C]
        );
    }

    #[test]
    fn init_fresh_driver_succeeds() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        assert!(drv.is_initialised());
        assert_eq!(drv.mac_address(), [0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
        assert!(drv.link_up());
    }

    #[test]
    fn init_writes_status_sequence_in_spec_order() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let log = bus.status_log();
        assert!(log.len() >= 5, "status log too short: {}", log.len());
        assert_eq!(log[0].value, 0);
        assert_eq!(log[1].value, virtio_status::ACK);
        assert_eq!(log[2].value, virtio_status::ACK | virtio_status::DRIVER);
        assert_eq!(
            log[3].value,
            virtio_status::ACK | virtio_status::DRIVER | virtio_status::FEATURES_OK
        );
        assert_eq!(
            log[4].value,
            virtio_status::ACK
                | virtio_status::DRIVER
                | virtio_status::FEATURES_OK
                | virtio_status::DRIVER_OK
        );
    }

    #[test]
    fn init_negotiates_feature_set() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let accepted = bus.driver_features();
        assert!(accepted & virtio_net_feature::VERSION_1 != 0);
        assert!(accepted & virtio_net_feature::MAC != 0);
        assert!(accepted & virtio_net_feature::STATUS != 0);
        assert!(accepted & virtio_net_feature::CSUM != 0);
        // MRG_RXBUF and GUEST_CSUM must NOT be accepted: not in mask.
        assert_eq!(accepted & virtio_net_feature::MRG_RXBUF, 0);
        assert_eq!(accepted & virtio_net_feature::GUEST_CSUM, 0);
        assert_eq!(drv.negotiated_features(), accepted);
    }

    #[test]
    fn init_rejects_legacy_device() {
        let mut bus = MemVirtioBus::new();
        bus.set_device_features(virtio_net_feature::MAC); // no VERSION_1
        let mut drv = VirtioNet::new();
        assert_eq!(
            drv.init(&mut bus).unwrap_err(),
            NetDeviceError::LegacyDeviceUnsupported
        );
        assert!(!drv.is_initialised());
    }

    #[test]
    fn init_rejects_missing_mac() {
        let mut bus = MemVirtioBus::new();
        bus.set_device_features(virtio_net_feature::VERSION_1);
        let mut drv = VirtioNet::new();
        assert_eq!(
            drv.init(&mut bus).unwrap_err(),
            NetDeviceError::MacNotAdvertised
        );
    }

    #[test]
    fn init_rejects_undersized_queue() {
        let mut bus = MemVirtioBus::new();
        bus.set_queue_size(32);
        let mut drv = VirtioNet::new();
        assert_eq!(
            drv.init(&mut bus).unwrap_err(),
            NetDeviceError::QueueTooSmall
        );
    }

    #[test]
    fn init_is_not_idempotent() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("first init");
        assert_eq!(
            drv.init(&mut bus).unwrap_err(),
            NetDeviceError::AlreadyInitialised
        );
    }

    #[test]
    fn init_reads_link_down_when_status_word_clear() {
        let mut bus = MemVirtioBus::new();
        bus.set_status_word(0);
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        assert!(!drv.link_up());
    }

    #[test]
    fn init_with_mac_only_features_keeps_link_up_false() {
        let mut bus = MemVirtioBus::new();
        bus.set_device_features(virtio_net_feature::VERSION_1 | virtio_net_feature::MAC);
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        // STATUS was not negotiated, so link_up stays false even if the
        // bus's status_word is non-zero.
        assert!(!drv.link_up());
    }

    #[test]
    fn transmit_requires_init() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        let result = drv.transmit(&mut bus, &[0x00; 60]);
        assert_eq!(result.unwrap_err(), NetDeviceError::NotInitialised);
    }

    #[test]
    fn transmit_rejects_empty_frame() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        assert_eq!(
            drv.transmit(&mut bus, &[]).unwrap_err(),
            NetDeviceError::FrameEmpty
        );
    }

    #[test]
    fn transmit_rejects_oversized_frame() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let big = [0u8; MAX_FRAME_LEN + 1];
        assert_eq!(
            drv.transmit(&mut bus, &big).unwrap_err(),
            NetDeviceError::FrameTooLarge
        );
    }

    #[test]
    fn transmit_captured_byte_for_byte() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let frame: [u8; 60] = core::array::from_fn(|i| (i * 7 + 3) as u8);
        drv.transmit(&mut bus, &frame).expect("transmit");
        let obs = bus.tx_observations();
        assert_eq!(obs.len(), 1);
        assert_eq!(obs[0].len, 60);
        assert_eq!(&obs[0].bytes[..60], &frame[..]);
    }

    #[test]
    fn transmit_rings_doorbell() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        assert_eq!(bus.tx_notify_count(), 0);
        drv.transmit(&mut bus, &[0xAA; 64]).expect("transmit");
        assert_eq!(bus.tx_notify_count(), 1);
    }

    #[test]
    fn transmit_chain_carries_virtio_hdr_then_payload() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let payload = [0x42u8; 100];
        drv.transmit(&mut bus, &payload).expect("transmit");
        // The shadow at PHYS_TX_BUFFER should hold the 12-byte hdr +
        // payload at PHYS_TX_BUFFER + 64.
        let mut hdr_bytes = [0u8; VIRTIO_NET_HDR_LEN];
        bus.dma_read(PHYS_TX_BUFFER, &mut hdr_bytes);
        let hdr = decode_net_hdr(&hdr_bytes);
        assert_eq!(hdr.num_buffers, 1);
        assert_eq!(hdr.flags, 0);
        assert_eq!(hdr.gso_type, 0);
        let mut payload_back = [0u8; 100];
        bus.dma_read(PHYS_TX_BUFFER + 64, &mut payload_back);
        assert_eq!(payload_back, payload);
    }

    #[test]
    fn transmit_multiple_increments_avail_idx() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        for _ in 0..5 {
            drv.transmit(&mut bus, &[0xCC; 64]).expect("transmit");
        }
        assert_eq!(drv.tx_count(), 5);
        assert_eq!(bus.tx_notify_count(), 5);
        assert_eq!(bus.tx_observations().len(), 5);
    }

    #[test]
    fn receive_returns_empty_when_no_frame_pending() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let mut out = [0u8; MAX_FRAME_LEN];
        assert_eq!(
            drv.receive(&mut bus, &mut out).unwrap_err(),
            NetDeviceError::RxQueueEmpty
        );
    }

    #[test]
    fn receive_rejects_small_buffer() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let mut small = [0u8; 100];
        assert_eq!(
            drv.receive(&mut bus, &mut small).unwrap_err(),
            NetDeviceError::OutputBufferTooSmall
        );
    }

    #[test]
    fn receive_round_trips_a_pending_frame() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let frame: [u8; 80] = core::array::from_fn(|i| (i as u8) ^ 0x5A);
        assert!(bus.enqueue_rx(&frame));
        assert!(bus.deliver_pending_rx());
        let mut out = [0u8; MAX_FRAME_LEN];
        let n = drv.receive(&mut bus, &mut out).expect("receive");
        assert_eq!(n, 80);
        assert_eq!(&out[..80], &frame[..]);
        assert_eq!(drv.rx_count(), 1);
    }

    #[test]
    fn receive_round_trips_multiple_frames() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let f1 = [0x11u8; 60];
        let f2 = [0x22u8; 90];
        let f3 = [0x33u8; 1200];
        assert!(bus.enqueue_rx(&f1));
        assert!(bus.enqueue_rx(&f2));
        assert!(bus.enqueue_rx(&f3));
        assert!(bus.deliver_pending_rx());
        assert!(bus.deliver_pending_rx());
        assert!(bus.deliver_pending_rx());
        let mut out = [0u8; MAX_FRAME_LEN];
        let n1 = drv.receive(&mut bus, &mut out).unwrap();
        assert_eq!(n1, 60);
        assert_eq!(&out[..60], &f1[..]);
        let n2 = drv.receive(&mut bus, &mut out).unwrap();
        assert_eq!(n2, 90);
        assert_eq!(&out[..90], &f2[..]);
        let n3 = drv.receive(&mut bus, &mut out).unwrap();
        assert_eq!(n3, 1200);
        assert_eq!(&out[..1200], &f3[..]);
        assert_eq!(drv.rx_count(), 3);
    }

    #[test]
    fn receive_strips_virtio_hdr_byte_for_byte() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        // Use a frame that starts with a recognisable Ethernet
        // header so we can confirm the 12-byte header was stripped.
        let mut frame = [0u8; 60];
        for i in 0..6 {
            frame[i] = 0xFF; // destination = broadcast
        }
        for i in 6..12 {
            frame[i] = 0x52 + i as u8; // source MAC, non-zero
        }
        frame[12] = 0x08;
        frame[13] = 0x00; // EtherType = IPv4
        for i in 14..60 {
            frame[i] = (i * 3) as u8;
        }
        assert!(bus.enqueue_rx(&frame));
        assert!(bus.deliver_pending_rx());
        let mut out = [0u8; MAX_FRAME_LEN];
        let n = drv.receive(&mut bus, &mut out).expect("receive");
        assert_eq!(n, 60);
        // First 6 bytes still broadcast (would have been the
        // virtio_net_hdr's flags etc. if the header weren't stripped).
        assert_eq!(&out[..6], &[0xFF; 6]);
        assert_eq!(out[12], 0x08);
        assert_eq!(out[13], 0x00);
    }

    #[test]
    fn full_round_trip_transmit_then_receive() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let tx_frame: [u8; 100] = core::array::from_fn(|i| (i as u8).wrapping_mul(13));
        drv.transmit(&mut bus, &tx_frame).expect("tx");
        assert_eq!(bus.tx_observations()[0].len, 100);

        let rx_frame: [u8; 70] = core::array::from_fn(|i| 0xA0 ^ (i as u8));
        bus.enqueue_rx(&rx_frame);
        bus.deliver_pending_rx();
        let mut out = [0u8; MAX_FRAME_LEN];
        let n = drv.receive(&mut bus, &mut out).expect("rx");
        assert_eq!(n, 70);
        assert_eq!(&out[..70], &rx_frame[..]);
    }

    #[test]
    fn read_device_features_returns_64bit_combined() {
        let mut bus = MemVirtioBus::new();
        bus.set_device_features(0xDEAD_BEEF_CAFE_F00D);
        let combined = VirtioNet::read_device_features(&mut bus);
        assert_eq!(combined, 0xDEAD_BEEF_CAFE_F00D);
    }

    #[test]
    fn write_driver_features_splits_into_halves() {
        let mut bus = MemVirtioBus::new();
        VirtioNet::write_driver_features(&mut bus, 0x1122_3344_5566_7788);
        assert_eq!(bus.driver_features(), 0x1122_3344_5566_7788);
    }

    #[test]
    fn rx_descriptor_pair_layout() {
        let (head, tail) = VirtioNet::rx_descriptor_pair(3);
        // Buffer 3 lives at PHYS_RX_BUFFERS + 3 * RX_BUF_SIZE.
        let expected = PHYS_RX_BUFFERS + 3 * (RX_BUF_SIZE as u64);
        assert_eq!(head.addr, expected);
        assert_eq!(head.len as usize, VIRTIO_NET_HDR_LEN);
        assert_eq!(head.flags, virtq_desc_flags::NEXT | virtq_desc_flags::WRITE);
        assert_eq!(head.next, 7); // 2 * 3 + 1
        assert_eq!(tail.addr, expected + 64);
        assert_eq!(tail.len as usize, RX_BUF_SIZE - 64);
        assert_eq!(tail.flags, virtq_desc_flags::WRITE);
        assert_eq!(tail.next, 0);
    }

    #[test]
    fn tx_descriptor_pair_layout() {
        let (head, tail) = VirtioNet::tx_descriptor_pair(60);
        assert_eq!(head.addr, PHYS_TX_BUFFER);
        assert_eq!(head.len as usize, VIRTIO_NET_HDR_LEN);
        assert_eq!(head.flags, virtq_desc_flags::NEXT);
        // TX is NOT device-writable.
        assert_eq!(head.flags & virtq_desc_flags::WRITE, 0);
        assert_eq!(head.next, 1);
        assert_eq!(tail.addr, PHYS_TX_BUFFER + 64);
        assert_eq!(tail.len, 60);
        assert_eq!(tail.flags, 0);
        assert_eq!(tail.next, 0);
    }

    /// After init, the RX ring should have RX_BUFFERS slots populated
    /// and avail.idx should be RX_BUFFERS.
    #[test]
    fn init_pre_posts_rx_buffers() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let avail_idx = bus.read_avail_idx(PHYS_RX_AVAIL);
        assert_eq!(avail_idx as usize, RX_BUFFERS);
        // The RX queue should have been notified once at the end of
        // init (driver tells device "I've posted buffers").
        assert_eq!(bus.rx_notify_count(), 1);
    }

    #[test]
    fn transmit_avail_ring_writes_descriptor_index_zero() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        drv.transmit(&mut bus, &[0u8; 60]).expect("tx");
        let mut head_le = [0u8; 2];
        bus.dma_read(PHYS_TX_AVAIL + 4, &mut head_le);
        assert_eq!(u16::from_le_bytes(head_le), 0);
    }

    /// The driver always reuses TX descriptor 0+1 — confirmed by
    /// reading back the descriptor table after multiple sends.
    #[test]
    fn transmit_reuses_descriptor_slot_zero() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        drv.transmit(&mut bus, &[0xAA; 100]).expect("tx");
        drv.transmit(&mut bus, &[0xBB; 100]).expect("tx");
        let mut bytes = [0u8; 16];
        bus.dma_read(PHYS_TX_DESC, &mut bytes);
        let head = decode_desc(&bytes);
        // Head still points to PHYS_TX_BUFFER (slot 0).
        assert_eq!(head.addr, PHYS_TX_BUFFER);
        assert_eq!(head.next, 1);
    }

    /// Feature negotiation always writes `SEED_REQUIRED_MASK | (offered
    /// & SEED_FEATURE_MASK)` — the device-side observed
    /// `driver_feature` halves must combine to that exact value when
    /// the device offers the full feature set.
    #[test]
    fn driver_feature_writeback_matches_locked_mask() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        let expected = virtio_net_feature::VERSION_1
            | virtio_net_feature::MAC
            | virtio_net_feature::STATUS
            | virtio_net_feature::CSUM;
        assert_eq!(bus.driver_features(), expected);
    }

    #[test]
    fn receive_after_init_then_no_pending_rx_returns_empty() {
        let mut bus = MemVirtioBus::new();
        let mut drv = VirtioNet::new();
        drv.init(&mut bus).expect("init");
        // Deliver_pending_rx with no pending frames is a no-op.
        assert!(!bus.deliver_pending_rx());
        let mut out = [0u8; MAX_FRAME_LEN];
        assert_eq!(
            drv.receive(&mut bus, &mut out).unwrap_err(),
            NetDeviceError::RxQueueEmpty
        );
    }

    #[test]
    fn enqueue_rx_rejects_oversized() {
        let mut bus = MemVirtioBus::new();
        let big = [0u8; MAX_FRAME_LEN + 1];
        assert!(!bus.enqueue_rx(&big));
    }

    #[test]
    fn enqueue_rx_rejects_when_full() {
        let mut bus = MemVirtioBus::new();
        let f = [0u8; 64];
        for _ in 0..PENDING_RX_CAP {
            assert!(bus.enqueue_rx(&f));
        }
        assert!(!bus.enqueue_rx(&f));
    }

    #[test]
    fn driver_starts_uninitialised() {
        let drv = VirtioNet::new();
        assert!(!drv.is_initialised());
        assert_eq!(drv.mac_address(), [0u8; 6]);
        assert_eq!(drv.negotiated_features(), 0);
        assert!(!drv.link_up());
        assert_eq!(drv.tx_count(), 0);
        assert_eq!(drv.rx_count(), 0);
    }

    /// Sanity-check the bus's shadow-memory bounds: writes past the
    /// end silently drop. Helps catch tests that accidentally point a
    /// descriptor outside the 1 MiB shadow.
    #[test]
    fn shadow_writes_past_end_are_dropped() {
        let mut bus = MemVirtioBus::new();
        let big_phys = MEM_BUS_BYTES as u64 + 100;
        bus.dma_write(big_phys, &[0xFF; 4]);
        // No panic; subsequent reads from that range yield zeros.
        let mut out = [0xAAu8; 4];
        bus.dma_read(big_phys, &mut out);
        assert_eq!(out, [0u8; 4]);
    }
}
