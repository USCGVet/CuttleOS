//! VirtIO and network controller driver contracts: MmioBus, NetDevice, BlockDeviceVirtio, VirtioPciCaps, MmioRegBus, and EthernetController.

// ---------------------------------------------------------------------------
// NetDevice / VirtIO 1.0 network-device wire surface (TASK-048)
// ---------------------------------------------------------------------------

/// VirtIO common-cfg `device_status` register bit constants.
///
/// Layout matches the VirtIO 1.0 specification §2.1 (Device Status
/// Field). The driver brings the device up by writing this sequence
/// of values to the 1-byte register at common-cfg offset 0x14:
///
///   `0` (RESET) → `ACK` → `ACK|DRIVER` → `ACK|DRIVER|FEATURES_OK`
///   → `ACK|DRIVER|FEATURES_OK|DRIVER_OK`.
///
/// Reading back `FAILED` after any write means the device rejected
/// the negotiation; reading back the previous value without
/// `FEATURES_OK` after writing it means the device refused our
/// feature set. The driver must abort in either case.
pub mod virtio_status {
    /// Driver acknowledges the device. Set first.
    pub const ACK: u8 = 0x01;
    /// Driver knows how to drive the device.
    pub const DRIVER: u8 = 0x02;
    /// Driver is fully set up and ready to drive. Set last.
    pub const DRIVER_OK: u8 = 0x04;
    /// Driver has accepted the feature set negotiated below.
    pub const FEATURES_OK: u8 = 0x08;
    /// Device failed re-init / signalled fatal error. Driver aborts.
    pub const FAILED: u8 = 0x80;
}

/// VirtIO-net feature-negotiation bit constants (VirtIO 1.0 §5.1.3
/// "Feature bits"). The seed driver negotiates the subset listed in
/// [`virtio_net_feature::SEED_FEATURE_MASK`].
pub mod virtio_net_feature {
    /// `VIRTIO_NET_F_CSUM` — device supports TX checksum offload (bit 0).
    pub const CSUM: u64 = 1 << 0;
    /// `VIRTIO_NET_F_GUEST_CSUM` — driver supports RX checksum offload
    /// (bit 1). Not negotiated by the seed.
    pub const GUEST_CSUM: u64 = 1 << 1;
    /// `VIRTIO_NET_F_MAC` — device provides a MAC address in
    /// device-cfg (bit 5).
    pub const MAC: u64 = 1 << 5;
    /// `VIRTIO_NET_F_STATUS` — device exposes the LINK_UP /
    /// ANNOUNCE bits in the device-cfg `status` word (bit 16).
    pub const STATUS: u64 = 1 << 16;
    /// `VIRTIO_NET_F_MRG_RXBUF` — driver MAY merge receive
    /// buffers (bit 15). Not negotiated by the seed.
    pub const MRG_RXBUF: u64 = 1 << 15;
    /// `VIRTIO_F_VERSION_1` — VirtIO 1.0+ compliance (bit 32).
    /// Mandatory for the seed.
    pub const VERSION_1: u64 = 1 << 32;
    /// The exact feature set the seed driver offers + requires the
    /// device to support. `VERSION_1 | MAC | STATUS | CSUM`. Any
    /// drift here is observable as a different `driver_feature`
    /// dword pair written to common-cfg.
    pub const SEED_FEATURE_MASK: u64 = VERSION_1 | MAC | STATUS | CSUM;
    /// Subset that the seed driver REQUIRES to be advertised by the
    /// device. `VERSION_1 | MAC`. If the device offers less, the
    /// driver aborts.
    pub const SEED_REQUIRED_MASK: u64 = VERSION_1 | MAC;
}

/// VirtIO-net device-cfg `status` word bits (VirtIO 1.0 §5.1.4).
/// Lives at offset 6 of device-cfg; only meaningful when
/// [`virtio_net_feature::STATUS`] was negotiated.
pub mod virtio_net_status {
    /// Link is up.
    pub const LINK_UP: u16 = 1 << 0;
    /// Device wishes to announce itself.
    pub const ANNOUNCE: u16 = 1 << 1;
}

/// VirtIO virtqueue descriptor flags (VirtIO 1.0 §2.6.5).
pub mod virtq_desc_flags {
    /// Buffer continues via `next` to the next descriptor in a chain.
    pub const NEXT: u16 = 1;
    /// Buffer is device-writable (driver→device is the default —
    /// without this bit set, the buffer is device-READABLE).
    pub const WRITE: u16 = 2;
}

/// VirtIO common-cfg field offsets (VirtIO 1.0 §4.1.4.3 Table 4.1).
/// The wire layout of the common-cfg region is locked by the spec.
pub mod virtio_common_cfg {
    /// `device_feature_select` (u32, RW). 0 selects bits 0..31; 1
    /// selects bits 32..63.
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    /// `device_feature` (u32, RO). Reads return the selected 32-bit
    /// slice of the device feature set.
    pub const DEVICE_FEATURE: usize = 0x04;
    /// `driver_feature_select` (u32, RW). Same select semantics as
    /// device_feature_select.
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    /// `driver_feature` (u32, RW). Driver writes the accepted
    /// 32-bit slice here.
    pub const DRIVER_FEATURE: usize = 0x0C;
    /// `device_status` (u8, RW). Bring-up sequence register —
    /// see [`super::virtio_status`].
    pub const DEVICE_STATUS: usize = 0x14;
    /// `queue_select` (u16, RW). Selects the queue subsequent
    /// queue_* accesses refer to.
    pub const QUEUE_SELECT: usize = 0x16;
    /// `queue_size` (u16, RW). Reads return the device-supported
    /// max size; writes set the driver-chosen size (must be a
    /// power of two ≤ the supported max).
    pub const QUEUE_SIZE: usize = 0x18;
    /// `queue_enable` (u16, RW). Driver writes 1 after configuring
    /// queue_desc/driver/device to bring the queue online.
    pub const QUEUE_ENABLE: usize = 0x1C;
    /// `queue_notify_off` (u16, RO). Offset into the notify region
    /// the driver should write to to ring the doorbell. The actual
    /// notify address is `notify_base + queue_notify_off *
    /// notify_off_multiplier`.
    pub const QUEUE_NOTIFY_OFF: usize = 0x1E;
    /// `queue_desc` (u64, RW). Phys-addr of the descriptor table.
    pub const QUEUE_DESC: usize = 0x20;
    /// `queue_driver` (u64, RW). Phys-addr of the avail ring.
    pub const QUEUE_DRIVER: usize = 0x28;
    /// `queue_device` (u64, RW). Phys-addr of the used ring.
    pub const QUEUE_DEVICE: usize = 0x30;
}

/// Sentinel index identifying the VirtIO-net receive queue
/// (VirtIO 1.0 §5.1.2). Always 0 for the single-queue seed.
pub const VIRTIO_NET_QUEUE_RX: u16 = 0;
/// Sentinel index identifying the VirtIO-net transmit queue
/// (VirtIO 1.0 §5.1.2). Always 1 for the single-queue seed.
pub const VIRTIO_NET_QUEUE_TX: u16 = 1;

/// Locked VirtIO descriptor entry. The byte layout is fixed by VirtIO
/// 1.0 §2.6.5 — 16 bytes, little-endian. Every morph cycle's
/// implementation must produce an identical in-memory representation
/// because the device walks the descriptor table by raw byte offset.
///
/// Field order locked: `addr (u64) || len (u32) || flags (u16) || next
/// (u16)`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtqDesc {
    /// Phys-address of the buffer this descriptor covers.
    pub addr: u64,
    /// Buffer length in bytes.
    pub len: u32,
    /// Combination of [`virtq_desc_flags`] bits.
    pub flags: u16,
    /// Index of the next descriptor in the chain. Only meaningful if
    /// `flags & NEXT != 0`.
    pub next: u16,
}

/// Compile-time assertion: VirtqDesc must be exactly 16 bytes.
/// A morph that perturbs the field layout breaks the bus contract.
const _: () = {
    assert!(core::mem::size_of::<VirtqDesc>() == 16);
};

/// Wire length of the VirtIO-net packet header when VIRTIO_F_VERSION_1
/// is negotiated (VirtIO 1.0 §5.1.6): exactly 12 bytes prepended to
/// every transmitted / received Ethernet frame.
pub const VIRTIO_NET_HDR_LEN: usize = 12;

/// Locked VirtIO-net packet header (VirtIO 1.0 §5.1.6 Figure "Network
/// Header"). 12 bytes prepended to every TX / RX frame. Field order
/// and types are locked across morph cycles.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtioNetHdr {
    /// Header flags. `VIRTIO_NET_HDR_F_NEEDS_CSUM=1` instructs the
    /// device to compute the L4 checksum; the seed driver always
    /// emits 0 (no checksum offload).
    pub flags: u8,
    /// GSO type. 0 (`VIRTIO_NET_HDR_GSO_NONE`) for the seed.
    pub gso_type: u8,
    /// Header length (when GSO is in use). 0 for the seed.
    pub hdr_len: u16,
    /// GSO segment size. 0 for the seed.
    pub gso_size: u16,
    /// L4 checksum start offset. 0 for the seed.
    pub csum_start: u16,
    /// L4 checksum offset. 0 for the seed.
    pub csum_offset: u16,
    /// Number of mergeable buffers spanned by this packet. 1 for
    /// every TX frame; on RX, the device sets this when VIRTIO_NET_F_MRG_RXBUF
    /// is negotiated. The seed does not negotiate MRG_RXBUF and
    /// asserts `num_buffers == 1` on every received frame.
    pub num_buffers: u16,
}

/// Compile-time assertion: VirtioNetHdr must be exactly
/// [`VIRTIO_NET_HDR_LEN`] (12) bytes.
const _: () = {
    assert!(core::mem::size_of::<VirtioNetHdr>() == VIRTIO_NET_HDR_LEN);
};

/// Errors surfaced by the [`NetDevice`] contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetDeviceError {
    /// `init` has not been called, or it returned an error.
    NotInitialised,
    /// A second call to `init` was attempted on a device that already
    /// completed bring-up.
    AlreadyInitialised,
    /// `transmit` called with an empty `frame`.
    FrameEmpty,
    /// `transmit` called with `frame.len() > MAX_FRAME_LEN` (1514).
    FrameTooLarge,
    /// `receive` called with `buf.len() < MAX_FRAME_LEN` — the buffer
    /// must be large enough to hold a full Ethernet frame.
    OutputBufferTooSmall,
    /// `receive` called when no frame is pending in the used ring.
    RxQueueEmpty,
    /// The device's reset / status-negotiation handshake did not
    /// converge inside the bounded poll window.
    ResetTimeout,
    /// Device's negotiated queue size is below the seed's required
    /// minimum (64 entries).
    QueueTooSmall,
    /// Device rejected the driver's feature set (read-back of
    /// `device_status` after writing `FEATURES_OK` showed the bit
    /// cleared).
    FeaturesOkRejected,
    /// Device did not advertise `VIRTIO_F_VERSION_1` — the seed only
    /// drives 1.0+ devices.
    LegacyDeviceUnsupported,
    /// Device did not advertise `VIRTIO_NET_F_MAC` — the seed needs
    /// a MAC from device-cfg, not a self-assigned one.
    MacNotAdvertised,
    /// Device set `STATUS_FAILED` during the bring-up handshake.
    DeviceFailed,
    /// The used-ring index walked past the avail-ring index, i.e.
    /// the device returned more completions than we submitted.
    UsedRingOverflow,
    /// A descriptor returned via the used ring carried an index
    /// outside the descriptor table.
    DescriptorIndexOutOfRange,
    /// The received frame's `num_buffers` field was not 1 — the seed
    /// driver does not implement merged RX buffers.
    UnsupportedRxBuffersMerged,
    /// The received frame's total length was less than
    /// [`VIRTIO_NET_HDR_LEN`].
    RxFrameTruncated,
}

/// Abstract VirtIO-MMIO bus. Real hardware implements this with
/// volatile reads/writes against the controller's BAR0 + DMA-coherent
/// shadow memory; the in-memory emulator [`crate`]'s
/// `MemVirtioBus` (in `target_enterprise::virtio_net`) implements it
/// against byte buffers.
///
/// The bus surface is the locked contract between driver and device;
/// the driver state machine is morphable but every byte the driver
/// writes through this trait reaches the device side as the same
/// byte. That is the load-bearing property the verifier exercises.
pub trait MmioBus {
    /// Read a u8 from common-cfg at offset `off`.
    fn read_common_u8(&self, off: usize) -> u8;
    /// Write a u8 to common-cfg at offset `off`.
    fn write_common_u8(&mut self, off: usize, val: u8);
    /// Read a u16 from common-cfg.
    fn read_common_u16(&self, off: usize) -> u16;
    /// Write a u16 to common-cfg.
    fn write_common_u16(&mut self, off: usize, val: u16);
    /// Read a u32 from common-cfg.
    fn read_common_u32(&self, off: usize) -> u32;
    /// Write a u32 to common-cfg.
    fn write_common_u32(&mut self, off: usize, val: u32);
    /// Write a u64 to common-cfg.
    fn write_common_u64(&mut self, off: usize, val: u64);
    /// Read a u8 from device-cfg.
    fn read_device_u8(&self, off: usize) -> u8;
    /// Read a u16 from device-cfg.
    fn read_device_u16(&self, off: usize) -> u16;
    /// Ring the doorbell for `queue` (0 = RX, 1 = TX). Caller has
    /// already published the new avail.idx via DMA. Real hardware
    /// writes the queue index to a fixed offset inside the notify
    /// region; the emulator dequeues the avail ring synchronously.
    fn notify_queue(&mut self, queue: u16);
    /// DMA: copy `data` to the shadow phys-address `phys`. Real
    /// hardware no-op (driver memory is already DMA-coherent).
    fn dma_write(&mut self, phys: u64, data: &[u8]);
    /// DMA: copy `out.len()` bytes from shadow phys `phys` into
    /// `out`. Real hardware no-op.
    fn dma_read(&self, phys: u64, out: &mut [u8]);
}

/// VirtIO-net network device contract.
///
/// Implementations drive a single VirtIO-net device through its
/// [`MmioBus`] surface. The internal state machine (descriptor ring
/// management, feature negotiation, queue indexing) is diversifiable
/// across morph cycles; the wire-observable surface — every byte the
/// driver writes through `MmioBus` — is not.
///
/// # Locked invariants the verifier checks
///
/// 1. After [`init`](NetDevice::init) succeeds, [`mac_address`](NetDevice::mac_address)
///    returns the MAC the device advertised at device-cfg offsets
///    `0..6`. A morph that perturbs the read sequence produces a
///    different MAC and the kernel banner panics.
/// 2. The bring-up sequence writes `device_status` in the exact
///    `0 → ACK → ACK|DRIVER → ACK|DRIVER|FEATURES_OK →
///    ACK|DRIVER|FEATURES_OK|DRIVER_OK` order. The bus's observation
///    log records every status write; a morph that reorders them
///    fails the verifier's status-sequence assertion.
/// 3. Every byte of [`virtio_net_feature::SEED_FEATURE_MASK`] that the
///    device advertised is written back to `driver_feature` (in two
///    32-bit halves keyed by `driver_feature_select`).
/// 4. For every accepted [`transmit`](NetDevice::transmit) call with
///    `frame ∈ [1, MAX_FRAME_LEN]`, the driver publishes a 2-
///    descriptor chain on the TX queue (header descriptor at index
///    2 * idx, payload descriptor at 2 * idx + 1, NEXT-chained), and
///    the 12-byte [`VirtioNetHdr`] is byte-identical to a header with
///    `num_buffers == 1` and all other fields zero.
/// 5. For every [`receive`](NetDevice::receive) call, the driver
///    consumes from the head of the RX used ring, strips the 12-byte
///    `VirtioNetHdr`, and writes only the Ethernet payload into the
///    caller's buffer. The total byte count returned equals
///    `used.len - VIRTIO_NET_HDR_LEN`.
/// 6. `init` is idempotent — a second call returns
///    [`NetDeviceError::AlreadyInitialised`] without touching the
///    bus.
///
/// # Not in this contract (intentional)
///
/// - Interrupts / MSI-X. The seed is polled.
/// - Merged RX buffers (VIRTIO_NET_F_MRG_RXBUF).
/// - GSO / TSO / UFO / checksum offload paths beyond the FEATURE_CSUM
///   bit being negotiated (the seed driver never sets
///   `flags & NEEDS_CSUM`).
/// - Multi-queue. Single RX + single TX is the seed.
/// - PCI enumeration. The bus is constructed by the caller
///   (kernel: from a probed PCI BAR; tests: in-memory).
pub trait NetDevice {
    /// Drive the device through reset → ACK → DRIVER → feature
    /// negotiation → queue setup → DRIVER_OK. Returns
    /// [`NetDeviceError::AlreadyInitialised`] on second call without
    /// touching the bus.
    fn init(&mut self, bus: &mut dyn MmioBus) -> Result<(), NetDeviceError>;

    /// Transmit one Ethernet frame. The driver prepends a 12-byte
    /// [`VirtioNetHdr`]; `frame` must NOT include the virtio_net_hdr.
    /// Does not block on completion — returns once the descriptor
    /// chain is published + the TX doorbell rung.
    fn transmit(
        &mut self,
        bus: &mut dyn MmioBus,
        frame: &[u8],
    ) -> Result<(), NetDeviceError>;

    /// Receive one Ethernet frame into `out`. Returns the number of
    /// payload bytes written (≥ 0). The 12-byte VirtIO-net header is
    /// stripped before write. Returns
    /// [`NetDeviceError::RxQueueEmpty`] if no frame is pending; the
    /// caller should retry after a future RX completion.
    fn receive(
        &mut self,
        bus: &mut dyn MmioBus,
        out: &mut [u8],
    ) -> Result<usize, NetDeviceError>;

    /// MAC address of the device, as read from device-cfg during
    /// [`init`](Self::init). Returns `[0; 6]` if `init` has not been
    /// called.
    fn mac_address(&self) -> [u8; 6];
}

// ============================================================
// VirtIO-blk block device contract (TASK-061)
// ============================================================

/// Index of the (single) VirtIO-blk request virtqueue (VirtIO 1.0
/// §5.2.2). Locked across morph cycles.
pub const VIRTIO_BLK_QUEUE_REQUESTQ: u16 = 0;

/// Wire length of the VirtIO-blk request header (VirtIO 1.0 §5.2.6):
/// `type (u32) || reserved (u32) || sector (u64)` = 16 bytes,
/// little-endian. Locked across morph cycles — the device walks the
/// descriptor chain by raw byte offsets, so any drift here breaks
/// the contract.
pub const VIRTIO_BLK_HDR_LEN: usize = 16;

/// Wire length of every VirtIO-blk data sector (VirtIO 1.0 §5.2.5).
/// The device always uses 512-byte logical blocks for the request
/// queue regardless of the BLK_SIZE-advertised "preferred" block
/// size — the BLK_SIZE feature only changes the partition-layout
/// arithmetic, not the on-wire sector size.
pub const VIRTIO_BLK_SECTOR_SIZE: usize = 512;

/// Wire length of the device-written status byte at the tail of every
/// request chain (VirtIO 1.0 §5.2.6). Always exactly 1 byte.
pub const VIRTIO_BLK_STATUS_LEN: usize = 1;

/// VirtIO-blk feature-negotiation bit constants (VirtIO 1.0 §5.2.3
/// "Feature bits"). The seed driver negotiates the subset listed in
/// [`virtio_blk_feature::SEED_FEATURE_MASK`].
pub mod virtio_blk_feature {
    /// `VIRTIO_BLK_F_SIZE_MAX` — `size_max` field in device-cfg gives
    /// the maximum segment size the device will accept (bit 1).
    pub const SIZE_MAX: u64 = 1 << 1;
    /// `VIRTIO_BLK_F_SEG_MAX` — `seg_max` field in device-cfg gives
    /// the maximum number of segments per request (bit 2).
    pub const SEG_MAX: u64 = 1 << 2;
    /// `VIRTIO_BLK_F_GEOMETRY` — device-cfg exposes legacy CHS
    /// geometry triple (bit 4).
    pub const GEOMETRY: u64 = 1 << 4;
    /// `VIRTIO_BLK_F_RO` — device is read-only (bit 5).
    pub const RO: u64 = 1 << 5;
    /// `VIRTIO_BLK_F_BLK_SIZE` — device-cfg exposes a preferred
    /// logical block size for partition arithmetic (bit 6).
    pub const BLK_SIZE: u64 = 1 << 6;
    /// `VIRTIO_BLK_F_FLUSH` — device supports the FLUSH command
    /// (bit 9).
    pub const FLUSH: u64 = 1 << 9;
    /// `VIRTIO_BLK_F_TOPOLOGY` — device-cfg exposes 4 alignment /
    /// pref-IO-size bytes (bit 10).
    pub const TOPOLOGY: u64 = 1 << 10;
    /// `VIRTIO_BLK_F_CONFIG_WCE` — writeback-cache enable bit is
    /// driver-controllable via device-cfg (bit 11).
    pub const CONFIG_WCE: u64 = 1 << 11;
    /// `VIRTIO_BLK_F_MQ` — device supports multiple request queues
    /// (bit 12). Seed driver is single-queue only and never
    /// negotiates this.
    pub const MQ: u64 = 1 << 12;
    /// `VIRTIO_BLK_F_DISCARD` — device supports the DISCARD command
    /// (bit 13).
    pub const DISCARD: u64 = 1 << 13;
    /// `VIRTIO_BLK_F_WRITE_ZEROES` — device supports the
    /// WRITE_ZEROES command (bit 14).
    pub const WRITE_ZEROES: u64 = 1 << 14;
    /// `VIRTIO_F_VERSION_1` — VirtIO 1.0+ compliance (bit 32).
    /// Mandatory for the seed. Mirrors [`super::virtio_net_feature::VERSION_1`].
    pub const VERSION_1: u64 = 1 << 32;
    /// The exact feature set the seed driver offers + accepts when
    /// the device advertises it. `VERSION_1 | FLUSH | BLK_SIZE`.
    /// Every byte of this mask reaches the device side via two
    /// 32-bit `driver_feature` halves; the verifier asserts every
    /// byte arrives unaltered.
    pub const SEED_FEATURE_MASK: u64 = VERSION_1 | FLUSH | BLK_SIZE;
    /// Subset that the seed driver REQUIRES to be advertised by the
    /// device. `VERSION_1` alone — the seed will fall back to the
    /// 512-byte default if BLK_SIZE / FLUSH are absent, but it
    /// refuses to drive a legacy (sub-1.0) device.
    pub const SEED_REQUIRED_MASK: u64 = VERSION_1;
}

/// VirtIO-blk request-type byte at offset 0 of every request header
/// (VirtIO 1.0 §5.2.6 Table 5.7).
pub mod virtio_blk_req_type {
    /// `VIRTIO_BLK_T_IN` — read sectors from the device into
    /// driver-supplied buffers. The data descriptor is device-WRITABLE.
    pub const IN: u32 = 0;
    /// `VIRTIO_BLK_T_OUT` — write sectors from driver-supplied
    /// buffers to the device. The data descriptor is device-READABLE.
    pub const OUT: u32 = 1;
    /// `VIRTIO_BLK_T_FLUSH` — request the device flush its
    /// writeback cache to durable media. No data descriptor; only
    /// the header + status. Requires
    /// [`super::virtio_blk_feature::FLUSH`].
    pub const FLUSH: u32 = 4;
    /// `VIRTIO_BLK_T_GET_ID` — request the device's 20-byte ASCII
    /// serial identifier (data descriptor is device-WRITABLE, 20
    /// bytes long).
    pub const GET_ID: u32 = 8;
    /// `VIRTIO_BLK_T_DISCARD` — request the device discard a range
    /// of sectors. Requires
    /// [`super::virtio_blk_feature::DISCARD`].
    pub const DISCARD: u32 = 11;
    /// `VIRTIO_BLK_T_WRITE_ZEROES` — request the device write zeros
    /// to a range of sectors without driver-supplied data. Requires
    /// [`super::virtio_blk_feature::WRITE_ZEROES`].
    pub const WRITE_ZEROES: u32 = 13;
}

/// VirtIO-blk status-byte values written by the device into the tail
/// descriptor on every request completion (VirtIO 1.0 §5.2.6).
pub mod virtio_blk_status_byte {
    /// `VIRTIO_BLK_S_OK` — request completed successfully.
    pub const OK: u8 = 0;
    /// `VIRTIO_BLK_S_IOERR` — device-side I/O error (media failure
    /// or unrecoverable hardware fault).
    pub const IOERR: u8 = 1;
    /// `VIRTIO_BLK_S_UNSUPP` — device does not support the request
    /// type (e.g. FLUSH without FEATURE_FLUSH negotiated).
    pub const UNSUPP: u8 = 2;
    /// Sentinel value the driver writes to the status byte before
    /// publishing a request. The device overwrites it with one of
    /// [`OK`] / [`IOERR`] / [`UNSUPP`] on completion; a still-0xFF
    /// status at completion time means the device never touched
    /// the tail descriptor (driver bug or device misbehaviour).
    /// Locked because the seed driver's "did the device respond"
    /// check compares against this exact byte.
    pub const SENTINEL: u8 = 0xFF;
}

/// VirtIO-blk device-cfg byte offsets (VirtIO 1.0 §5.2.4 Table 5.6).
/// The device-cfg region is the only piece of state where virtio-blk
/// and virtio-net differ on the wire — the common-cfg + virtqueue
/// surfaces are identical and reused from
/// [`virtio_common_cfg`].
pub mod virtio_blk_device_cfg {
    /// `capacity` (u64). Total disk size in 512-byte sectors. Always
    /// present (no feature gate); reads as 0 on an empty backing
    /// store. Read by [`super::BlockDeviceVirtio::init`] to populate
    /// [`super::BlockDeviceVirtio::capacity_sectors`].
    pub const CAPACITY: usize = 0x00;
    /// `size_max` (u32). Maximum segment size in bytes. Only valid
    /// when `VIRTIO_BLK_F_SIZE_MAX` is negotiated.
    pub const SIZE_MAX: usize = 0x08;
    /// `seg_max` (u32). Maximum number of segments per request.
    /// Only valid when `VIRTIO_BLK_F_SEG_MAX` is negotiated.
    pub const SEG_MAX: usize = 0x0C;
    /// `geometry.cylinders` (u16). Legacy CHS geometry. Only valid
    /// when `VIRTIO_BLK_F_GEOMETRY` is negotiated.
    pub const GEOMETRY_CYLINDERS: usize = 0x10;
    /// `geometry.heads` (u8).
    pub const GEOMETRY_HEADS: usize = 0x12;
    /// `geometry.sectors` (u8).
    pub const GEOMETRY_SECTORS: usize = 0x13;
    /// `blk_size` (u32). Preferred logical block size for partition
    /// arithmetic — does NOT change the 512-byte on-wire sector
    /// size used by the request queue. Only valid when
    /// `VIRTIO_BLK_F_BLK_SIZE` is negotiated.
    pub const BLK_SIZE: usize = 0x14;
}

/// Locked VirtIO-blk request header (VirtIO 1.0 §5.2.6). Sixteen
/// bytes, little-endian. Field order locked across morph cycles —
/// the device walks the header by raw byte offset.
///
/// Layout: `type (u32 LE) || reserved (u32 LE) || sector (u64 LE)`.
/// `reserved` MUST be written as 0; the device returns
/// `VIRTIO_BLK_S_IOERR` if non-zero (and even tolerant devices
/// preserve the byte, so a morph that perturbs the reserved field
/// is observable).
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct VirtBlkRequest {
    /// One of [`virtio_blk_req_type`] (IN / OUT / FLUSH / GET_ID /
    /// DISCARD / WRITE_ZEROES).
    pub req_type: u32,
    /// Reserved word; the seed driver writes 0 unconditionally.
    pub reserved: u32,
    /// Starting LBA (512-byte sectors). For FLUSH / GET_ID the
    /// field is unused but the seed driver still writes 0.
    pub sector: u64,
}

/// Compile-time assertion: VirtBlkRequest must be exactly
/// [`VIRTIO_BLK_HDR_LEN`] bytes. A morph that perturbs the field
/// layout breaks the bus contract.
const _: () = {
    assert!(core::mem::size_of::<VirtBlkRequest>() == VIRTIO_BLK_HDR_LEN);
};

/// Errors surfaced by the [`BlockDeviceVirtio`] contract.
///
/// Locked discriminant set: external code (and the verifier) may
/// pattern-match on variant names; appending a variant is schema-
/// compatible, removing or reordering one is a schema break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtBlkError {
    /// `init` has not been called, or it returned an error.
    NotInitialised,
    /// A second call to `init` was attempted on a device that
    /// already completed bring-up.
    AlreadyInitialised,
    /// The device's reset / status-negotiation handshake did not
    /// converge inside the bounded poll window.
    ResetTimeout,
    /// Device's negotiated queue size is below the seed's required
    /// minimum.
    QueueTooSmall,
    /// Device rejected the driver's feature set (read-back of
    /// `device_status` after writing `FEATURES_OK` showed the bit
    /// cleared).
    FeaturesOkRejected,
    /// Device did not advertise `VIRTIO_F_VERSION_1` — the seed
    /// only drives 1.0+ devices.
    LegacyDeviceUnsupported,
    /// Device set `STATUS_FAILED` during the bring-up handshake.
    DeviceFailed,
    /// `read_block` / `write_block` called with `sector >=
    /// capacity_sectors()`.
    SectorOutOfRange,
    /// `read_block` / `write_block` called with a buffer whose
    /// length is not exactly [`VIRTIO_BLK_SECTOR_SIZE`].
    BufferSizeMismatch,
    /// `write_block` called on a device that advertised
    /// [`virtio_blk_feature::RO`].
    DeviceReadOnly,
    /// The used-ring index walked past the avail-ring index, i.e.
    /// the device returned more completions than the driver
    /// submitted.
    UsedRingOverflow,
    /// A descriptor returned via the used ring carried an index
    /// outside the descriptor table.
    DescriptorIndexOutOfRange,
    /// The status byte the device wrote into the tail descriptor
    /// was [`virtio_blk_status_byte::IOERR`] (1).
    DeviceIoError,
    /// The status byte the device wrote into the tail descriptor
    /// was [`virtio_blk_status_byte::UNSUPP`] (2).
    RequestUnsupported,
    /// The completion's status byte was still
    /// [`virtio_blk_status_byte::SENTINEL`] (0xFF) — the device
    /// never overwrote it. Either the device dropped the request
    /// or the descriptor chain's tail pointer is wrong.
    StatusByteUntouched,
    /// The bounded poll for completion exhausted its budget without
    /// observing the new used-ring index.
    CompletionTimeout,
    /// FLUSH requested but `VIRTIO_BLK_F_FLUSH` was not negotiated.
    FlushUnsupported,
}

/// VirtIO-blk block-device contract.
///
/// Implementations drive a single VirtIO-blk device through its
/// [`MmioBus`] surface. The internal state machine (descriptor ring
/// management, feature negotiation, queue indexing, request
/// scheduling) is diversifiable across morph cycles; the wire-
/// observable surface — every byte the driver writes through
/// `MmioBus` — is not.
///
/// # Locked invariants the verifier checks
///
/// 1. After [`init`](BlockDeviceVirtio::init) succeeds,
///    [`capacity_sectors`](BlockDeviceVirtio::capacity_sectors)
///    returns the value the device advertised at device-cfg offsets
///    `0..8` (`capacity` field, little-endian u64). A morph that
///    perturbs the read order produces a different capacity and the
///    kernel banner panics.
/// 2. The bring-up sequence writes `device_status` in the exact
///    `0 → ACK → ACK|DRIVER → ACK|DRIVER|FEATURES_OK →
///    ACK|DRIVER|FEATURES_OK|DRIVER_OK` order. The bus's
///    observation log records every status write; a morph that
///    reorders them fails the verifier's status-sequence assertion.
/// 3. Every byte of the accepted feature mask (a subset of
///    [`virtio_blk_feature::SEED_FEATURE_MASK`]) is written back to
///    `driver_feature` in two 32-bit halves keyed by
///    `driver_feature_select`.
/// 4. For every accepted [`read_block`](BlockDeviceVirtio::read_block)
///    call, the driver publishes a 3-descriptor chain on the request
///    queue: header descriptor (device-READABLE, 16 bytes), data
///    descriptor (device-WRITABLE, 512 bytes), status descriptor
///    (device-WRITABLE, 1 byte). The 16-byte header is byte-
///    identical to [`VirtBlkRequest::IN`-encoded] with `reserved = 0`.
/// 5. For every accepted [`write_block`](BlockDeviceVirtio::write_block)
///    call, the driver publishes the same 3-descriptor chain shape
///    but the data descriptor is device-READABLE (no `WRITE` flag).
/// 6. `init` is idempotent — a second call returns
///    [`VirtBlkError::AlreadyInitialised`] without touching the
///    bus.
///
/// # Not in this contract (intentional)
///
/// - Interrupts / MSI-X. The seed is polled.
/// - Multi-queue (VIRTIO_BLK_F_MQ).
/// - DISCARD / WRITE_ZEROES / GET_ID. Future port.
/// - Asynchronous queueing / batching of requests. One in-flight
///   at a time; the driver serialises through internal state.
/// - PCI enumeration. The bus is constructed by the caller
///   (kernel: from a probed PCI BAR; tests: in-memory).
pub trait BlockDeviceVirtio {
    /// Drive the device through reset → ACK → DRIVER → feature
    /// negotiation → queue setup → DRIVER_OK. Reads the disk
    /// capacity from device-cfg. Returns
    /// [`VirtBlkError::AlreadyInitialised`] on second call without
    /// touching the bus.
    fn init(&mut self, bus: &mut dyn MmioBus) -> Result<(), VirtBlkError>;

    /// Read one 512-byte sector from `sector` into `out`.
    /// `out.len()` MUST equal [`VIRTIO_BLK_SECTOR_SIZE`].
    /// Synchronous: builds the 3-descriptor chain, publishes it,
    /// notifies the queue, polls the used ring for completion.
    fn read_block(
        &mut self,
        bus: &mut dyn MmioBus,
        sector: u64,
        out: &mut [u8],
    ) -> Result<(), VirtBlkError>;

    /// Write one 512-byte sector to `sector` from `data`.
    /// `data.len()` MUST equal [`VIRTIO_BLK_SECTOR_SIZE`].
    /// Synchronous: same shape as [`read_block`](Self::read_block)
    /// but the data descriptor is device-READABLE.
    fn write_block(
        &mut self,
        bus: &mut dyn MmioBus,
        sector: u64,
        data: &[u8],
    ) -> Result<(), VirtBlkError>;

    /// Disk capacity in 512-byte sectors, as read from device-cfg
    /// during [`init`](Self::init). Returns 0 if `init` has not
    /// been called.
    fn capacity_sectors(&self) -> u64;
}
// ============================================================
// TASK-056 — Intel 8254x (e1000) NIC driver surface.
//
// The contract has two locked surfaces:
//
// 1. `MmioRegBus` — a register-window abstraction (volatile u32
//    read/write at a byte offset within the BAR). Real hardware
//    implements it with `core::ptr::read_volatile` / `write_volatile`
//    against the BAR's MMIO mapping; the in-memory harness in
//    `target_enterprise::e1000` implements it against a 128 KiB shadow
//    buffer plus an EEPROM fixture state machine + descriptor-ring
//    capture/inject for round-trip tests.
//
// 2. `EthernetController` — the driver-side state machine that drives
//    the register window through the Intel 82540EM bring-up sequence,
//    reads the MAC from EEPROM words 0..2, configures descriptor
//    rings, and exposes transmit/receive over locked 16-byte
//    descriptor formats (`E1000_TX_DESC_LEN` / `E1000_RX_DESC_LEN`).
//
// Constants below (register offsets, bit flags, EEPROM layout) are
// the wire-locked surface; a morph that perturbs them changes which
// MMIO bytes the driver writes and the in-memory harness records the
// drift on the very first round-trip.
// ============================================================

/// Intel 82540EM CTRL register offset (byte 0x0).
pub const E1000_REG_CTRL: usize = 0x0000;
/// Intel 82540EM STATUS register offset (byte 0x8).
pub const E1000_REG_STATUS: usize = 0x0008;
/// EEPROM Read register (EERD) offset.
pub const E1000_REG_EERD: usize = 0x0014;
/// Interrupt Cause Read offset.
pub const E1000_REG_ICR: usize = 0x00C0;
/// Interrupt Mask Set/Read offset.
pub const E1000_REG_IMS: usize = 0x00D0;
/// Interrupt Mask Clear offset (write 1s to mask).
pub const E1000_REG_IMC: usize = 0x00D8;
/// Receive Control register offset.
pub const E1000_REG_RCTL: usize = 0x0100;
/// Transmit Control register offset.
pub const E1000_REG_TCTL: usize = 0x0400;
/// Transmit Inter-Packet Gap register offset.
pub const E1000_REG_TIPG: usize = 0x0410;
/// RX descriptor ring base address low.
pub const E1000_REG_RDBAL: usize = 0x2800;
/// RX descriptor ring base address high.
pub const E1000_REG_RDBAH: usize = 0x2804;
/// RX descriptor ring byte length.
pub const E1000_REG_RDLEN: usize = 0x2808;
/// RX descriptor ring HEAD index (owned by device).
pub const E1000_REG_RDH: usize = 0x2810;
/// RX descriptor ring TAIL index (owned by driver).
pub const E1000_REG_RDT: usize = 0x2818;
/// TX descriptor ring base address low.
pub const E1000_REG_TDBAL: usize = 0x3800;
/// TX descriptor ring base address high.
pub const E1000_REG_TDBAH: usize = 0x3804;
/// TX descriptor ring byte length.
pub const E1000_REG_TDLEN: usize = 0x3808;
/// TX descriptor ring HEAD index (owned by device).
pub const E1000_REG_TDH: usize = 0x3810;
/// TX descriptor ring TAIL index (owned by driver).
pub const E1000_REG_TDT: usize = 0x3818;

/// CTRL.RST — global software reset bit. Writing 1 forces every
/// register but a small set of "sticky" bits back to defaults; the
/// device clears the bit when reset completes (≤ 1 µs per spec).
pub const E1000_CTRL_RST: u32 = 1 << 26;
/// CTRL.SLU — Set Link Up. Drives the PHY through auto-negotiation.
pub const E1000_CTRL_SLU: u32 = 1 << 6;
/// STATUS.LU — Link Up. Set by the PHY once the line is established.
pub const E1000_STATUS_LU: u32 = 1 << 1;
/// STATUS.FD — Full Duplex.
pub const E1000_STATUS_FD: u32 = 1 << 0;
/// STATUS.SPEED bits 6..7 — `00 = 10`, `01 = 100`, `10/11 = 1000`.
pub const E1000_STATUS_SPEED_SHIFT: u32 = 6;
/// Mask covering the two-bit SPEED field.
pub const E1000_STATUS_SPEED_MASK: u32 = 0b11;

/// EERD.START — write 1 to begin a single-word EEPROM read.
pub const E1000_EERD_START: u32 = 1 << 0;
/// EERD.DONE — set by the device when DATA is valid for read. The
/// 82540EM places DONE at bit 4 (later silicon families use bit 1;
/// this driver targets 82540EM specifically — QEMU's default).
pub const E1000_EERD_DONE: u32 = 1 << 4;
/// EERD address field starts at bit 8 (8 bits wide on 82540EM).
pub const E1000_EERD_ADDR_SHIFT: u32 = 8;
/// EERD address field mask (8-bit).
pub const E1000_EERD_ADDR_MASK: u32 = 0xFF;
/// EERD data field starts at bit 16 (16 bits wide).
pub const E1000_EERD_DATA_SHIFT: u32 = 16;
/// EERD data field mask (16-bit).
pub const E1000_EERD_DATA_MASK: u32 = 0xFFFF;
/// EEPROM word index holding the low 16 bits of the MAC address
/// (bytes 0..2 of the burned-in MAC).
pub const E1000_EEPROM_MAC_WORD0: u8 = 0x00;
/// EEPROM word holding the middle 16 bits of the MAC (bytes 2..4).
pub const E1000_EEPROM_MAC_WORD1: u8 = 0x01;
/// EEPROM word holding the high 16 bits of the MAC (bytes 4..6).
pub const E1000_EEPROM_MAC_WORD2: u8 = 0x02;

/// RCTL.EN — Receiver Enable.
pub const E1000_RCTL_EN: u32 = 1 << 1;
/// RCTL.BAM — Broadcast Accept Mode.
pub const E1000_RCTL_BAM: u32 = 1 << 15;
/// RCTL.SECRC — Strip Ethernet CRC.
pub const E1000_RCTL_SECRC: u32 = 1 << 26;
/// TCTL.EN — Transmitter Enable.
pub const E1000_TCTL_EN: u32 = 1 << 1;
/// TCTL.PSP — Pad Short Packets to 64 bytes.
pub const E1000_TCTL_PSP: u32 = 1 << 3;

/// Legacy TX descriptor CMD.EOP — End Of Packet (single-descriptor frame).
pub const E1000_TXD_CMD_EOP: u8 = 1 << 0;
/// Legacy TX descriptor CMD.IFCS — Insert FCS (let device compute Ethernet CRC).
pub const E1000_TXD_CMD_IFCS: u8 = 1 << 1;
/// Legacy TX descriptor CMD.RS — Report Status (device writes DD back on completion).
pub const E1000_TXD_CMD_RS: u8 = 1 << 3;
/// Legacy descriptor STATUS.DD — Descriptor Done.
pub const E1000_DESC_STA_DD: u8 = 1 << 0;
/// Legacy RX descriptor STATUS.EOP — End Of Packet.
pub const E1000_RXD_STA_EOP: u8 = 1 << 1;

/// Legacy TX descriptor byte length (16 bytes per Intel 8254x spec).
pub const E1000_TX_DESC_LEN: usize = 16;
/// Legacy RX descriptor byte length (16 bytes per Intel 8254x spec).
pub const E1000_RX_DESC_LEN: usize = 16;
/// Number of TX descriptors in the ring. Constrained to a power of 2
/// (Intel spec: ring length must be a multiple of 8 and at least 8
/// entries). Drives `E1000_REG_TDLEN` programming and the wrap-around
/// modulus in `transmit`.
pub const E1000_TX_RING_LEN: usize = 16;
/// Number of RX descriptors in the ring (same constraints as TX).
pub const E1000_RX_RING_LEN: usize = 16;
/// Maximum Ethernet frame the driver will accept on a single
/// descriptor — matches the legacy MTU + Ethernet header (no jumbo,
/// no VLAN tag). Aligns with [`EthFrameView::MAX_PAYLOAD_LEN`] plus
/// the 14-byte L2 header.
pub const E1000_MAX_FRAME_LEN: usize = 1518;

/// Decoded link state, returned by [`EthernetController::link_state`].
/// Cached during [`EthernetController::init`] from the STATUS register
/// — the driver does not re-poll on every `link_state` call (a future
/// task may add a `poll_link` method for proactive PHY refresh).
///
/// Locked discriminant order: pattern-matchable by name; appending a
/// variant is schema-compatible, reordering is not.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum LinkState {
    /// Link is down. `STATUS.LU` was clear after reset.
    Down = 0,
    /// Link came up at 10 Mbit/s (`STATUS.SPEED = 0b00`).
    Up10 = 1,
    /// Link came up at 100 Mbit/s (`STATUS.SPEED = 0b01`).
    Up100 = 2,
    /// Link came up at 1 Gbit/s (`STATUS.SPEED = 0b10` or `0b11`).
    Up1000 = 3,
}

/// Error discriminants surfaced from [`EthernetController`].
///
/// Locked: external code matches by variant name; appending is
/// schema-compatible.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
#[repr(u8)]
pub enum E1000Error {
    /// The link came up after reset but `STATUS.LU` is clear at the
    /// time of a transmit/receive call. Caller should retry after a
    /// future link-state poll.
    NoLink = 0,
    /// The TX descriptor ring is full — every slot still has STATUS.DD
    /// clear (i.e. the device hasn't drained them). Caller should
    /// retry once the device advances its head pointer.
    RingFull = 1,
    /// The EEPROM read state-machine completed but the recovered MAC
    /// is structurally invalid (all-zero, all-0xFF, or the multicast
    /// bit is set in the first octet — burned-in MACs are unicast).
    BadEeprom = 2,
    /// A descriptor field had an invalid value: address misaligned,
    /// length exceeds the buffer, or required bits were unset by the
    /// device on RX (no STATUS.EOP after STATUS.DD).
    BadDescriptor = 3,
    /// An MMIO read returned a sentinel pattern signalling the BAR
    /// has been unmapped or the device fell off the bus. The host
    /// reads `0xFFFF_FFFF` from a vanished PCI device.
    MmioFault = 4,
    /// The EEPROM read timed out — the DONE bit never came up within
    /// the bounded poll budget. Real hardware should set DONE within a
    /// microsecond; a timeout means a malformed device or test stub.
    MacReadFailed = 5,
    /// The provided RX frame buffer is shorter than the received
    /// frame. Caller should retry with a buffer of at least the
    /// returned length.
    BufferTooSmall = 6,
    /// The frame passed to `transmit` exceeds [`E1000_MAX_FRAME_LEN`]
    /// or is empty.
    FrameLengthInvalid = 7,
    /// Receive ring is empty — head == tail with no STATUS.DD set on
    /// the slot at `tail`. Caller polls again later.
    NoFramePending = 8,
}

/// Abstract MMIO register window for a memory-mapped device. Real
/// hardware implements it with volatile reads/writes against the BAR's
/// kernel virtual mapping; in-memory harnesses implement it against a
/// shadow byte buffer plus a per-device side-channel (e.g. an EEPROM
/// fixture, a TX-frame capture log).
///
/// Distinct from [`MmioBus`] (VirtIO common-cfg / device-cfg / notify
/// / DMA): that trait is virtio-specific by design, whereas
/// `MmioRegBus` is the bare 32-bit register window used by classical
/// MMIO devices like the Intel 82540EM.
///
/// # Locked invariants
///
/// 1. `read_u32(off)` returns the most recent value written to `off`
///    by either the driver (via `write_u32`) OR the device-side
///    simulator (via its own `poke_u32` / equivalent back door). The
///    bus does not coalesce writes nor silently drop reads.
/// 2. Reads from un-modeled offsets return `0` (not `0xFFFF_FFFF` —
///    the latter is reserved for the [`E1000Error::MmioFault`] sentinel).
/// 3. `write_u32(off, val)` overwrites the 4 bytes at `off`
///    starting at the lowest. Side effects (descriptor-ring drain on
///    TDT writes, EEPROM state-machine on EERD writes) are kept on
///    the device-simulator side, not in the bus trait.
pub trait MmioRegBus {
    /// Volatile 32-bit read at `offset` bytes from the BAR base.
    fn read_u32(&mut self, offset: usize) -> u32;
    /// Volatile 32-bit write at `offset` bytes from the BAR base.
    fn write_u32(&mut self, offset: usize, value: u32);
}

/// Intel 82540EM (e1000) NIC driver surface — TASK-056.
///
/// Implementations drive a single 8254x-family device through its
/// [`MmioRegBus`] surface. The internal state machine (descriptor
/// indexing, EEPROM polling, link-state caching) is fully
/// diversifiable across morph cycles; the wire-observable surface —
/// every byte the driver writes through `MmioRegBus`, every 16-byte
/// descriptor it lays down, the EEPROM word offsets it polls — is
/// not.
///
/// # Locked invariants the verifier checks
///
/// 1. [`init`](EthernetController::init) writes `CTRL.RST = 1` then
///    polls until `CTRL.RST == 0`, then writes `CTRL.SLU = 1` to
///    bring the link up. The harness records the precise sequence.
/// 2. The MAC address `init` returns matches the EEPROM bytes at
///    words 0/1/2 in little-endian order (`mac[0..2] = word0_le`,
///    `mac[2..4] = word1_le`, `mac[4..6] = word2_le`). A morph that
///    swaps the byte order or word indices produces a different MAC
///    and the kernel banner panics.
/// 3. After `init`, the device's `RDBAL/RDBAH/RDLEN` registers point
///    at the driver-supplied RX descriptor ring, `TDBAL/TDBAH/TDLEN`
///    at the TX ring, and `RCTL.EN` + `TCTL.EN` are both set.
/// 4. `transmit(frame)` for `frame ∈ [1, E1000_MAX_FRAME_LEN]`
///    publishes a single 16-byte legacy TX descriptor with
///    `CMD = EOP | IFCS | RS`, `length = frame.len()`, `STATUS = 0`,
///    advances `TDT` by one (mod `E1000_TX_RING_LEN`), and copies
///    the frame bytes into the buffer pointed at by the descriptor.
/// 5. `receive(buf)` for a buffer of at least the pending frame's
///    length consumes a single RX descriptor at the ring head, copies
///    `length` payload bytes into `buf[..length]`, clears the
///    descriptor's STATUS byte, advances `RDT` by one, and returns
///    `Ok(Some(length))`. With no frame pending, returns `Ok(None)`.
/// 6. `link_state` returns the value cached from the last `init`
///    call. `init` may be re-invoked to refresh the cache; subsequent
///    `link_state` calls reflect the new cache.
/// 7. A second `init` call on the same instance returns
///    `Ok(())` — `init` is idempotent. The harness sees the bring-up
///    register sequence repeated (the device is reset again, the
///    rings are re-programmed). This matches the donor semantics —
///    a kernel that re-probes after a PCI re-enumeration must be
///    able to drive `init` again without leaking state.
///
/// # Not in this contract (intentional)
///
/// - Interrupts. The seed polls descriptor rings directly.
/// - Jumbo frames. `E1000_MAX_FRAME_LEN = 1518` covers IEEE 802.3
///   classic Ethernet + the 14-byte header; jumbo would push the
///   constant past one descriptor's address range and is out of
///   scope.
/// - MSI / MSI-X. Out of scope for the seed.
/// - PCI enumeration. The bus + driver instance are constructed by
///   the caller (kernel: from a probed BAR; tests: in-memory).
pub trait EthernetController {
    /// Drive the device through `reset → poll(!RST) → SLU → read MAC
    /// from EEPROM → program RX/TX descriptor rings → RCTL.EN +
    /// TCTL.EN → cache STATUS bits as `LinkState``. Writes the recovered
    /// MAC into `mac_out`. Idempotent — a second call repeats the
    /// sequence (no state-leak).
    fn init(
        &mut self,
        bus: &mut dyn MmioRegBus,
        mac_out: &mut [u8; 6],
    ) -> Result<(), E1000Error>;

    /// Transmit one Ethernet frame. The frame must be the bytes from
    /// destination MAC through payload — the device computes the FCS
    /// (the driver sets `CMD.IFCS`). Returns `RingFull` when every
    /// descriptor still has STATUS.DD clear (i.e. the device hasn't
    /// drained the previous queue).
    fn transmit(
        &mut self,
        bus: &mut dyn MmioRegBus,
        frame: &[u8],
    ) -> Result<(), E1000Error>;

    /// Receive one Ethernet frame into `buf`. Returns `Ok(Some(n))`
    /// for `n` payload bytes written into `buf[..n]`, `Ok(None)` if
    /// no frame is pending, or an error.
    fn receive(
        &mut self,
        bus: &mut dyn MmioRegBus,
        buf: &mut [u8],
    ) -> Result<Option<usize>, E1000Error>;

    /// Cached link state from the most recent `init`.
    fn link_state(&self) -> LinkState;
}

// ============================================================
// VirtioPciCaps — VirtIO PCI capability list walker (TASK-077)
// ============================================================

/// Vendor-specific capability ID used by VirtIO.
pub const VIRTIO_PCI_CAP_ID: u8 = 0x09;
/// Common configuration structure.
pub const VIRTIO_PCI_CAP_COMMON_CFG: u8 = 1;
/// Notifications.
pub const VIRTIO_PCI_CAP_NOTIFY_CFG: u8 = 2;
/// ISR status.
pub const VIRTIO_PCI_CAP_ISR_CFG: u8 = 3;
/// Device-specific configuration.
pub const VIRTIO_PCI_CAP_DEVICE_CFG: u8 = 4;
/// PCI configuration access.
pub const VIRTIO_PCI_CAP_PCI_CFG: u8 = 5;
/// Max capability nodes walked.
pub const VIRTIO_PCI_CAP_MAX: usize = 8;

/// One VirtIO PCI capability header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct VirtioPciCap {
    /// Config-space offset of this capability.
    pub offset: u8,
    /// `cfg_type` (common/notify/isr/device/pci).
    pub cfg_type: u8,
    /// BAR index.
    pub bar: u8,
    /// Offset within BAR.
    pub bar_offset: u32,
    /// Length in BAR.
    pub length: u32,
}

/// Errors walking VirtIO caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VirtioPciCapError {
    /// No vendor-cap chain / empty.
    NotFound,
    /// Walk exceeded hop budget.
    TooMany,
    /// Truncated header.
    Truncated,
}

/// VirtIO PCI capability list walker over raw config dwords.
pub trait VirtioPciCaps {
    /// Walk capabilities starting at `cap_ptr`, reading 8-byte
    /// vendor-cap headers via the provided dword reader callback
    /// `read(offset) -> dword`. Fills `out`, returns count.
    fn walk(
        cap_ptr: u8,
        read_dword: &mut dyn FnMut(u8) -> u32,
        out: &mut [VirtioPciCap; VIRTIO_PCI_CAP_MAX],
    ) -> Result<usize, VirtioPciCapError>;
    /// Find first cap of `cfg_type` in a filled list.
    fn find(caps: &[VirtioPciCap], cfg_type: u8) -> Option<VirtioPciCap>;
}

