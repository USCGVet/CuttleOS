//! Intel 82540EM (e1000) NIC driver — TASK-056.
//!
//! Implements the [`EthernetController`] contract against the
//! [`MmioRegBus`] register window. The driver state machine is
//! fully diversifiable across morph cycles; the wire-observable
//! surface (every byte written through the bus, the 16-byte legacy
//! descriptor format, the EEPROM word offsets polled) is locked
//! by the contract's constants.
//!
//! The companion harness [`MemMmioBus`] is the in-memory device
//! simulator used by both unit tests and the kernel banner: it
//! shadows a 128 KiB MMIO window, models the EEPROM read state
//! machine (EERD START/DONE/ADDR/DATA bit fields), drains the TX
//! descriptor ring when the driver advances TDT, and lets a test
//! inject one or more frames into the RX descriptor ring so the
//! driver's `receive` can round-trip them.
//!
//! References:
//!   * Intel 8254x Family Software Developer's Manual rev 3.4
//!     §13 (PCI configuration), §14 (Receive Path), §13.4 (CTRL),
//!     §13.5 (STATUS), §5.3 (EERD), §13.7 (Receive Control), §13.8
//!     (Transmit Control), §3.2 (legacy receive descriptor
//!     format), §3.3 (legacy transmit descriptor format).
//!   * RustOSa `src/e1000.rs` — the canonical donor for the
//!     bring-up sequence + descriptor packing.
//!
//! Differences from the donor:
//!   * No global statics. The driver instance owns the rings; an
//!     external caller (kernel or test) constructs the bus and
//!     hands it to `init` / `transmit` / `receive`. Avoids the
//!     `spin::Once<Mutex<...>>` pattern that the donor needed
//!     because Rust at the time did not have `&mut` through a
//!     statically-resolved singleton.
//!   * No `alloc`. The TX/RX rings are owned by the driver as
//!     fixed-capacity arrays; buffer storage is co-located, so
//!     `phys_addr_of` returns a stable address for the device
//!     side of the simulation.
//!   * MAC is read from EEPROM via EERD, not from RAR0. RAR0 only
//!     gets the burned-in address loaded after a hardware reset on
//!     real silicon; the EEPROM path is the contract surface here
//!     because it exercises a real state machine the morph engine
//!     can diversify against.

#![allow(clippy::needless_range_loop)]

use cuttle_contracts::{
    EthernetController, E1000Error, LinkState, MmioRegBus,
    // CTRL / STATUS / EERD / RCTL / TCTL / IMC bit flags + offsets
    E1000_CTRL_RST, E1000_CTRL_SLU, E1000_DESC_STA_DD, E1000_EEPROM_MAC_WORD0,
    E1000_EEPROM_MAC_WORD1, E1000_EEPROM_MAC_WORD2, E1000_EERD_ADDR_MASK,
    E1000_EERD_ADDR_SHIFT, E1000_EERD_DATA_MASK, E1000_EERD_DATA_SHIFT, E1000_EERD_DONE,
    E1000_EERD_START, E1000_MAX_FRAME_LEN, E1000_RCTL_BAM, E1000_RCTL_EN, E1000_RCTL_SECRC,
    E1000_REG_CTRL, E1000_REG_EERD, E1000_REG_IMC, E1000_REG_IMS, E1000_REG_RCTL,
    E1000_REG_RDBAH, E1000_REG_RDBAL, E1000_REG_RDH, E1000_REG_RDLEN, E1000_REG_RDT,
    E1000_REG_STATUS, E1000_REG_TCTL, E1000_REG_TDBAH, E1000_REG_TDBAL, E1000_REG_TDH,
    E1000_REG_TDLEN, E1000_REG_TDT, E1000_REG_TIPG, E1000_RX_DESC_LEN, E1000_RX_RING_LEN,
    E1000_RXD_STA_EOP, E1000_STATUS_FD, E1000_STATUS_LU, E1000_STATUS_SPEED_MASK,
    E1000_STATUS_SPEED_SHIFT, E1000_TCTL_EN, E1000_TCTL_PSP, E1000_TX_DESC_LEN,
    E1000_TX_RING_LEN, E1000_TXD_CMD_EOP, E1000_TXD_CMD_IFCS, E1000_TXD_CMD_RS,
};

// ============================================================
// Descriptor formats (legacy 16-byte layout, Intel 8254x §3.2 / §3.3).
// ============================================================

/// 16-byte legacy receive descriptor.
///
/// Wire bytes (little-endian fields):
///   * `addr`     bytes 0..8   — physical address of the receive buffer
///   * `length`   bytes 8..10  — frame length the device DMA'd
///   * `checksum` bytes 10..12 — RX packet checksum
///   * `status`   byte 12      — STATUS bits (DD, EOP, …)
///   * `errors`   byte 13      — error flags
///   * `special`  bytes 14..16 — VLAN tag (unused)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct RxDesc {
    /// Physical address of the receive buffer (bytes 0..8).
    pub addr: u64,
    /// Frame length the device DMA'd (bytes 8..10).
    pub length: u16,
    /// RX packet checksum (bytes 10..12).
    pub checksum: u16,
    /// STATUS bits — DD, EOP, … (byte 12).
    pub status: u8,
    /// Error flags written by the device (byte 13).
    pub errors: u8,
    /// VLAN tag — unused in legacy mode (bytes 14..16).
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<RxDesc>() == E1000_RX_DESC_LEN);
const _: () = assert!(core::mem::align_of::<RxDesc>() == 8);

impl RxDesc {
    /// Encode the descriptor into its 16-byte little-endian wire form.
    pub fn encode(&self) -> [u8; E1000_RX_DESC_LEN] {
        let mut b = [0u8; E1000_RX_DESC_LEN];
        b[0..8].copy_from_slice(&self.addr.to_le_bytes());
        b[8..10].copy_from_slice(&self.length.to_le_bytes());
        b[10..12].copy_from_slice(&self.checksum.to_le_bytes());
        b[12] = self.status;
        b[13] = self.errors;
        b[14..16].copy_from_slice(&self.special.to_le_bytes());
        b
    }

    /// Decode 16 little-endian bytes into a descriptor. Panics if the
    /// slice is the wrong length — callers slice the ring exactly.
    pub fn decode(b: &[u8; E1000_RX_DESC_LEN]) -> Self {
        let addr = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let length = u16::from_le_bytes([b[8], b[9]]);
        let checksum = u16::from_le_bytes([b[10], b[11]]);
        let status = b[12];
        let errors = b[13];
        let special = u16::from_le_bytes([b[14], b[15]]);
        Self { addr, length, checksum, status, errors, special }
    }
}

/// 16-byte legacy transmit descriptor.
///
/// Wire bytes:
///   * `addr`    bytes 0..8   — phys addr of the frame buffer
///   * `length`  bytes 8..10  — frame length
///   * `cso`     byte 10      — checksum offset (unused; legacy mode)
///   * `cmd`     byte 11      — command bits (EOP, IFCS, RS)
///   * `sta`     byte 12      — STATUS bits the device writes back
///   * `css`     byte 13      — checksum start (unused)
///   * `special` bytes 14..16 — VLAN tag (unused)
#[repr(C)]
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct TxDesc {
    /// Physical address of the frame buffer (bytes 0..8).
    pub addr: u64,
    /// Frame length (bytes 8..10).
    pub length: u16,
    /// Checksum offset — unused in legacy mode (byte 10).
    pub cso: u8,
    /// Command bits — EOP, IFCS, RS (byte 11).
    pub cmd: u8,
    /// STATUS bits the device writes back (byte 12).
    pub sta: u8,
    /// Checksum start — unused in legacy mode (byte 13).
    pub css: u8,
    /// VLAN tag — unused (bytes 14..16).
    pub special: u16,
}

const _: () = assert!(core::mem::size_of::<TxDesc>() == E1000_TX_DESC_LEN);
const _: () = assert!(core::mem::align_of::<TxDesc>() == 8);

impl TxDesc {
    /// Encode into 16-byte little-endian wire form.
    pub fn encode(&self) -> [u8; E1000_TX_DESC_LEN] {
        let mut b = [0u8; E1000_TX_DESC_LEN];
        b[0..8].copy_from_slice(&self.addr.to_le_bytes());
        b[8..10].copy_from_slice(&self.length.to_le_bytes());
        b[10] = self.cso;
        b[11] = self.cmd;
        b[12] = self.sta;
        b[13] = self.css;
        b[14..16].copy_from_slice(&self.special.to_le_bytes());
        b
    }

    /// Decode 16 little-endian bytes.
    pub fn decode(b: &[u8; E1000_TX_DESC_LEN]) -> Self {
        let addr = u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]);
        let length = u16::from_le_bytes([b[8], b[9]]);
        let cso = b[10];
        let cmd = b[11];
        let sta = b[12];
        let css = b[13];
        let special = u16::from_le_bytes([b[14], b[15]]);
        Self { addr, length, cso, cmd, sta, css, special }
    }
}

// ============================================================
// Driver state.
// ============================================================

/// Per-frame TX buffer size. Matches `E1000_MAX_FRAME_LEN`; the
/// device DMAs at most one frame per legacy descriptor.
const TX_BUF_LEN: usize = E1000_MAX_FRAME_LEN;
/// Per-frame RX buffer size. Same rationale.
const RX_BUF_LEN: usize = E1000_MAX_FRAME_LEN;

/// EEPROM poll budget. Real hardware sets DONE within ~1 µs; we
/// budget two orders of magnitude over that to absorb host-side
/// scheduling jitter in the harness without giving a malicious or
/// broken device unbounded time to hang the driver.
const EEPROM_POLL_LIMIT: u32 = 10_000;

/// Bit-pattern read back from a vanished PCI device. Reading any
/// register from a BAR that has been unmapped or whose device has
/// fallen off the bus returns this value across the entire MMIO
/// window. We use it as a sentinel to surface `MmioFault`.
const MMIO_FAULT_SENTINEL: u32 = 0xFFFF_FFFF;

/// Intel 82540EM driver.
///
/// The descriptor rings + buffer pool are owned in-line so the
/// struct can hand out stable physical addresses to the device
/// simulator. The simulator shares the byte layout: it reads
/// descriptors directly out of the addresses the driver hands it
/// via `RDBAL/RDBAH` and `TDBAL/TDBAH`.
///
/// Phys-address mapping: the harness treats `phys = virt` for the
/// driver-owned arrays. The kernel banner uses the same identity
/// mapping because the `MemMmioBus` is a pure in-memory thing —
/// no real DMA happens.
pub struct E1000Impl {
    /// TX descriptor ring storage. Each entry is the 16-byte
    /// little-endian wire form; the driver re-encodes whenever it
    /// publishes a new descriptor.
    tx_ring: [[u8; E1000_TX_DESC_LEN]; E1000_TX_RING_LEN],
    /// TX per-slot frame buffer.
    tx_bufs: [[u8; TX_BUF_LEN]; E1000_TX_RING_LEN],
    /// Driver-side TX tail (the next slot we'll write to).
    tx_tail: usize,

    /// RX descriptor ring storage.
    rx_ring: [[u8; E1000_RX_DESC_LEN]; E1000_RX_RING_LEN],
    /// RX per-slot frame buffer.
    rx_bufs: [[u8; RX_BUF_LEN]; E1000_RX_RING_LEN],
    /// Driver-side RX next-to-consume cursor (the next descriptor
    /// we expect to see STATUS.DD on).
    rx_next: usize,

    /// Cached MAC address read out of the EEPROM during init.
    /// Zeroed before the first successful init.
    mac: [u8; 6],
    /// Cached link state from the most recent init.
    link: LinkState,
    /// Whether init has successfully completed at least once. Re-
    /// init is allowed; this flag controls whether `transmit` /
    /// `receive` reject calls before bring-up.
    initialised: bool,
}

impl Default for E1000Impl {
    fn default() -> Self {
        Self::new()
    }
}

impl E1000Impl {
    /// Construct a fresh driver with empty rings and zeroed buffers.
    pub const fn new() -> Self {
        Self {
            tx_ring: [[0u8; E1000_TX_DESC_LEN]; E1000_TX_RING_LEN],
            tx_bufs: [[0u8; TX_BUF_LEN]; E1000_TX_RING_LEN],
            tx_tail: 0,
            rx_ring: [[0u8; E1000_RX_DESC_LEN]; E1000_RX_RING_LEN],
            rx_bufs: [[0u8; RX_BUF_LEN]; E1000_RX_RING_LEN],
            rx_next: 0,
            mac: [0u8; 6],
            link: LinkState::Down,
            initialised: false,
        }
    }

    /// Physical address the device simulator should treat as the TX
    /// ring base. With the identity-mapped harness, the ring's
    /// memory address (as a `u64`) is the wire phys address.
    pub fn tx_ring_addr(&self) -> u64 {
        self.tx_ring.as_ptr() as u64
    }

    /// Physical address of the RX ring base.
    pub fn rx_ring_addr(&self) -> u64 {
        self.rx_ring.as_ptr() as u64
    }

    /// Physical address of the TX buffer at slot `idx`.
    pub fn tx_buf_addr(&self, idx: usize) -> u64 {
        self.tx_bufs[idx].as_ptr() as u64
    }

    /// Physical address of the RX buffer at slot `idx`.
    pub fn rx_buf_addr(&self, idx: usize) -> u64 {
        self.rx_bufs[idx].as_ptr() as u64
    }

    /// Cached MAC address from the most recent `init`.
    pub fn mac_address(&self) -> [u8; 6] {
        self.mac
    }

    /// Drive the EERD state machine to read EEPROM word `addr`.
    /// Writes EERD with START=1 + ADDR=addr, polls until DONE is
    /// observed, then extracts the 16-bit DATA field. Returns
    /// `MacReadFailed` if the device never sets DONE within the
    /// poll budget.
    fn read_eeprom_word(bus: &mut dyn MmioRegBus, addr: u8) -> Result<u16, E1000Error> {
        let cmd = E1000_EERD_START
            | ((addr as u32 & E1000_EERD_ADDR_MASK) << E1000_EERD_ADDR_SHIFT);
        bus.write_u32(E1000_REG_EERD, cmd);
        let mut spins = 0u32;
        loop {
            let v = bus.read_u32(E1000_REG_EERD);
            if v == MMIO_FAULT_SENTINEL {
                return Err(E1000Error::MmioFault);
            }
            if v & E1000_EERD_DONE != 0 {
                let data = (v >> E1000_EERD_DATA_SHIFT) & E1000_EERD_DATA_MASK;
                return Ok(data as u16);
            }
            spins += 1;
            if spins > EEPROM_POLL_LIMIT {
                return Err(E1000Error::MacReadFailed);
            }
        }
    }

    /// Read 3 EEPROM words → 6-byte MAC. Returns `BadEeprom` if the
    /// recovered MAC is structurally invalid (all-zero, all-ones, or
    /// has the multicast bit set in the first octet — burned-in MACs
    /// must be unicast per IEEE 802 §3.2.3).
    fn read_mac_from_eeprom(bus: &mut dyn MmioRegBus) -> Result<[u8; 6], E1000Error> {
        let w0 = Self::read_eeprom_word(bus, E1000_EEPROM_MAC_WORD0)?;
        let w1 = Self::read_eeprom_word(bus, E1000_EEPROM_MAC_WORD1)?;
        let w2 = Self::read_eeprom_word(bus, E1000_EEPROM_MAC_WORD2)?;
        // Each word stores two MAC bytes in little-endian order:
        // word0 low byte is mac[0], high byte is mac[1].
        let mac = [
            (w0 & 0xFF) as u8,
            ((w0 >> 8) & 0xFF) as u8,
            (w1 & 0xFF) as u8,
            ((w1 >> 8) & 0xFF) as u8,
            (w2 & 0xFF) as u8,
            ((w2 >> 8) & 0xFF) as u8,
        ];
        if mac == [0u8; 6] || mac == [0xFFu8; 6] {
            return Err(E1000Error::BadEeprom);
        }
        // Multicast bit (LSB of first octet) must be zero on a
        // burned-in unicast MAC.
        if mac[0] & 0x01 != 0 {
            return Err(E1000Error::BadEeprom);
        }
        Ok(mac)
    }

    /// Issue CTRL.RST, poll until the device clears it (bounded), then
    /// mask interrupts. Returns `MmioFault` if the BAR vanished.
    fn reset(bus: &mut dyn MmioRegBus) -> Result<(), E1000Error> {
        // Mask any pending interrupts so the reset can't trip an IRQ.
        bus.write_u32(E1000_REG_IMC, 0xFFFF_FFFF);
        let ctrl = bus.read_u32(E1000_REG_CTRL);
        if ctrl == MMIO_FAULT_SENTINEL {
            return Err(E1000Error::MmioFault);
        }
        bus.write_u32(E1000_REG_CTRL, ctrl | E1000_CTRL_RST);
        // Bounded poll — a broken device must not hang the driver.
        let mut spins = 0u32;
        loop {
            let v = bus.read_u32(E1000_REG_CTRL);
            if v == MMIO_FAULT_SENTINEL {
                return Err(E1000Error::MmioFault);
            }
            if v & E1000_CTRL_RST == 0 {
                break;
            }
            spins += 1;
            if spins > EEPROM_POLL_LIMIT {
                // CTRL.RST never cleared. Treat as a fault — the
                // device is malformed.
                return Err(E1000Error::MmioFault);
            }
        }
        // Some post-reset states re-enable interrupt sources; clear
        // them again.
        bus.write_u32(E1000_REG_IMC, 0xFFFF_FFFF);
        // Clear ICR by reading it (read-to-clear semantics).
        let _ = bus.read_u32(E1000_REG_ICR_OFFSET);
        Ok(())
    }

    /// Decode STATUS register bits into a [`LinkState`].
    fn decode_link(status: u32) -> LinkState {
        if status & E1000_STATUS_LU == 0 {
            return LinkState::Down;
        }
        let speed = (status >> E1000_STATUS_SPEED_SHIFT) & E1000_STATUS_SPEED_MASK;
        match speed {
            0 => LinkState::Up10,
            1 => LinkState::Up100,
            // 0b10 + 0b11 both encode 1 Gbit — the spec reserves the
            // top combination for "reserved" but QEMU emits 0b10
            // and earlier Intel parts emit 0b11; treat both as 1G.
            2 | 3 => LinkState::Up1000,
            _ => LinkState::Down,
        }
    }

    /// Re-encode the TX/RX rings into a clean, "device-DD-clear"
    /// pre-bring-up state, then re-program the device's ring base /
    /// length / head / tail. Called from `init`.
    fn program_rings(&mut self, bus: &mut dyn MmioRegBus) {
        // RX: every descriptor points at its buffer; STATUS is
        // cleared so the driver waits for the device to DD-mark it.
        for i in 0..E1000_RX_RING_LEN {
            let desc = RxDesc {
                addr: self.rx_buf_addr(i),
                length: 0,
                checksum: 0,
                status: 0,
                errors: 0,
                special: 0,
            };
            self.rx_ring[i] = desc.encode();
        }
        self.rx_next = 0;
        let rx_base = self.rx_ring_addr();
        bus.write_u32(E1000_REG_RDBAL, rx_base as u32);
        bus.write_u32(E1000_REG_RDBAH, (rx_base >> 32) as u32);
        bus.write_u32(
            E1000_REG_RDLEN,
            (E1000_RX_RING_LEN * E1000_RX_DESC_LEN) as u32,
        );
        bus.write_u32(E1000_REG_RDH, 0);
        // Per Intel spec, RDT must lag the descriptors handed to the
        // device by one — and HEAD must never equal TAIL while RCTL.EN
        // is set. Start with the device owning ring entries
        // [0, RX_RING_LEN-1].
        bus.write_u32(E1000_REG_RDT, (E1000_RX_RING_LEN - 1) as u32);
        // Enable receiver: broadcast accept + strip Ethernet CRC.
        // Buffer-size bits zero default to 2 KiB which is enough for
        // 1518-byte legacy frames.
        let rctl = E1000_RCTL_EN | E1000_RCTL_BAM | E1000_RCTL_SECRC;
        bus.write_u32(E1000_REG_RCTL, rctl);

        // TX: every descriptor pre-seeded as STATUS.DD = 1 so the
        // first `transmit` accepts the slot. The actual addr field
        // is set by `transmit` to the buffer for the frame.
        for i in 0..E1000_TX_RING_LEN {
            let desc = TxDesc {
                addr: self.tx_buf_addr(i),
                length: 0,
                cso: 0,
                cmd: 0,
                sta: E1000_DESC_STA_DD,
                css: 0,
                special: 0,
            };
            self.tx_ring[i] = desc.encode();
        }
        self.tx_tail = 0;
        let tx_base = self.tx_ring_addr();
        bus.write_u32(E1000_REG_TDBAL, tx_base as u32);
        bus.write_u32(E1000_REG_TDBAH, (tx_base >> 32) as u32);
        bus.write_u32(
            E1000_REG_TDLEN,
            (E1000_TX_RING_LEN * E1000_TX_DESC_LEN) as u32,
        );
        bus.write_u32(E1000_REG_TDH, 0);
        bus.write_u32(E1000_REG_TDT, 0);
        // Per Intel 82540EM spec table 13-77: IPGT=10, IPGR1=10,
        // IPGR2=10. Field layout: [9:0] IPGT, [19:10] IPGR1,
        // [29:20] IPGR2.
        let tipg: u32 = 10 | (10u32 << 10) | (10u32 << 20);
        bus.write_u32(E1000_REG_TIPG, tipg);
        // TCTL: enable, pad-short-packets, CT=0x10, COLD=0x40.
        let tctl: u32 = E1000_TCTL_EN | E1000_TCTL_PSP | (0x10u32 << 4) | (0x40u32 << 12);
        bus.write_u32(E1000_REG_TCTL, tctl);
    }
}

/// Synthesised offset constant alias — the contract exposes
/// `E1000_REG_ICR` but the driver uses it as a `usize` for the bus
/// read in `reset`; keeping the alias local lets us avoid a fully-
/// qualified path in the call.
const E1000_REG_ICR_OFFSET: usize = cuttle_contracts::E1000_REG_ICR;

impl EthernetController for E1000Impl {
    fn init(
        &mut self,
        bus: &mut dyn MmioRegBus,
        mac_out: &mut [u8; 6],
    ) -> Result<(), E1000Error> {
        Self::reset(bus)?;
        let mac = Self::read_mac_from_eeprom(bus)?;
        // Bring the link up by setting CTRL.SLU.
        let ctrl = bus.read_u32(E1000_REG_CTRL);
        if ctrl == MMIO_FAULT_SENTINEL {
            return Err(E1000Error::MmioFault);
        }
        bus.write_u32(E1000_REG_CTRL, ctrl | E1000_CTRL_SLU);
        // Sample STATUS and cache the link state.
        let status = bus.read_u32(E1000_REG_STATUS);
        if status == MMIO_FAULT_SENTINEL {
            return Err(E1000Error::MmioFault);
        }
        self.link = Self::decode_link(status);
        // Program descriptor rings.
        self.program_rings(bus);
        // Confirm IMS is masked. We don't take device interrupts in
        // the seed driver — polling is the contract.
        bus.write_u32(E1000_REG_IMS, 0);
        self.mac = mac;
        *mac_out = mac;
        self.initialised = true;
        Ok(())
    }

    fn transmit(
        &mut self,
        bus: &mut dyn MmioRegBus,
        frame: &[u8],
    ) -> Result<(), E1000Error> {
        if !self.initialised {
            return Err(E1000Error::NoLink);
        }
        if frame.is_empty() || frame.len() > E1000_MAX_FRAME_LEN {
            return Err(E1000Error::FrameLengthInvalid);
        }
        if matches!(self.link, LinkState::Down) {
            return Err(E1000Error::NoLink);
        }
        // Verify the slot at `tx_tail` is available (STATUS.DD set
        // by either the previous TX completion or the init seeding).
        let slot = self.tx_tail;
        let cur = TxDesc::decode(&self.tx_ring[slot]);
        if cur.sta & E1000_DESC_STA_DD == 0 {
            return Err(E1000Error::RingFull);
        }
        // Copy the frame into the slot's TX buffer.
        let buf = &mut self.tx_bufs[slot];
        buf[..frame.len()].copy_from_slice(frame);
        // Re-encode the descriptor with the new length + command
        // bits + cleared status (the device will DD it on completion).
        let new_desc = TxDesc {
            addr: self.tx_buf_addr(slot),
            length: frame.len() as u16,
            cso: 0,
            cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
            sta: 0,
            css: 0,
            special: 0,
        };
        self.tx_ring[slot] = new_desc.encode();
        // Advance tail (mod ring length) and ring the doorbell.
        self.tx_tail = (slot + 1) % E1000_TX_RING_LEN;
        bus.write_u32(E1000_REG_TDT, self.tx_tail as u32);
        Ok(())
    }

    fn receive(
        &mut self,
        bus: &mut dyn MmioRegBus,
        buf: &mut [u8],
    ) -> Result<Option<usize>, E1000Error> {
        if !self.initialised {
            return Err(E1000Error::NoLink);
        }
        let slot = self.rx_next;
        let desc = RxDesc::decode(&self.rx_ring[slot]);
        if desc.status & E1000_DESC_STA_DD == 0 {
            return Ok(None);
        }
        // STATUS.EOP must be set for a complete frame. Multi-
        // descriptor jumbo frames are out of contract scope; reject
        // them as BadDescriptor.
        if desc.status & E1000_RXD_STA_EOP == 0 {
            return Err(E1000Error::BadDescriptor);
        }
        let length = desc.length as usize;
        if length == 0 || length > RX_BUF_LEN {
            return Err(E1000Error::BadDescriptor);
        }
        if buf.len() < length {
            return Err(E1000Error::BufferTooSmall);
        }
        // Copy payload into the caller's buffer.
        buf[..length].copy_from_slice(&self.rx_bufs[slot][..length]);
        // Hand the descriptor back to the device: clear status,
        // advance tail.
        let cleared = RxDesc {
            addr: desc.addr,
            length: 0,
            checksum: 0,
            status: 0,
            errors: 0,
            special: 0,
        };
        self.rx_ring[slot] = cleared.encode();
        // RDT lags the most-recently-freed slot by one (Intel spec
        // forbids HEAD == TAIL while receiver is enabled).
        bus.write_u32(E1000_REG_RDT, slot as u32);
        self.rx_next = (slot + 1) % E1000_RX_RING_LEN;
        Ok(Some(length))
    }

    fn link_state(&self) -> LinkState {
        self.link
    }
}

// ============================================================
// MemMmioBus — in-memory simulator + EEPROM fixture + ring drain.
// ============================================================

/// MMIO window byte size (Intel 82540EM BAR0). We allocate a flat
/// shadow buffer; the EEPROM and ring side effects live in the
/// device-side state below.
pub const MEM_MMIO_BYTES: usize = 128 * 1024;

/// Number of EEPROM words modelled (Intel spec is 64 for 82540EM,
/// 256 for newer; the driver only reads 0/1/2 for the MAC).
pub const EEPROM_WORDS: usize = 64;

/// Capacity for captured TX frames. Sized for the kernel banner's
/// single-frame round-trip plus generous headroom for unit tests.
pub const TX_CAPTURE_CAP: usize = 16;
/// Capacity for pending RX frames waiting to be injected.
pub const RX_PENDING_CAP: usize = 16;

/// A captured TX frame.
#[derive(Copy, Clone)]
pub struct TxCapture {
    /// Captured frame bytes (padded to the max-frame size).
    pub bytes: [u8; E1000_MAX_FRAME_LEN],
    /// Number of valid bytes at the start of `bytes`.
    pub len: usize,
}

impl TxCapture {
    const fn zeroed() -> Self {
        Self { bytes: [0u8; E1000_MAX_FRAME_LEN], len: 0 }
    }
}

/// In-memory implementation of [`MmioRegBus`] driving a simulated
/// Intel 82540EM. Use [`MemMmioBus::new`] to construct one with a
/// caller-supplied MAC; use [`MemMmioBus::inject_rx_frame`] to push
/// a frame into the device-side of the RX ring (the next call to
/// `EthernetController::receive` will recover it); use
/// [`MemMmioBus::tx_captures`] to read frames the driver has
/// transmitted.
pub struct MemMmioBus {
    /// Shadow byte buffer covering the entire BAR. Reads of un-
    /// modelled offsets return 0 (the contract's normal
    /// "uninitialised register" semantics).
    shadow: [u8; MEM_MMIO_BYTES],
    /// EEPROM fixture words. Bytes 0..6 of the MAC are packed into
    /// words 0/1/2 by the constructor.
    eeprom: [u16; EEPROM_WORDS],
    /// Mirror of the most-recent CTRL write. We expose it through
    /// `read_u32(E1000_REG_CTRL)` so the driver's reset spin sees
    /// CTRL.RST clear within one read after we mark it cleared.
    ctrl: u32,
    /// Mirror of STATUS register. The constructor seeds it with
    /// LU + Up1000.
    status: u32,
    /// Most recent EERD value the driver wrote. The bus completes
    /// the EEPROM read synchronously on the next `read_u32`.
    eerd_pending_read: bool,
    eerd_pending_value: u32,
    /// Captured TX frames (driver wrote a TX descriptor with EOP+RS;
    /// the bus copied the payload out of the TX buffer).
    tx_captures: [TxCapture; TX_CAPTURE_CAP],
    tx_captures_len: usize,
    /// Pending RX frames to inject. Each call to
    /// `EthernetController::receive` consumes one from the front.
    rx_pending: [TxCapture; RX_PENDING_CAP],
    rx_pending_len: usize,
    /// Driver-supplied RX ring base address.
    rx_ring_base: u64,
    /// Driver-supplied TX ring base address.
    tx_ring_base: u64,
    /// Most-recent RDT the driver wrote (for descriptor drain).
    rdt: u32,
    /// Most-recent TDT the driver wrote.
    tdt: u32,
    /// MmioFault sentinel — when set, every read returns 0xFFFF_FFFF.
    fault_mode: bool,
    /// Force CTRL.RST to never auto-clear (timeout-path test).
    rst_never_clears: bool,
    /// Force EERD.DONE to never come up (EEPROM timeout test).
    eeprom_never_done: bool,
}

impl MemMmioBus {
    /// `const fn` zeroed constructor for static storage in the kernel
    /// banner. Sets STATUS to the default Up@1G + FD pattern so the
    /// caller only needs to set the EEPROM MAC; behaviourally
    /// equivalent to `new([0; 6])` followed by `set_eeprom_mac`.
    /// Distinct from `new` because the latter calls `from_le_bytes`,
    /// which is not currently const in this MSRV pin.
    pub const fn zeroed() -> Self {
        let status =
            E1000_STATUS_LU | E1000_STATUS_FD | (0b10u32 << E1000_STATUS_SPEED_SHIFT);
        Self {
            shadow: [0u8; MEM_MMIO_BYTES],
            eeprom: [0u16; EEPROM_WORDS],
            ctrl: 0,
            status,
            eerd_pending_read: false,
            eerd_pending_value: 0,
            tx_captures: [TxCapture::zeroed(); TX_CAPTURE_CAP],
            tx_captures_len: 0,
            rx_pending: [TxCapture::zeroed(); RX_PENDING_CAP],
            rx_pending_len: 0,
            rx_ring_base: 0,
            tx_ring_base: 0,
            rdt: 0,
            tdt: 0,
            fault_mode: false,
            rst_never_clears: false,
            eeprom_never_done: false,
        }
    }

    /// Construct a fresh bus with the supplied MAC pre-seeded into
    /// EEPROM words 0/1/2. Link state defaults to Up @ 1G.
    pub fn new(mac: [u8; 6]) -> Self {
        let mut eeprom = [0u16; EEPROM_WORDS];
        eeprom[0] = u16::from_le_bytes([mac[0], mac[1]]);
        eeprom[1] = u16::from_le_bytes([mac[2], mac[3]]);
        eeprom[2] = u16::from_le_bytes([mac[4], mac[5]]);
        // STATUS.LU + STATUS.FD + SPEED = 0b10 (1 Gbit).
        let status = E1000_STATUS_LU | E1000_STATUS_FD | (0b10u32 << E1000_STATUS_SPEED_SHIFT);
        Self {
            shadow: [0u8; MEM_MMIO_BYTES],
            eeprom,
            ctrl: 0,
            status,
            eerd_pending_read: false,
            eerd_pending_value: 0,
            tx_captures: [TxCapture::zeroed(); TX_CAPTURE_CAP],
            tx_captures_len: 0,
            rx_pending: [TxCapture::zeroed(); RX_PENDING_CAP],
            rx_pending_len: 0,
            rx_ring_base: 0,
            tx_ring_base: 0,
            rdt: 0,
            tdt: 0,
            fault_mode: false,
            rst_never_clears: false,
            eeprom_never_done: false,
        }
    }

    /// Override STATUS register bits — for tests of `decode_link`
    /// at different speeds. Caller supplies the raw bit pattern.
    pub fn set_status(&mut self, status: u32) {
        self.status = status;
    }

    /// Set the MAC bytes in EEPROM directly (test override).
    pub fn set_eeprom_mac(&mut self, mac: [u8; 6]) {
        self.eeprom[0] = u16::from_le_bytes([mac[0], mac[1]]);
        self.eeprom[1] = u16::from_le_bytes([mac[2], mac[3]]);
        self.eeprom[2] = u16::from_le_bytes([mac[4], mac[5]]);
    }

    /// Activate MMIO-fault mode: every subsequent register read
    /// returns the 0xFFFF_FFFF sentinel.
    pub fn force_mmio_fault(&mut self) {
        self.fault_mode = true;
    }

    /// Make CTRL.RST sticky (never auto-clears) — exercises the
    /// `reset` poll-timeout path.
    pub fn force_reset_hang(&mut self) {
        self.rst_never_clears = true;
    }

    /// Make EERD.DONE never come up — exercises the EEPROM-timeout
    /// path.
    pub fn force_eeprom_timeout(&mut self) {
        self.eeprom_never_done = true;
    }

    /// Inject a frame into the device side of the RX ring. The next
    /// `EthernetController::receive` consumes one slot's worth from
    /// here. Returns the slot index used; `Err(())` if the pending
    /// queue is full.
    pub fn inject_rx_frame(&mut self, frame: &[u8]) -> Result<usize, ()> {
        if frame.len() > E1000_MAX_FRAME_LEN || self.rx_pending_len >= RX_PENDING_CAP {
            return Err(());
        }
        let idx = self.rx_pending_len;
        let slot = &mut self.rx_pending[idx];
        slot.bytes[..frame.len()].copy_from_slice(frame);
        slot.len = frame.len();
        self.rx_pending_len += 1;
        // Plant the frame in the corresponding RX ring slot the
        // driver is going to inspect next. We use rx_next-style
        // round-robin keyed by how many frames we've injected — the
        // driver also walks the ring 0..N in order.
        let driver_slot = (idx) % E1000_RX_RING_LEN;
        let desc = self.read_rx_desc(driver_slot);
        if desc.addr != 0 {
            // Driver has programmed the ring; copy frame to the
            // buffer at `addr` (identity-mapped phys = virt).
            let dst = desc.addr as *mut u8;
            for (i, b) in frame.iter().enumerate() {
                // SAFETY: identity-mapped phys; harness owns the
                // backing memory through E1000Impl.
                unsafe { dst.add(i).write(*b) };
            }
            // Set STATUS.DD + EOP and length on the descriptor.
            let written = RxDesc {
                addr: desc.addr,
                length: frame.len() as u16,
                checksum: 0,
                status: E1000_DESC_STA_DD | E1000_RXD_STA_EOP,
                errors: 0,
                special: 0,
            };
            self.write_rx_desc(driver_slot, &written);
        }
        Ok(idx)
    }

    /// Capture log of frames the driver has transmitted (in order).
    pub fn tx_captures(&self) -> &[TxCapture] {
        &self.tx_captures[..self.tx_captures_len]
    }

    /// Driver-supplied RX ring base address.
    pub fn rx_ring_base(&self) -> u64 {
        self.rx_ring_base
    }

    /// Driver-supplied TX ring base address.
    pub fn tx_ring_base(&self) -> u64 {
        self.tx_ring_base
    }

    /// Most-recent RDT the driver wrote.
    pub fn rdt(&self) -> u32 {
        self.rdt
    }

    /// Most-recent TDT the driver wrote.
    pub fn tdt(&self) -> u32 {
        self.tdt
    }

    fn read_rx_desc(&self, slot: usize) -> RxDesc {
        if self.rx_ring_base == 0 {
            return RxDesc::default();
        }
        let addr = self.rx_ring_base + (slot * E1000_RX_DESC_LEN) as u64;
        let mut b = [0u8; E1000_RX_DESC_LEN];
        // SAFETY: identity-mapped phys; descriptor lives inside the
        // driver-owned ring array.
        let src = addr as *const u8;
        for i in 0..E1000_RX_DESC_LEN {
            b[i] = unsafe { src.add(i).read() };
        }
        RxDesc::decode(&b)
    }

    fn write_rx_desc(&mut self, slot: usize, desc: &RxDesc) {
        if self.rx_ring_base == 0 {
            return;
        }
        let addr = self.rx_ring_base + (slot * E1000_RX_DESC_LEN) as u64;
        let bytes = desc.encode();
        let dst = addr as *mut u8;
        for i in 0..E1000_RX_DESC_LEN {
            // SAFETY: as above.
            unsafe { dst.add(i).write(bytes[i]) };
        }
    }

    fn read_tx_desc(&self, slot: usize) -> TxDesc {
        if self.tx_ring_base == 0 {
            return TxDesc::default();
        }
        let addr = self.tx_ring_base + (slot * E1000_TX_DESC_LEN) as u64;
        let mut b = [0u8; E1000_TX_DESC_LEN];
        let src = addr as *const u8;
        for i in 0..E1000_TX_DESC_LEN {
            b[i] = unsafe { src.add(i).read() };
        }
        TxDesc::decode(&b)
    }

    fn write_tx_desc(&mut self, slot: usize, desc: &TxDesc) {
        if self.tx_ring_base == 0 {
            return;
        }
        let addr = self.tx_ring_base + (slot * E1000_TX_DESC_LEN) as u64;
        let bytes = desc.encode();
        let dst = addr as *mut u8;
        for i in 0..E1000_TX_DESC_LEN {
            unsafe { dst.add(i).write(bytes[i]) };
        }
    }

    /// On TDT advance, drain newly-published TX descriptors: copy
    /// their payload into the capture log and set STATUS.DD so the
    /// driver's next transmit accepts the slot.
    fn drain_tx(&mut self, new_tdt: u32) {
        if self.tx_ring_base == 0 {
            return;
        }
        let new = new_tdt as usize;
        // Walk every slot 0..N looking for descriptors with
        // STATUS.DD clear and CMD.EOP set — i.e. the driver
        // published them but the device hasn't drained them.
        for slot in 0..E1000_TX_RING_LEN {
            let desc = self.read_tx_desc(slot);
            if desc.sta & E1000_DESC_STA_DD == 0
                && desc.cmd & E1000_TXD_CMD_EOP != 0
                && desc.length > 0
                && desc.length as usize <= E1000_MAX_FRAME_LEN
            {
                let len = desc.length as usize;
                if self.tx_captures_len < TX_CAPTURE_CAP {
                    let cap_slot = &mut self.tx_captures[self.tx_captures_len];
                    let src = desc.addr as *const u8;
                    for i in 0..len {
                        cap_slot.bytes[i] = unsafe { src.add(i).read() };
                    }
                    cap_slot.len = len;
                    self.tx_captures_len += 1;
                }
                // Mark descriptor done so the driver's next pass
                // accepts the slot again.
                let done = TxDesc {
                    addr: desc.addr,
                    length: desc.length,
                    cso: desc.cso,
                    cmd: desc.cmd,
                    sta: E1000_DESC_STA_DD,
                    css: desc.css,
                    special: desc.special,
                };
                self.write_tx_desc(slot, &done);
            }
        }
        // Advance the device-side TDH to match TDT (descriptors all
        // consumed in this drain-pass).
        self.shadow_u32_write(E1000_REG_TDH, new as u32);
    }

    fn shadow_u32_write(&mut self, off: usize, v: u32) {
        if off + 4 > MEM_MMIO_BYTES {
            return;
        }
        let bytes = v.to_le_bytes();
        self.shadow[off..off + 4].copy_from_slice(&bytes);
    }

    fn shadow_u32_read(&self, off: usize) -> u32 {
        if off + 4 > MEM_MMIO_BYTES {
            return 0;
        }
        let mut b = [0u8; 4];
        b.copy_from_slice(&self.shadow[off..off + 4]);
        u32::from_le_bytes(b)
    }
}

impl MmioRegBus for MemMmioBus {
    fn read_u32(&mut self, offset: usize) -> u32 {
        if self.fault_mode {
            return MMIO_FAULT_SENTINEL;
        }
        match offset {
            E1000_REG_CTRL => {
                // If the driver wrote CTRL.RST and we're not stuck,
                // clear it on read so the bounded spin terminates.
                if self.ctrl & E1000_CTRL_RST != 0 && !self.rst_never_clears {
                    self.ctrl &= !E1000_CTRL_RST;
                }
                self.ctrl
            }
            E1000_REG_STATUS => self.status,
            E1000_REG_EERD => {
                if self.eerd_pending_read {
                    if self.eeprom_never_done {
                        // Driver will spin until its poll budget
                        // expires. We keep returning the value
                        // without DONE.
                        let addr = (self.eerd_pending_value >> E1000_EERD_ADDR_SHIFT)
                            & E1000_EERD_ADDR_MASK;
                        return E1000_EERD_START
                            | ((addr & E1000_EERD_ADDR_MASK) << E1000_EERD_ADDR_SHIFT);
                    }
                    let addr = ((self.eerd_pending_value >> E1000_EERD_ADDR_SHIFT)
                        & E1000_EERD_ADDR_MASK) as usize;
                    let word = if addr < EEPROM_WORDS { self.eeprom[addr] } else { 0 };
                    let v = E1000_EERD_DONE
                        | ((word as u32 & E1000_EERD_DATA_MASK) << E1000_EERD_DATA_SHIFT)
                        | (((addr as u32) & E1000_EERD_ADDR_MASK) << E1000_EERD_ADDR_SHIFT);
                    // Clear the pending flag so the next read is
                    // back to the "no read in flight" state.
                    self.eerd_pending_read = false;
                    self.eerd_pending_value = v;
                    v
                } else {
                    self.eerd_pending_value
                }
            }
            E1000_REG_ICR_OFFSET => {
                let v = self.shadow_u32_read(E1000_REG_ICR_OFFSET);
                self.shadow_u32_write(E1000_REG_ICR_OFFSET, 0);
                v
            }
            _ => self.shadow_u32_read(offset),
        }
    }

    fn write_u32(&mut self, offset: usize, value: u32) {
        match offset {
            E1000_REG_CTRL => {
                self.ctrl = value;
            }
            E1000_REG_EERD => {
                if value & E1000_EERD_START != 0 {
                    self.eerd_pending_read = true;
                    self.eerd_pending_value = value;
                }
            }
            E1000_REG_RDBAL => {
                let cur = self.rx_ring_base & 0xFFFF_FFFF_0000_0000;
                self.rx_ring_base = cur | (value as u64);
            }
            E1000_REG_RDBAH => {
                let cur = self.rx_ring_base & 0x0000_0000_FFFF_FFFF;
                self.rx_ring_base = cur | ((value as u64) << 32);
            }
            E1000_REG_RDT => {
                self.rdt = value;
                self.shadow_u32_write(E1000_REG_RDT, value);
            }
            E1000_REG_TDBAL => {
                let cur = self.tx_ring_base & 0xFFFF_FFFF_0000_0000;
                self.tx_ring_base = cur | (value as u64);
            }
            E1000_REG_TDBAH => {
                let cur = self.tx_ring_base & 0x0000_0000_FFFF_FFFF;
                self.tx_ring_base = cur | ((value as u64) << 32);
            }
            E1000_REG_TDT => {
                self.tdt = value;
                self.shadow_u32_write(E1000_REG_TDT, value);
                self.drain_tx(value);
            }
            _ => self.shadow_u32_write(offset, value),
        }
    }
}

// ============================================================
// Locked kernel-banner harness.
// ============================================================

/// Locked MAC address used by the kernel banner's `init` round-trip.
/// Distinct from the locked MAC in the virtio_net banner so a morph
/// that swaps the EEPROM word order is byte-detectable in the QEMU
/// log (the printed MAC differs).
pub const BANNER_MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];

/// Locked 64-byte Ethernet frame used by the kernel banner's
/// transmit + receive round-trip. The first 6 bytes are the
/// destination MAC (broadcast), the next 6 are the source MAC
/// (`BANNER_MAC`), the next 2 are EtherType = 0x0800 (IPv4), and
/// the remaining 50 bytes are a recognisable byte pattern (`0xC0 ..
/// 0xC0 + 50`). Any morph that perturbs the descriptor's `length`
/// field, the `addr` field, the buffer-copy loop, or the wraparound
/// modulus on `tx_tail` will produce a mismatched capture and the
/// banner's `assert!` panics.
pub fn build_banner_frame() -> [u8; 64] {
    let mut frame = [0u8; 64];
    // Destination MAC = broadcast.
    frame[0..6].copy_from_slice(&[0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]);
    // Source MAC.
    frame[6..12].copy_from_slice(&BANNER_MAC);
    // EtherType = 0x0800 (IPv4) in network byte order.
    frame[12] = 0x08;
    frame[13] = 0x00;
    // Payload: 0xC0, 0xC1, ... 0xF1 (50 bytes).
    for i in 0..50 {
        frame[14 + i] = 0xC0u8.wrapping_add(i as u8);
    }
    frame
}

/// Run the full TASK-056 banner sequence: build a bus pre-seeded
/// with `BANNER_MAC`, init the driver, transmit one banner frame,
/// inject the same frame into the RX ring, receive it, assert
/// every byte round-tripped. Returns the recovered MAC and the
/// number of received bytes — the banner emitter format-prints
/// both.
///
/// On any byte-level drift (descriptor packing, EEPROM word order,
/// ring wraparound, length field, EOP flag) the assertions panic
/// inside this fn — surfacing the failure in the QEMU log as a
/// `PANIC` banner instead of the expected `E1000 ...` lines.
pub fn run_banner_round_trip() -> ([u8; 6], usize) {
    let mut driver = E1000Impl::new();
    let mut bus = MemMmioBus::new(BANNER_MAC);
    let mut mac = [0u8; 6];
    match driver.init(&mut bus, &mut mac) {
        Ok(()) => {}
        Err(_) => panic!("e1000: init failed"),
    }
    if mac != BANNER_MAC {
        panic!("e1000: MAC drift");
    }
    if driver.mac_address() != BANNER_MAC {
        panic!("e1000: cached MAC drift");
    }
    if driver.link_state() != LinkState::Up1000 {
        panic!("e1000: link state drift");
    }
    let frame = build_banner_frame();
    match driver.transmit(&mut bus, &frame) {
        Ok(()) => {}
        Err(_) => panic!("e1000: transmit failed"),
    }
    // The bus captured the frame — assert byte-equivalence.
    let caps = bus.tx_captures();
    if caps.len() != 1 || caps[0].len != frame.len() {
        panic!("e1000: TX capture count or length drift");
    }
    let mut tx_ok = true;
    for i in 0..frame.len() {
        if caps[0].bytes[i] != frame[i] {
            tx_ok = false;
            break;
        }
    }
    if !tx_ok {
        panic!("e1000: TX capture byte drift");
    }
    // Inject the same frame into RX and round-trip.
    if bus.inject_rx_frame(&frame).is_err() {
        panic!("e1000: RX inject failed");
    }
    let mut rx_buf = [0u8; 64];
    let rx_len = match driver.receive(&mut bus, &mut rx_buf) {
        Ok(Some(n)) => n,
        _ => panic!("e1000: receive failed"),
    };
    if rx_len != frame.len() {
        panic!("e1000: RX length drift");
    }
    for i in 0..rx_len {
        if rx_buf[i] != frame[i] {
            panic!("e1000: RX byte drift");
        }
    }
    (mac, rx_len)
}

// ============================================================
// Tests.
// ============================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_mac() -> [u8; 6] {
        [0x02, 0x00, 0xC0, 0xFF, 0xEE, 0x42]
    }

    // ---- descriptor packing ----

    #[test]
    fn tx_desc_round_trips() {
        let d = TxDesc {
            addr: 0x1234_5678_9ABC_DEF0,
            length: 0x1357,
            cso: 0xAA,
            cmd: E1000_TXD_CMD_EOP | E1000_TXD_CMD_IFCS | E1000_TXD_CMD_RS,
            sta: E1000_DESC_STA_DD,
            css: 0xBB,
            special: 0xC0DE,
        };
        let bytes = d.encode();
        let back = TxDesc::decode(&bytes);
        assert_eq!(back, d);
    }

    #[test]
    fn rx_desc_round_trips() {
        let d = RxDesc {
            addr: 0xFEDC_BA98_7654_3210,
            length: 0x0F0F,
            checksum: 0xABCD,
            status: E1000_DESC_STA_DD | E1000_RXD_STA_EOP,
            errors: 0x05,
            special: 0xDEAD,
        };
        let bytes = d.encode();
        let back = RxDesc::decode(&bytes);
        assert_eq!(back, d);
    }

    #[test]
    fn tx_desc_size_locked_to_16() {
        assert_eq!(core::mem::size_of::<TxDesc>(), 16);
    }

    #[test]
    fn rx_desc_size_locked_to_16() {
        assert_eq!(core::mem::size_of::<RxDesc>(), 16);
    }

    #[test]
    fn tx_desc_addr_little_endian_first() {
        let d = TxDesc { addr: 0x0102_0304_0506_0708, ..Default::default() };
        let b = d.encode();
        assert_eq!(b[0], 0x08);
        assert_eq!(b[7], 0x01);
    }

    #[test]
    fn tx_desc_cmd_at_byte_11() {
        let d = TxDesc { cmd: 0xAB, ..Default::default() };
        let b = d.encode();
        assert_eq!(b[11], 0xAB);
    }

    #[test]
    fn rx_desc_status_at_byte_12() {
        let d = RxDesc { status: 0x77, ..Default::default() };
        let b = d.encode();
        assert_eq!(b[12], 0x77);
    }

    // ---- EEPROM read state machine ----

    #[test]
    fn eeprom_word_round_trips() {
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.set_eeprom_mac([0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45]);
        let w0 = E1000Impl::read_eeprom_word(&mut bus, E1000_EEPROM_MAC_WORD0).unwrap();
        let w1 = E1000Impl::read_eeprom_word(&mut bus, E1000_EEPROM_MAC_WORD1).unwrap();
        let w2 = E1000Impl::read_eeprom_word(&mut bus, E1000_EEPROM_MAC_WORD2).unwrap();
        assert_eq!(w0, u16::from_le_bytes([0xAB, 0xCD]));
        assert_eq!(w1, u16::from_le_bytes([0xEF, 0x01]));
        assert_eq!(w2, u16::from_le_bytes([0x23, 0x45]));
    }

    #[test]
    fn eeprom_mac_recovery() {
        let mut bus = MemMmioBus::new(fixture_mac());
        let mac = E1000Impl::read_mac_from_eeprom(&mut bus).unwrap();
        assert_eq!(mac, fixture_mac());
    }

    #[test]
    fn eeprom_rejects_all_zero_mac() {
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.set_eeprom_mac([0u8; 6]);
        assert_eq!(
            E1000Impl::read_mac_from_eeprom(&mut bus),
            Err(E1000Error::BadEeprom)
        );
    }

    #[test]
    fn eeprom_rejects_all_ones_mac() {
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.set_eeprom_mac([0xFFu8; 6]);
        assert_eq!(
            E1000Impl::read_mac_from_eeprom(&mut bus),
            Err(E1000Error::BadEeprom)
        );
    }

    #[test]
    fn eeprom_rejects_multicast_mac() {
        let mut bus = MemMmioBus::new(fixture_mac());
        // First octet has the multicast bit set.
        bus.set_eeprom_mac([0x01, 0x02, 0x03, 0x04, 0x05, 0x06]);
        assert_eq!(
            E1000Impl::read_mac_from_eeprom(&mut bus),
            Err(E1000Error::BadEeprom)
        );
    }

    #[test]
    fn eeprom_timeout_path() {
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.force_eeprom_timeout();
        assert_eq!(
            E1000Impl::read_eeprom_word(&mut bus, E1000_EEPROM_MAC_WORD0),
            Err(E1000Error::MacReadFailed)
        );
    }

    #[test]
    fn eeprom_returns_zero_for_unmodelled_word() {
        let mut bus = MemMmioBus::new(fixture_mac());
        let w = E1000Impl::read_eeprom_word(&mut bus, 0x3F).unwrap();
        assert_eq!(w, 0);
    }

    // ---- link-state decode ----

    #[test]
    fn decode_link_down_when_lu_clear() {
        assert_eq!(E1000Impl::decode_link(0), LinkState::Down);
    }

    #[test]
    fn decode_link_10mbit() {
        let s = E1000_STATUS_LU; // SPEED = 0b00
        assert_eq!(E1000Impl::decode_link(s), LinkState::Up10);
    }

    #[test]
    fn decode_link_100mbit() {
        let s = E1000_STATUS_LU | (0b01u32 << E1000_STATUS_SPEED_SHIFT);
        assert_eq!(E1000Impl::decode_link(s), LinkState::Up100);
    }

    #[test]
    fn decode_link_1000mbit_via_0b10() {
        let s = E1000_STATUS_LU | (0b10u32 << E1000_STATUS_SPEED_SHIFT);
        assert_eq!(E1000Impl::decode_link(s), LinkState::Up1000);
    }

    #[test]
    fn decode_link_1000mbit_via_0b11() {
        let s = E1000_STATUS_LU | (0b11u32 << E1000_STATUS_SPEED_SHIFT);
        assert_eq!(E1000Impl::decode_link(s), LinkState::Up1000);
    }

    // ---- driver bring-up ----

    #[test]
    fn init_recovers_mac_and_caches_link() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).expect("init");
        assert_eq!(mac, fixture_mac());
        assert_eq!(driver.mac_address(), fixture_mac());
        assert_eq!(driver.link_state(), LinkState::Up1000);
    }

    #[test]
    fn init_programs_rx_ring_base() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        assert_eq!(bus.rx_ring_base(), driver.rx_ring_addr());
    }

    #[test]
    fn init_programs_tx_ring_base() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        assert_eq!(bus.tx_ring_base(), driver.tx_ring_addr());
    }

    #[test]
    fn init_sets_rdt_to_ring_len_minus_one() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        assert_eq!(bus.rdt() as usize, E1000_RX_RING_LEN - 1);
    }

    #[test]
    fn init_idempotent_repeats_bring_up_safely() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        // Second init must also succeed.
        let mut mac2 = [0u8; 6];
        driver.init(&mut bus, &mut mac2).unwrap();
        assert_eq!(mac2, fixture_mac());
        assert_eq!(driver.tx_tail, 0);
        assert_eq!(driver.rx_next, 0);
    }

    #[test]
    fn init_rejects_mmio_fault() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.force_mmio_fault();
        let mut mac = [0u8; 6];
        assert_eq!(
            driver.init(&mut bus, &mut mac),
            Err(E1000Error::MmioFault)
        );
    }

    #[test]
    fn init_rejects_reset_hang() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.force_reset_hang();
        let mut mac = [0u8; 6];
        // Reset spin will time out and the driver should surface
        // it as MmioFault (the bounded loop can't tell the
        // difference between "device fell off" and "device hung").
        assert_eq!(
            driver.init(&mut bus, &mut mac),
            Err(E1000Error::MmioFault)
        );
    }

    #[test]
    fn init_rejects_eeprom_timeout() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.force_eeprom_timeout();
        let mut mac = [0u8; 6];
        assert_eq!(
            driver.init(&mut bus, &mut mac),
            Err(E1000Error::MacReadFailed)
        );
    }

    #[test]
    fn init_with_status_down_caches_link_down() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.set_status(0); // LU clear
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        assert_eq!(driver.link_state(), LinkState::Down);
    }

    // ---- transmit ----

    #[test]
    fn transmit_before_init_returns_nolink() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let frame = [0xAAu8; 32];
        assert_eq!(
            driver.transmit(&mut bus, &frame),
            Err(E1000Error::NoLink)
        );
    }

    #[test]
    fn transmit_empty_frame_rejected() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        assert_eq!(
            driver.transmit(&mut bus, &[]),
            Err(E1000Error::FrameLengthInvalid)
        );
    }

    #[test]
    fn transmit_oversized_frame_rejected() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let too_big = [0u8; E1000_MAX_FRAME_LEN + 1];
        assert_eq!(
            driver.transmit(&mut bus, &too_big),
            Err(E1000Error::FrameLengthInvalid)
        );
    }

    #[test]
    fn transmit_when_link_down_returns_nolink() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        bus.set_status(0);
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let frame = [0xAA; 32];
        assert_eq!(
            driver.transmit(&mut bus, &frame),
            Err(E1000Error::NoLink)
        );
    }

    #[test]
    fn transmit_one_frame_round_trips_through_capture() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let frame = build_banner_frame();
        driver.transmit(&mut bus, &frame).unwrap();
        let caps = bus.tx_captures();
        assert_eq!(caps.len(), 1);
        assert_eq!(caps[0].len, frame.len());
        assert_eq!(&caps[0].bytes[..frame.len()], &frame[..]);
    }

    #[test]
    fn transmit_advances_tdt_by_one() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let frame = [0x55u8; 64];
        driver.transmit(&mut bus, &frame).unwrap();
        assert_eq!(bus.tdt(), 1);
    }

    #[test]
    fn transmit_wraps_tdt_at_ring_len() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let frame = [0x33u8; 64];
        for _ in 0..E1000_TX_RING_LEN {
            driver.transmit(&mut bus, &frame).unwrap();
        }
        // After RING_LEN transmits, TDT wrapped to 0.
        assert_eq!(bus.tdt(), 0);
    }

    #[test]
    fn transmit_ring_full_when_slot_not_done() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        // Manually clear the DD bit on the slot the driver will use
        // next so it sees the ring as full.
        let mut desc = TxDesc::decode(&driver.tx_ring[0]);
        desc.sta = 0;
        driver.tx_ring[0] = desc.encode();
        let frame = [0x44u8; 32];
        assert_eq!(
            driver.transmit(&mut bus, &frame),
            Err(E1000Error::RingFull)
        );
    }

    // ---- receive ----

    #[test]
    fn receive_before_init_returns_nolink() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut buf = [0u8; 64];
        assert_eq!(
            driver.receive(&mut bus, &mut buf),
            Err(E1000Error::NoLink)
        );
    }

    #[test]
    fn receive_empty_ring_returns_ok_none() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let mut buf = [0u8; 64];
        assert_eq!(driver.receive(&mut bus, &mut buf), Ok(None));
    }

    #[test]
    fn receive_one_frame_round_trip() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let frame = build_banner_frame();
        bus.inject_rx_frame(&frame).unwrap();
        let mut buf = [0u8; 64];
        let n = driver.receive(&mut bus, &mut buf).unwrap().unwrap();
        assert_eq!(n, frame.len());
        assert_eq!(&buf[..n], &frame[..]);
    }

    #[test]
    fn receive_buffer_too_small_surfaces_error() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let frame = build_banner_frame();
        bus.inject_rx_frame(&frame).unwrap();
        let mut buf = [0u8; 32]; // smaller than 64
        assert_eq!(
            driver.receive(&mut bus, &mut buf),
            Err(E1000Error::BufferTooSmall)
        );
    }

    #[test]
    fn receive_advances_rdt_to_consumed_slot() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        // Initial RDT is RING_LEN - 1 (init seed).
        assert_eq!(bus.rdt() as usize, E1000_RX_RING_LEN - 1);
        let frame = [0x88u8; 64];
        bus.inject_rx_frame(&frame).unwrap();
        let mut buf = [0u8; 64];
        driver.receive(&mut bus, &mut buf).unwrap();
        // After consuming slot 0, RDT lags by one — driver wrote 0.
        assert_eq!(bus.rdt(), 0);
    }

    #[test]
    fn receive_rejects_descriptor_without_eop() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        // Manually plant a descriptor with DD but not EOP.
        let mut desc = RxDesc::decode(&driver.rx_ring[0]);
        desc.status = E1000_DESC_STA_DD;
        desc.length = 32;
        driver.rx_ring[0] = desc.encode();
        let mut buf = [0u8; 64];
        assert_eq!(
            driver.receive(&mut bus, &mut buf),
            Err(E1000Error::BadDescriptor)
        );
    }

    #[test]
    fn receive_rejects_zero_length_descriptor() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let mut desc = RxDesc::decode(&driver.rx_ring[0]);
        desc.status = E1000_DESC_STA_DD | E1000_RXD_STA_EOP;
        desc.length = 0;
        driver.rx_ring[0] = desc.encode();
        let mut buf = [0u8; 64];
        assert_eq!(
            driver.receive(&mut bus, &mut buf),
            Err(E1000Error::BadDescriptor)
        );
    }

    #[test]
    fn receive_multiple_frames_in_order() {
        let mut driver = E1000Impl::new();
        let mut bus = MemMmioBus::new(fixture_mac());
        let mut mac = [0u8; 6];
        driver.init(&mut bus, &mut mac).unwrap();
        let f1 = [0x11u8; 48];
        let f2 = [0x22u8; 56];
        bus.inject_rx_frame(&f1).unwrap();
        bus.inject_rx_frame(&f2).unwrap();
        let mut buf = [0u8; 64];
        let n1 = driver.receive(&mut bus, &mut buf).unwrap().unwrap();
        assert_eq!(n1, 48);
        assert_eq!(&buf[..48], &f1[..]);
        let n2 = driver.receive(&mut bus, &mut buf).unwrap().unwrap();
        assert_eq!(n2, 56);
        assert_eq!(&buf[..56], &f2[..]);
    }

    // ---- banner round trip ----

    #[test]
    fn banner_round_trip_recovers_mac_and_length() {
        let (mac, n) = run_banner_round_trip();
        assert_eq!(mac, BANNER_MAC);
        assert_eq!(n, 64);
    }

    #[test]
    fn banner_frame_has_locked_layout() {
        let f = build_banner_frame();
        assert_eq!(&f[0..6], &[0xFF; 6]);
        assert_eq!(&f[6..12], &BANNER_MAC);
        assert_eq!(f[12], 0x08);
        assert_eq!(f[13], 0x00);
        assert_eq!(f[14], 0xC0);
        assert_eq!(f[63], 0xC0u8.wrapping_add(49));
    }
}
