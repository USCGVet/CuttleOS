//! Hardware rings, ACPI/UEFI/Multiboot2, storage (GPT/FAT32/JFS/AHCI), and timer/RTC contracts.
use crate::*;
// ============================================================
// Gpt — protective MBR + GPT header + entry (TASK-085)
// ============================================================

/// GPT header signature "EFI PART".
pub const GPT_SIG: [u8; 8] = *b"EFI PART";
/// Sector size assumed.
pub const GPT_SECTOR: usize = 512;
/// Partition entry size.
pub const GPT_ENTRY_LEN: usize = 128;
/// Protective MBR type for GPT.
pub const GPT_MBR_TYPE: u8 = 0xEE;

/// Parsed GPT header (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptHeader {
    /// LBA of this header (usually 1).
    pub my_lba: u64,
    /// First usable LBA.
    pub first_usable: u64,
    /// Last usable LBA.
    pub last_usable: u64,
    /// Partition entry LBA.
    pub part_lba: u64,
    /// Number of partition entries.
    pub num_parts: u32,
    /// Size of each entry.
    pub entry_size: u32,
}

/// One GPT partition entry view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GptPart {
    /// Starting LBA.
    pub start_lba: u64,
    /// Ending LBA (inclusive).
    pub end_lba: u64,
    /// True if type GUID is non-zero (present).
    pub present: bool,
}

/// GPT errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GptError {
    /// Image too short.
    Truncated,
    /// Bad protective MBR or GPT signature.
    BadMagic,
    /// Geometry inconsistent.
    BadGeometry,
}

/// GPT disk layout walker over a byte image (LBA-addressed).
pub trait Gpt {
    /// Parse GPT header at LBA 1; check protective MBR type at LBA 0.
    fn parse_header(image: &[u8]) -> Result<GptHeader, GptError>;
    /// Read partition entry `idx` (0-based).
    fn read_part(image: &[u8], hdr: &GptHeader, idx: u32) -> Result<GptPart, GptError>;
}

// ============================================================
// DnsName — RFC 1035 labels + compression pointer (TASK-086)
// ============================================================

/// Max labels in a name.
pub const DNS_MAX_LABELS: usize = 8;
/// Max label length.
pub const DNS_MAX_LABEL_LEN: usize = 63;
/// Compression pointer high bits.
pub const DNS_PTR_MASK: u8 = 0xC0;

/// DNS name codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsNameError {
    /// Truncated buffer.
    Truncated,
    /// Bad label length / pointer.
    BadLabel,
    /// Output too small.
    BufferTooSmall,
    /// Too many labels.
    TooMany,
}

/// DNS name wire codec (encode labels, decode with optional pointer).
pub trait DnsName {
    /// Encode `labels` (slices of ASCII) into wire form ending with 0.
    /// Returns bytes written.
    fn encode(labels: &[&[u8]], out: &mut [u8]) -> Result<usize, DnsNameError>;
    /// Decode name starting at `offset` in `msg` into `out_labels`
    /// (caller provides storage of up to DNS_MAX_LABELS × 64).
    /// Returns (label_count, bytes_consumed_from_offset_without_following_ptrs_past_start).
    fn decode(
        msg: &[u8],
        offset: usize,
        out_labels: &mut [[u8; 64]; DNS_MAX_LABELS],
        out_lens: &mut [usize; DNS_MAX_LABELS],
    ) -> Result<(usize, usize), DnsNameError>;
    /// Build a 2-byte compression pointer to `target_offset`.
    fn make_pointer(target_offset: u16) -> [u8; 2];
}

// ============================================================
// HmacDrbg — one-step HMAC-SHA256 expand KAT (TASK-087)
// ============================================================

/// Seed / key length for the DRBG KAT.
pub const DRBG_SEED_LEN: usize = 32;
/// Output length for banner KAT.
pub const DRBG_OUT_LEN: usize = 16;

/// HMAC-DRBG-shaped expand (HMAC-SHA256 chain).
pub trait HmacDrbg {
    /// `out = HMAC-SHA256(seed, label || 0x01)` truncated/padded to out.len().
    fn expand(seed: &[u8; DRBG_SEED_LEN], label: &[u8], out: &mut [u8]);
}

// ============================================================
// AhciFis — Register H2D FIS for ATA IDENTIFY / READ DMA (TASK-088)
// ============================================================

/// SATA FIS type: Register Host-to-Device.
pub const AHCI_FIS_TYPE_H2D: u8 = 0x27;
/// Register H2D FIS length in bytes (5 dwords).
pub const AHCI_FIS_H2D_LEN: usize = 20;
/// Command-update bit in FIS byte 1 (bit 7). When set, the device
/// treats the FIS as a new command (not a control-only update).
pub const AHCI_FIS_C_BIT: u8 = 1 << 7;
/// Port-multiplier port mask in FIS byte 1 (bits 3:0).
pub const AHCI_FIS_PMP_MASK: u8 = 0x0F;

/// ATA command: IDENTIFY DEVICE.
pub const ATA_CMD_IDENTIFY: u8 = 0xEC;
/// ATA command: READ DMA (28-bit LBA).
pub const ATA_CMD_READ_DMA: u8 = 0xC8;
/// ATA command: READ DMA EXT (48-bit LBA).
pub const ATA_CMD_READ_DMA_EXT: u8 = 0x25;
/// Device register: LBA addressing mode (bit 6).
pub const ATA_DEV_LBA: u8 = 0x40;

/// Parameters for a Register Host-to-Device FIS.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct H2dFisParams {
    /// ATA command opcode (e.g. [`ATA_CMD_IDENTIFY`]).
    pub command: u8,
    /// Features register (16-bit; low byte in FIS[3], high in FIS[11]).
    pub features: u16,
    /// Logical block address (48-bit used; upper bits of u64 ignored).
    pub lba: u64,
    /// Sector count (16-bit; low in FIS[12], high in FIS[13]).
    pub count: u16,
    /// Device/head register (typically [`ATA_DEV_LBA`]).
    pub device: u8,
    /// Port-multiplier port (0..=15).
    pub pm_port: u8,
    /// When true, set the C bit (command update).
    pub is_command: bool,
}

/// AHCI / SATA FIS codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciFisError {
    /// Output buffer shorter than [`AHCI_FIS_H2D_LEN`], or input truncated.
    Truncated,
    /// FIS type byte is not [`AHCI_FIS_TYPE_H2D`].
    BadType,
    /// Port-multiplier port out of range (> 15).
    BadPort,
}

/// AHCI Register Host-to-Device FIS encoder/decoder.
///
/// Locks the 20-byte SATA H2D layout so diversifier morphs cannot
/// silently reorder ATA command framing used by future AHCI drivers.
pub trait AhciFis {
    /// Encode `p` into a 20-byte Register H2D FIS at the start of `out`.
    /// Returns [`AHCI_FIS_H2D_LEN`] on success.
    fn encode_h2d(p: &H2dFisParams, out: &mut [u8]) -> Result<usize, AhciFisError>;
    /// Decode a Register H2D FIS from `fis` (must be ≥ 20 bytes).
    fn decode_h2d(fis: &[u8]) -> Result<H2dFisParams, AhciFisError>;
    /// Build params for ATA IDENTIFY DEVICE (`command = 0xEC`, C=1, LBA mode).
    fn identify(pm_port: u8) -> Result<H2dFisParams, AhciFisError>;
    /// Build params for ATA READ DMA (`command = 0xC8`, 28-bit LBA + count).
    fn read_dma(lba: u64, count: u16, pm_port: u8) -> Result<H2dFisParams, AhciFisError>;
}

// ============================================================
// XhciTrb — USB3 Transfer Request Block No-Op + Link (TASK-089)
// ============================================================

/// TRB size in bytes (4 dwords).
pub const XHCI_TRB_LEN: usize = 16;
/// TRB Type: Link.
pub const XHCI_TRB_TYPE_LINK: u8 = 6;
/// TRB Type: No-Op Transfer TRB.
pub const XHCI_TRB_TYPE_NOOP: u8 = 8;
/// Cycle bit in TRB dword 3 bit 0.
pub const XHCI_TRB_CYCLE: u32 = 1 << 0;
/// Toggle Cycle bit in Link TRB dword 3 bit 1.
pub const XHCI_TRB_TOGGLE_CYCLE: u32 = 1 << 1;
/// TRB Type field shift in dword 3 (bits 15:10).
pub const XHCI_TRB_TYPE_SHIFT: u32 = 10;

/// Four little-endian dwords of one TRB.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct XhciTrbWords {
    /// Parameter low / ring segment pointer low.
    pub d0: u32,
    /// Parameter high / ring segment pointer high.
    pub d1: u32,
    /// Status dword.
    pub d2: u32,
    /// Control dword (Cycle + Type + flags).
    pub d3: u32,
}

/// XHCI TRB codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum XhciTrbError {
    /// Buffer shorter than [`XHCI_TRB_LEN`].
    Truncated,
    /// Link ring pointer not 16-byte aligned.
    BadAlign,
}

/// xHCI Transfer Request Block encoder for No-Op and Link TRBs.
pub trait XhciTrb {
    /// Encode a No-Op Transfer TRB (`type = 8`) with the given cycle bit.
    fn encode_noop(cycle: bool) -> XhciTrbWords;
    /// Encode a Link TRB pointing at `ring_ptr` (must be 16-byte aligned).
    fn encode_link(
        ring_ptr: u64,
        cycle: bool,
        toggle_cycle: bool,
    ) -> Result<XhciTrbWords, XhciTrbError>;
    /// Extract TRB Type field from dword 3.
    fn trb_type(d3: u32) -> u8;
    /// Serialize words to 16 little-endian bytes.
    fn to_bytes(w: &XhciTrbWords, out: &mut [u8]) -> Result<usize, XhciTrbError>;
    /// Parse 16 little-endian bytes into words.
    fn from_bytes(buf: &[u8]) -> Result<XhciTrbWords, XhciTrbError>;
}

// ============================================================
// UefiGop — Graphics Output Protocol mode info view (TASK-090)
// ============================================================

/// Packed GOP mode info length (version, H, V, format, 4×mask, ppsl).
pub const GOP_MODE_INFO_LEN: usize = 40;
/// Pixel format: RGB reserved 8-bit per color.
pub const GOP_PIXEL_RGB: u32 = 0;
/// Pixel format: BGR reserved 8-bit per color.
pub const GOP_PIXEL_BGR: u32 = 1;
/// Pixel format: bit mask.
pub const GOP_PIXEL_BITMASK: u32 = 2;
/// Pixel format: Blt-only.
pub const GOP_PIXEL_BLT_ONLY: u32 = 3;

/// UEFI GOP mode information (subset of EFI_GRAPHICS_OUTPUT_MODE_INFORMATION).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GopModeInfo {
    /// Structure version (0 for current UEFI).
    pub version: u32,
    /// Horizontal resolution in pixels.
    pub horizontal: u32,
    /// Vertical resolution in pixels.
    pub vertical: u32,
    /// Pixel format enum ([`GOP_PIXEL_RGB`], …).
    pub pixel_format: u32,
    /// Red mask (bitmask format only; else 0).
    pub red_mask: u32,
    /// Green mask.
    pub green_mask: u32,
    /// Blue mask.
    pub blue_mask: u32,
    /// Reserved mask.
    pub reserved_mask: u32,
    /// Pixels per scan line (≥ horizontal).
    pub pixels_per_scan_line: u32,
}

/// GOP codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GopError {
    /// Buffer shorter than [`GOP_MODE_INFO_LEN`].
    Truncated,
    /// Geometry inconsistent (e.g. zero resolution).
    BadGeometry,
}

/// UEFI Graphics Output Protocol mode-info pack/unpack.
pub trait UefiGop {
    /// Pack mode info into little-endian bytes (40 bytes).
    fn encode(info: &GopModeInfo, out: &mut [u8]) -> Result<usize, GopError>;
    /// Unpack mode info from little-endian bytes.
    fn decode(buf: &[u8]) -> Result<GopModeInfo, GopError>;
    /// Canonical 1280×720 RGB mode used by the kernel banner.
    fn mode_1280x720() -> GopModeInfo;
}

// ============================================================
// AttestTlv — JSON-free type-length-value fields (TASK-091)
// ============================================================

/// TLV header size: u16 type + u16 length (little-endian).
pub const ATTEST_TLV_HDR_LEN: usize = 4;
/// Maximum value length accepted by the codec.
pub const ATTEST_TLV_MAX_VAL: usize = 256;
/// Max tags walked in one sequence parse.
pub const ATTEST_TLV_MAX_TAGS: usize = 32;
/// Example tag: morph cycle number.
pub const ATTEST_TLV_TAG_CYCLE: u16 = 1;
/// Example tag: layout seed.
pub const ATTEST_TLV_TAG_SEED: u16 = 2;
/// Example tag: module name bytes.
pub const ATTEST_TLV_TAG_MODULE: u16 = 3;

/// One decoded TLV record (value lives in the source buffer).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestTlvRecord {
    /// Type tag.
    pub tag: u16,
    /// Byte offset of value within the input buffer.
    pub value_off: usize,
    /// Value length in bytes.
    pub value_len: usize,
}

/// Attestation TLV errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AttestTlvError {
    /// Truncated header or value.
    Truncated,
    /// Value length exceeds [`ATTEST_TLV_MAX_VAL`].
    ValueTooLong,
    /// Output buffer too small.
    BufferTooSmall,
    /// Too many tags in sequence.
    TooMany,
}

/// Minimal type-length-value codec for future attest v7 extension fields.
pub trait AttestTlv {
    /// Encode one TLV: `type(u16le) || len(u16le) || value`. Returns bytes written.
    fn encode(tag: u16, value: &[u8], out: &mut [u8]) -> Result<usize, AttestTlvError>;
    /// Decode the first TLV in `buf`.
    fn decode(buf: &[u8]) -> Result<AttestTlvRecord, AttestTlvError>;
    /// Count TLVs in a concatenated sequence (stops at end of `buf`).
    fn count_sequence(buf: &[u8]) -> Result<usize, AttestTlvError>;
}

// ============================================================
// Base64 — RFC 4648 standard alphabet (TASK-092)
// ============================================================

/// Base64 codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Base64Error {
    /// Output buffer too small.
    BufferTooSmall,
    /// Invalid alphabet character or padding.
    InvalidInput,
    /// Input length not valid for decode (mod 4).
    BadLength,
}

/// RFC 4648 Base64 encode/decode without allocation.
pub trait Base64 {
    /// Encode `input` into `out` (standard alphabet + `=` padding).
    /// Returns bytes written.
    fn encode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error>;
    /// Decode base64 `input` into `out`. Returns plaintext bytes written.
    fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error>;
    /// Exact encoded length for `n` input bytes (with padding).
    fn encoded_len(n: usize) -> usize;
}

// ============================================================
// AhciCmd — command list header + PRDT entry (TASK-093)
// ============================================================

/// AHCI command header size (8 dwords).
pub const AHCI_CMD_HDR_LEN: usize = 32;
/// Physical Region Descriptor Table entry size (4 dwords).
pub const AHCI_PRDT_LEN: usize = 16;
/// Command FIS length in dwords for Register H2D (20 bytes → 5).
pub const AHCI_CFL_H2D: u8 = 5;
/// PRDT IOC (interrupt on completion) bit in DW3 bit 31.
pub const AHCI_PRDT_IOC: u32 = 1 << 31;

/// AHCI command list entry (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciCmdHeader {
    /// Command FIS length in dwords (bits 4:0 of DW0); typically 5.
    pub cfl: u8,
    /// Write bit (host→device data).
    pub write: bool,
    /// Port multiplier port (0..=15).
    pub pmp: u8,
    /// Physical region descriptor table length (number of PRDTe).
    pub prdtl: u16,
    /// Physical region descriptor byte count (may be 0 until completion).
    pub prdbc: u32,
    /// Command table base address (128-byte aligned in hardware; not enforced here).
    pub ctba: u64,
}

/// One PRDT entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciPrdt {
    /// Data base address.
    pub dba: u64,
    /// Byte count (1..=4 MiB per AHCI; stored as true count, encoded as count−1).
    pub byte_count: u32,
    /// Interrupt on completion.
    pub ioc: bool,
}

/// AHCI command table codec errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AhciCmdError {
    /// Buffer truncated.
    Truncated,
    /// Invalid CFL / PRDTL / byte_count.
    BadField,
    /// Port out of range.
    BadPort,
}

/// AHCI command header + PRDT encoder for IDENTIFY DMA setup.
pub trait AhciCmd {
    /// Encode a 32-byte command header.
    fn encode_header(h: &AhciCmdHeader, out: &mut [u8]) -> Result<usize, AhciCmdError>;
    /// Decode a 32-byte command header.
    fn decode_header(buf: &[u8]) -> Result<AhciCmdHeader, AhciCmdError>;
    /// Encode a 16-byte PRDT entry.
    fn encode_prdt(p: &AhciPrdt, out: &mut [u8]) -> Result<usize, AhciCmdError>;
    /// Decode a 16-byte PRDT entry.
    fn decode_prdt(buf: &[u8]) -> Result<AhciPrdt, AhciCmdError>;
    /// Build header + single PRDT for IDENTIFY DEVICE DMA into `data_buf`.
    fn identify_slot(ctba: u64, data_buf: u64) -> Result<(AhciCmdHeader, AhciPrdt), AhciCmdError>;
}

// ============================================================
// IoApic — redirection table entry encode (TASK-083)
// ============================================================

/// Delivery mode: fixed.
pub const IOAPIC_DELIVERY_FIXED: u8 = 0;
/// Delivery mode: lowest priority.
pub const IOAPIC_DELIVERY_LOWEST: u8 = 1;
/// Delivery mode: SMI.
pub const IOAPIC_DELIVERY_SMI: u8 = 2;
/// Delivery mode: NMI.
pub const IOAPIC_DELIVERY_NMI: u8 = 4;
/// Delivery mode: INIT.
pub const IOAPIC_DELIVERY_INIT: u8 = 5;
/// Delivery mode: ExtINT.
pub const IOAPIC_DELIVERY_EXTINT: u8 = 7;
/// Destination mode: physical.
pub const IOAPIC_DEST_PHYSICAL: u8 = 0;
/// Destination mode: logical.
pub const IOAPIC_DEST_LOGICAL: u8 = 1;
/// Trigger: edge.
pub const IOAPIC_TRIGGER_EDGE: u8 = 0;
/// Trigger: level.
pub const IOAPIC_TRIGGER_LEVEL: u8 = 1;
/// Pin polarity: active high.
pub const IOAPIC_POLARITY_HIGH: u8 = 0;
/// Pin polarity: active low.
pub const IOAPIC_POLARITY_LOW: u8 = 1;
/// Mask bit set = masked.
pub const IOAPIC_MASKED: u8 = 1;

/// Decoded IOAPIC redirection table entry (low + high dwords).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IoApicRedir {
    /// Interrupt vector 0x10..=0xFE.
    pub vector: u8,
    /// Delivery mode (3 bits).
    pub delivery: u8,
    /// Destination mode (1 bit).
    pub dest_mode: u8,
    /// Polarity.
    pub polarity: u8,
    /// Trigger mode.
    pub trigger: u8,
    /// Mask bit.
    pub mask: u8,
    /// Destination APIC id (bits 56..63 of high dword).
    pub dest: u8,
}

/// IOAPIC redtable codec.
pub trait IoApic {
    /// Pack entry into (low, high) dwords.
    fn encode(e: &IoApicRedir) -> (u32, u32);
    /// Unpack (low, high) dwords.
    fn decode(low: u32, high: u32) -> IoApicRedir;
}

// ============================================================
// LapicIcr — ICR INIT/SIPI command builder (TASK-084)
// ============================================================

/// ICR delivery: Fixed.
pub const ICR_DELIVERY_FIXED: u32 = 0 << 8;
/// ICR delivery: INIT.
pub const ICR_DELIVERY_INIT: u32 = 5 << 8;
/// ICR delivery: Start-Up (SIPI).
pub const ICR_DELIVERY_SIPI: u32 = 6 << 8;
/// ICR level assert.
pub const ICR_LEVEL_ASSERT: u32 = 1 << 14;
/// ICR level deassert.
pub const ICR_LEVEL_DEASSERT: u32 = 0 << 14;
/// ICR trigger level.
pub const ICR_TRIGGER_LEVEL: u32 = 1 << 15;
/// ICR dest shorthand: no shorthand.
pub const ICR_DEST_NONE: u32 = 0 << 18;
/// ICR high dword dest shift (APIC id in bits 24..31 of ICR_HIGH).
pub const ICR_HIGH_DEST_SHIFT: u32 = 24;

/// Built ICR pair.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IcrCommand {
    /// ICR low dword (0x300).
    pub low: u32,
    /// ICR high dword (0x310).
    pub high: u32,
}

/// LAPIC ICR builder.
pub trait LapicIcr {
    /// Build INIT IPI to `apic_id` (assert then software sequences deassert).
    fn init(apic_id: u8) -> IcrCommand;
    /// Build SIPI with startup vector page (`vec` = pa >> 12, low 8 bits).
    fn sipi(apic_id: u8, startup_vec: u8) -> IcrCommand;
    /// Extract delivery mode field from low dword.
    fn delivery_of(low: u32) -> u32;
}

// ============================================================
// Multiboot2 info tag walker (TASK-079)
// ============================================================

/// Multiboot2 info total_size field is first u32.
pub const MB2_HEADER_LEN: usize = 8;
/// Tag header length (type + size).
pub const MB2_TAG_HDR_LEN: usize = 8;
/// End tag type.
pub const MB2_TAG_END: u32 = 0;
/// Basic memory info tag.
pub const MB2_TAG_BASIC_MEMINFO: u32 = 4;
/// Memory map tag.
pub const MB2_TAG_MMAP: u32 = 6;
/// Framebuffer tag.
pub const MB2_TAG_FRAMEBUFFER: u32 = 8;
/// Max tags walked.
pub const MB2_MAX_TAGS: usize = 16;

/// One Multiboot2 tag header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Mb2Tag {
    /// Tag type.
    pub typ: u32,
    /// Total tag size including header.
    pub size: u32,
    /// Byte offset of tag in the info block.
    pub offset: usize,
}

/// Multiboot2 errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mb2Error {
    /// Buffer too short.
    Truncated,
    /// total_size inconsistent / tag overflow.
    BadSize,
    /// Too many tags.
    TooMany,
}

/// Multiboot2 info-block tag walker.
pub trait Multiboot2 {
    /// Walk tags in `info` (starts with total_size + reserved).
    /// Fills `out`, returns count (excluding END tag).
    fn walk(
        info: &[u8],
        out: &mut [Mb2Tag; MB2_MAX_TAGS],
    ) -> Result<usize, Mb2Error>;
    /// Find first tag of `typ`.
    fn find(tags: &[Mb2Tag], typ: u32) -> Option<Mb2Tag>;
}

// ============================================================
// Crc32c — Castagnoli (TASK-080)
// ============================================================

/// CRC32-C reversed polynomial (Castagnoli).
pub const CRC32C_POLY_REV: u32 = 0x82F6_3B78;

/// CRC32-C (Castagnoli) hash.
pub trait Crc32c {
    /// Compute CRC32-C over `data` (init 0xFFFFFFFF, final XOR same).
    fn hash(data: &[u8]) -> u32;
}

// ============================================================
// AcpiRsdp — RSDP signature + checksum (TASK-081)
// ============================================================

/// RSDP signature "RSD PTR ".
pub const RSDP_SIG: [u8; 8] = *b"RSD PTR ";
/// RSDP v1 length (checksum coverage).
pub const RSDP_V1_LEN: usize = 20;
/// RSDP v2 extended length field offset.
pub const RSDP_LEN_OFF: usize = 20;

/// Parsed RSDP view (v1 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RsdpV1 {
    /// OEM id 6 bytes.
    pub oem_id: [u8; 6],
    /// Revision (0 = v1, 2 = v2).
    pub revision: u8,
    /// RSDT physical address.
    pub rsdt_addr: u32,
}

/// RSDP errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RsdpError {
    /// Too short.
    Truncated,
    /// Bad signature.
    BadSig,
    /// Checksum failed.
    BadChecksum,
}

/// ACPI RSDP parser.
pub trait AcpiRsdp {
    /// Parse and validate v1 fields (first 20 bytes checksum).
    fn parse_v1(bytes: &[u8]) -> Result<RsdpV1, RsdpError>;
    /// Compute 8-bit sum checksum over `bytes` (must be 0 for valid).
    fn checksum(bytes: &[u8]) -> u8;
}

// ============================================================
// FrameBitmap — fixed bitmap frame allocator codec (TASK-082)
// ============================================================

/// Max frames the seed bitmap tracks (4096 bits = 512 bytes).
pub const FRAME_BITMAP_BITS: usize = 4096;

/// Frame bitmap errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameBitmapError {
    /// Index out of range.
    Oob,
    /// No free frame.
    Exhausted,
    /// Double-free.
    AlreadyFree,
}

/// Bitmap frame allocator surface.
pub trait FrameBitmap {
    /// Mark all frames free.
    fn clear_all(&mut self);
    /// Mark frame `idx` used.
    fn alloc_at(&mut self, idx: usize) -> Result<(), FrameBitmapError>;
    /// Allocate lowest free frame index.
    fn alloc(&mut self) -> Result<usize, FrameBitmapError>;
    /// Free frame `idx`.
    fn free(&mut self, idx: usize) -> Result<(), FrameBitmapError>;
    /// True if frame is free.
    fn is_free(&self, idx: usize) -> Result<bool, FrameBitmapError>;
    /// Count of free frames.
    fn free_count(&self) -> usize;
}

// ============================================================
// Serial16550 — UART init / TX wire codec (TASK-075)
// ============================================================

/// COM1 base port.
pub const SERIAL_COM1: u16 = 0x3F8;
/// COM2 base port.
pub const SERIAL_COM2: u16 = 0x2F8;
/// Line Status Register offset from base.
pub const SERIAL_LSR_OFF: u16 = 5;
/// Line Control Register offset.
pub const SERIAL_LCR_OFF: u16 = 3;
/// FIFO Control Register offset.
pub const SERIAL_FCR_OFF: u16 = 2;
/// Modem Control Register offset.
pub const SERIAL_MCR_OFF: u16 = 4;
/// Interrupt Enable Register offset.
pub const SERIAL_IER_OFF: u16 = 1;
/// LSR bit 5: THR empty.
pub const SERIAL_LSR_THRE: u8 = 1 << 5;
/// LSR bit 0: data ready.
pub const SERIAL_LSR_DR: u8 = 1 << 0;
/// LCR DLAB bit.
pub const SERIAL_LCR_DLAB: u8 = 0x80;
/// LCR 8N1 value (DLAB off).
pub const SERIAL_LCR_8N1: u8 = 0x03;
/// Divisor latch low for 38400 baud (with 1.8432 MHz clock).
pub const SERIAL_DIVISOR_LO_38400: u8 = 0x03;
/// Divisor latch high for 38400.
pub const SERIAL_DIVISOR_HI_38400: u8 = 0x00;
/// FCR enable + clear + 14-byte trigger.
pub const SERIAL_FCR_INIT: u8 = 0xC7;
/// MCR DTR|RTS|OUT2.
pub const SERIAL_MCR_INIT: u8 = 0x0B;
/// Number of port writes in the locked init sequence.
pub const SERIAL_INIT_WRITES: usize = 7;

/// One recorded `out` in the init sequence.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SerialPortWrite {
    /// Absolute I/O port.
    pub port: u16,
    /// Byte written.
    pub value: u8,
}

/// 16550 UART wire codec over [`IoPort`].
pub trait Serial16550 {
    /// Emit the locked 38400 8N1 init sequence for `base` (COM1/COM2).
    /// Returns the number of writes (always [`SERIAL_INIT_WRITES`]).
    fn init(port: &mut dyn IoPort, base: u16) -> usize;
    /// Wait for THRE then write `byte` to THR (`base + 0`).
    fn write_byte(port: &mut dyn IoPort, base: u16, byte: u8);
}

// ============================================================
// TickSource — PIT / HPET mux (TASK-076)
// ============================================================

/// Which hardware counter backs the tick view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum TickKind {
    /// 8253/8254 PIT.
    Pit = 0,
    /// High Precision Event Timer.
    Hpet = 1,
}

/// Unified monotonic tick source.
pub trait TickSource {
    /// Select the active kind.
    fn select(&mut self, kind: TickKind);
    /// Currently selected kind.
    fn kind(&self) -> TickKind;
    /// Advance the synthetic counter by `delta` (test harness / IRQ).
    fn advance(&mut self, delta: u64);
    /// Current tick count for the selected source.
    fn now_ticks(&self) -> u64;
    /// Pet-friendly remaining helper: saturating sub of deadline.
    fn until(&self, deadline: u64) -> u64;
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

// ============================================================
// SigKat — Ed25519 RFC 8032 known-answer harness (TASK-078)
// ============================================================

/// Number of locked RFC 8032 vectors in the suite.
pub const SIGKAT_VECTOR_COUNT: u8 = 2;
/// Ed25519 public key length.
pub const SIGKAT_PK_LEN: usize = 32;
/// Ed25519 secret key length (seed).
pub const SIGKAT_SK_LEN: usize = 32;
/// Ed25519 signature length.
pub const SIGKAT_SIG_LEN: usize = 64;

/// One vector outcome.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigKatResult {
    /// Vector id 0..SIGKAT_VECTOR_COUNT.
    pub id: u8,
    /// True if all checks passed.
    pub pass: bool,
}

/// Aggregate suite result.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SigKatSuite {
    /// Total vectors.
    pub total: u8,
    /// Passed count.
    pub passed: u8,
}

impl SigKatSuite {
    /// All vectors passed.
    pub const fn all_ok(self) -> bool {
        self.passed == self.total
    }
}

/// Ed25519 known-answer harness (fixture integrity + structural
/// verify against published RFC 8032 bytes).
pub trait SigKat {
    /// Run the full locked suite.
    fn run_all() -> SigKatSuite;
    /// Run one vector by id.
    fn run_one(id: u8) -> Option<SigKatResult>;
}

// ============================================================
// Watchdog — software deadline arm/pet/check (TASK-071)
// ============================================================

/// Default deadline in ticks (300 = 3 s at 100 Hz; banner-friendly).
pub const WATCHDOG_DEFAULT_DEADLINE_TICKS: u32 = 300;

/// Watchdog errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WatchdogError {
    /// Not armed / disabled.
    NotArmed,
    /// Deadline already fired.
    Fired,
    /// Zero deadline rejected.
    ZeroDeadline,
}

/// Software watchdog against an injected tick counter.
pub trait Watchdog {
    /// Arm with `deadline_ticks` remaining. Rejects zero.
    fn arm(&mut self, deadline_ticks: u32) -> Result<(), WatchdogError>;
    /// Reset remaining to the armed deadline.
    fn pet(&mut self) -> Result<(), WatchdogError>;
    /// Advance one tick. Returns `Err(Fired)` when remaining hits 0.
    fn tick(&mut self) -> Result<(), WatchdogError>;
    /// Cooperative check — `Err(Fired)` if previously fired.
    fn check(&self) -> Result<(), WatchdogError>;
    /// Current remaining ticks (0 if fired or not armed).
    fn remaining(&self) -> u32;
    /// Armed deadline value.
    fn deadline(&self) -> u32;
    /// True if currently armed and not fired.
    fn is_armed(&self) -> bool;
}

// ============================================================
// Random — deterministic seed mixer / counter DRBG (TASK-072)
// ============================================================

/// Seed length in bytes.
pub const RANDOM_SEED_LEN: usize = 32;
/// Default output block length for KAT.
pub const RANDOM_BLOCK_LEN: usize = 16;

/// RNG errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RandomError {
    /// Not seeded yet.
    NotSeeded,
    /// Output buffer empty.
    EmptyOutput,
    /// Seed all-zero rejected.
    WeakSeed,
}

/// Deterministic CSPRNG-shaped mixer (ChaCha-inspired quarter rounds
/// over a 32-byte state). Locked KAT for morph detection.
pub trait Random {
    /// Seed from 32 bytes (must not be all-zero).
    fn seed(&mut self, seed: &[u8; RANDOM_SEED_LEN]) -> Result<(), RandomError>;
    /// Fill `out` with next pseudorandom bytes.
    fn fill(&mut self, out: &mut [u8]) -> Result<(), RandomError>;
    /// Next u64 (little-endian from 8 fill bytes).
    fn next_u64(&mut self) -> Result<u64, RandomError>;
}

// ============================================================
// Power — ACPI PM1a S5 soft-off encode (TASK-073)
// ============================================================

/// PM1 control SLP_EN bit (bit 13).
pub const PM1_SLP_EN: u16 = 1 << 13;
/// SLP_TYP field shift (bits 10..12).
pub const PM1_SLP_TYP_SHIFT: u16 = 10;
/// SLP_TYP field mask (3 bits).
pub const PM1_SLP_TYP_MASK: u16 = 0b111;
/// Classic S5 sleep type value used by many firmwares.
pub const SLP_TYP_S5: u8 = 5;
/// QEMU/Bochs ACPI PM1a_CNT default I/O port.
pub const PM1A_CNT_PORT: u16 = 0x604;

/// Encoded PM1 control register view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Pm1Control {
    /// Raw 16-bit PM1_CNT value.
    pub raw: u16,
}

/// Power management wire codec.
pub trait Power {
    /// Build PM1_CNT value for sleep type `slp_typ` with SLP_EN set.
    fn encode_s5(slp_typ: u8) -> Pm1Control;
    /// Extract SLP_TYP from a PM1_CNT value.
    fn decode_slp_typ(pm1: Pm1Control) -> u8;
    /// True if SLP_EN is set.
    fn is_slp_en(pm1: Pm1Control) -> bool;
}

// ============================================================
// Elf64 — ELF64 Ehdr + PT_LOAD walker (TASK-074)
// ============================================================

/// ELF magic.
pub const ELF_MAGIC: [u8; 4] = [0x7F, b'E', b'L', b'F'];
/// ELFCLASS64.
pub const ELF_CLASS64: u8 = 2;
/// ELFDATA2LSB.
pub const ELF_DATA_LE: u8 = 1;
/// EM_X86_64.
pub const ELF_EM_X86_64: u16 = 62;
/// ET_EXEC.
pub const ELF_ET_EXEC: u16 = 2;
/// ET_DYN.
pub const ELF_ET_DYN: u16 = 3;
/// PT_LOAD.
pub const ELF_PT_LOAD: u32 = 1;
/// Size of ELF64 Ehdr.
pub const ELF_EHDR_LEN: usize = 64;
/// Size of ELF64 Phdr.
pub const ELF_PHDR_LEN: usize = 56;
/// Max PT_LOAD segments the seed walker accepts.
pub const ELF_MAX_PHDRS: usize = 8;

/// Parsed ELF64 file header (subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfHeader {
    /// e_entry
    pub entry: u64,
    /// e_phoff
    pub phoff: u64,
    /// e_phnum
    pub phnum: u16,
    /// e_phentsize
    pub phentsize: u16,
    /// e_type
    pub etype: u16,
    /// e_machine
    pub machine: u16,
}

/// One PT_LOAD program header view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ElfPhdr {
    /// p_type (must be PT_LOAD for returned entries)
    pub ptype: u32,
    /// p_flags
    pub flags: u32,
    /// p_offset
    pub offset: u64,
    /// p_vaddr
    pub vaddr: u64,
    /// p_filesz
    pub filesz: u64,
    /// p_memsz
    pub memsz: u64,
    /// p_align
    pub align: u64,
}

/// ELF parse errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ElfError {
    /// Buffer too short.
    Truncated,
    /// Bad magic / class / endian / machine.
    BadHeader,
    /// phentsize/phnum out of range.
    BadPhdrs,
    /// Too many PT_LOAD segments.
    TooManyLoads,
}

/// ELF64 header + PT_LOAD walker.
pub trait Elf64 {
    /// Parse Ehdr from `image`.
    fn parse_header(image: &[u8]) -> Result<ElfHeader, ElfError>;
    /// Collect PT_LOAD phdrs into `out` (capacity [`ELF_MAX_PHDRS`]).
    /// Returns count written.
    fn load_phdrs(
        image: &[u8],
        hdr: &ElfHeader,
        out: &mut [ElfPhdr; ELF_MAX_PHDRS],
    ) -> Result<usize, ElfError>;
}

// ============================================================
// Hpet — High Precision Event Timer MMIO codec (TASK-067)
// ============================================================

/// General Capabilities & ID register (64-bit, low dword at this off).
pub const HPET_REG_CAP: usize = 0x000;
/// General Configuration register.
pub const HPET_REG_CONFIG: usize = 0x010;
/// Main counter value (64-bit, low dword).
pub const HPET_REG_MAIN_COUNTER: usize = 0x0F0;
/// Timer 0 configuration / capability register.
pub const HPET_REG_TIMER0_CONFIG: usize = 0x100;
/// Timer 0 comparator value (64-bit low dword).
pub const HPET_REG_TIMER0_COMPARATOR: usize = 0x108;

/// CONFIG bit 0: ENABLE_CNF — main counter runs when set.
pub const HPET_CFG_ENABLE: u32 = 1 << 0;
/// CAP bit 13: COUNT_SIZE_CAP — 64-bit main counter when set.
pub const HPET_CAP_COUNT_SIZE_64: u32 = 1 << 13;
/// Timer-N config bit 2: interrupt enable.
pub const HPET_TN_INT_ENB: u32 = 1 << 2;
/// Timer-N config bit 3: periodic mode (1) vs one-shot (0).
pub const HPET_TN_TYPE_PERIODIC: u32 = 1 << 3;
/// Timer-N config bit 6: allow software to set accumulator.
pub const HPET_TN_VAL_SET: u32 = 1 << 6;

/// Parsed HPET capability view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HpetCaps {
    /// Counter period in femtoseconds (from CAP bits 32..63).
    pub period_fs: u32,
    /// True if 64-bit main counter is supported.
    pub count_size_64: bool,
    /// Vendor ID from CAP bits 16..31.
    pub vendor_id: u16,
    /// Number of timers minus one (CAP bits 8..12) + 1 = timer count.
    pub num_timers: u8,
}

/// Errors from [`Hpet`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HpetError {
    /// CAP.COUNT_SIZE_CAP clear — seed requires 64-bit counter.
    Not64Bit,
    /// Period field was zero (illegal per HPET spec).
    BadPeriod,
    /// Comparator ticks computed as zero for the requested interval.
    BadInterval,
}

/// HPET MMIO wire codec over [`MmioRegBus`].
pub trait Hpet {
    /// Read and decode the CAP register pair into [`HpetCaps`].
    fn read_caps(bus: &mut dyn MmioRegBus) -> Result<HpetCaps, HpetError>;
    /// Enable the main counter (`CONFIG.ENABLE_CNF = 1`).
    fn enable(bus: &mut dyn MmioRegBus);
    /// Disable the main counter.
    fn disable(bus: &mut dyn MmioRegBus);
    /// Read the 64-bit main counter (low then high dword).
    fn read_counter(bus: &mut dyn MmioRegBus) -> u64;
    /// Program timer 0 as periodic with `comparator` ticks and enable.
    /// Returns the config dword written.
    fn program_timer0_periodic(
        bus: &mut dyn MmioRegBus,
        comparator: u64,
    ) -> Result<u32, HpetError>;
    /// Convert `period_ms` to comparator ticks given `period_fs`.
    /// `ticks = (period_ms * 1_000_000_000_000) / period_fs`  (ms→fs).
    fn ms_to_ticks(period_fs: u32, period_ms: u32) -> Result<u64, HpetError>;
}

// ============================================================
// StackCanary — SSP token surface (TASK-068)
// ============================================================

/// Length of a canary token in bytes.
pub const STACK_CANARY_LEN: usize = 8;

/// One minted canary token (8 bytes).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CanaryToken {
    /// Raw token bytes.
    pub bytes: [u8; STACK_CANARY_LEN],
}

/// Errors from [`StackCanary`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CanaryError {
    /// Stored token does not match expected.
    Mismatch,
    /// Seed was all-zero (rejected — weak canary).
    WeakSeed,
}

/// Stack-smashing protector token surface.
pub trait StackCanary {
    /// Mint a token from `seed` (must not be all-zero).
    fn mint(seed: &[u8; STACK_CANARY_LEN]) -> Result<CanaryToken, CanaryError>;
    /// Verify `got` equals `expected`.
    fn verify(expected: &CanaryToken, got: &CanaryToken) -> Result<(), CanaryError>;
    /// Fingerprint of a failed check: XOR of expected and got, as u64 LE.
    fn fail_fingerprint(expected: &CanaryToken, got: &CanaryToken) -> u64;
}

// ============================================================
// Keyboard — PS/2 set-1 scancode decoder (TASK-069)
// ============================================================

/// Set-1 make code for `A`.
pub const KBD_MAKE_A: u8 = 0x1E;
/// Set-1 break code for `A` (`make | 0x80`).
pub const KBD_BREAK_A: u8 = 0x9E;
/// Set-1 make code for `B`.
pub const KBD_MAKE_B: u8 = 0x30;
/// Set-1 break code for `B`.
pub const KBD_BREAK_B: u8 = 0xB0;
/// Extended prefix byte.
pub const KBD_PREFIX_E0: u8 = 0xE0;
/// Pause-sequence prefix.
pub const KBD_PREFIX_E1: u8 = 0xE1;
/// Left shift make.
pub const KBD_MAKE_LSHIFT: u8 = 0x2A;
/// Left shift break.
pub const KBD_BREAK_LSHIFT: u8 = 0xAA;
/// Enter make.
pub const KBD_MAKE_ENTER: u8 = 0x1C;
/// Escape make.
pub const KBD_MAKE_ESC: u8 = 0x01;
/// Backspace make.
pub const KBD_MAKE_BACKSPACE: u8 = 0x0E;

/// Logical key identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KeyCode {
    /// Letter A..=Z (stored as uppercase ASCII).
    Letter(u8),
    /// Digit '0'..='9'.
    Digit(u8),
    /// Enter / return.
    Enter,
    /// Escape.
    Escape,
    /// Backspace.
    Backspace,
    /// Space.
    Space,
    /// Left or right shift (indistinguished in set-1 bare).
    Shift,
    /// Left or right ctrl.
    Ctrl,
    /// Left or right alt.
    Alt,
    /// Arrow up (E0 48).
    ArrowUp,
    /// Arrow down (E0 50).
    ArrowDown,
    /// Arrow left (E0 4B).
    ArrowLeft,
    /// Arrow right (E0 4D).
    ArrowRight,
    /// Unrecognised / non-printable.
    Other(u8),
}

/// One decoded key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KeyEvent {
    /// Key identity.
    pub code: KeyCode,
    /// True = make (press), false = break (release).
    pub pressed: bool,
    /// ASCII byte if printable and pressed; else 0.
    pub ascii: u8,
}

/// Keyboard decoder errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KbError {
    /// Need more scancode bytes (prefix in flight).
    NeedMore,
    /// Byte stream produced no event (swallowed prefix/modifier).
    Consumed,
}

/// PS/2 set-1 scancode decoder.
pub trait Keyboard {
    /// Feed one scancode byte. Returns `Some(event)` when a complete
    /// make/break is decoded; `None` if the byte was a prefix or
    /// part of a multi-byte sequence still in flight.
    fn feed(&mut self, scancode: u8) -> Option<KeyEvent>;
    /// Reset prefix / modifier state.
    fn reset(&mut self);
}

// ============================================================
// Fat32 — BPB + root-dir walker (TASK-070)
// ============================================================

/// Sector size assumed by the seed FAT32 walker.
pub const FAT_SECTOR_SIZE: usize = 512;
/// Directory entry length.
pub const FAT_DIR_ENTRY_LEN: usize = 32;
/// BPB offset: bytes per sector (u16).
pub const FAT_BPB_BYTES_PER_SECTOR: usize = 11;
/// BPB offset: sectors per cluster (u8).
pub const FAT_BPB_SEC_PER_CLUS: usize = 13;
/// BPB offset: reserved sector count (u16).
pub const FAT_BPB_RESERVED: usize = 14;
/// BPB offset: number of FATs (u8).
pub const FAT_BPB_NUM_FATS: usize = 16;
/// BPB offset: FAT size in sectors (u32) at offset 36.
pub const FAT_BPB_FAT_SIZE_32: usize = 36;
/// BPB offset: root cluster (u32) at offset 44.
pub const FAT_BPB_ROOT_CLUSTER: usize = 44;
/// BPB offset: FS type string "FAT32   " at 82.
pub const FAT_BPB_FS_TYPE: usize = 82;
/// Dirent attribute byte offset.
pub const FAT_DIR_ATTR: usize = 11;
/// Dirent cluster high u16.
pub const FAT_DIR_CLUS_HI: usize = 20;
/// Dirent cluster low u16.
pub const FAT_DIR_CLUS_LO: usize = 26;
/// Dirent file size u32.
pub const FAT_DIR_SIZE: usize = 28;
/// Attribute: LFN entry.
pub const FAT_ATTR_LFN: u8 = 0x0F;
/// Attribute: directory.
pub const FAT_ATTR_DIR: u8 = 0x10;
/// Attribute: volume id.
pub const FAT_ATTR_VOLUME: u8 = 0x08;
/// End-of-chain threshold (masked 28-bit).
pub const FAT_EOC: u32 = 0x0FFF_FFF8;
/// Cluster number mask.
pub const FAT_CLUS_MASK: u32 = 0x0FFF_FFFF;

/// Parsed BIOS Parameter Block (FAT32 subset).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatBpb {
    /// Bytes per sector (must be 512 for the seed).
    pub bytes_per_sector: u16,
    /// Sectors per cluster.
    pub sectors_per_cluster: u8,
    /// Reserved sector count.
    pub reserved_sectors: u16,
    /// Number of FAT copies.
    pub num_fats: u8,
    /// FAT size in sectors.
    pub fat_size_sectors: u32,
    /// Root directory starting cluster.
    pub root_cluster: u32,
    /// First sector of FAT #0 (= reserved_sectors).
    pub fat_start: u32,
    /// First data sector (cluster 2).
    pub first_data_sector: u32,
}

/// One 8.3 directory entry view.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FatDirent {
    /// 11-byte 8.3 name (space-padded).
    pub name_83: [u8; 11],
    /// Attribute byte.
    pub attr: u8,
    /// Starting cluster.
    pub cluster: u32,
    /// File size in bytes.
    pub size: u32,
}

/// FAT32 walker errors.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FatError {
    /// Image too short.
    Truncated,
    /// Not a FAT32 BPB (bad signature / type string / geometry).
    BadBpb,
    /// Directory entry not found.
    NotFound,
    /// Path is a directory or volume label.
    NotFile,
    /// Output buffer too small.
    BufferTooSmall,
    /// Cluster chain broken / reserved.
    BadChain,
}

/// Read-only FAT32 BPB + root-directory walker over a byte image.
pub trait Fat32 {
    /// Parse BPB from sector 0 of `image`.
    fn mount(image: &[u8]) -> Result<Self, FatError>
    where
        Self: Sized;
    /// Superblock / layout view.
    fn bpb(&self) -> &FatBpb;
    /// Find an 8.3 name in the root directory (case-insensitive).
    fn lookup_root(&self, image: &[u8], name_83: &[u8; 11]) -> Result<FatDirent, FatError>;
    /// Read file body for a dirent into `out`. Returns bytes written.
    fn read_file(
        &self,
        image: &[u8],
        ent: &FatDirent,
        out: &mut [u8],
    ) -> Result<usize, FatError>;
}

// ============================================================
// Quota — per-uid disk quota wire codec (TASK-066)
// ============================================================

/// On-disk / in-memory record length in bytes.
pub const QUOTA_RECORD_LEN: usize = 32;
/// Maximum records a fixed-capacity table / scan will accept.
pub const QUOTA_MAX_RECORDS: usize = 256;
/// Sentinel limit meaning "unlimited" (never rejects on that resource).
pub const QUOTA_UNLIMITED: u64 = u64::MAX;

/// Byte offset of `uid` (u32 LE) within a record.
pub const QUOTA_OFF_UID: usize = 0;
/// Byte offset of `block_used` (u64 LE).
pub const QUOTA_OFF_BLOCK_USED: usize = 4;
/// Byte offset of `block_limit` (u64 LE).
pub const QUOTA_OFF_BLOCK_LIMIT: usize = 12;
/// Byte offset of `inode_used` (u32 LE).
pub const QUOTA_OFF_INODE_USED: usize = 20;
/// Byte offset of `inode_limit` (u32 LE).
pub const QUOTA_OFF_INODE_LIMIT: usize = 24;
/// Byte offset of `grace` (u32 LE) — Unix seconds when the soft-limit
/// grace period expires. Zero means no grace (hard fail immediately
/// once a soft limit is exceeded / hard-limit check only).
pub const QUOTA_OFF_GRACE: usize = 28;

/// One per-uid quota record. Storage-only; 32 bytes on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QuotaRecord {
    /// User id this record accounts for. Zero is a free / empty slot.
    pub uid: u32,
    /// Blocks currently charged to this uid.
    pub block_used: u64,
    /// Maximum blocks allowed. [`QUOTA_UNLIMITED`] = no block cap.
    pub block_limit: u64,
    /// Inodes currently charged.
    pub inode_used: u32,
    /// Maximum inodes allowed. `u32::MAX` = no inode cap.
    pub inode_limit: u32,
    /// Grace expiry as Unix epoch seconds. `0` = no grace window
    /// (any would-exceed is a hard reject).
    pub grace: u32,
}

/// Why a check-on-write rejected the request. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum QuotaReject {
    /// `block_used + delta > block_limit` (and grace expired or zero).
    BlockLimit = 1,
    /// `inode_used + delta > inode_limit` (and grace expired or zero).
    InodeLimit = 2,
    /// Grace period still open but the hard limit is already past
    /// (seed treats any would-exceed with grace==0 or grace<=now as
    /// hard; this variant surfaces an explicit grace-expired path).
    GraceExpired = 3,
}

/// Errors returned by [`Quota`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum QuotaError {
    /// Buffer shorter than one record, or scan past EOF mid-record.
    Truncated,
    /// Record count would exceed [`QUOTA_MAX_RECORDS`].
    TableFull,
    /// UID not present in the table / scan.
    NotFound,
    /// UID 0 used as a live record (reserved as free-slot sentinel).
    BadUid,
    /// Buffer length is not a multiple of [`QUOTA_RECORD_LEN`].
    BadLength,
}

/// Per-uid disk quota accounting surface.
///
/// # Locked invariants the verifier checks
///
/// 1. [`parse_record`](Quota::parse_record) / [`encode_record`](Quota::encode_record)
///    are inverse over any well-formed [`QuotaRecord`] with
///    `uid != 0`.
/// 2. [`scan`](Quota::scan) walks `buf` in [`QUOTA_RECORD_LEN`]-byte
///    strides and invokes the sink once per record with `uid != 0`.
/// 3. [`lookup`](Quota::lookup) returns the first record whose `uid`
///    matches, or [`QuotaError::NotFound`].
/// 4. [`check_write`](Quota::check_write) returns `Ok(())` when both
///    block and inode deltas fit under the limits (or the limit is
///    unlimited); returns `Err(QuotaReject::*)` on exceed when
///    `grace == 0` or `grace <= now_unix`.
///
/// Pure codec + predicate — no disk I/O, no allocator. A higher
/// layer loads the quotafile bytes and calls these methods.
pub trait Quota {
    /// Decode one 32-byte record.
    fn parse_record(buf: &[u8]) -> Result<QuotaRecord, QuotaError>;

    /// Encode one record into a 32-byte buffer.
    fn encode_record(rec: &QuotaRecord, out: &mut [u8]) -> Result<(), QuotaError>;

    /// Walk every live (`uid != 0`) record in `buf`. Returns the
    /// number of live records visited.
    fn scan(buf: &[u8], sink: &mut dyn FnMut(QuotaRecord)) -> Result<usize, QuotaError>;

    /// Find the first record for `uid` in `buf`.
    fn lookup(buf: &[u8], uid: u32) -> Result<QuotaRecord, QuotaError>;

    /// Would charging `block_delta` blocks and `inode_delta` inodes
    /// to `rec` succeed at wall-clock `now_unix`?
    fn check_write(
        rec: &QuotaRecord,
        block_delta: u64,
        inode_delta: u32,
        now_unix: u32,
    ) -> Result<(), QuotaReject>;
}

// ============================================================
// GdbStub — GDB Remote Serial Protocol wire codec (TASK-065)
// ============================================================

/// ACK byte the stub emits after a well-framed packet (`+`).
pub const GDB_ACK: u8 = b'+';
/// NACK byte the stub emits on a bad checksum (`-`).
pub const GDB_NACK: u8 = b'-';
/// Packet start delimiter (`$`).
pub const GDB_PACKET_START: u8 = b'$';
/// Packet end delimiter (`#`), followed by two hex checksum digits.
pub const GDB_PACKET_END: u8 = b'#';
/// Ctrl-C interrupt byte gdb sends to halt the target.
pub const GDB_INTERRUPT: u8 = 0x03;
/// Maximum packet body length we advertise via `qSupported`
/// (`PacketSize=400`).
pub const GDB_MAX_BODY: usize = 400;
/// Hex-character length of a `g` (read-registers) reply: 16 GPRs ×
/// 8 bytes × 2 hex digits = 256.
pub const GDB_REG_HEX_LEN: usize = 256;
/// Maximum `m addr,len` length the stub will accept.
pub const GDB_MAX_MEM_READ: u64 = 256;
/// SIGTRAP stop-reason byte used in `S05` replies for `?` / `c` / `s`.
pub const GDB_SIGTRAP: u8 = 0x05;

/// View of one well-framed RSP packet. The body slice borrows from
/// the caller's input buffer (bytes between `$` and `#`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GdbPacket<'a> {
    /// Payload bytes between `$` and `#` (may be empty).
    pub body: &'a [u8],
    /// Decoded 8-bit checksum from the two hex digits after `#`.
    pub checksum: u8,
}

/// Classified RSP command. Discriminants are part of the locked
/// surface so a morph cannot silently reclassify a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdbCommand {
    /// `g` — read all general-purpose registers.
    ReadRegisters,
    /// `G…` — write all registers (stub accepts, replies `OK`).
    WriteRegisters,
    /// `m addr,len` — read memory.
    ReadMemory {
        /// Start address (hex-decoded).
        addr: u64,
        /// Length in bytes (hex-decoded).
        len: u64,
    },
    /// `M addr,len:data` — write memory (stub refuses with `E01`).
    WriteMemory,
    /// `Z0,addr,kind` — set software breakpoint (stub replies `OK`).
    SetBreakpoint {
        /// Breakpoint address.
        addr: u64,
    },
    /// `c` — continue.
    Continue,
    /// `s` — single step.
    Step,
    /// `D` — detach.
    Detach,
    /// `?` — query halt reason.
    HaltReason,
    /// `qSupported…` — feature negotiation.
    QuerySupported,
    /// `vMustReplyEmpty` — gdb handshake probe (empty reply).
    VMustReplyEmpty,
    /// `qC` — current thread.
    QueryCurrentThread,
    /// `+` ACK (standalone, not a `$…#` packet).
    Ack,
    /// `-` NACK.
    Nack,
    /// `0x03` interrupt.
    Interrupt,
    /// Recognised but empty / unknown payload — empty reply.
    Empty,
    /// Unclassified payload — empty reply.
    Unknown,
}

/// Errors returned by [`GdbStub`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GdbError {
    /// Buffer shorter than the minimum frame (`$#00` = 4 bytes) or
    /// missing delimiters.
    Truncated,
    /// Frame does not start with `$` or end with `#` + two hex digits.
    BadFraming,
    /// Checksum hex digits are not valid hex, or the decoded sum
    /// does not match the body XOR-sum (actually modular sum).
    BadChecksum,
    /// Output buffer too small for the framed packet.
    BufferTooSmall,
    /// Body longer than [`GDB_MAX_BODY`].
    BodyTooLong,
    /// `m` / `Z` argument parse failure (missing comma, bad hex).
    BadArgs,
}

/// GDB Remote Serial Protocol wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`checksum`](GdbStub::checksum) equals the 8-bit wrapping sum
///    of every body byte (not XOR — the RSP spec uses unsigned sum).
/// 2. [`parse_frame`](GdbStub::parse_frame) on `$g#67` returns a
///    packet whose body is `b"g"` and whose checksum is `0x67`.
/// 3. [`build_frame`](GdbStub::build_frame) of body `b"g"` produces
///    exactly the four-byte sequence `$g#67` (plus no trailing junk
///    in the returned length).
/// 4. [`classify`](GdbStub::classify) maps `b"g"` →
///    [`GdbCommand::ReadRegisters`], `b"qSupported"` →
///    [`GdbCommand::QuerySupported`], `b"vMustReplyEmpty"` →
///    [`GdbCommand::VMustReplyEmpty`].
/// 5. [`reply_body`](GdbStub::reply_body) for `ReadRegisters` writes
///    exactly [`GDB_REG_HEX_LEN`] ASCII `'0'` bytes.
///
/// No live target halt, no INT3 rewrite, no memory probe — pure
/// codec. Composition with a serial port is a higher layer.
pub trait GdbStub {
    /// 8-bit wrapping sum of `body` bytes (RSP checksum).
    fn checksum(body: &[u8]) -> u8;

    /// Parse a complete `$body#cs` frame. Returns the body view +
    /// decoded checksum after validating the sum.
    fn parse_frame(frame: &[u8]) -> Result<GdbPacket<'_>, GdbError>;

    /// Frame `body` as `$body#cs` into `out`. Returns bytes written.
    fn build_frame(body: &[u8], out: &mut [u8]) -> Result<usize, GdbError>;

    /// Classify a packet body into a [`GdbCommand`].
    fn classify(body: &[u8]) -> GdbCommand;

    /// Build the **reply body** (not framed) for `cmd` into `out`.
    /// Returns bytes written. Memory-read replies are empty here
    /// (no live target); use a higher layer to fill hex data.
    fn reply_body(cmd: &GdbCommand, out: &mut [u8]) -> Result<usize, GdbError>;
}

// ============================================================
// JournalFs — on-disk JFS image walker (TASK-064)
// ============================================================

/// On-disk superblock magic: ASCII `JFS2`.
pub const JFS_MAGIC: [u8; 4] = *b"JFS2";
/// On-disk inode magic: ASCII `JINO`.
pub const JFS_INODE_MAGIC: [u8; 4] = *b"JINO";
/// Superblock format version carried after the magic.
pub const JFS_VERSION: u32 = 2;
/// Sector / block size in bytes. Fixed at 512 for the seed.
pub const JFS_SECTOR_SIZE: usize = 512;
/// Byte length of the parsed superblock header (leading portion of
/// sector 0). The rest of the sector is reserved / zero.
pub const JFS_SB_LEN: usize = 32;
/// Byte length of one on-disk inode.
pub const JFS_INODE_LEN: usize = 32;
/// Fixed directory-entry record length.
pub const JFS_DIRENT_LEN: usize = 32;
/// Maximum bytes of a directory-entry name (excluding NUL). Packed as
/// `inode(4) + name_len(1) + name(27)`.
pub const JFS_DIRENT_MAX_NAME: usize = 27;
/// Inodes packed per inode-table sector (`512 / 32 = 16`).
pub const JFS_INODES_PER_SECTOR: u32 = 16;
/// Root directory always lives at inode 1. Inode 0 is the null /
/// free sentinel and is never a real entry.
pub const JFS_ROOT_INODE: u32 = 1;
/// Inode kind: regular file.
pub const JFS_KIND_FILE: u8 = 0;
/// Inode kind: directory.
pub const JFS_KIND_DIR: u8 = 1;

// --- Superblock field offsets (within the first JFS_SB_LEN bytes) ---

/// Offset of the 4-byte magic.
pub const JFS_SB_OFF_MAGIC: usize = 0;
/// Offset of the u32 LE version.
pub const JFS_SB_OFF_VERSION: usize = 4;
/// Offset of the u32 LE block_size.
pub const JFS_SB_OFF_BLOCK_SIZE: usize = 8;
/// Offset of the u32 LE root_inode.
pub const JFS_SB_OFF_ROOT_INODE: usize = 12;
/// Offset of the u32 LE inode_count (number of inodes in the table,
/// including the unused slot 0).
pub const JFS_SB_OFF_INODE_COUNT: usize = 16;
/// Offset of the u32 LE inode_table_lba.
pub const JFS_SB_OFF_INODE_TABLE_LBA: usize = 20;
/// Offset of the u32 LE data_start_lba (first data sector).
pub const JFS_SB_OFF_DATA_START_LBA: usize = 24;
/// Offset of the u32 LE free_bitmap_lba (0 = none / not used by walker).
pub const JFS_SB_OFF_BITMAP_LBA: usize = 28;

// --- Inode field offsets ---

/// Offset of the 4-byte inode magic.
pub const JFS_INO_OFF_MAGIC: usize = 0;
/// Offset of the u32 LE size_bytes.
pub const JFS_INO_OFF_SIZE: usize = 4;
/// Offset of the u64 LE mtime_unix.
pub const JFS_INO_OFF_MTIME: usize = 8;
/// Offset of extents[0] (u32 LE sector number; 0 = unallocated).
pub const JFS_INO_OFF_EXTENT0: usize = 16;
/// Offset of extents[1].
pub const JFS_INO_OFF_EXTENT1: usize = 20;
/// Offset of extents[2].
pub const JFS_INO_OFF_EXTENT2: usize = 24;
/// Offset of the kind byte.
pub const JFS_INO_OFF_KIND: usize = 28;

// --- Dirent field offsets ---

/// Offset of the target inode number (u32 LE).
pub const JFS_DE_OFF_INODE: usize = 0;
/// Offset of the name length byte.
pub const JFS_DE_OFF_NAME_LEN: usize = 4;
/// Offset of the name bytes (up to [`JFS_DIRENT_MAX_NAME`]).
pub const JFS_DE_OFF_NAME: usize = 5;

/// Parsed superblock view. Storage-only; produced by
/// [`JournalFs::mount`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JfsSuperblock {
    /// Format version (must equal [`JFS_VERSION`] after a successful
    /// mount).
    pub version: u32,
    /// Block / sector size in bytes (must equal [`JFS_SECTOR_SIZE`]).
    pub block_size: u32,
    /// Root directory inode number (must equal [`JFS_ROOT_INODE`]).
    pub root_inode: u32,
    /// Number of inode slots in the table (including slot 0).
    pub inode_count: u32,
    /// LBA of the first inode-table sector.
    pub inode_table_lba: u32,
    /// LBA of the first data sector.
    pub data_start_lba: u32,
    /// LBA of the free-bitmap region, or 0 if absent.
    pub free_bitmap_lba: u32,
}

/// Parsed inode view. Storage-only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JfsInode {
    /// Inode number this view was loaded from.
    pub ino: u32,
    /// File / directory size in bytes.
    pub size_bytes: u32,
    /// Last-modification time (Unix seconds). Zero is valid.
    pub mtime_unix: u64,
    /// Up to three direct data-sector LBAs (0 = unused).
    pub extents: [u32; 3],
    /// [`JFS_KIND_FILE`] or [`JFS_KIND_DIR`].
    pub kind: u8,
}

impl JfsInode {
    /// True iff this inode is a regular file.
    pub const fn is_file(self) -> bool {
        self.kind == JFS_KIND_FILE
    }
    /// True iff this inode is a directory.
    pub const fn is_dir(self) -> bool {
        self.kind == JFS_KIND_DIR
    }
}

/// One directory entry view. The name slice borrows from a
/// caller-supplied scratch buffer filled by
/// [`JournalFs::read_dir`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JfsDirEntry<'a> {
    /// Target inode number.
    pub ino: u32,
    /// Entry name bytes (1..=[`JFS_DIRENT_MAX_NAME`]).
    pub name: &'a [u8],
}

/// Errors returned by [`JournalFs`]. Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JfsError {
    /// Image shorter than one sector, or a requested LBA falls off
    /// the end of the image.
    Truncated,
    /// Superblock magic is not [`JFS_MAGIC`].
    BadMagic,
    /// Superblock version is not [`JFS_VERSION`].
    BadVersion,
    /// Superblock `block_size` is not [`JFS_SECTOR_SIZE`].
    BadBlockSize,
    /// Superblock `root_inode` is not [`JFS_ROOT_INODE`], or
    /// `inode_count` is zero / exceeds the table capacity implied
    /// by image size.
    BadSuperblock,
    /// Inode magic is not [`JFS_INODE_MAGIC`], or the inode number
    /// is out of range / free (all-zero slot).
    BadInode,
    /// Directory entry has zero or over-long name, or the dir body
    /// is not a multiple of [`JFS_DIRENT_LEN`].
    BadDirent,
    /// `lookup` found no matching name.
    NotFound,
    /// Called a file-only operation on a directory, or vice versa.
    WrongKind,
    /// Caller-supplied output buffer is too small for the file body.
    BufferTooSmall,
    /// File size exceeds what three direct extents can address
    /// (`3 * JFS_SECTOR_SIZE`).
    FileTooLarge,
}

/// On-disk Journaled-FS image walker.
///
/// # Locked invariants the verifier checks
///
/// 1. [`mount`](JournalFs::mount) on a buffer whose first four bytes
///    are not [`JFS_MAGIC`] returns [`JfsError::BadMagic`]. A
///    well-formed image returns `Ok` with a superblock whose
///    `version == JFS_VERSION`, `block_size == JFS_SECTOR_SIZE`,
///    and `root_inode == JFS_ROOT_INODE`.
/// 2. [`read_inode`](JournalFs::read_inode) for inode 0 or an out-of-
///    range number returns [`JfsError::BadInode`]. A present inode
///    has magic [`JFS_INODE_MAGIC`] and a kind of
///    [`JFS_KIND_FILE`] or [`JFS_KIND_DIR`].
/// 3. [`read_dir`](JournalFs::read_dir) on a directory inode walks
///    fixed [`JFS_DIRENT_LEN`]-byte records and invokes the sink
///    once per non-zero inode entry, in on-disk order.
/// 4. [`lookup`](JournalFs::lookup) returns the first dirent whose
///    name equals the query byte-for-byte, or
///    [`JfsError::NotFound`].
/// 5. [`read_file`](JournalFs::read_file) concatenates the direct
///    extents up to `size_bytes` into the caller buffer and returns
///    the byte count. A buffer shorter than `size_bytes` returns
///    [`JfsError::BufferTooSmall`].
///
/// The seed is a **read-only walker** over a caller-supplied image
/// byte buffer — no allocator, no WAL, no free-bitmap mutation.
/// Composition with [`BlockDeviceVirtio`] is a higher layer that
/// fills the image buffer from sectors.
pub trait JournalFs {
    /// Parse and validate the superblock at the start of `image`.
    /// On success, subsequent methods may read inodes / dirs / files
    /// from the same `image` slice.
    fn mount(image: &[u8]) -> Result<Self, JfsError>
    where
        Self: Sized;

    /// Superblock captured at mount time.
    fn superblock(&self) -> &JfsSuperblock;

    /// Load inode `ino` from the inode table.
    fn read_inode(&self, image: &[u8], ino: u32) -> Result<JfsInode, JfsError>;

    /// Walk directory entries of `dir_ino`, calling `sink` once per
    /// live entry. Returns the number of entries visited.
    fn read_dir(
        &self,
        image: &[u8],
        dir_ino: u32,
        sink: &mut dyn FnMut(JfsDirEntry<'_>),
    ) -> Result<usize, JfsError>;

    /// Look up `name` inside directory `dir_ino`.
    fn lookup(&self, image: &[u8], dir_ino: u32, name: &[u8]) -> Result<u32, JfsError>;

    /// Read the full file body of `ino` into `out`. Returns bytes
    /// written (`== size_bytes` on success).
    fn read_file(&self, image: &[u8], ino: u32, out: &mut [u8]) -> Result<usize, JfsError>;
}

// ============================================================
// KatRunner — Known-Answer Test harness (TASK-063)
// ============================================================

/// Output length of every digest / PRK the suite asserts against.
/// SHA-256 and HMAC-SHA-256 both produce 32 bytes.
pub const KAT_DIGEST_LEN: usize = 32;

/// Number of locked vectors in the boot suite. Every
/// [`KatRunner::run_all`] implementation MUST exercise exactly this
/// many vectors, in [`KatId`] discriminant order.
///
/// Composition (locked):
/// - 3 × SHA-256 (FIPS 180-4 / RFC 6234): empty, `"abc"`, million-`a`
/// - 4 × HMAC-SHA-256 (RFC 4231 §4.2–§4.5): test cases 1–4
/// - 2 × HKDF-SHA-256 (RFC 5869 §A.1–§A.2): cases 1–2 (PRK + OKM)
pub const KAT_VECTOR_COUNT: u8 = 9;

/// Which crypto primitive a vector exercises. Discriminants are part
/// of the locked surface so a morph cannot silently reclassify a
/// vector (e.g. claim a SHA failure as an HMAC failure).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KatPrimitive {
    /// SHA-256 (FIPS 180-4).
    Sha256 = 0,
    /// HMAC-SHA-256 (RFC 2104 / RFC 4231).
    HmacSha256 = 1,
    /// HKDF-Extract + Expand over SHA-256 (RFC 5869).
    HkdfSha256 = 2,
}

/// Stable identity of one vector in the locked suite. Discriminant
/// values 0..[`KAT_VECTOR_COUNT`] are part of the wire-observable
/// surface (the kernel banner prints the count; a failed vector's
/// id lands in [`KatSuiteResult::first_fail`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum KatId {
    /// SHA-256 of the empty string.
    Sha256Empty = 0,
    /// SHA-256 of `"abc"`.
    Sha256Abc = 1,
    /// SHA-256 of one million ASCII `'a'` bytes.
    Sha256MillionA = 2,
    /// RFC 4231 test case 1.
    HmacRfc4231Case1 = 3,
    /// RFC 4231 test case 2.
    HmacRfc4231Case2 = 4,
    /// RFC 4231 test case 3.
    HmacRfc4231Case3 = 5,
    /// RFC 4231 test case 4.
    HmacRfc4231Case4 = 6,
    /// RFC 5869 test case 1 (PRK + OKM).
    HkdfRfc5869Case1 = 7,
    /// RFC 5869 test case 2 (PRK + OKM).
    HkdfRfc5869Case2 = 8,
}

impl KatId {
    /// Construct from the raw discriminant. Returns `None` if `raw`
    /// is outside `0..KAT_VECTOR_COUNT`.
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Sha256Empty),
            1 => Some(Self::Sha256Abc),
            2 => Some(Self::Sha256MillionA),
            3 => Some(Self::HmacRfc4231Case1),
            4 => Some(Self::HmacRfc4231Case2),
            5 => Some(Self::HmacRfc4231Case3),
            6 => Some(Self::HmacRfc4231Case4),
            7 => Some(Self::HkdfRfc5869Case1),
            8 => Some(Self::HkdfRfc5869Case2),
            _ => None,
        }
    }

    /// Primitive family this vector exercises.
    pub const fn primitive(self) -> KatPrimitive {
        match self {
            Self::Sha256Empty | Self::Sha256Abc | Self::Sha256MillionA => KatPrimitive::Sha256,
            Self::HmacRfc4231Case1
            | Self::HmacRfc4231Case2
            | Self::HmacRfc4231Case3
            | Self::HmacRfc4231Case4 => KatPrimitive::HmacSha256,
            Self::HkdfRfc5869Case1 | Self::HkdfRfc5869Case2 => KatPrimitive::HkdfSha256,
        }
    }

    /// Short stable name for serial banners / audit logs.
    pub const fn name(self) -> &'static str {
        match self {
            Self::Sha256Empty => "sha256_empty",
            Self::Sha256Abc => "sha256_abc",
            Self::Sha256MillionA => "sha256_million_a",
            Self::HmacRfc4231Case1 => "hmac_rfc4231_1",
            Self::HmacRfc4231Case2 => "hmac_rfc4231_2",
            Self::HmacRfc4231Case3 => "hmac_rfc4231_3",
            Self::HmacRfc4231Case4 => "hmac_rfc4231_4",
            Self::HkdfRfc5869Case1 => "hkdf_rfc5869_1",
            Self::HkdfRfc5869Case2 => "hkdf_rfc5869_2",
        }
    }

    /// Publication source citation.
    pub const fn source(self) -> &'static str {
        match self {
            Self::Sha256Empty | Self::Sha256Abc | Self::Sha256MillionA => "FIPS 180-4 / RFC 6234",
            Self::HmacRfc4231Case1
            | Self::HmacRfc4231Case2
            | Self::HmacRfc4231Case3
            | Self::HmacRfc4231Case4 => "RFC 4231",
            Self::HkdfRfc5869Case1 | Self::HkdfRfc5869Case2 => "RFC 5869",
        }
    }
}

/// One vector's outcome. Storage-only; no allocation. The expected
/// and actual digests are always [`KAT_DIGEST_LEN`] bytes for
/// SHA-256 / HMAC vectors; for HKDF vectors `expected`/`actual` hold
/// the PRK (32 bytes) and `okm_match` reports the expand step.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KatResult {
    /// Vector identity.
    pub id: KatId,
    /// True iff every asserted output matched the published answer.
    pub pass: bool,
    /// Actual primary digest / PRK produced by the implementation.
    pub actual: [u8; KAT_DIGEST_LEN],
    /// Expected primary digest / PRK from the published standard.
    pub expected: [u8; KAT_DIGEST_LEN],
    /// For HKDF vectors: whether the OKM (expand output) matched.
    /// For non-HKDF vectors: always `true` (unused).
    pub okm_match: bool,
}

/// Aggregate outcome of [`KatRunner::run_all`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KatSuiteResult {
    /// Always equal to [`KAT_VECTOR_COUNT`] on a conforming impl.
    pub total: u8,
    /// Number of vectors that passed.
    pub passed: u8,
    /// First failing vector, if any. `None` means the suite is clean.
    pub first_fail: Option<KatId>,
}

impl KatSuiteResult {
    /// True iff every vector passed.
    pub const fn all_ok(self) -> bool {
        self.passed == self.total && self.first_fail.is_none()
    }
}

/// Known-answer test harness for the kernel crypto primitives.
///
/// # Locked invariants the verifier checks
///
/// 1. [`run_all`](KatRunner::run_all) exercises exactly
///    [`KAT_VECTOR_COUNT`] vectors in [`KatId`] order 0..N-1.
/// 2. On a clean suite, `passed == total`, `first_fail == None`, and
///    `all_ok()` is true.
/// 3. On the first failing vector, `first_fail` equals that vector's
///    id and `passed` equals the count of vectors before it that
///    passed (the suite may continue or short-circuit — either is
///    allowed; the seed continues so the banner can report `passed`).
/// 4. [`run_one`](KatRunner::run_one) for each [`KatId`] returns a
///    [`KatResult`] whose `expected` field is the published digest
///    for that vector (byte-exact against the standard).
///
/// The harness is pure computation over fixed inputs — no I/O, no
/// allocation, no global state. A morph that perturbs SHA-256,
/// HMAC, or HKDF arithmetic fails a published vector in the same
/// cycle the morph is deployed.
pub trait KatRunner {
    /// Run every locked vector. Returns the aggregate result.
    fn run_all() -> KatSuiteResult;

    /// Run a single vector by id.
    fn run_one(id: KatId) -> KatResult;
}

// ============================================================
// PicTimer + Rtc — PIT 8253/8254 + MC146818 CMOS RTC (TASK-062)
// ============================================================

/// PIT command port (IBM PC architecture). Writes the channel /
/// access / mode / BCD command byte.
pub const PIT_CMD_PORT: u16 = 0x43;
/// PIT channel-0 data port. Divisor low then high after a command.
pub const PIT_CH0_PORT: u16 = 0x40;
/// PIT input clock frequency in Hz — fixed by IBM PC architecture
/// at ~1.193182 MHz (derived from the 14.31818 MHz crystal / 12).
pub const PIT_BASE_HZ: u32 = 1_193_182;
/// Command byte: channel 0, lobyte/hibyte access, mode 3 (square
/// wave generator), binary counting. Bit layout
/// `SC1 SC0 RW1 RW0 M2 M1 M0 BCD` = `00 11 011 0` = `0x36`.
pub const PIT_CMD_CH0_LOHI_MODE3_BIN: u8 = 0x36;

/// CMOS RTC index port. Writing selects the register; bit 7 is the
/// NMI-disable latch (legacy — leave clear so NMI policy is preserved).
pub const CMOS_INDEX_PORT: u16 = 0x70;
/// CMOS RTC data port. Read/write the register selected via
/// [`CMOS_INDEX_PORT`].
pub const CMOS_DATA_PORT: u16 = 0x71;

/// RTC register: seconds (0..=59).
pub const RTC_REG_SECONDS: u8 = 0x00;
/// RTC register: minutes (0..=59).
pub const RTC_REG_MINUTES: u8 = 0x02;
/// RTC register: hours (0..=23 or 1..=12 + PM bit).
pub const RTC_REG_HOURS: u8 = 0x04;
/// RTC register: day of month (1..=31).
pub const RTC_REG_DAY: u8 = 0x07;
/// RTC register: month (1..=12).
pub const RTC_REG_MONTH: u8 = 0x08;
/// RTC register: year within century (0..=99).
pub const RTC_REG_YEAR: u8 = 0x09;
/// RTC register: status A (bit 7 = Update In Progress).
pub const RTC_REG_STATUS_A: u8 = 0x0A;
/// RTC register: status B (bit 1 = 24-hour, bit 2 = binary mode).
pub const RTC_REG_STATUS_B: u8 = 0x0B;

/// Status-A bit 7: Update In Progress. Registers may be incoherent
/// while this bit is set.
pub const RTC_STATUS_A_UIP: u8 = 0x80;
/// Status-B bit 1: 24-hour clock when set; 12-hour when clear.
pub const RTC_STATUS_B_24H: u8 = 0x02;
/// Status-B bit 2: binary (binary=1) vs BCD (binary=0) encoding.
pub const RTC_STATUS_B_BINARY: u8 = 0x04;
/// Hours-register bit 7: PM indicator in 12-hour mode.
pub const RTC_HOUR_PM: u8 = 0x80;

/// Maximum spin iterations while waiting for UIP to clear. At the
/// RTC's 32.768 kHz crystal UIP self-clears in <2.4 µs; this budget
/// is generous for a slow emulator and bounded so a broken RTC
/// cannot hang the kernel forever.
pub const RTC_UIP_SPIN_BUDGET: u32 = 1_000_000;
/// Maximum consecutive raw-read pairs attempted for the RTC
/// consistency dance (two consecutive identical snapshots).
pub const RTC_CONSISTENCY_PASSES: u32 = 16;

/// Abstract 8-bit I/O-port surface. Caller-supplied so the seed's
/// [`PicTimer`] / [`Rtc`] codecs can be exercised against a
/// recording test harness AND against real `in`/`out` at kernel
/// runtime through the same trait surface.
pub trait IoPort {
    /// Write an 8-bit value to the given I/O port.
    fn write_u8(&mut self, port: u16, value: u8);
    /// Read an 8-bit value from the given I/O port.
    fn read_u8(&mut self, port: u16) -> u8;
}

/// Decomposed Gregorian wall-clock time recovered from the RTC,
/// plus the derived Unix epoch seconds. Year is full (e.g. 2026);
/// month + day are 1-based; hour / minute / second are 0-based.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RtcTimeView {
    /// Full Gregorian year (e.g. 2026).
    pub year: u32,
    /// Month 1..=12.
    pub month: u8,
    /// Day of month 1..=31.
    pub day: u8,
    /// Hour 0..=23 (always converted to 24-hour form).
    pub hour: u8,
    /// Minute 0..=59.
    pub minute: u8,
    /// Second 0..=59.
    pub second: u8,
    /// Seconds since the Unix epoch (1970-01-01T00:00:00Z).
    pub unix: u64,
}

/// Errors emitted by [`PicTimer::program_hz`] and [`Rtc::read_time`].
/// Locked variant set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TimerError {
    /// Caller requested `hz == 0` — a no-op that would hang any
    /// subsequent tick-based sleep, so it is rejected explicitly.
    ZeroHz,
    /// UIP bit stayed set for more than [`RTC_UIP_SPIN_BUDGET`]
    /// spins — RTC is absent or broken.
    UipTimeout,
    /// Two consecutive raw register snapshots never agreed across
    /// [`RTC_CONSISTENCY_PASSES`] attempts.
    InconsistentRead,
}

/// Programmable Interval Timer (8253/8254) channel-0 wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`program_hz`](PicTimer::program_hz) with `hz == 0` returns
///    [`TimerError::ZeroHz`] and issues **zero** port writes.
/// 2. For every non-zero `hz`, the method writes exactly three
///    bytes in order:
///    - `write_u8(PIT_CMD_PORT, PIT_CMD_CH0_LOHI_MODE3_BIN)`
///    - `write_u8(PIT_CH0_PORT, (divisor & 0xFF) as u8)`
///    - `write_u8(PIT_CH0_PORT, (divisor >> 8) as u8)`
///    where `divisor = (PIT_BASE_HZ / hz).clamp(1, u16::MAX)`.
/// 3. The returned `u16` equals that divisor.
///
/// No IRQ unmask, no tick counter, no sleep primitive — those are
/// scheduler / interrupt-handler surfaces layered on top of this
/// codec.
pub trait PicTimer {
    /// Program channel 0 to fire IRQ 0 at approximately `hz` Hz.
    /// Returns the 16-bit divisor written to the data port.
    fn program_hz(port: &mut dyn IoPort, hz: u32) -> Result<u16, TimerError>;
}

/// MC146818 CMOS Real-Time Clock wire codec.
///
/// # Locked invariants the verifier checks
///
/// 1. [`read_time`](Rtc::read_time) polls status-A until UIP clears
///    (or returns [`TimerError::UipTimeout`]), then reads the six
///    calendar registers + status-B, re-reading until two
///    consecutive snapshots match (or returns
///    [`TimerError::InconsistentRead`]).
/// 2. BCD vs binary is decided by status-B bit 2
///    ([`RTC_STATUS_B_BINARY`]); 12-hour vs 24-hour by bit 1
///    ([`RTC_STATUS_B_24H`]); the PM bit is bit 7 of the hours
///    register ([`RTC_HOUR_PM`]).
/// 3. Two-digit years map to 2000..=2079 for `year2 < 80`, else
///    1900..=1979 — covering the classic CMOS century window.
/// 4. [`RtcTimeView::unix`] equals the pure Gregorian conversion
///    of the decoded Y/M/D/H/Mi/S tuple (no timezone offset).
///
/// No HPET composition, no boot-snapshot atomics — those are
/// higher-level kernel services layered on top of this codec.
pub trait Rtc {
    /// Read the current wall-clock time as a decoded
    /// [`RtcTimeView`]. Performs the UIP + consistency dance.
    fn read_time(port: &mut dyn IoPort) -> Result<RtcTimeView, TimerError>;
}

