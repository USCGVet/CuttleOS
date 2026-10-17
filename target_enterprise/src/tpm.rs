//! TPM 2.0 client-side wire codec.
//!
//! Concrete [`proteus_contracts::Tpm`] implementation. Builds TCG-spec
//! command frames for `TPM2_Startup`, `TPM2_GetRandom`, `TPM2_PCR_Read`,
//! and `TPM2_PCR_Extend`, and parses the TPM 2.0 response header. The
//! codec is intentionally transport-agnostic — every function takes a
//! caller-supplied byte slice and returns the number of bytes written
//! or a [`proteus_contracts::TpmError`]; nothing here touches MMIO,
//! ACPI, the CRB/TIS control area, or any other device.
//!
//! Where the RustOSa donor `src/tpm.rs` couples the codec with the CRB
//! MMIO sequencer, this port keeps the surfaces orthogonal. A future
//! `target_enterprise::tpm_crb` driver would import [`TpmImpl`] and
//! feed the built frames to the CRB control registers; for now the
//! kernel banner exercises only the wire codec, which is the locked
//! contract.
//!
//! ## Why a separate trait
//!
//! Measured boot is one of Proteus's hard requirements — every cycle's
//! kernel ELF must be PCR-extended into a TPM bank before the
//! attestation log can vouch for the image. The wire codec is the
//! contract-locked half of that flow because every byte of every
//! command and every response is hashed into PCR 8 by the TPM itself;
//! a per-cycle morph that perturbs even one byte of the wire-format
//! would invalidate the PCR chain. Keeping the codec under the
//! [`proteus_contracts::Tpm`] surface means the verifier can reject
//! such a morph at the *trait* boundary rather than waiting for a
//! mismatched attestation quote at deploy time.

use proteus_contracts::{
    Tpm, TpmError, TpmResponseView, TPM_ALG_SHA1, TPM_ALG_SHA256, TPM_CC_GET_RANDOM,
    TPM_CC_PCR_EXTEND, TPM_CC_PCR_READ, TPM_CC_STARTUP, TPM_HEADER_LEN, TPM_MAX_PCR_INDEX,
    TPM_RS_PW, TPM_SHA1_DIGEST_LEN, TPM_SHA256_DIGEST_LEN, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS,
};

// ---------------------------------------------------------------------
// Locked wire lengths
// ---------------------------------------------------------------------

/// Locked wire length of a `TPM2_Startup` command. Header (10) + `TPM_SU` (2).
pub const TPM_STARTUP_CMD_LEN: usize = TPM_HEADER_LEN + 2;

/// Locked wire length of a `TPM2_GetRandom` command. Header (10) +
/// `bytesRequested` (2).
pub const TPM_GET_RANDOM_CMD_LEN: usize = TPM_HEADER_LEN + 2;

/// Locked wire length of a `TPM2_PCR_Read` command. Header (10) +
/// `TPML_PCR_SELECTION` (count u32 + one selection of 2 + 1 + 3 bytes).
pub const TPM_PCR_READ_CMD_LEN: usize = TPM_HEADER_LEN + 4 + 2 + 1 + PCR_SELECT_BITMAP_LEN;

/// Locked wire length of a `TPM2_PCR_Extend` command carrying one
/// SHA-256 digest. Header (10) + pcrHandle (4) + authSize (4) + session
/// (9) + digests.count (4) + hashAlg (2) + digest (32).
pub const TPM_PCR_EXTEND_SHA256_CMD_LEN: usize =
    TPM_HEADER_LEN + 4 + 4 + AUTH_SESSION_LEN + 4 + 2 + TPM_SHA256_DIGEST_LEN;

/// Locked wire length of a `TPM2_PCR_Extend` command carrying one
/// SHA-1 digest. Header (10) + pcrHandle (4) + authSize (4) + session
/// (9) + digests.count (4) + hashAlg (2) + digest (20).
pub const TPM_PCR_EXTEND_SHA1_CMD_LEN: usize =
    TPM_HEADER_LEN + 4 + 4 + AUTH_SESSION_LEN + 4 + 2 + TPM_SHA1_DIGEST_LEN;

/// Locked length of the password-authorization session block on the
/// wire. `sessionHandle u32 + nonceSize u16 + sessionAttributes u8 +
/// hmacSize u16 = 9 bytes`. The nonces and HMAC for the
/// password-session sentinel are zero-length, so the entire session
/// block reduces to the four length-prefix fields with the buffer-
/// less variants set to zero.
pub const AUTH_SESSION_LEN: usize = 9;

/// Locked length of the `pcrSelect` bitmap field inside a
/// `TPMS_PCR_SELECTION`. The TCG Platform Profile defines 24 PCRs
/// (0..=23), so a 3-byte bitmap covers every platform PCR. Each bit
/// `i` corresponds to PCR `(byte_index * 8) + bit_index`.
pub const PCR_SELECT_BITMAP_LEN: usize = 3;

/// Largest wire frame any of the locked command builders produces.
/// Used by `MaxTpmCommandBuf` so callers can stack-allocate a single
/// buffer that suits every command in this codec without sizing it by
/// hand.
pub const TPM_MAX_CMD_LEN: usize = TPM_PCR_EXTEND_SHA256_CMD_LEN;

// ---------------------------------------------------------------------
// Concrete impl
// ---------------------------------------------------------------------

/// Zero-sized concrete implementation of [`proteus_contracts::Tpm`].
///
/// The codec is stateless — every function in the trait is associated,
/// not method, so `TpmImpl` is a marker type whose value never needs
/// to be constructed at run time. A `MaxTpmCommandBuf` next door
/// allows the kernel banner to feed `TpmImpl` from a stack array of
/// the locked maximum size without naming a per-command const.
pub struct TpmImpl;

impl Tpm for TpmImpl {
    fn build_startup(out: &mut [u8], startup_type: u16) -> Result<usize, TpmError> {
        build_startup(out, startup_type)
    }

    fn build_get_random(out: &mut [u8], bytes_requested: u16) -> Result<usize, TpmError> {
        build_get_random(out, bytes_requested)
    }

    fn build_pcr_read(out: &mut [u8], pcr_index: u32) -> Result<usize, TpmError> {
        build_pcr_read(out, pcr_index)
    }

    fn build_pcr_extend(
        out: &mut [u8],
        pcr_index: u32,
        digest_alg: u16,
        digest: &[u8],
    ) -> Result<usize, TpmError> {
        build_pcr_extend(out, pcr_index, digest_alg, digest)
    }

    fn parse_response(buf: &[u8]) -> Result<TpmResponseView<'_>, TpmError> {
        parse_response(buf)
    }
}

/// Convenience newtype around an `[u8; TPM_MAX_CMD_LEN]` scratch
/// buffer that the kernel banner reuses across the four builders.
/// Acting as a small wrapper keeps the bare-array `[u8; 65]` from
/// proliferating through banner code.
#[derive(Clone)]
pub struct MaxTpmCommandBuf {
    bytes: [u8; TPM_MAX_CMD_LEN],
}

impl Default for MaxTpmCommandBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl MaxTpmCommandBuf {
    /// Construct an all-zero buffer of the locked maximum size.
    pub const fn new() -> Self {
        Self {
            bytes: [0u8; TPM_MAX_CMD_LEN],
        }
    }

    /// Borrow the entire underlying buffer mutably. Pass this to
    /// `Tpm::build_*` then slice the returned length yourself.
    pub fn as_mut(&mut self) -> &mut [u8] {
        &mut self.bytes
    }

    /// Borrow a sub-slice of length `len`. Panics if `len >
    /// TPM_MAX_CMD_LEN` so a runtime drift between the locked
    /// constant and the caller's expectation surfaces immediately.
    pub fn prefix(&self, len: usize) -> &[u8] {
        &self.bytes[..len]
    }
}

// ---------------------------------------------------------------------
// Big-endian writers
// ---------------------------------------------------------------------

/// Write `value` big-endian to `out[off..off+2]`. Returns
/// `BufferTooSmall` if the slice is short.
fn put_u16_be(out: &mut [u8], off: usize, value: u16) -> Result<(), TpmError> {
    if off + 2 > out.len() {
        return Err(TpmError::BufferTooSmall);
    }
    out[off] = (value >> 8) as u8;
    out[off + 1] = value as u8;
    Ok(())
}

/// Write `value` big-endian to `out[off..off+4]`. Returns
/// `BufferTooSmall` if the slice is short.
fn put_u32_be(out: &mut [u8], off: usize, value: u32) -> Result<(), TpmError> {
    if off + 4 > out.len() {
        return Err(TpmError::BufferTooSmall);
    }
    out[off] = (value >> 24) as u8;
    out[off + 1] = (value >> 16) as u8;
    out[off + 2] = (value >> 8) as u8;
    out[off + 3] = value as u8;
    Ok(())
}

/// Read `u16` big-endian from `buf[off..off+2]`. Caller has already
/// bounds-checked.
fn read_u16_be(buf: &[u8], off: usize) -> u16 {
    ((buf[off] as u16) << 8) | buf[off + 1] as u16
}

/// Read `u32` big-endian from `buf[off..off+4]`. Caller has already
/// bounds-checked.
fn read_u32_be(buf: &[u8], off: usize) -> u32 {
    ((buf[off] as u32) << 24)
        | ((buf[off + 1] as u32) << 16)
        | ((buf[off + 2] as u32) << 8)
        | buf[off + 3] as u32
}

// ---------------------------------------------------------------------
// Header writer
// ---------------------------------------------------------------------

/// Write the 10-byte TPM 2.0 command header `(tag, commandSize,
/// commandCode)` to `out[0..10]` big-endian.
fn write_header(out: &mut [u8], tag: u16, size: u32, command_code: u32) -> Result<(), TpmError> {
    if out.len() < TPM_HEADER_LEN {
        return Err(TpmError::BufferTooSmall);
    }
    put_u16_be(out, 0, tag)?;
    put_u32_be(out, 2, size)?;
    put_u32_be(out, 6, command_code)?;
    Ok(())
}

// ---------------------------------------------------------------------
// Builders
// ---------------------------------------------------------------------

/// Build a `TPM2_Startup(startup_type)` command into `out`.
///
/// Wire layout (12 bytes, all big-endian):
///   `tag = 0x8001` (no sessions)
///   `commandSize = 0x0000000C` (12)
///   `commandCode = 0x00000144` (TPM_CC_Startup)
///   `startupType = <startup_type>`
pub fn build_startup(out: &mut [u8], startup_type: u16) -> Result<usize, TpmError> {
    if out.len() < TPM_STARTUP_CMD_LEN {
        return Err(TpmError::BufferTooSmall);
    }
    write_header(out, TPM_ST_NO_SESSIONS, TPM_STARTUP_CMD_LEN as u32, TPM_CC_STARTUP)?;
    put_u16_be(out, TPM_HEADER_LEN, startup_type)?;
    Ok(TPM_STARTUP_CMD_LEN)
}

/// Build a `TPM2_GetRandom(bytes_requested)` command into `out`.
///
/// Wire layout (12 bytes, all big-endian):
///   `tag = 0x8001` (no sessions)
///   `commandSize = 0x0000000C` (12)
///   `commandCode = 0x0000017B` (TPM_CC_GetRandom)
///   `bytesRequested = <bytes_requested>`
///
/// Rejects `bytes_requested == 0` because the response would carry
/// a zero-length `TPM2B_DIGEST` — legal per TCG, but a sign of caller
/// misuse worth surfacing at the build site.
pub fn build_get_random(out: &mut [u8], bytes_requested: u16) -> Result<usize, TpmError> {
    if bytes_requested == 0 {
        return Err(TpmError::BadByteCount);
    }
    if out.len() < TPM_GET_RANDOM_CMD_LEN {
        return Err(TpmError::BufferTooSmall);
    }
    write_header(out, TPM_ST_NO_SESSIONS, TPM_GET_RANDOM_CMD_LEN as u32, TPM_CC_GET_RANDOM)?;
    put_u16_be(out, TPM_HEADER_LEN, bytes_requested)?;
    Ok(TPM_GET_RANDOM_CMD_LEN)
}

/// Build a `TPM2_PCR_Read` command selecting a single PCR in the
/// SHA-256 bank.
///
/// Wire layout (20 bytes, all big-endian):
///   `tag = 0x8001` (no sessions)
///   `commandSize = 0x00000014` (20)
///   `commandCode = 0x0000017E` (TPM_CC_PCR_Read)
///   `pcrSelectionIn:`
///       `count = 0x00000001`
///       `pcrSelections[0]:`
///           `hash = 0x000B` (TPM_ALG_SHA256)
///           `sizeOfSelect = 0x03`
///           `pcrSelect[3] = <bitmask with bit pcr_index set>`
pub fn build_pcr_read(out: &mut [u8], pcr_index: u32) -> Result<usize, TpmError> {
    if pcr_index > TPM_MAX_PCR_INDEX {
        return Err(TpmError::BadPcrIndex);
    }
    if out.len() < TPM_PCR_READ_CMD_LEN {
        return Err(TpmError::BufferTooSmall);
    }
    write_header(out, TPM_ST_NO_SESSIONS, TPM_PCR_READ_CMD_LEN as u32, TPM_CC_PCR_READ)?;
    // count = 1
    put_u32_be(out, TPM_HEADER_LEN, 1)?;
    // hash = SHA-256
    put_u16_be(out, TPM_HEADER_LEN + 4, TPM_ALG_SHA256)?;
    // sizeOfSelect = 3
    out[TPM_HEADER_LEN + 6] = PCR_SELECT_BITMAP_LEN as u8;
    // pcrSelect bitmap
    let bitmap_off = TPM_HEADER_LEN + 7;
    out[bitmap_off] = 0;
    out[bitmap_off + 1] = 0;
    out[bitmap_off + 2] = 0;
    let byte_idx = (pcr_index / 8) as usize;
    let bit_idx = (pcr_index % 8) as u8;
    out[bitmap_off + byte_idx] = 1u8 << bit_idx;
    Ok(TPM_PCR_READ_CMD_LEN)
}

/// Build a `TPM2_PCR_Extend(pcr_index, digest_alg, digest)` command.
/// Uses the well-known password-authorization session with empty
/// password.
///
/// Wire layout for SHA-256 (65 bytes, all big-endian):
///   `tag = 0x8002` (sessions)
///   `commandSize = 0x00000041` (65)
///   `commandCode = 0x00000182` (TPM_CC_PCR_Extend)
///   `pcrHandle = pcr_index` (PCR handle space starts at 0)
///   `authorizationSize = 0x00000009`
///   `session:`
///       `sessionHandle = 0x40000009` (TPM_RS_PW)
///       `nonceSize = 0x0000`
///       `sessionAttributes = 0x00`
///       `hmacSize = 0x0000`
///   `digests:`
///       `count = 0x00000001`
///       `digests[0]:`
///           `hashAlg = <digest_alg>`
///           `digest = <digest bytes>`
pub fn build_pcr_extend(
    out: &mut [u8],
    pcr_index: u32,
    digest_alg: u16,
    digest: &[u8],
) -> Result<usize, TpmError> {
    if pcr_index > TPM_MAX_PCR_INDEX {
        return Err(TpmError::BadPcrIndex);
    }
    let expected_len = match digest_alg {
        TPM_ALG_SHA256 => TPM_SHA256_DIGEST_LEN,
        TPM_ALG_SHA1 => TPM_SHA1_DIGEST_LEN,
        _ => return Err(TpmError::UnsupportedAlg),
    };
    if digest.len() != expected_len {
        return Err(TpmError::BadDigestLen);
    }
    let cmd_len = TPM_HEADER_LEN + 4 + 4 + AUTH_SESSION_LEN + 4 + 2 + expected_len;
    if out.len() < cmd_len {
        return Err(TpmError::BufferTooSmall);
    }
    write_header(out, TPM_ST_SESSIONS, cmd_len as u32, TPM_CC_PCR_EXTEND)?;
    let mut off = TPM_HEADER_LEN;
    // pcrHandle
    put_u32_be(out, off, pcr_index)?;
    off += 4;
    // authorizationSize
    put_u32_be(out, off, AUTH_SESSION_LEN as u32)?;
    off += 4;
    // session.sessionHandle = TPM_RS_PW
    put_u32_be(out, off, TPM_RS_PW)?;
    off += 4;
    // session.nonceSize = 0
    put_u16_be(out, off, 0)?;
    off += 2;
    // session.sessionAttributes = 0
    out[off] = 0;
    off += 1;
    // session.hmacSize = 0
    put_u16_be(out, off, 0)?;
    off += 2;
    // digests.count = 1
    put_u32_be(out, off, 1)?;
    off += 4;
    // digests[0].hashAlg
    put_u16_be(out, off, digest_alg)?;
    off += 2;
    // digests[0].digest
    out[off..off + expected_len].copy_from_slice(digest);
    off += expected_len;
    debug_assert_eq!(off, cmd_len);
    Ok(cmd_len)
}

// ---------------------------------------------------------------------
// Response parser
// ---------------------------------------------------------------------

/// Parse a TPM 2.0 response header and return a [`TpmResponseView`]
/// over `buf`. Validates `tag ∈ {TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS}`
/// and `size == buf.len()` exactly.
pub fn parse_response(buf: &[u8]) -> Result<TpmResponseView<'_>, TpmError> {
    if buf.len() < TPM_HEADER_LEN {
        return Err(TpmError::Truncated);
    }
    let tag = read_u16_be(buf, 0);
    if tag != TPM_ST_NO_SESSIONS && tag != TPM_ST_SESSIONS {
        return Err(TpmError::BadTag);
    }
    let size = read_u32_be(buf, 2);
    if size as usize != buf.len() {
        return Err(TpmError::BadSizeField);
    }
    let response_code = read_u32_be(buf, 6);
    Ok(TpmResponseView {
        tag,
        size,
        response_code,
        body: &buf[TPM_HEADER_LEN..],
    })
}

/// Extract the random-byte payload from a parsed `TPM2_GetRandom`
/// response body. Helper used by the kernel banner. Returns
/// `Err(Truncated)` if the body is too short for the inline
/// `TPM2B_DIGEST`, `Err(BadSizeField)` if the inline size field
/// disagrees with the remaining body length.
///
/// `TPM2B_DIGEST` layout: `u16 size + size bytes`. The function
/// allows callers to assert the size matches what was requested.
pub fn extract_get_random_bytes(body: &[u8]) -> Result<&[u8], TpmError> {
    if body.len() < 2 {
        return Err(TpmError::Truncated);
    }
    let n = read_u16_be(body, 0) as usize;
    if 2 + n != body.len() {
        return Err(TpmError::BadSizeField);
    }
    Ok(&body[2..2 + n])
}

/// Render the PCR-select bitmap byte/bit position for a given PCR
/// index. Returned tuple is `(byte_index, bit_mask)`. Inlined by the
/// kernel banner so banner code can assert the encoder produced the
/// expected byte without recomputing the masking arithmetic.
pub fn pcr_bitmap_position(pcr_index: u32) -> (usize, u8) {
    ((pcr_index / 8) as usize, 1u8 << (pcr_index % 8))
}

// ---------------------------------------------------------------------
// TCG PC Client PTP TPM 2.0 TIS (TPM Interface Specification) MMIO Driver
// ---------------------------------------------------------------------

/// Architectural guest-physical base address of TPM 2.0 TIS Locality 0.
pub const TPM_TIS_BASE_PHYS: u64 = 0xFED4_0000;

/// Locality 0 `TPM_ACCESS_0` 8-bit register offset (`0x0000`).
pub const TPM_ACCESS_0: usize = 0x0000;

/// Locality 0 `TPM_STS_0` 32-bit register offset (`0x0018`).
pub const TPM_STS_0: usize = 0x0018;

/// Locality 0 `TPM_DATA_FIFO_0` 8-bit FIFO register offset (`0x0024`).
pub const TPM_DATA_FIFO_0: usize = 0x0024;

/// Locality 0 `TPM_DID_VID_0` 32-bit Device/Vendor ID register offset (`0x0F00`).
pub const TPM_DID_VID_0: usize = 0x0F00;

/// Default TCG TPM 2.0 TIS Device/Vendor ID (`0x0001_15D1`, Infineon SLB9670 / QEMU TIS).
pub const TPM_DEFAULT_DID_VID: u32 = 0x0001_15D1;

/// `TPM_ACCESS_0` bit 7: `tpmRegValidSts` (register contents valid).
pub const TPM_ACCESS_VALID: u8 = 0x80;

/// `TPM_ACCESS_0` bit 5: `activeLocality` (read: locality active; write 1: relinquish).
pub const TPM_ACCESS_ACTIVE_LOCALITY: u8 = 0x20;

/// `TPM_ACCESS_0` bit 1: `requestUse` (write 1 to request locality).
pub const TPM_ACCESS_REQUEST_USE: u8 = 0x02;

/// `TPM_STS_0` bit 7: `stsValid` (`dataAvail` and `expect` bits are valid).
pub const TPM_STS_VALID: u8 = 0x80;

/// `TPM_STS_0` bit 6: `commandReady` (read: ready for command; write 1: abort/ready).
pub const TPM_STS_COMMAND_READY: u8 = 0x40;

/// `TPM_STS_0` bit 5: `tpmGo` (write 1 to execute the queued FIFO command).
pub const TPM_STS_GO: u8 = 0x20;

/// `TPM_STS_0` bit 4: `dataAvail` (response bytes available in `TPM_DATA_FIFO_0`).
pub const TPM_STS_DATA_AVAIL: u8 = 0x10;

/// `TPM_STS_0` bit 3: `expect` (TPM expects more command bytes in `TPM_DATA_FIFO_0`).
pub const TPM_STS_EXPECT: u8 = 0x08;

/// Bounded poll limit for TIS status transitions.
pub const TPM_TIS_MAX_SPINS: usize = 4096;

/// Locked wire length of a `TPM2_PCR_Read` single-PCR SHA-256 response:
/// Header (10) + `pcrUpdateCounter` (4) + `pcrSelectionOut` (10) + `pcrValues` (4 + 2 + 32) = 62 bytes.
pub const TPM_PCR_READ_SHA256_RESP_LEN: usize = 62;

/// Compute the FIPS 180-4 SHA-256 PCR extension `SHA256(current_pcr || extend_digest)`.
pub fn tpm_pcr_extend_sha256_math(current: &[u8; 32], extend_digest: &[u8; 32]) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    hasher.update(current);
    hasher.update(extend_digest);
    let result = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&result);
    out
}

/// Hardware or emulator register bus for a TCG PC Client PTP TPM 2.0 TIS locality.
pub trait TpmTisBus {
    /// Read an 8-bit register at `offset` relative to the locality base (`0xFED4_0000`).
    fn read_u8(&mut self, offset: usize) -> u8;

    /// Write an 8-bit register at `offset` relative to the locality base (`0xFED4_0000`).
    fn write_u8(&mut self, offset: usize, val: u8);

    /// Read a 32-bit little-endian register at `offset` (e.g. `TPM_STS_0`, `TPM_DID_VID_0`).
    fn read_u32(&mut self, offset: usize) -> u32 {
        let b0 = self.read_u8(offset) as u32;
        let b1 = self.read_u8(offset + 1) as u32;
        let b2 = self.read_u8(offset + 2) as u32;
        let b3 = self.read_u8(offset + 3) as u32;
        b0 | (b1 << 8) | (b2 << 16) | (b3 << 24)
    }
}

/// TCG PC Client PTP TPM 2.0 TIS Locality 0 driver over any [`TpmTisBus`].
pub struct TpmTisDriver<B: TpmTisBus> {
    bus: B,
}

impl<B: TpmTisBus> TpmTisDriver<B> {
    /// Construct a new TIS driver wrapping `bus`.
    pub const fn new(bus: B) -> Self {
        Self { bus }
    }

    /// Borrow the underlying TIS register bus.
    pub fn bus(&self) -> &B {
        &self.bus
    }

    /// Mutably borrow the underlying TIS register bus.
    pub fn bus_mut(&mut self) -> &mut B {
        &mut self.bus
    }

    /// Probe `TPM_DID_VID_0` (`0x0F00`) and return `Some(did_vid)` if a TPM 2.0 TIS
    /// controller is present (`did_vid != 0` and `did_vid != 0xFFFF_FFFF`).
    pub fn probe_did_vid(&mut self) -> Option<u32> {
        let did_vid = self.bus.read_u32(TPM_DID_VID_0);
        if did_vid == 0 || did_vid == 0xFFFF_FFFF {
            None
        } else {
            Some(did_vid)
        }
    }

    /// Request Locality 0 ownership via `TPM_ACCESS_0` and wait until
    /// `TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY` is asserted.
    pub fn request_locality_0(&mut self) -> Result<(), TpmError> {
        let mask = TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY;
        if (self.bus.read_u8(TPM_ACCESS_0) & mask) == mask {
            return Ok(());
        }
        self.bus.write_u8(TPM_ACCESS_0, TPM_ACCESS_REQUEST_USE);
        let mut spins = 0usize;
        while spins < TPM_TIS_MAX_SPINS {
            if (self.bus.read_u8(TPM_ACCESS_0) & mask) == mask {
                return Ok(());
            }
            spins += 1;
        }
        Err(TpmError::Truncated)
    }

    /// Relinquish Locality 0 ownership by writing `TPM_ACCESS_ACTIVE_LOCALITY` to `TPM_ACCESS_0`.
    pub fn relinquish_locality_0(&mut self) {
        self.bus.write_u8(TPM_ACCESS_0, TPM_ACCESS_ACTIVE_LOCALITY);
    }

    /// Read the 16-bit `burstCount` field (`STS[23:8]`) from `TPM_STS_0`.
    fn wait_burst_count(&mut self) -> Result<usize, TpmError> {
        let mut spins = 0usize;
        while spins < TPM_TIS_MAX_SPINS {
            let sts32 = self.bus.read_u32(TPM_STS_0);
            let burst = ((sts32 >> 8) & 0xFFFF) as usize;
            if burst > 0 {
                return Ok(burst);
            }
            spins += 1;
        }
        Err(TpmError::Truncated)
    }

    /// Transmit a TPM 2.0 command frame over `TPM_DATA_FIFO_0`, trigger execution
    /// via `TPM_STS_GO`, and read the response frame into `resp_out`.
    pub fn transceive(&mut self, cmd: &[u8], resp_out: &mut [u8]) -> Result<usize, TpmError> {
        if cmd.len() < TPM_HEADER_LEN {
            return Err(TpmError::Truncated);
        }
        if resp_out.len() < TPM_HEADER_LEN {
            return Err(TpmError::BufferTooSmall);
        }
        self.request_locality_0()?;

        // Transition to Command Ready state.
        if (self.bus.read_u8(TPM_STS_0) & TPM_STS_COMMAND_READY) == 0 {
            self.bus.write_u8(TPM_STS_0, TPM_STS_COMMAND_READY);
            let mut spins = 0usize;
            while (self.bus.read_u8(TPM_STS_0) & TPM_STS_COMMAND_READY) == 0 {
                spins += 1;
                if spins >= TPM_TIS_MAX_SPINS {
                    return Err(TpmError::Truncated);
                }
            }
        }

        // Write command bytes to `TPM_DATA_FIFO_0` respecting `burstCount`.
        let mut written = 0usize;
        while written < cmd.len() {
            let burst = self.wait_burst_count()?;
            let step = (cmd.len() - written).min(burst);
            let mut i = 0usize;
            while i < step {
                self.bus.write_u8(TPM_DATA_FIFO_0, cmd[written + i]);
                i += 1;
            }
            written += step;
        }

        // Verify `stsValid == 1` and `expect == 0` after the final command byte.
        let sts_after = self.bus.read_u8(TPM_STS_0);
        if (sts_after & TPM_STS_VALID) == 0 || (sts_after & TPM_STS_EXPECT) != 0 {
            return Err(TpmError::BadSizeField);
        }

        // Trigger command execution.
        self.bus.write_u8(TPM_STS_0, TPM_STS_GO);

        // Poll until `TPM_STS_VALID | TPM_STS_DATA_AVAIL` is set.
        let avail_mask = TPM_STS_VALID | TPM_STS_DATA_AVAIL;
        let mut spins = 0usize;
        while (self.bus.read_u8(TPM_STS_0) & avail_mask) != avail_mask {
            spins += 1;
            if spins >= TPM_TIS_MAX_SPINS {
                return Err(TpmError::Truncated);
            }
        }

        // Read the 10-byte response header first.
        let mut read_pos = 0usize;
        while read_pos < TPM_HEADER_LEN {
            let burst = self.wait_burst_count()?;
            let step = (TPM_HEADER_LEN - read_pos).min(burst);
            let mut i = 0usize;
            while i < step {
                resp_out[read_pos + i] = self.bus.read_u8(TPM_DATA_FIFO_0);
                i += 1;
            }
            read_pos += step;
        }

        let total_size = read_u32_be(&resp_out[..TPM_HEADER_LEN], 2) as usize;
        if total_size < TPM_HEADER_LEN {
            return Err(TpmError::BadSizeField);
        }
        if total_size > resp_out.len() {
            return Err(TpmError::BufferTooSmall);
        }

        while read_pos < total_size {
            let burst = self.wait_burst_count()?;
            let step = (total_size - read_pos).min(burst);
            let mut i = 0usize;
            while i < step {
                resp_out[read_pos + i] = self.bus.read_u8(TPM_DATA_FIFO_0);
                i += 1;
            }
            read_pos += step;
        }

        // Return FIFO to Command Ready / Idle.
        self.bus.write_u8(TPM_STS_0, TPM_STS_COMMAND_READY);
        Ok(total_size)
    }

    /// Execute `TPM2_Startup(startup_type)` over the TIS FIFO and verify `TPM_RC_SUCCESS`.
    pub fn startup(&mut self, startup_type: u16) -> Result<(), TpmError> {
        let mut cmd = [0u8; TPM_STARTUP_CMD_LEN];
        let cmd_len = build_startup(&mut cmd, startup_type)?;
        let mut resp = [0u8; 32];
        let resp_len = self.transceive(&cmd[..cmd_len], &mut resp)?;
        let view = parse_response(&resp[..resp_len])?;
        if view.response_code != proteus_contracts::TPM_RC_SUCCESS {
            return Err(TpmError::BadTag);
        }
        Ok(())
    }

    /// Execute `TPM2_PCR_Extend` for `pcr_index` in the SHA-256 bank over the TIS FIFO.
    pub fn pcr_extend_sha256(&mut self, pcr_index: u32, digest: &[u8; 32]) -> Result<(), TpmError> {
        let mut cmd = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let cmd_len = build_pcr_extend(&mut cmd, pcr_index, TPM_ALG_SHA256, digest)?;
        let mut resp = [0u8; 64];
        let resp_len = self.transceive(&cmd[..cmd_len], &mut resp)?;
        let view = parse_response(&resp[..resp_len])?;
        if view.response_code != proteus_contracts::TPM_RC_SUCCESS {
            return Err(TpmError::BadTag);
        }
        Ok(())
    }

    /// Execute `TPM2_PCR_Read` for `pcr_index` in the SHA-256 bank over the TIS FIFO,
    /// copy the 32-byte PCR value into `out_digest`, and return `pcrUpdateCounter`.
    pub fn pcr_read_sha256(
        &mut self,
        pcr_index: u32,
        out_digest: &mut [u8; 32],
    ) -> Result<u32, TpmError> {
        let mut cmd = [0u8; TPM_PCR_READ_CMD_LEN];
        let cmd_len = build_pcr_read(&mut cmd, pcr_index)?;
        let mut resp = [0u8; 96];
        let resp_len = self.transceive(&cmd[..cmd_len], &mut resp)?;
        let view = parse_response(&resp[..resp_len])?;
        if view.response_code != proteus_contracts::TPM_RC_SUCCESS {
            return Err(TpmError::BadTag);
        }
        // Body layout: pcrUpdateCounter(4) + pcrSelectionOut(10) + count(4) + size(2) + digest(32) = 52 bytes.
        if view.body.len() < 52 {
            return Err(TpmError::Truncated);
        }
        let update_counter = read_u32_be(view.body, 0);
        let digest_count = read_u32_be(view.body, 14);
        let digest_size = read_u16_be(view.body, 18) as usize;
        if digest_count != 1 || digest_size != TPM_SHA256_DIGEST_LEN {
            return Err(TpmError::BadDigestLen);
        }
        out_digest.copy_from_slice(&view.body[20..52]);
        Ok(update_counter)
    }

    /// Execute `TPM2_GetRandom` over the TIS FIFO and fill `out` (up to 32 bytes).
    pub fn get_random(&mut self, out: &mut [u8]) -> Result<usize, TpmError> {
        if out.is_empty() || out.len() > 32 {
            return Err(TpmError::BadByteCount);
        }
        let req_len = out.len() as u16;
        let mut cmd = [0u8; TPM_GET_RANDOM_CMD_LEN];
        let cmd_len = build_get_random(&mut cmd, req_len)?;
        let mut resp = [0u8; 64];
        let resp_len = self.transceive(&cmd[..cmd_len], &mut resp)?;
        let view = parse_response(&resp[..resp_len])?;
        if view.response_code != proteus_contracts::TPM_RC_SUCCESS {
            return Err(TpmError::BadTag);
        }
        let rnd = extract_get_random_bytes(view.body)?;
        if rnd.len() != out.len() {
            return Err(TpmError::BadSizeField);
        }
        out.copy_from_slice(rnd);
        Ok(rnd.len())
    }
}

/// Deterministic in-memory TCG PC Client PTP TPM 2.0 TIS Locality 0 emulator.
///
/// Implements the hardware register state machine (`TPM_ACCESS_0`, `TPM_STS_0`,
/// `TPM_DATA_FIFO_0`, `TPM_DID_VID_0`) and maintains a 24-PCR SHA-256 bank so
/// [`TpmTisDriver`] executes identical register-level FIFO transfers on hosts
/// and QEMU guests without an external `swtpm` socket.
pub struct MemTpmTisBus {
    did_vid: u32,
    access: u8,
    sts: u8,
    cmd_fifo: [u8; 128],
    cmd_len: usize,
    cmd_expected: usize,
    resp_fifo: [u8; 128],
    resp_len: usize,
    resp_pos: usize,
    started: bool,
    pcr_update_counter: u32,
    pcrs_sha256: [[u8; 32]; 24],
    rng_counter: u64,
}

impl Default for MemTpmTisBus {
    fn default() -> Self {
        Self::new()
    }
}

impl MemTpmTisBus {
    /// Construct a new in-memory TPM 2.0 TIS locality 0 device with default `DID_VID`.
    pub const fn new() -> Self {
        Self {
            did_vid: TPM_DEFAULT_DID_VID,
            access: TPM_ACCESS_VALID,
            sts: TPM_STS_VALID,
            cmd_fifo: [0u8; 128],
            cmd_len: 0,
            cmd_expected: 0,
            resp_fifo: [0u8; 128],
            resp_len: 0,
            resp_pos: 0,
            started: false,
            pcr_update_counter: 0,
            pcrs_sha256: [[0u8; 32]; 24],
            rng_counter: 1,
        }
    }

    /// Inspect a SHA-256 PCR value directly from the emulated bank.
    pub fn pcr_sha256(&self, index: usize) -> &[u8; 32] {
        &self.pcrs_sha256[index]
    }

    /// Execute the command currently buffered in `cmd_fifo[..cmd_len]` and populate `resp_fifo`.
    fn execute_command(&mut self) {
        self.resp_pos = 0;
        self.resp_len = 0;
        if self.cmd_len < TPM_HEADER_LEN {
            self.write_error_response(TPM_ST_NO_SESSIONS, 0x0000_0100);
            return;
        }
        let tag = read_u16_be(&self.cmd_fifo, 0);
        let size = read_u32_be(&self.cmd_fifo, 2) as usize;
        let cc = read_u32_be(&self.cmd_fifo, 6);
        if size != self.cmd_len {
            self.write_error_response(tag, 0x0000_0100);
            return;
        }

        match cc {
            TPM_CC_STARTUP => {
                if self.cmd_len != TPM_STARTUP_CMD_LEN {
                    self.write_error_response(TPM_ST_NO_SESSIONS, 0x0000_0100);
                    return;
                }
                let st_type = read_u16_be(&self.cmd_fifo, 10);
                if st_type == proteus_contracts::TPM_SU_CLEAR {
                    self.pcrs_sha256 = [[0u8; 32]; 24];
                    self.pcr_update_counter = 0;
                }
                self.started = true;
                let _ = write_header(
                    &mut self.resp_fifo,
                    TPM_ST_NO_SESSIONS,
                    TPM_HEADER_LEN as u32,
                    proteus_contracts::TPM_RC_SUCCESS,
                );
                self.resp_len = TPM_HEADER_LEN;
            }
            TPM_CC_PCR_EXTEND => {
                if !self.started || self.cmd_len != TPM_PCR_EXTEND_SHA256_CMD_LEN {
                    self.write_error_response(TPM_ST_SESSIONS, 0x0000_0100);
                    return;
                }
                let pcr_idx = read_u32_be(&self.cmd_fifo, 10) as usize;
                let alg_off = TPM_HEADER_LEN + 4 + 4 + AUTH_SESSION_LEN + 4;
                let alg = read_u16_be(&self.cmd_fifo, alg_off);
                if pcr_idx > TPM_MAX_PCR_INDEX as usize || alg != TPM_ALG_SHA256 {
                    self.write_error_response(TPM_ST_SESSIONS, 0x0000_0100);
                    return;
                }
                let mut extend_val = [0u8; 32];
                extend_val.copy_from_slice(&self.cmd_fifo[alg_off + 2..alg_off + 34]);
                self.pcrs_sha256[pcr_idx] =
                    tpm_pcr_extend_sha256_math(&self.pcrs_sha256[pcr_idx], &extend_val);
                self.pcr_update_counter = self.pcr_update_counter.wrapping_add(1);

                // 19-byte TPM_ST_SESSIONS response: header(10) + paramSize(0, 4B) + PWAP auth(5B) = 19B.
                let mut i = 0usize;
                while i < 19 {
                    self.resp_fifo[i] = 0;
                    i += 1;
                }
                let _ = write_header(
                    &mut self.resp_fifo,
                    TPM_ST_SESSIONS,
                    19,
                    proteus_contracts::TPM_RC_SUCCESS,
                );
                self.resp_len = 19;
            }
            TPM_CC_PCR_READ => {
                if !self.started || self.cmd_len != TPM_PCR_READ_CMD_LEN {
                    self.write_error_response(TPM_ST_NO_SESSIONS, 0x0000_0100);
                    return;
                }
                let b0 = self.cmd_fifo[17];
                let b1 = self.cmd_fifo[18];
                let b2 = self.cmd_fifo[19];
                let mut selected_pcr: Option<usize> = None;
                let mut idx = 0usize;
                while idx < 24 {
                    let byte = match idx / 8 {
                        0 => b0,
                        1 => b1,
                        _ => b2,
                    };
                    if (byte & (1u8 << (idx % 8))) != 0 {
                        selected_pcr = Some(idx);
                        break;
                    }
                    idx += 1;
                }
                let Some(pcr_idx) = selected_pcr else {
                    self.write_error_response(TPM_ST_NO_SESSIONS, 0x0000_0100);
                    return;
                };
                let _ = write_header(
                    &mut self.resp_fifo,
                    TPM_ST_NO_SESSIONS,
                    TPM_PCR_READ_SHA256_RESP_LEN as u32,
                    proteus_contracts::TPM_RC_SUCCESS,
                );
                // pcrUpdateCounter
                let _ = put_u32_be(&mut self.resp_fifo, 10, self.pcr_update_counter);
                // pcrSelectionOut (copy 10 bytes from request offset 10..20)
                self.resp_fifo[14..24].copy_from_slice(&self.cmd_fifo[10..20]);
                // pcrValues: count = 1, size = 32, digest[32]
                let _ = put_u32_be(&mut self.resp_fifo, 24, 1);
                let _ = put_u16_be(&mut self.resp_fifo, 28, TPM_SHA256_DIGEST_LEN as u16);
                self.resp_fifo[30..62].copy_from_slice(&self.pcrs_sha256[pcr_idx]);
                self.resp_len = TPM_PCR_READ_SHA256_RESP_LEN;
            }
            TPM_CC_GET_RANDOM => {
                if !self.started || self.cmd_len != TPM_GET_RANDOM_CMD_LEN {
                    self.write_error_response(TPM_ST_NO_SESSIONS, 0x0000_0100);
                    return;
                }
                let req = (read_u16_be(&self.cmd_fifo, 10) as usize).min(32);
                let mut seed_block = [0u8; 32];
                seed_block[0..8].copy_from_slice(&self.rng_counter.to_le_bytes());
                seed_block[8..12].copy_from_slice(&self.pcr_update_counter.to_le_bytes());
                self.rng_counter = self.rng_counter.wrapping_add(1);
                let digest = tpm_pcr_extend_sha256_math(&self.pcrs_sha256[0], &seed_block);
                let total_len = TPM_HEADER_LEN + 2 + req;
                let _ = write_header(
                    &mut self.resp_fifo,
                    TPM_ST_NO_SESSIONS,
                    total_len as u32,
                    proteus_contracts::TPM_RC_SUCCESS,
                );
                let _ = put_u16_be(&mut self.resp_fifo, 10, req as u16);
                self.resp_fifo[12..12 + req].copy_from_slice(&digest[..req]);
                self.resp_len = total_len;
            }
            _ => {
                self.write_error_response(TPM_ST_NO_SESSIONS, 0x0000_0143);
            }
        }
    }

    fn write_error_response(&mut self, tag: u16, rc: u32) {
        let _ = write_header(&mut self.resp_fifo, tag, TPM_HEADER_LEN as u32, rc);
        self.resp_len = TPM_HEADER_LEN;
        self.resp_pos = 0;
    }
}

impl TpmTisBus for MemTpmTisBus {
    fn read_u8(&mut self, offset: usize) -> u8 {
        match offset {
            TPM_ACCESS_0 => self.access,
            TPM_STS_0 => self.sts,
            0x0019 => 0x40, // burstCount low byte = 64 bytes
            0x001A => 0x00, // burstCount high byte = 0
            0x001B => 0x00,
            TPM_DATA_FIFO_0 => {
                if self.resp_pos < self.resp_len {
                    let b = self.resp_fifo[self.resp_pos];
                    self.resp_pos += 1;
                    if self.resp_pos >= self.resp_len {
                        self.sts &= !TPM_STS_DATA_AVAIL;
                    }
                    b
                } else {
                    0
                }
            }
            o if (TPM_DID_VID_0..TPM_DID_VID_0 + 4).contains(&o) => {
                let shift = (o - TPM_DID_VID_0) * 8;
                ((self.did_vid >> shift) & 0xFF) as u8
            }
            _ => 0,
        }
    }

    fn write_u8(&mut self, offset: usize, val: u8) {
        match offset {
            TPM_ACCESS_0 => {
                if (val & TPM_ACCESS_REQUEST_USE) != 0 {
                    self.access = TPM_ACCESS_VALID | TPM_ACCESS_ACTIVE_LOCALITY;
                } else if (val & TPM_ACCESS_ACTIVE_LOCALITY) != 0 {
                    self.access = TPM_ACCESS_VALID;
                }
            }
            TPM_STS_0 => {
                if (val & TPM_STS_COMMAND_READY) != 0 {
                    self.cmd_len = 0;
                    self.cmd_expected = 0;
                    self.resp_len = 0;
                    self.resp_pos = 0;
                    self.sts = TPM_STS_VALID | TPM_STS_COMMAND_READY | TPM_STS_EXPECT;
                } else if (val & TPM_STS_GO) != 0 {
                    self.execute_command();
                    self.sts = TPM_STS_VALID | TPM_STS_DATA_AVAIL;
                }
            }
            TPM_DATA_FIFO_0 => {
                if (self.sts & TPM_STS_EXPECT) != 0 && self.cmd_len < self.cmd_fifo.len() {
                    self.cmd_fifo[self.cmd_len] = val;
                    self.cmd_len += 1;
                    if self.cmd_len == 6 {
                        let declared = read_u32_be(&self.cmd_fifo, 2) as usize;
                        self.cmd_expected = declared.min(self.cmd_fifo.len());
                    }
                    if self.cmd_expected != 0 && self.cmd_len >= self.cmd_expected {
                        self.sts &= !TPM_STS_EXPECT;
                    }
                }
            }
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::{
        Tpm, TpmError, TPM_RC_SUCCESS, TPM_ST_NO_SESSIONS, TPM_ST_SESSIONS, TPM_SU_CLEAR,
        TPM_SU_STATE,
    };

    /// Golden bytes for `TPM2_Startup(SU_CLEAR)`.
    const STARTUP_CLEAR_GOLDEN: [u8; 12] = [
        0x80, 0x01, // tag = TPM_ST_NO_SESSIONS
        0x00, 0x00, 0x00, 0x0C, // commandSize = 12
        0x00, 0x00, 0x01, 0x44, // commandCode = TPM_CC_Startup
        0x00, 0x00, // TPM_SU_CLEAR
    ];

    /// Golden bytes for `TPM2_Startup(SU_STATE)`.
    const STARTUP_STATE_GOLDEN: [u8; 12] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x0C, 0x00, 0x00, 0x01, 0x44, 0x00, 0x01,
    ];

    /// Golden bytes for `TPM2_GetRandom(16)`.
    const GET_RANDOM_16_GOLDEN: [u8; 12] = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x0C, // commandSize = 12
        0x00, 0x00, 0x01, 0x7B, // commandCode = TPM_CC_GetRandom
        0x00, 0x10, // bytesRequested = 16
    ];

    /// Golden bytes for `TPM2_PCR_Read(pcr=0)` in the SHA-256 bank.
    const PCR_READ_0_GOLDEN: [u8; 20] = [
        0x80, 0x01, // tag
        0x00, 0x00, 0x00, 0x14, // commandSize = 20
        0x00, 0x00, 0x01, 0x7E, // commandCode = TPM_CC_PCR_Read
        0x00, 0x00, 0x00, 0x01, // pcrSelectionIn.count = 1
        0x00, 0x0B, // hash = TPM_ALG_SHA256
        0x03, // sizeOfSelect = 3
        0x01, 0x00, 0x00, // pcrSelect bitmap: bit 0 of byte 0
    ];

    /// Golden bytes for `TPM2_PCR_Read(pcr=10)`.
    const PCR_READ_10_GOLDEN: [u8; 20] = [
        0x80, 0x01, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x01, 0x7E, 0x00, 0x00, 0x00, 0x01, 0x00,
        0x0B, 0x03, 0x00, 0x04, 0x00, // bitmap: bit (10 % 8) = 2 in byte 1
    ];

    /// Golden bytes for `TPM2_PCR_Extend(pcr=8, SHA-256, [0x42; 32])`.
    const PCR_EXTEND_SHA256_GOLDEN: [u8; 65] = [
        // header
        0x80, 0x02, // tag = TPM_ST_SESSIONS
        0x00, 0x00, 0x00, 0x41, // commandSize = 65
        0x00, 0x00, 0x01, 0x82, // commandCode = TPM_CC_PCR_Extend
        // pcrHandle = 8
        0x00, 0x00, 0x00, 0x08,
        // authorizationSize = 9
        0x00, 0x00, 0x00, 0x09,
        // session: handle = 0x40000009, nonce_size = 0, attrs = 0, hmac_size = 0
        0x40, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x00, 0x00,
        // digests.count = 1
        0x00, 0x00, 0x00, 0x01,
        // hashAlg = SHA-256
        0x00, 0x0B,
        // digest = [0x42; 32]
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42,
        0x42, 0x42,
    ];

    #[test]
    fn startup_clear_matches_golden() {
        let mut buf = [0u8; TPM_STARTUP_CMD_LEN];
        let n = TpmImpl::build_startup(&mut buf, TPM_SU_CLEAR).unwrap();
        assert_eq!(n, TPM_STARTUP_CMD_LEN);
        assert_eq!(buf, STARTUP_CLEAR_GOLDEN);
    }

    #[test]
    fn startup_state_matches_golden() {
        let mut buf = [0u8; TPM_STARTUP_CMD_LEN];
        let n = TpmImpl::build_startup(&mut buf, TPM_SU_STATE).unwrap();
        assert_eq!(n, TPM_STARTUP_CMD_LEN);
        assert_eq!(buf, STARTUP_STATE_GOLDEN);
    }

    #[test]
    fn startup_short_buffer_rejected() {
        let mut buf = [0u8; 11];
        let r = TpmImpl::build_startup(&mut buf, TPM_SU_CLEAR);
        assert_eq!(r, Err(TpmError::BufferTooSmall));
    }

    #[test]
    fn startup_allows_oversized_buffer() {
        let mut buf = [0u8; 32];
        let n = TpmImpl::build_startup(&mut buf, TPM_SU_CLEAR).unwrap();
        assert_eq!(n, TPM_STARTUP_CMD_LEN);
        assert_eq!(&buf[..n], &STARTUP_CLEAR_GOLDEN[..]);
        // Trailing bytes left untouched.
        for &b in &buf[n..] {
            assert_eq!(b, 0);
        }
    }

    #[test]
    fn get_random_16_matches_golden() {
        let mut buf = [0u8; TPM_GET_RANDOM_CMD_LEN];
        let n = TpmImpl::build_get_random(&mut buf, 16).unwrap();
        assert_eq!(n, TPM_GET_RANDOM_CMD_LEN);
        assert_eq!(buf, GET_RANDOM_16_GOLDEN);
    }

    #[test]
    fn get_random_rejects_zero_bytes() {
        let mut buf = [0u8; TPM_GET_RANDOM_CMD_LEN];
        let r = TpmImpl::build_get_random(&mut buf, 0);
        assert_eq!(r, Err(TpmError::BadByteCount));
    }

    #[test]
    fn get_random_short_buffer_rejected() {
        let mut buf = [0u8; 11];
        let r = TpmImpl::build_get_random(&mut buf, 16);
        assert_eq!(r, Err(TpmError::BufferTooSmall));
    }

    #[test]
    fn get_random_endianness_is_big() {
        let mut buf = [0u8; TPM_GET_RANDOM_CMD_LEN];
        TpmImpl::build_get_random(&mut buf, 0x1234).unwrap();
        assert_eq!(buf[10], 0x12);
        assert_eq!(buf[11], 0x34);
    }

    #[test]
    fn pcr_read_index_0_matches_golden() {
        let mut buf = [0u8; TPM_PCR_READ_CMD_LEN];
        let n = TpmImpl::build_pcr_read(&mut buf, 0).unwrap();
        assert_eq!(n, TPM_PCR_READ_CMD_LEN);
        assert_eq!(buf, PCR_READ_0_GOLDEN);
    }

    #[test]
    fn pcr_read_index_10_matches_golden() {
        let mut buf = [0u8; TPM_PCR_READ_CMD_LEN];
        let n = TpmImpl::build_pcr_read(&mut buf, 10).unwrap();
        assert_eq!(n, TPM_PCR_READ_CMD_LEN);
        assert_eq!(buf, PCR_READ_10_GOLDEN);
    }

    #[test]
    fn pcr_read_index_23_sets_high_bit() {
        let mut buf = [0u8; TPM_PCR_READ_CMD_LEN];
        TpmImpl::build_pcr_read(&mut buf, 23).unwrap();
        // bitmap[2] should have bit 7 set; bitmap[0] / bitmap[1] zero.
        assert_eq!(buf[17], 0x00);
        assert_eq!(buf[18], 0x00);
        assert_eq!(buf[19], 0x80);
    }

    #[test]
    fn pcr_read_rejects_index_above_max() {
        let mut buf = [0u8; TPM_PCR_READ_CMD_LEN];
        let r = TpmImpl::build_pcr_read(&mut buf, 24);
        assert_eq!(r, Err(TpmError::BadPcrIndex));
    }

    #[test]
    fn pcr_read_short_buffer_rejected() {
        let mut buf = [0u8; 19];
        let r = TpmImpl::build_pcr_read(&mut buf, 0);
        assert_eq!(r, Err(TpmError::BufferTooSmall));
    }

    #[test]
    fn pcr_extend_sha256_matches_golden() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0x42u8; TPM_SHA256_DIGEST_LEN];
        let n = TpmImpl::build_pcr_extend(&mut buf, 8, TPM_ALG_SHA256, &digest).unwrap();
        assert_eq!(n, TPM_PCR_EXTEND_SHA256_CMD_LEN);
        assert_eq!(buf, PCR_EXTEND_SHA256_GOLDEN);
    }

    #[test]
    fn pcr_extend_sha1_length_is_locked() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0xAAu8; TPM_SHA1_DIGEST_LEN];
        let n = TpmImpl::build_pcr_extend(&mut buf, 1, TPM_ALG_SHA1, &digest).unwrap();
        assert_eq!(n, TPM_PCR_EXTEND_SHA1_CMD_LEN);
        // Header & body checks.
        assert_eq!(&buf[0..2], &[0x80, 0x02]); // sessions tag
        assert_eq!(&buf[2..6], &(TPM_PCR_EXTEND_SHA1_CMD_LEN as u32).to_be_bytes());
        assert_eq!(&buf[6..10], &[0x00, 0x00, 0x01, 0x82]); // cc
        assert_eq!(&buf[10..14], &[0x00, 0x00, 0x00, 0x01]); // pcrHandle = 1
        // hashAlg
        let alg_off = TPM_HEADER_LEN + 4 + 4 + AUTH_SESSION_LEN + 4;
        assert_eq!(&buf[alg_off..alg_off + 2], &[0x00, 0x04]);
        // digest bytes follow
        for i in 0..TPM_SHA1_DIGEST_LEN {
            assert_eq!(buf[alg_off + 2 + i], 0xAA);
        }
    }

    #[test]
    fn pcr_extend_rejects_wrong_digest_len() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let short = [0u8; 16];
        let r = TpmImpl::build_pcr_extend(&mut buf, 0, TPM_ALG_SHA256, &short);
        assert_eq!(r, Err(TpmError::BadDigestLen));
        let long = [0u8; TPM_SHA1_DIGEST_LEN];
        let r2 = TpmImpl::build_pcr_extend(&mut buf, 0, TPM_ALG_SHA256, &long);
        assert_eq!(r2, Err(TpmError::BadDigestLen));
    }

    #[test]
    fn pcr_extend_rejects_unsupported_alg() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0u8; TPM_SHA256_DIGEST_LEN];
        // TPM_ALG_SHA384 = 0x000C, but we only locked SHA-1 / SHA-256
        let r = TpmImpl::build_pcr_extend(&mut buf, 0, 0x000C, &digest);
        assert_eq!(r, Err(TpmError::UnsupportedAlg));
    }

    #[test]
    fn pcr_extend_rejects_bad_pcr_index() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0u8; TPM_SHA256_DIGEST_LEN];
        let r = TpmImpl::build_pcr_extend(&mut buf, 24, TPM_ALG_SHA256, &digest);
        assert_eq!(r, Err(TpmError::BadPcrIndex));
    }

    #[test]
    fn pcr_extend_short_buffer_rejected() {
        let mut buf = [0u8; 64];
        let digest = [0u8; TPM_SHA256_DIGEST_LEN];
        let r = TpmImpl::build_pcr_extend(&mut buf, 0, TPM_ALG_SHA256, &digest);
        assert_eq!(r, Err(TpmError::BufferTooSmall));
    }

    #[test]
    fn parse_response_truncated() {
        let buf = [0u8; 9];
        let r = TpmImpl::parse_response(&buf);
        assert_eq!(r, Err(TpmError::Truncated));
    }

    #[test]
    fn parse_response_bad_tag() {
        let mut buf = [0u8; 10];
        // tag = 0x8003 — unknown
        buf[0] = 0x80;
        buf[1] = 0x03;
        // size = 10
        buf[5] = 10;
        let r = TpmImpl::parse_response(&buf);
        assert_eq!(r, Err(TpmError::BadTag));
    }

    #[test]
    fn parse_response_bad_size_mismatch() {
        let mut buf = [0u8; 10];
        // tag = 0x8001 (no sessions)
        buf[0] = 0x80;
        buf[1] = 0x01;
        // size = 12 (lie) but buf is 10
        buf[5] = 12;
        let r = TpmImpl::parse_response(&buf);
        assert_eq!(r, Err(TpmError::BadSizeField));
    }

    #[test]
    fn parse_response_success_empty_body() {
        let mut buf = [0u8; 10];
        // tag = 0x8001
        buf[0] = 0x80;
        buf[1] = 0x01;
        // size = 10
        buf[5] = 10;
        // responseCode = 0
        let view = TpmImpl::parse_response(&buf).unwrap();
        assert_eq!(view.tag, TPM_ST_NO_SESSIONS);
        assert_eq!(view.size, 10);
        assert_eq!(view.response_code, TPM_RC_SUCCESS);
        assert!(view.body.is_empty());
    }

    #[test]
    fn parse_response_session_tag_accepted() {
        let mut buf = [0u8; 14];
        // tag = 0x8002 (sessions)
        buf[0] = 0x80;
        buf[1] = 0x02;
        // size = 14
        buf[5] = 14;
        // responseCode = 0
        buf[10] = 0xAB;
        buf[11] = 0xCD;
        buf[12] = 0xEF;
        buf[13] = 0x01;
        let view = TpmImpl::parse_response(&buf).unwrap();
        assert_eq!(view.tag, TPM_ST_SESSIONS);
        assert_eq!(view.body, &[0xAB, 0xCD, 0xEF, 0x01]);
    }

    #[test]
    fn parse_response_carries_nonzero_rc() {
        let mut buf = [0u8; 10];
        buf[0] = 0x80;
        buf[1] = 0x01;
        buf[5] = 10;
        // responseCode = 0x00000100 (TPM_RC_INITIALIZE)
        buf[8] = 0x01;
        let view = TpmImpl::parse_response(&buf).unwrap();
        assert_eq!(view.response_code, 0x0000_0100);
    }

    #[test]
    fn extract_get_random_bytes_round_trip() {
        // Hand-built GetRandom response: tag=0x8001, size=10+2+8=20,
        // rc=0, then TPM2B_DIGEST { size=8, bytes=0..7 }.
        let mut buf = [0u8; 20];
        buf[0] = 0x80;
        buf[1] = 0x01;
        // size = 20
        buf[5] = 20;
        // rc = 0
        // body: size = 8
        buf[10] = 0x00;
        buf[11] = 0x08;
        for i in 0..8 {
            buf[12 + i] = i as u8;
        }
        let view = TpmImpl::parse_response(&buf).unwrap();
        assert_eq!(view.response_code, TPM_RC_SUCCESS);
        let random = extract_get_random_bytes(view.body).unwrap();
        assert_eq!(random, &[0, 1, 2, 3, 4, 5, 6, 7]);
    }

    #[test]
    fn extract_get_random_bytes_truncated() {
        let body = [0x00u8];
        assert_eq!(
            extract_get_random_bytes(&body),
            Err(TpmError::Truncated)
        );
    }

    #[test]
    fn extract_get_random_bytes_size_mismatch() {
        // size says 8 but only 4 bytes follow.
        let body = [0x00, 0x08, 1, 2, 3, 4];
        assert_eq!(
            extract_get_random_bytes(&body),
            Err(TpmError::BadSizeField)
        );
    }

    #[test]
    fn pcr_bitmap_position_known_values() {
        assert_eq!(pcr_bitmap_position(0), (0, 0x01));
        assert_eq!(pcr_bitmap_position(7), (0, 0x80));
        assert_eq!(pcr_bitmap_position(8), (1, 0x01));
        assert_eq!(pcr_bitmap_position(15), (1, 0x80));
        assert_eq!(pcr_bitmap_position(16), (2, 0x01));
        assert_eq!(pcr_bitmap_position(23), (2, 0x80));
    }

    #[test]
    fn header_bytes_are_big_endian() {
        // Build a startup and pull the multi-byte fields out.
        let mut buf = [0u8; TPM_STARTUP_CMD_LEN];
        TpmImpl::build_startup(&mut buf, TPM_SU_CLEAR).unwrap();
        // tag = 0x8001
        assert_eq!(read_u16_be(&buf, 0), TPM_ST_NO_SESSIONS);
        // size = 12
        assert_eq!(read_u32_be(&buf, 2), TPM_STARTUP_CMD_LEN as u32);
        // cc = 0x00000144
        assert_eq!(read_u32_be(&buf, 6), TPM_CC_STARTUP);
    }

    #[test]
    fn max_cmd_buf_round_trip() {
        let mut scratch = MaxTpmCommandBuf::new();
        let n = TpmImpl::build_pcr_extend(
            scratch.as_mut(),
            8,
            TPM_ALG_SHA256,
            &[0x42u8; TPM_SHA256_DIGEST_LEN],
        )
        .unwrap();
        assert_eq!(n, TPM_PCR_EXTEND_SHA256_CMD_LEN);
        assert_eq!(scratch.prefix(n), &PCR_EXTEND_SHA256_GOLDEN[..]);
    }

    #[test]
    fn pcr_extend_session_block_byte_for_byte() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0u8; TPM_SHA256_DIGEST_LEN];
        TpmImpl::build_pcr_extend(&mut buf, 0, TPM_ALG_SHA256, &digest).unwrap();
        // authSize = 9
        assert_eq!(&buf[14..18], &[0x00, 0x00, 0x00, 0x09]);
        // session: handle = 0x40000009
        assert_eq!(&buf[18..22], &[0x40, 0x00, 0x00, 0x09]);
        // nonceSize = 0
        assert_eq!(&buf[22..24], &[0x00, 0x00]);
        // attrs = 0
        assert_eq!(buf[24], 0x00);
        // hmacSize = 0
        assert_eq!(&buf[25..27], &[0x00, 0x00]);
    }

    #[test]
    fn pcr_read_size_field_matches_buffer() {
        let mut buf = [0u8; TPM_PCR_READ_CMD_LEN];
        TpmImpl::build_pcr_read(&mut buf, 8).unwrap();
        let size = read_u32_be(&buf, 2);
        assert_eq!(size as usize, TPM_PCR_READ_CMD_LEN);
        // sizeOfSelect = 3
        assert_eq!(buf[16], 3);
    }

    #[test]
    fn pcr_extend_size_field_matches_for_sha256() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0u8; TPM_SHA256_DIGEST_LEN];
        TpmImpl::build_pcr_extend(&mut buf, 0, TPM_ALG_SHA256, &digest).unwrap();
        let size = read_u32_be(&buf, 2);
        assert_eq!(size as usize, TPM_PCR_EXTEND_SHA256_CMD_LEN);
    }

    #[test]
    fn pcr_extend_size_field_matches_for_sha1() {
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0u8; TPM_SHA1_DIGEST_LEN];
        TpmImpl::build_pcr_extend(&mut buf, 0, TPM_ALG_SHA1, &digest).unwrap();
        let size = read_u32_be(&buf, 2);
        assert_eq!(size as usize, TPM_PCR_EXTEND_SHA1_CMD_LEN);
    }

    #[test]
    fn startup_command_size_field_matches_locked_len() {
        let mut buf = [0u8; TPM_STARTUP_CMD_LEN];
        TpmImpl::build_startup(&mut buf, TPM_SU_CLEAR).unwrap();
        let size = read_u32_be(&buf, 2);
        assert_eq!(size as usize, TPM_STARTUP_CMD_LEN);
    }

    #[test]
    fn get_random_command_size_field_matches_locked_len() {
        let mut buf = [0u8; TPM_GET_RANDOM_CMD_LEN];
        TpmImpl::build_get_random(&mut buf, 32).unwrap();
        let size = read_u32_be(&buf, 2);
        assert_eq!(size as usize, TPM_GET_RANDOM_CMD_LEN);
    }

    #[test]
    fn parse_extend_response_with_session_padding_succeeds() {
        // PCR_Extend on success returns 10-byte header + 0-byte parameter
        // area + authorization area; even an empty auth area uses the
        // session tag. The header-only parser is content with that.
        let mut buf = [0u8; 19];
        buf[0] = 0x80;
        buf[1] = 0x02; // sessions
        buf[5] = 19;
        // body: 9 bytes of session auth — content irrelevant to header parser.
        let view = TpmImpl::parse_response(&buf).unwrap();
        assert_eq!(view.tag, TPM_ST_SESSIONS);
        assert_eq!(view.size, 19);
        assert_eq!(view.body.len(), 9);
    }

    #[test]
    fn build_then_parse_self_built_get_random_response() {
        // Show that the parser is happy with bytes we ourselves emitted
        // by hand-building a response that mirrors what the TPM would
        // send for `TPM2_GetRandom(4) -> [0xDE, 0xAD, 0xBE, 0xEF]`.
        let mut buf = [0u8; 16];
        buf[0] = 0x80;
        buf[1] = 0x01;
        buf[5] = 16;
        // rc = 0
        buf[11] = 4;
        buf[12] = 0xDE;
        buf[13] = 0xAD;
        buf[14] = 0xBE;
        buf[15] = 0xEF;
        let view = TpmImpl::parse_response(&buf).unwrap();
        let random = extract_get_random_bytes(view.body).unwrap();
        assert_eq!(random, &[0xDE, 0xAD, 0xBE, 0xEF]);
    }

    #[test]
    fn parse_response_tag_zero_rejected() {
        let mut buf = [0u8; 10];
        buf[5] = 10;
        let r = TpmImpl::parse_response(&buf);
        assert_eq!(r, Err(TpmError::BadTag));
    }

    #[test]
    fn parse_response_oversized_buffer_rejected() {
        // Buffer is 12 bytes but size field says 10 — disagreement
        // must surface as BadSizeField, not silent acceptance.
        let mut buf = [0u8; 12];
        buf[0] = 0x80;
        buf[1] = 0x01;
        buf[5] = 10;
        let r = TpmImpl::parse_response(&buf);
        assert_eq!(r, Err(TpmError::BadSizeField));
    }

    #[test]
    fn locked_constants_are_canonical() {
        // Compile-time-ish sanity: numeric values match what the kernel
        // banner and any external consumer locked against.
        assert_eq!(TPM_HEADER_LEN, 10);
        assert_eq!(TPM_ST_NO_SESSIONS, 0x8001);
        assert_eq!(TPM_ST_SESSIONS, 0x8002);
        assert_eq!(TPM_CC_STARTUP, 0x0000_0144);
        assert_eq!(TPM_CC_GET_RANDOM, 0x0000_017B);
        assert_eq!(TPM_CC_PCR_READ, 0x0000_017E);
        assert_eq!(TPM_CC_PCR_EXTEND, 0x0000_0182);
        assert_eq!(TPM_RS_PW, 0x4000_0009);
        assert_eq!(TPM_SHA256_DIGEST_LEN, 32);
        assert_eq!(TPM_SHA1_DIGEST_LEN, 20);
        assert_eq!(TPM_MAX_PCR_INDEX, 23);
    }

    #[test]
    fn startup_clear_response_round_trip() {
        // The kernel banner asserts byte equality on the request and
        // also walks the response shape: a 10-byte success response.
        let mut req = [0u8; TPM_STARTUP_CMD_LEN];
        let req_len = TpmImpl::build_startup(&mut req, TPM_SU_CLEAR).unwrap();
        // 12-byte request, identifying tag/cc cleanly.
        assert_eq!(read_u16_be(&req[..req_len], 0), TPM_ST_NO_SESSIONS);
        assert_eq!(read_u32_be(&req[..req_len], 6), TPM_CC_STARTUP);

        // Locked success response.
        let resp = [0x80u8, 0x01, 0x00, 0x00, 0x00, 0x0A, 0x00, 0x00, 0x00, 0x00];
        let view = TpmImpl::parse_response(&resp).unwrap();
        assert_eq!(view.tag, TPM_ST_NO_SESSIONS);
        assert_eq!(view.size, 10);
        assert_eq!(view.response_code, TPM_RC_SUCCESS);
        assert!(view.body.is_empty());
    }

    #[test]
    fn pcr_extend_pcr_handle_is_index() {
        // Per TCG, PCR handle space starts at 0x00000000 and the index
        // is the handle directly. Confirm the encoder respects that.
        let mut buf = [0u8; TPM_PCR_EXTEND_SHA256_CMD_LEN];
        let digest = [0u8; TPM_SHA256_DIGEST_LEN];
        TpmImpl::build_pcr_extend(&mut buf, 17, TPM_ALG_SHA256, &digest).unwrap();
        assert_eq!(read_u32_be(&buf, 10), 17);
    }

    #[test]
    fn tpm_tis_driver_startup_extend_read_and_random_round_trip() {
        let mut drv = TpmTisDriver::new(MemTpmTisBus::new());
        assert_eq!(drv.probe_did_vid(), Some(TPM_DEFAULT_DID_VID));
        drv.startup(TPM_SU_CLEAR).unwrap();

        let measurement = [0x42u8; 32];
        drv.pcr_extend_sha256(10, &measurement).unwrap();

        let mut pcr10 = [0u8; 32];
        let count = drv.pcr_read_sha256(10, &mut pcr10).unwrap();
        assert_eq!(count, 1);

        let expected = tpm_pcr_extend_sha256_math(&[0u8; 32], &measurement);
        assert_eq!(pcr10, expected);
        assert_eq!(drv.bus().pcr_sha256(10), &expected);

        let mut rnd_a = [0u8; 16];
        let mut rnd_b = [0u8; 16];
        assert_eq!(drv.get_random(&mut rnd_a).unwrap(), 16);
        assert_eq!(drv.get_random(&mut rnd_b).unwrap(), 16);
        assert_ne!(rnd_a, [0u8; 16]);
        assert_ne!(rnd_a, rnd_b);

        drv.relinquish_locality_0();
    }

    #[test]
    fn tpm_tis_driver_rejects_commands_before_startup() {
        let mut drv = TpmTisDriver::new(MemTpmTisBus::new());
        let mut pcr = [0u8; 32];
        assert!(drv.pcr_read_sha256(0, &mut pcr).is_err());
    }
}

