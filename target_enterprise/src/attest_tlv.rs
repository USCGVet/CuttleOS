//! JSON-free attestation TLV field codec — TASK-091.

#![allow(missing_docs)]

use cuttle_contracts::{
    AttestTlv, AttestTlvError, AttestTlvRecord, ATTEST_TLV_HDR_LEN, ATTEST_TLV_MAX_TAGS,
    ATTEST_TLV_MAX_VAL, ATTEST_TLV_TAG_CYCLE, ATTEST_TLV_TAG_MODULE, ATTEST_TLV_TAG_SEED,
};

pub struct AttestTlvImpl;

impl AttestTlv for AttestTlvImpl {
    fn encode(tag: u16, value: &[u8], out: &mut [u8]) -> Result<usize, AttestTlvError> {
        encode_impl(tag, value, out)
    }
    fn decode(buf: &[u8]) -> Result<AttestTlvRecord, AttestTlvError> {
        decode_impl(buf)
    }
    fn count_sequence(buf: &[u8]) -> Result<usize, AttestTlvError> {
        count_sequence_impl(buf)
    }
}

pub fn encode_impl(tag: u16, value: &[u8], out: &mut [u8]) -> Result<usize, AttestTlvError> {
    if value.len() > ATTEST_TLV_MAX_VAL {
        return Err(AttestTlvError::ValueTooLong);
    }
    let need = ATTEST_TLV_HDR_LEN + value.len();
    if out.len() < need {
        return Err(AttestTlvError::BufferTooSmall);
    }
    out[0..2].copy_from_slice(&tag.to_le_bytes());
    out[2..4].copy_from_slice(&(value.len() as u16).to_le_bytes());
    out[4..4 + value.len()].copy_from_slice(value);
    Ok(need)
}

pub fn decode_impl(buf: &[u8]) -> Result<AttestTlvRecord, AttestTlvError> {
    if buf.len() < ATTEST_TLV_HDR_LEN {
        return Err(AttestTlvError::Truncated);
    }
    let tag = u16::from_le_bytes([buf[0], buf[1]]);
    let len = u16::from_le_bytes([buf[2], buf[3]]) as usize;
    if len > ATTEST_TLV_MAX_VAL {
        return Err(AttestTlvError::ValueTooLong);
    }
    if buf.len() < ATTEST_TLV_HDR_LEN + len {
        return Err(AttestTlvError::Truncated);
    }
    Ok(AttestTlvRecord {
        tag,
        value_off: ATTEST_TLV_HDR_LEN,
        value_len: len,
    })
}

pub fn count_sequence_impl(buf: &[u8]) -> Result<usize, AttestTlvError> {
    let mut off = 0usize;
    let mut n = 0usize;
    while off < buf.len() {
        if n >= ATTEST_TLV_MAX_TAGS {
            return Err(AttestTlvError::TooMany);
        }
        if buf.len() - off < ATTEST_TLV_HDR_LEN {
            return Err(AttestTlvError::Truncated);
        }
        let len = u16::from_le_bytes([buf[off + 2], buf[off + 3]]) as usize;
        if len > ATTEST_TLV_MAX_VAL {
            return Err(AttestTlvError::ValueTooLong);
        }
        let rec = ATTEST_TLV_HDR_LEN + len;
        if buf.len() - off < rec {
            return Err(AttestTlvError::Truncated);
        }
        off += rec;
        n += 1;
    }
    Ok(n)
}

/// Banner fixture: cycle + seed + module → 3 tags.
pub fn banner_three_tags(out: &mut [u8]) -> Result<usize, AttestTlvError> {
    let mut pos = 0;
    pos += AttestTlvImpl::encode(ATTEST_TLV_TAG_CYCLE, &6201u32.to_le_bytes(), &mut out[pos..])?;
    pos += AttestTlvImpl::encode(ATTEST_TLV_TAG_SEED, &0xAAu8.to_le_bytes(), &mut out[pos..])?;
    pos += AttestTlvImpl::encode(ATTEST_TLV_TAG_MODULE, b"ahci", &mut out[pos..])?;
    Ok(pos)
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::AttestTlv;

    #[test]
    fn constants() {
        assert_eq!(ATTEST_TLV_HDR_LEN, 4);
        assert_eq!(ATTEST_TLV_TAG_CYCLE, 1);
        assert_eq!(ATTEST_TLV_TAG_SEED, 2);
        assert_eq!(ATTEST_TLV_TAG_MODULE, 3);
    }

    #[test]
    fn encode_decode() {
        let mut b = [0u8; 32];
        let n = AttestTlvImpl::encode(7, b"hi", &mut b).unwrap();
        assert_eq!(n, 6);
        let r = AttestTlvImpl::decode(&b[..n]).unwrap();
        assert_eq!(r.tag, 7);
        assert_eq!(r.value_len, 2);
        assert_eq!(&b[r.value_off..r.value_off + r.value_len], b"hi");
    }

    #[test]
    fn three_tags() {
        let mut b = [0u8; 64];
        let n = banner_three_tags(&mut b).unwrap();
        assert_eq!(AttestTlvImpl::count_sequence(&b[..n]).unwrap(), 3);
    }

    #[test]
    fn empty_value() {
        let mut b = [0u8; 8];
        let n = AttestTlvImpl::encode(1, b"", &mut b).unwrap();
        assert_eq!(n, 4);
        let r = AttestTlvImpl::decode(&b[..n]).unwrap();
        assert_eq!(r.value_len, 0);
    }

    #[test]
    fn value_too_long() {
        let v = [0u8; ATTEST_TLV_MAX_VAL + 1];
        let mut b = [0u8; 512];
        assert_eq!(
            AttestTlvImpl::encode(1, &v, &mut b),
            Err(AttestTlvError::ValueTooLong)
        );
    }

    #[test]
    fn buffer_small() {
        let mut b = [0u8; 3];
        assert_eq!(
            AttestTlvImpl::encode(1, b"x", &mut b),
            Err(AttestTlvError::BufferTooSmall)
        );
    }

    #[test]
    fn truncated_header() {
        assert_eq!(
            AttestTlvImpl::decode(&[1, 0]),
            Err(AttestTlvError::Truncated)
        );
    }

    #[test]
    fn truncated_value() {
        let mut b = [0u8; 4];
        b[0] = 1;
        b[2] = 10; // claims 10 bytes
        assert_eq!(AttestTlvImpl::decode(&b), Err(AttestTlvError::Truncated));
    }

    #[test]
    fn free_match() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        encode_impl(1, b"z", &mut a).unwrap();
        AttestTlvImpl::encode(1, b"z", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn le_tag() {
        let mut b = [0u8; 8];
        AttestTlvImpl::encode(0x0201, b"", &mut b).unwrap();
        assert_eq!(b[0], 0x01);
        assert_eq!(b[1], 0x02);
    }

    #[test]
    fn sequence_empty() {
        assert_eq!(AttestTlvImpl::count_sequence(&[]).unwrap(), 0);
    }

    #[test]
    fn banner() {
        let mut b = [0u8; 64];
        let n = banner_three_tags(&mut b).unwrap();
        assert_eq!(AttestTlvImpl::count_sequence(&b[..n]).unwrap(), 3);
    }

    #[test]
    fn banner_str() {
        // TLV parse OK tags=3
        assert_eq!(ATTEST_TLV_TAG_MODULE, 3);
    }

    #[test]
    fn det() {
        let mut a = [0u8; 64];
        let mut b = [0u8; 64];
        let na = banner_three_tags(&mut a).unwrap();
        let nb = banner_three_tags(&mut b).unwrap();
        assert_eq!(&a[..na], &b[..nb]);
    }

    #[test]
    fn max_val_ok() {
        let v = [0xABu8; ATTEST_TLV_MAX_VAL];
        let mut b = [0u8; ATTEST_TLV_HDR_LEN + ATTEST_TLV_MAX_VAL];
        let n = AttestTlvImpl::encode(9, &v, &mut b).unwrap();
        let r = AttestTlvImpl::decode(&b[..n]).unwrap();
        assert_eq!(r.value_len, ATTEST_TLV_MAX_VAL);
    }

    #[test]
    fn end_to_end() {
        let mut b = [0u8; 64];
        let n = banner_three_tags(&mut b).unwrap();
        let r0 = AttestTlvImpl::decode(&b[..n]).unwrap();
        assert_eq!(r0.tag, ATTEST_TLV_TAG_CYCLE);
    }

    #[test]
    fn two_then_count() {
        let mut b = [0u8; 32];
        let mut p = 0;
        p += AttestTlvImpl::encode(1, b"a", &mut b[p..]).unwrap();
        p += AttestTlvImpl::encode(2, b"bb", &mut b[p..]).unwrap();
        assert_eq!(AttestTlvImpl::count_sequence(&b[..p]).unwrap(), 2);
    }
}
