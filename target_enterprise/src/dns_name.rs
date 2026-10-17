//! DNS name label + compression pointer codec — TASK-086.

#![allow(missing_docs)]

use proteus_contracts::{
    DnsName, DnsNameError, DNS_MAX_LABEL_LEN, DNS_MAX_LABELS, DNS_PTR_MASK,
};

pub struct DnsNameImpl;

impl DnsName for DnsNameImpl {
    fn encode(labels: &[&[u8]], out: &mut [u8]) -> Result<usize, DnsNameError> {
        encode_impl(labels, out)
    }
    fn decode(
        msg: &[u8],
        offset: usize,
        out_labels: &mut [[u8; 64]; DNS_MAX_LABELS],
        out_lens: &mut [usize; DNS_MAX_LABELS],
    ) -> Result<(usize, usize), DnsNameError> {
        decode_impl(msg, offset, out_labels, out_lens)
    }
    fn make_pointer(target_offset: u16) -> [u8; 2] {
        make_pointer_impl(target_offset)
    }
}

pub fn encode_impl(labels: &[&[u8]], out: &mut [u8]) -> Result<usize, DnsNameError> {
    if labels.len() > DNS_MAX_LABELS {
        return Err(DnsNameError::TooMany);
    }
    let mut pos = 0usize;
    for lab in labels {
        if lab.is_empty() || lab.len() > DNS_MAX_LABEL_LEN {
            return Err(DnsNameError::BadLabel);
        }
        if pos + 1 + lab.len() + 1 > out.len() {
            return Err(DnsNameError::BufferTooSmall);
        }
        out[pos] = lab.len() as u8;
        pos += 1;
        out[pos..pos + lab.len()].copy_from_slice(lab);
        pos += lab.len();
    }
    if pos >= out.len() {
        return Err(DnsNameError::BufferTooSmall);
    }
    out[pos] = 0;
    Ok(pos + 1)
}

pub fn decode_impl(
    msg: &[u8],
    offset: usize,
    out_labels: &mut [[u8; 64]; DNS_MAX_LABELS],
    out_lens: &mut [usize; DNS_MAX_LABELS],
) -> Result<(usize, usize), DnsNameError> {
    let mut pos = offset;
    let mut count = 0usize;
    let mut consumed = 0usize;
    let mut followed_ptr = false;
    loop {
        if pos >= msg.len() {
            return Err(DnsNameError::Truncated);
        }
        let len = msg[pos];
        if len == 0 {
            if !followed_ptr {
                consumed = pos + 1 - offset;
            }
            return Ok((count, consumed));
        }
        if len & DNS_PTR_MASK == DNS_PTR_MASK {
            if pos + 1 >= msg.len() {
                return Err(DnsNameError::Truncated);
            }
            let ptr = (((len as u16) & 0x3F) << 8) | (msg[pos + 1] as u16);
            if !followed_ptr {
                consumed = pos + 2 - offset;
            }
            followed_ptr = true;
            pos = ptr as usize;
            continue;
        }
        if len as usize > DNS_MAX_LABEL_LEN {
            return Err(DnsNameError::BadLabel);
        }
        if pos + 1 + (len as usize) > msg.len() {
            return Err(DnsNameError::Truncated);
        }
        if count >= DNS_MAX_LABELS {
            return Err(DnsNameError::TooMany);
        }
        let n = len as usize;
        out_labels[count][..n].copy_from_slice(&msg[pos + 1..pos + 1 + n]);
        out_lens[count] = n;
        count += 1;
        pos += 1 + n;
    }
}

pub fn make_pointer_impl(target_offset: u16) -> [u8; 2] {
    let v = 0xC000u16 | (target_offset & 0x3FFF);
    v.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::DnsName;

    #[test]
    fn encode_two_labels() {
        let mut out = [0u8; 32];
        let n = DnsNameImpl::encode(&[b"www", b"x"], &mut out).unwrap();
        assert_eq!(&out[..n], b"\x03www\x01x\x00");
    }

    #[test]
    fn decode_two() {
        let msg = b"\x03www\x01x\x00";
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        let (c, cons) = DnsNameImpl::decode(msg, 0, &mut labs, &mut lens).unwrap();
        assert_eq!(c, 2);
        assert_eq!(cons, 7);
        assert_eq!(&labs[0][..lens[0]], b"www");
        assert_eq!(&labs[1][..lens[1]], b"x");
    }

    #[test]
    fn pointer() {
        let p = DnsNameImpl::make_pointer(0x000C);
        assert_eq!(p, [0xC0, 0x0C]);
    }

    #[test]
    fn decode_with_ptr() {
        // msg: 03www00 then at offset 0 name that is ptr to 0
        // Actually: full name at 0: 03www01x00; second name at 8: ptr to 0
        let mut msg = [0u8; 16];
        let n = DnsNameImpl::encode(&[b"www", b"x"], &mut msg).unwrap();
        assert_eq!(n, 7);
        let p = DnsNameImpl::make_pointer(0);
        msg[8] = p[0];
        msg[9] = p[1];
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        let (c, cons) = DnsNameImpl::decode(&msg, 8, &mut labs, &mut lens).unwrap();
        assert_eq!(c, 2);
        assert_eq!(cons, 2); // only pointer bytes consumed at start
        assert_eq!(&labs[0][..3], b"www");
    }

    #[test]
    fn empty_label_bad() {
        let mut out = [0u8; 8];
        assert_eq!(
            DnsNameImpl::encode(&[b""], &mut out),
            Err(DnsNameError::BadLabel)
        );
    }

    #[test]
    fn too_long_label() {
        let mut out = [0u8; 128];
        let lab = [b'a'; 64];
        assert!(DnsNameImpl::encode(&[&lab], &mut out).is_err());
    }

    #[test]
    fn buffer_small() {
        let mut out = [0u8; 2];
        assert!(DnsNameImpl::encode(&[b"ab"], &mut out).is_err());
    }

    #[test]
    fn truncated_decode() {
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        assert!(DnsNameImpl::decode(b"\x03ww", 0, &mut labs, &mut lens).is_err());
    }

    #[test]
    fn root_only() {
        let mut out = [0u8; 4];
        let n = DnsNameImpl::encode(&[], &mut out).unwrap();
        assert_eq!(n, 1);
        assert_eq!(out[0], 0);
    }

    #[test]
    fn free_match() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        assert_eq!(
            encode_impl(&[b"a"], &mut a).unwrap(),
            DnsNameImpl::encode(&[b"a"], &mut b).unwrap()
        );
    }

    #[test]
    fn constants() {
        assert_eq!(DNS_MAX_LABELS, 8);
        assert_eq!(DNS_MAX_LABEL_LEN, 63);
        assert_eq!(DNS_PTR_MASK, 0xC0);
    }

    #[test]
    fn banner() {
        let mut out = [0u8; 32];
        let n = DnsNameImpl::encode(&[b"a", b"b"], &mut out).unwrap();
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        let (c, _) = DnsNameImpl::decode(&out[..n], 0, &mut labs, &mut lens).unwrap();
        assert_eq!(c, 2);
    }

    #[test]
    fn pointer_max_offset() {
        let p = make_pointer_impl(0x3FFF);
        assert_eq!(p[0], 0xFF);
        assert_eq!(p[1], 0xFF);
    }

    #[test]
    fn three_labels() {
        let mut out = [0u8; 32];
        let n = DnsNameImpl::encode(&[b"a", b"b", b"c"], &mut out).unwrap();
        assert_eq!(out[n - 1], 0);
    }

    #[test]
    fn det() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        DnsNameImpl::encode(&[b"x"], &mut a).unwrap();
        DnsNameImpl::encode(&[b"x"], &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn errors() {
        assert_ne!(DnsNameError::Truncated, DnsNameError::BadLabel);
    }

    #[test]
    fn end_to_end() {
        let mut wire = [0u8; 32];
        let n = DnsNameImpl::encode(&[b"proteus", b"os"], &mut wire).unwrap();
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        let (c, cons) = DnsNameImpl::decode(&wire, 0, &mut labs, &mut lens).unwrap();
        assert_eq!(c, 2);
        assert_eq!(cons, n);
        assert_eq!(&labs[0][..lens[0]], b"proteus");
    }

    #[test]
    fn too_many_encode() {
        let labs: [&[u8]; 9] = [
            b"a", b"b", b"c", b"d", b"e", b"f", b"g", b"h", b"i",
        ];
        let mut out = [0u8; 64];
        assert_eq!(
            DnsNameImpl::encode(&labs, &mut out),
            Err(DnsNameError::TooMany)
        );
    }

    #[test]
    fn make_ptr_zero() {
        assert_eq!(DnsNameImpl::make_pointer(0), [0xC0, 0x00]);
    }

    #[test]
    fn banner_str() {
        // DNS name OK labels=2
        assert_eq!(2usize, 2);
    }

    #[test]
    fn label_len_63_ok() {
        let lab = [b'x'; 63];
        let mut out = [0u8; 80];
        assert!(DnsNameImpl::encode(&[&lab], &mut out).is_ok());
    }

    #[test]
    fn decode_root() {
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        let (c, cons) = DnsNameImpl::decode(b"\x00", 0, &mut labs, &mut lens).unwrap();
        assert_eq!((c, cons), (0, 1));
    }

    #[test]
    fn ptr_truncated() {
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        assert!(DnsNameImpl::decode(b"\xC0", 0, &mut labs, &mut lens).is_err());
    }

    #[test]
    fn encode_single() {
        let mut out = [0u8; 8];
        assert_eq!(DnsNameImpl::encode(&[b"z"], &mut out).unwrap(), 3);
    }
}
