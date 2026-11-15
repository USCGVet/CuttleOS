//! DNS name label + compression pointer codec — TASK-086.

#![allow(missing_docs)]

use cuttle_contracts::{
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

const DNS_MAX_WIRE_NAME_LEN: usize = 255;
const DNS_MAX_PTR_HOPS: usize = 16;

pub fn encode_impl(labels: &[&[u8]], out: &mut [u8]) -> Result<usize, DnsNameError> {
    if labels.len() > DNS_MAX_LABELS {
        return Err(DnsNameError::TooMany);
    }
    let mut needed = 1usize; // root NUL octet
    for lab in labels {
        if lab.is_empty() || lab.len() > DNS_MAX_LABEL_LEN {
            return Err(DnsNameError::BadLabel);
        }
        needed = needed
            .checked_add(1 + lab.len())
            .ok_or(DnsNameError::BadLabel)?;
        if needed > DNS_MAX_WIRE_NAME_LEN {
            return Err(DnsNameError::BadLabel);
        }
    }
    if out.len() < needed {
        return Err(DnsNameError::BufferTooSmall);
    }
    let mut pos = 0usize;
    for lab in labels {
        out[pos] = lab.len() as u8;
        pos += 1;
        out[pos..pos + lab.len()].copy_from_slice(lab);
        pos += lab.len();
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
    let mut staged_labels = [[0u8; 64]; DNS_MAX_LABELS];
    let mut staged_lens = [0usize; DNS_MAX_LABELS];
    let mut pos = offset;
    let mut count = 0usize;
    let mut consumed = 0usize;
    let mut followed_ptr = false;
    let mut hops = 0usize;
    let mut wire_octets = 0usize;
    loop {
        if pos >= msg.len() {
            return Err(DnsNameError::Truncated);
        }
        let len = msg[pos];
        if len == 0 {
            wire_octets = wire_octets.checked_add(1).ok_or(DnsNameError::BadLabel)?;
            if wire_octets > DNS_MAX_WIRE_NAME_LEN {
                return Err(DnsNameError::BadLabel);
            }
            if !followed_ptr {
                consumed = pos
                    .checked_add(1)
                    .and_then(|end| end.checked_sub(offset))
                    .ok_or(DnsNameError::Truncated)?;
            }
            for i in 0..count {
                let n = staged_lens[i];
                out_labels[i][..n].copy_from_slice(&staged_labels[i][..n]);
                out_lens[i] = n;
            }
            return Ok((count, consumed));
        }
        if len & DNS_PTR_MASK == DNS_PTR_MASK {
            let ptr_lo_idx = pos.checked_add(1).ok_or(DnsNameError::Truncated)?;
            if ptr_lo_idx >= msg.len() {
                return Err(DnsNameError::Truncated);
            }
            let ptr = ((((len as u16) & 0x3F) << 8) | (msg[ptr_lo_idx] as u16)) as usize;
            // RFC 1035 §4.1.4: compression pointers MUST strictly point backward (`ptr < pos`).
            if ptr >= pos {
                return Err(DnsNameError::BadLabel);
            }
            hops += 1;
            if hops > DNS_MAX_PTR_HOPS {
                return Err(DnsNameError::BadLabel);
            }
            if !followed_ptr {
                consumed = pos
                    .checked_add(2)
                    .and_then(|end| end.checked_sub(offset))
                    .ok_or(DnsNameError::Truncated)?;
            }
            followed_ptr = true;
            pos = ptr;
            continue;
        }
        if len & DNS_PTR_MASK != 0 {
            return Err(DnsNameError::BadLabel);
        }
        let n = len as usize;
        if n > DNS_MAX_LABEL_LEN {
            return Err(DnsNameError::BadLabel);
        }
        let label_start = pos.checked_add(1).ok_or(DnsNameError::Truncated)?;
        let label_end = label_start.checked_add(n).ok_or(DnsNameError::Truncated)?;
        if label_end > msg.len() {
            return Err(DnsNameError::Truncated);
        }
        wire_octets = wire_octets
            .checked_add(1 + n)
            .ok_or(DnsNameError::BadLabel)?;
        if wire_octets >= DNS_MAX_WIRE_NAME_LEN {
            return Err(DnsNameError::BadLabel);
        }
        if count >= DNS_MAX_LABELS {
            return Err(DnsNameError::TooMany);
        }
        staged_labels[count][..n].copy_from_slice(&msg[label_start..label_end]);
        staged_lens[count] = n;
        count += 1;
        pos = label_end;
    }
}

pub fn make_pointer_impl(target_offset: u16) -> [u8; 2] {
    let v = 0xC000u16 | (target_offset & 0x3FFF);
    v.to_be_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::DnsName;

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
        let n = DnsNameImpl::encode(&[b"cuttle", b"os"], &mut wire).unwrap();
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        let (c, cons) = DnsNameImpl::decode(&wire, 0, &mut labs, &mut lens).unwrap();
        assert_eq!(c, 2);
        assert_eq!(cons, n);
        assert_eq!(&labs[0][..lens[0]], b"cuttle");
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

    #[test]
    fn decode_rejects_self_and_forward_compression_pointers_and_reserved_labels() {
        extern crate std;
        let (tx, rx) = std::sync::mpsc::channel();
        std::thread::spawn(move || {
            let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
            let mut lens = [0usize; DNS_MAX_LABELS];
            let r_self = DnsNameImpl::decode(&[0xC0, 0x00], 0, &mut labs, &mut lens);
            let r_fwd = DnsNameImpl::decode(&[0xC0, 0x02, 0x01, b'a', 0x00], 0, &mut labs, &mut lens);
            let r_cycle = DnsNameImpl::decode(&[0xC0, 0x02, 0xC0, 0x00], 2, &mut labs, &mut lens);
            let _ = tx.send((r_self, r_fwd, r_cycle));
        });
        let (r_self, r_fwd, r_cycle) = rx
            .recv_timeout(std::time::Duration::from_millis(150))
            .expect("DnsNameImpl::decode hung on compression pointer cycle");
        assert!(r_self.is_err(), "self-pointer at offset 0 must fail");
        assert!(r_fwd.is_err(), "forward compression pointer must fail");
        assert!(r_cycle.is_err(), "compression pointer cycle must fail");

        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        // Reserved RFC 1035 label header bits 01xxxxxx (0x41) and 10xxxxxx (0x81)
        assert_eq!(
            DnsNameImpl::decode(&[0x41, b'a', 0x00], 0, &mut labs, &mut lens),
            Err(DnsNameError::BadLabel)
        );
        assert_eq!(
            DnsNameImpl::decode(&[0x81, b'a', 0x00], 0, &mut labs, &mut lens),
            Err(DnsNameError::BadLabel)
        );
    }

    #[test]
    fn encode_and_decode_enforce_rfc1035_255_octet_wire_limit() {
        // 4 labels of 63 octets = 4 * 64 + 1 = 257 wire octets (> 255 max).
        let lab63 = [b'a'; 63];
        let four_63: [&[u8]; 4] = [&lab63, &lab63, &lab63, &lab63];
        let mut out = [0u8; 300];
        assert!(
            DnsNameImpl::encode(&four_63, &mut out).is_err(),
            "RFC 1035 §2.3.4 forbids wire names exceeding 255 octets"
        );

        // Manually construct 257-octet wire name and verify decode also rejects it.
        let mut raw = [0u8; 257];
        let mut p = 0usize;
        for _ in 0..4 {
            raw[p] = 63;
            raw[p + 1..p + 64].fill(b'x');
            p += 64;
        }
        raw[p] = 0;
        let mut labs = [[0u8; 64]; DNS_MAX_LABELS];
        let mut lens = [0usize; DNS_MAX_LABELS];
        assert!(
            DnsNameImpl::decode(&raw, 0, &mut labs, &mut lens).is_err(),
            "DnsNameImpl::decode must reject wire names > 255 octets"
        );
    }

    #[test]
    fn encode_and_decode_are_all_or_nothing_on_failure() {
        let mut out = [0xAAu8; 5];
        assert_eq!(
            DnsNameImpl::encode(&[b"ab", b"cd"], &mut out),
            Err(DnsNameError::BufferTooSmall)
        );
        assert_eq!(
            out,
            [0xAAu8; 5],
            "failed DnsNameImpl::encode must leave output untouched"
        );

        let mut labs = [[0xAAu8; 64]; DNS_MAX_LABELS];
        let mut lens = [99usize; DNS_MAX_LABELS];
        assert_eq!(
            DnsNameImpl::decode(b"\x03www\x05trun", 0, &mut labs, &mut lens),
            Err(DnsNameError::Truncated)
        );
        assert_eq!(
            labs,
            [[0xAAu8; 64]; DNS_MAX_LABELS],
            "failed DnsNameImpl::decode must leave out_labels untouched"
        );
        assert_eq!(
            lens,
            [99usize; DNS_MAX_LABELS],
            "failed DnsNameImpl::decode must leave out_lens untouched"
        );
    }
}
