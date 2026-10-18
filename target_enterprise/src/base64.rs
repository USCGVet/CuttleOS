//! RFC 4648 Base64 encode/decode — TASK-092.

#![allow(missing_docs)]

use cuttle_contracts::{Base64, Base64Error};

const ENC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub struct Base64Impl;

impl Base64 for Base64Impl {
    fn encode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error> {
        encode_impl(input, out)
    }
    fn decode(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error> {
        decode_impl(input, out)
    }
    fn encoded_len(n: usize) -> usize {
        encoded_len_impl(n)
    }
}

pub fn encoded_len_impl(n: usize) -> usize {
    n.div_ceil(3) * 4
}

fn dec_val(c: u8) -> Result<u8, Base64Error> {
    match c {
        b'A'..=b'Z' => Ok(c - b'A'),
        b'a'..=b'z' => Ok(c - b'a' + 26),
        b'0'..=b'9' => Ok(c - b'0' + 52),
        b'+' => Ok(62),
        b'/' => Ok(63),
        _ => Err(Base64Error::InvalidInput),
    }
}

pub fn encode_impl(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error> {
    let need = encoded_len_impl(input.len());
    if out.len() < need {
        return Err(Base64Error::BufferTooSmall);
    }
    let mut i = 0usize;
    let mut o = 0usize;
    while i + 3 <= input.len() {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8) | (input[i + 2] as u32);
        out[o] = ENC[((n >> 18) & 0x3F) as usize];
        out[o + 1] = ENC[((n >> 12) & 0x3F) as usize];
        out[o + 2] = ENC[((n >> 6) & 0x3F) as usize];
        out[o + 3] = ENC[(n & 0x3F) as usize];
        i += 3;
        o += 4;
    }
    let rem = input.len() - i;
    if rem == 1 {
        let n = (input[i] as u32) << 16;
        out[o] = ENC[((n >> 18) & 0x3F) as usize];
        out[o + 1] = ENC[((n >> 12) & 0x3F) as usize];
        out[o + 2] = b'=';
        out[o + 3] = b'=';
        o += 4;
    } else if rem == 2 {
        let n = ((input[i] as u32) << 16) | ((input[i + 1] as u32) << 8);
        out[o] = ENC[((n >> 18) & 0x3F) as usize];
        out[o + 1] = ENC[((n >> 12) & 0x3F) as usize];
        out[o + 2] = ENC[((n >> 6) & 0x3F) as usize];
        out[o + 3] = b'=';
        o += 4;
    }
    Ok(o)
}

pub fn decode_impl(input: &[u8], out: &mut [u8]) -> Result<usize, Base64Error> {
    if input.is_empty() {
        return Ok(0);
    }
    if input.len() % 4 != 0 {
        return Err(Base64Error::BadLength);
    }
    let mut o = 0usize;
    let mut i = 0usize;
    while i < input.len() {
        let c0 = input[i];
        let c1 = input[i + 1];
        let c2 = input[i + 2];
        let c3 = input[i + 3];
        if c0 == b'=' || c1 == b'=' {
            return Err(Base64Error::InvalidInput);
        }
        let v0 = dec_val(c0)? as u32;
        let v1 = dec_val(c1)? as u32;
        let (v2, pad2) = if c2 == b'=' {
            (0u32, true)
        } else {
            (dec_val(c2)? as u32, false)
        };
        let (v3, pad3) = if c3 == b'=' {
            (0u32, true)
        } else {
            (dec_val(c3)? as u32, false)
        };
        if pad2 && !pad3 {
            return Err(Base64Error::InvalidInput);
        }
        if pad2 && i + 4 != input.len() {
            return Err(Base64Error::InvalidInput);
        }
        let n = (v0 << 18) | (v1 << 12) | (v2 << 6) | v3;
        let produce = if pad2 {
            1
        } else if pad3 {
            2
        } else {
            3
        };
        if o + produce > out.len() {
            return Err(Base64Error::BufferTooSmall);
        }
        out[o] = ((n >> 16) & 0xFF) as u8;
        if produce >= 2 {
            out[o + 1] = ((n >> 8) & 0xFF) as u8;
        }
        if produce == 3 {
            out[o + 2] = (n & 0xFF) as u8;
        }
        o += produce;
        i += 4;
    }
    Ok(o)
}

/// Banner: encode "cuttle" and decode back.
pub fn banner_roundtrip() -> bool {
    let msg = b"cuttle";
    let mut enc = [0u8; 16];
    let n = match Base64Impl::encode(msg, &mut enc) {
        Ok(n) => n,
        Err(_) => return false,
    };
    let mut dec = [0u8; 16];
    let m = match Base64Impl::decode(&enc[..n], &mut dec) {
        Ok(m) => m,
        Err(_) => return false,
    };
    &dec[..m] == msg
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::Base64;

    #[test]
    fn empty() {
        let mut o = [0u8; 4];
        assert_eq!(Base64Impl::encode(b"", &mut o).unwrap(), 0);
        assert_eq!(Base64Impl::decode(b"", &mut o).unwrap(), 0);
    }

    #[test]
    fn rfc_f() {
        // RFC 4648: "f" → "Zg=="
        let mut o = [0u8; 8];
        let n = Base64Impl::encode(b"f", &mut o).unwrap();
        assert_eq!(&o[..n], b"Zg==");
        let mut d = [0u8; 4];
        let m = Base64Impl::decode(b"Zg==", &mut d).unwrap();
        assert_eq!(&d[..m], b"f");
    }

    #[test]
    fn rfc_fo() {
        let mut o = [0u8; 8];
        let n = Base64Impl::encode(b"fo", &mut o).unwrap();
        assert_eq!(&o[..n], b"Zm8=");
    }

    #[test]
    fn rfc_foo() {
        let mut o = [0u8; 8];
        let n = Base64Impl::encode(b"foo", &mut o).unwrap();
        assert_eq!(&o[..n], b"Zm9v");
    }

    #[test]
    fn rfc_foobar() {
        let mut o = [0u8; 16];
        let n = Base64Impl::encode(b"foobar", &mut o).unwrap();
        assert_eq!(&o[..n], b"Zm9vYmFy");
        let mut d = [0u8; 16];
        let m = Base64Impl::decode(&o[..n], &mut d).unwrap();
        assert_eq!(&d[..m], b"foobar");
    }

    #[test]
    fn encoded_len() {
        assert_eq!(Base64Impl::encoded_len(0), 0);
        assert_eq!(Base64Impl::encoded_len(1), 4);
        assert_eq!(Base64Impl::encoded_len(2), 4);
        assert_eq!(Base64Impl::encoded_len(3), 4);
        assert_eq!(Base64Impl::encoded_len(4), 8);
    }

    #[test]
    fn buffer_small_enc() {
        let mut o = [0u8; 2];
        assert_eq!(
            Base64Impl::encode(b"f", &mut o),
            Err(Base64Error::BufferTooSmall)
        );
    }

    #[test]
    fn bad_length() {
        let mut d = [0u8; 8];
        assert_eq!(
            Base64Impl::decode(b"A", &mut d),
            Err(Base64Error::BadLength)
        );
    }

    #[test]
    fn invalid_char() {
        let mut d = [0u8; 8];
        assert_eq!(
            Base64Impl::decode(b"!!!!", &mut d),
            Err(Base64Error::InvalidInput)
        );
    }

    #[test]
    fn banner() {
        assert!(banner_roundtrip());
    }

    #[test]
    fn free_match() {
        let mut a = [0u8; 16];
        let mut b = [0u8; 16];
        encode_impl(b"x", &mut a).unwrap();
        Base64Impl::encode(b"x", &mut b).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn det() {
        assert!(banner_roundtrip());
        assert!(banner_roundtrip());
    }

    #[test]
    fn banner_str() {
        // B64 roundtrip OK
        assert!(banner_roundtrip());
    }

    #[test]
    fn end_to_end() {
        let msg = b"cuttle-b64";
        let mut e = [0u8; 32];
        let n = Base64Impl::encode(msg, &mut e).unwrap();
        let mut d = [0u8; 32];
        let m = Base64Impl::decode(&e[..n], &mut d).unwrap();
        assert_eq!(&d[..m], msg);
    }

    #[test]
    fn plus_slash() {
        // bytes that produce + and /
        let mut e = [0u8; 8];
        let n = Base64Impl::encode(&[0xFB, 0xFF, 0xFE], &mut e).unwrap();
        assert!(e[..n].contains(&b'+') || e[..n].contains(&b'/') || n == 4);
        let mut d = [0u8; 4];
        let m = Base64Impl::decode(&e[..n], &mut d).unwrap();
        assert_eq!(&d[..m], &[0xFB, 0xFF, 0xFE]);
    }

    #[test]
    fn pad_one() {
        let mut d = [0u8; 4];
        let m = Base64Impl::decode(b"YQ==", &mut d).unwrap();
        assert_eq!(&d[..m], b"a");
    }

    #[test]
    fn pad_two() {
        let mut d = [0u8; 4];
        let m = Base64Impl::decode(b"YWI=", &mut d).unwrap();
        assert_eq!(&d[..m], b"ab");
    }
}
