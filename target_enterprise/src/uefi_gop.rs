//! UEFI GOP mode info pack/unpack — TASK-090.

#![allow(missing_docs)]

use cuttle_contracts::{GopError, GopModeInfo, UefiGop, GOP_MODE_INFO_LEN, GOP_PIXEL_BGR};
#[cfg(test)]
use cuttle_contracts::{GOP_PIXEL_BITMASK, GOP_PIXEL_BLT_ONLY, GOP_PIXEL_RGB};

pub struct UefiGopImpl;

impl UefiGop for UefiGopImpl {
    fn encode(info: &GopModeInfo, out: &mut [u8]) -> Result<usize, GopError> {
        encode_impl(info, out)
    }
    fn decode(buf: &[u8]) -> Result<GopModeInfo, GopError> {
        decode_impl(buf)
    }
    fn mode_1280x720() -> GopModeInfo {
        mode_1280x720_impl()
    }
}

fn put_u32(out: &mut [u8], off: usize, v: u32) {
    out[off..off + 4].copy_from_slice(&v.to_le_bytes());
}

fn get_u32(buf: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([buf[off], buf[off + 1], buf[off + 2], buf[off + 3]])
}

pub fn encode_impl(info: &GopModeInfo, out: &mut [u8]) -> Result<usize, GopError> {
    if out.len() < GOP_MODE_INFO_LEN {
        return Err(GopError::Truncated);
    }
    if info.horizontal == 0 || info.vertical == 0 {
        return Err(GopError::BadGeometry);
    }
    if info.pixels_per_scan_line < info.horizontal {
        return Err(GopError::BadGeometry);
    }
    put_u32(out, 0, info.version);
    put_u32(out, 4, info.horizontal);
    put_u32(out, 8, info.vertical);
    put_u32(out, 12, info.pixel_format);
    put_u32(out, 16, info.red_mask);
    put_u32(out, 20, info.green_mask);
    put_u32(out, 24, info.blue_mask);
    put_u32(out, 28, info.reserved_mask);
    put_u32(out, 32, info.pixels_per_scan_line);
    // pad to 40
    put_u32(out, 36, 0);
    Ok(GOP_MODE_INFO_LEN)
}

pub fn decode_impl(buf: &[u8]) -> Result<GopModeInfo, GopError> {
    if buf.len() < GOP_MODE_INFO_LEN {
        return Err(GopError::Truncated);
    }
    let info = GopModeInfo {
        version: get_u32(buf, 0),
        horizontal: get_u32(buf, 4),
        vertical: get_u32(buf, 8),
        pixel_format: get_u32(buf, 12),
        red_mask: get_u32(buf, 16),
        green_mask: get_u32(buf, 20),
        blue_mask: get_u32(buf, 24),
        reserved_mask: get_u32(buf, 28),
        pixels_per_scan_line: get_u32(buf, 32),
    };
    if info.horizontal == 0 || info.vertical == 0 {
        return Err(GopError::BadGeometry);
    }
    if info.pixels_per_scan_line < info.horizontal {
        return Err(GopError::BadGeometry);
    }
    Ok(info)
}

pub fn mode_1280x720_impl() -> GopModeInfo {
    GopModeInfo {
        version: 0,
        horizontal: 1280,
        vertical: 720,
        pixel_format: GOP_PIXEL_BGR,
        red_mask: 0,
        green_mask: 0,
        blue_mask: 0,
        reserved_mask: 0,
        pixels_per_scan_line: 1280,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::UefiGop;

    #[test]
    fn constants() {
        assert_eq!(GOP_MODE_INFO_LEN, 40);
        assert_eq!(GOP_PIXEL_RGB, 0);
        assert_eq!(GOP_PIXEL_BGR, 1);
        assert_eq!(GOP_PIXEL_BITMASK, 2);
        assert_eq!(GOP_PIXEL_BLT_ONLY, 3);
    }

    #[test]
    fn banner_mode() {
        let m = UefiGopImpl::mode_1280x720();
        assert_eq!(m.horizontal, 1280);
        assert_eq!(m.vertical, 720);
    }

    #[test]
    fn roundtrip() {
        let m = UefiGopImpl::mode_1280x720();
        let mut b = [0u8; GOP_MODE_INFO_LEN];
        UefiGopImpl::encode(&m, &mut b).unwrap();
        assert_eq!(UefiGopImpl::decode(&b).unwrap(), m);
    }

    #[test]
    fn le_h() {
        let m = UefiGopImpl::mode_1280x720();
        let mut b = [0u8; 40];
        UefiGopImpl::encode(&m, &mut b).unwrap();
        assert_eq!(u32::from_le_bytes([b[4], b[5], b[6], b[7]]), 1280);
        assert_eq!(u32::from_le_bytes([b[8], b[9], b[10], b[11]]), 720);
    }

    #[test]
    fn truncated() {
        let m = UefiGopImpl::mode_1280x720();
        let mut s = [0u8; 10];
        assert_eq!(UefiGopImpl::encode(&m, &mut s), Err(GopError::Truncated));
        assert_eq!(UefiGopImpl::decode(&[0u8; 8]), Err(GopError::Truncated));
    }

    #[test]
    fn bad_geo_zero() {
        let mut m = UefiGopImpl::mode_1280x720();
        m.horizontal = 0;
        let mut b = [0u8; 40];
        assert_eq!(UefiGopImpl::encode(&m, &mut b), Err(GopError::BadGeometry));
    }

    #[test]
    fn bad_ppsl() {
        let mut m = UefiGopImpl::mode_1280x720();
        m.pixels_per_scan_line = 100;
        let mut b = [0u8; 40];
        assert_eq!(UefiGopImpl::encode(&m, &mut b), Err(GopError::BadGeometry));
    }

    #[test]
    fn free_match() {
        assert_eq!(mode_1280x720_impl(), UefiGopImpl::mode_1280x720());
    }

    #[test]
    fn bitmask_roundtrip() {
        let m = GopModeInfo {
            version: 0,
            horizontal: 640,
            vertical: 480,
            pixel_format: GOP_PIXEL_BITMASK,
            red_mask: 0xFF0000,
            green_mask: 0x00FF00,
            blue_mask: 0x0000FF,
            reserved_mask: 0xFF000000,
            pixels_per_scan_line: 640,
        };
        let mut b = [0u8; 40];
        UefiGopImpl::encode(&m, &mut b).unwrap();
        assert_eq!(UefiGopImpl::decode(&b).unwrap(), m);
    }

    #[test]
    fn det() {
        assert_eq!(
            UefiGopImpl::mode_1280x720(),
            UefiGopImpl::mode_1280x720()
        );
    }

    #[test]
    fn decode_bad_geo() {
        let mut b = [0u8; 40];
        // h=0 v=720
        b[8] = 0xD0;
        b[9] = 0x02;
        assert_eq!(UefiGopImpl::decode(&b), Err(GopError::BadGeometry));
    }

    #[test]
    fn banner_str() {
        // GOP mode OK 1280x720
        let m = UefiGopImpl::mode_1280x720();
        assert_eq!((m.horizontal, m.vertical), (1280, 720));
    }

    #[test]
    fn end_to_end() {
        let m = UefiGopImpl::mode_1280x720();
        let mut b = [0u8; 40];
        UefiGopImpl::encode(&m, &mut b).unwrap();
        let d = UefiGopImpl::decode(&b).unwrap();
        assert_eq!(d.horizontal, 1280);
        assert_eq!(d.vertical, 720);
    }

    #[test]
    fn format_bgr() {
        assert_eq!(UefiGopImpl::mode_1280x720().pixel_format, GOP_PIXEL_BGR);
    }

    #[test]
    fn wide_ppsl() {
        let mut m = UefiGopImpl::mode_1280x720();
        m.pixels_per_scan_line = 2048;
        let mut b = [0u8; 40];
        UefiGopImpl::encode(&m, &mut b).unwrap();
        assert_eq!(UefiGopImpl::decode(&b).unwrap().pixels_per_scan_line, 2048);
    }
}
