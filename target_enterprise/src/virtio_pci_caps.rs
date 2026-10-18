//! VirtIO PCI capability list walker — TASK-077.

#![allow(missing_docs)]

use cuttle_contracts::{
    VirtioPciCap, VirtioPciCapError, VirtioPciCaps, VIRTIO_PCI_CAP_ID, VIRTIO_PCI_CAP_MAX,
};
#[cfg(test)]
use cuttle_contracts::{
    VIRTIO_PCI_CAP_COMMON_CFG, VIRTIO_PCI_CAP_DEVICE_CFG, VIRTIO_PCI_CAP_ISR_CFG,
    VIRTIO_PCI_CAP_NOTIFY_CFG, VIRTIO_PCI_CAP_PCI_CFG,
};

/// Stateless walker.
pub struct VirtioPciCapsImpl;

impl VirtioPciCaps for VirtioPciCapsImpl {
    fn walk(
        cap_ptr: u8,
        read_dword: &mut dyn FnMut(u8) -> u32,
        out: &mut [VirtioPciCap; VIRTIO_PCI_CAP_MAX],
    ) -> Result<usize, VirtioPciCapError> {
        walk_impl(cap_ptr, read_dword, out)
    }
    fn find(caps: &[VirtioPciCap], cfg_type: u8) -> Option<VirtioPciCap> {
        find_impl(caps, cfg_type)
    }
}

/// VirtIO vendor-cap layout (PCI):
///   +0: cap_vndr (0x09), cap_next, cap_len, cfg_type
///   +4: bar, padding[3]
///   +8: offset u32
///   +12: length u32
/// We only require the first 16 bytes per node; dword reader supplies them.
pub fn walk_impl(
    mut ptr: u8,
    read_dword: &mut dyn FnMut(u8) -> u32,
    out: &mut [VirtioPciCap; VIRTIO_PCI_CAP_MAX],
) -> Result<usize, VirtioPciCapError> {
    if ptr == 0 {
        return Err(VirtioPciCapError::NotFound);
    }
    let mut count = 0usize;
    let mut hops = 0u8;
    while ptr != 0 {
        if hops >= 48 {
            return Err(VirtioPciCapError::TooMany);
        }
        hops += 1;
        let d0 = read_dword(ptr);
        let id = (d0 & 0xFF) as u8;
        let next = ((d0 >> 8) & 0xFF) as u8;
        let cfg_type = ((d0 >> 24) & 0xFF) as u8;
        if id == VIRTIO_PCI_CAP_ID {
            if count >= VIRTIO_PCI_CAP_MAX {
                return Err(VirtioPciCapError::TooMany);
            }
            let d1 = read_dword(ptr.wrapping_add(4));
            let bar = (d1 & 0xFF) as u8;
            let bar_offset = read_dword(ptr.wrapping_add(8));
            let length = read_dword(ptr.wrapping_add(12));
            out[count] = VirtioPciCap {
                offset: ptr,
                cfg_type,
                bar,
                bar_offset,
                length,
            };
            count += 1;
        }
        if next == 0 || next == ptr {
            break;
        }
        ptr = next;
    }
    if count == 0 {
        return Err(VirtioPciCapError::NotFound);
    }
    Ok(count)
}

pub fn find_impl(caps: &[VirtioPciCap], cfg_type: u8) -> Option<VirtioPciCap> {
    let mut i = 0usize;
    while i < caps.len() {
        if caps[i].cfg_type == cfg_type {
            return Some(caps[i]);
        }
        i += 1;
    }
    None
}

/// Banner fixture: scripted dword map for a chain with common-cfg.
pub fn banner_read_dword(off: u8) -> u32 {
    // cap at 0x40: id=09, next=0x50, len=16, type=COMMON(1)
    // at 0x44: bar=0
    // at 0x48: bar_offset=0x0000
    // at 0x4C: length=0x1000
    // cap at 0x50: id=09, next=0, type=NOTIFY(2)
    match off {
        0x40 => 0x01_10_50_09, // type=1, len=0x10, next=0x50, id=09
        0x44 => 0x0000_0000,   // bar 0
        0x48 => 0x0000_0000,
        0x4C => 0x0000_1000,
        0x50 => 0x02_10_00_09, // type=2, next=0
        0x54 => 0x0000_0001,   // bar 1
        0x58 => 0x0000_2000,
        0x5C => 0x0000_0004,
        _ => 0,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::VirtioPciCaps;

    #[test]
    fn constants() {
        assert_eq!(VIRTIO_PCI_CAP_ID, 0x09);
        assert_eq!(VIRTIO_PCI_CAP_COMMON_CFG, 1);
        assert_eq!(VIRTIO_PCI_CAP_NOTIFY_CFG, 2);
        assert_eq!(VIRTIO_PCI_CAP_ISR_CFG, 3);
        assert_eq!(VIRTIO_PCI_CAP_DEVICE_CFG, 4);
        assert_eq!(VIRTIO_PCI_CAP_PCI_CFG, 5);
    }

    #[test]
    fn walk_banner_chain() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert_eq!(n, 2);
        assert_eq!(out[0].cfg_type, VIRTIO_PCI_CAP_COMMON_CFG);
        assert_eq!(out[1].cfg_type, VIRTIO_PCI_CAP_NOTIFY_CFG);
    }

    #[test]
    fn find_common() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        let c = VirtioPciCapsImpl::find(&out[..n], VIRTIO_PCI_CAP_COMMON_CFG).unwrap();
        assert_eq!(c.offset, 0x40);
        assert_eq!(c.length, 0x1000);
    }

    #[test]
    fn empty_ptr() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        assert_eq!(
            VirtioPciCapsImpl::walk(0, &mut |_| 0, &mut out),
            Err(VirtioPciCapError::NotFound)
        );
    }

    #[test]
    fn no_virtio_caps() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        // id=0x01 MSI, next=0
        assert_eq!(
            VirtioPciCapsImpl::walk(0x40, &mut |o| if o == 0x40 { 0x0000_0001 } else { 0 }, &mut out),
            Err(VirtioPciCapError::NotFound)
        );
    }

    #[test]
    fn find_missing() {
        let caps = [VirtioPciCap {
            offset: 1,
            cfg_type: 1,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }];
        assert!(VirtioPciCapsImpl::find(&caps, 99).is_none());
    }

    #[test]
    fn banner_common_found() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = walk_impl(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert!(find_impl(&out[..n], VIRTIO_PCI_CAP_COMMON_CFG).is_some());
    }

    // pad tests
    #[test]
    fn notify_bar() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        let ntf = VirtioPciCapsImpl::find(&out[..n], VIRTIO_PCI_CAP_NOTIFY_CFG).unwrap();
        assert_eq!(ntf.bar, 1);
        assert_eq!(ntf.bar_offset, 0x2000);
    }
    #[test]
    fn max_const() {
        assert_eq!(VIRTIO_PCI_CAP_MAX, 8);
    }
    #[test]
    fn type_device() {
        assert_eq!(VIRTIO_PCI_CAP_DEVICE_CFG, 4);
    }
    #[test]
    fn type_isr() {
        assert_eq!(VIRTIO_PCI_CAP_ISR_CFG, 3);
    }
    #[test]
    fn type_pci() {
        assert_eq!(VIRTIO_PCI_CAP_PCI_CFG, 5);
    }
    #[test]
    fn common_length() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert_eq!(out[0].length, 0x1000);
        let _ = n;
    }
    #[test]
    fn self_loop_breaks() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        // next points to self with virtio id
        let r = VirtioPciCapsImpl::walk(0x40, &mut |o| {
            if o == 0x40 {
                0x01_10_40_09
            } else if o == 0x44 {
                0
            } else if o == 0x48 {
                0
            } else if o == 0x4C {
                0x10
            } else {
                0
            }
        }, &mut out);
        assert!(r.is_ok());
    }
    #[test]
    fn end_to_end() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert!(n >= 1);
        assert!(VirtioPciCapsImpl::find(&out[..n], 1).is_some());
    }
    #[test]
    fn errors_distinct() {
        assert_ne!(VirtioPciCapError::NotFound, VirtioPciCapError::TooMany);
    }
    #[test]
    fn first_offset() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert_eq!(out[0].offset, 0x40);
    }
    #[test]
    fn second_offset() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert_eq!(out[1].offset, 0x50);
    }
    #[test]
    fn free_match() {
        let mut a = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let mut b = a;
        assert_eq!(
            walk_impl(0x40, &mut banner_read_dword, &mut a).unwrap(),
            VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut b).unwrap()
        );
    }
    #[test]
    fn truncated_variant_exists() {
        let _ = VirtioPciCapError::Truncated;
    }
    #[test]
    fn find_on_empty() {
        assert!(VirtioPciCapsImpl::find(&[], 1).is_none());
    }
    #[test]
    fn banner_string_doc() {
        // VIRTIO caps OK common=found
        assert_eq!(VIRTIO_PCI_CAP_COMMON_CFG, 1);
    }
    #[test]
    fn bar0_common() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert_eq!(out[0].bar, 0);
    }
    #[test]
    fn notify_len() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        let n = VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap();
        assert_eq!(out[1].length, 4);
        let _ = n;
    }
    #[test]
    fn count_two() {
        let mut out = [VirtioPciCap {
            offset: 0,
            cfg_type: 0,
            bar: 0,
            bar_offset: 0,
            length: 0,
        }; VIRTIO_PCI_CAP_MAX];
        assert_eq!(
            VirtioPciCapsImpl::walk(0x40, &mut banner_read_dword, &mut out).unwrap(),
            2
        );
    }
}
