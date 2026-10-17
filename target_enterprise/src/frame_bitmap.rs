//! Fixed bitmap frame allocator codec — TASK-082.

#![allow(missing_docs)]

use proteus_contracts::{FrameBitmap, FrameBitmapError, FRAME_BITMAP_BITS};

/// Bitmap: bit=1 means free, bit=0 means used (or invert — we use 1=free).
pub struct FrameBitmapImpl {
    /// 4096 bits = 512 bytes
    bits: [u8; FRAME_BITMAP_BITS / 8],
    free: usize,
}

impl Default for FrameBitmapImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl FrameBitmapImpl {
    pub const fn new() -> Self {
        Self {
            bits: [0xFF; FRAME_BITMAP_BITS / 8], // all free
            free: FRAME_BITMAP_BITS,
        }
    }
}

impl FrameBitmap for FrameBitmapImpl {
    fn clear_all(&mut self) {
        self.bits = [0xFF; FRAME_BITMAP_BITS / 8];
        self.free = FRAME_BITMAP_BITS;
    }
    fn alloc_at(&mut self, idx: usize) -> Result<(), FrameBitmapError> {
        if idx >= FRAME_BITMAP_BITS {
            return Err(FrameBitmapError::Oob);
        }
        if !bit_is_free(&self.bits, idx) {
            return Err(FrameBitmapError::Exhausted); // already used
        }
        clear_bit(&mut self.bits, idx);
        self.free -= 1;
        Ok(())
    }
    fn alloc(&mut self) -> Result<usize, FrameBitmapError> {
        let mut i = 0usize;
        while i < FRAME_BITMAP_BITS {
            if bit_is_free(&self.bits, i) {
                clear_bit(&mut self.bits, i);
                self.free -= 1;
                return Ok(i);
            }
            i += 1;
        }
        Err(FrameBitmapError::Exhausted)
    }
    fn free(&mut self, idx: usize) -> Result<(), FrameBitmapError> {
        if idx >= FRAME_BITMAP_BITS {
            return Err(FrameBitmapError::Oob);
        }
        if bit_is_free(&self.bits, idx) {
            return Err(FrameBitmapError::AlreadyFree);
        }
        set_bit(&mut self.bits, idx);
        self.free += 1;
        Ok(())
    }
    fn is_free(&self, idx: usize) -> Result<bool, FrameBitmapError> {
        if idx >= FRAME_BITMAP_BITS {
            return Err(FrameBitmapError::Oob);
        }
        Ok(bit_is_free(&self.bits, idx))
    }
    fn free_count(&self) -> usize {
        self.free
    }
}

fn bit_is_free(bits: &[u8], idx: usize) -> bool {
    let byte = bits[idx / 8];
    let mask = 1u8 << (idx % 8);
    byte & mask != 0
}
fn clear_bit(bits: &mut [u8], idx: usize) {
    bits[idx / 8] &= !(1u8 << (idx % 8));
}
fn set_bit(bits: &mut [u8], idx: usize) {
    bits[idx / 8] |= 1u8 << (idx % 8);
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::FrameBitmap;

    #[test]
    fn bits_const() {
        assert_eq!(FRAME_BITMAP_BITS, 4096);
    }

    #[test]
    fn new_all_free() {
        let b = FrameBitmapImpl::new();
        assert_eq!(b.free_count(), 4096);
        assert!(b.is_free(0).unwrap());
    }

    #[test]
    fn alloc_lowest() {
        let mut b = FrameBitmapImpl::new();
        assert_eq!(b.alloc().unwrap(), 0);
        assert_eq!(b.alloc().unwrap(), 1);
        assert_eq!(b.free_count(), 4094);
    }

    #[test]
    fn alloc_at() {
        let mut b = FrameBitmapImpl::new();
        b.alloc_at(10).unwrap();
        assert!(!b.is_free(10).unwrap());
        assert_eq!(b.alloc().unwrap(), 0);
    }

    #[test]
    fn free_roundtrip() {
        let mut b = FrameBitmapImpl::new();
        let i = b.alloc().unwrap();
        b.free(i).unwrap();
        assert!(b.is_free(i).unwrap());
        assert_eq!(b.free_count(), 4096);
    }

    #[test]
    fn double_free() {
        let mut b = FrameBitmapImpl::new();
        assert_eq!(b.free(0), Err(FrameBitmapError::AlreadyFree));
    }

    #[test]
    fn oob() {
        let mut b = FrameBitmapImpl::new();
        assert_eq!(b.alloc_at(99999), Err(FrameBitmapError::Oob));
        assert_eq!(b.is_free(99999), Err(FrameBitmapError::Oob));
    }

    #[test]
    fn clear_all() {
        let mut b = FrameBitmapImpl::new();
        b.alloc().unwrap();
        b.clear_all();
        assert_eq!(b.free_count(), 4096);
    }

    #[test]
    fn banner() {
        let mut b = FrameBitmapImpl::new();
        let a = b.alloc().unwrap();
        let c = b.alloc().unwrap();
        assert_eq!(a, 0);
        assert_eq!(c, 1);
        assert_eq!(b.free_count(), 4094);
    }

    #[test]
    fn alloc_at_used() {
        let mut b = FrameBitmapImpl::new();
        b.alloc_at(5).unwrap();
        assert!(b.alloc_at(5).is_err());
    }

    #[test]
    fn exhaust_small() {
        // just check alloc reduces
        let mut b = FrameBitmapImpl::new();
        for _ in 0..100 {
            b.alloc().unwrap();
        }
        assert_eq!(b.free_count(), 3996);
    }

    #[test]
    fn free_oob() {
        let mut b = FrameBitmapImpl::new();
        assert_eq!(b.free(5000), Err(FrameBitmapError::Oob));
    }

    #[test]
    fn default() {
        assert_eq!(FrameBitmapImpl::default().free_count(), 4096);
    }

    #[test]
    fn bit63() {
        let mut b = FrameBitmapImpl::new();
        b.alloc_at(63).unwrap();
        assert!(!b.is_free(63).unwrap());
        b.free(63).unwrap();
    }

    #[test]
    fn bit64() {
        let mut b = FrameBitmapImpl::new();
        b.alloc_at(64).unwrap();
        assert!(!b.is_free(64).unwrap());
    }

    #[test]
    fn alloc_skips_used() {
        let mut b = FrameBitmapImpl::new();
        b.alloc_at(0).unwrap();
        assert_eq!(b.alloc().unwrap(), 1);
    }

    #[test]
    fn free_count_tracks() {
        let mut b = FrameBitmapImpl::new();
        b.alloc().unwrap();
        b.alloc().unwrap();
        b.free(0).unwrap();
        assert_eq!(b.free_count(), 4095);
    }

    #[test]
    fn errors_distinct() {
        assert_ne!(FrameBitmapError::Oob, FrameBitmapError::Exhausted);
    }

    #[test]
    fn end_to_end() {
        let mut b = FrameBitmapImpl::new();
        let i = b.alloc().unwrap();
        assert!(!b.is_free(i).unwrap());
    }

    #[test]
    fn last_frame() {
        let mut b = FrameBitmapImpl::new();
        b.alloc_at(FRAME_BITMAP_BITS - 1).unwrap();
        assert!(!b.is_free(FRAME_BITMAP_BITS - 1).unwrap());
    }

    #[test]
    fn banner_str() {
        // FRAME alloc OK free=4094
        let mut b = FrameBitmapImpl::new();
        b.alloc().unwrap();
        b.alloc().unwrap();
        assert_eq!(b.free_count(), 4094);
    }

    #[test]
    fn already_free_variant() {
        let _ = FrameBitmapError::AlreadyFree;
    }

    #[test]
    fn re_alloc_after_free() {
        let mut b = FrameBitmapImpl::new();
        let i = b.alloc().unwrap();
        b.free(i).unwrap();
        assert_eq!(b.alloc().unwrap(), 0);
    }

    #[test]
    fn many_free() {
        let mut b = FrameBitmapImpl::new();
        for i in 0..50 {
            b.alloc_at(i).unwrap();
        }
        for i in 0..50 {
            b.free(i).unwrap();
        }
        assert_eq!(b.free_count(), 4096);
    }

    #[test]
    fn is_free_true() {
        let b = FrameBitmapImpl::new();
        assert_eq!(b.is_free(100).unwrap(), true);
    }
}
