//! PS/2 keyboard set-1 scancode decoder — TASK-069.
//!
//! Wire codec only: feed scancode bytes, get [`KeyEvent`]s. No IRQ.

#![allow(missing_docs)]
#![allow(clippy::needless_range_loop)]

use proteus_contracts::{KeyCode, KeyEvent, Keyboard, KBD_PREFIX_E0, KBD_PREFIX_E1};
#[cfg(test)]
use proteus_contracts::{
    KBD_BREAK_A, KBD_BREAK_B, KBD_BREAK_LSHIFT, KBD_MAKE_A, KBD_MAKE_B, KBD_MAKE_BACKSPACE,
    KBD_MAKE_ENTER, KBD_MAKE_ESC, KBD_MAKE_LSHIFT,
};

/// Stateful set-1 decoder.
pub struct KeyboardImpl {
    extended: bool,
    e1_left: u8,
    shift: bool,
}

impl Default for KeyboardImpl {
    fn default() -> Self {
        Self::new()
    }
}

impl KeyboardImpl {
    pub const fn new() -> Self {
        Self {
            extended: false,
            e1_left: 0,
            shift: false,
        }
    }
}

impl Keyboard for KeyboardImpl {
    fn feed(&mut self, scancode: u8) -> Option<KeyEvent> {
        feed_impl(self, scancode)
    }
    fn reset(&mut self) {
        self.extended = false;
        self.e1_left = 0;
        self.shift = false;
    }
}

pub fn feed_impl(st: &mut KeyboardImpl, code: u8) -> Option<KeyEvent> {
    if st.e1_left > 0 {
        st.e1_left -= 1;
        return None;
    }
    if code == KBD_PREFIX_E0 {
        st.extended = true;
        return None;
    }
    if code == KBD_PREFIX_E1 {
        st.e1_left = 5; // Pause multi-byte swallow
        return None;
    }
    let ext = st.extended;
    st.extended = false;
    let pressed = code & 0x80 == 0;
    let make = code & 0x7F;

    if !ext {
        match make {
            0x2A | 0x36 => {
                // L/R shift
                st.shift = pressed;
                return Some(KeyEvent {
                    code: KeyCode::Shift,
                    pressed,
                    ascii: 0,
                });
            }
            0x1D => {
                return Some(KeyEvent {
                    code: KeyCode::Ctrl,
                    pressed,
                    ascii: 0,
                });
            }
            0x38 => {
                return Some(KeyEvent {
                    code: KeyCode::Alt,
                    pressed,
                    ascii: 0,
                });
            }
            _ => {}
        }
    }

    let (kc, ascii) = if ext {
        match make {
            0x48 => (KeyCode::ArrowUp, 0u8),
            0x50 => (KeyCode::ArrowDown, 0),
            0x4B => (KeyCode::ArrowLeft, 0),
            0x4D => (KeyCode::ArrowRight, 0),
            _ => (KeyCode::Other(make), 0),
        }
    } else {
        decode_make(make, st.shift)
    };

    Some(KeyEvent {
        code: kc,
        pressed,
        ascii: if pressed { ascii } else { 0 },
    })
}

fn decode_make(make: u8, shift: bool) -> (KeyCode, u8) {
    // Letters
    let letter = match make {
        0x1E => b'A',
        0x30 => b'B',
        0x2E => b'C',
        0x20 => b'D',
        0x12 => b'E',
        0x21 => b'F',
        0x22 => b'G',
        0x23 => b'H',
        0x17 => b'I',
        0x24 => b'J',
        0x25 => b'K',
        0x26 => b'L',
        0x32 => b'M',
        0x31 => b'N',
        0x18 => b'O',
        0x19 => b'P',
        0x10 => b'Q',
        0x13 => b'R',
        0x1F => b'S',
        0x14 => b'T',
        0x16 => b'U',
        0x2F => b'V',
        0x11 => b'W',
        0x2D => b'X',
        0x15 => b'Y',
        0x2C => b'Z',
        _ => 0,
    };
    if letter != 0 {
        let ascii = if shift { letter } else { letter + 32 }; // lower
        return (KeyCode::Letter(letter), ascii);
    }
    match make {
        0x02 => (KeyCode::Digit(b'1'), if shift { b'!' } else { b'1' }),
        0x03 => (KeyCode::Digit(b'2'), if shift { b'@' } else { b'2' }),
        0x0B => (KeyCode::Digit(b'0'), if shift { b')' } else { b'0' }),
        0x1C => (KeyCode::Enter, b'\n'),
        0x01 => (KeyCode::Escape, 0x1B),
        0x0E => (KeyCode::Backspace, 0x08),
        0x39 => (KeyCode::Space, b' '),
        _ => (KeyCode::Other(make), 0),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proteus_contracts::Keyboard;

    #[test]
    fn constants() {
        assert_eq!(KBD_MAKE_A, 0x1E);
        assert_eq!(KBD_BREAK_A, 0x9E);
        assert_eq!(KBD_MAKE_B, 0x30);
        assert_eq!(KBD_BREAK_B, 0xB0);
    }

    #[test]
    fn banner_stream_a_then_b() {
        let mut k = KeyboardImpl::new();
        let e1 = k.feed(KBD_MAKE_A).unwrap();
        assert!(e1.pressed);
        assert_eq!(e1.code, KeyCode::Letter(b'A'));
        assert_eq!(e1.ascii, b'a');
        assert!(k.feed(KBD_BREAK_A).unwrap().pressed == false);
        let e3 = k.feed(KBD_MAKE_B).unwrap();
        assert_eq!(e3.code, KeyCode::Letter(b'B'));
        assert_eq!(e3.ascii, b'b');
        let e4 = k.feed(KBD_BREAK_B).unwrap();
        assert!(!e4.pressed);
        assert_eq!(e4.ascii, 0);
    }

    #[test]
    fn shift_uppercase() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_MAKE_LSHIFT);
        let e = k.feed(KBD_MAKE_A).unwrap();
        assert_eq!(e.ascii, b'A');
        k.feed(KBD_BREAK_LSHIFT);
        let e2 = k.feed(KBD_MAKE_A).unwrap();
        assert_eq!(e2.ascii, b'a');
    }

    #[test]
    fn enter_escape_backspace_space() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(KBD_MAKE_ENTER).unwrap().code, KeyCode::Enter);
        assert_eq!(k.feed(KBD_MAKE_ESC).unwrap().code, KeyCode::Escape);
        assert_eq!(
            k.feed(KBD_MAKE_BACKSPACE).unwrap().code,
            KeyCode::Backspace
        );
        assert_eq!(k.feed(0x39).unwrap().ascii, b' ');
    }

    #[test]
    fn e0_prefix_arrows() {
        let mut k = KeyboardImpl::new();
        assert!(k.feed(KBD_PREFIX_E0).is_none());
        assert_eq!(k.feed(0x48).unwrap().code, KeyCode::ArrowUp);
        k.feed(KBD_PREFIX_E0);
        assert_eq!(k.feed(0x50).unwrap().code, KeyCode::ArrowDown);
        k.feed(KBD_PREFIX_E0);
        assert_eq!(k.feed(0x4B).unwrap().code, KeyCode::ArrowLeft);
        k.feed(KBD_PREFIX_E0);
        assert_eq!(k.feed(0x4D).unwrap().code, KeyCode::ArrowRight);
    }

    #[test]
    fn e1_swallows() {
        let mut k = KeyboardImpl::new();
        assert!(k.feed(KBD_PREFIX_E1).is_none());
        for _ in 0..5 {
            assert!(k.feed(0x1D).is_none());
        }
        // next real event
        assert!(k.feed(KBD_MAKE_A).is_some());
    }

    #[test]
    fn reset_clears_shift() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_MAKE_LSHIFT);
        k.reset();
        assert_eq!(k.feed(KBD_MAKE_A).unwrap().ascii, b'a');
    }

    #[test]
    fn break_ascii_zero() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_MAKE_A);
        assert_eq!(k.feed(KBD_BREAK_A).unwrap().ascii, 0);
    }

    #[test]
    fn digit_one() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(0x02).unwrap().ascii, b'1');
    }

    #[test]
    fn ctrl_alt() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(0x1D).unwrap().code, KeyCode::Ctrl);
        assert_eq!(k.feed(0x38).unwrap().code, KeyCode::Alt);
    }

    #[test]
    fn other_unknown() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(0x7F).unwrap().code, KeyCode::Other(0x7F));
    }

    #[test]
    fn count_banner_events() {
        let mut k = KeyboardImpl::new();
        let stream = [KBD_MAKE_A, KBD_BREAK_A, KBD_MAKE_B, KBD_BREAK_B];
        let mut n = 0usize;
        let mut last = KeyCode::Other(0);
        for &b in &stream {
            if let Some(e) = k.feed(b) {
                n += 1;
                last = e.code;
            }
        }
        assert_eq!(n, 4);
        assert_eq!(last, KeyCode::Letter(b'B'));
    }

    #[test]
    fn pressed_keys_only_count_makes_for_banner() {
        // Banner wants keys=2 last=b meaning two printable makes
        let mut k = KeyboardImpl::new();
        let mut makes = 0usize;
        let mut last_ascii = 0u8;
        for &b in &[KBD_MAKE_A, KBD_BREAK_A, KBD_MAKE_B, KBD_BREAK_B] {
            if let Some(e) = k.feed(b) {
                if e.pressed && e.ascii != 0 {
                    makes += 1;
                    last_ascii = e.ascii;
                }
            }
        }
        assert_eq!(makes, 2);
        assert_eq!(last_ascii, b'b');
    }

    #[test]
    fn letter_c() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(0x2E).unwrap().ascii, b'c');
    }

    #[test]
    fn rshift() {
        let mut k = KeyboardImpl::new();
        let e = k.feed(0x36).unwrap();
        assert_eq!(e.code, KeyCode::Shift);
        assert!(e.pressed);
    }

    #[test]
    fn default_new() {
        let k = KeyboardImpl::default();
        assert!(!k.shift);
    }

    #[test]
    fn extended_cleared_after_event() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_PREFIX_E0);
        k.feed(0x48);
        // next without E0 is normal
        assert_eq!(k.feed(KBD_MAKE_A).unwrap().code, KeyCode::Letter(b'A'));
    }

    #[test]
    fn space_break() {
        let mut k = KeyboardImpl::new();
        k.feed(0x39);
        let e = k.feed(0xB9).unwrap();
        assert!(!e.pressed);
        assert_eq!(e.code, KeyCode::Space);
    }

    #[test]
    fn many_letters() {
        let mut k = KeyboardImpl::new();
        // Q W E
        assert_eq!(k.feed(0x10).unwrap().ascii, b'q');
        assert_eq!(k.feed(0x11).unwrap().ascii, b'w');
        assert_eq!(k.feed(0x12).unwrap().ascii, b'e');
    }

    #[test]
    fn enter_ascii_newline() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(KBD_MAKE_ENTER).unwrap().ascii, b'\n');
    }

    #[test]
    fn escape_ascii() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(KBD_MAKE_ESC).unwrap().ascii, 0x1B);
    }

    #[test]
    fn zero_digit() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(0x0B).unwrap().ascii, b'0');
    }

    #[test]
    fn shift_digit_bang() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_MAKE_LSHIFT);
        assert_eq!(k.feed(0x02).unwrap().ascii, b'!');
    }

    #[test]
    fn break_shift() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_MAKE_LSHIFT);
        let e = k.feed(KBD_BREAK_LSHIFT).unwrap();
        assert!(!e.pressed);
        assert_eq!(e.code, KeyCode::Shift);
    }

    #[test]
    fn stream_interleaved() {
        let mut k = KeyboardImpl::new();
        assert!(k.feed(KBD_MAKE_A).unwrap().pressed);
        assert!(!k.feed(KBD_BREAK_A).unwrap().pressed);
        assert!(k.feed(KBD_MAKE_B).unwrap().pressed);
    }

    #[test]
    fn other_extended() {
        let mut k = KeyboardImpl::new();
        k.feed(KBD_PREFIX_E0);
        assert_eq!(k.feed(0x5B).unwrap().code, KeyCode::Other(0x5B));
    }

    #[test]
    fn backspace_ascii() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(KBD_MAKE_BACKSPACE).unwrap().ascii, 0x08);
    }

    #[test]
    fn z_letter() {
        let mut k = KeyboardImpl::new();
        assert_eq!(k.feed(0x2C).unwrap().ascii, b'z');
    }

    #[test]
    fn feed_returns_option() {
        let mut k = KeyboardImpl::new();
        assert!(k.feed(KBD_PREFIX_E0).is_none());
        assert!(k.feed(0x48).is_some());
    }

    #[test]
    fn two_keys_last_b_banner_contract() {
        let mut k = KeyboardImpl::new();
        let mut last = b'\0';
        let mut keys = 0u32;
        for &sc in &[0x1Eu8, 0x9E, 0x30, 0xB0] {
            if let Some(ev) = k.feed(sc) {
                if ev.pressed && ev.ascii != 0 {
                    keys += 1;
                    last = ev.ascii;
                }
            }
        }
        assert_eq!(keys, 2);
        assert_eq!(last, b'b');
    }
}
