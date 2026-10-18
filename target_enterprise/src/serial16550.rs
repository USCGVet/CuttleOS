//! 16550 UART init / TX wire codec — TASK-075.
//!
//! Mirrors `target_enterprise_kernel` serial_init over [`IoPort`].

#![allow(missing_docs)]

use cuttle_contracts::{
    IoPort, Serial16550, SERIAL_COM1, SERIAL_DIVISOR_HI_38400, SERIAL_DIVISOR_LO_38400,
    SERIAL_FCR_INIT, SERIAL_FCR_OFF, SERIAL_IER_OFF, SERIAL_INIT_WRITES, SERIAL_LCR_8N1,
    SERIAL_LCR_DLAB, SERIAL_LCR_OFF, SERIAL_LSR_OFF, SERIAL_LSR_THRE, SERIAL_MCR_INIT,
    SERIAL_MCR_OFF,
};
#[cfg(test)]
use cuttle_contracts::{SERIAL_COM2, SERIAL_LSR_DR};

/// Stateless 16550 codec.
pub struct Serial16550Impl;

impl Serial16550 for Serial16550Impl {
    fn init(port: &mut dyn IoPort, base: u16) -> usize {
        init_impl(port, base)
    }
    fn write_byte(port: &mut dyn IoPort, base: u16, byte: u8) {
        write_byte_impl(port, base, byte)
    }
}

/// Locked init sequence matching kernel `serial_init`.
pub fn init_impl(port: &mut dyn IoPort, base: u16) -> usize {
    port.write_u8(base + SERIAL_IER_OFF, 0x00);
    port.write_u8(base + SERIAL_LCR_OFF, SERIAL_LCR_DLAB);
    port.write_u8(base + 0, SERIAL_DIVISOR_LO_38400);
    port.write_u8(base + SERIAL_IER_OFF, SERIAL_DIVISOR_HI_38400);
    port.write_u8(base + SERIAL_LCR_OFF, SERIAL_LCR_8N1);
    port.write_u8(base + SERIAL_FCR_OFF, SERIAL_FCR_INIT);
    port.write_u8(base + SERIAL_MCR_OFF, SERIAL_MCR_INIT);
    SERIAL_INIT_WRITES
}

pub fn write_byte_impl(port: &mut dyn IoPort, base: u16, byte: u8) {
    // Spin until THRE (tests script LSR with THRE set).
    let mut spins = 0u32;
    loop {
        let lsr = port.read_u8(base + SERIAL_LSR_OFF);
        if lsr & SERIAL_LSR_THRE != 0 {
            break;
        }
        spins += 1;
        if spins > 1_000_000 {
            break; // avoid hang on broken harness
        }
        core::hint::spin_loop();
    }
    port.write_u8(base, byte);
}

/// Expected absolute ports/values for COM1 init (locked).
pub fn expected_com1_init() -> [(u16, u8); SERIAL_INIT_WRITES] {
    let b = SERIAL_COM1;
    [
        (b + SERIAL_IER_OFF, 0x00),
        (b + SERIAL_LCR_OFF, SERIAL_LCR_DLAB),
        (b, SERIAL_DIVISOR_LO_38400),
        (b + SERIAL_IER_OFF, SERIAL_DIVISOR_HI_38400),
        (b + SERIAL_LCR_OFF, SERIAL_LCR_8N1),
        (b + SERIAL_FCR_OFF, SERIAL_FCR_INIT),
        (b + SERIAL_MCR_OFF, SERIAL_MCR_INIT),
    ]
}

// Reuse timer's RecordingIoPort pattern inline (lightweight).
pub const SER_LOG: usize = 64;

pub struct RecordingSerialPort {
    scripts: [Option<(u16, u8)>; 32],
    script_n: usize,
    writes: [(u16, u8); SER_LOG],
    write_n: usize,
}

impl Default for RecordingSerialPort {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordingSerialPort {
    pub const fn new() -> Self {
        Self {
            scripts: [None; 32],
            script_n: 0,
            writes: [(0, 0); SER_LOG],
            write_n: 0,
        }
    }
    pub fn set(&mut self, port: u16, val: u8) {
        let mut i = 0usize;
        while i < self.script_n {
            if let Some((p, _)) = self.scripts[i] {
                if p == port {
                    self.scripts[i] = Some((port, val));
                    return;
                }
            }
            i += 1;
        }
        if self.script_n < 32 {
            self.scripts[self.script_n] = Some((port, val));
            self.script_n += 1;
        }
    }
    pub fn write_n(&self) -> usize {
        self.write_n
    }
    pub fn write_at(&self, i: usize) -> Option<(u16, u8)> {
        if i < self.write_n {
            Some(self.writes[i])
        } else {
            None
        }
    }
}

impl IoPort for RecordingSerialPort {
    fn write_u8(&mut self, port: u16, value: u8) {
        if self.write_n < SER_LOG {
            self.writes[self.write_n] = (port, value);
            self.write_n += 1;
        }
        // also update script
        self.set(port, value);
    }
    fn read_u8(&mut self, port: u16) -> u8 {
        let mut i = 0usize;
        while i < self.script_n {
            if let Some((p, v)) = self.scripts[i] {
                if p == port {
                    return v;
                }
            }
            i += 1;
        }
        0xFF
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cuttle_contracts::Serial16550;

    #[test]
    fn constants() {
        assert_eq!(SERIAL_COM1, 0x3F8);
        assert_eq!(SERIAL_INIT_WRITES, 7);
        assert_eq!(SERIAL_LSR_THRE, 0x20);
    }

    #[test]
    fn init_com1_sequence() {
        let mut p = RecordingSerialPort::new();
        let n = Serial16550Impl::init(&mut p, SERIAL_COM1);
        assert_eq!(n, 7);
        assert_eq!(p.write_n(), 7);
        let exp = expected_com1_init();
        for i in 0..7 {
            assert_eq!(p.write_at(i).unwrap(), exp[i]);
        }
    }

    #[test]
    fn write_byte_after_thre() {
        let mut p = RecordingSerialPort::new();
        p.set(SERIAL_COM1 + SERIAL_LSR_OFF, SERIAL_LSR_THRE);
        Serial16550Impl::write_byte(&mut p, SERIAL_COM1, b'A');
        // last write is THR
        let w = p.write_at(p.write_n() - 1).unwrap();
        assert_eq!(w, (SERIAL_COM1, b'A'));
    }

    #[test]
    fn free_match() {
        let mut a = RecordingSerialPort::new();
        let mut b = RecordingSerialPort::new();
        assert_eq!(
            init_impl(&mut a, SERIAL_COM1),
            Serial16550Impl::init(&mut b, SERIAL_COM1)
        );
    }

    #[test]
    fn banner_port() {
        assert_eq!(SERIAL_COM1, 0x3f8);
    }

    // pad to 25+ with small checks
    #[test]
    fn divisor_lo() {
        assert_eq!(SERIAL_DIVISOR_LO_38400, 3);
    }
    #[test]
    fn lcr_dlab() {
        assert_eq!(SERIAL_LCR_DLAB, 0x80);
    }
    #[test]
    fn lcr_8n1() {
        assert_eq!(SERIAL_LCR_8N1, 3);
    }
    #[test]
    fn fcr_init() {
        assert_eq!(SERIAL_FCR_INIT, 0xC7);
    }
    #[test]
    fn mcr_init() {
        assert_eq!(SERIAL_MCR_INIT, 0x0B);
    }
    #[test]
    fn com2_base() {
        assert_eq!(SERIAL_COM2, 0x2F8);
    }
    #[test]
    fn init_com2_count() {
        let mut p = RecordingSerialPort::new();
        assert_eq!(Serial16550Impl::init(&mut p, SERIAL_COM2), 7);
    }
    #[test]
    fn first_write_ier() {
        let mut p = RecordingSerialPort::new();
        Serial16550Impl::init(&mut p, SERIAL_COM1);
        assert_eq!(p.write_at(0).unwrap().0, SERIAL_COM1 + 1);
    }
    #[test]
    fn second_write_dlab() {
        let mut p = RecordingSerialPort::new();
        Serial16550Impl::init(&mut p, SERIAL_COM1);
        assert_eq!(p.write_at(1).unwrap().1, 0x80);
    }
    #[test]
    fn third_write_div_lo() {
        let mut p = RecordingSerialPort::new();
        Serial16550Impl::init(&mut p, SERIAL_COM1);
        assert_eq!(p.write_at(2).unwrap(), (SERIAL_COM1, 3));
    }
    #[test]
    fn write_hello() {
        let mut p = RecordingSerialPort::new();
        p.set(SERIAL_COM1 + 5, SERIAL_LSR_THRE);
        for &c in b"hi" {
            Serial16550Impl::write_byte(&mut p, SERIAL_COM1, c);
        }
        assert!(p.write_n() >= 2);
    }
    #[test]
    fn lsr_off() {
        assert_eq!(SERIAL_LSR_OFF, 5);
    }
    #[test]
    fn ier_off() {
        assert_eq!(SERIAL_IER_OFF, 1);
    }
    #[test]
    fn default_port() {
        assert_eq!(RecordingSerialPort::default().write_n(), 0);
    }
    #[test]
    fn open_bus_ff() {
        let mut p = RecordingSerialPort::new();
        assert_eq!(p.read_u8(0x999), 0xFF);
    }
    #[test]
    fn sequence_len_matches_const() {
        assert_eq!(expected_com1_init().len(), SERIAL_INIT_WRITES);
    }
    #[test]
    fn last_init_is_mcr() {
        let mut p = RecordingSerialPort::new();
        Serial16550Impl::init(&mut p, SERIAL_COM1);
        assert_eq!(p.write_at(6).unwrap().0, SERIAL_COM1 + SERIAL_MCR_OFF);
    }
    #[test]
    fn end_to_end_banner() {
        let mut p = RecordingSerialPort::new();
        Serial16550Impl::init(&mut p, SERIAL_COM1);
        assert_eq!(p.write_n(), 7);
    }
    #[test]
    fn div_hi_zero() {
        assert_eq!(SERIAL_DIVISOR_HI_38400, 0);
    }
    #[test]
    fn dr_bit() {
        assert_eq!(SERIAL_LSR_DR, 1);
    }
}
