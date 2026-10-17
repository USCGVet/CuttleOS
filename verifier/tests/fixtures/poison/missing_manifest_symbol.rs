//! Poison: parses and looks like a morph, but drops a locked public
//! symbol (`fletcher32`). Manifest stage must reject before cargo runs.

#![no_std]

pub fn feistel_mix(state: u64) -> u64 {
    state
}

pub fn derive_byte(seed: u8, _rounds: u32) -> u8 {
    seed
}

pub struct DemoHash;
pub struct DemoAead;
pub struct DemoSignatureVerify;
pub struct DemoSyscallDispatch;
pub enum DemoErrno {
    ENOSYS,
}
