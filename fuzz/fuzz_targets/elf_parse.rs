#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 64 * 1024 {
        return;
    }
    let mut buf = data.to_vec();
    let _ = cuttle_binmorph::rewrite_elf_bytes(&mut buf, 0xCAFE_BABE_1234_5678);
});
