#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 9 || data.len() > 256 {
        return;
    }
    let seed = u64::from_le_bytes(data[..8].try_into().unwrap());
    let mut code = data[8..].to_vec();
    if code.last() != Some(&0xC3) {
        code.push(0xC3);
    }
    let base_ip = 0x1000u64;
    let orig_len = code.len();
    let mut prng = cuttle_binmorph::Prng::new(seed);
    let mut stats = cuttle_binmorph::Stats::default();
    cuttle_binmorph::rewrite_function(&mut code, base_ip, &mut prng, &mut stats);
    assert_eq!(code.len(), orig_len, "binmorph must preserve byte length");
});
