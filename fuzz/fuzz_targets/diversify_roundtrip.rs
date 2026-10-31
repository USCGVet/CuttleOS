#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 8 || data.len() > 16 * 1024 {
        return;
    }
    let seed_u64 = u64::from_le_bytes(data[..8].try_into().unwrap());
    let Ok(src) = std::str::from_utf8(&data[8..]) else {
        return;
    };
    let seed = cuttle_diversifier::Seed::derive(seed_u64, "fuzz");
    if let Ok((out1, log1)) = cuttle_diversifier::diversify_with_log(src, &seed) {
        let (out2, log2) = cuttle_diversifier::diversify_with_log(src, &seed)
            .expect("deterministic second diversify run must succeed");
        assert_eq!(out1, out2);
        assert_eq!(log1, log2);
    }
});
