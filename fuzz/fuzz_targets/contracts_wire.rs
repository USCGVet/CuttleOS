#![no_main]
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() > 8192 {
        return;
    }
    // Exercise contracts wire-format helpers against arbitrary untrusted byte slices.
    let _ = cuttle_contracts::net_protocols::EthHeader::from_bytes(data);
    let _ = cuttle_contracts::net_protocols::ArpPacket::from_bytes(data);
});
