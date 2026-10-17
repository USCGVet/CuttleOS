//! One-shot generator for DemoAead golden vectors. Run with
//! `cargo run -p proteus-target-minimal --example gen_aead_goldens`.
//! Prints lines suitable for appending to `golden.txt`. NOT part of
//! the morph contract — this file is build-system scaffolding.

use proteus_contracts::Aead;
use proteus_target_minimal::DemoAead;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn enc(key: &[u8], nonce: &[u8], pt: &[u8], aad: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; pt.len() + DemoAead::TAG_LEN];
    let n = DemoAead::encrypt(key, nonce, pt, aad, &mut out);
    out.truncate(n);
    out
}

fn main() {
    // Five round-trip cases of varying shape; we emit both the encrypt
    // line (which checks the ciphertext byte-for-byte) and a separate
    // _decrypt_roundtrip marker (so the golden test driver can also
    // exercise the decrypt path against the same vectors).
    let key1 = b"YELLOW SUBMARINE";
    let key2 = b"yellow submarine";
    let nonce = b"NONCE_08";

    let cases: &[(&str, &[u8], &[u8])] = &[
        ("empty",     b"",                                                       b""),
        ("onebyte",   b"A",                                                      b""),
        ("aligned16", b"ABCDEFGHIJKLMNOP",                                       b"ad-A"),
        ("unaligned", b"the quick brown fox jumps over",                         b"ad-2"),
        ("long",      b"Proteus morphs every cycle; the contract survives.--END", b"final-aad"),
    ];

    for (_name, pt, aad) in cases {
        let ct = enc(key1, nonce, pt, aad);
        println!(
            "demo_aead_encrypt {} {} {} {} {}",
            hex(key1),
            hex(nonce),
            hex(pt),
            hex(aad),
            hex(&ct),
        );
    }
    for (_name, pt, aad) in cases {
        println!(
            "demo_aead_decrypt_roundtrip {} {} {} {}",
            hex(key1),
            hex(nonce),
            hex(pt),
            hex(aad),
        );
    }

    // Tampered vectors: take the 'unaligned' ciphertext and flip the
    // first byte (body tamper) and the last byte (tag tamper). Also
    // the same ciphertext under a different key, and under a different
    // AAD — all four should reject.
    let pt = b"the quick brown fox jumps over";
    let aad = b"ad-2";
    let aad_other = b"ad-X-wrong";
    let ct = enc(key1, nonce, pt, aad);

    let mut tamper_body = ct.clone();
    tamper_body[0] ^= 0x01;
    let mut tamper_tag = ct.clone();
    let last = tamper_tag.len() - 1;
    tamper_tag[last] ^= 0x80;

    println!(
        "demo_aead_decrypt_tampered {} {} {} {}",
        hex(key1),
        hex(nonce),
        hex(&tamper_body),
        hex(aad),
    );
    println!(
        "demo_aead_decrypt_tampered {} {} {} {}",
        hex(key1),
        hex(nonce),
        hex(&tamper_tag),
        hex(aad),
    );
    println!(
        "demo_aead_decrypt_tampered {} {} {} {}",
        hex(key1),
        hex(nonce),
        hex(&ct),
        hex(aad_other),
    );
    println!(
        "demo_aead_decrypt_tampered {} {} {} {}",
        hex(key2),
        hex(nonce),
        hex(&ct),
        hex(aad),
    );
}
