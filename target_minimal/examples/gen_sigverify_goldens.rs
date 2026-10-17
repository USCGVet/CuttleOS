//! One-shot generator for DemoSignatureVerify golden vectors. Run with
//! `cargo run -p proteus-target-minimal --example gen_sigverify_goldens`.
//! Prints lines suitable for appending to `golden.txt`. NOT part of the
//! morph contract — this file is build-system scaffolding.
//!
//! Implements the "sign" half of the toy construction:
//!     signature[0..32]  = fletcher_pair(pubkey, message)
//!     signature[32..64] = fletcher_pair(message, pubkey)
//! and emits accept + reject (tampered-sig, wrong-msg, wrong-pubkey)
//! golden lines.

use proteus_target_minimal::fletcher_pair;

fn hex(bytes: &[u8]) -> String {
    if bytes.is_empty() {
        return "-".to_string();
    }
    bytes.iter().map(|b| format!("{:02x}", b)).collect()
}

fn sign(pubkey: &[u8; 32], message: &[u8]) -> [u8; 64] {
    let lo = fletcher_pair(pubkey, message);
    let hi = fletcher_pair(message, pubkey);
    let mut out = [0u8; 64];
    out[..32].copy_from_slice(&lo);
    out[32..].copy_from_slice(&hi);
    out
}

fn main() {
    // Fixed test vectors. The pubkey is the byte sequence 00..1F so it
    // is easy to read in hex; an alternative wrong_pubkey is a single
    // bit flip in the leading byte.
    let mut pk = [0u8; 32];
    let mut i = 0u8;
    while (i as usize) < 32 {
        pk[i as usize] = i;
        i += 1;
    }
    let mut wrong_pk = pk;
    wrong_pk[0] ^= 0x01;

    let messages: &[(&str, &[u8])] = &[
        ("empty", b""),
        ("onebyte", b"A"),
        ("medium", b"proteus-sigverify-demo"),
        ("long", b"Proteus morphs every cycle; the contract survives.--END"),
    ];

    // demo_sigverify_accept lines: legitimate (pk, msg, sig) triples.
    for (_name, msg) in messages {
        let sig = sign(&pk, msg);
        println!(
            "demo_sigverify_accept {} {} {}",
            hex(&pk),
            hex(msg),
            hex(&sig),
        );
    }

    // demo_sigverify_reject_tampered_sig: same (pk, msg) but with a
    // single bit flipped somewhere in the middle of the signature.
    {
        let msg: &[u8] = b"proteus-sigverify-demo";
        let mut sig = sign(&pk, msg);
        sig[20] ^= 0x40;
        println!(
            "demo_sigverify_reject_tampered_sig {} {} {}",
            hex(&pk),
            hex(msg),
            hex(&sig),
        );
        // And a second tamper at the tail.
        let mut sig2 = sign(&pk, msg);
        let last = sig2.len() - 1;
        sig2[last] ^= 0x01;
        println!(
            "demo_sigverify_reject_tampered_sig {} {} {}",
            hex(&pk),
            hex(msg),
            hex(&sig2),
        );
    }

    // demo_sigverify_reject_wrong_msg: legitimate signature over msgA
    // presented against msgB (one-byte mutation of msgA).
    {
        let msg_a: &[u8] = b"proteus-sigverify-demo";
        let mut msg_b = msg_a.to_vec();
        msg_b[0] ^= 0x01;
        let sig = sign(&pk, msg_a);
        println!(
            "demo_sigverify_reject_wrong_msg {} {} {}",
            hex(&pk),
            hex(&msg_b),
            hex(&sig),
        );
    }

    // demo_sigverify_reject_wrong_pubkey: signature legit under pk,
    // but verifier presented wrong_pk.
    {
        let msg: &[u8] = b"proteus-sigverify-demo";
        let sig = sign(&pk, msg);
        println!(
            "demo_sigverify_reject_wrong_pubkey {} {} {}",
            hex(&wrong_pk),
            hex(msg),
            hex(&sig),
        );
    }
}
