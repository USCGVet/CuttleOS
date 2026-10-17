//! Golden output corpus for proteus-target-minimal.
//!
//! This integration test is the load-bearing semantic check that every
//! morph candidate must pass. It loads `golden.txt` (compiled in via
//! `include_str!`), parses each test case, invokes the corresponding
//! locked function on the candidate, and asserts byte-for-byte equality.
//!
//! It also drives the property-test harness defined in
//! `proteus_contracts::harness` against the candidate's `DemoHash` and
//! `DemoAead` impls — the verifier downstream relies on this test target
//! compiling and passing as proof that the candidate honours the trait
//! contract.

use proteus_contracts::harness::{
    check_aead, check_hash, check_signature, check_signature_thorough, check_syscall_dispatch,
    Verdict,
};
use proteus_contracts::{Aead, Hash, SignatureVerify, SyscallDispatch};
use proteus_target_minimal::{
    derive_byte, feistel_mix, fletcher32, fletcher_pair, DemoAead, DemoErrno, DemoHash,
    DemoSignatureVerify, DemoSyscallDispatch,
};

const GOLDEN: &str = include_str!("../golden.txt");

#[test]
fn golden_corpus_matches() {
    let mut total = 0usize;
    let mut by_fn: std::collections::BTreeMap<&str, usize> = Default::default();

    for (lineno, raw) in GOLDEN.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let parts: Vec<&str> = line.split_whitespace().collect();
        assert!(
            !parts.is_empty(),
            "line {}: empty after split",
            lineno + 1
        );
        let name = parts[0];

        match name {
            // ---- existing 3-token (name, input, expected) variants ----
            "fletcher32" => {
                expect_tokens(&parts, 3, lineno);
                let input = parse_hex(parts[1]);
                let expected = parse_hex(parts[2]);
                let got = fletcher32(&input).to_be_bytes();
                assert_eq!(
                    &got[..],
                    expected.as_slice(),
                    "line {} fletcher32({}) mismatch",
                    lineno + 1,
                    parts[1]
                );
            }
            "DemoHash::hash" => {
                expect_tokens(&parts, 3, lineno);
                let input = parse_hex(parts[1]);
                let expected = parse_hex(parts[2]);
                let mut out = [0u8; <DemoHash as Hash>::OUTPUT_LEN];
                <DemoHash as Hash>::hash(&input, &mut out);
                assert_eq!(
                    &out[..],
                    expected.as_slice(),
                    "line {} DemoHash::hash({}) mismatch",
                    lineno + 1,
                    parts[1]
                );
            }
            "feistel_mix" => {
                expect_tokens(&parts, 3, lineno);
                let input = parse_hex(parts[1]);
                let expected = parse_hex(parts[2]);
                assert_eq!(input.len(), 8, "line {}: feistel_mix input must be 8 bytes", lineno + 1);
                assert_eq!(expected.len(), 8, "line {}: feistel_mix output must be 8 bytes", lineno + 1);
                let state = u64::from_be_bytes(input.as_slice().try_into().unwrap());
                let got = feistel_mix(state).to_be_bytes();
                assert_eq!(
                    &got[..],
                    expected.as_slice(),
                    "line {} feistel_mix({:016x}) mismatch",
                    lineno + 1,
                    state
                );
            }
            "derive_byte" => {
                expect_tokens(&parts, 3, lineno);
                let input = parse_hex(parts[1]);
                let expected = parse_hex(parts[2]);
                assert_eq!(input.len(), 5, "line {}: derive_byte input must be 5 bytes (seed||rounds_be)", lineno + 1);
                assert_eq!(expected.len(), 1, "line {}: derive_byte output must be 1 byte", lineno + 1);
                let seed = input[0];
                let rounds = u32::from_be_bytes(input[1..5].try_into().unwrap());
                let got = derive_byte(seed, rounds);
                assert_eq!(
                    got, expected[0],
                    "line {} derive_byte({:#04x}, {}) mismatch",
                    lineno + 1,
                    seed,
                    rounds
                );
            }
            // ---- DemoAead: 6-token encrypt vector --------------------
            // demo_aead_encrypt <key> <nonce> <pt> <aad> <expected-ct>
            "demo_aead_encrypt" => {
                expect_tokens(&parts, 6, lineno);
                let key = parse_hex(parts[1]);
                let nonce = parse_hex(parts[2]);
                let pt = parse_hex(parts[3]);
                let aad = parse_hex(parts[4]);
                let expected = parse_hex(parts[5]);
                let mut out = vec![0u8; pt.len() + <DemoAead as Aead>::TAG_LEN];
                let n = <DemoAead as Aead>::encrypt(&key, &nonce, &pt, &aad, &mut out);
                assert_eq!(
                    n,
                    pt.len() + <DemoAead as Aead>::TAG_LEN,
                    "line {} demo_aead_encrypt: wrong output length",
                    lineno + 1
                );
                assert_eq!(
                    &out[..n],
                    expected.as_slice(),
                    "line {} demo_aead_encrypt ciphertext mismatch",
                    lineno + 1
                );
            }
            // ---- DemoAead: 5-token roundtrip vector ------------------
            // demo_aead_decrypt_roundtrip <key> <nonce> <pt> <aad>
            "demo_aead_decrypt_roundtrip" => {
                expect_tokens(&parts, 5, lineno);
                let key = parse_hex(parts[1]);
                let nonce = parse_hex(parts[2]);
                let pt = parse_hex(parts[3]);
                let aad = parse_hex(parts[4]);
                let mut ct = vec![0u8; pt.len() + <DemoAead as Aead>::TAG_LEN];
                let n = <DemoAead as Aead>::encrypt(&key, &nonce, &pt, &aad, &mut ct);
                let mut recovered = vec![0u8; pt.len()];
                let m = <DemoAead as Aead>::decrypt(&key, &nonce, &ct[..n], &aad, &mut recovered)
                    .unwrap_or_else(|_| panic!("line {} demo_aead_decrypt_roundtrip: decrypt rejected legitimate ct", lineno + 1));
                assert_eq!(
                    m,
                    pt.len(),
                    "line {} demo_aead_decrypt_roundtrip: wrong recovered length",
                    lineno + 1
                );
                assert_eq!(
                    &recovered[..m],
                    pt.as_slice(),
                    "line {} demo_aead_decrypt_roundtrip: recovered != original",
                    lineno + 1
                );
            }
            // ---- DemoAead: 5-token tamper-rejection vector -----------
            // demo_aead_decrypt_tampered <key> <nonce> <ct> <aad>  -> MUST Err
            "demo_aead_decrypt_tampered" => {
                expect_tokens(&parts, 5, lineno);
                let key = parse_hex(parts[1]);
                let nonce = parse_hex(parts[2]);
                let ct = parse_hex(parts[3]);
                let aad = parse_hex(parts[4]);
                let pt_len = ct.len().saturating_sub(<DemoAead as Aead>::TAG_LEN);
                let mut sink = vec![0u8; pt_len];
                let res = <DemoAead as Aead>::decrypt(&key, &nonce, &ct, &aad, &mut sink);
                assert!(
                    res.is_err(),
                    "line {} demo_aead_decrypt_tampered: tampered ct was accepted",
                    lineno + 1
                );
            }
            // ---- DemoSignatureVerify: 4-token vectors ----------------
            // demo_sigverify_accept              <pk> <msg> <sig>  -> verify true
            // demo_sigverify_reject_tampered_sig <pk> <msg> <sig>  -> verify false
            // demo_sigverify_reject_wrong_msg    <pk> <msg> <sig>  -> verify false
            // demo_sigverify_reject_wrong_pubkey <pk> <msg> <sig>  -> verify false
            "demo_sigverify_accept" => {
                expect_tokens(&parts, 4, lineno);
                let pk = parse_hex(parts[1]);
                let msg = parse_hex(parts[2]);
                let sig = parse_hex(parts[3]);
                assert!(
                    <DemoSignatureVerify as SignatureVerify>::verify(&pk, &msg, &sig),
                    "line {} demo_sigverify_accept: legitimate sig was rejected",
                    lineno + 1
                );
            }
            "demo_sigverify_reject_tampered_sig"
            | "demo_sigverify_reject_wrong_msg"
            | "demo_sigverify_reject_wrong_pubkey" => {
                expect_tokens(&parts, 4, lineno);
                let pk = parse_hex(parts[1]);
                let msg = parse_hex(parts[2]);
                let sig = parse_hex(parts[3]);
                assert!(
                    !<DemoSignatureVerify as SignatureVerify>::verify(&pk, &msg, &sig),
                    "line {} {}: bogus sig was accepted",
                    lineno + 1,
                    name
                );
            }
            // ---- DemoSyscallDispatch: 9-token vector -----------------
            // demo_syscall <nr-dec> <a0> <a1> <a2> <a3> <a4> <a5> <expected>
            // where each <ai> is a 16-hex-digit u64 (textual hex, NOT raw
            // little-endian bytes) and <expected> is "Ok=<u64-hex>",
            // "Err=ENOSYS", "Err=EINVAL", or "Err=EFAULT".
            "demo_syscall" => {
                expect_tokens(&parts, 9, lineno);
                let nr: u64 = parts[1]
                    .parse()
                    .unwrap_or_else(|_| panic!("line {}: bad syscall nr", lineno + 1));
                let a0 = parse_u64_hex(parts[2], lineno);
                let a1 = parse_u64_hex(parts[3], lineno);
                let a2 = parse_u64_hex(parts[4], lineno);
                let a3 = parse_u64_hex(parts[5], lineno);
                let a4 = parse_u64_hex(parts[6], lineno);
                let a5 = parse_u64_hex(parts[7], lineno);
                let expected = parts[8];
                let got =
                    <DemoSyscallDispatch as SyscallDispatch>::dispatch(nr, a0, a1, a2, a3, a4, a5);
                if let Some(hex) = expected.strip_prefix("Ok=") {
                    let want = parse_u64_hex(hex, lineno);
                    match got {
                        Ok(v) => assert_eq!(
                            v,
                            want,
                            "line {} demo_syscall(nr={}) Ok payload mismatch: got {:016x} want {:016x}",
                            lineno + 1,
                            nr,
                            v,
                            want,
                        ),
                        Err(e) => panic!(
                            "line {} demo_syscall(nr={}) expected Ok={:016x}, got Err({:?})",
                            lineno + 1,
                            nr,
                            want,
                            e,
                        ),
                    }
                } else if let Some(errname) = expected.strip_prefix("Err=") {
                    let want_err = match errname {
                        "ENOSYS" => DemoErrno::ENOSYS,
                        "EINVAL" => DemoErrno::EINVAL,
                        "EFAULT" => DemoErrno::EFAULT,
                        _ => panic!(
                            "line {}: unknown DemoErrno variant {:?}",
                            lineno + 1,
                            errname
                        ),
                    };
                    match got {
                        Err(e) => assert_eq!(
                            e,
                            want_err,
                            "line {} demo_syscall(nr={}) Err variant mismatch: got {:?} want {:?}",
                            lineno + 1,
                            nr,
                            e,
                            want_err,
                        ),
                        Ok(v) => panic!(
                            "line {} demo_syscall(nr={}) expected Err({:?}), got Ok({:016x})",
                            lineno + 1,
                            nr,
                            want_err,
                            v,
                        ),
                    }
                } else {
                    panic!(
                        "line {}: demo_syscall expected-result must be Ok=<hex> or Err=<NAME>, got {:?}",
                        lineno + 1,
                        expected
                    );
                }
            }
            other => panic!("line {}: unknown function name {:?}", lineno + 1, other),
        }

        total += 1;
        let bucket = match name {
            "fletcher32" => "fletcher32",
            "DemoHash::hash" => "DemoHash::hash",
            "feistel_mix" => "feistel_mix",
            "derive_byte" => "derive_byte",
            "demo_aead_encrypt" => "demo_aead_encrypt",
            "demo_aead_decrypt_roundtrip" => "demo_aead_decrypt_roundtrip",
            "demo_aead_decrypt_tampered" => "demo_aead_decrypt_tampered",
            "demo_sigverify_accept" => "demo_sigverify_accept",
            "demo_sigverify_reject_tampered_sig" => "demo_sigverify_reject_tampered_sig",
            "demo_sigverify_reject_wrong_msg" => "demo_sigverify_reject_wrong_msg",
            "demo_sigverify_reject_wrong_pubkey" => "demo_sigverify_reject_wrong_pubkey",
            "demo_syscall" => "demo_syscall",
            _ => unreachable!(),
        };
        *by_fn.entry(bucket).or_default() += 1;
    }

    assert!(
        total >= 10,
        "golden corpus must hold at least 10 cases, found {}",
        total
    );
    for fname in [
        "fletcher32",
        "DemoHash::hash",
        "feistel_mix",
        "derive_byte",
        "demo_aead_encrypt",
        "demo_aead_decrypt_roundtrip",
        "demo_aead_decrypt_tampered",
        "demo_sigverify_accept",
        "demo_sigverify_reject_tampered_sig",
        "demo_sigverify_reject_wrong_msg",
        "demo_sigverify_reject_wrong_pubkey",
        "demo_syscall",
    ] {
        assert!(
            by_fn.get(fname).copied().unwrap_or(0) > 0,
            "golden corpus must include at least one case for {}",
            fname
        );
    }
}

#[test]
fn demo_hash_satisfies_harness_invariants() {
    match check_hash::<DemoHash>() {
        Verdict::Pass => {}
        Verdict::Fail(why) => panic!("DemoHash failed harness invariant: {}", why),
        Verdict::Invalid(why) => panic!("DemoHash was invalid: {}", why),
    }
}

#[test]
fn demo_aead_satisfies_harness_invariants() {
    match check_aead::<DemoAead>() {
        Verdict::Pass => {}
        Verdict::Fail(why) => panic!("DemoAead failed harness invariant: {}", why),
        Verdict::Invalid(why) => panic!("DemoAead was invalid: {}", why),
    }
}

#[test]
fn demo_sigverify_satisfies_harness_invariants() {
    // Construct a known-good (pk, msg, sig) triple on the fly using the
    // public fletcher_pair helper. The pubkey is 32 bytes 00..1F, the
    // wrong pubkey flips one bit, and the message is a short ASCII tag.
    let mut pk = [0u8; <DemoSignatureVerify as SignatureVerify>::PUBKEY_LEN];
    {
        let mut i = 0u8;
        while (i as usize) < pk.len() {
            pk[i as usize] = i;
            i += 1;
        }
    }
    let mut wrong_pk = pk;
    wrong_pk[0] ^= 0x01;

    let msg: &[u8] = b"proteus-harness-msg";
    let lo = fletcher_pair(&pk, msg);
    let hi = fletcher_pair(msg, &pk);
    let mut sig = [0u8; <DemoSignatureVerify as SignatureVerify>::SIGNATURE_LEN];
    sig[..32].copy_from_slice(&lo);
    sig[32..].copy_from_slice(&hi);

    // Sanity: the on-the-fly construction must verify.
    assert!(
        <DemoSignatureVerify as SignatureVerify>::verify(&pk, msg, &sig),
        "self-constructed sig must verify"
    );

    match check_signature::<DemoSignatureVerify>(&pk, msg, &sig) {
        Verdict::Pass => {}
        Verdict::Fail(why) => panic!("DemoSignatureVerify failed check_signature: {}", why),
        Verdict::Invalid(why) => panic!("DemoSignatureVerify check_signature invalid: {}", why),
    }

    match check_signature_thorough::<DemoSignatureVerify>(&pk, msg, &sig, &wrong_pk) {
        Verdict::Pass => {}
        Verdict::Fail(why) => {
            panic!("DemoSignatureVerify failed check_signature_thorough: {}", why)
        }
        Verdict::Invalid(why) => {
            panic!("DemoSignatureVerify check_signature_thorough invalid: {}", why)
        }
    }
}

#[test]
fn demo_syscall_satisfies_harness_invariants() {
    match check_syscall_dispatch::<DemoSyscallDispatch>() {
        Verdict::Pass => {}
        Verdict::Fail(why) => panic!("DemoSyscallDispatch failed harness invariant: {}", why),
        Verdict::Invalid(why) => panic!("DemoSyscallDispatch was invalid: {}", why),
    }
}

fn parse_u64_hex(s: &str, lineno: usize) -> u64 {
    assert!(
        s.len() <= 16,
        "line {}: u64 hex too long ({:?})",
        lineno + 1,
        s
    );
    u64::from_str_radix(s, 16)
        .unwrap_or_else(|_| panic!("line {}: bad u64 hex {:?}", lineno + 1, s))
}

fn expect_tokens(parts: &[&str], want: usize, lineno: usize) {
    assert_eq!(
        parts.len(),
        want,
        "line {}: expected {} tokens for {:?}, got {}",
        lineno + 1,
        want,
        parts[0],
        parts.len()
    );
}

fn parse_hex(s: &str) -> Vec<u8> {
    if s == "-" {
        return Vec::new();
    }
    assert!(
        s.len() % 2 == 0,
        "hex string must be even length: {:?}",
        s
    );
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("bad hex digit"))
        .collect()
}
