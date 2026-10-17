//! Integration tests for the M-of-N federation (TASK-006).
//!
//! Each test isolates itself via per-test tempdirs for both the
//! attestation log (`PROTEUS_ATTEST_DIR`) and the federation config
//! (`PROTEUS_FEDERATION_CONFIG`). We serialize env-mutating tests with
//! a mutex to avoid clobbering each other across the cargo test
//! worker pool.

use ed25519_dalek::{Signer as _, SigningKey};
use proteus_morph_engine::attest::{
    self, load_anchors, load_entries, parse_hex32, rebuild_anchors_after_cosign,
    rebuild_chain_after_cosign, verify_chain, verify_chain_with_options, write_attestation,
    write_chain_atomic, AttestEntryFields, VerifyOptions, ATTEST_DIR_ENV, SCHEMA_VERSION,
};
use proteus_morph_engine::federation::{
    self, load_federation, verify_cosignatures, Cosignature, FederationConfig,
    Signer as FedSigner, FEDERATION_CONFIG_ENV,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fresh_tempdir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "proteus_fed_int_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn pk_hex(sk: &SigningKey) -> String {
    sk.verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

fn sig_hex(sk: &SigningKey, msg: &[u8; 32]) -> String {
    sk.sign(msg)
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Write a `factory_keys.toml` with three signers seeded as [0;32],
/// [1;32], [2;32] (matching the bootstrap seeds shipped in
/// tests/fixtures/federation/).
fn write_test_federation(dir: &PathBuf, threshold: u32) -> PathBuf {
    let sk_primary = SigningKey::from_bytes(&[0u8; 32]);
    let sk_a = SigningKey::from_bytes(&[1u8; 32]);
    let sk_b = SigningKey::from_bytes(&[2u8; 32]);
    let toml = format!(
        "threshold = {}\n\
         [[signers]]\nid = \"primary\"\npubkey_hex = \"{}\"\n\
         [[signers]]\nid = \"placeholder-a\"\npubkey_hex = \"{}\"\n\
         [[signers]]\nid = \"placeholder-b\"\npubkey_hex = \"{}\"\n",
        threshold,
        pk_hex(&sk_primary),
        pk_hex(&sk_a),
        pk_hex(&sk_b),
    );
    let p = dir.join("factory_keys.toml");
    fs::write(&p, toml).unwrap();
    p
}

fn fields_with_primary_cosig(cycle: u64, threshold: u32) -> AttestEntryFields {
    let cand_hex = "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8";
    let cand = parse_hex32(cand_hex).unwrap();
    let sk_primary = SigningKey::from_bytes(&[0u8; 32]);
    let sig_hex_str = sig_hex(&sk_primary, &cand);
    AttestEntryFields {
        cycle,
        module: "lib".into(),
        candidate_sha256: cand_hex.into(),
        sig_ed25519: sig_hex_str.clone(),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: vec![Cosignature {
            signer_id: "primary".into(),
            sig_ed25519: sig_hex_str,
        }],
        federation_threshold: Some(threshold),
        factory_binaries: std::collections::BTreeMap::new(),
        bundle_name: None,
        modules: std::collections::BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
    diversity: None,
    durable_seals: std::collections::BTreeMap::new(),
    signing_key: None,
    }
}

/// 1. ACCEPTED: with M=2 and both primary + placeholder-a cosigs
/// present, `verify-attest --require-threshold` succeeds.
#[test]
fn accepts_when_threshold_met() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("threshold_met");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }

    // Write 1 attestation entry; primary cosig only.
    write_attestation(fields_with_primary_cosig(1, 2)).unwrap();

    // In-process equivalent of `morph cosign --signer placeholder-a --all`.
    let mut entries = load_entries().unwrap();
    let mut anchors = load_anchors().unwrap();
    let sk_a = SigningKey::from_bytes(&[1u8; 32]);
    let cand = parse_hex32(&entries[0].candidate_sha256).unwrap();
    entries[0].cosignatures.push(Cosignature {
        signer_id: "placeholder-a".into(),
        sig_ed25519: sig_hex(&sk_a, &cand),
    });
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    rebuild_anchors_after_cosign(&entries, &mut anchors, 0).unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    // Both verify modes succeed.
    let report = verify_chain().expect("plain verify ok");
    assert_eq!(report.entries_ok, 1);
    let report = verify_chain_with_options(&VerifyOptions {
        require_threshold: true,
        federation_config: Some(fed_path.clone()),
        require_merkle_root: false,
        require_strict_factory: false,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    })
    .expect("threshold verify ok");
    assert_eq!(report.entries_ok, 1);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// 2. REJECTED: with M=2 and only one cosig (primary), `verify-attest
/// --require-threshold` returns a clear error.
#[test]
fn rejects_below_threshold() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("below_thr");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }

    write_attestation(fields_with_primary_cosig(1, 2)).unwrap();

    // Plain verify ok (no threshold check); --require-threshold fails.
    verify_chain().expect("plain verify still ok");
    let err = verify_chain_with_options(&VerifyOptions {
        require_threshold: true,
        federation_config: Some(fed_path.clone()),
        require_merkle_root: false,
        require_strict_factory: false,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    })
    .expect_err("must fail under --require-threshold");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("threshold not met") && msg.contains("of 2"),
        "unexpected error: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// 3. REJECTED: an entry containing a cosig with an unknown `signer_id`
/// must fail under --require-threshold.
#[test]
fn rejects_unknown_signer() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("unknown_signer");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }

    write_attestation(fields_with_primary_cosig(1, 2)).unwrap();

    // Inject a rogue cosig (well-formed sig hex, but unknown id).
    let mut entries = load_entries().unwrap();
    let mut anchors = load_anchors().unwrap();
    let sk_rogue = SigningKey::from_bytes(&[99u8; 32]);
    let cand = parse_hex32(&entries[0].candidate_sha256).unwrap();
    entries[0].cosignatures.push(Cosignature {
        signer_id: "rogue".into(),
        sig_ed25519: sig_hex(&sk_rogue, &cand),
    });
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    rebuild_anchors_after_cosign(&entries, &mut anchors, 0).unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    let err = verify_chain_with_options(&VerifyOptions {
        require_threshold: true,
        federation_config: Some(fed_path.clone()),
        require_merkle_root: false,
        require_strict_factory: false,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    })
    .expect_err("must reject unknown signer");
    let msg = format!("{:#}", err);
    assert!(msg.contains("unknown signer"), "unexpected: {}", msg);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// 4. DEDUPE: identical primary cosig pushed twice into one entry must
/// be counted as one distinct signer. With M=2 the entry still fails.
#[test]
fn dedupes_repeat_signer() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("dedupe");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }

    write_attestation(fields_with_primary_cosig(1, 2)).unwrap();

    // Append a second, identical primary cosig.
    let mut entries = load_entries().unwrap();
    let mut anchors = load_anchors().unwrap();
    let sk_primary = SigningKey::from_bytes(&[0u8; 32]);
    let cand = parse_hex32(&entries[0].candidate_sha256).unwrap();
    entries[0].cosignatures.push(Cosignature {
        signer_id: "primary".into(),
        sig_ed25519: sig_hex(&sk_primary, &cand),
    });
    assert_eq!(entries[0].cosignatures.len(), 2);
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    rebuild_anchors_after_cosign(&entries, &mut anchors, 0).unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    let err = verify_chain_with_options(&VerifyOptions {
        require_threshold: true,
        federation_config: Some(fed_path.clone()),
        require_merkle_root: false,
        require_strict_factory: false,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    })
    .expect_err("two copies of same signer must still fail M=2");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("threshold not met") && msg.contains("have 1"),
        "expected dedupe to count as 1; got: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// In-process API exercise: load the bootstrap seeds from
/// `tests/fixtures/federation/`, sign a message, call
/// `verify_cosignatures` directly.
#[test]
fn fixture_seeds_match_factory_keys_toml() {
    // Find the fixtures dir relative to this test file's crate.
    let fixtures = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("federation");
    let primary_bytes = fs::read(fixtures.join("primary.seed")).unwrap();
    let a_bytes = fs::read(fixtures.join("placeholder_a.seed")).unwrap();
    let b_bytes = fs::read(fixtures.join("placeholder_b.seed")).unwrap();
    assert_eq!(primary_bytes.len(), 32);
    assert_eq!(a_bytes.len(), 32);
    assert_eq!(b_bytes.len(), 32);

    let mut p = [0u8; 32];
    p.copy_from_slice(&primary_bytes);
    let mut a = [0u8; 32];
    a.copy_from_slice(&a_bytes);
    let mut b = [0u8; 32];
    b.copy_from_slice(&b_bytes);
    let sk_p = SigningKey::from_bytes(&p);
    let sk_a = SigningKey::from_bytes(&a);
    let sk_b = SigningKey::from_bytes(&b);

    // The placeholder pubkeys must match the workspace-root
    // factory_keys.toml. The `primary` slot was rotated (2026-07-27, v11
    // entry-signature fix) to the REAL factory_signing_key.bin pubkey:
    // verify-attest authenticates v11+ entries against it, so a test
    // fixture there would make every legitimately-minted entry fail
    // verification — and would mean the checked-in fixture seed could
    // forge production signatures. Assert primary is NOT a fixture seed.
    let workspace_root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let cfg = load_federation(&workspace_root.join("factory_keys.toml")).unwrap();
    let want_primary = &cfg.signers.iter().find(|s| s.id == "primary").unwrap().pubkey_hex;
    let want_a = &cfg.signers.iter().find(|s| s.id == "placeholder-a").unwrap().pubkey_hex;
    let want_b = &cfg.signers.iter().find(|s| s.id == "placeholder-b").unwrap().pubkey_hex;
    assert_ne!(
        &pk_hex(&sk_p),
        want_primary,
        "workspace factory_keys.toml primary must be the real factory key, not the test fixture"
    );
    assert_eq!(&pk_hex(&sk_a), want_a);
    assert_eq!(&pk_hex(&sk_b), want_b);

    // Sign a synthetic candidate with the fixture seeds under their own
    // test-only roster and verify 2-of-3 threshold passes there. (The
    // workspace roster is no longer signable by fixtures — by design.)
    let test_cfg = FederationConfig {
        threshold: 2,
        signers: vec![
            FedSigner { id: "primary".into(), pubkey_hex: pk_hex(&sk_p) },
            FedSigner { id: "placeholder-a".into(), pubkey_hex: pk_hex(&sk_a) },
            FedSigner { id: "placeholder-b".into(), pubkey_hex: pk_hex(&sk_b) },
        ],
    };
    let msg = [0x42u8; 32];
    let cosigs = vec![
        Cosignature { signer_id: "primary".into(), sig_ed25519: sig_hex(&sk_p, &msg) },
        Cosignature { signer_id: "placeholder-b".into(), sig_ed25519: sig_hex(&sk_b, &msg) },
    ];
    verify_cosignatures(&msg, &cosigs, &test_cfg).unwrap();
}

/// After `cosign` modifies entries we must rewrite the chain so plain
/// (non-threshold) `verify_chain` still passes. This exercises the
/// `rebuild_chain_after_cosign` + `rebuild_anchors_after_cosign`
/// helpers over a multi-entry, post-anchor log.
#[test]
fn rebuild_chain_preserves_plain_verify() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("rebuild");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }

    // Write 12 entries: triggers one anchor (entries 0..=9).
    for i in 1u64..=12 {
        write_attestation(fields_with_primary_cosig(i, 2)).unwrap();
    }
    let anchors_before = load_anchors().unwrap();
    assert_eq!(anchors_before.len(), 1);
    verify_chain().expect("pre-cosign chain ok");

    // Cosign every entry with placeholder-a.
    let mut entries = load_entries().unwrap();
    let mut anchors = load_anchors().unwrap();
    let sk_a = SigningKey::from_bytes(&[1u8; 32]);
    for i in 0..entries.len() {
        let cand = parse_hex32(&entries[i].candidate_sha256).unwrap();
        entries[i].cosignatures.push(Cosignature {
            signer_id: "placeholder-a".into(),
            sig_ed25519: sig_hex(&sk_a, &cand),
        });
    }
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    rebuild_anchors_after_cosign(&entries, &mut anchors, 0).unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    // Plain verify must still pass (the chain was rebuilt).
    let report = verify_chain().expect("post-cosign plain verify ok");
    assert_eq!(report.entries_ok, 12);
    assert_eq!(report.anchors_ok, 1);

    // Threshold verify must now succeed (primary + placeholder-a = 2-of-3).
    let report = verify_chain_with_options(&VerifyOptions {
        require_threshold: true,
        federation_config: Some(fed_path.clone()),
        require_merkle_root: false,
        require_strict_factory: false,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    })
    .expect("post-cosign threshold verify ok");
    assert_eq!(report.entries_ok, 12);

    // And the anchor's merkle_root reflects the new entry hashes (i.e.
    // it changed from the pre-cosign root).
    let anchors_after = load_anchors().unwrap();
    assert_ne!(
        anchors_before[0].merkle_root, anchors_after[0].merkle_root,
        "anchor merkle_root must shift after entries were modified"
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// v3 entries written by `write_attestation` must carry the new fields
/// in their serialized form when populated.
#[test]
fn v3_entry_carries_federation_fields() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("v3_fields");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }
    write_attestation(fields_with_primary_cosig(7, 2)).unwrap();
    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].schema_version, proteus_morph_engine::attest::LEGACY_SCHEMA_VERSION);
    assert_eq!(entries[0].federation_threshold, Some(2));
    assert_eq!(entries[0].cosignatures.len(), 1);
    assert_eq!(entries[0].cosignatures[0].signer_id, "primary");

    // The on-disk JSON line must contain the new fields.
    let path = attest::attest_log_path();
    let raw = fs::read_to_string(&path).unwrap();
    assert!(raw.contains("\"cosignatures\""), "raw line: {}", raw);
    assert!(raw.contains("\"federation_threshold\""), "raw line: {}", raw);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Schema migration: a v2 log on disk is migrated aside on the first v3
/// write. Mirrors the existing `v1_log_is_migrated_aside` test.
#[test]
fn v2_log_is_migrated_aside_to_v2_bak() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("v2_migrate");
    let fed_path = write_test_federation(&dir, 2);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }
    // Plant a v2-shape log line (schema_version=2, no cosignatures).
    let v2_line = r#"{"schema_version":2,"cycle":1,"ts_unix":1700000000,"module":"lib","candidate_sha256":"39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8","sig_ed25519":"00","accepted":true,"synthesizer":"passthrough","prev_entry_sha256":"0000000000000000000000000000000000000000000000000000000000000000","entry_sha256":"deadbeef"}"#;
    fs::write(attest::attest_log_path(), format!("{}\n", v2_line)).unwrap();

    write_attestation(fields_with_primary_cosig(5, 2)).unwrap();

    let bak = dir.join(attest::ATTEST_LOG_V2_BAK);
    assert!(bak.exists(), "expected v2 backup at {}", bak.display());

    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].cycle, 5);
    assert_eq!(entries[0].schema_version, proteus_morph_engine::attest::LEGACY_SCHEMA_VERSION);
    assert_eq!(entries[0].federation_threshold, Some(2));

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// Construct a `FederationConfig` in memory and exercise
/// `verify_cosignatures` directly without touching the filesystem.
/// Doubles as a regression for the dedup logic invoked from the cosign
/// CLI path.
#[test]
fn in_process_verify_cosignatures_smoke() {
    let sk_a = SigningKey::from_bytes(&[1u8; 32]);
    let sk_b = SigningKey::from_bytes(&[2u8; 32]);
    let cfg = FederationConfig {
        threshold: 2,
        signers: vec![
            FedSigner { id: "a".into(), pubkey_hex: pk_hex(&sk_a) },
            FedSigner { id: "b".into(), pubkey_hex: pk_hex(&sk_b) },
        ],
    };
    let msg = [7u8; 32];
    let cosigs = vec![
        Cosignature { signer_id: "a".into(), sig_ed25519: sig_hex(&sk_a, &msg) },
        Cosignature { signer_id: "b".into(), sig_ed25519: sig_hex(&sk_b, &msg) },
    ];
    verify_cosignatures(&msg, &cosigs, &cfg).unwrap();
    // Sanity: federation::resolve_federation_path env mechanism.
    unsafe {
        std::env::set_var(FEDERATION_CONFIG_ENV, "/nonexistent/path/factory_keys.toml");
    }
    let p = federation::resolve_federation_path();
    assert_eq!(p, PathBuf::from("/nonexistent/path/factory_keys.toml"));
    unsafe {
        std::env::remove_var(FEDERATION_CONFIG_ENV);
    }
}

