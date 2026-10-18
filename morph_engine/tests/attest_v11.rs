//! v11 entry-content signatures — regression tests for the 2026-07-27
//! red-team findings:
//!
//! F1: pre-v11, `verify-attest` checked hashes only; a filesystem
//!     attacker could rewrite the whole log and recompute the chain.
//! F2: pre-v11, the primary signature covered only `candidate_sha256`,
//!     so a signed candidate could be relabelled onto a different module
//!     or have its diversity/image/seal evidence forged.
//!
//! v11 mints `sig_ed25519` over the signable entry hash (canonical entry
//! minus sig/cosigs/entry_sha256) and `verify_chain` ALWAYS authenticates
//! v11+ entries. These tests prove the attacks fail and the legit path
//! still works.

use ed25519_dalek::{Signer as _, SigningKey};
use cuttle_morph_engine::attest::{
    self, load_entries, rebuild_chain_after_cosign, verify_chain, write_attestation,
    write_chain_atomic, AttestEntryFields, ATTEST_DIR_ENV,
};
use cuttle_morph_engine::federation::FEDERATION_CONFIG_ENV;
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fresh_tempdir(label: &str) -> PathBuf {
    use std::sync::atomic::{AtomicU64, Ordering};
    static C: AtomicU64 = AtomicU64::new(0);
    let n = C.fetch_add(1, Ordering::Relaxed);
    let d = std::env::temp_dir().join(format!("cuttle_v11_{}_{}_{}", label, std::process::id(), n));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn test_key() -> SigningKey {
    SigningKey::from_bytes(&[0x42u8; 32])
}

fn pk_hex(sk: &SigningKey) -> String {
    sk.verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect()
}

/// Write a federation config whose "primary" signer is the test key, so
/// the verifier's trusted-key resolution authenticates against it.
fn write_fed_toml(dir: &PathBuf, sk: &SigningKey) -> PathBuf {
    let p = dir.join("factory_keys.toml");
    fs::write(
        &p,
        format!(
            "threshold = 1\n[[signers]]\nid = \"primary\"\npubkey_hex = \"{}\"\n",
            pk_hex(sk)
        ),
    )
    .unwrap();
    p
}

fn fields(cycle: u64, module: &str, key: SigningKey) -> AttestEntryFields {
    let cand = [cycle as u8; 32];
    // Primary cosig keeps its historical semantics: signature over the
    // candidate hash. (Not exercised by these tests; shape only.)
    let cosig = cuttle_morph_engine::federation::Cosignature {
        signer_id: "primary".to_string(),
        sig_ed25519: key
            .sign(&cand)
            .to_bytes()
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect(),
    };
    AttestEntryFields {
        cycle,
        module: module.to_string(),
        candidate_sha256: cand.iter().map(|b| format!("{:02x}", b)).collect(),
        sig_ed25519: String::new(), // ignored — write_attestation signs at write time
        accepted: true,
        synthesizer: "passthrough".to_string(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: vec![cosig],
        federation_threshold: Some(1),
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: BTreeMap::new(),
        signing_key: Some(key),
    }
}

struct Guard {
    dir: PathBuf,
}
impl Guard {
    fn new(label: &str) -> (std::sync::MutexGuard<'static, ()>, Self) {
        let g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = fresh_tempdir(label);
        unsafe {
            std::env::set_var(ATTEST_DIR_ENV, &dir);
        }
        (g, Self { dir })
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(ATTEST_DIR_ENV);
            std::env::remove_var(FEDERATION_CONFIG_ENV);
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn signed_v11_entries_verify_and_mint_at_schema_11() {
    let (_g, guard) = Guard::new("happy");
    let sk = test_key();
    let fed = write_fed_toml(&guard.dir, &sk);
    unsafe {
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed);
    }
    write_attestation(fields(1, "tls", sk.clone())).unwrap();
    write_attestation(fields(2, "wal", sk.clone())).unwrap();

    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 2);
    for e in &entries {
        assert_eq!(e.schema_version, attest::SCHEMA_VERSION);
        assert_eq!(e.sig_ed25519.len(), 128);
    }
    let report = verify_chain().expect("signed chain must verify");
    assert_eq!(report.entries_ok, 2);
}

#[test]
fn f2_relabelled_signed_entry_fails_verification() {
    let (_g, guard) = Guard::new("relabel");
    let sk = test_key();
    let fed = write_fed_toml(&guard.dir, &sk);
    unsafe {
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed);
    }
    write_attestation(fields(1, "tls", sk.clone())).unwrap();

    // ATTACK (the original F2): filesystem attacker relabels the signed
    // candidate onto a locked module and recomputes the hash chain so it
    // is internally consistent — exactly what pre-v11 verify accepted.
    let mut entries = load_entries().unwrap();
    entries[0].module = "kpti".to_string();
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    let anchors = attest::load_anchors().unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    let err = verify_chain().unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("signature"),
        "expected signature failure, got: {msg}"
    );
}

#[test]
fn f2_forged_diversity_evidence_fails_verification() {
    let (_g, guard) = Guard::new("forge_diversity");
    let sk = test_key();
    let fed = write_fed_toml(&guard.dir, &sk);
    unsafe {
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed);
    }
    write_attestation(fields(1, "tcp", sk.clone())).unwrap();

    // ATTACK: fabricate "measured diversity" on a signed entry.
    let mut entries = load_entries().unwrap();
    entries[0].diversity = Some(attest::DiversityEvidence {
        positional_survival_bps: Some(0),
        ..Default::default()
    });
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    let anchors = attest::load_anchors().unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    let err = verify_chain().unwrap_err();
    assert!(
        format!("{:#}", err).contains("signature"),
        "expected signature failure, got: {:#}",
        err
    );
}

#[test]
fn f1_full_log_rewrite_without_key_fails_closed() {
    let (_g, guard) = Guard::new("rewrite");
    let sk = test_key();
    let fed = write_fed_toml(&guard.dir, &sk);
    unsafe {
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed);
    }
    write_attestation(fields(1, "dns", sk.clone())).unwrap();

    // ATTACK (the original F1): attacker without the key rewrites the
    // entry content entirely and recomputes every hash. They cannot
    // produce a valid sig over the new content.
    let mut entries = load_entries().unwrap();
    entries[0].candidate_sha256 = "ff".repeat(32);
    entries[0].accepted = true;
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    let anchors = attest::load_anchors().unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    let err = verify_chain().unwrap_err();
    assert!(
        format!("{:#}", err).contains("signature"),
        "expected signature failure, got: {:#}",
        err
    );
}

#[test]
fn unsigned_v11_entry_fails_closed_even_with_valid_hashes() {
    let (_g, guard) = Guard::new("unsigned");
    // Attacker writes a hand-crafted v11 entry with a zero sig. Note: no
    // federation config and no key file in this tempdir at all — the
    // verifier must ALSO fail closed on key resolution.
    let mut e = attest::AttestEntry {
        schema_version: attest::SCHEMA_VERSION,
        cycle: 1,
        ts_unix: 1,
        module: "lib".into(),
        candidate_sha256: "aa".repeat(32),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: None,
        modules: BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: Some(
            cuttle_morph_engine::build_ext_tlv_b64(1, "lib", &"aa".repeat(32)).unwrap(),
        ),
        diversity: None,
        durable_seals: BTreeMap::new(),
        prev_entry_sha256: attest::ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    e.entry_sha256 = {
        let h = attest::compute_entry_sha256(&e).unwrap();
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let path = guard.dir.join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();

    let err = verify_chain().unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("no trusted primary key") || msg.contains("signature"),
        "expected fail-closed error, got: {msg}"
    );
}

#[test]
fn legacy_unsigned_v10_chain_still_verifies() {
    let (_g, _guard) = Guard::new("legacy");
    // No federation config, no key file — legacy entries must remain
    // verifiable (hash-chain semantics) without any trusted key.
    let mut f = fields(1, "lib", test_key());
    f.signing_key = None;
    f.sig_ed25519 = "00".repeat(64);
    f.cosignatures = Vec::new();
    f.federation_threshold = None;
    write_attestation(f).unwrap();

    let entries = load_entries().unwrap();
    assert_eq!(entries[0].schema_version, attest::LEGACY_SCHEMA_VERSION);
    let report = verify_chain().expect("legacy chain must verify");
    assert_eq!(report.entries_ok, 1);
}

#[test]
fn cosign_appended_post_mint_does_not_invalidate_primary_sig() {
    let (_g, guard) = Guard::new("cosign");
    let sk = test_key();
    let fed = write_fed_toml(&guard.dir, &sk);
    unsafe {
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed);
    }
    write_attestation(fields(1, "http", sk.clone())).unwrap();

    // Simulate `morph cosign`: append a second cosignature and rebuild
    // the chain. The primary sig excludes `cosignatures` from its
    // preimage, so it must still verify.
    let mut entries = load_entries().unwrap();
    let other = SigningKey::from_bytes(&[0x99u8; 32]);
    let cand = attest::parse_hex32(&entries[0].candidate_sha256).unwrap();
    entries[0]
        .cosignatures
        .push(cuttle_morph_engine::federation::Cosignature {
            signer_id: "placeholder-a".to_string(),
            sig_ed25519: other
                .sign(&cand)
                .to_bytes()
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect(),
        });
    rebuild_chain_after_cosign(&mut entries, 0).unwrap();
    let anchors = attest::load_anchors().unwrap();
    write_chain_atomic(&entries, &anchors).unwrap();

    let report = verify_chain().expect("cosigned chain must still verify");
    assert_eq!(report.entries_ok, 1);
}
