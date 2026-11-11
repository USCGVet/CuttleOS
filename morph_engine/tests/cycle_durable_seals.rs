//! TASK-155 — one morph cycle with `CUTTLE_DURABLE_SEALS_DIR` attaches
//! seals onto the attestation entry.
//!
//! Always-on (not env-gated): single-module `target_minimal` cycle is
//! cheap relative to full `[bundle.kernel]`. Uses temp attest + seals
//! dirs so production chain is untouched.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cuttle_morph_engine::{
    run_cycle, verify_chain_with_options, CycleArgs, DurableSeal, SynthesizerKind, VerifyOptions,
    ATTEST_DIR_ENV, DURABLE_SEALS_DIR_ENV, FEDERATION_CONFIG_ENV, SIGNING_KEY_ENV,
};
use ed25519_dalek::SigningKey;

static TEST_MUTEX: Mutex<()> = Mutex::new(());

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("morph_engine parent")
        .to_path_buf()
}

fn stamp() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
}

fn last_accepted_entry(attest_dir: &Path) -> serde_json::Value {
    let log = attest_dir.join("attest.log.jsonl");
    let txt = fs::read_to_string(&log).expect("read attest log");
    let mut last: Option<serde_json::Value> = None;
    for line in txt.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("jsonl line");
        if v.get("accepted").and_then(|a| a.as_bool()) == Some(true) {
            last = Some(v);
        }
    }
    last.expect("expected at least one accepted attest entry")
}

#[test]
fn cycle_attaches_durable_seals_from_dir() {
    let _g = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();

    // Ensure verify binary exists (cycle stage 3 shells out).
    let st = Command::new("cargo")
        .args(["build", "-p", "cuttle-verifier", "--bin", "verify"])
        .current_dir(&root)
        .status()
        .expect("cargo build verify");
    assert!(st.success(), "build verify failed");

    let run_dir = root
        .join("experiments")
        .join("cycle_durable_seals")
        .join(format!("run_{}", stamp()));
    let attest_dir = run_dir.join("attest");
    let seals_dir = run_dir.join("seals");
    fs::create_dir_all(&attest_dir).unwrap();
    fs::create_dir_all(&seals_dir).unwrap();

    // Provision a temporary signing key + matching federation config in run_dir
    // so this test passes on a fresh checkout without workspace-root factory_signing_key.bin.
    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let sk_bytes = sk.to_bytes();
    let pk_hex: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let key_path = run_dir.join("factory_signing_key.bin");
    fs::write(&key_path, &sk_bytes).unwrap();
    let fed_path = run_dir.join("factory_keys.toml");
    fs::write(
        &fed_path,
        format!(
            "threshold = 1\n[[signers]]\nid = \"primary\"\npubkey_hex = \"{}\"\n",
            pk_hex
        ),
    )
    .unwrap();

    // Fixture seals (labels must appear on the attest entry).
    DurableSeal::seal("fixture_audit", b"audit-blob-v1")
        .write_file(&seals_dir.join("fixture_audit.json"))
        .unwrap();
    DurableSeal::seal("fixture_wal", b"wal-head-bytes")
        .write_file(&seals_dir.join("fixture_wal.json"))
        .unwrap();

    let lib_path = root.join("target_minimal").join("src").join("lib.rs");
    let lib_before = fs::read_to_string(&lib_path).expect("read lib.rs");

    // Perf baseline can flap under load; clear for this one-shot cycle.
    let perf_path = root.join("perf.jsonl");
    let perf_bak = run_dir.join("perf.jsonl.bak");
    let had_perf = perf_path.exists();
    if had_perf {
        fs::copy(&perf_path, &perf_bak).ok();
        fs::write(&perf_path, "").ok();
    }

    let prev_attest = std::env::var_os(ATTEST_DIR_ENV);
    let prev_seals = std::env::var_os(DURABLE_SEALS_DIR_ENV);
    let prev_key = std::env::var_os(SIGNING_KEY_ENV);
    let prev_fed = std::env::var_os(FEDERATION_CONFIG_ENV);
    let prev_cwd = std::env::current_dir().expect("cwd");

    // Safety: restore env/cwd/lib and remove temp run_dir even on panic.
    struct Guard {
        prev_cwd: PathBuf,
        prev_attest: Option<std::ffi::OsString>,
        prev_seals: Option<std::ffi::OsString>,
        prev_key: Option<std::ffi::OsString>,
        prev_fed: Option<std::ffi::OsString>,
        lib_path: PathBuf,
        lib_before: String,
        had_perf: bool,
        perf_path: PathBuf,
        perf_bak: PathBuf,
        run_dir: PathBuf,
    }
    impl Drop for Guard {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev_cwd);
            unsafe {
                match &self.prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
                match &self.prev_seals {
                    Some(v) => std::env::set_var(DURABLE_SEALS_DIR_ENV, v),
                    None => std::env::remove_var(DURABLE_SEALS_DIR_ENV),
                }
                match &self.prev_key {
                    Some(v) => std::env::set_var(SIGNING_KEY_ENV, v),
                    None => std::env::remove_var(SIGNING_KEY_ENV),
                }
                match &self.prev_fed {
                    Some(v) => std::env::set_var(FEDERATION_CONFIG_ENV, v),
                    None => std::env::remove_var(FEDERATION_CONFIG_ENV),
                }
            }
            let _ = fs::write(&self.lib_path, &self.lib_before);
            if self.had_perf {
                let _ = fs::copy(&self.perf_bak, &self.perf_path);
            }
            let _ = fs::remove_dir_all(&self.run_dir);
            if let Some(parent) = self.run_dir.parent() {
                let _ = fs::remove_dir(parent);
            }
        }
    }
    let _guard = Guard {
        prev_cwd: prev_cwd.clone(),
        prev_attest: prev_attest.clone(),
        prev_seals: prev_seals.clone(),
        prev_key: prev_key.clone(),
        prev_fed: prev_fed.clone(),
        lib_path: lib_path.clone(),
        lib_before: lib_before.clone(),
        had_perf,
        perf_path: perf_path.clone(),
        perf_bak: perf_bak.clone(),
        run_dir: run_dir.clone(),
    };

    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &attest_dir);
        // Prefer CLI path on CycleArgs; also set env so resolve is dual-covered.
        std::env::set_var(DURABLE_SEALS_DIR_ENV, &seals_dir);
        std::env::set_var(SIGNING_KEY_ENV, &key_path);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }
    std::env::set_current_dir(&root).expect("cd workspace");

    // Unique cycle id so candidate hash differs across re-runs if needed.
    let cycle = (stamp() % 1_000_000) as u64 + 10_000;
    let args = CycleArgs {
        cycle,
        module: "lib".into(),
        target_dir: root.join("target_minimal").join("src"),
        manifest: Some(root.join("target_minimal").join("manifest.txt")),
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: true,
        durable_seals_dir: Some(seals_dir.clone()),
    };

    eprintln!(
        "cycle_durable_seals: cycle={} seals={} attest={}",
        cycle,
        seals_dir.display(),
        attest_dir.display()
    );
    run_cycle(&args).expect("run_cycle should accept");

    // Structural verify with require_durable_seals hard-fails if missing.
    verify_chain_with_options(&VerifyOptions {
        require_threshold: false,
        require_merkle_root: false,
        require_strict_factory: false,
        federation_config: Some(fed_path.clone()),
        factory_expected_path: None,
        require_ext_tlv: true,
        require_diversity: false, // single-module may still fill diversity
        require_durable_seals: true,
    })
    .expect("verify-attest --require-durable-seals");

    // JSONL surface (forensics path).
    let v = last_accepted_entry(&attest_dir);
    assert_eq!(v.get("accepted").and_then(|a| a.as_bool()), Some(true));
    let map = v
        .get("durable_seals")
        .and_then(|d| d.as_object())
        .expect("json durable_seals object");
    let expect_audit = DurableSeal::seal("fixture_audit", b"audit-blob-v1").sha256;
    let expect_wal = DurableSeal::seal("fixture_wal", b"wal-head-bytes").sha256;
    assert_eq!(
        map.get("fixture_audit").and_then(|x| x.as_str()),
        Some(expect_audit.as_str())
    );
    assert_eq!(
        map.get("fixture_wal").and_then(|x| x.as_str()),
        Some(expect_wal.as_str())
    );

    eprintln!(
        "cycle_durable_seals: OK labels={:?}",
        map.keys().collect::<Vec<_>>()
    );
}

#[test]
fn rejected_cycles_preserve_v11_chain_cleanup_candidates_and_record_bundle_semantic_log() {
    use cuttle_morph_engine::{
        attest, attest_proposal, propose_cycle, run_bundle, verify_chain, BundleCycleArgs, Proposal,
        PROPOSAL_SCHEMA_VERSION,
    };
    use ed25519_dalek::Signer as _;

    let _g = TEST_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();

    let st = Command::new("cargo")
        .args(["build", "-p", "cuttle-verifier", "--bin", "verify"])
        .current_dir(&root)
        .status()
        .expect("cargo build verify");
    assert!(st.success(), "build verify failed");

    let run_dir = root
        .join("experiments")
        .join("cycle_durable_seals")
        .join(format!("run_rej_{}", stamp()));
    let attest_dir = run_dir.join("attest");
    fs::create_dir_all(&attest_dir).unwrap();

    let sk = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk_hex: String = sk
        .verifying_key()
        .to_bytes()
        .iter()
        .map(|b| format!("{:02x}", b))
        .collect();
    let key_path = run_dir.join("factory_signing_key.bin");
    fs::write(&key_path, sk.to_bytes()).unwrap();
    let fed_path = run_dir.join("factory_keys.toml");
    fs::write(
        &fed_path,
        format!("threshold = 1\n[[signers]]\nid = \"primary\"\npubkey_hex = \"{pk_hex}\"\n"),
    )
    .unwrap();

    let src_dir = root.join("target_minimal").join("src");
    let lib_path = src_dir.join("lib.rs");
    let lib_before = fs::read_to_string(&lib_path).expect("read lib.rs");
    let lib_last_good = src_dir.join("lib.last_good.rs");
    let had_last_good = lib_last_good.exists();
    let bad_mod = "tmp_stage8_reject_probe";
    let bad_src_path = src_dir.join(format!("{bad_mod}.rs"));
    let bad_cand_path = src_dir.join(format!("{bad_mod}.candidate.rs"));
    let bad_last_good_path = src_dir.join(format!("{bad_mod}.last_good.rs"));
    // Valid Rust AST so diversifier succeeds (and emits semantic_decisions on `probe`),
    // while `bad_manifest` triggers immediate <5ms static rejection (`MissingManifestSymbols`) in `verify`!
    fs::write(
        &bad_src_path,
        "pub fn probe(x: u32) -> u32 { if x == 0 { 1 } else { x * 8 } }\n",
    )
    .unwrap();
    let bad_manifest = run_dir.join("require_missing_sym.txt");
    fs::write(&bad_manifest, "missing_required_symbol_for_stage8_test\n").unwrap();

    let prev_attest = std::env::var_os(ATTEST_DIR_ENV);
    let prev_seals = std::env::var_os(DURABLE_SEALS_DIR_ENV);
    let prev_key = std::env::var_os(SIGNING_KEY_ENV);
    let prev_fed = std::env::var_os(FEDERATION_CONFIG_ENV);
    let prev_cwd = std::env::current_dir().expect("cwd");

    struct Cleanup {
        prev_cwd: PathBuf,
        prev_attest: Option<std::ffi::OsString>,
        prev_seals: Option<std::ffi::OsString>,
        prev_key: Option<std::ffi::OsString>,
        prev_fed: Option<std::ffi::OsString>,
        lib_path: PathBuf,
        lib_before: String,
        lib_last_good: PathBuf,
        had_last_good: bool,
        bad_src_path: PathBuf,
        bad_cand_path: PathBuf,
        bad_last_good_path: PathBuf,
        run_dir: PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev_cwd);
            unsafe {
                match &self.prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
                match &self.prev_seals {
                    Some(v) => std::env::set_var(DURABLE_SEALS_DIR_ENV, v),
                    None => std::env::remove_var(DURABLE_SEALS_DIR_ENV),
                }
                match &self.prev_key {
                    Some(v) => std::env::set_var(SIGNING_KEY_ENV, v),
                    None => std::env::remove_var(SIGNING_KEY_ENV),
                }
                match &self.prev_fed {
                    Some(v) => std::env::set_var(FEDERATION_CONFIG_ENV, v),
                    None => std::env::remove_var(FEDERATION_CONFIG_ENV),
                }
            }
            let _ = fs::write(&self.lib_path, &self.lib_before);
            if !self.had_last_good {
                let _ = fs::remove_file(&self.lib_last_good);
            }
            let _ = fs::remove_file(&self.bad_src_path);
            let _ = fs::remove_file(&self.bad_cand_path);
            let _ = fs::remove_file(&self.bad_last_good_path);
            let _ = fs::remove_dir_all(&self.run_dir);
            if let Some(parent) = self.run_dir.parent() {
                let _ = fs::remove_dir(parent);
            }
        }
    }
    let _cleanup = Cleanup {
        prev_cwd,
        prev_attest,
        prev_seals,
        prev_key,
        prev_fed,
        lib_path: lib_path.clone(),
        lib_before: lib_before.clone(),
        lib_last_good,
        had_last_good,
        bad_src_path: bad_src_path.clone(),
        bad_cand_path: bad_cand_path.clone(),
        bad_last_good_path,
        run_dir: run_dir.clone(),
    };

    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &attest_dir);
        std::env::remove_var(DURABLE_SEALS_DIR_ENV);
        std::env::set_var(SIGNING_KEY_ENV, &key_path);
        std::env::set_var(FEDERATION_CONFIG_ENV, &fed_path);
    }
    std::env::set_current_dir(&root).expect("cd workspace");

    // 1. Seed chain with a v11 accepted entry signed by `sk` (1ms, no scratch compile needed).
    let sig0 = sk.sign(&[0x55u8; 32]);
    let sig0_hex: String = sig0.to_bytes().iter().map(|b| format!("{:02x}", b)).collect();
    attest::write_attestation(attest::AttestEntryFields {
        cycle: 101,
        module: "lib".into(),
        candidate_sha256: "55".repeat(32),
        sig_ed25519: sig0_hex.clone(),
        accepted: true,
        synthesizer: "fireworks".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: vec![cuttle_morph_engine::federation::Cosignature {
            signer_id: "primary".into(),
            sig_ed25519: sig0_hex,
        }],
        federation_threshold: Some(1),
        factory_binaries: std::collections::BTreeMap::new(),
        bundle_name: None,
        modules: std::collections::BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        signing_key: Some(sk.clone()),
    })
    .expect("seed accepted v11 entry");

    // 2. Rejected single-module `run_cycle` must clean up `.candidate.rs` AND emit a v11 signed rejection!
    let rej_args = CycleArgs {
        cycle: 102,
        module: bad_mod.into(),
        target_dir: src_dir.clone(),
        manifest: Some(bad_manifest.clone()),
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: true,
        durable_seals_dir: None,
    };
    assert!(run_cycle(&rej_args).is_err(), "missing-manifest candidate must be rejected");
    assert!(
        !bad_cand_path.exists(),
        "run_cycle must remove {} on verifier rejection",
        bad_cand_path.display()
    );

    // 3. Rejected `propose_cycle` and `attest_proposal` must also remove `.candidate.rs`!
    let unused_out = run_dir.join("rejected_proposal.json");
    assert!(propose_cycle(&rej_args, &unused_out).is_err());
    assert!(
        !bad_cand_path.exists(),
        "propose_cycle must remove {} on verifier rejection",
        bad_cand_path.display()
    );
    let rej_cand_src = "pub fn probe(x: u32) -> u32 { x << 3 }\n";
    fs::write(&bad_cand_path, rej_cand_src).unwrap();
    let rej_cand_hash = cuttle_diversifier::canonical_hash(rej_cand_src).unwrap();
    let rej_cand_hex: String = rej_cand_hash.iter().map(|b| format!("{:02x}", b)).collect();
    let rej_prop_path = run_dir.join("bad_proposal.json");
    let rej_prop = Proposal {
        schema_version: PROPOSAL_SCHEMA_VERSION,
        cycle: 102,
        module: bad_mod.into(),
        candidate_path: bad_cand_path.display().to_string(),
        candidate_sha256: rej_cand_hex,
        synthesizer: "fireworks".into(),
        diversifier_log: attest::DiversifierLog::default(),
        proposer_verified_ok: true,
        ts_unix: 1700000100,
    };
    fs::write(&rej_prop_path, serde_json::to_string_pretty(&rej_prop).unwrap()).unwrap();
    assert!(attest_proposal(&rej_args, &rej_prop_path).is_err());
    assert!(
        !bad_cand_path.exists(),
        "attest_proposal must remove {} on verifier rejection",
        bad_cand_path.display()
    );

    // 4. Rejected `run_bundle` must emit a v11 signed rejection AND preserve `semantic_decisions`!
    let bargs = BundleCycleArgs {
        cycle: 103,
        bundle_name: "test_bundle".into(),
        workspace: root.join("target_minimal"),
        modules: vec![bad_mod.into()],
        manifest: Some(bad_manifest),
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: true,
        durable_seals_dir: None,
    };
    assert!(run_bundle(&bargs).is_err(), "missing-manifest bundle must be rejected");

    // Verify full 3-entry chain (accepted v11 -> rejected v11 -> rejected bundle v11)!
    let report = verify_chain().expect("chain with v11 rejections after v11 accept must verify");
    assert_eq!(report.entries_ok, 3);

    let entries = attest::load_entries().unwrap();
    assert_eq!(
        entries[0].synthesizer, "fireworks",
        "attest_proposal must preserve 'fireworks' synthesizer label"
    );
    assert_eq!(entries[1].schema_version, attest::SCHEMA_VERSION);
    assert!(!entries[1].accepted);
    assert_eq!(entries[2].schema_version, attest::SCHEMA_VERSION);
    assert!(!entries[2].accepted);
    let b_div_log = entries[2]
        .diversifier_log
        .as_ref()
        .expect("bundle diversifier_log present");
    assert!(
        b_div_log
            .semantic_decisions
            .keys()
            .any(|k| k == &format!("{bad_mod}::probe")),
        "bundle_div_log must merge member semantic_decisions, got: {:?}",
        b_div_log.semantic_decisions
    );
}
