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
