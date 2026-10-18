//! TASK-102 — attestation schema v8: `ext_tlv_b64` (TLV + Base64).
//!
//! Load-bearing properties:
//! 1. SCHEMA_VERSION >= 8
//! 2. write_attestation auto-fills ext_tlv_b64
//! 3. verify_chain accepts a chain with valid TLV
//! 4. corrupt ext_tlv_b64 fails verify
//! 5. --require-ext-tlv rejects missing field
//! 6. None is skip_serialized (pre-v8 hash stability)

use cuttle_morph_engine::attest::{
    self, compute_entry_sha256, load_entries, verify_chain, verify_chain_with_options,
    write_attestation, AttestEntry, AttestEntryFields, VerifyOptions, ATTEST_DIR_ENV,
    READABLE_MIN_SCHEMA, SCHEMA_VERSION,
};
use cuttle_morph_engine::{build_ext_tlv_b64, verify_ext_tlv_b64, EXT_TLV_TAG_COUNT};
use std::collections::BTreeMap;
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
        "cuttle_attest_v8_test_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    dir: PathBuf,
}

impl EnvGuard {
    fn new(label: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = fresh_tempdir(label);
        unsafe {
            std::env::set_var(ATTEST_DIR_ENV, &dir);
        }
        Self { _lock: lock, dir }
    }
}

impl Drop for EnvGuard {
    fn drop(&mut self) {
        unsafe {
            std::env::remove_var(ATTEST_DIR_ENV);
        }
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn fields(cycle: u64) -> AttestEntryFields {
    AttestEntryFields {
        cycle,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
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
        ext_tlv_b64: None,
    diversity: None,
    durable_seals: std::collections::BTreeMap::new(),
    signing_key: None,
    }
}

#[test]
fn schema_v8_floor() {
    assert!(SCHEMA_VERSION >= 8);
    assert_eq!(READABLE_MIN_SCHEMA, 3);
    assert_eq!(EXT_TLV_TAG_COUNT, 3);
}

#[test]
fn write_auto_fills_ext_tlv_and_verify_ok() {
    let _g = EnvGuard::new("autofill");
    write_attestation(fields(1)).unwrap();
    write_attestation(fields(2)).unwrap();
    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 2);
    for e in &entries {
        let b64 = e.ext_tlv_b64.as_ref().expect("ext_tlv_b64 present");
        verify_ext_tlv_b64(b64, e.cycle, &e.module, &e.candidate_sha256).unwrap();
    }
    let rep = verify_chain().unwrap();
    assert_eq!(rep.entries_ok, 2);
}

#[test]
fn default_require_ext_tlv_rejects_missing() {
    let _g = EnvGuard::new("require");
    // Hand-write a JSONL line with no ext_tlv_b64 (simulates pre-v8).
    let mut e = AttestEntry {
        schema_version: 7,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
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
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: attest::ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    e.entry_sha256 = {
        let h = compute_entry_sha256(&e).unwrap();
        h.iter().map(|b| format!("{:02x}", b)).collect()
    };
    let log = std::env::var(ATTEST_DIR_ENV).unwrap();
    let path = PathBuf::from(log).join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();

    // TASK-106: default verify requires ext_tlv_b64.
    assert!(VerifyOptions::default().require_ext_tlv);
    let err = verify_chain().unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("ext_tlv_b64") || msg.contains("require-ext-tlv"),
        "unexpected err: {msg}"
    );

    // Legacy opt-out (CLI --allow-missing-ext-tlv).
    let opts = VerifyOptions {
        require_ext_tlv: false,
        ..Default::default()
    };
    verify_chain_with_options(&opts).unwrap();
}

#[test]
fn default_options_require_ext_tlv_true() {
    assert!(VerifyOptions::default().require_ext_tlv);
}

#[test]
fn corrupt_ext_tlv_fails_verify() {
    let _g = EnvGuard::new("corrupt");
    write_attestation(fields(1)).unwrap();
    let mut entries = load_entries().unwrap();
    entries[0].ext_tlv_b64 = Some("!!!!not-valid-base64!!!!".into());
    // Rewrite log with broken hash-unrelated corruption — recompute hash
    // so chain hash check passes but TLV check fails.
    let mut e = entries[0].clone();
    e.entry_sha256 = String::new();
    let h = compute_entry_sha256(&e).unwrap();
    e.entry_sha256 = h.iter().map(|b| format!("{:02x}", b)).collect();
    let log = std::env::var(ATTEST_DIR_ENV).unwrap();
    let path = PathBuf::from(log).join(attest::ATTEST_LOG);
    fs::write(&path, serde_json::to_string(&e).unwrap() + "\n").unwrap();

    let err = verify_chain().unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("ext_tlv") || msg.contains("base64") || msg.contains("decode"),
        "unexpected err: {msg}"
    );
}

#[test]
fn none_omitted_from_json() {
    let e = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 1,
        ts_unix: 1,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
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
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: attest::ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    let v = serde_json::to_value(&e).unwrap();
    assert!(!v.as_object().unwrap().contains_key("ext_tlv_b64"));
}

#[test]
fn build_helper_roundtrip() {
    let hex = "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8";
    let b64 = build_ext_tlv_b64(99, "kernel", hex).unwrap();
    verify_ext_tlv_b64(&b64, 99, "kernel", hex).unwrap();
}
