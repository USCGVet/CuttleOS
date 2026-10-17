//! TASK-140 — schema v10 `durable_seals` on attestation entries.

use proteus_morph_engine::attest::{
    load_entries, verify_chain, write_attestation, AttestEntryFields, ATTEST_DIR_ENV,
    SCHEMA_VERSION,
};
use proteus_morph_engine::{durable_seals_map_from, DurableSeal};
use std::collections::BTreeMap;
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
        "proteus_attest_v10_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn base_fields(cycle: u64) -> AttestEntryFields {
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
        durable_seals: BTreeMap::new(),
        signing_key: None,
    }
}

#[test]
fn schema_v10_floor() {
    assert!(SCHEMA_VERSION >= 10);
}

#[test]
fn write_with_durable_seals_and_verify() {
    let _g = EnvGuard::new("seals");
    let seal = DurableSeal::seal("audit_snapshot", b"demo-audit-bytes");
    let mut f = base_fields(1);
    f.durable_seals = durable_seals_map_from(&[seal.clone()]);
    write_attestation(f).unwrap();
    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(
        entries[0].durable_seals.get("audit_snapshot"),
        Some(&seal.sha256)
    );
    verify_chain().unwrap();
}

#[test]
fn empty_durable_seals_omitted_from_json() {
    use proteus_morph_engine::attest::{compute_entry_sha256, AttestEntry, ZERO_HEX};
    let e = AttestEntry {
        schema_version: SCHEMA_VERSION,
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
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: BTreeMap::new(),
        prev_entry_sha256: ZERO_HEX.to_string(),
        entry_sha256: "bb".repeat(32),
    };
    let line = serde_json::to_string(&e).unwrap();
    assert!(
        !line.contains("\"durable_seals\""),
        "empty durable_seals must be omitted: {line}"
    );
    let _ = compute_entry_sha256(&e);
}

#[test]
fn bad_seal_hex_rejected_on_write() {
    let _g = EnvGuard::new("bad");
    let mut f = base_fields(1);
    f.durable_seals
        .insert("x".into(), "not-hex".into());
    assert!(write_attestation(f).is_err());
}

#[test]
fn require_durable_seals_rejects_missing() {
    use proteus_morph_engine::attest::verify_chain_with_options;
    use proteus_morph_engine::VerifyOptions;
    let _g = EnvGuard::new("req_seals");
    write_attestation(base_fields(1)).unwrap();
    // Default: no require → OK.
    verify_chain().unwrap();
    let err = verify_chain_with_options(&VerifyOptions {
        require_durable_seals: true,
        ..VerifyOptions::default()
    })
    .unwrap_err();
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("durable_seals") || msg.contains("require-durable"),
        "unexpected: {msg}"
    );
}

#[test]
fn require_durable_seals_accepts_present() {
    use proteus_morph_engine::attest::verify_chain_with_options;
    use proteus_morph_engine::VerifyOptions;
    let _g = EnvGuard::new("req_seals_ok");
    let seal = DurableSeal::seal("wal_head", b"lsn=42");
    let mut f = base_fields(1);
    f.durable_seals = durable_seals_map_from(&[seal]);
    write_attestation(f).unwrap();
    verify_chain_with_options(&VerifyOptions {
        require_durable_seals: true,
        ..VerifyOptions::default()
    })
    .unwrap();
}
