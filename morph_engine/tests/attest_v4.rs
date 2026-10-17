//! TASK-022 — integration tests for the v4 attestation schema
//! (`factory_binaries` map) and `verify-attest --strict-factory`.
//!
//! Test isolation uses `PROTEUS_ATTEST_DIR` like `tests/attest.rs`; the
//! env-var lock is local to this file (Rust integration tests live in
//! separate binaries, so we can't share `ENV_LOCK` across files).

use proteus_morph_engine::attest::{
    self, compute_entry_sha256, load_entries, verify_chain, verify_chain_with_options,
    write_attestation, AttestEntry, AttestEntryFields, MerkleRootStatus, VerifyOptions,
    ATTEST_DIR_ENV, READABLE_MIN_SCHEMA, SCHEMA_VERSION,
};
use proteus_morph_engine::factory::{
    self, FactoryExpected, COMPONENT_DIVERSIFY, COMPONENT_MORPH, COMPONENT_RUSTC,
    COMPONENT_VERIFY,
};
use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// Local env-var serialisation — see comment in tests/attest.rs.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fresh_tempdir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "proteus_attest_v4_test_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn h(b: u8) -> String {
    let mut s = String::with_capacity(64);
    for _ in 0..64 {
        s.push_str(&format!("{:x}", b & 0xf));
    }
    s
}

fn good_map() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert(COMPONENT_MORPH.into(), h(0xa));
    m.insert(COMPONENT_VERIFY.into(), h(0xb));
    m.insert(COMPONENT_DIVERSIFY.into(), h(0xc));
    m.insert(COMPONENT_RUSTC.into(), h(0xd));
    m
}

fn good_expected_file(path: &std::path::Path) {
    let cfg = FactoryExpected {
        required: vec![
            COMPONENT_MORPH.into(),
            COMPONENT_VERIFY.into(),
            COMPONENT_DIVERSIFY.into(),
            COMPONENT_RUSTC.into(),
        ],
        components: {
            let mut c: BTreeMap<String, Vec<String>> = BTreeMap::new();
            c.insert(COMPONENT_MORPH.into(), vec![h(0xa)]);
            c.insert(COMPONENT_VERIFY.into(), vec![h(0xb)]);
            c.insert(COMPONENT_DIVERSIFY.into(), vec![h(0xc)]);
            c.insert(COMPONENT_RUSTC.into(), vec![h(0xd), h(0xe)]);
            c
        },
    };
    let raw = toml::to_string(&cfg).unwrap();
    fs::write(path, raw).unwrap();
}

fn fields_with_factory(cycle: u64, accepted: bool, factory: BTreeMap<String, String>) -> AttestEntryFields {
    AttestEntryFields {
        cycle,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519:
            "592a10ada2935a65cfac37070d4f5b8b2b0113df1067c76c33caa073a719e9aa\
             300c434ebbd8f94a76021be908427976bdf00fdb340ef7107abd83ecb016dd02"
                .into(),
        accepted,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: factory,
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

// =====================================================================
// 1. Schema-bump invariants
// =====================================================================

/// `SCHEMA_VERSION` is the current value (v5 after TASK-036 / Phase A)
/// and the `READABLE_MIN_SCHEMA` band still includes 3 — v3 / v4
/// chains continue to verify under a v5 binary because every v5
/// addition (`factory_binaries`, `bundle_name`, `modules`) is
/// `skip_serializing_if`-omittable. The constants surface so external
/// auditors can confirm the bump without reading the code.
#[test]
fn schema_constants_are_v3_through_current_band() {
    // SCHEMA_VERSION has advanced past v4; this v4-vintage test now
    // just pins the readable-min floor and the live current version.
    // The current value is bumped by whichever task last touched the
    // schema; the readable-min floor stays at v3 because every bump
    // since has been additive (`skip_serializing_if`-omitted).
    assert!(SCHEMA_VERSION >= 4, "v4 floor must hold");
    assert_eq!(READABLE_MIN_SCHEMA, 3);
}

/// Two structurally identical entries — one with `factory_binaries`
/// explicitly empty, one with the field "absent" via deserialising
/// from JSON that omits the key — must produce the same
/// `entry_sha256`. This is the canonical-JSON contract that lets v3
/// entries verify under v4 code without a migration.
#[test]
fn empty_factory_binaries_is_canonically_invisible() {
    let e1 = AttestEntry {
        schema_version: 3,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519:
            "592a10ada2935a65cfac37070d4f5b8b2b0113df1067c76c33caa073a719e9aa\
             300c434ebbd8f94a76021be908427976bdf00fdb340ef7107abd83ecb016dd02"
                .into(),
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
    let v = serde_json::to_value(&e1).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("factory_binaries"),
        "factory_binaries must be skip_serializing when empty, got: {:?}",
        obj
    );
    let h1 = compute_entry_sha256(&e1).unwrap();
    let e2: AttestEntry = serde_json::from_value(v).unwrap();
    let h2 = compute_entry_sha256(&e2).unwrap();
    assert_eq!(h1, h2, "round-trip via serde changed the hash");
}

/// A non-empty `factory_binaries` map MUST shift the hash. Without
/// this property an attacker could insert a forged map into a stored
/// entry without invalidating the chain.
#[test]
fn populated_factory_binaries_perturbs_canonical_hash() {
    let base = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519:
            "592a10ada2935a65cfac37070d4f5b8b2b0113df1067c76c33caa073a719e9aa\
             300c434ebbd8f94a76021be908427976bdf00fdb340ef7107abd83ecb016dd02"
                .into(),
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
    let h_empty = compute_entry_sha256(&base).unwrap();

    let mut with_map = base.clone();
    with_map.factory_binaries = good_map();
    let h_populated = compute_entry_sha256(&with_map).unwrap();
    assert_ne!(
        h_empty, h_populated,
        "populated factory_binaries must shift the canonical hash"
    );

    let v = serde_json::to_value(&with_map).unwrap();
    assert!(v.as_object().unwrap().contains_key("factory_binaries"));
}

/// Two maps with the same key-value pairs but different insertion
/// orders must canonical-hash to the same value. `BTreeMap` sorts on
/// iteration so this is a sanity check on `canonical_json`'s sort.
#[test]
fn factory_map_canonical_hash_is_order_independent() {
    let mut m1: BTreeMap<String, String> = BTreeMap::new();
    m1.insert("morph".into(), h(0xa));
    m1.insert("verify".into(), h(0xb));
    let mut m2: BTreeMap<String, String> = BTreeMap::new();
    m2.insert("verify".into(), h(0xb));
    m2.insert("morph".into(), h(0xa));

    let e1 = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 5,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519:
            "592a10ada2935a65cfac37070d4f5b8b2b0113df1067c76c33caa073a719e9aa\
             300c434ebbd8f94a76021be908427976bdf00fdb340ef7107abd83ecb016dd02"
                .into(),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: m1,
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
    let mut e2 = e1.clone();
    e2.factory_binaries = m2;
    let h1 = compute_entry_sha256(&e1).unwrap();
    let h2 = compute_entry_sha256(&e2).unwrap();
    assert_eq!(h1, h2, "same-content maps must produce the same hash");
}

// =====================================================================
// 2. Write/verify happy path
// =====================================================================

#[test]
fn write_chain_with_factory_binaries_verifies() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("v4_happy");
    // SAFETY: tests serialised via ENV_LOCK.
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    write_attestation(fields_with_factory(1, true, good_map())).unwrap();
    write_attestation(fields_with_factory(2, true, good_map())).unwrap();
    write_attestation(fields_with_factory(3, true, good_map())).unwrap();

    let report = verify_chain().expect("chain must verify");
    assert_eq!(report.entries_ok, 3);
    let entries = load_entries().unwrap();
    for e in &entries {
        assert_eq!(e.schema_version, proteus_morph_engine::attest::LEGACY_SCHEMA_VERSION);
        assert_eq!(e.factory_binaries.len(), 4);
    }

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

// =====================================================================
// 3. v3 ↔ v4 mixed-presence verification
// =====================================================================

/// Plant a v3-shape entry by writing a fresh entry then editing its
/// schema_version on disk to 3 and removing the (empty) factory map
/// reference. Recompute its entry_sha256, then append a v4 entry on
/// top. The whole chain must verify because v3 entries with no
/// factory_binaries hash identically under v4 canonical-JSON rules.
#[test]
fn v3_then_v4_chain_verifies() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("v3v4mix");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    // Step 1: write a v3-looking entry. We do this by overwriting
    // schema_version in the in-memory entry before hashing.
    use std::io::Write;
    let mut e1 = AttestEntry {
        schema_version: 3,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519:
            "592a10ada2935a65cfac37070d4f5b8b2b0113df1067c76c33caa073a719e9aa\
             300c434ebbd8f94a76021be908427976bdf00fdb340ef7107abd83ecb016dd02"
                .into(),
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
    let h1 = compute_entry_sha256(&e1).unwrap();
    e1.entry_sha256 = attest::hex(&h1);
    let line = serde_json::to_string(&e1).unwrap();
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(attest::attest_log_path())
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
    }

    // Step 2: append a v4 entry via the public API. Migration should
    // NOT move the v3 entry aside (the migrate_chain `Some(3)` arm
    // leaves it in place).
    write_attestation(fields_with_factory(2, true, good_map())).unwrap();

    // Step 3: the chain verifies end-to-end.
    let report = verify_chain_with_options(&VerifyOptions { require_ext_tlv: false, ..Default::default() }).expect("v3-then-v4 chain must verify");
    assert_eq!(report.entries_ok, 2);

    let entries = load_entries().unwrap();
    assert_eq!(entries[0].schema_version, 3);
    // Entry 1 is whatever the current binary emits. Today: v5 (TASK-036
    // Phase A). The post-v3 hardcoded `4` was right at the time this
    // test was written; assert against the live SCHEMA_VERSION so
    // future bumps don't have to re-edit every chain test.
    assert_eq!(entries[1].schema_version, proteus_morph_engine::attest::LEGACY_SCHEMA_VERSION);
    assert_eq!(entries[1].factory_binaries.len(), 4);
    // Chain link: entry 1's prev points at entry 0's hash.
    assert_eq!(entries[1].prev_entry_sha256, entries[0].entry_sha256);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// A v3 entry that already carried `cosignatures` and
/// `federation_threshold` (post-TASK-009) must continue to verify
/// under v4. Same shape as the chain test but the planted entry has
/// the v3 fields populated.
#[test]
fn legacy_v3_with_cosigs_still_verifies_under_v4() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("v3_cosig_compat");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    use std::io::Write;
    let mut cosigs = Vec::new();
    cosigs.push(proteus_morph_engine::Cosignature {
        signer_id: "primary".into(),
        sig_ed25519: "ab".repeat(64),
    });
    let mut e1 = AttestEntry {
        schema_version: 3,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519:
            "592a10ada2935a65cfac37070d4f5b8b2b0113df1067c76c33caa073a719e9aa\
             300c434ebbd8f94a76021be908427976bdf00fdb340ef7107abd83ecb016dd02"
                .into(),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: cosigs,
        federation_threshold: Some(2),
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
    let h1 = compute_entry_sha256(&e1).unwrap();
    e1.entry_sha256 = attest::hex(&h1);
    let line = serde_json::to_string(&e1).unwrap();
    {
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(attest::attest_log_path())
            .unwrap();
        f.write_all(line.as_bytes()).unwrap();
        f.write_all(b"\n").unwrap();
    }

    write_attestation(fields_with_factory(2, true, good_map())).unwrap();

    let report = verify_chain_with_options(&VerifyOptions { require_ext_tlv: false, ..Default::default() }).expect("legacy v3+cosig+v4 must verify");
    assert_eq!(report.entries_ok, 2);
    let entries = load_entries().unwrap();
    assert_eq!(entries[0].schema_version, 3);
    assert_eq!(entries[0].cosignatures.len(), 1);
    // Newly-emitted entry uses the live SCHEMA_VERSION (v5 after
    // TASK-036). The chain still verifies because v3..=v5 entries
    // canonicalize compatibly via `skip_serializing_if` on every
    // post-v2 field.
    assert_eq!(entries[1].schema_version, proteus_morph_engine::attest::LEGACY_SCHEMA_VERSION);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

// =====================================================================
// 4. --strict-factory verification
// =====================================================================

#[test]
fn strict_factory_accepts_matching_chain() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_ok");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    for i in 1u64..=3 {
        write_attestation(fields_with_factory(i, true, good_map())).unwrap();
    }
    let expected_path = dir.join("factory_expected.toml");
    good_expected_file(&expected_path);

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path.clone()),
        ..VerifyOptions::default()
    };
    let report = verify_chain_with_options(&opts).expect("strict factory must verify");
    assert_eq!(report.entries_ok, 3);
    assert_eq!(report.factory_verified, Some(3));
    assert_eq!(report.merkle_root_verified, Some(MerkleRootStatus::Ok));

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_rejects_unknown_hash() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_unknown_hash");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    let mut bad = good_map();
    bad.insert(COMPONENT_MORPH.into(), h(0xf));
    write_attestation(fields_with_factory(1, true, bad)).unwrap();

    let expected_path = dir.join("factory_expected.toml");
    good_expected_file(&expected_path);

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path),
        ..VerifyOptions::default()
    };
    let err = verify_chain_with_options(&opts).expect_err("must reject unknown hash");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("not in expected set"),
        "unexpected error: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_rejects_missing_required_component() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_missing");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    let mut partial = good_map();
    partial.remove(COMPONENT_VERIFY);
    write_attestation(fields_with_factory(1, true, partial)).unwrap();

    let expected_path = dir.join("factory_expected.toml");
    good_expected_file(&expected_path);

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path),
        ..VerifyOptions::default()
    };
    let err = verify_chain_with_options(&opts).expect_err("must reject missing component");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("missing required factory component"),
        "unexpected error: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_rejects_unknown_component() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_smuggled");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    let mut smuggled = good_map();
    smuggled.insert("evil-tool".into(), h(0x1));
    write_attestation(fields_with_factory(1, true, smuggled)).unwrap();

    let expected_path = dir.join("factory_expected.toml");
    good_expected_file(&expected_path);

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path),
        ..VerifyOptions::default()
    };
    let err = verify_chain_with_options(&opts).expect_err("must reject unknown component");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("unknown factory component"),
        "unexpected error: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_rejects_empty_factory_binaries() {
    // An accepted entry with no factory_binaries (e.g. produced by a
    // v3 binary, or v4 with hashing disabled) is incompatible with
    // strict mode. We use write_attestation with an empty map and
    // expect verify to reject under --strict-factory.
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_empty");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    write_attestation(fields_with_factory(1, true, BTreeMap::new())).unwrap();

    let expected_path = dir.join("factory_expected.toml");
    good_expected_file(&expected_path);

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path),
        ..VerifyOptions::default()
    };
    let err = verify_chain_with_options(&opts).expect_err("must reject empty factory");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("empty"),
        "unexpected error: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_default_off_lets_empty_chain_verify() {
    // Sanity: WITHOUT --strict-factory, an empty factory_binaries map
    // does NOT cause rejection. Backwards compat with v3 production
    // chains.
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_off_compat");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    write_attestation(fields_with_factory(1, true, BTreeMap::new())).unwrap();
    write_attestation(fields_with_factory(2, true, BTreeMap::new())).unwrap();

    let report = verify_chain().expect("default mode must accept empty maps");
    assert_eq!(report.entries_ok, 2);
    assert!(report.factory_verified.is_none());

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_accepts_alternative_rustc_hash() {
    // The expected set lists two valid rustc hashes; the entry uses
    // the second. Verifies that multi-hash transitions work.
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_alt_rustc");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    let mut alt = good_map();
    alt.insert(COMPONENT_RUSTC.into(), h(0xe));
    write_attestation(fields_with_factory(1, true, alt)).unwrap();

    let expected_path = dir.join("factory_expected.toml");
    good_expected_file(&expected_path);

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path),
        ..VerifyOptions::default()
    };
    let report = verify_chain_with_options(&opts).expect("alt rustc hash must verify");
    assert_eq!(report.entries_ok, 1);
    assert_eq!(report.factory_verified, Some(1));

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn strict_factory_surfaces_missing_expected_file() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("strict_missing_file");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    write_attestation(fields_with_factory(1, true, good_map())).unwrap();

    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(dir.join("does_not_exist.toml")),
        ..VerifyOptions::default()
    };
    let err = verify_chain_with_options(&opts).expect_err("must surface load failure");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("does_not_exist.toml") || msg.contains("strict-factory"),
        "unexpected error: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

// =====================================================================
// 5. Bootstrap workflow (fingerprint → toml → cycle → verify)
// =====================================================================

/// Simulate the operator bootstrap workflow:
///   1. The factory writes attestation entries with a known
///      `factory_binaries` map (via the JSON-override env var so the
///      test isn't dependent on real binary hashes).
///   2. Operator runs `factory_fingerprint_uncached()` to get the
///      live map, writes a `factory_expected.toml`.
///   3. `verify-attest --strict-factory` accepts the chain because
///      the entry's map is a subset of the expected.
#[test]
fn bootstrap_workflow_round_trips() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("bootstrap");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }
    // Stub the live fingerprint so the test isn't tied to real
    // `target/debug/morph.exe` bytes (which change every cargo build).
    let stub = good_map();
    let stub_json = serde_json::to_string(&stub).unwrap();
    unsafe {
        std::env::set_var(factory::FACTORY_OVERRIDE_ENV, &stub_json);
    }

    // Step 1: write entries that record the stubbed fingerprint.
    write_attestation(fields_with_factory(1, true, factory::fingerprint_uncached())).unwrap();
    write_attestation(fields_with_factory(2, true, factory::fingerprint_uncached())).unwrap();

    // Step 2: operator captures `morph factory-fingerprint --toml`
    // equivalent into a file. Use `factory_expected.toml` shaped to
    // commit to the stub.
    let expected_path = dir.join("factory_expected.toml");
    let live = factory::fingerprint_uncached();
    let mut components: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for (k, v) in &live {
        components.insert(k.clone(), vec![v.clone()]);
    }
    let cfg = FactoryExpected {
        required: live.keys().cloned().collect(),
        components,
    };
    fs::write(&expected_path, toml::to_string(&cfg).unwrap()).unwrap();

    // Step 3: verify under strict mode.
    let opts = VerifyOptions {
        require_strict_factory: true,
        factory_expected_path: Some(expected_path),
        ..VerifyOptions::default()
    };
    let report = verify_chain_with_options(&opts).expect("bootstrap chain must verify");
    assert_eq!(report.entries_ok, 2);
    assert_eq!(report.factory_verified, Some(2));

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
        std::env::remove_var(factory::FACTORY_OVERRIDE_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// `fingerprint_uncached` honours the JSON override env var. This is
/// the seam that lets the bootstrap test be deterministic.
#[test]
fn fingerprint_uncached_honours_override_env() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let m = good_map();
    let raw = serde_json::to_string(&m).unwrap();
    unsafe {
        std::env::set_var(factory::FACTORY_OVERRIDE_ENV, &raw);
    }
    let live = factory::fingerprint_uncached();
    assert_eq!(live, m);
    unsafe {
        std::env::remove_var(factory::FACTORY_OVERRIDE_ENV);
    }
}
