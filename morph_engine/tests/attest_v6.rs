//! TASK-031 — integration tests for the v6 attestation schema
//! (`diversifier_log` field).
//!
//! The v6 bump is purely additive: an `Option<DiversifierLog>` whose
//! `None` value is `skip_serializing_if`-omitted from the canonical
//! JSON. The load-bearing properties are:
//!
//! 1. **Backward compat**: a v3 / v4 / v5 entry (no `diversifier_log`
//!    field at all) and a v6 entry with `diversifier_log = None` MUST
//!    hash to the same `entry_sha256`. Otherwise an existing chain
//!    breaks when re-verified under v6 code.
//! 2. **Schema bump asserted**: `SCHEMA_VERSION` must equal 6 and
//!    `READABLE_MIN_SCHEMA` must still equal 3.
//! 3. **Round-trip canonicalisation**: an entry with a populated
//!    `diversifier_log` must serialise to canonical JSON, deserialise
//!    back, and hash to the same `entry_sha256` after the round trip.
//! 4. **Field perturbs the hash**: changing any pad-decision byte or
//!    perturb-decision label must change `entry_sha256`. Otherwise an
//!    attacker who can flip the field would not invalidate the chain.
//! 5. **Sort-order canonicalisation**: two `DiversifierLog`s built from
//!    the same `(key, value)` pairs inserted in different orders must
//!    produce byte-identical canonical JSON (BTreeMap guarantee).
//! 6. **Mixed v3/v6 chain verifies**: writing one entry with
//!    `diversifier_log = None` and one with `Some(...)` to the same
//!    log produces a chain that `verify_chain` accepts end-to-end.
//! 7. **Empty-but-Some vs None**: `Some(DiversifierLog::default())` is
//!    serialised as `"diversifier_log":{}` and is observably distinct
//!    from `None` (omitted entirely). Pinned because the cycle code
//!    chose `Some(empty)` for paths where the diversifier produced an
//!    empty log; a future refactor that confuses these two would
//!    silently change the entry hash.
//! 8. **End-to-end through `write_attestation` + `verify_chain`** with
//!    a real diversifier log captured from `diversify_with_log`.
//!
//! Env-var isolation mirrors `tests/attest.rs` / `tests/attest_v4.rs` —
//! each integration test gets its own `CUTTLE_ATTEST_DIR`.

use cuttle_morph_engine::attest::{
    self, compute_entry_sha256, load_entries, verify_chain, write_attestation, AttestEntry,
    AttestEntryFields, DiversifierLog, ATTEST_DIR_ENV, READABLE_MIN_SCHEMA, SCHEMA_VERSION,
};
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
        "cuttle_attest_v6_test_{}_{}_{}_{}",
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

fn base_entry(cycle: u64, prev: &str, schema_version: u64) -> AttestEntry {
    AttestEntry {
        schema_version,
        cycle,
        ts_unix: 1_700_000_000 + cycle,
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
        prev_entry_sha256: prev.to_string(),
        entry_sha256: String::new(),
    }
}

fn fields(cycle: u64, accepted: bool) -> AttestEntryFields {
    AttestEntryFields {
        cycle,
        module: "lib".into(),
        candidate_sha256:
            "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8".into(),
        sig_ed25519: "00".repeat(64),
        accepted,
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

// =====================================================================
// 1. Schema bump invariants
// =====================================================================

#[test]
fn schema_version_is_at_least_six() {
    // v6 introduced the diversifier_log (TASK-031); later bumps are
    // additive and forward-compatible, so this is a floor, not an equality
    // (v7 added kernel_layout_seed — see tests below + migrate range).
    assert!(SCHEMA_VERSION >= 6, "v6 diversifier_log floor must hold");
}

/// v7 (Phase 1 codegen diversity): `kernel_layout_seed` is omitted from the
/// canonical JSON when `None` — so v3–v6 entries hash byte-identically under
/// v7 — and is covered by the entry hash when `Some`, so the chain commits
/// to the recorded layout seed.
#[test]
fn kernel_layout_seed_v7_omitted_when_none_and_hashed_when_some() {
    let mut e = base_entry(1, attest::ZERO_HEX, SCHEMA_VERSION);
    assert!(e.kernel_layout_seed.is_none());
    let v_none = serde_json::to_value(&e).unwrap();
    assert!(
        !v_none.as_object().unwrap().contains_key("kernel_layout_seed"),
        "None kernel_layout_seed must be skip_serialized (v6 forward-compat)"
    );
    let h_none = compute_entry_sha256(&e).unwrap();

    e.kernel_layout_seed = Some(0xABCD_1234_5678_9AB);
    let v_some = serde_json::to_value(&e).unwrap();
    assert_eq!(
        v_some.get("kernel_layout_seed").and_then(|x| x.as_u64()),
        Some(0xABCD_1234_5678_9AB)
    );
    let h_some = compute_entry_sha256(&e).unwrap();
    assert_ne!(
        h_none, h_some,
        "the recorded layout seed must be covered by entry_sha256"
    );

    // Round-trips through serde unchanged.
    let back: AttestEntry = serde_json::from_value(v_some).unwrap();
    assert_eq!(back.kernel_layout_seed, Some(0xABCD_1234_5678_9AB));
}

#[test]
fn readable_min_schema_still_three() {
    // The chain reader accepts entries from v3 onward — every schema
    // bump since v3 has been additive (skip_serializing_if-omitted
    // fields), so a v6 binary continues to verify v3/v4/v5 chains.
    assert_eq!(
        READABLE_MIN_SCHEMA, 3,
        "v6 must still read v3+ chains; bump only when a non-additive change lands"
    );
}

// =====================================================================
// 2. Backward-compat — `None` perturbs nothing
// =====================================================================

#[test]
fn v5_shaped_entry_hashes_identically_to_v6_with_none() {
    // The load-bearing property of the v5 -> v6 bump: an entry with
    // `diversifier_log = None` (the default for any cycle without a
    // log to record) must produce byte-identical canonical bytes to a
    // hypothetical v5 entry with the same other fields. Since v5
    // entries are simply v6 entries minus the field, the assertion is
    // "the JSON encoding must not contain a `diversifier_log` key when
    // the field is None".
    let mut e_v5_shape = base_entry(1, attest::ZERO_HEX, 5);
    e_v5_shape.diversifier_log = None;
    let h_v5 = compute_entry_sha256(&e_v5_shape).unwrap();

    let mut e_v6_shape = base_entry(1, attest::ZERO_HEX, 6);
    e_v6_shape.diversifier_log = None;
    // Only the schema_version differs; that ALONE alters the hash.
    // To test the field-omission invariant we keep schema_version
    // equal between the two encodings and compare canonical JSON
    // directly.
    e_v6_shape.schema_version = 5;
    let h_v6_none = compute_entry_sha256(&e_v6_shape).unwrap();
    assert_eq!(
        h_v5, h_v6_none,
        "v6 struct with diversifier_log=None must hash identically to a v5 entry under the same schema_version"
    );

    // Also assert the JSON form omits the key entirely.
    let json = serde_json::to_value(&e_v5_shape).unwrap();
    let obj = json.as_object().unwrap();
    assert!(
        !obj.contains_key("diversifier_log"),
        "diversifier_log must be skip_serializing_if-omitted when None: {:?}",
        obj
    );
}

// =====================================================================
// 3. Field-presence perturbs the hash
// =====================================================================

#[test]
fn diversifier_log_present_perturbs_canonical_hash() {
    // Same entry shape; only difference is diversifier_log = Some(_).
    // The hash MUST differ — otherwise an attacker who flipped the
    // field would not invalidate the chain.
    let base = base_entry(2, attest::ZERO_HEX, SCHEMA_VERSION);
    let h_absent = compute_entry_sha256(&base).unwrap();

    let mut with_log = base.clone();
    let mut log = DiversifierLog::default();
    log.pad_decisions.insert("alpha".into(), 64);
    log.perturb_decisions
        .insert("alpha".into(), "inline-always".into());
    with_log.diversifier_log = Some(log);
    let h_present = compute_entry_sha256(&with_log).unwrap();

    assert_ne!(
        h_absent, h_present,
        "diversifier_log=Some must perturb the canonical hash"
    );
}

#[test]
fn changing_pad_byte_perturbs_hash() {
    // Sensitivity check on the pad bytes value: flipping a single
    // u32 must change the hash. Otherwise the chain doesn't actually
    // commit to the pad decisions.
    let base = base_entry(3, attest::ZERO_HEX, SCHEMA_VERSION);

    let mut e1 = base.clone();
    let mut log1 = DiversifierLog::default();
    log1.pad_decisions.insert("alpha".into(), 64);
    e1.diversifier_log = Some(log1);
    let h1 = compute_entry_sha256(&e1).unwrap();

    let mut e2 = base.clone();
    let mut log2 = DiversifierLog::default();
    log2.pad_decisions.insert("alpha".into(), 65);
    e2.diversifier_log = Some(log2);
    let h2 = compute_entry_sha256(&e2).unwrap();

    assert_ne!(h1, h2, "different pad byte must yield different entry hash");
}

#[test]
fn changing_perturb_label_perturbs_hash() {
    let base = base_entry(4, attest::ZERO_HEX, SCHEMA_VERSION);

    let mut e1 = base.clone();
    let mut log1 = DiversifierLog::default();
    log1.perturb_decisions
        .insert("alpha".into(), "no-attr".into());
    e1.diversifier_log = Some(log1);
    let h1 = compute_entry_sha256(&e1).unwrap();

    let mut e2 = base.clone();
    let mut log2 = DiversifierLog::default();
    log2.perturb_decisions
        .insert("alpha".into(), "inline-never".into());
    e2.diversifier_log = Some(log2);
    let h2 = compute_entry_sha256(&e2).unwrap();

    assert_ne!(
        h1, h2,
        "different perturb label must yield different entry hash"
    );
}

// =====================================================================
// 4. Round-trip canonicalisation
// =====================================================================

#[test]
fn diversifier_log_round_trips_through_serde() {
    let mut e1 = base_entry(5, attest::ZERO_HEX, SCHEMA_VERSION);
    let mut log = DiversifierLog::default();
    // Insert keys out of lexical order to exercise the BTreeMap sort.
    log.pad_decisions.insert("zeta".into(), 200);
    log.pad_decisions.insert("alpha".into(), 32);
    log.pad_decisions.insert("delta".into(), 96);
    log.perturb_decisions
        .insert("zeta".into(), "inline-always".into());
    log.perturb_decisions
        .insert("alpha".into(), "no-attr".into());
    e1.diversifier_log = Some(log);

    let h1 = compute_entry_sha256(&e1).unwrap();

    // serde round-trip via JSON Value.
    let v = serde_json::to_value(&e1).unwrap();
    let e1_round: AttestEntry = serde_json::from_value(v).unwrap();
    let h1_round = compute_entry_sha256(&e1_round).unwrap();
    assert_eq!(h1, h1_round, "round-trip via serde changed the hash");
    assert_eq!(e1.diversifier_log, e1_round.diversifier_log);
}

#[test]
fn insertion_order_does_not_affect_canonical_hash() {
    // Two DiversifierLogs built from the same (k, v) pairs in
    // different orders must hash to the same entry_sha256. BTreeMap
    // guarantees canonical ordering on iteration; the test pins this
    // property at the attestation layer.
    let base = base_entry(6, attest::ZERO_HEX, SCHEMA_VERSION);

    let mut e1 = base.clone();
    let mut log1 = DiversifierLog::default();
    log1.pad_decisions.insert("alpha".into(), 32);
    log1.pad_decisions.insert("beta".into(), 64);
    log1.pad_decisions.insert("gamma".into(), 96);
    log1.perturb_decisions
        .insert("alpha".into(), "no-attr".into());
    log1.perturb_decisions
        .insert("gamma".into(), "inline-always".into());
    e1.diversifier_log = Some(log1);
    let h1 = compute_entry_sha256(&e1).unwrap();

    let mut e2 = base.clone();
    let mut log2 = DiversifierLog::default();
    log2.pad_decisions.insert("gamma".into(), 96);
    log2.pad_decisions.insert("alpha".into(), 32);
    log2.pad_decisions.insert("beta".into(), 64);
    log2.perturb_decisions
        .insert("gamma".into(), "inline-always".into());
    log2.perturb_decisions
        .insert("alpha".into(), "no-attr".into());
    e2.diversifier_log = Some(log2);
    let h2 = compute_entry_sha256(&e2).unwrap();

    assert_eq!(
        h1, h2,
        "insertion-order must not affect canonical hash (BTreeMap canonicalisation)"
    );
}

// =====================================================================
// 5. Empty-but-Some vs None
// =====================================================================

#[test]
fn some_empty_log_is_distinct_from_none() {
    // Important: `Some(DiversifierLog::default())` must NOT collapse
    // to `None` in canonical JSON. The skip_serializing_if applies
    // only at the top-level `Option`; an empty inner log serialises
    // as `"diversifier_log":{}` (the inner BTreeMaps themselves skip
    // their empty values). The outer Some/None distinction is
    // preserved.
    let base = base_entry(7, attest::ZERO_HEX, SCHEMA_VERSION);

    let mut e_none = base.clone();
    e_none.diversifier_log = None;
    let h_none = compute_entry_sha256(&e_none).unwrap();

    let mut e_some_empty = base.clone();
    e_some_empty.diversifier_log = Some(DiversifierLog::default());
    let h_some_empty = compute_entry_sha256(&e_some_empty).unwrap();

    assert_ne!(
        h_none, h_some_empty,
        "Some(empty) must be distinguishable from None at the canonical-JSON level"
    );

    // The Some(empty) serialisation must contain the key with an
    // empty object value.
    let v = serde_json::to_value(&e_some_empty).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        obj.contains_key("diversifier_log"),
        "Some(empty) must serialise the diversifier_log key"
    );
    assert!(
        obj.get("diversifier_log").unwrap().as_object().unwrap().is_empty(),
        "Some(empty) must serialise as an empty object"
    );
}

// =====================================================================
// 6. End-to-end via write_attestation + verify_chain
// =====================================================================

#[test]
fn mixed_none_and_some_entries_verify_in_one_chain() {
    let g = EnvGuard::new("mixed_chain");
    let _ = &g;

    // Entry 1: no diversifier log (legacy-shaped).
    let mut f1 = fields(1, true);
    f1.diversifier_log = None;
    write_attestation(f1).unwrap();

    // Entry 2: populated diversifier log.
    let mut f2 = fields(2, true);
    let mut log = DiversifierLog::default();
    log.pad_decisions.insert("alpha".into(), 64);
    log.pad_decisions.insert("beta".into(), 96);
    log.perturb_decisions
        .insert("alpha".into(), "inline-always".into());
    log.perturb_decisions
        .insert("beta".into(), "no-attr".into());
    f2.diversifier_log = Some(log);
    write_attestation(f2).unwrap();

    // Entry 3: empty Some — exercises the Some(empty) path.
    let mut f3 = fields(3, true);
    f3.diversifier_log = Some(DiversifierLog::default());
    write_attestation(f3).unwrap();

    let report = verify_chain().expect("v6 chain must verify");
    assert_eq!(report.entries_ok, 3);

    let entries = load_entries().unwrap();
    assert!(entries[0].diversifier_log.is_none());
    assert!(entries[1].diversifier_log.is_some());
    assert!(entries[2]
        .diversifier_log
        .as_ref()
        .map(|l| l.is_empty())
        .unwrap_or(false));
}

#[test]
fn diversifier_log_from_real_diversifier_round_trips() {
    // End-to-end: capture a log from the real diversifier and assert
    // it survives the attestation round-trip without losing fidelity.
    const FIXTURE: &str = r#"
        fn helper() { let x = 1; let _ = x; }
        pub fn entry() { helper(); }
    "#;
    let seed = cuttle_diversifier::Seed::derive(42, "v6_test");
    let (_candidate, raw_log) =
        cuttle_diversifier::diversify_with_log(FIXTURE, &seed).expect("diversify");
    let attest_log = attest::diversifier_log_from(&raw_log);
    assert!(
        !attest_log.is_empty(),
        "fixture should produce non-empty log"
    );

    let mut e = base_entry(99, attest::ZERO_HEX, SCHEMA_VERSION);
    e.diversifier_log = Some(attest_log.clone());
    let h_pre = compute_entry_sha256(&e).unwrap();

    let json = serde_json::to_string(&e).unwrap();
    let e_back: AttestEntry = serde_json::from_str(&json).unwrap();
    let h_post = compute_entry_sha256(&e_back).unwrap();

    assert_eq!(h_pre, h_post);
    assert_eq!(e_back.diversifier_log.unwrap(), attest_log);
}

#[test]
fn diversifier_log_helpers_match_implementation() {
    let mut log = DiversifierLog::default();
    assert!(log.is_empty());
    log.pad_decisions.insert("foo".into(), 64);
    assert!(!log.is_empty());
    log.pad_decisions.remove("foo");
    log.perturb_decisions.insert("foo".into(), "no-attr".into());
    assert!(!log.is_empty());
}
