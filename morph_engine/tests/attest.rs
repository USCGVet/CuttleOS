//! Integration tests for the v2 attestation log (hash chain + Merkle
//! anchors).
//!
//! Each test isolates itself via `CUTTLE_ATTEST_DIR` pointing at a fresh
//! per-test tempdir. We serialize tests that touch the env var with a
//! mutex so parallel `cargo test` workers don't stomp on each other.

use cuttle_morph_engine::attest::{
    self, compute_entry_sha256, compute_merkle_root, load_anchors, load_entries, parse_hex32,
    verify_chain, write_attestation, AttestEntry, AttestEntryFields, ANCHOR_INTERVAL,
    ATTEST_DIR_ENV, SCHEMA_VERSION,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

// All tests set the same env var. Serialize so they don't race.
static ENV_LOCK: Mutex<()> = Mutex::new(());

fn fresh_tempdir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "cuttle_attest_test_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn fields(cycle: u64, accepted: bool) -> AttestEntryFields {
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

/// Build a synthetic entry without going through write_attestation
/// (useful for the determinism test where we want to pin all fields
/// including `ts_unix`).
fn fixed_entry(cycle: u64, prev: &str) -> AttestEntry {
    AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle,
        ts_unix: 1_700_000_000 + cycle,
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
        factory_binaries: std::collections::BTreeMap::new(),
        bundle_name: None,
        modules: std::collections::BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: prev.to_string(),
        entry_sha256: String::new(),
    }
}

#[test]
fn entry_hash_is_deterministic() {
    let e1 = fixed_entry(1, attest::ZERO_HEX);
    let e2 = fixed_entry(1, attest::ZERO_HEX);
    let h1 = compute_entry_sha256(&e1).unwrap();
    let h2 = compute_entry_sha256(&e2).unwrap();
    assert_eq!(h1, h2, "same fields must produce same entry_sha256");

    // Changing any field changes the hash.
    let mut e3 = fixed_entry(1, attest::ZERO_HEX);
    e3.cycle = 2;
    let h3 = compute_entry_sha256(&e3).unwrap();
    assert_ne!(h1, h3, "differing cycle must yield different hash");
}

#[test]
fn merkle_root_is_deterministic() {
    let mut leaves = Vec::new();
    for i in 0u8..10 {
        let mut leaf = [0u8; 32];
        leaf[0] = i;
        leaves.push(leaf);
    }
    let r1 = compute_merkle_root(&leaves);
    let r2 = compute_merkle_root(&leaves);
    assert_eq!(r1, r2, "merkle root must be deterministic");

    // Swapping leaves changes the root.
    let mut shuffled = leaves.clone();
    shuffled.swap(0, 1);
    let r3 = compute_merkle_root(&shuffled);
    assert_ne!(r1, r3, "reordered leaves must yield different root");
}

#[test]
fn merkle_padding_handles_odd_layer() {
    // An odd-length set (3) exercises the duplicate-last-node padding.
    let mut leaves = Vec::new();
    for i in 0u8..3 {
        let mut leaf = [0u8; 32];
        leaf[0] = i;
        leaves.push(leaf);
    }
    let r = compute_merkle_root(&leaves);
    // Must equal hand-computed value: H(H(L0||L1) || H(L2||L2)).
    use sha2::{Digest, Sha256};
    let mut h01 = Sha256::new();
    h01.update(leaves[0]);
    h01.update(leaves[1]);
    let h01: [u8; 32] = h01.finalize().into();
    let mut h22 = Sha256::new();
    h22.update(leaves[2]);
    h22.update(leaves[2]);
    let h22: [u8; 32] = h22.finalize().into();
    let mut top = Sha256::new();
    top.update(h01);
    top.update(h22);
    let expected: [u8; 32] = top.finalize().into();
    assert_eq!(r, expected);
}

#[test]
fn write_and_verify_three_entries() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("happy");
    // SAFETY: tests serialized via ENV_LOCK; no concurrent env reads.
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    write_attestation(fields(1, true)).unwrap();
    write_attestation(fields(2, true)).unwrap();
    write_attestation(fields(3, false)).unwrap();

    let report = verify_chain().expect("verify on good log");
    assert_eq!(report.entries_ok, 3);
    assert_eq!(report.anchors_ok, 0); // no anchor yet — under 10 entries

    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].prev_entry_sha256, attest::ZERO_HEX);
    assert_eq!(entries[1].prev_entry_sha256, entries[0].entry_sha256);
    assert_eq!(entries[2].prev_entry_sha256, entries[1].entry_sha256);
    for e in &entries {
        // fields() passes signing_key: None → legacy-mint schema.
        assert_eq!(e.schema_version, attest::LEGACY_SCHEMA_VERSION);
    }

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn chain_breaks_on_modified_entry() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("modify");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }
    write_attestation(fields(1, true)).unwrap();
    write_attestation(fields(2, true)).unwrap();
    write_attestation(fields(3, true)).unwrap();

    // Rewrite the middle entry on disk with one byte of candidate_sha256
    // flipped. This invalidates entry[1]'s entry_sha256 hash AND breaks
    // entry[2]'s prev link, so verify must fail.
    let path = attest::attest_log_path();
    let raw = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
    lines[1] = lines[1].replace("39b94ac8", "39b94ac9");
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = verify_chain().expect_err("must detect modification");
    let msg = format!("{:#}", err);
    // We expect the failure to point at entry index 1 (the modified one).
    assert!(
        msg.contains("entry 1") && msg.contains("corrupted entry_sha256"),
        "unexpected failure message: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn chain_breaks_on_reordered_entries() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("reorder");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }
    write_attestation(fields(1, true)).unwrap();
    write_attestation(fields(2, true)).unwrap();
    write_attestation(fields(3, true)).unwrap();

    // Swap lines 1 and 2 on disk. Line 0 remains the genuine genesis
    // entry. Line 1 is now the OLD entry 2, whose own entry_sha256 is
    // self-consistent (so the hash check passes) but whose
    // prev_entry_sha256 points at OLD entry 1, not OLD entry 0 — chain
    // break at index 1.
    let path = attest::attest_log_path();
    let raw = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
    lines.swap(1, 2);
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = verify_chain().expect_err("must detect reorder");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("entry 1") && msg.contains("chain break"),
        "unexpected failure message: {}",
        msg
    );

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn anchor_emitted_every_10_entries() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("anchor");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }
    for i in 1u64..=25 {
        write_attestation(fields(i, true)).unwrap();
    }
    let anchors = load_anchors().unwrap();
    assert_eq!(
        anchors.len(),
        2,
        "expected exactly 2 anchors after 25 entries (covering 0..=9 and 10..=19); got {}",
        anchors.len()
    );
    assert_eq!(anchors[0].first_entry, 0);
    assert_eq!(anchors[0].last_entry, ANCHOR_INTERVAL - 1);
    assert_eq!(anchors[0].anchor_index, 0);
    assert_eq!(anchors[0].prev_anchor_merkle_root, attest::ZERO_HEX);
    assert_eq!(anchors[1].first_entry, ANCHOR_INTERVAL);
    assert_eq!(anchors[1].last_entry, 2 * ANCHOR_INTERVAL - 1);
    assert_eq!(anchors[1].anchor_index, 1);
    assert_eq!(anchors[1].prev_anchor_merkle_root, anchors[0].merkle_root);

    // Sanity: recomputing merkle root from the entries should match.
    let entries = load_entries().unwrap();
    let leaves: Vec<[u8; 32]> = entries[0..10]
        .iter()
        .map(|e| parse_hex32(&e.entry_sha256).unwrap())
        .collect();
    let root = compute_merkle_root(&leaves);
    assert_eq!(attest::hex(&root), anchors[0].merkle_root);

    // Full verify should still pass.
    let report = verify_chain().expect("verify ok");
    assert_eq!(report.entries_ok, 25);
    assert_eq!(report.anchors_ok, 2);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn verify_attest_passes_on_good_log() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("good");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }
    for i in 1u64..=5 {
        write_attestation(fields(i, true)).unwrap();
    }
    let report = verify_chain().expect("clean log must verify");
    assert_eq!(report.entries_ok, 5);
    assert_eq!(report.anchors_ok, 0);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn v1_log_is_migrated_aside() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("migrate");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }
    // Plant a v1-shape log (no schema_version, no entry_sha256).
    let v1_line = r#"{"cycle":1,"ts_unix":1700000000,"module":"lib","candidate_sha256":"39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8","sig_ed25519":"00","accepted":true,"synthesizer":"passthrough"}"#;
    fs::write(attest::attest_log_path(), format!("{}\n", v1_line)).unwrap();

    // First v2 write must migrate the v1 log aside and start fresh.
    write_attestation(fields(2, true)).unwrap();

    let bak = dir.join(attest::ATTEST_LOG_V1_BAK);
    assert!(
        bak.exists(),
        "expected v1 backup at {}",
        bak.display()
    );

    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 1, "fresh v2 log starts at one entry");
    assert_eq!(entries[0].cycle, 2);
    assert_eq!(entries[0].prev_entry_sha256, attest::ZERO_HEX);
    assert_eq!(entries[0].schema_version, attest::LEGACY_SCHEMA_VERSION);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}

/// `image_sha256` is the TASK-003 add. It must:
///   1. Round-trip through canonical-JSON encoding (so the entry hash
///      is stable across read-write cycles).
///   2. Be omitted from canonical JSON when `None` (so legacy entries
///      that pre-date the field continue to hash to the same value
///      they did before — i.e. zero schema bump).
///   3. Not break chain verification regardless of whether successive
///      entries do or do not set the field.
#[test]
fn image_sha256_absent_does_not_perturb_canonical_hash() {
    // Construct two structurally identical entries — one constructed
    // with explicit `image_sha256: None`, one constructed via the
    // legacy-shaped fields() helper (which sets it to None too). Both
    // must hash to the same entry_sha256 because the field is omitted
    // when None.
    let e1 = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 7,
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
        factory_binaries: std::collections::BTreeMap::new(),
        bundle_name: None,
        modules: std::collections::BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: attest::ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    let h1 = compute_entry_sha256(&e1).unwrap();

    // Build an identical entry but go via serialize→deserialize, which
    // exercises the serde path: deserialization of a JSON object that
    // *omits* `image_sha256` must yield `None`.
    let v = serde_json::to_value(&e1).unwrap();
    let obj = v.as_object().unwrap();
    assert!(
        !obj.contains_key("image_sha256"),
        "image_sha256 must be skip_serializing when None, got: {:?}",
        obj
    );
    let e1_round: AttestEntry = serde_json::from_value(v).unwrap();
    let h1_round = compute_entry_sha256(&e1_round).unwrap();
    assert_eq!(h1, h1_round, "round-trip via serde changed the hash");
}

#[test]
fn image_sha256_present_perturbs_canonical_hash() {
    // Same entry shape; only difference is image_sha256 = Some(_). The
    // hash MUST differ — otherwise an attacker who can flip the field
    // wouldn't invalidate the chain.
    let base = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 8,
        ts_unix: 1_700_000_001,
        module: "target_enterprise".into(),
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
        factory_binaries: std::collections::BTreeMap::new(),
        bundle_name: None,
        modules: std::collections::BTreeMap::new(),
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: attest::ZERO_HEX.to_string(),
        entry_sha256: String::new(),
    };
    let h_absent = compute_entry_sha256(&base).unwrap();

    let mut with_image = base.clone();
    with_image.image_sha256 = Some(
        "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".to_string(),
    );
    let h_present = compute_entry_sha256(&with_image).unwrap();
    assert_ne!(h_absent, h_present, "image_sha256 change must shift hash");

    // And canonical JSON for the with-image variant must contain the
    // key — confirm we're not accidentally skipping it.
    let v = serde_json::to_value(&with_image).unwrap();
    let obj = v.as_object().unwrap();
    assert!(obj.contains_key("image_sha256"));
}

#[test]
fn chain_verifies_with_mixed_image_field_presence() {
    let _g = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
    let dir = fresh_tempdir("imgmix");
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &dir);
    }

    // Entry 0: no image. Entry 1: image set. Entry 2: no image again.
    // verify_chain() must accept all three — image_sha256 is purely
    // additive metadata, not a chain-link primitive.
    let mut f0 = fields(1, true);
    f0.image_sha256 = None;
    write_attestation(f0).unwrap();

    let mut f1 = fields(2, true);
    f1.image_sha256 = Some(
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".into(),
    );
    write_attestation(f1).unwrap();

    let mut f2 = fields(3, true);
    f2.image_sha256 = None;
    write_attestation(f2).unwrap();

    let report = verify_chain().expect("chain must verify across mixed presence");
    assert_eq!(report.entries_ok, 3);

    let entries = load_entries().unwrap();
    assert_eq!(entries[0].image_sha256, None);
    assert_eq!(
        entries[1].image_sha256.as_deref(),
        Some("0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef")
    );
    assert_eq!(entries[2].image_sha256, None);

    unsafe {
        std::env::remove_var(ATTEST_DIR_ENV);
    }
    let _ = fs::remove_dir_all(&dir);
}
