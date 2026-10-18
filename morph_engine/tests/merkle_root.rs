//! TASK-013 integration tests: the rolling Merkle root sidecar
//! (`attest.merkle_root`).
//!
//! Each test isolates itself via `CUTTLE_ATTEST_DIR` pointing at a
//! fresh per-test tempdir. The env var is shared process-wide, so all
//! tests in this file serialise on a module-local mutex — matches the
//! pattern used by `tests/attest.rs`.

use cuttle_morph_engine::attest::{
    self, compute_merkle_root, load_entries, load_merkle_root, parse_hex32,
    recompute_merkle_root_from_disk, verify_chain, verify_chain_with_options,
    write_attestation, write_merkle_root, AttestEntryFields, MerkleRootStatus, VerifyOptions,
    ATTEST_DIR_ENV, ATTEST_MERKLE_ROOT, MERKLE_ROOT_SCHEMA_VERSION, SCHEMA_VERSION,
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
        "cuttle_merkle_test_{}_{}_{}_{}",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

fn fields(cycle: u64) -> AttestEntryFields {
    AttestEntryFields {
        cycle,
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
    signing_key: None,
    }
}

/// Establish per-test isolation. The returned guard sets the env var
/// on construction and clears it on drop, ensuring later tests don't
/// inherit it even if this test panics.
struct EnvGuard {
    _lock: std::sync::MutexGuard<'static, ()>,
    dir: PathBuf,
}

impl EnvGuard {
    fn new(label: &str) -> Self {
        let lock = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let dir = fresh_tempdir(label);
        // SAFETY: tests serialised via ENV_LOCK; no concurrent env reads.
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

// ---------------------------------------------------------------------------
// Determinism + write-side
// ---------------------------------------------------------------------------

#[test]
fn rolling_root_is_written_after_first_append() {
    let g = EnvGuard::new("write_first");
    let sidecar = g.dir.join(ATTEST_MERKLE_ROOT);
    assert!(!sidecar.exists(), "no sidecar before any append");

    write_attestation(fields(1)).unwrap();
    let stored = load_merkle_root().unwrap().expect("sidecar must exist");
    assert_eq!(stored.schema_version, MERKLE_ROOT_SCHEMA_VERSION);
    assert_eq!(stored.entry_schema_version, SCHEMA_VERSION);
    assert_eq!(stored.entry_count, 1);
    let entries = load_entries().unwrap();
    assert_eq!(stored.last_entry_sha256, entries[0].entry_sha256);
    assert_eq!(stored.merkle_root, entries[0].entry_sha256, "1-leaf root == leaf");
}

#[test]
fn rolling_root_is_deterministic_across_recompute() {
    let _g = EnvGuard::new("deterministic");
    for i in 1u64..=7 {
        write_attestation(fields(i)).unwrap();
    }
    let before = load_merkle_root().unwrap().unwrap();
    // Recompute from disk; result must be byte-identical (modulo
    // timestamp).
    let after = recompute_merkle_root_from_disk().unwrap();
    assert_eq!(before.entry_count, after.entry_count);
    assert_eq!(before.last_entry_sha256, after.last_entry_sha256);
    assert_eq!(before.merkle_root, after.merkle_root);
    assert_eq!(before.entry_schema_version, after.entry_schema_version);
}

#[test]
fn rolling_root_matches_compute_merkle_root_helper() {
    // The rolling root and the chunked-anchor helper must agree on
    // the same leaf set. This is the cross-check that prevents a
    // future refactor from accidentally introducing two different
    // tree shapes.
    let _g = EnvGuard::new("cross_check");
    for i in 1u64..=6 {
        write_attestation(fields(i)).unwrap();
    }
    let entries = load_entries().unwrap();
    let leaves: Vec<[u8; 32]> = entries
        .iter()
        .map(|e| parse_hex32(&e.entry_sha256).unwrap())
        .collect();
    let expected = attest::hex(&compute_merkle_root(&leaves));
    let stored = load_merkle_root().unwrap().unwrap();
    assert_eq!(stored.merkle_root, expected);
}

#[test]
fn rolling_root_updates_on_each_append() {
    let _g = EnvGuard::new("each_append");
    let mut prev_root: Option<String> = None;
    for i in 1u64..=5 {
        write_attestation(fields(i)).unwrap();
        let stored = load_merkle_root().unwrap().unwrap();
        assert_eq!(stored.entry_count, i, "entry_count must track");
        if let Some(p) = &prev_root {
            assert_ne!(
                p, &stored.merkle_root,
                "rolling root must shift on every append (cycle {})",
                i
            );
        }
        prev_root = Some(stored.merkle_root);
    }
}

// ---------------------------------------------------------------------------
// Verify path
// ---------------------------------------------------------------------------

#[test]
fn verify_chain_reports_rolling_root_ok() {
    let _g = EnvGuard::new("verify_ok");
    for i in 1u64..=4 {
        write_attestation(fields(i)).unwrap();
    }
    let report = verify_chain().expect("clean log must verify");
    assert_eq!(report.entries_ok, 4);
    assert_eq!(report.merkle_root_verified, Some(MerkleRootStatus::Ok));
}

#[test]
fn verify_chain_legacy_log_reports_absent_when_not_required() {
    let _g = EnvGuard::new("absent_legacy");
    for i in 1u64..=3 {
        write_attestation(fields(i)).unwrap();
    }
    // Simulate a pre-TASK-013 factory: delete the sidecar but keep
    // the attest log. verify_chain() must still pass and surface the
    // Absent status.
    fs::remove_file(attest::merkle_root_path()).unwrap();
    let report = verify_chain().expect("legacy log must verify without sidecar");
    assert_eq!(report.entries_ok, 3);
    assert_eq!(report.merkle_root_verified, Some(MerkleRootStatus::Absent));
}

#[test]
fn verify_chain_rejects_when_sidecar_required_but_absent() {
    let _g = EnvGuard::new("require_absent");
    for i in 1u64..=3 {
        write_attestation(fields(i)).unwrap();
    }
    fs::remove_file(attest::merkle_root_path()).unwrap();
    let err = verify_chain_with_options(&VerifyOptions {
        require_threshold: false,
        federation_config: None,
        require_merkle_root: true,
        require_strict_factory: false,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    })
    .expect_err("require_merkle_root must fail on missing sidecar");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("missing") && msg.contains(ATTEST_MERKLE_ROOT),
        "unexpected error: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Tamper detection — covers the TASK-013 "first / middle / last" matrix.
// Each test independently writes 5 entries (more than enough to expose
// every tamper position) then mutates exactly the targeted entry.
// ---------------------------------------------------------------------------

fn write_five_entries() {
    for i in 1u64..=5 {
        write_attestation(fields(i)).unwrap();
    }
}

/// Tamper helper: rewrite the entry log so line `idx` has the first
/// occurrence of `from` replaced by `to`. Leaves the rolling-root
/// sidecar untouched so `verify-attest` sees a "stored root says X,
/// log produces Y" inconsistency.
fn tamper_byte(idx: usize, from: &str, to: &str) {
    let path = attest::attest_log_path();
    let raw = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
    let line = &mut lines[idx];
    let pos = line.find(from).expect("from-substr not found");
    line.replace_range(pos..pos + from.len(), to);
    fs::write(&path, lines.join("\n") + "\n").unwrap();
}

#[test]
fn tamper_first_entry_caught_by_rolling_root() {
    let _g = EnvGuard::new("tamper_first");
    write_five_entries();
    // The first entry's own hash check WILL also fail — but that's
    // fine; verify_chain is allowed to surface either bound. We just
    // assert it does not pass.
    tamper_byte(0, "39b94ac8", "39b94ac9");
    let err = verify_chain().expect_err("first-entry tamper must be detected");
    let msg = format!("{:#}", err);
    // verify_chain hits the entry-hash check first for index 0; the
    // exact wording is "corrupted entry_sha256". The point is that
    // verify-attest exits non-zero on a tampered log.
    assert!(
        msg.contains("entry 0") || msg.contains("rolling-root"),
        "expected first-entry failure, got: {}",
        msg
    );
}

#[test]
fn tamper_middle_entry_caught() {
    let _g = EnvGuard::new("tamper_middle");
    write_five_entries();
    tamper_byte(2, "39b94ac8", "39b94ac9");
    let err = verify_chain().expect_err("middle-entry tamper must be detected");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("entry 2") || msg.contains("rolling-root"),
        "expected middle-entry failure, got: {}",
        msg
    );
}

#[test]
fn tamper_last_entry_caught_via_rolling_root() {
    let _g = EnvGuard::new("tamper_last");
    write_five_entries();
    // Flip a byte in the last line's candidate_sha256.
    tamper_byte(4, "39b94ac8", "39b94ac9");
    let err = verify_chain().expect_err("last-entry tamper must be detected");
    let msg = format!("{:#}", err);
    // The last entry's hash check catches it; the rolling-root would
    // catch it too if the entry-hash check passed. Either failure
    // suffices.
    assert!(
        msg.contains("entry 4") || msg.contains("rolling-root"),
        "expected last-entry failure, got: {}",
        msg
    );
}

#[test]
fn rolling_root_catches_tamper_when_chain_was_recomputed() {
    // This is the "purest" TASK-013 test: the attacker has
    // **also** recomputed each entry's `entry_sha256` and the chain
    // links so the per-entry hash / chain checks all pass. The
    // rolling-root sidecar is the only thing keeping them honest.
    let _g = EnvGuard::new("rolling_only");
    write_five_entries();
    let stored_root = load_merkle_root().unwrap().unwrap().merkle_root.clone();

    // Load entries, mutate the middle one (cycle), re-hash the chain,
    // and rewrite. We deliberately do NOT call `write_merkle_root`
    // afterwards — that's the attacker's mistake.
    let mut entries = load_entries().unwrap();
    entries[2].cycle = 9999;
    // Keep ext_tlv_b64 consistent with the mutated cycle so the
    // TASK-102 TLV check does not fire first — this test isolates
    // rolling-root detection after a fully re-hashed chain rewrite.
    entries[2].ext_tlv_b64 = Some(
        cuttle_morph_engine::build_ext_tlv_b64(
            entries[2].cycle,
            &entries[2].module,
            &entries[2].candidate_sha256,
        )
        .unwrap(),
    );
    attest::rebuild_chain_after_cosign(&mut entries, 2).unwrap();
    let mut anchors = attest::load_anchors().unwrap();
    // We have only 5 entries; no anchors yet. But just in case future
    // ANCHOR_INTERVAL changes, run the helper.
    attest::rebuild_anchors_after_cosign(&entries, &mut anchors, 2).unwrap();
    // Manually write the chain *without* updating the sidecar.
    let log = attest::attest_log_path();
    let mut content = String::new();
    for e in &entries {
        content.push_str(&serde_json::to_string(e).unwrap());
        content.push('\n');
    }
    fs::write(&log, content).unwrap();
    // Re-verify: sidecar still holds the original root; the chain on
    // disk produces a different root. Mismatch must surface.
    let err = verify_chain().expect_err("rolling-root mismatch must be detected");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("rolling-root mismatch") || msg.contains("last_entry_sha256"),
        "expected rolling-root failure (entries hand-recomputed), got: {}",
        msg
    );
    // Sanity: the stored root we expected to mismatch is the one in
    // the sidecar.
    let still_stored = load_merkle_root().unwrap().unwrap();
    assert_eq!(still_stored.merkle_root, stored_root);
}

#[test]
fn rolling_root_catches_truncated_log() {
    // Attacker deletes the last entry but leaves the sidecar in
    // place. Per-entry checks all pass (entries 0..=3 are unchanged)
    // but the sidecar's entry_count and merkle_root no longer match.
    let _g = EnvGuard::new("truncate");
    write_five_entries();
    let path = attest::attest_log_path();
    let raw = fs::read_to_string(&path).unwrap();
    let mut lines: Vec<String> = raw.lines().map(|s| s.to_string()).collect();
    lines.pop();
    fs::write(&path, lines.join("\n") + "\n").unwrap();

    let err = verify_chain().expect_err("truncated log must be detected");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("entry_count")
            || msg.contains("rolling-root")
            || msg.contains("last_entry_sha256"),
        "expected entry-count mismatch, got: {}",
        msg
    );
}

// ---------------------------------------------------------------------------
// Edge cases
// ---------------------------------------------------------------------------

#[test]
fn empty_log_handled_by_explicit_recompute() {
    // No entries written. recompute_merkle_root_from_disk is the
    // canonical way to materialise an empty-log sidecar.
    let _g = EnvGuard::new("empty_recompute");
    assert!(load_entries().unwrap().is_empty());
    let f = recompute_merkle_root_from_disk().unwrap();
    assert_eq!(f.entry_count, 0);
    assert_eq!(f.merkle_root, attest::ZERO_HEX);
    assert_eq!(f.last_entry_sha256, attest::ZERO_HEX);

    // verify_chain on empty log + empty sidecar passes.
    let report = verify_chain().unwrap();
    assert_eq!(report.entries_ok, 0);
    assert_eq!(report.merkle_root_verified, Some(MerkleRootStatus::Ok));
}

#[test]
fn single_entry_root_equals_entry_hash() {
    let _g = EnvGuard::new("single");
    write_attestation(fields(42)).unwrap();
    let stored = load_merkle_root().unwrap().unwrap();
    let entries = load_entries().unwrap();
    assert_eq!(entries.len(), 1);
    // A 1-leaf Merkle root is the leaf itself.
    assert_eq!(stored.merkle_root, entries[0].entry_sha256);
    assert_eq!(stored.entry_count, 1);
    assert_eq!(verify_chain().unwrap().merkle_root_verified, Some(MerkleRootStatus::Ok));
}

#[test]
fn rolling_root_survives_restart_round_trip() {
    // The "restart" simulation: write some entries, drop everything
    // we hold in memory (load_merkle_root will re-read from disk),
    // re-verify.
    let _g = EnvGuard::new("restart");
    for i in 1u64..=8 {
        write_attestation(fields(i)).unwrap();
    }
    let pre = load_merkle_root().unwrap().unwrap();

    // Simulate restart by clearing any in-memory state we control
    // (there is none — but the load is now identical to a fresh
    // process). Reload and re-verify.
    let post = load_merkle_root().unwrap().unwrap();
    assert_eq!(pre.merkle_root, post.merkle_root);
    assert_eq!(pre.entry_count, post.entry_count);
    assert_eq!(pre.last_entry_sha256, post.last_entry_sha256);
    assert_eq!(verify_chain().unwrap().merkle_root_verified, Some(MerkleRootStatus::Ok));
}

#[test]
fn schema_v3_compatibility_round_trip() {
    // Mixed image_sha256 / cosignatures presence — exactly the v3
    // surface — must round-trip through the rolling root without
    // perturbing equality. This guards against the v3 entry shape
    // canonically-hashing to one value at write time and a different
    // value at verify time (the exact bug class image_sha256 nearly
    // hit in TASK-003).
    let _g = EnvGuard::new("schema_v3");

    let mut f0 = fields(1);
    f0.image_sha256 = None;
    write_attestation(f0).unwrap();

    let mut f1 = fields(2);
    f1.image_sha256 = Some(
        "deadbeefcafebabedeadbeefcafebabedeadbeefcafebabedeadbeefcafebabe".into(),
    );
    f1.federation_threshold = Some(2);
    write_attestation(f1).unwrap();

    let mut f2 = fields(3);
    f2.image_sha256 = None;
    write_attestation(f2).unwrap();

    let report = verify_chain().expect("v3 mixed-presence log must verify");
    assert_eq!(report.entries_ok, 3);
    assert_eq!(report.merkle_root_verified, Some(MerkleRootStatus::Ok));

    let stored = load_merkle_root().unwrap().unwrap();
    assert_eq!(stored.entry_schema_version, SCHEMA_VERSION);
    assert_eq!(stored.entry_count, 3);
}

#[test]
fn rolling_root_rejects_sidecar_with_wrong_entry_count() {
    // Operator manually corrupts the sidecar (count off by one). The
    // recompute would otherwise quietly pass — we explicitly assert
    // the entry_count guard catches this before the root comparison.
    let _g = EnvGuard::new("wrong_count");
    for i in 1u64..=3 {
        write_attestation(fields(i)).unwrap();
    }
    // Read sidecar, increment entry_count, write back via raw fs.
    let mut stored = load_merkle_root().unwrap().unwrap();
    stored.entry_count += 1;
    let raw = serde_json::to_string(&stored).unwrap();
    fs::write(attest::merkle_root_path(), raw + "\n").unwrap();

    let err = verify_chain().expect_err("entry_count tamper must be caught");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("entry_count"),
        "expected entry_count error, got: {}",
        msg
    );
}

#[test]
fn rolling_root_rejects_sidecar_with_wrong_root() {
    // Same kind of manual corruption, but on the merkle_root field.
    let _g = EnvGuard::new("wrong_root");
    for i in 1u64..=4 {
        write_attestation(fields(i)).unwrap();
    }
    let mut stored = load_merkle_root().unwrap().unwrap();
    // Flip a hex char in the recorded root.
    let mut chars: Vec<char> = stored.merkle_root.chars().collect();
    chars[0] = if chars[0] == 'a' { 'b' } else { 'a' };
    stored.merkle_root = chars.iter().collect();
    let raw = serde_json::to_string(&stored).unwrap();
    fs::write(attest::merkle_root_path(), raw + "\n").unwrap();

    let err = verify_chain().expect_err("root tamper must be caught");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("rolling-root mismatch"),
        "expected rolling-root mismatch, got: {}",
        msg
    );
}

#[test]
fn rolling_root_rejects_sidecar_with_wrong_schema_version() {
    let _g = EnvGuard::new("wrong_schema");
    write_attestation(fields(1)).unwrap();
    let mut stored = load_merkle_root().unwrap().unwrap();
    stored.schema_version = 999;
    let raw = serde_json::to_string(&stored).unwrap();
    fs::write(attest::merkle_root_path(), raw + "\n").unwrap();
    // load_merkle_root itself returns Err for an unsupported schema.
    let err = load_merkle_root().expect_err("unsupported sidecar schema must surface");
    let msg = format!("{:#}", err);
    assert!(
        msg.contains("schema_version"),
        "expected schema error, got: {}",
        msg
    );
}

#[test]
fn write_merkle_root_round_trip_empty_set() {
    // Direct write_merkle_root path with an empty slice — the empty
    // sentinel. Equivalent to recompute_merkle_root_from_disk on an
    // untouched dir, but tested directly.
    let _g = EnvGuard::new("write_empty");
    let f = write_merkle_root(&[]).unwrap();
    assert_eq!(f.entry_count, 0);
    assert_eq!(f.merkle_root, attest::ZERO_HEX);
    let reloaded = load_merkle_root().unwrap().unwrap();
    assert_eq!(reloaded, f);
}
