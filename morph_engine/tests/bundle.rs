//! TASK-036 / Phase A integration tests for atomic multi-module bundle
//! morph cycles. Exercises the new public surface:
//!
//! - `BundleCycleArgs::from_cli` parser
//! - `scheduler::pick_next_work_at` competition between modules and
//!   bundles
//! - `scheduler::SchedulerState::bundles` per-bundle bookkeeping
//! - v5 attestation: a bundle entry's canonical-JSON shape, and
//!   round-trip through serde
//!
//! The full end-to-end `run_bundle` test (which spawns the verifier
//! binary and runs cargo against a scratch workspace) is
//! `#[ignore]`-gated; run it explicitly with
//! `cargo test -p proteus-morph-engine --test bundle -- --ignored
//! end_to_end_bundle_runs_clean`.

use std::collections::BTreeMap;
use std::path::PathBuf;

use proteus_morph_engine::{
    attest::{AttestEntry, ModuleArtifact, SCHEMA_VERSION},
    scheduler::{
        pick_next_work_at, BundleConfig, ModuleConfig, ModuleState, NextWork, SchedulerConfig,
        SchedulerState,
    },
    BundleCycleArgs, SynthesizerKind,
};

// ---------------------------------------------------------------------------
// BundleCycleArgs::from_cli
// ---------------------------------------------------------------------------

fn cli(args: &[&str]) -> Vec<String> {
    args.iter().map(|s| s.to_string()).collect()
}

#[test]
fn bundle_args_parse_happy_path() {
    let raw = cli(&[
        "--cycle", "42",
        "--bundle", "kernel",
        "--workspace", "target_enterprise",
        "--module", "tls",
        "--module", "wal",
        "--module", "iommu",
    ]);
    let args = BundleCycleArgs::from_cli(&raw).expect("parse must succeed");
    assert_eq!(args.cycle, 42);
    assert_eq!(args.bundle_name, "kernel");
    assert_eq!(args.workspace, PathBuf::from("target_enterprise"));
    assert_eq!(args.modules, vec!["tls", "wal", "iommu"]);
    assert!(args.manifest.is_none());
    assert_eq!(args.synthesizer, SynthesizerKind::PassThrough);
    assert!(!args.emit_image);
}

#[test]
fn bundle_args_parse_with_manifest_and_synthesizer() {
    let raw = cli(&[
        "--cycle", "7",
        "--bundle", "kernel",
        "--workspace", "target_enterprise",
        "--module", "tls",
        "--manifest", "target_enterprise/manifest.txt",
        "--synthesizer", "prompt-only",
        "--emit-image",
    ]);
    let args = BundleCycleArgs::from_cli(&raw).expect("parse must succeed");
    assert_eq!(args.manifest, Some(PathBuf::from("target_enterprise/manifest.txt")));
    assert_eq!(args.synthesizer, SynthesizerKind::PromptOnly);
    assert!(args.emit_image);
}

#[test]
fn bundle_args_rejects_missing_required_fields() {
    // Missing --cycle.
    let raw = cli(&[
        "--bundle", "kernel",
        "--workspace", "target_enterprise",
        "--module", "tls",
    ]);
    assert!(BundleCycleArgs::from_cli(&raw).is_err());

    // Missing --bundle.
    let raw = cli(&[
        "--cycle", "1",
        "--workspace", "target_enterprise",
        "--module", "tls",
    ]);
    assert!(BundleCycleArgs::from_cli(&raw).is_err());

    // Missing --workspace.
    let raw = cli(&[
        "--cycle", "1",
        "--bundle", "kernel",
        "--module", "tls",
    ]);
    assert!(BundleCycleArgs::from_cli(&raw).is_err());

    // Missing any --module (empty bundle is invalid).
    let raw = cli(&[
        "--cycle", "1",
        "--bundle", "kernel",
        "--workspace", "target_enterprise",
    ]);
    assert!(BundleCycleArgs::from_cli(&raw).is_err());
}

#[test]
fn bundle_args_unknown_flag_rejected() {
    let raw = cli(&[
        "--cycle", "1",
        "--bundle", "kernel",
        "--workspace", "target_enterprise",
        "--module", "tls",
        "--frobnicate",
    ]);
    assert!(BundleCycleArgs::from_cli(&raw).is_err());
}

// ---------------------------------------------------------------------------
// scheduler::pick_next_work_at
// ---------------------------------------------------------------------------

fn module_cfg(priority: u64, max_age: u64) -> ModuleConfig {
    ModuleConfig {
        priority,
        max_age_secs: max_age,
        target_dir: PathBuf::from("/tmp/x"),
        manifest: None,
    }
}

fn bundle_cfg(priority: u64, max_age: u64, modules: &[&str]) -> BundleConfig {
    BundleConfig {
        priority,
        max_age_secs: max_age,
        workspace: PathBuf::from("target_enterprise"),
        modules: modules.iter().map(|s| s.to_string()).collect(),
        manifest: None,
    }
}

#[test]
fn pick_next_work_returns_none_when_nothing_due() {
    let mut cfg = SchedulerConfig::default();
    cfg.modules.insert("m1".to_string(), module_cfg(1, 3600));
    cfg.bundles.insert(
        "kernel".to_string(),
        bundle_cfg(1, 3600, &["tls"]),
    );
    let mut state = SchedulerState::default();
    state.modules.insert("m1".to_string(), ModuleState { last_cycle: 1, last_morph_unix: 1000 });
    state.bundles.insert("kernel".to_string(), ModuleState { last_cycle: 1, last_morph_unix: 1000 });
    // now = 1001 → elapsed = 1, priority=1 → weighted=1 < 3600. Both not due.
    let pick = pick_next_work_at(&cfg, &state, 1001);
    assert!(pick.is_none());
}

#[test]
fn pick_next_work_picks_bundle_when_only_bundle_is_due() {
    let mut cfg = SchedulerConfig::default();
    cfg.modules.insert("m1".to_string(), module_cfg(1, 100_000));
    cfg.bundles.insert(
        "kernel".to_string(),
        bundle_cfg(10, 100, &["tls", "wal"]),
    );
    let state = SchedulerState::default();
    // now = 200, last = 0 for both. Module: 200*1=200 < 100000 (not due).
    // Bundle: 200*10=2000 >= 100 (due).
    let pick = pick_next_work_at(&cfg, &state, 200).expect("bundle should be due");
    match pick {
        NextWork::Bundle(b) => {
            assert_eq!(b.bundle, "kernel");
            assert_eq!(b.config.modules, vec!["tls", "wal"]);
        }
        NextWork::Module(_) => panic!("expected bundle, got module"),
    }
}

#[test]
fn pick_next_work_picks_module_when_module_outranks_bundle() {
    let mut cfg = SchedulerConfig::default();
    cfg.modules.insert("hot".to_string(), module_cfg(100, 100));
    cfg.bundles.insert(
        "kernel".to_string(),
        bundle_cfg(10, 100, &["tls"]),
    );
    let state = SchedulerState::default();
    // now = 200, both due. Module priority 100 > bundle priority 10.
    let pick = pick_next_work_at(&cfg, &state, 200).expect("at least one is due");
    match pick {
        NextWork::Module(m) => assert_eq!(m.module, "hot"),
        NextWork::Bundle(_) => panic!("expected module (higher priority), got bundle"),
    }
}

#[test]
fn pick_next_work_picks_bundle_when_bundle_outranks_module() {
    let mut cfg = SchedulerConfig::default();
    cfg.modules.insert("cold".to_string(), module_cfg(1, 100));
    cfg.bundles.insert(
        "kernel".to_string(),
        bundle_cfg(50, 100, &["tls", "wal", "iommu"]),
    );
    let state = SchedulerState::default();
    let pick = pick_next_work_at(&cfg, &state, 200).expect("at least one is due");
    match pick {
        NextWork::Bundle(b) => {
            assert_eq!(b.bundle, "kernel");
            assert_eq!(b.config.modules.len(), 3);
        }
        NextWork::Module(_) => panic!("expected bundle (higher priority), got module"),
    }
}

#[test]
fn pick_next_work_age_tiebreaker_for_bundles() {
    // Two bundles, same priority, different ages. Older wins.
    let mut cfg = SchedulerConfig::default();
    cfg.bundles.insert(
        "old".to_string(),
        bundle_cfg(10, 100, &["m1"]),
    );
    cfg.bundles.insert(
        "new".to_string(),
        bundle_cfg(10, 100, &["m2"]),
    );
    let mut state = SchedulerState::default();
    state.bundles.insert("old".to_string(), ModuleState { last_cycle: 0, last_morph_unix: 100 });
    state.bundles.insert("new".to_string(), ModuleState { last_cycle: 0, last_morph_unix: 500 });
    // now = 1000 → old elapsed 900*10=9000 > 100, new elapsed 500*10=5000 > 100.
    // Both due. Older (lower last_morph_unix) wins.
    let pick = pick_next_work_at(&cfg, &state, 1000).expect("at least one is due");
    match pick {
        NextWork::Bundle(b) => assert_eq!(b.bundle, "old"),
        NextWork::Module(_) => panic!("expected bundle"),
    }
}

// ---------------------------------------------------------------------------
// v5 attestation: schema + canonical-JSON stability
// ---------------------------------------------------------------------------

#[test]
fn v5_schema_constant_is_5() {
    // Originally pinned `SCHEMA_VERSION == 5` for the v4 -> v5 bump
    // landing (TASK-036). Subsequent additive bumps (v6 = TASK-031
    // diversifier_log) keep the live constant moving while the v5
    // bundle-shape contract — the actual subject of this file —
    // continues to hold because every additive field is
    // `skip_serializing_if`-omitted. Pin the floor, not the exact value.
    assert!(SCHEMA_VERSION >= 5, "v5 bundle-shape floor must hold");
}

#[test]
fn module_artifact_round_trips_through_serde() {
    let art = ModuleArtifact {
        candidate_sha256: "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8"
            .to_string(),
        elf_text_sha256: Some(
            "abcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd".to_string(),
        ),
    };
    let json = serde_json::to_string(&art).unwrap();
    assert!(json.contains("candidate_sha256"));
    assert!(json.contains("elf_text_sha256"));
    let back: ModuleArtifact = serde_json::from_str(&json).unwrap();
    assert_eq!(back, art);
}

#[test]
fn module_artifact_skips_absent_elf_text_sha256() {
    let art = ModuleArtifact {
        candidate_sha256: "aabb".repeat(16),
        elf_text_sha256: None,
    };
    let json = serde_json::to_string(&art).unwrap();
    assert!(!json.contains("elf_text_sha256"));
}

#[test]
fn v4_shaped_entry_canonically_stable_under_v5() {
    // Construct an AttestEntry that omits the v5 fields (bundle_name=None,
    // modules empty). Its canonical bytes (and therefore entry_sha256)
    // must match what v4 code produced.
    //
    // This is the load-bearing backward-compatibility property of the
    // v4 → v5 bump: a fleet that produced v4 entries before this code
    // shipped must continue to verify under v5 code without rewriting
    // the chain.
    let entry = AttestEntry {
        schema_version: 4,
        cycle: 1,
        ts_unix: 1_700_000_000,
        module: "lib".into(),
        candidate_sha256: "39b94ac83ca00c15a2f4c292e41717f9e390b3c3157bb6428a519c9b42b0a7d8"
            .into(),
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
        prev_entry_sha256: "0".repeat(64),
        entry_sha256: String::new(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    // v5-specific keys must not appear when the values are absent/empty.
    assert!(!json.contains("\"bundle_name\""));
    assert!(!json.contains("\"modules\""));
    // v6: same skip-when-None policy for diversifier_log.
    assert!(!json.contains("\"diversifier_log\""));
}

#[test]
fn bundle_entry_serialises_with_bundle_name_and_modules() {
    let mut modules = BTreeMap::new();
    modules.insert(
        "tls".to_string(),
        ModuleArtifact {
            candidate_sha256: "aa".repeat(32),
            elf_text_sha256: None,
        },
    );
    modules.insert(
        "wal".to_string(),
        ModuleArtifact {
            candidate_sha256: "bb".repeat(32),
            elf_text_sha256: None,
        },
    );

    let entry = AttestEntry {
        schema_version: SCHEMA_VERSION,
        cycle: 7,
        ts_unix: 1_700_000_000,
        module: "kernel".into(),
        candidate_sha256: "cc".repeat(32),
        sig_ed25519: "00".repeat(64),
        accepted: true,
        synthesizer: "passthrough".into(),
        prompt_path: None,
        image_sha256: None,
        cosignatures: Vec::new(),
        federation_threshold: None,
        factory_binaries: BTreeMap::new(),
        bundle_name: Some("kernel".to_string()),
        modules,
        diversifier_log: None,
        kernel_layout_seed: None,
        ext_tlv_b64: None,
        diversity: None,
        durable_seals: std::collections::BTreeMap::new(),
        prev_entry_sha256: "0".repeat(64),
        entry_sha256: String::new(),
    };
    let json = serde_json::to_string(&entry).unwrap();
    assert!(json.contains("\"bundle_name\":\"kernel\""));
    assert!(json.contains("\"tls\""));
    assert!(json.contains("\"wal\""));

    // Round-trip back into the struct.
    let back: AttestEntry = serde_json::from_str(&json).unwrap();
    assert_eq!(back.bundle_name.as_deref(), Some("kernel"));
    assert_eq!(back.modules.len(), 2);
}
