//! Integration tests for TASK-015's diversity_demo.
//!
//! Both tests run in fast-mode (no nightly kernel build) so the
//! workspace `cargo test` stays fast. The CLI demo runs the real
//! `factory_builder::build_kernel`; fast-mode is documented in
//! REPORT.md and exists exclusively for these tests.

use diversity_demo::{
    evaluate_mtd_gate, render_report, run_experiment, ExperimentArgs, MtdGateStatus,
};
use std::path::PathBuf;
use std::sync::Mutex;

// Both tests mutate `target_enterprise/src/tls.rs` (write a candidate,
// then restore the pristine version). Running them concurrently would
// race on that file. Serialize via a process-global Mutex.
static FS_MUTEX: Mutex<()> = Mutex::new(());

fn workspace_root() -> PathBuf {
    // Tests live at `<root>/experiments/diversity_demo/tests/`; the
    // CARGO_MANIFEST_DIR env var resolves to the diversity_demo crate
    // dir at compile time.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .unwrap()
        .to_path_buf()
}

fn fast_args(results_subdir: &str, cycles: u64) -> ExperimentArgs {
    let root = workspace_root();
    let results_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results").join(results_subdir);
    ExperimentArgs {
        cycles,
        target_dir: root.join("target_enterprise"),
        module: "tls".to_string(),
        bundle_name: None,
        bundle_modules: None,
        kernel_crate_dir: root.join("target_enterprise_kernel"),
        results_dir,
        fast_mode: true,
        // Skip verify — when running under `cargo test`, the verify
        // binary may not be present beside the test exe (the test exe
        // lives in `target/debug/deps/`, the verify binary in
        // `target/debug/`; our resolver does try `..` but on a clean
        // checkout the verify binary hasn't been built yet). Skipping
        // verify keeps the test self-contained.
        skip_verify: true,
        signing_key_path: None,
        verify_bin: None,
        save_candidates: false,
        boot_each_cycle: false,
        // Historical (pre-layout-seed) behaviour: these smoke tests pin
        // the AST-diversifier-only path. The seeded path has its own
        // test (`layout_seed_relocates_offsets_and_is_recorded`).
        layout_seed_enabled: false,
        // Production default: stack-pad off (gadget inflation vs layout seed).
        stack_pad_enabled: false,
    }
}

#[test]
fn smoke_3_cycles_run_clean() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let args = fast_args("smoke3", 3);
    let summary = run_experiment(&args).expect("run_experiment");
    let report = render_report(&summary, &args.results_dir).expect("render_report");
    assert!(report.exists(), "REPORT.md was not written at {}", report.display());

    // Each of the three JSONL files must exist and parse as JSONL.
    for path in [
        &summary.cycles_jsonl,
        &summary.diversity_jsonl,
        &summary.survival_jsonl,
    ] {
        let text = std::fs::read_to_string(path)
            .unwrap_or_else(|e| panic!("read {}: {}", path.display(), e));
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() {
                continue;
            }
            let _: serde_json::Value = serde_json::from_str(line)
                .unwrap_or_else(|e| panic!("malformed JSONL line in {}: {} :: {}", path.display(), line, e));
        }
    }

    assert_eq!(
        summary.cycles_requested, 3,
        "summary.cycles_requested mismatch"
    );
    assert!(
        summary.cycles_completed >= 1,
        "at least cycle 0 should be accepted; got {}",
        summary.cycles_completed
    );
    assert_eq!(
        summary.fast_mode, true,
        "fast-mode flag should be recorded in the summary"
    );

    // After the run, target_enterprise/src/tls.rs must be unchanged.
    let src = args.target_dir.join("src").join("tls.rs");
    let body = std::fs::read_to_string(&src).expect("read tls.rs");
    assert!(
        body.contains("Tls13Server") || body.contains("tls"),
        "tls.rs looks corrupted after run; first chars: {}",
        &body.chars().take(120).collect::<String>()
    );
    // And the backup file must have been removed on clean exit.
    let backup = args.target_dir.join("src").join("tls.rs.preexp.bak");
    assert!(
        !backup.exists(),
        "backup file should be cleaned up after a successful run"
    );
}

#[test]
fn save_candidates_writes_one_file_per_accepted_cycle() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut args = fast_args("savecands3", 3);
    args.save_candidates = true;
    let summary = run_experiment(&args).expect("run_experiment");
    let cand_dir = args.results_dir.join("candidates");
    assert!(
        cand_dir.exists(),
        "candidates dir not created at {}",
        cand_dir.display()
    );
    let mut saved = 0u64;
    for entry in std::fs::read_dir(&cand_dir).expect("read candidates dir") {
        let entry = entry.expect("read entry");
        let p = entry.path();
        if p.extension().and_then(|s| s.to_str()) == Some("rs") {
            let body = std::fs::read_to_string(&p).expect("read candidate");
            assert!(
                !body.is_empty(),
                "candidate at {} should be non-empty",
                p.display()
            );
            assert!(
                body.contains("hkdf") || body.contains("Tls") || body.contains("tls"),
                "candidate at {} does not look like tls.rs (first 80 chars: {})",
                p.display(),
                &body.chars().take(80).collect::<String>()
            );
            saved += 1;
        }
    }
    assert_eq!(
        saved, summary.cycles_completed,
        "expected one candidate file per accepted cycle ({}), got {}",
        summary.cycles_completed, saved
    );
}

#[test]
fn entropy_floor_not_zero() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let args = fast_args("entropy3", 3);
    let summary = run_experiment(&args).expect("run_experiment");
    assert!(
        summary.cycles_completed >= 2,
        "need at least 2 accepted cycles to assess entropy floor; got {}",
        summary.cycles_completed
    );
    // The whole point: if the diversifier is a no-op on tls.rs, this
    // assertion fails LOUDLY. That's the bug-surfacing contract from
    // the task brief.
    assert!(
        summary.distinct_text_sha256 >= 2,
        "entropy floor failure: only {} distinct elf_text_sha256 across {} \
         accepted cycles — the diversifier produced zero binary diversity \
         on tls.rs under fast-mode pseudo-ELF derivation. This means the \
         candidate_sha256 itself is not varying cycle-to-cycle, which is \
         the project's central claim broken.",
        summary.distinct_text_sha256,
        summary.cycles_completed
    );
}

/// Phase-1 layout seeding, fast-mode end-to-end. Asserts the three
/// properties the real-mode lever provides, at the layer the harness
/// can test without a nightly build:
/// - every accepted cycle's record carries
///   `kernel_layout_seed == cycle_layout_seed(cycle)`;
/// - the summary reports the seeding as enabled and computes the new
///   layout-entropy metrics;
/// - REPORT.md surfaces the seeding state + distinct-layout headline.
#[test]
fn layout_seed_relocates_offsets_and_is_recorded() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut args = fast_args("layoutseed_fast4", 4);
    args.layout_seed_enabled = true;
    let summary = run_experiment(&args).expect("run_experiment");
    assert!(summary.layout_seed_enabled, "summary must record seeding");
    assert!(
        summary.cycles_completed >= 2,
        "need >= 2 accepted cycles to say anything about layouts; got {}",
        summary.cycles_completed
    );

    // Every accepted record carries the mirrored per-cycle seed.
    let text = std::fs::read_to_string(&summary.cycles_jsonl).expect("read cycles.jsonl");
    let mut accepted_seen = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("parse JSON");
        if !v.get("accepted").and_then(|x| x.as_bool()).unwrap_or(false) {
            continue;
        }
        let cycle = v.get("cycle").and_then(|x| x.as_u64()).expect("cycle field");
        let seed = v
            .get("kernel_layout_seed")
            .and_then(|x| x.as_u64())
            .expect("accepted record must carry kernel_layout_seed");
        assert_eq!(
            seed,
            diversity_demo::cycle_layout_seed(cycle),
            "recorded seed must be cycle_layout_seed(cycle) for cycle {}",
            cycle
        );
        accepted_seen += 1;
    }
    assert!(accepted_seen >= 2);

    // Layout entropy metrics: distinct layouts should track accepted
    // cycles (the pseudo-ELF scatters offsets from (hash, seed), and
    // both differ every cycle).
    assert_eq!(
        summary.distinct_function_layouts, summary.cycles_completed as usize,
        "every seeded cycle should produce a distinct function layout"
    );
    assert!(
        summary.chain_offset_a_distinct >= 2,
        "anchor symbol must relocate across cycles; observed {} distinct offsets",
        summary.chain_offset_a_distinct
    );

    // REPORT.md surfaces the new headline.
    let report = render_report(&summary, &args.results_dir).expect("render_report");
    let body = std::fs::read_to_string(&report).expect("read REPORT.md");
    assert!(
        body.contains("Per-cycle kernel layout seeding") && body.contains("ENABLED"),
        "REPORT.md must surface the seeding state"
    );
    assert!(
        body.contains("Distinct (symbol → offset) layouts"),
        "REPORT.md must surface the distinct-layouts headline"
    );
    assert!(
        body.contains("MTD regression gate") && body.contains("PASSED"),
        "REPORT.md must surface a PASSED MTD gate under layout seeding"
    );

    // CI bar: evaluate_mtd_gate must Pass on the same metrics the
    // real-mode TASK-067 experiment established.
    match evaluate_mtd_gate(&summary) {
        MtdGateStatus::Passed => {}
        other => panic!(
            "layout-seeded fast-mode run must PASS the MTD gate; got {:?}",
            other
        ),
    }
    assert!(!summary.stack_pad_enabled, "production default leaves pad off");
}

/// Production default: stack-pad stays off; candidates must not contain
/// the TASK-029 pad identifier when `stack_pad_enabled` is false.
#[test]
fn default_stack_pad_off_in_experiment() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut args = fast_args("stackpad_off3", 3);
    args.save_candidates = true;
    assert!(!args.stack_pad_enabled);
    let summary = run_experiment(&args).expect("run_experiment");
    assert!(!summary.stack_pad_enabled);
    let cand_dir = args.results_dir.join("candidates");
    for entry in std::fs::read_dir(&cand_dir).expect("read candidates") {
        let p = entry.expect("entry").path();
        if p.extension().and_then(|s| s.to_str()) != Some("rs") {
            continue;
        }
        let body = std::fs::read_to_string(&p).expect("read candidate");
        assert!(
            !body.contains("__cuttle_stack_pad_"),
            "candidate {} must not contain stack pads when stack_pad_enabled=false",
            p.display()
        );
    }
}

/// A/B contract: with seeding disabled the records must NOT carry the
/// field at all (additive schema — old consumers see the old shape).
#[test]
fn no_layout_seed_keeps_legacy_record_shape() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let args = fast_args("layoutseed_off2", 2);
    assert!(!args.layout_seed_enabled, "fast_args pins the legacy path");
    let summary = run_experiment(&args).expect("run_experiment");
    assert!(!summary.layout_seed_enabled);
    let text = std::fs::read_to_string(&summary.cycles_jsonl).expect("read cycles.jsonl");
    assert!(
        !text.contains("kernel_layout_seed"),
        "disabled seeding must keep cycles.jsonl free of the new field"
    );
}

// =====================================================================
// TASK-036 Phase B: bundle-mode smoke tests
// =====================================================================

fn fast_bundle_args(results_subdir: &str, cycles: u64, members: &[&str]) -> ExperimentArgs {
    let root = workspace_root();
    let results_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results").join(results_subdir);
    ExperimentArgs {
        cycles,
        target_dir: root.join("target_enterprise"),
        // In bundle mode `module` is a label for the summary; the
        // actual files come from `bundle_modules`.
        module: "kernel".to_string(),
        bundle_name: Some("kernel".to_string()),
        bundle_modules: Some(members.iter().map(|s| s.to_string()).collect()),
        kernel_crate_dir: root.join("target_enterprise_kernel"),
        results_dir,
        fast_mode: true,
        skip_verify: true,
        signing_key_path: None,
        verify_bin: None,
        save_candidates: false,
        boot_each_cycle: false,
        layout_seed_enabled: false,
        stack_pad_enabled: false,
    }
}

/// 3-cycle fast-mode run against a 2-module bundle. Asserts:
/// - Every member's pristine source is preserved on exit.
/// - Every member's `.preexp.bak` is cleaned up.
/// - `cycles.jsonl` records `bundle_modules` with both member hashes.
/// - `summary.bundle_name == Some("kernel")` and `bundle_members` has
///   both names.
/// - The pseudo-ELF entropy floor is non-degenerate: ≥ 2 distinct
///   bundle-hash-derived ELF sha256 values.
#[test]
fn smoke_bundle_2_member_3_cycles() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    // Use `tls` + `wal` — both are in the production `[bundle.kernel]`
    // declaration, both have established morph-round-trip tests, both
    // have public files at target_enterprise/src/<name>.rs that the
    // pristine-restore machinery can find.
    let args = fast_bundle_args("bundle_smoke_2x3", 3, &["tls", "wal"]);

    // Confirm both source files exist before the run.
    for member in ["tls", "wal"] {
        let p = args.target_dir.join("src").join(format!("{}.rs", member));
        assert!(p.exists(), "precondition: {} must exist", p.display());
    }

    let summary = run_experiment(&args).expect("run_experiment(bundle)");

    // Bundle-aware summary fields.
    assert_eq!(summary.bundle_name.as_deref(), Some("kernel"));
    assert_eq!(summary.bundle_members, vec!["tls".to_string(), "wal".to_string()]);

    // Cycle records carry per-member hashes.
    let text = std::fs::read_to_string(&summary.cycles_jsonl)
        .expect("read cycles.jsonl");
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert!(lines.len() >= 1, "expected ≥ 1 cycle record");
    for line in &lines {
        let v: serde_json::Value =
            serde_json::from_str(line).expect("cycle record JSON parse");
        // Rejected cycles have no bundle_modules (the field is
        // `skip_serializing_if = "BTreeMap::is_empty"`). Accepted
        // cycles must have both members.
        let accepted = v.get("accepted").and_then(|x| x.as_bool()).unwrap_or(false);
        if accepted {
            let bm = v
                .get("bundle_modules")
                .and_then(|x| x.as_object())
                .expect("accepted record missing bundle_modules");
            assert!(
                bm.contains_key("tls") && bm.contains_key("wal"),
                "bundle_modules missing a member: {:?}",
                bm.keys().collect::<Vec<_>>()
            );
        }
    }

    // Every member's source must be restored to pristine; no backup
    // file should remain.
    for member in ["tls", "wal"] {
        let src = args.target_dir.join("src").join(format!("{}.rs", member));
        let body = std::fs::read_to_string(&src).expect("read source");
        assert!(
            body.len() > 100,
            "{} looks empty after run — restore failed?",
            src.display()
        );
        let bk = args.target_dir.join("src").join(format!("{}.rs.preexp.bak", member));
        assert!(
            !bk.exists(),
            "backup file for {} should be cleaned up",
            member
        );
    }

    // The diversifier should produce per-cycle binary diversity even
    // in fast-mode (the bundle hash threaded into `synthesize_pseudo_elf`
    // varies cycle-to-cycle because every member's canonical hash
    // varies).
    assert!(
        summary.cycles_completed >= 1,
        "at least cycle 0 must be accepted in fast-mode bundle run"
    );
    if summary.cycles_completed >= 2 {
        assert!(
            summary.distinct_text_sha256 >= 2,
            "fast-mode bundle entropy floor failure: {} distinct elf_text_sha256 \
             across {} accepted cycles — the bundle hash isn't varying.",
            summary.distinct_text_sha256,
            summary.cycles_completed
        );
    }
}

// =====================================================================
// TASK-026 — per-cycle QEMU serial-log capture.
// =====================================================================

/// Fast-mode + `boot_each_cycle = true` is a documented no-op. The
/// lib emits a one-time warning on stderr and leaves `serial_log_
/// sha256` as None on every accepted cycle. This test exercises that
/// path so the warning latch + None-default behaviour is pinned —
/// otherwise an accidental refactor that started writing fake sha256s
/// into accepted records under fast-mode (e.g. "use the bundle hash
/// as a stand-in for the serial log") would slip past CI silently.
#[test]
fn boot_each_cycle_is_noop_under_fast_mode() {
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let mut args = fast_args("boot_each_cycle_fast_noop", 3);
    args.boot_each_cycle = true;
    let summary = run_experiment(&args).expect("run_experiment");

    // Every accepted cycle in fast-mode must omit the field entirely
    // (per skip_serializing_if=Option::is_none).
    let text = std::fs::read_to_string(&summary.cycles_jsonl).expect("read cycles.jsonl");
    let mut accepted = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("parse JSON");
        if v.get("accepted").and_then(|x| x.as_bool()).unwrap_or(false) {
            accepted += 1;
            assert!(
                v.get("serial_log_sha256").is_none(),
                "fast-mode + boot_each_cycle should NOT write serial_log_sha256, got: {}",
                line
            );
        }
    }
    assert!(accepted >= 1, "at least one cycle should be accepted");

    // And the QEMU side-effect directories must NOT have been created
    // (since we never invoked qemu).
    let logs_dir = args.results_dir.join("serial_logs");
    let images_dir = args.results_dir.join("images");
    assert!(
        !logs_dir.exists(),
        "fast-mode must not create serial_logs/ — got {}",
        logs_dir.display()
    );
    assert!(
        !images_dir.exists(),
        "fast-mode must not create images/ — got {}",
        images_dir.display()
    );
}

/// Real-mode, opt-in via `CUTTLE_BOOT_EACH_CYCLE_TEST=1`. Drives a
/// 2-cycle real run against `target_enterprise/tls` with
/// `--boot-each-cycle`, then asserts every accepted cycle's
/// `cycles.jsonl` record carries a 64-hex-char `serial_log_sha256`
/// and the corresponding `<results>/serial_logs/cycle_NN.log` file
/// is non-empty.
///
/// Gated by env var because:
///   - QEMU may not be installed on the CI machine.
///   - The real kernel build (nightly + build-std) is multi-minute
///     and not in the workspace `cargo test` default budget.
///   - The packaging step pulls in `factory_builder_pkg`, also
///     nightly, also multi-minute on first build.
///
/// Skips (not fails) when:
///   - The env var isn't set to "1".
///   - QEMU isn't on PATH.
///   - `target_enterprise_kernel/` or `factory_builder_pkg/` is missing
///     (e.g. clean checkout without the out-of-workspace crates).
#[test]
fn boot_each_cycle_real_mode_captures_per_cycle_serial_logs() {
    if std::env::var("CUTTLE_BOOT_EACH_CYCLE_TEST").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: CUTTLE_BOOT_EACH_CYCLE_TEST != 1; set the env var to run the 2-cycle \
             real-mode boot-each-cycle test (requires QEMU + nightly toolchain + several minutes)"
        );
        return;
    }
    let _g = FS_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let kernel_crate = root.join("target_enterprise_kernel");
    let pkg_crate = root.join("factory_builder_pkg");
    if !kernel_crate.join("Cargo.toml").exists() {
        eprintln!(
            "SKIP: target_enterprise_kernel/ missing at {}",
            kernel_crate.display()
        );
        return;
    }
    if !pkg_crate.join("Cargo.toml").exists() {
        eprintln!(
            "SKIP: factory_builder_pkg/ missing at {}",
            pkg_crate.display()
        );
        return;
    }
    if diversity_demo::qemu_boot::find_qemu().is_none() {
        eprintln!(
            "SKIP: qemu-system-x86_64 not found on PATH nor at C:/Program Files/qemu/"
        );
        return;
    }

    let results_dir =
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results").join("real_boot_each_cycle_2");
    // Ensure a clean run — remove any stale per-cycle directories.
    let _ = std::fs::remove_dir_all(&results_dir);

    let args = ExperimentArgs {
        cycles: 2,
        target_dir: root.join("target_enterprise"),
        module: "tls".to_string(),
        bundle_name: None,
        bundle_modules: None,
        kernel_crate_dir: kernel_crate,
        results_dir: results_dir.clone(),
        fast_mode: false,
        skip_verify: true,
        signing_key_path: None,
        verify_bin: None,
        save_candidates: false,
        boot_each_cycle: true,
        // Production default: when this env-gated test IS run, it
        // proves the layout-seeded kernel boots and serves serial
        // output (the seeded image was separately QEMU-banner-proven
        // when the lever landed in factory_builder).
        layout_seed_enabled: true,
        stack_pad_enabled: false,
    };
    let summary = run_experiment(&args).expect("run_experiment real-mode boot-each-cycle");
    assert!(
        summary.cycles_completed >= 1,
        "at least cycle 0 must be accepted; got {}",
        summary.cycles_completed
    );

    // Every accepted cycle record must carry a 64-hex-char serial sha.
    let text = std::fs::read_to_string(&summary.cycles_jsonl).expect("read cycles.jsonl");
    let mut accepted_with_sha = 0u64;
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let v: serde_json::Value = serde_json::from_str(line).expect("parse JSON");
        if v.get("accepted").and_then(|x| x.as_bool()).unwrap_or(false) {
            let sha = v
                .get("serial_log_sha256")
                .and_then(|x| x.as_str())
                .expect("accepted record must carry serial_log_sha256");
            assert_eq!(
                sha.len(),
                64,
                "serial_log_sha256 must be a 64-char hex string; got len={} value={:?}",
                sha.len(),
                sha
            );
            assert!(
                sha.chars().all(|c| c.is_ascii_hexdigit()),
                "serial_log_sha256 must be hex; got {:?}",
                sha
            );
            accepted_with_sha += 1;
        }
    }
    assert!(
        accepted_with_sha >= 1,
        "expected at least one accepted record with a serial_log_sha256"
    );

    // And the per-cycle serial log files must exist on disk.
    let logs_dir = results_dir.join("serial_logs");
    assert!(
        logs_dir.exists(),
        "serial_logs/ must exist after real-mode --boot-each-cycle run at {}",
        logs_dir.display()
    );
    let mut log_count = 0u64;
    for entry in std::fs::read_dir(&logs_dir).expect("read serial_logs dir") {
        let e = entry.expect("dir entry");
        let p = e.path();
        if p.extension().and_then(|s| s.to_str()) == Some("log") {
            let bytes = std::fs::read(&p).expect("read serial log");
            assert!(
                !bytes.is_empty(),
                "captured serial log at {} is empty",
                p.display()
            );
            // The kernel's HALT banner must appear in every captured log;
            // any earlier exit would have failed the cycle's
            // qemu_boot::boot_and_capture call before we got here.
            let s = String::from_utf8_lossy(&bytes);
            assert!(
                s.contains("CUTTLE-TE HALT"),
                "captured serial log at {} missing CUTTLE-TE HALT",
                p.display()
            );
            log_count += 1;
        }
    }
    assert!(log_count >= 1, "no captured .log files in {}", logs_dir.display());
}
