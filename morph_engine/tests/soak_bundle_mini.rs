//! Mini-bundle morph-daemon soak — atomic N-module factory proof.
//!
//! Same structure as `soak_short`, but the due work is
//! `[bundle.kernel_mini]` (`tls` + `wal` + `net` under
//! `target_enterprise`). This is the production-shaped path: one
//! verify invocation for the whole set, one attestation entry per
//! cycle, atomic deploy.
//!
//! # Invocation
//!
//! ```text
//! $env:CUTTLE_SOAK_BUNDLE_MINI = "1"
//! $env:CUTTLE_SOAK_ITERS = "2"   # optional; default 2
//! cargo test -p cuttle-morph-engine --test soak_bundle_mini -- --nocapture
//! ```

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cuttle_morph_engine::{
    daemon::{run_daemon, DaemonArgs, DaemonReport, DAEMON_LOG},
    verify_chain_with_options, SynthesizerKind, VerifyOptions, ATTEST_DIR_ENV,
    FEDERATION_CONFIG_ENV, SIGNING_KEY_ENV,
};

static SOAK_MUTEX: Mutex<()> = Mutex::new(());

const BUNDLE_MODULES: &[&str] = &["tls", "wal", "net"];

fn copy_crate_tree_no_target(src: &Path, dst: &Path) {
    fs::create_dir_all(dst).expect("create staged crate dir");
    for entry in fs::read_dir(src).expect("read_dir") {
        let entry = entry.expect("dir entry");
        let name = entry.file_name();
        let name_s = name.to_string_lossy();
        if matches!(name_s.as_ref(), "target" | ".git" | ".vscode" | ".idea") {
            continue;
        }
        let from = entry.path();
        let to = dst.join(&name);
        let ty = entry.file_type().expect("file_type");
        if ty.is_dir() {
            copy_crate_tree_no_target(&from, &to);
        } else if ty.is_file() {
            fs::copy(&from, &to).expect("copy staged file");
        }
    }
}

fn assert_clean_checkout_dir(root: &Path, rel_src: &str) {
    let dir = root.join(rel_src);
    if let Ok(entries) = fs::read_dir(&dir) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                assert!(
                    !name.ends_with(".candidate.rs") && !name.ends_with(".rs.preexp.bak"),
                    "refusing to run with stale staging file in live checkout: {}",
                    p.display()
                );
            }
        }
    }
    if let Ok(out) = Command::new("git")
        .args(["status", "--porcelain", "--", rel_src])
        .current_dir(root)
        .output()
    {
        if out.status.success() {
            let txt = String::from_utf8_lossy(&out.stdout);
            assert!(
                txt.trim().is_empty(),
                "live checkout has modified/untracked files under {}: {}",
                rel_src,
                txt.trim()
            );
        }
    }
}

fn stage_enterprise_soak_workspace(root: &Path, run_id: u64) -> PathBuf {
    let stage = std::env::temp_dir().join(format!(
        "cuttle-soak-bmini-{}-{}",
        std::process::id(),
        run_id
    ));
    let _ = fs::remove_dir_all(&stage);
    fs::create_dir_all(&stage).expect("create stage root");
    for f in [
        "Cargo.toml",
        "Cargo.lock",
        "locked_modules.toml",
        "factory_keys.toml",
        "factory_signing_key.bin",
    ] {
        let src = root.join(f);
        if src.exists() {
            fs::copy(&src, stage.join(f)).expect("copy root file");
        }
    }
    for d in ["contracts", "target_enterprise", "diversifier", "verifier"] {
        copy_crate_tree_no_target(&root.join(d), &stage.join(d));
    }
    stage
}

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("morph_engine parent")
        .to_path_buf()
}

fn soak_root() -> PathBuf {
    workspace_root().join("experiments").join("soak_bundle_mini")
}

fn count_kind(events: &[serde_json::Value], kind: &str) -> usize {
    events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .count()
}

fn count_bundle_accepts(events: &[serde_json::Value]) -> usize {
    events
        .iter()
        .filter(|e| {
            e.get("kind").and_then(|v| v.as_str()) == Some("cycle_accept")
                && e.get("work_kind").and_then(|v| v.as_str()) == Some("bundle")
        })
        .count()
}

fn read_jsonl_events(path: &Path) -> Vec<serde_json::Value> {
    let txt = fs::read_to_string(path).unwrap_or_default();
    txt.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
}

fn snapshot_modules(root: &Path) -> Vec<(PathBuf, String)> {
    let src = root.join("target_enterprise").join("src");
    BUNDLE_MODULES
        .iter()
        .map(|m| {
            let p = src.join(format!("{}.rs", m));
            let body = fs::read_to_string(&p)
                .unwrap_or_else(|e| panic!("read {}: {}", p.display(), e));
            (p, body)
        })
        .collect()
}

fn restore_modules(snaps: &[(PathBuf, String)]) {
    for (p, body) in snaps {
        let _ = fs::write(p, body);
        let cand = p.with_extension("candidate.rs");
        let _ = fs::remove_file(cand);
    }
}

fn write_report(
    results_dir: &Path,
    report: &DaemonReport,
    events: &[serde_json::Value],
    attest_ok: bool,
    iters: u64,
) {
    let accepts = count_kind(events, "cycle_accept");
    let rejects = count_kind(events, "cycle_reject");
    let bundle_acc = count_bundle_accepts(events);
    let body = format!(
        "# Mini-bundle morph-daemon soak REPORT\n\n\
         ## Config\n\n\
         - Bundle: `kernel_mini` = {mods:?}\n\
         - Workspace: `target_enterprise`\n\
         - Synthesizer: passthrough + diversify\n\
         - Requested accepted cycles: {iters}\n\
         - Results dir: `{results}`\n\n\
         ## DaemonReport\n\n\
         - ticks_executed: {ticks}\n\
         - cycles_accepted: {acc}\n\
         - cycles_rejected: {rej}\n\
         - cycles_overrun: {ovr}\n\
         - idle_ticks: {idle}\n\n\
         ## daemon.log\n\n\
         - cycle_accept: {elog_acc} (bundle: {bundle_acc})\n\
         - cycle_reject: {elog_rej}\n\n\
         ## Attestation\n\n\
         - verify-attest: {attest}\n\n\
         ## Verdict\n\n\
         {verdict}\n",
        mods = BUNDLE_MODULES,
        iters = iters,
        results = results_dir.display(),
        ticks = report.ticks_executed,
        acc = report.cycles_accepted,
        rej = report.cycles_rejected,
        ovr = report.cycles_overrun,
        idle = report.idle_ticks,
        elog_acc = accepts,
        bundle_acc = bundle_acc,
        elog_rej = rejects,
        attest = if attest_ok { "PASS" } else { "FAIL" },
        verdict = if report.cycles_accepted >= iters
            && report.cycles_rejected == 0
            && bundle_acc >= iters as usize
            && rejects == 0
            && attest_ok
        {
            "**PASS** — mini-bundle soak met all acceptance criteria."
        } else {
            "**FAIL** — see counters above."
        },
    );
    let _ = fs::write(results_dir.join("REPORT.md"), body);
}

#[test]
fn mini_bundle_daemon_soak() {
    if std::env::var("CUTTLE_SOAK_BUNDLE_MINI").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: set CUTTLE_SOAK_BUNDLE_MINI=1 to run the mini-bundle soak \
             (target_enterprise compile × N cycles; several minutes)"
        );
        return;
    }

    let _g = SOAK_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let soak = soak_root();
    assert!(
        soak.join("scheduler.toml").exists(),
        "missing {}",
        soak.join("scheduler.toml").display()
    );

    let iters: u64 = std::env::var("CUTTLE_SOAK_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(2);
    assert!((1..=10).contains(&iters));

    assert!(
        root.join("factory_signing_key.bin").exists(),
        "factory_signing_key.bin missing; run morph init-key"
    );

    let verify_status = Command::new("cargo")
        .args(["build", "-p", "cuttle-verifier", "--bin", "verify"])
        .current_dir(&root)
        .status()
        .expect("build verify");
    assert!(verify_status.success());

    assert_clean_checkout_dir(&root, "target_enterprise/src");
    let snaps = snapshot_modules(&root);

    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let results_dir = soak.join("results").join(format!("run_{}", run_id));
    fs::create_dir_all(&results_dir).expect("results dir");

    let stage_root = stage_enterprise_soak_workspace(&root, run_id);
    let stage_soak = stage_root.join("soak_cfg");
    fs::create_dir_all(&stage_soak).expect("stage soak cfg");
    fs::copy(soak.join("scheduler.toml"), stage_soak.join("scheduler.toml"))
        .expect("copy scheduler.toml");

    let prev_attest = std::env::var_os(ATTEST_DIR_ENV);
    let prev_key = std::env::var_os(SIGNING_KEY_ENV);
    let prev_fed = std::env::var_os(FEDERATION_CONFIG_ENV);
    let prev_cwd = std::env::current_dir().expect("cwd");
    struct Cleanup {
        prev_cwd: PathBuf,
        prev_attest: Option<std::ffi::OsString>,
        prev_key: Option<std::ffi::OsString>,
        prev_fed: Option<std::ffi::OsString>,
        stage_root: PathBuf,
    }
    impl Drop for Cleanup {
        fn drop(&mut self) {
            let _ = std::env::set_current_dir(&self.prev_cwd);
            unsafe {
                match &self.prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
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
            let _ = fs::remove_dir_all(&self.stage_root);
        }
    }
    let cleanup = Cleanup {
        prev_cwd,
        prev_attest,
        prev_key,
        prev_fed,
        stage_root: stage_root.clone(),
    };

    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &results_dir);
        std::env::set_var(SIGNING_KEY_ENV, stage_root.join("factory_signing_key.bin"));
        if stage_root.join("factory_keys.toml").exists() {
            std::env::set_var(FEDERATION_CONFIG_ENV, stage_root.join("factory_keys.toml"));
        }
    }
    std::env::set_current_dir(&stage_root).expect("cd staged workspace");

    let state_path = stage_soak.join("scheduler_state.json");
    let daemon_log = stage_soak.join(DAEMON_LOG);

    let args = DaemonArgs {
        root: stage_soak.clone(),
        max_iters: iters,
        max_cycle_secs: 900,
        heartbeat_secs: 3600,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: true,
    };

    eprintln!(
        "soak_bundle_mini: max_iters={} modules={:?} staged_root={}",
        iters, BUNDLE_MODULES, stage_soak.display()
    );

    let report = run_daemon(&args).unwrap_or_else(|e| panic!("run_daemon failed: {:#}", e));

    eprintln!(
        "soak_bundle_mini: accepted={} rejected={} ticks={}",
        report.cycles_accepted, report.cycles_rejected, report.ticks_executed
    );

    if daemon_log.exists() {
        let _ = fs::copy(&daemon_log, results_dir.join(DAEMON_LOG));
    }
    if state_path.exists() {
        let _ = fs::copy(&state_path, results_dir.join("scheduler_state.json"));
    }

    let events = read_jsonl_events(&daemon_log);
    let accepts = count_kind(&events, "cycle_accept");
    let rejects = count_kind(&events, "cycle_reject");
    let bundle_acc = count_bundle_accepts(&events);

    let attest_ok = match verify_chain_with_options(&VerifyOptions {
        require_threshold: false,
        require_merkle_root: false,
        require_strict_factory: false,
        federation_config: None,
        factory_expected_path: None,
        require_ext_tlv: false,
        require_diversity: false,
        require_durable_seals: false,
    }) {
        Ok(rep) => {
            eprintln!(
                "soak_bundle_mini: verify-attest ok entries_ok={}",
                rep.entries_ok
            );
            true
        }
        Err(e) => {
            eprintln!("soak_bundle_mini: verify-attest FAILED: {:#}", e);
            false
        }
    };

    write_report(&results_dir, &report, &events, attest_ok, iters);
    eprintln!(
        "soak_bundle_mini: REPORT {}",
        results_dir.join("REPORT.md").display()
    );

    drop(cleanup);
    let _ = restore_modules as fn(&[(PathBuf, String)]);

    // Post-condition: live checkout was never touched.
    assert_clean_checkout_dir(&root, "target_enterprise/src");
    for (p, before) in &snaps {
        let after = fs::read_to_string(p).expect("re-read");
        assert_eq!(
            &after, before,
            "{} must never be modified in live checkout",
            p.display()
        );
    }

    assert_eq!(report.ticks_executed, iters);
    assert!(
        report.cycles_accepted >= iters,
        "accepted {} < {}",
        report.cycles_accepted,
        iters
    );
    assert_eq!(report.cycles_rejected, 0, "rejects={}", report.cycles_rejected);
    assert!(
        bundle_acc >= iters as usize,
        "bundle cycle_accept {} < {}",
        bundle_acc,
        iters
    );
    assert_eq!(rejects, 0);
    assert!(accepts >= iters as usize);
    assert!(attest_ok, "attest chain failed");

    eprintln!(
        "soak_bundle_mini: PASS iters={} accepted={} results={}",
        iters,
        report.cycles_accepted,
        results_dir.display()
    );
}
