//! Short morph-daemon soak — unattended multi-cycle factory proof.
//!
//! Drives the **production** daemon + work runner against
//! `target_minimal` for N accept cycles (default 3), then checks:
//!
//! 1. `DaemonReport.cycles_accepted >= N` and `cycles_rejected == 0`
//! 2. `daemon.log` has ≥ N `cycle_accept` events and 0 `cycle_reject`
//! 3. Attestation chain under the soak `CUTTLE_ATTEST_DIR` verifies
//! 4. `target_minimal/src/lib.rs` is restored from `.last_good.rs`
//!
//! # Invocation
//!
//! ```text
//! $env:CUTTLE_SOAK_SHORT = "1"
//! # optional: $env:CUTTLE_SOAK_ITERS = "5"
//! cargo test -p cuttle-morph-engine --test soak_short -- --nocapture
//! ```
//!
//! Or: `tools/soak_short.ps1`
//!
//! Requires: built `verify` sibling (cargo builds it as a workspace
//! dep when morph-engine tests link), `factory_signing_key.bin` at
//! the workspace root, and a writable workspace.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use cuttle_morph_engine::{
    daemon::{run_daemon, DaemonArgs, DaemonReport, DAEMON_LOG},
    verify_chain_with_options, SynthesizerKind, VerifyOptions, ATTEST_DIR_ENV,
};

/// Serialize so concurrent soak runs cannot race on target_minimal
/// or the env-based attest dir.
static SOAK_MUTEX: Mutex<()> = Mutex::new(());

fn workspace_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("morph_engine parent")
        .to_path_buf()
}

fn soak_root() -> PathBuf {
    workspace_root().join("experiments").join("soak_short")
}

fn count_kind(events: &[serde_json::Value], kind: &str) -> usize {
    events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .count()
}

fn read_jsonl_events(path: &Path) -> Vec<serde_json::Value> {
    let txt = fs::read_to_string(path).unwrap_or_default();
    txt.lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect()
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
    let body = format!(
        "# Short morph-daemon soak REPORT\n\n\
         ## Config\n\n\
         - Module: `target_minimal` / `lib` (passthrough synthesizer)\n\
         - Requested accepted cycles: {iters}\n\
         - Results dir: `{results}`\n\n\
         ## DaemonReport\n\n\
         - ticks_executed: {ticks}\n\
         - cycles_accepted: {acc}\n\
         - cycles_rejected: {rej}\n\
         - cycles_overrun: {ovr}\n\
         - idle_ticks: {idle}\n\
         - heartbeats_written: {hb}\n\n\
         ## daemon.log\n\n\
         - cycle_accept events: {elog_acc}\n\
         - cycle_reject events: {elog_rej}\n\n\
         ## Attestation\n\n\
         - `verify-attest` (chain from genesis): {attest}\n\n\
         ## Verdict\n\n\
         {verdict}\n",
        iters = iters,
        results = results_dir.display(),
        ticks = report.ticks_executed,
        acc = report.cycles_accepted,
        rej = report.cycles_rejected,
        ovr = report.cycles_overrun,
        idle = report.idle_ticks,
        hb = report.heartbeats_written,
        elog_acc = accepts,
        elog_rej = rejects,
        attest = if attest_ok { "PASS" } else { "FAIL" },
        verdict = if report.cycles_accepted >= iters
            && report.cycles_rejected == 0
            && accepts >= iters as usize
            && rejects == 0
            && attest_ok
        {
            "**PASS** — short soak met all acceptance criteria."
        } else {
            "**FAIL** — see counters above."
        },
    );
    let _ = fs::write(results_dir.join("REPORT.md"), body);
}

#[test]
fn short_daemon_soak_three_accepts() {
    if std::env::var("CUTTLE_SOAK_SHORT").as_deref() != Ok("1") {
        eprintln!(
            "SKIP: set CUTTLE_SOAK_SHORT=1 to run the short morph-daemon soak \
             (real cargo verify × N cycles; several minutes)"
        );
        return;
    }

    let _g = SOAK_MUTEX.lock().unwrap_or_else(|e| e.into_inner());
    let root = workspace_root();
    let soak = soak_root();
    assert!(
        soak.join("scheduler.toml").exists(),
        "missing {}; commit experiments/soak_short/scheduler.toml",
        soak.join("scheduler.toml").display()
    );

    let iters: u64 = std::env::var("CUTTLE_SOAK_ITERS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(3);
    assert!(iters >= 1 && iters <= 20, "CUTTLE_SOAK_ITERS out of range 1..=20");

    // Ensure signing key exists (morph stage 4).
    let key = root.join("factory_signing_key.bin");
    assert!(
        key.exists(),
        "factory_signing_key.bin missing at {}; run `morph init-key`",
        key.display()
    );

    // Ensure verify binary is buildable / present for cycle stage 3.
    let verify_status = Command::new("cargo")
        .args(["build", "-p", "cuttle-verifier", "--bin", "verify"])
        .current_dir(&root)
        .status()
        .expect("cargo build verify");
    assert!(verify_status.success(), "failed to build verify binary");

    // Snapshot target_minimal lib so we can restore after morph deploys.
    let lib_path = root.join("target_minimal").join("src").join("lib.rs");
    let lib_before = fs::read_to_string(&lib_path).expect("read lib.rs before soak");

    // Fresh results dir + clean scheduler state for this run.
    let run_id = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let results_dir = soak.join("results").join(format!("run_{}", run_id));
    fs::create_dir_all(&results_dir).expect("create results dir");

    // Isolate perf.jsonl: the production baseline was measured on a
    // quiet host and absolute-ns fields (feistel_mix at 5 ns) flap
    // under load when the soak runs. A short soak proves the *loop*
    // (accept/attest/deploy), not the perf envelope — that has its own
    // suite. Move the live baseline aside and leave an empty file so
    // the verifier takes the documented "no baseline → skip perf gate"
    // path. Restored in the cleanup block below.
    let perf_path = root.join("perf.jsonl");
    let perf_bak = results_dir.join("perf.jsonl.production.bak");
    let had_perf = perf_path.exists();
    if had_perf {
        fs::copy(&perf_path, &perf_bak).expect("backup perf.jsonl");
        fs::write(&perf_path, "").expect("clear perf.jsonl for soak");
    }

    // Point attest log at the soak results dir so we don't append to
    // the operator's production chain. (set_var is unsafe on Rust 2024
    // edition — process-wide env mutation.)
    let prev_attest = std::env::var_os(ATTEST_DIR_ENV);
    unsafe {
        std::env::set_var(ATTEST_DIR_ENV, &results_dir);
    }

    // Copy soak scheduler into place; wipe state so global_cycle starts 0.
    let state_path = soak.join("scheduler_state.json");
    let _ = fs::remove_file(&state_path);
    // daemon.log for this root
    let daemon_log = soak.join(DAEMON_LOG);
    let _ = fs::remove_file(&daemon_log);

    // Morph must resolve relative paths from workspace root.
    // run_daemon uses absolute paths from scheduler.toml; those are
    // workspace-relative, so set CWD via std::env::set_current_dir.
    let prev_cwd = std::env::current_dir().expect("cwd");
    std::env::set_current_dir(&root).expect("cd workspace root");

    let args = DaemonArgs {
        root: soak.clone(),
        max_iters: iters,
        max_cycle_secs: 600, // generous: verify scratch can be slow cold
        heartbeat_secs: 3600,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        // Semantics-only soak: absolute-ns perf baselines flap under
        // load and would reject a green golden path (measured earlier).
        no_perf_check: true,
    };

    eprintln!(
        "soak_short: starting daemon max_iters={} root={} attest_dir={}",
        iters,
        soak.display(),
        results_dir.display()
    );

    let report = match run_daemon(&args) {
        Ok(r) => r,
        Err(e) => {
            // Restore env/cwd before panicking.
            std::env::set_current_dir(&prev_cwd).ok();
            unsafe {
                match prev_attest {
                    Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
                    None => std::env::remove_var(ATTEST_DIR_ENV),
                }
            }
            // Restore lib + perf baseline if morph deployed mid-failure.
            let _ = fs::write(&lib_path, &lib_before);
            if had_perf {
                let _ = fs::copy(&perf_bak, &perf_path);
            }
            panic!("run_daemon failed: {:#}", e);
        }
    };

    eprintln!(
        "soak_short: DaemonReport accepted={} rejected={} ticks={} idle={}",
        report.cycles_accepted, report.cycles_rejected, report.ticks_executed, report.idle_ticks
    );

    // Copy daemon log + state into results for the report archive.
    if daemon_log.exists() {
        let _ = fs::copy(&daemon_log, results_dir.join(DAEMON_LOG));
    }
    if state_path.exists() {
        let _ = fs::copy(&state_path, results_dir.join("scheduler_state.json"));
    }

    let events = read_jsonl_events(&daemon_log);
    let accepts = count_kind(&events, "cycle_accept");
    let rejects = count_kind(&events, "cycle_reject");
    eprintln!(
        "soak_short: daemon.log cycle_accept={} cycle_reject={}",
        accepts, rejects
    );

    // Attestation chain under CUTTLE_ATTEST_DIR.
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
                "soak_short: verify-attest ok entries_ok={} anchors_ok={}",
                rep.entries_ok, rep.anchors_ok
            );
            true
        }
        Err(e) => {
            eprintln!("soak_short: verify-attest FAILED: {:#}", e);
            false
        }
    };

    write_report(&results_dir, &report, &events, attest_ok, iters);
    eprintln!(
        "soak_short: REPORT written to {}",
        results_dir.join("REPORT.md").display()
    );

    // Restore target_minimal source to pre-soak bytes.
    // Prefer last_good if the cycle left one that matches pre-soak
    // content length-ish; otherwise write the snapshot we took.
    let last_good = root
        .join("target_minimal")
        .join("src")
        .join("lib.last_good.rs");
    if last_good.exists() {
        // last_good is the pre-morph content of the *last* cycle, which
        // may itself be a prior morph. Restore the absolute pre-soak
        // snapshot for determinism of the workspace tree.
        let _ = last_good;
    }
    fs::write(&lib_path, &lib_before).expect("restore lib.rs after soak");
    // Clean candidate litter if any.
    let cand = root
        .join("target_minimal")
        .join("src")
        .join("lib.candidate.rs");
    let _ = fs::remove_file(cand);

    // Restore production perf baseline (and the soak-written samples
    // stay in results_dir if the verifier appended any).
    if had_perf {
        // If the soak wrote samples into perf.jsonl, park them.
        if let Ok(soak_perf) = fs::read_to_string(&perf_path) {
            if !soak_perf.trim().is_empty() {
                let _ = fs::write(results_dir.join("perf.jsonl.soak_samples"), soak_perf);
            }
        }
        fs::copy(&perf_bak, &perf_path).expect("restore production perf.jsonl");
    }

    // Restore env + cwd.
    std::env::set_current_dir(&prev_cwd).ok();
    unsafe {
        match prev_attest {
            Some(v) => std::env::set_var(ATTEST_DIR_ENV, v),
            None => std::env::remove_var(ATTEST_DIR_ENV),
        }
    }

    // Assertions — the pass bar.
    assert_eq!(
        report.ticks_executed, iters,
        "daemon should run exactly max_iters ticks"
    );
    assert!(
        report.cycles_accepted >= iters,
        "expected ≥ {} accepts, got {}",
        iters,
        report.cycles_accepted
    );
    assert_eq!(
        report.cycles_rejected, 0,
        "short soak must have zero rejects; got {}",
        report.cycles_rejected
    );
    assert!(
        accepts >= iters as usize,
        "daemon.log cycle_accept count {} < {}",
        accepts,
        iters
    );
    assert_eq!(rejects, 0, "daemon.log has cycle_reject events");
    assert!(attest_ok, "attestation chain failed verify-attest");

    // Restored source must match pre-soak snapshot.
    let lib_after = fs::read_to_string(&lib_path).expect("read lib after restore");
    assert_eq!(
        lib_after, lib_before,
        "target_minimal/src/lib.rs was not restored to pre-soak content"
    );

    eprintln!(
        "soak_short: PASS iters={} accepted={} attest=ok results={}",
        iters,
        report.cycles_accepted,
        results_dir.display()
    );
}
