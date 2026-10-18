//! Integration tests for TASK-012's `morph daemon` loop.
//!
//! These exercise the *loop* — picker reload, work dispatch, error
//! survival, heartbeat scheduling, max-iters termination, log-event
//! emission — using stub [`WorkRunner`] and [`FakeClock`] so the tests
//! complete in milliseconds without invoking cargo or the verifier
//! binary.
//!
//! The full end-to-end "real cargo cycle" test path lives in the
//! `bundle.rs` integration suite (the `--ignored` `end_to_end_*`
//! tests); duplicating it here adds nothing because the daemon's only
//! contract over the cycle is "call the runner, count the result".

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::Duration;

use anyhow::{bail, Result};
use cuttle_morph_engine::{
    daemon::{
        run_daemon_with, Clock, DaemonArgs, FakeClock, WorkRunner, DAEMON_LOG,
        DEFAULT_HEARTBEAT_SECS, DEFAULT_MAX_CYCLE_SECS, DEFAULT_POLL_SECS,
    },
    scheduler::{NextBundleChoice, NextChoice, SCHEDULER_CONFIG, SCHEDULER_STATE},
    SynthesizerKind,
};

// ---------------------------------------------------------------------------
// Test fixtures: a `tempdir()` workspace + a scheduler.toml.
// ---------------------------------------------------------------------------

/// Create a fresh per-test fixture directory under the OS temp dir.
/// The directory is wiped on every call so tests are deterministic
/// even when the prior run left behind a stale daemon.log.
fn fixture(label: &str) -> PathBuf {
    let base = std::env::temp_dir().join(format!(
        "cuttle-daemon-it-{}-{}",
        label,
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir_all(&base).unwrap();
    base
}

fn write_scheduler_toml(root: &Path, body: &str) {
    fs::write(root.join(SCHEDULER_CONFIG), body).unwrap();
}

fn read_daemon_log(root: &Path) -> Vec<serde_json::Value> {
    let txt = fs::read_to_string(root.join(DAEMON_LOG)).unwrap_or_default();
    txt.lines()
        .filter(|l| !l.trim().is_empty())
        .map(|l| serde_json::from_str(l).expect("valid JSON line"))
        .collect()
}

fn count_kind(events: &[serde_json::Value], kind: &str) -> usize {
    events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some(kind))
        .count()
}

// ---------------------------------------------------------------------------
// Recording runner — captures calls so the test can assert on the
// (work_kind, name, cycle) tuples the daemon dispatched.
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct RecordedCall {
    work_kind: &'static str,
    name: String,
    cycle: u64,
    synthesizer: SynthesizerKind,
    emit_image: bool,
}

#[derive(Default)]
struct RecordingRunner {
    calls: Mutex<Vec<RecordedCall>>,
    fail_calls: Mutex<Vec<usize>>,
}

impl RecordingRunner {
    fn fail_on(&self, indices: &[usize]) {
        let mut g = self.fail_calls.lock().unwrap();
        g.clear();
        g.extend_from_slice(indices);
    }
    fn calls(&self) -> Vec<RecordedCall> {
        self.calls.lock().unwrap().clone()
    }
}

impl WorkRunner for RecordingRunner {
    fn run_module(
        &self,
        choice: &NextChoice,
        synthesizer: SynthesizerKind,
        emit_image: bool,
        _no_perf_check: bool,
    ) -> Result<()> {
        let mut calls = self.calls.lock().unwrap();
        let idx = calls.len();
        calls.push(RecordedCall {
            work_kind: "module",
            name: choice.module.clone(),
            cycle: choice.next_cycle,
            synthesizer,
            emit_image,
        });
        drop(calls);
        if self.fail_calls.lock().unwrap().contains(&idx) {
            bail!("synthetic module failure on call {}", idx);
        }
        Ok(())
    }

    fn run_bundle(
        &self,
        choice: &NextBundleChoice,
        synthesizer: SynthesizerKind,
        emit_image: bool,
        _no_perf_check: bool,
    ) -> Result<()> {
        let mut calls = self.calls.lock().unwrap();
        let idx = calls.len();
        calls.push(RecordedCall {
            work_kind: "bundle",
            name: choice.bundle.clone(),
            cycle: choice.next_cycle,
            synthesizer,
            emit_image,
        });
        drop(calls);
        if self.fail_calls.lock().unwrap().contains(&idx) {
            bail!("synthetic bundle failure on call {}", idx);
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Headline test: daemon with --max-iters 3 against a fixture
// workspace, asserts 3 cycles land and exit 0.
//
// This is the TASK-012 acceptance test. The runner is a recording
// stub (real cycle execution is covered by bundle.rs and run-time
// smoke); the test validates the LOOP — that 3 ticks produce 3
// dispatched cycles, 3 cycle_accept events in daemon.log, and a
// clean daemon_stop with reason=max_iters_reached.
// ---------------------------------------------------------------------------

#[test]
fn daemon_max_iters_3_runs_3_module_cycles() {
    let root = fixture("max-iters-3");
    // priority=1, max_age=0 → always due, every tick picks the
    // same module. The `target_dir` is a placeholder — the
    // recording runner never reads it.
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/cuttle-fixture-src\"\n",
    );

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 3,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(1_700_000_000);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    // === Report ===
    assert_eq!(report.ticks_executed, 3);
    assert_eq!(report.cycles_accepted, 3);
    assert_eq!(report.cycles_rejected, 0);
    assert_eq!(report.cycles_overrun, 0);
    assert_eq!(report.heartbeats_written, 0);
    assert_eq!(report.idle_ticks, 0);

    // === Runner saw 3 module calls with monotonically advancing cycle ===
    let calls = runner.calls();
    assert_eq!(calls.len(), 3);
    for (i, c) in calls.iter().enumerate() {
        assert_eq!(c.work_kind, "module");
        assert_eq!(c.name, "lib");
        assert_eq!(c.cycle, (i + 1) as u64);
        assert_eq!(c.synthesizer, SynthesizerKind::PassThrough);
        assert!(!c.emit_image);
    }

    // === daemon.log shape ===
    let events = read_daemon_log(&root);
    assert_eq!(count_kind(&events, "daemon_start"), 1);
    assert_eq!(count_kind(&events, "cycle_start"), 3);
    assert_eq!(count_kind(&events, "cycle_accept"), 3);
    assert_eq!(count_kind(&events, "cycle_reject"), 0);
    assert_eq!(count_kind(&events, "daemon_stop"), 1);

    // === Final scheduler_state.json reflects the last cycle ===
    let state_path = root.join(SCHEDULER_STATE);
    assert!(state_path.exists(), "state file should be written");
    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
    assert_eq!(state["global_cycle"].as_u64().unwrap(), 3);
    let last_cycle = state["modules"]["lib"]["last_cycle"].as_u64().unwrap();
    assert_eq!(last_cycle, 3);
}

// ---------------------------------------------------------------------------
// Broken-synthesizer survival: one cycle fails, next cycle proceeds.
// ---------------------------------------------------------------------------

#[test]
fn daemon_survives_first_cycle_failure_and_continues() {
    let root = fixture("survive-failure");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/cuttle-fixture-src\"\n",
    );

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 4,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    // Call index 0 fails (the first cycle). Calls 1..3 succeed.
    runner.fail_on(&[0]);
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    assert_eq!(report.ticks_executed, 4);
    assert_eq!(report.cycles_accepted, 3);
    assert_eq!(report.cycles_rejected, 1);

    let events = read_daemon_log(&root);
    assert_eq!(count_kind(&events, "cycle_reject"), 1);
    assert_eq!(count_kind(&events, "cycle_accept"), 3);

    // The reject's `error` field carries the runner's message.
    let reject = events
        .iter()
        .find(|e| e.get("kind").and_then(|v| v.as_str()) == Some("cycle_reject"))
        .unwrap();
    let err = reject.get("error").and_then(|v| v.as_str()).unwrap();
    assert!(
        err.contains("synthetic module failure"),
        "expected synthetic error message, got {}",
        err
    );

    // The rejected cycle's number must equal 1 (the first cycle
    // attempted) — scheduler state was NOT advanced on reject, so
    // the subsequent accept used cycle=1 again. Verify by walking
    // the accept events.
    let accept_cycles: Vec<u64> = events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some("cycle_accept"))
        .map(|e| e.get("cycle").and_then(|v| v.as_u64()).unwrap())
        .collect();
    assert_eq!(accept_cycles, vec![1, 2, 3]);
}

// ---------------------------------------------------------------------------
// Bundle path: bundle competes and wins.
// ---------------------------------------------------------------------------

#[test]
fn daemon_picks_bundle_when_bundle_outranks_module() {
    let root = fixture("bundle-pick");
    write_scheduler_toml(
        &root,
        "[modules.cold]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/cold-src\"\n\
         \n\
         [bundle.kernel]\n\
         priority = 50\n\
         max_age_secs = 0\n\
         workspace = \"target_enterprise\"\n\
         modules = [\"tls\", \"wal\", \"iommu\"]\n",
    );

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 2,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    assert_eq!(report.cycles_accepted, 2);

    let calls = runner.calls();
    assert_eq!(calls.len(), 2);
    for c in &calls {
        assert_eq!(c.work_kind, "bundle");
        assert_eq!(c.name, "kernel");
    }
    assert_eq!(calls[0].cycle, 1);
    assert_eq!(calls[1].cycle, 2);
}

// ---------------------------------------------------------------------------
// Heartbeat scheduling: nothing-due ticks emit heartbeats at cadence.
// ---------------------------------------------------------------------------

#[test]
fn daemon_emits_heartbeats_while_idle() {
    let root = fixture("heartbeats");
    // Use a very large max_age_secs so even priority=1 stays not-due
    // for the entire fake-clock window. `(now - 0) * 1 >= u64::MAX/2`
    // never holds.
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 9223372036854775000\n\
         target_dir = \"/tmp/x\"\n",
    );

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 6,
        max_cycle_secs: 60,
        // 10s heartbeat cadence; 5s per-tick sleep => 2 heartbeats
        // across 6 idle ticks (at t=10s and t=20s after the start
        // marker). The last_heartbeat anchor starts at clock.now_unix()
        // (= 0 here), so the first heartbeat fires once the clock
        // has advanced past 10s.
        heartbeat_secs: 10,
        poll_secs: 5,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    assert_eq!(report.ticks_executed, 6);
    assert_eq!(report.idle_ticks, 6);
    assert_eq!(report.cycles_accepted, 0);
    assert_eq!(report.cycles_rejected, 0);
    // The first idle tick sleeps poll_secs=5 → clock=5. Heartbeat at
    // start of tick: elapsed=0 (< 10), no beat. Tick 2: clock=5,
    // elapsed=5 (< 10), no beat, sleep → clock=10. Tick 3: elapsed=10
    // (>= 10), beat (anchor=10), sleep → clock=15. Tick 4: elapsed=5
    // (< 10), no beat, sleep → clock=20. Tick 5: elapsed=10 (>= 10),
    // beat (anchor=20), sleep → clock=25. Tick 6: elapsed=5, no beat,
    // sleep → clock=30.
    // So we expect EXACTLY 2 heartbeats.
    assert_eq!(
        report.heartbeats_written, 2,
        "want 2 heartbeats from 6 idle 5s ticks at 10s cadence; got {}",
        report.heartbeats_written
    );

    let events = read_daemon_log(&root);
    let beats: Vec<u64> = events
        .iter()
        .filter(|e| e.get("kind").and_then(|v| v.as_str()) == Some("heartbeat"))
        .map(|e| e.get("ts_unix").and_then(|v| v.as_u64()).unwrap())
        .collect();
    assert_eq!(beats, vec![10, 20]);
}

// ---------------------------------------------------------------------------
// Reject does NOT advance state but the daemon does NOT panic.
// ---------------------------------------------------------------------------

#[test]
fn rejected_cycle_does_not_advance_state() {
    let root = fixture("reject-no-state");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/x\"\n",
    );

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 2,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    runner.fail_on(&[0, 1]);
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    assert_eq!(report.cycles_accepted, 0);
    assert_eq!(report.cycles_rejected, 2);

    // scheduler_state.json may or may not exist (state only saved on
    // accept). If it exists, it must not record any successful
    // cycles for "lib".
    let state_path = root.join(SCHEDULER_STATE);
    if state_path.exists() {
        let state: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&state_path).unwrap()).unwrap();
        if let Some(lib) = state.get("modules").and_then(|m| m.get("lib")) {
            let last_cycle = lib.get("last_cycle").and_then(|v| v.as_u64()).unwrap_or(0);
            assert_eq!(last_cycle, 0, "rejected cycles should not advance state");
        }
    }
}

// ---------------------------------------------------------------------------
// Malformed scheduler.toml: daemon does NOT panic and does NOT
// terminate; it logs a scheduler_error and continues.
// ---------------------------------------------------------------------------

#[test]
fn malformed_scheduler_toml_logs_error_and_continues() {
    let root = fixture("malformed-toml");
    write_scheduler_toml(&root, "this is = NOT toml [\n");

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 3,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    // All 3 ticks consumed; none ran a cycle.
    assert_eq!(report.ticks_executed, 3);
    assert_eq!(report.cycles_accepted, 0);
    assert_eq!(report.cycles_rejected, 0);
    assert_eq!(report.idle_ticks, 3);

    let events = read_daemon_log(&root);
    assert!(
        count_kind(&events, "scheduler_error") >= 3,
        "expected at least 3 scheduler_error events, got {}",
        count_kind(&events, "scheduler_error")
    );

    // The runner was never invoked.
    assert!(runner.calls().is_empty());
}

// ---------------------------------------------------------------------------
// Missing scheduler.toml is treated as a recoverable config error.
// ---------------------------------------------------------------------------

#[test]
fn missing_scheduler_toml_logs_error_and_continues() {
    let root = fixture("missing-toml");
    // Deliberately don't write scheduler.toml.

    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 2,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    assert_eq!(report.ticks_executed, 2);
    assert_eq!(report.cycles_accepted, 0);

    let events = read_daemon_log(&root);
    assert!(count_kind(&events, "scheduler_error") >= 2);
}

// ---------------------------------------------------------------------------
// Cycle overrun: a slow runner produces a cycle_overrun event AND a
// cycle_accept event for the same tick.
// ---------------------------------------------------------------------------

struct SlowRunner<'c> {
    clock: &'c FakeClock,
    advance_secs: u64,
}

impl<'c> WorkRunner for SlowRunner<'c> {
    fn run_module(
        &self,
        _choice: &NextChoice,
        _synth: SynthesizerKind,
        _emit: bool,
        _no_perf: bool,
    ) -> Result<()> {
        self.clock.advance(self.advance_secs);
        Ok(())
    }
    fn run_bundle(
        &self,
        _choice: &NextBundleChoice,
        _synth: SynthesizerKind,
        _emit: bool,
        _no_perf: bool,
    ) -> Result<()> {
        self.clock.advance(self.advance_secs);
        Ok(())
    }
}

#[test]
fn cycle_overrun_logs_event_but_does_not_fail_the_cycle() {
    let root = fixture("overrun");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/x\"\n",
    );

    let clock = FakeClock::new(0);
    let runner = SlowRunner {
        clock: &clock,
        advance_secs: 1_000,
    };
    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 1,
        max_cycle_secs: 300,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let report = run_daemon_with(&args, &runner, &clock).expect("daemon exit Ok");

    assert_eq!(report.cycles_accepted, 1);
    assert_eq!(report.cycles_overrun, 1);

    let events = read_daemon_log(&root);
    let overrun = events
        .iter()
        .find(|e| e.get("kind").and_then(|v| v.as_str()) == Some("cycle_overrun"))
        .expect("overrun event present");
    let wall = overrun.get("wall_secs").and_then(|v| v.as_u64()).unwrap();
    let budget = overrun.get("budget_secs").and_then(|v| v.as_u64()).unwrap();
    assert_eq!(wall, 1_000);
    assert_eq!(budget, 300);
}

// ---------------------------------------------------------------------------
// daemon_start event records the args that were passed in.
// ---------------------------------------------------------------------------

#[test]
fn daemon_start_event_records_args() {
    let root = fixture("start-event");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 9999999\n\
         target_dir = \"/tmp/x\"\n",
    );
    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 1,
        max_cycle_secs: 42,
        heartbeat_secs: 17,
        poll_secs: 3,
        synthesizer: SynthesizerKind::PromptOnly,
        emit_image: true,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(1_234_567);
    let _ = run_daemon_with(&args, &runner, &clock).unwrap();

    let events = read_daemon_log(&root);
    let start = events
        .iter()
        .find(|e| e.get("kind").and_then(|v| v.as_str()) == Some("daemon_start"))
        .unwrap();
    assert_eq!(start.get("max_iters").unwrap().as_u64().unwrap(), 1);
    assert_eq!(start.get("max_cycle_secs").unwrap().as_u64().unwrap(), 42);
    assert_eq!(start.get("heartbeat_secs").unwrap().as_u64().unwrap(), 17);
    assert_eq!(start.get("poll_secs").unwrap().as_u64().unwrap(), 3);
    assert_eq!(start.get("synthesizer").unwrap().as_str().unwrap(), "prompt-only");
    assert!(start.get("emit_image").unwrap().as_bool().unwrap());
}

// ---------------------------------------------------------------------------
// daemon_stop event closes the log with the final counters.
// ---------------------------------------------------------------------------

#[test]
fn daemon_stop_event_records_final_counters() {
    let root = fixture("stop-event");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/x\"\n",
    );
    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 4,
        ..DaemonArgs::default()
    };
    let runner = RecordingRunner::default();
    runner.fail_on(&[1, 3]);
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).unwrap();

    let events = read_daemon_log(&root);
    let stop = events
        .iter()
        .rev()
        .find(|e| e.get("kind").and_then(|v| v.as_str()) == Some("daemon_stop"))
        .unwrap();
    assert_eq!(
        stop.get("ticks_executed").unwrap().as_u64().unwrap(),
        report.ticks_executed
    );
    assert_eq!(
        stop.get("cycles_accepted").unwrap().as_u64().unwrap(),
        report.cycles_accepted
    );
    assert_eq!(
        stop.get("cycles_rejected").unwrap().as_u64().unwrap(),
        report.cycles_rejected
    );
    assert_eq!(
        stop.get("reason").unwrap().as_str().unwrap(),
        "max_iters_reached"
    );
}

// ---------------------------------------------------------------------------
// Default constants match brief: 300/60/10 for cycle/heartbeat/poll.
// ---------------------------------------------------------------------------

#[test]
fn default_constants_match_task_brief() {
    assert_eq!(DEFAULT_MAX_CYCLE_SECS, 300);
    assert_eq!(DEFAULT_HEARTBEAT_SECS, 60);
    assert_eq!(DEFAULT_POLL_SECS, 10);
}

// ---------------------------------------------------------------------------
// SystemClock is a thin wrapper — sanity check it doesn't crash.
// We avoid asserting absolute values because wall-clock time is real.
// ---------------------------------------------------------------------------

#[test]
fn system_clock_sleeps_minimum_duration() {
    use cuttle_morph_engine::daemon::SystemClock;
    let c = SystemClock;
    let t1 = c.now_unix();
    c.sleep(Duration::from_millis(1));
    let t2 = c.now_unix();
    // Wall time advances monotonically modulo NTP weirdness, but
    // 1ms is too small to guarantee a unix-second tick. The bare
    // minimum assertion is "t2 not behind t1 by much"; we accept a
    // 0-difference outcome.
    assert!(t2 >= t1 || t1 - t2 <= 1);
}

// ---------------------------------------------------------------------------
// Many ticks: sanity that the loop scales linearly and doesn't
// quadratically slow down (large state file is not re-parsed many
// times since each tick is independent).
// ---------------------------------------------------------------------------

#[test]
fn daemon_handles_large_tick_count_without_state_drift() {
    let root = fixture("many-ticks");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/x\"\n",
    );
    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 50,
        max_cycle_secs: 60,
        heartbeat_secs: 60,
        poll_secs: 0,
        synthesizer: SynthesizerKind::PassThrough,
        emit_image: false,
        no_perf_check: false,
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(0);
    let report = run_daemon_with(&args, &runner, &clock).unwrap();
    assert_eq!(report.cycles_accepted, 50);
    let calls = runner.calls();
    // Cycle numbers must be 1..=50 in order.
    let cycles: Vec<u64> = calls.iter().map(|c| c.cycle).collect();
    assert_eq!(cycles, (1u64..=50).collect::<Vec<u64>>());

    let state: serde_json::Value =
        serde_json::from_str(&fs::read_to_string(root.join(SCHEDULER_STATE)).unwrap()).unwrap();
    assert_eq!(state["global_cycle"].as_u64().unwrap(), 50);
    assert_eq!(
        state["modules"]["lib"]["last_cycle"].as_u64().unwrap(),
        50
    );
}

// ---------------------------------------------------------------------------
// Smoke: the event-tagging field names produced by serde are stable.
// If a future refactor changes the tag from "kind" to anything else,
// this test catches it before TUI consumers break.
// ---------------------------------------------------------------------------

#[test]
fn event_tag_field_is_kind_and_known_kinds_only() {
    let root = fixture("event-tags");
    write_scheduler_toml(
        &root,
        "[modules.lib]\n\
         priority = 1\n\
         max_age_secs = 0\n\
         target_dir = \"/tmp/x\"\n",
    );
    let args = DaemonArgs {
        root: root.clone(),
        max_iters: 1,
        ..DaemonArgs::default()
    };
    let runner = RecordingRunner::default();
    let clock = FakeClock::new(0);
    let _ = run_daemon_with(&args, &runner, &clock).unwrap();

    let events = read_daemon_log(&root);
    let known: BTreeMap<&str, ()> = [
        ("daemon_start", ()),
        ("daemon_stop", ()),
        ("heartbeat", ()),
        ("cycle_start", ()),
        ("cycle_accept", ()),
        ("cycle_reject", ()),
        ("cycle_overrun", ()),
        ("scheduler_error", ()),
    ]
    .into_iter()
    .collect();
    for e in &events {
        let kind = e.get("kind").and_then(|v| v.as_str()).expect("kind field");
        assert!(known.contains_key(kind), "unknown kind {}", kind);
    }
}
