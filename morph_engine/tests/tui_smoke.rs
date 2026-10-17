//! Headless smoke test for `morph tui`.
//!
//! We can't reliably inject keystrokes from a `Command::spawn` on
//! Windows (no real TTY when stdout is piped), so the TUI exposes a
//! hidden `--ticks <N>` flag that swaps the live crossterm backend for
//! a `ratatui::backend::TestBackend`. This test drives that path with a
//! minimal fixture under a temp dir and asserts exit code 0 + empty
//! stderr.

use std::fs;
use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_tempdir(tag: &str) -> PathBuf {
    let mut p = std::env::temp_dir();
    let nonce = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    p.push(format!("proteus_tui_smoke_{}_{}", tag, nonce));
    fs::create_dir_all(&p).unwrap();
    p
}

fn write_fixture(dir: &PathBuf) {
    fs::write(
        dir.join("scheduler.toml"),
        r#"[modules.lib]
priority = 10
max_age_secs = 3600
target_dir = "target_minimal/src"
manifest = "target_minimal/manifest.txt"

[modules.aux]
priority = 1
max_age_secs = 7200
target_dir = "target_minimal/src"
"#,
    )
    .unwrap();

    // Two attestation entries, one accepted, one not. Both are
    // tolerant-parsed (schema_version=2, no cosigs).
    fs::write(
        dir.join("attest.log.jsonl"),
        "{\"schema_version\":2,\"cycle\":700,\"ts_unix\":1778900613,\"module\":\"lib\",\
\"candidate_sha256\":\"aff2812fbe05e4531e3bc7950f2eb9c7a13e4cdf2a99c30abb4a007508c403c4\",\
\"sig_ed25519\":\"deadbeef\",\"accepted\":true,\"synthesizer\":\"passthrough\",\
\"prev_entry_sha256\":\"0000000000000000000000000000000000000000000000000000000000000000\",\
\"entry_sha256\":\"22572243\"}\n\
{\"schema_version\":2,\"cycle\":800,\"ts_unix\":1778900632,\"module\":\"lib\",\
\"candidate_sha256\":\"5266bb81d6b1987de029bc0f06482d21fe516e07fedbb537c8a6ec9a6803d658\",\
\"sig_ed25519\":\"00\",\"accepted\":false,\"synthesizer\":\"passthrough\",\
\"prev_entry_sha256\":\"22572243\",\"entry_sha256\":\"052be8c4\"}\n",
    )
    .unwrap();

    fs::write(
        dir.join("perf.jsonl"),
        "{\"ts_unix\":1778901425,\"fletcher32_ns\":20,\"feistel_mix_ns\":5,\
\"derive_byte_ns\":23,\"demohash_ns\":21,\"demosyscall_ns\":8,\
\"demosigverify_ns\":2027}\n\
{\"ts_unix\":1778901431,\"fletcher32_ns\":19,\"feistel_mix_ns\":4,\
\"derive_byte_ns\":23,\"demohash_ns\":21,\"demosyscall_ns\":8,\
\"demosigverify_ns\":2029}\n\
{\"ts_unix\":1778901437,\"fletcher32_ns\":27,\"feistel_mix_ns\":4,\
\"derive_byte_ns\":23,\"demohash_ns\":21,\"demosyscall_ns\":7,\
\"demosigverify_ns\":2016}\n",
    )
    .unwrap();

    fs::write(
        dir.join("factory_keys.toml"),
        r#"threshold = 2

[[signers]]
id = "primary"
pubkey_hex = "00"

[[signers]]
id = "a"
pubkey_hex = "01"

[[signers]]
id = "b"
pubkey_hex = "02"
"#,
    )
    .unwrap();
}

#[test]
fn tui_ticks_one_exits_clean() {
    let dir = unique_tempdir("ticks1");
    write_fixture(&dir);

    let exe = env!("CARGO_BIN_EXE_morph");
    let output = Command::new(exe)
        .args(["tui", "--root", dir.to_str().unwrap(), "--ticks", "1"])
        .output()
        .expect("spawn morph");

    assert!(
        output.status.success(),
        "morph tui --ticks 1 exited with status {:?}\nstdout: {}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr),
    );
    assert!(
        output.stderr.is_empty(),
        "expected empty stderr, got: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}

#[test]
fn tui_ticks_multiple_exits_clean() {
    let dir = unique_tempdir("ticks5");
    write_fixture(&dir);

    let exe = env!("CARGO_BIN_EXE_morph");
    let output = Command::new(exe)
        .args(["tui", "--root", dir.to_str().unwrap(), "--ticks", "5"])
        .output()
        .expect("spawn morph");

    assert!(output.status.success(), "exit status: {:?}", output.status);
    assert!(output.stderr.is_empty());
}

#[test]
fn tui_ticks_works_on_empty_workspace() {
    // No fixture files written at all — virgin workspace case.
    let dir = unique_tempdir("empty");

    let exe = env!("CARGO_BIN_EXE_morph");
    let output = Command::new(exe)
        .args(["tui", "--root", dir.to_str().unwrap(), "--ticks", "2"])
        .output()
        .expect("spawn morph");

    // Even with no scheduler.toml the TUI must exit cleanly; the
    // missing-file case is rendered as a banner, not a fatal error.
    assert!(
        output.status.success(),
        "expected clean exit on virgin workspace, got {:?}\nstderr: {}",
        output.status.code(),
        String::from_utf8_lossy(&output.stderr),
    );
}

#[test]
fn tui_rejects_unknown_flag() {
    let exe = env!("CARGO_BIN_EXE_morph");
    let output = Command::new(exe)
        .args(["tui", "--nonsense"])
        .output()
        .expect("spawn morph");
    assert!(!output.status.success(), "should exit non-zero");
}
