//! CLI integration tests for `factory_builder`.
//!
//! Exercise the public surface that the morph engine calls into:
//! - rejects-missing-file, rejects-non-elf, rejects-empty
//! - exits non-zero with a clear stderr message on each
//! - prints a parseable `bios <abs-path> <hex-sha256>` line on success
//!   (real success requires the out-of-workspace `factory_builder_pkg`
//!   crate to be present + nightly; covered in `qemu_smoke.rs`)
//!
//! The bulk of the validation logic is covered by unit tests in
//! `src/lib.rs`. These tests exercise the CLI plumbing on top.

use std::path::PathBuf;
use std::process::Command;

fn factory_builder_bin() -> PathBuf {
    // CARGO_BIN_EXE_<name> is auto-injected by cargo for integration
    // tests of bin targets in the same package.
    PathBuf::from(env!("CARGO_BIN_EXE_factory_builder"))
}

fn tmpdir(label: &str) -> PathBuf {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .subsec_nanos();
    let p = std::env::temp_dir().join(format!(
        "factory_builder_cli_{}_{}_{}",
        label,
        std::process::id(),
        nanos
    ));
    std::fs::create_dir_all(&p).unwrap();
    p
}

#[test]
fn no_args_exits_nonzero_with_usage() {
    let out = Command::new(factory_builder_bin())
        .output()
        .expect("spawn factory_builder");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("usage:") || stderr.contains("no arguments"),
        "expected usage hint, got: {}",
        stderr
    );
}

#[test]
fn rejects_missing_candidate_file() {
    let dir = tmpdir("missing");
    let bogus = dir.join("does-not-exist.elf");
    let out_img = dir.join("out.img");
    let out = Command::new(factory_builder_bin())
        .args(["--candidate"])
        .arg(&bogus)
        .args(["--out"])
        .arg(&out_img)
        .output()
        .expect("spawn factory_builder");
    assert!(!out.status.success(), "must exit non-zero on missing file");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not found"),
        "stderr should mention 'not found': {}",
        stderr
    );
}

#[test]
fn rejects_empty_file_as_not_elf() {
    let dir = tmpdir("empty");
    let empty = dir.join("empty.bin");
    std::fs::write(&empty, []).unwrap();
    let out_img = dir.join("out.img");
    let out = Command::new(factory_builder_bin())
        .args(["--candidate"])
        .arg(&empty)
        .args(["--out"])
        .arg(&out_img)
        .output()
        .expect("spawn factory_builder");
    assert!(!out.status.success(), "must reject empty file");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("not an ELF") || stderr.contains("magic"),
        "stderr should mention ELF/magic: {}",
        stderr
    );
}

#[test]
fn rejects_random_bytes_as_not_elf() {
    let dir = tmpdir("random");
    let p = dir.join("garbage.bin");
    std::fs::write(&p, b"MZ\x90\x00not-an-elf-at-all-just-PE-magic-bytes").unwrap();
    let out_img = dir.join("out.img");
    let out = Command::new(factory_builder_bin())
        .args(["--candidate"])
        .arg(&p)
        .args(["--out"])
        .arg(&out_img)
        .output()
        .expect("spawn factory_builder");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("magic mismatch") || stderr.contains("not an ELF"));
}

#[test]
fn missing_required_flag_errors_out() {
    // --candidate present but --out missing.
    let dir = tmpdir("noout");
    let p = dir.join("magic.bin");
    std::fs::write(&p, b"\x7FELF\x00\x00\x00\x00\x00").unwrap();
    let out = Command::new(factory_builder_bin())
        .args(["--candidate"])
        .arg(&p)
        .output()
        .expect("spawn factory_builder");
    assert!(!out.status.success(), "must require --out");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--out") || stderr.contains("required"),
        "expected --out hint, got: {}",
        stderr
    );
}

#[test]
fn unknown_flag_errors_out() {
    let out = Command::new(factory_builder_bin())
        .args(["--frobnicate", "yes"])
        .output()
        .expect("spawn factory_builder");
    assert!(!out.status.success());
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("unknown argument"),
        "expected 'unknown argument', got: {}",
        stderr
    );
}

#[test]
fn build_kernel_subcommand_requires_kernel_crate_flag() {
    let out = Command::new(factory_builder_bin())
        .args(["build-kernel"])
        .output()
        .expect("spawn factory_builder build-kernel");
    assert!(!out.status.success(), "must require --kernel-crate");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(
        stderr.contains("--kernel-crate") || stderr.contains("required"),
        "expected --kernel-crate hint, got: {}",
        stderr
    );
}

#[test]
fn help_flag_succeeds() {
    let out = Command::new(factory_builder_bin())
        .args(["--help"])
        .output()
        .expect("spawn factory_builder --help");
    assert!(out.status.success(), "--help must exit 0");
    let stderr = String::from_utf8_lossy(&out.stderr);
    assert!(stderr.contains("usage:"));
}
