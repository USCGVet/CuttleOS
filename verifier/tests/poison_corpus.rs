//! Permanent poison corpus for the Proteus verifier.
//!
//! # Why this exists
//!
//! The load-bearing safety claim is: **bad candidates never ACCEPT**.
//! Without a permanent, multi-stage reject corpus, a future refactor
//! can silently stop rejecting a whole class of bad morphs (parse
//! poison, manifest shrink, surface regression, zero diversity,
//! semantic golden break) and CI still goes green.
//!
//! # Layers
//!
//! 1. **Static unit path** (default `cargo test`): drives
//!    [`proteus_verifier::evaluate_static`] against every static
//!    poison fixture. No rustc of the candidate. Always on.
//! 2. **Binary smoke path** (default `cargo test`): spawns the real
//!    `verify` binary against static poisons with `--no-perf-check`.
//!    Static rejects exit 1 *before* the scratch cargo build, so these
//!    stay fast.
//! 3. **Semantic e2e** (`#[ignore]` / `PROTEUS_VERIFIER_POISON_E2E=1`):
//!    the existing `broken_fletcher32` fixture — golden-test reject
//!    after a real cargo build.
//!
//! A corpus case that ACCEPTs is a hard test failure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

use proteus_verifier::{
    evaluate_static, parse_manifest_str, StaticCheckInput, StaticCheckOutcome, StaticRejectReason,
};

fn fixtures_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join("poison")
}

fn read_fixture(name: &str) -> String {
    let p = fixtures_dir().join(name);
    std::fs::read_to_string(&p).unwrap_or_else(|e| {
        panic!("read poison fixture {}: {}", p.display(), e);
    })
}

fn target_minimal_manifest() -> BTreeSet<String> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("target_minimal")
        .join("manifest.txt");
    let body = std::fs::read_to_string(&p).expect("read target_minimal/manifest.txt");
    parse_manifest_str(&body)
}

// =====================================================================
// Layer 1 — pure static evaluate_static (always on)
// =====================================================================

#[test]
fn poison_syntax_error_static() {
    let src = read_fixture("syntax_error.rs");
    let empty = BTreeSet::new();
    let out = evaluate_static(&StaticCheckInput {
        candidate: &src,
        previous: None,
        required_pub: &empty,
    });
    assert_eq!(
        out.reject_tag(),
        Some("parse_failed"),
        "syntax poison must hit parse stage: {:?}",
        out
    );
}

#[test]
fn poison_missing_manifest_symbol_static() {
    let src = read_fixture("missing_manifest_symbol.rs");
    let req = target_minimal_manifest();
    let out = evaluate_static(&StaticCheckInput {
        candidate: &src,
        previous: None,
        required_pub: &req,
    });
    match out {
        StaticCheckOutcome::Reject {
            reason: StaticRejectReason::MissingManifestSymbols { missing },
        } => {
            assert!(
                missing.iter().any(|m| m == "fletcher32"),
                "expected fletcher32 in missing set, got {:?}",
                missing
            );
        }
        other => panic!("expected missing_manifest_symbols, got {:?}", other),
    }
}

#[test]
fn poison_removed_previous_symbol_static() {
    let cand = read_fixture("removed_previous_symbol.rs");
    let prev = read_fixture("previous_full_surface.rs");
    let empty = BTreeSet::new();
    let out = evaluate_static(&StaticCheckInput {
        candidate: &cand,
        previous: Some(&prev),
        required_pub: &empty,
    });
    match out {
        StaticCheckOutcome::Reject {
            reason: StaticRejectReason::RemovedPreviousSymbol { name },
        } => assert_eq!(name, "drop_me"),
        other => panic!("expected removed_previous_symbol, got {:?}", other),
    }
}

#[test]
fn poison_canonical_duplicate_static() {
    let src = read_fixture("canonical_duplicate.rs");
    // Whitespace-only reformat of the same AST.
    let prev = src.replace("morph_me()", "morph_me ( )");
    let empty = BTreeSet::new();
    let out = evaluate_static(&StaticCheckInput {
        candidate: &src,
        previous: Some(&prev),
        required_pub: &empty,
    });
    assert_eq!(
        out.reject_tag(),
        Some("canonical_duplicate"),
        "whitespace-only reformat must be treated as zero diversity: {:?}",
        out
    );
}

/// Meta-gate: every static poison file on disk is classified by the
/// table below and must reject with the expected tag. Adding a new
/// static fixture without extending this table is a test failure.
#[test]
fn poison_corpus_table_covers_all_static_fixtures() {
    let table: &[(&str, Option<&str>, &str)] = &[
        // (fixture, previous_fixture, expected_tag)
        ("syntax_error.rs", None, "parse_failed"),
        ("missing_manifest_symbol.rs", None, "missing_manifest_symbols"),
        (
            "removed_previous_symbol.rs",
            Some("previous_full_surface.rs"),
            "removed_previous_symbol",
        ),
        // canonical_duplicate uses itself as previous after a
        // whitespace rewrite; handled in its dedicated test.
    ];

    let req = target_minimal_manifest();
    let empty = BTreeSet::new();

    // Every *.rs in poison/ except previous_full_surface and
    // canonical_duplicate (special-cased) must appear in the table.
    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(fixtures_dir()).expect("read poison dir") {
        let e = entry.expect("entry");
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".rs") {
            on_disk.insert(name);
        }
    }
    // Non-poison helpers / special cases excluded from the table.
    on_disk.remove("previous_full_surface.rs");
    on_disk.remove("canonical_duplicate.rs");

    let mut table_names: BTreeSet<String> = BTreeSet::new();
    for entry in table {
        let fixture_name: &str = entry.0;
        let prev_name: Option<&str> = entry.1;
        let expected_tag: &str = entry.2;
        table_names.insert(fixture_name.to_string());
        let cand = read_fixture(fixture_name);
        let prev_body = prev_name.map(read_fixture);
        // missing_manifest uses the real target_minimal manifest;
        // others use empty so they don't fail at manifest first.
        let required = if expected_tag == "missing_manifest_symbols" {
            &req
        } else {
            &empty
        };
        let out = evaluate_static(&StaticCheckInput {
            candidate: &cand,
            previous: prev_body.as_deref(),
            required_pub: required,
        });
        if out.reject_tag() != Some(expected_tag) {
            panic!(
                "fixture {} expected tag {}, got {:?}",
                fixture_name, expected_tag, out
            );
        }
    }

    assert_eq!(
        on_disk, table_names,
        "poison dir has fixtures not listed in the corpus table (or vice versa).\n\
         on_disk={:?}\n table={:?}\n Add the new fixture to the table with its expected reject tag.",
        on_disk, table_names
    );
}

// =====================================================================
// Layer 2 — real verify binary, static rejects only (always on, fast)
// =====================================================================

fn verify_binary() -> PathBuf {
    if let Some(p) = option_env!("CARGO_BIN_EXE_verify") {
        return PathBuf::from(p);
    }
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let exe = if cfg!(windows) { "verify.exe" } else { "verify" };
    root.join("target").join("debug").join(exe)
}

fn run_verify_static(
    candidate: &Path,
    previous: Option<&Path>,
    manifest: Option<&Path>,
) -> (i32, String) {
    let mut cmd = Command::new(verify_binary());
    cmd.arg("--no-perf-check");
    if let Some(p) = previous {
        cmd.arg("--previous").arg(p);
    }
    if let Some(m) = manifest {
        cmd.arg("--manifest").arg(m);
    }
    cmd.arg(candidate);
    let out = cmd.output().expect("spawn verify");
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    (out.status.code().unwrap_or(-1), stderr)
}

#[test]
fn poison_syntax_error_verify_binary_rejects() {
    let cand = fixtures_dir().join("syntax_error.rs");
    // Candidate path must live under the workspace so locate_workspace_root
    // can walk up to contracts/. Our fixtures are under verifier/tests/
    // which is fine.
    let (code, stderr) = run_verify_static(&cand, None, None);
    assert_eq!(
        code, 1,
        "syntax poison must REJECT (exit 1), got {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("parse failed"),
        "stderr must mention parse failure:\n{}",
        stderr
    );
    // Must not reach the slow cargo stage.
    assert!(
        !stderr.contains("scratch dir"),
        "static poison must not enter compile-and-test:\n{}",
        stderr
    );
}

#[test]
fn poison_missing_manifest_verify_binary_rejects() {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let cand = fixtures_dir().join("missing_manifest_symbol.rs");
    let manifest = root.join("target_minimal").join("manifest.txt");
    let (code, stderr) = run_verify_static(&cand, None, Some(&manifest));
    assert_eq!(
        code, 1,
        "missing-manifest poison must REJECT, got {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("missing required public symbols"),
        "stderr must mention missing symbols:\n{}",
        stderr
    );
}

#[test]
fn poison_removed_previous_verify_binary_rejects() {
    let cand = fixtures_dir().join("removed_previous_symbol.rs");
    let prev = fixtures_dir().join("previous_full_surface.rs");
    let (code, stderr) = run_verify_static(&cand, Some(&prev), None);
    assert_eq!(
        code, 1,
        "removed-previous poison must REJECT, got {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("removed public symbol") && stderr.contains("drop_me"),
        "stderr must name the dropped symbol:\n{}",
        stderr
    );
}

#[test]
fn poison_canonical_duplicate_verify_binary_rejects() {
    let cand = fixtures_dir().join("canonical_duplicate.rs");
    // Same file as previous → zero diversity.
    let (code, stderr) = run_verify_static(&cand, Some(&cand), None);
    assert_eq!(
        code, 1,
        "canonical-duplicate poison must REJECT, got {}\nstderr:\n{}",
        code, stderr
    );
    assert!(
        stderr.contains("canonical-equivalent") || stderr.contains("no diversity"),
        "stderr must mention canonical dedup:\n{}",
        stderr
    );
}

// =====================================================================
// Layer 3 — semantic golden (slow; opt-in via PROTEUS_VERIFIER_POISON_E2E=1)
// =====================================================================

/// Semantic poisons: pass static checks, compile, fail golden/harness.
/// Relative to `tests/fixtures/poison/semantic/`.
const SEMANTIC_POISONS: &[&str] = &[
    "broken_fletcher32_halves.rs",
    "broken_feistel_rounds.rs",
    "aead_accept_tampered.rs",
    "sigverify_always_true.rs",
    "syscall_wrong_identity.rs",
];

fn semantic_dir() -> PathBuf {
    fixtures_dir().join("semantic")
}

/// Always-on: every semantic poison file exists and is listed.
/// Adding a `.rs` under `semantic/` without enrolling it here fails.
#[test]
fn semantic_poison_files_present_and_enrolled() {
    let dir = semantic_dir();
    assert!(dir.is_dir(), "missing semantic poison dir {}", dir.display());

    let mut on_disk: BTreeSet<String> = BTreeSet::new();
    for entry in std::fs::read_dir(&dir).expect("read semantic/") {
        let e = entry.expect("entry");
        let name = e.file_name().to_string_lossy().into_owned();
        if name.ends_with(".rs") && name != "base_good.rs" {
            on_disk.insert(name);
        }
    }

    let enrolled: BTreeSet<String> = SEMANTIC_POISONS.iter().map(|s| (*s).to_string()).collect();
    assert_eq!(
        on_disk, enrolled,
        "semantic/ poison fixtures must match SEMANTIC_POISONS table.\n\
         on_disk={:?}\n enrolled={:?}\n Add the fixture to SEMANTIC_POISONS \
         (and ensure it is a surgical morph of base_good.rs).",
        on_disk, enrolled
    );

    // Positive control must exist.
    assert!(
        dir.join("base_good.rs").exists(),
        "base_good.rs (ACCEPT control) missing"
    );

    // Each poison must pass static checks with the real target_minimal
    // manifest + previous, so e2e failures are semantic — not static.
    let req = target_minimal_manifest();
    let previous = std::fs::read_to_string(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .join("target_minimal")
            .join("src")
            .join("lib.rs"),
    )
    .expect("read previous lib.rs");
    for name in SEMANTIC_POISONS {
        let cand = std::fs::read_to_string(dir.join(name))
            .unwrap_or_else(|e| panic!("read {}: {}", name, e));
        let out = evaluate_static(&StaticCheckInput {
            candidate: &cand,
            previous: Some(&previous),
            required_pub: &req,
        });
        assert!(
            out.is_accept(),
            "semantic poison {} must pass static checks (got {:?}); \
             otherwise the e2e assay is invalid",
            name,
            out
        );
    }
}

/// Full verify binary against every semantic poison. Opt-in: each case
/// rebuilds a scratch workspace (~1 min cold).
///
/// ```text
/// PROTEUS_VERIFIER_POISON_E2E=1 cargo test -p proteus-verifier \
///   --test poison_corpus semantic_poison_e2e -- --nocapture
/// ```
#[test]
fn semantic_poison_e2e_all_reject() {
    if std::env::var("PROTEUS_VERIFIER_POISON_E2E").as_deref() != Ok("1") {
        eprintln!(
            "SKIP semantic e2e: set PROTEUS_VERIFIER_POISON_E2E=1 to run {} poisons \
             through the full verify binary (scratch cargo build each)",
            SEMANTIC_POISONS.len()
        );
        return;
    }

    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let previous = root.join("target_minimal").join("src").join("lib.rs");
    let manifest = root.join("target_minimal").join("manifest.txt");
    let dir = semantic_dir();

    // Positive control first: base_good must ACCEPT. If this fails,
    // every poison reject is uninterpretable.
    {
        let good = dir.join("base_good.rs");
        let mut cmd = Command::new(verify_binary());
        cmd.arg("--no-perf-check")
            .arg("--previous")
            .arg(&previous)
            .arg("--manifest")
            .arg(&manifest)
            .arg(&good);
        let out = cmd.output().expect("spawn verify base_good");
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        assert_eq!(
            code, 0,
            "POSITIVE CONTROL FAILED: base_good must ACCEPT (exit 0), got {}\nstderr:\n{}",
            code, stderr
        );
        assert!(
            stderr.contains("verify: ACCEPT") || code == 0,
            "base_good stderr should show ACCEPT:\n{}",
            stderr
        );
        eprintln!("semantic e2e: base_good ACCEPT ok");
    }

    let mut failures: Vec<String> = Vec::new();
    for name in SEMANTIC_POISONS {
        let fixture = dir.join(name);
        let mut cmd = Command::new(verify_binary());
        cmd.arg("--no-perf-check")
            .arg("--previous")
            .arg(&previous)
            .arg("--manifest")
            .arg(&manifest)
            .arg(&fixture);
        let out = cmd.output().expect("spawn verify");
        let code = out.status.code().unwrap_or(-1);
        let stderr = String::from_utf8_lossy(&out.stderr);
        eprintln!("semantic e2e: {} exit={}", name, code);

        if code != 1 {
            failures.push(format!(
                "{}: expected REJECT (exit 1), got {}\nstderr:\n{}",
                name, code, stderr
            ));
            continue;
        }
        if stderr.contains("parse failed")
            || stderr.contains("missing required public symbols")
            || stderr.contains("canonical-equivalent")
        {
            failures.push(format!(
                "{}: rejected at STATIC stage, not golden — assay invalid\nstderr:\n{}",
                name, stderr
            ));
            continue;
        }
        let semantic = stderr.contains("failed the golden test")
            || stderr.contains("FAILED")
            || stderr.contains("panicked")
            || stderr.contains("assertion")
            || stderr.contains("harness");
        if !semantic {
            failures.push(format!(
                "{}: REJECT without golden/harness signal\nstderr:\n{}",
                name, stderr
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "semantic poison e2e failures ({}):\n\n{}",
        failures.len(),
        failures.join("\n\n---\n\n")
    );
}
