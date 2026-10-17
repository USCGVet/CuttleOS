//! Stage 1 (`synth.rs`) integration tests.
//!
//! These cover the trait contract, the prompt-builder substitution, the
//! prompt-only file-emission side effect, and the attestation-log
//! synthesizer-name stability invariant.
//!
//! No `tempfile` crate is used here on purpose — the morph_engine
//! Cargo.toml is constrained to its existing dependencies. We build
//! unique tempdirs under `std::env::temp_dir()` and clean them up.

use proteus_morph_engine::{
    MutationBudget, PassThrough, PromptBuilder, PromptOnly, SynthRequest, Synthesizer,
};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

// === Test fixtures =========================================================

const PREV: &str = "pub fn fletcher32(data: &[u8]) -> u32 { 0xDEADBEEF }";

const CONTRACTS_FIXTURE: &str = r#"
//! Contracts crate fixture used in synth tests. Mirrors the trait names
//! that the real `contracts/src/lib.rs` declares so the
//! `prompt_builder_includes_every_contract_trait` test exercises a
//! realistic input. The bodies are stubs — we only need the names.
pub trait Hash {}
pub trait Aead {}
pub trait SignatureVerify {}
pub trait SyscallDispatch {}
pub trait BlockDevice {}
pub trait Allocator {}
"#;

/// Every trait the morph contract preserves. If the contracts crate
/// gains a new trait, this list must grow; the prompt would otherwise
/// silently drop that trait from the LLM's mental model.
const EXPECTED_CONTRACT_TRAITS: &[&str] = &[
    "Hash",
    "Aead",
    "SignatureVerify",
    "SyscallDispatch",
    "BlockDevice",
    "Allocator",
];

fn manifest() -> Vec<String> {
    vec![
        "fletcher32".into(),
        "feistel_mix".into(),
        "derive_byte".into(),
        "DemoHash".into(),
    ]
}

fn req<'a>(prev: &'a str, contracts: &'a str, m: &'a [String]) -> SynthRequest<'a> {
    SynthRequest {
        module_name: "lib",
        cycle: 99,
        previous_source: prev,
        contracts_source: contracts,
        manifest: m,
        mutation_budget: MutationBudget::default(),
    }
}

/// Build a fresh, empty tempdir under the OS temp dir. Path is unique
/// per call so parallel `cargo test` workers do not collide.
fn fresh_tempdir(label: &str) -> PathBuf {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let n = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "proteus_synth_test_{}_{}_{}_{}_",
        label,
        std::process::id(),
        nanos,
        n,
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).expect("create tempdir");
    dir
}

// === Required tests ========================================================

#[test]
fn passthrough_returns_identical_source() {
    let m = manifest();
    let r = req(PREV, CONTRACTS_FIXTURE, &m);
    let resp = PassThrough.synthesize(&r).expect("synth ok");
    assert_eq!(
        resp.candidate_source, PREV,
        "PassThrough must be byte-for-byte identity"
    );
    assert_eq!(
        resp.estimated_entropy_bits, 0.0,
        "PassThrough morphs zero entropy"
    );
}

#[test]
fn prompt_builder_includes_previous_source() {
    let m = manifest();
    let r = req(PREV, CONTRACTS_FIXTURE, &m);
    let s = PromptBuilder::new().build(&r);
    assert!(
        s.contains(PREV),
        "prompt must include previous_source verbatim; got:\n{}",
        s
    );
    // Sanity: placeholder was actually substituted.
    assert!(!s.contains("{{previous_source}}"));
}

#[test]
fn prompt_builder_includes_every_contract_trait() {
    let m = manifest();
    let r = req(PREV, CONTRACTS_FIXTURE, &m);
    let s = PromptBuilder::new().build(&r);
    for t in EXPECTED_CONTRACT_TRAITS {
        assert!(
            s.contains(t),
            "prompt missing contract trait `{}`. Either the contracts \
             crate fixture changed or the prompt template is no longer \
             substituting `{{{{contracts_source}}}}` correctly.",
            t
        );
    }
}

#[test]
fn prompt_builder_includes_every_locked_symbol() {
    let m = manifest();
    let r = req(PREV, CONTRACTS_FIXTURE, &m);
    let s = PromptBuilder::new().build(&r);
    for sym in &m {
        assert!(
            s.contains(sym),
            "prompt missing locked symbol `{}`. The manifest \
             substitution is broken.",
            sym
        );
    }
}

#[test]
fn prompt_builder_includes_abort_instruction() {
    let m = manifest();
    let r = req(PREV, CONTRACTS_FIXTURE, &m);
    let s = PromptBuilder::new().build(&r);
    assert!(
        s.contains("ABORT"),
        "prompt must include the ABORT fallback instruction"
    );
}

#[test]
fn prompt_only_writes_a_file_under_prompt_out_dir() {
    let dir = fresh_tempdir("promptonly");
    let m = manifest();
    let r = req(PREV, CONTRACTS_FIXTURE, &m);
    let s = PromptOnly {
        prompt_out_dir: dir.clone(),
    };
    let resp = s.synthesize(&r).expect("synth ok");
    // The body is still the previous source (PromptOnly does not call
    // any model).
    assert_eq!(resp.candidate_source, PREV);

    // File exists at the documented path and contains the rendered
    // prompt (spot-check via the previous source body).
    let expected_path = dir.join("cycle_99_lib_prompt.txt");
    assert!(
        expected_path.exists(),
        "expected prompt file at {} to exist",
        expected_path.display()
    );
    let body = fs::read_to_string(&expected_path).expect("read prompt");
    assert!(body.contains(PREV), "written prompt must include prev source");
    assert!(body.contains("ABORT"), "written prompt must include ABORT");

    // Cleanup.
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn synthesizer_name_is_stable() {
    // These string values land in attestation logs. They must not drift
    // between releases without an explicit schema-version bump.
    assert_eq!(PassThrough.name(), "passthrough");
    assert_eq!(
        PromptOnly {
            prompt_out_dir: PathBuf::from(".")
        }
        .name(),
        "prompt-only"
    );
}
