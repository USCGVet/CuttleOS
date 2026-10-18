//! Integration test for `AnthropicSynth` — the real-network E2E.
//!
//! This file is `#[ignore]`-gated for one reason: it costs real money.
//! Every invocation makes a live POST to `https://api.anthropic.com/v1/messages`
//! and bills the operator's account. CI runs it on-demand only:
//!
//! ```text
//! cargo test -p cuttle-morph-engine -- --ignored anthropic
//! ```
//!
//! Behaviour:
//!
//! - If `ANTHROPIC_API_KEY` is unset, the test prints a notice via
//!   `eprintln!` and returns successfully (rather than panicking). This
//!   matches the convention used for other "credentials-required" E2E
//!   tests across the workspace — `--ignored` lets a developer run
//!   the suite even when they have not provisioned a key.
//! - With a valid key, the test:
//!     1. Builds a minimal `SynthRequest` whose `previous_source` is a
//!        one-line no-op function.
//!     2. Calls `AnthropicSynth::synthesize` with `max_tokens = 1024`
//!        (cheap by Messages API standards).
//!     3. Asserts the returned `candidate_source` contains a `fn `
//!        token and is not `ABORT`.
//!     4. Asserts the file `prompts_out/cycle-0-demo-anthropic.rs`
//!        exists (matches the acceptance criterion's filename pattern).
//!
//! The candidate is NOT handed to the verifier or the diversifier here
//! — those stages have their own test suites. This test exists only to
//! prove the synthesizer round-trips against the real API surface.

use cuttle_morph_engine::{
    AnthropicSynth, MutationBudget, SynthRequest, Synthesizer, ANTHROPIC_API_KEY_ENV,
};
use std::env;
use std::path::PathBuf;
use std::time::Duration;

/// Minimal contracts source for the prompt. The real `contracts/src/lib.rs`
/// has more traits; for this smoke test we only need the prompt to render.
const CONTRACTS_FIXTURE: &str = r#"
pub trait Hash { fn finalize(&self) -> [u8; 32]; }
"#;

/// Minimal previous source. The model is asked to morph this, but for
/// the acceptance criterion we only check that the returned source is
/// a fenced fn — not that it preserves byte-equivalent semantics.
const PREVIOUS_SOURCE: &str = "pub fn one() -> u32 { 1 }\n";

#[test]
#[ignore = "costs real money — run with --ignored anthropic"]
fn anthropic_live_round_trip() {
    // Skip cleanly if no key is configured. We intentionally do not
    // panic: a developer running the ignored suite without a key is
    // a normal state, and we want the rest of `--ignored` to proceed.
    if env::var(ANTHROPIC_API_KEY_ENV).ok().filter(|v| !v.trim().is_empty()).is_none() {
        eprintln!(
            "skipping anthropic_live_round_trip: {} not set",
            ANTHROPIC_API_KEY_ENV
        );
        return;
    }

    let out_dir = PathBuf::from("prompts_out");
    // Keep cost down: tiny token budget, short timeout. The synthesis
    // prompt for a 1-line previous_source is itself small, so 1024
    // tokens is plenty of headroom for a minimal morph.
    let synth = AnthropicSynth::from_env(out_dir.clone())
        .expect("ANTHROPIC_API_KEY is set; from_env must succeed")
        .with_max_tokens(1024)
        .with_timeout(Duration::from_secs(60));

    let manifest: Vec<String> = vec!["one".into()];
    let req = SynthRequest {
        module_name: "demo",
        cycle: 0,
        previous_source: PREVIOUS_SOURCE,
        contracts_source: CONTRACTS_FIXTURE,
        manifest: &manifest,
        mutation_budget: MutationBudget::default(),
    };

    let resp = synth.synthesize(&req).expect("Anthropic synthesize round-trip");
    assert!(
        resp.candidate_source.contains("fn "),
        "candidate must contain a fn token; got:\n{}",
        resp.candidate_source
    );
    assert_ne!(
        resp.candidate_source.trim(),
        "ABORT",
        "ABORT was supposed to error inside parse, not bubble through"
    );

    // The synthesizer writes the parsed candidate under
    // `prompts_out/cycle-0-demo-anthropic.rs`. The acceptance criterion
    // glob `cycle-*-anthropic.rs` matches this filename.
    let expected_out = out_dir.join("cycle-0-demo-anthropic.rs");
    assert!(
        expected_out.exists(),
        "expected output file at {} to exist after a successful round-trip",
        expected_out.display()
    );
}
