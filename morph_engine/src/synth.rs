//! Stage 1 of the morph pipeline: source synthesis.
//!
//! In production, Stage 1 is an LLM that emits a complete replacement
//! source file for one module per cycle. In the skeleton we keep the
//! *interface* nailed down so swapping in a real LLM is mechanical:
//!
//! - [`Synthesizer`] is the trait every Stage 1 backend implements.
//! - [`PassThrough`] returns the previous source unchanged — the default
//!   behaviour preserved for backward compatibility.
//! - [`PromptOnly`] writes the structured prompt to disk and returns the
//!   previous source unchanged. Use it to audit what we would ask an LLM,
//!   or to drive a model out-of-band.
//!
//! The prompt template lives in `prompts/synthesis_v1.md` and is baked
//! into the binary via [`include_str!`]. [`PromptBuilder`] performs simple
//! `{{placeholder}}` substitution against it — no templating engine is
//! pulled in; the engine surface is small enough to spell out.

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

/// The canonical Stage 1 prompt template, baked into the binary.
///
/// Editing this file is a schema change: it alters what the LLM is told,
/// which in turn alters the morph distribution. Treat changes here with
/// the same rigour as a contracts-crate edit.
pub const SYNTHESIS_PROMPT_V1: &str = include_str!("../prompts/synthesis_v1.md");

/// Inputs to a Stage 1 synthesis call.
#[derive(Debug)]
pub struct SynthRequest<'a> {
    /// Logical module name (e.g. `"lib"`, `"kpti"`). Appears in prompt
    /// header and in the prompt-output filename.
    pub module_name: &'a str,
    /// Monotonic cycle counter. Distinguishes prompt-output files.
    pub cycle: u64,
    /// The verbatim source of the module's previous cycle. The LLM is
    /// instructed to morph this, not to rewrite it from scratch.
    pub previous_source: &'a str,
    /// The verbatim source of `contracts/src/lib.rs`. The LLM's output
    /// must continue to satisfy every trait in here.
    pub contracts_source: &'a str,
    /// Locked public symbols — every name in this list must remain a
    /// `pub` item in the candidate, by name and by signature.
    pub manifest: &'a [String],
    /// How much the synthesizer is allowed to drift from `previous_source`.
    pub mutation_budget: MutationBudget,
}

/// Edit-distance bounds the synthesizer is asked to honour.
#[derive(Debug, Clone, Copy)]
pub struct MutationBudget {
    /// Target Levenshtein distance ratio from previous source.
    /// 0.0 = identical, 1.0 = fully rewritten. Practical range 0.2-0.7.
    pub target_distance_ratio: f32,
    /// Maximum allowable distance ratio. Above this the synthesizer
    /// should retry (or the verifier will reject for over-mutation).
    pub max_distance_ratio: f32,
}

impl Default for MutationBudget {
    fn default() -> Self {
        Self {
            target_distance_ratio: 0.35,
            max_distance_ratio: 0.65,
        }
    }
}

/// Output of a Stage 1 synthesis call.
#[derive(Debug)]
pub struct SynthResponse {
    /// The candidate replacement source. May equal `previous_source` if
    /// the synthesizer chose not to morph this cycle (PassThrough always
    /// does this).
    pub candidate_source: String,
    /// Synthesizer's best-effort entropy estimate of how much it changed
    /// from the input. The verifier independently verifies this with
    /// canonical-hash dedup; this number is advisory only.
    pub estimated_entropy_bits: f32,
}

/// Stage 1 backend.
///
/// Implementations must be deterministic relative to their own seed (so
/// the attestation chain stays reproducible) and must NEVER mutate
/// caller-owned state besides files in directories they were configured
/// with.
pub trait Synthesizer {
    /// Produce a candidate source for `req.module_name`.
    fn synthesize(&self, req: &SynthRequest) -> Result<SynthResponse>;
    /// Stable identifier for attestation logs. Must be a constant string
    /// — log readers depend on it not drifting between cycles of the
    /// same synthesizer implementation.
    fn name(&self) -> &'static str;
}

/// Synthesizer that returns the previous source unchanged. The skeleton
/// default. Used in tests where Stage 1 is not under test, and as the
/// fallback when no `--synthesizer` flag is given.
pub struct PassThrough;

impl Synthesizer for PassThrough {
    fn synthesize(&self, req: &SynthRequest) -> Result<SynthResponse> {
        Ok(SynthResponse {
            candidate_source: req.previous_source.to_string(),
            estimated_entropy_bits: 0.0,
        })
    }

    fn name(&self) -> &'static str {
        "passthrough"
    }
}

/// Synthesizer that writes the full LLM prompt to disk and returns the
/// previous source unchanged. Use this to manually audit what the
/// synthesizer would ask, or to drive an LLM out-of-band against the
/// generated prompt file.
pub struct PromptOnly {
    /// Directory the prompt files are written under. Created on first
    /// use if missing.
    pub prompt_out_dir: PathBuf,
}

impl PromptOnly {
    /// Path the next call will write to. Exposed so the caller (cycle
    /// driver) can record it in the attestation log without re-deriving.
    pub fn prompt_path(&self, cycle: u64, module: &str) -> PathBuf {
        self.prompt_out_dir
            .join(format!("cycle_{}_{}_prompt.txt", cycle, module))
    }
}

impl Synthesizer for PromptOnly {
    fn synthesize(&self, req: &SynthRequest) -> Result<SynthResponse> {
        fs::create_dir_all(&self.prompt_out_dir).with_context(|| {
            format!("create prompt-out dir {}", self.prompt_out_dir.display())
        })?;
        let prompt = PromptBuilder::new().build(req);
        let path = self.prompt_path(req.cycle, req.module_name);
        fs::write(&path, &prompt)
            .with_context(|| format!("write prompt file {}", path.display()))?;
        Ok(SynthResponse {
            candidate_source: req.previous_source.to_string(),
            estimated_entropy_bits: 0.0,
        })
    }

    fn name(&self) -> &'static str {
        "prompt-only"
    }
}

/// Renders [`SYNTHESIS_PROMPT_V1`] against a [`SynthRequest`] by simple
/// `{{placeholder}}` string substitution. No templating engine; the
/// surface is small enough that hand-rolled substitution stays auditable.
///
/// Placeholders supported:
/// - `{{module_name}}`
/// - `{{cycle}}`
/// - `{{previous_source}}`
/// - `{{contracts_source}}`
/// - `{{manifest}}` — rendered as a bullet list, one symbol per line.
/// - `{{target_distance_ratio}}`
/// - `{{max_distance_ratio}}`
pub struct PromptBuilder {
    template: &'static str,
}

impl PromptBuilder {
    /// Build against the canonical v1 template.
    pub fn new() -> Self {
        Self {
            template: SYNTHESIS_PROMPT_V1,
        }
    }

    /// Build against an explicit template — exposed so tests can pin a
    /// minimal template without rebuilding the whole binary.
    #[cfg(test)]
    pub fn with_template(template: &'static str) -> Self {
        Self { template }
    }

    /// Render the template, substituting every placeholder against `req`.
    /// Returns the fully-rendered prompt; unknown `{{...}}` sequences are
    /// passed through unchanged (no error), so future placeholders can
    /// be added without breaking older templates.
    pub fn build(&self, req: &SynthRequest) -> String {
        let manifest_md = if req.manifest.is_empty() {
            "(no locked symbols declared — module has no public surface)".to_string()
        } else {
            let mut s = String::new();
            for sym in req.manifest {
                s.push_str("- `");
                s.push_str(sym);
                s.push_str("`\n");
            }
            // Trim the trailing newline so the substitution sits cleanly
            // inside the surrounding Markdown.
            s.trim_end().to_string()
        };

        let cycle_str = req.cycle.to_string();
        let target_str = format_ratio(req.mutation_budget.target_distance_ratio);
        let max_str = format_ratio(req.mutation_budget.max_distance_ratio);

        let mut out = self.template.to_string();
        out = out.replace("{{module_name}}", req.module_name);
        out = out.replace("{{cycle}}", &cycle_str);
        out = out.replace("{{previous_source}}", req.previous_source);
        out = out.replace("{{contracts_source}}", req.contracts_source);
        out = out.replace("{{manifest}}", &manifest_md);
        out = out.replace("{{target_distance_ratio}}", &target_str);
        out = out.replace("{{max_distance_ratio}}", &max_str);
        out
    }
}

impl Default for PromptBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a ratio for the prompt. Two decimals is enough resolution for
/// an LLM to act on and keeps the rendered prompt diffable across cycles.
fn format_ratio(r: f32) -> String {
    format!("{:.2}", r)
}

/// Convenience: read the workspace's `contracts/src/lib.rs` relative to
/// the morph engine's runtime cwd. The cycle driver uses this so the
/// prompt always reflects what the verifier is actually checking against.
///
/// Falls back to an empty string if the file is unreadable — the
/// caller's verifier will reject the cycle anyway, and we prefer not to
/// fail Stage 1 on a missing-input that only PromptOnly cares about.
pub fn read_contracts_source() -> String {
    let dir_candidates = [Path::new("contracts/src"), Path::new("../contracts/src")];
    let files = [
        "lib.rs",
        "core_primitives.rs",
        "tls_wal_iommu_net.rs",
        "kpti_virtio_security.rs",
        "fs_ebpf_smp_pci_x509.rs",
        "hw_storage_boot.rs",
    ];
    for dir in &dir_candidates {
        let lib_path = dir.join("lib.rs");
        if lib_path.is_file() {
            let mut out = String::new();
            for f in &files {
                if let Ok(s) = fs::read_to_string(dir.join(f)) {
                    out.push_str(&s);
                    out.push('\n');
                }
            }
            return out;
        }
    }
    String::new()
}

/// Convenience: read a manifest file (one symbol per non-comment,
/// non-blank line) into a `Vec<String>`. Comment lines start with `#`.
pub fn read_manifest(path: &Path) -> Result<Vec<String>> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read manifest {}", path.display()))?;
    Ok(raw
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(String::from)
        .collect())
}

// === AnthropicSynth ========================================================
//
// The third Stage 1 backend: actually call the Anthropic Messages API,
// parse the fenced response, and return the extracted Rust source as the
// candidate. Unlike `PromptOnly` (which is an audit aid) this synthesizer
// is the production path — its output goes straight into the diversifier
// and the verifier.
//
// Hard rules:
//   - Missing `ANTHROPIC_API_KEY` is an error. NEVER silently fall back.
//   - Response must contain `// SYNTH_BEGIN` / `// SYNTH_END` fences.
//   - The fenced body must contain at least one `fn ` token, otherwise
//     it is rejected at the synth stage (not handed to the verifier).
//   - `ABORT` (after trimming) is a refusal — reject.
//
// HTTP is intentionally blocking (`ureq`). The orchestrator runs one
// cycle at a time; an async runtime would be ceremony for no gain.

/// Default Anthropic Messages API endpoint. Override via the
/// `with_endpoint` builder for tests so we never accidentally hit the
/// real network from `cargo test`.
pub const ANTHROPIC_DEFAULT_ENDPOINT: &str = "https://api.anthropic.com/v1/messages";

/// API key environment variable. The ONLY credential surface.
pub const ANTHROPIC_API_KEY_ENV: &str = "ANTHROPIC_API_KEY";

/// Optional model override environment variable.
pub const ANTHROPIC_MODEL_ENV: &str = "ANTHROPIC_MODEL";

/// Default model. Picked to be a current top-tier ID per the SDK
/// knowledge cutoff. Operators override via `ANTHROPIC_MODEL`.
pub const ANTHROPIC_DEFAULT_MODEL: &str = "claude-opus-4-7";

/// Default token budget. Synthesis output is rarely huge — a few hundred
/// lines of Rust comfortably fits in 4096 tokens — but we leave headroom
/// for the bigger target_enterprise modules.
pub const ANTHROPIC_DEFAULT_MAX_TOKENS: u32 = 4096;

/// Anthropic API version pin. The Messages API guarantees backward
/// compatibility under this header; if Anthropic publishes a new version
/// we bump it explicitly here (and re-run the integration test) rather
/// than implicitly tracking the latest.
pub const ANTHROPIC_API_VERSION: &str = "2023-06-01";

/// Fence the synthesis prompt instructs the model to emit. Mirrors the
/// language in `prompts/synthesis_v1.md` — if you change one you MUST
/// change the other.
pub const SYNTH_BEGIN_FENCE: &str = "// SYNTH_BEGIN";
pub const SYNTH_END_FENCE: &str = "// SYNTH_END";

/// Request body sent to `POST /v1/messages`. Subset of the full schema;
/// we only need `model`, `max_tokens`, `messages`, and optionally
/// `system`. Anthropic ignores unknown fields, but emitting only the
/// fields we use keeps wire payloads small and auditable.
#[derive(Debug, Serialize)]
struct AnthropicRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    messages: Vec<AnthropicMessage<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    system: Option<&'a str>,
}

#[derive(Debug, Serialize)]
struct AnthropicMessage<'a> {
    role: &'a str,
    content: &'a str,
}

/// Response from `POST /v1/messages`. We only deserialize the fields we
/// actually consume — additional fields (`id`, `usage`, `stop_reason`,
/// etc.) are ignored.
#[derive(Debug, Deserialize)]
struct AnthropicResponse {
    #[serde(default)]
    content: Vec<AnthropicContentBlock>,
    #[serde(default)]
    stop_reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AnthropicContentBlock {
    #[serde(rename = "type")]
    block_type: String,
    #[serde(default)]
    text: Option<String>,
}

/// Synthesizer that calls the Anthropic Messages API.
///
/// Constructor `from_env` is the production path: it reads
/// `ANTHROPIC_API_KEY` (required) and `ANTHROPIC_MODEL` (optional, with
/// a default). For tests, `with_endpoint` lets you redirect the HTTP
/// POST elsewhere — but the unit tests in this crate exercise the
/// parsing layer directly via `parse_anthropic_response_text` and never
/// open a socket, which keeps `cargo test` deterministic.
pub struct AnthropicSynth {
    api_key: String,
    model: String,
    max_tokens: u32,
    endpoint: String,
    /// Directory where the rendered prompt is written before the API
    /// call, and where the parsed candidate is written on success.
    /// Mirrors `PromptOnly` so the prompt-audit story is identical
    /// regardless of which Stage 1 backend ran.
    prompt_out_dir: PathBuf,
    /// HTTP timeout. Anthropic responses for synthesis-sized prompts
    /// typically land in <30s; we allow generous headroom because the
    /// alternative is a half-completed cycle.
    timeout: Duration,
}

impl std::fmt::Debug for AnthropicSynth {
    /// Redacted: the API key is a secret and must NEVER hit logs.
    /// All other fields are safe to print and useful in diagnostics.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AnthropicSynth")
            .field("api_key", &"<redacted>")
            .field("model", &self.model)
            .field("max_tokens", &self.max_tokens)
            .field("endpoint", &self.endpoint)
            .field("prompt_out_dir", &self.prompt_out_dir)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl AnthropicSynth {
    /// Construct from environment. Fails fast if `ANTHROPIC_API_KEY` is
    /// unset or empty — there is no fallback path, per TASK-002.
    pub fn from_env(prompt_out_dir: PathBuf) -> Result<Self> {
        let api_key = env::var(ANTHROPIC_API_KEY_ENV).map_err(|_| {
            anyhow!(
                "{} is not set; AnthropicSynth refuses to fall back silently",
                ANTHROPIC_API_KEY_ENV
            )
        })?;
        if api_key.trim().is_empty() {
            bail!(
                "{} is set but empty; AnthropicSynth refuses to fall back silently",
                ANTHROPIC_API_KEY_ENV
            );
        }
        let model = env::var(ANTHROPIC_MODEL_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| ANTHROPIC_DEFAULT_MODEL.to_string());
        Ok(Self {
            api_key,
            model,
            max_tokens: ANTHROPIC_DEFAULT_MAX_TOKENS,
            endpoint: ANTHROPIC_DEFAULT_ENDPOINT.to_string(),
            prompt_out_dir,
            timeout: Duration::from_secs(120),
        })
    }

    /// Override the API endpoint. Intended for tests that spin up a
    /// local HTTP listener; production code uses `from_env` and the
    /// default endpoint.
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Override the max-tokens budget. Useful for the ignored E2E test
    /// which wants to keep cost down.
    pub fn with_max_tokens(mut self, max_tokens: u32) -> Self {
        self.max_tokens = max_tokens;
        self
    }

    /// Override the model identifier.
    pub fn with_model(mut self, model: impl Into<String>) -> Self {
        self.model = model.into();
        self
    }

    /// Override the HTTP timeout.
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }

    /// Filesystem path the rendered prompt will be written to before
    /// the API call. Exposed so the cycle driver can quote it in
    /// attestation logs.
    pub fn prompt_path(&self, cycle: u64, module: &str) -> PathBuf {
        self.prompt_out_dir
            .join(format!("cycle_{}_{}_anthropic_prompt.txt", cycle, module))
    }

    /// Filesystem path the parsed candidate source will be written to
    /// on a successful API call. Matches the acceptance criterion's
    /// `cycle-*-anthropic.rs` pattern (the dash naming) so operators
    /// can find generated source by glob.
    pub fn output_path(&self, cycle: u64, module: &str) -> PathBuf {
        self.prompt_out_dir
            .join(format!("cycle-{}-{}-anthropic.rs", cycle, module))
    }

    /// Build the request body as the JSON value we will POST. Factored
    /// out so the unit tests can assert on the request shape without
    /// going through HTTP.
    pub fn build_request_body(&self, prompt: &str) -> serde_json::Value {
        let req = AnthropicRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            messages: vec![AnthropicMessage {
                role: "user",
                content: prompt,
            }],
            system: None,
        };
        // Serializing to `serde_json::Value` keeps the test assertions
        // readable (`v["model"]`) without exposing the private struct.
        serde_json::to_value(&req).expect("AnthropicRequest is always serializable")
    }
}

impl Synthesizer for AnthropicSynth {
    fn synthesize(&self, req: &SynthRequest) -> Result<SynthResponse> {
        fs::create_dir_all(&self.prompt_out_dir).with_context(|| {
            format!("create prompt-out dir {}", self.prompt_out_dir.display())
        })?;
        let prompt = PromptBuilder::new().build(req);
        let prompt_path = self.prompt_path(req.cycle, req.module_name);
        fs::write(&prompt_path, &prompt)
            .with_context(|| format!("write prompt file {}", prompt_path.display()))?;

        let body = self.build_request_body(&prompt);

        // ureq's blocking call. Errors here include network failure
        // AND non-2xx status; in the latter case the response body is
        // surfaced so the operator can see what Anthropic complained
        // about (rate limit, bad model id, etc.).
        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let resp = agent
            .post(&self.endpoint)
            .set("x-api-key", &self.api_key)
            .set("anthropic-version", ANTHROPIC_API_VERSION)
            .set("content-type", "application/json")
            .send_json(&body);

        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r
                    .into_string()
                    .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
                bail!(
                    "Anthropic API returned HTTP {} for module {}: {}",
                    code,
                    req.module_name,
                    body
                );
            }
            Err(e) => {
                bail!(
                    "Anthropic API transport error for module {}: {}",
                    req.module_name,
                    e
                );
            }
        };

        let raw_text = resp
            .into_string()
            .context("read Anthropic API response body")?;

        let parsed: AnthropicResponse = serde_json::from_str(&raw_text)
            .with_context(|| format!("parse Anthropic response JSON: {}", raw_text))?;

        // Concatenate every text block, in order. Anthropic returns
        // a `content` array; tool-use turns add non-text blocks which
        // we skip (they would not contain code anyway).
        let mut concat = String::new();
        for block in &parsed.content {
            if block.block_type == "text" {
                if let Some(t) = &block.text {
                    concat.push_str(t);
                }
            }
        }
        if concat.is_empty() {
            bail!(
                "Anthropic response had no text content blocks (stop_reason={:?})",
                parsed.stop_reason
            );
        }

        let candidate_source = parse_anthropic_response_text(&concat)?;

        let out_path = self.output_path(req.cycle, req.module_name);
        fs::write(&out_path, &candidate_source)
            .with_context(|| format!("write candidate source {}", out_path.display()))?;

        let entropy = estimate_entropy_bits(req.previous_source, &candidate_source);
        Ok(SynthResponse {
            candidate_source,
            estimated_entropy_bits: entropy,
        })
    }

    fn name(&self) -> &'static str {
        "anthropic"
    }
}

// === FireworksSynth ==========================================================
//
// Fourth Stage 1 backend: Fireworks AI's OpenAI-compatible chat
// completions API. Same hard rules as AnthropicSynth:
//   - Missing FIREWORKS_API_KEY is an error. NEVER silently fall back.
//   - Response must contain SYNTH_BEGIN / SYNTH_END fences with a `fn `.
//   - Blocking HTTP via ureq (one cycle at a time; no async ceremony).

/// Default Fireworks OpenAI-compatible endpoint.
pub const FIREWORKS_DEFAULT_ENDPOINT: &str =
    "https://api.fireworks.ai/inference/v1/chat/completions";

/// API key environment variable. The ONLY credential surface.
pub const FIREWORKS_API_KEY_ENV: &str = "FIREWORKS_API_KEY";

/// Optional model override environment variable.
pub const FIREWORKS_MODEL_ENV: &str = "FIREWORKS_MODEL";

/// Default model. CHEAP BY DESIGN: the LLM only proposes rewrites —
/// the deterministic verifier does all trust work, so a small fast
/// instruct model is sufficient (gpt-oss-20b is ~$0.07/M tokens,
/// ~40x cheaper than frontier models; probed available on this
/// account 2026-07-28). Override via FIREWORKS_MODEL.
pub const FIREWORKS_DEFAULT_MODEL: &str = "accounts/fireworks/models/gpt-oss-20b";

/// OpenAI-compatible request body.
#[derive(Debug, Serialize)]
struct FireworksRequest<'a> {
    model: &'a str,
    max_tokens: u32,
    temperature: f32,
    messages: Vec<AnthropicMessage<'a>>,
    /// gpt-oss-family models burn the entire completion budget on
    /// hidden reasoning otherwise (observed: 32768 reasoning tokens,
    /// zero content). `low` keeps the chain-of-thought cheap.
    reasoning_effort: &'a str,
}

/// OpenAI-compatible response (subset).
#[derive(Debug, Deserialize)]
struct FireworksResponse {
    #[serde(default)]
    choices: Vec<FireworksChoice>,
}

#[derive(Debug, Deserialize)]
struct FireworksChoice {
    message: FireworksMessage,
}

#[derive(Debug, Deserialize)]
struct FireworksMessage {
    #[serde(default)]
    content: Option<String>,
}

/// Synthesizer that calls the Fireworks AI OpenAI-compatible API.
pub struct FireworksSynth {
    api_key: String,
    model: String,
    max_tokens: u32,
    endpoint: String,
    prompt_out_dir: PathBuf,
    timeout: Duration,
}

impl std::fmt::Debug for FireworksSynth {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FireworksSynth")
            .field("api_key", &"<redacted>")
            .field("model", &self.model)
            .field("max_tokens", &self.max_tokens)
            .field("endpoint", &self.endpoint)
            .field("prompt_out_dir", &self.prompt_out_dir)
            .field("timeout", &self.timeout)
            .finish()
    }
}

impl FireworksSynth {
    /// Construct from environment. Fails fast if `FIREWORKS_API_KEY` is
    /// unset or empty — no silent fallback, same rule as AnthropicSynth.
    pub fn from_env(prompt_out_dir: PathBuf) -> Result<Self> {
        let api_key = env::var(FIREWORKS_API_KEY_ENV).map_err(|_| {
            anyhow!(
                "{} is not set; FireworksSynth refuses to fall back silently",
                FIREWORKS_API_KEY_ENV
            )
        })?;
        if api_key.trim().is_empty() {
            bail!(
                "{} is set but empty; FireworksSynth refuses to fall back silently",
                FIREWORKS_API_KEY_ENV
            );
        }
        let model = env::var(FIREWORKS_MODEL_ENV)
            .ok()
            .filter(|s| !s.trim().is_empty())
            .unwrap_or_else(|| FIREWORKS_DEFAULT_MODEL.to_string());
        Ok(Self {
            api_key,
            model,
            max_tokens: 32768, // replacement module can be ~12-20k tokens
            endpoint: FIREWORKS_DEFAULT_ENDPOINT.to_string(),
            prompt_out_dir,
            // Reasoning-style models can sit silent for minutes while
            // they "think" before the first byte; 120s was too tight
            // (observed: connection timeout os error 10060 on kimi-k3
            // with an 8192-token budget).
            timeout: Duration::from_secs(600),
        })
    }

    /// Override the endpoint (tests only; production uses from_env).
    pub fn with_endpoint(mut self, endpoint: impl Into<String>) -> Self {
        self.endpoint = endpoint.into();
        self
    }

    /// Filesystem path the rendered prompt is written to before the API call.
    pub fn prompt_path(&self, cycle: u64, module: &str) -> PathBuf {
        self.prompt_out_dir
            .join(format!("cycle_{}_{}_fireworks_prompt.txt", cycle, module))
    }

    /// Filesystem path the parsed candidate source is written to.
    pub fn output_path(&self, cycle: u64, module: &str) -> PathBuf {
        self.prompt_out_dir
            .join(format!("cycle-{}-{}-fireworks.rs", cycle, module))
    }
}

impl Synthesizer for FireworksSynth {
    fn synthesize(&self, req: &SynthRequest) -> Result<SynthResponse> {
        fs::create_dir_all(&self.prompt_out_dir).with_context(|| {
            format!("create prompt-out dir {}", self.prompt_out_dir.display())
        })?;
        let prompt = PromptBuilder::new().build(req);
        let prompt_path = self.prompt_path(req.cycle, req.module_name);
        fs::write(&prompt_path, &prompt)
            .with_context(|| format!("write prompt file {}", prompt_path.display()))?;

        let body = serde_json::to_value(FireworksRequest {
            model: &self.model,
            max_tokens: self.max_tokens,
            temperature: 0.3,
            reasoning_effort: "low",
            messages: vec![
                // Reasoning-style models burn the whole token budget on
                // analysis if given the chance — the fence contract must
                // be asserted up front. (Fireworks' endpoint takes system
                // as a message, not a top-level field.)
                AnthropicMessage {
                    role: "system",
                    content: "You are a code-generation backend in an automated pipeline. \
                              Respond with ONLY the deliverable: the complete module source \
                              between `// SYNTH_BEGIN` and `// SYNTH_END` fences. No analysis, \
                              no commentary, no markdown — the first bytes of your reply are \
                              the begin fence and the last bytes are the end fence.",
                },
                AnthropicMessage {
                    role: "user",
                    content: &prompt,
                },
            ],
        })
        .expect("FireworksRequest is always serializable");

        let agent = ureq::AgentBuilder::new().timeout(self.timeout).build();
        let resp = agent
            .post(&self.endpoint)
            .set("authorization", &format!("Bearer {}", self.api_key))
            .set("content-type", "application/json")
            .send_json(&body);

        let resp = match resp {
            Ok(r) => r,
            Err(ureq::Error::Status(code, r)) => {
                let body = r
                    .into_string()
                    .unwrap_or_else(|e| format!("<failed to read body: {}>", e));
                bail!(
                    "Fireworks API returned HTTP {} for module {}: {}",
                    code,
                    req.module_name,
                    body
                );
            }
            Err(e) => {
                bail!(
                    "Fireworks API transport error for module {}: {}",
                    req.module_name,
                    e
                );
            }
        };

        let raw_text = resp
            .into_string()
            .context("read Fireworks API response body")?;
        let parsed: FireworksResponse = serde_json::from_str(&raw_text)
            .with_context(|| format!("parse Fireworks response JSON: {}", raw_text))?;

        let mut concat = String::new();
        for choice in &parsed.choices {
            if let Some(t) = &choice.message.content {
                concat.push_str(t);
            }
        }
        if concat.is_empty() {
            // Dump the raw response so the operator can see what the
            // model actually returned (reasoning fields, refusals, …).
            let dbg_path = self.prompt_out_dir.join(format!(
                "cycle-{}-{}-fireworks-EMPTY-RAW.json",
                req.cycle, req.module_name
            ));
            let _ = fs::write(&dbg_path, &raw_text);
            bail!(
                "Fireworks response had no message content (raw dumped to {})",
                dbg_path.display()
            );
        }

        let candidate_source = match parse_anthropic_response_text(&concat) {
            Ok(c) => c,
            Err(e) => {
                // Dump the raw model output for operator debugging —
                // fence compliance is a per-model behavior, and the fix
                // is usually prompt-side, not code-side.
                let dbg_path = self
                    .prompt_out_dir
                    .join(format!("cycle-{}-{}-fireworks-RAW.txt", req.cycle, req.module_name));
                let _ = fs::write(&dbg_path, &concat);
                return Err(e).with_context(|| {
                    format!("raw model output dumped to {}", dbg_path.display())
                });
            }
        };

        let out_path = self.output_path(req.cycle, req.module_name);
        fs::write(&out_path, &candidate_source)
            .with_context(|| format!("write candidate source {}", out_path.display()))?;

        let entropy = estimate_entropy_bits(req.previous_source, &candidate_source);
        Ok(SynthResponse {
            candidate_source,
            estimated_entropy_bits: entropy,
        })
    }

    fn name(&self) -> &'static str {
        "fireworks"
    }
}

/// Extract the source body between `// SYNTH_BEGIN` and `// SYNTH_END`
/// fences from a model response.
///
/// Hard rules (per TASK-002):
/// - Trimmed input equal to `ABORT` -> error. The model is saying it
///   could not comply; we refuse the candidate rather than feeding
///   garbage to the verifier.
/// - Missing either fence -> error.
/// - Body present but contains no `fn ` token -> error. The deliverable
///   says output must contain a single `fn` body that compiles in
///   isolation; an empty or comment-only body fails that contract.
///
/// Returns the trimmed body on success (leading/trailing whitespace
/// stripped, fences NOT included).
pub fn parse_anthropic_response_text(raw: &str) -> Result<String> {
    let trimmed = raw.trim();
    if trimmed == "ABORT" {
        bail!(
            "Anthropic synthesizer aborted (model emitted the ABORT \
             sentinel — it could not satisfy the morph constraints)"
        );
    }

    let begin_idx = raw.find(SYNTH_BEGIN_FENCE).ok_or_else(|| {
        anyhow!(
            "Anthropic response missing `{}` fence; cannot extract candidate source",
            SYNTH_BEGIN_FENCE
        )
    })?;
    let after_begin = begin_idx + SYNTH_BEGIN_FENCE.len();
    let end_rel = raw[after_begin..].find(SYNTH_END_FENCE).ok_or_else(|| {
        anyhow!(
            "Anthropic response missing `{}` fence after `{}`; cannot extract candidate source",
            SYNTH_END_FENCE,
            SYNTH_BEGIN_FENCE
        )
    })?;
    let body = &raw[after_begin..after_begin + end_rel];
    let body = body.trim();

    if body.is_empty() {
        bail!("Anthropic response had empty body between SYNTH_BEGIN/SYNTH_END fences");
    }
    if !contains_fn_token(body) {
        bail!(
            "Anthropic response body has no `fn ` token; candidate \
             cannot satisfy the 'single fn body that compiles' contract"
        );
    }

    Ok(body.to_string())
}

/// Check whether a Rust source string contains at least one `fn `
/// token at a word boundary. We do a cheap scan rather than parsing
/// because the verifier downstream will fully parse the candidate; this
/// is just a fast sanity gate at the synth stage.
fn contains_fn_token(src: &str) -> bool {
    let bytes = src.as_bytes();
    let needle = b"fn ";
    if bytes.len() < needle.len() {
        return false;
    }
    for i in 0..=bytes.len() - needle.len() {
        if &bytes[i..i + needle.len()] == needle {
            // Word boundary: either start of string, or the byte
            // before is not alphanumeric / underscore. Prevents
            // matching `defn ` or similar.
            let boundary = i == 0
                || {
                    let b = bytes[i - 1];
                    !(b.is_ascii_alphanumeric() || b == b'_')
                };
            if boundary {
                return true;
            }
        }
    }
    false
}

/// Estimate "entropy bits" of the candidate relative to the previous
/// source. This is advisory metadata only — the verifier independently
/// proves uniqueness via canonical hashing. We compute a byte-difference
/// ratio scaled to bits so the field is comparable across cycles.
///
/// Formula: `(differing_bytes / max(prev_len, cand_len)) * 8.0`. A
/// fully-rewritten file of N bytes that shares no run of bytes with the
/// previous reads as `8.0 * len_ratio` bits which sits in the same
/// order of magnitude as a hand-tuned per-byte entropy estimate.
fn estimate_entropy_bits(previous: &str, candidate: &str) -> f32 {
    let p = previous.as_bytes();
    let c = candidate.as_bytes();
    let n = p.len().max(c.len());
    if n == 0 {
        return 0.0;
    }
    let common = p.len().min(c.len());
    let mut diff: usize = 0;
    for i in 0..common {
        if p[i] != c[i] {
            diff += 1;
        }
    }
    // Bytes past the end of the shorter buffer are all "different".
    diff += n - common;
    (diff as f32 / n as f32) * 8.0
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req<'a>(prev: &'a str, manifest: &'a [String]) -> SynthRequest<'a> {
        SynthRequest {
            module_name: "lib",
            cycle: 42,
            previous_source: prev,
            contracts_source: "pub trait Hash {} pub trait Aead {}",
            manifest,
            mutation_budget: MutationBudget::default(),
        }
    }

    #[test]
    fn passthrough_is_identity() {
        let prev = "pub fn foo() {}";
        let m: Vec<String> = vec!["foo".into()];
        let resp = PassThrough.synthesize(&req(prev, &m)).unwrap();
        assert_eq!(resp.candidate_source, prev);
    }

    #[test]
    fn prompt_builder_substitutes_module_and_cycle() {
        let prev = "pub fn foo() {}";
        let m: Vec<String> = vec!["foo".into()];
        let s = PromptBuilder::new().build(&req(prev, &m));
        assert!(s.contains("lib"));
        assert!(s.contains("42"));
        assert!(!s.contains("{{module_name}}"));
        assert!(!s.contains("{{cycle}}"));
        assert!(!s.contains("{{previous_source}}"));
    }

    #[test]
    fn manifest_renders_as_bullet_list() {
        let prev = "";
        let m: Vec<String> = vec!["alpha".into(), "beta".into()];
        let s = PromptBuilder::new().build(&req(prev, &m));
        assert!(s.contains("- `alpha`"));
        assert!(s.contains("- `beta`"));
    }

    // === AnthropicSynth unit tests ====================================
    //
    // These tests MUST NOT hit the network. We exercise the parse and
    // request-shape layers directly. The full HTTP round-trip lives in
    // the `#[ignore]`-gated integration test in `tests/synth_anthropic.rs`.

    /// Guard helper. Some tests need to mutate `ANTHROPIC_API_KEY` and
    /// must not race other tests. We serialize the env-mutating cases
    /// behind a process-global mutex (no extra dep — std's mutex is
    /// fine, and we accept poisoning by recovering the guard).
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::{Mutex, OnceLock};
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        let m = LOCK.get_or_init(|| Mutex::new(()));
        m.lock().unwrap_or_else(|p| p.into_inner())
    }

    #[test]
    fn anthropic_synth_missing_key_errors() {
        let _g = env_lock();
        // Snapshot and clear; restore at end via guard drop is manual.
        let prev = env::var(ANTHROPIC_API_KEY_ENV).ok();
        // SAFETY: env mutation is serialized by env_lock above.
        unsafe {
            env::remove_var(ANTHROPIC_API_KEY_ENV);
        }
        let err =
            AnthropicSynth::from_env(PathBuf::from(".")).expect_err("missing key must error");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains(ANTHROPIC_API_KEY_ENV),
            "error must name the env var; got: {}",
            msg
        );
        // Restore so we don't disturb a developer's local shell state.
        if let Some(v) = prev {
            unsafe {
                env::set_var(ANTHROPIC_API_KEY_ENV, v);
            }
        }
    }

    #[test]
    fn anthropic_synth_empty_key_errors() {
        let _g = env_lock();
        let prev = env::var(ANTHROPIC_API_KEY_ENV).ok();
        unsafe {
            env::set_var(ANTHROPIC_API_KEY_ENV, "");
        }
        let err =
            AnthropicSynth::from_env(PathBuf::from(".")).expect_err("empty key must error");
        let msg = format!("{:#}", err);
        assert!(msg.contains(ANTHROPIC_API_KEY_ENV));
        match prev {
            Some(v) => unsafe { env::set_var(ANTHROPIC_API_KEY_ENV, v) },
            None => unsafe { env::remove_var(ANTHROPIC_API_KEY_ENV) },
        }
    }

    #[test]
    fn anthropic_synth_parses_fenced_response() {
        let raw = "Sure, here it is:\n\
                   // SYNTH_BEGIN\n\
                   pub fn one() -> u32 { 1 }\n\
                   // SYNTH_END\n\
                   And that's the file.";
        let body = parse_anthropic_response_text(raw).expect("parse ok");
        assert!(
            body.contains("pub fn one()"),
            "body must retain the fn declaration; got: {}",
            body
        );
        assert!(
            !body.contains("SYNTH_BEGIN"),
            "fences must be stripped; got: {}",
            body
        );
        assert!(
            !body.contains("SYNTH_END"),
            "fences must be stripped; got: {}",
            body
        );
        assert!(
            !body.contains("Sure, here it is"),
            "prose preamble must be stripped"
        );
    }

    #[test]
    fn anthropic_synth_rejects_abort() {
        let err = parse_anthropic_response_text("ABORT").expect_err("ABORT must error");
        let msg = format!("{:#}", err);
        assert!(msg.contains("ABORT"), "error must mention ABORT; got: {}", msg);
    }

    #[test]
    fn anthropic_synth_rejects_abort_with_whitespace() {
        // Trimmed ABORT is still ABORT — models love trailing newlines.
        let err = parse_anthropic_response_text("  ABORT\n").expect_err("ABORT must error");
        assert!(format!("{:#}", err).contains("ABORT"));
    }

    #[test]
    fn anthropic_synth_rejects_missing_fences() {
        let raw = "pub fn one() -> u32 { 1 }";
        let err = parse_anthropic_response_text(raw)
            .expect_err("missing fences must error");
        let msg = format!("{:#}", err);
        assert!(
            msg.contains("SYNTH_BEGIN"),
            "error must explain which fence is missing; got: {}",
            msg
        );
    }

    #[test]
    fn anthropic_synth_rejects_missing_end_fence() {
        let raw = "// SYNTH_BEGIN\npub fn one() -> u32 { 1 }\n";
        let err = parse_anthropic_response_text(raw)
            .expect_err("missing end fence must error");
        assert!(format!("{:#}", err).contains("SYNTH_END"));
    }

    #[test]
    fn anthropic_synth_rejects_response_without_fn() {
        let raw = "// SYNTH_BEGIN\npub const ONE: u32 = 1;\n// SYNTH_END";
        let err = parse_anthropic_response_text(raw)
            .expect_err("no fn token must error");
        assert!(format!("{:#}", err).contains("fn"));
    }

    #[test]
    fn anthropic_synth_rejects_empty_fenced_body() {
        let raw = "// SYNTH_BEGIN\n\n// SYNTH_END";
        let err = parse_anthropic_response_text(raw)
            .expect_err("empty body must error");
        assert!(format!("{:#}", err).contains("empty"));
    }

    #[test]
    fn anthropic_synth_request_body_shape() {
        let _g = env_lock();
        let prev = env::var(ANTHROPIC_API_KEY_ENV).ok();
        unsafe {
            env::set_var(ANTHROPIC_API_KEY_ENV, "test-key-not-real");
        }
        let synth = AnthropicSynth::from_env(PathBuf::from(".")).expect("ctor ok");
        let body = synth.build_request_body("PROMPT-MARKER-XYZZY");
        assert_eq!(body["model"], synth.model);
        assert_eq!(body["max_tokens"], synth.max_tokens);
        assert!(body["messages"].is_array());
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["role"], "user");
        assert_eq!(msgs[0]["content"], "PROMPT-MARKER-XYZZY");
        // Restore env.
        match prev {
            Some(v) => unsafe { env::set_var(ANTHROPIC_API_KEY_ENV, v) },
            None => unsafe { env::remove_var(ANTHROPIC_API_KEY_ENV) },
        }
    }

    #[test]
    fn anthropic_synth_name_is_stable() {
        let _g = env_lock();
        let prev = env::var(ANTHROPIC_API_KEY_ENV).ok();
        unsafe {
            env::set_var(ANTHROPIC_API_KEY_ENV, "test-key-not-real");
        }
        let synth = AnthropicSynth::from_env(PathBuf::from(".")).expect("ctor ok");
        assert_eq!(synth.name(), "anthropic");
        match prev {
            Some(v) => unsafe { env::set_var(ANTHROPIC_API_KEY_ENV, v) },
            None => unsafe { env::remove_var(ANTHROPIC_API_KEY_ENV) },
        }
    }

    #[test]
    fn anthropic_synth_model_override_via_env() {
        let _g = env_lock();
        let prev_key = env::var(ANTHROPIC_API_KEY_ENV).ok();
        let prev_model = env::var(ANTHROPIC_MODEL_ENV).ok();
        unsafe {
            env::set_var(ANTHROPIC_API_KEY_ENV, "test-key-not-real");
            env::set_var(ANTHROPIC_MODEL_ENV, "claude-test-override");
        }
        let synth = AnthropicSynth::from_env(PathBuf::from(".")).expect("ctor ok");
        assert_eq!(synth.model, "claude-test-override");
        match prev_key {
            Some(v) => unsafe { env::set_var(ANTHROPIC_API_KEY_ENV, v) },
            None => unsafe { env::remove_var(ANTHROPIC_API_KEY_ENV) },
        }
        match prev_model {
            Some(v) => unsafe { env::set_var(ANTHROPIC_MODEL_ENV, v) },
            None => unsafe { env::remove_var(ANTHROPIC_MODEL_ENV) },
        }
    }

    #[test]
    fn anthropic_synth_default_model_when_env_unset() {
        let _g = env_lock();
        let prev_key = env::var(ANTHROPIC_API_KEY_ENV).ok();
        let prev_model = env::var(ANTHROPIC_MODEL_ENV).ok();
        unsafe {
            env::set_var(ANTHROPIC_API_KEY_ENV, "test-key-not-real");
            env::remove_var(ANTHROPIC_MODEL_ENV);
        }
        let synth = AnthropicSynth::from_env(PathBuf::from(".")).expect("ctor ok");
        assert_eq!(synth.model, ANTHROPIC_DEFAULT_MODEL);
        match prev_key {
            Some(v) => unsafe { env::set_var(ANTHROPIC_API_KEY_ENV, v) },
            None => unsafe { env::remove_var(ANTHROPIC_API_KEY_ENV) },
        }
        if let Some(v) = prev_model {
            unsafe {
                env::set_var(ANTHROPIC_MODEL_ENV, v);
            }
        }
    }

    #[test]
    fn contains_fn_token_handles_boundaries() {
        assert!(contains_fn_token("fn foo() {}"));
        assert!(contains_fn_token("pub fn foo() {}"));
        assert!(contains_fn_token("\tfn foo()"));
        assert!(!contains_fn_token("defn foo()"));
        assert!(!contains_fn_token("xfn foo()"));
        assert!(!contains_fn_token("const ONE: u32 = 1;"));
        assert!(!contains_fn_token(""));
    }

    #[test]
    fn estimate_entropy_bits_is_zero_for_identical() {
        let s = "pub fn foo() -> u32 { 1 }";
        assert_eq!(estimate_entropy_bits(s, s), 0.0);
    }

    #[test]
    fn estimate_entropy_bits_grows_with_diff() {
        let a = "pub fn foo() -> u32 { 1 }";
        let b = "pub fn bar() -> u32 { 2 }";
        let bits = estimate_entropy_bits(a, b);
        assert!(bits > 0.0, "differing inputs must report > 0 bits");
        assert!(bits <= 8.0, "ratio*8 cannot exceed 8.0");
    }
}
