//! Multi-module scheduler. Picks which module the factory should morph
//! next based on age (wall-clock time since its last successful morph)
//! and an operator-configured priority weight.
//!
//! Today's factory invokes the cycle pipeline for exactly one module per
//! `morph run` invocation. With more than one module under management,
//! the operator no longer wants to hand-pick which one — they want to
//! declare a per-module morph cadence and let the factory decide. That
//! declaration lives in `scheduler.toml`; the running state of the
//! schedule lives in `scheduler_state.json`.
//!
//! ## Priority/age formula
//!
//! A module is due when:
//!
//! ```text
//! (now - last_morph_unix) * priority >= max_age_secs
//! ```
//!
//! Priority is a multiplier on elapsed time, so a higher number means a
//! more aggressive morph cadence (the module becomes due *sooner*). With
//! `max_age_secs = 3600`:
//!
//! - priority 1 → due after 3600s elapsed (the full max_age)
//! - priority 10 → due after 360s elapsed
//! - priority 100 → due after 36s elapsed
//!
//! This makes priority an intuitive "morph more often" knob without
//! forcing the operator to compute reciprocal cadences. Among all due
//! modules the highest priority wins; ties break by oldest
//! `last_morph_unix` so chronically-starved modules eventually run.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

/// Exit code returned by `morph next` / `morph tick` when no module is
/// currently due. Mirrors sysexits.h `EX_NOINPUT` so shell wrappers can
/// trivially distinguish "nothing to do" from a real error.
pub const EX_NOINPUT: i32 = 64;

pub const SCHEDULER_CONFIG: &str = "scheduler.toml";
pub const SCHEDULER_STATE: &str = "scheduler_state.json";

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ModuleConfig {
    pub priority: u64,
    pub max_age_secs: u64,
    pub target_dir: PathBuf,
    pub manifest: Option<PathBuf>,
}

/// A morph **bundle** — a set of modules from the same workspace
/// crate that morph **atomically per cycle**: every member is
/// diversified with its own per-(cycle, member) seed, the whole set
/// is handed to the verifier for one combined `cargo build` + test
/// run, and a single attestation entry records the bundle hash plus
/// the per-module artefacts. If the verifier rejects ONE member, the
/// entire bundle is rejected and NO source files on disk are touched.
///
/// This is the load-bearing architectural primitive for whole-kernel
/// metamorphism: declare every diversifiable kernel module under one
/// `[bundle.kernel]` section and the factory rotates all of them
/// together, producing one new kernel ELF per cycle whose function
/// offsets shift across the entire `.text` rather than inside a
/// single module.
///
/// The cadence formula is the same `(now - last) * priority >= max_age_secs`
/// rule used for single modules — bundles compete with modules in the
/// same priority pool, so an operator can mix-and-match.
///
/// # Known design deferments (TASK-036 Phase A landing — 2026-05-16)
///
/// These four constraints are intentional simplifications. Each is
/// fixable with a small additive patch when the trigger condition
/// arrives. **Do not address them speculatively** — solving them
/// before the trigger is the over-engineering trap.
///
/// 1. **No disjoint-membership validation across bundles.** Listing
///    the same module in two different `[bundle.NAME]` sections
///    silently lets later cycles overwrite earlier ones. Unpark when
///    a second bundle joins `scheduler.toml`.
/// 2. **No cross-bundle internal-symbol coupling check.** A module
///    in bundle A directly referencing a private helper in bundle B
///    can break when the two bundles rotate at different cadences.
///    Unpark when 2+ bundles exist AND modules actually interlock
///    outside the `proteus_contracts::*` trait surface.
/// 3. **No `morph rollback-bundle <name>` subcommand.** The
///    `<module>.last_good.rs` files exist per member, so manual
///    restore works; there's just no atomic command to do them all.
///    Unpark when an operator hits the pain in production.
/// 4. **`ModuleArtifact::elf_text_sha256` is per-module** but the
///    kernel is built once per bundle, so every member ends up with
///    the same value. Wasteful but functionally correct. Unpark
///    only on a schema bump that has other reasons to ship.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct BundleConfig {
    pub priority: u64,
    pub max_age_secs: u64,
    /// Path to the workspace member crate, e.g. `target_enterprise`.
    /// Member source files resolve to `<workspace>/src/<module>.rs`.
    pub workspace: PathBuf,
    /// Module names. Each must correspond to an existing source file
    /// under `<workspace>/src/<name>.rs`. The diversifier checks
    /// `locked_modules.toml` at cycle time; locked members are refused
    /// before any work is done, surfacing the misconfiguration loudly.
    pub modules: Vec<String>,
    #[serde(default)]
    pub manifest: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SchedulerConfig {
    #[serde(default)]
    pub modules: BTreeMap<String, ModuleConfig>,
    /// Bundles declared by the operator. Empty when the factory is
    /// configured for single-module-per-cycle operation only (the
    /// legacy mode preserved for backward compatibility).
    #[serde(default, rename = "bundle")]
    pub bundles: BTreeMap<String, BundleConfig>,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct ModuleState {
    pub last_cycle: u64,
    pub last_morph_unix: u64,
}

#[derive(Debug, Clone, Default, Deserialize, Serialize)]
pub struct SchedulerState {
    #[serde(default)]
    pub global_cycle: u64,
    #[serde(default)]
    pub modules: BTreeMap<String, ModuleState>,
    /// Per-bundle last-morph timestamps. Same shape as the per-module
    /// state — a bundle behaves like one item for scheduling purposes.
    #[serde(default)]
    pub bundles: BTreeMap<String, ModuleState>,
}

/// The selection produced by `pick_next`. `next_cycle` is the
/// `global_cycle + 1` value the caller should pass to `run_cycle` and
/// then persist back into state.
#[derive(Debug, Clone)]
pub struct NextChoice {
    pub module: String,
    pub config: ModuleConfig,
    pub next_cycle: u64,
}

/// The bundle equivalent of [`NextChoice`].
#[derive(Debug, Clone)]
pub struct NextBundleChoice {
    pub bundle: String,
    pub config: BundleConfig,
    pub next_cycle: u64,
}

/// Unified scheduler choice: either a single module is next, or a
/// bundle is. The picker compares both pools with the same scoring
/// formula and returns the winning work item.
#[derive(Debug, Clone)]
pub enum NextWork {
    Module(NextChoice),
    Bundle(NextBundleChoice),
}

pub fn load_config(path: &Path) -> Result<SchedulerConfig> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read scheduler config {}", path.display()))?;
    let cfg: SchedulerConfig = toml::from_str(&text)
        .with_context(|| format!("parse scheduler config {}", path.display()))?;
    Ok(cfg)
}

/// Load scheduler state. Missing file is **not** an error: it is
/// equivalent to "no module has ever been morphed", which the scheduler
/// treats as maximally-due. This matters on first run.
pub fn load_state(path: &Path) -> Result<SchedulerState> {
    match fs::read_to_string(path) {
        Ok(text) => {
            let st: SchedulerState = serde_json::from_str(&text)
                .with_context(|| format!("parse scheduler state {}", path.display()))?;
            Ok(st)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(SchedulerState::default()),
        Err(e) => Err(anyhow::Error::new(e)
            .context(format!("read scheduler state {}", path.display()))),
    }
}

pub fn save_state(path: &Path, state: &SchedulerState) -> Result<()> {
    let text = serde_json::to_string_pretty(state).context("serialize scheduler state")?;
    fs::write(path, text)
        .with_context(|| format!("write scheduler state {}", path.display()))?;
    Ok(())
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Pure pick: given a config, state, and the current time, return the
/// chosen module or `None` if nothing is due. Factored out of
/// [`pick_next`] so tests can drive it with synthetic clocks instead of
/// real wall-clock time.
pub fn pick_next_at(
    cfg: &SchedulerConfig,
    state: &SchedulerState,
    now: u64,
) -> Option<NextChoice> {
    // Score candidates: only modules that are due participate.
    // Selection key: (priority DESC, last_morph_unix ASC). Ties on
    // priority break to the oldest last-morph so a chronically-starved
    // module eventually runs even when its peers are also due.
    let mut best: Option<(u64, u64, &str, &ModuleConfig)> = None;
    for (name, mcfg) in &cfg.modules {
        let last = state
            .modules
            .get(name)
            .map(|ms| ms.last_morph_unix)
            .unwrap_or(0);
        let elapsed = now.saturating_sub(last);
        // (now - last) * priority >= max_age_secs
        let weighted = elapsed.saturating_mul(mcfg.priority);
        if weighted < mcfg.max_age_secs {
            continue;
        }
        let candidate_key = (mcfg.priority, last, name.as_str(), mcfg);
        best = match best {
            None => Some(candidate_key),
            Some(prev) => {
                // Prefer higher priority, then older last_morph_unix.
                if candidate_key.0 > prev.0
                    || (candidate_key.0 == prev.0 && candidate_key.1 < prev.1)
                {
                    Some(candidate_key)
                } else {
                    Some(prev)
                }
            }
        };
    }
    best.map(|(_, _, name, mcfg)| NextChoice {
        module: name.to_string(),
        config: mcfg.clone(),
        next_cycle: state.global_cycle + 1,
    })
}

/// Wall-clock variant. Reads `now` from `SystemTime::now()`.
pub fn pick_next(cfg: &SchedulerConfig, state: &SchedulerState) -> Option<NextChoice> {
    pick_next_at(cfg, state, now_unix())
}

/// Score a candidate for the unified picker. Higher tuple wins.
///
/// Scoring: `(priority, -last_morph_unix)` — primary key is priority
/// (higher = preferred), tie-breaker is age (older last morph =
/// preferred so chronically-starved targets eventually run).
///
/// Returns `None` if the candidate is not yet due.
fn score(priority: u64, max_age_secs: u64, last_morph_unix: u64, now: u64) -> Option<(u64, i128)> {
    let elapsed = now.saturating_sub(last_morph_unix);
    let weighted = elapsed.saturating_mul(priority);
    if weighted < max_age_secs {
        return None;
    }
    // Negate last_morph_unix so smaller (older) values produce a
    // larger sort key — `i128` keeps the negation safe across the
    // full `u64` range.
    Some((priority, -(last_morph_unix as i128)))
}

/// Unified picker: walks both `cfg.modules` and `cfg.bundles`, returns
/// whichever has the highest score, or `None` if nothing is due. This
/// is what `morph tick` should call once bundle support is in place;
/// the legacy module-only [`pick_next`] is preserved for callers that
/// have not yet been ported.
pub fn pick_next_work_at(
    cfg: &SchedulerConfig,
    state: &SchedulerState,
    now: u64,
) -> Option<NextWork> {
    // Best across both pools, with the pool tag stored alongside the score
    // so we can construct the right variant when we win.
    enum Pool<'a> {
        Module(&'a str, &'a ModuleConfig),
        Bundle(&'a str, &'a BundleConfig),
    }

    let mut best: Option<((u64, i128), Pool<'_>)> = None;

    for (name, mcfg) in &cfg.modules {
        let last = state
            .modules
            .get(name)
            .map(|s| s.last_morph_unix)
            .unwrap_or(0);
        if let Some(s) = score(mcfg.priority, mcfg.max_age_secs, last, now) {
            let cand = Pool::Module(name.as_str(), mcfg);
            best = match best {
                None => Some((s, cand)),
                Some((bs, bc)) => {
                    if s > bs {
                        Some((s, cand))
                    } else {
                        Some((bs, bc))
                    }
                }
            };
        }
    }
    for (name, bcfg) in &cfg.bundles {
        let last = state
            .bundles
            .get(name)
            .map(|s| s.last_morph_unix)
            .unwrap_or(0);
        if let Some(s) = score(bcfg.priority, bcfg.max_age_secs, last, now) {
            let cand = Pool::Bundle(name.as_str(), bcfg);
            best = match best {
                None => Some((s, cand)),
                Some((bs, bc)) => {
                    if s > bs {
                        Some((s, cand))
                    } else {
                        Some((bs, bc))
                    }
                }
            };
        }
    }

    best.map(|(_, pool)| match pool {
        Pool::Module(name, cfg) => NextWork::Module(NextChoice {
            module: name.to_string(),
            config: cfg.clone(),
            next_cycle: state.global_cycle + 1,
        }),
        Pool::Bundle(name, cfg) => NextWork::Bundle(NextBundleChoice {
            bundle: name.to_string(),
            config: cfg.clone(),
            next_cycle: state.global_cycle + 1,
        }),
    })
}

/// Wall-clock variant of [`pick_next_work_at`].
pub fn pick_next_work(cfg: &SchedulerConfig, state: &SchedulerState) -> Option<NextWork> {
    pick_next_work_at(cfg, state, now_unix())
}

/// Record a successful morph in the state document. Caller is
/// responsible for persisting the returned state via [`save_state`].
pub fn record_success(state: &mut SchedulerState, module: &str, cycle: u64) {
    state.global_cycle = cycle;
    let entry = state.modules.entry(module.to_string()).or_default();
    entry.last_cycle = cycle;
    entry.last_morph_unix = now_unix();
}

/// Bundle equivalent of [`record_success`].
pub fn record_success_bundle(state: &mut SchedulerState, bundle: &str, cycle: u64) {
    state.global_cycle = cycle;
    let entry = state.bundles.entry(bundle.to_string()).or_default();
    entry.last_cycle = cycle;
    entry.last_morph_unix = now_unix();
}

/// Same as [`record_success`] but with an injected clock, for tests.
pub fn record_success_at(state: &mut SchedulerState, module: &str, cycle: u64, now: u64) {
    state.global_cycle = cycle;
    let entry = state.modules.entry(module.to_string()).or_default();
    entry.last_cycle = cycle;
    entry.last_morph_unix = now;
}

/// Bundle equivalent of [`record_success_at`]; injected-clock variant
/// for tests.
pub fn record_success_bundle_at(
    state: &mut SchedulerState,
    bundle: &str,
    cycle: u64,
    now: u64,
) {
    state.global_cycle = cycle;
    let entry = state.bundles.entry(bundle.to_string()).or_default();
    entry.last_cycle = cycle;
    entry.last_morph_unix = now;
}
