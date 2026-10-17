//! TASK-024 — diagnose ELF `.text` dedup observed in `diversity_demo`
//! real-mode runs.
//!
//! # Why this crate exists
//!
//! Iteration 13 (TASK-023) raised distinct ELF `.text` SHA-256 across
//! the 20-cycle `diversity_demo` real-mode run from 1/19 to 15/19,
//! confirming for the first time that source-level diversification
//! reaches the deployed kernel binary. But 4 cycles still collided
//! with an earlier cycle's `.text` section, falling short of the
//! task's `≥ 18/19` acceptance bar.
//!
//! Two hypotheses for the residual dedup are documented in
//! `experiments/diversity_demo/results/REPORT-real.md`:
//!
//! 1. **Seed-distinct, AST-equivalent.** Diversifier output token
//!    streams differ but `syn`-parsed ASTs are identical, so `rustc`
//!    builds byte-identical MIR.
//! 2. **MIR-distinct, codegen-folded.** ASTs differ but LLVM's
//!    inliner / branch optimiser folds the two MIR shapes into the
//!    same machine code.
//!
//! This crate is the diagnostic: it reads `cycles.jsonl`, groups
//! cycles by `elf_text_sha256`, and — when candidate sources have
//! been saved alongside (via `diversity_demo --save-candidates`) —
//! installs each colliding pair into `target_enterprise/src/tls.rs`
//! in turn, runs `cargo rustc --emit=mir`, hashes the emitted MIR,
//! and labels each collision `AstEquivalent` (MIR hashes match) or
//! `CodegenFolded` (MIR hashes differ but ELF still collides).
//!
//! The diagnosis does NOT fix the dedup. It tells us which hypothesis
//! is responsible for each collision, which informs the follow-up
//! task: hypothesis 1 means tighten the diversifier so AST-equivalent
//! rewrites are detected pre-build; hypothesis 2 means add codegen-
//! level perturbations (e.g. `#[inline(never)]` toggles) or shift the
//! gate from `elf_text_sha256` to MIR-hash.

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// One row from `cycles.jsonl`. Matches the public schema of
/// `diversity_demo::CycleRecord` for the fields we consume — kept as
/// a local Deserialize struct so we don't pull every diversity_demo
/// type into our public API.
#[derive(Debug, Clone, Deserialize)]
pub struct CycleRow {
    pub cycle: u64,
    pub accepted: bool,
    pub reject_reason: Option<String>,
    pub candidate_sha256: String,
    pub elf_text_sha256: String,
    pub elf_text_size: usize,
    #[serde(default)]
    pub function_offsets: HashMap<String, u64>,
}

/// Read a JSONL file of `CycleRow` records.
pub fn read_cycles_jsonl(path: &Path) -> Result<Vec<CycleRow>> {
    let text = fs::read_to_string(path)
        .with_context(|| format!("read cycles.jsonl at {}", path.display()))?;
    let mut out = Vec::new();
    for (lineno, line) in text.lines().enumerate() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let row: CycleRow = serde_json::from_str(line).with_context(|| {
            format!("parse cycles.jsonl line {} in {}", lineno + 1, path.display())
        })?;
        out.push(row);
    }
    Ok(out)
}

/// A cluster of accepted cycles whose `elf_text_sha256` collide.
/// Singletons (size == 1) are not collision clusters; this struct is
/// reserved for clusters of size ≥ 2.
#[derive(Debug, Clone, Serialize)]
pub struct CollisionCluster {
    pub elf_text_sha256: String,
    /// Cycle numbers in ascending order.
    pub cycles: Vec<u64>,
    /// Per-cycle `candidate_sha256`s. Same order as `cycles`. If every
    /// element is distinct, the colliding ELFs came from at least
    /// token-stream-distinct sources (canonical_hash hashes the
    /// `quote!` output of the parsed AST, so byte-equal candidate
    /// hashes imply byte-equal AST round-trips).
    pub candidate_sha256s: Vec<String>,
    /// Per-cycle `elf_text_size` (in bytes). Should agree across the
    /// cluster — they share the same `elf_text_sha256` after all —
    /// recorded for sanity.
    pub elf_text_sizes: Vec<usize>,
    /// Function-offset diffs between each cycle in the cluster and
    /// the anchor cycle (cycles[0]). For a true ELF collision these
    /// should be empty (same `.text` bytes = same offsets), but we
    /// record them for paranoia.
    pub function_offset_deltas: Vec<FunctionOffsetDelta>,
}

/// What changed in the `function_offsets` map between two cycles in
/// the same collision cluster.
#[derive(Debug, Clone, Serialize)]
pub struct FunctionOffsetDelta {
    pub anchor_cycle: u64,
    pub other_cycle: u64,
    /// Symbols present in the anchor but missing from `other`.
    pub anchor_only: Vec<String>,
    /// Symbols present in `other` but missing from the anchor.
    pub other_only: Vec<String>,
    /// Symbols present in both but with distinct offsets. (Should be
    /// empty for a true ELF-`.text` collision.)
    pub offset_changed: Vec<(String, u64, u64)>,
}

/// Group accepted cycles by `elf_text_sha256` and return clusters of
/// size ≥ 2 in ascending order of the first cycle in each cluster.
pub fn group_collisions(rows: &[CycleRow]) -> Vec<CollisionCluster> {
    let mut by_hash: BTreeMap<String, Vec<&CycleRow>> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.accepted) {
        by_hash.entry(r.elf_text_sha256.clone()).or_default().push(r);
    }
    let mut clusters: Vec<CollisionCluster> = Vec::new();
    for (sha, mut group) in by_hash {
        if group.len() < 2 {
            continue;
        }
        group.sort_by_key(|r| r.cycle);
        let cycles: Vec<u64> = group.iter().map(|r| r.cycle).collect();
        let candidate_sha256s: Vec<String> =
            group.iter().map(|r| r.candidate_sha256.clone()).collect();
        let elf_text_sizes: Vec<usize> = group.iter().map(|r| r.elf_text_size).collect();
        let anchor = group[0];
        let mut function_offset_deltas = Vec::new();
        for other in group.iter().skip(1) {
            function_offset_deltas.push(diff_function_offsets(anchor, other));
        }
        clusters.push(CollisionCluster {
            elf_text_sha256: sha,
            cycles,
            candidate_sha256s,
            elf_text_sizes,
            function_offset_deltas,
        });
    }
    // Order clusters by the smallest cycle number, so output is
    // reproducible and human-scannable.
    clusters.sort_by_key(|c| c.cycles[0]);
    clusters
}

fn diff_function_offsets(a: &CycleRow, b: &CycleRow) -> FunctionOffsetDelta {
    let a_keys: BTreeSet<&String> = a.function_offsets.keys().collect();
    let b_keys: BTreeSet<&String> = b.function_offsets.keys().collect();
    let mut anchor_only: Vec<String> =
        a_keys.difference(&b_keys).map(|s| (*s).clone()).collect();
    let mut other_only: Vec<String> =
        b_keys.difference(&a_keys).map(|s| (*s).clone()).collect();
    anchor_only.sort();
    other_only.sort();
    let common: Vec<&String> = a_keys.intersection(&b_keys).copied().collect();
    let mut offset_changed: Vec<(String, u64, u64)> = Vec::new();
    for k in common {
        let oa = a.function_offsets[k];
        let ob = b.function_offsets[k];
        if oa != ob {
            offset_changed.push((k.clone(), oa, ob));
        }
    }
    offset_changed.sort();
    FunctionOffsetDelta {
        anchor_cycle: a.cycle,
        other_cycle: b.cycle,
        anchor_only,
        other_only,
        offset_changed,
    }
}

/// Per-pair source-level diff between two candidate files.
///
/// We intentionally do NOT shell out to `diff`; an in-process line
/// hash diff is enough for the diagnostic — we just need to surface
/// whether the candidates differ at all, and where, before the MIR
/// pass tells us whether the differences mattered to the compiler.
#[derive(Debug, Clone, Serialize)]
pub struct SourceDiff {
    pub anchor_path: PathBuf,
    pub other_path: PathBuf,
    pub anchor_line_count: usize,
    pub other_line_count: usize,
    /// Lines present in `anchor` but absent (at the same line index)
    /// from `other`. Capped at `SOURCE_DIFF_CAP`.
    pub anchor_only_lines: Vec<(usize, String)>,
    /// Lines present in `other` but absent (at the same line index)
    /// from `anchor`. Capped at `SOURCE_DIFF_CAP`.
    pub other_only_lines: Vec<(usize, String)>,
    /// Total number of line indices that differ across the two files.
    pub differing_line_count: usize,
}

/// How many distinct diff lines we keep in `SourceDiff` before
/// truncating. Diff payloads can grow large; for a diagnostic the
/// human just needs a representative sample.
pub const SOURCE_DIFF_CAP: usize = 16;

/// Compute a positional line diff between two files. We compare line
/// by line — not a true LCS — because for the diversifier's seed-
/// derived rewrites, identifier renames and statement-order swaps land
/// on the same line as the original, so positional comparison surfaces
/// the actual changes cleanly.
pub fn source_diff(anchor_path: &Path, other_path: &Path) -> Result<SourceDiff> {
    let a_text = fs::read_to_string(anchor_path)
        .with_context(|| format!("read anchor candidate at {}", anchor_path.display()))?;
    let b_text = fs::read_to_string(other_path)
        .with_context(|| format!("read other candidate at {}", other_path.display()))?;
    let a_lines: Vec<&str> = a_text.lines().collect();
    let b_lines: Vec<&str> = b_text.lines().collect();
    let max_lines = a_lines.len().max(b_lines.len());
    let mut differing = 0usize;
    let mut anchor_only_lines: Vec<(usize, String)> = Vec::new();
    let mut other_only_lines: Vec<(usize, String)> = Vec::new();
    for i in 0..max_lines {
        let a = a_lines.get(i).copied().unwrap_or("");
        let b = b_lines.get(i).copied().unwrap_or("");
        if a == b {
            continue;
        }
        differing += 1;
        if anchor_only_lines.len() < SOURCE_DIFF_CAP {
            anchor_only_lines.push((i + 1, a.to_string()));
        }
        if other_only_lines.len() < SOURCE_DIFF_CAP {
            other_only_lines.push((i + 1, b.to_string()));
        }
    }
    Ok(SourceDiff {
        anchor_path: anchor_path.to_path_buf(),
        other_path: other_path.to_path_buf(),
        anchor_line_count: a_lines.len(),
        other_line_count: b_lines.len(),
        anchor_only_lines,
        other_only_lines,
        differing_line_count: differing,
    })
}

/// Classification of a collision pair after MIR comparison.
///
/// `Indeterminate` is returned when the MIR pass was skipped (eg the
/// candidates aren't available on disk, or MIR emission was disabled).
#[derive(Debug, Clone, Serialize, PartialEq, Eq)]
pub enum CollisionLabel {
    /// MIR for the two candidates is byte-identical (after
    /// filename-line normalisation). Hypothesis 1.
    AstEquivalent,
    /// MIR for the two candidates differs, but the linker's output
    /// (`.text` SHA-256) coincides. Hypothesis 2.
    CodegenFolded,
    /// MIR comparison could not run — record reason for the report.
    Indeterminate(String),
}

/// Settings for the MIR-comparison step. `target_enterprise_dir` is
/// the workspace member containing `src/tls.rs` (the file replaced
/// per-cycle in real-mode runs). `cargo_invocation_args` is appended
/// to the base `cargo rustc -p target_enterprise --lib --release`
/// command — typically `["--", "--emit=mir"]`.
#[derive(Debug, Clone)]
pub struct MirSettings {
    pub workspace_root: PathBuf,
    pub target_enterprise_dir: PathBuf,
    /// File inside `target_enterprise_dir/src/` that the diversifier
    /// rewrites and the dedup-diag tool will swap in/out per candidate.
    /// For the post-TASK-023 run this is `tls.rs`.
    pub module_filename: String,
}

impl MirSettings {
    pub fn module_path(&self) -> PathBuf {
        self.target_enterprise_dir.join("src").join(&self.module_filename)
    }
    pub fn backup_path(&self) -> PathBuf {
        self.target_enterprise_dir
            .join("src")
            .join(format!("{}.dedup_diag.bak", self.module_filename))
    }
}

/// Run `cargo rustc -p target_enterprise --lib --release -- --emit=mir`
/// with the candidate at `candidate_path` swapped into
/// `<target>/src/<module>`. Returns the SHA-256 of the resulting MIR
/// (concatenated `*.mir` files matching `target_enterprise-*.mir`).
///
/// The caller is responsible for backing up + restoring the original
/// `<module>` file — see `emit_mir_for_candidates` which sequences
/// multiple emits with a single backup/restore pair.
pub fn emit_mir_hash(candidate_path: &Path, settings: &MirSettings) -> Result<[u8; 32]> {
    let module = settings.module_path();
    let body = fs::read_to_string(candidate_path)
        .with_context(|| format!("read candidate {}", candidate_path.display()))?;
    fs::write(&module, &body)
        .with_context(|| format!("install candidate at {}", module.display()))?;

    // Force a fresh MIR emit by touching the file's mtime forward.
    let now = std::time::SystemTime::now();
    let _ = filetime_set(&module, now);

    let target_dir = settings.workspace_root.join("target");
    let deps_dir = target_dir.join("release").join("deps");

    // Clean any stale MIR files BEFORE we run, so we know which file
    // was produced by THIS invocation.
    if deps_dir.exists() {
        for entry in fs::read_dir(&deps_dir)?.flatten() {
            let p = entry.path();
            if let Some(ext) = p.extension().and_then(|s| s.to_str()) {
                if ext == "mir" {
                    if let Some(name) = p.file_name().and_then(|s| s.to_str()) {
                        if name.starts_with("target_enterprise") {
                            let _ = fs::remove_file(&p);
                        }
                    }
                }
            }
        }
    }

    let out = Command::new("cargo")
        .current_dir(&settings.workspace_root)
        .args([
            "rustc",
            "-p",
            "target_enterprise",
            "--lib",
            "--release",
            "--",
            "--emit=mir",
        ])
        .output()
        .with_context(|| {
            format!(
                "spawn cargo rustc (workspace {})",
                settings.workspace_root.display()
            )
        })?;
    if !out.status.success() {
        bail!(
            "cargo rustc --emit=mir failed (exit {:?}): stderr={}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }

    // Collect every MIR file that names target_enterprise — the
    // package emits a single `target_enterprise-<hash>.mir` per build,
    // but a workspace-wide rebuild may also emit MIR for the same
    // crate at different version hashes. We concatenate them in
    // deterministic order and hash the result.
    let mut mir_files: Vec<PathBuf> = Vec::new();
    if deps_dir.exists() {
        for entry in fs::read_dir(&deps_dir)?.flatten() {
            let p = entry.path();
            if p.extension().and_then(|s| s.to_str()) != Some("mir") {
                continue;
            }
            let Some(name) = p.file_name().and_then(|s| s.to_str()) else {
                continue;
            };
            if name.starts_with("target_enterprise") {
                mir_files.push(p);
            }
        }
    }
    if mir_files.is_empty() {
        bail!(
            "no MIR file produced for target_enterprise after `cargo rustc --emit=mir` \
             (looked under {})",
            deps_dir.display()
        );
    }
    mir_files.sort();
    let mut h = Sha256::new();
    for path in &mir_files {
        let bytes = fs::read(path)
            .with_context(|| format!("read MIR file {}", path.display()))?;
        // Normalise filenames embedded in MIR comments. The MIR text
        // includes lines like `// MIR for target_enterprise::tls::...`
        // — the source file path is identical across runs (we swap
        // contents in place), so we don't need any cross-run
        // normalisation here. We DO normalise CRLF→LF and trailing
        // whitespace just to be tolerant of any Windows-side surprise.
        let s = String::from_utf8_lossy(&bytes);
        for line in s.lines() {
            h.update(line.trim_end().as_bytes());
            h.update(b"\n");
        }
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    Ok(out)
}

/// Minimal filetime nudge — `cargo rustc` is mtime-sensitive when
/// deciding whether to rerun rustc; without this nudge a freshly
/// installed candidate whose mtime equals the previous candidate's
/// mtime can be skipped.
fn filetime_set(path: &Path, time: std::time::SystemTime) -> std::io::Result<()> {
    // Open + close with truncate=false; on Windows opening for write
    // bumps mtime. We use OpenOptions to avoid pulling in the
    // `filetime` crate just for this.
    let mut opts = fs::OpenOptions::new();
    opts.write(true).open(path).map(|_| ())?;
    // Bump again by reading + writing identical bytes — guarantees a
    // non-zero mtime delta even on filesystems that round to seconds.
    let body = fs::read(path)?;
    fs::write(path, &body)?;
    let _ = time; // present for callers that may later use a precise stamp
    Ok(())
}

/// Classify a single collision pair: emit MIR for each candidate,
/// compare hashes, label accordingly. Used by
/// `analyse_cluster_with_mir`. Re-entrant: the caller installs and
/// restores the backup itself, so we do not touch the module file
/// here except via `emit_mir_hash`.
pub fn classify_pair(
    anchor_candidate: &Path,
    other_candidate: &Path,
    settings: &MirSettings,
) -> Result<CollisionLabel> {
    let anchor_hash = emit_mir_hash(anchor_candidate, settings)
        .with_context(|| format!("emit MIR for anchor {}", anchor_candidate.display()))?;
    let other_hash = emit_mir_hash(other_candidate, settings)
        .with_context(|| format!("emit MIR for other {}", other_candidate.display()))?;
    if anchor_hash == other_hash {
        Ok(CollisionLabel::AstEquivalent)
    } else {
        Ok(CollisionLabel::CodegenFolded)
    }
}

/// The full diagnostic produced for one collision cluster.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterDiagnosis {
    pub cluster: CollisionCluster,
    /// Per-pair (anchor vs cycles[i] for i≥1) source diff. `None` if
    /// `--save-candidates` was not run and the source files are
    /// missing on disk.
    pub source_diffs: Vec<Option<SourceDiff>>,
    /// Per-pair MIR classification. Same length as `source_diffs`.
    pub labels: Vec<CollisionLabel>,
}

/// Run the full diagnostic against a cluster: source-diff each pair
/// and (if MIR settings are provided AND the candidate files are
/// available) run the MIR-emit pair classification.
pub fn analyse_cluster(
    cluster: &CollisionCluster,
    candidates_dir: Option<&Path>,
    mir_settings: Option<&MirSettings>,
) -> Result<ClusterDiagnosis> {
    let anchor_cycle = cluster.cycles[0];
    let anchor_candidate = candidates_dir.map(|d| d.join(format!("cycle_{:02}.rs", anchor_cycle)));
    let mut source_diffs: Vec<Option<SourceDiff>> = Vec::with_capacity(cluster.cycles.len() - 1);
    let mut labels: Vec<CollisionLabel> = Vec::with_capacity(cluster.cycles.len() - 1);
    for &other_cycle in &cluster.cycles[1..] {
        let other_candidate =
            candidates_dir.map(|d| d.join(format!("cycle_{:02}.rs", other_cycle)));
        let diff = match (&anchor_candidate, &other_candidate) {
            (Some(a), Some(b)) if a.exists() && b.exists() => Some(source_diff(a, b)?),
            _ => None,
        };
        let label = match (mir_settings, &anchor_candidate, &other_candidate) {
            (Some(settings), Some(a), Some(b)) if a.exists() && b.exists() => {
                // Wrap the call in a backup/restore — emit_mir_hash
                // overwrites the module file, so the caller MUST
                // restore for the workspace to remain buildable.
                let module = settings.module_path();
                let backup = settings.backup_path();
                fs::copy(&module, &backup).with_context(|| {
                    format!("backup {} -> {}", module.display(), backup.display())
                })?;
                let result = classify_pair(a, b, settings);
                fs::write(&module, fs::read(&backup)?)?;
                let _ = fs::remove_file(&backup);
                match result {
                    Ok(label) => label,
                    Err(e) => CollisionLabel::Indeterminate(format!("{:#}", e)),
                }
            }
            (None, _, _) => CollisionLabel::Indeterminate("MIR pass disabled".to_string()),
            _ => CollisionLabel::Indeterminate(
                "candidate source files missing (rerun diversity_demo with --save-candidates)"
                    .to_string(),
            ),
        };
        source_diffs.push(diff);
        labels.push(label);
    }
    Ok(ClusterDiagnosis {
        cluster: cluster.clone(),
        source_diffs,
        labels,
    })
}

/// Top-level summary: cluster count, per-label tally, and a
/// human-readable Markdown rendering. Returned by `run_diagnosis`.
#[derive(Debug, Clone, Serialize)]
pub struct DiagnosisSummary {
    pub total_accepted_cycles: usize,
    pub distinct_elf_text_sha256: usize,
    pub cluster_count: usize,
    pub redundant_cycle_count: usize,
    /// Per-label tally over all per-pair classifications across all
    /// clusters. Useful for the headline number (eg "3/4 collisions
    /// AST-equivalent").
    pub ast_equivalent_pairs: usize,
    pub codegen_folded_pairs: usize,
    pub indeterminate_pairs: usize,
    pub clusters: Vec<ClusterDiagnosis>,
    pub markdown: String,
}

/// Drive the full diagnostic end-to-end. Reads `cycles.jsonl`,
/// classifies collisions, optionally runs the MIR pass, and renders a
/// Markdown summary.
pub fn run_diagnosis(
    cycles_jsonl: &Path,
    candidates_dir: Option<&Path>,
    mir_settings: Option<&MirSettings>,
) -> Result<DiagnosisSummary> {
    let rows = read_cycles_jsonl(cycles_jsonl)?;
    let total_accepted: usize = rows.iter().filter(|r| r.accepted).count();
    let mut by_sha: BTreeSet<String> = BTreeSet::new();
    for r in rows.iter().filter(|r| r.accepted) {
        by_sha.insert(r.elf_text_sha256.clone());
    }
    let distinct_elf = by_sha.len();
    let clusters = group_collisions(&rows);
    let redundant_cycle_count: usize = clusters.iter().map(|c| c.cycles.len() - 1).sum();
    let mut diagnoses: Vec<ClusterDiagnosis> = Vec::new();
    let mut ast_eq = 0usize;
    let mut codegen = 0usize;
    let mut indet = 0usize;
    for cluster in &clusters {
        let diag = analyse_cluster(cluster, candidates_dir, mir_settings)?;
        for lab in &diag.labels {
            match lab {
                CollisionLabel::AstEquivalent => ast_eq += 1,
                CollisionLabel::CodegenFolded => codegen += 1,
                CollisionLabel::Indeterminate(_) => indet += 1,
            }
        }
        diagnoses.push(diag);
    }
    let markdown = render_markdown(
        total_accepted,
        distinct_elf,
        &diagnoses,
        ast_eq,
        codegen,
        indet,
    );
    Ok(DiagnosisSummary {
        total_accepted_cycles: total_accepted,
        distinct_elf_text_sha256: distinct_elf,
        cluster_count: clusters.len(),
        redundant_cycle_count,
        ast_equivalent_pairs: ast_eq,
        codegen_folded_pairs: codegen,
        indeterminate_pairs: indet,
        clusters: diagnoses,
        markdown,
    })
}

fn short_hash(h: &str, n: usize) -> &str {
    let upper = n.min(h.len());
    &h[..upper]
}

fn truncate(s: &str, max: usize) -> String {
    let mut chars: Vec<char> = s.chars().collect();
    if chars.len() <= max {
        return s.to_string();
    }
    chars.truncate(max);
    let mut out: String = chars.into_iter().collect();
    out.push_str(&format!(" … [+{} bytes truncated]", s.len().saturating_sub(max)));
    out
}

fn render_markdown(
    total_accepted: usize,
    distinct_elf: usize,
    clusters: &[ClusterDiagnosis],
    ast_eq: usize,
    codegen: usize,
    indet: usize,
) -> String {
    let mut s = String::new();
    s.push_str("## Dedup diagnosis (TASK-024)\n\n");
    s.push_str(&format!(
        "- Accepted cycles: {}  \n- Distinct `elf_text_sha256`: {}  \n",
        total_accepted, distinct_elf
    ));
    s.push_str(&format!(
        "- Collision clusters (size ≥ 2): {}  \n",
        clusters.len()
    ));
    let pairs = ast_eq + codegen + indet;
    s.push_str(&format!(
        "- Per-pair classifications: {ast} AST-equivalent, {cg} codegen-folded, {ind} indeterminate (total {pairs})\n\n",
        ast = ast_eq,
        cg = codegen,
        ind = indet,
        pairs = pairs,
    ));
    for diag in clusters {
        let c = &diag.cluster;
        s.push_str(&format!(
            "### Cluster — `elf_text_sha256 = {}…` (cycles {:?}, size {} bytes)\n\n",
            short_hash(&c.elf_text_sha256, 16),
            c.cycles,
            c.elf_text_sizes[0],
        ));
        s.push_str("| anchor → other | candidate_sha256 anchor | candidate_sha256 other | label | source diff (lines) |\n");
        s.push_str("|---|---|---|---|---|\n");
        for (i, &other_cycle) in c.cycles.iter().enumerate().skip(1) {
            let lab = &diag.labels[i - 1];
            let diff_summary = match &diag.source_diffs[i - 1] {
                Some(d) => format!("{} differing of {} max", d.differing_line_count, d.anchor_line_count.max(d.other_line_count)),
                None => "n/a (candidates not saved)".to_string(),
            };
            s.push_str(&format!(
                "| {} → {} | `{}…` | `{}…` | {} | {} |\n",
                c.cycles[0],
                other_cycle,
                short_hash(&c.candidate_sha256s[0], 16),
                short_hash(&c.candidate_sha256s[i], 16),
                match lab {
                    CollisionLabel::AstEquivalent => "AST-equivalent".to_string(),
                    CollisionLabel::CodegenFolded => "codegen-folded".to_string(),
                    CollisionLabel::Indeterminate(r) => format!("indeterminate ({})", r),
                },
                diff_summary,
            ));
        }
        s.push('\n');
        // First non-empty source-diff excerpt (up to 6 line pairs).
        // The diversifier emits candidate sources through `quote!`,
        // which collapses the whole file onto a single line — so we
        // additionally trim each line's payload to PER_LINE_CAP bytes
        // before printing, otherwise a single excerpt can be 50+ KB.
        const PER_LINE_CAP: usize = 240;
        for d in diag.source_diffs.iter().flatten().take(1) {
            s.push_str("Representative source diff excerpt (per-line payload capped):\n\n```\n");
            let cap = 6.min(d.anchor_only_lines.len());
            for i in 0..cap {
                let (al, av) = &d.anchor_only_lines[i];
                let (bl, bv) = d.other_only_lines.get(i).cloned().unwrap_or((0, String::new()));
                s.push_str(&format!("-{:>5}: {}\n", al, truncate(av, PER_LINE_CAP)));
                s.push_str(&format!("+{:>5}: {}\n", bl, truncate(&bv, PER_LINE_CAP)));
            }
            if d.differing_line_count > cap {
                s.push_str(&format!(
                    "... ({} more differing lines)\n",
                    d.differing_line_count - cap
                ));
            }
            s.push_str("```\n\n");
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_row(
        cycle: u64,
        accepted: bool,
        cand_sha: &str,
        elf_sha: &str,
        elf_size: usize,
        offsets: &[(&str, u64)],
    ) -> CycleRow {
        let mut m = HashMap::new();
        for (k, v) in offsets {
            m.insert((*k).to_string(), *v);
        }
        CycleRow {
            cycle,
            accepted,
            reject_reason: None,
            candidate_sha256: cand_sha.to_string(),
            elf_text_sha256: elf_sha.to_string(),
            elf_text_size: elf_size,
            function_offsets: m,
        }
    }

    /// Fixture 1: a 5-cycle run where cycles 1 and 4 produced the same
    /// ELF but distinct candidate sources. We don't yet know which
    /// hypothesis is responsible (the MIR pass would tell us); we
    /// just verify the grouping logic surfaces the cluster correctly.
    #[test]
    fn collision_cluster_is_grouped_by_elf_text_sha256() {
        let rows = vec![
            make_row(0, true, "candA", "elfX", 100, &[("foo", 0x10)]),
            make_row(1, true, "candB", "elfY", 100, &[("foo", 0x10)]),
            make_row(2, true, "candC", "elfZ", 100, &[("foo", 0x10)]),
            make_row(3, true, "candD", "elfW", 100, &[("foo", 0x10)]),
            make_row(4, true, "candE", "elfY", 100, &[("foo", 0x10)]),
        ];
        let clusters = group_collisions(&rows);
        assert_eq!(clusters.len(), 1, "expected one collision cluster");
        let c = &clusters[0];
        assert_eq!(c.cycles, vec![1, 4]);
        assert_eq!(c.candidate_sha256s, vec!["candB".to_string(), "candE".to_string()]);
        assert_eq!(c.elf_text_sha256, "elfY");
    }

    /// Fixture 2: a 5-cycle run with TWO independent collision
    /// clusters — cycles 0&2 and cycles 1&3. Exercises the ordering
    /// guarantee (clusters are sorted by smallest cycle in each).
    #[test]
    fn two_independent_clusters_are_both_reported_in_cycle_order() {
        let rows = vec![
            make_row(0, true, "a", "elfP", 50, &[]),
            make_row(1, true, "b", "elfQ", 50, &[]),
            make_row(2, true, "c", "elfP", 50, &[]),
            make_row(3, true, "d", "elfQ", 50, &[]),
            make_row(4, true, "e", "elfR", 50, &[]),
        ];
        let clusters = group_collisions(&rows);
        assert_eq!(clusters.len(), 2);
        assert_eq!(clusters[0].cycles, vec![0, 2]);
        assert_eq!(clusters[1].cycles, vec![1, 3]);
    }

    /// Fixture 3: rejected cycles must NEVER be counted as collisions
    /// even if they accidentally share an `elf_text_sha256` placeholder
    /// (which they do, as the empty string, in real cycles.jsonl).
    #[test]
    fn rejected_cycles_are_excluded_from_collision_clusters() {
        let rows = vec![
            make_row(0, true, "a", "elfX", 50, &[]),
            make_row(1, false, "", "", 0, &[]),
            make_row(2, false, "", "", 0, &[]),
            make_row(3, true, "b", "elfY", 50, &[]),
        ];
        let clusters = group_collisions(&rows);
        assert!(
            clusters.is_empty(),
            "no genuine collisions; got {} clusters",
            clusters.len()
        );
    }

    /// Singletons (size-1 groups) must never be reported as collisions.
    #[test]
    fn singleton_groups_are_not_clusters() {
        let rows = vec![
            make_row(0, true, "a", "elfA", 50, &[]),
            make_row(1, true, "b", "elfB", 50, &[]),
            make_row(2, true, "c", "elfC", 50, &[]),
        ];
        let clusters = group_collisions(&rows);
        assert!(clusters.is_empty());
    }

    /// Function-offset delta exposed when same `.text` somehow has
    /// different parsed offsets — a sanity guard for the data path.
    #[test]
    fn function_offset_delta_records_diverging_offset() {
        let rows = vec![
            make_row(0, true, "a", "elfX", 50, &[("foo", 0x10), ("bar", 0x20)]),
            make_row(1, true, "b", "elfX", 50, &[("foo", 0x10), ("bar", 0x30)]),
        ];
        let clusters = group_collisions(&rows);
        assert_eq!(clusters.len(), 1);
        let delta = &clusters[0].function_offset_deltas[0];
        assert_eq!(delta.offset_changed, vec![("bar".to_string(), 0x20, 0x30)]);
    }

    #[test]
    fn source_diff_counts_differing_lines_positionally() {
        let dir = std::env::temp_dir().join("dedup_diag_test_src_diff");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.rs");
        let b = dir.join("b.rs");
        fs::write(&a, "fn main() {\n    let x = 1;\n    let y = 2;\n}\n").unwrap();
        fs::write(&b, "fn main() {\n    let x = 9;\n    let y = 2;\n}\n").unwrap();
        let d = source_diff(&a, &b).unwrap();
        assert_eq!(d.differing_line_count, 1);
        assert_eq!(d.anchor_only_lines.len(), 1);
        assert_eq!(d.anchor_only_lines[0].0, 2);
        assert!(d.anchor_only_lines[0].1.contains("let x = 1"));
        assert!(d.other_only_lines[0].1.contains("let x = 9"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn source_diff_handles_unequal_line_counts() {
        let dir = std::env::temp_dir().join("dedup_diag_test_src_diff_uneven");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let a = dir.join("a.rs");
        let b = dir.join("b.rs");
        fs::write(&a, "fn f() {\n}\n").unwrap();
        fs::write(&b, "fn f() {\n    let x = 1;\n}\n").unwrap();
        let d = source_diff(&a, &b).unwrap();
        assert!(d.differing_line_count >= 1);
        assert!(d.other_only_lines.iter().any(|(_, v)| v.contains("let x = 1")));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_cycles_jsonl_round_trips_through_serde() {
        let dir = std::env::temp_dir().join("dedup_diag_test_jsonl");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("cycles.jsonl");
        let body = "{\"cycle\":0,\"accepted\":true,\"reject_reason\":null,\
                    \"candidate_sha256\":\"abc\",\"elf_text_sha256\":\"xyz\",\
                    \"elf_text_size\":10,\"function_offsets\":{\"f\":16}}\n\
                    {\"cycle\":1,\"accepted\":false,\"reject_reason\":\"bad\",\
                    \"candidate_sha256\":\"\",\"elf_text_sha256\":\"\",\
                    \"elf_text_size\":0,\"function_offsets\":{}}\n";
        fs::write(&path, body).unwrap();
        let rows = read_cycles_jsonl(&path).unwrap();
        assert_eq!(rows.len(), 2);
        assert!(rows[0].accepted);
        assert!(!rows[1].accepted);
        assert_eq!(rows[0].function_offsets.get("f"), Some(&16));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn markdown_summary_includes_cluster_count_and_label_tally() {
        let rows = vec![
            make_row(0, true, "a", "elfX", 50, &[]),
            make_row(1, true, "b", "elfX", 50, &[]),
            make_row(2, true, "c", "elfY", 50, &[]),
        ];
        let clusters = group_collisions(&rows);
        assert_eq!(clusters.len(), 1);
        let mut diagnoses = Vec::new();
        for c in &clusters {
            diagnoses.push(ClusterDiagnosis {
                cluster: c.clone(),
                source_diffs: vec![None],
                labels: vec![CollisionLabel::Indeterminate(
                    "MIR pass disabled".to_string(),
                )],
            });
        }
        let md = render_markdown(3, 2, &diagnoses, 0, 0, 1);
        assert!(md.contains("Accepted cycles: 3"));
        assert!(md.contains("Distinct `elf_text_sha256`: 2"));
        assert!(md.contains("Collision clusters (size \u{2265} 2): 1"));
        assert!(md.contains("indeterminate"));
    }

    #[test]
    fn collision_label_serializes_as_expected() {
        let s = serde_json::to_string(&CollisionLabel::AstEquivalent).unwrap();
        assert_eq!(s, "\"AstEquivalent\"");
        let s = serde_json::to_string(&CollisionLabel::CodegenFolded).unwrap();
        assert_eq!(s, "\"CodegenFolded\"");
        let s = serde_json::to_string(&CollisionLabel::Indeterminate(
            "MIR pass disabled".to_string(),
        ))
        .unwrap();
        assert!(s.contains("Indeterminate"));
        assert!(s.contains("MIR pass disabled"));
    }
}
