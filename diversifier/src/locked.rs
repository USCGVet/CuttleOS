//! Locked-modules enforcement — TASK-017 prerequisite.
//!
//! # Why this exists
//!
//! Some source files in the workspace MUST NOT be morphed. The
//! canonical example is the KPTI port (`target_enterprise/src/kpti.rs`,
//! landing in this iteration): its trampoline-blob byte sequences and
//! the CR3-swap-before-register-save discipline in `build_user_view`
//! are load-bearing security boundaries. A diversifier statement-reorder
//! that swaps CR3 with a register save would silently break the kernel
//! ↔ user isolation guarantee. The contract surface itself
//! (`contracts/src/lib.rs`) is locked for the same reason — every
//! `target_*` crate's API depends on its bit-stability.
//!
//! # Mechanism
//!
//! A single workspace-rooted file `locked_modules.toml` lists the
//! workspace-relative paths the diversifier must refuse to morph.
//! [`diversify_path`] reads it at call time, canonicalises both the
//! lock-list and the candidate path, and returns
//! [`DiversifyError::LockedModule`] on a match.
//!
//! Callers MUST use [`diversify_path`] rather than the lower-level
//! [`super::diversify`] when the morph target is on disk — bypassing
//! the lock check is a security violation, not a convenience option.
//!
//! # Missing file = fatal
//!
//! If `locked_modules.toml` doesn't exist, [`diversify_path`] returns
//! [`DiversifyError::MissingLockedModulesFile`]. "Silently default to
//! the empty lock set" would let an attacker disable the protection by
//! deleting one file. No silent fallback.
//!
//! # Workspace-root discovery
//!
//! Walk up from the candidate file's directory until we find a file
//! named `locked_modules.toml`. That directory is the workspace root.
//! All lock-list paths are interpreted relative to it.

use std::fs;
use std::path::{Path, PathBuf};

/// Errors that can occur during a path-aware diversify call.
#[derive(Debug)]
pub enum DiversifyError {
    /// The candidate file is in the locked set. Refused; do not morph.
    LockedModule { path: PathBuf, workspace_root: PathBuf },
    /// `locked_modules.toml` was not found by walking up from the candidate
    /// file's directory. Fatal — no silent fallback.
    MissingLockedModulesFile { searched_from: PathBuf },
    /// Couldn't read the candidate file.
    ReadCandidate { path: PathBuf, source: std::io::Error },
    /// Couldn't read `locked_modules.toml`.
    ReadLockedModulesFile { path: PathBuf, source: std::io::Error },
    /// Couldn't parse `locked_modules.toml`.
    ParseLockedModulesFile { path: PathBuf, message: String },
    /// `schema_version` in `locked_modules.toml` is not the current value.
    UnsupportedLockedModulesSchema { path: PathBuf, found: u64, expected: u64 },
    /// Wraps an internal diversify failure (parse / transform error).
    Diversify(anyhow::Error),
}

impl std::fmt::Display for DiversifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DiversifyError::LockedModule { path, workspace_root } => write!(
                f,
                "refusing to morph locked module {} (workspace root {})",
                path.display(),
                workspace_root.display()
            ),
            DiversifyError::MissingLockedModulesFile { searched_from } => write!(
                f,
                "locked_modules.toml not found walking up from {} — refusing to morph (no silent fallback)",
                searched_from.display()
            ),
            DiversifyError::ReadCandidate { path, source } => write!(f, "read candidate {}: {}", path.display(), source),
            DiversifyError::ReadLockedModulesFile { path, source } => {
                write!(f, "read locked_modules.toml at {}: {}", path.display(), source)
            }
            DiversifyError::ParseLockedModulesFile { path, message } => {
                write!(f, "parse locked_modules.toml at {}: {}", path.display(), message)
            }
            DiversifyError::UnsupportedLockedModulesSchema { path, found, expected } => write!(
                f,
                "locked_modules.toml at {} has schema_version={} but this binary supports {}",
                path.display(),
                found,
                expected
            ),
            DiversifyError::Diversify(e) => write!(f, "diversify failed: {:#}", e),
        }
    }
}

impl std::error::Error for DiversifyError {}

/// Current schema version of `locked_modules.toml`. Bumping this is
/// the contract-versioning lever — any change to the policy semantics
/// (e.g., adding a `mode = "soft"` field) requires a bump so that
/// attestations from before/after the change are distinguishable.
pub const LOCKED_MODULES_SCHEMA_VERSION: u64 = 1;

/// Parsed lock-list. Cheap to clone; small (a handful of paths).
#[derive(Debug, Clone)]
pub struct LockedModules {
    /// Absolute path to the workspace root (where `locked_modules.toml`
    /// lives).
    pub workspace_root: PathBuf,
    /// Absolute paths of locked source files. Canonicalised when present
    /// on disk; left as-joined when the path doesn't exist yet (lets the
    /// lock-list reference a file that's about to be created in this
    /// iteration).
    pub locked: Vec<PathBuf>,
}

impl LockedModules {
    /// True iff `candidate_path` matches any locked entry. Path matching
    /// uses `std::fs::canonicalize` when both sides exist; falls back to
    /// lexical equality after `clean_path` normalization otherwise. On
    /// Windows the comparison is case-insensitive (the filesystem is):
    /// `Target_Enterprise\src\KPTI.rs` MUST match a lock entry spelled
    /// `target_enterprise/src/kpti.rs`, or a case-variant path becomes a
    /// lock-bypass primitive.
    pub fn is_locked(&self, candidate_path: &Path) -> bool {
        let cand = canonicalize_loose(candidate_path);
        self.locked.iter().any(|locked| {
            let locked_canon = canonicalize_loose(locked);
            paths_equal(&locked_canon, &cand)
        })
    }
}

/// Platform-aware path equality. Windows filesystems are
/// case-insensitive; Rust's `PathBuf` comparison is not. Normalize case
/// on Windows so a differently-cased spelling of a locked path cannot
/// slip past the check.
fn paths_equal(a: &Path, b: &Path) -> bool {
    if cfg!(windows) {
        a.to_string_lossy().to_lowercase() == b.to_string_lossy().to_lowercase()
    } else {
        a == b
    }
}

/// Walk up from `start_dir` and return the **outermost** directory that
/// contains a `locked_modules.toml` (the highest ancestor, not the
/// nearest). Nearest-match discovery is a shadowing vulnerability: any
/// writer who can drop a `locked_modules.toml` into a directory closer
/// to the candidate (e.g. `target_enterprise/src/`) could replace the
/// real policy with an empty lock list and morph KPTI. The outermost
/// file is the workspace-root policy; attackers inside the workspace
/// cannot plant a file above it.
fn find_workspace_root(start_dir: &Path) -> Option<PathBuf> {
    let mut found: Option<PathBuf> = None;
    let mut here: PathBuf = start_dir.to_path_buf();
    loop {
        let candidate = here.join("locked_modules.toml");
        if candidate.is_file() {
            found = Some(here.clone());
        }
        if !here.pop() {
            return found;
        }
    }
}

/// Load and parse `locked_modules.toml` by walking up from `start_path`.
/// `start_path` may be a file (its parent dir is the walk seed) or a dir.
pub fn load_locked_modules(start_path: &Path) -> Result<LockedModules, DiversifyError> {
    let seed_dir: PathBuf = if start_path.is_file() {
        start_path
            .parent()
            .map(|p| p.to_path_buf())
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        start_path.to_path_buf()
    };
    let root = find_workspace_root(&seed_dir).ok_or_else(|| {
        DiversifyError::MissingLockedModulesFile {
            searched_from: seed_dir.clone(),
        }
    })?;
    parse_locked_modules_at(&root)
}

/// Parse a `locked_modules.toml` in a specific directory. Used directly
/// by tests; production code goes via [`load_locked_modules`].
pub fn parse_locked_modules_at(workspace_root: &Path) -> Result<LockedModules, DiversifyError> {
    let path = workspace_root.join("locked_modules.toml");
    let raw = fs::read_to_string(&path).map_err(|e| DiversifyError::ReadLockedModulesFile {
        path: path.clone(),
        source: e,
    })?;
    parse_locked_modules_str(workspace_root, &path, &raw)
}

/// Parse from an in-memory string. Used by unit tests to avoid touching
/// the filesystem.
pub fn parse_locked_modules_str(
    workspace_root: &Path,
    diag_path: &Path,
    raw: &str,
) -> Result<LockedModules, DiversifyError> {
    let value: toml::Value =
        toml::from_str(raw).map_err(|e| DiversifyError::ParseLockedModulesFile {
            path: diag_path.to_path_buf(),
            message: e.to_string(),
        })?;

    let schema_version =
        value
            .get("schema_version")
            .and_then(|v| v.as_integer())
            .ok_or_else(|| DiversifyError::ParseLockedModulesFile {
                path: diag_path.to_path_buf(),
                message: "missing `schema_version` integer field".into(),
            })? as u64;
    if schema_version != LOCKED_MODULES_SCHEMA_VERSION {
        return Err(DiversifyError::UnsupportedLockedModulesSchema {
            path: diag_path.to_path_buf(),
            found: schema_version,
            expected: LOCKED_MODULES_SCHEMA_VERSION,
        });
    }

    let locked_arr = value
        .get("locked")
        .and_then(|v| v.as_array())
        .ok_or_else(|| DiversifyError::ParseLockedModulesFile {
            path: diag_path.to_path_buf(),
            message: "missing `locked` array field".into(),
        })?;

    let mut locked = Vec::with_capacity(locked_arr.len());
    for entry in locked_arr {
        let s = entry
            .as_str()
            .ok_or_else(|| DiversifyError::ParseLockedModulesFile {
                path: diag_path.to_path_buf(),
                message: format!("entry {:?} is not a string", entry),
            })?;
        locked.push(workspace_root.join(s));
    }

    Ok(LockedModules {
        workspace_root: workspace_root.to_path_buf(),
        locked,
    })
}

/// Try `fs::canonicalize`; on failure (file doesn't exist yet, perm
/// error, etc.) return a lexically-normalised path so we still get a
/// useful comparison. We never return `None` — the caller's
/// `is_locked` walks both sides through this, so consistent-shape
/// outputs are what we need.
fn canonicalize_loose(p: &Path) -> PathBuf {
    fs::canonicalize(p).unwrap_or_else(|_| lexical_normalize(p))
}

/// Lexical-only path normalisation: collapse `.` and `..` components,
/// uniform separator. Cheap, no filesystem access. Matches what
/// `canonicalize` would return for an existing path closely enough that
/// the `is_locked` equality check stays consistent.
fn lexical_normalize(p: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for c in p.components() {
        match c {
            std::path::Component::ParentDir => {
                out.pop();
            }
            std::path::Component::CurDir => {}
            other => out.push(other.as_os_str()),
        }
    }
    out
}

/// Path-aware diversify entry point. Reads the candidate file from disk,
/// checks it against the locked-modules policy, and runs the diversify
/// pipeline iff the path is unlocked.
///
/// Callers SHOULD use this rather than [`super::diversify`] when the
/// morph target is on disk. The lower-level API stays public for tests
/// that drive in-memory source strings.
pub fn diversify_path(
    candidate_path: &Path,
    seed: &super::Seed,
) -> Result<String, DiversifyError> {
    diversify_path_with_log(candidate_path, seed).map(|(s, _log)| s)
}

/// Path-aware diversify entry point that returns the per-cycle decision
/// log alongside the candidate source. Thin wrapper around
/// [`super::diversify_with_log`] with the same locked-modules check as
/// [`diversify_path`]. Used by the morph engine to plumb the log into
/// the attestation entry (TASK-031); legacy callers continue to use
/// [`diversify_path`].
pub fn diversify_path_with_log(
    candidate_path: &Path,
    seed: &super::Seed,
) -> Result<(String, super::DiversifierLog), DiversifyError> {
    diversify_path_with_log_and_options(candidate_path, seed, &super::DiversifyOptions::default())
}

/// Path-aware diversify with explicit [`super::DiversifyOptions`].
/// Same locked-modules check as [`diversify_path`]; use this when the
/// caller needs stack-pad on (or future tunables) without bypassing
/// the lock list.
pub fn diversify_path_with_log_and_options(
    candidate_path: &Path,
    seed: &super::Seed,
    options: &super::DiversifyOptions,
) -> Result<(String, super::DiversifierLog), DiversifyError> {
    let lock = load_locked_modules(candidate_path)?;
    if lock.is_locked(candidate_path) {
        return Err(DiversifyError::LockedModule {
            path: candidate_path.to_path_buf(),
            workspace_root: lock.workspace_root,
        });
    }
    let source =
        fs::read_to_string(candidate_path).map_err(|e| DiversifyError::ReadCandidate {
            path: candidate_path.to_path_buf(),
            source: e,
        })?;
    super::diversify_with_options(&source, seed, options).map_err(DiversifyError::Diversify)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(p: &Path, content: &str) {
        if let Some(parent) = p.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(p, content).unwrap();
    }

    #[test]
    fn parses_valid_locked_modules_toml() {
        let raw = r#"
            schema_version = 1
            locked = ["a/b.rs", "c/d.rs"]
        "#;
        let root = Path::new("/tmp/proteus-test-fake-root");
        let parsed = parse_locked_modules_str(root, Path::new("locked_modules.toml"), raw).unwrap();
        assert_eq!(parsed.locked.len(), 2);
        assert!(parsed.locked[0].ends_with("a/b.rs") || parsed.locked[0].ends_with("a\\b.rs"));
    }

    #[test]
    fn missing_schema_version_is_a_parse_error() {
        let raw = r#"locked = []"#;
        let root = Path::new("/tmp/proteus-test-fake-root");
        let err = parse_locked_modules_str(root, Path::new("x"), raw).unwrap_err();
        assert!(matches!(err, DiversifyError::ParseLockedModulesFile { .. }));
    }

    #[test]
    fn missing_locked_array_is_a_parse_error() {
        let raw = "schema_version = 1\n";
        let root = Path::new("/tmp/proteus-test-fake-root");
        let err = parse_locked_modules_str(root, Path::new("x"), raw).unwrap_err();
        assert!(matches!(err, DiversifyError::ParseLockedModulesFile { .. }));
    }

    #[test]
    fn unsupported_schema_version_rejected() {
        let raw = "schema_version = 99\nlocked = []\n";
        let root = Path::new("/tmp/proteus-test-fake-root");
        let err = parse_locked_modules_str(root, Path::new("x"), raw).unwrap_err();
        assert!(matches!(
            err,
            DiversifyError::UnsupportedLockedModulesSchema { found: 99, expected: 1, .. }
        ));
    }

    #[test]
    fn missing_locked_modules_file_is_fatal() {
        // Use a temp dir that definitely doesn't have a locked_modules.toml.
        let tmp = std::env::temp_dir().join("proteus-locked-test-no-file");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        let candidate = tmp.join("subdir").join("file.rs");
        write(&candidate, "fn f() {}");

        let err = load_locked_modules(&candidate).unwrap_err();
        assert!(
            matches!(err, DiversifyError::MissingLockedModulesFile { .. }),
            "expected MissingLockedModulesFile, got {:?}",
            err
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn end_to_end_locked_path_refused() {
        // Create a tiny fake workspace with a locked_modules.toml and
        // a locked file.
        let tmp = std::env::temp_dir().join("proteus-locked-test-end-to-end");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        write(
            &tmp.join("locked_modules.toml"),
            "schema_version = 1\nlocked = [\"sub/locked.rs\"]\n",
        );
        let locked = tmp.join("sub").join("locked.rs");
        write(&locked, "fn f() {}");

        let err =
            diversify_path(&locked, &super::super::Seed::derive(1, "test")).unwrap_err();
        assert!(
            matches!(err, DiversifyError::LockedModule { .. }),
            "expected LockedModule, got {:?}",
            err
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn end_to_end_unlocked_path_morphs_successfully() {
        let tmp = std::env::temp_dir().join("proteus-locked-test-unlocked");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        write(
            &tmp.join("locked_modules.toml"),
            "schema_version = 1\nlocked = [\"sub/locked.rs\"]\n",
        );
        let unlocked = tmp.join("sub").join("unlocked.rs");
        write(
            &unlocked,
            "pub fn add(a: u32, b: u32) -> u32 { let r = a + b; r }\n",
        );

        let out = diversify_path(&unlocked, &super::super::Seed::derive(1, "test")).unwrap();
        // Production default leaves stack-pad off; prove the path still
        // morphs by re-parsing and checking the body is non-empty Rust.
        assert!(
            !out.trim().is_empty(),
            "diversifier produced empty output"
        );
        let _: syn::File = syn::parse_str(&out).expect("diversified output must reparse");

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn workspace_root_walks_up_from_nested_dir() {
        let tmp = std::env::temp_dir().join("proteus-locked-test-walkup");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        write(&tmp.join("locked_modules.toml"), "schema_version = 1\nlocked = []\n");
        let deep = tmp.join("a").join("b").join("c").join("file.rs");
        write(&deep, "fn f() {}");

        let lock = load_locked_modules(&deep).unwrap();
        // workspace_root.canonicalize() == tmp.canonicalize() (they may
        // differ in case on Windows; compare canonical forms).
        assert_eq!(
            fs::canonicalize(&lock.workspace_root).unwrap(),
            fs::canonicalize(&tmp).unwrap()
        );

        let _ = fs::remove_dir_all(&tmp);
    }

    #[test]
    fn is_locked_returns_false_for_unlocked_path() {
        let lock = LockedModules {
            workspace_root: PathBuf::from("/tmp/fake"),
            locked: vec![PathBuf::from("/tmp/fake/locked.rs")],
        };
        assert!(!lock.is_locked(Path::new("/tmp/fake/other.rs")));
    }

    #[test]
    fn is_locked_returns_true_for_locked_path() {
        let lock = LockedModules {
            workspace_root: PathBuf::from("/tmp/fake"),
            locked: vec![PathBuf::from("/tmp/fake/locked.rs")],
        };
        assert!(lock.is_locked(Path::new("/tmp/fake/locked.rs")));
    }

    #[test]
    fn locked_modules_schema_version_constant_matches_workspace_toml() {
        // If someone bumps the schema version in this file, the workspace
        // locked_modules.toml needs to be bumped too. This test fires if
        // they fall out of sync (when the test runs from the workspace
        // root — it's tolerant of running elsewhere).
        let here = std::env::current_dir().unwrap();
        let mut walk = here.clone();
        let workspace_toml = loop {
            let candidate = walk.join("locked_modules.toml");
            if candidate.is_file() {
                break Some(candidate);
            }
            if !walk.pop() {
                break None;
            }
        };
        if let Some(toml_path) = workspace_toml {
            let raw = fs::read_to_string(&toml_path).unwrap();
            let value: toml::Value = toml::from_str(&raw).unwrap();
            let v = value.get("schema_version").unwrap().as_integer().unwrap() as u64;
            assert_eq!(
                v, LOCKED_MODULES_SCHEMA_VERSION,
                "workspace locked_modules.toml schema_version drifted from code constant"
            );
        }
        // If we couldn't find one, we're running outside the workspace
        // (e.g. in a sub-tree). Nothing to check.
    }
}
