//! Durable-state sealing scaffold (TASK-137).
//!
//! **Honest scope:** morph resets *code*, not durable data (WAL, audit
//! rings, fs images, keys). This module is a **host-side** helper to
//! hash-seal opaque durable blobs so operators / factory tooling can
//! detect *change* against a baseline. It does **not**:
//!
//! - prevent implants from writing durable state
//! - run inside the guest kernel (no_std path is a later task)
//! - claim implant prevention (seals detect change only)
//!
//! Attest binding: schema v10 `durable_seals` (TASK-140); morph cycle
//! can load a seals directory via `--durable-seals-dir` /
//! `PROTEUS_DURABLE_SEALS_DIR` (TASK-146).
//!
//! Wire format of a seal file (JSON, one object):
//! ```json
//! { "schema": 1, "label": "audit_snapshot", "sha256": "<64 hex>", "len": 123 }
//! ```

use anyhow::{bail, Context, Result};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Current seal file schema version.
pub const DURABLE_SEAL_SCHEMA: u32 = 1;

/// On-disk / in-memory seal over a durable blob.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DurableSeal {
    pub schema: u32,
    /// Operator label (e.g. `audit_snapshot`, `wal_head`, `jfs_super`).
    pub label: String,
    /// Lowercase hex SHA-256 of the sealed bytes.
    pub sha256: String,
    /// Byte length of the sealed payload.
    pub len: u64,
}

impl DurableSeal {
    /// Hash `payload` and build a seal with the given label.
    pub fn seal(label: &str, payload: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(payload);
        let dig = h.finalize();
        let sha256: String = dig.iter().map(|b| format!("{:02x}", b)).collect();
        Self {
            schema: DURABLE_SEAL_SCHEMA,
            label: label.to_string(),
            sha256,
            len: payload.len() as u64,
        }
    }

    /// Verify `payload` matches this seal (label ignored for equality of
    /// content; schema and hash + len must match).
    pub fn verify(&self, payload: &[u8]) -> Result<()> {
        if self.schema != DURABLE_SEAL_SCHEMA {
            bail!(
                "durable seal schema {} unsupported (want {})",
                self.schema,
                DURABLE_SEAL_SCHEMA
            );
        }
        if self.len != payload.len() as u64 {
            bail!(
                "durable seal len mismatch: seal={} payload={}",
                self.len,
                payload.len()
            );
        }
        let expect = DurableSeal::seal(&self.label, payload);
        if expect.sha256 != self.sha256 {
            bail!(
                "durable seal sha256 mismatch for label {:?}: seal={} got={}",
                self.label,
                self.sha256,
                expect.sha256
            );
        }
        Ok(())
    }

    /// Write seal JSON to `path`.
    pub fn write_file(&self, path: &Path) -> Result<()> {
        let text = serde_json::to_string_pretty(self).context("serialize durable seal")?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).ok();
        }
        fs::write(path, text).with_context(|| format!("write seal {}", path.display()))?;
        Ok(())
    }

    /// Load seal JSON from `path`.
    pub fn read_file(path: &Path) -> Result<Self> {
        let text = fs::read_to_string(path)
            .with_context(|| format!("read seal {}", path.display()))?;
        let s: Self = serde_json::from_str(&text).context("parse durable seal JSON")?;
        if s.schema != DURABLE_SEAL_SCHEMA {
            bail!("unsupported seal schema {}", s.schema);
        }
        if s.sha256.len() != 64 || !s.sha256.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!("seal sha256 not 64 hex chars");
        }
        Ok(s)
    }
}

/// Convenience: seal bytes from a file path.
pub fn seal_file(label: &str, path: &Path) -> Result<DurableSeal> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(DurableSeal::seal(label, &bytes))
}

/// Verify file contents against a seal file.
pub fn verify_file(seal_path: &Path, data_path: &Path) -> Result<()> {
    let seal = DurableSeal::read_file(seal_path)?;
    let bytes = fs::read(data_path).with_context(|| format!("read {}", data_path.display()))?;
    seal.verify(&bytes)
}

/// Build the attest-entry map form of one or more seals (TASK-140).
/// Keys = labels; values = sha256 hex. Last seal wins on label clash.
pub fn seals_map_from(seals: &[DurableSeal]) -> std::collections::BTreeMap<String, String> {
    let mut m = std::collections::BTreeMap::new();
    for s in seals {
        m.insert(s.label.clone(), s.sha256.clone());
    }
    m
}

/// Structural check for `AttestEntry.durable_seals` (hex digests only).
pub fn validate_seals_map(m: &std::collections::BTreeMap<String, String>) -> Result<()> {
    for (label, dig) in m {
        if label.is_empty() {
            bail!("durable_seals: empty label");
        }
        if dig.len() != 64 || !dig.chars().all(|c| c.is_ascii_hexdigit()) {
            bail!(
                "durable_seals[{label:?}]: expected 64 hex chars, got len={}",
                dig.len()
            );
        }
    }
    Ok(())
}

/// Env var: directory of `*.json` DurableSeal files to attach on morph
/// (TASK-146). Used when CLI `--durable-seals-dir` is omitted.
pub const DURABLE_SEALS_DIR_ENV: &str = "PROTEUS_DURABLE_SEALS_DIR";

/// Load every `*.json` seal under `dir` into a label → sha256 map.
/// Non-JSON files are skipped. Empty directory → empty map.
/// Duplicate labels: last file wins (sorted by file name for stability).
pub fn load_seals_dir(dir: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    if !dir.is_dir() {
        bail!("durable seals dir is not a directory: {}", dir.display());
    }
    let mut paths: Vec<_> = fs::read_dir(dir)
        .with_context(|| format!("read seals dir {}", dir.display()))?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .and_then(|x| x.to_str())
                .map(|x| x.eq_ignore_ascii_case("json"))
                .unwrap_or(false)
        })
        .collect();
    paths.sort();
    let mut seals = Vec::new();
    for p in &paths {
        match DurableSeal::read_file(p) {
            Ok(s) => seals.push(s),
            Err(e) => {
                bail!(
                    "load seal {}: {:#}",
                    p.display(),
                    e
                );
            }
        }
    }
    let m = seals_map_from(&seals);
    validate_seals_map(&m)?;
    Ok(m)
}

/// Resolve seals for a morph cycle (TASK-146):
/// 1. explicit `dir` if `Some`
/// 2. else `PROTEUS_DURABLE_SEALS_DIR` if set
/// 3. else empty map (legacy / no seals)
///
/// If a path is configured but missing, returns Err (operator intent).
pub fn resolve_durable_seals(
    dir: Option<&Path>,
) -> Result<std::collections::BTreeMap<String, String>> {
    let chosen = match dir {
        Some(p) => Some(p.to_path_buf()),
        None => std::env::var_os(DURABLE_SEALS_DIR_ENV).map(std::path::PathBuf::from),
    };
    match chosen {
        None => Ok(std::collections::BTreeMap::new()),
        Some(p) => {
            if !p.exists() {
                bail!(
                    "durable seals dir does not exist: {} (from CLI or {})",
                    p.display(),
                    DURABLE_SEALS_DIR_ENV
                );
            }
            load_seals_dir(&p)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn seal_verify_roundtrip() {
        let payload = b"audit-snapshot-v1-demo-bytes";
        let s = DurableSeal::seal("audit_snapshot", payload);
        assert_eq!(s.schema, DURABLE_SEAL_SCHEMA);
        assert_eq!(s.len, payload.len() as u64);
        assert_eq!(s.sha256.len(), 64);
        s.verify(payload).unwrap();
    }

    #[test]
    fn seal_detects_tamper() {
        let s = DurableSeal::seal("wal", b"abc");
        assert!(s.verify(b"abd").is_err());
        assert!(s.verify(b"ab").is_err());
    }

    #[test]
    fn seal_file_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "proteus_durable_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let data = dir.join("blob.bin");
        let seal_path = dir.join("blob.seal.json");
        fs::write(&data, b"durable-blob-contents").unwrap();
        let s = seal_file("blob", &data).unwrap();
        s.write_file(&seal_path).unwrap();
        verify_file(&seal_path, &data).unwrap();
        // Tamper data → verify fails.
        fs::write(&data, b"tampered").unwrap();
        assert!(verify_file(&seal_path, &data).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn deterministic_hash() {
        let a = DurableSeal::seal("x", b"same");
        let b = DurableSeal::seal("x", b"same");
        assert_eq!(a.sha256, b.sha256);
    }

    #[test]
    fn seals_map_and_validate() {
        let s = DurableSeal::seal("audit", b"payload");
        let m = seals_map_from(&[s.clone()]);
        assert_eq!(m.get("audit"), Some(&s.sha256));
        validate_seals_map(&m).unwrap();
        let mut bad = m.clone();
        bad.insert("x".into(), "dead".into());
        assert!(validate_seals_map(&bad).is_err());
    }

    #[test]
    fn load_seals_dir_roundtrip() {
        let dir = std::env::temp_dir().join(format!(
            "proteus_seals_dir_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        DurableSeal::seal("audit_snapshot", b"snap-v1")
            .write_file(&dir.join("audit.json"))
            .unwrap();
        DurableSeal::seal("wal_head", b"wal-bytes")
            .write_file(&dir.join("wal.json"))
            .unwrap();
        // Non-json ignored
        fs::write(dir.join("notes.txt"), b"ignore").unwrap();
        let m = load_seals_dir(&dir).unwrap();
        assert_eq!(m.len(), 2);
        assert_eq!(
            m.get("audit_snapshot"),
            Some(&DurableSeal::seal("audit_snapshot", b"snap-v1").sha256)
        );
        assert_eq!(
            m.get("wal_head"),
            Some(&DurableSeal::seal("wal_head", b"wal-bytes").sha256)
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_durable_seals_empty_dir() {
        let dir = std::env::temp_dir().join(format!(
            "proteus_seals_empty_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let m = resolve_durable_seals(Some(&dir)).unwrap();
        assert!(m.is_empty());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn resolve_durable_seals_missing_dir_errs() {
        let missing = std::env::temp_dir().join(format!(
            "proteus_seals_missing_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(resolve_durable_seals(Some(&missing)).is_err());
    }
}
