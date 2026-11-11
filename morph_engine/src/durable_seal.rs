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
//! `CUTTLE_DURABLE_SEALS_DIR` (TASK-146).
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

/// Compute RFC 2104 `HMAC-SHA256(key, data)` using `sha2::Sha256`.
pub fn hmac_sha256_host(key: &[u8; 32], data: &[u8]) -> [u8; 32] {
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..32 {
        ipad[i] ^= key[i];
        opad[i] ^= key[i];
    }
    let mut inner = Sha256::new();
    inner.update(&ipad);
    inner.update(data);
    let inner_dig = inner.finalize();

    let mut outer = Sha256::new();
    outer.update(&opad);
    outer.update(&inner_dig);
    let outer_dig = outer.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&outer_dig);
    out
}

fn constant_time_hex_eq(a: &str, b: &str) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let ab = a.as_bytes();
    let bb = b.as_bytes();
    let mut diff = 0u8;
    for i in 0..ab.len() {
        diff |= ab[i] ^ bb[i];
    }
    diff == 0
}

fn compute_envelope_hmac_hex(
    key: &[u8; 32],
    label: &str,
    sha256: &str,
    len: u64,
    payload_hmac_hex: &str,
) -> String {
    let mut msg = Vec::with_capacity(64 + label.len() + sha256.len() + payload_hmac_hex.len());
    msg.extend_from_slice(b"cuttle-durable-seal-envelope-v1:");
    msg.extend_from_slice(&(label.len() as u64).to_le_bytes());
    msg.extend_from_slice(label.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(sha256.as_bytes());
    msg.push(b':');
    msg.extend_from_slice(&len.to_le_bytes());
    msg.push(b':');
    msg.extend_from_slice(payload_hmac_hex.as_bytes());
    let mac = hmac_sha256_host(key, &msg);
    mac.iter().map(|b| format!("{:02x}", b)).collect()
}

/// On-disk / in-memory seal over a durable blob.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct DurableSeal {
    pub schema: u32,
    /// Operator label (e.g. `audit_snapshot`, `wal_head`, `jfs_super`).
    pub label: String,
    /// Lowercase hex SHA-256 of the sealed bytes.
    pub sha256: String,
    /// Optional lowercase hex `HMAC-SHA256(device_key, payload)` for tamper-proof verification.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hmac_sha256: Option<String>,
    /// Optional lowercase hex `HMAC-SHA256(device_key, envelope)` binding `(label, sha256, len, hmac_sha256)`
    /// so `load_seals_dir` can authenticate seal JSON files when `CUTTLE_DURABLE_SEAL_KEY_FILE` is set.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub envelope_hmac_sha256: Option<String>,
    /// Byte length of the sealed payload.
    pub len: u64,
}

impl DurableSeal {
    /// Hash `payload` and build an unkeyed drift-detection seal with the given label.
    pub fn seal(label: &str, payload: &[u8]) -> Self {
        let mut h = Sha256::new();
        h.update(payload);
        let dig = h.finalize();
        let sha256: String = dig.iter().map(|b| format!("{:02x}", b)).collect();
        Self {
            schema: DURABLE_SEAL_SCHEMA,
            label: label.to_string(),
            sha256,
            hmac_sha256: None,
            envelope_hmac_sha256: None,
            len: payload.len() as u64,
        }
    }

    /// Build a tamper-proof keyed `HMAC-SHA256` seal over `payload` using `key`.
    pub fn seal_keyed(label: &str, payload: &[u8], key: &[u8; 32]) -> Self {
        let mut s = Self::seal(label, payload);
        let mac = hmac_sha256_host(key, payload);
        let mac_hex: String = mac.iter().map(|b| format!("{:02x}", b)).collect();
        let env_hex = compute_envelope_hmac_hex(key, &s.label, &s.sha256, s.len, &mac_hex);
        s.hmac_sha256 = Some(mac_hex);
        s.envelope_hmac_sha256 = Some(env_hex);
        s
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
        if !constant_time_hex_eq(&expect.sha256, &self.sha256) {
            bail!(
                "durable seal sha256 mismatch for label {:?}: seal={} got={}",
                self.label,
                self.sha256,
                expect.sha256
            );
        }
        Ok(())
    }

    /// Verify `payload` against BOTH the SHA-256 digest and the keyed `HMAC-SHA256` MAC in
    /// constant time. Rejects unkeyed seals or seals forged by an attacker who recomputed `sha256`
    /// without `key`.
    pub fn verify_keyed(&self, payload: &[u8], key: &[u8; 32]) -> Result<()> {
        self.verify(payload)?;
        let expected_mac_hex = self
            .hmac_sha256
            .as_deref()
            .ok_or_else(|| anyhow::anyhow!("durable seal {:?} is missing hmac_sha256 tag", self.label))?;
        let computed = hmac_sha256_host(key, payload);
        let computed_hex: String = computed.iter().map(|b| format!("{:02x}", b)).collect();
        if !constant_time_hex_eq(expected_mac_hex, &computed_hex) {
            bail!(
                "durable seal hmac_sha256 mismatch for label {:?}: tamper or wrong key",
                self.label
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
        if let Some(mac) = &s.hmac_sha256 {
            if mac.len() != 64 || !mac.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("seal hmac_sha256 not 64 hex chars");
            }
        }
        if let Some(env_mac) = &s.envelope_hmac_sha256 {
            if env_mac.len() != 64 || !env_mac.chars().all(|c| c.is_ascii_hexdigit()) {
                bail!("seal envelope_hmac_sha256 not 64 hex chars");
            }
        }
        Ok(s)
    }

    /// Verify the seal's keyed envelope `(label, sha256, len, hmac_sha256)` against `key`
    /// in constant time. Rejects unkeyed seals or seals whose label/sha256/len were altered.
    pub fn verify_envelope_keyed(&self, key: &[u8; 32]) -> Result<()> {
        if self.schema != DURABLE_SEAL_SCHEMA {
            bail!(
                "durable seal schema {} unsupported (want {})",
                self.schema,
                DURABLE_SEAL_SCHEMA
            );
        }
        let mac_hex = self.hmac_sha256.as_deref().ok_or_else(|| {
            anyhow::anyhow!("durable seal {:?} is unkeyed (missing hmac_sha256)", self.label)
        })?;
        let expected_env = self.envelope_hmac_sha256.as_deref().ok_or_else(|| {
            anyhow::anyhow!(
                "durable seal {:?} is missing envelope_hmac_sha256 tag",
                self.label
            )
        })?;
        let computed = compute_envelope_hmac_hex(key, &self.label, &self.sha256, self.len, mac_hex);
        if !constant_time_hex_eq(expected_env, &computed) {
            bail!(
                "durable seal envelope_hmac_sha256 mismatch for label {:?}: tamper or wrong key",
                self.label
            );
        }
        Ok(())
    }
}

/// Convenience: seal bytes from a file path.
pub fn seal_file(label: &str, path: &Path) -> Result<DurableSeal> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(DurableSeal::seal(label, &bytes))
}

/// Convenience: seal bytes from a file path with a 256-bit `HMAC-SHA256` key.
pub fn seal_file_keyed(label: &str, path: &Path, key: &[u8; 32]) -> Result<DurableSeal> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    Ok(DurableSeal::seal_keyed(label, &bytes, key))
}

/// Verify file contents against a seal file.
pub fn verify_file(seal_path: &Path, data_path: &Path) -> Result<()> {
    let seal = DurableSeal::read_file(seal_path)?;
    let bytes = fs::read(data_path).with_context(|| format!("read {}", data_path.display()))?;
    seal.verify(&bytes)
}

/// Verify file contents against a keyed `HMAC-SHA256` seal file.
pub fn verify_file_keyed(seal_path: &Path, data_path: &Path, key: &[u8; 32]) -> Result<()> {
    let seal = DurableSeal::read_file(seal_path)?;
    let bytes = fs::read(data_path).with_context(|| format!("read {}", data_path.display()))?;
    seal.verify_keyed(&bytes, key)
}

/// Load a 32-byte per-device secret seal key from `key_path`, strictly
/// rejecting malformed or all-zero files without overwriting them, or
/// generate a fresh 256-bit cryptographically random key via OS CSPRNG
/// (`OsRng`) and persist it exclusively with owner-only permissions on
/// first setup (`R1`).
pub fn load_or_generate_device_seal_key(key_path: &Path) -> Result<[u8; 32]> {
    crate::secret_file::load_or_create_strict_32(key_path)
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
pub const DURABLE_SEALS_DIR_ENV: &str = "CUTTLE_DURABLE_SEALS_DIR";

/// Optional env var pointing to a 32-byte device seal key file; when set,
/// `load_seals_dir` requires every seal JSON to pass `verify_envelope_keyed`.
pub const DURABLE_SEAL_KEY_ENV: &str = "CUTTLE_DURABLE_SEAL_KEY_FILE";

/// Load every `*.json` seal under `dir` into a label → sha256 map.
/// Non-JSON files are skipped. Empty directory → empty map.
/// Duplicate labels across files in `dir` are rejected as a shadowing hazard.
pub fn load_seals_dir(dir: &Path) -> Result<std::collections::BTreeMap<String, String>> {
    if !dir.is_dir() {
        bail!("durable seals dir is not a directory: {}", dir.display());
    }
    let configured_key = match std::env::var_os(DURABLE_SEAL_KEY_ENV) {
        Some(v) if !v.is_empty() => {
            let kp = std::path::PathBuf::from(v);
            Some(
                crate::secret_file::load_strict(&kp)
                    .with_context(|| format!("load {} at {}", DURABLE_SEAL_KEY_ENV, kp.display()))?,
            )
        }
        _ => None,
    };
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
    let mut seen_labels = std::collections::BTreeSet::new();
    let mut seals = Vec::new();
    for p in &paths {
        match DurableSeal::read_file(p) {
            Ok(s) => {
                if !seen_labels.insert(s.label.clone()) {
                    bail!(
                        "duplicate durable seal label {:?} in {}",
                        s.label,
                        dir.display()
                    );
                }
                if let Some(ref key) = configured_key {
                    s.verify_envelope_keyed(key)
                        .with_context(|| format!("verify keyed seal {}", p.display()))?;
                }
                seals.push(s);
            }
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
/// 2. else `CUTTLE_DURABLE_SEALS_DIR` if set
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
            "cuttle_durable_{}",
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
            "cuttle_seals_dir_{}",
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
            "cuttle_seals_empty_{}",
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
            "cuttle_seals_missing_{}",
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        assert!(resolve_durable_seals(Some(&missing)).is_err());
    }

    #[test]
    fn load_seals_dir_rejects_duplicate_labels() {
        let dir = std::env::temp_dir().join(format!(
            "cuttle_seals_dup_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        DurableSeal::seal("wal_head", b"genuine-wal")
            .write_file(&dir.join("01_wal.json"))
            .unwrap();
        DurableSeal::seal("wal_head", b"shadowed-wal")
            .write_file(&dir.join("02_wal.json"))
            .unwrap();
        let res = load_seals_dir(&dir);
        let _ = fs::remove_dir_all(&dir);
        assert!(
            res.is_err(),
            "load_seals_dir must reject duplicate seal labels instead of silently shadowing"
        );
    }

    #[test]
    fn hmac_sha256_host_matches_rfc4231_test_vectors() {
        // RFC 4231 Test Case 1: key = 20 bytes of 0x0b (padded to 32 bytes with 0x00 -> identical
        // to 20-byte HMAC key because keys <= 64 bytes are right-padded with zeros in RFC 2104!).
        let mut k1 = [0u8; 32];
        k1[..20].fill(0x0b);
        let mac1 = hmac_sha256_host(&k1, b"Hi There");
        let hex1: String = mac1.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex1,
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );

        // RFC 4231 Test Case 2: key = "Jefe", data = "what do ya want for nothing?"
        let mut k2 = [0u8; 32];
        k2[..4].copy_from_slice(b"Jefe");
        let mac2 = hmac_sha256_host(&k2, b"what do ya want for nothing?");
        let hex2: String = mac2.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(
            hex2,
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn load_seals_dir_enforces_keyed_envelope_when_seal_key_configured() {
        let dir = std::env::temp_dir().join(format!(
            "cuttle_seals_keyed_{}_{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        fs::create_dir_all(&dir).unwrap();
        let key_path = dir.join("device_seal_key.bin");
        let key = load_or_generate_device_seal_key(&key_path).unwrap();

        let keyed = DurableSeal::seal_keyed("audit_snapshot", b"authentic-audit", &key);
        keyed.verify_keyed(b"authentic-audit", &key).unwrap();
        keyed.verify_envelope_keyed(&key).unwrap();
        keyed.write_file(&dir.join("audit.json")).unwrap();

        unsafe {
            std::env::set_var(DURABLE_SEAL_KEY_ENV, &key_path);
        }
        let m = load_seals_dir(&dir).expect("keyed seal must load when valid key configured");
        assert_eq!(m.get("audit_snapshot"), Some(&keyed.sha256));

        // Unkeyed seal added into dir must be rejected when DURABLE_SEAL_KEY_ENV is active.
        DurableSeal::seal("forged_unkeyed", b"attacker-blob")
            .write_file(&dir.join("forged.json"))
            .unwrap();
        let err_unkeyed = load_seals_dir(&dir);

        // Relabelled keyed seal (tampering label without key) must also fail verify_envelope_keyed.
        let mut relabelled = keyed.clone();
        relabelled.label = "wal_head".into();
        let err_relabel = relabelled.verify_envelope_keyed(&key);

        unsafe {
            std::env::remove_var(DURABLE_SEAL_KEY_ENV);
        }
        let _ = fs::remove_dir_all(&dir);

        assert!(err_unkeyed.is_err(), "unkeyed seal must fail when seal key env is set");
        assert!(err_relabel.is_err(), "relabelled seal must fail keyed envelope verification");
    }
}
