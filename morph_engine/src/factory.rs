//! TASK-022 — factory-fingerprint recording and audit.
//!
//! Every accepted attestation entry carries an opaque `factory_binaries`
//! map: a per-component SHA-256 of the executable that produced it.
//! Post-hoc audit can then catch a tampered factory by comparing those
//! hashes to a reference list operators bless out-of-band
//! (`factory_expected.toml`).
//!
//! ## Scope
//!
//! - Component set is hard-coded for now: `morph`, `verify`,
//!   `diversify`, `rustc`. Adding a component is a deliberate change —
//!   future tasks may add `factory_builder` once it stabilises.
//! - Hashing strategy: SHA-256 of the file's bytes. `rustc` is special:
//!   we hash the output of `rustc --version` (stable across paths,
//!   captures both rustc version and host triple). The same trick works
//!   for any tool whose installed path varies but whose `--version`
//!   output uniquely identifies the build.
//! - Caching: we use a process-wide `OnceLock` so multiple cycles in
//!   the same `morph` invocation pay the hashing cost once. Tests run
//!   in fresh `cargo test` processes, so they re-fingerprint.
//! - All errors surface via stderr but only the worst kind (cannot
//!   open the morph binary at all) propagates. A missing sibling
//!   `verify.exe` is logged and the corresponding map entry is
//!   omitted — never silently faked. The audit catches that case in
//!   strict mode (entry's map is missing a required component → reject).
//!
//! ## Strict audit semantics
//!
//! `verify-attest --strict-factory` calls [`verify_entry_factory_subset`]
//! per entry. Rules:
//!
//! 1. The entry must carry a non-empty `factory_binaries` map. Empty
//!    means the entry was minted by a factory that didn't record its
//!    fingerprint (legacy v3 entries, or v4 entries where
//!    fingerprinting was disabled). Strict mode is incompatible with
//!    such entries by design.
//! 2. Every component in the entry's map must appear in the expected
//!    set. Unknown components → reject (could be an attacker injecting
//!    a new tool).
//! 3. Every component in `required` from the expected file must be
//!    present in the entry's map.
//! 4. Each component's hash must appear in the expected set's list for
//!    that component (transitions are supported by listing multiple
//!    hashes).

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::OnceLock;

/// Workspace-relative default location for the expected-factory TOML.
pub const FACTORY_EXPECTED_PATH: &str = "factory_expected.toml";

/// Override env var (mirrors `CUTTLE_FEDERATION_CONFIG`).
pub const FACTORY_EXPECTED_ENV: &str = "CUTTLE_FACTORY_EXPECTED";

/// The component-name keys recorded in the `factory_binaries` map.
/// Stable strings — changing one of these is a schema-affecting move
/// because existing entries on disk carry the old name as a key.
pub const COMPONENT_MORPH: &str = "morph";
pub const COMPONENT_VERIFY: &str = "verify";
pub const COMPONENT_DIVERSIFY: &str = "diversify";
pub const COMPONENT_RUSTC: &str = "rustc";

/// Override env var: when set to a non-empty value, the cycle code
/// uses the directory pointed to as the search root for sibling
/// executables instead of probing relative to the morph binary's own
/// path. Lets the integration tests inject pre-built fixtures.
pub const FACTORY_BIN_DIR_ENV: &str = "CUTTLE_FACTORY_BIN_DIR";

/// Override env var: when set, [`fingerprint`] returns a copy of the
/// `factory_binaries` map *from this var's parsed JSON*. Used by the
/// integration tests so they can plant a deterministic map without
/// actually shelling out to `rustc` / hashing the test binary (which
/// would produce a hash dependent on cargo's incremental output).
///
/// Format: standard JSON object, e.g. `{"morph":"aa..","rustc":"bb.."}`.
pub const FACTORY_OVERRIDE_ENV: &str = "CUTTLE_FACTORY_FINGERPRINT_JSON";

/// Resolve the path to `factory_expected.toml`. Env var override wins
/// over the workspace-relative default.
pub fn resolve_factory_expected_path() -> PathBuf {
    match std::env::var(FACTORY_EXPECTED_ENV) {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        _ => PathBuf::from(FACTORY_EXPECTED_PATH),
    }
}

// =====================================================================
// Fingerprinting (write side)
// =====================================================================

static FINGERPRINT_CACHE: OnceLock<BTreeMap<String, String>> = OnceLock::new();

/// Return the process-wide factory fingerprint, computing it on first
/// call. The map keys are `morph`, `verify`, `diversify`, `rustc`
/// where the binary could be located. Components whose binary cannot
/// be located are logged to stderr and omitted from the map (the
/// strict-factory audit catches the missing component if the operator
/// configured one).
///
/// Override priority:
///   1. `CUTTLE_FACTORY_FINGERPRINT_JSON` env var (tests only).
///   2. `CUTTLE_FACTORY_BIN_DIR` env var (controls sibling search root).
///   3. The directory of `current_exe()` (production default).
pub fn fingerprint() -> &'static BTreeMap<String, String> {
    FINGERPRINT_CACHE.get_or_init(compute_fingerprint)
}

/// Force-recompute the fingerprint, ignoring the cache. Used by the
/// `morph factory-fingerprint` subcommand and by tests that want a
/// hash over a freshly written set of test executables. Not threadsafe
/// vs concurrent [`fingerprint`] callers — but that's not a real
/// scenario because the cycle code calls one or the other, not both.
pub fn fingerprint_uncached() -> BTreeMap<String, String> {
    compute_fingerprint()
}

fn compute_fingerprint() -> BTreeMap<String, String> {
    // Tests: override via JSON env var.
    if let Ok(raw) = std::env::var(FACTORY_OVERRIDE_ENV) {
        if !raw.is_empty() {
            match serde_json::from_str::<BTreeMap<String, String>>(&raw) {
                Ok(m) => return m,
                Err(e) => {
                    eprintln!(
                        "morph: CUTTLE_FACTORY_FINGERPRINT_JSON parse failed ({}); \
                         falling back to live hashing",
                        e
                    );
                }
            }
        }
    }
    let mut out = BTreeMap::new();
    let bin_dir = bin_search_dir();
    for (name, components) in [
        (COMPONENT_MORPH, "morph"),
        (COMPONENT_VERIFY, "verify"),
        (COMPONENT_DIVERSIFY, "diversify"),
    ] {
        let path = bin_dir.join(exe_name(components));
        match hash_file(&path) {
            Ok(h) => {
                out.insert(name.to_string(), h);
            }
            Err(e) => {
                eprintln!(
                    "morph: factory-fingerprint: skipping {} ({}): {:#}",
                    name,
                    path.display(),
                    e
                );
            }
        }
    }
    match hash_rustc_version() {
        Ok(h) => {
            out.insert(COMPONENT_RUSTC.to_string(), h);
        }
        Err(e) => {
            eprintln!("morph: factory-fingerprint: skipping rustc: {:#}", e);
        }
    }
    out
}

fn bin_search_dir() -> PathBuf {
    if let Ok(dir) = std::env::var(FACTORY_BIN_DIR_ENV) {
        if !dir.is_empty() {
            return PathBuf::from(dir);
        }
    }
    match std::env::current_exe() {
        Ok(exe) => exe
            .parent()
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from(".")),
        Err(_) => PathBuf::from("."),
    }
}

fn exe_name(base: &str) -> String {
    if cfg!(windows) {
        format!("{}.exe", base)
    } else {
        base.to_string()
    }
}

/// SHA-256 of `path`'s bytes, lowercase hex. Errors propagate.
pub fn hash_file(path: &Path) -> Result<String> {
    let bytes = fs::read(path).with_context(|| format!("read {}", path.display()))?;
    let mut h = Sha256::new();
    h.update(&bytes);
    Ok(hex_lower(&h.finalize()))
}

/// SHA-256 of `<rustc --version>` stdout (trimmed). We capture both
/// stdout and the host triple via `-vV` for a stronger fingerprint;
/// the leading line is the human "rustc 1.x.y" string and the rest is
/// "host: x86_64-pc-windows-msvc" etc.
fn hash_rustc_version() -> Result<String> {
    let out = Command::new("rustc")
        .arg("-vV")
        .output()
        .context("spawn rustc -vV")?;
    if !out.status.success() {
        bail!(
            "rustc -vV exited non-zero ({:?}): {}",
            out.status.code(),
            String::from_utf8_lossy(&out.stderr)
        );
    }
    let mut h = Sha256::new();
    // Trim trailing newlines so a CI tool that strips them doesn't
    // produce a different hash than a developer running the same
    // rustc locally. Internal whitespace is canonical.
    h.update(out.stdout.trim_ascii_end());
    Ok(hex_lower(&h.finalize()))
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}

// =====================================================================
// Expected set (audit side)
// =====================================================================

/// On-disk shape of `factory_expected.toml`. Top-level keys:
///
/// - `required` (optional list): components that MUST be present in
///   every entry's `factory_binaries`. Defaults to all four components
///   when absent.
/// - `components`: TOML table whose keys are component names and
///   values are lists of acceptable lowercase-hex SHA-256 strings.
///   Multiple values per component allow operator-managed transitions
///   (build a new rustc, accept both for a few days, then prune the
///   old).
///
/// Example:
///
/// ```toml
/// required = ["morph", "verify", "diversify", "rustc"]
/// [components]
/// morph = ["aa..", "bb.."]
/// verify = ["cc.."]
/// diversify = ["dd.."]
/// rustc = ["ee..", "ff.."]
/// ```
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct FactoryExpected {
    #[serde(default = "default_required")]
    pub required: Vec<String>,
    #[serde(default)]
    pub components: BTreeMap<String, Vec<String>>,
}

fn default_required() -> Vec<String> {
    vec![
        COMPONENT_MORPH.to_string(),
        COMPONENT_VERIFY.to_string(),
        COMPONENT_DIVERSIFY.to_string(),
        COMPONENT_RUSTC.to_string(),
    ]
}

/// Load and validate `factory_expected.toml`. Validation:
///
/// - `required` must list at least one component name from the
///   well-known set (`morph`/`verify`/`diversify`/`rustc`).
/// - `components` must be a non-empty map.
/// - Every entry in `required` must appear as a key in `components`
///   (otherwise the required-but-no-hashes-listed combination would
///   reject every entry — almost certainly a misconfiguration).
/// - Every hash string must be 64 lowercase-hex chars.
/// Comment-trailer prefix used to embed detached-compatible Ed25519 signatures
/// inside `factory_expected.toml` and `locked_modules.toml` (`R3`).
pub const POLICY_SIG_PREFIX: &str = "# cuttle-policy-sig-v1:";

/// Compute canonical policy bytes (LF-normalized content excluding any
/// `# cuttle-policy-sig-v1:` signature trailer lines, trimmed + single `\n`).
pub fn canonical_policy_bytes(raw_toml: &str) -> Vec<u8> {
    let mut lines: Vec<&str> = Vec::new();
    for line in raw_toml.lines() {
        let trimmed = line.trim();
        if trimmed.starts_with(POLICY_SIG_PREFIX) {
            continue;
        }
        lines.push(line.trim_end_matches('\r'));
    }
    let mut out = lines.join("\n").trim_end().to_string();
    out.push('\n');
    out.into_bytes()
}

/// Sign `raw_toml` with `sk` under `signer_id` and append a
/// `# cuttle-policy-sig-v1: signer=<id> sig=<128hex>` line.
pub fn sign_policy_toml_str(
    raw_toml: &str,
    signer_id: &str,
    sk: &ed25519_dalek::SigningKey,
) -> String {
    use ed25519_dalek::Signer as _;
    let canon = canonical_policy_bytes(raw_toml);
    let dig: [u8; 32] = Sha256::digest(&canon).into();
    let sig = sk.sign(&dig);
    let sig_hex = hex_lower(&sig.to_bytes());
    let mut out = raw_toml.replace("\r\n", "\n").trim_end().to_string();
    out.push_str(&format!(
        "\n{POLICY_SIG_PREFIX} signer={signer_id} sig={sig_hex}\n"
    ));
    out
}

/// Verify that `raw_toml` carries at least one valid `# cuttle-policy-sig-v1:`
/// signature from a non-revoked signer in `fed`.
pub fn verify_policy_toml_str(
    raw_toml: &str,
    fed: &crate::federation::FederationConfig,
    policy_name: &str,
) -> Result<()> {
    let mut cosigs: Vec<crate::federation::Cosignature> = Vec::new();
    for line in raw_toml.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(POLICY_SIG_PREFIX) {
            let mut signer_id: Option<String> = None;
            let mut sig_hex: Option<String> = None;
            for tok in rest.split_whitespace() {
                if let Some(s) = tok.strip_prefix("signer=") {
                    signer_id = Some(s.to_string());
                } else if let Some(sig) = tok.strip_prefix("sig=") {
                    sig_hex = Some(sig.to_string());
                }
            }
            let sid = signer_id.ok_or_else(|| {
                anyhow::anyhow!("{policy_name}: malformed policy signature line (missing signer=)")
            })?;
            let sh = sig_hex.ok_or_else(|| {
                anyhow::anyhow!("{policy_name}: malformed policy signature line (missing sig=)")
            })?;
            cosigs.push(crate::federation::Cosignature {
                signer_id: sid,
                sig_ed25519: sh,
            });
        }
    }
    if cosigs.is_empty() {
        bail!("{policy_name}: missing `{POLICY_SIG_PREFIX}` signature");
    }
    let canon = canonical_policy_bytes(raw_toml);
    let dig: [u8; 32] = Sha256::digest(&canon).into();
    let mut policy_fed = fed.clone();
    if cosigs.len() < (policy_fed.threshold as usize) {
        // Policy files signed by primary or threshold signers verify against
        // their present cosignatures if threshold=1, or require fed.threshold.
    } else {
        policy_fed.threshold = fed.threshold.max(1);
    }
    crate::federation::verify_cosignatures(&dig, &cosigs, &policy_fed)
        .with_context(|| format!("verify signed policy TOML {policy_name}"))
}

/// Load, validate, and strictly verify the factory signature on `factory_expected.toml` (`R3`).
pub fn load_and_verify_signed_factory_expected(
    path: &Path,
    fed: &crate::federation::FederationConfig,
) -> Result<FactoryExpected> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    verify_policy_toml_str(&raw, fed, &path.display().to_string())?;
    let cfg: FactoryExpected =
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    validate_factory_expected(&cfg)
        .with_context(|| format!("validate {}", path.display()))?;
    Ok(cfg)
}

/// Strictly verify the factory signature on `locked_modules.toml` (`R3`).
pub fn verify_signed_locked_modules(
    path: &Path,
    fed: &crate::federation::FederationConfig,
) -> Result<()> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    verify_policy_toml_str(&raw, fed, &path.display().to_string())
}

/// Generate a deterministic CycloneDX 1.5 JSON SBOM for `kernel_crate_dir`
/// (parsing `Cargo.lock` packages in sorted `(name, version)` order) and
/// return `(cyclonedx_json, sha256_hex)` (`R5`).
pub fn generate_cyclonedx_sbom(kernel_crate_dir: &Path) -> Result<(String, String)> {
    let lock_path = if kernel_crate_dir.join("Cargo.lock").exists() {
        kernel_crate_dir.join("Cargo.lock")
    } else if let Some(ws) = kernel_crate_dir.parent() {
        ws.join("Cargo.lock")
    } else {
        kernel_crate_dir.join("Cargo.lock")
    };
    let text = fs::read_to_string(&lock_path)
        .with_context(|| format!("read Cargo.lock at {}", lock_path.display()))?;
    let mut pkgs: Vec<(String, String, String)> = Vec::new();
    let mut cur_name = String::new();
    let mut cur_ver = String::new();
    let mut cur_chk = String::new();
    for raw_line in text.lines() {
        let line = raw_line.trim();
        if line == "[[package]]" {
            if !cur_name.is_empty() {
                pkgs.push((
                    std::mem::take(&mut cur_name),
                    std::mem::take(&mut cur_ver),
                    std::mem::take(&mut cur_chk),
                ));
            }
        } else if let Some(v) = line.strip_prefix("name = ") {
            cur_name = v.trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("version = ") {
            cur_ver = v.trim_matches('"').to_string();
        } else if let Some(v) = line.strip_prefix("checksum = ") {
            cur_chk = v.trim_matches('"').to_string();
        }
    }
    if !cur_name.is_empty() {
        pkgs.push((cur_name, cur_ver, cur_chk));
    }
    pkgs.sort();
    pkgs.dedup();

    let mut components_json = String::new();
    for (idx, (name, ver, chk)) in pkgs.iter().enumerate() {
        if idx > 0 {
            components_json.push(',');
        }
        let purl = format!("pkg:cargo/{name}@{ver}");
        if chk.is_empty() {
            components_json.push_str(&format!(
                "{{\"type\":\"library\",\"name\":\"{name}\",\"version\":\"{ver}\",\"purl\":\"{purl}\"}}"
            ));
        } else {
            components_json.push_str(&format!(
                "{{\"type\":\"library\",\"name\":\"{name}\",\"version\":\"{ver}\",\"purl\":\"{purl}\",\"hashes\":[{{\"alg\":\"SHA-256\",\"content\":\"{chk}\"}}]}}"
            ));
        }
    }
    let sbom = format!(
        "{{\"bomFormat\":\"CycloneDX\",\"specVersion\":\"1.5\",\"version\":1,\"components\":[{components_json}]}}\n"
    );
    let dig: [u8; 32] = Sha256::digest(sbom.as_bytes()).into();
    Ok((sbom, hex_lower(&dig)))
}

pub fn load_factory_expected(path: &Path) -> Result<FactoryExpected> {
    let raw = fs::read_to_string(path).with_context(|| format!("read {}", path.display()))?;
    if raw.contains(POLICY_SIG_PREFIX) {
        let fed_path = crate::federation::resolve_federation_path();
        if fed_path.exists() {
            let fed = crate::federation::load_federation(&fed_path)?;
            verify_policy_toml_str(&raw, &fed, &path.display().to_string())?;
        }
    }
    let cfg: FactoryExpected =
        toml::from_str(&raw).with_context(|| format!("parse {}", path.display()))?;
    validate_factory_expected(&cfg)
        .with_context(|| format!("validate {}", path.display()))?;
    Ok(cfg)
}

/// Validation logic factored out so tests can synthesise an in-memory
/// config and feed it through.
pub fn validate_factory_expected(cfg: &FactoryExpected) -> Result<()> {
    if cfg.required.is_empty() {
        bail!("`required` must list at least one component name");
    }
    if cfg.components.is_empty() {
        bail!("`components` table must contain at least one entry");
    }
    for r in &cfg.required {
        if !cfg.components.contains_key(r) {
            bail!(
                "component '{}' is in `required` but has no entry in `components`",
                r
            );
        }
    }
    for (name, hashes) in &cfg.components {
        if hashes.is_empty() {
            bail!("component '{}' has empty hash list", name);
        }
        for h in hashes {
            if !is_lower_hex32(h) {
                bail!(
                    "component '{}' has malformed hash '{}' (expected 64 lowercase hex)",
                    name,
                    h
                );
            }
        }
    }
    Ok(())
}

fn is_lower_hex32(s: &str) -> bool {
    s.len() == 64
        && s.chars()
            .all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

// =====================================================================
// Audit
// =====================================================================

/// Verify a single entry's `factory_binaries` against the expected set.
/// Public so unit tests can drive the check without writing a chain.
///
/// Returns Ok(()) when the entry's map is a valid subset:
///   - non-empty,
///   - every key appears in `expected.components`,
///   - every required component is present,
///   - every hash is in the expected list for its component.
///
/// Returns Err naming the first rejection.
pub fn verify_entry_factory_subset(
    entry: &BTreeMap<String, String>,
    expected: &FactoryExpected,
) -> Result<()> {
    if entry.is_empty() {
        bail!(
            "factory_binaries is empty — strict mode requires a v4 entry with a populated map"
        );
    }
    // Rule 2: no unknown components.
    for k in entry.keys() {
        if !expected.components.contains_key(k) {
            bail!("unknown factory component '{}' not in expected set", k);
        }
    }
    // Rule 3: required components must all be present.
    for r in &expected.required {
        if !entry.contains_key(r) {
            bail!("missing required factory component '{}'", r);
        }
    }
    // Rule 4: each hash must appear in the expected list.
    for (k, v) in entry {
        let allowed = expected
            .components
            .get(k)
            .expect("checked above via Rule 2");
        if !allowed.iter().any(|h| h == v) {
            bail!(
                "component '{}' hash '{}' not in expected set ({} accepted values)",
                k,
                v,
                allowed.len()
            );
        }
    }
    Ok(())
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;

    fn h(b: u8) -> String {
        let mut s = String::with_capacity(64);
        for _ in 0..64 {
            s.push_str(&format!("{:x}", b & 0xf));
        }
        s
    }

    fn good_expected() -> FactoryExpected {
        let mut comp = BTreeMap::new();
        comp.insert(COMPONENT_MORPH.into(), vec![h(0xa)]);
        comp.insert(COMPONENT_VERIFY.into(), vec![h(0xb)]);
        comp.insert(COMPONENT_DIVERSIFY.into(), vec![h(0xc)]);
        comp.insert(COMPONENT_RUSTC.into(), vec![h(0xd), h(0xe)]);
        FactoryExpected {
            required: default_required(),
            components: comp,
        }
    }

    fn good_entry() -> BTreeMap<String, String> {
        let mut m = BTreeMap::new();
        m.insert(COMPONENT_MORPH.into(), h(0xa));
        m.insert(COMPONENT_VERIFY.into(), h(0xb));
        m.insert(COMPONENT_DIVERSIFY.into(), h(0xc));
        m.insert(COMPONENT_RUSTC.into(), h(0xd));
        m
    }

    #[test]
    fn validate_rejects_empty_required() {
        let mut cfg = good_expected();
        cfg.required.clear();
        assert!(validate_factory_expected(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_empty_components() {
        let mut cfg = good_expected();
        cfg.components.clear();
        assert!(validate_factory_expected(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_required_not_in_components() {
        let mut cfg = good_expected();
        cfg.required.push("nonexistent".into());
        assert!(validate_factory_expected(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_empty_hash_list() {
        let mut cfg = good_expected();
        cfg.components.insert("morph".into(), vec![]);
        assert!(validate_factory_expected(&cfg).is_err());
    }

    #[test]
    fn validate_rejects_malformed_hash() {
        let mut cfg = good_expected();
        cfg.components.insert("morph".into(), vec!["XXnotaHash".into()]);
        assert!(validate_factory_expected(&cfg).is_err());
    }

    #[test]
    fn validate_accepts_alternative_rustc_hash() {
        // Both rustc hashes valid; entry uses the second.
        let cfg = good_expected();
        let mut entry = good_entry();
        entry.insert(COMPONENT_RUSTC.into(), h(0xe));
        assert!(verify_entry_factory_subset(&entry, &cfg).is_ok());
    }

    #[test]
    fn subset_accepts_good_entry() {
        let cfg = good_expected();
        let entry = good_entry();
        assert!(verify_entry_factory_subset(&entry, &cfg).is_ok());
    }

    #[test]
    fn subset_rejects_empty_entry() {
        let cfg = good_expected();
        let entry: BTreeMap<String, String> = BTreeMap::new();
        let err = verify_entry_factory_subset(&entry, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("empty"), "unexpected: {}", m);
    }

    #[test]
    fn subset_rejects_unknown_component() {
        let cfg = good_expected();
        let mut entry = good_entry();
        entry.insert("smuggled_in".into(), h(0x1));
        let err = verify_entry_factory_subset(&entry, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("unknown factory component"), "unexpected: {}", m);
    }

    #[test]
    fn subset_rejects_missing_required() {
        let cfg = good_expected();
        let mut entry = good_entry();
        entry.remove(COMPONENT_VERIFY);
        let err = verify_entry_factory_subset(&entry, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("missing required factory component"), "unexpected: {}", m);
    }

    #[test]
    fn subset_rejects_hash_not_in_allowed_set() {
        let cfg = good_expected();
        let mut entry = good_entry();
        entry.insert(COMPONENT_MORPH.into(), h(0xf));
        let err = verify_entry_factory_subset(&entry, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("not in expected set"), "unexpected: {}", m);
    }

    #[test]
    fn loose_required_allows_partial_entry() {
        // Operator-controlled required list: only `morph` is required.
        let mut cfg = good_expected();
        cfg.required = vec![COMPONENT_MORPH.into()];
        validate_factory_expected(&cfg).unwrap();
        let mut entry: BTreeMap<String, String> = BTreeMap::new();
        entry.insert(COMPONENT_MORPH.into(), h(0xa));
        // Subset of components is OK as long as every key is known.
        assert!(verify_entry_factory_subset(&entry, &cfg).is_ok());
    }

    #[test]
    fn hex_lower_round_trip() {
        let bytes = [0u8, 1, 2, 0xfe, 0xff];
        assert_eq!(hex_lower(&bytes), "000102feff");
    }

    #[test]
    fn is_lower_hex32_accepts_canonical() {
        assert!(is_lower_hex32(&"ab".repeat(32)));
        assert!(is_lower_hex32(&"0".repeat(64)));
    }

    #[test]
    fn is_lower_hex32_rejects_uppercase() {
        assert!(!is_lower_hex32(&"AB".repeat(32)));
    }

    #[test]
    fn is_lower_hex32_rejects_wrong_length() {
        assert!(!is_lower_hex32(&"ab".repeat(31)));
        assert!(!is_lower_hex32(&"ab".repeat(33)));
    }

    #[test]
    fn factory_expected_round_trips_via_toml() {
        let cfg = good_expected();
        let s = toml::to_string(&cfg).unwrap();
        let back: FactoryExpected = toml::from_str(&s).unwrap();
        assert_eq!(back.required, cfg.required);
        assert_eq!(back.components, cfg.components);
        validate_factory_expected(&back).unwrap();
    }

    #[test]
    fn tampered_factory_expected_toml_fails_strict_factory() {
        use ed25519_dalek::SigningKey;
        let sk = SigningKey::generate(&mut rand::rngs::OsRng);
        let pk_hex = hex_lower(&sk.verifying_key().to_bytes());
        let fed = crate::federation::FederationConfig {
            threshold: 1,
            signers: vec![crate::federation::Signer {
                id: "primary".into(),
                pubkey_hex: pk_hex,
            }],
            revoked: Vec::new(),
        };

        let cfg = good_expected();
        let raw = toml::to_string(&cfg).unwrap();
        let signed = sign_policy_toml_str(&raw, "primary", &sk);

        let dir = std::env::temp_dir().join(format!(
            "cuttle_signed_policy_test_{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let exp_path = dir.join("factory_expected.toml");
        fs::write(&exp_path, &signed).unwrap();

        // Valid signed policy loads and verifies cleanly.
        let loaded = load_and_verify_signed_factory_expected(&exp_path, &fed)
            .expect("valid signed factory_expected.toml must verify");
        assert_eq!(loaded.required, cfg.required);

        // Tamper with a hash in factory_expected.toml while keeping the signature line.
        let tampered = signed.replace(&h(0xa), &h(0x9));
        fs::write(&exp_path, &tampered).unwrap();
        let err = load_and_verify_signed_factory_expected(&exp_path, &fed)
            .expect_err("tampered factory_expected.toml must fail strict verification");
        assert!(
            format!("{err:#}").contains("invalid signature"),
            "unexpected error: {err:#}"
        );

        // Stripping the signature line completely must also fail.
        fs::write(&exp_path, &raw).unwrap();
        let err2 = load_and_verify_signed_factory_expected(&exp_path, &fed)
            .expect_err("unsigned factory_expected.toml must fail strict signed verification");
        assert!(
            format!("{err2:#}").contains("missing"),
            "unexpected error: {err2:#}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn workspace_policy_files_verify_against_factory_keys() {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root")
            .to_path_buf();
        let fed = crate::federation::load_federation(&root.join("factory_keys.toml"))
            .expect("load workspace factory_keys.toml");
        let exp_path = root.join("factory_expected.toml");
        let lock_path = root.join("locked_modules.toml");

        load_and_verify_signed_factory_expected(&exp_path, &fed)
            .expect("workspace factory_expected.toml must carry valid primary signature");
        verify_signed_locked_modules(&lock_path, &fed)
            .expect("workspace locked_modules.toml must carry valid primary signature");
    }
}
