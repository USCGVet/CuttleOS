//! Federated cross-factory signature requirement (M-of-N).
//!
//! Attestation entries are valid for deployment only when they carry at
//! least `threshold` signatures from distinct factory public keys listed
//! in `factory_keys.toml`. Bootstrap configuration ships with M=2, N=3:
//! one "real" `primary` slot (currently filled by a deterministic
//! test-only seed, see `tests/fixtures/federation/`) plus two placeholder
//! slots used to exercise the threshold logic in tests.
//!
//! The TOML schema:
//!
//! ```toml
//! threshold = 2
//! [[signers]]
//! id = "primary"
//! pubkey_hex = "<64-hex>"
//! [[signers]]
//! id = "placeholder-a"
//! pubkey_hex = "<64-hex>"
//! [[signers]]
//! id = "placeholder-b"
//! pubkey_hex = "<64-hex>"
//! ```
//!
//! Cosignatures attached to an attestation entry sign the same 32-byte
//! `candidate_sha256` message (the deployed code hash). The federation
//! verifier dedupes by `signer_id`: a duplicate cosignature counts once.

use anyhow::{bail, Context, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

/// Workspace-relative default location for the federation config.
pub const FEDERATION_CONFIG_PATH: &str = "factory_keys.toml";

/// Tests and operators can override the federation config path via this
/// env var. Mirrors `ATTEST_DIR_ENV` in `attest.rs`.
pub const FEDERATION_CONFIG_ENV: &str = "CUTTLE_FEDERATION_CONFIG";

/// Resolve the federation config path. `CUTTLE_FEDERATION_CONFIG`
/// overrides; otherwise we use the workspace-relative
/// `factory_keys.toml`.
pub fn resolve_federation_path() -> PathBuf {
    match std::env::var(FEDERATION_CONFIG_ENV) {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        _ => PathBuf::from(FEDERATION_CONFIG_PATH),
    }
}

/// Top-level `factory_keys.toml` representation.
#[derive(Debug, Clone, Deserialize)]
pub struct FederationConfig {
    pub threshold: u32,
    pub signers: Vec<Signer>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Signer {
    pub id: String,
    pub pubkey_hex: String,
}

/// A single cosignature attached to an attestation entry. `sig_ed25519`
/// is 128 lowercase hex characters (the raw 64-byte ed25519 signature).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Cosignature {
    pub signer_id: String,
    pub sig_ed25519: String,
}

/// Load the federation config from `path`. Validates the schema:
///
/// - `threshold >= 1`
/// - `threshold as usize <= signers.len()`
/// - signer `id` is unique
/// - each `pubkey_hex` is 64 lowercase hex chars (parseable as 32 bytes)
pub fn load_federation(path: &Path) -> Result<FederationConfig> {
    let raw = fs::read_to_string(path)
        .with_context(|| format!("read federation config {}", path.display()))?;
    let cfg: FederationConfig = toml::from_str(&raw)
        .with_context(|| format!("parse federation config {}", path.display()))?;

    if cfg.threshold < 1 {
        bail!("federation config: threshold must be >= 1, got {}", cfg.threshold);
    }
    if (cfg.threshold as usize) > cfg.signers.len() {
        bail!(
            "federation config: threshold ({}) exceeds signer count ({})",
            cfg.threshold,
            cfg.signers.len()
        );
    }
    let mut seen = HashSet::new();
    for s in &cfg.signers {
        if !seen.insert(s.id.clone()) {
            bail!("federation config: duplicate signer id '{}'", s.id);
        }
        if s.pubkey_hex.len() != 64 {
            bail!(
                "federation config: signer '{}' pubkey_hex must be 64 chars, got {}",
                s.id,
                s.pubkey_hex.len()
            );
        }
        if !s.pubkey_hex.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()) {
            bail!(
                "federation config: signer '{}' pubkey_hex must be lowercase hex",
                s.id
            );
        }
    }
    Ok(cfg)
}

fn parse_pubkey(hex_str: &str) -> Result<VerifyingKey> {
    if hex_str.len() != 64 {
        bail!("pubkey hex must be 64 chars, got {}", hex_str.len());
    }
    let mut bytes = [0u8; 32];
    for i in 0..32 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid hex byte at {}", i))?;
    }
    VerifyingKey::from_bytes(&bytes).context("invalid ed25519 verifying key bytes")
}

fn parse_sig(hex_str: &str) -> Result<Signature> {
    if hex_str.len() != 128 {
        bail!("signature hex must be 128 chars, got {}", hex_str.len());
    }
    let mut bytes = [0u8; 64];
    for i in 0..64 {
        bytes[i] = u8::from_str_radix(&hex_str[i * 2..i * 2 + 2], 16)
            .with_context(|| format!("invalid signature hex byte at {}", i))?;
    }
    Ok(Signature::from_bytes(&bytes))
}

/// Verify the supplied cosignatures against `message` using the
/// federation pubkeys. Each unique valid signer is counted once. Returns
/// Ok iff the distinct-valid-signer count is at least `fed.threshold`.
///
/// Errors are precise:
/// - `unknown signer 'X'` if the cosig's `signer_id` is not in `fed.signers`
/// - `invalid signature for signer 'X'` if the ed25519 verify fails
/// - `threshold not met: have K want M` if the cosig set is too small
pub fn verify_cosignatures(
    message: &[u8; 32],
    cosigs: &[Cosignature],
    fed: &FederationConfig,
) -> Result<()> {
    let mut counted: HashSet<String> = HashSet::new();
    for c in cosigs {
        let signer = fed
            .signers
            .iter()
            .find(|s| s.id == c.signer_id)
            .ok_or_else(|| anyhow::anyhow!("unknown signer '{}'", c.signer_id))?;
        let pk = parse_pubkey(&signer.pubkey_hex)
            .with_context(|| format!("signer '{}' has malformed pubkey_hex", signer.id))?;
        let sig = parse_sig(&c.sig_ed25519)
            .with_context(|| format!("signer '{}' cosignature has malformed sig hex", signer.id))?;
        pk.verify(message, &sig)
            .map_err(|_| anyhow::anyhow!("invalid signature for signer '{}'", signer.id))?;
        // Each distinct id counts once.
        counted.insert(c.signer_id.clone());
    }
    let have = counted.len() as u32;
    if have < fed.threshold {
        bail!(
            "threshold not met: have {} of {} required ({}-of-{})",
            have,
            fed.threshold,
            fed.threshold,
            fed.signers.len()
        );
    }
    Ok(())
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer as _, SigningKey};

    fn pk_hex(sk: &SigningKey) -> String {
        let pk = sk.verifying_key();
        let mut s = String::with_capacity(64);
        for b in pk.to_bytes() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn sig_hex(sk: &SigningKey, msg: &[u8; 32]) -> String {
        let sig = sk.sign(msg);
        let mut s = String::with_capacity(128);
        for b in sig.to_bytes() {
            s.push_str(&format!("{:02x}", b));
        }
        s
    }

    fn write_toml(dir: &Path, contents: &str) -> PathBuf {
        let p = dir.join("factory_keys.toml");
        fs::write(&p, contents).unwrap();
        p
    }

    fn tmpdir(label: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static C: AtomicU64 = AtomicU64::new(0);
        let n = C.fetch_add(1, Ordering::Relaxed);
        let pid = std::process::id();
        let d = std::env::temp_dir().join(format!("cuttle_fed_test_{}_{}_{}", label, pid, n));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn loads_good_toml() {
        let d = tmpdir("good");
        let sk0 = SigningKey::from_bytes(&[0u8; 32]);
        let sk1 = SigningKey::from_bytes(&[1u8; 32]);
        let p = write_toml(
            &d,
            &format!(
                "threshold = 1\n\
                 [[signers]]\nid = \"a\"\npubkey_hex = \"{}\"\n\
                 [[signers]]\nid = \"b\"\npubkey_hex = \"{}\"\n",
                pk_hex(&sk0),
                pk_hex(&sk1)
            ),
        );
        let cfg = load_federation(&p).unwrap();
        assert_eq!(cfg.threshold, 1);
        assert_eq!(cfg.signers.len(), 2);
    }

    #[test]
    fn rejects_threshold_above_signer_count() {
        let d = tmpdir("hi_thr");
        let sk0 = SigningKey::from_bytes(&[0u8; 32]);
        let p = write_toml(
            &d,
            &format!(
                "threshold = 5\n[[signers]]\nid = \"only\"\npubkey_hex = \"{}\"\n",
                pk_hex(&sk0)
            ),
        );
        let err = load_federation(&p).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("threshold"), "got: {}", msg);
    }

    #[test]
    fn rejects_duplicate_signer_id() {
        let d = tmpdir("dup");
        let sk0 = SigningKey::from_bytes(&[0u8; 32]);
        let sk1 = SigningKey::from_bytes(&[1u8; 32]);
        let p = write_toml(
            &d,
            &format!(
                "threshold = 1\n\
                 [[signers]]\nid = \"x\"\npubkey_hex = \"{}\"\n\
                 [[signers]]\nid = \"x\"\npubkey_hex = \"{}\"\n",
                pk_hex(&sk0),
                pk_hex(&sk1)
            ),
        );
        let err = load_federation(&p).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("duplicate"), "got: {}", msg);
    }

    #[test]
    fn rejects_bad_pubkey_hex() {
        let d = tmpdir("badhex");
        let p = write_toml(
            &d,
            "threshold = 1\n[[signers]]\nid = \"x\"\npubkey_hex = \"notvalidhex\"\n",
        );
        let err = load_federation(&p).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("pubkey_hex"), "got: {}", msg);
    }

    #[test]
    fn verify_happy_path_threshold_2() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let cfg = FederationConfig {
            threshold: 2,
            signers: vec![
                Signer { id: "a".into(), pubkey_hex: pk_hex(&sk_a) },
                Signer { id: "b".into(), pubkey_hex: pk_hex(&sk_b) },
            ],
        };
        let msg = [9u8; 32];
        let cosigs = vec![
            Cosignature { signer_id: "a".into(), sig_ed25519: sig_hex(&sk_a, &msg) },
            Cosignature { signer_id: "b".into(), sig_ed25519: sig_hex(&sk_b, &msg) },
        ];
        verify_cosignatures(&msg, &cosigs, &cfg).unwrap();
    }

    #[test]
    fn verify_rejects_unknown_signer() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let cfg = FederationConfig {
            threshold: 1,
            signers: vec![Signer { id: "a".into(), pubkey_hex: pk_hex(&sk_a) }],
        };
        let msg = [9u8; 32];
        let cosigs = vec![Cosignature {
            signer_id: "rogue".into(),
            sig_ed25519: sig_hex(&sk_a, &msg),
        }];
        let err = verify_cosignatures(&msg, &cosigs, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("unknown signer"), "got: {}", m);
    }

    #[test]
    fn verify_rejects_bad_signature() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let cfg = FederationConfig {
            threshold: 1,
            signers: vec![Signer { id: "a".into(), pubkey_hex: pk_hex(&sk_a) }],
        };
        let msg = [9u8; 32];
        // Sig produced by sk_b but claimed under id "a" — fails verify.
        let cosigs = vec![Cosignature {
            signer_id: "a".into(),
            sig_ed25519: sig_hex(&sk_b, &msg),
        }];
        let err = verify_cosignatures(&msg, &cosigs, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("invalid signature"), "got: {}", m);
    }

    #[test]
    fn verify_dedupes_repeat_signer() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let cfg = FederationConfig {
            threshold: 2,
            signers: vec![
                Signer { id: "a".into(), pubkey_hex: pk_hex(&sk_a) },
                Signer { id: "b".into(), pubkey_hex: pk_hex(&sk_b) },
            ],
        };
        let msg = [9u8; 32];
        // Two valid cosigs from 'a' but none from 'b' — distinct count = 1.
        let cosigs = vec![
            Cosignature { signer_id: "a".into(), sig_ed25519: sig_hex(&sk_a, &msg) },
            Cosignature { signer_id: "a".into(), sig_ed25519: sig_hex(&sk_a, &msg) },
        ];
        let err = verify_cosignatures(&msg, &cosigs, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("threshold not met"), "got: {}", m);
    }

    #[test]
    fn verify_rejects_below_threshold() {
        let sk_a = SigningKey::from_bytes(&[1u8; 32]);
        let sk_b = SigningKey::from_bytes(&[2u8; 32]);
        let cfg = FederationConfig {
            threshold: 2,
            signers: vec![
                Signer { id: "a".into(), pubkey_hex: pk_hex(&sk_a) },
                Signer { id: "b".into(), pubkey_hex: pk_hex(&sk_b) },
            ],
        };
        let msg = [9u8; 32];
        let cosigs = vec![Cosignature {
            signer_id: "a".into(),
            sig_ed25519: sig_hex(&sk_a, &msg),
        }];
        let err = verify_cosignatures(&msg, &cosigs, &cfg).unwrap_err();
        let m = format!("{:#}", err);
        assert!(m.contains("threshold not met"), "got: {}", m);
    }
}
