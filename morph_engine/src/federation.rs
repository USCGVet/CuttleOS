//! Federated cross-factory signature requirement (M-of-N).
//!
//! Attestation entries are valid for federated deployment when they carry at
//! least `threshold` signatures from distinct factory public keys listed in
//! `factory_keys.toml`. The repository configuration ships with only the
//! single `primary` signer (`threshold = 1`, corresponding to the operator's
//! `factory_signing_key.bin`); multi-signer M-of-N verification
//! (`verify-attest --require-threshold`) requires `threshold >= 2` once the
//! operator enrolls independent co-signer public keys. Deterministic test-only
//! seeds in `tests/fixtures/federation/` and published RFC 8032 example keys
//! are strictly rejected by verification (`KNOWN_FIXTURE_PUBKEYS`).
//!
//! The TOML schema:
//!
//! ```toml
//! threshold = 2
//! [[signers]]
//! id = "primary"
//! pubkey_hex = "<64-hex>"
//! [[signers]]
//! id = "cosigner-a"
//! pubkey_hex = "<64-hex>"
//! [[signers]]
//! id = "cosigner-b"
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

/// Known public keys derived from the committed test fixture seeds in
/// `tests/fixtures/federation/` (`[0u8; 32]`, `[1u8; 32]`, `[2u8; 32]`) as
/// well as all five published RFC 8032 §7.1 Ed25519 test vector keys whose
/// private keys are public. Any federation roster or primary key matching one
/// of these keys (or [`KNOWN_TEST_SEEDS`]) is rejected by [`load_federation`],
/// [`verify_cosignatures`], and [`reject_fixture_verifying_key`].
pub const KNOWN_FIXTURE_PUBKEYS: &[(&str, &str)] = &[
    (
        "primary.seed ([0u8; 32])",
        "3b6a27bcceb6a42d62a3a8d02a6f0d73653215771de243a63ac048a18b59da29",
    ),
    (
        "placeholder_a.seed ([1u8; 32])",
        "8a88e3dd7409f195fd52db2d3cba5d72ca6709bf1d94121bf3748801b40f6f5c",
    ),
    (
        "placeholder_b.seed ([2u8; 32])",
        "8139770ea87d175f56a35466c34c7ecccb8d8a91b4ee37a25df60f5b8fc9b394",
    ),
    (
        "RFC 8032 §7.1 TEST 1",
        "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
    ),
    (
        "RFC 8032 §7.1 TEST 2",
        "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
    ),
    (
        "RFC 8032 §7.1 TEST 3",
        "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
    ),
    (
        "RFC 8032 §7.1 TEST 1024",
        "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e",
    ),
    (
        "RFC 8032 §7.1 TEST SHA(abc)",
        "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
    ),
];

/// Deterministic single-byte-repeated test seeds previously used in repository
/// tests. Derived public keys are rejected in verification rosters and primary
/// key fallbacks alongside [`KNOWN_FIXTURE_PUBKEYS`].
pub const KNOWN_TEST_SEEDS: &[(&str, [u8; 32])] = &[
    ("test seed [0x10; 32]", [0x10u8; 32]),
    ("test seed [0x11; 32]", [0x11u8; 32]),
    ("test seed [0x12; 32]", [0x12u8; 32]),
    ("test seed [0x33; 32]", [0x33u8; 32]),
    ("test seed [0x37; 32]", [0x37u8; 32]),
    ("test seed [0x42; 32]", [0x42u8; 32]),
    ("test seed [0x55; 32]", [0x55u8; 32]),
    ("test seed [99u8; 32]", [99u8; 32]),
    ("test seed [0x77; 32]", [0x77u8; 32]),
    ("test seed [0x99; 32]", [0x99u8; 32]),
];

/// Reject a decoded [`VerifyingKey`] if its 32-byte representation matches any
/// entry in [`KNOWN_FIXTURE_PUBKEYS`] or [`KNOWN_TEST_SEEDS`].
pub fn reject_fixture_verifying_key(vk: &VerifyingKey, signer_desc: &str) -> Result<()> {
    let vk_bytes = vk.to_bytes();
    for (fixture_label, fixture_pk) in KNOWN_FIXTURE_PUBKEYS {
        if let Ok(fpk) = parse_pubkey(fixture_pk) {
            if fpk.to_bytes() == vk_bytes {
                bail!(
                    "federation config: signer '{}' uses known test fixture key {} ({}); \
                     committed fixture seeds are forbidden in verification rosters",
                    signer_desc,
                    fixture_pk,
                    fixture_label
                );
            }
        }
    }
    for (seed_label, seed_bytes) in KNOWN_TEST_SEEDS {
        let sk = ed25519_dalek::SigningKey::from_bytes(seed_bytes);
        if sk.verifying_key().to_bytes() == vk_bytes {
            let mut pk_hex = String::with_capacity(64);
            for b in vk_bytes {
                pk_hex.push_str(&format!("{:02x}", b));
            }
            bail!(
                "federation config: signer '{}' uses known test fixture key {} ({}); \
                 committed fixture seeds are forbidden in verification rosters",
                signer_desc,
                pk_hex,
                seed_label
            );
        }
    }
    Ok(())
}

/// Reject a federation roster if any signer uses a known test-fixture public key
/// or if two signers share the same decoded 32-byte public key.
pub fn reject_fixture_signers(fed: &FederationConfig) -> Result<()> {
    let mut seen_keys: HashSet<[u8; 32]> = HashSet::new();
    for s in &fed.signers {
        for (fixture_label, fixture_pk) in KNOWN_FIXTURE_PUBKEYS {
            if s.pubkey_hex.eq_ignore_ascii_case(fixture_pk) {
                bail!(
                    "federation config: signer '{}' uses known test fixture key {} ({}); \
                     committed fixture seeds are forbidden in verification rosters",
                    s.id,
                    fixture_pk,
                    fixture_label
                );
            }
        }
        let pk = parse_pubkey(&s.pubkey_hex)
            .with_context(|| format!("signer '{}' has malformed pubkey_hex", s.id))?;
        reject_fixture_verifying_key(&pk, &s.id)?;
        if !seen_keys.insert(pk.to_bytes()) {
            bail!(
                "federation config: duplicate signer public key {} on signer '{}'",
                s.pubkey_hex,
                s.id
            );
        }
    }
    Ok(())
}

/// Load the federation config from `path`. Validates the schema:
///
/// - `threshold >= 1`
/// - `threshold as usize <= signers.len()`
/// - signer `id` is unique
/// - each `pubkey_hex` is 64 lowercase hex chars (parseable as a distinct 32-byte key)
/// - no signer key is in [`KNOWN_FIXTURE_PUBKEYS`] or [`KNOWN_TEST_SEEDS`]
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
    reject_fixture_signers(&cfg)?;
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
    reject_fixture_signers(fed)?;
    let mut counted: HashSet<[u8; 32]> = HashSet::new();
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
        // Each distinct verified 32-byte public key counts once.
        counted.insert(pk.to_bytes());
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

    fn random_sk() -> SigningKey {
        SigningKey::generate(&mut rand::rngs::OsRng)
    }

    #[test]
    fn loads_good_toml() {
        let d = tmpdir("good");
        let sk0 = random_sk();
        let sk1 = random_sk();
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
    fn rejects_known_fixture_pubkeys() {
        let d = tmpdir("fixture_reject");
        for (i, (label, fixture_pk)) in KNOWN_FIXTURE_PUBKEYS.iter().enumerate() {
            let p = write_toml(
                &d,
                &format!(
                    "threshold = 1\n[[signers]]\nid = \"f{}\"\npubkey_hex = \"{}\"\n",
                    i, fixture_pk
                ),
            );
            let err = load_federation(&p).unwrap_err();
            let msg = format!("{:#}", err);
            assert!(
                msg.contains("known test fixture key") && msg.contains(label),
                "got: {}",
                msg
            );

            let cfg = FederationConfig {
                threshold: 1,
                signers: vec![Signer {
                    id: format!("f{}", i),
                    pubkey_hex: (*fixture_pk).to_string(),
                }],
            };
            let msg_bytes = [9u8; 32];
            let sk = random_sk();
            let cosigs = vec![Cosignature {
                signer_id: format!("f{}", i),
                sig_ed25519: sig_hex(&sk, &msg_bytes),
            }];
            let verr = verify_cosignatures(&msg_bytes, &cosigs, &cfg).unwrap_err();
            let vmsg = format!("{:#}", verr);
            assert!(
                vmsg.contains("known test fixture key") && vmsg.contains(label),
                "got: {}",
                vmsg
            );
        }
    }

    #[test]
    fn rejects_duplicate_signer_pubkey_and_test_seeds() {
        let d = tmpdir("dup_pubkey");
        let sk0 = random_sk();
        let p = write_toml(
            &d,
            &format!(
                "threshold = 2\n\
                 [[signers]]\nid = \"a\"\npubkey_hex = \"{}\"\n\
                 [[signers]]\nid = \"b\"\npubkey_hex = \"{}\"\n",
                pk_hex(&sk0),
                pk_hex(&sk0)
            ),
        );
        let err = load_federation(&p).unwrap_err();
        let msg = format!("{:#}", err);
        assert!(msg.contains("duplicate signer public key"), "got: {}", msg);

        let cfg = FederationConfig {
            threshold: 2,
            signers: vec![
                Signer { id: "a".into(), pubkey_hex: pk_hex(&sk0) },
                Signer { id: "b".into(), pubkey_hex: pk_hex(&sk0) },
            ],
        };
        let msg_bytes = [9u8; 32];
        let cosigs = vec![
            Cosignature { signer_id: "a".into(), sig_ed25519: sig_hex(&sk0, &msg_bytes) },
            Cosignature { signer_id: "b".into(), sig_ed25519: sig_hex(&sk0, &msg_bytes) },
        ];
        let verr = verify_cosignatures(&msg_bytes, &cosigs, &cfg).unwrap_err();
        assert!(format!("{:#}", verr).contains("duplicate signer public key"));

        // Verify all KNOWN_TEST_SEEDS are rejected by reject_fixture_verifying_key and load_federation.
        for (i, (label, seed_bytes)) in KNOWN_TEST_SEEDS.iter().enumerate() {
            let sk_seed = SigningKey::from_bytes(seed_bytes);
            let r = reject_fixture_verifying_key(&sk_seed.verifying_key(), "test");
            assert!(r.is_err(), "expected seed {} to be rejected", label);
            let p_seed = write_toml(
                &d,
                &format!(
                    "threshold = 1\n[[signers]]\nid = \"s{}\"\npubkey_hex = \"{}\"\n",
                    i,
                    pk_hex(&sk_seed)
                ),
            );
            assert!(
                load_federation(&p_seed).is_err(),
                "expected load_federation to reject seed {}",
                label
            );
        }
    }

    #[test]
    fn rejects_threshold_above_signer_count() {
        let d = tmpdir("hi_thr");
        let sk0 = random_sk();
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
        let sk0 = random_sk();
        let sk1 = random_sk();
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
        let sk_a = random_sk();
        let sk_b = random_sk();
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
        let sk_a = random_sk();
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
        let sk_a = random_sk();
        let sk_b = random_sk();
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
        let sk_a = random_sk();
        let sk_b = random_sk();
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
        let sk_a = random_sk();
        let sk_b = random_sk();
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
