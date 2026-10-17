//! Software signing key management. Production replaces this with HSM
//! invocation; the cycle code does not care which.

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::fs;
use std::path::Path;

pub const SIGNING_KEY_FILE: &str = "factory_signing_key.bin";

pub fn init_signing_key() -> Result<()> {
    if Path::new(SIGNING_KEY_FILE).exists() {
        bail!("signing key already exists at {}", SIGNING_KEY_FILE);
    }
    let key = SigningKey::generate(&mut OsRng);
    fs::write(SIGNING_KEY_FILE, key.to_bytes())
        .with_context(|| format!("write {}", SIGNING_KEY_FILE))?;
    eprintln!(
        "morph: generated factory signing key at {} (verifying key: {})",
        SIGNING_KEY_FILE,
        hex(&key.verifying_key().to_bytes())
    );
    Ok(())
}

pub fn load_signing_key() -> Result<SigningKey> {
    load_signing_key_from(Path::new(SIGNING_KEY_FILE))
        .with_context(|| format!("run `morph init-key` first"))
}

/// Load a 32-byte Ed25519 signing key from an explicit path. Used by
/// attestation verification to derive the primary verifying key from
/// wherever the key file actually lives.
pub fn load_signing_key_from(path: &Path) -> Result<SigningKey> {
    let bytes = fs::read(path)
        .with_context(|| format!("read {}", path.display()))?;
    if bytes.len() != 32 {
        bail!(
            "signing key file {} has wrong length: {}",
            path.display(),
            bytes.len()
        );
    }
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    Ok(SigningKey::from_bytes(&arr))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
