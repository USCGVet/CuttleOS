//! Software signing key management. Production replaces this with HSM
//! invocation; the cycle code does not care which.

use anyhow::{bail, Context, Result};
use ed25519_dalek::SigningKey;
use rand::rngs::OsRng;
use std::path::{Path, PathBuf};

pub const SIGNING_KEY_FILE: &str = "factory_signing_key.bin";
pub const SIGNING_KEY_ENV: &str = "CUTTLE_SIGNING_KEY_PATH";

pub fn resolve_signing_key_path() -> PathBuf {
    match std::env::var(SIGNING_KEY_ENV) {
        Ok(s) if !s.is_empty() => PathBuf::from(s),
        _ => {
            let local = PathBuf::from(SIGNING_KEY_FILE);
            if local.exists() {
                local
            } else {
                crate::secret_file::default_user_keys_dir().join(SIGNING_KEY_FILE)
            }
        }
    }
}

pub fn init_signing_key() -> Result<()> {
    let path = resolve_signing_key_path();
    if path.exists() {
        bail!("signing key already exists at {}", path.display());
    }
    let key = SigningKey::generate(&mut OsRng);
    crate::secret_file::write_exclusive(&path, &key.to_bytes())
        .with_context(|| format!("write {}", path.display()))?;
    eprintln!(
        "morph: generated factory signing key at {} (verifying key: {})",
        path.display(),
        hex(&key.verifying_key().to_bytes())
    );
    Ok(())
}

pub fn load_signing_key() -> Result<SigningKey> {
    let path = resolve_signing_key_path();
    load_signing_key_from(&path)
        .with_context(|| "run `morph init-key` first".to_string())
}

/// Load a 32-byte Ed25519 signing key from an explicit path. Used by
/// attestation verification to derive the primary verifying key from
/// wherever the key file actually lives.
pub fn load_signing_key_from(path: &Path) -> Result<SigningKey> {
    let arr = crate::secret_file::load_strict(path)?;
    Ok(SigningKey::from_bytes(&arr))
}

pub(crate) fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push_str(&format!("{:02x}", b));
    }
    s
}
