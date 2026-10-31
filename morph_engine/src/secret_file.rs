//! Strict host-side secret key file custody (`R1`).
//!
//! Mirrors the semantics of `tools/triad_controller.py::write_secret_file` and
//! `load_or_create_secret_file`:
//! 1. Never overwrite or silently regenerate an existing secret file that has a
//!    malformed length or all-zero contents (`load_strict`, `load_or_create_strict_32`).
//! 2. Create a temporary sibling file exclusively (`create_new(true)` / `O_EXCL`),
//!    restrict permissions (`0600` on Unix, owner-only DACL via `icacls` on Windows),
//!    write all bytes, `sync_all()` (`fsync`), and rename into place (`write_exclusive`).
//! 3. Resolve default secret locations to a per-user directory outside the git
//!    working tree (`%LOCALAPPDATA%\Cuttle\keys` on Windows, `$XDG_DATA_HOME/cuttle/keys`
//!    or `$HOME/.local/share/cuttle/keys` on Unix), while honoring explicit env-var
//!    overrides (`CUTTLE_KEYS_DIR`, `CUTTLE_SIGNING_KEY_PATH`).

use anyhow::{bail, Context, Result};
use rand::RngCore;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

/// Optional environment variable overriding the per-user keys directory.
pub const KEYS_DIR_ENV: &str = "CUTTLE_KEYS_DIR";

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Return the default per-user secret keys directory outside the repository
/// (`%LOCALAPPDATA%\Cuttle\keys` on Windows, `$XDG_DATA_HOME/cuttle/keys` or
/// `$HOME/.local/share/cuttle/keys` on Unix).
pub fn default_user_keys_dir() -> PathBuf {
    if let Ok(custom) = std::env::var(KEYS_DIR_ENV) {
        if !custom.trim().is_empty() {
            return PathBuf::from(custom);
        }
    }
    if cfg!(windows) {
        if let Ok(local_app_data) = std::env::var("LOCALAPPDATA") {
            if !local_app_data.trim().is_empty() {
                return PathBuf::from(local_app_data).join("Cuttle").join("keys");
            }
        }
        if let Ok(user_profile) = std::env::var("USERPROFILE") {
            if !user_profile.trim().is_empty() {
                return PathBuf::from(user_profile)
                    .join("AppData")
                    .join("Local")
                    .join("Cuttle")
                    .join("keys");
            }
        }
    } else {
        if let Ok(xdg) = std::env::var("XDG_DATA_HOME") {
            if !xdg.trim().is_empty() {
                return PathBuf::from(xdg).join("cuttle").join("keys");
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.trim().is_empty() {
                return PathBuf::from(home)
                    .join(".local")
                    .join("share")
                    .join("cuttle")
                    .join("keys");
            }
        }
    }
    std::env::temp_dir().join("cuttle_user_keys")
}

/// Apply owner-only permissions (`0600` on Unix; `/inheritance:r /grant:r <USER>:F`
/// via `icacls` on Windows) to `path`.
pub fn restrict_file_owner_only(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let perms = fs::Permissions::from_mode(0o600);
        fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 0600 {}", path.display()))?;
    }
    #[cfg(windows)]
    {
        let user = std::env::var("USERNAME").unwrap_or_default();
        if !user.trim().is_empty() {
            let grant_arg = match std::env::var("USERDOMAIN") {
                Ok(dom) if !dom.trim().is_empty() => format!("{dom}\\{user}:F"),
                _ => format!("{user}:F"),
            };
            let out = Command::new("icacls")
                .arg(path)
                .arg("/inheritance:r")
                .arg("/grant:r")
                .arg(&grant_arg)
                .output();
            if let Ok(o) = out {
                if !o.status.success() {
                    let _ = Command::new("icacls")
                        .arg(path)
                        .arg("/inheritance:r")
                        .arg("/grant:r")
                        .arg(format!("{user}:F"))
                        .output();
                }
            }
        }
    }
    Ok(())
}

/// Write `data` to `path` via an exclusively created temporary sibling file (`O_EXCL`),
/// setting owner-only permissions before writing bytes, flushing via `sync_all()`, and
/// renaming into place. Refuses if `path` already exists.
pub fn write_exclusive(path: &Path, data: &[u8]) -> Result<()> {
    if path.exists() {
        bail!(
            "secret_file::write_exclusive refused: target {} already exists",
            path.display()
        );
    }
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)
                .with_context(|| format!("create parent dir {}", parent.display()))?;
        }
    }
    let pid = std::process::id();
    let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
    let file_name = path
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("secret.bin");
    let tmp_name = format!(".{file_name}.{pid}.{seq}.tmp");
    let tmp_path = path.with_file_name(tmp_name);

    let mut f = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp_path)
        .with_context(|| format!("exclusive create {}", tmp_path.display()))?;

    if let Err(e) = (|| -> Result<()> {
        restrict_file_owner_only(&tmp_path)?;
        f.write_all(data)
            .with_context(|| format!("write secret bytes to {}", tmp_path.display()))?;
        f.sync_all()
            .with_context(|| format!("fsync {}", tmp_path.display()))?;
        Ok(())
    })() {
        drop(f);
        let _ = fs::remove_file(&tmp_path);
        return Err(e);
    }
    drop(f);

    if path.exists() {
        let _ = fs::remove_file(&tmp_path);
        bail!(
            "secret_file::write_exclusive refused: target {} appeared concurrently",
            path.display()
        );
    }
    if let Err(e) = fs::rename(&tmp_path, path) {
        let _ = fs::remove_file(&tmp_path);
        return Err(e).with_context(|| {
            format!("rename {} -> {}", tmp_path.display(), path.display())
        });
    }
    restrict_file_owner_only(path)?;
    Ok(())
}

/// Strictly load a 32-byte non-zero secret key from `path`. Never modifies or
/// regenerates `path`. Fails closed if the file is missing, unreadable, not
/// exactly 32 bytes, or all zeros.
pub fn load_strict(path: &Path) -> Result<[u8; 32]> {
    let bytes = fs::read(path).with_context(|| format!("read secret file {}", path.display()))?;
    if bytes.len() != 32 {
        bail!(
            "secret file {} has invalid length {} (expected 32 bytes); refusing to overwrite or regenerate",
            path.display(),
            bytes.len()
        );
    }
    if bytes.iter().all(|&b| b == 0) {
        bail!(
            "secret file {} is all-zero (32 zero bytes); refusing to overwrite or regenerate",
            path.display()
        );
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// Load a 32-byte secret key from `path` if it exists (strictly rejecting
/// malformed or all-zero files without overwriting them), or generate a fresh
/// 32-byte OS-CSPRNG key via [`write_exclusive`] if `path` does not exist.
pub fn load_or_create_strict_32(path: &Path) -> Result<[u8; 32]> {
    if path.exists() {
        return load_strict(path);
    }
    let mut key = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    if key.iter().all(|&b| b == 0) {
        bail!("OS CSPRNG returned 32 zero bytes");
    }
    write_exclusive(path, &key)?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn unique_tmp_dir(tag: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        let seq = TMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("cuttle_secret_file_{tag}_{nanos}_{seq}"));
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn secret_file_rejects_malformed_existing_key_without_overwrite() {
        let dir = unique_tmp_dir("malformed");
        let short_path = dir.join("device_secret_key.bin");
        let short_bytes: Vec<u8> = (1u8..=31).collect();
        fs::write(&short_path, &short_bytes).unwrap();

        let err = load_or_create_strict_32(&short_path)
            .expect_err("31-byte existing key must be rejected");
        assert!(
            format!("{err:#}").contains("invalid length 31"),
            "unexpected error: {err:#}"
        );
        assert_eq!(fs::read(&short_path).unwrap(), short_bytes);

        let zero_path = dir.join("zero_secret_key.bin");
        fs::write(&zero_path, [0u8; 32]).unwrap();
        let zerr = load_or_create_strict_32(&zero_path)
            .expect_err("all-zero 32-byte key must be rejected");
        assert!(
            format!("{zerr:#}").contains("all-zero"),
            "unexpected error: {zerr:#}"
        );
        assert_eq!(fs::read(&zero_path).unwrap(), vec![0u8; 32]);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn init_key_creates_owner_only_file() {
        let dir = unique_tmp_dir("owner_only");
        let key_path = dir.join("factory_signing_key.bin");
        let key = load_or_create_strict_32(&key_path).expect("create fresh 32-byte secret key");
        assert_eq!(load_strict(&key_path).unwrap(), key);

        assert!(write_exclusive(&key_path, &[0xAA; 32]).is_err());

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(&key_path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "expected 0600 permissions on Unix, got {mode:o}");
        }
        #[cfg(windows)]
        {
            let out = Command::new("icacls")
                .arg(&key_path)
                .output()
                .expect("run icacls on key file");
            assert!(out.status.success());
            let stdout = String::from_utf8_lossy(&out.stdout);
            let user = std::env::var("USERNAME").unwrap_or_default();
            if !user.is_empty() {
                assert!(
                    stdout.to_ascii_lowercase().contains(&user.to_ascii_lowercase()),
                    "expected icacls output to grant current user {user:?}, got:\n{stdout}"
                );
            }
            assert!(
                !stdout.contains("(I)"),
                "expected icacls /inheritance:r to strip inherited ACEs, got:\n{stdout}"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn repo_tracks_no_secret_key_or_token_files() {
        let ws_root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("workspace root");
        let out = Command::new("git")
            .current_dir(ws_root)
            .args([
                "ls-files",
                "*secret_key*.bin",
                "factory_signing_key.bin",
                "factory_keys.local.toml",
                ".cargo/config.toml",
                "*token.txt",
                "**/operator_token.txt",
                "**/provider_token.txt",
                "**/client_token.txt",
                "*.pyc",
            ])
            .output()
            .expect("run git ls-files secret check");
        assert!(out.status.success());
        let tracked = String::from_utf8_lossy(&out.stdout).trim().to_string();
        assert!(
            tracked.is_empty(),
            "forbidden secret/token/bytecode files tracked in git: {tracked}"
        );
    }
}
