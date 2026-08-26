//! The shared node identity: one 32-byte ed25519 secret on disk, so every swoosh verb speaks from the
//! same address across runs. This is the whole point of unifying the tools: one identity, one config
//! dir, one address for every operation, not a different key per verb.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes its bytes on drop so the
//! key does not linger in freed memory, and it is only unwrapped at the single boundary where the
//! transport consumes it.
//!
//! Override the location with `SWOOSH_KEY`; otherwise `~/.config/swoosh/identity.key`, mode 0600.

use std::path::{Path, PathBuf};

use eyre::eyre;
use zeroize::{Zeroize as _, ZeroizeOnDrop};

/// The persisted ed25519 secret key. Wraps the raw bytes so they zeroize on drop and never cross a
/// boundary as a bare array; unwrap only at the transport bind, the one place the key must be raw.
#[derive(ZeroizeOnDrop)]
pub struct Secret([u8; 32]);

impl Secret {
    /// Consume the secret into its raw bytes for the transport bind. This is the single boundary where
    /// the key leaves the zeroizing wrapper; the transport crate owns the key type downstream.
    pub fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        // Wipe our copy; the returned array is the caller's to own (and, ideally, zeroize) from here.
        self.0.zeroize();
        bytes
    }
}

/// Load the persisted secret key, creating and saving a fresh one on first run.
pub async fn load_or_create() -> eyre::Result<Secret> {
    let path = key_path()?;
    if let Ok(mut bytes) = tokio::fs::read(&path).await {
        if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
            bytes.zeroize();
            return Ok(Secret(secret));
        }
        bytes.zeroize();
    }

    let secret: [u8; 32] = rand::random();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, &secret).await?;
    restrict(&path).await?;
    Ok(Secret(secret))
}

fn key_path() -> eyre::Result<PathBuf> {
    if let Some(path) = std::env::var_os("SWOOSH_KEY") {
        return Ok(PathBuf::from(path));
    }
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set; set SWOOSH_KEY"))?;
    Ok(PathBuf::from(home)
        .join(".config")
        .join("swoosh")
        .join("identity.key"))
}

#[cfg(unix)]
async fn restrict(path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::PermissionsExt as _;

    tokio::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).await?;
    Ok(())
}

#[cfg(not(unix))]
async fn restrict(_path: &Path) -> eyre::Result<()> {
    Ok(())
}
