//! The shared node identity: one 32-byte ed25519 secret on disk, so every swoosh verb speaks from the
//! same address across runs. This is the whole point of unifying the tools: one identity, one config
//! dir, one address for every operation, not a different key per verb.
//!
//! Override the location with `SWOOSH_KEY`; otherwise `~/.config/swoosh/identity.key`, mode 0600.

use std::path::{Path, PathBuf};

use eyre::eyre;

/// Load the persisted secret key, creating and saving a fresh one on first run.
pub async fn load_or_create() -> eyre::Result<[u8; 32]> {
    let path = key_path()?;
    if let Ok(bytes) = tokio::fs::read(&path).await
        && let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice())
    {
        return Ok(secret);
    }

    let secret: [u8; 32] = rand::random();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, &secret).await?;
    restrict(&path).await?;
    Ok(secret)
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
