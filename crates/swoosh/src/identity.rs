//! The node identity: the ed25519 secret every swoosh verb binds under.
//!
//! Identity is chosen by intent, not one-size-fits-all. A verb that must be *reachable at a stable
//! address* ([`serve`](crate::commands::serve)) persists its secret to disk, so restarting the node
//! keeps its address. A verb that only *reaches outward* ([`ping`](crate::commands::ping),
//! [`speed`](crate::commands::speed), [`status`](crate::commands::status)) needs no lasting identity,
//! so it mints a fresh random ephemeral key each run: nothing on disk, no address to pin, no key file to
//! provision before a speed test. An explicit key (`--key <path>` or `SWOOSH_KEY`) overrides either way,
//! for the caller who does want a pinned identity even when reaching outward.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes its bytes on drop so the
//! key does not linger in freed memory, and it is only unwrapped at the single boundary where the
//! transport consumes it.
//!
//! The persisted default lives at `~/.config/swoosh/identity.key`, mode 0600.

use std::path::{Path, PathBuf};

use eyre::eyre;
use zeroize::{Zeroize as _, ZeroizeOnDrop};

/// The ed25519 secret key a verb binds under. Wraps the raw bytes so they zeroize on drop and never
/// cross a boundary as a bare array; unwrap only at the transport bind, the one place the key must be
/// raw.
#[derive(ZeroizeOnDrop)]
pub struct Secret([u8; 32]);

impl Secret {
    /// A fresh random secret, kept only in memory. The identity of a reach-outward run.
    pub fn ephemeral() -> Self {
        Self(rand::random())
    }

    /// Consume the secret into its raw bytes for the transport bind. This is the single boundary where
    /// the key leaves the zeroizing wrapper; the transport crate owns the key type downstream.
    pub fn into_bytes(mut self) -> [u8; 32] {
        let bytes = self.0;
        // Wipe our copy; the returned array is the caller's to own (and, ideally, zeroize) from here.
        self.0.zeroize();
        bytes
    }
}

/// How a verb wants its identity: pinned to a stable address, or freshly minted for one run.
///
/// The distinction that drives the whole module: `serve` must be reachable at the same address across
/// runs, so it [`Persisted`](Self::Persisted); the reach-outward verbs address a peer and never need to
/// be found again, so they are [`Ephemeral`](Self::Ephemeral). An explicit `--key`/`SWOOSH_KEY`
/// overrides either intent (see [`resolve`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Persist the secret to disk and reuse it every run, so this node keeps one stable address.
    Persisted,
    /// Mint a fresh random secret in memory for this run only; nothing is written or read.
    Ephemeral,
}

/// Resolve the secret a verb binds under, honoring an explicit override before the verb's [`Identity`].
///
/// An explicit key path (`--key` or `SWOOSH_KEY`) always wins: load it, creating and saving one if it
/// does not exist yet, whatever the verb's intent. With no override, [`Persisted`](Identity::Persisted)
/// loads-or-creates the default key file and [`Ephemeral`](Identity::Ephemeral) mints a random key that
/// never touches disk.
pub async fn resolve(intent: Identity, explicit: Option<&Path>) -> eyre::Result<Secret> {
    match (explicit, intent) {
        (Some(path), _) => load_or_create(path).await,
        (None, Identity::Persisted) => load_or_create(&default_path()?).await,
        (None, Identity::Ephemeral) => Ok(Secret::ephemeral()),
    }
}

/// Load the secret at `path`, creating and saving a fresh one on first use.
async fn load_or_create(path: &Path) -> eyre::Result<Secret> {
    if let Ok(mut bytes) = tokio::fs::read(path).await {
        if let Ok(secret) = <[u8; 32]>::try_from(bytes.as_slice()) {
            bytes.zeroize();
            return Ok(Secret(secret));
        }
        bytes.zeroize();
    }

    let secret = Secret::ephemeral();
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(path, secret.0).await?;
    restrict(path).await?;
    Ok(secret)
}

/// The default persisted key location, `~/.config/swoosh/identity.key`.
fn default_path() -> eyre::Result<PathBuf> {
    let home = std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set; pass --key"))?;
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
