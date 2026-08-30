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

use bifrost::NodeId;
use eyre::eyre;
use tightbeam::identity::AsVerifyKey as _;
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

    /// The node id this secret binds under: the identity a peer reaches when it dials this key. Derived
    /// offline (no transport stood up), so `swoosh identity` can print it without serving.
    pub fn node_id(&self) -> NodeId {
        NodeId::from_ed25519_secret(&self.0)
    }

    /// The cap-signing identity rooted at this secret: the same key, read as a nauthy [`Identity`] that
    /// can mint and verify capabilities. Borrows, so the secret stays owned here and zeroizes on drop.
    ///
    /// This is what lets the signet holder SELF-SIGN a membership badge when it dials a family-gated node
    /// (`mint` signs a device's badge; `swoosh ssh` self-signs its own): the badge roots at this key, the
    /// same key the dial binds under, so the gate's device-binding matches. Mirrors tightbeam's
    /// `Secret::cap_identity`, the exposer side of the same seam.
    pub fn cap_identity(&self) -> eyre::Result<nauthy::Identity> {
        Ok(nauthy::Identity::from_secret(&self.0)?)
    }

    /// Self-sign a membership badge for THIS identity: a short-lived cap carrying a `member(true)` fact in
    /// its authority block, rooted at this key and bound to this key's own node id. The `member(true)` fact
    /// is what a family gate reads as membership; because biscuit trusts only authority-block facts, it
    /// cannot be forged by attenuation. The signet holder is the one party always entitled to a badge
    /// (it holds the root), so when it dials a family-gated node it mints one in-process rather than
    /// carrying a stored one. Short-lived because it is re-minted per dial; the binding makes it useless if
    /// intercepted off another key. Returns the `sheer:` link to present.
    pub fn member_badge(&self) -> eyre::Result<String> {
        use core::time::Duration;

        // Minted fresh each dial, so a few minutes is ample and bounds a leaked in-flight badge.
        let ttl = Duration::from_secs(5 * 60);
        let badge = self
            .cap_identity()?
            .mint_member(self.node_id().verify_key(), nauthy::expires_in(ttl))?
            .seal()?
            .link()?;
        Ok(badge)
    }

    /// A stable seed for this node's ssh host key, derived from this secret by the same domain-separated
    /// KDF tightbeam uses, so a swoosh node exposing `ssh=sshd:` under its persisted key presents the SAME
    /// host key a client pins. Delegates to tightbeam's [`ssh_host_seed`](tightbeam::identity::ssh_host_seed)
    /// so the derivation lives in exactly one place; the raw secret never leaves the wrapper, only the seed.
    pub fn ssh_host_seed(&self) -> [u8; 32] {
        tightbeam::identity::ssh_host_seed(&self.0)
    }

    /// The seed for a device identity derived from this key (the signet) under `label`: the secret a
    /// machine ADOPTS to become that device, and the payload of a `mint`ed authkey. Borrows, so this root
    /// stays owned here and zeroizes on drop; the raw root never leaves the wrapper, only the derived
    /// child does. Hardened (only the holder of this root can compute a child), so a leaked device seed
    /// cannot recover the root or a sibling.
    pub fn derive_child_seed(&self, label: &str) -> [u8; 32] {
        bifrost_core::derive_ed25519_child_secret(&self.0, label)
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

/// Write `seed` as the persisted identity at `explicit` (or the default path), mode 0600, creating the
/// directory. This is how [`adopt`](crate::commands::adopt) provisions the device identity a later
/// `serve`/`tunnel expose` binds: it MUST land in the same store [`resolve`] reads, so the node comes up
/// AS the adopted device. (Writing tightbeam's separate store instead was the qat identity-mismatch bug:
/// `expose` bound swoosh's own key, never the adopted one, so the exposed node had a different id than the
/// contact pointed at.)
pub async fn write(seed: &[u8; 32], explicit: Option<&Path>) -> eyre::Result<()> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => default_path()?,
    };
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, seed).await?;
    restrict(&path).await?;
    Ok(())
}

/// The default persisted key location, `~/.config/swoosh/identity.key`.
pub(crate) fn default_path() -> eyre::Result<PathBuf> {
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
