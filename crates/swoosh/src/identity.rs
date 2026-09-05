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

/// How long a signet-signed, STORED device membership badge stands before it must be re-minted.
///
/// The adversary's one rider (deliberation 10): a stored badge is a longer-lived bearer credential than
/// the 5-minute self-sign a signet holder mints per dial, so it must carry a FINITE lifetime, not
/// "forever" -- a lost, un-denylisted device then ages out on its own even absent an explicit revoke.
/// One year is the chosen point: long enough that a device provisioned once keeps reaching family
/// services across a normal ownership span without a re-mint chore, short enough that a badge whose
/// device fell out of the family without being denylisted does not stand indefinitely. Revocation stays
/// the primary, immediate control (the `FileDenylist`, offline + live); the TTL is the backstop. A signet
/// holder can re-mint (`swoosh mint`) and re-adopt to refresh a badge before it lapses.
const DEVICE_BADGE_TTL: core::time::Duration = core::time::Duration::from_secs(365 * 24 * 60 * 60);

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
            .mint_member(
                self.node_id().verify_key(),
                nauthy::Request::expires_in(ttl),
            )?
            .seal()?
            .link()?;
        Ok(badge)
    }

    /// A stable seed for this node's ssh host key, so a swoosh node exposing `ssh=sshd:` under its persisted
    /// key presents the SAME host key a client pins. Delegates to [`sshh::host_seed`], which owns the
    /// domain-separated derivation, so it lives in exactly one place; the raw secret never leaves the
    /// wrapper, only the seed. Gated on the `ssh` feature, like the rest of the shell surface: a lean client
    /// built without `ssh` neither serves a shell nor needs a host key.
    #[cfg(feature = "ssh")]
    pub fn ssh_host_seed(&self) -> [u8; 32] {
        sshh::host_seed(&self.0)
    }

    /// Sign a membership badge FOR a device, rooted at THIS key (the signet) and bound to `device`.
    ///
    /// This is the mint-time counterpart to [`member_badge`](Self::member_badge): where the signet holder
    /// self-signs its OWN badge per dial (root == dialer), here the signet signs a badge for a DIFFERENT
    /// key (the device's derived node id), so the device can present a signet-rooted proof it could never
    /// mint itself. The gate trusts the signet root, so this badge admits; a device's own self-sign roots
    /// at its child key and is (correctly) refused. `bound_device` = `device`, so an intercepted badge
    /// replayed from another key fails the binding.
    ///
    /// FINITE lifetime: unlike the 5-minute self-sign (re-minted per dial), this badge is STORED on the
    /// device and stands until it expires or is denylisted, so it carries a generous-but-finite TTL
    /// ([`DEVICE_BADGE_TTL`]) rather than "forever" -- a lost, un-denylisted device eventually ages out.
    /// The signet secret stays in this wrapper: only the signed public badge (a `sheer:` link) leaves.
    pub fn sign_device_badge(&self, device: NodeId) -> eyre::Result<String> {
        let badge = self
            .cap_identity()?
            .mint_member(
                device.verify_key(),
                nauthy::Request::expires_in(DEVICE_BADGE_TTL),
            )?
            .seal()?
            .link()?;
        Ok(badge)
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
    /// Dial under the persisted identity WHEN one already exists, else mint a fresh ephemeral key. The
    /// diagnostic verbs (`ping`/`speed`/`status`) want this: a self-signed membership badge only admits at
    /// a family-gated node when it roots at the SAME key the dial binds under, so a provisioned operator
    /// reaches their own gated node by loading the persisted identity, while a fresh install still dials
    /// out ephemerally with nothing on disk. Never CREATES the persisted file (unlike `Persisted`): an
    /// outward dial must not silently mint a lasting identity where one was not asked for.
    PersistedIfPresent,
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
        // Load the persisted key only if it already exists; never create it. So a provisioned operator's
        // outward dial roots at their own key (their self-badge admits at their gated node) while a fresh
        // install dials out ephemerally, with nothing written to disk.
        (None, Identity::PersistedIfPresent) => match load_existing(&default_path()?).await? {
            Some(secret) => Ok(secret),
            None => Ok(Secret::ephemeral()),
        },
    }
}

/// Reject a `--key` that names a directory, with a teaching error instead of the bare `Is a directory
/// (os error 21)` the raw file IO would surface. `--key` wants a key FILE (its sidecars -- the signet,
/// the badge, the contacts book -- live beside it in the parent dir), and pointing it at a directory is
/// the mistake everyone makes, so name the fix. A no-op for the default path (always `identity.key`) and
/// for a not-yet-created file; it only fires on an existing directory.
fn reject_key_directory(path: &Path) -> eyre::Result<()> {
    if path.is_dir() {
        return Err(eyre!(
            "--key wants a key file, not a directory: {dir}. Name a file inside it, e.g. {dir}/identity.key",
            dir = path.display(),
        ));
    }
    Ok(())
}

/// Load the secret at `path` if the file exists and holds a 32-byte key, else `None`. Unlike
/// [`load_or_create`], never writes: an outward dial reads a provisioned identity but does not mint one.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn load_existing(path: &Path) -> eyre::Result<Option<Secret>> {
    reject_key_directory(path)?;
    match tokio::fs::read(path).await {
        Ok(mut bytes) => {
            let secret = <[u8; 32]>::try_from(bytes.as_slice()).ok().map(Secret);
            bytes.zeroize();
            Ok(secret)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Load the secret at `path`, creating and saving a fresh one on first use.
async fn load_or_create(path: &Path) -> eyre::Result<Secret> {
    reject_key_directory(path)?;
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
/// `serve` binds: it MUST land in the same store [`resolve`] reads, so the node comes up AS the adopted
/// device. (Writing tightbeam's separate store instead was the qat identity-mismatch bug: `serve` bound
/// swoosh's own key, never the adopted one, so the exposed node had a different id than the contact
/// pointed at.)
pub async fn write(seed: &[u8; 32], explicit: Option<&Path>) -> eyre::Result<()> {
    let path = match explicit {
        Some(p) => p.to_path_buf(),
        None => default_path()?,
    };
    reject_key_directory(&path)?;
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
