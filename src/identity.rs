//! The node identity: the ed25519 secret every swoosh verb binds under.
//!
//! Identity is chosen by intent, and exactly one intent CREATES a key. A verb that must be *reachable at
//! a stable address* (`serve`), or that must dial under this node's own key (the `swoosh ssh` bridge),
//! persists its secret at `<home>/identity.key`: it loads that key and writes one on first use, so
//! restarting the node keeps its address. A verb that only *reaches outward* (`ping`, `speed`, `reach`)
//! LOADS that key when it already exists, because the membership badge it presents must root at the key
//! the dial binds under, and mints a throwaway in-memory key when it does not. It never writes one: a
//! dial does not provision a node, and the file it would write is the very key a later `serve` roots its
//! fleet at.
//!
//! An explicit home (`--home <dir>` or `SWOOSH_HOME`) chooses WHERE that key lives, never WHETHER one is
//! created. The verb's intent alone decides that, so a home named for one outward dial is left exactly as
//! it was found.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes its bytes on drop so the
//! key does not linger in freed memory, and it is only unwrapped at the single boundary where the
//! transport consumes it.
//!
//! The persisted default lives at `~/.config/swoosh/identity.key`, mode 0600.

use std::path::Path;

use bifrost::NodeId;
use eyre::WrapErr as _;
use nauthy::Link;
use tightbeam::identity::AsVerifyKey as _;
use zeroize::{Zeroize as _, ZeroizeOnDrop};

use crate::home::Home;

/// The exact byte length of a persisted ed25519 seed. An `identity.key` of any other length is corrupt or
/// foreign: reading it fails closed and [`write`] never mints a fresh key over it.
const KEY_LEN: usize = 32;

/// The DEFAULT lifetime a signet-signed, STORED device membership badge stands before it must be
/// re-minted, applied by `swoosh invite add` only when the operator passes no `--expires`. A default, not a
/// hardcoded law: the CLI threads an explicit window straight into [`sign_device_badge`], and falls back
/// to this value when none is given.
///
/// A stored badge is a longer-lived bearer credential than the 5-minute self-sign a signet holder mints
/// per dial, so it must carry a FINITE lifetime, not "forever" -- a lost, un-denylisted device then ages
/// out on its own even absent an explicit revoke. Offline there is no control plane to split the invite's
/// leak-window from the badge lifetime, so this value IS the worst-case leak window for a mint that is
/// never revoked. 90 days is the chosen default: a real re-mint cadence (about quarterly) a homelab owner
/// can absorb, and a 90-day backstop instead of a year, matching the invite default operators expect. A
/// longer window (up to a year via `swoosh invite add --expires 365d`, for a controlled reused-secret case such
/// as qat) stays reachable, but is now a conscious opt-in rather than the silent, only value. Revocation
/// stays the primary, immediate control (the `FileDenylist`, offline + live); the TTL is the backstop for
/// a leak never noticed.
pub const DEVICE_BADGE_TTL: core::time::Duration =
    core::time::Duration::from_secs(90 * 24 * 60 * 60);

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
    /// (`invite add` signs a device's badge; `swoosh ssh` self-signs its own): the badge roots at this key, the
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
    pub fn member_badge(&self) -> eyre::Result<Link> {
        use core::time::Duration;

        // Minted fresh each dial, so a few minutes is ample and bounds a leaked in-flight badge.
        let ttl = Duration::from_secs(5 * 60);
        Ok(self
            .cap_identity()?
            .mint_member(
                self.node_id().verify_key(),
                nauthy::Request::expires_in(ttl),
            )?
            .seal()?
            .link()?)
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
    /// device and stands until it expires or is denylisted, so it carries a generous-but-finite `ttl`
    /// rather than "forever" -- a lost, un-denylisted device eventually ages out. The caller owns the
    /// window: `swoosh invite add` passes an explicit `--expires`, or falls back to [`DEVICE_BADGE_TTL`], so
    /// the lifetime is a default the CLI applies, not a constant buried in this signer. The signet secret
    /// stays in this wrapper: only the signed public badge (a `sheer:` link) leaves.
    pub fn sign_device_badge(
        &self,
        device: NodeId,
        ttl: core::time::Duration,
    ) -> eyre::Result<Link> {
        Ok(self
            .cap_identity()?
            .mint_member(device.verify_key(), nauthy::Request::expires_in(ttl))?
            .seal()?
            .link()?)
    }

    /// The seed for a device identity derived from this key (the signet) under `label`: the secret a
    /// machine ADOPTS to become that device, and the payload of a derived invite. Borrows, so this root
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
/// runs, so it is [`Persisted`](Self::Persisted); a reach-outward verb addresses a peer and never needs
/// to be found again, so it is [`PersistedIfPresent`](Self::PersistedIfPresent), binding the home's key
/// where one exists (its badge roots there) and a throwaway where none does. The home says where the key
/// lives; only the intent says whether one is written (see [`resolve`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Identity {
    /// Persist the secret to disk and reuse it every run, so this node keeps one stable address.
    Persisted,
    /// Mint a fresh random secret in memory for this run only; nothing is written or read.
    Ephemeral,
    /// Dial under the persisted identity WHEN one already exists, else mint a fresh ephemeral key. Every
    /// reach-outward verb wants this: a membership badge only admits at a family-gated node when it roots
    /// at the SAME key the dial binds under, so a provisioned operator reaches their own gated node by
    /// loading the persisted identity, while a fresh install still dials out with nothing on disk. Never
    /// CREATES the persisted file, under any home: an outward dial must not mint a lasting identity where
    /// one was not asked for, least of all the key a later `serve` would gate its whole fleet on.
    PersistedIfPresent,
}

/// Resolve the secret a verb binds under from its home: the key is always `<home>/identity.key`, and the
/// verb's [`Identity`] ALONE decides whether one is written.
///
/// The home names the directory, default or explicit alike. A `--home`/`SWOOSH_HOME` run does not turn an
/// outward dial into a provisioning step: the home the caller named for one `swoosh reach` must be left
/// as it was found, because the key that would appear there is the root a later `serve` gates its fleet
/// on, and nothing asked for a fleet.
pub async fn resolve(intent: Identity, home: &Home) -> eyre::Result<Secret> {
    let key = home.identity_key();
    match intent {
        Identity::Persisted => load_or_create(&key).await,
        Identity::Ephemeral => Ok(Secret::ephemeral()),
        // Load the persisted key only if it already exists; never create it. So a provisioned operator's
        // outward dial roots at their own key (their badge admits at their gated node) while a fresh
        // install dials out ephemerally, with nothing written to disk.
        Identity::PersistedIfPresent => match load_existing(&key).await? {
            Some(secret) => Ok(secret),
            None => Ok(Secret::ephemeral()),
        },
    }
}

/// Load the persisted secret at `<home>/identity.key` if the file exists and holds a key, else `None`,
/// WITHOUT creating one. A bound invite carries no seed, so `adopt` uses this to require the key the
/// badge was signed for; a home with no identity gets a teaching error, never a fresh key minted over
/// the invite's binding.
pub async fn load(home: &Home) -> eyre::Result<Option<Secret>> {
    load_existing(&home.identity_key()).await
}

/// Load the secret at `path` if the file exists and holds a 32-byte key, else `None`. Unlike
/// [`load_or_create`], never writes: an outward dial reads a provisioned identity but does not mint one.
/// A file that exists but is the wrong size fails closed (a corrupt or foreign key file is a loud error,
/// never a silent fall-through to a fresh ephemeral identity).
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn load_existing(path: &Path) -> eyre::Result<Option<Secret>> {
    read_key(path).await
}

/// Load the secret at `path`, creating and saving a fresh one on first use.
async fn load_or_create(path: &Path) -> eyre::Result<Secret> {
    if let Some(secret) = read_key(path).await? {
        return Ok(secret);
    }

    let secret = Secret::ephemeral();
    crate::config::write_private_atomic(path, &secret.0).await?;
    Ok(secret)
}

/// Read the persisted key at `path`: `Ok(None)` only when the file is absent, the key otherwise. A file
/// that exists but holds anything other than exactly [`KEY_LEN`] bytes is refused with the size named, so
/// a corrupt key file is never silently discarded and [`load_or_create`] never mints over it.
///
/// The mode is read from the OPEN handle and the bytes are read from that SAME handle, so a symlink swap
/// between the check and the read cannot slip a different file past the guard (TOCTOU-safe), mirroring the
/// `@<path>` secret reader in [`crate::secret`].
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
async fn read_key(path: &Path) -> eyre::Result<Option<Secret>> {
    use tokio::io::AsyncReadExt as _;

    let file = match tokio::fs::File::open(path).await {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
    };
    guard_mode(&file, path).await?;
    // Read one byte past the key so an oversized file is DETECTED rather than silently truncated to its
    // first 32 bytes: any other length is corrupt or foreign, and fail-closed keeps a fresh key from
    // silently replacing it. The buffer zeroizes on drop, so a partial read leaves no key material behind.
    let mut bytes = zeroize::Zeroizing::new(Vec::new());
    file.take((KEY_LEN + 1) as u64)
        .read_to_end(&mut bytes)
        .await
        .wrap_err_with(|| format!("failed to read the identity key {}", path.display()))?;
    let secret = <[u8; KEY_LEN]>::try_from(bytes.as_slice()).map_err(|_| {
        eyre::eyre!(
            "identity key {} is {} bytes; an ed25519 key is exactly {KEY_LEN}. refusing to \
             overwrite it: restore a valid key or move the file aside",
            path.display(),
            bytes.len(),
        )
    })?;
    Ok(Some(Secret(secret)))
}

/// Refuse a group- or world-accessible identity key, mirroring the `@<path>` secret reader: the key IS a
/// full node identity, so silently reading a file others can read defeats the point. Owner-only means no
/// group/other bits (`mode & 0o077 == 0`); the error names the file and hints `chmod 600`.
///
/// The mode is read from the OPEN handle the caller also reads from, so this is TOCTOU-safe.
#[cfg(unix)]
async fn guard_mode(file: &tokio::fs::File, path: &Path) -> eyre::Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let mode = file
        .metadata()
        .await
        .wrap_err_with(|| format!("failed to stat the identity key {}", path.display()))?
        .mode();
    if mode & 0o077 != 0 {
        return Err(eyre::eyre!(
            "permissions {:04o} for the identity key {} are too open: group or other can read it. \
             run `chmod 600 {}`",
            mode & 0o7777,
            path.display(),
            path.display(),
        ));
    }
    Ok(())
}

/// Non-unix has no portable file-mode equivalent, so the guarantee is unix-only: read the file as given.
#[cfg(not(unix))]
async fn guard_mode(_file: &tokio::fs::File, _path: &Path) -> eyre::Result<()> {
    Ok(())
}

/// Write `seed` as the persisted identity at `<home>/identity.key`, mode 0600, creating the store dir.
/// This is how `adopt` provisions the device identity a later `serve` binds: it
/// MUST land in the same store [`resolve`] reads, so the node comes up AS the adopted device. (Writing
/// tightbeam's separate store instead was the qat identity-mismatch bug: `serve` bound swoosh's own key,
/// never the adopted one, so the exposed node had a different id than the contact pointed at.)
///
/// The write is ATOMIC (a unique temp sibling in the same directory, then one rename over the target), so
/// a crash or a failed write can never truncate the key: the old file stays intact until the rename lands.
pub async fn write(seed: &[u8; 32], home: &Home) -> eyre::Result<()> {
    crate::config::write_private_atomic(&home.identity_key(), seed).await
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
