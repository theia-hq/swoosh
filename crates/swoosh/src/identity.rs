//! The node identity: the ed25519 secret every swoosh verb binds under.
//!
//! Identity is chosen by intent, not one-size-fits-all. A verb that must be *reachable at a stable
//! address* ([`serve`](crate::commands::serve)) persists its secret to disk, so restarting the node
//! keeps its address. A verb that only *reaches outward* ([`ping`](crate::commands::ping),
//! [`speed`](crate::commands::speed), [`status`](crate::commands::status)) needs no lasting identity,
//! so it mints a fresh random ephemeral key each run: nothing on disk, no address to pin, no key file to
//! provision before a speed test. An explicit home (`--home <dir>` or `SWOOSH_HOME`) overrides either way,
//! pinning the identity at `<home>/identity.key` even when reaching outward, for the caller who wants it.
//!
//! The secret is a [`Secret`] newtype, never a bare `[u8; 32]`: it zeroizes its bytes on drop so the
//! key does not linger in freed memory, and it is only unwrapped at the single boundary where the
//! transport consumes it.
//!
//! The persisted default lives at `~/.config/swoosh/identity.key`, mode 0600.

use core::sync::atomic::{AtomicU64, Ordering};
use std::path::{Path, PathBuf};

use bifrost::NodeId;
use eyre::WrapErr as _;
use tightbeam::identity::AsVerifyKey as _;
use zeroize::{Zeroize as _, ZeroizeOnDrop};

use crate::home::Home;

/// The exact byte length of a persisted ed25519 seed. An `identity.key` of any other length is corrupt or
/// foreign: reading it fails closed and [`write`] never mints a fresh key over it.
const KEY_LEN: usize = 32;

/// The DEFAULT lifetime a signet-signed, STORED device membership badge stands before it must be
/// re-minted, applied by `swoosh mint` only when the operator passes no `--expires`. A default, not a
/// hardcoded law: the CLI threads an explicit window straight into [`sign_device_badge`], and falls back
/// to this value when none is given.
///
/// A stored badge is a longer-lived bearer credential than the 5-minute self-sign a signet holder mints
/// per dial, so it must carry a FINITE lifetime, not "forever" -- a lost, un-denylisted device then ages
/// out on its own even absent an explicit revoke. Offline there is no control plane to split the authkey's
/// leak-window from the badge lifetime, so this value IS the worst-case leak window for a mint that is
/// never revoked. 90 days is the chosen default: a real re-mint cadence (about quarterly) a homelab owner
/// can absorb, and a 90-day backstop instead of a year, matching the auth-key default operators expect. A
/// longer window (up to a year via `swoosh mint --expires 365d`, for a controlled reused-secret case such
/// as qat) stays reachable, but is now a conscious opt-in rather than the silent, only value. Revocation
/// stays the primary, immediate control (the `FileDenylist`, offline + live); the TTL is the backstop for
/// a leak never noticed.
///
/// 90d is the ratified default pending final founder confirm.
pub(crate) const DEVICE_BADGE_TTL: core::time::Duration =
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
        Ok(badge.to_string())
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
    /// window: `swoosh mint` passes an explicit `--expires`, or falls back to [`DEVICE_BADGE_TTL`], so
    /// the lifetime is a default the CLI applies, not a constant buried in this signer. The signet secret
    /// stays in this wrapper: only the signed public badge (a `sheer:` link) leaves.
    pub fn sign_device_badge(
        &self,
        device: NodeId,
        ttl: core::time::Duration,
    ) -> eyre::Result<String> {
        let badge = self
            .cap_identity()?
            .mint_member(device.verify_key(), nauthy::Request::expires_in(ttl))?
            .seal()?
            .link()?;
        Ok(badge.to_string())
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
/// be found again, so they are [`Ephemeral`](Self::Ephemeral). An explicit home (`--home`/`SWOOSH_HOME`)
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

/// Resolve the secret a verb binds under from its home, honoring an explicit home before the verb's
/// [`Identity`].
///
/// The key is always `<home>/identity.key`. An explicit home (`--home`/`SWOOSH_HOME`, see
/// [`Home::is_explicit`]) pins the identity: load it, creating and saving one if it does not exist yet,
/// whatever the verb's intent. With the DEFAULT home, [`Persisted`](Identity::Persisted) loads-or-creates
/// the key and [`Ephemeral`](Identity::Ephemeral) mints a random key that never touches disk.
pub async fn resolve(intent: Identity, home: &Home) -> eyre::Result<Secret> {
    let key = home.identity_key();
    match (home.is_explicit(), intent) {
        // An explicit home pins the identity (load-or-create) even for a reach-outward verb, the override
        // the retired explicit `--key` carried; `Persisted` always loads-or-creates too.
        (true, _) | (_, Identity::Persisted) => load_or_create(&key).await,
        (false, Identity::Ephemeral) => Ok(Secret::ephemeral()),
        // Load the persisted key only if it already exists; never create it. So a provisioned operator's
        // outward dial roots at their own key (their self-badge admits at their gated node) while a fresh
        // install dials out ephemerally, with nothing written to disk.
        (false, Identity::PersistedIfPresent) => match load_existing(&key).await? {
            Some(secret) => Ok(secret),
            None => Ok(Secret::ephemeral()),
        },
    }
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
    write_atomic(path, &secret.0).await?;
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
/// This is how [`adopt`](crate::commands::adopt) provisions the device identity a later `serve` binds: it
/// MUST land in the same store [`resolve`] reads, so the node comes up AS the adopted device. (Writing
/// tightbeam's separate store instead was the qat identity-mismatch bug: `serve` bound swoosh's own key,
/// never the adopted one, so the exposed node had a different id than the contact pointed at.)
///
/// The write is ATOMIC (a unique temp sibling in the same directory, then one rename over the target), so
/// a crash or a failed write can never truncate the key: the old file stays intact until the rename lands.
pub async fn write(seed: &[u8; 32], home: &Home) -> eyre::Result<()> {
    write_atomic(&home.identity_key(), seed).await
}

/// The atomic write behind [`write`]: create the store dir 0700, write the seed to a temp sibling opened
/// 0600 (so the rename carries owner-only onto the target), then rename it over `path`. A failed write or
/// rename removes the temp best-effort, leaving the previous key untouched and no litter behind.
async fn write_atomic(path: &Path, seed: &[u8; 32]) -> eyre::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if let Some(parent) = path.parent() {
        crate::config::create_store_dir(parent)?;
    }
    let tmp = temp_path(path);
    // A fresh temp sibling: the pid separates processes and an atomic sequence separates writes within
    // one, so two writers can never share one temp path and truncate each other's in-flight seed.
    let written = async {
        let mut options = tokio::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&tmp).await?;
        file.write_all(seed).await?;
        file.flush().await?;
        file.sync_all().await
    }
    .await;
    if let Err(error) = written {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(error.into());
    }
    if let Err(error) = tokio::fs::rename(&tmp, path).await {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(error.into());
    }
    Ok(())
}

/// A temp sibling unique to ONE write: the key path plus `.tmp.<pid>.<seq>`. The pid separates processes
/// and an atomic sequence separates writes within one, so two writers can never share one temp path.
fn temp_path(path: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{seq}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
#[path = "identity_tests.rs"]
mod identity_tests;
