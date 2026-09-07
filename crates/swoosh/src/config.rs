//! Where swoosh keeps its trust files: the signet it gates on and the revocation denylist.
//!
//! These live beside swoosh's identity, dir-derived from `--key` exactly as [`contacts`](crate::contacts)
//! is: a pinned `--key` moves the whole identity+trust unit (identity.key + contacts.toml + signet +
//! revoked) as one, so `swoosh adopt --key /custom` and `swoosh serve --key /custom` read and write
//! the SAME dir. Without `--key` the default `~/.config/swoosh/` applies. swoosh owns these outright: it
//! never reaches into tightbeam's config, so the store dir is a function of swoosh's own `--key`.

use std::path::{Path, PathBuf};

use bifrost::NodeId;
use eyre::eyre;

/// The swoosh config directory: beside an explicit `--key`, else the default `~/.config/swoosh`.
///
/// Mirrors [`contacts_path`](crate::contacts::default_path)'s convention so one `--key` moves the whole
/// identity+trust unit together.
fn config_dir(key: Option<&Path>) -> eyre::Result<PathBuf> {
    match key.and_then(Path::parent) {
        Some(dir) => Ok(dir.to_path_buf()),
        None => {
            let home =
                std::env::var_os("HOME").ok_or_else(|| eyre!("HOME is not set; pass --key"))?;
            Ok(PathBuf::from(home).join(".config").join("swoosh"))
        }
    }
}

/// The persisted signet location, `<config-dir>/signet`. Holds one thing: the public [`NodeId`] of the
/// signet this node trusts, written once by provisioning (`swoosh adopt`). Public material (a key you
/// already share), so it sits beside the secret identity, never inside it.
pub fn signet_path(key: Option<&Path>) -> eyre::Result<PathBuf> {
    Ok(config_dir(key)?.join("signet"))
}

/// The persisted revocation-denylist location, `<config-dir>/revoked`. Records the biscuit revocation ids
/// of caps this node has revoked, which the next `swoosh serve` reads.
pub fn revoked_path(key: Option<&Path>) -> eyre::Result<PathBuf> {
    Ok(config_dir(key)?.join("revoked"))
}

/// The persisted mint-log ledger location, `<config-dir>/grants`. Records one line per grant this node has
/// issued (service, kind, holder, root revocation id, expiry), the issuer-side index that makes revoke-by-
/// holder and `grant ls` possible. A who-can-reach-what record, so [`Grants`](crate::grants::Grants) writes
/// it `0600`; the expose gate never reads it (issuer-side audit and revoke only).
pub fn grants_path(key: Option<&Path>) -> eyre::Result<PathBuf> {
    Ok(config_dir(key)?.join("grants"))
}

/// The persisted membership-badge location, `<config-dir>/badge`. Holds one thing: the signet-signed,
/// device-bound membership badge (a `sheer:` link) this device presents on connect, written once by
/// provisioning (`swoosh adopt`) from the authkey's badge field. Public material (the signet already
/// signed it and it carries no secret), so it sits beside the secret identity, never inside it.
pub fn badge_path(key: Option<&Path>) -> eyre::Result<PathBuf> {
    Ok(config_dir(key)?.join("badge"))
}

/// Load this node's signet: the [`NodeId`] it was provisioned to trust, or `None` if it was never
/// provisioned. The file is a single public node id; an absent file means unprovisioned, which `serve`
/// treats as "gate on this node's OWN key" (person-zero self-trusts: it admits itself and its devices,
/// refuses strangers), never a silent open.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_signet(key: Option<&Path>) -> eyre::Result<Option<NodeId>> {
    match tokio::fs::read_to_string(signet_path(key)?).await {
        Ok(text) => Ok(Some(text.trim().parse::<NodeId>()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this node's signet: the public [`NodeId`] its default gate will trust, as `adopt` sets it from an
/// authkey. Overwrites any prior signet (re-provisioning re-trusts), creating the config dir. Written
/// `0600` beside the secret identity: the signet roots this node's whole trust decision (whose devices it
/// admits), so it must not be world-readable to a local user who could read or (worse) rewrite it.
pub async fn write_signet(key: Option<&Path>, signet: NodeId) -> eyre::Result<()> {
    write_private(&signet_path(key)?, format!("{signet}\n").as_bytes()).await
}

/// Load this device's stored membership badge: the signet-signed, device-bound `sheer:` link it presents
/// on connect, or `None` if none was stored. An absent file means the node was provisioned without a badge
/// (a legacy two-field authkey) or is the signet holder itself (person-zero), either of which falls back to
/// self-signing. Mirrors [`load_signet`].
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_badge(key: Option<&Path>) -> eyre::Result<Option<String>> {
    match tokio::fs::read_to_string(badge_path(key)?).await {
        Ok(text) => {
            let badge = text.trim();
            Ok((!badge.is_empty()).then(|| badge.to_owned()))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this device's membership badge: the signet-signed, device-bound `sheer:` link it presents on
/// connect, as `adopt` stores it from an authkey's badge field. Overwrites any prior badge (re-provisioning
/// re-badges), creating the config dir. It lands beside the identity, mirroring [`write_signet`], and is
/// written `0600`: though the signet already signed it (it carries no secret), it is a device-bound
/// membership credential and this store is owner-only throughout, so it is not left world-readable either.
pub async fn write_badge(key: Option<&Path>, badge: &str) -> eyre::Result<()> {
    write_private(&badge_path(key)?, format!("{badge}\n").as_bytes()).await
}

/// Create swoosh's store directory owner-only (`0700`) on Unix, recursively, if it does not already exist.
///
/// The store holds the secret identity, the signet, the badge, and the denylist, so it must never be
/// group/world-traversable. Mirrors the mint-log's dir-create ([`Grants::append`](crate::grants::Grants)):
/// create-with-mode tightens only a dir WE make and is a no-op on an existing one, so an already-provisioned
/// store another verb (or the user) made is left as they set it, never chmod'd out from under them.
pub(crate) fn create_store_dir(dir: &Path) -> std::io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;

        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
    }
    #[cfg(not(unix))]
    {
        std::fs::create_dir_all(dir)
    }
}

/// Write `contents` to `path` as an owner-only (`0600` on Unix) file, creating the store dir `0700` first.
///
/// The trust files beside the identity (the signet, the badge) are as sensitive as the store they live in,
/// so this asserts the private posture on every write: the dir is created `0700`, and the file is created
/// `0600` AND reasserted `0600` even when it already existed (create's mode fires only on first creation),
/// so a file loosened after an earlier write is retightened. Truncates any prior contents. Non-Unix has no
/// mode bits; the write still creates the dir and replaces the file.
async fn write_private(path: &Path, contents: &[u8]) -> eyre::Result<()> {
    use tokio::io::AsyncWriteExt as _;

    if let Some(parent) = path.parent() {
        create_store_dir(parent)?;
    }
    let mut options = tokio::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    // tokio's `OpenOptions` carries the `mode` setter inherently under the `fs` feature (as the mint-log
    // does), so no `OpenOptionsExt` import is needed.
    #[cfg(unix)]
    options.mode(0o600);
    let mut file = options.open(path).await?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;

        // Reassert 0600 on a pre-existing file (create's mode fired only on first creation).
        file.set_permissions(std::fs::Permissions::from_mode(0o600))
            .await?;
    }
    file.write_all(contents).await?;
    file.flush().await?;
    Ok(())
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
