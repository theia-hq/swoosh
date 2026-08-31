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

/// The persisted membership-badge location, `<config-dir>/badge`. Holds one thing: the signet-signed,
/// device-bound membership badge (a `sheer:` link) this device presents on connect, written once by
/// provisioning (`swoosh adopt`) from the authkey's badge field. Public material (the signet already
/// signed it and it carries no secret), so it sits beside the secret identity, never inside it.
pub fn badge_path(key: Option<&Path>) -> eyre::Result<PathBuf> {
    Ok(config_dir(key)?.join("badge"))
}

/// Load this node's signet: the [`NodeId`] it was provisioned to trust, or `None` if it was never
/// provisioned. The file is a single public node id; an absent file means unprovisioned, which `expose`
/// treats as "no default gate" (a loud error), never a silent open.
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
/// authkey. Overwrites any prior signet (re-provisioning re-trusts), creating the config dir.
pub async fn write_signet(key: Option<&Path>, signet: NodeId) -> eyre::Result<()> {
    let path = signet_path(key)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, format!("{signet}\n")).await?;
    Ok(())
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
/// re-badges), creating the config dir. Public material (the signet already signed it, it carries no
/// secret), so it lands beside the identity, mirroring [`write_signet`].
pub async fn write_badge(key: Option<&Path>, badge: &str) -> eyre::Result<()> {
    let path = badge_path(key)?;
    if let Some(parent) = path.parent() {
        tokio::fs::create_dir_all(parent).await?;
    }
    tokio::fs::write(&path, format!("{badge}\n")).await?;
    Ok(())
}
