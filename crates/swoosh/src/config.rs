//! Reading and writing swoosh's trust files: the signet it gates on, the membership badge it presents, and
//! the revocation denylist.
//!
//! The paths themselves live on [`Home`](crate::home::Home) (every node file is a function of the one home
//! dir); this module owns the IO over them, and the PRIVATE posture that IO asserts: a trust file is
//! created owner-only (`0600`) in an owner-only (`0700`) store dir, so a co-tenant local user cannot read
//! this node's trust graph. All three files move as one unit when the home moves, since they all hang off
//! the same [`Home`].

use std::path::Path;

use bifrost::NodeId;

use crate::home::Home;

/// Load this node's signet: the [`NodeId`] it was provisioned to trust, or `None` if it was never
/// provisioned. The file is a single public node id; an absent file means unprovisioned, which `serve`
/// treats as "gate on this node's OWN key" (person-zero self-trusts: it admits itself and its devices,
/// refuses strangers), never a silent open.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_signet(home: &Home) -> eyre::Result<Option<NodeId>> {
    match tokio::fs::read_to_string(home.signet()).await {
        Ok(text) => Ok(Some(text.trim().parse::<NodeId>()?)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this node's signet: the public [`NodeId`] its default gate will trust, as `adopt` sets it from an
/// authkey. Overwrites any prior signet (re-provisioning re-trusts), creating the store dir. Written
/// `0600` beside the secret identity: the signet roots this node's whole trust decision (whose devices it
/// admits), so it must not be world-readable to a local user who could read or (worse) rewrite it.
pub async fn write_signet(home: &Home, signet: NodeId) -> eyre::Result<()> {
    write_private(&home.signet(), format!("{signet}\n").as_bytes()).await
}

/// Load this device's stored membership badge: the signet-signed, device-bound `sheer:` link it presents
/// on connect, or `None` if none was stored. An absent file means the node was provisioned without a badge
/// (a legacy two-field authkey) or is the signet holder itself (person-zero), either of which falls back to
/// self-signing. Mirrors [`load_signet`].
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_badge(home: &Home) -> eyre::Result<Option<String>> {
    match tokio::fs::read_to_string(home.badge()).await {
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
/// re-badges), creating the store dir. It lands beside the identity, mirroring [`write_signet`], and is
/// written `0600`: though the signet already signed it (it carries no secret), it is a device-bound
/// membership credential and this store is owner-only throughout, so it is not left world-readable either.
pub async fn write_badge(home: &Home, badge: &str) -> eyre::Result<()> {
    write_private(&home.badge(), format!("{badge}\n").as_bytes()).await
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
