//! Reading and writing swoosh's trust files: the signet it gates on, the membership badge it presents, and
//! the revocation denylist.
//!
//! The paths themselves live on [`Home`](crate::home::Home) (every node file is a function of the one home
//! dir); this module owns the IO over them, and the PRIVATE posture that IO asserts: a trust file is
//! created owner-only (`0600`) in an owner-only (`0700`) store dir, so a co-tenant local user cannot read
//! this node's trust graph. All three files move as one unit when the home moves, since they all hang off
//! the same [`Home`].

use core::sync::atomic::{AtomicU64, Ordering};
use std::path::{Path, PathBuf};

use bifrost::NodeId;
use eyre::WrapErr as _;
use nauthy::Link;
use tightbeam::identity::AsVerifyKey as _;

use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::standing::{Disagreement, damaged_line};

/// Load this node's signet: the [`NodeId`] it was provisioned to trust, or `None` if it was never
/// provisioned. The file is a single public node id; an absent file means this machine trusts no root,
/// and `serve`'s gate then admits no member at all. A file that is not exactly one usable key refuses with
/// the damaged-home line [`Standing`](crate::standing::Standing) reads it as, naming the file.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_signet(home: &Home) -> eyre::Result<Option<NodeId>> {
    match crate::home::read_trust_file_async(&home.root_pub()).await {
        Ok(text) => text.trim().parse::<NodeId>().map(Some).map_err(|_| {
            eyre::eyre!(
                "{}",
                damaged_line(&Disagreement::UnreadablePin {
                    path: home.root_pub()
                })
            )
        }),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Whether this home has revoked `root`: the question a verb asks before it follows a key it did not
/// sign itself, read from the same `revoked` the `serve` gate refuses every cap rooted there on. Fails
/// closed: a file that cannot be read, or that lost entries it once held, is an error, never "nothing is
/// revoked".
pub fn is_revoked(home: &Home, root: NodeId) -> eyre::Result<bool> {
    let revoked = crate::revoked::open(home)?;
    Ok(revoked.is_revoked_key(&root.verify_key()?))
}

/// Write this node's signet: the public [`NodeId`] its default gate will trust, as `join` sets it from an
/// invite. Overwrites any prior signet (re-provisioning re-trusts), creating the store dir. Written
/// `0600` beside the secret identity: the signet roots this node's whole trust decision (whose devices it
/// admits), so it must not be world-readable to a local user who could read or (worse) rewrite it.
///
/// Atomic and durable ([`write_private_atomic`]): a running `serve` reads the pin live and fails closed
/// on a body that is not exactly one key, so a truncating write would drop every member for the length
/// of the write, and the pin is the commit point every write ordered before it relies on.
pub fn write_signet(home_lock: &HomeWrite, home: &Home, signet: NodeId) -> std::io::Result<()> {
    write_private_atomic(
        home_lock,
        &home.root_pub(),
        format!("{signet}\n").as_bytes(),
    )
}

/// Load this device's stored membership badge: the signet-signed, device-bound link it presents
/// on connect, or `None` if none was stored: a machine that is no root's device presents no badge.
/// Mirrors [`load_signet`].
///
/// The text becomes a [`Link`] HERE, at the one place it leaves the disk, so every consumer downstream
/// holds a credential that already decoded and verified against its embedded root. A file that holds
/// something else fails closed with the fix named, rather than travelling the reach path as a badge the
/// far gate will refuse without ever saying why.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub async fn load_badge(home: &Home) -> eyre::Result<Option<Link>> {
    let path = home.key_cert();
    match tokio::fs::read_to_string(&path).await {
        Ok(text) => {
            let badge = text.trim();
            if badge.is_empty() {
                return Ok(None);
            }
            let badge = badge.parse::<Link>().wrap_err_with(|| {
                format!(
                    "the stored device record {} is not a usable link: run swoosh leave to \
                     start over",
                    EscapedPath(&path),
                )
            })?;
            Ok(Some(badge))
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

/// Write this device's membership badge: the signet-signed, device-bound link it presents on
/// connect, as `join` stores it from an invite. Overwrites any prior badge (re-provisioning
/// re-badges), creating the store dir. It lands beside the identity, mirroring [`write_signet`], and is
/// written `0600`: though the signet already signed it (it carries no secret), it is a device-bound
/// membership credential and this store is owner-only throughout, so it is not left world-readable either.
///
/// Takes the [`Link`] [`load_badge`] returns, so the store speaks one type in both directions and only a
/// badge that has decoded and verified against its root can ever reach the disk.
///
/// Atomic and durable ([`write_private_atomic`]), like the pin it is ordered before: a torn badge reads as
/// a damaged home.
pub fn write_badge(home_lock: &HomeWrite, home: &Home, badge: &Link) -> std::io::Result<()> {
    write_private_atomic(home_lock, &home.key_cert(), format!("{badge}\n").as_bytes())
}

/// Create swoosh's store directory owner-only (`0700`) on Unix, recursively, if it does not already exist.
///
/// The store holds the secret identity, the signet, the badge, and the denylist, so it must never be
/// group/world-traversable. Mirrors the mint-log's dir-create ([`Grants::append`](crate::grants::Grants)):
/// create-with-mode tightens only a dir WE make and is a no-op on an existing one, so an already-provisioned
/// store another verb (or the user) made is left as they set it, never chmod'd out from under them.
pub fn create_store_dir(dir: &Path) -> std::io::Result<()> {
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

/// Write `contents` to `path` owner-only, through a unique temp sibling renamed over the target: the one
/// way every file in the home is written, under `home.lock` (`_home_lock`).
///
/// The key file store ([`keystore`]) and nauthy's stores write their own files the same way. Each file is
/// read by a later run and is unrecoverable if it is torn, so the bytes are durable (`sync_all`) before the
/// rename makes them visible, and the temp is opened `create_new` at mode `0600` so the file is never
/// world-readable for an instant and the rename carries that mode onto the target. The directory is synced
/// after the rename, so the new name is durable too: a write ordered before the pin is on disk before the
/// pin is. A failed write or rename removes the temp, leaving the previous contents intact and no litter
/// behind. Synchronous: a write is a few milliseconds of local disk, and it never waits on another process.
///
/// # Errors
///
/// The directory could not be made, or the temp could not be written, synced or renamed.
pub fn write_private_atomic(
    _home_lock: &HomeWrite,
    path: &Path,
    contents: &[u8],
) -> std::io::Result<()> {
    use std::io::Write as _;
    #[cfg(unix)]
    use std::os::unix::fs::OpenOptionsExt as _;

    if let Some(parent) = path.parent() {
        create_store_dir(parent)?;
    }
    let temp = temp_path(path);
    let written = (|| {
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        options.mode(0o600);
        let mut file = options.open(&temp)?;
        file.write_all(contents)?;
        file.sync_all()?;
        synced(Synced::File);
        Ok::<(), std::io::Error>(())
    })();
    if let Err(error) = written {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    if let Err(error) = std::fs::rename(&temp, path) {
        let _ = std::fs::remove_file(&temp);
        return Err(error);
    }
    if let Some(parent) = path.parent() {
        std::fs::File::open(parent)?.sync_all()?;
        synced(Synced::Dir);
    }
    Ok(())
}

/// What [`write_private_atomic`] made durable: the file's bytes, or the directory entry that names it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Synced {
    /// The temp file's bytes, before the rename.
    File,
    /// The parent directory, after the rename.
    Dir,
}

#[cfg(test)]
thread_local! {
    /// Every sync [`write_private_atomic`] made on this thread, in order, for a test to count.
    static SYNCS: core::cell::RefCell<Vec<Synced>> = const { core::cell::RefCell::new(Vec::new()) };
}

/// Record a sync for a test to count. Nothing outside tests.
fn synced(what: Synced) {
    #[cfg(test)]
    SYNCS.with_borrow_mut(|syncs| syncs.push(what));
    #[cfg(not(test))]
    let _ = what;
}

/// A temp sibling unique to ONE write: the target name plus `.tmp.<pid>.<seq>`. The pid separates
/// processes and an atomic sequence separates writes within one, so two writers can never share a temp
/// path and truncate each other's in-flight bytes.
fn temp_path(path: &Path) -> PathBuf {
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let seq = SEQ.fetch_add(1, Ordering::Relaxed);
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(format!(".tmp.{}.{seq}", std::process::id()));
    path.with_file_name(name)
}

#[cfg(test)]
#[path = "config_tests.rs"]
mod config_tests;
