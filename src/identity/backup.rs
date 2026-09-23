//! `export` and `restore`: a sealed copy of the home's key, and putting one back.
//!
//! A backup is always sealed under a passphrase, whatever protects the key at home: a plain copy on a
//! USB stick is the identity handed to whoever finds it, and a restore from one would quietly drop the
//! protection the home had. So a backup is a sealed key file in the one format every key file uses, and
//! restoring it installs it sealed; unsealing is a separate, named act (`protect plain`).
//!
//! Both write files and only files. Nothing here prints a key, and neither verb has a way to send one to
//! a terminal or a pipe.
//!
//! A restore puts back the KEY and nothing else. The rest of the home (the signet it trusts, its badge,
//! the grants it issued, and the denylist of what it revoked) stays as it is. A restore is for a lost
//! key; a key that may have been stolen is replaced, not restored, because the thief holds the same one.

use std::path::Path;

use bifrost::NodeId;
use eyre::WrapErr as _;
use keystore::{KeyFile, Stored};

use super::key_file;
use super::lock::HomeLock;
use super::stage::{Seen, Stage, read_backup};
use crate::home::Home;
use crate::passphrase::Prompt;

/// What to do when the destination already holds a file. A typed choice rather than a flag's bool, so
/// the call site reads as the decision it is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Existing {
    /// Refuse, and leave the file exactly as it is.
    Refuse,
    /// Replace it, the caller having been told what it holds.
    Replace,
}

/// Write a sealed copy of the home's key to `to`, and return the node it is.
///
/// The backup is sealed under a passphrase of its own, chosen now; a sealed home is unlocked first, so a
/// home whose passphrase is not known cannot be exported. A file at `to`
/// is a backup that may be the only one, so it is replaced only when `existing` says so, and never when
/// it is this home's own key file.
// `core::io::ErrorKind` is still unstable, so the NotFound check reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub fn export(
    home: &Home,
    to: &Path,
    existing: Existing,
    prompt: &mut impl Prompt,
) -> eyre::Result<NodeId> {
    let file = key_file(home);
    // `-` is not a file, and a backup is only ever a file.
    if to == Path::new("-") {
        eyre::bail!("a backup is written to a file; name the file to write it to");
    }
    let occupied = match to.symlink_metadata() {
        Ok(metadata) if !metadata.is_file() => {
            eyre::bail!(
                "{} is not a regular file; a backup is written to a file",
                to.display()
            )
        }
        Ok(_) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => false,
        Err(error) => {
            return Err(error).wrap_err_with(|| format!("could not read {}", to.display()));
        }
    };
    if occupied {
        if existing == Existing::Refuse {
            eyre::bail!(
                "refusing to overwrite {}: a backup may be the only copy (pass --force to replace it)",
                to.display()
            );
        }
        if is_same_file(to, file.path()) {
            eyre::bail!(
                "{} is this home's own key file; `swoosh identity protect passphrase` seals it in place",
                to.display()
            );
        }
    }
    let Some(stored) = file.load()? else {
        eyre::bail!(
            "there is no identity at {} to export; run `swoosh identity` to create one",
            file.path().display()
        );
    };
    let secret = match stored {
        Stored::Plain(secret) => secret,
        Stored::Locked(locked) => locked.unlock(&prompt.unlock(file.path())?)?,
    };
    // The backup gets a passphrase of its own, chosen now. The medium a backup lives on is the one most
    // likely to be lost, so its passphrase must not be the one typed every day at this machine.
    let passphrase = prompt.choose(to)?;
    // Sealed and verified by the key file store on the home's own disk, then copied to where the backup
    // goes, which may be a stick with no hard links and no modes.
    let seen = Seen::of(to)?;
    let (_sealed, bytes) = Stage::seal(file.path(), &secret, &passphrase)?;
    let staged = Stage::write(to, &bytes)?;
    if occupied {
        staged.publish_over(to, seen)?;
    } else {
        staged.publish_new(to, &bytes)?;
    }
    Ok(secret.node_id())
}

/// What a restore did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Restored {
    /// The node the home now is.
    pub node: NodeId,
    /// The backup's mode, when it let others read the file. A sealed backup is restored anyway, since its
    /// passphrase is what protects it; the caller says so.
    pub loose: Option<u32>,
}

/// Replace the home's key with the one sealed in the backup at `from`.
///
/// Nothing serves this home while it runs: the home lock is taken first and held to the end, so no node
/// can be left serving a key the disk no longer names. The backup is copied beside the home key and
/// unlocked there FIRST, so a wrong passphrase or a damaged file is caught before the home is touched. The
/// home's key is then replaced only when it is absent, when it is the same node, or when `existing` says
/// so: a different key at home may be the only copy of that identity. The copy that unlocked is the file
/// put in place, so the restored key stays sealed under the backup's passphrase.
///
/// Only the key comes back. The rest of the home, the denylist of what it revoked included, is untouched.
pub fn restore(
    home: &Home,
    from: &Path,
    existing: Existing,
    prompt: &mut impl Prompt,
) -> eyre::Result<Restored> {
    let _lock = HomeLock::replacing(home)?;
    let backup = read_backup(from)?;
    let file = key_file(home);
    let staged = Stage::write(file.path(), &backup.bytes)?;
    // The copy is read at its stage, so a refusal names the backup the user gave, not the stage.
    let locked = match KeyFile::from(staged.path())
        .load()
        .wrap_err_with(|| format!("{} is not a backup this build can read", from.display()))?
    {
        Some(Stored::Locked(locked)) => locked,
        Some(Stored::Plain(_)) => eyre::bail!(
            "{} is a plain key, not a sealed backup; `swoosh identity export` writes a backup",
            from.display()
        ),
        None => eyre::bail!("there is no backup at {}", from.display()),
    };
    let passphrase = prompt.unlock(from)?;
    let incoming = match locked.unlock(&passphrase) {
        Ok(secret) => secret.node_id(),
        Err(keystore::Error::Unlock { .. }) => eyre::bail!(
            "could not unlock the backup {}: wrong passphrase, or the file is damaged",
            from.display()
        ),
        Err(error) => {
            return Err(error)
                .wrap_err_with(|| format!("could not unlock the backup {}", from.display()));
        }
    };

    let seen = Seen::of(file.path())?;
    match file.load() {
        Ok(None) => {}
        // Only a plain file's node is a fact. A sealed file's header only claims one, and anyone who can
        // write the file can make it claim this node, so a sealed home is treated as a different key.
        Ok(Some(Stored::Plain(held))) if held.node_id() == incoming => {}
        Ok(Some(Stored::Locked(held))) if held.node_id() == incoming => {
            if existing == Existing::Refuse {
                eyre::bail!(
                    "{} is sealed and claims to be {incoming}, but only its passphrase can prove that; \
                     pass --force to replace it with the backup",
                    file.path().display()
                );
            }
        }
        Ok(Some(stored)) => {
            if existing == Existing::Refuse {
                eyre::bail!(
                    "this home holds {}; restoring would replace it with {incoming}. {} may hold the \
                     only copy of that key: back it up with `swoosh identity export <path>`, then pass \
                     --force to replace it",
                    stored.node_id(),
                    file.path().display()
                );
            }
        }
        // A key file that cannot be read cannot be compared, so replacing it takes the same --force as
        // replacing a different one.
        Err(error) => {
            if existing == Existing::Refuse {
                return Err(error).wrap_err(
                    "the identity at this home cannot be read, so restoring over it needs --force",
                );
            }
        }
    }
    match seen {
        Seen::Absent => staged.publish_new(file.path(), &backup.bytes)?,
        Seen::File { .. } => staged.publish_over(file.path(), seen)?,
    }
    Ok(Restored {
        node: incoming,
        loose: backup.loose,
    })
}

/// Whether `a` and `b` name the same file. Only asked when `a` exists; a `b` that cannot be resolved
/// is not `a`.
fn is_same_file(a: &Path, b: &Path) -> bool {
    match (std::fs::canonicalize(a), std::fs::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod backup_tests;
