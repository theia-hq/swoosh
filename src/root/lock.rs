//! `root lock [<dir>]`: change your root's passphrase, on this machine or in a copy.
//!
//! Only `root.key` is rewritten, through the key store's lock change: opened with the current passphrase,
//! wrapped under the new one, read back through the new one, and renamed over the old. The key stays the
//! same, nothing is signed and nothing is synced, so `devices` is untouched. Other copies keep the old
//! passphrase. One prompt event: the current passphrase, then the new one twice.

use std::path::{Path, PathBuf};

use keystore::{KeyFile, NewLock, Unlock};
use tightbeam::identity::AsVerifyKey as _;

use super::{KEY_FILE, RootError, header_key, read_header};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::passphrase::{Asked, Prompt};
use crate::standing::Standing;

/// Why the root's passphrase was not changed.
#[derive(Debug, thiserror::Error)]
pub enum RootLockError {
    /// No `<dir>`, and this machine keeps no root and is no root's device.
    #[error("this machine holds no root; your first invite makes one: swoosh invite <name> <key>")]
    NoRoot,
    /// No `<dir>`, on a device of a root kept elsewhere.
    #[error("your root is not on this machine; to change it in a copy: swoosh root lock <dir>")]
    NotHere,
    /// `<dir>` holds no root key.
    #[error(
        "{} holds no copy of your root; make one first: swoosh root backup {}",
        EscapedPath(.dir),
        EscapedPath(.dir)
    )]
    NoCopy {
        /// The directory named.
        dir: PathBuf,
    },
    /// The passphrase could not be asked for, or did not open the root.
    #[error("{0}")]
    Prompt(String),
    /// The root, its records, or a file failed.
    #[error(transparent)]
    Root(#[from] RootError),
}

/// Change the passphrase of the root kept on this machine (`dir` `None`) or of the copy in `dir`. A copy is
/// changed on any machine, one that keeps no root included, but never one of another root than the one this
/// machine trusts.
///
/// # Errors
///
/// No root to change; the passphrase was not given or did not open it; or the rewrite failed.
pub async fn lock(
    home: &Home,
    dir: Option<&Path>,
    prompt: &mut impl Prompt,
) -> Result<(), RootLockError> {
    let standing = Standing::read(home).await.map_err(RootError::from)?;
    let (path, asked) = match (dir, standing) {
        (None, Standing::HoldsRoot { .. }) => (home.root_key(), Asked::Root),
        (None, Standing::InterruptedMint { root_key }) => {
            return Err(RootError::Unfinished { root: root_key }.into());
        }
        (None, Standing::Device { .. }) => return Err(RootLockError::NotHere),
        (None, Standing::Unpinned) => return Err(RootLockError::NoRoot),
        (Some(dir), _) => (dir.join(KEY_FILE), Asked::Copy(dir)),
    };
    if let Some(dir) = dir
        && !path.is_file()
    {
        return Err(RootLockError::NoCopy {
            dir: dir.to_path_buf(),
        });
    }
    let locked = read_header(&path)?;
    let key = header_key(&path, &locked)?;
    // A copy is held to the root this machine trusts, as every use of a copy is (`present`'s rule); and a
    // root revoked here is changed nowhere.
    let pin = match standing {
        Standing::HoldsRoot { pin, .. } | Standing::Device { pin, .. } => Some(pin),
        Standing::InterruptedMint { root_key } => Some(root_key),
        Standing::Unpinned => None,
    };
    if let Some(pin) = pin
        && pin != key
    {
        return Err(RootError::Mismatch { root: key, pin }.into());
    }
    let revoked = crate::revoked::open(home)
        .map_err(crate::standing::StandingError::Revoked)
        .map_err(RootError::from)?;
    if revoked.is_revoked_key(&key.verify_key().map_err(RootError::from)?) {
        return Err(RootError::Revoked { root: key }.into());
    }
    if !prompt.terminal() {
        return Err(RootError::NoTerminalToUnlock.into());
    }
    let prompt_error = |report: eyre::Report| RootLockError::Prompt(format!("{report:#}"));
    let ((), current) = crate::passphrase::unlock(prompt, asked, |passphrase| {
        locked.unlock(Unlock::Passphrase(passphrase)).map(drop)
    })
    .map_err(prompt_error)?;
    let new = crate::passphrase::choose(prompt, Asked::Root).map_err(prompt_error)?;
    // `home.lock` for the root kept here, the one file of the home this changes.
    let _home_lock = match dir {
        None => Some(HomeWrite::take(home).await.map_err(RootError::from)?),
        Some(_) => None,
    };
    KeyFile::root(&path)
        .add_lock(
            Some(Unlock::Passphrase(&current)),
            NewLock::Passphrase(&new),
        )
        .map_err(RootError::from)?;
    Ok(())
}
