//! `root lock [touch-id] [<dir>] [--remove]`: change your root's passphrase, or add or remove its `touch-id`
//! lock, on this machine or in a copy.
//!
//! Only `root.key` is rewritten, through the key store's lock change: opened with the current passphrase,
//! wrapped under the new lock, read back through the new lock, and renamed over the old. The key stays the
//! same, nothing is signed and nothing is synced, so `devices` is untouched. Other copies keep their locks.
//! A passphrase change is one prompt event: the current passphrase, then the new one twice. Adding `touch-id`
//! is the current passphrase, then one touch to prove the new lock opens. Every change opens with the
//! passphrase, never a touch: the key store sets a root's passphrase only through its passphrase, and setting
//! `touch-id` again is how a lock that stopped opening is mended.

use std::path::{Path, PathBuf};

use keystore::{KeyFile, Method, NewLock, Passphrase, Unlock};
use tightbeam::identity::AsVerifyKey as _;

use super::{KEY_FILE, RootError, header_key, read_header};
use crate::escape::EscapedPath;
use crate::home::{Home, HomeWrite};
use crate::passphrase::{Asked, Prompt};
use crate::standing::Standing;
use crate::touch::{self, Then, Touch, TouchAct, TouchHere};

/// Why the root's locks were not changed.
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
    /// The passphrase could not be asked for or did not open the root, or a touch could not be asked for or
    /// did not open it.
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
) -> Result<Relocked, RootLockError> {
    let target = Target::find(home, dir).await?;
    if !prompt.terminal() {
        return Err(RootError::NoTerminalToUnlock.into());
    }
    let current = target.prove(prompt)?;
    let new = crate::passphrase::choose(prompt, target.asked).map_err(prompt_error)?;
    let _home_lock = target.home_lock(home).await?;
    KeyFile::root(&target.path)
        .add_lock(
            Some(Unlock::Passphrase(&current)),
            NewLock::Passphrase(&new),
        )
        .map_err(RootError::from)?;
    Ok(target.relocked())
}

/// Add a `touch-id` lock beside the passphrase of the root kept here or of the copy in `dir`, or set it again,
/// or with `remove` take it off. Added only at this Mac's own screen, after the line that says what a new
/// fingerprint does to it; opened with the passphrase, then proven by one touch, bounded.
///
/// # Errors
///
/// As [`lock`], and: a touch cannot be asked for here, or the touch did not open the new lock.
pub async fn lock_touch_id(
    home: &Home,
    dir: Option<&Path>,
    remove: bool,
    prompt: &mut impl Prompt,
) -> Result<(Relocked, TouchIdChange), RootLockError> {
    let target = Target::find(home, dir).await?;
    let holds = target
        .locked
        .methods()
        .any(|method| method == Method::TouchId);
    if remove && !holds {
        return Ok((target.relocked(), TouchIdChange::NoTouchId));
    }
    if !remove {
        let here = prompt.touch_here();
        if here != TouchHere::Here {
            let command = match target.dir {
                Some(dir) => format!("swoosh root lock touch-id {}", EscapedPath(dir)),
                None => "swoosh root lock touch-id".to_owned(),
            };
            return Err(RootLockError::Prompt(touch::set_elsewhere(here, &command)));
        }
    }
    if !prompt.terminal() {
        return Err(RootError::NoTerminalToUnlock.into());
    }
    let file = KeyFile::root(&target.path);
    let lines = touch::Lines::of(target.asked, &file, true);
    if !remove {
        prompt.warn(touch::ROOT_BESIDE_PASSPHRASE);
        if target.dir.is_none() && machine_key_opens_by_touch(home) {
            prompt.warn(touch::SHARED_FINGER);
        }
        // Setting a lock that does not open here again says first to check for a fingerprint nobody added:
        // the new lock opens under every finger enrolled now.
        if holds && prompt.health(&target.locked) == Some(keystore::Health::Dead) {
            prompt.warn(&lines.warning());
        }
    }
    let current = target.prove(prompt)?;
    let _home_lock = target.home_lock(home).await?;
    if remove {
        file.remove_lock(Unlock::Passphrase(&current), Method::TouchId)
            .map_err(RootError::from)?;
        return Ok((target.relocked(), TouchIdChange::Removed));
    }
    prompt.say(&lines.checking());
    let touch = Touch {
        file,
        reason: touch::CHECK_ROOT,
        act: TouchAct::BesidePassphrase {
            current,
            then: Then::Keep,
        },
    };
    touch::changed(prompt.touch(touch), &lines).map_err(prompt_error)?;
    Ok((target.relocked(), TouchIdChange::Added))
}

/// What [`lock_touch_id`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TouchIdChange {
    /// The root opens with `touch-id` on this Mac now, beside its passphrase.
    Added,
    /// Its `touch-id` lock was taken off; the passphrase opens it.
    Removed,
    /// `--remove` on a root with no `touch-id` lock: nothing to do.
    NoTouchId,
}

/// The root a lock change is on: its key file, read to its header, checked against the root this machine
/// trusts.
struct Target<'a> {
    /// The copy's directory, `None` for the root kept here (a `<dir>` that is the home included).
    dir: Option<&'a Path>,
    path: PathBuf,
    asked: Asked<'a>,
    locked: keystore::Locked,
}

impl<'a> Target<'a> {
    /// The root kept here, or the copy in `dir`, with every check a change makes before it asks anything.
    async fn find(home: &Home, dir: Option<&'a Path>) -> Result<Self, RootLockError> {
        // A `<dir>` that is the home itself names the root kept here, and is changed as that one is: under
        // `home.lock`.
        let dir = dir.filter(|dir| !is_home(dir, home));
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
        Ok(Self {
            dir,
            path,
            asked,
            locked,
        })
    }

    /// Prove the root's passphrase, asking up to three times, and hand it back for the change.
    fn prove(&self, prompt: &mut impl Prompt) -> Result<Passphrase, RootLockError> {
        let ((), current) = crate::passphrase::unlock(prompt, self.asked, |passphrase| {
            self.locked.unlock(Unlock::Passphrase(passphrase)).map(drop)
        })
        .map_err(prompt_error)?;
        Ok(current)
    }

    /// `home.lock` for the root kept here, the one file of the home a change rewrites; none for a copy.
    async fn home_lock(&self, home: &Home) -> Result<Option<HomeWrite>, RootLockError> {
        Ok(match self.dir {
            None => Some(HomeWrite::take(home).await.map_err(RootError::from)?),
            Some(_) => None,
        })
    }

    const fn relocked(&self) -> Relocked {
        match self.dir {
            None => Relocked::Here,
            Some(_) => Relocked::Copy,
        }
    }
}

/// A prompt's failure, or a touch's, as the one line it reads as.
fn prompt_error(report: eyre::Report) -> RootLockError {
    RootLockError::Prompt(format!("{report:#}"))
}

/// Whether this machine's key has a `touch-id` lock, read from its header.
fn machine_key_opens_by_touch(home: &Home) -> bool {
    matches!(
        KeyFile::device(home.key()).load(),
        Ok(Some(keystore::Stored::Locked(key)))
            if key.methods().any(|method| method == Method::TouchId)
    )
}

/// Where [`lock`] or [`lock_touch_id`] changed the root.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Relocked {
    /// The root kept on this machine (a `<dir>` that is the home included).
    Here,
    /// The copy in the `<dir>` named.
    Copy,
}

/// Whether `dir`, resolved, is the home's own directory.
fn is_home(dir: &Path, home: &Home) -> bool {
    match (
        std::fs::canonicalize(dir),
        std::fs::canonicalize(home.dir()),
    ) {
        (Ok(dir), Ok(home)) => dir == home,
        _ => false,
    }
}
