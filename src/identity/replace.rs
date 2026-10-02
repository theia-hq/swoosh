//! Replacing this machine's key with a fresh random one, keeping the old key and its links aside.
//!
//! The caller holds `serve.lock` ([`ServeLock`](crate::home::ServeLock)), so no node serves as the key
//! being replaced, and `home.lock` when it puts the new key in place. The new key is written whole beside the old one first; the old one
//! is then linked to its kept name and the new one renamed over it, so a crash at any step leaves either
//! the old key or the new one at `<home>/machine/key`, never neither.

use std::io;
use std::path::{Path, PathBuf};

use bifrost::NodeId;
use keystore::{KeyFile, Protection, Stored};

use crate::home::Home;
use crate::passphrase::Prompt;

/// What [`NewKey::put`] did.
#[derive(Debug)]
pub struct Replaced {
    /// The new key.
    pub key: NodeId,
    /// Where the old key was kept, when there was one.
    pub kept: Option<PathBuf>,
    /// Where the old key's links were kept, when there were any.
    pub links_kept: Option<PathBuf>,
}

/// The refusal when the new key is to be locked and nobody is at a terminal to choose its passphrase.
pub const CHOOSE_NEEDS_TERMINAL: &str = "the new key is locked like the old one, and choosing its passphrase needs a terminal: run this at one.";

/// A fresh random key written whole at `<home>/machine/key.new`, not yet in place. Staging runs every step that
/// can ask or fail, so a caller stages first, makes its own writes, then [`put`](Self::put)s it. Dropped
/// unput, the staged file is removed.
#[derive(Debug)]
#[must_use = "the key is staged, not replaced, until it is put"]
pub struct NewKey {
    /// The new key.
    key: NodeId,
    /// Whether the home had a key to keep aside.
    had_old: bool,
    /// `<home>/machine/key.new`.
    staged: PathBuf,
    /// Whether it was put, so the drop leaves it.
    put: bool,
}

impl NewKey {
    /// Choose the new passphrase if the old key was locked, and write the new key at
    /// `<home>/machine/key.new`.
    pub fn stage(home: &Home, prompt: &mut impl Prompt) -> eyre::Result<Self> {
        let path = home.key();
        let old = KeyFile::device(&path).load()?;
        let locked = matches!(old, Some(Stored::Locked(_)));
        if locked && !prompt.terminal() {
            eyre::bail!("{CHOOSE_NEEDS_TERMINAL}");
        }
        let passphrase = if locked {
            Some(crate::passphrase::choose(
                prompt,
                crate::passphrase::Asked::MachineKey,
            )?)
        } else {
            None
        };
        let protection = passphrase
            .as_ref()
            .map_or(Protection::Plain, Protection::Passphrase);
        let secret = keystore::Secret::generate()?;
        super::make_machine_dir(home)?;
        let staged = home.machine().join("key.new");
        remove(&staged)?;
        let new = Self {
            key: secret.with_bytes(NodeId::from_ed25519_secret),
            had_old: old.is_some(),
            staged,
            put: false,
        };
        KeyFile::device(&new.staged).write(&secret, protection)?;
        Ok(new)
    }

    /// Put the staged key in place, keeping the old key as `machine/key.replaced-<day>[-n]` and `links` as
    /// `links.replaced-<day>[-n]` with the first `n` free for both. `day` is today, as `YYYY-MM-DD`. The
    /// old key stays in `machine/`, which system backups leave out, as a key's every copy here does.
    pub fn put(
        mut self,
        _home_lock: &crate::home::HomeWrite,
        home: &Home,
        day: &str,
    ) -> eyre::Result<Replaced> {
        let path = home.key();
        let (kept, links_kept) = free_names(home, day);
        let kept = if self.had_old {
            std::fs::hard_link(&path, &kept)?;
            Some(kept)
        } else {
            None
        };
        std::fs::rename(&self.staged, &path)?;
        self.put = true;
        let links_kept = if home.links().exists() {
            std::fs::rename(home.links(), &links_kept)?;
            Some(links_kept)
        } else {
            None
        };
        std::fs::File::open(home.machine())?.sync_all()?;
        std::fs::File::open(home.dir())?.sync_all()?;
        Ok(Replaced {
            key: self.key,
            kept,
            links_kept,
        })
    }
}

impl Drop for NewKey {
    fn drop(&mut self) {
        if !self.put {
            let _ = remove(&self.staged);
        }
    }
}

/// The first `key.replaced-<day>[-n]` and `links.replaced-<day>[-n]` pair with neither name taken.
fn free_names(home: &Home, day: &str) -> (PathBuf, PathBuf) {
    let at = |n: u32| {
        let suffix = if n == 0 {
            day.to_owned()
        } else {
            format!("{day}-{n}")
        };
        (
            home.machine().join(format!("key.replaced-{suffix}")),
            home.dir().join(format!("links.replaced-{suffix}")),
        )
    };
    let mut n = 0;
    loop {
        let (key, links) = at(n);
        if !key.exists() && !links.exists() {
            return (key, links);
        }
        n += 1;
    }
}

/// Remove a file. Already gone is done.
// `core::io::ErrorKind` is still unstable, so the kind reads from `std`.
#[allow(clippy::std_instead_of_core)]
pub(super) fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}
