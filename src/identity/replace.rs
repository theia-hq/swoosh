//! Replacing this machine's key with a fresh random one, keeping the old key and its links aside.
//!
//! The caller holds the home lock exclusive ([`HomeLock::new_key`](super::HomeLock::new_key)), so no node
//! serves as the key being replaced. The new key is written whole beside the old one first; the old one
//! is then linked to its kept name and the new one renamed over it, so a crash at any step leaves either
//! the old key or the new one at `<home>/key`, never neither.

use std::io;
use std::path::{Path, PathBuf};

use bifrost::NodeId;
use keystore::{KeyFile, Protection, Stored};

use crate::home::Home;
use crate::passphrase::Prompt;

/// What [`replace`] did.
#[derive(Debug)]
pub struct Replaced {
    /// The new key.
    pub key: NodeId,
    /// Where the old key was kept, when there was one.
    pub kept: Option<PathBuf>,
    /// Where the old key's links were kept, when there were any.
    pub links_kept: Option<PathBuf>,
}

/// Write a fresh random key at `<home>/key`, locked with a new passphrase from `prompt` if the old one was
/// locked, and keep the old key and `links` as `key.replaced-<day>[-n]` and `links.replaced-<day>[-n]`
/// with the first `n` free for both. `day` is today, as `YYYY-MM-DD`.
pub fn replace(home: &Home, prompt: &mut impl Prompt, day: &str) -> eyre::Result<Replaced> {
    let path = home.key();
    let old = KeyFile::device(&path).load()?;
    let passphrase = match &old {
        Some(Stored::Locked(_)) => Some(prompt.choose(&path)?),
        Some(Stored::Plain(_)) | None => None,
    };
    let protection = passphrase
        .as_ref()
        .map_or(Protection::Plain, Protection::Passphrase);
    let secret = keystore::Secret::generate()?;
    let key = secret.node_id();
    let staged = home.dir().join("key.new");
    remove(&staged)?;
    KeyFile::device(&staged).write(&secret, protection)?;

    let (kept, links_kept) = free_names(home, day);
    let kept = match old {
        Some(_) => {
            std::fs::hard_link(&path, &kept)?;
            Some(kept)
        }
        None => None,
    };
    std::fs::rename(&staged, &path)?;
    let links_kept = if home.links().exists() {
        std::fs::rename(home.links(), &links_kept)?;
        Some(links_kept)
    } else {
        None
    };
    std::fs::File::open(home.dir())?.sync_all()?;
    Ok(Replaced {
        key,
        kept,
        links_kept,
    })
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
            home.dir().join(format!("key.replaced-{suffix}")),
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
fn remove(path: &Path) -> io::Result<()> {
    match std::fs::remove_file(path) {
        Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
        _ => Ok(()),
    }
}
