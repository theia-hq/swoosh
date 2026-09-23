//! `protect`: choose how the home's key file protects its key.

use bifrost::NodeId;
use keystore::{Method, Protection, Stored};

use super::lock::HomeLock;
use super::{create_dir, key_file};
use crate::home::Home;
use crate::passphrase::Prompt;

/// What a [`protect`] did to the home's key file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Protected {
    /// The home had no key, so its first one, this node, was created under the method asked for.
    Created(NodeId),
    /// The key was rewritten under the method asked for: sealed, unsealed, or sealed under a new
    /// passphrase. The key, and so the node, is the same one.
    Rewritten,
    /// The key was already plain, and plain is what was asked for.
    Unchanged,
}

/// Protect the home's key under `method`.
///
/// A home with no key gets its first one directly under `method`, so a key meant to be sealed never
/// touches the disk in the clear. Otherwise the file is migrated in place: unlocked as it stands,
/// re-wrapped, test-unlocked, and atomically renamed over, so a wrong passphrase or a crash leaves it
/// exactly as it was. `passphrase` over a sealed key asks for the current passphrase and then a new one,
/// which is how a passphrase is changed.
///
/// Safe beside a running node: the node already holds its key in memory, and the key does not change. It
/// shares the home lock with running nodes, so it never interleaves with a restore.
pub fn protect(home: &Home, method: Method, prompt: &mut impl Prompt) -> eyre::Result<Protected> {
    let _lock = HomeLock::rewriting(home)?;
    let file = key_file(home);
    let path = file.path();
    let Some(stored) = file.load()? else {
        let secret = keystore::Secret::generate()?;
        create_dir(&file)?;
        match method {
            Method::Plain => file.write(&secret, Protection::Plain)?,
            Method::Passphrase => {
                let passphrase = prompt.choose(path)?;
                file.write(&secret, Protection::Passphrase(&passphrase))?;
            }
        }
        return Ok(Protected::Created(secret.node_id()));
    };
    match (stored, method) {
        (Stored::Plain(_), Method::Plain) => return Ok(Protected::Unchanged),
        (Stored::Plain(_), Method::Passphrase) => {
            let new = prompt.choose(path)?;
            file.migrate(Protection::Plain, Protection::Passphrase(&new))?;
        }
        (Stored::Locked(_), Method::Plain) => {
            let current = prompt.unlock(path)?;
            file.migrate(Protection::Passphrase(&current), Protection::Plain)?;
        }
        (Stored::Locked(locked), Method::Passphrase) => {
            let current = prompt.unlock(path)?;
            // Proven before the new one is asked for, so a mistyped current passphrase fails at once
            // rather than after the new one has been typed twice.
            drop(locked.unlock(&current)?);
            let new = prompt.choose(path)?;
            file.migrate(
                Protection::Passphrase(&current),
                Protection::Passphrase(&new),
            )?;
        }
    }
    Ok(Protected::Rewritten)
}

#[cfg(test)]
#[path = "protect_tests.rs"]
mod protect_tests;
