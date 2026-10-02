//! `swoosh root`: the group for your root, the key that vouches for your devices.
//!
//! ```text
//! root backup <dir>      copy your root to a new directory
//! root forget <dir>      remove your root from this machine, after checking the copy in <dir>
//! root restore <dir>     put your root on this machine from a copy
//! root lock [<dir>]      change your root's passphrase, on this machine or in <dir>
//! ```
//!
//! There is no move: a copy, then a checked forget. Every `<dir>` names the copy's own directory, which holds
//! `root.key` and `devices` and nothing else, the same directory `--root <dir>` names. `backup`, `forget` and
//! `lock` are local; `restore` checks, asks and writes locally, then binds a transport only for the
//! exchange that brings the restored root up to date ([`restore::RestoreSync`]). Ending a root for good is
//! `swoosh revoke root:<key>`.

use clap::Subcommand;
use swoosh::home::Home;

pub mod backup;
pub mod forget;
pub mod lock;
pub mod restore;

/// The `root` group's leaves.
#[derive(Debug, Subcommand)]
pub enum RootCmd {
    /// copy your root to a new directory
    Backup(backup::BackupCmd),
    /// remove your root from this machine, after checking the copy in <dir>
    Forget(forget::ForgetCmd),
    /// put your root on this machine from a copy
    Restore(restore::RestoreCmd),
    /// change your root's passphrase, on this machine or in <dir>
    Lock(lock::RootLockCmd),
}

/// A `root` leaf, split by whether it binds a transport.
#[derive(Debug)]
pub enum Split {
    /// `backup`, `forget` or `lock`: the home alone.
    Local(Local),
    /// `restore`: local checks and writes, then an exchange over a transport.
    Restore(restore::RestoreCmd),
}

/// The leaves that need only the home.
#[derive(Debug)]
pub enum Local {
    /// `root backup <dir>`.
    Backup(backup::BackupCmd),
    /// `root forget <dir>`.
    Forget(forget::ForgetCmd),
    /// `root lock [<dir>]`.
    Lock(lock::RootLockCmd),
}

impl RootCmd {
    /// Split the leaf by whether it binds a transport.
    pub fn split(self) -> Split {
        match self {
            Self::Backup(cmd) => Split::Local(Local::Backup(cmd)),
            Self::Forget(cmd) => Split::Local(Local::Forget(cmd)),
            Self::Lock(cmd) => Split::Local(Local::Lock(cmd)),
            Self::Restore(cmd) => Split::Restore(cmd),
        }
    }
}

impl Local {
    /// Run the leaf against `home`.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        match self {
            Self::Backup(cmd) => cmd.run(home).await,
            Self::Forget(cmd) => cmd.run(home).await,
            Self::Lock(cmd) => cmd.run(home).await,
        }
    }
}

#[cfg(test)]
#[path = "root_tests.rs"]
mod root_tests;
