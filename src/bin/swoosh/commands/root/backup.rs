//! `swoosh root backup <dir>`: copy your root to a new directory.
//!
//! The copy is your root's two files, locked as they are stored, so nothing is asked and nothing is
//! unlocked ([`swoosh::root::backup`]). Your root stays on this machine; `root forget <dir>` takes it off once
//! the copy is checked.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;
use swoosh::escape::EscapedPath;
use swoosh::home::Home;

/// copy your root to a new directory
#[derive(Debug, Args)]
pub struct BackupCmd {
    /// the directory to copy your root into
    #[arg(value_name = "dir")]
    pub(crate) dir: PathBuf,
}

impl BackupCmd {
    /// Copy, then say where the root is now.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.backup(home, &mut io::stderr()).await
    }

    pub(crate) async fn backup(self, home: &Home, err: &mut impl Write) -> eyre::Result<()> {
        swoosh::root::backup(home, &self.dir).await?;
        let dir = EscapedPath(&self.dir);
        writeln!(
            err,
            "copied your root to {dir}. Your root is still on this machine; to take it off: swoosh root forget \
             {dir}"
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod backup_tests;
