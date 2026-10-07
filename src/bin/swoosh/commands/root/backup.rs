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
use swoosh::root::Copied;

/// copy your root to a new directory
#[derive(Debug, Args)]
pub struct BackupCmd {
    /// the directory to copy your root into
    #[arg(value_name = "dir")]
    pub(crate) dir: PathBuf,
}

impl BackupCmd {
    /// Copy, then say where the root is now, and when a key the copy held was replaced.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.backup(home, &mut io::stderr()).await
    }

    pub(crate) async fn backup(self, home: &Home, err: &mut impl Write) -> eyre::Result<()> {
        let copied = swoosh::root::backup(home, &self.dir).await?;
        let dir = EscapedPath(&self.dir);
        writeln!(
            err,
            "copied your root to {dir}. Your root is still on this machine; to take it off: swoosh root forget \
             {dir}"
        )?;
        // A key the copy held is replaced by this machine's, whatever locked it: said, never silent.
        match copied {
            Copied::Replaced => writeln!(
                err,
                "warning: the copy in {dir} was locked differently or damaged, so it was replaced; it now opens \
                 with your root's passphrase on this machine. If you gave the copy its own passphrase, set it \
                 again: swoosh root lock {dir}"
            )?,
            Copied::New | Copied::Kept => {}
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "backup_tests.rs"]
mod backup_tests;
