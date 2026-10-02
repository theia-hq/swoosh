//! `swoosh root lock [<dir>]`: change your root's passphrase, on this machine or in a copy.
//!
//! Rewrites `root.key` only ([`swoosh::root::lock`]): nothing is signed or synced. Other copies keep the old
//! passphrase.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;
use swoosh::escape::EscapedPath;
use swoosh::home::Home;
use swoosh::passphrase::{Prompt, Terminal};

/// change your root's passphrase, on this machine or in <dir>
#[derive(Debug, Args)]
pub struct RootLockCmd {
    /// a copy's own directory; without it, your root on this machine
    #[arg(value_name = "dir")]
    dir: Option<PathBuf>,
}

impl RootLockCmd {
    /// Change it at the terminal.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.lock(home, &mut Terminal, &mut io::stderr()).await
    }

    pub(crate) async fn lock(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let relocked = swoosh::root::lock(home, self.dir.as_deref(), prompt).await?;
        match (relocked, &self.dir) {
            (swoosh::root::Relocked::Here, _) | (_, None) => writeln!(
                err,
                "changed your root's passphrase on this machine. Other copies keep the old one."
            )?,
            (swoosh::root::Relocked::Copy, Some(dir)) => writeln!(
                err,
                "changed your root's passphrase in {}. Other copies keep the old one.",
                EscapedPath(dir)
            )?,
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
