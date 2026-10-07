//! `swoosh root forget <dir>`: remove your root from this machine, after checking the copy in `<dir>`.
//!
//! Six checks, each a refusal that writes nothing ([`swoosh::root::forget`]); then `root.key` on this machine
//! is deleted. The line after never says no copy is left on this machine, since system backups made before
//! still hold one, and never says the copy is safe: only where it is kept.

use std::io::{self, Write};
use std::path::PathBuf;

use clap::Args;
use swoosh::escape::EscapedPath;
use swoosh::home::Home;
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::{Disk, RealDisk};

/// remove your root from this machine, after checking the copy in <dir>
#[derive(Debug, Args)]
pub struct ForgetCmd {
    /// the copy's own directory, which root backup made
    #[arg(value_name = "dir")]
    pub(crate) dir: PathBuf,
}

impl ForgetCmd {
    /// Forget, at the terminal and on the real disk.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.forget(home, &mut Terminal, &RealDisk, &mut io::stderr())
            .await
    }

    pub(crate) async fn forget(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        disk: &impl Disk,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let forgot = swoosh::root::forget(home, &self.dir, prompt, disk, err).await?;
        let dir = EscapedPath(&self.dir);
        let kept = if forgot.synced {
            format!(
                "Your root is now kept in {dir}, in the cloud; its passphrase is all that protects it there."
            )
        } else {
            format!("Your root is now kept in {dir}.")
        };
        writeln!(
            err,
            "removed your root from this machine. {kept} Keep it away from this machine. Use it with --root \
             {dir}. System backups made before now still hold it, locked with its passphrase."
        )?;
        Ok(())
    }
}

#[cfg(test)]
#[path = "forget_tests.rs"]
mod forget_tests;
