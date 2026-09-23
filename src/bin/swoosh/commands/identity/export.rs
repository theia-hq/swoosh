//! `swoosh identity export <path> [--force]`: write a sealed backup of this identity to a file.
//!
//! The backup is always sealed: a plain key is sealed under a passphrase chosen now, and a sealed key is
//! copied under the passphrase it already has. It is written to the file named and nowhere else; the key
//! is never printed. A file already at the path may be the only other backup, so it is replaced only with
//! `--force`.

use std::path::PathBuf;

use clap::Args;
use swoosh::home::Home;
use swoosh::identity::{self, Existing};
use swoosh::passphrase::Terminal;

/// Write a sealed backup of this identity to <path>.
#[derive(Debug, Args)]
pub struct ExportCmd {
    /// the file to write the backup to
    #[arg(value_name = "path")]
    path: PathBuf,
    /// replace a file already at <path>
    #[arg(long)]
    force: bool,
}

impl ExportCmd {
    /// Seal the home's key into the backup file, then say where it went and how it comes back.
    pub fn run(self, home: &Home) -> eyre::Result<()> {
        let existing = if self.force {
            Existing::Replace
        } else {
            Existing::Refuse
        };
        identity::export(home, &self.path, existing, &mut Terminal)?;
        println!("exported to {}", self.path.display());
        println!(
            "restore with `swoosh identity restore {}`",
            self.path.display()
        );
        Ok(())
    }
}
