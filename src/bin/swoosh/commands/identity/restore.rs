//! `swoosh identity restore <path> [--force]`: replace this home's key from a backup.
//!
//! The backup is unlocked before anything at home is touched, so a wrong passphrase or a damaged file
//! changes nothing. A home that already holds a DIFFERENT key keeps it unless `--force` is given, because
//! that key may be the only copy of its identity. A node serving this home refuses the restore, through
//! the home lock every `serve` holds.
//!
//! Only the key comes back. The signet this home trusts, its badge, the grants it issued, and what it
//! revoked are left as they are, so a restore into a fresh home admits again every grant revoked before.
//! The verb says that every time, because the fresh home is exactly where a restore for a lost machine
//! lands. A restore is for a lost key, not a stolen one.

use std::path::PathBuf;

use clap::Args;
use swoosh::home::Home;
use swoosh::identity::{self, Existing};
use swoosh::passphrase::Terminal;

/// Restore this home's key from a backup file (the key only, not revocations).
#[derive(Debug, Args)]
pub struct RestoreCmd {
    /// the backup file to restore from
    #[arg(value_name = "path")]
    path: PathBuf,
    /// replace a different identity already at this home
    #[arg(long)]
    force: bool,
}

impl RestoreCmd {
    /// Restore, then name the identity that came back and what did not.
    pub fn run(self, home: &Home) -> eyre::Result<()> {
        let existing = if self.force {
            Existing::Replace
        } else {
            Existing::Refuse
        };
        let restored = identity::restore(home, &self.path, existing, &mut Terminal)?;
        if let Some(mode) = restored.loose {
            eprintln!(
                "note: {} is readable by others (mode {mode:04o}); it is sealed, so its passphrase is \
                 what protects it",
                self.path.display()
            );
        }
        println!("restored {}", restored.node);
        println!("{}", scope_line(home.revoked().exists()));
        Ok(())
    }
}

/// The one line that says what a restore did not bring back. Louder when the home has no revocation list,
/// because that is the case where grants revoked before are admitted again.
fn scope_line(has_revocations: bool) -> &'static str {
    if has_revocations {
        "only the key came back; this home's revocations and trust are unchanged"
    } else {
        "only the key came back; this home has no revocation list, so grants you revoked work again"
    }
}

#[cfg(test)]
#[path = "restore_tests.rs"]
mod restore_tests;
