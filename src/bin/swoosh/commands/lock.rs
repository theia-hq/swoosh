//! `swoosh lock [<method>] [--remove]`: set, change or remove the passphrase on this machine's key.
//!
//! The method is a property of the key file, chosen here and nowhere else. `lock` only ever wraps the same key,
//! so this machine stays the same machine, and it runs beside a `serve`, which holds its key in memory. Your
//! root's passphrase is `swoosh root lock`'s; this command takes no `--root`.

use std::io::{self, Write};

use clap::{Args, ValueEnum};
use keystore::Method;
use swoosh::home::Home;
use swoosh::identity::Locked;
use swoosh::passphrase::{Prompt, Terminal};

/// set, change or remove the passphrase on this machine's key
#[derive(Debug, Args)]
pub struct LockCmd {
    /// how the key is locked
    #[arg(value_name = "method", default_value = "passphrase")]
    method: LockMethod,
    /// remove the passphrase
    #[arg(long)]
    remove: bool,
}

/// The ways this machine's key can be locked, as the command line names them. Only built methods are values,
/// so `--help` never offers one that does nothing, and no value means no lock: that is `--remove`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum LockMethod {
    // No doc comment: a documented value makes clap print `lock --help` in its long form, a block per value.
    Passphrase,
}

/// Exhaustive both ways: a value with no method, or a method the key store adds, fails to compile here.
impl From<LockMethod> for Method {
    fn from(method: LockMethod) -> Self {
        match method {
            LockMethod::Passphrase => Self::Passphrase,
        }
    }
}

impl LockCmd {
    /// Lock, at the terminal, saying what changed on stderr.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.lock(home, &mut Terminal, &mut io::stderr()).await
    }

    pub(crate) async fn lock(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        match swoosh::identity::lock(home, Method::from(self.method), self.remove, prompt).await? {
            Locked::Set { first: true } => writeln!(
                err,
                "set a passphrase on this machine's key. Every command that acts as this machine now asks \
                 for it, so swoosh serve cannot start with nobody at a terminal."
            )?,
            Locked::Set { first: false } => {
                writeln!(err, "changed the passphrase on this machine's key.")?;
            }
            Locked::Removed => writeln!(
                err,
                "removed the passphrase from this machine's key: anyone with a copy of its key file can now \
                 act as this machine."
            )?,
            Locked::AlreadyPlain => writeln!(
                err,
                "this machine's key has no passphrase; nothing was changed."
            )?,
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
