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
    /// take the lock off
    #[arg(long)]
    remove: bool,
}

/// The ways this machine's key can be locked, as the command line names them. Only built methods are values,
/// so `--help` never offers one that does nothing, and no value means no lock: that is `--remove`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum LockMethod {
    /// a passphrase you type
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
            Locked::Set { first } => {
                if first {
                    writeln!(err, "`swoosh serve` will ask for it at every start.")?;
                }
                writeln!(err, "this machine's key now has a passphrase.")?;
            }
            Locked::Removed => writeln!(
                err,
                "this machine's key has no passphrase now: a copy of the file is this machine."
            )?,
            Locked::AlreadyPlain => writeln!(err, "this machine's key has no passphrase")?,
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
