//! `swoosh root lock [<method>] [<dir>] [--remove]`: change your root's passphrase, or add or remove its
//! `touch-id` lock, on this machine or in a copy.
//!
//! Rewrites `root.key` only ([`swoosh::root::lock`], [`swoosh::root::lock_touch_id`]): nothing is signed or
//! synced. Other copies keep their locks. `touch-id` is a value on a macOS build only, and the passphrase is
//! never removed: it is how every copy opens on another machine.
//!
//! Both arguments are optional, so a lone word is told apart by its shape: a method's name is a method, and a
//! directory holds a `/` (or is `.` or `..`). A word that is neither is refused with the fix, so a mistyped
//! method is never taken for a directory.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::Args;
use keystore::Method;
use swoosh::escape::EscapedPath;
use swoosh::home::Home;
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::{Relocked, TouchIdChange};

/// change your root's passphrase, on this machine or in <dir>
#[derive(Debug, Args)]
pub struct RootLockCmd {
    /// how your root opens: passphrase, or touch-id beside it; or a copy's own directory
    #[arg(value_name = "method", value_parser = first)]
    pub(crate) first: Option<First>,
    /// a copy's own directory; without it, your root on this machine
    #[arg(value_name = "dir")]
    pub(crate) dir: Option<PathBuf>,
    /// remove this lock instead
    #[arg(long)]
    pub(crate) remove: bool,
}

/// The first argument, by its shape.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum First {
    /// A method's name.
    Method(Method),
    /// A copy's own directory.
    Dir(PathBuf),
}

/// The methods `root lock` takes, by name: the passphrase everywhere, `touch-id` on a macOS build.
fn method(word: &str) -> Option<Method> {
    match word {
        "passphrase" => Some(Method::Passphrase),
        #[cfg(target_os = "macos")]
        "touch-id" => Some(Method::TouchId),
        _ => None,
    }
}

/// Parse the first argument: a method, or a directory, which holds a `/`.
fn first(word: &str) -> Result<First, String> {
    if let Some(method) = method(word) {
        return Ok(First::Method(method));
    }
    if word.contains('/') || word == "." || word == ".." {
        return Ok(First::Dir(PathBuf::from(word)));
    }
    Err(format!(
        "{word} is not a lock method; a directory needs a /: swoosh root lock ./{word}"
    ))
}

/// A usage error found once the arguments are read together, as clap would print it: exit 2.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

/// The refusal of `root lock --remove`: the passphrase is the one lock that opens every copy.
pub(crate) const KEEPS_PASSPHRASE: &str =
    "your root always keeps its passphrase: it is how every copy opens on another machine";

impl RootLockCmd {
    /// Change it at the terminal.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.lock(home, &mut Terminal, &mut io::stderr()).await
    }

    /// The method and the directory the arguments name, read together.
    fn target(&self) -> Result<(Method, Option<&Path>), Usage> {
        let (method, dir) = match (&self.first, &self.dir) {
            (None, _) => (Method::Passphrase, self.dir.as_deref()),
            (Some(First::Method(method)), dir) => (*method, dir.as_deref()),
            (Some(First::Dir(dir)), None) => (Method::Passphrase, Some(dir.as_path())),
            (Some(First::Dir(dir)), Some(_)) => {
                return Err(Usage(format!(
                    "{} is not a lock method; name the method first: swoosh root lock touch-id <dir>",
                    EscapedPath(dir)
                )));
            }
        };
        if self.remove && method == Method::Passphrase {
            return Err(Usage(KEEPS_PASSPHRASE.to_owned()));
        }
        Ok((method, dir))
    }

    pub(crate) async fn lock(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let (method, dir) = self.target()?;
        let here = |relocked: Relocked| matches!(relocked, Relocked::Here) || dir.is_none();
        match method {
            Method::Passphrase => {
                let relocked = swoosh::root::lock(home, dir, prompt).await?;
                match dir {
                    Some(dir) if !here(relocked) => writeln!(
                        err,
                        "changed your root's passphrase in {}. Other copies keep the old one.",
                        EscapedPath(dir)
                    )?,
                    _ => writeln!(
                        err,
                        "changed your root's passphrase on this machine. Other copies keep the old one."
                    )?,
                }
            }
            Method::TouchId => {
                let (relocked, change) =
                    swoosh::root::lock_touch_id(home, dir, self.remove, prompt).await?;
                let place = match dir {
                    Some(dir) if !here(relocked) => {
                        format!("the copy of your root in {}", EscapedPath(dir))
                    }
                    _ => "your root".to_owned(),
                };
                match change {
                    TouchIdChange::Added => writeln!(
                        err,
                        "added touch-id to {place} on this Mac; its passphrase still opens it."
                    )?,
                    TouchIdChange::Removed => writeln!(
                        err,
                        "removed touch-id from {place}; its passphrase opens it."
                    )?,
                    TouchIdChange::NoTouchId => {
                        writeln!(err, "{place} has no touch-id; nothing was changed.")?;
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
