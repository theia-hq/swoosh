//! `swoosh lock [<method>] [--remove]`: add, change or remove a lock on this machine's key.
//!
//! The methods are a property of the key file, chosen here and nowhere else. `lock <method>` adds that lock
//! beside the ones the key has, and only `--remove` takes one off. `lock` only ever wraps the same key,
//! so this machine stays the same machine, and it runs beside a `serve`, which holds its key in memory. Your
//! root's locks are `swoosh root lock`'s; this command takes no `--root`. `touch-id` is a value on a macOS
//! build only: elsewhere there is no enclave to make it, so it is not offered.

use clap::{Args, ValueEnum};
use keystore::Method;
use swoosh::home::Home;
use swoosh::identity::Locked;
use swoosh::passphrase::{Prompt, Terminal};

use crate::screen::{Block, Paint, Screen};

/// set, change or remove the lock on this machine's key
#[derive(Debug, Args)]
pub struct LockCmd {
    /// how the key is locked
    #[arg(value_name = "method", default_value = "passphrase")]
    method: LockMethod,
    /// remove this lock instead
    #[arg(long)]
    remove: bool,
}

/// The ways this machine's key can be locked, as the command line names them. Only built methods are values,
/// so `--help` never offers one that does nothing, and no value means no lock: that is `--remove`.
#[derive(Debug, Clone, Copy, ValueEnum)]
enum LockMethod {
    // No doc comment: a documented value makes clap print `lock --help` in its long form, a block per value.
    Passphrase,
    #[cfg(target_os = "macos")]
    TouchId,
}

/// Exhaustive both ways: a value with no method, or a method the key store adds, fails to compile here.
impl From<LockMethod> for Method {
    fn from(method: LockMethod) -> Self {
        match method {
            LockMethod::Passphrase => Self::Passphrase,
            #[cfg(target_os = "macos")]
            LockMethod::TouchId => Self::TouchId,
        }
    }
}

impl LockCmd {
    /// Lock, at the terminal, saying what changed on stderr.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.lock(home, &mut Terminal, &mut anstream::stderr())
            .await
    }

    pub(crate) async fn lock(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        err: &mut impl Paint,
    ) -> eyre::Result<()> {
        let locked =
            swoosh::identity::lock(home, Method::from(self.method), self.remove, prompt).await?;
        match locked {
            Locked::PassphraseBesideTouchId { root_kept } => beside(
                "Added a passphrase to this machine's key.",
                (!root_kept).then_some("To go back to Touch ID alone:"),
            )
            .write(err)?,
            Locked::TouchIdBesidePassphrase { root_kept } => beside(
                "Added Touch ID to this machine's key.",
                (!root_kept).then_some("To make Touch ID its only lock:"),
            )
            .write(err)?,
            Locked::TouchIdChanged => Screen::default()
                .block(Block::default().text("Changed Touch ID on this machine's key.".to_owned()))
                .write(err)?,
            Locked::NeedsPassphrase => needs_passphrase().write(err)?,
            Locked::Set { first: true } => writeln!(
                err,
                "set a passphrase on this machine's key.\n\
                 every command that acts as this machine now asks for it, so swoosh serve cannot start with \
                 nobody at a terminal."
            )?,
            Locked::Set { first: false } => {
                writeln!(err, "changed the passphrase on this machine's key.")?;
            }
            Locked::Removed { plain: true } => writeln!(
                err,
                "removed the passphrase from this machine's key, which now has no lock.\n\
                 anyone with a copy of its key file can act as this machine."
            )?,
            Locked::Removed { plain: false } => writeln!(
                err,
                "removed the passphrase from this machine's key, which now opens with touch-id only."
            )?,
            Locked::NoPassphrase => writeln!(
                err,
                "this machine's key has no passphrase; nothing was changed."
            )?,
            Locked::TouchId { passphrase: true } => writeln!(
                err,
                "added touch-id to this machine's key, beside its passphrase."
            )?,
            Locked::TouchId { passphrase: false } => writeln!(
                err,
                "this machine's key now opens with touch-id only.\n\
                 every command that acts as this machine now needs a touch at this Mac, so swoosh serve \
                 cannot start with nobody there."
            )?,
            Locked::TouchIdRemoved { plain: true } => writeln!(
                err,
                "removed touch-id from this machine's key, which now has no lock.\n\
                 anyone with a copy of its key file can act as this machine."
            )?,
            Locked::TouchIdRemoved { plain: false } => writeln!(
                err,
                "removed touch-id from this machine's key, which now opens with its passphrase only."
            )?,
            Locked::NoTouchId => writeln!(
                err,
                "this machine's key has no touch-id; nothing was changed."
            )?,
            Locked::HasTouchId => writeln!(
                err,
                "this machine's key already has touch-id as its only lock; nothing was changed."
            )?,
        }
        Ok(())
    }
}

/// The screen for a lock put beside the key's other one: what was added, what it opens with now, then the
/// step that takes the passphrase off, under `back`. Where a root is kept here the passphrase never comes off
/// beside `touch-id`, so the caller gives no `back` and no step prints.
fn beside(done: &'static str, back: Option<&'static str>) -> Screen<'static> {
    let now = Block::default()
        .text(done.to_owned())
        .text("It now opens with Touch ID or the passphrase.".to_owned());
    let step = back.map_or_else(Block::default, |back| {
        Block::default()
            .text(back.to_owned())
            .command("swoosh lock passphrase --remove".to_owned())
    });
    Screen::default().block(now).block(step)
}

/// The screen for `lock touch-id` on a key under `touch-id` alone beside a kept root: nothing changed, which
/// must not read as all clear, since the key there needs a passphrase beside it.
fn needs_passphrase() -> Screen<'static> {
    Screen::default().block(
        Block::default()
            .text(
                "Your root is on this machine, so its key needs a passphrase beside Touch ID."
                    .to_owned(),
            )
            .text("Nothing was changed.".to_owned())
            .text("To add the passphrase:".to_owned())
            .command("swoosh lock passphrase".to_owned()),
    )
}

#[cfg(test)]
#[path = "lock_tests.rs"]
mod lock_tests;
