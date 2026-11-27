//! `swoosh lock [<method>] [--remove]`: add, change or remove a lock on this machine's key.
//!
//! The methods are a property of the key file, chosen here and nowhere else. `lock <method>` adds that lock
//! beside the ones the key has, and only `--remove` takes one off. `lock` only ever wraps the same key,
//! so this machine stays the same machine, and it runs beside a `serve`, which holds its key in memory. Your
//! root's locks are `swoosh root lock`'s; this command takes no `--root`. `touch-id` is a value on a macOS
//! build only: elsewhere there is no enclave to make it, so it is not offered.

use clap::{Args, ValueEnum};
use keystore::{Health, Method};
use swoosh::home::Home;
use swoosh::identity::{Gone, Locked, Locks, Methods, Now, Root, Unconfirmed, Why};
use swoosh::passphrase::{Prompt, Terminal};

use crate::commands::through_serve::Reported;
use crate::screen::{Block, Cell, Paint, Screen, Style};

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
        let locked = match swoosh::identity::lock(
            home,
            Method::from(self.method),
            self.remove,
            prompt,
        )
        .await
        {
            Ok(locked) => locked,
            Err(report) => return Err(refused(report, err)),
        };
        // The made key is the one token a result prints, so its text lives here, beside the screen that
        // borrows it.
        let key = match &locked {
            Locked::Made { key, .. } => key.to_string(),
            _ => String::new(),
        };
        result(&locked, &key).write(err)?;
        Ok(())
    }
}

/// A refusal whose key file this command could not confirm, or whose file is gone, drawn as a screen on
/// `err`, then [`Reported`] for the exit 1; any other is returned as it is, for `main` to print.
fn refused(report: eyre::Report, err: &mut impl Paint) -> eyre::Report {
    let screen = if let Some(unconfirmed) = report.downcast_ref::<Unconfirmed>() {
        let path = unconfirmed.path.to_string_lossy().into_owned();
        let read = unconfirmed
            .read
            .as_ref()
            .map(|error| swoosh::escape::causes(error));
        let block = unconfirmable(
            Block::default().head(
                Style::ERROR,
                "error:",
                "this command could not confirm the key file".to_owned(),
            ),
            &path,
            read.as_deref(),
        );
        Screen::default().block(block).write(err)
    } else if report.downcast_ref::<Gone>().is_some() {
        let block = Block::default()
            .head(
                Style::ERROR,
                "error:",
                "the key file this command wrote is gone".to_owned(),
            )
            .text(STATUS_SHOWS.to_owned());
        Screen::default().block(block).write(err)
    } else {
        return report;
    };
    match screen {
        Ok(()) => Reported.into(),
        Err(error) => error.into(),
    }
}

/// Where the reader looks when this command cannot say what the key file holds.
const STATUS_SHOWS: &str = "  swoosh status shows what is there.";

/// `block`, with what is said where the key file cannot be confirmed: where `status` shows it, the file, and
/// the read's error where one failed. The rows' values are the file's path and system text, each escaped
/// whole and last on its line.
fn unconfirmable<'a>(block: Block<'a>, path: &'a str, read: Option<&'a str>) -> Block<'a> {
    let block = block
        .text(STATUS_SHOWS.to_owned())
        .column(ROW_COLUMN)
        .row([Cell::Word("file"), Cell::Token(path)]);
    match read {
        Some(read) => block.row([Cell::Word("read"), Cell::Token(read)]),
        None => block,
    }
}

/// Where the value column of a key file's rows starts: three spaces after `file` and `read`.
const ROW_COLUMN: usize = 9;

/// Where the value column of a made key's failure row starts: three spaces after `failure`.
const FAILURE_COLUMN: usize = 12;

/// The screen for what `lock` did, one per outcome. A line that says what the key opens with now is read
/// from the file after the write, never from what was asked; `key` is the made key's text.
fn result<'a>(locked: &'a Locked, key: &'a str) -> Screen<'a> {
    match locked {
        Locked::Made { now, failed, .. } => {
            let made = Block::default()
                .text(
                    match now {
                        Methods::Passphrase => "Made this machine's key, locked with a passphrase:",
                        Methods::TouchId => "Made this machine's key, locked with Touch ID:",
                        Methods::Both => {
                            "Made this machine's key, locked with Touch ID or a passphrase:"
                        }
                    }
                    .to_owned(),
                )
                .row([Cell::Token(key)]);
            // The key is in place, so it is made; a failure the key store answered after it is said under it.
            let failed = failed.as_deref().map_or_else(Block::default, |failed| {
                Block::default()
                    .head(
                        Style::WARNING,
                        "warning:",
                        "the key file was written, but a step after it failed".to_owned(),
                    )
                    .column(FAILURE_COLUMN)
                    .row([Cell::Word("failure"), Cell::Token(failed)])
            });
            Screen::default().block(made).block(failed)
        }
        Locked::Added { method, now, root } => added(*method, now, *root),
        Locked::Changed {
            method: Method::Passphrase,
            now: Now::Read(_),
        } => one(&[
            "Changed the passphrase on this machine's key.",
            "A copy made earlier still opens with the old passphrase.",
        ]),
        Locked::Changed { method, now } => {
            let done = Block::default().text(
                match method {
                    Method::Passphrase => "Changed the passphrase on this machine's key.",
                    Method::TouchId => "Changed Touch ID on this machine's key.",
                }
                .to_owned(),
            );
            Screen::default().block(unread(done, now))
        }
        Locked::Removed { method, now } => removed(*method, now),
        Locked::Unchanged(Why::NeedsPassphrase) => needs_passphrase(),
        Locked::Unchanged(why) => one(&[match why {
            Why::NoKey => "This machine has no key yet, so nothing was changed.",
            Why::NoLock => "This machine's key has no lock, so nothing was changed.",
            Why::NoSuchLock(Method::Passphrase) => {
                "This machine's key has no passphrase, so nothing was changed."
            }
            Why::NoSuchLock(Method::TouchId) => {
                "This machine's key has no Touch ID lock, so nothing was changed."
            }
            Why::TouchIdAlone | Why::NeedsPassphrase => {
                "This machine's key already opens with Touch ID alone, so nothing was changed."
            }
        }]),
    }
}

/// A screen of one block of fixed lines.
fn one(lines: &[&'static str]) -> Screen<'static> {
    let block = lines.iter().fold(Block::default(), |block, line| {
        block.text((*line).to_owned())
    });
    Screen::default().block(block)
}

/// `done`, with the warning that the file could not be read back where `now` was not: the write stands, so it
/// is said, but nothing after it can be.
fn unread<'a>(done: Block<'a>, now: &'a Now) -> Block<'a> {
    match now {
        Now::Read(_) => done,
        Now::Unread(unread) => unconfirmable(
            done.head(
                Style::WARNING,
                "warning:",
                "this command could not confirm the key file".to_owned(),
            ),
            &unread.path,
            Some(&unread.read),
        ),
    }
}

/// `done`, with the line that says what the key opens with now, from `now`. A Touch ID lock that reads dead
/// here is said as such, as a risk, never as a lock the key opens with.
fn opens(done: Block<'_>, now: Locks) -> Block<'_> {
    match now {
        Locks::None => done.text("It now has no lock.".to_owned()),
        Locks::TouchId(Some(Health::Dead)) => done
            .risk("Touch ID does not open on this Mac now, so nothing opens this machine's key."),
        Locks::Both(Some(Health::Dead)) => {
            done.risk("It opens with the passphrase; Touch ID does not open on this Mac now.")
        }
        Locks::Passphrase | Locks::TouchId(_) | Locks::Both(_) => match now.opens_with() {
            Some(opens) => done.text(format!("It now opens with {opens}.")),
            None => done,
        },
    }
}

/// The screen for locks put on the key: what was added, what it opens with now, then, where the key now has
/// both locks from one added beside the other, the step that takes the passphrase off. Where a root is kept
/// here the passphrase never comes off beside Touch ID, so no step prints; where the file could not be read
/// back, neither line can be said.
fn added(method: Methods, now: &Now, root: Root) -> Screen<'_> {
    let done = Block::default().text(format!(
        "Added {} to this machine's key.",
        match method {
            Methods::Passphrase => "a passphrase",
            Methods::TouchId => "Touch ID",
            Methods::Both => "Touch ID and a passphrase",
        }
    ));
    let Now::Read(locks) = now else {
        return Screen::default().block(unread(done, now));
    };
    // A Touch ID lock that reads dead here cannot be left alone, so the key store refuses the step that takes
    // the passphrase off: none is offered.
    let back = match (root, method, locks) {
        (_, _, Locks::Both(Some(Health::Dead))) => None,
        (Root::NotKept, Methods::Passphrase, Locks::Both(_)) => {
            Some("To go back to Touch ID alone:")
        }
        (Root::NotKept, Methods::TouchId, Locks::Both(_)) => {
            Some("To make Touch ID its only lock:")
        }
        _ => None,
    };
    let step = back.map_or_else(Block::default, |back| {
        Block::default()
            .text(back.to_owned())
            .command("swoosh lock passphrase --remove".to_owned())
    });
    Screen::default().block(opens(done, *locks)).block(step)
}

/// The screen for a lock taken off: which, what the key opens with now, and, where a lock is left, that a
/// copy of the file made before still opens with the one taken off, since removing a lock reaches no copy.
fn removed(method: Method, now: &Now) -> Screen<'_> {
    let done = Block::default().text(format!(
        "Removed {} from this machine's key.",
        match method {
            Method::Passphrase => "the passphrase",
            Method::TouchId => "Touch ID",
        }
    ));
    let Now::Read(locks) = now else {
        return Screen::default().block(unread(done, now));
    };
    let done = opens(done, *locks);
    let done = match (locks, method) {
        (Locks::None, _) => done,
        (_, Method::Passphrase) => {
            done.text("A copy made earlier still opens with the passphrase.".to_owned())
        }
        (_, Method::TouchId) => {
            done.text("A copy made earlier still opens with Touch ID on this Mac.".to_owned())
        }
    };
    Screen::default().block(done)
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
