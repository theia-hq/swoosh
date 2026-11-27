//! `swoosh lock [<method>] [--remove]`: show, add, change or remove a lock on this machine's key.
//!
//! The methods are a property of the key file, chosen here and nowhere else. A bare `lock` only reads: it
//! shows the key's locks and the steps that change them, and asks, touches and writes nothing. `lock
//! <method>` adds that lock beside the ones the key has, and only `--remove` takes one off. `lock` only ever
//! wraps the same key, so this machine stays the same machine, and it runs beside a `serve`, which holds its
//! key in memory. Your root's locks are `swoosh root lock`'s; this command takes no `--root`. `touch-id` is a
//! value on a macOS build only: elsewhere there is no enclave to make it, so it is not offered.

use std::sync::OnceLock;

use clap::{Args, ValueEnum};
use keystore::{Health, Method};
use swoosh::home::Home;
use swoosh::identity::{
    Gone, Locked, Locks, Methods, Now, Root, TouchIdNotAdded, Unconfirmed, Why,
};
use swoosh::passphrase::{Prompt, Terminal};

use crate::commands::through_serve::Reported;
use crate::screen::{Block, Cell, Paint, Screen, Style};

// `touch-id` is a method on a macOS build only, so the summary names Touch ID there only.
#[cfg_attr(
    target_os = "macos",
    doc = "Lock this machine's key with a passphrase or Touch ID"
)]
#[cfg_attr(
    not(target_os = "macos"),
    doc = "Lock this machine's key with a passphrase"
)]
#[derive(Debug, Args)]
pub struct LockCmd {
    /// The lock; omit to show them
    #[arg(value_name = "method")]
    method: Option<LockMethod>,
    /// Take this lock off
    // A bare `--remove` names no lock to take off, so it is clap's own usage error, never a guess.
    #[arg(long, requires = "method")]
    remove: bool,
}

/// The ways this machine's key can be locked, as the command line names them. Only built methods are values,
/// so `--help` never offers one that does nothing; no lock is `--remove`, and no value is the read.
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
    /// Show the locks on stdout, or lock at the terminal, saying what changed on stderr.
    pub async fn run(self, home: &Home) -> eyre::Result<()> {
        self.lock(
            home,
            &mut Terminal,
            &mut anstream::stdout(),
            &mut anstream::stderr(),
        )
        .await
    }

    /// The read where no method is named, on `out`; else the act, saying what changed on `err`.
    pub(crate) async fn lock(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        out: &mut impl Paint,
        err: &mut impl Paint,
    ) -> eyre::Result<()> {
        let Some(method) = self.method else {
            return show(home, prompt, out, err);
        };
        let locked =
            match swoosh::identity::lock(home, Method::from(method), self.remove, prompt).await {
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

/// The bare `lock`: the key's locks and the steps that change them, on `out`, exit 0. Read from the key file's
/// header with `prompt` borrowed shared, so nothing is asked or touched, and no `home.lock` is taken: a read
/// never writes. A key file that cannot be read refuses on `err`, exit 1.
fn show(
    home: &Home,
    prompt: &impl Prompt,
    out: &mut impl Paint,
    err: &mut impl Paint,
) -> eyre::Result<()> {
    let locks = match swoosh::identity::locks(home, prompt) {
        Ok(locks) => locks,
        Err(error) => return Err(unreadable(&home.key(), &error, err)),
    };
    // A root that cannot be told kept or not counts as kept: that drops a step a command would refuse, and
    // claims nothing, so the screen says nothing of it.
    let root = if matches!(home.keeps_root(), Ok(false)) {
        Root::NotKept
    } else {
        Root::Kept
    };
    read(locks, root, Enclave::BUILT).write(out)?;
    Ok(())
}

/// Whether this build can put Touch ID on a key: a macOS build has an enclave to make it, so `touch-id` is a
/// value there, and only there does a step name it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Enclave {
    /// Touch ID can be put on a key here.
    Here,
    /// This build has no enclave.
    Absent,
}

impl Enclave {
    /// This build's.
    pub(crate) const BUILT: Self = if cfg!(target_os = "macos") {
        Self::Here
    } else {
        Self::Absent
    };
}

/// The refusal where the key file cannot be read, drawn on `err`: the file and the read's error, each escaped
/// whole and last on its line. It names no command to look with, since `status` reads the same file.
fn unreadable(
    path: &std::path::Path,
    error: &keystore::Error,
    err: &mut impl Paint,
) -> eyre::Report {
    let path = path.to_string_lossy();
    let read = swoosh::escape::causes(error);
    let block = Block::default()
        .head(
            Style::ERROR,
            "error:",
            "this command could not read the key file".to_owned(),
        )
        .column(ROW_COLUMN)
        .row([Cell::Word("file"), Cell::Token(&path)])
        .row([Cell::Word("read"), Cell::Token(&read)]);
    match Screen::default().block(block).write(err) {
        Ok(()) => Reported.into(),
        Err(error) => error.into(),
    }
}

/// The read's screen for a key whose locks are `locks` (`None`: no key yet): the first sentence, the
/// `locks` rows, then the steps, each a command this state would not refuse. A Touch ID lock that does not
/// read live here counts for nothing the key store would let go: beside one, the passphrase's `--remove`
/// refuses, and on one alone so does `lock passphrase`, so neither is offered; nor is the passphrase's
/// `--remove` where a root is kept.
fn read(locks: Option<Locks>, root: Root, enclave: Enclave) -> Screen<'static> {
    let Some(locks) = locks else {
        let rows = match enclave {
            Enclave::Here => Block::titled("locks").columns(COLUMNS).row([
                Cell::Word(name(Method::TouchId)),
                Cell::Word(TOUCH_ID_GLOSS),
            ]),
            Enclave::Absent => Block::titled("locks").columns(COLUMNS),
        }
        .row([
            Cell::Word(name(Method::Passphrase)),
            Cell::Word(PASSPHRASE_GLOSS),
        ]);
        let steps = match enclave {
            Enclave::Here => steps(
                "To make the key with one of them:",
                &[ADD_TOUCH_ID, ADD_PASSPHRASE],
            ),
            Enclave::Absent => steps("To make the key with a passphrase:", &[ADD_PASSPHRASE]),
        };
        return Screen::default()
            .block(Block::titled("This machine has no key yet."))
            .block(rows)
            .block(steps);
    };
    let (title, steps) = match (locks, enclave) {
        (Locks::None, Enclave::Here) => (
            Block::default().risk("This machine's key has no lock."),
            steps(
                "To lock it with one of them:",
                &[ADD_TOUCH_ID, ADD_PASSPHRASE],
            ),
        ),
        (Locks::None, Enclave::Absent) => (
            Block::default().risk("This machine's key has no lock."),
            steps("To lock it with a passphrase:", &[ADD_PASSPHRASE]),
        ),
        (Locks::Passphrase, Enclave::Here) => (
            Block::titled("This machine's key opens with a passphrase."),
            steps("To add Touch ID beside the passphrase:", &[ADD_TOUCH_ID]),
        ),
        (Locks::Passphrase, Enclave::Absent) => (
            Block::titled("This machine's key opens with a passphrase."),
            steps("To change the passphrase:", &[ADD_PASSPHRASE]),
        ),
        (Locks::TouchId(Some(Health::Live)), _) => (
            Block::titled("This machine's key opens with Touch ID, on this Mac only."),
            steps("To add a passphrase beside Touch ID:", &[ADD_PASSPHRASE]),
        ),
        // `status` says how to mend a dead lock, the fingerprint or a new key; no `lock` command can.
        (Locks::TouchId(Some(Health::Dead)), _) => (
            Block::default().risk("This machine's key does not open on this Mac now."),
            Block::default().text("swoosh status says how to mend it.".to_owned()),
        ),
        // No command mends a check that did not answer.
        (Locks::TouchId(Some(Health::Unchecked)), _) => (
            Block::titled("Touch ID on this machine's key cannot be checked now."),
            Block::default(),
        ),
        // Nothing on this build can open it.
        (Locks::TouchId(None), _) => (
            Block::default().risk("Touch ID opens this machine's key only on the Mac that set it."),
            Block::default(),
        ),
        (Locks::Both(Some(Health::Live)), _) => (
            Block::titled("This machine's key opens with Touch ID or a passphrase."),
            match root {
                Root::NotKept => steps("To take one off:", &[REMOVE_TOUCH_ID, REMOVE_PASSPHRASE]),
                Root::Kept => steps("To take Touch ID off:", &[REMOVE_TOUCH_ID]),
            },
        ),
        (Locks::Both(Some(Health::Dead | Health::Unchecked)), _) => (
            Block::titled("This machine's key opens with a passphrase."),
            steps("To take Touch ID off:", &[REMOVE_TOUCH_ID]),
        ),
        (Locks::Both(None), _) => (
            Block::titled("This machine's key opens with a passphrase."),
            steps("To change the passphrase:", &[ADD_PASSPHRASE]),
        ),
    };
    let touch_id = match locks {
        Locks::None | Locks::Passphrase => match enclave {
            Enclave::Here => Some([
                Cell::Word(name(Method::TouchId)),
                Cell::Word("off"),
                Cell::Word(TOUCH_ID_GLOSS),
            ]),
            Enclave::Absent => None,
        },
        Locks::TouchId(health) | Locks::Both(health) => Some([
            Cell::Word(name(Method::TouchId)),
            Cell::Word("on"),
            match health {
                Some(Health::Live) => Cell::Word(TOUCH_ID_GLOSS),
                // On a dead lock the gloss is its state.
                Some(Health::Dead) => Cell::Risk("does not open on this Mac now"),
                Some(Health::Unchecked) => Cell::Word("cannot be checked now"),
                // A risk where nothing else opens the key.
                None if matches!(locks, Locks::TouchId(_)) => {
                    Cell::Risk("opens only on the Mac that set it")
                }
                None => Cell::Word("opens only on the Mac that set it"),
            },
        ]),
    };
    let passphrase = match locks {
        Locks::Passphrase | Locks::Both(_) => "on",
        Locks::None | Locks::TouchId(_) => "off",
    };
    let rows = touch_id
        .into_iter()
        .fold(Block::titled("locks").columns(COLUMNS), Block::row)
        .row([
            Cell::Word(name(Method::Passphrase)),
            Cell::Word(passphrase),
            Cell::Word(PASSPHRASE_GLOSS),
        ]);
    Screen::default().block(title).block(rows).block(steps)
}

/// Where the `locks` rows' state and gloss columns start, so `on` and `off` keep one place.
const COLUMNS: [usize; 2] = [15, 21];

/// A `locks` row's name: the method as `lock` takes it, from [`LockMethod`]'s own value, so the typed name has
/// one source. A build with no enclave takes no Touch ID value, yet a key file moved from a Mac can hold that
/// lock, so its row names the method as the key store spells it, which a test holds to the same word. Worked
/// out once: clap lends a value's name only for as long as the value, and a row holds `'static` words.
fn name(method: Method) -> &'static str {
    static NAMES: OnceLock<[String; 2]> = OnceLock::new();
    let typed = |method: Method| {
        LockMethod::value_variants()
            .iter()
            .find(|value| Method::from(**value) == method)
            .and_then(ValueEnum::to_possible_value)
            .map_or_else(|| method.to_string(), |value| value.get_name().to_owned())
    };
    let [passphrase, touch_id] =
        NAMES.get_or_init(|| [typed(Method::Passphrase), typed(Method::TouchId)]);
    match method {
        Method::Passphrase => passphrase,
        Method::TouchId => touch_id,
    }
}
/// What a live Touch ID lock is.
const TOUCH_ID_GLOSS: &str = "a touch on this Mac's sensor; opens on this Mac only";
/// What a passphrase lock is.
const PASSPHRASE_GLOSS: &str = "typed at each use; a copy opens on any machine";

/// The commands the read's steps name.
const ADD_TOUCH_ID: &str = "swoosh lock touch-id";
const ADD_PASSPHRASE: &str = "swoosh lock passphrase";
const REMOVE_TOUCH_ID: &str = "swoosh lock touch-id --remove";
const REMOVE_PASSPHRASE: &str = "swoosh lock passphrase --remove";

/// A step block: `lead`, then each command alone on its line.
fn steps(lead: &'static str, commands: &[&'static str]) -> Block<'static> {
    commands
        .iter()
        .fold(Block::default().text(lead.to_owned()), |block, command| {
            block.command((*command).to_owned())
        })
}

/// What this machine's key opens with, as `status`'s `lock` row records it: a passphrase without its
/// article, Touch ID with how it reads here where that is not live. The bare read's first sentence reads the
/// same [`Locks`].
pub(crate) fn key_locks(locks: Locks) -> &'static str {
    match locks {
        Locks::None => "none",
        Locks::Passphrase => "passphrase",
        Locks::TouchId(Some(Health::Live)) => "Touch ID, on this Mac only",
        Locks::TouchId(Some(Health::Dead)) => "Touch ID (does not open on this Mac now)",
        Locks::TouchId(Some(Health::Unchecked)) => "Touch ID (cannot be checked now)",
        Locks::TouchId(None) => "Touch ID (opens only on the Mac that set it)",
        Locks::Both(Some(Health::Live)) => "Touch ID or a passphrase",
        Locks::Both(Some(Health::Dead)) => {
            "Touch ID (does not open on this Mac now) or a passphrase"
        }
        Locks::Both(Some(Health::Unchecked)) => "Touch ID (cannot be checked now) or a passphrase",
        Locks::Both(None) => "Touch ID (opens only on the Mac that set it) or a passphrase",
    }
}

/// What a root opens with, as `status`'s root `lock` row says it: a root always keeps its passphrase, so a
/// Touch ID lock reads as beside it.
pub(crate) fn root_locks(locks: Locks) -> &'static str {
    match locks {
        // A sealed root file read here holds its passphrase; a plain one is never read as a root.
        Locks::None | Locks::Passphrase => key_locks(Locks::Passphrase),
        Locks::TouchId(health) | Locks::Both(health) => key_locks(Locks::Both(health)),
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
    } else if let Some(short) = report.downcast_ref::<TouchIdNotAdded>() {
        // The key is made, so it is shown, with the failure; the run fails, since Touch ID was not added.
        let key = short.key.to_string();
        let step = Block::default()
            .text("Touch ID was not added.".to_owned())
            .text("To add it:".to_owned())
            .command("swoosh lock touch-id".to_owned());
        Screen::default()
            .block(made(Methods::Passphrase, &key))
            .block(failure(Some(&short.failed)))
            .block(step)
            .write(err)
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
        // The key is in place, so it is made; a failure the key store answered after it is said under it.
        Locked::Made { now, failed, .. } => Screen::default()
            .block(made(*now, key))
            .block(failure(failed.as_deref())),
        Locked::Added {
            method,
            now,
            root,
            failed,
        } => added(*method, now, *root, failed.as_deref()),
        Locked::Changed {
            method: Method::Passphrase,
            now: Now::Read(_),
            failed,
        } => one(&[
            "Changed the passphrase on this machine's key.",
            "A copy made earlier still opens with the old passphrase.",
        ])
        .block(failure(failed.as_deref())),
        Locked::Changed {
            method,
            now,
            failed,
        } => {
            let done = Block::default().text(
                match method {
                    Method::Passphrase => "Changed the passphrase on this machine's key.",
                    Method::TouchId => "Changed Touch ID on this machine's key.",
                }
                .to_owned(),
            );
            Screen::default()
                .block(unread(done, now))
                .block(failure(failed.as_deref()))
        }
        Locked::Removed {
            method,
            now,
            failed,
        } => removed(*method, now, failed.as_deref()),
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

/// The made key: what it is locked with, then the key alone.
fn made(now: Methods, key: &str) -> Block<'_> {
    Block::default()
        .text(
            match now {
                Methods::Passphrase => "Made this machine's key, locked with a passphrase:",
                Methods::TouchId => "Made this machine's key, locked with Touch ID:",
                Methods::Both => "Made this machine's key, locked with Touch ID or a passphrase:",
            }
            .to_owned(),
        )
        .row([Cell::Token(key)])
}

/// The warning after a result whose write is in place though the key store answered `failed` after it, so
/// the person knows the write may not survive a power cut; no block where nothing failed.
fn failure(failed: Option<&str>) -> Block<'_> {
    failed.map_or_else(Block::default, |failed| {
        Block::default()
            .head(
                Style::WARNING,
                "warning:",
                "the key file was written, but a step after it failed".to_owned(),
            )
            .column(FAILURE_COLUMN)
            .row([Cell::Word("failure"), Cell::Token(failed)])
    })
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
/// back, neither line can be said. A failure after the write is said after what was done, before the step.
fn added<'a>(method: Methods, now: &'a Now, root: Root, failed: Option<&'a str>) -> Screen<'a> {
    let done = Block::default().text(format!(
        "Added {} to this machine's key.",
        match method {
            Methods::Passphrase => "a passphrase",
            Methods::TouchId => "Touch ID",
            Methods::Both => "Touch ID and a passphrase",
        }
    ));
    let Now::Read(locks) = now else {
        return Screen::default()
            .block(unread(done, now))
            .block(failure(failed));
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
    Screen::default()
        .block(opens(done, *locks))
        .block(failure(failed))
        .block(step)
}

/// The screen for a lock taken off: which, what the key opens with now, and, where a lock is left, that a
/// copy of the file made before still opens with the one taken off, since removing a lock reaches no copy;
/// then a failure after the write.
fn removed<'a>(method: Method, now: &'a Now, failed: Option<&'a str>) -> Screen<'a> {
    let done = Block::default().text(format!(
        "Removed {} from this machine's key.",
        match method {
            Method::Passphrase => "the passphrase",
            Method::TouchId => "Touch ID",
        }
    ));
    let Now::Read(locks) = now else {
        return Screen::default()
            .block(unread(done, now))
            .block(failure(failed));
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
    Screen::default().block(done).block(failure(failed))
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
