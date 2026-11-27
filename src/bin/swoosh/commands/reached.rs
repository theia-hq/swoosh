//! Where a revoke landed, as it prints: one block that names the revoke, then a row per place it reached.
//!
//! The first row, `this machine   blocks it now`, is the one claim a revoke makes before any root step, so
//! it is never printed from what was asked: only a [`Blocked`] prints it, and only [`Blocked::read`] makes
//! one, from `<home>/revoked` read back after the write. A screen built before the write, or after the
//! file lost the entry, cannot exist; the run refuses instead. The partial landing ([`Blocked::partway`])
//! is the same block with the root step's reason in its second row, so the person compares one screen with
//! the other and sees the missing row.

use std::io;

use nauthy::Revocation;
use swoosh::home::Home;
use swoosh::reach_report::{Missed, Reach, Why};
use swoosh::root::{Date, RootError};

use crate::commands::status::report::COLUMN;
use crate::screen::{Block, Cell, Screen};

/// What a revoke took back, as its screen names it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Revoked {
    /// A device, a person or a key, by the name the person typed it as: `me/laptop`, `bob`.
    Named(String),
    /// A link: never printed, since a link is a secret; a command to run again names it `<link>`.
    Link,
}

impl Revoked {
    /// The target as its lines name it.
    fn name(&self) -> &str {
        match self {
            Self::Named(name) => name,
            Self::Link => "the link",
        }
    }

    /// The target as a command to run again takes it: a link as a placeholder, never the secret itself.
    fn typed(&self) -> &str {
        match self {
            Self::Named(name) => name,
            Self::Link => "<link>",
        }
    }
}

/// Proof that this machine's `revoked` holds every entry a revoke wrote, read back after the write. The
/// only thing that prints `this machine   blocks it now`.
#[derive(Debug)]
pub(crate) struct Blocked {
    target: Revoked,
}

impl Blocked {
    /// Read `<home>/revoked` back and hold `entries` against it. A file that cannot be read, or that lacks
    /// any entry, refuses: no screen says this machine blocks what the file does not hold. Nothing written
    /// refuses too, since an empty set holds against any file.
    pub(crate) fn read(home: &Home, target: Revoked, entries: &[Revocation]) -> eyre::Result<Self> {
        let held = !entries.is_empty()
            && match swoosh::revoked::open(home) {
                Ok(revoked) => entries.iter().all(|entry| match entry {
                    Revocation::Key(key) => revoked.is_revoked_key(key),
                    Revocation::Id(id) => revoked.is_revoked_any([id]),
                }),
                Err(error) => {
                    tracing::debug!(%error, "revoked could not be read back");
                    false
                }
            };
        if !held {
            eyre::bail!(
                "this command could not confirm that {} is blocked here\n  To see what is revoked:\n    \
                 swoosh status",
                target.name()
            );
        }
        Ok(Self { target })
    }

    /// The screen for where the revoke reached, on `err`: the revoke and its rows, each only where it has
    /// a value, then what follows from them a blank line below.
    pub(crate) fn landed(&self, reach: &Reach, err: &mut impl io::Write) -> io::Result<()> {
        let target = self.target.name();
        let (took, silent, refused) = match reach {
            Reach::Published { took, missed, .. } => (
                took.join(", "),
                named(missed, Why::Silent),
                named(missed, Why::Refused),
            ),
            Reach::Held { missed, .. } => {
                (String::new(), String::new(), named(missed, Why::Refused))
            }
            Reach::Complete | Reach::Behind | Reach::LocalOnly { .. } => Default::default(),
        };
        let here = Block::default()
            .column(COLUMN)
            .text(format!("Revoked {target}."))
            .row([Cell::Word("this machine"), Cell::Word("blocks it now")]);
        let after = Block::default();
        let (rows, after) = match reach {
            Reach::Complete => (
                here.row([
                    Cell::Word("your devices"),
                    Cell::Word("none ever admitted it"),
                ]),
                after,
            ),
            Reach::Published { until, .. } => {
                let rows = [
                    ("has it", &took),
                    ("did not answer", &silent),
                    ("refused it", &refused),
                ]
                .into_iter()
                .filter(|(_, names)| !names.is_empty())
                .fold(here, |block, (label, names)| {
                    block.row([Cell::Word(label), Cell::Names(names)])
                });
                let after = if silent.is_empty() {
                    after
                } else {
                    after.text("A device that did not answer gets it on its next sync.".into())
                };
                let after = refused_line(after, &refused, target);
                let after = match until {
                    None => after,
                    Some(until) => after
                        .text(format!("A device that never syncs admits it until {}.", Date(*until)))
                        .text(
                            "Anyone who shared with your root admits your devices until each one's date."
                                .into(),
                        )
                        .text("Tell them.".into()),
                };
                (rows, after)
            }
            Reach::Held { .. } => {
                let rows = here.row([Cell::Word("your devices"), Cell::Word("none has it yet")]);
                let rows = if refused.is_empty() {
                    rows
                } else {
                    rows.row([Cell::Word("refused it"), Cell::Names(&refused)])
                };
                let after = after.text(
                    "They learn of it at your next swoosh sync, or while swoosh serve runs here."
                        .into(),
                );
                (rows, refused_line(after, &refused, target))
            }
            Reach::Behind => (
                behind(Block::default().text(format!(
                    "Revoked {target} on this machine, but nothing was published."
                ))),
                after,
            ),
            Reach::LocalOnly { until } => (
                here.row([
                    Cell::Word("your devices"),
                    Cell::Word("not told; your root is not here"),
                ]),
                after
                    .text(format!(
                        "Your other devices admit it until {}.",
                        Date(*until)
                    ))
                    .text("To block it everywhere, run this where your root is kept:".into())
                    .command(format!("swoosh revoke {}", self.target.typed()))
                    .text("Or, with a copy of your root:".into())
                    .command(format!(
                        "swoosh revoke {} --root <dir>",
                        self.target.typed()
                    )),
            ),
        };
        print(Screen::default().block(rows).block(after), err)
    }

    /// The line for a link whose device your root revoked already: blocked here, and no further, so no
    /// screen of rows follows. Held behind the read-back like the screen, so it cannot print before it.
    pub(crate) fn already(&self, err: &mut impl io::Write) -> io::Result<()> {
        writeln!(err, "revoked the link: {ALREADY}")
    }

    /// The line for a root that was never this machine's own, a contact's or one it does not know, once its
    /// latch reads back: revoked here, for good.
    pub(crate) fn for_good(&self, err: &mut impl io::Write) -> io::Result<()> {
        writeln!(err, "revoked {} here for good.", self.target.name())
    }

    /// The line for the root this machine was a device of, once it has left and its latch reads back: left,
    /// for good.
    pub(crate) fn left(&self, err: &mut impl io::Write) -> io::Result<()> {
        writeln!(err, "left {} for good.", self.target.name())
    }

    /// The refusal when the root step stops after this machine's block: the same two rows as the
    /// success screen, the second saying why your devices were not told, then what finishes it. One
    /// reason per cause, since each asks something different of the person. Exit 1, no success line.
    pub(crate) fn partway(&self, error: RootError) -> eyre::Report {
        let rerun = format!("  swoosh revoke {}", self.target.typed());
        let (told, action) = match error {
            RootError::NoTerminalToUnlock => (
                "not told; no terminal to ask for your root's passphrase",
                format!(
                    "To finish, run this again at a terminal:\n{rerun}\n\nOver swoosh ssh, add -t after --."
                ),
            ),
            // A third wrong passphrase, or a prompt that ended without one.
            RootError::Prompt(_) => (
                "not told; your root was not unlocked",
                format!("To finish, run this again:\n{rerun}"),
            ),
            RootError::NotOnThisMachine => (
                "not told; your root is not on this machine",
                format!("To finish, run this where your root is kept:\n{rerun}"),
            ),
            RootError::NoRootHere => (
                "not told; this machine holds no root",
                format!("To finish, run this where your root is kept:\n{rerun}"),
            ),
            // The cause names its own fix, on its own lines: a cause flattened into the row would run its
            // sentences, and any head it has, into one value.
            other => (
                "not told",
                other
                    .to_string()
                    .lines()
                    .map(|line| format!("  {line}"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            ),
        };
        self.partial(told, &action)
    }

    /// The refusal when the block landed and a `swoosh serve` here could not be reached before the root
    /// step: the partial landing, with `report`, what stopped it, on its own lines.
    pub(crate) fn unreached(&self, report: &eyre::Report) -> eyre::Report {
        let cause: Vec<_> = format!("{report:#}")
            .lines()
            .map(|line| format!("  {line}"))
            .collect();
        let action = format!(
            "{}\n\nTo finish, run this again:\n  swoosh revoke {}",
            cause.join("\n"),
            self.target.typed()
        );
        self.partial(
            "not told; the swoosh serve here could not be reached",
            &action,
        )
    }

    /// The partial landing's screen: the head, the two rows with `told` in the second, then `action` a
    /// blank line below.
    fn partial(&self, told: &'static str, action: &str) -> eyre::Report {
        let rows = Block::default()
            .column(COLUMN)
            .row([Cell::Word("this machine"), Cell::Word("blocks it now")])
            .row([Cell::Word("your devices"), Cell::Word(told)]);
        let mut printed = Vec::new();
        if let Err(error) = Screen::default().block(rows).write(&mut printed) {
            return error.into();
        }
        let rows = String::from_utf8_lossy(&printed);
        eyre::eyre!(
            "{} is blocked on this machine only\n{rows}\n{action}",
            self.target.name()
        )
    }
}

/// What a link whose device your root revoked already says after "revoked the link: "
/// ([`Blocked::already`]).
const ALREADY: &str = "blocked here. Your root revoked the device it stands for already.";

/// What `invite` prints when a newer list on your devices kept its act back: the invite is made, and
/// nothing was published.
pub(crate) fn invite_behind(device: &str, err: &mut impl io::Write) -> io::Result<()> {
    let block = Block::default().text(format!(
        "The invite for {device} is made, but nothing was published."
    ));
    print(Screen::default().block(behind(block)), err)
}

/// What `invite` prints after renewing another device by name: where the renewal reached, a row per
/// place, then how the device takes it if it reaches none of them. Nothing for a reach no renewal makes
/// (`Complete`, `LocalOnly`), nor for `Behind`, whose screen [`invite_behind`] prints.
pub(crate) fn renewed(
    device: &str,
    until: u64,
    reach: &Reach,
    err: &mut impl io::Write,
) -> io::Result<()> {
    let (took, missed) = match reach {
        Reach::Published { took, missed, .. } => (took.join(", "), missed.as_slice()),
        Reach::Held { missed, .. } => (String::new(), missed.as_slice()),
        Reach::Behind | Reach::Complete | Reach::LocalOnly { .. } => return Ok(()),
    };
    let (silent, refused) = (named(missed, Why::Silent), named(missed, Why::Refused));
    let rows = [
        ("has it", &took),
        ("did not answer", &silent),
        ("refused it", &refused),
    ]
    .into_iter()
    .filter(|(_, names)| !names.is_empty())
    .fold(
        Block::default()
            .column(COLUMN)
            .text(format!("Renewed {device} until {}.", Date(until))),
        |block, (label, names)| block.row([Cell::Word(label), Cell::Names(names)]),
    );
    let after = if silent.is_empty() {
        Block::default()
    } else {
        Block::default().text(
            "A device that did not answer picks it up when it next reaches your devices.".into(),
        )
    };
    let after = after.text(format!(
        "If {device} cannot reach your devices, paste the invite into swoosh join on it."
    ));
    print(Screen::default().block(rows).block(after), err)
}

/// `block` with what every act a newer list kept back says next: why, and the sync that catches this
/// copy up.
fn behind(block: Block<'_>) -> Block<'_> {
    block
        .text("Your devices hold a newer list than this copy of your root.".into())
        .text("To catch this copy up first:".into())
        .command("swoosh sync".into())
        .text("Then run this again.".into())
}

/// `after` with the line for devices that refused the cut, where any did: they are told apart from the
/// ones that did not answer, since a refusal may leave the device admitting the target.
fn refused_line<'a>(after: Block<'a>, refused: &str, target: &str) -> Block<'a> {
    if refused.is_empty() {
        return after;
    }
    after.text(format!(
        "A device that refused it may still admit {target}."
    ))
}

/// The names of the devices that missed the cut for `why`, a comma apart; empty when none did.
fn named(missed: &[Missed], why: Why) -> String {
    missed
        .iter()
        .filter(|device| device.why == why)
        .map(|device| device.name.as_str())
        .collect::<Vec<_>>()
        .join(", ")
}

/// `screen` written whole onto `err`, unstyled: every value here is swoosh's own or a device name.
fn print(screen: Screen<'_>, err: &mut impl io::Write) -> io::Result<()> {
    let mut printed = Vec::new();
    screen.write(&mut printed)?;
    err.write_all(&printed)
}

#[cfg(test)]
#[path = "reached_tests.rs"]
mod reached_tests;
