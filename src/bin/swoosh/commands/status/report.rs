//! The bare `swoosh status`: what this machine is, read from its own files.
//!
//! It never dials, never asks for a passphrase and never writes: the root is read through
//! [`Root::inspect`], which looks only at the key file's header and the signed records beside it. A home
//! with no key prints `none yet` on its `key` row; the first verb that needs a key makes it.
//!
//! The report goes to stdout whole, as blocks a blank line apart: `this machine`, `your root`, `reach`,
//! `internal routes`, `devices`, `contacts`, `links you shared`, then the lines that say what to do. Every
//! notice (a running `serve` it could not read) goes to stderr, so a script that reads the report reads only
//! it.

use std::io;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost::NodeId;
use keystore::{Health, KeyFile, Stored};
use nauthy::{Denylist, VerifyKey};
use swoosh::contacts::{Contacts, ContactsStore, DeviceLabel, ME, Source};
use swoosh::credential::short;
use swoosh::escape::{Escaped, EscapedPath};
use swoosh::grants::{ANYONE, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::identity::Locks;
use swoosh::passphrase::{Asked, Prompt, Terminal};
use swoosh::root::{Date, Inspected, Root, RootPlace};
use swoosh::root_key::RootKey;
use swoosh::roster::{Member, RevokedDevice};
use swoosh::serve::{
    CONTROL_SERVE_SERVICE, LOOKUP_ROOT_SERVICE, RENEWAL_SERVICE, SYNC_SERVICE, control,
};
use swoosh::standing::{Standing, StandingError};
use swoosh::{badge, roster, standing, sync, touch};
use tightbeam::identity::AsVerifyKey as _;

use crate::commands::lock::{key_locks, root_locks};
use crate::commands::serve::{ReachRows, Scope};
use crate::commands::service_state::{ReadError, ReadMode, ServiceState};
use crate::screen::{Block, Cell, Paint, Screen};

/// Where the head blocks' values start, the column the `reach` block and serve's banner use.
const COLUMN: usize = 17;

/// What bare `status` prints on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Print {
    /// The whole report.
    Report,
    /// This machine's key alone (`--key`).
    Key,
}

/// `status --key`'s refusal on a home with no key: `status` makes none.
pub(crate) const NO_KEY: &str =
    "this machine has no key yet; to make one and print it: swoosh join";

/// What a machine that is no device of a root is, beside `this machine`.
const NOT_A_DEVICE: &str = "not one of your devices yet";

/// The ways forward a machine that is no device of a root prints, last.
const NOT_A_DEVICE_STEPS: [&str; 2] = [
    "to join yours, paste its invite into: swoosh join",
    "to make your root on this machine: swoosh invite <name> <key>",
];

/// Print what `print` asks for. Writes nothing to the home.
pub(crate) async fn run(home: &Home, print: Print) -> eyre::Result<()> {
    run_to(home, print, &mut std::io::stdout(), &mut std::io::stderr()).await
}

/// [`run`], printing the report or the key on `out` and every other line on `err`.
pub(crate) async fn run_to(
    home: &Home,
    print: Print,
    out: &mut impl Paint,
    err: &mut impl std::io::Write,
) -> eyre::Result<()> {
    let key = KeyFile::new(home.key()).load()?;
    if print == Print::Key {
        let Some(key) = key else {
            eyre::bail!(NO_KEY);
        };
        writeln!(
            out,
            "{}",
            swoosh::identity::key_of(&KeyFile::new(home.key()), &key)?
        )?;
        return Ok(());
    }
    let report = Report::gather(home, key.as_ref(), unix_now()).await?;
    for notice in &report.notices {
        writeln!(err, "{notice}")?;
    }
    report.write(out)?;
    Ok(())
}

/// Everything bare `status` says, gathered from the home's files before anything prints.
#[derive(Debug)]
pub(crate) struct Report {
    /// This machine's key and its locks, a Touch ID lock with its health as the enclave reads it with no
    /// dialog; `None` when the home has no key.
    key: Option<(NodeId, Locks)>,
    /// The locks of the root kept here, read from its key file's header the same way; `None` where no root
    /// header was read, so no line claims a root this read did not see.
    root: Option<Locks>,
    /// The home's directory, escaped.
    home: String,
    /// What this machine is, beside `this machine`: `me/<name>` once a list names it, else its name or key
    /// with its standing's date, or that it is no device yet. `None` claims nothing there.
    standing: Option<String>,
    /// The `your root` block, where this read saw a root.
    your_root: Option<YourRoot>,
    sections: Vec<Section>,
    /// The `serving` row's value; present on every home with a key.
    serving: Option<String>,
    /// The `reach` block's rows, while a `serve` answers here.
    reach: Option<ReachRows>,
    /// Whether the `internal routes` block prints: only while a `serve` answers here.
    internal: bool,
    /// The lines that say what to do, last, a block each.
    nags: Vec<Nag>,
    /// What goes to stderr.
    pub(crate) notices: Vec<String>,
}

/// The root this machine trusts: where it is kept, its key, and the locks it opens with where it is kept here.
#[derive(Debug)]
struct YourRoot {
    /// `on this machine` or `on another machine`.
    place: &'static str,
    /// `root:<key>`, whole, the key `join` asks a person to compare.
    key: String,
    /// What the root opens with, read from a header this read saw; `None` on a device, where it is not here.
    lock: Option<&'static str>,
}

/// One titled table of rows. Printed only when it has a row.
#[derive(Debug)]
struct Section {
    title: &'static str,
    /// Said beside the title, such as when a device's list was last synced.
    note: Option<String>,
    rows: Vec<[String; 4]>,
}

/// A block after the others that says what to do.
#[derive(Debug)]
enum Nag {
    /// Sentences, and the commands they name, held to the screen law.
    Said(Vec<Said>),
    /// Lines another module words for every command that prints them, printed as it gives them so `status`
    /// never says them apart from the rest.
    Given(String),
}

/// One line of a [`Nag::Said`].
#[derive(Debug)]
enum Said {
    /// A sentence, flush left.
    Line(String),
    /// A command to type, alone on its line at indent two.
    Command(String),
}

impl Nag {
    /// The nag's sentences and commands, from `lines`.
    fn said(lines: impl IntoIterator<Item = Said>) -> Self {
        Self::Said(lines.into_iter().collect())
    }
}

impl Said {
    fn line(text: impl Into<String>) -> Self {
        Self::Line(text.into())
    }

    fn command(text: impl Into<String>) -> Self {
        Self::Command(text.into())
    }
}

impl Report {
    /// Read the home: its standing, the root's records or the update it holds, its contacts, the links it
    /// shared, and what a running `serve` serves.
    pub(crate) async fn gather(home: &Home, key: Option<&Stored>, now: u64) -> eyre::Result<Self> {
        Self::gather_with(home, key, now, &Terminal).await
    }

    /// [`gather`](Self::gather), asking `prompt` how each `touch-id` lock reads: never a dialog.
    pub(crate) async fn gather_with(
        home: &Home,
        key: Option<&Stored>,
        now: u64,
        prompt: &impl Prompt,
    ) -> eyre::Result<Self> {
        let root = match KeyFile::strict(home.root_key()).load() {
            Ok(Some(stored @ Stored::Locked(_))) => Some(Locks::of(&stored, prompt)),
            _ => None,
        };
        let mut report = Self {
            key: key
                .map(|key| {
                    swoosh::identity::key_of(&KeyFile::new(home.key()), key)
                        .map(|node| (node, Locks::of(key, prompt)))
                })
                .transpose()?,
            root,
            home: EscapedPath(home.dir()).to_string(),
            standing: None,
            your_root: None,
            sections: Vec::new(),
            serving: None,
            reach: None,
            internal: false,
            nags: Vec::new(),
            notices: Vec::new(),
        };
        let store = ContactsStore::open(home).await?;
        let contacts = store.contacts();
        // An act that did not finish, or a home whose records disagree, says so on the last line.
        let mut last = None;
        match key {
            None => match Standing::read(home).await {
                // A `leave` from a restored home where the root is kept leaves the root half made, and the
                // next `invite` finishes it under the key it makes: the same line as a mint that stopped.
                Ok(Standing::InterruptedMint { .. }) => {
                    last = Some(Nag::Given(standing::UNFINISHED_MINT.to_owned()));
                }
                // A torn `root.key` says so first: nothing a restored home's lines name can mend it.
                Err(StandingError::Damaged(
                    what @ standing::Disagreement::UnreadableRoot { .. },
                )) => {
                    last = Some(Nag::Given(standing::damaged_line(&what)));
                }
                // A file that could not be read, or a root key refused for its modes, its owner or not
                // being a file, says why, as it does on a home with a key.
                Err(
                    error @ (StandingError::Read { .. }
                    | StandingError::Revoked(_)
                    | StandingError::Loose(_)
                    | StandingError::NotAFile { .. }),
                ) => {
                    return Err(error.into());
                }
                _ if restored(home) => report.nags.push(restored_lines(home).await?),
                _ => report.not_a_device(),
            },
            Some(_) => match Standing::read(home).await {
                Err(StandingError::Damaged(what)) => {
                    last = Some(Nag::Given(standing::damaged_line(&what)));
                }
                Err(other) => return Err(other.into()),
                Ok(Standing::InterruptedMint { .. }) => {
                    last = Some(Nag::Given(standing::UNFINISHED_MINT.to_owned()));
                }
                Ok(Standing::Unpinned) => report.not_a_device(),
                Ok(standing) => {
                    report.standing(home, standing, now).await?;
                }
            },
        }
        // This machine's key under a `touch-id` lock that does not open here says how to mend it.
        if let Some((
            _,
            locks @ (Locks::TouchId(Some(Health::Dead)) | Locks::Both(Some(Health::Dead))),
        )) = report.key
        {
            let file = KeyFile::new(home.key());
            let passphrase = matches!(locks, Locks::Both(_));
            report.nags.push(Nag::Given(
                touch::Lines::of(Asked::MachineKey, &file, passphrase).dead(),
            ));
        }
        // A key under `touch-id` alone beside a root kept here: the state a root made or restored beside it
        // leaves, said until the passphrase goes beside the touch.
        if swoosh::identity::touch_id_alone_beside_root(home) {
            report.nags.push(Nag::Given(
                swoosh::identity::TOUCH_ID_ALONE_BESIDE_ROOT.to_owned(),
            ));
        }
        // A root kept here whose machine's key is revoked still works; the devices refuse this machine.
        if let Ok(Standing::HoldsRoot { pin, .. }) = Standing::read(home).await
            && swoosh::root::own_key_revoked(home, pin.verify_key()?)?
        {
            report.nags.push(Nag::said([
                Said::line("This machine's key was revoked, so your devices no longer admit it."),
                Said::line("Your root still works here."),
            ]));
        }
        // A revoke of that root that stopped after its latch; running it again deletes it. The whole key,
        // since the line gives a command.
        if let Some(root) = Standing::revoked_root(home).await? {
            report.nags.push(Nag::said([
                Said::line("A revoked root is still on this machine; to delete it:"),
                Said::command(format!("swoosh revoke root:{root}")),
            ]));
        }
        report.sections.push(contacts_section(contacts));
        report.sections.push(links_section(home, now).await?);
        if key.is_some() {
            let mut serving = report.serving_line(home).await;
            if let Some(root) = swoosh::home::ServeLock::recorded(home).admit
                && swoosh::home::serve_running(home).await
            {
                serving = admitting(&serving, root);
            }
            report.serving = Some(serving);
        }
        if roster_fork_held(home) {
            report.nags.push(Nag::said([
                Said::line(
                    "Two copies of your root have been used: your devices hold two different lists.",
                ),
                Said::line("Keep one copy; the next time you use it, it settles this."),
                Said::line("If you did not use two copies, your root may be stolen:"),
                Said::command("swoosh revoke --help"),
            ]));
        }
        report.nags.extend(last);
        Ok(report)
    }

    /// A machine that is no device of a root: says so beside `this machine`, and its ways forward last.
    fn not_a_device(&mut self) {
        self.standing = Some(NOT_A_DEVICE.to_owned());
        self.nags
            .push(Nag::said(NOT_A_DEVICE_STEPS.map(Said::line)));
    }

    /// The root's line, this machine's line, the devices, and the lines about renewing, on a device of a
    /// root: one that keeps it or one that does not.
    async fn standing(&mut self, home: &Home, standing: Standing, now: u64) -> eyre::Result<()> {
        let mut carrying = Vec::new();
        let (rows, until) = match standing {
            Standing::Unpinned | Standing::InterruptedMint { .. } => return Ok(()),
            Standing::HoldsRoot { pin, until } => {
                let inspected = Root::inspect(home, RootPlace::Home).await?;
                // Said only from a root header this read saw: one it could not read claims nothing here.
                self.your_root = self.root.map(|locks| YourRoot {
                    place: "on this machine",
                    key: format!("root:{pin}"),
                    lock: Some(root_locks(locks)),
                });
                // A lock that does not open says how to mend it, last; one that cannot be checked says
                // nothing more than its line.
                if let Some(Locks::TouchId(Some(Health::Dead)) | Locks::Both(Some(Health::Dead))) =
                    self.root
                {
                    let file = KeyFile::strict(home.root_key());
                    self.nags.push(Nag::Given(
                        touch::Lines::of(Asked::Root, &file, true).dead(),
                    ));
                }
                let rows = held_rows(&inspected);
                self.devices(None, &rows, now);
                // Due by the same test the renewal runs, which skips a device it cannot renew.
                let due: Vec<VerifyKey> = inspected.due(now).map(|row| row.node).collect();
                self.nags.extend(
                    rows.iter()
                        .filter(|row| !row.revoked && due.contains(&row.key))
                        .filter_map(|row| renew_line(row, "")),
                );
                carrying = inspected
                    .rows()
                    .iter()
                    .filter_map(|row| invite_ends(row, now))
                    .collect();
                (rows, until)
            }
            Standing::Device { pin, until } => {
                self.your_root = Some(YourRoot {
                    place: "on another machine",
                    key: format!("root:{pin}"),
                    lock: None,
                });
                let rows = synced_rows(home, pin);
                let note = format!("(as of the last sync, {})", sync::ago(home));
                self.devices(Some(note), &rows, now);
                self.nags.extend(
                    rows.iter()
                        .filter(|row| due(row, now).is_some())
                        .filter_map(|row| renew_line(row, " --root <dir>")),
                );
                (rows, until)
            }
        };
        let until = unix(until);
        let Some((key, _)) = self.key.as_ref() else {
            return Ok(());
        };
        let own = key.verify_key().ok();
        let own_row = rows.iter().find(|row| Some(row.key) == own);
        // Named by the list once it lands. A line that gives a command takes only that name.
        let name = named(home, own_row).await;
        // Before a list names it, the lines that say what to do call it `This machine`: the title the reader
        // has already seen for it, at a sentence's start.
        let me = name
            .as_ref()
            .map_or_else(|| "This machine".to_owned(), |name| format!("me/{name}"));
        self.standing = Some(match own_row {
            // The list's row says its date; the title says only the name it gives.
            Some(row) => format!("me/{}", row.label),
            None => {
                // Before the list lands, the title names it by the name its invite gave it: a hint that only
                // this line prints.
                let hinted = name.clone().or_else(|| {
                    swoosh::joining::InvitedBy::read(home).and_then(|invited| invited.name)
                });
                let shown = hinted.map_or_else(|| short(&key), |name| format!("me/{name}"));
                // A date already passed reads as the row's does: `ended`, never `until`.
                if until <= now {
                    format!("{shown}, ended {}", Date(until))
                } else {
                    format!("{shown}, your device until {}", Date(until))
                }
            }
        });
        if own_row.is_some_and(|row| row.revoked) {
            self.nags.push(Nag::said([
                Said::line("This machine is no longer one of your devices: your root revoked it."),
                Said::line("To join again:"),
                Said::command("swoosh leave --new-key"),
                Said::line("Then:"),
                Said::command("swoosh join"),
            ]));
            return Ok(());
        }
        let name = name.map_or_else(|| "<name>".to_owned(), |name| name.to_string());
        if until <= now {
            self.nags.push(Nag::said([
                Said::line(format!(
                    "{me} ended on {}; your devices refuse it.",
                    Date(until)
                )),
                Said::line("Where your root is kept:"),
                Said::command(format!("swoosh invite {name}")),
                Said::line(
                    "This machine picks up the renewal the next time it reaches one of your devices.",
                ),
                Said::line("To pick it up now:"),
                Said::command("swoosh sync"),
            ]));
        } else if until - now <= badge::DEVICE_WARN_WINDOW.as_secs() {
            let renews = own_row.is_some_and(|row| {
                swoosh::root::renew_by(row.until, row.duration, row.seeded).is_some()
            });
            let mut said = vec![Said::line(format!("{me} ends on {}.", Date(until)))];
            if renews {
                said.push(Said::line(
                    "It renews the next time you use your root, when this machine next syncs.",
                ));
            } else {
                said.extend([
                    Said::line("It is not renewed on its own."),
                    Said::line("With your root:"),
                    Said::command(format!("swoosh invite {name}")),
                ]);
            }
            self.nags.push(Nag::Said(said));
        }
        self.nags.extend(carrying);
        Ok(())
    }

    /// The devices table: every row the root has, revoked ones too; the root itself is never a row. A live
    /// row leaves the state column blank.
    fn devices(&mut self, note: Option<String>, rows: &[DeviceRow], now: u64) {
        let own = self.key.as_ref().and_then(|(key, _)| key.verify_key().ok());
        let rows = rows
            .iter()
            .map(|row| {
                let (state, date) = if row.revoked {
                    ("revoked".to_owned(), String::new())
                } else if row.until <= now {
                    (format!("ended {}", Date(row.until)), String::new())
                } else {
                    let state = match due(row, now) {
                        _ if Some(row.key) == own => "this machine".to_owned(),
                        Some(by) => format!("renew by {}", Date(by)),
                        None => String::new(),
                    };
                    (state, format!("until {}", Date(row.until)))
                };
                // The key column tells apart a revoked device and a live one that took its name (O2: the
                // line names the machine).
                [format!("me/{}", row.label), short(&row.key), state, date]
            })
            .collect();
        self.sections.push(Section {
            title: "devices",
            note,
            rows,
        });
    }

    /// The validated local list, or the bound names while the local resident runs. File
    /// refusals report the file, never a daemon failure; neither changes status's successful exit.
    async fn serving_line(&mut self, home: &Home) -> String {
        match ServiceState::read(home, ReadMode::Membership).await {
            Ok(state) => {
                // Only a `serve` that answered binds the routes and says how it is reached; an unknown one
                // is said on the `serving` row.
                if state.resident_present() {
                    self.reach = state.reach().map(|reach| ReachRows::of(reach, Scope::All));
                    self.internal = true;
                }
                serving(&state)
            }
            Err(ReadError::Daemon(error)) => self.serving_unknown(&error),
            Err(error) => {
                self.notices.push(serving_file_notice(home, error));
                "unknown".to_owned()
            }
        }
    }

    /// A `serve` is there and could not be read: the row says so, and why goes to stderr.
    fn serving_unknown(&mut self, why: &dyn core::fmt::Display) -> String {
        self.notices
            .push(format!("could not read the running swoosh serve.\n{why}"));
        "unknown".to_owned()
    }

    /// Write the report on `out` in one write: its blocks a blank line apart, an empty block left out, then
    /// the lines that say what to do. A line another module words is written as it gives it, in its place
    /// among them.
    pub(crate) fn write(&self, out: &mut impl Paint) -> io::Result<()> {
        let mut written = Buffer {
            bytes: Vec::new(),
            styled: out.styled(),
        };
        let key = self.key.as_ref().map(|(key, _)| key.to_string());
        let mut screen = Screen::default()
            .block(self.head(key.as_deref()))
            .block(self.your_root())
            .block(
                self.reach
                    .as_ref()
                    .map_or_else(Block::default, |rows| rows.block("reach")),
            )
            .block(if self.internal {
                internal_routes()
            } else {
                Block::default()
            });
        for section in &self.sections {
            screen = screen.block(section.block());
        }
        for nag in &self.nags {
            match nag {
                Nag::Said(lines) => screen = screen.block(said(lines)),
                Nag::Given(lines) => {
                    written.screen(&screen)?;
                    screen = Screen::default();
                    written.append(format!("{lines}\n").as_bytes());
                }
            }
        }
        written.screen(&screen)?;
        out.write_all(&written.bytes)
    }

    /// The report as plain text, as a pipe gets it.
    #[cfg(test)]
    pub(crate) fn render(&self) -> String {
        let mut out = Vec::new();
        self.write(&mut out).expect("a `Vec` takes every write");
        String::from_utf8(out).expect("the report is text")
    }

    /// `this machine`: what it is on the title row, then its key, the key's locks, what it serves, and the
    /// home, last on every home.
    fn head<'a>(&'a self, key: Option<&'a str>) -> Block<'a> {
        let block = Block::titled("this machine").column(COLUMN);
        let block = match &self.standing {
            Some(standing) => block.value(Cell::Token(standing)),
            None => block,
        };
        let block = match key.zip(self.key.as_ref().map(|(_, locks)| *locks)) {
            Some((key, locks)) => block
                .row([Cell::Word("key"), Cell::Token(key)])
                .row([Cell::Word("lock"), Cell::Word(key_locks(locks))]),
            None => block.row([Cell::Word("key"), Cell::Word("none yet")]),
        };
        let block = match &self.serving {
            Some(serving) => block.row([Cell::Word("serving"), Cell::Names(serving)]),
            None => block,
        };
        block.row([Cell::Word("home"), Cell::Escaped(&self.home)])
    }

    /// `your root`: where it is kept on the title row, then its key whole and, where it is kept here, its
    /// locks. Empty where this read saw no root.
    fn your_root(&self) -> Block<'_> {
        let Some(root) = &self.your_root else {
            return Block::default();
        };
        let block = Block::titled("your root")
            .column(COLUMN)
            .value(Cell::Word(root.place))
            .row([Cell::Word("key"), Cell::Token(&root.key)]);
        match root.lock {
            Some(lock) => block.row([Cell::Word("lock"), Cell::Word(lock)]),
            None => block,
        }
    }
}

impl Section {
    /// The table under its title, each column as wide as its widest cell; a row's empty cells at its end
    /// print nothing. Empty where it has no row, so the block drops out.
    fn block(&self) -> Block<'_> {
        if self.rows.is_empty() {
            return Block::default();
        }
        let width = |column: usize| {
            self.rows
                .iter()
                .map(|row| row[column].chars().count())
                .max()
                .unwrap_or(0)
        };
        // Each column starts two past the widest cell before it, counted over every row, so a row whose
        // later cells are empty lines up with the rest.
        let columns = (0..3).scan(2, |at, column| {
            *at += width(column) + 2;
            Some(*at)
        });
        let block = Block::titled(self.title).columns(columns);
        let block = match &self.note {
            Some(note) => block.value(Cell::Token(note)),
            None => block,
        };
        self.rows.iter().fold(block, |block, row| {
            let filled = row
                .iter()
                .rposition(|cell| !cell.is_empty())
                .map_or(0, |at| at + 1);
            block.row(row[..filled].iter().map(|cell| Cell::Token(cell)))
        })
    }
}

/// A nag's block: each sentence flush left, each command alone at indent two.
fn said(lines: &[Said]) -> Block<'_> {
    lines
        .iter()
        .fold(Block::default(), |block, line| match line {
            Said::Line(text) => block.text(text.clone()),
            Said::Command(command) => block.command(command.clone()),
        })
}

/// The report as it is built, styled as the writer it goes to is, so it reaches that writer in one write.
struct Buffer {
    bytes: Vec<u8>,
    styled: bool,
}

impl Buffer {
    /// Add `screen`'s blocks, a blank line after what is already here.
    fn screen(&mut self, screen: &Screen<'_>) -> io::Result<()> {
        let mut bytes = Self {
            bytes: Vec::new(),
            styled: self.styled,
        };
        screen.write(&mut bytes)?;
        self.append(&bytes.bytes);
        Ok(())
    }

    /// Add `bytes`, a blank line after what is already here; nothing for none.
    fn append(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        if !self.bytes.is_empty() {
            self.bytes.push(b'\n');
        }
        self.bytes.extend_from_slice(bytes);
    }
}

impl io::Write for Buffer {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.bytes.write(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl Paint for Buffer {
    fn styled(&self) -> bool {
        self.styled
    }
}

/// Whether a home with no key still holds what a device or a root leaves: a home restored from a system
/// backup, which leaves `machine/` out.
fn restored(home: &Home) -> bool {
    [home.root_pub(), home.key_cert(), home.root_key()]
        .iter()
        .any(|path| Path::exists(path))
}

/// The last lines of a home restored from a system backup. `leave` starts over and keeps a root kept here;
/// after it, `join` makes this machine a device again, and where a root is kept `invite` finishes it under
/// a new key instead. A torn `root.key` never reaches here: its damaged line comes first.
async fn restored_lines(home: &Home) -> eyre::Result<Nag> {
    const MISSING: &str =
        "This machine's key is not in this home, because system backups leave it out.";
    let kept = home.root_key().exists() && Standing::revoked_root(home).await?.is_none();
    let (stays, then) = if kept {
        (
            Some("A root kept on this machine stays."),
            "swoosh invite <name> <key>",
        )
    } else {
        (None, "swoosh join")
    };
    Ok(Nag::said(
        [Some(MISSING), stays, Some("To start over:")]
            .into_iter()
            .flatten()
            .map(Said::line)
            .chain([
                Said::command("swoosh leave"),
                Said::line("Then:"),
                Said::command(then),
            ]),
    ))
}

/// The day a live row falls due to renew, once that day has come.
fn due(row: &DeviceRow, now: u64) -> Option<u64> {
    if row.revoked || row.until <= now {
        return None;
    }
    swoosh::root::renew_by(row.until, row.duration, row.seeded).filter(|by| *by <= now)
}

/// The lines for a device due to renew: `Renew me/<name> by <date>:`, then `swoosh invite <name>`, with
/// `root` after it where the root is not on this machine. Nothing for a device that never renews on its own.
fn renew_line(row: &DeviceRow, root: &str) -> Option<Nag> {
    let by = swoosh::root::renew_by(row.until, row.duration, row.seeded)?;
    let name = &row.label;
    Some(Nag::said([
        Said::line(format!("Renew me/{name} by {}:", Date(by))),
        Said::command(format!("swoosh invite {name}{root}")),
    ]))
}

/// Typed file errors already name their path; only a command-line list error needs file context here.
/// Alternate report formatting retains the source of an I/O refusal without repeating a path.
fn serving_file_notice(home: &Home, error: ReadError) -> String {
    match error {
        ReadError::List(error) => format!(
            "{}: {:#}",
            EscapedPath(&home.serve_toml()),
            eyre::Report::new(error)
        ),
        error => format!("{:#}", eyre::Report::new(error)),
    }
}

/// Admission follows the complete list, including off marks, an empty list or an unknown one.
fn admitting(serving: &str, root: NodeId) -> String {
    format!("{serving}, admitting root:{root}")
}

/// While a serve runs, the bound names: saved ones first, in the file's order, then bound ones the file does
/// not hold, which say nothing of why they are bound. A saved name not bound is left out. `(off)` comes from
/// the file alone. A bound name the serve refuses without an off mark says so apart from `(off)`, saved or
/// not: a bare serve refuses a name removed from the file, and that must not read as plainly serving.
fn serving(state: &ServiceState) -> String {
    let saved = state.started.names();
    let bound = state.bound_names();
    let unsaved = bound
        .iter()
        .copied()
        .filter(|name| !saved.iter().any(|held| held == name));
    let names: Vec<String> = saved
        .iter()
        .map(String::as_str)
        .filter(|name| !state.resident_present() || state.contains_bound(name))
        .chain(unsaved)
        .map(|name| (name, state.refusing(name)))
        .map(|(name, refusing)| {
            let name = Escaped(name);
            if state.off.contains(name.0) {
                format!("{name} (off)")
            } else if refusing {
                format!("{name} (refusing new connections)")
            } else {
                name.to_string()
            }
        })
        .collect();
    let list = if names.is_empty() {
        "nothing".to_owned()
    } else {
        names.join(", ")
    };
    match (state.resident_present(), names.is_empty()) {
        (true, _) => list,
        (false, true) => "nothing, even when swoosh serve runs".to_owned(),
        (false, false) => format!("{list}, when swoosh serve runs"),
    }
}

/// `internal routes`: every route a `serve` binds that no entry names, in the table's order, with who
/// reaches it and what it does. Read from swoosh's own table, never the running node's catalog, so what
/// each row says it admits is what its bind enforces.
fn internal_routes() -> Block<'static> {
    control::INTERNAL
        .iter()
        .fold(Block::titled("internal routes"), |block, route| {
            block.row([
                Cell::Word(route.name),
                Cell::Word(who(route.admits)),
                Cell::Word(what(route.name)),
            ])
        })
}

/// Who reaches a route, in words: who its bind admits, never who it answers.
fn who(admits: control::Admits) -> &'static str {
    match admits {
        control::Admits::Devices | control::Admits::DevicesByKey => "your devices",
        control::Admits::Saved => "your devices, saved machines",
    }
}

/// What a route does, in words; empty for a name the table does not hold, which a test refuses.
fn what(route: &str) -> &'static str {
    match route {
        CONTROL_SERVE_SERVICE => "stops it, lists its services",
        SYNC_SERVICE => "syncs your device list",
        RENEWAL_SERVICE => "renews your devices",
        LOOKUP_ROOT_SERVICE => "says which root vouches for it",
        _ => "",
    }
}

/// One of the root's devices, from its records where the root is kept, or from the update a device holds.
#[derive(Debug)]
struct DeviceRow {
    /// Its name among `me`'s devices; for a revoked device, the name it had when it was revoked.
    label: DeviceLabel,
    key: VerifyKey,
    until: u64,
    duration: u64,
    seeded: bool,
    /// Revoked, by these records or by an update another copy of the root signed.
    revoked: bool,
}

/// This machine's name among your devices, the one `status` and serve's banner both print: its own row of
/// the list this home holds, else the name a verified list gave it. Never the name an invite carried, which
/// no list has vouched for. `None` when no list names it, or the list cannot be read.
pub(crate) async fn own_name(home: &Home, own: NodeId) -> Option<DeviceLabel> {
    let own = own.verify_key().ok()?;
    let rows = match Standing::read(home).await {
        Ok(Standing::HoldsRoot { .. }) => Root::inspect(home, RootPlace::Home)
            .await
            .map(|inspected| held_rows(&inspected))
            .unwrap_or_default(),
        Ok(Standing::Device { pin, .. }) => synced_rows(home, pin),
        _ => Vec::new(),
    };
    named(home, rows.iter().find(|row| row.key == own)).await
}

/// The name `own_row` gives this machine, else the one a verified list gave it.
async fn named(home: &Home, own_row: Option<&DeviceRow>) -> Option<DeviceLabel> {
    match own_row {
        Some(row) => Some(row.label.clone()),
        None => swoosh::renewal::own_label(home).await,
    }
}

/// Every device row of the root kept here: its list, the rows it marked revoked, then each revoked device
/// the list carries no row for. Another copy of the root, or this machine, may have revoked a device since
/// the last act here: the records as the next act would bring them forward say so before the list does.
fn held_rows(inspected: &Inspected) -> Vec<DeviceRow> {
    let device = |row: &Member, revoked| DeviceRow {
        label: row.label.clone(),
        key: row.node,
        until: row.until,
        duration: row.duration,
        seeded: row.seeded(),
        revoked,
    };
    let marked = inspected.marked().iter().map(|row| device(row, true));
    let listed: Vec<VerifyKey> = inspected
        .rows()
        .iter()
        .chain(inspected.marked())
        .map(|row| row.node)
        .collect();
    // A revoked device the list carries no row for: its key and the name it had.
    let unlisted = inspected
        .revoked_devices()
        .filter(|device| !listed.contains(&device.node))
        .map(revoked_device);
    inspected
        .rows()
        .iter()
        .map(|row| device(row, false))
        .chain(marked)
        .chain(unlisted)
        .collect()
}

/// Every device row of the list this device last synced from `pin`'s root; none when it holds none.
fn synced_rows(home: &Home, pin: NodeId) -> Vec<DeviceRow> {
    pin.verify_key()
        .ok()
        .and_then(|root| roster::held(home, root))
        .map(|update| {
            let members = update.members().iter().map(|member| DeviceRow {
                label: member.label.clone(),
                key: member.node,
                until: member.until,
                duration: member.duration,
                seeded: member.seeded(),
                revoked: false,
            });
            // A revoked device carries its key and the name it had, and no date.
            let revoked = update.revoked_devices().iter().map(revoked_device);
            members.chain(revoked).collect()
        })
        .unwrap_or_default()
}

/// A revoked device with no row: its key and the name it had.
fn revoked_device(device: &RevokedDevice) -> DeviceRow {
    DeviceRow {
        label: device.label.clone(),
        key: device.node,
        until: 0,
        duration: 0,
        seeded: false,
        revoked: true,
    }
}

/// For a device whose key came in its invite, in the 14 days before that invite ends: what to do if it
/// starts from that invite each time. Read from `invite_until`, never `until`: a bound renewal moves the
/// row's date, not the date its invite stops working.
fn invite_ends(row: &Member, now: u64) -> Option<Nag> {
    let ends = row.invite_until;
    let warns = row.seeded()
        && ends.saturating_sub(badge::DEVICE_WARN_WINDOW.as_secs()) <= now
        && now < ends;
    let name = &row.label;
    warns.then(|| {
        Nag::said([
            Said::line(format!(
                "me/{name}'s key came in its invite, which ends on {}.",
                Date(ends)
            )),
            Said::line("If it starts from that invite each time (a CI job, for example), run:"),
            Said::command(format!("swoosh invite {name} --new-key")),
            Said::line("Then set its secret again."),
        ])
    })
}

/// `contacts`: each person with their root, and each machine saved by hand. Your own devices are under
/// `devices`, never here. A machine's row says `one machine`, so a person's row and a machine's differ by
/// words as well as by the key's shape (`root:` or a machine's bare key).
fn contacts_section(contacts: &Contacts) -> Section {
    let mut rows = Vec::new();
    for person in contacts.petnames().filter(|person| person.as_str() != ME) {
        if let Some(root) = contacts.signet(person) {
            // A learned root is only as trustworthy as the device it came from, so the row names it.
            let learned = match &root.source {
                Source::Learned(device) => format!("learned from {person}/{device}"),
                Source::Explicit => String::new(),
            };
            rows.push([
                person.to_string(),
                RootKey::from(root.node).short(),
                learned,
                String::new(),
            ]);
        }
        for (label, key) in contacts.devices(person).into_iter().flatten() {
            let name = if label.as_str() == DeviceLabel::DEFAULT {
                person.to_string()
            } else {
                format!("{person}/{label}")
            };
            rows.push([name, short(&key), "one machine".to_owned(), String::new()]);
        }
    }
    Section {
        title: "contacts",
        note: None,
        rows,
    }
}

/// `links you shared`: each link this machine issued, by the first 8 hex characters of its revocation id,
/// with the service, who holds it, and when it ends. Devices are under `devices`, never here.
async fn links_section(home: &Home, now: u64) -> eyre::Result<Section> {
    let records = Grants::at(home.links()).load().await?;
    let revoked = swoosh::revoked::open(home)?;
    let rows = records
        .iter()
        .map(|record| link_row(record, &revoked, now))
        .collect();
    Ok(Section {
        title: "links you shared",
        note: None,
        rows,
    })
}

/// One link's row.
fn link_row(record: &GrantRecord, revoked: &Denylist, now: u64) -> [String; 4] {
    let id: String = record.root_id.to_hex().chars().take(8).collect();
    let holder = match record.holder.as_str() {
        ANYONE => "anyone".to_owned(),
        holder => match holder.parse::<NodeId>() {
            // A link shared with a person's devices is bound to their root, and a root prints as one.
            Ok(key) if record.kind == GrantKind::Fleet => {
                format!("root:{}", short(&key))
            }
            Ok(key) => short(&key),
            Err(_) => holder.to_owned(),
        },
    };
    let ends = unix(record.expiry);
    let state = if revoked.is_revoked_any([&record.root_id]) {
        "revoked".to_owned()
    } else if ends <= now {
        format!("ended {}", Date(ends))
    } else {
        format!("until {}", Date(ends))
    };
    [id, record.target.as_str().to_owned(), holder, state]
}

/// Whether `devices.conflict` holds an update: two copies of the root signed, and a device saw both.
fn roster_fork_held(home: &Home) -> bool {
    std::fs::metadata(home.devices_conflict()).is_ok_and(|meta| meta.len() > 0)
}

fn unix(time: SystemTime) -> u64 {
    time.duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

fn unix_now() -> u64 {
    unix(SystemTime::now())
}

#[cfg(test)]
#[path = "report_tests.rs"]
mod report_tests;
