//! The bare `swoosh status`: what this machine is, read from its own files.
//!
//! It never dials and never asks for a passphrase: the root is read through [`Root::inspect`], which
//! looks only at the key file's header and the signed records beside it. Its one write is this machine's
//! key, made plain on a home that has none, and said once on stderr.
//!
//! The report goes to stdout whole; every notice (the key it made, a crash state the read finished, a
//! running `serve` it could not read) goes to stderr, so a script that reads the report reads only it.

use std::time::{SystemTime, UNIX_EPOCH};

use bifrost::NodeId;
use keystore::{Method, Stored};
use nauthy::{FileDenylist, VerifyKey};
use swoosh::contacts::{Contacts, ContactsStore, DeviceLabel, ME};
use swoosh::grants::{ANYONE, GrantRecord, GrantTarget, Grants};
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::root::{Date, Moved, Root, RootPlace};
use swoosh::serve::control_codec::{ControlError, DisabledList};
use swoosh::standing::{Standing, StandingError};
use swoosh::{badge, identity, roster, standing, sync};
use tightbeam::identity::AsVerifyKey as _;

/// What bare `status` prints on stdout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Print {
    /// The whole report.
    Report,
    /// This machine's key alone (`--key`).
    Key,
}

/// The line `serving:` reads when no `serve` runs here.
pub(crate) const SERVING_NOTHING: &str = "serving: nothing (swoosh serve is not running)";

/// The characters of a key a row shows: `ed01` and 8 more.
const SHORT: usize = 12;

/// Make this machine's key if the home has none, then print what `print` asks for.
pub(crate) async fn run(home: &Home, print: Print) -> eyre::Result<()> {
    let key = identity::inspect(home)?;
    if let identity::Inspected::Made(_) = key {
        eprintln!(
            "made this machine's key (first run): {}",
            home.key().display()
        );
    }
    if print == Print::Key {
        println!("{}", key.stored().node_id());
        return Ok(());
    }
    let report = Report::gather(home, key.stored(), unix_now()).await?;
    for notice in &report.notices {
        eprintln!("{notice}");
    }
    print!("{}", report.render());
    Ok(())
}

/// Everything bare `status` says, gathered from the home's files before anything prints.
#[derive(Debug)]
pub(crate) struct Report {
    key: NodeId,
    lock: Method,
    /// The `root:` block: one line, or a line and what follows it.
    root: Vec<String>,
    /// `this machine: me/<name>, your device until <date>`, on a device.
    this_machine: Option<String>,
    sections: Vec<Section>,
    serving: String,
    /// The lines that say what to do, last.
    nags: Vec<String>,
    /// What goes to stderr.
    pub(crate) notices: Vec<String>,
}

/// One titled table of rows. Printed only when it has a row.
#[derive(Debug)]
struct Section {
    title: String,
    rows: Vec<[String; 4]>,
}

impl Report {
    /// Read the home: its standing, the root's records or the update it holds, its contacts, the links it
    /// shared, and what a running `serve` serves.
    pub(crate) async fn gather(home: &Home, key: &Stored, now: u64) -> eyre::Result<Self> {
        let own = key.node_id();
        let mut report = Self {
            key: own,
            lock: key.method(),
            root: Vec::new(),
            this_machine: None,
            sections: Vec::new(),
            serving: String::new(),
            nags: Vec::new(),
            notices: Vec::new(),
        };
        let store = ContactsStore::open(home.contacts()).await?;
        let contacts = store.contacts();
        match Standing::read(home).await {
            Err(StandingError::Damaged(what)) => report.root = vec![standing::damaged_line(&what)],
            Err(other) => return Err(other.into()),
            Ok(read) => {
                report
                    .notices
                    .extend(read.finished.iter().map(ToString::to_string));
                report.standing(home, read.standing, contacts, now).await?;
            }
        }
        report.sections.push(contacts_section(contacts));
        report.sections.push(links_section(home, now).await?);
        report.serving = report.serving_line(home).await;
        if roster_fork_held(home) {
            report.nags.push(
                "two copies of your root have been used: your devices hold two different lists. Keep one \
                 copy; the next time you use it, it settles this. If you did not use two copies, your root \
                 may be stolen: swoosh revoke --help"
                    .to_owned(),
            );
        }
        Ok(report)
    }

    /// The `root:` block, this machine's line, the devices, and the lines about renewing, by standing.
    async fn standing(
        &mut self,
        home: &Home,
        standing: Standing,
        contacts: &Contacts,
        now: u64,
    ) -> eyre::Result<()> {
        let (rows, until) = match standing {
            Standing::Unpinned => {
                self.root = vec![
                    "root: none yet.".to_owned(),
                    "  to join yours: swoosh join".to_owned(),
                    "  to make one here: swoosh invite <name> <key>".to_owned(),
                ];
                return Ok(());
            }
            Standing::InterruptedMint { root_key } => {
                self.root = vec![standing::unfinished_line(root_key)];
                return Ok(());
            }
            Standing::PinOnly { pin } => {
                self.root = vec![not_here(home, pin)];
                return Ok(());
            }
            Standing::HoldsRoot { pin, until } => {
                let inspected = Root::inspect(home, RootPlace::Home).await?;
                self.notices
                    .extend(inspected.finished.iter().map(ToString::to_string));
                self.root = vec![
                    format!(
                        "root: root:{pin}, kept on this machine, locked with a passphrase."
                    ),
                    "      Your root is a key, not a machine: it vouches for your devices, and it never dials \
                     or serves."
                        .to_owned(),
                ];
                let rows: Vec<DeviceRow> = inspected
                    .state
                    .rows()
                    .iter()
                    .map(|row| DeviceRow {
                        label: row.label.clone(),
                        key: row.key,
                        until: row.until,
                        duration: row.duration,
                        seeded: row.seeded,
                        revoked_on: row.revoked_on,
                    })
                    .collect();
                self.devices("devices:".to_owned(), &rows, now);
                (rows, until)
            }
            Standing::Device { pin, until } => {
                self.root = vec![not_here(home, pin)];
                let rows: Vec<DeviceRow> = pin
                    .verify_key()
                    .ok()
                    .and_then(|root| roster::held(home, root))
                    .map(|update| {
                        update
                            .members()
                            .iter()
                            .map(|member| DeviceRow {
                                label: member.label.clone(),
                                key: member.node,
                                until: member.until,
                                duration: member.duration,
                                seeded: false,
                                revoked_on: 0,
                            })
                            .collect()
                    })
                    .unwrap_or_default();
                let title = format!("devices (as of the last sync, {}):", sync::ago(home));
                self.devices(title, &rows, now);
                (rows, until)
            }
        };
        let until = unix(until);
        let own = self.key.verify_key().ok();
        let own_row = rows.iter().find(|row| Some(row.key) == own);
        let name = own_row
            .map(|row| row.label.clone())
            .or_else(|| own_name(contacts, self.key));
        let me = name
            .as_ref()
            .map_or_else(|| self.key.short(), |name| format!("me/{name}"));
        self.this_machine = Some(format!(
            "this machine: {me}, your device until {}",
            Date(until)
        ));
        self.nags.extend(use_your_root(&rows, now));
        let name = name.map_or_else(|| "<name>".to_owned(), |name| name.to_string());
        if until <= now {
            self.nags.push(format!(
                "device: {me} ended on {}; your devices refuse it. Where your root is kept: swoosh invite \
                 {name}. This machine picks it up the next time it reaches one of your devices (or now: \
                 swoosh sync).",
                Date(until)
            ));
        } else if until - now <= badge::DEVICE_WARN_WINDOW.as_secs() {
            let renews = own_row.is_some_and(|row| {
                swoosh::root::renew_by(row.until, row.duration, row.seeded).is_some()
            });
            let how = if renews {
                "It renews the next time you use your root, when this machine next syncs."
                    .to_owned()
            } else {
                format!("It is not renewed on its own. With your root: swoosh invite {name}.")
            };
            self.nags
                .push(format!("{me} ends on {}. {how}", Date(until)));
        }
        Ok(())
    }

    /// The devices table: every row the root has, revoked ones too; the root itself is never a row.
    fn devices(&mut self, title: String, rows: &[DeviceRow], now: u64) {
        let own = self.key.verify_key().ok();
        let rows = rows
            .iter()
            .map(|row| {
                let (state, date) = if row.revoked_on != 0 {
                    ("revoked".to_owned(), Date(row.revoked_on).to_string())
                } else if row.until <= now {
                    ("ended".to_owned(), Date(row.until).to_string())
                } else {
                    let due = swoosh::root::renew_by(row.until, row.duration, row.seeded)
                        .filter(|by| *by <= now);
                    let state = match due {
                        _ if Some(row.key) == own => "this machine".to_owned(),
                        Some(by) => format!("renew by {}", Date(by)),
                        None => "live".to_owned(),
                    };
                    (state, format!("until {}", Date(row.until)))
                };
                [
                    format!("me/{}", row.label),
                    short(&row.key.to_string()),
                    state,
                    date,
                ]
            })
            .collect();
        self.sections.push(Section { title, rows });
    }

    /// `serving:`, from the running `serve`'s local control socket when there is one. Reading it is not a
    /// dial: no other machine is contacted.
    async fn serving_line(&mut self, home: &Home) -> String {
        let client = match ControlClient::resolve(home) {
            Ok(client) => client,
            Err(ControlError::NoResident) => return SERVING_NOTHING.to_owned(),
            Err(error) => return self.serving_unknown(&error),
        };
        match client.status().await {
            Ok(status) => {
                let off: &[String] = match &status.menu.disabled {
                    DisabledList::Known(names) => names,
                    DisabledList::Unknown(_) => &[],
                };
                let on: Vec<&str> = status
                    .menu
                    .catalog
                    .entries()
                    .map(|entry| entry.name.as_str())
                    .filter(|name| !off.iter().any(|off| off == name))
                    .collect();
                match on.as_slice() {
                    [] => "serving: nothing".to_owned(),
                    names => format!("serving: {}", names.join(", ")),
                }
            }
            Err(error) => self.serving_unknown(&error),
        }
    }

    /// A `serve` is there and could not be read: the line says so, and why goes to stderr.
    fn serving_unknown(&mut self, error: &ControlError) -> String {
        self.notices
            .push(format!("could not read the running swoosh serve: {error}"));
        "serving: unknown".to_owned()
    }

    /// The report, in order: the key, the lock, the root, this machine, each section with a row, what is
    /// served, then the lines that say what to do.
    pub(crate) fn render(&self) -> String {
        let mut out = format!("key: {}\n", self.key);
        out.push_str(match self.lock {
            Method::Plain => "lock: none\n",
            Method::Passphrase => "lock: passphrase\n",
        });
        for line in &self.root {
            out.push_str(line);
            out.push('\n');
        }
        if let Some(line) = &self.this_machine {
            out.push_str(line);
            out.push('\n');
        }
        out.push('\n');
        for section in self
            .sections
            .iter()
            .filter(|section| !section.rows.is_empty())
        {
            out.push_str(&section.title);
            out.push('\n');
            let width = |column: usize| {
                section
                    .rows
                    .iter()
                    .map(|row| row[column].chars().count())
                    .max()
                    .unwrap_or(0)
            };
            let (name, key, state) = (width(0), width(1), width(2));
            for [a, b, c, d] in &section.rows {
                let line = format!("  {a:<name$}  {b:<key$}  {c:<state$}  {d}");
                out.push_str(line.trim_end());
                out.push('\n');
            }
        }
        out.push_str(&self.serving);
        out.push('\n');
        if !self.nags.is_empty() {
            out.push('\n');
            for line in &self.nags {
                out.push_str(line);
                out.push('\n');
            }
        }
        out
    }
}

/// One of the root's devices, from its records where the root is kept, or from the update a device holds.
#[derive(Debug)]
struct DeviceRow {
    label: DeviceLabel,
    key: VerifyKey,
    until: u64,
    duration: u64,
    seeded: bool,
    revoked_on: u64,
}

/// The `root:` line where the root is not kept: where it went, when this machine moved it.
fn not_here(home: &Home, root: NodeId) -> String {
    match Moved::read(home) {
        Some(moved) => format!(
            "root: root:{root}, not on this machine (you moved it to {} on {}).",
            moved.to.display(),
            moved.on
        ),
        None => format!("root: root:{root}, not on this machine."),
    }
}

/// "use your root by <date>", the earliest day a device of the root falls due to renew, or, once that
/// day has passed, how many are due. Nothing when no device renews on its own.
fn use_your_root(rows: &[DeviceRow], now: u64) -> Option<String> {
    let due: Vec<u64> = rows
        .iter()
        .filter(|row| row.revoked_on == 0 && row.until > now)
        .filter_map(|row| swoosh::root::renew_by(row.until, row.duration, row.seeded))
        .collect();
    let earliest = due.iter().min()?;
    if now < *earliest {
        return Some(format!(
            "use your root by {}: swoosh invite (it lists what is due)",
            Date(*earliest)
        ));
    }
    let count = due.iter().filter(|by| **by <= now).count();
    let noun = if count == 1 { "device" } else { "devices" };
    Some(format!(
        "use your root now: swoosh invite ({count} {noun} due)"
    ))
}

/// The name this machine has among `me`'s devices in the address book, when the root's list has none.
fn own_name(contacts: &Contacts, own: NodeId) -> Option<DeviceLabel> {
    let me = ME.parse().ok()?;
    contacts
        .devices(&me)?
        .find(|(_, key)| **key == own)
        .map(|(label, _)| label.clone())
}

/// `contacts:`: each person with their root, and each device saved by hand. Your own devices are under
/// `devices:`, never here.
fn contacts_section(contacts: &Contacts) -> Section {
    let mut rows = Vec::new();
    for person in contacts.petnames().filter(|person| person.as_str() != ME) {
        if let Some(root) = contacts.signet(person) {
            rows.push([
                person.to_string(),
                format!("root:{}", short(&root.node.to_string())),
                "root".to_owned(),
                String::new(),
            ]);
        }
        for (label, key) in contacts.devices(person).into_iter().flatten() {
            let name = if label.as_str() == DeviceLabel::DEFAULT {
                person.to_string()
            } else {
                format!("{person}/{label}")
            };
            rows.push([
                name,
                short(&key.to_string()),
                "device".to_owned(),
                String::new(),
            ]);
        }
    }
    Section {
        title: "contacts:".to_owned(),
        rows,
    }
}

/// `links you shared:`: each link this machine issued, by the first 8 hex characters of its revocation id,
/// with the service, who holds it, and when it ends. Devices are under `devices:`, never here.
async fn links_section(home: &Home, now: u64) -> eyre::Result<Section> {
    let records = Grants::at(home.links()).load().await?;
    let revoked = FileDenylist::load(home.revoked()).await?;
    let rows = records
        .iter()
        .filter(|record| record.target != GrantTarget::Membership)
        .map(|record| link_row(record, &revoked, now))
        .collect();
    Ok(Section {
        title: "links you shared:".to_owned(),
        rows,
    })
}

/// One link's row.
fn link_row(record: &GrantRecord, revoked: &FileDenylist, now: u64) -> [String; 4] {
    let id: String = record.root_id.to_hex().chars().take(8).collect();
    let holder = match record.holder.as_str() {
        ANYONE => "anyone".to_owned(),
        holder => match holder.parse::<NodeId>() {
            Ok(key) => short(&key.to_string()),
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

/// Whether `roster.fork` holds an update: two copies of the root signed, and a device saw both.
fn roster_fork_held(home: &Home) -> bool {
    std::fs::metadata(home.roster_fork()).is_ok_and(|meta| meta.len() > 0)
}

/// A key as a row shows it: `ed01` and 8 more characters.
fn short(key: &str) -> String {
    key.chars().take(SHORT).collect()
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
