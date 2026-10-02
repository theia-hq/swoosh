//! The bare `swoosh status`: what this machine is, read from its own files.
//!
//! It never dials, never asks for a passphrase and never writes: the root is read through
//! [`Root::inspect`], which looks only at the key file's header and the signed records beside it. A home
//! with no key prints `key: none yet`; the first verb that needs a key makes it.
//!
//! The report goes to stdout whole; every notice (a running `serve` it could not read) goes to stderr, so a
//! script that reads the report reads only it.

use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use bifrost::NodeId;
use keystore::{KeyFile, Method, Stored};
use nauthy::{Denylist, VerifyKey};
use swoosh::contacts::{Contacts, ContactsStore, DeviceLabel, ME};
use swoosh::credential::short;
use swoosh::escape::EscapedPath;
use swoosh::grants::{ANYONE, GrantKind, GrantRecord, Grants};
use swoosh::home::Home;
use swoosh::node_client::{ControlClient, NodeClient as _};
use swoosh::root::{Date, Root, RootPlace};
use swoosh::roster::{Member, RevokedDevice};
use swoosh::serve::control_codec::{ControlError, DisabledList, ServiceMenu};
use swoosh::standing::{Standing, StandingError};
use swoosh::{badge, roster, standing, sync};
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

/// `status --key`'s refusal on a home with no key: `status` makes none.
pub(crate) const NO_KEY: &str =
    "this machine has no key yet; to make one and print it: swoosh join";

/// The block a machine that is no device of a root prints after `home:`.
const NOT_A_DEVICE: [&str; 3] = [
    "this machine: not one of your devices yet",
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
    out: &mut impl std::io::Write,
    err: &mut impl std::io::Write,
) -> eyre::Result<()> {
    let key = KeyFile::device(home.key()).load()?;
    if print == Print::Key {
        let Some(key) = key else {
            eyre::bail!(NO_KEY);
        };
        writeln!(
            out,
            "{}",
            swoosh::identity::key_of(&KeyFile::device(home.key()), &key)?
        )?;
        return Ok(());
    }
    let report = Report::gather(home, key.as_ref(), unix_now()).await?;
    for notice in &report.notices {
        writeln!(err, "{notice}")?;
    }
    write!(out, "{}", report.render())?;
    Ok(())
}

/// Everything bare `status` says, gathered from the home's files before anything prints.
#[derive(Debug)]
pub(crate) struct Report {
    /// This machine's key and how it is locked; `None` when the home has no key.
    key: Option<(NodeId, Vec<Method>)>,
    /// The home's directory.
    home: String,
    /// The lines after `home:`: the root's line, or what this machine is when it is no device.
    top: Vec<String>,
    /// `this machine: me/<name>, your device until <date>` (or `ended <date>`), when this machine is no row of
    /// the list.
    this_machine: Option<String>,
    sections: Vec<Section>,
    /// `serving:`; `None` when nothing runs and this machine is no device, which has nothing to say.
    serving: Option<String>,
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
    pub(crate) async fn gather(home: &Home, key: Option<&Stored>, now: u64) -> eyre::Result<Self> {
        let mut report = Self {
            key: key
                .map(|key| {
                    let methods = match key {
                        Stored::Plain(_) => Vec::new(),
                        Stored::Locked(locked) => locked.methods().collect(),
                    };
                    swoosh::identity::key_of(&KeyFile::device(home.key()), key)
                        .map(|node| (node, methods))
                })
                .transpose()?,
            home: EscapedPath(home.dir()).to_string(),
            top: Vec::new(),
            this_machine: None,
            sections: Vec::new(),
            serving: None,
            nags: Vec::new(),
            notices: Vec::new(),
        };
        let store = ContactsStore::open(home).await?;
        let contacts = store.contacts();
        // An act that did not finish, or a home whose records disagree, says so on the last line.
        let mut last = None;
        let mut device = false;
        match key {
            None => match Standing::read(home).await {
                // A `leave` from a restored home where the root is kept leaves the root half made, and the
                // next `invite` finishes it under the key it makes: the same line as a mint that stopped.
                Ok(Standing::InterruptedMint { .. }) => {
                    last = Some(standing::UNFINISHED_MINT.to_owned());
                }
                // A torn `root.key` says so first: nothing a restored home's lines name can mend it.
                Err(StandingError::Damaged(
                    what @ standing::Disagreement::UnreadableRoot { .. },
                )) => {
                    last = Some(standing::damaged_line(&what));
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
                _ if restored(home) => report.nags.extend(restored_lines(home).await?),
                _ => report.top = NOT_A_DEVICE.map(str::to_owned).to_vec(),
            },
            Some(_) => match Standing::read(home).await {
                Err(StandingError::Damaged(what)) => last = Some(standing::damaged_line(&what)),
                Err(other) => return Err(other.into()),
                Ok(Standing::InterruptedMint { .. }) => {
                    last = Some(standing::UNFINISHED_MINT.to_owned());
                }
                Ok(Standing::Unpinned) => report.top = NOT_A_DEVICE.map(str::to_owned).to_vec(),
                Ok(standing) => {
                    device = true;
                    report.standing(home, standing, now).await?;
                }
            },
        }
        // No verb deletes it yet: the line names none.
        if Standing::revoked_root(home).await?.is_some() {
            report
                .nags
                .push("a revoked root is still on this machine; swoosh does not use it".to_owned());
        }
        report.sections.push(contacts_section(contacts));
        report.sections.push(links_section(home, now).await?);
        report.serving = report.serving_line(home).await;
        if let Some(root) = swoosh::home::ServeLock::recorded(home).admit
            && swoosh::home::serve_running(home).await
        {
            report.serving = Some(admitting(report.serving.as_deref(), root));
        }
        if device && report.serving.is_none() {
            report.serving = Some(SERVING_NOTHING.to_owned());
        }
        if roster_fork_held(home) {
            report.nags.push(
                "two copies of your root have been used: your devices hold two different lists. Keep one \
                 copy; the next time you use it, it settles this. If you did not use two copies, your root \
                 may be stolen: swoosh revoke --help"
                    .to_owned(),
            );
        }
        report.nags.extend(last);
        Ok(report)
    }

    /// The root's line, this machine's line, the devices, and the lines about renewing, on a device of a
    /// root: one that keeps it or one that does not.
    async fn standing(&mut self, home: &Home, standing: Standing, now: u64) -> eyre::Result<()> {
        let mut carrying = Vec::new();
        let (rows, until) = match standing {
            Standing::Unpinned | Standing::InterruptedMint { .. } => return Ok(()),
            Standing::HoldsRoot { pin, until } => {
                let inspected = Root::inspect(home, RootPlace::Home).await?;
                self.top = vec![format!(
                    "root:{pin} on this machine, locked with a passphrase."
                )];
                // Another copy of the root, or this machine, may have revoked a device since the last act
                // here: the records as the next act would bring them forward say so before the list does.
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
                let rows: Vec<DeviceRow> = inspected
                    .rows()
                    .iter()
                    .map(|row| device(row, false))
                    .chain(marked)
                    .chain(unlisted)
                    .collect();
                self.devices("devices:".to_owned(), &rows, now);
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
                self.top = vec![format!("root:{pin} not on this machine.")];
                let rows: Vec<DeviceRow> = pin
                    .verify_key()
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
                    .unwrap_or_default();
                let title = format!("devices (as of the last sync, {}):", sync::ago(home));
                self.devices(title, &rows, now);
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
        let name = match own_row {
            Some(row) => Some(row.label.clone()),
            None => swoosh::renewal::own_label(home).await,
        };
        // Before a list names it, the lines that say what to do call it `this machine`: the one name the
        // reader has already seen for it on `this machine:`.
        let me = name
            .as_ref()
            .map_or_else(|| "this machine".to_owned(), |name| format!("me/{name}"));
        if own_row.is_none() {
            // Before the list lands, `this machine:` names it by the name its invite gave it: a hint that
            // only this line prints.
            let hinted = name.clone().or_else(|| {
                swoosh::joining::InvitedBy::read(home).and_then(|invited| invited.name)
            });
            let shown = hinted.map_or_else(|| short(&key), |name| format!("me/{name}"));
            // A date already passed reads as the row's does: `ended`, never `until`.
            self.this_machine = Some(if until <= now {
                format!("this machine: {shown}, ended {}", Date(until))
            } else {
                format!("this machine: {shown}, your device until {}", Date(until))
            });
        }
        if own_row.is_some_and(|row| row.revoked) {
            self.nags.extend(
                [
                    "this machine is no longer one of your devices: your root revoked it. To join again: \
                     swoosh leave --new-key",
                    "then: swoosh join",
                ]
                .map(str::to_owned),
            );
            return Ok(());
        }
        let name = name.map_or_else(|| "<name>".to_owned(), |name| name.to_string());
        if until <= now {
            self.nags.push(format!(
                "{me} ended on {}; your devices refuse it. Where your root is kept: swoosh invite {name}",
                Date(until)
            ));
            self.nags.push(
                "this machine picks it up the next time it reaches one of your devices, or now: swoosh sync"
                    .to_owned(),
            );
        } else if until - now <= badge::DEVICE_WARN_WINDOW.as_secs() {
            let renews = own_row.is_some_and(|row| {
                swoosh::root::renew_by(row.until, row.duration, row.seeded).is_some()
            });
            let how = if renews {
                "It renews the next time you use your root, when this machine next syncs."
                    .to_owned()
            } else {
                format!("It is not renewed on its own. With your root: swoosh invite {name}")
            };
            self.nags
                .push(format!("{me} ends on {}. {how}", Date(until)));
        }
        self.nags.extend(carrying);
        Ok(())
    }

    /// The devices table: every row the root has, revoked ones too; the root itself is never a row. A live
    /// row leaves the state column blank.
    fn devices(&mut self, title: String, rows: &[DeviceRow], now: u64) {
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
        self.sections.push(Section { title, rows });
    }

    /// `serving:`, from the running `serve`'s local control socket when there is one; `None` when no
    /// `serve` runs. Reading it is not a dial: no other machine is contacted. A socket nothing listens on
    /// (a `serve` that was killed) is the same as none.
    async fn serving_line(&mut self, home: &Home) -> Option<String> {
        let client = match ControlClient::resolve(home) {
            Ok(client) => client,
            Err(ControlError::NoResident) => return None,
            Err(error) => return Some(self.serving_unknown(&error)),
        };
        match client.status().await {
            Ok(status) => Some(match serving(&status.menu) {
                Ok(line) => line,
                Err(why) => self.serving_unknown(&why),
            }),
            Err(ControlError::NoResident) => None,
            Err(error) => Some(self.serving_unknown(&error)),
        }
    }

    /// A `serve` is there and could not be read: the line says so, and why goes to stderr.
    fn serving_unknown(&mut self, why: &dyn core::fmt::Display) -> String {
        self.notices
            .push(format!("could not read the running swoosh serve: {why}"));
        "serving: unknown".to_owned()
    }

    /// The report, in blocks a blank line apart, an empty block left out: the key, its lock, the home and
    /// the root's line (or what this machine is); each section with a row and what is served; the lines that
    /// say what to do.
    pub(crate) fn render(&self) -> String {
        let mut head = match &self.key {
            Some((key, methods)) => {
                vec![
                    format!("key: {key}"),
                    format!("key lock: {}", lock(methods)),
                ]
            }
            None => vec!["key: none yet".to_owned()],
        };
        head.push(format!("home: {}", self.home));
        head.extend(self.top.iter().cloned());
        head.extend(self.this_machine.iter().cloned());

        let mut body = Vec::new();
        for section in self
            .sections
            .iter()
            .filter(|section| !section.rows.is_empty())
        {
            body.push(section.title.clone());
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
                body.push(line.trim_end().to_owned());
            }
        }
        body.extend(self.serving.iter().cloned());

        let blocks: Vec<String> = [head, body, self.nags.clone()]
            .into_iter()
            .filter(|block| !block.is_empty())
            .map(|block| block.join("\n") + "\n")
            .collect();
        blocks.join("\n")
    }
}

/// The words `key lock:` names the key's locks by: `none` for a plain key, else each lock's method, in the
/// key file's order.
fn lock(methods: &[Method]) -> String {
    if methods.is_empty() {
        return "none".to_owned();
    }
    methods
        .iter()
        .map(|method| match method {
            Method::Passphrase => "passphrase",
        })
        .collect::<Vec<_>>()
        .join(", ")
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
async fn restored_lines(home: &Home) -> eyre::Result<Vec<String>> {
    const MISSING: &str =
        "this machine's key is not in this home, because system backups leave it out.";
    let kept = home.root_key().exists() && Standing::revoked_root(home).await?.is_none();
    if !kept {
        return Ok(vec![
            format!("{MISSING} To start over: swoosh leave"),
            "then: swoosh join".to_owned(),
        ]);
    }
    Ok(vec![
        format!("{MISSING} A root kept on this machine stays. To start over: swoosh leave"),
        "then: swoosh invite <name> <key>".to_owned(),
    ])
}

/// The day a live row falls due to renew, once that day has come.
fn due(row: &DeviceRow, now: u64) -> Option<u64> {
    if row.revoked || row.until <= now {
        return None;
    }
    swoosh::root::renew_by(row.until, row.duration, row.seeded).filter(|by| *by <= now)
}

/// The line for a device due to renew: `renew me/<name> by <date>: swoosh invite <name>`, with `root`
/// after it where the root is not on this machine. Nothing for a device that never renews on its own.
fn renew_line(row: &DeviceRow, root: &str) -> Option<String> {
    let by = swoosh::root::renew_by(row.until, row.duration, row.seeded)?;
    Some(format!(
        "renew me/{name} by {}: swoosh invite {name}{root}",
        Date(by),
        name = row.label
    ))
}

/// `serving:` with the root a running `serve --admit` admits, after what it serves when that is known.
fn admitting(serving: Option<&str>, root: NodeId) -> String {
    let head = match serving {
        None | Some(SERVING_NOTHING) => "serving:".to_owned(),
        Some(serving) => format!("{serving},"),
    };
    format!("{head} admitting root:{root}")
}

/// `serving:` from a running `serve`'s menu: every service it serves that is not turned off. When the list
/// of what is off could not be read, what is served is not known: the reason, for stderr.
fn serving(menu: &ServiceMenu) -> Result<String, String> {
    let off = match &menu.disabled {
        DisabledList::Known(names) => names,
        DisabledList::Unknown(why) => {
            return Err(format!("its list of services turned off: {why}"));
        }
    };
    let on: Vec<&str> = menu
        .catalog
        .entries()
        .map(|entry| entry.name.as_str())
        // The node's own routes (`control.*`) are no service a person started, so none is listed.
        .filter(|name| !name.starts_with("control."))
        .filter(|name| !off.iter().any(|off| off == name))
        .collect();
    Ok(match on.as_slice() {
        [] => "serving: nothing".to_owned(),
        names => format!("serving: {}", names.join(", ")),
    })
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
fn invite_ends(row: &Member, now: u64) -> Option<String> {
    let ends = row.invite_until;
    let warns = row.seeded()
        && ends.saturating_sub(badge::DEVICE_WARN_WINDOW.as_secs()) <= now
        && now < ends;
    warns.then(|| {
        format!(
            "me/{name}'s key came in its invite, which ends on {}. If it starts from that invite each time \
             (a runner summoned from a secret): swoosh invite {name} --new-key, then set its secret again.",
            Date(ends),
            name = row.label
        )
    })
}

/// `contacts:`: each person with their root, and each device saved by hand. Your own devices are under
/// `devices:`, never here.
fn contacts_section(contacts: &Contacts) -> Section {
    let mut rows = Vec::new();
    for person in contacts.petnames().filter(|person| person.as_str() != ME) {
        if let Some(root) = contacts.signet(person) {
            rows.push([
                person.to_string(),
                format!("root:{}", short(&root.node)),
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
            rows.push([name, short(&key), "device".to_owned(), String::new()]);
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
    let revoked = swoosh::revoked::open(home)?;
    let rows = records
        .iter()
        .map(|record| link_row(record, &revoked, now))
        .collect();
    Ok(Section {
        title: "links you shared:".to_owned(),
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
