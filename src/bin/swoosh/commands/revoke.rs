//! `swoosh revoke`: take back a link, a device, or everything shared with a contact.
//!
//! ```text
//! revoke <link | path | ->     that link and everything narrowed from it
//! revoke me/<name>             the device: every id of its live standings, its key, and the links given it
//! revoke <person>              every link given to any device of that contact, or bound to their root
//! revoke <person>/<name>       every link given to that device's key
//! revoke <key>                 every link given to that key
//! ```
//!
//! Every form blocks here first, in this machine's own `revoked`, which a running
//! `serve` reads live. A link this machine signed, and a link it gave a key, were only ever admitted here,
//! so that block is the whole revoke. A device is admitted by all your devices: with your root (kept here,
//! or `--root <dir>`) the revoke then presents it, cuts, and offers the cut; without it, it stays on this
//! machine and says so. Only the root's passphrase is ever asked for, and only after the block is written.

use std::io::{self, Read, Write};
use std::path::PathBuf;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{Link, Revocation, RevocationId, VerifyKey};
use swoosh::contacts::{ContactRef, ContactsStore, DeviceLabel, ME, Petname, ResolveError};
use swoosh::grants::Grants;
use swoosh::home::{Home, HomeWrite};
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::reach_report::{Reach, What};
use swoosh::root::{Root, RootError, RootPlace, RootVerb};
use swoosh::standing::{Standing, StandingError};
use swoosh::sync::{Dial, NodeDial};
use swoosh::transport::ReachArgs;
use tightbeam::identity::AsVerifyKey as _;

/// The most bytes of stdin read for one link: far above any link, far below anything that costs a read.
const MAX_STDIN: u64 = 64 * 1024;

/// Take back a link, a device, or everything you shared with a contact; or end a root for good.
#[derive(Debug, Args)]
pub struct RevokeCmd {
    /// what to take back
    #[arg(
        value_name = "link | path | - | me/<name> | <person> | <person>/<name> | key | root key",
        value_parser = target
    )]
    pub target: Target,
    /// Act on your root, or on the root kept in `<dir>`.
    #[arg(long = "root", value_name = "dir")]
    pub root: Option<PathBuf>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// What `revoke` was given, as typed.
#[derive(Debug, Clone)]
pub enum Target {
    /// A `swoosh:` link, typed or read from the file a path names.
    Link(Link),
    /// `-`: one link, read from stdin.
    Stdin,
    /// `me/<name>`: one of your devices.
    Device(DeviceLabel),
    /// `<person>`: a contact.
    Person(Petname),
    /// `<person>/<name>`: one device of a contact.
    PersonDevice(ContactRef),
    /// A key.
    Key(NodeId),
}

/// The positional: `-`, a path, a link, a key, `me/<name>`, a person or one of their devices. A bare word
/// is a person, never `me/<name>`. Anything else, a `root:` key included until its form lands, is a usage
/// error.
fn target(text: &str) -> Result<Target, String> {
    if text == "-" {
        return Ok(Target::Stdin);
    }
    if swoosh::peer::is_path(text) {
        return swoosh::peer::read_link_file(text)
            .map(|(link, _)| Target::Link(link))
            .map_err(|error| error.to_string());
    }
    if swoosh::link::is_prefixed(text) {
        return swoosh::link::parse(text)
            .map(Target::Link)
            .map_err(|error| error.to_string());
    }
    match swoosh::peer::raw_key(text) {
        Ok(Some(key)) => return Ok(Target::Key(key)),
        Ok(None) => {}
        Err(unusable) => return Err(unusable.to_string()),
    }
    if swoosh::link::looks_bare(text) {
        return Err(swoosh::link::LinkError::Prefix.to_string());
    }
    if text.eq_ignore_ascii_case(ME) {
        return Err(
            "`me` alone names all your devices; revoke one: `swoosh revoke me/<name>`".to_owned(),
        );
    }
    let typed: ContactRef = text
        .parse()
        .map_err(|error: swoosh::names::NameError| error.to_string())?;
    match (typed.petname().as_str() == ME, typed.device()) {
        (true, Some(device)) => Ok(Target::Device(device.clone())),
        (_, device) => {
            let person = Petname::clone(typed.petname())
                .unreserved()
                .map_err(|error| error.to_string())?;
            match device {
                None => Ok(Target::Person(person)),
                Some(_) => Ok(Target::PersonDevice(typed)),
            }
        }
    }
}

/// A usage error found only once the command runs (stdin held no link): exit 2, as clap's own are.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

/// The device part of a `revoke me/<name>`, left for the root once this machine's block is written.
#[derive(Debug)]
pub struct Publish {
    place: RootPlace,
    name: DeviceLabel,
    /// The device's key, which finds its row: a name can pass to a new device once the old one is revoked.
    key: VerifyKey,
    /// Every key the name held live when this machine found the device, so the act refuses a device that
    /// got a new key it never saw.
    listed: Vec<VerifyKey>,
    /// Whether this machine had given the device's key any link.
    links: bool,
}

/// `revoke me/<name>` with your root: the device part, run as a reaching verb since it syncs with your
/// devices before it signs and offers them its cut after.
#[derive(Debug)]
pub struct RevokeRoot {
    pub publish: Publish,
    pub reach: ReachArgs,
}

impl RevokeCmd {
    /// Everything before the root: refuse what the target refuses, write this machine's block, and print
    /// what it did. `Some` when a device part follows that needs the root.
    pub async fn block(
        &self,
        home: &Home,
        stdin: impl Read,
        err: &mut impl Write,
    ) -> eyre::Result<Option<Publish>> {
        let target = match &self.target {
            Target::Stdin => Target::Link(read_stdin(stdin)?),
            other => other.clone(),
        };
        match target {
            Target::Link(link) => self.link(home, &link, err).await,
            Target::Device(name) => self.device(home, &name, None, err).await,
            Target::Person(person) => {
                self.no_root()?;
                person_links(home, &person, err).await?;
                Ok(None)
            }
            Target::PersonDevice(device) => {
                self.no_root()?;
                let store = ContactsStore::open(home).await?;
                let candidates = store
                    .contacts()
                    .resolve_candidates(&device)
                    .map_err(unknown)?;
                let keys: Vec<NodeId> = candidates.iter().map(|candidate| candidate.node).collect();
                let what = match device.device() {
                    Some(name) => format!("{}/{name}", device.petname()),
                    None => device.petname().to_string(),
                };
                key_links(home, &keys, &what, err).await?;
                Ok(None)
            }
            Target::Key(key) => {
                self.no_root()?;
                let short = format!("{}…", key.short());
                key_links(home, &[key], &short, err).await?;
                Ok(None)
            }
            Target::Stdin => Err(Usage("stdin held no swoosh: link.".to_owned()).into()),
        }
    }

    /// `--root` on a form where nothing needs the root refuses, before anything is written.
    fn no_root(&self) -> eyre::Result<()> {
        if self.root.is_some() {
            eyre::bail!("`--root` is only for acts that need your root");
        }
        Ok(())
    }

    /// A link: this machine's own is blocked here, and was only ever admitted here. A standing your root
    /// signed is the device it stands for, found by the link's id; one whose device your root has revoked
    /// already, or that no list of your devices here carries, is blocked here and goes no further. Any
    /// other issuer's refuses.
    async fn link(
        &self,
        home: &Home,
        link: &Link,
        err: &mut impl Write,
    ) -> eyre::Result<Option<Publish>> {
        let issuer = link.root();
        if own_key(home)?.is_some_and(|own| own == issuer) {
            self.no_root()?;
            let home_lock = HomeWrite::take(home).await?;
            revoke_link(&home_lock, home, link)?;
            writeln!(
                err,
                "{}",
                Reach::Complete.line(&What::Revoked("the link".to_owned()))
            )?;
            return Ok(None);
        }
        let pin = pin(home).await;
        if pin.is_none_or(|pin| pin != issuer) {
            eyre::bail!(
                "this link was issued by {}…, not by this machine or your root. Revoke it where it was issued.",
                short(&issuer)
            );
        }
        let id = link.cap().root_revocation_id();
        let source = self.source(home, &mut io::sink()).await?;
        let row = source
            .rows
            .iter()
            .find(|row| {
                id.as_ref()
                    .is_some_and(|id| row.ids.iter().any(|held| held.id == *id))
            })
            .cloned();
        // A row's key says whether its device is revoked, never its id alone: a root can hold a revoked id
        // on a live row (a block made here without the root, carried by its next act), and that device
        // is still to revoke. Only a link no row carries is judged by its id.
        let revoked = match &row {
            Some(row) => source.revoked_keys.contains(&row.key),
            None => id.as_ref().is_some_and(|id| source.revoked.contains(id)),
        };
        let what = What::Revoked("the link".to_owned());
        if revoked {
            // Your root has revoked the device already: its name may be a new device's now, so this stops
            // at the link and the key it was signed for.
            self.no_root()?;
            let home_lock = HomeWrite::take(home).await?;
            revoke_link(&home_lock, home, link)?;
            if let Some(row) = &row {
                swoosh::revoked::add(&home_lock, home, [Revocation::Key(row.key)])?;
            }
            writeln!(err, "{what}: {ALREADY}")?;
            return Ok(None);
        }
        if let Some(row) = row {
            let name = row.label.clone();
            return self.device(home, &name, Some(row), err).await;
        }
        // No list of your devices here carries it: it has ended, or this machine has not seen its device
        // yet. Until it ends, your other devices may admit it.
        let Some(ends) = link.cap().expiry().ok().flatten().map(unix_secs) else {
            eyre::bail!("this link carries no end date; nothing revoked.");
        };
        let reach = if ends <= unix_now() {
            self.no_root()?;
            Reach::Complete
        } else {
            Reach::LocalOnly { until: ends }
        };
        let home_lock = HomeWrite::take(home).await?;
        revoke_link(&home_lock, home, link)?;
        writeln!(err, "{}", reach.line(&what))?;
        Ok(None)
    }

    /// `me/<name>`: find its row before any write, refuse this machine's own, block its ids, its key and
    /// the links given it here, then leave the device part to the root, or say it stays here.
    async fn device(
        &self,
        home: &Home,
        name: &DeviceLabel,
        found: Option<Device>,
        err: &mut impl Write,
    ) -> eyre::Result<Option<Publish>> {
        let source = self.source(home, err).await?;
        let row = match found {
            Some(row) => row,
            None => source
                .rows
                .iter()
                .filter(|row| &row.label == name)
                .min_by_key(|row| row.revoked)
                .cloned()
                .ok_or_else(|| RootError::NotYourDevice { name: name.clone() })?,
        };
        if own_key(home)?.is_some_and(|own| own == row.key) {
            eyre::bail!(
                "me/{name} is this machine. To stop being one of your devices: swoosh leave"
            );
        }

        let now = unix_now();
        let home_lock = HomeWrite::take(home).await?;
        let given = given_to(home, &[row.key.to_string()]).await?;
        let links = !given.is_empty();
        let ids = row
            .ids
            .iter()
            .filter(|id| id.expires > now)
            .map(|id| RevocationId::clone(&id.id))
            .chain(given)
            .map(Revocation::Id);
        swoosh::revoked::add(&home_lock, home, ids.chain([Revocation::Key(row.key)]))?;
        let device = format!("me/{name}");

        match source.place {
            Some(place) => {
                writeln!(
                    err,
                    "revoked {device}: blocked here now. This key can never be your device again; {name} will \
                     need `swoosh leave --new-key` at its console."
                )?;
                let listed = source
                    .rows
                    .iter()
                    .filter(|listed| &listed.label == name && !listed.revoked)
                    .map(|listed| listed.key)
                    .collect();
                Ok(Some(Publish {
                    place,
                    name: name.clone(),
                    key: row.key,
                    listed,
                    links,
                }))
            }
            None => {
                let reach = Reach::LocalOnly { until: row.until };
                writeln!(err, "{}", reach.line(&What::Revoked(device)))?;
                if links {
                    writeln!(err, "{LINKS_LINE}")?;
                }
                Ok(None)
            }
        }
    }

    /// Where a device's ids come from, and where the root that publishes its revoke is, if anywhere: your
    /// root's records where the root is kept here or given with `--root`, else the update this device
    /// holds. Read with no lock and no prompt.
    async fn source(&self, home: &Home, err: &mut impl Write) -> eyre::Result<Source> {
        let read = match Standing::read(home).await {
            Ok(read) => read,
            Err(StandingError::Damaged(what)) => {
                eyre::bail!("{}", swoosh::standing::damaged_line(&what))
            }
            Err(other) => return Err(other.into()),
        };
        for line in &read.finished {
            writeln!(err, "{line}")?;
        }
        let place = match (&self.root, &read.standing) {
            (Some(_), Standing::Unpinned) => return Err(RootError::NotADevice.into()),
            (Some(dir), _) => Some(RootPlace::Dir(dir.clone())),
            // A machine that trusts no root has no devices to name.
            (None, Standing::Unpinned) => None,
            (None, Standing::HoldsRoot { .. } | Standing::InterruptedMint { .. }) => {
                Some(RootPlace::Home)
            }
            (None, Standing::Device { .. }) => None,
        };
        let mut source = Source {
            place,
            rows: Vec::new(),
            revoked: Vec::new(),
            revoked_keys: Vec::new(),
        };
        match (&source.place, &read.standing) {
            (Some(place), _) => {
                let inspected = Root::inspect(home, place.clone()).await?;
                let device = |row: &swoosh::roster::Member, revoked| Device {
                    label: row.label.clone(),
                    key: row.node,
                    until: row.until,
                    ids: row.ids.clone(),
                    revoked,
                };
                source.rows = inspected
                    .rows()
                    .iter()
                    .map(|row| device(row, false))
                    .chain(inspected.marked().iter().map(|row| device(row, true)))
                    .collect();
                source.revoked = inspected
                    .listed_revoked()
                    .map(|id| RevocationId::clone(&id.id))
                    .collect();
                source.revoked_keys = inspected.listed_revoked_keys().copied().collect();
            }
            (None, Standing::Device { pin, .. }) => {
                let pin = swoosh::standing::pin_key(home, *pin)?;
                if let Some(doc) = swoosh::roster::held(home, pin) {
                    source.rows = doc
                        .members()
                        .iter()
                        .map(|member| Device {
                            label: member.label.clone(),
                            key: member.node,
                            until: member.until,
                            ids: member.ids.clone(),
                            revoked: false,
                        })
                        .collect();
                    source.revoked = ids(doc.revoked());
                    source.revoked_keys = doc.revoked_keys().to_vec();
                }
            }
            (None, _) => {}
        }
        Ok(source)
    }
}

/// The line after a device's reach line, when this machine had given its key links.
const LINKS_LINE: &str =
    "and the links this machine gave it: blocked (only this machine admitted them).";

/// One of your devices as a revoke reads it.
#[derive(Debug, Clone)]
struct Device {
    label: DeviceLabel,
    key: VerifyKey,
    until: u64,
    ids: Vec<swoosh::roster::Id>,
    /// Whether the root's records already mark it revoked.
    revoked: bool,
}

/// Where a device's ids come from.
struct Source {
    /// The root that publishes the revoke, when there is one.
    place: Option<RootPlace>,
    /// Your devices, as the next act that cuts would find them: a row this machine blocked is marked.
    rows: Vec<Device>,
    /// The ids your root's records, or the update, revoke.
    revoked: Vec<RevocationId>,
    /// The keys your root's records, or the update, revoke.
    revoked_keys: Vec<VerifyKey>,
}

/// What a link whose device your root revoked already says after "revoked the link: ".
const ALREADY: &str = "blocked here. Your root revoked the device it stands for already.";

fn ids(held: &[swoosh::roster::Id]) -> Vec<RevocationId> {
    held.iter().map(|id| RevocationId::clone(&id.id)).collect()
}

impl Publish {
    /// Present the root, revoke the device, cut, and offer the cut; then say which of your devices took it.
    pub(crate) async fn run(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let mut root =
            Root::present_to(home, self.place, RootVerb::Revoke, prompt, dial, err).await?;
        root.revoke_device(&self.name, self.key, &self.listed)?;
        let _ = root.renew_due()?;
        let committed = root.commit_to(err).await?;
        let reach = committed.offer(dial).await;
        writeln!(
            err,
            "{}",
            reach.line(&What::Revoked(format!("me/{}", self.name)))
        )?;
        if self.links {
            writeln!(err, "{LINKS_LINE}")?;
        }
        Ok(())
    }
}

/// `<person>`: every link given to any device of that contact, and every link bound to their root.
async fn person_links(home: &Home, person: &Petname, err: &mut impl Write) -> eyre::Result<()> {
    let store = ContactsStore::open(home).await?;
    let contacts = store.contacts();
    let whole: ContactRef = person.as_str().parse()?;
    let mut holders: Vec<String> = match contacts.resolve_candidates(&whole) {
        Ok(candidates) => candidates
            .into_iter()
            .map(|candidate| candidate.node.to_string())
            .collect(),
        Err(_) if contacts.signet(person).is_some() => Vec::new(),
        Err(error) => return Err(unknown(error)),
    };
    if let Some(root) = contacts.signet(person) {
        holders.push(root.node.to_string());
    }
    let home_lock = HomeWrite::take(home).await?;
    let given = given_to(home, &holders).await?;
    if given.is_empty() {
        eyre::bail!("no link from this machine was given to {person}; nothing revoked.");
    }
    swoosh::revoked::add(&home_lock, home, given.into_iter().map(Revocation::Id))?;
    writeln!(
        err,
        "{}",
        Reach::Complete.line(&What::Revoked(person.to_string()))
    )?;
    Ok(())
}

/// A person this machine has no contact for: adding one is never how a revoke goes on, so the refusal
/// names where your contacts are listed.
fn unknown(error: ResolveError) -> eyre::Report {
    match error {
        ResolveError::UnknownPetname(person) => {
            eyre::eyre!("{person} is not one of your contacts (`swoosh status`)")
        }
        other => other.into(),
    }
}

/// A key, or a contact's device: every link given to it, then what else the key is here.
async fn key_links(
    home: &Home,
    keys: &[NodeId],
    what: &str,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let holders: Vec<String> = keys.iter().map(ToString::to_string).collect();
    let home_lock = HomeWrite::take(home).await?;
    let given = given_to(home, &holders).await?;
    let revoked = given.len();
    swoosh::revoked::add(&home_lock, home, given.into_iter().map(Revocation::Id))?;
    let mut trailing = Vec::new();
    for key in keys {
        trailing.extend(also(home, *key).await?);
    }
    if revoked == 0 {
        let mut lines = vec![format!(
            "no link from this machine was given to {what}; nothing revoked."
        )];
        lines.extend(trailing);
        eyre::bail!("{}", lines.join("\n"));
    }
    writeln!(
        err,
        "{}",
        Reach::Complete.line(&What::Revoked(what.to_owned()))
    )?;
    for line in trailing {
        writeln!(err, "{line}")?;
    }
    Ok(())
}

/// What else `key` is on this machine, one line each: one of your devices, or a root it knows. A root is
/// never revoked by its bare key, and no line prints a runnable root revoke. This machine's own key names
/// no device to revoke, since `revoke me/<own>` refuses.
async fn also(home: &Home, key: NodeId) -> eyre::Result<Vec<String>> {
    let short = format!("{}…", key.short());
    let verify = key.verify_key()?;
    let mut lines = Vec::new();
    let pin = pin(home).await;
    if let Some(pin) = pin
        && own_key(home)? != Some(verify)
        && let Some(doc) = swoosh::roster::held(home, pin)
        && let Some(member) = doc.members().iter().find(|member| member.node == verify)
    {
        let name = &member.label;
        lines.push(format!(
            "{short} is also your device me/{name}: `swoosh revoke me/{name}` revokes the device."
        ));
    }
    let store = ContactsStore::open(home).await?;
    let contacts = store.contacts();
    let mut roots = Vec::new();
    if pin == Some(verify) {
        roots.push("your root".to_owned());
    }
    for person in contacts.petnames() {
        if person.as_str() != ME
            && contacts
                .signet(person)
                .is_some_and(|binding| binding.node == key)
        {
            roots.push(format!("{person}'s root"));
        }
    }
    for root in roots {
        lines.push(format!(
            "{short} is also {root}. This took back only the links given to that key. To end a root: \
             swoosh revoke --help"
        ));
    }
    Ok(lines)
}

/// The root id of every link this machine's ledger records as given to one of `holders`, one per link.
async fn given_to(home: &Home, holders: &[String]) -> eyre::Result<Vec<RevocationId>> {
    let records = Grants::at(home.links()).load().await?;
    Ok(records
        .iter()
        .filter(|record| holders.contains(&record.holder))
        .map(|record| RevocationId::clone(&record.root_id))
        .collect())
}

/// Block `link` in this machine's `revoked` at its narrowest id, so it and everything narrowed from it are
/// refused and the wider link it was narrowed from is not. Under `home.lock`, which the caller holds.
fn revoke_link(home_lock: &HomeWrite, home: &Home, link: &Link) -> eyre::Result<()> {
    let narrowest = link.cap().revocation_ids().pop();
    swoosh::revoked::add(home_lock, home, narrowest.map(Revocation::Id))?;
    Ok(())
}

/// One link from stdin, and nothing else.
fn read_stdin(stdin: impl Read) -> eyre::Result<Link> {
    let mut text = String::new();
    stdin
        .take(MAX_STDIN)
        .read_to_string(&mut text)
        .map_err(|_| Usage("stdin held no swoosh: link.".to_owned()))?;
    let text = text.trim();
    if !swoosh::link::is_prefixed(text) {
        return Err(Usage("stdin held no swoosh: link.".to_owned()).into());
    }
    swoosh::link::parse(text).map_err(|error| Usage(format!("stdin: {error}")).into())
}

/// This machine's key, when it has one. Read only: a revoke never makes one.
fn own_key(home: &Home) -> eyre::Result<Option<VerifyKey>> {
    let stored = keystore::KeyFile::device(home.key())
        .load()
        .map_err(|error| eyre::eyre!(error))?;
    Ok(match stored {
        Some(stored) => Some(stored.node_id().verify_key()?),
        None => None,
    })
}

/// The root this machine trusts, when it trusts one.
async fn pin(home: &Home) -> Option<VerifyKey> {
    match Standing::read(home).await.ok()?.standing {
        Standing::Device { pin, .. } | Standing::HoldsRoot { pin, .. } => {
            swoosh::standing::pin_key(home, pin).ok()
        }
        Standing::Unpinned | Standing::InterruptedMint { .. } => None,
    }
}

fn short(key: &VerifyKey) -> String {
    swoosh::credential::short(key)
}

fn unix_now() -> u64 {
    unix_secs(std::time::SystemTime::now())
}

fn unix_secs(at: std::time::SystemTime) -> u64 {
    at.duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl swoosh::reaching::Reaching for RevokeRoot {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// The device part dials your devices itself: to sync before it signs, and to offer what it cut.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        None
    }

    /// `revoke` takes no `--present`, so there is nothing to conflict.
    fn reject_redundant_present(&self) -> eyre::Result<()> {
        Ok(())
    }

    fn identity(&self) -> swoosh::identity::Identity {
        self.bind_role().identity()
    }

    /// Dialing, as this machine: each device's gate admits it by the standing it presents.
    fn bind_role(&self) -> swoosh::reaching::BindRole {
        swoosh::reaching::BindRole::Dialing(swoosh::credential::Credential::Family {
            present: None,
        })
    }

    async fn run<T: Transport, D: Discovery>(
        self,
        node: &Node<T, D>,
        ctx: swoosh::reaching::ReachCtx<'_>,
    ) -> eyre::Result<()>
    where
        <T::Session as Session>::Write: Send + 'static,
        <T::Session as Session>::Read: Send + 'static,
    {
        let dial = NodeDial::new(node, ctx.home);
        self.publish
            .run(ctx.home, &mut Terminal, &dial, &mut io::stderr())
            .await
    }
}

#[cfg(test)]
#[path = "revoke_tests.rs"]
mod revoke_tests;
