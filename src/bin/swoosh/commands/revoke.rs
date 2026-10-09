//! `swoosh revoke`: take back a link, a device, or everything shared with a contact.
//!
//! ```text
//! revoke <link | path | ->     that link and everything narrowed from it
//! revoke me/<name>             the device: every id of its live standings, its key, and the links given it
//! revoke <person>              every link given to any device of that contact, or bound to their root
//! revoke <person>/<name>       every link given to that device's key
//! revoke <key>                 every link given to that key
//! revoke root:<key>            that root, for good, on this machine
//! ```
//!
//! Every form but the root's blocks here first, in this machine's own `revoked`, which a running
//! `serve` reads live. A link this machine signed, and a link it gave a key, were only ever admitted here,
//! so that block is the whole revoke. A device is admitted by all your devices: with your root (kept here,
//! or `--root <dir>`) the revoke then presents it, cuts, and offers the cut; without it, it stays on this
//! machine and says so. Only the root's passphrase is ever asked for, and only after the block is written;
//! a root step that cannot run says the device is blocked here only, in one line, and exits 1.
//!
//! `root:<key>` is the one form that ends something everywhere, so it is the one form that asks first: only
//! from argv (a link read from stdin or a file is never a root), never a key one of your devices or a
//! contact's holds, only at a terminal, and only once the person has read what this machine is to that root
//! and typed the 8 characters after the key's `ed01` ([`token`]). Then, by what this machine is to it: where the root is kept,
//! its passphrase, and the root and every file it vouched for go ([`swoosh::root::retire`]); on its device,
//! the device files and the pin go; for a contact's root, the links given to it are revoked. Each latches the
//! key into `revoked` first, so a crash leaves files rooted at a revoked key, which every read takes as
//! absent, and running it again finishes.

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
use swoosh::root_key::{RootKey, RootKeyError};
use swoosh::roster::Epoch;
use swoosh::standing::{Standing, StandingError};
use swoosh::sync::{Answer, Dial, ExchangeError, NodeDial};
use swoosh::transport::ReachArgs;
use tightbeam::identity::AsVerifyKey as _;

use crate::commands::token;

/// The most bytes of stdin read for one link: far above any link, far below anything that costs a read.
const MAX_STDIN: u64 = 64 * 1024;

/// Take back a link, a device, or everything you shared with a contact; or end a root for good.
#[derive(Debug, Args)]
#[command(after_long_help = RECIPE)]
pub struct RevokeCmd {
    /// what to take back
    #[arg(
        value_name = "link | path | - | me/<name> | <person> | <person>/<name> | key | root key",
        value_parser = target
    )]
    pub target: Target,
    /// use the copy of your root in <dir>
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
    /// `root:<key>`: a root, typed in argv and nowhere else.
    Root(RootKey),
}

/// The steps to replace your root, printed by `revoke --help` and never by `-h`: the one verb whose long
/// help carries a recipe, since the act cannot be undone and nobody should compose it on the worst day.
/// The link the first line makes is bound to a key made for the rescue, in its own home, which the old
/// root never listed and so a thief holding it cannot revoke first.
const RECIPE: &str = concat!(
    "To replace your root:\n",
    "  desk$   (umask 077; swoosh ssh me/nas -- swoosh share ssh $(swoosh --home ~/.swoosh-rescue leave --new-key) --expires 7d > ~/nas.link)\n",
    "  desk$   swoosh --home ~/.swoosh-rescue ssh ~/nas.link -- -t swoosh revoke root:ed01OLD…\n",
    "  desk$   swoosh revoke root:ed01OLD…\n",
    "  desk$   swoosh invite laptop ed01L…\n",
    "  desk$   swoosh invite nas ed01NAS… > nas.invite\n",
    "  desk$   swoosh --home ~/.swoosh-rescue ssh ~/nas.link -- swoosh join < nas.invite\n",
    "  laptop$ swoosh revoke root:ed01OLD…; swoosh join\n",
    // A runner named for no repo: no tracked file here names a repo that depends on swoosh (layering
    // check 4).
    "  desk$   swoosh invite runner --new-key | gh secret set SWOOSH_INVITE --repo <you>/<repo>\n",
    "  friend$ swoosh contact add <you> root:ed01NEW…\n",
    "  desk$   swoosh ssh me/nas -- swoosh revoke - < ~/nas.link; rm -r ~/nas.link ~/.swoosh-rescue",
);

/// The refusal when a root's revoke has no terminal to ask at: before anything is read, or when the
/// confirmation finds it gone.
const ROOT_NEEDS_TERMINAL: &str =
    "this cannot be undone, so it needs a terminal: over swoosh ssh, add -t after --";

/// The positional: `-`, a path, a link, a key, `root:<key>`, `me/<name>`, a person or one of their
/// devices. A bare word is a person, never `me/<name>`, and a bare key is always the key form, never a
/// root. `root:` with anything after it that is not a key, a name included, is a usage error; `root`
/// alone is the reserved name's.
fn target(text: &str) -> Result<Target, String> {
    if text == "-" {
        return Ok(Target::Stdin);
    }
    if swoosh::root_key::is_prefixed(text) {
        return match text.parse::<RootKey>() {
            Ok(root) => Ok(Target::Root(root)),
            Err(RootKeyError::Unusable(unusable)) => Err(unusable.to_string()),
            Err(RootKeyError::NotAKey(_) | RootKeyError::NoPrefix) => Err(format!(
                "{text} is not a root key; to see yours: swoosh status"
            )),
        };
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
    /// what it did. `Some` when a device part follows that needs the root. A root's revoke runs whole here,
    /// asking `prompt`; it cuts nothing, so `dial` is never dialed.
    pub async fn block(
        &self,
        home: &Home,
        stdin: impl Read,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        err: &mut impl Write,
    ) -> eyre::Result<Option<Publish>> {
        let target = match &self.target {
            Target::Stdin => Target::Link(read_stdin(stdin)?),
            other => other.clone(),
        };
        match target {
            Target::Root(root) => {
                self.revoke_root(home, root, prompt, dial, err).await?;
                Ok(None)
            }
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
                let short = swoosh::credential::short(&key);
                key_links(home, &[key], &short, err).await?;
                Ok(None)
            }
            Target::Stdin => Err(Usage("stdin held no link.".to_owned()).into()),
        }
    }

    /// `root:<key>`: what this machine is to that root, then every check, then the typed prefix; then, by
    /// what it is, the root's passphrase where it is kept, and the act under `home.lock`, the key latched
    /// first. Nothing is written before the prefix, nor before the passphrase where the root is kept.
    async fn revoke_root(
        &self,
        home: &Home,
        typed: RootKey,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        if self.root.is_some() {
            return Err(Usage(
                "--root is for acts that use your root; revoking a root needs none.".to_owned(),
            )
            .into());
        }
        let key = typed.key();
        if own_key(home)?.is_some_and(|own| key.verify_key().is_ok_and(|key| key == own)) {
            eyre::bail!("that is this machine's key, not a root.");
        }
        // Classified first, with no lock, prompt or write: a root this machine knows stays a root when a
        // list of devices also names its key, so only a key no root here is asked as a device's.
        let kind = Kind::of(home, key).await?;
        if kind == Kind::Unknown
            && let Some(refusal) = device_key(home, key).await?
        {
            eyre::bail!("{refusal}");
        }
        if !prompt.terminal() {
            eyre::bail!("{ROOT_NEEDS_TERMINAL}");
        }
        let root = typed.short();
        // Where the prompt is, so a stderr sent elsewhere never leaves the person typing blind.
        for line in kind.before(&root) {
            prompt.say(&line);
        }
        let answer = token::ask(prompt, typed, "revoke this root for good")
            // A terminal gone since the check is the missing terminal; a read or write that failed on an
            // open one prints its own cause.
            .map_err(|cause| match cause.downcast_ref::<std::io::Error>() {
                Some(_) => cause,
                None => eyre::eyre!("{ROOT_NEEDS_TERMINAL}"),
            })?;
        if answer == token::Typed::Other {
            eyre::bail!("that was not {}; nothing was revoked.", typed.token());
        }

        match &kind {
            Kind::Holder(Held::Pinned | Held::HalfMade) => {
                swoosh::root::retire(home, key, prompt, dial, err).await?;
            }
            Kind::Holder(Held::Latched) => swoosh::root::finish_retire(home, key).await?,
            Kind::Device { .. } | Kind::Contact(_) | Kind::Unknown => {
                let home_lock = HomeWrite::take(home).await?;
                // What this machine is to the root may have moved while the person typed: a join or a
                // contact added meanwhile.
                if Kind::of(home, key).await? != kind {
                    eyre::bail!("{}", swoosh::standing::CHANGED);
                }
                let links = match &kind {
                    Kind::Contact(_) => given_to(home, &[key.to_string()]).await?,
                    _ => Vec::new(),
                };
                let latch = Revocation::Key(key.verify_key()?);
                swoosh::revoked::add(
                    &home_lock,
                    home,
                    links.into_iter().map(Revocation::Id).chain([latch]),
                )?;
                if matches!(kind, Kind::Device { .. }) {
                    swoosh::joining::leave(&home_lock, home)?;
                }
            }
        }
        for line in kind.after(&root) {
            writeln!(err, "{line}")?;
        }
        if kind.admitted() && swoosh::home::serve_running(home).await {
            writeln!(
                err,
                "sessions from devices of {root} end now, yours too if you reached this machine as one."
            )?;
            writeln!(err, "sessions through links this machine made stay open.")?;
        }
        Ok(())
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
                "this link was issued by {}, not by this machine or your root. Revoke it where it was issued.",
                short(&issuer)
            );
        }
        let id = link.cap().root_revocation_id();
        let source = self.source(home).await?;
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
        let source = self.source(home).await?;
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
            // Said only once the root step commits ([`Publish::run`]): until then the device is blocked on
            // this machine alone.
            Some(place) => {
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
    async fn source(&self, home: &Home) -> eyre::Result<Source> {
        let standing = match Standing::read(home).await {
            Ok(standing) => standing,
            Err(StandingError::Damaged(what)) => {
                eyre::bail!("{}", swoosh::standing::damaged_line(&what))
            }
            Err(other) => return Err(other.into()),
        };
        let place = match (&self.root, &standing) {
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
        match (&source.place, &standing) {
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
                    source.revoked_keys = doc.revoked_keys().collect();
                }
            }
            (None, _) => {}
        }
        Ok(source)
    }
}

/// What this machine is to a root a `revoke root:<key>` names, read from its files as they lie. A root a
/// revoke latched and did not finish still reads as what it was, so running the revoke again finishes it.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Kind {
    /// The root is kept here.
    Holder(Held),
    /// This machine is the root's device, `name` among your devices when its list says so. `latched` when a
    /// revoke latched the root and stopped, so only the pin's file still names it.
    Device {
        name: Option<DeviceLabel>,
        latched: bool,
    },
    /// The root of a contact.
    Contact(Petname),
    /// A root this machine does not know.
    Unknown,
}

/// How the root kept here stands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Held {
    /// Made, and this machine's pin.
    Pinned,
    /// Its making or restore stopped after `root.key` and before the pin: a root all the same, and nothing
    /// was ever admitted here under it.
    HalfMade,
    /// Latched by a revoke that stopped: what it left goes with no passphrase.
    Latched,
}

impl Kind {
    /// Read with no lock, no prompt and no write. A home whose records disagree refuses, as every verb that
    /// needs to know which root it trusts does.
    async fn of(home: &Home, key: NodeId) -> eyre::Result<Self> {
        if Standing::revoked_root(home).await? == Some(key) {
            return Ok(Self::Holder(Held::Latched));
        }
        let standing = match Standing::read(home).await {
            Ok(standing) => standing,
            Err(StandingError::Damaged(what)) => {
                eyre::bail!("{}", swoosh::standing::damaged_line(&what))
            }
            Err(other) => return Err(other.into()),
        };
        match standing {
            Standing::HoldsRoot { pin, .. } if pin == key => {
                return Ok(Self::Holder(Held::Pinned));
            }
            // A root half made here is retired as a made one: it asks its passphrase, then latches and goes.
            Standing::InterruptedMint { root_key } if root_key == key => {
                return Ok(Self::Holder(Held::HalfMade));
            }
            Standing::Device { pin, .. } if pin == key => {
                return Ok(Self::Device {
                    name: swoosh::renewal::own_label(home).await,
                    latched: false,
                });
            }
            _ => {}
        }
        // A pin a revoke latched and did not remove reads as no pin; its file still names the root.
        if pinned_file(home).await == Some(key) {
            return Ok(Self::Device {
                name: None,
                latched: true,
            });
        }
        let store = ContactsStore::open(home).await?;
        let contacts = store.contacts();
        Ok(contacts
            .petnames()
            .find(|person| {
                person.as_str() != ME
                    && contacts
                        .signet(person)
                        .is_some_and(|binding| binding.node == key)
            })
            .map_or(Self::Unknown, |person| Self::Contact(person.clone())))
    }

    /// Whether this machine admitted sessions under the root until this act: it was the live pin. A root
    /// half made was never pinned, and one a stopped revoke latched ended its sessions then.
    fn admitted(&self) -> bool {
        matches!(
            self,
            Self::Holder(Held::Pinned) | Self::Device { latched: false, .. }
        )
    }

    /// The lines before the prompt: what this machine is to `root`, and what revoking it does here.
    fn before(&self, root: &str) -> Vec<String> {
        match self {
            Self::Holder(_) => vec![format!(
                "this machine keeps {root}; this deletes it here and ends it for good."
            )],
            Self::Device {
                name: Some(name), ..
            } => vec![format!(
                "this machine is me/{name}, a device of {root}; it leaves that root and can never join it \
                 again."
            )],
            Self::Device { name: None, .. } => vec![format!(
                "this machine is a device of {root}; it leaves that root and can never join it again."
            )],
            Self::Contact(person) => vec![
                format!("{root} is {person}'s root; this machine will never trust it again."),
                format!("to stop sharing with {person} instead: swoosh revoke {person}"),
            ],
            Self::Unknown => vec![format!(
                "this machine does not know {root}, and will never trust it."
            )],
        }
    }

    /// The lines once the act has committed.
    fn after(&self, root: &str) -> Vec<String> {
        match self {
            Self::Holder(_) => vec![
                format!("retired {root}, your root, on this machine."),
                "to make a new root: swoosh invite <name> <key>".to_owned(),
                "tell your contacts; each of them runs: swoosh contact add <you> <new root key>"
                    .to_owned(),
            ],
            Self::Device { .. } => vec![
                format!("left {root} for good."),
                "to join a new root: swoosh join".to_owned(),
            ],
            Self::Contact(_) | Self::Unknown => vec![format!("revoked {root} here for good.")],
        }
    }
}

/// The refusal when `key` is a device's, one of yours or a contact's, and so never a root: the root form
/// would latch it as a root this machine does not know, and your root's next act would carry that to every
/// one of your devices. `None` when no device here holds it.
async fn device_key(home: &Home, key: NodeId) -> eyre::Result<Option<String>> {
    let store = ContactsStore::open(home).await?;
    let contacts = store.contacts();
    for person in contacts.petnames() {
        let Some(name) = contacts
            .devices(person)
            .and_then(|mut devices| devices.find(|(_, node)| **node == key))
            .map(|(name, _)| name)
        else {
            continue;
        };
        return Ok(Some(if person.as_str() == ME {
            format!(
                "that is me/{name}'s key, not a root; to revoke the device: swoosh revoke me/{name}"
            )
        } else {
            format!(
                "that is {person}/{name}'s key, not a root; to take back the links this machine gave it: \
                 swoosh revoke {person}/{name}"
            )
        }));
    }
    Ok(None)
}

/// The root `root.pub` names, read as the file lies: a pin this machine revoked included, which every
/// other read takes as no pin. `None` when there is none, or it is not one key.
async fn pinned_file(home: &Home) -> Option<NodeId> {
    swoosh::home::read_trust_file_async(&home.root_pub())
        .await
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The dial a root's revoke is given outside tests: the act cuts nothing, so nothing is dialed, and a dial
/// refuses.
#[derive(Debug, Clone, Copy)]
pub struct Undialed;

impl Dial for Undialed {
    async fn exchange(&self, _peer: NodeId) -> Result<Answer, ExchangeError> {
        Err(eyre::eyre!("a root's revoke dials none of your devices").into())
    }

    async fn offer(
        &self,
        peer: NodeId,
        _number: Epoch,
        _bytes: &[u8],
    ) -> Result<Answer, ExchangeError> {
        self.exchange(peer).await
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
    /// Present the root, revoke the device, cut, and offer the cut; then say which of your devices took it,
    /// and that the device can never come back under its key. A root step that cannot finish says the
    /// device is blocked on this machine only ([`partway`]).
    pub(crate) async fn run(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let name = &self.name;
        let committed = async {
            let mut root =
                Root::present_to(home, self.place, RootVerb::Revoke, prompt, dial, err).await?;
            root.revoke_device(name, self.key, &self.listed)?;
            let _ = root.renew_due()?;
            root.commit_to(err).await
        }
        .await
        .map_err(|error| partway(name, error))?;
        let reach = committed.offer(dial).await;
        writeln!(
            err,
            "{}",
            reach.line(&What::Revoked(format!("me/{}", self.name)))
        )?;
        if self.links {
            writeln!(err, "{LINKS_LINE}")?;
        }
        writeln!(
            err,
            "me/{name} can never rejoin your devices with its current key."
        )?;
        writeln!(
            err,
            "to add {name} again, first run this at its console: swoosh leave --new-key"
        )?;
        Ok(())
    }
}

/// The refusal when the root step of `revoke me/<name>` stops, its block on this machine already written:
/// what landed and what did not. A cause this names the fix for is one line; any other is the partway
/// sentence, then the cause's own line, which names its own fix. A Ctrl-C at the prompt ends by its signal,
/// and says nothing.
fn partway(name: &DeviceLabel, error: RootError) -> eyre::Report {
    let blocked = format!("me/{name} is blocked on this machine, not yet on your other devices");
    match error {
        RootError::NoTerminalToUnlock => eyre::eyre!(
            "{blocked}; your root's passphrase needs a terminal: over swoosh ssh, add -t after --"
        ),
        // A third wrong passphrase, or a prompt that ended without one; or the home changed under the act,
        // which a rerun reads afresh.
        RootError::Prompt(_) | RootError::NotOnThisMachine | RootError::NoRootHere => {
            eyre::eyre!("{blocked}; to finish, run it again: swoosh revoke me/{name}")
        }
        // One message, two lines: a cause chained after a colon would run its sentences into this one.
        other => eyre::eyre!("{blocked}.\n{other}"),
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
    let short = swoosh::credential::short(&key);
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
        .map_err(|_| Usage("stdin held no link.".to_owned()))?;
    let text = text.trim();
    if !swoosh::link::is_prefixed(text) {
        return Err(Usage("stdin held no link.".to_owned()).into());
    }
    swoosh::link::parse(text).map_err(|error| Usage(format!("stdin: {error}")).into())
}

/// This machine's key, when it has one. Read only: a revoke never makes one.
fn own_key(home: &Home) -> eyre::Result<Option<VerifyKey>> {
    let file = keystore::KeyFile::new(home.key());
    let stored = file.load().map_err(|error| eyre::eyre!(error))?;
    Ok(match stored {
        Some(stored) => Some(swoosh::identity::key_of(&file, &stored)?.verify_key()?),
        None => None,
    })
}

/// The root this machine trusts, when it trusts one.
async fn pin(home: &Home) -> Option<VerifyKey> {
    match Standing::read(home).await.ok()? {
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
pub(crate) mod revoke_tests;
