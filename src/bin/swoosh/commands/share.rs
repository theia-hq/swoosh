//! `swoosh share <service> <who>`: make a link to one of this machine's services; `swoosh share <link>`: make
//! a shorter copy of a link.
//!
//! A local verb: it binds no transport. The service form signs with this machine's own key (the key its
//! `serve` answers at), records the link in the ledger before it prints, and says on stderr what the link
//! gives. Who it is for decides how it is bound, from the shape of the name: a person (`bob`) is every
//! machine of the root saved for them, `bob/laptop` or a key is that one machine, and `anyone` is whoever
//! holds the link. A bound link is sealed, since only who it names can use it; an `anyone` link is left open,
//! so its holder can make a shorter copy.
//!
//! An `anyone` link to a service whose engine must never face an open gate (a shell, an engine with no
//! limits of its own, receiving files) is refused unless `--once` asks for it, and so is one to a target
//! swoosh does not know. `--once` makes a link for anyone that this machine admits once, that lasts 15
//! minutes at most, and that is sealed, so it cannot be passed on. Every row records what the service's name
//! served when the link was made, so `serve` admits a link only to that target, and warns when it binds
//! such an engine under a name whose links were made for something else.
//!
//! The link form is wholly offline: it reads no key and writes no ledger row, it only adds a shorter end to
//! the link it was given. A copy can never do more than its source, so it needs no one's leave. The link is
//! read from a path or stdin as well as typed, so it need never enter argv.
//!
//! Every check that can refuse runs before anything is written. `--save`'s file is made, empty, before the
//! key is read or a row is written, and filled before any line says what the link gives, so a file that
//! cannot be made leaves no row behind, and a refused save never follows a line that claimed it worked.

use core::fmt;
use core::time::Duration;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt as _;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use bifrost::NodeId;
use clap::Args;
use nauthy::{Cap, CapError, Link, Service};
use swoosh::contacts::{ContactRef, Contacts, ContactsStore, ME, Petname};
use swoosh::escape::EscapedPath;
use swoosh::grants::{self, Delegation, GrantKind, GrantRecord, Grants};
use swoosh::home::{Home, HomeWrite};
use swoosh::identity::{self, Identity};
use swoosh::names::NameError;
use swoosh::node_signer::{Bind, NodeSigner};
use swoosh::serve::{Scheme, ServedTarget, Started};
use swoosh::serve_toml::ServeToml;
use tightbeam::identity::AsVerifyKey as _;

/// Make a link to a service for a person, a device, a key, or anyone
#[derive(Debug, Args)]
pub struct ShareCmd {
    /// the service, or a link to copy: swoosh:…, a path, or - for stdin
    #[arg(value_name = "service | link", value_parser = shared)]
    pub what: Shared,
    /// who it is for
    #[arg(value_name = "person | person/name | key | anyone", value_parser = recipient)]
    pub who: Option<Recipient>,
    /// How long: `2h`, `90d`.
    #[arg(long, value_name = "d", value_parser = str::parse::<Span>)]
    pub expires: Option<Span>,
    /// Write the link to a new private file and print only the path.
    #[arg(long, value_name = "file")]
    pub save: Option<PathBuf>,
    /// Make a link to anyone that works once and lasts 15m at most.
    #[arg(long)]
    pub once: bool,
}

/// What `share` was given first: a service to make a link to, or a link to copy.
#[derive(Debug, Clone)]
pub enum Shared {
    /// A service this machine serves, by name.
    Service(Service),
    /// A link, typed as `swoosh:…` or read from the file a path names.
    Link(Link),
    /// `-`: one link, read from stdin.
    Stdin,
}

/// Who a link is for, by the shape of the name typed.
#[derive(Debug, Clone)]
pub enum Recipient {
    /// `anyone`: whoever holds the link.
    Anyone,
    /// `<person>`: every machine of the root saved for them.
    Person(Petname),
    /// `<person>/<name>`: one machine of theirs.
    Device(ContactRef),
    /// A key: that one machine.
    Key(NodeId),
}

/// The recipient that is whoever holds the link: a reserved name, so no contact can be called it.
const ANYONE: &str = "anyone";

/// The shortest `--expires` the service form takes: a link must live long enough to be delivered. A copy has
/// no floor, since shortening is the whole act and its source bounds it.
const SHORTEST: Duration = Duration::from_secs(60 * 60);

/// The longest `--expires` the service form takes.
const LONGEST: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The life of a `--once` link, and the longest `--expires` it takes.
const ONCE: Duration = Duration::from_secs(15 * 60);

/// The refusal for `--expires` outside a link's range.
const EXPIRES_RANGE: &str = "a link's --expires is 1h to 365d";

/// The refusal for `--expires` past a one-use link's life.
const EXPIRES_ONCE: &str = "with --once, --expires is 15m at most";

/// The refusal for `--once` with a recipient other than `anyone`, or on a link.
const ONCE_ANYONE: &str = "--once is only for a link to anyone";

/// The most read from stdin for one link. A link is well under a kilobyte.
const MAX_STDIN: u64 = 64 * 1024;

/// The refusal for a sealed link handed to `share <link>`: one bound to a person or a machine, or one that
/// works once. One line, true of both, so the refusal never says which kind a link is.
const BOUND: &str = "this link cannot be copied: ask whoever made it for another";

/// The line for your own devices as a recipient: they reach what this machine serves already.
const YOURS: &str = "your devices already reach it.";

/// The first positional: `-`, a path, a `swoosh:` link, or a service name. A path is read here, so the
/// link it holds never enters argv; text shaped like a link without its prefix refuses naming the prefix.
fn shared(text: &str) -> Result<Shared, String> {
    if text == "-" {
        return Ok(Shared::Stdin);
    }
    if swoosh::peer::is_path(text) {
        return swoosh::peer::read_link_file(text)
            .map(|(link, _)| Shared::Link(link))
            .map_err(|error| error.to_string());
    }
    if swoosh::link::is_prefixed(text) {
        return swoosh::link::parse(text)
            .map(Shared::Link)
            .map_err(|error| error.to_string());
    }
    if swoosh::link::looks_bare(text) {
        return Err(swoosh::link::LinkError::Prefix.to_string());
    }
    swoosh::names::service(text)
        .map(Shared::Service)
        .map_err(|error| error.to_string())
}

/// The second positional: `anyone`, a key, `<person>` or `<person>/<name>`. Empty text names nobody, and
/// `me` or `me/<name>` is refused: your devices reach this machine without a link.
fn recipient(text: &str) -> Result<Recipient, String> {
    if text.trim().is_empty() {
        return Err(who_is_it_for("<service>"));
    }
    match swoosh::peer::raw_key(text) {
        Ok(Some(key)) => return Ok(Recipient::Key(key)),
        Ok(None) => {}
        Err(unusable) => return Err(unusable.to_string()),
    }
    let typed: ContactRef = text.parse().map_err(|error: NameError| error.to_string())?;
    if typed.petname().as_str() == ME {
        return Err(YOURS.to_owned());
    }
    if typed.device().is_none() && typed.petname().as_str() == ANYONE {
        return Ok(Recipient::Anyone);
    }
    Petname::clone(typed.petname())
        .unreserved()
        .map_err(|error| error.to_string())?;
    Ok(match typed.device() {
        None => Recipient::Person(Petname::clone(typed.petname())),
        Some(_) => Recipient::Device(typed),
    })
}

/// A span as `--expires` takes it and a line prints it back: one or more counts, each with its unit (`d`,
/// `h`, `m`), largest first and each unit once (`2h`, `90m`, `1h30m`). The minute is the smallest unit, so
/// no link ends before it could be pasted. It keeps the text typed, so `90m`
/// prints `90m` and `1h30m` prints `1h30m`: the same span, said the way the person said it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Span {
    typed: String,
    span: Duration,
}

impl Span {
    /// The default life of a link from the service form: `1h`.
    fn default_life() -> Self {
        Self {
            typed: "1h".to_owned(),
            span: SHORTEST,
        }
    }

    /// The default life of a `--once` link: `15m`, the most it takes.
    fn once_life() -> Self {
        Self {
            typed: "15m".to_owned(),
            span: ONCE,
        }
    }

    /// How long the span is.
    fn duration(&self) -> Duration {
        self.span
    }
}

/// The units a span takes, largest first, with their length in seconds.
const UNITS: [(char, u64); 3] = [('d', 24 * 60 * 60), ('h', 60 * 60), ('m', 60)];

/// The refusal for text that is not a span.
const NOT_A_SPAN: &str = "a span is a number and a unit, like 2h, 90d or 1h30m";

impl core::str::FromStr for Span {
    type Err = String;

    fn from_str(text: &str) -> Result<Self, Self::Err> {
        let mut secs: u64 = 0;
        // Each unit is taken at most once and only after a larger one, so the next one is looked for from here.
        let mut units = UNITS.iter();
        let mut rest = text;
        while !rest.is_empty() {
            let digits = rest
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(rest.len());
            let (count, after) = rest.split_at(digits);
            let mut chars = after.chars();
            let unit = chars.next().ok_or(NOT_A_SPAN)?;
            let &(_, each) = units.find(|(name, _)| *name == unit).ok_or(NOT_A_SPAN)?;
            let count: u64 = count.parse().map_err(|_| NOT_A_SPAN)?;
            secs = count
                .checked_mul(each)
                .and_then(|part| secs.checked_add(part))
                .ok_or(NOT_A_SPAN)?;
            rest = chars.as_str();
        }
        if secs == 0 {
            return Err(NOT_A_SPAN.to_owned());
        }
        Ok(Self {
            typed: text.to_owned(),
            span: Duration::from_secs(secs),
        })
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.typed)
    }
}

/// How many times a link from the service form admits: until it ends, or once.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Uses {
    /// Every admission until it ends.
    UntilItEnds,
    /// The first admission only (`--once`).
    Once,
}

impl Uses {
    /// The life a link of these uses gets from `--expires`: 1h to 365d, 1h when not given; or, once, 15m
    /// at most, 15m when not given. A copy is not checked here: its source bounds it.
    fn life(self, expires: Option<Span>) -> Result<Span, Usage> {
        match self {
            Self::UntilItEnds => {
                let span = expires.unwrap_or_else(Span::default_life);
                if !(SHORTEST..=LONGEST).contains(&span.duration()) {
                    return Err(Usage(EXPIRES_RANGE.to_owned()));
                }
                Ok(span)
            }
            Self::Once => {
                let span = expires.unwrap_or_else(Span::once_life);
                if span.duration() > ONCE {
                    return Err(Usage(EXPIRES_ONCE.to_owned()));
                }
                Ok(span)
            }
        }
    }
}

/// The refusal for a share that names no one, spelled with the service typed.
fn who_is_it_for(service: &str) -> String {
    format!(
        "who is it for? swoosh share {service} <person>, <person>/<name>, <key>, or anyone (whoever holds the link)"
    )
}

/// A usage error found once the command runs (no recipient, or one given with a link): exit 2, as clap's
/// own are.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct Usage(pub String);

impl ShareCmd {
    /// Make the link, or the copy: refuse what the arguments refuse before anything is written, then the
    /// lines that say what it gives on `err` and the link (or the `--save` path) on `out`.
    pub async fn run(
        self,
        home: &Home,
        stdin: impl Read,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let source = match self.what {
            Shared::Service(service) => {
                let Some(who) = self.who else {
                    return Err(Usage(who_is_it_for(service.as_str())).into());
                };
                let uses = match (self.once, &who) {
                    (false, _) => Uses::UntilItEnds,
                    (true, Recipient::Anyone) => Uses::Once,
                    (true, _) => return Err(Usage(ONCE_ANYONE.to_owned()).into()),
                };
                let issue = Issue {
                    service,
                    who,
                    uses,
                    lifetime: uses.life(self.expires)?,
                };
                return issue.run(home, self.save.as_deref(), out, err).await;
            }
            Shared::Link(_) | Shared::Stdin if self.once => {
                return Err(Usage(ONCE_ANYONE.to_owned()).into());
            }
            Shared::Link(link) => link,
            Shared::Stdin => read_stdin(stdin)?,
        };
        if self.who.is_some() {
            return Err(Usage(
                "a copy of a link is for whoever holds it, so share <link> takes no recipient"
                    .to_owned(),
            )
            .into());
        }
        copy(
            &source,
            self.expires.as_ref(),
            self.save.as_deref(),
            out,
            err,
        )
    }
}

/// One link to make from the service form, its arguments read.
struct Issue {
    service: Service,
    who: Recipient,
    uses: Uses,
    lifetime: Span,
}

impl Issue {
    /// Resolve what the service is here, and who it is for, before anything is written; refuse an `anyone`
    /// link to an engine that must never face an open gate unless it works once, and to a target swoosh
    /// does not know at all; then sign, record the row, and print.
    async fn run(
        self,
        home: &Home,
        save: Option<&Path>,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let service = &self.service;
        let serves = match Served::of(service, &ServeToml::read(home)?, home)? {
            Served::Nothing => None,
            Served::Target(target) => Some(target),
            // Nothing can say what such a target would give anyone, so it gets no link to anyone; a bound
            // link records nothing for it, and the gate admits no link to a name bound to it anyway.
            Served::Unknown(target) if matches!(self.who, Recipient::Anyone) => eyre::bail!(
                "{service} serves {}, which swoosh does not know; share it with a person: swoosh share \
                 {service} <person>",
                target.escape_debug()
            ),
            Served::Unknown(_) => None,
        };
        let runs_code = serves.as_ref().is_some_and(ServedTarget::runs_code);
        if serves.as_ref().is_some_and(ServedTarget::never_public)
            && matches!(self.who, Recipient::Anyone)
            && self.uses == Uses::UntilItEnds
        {
            let gives = if runs_code {
                format!("{service} opens a shell on this machine")
            } else {
                format!("whoever holds a link to anyone could use {service} any number of times")
            };
            eyre::bail!(
                "{gives}; share it with a person: swoosh share {service} <person>\nor make a link that \
                 works once: swoosh share {service} anyone --once"
            );
        }
        let gives = Gives::of(service, serves.as_ref());
        let store = ContactsStore::open(home).await?;
        let bound = self.bind(store.contacts(), home).await?;
        // A `--save` file is made before the key is read or a row is written, so a directory that takes no
        // new file refuses with no row; any error after this removes it.
        let save = save.map(NewFile::make).transpose()?;
        let link = self.sign(home, &bound, serves).await?;
        let delivered = Delivered::new(&link, save)?;
        let until = Until::from_now(self.lifetime.duration(), Some(&self.lifetime));
        // A one-use link says so in the grant's own line, so its end prints once.
        let before_until = match self.uses {
            Uses::Once => ", once, ",
            Uses::UntilItEnds => gives.before_until(),
        };
        writeln!(err, "{} {gives}{before_until}until {until}.", bound.who)?;
        writeln!(
            err,
            "the link dials this machine: it works while this machine serves {service}."
        )?;
        match (bound.bind, runs_code) {
            (Bind::Anyone, true) => writeln!(
                err,
                "that shell can reach your other devices: send the link privately."
            )?,
            (Bind::Anyone, false) => writeln!(
                err,
                "anyone holding this link can use it: send it privately."
            )?,
            (Bind::Device(_) | Bind::Fleet(_), true) => {
                writeln!(err, "that shell can reach your other devices.")?;
            }
            (Bind::Device(_) | Bind::Fleet(_), false) => {}
        }
        delivered.print(out)
    }

    /// The bind the recipient names, with what the ledger records for it. A person is the root saved for
    /// them, never one of their devices, and never your own root: your devices reach this machine already.
    async fn bind(&self, contacts: &Contacts, home: &Home) -> eyre::Result<Bound> {
        Ok(match &self.who {
            // A one-use link is sealed: a narrowed copy would be a second link to spend.
            Recipient::Anyone => {
                let (kind, delegation) = match self.uses {
                    Uses::UntilItEnds => (GrantKind::Bearer, Delegation::Delegable),
                    Uses::Once => (GrantKind::Once, Delegation::Sealed),
                };
                Bound {
                    bind: Bind::Anyone,
                    kind,
                    delegation,
                    holder: grants::ANYONE.to_owned(),
                    who: ANYONE.to_owned(),
                }
            }
            Recipient::Person(person) => {
                let Some(root) = contacts.signet(person).map(|binding| binding.node) else {
                    eyre::bail!(
                        "{person} has no root saved here: swoosh contact add {person} <root key>"
                    );
                };
                if swoosh::config::load_signet(home).await? == Some(root) {
                    eyre::bail!("{person} is saved with your own root: {YOURS}");
                }
                // This machine's gate refuses every badge under a root it revoked, so a link bound to one
                // would print and never work.
                if swoosh::config::is_revoked(home, root)? {
                    eyre::bail!(
                        "{person}'s root is revoked here, so a link for {person} would not work"
                    );
                }
                Bound {
                    bind: Bind::Fleet(root.verify_key()?),
                    kind: GrantKind::Fleet,
                    delegation: Delegation::Sealed,
                    holder: root.to_string(),
                    who: person.to_string(),
                }
            }
            Recipient::Device(device) => {
                let node = match contacts.resolve_candidates(device)?.as_slice() {
                    [one] => one.node,
                    _ => eyre::bail!("{device} names more than one device; name exactly one"),
                };
                Bound::machine(node, device.to_string())?
            }
            Recipient::Key(key) => Bound::machine(*key, key.to_string())?,
        })
    }

    /// Sign the link under this machine's key (made here on first use) and record its row under
    /// `home.lock`, so the link is on disk before it prints and this machine's gate admits it.
    async fn sign(
        &self,
        home: &Home,
        bound: &Bound,
        serves: Option<ServedTarget>,
    ) -> eyre::Result<Link> {
        let secret = identity::resolve(Identity::Persisted, home).await?;
        // A slip bound to this machine's own key would let a copy of that key vouch for any device it
        // likes, so the root of a person is never this machine.
        if let Bind::Fleet(root) = bound.bind
            && secret.node_id().verify_key()? == root
        {
            eyre::bail!(
                "{} is saved with this machine's own key: {YOURS}",
                bound.who
            );
        }
        let lifetime = self.lifetime.duration();
        let expiry = nauthy::Request::expires_in(lifetime);
        let link = NodeSigner::from(&secret).mint_slip(
            &self.service,
            bound.bind,
            lifetime,
            bound.delegation,
        )?;
        let root_id = Cap::parse(link.as_str())?
            .root_revocation_id()
            .ok_or_else(|| eyre::eyre!("the link has no id to revoke it by"))?;
        let record = GrantRecord {
            target: Service::clone(&self.service),
            serves,
            kind: bound.kind,
            delegation: bound.delegation,
            holder: bound.holder.clone(),
            root_id,
            expiry,
        };
        let home_lock = HomeWrite::take(home).await?;
        Grants::at(home.links()).append(&home_lock, &record)?;
        Ok(link)
    }
}

/// A recipient, resolved: how the link is bound, how the ledger records it, and how a line names it.
struct Bound {
    bind: Bind,
    kind: GrantKind,
    delegation: Delegation,
    /// The ledger's holder: the resolved key, so `revoke` finds the row by name or by key.
    holder: String,
    /// The recipient as a line names it.
    who: String,
}

impl Bound {
    /// One machine, by its key: a sealed link only that machine can use.
    fn machine(node: NodeId, who: String) -> eyre::Result<Self> {
        Ok(Self {
            bind: Bind::Device(node.verify_key()?),
            kind: GrantKind::Device,
            delegation: Delegation::Sealed,
            holder: node.to_string(),
            who,
        })
    }
}

/// What a bare `serve` would bind for a service's name now: the target of its entry in `serve.toml`, names
/// folded the way `serve` folds them, else the built-in form's (`ssh` is `sshd:`), else nothing. What a link
/// records it was made for, and what it says it gives.
enum Served {
    /// No entry, and no built-in form.
    Nothing,
    /// A target some `serve` binds.
    Target(ServedTarget),
    /// A target no link can record: a scheme no `serve` binds, or a control character.
    Unknown(String),
}

impl Served {
    /// Read what `service` serves from `served`, the home's `serve.toml`, as a bare `serve` would start it.
    ///
    /// # Errors
    ///
    /// `served` lists something that is not a service form, which `serve` refuses to start over too.
    fn of(service: &Service, served: &ServeToml, home: &Home) -> eyre::Result<Self> {
        let name = service.as_str();
        let entries = Started::bare(served, &home.serve_toml())?.entries();
        let target = entries
            .iter()
            .find_map(|entry| {
                entry
                    .split_once('=')
                    .filter(|(named, _)| *named == name)
                    .map(|(_, target)| target.to_owned())
            })
            .or_else(|| {
                swoosh::serve::service_entry(name)
                    .ok()
                    .and_then(|entry| entry.split_once('=').map(|(_, target)| target.to_owned()))
            });
        Ok(match target {
            None => Self::Nothing,
            Some(target) => match target.parse() {
                Ok(target) => Self::Target(target),
                Err(_) => Self::Unknown(target),
            },
        })
    }
}

/// What a link to a service gives, from what its name serves ([`serves`]).
#[derive(Debug, PartialEq, Eq)]
enum Gives {
    /// A shell on this machine.
    Shell,
    /// A forward to a local address or socket: the service name, and where it leads.
    Forward { service: String, to: String },
    /// A proxy through this machine, to the origin it is scoped to (all of them when empty).
    Proxy { origin: String },
    /// Anything else: the service by name.
    Service(String),
}

impl Gives {
    /// Read what `service` gives, serving `served`.
    fn of(service: &Service, served: Option<&ServedTarget>) -> Self {
        let name = service.as_str();
        let Some(served) = served else {
            return Self::Service(name.to_owned());
        };
        match served.scheme() {
            Scheme::Sshd => Self::Shell,
            Scheme::Tcp | Scheme::Unix => Self::Forward {
                service: name.to_owned(),
                to: served.argument().to_owned(),
            },
            Scheme::Proxy => Self::Proxy {
                origin: served.argument().to_owned(),
            },
            Scheme::Ping
            | Scheme::Speed
            | Scheme::Recv
            | Scheme::File
            | Scheme::Fifo
            | Scheme::Stdin
            | Scheme::Echo => Self::Service(name.to_owned()),
        }
    }

    /// What goes between the grant and "until": a comma after a grant that ends in a place.
    fn before_until(&self) -> &'static str {
        match self {
            Self::Proxy { .. } => ", ",
            Self::Shell | Self::Forward { .. } | Self::Service(_) => " ",
        }
    }
}

impl fmt::Display for Gives {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Shell => f.write_str("can open a shell on this machine"),
            Self::Forward { service, to } => {
                write!(f, "can reach {service} ({to} on this machine)")
            }
            Self::Proxy { origin } if origin.is_empty() => {
                f.write_str("can reach, through this machine, anything this machine can reach")
            }
            Self::Proxy { origin } => write!(
                f,
                "can reach, through this machine, anything this machine can reach at {origin}"
            ),
            Self::Service(service) => write!(f, "can use {service} on this machine"),
        }
    }
}

/// `share <link>`: a copy of `source` that ends at `expires` from now, or when the source does. A bound
/// link is sealed, so it refuses: it works only for whoever it was made for.
fn copy(
    source: &Link,
    expires: Option<&Span>,
    save: Option<&Path>,
    out: &mut impl Write,
    err: &mut impl Write,
) -> eyre::Result<()> {
    let now = SystemTime::now();
    let ends = source
        .cap()
        .valid_until()?
        .ok_or_else(|| eyre::eyre!("this link carries no end date; nothing was copied."))?;
    let left = ends
        .duration_since(now)
        .ok()
        .filter(|left| !left.is_zero())
        .ok_or_else(|| eyre::eyre!("this link has ended; nothing was copied."))?;
    // A copy ends where `--expires` asked only when that is sooner than its link; otherwise it ends with its
    // link, and its line says so rather than print a span nobody typed.
    let asked = expires.filter(|asked| asked.duration() < left);
    let span = asked.map_or(left, Span::duration);
    let copy = match source.narrow(None, Some(span)) {
        Ok(copy) => copy,
        Err(CapError::Attenuate(_)) => eyre::bail!("{BOUND}"),
        Err(other) => return Err(other.into()),
    };
    let save = save.map(NewFile::make).transpose()?;
    let delivered = Delivered::new(&copy, save)?;
    let until = Until::from_now(span, asked);
    match asked {
        Some(_) => writeln!(err, "the copy works until {until}.")?,
        None => writeln!(err, "the copy works until {until}, when its link ends.")?,
    }
    writeln!(
        err,
        "anyone holding this link can use it: send it privately."
    )?;
    delivered.print(out)
}

/// A link made and, under `--save`, already in its file: all that is left is to print it, or the path.
enum Delivered<'a> {
    /// No `--save`: the link itself goes to stdout.
    Printed(swoosh::link::Link),
    /// Written into this new file; only the path goes to stdout.
    Saved(&'a Path),
}

impl<'a> Delivered<'a> {
    /// Fill the `--save` file now, before any line says what the link gives, so a file that cannot be
    /// written refuses with nothing claimed.
    fn new(link: &Link, save: Option<NewFile<'a>>) -> eyre::Result<Self> {
        let printed = swoosh::link::Link::from(Link::clone(link));
        match save {
            Some(file) => Ok(Self::Saved(file.fill(&printed)?)),
            None => Ok(Self::Printed(printed)),
        }
    }

    /// The one stdout line: the link, or the path it was saved to.
    fn print(self, out: &mut impl Write) -> eyre::Result<()> {
        match self {
            Self::Printed(link) => writeln!(out, "{link}")?,
            Self::Saved(path) => writeln!(out, "{}", EscapedPath(path))?,
        }
        Ok(())
    }
}

/// A `--save` file made new and empty, `0600`, before the key is read or a row is written: a directory that
/// takes no new file then refuses before there is a row for a link nobody holds. Dropped unfilled, on any
/// error after it was made, it removes the file, so a refusal leaves no empty file behind. A run killed
/// at the passphrase prompt runs no drop, so that one case leaves the empty file.
struct NewFile<'a> {
    path: &'a Path,
    file: std::fs::File,
    /// Set once the link is written and synced; until then a drop removes the file.
    filled: bool,
}

impl<'a> NewFile<'a> {
    /// Make the file with an exclusive create, which refuses a path that names anything already, a dangling
    /// symlink included, and gives every other refusal in swoosh's words.
    // `core::io::ErrorKind` is still unstable, so the AlreadyExists check reads from `std`.
    #[allow(clippy::std_instead_of_core)]
    fn make(path: &'a Path) -> eyre::Result<Self> {
        let file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(path)
            .map_err(|error| match error.kind() {
                std::io::ErrorKind::AlreadyExists => exists(path),
                kind => cannot_make(path, kind),
            })?;
        Ok(Self {
            path,
            file,
            filled: false,
        })
    }

    /// Write the printed form of `link`, the form a person pastes, and sync it; the path is what is left to
    /// print. A write or sync that fails drops the file unfilled, which removes it.
    fn fill(mut self, link: &swoosh::link::Link) -> eyre::Result<&'a Path> {
        writeln!(self.file, "{link}")
            .and_then(|()| self.file.sync_all())
            .map_err(|error| cannot_make(self.path, error.kind()))?;
        self.filled = true;
        Ok(self.path)
    }
}

impl Drop for NewFile<'_> {
    fn drop(&mut self) {
        if !self.filled {
            // Nothing is left to report to: the error that dropped it is already on its way out.
            let _ = std::fs::remove_file(self.path);
        }
    }
}

/// The refusal for a `--save` file that cannot be made, its cause in plain words: never the system's text.
// `core::io::ErrorKind` is still unstable, so the kinds read from `std`.
#[allow(clippy::std_instead_of_core)]
fn cannot_make(path: &Path, kind: std::io::ErrorKind) -> eyre::Report {
    let path = EscapedPath(path);
    let why = match kind {
        std::io::ErrorKind::NotFound | std::io::ErrorKind::NotADirectory => "no such directory",
        std::io::ErrorKind::PermissionDenied => "permission denied",
        std::io::ErrorKind::ReadOnlyFilesystem => "the disk is read-only",
        std::io::ErrorKind::StorageFull => "the disk is full",
        _ => return eyre::eyre!("could not make {path}"),
    };
    eyre::eyre!("could not make {path}: {why}")
}

/// The refusal for a `--save` path that is taken.
fn exists(path: &Path) -> eyre::Report {
    eyre::eyre!(
        "{} exists already; --save writes only a new file",
        EscapedPath(path)
    )
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

/// When a link ends, as its line prints it: the local clock time when that is within a day, else the local
/// date; then, when the person typed it or took the default, the span, as `--expires` takes it.
struct Until<'a> {
    at: SystemTime,
    left: Duration,
    span: Option<&'a Span>,
}

impl<'a> Until<'a> {
    /// `left` from now, printed with `span` when there is one.
    fn from_now(left: Duration, span: Option<&'a Span>) -> Self {
        Self {
            at: SystemTime::now() + left,
            left,
            span,
        }
    }
}

/// A day, the bound under which an end prints as a clock time.
const DAY: Duration = Duration::from_secs(24 * 60 * 60);

/// The months as a date line names them.
const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

impl fmt::Display for Until<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let secs = self
            .at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        match local_time(secs) {
            Some(local) => End {
                local: &local,
                within_a_day: self.left <= DAY,
            }
            .fmt(f)?,
            None => write!(f, "{}", swoosh::root::Date(secs))?,
        }
        match self.span {
            Some(span) => write!(f, " ({span})"),
            None => Ok(()),
        }
    }
}

/// A local time as an end prints: `15:04` within a day, `15 Oct 2026` past it. Apart from the clock read, so
/// its shape is tested on a time made by hand.
struct End<'a> {
    local: &'a libc::tm,
    within_a_day: bool,
}

impl fmt::Display for End<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let local = self.local;
        if self.within_a_day {
            return write!(f, "{:02}:{:02}", local.tm_hour, local.tm_min);
        }
        let month = usize::try_from(local.tm_mon)
            .ok()
            .and_then(|month| MONTHS.get(month))
            .copied()
            .unwrap_or("?");
        write!(
            f,
            "{} {month} {}",
            local.tm_mday,
            i64::from(local.tm_year) + 1900
        )
    }
}

/// `secs` since the epoch in this machine's local time zone, or `None` when the system cannot say.
fn local_time(secs: u64) -> Option<libc::tm> {
    let time = libc::time_t::try_from(secs).ok()?;
    // SAFETY: `tm` is plain C data (integers and, on some platforms, a pointer the call sets), so all-zero is
    // a valid value for `localtime_r` to overwrite.
    let mut local: libc::tm = unsafe { core::mem::zeroed() };
    // SAFETY: both pointers name live, initialized values owned by this frame; `localtime_r` writes only
    // `local` and is the thread-safe form.
    let done = unsafe { libc::localtime_r(&time, &mut local) };
    (!done.is_null()).then_some(local)
}

#[cfg(test)]
#[path = "share_tests.rs"]
mod share_tests;
