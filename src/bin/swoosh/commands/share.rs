//! `swoosh share <service> <who>`: make a link to one of this machine's services; `swoosh share <link>`: make
//! a shorter copy of a link.
//!
//! A local verb: it binds no transport. The service form signs with this machine's own key (the key its
//! `serve` answers at), records the link in the ledger before it prints, and says on stderr what the link
//! gives. Who it is for decides how it is bound, from the shape of the name: a person (`bob`) is every
//! machine of the root saved for them, `bob/laptop` or a key is that one machine, and `anyone` is whoever
//! holds the link. A bound link is sealed, since only its machine can use it; an `anyone` link is left open,
//! so its holder can make a shorter copy.
//!
//! The link form is wholly offline: it reads no key and writes no ledger row, it only adds a shorter end to
//! the link it was given. A copy can never do more than its source, so it needs no one's leave. The link is
//! read from a path or stdin as well as typed, so it need never enter argv.

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
use swoosh::serve_toml::ServeToml;
use tightbeam::duration::Lifetime;
use tightbeam::identity::AsVerifyKey as _;

/// Make a link to one service for a person, one of their devices, a key, or `anyone`.
///
/// `share <link>` makes a shorter copy.
#[derive(Debug, Args)]
pub struct ShareCmd {
    /// the service, or a link to copy: swoosh:…, a path, or - for stdin
    #[arg(value_name = "service | link", value_parser = shared)]
    pub what: Shared,
    /// who it is for: <person>, <person>/<name>, a key, or anyone
    #[arg(value_name = "who", value_parser = recipient)]
    pub who: Option<Recipient>,
    /// How long: `2h`, `90d`.
    #[arg(long, value_name = "d", value_parser = link_expiry)]
    pub expires: Option<Duration>,
    /// Write the link to a new private file and print only the path.
    #[arg(long, value_name = "file")]
    pub save: Option<PathBuf>,
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

/// The default life of a link from the service form.
const DEFAULT_EXPIRY: Duration = Duration::from_secs(60 * 60);

/// The shortest `--expires` a link takes.
const SHORTEST: Duration = Duration::from_secs(60 * 60);

/// The longest `--expires` a link takes.
const LONGEST: Duration = Duration::from_secs(365 * 24 * 60 * 60);

/// The most read from stdin for one link. A link is well under a kilobyte.
const MAX_STDIN: u64 = 64 * 1024;

/// The refusal for a bound link handed to `share <link>`.
const BOUND: &str = "this link works only for the device it was made for, so it cannot be passed on: ask its issuer.";

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

/// `--expires`: a span from 1h to 365d.
fn link_expiry(text: &str) -> Result<Duration, String> {
    let span = text
        .parse::<Lifetime>()
        .map_err(|error| error.to_string())?
        .duration();
    if !(SHORTEST..=LONGEST).contains(&span) {
        return Err("a link's --expires is 1h to 365d".to_owned());
    }
    Ok(span)
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
                let issue = Issue {
                    service,
                    who,
                    lifetime: self.expires.unwrap_or(DEFAULT_EXPIRY),
                };
                return issue.run(home, self.save.as_deref(), out, err).await;
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
        copy(&source, self.expires, self.save.as_deref(), out, err)
    }
}

/// One link to make from the service form, its arguments read.
struct Issue {
    service: Service,
    who: Recipient,
    lifetime: Duration,
}

impl Issue {
    /// Resolve who it is for, and what the service is here, before anything is written; then sign, record the
    /// row, and print.
    async fn run(
        self,
        home: &Home,
        save: Option<&Path>,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let store = ContactsStore::open(home).await?;
        let bound = self.bind(store.contacts(), home).await?;
        let gives = Gives::of(&self.service, &ServeToml::read(home)?);
        // A path `--save` names that holds anything refuses before the key is read or a row is written.
        let save = save.map(unused).transpose()?;
        let link = self.sign(home, &bound).await?;
        let until = Until::from_now(self.lifetime);
        writeln!(
            err,
            "{} {}{}until {until}.",
            bound.who,
            gives,
            gives.before_until()
        )?;
        writeln!(
            err,
            "the link dials this machine: it works while this machine serves {}.",
            self.service
        )?;
        if matches!(bound.bind, Bind::Anyone) {
            writeln!(
                err,
                "anyone holding this link can use it: send it privately."
            )?;
        }
        deliver(&link, save, out)
    }

    /// The bind the recipient names, with what the ledger records for it. A person is the root saved for
    /// them, never one of their devices, and never your own root: your devices reach this machine already.
    async fn bind(&self, contacts: &Contacts, home: &Home) -> eyre::Result<Bound> {
        Ok(match &self.who {
            Recipient::Anyone => Bound {
                bind: Bind::Anyone,
                kind: GrantKind::Bearer,
                delegation: Delegation::Delegable,
                holder: grants::ANYONE.to_owned(),
                who: ANYONE.to_owned(),
            },
            Recipient::Person(person) => {
                let Some(root) = contacts.signet(person).map(|binding| binding.node) else {
                    eyre::bail!(
                        "{person} has no root saved here: swoosh contact add {person} <root key>"
                    );
                };
                if swoosh::config::load_signet(home).await? == Some(root) {
                    eyre::bail!("{person} is saved with your own root: {YOURS}");
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
    async fn sign(&self, home: &Home, bound: &Bound) -> eyre::Result<Link> {
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
        let expiry = nauthy::Request::expires_in(self.lifetime);
        let link = NodeSigner::from(&secret).mint_slip(
            &self.service,
            bound.bind,
            self.lifetime,
            bound.delegation,
        )?;
        let root_id = Cap::parse(link.as_str())?
            .root_revocation_id()
            .ok_or_else(|| eyre::eyre!("the link has no id to revoke it by"))?;
        let record = GrantRecord {
            target: Service::clone(&self.service),
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

/// What a link to a service gives, from what a bare `serve` would bind for that name now: its entry in
/// `serve.toml`, else the built-in form, else nothing known.
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
    /// Read what `service` is here.
    fn of(service: &Service, served: &ServeToml) -> Self {
        let name = service.as_str();
        let entry = served
            .services
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
        let Some((scheme, rest)) = entry.as_deref().and_then(|target| target.split_once(':'))
        else {
            return Self::Service(name.to_owned());
        };
        match scheme {
            "sshd" => Self::Shell,
            "tcp" | "unix" => Self::Forward {
                service: name.to_owned(),
                to: rest.to_owned(),
            },
            "fetch" | "proxy" => Self::Proxy {
                origin: rest.to_owned(),
            },
            _ => Self::Service(name.to_owned()),
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
/// link is sealed, so it refuses: it works only for its own device.
fn copy(
    source: &Link,
    expires: Option<Duration>,
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
    let span = expires.map_or(left, |asked| asked.min(left));
    let copy = match source.narrow(None, Some(span)) {
        Ok(copy) => copy,
        Err(CapError::Attenuate(_)) => eyre::bail!("{BOUND}"),
        Err(other) => return Err(other.into()),
    };
    let save = save.map(unused).transpose()?;
    writeln!(err, "the copy works until {}.", Until::from_now(span))?;
    writeln!(
        err,
        "anyone holding this link can use it: send it privately."
    )?;
    deliver(&copy, save, out)
}

/// Print the link on `out`, or write it into the `--save` file and print only the path.
fn deliver(link: &Link, save: Option<&Path>, out: &mut impl Write) -> eyre::Result<()> {
    let printed = swoosh::link::Link::from(Link::clone(link));
    match save {
        Some(path) => {
            save_new(path, &printed)?;
            writeln!(out, "{}", EscapedPath(path))?;
        }
        None => writeln!(out, "{printed}")?,
    }
    Ok(())
}

/// `path`, when it names nothing yet: `--save` writes only a new file, so this refuses before anything is
/// made or written. A dangling symlink names something too.
fn unused(path: &Path) -> eyre::Result<&Path> {
    if path.symlink_metadata().is_ok() {
        return Err(exists(path));
    }
    Ok(path)
}

/// Write the printed form of `link`, the form a person pastes, into a new `0600` file at `path`, and sync
/// it. Made only once the link exists, so a run stopped at a prompt leaves no empty file behind; the
/// exclusive create still refuses a file that appeared since [`unused`] looked.
// `core::io::ErrorKind` is still unstable, so the AlreadyExists check reads from `std`.
#[allow(clippy::std_instead_of_core)]
fn save_new(path: &Path, link: &swoosh::link::Link) -> eyre::Result<()> {
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .map_err(|error| match error.kind() {
            std::io::ErrorKind::AlreadyExists => exists(path),
            _ => eyre::Report::new(error).wrap_err(format!("could not make {}", EscapedPath(path))),
        })?;
    writeln!(file, "{link}")?;
    file.sync_all()?;
    Ok(())
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
        .map_err(|_| Usage("stdin held no swoosh: link.".to_owned()))?;
    let text = text.trim();
    if !swoosh::link::is_prefixed(text) {
        return Err(Usage("stdin held no swoosh: link.".to_owned()).into());
    }
    swoosh::link::parse(text).map_err(|error| Usage(format!("stdin: {error}")).into())
}

/// When a link ends, as its line prints it: the local clock time when that is within a day, else the local
/// date; then the span it was given, in the grammar `--expires` takes.
struct Until {
    at: SystemTime,
    span: Duration,
}

impl Until {
    /// `span` from now.
    fn from_now(span: Duration) -> Self {
        Self {
            at: SystemTime::now() + span,
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

impl fmt::Display for Until {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let span = grants::humanize(self.span);
        let secs = self
            .at
            .duration_since(SystemTime::UNIX_EPOCH)
            .map_or(0, |since| since.as_secs());
        let Some(local) = local_time(secs) else {
            return write!(f, "{} ({span})", swoosh::root::Date(secs));
        };
        if self.span <= DAY {
            write!(f, "{:02}:{:02} ({span})", local.tm_hour, local.tm_min)
        } else {
            let month = usize::try_from(local.tm_mon)
                .ok()
                .and_then(|month| MONTHS.get(month))
                .copied()
                .unwrap_or("?");
            write!(
                f,
                "{} {month} {} ({span})",
                local.tm_mday,
                i64::from(local.tm_year) + 1900
            )
        }
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
