//! `swoosh invite`: add one of your devices, renew one, hand a machine with no console a key, or list what
//! is due.
//!
//! ```text
//! invite <name> <key>        add the device that made <key>, or renew it if <name> is already that key
//! invite <name>              renew that device
//! invite <name> --new-key    an invite that carries a new key, for a machine with no console
//! invite                     list what is due, one line each; writes nothing
//! ```
//!
//! Only the root adds or renews a device, so every form but the bare one is a root act that cuts: it asks
//! your devices for a newer list first, refuses before the passphrase whatever the records refuse, signs,
//! writes, prints the invite, and then offers the cut to your other devices. The bare form reads the root's
//! records with no lock and no prompt.

use core::time::Duration;
use std::io::{self, Write};
use std::path::PathBuf;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use clap::Args;
use nauthy::{Link, VerifyKey};
use swoosh::contacts::{ContactsStore, DeviceLabel, ME};
use swoosh::home::Home;
use swoosh::invite::Invite;
use swoosh::passphrase::{Prompt, Terminal};
use swoosh::root::{self, Date, Minted, Records, Root, RootError, RootPlace, RootVerb};
use swoosh::standing::{Standing, StandingError};
use swoosh::state::Row;
use swoosh::sync::{Dial, NodeDial};
use swoosh::transport::ReachArgs;
use tightbeam::duration::Lifetime;
use tightbeam::identity::AsVerifyKey as _;

const DAY: u64 = 24 * 60 * 60;

/// The shortest `--expires` a device takes.
const SHORTEST: u64 = 60 * 60;

/// The longest `--expires` a device takes.
const LONGEST: u64 = 365 * DAY;

/// Under this, an issue says a leaked copy dies with its date.
const SHORT_LIVED: u64 = 30 * DAY;

/// Add one of your devices, or renew it. Bare `invite` lists what is due.
#[derive(Debug, Args)]
pub struct InviteCmd {
    /// the device, as it is named among your devices (me/<name>)
    #[arg(value_name = "name")]
    pub name: Option<DeviceLabel>,
    /// the key the device made (`swoosh join` on it shows it)
    #[arg(value_name = "key", requires = "name")]
    pub key: Option<String>,
    /// Make a new key: inside the invite, or for this machine.
    #[arg(long = "new-key", requires = "name", conflicts_with = "key")]
    pub new_key: bool,
    /// How long: `2h`, `90d`.
    #[arg(long, value_name = "d", requires = "name", value_parser = device_expiry)]
    pub expires: Option<Duration>,
    /// where your root is, when it is not kept on this machine
    #[arg(long = "root", value_name = "dir")]
    pub root: Option<PathBuf>,
    #[command(flatten)]
    pub reach: ReachArgs,
}

/// A device's `--expires`: a duration from 1h to 365d.
fn device_expiry(text: &str) -> Result<Duration, String> {
    let duration = text
        .parse::<Lifetime>()
        .map_err(|error| error.to_string())?
        .duration();
    if !(SHORTEST..=LONGEST).contains(&duration.as_secs()) {
        return Err("a device's --expires is 1h to 365d".to_owned());
    }
    Ok(duration)
}

/// What the command line asks for, before the records are read.
#[derive(Debug, Clone, Copy)]
enum Ask {
    /// `invite <name> <key>`.
    Add(VerifyKey),
    /// `invite <name> --new-key`.
    NewKey,
    /// `invite <name>`.
    Renew,
}

/// What the act does, once the records are read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Plan {
    /// Add the device that made this key.
    Add(VerifyKey),
    /// Add a device whose key the root makes.
    Keyed,
    /// Renew the named device, keeping its key.
    Renew,
    /// Hand the named device, whose key came in its invite, a new one.
    Rekey,
}

impl InviteCmd {
    fn place(&self) -> RootPlace {
        self.root.clone().map_or(RootPlace::Home, RootPlace::Dir)
    }

    /// The bare `invite`: one `swoosh invite <name>` line on `out` for each device due to renew, read with
    /// no lock and no prompt, writing nothing.
    pub async fn run_due(self, home: &Home) -> eyre::Result<()> {
        self.due(home, &mut io::stdout(), &mut io::stderr()).await
    }

    pub(crate) async fn due(
        &self,
        home: &Home,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let inspected = Root::inspect(home, self.place()).await?;
        for line in &inspected.finished {
            writeln!(err, "{line}")?;
        }
        for row in inspected.due(unix_now()) {
            writeln!(out, "swoosh invite {}", row.label)?;
        }
        Ok(())
    }

    /// Add, renew or rekey the named device: refuse before the passphrase whatever the records refuse, sign,
    /// write, print the invite on `out`, then offer the cut through `dial`. Every other line goes to `err`.
    pub(crate) async fn issue(
        self,
        home: &Home,
        prompt: &mut impl Prompt,
        dial: &impl Dial,
        out: &mut impl Write,
        err: &mut impl Write,
    ) -> eyre::Result<()> {
        let place = self.place();
        let Some(name) = self.name else {
            eyre::bail!("name the device: swoosh invite <name> <key>");
        };
        let ask = match (&self.key, self.new_key) {
            (Some(key), _) => Ask::Add(parse_key(key)?),
            (None, true) => Ask::NewKey,
            (None, false) => Ask::Renew,
        };
        refuse_a_contact(home, &name).await?;
        let standing = match Standing::read(home).await {
            Ok(read) => read.standing,
            Err(StandingError::Damaged(what)) => {
                eyre::bail!("{}", swoosh::standing::damaged_line(&what))
            }
            Err(other) => return Err(other.into()),
        };
        let mints = place == RootPlace::Home
            && matches!(
                standing,
                Standing::Unpinned | Standing::InterruptedMint { .. }
            );

        // A renewal that would sign nothing, with nothing else to sign, takes no lock and asks nothing. Only
        // on one of your devices: anywhere else a root act refuses, and this read must not get past that.
        let device = matches!(
            standing,
            Standing::HoldsRoot { .. } | Standing::Device { .. }
        );
        if device && !matches!(ask, Ask::NewKey) {
            let unchanged = Root::unchanged(home, place.clone(), &name, self.expires).await?;
            if let Some((key, until, standing)) = unchanged
                && match ask {
                    Ask::Add(asked) => asked == key,
                    Ask::NewKey | Ask::Renew => true,
                }
            {
                let from = own_key(home)?;
                let own = from.verify_key().ok() == Some(key);
                writeln!(out, "{}", Invite::bound(from, name.clone(), standing))?;
                writeln!(err, "{}", needs_no_renewal(&name, until, own))?;
                return Ok(());
            }
        }

        let (mut root, plan) = if mints {
            if let Standing::Unpinned = standing {
                refuse_before_the_first_root(home, &name, ask)?;
            }
            match Root::mint_to(home, prompt, err).await? {
                Minted::Made(root) => {
                    let plan = plan(&root.records(), &name, ask, err)?;
                    (*root, plan)
                }
                Minted::Finished => present(home, place, prompt, dial, err, &name, ask).await?,
            }
        } else {
            present(home, place, prompt, dial, err, &name, ask).await?
        };

        let from = own_key(home)?;
        let own = from.verify_key().ok();
        let issued = match plan {
            Plan::Add(key) => {
                let duration = self.expires.unwrap_or(root::DEFAULT_DURATION);
                let standing = root.sign_standing(key, name.clone(), duration)?;
                Issued::bound(standing, duration, self.expires.is_none())
            }
            Plan::Keyed => {
                let duration = self.expires.unwrap_or(root::DEFAULT_DURATION);
                let (standing, seed) = root.sign_keyed(name.clone(), duration)?;
                Issued {
                    standing,
                    seed: Some(seed),
                    duration,
                    default: self.expires.is_none(),
                    old_invite_until: None,
                    unchanged: None,
                }
            }
            Plan::Rekey => {
                let duration = self
                    .expires
                    .unwrap_or_else(|| own_duration(root.rows(), &name));
                let rekeyed = root.rekey(&name, duration)?;
                Issued {
                    standing: rekeyed.standing,
                    seed: Some(rekeyed.seed),
                    duration,
                    default: self.expires.is_none(),
                    old_invite_until: Some(rekeyed.old_invite_until),
                    unchanged: None,
                }
            }
            Plan::Renew => {
                let default = self.expires.is_none();
                let mut list = root.renew(core::slice::from_ref(&name), self.expires)?;
                match (list.renewed.pop(), list.unchanged.pop()) {
                    (Some(renewed), _) => {
                        let duration = self
                            .expires
                            .unwrap_or_else(|| own_duration(root.rows(), &name));
                        Issued::bound(renewed.standing, duration, default)
                    }
                    (None, Some((_, until, standing))) => Issued {
                        standing,
                        seed: None,
                        duration: Duration::ZERO,
                        default,
                        old_invite_until: None,
                        unchanged: Some(until),
                    },
                    (None, None) => {
                        return Err(RootError::NoDeviceToRenew { name: name.clone() }.into());
                    }
                }
            }
        };
        let _ = root.renew_due()?;
        let committed = root.commit_to(err).await?;
        let row = root
            .rows()
            .iter()
            .find(|row| !row.is_revoked() && row.label == name)
            .cloned();
        let until = row.as_ref().map_or(0, |row| row.until);

        // After the commit, and before the offer: the invite alone on stdout, then what it means.
        let invite = match &issued.seed {
            Some(seed) => Invite::keyed(**seed, from, name.clone(), issued.standing.clone()),
            None => Invite::bound(from, name.clone(), issued.standing.clone()),
        };
        writeln!(out, "{invite}")?;
        out.flush()?;
        let device = format!("me/{name}");
        if let Some(until) = issued.unchanged {
            let own_row = row.as_ref().is_some_and(|row| Some(row.key) == own);
            writeln!(err, "{}", needs_no_renewal(&name, until, own_row))?;
        } else {
            issued.lines(err, &device, until)?;
        }

        let reach = committed.offer(dial).await;
        if let Some(line) = reach.invite_line(&device) {
            writeln!(err, "{line}")?;
        }
        let renewed_another = plan == Plan::Renew
            && issued.unchanged.is_none()
            && row.as_ref().is_some_and(|row| Some(row.key) != own);
        if renewed_another && let Some(line) = reach.renewed_line(&device, until) {
            writeln!(err, "{line}")?;
        }
        Ok(())
    }
}

/// What the act signed for the named device, to print.
struct Issued {
    standing: Link,
    /// The key the invite carries, when it carries one.
    seed: Option<zeroize::Zeroizing<[u8; 32]>>,
    duration: Duration,
    /// Whether `--expires` was left to its default.
    default: bool,
    /// When a rekeyed device's old invite ends, in unix seconds.
    old_invite_until: Option<u64>,
    /// When a named device that needed no renewal ends: its stored standing is what prints.
    unchanged: Option<u64>,
}

impl Issued {
    fn bound(standing: Link, duration: Duration, default: bool) -> Self {
        Self {
            standing,
            seed: None,
            duration,
            default,
            old_invite_until: None,
            unchanged: None,
        }
    }

    /// The lines after a new invite: how long it runs, and, for one that carries a key, who it makes the
    /// device and that it is not renewed on its own.
    fn lines(&self, err: &mut impl Write, device: &str, until: u64) -> io::Result<()> {
        let date = Date(until);
        let span = swoosh::grants::humanize(self.duration);
        if self.default {
            writeln!(
                err,
                "{device} runs {span} from now, until {date} (the default; --expires sets 1h to 365d)."
            )?;
        } else {
            writeln!(err, "{device} runs {span} from now, until {date}.")?;
        }
        match self.old_invite_until {
            Some(old) => writeln!(
                err,
                "{device}'s new key is inside this invite: send it privately. If {device} starts from its \
                 invite each time, give it this one the way it got the last (a runner: gh secret set \
                 SWOOSH_INVITE). The old invite works until {}.",
                Date(old)
            )?,
            None if self.seed.is_some() => writeln!(
                err,
                "anyone holding this invite becomes {device} until {date}: send it privately."
            )?,
            None => {}
        }
        if self.seed.is_some() {
            writeln!(err, "it ends on {date} and is not renewed on its own")?;
        } else if self.duration.as_secs() < SHORT_LIVED {
            writeln!(
                err,
                "it ends on its date and is not renewed on its own, so a leaked copy dies with it"
            )?;
        }
        Ok(())
    }
}

/// Present the root to `invite`, planning the act on its records before the passphrase.
async fn present<E: Write>(
    home: &Home,
    place: RootPlace,
    prompt: &mut impl Prompt,
    dial: &impl Dial,
    err: &mut E,
    name: &DeviceLabel,
    ask: Ask,
) -> Result<(Root, Plan), RootError> {
    Root::present_with(
        home,
        place,
        RootVerb::Invite,
        prompt,
        dial,
        err,
        |records, err| plan(records, name, ask, err),
    )
    .await
}

/// What `ask` does to the records, or why they refuse it; and the lines that come before the passphrase.
fn plan(
    records: &Records<'_>,
    name: &DeviceLabel,
    ask: Ask,
    err: &mut impl Write,
) -> Result<Plan, RootError> {
    let device = records.device(name);
    let plan = match (ask, device) {
        (Ask::Add(key), Some(row)) if row.key == key => Plan::Renew,
        (Ask::Add(key), _) => {
            records.check_add(key, name)?;
            Plan::Add(key)
        }
        (Ask::NewKey, Some(_)) => {
            records.check_rekey(name)?;
            Plan::Rekey
        }
        (Ask::NewKey, None) => Plan::Keyed,
        (Ask::Renew, Some(_)) => Plan::Renew,
        (Ask::Renew, None) => return Err(RootError::NoDeviceToRenew { name: name.clone() }),
    };
    match (plan, device) {
        (Plan::Add(_) | Plan::Keyed, _) => {
            let _ = writeln!(
                err,
                "me/{name} will be one of your own devices: it reaches everything your devices serve."
            );
        }
        (Plan::Renew, Some(row)) if row.until <= records.now() => {
            let key = row.key;
            let _ = writeln!(
                err,
                "renewing me/{name} ({key}), which ended on {}. Whatever machine holds {key} picks this up \
                 the next time it reaches one of your devices. If that is not a machine you still have, stop \
                 here and run: swoosh revoke me/{name}",
                Date(row.until)
            );
        }
        _ => {}
    }
    Ok(plan)
}

/// Before a root is made here, refuse what the new root's records would: this machine's own key, which
/// becomes its first device, and a renewal, since the root has no device yet.
fn refuse_before_the_first_root(home: &Home, name: &DeviceLabel, ask: Ask) -> eyre::Result<()> {
    match ask {
        Ask::Add(key) if own_key(home)?.verify_key().ok() == Some(key) => {
            let own = swoosh::names::suggest().as_str().parse()?;
            Err(RootError::OwnKey { name: own }.into())
        }
        Ask::Renew => Err(RootError::NoDeviceToRenew { name: name.clone() }.into()),
        Ask::Add(_) | Ask::NewKey => Ok(()),
    }
}

/// Refuse a name that is a contact's: a person is shared with, never made one of your devices.
async fn refuse_a_contact(home: &Home, name: &DeviceLabel) -> eyre::Result<()> {
    let store = ContactsStore::open(home.contacts()).await?;
    let contact = store
        .contacts()
        .petnames()
        .any(|person| person.as_str() != ME && person.as_str() == name.as_str());
    if contact {
        eyre::bail!(
            "{name} is a contact: to let {name} use a service, swoosh share <service> {name}"
        );
    }
    Ok(())
}

/// The second positional, which is always a key.
fn parse_key(text: &str) -> eyre::Result<VerifyKey> {
    text.parse::<NodeId>()
        .ok()
        .and_then(|key| key.verify_key().ok())
        .ok_or_else(|| eyre::eyre!("{text} is not a key: to renew {text}, swoosh invite {text}"))
}

/// This machine's key, made if the home has none.
fn own_key(home: &Home) -> eyre::Result<NodeId> {
    Ok(swoosh::identity::inspect(home)?.stored().node_id())
}

/// The named device's own renewal length, or the default when it has none.
fn own_duration(rows: &[Row], name: &DeviceLabel) -> Duration {
    rows.iter()
        .find(|row| !row.is_revoked() && &row.label == name)
        .map(|row| row.duration)
        .filter(|duration| *duration != 0)
        .map_or(root::DEFAULT_DURATION, Duration::from_secs)
}

/// Why a named device's stored standing printed: it needs no renewal. For another device, how it takes the
/// line; this machine takes its standing from its own fold, and `join` refuses where the root is kept.
fn needs_no_renewal(name: &DeviceLabel, until: u64, own: bool) -> String {
    let head = format!("me/{name} needs no renewal (until {}).", Date(until));
    if own {
        head
    } else {
        format!("{head} If it left, or its date passed, on it: swoosh join and paste this line.")
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl swoosh::reaching::Reaching for InviteCmd {
    fn reach_args(&self) -> &ReachArgs {
        &self.reach
    }

    /// `invite` dials your devices itself: to sync before it signs, and to offer what it cut.
    fn dialed(&self) -> Option<&swoosh::peer::Peer> {
        None
    }

    /// `invite` takes no `--present` and no peer, so there is nothing to conflict.
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
        self.issue(
            ctx.home,
            &mut Terminal,
            &dial,
            &mut io::stdout(),
            &mut io::stderr(),
        )
        .await
    }
}

#[cfg(test)]
#[path = "invite_tests.rs"]
mod invite_tests;
