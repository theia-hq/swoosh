//! Learning a person's root from one of their machines you already saved.
//!
//! A root cannot be computed from a machine's key. But when `alice/laptop` was saved with a key alice gave
//! you, the transport proves that key when the machine answers, and the standing it hands over proves
//! which root vouches for it: a root that vouches for that key, only as trustworthy as whoever holds it.
//! A dial asks once its first stream is admitted, on the root route ([`LOOKUP_ROOT_SERVICE`]), through
//! the source that stream came from, and only for a machine saved as one of a person's other than
//! yours; `sync` asks every such machine of a person with no root saved. The answer teaches nothing
//! unless the standing verifies under the root it names, is bound to the key dialed, and outlives now.
//!
//! What was learned is never followed on its own: an empty slot is offered to the person, who says yes or
//! no; a root that differs from the one saved is a conflict to warn about, never a replace. Each machine
//! remembers the root it last showed (its `seen_root`, kept on this machine only), so the offer and the
//! warning come once per new root, not once per dial. The words are the binary's.

use core::time::Duration;
use std::time::SystemTime;

use bifrost::NodeId;
use futures::StreamExt as _;
use futures::future::LocalBoxFuture;
use nauthy::{Link, Service};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use tokio::sync::oneshot;

use crate::contacts::{Contacts, ContactsStore, DeviceLabel, ME, Petname, Taken};
use crate::home::{Home, HomeWrite};
use crate::peer::{Kind, Machine};
use crate::peers::Hints;
use crate::renewal::FetchError;
use crate::root_key::RootKey;
use crate::serve::LOOKUP_ROOT_SERVICE;
use crate::serve::control_codec::OpenLane;
use crate::streams::{Ask, StreamSource, Unopened};

/// The longest a dial's question may run, from its start: under the asked machine's 5 s cap on the
/// stream, and short enough that a machine that admits it and never answers holds the run open no longer.
pub const DEADLINE: Duration = Duration::from_secs(2);

/// How long `sync` gives each machine it asks.
pub const EACH: Duration = Duration::from_secs(5);

/// How many machines `sync` asks at once.
pub const AT_ONCE: usize = 8;

/// One machine to ask: saved here as `<person>/<device>`, for a person other than you.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Asked {
    /// The person it is saved under.
    pub person: Petname,
    /// Its name among theirs.
    pub device: DeviceLabel,
    /// Its key, the one dialed and the one a standing must be bound to.
    pub key: NodeId,
}

impl Asked {
    /// What `standing`, the machine's answer, teaches about it: the root it names, when it vouches for this
    /// machine now ([`vouching`]).
    pub fn taught(&self, standing: &Link) -> Option<Shown> {
        let root = vouching(standing, self.key, SystemTime::now())?;
        Some(Shown {
            asked: self.clone(),
            root,
        })
    }

    /// The machine a dial asks about, when it is a person's saved machine and not yours: a key no name
    /// holds, a link, one of your devices, and a key saved only as a root are never asked.
    pub fn of(machine: &Machine) -> Option<Self> {
        if machine.kind() != Kind::Contact {
            return None;
        }
        let name = machine.name()?;
        let device = name.device()?;
        if name.petname().as_str() == ME {
            return None;
        }
        Some(Self {
            person: name.petname().clone(),
            device: device.clone(),
            key: machine.key(),
        })
    }
}

/// A root a machine showed: the machine, and the root its standing named.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shown {
    /// The machine that showed it.
    pub asked: Asked,
    /// The root that vouches for it.
    pub root: RootKey,
}

/// What a shown root means here, read against the book: what the person is told, if anything.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Found {
    /// The person has no root saved, and no name here holds this one: offer it.
    Offer,
    /// The person's saved root is another: warn, and follow nothing.
    Conflict {
        /// The root saved here for the person.
        saved: RootKey,
    },
    /// Nothing to say: the machine showed this root before, or it is the root saved for the person, or
    /// another name here holds it.
    Quiet,
}

impl Found {
    /// What `shown` means against `contacts`. A root the machine showed last time is quiet, so a decline
    /// is remembered and a conflict is said once per new root. Only an empty slot is ever offered: a saved
    /// root is replaced only by a typed `contact add`.
    pub fn of(contacts: &Contacts, shown: &Shown) -> Self {
        let Shown { asked, root } = shown;
        if contacts.seen_root(&asked.person, &asked.device) == Some(root.key()) {
            return Self::Quiet;
        }
        match contacts.signet(&asked.person) {
            Some(saved) if saved.node == root.key() => Self::Quiet,
            Some(saved) => Self::Conflict {
                saved: RootKey::from(saved.node),
            },
            None if contacts.saved_at(&root.key()).is_some() => Self::Quiet,
            None => Self::Offer,
        }
    }
}

/// Open the root route to `key` through `source`, presenting nothing, on Main, and read its one answer:
/// the standing on a hit, `None` on a miss. A full pool or a key the route does not know is refused
/// before a stream opens, and a refusal of any kind is the same miss to the asker.
///
/// # Errors
///
/// The stream failed some other way, or its answer did not read.
pub async fn ask_through(
    source: &impl StreamSource,
    key: NodeId,
) -> Result<Option<Link>, FetchError> {
    let service: Service = LOOKUP_ROOT_SERVICE
        .parse()
        .map_err(|error| eyre::eyre!("{error}"))?;
    let ask = Ask {
        peer: key,
        hints: Hints::NONE,
        service,
        lane: OpenLane::Main,
        slip: None,
    };
    let opened = match source.open(&ask).await {
        Ok(opened) => opened,
        Err(Unopened::Refused(_)) => return Ok(None),
        Err(other) => return Err(FetchError::Unopened(other)),
    };
    crate::renewal::read_answer(opened.read).await
}

/// The root `standing` teaches about the machine `device`: only when it verifies under the root it names,
/// is bound to `device`'s key, and outlives `now`. A lapsed, foreign or damaged standing teaches nothing.
pub fn vouching(standing: &Link, device: NodeId, now: SystemTime) -> Option<RootKey> {
    let cap = standing.cap();
    let root = standing.root();
    let device = device.verify_key().ok()?;
    cap.verify_member_at_root_without_revocation(now, device, root)
        .ok()?;
    match cap.expiry() {
        Ok(Some(ends)) if ends > now => {}
        _ => return None,
    }
    root.node_id().ok().map(RootKey::from)
}

/// Every machine `sync` asks: each saved machine of a person other than you who has no root saved, in name
/// order.
pub fn unrooted(contacts: &Contacts) -> Vec<Asked> {
    contacts
        .petnames()
        .filter(|person| person.as_str() != ME && contacts.signet(person).is_none())
        .flat_map(|person| {
            contacts
                .devices(person)
                .into_iter()
                .flatten()
                .map(|(device, key)| Asked {
                    person: person.clone(),
                    device: device.clone(),
                    key: *key,
                })
        })
        .collect()
}

/// Ask every machine in `machines` through `source`, [`AT_ONCE`] at a time and each within [`EACH`]: the
/// roots they showed, in the order given. A machine that does not answer is left out, silently.
pub async fn sweep(source: &impl StreamSource, machines: Vec<Asked>) -> Vec<Shown> {
    let mut asked: Vec<(usize, Shown)> = futures::stream::iter(machines.into_iter().enumerate())
        .map(|(at, asked)| async move {
            let standing = match tokio::time::timeout(EACH, ask_through(source, asked.key)).await {
                Ok(Ok(standing)) => standing,
                Ok(Err(error)) => {
                    tracing::debug!(?error, "the root lookup failed");
                    None
                }
                Err(_elapsed) => None,
            };
            standing
                .and_then(|standing| asked.taught(&standing))
                .map(|shown| (at, shown))
        })
        .buffer_unordered(AT_ONCE)
        .filter_map(core::future::ready)
        .collect()
        .await;
    asked.sort_by_key(|(at, _)| *at);
    asked.into_iter().map(|(_, shown)| shown).collect()
}

/// Remember `shown` as the root its machine last showed, under `home.lock`: after the person was told, so
/// it is said once.
///
/// # Errors
///
/// The book could not be read or written.
pub async fn remember(home: &Home, shown: &Shown) -> eyre::Result<()> {
    let home_lock = HomeWrite::take(home).await?;
    let mut store = ContactsStore::open(home).await?;
    let Shown { asked, root } = shown;
    store
        .contacts_mut()
        .see_root(&asked.person, &asked.device, root.key());
    store.save(&home_lock)?;
    Ok(())
}

/// Save `shown`'s root as its person's, learned from its machine, and remember it as shown, under
/// `home.lock`. When the slot filled meanwhile or another name took the key, nothing is saved but the
/// memory, and the inner refusal says which.
///
/// # Errors
///
/// The book could not be read or written.
pub async fn save(home: &Home, shown: &Shown) -> eyre::Result<Result<(), Taken>> {
    let home_lock = HomeWrite::take(home).await?;
    let mut store = ContactsStore::open(home).await?;
    let Shown { asked, root } = shown;
    let contacts = store.contacts_mut();
    let saved = contacts.learn(&asked.person, root.key(), asked.device.clone());
    contacts.see_root(&asked.person, &asked.device, root.key());
    store.save(&home_lock)?;
    Ok(saved)
}

/// The root question a dial's first admitted stream hands over: the machine's standing, asked beside the
/// verb's streams, holding what it asks through until it ends. Its answer is read with [`Asked::taught`].
pub type Question<'s> = LocalBoxFuture<'s, Option<Link>>;

/// The signal a dial's first admitted stream gives: the question to ask beside the verb, from that moment
/// and never ahead of it. Dropped unsent when the verb ends with no stream admitted, so whoever waits on it
/// stops waiting.
#[derive(Default)]
pub struct Admitted<'s>(Option<oneshot::Sender<Question<'s>>>);

// By hand: a question is a future, which has no `Debug` of its own.
impl core::fmt::Debug for Admitted<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self(signal) = self;
        f.debug_struct("Admitted")
            .field("heard", &signal.is_some())
            .finish()
    }
}

impl<'s> Admitted<'s> {
    /// A signal and the end that hears it.
    pub fn new() -> (Self, oneshot::Receiver<Question<'s>>) {
        let (tx, rx) = oneshot::channel();
        (Self(Some(tx)), rx)
    }

    /// A signal nobody hears: for a verb that asks nothing.
    pub fn unheard() -> Self {
        Self(None)
    }

    /// Give the signal: `question`, asked beside the verb from now on. For a verb whose first stream was
    /// just admitted.
    pub fn ask(self, question: Question<'s>) {
        let Self(signal) = self;
        if let Some(signal) = signal {
            // Nobody listening any more is no failure of the verb's.
            let _ = signal.send(question);
        }
    }

    /// Give the signal for a stream opened through `source` to `key` that was just admitted: the question
    /// is the root route to `key` through that same source ([`ask_through`]), and a failure is a miss,
    /// logged.
    pub fn asked_through<S: StreamSource + 's>(self, source: S, key: NodeId) {
        self.ask(Box::pin(async move {
            match ask_through(&source, key).await {
                Ok(standing) => standing,
                Err(error) => {
                    tracing::debug!(%error, "the root lookup failed");
                    None
                }
            }
        }));
    }
}

#[cfg(test)]
#[path = "learn_tests.rs"]
mod tests;
