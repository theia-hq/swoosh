//! Learning a person's root from one of their machines you already saved.
//!
//! A root cannot be computed from a machine's key. But when `alice/laptop` was saved with a key alice gave
//! you, the transport proves that key when the machine answers, and the standing it hands over proves
//! which root vouches for it: a root that vouches for that key, only as trustworthy as whoever holds it.
//! A dial asks once its first stream is admitted, on the root route ([`LOOKUP_ROOT_SERVICE`]) of the
//! session it dialed, and only for a machine saved as one of a person's other than yours; `sync` asks every
//! such machine of a person with no root saved. The answer teaches nothing unless the standing verifies
//! under the root it names, is bound to the key dialed, and outlives now.
//!
//! What was learned is never followed on its own: an empty slot is offered to the person, who says yes or
//! no; a root that differs from the one saved is a conflict to warn about, never a replace. Each machine
//! remembers the root it last showed (its `seen_root`, kept on this machine only), so the offer and the
//! warning come once per new root, not once per dial. The words are the binary's.

use core::cell::Cell;
use core::time::Duration;
use std::rc::Rc;
use std::time::SystemTime;

use bifrost::{ConnInfo, Discovery, Node, NodeId, PathChanges, Session, Transport};
use futures::StreamExt as _;
use futures::future::LocalBoxFuture;
use nauthy::{Link, Service};
use tightbeam::identity::{AsNodeId as _, AsVerifyKey as _};
use tightbeam::tunnel::Connector;
use tokio::sync::oneshot;

use crate::contacts::{Contacts, ContactsStore, DeviceLabel, ME, Petname, Taken};
use crate::home::{Home, HomeWrite};
use crate::peer::{Kind, Machine};
use crate::renewal::FetchError;
use crate::root_key::RootKey;
use crate::serve::LOOKUP_ROOT_SERVICE;

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

/// Ask `asked`'s machine which root vouches for it, over a connection of its own on `node`: the root its
/// standing names, when the standing verifies. For `sync`, which holds no other session to the machine; a
/// dial asks on its own session instead ([`Admitted`]), since an endpoint may hold one connection per peer
/// and a second would replace the verb's. `None` on a miss, a failure, or a standing that teaches nothing;
/// never an error, since nothing else depends on it.
pub async fn ask<T: Transport, D: Discovery>(node: &Node<T, D>, asked: &Asked) -> Option<Shown> {
    let session = match node.connect(asked.key).await {
        Ok(session) => session,
        Err(error) => {
            tracing::debug!(%error, "the root lookup could not reach the machine");
            return None;
        }
    };
    let standing = answer(&session).await?;
    asked.taught(&standing)
}

/// The standing `session`'s peer hands over on its root route, or `None` on a miss or a failure, logged.
async fn answer<S: Session>(session: &S) -> Option<Link> {
    match ask_on(session, session.peer()).await {
        Ok(standing) => standing,
        Err(error) => {
            tracing::debug!(%error, "the root lookup failed");
            None
        }
    }
}

/// Open the root route on `session` to `key`, presenting nothing, and read its one answer: the standing on
/// a hit, `None` on a miss. A full pool or a key the route does not know is refused before a stream opens,
/// which to the asker is the same miss.
pub async fn ask_on<S: Session>(session: &S, key: NodeId) -> Result<Option<Link>, FetchError> {
    let service: Service = LOOKUP_ROOT_SERVICE
        .parse()
        .map_err(|error| eyre::eyre!("{error}"))?;
    let (_writer, reader) = match Connector::to_node(key, service, None)
        .open_on(session)
        .await
    {
        Ok(halves) => halves,
        Err(bifrost::Error::Refused(_)) => return Ok(None),
        Err(other) => return Err(eyre::eyre!(other).into()),
    };
    crate::renewal::read_answer(reader).await
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

/// Ask every machine in `machines` on `node`, [`AT_ONCE`] at a time and each within [`EACH`]: the roots
/// they showed, in the order given. A machine that does not answer is left out, silently.
pub async fn sweep<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    machines: Vec<Asked>,
) -> Vec<Shown> {
    let mut asked: Vec<(usize, Shown)> = futures::stream::iter(machines.into_iter().enumerate())
        .map(|(at, asked)| async move {
            tokio::time::timeout(EACH, ask(node, &asked))
                .await
                .ok()
                .flatten()
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

/// The root question a dial's first admitted stream hands over: the machine's standing, asked on the
/// session the verb dialed, which it holds open until it ends. Its answer is read with [`Asked::taught`].
pub type Question = LocalBoxFuture<'static, Option<Link>>;

/// The signal a dial's first admitted stream gives: the question to ask beside the verb, from that moment
/// and never ahead of it. Dropped unsent when the verb ends with no stream admitted, so whoever waits on it
/// stops waiting.
#[derive(Default)]
pub struct Admitted(Option<oneshot::Sender<Question>>);

// By hand: a question is a future, which has no `Debug` of its own.
impl core::fmt::Debug for Admitted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let Self(signal) = self;
        f.debug_struct("Admitted")
            .field("heard", &signal.is_some())
            .finish()
    }
}

impl Admitted {
    /// A signal and the end that hears it.
    pub fn new() -> (Self, oneshot::Receiver<Question>) {
        let (tx, rx) = oneshot::channel();
        (Self(Some(tx)), rx)
    }

    /// A signal nobody hears: for a verb that asks nothing.
    pub fn unheard() -> Self {
        Self(None)
    }

    /// `session`, gated through `connector` on every stream it opens, giving this signal the first time one
    /// is admitted.
    pub fn watch<S: Session + 'static>(self, session: S, connector: Connector) -> Watched<S> {
        let Self(signal) = self;
        Watched {
            session: Rc::new(session),
            connector,
            signal: Cell::new(signal),
        }
    }
}

/// A dialed session whose every stream is gated through one service request, as a service session's is,
/// and that hands over the root question when its first stream is admitted ([`Admitted::watch`]).
///
/// The question rides this same session, and holds it (an `Rc`, since a dial runs on one task) so it stays
/// open until the question ends, past the verb if it must: an endpoint may hold one connection per peer,
/// so a connection of its own would replace the verb's.
pub struct Watched<S> {
    session: Rc<S>,
    connector: Connector,
    // A `Cell`: a stream opens through `&self`, and the sender is taken once, by whichever open admits
    // first. Never shared across threads, since the session is not.
    signal: Cell<Option<oneshot::Sender<Question>>>,
}

impl<S: Session + 'static> Session for Watched<S> {
    type Security = S::Security;
    type Write = S::Write;
    type Read = S::Read;

    fn peer(&self) -> NodeId {
        self.session.peer()
    }

    /// A stream returns only once the host admitted it, so the first that returns is the signal.
    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        let halves = self.connector.open_on(&*self.session).await?;
        if let Some(signal) = self.signal.take() {
            let held = Rc::clone(&self.session);
            // Nobody listening any more is no failure of the verb's.
            let _ = signal.send(Box::pin(async move { answer(&*held).await }));
        }
        Ok(halves)
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        // A service client never accepts peer-opened streams; refusing keeps the view total.
        Err(bifrost::Error::Stream(
            "a service-scoped session does not accept inbound streams".into(),
        ))
    }

    async fn wait_closed(&self) {
        self.session.wait_closed().await;
    }

    fn close(&self) {
        self.session.close();
    }

    fn conn_info(&self) -> ConnInfo {
        self.session.conn_info()
    }

    fn path_changes(&self) -> PathChanges {
        self.session.path_changes()
    }
}

#[cfg(test)]
#[path = "learn_tests.rs"]
mod tests;
