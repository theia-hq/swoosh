//! Run-owned sessions to peers, in lanes. Each stream requests admission separately; renewal pick-ups
//! present no credentials.
//!
//! [`Lane::Main`] carries ordinary service streams and [`Lane::Bulk`] fan-out pipes, each on its own held
//! session per peer, so a full fan-out never stalls an exchange. A slip rides held sessions of its own,
//! shared only by streams presenting the identical slip, one per lane, so a slip's fan-out never stalls
//! its exchanges either. [`Peers::isolated`] dials a connection per caller under the ten-second dial
//! deadline and never holds it; its caller bounds the open on it with Bulk's ten seconds, since nothing
//! is evicted and nothing races it. Every lane has a per-peer cap, enforced here for every run. An open
//! that gets no answer in its lane's deadline evicts a session no other open got through on; dropping an
//! open never removes a session.
//!
//! A caller's [`Hints`] go into the address feed of a dial it starts, ahead of the run's own addresses
//! and mDNS, and into no other dial's feed; what the transport keeps of them is
//! [`Node::connect_hinted`]'s to say. A caller that joins a dial in flight or reuses a held session has
//! its hints ignored, and never causes a second dial.

use core::cell::{Cell, RefCell};
use core::fmt;
use core::net::SocketAddr;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use bifrost::{ConnInfo, Discovery, Node, NodeId, PathChanges, Session, Transport, WriteEnd};
use futures::FutureExt as _;
use futures::future::{LocalBoxFuture, Shared};
use nauthy::{Link, Service};
use tightbeam::tunnel::{Connector, WrongPeer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

pub(crate) const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
// A Bulk or Isolated open's deadline. Neither caller waits on its open with anything racing it, so the
// open itself bounds how long a silent session, or a fresh isolated connection, is kept.
pub(crate) const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
/// A Main open's deadline, shorter than any Main caller's own bound, so the open's timer rather than the
/// caller's fires on a silent session and evicts it.
pub(crate) const MAIN_OPEN_TIMEOUT: Duration = Duration::from_secs(4);
const IDLE_EVICTION: Duration = Duration::from_secs(5 * 60);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const MAIN_STREAMS: u16 = 64;
// The most pipes one fan-out holds, so a full forward or proxy never queues inside the owner.
const BULK_STREAMS: u16 = 128;
const ISOLATED_CONNECTIONS: u16 = 4;

/// The held session a stream rides. An isolated connection is [`Peers::isolated`], never held.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Lane {
    /// Ordinary service use: exchanges, pick-ups, one call at a time.
    Main,
    /// Fan-out pipes, one stream per local connection, kept off Main so they never take its slots.
    Bulk,
}

/// The addresses one open puts in the feed of the dial it starts, at most [`Hints::MAX`], ahead of the
/// run's own addresses and mDNS.
///
/// Order and repeats are kept as given. A hint is an address, not text: an IPv4-mapped IPv6 address is
/// held in its IPv4 form, and an IPv6 address without its flow label, which no hint's text can carry; a
/// scope stays. An address that can never be a peer's endpoint is refused, judged on that held form so a
/// mapped spelling cannot slip past. `Debug` prints only the count: a hint says where the caller expects
/// the peer, which no log line needs.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct Hints(Vec<SocketAddr>);

impl Hints {
    /// The most addresses one open may hand its dial.
    pub const MAX: usize = 16;

    /// No hints: the dial reads only the run's addresses and mDNS.
    pub const NONE: Self = Self(Vec::new());

    /// Hold `addrs` as one open's hints.
    ///
    /// # Errors
    ///
    /// [`HintsError::TooMany`] past [`MAX`](Self::MAX) addresses, and [`HintsError::Unusable`] for an
    /// unspecified, multicast or limited-broadcast address or port 0. Loopback and link-local pass: a
    /// peer on this host or this link is reached there.
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>) -> Result<Self, HintsError> {
        let mut hints = Vec::new();
        for addr in addrs {
            if hints.len() == Self::MAX {
                return Err(HintsError::TooMany);
            }
            let addr = canonical(addr);
            if !endpoint(addr) {
                return Err(HintsError::Unusable);
            }
            hints.push(addr);
        }
        Ok(Self(hints))
    }

    /// The addresses, in the order the caller gave them.
    pub fn as_slice(&self) -> &[SocketAddr] {
        &self.0
    }
}

impl fmt::Debug for Hints {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_tuple("Hints").field(&self.0.len()).finish()
    }
}

/// Why addresses are not one open's [`Hints`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum HintsError {
    /// More than [`Hints::MAX`] addresses.
    #[error("at most {} dial hints per open", Hints::MAX)]
    TooMany,
    /// An address that is never a peer's endpoint.
    #[error("a dial hint is not an address a machine can be reached at")]
    Unusable,
}

/// An IPv4-mapped IPv6 address as its IPv4 form, and any other IPv6 address without its flow label; the
/// scope and everything else unchanged.
fn canonical(addr: SocketAddr) -> SocketAddr {
    match addr {
        SocketAddr::V6(v6) => match v6.ip().to_ipv4_mapped() {
            Some(v4) => SocketAddr::from((v4, v6.port())),
            None => SocketAddr::V6(core::net::SocketAddrV6::new(
                *v6.ip(),
                v6.port(),
                0,
                v6.scope_id(),
            )),
        },
        SocketAddr::V4(_) => addr,
    }
}

/// Whether a dial could reach a peer at `addr`: not port 0, and not an unspecified, multicast or
/// limited-broadcast address, none of which is any one machine's endpoint.
fn endpoint(addr: SocketAddr) -> bool {
    let ip = addr.ip();
    addr.port() != 0
        && !ip.is_unspecified()
        && !ip.is_multicast()
        && ip != core::net::IpAddr::V4(core::net::Ipv4Addr::BROADCAST)
}

/// What a stream presents, which also picks the held session it rides.
#[derive(Debug, Clone)]
pub enum Presents {
    /// This home's own badge in slot 1, or nothing. Never a slip: the host ends a whole session when the
    /// earliest grant presented on it ends, so a short grant must never share the home's session.
    Standing(Option<Link>),
    /// A link typed as the peer in slot 1, and this home's badge in slot 2 when the slip pins its fleet.
    /// It rides a session per lane, shared only by the identical slip and slot 2.
    Slip {
        /// The link typed as the peer.
        slip: Link,
        /// Slot 2, beside a signet-bound slip.
        membership: Option<Link>,
    },
}

impl Presents {
    /// The slots a reaching verb resolved, as presented on `peer`: slot 1 is a slip exactly when the peer
    /// was typed as a link. The resolver fills slot 2 only beside a slip, so a standing never carries one.
    pub fn resolved(
        peer: &crate::peer::Peer,
        present: Option<Link>,
        membership: Option<Link>,
    ) -> Self {
        match (peer.self_present(), present) {
            (Some(_), Some(slip)) => Self::Slip { slip, membership },
            (_, present) => Self::Standing(present),
        }
    }

    fn carry(&self, lane: Lane) -> Carry {
        match self {
            Self::Standing(badge) => Carry::Home {
                lane,
                standing: badge.as_ref().map(|badge| badge.as_str().to_owned()),
            },
            Self::Slip { slip, membership } => Carry::Slip {
                lane,
                digest: *blake3::hash(slip.as_str().as_bytes()).as_bytes(),
                membership: membership.as_ref().map(|badge| badge.as_str().to_owned()),
            },
        }
    }

    /// The connector that presents these slots for `service` at `peer`.
    pub(crate) fn connector(self, peer: NodeId, service: Service) -> Connector {
        match self {
            Self::Standing(badge) => Connector::to_node(peer, service, badge),
            Self::Slip { slip, membership } => {
                crate::reach::gated(peer, service, Some(slip), membership)
            }
        }
    }
}

/// Why [`Peers`] handed back no stream or connection. `Busy` and `Timeout` are this owner's own bounds,
/// typed so a caller matches them rather than an io kind.
#[derive(Debug, thiserror::Error)]
pub enum OpenError {
    /// The peer's lane already holds its cap of live streams, or of connections for an isolated one.
    #[error("too many streams open to this machine; try again when one closes")]
    Busy,
    /// The held session took the request but the host did not answer within the lane's open deadline.
    /// The session is evicted, so the next stream dials afresh, unless another open on it succeeded
    /// during the wait: a slow host still answering keeps its session.
    #[error("the machine did not answer the request to open a stream in time")]
    Timeout,
    /// No session reached the peer: the dial failed or ran out of time.
    #[error(transparent)]
    Unreachable(DialFailure),
    /// The stream request failed on a reached session, or the host refused it.
    #[error(transparent)]
    Open(bifrost::Error),
}

/// One node's borrowed session owner, shared by everything one run opens to its peers.
///
/// No task is spawned. Dropping the owner releases pending dials and idle sessions; callers must drop
/// its borrowers, their streams and their isolated connections before closing the node.
pub struct Peers<'n, T: Transport, D: Discovery> {
    node: &'n Node<T, D>,
    // Structured futures interleave on one task. No borrow crosses an await; session values need not
    // be Send, Sync or Clone, and a cancelled caller must synchronously release its occupancy.
    entries: RefCell<HashMap<Key, Slot<'n, T::Session>>>,
    counts: RefCell<Counts>,
}

impl<'n, T: Transport, D: Discovery> Peers<'n, T, D> {
    /// Borrow the endpoint for everything this run opens.
    pub fn new(node: &'n Node<T, D>) -> Self {
        Self {
            node,
            entries: RefCell::new(HashMap::new()),
            counts: RefCell::new(HashMap::new()),
        }
    }

    /// Request one stream on `lane`, presenting this immutable snapshot for the cache key and the slots.
    /// `Standing(None)` sends neither slot and never reads a home. Admission repeats on every stream.
    ///
    /// A dial has ten seconds; an open has four on Main and ten on Bulk. A reused session found closed
    /// is redialed before the open, and a reused broken entry gets one redial; an open gets one redial
    /// at most, and a refusal, wrong peer, fresh failure or timeout never gets one. A timeout evicts the
    /// session only when no other open on it succeeded during the wait. Dropping an open never removes
    /// a session from the cache, at any instant on any lane, and leaves its idle clock where it was. The
    /// per-peer lane budget includes pending opens and remains occupied until both returned halves have
    /// dropped; past it, `Busy`.
    ///
    /// `hints` go into the feed of a dial this open starts, a cold one or its redial. They are ignored
    /// when the open reuses a held session or joins a dial already in flight.
    pub async fn open(
        &self,
        peer: NodeId,
        hints: Hints,
        service: Service,
        lane: Lane,
        presents: Presents,
    ) -> Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), OpenError> {
        let (_, _, writer, reader) = self
            .open_attached(peer, hints, service, lane, presents)
            .await?;
        Ok((writer, reader))
    }

    /// [`open`](Self::open), with the path report of the session the stream rides, read as it attached,
    /// and a watch on that session's closing.
    pub(crate) async fn open_attached(
        &self,
        peer: NodeId,
        hints: Hints,
        service: Service,
        lane: Lane,
        presents: Presents,
    ) -> Result<
        (
            ConnInfo,
            SessionEnd<T::Session>,
            impl AsyncWrite + Unpin + use<'_, 'n, T, D>,
            impl AsyncRead + Unpin + use<'_, 'n, T, D>,
        ),
        OpenError,
    > {
        let place = self.place(peer, lane)?;
        self.open_placed(place, hints, service, presents).await
    }

    /// A place on `peer`'s `lane`, counted against its cap from now until the stream it opens drops, or
    /// `Busy`. Synchronous and dependent on nothing but the peer and lane, so a caller takes it before
    /// anything slow and a full lane refuses first.
    pub(crate) fn place(&self, peer: NodeId, lane: Lane) -> Result<LanePlace, OpenError> {
        Ok(LanePlace {
            peer,
            lane,
            budget: self.reserve(peer, Class::from(lane))?,
        })
    }

    /// A place for one isolated connection to `peer`, or `Busy`; as [`place`](Self::place).
    pub(crate) fn isolated_place(&self, peer: NodeId) -> Result<IsolatedPlace, OpenError> {
        Ok(IsolatedPlace {
            peer,
            budget: self.reserve(peer, Class::Isolated)?,
        })
    }

    /// [`open_attached`](Self::open_attached) on a place already taken. The write half can also abort
    /// the stream, so a caller can tell the peer it was cut off.
    pub(crate) async fn open_placed(
        &self,
        place: LanePlace,
        hints: Hints,
        service: Service,
        presents: Presents,
    ) -> Result<
        (
            ConnInfo,
            SessionEnd<T::Session>,
            impl AsyncWrite + WriteEnd + Unpin + use<'_, 'n, T, D>,
            impl AsyncRead + Unpin + use<'_, 'n, T, D>,
        ),
        OpenError,
    > {
        let LanePlace { peer, lane, budget } = place;
        let key = Key {
            peer,
            carry: presents.carry(lane),
        };
        let connector = presents.connector(peer, service);
        let deadline = match lane {
            Lane::Main => MAIN_OPEN_TIMEOUT,
            Lane::Bulk => OPEN_TIMEOUT,
        };
        let (mut entry, reused) = self.session(&key, &hints).await?;
        let mut retry = reused;
        loop {
            let mut active = Active::new(Rc::clone(&entry));
            let start = Instant::now();
            let opened = tokio::time::timeout(deadline, connector.open_on(&entry.session)).await;
            if opened.is_ok() {
                active.answered = true;
            }
            match opened {
                Ok(Ok((writer, reader))) => {
                    entry.opened.set(Some(Instant::now()));
                    let info = entry.session.conn_info();
                    // The reservation transfers to the pair, not to either half alone.
                    let lease = Rc::new(Lease {
                        _active: active,
                        _budget: budget,
                    });
                    return Ok((
                        info,
                        SessionEnd(Rc::clone(&entry)),
                        Half {
                            inner: writer,
                            _lease: Rc::clone(&lease),
                        },
                        Half {
                            inner: reader,
                            _lease: lease,
                        },
                    ));
                }
                Ok(Err(error)) if retry && retryable(&error) => {
                    self.evict(&key, &entry);
                    drop(active);
                    entry = self.session(&key, &hints).await?.0;
                    retry = false;
                }
                Ok(Err(error)) => return Err(OpenError::Open(error)),
                Err(_) => {
                    // A stall freezes every open on its session while the session stays alive, so only
                    // an open that succeeded during this wait shows the host is still answering.
                    if entry.opened.get().is_none_or(|opened| opened < start) {
                        self.evict(&key, &entry);
                    }
                    return Err(OpenError::Timeout);
                }
            }
        }
    }

    /// Dial a connection of its own to `peer`, never held or shared, for a caller that must own the path
    /// it measures. The dial has ten seconds; streams the caller opens on the connection have no deadline
    /// from this owner. At most four live per peer, past which `Busy`; the count releases when the
    /// returned connection drops, which closes it. `hints` go into this dial's feed only.
    pub async fn isolated(
        &self,
        peer: NodeId,
        hints: Hints,
    ) -> Result<Isolated<T::Session>, OpenError> {
        let place = self.isolated_place(peer)?;
        self.isolated_placed(place, hints).await
    }

    /// [`isolated`](Self::isolated) on a place already taken.
    pub(crate) async fn isolated_placed(
        &self,
        place: IsolatedPlace,
        hints: Hints,
    ) -> Result<Isolated<T::Session>, OpenError> {
        let IsolatedPlace { peer, budget } = place;
        let session = dial(self.node, peer, &hints)
            .await
            .map_err(OpenError::Unreachable)?;
        Ok(Isolated {
            session,
            budget: Cell::new(Some(budget)),
        })
    }

    /// Sweep idle entries once per minute, driven beside the run and dropped with it.
    pub async fn sweep(&self) -> core::convert::Infallible {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            self.sweep_at(Instant::now());
        }
    }

    /// The held session for `key`, joining a dial in flight or starting one. Only a dial this call
    /// starts carries `hints`.
    async fn session(
        &self,
        key: &Key,
        hints: &Hints,
    ) -> Result<(Rc<Entry<T::Session>>, bool), OpenError> {
        let flight = {
            let mut entries = self.entries.borrow_mut();
            // A session the transport already closed would fail the open; dialing now spends the
            // open's one redial before a stream is asked of it.
            if matches!(entries.get(key), Some(Slot::Ready(entry)) if entry.session.wait_closed().now_or_never().is_some())
            {
                entries.remove(key);
            }
            match entries.get(key) {
                Some(Slot::Ready(entry)) => return Ok((Rc::clone(entry), true)),
                Some(Slot::Dialing(flight)) => Rc::clone(flight),
                None => {
                    let node = self.node;
                    let peer = key.peer;
                    // The flight owns its starter's hints, so a starter that leaves keeps them for the
                    // waiters still on the dial, and they end with the dial.
                    let hints = hints.clone();
                    // Shared polling keeps a waiter from depending on the original caller's lifetime.
                    // The map holds the future only while at least one caller is waiting for it.
                    let future = async move {
                        let session = dial(node, peer, &hints).await?;
                        Ok(Rc::new(Entry {
                            session,
                            live: Cell::new(0),
                            idle_since: Cell::new(Instant::now()),
                            opened: Cell::new(None),
                        }))
                    }
                    .boxed_local()
                    .shared();
                    let flight = Rc::new(Flight {
                        future,
                        waiters: Cell::new(0),
                    });
                    entries.insert(key.clone(), Slot::Dialing(Rc::clone(&flight)));
                    flight
                }
            }
        };
        flight.waiters.set(flight.waiters.get() + 1);
        let waiting = Waiting {
            peers: self,
            key,
            flight: Rc::clone(&flight),
        };
        let result = flight.future.clone().await;
        let mut entries = self.entries.borrow_mut();
        if matches!(entries.get(key), Some(Slot::Dialing(current)) if Rc::ptr_eq(current, &flight))
        {
            match &result {
                Ok(entry) => {
                    entries.insert(key.clone(), Slot::Ready(Rc::clone(entry)));
                }
                Err(_) => {
                    entries.remove(key);
                }
            }
        }
        drop(entries);
        drop(waiting);
        result
            .map(|entry| (entry, false))
            .map_err(OpenError::Unreachable)
    }

    fn reserve(&self, peer: NodeId, class: Class) -> Result<Budget, OpenError> {
        let mut counts = self.counts.borrow_mut();
        let count = counts
            .get(&(peer, class))
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let count = Rc::new(Cell::new(0));
                counts.insert((peer, class), Rc::downgrade(&count));
                count
            });
        if count.get() == class.cap() {
            return Err(OpenError::Busy);
        }
        count.set(count.get() + 1);
        Ok(Budget { count })
    }

    fn evict(&self, key: &Key, entry: &Rc<Entry<T::Session>>) {
        let mut entries = self.entries.borrow_mut();
        // A failed older open cannot evict a replacement another caller has already installed.
        if matches!(entries.get(key), Some(Slot::Ready(current)) if Rc::ptr_eq(current, entry)) {
            entries.remove(key);
        }
    }

    fn sweep_at(&self, now: Instant) {
        self.entries.borrow_mut().retain(|_, slot| match slot {
            Slot::Ready(entry) => {
                entry.live.get() != 0
                    || now.saturating_duration_since(entry.idle_since.get()) < IDLE_EVICTION
            }
            Slot::Dialing(_) => true,
        });
        self.counts
            .borrow_mut()
            .retain(|_, count| count.strong_count() != 0);
    }
}

/// Dial `peer` under the ten-second deadline, `hints` ahead of what the node's discovery finds in its feed.
/// No hints is a plain dial.
async fn dial<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    peer: NodeId,
    hints: &Hints,
) -> Result<T::Session, DialFailure> {
    match tokio::time::timeout(DIAL_TIMEOUT, node.connect_hinted(peer, hints.as_slice())).await {
        Ok(Ok(session)) => Ok(session),
        Ok(Err(error)) => Err(DialFailure::Failed(Arc::new(error))),
        Err(_elapsed) => Err(DialFailure::TimedOut),
    }
}

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    peer: NodeId,
    carry: Carry,
}

/// Which held session to a peer a stream rides. A renewed standing is a new key, so it opens a new
/// session and the old one ends with its last stream.
#[derive(Clone, PartialEq, Eq, Hash)]
enum Carry {
    Home {
        lane: Lane,
        standing: Option<String>,
    },
    // A lane per slip session, so a slip's stalled fan-out never holds its exchanges. The map keeps the
    // slip's digest, never the slip.
    Slip {
        lane: Lane,
        digest: [u8; 32],
        membership: Option<String>,
    },
}

// Weak, so a count no stream or connection holds any more is swept rather than kept per peer forever.
type Counts = HashMap<(NodeId, Class), Weak<Cell<u16>>>;

/// What a per-peer count bounds: one held lane's streams, or isolated connections.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Class {
    Main,
    Bulk,
    Isolated,
}

impl Class {
    const fn cap(self) -> u16 {
        match self {
            Self::Main => MAIN_STREAMS,
            Self::Bulk => BULK_STREAMS,
            Self::Isolated => ISOLATED_CONNECTIONS,
        }
    }
}

impl From<Lane> for Class {
    fn from(lane: Lane) -> Self {
        match lane {
            Lane::Main => Self::Main,
            Lane::Bulk => Self::Bulk,
        }
    }
}

enum Slot<'n, S: Session> {
    Dialing(Rc<Flight<'n, S>>),
    Ready(Rc<Entry<S>>),
}

struct Flight<'n, S: Session> {
    future: Shared<LocalBoxFuture<'n, DialResult<S>>>,
    waiters: Cell<u16>,
}

type DialResult<S> = Result<Rc<Entry<S>>, DialFailure>;

struct Waiting<'a, 'n, T: Transport, D: Discovery> {
    peers: &'a Peers<'n, T, D>,
    key: &'a Key,
    flight: Rc<Flight<'n, T::Session>>,
}

impl<T: Transport, D: Discovery> Drop for Waiting<'_, '_, T, D> {
    fn drop(&mut self) {
        let remaining = self.flight.waiters.get() - 1;
        self.flight.waiters.set(remaining);
        if remaining != 0 {
            return;
        }
        let mut entries = self.peers.entries.borrow_mut();
        if matches!(entries.get(self.key), Some(Slot::Dialing(current)) if Rc::ptr_eq(current, &self.flight))
        {
            entries.remove(self.key);
        }
    }
}

struct Entry<S: Session> {
    session: S,
    live: Cell<u16>,
    idle_since: Cell<Instant>,
    // When an open on this session last succeeded: the progress a timed-out open checks before evicting.
    opened: Cell<Option<Instant>>,
}

impl<S: Session> Drop for Entry<S> {
    fn drop(&mut self) {
        self.session.close();
    }
}

struct Budget {
    count: Rc<Cell<u16>>,
}

/// A stream's place on one peer's held lane, taken by [`Peers::place`] and spent by
/// [`Peers::open_placed`]; dropping it unspent gives the place back.
pub(crate) struct LanePlace {
    peer: NodeId,
    lane: Lane,
    budget: Budget,
}

/// An isolated connection's place among one peer's, taken by [`Peers::isolated_place`] and spent by
/// [`Peers::isolated_placed`]; dropping it unspent gives the place back.
pub(crate) struct IsolatedPlace {
    peer: NodeId,
    budget: Budget,
}

impl Drop for Budget {
    fn drop(&mut self) {
        self.count.set(self.count.get() - 1);
    }
}

struct Lease<S: Session> {
    _active: Active<S>,
    _budget: Budget,
}

struct Active<S: Session> {
    entry: Rc<Entry<S>>,
    // Whether the host answered this open. An open cancelled or timed out before an answer used the
    // session for nothing, so it must not keep an idle or stalled session from the sweep.
    answered: bool,
}

impl<S: Session> Active<S> {
    fn new(entry: Rc<Entry<S>>) -> Self {
        entry.live.set(entry.live.get() + 1);
        Self {
            entry,
            answered: false,
        }
    }
}

impl<S: Session> Drop for Active<S> {
    fn drop(&mut self) {
        self.entry.live.set(self.entry.live.get() - 1);
        if self.answered {
            self.entry.idle_since.set(Instant::now());
        }
    }
}

/// A hold on the held session a stream rides: a watch for a caller that must learn the session ended
/// while nothing reads or writes the stream, and the session an observed stream's path is read from. It
/// keeps the session as the stream's halves do, but counts toward no lane and leaves the idle clock
/// alone, so holding it past the stream keeps the session open without keeping it busy.
pub(crate) struct SessionEnd<S: Session>(Rc<Entry<S>>);

impl<S: Session> SessionEnd<S> {
    /// Resolve once the session has closed: the host ended it, or the path to it failed.
    pub(crate) async fn closed(&self) {
        self.0.session.wait_closed().await;
    }

    /// The session's path report as it reads now.
    pub(crate) fn conn_info(&self) -> ConnInfo {
        self.0.session.conn_info()
    }
}

impl<S: Session> Clone for SessionEnd<S> {
    fn clone(&self) -> Self {
        Self(Rc::clone(&self.0))
    }
}

struct Half<H, S: Session> {
    inner: H,
    _lease: Rc<Lease<S>>,
}

impl<H: AsyncRead + Unpin, S: Session> AsyncRead for Half<H, S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

// Forwarded, so a lane's stream can be cut off as any transport's can. `delivered` takes the half, and
// the lease goes with it: a caller waits on delivery only to close, so the slot is not wanted past it.
impl<H: WriteEnd, S: Session> WriteEnd for Half<H, S> {
    fn abort(&mut self) {
        self.inner.abort();
    }

    fn delivered(self) -> impl Future<Output = io::Result<()>> + Send + 'static {
        self.inner.delivered()
    }
}

impl<H: AsyncWrite + Unpin, S: Session> AsyncWrite for Half<H, S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A connection [`Peers::isolated`] dialed for one caller: never held, shared or reused.
///
/// Dropping it closes the connection and releases its per-peer count, so the count is exactly the live
/// connections; a stream that outlived it ends with it. A caller whose streams on it have ended may
/// release the count earlier and keep the connection open to read its path.
pub struct Isolated<S: Session> {
    session: S,
    budget: Cell<Option<Budget>>,
}

impl<S: Session> Isolated<S> {
    /// Give back this connection's place among the peer's isolated connections, keeping the connection
    /// open. Once only: a second call has nothing left to release.
    pub(crate) fn release_place(&self) {
        drop(self.budget.take());
    }
}

impl<S: Session> Session for Isolated<S> {
    type Write = S::Write;
    type Read = S::Read;

    fn peer(&self) -> NodeId {
        self.session.peer()
    }

    async fn open_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.session.open_bi().await
    }

    async fn accept_bi(&self) -> Result<(Self::Write, Self::Read), bifrost::Error> {
        self.session.accept_bi().await
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

impl<S: Session> Drop for Isolated<S> {
    fn drop(&mut self) {
        self.session.close();
    }
}

/// A dial that reached no session. Cloneable, so a shared failed flight reaches every waiter; a failure
/// keeps its source behind an `Arc`, since the transport's error is not `Clone`.
#[derive(Debug, Clone, thiserror::Error)]
pub enum DialFailure {
    /// The peer did not answer within the dial deadline. Worded as every verb's own dial words it.
    #[error("timed out after {DIAL_TIMEOUT:?} with no response")]
    TimedOut,
    /// The transport's own failure to connect.
    #[error(transparent)]
    Failed(Arc<bifrost::Error>),
}

fn retryable(error: &bifrost::Error) -> bool {
    match error {
        bifrost::Error::Connect(_) | bifrost::Error::Closed => true,
        bifrost::Error::Stream(cause) => !cause.is::<WrongPeer>(),
        bifrost::Error::Accept(_) | bifrost::Error::Refused(_) => false,
    }
}

#[cfg(test)]
#[path = "peers_tests.rs"]
mod tests;
