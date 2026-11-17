//! Run-owned sessions to peers, in lanes. Each stream requests admission separately; renewal pick-ups
//! present no credentials.
//!
//! [`Lane::Main`] carries ordinary service streams and [`Lane::Bulk`] fan-out pipes, each on its own held
//! session per peer, so a full fan-out never stalls an exchange. A slip rides held sessions of its own,
//! shared only by streams presenting the identical slip, one per lane, so a slip's fan-out never stalls
//! its exchanges either. [`Peers::isolated`] dials a connection per caller and never holds it. Every lane
//! has a per-peer cap, enforced here for every run. An open that gets no answer in its lane's deadline
//! evicts a session no other open got through on; dropping an open never removes a session.

use core::cell::{Cell, RefCell};
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use bifrost::{ConnInfo, Discovery, Node, NodeId, PathChanges, Session, Transport};
use futures::FutureExt as _;
use futures::future::{LocalBoxFuture, Shared};
use nauthy::{Link, Service};
use tightbeam::tunnel::{Connector, WrongPeer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
// A Bulk open's deadline. A pipe's caller waits on its open with nothing racing it, so the open itself
// bounds how long a silent session is kept.
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
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

    fn connector(self, peer: NodeId, service: Service) -> Connector {
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
    pub async fn open(
        &self,
        peer: NodeId,
        service: Service,
        lane: Lane,
        presents: Presents,
    ) -> Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), OpenError> {
        let budget = self.reserve(peer, Class::from(lane))?;
        let key = Key {
            peer,
            carry: presents.carry(lane),
        };
        let connector = presents.connector(peer, service);
        let deadline = match lane {
            Lane::Main => MAIN_OPEN_TIMEOUT,
            Lane::Bulk => OPEN_TIMEOUT,
        };
        let (mut entry, reused) = self.session(&key).await?;
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
                    // The reservation transfers to the pair, not to either half alone.
                    let lease = Rc::new(Lease {
                        _active: active,
                        _budget: budget,
                    });
                    return Ok((
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
                    entry = self.session(&key).await?.0;
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
    /// it measures. At most four live per peer, past which `Busy`; the count releases when the returned
    /// connection drops, which closes it.
    pub async fn isolated(&self, peer: NodeId) -> Result<Isolated<T::Session>, OpenError> {
        let budget = self.reserve(peer, Class::Isolated)?;
        let session = dial(self.node, peer)
            .await
            .map_err(OpenError::Unreachable)?;
        Ok(Isolated {
            session,
            _budget: budget,
        })
    }

    /// Sweep idle entries once per minute, driven beside the run and dropped with it.
    pub async fn sweep(&self) -> core::convert::Infallible {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            self.sweep_at(Instant::now());
        }
    }

    async fn session(&self, key: &Key) -> Result<(Rc<Entry<T::Session>>, bool), OpenError> {
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
                    // Shared polling keeps a waiter from depending on the original caller's lifetime.
                    // The map holds the future only while at least one caller is waiting for it.
                    let future = async move {
                        let session = dial(node, peer).await?;
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

/// Dial `peer` under the ten-second deadline.
async fn dial<T: Transport, D: Discovery>(
    node: &Node<T, D>,
    peer: NodeId,
) -> Result<T::Session, DialFailure> {
    match tokio::time::timeout(DIAL_TIMEOUT, node.connect(peer)).await {
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
/// connections; a stream that outlived it ends with it.
pub struct Isolated<S: Session> {
    session: S,
    _budget: Budget,
}

impl<S: Session> Session for Isolated<S> {
    type Security = S::Security;
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
