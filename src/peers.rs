//! Run-owned raw Main sessions. Each stream requests admission separately; renewal pick-ups present
//! no credentials.

use core::cell::{Cell, RefCell};
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::collections::HashMap;
use std::io;
use std::rc::{Rc, Weak};
use std::sync::Arc;

use bifrost::{Discovery, Node, NodeId, Session, Transport};
use futures::FutureExt as _;
use futures::future::{LocalBoxFuture, Shared};
use nauthy::{Link, Service};
use tightbeam::tunnel::{Connector, WrongPeer};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Instant;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const OPEN_TIMEOUT: Duration = Duration::from_secs(10);
const IDLE_EVICTION: Duration = Duration::from_secs(5 * 60);
const SWEEP_INTERVAL: Duration = Duration::from_secs(60);
const MAIN_STREAMS: u16 = 64;

/// One node's borrowed Main-session owner, shared by the run's exchanges and pick-ups.
///
/// No task is spawned. Dropping the owner releases pending dials and idle sessions; callers must drop
/// its borrowers and their streams before closing the node. Callers must supply only the home's own badge,
/// never a slip.
pub struct Peers<'n, T: Transport, D: Discovery> {
    node: &'n Node<T, D>,
    // Structured futures interleave on one task. No borrow crosses an await; session values need not
    // be Send, Sync or Clone, and a cancelled caller must synchronously release its occupancy.
    entries: RefCell<HashMap<Key, Slot<'n, T::Session>>>,
    counts: RefCell<HashMap<NodeId, Weak<Cell<u16>>>>,
}

impl<'n, T: Transport, D: Discovery> Peers<'n, T, D> {
    /// Borrow the endpoint for this run's exchanges and renewal pick-ups.
    pub fn new(node: &'n Node<T, D>) -> Self {
        Self {
            node,
            entries: RefCell::new(HashMap::new()),
            counts: RefCell::new(HashMap::new()),
        }
    }

    /// Request one stream using this immutable badge snapshot for the cache key and slot 1.
    /// `None` sends neither credential slot and never reads a home. Admission repeats on every stream.
    ///
    /// Dial and open each have their own ten-second deadline. A reused broken entry gets one redial,
    /// but a refusal, wrong peer, fresh failure or timeout never does. A caller that drops an open
    /// before it completes evicts the entry, as the timeout does. The per-peer Main budget includes
    /// pending opens and remains occupied until both returned halves have dropped.
    pub async fn open(
        &self,
        peer: NodeId,
        service: Service,
        standing: Option<Link>,
    ) -> Result<(impl AsyncWrite + Unpin, impl AsyncRead + Unpin), bifrost::Error> {
        let budget = self.reserve(peer)?;
        let key = Key {
            peer,
            standing: standing.as_ref().map(|badge| badge.as_str().to_owned()),
        };
        let connector = Connector::to_node(peer, service, standing);
        let (mut entry, reused) = self.session(&key).await?;
        let mut retry = reused;
        loop {
            let active = Active::new(Rc::clone(&entry));
            // Declared after `active`, so a cancelled caller evicts first and then releases its count.
            let attempt = Attempt {
                peers: self,
                key: &key,
                entry: &entry,
            };
            let opened =
                tokio::time::timeout(OPEN_TIMEOUT, connector.open_on(&entry.session)).await;
            attempt.complete();
            match opened {
                Ok(Ok((writer, reader))) => {
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
                Ok(Err(error)) => return Err(error),
                Err(_) => {
                    self.evict(&key, &entry);
                    return Err(bifrost::Error::Stream(Box::new(io::Error::from(
                        io::ErrorKind::TimedOut,
                    ))));
                }
            }
        }
    }

    /// Sweep idle entries once per minute, driven beside the run and dropped with it.
    pub async fn sweep(&self) -> core::convert::Infallible {
        loop {
            tokio::time::sleep(SWEEP_INTERVAL).await;
            self.sweep_at(Instant::now());
        }
    }

    async fn session(&self, key: &Key) -> Result<(Rc<Entry<T::Session>>, bool), bifrost::Error> {
        let flight = {
            let mut entries = self.entries.borrow_mut();
            match entries.get(key) {
                Some(Slot::Ready(entry)) => return Ok((Rc::clone(entry), true)),
                Some(Slot::Dialing(flight)) => Rc::clone(flight),
                None => {
                    let node = self.node;
                    let peer = key.peer;
                    // Shared polling keeps a waiter from depending on the original caller's lifetime.
                    // The map holds the future only while at least one caller is waiting for it.
                    let future = async move {
                        let session = tokio::time::timeout(DIAL_TIMEOUT, node.connect(peer))
                            .await
                            .unwrap_or_else(|_| {
                                Err(bifrost::Error::Connect(Box::new(io::Error::from(
                                    io::ErrorKind::TimedOut,
                                ))))
                            })
                            .map_err(Arc::new)?;
                        Ok(Rc::new(Entry {
                            session,
                            live: Cell::new(0),
                            idle_since: Cell::new(Instant::now()),
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
            .map_err(|error| bifrost::Error::Connect(Box::new(DialFailure(error))))
    }

    fn reserve(&self, peer: NodeId) -> Result<Budget, bifrost::Error> {
        let mut counts = self.counts.borrow_mut();
        let count = counts
            .get(&peer)
            .and_then(Weak::upgrade)
            .unwrap_or_else(|| {
                let count = Rc::new(Cell::new(0));
                counts.insert(peer, Rc::downgrade(&count));
                count
            });
        if count.get() == MAIN_STREAMS {
            return Err(bifrost::Error::Stream(Box::new(io::Error::from(
                io::ErrorKind::WouldBlock,
            ))));
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

#[derive(Clone, PartialEq, Eq, Hash)]
struct Key {
    peer: NodeId,
    // Only Main is consumed here. No lane selector exists until another lane has a real caller.
    standing: Option<String>,
}

enum Slot<'n, S: Session> {
    Dialing(Rc<Flight<'n, S>>),
    Ready(Rc<Entry<S>>),
}

struct Flight<'n, S: Session> {
    future: Shared<LocalBoxFuture<'n, DialResult<S>>>,
    waiters: Cell<u16>,
}

type DialResult<S> = Result<Rc<Entry<S>>, Arc<bifrost::Error>>;

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

// Callers bound an open below its own deadline, so a stalled session would otherwise stay cached and
// every cancelled try would reset its idle clock. Dropping an unfinished attempt evicts its entry.
struct Attempt<'a, 'n, T: Transport, D: Discovery> {
    peers: &'a Peers<'n, T, D>,
    key: &'a Key,
    entry: &'a Rc<Entry<T::Session>>,
}

impl<T: Transport, D: Discovery> Attempt<'_, '_, T, D> {
    fn complete(self) {
        // Only borrows are held, so forgetting the guard leaks nothing.
        core::mem::forget(self);
    }
}

impl<T: Transport, D: Discovery> Drop for Attempt<'_, '_, T, D> {
    fn drop(&mut self) {
        self.peers.evict(self.key, self.entry);
    }
}

struct Entry<S: Session> {
    session: S,
    live: Cell<u16>,
    idle_since: Cell<Instant>,
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
}

impl<S: Session> Active<S> {
    fn new(entry: Rc<Entry<S>>) -> Self {
        entry.live.set(entry.live.get() + 1);
        Self { entry }
    }
}

impl<S: Session> Drop for Active<S> {
    fn drop(&mut self) {
        self.entry.live.set(self.entry.live.get() - 1);
        self.entry.idle_since.set(Instant::now());
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

// A shared failed flight must preserve its source for every waiter without requiring Error: Clone.
#[derive(Debug, thiserror::Error)]
#[error(transparent)]
struct DialFailure(Arc<bifrost::Error>);

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
