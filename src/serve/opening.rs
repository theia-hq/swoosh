//! The server side of an Open: one admitted stream to a peer, spliced onto the control connection that
//! asked for it.
//!
//! Every check that can refuse without reaching out runs first: the peer is not this machine, the slip
//! is not one anyone may hold, the run has a reach slot for the lane, and the peer's lane has room. Only
//! then is the control slot released, the standing renewed when due, and the peer dialed. Once attached,
//! the two streams are spliced one direction at a time until both are done, or until the local client
//! is gone or, once the peer has ended, has finished writing.

use core::pin::pin;
use core::time::Duration;
use std::os::fd::{BorrowedFd, OwnedFd, RawFd};
use std::time::SystemTime;

use bifrost::{Discovery, NodeId, RefusalDetail, Session as _, Transport, WriteEnd};
use nauthy::Service;
use tokio::io::unix::AsyncFd;
use tokio::io::{self, AsyncBufRead, AsyncRead, AsyncWrite, AsyncWriteExt as _, Interest};
use tokio::sync::{Semaphore, SemaphorePermit};
use tokio::time::Instant;

use super::PROVEN_ROUTES;
use super::socket::{OpenLane, OpenRefusal, OpenRequest, Response};
use crate::credential::{Credential, admits_anyone_at};
use crate::home::Home;
use crate::peers::{DialFailure, Lane, OPEN_TIMEOUT, OpenError, Peers, Presents};
use crate::reaching::ResolveError;
use crate::renewal::{Fetch, OpenRenewal};

/// The most streams the run's Opens hold at once, across every peer and lane.
pub const MAX_REACH: usize = 256;

/// The most of [`MAX_REACH`] that Bulk, slip and Isolated streams may hold together, so the rest is
/// always there for an ordinary Main stream.
pub const MAX_BEYOND_MAIN: usize = 224;

const _: () = assert!(MAX_BEYOND_MAIN < MAX_REACH);

/// How long a splice whose local client has closed its socket in both directions, or has finished
/// writing after the peer ended, may go on sending what the client wrote, on every lane. Counted from
/// that moment and never extended by progress, so a peer taking a byte at a time cannot hold the
/// splice; at the deadline the splice is dropped, and with it the reach slots, the lane count and the
/// session, or the isolated connection. An isolated connection's close waits for the peer to hold what was
/// sent within the same bound.
pub const HANGUP_DRAIN: Duration = Duration::from_secs(4);

/// The soft open-file limit a run asks for: each Open holds two descriptors, its connection and the
/// watch's duplicate, and macOS starts a process at 256.
pub const OPEN_FILES: libc::rlim_t = 4096;

/// Raise this process's soft open-file limit to [`OPEN_FILES`], or to the hard limit when that is lower,
/// and never lower it. Processes this one starts afterwards (`sshd` shells, the services' backends)
/// inherit the raised limit.
///
/// # Errors
///
/// The limit cannot be read or set.
pub fn raise_open_files() -> io::Result<()> {
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a live, writable `rlimit` for the call to fill.
    if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let wanted = OPEN_FILES.min(limit.rlim_max);
    if limit.rlim_cur >= wanted {
        return Ok(());
    }
    limit.rlim_cur = wanted;
    // SAFETY: `limit` is a valid `rlimit` that outlives the call, which only reads it.
    if unsafe { libc::setrlimit(libc::RLIMIT_NOFILE, &limit) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// How long the reply to an Open, Attached or a refusal, may take to write.
const REPLY_TIMEOUT: Duration = super::resident::READ_TIMEOUT;

/// What the run lends the resident to answer Opens: its sessions, its renewal and its home, and the
/// reach slots every Open takes for as long as its stream lives.
pub struct Opener<'r, 'a, 'n, T: Transport, D: Discovery, F: Fetch> {
    peers: &'r Peers<'n, T, D>,
    renewal: &'r OpenRenewal<'a, F>,
    home: &'r Home,
    /// This machine, which an Open may not name as its peer.
    this: NodeId,
    reach: Semaphore,
    beyond_main: Semaphore,
}

impl<'r, 'a, 'n, T: Transport, D: Discovery, F: Fetch> Opener<'r, 'a, 'n, T, D, F> {
    /// Answer Opens for the run whose node is `this`.
    pub fn new(
        peers: &'r Peers<'n, T, D>,
        renewal: &'r OpenRenewal<'a, F>,
        home: &'r Home,
        this: NodeId,
    ) -> Self {
        Self {
            peers,
            renewal,
            home,
            this,
            reach: Semaphore::new(MAX_REACH),
            beyond_main: Semaphore::new(MAX_BEYOND_MAIN),
        }
    }

    /// The reach slots an Open on `lane` takes, or `Busy`. A slip's stream is never ordinary Main: it
    /// rides a session of its own, so it counts against the non-Main share whatever its lane.
    fn hold(&self, lane: OpenLane, slip: bool) -> Result<Held<'_>, OpenRefusal> {
        let beyond_main = match (lane, slip) {
            (OpenLane::Main, false) => None,
            (OpenLane::Main, true) | (OpenLane::Bulk | OpenLane::Isolated, _) => Some(
                self.beyond_main
                    .try_acquire()
                    .map_err(|_| OpenRefusal::Busy)?,
            ),
        };
        let reach = self.reach.try_acquire().map_err(|_| OpenRefusal::Busy)?;
        Ok(Held {
            _reach: reach,
            _beyond_main: beyond_main,
        })
    }

    /// What the stream presents: the slip when there is one, nothing on a proven-only route, else this
    /// home's standing as it reads now. An ended badge ends the Open with `StandingEnded`; a home that
    /// cannot be read ends it with the one fixed Error, since it says nothing about the standing.
    // `core::io::sink` is still unstable, so the sink for the warning comes from `std`.
    #[allow(clippy::std_instead_of_core)]
    async fn presents(
        &self,
        service: &Service,
        slip: Option<nauthy::Link>,
    ) -> Result<Presents, Response> {
        if slip.is_none() && PROVEN_ROUTES.contains(&service.as_str()) {
            return Ok(Presents::Standing(None));
        }
        let slipped = slip.is_some();
        // The expiring-badge line is the verb's to print, never the run's, once per Open.
        let mut no_warning = std::io::sink();
        let resolved = crate::reaching::resolve_to(
            Credential::Family { present: slip },
            self.this,
            self.home,
            &mut no_warning,
        )
        .await
        .map_err(|error| {
            tracing::debug!(error = %error, "an open's standing could not be presented");
            match error {
                ResolveError::Ended { .. } => Response::OpenRefusal(OpenRefusal::StandingEnded),
                ResolveError::Unreadable(_) => Response::Error(UNREADABLE_HOME.to_owned()),
            }
        })?;
        Ok(match (slipped, resolved.into_slots()) {
            (true, (Some(slip), membership)) => Presents::Slip { slip, membership },
            (_, (grant, _)) => Presents::Standing(grant),
        })
    }
}

/// An Open's reach slots, released when its stream ends.
struct Held<'o> {
    _reach: SemaphorePermit<'o>,
    _beyond_main: Option<SemaphorePermit<'o>>,
}

/// Something that answers an Open on the control connection that carried it.
pub trait Opens {
    /// Answer `open` to the client reading `to_client` and writing `from_client`, which `gone` watches.
    /// `from_client` still holds whatever the client sent after the request. `control` is the
    /// connection's control slot, released before anything reaches out.
    fn open<R, W>(
        &self,
        open: OpenRequest,
        from_client: R,
        to_client: W,
        gone: ClientGone,
        control: SemaphorePermit<'_>,
    ) -> impl Future<Output = ()>
    where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin;

    /// What runs beside the Opens for as long as the socket is served: a renewal an Open started runs
    /// to its end and its end counts, even when every Open waiting on it has gone, so a parked flight
    /// never holds `home.lock`.
    fn drive(&self) -> impl Future<Output = core::convert::Infallible>;
}

impl<T: Transport, D: Discovery, F: Fetch> Opens for Opener<'_, '_, '_, T, D, F> {
    fn drive(&self) -> impl Future<Output = core::convert::Infallible> {
        self.renewal.drive()
    }

    async fn open<R, W>(
        &self,
        open: OpenRequest,
        from_client: R,
        mut to_client: W,
        gone: ClientGone,
        control: SemaphorePermit<'_>,
    ) where
        R: AsyncBufRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let peer = open.peer();
        if peer == self.this {
            return refuse(&mut to_client, OpenRefusal::NotHere).await;
        }
        if let Some(slip) = open.slip()
            && admits_anyone_at(slip, open.service().as_str(), SystemTime::now())
        {
            return refuse(&mut to_client, OpenRefusal::NotHere).await;
        }
        let held = match self.hold(open.lane(), open.slip().is_some()) {
            Ok(held) => held,
            Err(refusal) => return refuse(&mut to_client, refusal).await,
        };
        // The peer's lane is counted before renewal, so an Open that would be Busy never starts or joins
        // a renewal flight.
        let place = match open.lane() {
            OpenLane::Main => self.peers.place(peer, Lane::Main).map(Place::Lane),
            OpenLane::Bulk => self.peers.place(peer, Lane::Bulk).map(Place::Lane),
            OpenLane::Isolated => self.peers.isolated_place(peer).map(Place::Isolated),
        };
        let place = match place {
            Ok(place) => place,
            Err(error) => return refuse(&mut to_client, failed(&error)).await,
        };
        // A stream may live for hours; the control slot is for answering the socket, not for that.
        drop(control);
        // From here the Open reaches out, so a client gone in the meantime ends it at once: nobody is
        // left to read the reply.
        let reached = until_gone(&gone, async {
            // The Open goes on with whatever standing the home holds after this, renewed or not.
            let _ = self.renewal.before(&open).await;
            let (hints, service) = (open.hints().clone(), open.service().clone());
            let presents = self.presents(&service, open.into_slip()).await?;
            Ok((hints, service, presents))
        })
        .await;
        let Some(reached) = reached else { return };
        let (hints, service, presents) = match reached {
            Ok(reached) => reached,
            Err(reply) => return answer(&mut to_client, reply).await,
        };
        let place = match place {
            Place::Lane(place) => place,
            Place::Isolated(place) => {
                let opened = until_gone(&gone, async {
                    let connection = self
                        .peers
                        .isolated_placed(place, hints)
                        .await
                        .map_err(|error| failed(&error))?;
                    let connector = presents.connector(peer, service);
                    // Bulk's deadline: nothing is evicted and nothing races this open.
                    match tokio::time::timeout(OPEN_TIMEOUT, connector.open_on(&connection)).await {
                        Ok(Ok((writer, reader))) => Ok((connection, writer, reader)),
                        Ok(Err(error)) => Err(failed(&OpenError::Open(error))),
                        Err(_) => Err(OpenRefusal::Timeout),
                    }
                })
                .await;
                let Some(opened) = opened else { return };
                let (connection, mut to_peer, from_peer) = match opened {
                    Ok(opened) => opened,
                    Err(refusal) => return refuse(&mut to_client, refusal).await,
                };
                let info = connection.conn_info();
                let close_by =
                    attach(from_client, to_client, from_peer, &mut to_peer, info, &gone).await;
                // Closing a connection discards what the peer has not acknowledged, so it stays open
                // until the peer holds every byte and the end, and closes then, never after `close_by`.
                // A cut-off stream was aborted on the way out of `attach`, so its delivery fails at once;
                // any failure means nothing more can reach the peer, and the close follows at once too.
                let _ = tokio::time::timeout_at(close_by, to_peer.delivered()).await;
                drop((connection, held));
                return;
            }
        };
        let opened = until_gone(
            &gone,
            self.peers.open_placed(place, hints, service, presents),
        )
        .await;
        let Some(opened) = opened else { return };
        match opened {
            // The held session outlives this stream, so what the peer has not taken is still delivered
            // after the splice drops it: no close to wait for.
            Ok((info, mut to_peer, from_peer)) => {
                let _ = attach(from_client, to_client, from_peer, &mut to_peer, info, &gone).await;
            }
            Err(error) => refuse(&mut to_client, failed(&error)).await,
        }
        drop(held);
    }
}

/// An Open's place on its peer, taken before anything slow.
enum Place {
    /// On a held lane.
    Lane(crate::peers::LanePlace),
    /// Among the peer's isolated connections.
    Isolated(crate::peers::IsolatedPlace),
}

/// `work`, or `None` once the client is gone.
async fn until_gone<F: Future>(gone: &ClientGone, work: F) -> Option<F::Output> {
    tokio::select! {
        done = work => Some(done),
        () = gone.wait() => None,
    }
}

/// Reply `refusal` and end the connection.
async fn refuse<W: AsyncWrite + Unpin>(to_client: &mut W, refusal: OpenRefusal) {
    answer(to_client, Response::OpenRefusal(refusal)).await;
}

/// Reply `reply`, a refusal or the Error, and end the connection.
async fn answer<W: AsyncWrite + Unpin>(to_client: &mut W, reply: Response) {
    let _ = tokio::time::timeout(REPLY_TIMEOUT, reply.write(to_client)).await;
    let _ = to_client.shutdown().await;
}

/// Reply Attached with the path the stream rides, then splice. Returns when a graceful close of an
/// isolated connection must be done by: at once when nothing was spliced.
///
/// However this ends, short of a successful shutdown of `to_peer`, the peer's stream is aborted: a failed
/// reply, a failed or cut-off splice, and this future dropped by a gone client, `Stop` or a panic.
async fn attach<R, W, PR, PW>(
    from_client: R,
    mut to_client: W,
    from_peer: PR,
    to_peer: &mut PW,
    info: bifrost::ConnInfo,
    gone: &ClientGone,
) -> Instant
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    PR: AsyncRead + Unpin,
    PW: AsyncWrite + WriteEnd + Unpin,
{
    // Armed before anything can return, so no early exit leaves the peer a clean end.
    let to_peer = ToPeer::arm(to_peer);
    let reply = Response::Attached(info);
    if !matches!(
        tokio::time::timeout(REPLY_TIMEOUT, reply.write(&mut to_client)).await,
        Ok(Ok(()))
    ) {
        return Instant::now();
    }
    splice(
        from_client,
        to_client,
        from_peer,
        to_peer,
        gone.wait(),
        gone.finished_writing(),
    )
    .await
}

/// Move bytes both ways, each direction on its own. The client's end of writing shuts the peer's
/// writing and the peer's end shuts the client's, while the reverse keeps flowing; the splice is done
/// when both directions are, or when the direction toward the peer fails.
///
/// `hangup` resolves when the client has closed its socket in both directions. Then the direction
/// toward the client stops at once, and what the client wrote before it went goes on toward the peer
/// for at most [`HANGUP_DRAIN`] from that moment; the splice then ends, dropping everything it holds.
/// The hang-up is watched only while this side still writes to the client: once it has shut that
/// writing, a hang-up can be its own (macOS reports one), so a gone client and a half-closed one look
/// the same. Then `finished` stands in: it resolves when the client has finished writing, gone or
/// half-closed, and starts the same drain. A client still writing to a peer that has ended stays live.
///
/// A write toward the client that fails ends only that direction: the client's bytes still go to the
/// peer, and a client that went is bounded by `finished` as above.
///
/// Each direction holds one 8 KiB buffer and no more: toward the peer, the client reader's own buffer,
/// read in place; toward the client, the one buffer of the copy.
///
/// Returns when a close that waits for the peer to take what was sent must be done by: the drain's own
/// deadline once one started, [`HANGUP_DRAIN`] from now after a clean end, and now when the direction
/// toward the peer failed, since nothing is left to deliver.
pub(crate) async fn splice<R, W, PR, PW>(
    mut from_client: R,
    mut to_client: W,
    mut from_peer: PR,
    mut to_peer: PW,
    hangup: impl Future<Output = ()>,
    finished: impl Future<Output = ()>,
) -> Instant
where
    R: AsyncBufRead + Unpin,
    W: AsyncWrite + Unpin,
    PR: AsyncRead + Unpin,
    PW: AsyncWrite + Unpin,
{
    // Done when the client stops writing.
    let mut up = pin!(async {
        io::copy_buf(&mut from_client, &mut to_peer).await?;
        to_peer.shutdown().await
    });
    // Done when the peer stops writing.
    let mut down = pin!(async {
        io::copy(&mut from_peer, &mut to_client).await?;
        to_client.shutdown().await
    });
    let (mut hangup, mut finished) = (pin!(hangup), pin!(finished));
    let (mut up_done, mut down_done) = (false, false);
    loop {
        tokio::select! {
            ended = &mut up, if !up_done => {
                if let Err(error) = ended {
                    tracing::debug!(%error, "a splice ended toward the peer");
                    return Instant::now();
                }
                up_done = true;
            }
            ended = &mut down, if !down_done => {
                if let Err(error) = ended {
                    tracing::debug!(%error, "a splice stopped writing to its client");
                }
                down_done = true;
            }
            () = &mut hangup, if !down_done => break,
            // Polled only once nothing more goes to the client, so an upload's data never wakes it
            // before then.
            () = &mut finished, if down_done => break,
        }
        if up_done && down_done {
            return Instant::now() + HANGUP_DRAIN;
        }
    }
    // One deadline from the hang-up; nothing the peer takes moves it.
    let drained_by = Instant::now() + HANGUP_DRAIN;
    if !up_done && let Ok(Err(error)) = tokio::time::timeout_at(drained_by, &mut up).await {
        tracing::debug!(%error, "a splice ended toward the peer");
        return Instant::now();
    }
    drained_by
}

/// The send half toward the peer for the life of an attached Open. Dropped before a successful shutdown,
/// it aborts the stream, so the peer reads a cut-off as `ConnectionReset` and never as a clean end: a
/// transport's write half dropped as it is ends the stream cleanly, which would pass a cut-off upload as
/// a finished one. A successful shutdown disarms it, so a finished stream is never reset.
///
/// It borrows the half, so the Open keeps it afterwards to wait on its delivery.
struct ToPeer<'h, W: WriteEnd> {
    half: &'h mut W,
    finished: bool,
}

impl<'h, W: WriteEnd> ToPeer<'h, W> {
    fn arm(half: &'h mut W) -> Self {
        Self {
            half,
            finished: false,
        }
    }
}

impl<W: AsyncWrite + WriteEnd + Unpin> AsyncWrite for ToPeer<'_, W> {
    fn poll_write(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<io::Result<usize>> {
        core::pin::Pin::new(&mut *self.get_mut().half).poll_write(cx, buf)
    }

    fn poll_flush(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        core::pin::Pin::new(&mut *self.get_mut().half).poll_flush(cx)
    }

    fn poll_shutdown(
        self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<io::Result<()>> {
        let this = self.get_mut();
        let shut = core::pin::Pin::new(&mut *this.half).poll_shutdown(cx);
        if matches!(shut, core::task::Poll::Ready(Ok(()))) {
            this.finished = true;
        }
        shut
    }
}

impl<W: WriteEnd> Drop for ToPeer<'_, W> {
    fn drop(&mut self) {
        if !self.finished {
            self.half.abort();
        }
    }
}

/// The refusal a failed open carries on the wire. The text is fixed here: a transport's own words can
/// name addresses, so they stay in the run's log.
fn failed(error: &OpenError) -> OpenRefusal {
    tracing::debug!(%error, "an open was not attached");
    match error {
        OpenError::Busy => OpenRefusal::Busy,
        OpenError::Timeout | OpenError::Unreachable(DialFailure::TimedOut) => OpenRefusal::Timeout,
        OpenError::Unreachable(DialFailure::Failed(_)) => {
            OpenRefusal::Unreachable(RefusalDetail::bounded(UNREACHABLE))
        }
        OpenError::Open(bifrost::Error::Refused(refusal)) => OpenRefusal::from(refusal.clone()),
        OpenError::Open(_) => OpenRefusal::Broken(RefusalDetail::bounded(BROKEN)),
    }
}

/// The detail an Unreachable refusal carries.
const UNREACHABLE: &str = "the machine could not be reached";

/// The detail a Broken refusal carries.
const BROKEN: &str = "the connection to the machine failed while opening the stream";

/// The Error an Open gets when this machine's home or badge cannot be read. It names no path and no
/// cause; those stay in the run's log.
const UNREADABLE_HOME: &str = "this machine's standing could not be read";

/// Watches a control connection for its client closing the socket in both directions.
///
/// A half-close is not that: a client that has finished writing still reads the peer's reply. Only a
/// socket closed both ways, which a client that exits or drops it leaves, reads as closed for writing
/// on this side: the kqueue write filter's end of file on macOS, a hang-up on Linux. The same watch
/// also tells when the client has finished writing, gone or half-closed: the read side's end of file,
/// seen even with the client's bytes still unread. The watch has a registration of its own, on a
/// duplicate of the connection's descriptor, so clearing its readiness never takes a wakeup from the
/// splice reading or writing the same socket. The duplicate is a second descriptor per Open.
pub struct ClientGone(AsyncFd<OwnedFd>);

impl ClientGone {
    /// Watch the connection at `fd`, which is open for the whole call.
    ///
    /// # Errors
    ///
    /// The descriptor cannot be duplicated or registered with the runtime.
    pub(crate) fn watch(fd: RawFd) -> io::Result<Self> {
        // SAFETY: the caller holds the connection that owns `fd` open for this call, and the borrow
        // ends inside it.
        let borrowed = unsafe { BorrowedFd::borrow_raw(fd) };
        let duplicate = borrowed.try_clone_to_owned()?;
        // SAFETY: the duplicate is an open descriptor this watch owns, so it stays open and names the
        // same socket for as long as the registration lives.
        let watch = unsafe {
            AsyncFd::register_with_interest(duplicate, Interest::WRITABLE | Interest::READABLE)
        }?;
        Ok(Self(watch))
    }

    /// Return once the client is gone. Each wake that is not the close clears the edge and waits for
    /// the next, so a writable socket never spins the watch.
    pub(crate) async fn wait(&self) {
        loop {
            let Ok(mut ready) = self.0.writable().await else {
                // A registration that fails can tell nothing; the splice still ends on its own.
                return core::future::pending().await;
            };
            if ready.ready().is_write_closed() {
                return;
            }
            ready.clear_ready();
        }
    }

    /// Return once the client has finished writing: half-closed, or gone. Each wake that is not that
    /// clears the edge and waits for the next, so a client still writing never spins the watch.
    pub(crate) async fn finished_writing(&self) {
        loop {
            let Ok(mut ready) = self.0.readable().await else {
                // A registration that fails can tell nothing; the splice still ends on its own.
                return core::future::pending().await;
            };
            if ready.ready().is_read_closed() {
                return;
            }
            ready.clear_ready();
        }
    }
}

#[cfg(test)]
#[path = "opening_tests.rs"]
mod tests;
